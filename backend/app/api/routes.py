"""
FastAPI Routes - Upload Security Gate & SSE Stream
- Streaming chunked upload with on-the-fly SHA-256 hashing and memory bounded writes
- Lightweight magic-bytes detection (PDF, JPEG, PNG, WebP, GIF, BMP, TIFF)
- Server-generated paths & client filename sanitization
- SSE endpoint streaming real-time progress and instant provisional security warnings
- Strict Cache-Control headers (no-store, private)

Authorization model (guest scanning, no login):
- Every job is bound to the caller's HttpOnly session cookie (see app.core.security).
- /result, /sse, /ws and DELETE /job require the owning session; a known job_id alone is
  not enough. Foreign/unknown jobs return 404 (no existence oracle).
- POST/DELETE require the X-QRGuard-Request header + allowed Origin (CSRF defense).
- WebSocket handshakes require an allowlisted / same-origin Origin header.
"""
import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from typing import AsyncGenerator, List, Optional

import aiofiles
from fastapi import APIRouter, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, StreamingResponse

from app.core import security as sec
from app.core.body_limit import RequestBodyTooLarge
from app.core.config import settings
from app.core.errors import AppError, error_response
from app.models.schemas import UploadResponse

logger = logging.getLogger(__name__)

router = APIRouter()

NO_STORE = {"Cache-Control": "no-store, private", "Pragma": "no-cache"}

# Magic bytes definitions for strict server-side file type verification
MAGIC_SIGNATURES = [
    (b"%PDF-", "pdf"),
    (b"\xff\xd8\xff", "image"),          # JPEG
    (b"\x89PNG\r\n\x1a\n", "image"),     # PNG
    (b"GIF87a", "image"),                # GIF
    (b"GIF89a", "image"),                # GIF
    (b"BM", "image"),                    # BMP
    (b"II*\x00", "image"),               # TIFF little-endian
    (b"MM\x00*", "image"),               # TIFF big-endian
]

# Client-declared MIME types we accept (magic bytes remain authoritative).
ALLOWED_DECLARED_MIME = {
    "image/jpeg", "image/jpg", "image/pjpeg", "image/png", "image/webp", "image/gif",
    "image/bmp", "image/x-ms-bmp", "image/tiff", "application/pdf",
    "application/octet-stream", "",
}

TERMINAL_STATUSES = ("completed", "failed", "cancelled")


def detect_magic_file_type(header: bytes) -> Optional[str]:
    """
    Determines if file is a safe image or PDF strictly from initial magic bytes.
    Does not rely on client-supplied Content-Type or file extensions.
    """
    if len(header) < 4:
        return None

    # Check WebP: "RIFF" (4 bytes) + file size (4 bytes) + "WEBP" (4 bytes)
    if len(header) >= 12 and header.startswith(b"RIFF") and header[8:12] == b"WEBP":
        return "image"

    for sig, ftype in MAGIC_SIGNATURES:
        if header.startswith(sig):
            return ftype

    return None


def declared_mime_consistent(declared: Optional[str], detected: str) -> bool:
    """Reject only clear contradictions (e.g. PDF bytes declared as image/png)."""
    mime = (declared or "").split(";")[0].strip().lower()
    if mime not in ALLOWED_DECLARED_MIME:
        return False
    if detected == "pdf" and mime.startswith("image/"):
        return False
    if detected == "image" and mime == "application/pdf":
        return False
    return True


def sanitize_filename(client_filename: Optional[str]) -> str:
    """Sanitizes client filename for safe UI display (basename only, max 100 chars)."""
    if not client_filename:
        return "upload.bin"
    base = os.path.basename(client_filename.replace("\\", "/"))
    # Filter non-printable / control characters
    clean = "".join(c for c in base if c.isprintable() and c not in '<>:"/\\|?*').strip()
    return clean[:100] if clean else "upload.bin"


def _sse(data: dict) -> str:
    """Format dictionary as SSE event string."""
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


def _safe_remove(path: str) -> None:
    try:
        if path and os.path.lexists(path):
            os.remove(path)
    except OSError:
        pass


def job_file_paths(job_id: str) -> List[str]:
    """Only server-generated names inside STORAGE_PATH are ever used."""
    return [os.path.join(settings.STORAGE_PATH, f"{job_id}{ext}") for ext in (".pdf", ".img", ".tmp")]


def _dispatch_job(job_id: str, file_path: str, display_filename: str, detected_type: str, enqueued_at: float) -> None:
    """Send the job to Celery. Isolated so tests can stub the broker."""
    from app.worker.celery_app import process_qr_file

    process_qr_file.apply_async(
        args=[job_id, file_path, display_filename, detected_type],
        kwargs={"enqueued_at": enqueued_at},
        task_id=job_id,
    )


async def _load_partial_events(r, job_id: str) -> List[dict]:
    """Per-QR events already emitted by the worker (for reconnect / late subscribers)."""
    try:
        raw = await r.hgetall(sec.events_key(job_id))
    except Exception:
        return []
    events = []
    for _, value in (raw or {}).items():
        try:
            events.append(json.loads(value))
        except (TypeError, ValueError):
            continue
    events.sort(key=lambda e: int(e.get("qr_index", 0)))
    return events


async def _authorize(r, job_id: str, session_id: Optional[str]) -> None:
    if not sec.is_valid_job_id(job_id):
        raise AppError("JOB_NOT_FOUND")
    try:
        ok = await sec.is_job_owner(r, job_id, session_id)
    except Exception:
        logger.warning("Redis unavailable during job authorization")
        raise AppError("SERVICE_UNAVAILABLE", headers={"Retry-After": "10"})
    if not ok:
        raise AppError("JOB_NOT_FOUND")


# ─── Upload ─────────────────────────────────────────────────────────────────
@router.post("/upload", response_model=UploadResponse)
async def upload_file(request: Request):
    """
    Upload Security Gate:
    0. CSRF, Content-Length and admission control run BEFORE the multipart body is
       parsed, so rejected requests never cost a multipart parse / temp-file spool.
    1. Chunked copy into a server-named file (bounded memory).
    2. Real-time SHA-256 computation and byte counting.
    3. Magic-byte verification from initial chunk.
    4. Server-generated storage path based on opaque job_id capability token.
    5. Dispatches processing task to Celery worker.
    """
    if not sec.csrf_ok(request.headers):
        raise AppError("CSRF_REJECTED")

    max_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
    declared_len = request.headers.get("content-length")
    if declared_len and declared_len.isdigit() and int(declared_len) > max_bytes + 64 * 1024:
        raise AppError("FILE_TOO_LARGE")
    if not (request.headers.get("content-type") or "").lower().startswith("multipart/form-data"):
        raise AppError("INVALID_FILE")

    r = request.app.state.redis
    session_id = sec.read_session_id(request.cookies)
    new_session = session_id is None
    if new_session:
        session_id = sec.new_session_id()
    fingerprint = sec.session_fingerprint(session_id)

    job_id = str(uuid.uuid4())
    # A slot must outlive the longest legitimate queue wait + run time, otherwise the
    # global cap silently stops counting jobs that are still queued.
    slot_ttl = settings.job_admission_ttl
    peer = request.client.host if request.client else None
    client_key = sec.client_slots_key(sec.client_bucket(sec.client_ip(request.headers, peer)))

    # Admission, from widest to narrowest scope (all atomic, see app.core.security):
    #   1. global cap  - protects the queue and the workers
    #   2. client cap  - one network cannot take the global cap by dropping its cookie
    #   3. session cap - fairness between tabs/sessions of the same user
    # Every rejection path gives back whatever was already taken (release_job_slot is idempotent).
    unflagged: List[str] = []  # slots taken whose flag key is not written yet
    try:
        if not await sec.acquire_global_slot(r, job_id, settings.MAX_GLOBAL_ACTIVE_JOBS, slot_ttl):
            raise AppError("SERVICE_UNAVAILABLE", headers={"Retry-After": "20"})
        if settings.MAX_ACTIVE_JOBS_PER_CLIENT > 0:
            if not await sec.acquire_slot(r, client_key, settings.MAX_ACTIVE_JOBS_PER_CLIENT, slot_ttl):
                await sec.release_job_slot(r, job_id, fingerprint)
                raise AppError("TOO_MANY_ACTIVE_JOBS", headers={"Retry-After": "15"})
            unflagged.append(client_key)
            await r.setex(sec.client_slot_flag_key(job_id), slot_ttl, client_key)
            unflagged.remove(client_key)
        session_key = sec.job_slots_key(fingerprint)
        if not await sec.acquire_slot(r, session_key, settings.MAX_ACTIVE_JOBS_PER_SESSION, slot_ttl):
            await sec.release_job_slot(r, job_id, fingerprint)
            raise AppError("TOO_MANY_ACTIVE_JOBS", headers={"Retry-After": "15"})
        unflagged.append(session_key)
        await r.setex(sec.job_slot_flag_key(job_id), slot_ttl, "1")
        unflagged.remove(session_key)
    except AppError:
        raise
    except Exception:
        logger.warning("Redis unavailable during upload admission")
        for key in unflagged:
            await sec.release_slot(r, key)
        await sec.release_job_slot(r, job_id, fingerprint)
        raise AppError("SERVICE_UNAVAILABLE", headers={"Retry-After": "10"})

    # Server generates filename exclusively from job_id; 'xb' = exclusive create (no clobber/symlink follow-through)
    temp_file_path = os.path.join(settings.STORAGE_PATH, f"{job_id}.tmp")
    hasher = hashlib.sha256()
    total_bytes = 0
    first_chunk = True
    detected_type: Optional[str] = None
    final_file_path = ""
    form = None

    async def _close_form():
        nonlocal form
        if form is not None:
            try:
                await form.close()
            except Exception:
                pass
            form = None

    async def _fail(code: str, headers: Optional[dict] = None):
        _safe_remove(temp_file_path)
        _safe_remove(final_file_path)
        await _close_form()
        await sec.release_job_slot(r, job_id, fingerprint)
        raise AppError(code, headers=headers)

    # Multipart is parsed only now — after CSRF, size and admission checks.
    try:
        form = await request.form(max_files=1, max_fields=4)
    except RequestBodyTooLarge:
        logger.info("Upload rejected: body exceeded limit while streaming")
        await _fail("FILE_TOO_LARGE")
    except Exception as e:
        logger.info("Upload multipart rejected: %s", type(e).__name__)
        await _fail("INVALID_FILE")
    file = form.get("file")
    if file is None or isinstance(file, str) or not hasattr(file, "read"):
        await _fail("INVALID_FILE")
    display_filename = sanitize_filename(getattr(file, "filename", None))

    try:
        async with aiofiles.open(temp_file_path, "xb") as out_f:
            try:
                os.chmod(temp_file_path, 0o600)
            except OSError:
                pass
            while chunk := await file.read(65536):
                total_bytes += len(chunk)

                # Enforce size limit during streaming
                if total_bytes > max_bytes:
                    raise AppError("FILE_TOO_LARGE")

                # Verify magic bytes on the very first chunk
                if first_chunk:
                    detected_type = detect_magic_file_type(chunk)
                    if not detected_type or not declared_mime_consistent(getattr(file, "content_type", None), detected_type):
                        raise AppError("UNSUPPORTED_FILE_TYPE")
                    first_chunk = False

                hasher.update(chunk)
                await out_f.write(chunk)
    except AppError as e:
        await _fail(e.code)
    except Exception as e:
        logger.error("Upload streaming error: %s", type(e).__name__)
        await _fail("INTERNAL_ERROR")
    # Release the spooled multipart temp file as soon as the bytes are copied.
    await _close_form()

    if total_bytes == 0 or not detected_type:
        await _fail("EMPTY_FILE")

    # Rename temp file to permanent server job file path
    final_ext = ".pdf" if detected_type == "pdf" else ".img"
    final_file_path = os.path.join(settings.STORAGE_PATH, f"{job_id}{final_ext}")
    enqueued_at = time.time()

    try:
        os.replace(temp_file_path, final_file_path)
        # Bind ownership BEFORE dispatch so the worker and clients see a consistent owner.
        await sec.bind_job_owner(r, job_id, session_id)
        await r.setex(
            sec.meta_key(job_id),
            settings.RESULT_CACHE_TTL,
            json.dumps({"file_type": detected_type, "size": total_bytes, "created_at": enqueued_at}),
        )
        initial_status = {
            "job_id": job_id,
            "status": "pending",
            "step": "queued",
            "progress": 0,
            "message": "Đã nhận tệp. Đang chờ kiểm tra...",
        }
        await r.setex(
            f"job:{job_id}:last_progress",
            settings.RESULT_CACHE_TTL,
            json.dumps(initial_status, ensure_ascii=False),
        )
    except Exception as e:
        logger.warning("Upload finalize failed: %s", type(e).__name__)
        await _fail("SERVICE_UNAVAILABLE", headers={"Retry-After": "10"})

    try:
        _dispatch_job(job_id, final_file_path, display_filename, detected_type, enqueued_at)
    except Exception as e:
        logger.error("Job dispatch failed: %s", type(e).__name__)
        try:
            await r.delete(sec.owner_key(job_id), f"job:{job_id}:last_progress", sec.meta_key(job_id))
        except Exception:
            pass
        await _fail("SERVICE_UNAVAILABLE", headers={"Retry-After": "10"})

    logger.info("Job accepted type=%s size=%d sha256=%s…", detected_type, total_bytes, hasher.hexdigest()[:12])
    body = UploadResponse(job_id=job_id, message="Đã nhận tệp. Đang kiểm tra...").model_dump()
    response = JSONResponse(content=body, headers=NO_STORE)
    if new_session:
        sec.set_session_cookie(response, session_id)
    return response


# ─── Polling ────────────────────────────────────────────────────────────────
@router.get("/result/{job_id}")
async def get_result(job_id: str, request: Request):
    """
    Polling result endpoint.
    Returns HTTP 200 with Cache-Control: no-store, private.
    """
    r = request.app.state.redis
    await _authorize(r, job_id, sec.read_session_id(request.cookies))

    try:
        result_json = await r.get(f"job:{job_id}:result")
        if result_json:
            return JSONResponse(content=json.loads(result_json), headers=NO_STORE)
        progress_json = await r.get(f"job:{job_id}:last_progress")
    except Exception:
        raise AppError("SERVICE_UNAVAILABLE", headers={"Retry-After": "5"})

    if progress_json:
        progress = json.loads(progress_json)
        return JSONResponse(
            content={
                "job_id": job_id,
                "status": progress.get("status", "processing"),
                "step": progress.get("step"),
                "message": progress.get("message", "Đang xử lý..."),
                "progress": progress.get("progress", 0),
                "is_final": False,
                "partial_results": await _load_partial_events(r, job_id),
            },
            headers=NO_STORE,
        )

    raise AppError("JOB_NOT_FOUND")


# ─── Cancel ─────────────────────────────────────────────────────────────────
@router.delete("/job/{job_id}")
async def cancel_job(job_id: str, request: Request):
    """User cancelled: mark job, revoke if not started, delete uploaded file immediately."""
    if not sec.csrf_ok(request.headers):
        raise AppError("CSRF_REJECTED")
    r = request.app.state.redis
    session_id = sec.read_session_id(request.cookies)
    await _authorize(r, job_id, session_id)

    try:
        if await r.get(f"job:{job_id}:result"):
            return JSONResponse({"job_id": job_id, "status": "completed"}, headers=NO_STORE)
        await r.setex(sec.cancel_key(job_id), settings.RESULT_CACHE_TTL, "1")
        payload = json.dumps({
            "job_id": job_id, "status": "cancelled", "step": "cancelled", "progress": 0,
            "message": "Bạn đã hủy lượt kiểm tra.",
        }, ensure_ascii=False)
        await r.setex(f"job:{job_id}:last_progress", settings.RESULT_CACHE_TTL, payload)
        await r.publish(f"job:{job_id}:progress", payload)
    except Exception:
        raise AppError("SERVICE_UNAVAILABLE", headers={"Retry-After": "5"})

    try:
        from app.worker.celery_app import celery_app

        celery_app.control.revoke(job_id)  # no terminate: the running task checks the cancel flag
    except Exception:
        pass
    for path in job_file_paths(job_id):
        _safe_remove(path)
    await sec.release_job_slot(r, job_id, sec.session_fingerprint(session_id))
    return JSONResponse({"job_id": job_id, "status": "cancelled"}, headers=NO_STORE)


# ─── SSE ────────────────────────────────────────────────────────────────────
@router.get("/sse/{job_id}")
async def sse_progress(job_id: str, request: Request):
    """
    Server-Sent Events: Real-time progress and instantaneous provisional warnings.
    """
    main_redis = request.app.state.redis
    session_id = sec.read_session_id(request.cookies)
    await _authorize(main_redis, job_id, session_id)

    slots_key = sec.stream_slots_key(sec.session_fingerprint(session_id))
    try:
        if not await sec.acquire_slot(main_redis, slots_key, settings.MAX_STREAMS_PER_SESSION, settings.STREAM_MAX_SECONDS + 60):
            raise AppError("TOO_MANY_STREAMS", headers={"Retry-After": "10"})
    except AppError:
        raise
    except Exception:
        raise AppError("SERVICE_UNAVAILABLE", headers={"Retry-After": "5"})

    released = False

    async def release_once() -> None:
        nonlocal released
        if not released:
            released = True
            await sec.release_slot(main_redis, slots_key)

    async def event_generator() -> AsyncGenerator[str, None]:
        pubsub = None
        channel = f"job:{job_id}:progress"
        try:
            # Step 0: Check if result is already completed
            result_json = await main_redis.get(f"job:{job_id}:result")
            if result_json:
                result = json.loads(result_json)
                yield _sse({"job_id": job_id, "status": result.get("status", "completed"), "progress": 100, "message": "Kết quả đã sẵn sàng"})
                yield _sse({"type": "result", "data": result})
                return

            # Step 1: subscribe FIRST, then replay -> no gap where events could be lost
            pubsub = main_redis.pubsub()
            await pubsub.subscribe(channel)

            progress_json = await main_redis.get(f"job:{job_id}:last_progress")
            if progress_json:
                yield f"data: {progress_json}\n\n"
            for ev in await _load_partial_events(main_redis, job_id):
                yield _sse(ev)

            HEARTBEAT = 15
            POLL_INTERVAL = 2.0
            loop = asyncio.get_running_loop()
            start = last_heartbeat = last_poll = loop.time()

            while True:
                now = loop.time()
                if now - start > settings.STREAM_MAX_SECONDS:
                    # Not a job failure: client should fall back to polling.
                    yield _sse({"job_id": job_id, "type": "stream_timeout", "message": "Kết nối trực tiếp đã đóng, đang chuyển sang kiểm tra định kỳ."})
                    break
                if await request.is_disconnected():
                    break

                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=0.5)
                if message and message.get("type") == "message":
                    data_str = message["data"]
                    yield f"data: {data_str}\n\n"
                    try:
                        parsed = json.loads(data_str)
                    except (TypeError, ValueError):
                        parsed = {}
                    if parsed.get("type") == "result":
                        break
                    if parsed.get("status") in TERMINAL_STATUSES:
                        await asyncio.sleep(0.15)
                        result_json = await main_redis.get(f"job:{job_id}:result")
                        if result_json:
                            yield _sse({"type": "result", "data": json.loads(result_json)})
                        break
                elif now - last_poll >= POLL_INTERVAL:
                    last_poll = now
                    result_json = await main_redis.get(f"job:{job_id}:result")
                    if result_json:
                        result = json.loads(result_json)
                        yield _sse({"job_id": job_id, "status": result.get("status", "completed"), "progress": 100, "message": "Hoàn thành"})
                        yield _sse({"type": "result", "data": result})
                        break

                if now - last_heartbeat >= HEARTBEAT:
                    last_heartbeat = now
                    yield ": heartbeat\n\n"

                await asyncio.sleep(0.1)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning("SSE stream error: %s", type(e).__name__)
            # Transient transport problem — NOT a job failure. Client falls back to polling.
            yield _sse({"job_id": job_id, "type": "stream_error", "message": "Mất kết nối tạm thời."})
        finally:
            if pubsub is not None:
                try:
                    await pubsub.unsubscribe(channel)
                    await pubsub.aclose()
                except Exception:
                    pass
            await release_once()

    return _SlotStreamingResponse(
        event_generator(),
        on_close=release_once,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store, private",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


class _SlotStreamingResponse(StreamingResponse):
    """StreamingResponse that always runs `on_close`, even when the client disconnects before
    the body generator has started (an unstarted generator never executes its `finally`)."""

    def __init__(self, content, on_close, **kwargs):
        super().__init__(content, **kwargs)
        self._on_close = on_close

    async def __call__(self, scope, receive, send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            try:
                await self._on_close()
            except Exception:
                pass


# ─── WebSocket ──────────────────────────────────────────────────────────────
@router.websocket("/ws/{job_id}")
async def websocket_job_stream(websocket: WebSocket, job_id: str):
    """
    WebSocket endpoint streaming real-time job progress, instant provisional warnings,
    and individual QR results as each code completes.
    """
    main_redis = websocket.app.state.redis

    # Origin + ownership are verified BEFORE accepting the handshake (CSWSH protection).
    if not sec.origin_allowed(websocket.headers.get("origin"), websocket.headers.get("host")):
        await websocket.close(code=1008)
        return
    session_id = sec.read_session_id(websocket.cookies)
    try:
        authorized = sec.is_valid_job_id(job_id) and await sec.is_job_owner(main_redis, job_id, session_id)
    except Exception:
        authorized = False
    if not authorized:
        await websocket.close(code=1008)
        return

    slots_key = sec.stream_slots_key(sec.session_fingerprint(session_id))
    try:
        slot_ok = await sec.acquire_slot(main_redis, slots_key, settings.MAX_STREAMS_PER_SESSION, settings.STREAM_MAX_SECONDS + 60)
    except Exception:
        slot_ok = False
    if not slot_ok:
        await websocket.close(code=1013)  # try again later
        return

    await websocket.accept()
    pubsub = None
    channel = f"job:{job_id}:progress"

    async def send(obj) -> None:
        await websocket.send_text(obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False))

    try:
        result_json = await main_redis.get(f"job:{job_id}:result")
        if result_json:
            result = json.loads(result_json)
            await send({"job_id": job_id, "status": result.get("status", "completed"), "progress": 100, "message": "Kết quả đã sẵn sàng"})
            await send({"type": "result", "data": result})
            return

        pubsub = main_redis.pubsub()
        await pubsub.subscribe(channel)
        progress_json = await main_redis.get(f"job:{job_id}:last_progress")
        if progress_json:
            await send(progress_json)
        for ev in await _load_partial_events(main_redis, job_id):
            await send(ev)

        async def client_listener():
            """Listen for pings or disconnect from client (inbound size bounded by uvicorn --ws-max-size).
            Inbound frames are rate-limited; a client exceeding WS_MAX_INBOUND_MESSAGES per
            WS_INBOUND_WINDOW_SECONDS is disconnected with 1008 (policy violation)."""
            window_start = time.monotonic()
            count = 0
            try:
                while True:
                    msg = await websocket.receive_text()
                    now = time.monotonic()
                    if now - window_start > settings.WS_INBOUND_WINDOW_SECONDS:
                        window_start, count = now, 0
                    count += 1
                    if count > settings.WS_MAX_INBOUND_MESSAGES:
                        await websocket.close(code=1008)
                        return
                    if msg == "ping":
                        await send({"type": "pong"})
            except (WebSocketDisconnect, Exception):
                pass

        async def pubsub_streamer():
            """Stream Redis Pub/Sub messages to WebSocket."""
            loop = asyncio.get_running_loop()
            start = loop.time()
            last_poll = start
            while loop.time() - start <= settings.STREAM_MAX_SECONDS:
                msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if msg and msg.get("type") == "message":
                    data_str = msg["data"]
                    await send(data_str)
                    try:
                        payload = json.loads(data_str)
                    except (TypeError, ValueError):
                        payload = {}
                    if payload.get("type") == "result":
                        return
                    if payload.get("status") in TERMINAL_STATUSES:
                        await asyncio.sleep(0.15)
                        rj = await main_redis.get(f"job:{job_id}:result")
                        if rj:
                            await send({"type": "result", "data": json.loads(rj)})
                        return
                elif loop.time() - last_poll >= 2.0:
                    last_poll = loop.time()
                    rj = await main_redis.get(f"job:{job_id}:result")
                    if rj:
                        result = json.loads(rj)
                        await send({"job_id": job_id, "status": result.get("status", "completed"), "progress": 100, "message": "Hoàn thành"})
                        await send({"type": "result", "data": result})
                        return
                await asyncio.sleep(0.05)
            await send({"job_id": job_id, "type": "stream_timeout"})

        listener_task = asyncio.create_task(client_listener())
        streamer_task = asyncio.create_task(pubsub_streamer())
        done, pending = await asyncio.wait([listener_task, streamer_task], return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
    except Exception as e:
        logger.warning("WebSocket session error: %s", type(e).__name__)
    finally:
        if pubsub is not None:
            try:
                await pubsub.unsubscribe(channel)
                await pubsub.aclose()
            except Exception:
                pass
        await sec.release_slot(main_redis, slots_key)
        try:
            await websocket.close()
        except Exception:
            pass


# ─── Health ─────────────────────────────────────────────────────────────────
@router.get("/health")
async def health_check():
    """Minimal Health check endpoint."""
    return {"status": "ok"}


@router.get("/health/ready")
async def readiness(request: Request):
    """Readiness: Redis reachable. Reveals no versions or configuration."""
    try:
        await request.app.state.redis.ping()
        return {"status": "ready"}
    except Exception:
        return error_response("SERVICE_UNAVAILABLE", headers={"Retry-After": "10"})
