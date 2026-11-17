"""
Celery Worker Application - THREAT INTELLIGENCE & MULTI-LAYER SECURITY
Processes compute tasks:
- Image & PDF Decompression Bomb Protection (Pillow verify+load fail-closed + PyMuPDF limits)
- Dual-Stage QR Decoder (Fast early-stop vs Complete ensemble mode, OpenCV last-resort fallback)
- Payload Classification: VietQR Candidate / URL / URI / Other
- URL Security Engine: Single-phase analysis (Rules + XGBoost Research Sensor + Local Verified IOC) -> Deterministic Verdict
- Payment Security Engine: Progressive Flow (Structural provisional -> Rendered-page OCR + Supplemental PDF text -> Spatial reconciliation -> Final verdict)
- Redis: Message broker, job state persistence, event pub/sub, and results store

Security invariants enforced here:
- Only server-generated paths `{STORAGE_PATH}/{job_id}.(img|pdf)` are opened (task messages are untrusted).
- Malformed / truncated / encrypted inputs fail closed with a stable error code.
- Partial coverage (PDF page cap, OCR/TI failures) is reported, never presented as complete.
- Raw QR payloads / account numbers are never written to logs.
"""
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import List, Optional

import numpy as np
import redis
from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded
from celery.signals import worker_process_init, worker_ready

from app.core.config import settings
from app.core.errors import ERRORS
from app.core.security import cancel_key, events_key, is_valid_job_id, owner_key, release_job_slot_sync
from app.models.schemas import (
    AlertCode,
    JobStatus,
    OCRData,
    PayloadType,
    ProcessingResult,
    QRCodeResult,
    SecurityVerdict,
)
from app.services.context_extractor import TextLine, extract_context
from app.services.file_safety import (
    EncryptedPdfError,
    InvalidFileError,
    ResourceLimitExceeded,
    UnsafePathError,
    decode_image_safely,
    read_job_file,
    resolve_job_file,
)
from app.services.fuzzy_matcher import fuzzy_match_and_alert
from app.services.qr_decoder import DualStageQRDecoder, resize_if_large
from app.services.url_security import (
    URLSecurityAnalyzer,
    URLSecurityPolicy,
    get_threat_intel_service,
    get_url_model_service,
)
from app.services.vietqr_parser import classify_payload, parse_vietqr

logger = logging.getLogger(__name__)

# ─── Structured Cache Version ────────────────────────────────────────────────
# Invalidate cache whenever code, rule, model, or policy logic evolves
STRUCTURED_CACHE_VERSION = (
    f"v8_p{URLSecurityPolicy.POLICY_VERSION}"
)

# ─── Celery App ─────────────────────────────────────────────────────────────
celery_app = Celery(
    "qr_guard",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_expires=settings.RESULT_CACHE_TTL,
    task_ignore_result=True,          # results live in job:{id}:result; avoid duplicate copies in Redis
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=False,  # never re-run a poison file in a crash loop
    worker_max_tasks_per_child=500,
    broker_connection_retry_on_startup=True,
    task_soft_time_limit=settings.CELERY_TASK_SOFT_TIME_LIMIT,
    task_time_limit=settings.CELERY_TASK_HARD_TIME_LIMIT,
    broker_transport_options={"visibility_timeout": settings.job_admission_ttl},
)

# ─── Global Singletons ──────────────────────────────────────────────────────
_qr_decoder: Optional[DualStageQRDecoder] = None
_redis_sync: Optional[redis.Redis] = None
_url_analyzer: Optional[URLSecurityAnalyzer] = None


def get_qr_decoder() -> DualStageQRDecoder:
    global _qr_decoder
    if _qr_decoder is None:
        _qr_decoder = DualStageQRDecoder(settings.WECHAT_QR_MODEL_DIR)
    return _qr_decoder


def get_redis() -> redis.Redis:
    global _redis_sync
    if _redis_sync is None:
        _redis_sync = redis.from_url(settings.REDIS_URL, decode_responses=True, socket_connect_timeout=3)
    return _redis_sync


def get_url_analyzer() -> URLSecurityAnalyzer:
    global _url_analyzer
    if _url_analyzer is None:
        _url_analyzer = URLSecurityAnalyzer()
    return _url_analyzer


_worker_warmed: bool = False


# ─── Load the local IOC feed and pre-warm models in worker process ───────────
def _warm_worker_resources():
    global _worker_warmed
    if _worker_warmed:
        return
    _worker_warmed = True
    try:
        ti = get_url_analyzer().threat_intel
        logger.info("Local IOC feed: status=%s indicators=%d", ti.local_feed_status, ti.local_feed_count)
    except Exception as e:
        logger.warning("Local IOC feed preload failed: %s", type(e).__name__)

    try:
        decoder = get_qr_decoder()
        decoder.warmup()
        logger.info("✓ QR decoders ready: %s", ", ".join(decoder.available_engines()))
    except Exception as e:
        logger.warning("QR decoder warmup failed: %s", type(e).__name__)

    if os.environ.get("OCR_WARMUP", "1") == "1":
        try:
            from app.services.ocr_service import warmup_ocr
            warmup_ocr()
            logger.info("✓ PaddleOCR PP-OCRv4 model warmed up")
        except Exception as e:
            logger.warning("OCR warmup failed: %s", type(e).__name__)

    try:
        model_svc = get_url_model_service()
        model_svc.warmup()
        logger.info("✓ XGBoost URL Model Service warmed up")
    except Exception as e:
        logger.warning("XGBoost warmup failed: %s", type(e).__name__)


@worker_process_init.connect
def load_threat_intel(**kwargs):
    """Pre-warm resources in prefork child processes."""
    _warm_worker_resources()


@worker_ready.connect
def warm_models(sender, **kwargs):
    """Ensure resources are warmed up when using thread/solo worker pools."""
    _warm_worker_resources()
    logger.info("Celery Worker ready — worker resources initialized.")


# ─── Event & Progress Publishing Helpers ─────────────────────────────────────
def publish_event(job_id: str, event_type: str, data: dict):
    """
    Publishes a structured typed event over Redis SSE channel (e.g. provisional_result, result).
    Per-QR events are also stored in job:{id}:events so late subscribers / pollers can replay them.
    """
    try:
        r = get_redis()
        payload = json.dumps({"type": event_type, "job_id": job_id, **data}, ensure_ascii=False)
        if event_type in ("provisional_result", "qr_result") and "qr_index" in data:
            pipe = r.pipeline()
            pipe.hset(events_key(job_id), str(data["qr_index"]), payload)
            pipe.expire(events_key(job_id), settings.RESULT_CACHE_TTL)
            pipe.publish(f"job:{job_id}:progress", payload)
            pipe.execute()
        else:
            r.publish(f"job:{job_id}:progress", payload)
    except Exception as e:
        logger.warning("Event publish failed (%s): %s", event_type, type(e).__name__)


def publish_progress(job_id: str, step: str, progress: int, message: str, status: str = "processing", **extra):
    """
    Publishes a standard progress update to SSE channel and caches in job:{id}:last_progress.
    Messages are plain Vietnamese for end users (no internal jargon).
    """
    try:
        r = get_redis()
        update = {
            "job_id": job_id,
            "step": step,
            "progress": progress,
            "message": message,
            "status": status,
            **extra,
        }
        payload = json.dumps(update, ensure_ascii=False)
        r.publish(f"job:{job_id}:progress", payload)
        r.setex(f"job:{job_id}:last_progress", settings.RESULT_CACHE_TTL, payload)
    except Exception as e:
        logger.warning("Progress publish failed: %s", type(e).__name__)


def file_hash(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def cache_namespace() -> str:
    """Cache key scope: code/policy/rules version + active model identity + local TI feed SHA-256 + decode mode."""
    try:
        model_fp = get_url_model_service().cache_fingerprint
    except Exception:
        model_fp = "none"
    try:
        feed_sha = get_threat_intel_service().get_feed_sha256()
        ti_token = f"ti-{feed_sha[:16]}" if feed_sha else "ti-unavailable"
    except Exception:
        ti_token = "ti-unavailable"
    return f"{STRUCTURED_CACHE_VERSION}:m{model_fp}:{ti_token}:d{settings.QR_DECODE_MODE}"


def result_cache_key(fhash: str) -> str:
    return f"file-result:{cache_namespace()}:{fhash}"


def scoped_file_hash(r: redis.Redis, job_id: str, fhash: str) -> Optional[str]:
    """
    The result cache is scoped to the uploader's session fingerprint. A shared cache
    lets anyone holding file X learn whether someone else scanned X recently (and replays the
    other user's verdict). Returns None (= do not cache) when the owner is unknown.
    """
    try:
        fp = r.get(owner_key(job_id))
    except Exception:
        fp = None
    if not fp:
        return None
    if isinstance(fp, bytes):
        fp = fp.decode("utf-8", "ignore")
    return hashlib.sha256(f"{fp}:{fhash}".encode("utf-8")).hexdigest()


def is_cancelled(r: redis.Redis, job_id: str) -> bool:
    try:
        return bool(r.exists(cancel_key(job_id)))
    except Exception:
        return False


class JobCancelled(Exception):
    pass


def _ms(seconds: float) -> float:
    return round(seconds * 1000.0, 1)


# ─── Image Safety & Preprocessing ───────────────────────────────────────────
@dataclass
class PreparedImage:
    image: np.ndarray
    text_lines: Optional[List[TextLine]] = None
    page_number: int = 0
    hidden_text_spans: int = 0      # invisible PDF text dropped on this page


@dataclass
class PreparedInput:
    images: List[PreparedImage]
    partial: bool = False
    total_pages: int = 1
    skipped_pages: Optional[List[int]] = None


def _scale_lines(lines: List[TextLine], scale: float) -> List[TextLine]:
    if scale == 1.0:
        return lines
    return [
        TextLine(
            text=l.text,
            conf=l.conf,
            cx=l.cx * scale if l.cx is not None else None,
            cy=l.cy * scale if l.cy is not None else None,
            w=l.w * scale if l.w is not None else None,
            h=l.h * scale if l.h is not None else None,
            relative_pos=l.relative_pos,
        )
        for l in lines
    ]


def prepare_input(file_bytes: bytes, file_type: str) -> PreparedInput:
    """
    Prepares images safely (fail-closed):
    - Images: Pillow header dims -> verify() -> load() under our pixel limit -> BGR ndarray.
      Any parse failure raises InvalidFileError; OpenCV never decodes raw untrusted bytes.
    - PDFs: projected pixel checks per page and in total; encrypted / unreadable PDFs raise;
      page cap and render failures are reported as partial coverage.
    """
    if file_type == "pdf":
        from app.services.pdf_extractor import extract_pdf

        extraction = extract_pdf(file_bytes)
        images = []
        for page in extraction.pages:
            img, scale = resize_if_large(page.image)
            images.append(PreparedImage(
                image=img,
                text_lines=_scale_lines(page.lines, scale) if page.lines else None,
                page_number=page.page_number,
                hidden_text_spans=getattr(page, "hidden_text_spans", 0),
            ))
        return PreparedInput(
            images=images,
            partial=extraction.partial,
            total_pages=extraction.total_pages,
            skipped_pages=extraction.skipped_pages,
        )

    if file_type != "image":
        raise InvalidFileError("unsupported file type")
    image = decode_image_safely(file_bytes)
    return PreparedInput(images=[PreparedImage(image=resize_if_large(image)[0])])


def build_other_result(payload: str, bbox=None, engine: str = "classifier") -> QRCodeResult:
    return QRCodeResult(
        payload=payload,
        payload_type=PayloadType.OTHER,
        bbox=bbox,
        engine=engine,
        alert_code=AlertCode.OTHER_PAYLOAD,
        alert_color="#546E7A",
        alert_title="Mã QR chứa văn bản",
        alert_message=f"Nội dung: {payload[:150]}{'...' if len(payload) > 150 else ''}",
        alert_recommendation="Mã QR này chứa văn bản, không phải liên kết web hay mã chuyển tiền. "
                             "Không làm theo yêu cầu chuyển tiền hoặc cung cấp mật khẩu ghi trong đó.",
    )


def build_error_result(payload: str, engine: str, bbox) -> QRCodeResult:
    return QRCodeResult(
        payload=payload,
        payload_type=PayloadType.UNKNOWN,
        engine=engine,
        bbox=bbox,
        alert_code=AlertCode.INVALID_PAYLOAD,
        alert_color="#546E7A",
        alert_title="Chưa thể kiểm tra đầy đủ mã QR này",
        alert_message="Đã xảy ra lỗi khi phân tích mã QR này. Các mã QR khác (nếu có) vẫn được xử lý bình thường.",
        alert_recommendation="Thử chụp lại ảnh rõ hơn. Nếu vẫn không kiểm tra được, đừng vội mở liên kết hoặc chuyển tiền.",
        analysis_completeness="partial",
        reason_codes=["QR_ANALYSIS_ERROR"],
    )


# ─── Result finalisation helpers ────────────────────────────────────────────
def _apply_error(result: ProcessingResult, code: str, status: JobStatus = JobStatus.FAILED) -> None:
    spec = ERRORS.get(code, ERRORS["PROCESSING_ERROR"])
    result.status = status
    result.error = code
    result.error_code = code
    result.user_message = spec.message
    result.recommended_action = spec.action
    result.is_final = True


def _finish(r: redis.Redis, job_id: str, result: ProcessingResult, started: float, timings: dict,
            fhash: Optional[str] = None, step: str = "complete", message: Optional[str] = None) -> None:
    result.completed_at = time.time()
    timings["total"] = _ms(result.completed_at - started)
    result.timings_ms = dict(timings)
    result.is_final = True
    _save_result(r, job_id, result, fhash)
    status = result.status.value if hasattr(result.status, "value") else str(result.status)
    publish_progress(job_id, step, 100, message or result.user_message or "Đã kiểm tra xong.", status)
    publish_event(job_id, "result", {"data": json.loads(result.model_dump_json())})


# ─── Main Celery Task ───────────────────────────────────────────────────────
@celery_app.task(bind=True, name="process_qr_file")
def process_qr_file(self, job_id: str, file_path: str, file_name: str, file_type: str, enqueued_at: Optional[float] = None):
    """
    Main Celery Processing Task:
    1. Validate the task message (job id, server-generated path, regular file).
    2. Check result cache by file SHA-256 (structured cache versioning incl. model digest).
    3. Safely inspect and prepare images/PDF pages (DoS / Decompression Bomb protection, fail-closed).
    4. Dual-stage QR decoding (fast vs complete mode).
    5. Payload Classification:
       - URL/URI:
         * analyze() -> single-phase: Normalize -> Validate -> Rules -> ML Sensor -> Local IOC -> Policy.
         * NEVER runs OCR for URL.
         * Exactly one final result; no provisional event.
       - VietQR:
         * Strict TLV + CRC integrity + semantic checks.
         * Only runs OCR if QR is structurally valid.
         * Caches OCR per image; uses PDF text layer if digital.
         * Context consistency match (never claims 100% safe).
    6. Save final result in Redis.
    """
    started = time.time()
    r = get_redis()
    timings: dict = {}
    if enqueued_at:
        timings["queue_wait"] = _ms(max(0.0, started - float(enqueued_at)))

    result = ProcessingResult(
        job_id=job_id,
        status=JobStatus.PROCESSING,
        file_name=(file_name or "upload.bin")[:100],
        is_final=False,
        created_at=float(enqueued_at) if enqueued_at else started,
    )
    validated_path: Optional[str] = None

    def check_cancel():
        if is_cancelled(r, job_id):
            raise JobCancelled()

    try:
        if not is_valid_job_id(job_id):
            logger.warning("Rejected task with malformed job id")
            return
        check_cancel()

        # ── 0. Task message validation (untrusted) ─────────────────
        try:
            validated_path = resolve_job_file(job_id, file_path, file_type)
        except FileNotFoundError:
            _apply_error(result, "JOB_NOT_FOUND")
            _finish(r, job_id, result, started, timings, step="error")
            return
        except UnsafePathError:
            logger.warning("SECURITY: task path failed validation (job %s)", job_id)
            _apply_error(result, "INVALID_FILE")
            _finish(r, job_id, result, started, timings, step="error")
            return

        # Bounded queue wait — never run a job the admission slot no longer covers.
        if enqueued_at and (started - float(enqueued_at)) > settings.JOB_QUEUE_MAX_WAIT_SECONDS:
            logger.warning("Job %s waited %.0fs in queue; rejecting", job_id, started - float(enqueued_at))
            _apply_error(result, "SERVICE_UNAVAILABLE")
            _finish(r, job_id, result, started, timings, step="error")
            return

        publish_progress(job_id, "validate", 5, "Đang kiểm tra tệp...")
        t0 = time.time()
        file_bytes = read_job_file(validated_path, settings.MAX_FILE_SIZE_MB * 1024 * 1024)

        # ── 1. Result Cache Check (Hash-based, scoped to the uploader's session) ──
        fhash = scoped_file_hash(r, job_id, file_hash(file_bytes))
        cached = None
        if fhash:
            try:
                cached = r.get(result_cache_key(fhash))
            except Exception:
                cached = None
        if cached:
            logger.info("Result cache hit (session-scoped) for job %s", job_id)
            cached_result = json.loads(cached)
            # Never leak the previous uploader's metadata
            cached_result.update({
                "job_id": job_id,
                "file_name": result.file_name,
                "created_at": result.created_at,
                "completed_at": time.time(),
                "is_final": True,
            })
            timings["cache_hit"] = 1
            timings["total"] = _ms(time.time() - started)
            cached_result["timings_ms"] = timings
            cached_result.setdefault("warnings", [])
            if "CACHED_RESULT" not in cached_result["warnings"]:
                cached_result["warnings"].append("CACHED_RESULT")
            r.setex(f"job:{job_id}:result", settings.RESULT_CACHE_TTL, json.dumps(cached_result, ensure_ascii=False))
            publish_progress(job_id, "complete", 100, "Đã kiểm tra xong.", cached_result.get("status", "completed"))
            publish_event(job_id, "result", {"data": cached_result})
            return

        # ── 2. Safe Image & PDF Preparation ─────────────────────────
        if file_type == "pdf":
            publish_progress(job_id, "prepare", 10, "Đang mở tệp PDF...")
        try:
            prepared = prepare_input(file_bytes, file_type)
        except ResourceLimitExceeded as rle:
            logger.info("Resource limit exceeded in job %s: %s", job_id, rle)
            _apply_error(result, "FILE_RESOURCE_LIMIT")
            _finish(r, job_id, result, started, timings, step="error")
            return
        except EncryptedPdfError:
            _apply_error(result, "PDF_ENCRYPTED")
            _finish(r, job_id, result, started, timings, step="error")
            return
        except InvalidFileError as ife:
            logger.info("Invalid file in job %s: %s", job_id, ife)
            _apply_error(result, "INVALID_FILE")
            _finish(r, job_id, result, started, timings, step="error")
            return
        del file_bytes
        images = prepared.images
        timings["prepare"] = _ms(time.time() - t0)

        if prepared.partial:
            result.analysis_completeness = "partial"
            result.warnings.append("PARTIAL_ANALYSIS")
            if prepared.total_pages > settings.MAX_PDF_PAGES:
                result.warnings.append(f"PDF_PAGE_LIMIT:{settings.MAX_PDF_PAGES}/{prepared.total_pages}")
            if prepared.skipped_pages:
                result.warnings.append("PDF_PAGES_SKIPPED:" + ",".join(str(p) for p in prepared.skipped_pages))

        hidden_pages = [p.page_number for p in images if getattr(p, "hidden_text_spans", 0)]
        if hidden_pages:
            # Invisible text was present and ignored; surface it, do not hide it.
            result.warnings.append("PDF_HIDDEN_TEXT:" + ",".join(str(p) for p in hidden_pages))

        check_cancel()
        publish_progress(job_id, "qr_decode", 20, "Đang tìm và đọc mã QR...")

        # ── 3. QR Decoding (Dual-Stage Ensemble) ───────────────────
        t0 = time.time()
        qr_decoder = get_qr_decoder()
        all_qr_raw = []
        for idx, prep in enumerate(images):
            for item in qr_decoder.decode_array(prep.image, mode=settings.QR_DECODE_MODE):
                item["image_index"] = idx
                all_qr_raw.append(item)
        timings["decode"] = _ms(time.time() - t0)

        if not all_qr_raw:
            result.status = JobStatus.COMPLETED
            result.qr_codes = []
            spec = ERRORS["NO_QR_FOUND"]
            result.error_code = "NO_QR_FOUND"
            result.user_message = spec.message
            result.recommended_action = spec.action
            _finish(r, job_id, result, started, timings, fhash=fhash, message=spec.message)
            return

        total = len(all_qr_raw)
        max_qr = max(1, settings.MAX_QR_PER_JOB)
        if total > max_qr:
            # Resource budget: analyse the first N codes and say so explicitly (never "full").
            result.analysis_completeness = "partial"
            if "PARTIAL_ANALYSIS" not in result.warnings:
                result.warnings.append("PARTIAL_ANALYSIS")
            result.warnings.append(f"QR_LIMIT:{max_qr}/{total}")
            all_qr_raw = all_qr_raw[:max_qr]
            total = max_qr
        publish_progress(
            job_id, "decoded", 35,
            f"Đã đọc được {total} mã QR." if total > 1 else "Đã đọc được 1 mã QR.",
            qr_total=total,
        )

        # ── 4. Process Each QR Code ────────────────────────────────
        url_analyzer = get_url_analyzer()
        context_cache: dict = {}
        ocr_ms = 0.0

        def get_context_lines(img_idx: int, step_prog: int, qr_bbox=None):
            """
            The PDF text layer is never trusted alone — it can omit text drawn as
            images/vector outlines and can carry text the reader never sees. OCR of the
            rendered page is always run; visible text-layer lines are merged in as a
            high-precision supplement.
            """
            nonlocal ocr_ms
            if img_idx not in context_cache:
                prep = images[img_idx]
                publish_progress(job_id, "ocr", step_prog, "Đang đọc chữ trên ảnh để so sánh thông tin chuyển tiền...")
                from app.services.ocr_service import run_ocr_lines_with_status
                t_ocr = time.time()
                ocr_lines, status = run_ocr_lines_with_status(prep.image, qr_bbox)
                ocr_ms += time.time() - t_ocr
                if prep.text_lines:
                    merged = list(prep.text_lines) + list(ocr_lines)
                    source = "pdf_text+ocr" if ocr_lines else "pdf_text"
                    context_cache[img_idx] = (merged, source, status)
                else:
                    context_cache[img_idx] = (ocr_lines, "ocr", status)
            return context_cache[img_idx]

        processed: dict = {}          # qr_index -> final QRCodeResult (order restored at the end)
        first_result_marked = False

        def mark_first_result():
            nonlocal first_result_marked
            if not first_result_marked:
                timings["first_result"] = _ms(time.time() - started)
                first_result_marked = True

        def emit_final(i: int, qr: QRCodeResult) -> None:
            processed[i] = qr
            publish_event(
                job_id=job_id,
                event_type="qr_result",
                data={"qr_index": i, "total": total, "result": json.loads(qr.model_dump_json())},
            )

        for i, qr_raw in enumerate(all_qr_raw):
            check_cancel()
            payload = qr_raw["payload"]
            bbox = qr_raw.get("bbox")
            engine = qr_raw.get("engine", "unknown")
            idx = qr_raw["image_index"]
            base_progress = 40 + int((i / total) * 55)
            label = f"Mã QR #{i + 1}: " if total > 1 else ""

            try:
                payload_type = classify_payload(payload)

                # ============================================================
                # BRANCH A: URL & URI SECURITY ENGINE
                # ============================================================
                if payload_type in (PayloadType.URL, PayloadType.URI):
                    publish_progress(job_id, "url_check", base_progress, f"{label}Đang kiểm tra liên kết.")

                    # Single-phase URL analysis (Normalize -> Rules -> ML -> Local IOC -> Policy)
                    final_analysis, alert_code, color, title, msg, rec, norm = url_analyzer.analyze(payload)
                    mark_first_result()
                    emit_final(i, QRCodeResult(
                        payload=payload,
                        payload_type=payload_type,
                        bbox=bbox,
                        engine=engine,
                        url_analysis=final_analysis,
                        alert_code=alert_code,
                        alert_color=color,
                        alert_title=title,
                        alert_message=msg,
                        alert_recommendation=rec,
                        is_provisional=False,
                    ))
                    continue

                # ============================================================
                # BRANCH B: OTHER / TEXT PAYLOADS
                # ============================================================
                if payload_type == PayloadType.OTHER:
                    other_qr = build_other_result(payload, bbox=bbox, engine=engine)
                    mark_first_result()
                    emit_final(i, other_qr)
                    continue

                # ============================================================
                # BRANCH C: PAYMENT SECURITY ENGINE (VIETQR)
                # ============================================================
                vietqr_data = parse_vietqr(payload)
                qr_reasons: List[str] = []
                qr_completeness = "full"

                if vietqr_data.crc_valid and vietqr_data.structure_valid:
                    # Provisional: we know the receiver data, the comparison is still pending.
                    prov_vietqr = QRCodeResult(
                        payload=payload,
                        payload_type=PayloadType.VIETQR,
                        bbox=bbox,
                        engine=engine,
                        vietqr_data=vietqr_data,
                        alert_code=AlertCode.INSUFFICIENT_CONTEXT,
                        alert_color="#1565C0",
                        alert_title="Đã đọc được mã QR chuyển tiền",
                        alert_message="Đang so sánh thông tin chuyển tiền với chữ trên ảnh...",
                        alert_recommendation="Chưa chuyển tiền cho đến khi có kết quả.",
                        is_provisional=True,
                        risk_level="pending",
                    )
                    publish_event(
                        job_id=job_id,
                        event_type="provisional_result",
                        data={"qr_index": i, "total": total, "result": json.loads(prov_vietqr.model_dump_json())},
                    )
                    mark_first_result()
                    publish_progress(job_id, "payment_check", base_progress + 3, f"{label}Đang so sánh thông tin chuyển tiền.")
                    lines, source, ocr_status = get_context_lines(idx, base_progress + 5, bbox)
                    ocr_data = extract_context(lines, bbox, source=source, target_vietqr=vietqr_data)
                    if getattr(images[idx], "hidden_text_spans", 0):
                        qr_reasons.append("PDF_HIDDEN_TEXT")
                    if ocr_status in ("unavailable", "error"):
                        # OCR failure must never be read as "information matches"
                        qr_reasons.append(f"OCR_{ocr_status.upper()}")
                        qr_completeness = "partial"
                else:
                    ocr_data = OCRData(source="skipped", context_type="skipped")

                match_result, alert_code, color, title, message, rec = fuzzy_match_and_alert(vietqr_data, ocr_data)
                if qr_completeness == "partial" and alert_code == AlertCode.INSUFFICIENT_CONTEXT:
                    message = message + "\n• Hệ thống đọc chữ trên ảnh chưa hoạt động, nên chưa thể so sánh."

                payment_qr = QRCodeResult(
                    payload=payload,
                    payload_type=PayloadType.VIETQR,
                    bbox=bbox,
                    engine=engine,
                    vietqr_data=vietqr_data,
                    ocr_data=ocr_data,
                    match_result=match_result,
                    alert_code=alert_code,
                    alert_color=color,
                    alert_title=title,
                    alert_message=message,
                    alert_recommendation=rec,
                    analysis_completeness=qr_completeness,
                    reason_codes=qr_reasons + [alert_code.value],
                )
                emit_final(i, payment_qr)

            except (JobCancelled, SoftTimeLimitExceeded):
                raise
            except Exception as e:
                logger.error("Processing QR #%d failed in job %s: %s", i + 1, job_id, type(e).__name__)
                emit_final(i, build_error_result(payload, engine, bbox))


        # ── 5. Completion ──────────────────────────────────────────
        processed_results: List[QRCodeResult] = [processed[k] for k in sorted(processed)]
        if ocr_ms:
            timings["ocr"] = _ms(ocr_ms)
        result.qr_codes = processed_results
        result.status = JobStatus.COMPLETED
        if any(q.analysis_completeness != "full" for q in processed_results):
            result.analysis_completeness = "partial"
        _finish(
            r, job_id, result, started, timings, fhash=fhash,
            message=f"Đã kiểm tra xong {len(processed_results)} mã QR." if len(processed_results) > 1 else "Đã kiểm tra xong.",
        )

    except JobCancelled:
        _apply_error(result, "PROCESSING_ERROR", status=JobStatus.CANCELLED)
        result.error_code = "CANCELLED"
        result.user_message = "Bạn đã hủy lượt kiểm tra."
        result.recommended_action = "Bạn có thể kiểm tra lại bất cứ lúc nào."
        _finish(r, job_id, result, started, timings, step="cancelled")

    except SoftTimeLimitExceeded:
        logger.warning("Job %s exceeded soft time limit", job_id)
        _apply_error(result, "JOB_TIMEOUT")
        _finish(r, job_id, result, started, timings, step="error")

    except Exception as e:
        logger.error("Task failed for job %s: %s", job_id, type(e).__name__)
        _apply_error(result, "PROCESSING_ERROR")
        _finish(r, job_id, result, started, timings, step="error")

    finally:
        # Only ever delete the validated, server-generated path (never a path from the message).
        if validated_path:
            try:
                os.remove(validated_path)
            except OSError:
                pass
        if is_valid_job_id(job_id):
            release_job_slot_sync(r, job_id)


def _save_result(
    r: redis.Redis,
    job_id: str,
    result: ProcessingResult,
    fhash: Optional[str] = None,
):
    """Saves final processing result to Redis and updates the hash-based result cache."""
    try:
        payload = result.model_dump_json()
        r.setex(f"job:{job_id}:result", settings.RESULT_CACHE_TTL, payload)
        # Only complete, fully-analysed results are reusable. Partial / TI-failed / OCR-failed
        # results must be recomputed so a transient outage is never replayed as a verdict.
        if (
            fhash
            and result.status == JobStatus.COMPLETED
            and result.analysis_completeness == "full"
            and not result.warnings
        ):
            ttl = settings.FILE_RESULT_CACHE_TTL
            r.setex(result_cache_key(fhash), ttl, payload)
    except Exception as e:
        logger.error("Failed to save result to Redis for job %s: %s", job_id, type(e).__name__)
