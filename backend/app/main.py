"""
QR Guard - Main FastAPI Application
API Gateway: tiếp nhận file, validate, đẩy job vào Celery qua Redis
"""
import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager, suppress
from typing import AsyncGenerator

import redis.asyncio as aioredis
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.routes import router, websocket_job_stream
from app.core.body_limit import BodySizeLimitMiddleware
from app.core.config import settings
from app.core.errors import AppError, error_response

logger = logging.getLogger(__name__)

_HTTP_TO_CODE = {
    404: "JOB_NOT_FOUND",
    405: "INVALID_FILE",
    413: "FILE_TOO_LARGE",
    415: "UNSUPPORTED_FILE_TYPE",
    429: "RATE_LIMITED",
    503: "SERVICE_UNAVAILABLE",
}


def purge_orphan_files(storage_path: str, max_age_seconds: int) -> int:
    """Delete uploaded files older than max_age (worker crash / abandoned uploads). Never follows symlinks."""
    removed = 0
    now = time.time()
    try:
        entries = list(os.scandir(storage_path))
    except OSError:
        return 0
    for entry in entries:
        try:
            if not entry.name.endswith((".tmp", ".img", ".pdf")):
                continue
            st = entry.stat(follow_symlinks=False)
            if entry.is_symlink() or now - st.st_mtime > max_age_seconds:
                os.remove(entry.path)
                removed += 1
        except OSError:
            continue
    return removed


async def _janitor() -> None:
    while True:
        await asyncio.sleep(120)
        removed = await asyncio.to_thread(purge_orphan_files, settings.STORAGE_PATH, settings.orphan_file_min_age)
        if removed:
            logger.info("Retention janitor removed %d stale upload file(s)", removed)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    # Startup: connect Redis (credentials come from REDIS_URL / REDIS_URL_FILE, never logged)
    app.state.redis = aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
        socket_connect_timeout=3,
        health_check_interval=30,
    )
    janitor = asyncio.create_task(_janitor())
    yield
    janitor.cancel()
    with suppress(asyncio.CancelledError):
        await janitor
    # Shutdown: close Redis
    await app.state.redis.aclose()


_docs = settings.ENABLE_API_DOCS and not settings.is_production
app = FastAPI(
    title="QR Guard - Quishing Detection & VietQR Verification System",
    description="Threat Intelligence-Based Quishing Detection and Warning System",
    version="2.1.0",
    lifespan=lifespan,
    docs_url="/api/docs" if _docs else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if _docs else None,
)


# ─── Safe error handling: stable codes, never tracebacks ────────────────────
@app.exception_handler(AppError)
async def _app_error_handler(request: Request, exc: AppError):
    return error_response(exc.code, headers=exc.headers)


@app.exception_handler(RequestValidationError)
async def _validation_handler(request: Request, exc: RequestValidationError):
    return error_response("INVALID_FILE", message="Yêu cầu không hợp lệ hoặc thiếu tệp tải lên.")


@app.exception_handler(StarletteHTTPException)
async def _http_handler(request: Request, exc: StarletteHTTPException):
    return error_response(_HTTP_TO_CODE.get(exc.status_code, "INTERNAL_ERROR"))


@app.exception_handler(Exception)
async def _unhandled_handler(request: Request, exc: Exception):
    logger.error("Unhandled error on %s: %s", request.url.path, type(exc).__name__)
    return error_response("INTERNAL_ERROR")


# ─── Response hardening (defense in depth; Nginx sets the full header set) ──
@app.middleware("http")
async def _security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store, private")
        response.headers.setdefault("X-Frame-Options", "DENY")
    return response


# Refuse to run a production deployment with settings that silently disable protections.
for _msg in settings.production_config_warnings():
    logger.warning("Config: %s", _msg)
_cfg_errors = settings.production_config_errors()
if _cfg_errors:
    raise RuntimeError("Insecure production configuration: " + "; ".join(_cfg_errors))

# Enforce secure CORS policy: no wildcard when credentials enabled
# (in production cors_origins_list already drops loopback origins; same-origin needs no entry)
origins = [o for o in settings.cors_origins_list if o != "*"]
if not origins and not settings.is_production:
    origins = ["http://localhost:5173", "http://localhost:3000", "http://localhost", "http://127.0.0.1"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", settings.CSRF_HEADER_NAME],
    max_age=600,
)

# Bound the upload body while it is received (also covers chunked bodies without
# Content-Length, which would otherwise be spooled to disk before the route's size check).
app.add_middleware(
    BodySizeLimitMiddleware,
    path="/api/upload",
    limit_bytes=lambda: settings.MAX_FILE_SIZE_MB * 1024 * 1024 + 64 * 1024,
)

# Router: /api/upload, /api/result/{id}, /api/sse/{id}, /api/ws/{id}, /api/job/{id}
app.include_router(router, prefix="/api")
# Backward-compatible WebSocket path used by the frontend
app.websocket("/ws/{job_id}")(websocket_job_stream)
