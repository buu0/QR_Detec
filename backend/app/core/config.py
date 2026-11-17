"""
Configuration settings loaded from environment variables.

Secrets policy:
- Secrets (e.g. REDIS_URL with password) are injected at deploy time,
  either as environment variables or via `<NAME>_FILE` pointing to a file with
  restricted permissions (e.g. Docker secrets mounted at /run/secrets/...).
- Secret values are never logged. Use `settings.redacted()` for diagnostics.
"""
import os
from typing import List

from pydantic_settings import BaseSettings


_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Settings that may be provided through `<NAME>_FILE` (Docker/K8s secret files)
_SECRET_FILE_KEYS = ("REDIS_URL",)


def _load_secret_files() -> None:
    """If NAME_FILE is set and NAME is not, read the secret from the file into the environment."""
    for key in _SECRET_FILE_KEYS:
        file_path = os.environ.get(f"{key}_FILE")
        if file_path and not os.environ.get(key):
            try:
                with open(file_path, "r", encoding="utf-8") as fh:
                    os.environ[key] = fh.read().strip()
            except OSError:
                # Do not leak paths/contents; the feature depending on it degrades gracefully.
                pass


_load_secret_files()


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}


def _is_loopback_origin(origin: str) -> bool:
    """True for http(s)://localhost[:port], 127.0.0.0/8, ::1 — never valid production origins."""
    from urllib.parse import urlparse

    try:
        host = (urlparse(origin).hostname or "").lower()
    except ValueError:
        return False
    return host in _LOOPBACK_HOSTS or host.endswith(".localhost") or host.startswith("127.")


class Settings(BaseSettings):
    # === Runtime ===
    ENVIRONMENT: str = "development"          # development | production
    ENABLE_API_DOCS: bool = False             # OpenAPI docs disabled unless explicitly enabled

    # === Redis & Storage ===
    REDIS_URL: str = "redis://localhost:6379/0"
    STORAGE_PATH: str = os.path.join(_BASE_DIR, "storage")
    WECHAT_QR_MODEL_DIR: str = os.path.join(_BASE_DIR, "models", "wechat_qr")
    PADDLE_OCR_LANG: str = "vi"
    MAX_FILE_SIZE_MB: int = 50
    RESULT_CACHE_TTL: int = 3600              # job results / progress retention (seconds)
    FILE_RESULT_CACHE_TTL: int = 1800         # content-hash result cache (seconds)
    ORPHAN_FILE_MAX_AGE_SECONDS: int = 900    # uploaded files older than this are purged

    # === Security & CORS ===
    CORS_ALLOWED_ORIGINS: str = "http://localhost:5173,http://localhost:3000,http://localhost,http://127.0.0.1"

    # === Guest session / job authorization ===
    SESSION_COOKIE_NAME: str = "qrg_sid"
    SESSION_COOKIE_SECURE: bool = True        # set false ONLY for plain-http local development
    SESSION_COOKIE_MAX_AGE: int = 86400
    CSRF_HEADER_NAME: str = "X-QRGuard-Request"
    MAX_STREAMS_PER_SESSION: int = 6          # concurrent SSE/WS connections per session
    MAX_ACTIVE_JOBS_PER_SESSION: int = 3      # concurrent queued/processing jobs per session
    # Global admission control: a client can drop its cookie to get a new session, so the
    # per-session limit alone cannot protect the queue. Sized for a moderate VPS (2 workers).
    MAX_GLOBAL_ACTIVE_JOBS: int = 40
    # Concurrent jobs per client network (IPv4 address / IPv6 /64), independent of cookies,
    # so dropping the session cookie cannot take over the global queue. 0 disables the cap.
    # Sized above MAX_ACTIVE_JOBS_PER_SESSION to tolerate several users behind one NAT.
    MAX_ACTIVE_JOBS_PER_CLIENT: int = 8
    # Trust X-Real-IP for the client address. Correct when the API is only reachable through the
    # bundled nginx (internal `app` network), which always overwrites that header.
    TRUST_PROXY_HEADERS: bool = True
    STREAM_MAX_SECONDS: int = 300
    # Inbound WebSocket frames per window (the client only needs occasional keep-alive pings).
    WS_MAX_INBOUND_MESSAGES: int = 10
    WS_INBOUND_WINDOW_SECONDS: float = 10.0

    # === URL Normalization & Security Limits ===
    URL_LENGTH_LIMIT: int = 4096

    # === Local Threat Intelligence (Local IOC Feed Only) ===
    TI_LOCAL_FEED_PATH: str = ""     # Optional path to local JSON/JSONL IOC feed
    TI_LOCAL_FEED_SHA256: str = ""   # Optional pinned digest; feed is rejected if it mismatches
    # Local IOC freshness: indicators older than this (last_seen/first_seen) or past their
    # explicit expires_at are treated as stale (reported, never escalated to MALICIOUS).
    TI_IOC_MAX_AGE_DAYS: int = 90

    # === URL Risk Policy Thresholds ===
    URL_MODEL_HIGH_THRESHOLD: float = 0.7850
    URL_MODEL_MEDIUM_THRESHOLD: float = 0.50

    # === XGBoost Model Configuration ===
    XGB_MODEL_DIR: str = os.path.join(_BASE_DIR, "models", "url_xgb")
    XGB_MANIFEST_PATH: str = os.path.join(_BASE_DIR, "models", "url_xgb", "manifest.json")
    XGB_MODEL_PATH: str = os.path.join(_BASE_DIR, "models", "url_xgb", "model.ubj")
    XGB_REQUIRE_SHA256: bool = True            # refuse a model whose manifest has no sha256
    XGB_REQUIRE_GOLDEN_VECTORS: bool = True    # refuse a model without golden_vectors.json
    XGB_GOLDEN_TOLERANCE: float = 1e-4

    # === QR Decoding Strategy ===
    QR_DECODE_MODE: str = "fast"     # "fast" (pyzbar early-stop) or "complete" (ensemble pyzbar + WeChatQR)
    QR_FAST_MULTI_SWEEP: bool = True # fast mode: one extra CNN sweep so a 2nd (sticker) QR is not missed
    MAX_QR_PER_JOB: int = 20         # QR codes analysed per upload; extra codes => partial result

    # === Resource Hardening Limits (Decompression Bomb & Denial of Service Protection) ===
    MAX_IMAGE_WIDTH: int = 8000
    MAX_IMAGE_HEIGHT: int = 8000
    MAX_IMAGE_PIXELS: int = 36000000      # 36 MP max
    MAX_PDF_PAGES: int = 10
    MAX_PDF_PAGE_WIDTH: int = 4000
    MAX_PDF_PAGE_HEIGHT: int = 4000
    MAX_PDF_PAGE_PIXELS: int = 16000000   # 16 MP max per page
    MAX_TOTAL_RENDERED_PIXELS: int = 50000000  # 50 MP total across all pages

    # === Celery Task Limits ===
    CELERY_TASK_SOFT_TIME_LIMIT: int = 180  # 3 minutes
    CELERY_TASK_HARD_TIME_LIMIT: int = 240  # 4 minutes
    # A job that waited longer than this in the queue is rejected by the worker
    # (SERVICE_UNAVAILABLE) instead of running late. Bounds the life of every admission slot.
    JOB_QUEUE_MAX_WAIT_SECONDS: int = 300

    @property
    def job_admission_ttl(self) -> int:
        """Upper bound on queued + running time of one job (admission slot lifetime)."""
        return self.JOB_QUEUE_MAX_WAIT_SECONDS + self.CELERY_TASK_HARD_TIME_LIMIT + 60

    @property
    def orphan_file_min_age(self) -> int:
        """Janitor never removes an upload that could still belong to a queued/running job."""
        return max(self.ORPHAN_FILE_MAX_AGE_SECONDS, self.job_admission_ttl + 60)

    @property
    def cors_origins_list(self) -> List[str]:
        if not self.CORS_ALLOWED_ORIGINS:
            return []
        origins = [origin.strip() for origin in self.CORS_ALLOWED_ORIGINS.split(",") if origin.strip()]
        if self.is_production:
            # The localhost defaults (or a stray "*") must never be trusted in production.
            # Same-origin requests keep working without any allowlist entry.
            origins = [o for o in origins if o != "*" and not _is_loopback_origin(o)]
        return origins

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    def production_config_errors(self) -> List[str]:
        """Settings that must never reach a production deployment."""
        if not self.is_production:
            return []
        errors = []
        if not self.SESSION_COOKIE_SECURE:
            errors.append("SESSION_COOKIE_SECURE=false is not allowed when ENVIRONMENT=production")
        return errors

    def production_config_warnings(self) -> List[str]:
        if not self.is_production:
            return []
        warnings = []
        raw = [o.strip() for o in (self.CORS_ALLOWED_ORIGINS or "").split(",") if o.strip()]
        dropped = [o for o in raw if o == "*" or _is_loopback_origin(o)]
        if dropped:
            warnings.append(f"Ignoring {len(dropped)} loopback/wildcard CORS origin(s) in production")
        if any(o.lower().startswith("http://") for o in self.cors_origins_list):
            warnings.append("CORS_ALLOWED_ORIGINS contains http:// origins in production (use https://)")
        return warnings

    def redacted(self) -> dict:
        """Diagnostic view of settings with secrets masked (safe to log)."""
        data = self.model_dump()
        url = data.get("REDIS_URL", "")
        if "@" in url:
            scheme, rest = url.split("://", 1) if "://" in url else ("redis", url)
            data["REDIS_URL"] = f"{scheme}://***@{rest.rsplit('@', 1)[1]}"
        return data

    model_config = {
        "env_file": ".env",
        "case_sensitive": True,
        "extra": "ignore",
    }


settings = Settings()


# Ensure storage directory exists with owner-only permissions where supported
os.makedirs(settings.STORAGE_PATH, exist_ok=True)
try:
    os.chmod(settings.STORAGE_PATH, 0o700)
except OSError:
    pass
