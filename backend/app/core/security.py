"""
Guest session & job authorization (no login required).

Model:
- Each browser gets a random 256-bit session id in an HttpOnly cookie (never in URL/localStorage).
- Redis stores only SHA-256(session_id) as the owner of a job: `job:{job_id}:owner`.
- Every read of a job (result / SSE / WebSocket / cancel) requires the caller's cookie to
  hash to the stored owner. Knowing a job_id alone is NOT sufficient.
- Unknown / foreign jobs are reported as 404 to avoid confirming existence.
- State-changing requests require a custom header (forces CORS preflight) plus an
  Origin allowlist / same-origin check (CSRF defense in depth next to SameSite=Strict).
"""
import hashlib
import hmac
import ipaddress
import logging
import re
import secrets
import time
from typing import Optional, Tuple
from urllib.parse import urlparse

from app.core.config import settings

logger = logging.getLogger(__name__)

JOB_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_SID_RE = re.compile(r"^[A-Za-z0-9_\-]{32,128}$")


# ─── Identifiers ────────────────────────────────────────────────────────────
def is_valid_job_id(job_id: str) -> bool:
    return bool(job_id) and bool(JOB_ID_RE.match(job_id))


def new_session_id() -> str:
    return secrets.token_urlsafe(32)


def session_fingerprint(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("ascii")).hexdigest()


def read_session_id(cookies) -> Optional[str]:
    sid = cookies.get(settings.SESSION_COOKIE_NAME) if cookies else None
    if sid and _SID_RE.match(sid):
        return sid
    return None


def set_session_cookie(response, session_id: str, secure: Optional[bool] = None) -> None:
    is_secure = settings.SESSION_COOKIE_SECURE if secure is None else secure
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_id,
        max_age=settings.SESSION_COOKIE_MAX_AGE,
        httponly=True,
        secure=is_secure,
        samesite="strict",
        path="/",
    )


# ─── Redis keys ─────────────────────────────────────────────────────────────
def owner_key(job_id: str) -> str:
    return f"job:{job_id}:owner"


def stream_slots_key(fingerprint: str) -> str:
    return f"sess:{fingerprint}:streams"


def job_slots_key(fingerprint: str) -> str:
    return f"sess:{fingerprint}:active_jobs"


def cancel_key(job_id: str) -> str:
    return f"job:{job_id}:cancelled"


def events_key(job_id: str) -> str:
    return f"job:{job_id}:events"


def job_slot_flag_key(job_id: str) -> str:
    return f"job:{job_id}:slot"


def meta_key(job_id: str) -> str:
    return f"job:{job_id}:meta"


# Global (cross-session) admission set: member = job_id, score = admission time.
GLOBAL_JOBS_KEY = "global:active_jobs"


# ─── Ownership (async, API side) ────────────────────────────────────────────
async def bind_job_owner(redis, job_id: str, session_id: str) -> None:
    await redis.setex(owner_key(job_id), settings.RESULT_CACHE_TTL, session_fingerprint(session_id))


async def is_job_owner(redis, job_id: str, session_id: Optional[str]) -> bool:
    if not session_id or not is_valid_job_id(job_id):
        return False
    stored = await redis.get(owner_key(job_id))
    if not stored:
        return False
    return hmac.compare_digest(str(stored), session_fingerprint(session_id))


# ─── Origin / CSRF ──────────────────────────────────────────────────────────
_DEFAULT_PORTS = {"http": 80, "https": 443}
OriginTuple = Tuple[str, str, int]  # (scheme, host, port) — RFC 6454 origin


def parse_origin(value: Optional[str]) -> Optional[OriginTuple]:
    """Parse an Origin header / allowlist entry into (scheme, host, port).

    Returns None for anything that is not a plain http(s) origin: "null", other schemes,
    user-info, path/query/fragment, or an invalid port. Default ports are made explicit so
    "https://a.example" and "https://a.example:443" compare equal, but http and https never do.
    """
    if not value:
        return None
    text = value.strip()
    if not text or text.lower() == "null":
        return None
    try:
        parsed = urlparse(text)
        port = parsed.port
    except ValueError:
        return None
    scheme = (parsed.scheme or "").lower()
    if scheme not in _DEFAULT_PORTS or not parsed.hostname:
        return None
    if parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        return None
    return scheme, parsed.hostname.lower().rstrip("."), port or _DEFAULT_PORTS[scheme]


def _parse_host_header(host: Optional[str], scheme: str) -> Optional[Tuple[str, int]]:
    """Host header ("example.com", "example.com:8443", "[::1]:8080") -> (host, port)."""
    if not host:
        return None
    try:
        parsed = urlparse("//" + host.strip())
        port = parsed.port
    except ValueError:
        return None
    if not parsed.hostname or parsed.username or parsed.password or parsed.path:
        return None
    return parsed.hostname.lower().rstrip("."), port or _DEFAULT_PORTS[scheme]


def origin_allowed(origin: Optional[str], host: Optional[str]) -> bool:
    """Accept an explicitly allowlisted origin, or same-origin (Origin host:port == Host header).

    Scheme-aware Origin hardening:
    - The scheme is part of the comparison: an allowlisted "https://x" never admits "http://x".
    - In production only https origins are accepted (also for same-origin), so a cleartext page
      on the same host name cannot drive state-changing requests or open a WebSocket.
    """
    parsed = parse_origin(origin)
    if parsed is None:
        return False
    scheme, o_host, o_port = parsed
    if settings.is_production and scheme != "https":
        return False

    for allowed in settings.cors_origins_list:
        if parse_origin(allowed) == parsed:
            return True

    host_tuple = _parse_host_header(host, scheme)
    return host_tuple is not None and host_tuple == (o_host, o_port)


def csrf_ok(headers) -> bool:
    """Custom header is mandatory; if the browser sent Origin it must be allowed."""
    target_name = settings.CSRF_HEADER_NAME.lower()
    csrf_val = None
    origin = None
    host = None

    # Handle Starlette Headers or dict or list-of-tuples
    items = headers.items() if hasattr(headers, "items") else headers
    for k, v in items:
        k_lower = k.lower()
        if k_lower == target_name:
            csrf_val = v
        elif k_lower == "origin":
            origin = v
        elif k_lower == "host":
            host = v

    if csrf_val != "1":
        # The header value is attacker-controlled: log only whether it was present.
        logger.warning(
            "CSRF rejected: %s %s",
            settings.CSRF_HEADER_NAME,
            "missing" if csrf_val is None else "invalid",
        )
        return False

    if origin is not None and not origin_allowed(origin, host):
        logger.warning(
            "CSRF rejected: origin %r not allowed for host %r",
            _log_safe(origin),
            _log_safe(host),
        )
        return False
    return True


def _log_safe(value, limit: int = 80):
    """Bounded, repr-escaped form of a client-supplied header for logs (no log injection/flooding)."""
    if value is None:
        return None
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"


# ─── Resource slots (atomic) ────────────────────────────────────────────────
# Every slot operation is ONE Redis round trip running a Lua script, so concurrent API
# workers can neither over-admit nor wrongly reject each other, a cancelled request can never
# leave a counter without TTL, and a rejected request never extends the counter's lifetime.
# The scripts only call GET/INCR/DECR/DEL/EXPIRE/TTL/Z* (allowed by the qrguard ACL).

ACQUIRE_SLOT_LUA = """
local limit = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local current = tonumber(redis.call('GET', KEYS[1]) or '0') or 0
if current >= limit then
  return 0
end
redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], ttl)
return 1
"""

RELEASE_SLOT_LUA = """
local current = tonumber(redis.call('GET', KEYS[1]) or '0') or 0
if current <= 1 then
  redis.call('DEL', KEYS[1])
  return 0
end
return redis.call('DECR', KEYS[1])
"""

ACQUIRE_GLOBAL_SLOT_LUA = """
local now = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local ttl = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - ttl)
if redis.call('ZSCORE', KEYS[1], ARGV[4]) then
  return 1
end
if redis.call('ZCARD', KEYS[1]) >= limit then
  return 0
end
redis.call('ZADD', KEYS[1], now, ARGV[4])
redis.call('EXPIRE', KEYS[1], ttl)
return 1
"""


async def acquire_slot(redis, key: str, limit: int, ttl: int) -> bool:
    """Atomically take one of `limit` slots under `key`. A rejection changes nothing."""
    return int(await redis.eval(ACQUIRE_SLOT_LUA, 1, key, int(limit), int(ttl))) == 1


async def release_slot(redis, key: str) -> None:
    """Atomically give one slot back; the counter is deleted when it reaches zero."""
    try:
        await redis.eval(RELEASE_SLOT_LUA, 1, key)
    except Exception:
        pass


async def acquire_global_slot(redis, job_id: str, limit: int, stale_after: int) -> bool:
    """Admission control across ALL sessions (a client can always mint new cookies).
    Entries older than `stale_after` seconds (crashed/killed jobs) are pruned first.
    Idempotent for the same job_id."""
    now = time.time()
    res = await redis.eval(ACQUIRE_GLOBAL_SLOT_LUA, 1, GLOBAL_JOBS_KEY, now, int(limit), int(stale_after), job_id)
    return int(res) == 1


# ─── Per-client admission ───────────────────────────────────────────────────
# Guest sessions are free to mint, so the per-session cap alone can be sidestepped by never
# sending the cookie back. A second cap keyed on the client network closes that gap:
# IPv4 -> the address, IPv6 -> its /64 (one subscriber normally owns a whole /64, same rule as
# nginx's $qrg_client_key). Redis only ever stores a SHA-256 bucket id, never the raw IP.

def client_ip(headers, peer: Optional[str]) -> str:
    """Client address. Behind nginx the API trusts X-Real-IP (nginx always overwrites it with
    $remote_addr); with TRUST_PROXY_HEADERS=false only the TCP peer address is used."""
    if settings.TRUST_PROXY_HEADERS and headers is not None:
        real_ip = headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
    return (peer or "").strip()


def client_bucket(ip: Optional[str]) -> str:
    """Stable, privacy-preserving bucket id for a client address."""
    text = (ip or "").strip()
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        network = f"other:{text[:64] or 'unknown'}"
    else:
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        if isinstance(addr, ipaddress.IPv6Address):
            network = f"v6:{ipaddress.IPv6Network((addr, 64), strict=False)}"
        else:
            network = f"v4:{addr}"
    return hashlib.sha256(network.encode("utf-8")).hexdigest()[:32]


def client_slots_key(bucket: str) -> str:
    return f"client:{bucket}:active_jobs"


def client_slot_flag_key(job_id: str) -> str:
    """Holds the client_slots_key a job was admitted under (so the worker can release it)."""
    return f"job:{job_id}:cslot"


# ─── Worker side (sync redis client) ────────────────────────────────────────
def release_job_slot_sync(redis_sync, job_id: str) -> None:
    """Called by the worker when a job finishes (success, failure, or cancel). Idempotent:
    only the caller that actually deletes a flag key gives the corresponding slot back."""
    try:
        redis_sync.zrem(GLOBAL_JOBS_KEY, job_id)
    except Exception:
        pass
    try:
        ckey = redis_sync.get(client_slot_flag_key(job_id))
        if ckey and redis_sync.delete(client_slot_flag_key(job_id)):
            redis_sync.eval(RELEASE_SLOT_LUA, 1, ckey)
    except Exception:
        pass
    try:
        fp = redis_sync.get(owner_key(job_id))
        if not fp:
            return
        if not redis_sync.delete(job_slot_flag_key(job_id)):
            return
        redis_sync.eval(RELEASE_SLOT_LUA, 1, job_slots_key(fp))
    except Exception:
        pass


async def release_job_slot(redis, job_id: str, fingerprint: str) -> None:
    """API-side idempotent release (upload failure / cancel before worker start)."""
    try:
        await redis.zrem(GLOBAL_JOBS_KEY, job_id)
    except Exception:
        pass
    try:
        ckey = await redis.get(client_slot_flag_key(job_id))
        if ckey and await redis.delete(client_slot_flag_key(job_id)):
            await release_slot(redis, ckey)
    except Exception:
        pass
    try:
        if not await redis.delete(job_slot_flag_key(job_id)):
            return
        await release_slot(redis, job_slots_key(fingerprint))
    except Exception:
        pass
