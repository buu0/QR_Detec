"""
Threat Intelligence (TI) Service — Local IOC Feed Only
======================================================
Architecture:
- Single source of truth: verified, cryptographically pinned local IOC feed in memory.
- Zero network requests: no external APIs, no remote providers, no network lookups.
- Zero L1/L2 TI caching: in-memory lookup over immutable local IOC snapshot.
  Old Redis TI keys (ti:url:*, ti:domain:*) have zero influence on verdicts.

Status Semantics:
- MATCH: indicator matched active local threat feed (verdict: known_malicious or suspicious).
- NO_MATCH: local feed was successfully loaded and consulted, but no indicator matched.
            (NO_MATCH != SAFE; NO_MATCH != TI_NOT_CONSULTED).
- NOT_CONFIGURED: expected local feed file is not configured.
- INTEGRITY_FAILED: feed exists but SHA-256 checksum validation failed (tamper resistance).
- LOAD_ERROR: feed file could not be read or parsed.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import tldextract

from app.core.config import settings
from app.models.schemas import ThreatIntelEvidence
from app.services.url_security.normalizer import NormalizedURL, URLNormalizer, _normalize_idn_to_ascii

logger = logging.getLogger(__name__)

# Offline PSL extractor with private suffixes enabled (guarantees tenant isolation for github.io, etc.)
_OFFLINE_PSL_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=None,
    include_psl_private_domains=True,
    cache_dir=None,
)

# Severity ordering used when multiple pieces of evidence exist for the same URL.
_SEVERITY = {"known_malicious": 4, "suspicious": 3, "no_known_risk": 2, "clean": 2, "unknown": 1}

# IOC feeds use free-form verdict strings; map them onto statuses understood by policy.
_IOC_SUSPICIOUS_VERDICTS = {"suspicious", "suspect", "grayware", "potentially_unwanted", "pua", "spam"}
_IOC_NON_INDICATOR_VERDICTS = {"clean", "benign", "harmless", "no_known_risk", "allow", "allowlist", "whitelist"}
_MAX_PROVENANCE = 10


def _severity(status: Optional[str]) -> int:
    return _SEVERITY.get(status or "", 0)


def _normalize_ioc_verdict(raw: Any) -> Optional[str]:
    """'malicious'/'phishing'/missing -> known_malicious; suspicious-family -> suspicious;
    allowlist-style values -> None (a blocklist feed must not whitelist anything)."""
    v = str(raw or "").strip().lower()
    if v in _IOC_NON_INDICATOR_VERDICTS:
        return None
    if v in _IOC_SUSPICIOUS_VERDICTS:
        return "suspicious"
    return "known_malicious"


def _safe_conf(raw: Any, default: float) -> float:
    try:
        return max(0.0, min(1.0, float(raw)))
    except (TypeError, ValueError):
        return default


def _parse_ts(raw: Any) -> Optional[float]:
    """ISO-8601 date/datetime (UTC assumed) or epoch seconds -> epoch seconds (UTC)."""
    if raw is None or raw == "":
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    text = str(raw).strip()
    if text.isdigit():
        return float(text)
    text = text.replace("Z", "").replace("z", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            st = time.strptime(text.split(".")[0], fmt)
            dt = datetime(st.tm_year, st.tm_mon, st.tm_mday, st.tm_hour, st.tm_min, st.tm_sec, tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    return None


def _hash_url(normalized_url: str) -> str:
    return hashlib.sha256(normalized_url.encode("utf-8")).hexdigest()


def privacy_safe_lookup_url(norm: NormalizedURL) -> str:
    """Canonical representation of URL for hash lookup (scheme://host[:port]/path)."""
    if not norm.hostname:
        return norm.normalized_url or norm.original_url
    scheme = norm.scheme or "http"
    host = norm.hostname
    if norm.port and not ((scheme == "http" and norm.port == 80) or (scheme == "https" and norm.port == 443)):
        host = f"{host}:{norm.port}"
    path = norm.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{host}{path}"


class LocalFeedStatus(str):
    """Case-insensitive string to seamlessly support legacy lowercase ('loaded', 'integrity_failed', 'not_configured', 'load_error')
    and Requirement 4 uppercase ('LOADED', 'INTEGRITY_FAILED', 'NOT_CONFIGURED', 'LOAD_ERROR')."""
    def __eq__(self, other):
        if isinstance(other, str):
            return self.lower() == other.lower()
        return super().__eq__(other)

    def __hash__(self):
        return hash(self.lower())


class ThreatIntelService:
    """
    Threat Intelligence Service using an immutable, verified Local IOC snapshot.
    Zero network requests. Zero L1/L2 Redis caching.
    """

    def __init__(
        self,
        feed_path: Optional[str] = None,
        feed_sha256: Optional[str] = None,
    ):
        self._local_iocs: Dict[str, List[dict]] = {}
        self.local_feed_status: LocalFeedStatus = LocalFeedStatus("NOT_CONFIGURED")  # NOT_CONFIGURED | INTEGRITY_FAILED | LOAD_ERROR | LOADED
        self.local_feed_count: int = 0
        self.local_feed_sha256: Optional[str] = None
        self._normalizer = URLNormalizer()
        self._load_local_feed(feed_path=feed_path, feed_sha256=feed_sha256)

    def get_feed_sha256(self) -> Optional[str]:
        return self.local_feed_sha256 if self.local_feed_status == "LOADED" else None

    # ─────────────────────────────── local IOC feed loader ───────────────────────────────
    def _resolve_feed_path(self, override_path: Optional[str]) -> Optional[str]:
        if override_path:
            return override_path
        cfg_path = getattr(settings, "TI_LOCAL_FEED_PATH", None) or os.environ.get("TI_LOCAL_FEED_PATH")
        if cfg_path and os.path.exists(cfg_path):
            return cfg_path
        # Fallback to repo-relative ti_feed/ioc_feed.jsonl if present
        repo_root = Path(__file__).resolve().parents[4]
        candidate = repo_root / "ti_feed" / "ioc_feed.jsonl"
        if candidate.exists():
            return str(candidate)
        return cfg_path

    def _load_local_feed(self, feed_path: Optional[str] = None, feed_sha256: Optional[str] = None) -> None:
        target_path = self._resolve_feed_path(feed_path)
        if not target_path or not os.path.exists(target_path):
            self.local_feed_status = LocalFeedStatus("NOT_CONFIGURED")
            return

        try:
            with open(target_path, "rb") as f:
                raw = f.read()

            actual_sha256 = hashlib.sha256(raw).hexdigest()

            # Integrity pin check: if expected SHA-256 configured, refuse tampered feed
            if feed_path is not None:
                expected = (feed_sha256 or "").strip().lower()
            else:
                expected = (feed_sha256 or getattr(settings, "TI_LOCAL_FEED_SHA256", "") or os.environ.get("TI_LOCAL_FEED_SHA256") or "").strip().lower()

            env_mode = (getattr(settings, "ENVIRONMENT", "") or os.environ.get("ENVIRONMENT", "")).lower()
            is_secure_mode = env_mode in ("production", "research", "security") or getattr(settings, "TI_REQUIRE_PIN", False)

            if not expected:
                if is_secure_mode:
                    self.local_feed_status = LocalFeedStatus("NOT_CONFIGURED")
                    logger.warning(
                        "Local IOC feed configured at %s but expected SHA-256 pin is missing in %s mode; refusing unverified feed",
                        target_path, env_mode,
                    )
                    return
            else:
                if not hmac.compare_digest(actual_sha256, expected):
                    self.local_feed_status = LocalFeedStatus("INTEGRITY_FAILED")
                    logger.error("Local IOC feed integrity check FAILED (expected %s, got %s)", expected, actual_sha256)
                    return

            content = raw.decode("utf-8").strip()
            if content.startswith("["):
                records_iter = json.loads(content)
            else:
                records_iter = (json.loads(line) for line in content.splitlines() if line.strip())

            canonical_url_re = re.compile(
                r"^(https?)://([a-z0-9-]+(?:\.[a-z0-9-]+)+(?::(?!80$|443$)[1-9][0-9]{0,4})?)(/[^\s\\]*)$"
            )
            count = 0
            shared_meta: Dict[tuple, dict] = {}
            for rec in records_iter:
                if not isinstance(rec, dict):
                    continue
                verdict = _normalize_ioc_verdict(rec.get("verdict"))
                if verdict is None:
                    continue
                rec = dict(rec)
                rec["verdict"] = verdict
                rec["revoked"] = bool(rec.get("revoked")) or str(rec.get("status", "")).lower() == "revoked"
                raw_dom = str(rec.pop("domain", "") or "").strip().lower().rstrip(".")
                domain = raw_dom if raw_dom.isascii() else _normalize_idn_to_ascii(raw_dom)
                url_hash = str(rec.pop("url_hash", "") or "").strip().lower()
                raw_url = str(rec.pop("url", "") or "").strip()
                if raw_url and not url_hash:
                    m = canonical_url_re.match(raw_url)
                    if m and ".0" not in m.group(2) and not m.group(2).startswith("0"):
                        url_hash = _hash_url(raw_url)
                    else:
                        n = self._normalizer.normalize(raw_url)
                        if n.is_valid and n.normalized_url:
                            url_hash = _hash_url(n.normalized_url)
                meta_key = tuple(sorted((k, repr(v)) for k, v in rec.items()))
                rec = shared_meta.setdefault(meta_key, rec)
                if domain:
                    self._local_iocs.setdefault(f"domain:{domain}", []).append(rec)
                    count += 1
                if url_hash:
                    self._local_iocs.setdefault(f"url:{url_hash}", []).append(rec)
                    count += 1

            self.local_feed_count = count
            self.local_feed_sha256 = actual_sha256
            self.local_feed_status = LocalFeedStatus("LOADED")
            logger.info("Loaded %d indicators from local IOC feed (SHA-256: %s)", count, actual_sha256[:16])
        except Exception as e:
            self.local_feed_status = LocalFeedStatus("LOAD_ERROR")
            logger.warning("Failed to load local IOC feed: %s", type(e).__name__)

    @staticmethod
    def _is_stale(rec: dict, now: float) -> bool:
        expires = _parse_ts(rec.get("expires_at"))
        if expires is not None and expires < now:
            return True
        seen = _parse_ts(rec.get("last_seen")) or _parse_ts(rec.get("first_seen"))
        max_days = getattr(settings, "TI_IOC_MAX_AGE_DAYS", 90)
        if seen is not None and now - seen > max_days * 86400:
            return True
        return False

    def _ioc_evidence(self, records: List[dict], default_conf: float, details: str,
                       scope: str = "ioc") -> Optional[ThreatIntelEvidence]:
        """Merge non-revoked records for one indicator into a typed evidence object."""
        now = time.time()
        active = [r for r in records if not r.get("revoked")]
        if not active:
            return None
        fresh = [r for r in active if not self._is_stale(r, now)]
        basis = fresh or active
        freshness = "fresh" if fresh else "stale"
        status = max((r["verdict"] for r in basis), key=_severity)

        def _src(r: dict) -> str:
            return str(r.get("source") or "Local IOC")

        distinct = sorted({_src(r).strip().lower(): _src(r) for r in basis}.values())
        malicious_sources = {_src(r).strip().lower() for r in basis if r["verdict"] == "known_malicious"}
        suspicious_sources = {_src(r).strip().lower() for r in basis if r["verdict"] == "suspicious"}
        provenance = [{
            "source": _src(r),
            "verdict": r["verdict"],
            "indicator_type": r.get("indicator_type"),
            "first_seen": r.get("first_seen"),
            "last_seen": r.get("last_seen"),
            "expires_at": r.get("expires_at"),
            "confidence": _safe_conf(r.get("confidence"), default_conf),
            "stale": self._is_stale(r, now),
        } for r in active[:_MAX_PROVENANCE]]
        if freshness == "stale":
            details = f"{details} — dữ liệu IOC đã hết hạn, chưa được xác nhận lại"

        return ThreatIntelEvidence(
            status=status,
            local_ti_status="MATCH",
            confidence=max(_safe_conf(r.get("confidence"), default_conf) for r in basis),
            sources=distinct or ["Local IOC"],
            malicious_count=len(malicious_sources),
            suspicious_count=len(suspicious_sources),
            last_checked=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            details=details,
            scope=scope,
            provenance=provenance,
            freshness=freshness,
            distinct_sources=len(distinct),
        )

    def _match_ioc_domain(self, host: str) -> Optional[Tuple[str, List[dict]]]:
        if not host:
            return None
        host = _normalize_idn_to_ascii(host.strip().lower().rstrip("."))
        # 1. Exact match on host
        recs = self._local_iocs.get(f"domain:{host}")
        if recs:
            return host, recs

        # 2. Registrable domain (eTLD+1) boundary check via offline PSL with private suffixes
        labels = host.split(".")
        if len(labels) <= 1:
            return None

        ext = _OFFLINE_PSL_EXTRACTOR(host)
        if ext.suffix and ext.domain:
            registrable_domain = f"{ext.domain}.{ext.suffix}".lower()
        else:
            # Fallback for reserved/test TLDs (e.g. .example, .test, .local) or unlisted suffixes
            registrable_domain = ".".join(labels[-2:]).lower()

        if host == registrable_domain:
            return None

        # 3. Walk parent domains only down to registrable_domain (inclusive)
        # Prevents traversing past safe tenant boundary (e.g. evil.github.io -> github.io prohibited)
        reg_labels_count = len(registrable_domain.split("."))
        for i in range(1, len(labels) - reg_labels_count + 1):
            candidate = ".".join(labels[i:])
            recs = self._local_iocs.get(f"domain:{candidate}")
            if recs:
                return candidate, recs
        return None

    def _local_ioc_lookup(self, norm: NormalizedURL) -> Optional[ThreatIntelEvidence]:
        host = norm.hostname.lower().rstrip(".") if norm.hostname else ""
        candidates: List[ThreatIntelEvidence] = []

        hashes = {_hash_url(norm.normalized_url or norm.original_url)}
        if norm.hostname and norm.scheme in ("http", "https"):
            hashes.add(_hash_url(privacy_safe_lookup_url(norm)))
        for h in hashes:
            recs = self._local_iocs.get(f"url:{h}")
            if recs:
                first = recs[0]
                ev = self._ioc_evidence(recs, 0.95, f"Exact URL matched local IOC: {first.get('indicator_type', 'phishing')}")
                if ev:
                    candidates.append(ev)

        if host:
            match = self._match_ioc_domain(host)
            if match:
                matched, recs = match
                where = "Domain" if matched == host else "Parent domain"
                ev = self._ioc_evidence(recs, 0.90, f"{where} matched local IOC: {recs[0].get('indicator_type', 'phishing')}")
                if ev:
                    candidates.append(ev)

        # Open-redirect wrappers: destination embedded in query/path. Checked locally only.
        for embedded in (getattr(norm, "embedded_urls", None) or [])[:5]:
            inner = self._normalizer.normalize(embedded)
            if not inner.is_valid or not inner.hostname or inner.hostname == host:
                continue
            inner_hashes = {_hash_url(inner.normalized_url or inner.original_url)}
            if inner.scheme in ("http", "https"):
                inner_hashes.add(_hash_url(privacy_safe_lookup_url(inner)))
            for ih in inner_hashes:
                recs = self._local_iocs.get(f"url:{ih}")
                if recs:
                    ev = self._ioc_evidence(
                        recs, 0.90,
                        f"Địa chỉ đích lồng bên trong liên kết ({inner.hostname}) khớp URL IOC cục bộ",
                        scope="ioc_embedded",
                    )
                    if ev:
                        candidates.append(ev)
            match = self._match_ioc_domain(inner.hostname)
            if match:
                _, recs = match
                ev = self._ioc_evidence(
                    recs, 0.85,
                    f"Địa chỉ đích lồng bên trong liên kết ({inner.hostname}) khớp IOC cục bộ",
                    scope="ioc_embedded",
                )
                if ev:
                    candidates.append(ev)

        if not candidates:
            return None
        return max(candidates, key=lambda e: (e.freshness == "fresh", _severity(e.status)))

    def query(self, norm: NormalizedURL) -> ThreatIntelEvidence:
        """
        Pure Local IOC query over in-memory feed.
        Never contacts remote network. Never uses L1/L2 Redis caches.
        """
        # 1. Feed availability checks
        if self.local_feed_status == "NOT_CONFIGURED":
            return ThreatIntelEvidence(
                status="unknown",
                local_ti_status="NOT_CONFIGURED",
                confidence=0.0,
                sources=[],
                details="Local IOC feed is not configured.",
            )
        if self.local_feed_status == "INTEGRITY_FAILED":
            return ThreatIntelEvidence(
                status="unknown",
                local_ti_status="INTEGRITY_FAILED",
                confidence=0.0,
                sources=[],
                details="Local IOC feed failed SHA-256 integrity verification.",
            )
        if self.local_feed_status == "LOAD_ERROR":
            return ThreatIntelEvidence(
                status="unknown",
                local_ti_status="LOAD_ERROR",
                confidence=0.0,
                sources=[],
                details="Local IOC feed could not be loaded or parsed.",
            )

        # 2. Local IOC match lookup
        ioc_ev = self._local_ioc_lookup(norm)
        if ioc_ev is not None:
            return ioc_ev

        # 3. Local IOC miss: NO MATCH (never certified safe, distinct from error)
        return ThreatIntelEvidence(
            status="unknown",
            local_ti_status="NO_MATCH",
            confidence=0.0,
            sources=["Local IOC"],
            malicious_count=0,
            suspicious_count=0,
            last_checked=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            details="NO KNOWN IOC MATCH: Local IOC consulted; no matching indicator found.",
            freshness="unknown",
        )

    def local_ioc_check_status(self, ti: ThreatIntelEvidence) -> str:
        """Maps typed local_ti_status to a checks_performed status string."""
        if ti.local_ti_status == "MATCH":
            return "stale" if ti.freshness == "stale" else "match"
        elif ti.local_ti_status == "NO_MATCH":
            return "no_match"
        elif ti.local_ti_status == "NOT_CONFIGURED":
            return "not_configured"
        elif ti.local_ti_status == "INTEGRITY_FAILED":
            return "integrity_failed"
        elif ti.local_ti_status == "LOAD_ERROR":
            return "load_error"
        return "unknown"


# Module-level singleton
_DEFAULT_THREAT_INTEL_SERVICE: Optional[ThreatIntelService] = None


def get_threat_intel_service() -> ThreatIntelService:
    global _DEFAULT_THREAT_INTEL_SERVICE
    if _DEFAULT_THREAT_INTEL_SERVICE is None:
        _DEFAULT_THREAT_INTEL_SERVICE = ThreatIntelService()
    return _DEFAULT_THREAT_INTEL_SERVICE
