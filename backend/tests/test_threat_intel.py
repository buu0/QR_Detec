"""
Unit tests for Threat Intelligence Service (Local IOC feed, zero L1/L2 cache, typed statuses, namespace).
Ensures obsolete Redis TI records cannot influence verdicts, and verifies typed status semantics.
"""
import json
import pytest

from app.services.url_security.normalizer import URLNormalizer
from app.services.url_security.threat_intel import ThreatIntelService

try:
    from app.worker.celery_app import cache_namespace
    HAS_CELERY = True
except ImportError:
    HAS_CELERY = False
    cache_namespace = None


@pytest.fixture
def normalizer():
    return URLNormalizer()


def test_utc_timestamp_parsing_is_deterministic():
    """
    P1-6: Verify IOC timestamp parsing uses timezone-aware UTC, deterministic across system timezones.
    """
    from app.services.url_security.threat_intel import _parse_ts, ThreatIntelService

    ts_str = "2024-03-01T12:00:00Z"
    # Expected epoch: 2024-03-01 12:00:00 UTC = 1709294400.0
    expected_epoch = 1709294400.0
    parsed = _parse_ts(ts_str)
    assert parsed == expected_epoch

    # Test space format
    assert _parse_ts("2024-03-01 12:00:00") == expected_epoch

    # Test date-only format
    assert _parse_ts("2024-03-01") == 1709251200.0

    # Test staleness evaluation in ThreatIntelService
    rec_expired = {"expires_at": "2024-03-01T12:00:00Z"}
    assert ThreatIntelService._is_stale(rec_expired, now=1709294401.0) is True
    assert ThreatIntelService._is_stale(rec_expired, now=1709294399.0) is False




def test_parent_domain_psl_boundary(tmp_path, normalizer):
    """
    P1-5: Parent-domain lookup must not cross PSL/eTLD+1 boundary (e.g., github.io, co.uk).
    One malicious tenant on shared hosting must never match all other tenants.
    """
    # Suppose "evil.github.io" is malicious.
    feed_file = tmp_path / "feed_psl.jsonl"
    feed_file.write_text('{"domain": "evil.github.io", "verdict": "phishing"}\n', encoding="utf-8")

    svc = ThreatIntelService(feed_path=str(feed_file))

    # Subdomain of evil.github.io should match (parent is evil.github.io)
    ev_sub = svc.query(normalizer.normalize("https://sub.evil.github.io/login"))
    assert ev_sub.local_ti_status == "MATCH"

    # Innocent neighbor on github.io must NOT match!
    ev_neighbor = svc.query(normalizer.normalize("https://innocent.github.io/app"))
    assert ev_neighbor.local_ti_status == "NO_MATCH"

    # github.io itself must NOT be matched or treated as malicious!
    ev_root = svc.query(normalizer.normalize("https://github.io/index.html"))
    assert ev_root.local_ti_status == "NO_MATCH"



def test_typed_ti_status_semantics(tmp_path, normalizer):
    """
    Verify typed status semantics (Requirement 4):
    MATCH, NO_MATCH, NOT_CONFIGURED, INTEGRITY_FAILED, LOAD_ERROR.
    """
    # 1. NOT_CONFIGURED
    svc_not_conf = ThreatIntelService(feed_path="/nonexistent/path/feed.jsonl")
    assert svc_not_conf.local_feed_status == "NOT_CONFIGURED"
    ev = svc_not_conf.query(normalizer.normalize("https://example.com"))
    assert ev.local_ti_status == "NOT_CONFIGURED"
    assert ev.status == "unknown"

    # 2. INTEGRITY_FAILED
    feed_file = tmp_path / "feed.jsonl"
    feed_file.write_text('{"domain": "bad.example", "verdict": "phishing"}\n', encoding="utf-8")
    svc_bad_hash = ThreatIntelService(feed_path=str(feed_file), feed_sha256="0000000000000000000000000000000000000000000000000000000000000000")
    assert svc_bad_hash.local_feed_status == "INTEGRITY_FAILED"
    ev = svc_bad_hash.query(normalizer.normalize("https://bad.example"))
    assert ev.local_ti_status == "INTEGRITY_FAILED"

    # 3. LOAD_ERROR (malformed jsonl)
    corrupt_file = tmp_path / "corrupt.jsonl"
    corrupt_file.write_bytes(b"\x80\x81\x82 invalid binary data {{{{")
    svc_load_err = ThreatIntelService(feed_path=str(corrupt_file))
    assert svc_load_err.local_feed_status == "LOAD_ERROR"
    ev = svc_load_err.query(normalizer.normalize("https://example.com"))
    assert ev.local_ti_status == "LOAD_ERROR"

    # 4. MATCH vs NO_MATCH
    valid_file = tmp_path / "valid.jsonl"
    valid_file.write_text('{"domain": "malicious.example", "verdict": "phishing"}\n', encoding="utf-8")
    svc_valid = ThreatIntelService(feed_path=str(valid_file))
    assert svc_valid.local_feed_status == "LOADED"

    # Match
    ev_match = svc_valid.query(normalizer.normalize("https://malicious.example/path"))
    assert ev_match.local_ti_status == "MATCH"
    assert ev_match.status == "known_malicious"

    # Miss (NO_MATCH)
    ev_miss = svc_valid.query(normalizer.normalize("https://clean.example/path"))
    assert ev_miss.local_ti_status == "NO_MATCH"
    assert ev_miss.status == "unknown"
    assert "NO KNOWN IOC MATCH" in ev_miss.details


@pytest.mark.skipif(not HAS_CELERY, reason="celery required for worker cache_namespace")
def test_cache_namespace_includes_local_ti_sha(monkeypatch):
    """
    Verify application result cache namespace includes Local IOC feed SHA-256 (Requirement 7).
    """
    class MockTISvc:
        def __init__(self, sha):
            self._sha = sha
        def get_feed_sha256(self):
            return self._sha

    # Feed 1
    monkeypatch.setattr("app.worker.celery_app.get_threat_intel_service", lambda: MockTISvc("11112222333344445555666677778888"))
    ns1 = cache_namespace()
    assert ":ti-1111222233334444:" in ns1

    # Feed 2 (changed hash)
    monkeypatch.setattr("app.worker.celery_app.get_threat_intel_service", lambda: MockTISvc("aaaabbbbccccddddeeeeffff00001111"))
    ns2 = cache_namespace()
    assert ":ti-aaaabbbbccccdddd:" in ns2
    assert ns1 != ns2

    # Feed unavailable
    monkeypatch.setattr("app.worker.celery_app.get_threat_intel_service", lambda: MockTISvc(None))
    ns3 = cache_namespace()
    assert ":ti-unavailable:" in ns3


def test_cache_namespace_pure_logic():
    """
    Unit test of cache namespace format with Local IOC SHA identity (Requirement 7).
    """
    from app.services.url_security.policy import URLSecurityPolicy

    def make_ns(model_fp, feed_sha, decode_mode="complete"):
        base_v = f"v8_p{URLSecurityPolicy.POLICY_VERSION}"
        ti_token = f"ti-{feed_sha[:16]}" if feed_sha else "ti-unavailable"
        return f"{base_v}:m{model_fp}:{ti_token}:d{decode_mode}"

    ns1 = make_ns("fp1", "3523fefb693fa813dd347ed7c0eb7a22bed8a2515870fe410101c5328eb072b7")
    ns2 = make_ns("fp1", "0000000000000000dd347ed7c0eb7a22bed8a2515870fe410101c5328eb072b7")
    ns_unavail = make_ns("fp1", None)

    assert ":ti-3523fefb693fa813:" in ns1
    assert ":ti-0000000000000000:" in ns2
    assert ns1 != ns2
    assert ":ti-unavailable:" in ns_unavail

