"""
Threat-Intelligence scenario tests: Local IOC Feed Only
(audit scenarios A, B, E, F) + local feed privacy.

All indicators below are synthetic test fixtures on reserved/example-style domains.
No external network access is made.
"""
import json
import time
import pytest

from app.core.config import settings
from app.models.schemas import (
    SecurityVerdict,
    ThreatIntelEvidence,
    URLModelEvidence,
)
from app.services.url_security.analyzer import URLSecurityAnalyzer
from app.services.url_security.normalizer import URLNormalizer
from app.services.url_security.policy import URLSecurityPolicy
from app.services.url_security.threat_intel import (
    ThreatIntelService,
    privacy_safe_lookup_url,
)

RECENT = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 2 * 86400))
OLD = "2020-01-01"


@pytest.fixture
def normalizer():
    return URLNormalizer()


def _service_with_feed(tmp_path, monkeypatch, rows):
    feed = tmp_path / "feed.jsonl"
    feed.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    monkeypatch.setattr(settings, "TI_LOCAL_FEED_PATH", str(feed))
    monkeypatch.setattr(settings, "TI_LOCAL_FEED_SHA256", "")
    return ThreatIntelService()


def _analyzer(svc):
    a = URLSecurityAnalyzer()
    a.threat_intel = svc
    return a


# ───────────────────────── Scenario A — known malicious IOC ─────────────────────────

def test_scenario_a_known_ioc_warns_early(tmp_path, monkeypatch):
    svc = _service_with_feed(tmp_path, monkeypatch, [
        {"domain": "phish-fixture.example", "verdict": "phishing", "source": "FixtureFeed",
         "last_seen": RECENT, "confidence": 0.9},
    ])
    a = _analyzer(svc)

    final, *_rest, norm = a.analyze("https://login.phish-fixture.example/verify")
    assert final.verdict == SecurityVerdict.MALICIOUS
    assert final.threat_intel.provenance and final.threat_intel.provenance[0]["source"] == "FixtureFeed"
    assert final.checks_performed["local_ioc"] == "match"


def test_scenario_a_low_ml_score_never_downgrades_ioc(normalizer):
    policy = URLSecurityPolicy()
    norm = normalizer.normalize("https://phish-fixture.example/")
    ti = ThreatIntelEvidence(status="known_malicious", sources=["FixtureFeed"], malicious_count=1,
                             scope="ioc", freshness="fresh")
    model = URLModelEvidence(status="ok", model_status="READY", model_score=0.01, ml_prediction=0)
    verdict, severity, reasons, *_ = policy.evaluate(norm, model, ti)
    assert verdict == SecurityVerdict.MALICIOUS and severity == "critical"
    assert "TI_KNOWN_MALICIOUS" in reasons


# ───────────────────────── Scenario B — IOC not found ─────────────────────────

def test_scenario_b_ioc_miss_is_not_safe_and_ml_still_runs(tmp_path, monkeypatch):
    svc = _service_with_feed(tmp_path, monkeypatch, [
        {"domain": "other-fixture.example", "verdict": "phishing", "last_seen": RECENT},
    ])
    a = _analyzer(svc)
    fast, *_rest, norm = a.analyze("https://vietcombank-xacthuc.com/dang-nhap")
    assert fast.checks_performed["local_ioc"] == "no_match"
    assert fast.verdict in (SecurityVerdict.MALICIOUS, SecurityVerdict.SUSPICIOUS)
    assert "URL_XGB_HIGH_SCORE" in fast.reason_codes or "BRAND_LOOKALIKE_DOMAIN" in fast.reason_codes

    final, *_rest2, norm2 = a.analyze("https://www.google.com/")
    # Local IOC miss is reported as NO_KNOWN_RISK with an explicit caveat, never "safe".
    assert final.verdict == SecurityVerdict.NO_KNOWN_RISK
    assert "NO_ANOMALIES_DETECTED" in final.reason_codes
    assert "NO KNOWN IOC MATCH" in (final.threat_intel.details or "")


# ───────────────────────── Scenario E — stale / revoked IOC ─────────────────────────

def test_scenario_e_stale_ioc_is_flagged_not_malicious(tmp_path, monkeypatch, normalizer):
    svc = _service_with_feed(tmp_path, monkeypatch, [
        {"domain": "old-fixture.example", "verdict": "phishing", "source": "FixtureFeed", "last_seen": OLD},
        {"domain": "expired-fixture.example", "verdict": "phishing", "expires_at": "2021-06-01"},
    ])
    for host in ("old-fixture.example", "expired-fixture.example"):
        norm = normalizer.normalize(f"https://{host}/")
        ti = svc.query(norm)
        assert ti.freshness == "stale", host
        verdict, severity, reasons, *_ = URLSecurityPolicy().evaluate(
            norm, URLModelEvidence(status="unavailable"), ti)
        assert verdict == SecurityVerdict.SUSPICIOUS and severity == "medium", host
        assert "TI_IOC_STALE" in reasons and "TI_KNOWN_MALICIOUS" not in reasons
        assert svc.local_ioc_check_status(ti) == "stale"


def test_scenario_e_revoked_ioc_is_ignored(tmp_path, monkeypatch, normalizer):
    svc = _service_with_feed(tmp_path, monkeypatch, [
        {"domain": "revoked-fixture.example", "verdict": "phishing", "revoked": True, "last_seen": RECENT},
        {"domain": "revoked2-fixture.example", "verdict": "phishing", "status": "revoked", "last_seen": RECENT},
    ])
    for host in ("revoked-fixture.example", "revoked2-fixture.example"):
        ti = svc.query(normalizer.normalize(f"https://{host}/"))
        assert ti.status == "unknown", host
        assert "NO KNOWN IOC MATCH" in (ti.details or "")


def test_scenario_e_fresh_record_wins_over_stale_copy(tmp_path, monkeypatch, normalizer):
    svc = _service_with_feed(tmp_path, monkeypatch, [
        {"domain": "both-fixture.example", "verdict": "phishing", "source": "OldFeed", "last_seen": OLD},
        {"domain": "both-fixture.example", "verdict": "phishing", "source": "NewFeed", "last_seen": RECENT},
    ])
    ti = svc.query(normalizer.normalize("https://both-fixture.example/"))
    assert ti.status == "known_malicious" and ti.freshness == "fresh"
    assert ti.sources == ["NewFeed"]
    assert len(ti.provenance) == 2   # stale record still visible in provenance


# ───────────────────────── Scenario F — duplicate / conflicting TI ─────────────────────────

def test_scenario_f_copies_from_one_source_count_once(tmp_path, monkeypatch, normalizer):
    svc = _service_with_feed(tmp_path, monkeypatch, [
        {"domain": "dup-fixture.example", "verdict": "phishing", "source": "FeedA", "last_seen": RECENT},
        {"domain": "dup-fixture.example", "verdict": "phishing", "source": "feeda", "last_seen": RECENT},
        {"domain": "dup-fixture.example", "verdict": "phishing", "source": "FeedA", "last_seen": RECENT},
    ])
    ti = svc.query(normalizer.normalize("https://dup-fixture.example/"))
    assert ti.distinct_sources == 1
    assert ti.malicious_count == 1


def test_scenario_f_conflicting_sources_keep_provenance(tmp_path, monkeypatch, normalizer):
    svc = _service_with_feed(tmp_path, monkeypatch, [
        {"domain": "conflict-fixture.example", "verdict": "suspicious", "source": "FeedA", "last_seen": RECENT},
        {"domain": "conflict-fixture.example", "verdict": "phishing", "source": "FeedB", "last_seen": RECENT},
        {"domain": "conflict-fixture.example", "verdict": "benign", "source": "FeedC", "last_seen": RECENT},
    ])
    ti = svc.query(normalizer.normalize("https://conflict-fixture.example/"))
    # Policy: most severe fresh verdict wins; allowlist rows from a blocklist feed are dropped.
    assert ti.status == "known_malicious"
    assert ti.distinct_sources == 2
    assert {p["source"] for p in ti.provenance} == {"FeedA", "FeedB"}
    assert all(p.get("last_seen") for p in ti.provenance)


def test_ioc_url_field_matches_scanned_variant(tmp_path, monkeypatch, normalizer):
    """Feed `url` rows are normalised with the scan-time normaliser (host case, default port)."""
    svc = _service_with_feed(tmp_path, monkeypatch, [
        {"url": "HTTPS://Pay-Fixture.example:443/checkout", "verdict": "phishing", "last_seen": RECENT},
    ])
    ti = svc.query(normalizer.normalize("https://pay-fixture.example/checkout"))
    assert ti.status == "known_malicious" and ti.scope == "ioc"


def test_embedded_destination_matching_ioc_is_malicious(tmp_path, monkeypatch, normalizer):
    svc = _service_with_feed(tmp_path, monkeypatch, [
        {"domain": "dest-fixture.example", "verdict": "phishing", "last_seen": RECENT},
    ])
    norm = normalizer.normalize(
        "https://redirect.example.com/out?u=https%3A%2F%2Fdest-fixture.example%2Flogin")
    ti = svc.query(norm)
    assert ti.scope == "ioc_embedded"
    verdict, _, reasons, *_ = URLSecurityPolicy().evaluate(
        norm, URLModelEvidence(status="unavailable"), ti)
    assert verdict == SecurityVerdict.MALICIOUS
    assert "TI_EMBEDDED_URL_MATCH" in reasons


# ───────────────────────── Privacy & Payloads ─────────────────────────

def test_privacy_safe_lookup_url_strips_secrets(normalizer):
    norm = normalizer.normalize("https://user:pass@shop-fixture.example/pay?token=abc123&acct=0123#frag")
    safe = privacy_safe_lookup_url(norm)
    assert safe == "https://shop-fixture.example/pay"
    for secret in ("user", "pass", "token", "abc123", "acct", "frag"):
        assert secret not in safe


def test_vietqr_payload_is_never_routed_to_url_ti():
    from app.models.schemas import PayloadType
    from app.services.vietqr_parser import classify_payload
    payload = "00020101021238570010A000000727012700069704360113012345678901230208QRIBFTTA53037045802VN6304ABCD"
    assert classify_payload(payload) == PayloadType.VIETQR
