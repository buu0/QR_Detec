"""
Verdict-integrity regressions:
- provisional results never present as "no known risk"
- a non-responding TI service never yields NO_KNOWN_RISK, and never downgrades protocol/ML findings
- 0 engines / transient TI failures are not cached or read as clean
- result schema exposes final/provisional metadata for the frontend
"""
from app.models.schemas import (
    AlertCode,
    ProcessingResult,
    QRCodeResult,
    SecurityVerdict,
    ThreatIntelEvidence,
    URLModelEvidence,
    PayloadType,
    JobStatus,
    risk_level_for_alert,
)
from app.services.url_security.normalizer import URLNormalizer
from app.services.url_security.policy import URLSecurityPolicy
from app.services.url_security.threat_intel import ThreatIntelService

norm = URLNormalizer()
policy = URLSecurityPolicy(model_high_threshold=0.7850, model_medium_threshold=0.50)


def test_provisional_url_result_is_pending_not_no_known_risk():
    qr = QRCodeResult(payload="https://example.org", payload_type=PayloadType.URL,
                      alert_code=AlertCode.URL_NO_KNOWN_RISK, is_provisional=True)
    assert qr.risk_level == "pending"
    assert qr.analysis_completeness == "pending"


def test_provisional_danger_is_kept_immediately():
    qr = QRCodeResult(payload="https://bad.example", payload_type=PayloadType.URL,
                      alert_code=AlertCode.URL_MALICIOUS, is_provisional=True)
    assert qr.risk_level == "danger"


def test_risk_mapping_never_has_safe():
    for code in AlertCode:
        assert risk_level_for_alert(code) in ("danger", "warning", "no_known_risk", "unverifiable", "info", "pending")


def test_ti_integrity_error_with_low_ml_is_unverifiable():
    n = norm.normalize("https://unknown-shop.example/item")
    for status in ("INTEGRITY_FAILED", "LOAD_ERROR"):
        verdict, *_rest = policy.evaluate(
            n,
            URLModelEvidence(model_status="READY", model_score=0.01, ml_prediction=0),
            ThreatIntelEvidence(local_ti_status=status),
        )
        assert verdict == SecurityVerdict.UNVERIFIABLE, status
        assert f"TI_{status}" in _rest[1]


def test_ti_error_does_not_downgrade_userinfo_or_ml_findings():
    n = norm.normalize("https://google.com@phish.example/login")
    verdict, *_ = policy.evaluate(
        n,
        URLModelEvidence(model_status="NOT_CONFIGURED"),
        ThreatIntelEvidence(local_ti_status="INTEGRITY_FAILED"),
    )
    assert verdict == SecurityVerdict.SUSPICIOUS


def test_known_malicious_not_downgraded_by_low_ml():
    n = norm.normalize("https://bank-login.example")
    verdict, *_ = policy.evaluate(
        n,
        URLModelEvidence(model_status="READY", model_score=0.0, ml_prediction=0),
        ThreatIntelEvidence(status="known_malicious", local_ti_status="MATCH", sources=["Local IOC Feed"], malicious_count=1),
    )
    assert verdict == SecurityVerdict.MALICIOUS


def test_no_known_risk_without_ti_marks_ti_not_consulted():
    n = norm.normalize("https://example.org")
    verdict, _sev, reasons, *_ = policy.evaluate(
        n,
        URLModelEvidence(model_status="READY", model_score=0.01, ml_prediction=0),
        ThreatIntelEvidence(local_ti_status="NOT_CONFIGURED"),
    )
    assert verdict == SecurityVerdict.NO_KNOWN_RISK
    assert "TI_NOT_CONSULTED" in reasons


def test_local_feed_integrity_pin(tmp_path, monkeypatch):
    from app.core.config import settings

    feed = tmp_path / "feed.jsonl"
    feed.write_text('{"domain": "bad.example", "verdict": "known_malicious"}\n', encoding="utf-8")
    monkeypatch.setattr(settings, "TI_LOCAL_FEED_PATH", str(feed))
    monkeypatch.setattr(settings, "TI_LOCAL_FEED_SHA256", "0" * 64)
    svc = ThreatIntelService()
    assert svc.local_feed_status == "integrity_failed"
    assert svc._local_iocs == {}

    import hashlib
    monkeypatch.setattr(settings, "TI_LOCAL_FEED_SHA256", hashlib.sha256(feed.read_bytes()).hexdigest())
    svc = ThreatIntelService()
    assert svc.local_feed_status == "loaded"
    assert "domain:bad.example" in svc._local_iocs


def test_processing_result_exposes_final_metadata():
    pr = ProcessingResult(job_id="x", status=JobStatus.COMPLETED, file_name="a.png")
    data = pr.model_dump()
    for key in ("is_final", "analysis_completeness", "error_code", "user_message",
                "recommended_action", "warnings", "created_at", "completed_at", "timings_ms"):
        assert key in data
