"""
Unit tests for URL Security Decision Policy & Risk Fusion (Pure AI + Local IOC, Zero Static Rules)
"""
import pytest
from app.models.schemas import (
    AlertCode,
    SecurityVerdict,
    ThreatIntelEvidence,
    URLModelEvidence,
    URLSHAPContribution,
)
from app.services.url_security.normalizer import URLNormalizer
from app.services.url_security.policy import URLSecurityPolicy


@pytest.fixture
def normalizer():
    return URLNormalizer()


@pytest.fixture
def policy():
    return URLSecurityPolicy(
        model_high_threshold=0.7850,
        model_medium_threshold=0.50,
    )


def test_threat_intel_known_malicious_overrides_ml(normalizer, policy):
    """
    Threat Intelligence is authoritative for known malicious threats.
    Even if XGBoost score is 0.05, verdict MUST be MALICIOUS.
    """
    norm = normalizer.normalize("https://known-bad-site.com/login")
    model = URLModelEvidence(model_status="READY", model_score=0.05, ml_prediction=0)
    ti = ThreatIntelEvidence(
        status="known_malicious",
        local_ti_status="MATCH",
        confidence=0.95,
        sources=["Local IOC"],
        malicious_count=12,
        details="Phishing site confirmed",
    )

    verdict, severity, reasons, alert_code, *_ = policy.evaluate(norm, model, ti)

    assert verdict == SecurityVerdict.MALICIOUS
    assert severity == "critical"
    assert alert_code == AlertCode.URL_MALICIOUS
    assert "TI_KNOWN_MALICIOUS" in reasons


def test_high_ml_score_produces_malicious(normalizer, policy):
    """
    Calibrated XGBoost AI score >= operating threshold (ml_prediction == 1) directly produces MALICIOUS.
    """
    norm = normalizer.normalize("https://vietcombạnk.com/login")
    model = URLModelEvidence(
        model_status="READY",
        model_score=0.9954,
        ml_threshold=0.7850,
        ml_prediction=1,
        shap_top_risk=[
            URLSHAPContribution(
                feature="hostname_mixed_script",
                label="Tên miền trộn lẫn nhiều bảng chữ cái (mixed-script)",
                value=1.0,
                shap_value=2.2172,
                direction="risk",
            )
        ],
    )
    ti = ThreatIntelEvidence(status="no_known_risk", local_ti_status="NO_MATCH", sources=["Local IOC"])

    verdict, severity, reasons, alert_code, *_ = policy.evaluate(norm, model, ti)

    assert verdict == SecurityVerdict.MALICIOUS
    assert severity == "high"
    assert alert_code == AlertCode.URL_MALICIOUS
    assert "URL_XGB_HIGH_SCORE" in reasons
    assert "IDN_BRAND_HOMOGRAPH" in reasons


def test_medium_ml_score_produces_suspicious(normalizer, policy):
    """
    Calibrated XGBoost AI score in [0.50, 0.7850) produces SUSPICIOUS (medium).
    """
    norm = normalizer.normalize("https://suspicious-new-domain.top/auth")
    model = URLModelEvidence(
        model_status="READY",
        model_score=0.62,
        ml_threshold=0.7850,
        ml_prediction=0,
    )
    ti = ThreatIntelEvidence(status="no_known_risk", local_ti_status="NO_MATCH", sources=["Local IOC"])

    verdict, severity, reasons, alert_code, *_ = policy.evaluate(norm, model, ti)

    assert verdict == SecurityVerdict.SUSPICIOUS
    assert severity == "medium"
    assert alert_code == AlertCode.URL_SUSPICIOUS
    assert "URL_XGB_MEDIUM_SCORE" in reasons


def test_score_from_non_ready_model_is_ignored(normalizer, policy):
    """A score attached to a model that is not READY must never be used (no fabricated ML)."""
    norm = normalizer.normalize("https://example.org/")
    model = URLModelEvidence(model_status="INCOMPATIBLE_FEATURE_SCHEMA", model_score=0.99)
    verdict, _, reasons, *_ = policy.evaluate(
        norm,
        model,
        ThreatIntelEvidence(status="no_known_risk", local_ti_status="NO_MATCH", sources=["Local IOC"]),
    )
    assert verdict == SecurityVerdict.NO_KNOWN_RISK
    assert "URL_XGB_HIGH_SCORE" not in reasons


def test_userinfo_tactic_produces_suspicious(normalizer, policy):
    norm = normalizer.normalize("https://google.com@phishing.example/login")
    model = URLModelEvidence(model_status="READY", model_score=0.10, ml_prediction=0)
    ti = ThreatIntelEvidence(status="no_known_risk", local_ti_status="NO_MATCH")

    verdict, severity, reasons, alert_code, *_ = policy.evaluate(norm, model, ti)

    assert verdict == SecurityVerdict.SUSPICIOUS
    assert "URL_USERINFO_PRESENT" in reasons


def test_clean_url_produces_no_known_risk(normalizer, policy):
    """
    System outputs NO_KNOWN_RISK, never claiming absolute SAFE.
    """
    norm = normalizer.normalize("https://example.org/about")
    model = URLModelEvidence(model_status="READY", model_score=0.01, ml_prediction=0, model_id="qrdetec-url-xgb", n_features=81)
    ti = ThreatIntelEvidence(status="no_known_risk", local_ti_status="NO_MATCH", confidence=0.8)

    verdict, severity, reasons, alert_code, *_ = policy.evaluate(norm, model, ti)

    assert verdict == SecurityVerdict.NO_KNOWN_RISK
    assert severity == "low"
    assert alert_code == AlertCode.URL_NO_KNOWN_RISK


def test_unavailable_model_and_ti_graceful(normalizer, policy):
    """
    When model and TI are unavailable, returns UNVERIFIABLE.
    """
    norm = normalizer.normalize("https://unknown-domain.xyz/page")
    model = URLModelEvidence(model_status="NOT_CONFIGURED", reason="MANIFEST_NOT_FOUND")
    ti = ThreatIntelEvidence(local_ti_status="LOAD_ERROR", details="Local feed missing")

    verdict, severity, reasons, alert_code, *_ = policy.evaluate(norm, model, ti)

    assert verdict == SecurityVerdict.UNVERIFIABLE
    assert alert_code == AlertCode.URL_UNVERIFIABLE


def test_invalid_syntax_url(normalizer, policy):
    norm = normalizer.normalize("")
    model = URLModelEvidence(model_status="NOT_CONFIGURED")
    ti = ThreatIntelEvidence(local_ti_status="NOT_CONFIGURED")

    verdict, severity, reasons, alert_code, *_ = policy.evaluate(norm, model, ti)

    assert verdict == SecurityVerdict.INVALID
    assert alert_code == AlertCode.INVALID_PAYLOAD
