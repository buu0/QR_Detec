"""
Regression tests for 81-feature XGBoost AI + URLNormalizer + URLSecurityPolicy decision table.

Static lexical heuristic rules (StaticURLRuleEngine) and shadow/active mode toggles have been
removed. The calibrated 81-feature XGBoost + Isotonic Calibration + TreeSHAP model operates
directly alongside Local IOC Threat Intelligence and URLNormalizer protocol/network guardrails.
"""
import pytest

from app.models.schemas import (
    SecurityVerdict,
    ThreatIntelEvidence,
    URLModelEvidence,
)
from app.services.url_security.model_service import URLModelService
from app.services.url_security.normalizer import URLNormalizer
from app.services.url_security.policy import URLSecurityPolicy

N = URLNormalizer()
M = URLModelService()
P = URLSecurityPolicy()
NO_MODEL = URLModelEvidence(status="unavailable", model_status="NOT_CONFIGURED")
CLEAN_MODEL = URLModelEvidence(status="ok", model_status="READY", model_score=0.02, raw_probability=0.03, ml_prediction=0)
HIGH_MODEL = URLModelEvidence(
    status="ok",
    model_status="READY",
    model_score=0.95,
    raw_probability=0.94,
    ml_prediction=1,
    top_features=[
        {"name": "brand_lookalike_registrable", "value": 1.0, "contribution": 1.4},
        {"name": "brand_official_domain_mismatch", "value": 1.0, "contribution": 0.9},
    ],
)


def run(url, ti=None):
    norm = N.normalize(url)
    model = M.predict(norm)
    verdict, severity, reasons, *_ = P.evaluate(norm, model, ti or ThreatIntelEvidence(status="unknown"))
    return verdict, severity, reasons, model


# ─────────────────────────── Audit examples (AI + Normalizer) ───────────────────────────

@pytest.mark.parametrize("url", [
    "https://learn.microsoft.com/en-us/azure",
    "https://tiki.vn/dien-thoai-may-tinh-bang",
    "https://www.google.com/search?q=" + "a" * 200 + "&hl=vi&source=hp",
    "https://accounts.google.com/signin/v2/identifier?service=mail",
    "https://ebanking.vietcombank.com.vn/ibanking2020/login",
    "https://shopee.vn/product/123?utm_source=qr&utm_medium=poster&utm_campaign=tet2026",
    "https://drive.google.com/file/d/1AbCdEfGhIjKlMnOpQrStUvWxYz/view?usp=sharing",
    "https://www.vietcombank.com.vn/vi-VN",
    "https://www.mbbank.com.vn/",
])
def test_benign_audit_examples_are_no_known_risk(url):
    verdict, *_ = run(url)
    assert verdict == SecurityVerdict.NO_KNOWN_RISK, url


def test_userinfo_trick_is_flagged():
    verdict, _, reasons, _ = run("https://vietcombank.com.vn@evil-fixture.example/login")
    assert verdict in (SecurityVerdict.SUSPICIOUS, SecurityVerdict.MALICIOUS)
    assert "URL_USERINFO_PRESENT" in reasons


@pytest.mark.parametrize("url", [
    "https://vietcombank-xacthuc.com/dang-nhap",
    "https://vietcombank.com.vn.secure-login.top/",
    "https://mbbank-hotro.net/dang-nhap",
])
def test_bank_impersonation_is_caught_by_ai_model(url):
    verdict, severity, reasons, model = run(url)
    assert model.model_status == "READY"
    assert verdict in (SecurityVerdict.MALICIOUS, SecurityVerdict.SUSPICIOUS), url
    assert severity in ("high", "critical", "medium"), url


# ─────────────────────────── IDN homograph (81-feature AI model) ───────────────────────────

@pytest.mark.parametrize("url", [
    "https://vietcombạnk.com/",          # Vietnamese diacritic
    "https://vietcômbank.com.vn/",       # homograph of the official domain itself
    "https://vіetcombank.com/",          # Cyrillic 'і'
    "https://mbbаnk.vn/",                # Cyrillic 'а'
])
def test_idn_brand_homograph_is_malicious_via_ai(url):
    verdict, severity, reasons, model = run(url)
    assert model.ml_prediction == 1, url
    assert verdict == SecurityVerdict.MALICIOUS and severity == "high", url
    assert "IDN_BRAND_HOMOGRAPH" in reasons, url


@pytest.mark.parametrize("url", [
    "https://đặcsản-hànội.vn/",
    "https://bücher.de/",
    "https://văn-hóa-việt.vn/",
])
def test_idn_without_brand_is_not_accused(url):
    verdict, _, reasons, model = run(url)
    assert "IDN_BRAND_HOMOGRAPH" not in reasons
    assert model.ml_prediction == 0
    assert verdict == SecurityVerdict.NO_KNOWN_RISK


# ─────────────────────────── Decision table (Phase 6) ───────────────────────────

def _ti(status, **kw):
    return ThreatIntelEvidence(status=status, **kw)


CLEAN_URL = "https://example.org/about"
SUSP_URL = "https://vietcombank-xacthuc.com/dang-nhap"


@pytest.mark.parametrize("name,url,ti,model,expected,must_have", [
    ("ioc_malicious_no_ml", CLEAN_URL,
     _ti("known_malicious", local_ti_status="MATCH", sources=["FixtureFeed"], scope="ioc", freshness="fresh", malicious_count=1),
     NO_MODEL, SecurityVerdict.MALICIOUS, "TI_KNOWN_MALICIOUS"),
    ("ioc_malicious_ml_low", CLEAN_URL,
     _ti("known_malicious", local_ti_status="MATCH", sources=["FixtureFeed"], scope="ioc", freshness="fresh"),
     CLEAN_MODEL, SecurityVerdict.MALICIOUS, "TI_KNOWN_MALICIOUS"),
    ("no_ioc_high_ml", SUSP_URL, _ti("unknown", local_ti_status="NOT_CONFIGURED"), HIGH_MODEL, SecurityVerdict.MALICIOUS, "URL_XGB_HIGH_SCORE"),
    ("no_ioc_clean_no_external", CLEAN_URL, _ti("unknown", local_ti_status="NOT_CONFIGURED"), CLEAN_MODEL, SecurityVerdict.NO_KNOWN_RISK, "TI_NOT_CONSULTED"),
    ("ti_integrity_failed", CLEAN_URL, _ti("unknown", local_ti_status="INTEGRITY_FAILED"), CLEAN_MODEL, SecurityVerdict.UNVERIFIABLE, "TI_INTEGRITY_FAILED"),
    ("ti_load_error", CLEAN_URL, _ti("unknown", local_ti_status="LOAD_ERROR"), CLEAN_MODEL, SecurityVerdict.UNVERIFIABLE, "TI_LOAD_ERROR"),
    ("ti_zero_high_ml", SUSP_URL, _ti("no_known_risk", local_ti_status="NO_MATCH", sources=["Local IOC"], scope="domain"),
     HIGH_MODEL, SecurityVerdict.MALICIOUS, "URL_XGB_HIGH_SCORE"),
    ("ioc_stale", CLEAN_URL, _ti("known_malicious", local_ti_status="MATCH", scope="ioc", freshness="stale"),
     CLEAN_MODEL, SecurityVerdict.SUSPICIOUS, "TI_IOC_STALE"),
    ("ti_suspicious", CLEAN_URL, _ti("suspicious", local_ti_status="MATCH", sources=["Local IOC"], suspicious_count=1),
     CLEAN_MODEL, SecurityVerdict.SUSPICIOUS, "TI_SUSPICIOUS"),
    ("malformed", "http://exa mple.com/", _ti("unknown", local_ti_status="NOT_CONFIGURED"), NO_MODEL, SecurityVerdict.INVALID, "URL_SYNTAX_INVALID"),
])
def test_decision_table(name, url, ti, model, expected, must_have):
    norm = N.normalize(url)
    verdict, severity, reasons, *_ = P.evaluate(norm, model, ti)
    assert verdict == expected, name
    assert must_have in reasons, name


def test_ti_clean_with_sources_is_no_known_risk_but_never_safe_wording():
    norm = N.normalize(CLEAN_URL)
    verdict, _, _, _, _, title, msg, rec = P.evaluate(
        norm, CLEAN_MODEL, _ti("no_known_risk", sources=["Local IOC"], scope="domain"))
    assert verdict == SecurityVerdict.NO_KNOWN_RISK
    text = f"{title} {msg} {rec}".lower()
    assert "an toàn tuyệt đối" in text and "không có nghĩa" in text   # explicit caveat
    assert "đã xác thực" not in text and "safe" not in text


def test_ml_high_score_produces_malicious():
    norm = N.normalize(CLEAN_URL)
    verdict, severity, reasons, *_ = P.evaluate(
        norm,
        URLModelEvidence(status="ok", model_status="READY", model_score=0.95, ml_prediction=1),
        _ti("unknown"),
    )
    assert verdict == SecurityVerdict.MALICIOUS and severity == "high"
    assert "URL_XGB_HIGH_SCORE" in reasons
