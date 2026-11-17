"""
Regression tests for Non-Web URI Semantics (P0 Section 2, 3, 4).
Tests:
- customscheme:
- ftp:
- javascript:
- data:
- file:
- intent:
- blob:
- mailto:
- tel:
- sms:
Verifies:
1. Unknown/unsupported URI must NEVER receive NO_KNOWN_RISK verdict.
2. Dangerous schemes receive deterministic SUSPICIOUS.
3. Informational schemes receive UNSUPPORTED_URI / info level.
4. Model and Local TI layers are reported as NOT_APPLICABLE when skipped, NOT as NOT_CONFIGURED or INFERENCE_ERROR.
5. Only http and https execute Rules -> ML -> Local IOC -> Policy.
"""
from unittest.mock import MagicMock
import pytest

from app.models.schemas import AlertCode, SecurityVerdict
from app.services.url_security import URLSecurityAnalyzer


@pytest.fixture
def analyzer():
    return URLSecurityAnalyzer()


@pytest.mark.parametrize("scheme,uri", [
    ("mailto", "mailto:victim@example.com?subject=Important"),
    ("tel", "tel:+84987654321"),
    ("sms", "sms:+84987654321?body=OTP%20Code"),
])
def test_informational_uri_schemes(analyzer, scheme, uri):
    """Informational URIs must return UNSUPPORTED_URI and NOT_APPLICABLE for ML and Local IOC."""
    analysis, alert_code, color, title, msg, rec, norm = analyzer.analyze(uri)

    assert alert_code == AlertCode.UNSUPPORTED_URI
    assert analysis.verdict == SecurityVerdict.NO_KNOWN_RISK
    assert analysis.model.model_status == "NOT_APPLICABLE"
    assert analysis.model.model_score is None
    assert analysis.threat_intel.local_ti_status == "NOT_APPLICABLE"
    assert analysis.checks_performed.get("ml_sensor") == "not_applicable"
    assert analysis.checks_performed.get("local_ioc") == "not_applicable"
    # Never expose duplicate 'threat_intel' check key
    assert "threat_intel" not in analysis.checks_performed


@pytest.mark.parametrize("scheme,uri", [
    ("javascript", "javascript:alert(document.cookie)"),
    ("data", "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="),
    ("file", "file:///etc/passwd"),
    ("intent", "intent://scan/#Intent;scheme=zxing;package=com.google.zxing.client.android;end"),
    ("blob", "blob:https://evil.com/uuid-blob"),
    ("vbscript", "vbscript:MsgBox(\"Hello\")"),
])
def test_dangerous_uri_schemes(analyzer, scheme, uri):
    """Dangerous protocols must yield deterministic SUSPICIOUS without executing ML or Local IOC."""
    analysis, alert_code, color, title, msg, rec, norm = analyzer.analyze(uri)

    assert alert_code == AlertCode.URL_SUSPICIOUS
    assert analysis.verdict == SecurityVerdict.SUSPICIOUS
    assert analysis.model.model_status == "NOT_APPLICABLE"
    assert analysis.threat_intel.local_ti_status == "NOT_APPLICABLE"
    assert analysis.checks_performed.get("ml_sensor") == "not_applicable"
    assert analysis.checks_performed.get("local_ioc") == "not_applicable"


@pytest.mark.parametrize("scheme,uri", [
    ("customscheme", "customscheme://app/pay?token=xyz"),
    ("ftp", "ftp://ftp.example.com/file.zip"),
    ("ssh", "ssh://user@server.example.com"),
    ("myapp", "myapp://deep/link"),
])
def test_unsupported_non_web_uri_schemes(analyzer, scheme, uri):
    """Unknown/unsupported URI must NEVER receive NO_KNOWN_RISK merely because rule score is low."""
    analysis, alert_code, color, title, msg, rec, norm = analyzer.analyze(uri)

    assert analysis.verdict != SecurityVerdict.NO_KNOWN_RISK
    assert alert_code != AlertCode.URL_NO_KNOWN_RISK
    assert alert_code == AlertCode.URL_UNVERIFIABLE
    assert analysis.verdict == SecurityVerdict.UNVERIFIABLE
    assert "UNSUPPORTED_URI_SCHEME" in analysis.reason_codes
    assert analysis.model.model_status == "NOT_APPLICABLE"
    assert analysis.threat_intel.local_ti_status == "NOT_APPLICABLE"


def test_valid_http_https_executes_ml_and_ioc(analyzer):
    """Valid web URLs execute the full multi-layer pipeline."""
    analysis, alert_code, color, title, msg, rec, norm = analyzer.analyze("https://vietcombank.com.vn/")

    # ML should have executed (READY)
    assert analysis.model.model_status in ("READY", "NOT_CONFIGURED")
    if analysis.model.model_status == "READY":
        assert analysis.model.model_score is not None
        assert analysis.model.raw_score is not None
        assert analysis.model.ml_threshold is not None
        assert analysis.model.ml_prediction in (0, 1)

    # Local IOC should have executed (NO_MATCH or MATCH)
    assert analysis.threat_intel.local_ti_status in ("NO_MATCH", "MATCH", "NOT_CONFIGURED")
    assert "local_ioc" in analysis.checks_performed
    assert "threat_intel" not in analysis.checks_performed
