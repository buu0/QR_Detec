"""
Unit tests for the Single-Phase URL Security Pipeline (Pure AI + Local IOC).
Verifies:
1. Single-phase execution (policy evaluated exactly once, is_provisional=False).
2. Short-circuiting of invalid URLs (model and local IOC are not invoked).
3. Short-circuiting of non-web URIs (mailto, tel, sms do not invoke model or local IOC).
4. Full execution on valid HTTP/HTTPS URLs.
"""
from unittest.mock import MagicMock
import pytest

from app.models.schemas import AlertCode, SecurityVerdict
from app.services.url_security.analyzer import URLSecurityAnalyzer


@pytest.fixture
def mock_analyzer():
    analyzer = URLSecurityAnalyzer()
    analyzer.model_service = MagicMock()
    analyzer.threat_intel = MagicMock()
    analyzer.policy = MagicMock()
    return analyzer


def test_invalid_syntax_short_circuits_without_ml_or_ti():
    """
    P0-1: Invalid URL syntax must NOT invoke ML model or Local IOC.
    """
    from unittest.mock import patch

    analyzer = URLSecurityAnalyzer()
    for invalid_input in ["http://", "", "not a url", "   "]:
        with patch.object(analyzer.model_service, "predict") as mock_predict, \
             patch.object(analyzer.threat_intel, "query") as mock_query:

            analysis, alert_code, color, title, msg, rec, norm = analyzer.analyze(invalid_input)

            mock_predict.assert_not_called()
            mock_query.assert_not_called()

            assert analysis.verdict == SecurityVerdict.INVALID
            assert analysis.is_provisional is False
            assert analysis.checks_performed["ml_sensor"] == "not_applicable"
            assert analysis.checks_performed["local_ioc"] == "not_applicable"


def test_informational_non_web_schemes_short_circuit_without_ml_or_ti():
    """
    P0-1: Informational non-web schemes (mailto:, tel:, sms:) must return NOT_APPLICABLE/informational
    and NOT invoke ML or Local IOC.
    """
    from unittest.mock import patch

    analyzer = URLSecurityAnalyzer()
    for uri in [
        "mailto:support@bank.example",
        "tel:+84901234567",
        "sms:+84901234567?body=Hello",
    ]:
        with patch.object(analyzer.model_service, "predict") as mock_predict, \
             patch.object(analyzer.threat_intel, "query") as mock_query:

            analysis, alert_code, color, title, msg, rec, norm = analyzer.analyze(uri)

            mock_predict.assert_not_called()
            mock_query.assert_not_called()

            assert analysis.is_provisional is False
            assert analysis.checks_performed["ml_sensor"] == "not_applicable"
            assert analysis.checks_performed["local_ioc"] == "not_applicable"
            assert alert_code in (AlertCode.UNSUPPORTED_URI, AlertCode.OTHER_PAYLOAD)


def test_dangerous_non_web_schemes_short_circuit_without_ml_or_ti():
    """
    P0-1: Dangerous non-web URI schemes (javascript:, data:, file:, intent:, blob:)
    must be evaluated by deterministic protocol guardrails without invoking ML or Local IOC.
    """
    from unittest.mock import patch

    analyzer = URLSecurityAnalyzer()
    dangerous_schemes = [
        "javascript:alert(1)",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "file:///etc/passwd",
        "intent://scan/#Intent;scheme=zxing;package=com.google.zxing.client.android;end",
        "blob:https://example.com/uuid-here",
    ]

    for d_uri in dangerous_schemes:
        with patch.object(analyzer.model_service, "predict") as mock_predict, \
             patch.object(analyzer.threat_intel, "query") as mock_query:

            analysis, alert_code, color, title, msg, rec, norm = analyzer.analyze(d_uri)

            mock_predict.assert_not_called()
            mock_query.assert_not_called()

            assert analysis.is_provisional is False
            assert analysis.checks_performed["ml_sensor"] == "not_applicable"
            assert analysis.checks_performed["local_ioc"] == "not_applicable"
            assert analysis.verdict in (SecurityVerdict.MALICIOUS, SecurityVerdict.SUSPICIOUS, SecurityVerdict.INVALID)


def test_valid_http_url_executes_single_phase_pipeline():
    """
    Valid HTTP/HTTPS executes full single-phase pipeline:
    ML (81 features) + Local IOC -> Policy.
    Invokes policy once and returns one final result.
    """
    from unittest.mock import patch

    analyzer = URLSecurityAnalyzer()

    with patch.object(analyzer.policy, "evaluate", wraps=analyzer.policy.evaluate) as spy_policy:
        analysis, alert_code, color, title, msg, rec, norm = analyzer.analyze("https://www.google.com/search?q=test")

        assert spy_policy.call_count == 1
        assert analysis.is_provisional is False
        assert analysis.verdict is not None
        assert "heuristics" not in analysis.checks_performed
        assert analysis.checks_performed["ml_sensor"] == "done"
        assert analysis.checks_performed["local_ioc"] in ("no_match", "match", "not_configured")
