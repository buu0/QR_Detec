"""
URL Security Analyzer Facade
============================
Unified single-phase URL security pipeline:
Normalize -> Validate URL eligibility -> XGBoost AI Model (81 features + Isotonic + TreeSHAP) -> Local IOC -> Policy Fusion -> Final Verdict

Execution is single-phase: exactly one policy evaluation, zero provisional events for URLs,
zero static lexical heuristics, zero external TI, and immediate short-circuit for invalid or non-web URIs.
"""
from __future__ import annotations

import logging
from typing import Dict, Optional, Tuple

from app.models.schemas import AlertCode, ThreatIntelEvidence, URLAnalysis, URLModelEvidence
from app.services.url_security.model_service import get_url_model_service
from app.services.url_security.normalizer import NormalizedURL, URLNormalizer
from app.services.url_security.policy import URLSecurityPolicy
from app.services.url_security.threat_intel import ThreatIntelService, get_threat_intel_service

logger = logging.getLogger(__name__)


class URLSecurityAnalyzer:
    """
    Facade managing the complete single-phase URL security pipeline.
    """

    ANALYSIS_VERSION = "3.0.0"

    def __init__(self, threat_intel: Optional[ThreatIntelService] = None):
        self.normalizer = URLNormalizer()
        self.model_service = get_url_model_service()
        self.threat_intel = threat_intel or get_threat_intel_service()
        self.policy = URLSecurityPolicy()

    def _checks(self, norm: NormalizedURL, model: URLModelEvidence, ti: ThreatIntelEvidence) -> Tuple[Dict[str, str], str]:
        """Describe which security checks actually executed."""
        checks: Dict[str, str] = {}
        model_status = getattr(model, "model_status", "NOT_CONFIGURED")
        checks["ml_sensor"] = "done" if model_status == "READY" and model.model_score is not None else model_status.lower()
        local_status = self.threat_intel.local_ioc_check_status(ti) if norm.hostname else "not_applicable"
        checks["local_ioc"] = local_status
        completeness = (
            "full"
            if checks["ml_sensor"] == "done" and local_status in ("match", "stale", "no_match", "not_applicable", "not_configured")
            else "partial"
        )
        return checks, completeness

    def analyze(
        self,
        raw_url: str,
    ) -> Tuple[URLAnalysis, AlertCode, str, str, str, str, NormalizedURL]:
        """
        Single-phase URL Security Pipeline:
        1. Normalize & Validate
        2. Short-circuit if INVALID syntax or non-web URI (no ML, no Local IOC)
        3. Calibrated 81-Feature XGBoost Model + TreeSHAP
        4. Local IOC Lookup (in-memory, verified feed)
        5. Final Policy Fusion -> Single definitive result
        """
        # 1. Normalize
        norm = self.normalizer.normalize(raw_url)

        # 2. Short-circuit: Invalid URL structure
        if not norm.is_valid:
            empty_model = URLModelEvidence(model_status="NOT_APPLICABLE")
            empty_ti = ThreatIntelEvidence(local_ti_status="NOT_APPLICABLE")
            verdict, severity, reasons, alert_code, color, title, msg, rec = self.policy.evaluate(
                norm=norm,
                model=empty_model,
                ti=empty_ti,
            )
            checks = {
                "ml_sensor": "not_applicable",
                "local_ioc": "not_applicable",
            }
            analysis = URLAnalysis(
                original_url=norm.original_url,
                normalized_url="",
                host="",
                scheme=norm.scheme or "",
                is_provisional=False,
                verdict=verdict,
                severity=severity,
                reason_codes=reasons,
                model=empty_model,
                threat_intel=empty_ti,
                analysis_version=self.ANALYSIS_VERSION,
                policy_version=self.policy.POLICY_VERSION,
                checks_performed=checks,
                analysis_completeness="full",
                embedded_urls=[],
            )
            return analysis, alert_code, color, title, msg, rec, norm

        # 3. Short-circuit: Informational non-web URI schemes (mailto, tel, sms)
        if norm.scheme in ("mailto", "tel", "sms"):
            empty_model = URLModelEvidence(model_status="NOT_APPLICABLE")
            empty_ti = ThreatIntelEvidence(local_ti_status="NOT_APPLICABLE")
            verdict, severity, reasons, alert_code, color, title, msg, rec = self.policy.evaluate(
                norm=norm,
                model=empty_model,
                ti=empty_ti,
            )
            checks = {
                "ml_sensor": "not_applicable",
                "local_ioc": "not_applicable",
            }
            analysis = URLAnalysis(
                original_url=norm.original_url,
                normalized_url=norm.normalized_url,
                host=norm.hostname or "",
                scheme=norm.scheme,
                is_provisional=False,
                verdict=verdict,
                severity=severity,
                reason_codes=reasons,
                model=empty_model,
                threat_intel=empty_ti,
                analysis_version=self.ANALYSIS_VERSION,
                policy_version=self.policy.POLICY_VERSION,
                checks_performed=checks,
                analysis_completeness="full",
                embedded_urls=[],
            )
            return analysis, alert_code, color, title, msg, rec, norm

        # 4. Short-circuit: Dangerous or non-web schemes (javascript, data, file, intent, blob, vbscript, customscheme, etc.)
        # Any scheme that is NOT http or https MUST NOT invoke ML and MUST NOT invoke Local IOC.
        if norm.scheme not in ("http", "https"):
            empty_model = URLModelEvidence(model_status="NOT_APPLICABLE")
            empty_ti = ThreatIntelEvidence(local_ti_status="NOT_APPLICABLE")
            verdict, severity, reasons, alert_code, color, title, msg, rec = self.policy.evaluate(
                norm=norm,
                model=empty_model,
                ti=empty_ti,
            )
            checks = {
                "ml_sensor": "not_applicable",
                "local_ioc": "not_applicable",
            }
            analysis = URLAnalysis(
                original_url=norm.original_url,
                normalized_url=norm.normalized_url,
                host=norm.hostname or "",
                scheme=norm.scheme,
                is_provisional=False,
                verdict=verdict,
                severity=severity,
                reason_codes=reasons,
                model=empty_model,
                threat_intel=empty_ti,
                analysis_version=self.ANALYSIS_VERSION,
                policy_version=self.policy.POLICY_VERSION,
                checks_performed=checks,
                analysis_completeness="full",
                embedded_urls=[],
            )
            return analysis, alert_code, color, title, msg, rec, norm

        # 5. ONLY valid Web URLs (http, https): Full single-phase AI + Local IOC analysis
        model = self.model_service.predict(norm)
        ti = self.threat_intel.query(norm)

        verdict, severity, reasons, alert_code, color, title, msg, rec = self.policy.evaluate(
            norm=norm,
            model=model,
            ti=ti,
        )

        checks, completeness = self._checks(norm, model, ti)
        analysis = URLAnalysis(
            original_url=norm.original_url,
            normalized_url=norm.normalized_url,
            host=norm.hostname,
            scheme=norm.scheme,
            is_provisional=False,
            verdict=verdict,
            severity=severity,
            reason_codes=reasons,
            model=model,
            threat_intel=ti,
            analysis_version=self.ANALYSIS_VERSION,
            policy_version=self.policy.POLICY_VERSION,
            checks_performed=checks,
            analysis_completeness=completeness,
            embedded_urls=list(norm.embedded_urls),
        )

        return analysis, alert_code, color, title, msg, rec, norm
