"""
URL Security Package
Provides AI + Local Threat-Intelligence URL security analysis for QR codes.
"""
from app.services.url_security.analyzer import URLSecurityAnalyzer
from app.services.url_security.model_service import URLModelService, get_url_model_service
from app.services.url_security.normalizer import NormalizedURL, URLNormalizer
from app.services.url_security.policy import URLSecurityPolicy
from app.services.url_security.threat_intel import ThreatIntelService, get_threat_intel_service

__all__ = [
    "URLSecurityAnalyzer",
    "URLNormalizer",
    "NormalizedURL",
    "URLModelService",
    "get_url_model_service",
    "ThreatIntelService",
    "get_threat_intel_service",
    "URLSecurityPolicy",
]
