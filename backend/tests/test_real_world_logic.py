"""
Real-world logic regressions for URL analysis (81-feature AI brand impersonation detection,
local IOC precedence, PSL boundary tenant isolation, and IOC verdict normalization).
"""
import json

import pytest

from app.models.schemas import SecurityVerdict, ThreatIntelEvidence
from app.services.url_security.model_service import URLModelService
from app.services.url_security.normalizer import URLNormalizer
from app.services.url_security.policy import URLSecurityPolicy
from app.services.url_security.threat_intel import ThreatIntelService, _hash_url


class MemRedis:
    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def setex(self, key, ttl, value):
        self.store[key] = value


@pytest.fixture
def normalizer():
    return URLNormalizer()


@pytest.fixture(scope="module")
def model_service():
    return URLModelService()


# ---------------------------------------------------------------- AI brand detection

@pytest.mark.parametrize("url", [
    "https://google.co.uk/",                   # brand's own ccTLD
    "https://portal.vietcombank.com.vn/home",
    "https://www.techcombank.com/",
    "https://accounts.google.com/",
])
def test_official_brand_domains_have_no_false_positive(model_service, normalizer, url):
    norm = normalizer.normalize(url)
    ev = model_service.predict(norm)
    verdict, _, reasons, *_ = URLSecurityPolicy().evaluate(
        norm, ev, ThreatIntelEvidence(status="unknown")
    )
    assert verdict == SecurityVerdict.NO_KNOWN_RISK, url
    assert "BRAND_LOOKALIKE_DOMAIN" not in reasons, url
    assert "BRAND_IN_SUBDOMAIN" not in reasons, url


@pytest.mark.parametrize("url", [
    "https://vietcombank-xacthuc.com/",
    "https://mbbank-hotro.net/dang-nhap",
    "https://vietcombankonline.xyz/",
    "https://momo-nhanqua.top/",
    "https://acb-online.info/",
])
def test_brand_lookalike_registered_domain_is_flagged_by_ai(model_service, normalizer, url):
    norm = normalizer.normalize(url)
    ev = model_service.predict(norm)
    verdict, *_ = URLSecurityPolicy().evaluate(
        norm, ev, ThreatIntelEvidence(status="unknown")
    )
    assert verdict in (SecurityVerdict.MALICIOUS, SecurityVerdict.SUSPICIOUS), url


# ---------------------------------------------------------- Local IOC precedence logic

def test_url_level_malicious_beats_clean_domain_cache(tmp_path, monkeypatch, normalizer):
    norm = normalizer.normalize("https://bigsite.example/phish/page")
    url_hash = _hash_url(norm.normalized_url)
    _feed(tmp_path, monkeypatch, [
        {"domain": "bigsite.example", "verdict": "no_known_risk"},
        {"url_hash": url_hash, "url": "https://bigsite.example/phish/page", "verdict": "phishing"}
    ])
    svc = ThreatIntelService()
    ev = svc.query(norm)
    assert ev.status == "known_malicious"
    assert ev.scope in ("url", "ioc")


# ---------------------------------------------------------------- local IOC

def _feed(tmp_path, monkeypatch, lines):
    from app.core.config import settings
    feed = tmp_path / "feed.jsonl"
    feed.write_text("\n".join(json.dumps(x) for x in lines) + "\n", encoding="utf-8")
    monkeypatch.setattr(settings, "TI_LOCAL_FEED_PATH", str(feed))
    monkeypatch.setattr(settings, "TI_LOCAL_FEED_SHA256", "")
    return ThreatIntelService()


def test_ioc_parent_domain_matches_subdomain(tmp_path, monkeypatch, normalizer):
    svc = _feed(tmp_path, monkeypatch, [{"domain": "evil-bank.example", "verdict": "phishing"}])
    ev = svc.query(normalizer.normalize("https://login.secure.evil-bank.example/x"))
    assert ev.status == "known_malicious"
    assert ev.scope == "ioc"
    # A different domain sharing only the TLD must not match.
    other = svc.query(normalizer.normalize("https://good.example/"))
    assert other.status == "unknown"


def test_ioc_psl_boundary_tenant_isolation(tmp_path, monkeypatch, normalizer):
    """P1-5: Parent domain lookup must never broaden past PSL registrable domain boundary (e.g. github.io)."""
    svc = _feed(tmp_path, monkeypatch, [{"domain": "malicious-user.github.io", "verdict": "phishing"}])
    # Subdomain of malicious tenant matches
    ev1 = svc.query(normalizer.normalize("https://sub.malicious-user.github.io/payload"))
    assert ev1.local_ti_status == "MATCH"
    assert ev1.status == "known_malicious"

    # Innocent sibling tenant on same shared hosting platform must NEVER match
    ev2 = svc.query(normalizer.normalize("https://innocent-user.github.io/blog"))
    assert ev2.local_ti_status == "NO_MATCH"
    assert ev2.status == "unknown"

    # The public suffix platform domain itself must NEVER be matched
    ev3 = svc.query(normalizer.normalize("https://github.io/"))
    assert ev3.local_ti_status == "NO_MATCH"
    assert ev3.status == "unknown"


def test_ioc_verdict_strings_are_normalized(tmp_path, monkeypatch, normalizer):
    svc = _feed(tmp_path, monkeypatch, [
        {"domain": "a.example", "verdict": "malicious"},
        {"domain": "b.example", "verdict": "suspicious"},
        {"domain": "c.example", "verdict": "benign"},
        {"domain": "d.example"},
    ])
    q = lambda h: svc.query(normalizer.normalize(f"https://{h}/")).status  # noqa: E731
    assert q("a.example") == "known_malicious"
    assert q("b.example") == "suspicious"
    assert q("c.example") == "unknown"          # allowlist-style rows are ignored, never "clean"
    assert q("d.example") == "known_malicious"  # missing verdict defaults to malicious
