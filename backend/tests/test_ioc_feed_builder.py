"""
Tests for scripts/build_ioc_feed.py and for loading its output into ThreatIntelService.

The filters matter for real users: the live Phishing.Database ACTIVE list contains entries
such as `sites.google.com` and `telegra.ph`. Because local IOC matching also checks parent
domains, keeping those entries would label EVERY link on those platforms as malicious.
"""
import importlib.util
import json
from pathlib import Path

import pytest

from app.core.config import settings
from app.services.url_security.normalizer import URLNormalizer
from app.services.url_security.threat_intel import ThreatIntelService

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "build_ioc_feed.py"

pytestmark = pytest.mark.skipif(not _SCRIPT.exists(), reason="scripts/ not available in this environment")


@pytest.fixture(scope="module")
def builder():
    spec = importlib.util.spec_from_file_location("build_ioc_feed", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def policy(builder):
    return builder.DomainPolicy(builder.load_rule_lists())


@pytest.mark.parametrize("entry", [
    "sites.google.com", "telegra.ph", "google.com", "docs.google.com", "github.io", "web.app",
    "vietcombank.com.vn", "com.vn", "co.uk", "sharepoint.com", "blogspot.com",
])
def test_entries_that_would_block_a_platform_are_dropped(policy, entry):
    decision, _ = policy.classify(entry)
    assert decision == "skip_protected"


@pytest.mark.parametrize("entry", ["bit.ly", "bit.ly.", "tinyurl.com", "h.tiny.cc"])
def test_shorteners_are_dropped(policy, entry):
    assert policy.classify(entry)[0] == "skip_shortener"


@pytest.mark.parametrize("entry", [
    "vietcombank-xacthuc.com", "evil-login.web.app", "0utlook-shared-storage-03.firebaseapp.com",
    "02accounts2.github.io", "bucket-x.s3.amazonaws.com", "01ezdhsga.s3.us-east-1.amazonaws.com",
    "0ce40dce93.s3-eu-west-1.amazonaws.com",
])
def test_attacker_controlled_hosts_stay_phishing(policy, entry):
    assert policy.classify(entry) == ("phishing", entry)


@pytest.mark.parametrize("entry", ["acme-my.sharepoint.com", "79.docs.google.com", "abc.vietcombank.com.vn"])
def test_subdomains_of_legitimate_services_are_downgraded(policy, entry):
    assert policy.classify(entry)[0] == "suspicious"


@pytest.mark.parametrize("entry,expected", [("1.2.3.4", "skip_ip"), ("not a domain", "skip_invalid"), ("localhost", "skip_invalid")])
def test_invalid_entries(policy, entry, expected):
    assert policy.classify(entry)[0] == expected


def test_phishing_database_parsing_dedupes_and_stamps_download_time(builder, policy):
    text = "# comment\nvietcombank-xacthuc.com\nVIETCOMBANK-XACTHUC.COM.\nsites.google.com\nacme-my.sharepoint.com\n"
    recs, stats = builder.build_phishing_database(policy, text, 1_760_000_000)
    assert [r["domain"] for r in recs] == ["vietcombank-xacthuc.com", "acme-my.sharepoint.com"]
    assert recs[0]["verdict"] == "phishing" and recs[1]["verdict"] == "suspicious"
    assert all(r["last_seen"] == "2025-10-09T08:53:20Z" for r in recs)
    assert stats["skip_protected"] == 1 and stats["kept"] == 2


def test_urlhaus_csv_yields_exact_urls_only(builder):
    csv_text = (
        "################################################################\n"
        "# abuse.ch URLhaus Database Dump (CSV - recent URLs only)       #\n"
        "# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n"
        '"1","2026-10-01 10:00:00","http://1.2.3.4:8080/bins/x.sh","online","2026-10-09 11:00:00",'
        '"malware_download","elf","https://urlhaus.abuse.ch/url/1/","r"\n'
        '"2","2026-10-02 10:00:00","https://github.com/u/r/raw/main/a.exe","offline","",'
        '"malware_download","exe","https://urlhaus.abuse.ch/url/2/","r"\n'
        '"3","2026-10-02 10:00:00","ftp://x.example/a","offline","","malware_download","","",""\n'
    )
    recs, stats = builder.build_urlhaus(csv_text.encode())
    assert [r["url"] for r in recs] == ["http://1.2.3.4:8080/bins/x.sh", "https://github.com/u/r/raw/main/a.exe"]
    assert all("domain" not in r for r in recs)  # never block github.com as a whole
    assert recs[0]["last_seen"] == "2026-10-09T11:00:00Z"
    assert recs[1]["last_seen"] == recs[1]["first_seen"] == "2026-10-02T10:00:00Z"
    assert stats["skip_invalid"] == 1


def test_built_feed_loads_and_matches(builder, policy, tmp_path, monkeypatch):
    import time as _time
    now = _time.time()
    pd, _ = builder.build_phishing_database(
        policy, "vietcombank-xacthuc.com\nmbbank-otp.net\nsites.google.com\nacme-my.sharepoint.com\n", now)
    feed = tmp_path / "ioc_feed.jsonl"
    feed.write_text("".join(json.dumps(r) + "\n" for r in pd), encoding="utf-8")
    monkeypatch.setattr(settings, "TI_LOCAL_FEED_PATH", str(feed))
    monkeypatch.setattr(settings, "TI_LOCAL_FEED_SHA256", "")

    svc = ThreatIntelService()
    assert svc.local_feed_status == "loaded" and svc.local_feed_count == 3
    # Identical metadata is shared, not copied per line (memory for ~400k-entry feeds).
    a = svc._local_iocs["domain:vietcombank-xacthuc.com"][0]
    b = svc._local_iocs["domain:mbbank-otp.net"][0]
    assert a is b and "domain" not in a

    norm = URLNormalizer()
    hit = svc._local_ioc_lookup(norm.normalize("https://login.vietcombank-xacthuc.com/x"))
    assert hit is not None and hit.status == "known_malicious" and hit.freshness == "fresh"
    assert svc._local_ioc_lookup(norm.normalize("https://sites.google.com/view/my-shop")) is None
    shp = svc._local_ioc_lookup(norm.normalize("https://acme-my.sharepoint.com/personal/x"))
    assert shp is not None and shp.status == "suspicious"


def test_idn_punycode_and_holdout_isolation(builder, policy, tmp_path, monkeypatch):
    import time as _time
    now = _time.time()
    pd_recs, _ = builder.build_cert_polska(
        policy, "việtcombank.com.vn\nholdout-phish-test.com\n", now
    )
    filtered, removed = builder.filter_holdout_overlap(
        pd_recs, {"holdout-phish-test.com"}, set()
    )
    assert removed == 1 and len(filtered) == 1
    assert filtered[0]["domain"] == "xn--vitcombank-dv3e.com.vn"

    feed = tmp_path / "ioc_feed_idn.jsonl"
    feed.write_text("".join(json.dumps(r) + "\n" for r in filtered), encoding="utf-8")
    monkeypatch.setattr(settings, "TI_LOCAL_FEED_PATH", str(feed))
    monkeypatch.setattr(settings, "TI_LOCAL_FEED_SHA256", "")

    svc = ThreatIntelService()
    norm = URLNormalizer()
    hit_u = svc._local_ioc_lookup(norm.normalize("https://việtcombank.com.vn/login"))
    hit_a = svc._local_ioc_lookup(norm.normalize("https://xn--vitcombank-dv3e.com.vn/login"))
    assert hit_u is not None and hit_u.status == "known_malicious"
    assert hit_a is not None and hit_a.status == "known_malicious"
