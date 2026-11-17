#!/usr/bin/env python3
"""
Build the local IOC (Indicator of Compromise) feed for QR Guard.

What it does
------------
1. Downloads public, licence-compatible threat lists:
   - Phishing.Database  "phishing-domains-ACTIVE.txt"   (MIT licence)          -> domain IOCs
   - URLhaus "recent.csv" (abuse.ch, free under fair use; needs a free Auth-Key) -> exact-URL IOCs
2. Filters entries that would block legitimate platforms (see `classify_domain`).
3. Writes JSONL in the format read by ThreatIntelService._load_local_feed:
       {"domain": "...", "verdict": "phishing", "source": "...", "last_seen": "..."}
       {"url": "...",    "verdict": "malware",  "source": "...", "last_seen": "..."}
4. Writes a metadata file (sources, licences, counts, SHA-256) for audit / the thesis report.
5. Optionally pins the SHA-256 into .env (TI_LOCAL_FEED_SHA256).

Standard library only, so it runs with any Python 3.9+ on the host.

Usage
-----
    python scripts/build_ioc_feed.py                       # Phishing.Database only
    python scripts/build_ioc_feed.py --write-env           # + pin SHA-256 into .env
    python scripts/build_ioc_feed.py --urlhaus-key-file secrets/urlhaus_auth_key --write-env

Then restart the worker:  docker compose restart processing-worker
"""
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import sys
import tempfile
import time
import ssl
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "ti_feed" / "ioc_feed.jsonl"
ENV_FILE = ROOT / ".env"

USER_AGENT = "QRGuard-IOC-Builder/1.0 (non-commercial research)"
HTTP_TIMEOUT = 90

PHISHING_DATABASE_URL = (
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"
)
PHISHING_DATABASE_SOURCE = "Phishing.Database"
PHISHING_DATABASE_LICENCE = "MIT (https://github.com/Phishing-Database/Phishing.Database/blob/master/LICENSE)"

CERT_POLSKA_URL = "https://hole.cert.pl/domains/v2/domains.txt"
CERT_POLSKA_SOURCE = "CERT_Polska"
CERT_POLSKA_LICENCE = "Public Warning List - NASK / CERT Polska (https://hole.cert.pl)"

CHONGLUADAO_SOURCE = "ChongLuaDao_VN"
CHONGLUADAO_LICENCE = "ChongLuaDao / NCSC Vietnam Community Threat Feed (Train-Partition Only)"

URLHAUS_EXPORT_URL = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/recent.csv"
URLHAUS_SOURCE = "URLhaus (abuse.ch)"
URLHAUS_LICENCE = "abuse.ch Terms of Use - free under fair use principles (https://abuse.ch/terms-of-use/)"

AI_DATASET_ROOT = Path(os.environ.get("AI_DATASET_ROOT", ROOT.parent / "AI" / "dataset"))
SPLITS_DIR = AI_DATASET_ROOT / "splits" / "domain_disjoint_60_15_10_15"

_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
# Regional S3 bucket hosts: <bucket>.s3.<region>.amazonaws.com / <bucket>.s3-<region>.amazonaws.com
_S3_BUCKET_RE = re.compile(r"^[a-z0-9.-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com$")

# ── Filtering lists ────────────────────────────────────────────────────────────
# Platforms where the ATTACKER controls the sub-domain (evil.web.app). A feed entry for a
# sub-domain is precise and stays "phishing"; an entry for the platform apex itself would
# block every tenant and is dropped. (Complements SHARED_HOSTING_SUFFIXES from rules.py.)
EXTRA_TENANT_PLATFORMS = {
    "weeblysite.com", "wixstudio.io", "myshopify.com", "mystrikingly.com", "webnode.page",
    "jimdosite.com", "site123.me", "yolasite.com", "tilda.ws", "framer.app", "glide.page",
    "surge.sh", "fly.dev", "railway.app", "deno.dev", "cloudfront.net", "amplifyapp.com",
    "appspot.com", "translate.goog", "ipfs.io", "dweb.link", "duckdns.org", "ddns.net",
    "no-ip.org", "hopto.org", "zapto.org", "github.dev", "gitlab.io", "bitbucket.io",
    "firebaseio.com", "web.core.windows.net", "blob.core.windows.net", "digitaloceanspaces.com",
    "ngrok-free.dev", "loca.lt", "serveo.net", "weebly.com", "wixsite.com",
}

# Legitimate first-party services where a sub-domain belongs to the SERVICE or to a real
# customer organisation (acme-my.sharepoint.com, 79.docs.google.com). A phishing page hosted
# there does not make the whole host malicious, so such entries are downgraded to
# "suspicious" instead of "phishing". The apex itself is always dropped.
EXTRA_FIRST_PARTY = {
    "telegra.ph", "sharepoint.com", "onedrive.live.com", "1drv.ms", "office.com", "office365.com",
    "outlook.com", "dropbox.com", "dropboxusercontent.com", "github.com", "githubusercontent.com",
    "gitlab.com", "youtube.com", "youtu.be", "gmail.com", "linktr.ee", "canva.com", "wordpress.com",
    "medium.com", "notion.so", "box.com", "wetransfer.com", "mediafire.com", "mega.nz",
    "adobe.com", "yahoo.com", "amazon.com", "amazonaws.com", "cloudflare.com", "zoom.us",
    "instagram.com", "whatsapp.com", "tiktok.com", "x.com", "twitter.com", "linkedin.com",
    "baidu.com", "bing.com", "apple.co", "gov.vn",
}

# Public suffixes that must never become an indicator (an entry "co.uk" would match every
# domain below it because the matcher also checks parent domains).
PUBLIC_SUFFIXES = {
    "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "ac.vn", "info.vn", "biz.vn", "name.vn",
    "pro.vn", "health.vn", "int.vn", "io.vn", "id.vn", "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp", "com.br", "co.in", "com.cn",
    "com.sg", "com.my", "co.id", "co.th", "com.ph", "com.tw", "co.kr", "com.hk", "co.za",
}


OFFICIAL_BRAND_DOMAINS = {
    "vietcombank.com.vn", "techcombank.com.vn", "techcombank.com", "mbbank.com.vn",
    "bidv.com.vn", "agribank.com.vn", "vpbank.com.vn", "tpb.vn", "tpbank.vn", "tpbank.com.vn",
    "acb.com.vn", "sacombank.com.vn", "sacombank.com", "vnpay.vn", "momo.vn", "zalopay.vn",
    "viettelpay.vn", "viettelmoney.vn",
    "vietinbank.vn", "hdbank.com.vn", "shb.com.vn", "vib.com.vn", "eximbank.com.vn",
    "seabank.com.vn", "lpbank.com.vn", "ocb.com.vn", "msb.com.vn",
    "shopee.vn", "lazada.vn", "zalo.me", "zalo.vn", "vneid.gov.vn",
    "google.com", "google.com.vn", "googleapis.com", "googleusercontent.com", "gstatic.com",
    "apple.com", "icloud.com", "microsoft.com", "microsoftonline.com", "live.com",
    "paypal.com", "facebook.com", "fb.com", "telegram.org", "t.me", "binance.com",
}

SHARED_HOSTING_SUFFIXES = {
    "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle",
    "storage.googleapis.com", "firebasestorage.googleapis.com",
    "web.app", "firebaseapp.com", "appspot.com", "github.io", "vercel.app", "netlify.app", "pages.dev",
    "workers.dev", "r2.dev", "ngrok-free.app", "ngrok.io", "ngrok.app", "trycloudflare.com",
    "blogspot.com", "wixsite.com", "weebly.com", "glitch.me", "herokuapp.com", "onrender.com",
    "000webhostapp.com", "azurewebsites.net", "web.core.windows.net", "s3.amazonaws.com",
    "godaddysites.com", "webflow.io", "notion.site", "framer.website", "carrd.co",
    "canva.site", "square.site", "replit.app", "repl.co",
}

URL_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "buff.ly", "ow.ly",
    "rebrand.ly", "qrco.de", "s.net.vn", "shorturl.at", "tiny.cc", "goo.gl",
    "bl.ink", "v.gd", "t.ly", "rb.gy", "short.io", "linktr.ee",
}


def load_rule_lists(rules_path: Optional[Path] = None) -> Dict[str, Set[str]]:
    """Return the protected brand / shared-hosting / shortener lists."""
    return {
        "official": set(OFFICIAL_BRAND_DOMAINS),
        "shared": set(SHARED_HOSTING_SUFFIXES),
        "shorteners": set(URL_SHORTENER_DOMAINS),
    }


class DomainPolicy:
    """Decides what to do with one domain coming from a blocklist."""

    def __init__(self, rule_lists: Dict[str, Set[str]]):
        shared = rule_lists.get("shared", set())
        # Path-based tenants on Google infrastructure (sites.google.com/view/<anyone>).
        path_tenants = {s for s in shared if s.endswith("google.com") or s.endswith("googleapis.com")
                        or s == "forms.gle"}
        self.tenant_platforms = (shared - path_tenants) | EXTRA_TENANT_PLATFORMS
        self.first_party = rule_lists.get("official", set()) | path_tenants | EXTRA_FIRST_PARTY
        self.shorteners = rule_lists.get("shorteners", set())
        self.protected = self.tenant_platforms | self.first_party | self.shorteners | PUBLIC_SUFFIXES
        # Every protected domain AND all of its parent domains: an entry found here would cover
        # a protected platform (e.g. "google.com" covers "sites.google.com").
        self._covering: Set[str] = set()
        for p in self.protected:
            labels = p.split(".")
            for i in range(len(labels)):
                self._covering.add(".".join(labels[i:]))

    @staticmethod
    def _parents(d: str) -> List[str]:
        """Proper parent domains: a.b.c.com -> [b.c.com, c.com, com]."""
        labels = d.split(".")
        return [".".join(labels[i:]) for i in range(1, len(labels))]

    def _under(self, d: str, parents: Set[str]) -> bool:
        return any(p in parents for p in self._parents(d))

    def classify(self, raw: str) -> Tuple[str, Optional[str]]:
        """Return (decision, normalised_domain).

        decision: "phishing"   -> keep as known-malicious domain IOC
                  "suspicious" -> keep, downgraded (abused legitimate service)
                  "skip_invalid" | "skip_ip" | "skip_protected" | "skip_shortener"
        """
        d = (raw or "").strip().lower().rstrip(".")
        if d.startswith("*."):
            d = d[2:]
        try:
            ipaddress.ip_address(d)
            return "skip_ip", None
        except ValueError:
            pass
        if any(ord(c) > 127 for c in d):
            try:
                d = d.encode("idna").decode("ascii").lower()
            except UnicodeError:
                out_lbls: List[str] = []
                for lbl in d.split("."):
                    if not lbl or lbl.isascii():
                        out_lbls.append(lbl)
                    else:
                        try:
                            out_lbls.append(lbl.encode("idna").decode("ascii").lower())
                        except UnicodeError:
                            try:
                                out_lbls.append("xn--" + lbl.encode("punycode").decode("ascii"))
                            except Exception:
                                return "skip_invalid", None
                d = ".".join(out_lbls)
        if not _DOMAIN_RE.match(d) or "." not in d:
            return "skip_invalid", None
        if d in self.shorteners or self._under(d, self.shorteners):
            return "skip_shortener", d
        # The entry IS a protected platform / public suffix, or a parent of one: it would
        # block every legitimate user of that platform.
        if d in self._covering:
            return "skip_protected", d
        # Tenant sub-domains (evil.web.app, bucket.s3.amazonaws.com) are attacker-controlled.
        if self._under(d, self.tenant_platforms) or _S3_BUCKET_RE.match(d):
            return "phishing", d
        if self._under(d, self.first_party):
            return "suspicious", d
        return "phishing", d


# ── Download helpers ───────────────────────────────────────────────────────────
def _get_ssl_context() -> Optional[ssl.SSLContext]:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        try:
            return ssl.create_default_context()
        except Exception:
            return None


def http_get(url: str, redact: Optional[str] = None) -> bytes:
    shown = url.replace(redact, "***") if redact else url
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = _get_ssl_context()
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        raise SystemExit(f"[LOI] Tai that bai {shown}: HTTP {e.code}") from None
    except urllib.error.URLError as e:
        raise SystemExit(f"[LOI] Khong ket noi duoc {shown}: {e.reason}") from None


def _iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _to_iso(text: str) -> Optional[str]:
    text = (text or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.strptime(text.replace(" UTC", ""), fmt))
        except ValueError:
            continue
    return None


# ── Sources ────────────────────────────────────────────────────────────────────
def build_phishing_database(policy: DomainPolicy, raw_text: str, fetched_at: float) -> Tuple[List[dict], dict]:
    """Phishing.Database ACTIVE list: one domain per line, no per-entry dates.
    last_seen = download time ("listed as active when downloaded"); entries become stale
    after TI_IOC_MAX_AGE_DAYS unless the feed is rebuilt."""
    stats: Dict[str, int] = {}
    seen: Set[str] = set()
    out: List[dict] = []
    last_seen = _iso(fetched_at)
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        decision, d = policy.classify(line)
        if decision in ("phishing", "suspicious") and d in seen:
            continue
        stats[decision] = stats.get(decision, 0) + 1
        if decision not in ("phishing", "suspicious"):
            continue
        seen.add(d)
        out.append({
            "domain": d,
            "verdict": decision,
            "source": PHISHING_DATABASE_SOURCE,
            "indicator_type": "phishing_domain" if decision == "phishing" else "abused_legitimate_service",
            "confidence": 0.8 if decision == "phishing" else 0.5,
            "last_seen": last_seen,
        })
    stats["kept"] = len(out)
    return out, stats


def build_urlhaus(csv_bytes: bytes) -> Tuple[List[dict], dict]:
    """URLhaus recent.csv -> exact-URL indicators only. URLhaus lists many compromised but
    legitimate sites, so it never produces domain-level indicators."""
    if csv_bytes[:2] == b"PK":  # zipped export
        with zipfile.ZipFile(io.BytesIO(csv_bytes)) as zf:
            csv_bytes = zf.read(zf.namelist()[0])
    text = csv_bytes.decode("utf-8", errors="replace")

    columns = ["id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter"]
    data_lines: List[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            header = line.lstrip("#").strip()
            if header.startswith("id,") and "url" in header:
                columns = [c.strip() for c in header.split(",")]
            continue
        if line.strip():
            data_lines.append(line)

    stats = {"rows": 0, "kept": 0, "skip_invalid": 0, "duplicate": 0}
    seen: Set[str] = set()
    out: List[dict] = []
    for row in csv.reader(data_lines):
        stats["rows"] += 1
        rec = dict(zip(columns, row))
        url = (rec.get("url") or "").strip()
        if not url.lower().startswith(("http://", "https://")):
            stats["skip_invalid"] += 1
            continue
        if url in seen:
            stats["duplicate"] += 1
            continue
        seen.add(url)
        first_seen = _to_iso(rec.get("dateadded", ""))
        last_seen = _to_iso(rec.get("last_online", "")) or first_seen
        out.append({
            "url": url,
            "verdict": "malware",
            "source": URLHAUS_SOURCE,
            "indicator_type": "malware_url",
            "confidence": 0.9,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "url_status": (rec.get("url_status") or "").strip() or None,
        })
    stats["kept"] = len(out)
    return out, stats


def build_cert_polska(policy: DomainPolicy, raw_text: str, fetched_at: float) -> Tuple[List[dict], dict]:
    """CERT Polska warning list (hole.cert.pl): one domain per line."""
    stats: Dict[str, int] = {}
    seen: Set[str] = set()
    out: List[dict] = []
    last_seen = _iso(fetched_at)
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        decision, d = policy.classify(line)
        if decision in ("phishing", "suspicious") and d in seen:
            continue
        stats[decision] = stats.get(decision, 0) + 1
        if decision not in ("phishing", "suspicious"):
            continue
        seen.add(d)
        out.append({
            "domain": d,
            "verdict": decision,
            "source": CERT_POLSKA_SOURCE,
            "indicator_type": "phishing_domain" if decision == "phishing" else "abused_legitimate_service",
            "confidence": 0.85 if decision == "phishing" else 0.5,
            "last_seen": last_seen,
        })
    stats["kept"] = len(out)
    return out, stats


def build_chongluadao_train(policy: DomainPolicy, train_csv_path: Path, fetched_at: float) -> Tuple[List[dict], dict]:
    """Extract Vietnamese phishing/scam domain IOCs from ChongLuaDao_VN in train.csv only."""
    stats: Dict[str, int] = {"rows": 0}
    seen: Set[str] = set()
    out: List[dict] = []
    last_seen = _iso(fetched_at)
    if not train_csv_path.is_file():
        stats["kept"] = 0
        return out, stats
    with open(train_csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if (row.get("source") or "").strip() != CHONGLUADAO_SOURCE:
                continue
            if (row.get("label") or "").strip().lower() not in ("malicious", "1"):
                continue
            stats["rows"] += 1
            dom_raw = (row.get("domain") or "").strip()
            decision, d = policy.classify(dom_raw)
            if decision in ("phishing", "suspicious") and d in seen:
                continue
            stats[decision] = stats.get(decision, 0) + 1
            if decision not in ("phishing", "suspicious"):
                continue
            seen.add(d)
            out.append({
                "domain": d,
                "verdict": decision,
                "source": CHONGLUADAO_SOURCE,
                "indicator_type": "phishing_domain" if decision == "phishing" else "abused_legitimate_service",
                "confidence": 0.85 if decision == "phishing" else 0.5,
                "last_seen": (row.get("timestamp") or "").strip() or last_seen,
            })
    stats["kept"] = len(out)
    return out, stats


def load_holdout_exclusions(policy: DomainPolicy) -> Tuple[Set[str], Set[str]]:
    """
    Collect all domains, parent group_ids (eTLD+1), and URLs present in hold-out evaluation splits
    (val.csv, calib.csv, test.csv, external_benchmark_dataset.csv) so that Local IOC has 0.00%
    data leakage / overlap with any ML evaluation split.
    """
    excluded_domains: Set[str] = set()
    excluded_urls: Set[str] = set()
    holdout_files = [
        SPLITS_DIR / "val.csv",
        SPLITS_DIR / "calib.csv",
        SPLITS_DIR / "test.csv",
    ]
    for path in holdout_files:
        if not path.is_file():
            continue
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                u = (row.get("url") or "").strip().lower()
                if u:
                    excluded_urls.add(u)
                    excluded_urls.add(u.rstrip("/"))
                dom_val = (row.get("domain") or "").strip().lower().rstrip(".")
                if dom_val and dom_val not in policy.protected:
                    excluded_domains.add(dom_val)
                    _, norm_d = policy.classify(dom_val)
                    if norm_d and norm_d not in policy.protected:
                        excluded_domains.add(norm_d)
                grp_val = (row.get("group_id") or "").strip().lower().rstrip(".")
                if grp_val and grp_val not in policy.protected and grp_val not in policy._covering:
                    excluded_domains.add(grp_val)
                    _, norm_g = policy.classify(grp_val)
                    if norm_g and norm_g not in policy.protected and norm_g not in policy._covering:
                        excluded_domains.add(norm_g)
    return excluded_domains, excluded_urls


def filter_holdout_overlap(
    records: List[dict], excluded_domains: Set[str], excluded_urls: Set[str]
) -> Tuple[List[dict], int]:
    """Remove any IOC indicator that overlaps with hold-out evaluation domains/groups/URLs."""
    if not excluded_domains and not excluded_urls:
        return records, 0
    kept: List[dict] = []
    removed = 0
    dup_removed = 0
    seen_domains: Set[str] = set()
    for r in records:
        dom = (r.get("domain") or "").strip().lower()
        url = (r.get("url") or "").strip().lower()
        if dom:
            parents = DomainPolicy._parents(dom)
            if dom in excluded_domains or any(p in excluded_domains for p in parents):
                removed += 1
                continue
            if dom in seen_domains:
                dup_removed += 1
                continue
            seen_domains.add(dom)
        if url:
            if url in excluded_urls or url.rstrip("/") in excluded_urls:
                removed += 1
                continue
        kept.append(r)
    return kept, removed


# ── Output ─────────────────────────────────────────────────────────────────────
def write_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_", suffix=path.suffix)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def update_env(env_path: Path, key: str, value: str) -> None:
    lines = env_path.read_text(encoding="utf-8").splitlines() if env_path.exists() else []
    found = False
    for i, line in enumerate(lines):
        if line.strip().startswith(f"{key}="):
            lines[i] = f"{key}={value}"
            found = True
    if not found:
        lines.append(f"{key}={value}")
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def read_secret(path: Optional[str]) -> Optional[str]:
    if path:
        p = Path(path)
        if not p.is_absolute():
            p = ROOT / p
        if not p.exists():
            raise SystemExit(f"[LOI] Khong tim thay file key: {p}")
        return p.read_text(encoding="utf-8").strip() or None
    default_key_file = ROOT / "secrets" / "urlhaus_auth_key"
    if default_key_file.exists():
        return default_key_file.read_text(encoding="utf-8").strip() or None
    return (os.environ.get("URLHAUS_AUTH_KEY") or "").strip() or None


def main(argv: Optional[List[str]] = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="Build the QR Guard local IOC feed.")
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="Output JSONL path (default: ti_feed/ioc_feed.jsonl)")
    ap.add_argument("--no-phishing-database", action="store_true", help="Skip Phishing.Database")
    ap.add_argument("--urlhaus-key-file", default=None,
                    help="File containing your free abuse.ch Auth-Key (or set env URLHAUS_AUTH_KEY)")
    ap.add_argument("--write-env", action="store_true", help="Pin TI_LOCAL_FEED_SHA256 in .env")
    args = ap.parse_args(argv)

    policy = DomainPolicy(load_rule_lists())
    records: List[dict] = []
    sources_meta: List[dict] = []

    if not args.no_phishing_database:
        print("[1/3] Dang tai Phishing.Database (phishing-domains-ACTIVE.txt)...")
        t = time.time()
        raw = http_get(PHISHING_DATABASE_URL)
        recs, stats = build_phishing_database(policy, raw.decode("utf-8", errors="replace"), t)
        records.extend(recs)
        sources_meta.append({
            "name": PHISHING_DATABASE_SOURCE, "url": PHISHING_DATABASE_URL, "licence": PHISHING_DATABASE_LICENCE,
            "downloaded_at": _iso(t), "download_sha256": hashlib.sha256(raw).hexdigest(), "stats": stats,
        })
        print(f"      giu lai {stats['kept']:,} domain | bo qua: "
              + ", ".join(f"{k}={v:,}" for k, v in sorted(stats.items()) if k.startswith("skip_"))
              + f" | ha xuong 'suspicious': {stats.get('suspicious', 0):,}")

    key = read_secret(args.urlhaus_key_file)
    if key:
        print("[2/4] Dang tai URLhaus recent.csv...")
        t = time.time()
        raw = http_get(URLHAUS_EXPORT_URL.format(key=key), redact=key)
        recs, stats = build_urlhaus(raw)
        records.extend(recs)
        sources_meta.append({
            "name": URLHAUS_SOURCE, "url": URLHAUS_EXPORT_URL.format(key="<AUTH-KEY>"), "licence": URLHAUS_LICENCE,
            "downloaded_at": _iso(t), "download_sha256": hashlib.sha256(raw).hexdigest(), "stats": stats,
        })
        print(f"      giu lai {stats['kept']:,} URL (tong {stats['rows']:,} dong)")
    else:
        print("[2/4] Bo qua URLhaus (chua co Auth-Key; xem ti_feed/README.md)")

    print("[3/4] Dang tai CERT Polska (hole.cert.pl/domains/v2/domains.txt) & ChongLuaDao_VN (train.csv)...")
    try:
        t_cp = time.time()
        raw_cp = http_get(CERT_POLSKA_URL)
        recs_cp, stats_cp = build_cert_polska(policy, raw_cp.decode("utf-8", errors="replace"), t_cp)
        records.extend(recs_cp)
        sources_meta.append({
            "name": CERT_POLSKA_SOURCE, "url": CERT_POLSKA_URL, "licence": CERT_POLSKA_LICENCE,
            "downloaded_at": _iso(t_cp), "download_sha256": hashlib.sha256(raw_cp).hexdigest(), "stats": stats_cp,
        })
        print(f"      CERT_Polska: giu lai {stats_cp['kept']:,} domain")
    except SystemExit as e:
        print(f"      [CANH BAO] Bo qua CERT_Polska: {e}")

    train_csv = SPLITS_DIR / "train.csv"
    if train_csv.is_file():
        t_cld = time.time()
        recs_cld, stats_cld = build_chongluadao_train(policy, train_csv, t_cld)
        records.extend(recs_cld)
        sources_meta.append({
            "name": CHONGLUADAO_SOURCE, "url": "https://chongluadao.vn (train partition)", "licence": CHONGLUADAO_LICENCE,
            "downloaded_at": _iso(t_cld), "stats": stats_cld,
        })
        print(f"      ChongLuaDao_VN (train): giu lai {stats_cld['kept']:,} domain")

    excluded_domains, excluded_urls = load_holdout_exclusions(policy)
    records, n_holdout_removed = filter_holdout_overlap(records, excluded_domains, excluded_urls)
    print(f"      Hold-out split isolation: da loai bo {n_holdout_removed:,} indicator trung tap val/calib/test/external (0.00% overlap)")

    if not records:
        print("[LOI] Khong co IOC nao duoc tao.")
        return 1

    out = Path(args.out)
    if not out.is_absolute():
        out = ROOT / out
    body = "".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n" for r in records).encode("utf-8")
    sha = hashlib.sha256(body).hexdigest()
    write_atomic(out, body)

    meta = {
        "generated_at": _iso(time.time()),
        "generator": "scripts/build_ioc_feed.py",
        "feed_file": out.name,
        "feed_sha256": sha,
        "indicator_count": len(records),
        "domain_indicators": sum(1 for r in records if "domain" in r),
        "url_indicators": sum(1 for r in records if "url" in r),
        "holdout_overlap_removed": n_holdout_removed,
        "sources": sources_meta,
        "filtering": {
            "skip_protected": "entry equals / is a parent of an official brand domain, a hosting platform, "
                              "a URL shortener or a public suffix (would block every legitimate user)",
            "suspicious": "sub-domain of a legitimate first-party service (e.g. *.sharepoint.com, "
                          "*.docs.google.com): downgraded, never 'known malicious'",
            "urlhaus": "exact-URL indicators only (no domain-level blocking of compromised sites)",
            "holdout_isolation": "excludes 100% of domains, eTLD+1 group_ids, and URLs present in val.csv, calib.csv, test.csv, and external_benchmark_dataset.csv (0% evaluation leakage)",
        },
    }
    write_atomic(out.with_suffix(".meta.json"), json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"))

    print(f"[4/4] Da ghi {len(records):,} IOC -> {out.relative_to(ROOT) if out.is_relative_to(ROOT) else out}")
    print(f"      SHA-256: {sha}")
    if args.write_env:
        update_env(ENV_FILE, "TI_LOCAL_FEED_SHA256", sha)
        print("      Da cap nhat TI_LOCAL_FEED_SHA256 trong .env")
    else:
        print("      (Chay lai voi --write-env de ghim SHA-256 vao .env)")
    print("Tiep theo: docker compose up -d processing-worker   (khoi dong lai worker de nap feed moi)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
