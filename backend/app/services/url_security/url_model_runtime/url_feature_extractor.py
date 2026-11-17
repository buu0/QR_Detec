"""
URL Feature Extractor — 81 Canonical Features
=============================================
Implements EXACTLY 81 features for the QRDetec URL XGBoost model
(69 QRDetec features with semantic lexicon fusion + 12 orthogonal features
inherited from Hannousse & Yahiouche, 2021).

Feature groups:
  A. URL structure            (11 features)
  B. Character & entropy      (15 features)
  C. Domain, scheme, encoding (10 features)
  D. Evasion & execution      (7 features)
  E. Brand & impersonation    (11 features)
  F. Phishing & VN keywords   (8 features)
  G. Unicode & IDN            (7 features)
  H. Lexical & token stats    (12 features)

Rules:
- Same extractor used across validation, calibration, testing, inference.
- No network requests, no DNS, no URL fetching.
- Errors for a single URL return zero-vector; do NOT raise.
"""

import math
import re
import unicodedata
import logging
from typing import Any

from .url_normalizer import (
    URLComponents,
    normalize_url,
    get_all_views,
    count_percent_encoding,
    has_nested_encoding,
    KNOWN_SAFE_SCHEMES,
    SUSPICIOUS_SCHEMES,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature constants
# ---------------------------------------------------------------------------
FEATURE_COUNT = 81
N_FEATURES = 81

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits/char) of string s."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _ratio(num: int, denom: int) -> float:
    return num / denom if denom > 0 else 0.0


def _count_digits(s: str) -> int:
    return sum(1 for c in s if c.isdigit())


def _count_letters(s: str) -> int:
    return sum(1 for c in s if c.isalpha())


def _tokenize_lower(s: str) -> list[str]:
    """Split into lowercase tokens on non-alphanumeric boundaries."""
    if not s:
        return []
    return re.split(r"[^a-z0-9]+", s.lower())


# ---------------------------------------------------------------------------
# A. URL Structure — 11 features
# ---------------------------------------------------------------------------

# Port value sentinel when no port is declared
_NO_PORT = -1
# Standard ports (used for context; port_val is the raw value, not a flag)
_STANDARD_PORTS = {80, 443, 21, 22, 25, 8080, 8443}


def _group_a(raw: str, comp: URLComponents) -> dict[str, Any]:
    """A. URL Structure — 11 features."""
    hostname = comp.hostname
    path = comp.path
    query = comp.query
    fragment = comp.fragment

    url_len = len(raw)
    hostname_len = len(hostname)
    path_len = len(path)
    query_len = len(query)
    fragment_len = len(fragment)

    n_digits_url = _count_digits(raw)
    n_letters_url = _count_letters(raw)
    n_special_url = len(re.findall(r"[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]", raw))

    # Subdomain count
    parts = [p for p in hostname.split(".") if p] if hostname else []
    if len(parts) >= 3:
        two_part = f"{parts[-2]}.{parts[-1]}".lower()
        _MULTI_TLDS = {
            "com.vn", "net.vn", "org.vn", "edu.vn", "gov.vn", "int.vn",
            "ac.vn", "biz.vn", "info.vn", "co.uk", "org.uk", "co.jp",
            "ne.jp", "com.au", "net.au", "com.sg", "edu.sg",
        }
        base = 3 if two_part in _MULTI_TLDS else 2
    else:
        base = 2
    n_subdomains = max(0, len(parts) - base)

    # Path depth = number of '/' in path
    path_depth = path.count("/") if path else 0

    # port_val: -1 if absent, else integer value
    port_val = comp.port if comp.port is not None else _NO_PORT

    return {
        # A1-A5: lengths
        "url_len":          url_len,
        "hostname_len":     hostname_len,
        "path_len":         path_len,
        "query_len":        query_len,
        "fragment_len":     fragment_len,
        # A6-A8: character ratios in full URL
        "ratio_digits_url":  _ratio(n_digits_url,  url_len),
        "ratio_letters_url": _ratio(n_letters_url, url_len),
        "ratio_special_url": _ratio(n_special_url, url_len),
        # A9-A11
        "n_subdomains":     n_subdomains,
        "path_depth":       path_depth,
        "port_val":         port_val,
    }


# ---------------------------------------------------------------------------
# B. Character counts & entropy — 15 features
# ---------------------------------------------------------------------------

def _group_b(raw: str, comp: URLComponents) -> dict[str, Any]:
    """B. Character & Entropy — 15 features."""
    hostname = comp.hostname
    path = comp.path
    decoded_host = _decode_idn_hostname(hostname) if "xn--" in hostname.lower() else hostname

    return {
        # URL-level character counts
        "n_dots_url":         raw.count("."),
        "n_hyphens_url":      raw.count("-"),
        "n_underscores_url":  raw.count("_"),
        "n_slashes_url":      raw.count("/"),
        "n_question_url":     raw.count("?"),
        "n_equal_url":        raw.count("="),
        "n_at_url":           raw.count("@"),
        "n_ampersand_url":    raw.count("&"),
        "n_percent_url":      raw.count("%"),
        # Hostname-level (evaluated on decoded U-label for Punycode IDNs so xn-- prefix/delta digits do not inflate counts)
        "n_dots_host":        decoded_host.count("."),
        "n_hyphens_host":     decoded_host.count("-"),
        "n_digits_host":      _count_digits(decoded_host),
        # Entropy
        "entropy_url":        _shannon_entropy(raw),
        "entropy_host":       _shannon_entropy(decoded_host),
        "entropy_path":       _shannon_entropy(path),
    }


# ---------------------------------------------------------------------------
# C. Domain, scheme & encoding — 10 features
# ---------------------------------------------------------------------------

# Suspicious TLD list — version-controlled, source: known abuse registrars
_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "pw", "cc",
    "ru", "cn", "info", "biz", "ws", "club", "site", "online",
    "work", "click", "link", "icu", "vip", "live", "buzz",
})

_HTML_ENTITY_RE = re.compile(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);")
_DATA_URI_RE    = re.compile(r"data:[^,]*,", re.IGNORECASE)


def _is_suspicious_tld(hostname: str) -> int:
    """1 if hostname ends with a suspicious TLD, else 0."""
    if not hostname:
        return 0
    parts = hostname.rstrip(".").split(".")
    if not parts:
        return 0
    tld = parts[-1].lower()
    return int(tld in _SUSPICIOUS_TLDS)


def _group_c(raw: str, comp: URLComponents) -> dict[str, Any]:
    """C. Domain, scheme & encoding — 10 features."""
    hostname = comp.hostname
    scheme = comp.scheme

    # TLD length
    parts = hostname.rstrip(".").split(".") if hostname else []
    tld_len = len(parts[-1]) if parts else 0

    # Scheme classification
    scheme_is_https = int(scheme == "https")
    scheme_is_http  = int(scheme == "http")
    scheme_is_other = int(
        scheme not in ("https", "http", "")
        and scheme not in SUSPICIOUS_SCHEMES
    )
    scheme_missing  = int(comp.had_missing_scheme)

    # Encoding
    n_pct_encoded = count_percent_encoding(raw)
    decode_depth  = comp.decode_depth_reached

    return {
        "has_ip_host":        int(comp.is_ip_host),
        "tld_len":            tld_len,
        "is_suspicious_tld":  _is_suspicious_tld(hostname),
        "has_userinfo":       int(bool(comp.userinfo)),
        "scheme_is_https":    scheme_is_https,
        "scheme_is_http":     scheme_is_http,
        "scheme_is_other":    scheme_is_other,
        "scheme_missing":     scheme_missing,
        "n_pct_encoded":      n_pct_encoded,
        "decode_depth":       decode_depth,
    }


# ---------------------------------------------------------------------------
# D. Evasion & execution — 7 features
# ---------------------------------------------------------------------------

_HEX_ESCAPE_RE  = re.compile(r"\\x[0-9a-fA-F]{2}")
_JS_PSEUDO_RE   = re.compile(r"javascript\s*:", re.IGNORECASE)
# Executable extensions in last path segment (structural signal, not verdict)
_EXE_EXTS: frozenset[str] = frozenset({
    "exe", "bat", "cmd", "ps1", "vbs", "scr", "jar", "hta",
    "com", "pif", "reg", "msi", "dll",
})
# Archive/compressed extensions
_ARCHIVE_EXTS: frozenset[str] = frozenset({
    "zip", "rar", "7z", "tar", "gz", "bz2", "cab", "iso",
    "apk", "dmg", "img",
})
# Redirect parameter names
_REDIRECT_PARAMS: frozenset[str] = frozenset({
    "redirect", "redirect_url", "redirect_uri", "return_url", "returnurl",
    "return_uri", "url", "target", "dest", "destination",
    "next", "continue", "goto", "redir", "forward", "link",
})


def _path_extension(path: str) -> str:
    """Extract lowercase file extension from last path segment, or ''."""
    if not path:
        return ""
    last = path.rstrip("/").split("/")[-1]
    if "." not in last:
        return ""
    ext = last.rsplit(".", 1)[-1].lower()
    # Strip query string if present
    ext = ext.split("?")[0].split("#")[0]
    return ext if re.match(r"^[a-z0-9]{1,8}$", ext) else ""


def _group_d(raw: str, comp: URLComponents) -> dict[str, Any]:
    """D. Evasion & execution — 7 features."""
    all_views = get_all_views(comp)

    has_escape_seq = int(any(_HEX_ESCAPE_RE.search(v) for v in all_views))
    has_html_entities = int(any(_HTML_ENTITY_RE.search(v) for v in all_views))
    has_data_uri = int(any(_DATA_URI_RE.search(v) for v in all_views))
    has_javascript_pseudo = int(any(_JS_PSEUDO_RE.search(v) for v in all_views))

    ext = _path_extension(comp.path)
    has_executable_extension = int(ext in _EXE_EXTS)
    has_archive_extension    = int(ext in _ARCHIVE_EXTS)

    # Redirect parameter in query string
    query_lower = comp.query.lower()
    has_redirect_parameter = 0
    if query_lower:
        param_names = set(k.split("=")[0].strip() for k in query_lower.split("&"))
        has_redirect_parameter = int(bool(param_names & _REDIRECT_PARAMS))

    return {
        "has_escape_seq":          has_escape_seq,
        "has_html_entities":       has_html_entities,
        "has_data_uri":            has_data_uri,
        "has_javascript_pseudo":   has_javascript_pseudo,
        "has_executable_extension": has_executable_extension,
        "has_archive_extension":   has_archive_extension,
        "has_redirect_parameter":  has_redirect_parameter,
    }


# ---------------------------------------------------------------------------
# E. Brand & impersonation — 11 features
# ---------------------------------------------------------------------------

# Import brand registry — used for all brand features
try:
    from .vietnamese_threats import (
        OFFICIAL_VN_BRANDS,
        MULTI_PART_TLDS,
        extract_registered_domain,
    )
    _BRAND_REGISTRY_AVAILABLE = True
except ImportError:
    OFFICIAL_VN_BRANDS = {}
    MULTI_PART_TLDS = set()
    _BRAND_REGISTRY_AVAILABLE = False
    logger.warning("vietnamese_threats.py not importable; brand features will be 0")


# Precomputed lookup structures (built once at module load, not per-URL)
def _build_brand_lookups():
    """Build fast lookup structures from OFFICIAL_VN_BRANDS."""
    # official_domain -> brand_key
    domain_to_brand: dict[str, str] = {}
    # (keyword, brand_key, is_short) list for sequential scan
    kw_list: list[tuple[str, str, bool]] = []
    # brand_key -> set of official_apex_domains
    brand_to_domains: dict[str, frozenset] = {}
    # brand_key -> list of keywords
    brand_to_kws: dict[str, list] = {}

    for bk, bi in OFFICIAL_VN_BRANDS.items():
        for d in bi.get("official_apex_domains", set()):
            domain_to_brand[d] = bk
        kws = bi.get("keywords", [])
        for kw in kws:
            kw_list.append((kw, bk, len(kw) <= 3))
        brand_to_domains[bk] = frozenset(bi.get("official_apex_domains", set()))
        brand_to_kws[bk] = list(kws)

    return domain_to_brand, kw_list, brand_to_domains, brand_to_kws


if _BRAND_REGISTRY_AVAILABLE and OFFICIAL_VN_BRANDS:
    _DOMAIN_TO_BRAND, _KW_LIST, _BRAND_TO_DOMAINS, _BRAND_TO_KWS = _build_brand_lookups()
else:
    _DOMAIN_TO_BRAND, _KW_LIST, _BRAND_TO_DOMAINS, _BRAND_TO_KWS = {}, [], {}, {}


# Security / payment keyword sets for brand co-occurrence
_SECURITY_KEYWORDS: frozenset[str] = frozenset({
    "secure", "login", "signin", "verify", "verification", "otp",
    "auth", "authentication", "validate", "xacthuc", "dangnhap",
    "baomat", "account", "confirm",
})
_PAYMENT_KEYWORDS: frozenset[str] = frozenset({
    "pay", "payment", "checkout", "transfer", "wallet", "ewallet",
    "billing", "transaction", "naptien", "chuyentien", "deposit",
})


_MAX_LEV_LEN = 30  # Cap string length to keep Levenshtein O(900) worst case


def _levenshtein_ratio(s1: str, s2: str) -> float:
    """
    Normalized Levenshtein similarity: 1 - edit_distance / max(len(s1), len(s2)).
    Returns 0.0 when either string is empty or either is > _MAX_LEV_LEN.
    Capped to avoid O(m*n) on long strings.
    """
    if not s1 or not s2:
        return 0.0
    if len(s1) > _MAX_LEV_LEN or len(s2) > _MAX_LEV_LEN:
        # For very long strings, use a fast prefix similarity heuristic
        common = sum(a == b for a, b in zip(s1[:_MAX_LEV_LEN], s2[:_MAX_LEV_LEN]))
        return common / _MAX_LEV_LEN
    m, n = len(s1), len(s2)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            if s1[i - 1] == s2[j - 1]:
                dp[j] = prev
            else:
                dp[j] = 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    edit_dist = dp[n]
    max_len = max(m, n)
    return 1.0 - edit_dist / max_len


# Cyrillic, Greek, and Latin homoglyph confusable map for IDN homograph detection
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic lookalikes
    "\u0430": "a", "\u0432": "b", "\u0441": "c", "\u0435": "e",
    "\u0433": "r", "\u04bb": "h", "\u0456": "i", "\u0457": "i",
    "\u0458": "j", "\u043a": "k", "\u04cf": "l", "\u043c": "m",
    "\u043d": "h", "\u043e": "o", "\u0440": "p", "\u0455": "s",
    "\u0442": "t", "\u0443": "y", "\u0445": "x", "\u0461": "w",
    "\u0434": "d", "\u0501": "d", "\u051b": "q", "\u051d": "w",
    # Greek lookalikes
    "\u03b1": "a", "\u03b2": "b", "\u03b3": "y", "\u03b5": "e",
    "\u03b9": "i", "\u03ba": "k", "\u03bd": "v", "\u03bf": "o",
    "\u03c1": "p", "\u03c4": "t", "\u03c5": "u", "\u03c7": "x",
    "\u03c9": "w",
    # Latin stroke / dotless lookalikes (including Vietnamese đ)
    "\u0111": "d", "\u0110": "d", "\u0131": "i", "\u0142": "l",
    "\u00f8": "o",
}

# Global high-value brands frequently targeted by IDN homograph / Punycode phishing
_IDN_EXTRA_BRANDS: dict[str, dict[str, Any]] = {
    "apple": {"official_apex_domains": frozenset({"apple.com", "icloud.com"}), "keywords": ["apple", "icloud"]},
    "microsoft": {"official_apex_domains": frozenset({"microsoft.com", "live.com", "office.com"}), "keywords": ["microsoft", "office365", "outlook", "onedrive", "sharepoint"]},
    "facebook": {"official_apex_domains": frozenset({"facebook.com", "fb.com", "meta.com"}), "keywords": ["facebook", "meta"]},
    "binance": {"official_apex_domains": frozenset({"binance.com"}), "keywords": ["binance"]},
    "telegram": {"official_apex_domains": frozenset({"telegram.org", "t.me"}), "keywords": ["telegram"]},
    "instagram": {"official_apex_domains": frozenset({"instagram.com"}), "keywords": ["instagram"]},
    "whatsapp": {"official_apex_domains": frozenset({"whatsapp.com"}), "keywords": ["whatsapp"]},
    "netflix": {"official_apex_domains": frozenset({"netflix.com"}), "keywords": ["netflix"]},
    "amazon": {"official_apex_domains": frozenset({"amazon.com"}), "keywords": ["amazon"]},
    "metamask": {"official_apex_domains": frozenset({"metamask.io"}), "keywords": ["metamask"]},
    "coinbase": {"official_apex_domains": frozenset({"coinbase.com"}), "keywords": ["coinbase"]},
    "booking": {"official_apex_domains": frozenset({"booking.com"}), "keywords": ["booking"]},
    "dhl": {"official_apex_domains": frozenset({"dhl.com"}), "keywords": ["dhl"]},
    "ebay": {"official_apex_domains": frozenset({"ebay.com"}), "keywords": ["ebay"]},
    "steam": {"official_apex_domains": frozenset({"steampowered.com", "steamcommunity.com"}), "keywords": ["steam", "steamcommunity"]},
    "discord": {"official_apex_domains": frozenset({"discord.com", "discordapp.com"}), "keywords": ["discord"]},
    "ripple": {"official_apex_domains": frozenset({"ripple.com", "xrpl.org"}), "keywords": ["ripple"]},
    "bitpanda": {"official_apex_domains": frozenset({"bitpanda.com"}), "keywords": ["bitpanda"]},
    "kraken": {"official_apex_domains": frozenset({"kraken.com"}), "keywords": ["kraken"]},
    "ledger": {"official_apex_domains": frozenset({"ledger.com"}), "keywords": ["ledger"]},
    "trezor": {"official_apex_domains": frozenset({"trezor.io"}), "keywords": ["trezor"]},
    "trustwallet": {"official_apex_domains": frozenset({"trustwallet.com"}), "keywords": ["trustwallet"]},
    "uniswap": {"official_apex_domains": frozenset({"uniswap.org"}), "keywords": ["uniswap"]},
    "opensea": {"official_apex_domains": frozenset({"opensea.io"}), "keywords": ["opensea"]},
    "allegro": {"official_apex_domains": frozenset({"allegro.pl"}), "keywords": ["allegro", "allegrolokalnie"]},
    "inpost": {"official_apex_domains": frozenset({"inpost.pl"}), "keywords": ["inpost"]},
    "pkobp": {"official_apex_domains": frozenset({"pkobp.pl", "ipko.pl"}), "keywords": ["pkobp", "ipko"]},
    "pekao": {"official_apex_domains": frozenset({"pekao.com.pl"}), "keywords": ["pekao"]},
    "santander": {"official_apex_domains": frozenset({"santander.pl", "santander.com"}), "keywords": ["santander"]},
    "mbank": {"official_apex_domains": frozenset({"mbank.pl"}), "keywords": ["mbank"]},
    "orlen": {"official_apex_domains": frozenset({"orlen.pl"}), "keywords": ["orlen"]},
    "poczta": {"official_apex_domains": frozenset({"poczta-polska.pl"}), "keywords": ["poczta-polska", "pocztapolska"]},
    "vinted": {"official_apex_domains": frozenset({"vinted.pl", "vinted.com"}), "keywords": ["vinted"]},
    "dpd": {"official_apex_domains": frozenset({"dpd.com", "dpd.com.pl"}), "keywords": ["dpd"]},
    "ups": {"official_apex_domains": frozenset({"ups.com"}), "keywords": ["ups"]},
    "fedex": {"official_apex_domains": frozenset({"fedex.com"}), "keywords": ["fedex"]},
    "revolut": {"official_apex_domains": frozenset({"revolut.com"}), "keywords": ["revolut"]},
    "stripe": {"official_apex_domains": frozenset({"stripe.com"}), "keywords": ["stripe"]},
    "chase": {"official_apex_domains": frozenset({"chase.com"}), "keywords": ["chase"]},
    "wellsfargo": {"official_apex_domains": frozenset({"wellsfargo.com"}), "keywords": ["wellsfargo"]},
    "citibank": {"official_apex_domains": frozenset({"citi.com", "citibank.com"}), "keywords": ["citibank"]},
    "hsbc": {"official_apex_domains": frozenset({"hsbc.com"}), "keywords": ["hsbc"]},
    "airbnb": {"official_apex_domains": frozenset({"airbnb.com"}), "keywords": ["airbnb"]},
    "linkedin": {"official_apex_domains": frozenset({"linkedin.com"}), "keywords": ["linkedin"]},
    "adobe": {"official_apex_domains": frozenset({"adobe.com"}), "keywords": ["adobe"]},
    "dropbox": {"official_apex_domains": frozenset({"dropbox.com"}), "keywords": ["dropbox"]},
    "docusign": {"official_apex_domains": frozenset({"docusign.com"}), "keywords": ["docusign"]},
}


def _decode_idn_hostname(hostname: str) -> str:
    """Safely decode Punycode (xn--) labels in hostname to lowercase Unicode without network calls."""
    if not hostname:
        return ""
    h_lower = hostname.lower()
    if "xn--" not in h_lower:
        return h_lower
    out_labels = []
    for lbl in h_lower.split("."):
        if lbl.startswith("xn--"):
            body = lbl[4:]
            decoded_lbl = None
            try:
                decoded_lbl = body.encode("ascii").decode("punycode").lower()
            except Exception:
                try:
                    decoded_lbl = lbl.encode("ascii").decode("idna").lower()
                except Exception:
                    if "-" in body:
                        decoded_lbl = body.rsplit("-", 1)[0]
                    else:
                        decoded_lbl = lbl
            out_labels.append(decoded_lbl)
        else:
            out_labels.append(lbl)
    return ".".join(out_labels)


def _apply_homoglyph_map(s: str) -> str:
    """Replace known homoglyphs with ASCII equivalents."""
    return "".join(_HOMOGLYPH_MAP.get(c, _HOMOGLYPH_MAP.get(c.lower(), c)) for c in s)


def _to_idn_ascii_skeleton(hostname: str) -> str:
    """
    Convert an IDN (Punycode xn-- or raw Unicode) hostname into its Latin ASCII skeleton:
      1. Decode any xn-- Punycode labels to Unicode
      2. Map Cyrillic/Greek/Latin-stroke lookalikes (e.g. а->a, е->e, р->p, ӏ->l, đ->d)
      3. Strip Unicode NFD combining diacritics (e.g. việtcombank -> vietcombank, mômô -> momo)
    """
    decoded = _decode_idn_hostname(hostname)
    mapped = _apply_homoglyph_map(decoded)
    decomposed = unicodedata.normalize("NFD", mapped)
    stripped = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
    return unicodedata.normalize("NFKC", stripped).lower()


def _group_e(raw: str, comp: URLComponents) -> dict[str, Any]:
    """E. Brand & impersonation — 11 features."""
    if not _BRAND_REGISTRY_AVAILABLE or not OFFICIAL_VN_BRANDS:
        return {k: 0 for k in [
            "brand_token_in_hostname", "brand_token_in_registered_domain",
            "brand_token_in_subdomain", "brand_token_in_path", "brand_token_in_query",
            "brand_official_domain_match", "brand_official_domain_mismatch",
            "brand_lookalike_distance", "brand_homoglyph_similarity",
            "brand_plus_security_keyword", "brand_plus_payment_keyword",
        ]}

    hostname = comp.hostname
    path_lower = comp.path.lower()
    query_lower = comp.query.lower()
    url_lower = raw.lower()

    subdomain_str, reg_domain = extract_registered_domain(hostname)
    is_idn_or_unicode = ("xn--" in hostname.lower()) or any(ord(c) > 127 for c in hostname)
    skeleton_host = _to_idn_ascii_skeleton(hostname) if is_idn_or_unicode else hostname
    skeleton_sub, skeleton_reg = (
        extract_registered_domain(skeleton_host) if is_idn_or_unicode else (subdomain_str, reg_domain)
    )

    # --- Find best candidate brand (using precomputed lookups) ---
    best_brand_key: str | None = None

    # Priority 1: O(1) official domain lookup
    best_brand_key = _DOMAIN_TO_BRAND.get(reg_domain)

    # Priority 2: keyword scan in URL (sequential but short-circuits on first match)
    if best_brand_key is None:
        # Precompute URL tokens for short keyword matching (done once per URL)
        url_tokens: set[str] | None = None
        for kw, bk, is_short in _KW_LIST:
            if is_short:
                if url_tokens is None:
                    url_tokens = set(re.split(r"[^a-zA-Z0-9]+", url_lower))
                if kw in url_tokens:
                    best_brand_key = bk
                    break
            else:
                if kw in url_lower:
                    best_brand_key = bk
                    break

    # Priority 3: IDN Homograph / Punycode / Vietnamese diacritic skeleton brand scan
    if best_brand_key is None and is_idn_or_unicode:
        best_brand_key = _DOMAIN_TO_BRAND.get(skeleton_reg)
        if best_brand_key is None:
            skel_tokens = set(re.split(r"[^a-z0-9]+", skeleton_host))
            for kw, bk, is_short in _KW_LIST:
                if is_short:
                    if kw in skel_tokens:
                        best_brand_key = bk
                        break
                else:
                    if kw in skeleton_host:
                        best_brand_key = bk
                        break
        # Fuzzy SLD lookalike on IDN skeleton (e.g., paypa1 / vitocombank encoded in Punycode)
        idn_fuzzy_reg_match = False
        if best_brand_key is None and skeleton_reg:
            skel_sld = skeleton_reg.split(".")[0]
            if len(skel_sld) >= 4:
                best_sim = 0.0
                for kw, bk, is_short in _KW_LIST:
                    if not is_short and len(kw) >= 4:
                        sim = _levenshtein_ratio(skel_sld, kw)
                        if sim >= 0.80 and sim > best_sim:
                            best_sim = sim
                            best_brand_key = bk
                            idn_fuzzy_reg_match = True
        if best_brand_key is None:
            skel_tokens = set(re.split(r"[^a-z0-9]+", skeleton_host))
            for bk, bi in _IDN_EXTRA_BRANDS.items():
                if skeleton_reg in bi["official_apex_domains"] or any(
                    (kw in skel_tokens if len(kw) <= 5 else kw in skeleton_host) for kw in bi["keywords"]
                ):
                    best_brand_key = bk
                    break
        if best_brand_key is None and skeleton_reg:
            skel_sld = skeleton_reg.split(".")[0]
            if len(skel_sld) >= 4:
                best_sim = 0.0
                for bk, bi in _IDN_EXTRA_BRANDS.items():
                    for kw in bi["keywords"]:
                        if len(kw) >= 4:
                            sim = _levenshtein_ratio(skel_sld, kw)
                            if sim >= 0.80 and sim > best_sim:
                                best_sim = sim
                                best_brand_key = bk
                                idn_fuzzy_reg_match = True
    else:
        idn_fuzzy_reg_match = False

    if best_brand_key is None:
        # No brand candidate — both match/mismatch = 0, distances = 0
        return {
            "brand_token_in_hostname":          0,
            "brand_token_in_registered_domain": 0,
            "brand_token_in_subdomain":         0,
            "brand_token_in_path":              0,
            "brand_token_in_query":             0,
            "brand_official_domain_match":      0,
            "brand_official_domain_mismatch":   0,
            "brand_lookalike_distance":         0.0,
            "brand_homoglyph_similarity":       0.0,
            "brand_plus_security_keyword":      0,
            "brand_plus_payment_keyword":       0,
        }

    # Use precomputed lookups for brand info (falling back to _IDN_EXTRA_BRANDS if matched there)
    if best_brand_key in _BRAND_TO_KWS:
        kws = _BRAND_TO_KWS[best_brand_key]
        official_domains = _BRAND_TO_DOMAINS.get(best_brand_key, frozenset())
    else:
        extra_info = _IDN_EXTRA_BRANDS.get(best_brand_key, {})
        kws = extra_info.get("keywords", [])
        official_domains = extra_info.get("official_apex_domains", frozenset())

    # Presence flags (check both raw hostname and IDN skeleton hostname when IDN/Unicode is used)
    brand_in_hostname = int(
        any(kw in hostname for kw in kws)
        or (is_idn_or_unicode and (any(kw in skeleton_host for kw in kws) or idn_fuzzy_reg_match))
    )
    brand_in_reg = int(
        any(kw in reg_domain for kw in kws)
        or (is_idn_or_unicode and (any(kw in skeleton_reg for kw in kws) or idn_fuzzy_reg_match))
    )
    brand_in_sub = int(
        (bool(subdomain_str) and any(kw in subdomain_str for kw in kws))
        or (is_idn_or_unicode and bool(skeleton_sub) and any(kw in skeleton_sub for kw in kws))
    )
    brand_in_path     = int(any(kw in path_lower for kw in kws))
    brand_in_query    = int(any(kw in query_lower for kw in kws))

    # Official domain match / mismatch (raw reg_domain must match official ASCII domain)
    is_official = (reg_domain in official_domains) and (not is_idn_or_unicode)
    brand_official_match    = int(is_official)
    brand_official_mismatch = int(not is_official and brand_in_hostname == 1)

    # Lookalike distance: best Levenshtein similarity of reg_domain (or skeleton_reg) vs any official domain
    if official_domains:
        lookalike_dist = max(
            _levenshtein_ratio(reg_domain, od) for od in official_domains
        )
        if is_idn_or_unicode and skeleton_reg:
            lookalike_dist = max(
                lookalike_dist,
                max(_levenshtein_ratio(skeleton_reg, od) for od in official_domains),
            )
    else:
        lookalike_dist = 0.0

    # Homoglyph similarity: apply homoglyph map to hostname, compare to each keyword
    normalized_host = _apply_homoglyph_map(hostname)
    homoglyph_sim = 0.0
    if kws:
        homoglyph_sim = max(_levenshtein_ratio(normalized_host, kw) for kw in kws)
        if is_idn_or_unicode:
            skel_sld = skeleton_reg.split(".")[0] if skeleton_reg else skeleton_host
            homoglyph_sim = max(
                homoglyph_sim,
                max(_levenshtein_ratio(skeleton_host, kw) for kw in kws),
                max(_levenshtein_ratio(skel_sld, kw) for kw in kws),
            )

    # Co-occurrence with security / payment keywords
    tokens_url = set(re.split(r"[^a-z0-9]+", url_lower))
    if is_idn_or_unicode:
        tokens_url |= set(re.split(r"[^a-z0-9]+", skeleton_host))
    brand_plus_security = int(
        (brand_in_hostname or brand_in_reg or brand_in_path)
        and bool(tokens_url & _SECURITY_KEYWORDS)
    )
    brand_plus_payment = int(
        (brand_in_hostname or brand_in_reg or brand_in_path)
        and bool(tokens_url & _PAYMENT_KEYWORDS)
    )

    return {
        "brand_token_in_hostname":          brand_in_hostname,
        "brand_token_in_registered_domain": brand_in_reg,
        "brand_token_in_subdomain":         brand_in_sub,
        "brand_token_in_path":              brand_in_path,
        "brand_token_in_query":             brand_in_query,
        "brand_official_domain_match":      brand_official_match,
        "brand_official_domain_mismatch":   brand_official_mismatch,
        "brand_lookalike_distance":         lookalike_dist,
        "brand_homoglyph_similarity":       homoglyph_sim,
        "brand_plus_security_keyword":      brand_plus_security,
        "brand_plus_payment_keyword":       brand_plus_payment,
    }


# ---------------------------------------------------------------------------
# F. Phishing & Vietnamese keywords — 8 features
# ---------------------------------------------------------------------------

_PHISHING_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "secure", "verify", "verification", "account",
    "update", "confirm", "credential", "password", "phishing", "fraud",
    "suspended", "unlock", "recover", "restore", "blocked",
})
_CREDENTIAL_KEYWORDS: frozenset[str] = frozenset({
    "username", "password", "passwd", "credential", "credentials",
    "otp", "pin", "passcode", "secret", "token", "auth", "2fa", "mfa",
})
_PAYMENT_KWS: frozenset[str] = frozenset({
    "pay", "payment", "checkout", "billing", "invoice",
    "transfer", "wallet", "deposit", "withdraw", "transaction",
})
_ACCOUNT_SECURITY_KEYWORDS: frozenset[str] = frozenset({
    "account", "profile", "settings", "security", "privacy",
    "manage", "dashboard", "portal", "myaccount",
})
_VIETNAMESE_KEYWORDS: frozenset[str] = frozenset({
    "xacthuc", "xac-thuc", "dangnhap", "dang-nhap", "taikhoan", "tai-khoan",
    "baomat", "bao-mat", "kichhoat", "kich-hoat", "capnhat", "cap-nhat",
    "naptien", "chuyentien", "ruttien", "nhan", "tang", "thuong",
    "khuyen-mai", "khuyenmai",
})
_VN_BANK_KEYWORDS: frozenset[str] = frozenset({
    "vietcombank", "techcombank", "mbbank", "bidv", "agribank",
    "vpbank", "tpbank", "sacombank", "vietinbank", "hdbank",
    "shb", "seabank", "ocb", "vib", "scb", "lpbank", "vcb",
})
_VN_OTP_KEYWORDS: frozenset[str] = frozenset({
    "otp", "xacthuc", "xac-thuc", "ma-otp", "nhap-otp", "ma-xac-nhan",
    "xacnhan", "confirm-otp",
})
_VN_PUBLIC_SERVICE_KEYWORDS: frozenset[str] = frozenset({
    "dichvucong", "dich-vu-cong", "chinhphu", "chinh-phu",
    "thue", "bhxh", "bhyt", "ho-khau", "cmnd", "cccd",
    "dichvu", "gov",
})


def _count_keywords(text: str, keywords: frozenset[str]) -> int:
    """Count how many keywords appear in lowercased text (substring match)."""
    lower = text.lower()
    return sum(1 for kw in keywords if kw in lower)


def _group_f(raw: str, comp: URLComponents) -> dict[str, Any]:
    """F. Phishing & Vietnamese keywords — 8 features."""
    host = comp.hostname
    if ("xn--" in host.lower()) or any(ord(c) > 127 for c in host):
        host_search = f"{host} {_to_idn_ascii_skeleton(host)}"
    else:
        host_search = host
    search_text = f"{host_search} {comp.path} {comp.query} {comp.fragment}".lower()

    return {
        "phishing_keyword_count":              _count_keywords(search_text, _PHISHING_KEYWORDS),
        "credential_keyword_count":            _count_keywords(search_text, _CREDENTIAL_KEYWORDS),
        "payment_keyword_count":               _count_keywords(search_text, _PAYMENT_KWS),
        "account_security_keyword_count":      _count_keywords(search_text, _ACCOUNT_SECURITY_KEYWORDS),
        "vietnamese_keyword_count":            _count_keywords(search_text, _VIETNAMESE_KEYWORDS),
        "vietnamese_bank_keyword_count":       _count_keywords(search_text, _VN_BANK_KEYWORDS),
        "vietnamese_otp_keyword_count":        _count_keywords(search_text, _VN_OTP_KEYWORDS),
        "vietnamese_public_service_keyword_count": _count_keywords(search_text, _VN_PUBLIC_SERVICE_KEYWORDS),
    }


# ---------------------------------------------------------------------------
# G. Unicode & IDN — 7 features
# ---------------------------------------------------------------------------

def _is_punycode_hostname(hostname: str) -> bool:
    return "xn--" in hostname.lower()


def _count_unicode_scripts(hostname: str) -> int:
    """Count distinct Unicode scripts in hostname characters."""
    scripts = set()
    for ch in hostname:
        if ord(ch) > 127:
            try:
                name = unicodedata.name(ch, "")
                # Extract script name from Unicode character name (e.g. "LATIN", "CYRILLIC")
                if name:
                    word = name.split()[0]
                    scripts.add(word)
            except Exception:
                pass
    return len(scripts)


def _is_accented_latin_confusable(ch: str) -> bool:
    """True if ch is a non-ASCII Latin character with combining diacritics (e.g. Vietnamese IDN spoof)."""
    if ord(ch) <= 127:
        return False
    decomp = unicodedata.normalize("NFD", ch)
    return any(unicodedata.category(c) == "Mn" for c in decomp)


def _is_non_latin_script_char(ch: str) -> bool:
    """True if ch is a non-ASCII alphabetic character belonging to a non-Latin Unicode script (Cyrillic, Greek, etc.)."""
    if ord(ch) <= 127 or not ch.isalpha():
        return False
    try:
        name = unicodedata.name(ch, "")
        return bool(name) and name.split()[0] != "LATIN"
    except Exception:
        return False


def _is_mixed_script(hostname: str) -> int:
    """
    1 if hostname exhibits UTS #39 IDN Homograph script mixing or skeleton spoofing:
      (1) Any single domain label mixes characters from >1 Unicode script (e.g., Latin + Cyrillic/Greek),
      (2) A non-Latin label consists entirely of Latin lookalike homoglyphs (whole-script confusable, e.g., аррӏе.com), or
      (3) A decoded IDN/Unicode hostname with confusable/diacritic characters matches a target brand skeleton.
    Legitimate single-script non-brand IDNs (e.g., münchen.de, bücher.de, пример.рф) return 0.
    """
    decoded = _decode_idn_hostname(hostname)
    for lbl in decoded.split("."):
        if not lbl:
            continue
        lbl_scripts = set()
        alpha_chars = []
        for ch in lbl:
            if ord(ch) <= 127:
                if ch.isalpha():
                    lbl_scripts.add("LATIN")
                    alpha_chars.append(ch)
            elif ch.isalpha():
                alpha_chars.append(ch)
                try:
                    name = unicodedata.name(ch, "")
                    if name:
                        lbl_scripts.add(name.split()[0])
                except Exception:
                    pass
        # (1) Within-label cross-script mixing (e.g., Latin + Cyrillic in same label)
        if len(lbl_scripts) > 1:
            return 1
        # (2) Whole-script non-Latin homoglyph label (every alpha char is a non-Latin lookalike in _HOMOGLYPH_MAP)
        if alpha_chars and lbl_scripts and "LATIN" not in lbl_scripts:
            if all((c in _HOMOGLYPH_MAP or c.lower() in _HOMOGLYPH_MAP) for c in alpha_chars):
                return 1
    # (3) Diacritic / homoglyph brand impersonation
    if (
        any(c in _HOMOGLYPH_MAP or c.lower() in _HOMOGLYPH_MAP or _is_accented_latin_confusable(c) for c in decoded)
        and _confusable_brand_match(decoded) == 1
    ):
        return 1
    return 0


def _count_confusable_chars(hostname: str) -> int:
    """
    Count confusable homoglyph characters on decoded IDN hostname according to UTS #39:
      - Non-Latin homoglyphs (Cyrillic/Greek in _HOMOGLYPH_MAP) are counted when the hostname has
        within-label script mixing, whole-script homoglyph spoofing, or brand skeleton match.
      - Accented/stroke Latin characters are counted when the hostname matches a brand skeleton (_confusable_brand_match == 1).
    """
    decoded = _decode_idn_hostname(hostname)
    brand_match = _confusable_brand_match(decoded) == 1
    mixed = _is_mixed_script(decoded) == 1
    if not brand_match and not mixed:
        return 0
    count = 0
    for c in decoded:
        if c in _HOMOGLYPH_MAP or c.lower() in _HOMOGLYPH_MAP:
            if _is_non_latin_script_char(c) or brand_match:
                count += 1
        elif brand_match and _is_accented_latin_confusable(c):
            count += 1
    return count


def _ascii_normalization_changed(hostname: str) -> int:
    """1 if NFKC changes hostname or UTS #39 IDN confusable skeleton normalization applies, else 0."""
    try:
        normalized = unicodedata.normalize("NFKC", hostname)
        if normalized != hostname:
            return 1
        if ("xn--" in hostname.lower()) or any(ord(c) > 127 for c in hostname):
            decoded = _decode_idn_hostname(hostname)
            if _count_confusable_chars(decoded) > 0 or _confusable_brand_match(decoded) == 1:
                return 1
        return 0
    except Exception:
        return 0


def _confusable_brand_match(hostname: str) -> int:
    """
    1 if applying homoglyph/IDN skeleton substitutions on hostname produces a string
    matching any known brand keyword, else 0.
    """
    if not _BRAND_REGISTRY_AVAILABLE or not OFFICIAL_VN_BRANDS:
        return 0
    normalized = _to_idn_ascii_skeleton(hostname)
    norm_tokens = set(re.split(r"[^a-z0-9]+", normalized))
    for kw, _, is_short in _KW_LIST:
        if is_short:
            if kw in norm_tokens:
                return 1
        elif kw in normalized:
            return 1
    if ("xn--" in hostname.lower()) or any(ord(c) > 127 for c in hostname):
        for bi in _IDN_EXTRA_BRANDS.values():
            for kw in bi.get("keywords", []):
                if (kw in norm_tokens) if len(kw) <= 5 else (kw in normalized):
                    return 1
        _, skel_reg = extract_registered_domain(normalized)
        skel_sld = skel_reg.split(".")[0] if skel_reg else ""
        if len(skel_sld) >= 4:
            for kw, _, is_short in _KW_LIST:
                if not is_short and len(kw) >= 4 and _levenshtein_ratio(skel_sld, kw) >= 0.80:
                    return 1
    return 0


def _group_g(raw: str, comp: URLComponents) -> dict[str, Any]:
    """G. Unicode & IDN — 7 features."""
    hostname = comp.hostname

    hostname_has_non_ascii = int(any(ord(c) > 127 for c in hostname))
    hostname_is_punycode   = int(_is_punycode_hostname(hostname))

    # Decode Punycode FIRST so mixed-script, confusable, and script counts work on xn-- domains
    decoded_host = _decode_idn_hostname(hostname) if hostname_is_punycode else hostname

    hostname_mixed_script               = _is_mixed_script(decoded_host)
    hostname_confusable_count           = _count_confusable_chars(decoded_host)
    hostname_confusable_brand_match     = _confusable_brand_match(decoded_host)
    hostname_unicode_script_count       = _count_unicode_scripts(decoded_host)
    hostname_ascii_normalization_changed = _ascii_normalization_changed(hostname)

    return {
        "hostname_has_non_ascii":              hostname_has_non_ascii,
        "hostname_is_punycode":                hostname_is_punycode,
        "hostname_mixed_script":               hostname_mixed_script,
        "hostname_confusable_count":           hostname_confusable_count,
        "hostname_confusable_brand_match":     hostname_confusable_brand_match,
        "hostname_unicode_script_count":       hostname_unicode_script_count,
        "hostname_ascii_normalization_changed": hostname_ascii_normalization_changed,
    }


# ---------------------------------------------------------------------------
# H. Inherited Lexical & Token Statistics (Hannousse & Yahiouche, 2021) — 12 features
# ---------------------------------------------------------------------------

_SHORTENING_RE = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
    r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
    r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
    r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|"
    r"db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|"
    r"q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
    r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|"
    r"link\.zip\.net|s\.net\.vn|by\.com\.vn",
    re.IGNORECASE,
)

_ABNORMAL_SUBDOMAIN_RE = re.compile(r"(http[s]?://(w[w]?|\d))([w]?(\d|-))", re.IGNORECASE)

_HANNOUSSE_HINTS: tuple[str, ...] = (
    "wp", "login", "includes", "admin", "content", "site", "images", "js",
    "alibaba", "css", "myaccount", "dropbox", "themes", "plugins", "signin", "view",
)

_HANNOUSSE_ALLBRANDS: frozenset[str] = frozenset({
    "accenture", "activisionblizzard", "adidas", "adobe", "adultfriendfinder",
    "agriculturalbankofchina", "akamai", "alibaba", "aliexpress", "alipay",
    "alliance", "alliancedata", "allianceone", "allianz", "alphabet", "amazon",
    "americanairlines", "americanexpress", "americantower", "andersons", "apache",
    "apple", "arrow", "ashleymadison", "audi", "autodesk", "avaya", "avisbudget",
    "avon", "axa", "badoo", "baidu", "bankofamerica", "bankofchina",
    "bankofnewyorkmellon", "barclays", "barnes", "bbc", "bbt", "bbva", "bebo",
    "benchmark", "bestbuy", "bim", "bing", "biogen", "blackstone", "blogger",
    "blogspot", "bmw", "bnpparibas", "boeing", "booking", "broadcom", "burberry",
    "caesars", "canon", "cardinalhealth", "carmax", "carters", "caterpillar",
    "cheesecakefactory", "chinaconstructionbank", "cinemark", "cintas", "cisco",
    "citi", "citigroup", "cnet", "coca-cola", "colgate", "colgate-palmolive",
    "columbiasportswear", "commonwealth", "communityhealth", "continental", "dell",
    "deltaairlines", "deutschebank", "disney", "dolby", "dominos", "donaldson",
    "dreamworks", "dropbox", "eastman", "eastmankodak", "ebay", "edison",
    "electronicarts", "equifax", "equinix", "expedia", "express", "facebook",
    "fedex", "flickr", "footlocker", "ford", "fordmotor", "fossil",
    "fosterwheeler", "foxconn", "fujitsu", "gap", "gartner", "genesis", "genuine",
    "genworth", "gigamedia", "gillette", "github", "global", "globalpayments",
    "goodyeartire", "google", "gucci", "harley-davidson", "harris",
    "hewlettpackard", "hilton", "hiltonworldwide", "hmstatil", "honda", "hsbc",
    "huawei", "huntingtonbancshares", "hyundai", "ibm", "ikea", "imdb", "imgur",
    "ingbank", "insight", "instagram", "intel", "jackdaniels", "jnj", "jpmorgan",
    "jpmorganchase", "kelly", "kfc", "kindermorgan", "lbrands", "lego", "lennox",
    "lenovo", "lindsay", "linkedin", "livejasmin", "loreal", "louisvuitton",
    "mastercard", "mcdonalds", "mckesson", "mckinsey", "mercedes-benz",
    "microsoft", "microsoftonline", "mini", "mitsubishi", "morganstanley",
    "motorola", "mrcglobal", "mtv", "myspace", "nescafe", "nestle", "netflix",
    "nike", "nintendo", "nissan", "nissanmotor", "nvidia", "nytimes", "oracle",
    "panasonic", "paypal", "pepsi", "pepsico", "philips", "pinterest", "pocket",
    "pornhub", "porsche", "prada", "rabobank", "reddit", "regal",
    "royalbankofcanada", "samsung", "scotiabank", "shell", "siemens", "skype",
    "snapchat", "sony", "soundcloud", "spiritairlines", "spotify", "sprite",
    "stackexchange", "stackoverflow", "starbucks", "swatch", "swift", "symantec",
    "synaptics", "target", "telegram", "tesla", "teslamotors", "theguardian",
    "homedepot", "piratebay", "tiffany", "tinder", "tmall", "toyota",
    "tripadvisor", "tumblr", "twitch", "twitter", "underarmour", "unilever",
    "universal", "ups", "verizon", "viber", "visa", "volkswagen", "volvocars",
    "walmart", "wechat", "weibo", "whatsapp", "wikipedia", "wordpress", "yahoo",
    "yamaha", "yandex", "youtube", "zara", "zebra", "iphone", "icloud", "itunes",
    "sinara", "normshield", "bga", "sinaralabs", "roksit", "cybrml", "turkcell",
    "n11", "hepsiburada", "migros",
})


def _char_repeat_count(words_raw: list[str]) -> int:
    """Count consecutive identical character runs of lengths 2..5 across URL word tokens."""
    total = 0
    for word in words_raw:
        wlen = len(word)
        for run_len in (2, 3, 4, 5):
            if wlen >= run_len:
                for i in range(wlen - run_len + 1):
                    sub = word[i:i + run_len]
                    if sub.count(sub[0]) == run_len:
                        total += 1
    return total


def _group_h(raw: str, comp: URLComponents) -> dict[str, Any]:
    """H. Inherited Lexical & Token Statistics (Hannousse & Yahiouche, 2021) — 12 features."""
    hostname = comp.hostname or ""
    path = comp.path or ""

    if _BRAND_REGISTRY_AVAILABLE:
        subdomain_str, reg_domain = extract_registered_domain(hostname)
    else:
        parts = [p for p in hostname.split(".") if p]
        reg_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        subdomain_str = ".".join(parts[:-2]) if len(parts) > 2 else ""

    if reg_domain and "." in reg_domain:
        tld = reg_domain.split(".", 1)[1].lower()
    else:
        parts = [p for p in hostname.rstrip(".").split(".") if p]
        tld = parts[-1].lower() if parts else ""

    raw_words = [w for w in re.split(r"\W+", raw.lower()) if w]
    host_words = [w for w in re.split(r"\W+", hostname.lower()) if w]
    path_words = [w for w in re.split(r"\W+", path.lower()) if w]

    tld_in_path_val = int(bool(tld and path.lower().count(tld) > 0))
    tld_in_sub_val = int(bool(tld and subdomain_str and subdomain_str.lower().count(tld) > 0))
    abnormal_sub_val = int(bool(_ABNORMAL_SUBDOMAIN_RE.search(raw)))
    shortener_val = int(bool(_SHORTENING_RE.search(raw)))

    nb_www_val = sum(1 for w in raw_words if "www" in w)
    nb_com_val = sum(1 for w in raw_words if "com" in w)

    dslash_positions = [m.start(0) for m in re.finditer(r"//", raw)]
    nb_dslash_val = int(bool(dslash_positions and dslash_positions[-1] > 6))

    char_repeat_val = _char_repeat_count(raw_words)
    shortest_word_host_val = min((len(w) for w in host_words), default=0)
    avg_word_host_val = (sum(len(w) for w in host_words) / len(host_words)) if host_words else 0.0
    longest_word_path_val = max((len(w) for w in path_words), default=0)
    avg_word_path_val = (sum(len(w) for w in path_words) / len(path_words)) if path_words else 0.0

    return {
        "tld_in_path":        tld_in_path_val,
        "tld_in_subdomain":   tld_in_sub_val,
        "abnormal_subdomain": abnormal_sub_val,
        "shortening_service": shortener_val,
        "nb_www":             nb_www_val,
        "nb_com":             nb_com_val,
        "nb_dslash":          nb_dslash_val,
        "char_repeat":        char_repeat_val,
        "shortest_word_host": shortest_word_host_val,
        "avg_word_host":      avg_word_host_val,
        "longest_word_path":  longest_word_path_val,
        "avg_word_path":      avg_word_path_val,
    }


# ---------------------------------------------------------------------------
# Feature contract validation
# ---------------------------------------------------------------------------

# Ordered list of all 81 feature names — DO NOT reorder after model is trained.
FEATURE_NAMES: list[str] = [
    # A. URL structure (11)
    "url_len", "hostname_len", "path_len", "query_len", "fragment_len",
    "ratio_digits_url", "ratio_letters_url", "ratio_special_url",
    "n_subdomains", "path_depth", "port_val",
    # B. Character & entropy (15)
    "n_dots_url", "n_hyphens_url", "n_underscores_url", "n_slashes_url",
    "n_question_url", "n_equal_url", "n_at_url", "n_ampersand_url",
    "n_percent_url", "n_dots_host", "n_hyphens_host", "n_digits_host",
    "entropy_url", "entropy_host", "entropy_path",
    # C. Domain, scheme, encoding (10)
    "has_ip_host", "tld_len", "is_suspicious_tld", "has_userinfo",
    "scheme_is_https", "scheme_is_http", "scheme_is_other", "scheme_missing",
    "n_pct_encoded", "decode_depth",
    # D. Evasion & execution (7)
    "has_escape_seq", "has_html_entities", "has_data_uri",
    "has_javascript_pseudo", "has_executable_extension",
    "has_archive_extension", "has_redirect_parameter",
    # E. Brand & impersonation (11)
    "brand_token_in_hostname", "brand_token_in_registered_domain",
    "brand_token_in_subdomain", "brand_token_in_path", "brand_token_in_query",
    "brand_official_domain_match", "brand_official_domain_mismatch",
    "brand_lookalike_distance", "brand_homoglyph_similarity",
    "brand_plus_security_keyword", "brand_plus_payment_keyword",
    # F. Phishing & VN keywords (8)
    "phishing_keyword_count", "credential_keyword_count",
    "payment_keyword_count", "account_security_keyword_count",
    "vietnamese_keyword_count", "vietnamese_bank_keyword_count",
    "vietnamese_otp_keyword_count", "vietnamese_public_service_keyword_count",
    # G. Unicode & IDN (7)
    "hostname_has_non_ascii", "hostname_is_punycode", "hostname_mixed_script",
    "hostname_confusable_count", "hostname_confusable_brand_match",
    "hostname_unicode_script_count", "hostname_ascii_normalization_changed",
    # H. Inherited Lexical & Token Statistics (12)
    "tld_in_path", "tld_in_subdomain", "abnormal_subdomain",
    "shortening_service", "nb_www", "nb_com", "nb_dslash",
    "char_repeat", "shortest_word_host", "avg_word_host",
    "longest_word_path", "avg_word_path",
]

# Validate schema at import time
assert len(FEATURE_NAMES) == FEATURE_COUNT, (
    f"Schema error: expected {FEATURE_COUNT}, got {len(FEATURE_NAMES)}"
)
assert len(set(FEATURE_NAMES)) == FEATURE_COUNT, (
    "Schema error: duplicate feature names detected"
)


def _zero_features() -> dict[str, Any]:
    """Return zero-vector dict (used on extraction error)."""
    return {k: 0 for k in FEATURE_NAMES}


# ---------------------------------------------------------------------------
# Main extraction functions
# ---------------------------------------------------------------------------

def extract_features(url: str) -> dict[str, Any]:
    """
    Extract exactly 81 features from a single URL.

    Returns:
        Ordered dict with feature_name -> value.
        On error: all values = 0.
    """
    try:
        return extract_features_strict(url)
    except Exception as e:
        logger.warning("Feature extraction failed for %r: %s", str(url)[:80], e)
        return _zero_features()


def extract_features_strict(url: str) -> dict[str, Any]:
    """Inner extraction — may raise; wrapped by extract_features."""
    comp = normalize_url(url)
    raw = comp.raw

    feats: dict[str, Any] = {}
    feats.update(_group_a(raw, comp))
    feats.update(_group_b(raw, comp))
    feats.update(_group_c(raw, comp))
    feats.update(_group_d(raw, comp))
    feats.update(_group_e(raw, comp))
    feats.update(_group_f(raw, comp))
    feats.update(_group_g(raw, comp))
    feats.update(_group_h(raw, comp))

    # Semantic lexicon fusion from Hannousse & Yahiouche (2021)
    if _BRAND_REGISTRY_AVAILABLE and comp.hostname:
        _, reg_dom = extract_registered_domain(comp.hostname)
        sld = reg_dom.split(".", 1)[0].lower() if reg_dom else ""
        if sld in _HANNOUSSE_ALLBRANDS:
            feats["brand_token_in_registered_domain"] = max(int(feats["brand_token_in_registered_domain"]), 1)
    if comp.path:
        p_low = comp.path.lower()
        feats["phishing_keyword_count"] = int(feats["phishing_keyword_count"]) + sum(p_low.count(h) for h in _HANNOUSSE_HINTS)

    # Return in canonical order
    return {k: feats[k] for k in FEATURE_NAMES}


def extract_features_batch(
    urls: list[str],
    show_progress: bool = False,
) -> "pd.DataFrame":
    """
    Extract features for a list of URLs.

    Returns:
        pd.DataFrame with shape (len(urls), 81), columns = FEATURE_NAMES.
        All values are float32.
    """
    import numpy as np
    import pandas as pd

    if show_progress:
        try:
            from tqdm import tqdm
            iterator = tqdm(urls, desc="Extracting features", unit="url")
        except ImportError:
            iterator = urls
    else:
        iterator = urls

    records = [extract_features(u) for u in iterator]
    df = pd.DataFrame(records, columns=FEATURE_NAMES)
    return df.astype(np.float32)


def get_feature_names() -> list[str]:
    """Return the canonical ordered list of 81 feature names."""
    return list(FEATURE_NAMES)


def validate_feature_dict(feats: dict[str, Any]) -> list[str]:
    """
    Validate a feature dict against the schema.

    Returns:
        List of validation error messages (empty if valid).
    """
    import math
    errors = []

    if set(feats.keys()) != set(FEATURE_NAMES):
        missing = set(FEATURE_NAMES) - set(feats.keys())
        extra   = set(feats.keys()) - set(FEATURE_NAMES)
        if missing:
            errors.append(f"Missing features: {sorted(missing)}")
        if extra:
            errors.append(f"Extra features: {sorted(extra)}")

    for name in FEATURE_NAMES:
        if name not in feats:
            continue
        v = feats[name]
        if not isinstance(v, (int, float)):
            errors.append(f"Feature '{name}': expected numeric, got {type(v).__name__}")
        elif math.isnan(v) or math.isinf(v):
            errors.append(f"Feature '{name}': NaN or Inf value")

    return errors




# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.WARNING)

    print(f"Number of features: {len(FEATURE_NAMES)}")
    assert len(FEATURE_NAMES) == 81, f"FAIL: got {len(FEATURE_NAMES)}"
    print("Feature count: PASS")

    test_cases = [
        ("https://google.com", "benign HTTPS"),
        ("http://192.168.1.1/admin", "IP host"),
        ("javascript:eval(atob('evil'))", "javascript pseudo"),
        ("http://momo.vn.attacker-login.tk/xacthuc?otp=123", "VN brand spoof"),
        ("https://vietcombank.com.vn/ibanking/login", "official VN bank"),
        ("http://pа%уpаl.com/secure-login", "typosquat with %"),  # Cyrillic
        ("data:text/html,<script>evil()</script>", "data URI"),
        ("example.com/page", "missing scheme"),
        ("", "empty URL"),
    ]

    for url, desc in test_cases:
        feats = extract_features(url)
        errors = validate_feature_dict(feats)
        status = "PASS" if not errors else f"FAIL: {errors}"
        non_zero = {k: v for k, v in feats.items() if v not in (0, 0.0)}
        print(f"\n[{status}] {desc}")
        print(f"  URL: {url[:70].encode('ascii', errors='replace').decode('ascii')}")
        print(f"  Non-zero features ({len(non_zero)}): {list(non_zero.keys())[:8]}")
