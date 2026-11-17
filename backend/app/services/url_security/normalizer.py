"""
Deterministic URL Normalizer & Parser
Parses and normalizes URLs strictly using standard libraries without external requests,
DNS lookups, or network calls.

Security goal: the hostname produced here must be the host a real browser would contact
(WHATWG URL parsing for "special" schemes). Any divergence lets an attacker show one host to
the heuristics / IOC lookup and send the victim to another (e.g. `https://evil.com\\.bank.vn`).
"""
import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import unquote, urlsplit, urlunsplit

from app.core.config import settings

# Characters to strip/sanitize
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "ws": 80,
    "wss": 443,
}
# WHATWG "special" schemes: backslash is a path separator and extra slashes are ignored.
_SPECIAL_SCHEMES = ("http", "https", "ws", "wss", "ftp")
_SPECIAL_PREFIX_RE = re.compile(r"^(https?|wss?|ftp):[/\\]*", re.IGNORECASE)
_HOST_PORT_RE = re.compile(r"^\d{1,5}(?:[/?#]|$)")
# Characters that can never appear in a valid host after percent-decoding.
_FORBIDDEN_HOST_CHARS = set(" \t<>\"'`/\\@#?%^|{}[]")
_EMBEDDED_URL_RE = re.compile(r"(?:https?://|www\.)[^\s&#\"'<>|]+", re.IGNORECASE)
_MAX_EMBEDDED_URLS = 5
NON_HOST_SCHEMES = {
    "data", "javascript", "vbscript", "file", "intent", "blob",
    "mailto", "tel", "sms",
}


@dataclass
class NormalizedURL:
    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    port: Optional[int]
    userinfo: Optional[str]
    path: str
    query: str
    fragment: str
    has_userinfo: bool
    is_ip_literal: bool
    is_private_or_local: bool
    is_punycode: bool
    is_valid: bool
    error: Optional[str] = None
    # Host was written in an obfuscated numeric form (decimal/hex/octal IPv4) or percent-encoded.
    host_obfuscated: bool = False
    # Path+query percent-decoded (max twice) — used for keyword matching only, never for lookups.
    decoded_path_query: str = ""
    # Absolute URLs embedded in path/query (open-redirect / wrapper links). Not fetched.
    embedded_urls: List[str] = field(default_factory=list)


def _invalid(orig: str, error: str, scheme: str = "") -> NormalizedURL:
    return NormalizedURL(
        original_url=orig,
        normalized_url="",
        scheme=scheme,
        hostname="",
        port=None,
        userinfo=None,
        path="",
        query="",
        fragment="",
        has_userinfo=False,
        is_ip_literal=False,
        is_private_or_local=False,
        is_punycode=False,
        is_valid=False,
        error=error,
    )


def _fix_special_prefix(url: str) -> str:
    """`https:\\\\evil.com`, `https:////evil.com`, `http:evil.com` -> `scheme://evil.com`,
    and backslashes before the query become '/' (WHATWG behaviour for special schemes)."""
    m = _SPECIAL_PREFIX_RE.match(url)
    if not m:
        return url
    rest = url[m.end():]
    cut = min([i for i in (rest.find("?"), rest.find("#")) if i >= 0] or [len(rest)])
    rest = rest[:cut].replace("\\", "/") + rest[cut:]
    return f"{m.group(1).lower()}://{rest}"


def _parse_ipv4_number(part: str) -> Optional[int]:
    if part == "":
        return None
    try:
        if part[:2].lower() == "0x":
            return int(part[2:] or "0", 16)
        if len(part) > 1 and part.startswith("0"):
            return int(part[1:], 8)
        if part.isdigit():
            return int(part, 10)
    except ValueError:
        return None
    return None


def _whatwg_ipv4(host: str) -> Optional[str]:
    """Browser IPv4 parsing: `3232235777`, `0x7f.1`, `0177.0.0.1`, `127.1` are all IPs."""
    parts = host.split(".")
    if parts and parts[-1] == "":
        parts = parts[:-1]
    if not parts or len(parts) > 4:
        return None
    nums = [_parse_ipv4_number(p) for p in parts]
    if any(n is None for n in nums):
        return None
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = nums[-1]
    for i, n in enumerate(nums[:-1]):
        value += n * 256 ** (3 - i)
    return str(ipaddress.IPv4Address(value))


def _is_private_ip(ip_obj) -> bool:
    if getattr(ip_obj, "ipv4_mapped", None) is not None:
        ip_obj = ip_obj.ipv4_mapped
    return bool(
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    )


def _decode_twice(text: str) -> str:
    once = unquote(text)
    return unquote(once) if "%" in once else once


def _embedded_urls(decoded: str) -> List[str]:
    found: List[str] = []
    for m in _EMBEDDED_URL_RE.finditer(decoded):
        candidate = m.group(0)[:512]
        if candidate not in found:
            found.append(candidate)
        if len(found) >= _MAX_EMBEDDED_URLS:
            break
    return found


def _normalize_idn_to_ascii(hostname: str) -> str:
    """Convert Unicode U-labels to ASCII Punycode A-labels (RFC 3492) with label-by-label fallback."""
    if not hostname or hostname.isascii():
        return hostname
    try:
        return hostname.encode("idna").decode("ascii").lower()
    except Exception:
        out_labels: List[str] = []
        for lbl in hostname.split("."):
            if not lbl or lbl.isascii():
                out_labels.append(lbl.lower())
            else:
                try:
                    out_labels.append(lbl.encode("idna").decode("ascii").lower())
                except Exception:
                    try:
                        out_labels.append("xn--" + lbl.lower().encode("punycode").decode("ascii"))
                    except Exception:
                        out_labels.append(lbl.lower())
        return ".".join(out_labels)


class URLNormalizer:
    """
    Deterministic normalizer for URLs/URIs:
    - Unicode normalization (NFKC)
    - Control characters stripping
    - Lowercase scheme and hostname
    - Userinfo extraction (e.g. https://google.com@evil.example/login -> host: evil.example, userinfo: google.com)
    - Default port stripping (80 for http, 443 for https)
    - IDNA/Punycode handling
    - IPv4/IPv6 literal normalization and private/local range detection
    - Deterministic path and query formatting
    - Strict length limit enforcement
    """

    def __init__(self, length_limit: int = settings.URL_LENGTH_LIMIT):
        self.length_limit = length_limit

    def normalize(self, raw_url: str) -> NormalizedURL:
        orig = raw_url.strip() if raw_url else ""

        if not orig:
            return _invalid(orig, "EMPTY_URL")

        if len(orig) > self.length_limit:
            return _invalid(orig[:256] + "...", "EXCESSIVE_URL_LENGTH_REJECTED")

        # 1. Unicode normalization & control character strip
        cleaned = unicodedata.normalize("NFKC", orig)
        cleaned = _CONTROL_CHARS_RE.sub("", cleaned)

        # 2. Scheme handling
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
            m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$", cleaned, re.DOTALL)
            if m:
                scheme_candidate, rest = m.group(1).lower(), m.group(2)
                if scheme_candidate in _SPECIAL_SCHEMES:
                    pass  # `https:/evil.com`, `http:evil.com`, `https:\\evil.com` — fixed below
                elif "." in scheme_candidate or _HOST_PORT_RE.match(rest):
                    # `example.com:8080/x` or `localhost:3000` is host:port, not a URI scheme
                    cleaned = "http://" + cleaned
                else:
                    # e.g. javascript:alert(1), mailto:test@example.com
                    return self._parse_non_hierarchical_uri(orig, cleaned, scheme_candidate)
            else:
                # Otherwise default to http://
                cleaned = "http://" + cleaned
        cleaned = _fix_special_prefix(cleaned)

        # 3. Parse with urlsplit
        try:
            parsed = urlsplit(cleaned)
        except Exception:
            return _invalid(orig, "PARSE_ERROR")

        scheme = (parsed.scheme or "").lower()
        raw_netloc = parsed.netloc

        # Userinfo (credential confusion: https://bank.vn@evil.com -> host evil.com)
        has_userinfo = "@" in raw_netloc
        userinfo: Optional[str] = raw_netloc.rsplit("@", 1)[0] if has_userinfo else None

        try:
            port = parsed.port
        except ValueError:
            return _invalid(orig, "INVALID_PORT", scheme)

        hostname = parsed.hostname or ""
        host_obfuscated = False

        # Browsers percent-decode the host: `%65vil.com` is `evil.com`.
        if "%" in hostname:
            decoded_host = unquote(hostname)
            if decoded_host != hostname:
                host_obfuscated = True
            hostname = unicodedata.normalize("NFKC", decoded_host)
        hostname = hostname.lower().rstrip(".")
        if any(c in _FORBIDDEN_HOST_CHARS for c in hostname):
            return _invalid(orig, "INVALID_HOST", scheme)

        # 4. Check IP literal and private ranges
        is_ip_literal = False
        is_private_or_local = False
        ip_obj = None
        try:
            ip_obj = ipaddress.ip_address(hostname)
        except ValueError:
            if scheme in _SPECIAL_SCHEMES and hostname:
                dotted = _whatwg_ipv4(hostname)
                if dotted is not None:
                    if dotted != hostname:
                        host_obfuscated = True
                    hostname = dotted
                    ip_obj = ipaddress.ip_address(dotted)
        if ip_obj is not None:
            is_ip_literal = True
            is_private_or_local = _is_private_ip(ip_obj)
        elif hostname in ("localhost", "local", "broadcasthost") or hostname.endswith(".local") \
                or hostname.endswith(".localhost") or hostname.endswith(".internal") \
                or (hostname and "." not in hostname and scheme in _SPECIAL_SCHEMES):
            # Check local/internal names (a dotless name only resolves inside a private network)
            is_private_or_local = True

        # 5. IDNA / Punycode handling
        is_punycode = False
        if not is_ip_literal:
            if "xn--" in hostname or not hostname.isascii():
                is_punycode = True
                if not hostname.isascii():
                    hostname = _normalize_idn_to_ascii(hostname)

        # 6. Normalize port
        if port and scheme in _DEFAULT_PORTS and port == _DEFAULT_PORTS[scheme]:
            port = None

        # Build netloc
        normalized_netloc = hostname
        if is_ip_literal and ":" in hostname:  # IPv6
            normalized_netloc = f"[{hostname}]"
        if port:
            normalized_netloc = f"{normalized_netloc}:{port}"

        # 7. Path: slashes are NOT collapsed — `//evil.com` inside a path can change meaning
        #    for redirect endpoints, so the original structure is preserved.
        norm_path = parsed.path or "/"
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path

        # 8. Reconstruct normalized URL
        normalized_url = urlunsplit((
            scheme,
            normalized_netloc,
            norm_path,
            parsed.query,
            parsed.fragment,
        ))

        is_valid = bool(scheme and (hostname or scheme in NON_HOST_SCHEMES))

        decoded_pq = ""
        embedded: List[str] = []
        if scheme in ("http", "https"):
            decoded_pq = _decode_twice(norm_path + ("?" + parsed.query if parsed.query else ""))
            embedded = _embedded_urls(decoded_pq)

        return NormalizedURL(
            original_url=orig,
            normalized_url=normalized_url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            userinfo=userinfo,
            path=norm_path,
            query=parsed.query,
            fragment=parsed.fragment,
            has_userinfo=has_userinfo,
            is_ip_literal=is_ip_literal,
            is_private_or_local=is_private_or_local,
            is_punycode=is_punycode,
            is_valid=is_valid,
            error=None if is_valid else "INVALID_STRUCTURE",
            host_obfuscated=host_obfuscated,
            decoded_path_query=decoded_pq,
            embedded_urls=embedded,
        )

    def _parse_non_hierarchical_uri(self, orig: str, cleaned: str, scheme: str) -> NormalizedURL:
        """Handles schemes like javascript:, data:, mailto:, tel:, file:, intent:, blob:"""
        return NormalizedURL(
            original_url=orig,
            normalized_url=cleaned,
            scheme=scheme,
            hostname="",
            port=None,
            userinfo=None,
            path=cleaned[len(scheme) + 1:],
            query="",
            fragment="",
            has_userinfo=False,
            is_ip_literal=False,
            is_private_or_local=False,
            is_punycode=False,
            is_valid=True,
            error=None,
        )

