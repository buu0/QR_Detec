"""
Unit tests for deterministic URL normalizer and parser
"""
import pytest
from app.services.url_security.normalizer import URLNormalizer


@pytest.fixture
def normalizer():
    return URLNormalizer(length_limit=4096)


def test_normal_url(normalizer):
    norm = normalizer.normalize("https://example.com/path?arg=1#frag")
    assert norm.is_valid
    assert norm.scheme == "https"
    assert norm.hostname == "example.com"
    assert norm.path == "/path"
    assert norm.query == "arg=1"
    assert not norm.has_userinfo
    assert not norm.is_ip_literal
    assert not norm.is_private_or_local


def test_userinfo_confusion_tactic(normalizer):
    """
    Critical security test:
    https://google.com@evil.example/login
    Hostname MUST be evil.example and has_userinfo MUST be True with userinfo='google.com'
    """
    norm = normalizer.normalize("https://google.com@evil.example/login")
    assert norm.is_valid
    assert norm.hostname == "evil.example"
    assert norm.has_userinfo
    assert norm.userinfo == "google.com"
    assert "evil.example" in norm.normalized_url


def test_punycode_and_idna(normalizer):
    # ASCII punycode format
    norm = normalizer.normalize("https://xn--vi-hia.vn/tintuc")
    assert norm.is_valid
    assert norm.is_punycode
    assert norm.hostname == "xn--vi-hia.vn"

    # Internationalized Vietnamese domain
    norm_idna = normalizer.normalize("https://bảo-hiểm.vn/gioithieu")
    assert norm_idna.is_valid
    assert norm_idna.is_punycode
    assert "xn--" in norm_idna.hostname


def test_ip_literal_host(normalizer):
    # Public IPv4
    norm = normalizer.normalize("http://8.8.8.8/test")
    assert norm.is_valid
    assert norm.is_ip_literal
    assert not norm.is_private_or_local
    assert norm.hostname == "8.8.8.8"

    # Private RFC1918 IPv4
    norm_priv = normalizer.normalize("http://192.168.1.10/admin")
    assert norm_priv.is_valid
    assert norm_priv.is_ip_literal
    assert norm_priv.is_private_or_local

    # Loopback IPv4
    norm_loop = normalizer.normalize("http://127.0.0.1:8000/api")
    assert norm_loop.is_valid
    assert norm_loop.is_ip_literal
    assert norm_loop.is_private_or_local

    # Localhost string
    norm_local = normalizer.normalize("http://localhost/setup")
    assert norm_local.is_valid
    assert norm_local.is_private_or_local


def test_default_ports_stripped(normalizer):
    norm_http = normalizer.normalize("http://example.com:80/home")
    assert norm_http.port is None
    assert norm_http.normalized_url == "http://example.com/home"

    norm_https = normalizer.normalize("https://example.com:443/home")
    assert norm_https.port is None
    assert norm_https.normalized_url == "https://example.com/home"

    norm_custom = normalizer.normalize("https://example.com:8443/home")
    assert norm_custom.port == 8443
    assert ":8443" in norm_custom.normalized_url


def test_path_slashes_are_preserved(normalizer):
    """BEFORE: '///a//b/c' was collapsed to '/a/b/c' (changes meaning for redirect endpoints).
    AFTER: the path is preserved exactly as a browser would send it."""
    norm = normalizer.normalize("https://example.com///a//b/c")
    assert norm.hostname == "example.com"
    assert norm.path == "///a//b/c"


# ─────────────────────── WHATWG parity: host confusion bypasses ───────────────────────

@pytest.mark.parametrize("raw,host", [
    ("https://evil.com\\.vietcombank.com.vn/login", "evil.com"),     # backslash = '/'
    ("https:\\\\evil.com/x", "evil.com"),
    ("https:////evil.com/x", "evil.com"),                             # extra slashes ignored
    ("http:evil.com/x", "evil.com"),                                  # scheme without //
    ("https://%65vil.com/", "evil.com"),                              # percent-encoded host
    ("https://evil.com./", "evil.com"),                               # trailing dot
    ("HTTPS://EVIL.COM/A", "evil.com"),
    ("https://vietcombank.com.vn@evil.com/", "evil.com"),             # userinfo
    ("https://a@b@evil.com/", "evil.com"),
    ("example.com:8080/login", "example.com"),                        # host:port without scheme
])
def test_host_matches_browser(normalizer, raw, host):
    norm = normalizer.normalize(raw)
    assert norm.is_valid, raw
    assert norm.hostname == host, raw


@pytest.mark.parametrize("raw,ip,private", [
    ("http://3232235777/", "192.168.1.1", True),      # decimal
    ("http://0x7f.1/", "127.0.0.1", True),            # hex + short form
    ("http://0177.0.0.1/", "127.0.0.1", True),        # octal
    ("http://134744072/", "8.8.8.8", False),
])
def test_numeric_ipv4_forms_are_detected(normalizer, raw, ip, private):
    norm = normalizer.normalize(raw)
    assert norm.is_ip_literal and norm.hostname == ip
    assert norm.is_private_or_local is private
    assert norm.host_obfuscated


def test_ipv4_mapped_ipv6_loopback_is_private(normalizer):
    norm = normalizer.normalize("http://[::ffff:127.0.0.1]/")
    assert norm.is_ip_literal and norm.is_private_or_local


def test_invalid_port_is_invalid_not_crash(normalizer):
    norm = normalizer.normalize("https://example.com:99999/")
    assert not norm.is_valid and norm.error == "INVALID_PORT"


def test_dotless_host_is_internal(normalizer):
    assert normalizer.normalize("http://intranet/login").is_private_or_local


def test_embedded_urls_extracted_without_fetching(normalizer):
    norm = normalizer.normalize("https://www.google.com/url?q=https%3A%2F%2Fevil.example%2Fpay&sa=D")
    assert norm.hostname == "www.google.com"
    assert any("evil.example" in u for u in norm.embedded_urls)


def test_double_encoded_keyword_visible_for_rules(normalizer):
    norm = normalizer.normalize("https://x.example/%256Cogin")
    assert "login" in norm.decoded_path_query
    # the raw path itself is untouched
    assert norm.path == "/%256Cogin"


def test_non_http_uri_schemes(normalizer):
    norm_js = normalizer.normalize("javascript:alert(1)")
    assert norm_js.is_valid
    assert norm_js.scheme == "javascript"

    norm_data = normalizer.normalize("data:text/html;base64,PHNjcmlwdD4=")
    assert norm_data.is_valid
    assert norm_data.scheme == "data"

    norm_mail = normalizer.normalize("mailto:support@bank.example")
    assert norm_mail.is_valid
    assert norm_mail.scheme == "mailto"

    norm_tel = normalizer.normalize("tel:+84901234567")
    assert norm_tel.is_valid
    assert norm_tel.scheme == "tel"


def test_excessive_url_length(normalizer):
    short_normalizer = URLNormalizer(length_limit=100)
    huge_url = "https://example.com/" + "a" * 150
    norm = short_normalizer.normalize(huge_url)
    assert not norm.is_valid
    assert norm.error == "EXCESSIVE_URL_LENGTH_REJECTED"


def test_empty_and_control_chars(normalizer):
    norm_empty = normalizer.normalize("   ")
    assert not norm_empty.is_valid

    norm_ctrl = normalizer.normalize("https://example.com/test\x00\x08")
    assert norm_ctrl.is_valid
    assert "\x00" not in norm_ctrl.normalized_url
    assert "\x08" not in norm_ctrl.normalized_url
