"""
URL Normalizer
==============
Mục đích: Chuẩn hóa URL an toàn, bảo toàn URL gốc, tạo các góc nhìn giải mã
có giới hạn phục vụ feature extraction.

Nguyên tắc thiết kế:
- URL gốc KHÔNG BAO GIỜ bị thay thế, chỉ được tạo thêm "view" mới.
- Không tùy tiện lowercase toàn bộ URL (hostname thì có thể, path thì không).
- Giới hạn độ sâu giải mã percent-encoding để tránh vòng lặp vô hạn.
- Không thực thi bất kỳ JavaScript hay HTTP request.
- Custom scheme được xử lý có chủ đích, không bị loại bỏ.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, unquote, urlunparse

logger = logging.getLogger(__name__)

# Giới hạn độ sâu giải mã để tránh multi-stage encoding vô hạn
MAX_DECODE_DEPTH = 5

# Các scheme hợp lệ phổ biến
KNOWN_SAFE_SCHEMES = {"http", "https", "ftp", "ftps", "tftp"}

# Scheme đáng ngờ (không filter bỏ, chỉ đánh dấu)
SUSPICIOUS_SCHEMES = {
    "javascript", "data", "vbscript", "file", "blob",
    "intent", "market", "whatsapp", "tel", "sms",
}

# Regex kiểm tra IP address trong hostname
_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

# Regex phát hiện percent encoding
_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")

# Regex phát hiện nested encoding (dấu hiệu %25xx)
_NESTED_PCT_RE = re.compile(r"%25[0-9A-Fa-f]{2}", re.IGNORECASE)


@dataclass
class URLComponents:
    """Kết quả phân tích URL. Bảo toàn URL gốc trong `raw`."""

    raw: str                        # URL gốc, không bao giờ thay đổi
    scheme: str = ""                # scheme đã lowercase
    netloc: str = ""                # netloc gốc
    hostname: str = ""              # hostname đã lowercase
    port: Optional[int] = None      # port số
    path: str = ""                  # path gốc
    query: str = ""                 # query gốc
    fragment: str = ""              # fragment gốc
    userinfo: str = ""              # user:password nếu có
    is_ip_host: bool = False        # hostname dạng IP?
    scheme_is_suspicious: bool = False  # scheme đáng ngờ?
    had_missing_scheme: bool = False    # ban đầu không có scheme?
    decode_views: list = field(default_factory=list)  # URL sau giải mã từng lớp
    decode_depth_reached: int = 0   # số lớp giải mã thực sự tìm thấy
    parse_error: str = ""           # lý do lỗi nếu có


def _add_scheme_if_missing(url: str) -> tuple[str, bool]:
    """
    Thêm scheme nếu thiếu để urlparse có thể hoạt động.
    Trả về (url_có_scheme, had_missing_scheme).
    """
    stripped = url.strip()
    if not stripped:
        return stripped, False

    # Kiểm tra có dấu hiệu scheme không
    if "://" in stripped[:30]:
        return stripped, False
    if stripped.startswith("//"):
        # Protocol-relative URL
        return "http:" + stripped, True

    # Một số URL bị obfuscated scheme
    lower = stripped.lower()
    for scheme in ("http", "https", "ftp", "javascript", "data", "file", "intent"):
        if lower.startswith(scheme):
            return stripped, False

    # Không tìm thấy scheme
    return "http://" + stripped, True


def _decode_one_layer(url: str) -> str:
    """Giải mã một lớp percent-encoding. Trả về URL sau giải mã."""
    try:
        return unquote(url, errors="replace")
    except Exception:
        return url


def _build_decode_views(url: str, max_depth: int = MAX_DECODE_DEPTH) -> tuple[list, int]:
    """
    Tạo danh sách URL sau từng lớp giải mã.
    Dừng khi không còn thay đổi hoặc đạt max_depth.
    
    Returns:
        (views, depth_reached)
        views: list các URL đã giải mã, không bao gồm URL gốc.
    """
    views = []
    current = url
    for depth in range(1, max_depth + 1):
        decoded = _decode_one_layer(current)
        if decoded == current:
            return views, depth - 1
        views.append(decoded)
        current = decoded
    return views, max_depth


def normalize_url(url: str) -> URLComponents:
    """
    Phân tích và chuẩn hóa một URL.
    
    URL gốc được lưu trong `result.raw` và không bao giờ bị thay đổi.
    
    Args:
        url: URL cần phân tích (bất kỳ dạng nào).
        
    Returns:
        URLComponents với đầy đủ thông tin phân tích.
    """
    raw = url  # Bảo toàn URL gốc

    if not isinstance(url, str) or not url.strip():
        return URLComponents(raw=raw, parse_error="empty_or_non_string")

    url = url.strip()

    # Bước 1: Thêm scheme nếu thiếu (chỉ để parse, không phải URL gốc)
    url_for_parse, had_missing_scheme = _add_scheme_if_missing(url)

    # Bước 2: Parse URL
    try:
        parsed = urlparse(url_for_parse)
    except Exception as e:
        return URLComponents(raw=raw, parse_error=f"urlparse_error:{e}")

    scheme = parsed.scheme.lower() if parsed.scheme else ""

    # Bước 3: Tách userinfo
    netloc = parsed.netloc or ""
    userinfo = ""
    hostname_part = netloc
    if "@" in netloc:
        userinfo, _, hostname_part = netloc.rpartition("@")

    # Bước 4: Tách port
    port = None
    hostname = hostname_part
    if hostname_part and hostname_part.count(":") == 1 and not hostname_part.startswith("["):
        h, _, p_str = hostname_part.rpartition(":")
        try:
            port = int(p_str)
            hostname = h
        except ValueError:
            pass  # Giữ nguyên nếu không parse được port

    # Hostname lowercase (hostname là case-insensitive theo RFC)
    hostname = hostname.lower()

    # Bước 5: Kiểm tra IP
    is_ip = bool(_IP_RE.match(hostname)) if hostname else False

    # Bước 6: Scheme đáng ngờ
    scheme_suspicious = scheme in SUSPICIOUS_SCHEMES

    # Bước 7: Tạo decode views (từ URL gốc, không phải URL đã thêm scheme)
    decode_views, depth_reached = _build_decode_views(url)

    # Nếu hostname chứa Punycode (xn--), giải mã và thêm vào decode_views
    if "xn--" in hostname:
        try:
            import idna
            decoded_host = idna.decode(hostname)
            if decoded_host != hostname:
                idn_url = url.replace(hostname, decoded_host)
                if idn_url not in decode_views:
                    decode_views.append(idn_url)
        except Exception:
            pass

    return URLComponents(
        raw=raw,
        scheme=scheme,
        netloc=netloc,
        hostname=hostname,
        port=port,
        path=parsed.path or "",
        query=parsed.query or "",
        fragment=parsed.fragment or "",
        userinfo=userinfo,
        is_ip_host=is_ip,
        scheme_is_suspicious=scheme_suspicious,
        had_missing_scheme=had_missing_scheme,
        decode_views=decode_views,
        decode_depth_reached=depth_reached,
        parse_error="",
    )


def get_all_views(components: URLComponents) -> list[str]:
    """
    Trả về danh sách tất cả các dạng URL để phân tích feature.
    Luôn đặt URL gốc đầu tiên.
    """
    views = [components.raw]
    for v in components.decode_views:
        if v not in views:
            views.append(v)
    return views


def count_percent_encoding(url: str) -> int:
    """Đếm số lượng percent-encoded sequences trong URL."""
    return len(_PCT_RE.findall(url))


def has_nested_encoding(url: str) -> bool:
    """Kiểm tra xem URL có chứa nested percent-encoding (%25xx) không."""
    return bool(_NESTED_PCT_RE.search(url))


# ---------------------------------------------------------------------------
# Batch processing
# ---------------------------------------------------------------------------

def normalize_batch(urls: list[str]) -> list[URLComponents]:
    """
    Chuẩn hóa một danh sách URL.
    Lỗi của từng URL được ghi nhận trong trường `parse_error`, không làm hỏng
    toàn bộ batch.
    """
    results = []
    for url in urls:
        try:
            comp = normalize_url(url)
        except Exception as e:
            logger.warning("Unexpected error normalizing URL %r: %s", url[:80], e)
            comp = URLComponents(raw=url, parse_error=f"unexpected:{e}")
        results.append(comp)
    return results


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    test_cases = [
        "https://example.com/path?q=1#frag",
        "http://user:pass@192.168.1.1:8080/admin",
        "javascript:eval(atob('YWxlcnQoMSk='))",
        "example.com/page",                          # missing scheme
        "hxxp://malware.example/payload",
        "http://evil.com/%6a%61%76%61%73%63%72%69%70%74%3aevil()",  # encoded js:
        "https://phish.example/%252F%252Fpaypal.com",  # nested encoding
        "data:text/html,<script>evil()</script>",
        "",
        "intent://evil.app#Intent;action=VIEW;end",
    ]
    for tc in test_cases:
        c = normalize_url(tc)
        print(f"\nRAW: {tc[:80]}")
        print(f"  scheme={c.scheme!r}  hostname={c.hostname!r}  port={c.port}")
        print(f"  is_ip={c.is_ip_host}  suspicious_scheme={c.scheme_is_suspicious}")
        print(f"  decode_depth={c.decode_depth_reached}  views={c.decode_views[:1]}")
        if c.parse_error:
            print(f"  PARSE_ERROR: {c.parse_error}")
