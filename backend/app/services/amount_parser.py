"""
Amount Parser — chuẩn hoá cách viết số tiền tiếng Việt về số nguyên VND.

Hỗ trợ:
    500k, 500K, 500 nghìn, 500 ngàn          → 500.000
    5tr, 5 triệu, 5 củ, 1tr5, 1.5tr, 1,5tr  → 5.000.000 / 1.500.000
    2 tỷ, 1ty2                               → 2.000.000.000 / 1.200.000.000
    50000vnd, 50.000đ, 50,000 VND, VND 50000 → 50.000
    500.000 (nhóm hàng nghìn, không đơn vị)  → 500.000

KHÔNG coi là số tiền: số trần không đơn vị, không nhóm nghìn (mã đơn, STK, SĐT...).

Hàm chạy trên chuỗi đã "gập dấu" GIỮ NGUYÊN ĐỘ DÀI, nên vị trí (span) trả về
trùng với chuỗi gốc — context_extractor dùng span để không nhặt nhầm số tiền
thành số tài khoản.
"""
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from unidecode import unidecode

MAX_VND = 10 ** 13

# Đơn vị nhân
_MULTIPLIERS = {
    "k": 1_000, "nghin": 1_000, "ngan": 1_000,
    "tr": 1_000_000, "trieu": 1_000_000, "cu": 1_000_000,
    "ty": 1_000_000_000, "ti": 1_000_000_000,
}
# Đơn vị tiền tệ (không nhân)
_CURRENCY = {"d", "vnd", "dong"}

_NUM = r"\d+(?:[.,]\d+)*"
_UNIT = r"trieu|nghin|ngan|dong|vnd|tr|ty|ti|cu|k|d"

# <số> <đơn vị> [phần lẻ sau đơn vị nhân: 1tr5, 2k5]
_AFTER = re.compile(
    rf"(?<![\d.,])(?P<num>{_NUM})\s*(?P<unit>{_UNIT})(?P<tail>\d{{1,3}})?(?![a-z0-9])"
)
# VND <số>
_BEFORE = re.compile(rf"(?<![a-z])vnd\s*[:=]?\s*(?P<num>{_NUM})(?![\d])")
# 500.000 / 1,250,000 — nhóm hàng nghìn, không cần đơn vị
_GROUPED = re.compile(r"(?<![\d.,])(?P<num>\d{1,3}(?:([.,])\d{3})(?:\2\d{3})*)(?![\w]|[.,]\d)")


@dataclass
class AmountMention:
    raw: str        # đoạn văn bản gốc, vd "500k"
    value: int      # VND
    start: int
    end: int


def fold(text: str) -> str:
    """Bỏ dấu + chữ thường, GIỮ NGUYÊN độ dài chuỗi (1 ký tự → 1 ký tự)."""
    out = []
    for ch in text:
        if ch == "₫":
            out.append("d")
        elif ord(ch) < 128:
            out.append(ch)
        else:
            u = unidecode(ch)
            out.append(u[0] if u and u[0].isalnum() else " ")
    return "".join(out).lower()


def _to_number(num: str, multiplier: int) -> Optional[float]:
    """
    Đọc phần số, phân biệt dấu nhóm nghìn và dấu thập phân:
      - 500.000 / 1,250,000   → nhóm nghìn
      - 1.5 / 1,5 (có đơn vị nhân) → thập phân
      - 500000.00 (tiền tệ)   → bỏ phần lẻ
    """
    if re.fullmatch(r"\d{1,3}(?:([.,])\d{3})(?:\1\d{3})*", num):
        return float(re.sub(r"[.,]", "", num))
    m = re.fullmatch(r"(\d+)(?:[.,](\d{1,2}))?", num)
    if not m:
        return None
    whole, frac = m.group(1), m.group(2)
    if frac and multiplier > 1:
        return float(f"{whole}.{frac}")
    return float(whole)


def _value(num: str, unit: str, tail: Optional[str]) -> Optional[int]:
    mult = _MULTIPLIERS.get(unit, 1)
    base = _to_number(num, mult)
    if base is None:
        return None
    if tail:
        if mult == 1 or "." in num or "," in num:
            return None                  # "50.000d5" — không phải cách viết tiền
        base += int(tail) / (10 ** len(tail))
    val = int(round(base * mult))
    return val if 0 < val < MAX_VND else None


def find_amounts(text: Optional[str]) -> List[AmountMention]:
    """Tìm mọi số tiền trong chuỗi (theo thứ tự xuất hiện, không chồng lấn)."""
    if not text:
        return []
    s = fold(text)
    found: List[AmountMention] = []
    taken: List[Tuple[int, int]] = []

    def free(a: int, b: int) -> bool:
        return all(b <= x or a >= y for x, y in taken)

    def add(a: int, b: int, val: Optional[int]):
        if val and free(a, b):
            taken.append((a, b))
            found.append(AmountMention(raw=text[a:b].strip(), value=val, start=a, end=b))

    for m in _AFTER.finditer(s):
        unit = m.group("unit")
        if unit not in _MULTIPLIERS and unit not in _CURRENCY:
            continue
        add(m.start(), m.end(), _value(m.group("num"), unit, m.group("tail")))

    for m in _BEFORE.finditer(s):
        add(m.start(), m.end(), _value(m.group("num"), "vnd", None))

    for m in _GROUPED.finditer(s):
        add(m.start("num"), m.end("num"), _value(m.group("num"), "", None))

    found.sort(key=lambda a: a.start)
    return found


def parse_vnd(text: Optional[str]) -> Optional[int]:
    """Đọc 1 số tiền (lấy mention đầu tiên). Vd parse_vnd('5tr') == 5_000_000."""
    found = find_amounts(text)
    return found[0].value if found else None


def format_vnd(value) -> Optional[str]:
    try:
        return f"{int(float(value)):,}".replace(",", ".") + " đ"
    except (TypeError, ValueError):
        return None
