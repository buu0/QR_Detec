"""
Bank Registry — nguồn dữ liệu DUY NHẤT về ngân hàng cho cả 2 phía:
  - Phía QR:      BIN (tag 38.01.00)      → bank_id
  - Phía ngữ cảnh: từ khoá trong văn bản  → bank_id

So khớp ngân hàng bằng bank_id (==) thay vì fuzzy tên hiển thị,
tránh lệch kiểu "Lienviet PostBank (LPB)" vs "LPBank".

Từ khoá được viết ở dạng ĐÃ CHUẨN HOÁ (không dấu, chữ thường, chỉ a-z0-9 và
khoảng trắng) và được so khớp có ranh giới từ, nên "mb" KHÔNG còn khớp
nhầm vào "techcombank" / "sacombank" / "number".
"""
import re
from functools import lru_cache
from typing import Dict, List, Optional, Tuple

from unidecode import unidecode

# (bank_id, tên hiển thị, [BIN], [từ khoá đã chuẩn hoá])
# LƯU Ý: bảng BIN giữ nguyên từ phiên bản trước — nên đối chiếu lại với
# danh sách NAPAS/VietQR chính thức khi có thời gian.
_BANKS: List[Tuple[str, str, List[str], List[str]]] = [
    # ── Ngân hàng thương mại nhà nước ─────────────────────────────
    ("VCB", "Vietcombank (VCB)", ["970436"], ["vietcombank", "vcb", "ngoai thuong"]),
    ("BIDV", "BIDV", ["970418", "970489"], ["bidv", "dau tu va phat trien"]),
    ("VTB", "Vietinbank", ["970415", "970467"], ["vietinbank", "viettinbank", "cong thuong"]),
    ("AGRIBANK", "Agribank", ["970405"], ["agribank", "nong nghiep va phat trien nong thon"]),

    # ── Ngân hàng thương mại cổ phần ──────────────────────────────
    ("MB", "Militarybank (MB)", ["970422", "970492"],
     ["mb", "mbbank", "mb bank", "military bank", "quan doi"]),
    ("TCB", "Techcombank (TCB)", ["970407"], ["techcombank", "tcb", "ky thuong"]),
    ("VPB", "VPBank", ["970432"], ["vpbank", "vp bank", "viet nam thinh vuong"]),
    ("VIB", "VIB", ["970427"], ["vib"]),
    ("ACB", "ACB", ["970416"], ["acb", "a chau"]),
    ("TPB", "TPBank", ["970423", "970472"], ["tpbank", "tp bank", "tien phong"]),
    ("HDB", "HDBank", ["970437"], ["hdbank", "hd bank"]),
    ("SHB", "SHB", ["970443"], ["shb", "sai gon ha noi"]),
    ("STB", "Sacombank", ["970403"], ["sacombank", "sai gon thuong tin"]),
    ("MSB", "MSB", ["970426", "970486"], ["msb", "maritime", "hang hai"]),
    ("OCB", "OCB", ["970429"], ["ocb", "phuong dong"]),
    ("EIB", "Eximbank", ["970431"], ["eximbank", "xuat nhap khau"]),
    ("SEAB", "Seabank", ["970440"], ["seabank", "dong nam a"]),
    ("ABB", "ABBank", ["970428"], ["abbank", "an binh"]),
    ("LPB", "LPBank (Lienviet PostBank)", ["970462", "970496"],
     ["lpbank", "lp bank", "lienviet", "lienvietpostbank", "lien viet", "buu dien lien viet", "loc phat"]),
    ("BAB", "Bắc Á Bank", ["970449", "970409"], ["bac a bank", "bacabank", "ngan hang bac a"]),
    ("DAB", "DongA Bank", ["970473", "970406"], ["dongabank", "donga bank", "dong a bank", "ngan hang dong a"]),
    ("SCB", "SCB", ["970474"], ["scb"]),
    ("VIETBANK", "VietBank", ["970476", "970411"], ["vietbank", "viet nam thuong tin"]),
    ("BVB", "BVBank", ["970454"], ["bvbank", "bv bank", "ban viet"]),
    ("BAOVIET", "BaoViet Bank", ["970438"], ["baoviet bank", "baovietbank", "bao viet bank"]),
    ("PVCB", "PVcomBank", ["970439", "970412"], ["pvcombank", "pvcom bank", "pvcom"]),
    ("KLB", "KienLong Bank", ["970448", "970452", "970420"], ["kienlongbank", "kienlong", "kien long"]),
    ("GPB", "GPBank", ["970456", "970408"], ["gpbank", "gp bank", "dau khi toan cau"]),
    ("VAB", "VietABank", ["970441", "970430"], ["vietabank", "viet a bank"]),
    ("VCCB", "VietCapitalBank", ["970425", "970417"], ["vietcapitalbank", "viet capital"]),
    ("SHEB", "Shebbank", ["970488"], ["shebbank"]),

    # ── Ngân hàng quy mô nhỏ & đặc thù ───────────────────────────
    ("NCB", "NCB (Ngân hàng Quốc Dân)", ["970419"], ["ncb", "quoc dan"]),
    ("VRB", "Việt Nga Bank (VRB)", ["970421"], ["vrb", "viet nga"]),
    ("DAIABANK", "DaiABank", ["970413"], ["daiabank"]),
    ("OCEANBANK", "Oceanbank", ["970414"], ["oceanbank", "ocean bank"]),
    ("NAB", "NamA Bank", ["970459"], ["namabank", "nam a bank"]),
    ("BIDC", "BIDC", ["970494"], ["bidc"]),

    # ── Ngân hàng nước ngoài tại VN ───────────────────────────────
    ("SHINHAN", "Shinhan Bank Vietnam", ["970424"], ["shinhan"]),
    ("HANA", "KEB Hana Bank Vietnam", ["970433"], ["keb hana", "hana bank"]),
    ("IVB", "Indovina Bank", ["970434"], ["indovina"]),
    ("HLB", "Hong Leong Bank Vietnam", ["970442"], ["hong leong", "hongleong"]),
    ("WOORI", "Woori Bank Vietnam", ["970457"], ["woori"]),

    # ── Ví điện tử & Ngân hàng số ─────────────────────────────────
    ("CAKE", "CAKE by VPBank", ["970458"], ["cake by vpbank", "ngan hang so cake"]),
    ("VTMONEY", "ViettelMoney", ["970483"], ["viettelmoney", "viettel money"]),
    ("TIMO", "Timo by BVBank", ["546034"], ["timo"]),
    ("MOMO", "MoMo", ["963388"], ["momo", "vi momo"]),
    ("ZALOPAY", "ZaloPay", ["963322"], ["zalopay", "zalo pay"]),
    ("SHOPEEPAY", "ShopeePay", ["963414"], ["shopeepay", "shopee pay"]),
]

BANK_NAMES: Dict[str, str] = {bid: name for bid, name, _, _ in _BANKS}
BIN_TO_BANK_ID: Dict[str, str] = {b: bid for bid, _, bins, _ in _BANKS for b in bins}
KNOWN_BINS = frozenset(BIN_TO_BANK_ID)

# Giữ tương thích ngược: BIN → tên hiển thị
BANK_BIN_MAP: Dict[str, str] = {b: BANK_NAMES[bid] for b, bid in BIN_TO_BANK_ID.items()}

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def normalize(text: Optional[str]) -> str:
    """Bỏ dấu, chữ thường, thay ký tự đặc biệt bằng khoảng trắng."""
    if not text:
        return ""
    return _NON_ALNUM.sub(" ", unidecode(text).lower()).strip()


@lru_cache(maxsize=1)
def _keyword_patterns() -> List[Tuple[re.Pattern, str]]:
    pats = []
    for bid, _, _, kws in _BANKS:
        for kw in kws:
            pats.append((re.compile(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z0-9])"), bid))
    # Từ khoá dài trước để ưu tiên cụm cụ thể
    pats.sort(key=lambda p: -len(p[0].pattern))
    return pats


def bank_id_from_bin(bin_code: Optional[str]) -> Optional[str]:
    return BIN_TO_BANK_ID.get((bin_code or "").strip())


def bank_display_name(bank_id: Optional[str]) -> Optional[str]:
    return BANK_NAMES.get(bank_id) if bank_id else None


def find_bank_ids(normalized_text: str) -> List[str]:
    """Tìm mọi ngân hàng xuất hiện trong văn bản ĐÃ chuẩn hoá (giữ thứ tự xuất hiện)."""
    if not normalized_text:
        return []
    hits: List[Tuple[int, str]] = []
    for pat, bid in _keyword_patterns():
        m = pat.search(normalized_text)
        if m:
            hits.append((m.start(), bid))
    seen, out = set(), []
    for _, bid in sorted(hits):
        if bid not in seen:
            seen.add(bid)
            out.append(bid)
    return out
