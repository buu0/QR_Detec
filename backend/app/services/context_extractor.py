"""
Context Extractor — bóc tách thông tin thanh toán từ VĂN BẢN NGỮ CẢNH quanh mã QR.

Ngữ cảnh có thể là: hoá đơn, standee/bảng QR tại quầy, poster quyên góp,
ảnh chụp màn hình app/tin nhắn, menu, bao bì... — KHÔNG chỉ là hoá đơn.

Module thuần Python (không phụ thuộc PaddleOCR/OpenCV) để dễ unit test.
Đầu vào là danh sách dòng văn bản (từ OCR hoặc từ text layer của PDF),
mỗi dòng có thể kèm toạ độ tâm để tính khoảng cách tới mã QR.
"""
import math
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

from unidecode import unidecode

from app.models.schemas import AccountCandidate, NameCandidate, OCRData
from app.services.amount_parser import find_amounts
from app.services.bank_registry import KNOWN_BINS, bank_display_name, find_bank_ids, normalize


@dataclass
class TextLine:
    text: str
    conf: float = 1.0
    cx: Optional[float] = None     # toạ độ tâm (pixel, cùng hệ toạ độ với bbox QR)
    cy: Optional[float] = None
    w: Optional[float] = None      # chiều rộng hộp chữ
    h: Optional[float] = None      # chiều cao hộp chữ
    relative_pos: Optional[str] = None  # above, below, left, right, inside


# ─── Sửa nhầm lẫn ký tự OCR tiếng Việt & số ────────────────────────────────
_OCR_CHAR_TO_DIGIT = {
    "O": "0", "o": "0", "D": "0", "Q": "0",
    "I": "1", "l": "1", "|": "1", "!": "1",
    "Z": "2", "z": "2",
    "S": "5", "s": "5",
    "B": "8",
    "g": "9", "q": "9",
}


def clean_ocr_digits(raw: str) -> str:
    """Chuyển các ký tự OCR dễ nhầm thành chữ số trong bối cảnh chuỗi số"""
    res = []
    for ch in raw:
        if ch.isdigit():
            res.append(ch)
        elif ch in _OCR_CHAR_TO_DIGIT:
            res.append(_OCR_CHAR_TO_DIGIT[ch])
    return "".join(res)


# Token có thể là số tài khoản bị OCR đọc nhầm: chỉ gồm chữ số + ký tự dễ nhầm, cho phép
# 1 dấu cách / chấm / gạch giữa các nhóm. Sửa lỗi OCR ở mức TOKEN (không phải cả dòng) để
# chữ trong nhãn ("STK" -> "5..") không bị ghép vào số và ký tự nhầm ở đầu ("O123...") được giữ.
_OCR_NUMERIC_TOKEN = re.compile(
    r"[0-9" + re.escape("".join(_OCR_CHAR_TO_DIGIT)) + r"]+"
    r"(?:[ .\-][0-9" + re.escape("".join(_OCR_CHAR_TO_DIGIT)) + r"]+)*"
)
_OCR_MIN_DIGIT_RATIO = 0.60


def ocr_numeric_tokens(text: str) -> List[str]:
    """Các chuỗi số đã sửa lỗi OCR (6–19 ký tự) từ những token có tỉ lệ chữ số >= 0.60."""
    out: List[str] = []
    for m in _OCR_NUMERIC_TOKEN.finditer(text or ""):
        compact = re.sub(r"[ .\-]", "", m.group(0))
        if not compact:
            continue
        digit_ratio = sum(c.isdigit() for c in compact) / len(compact)
        if digit_ratio < _OCR_MIN_DIGIT_RATIO:
            continue
        cleaned = clean_ocr_digits(compact)
        if 6 <= len(cleaned) <= 19:
            out.append(cleaned)
    return out


# ─── Từ khoá (đã chuẩn hoá: không dấu, chữ thường) ─────────────────────────
_ACCOUNT_KW = re.compile(
    r"\b(stk|so tk|so tai khoan|tai khoan|tk|account|acc|a c|acct|so the|card no|account no)(?=\b|\d)"
)
_PHONE_KW = re.compile(r"\b(hotline|tel|dien thoai|sdt|dt|zalo|lien he|phone|mobile|fax)\b")
_ID_KW = re.compile(
    r"\b(mst|ma so thue|tax|so hd|hoa don so|ma hd|invoice|ma don|order|ma gd|ma giao dich|"
    r"cccd|cmnd|ma kh|ma khach hang|so seri|serial|ky hieu|mau so)\b"
)
_NAME_KW = re.compile(
    r"\b(chu tk|chu tai khoan|ten tk|ten tai khoan|ten chu tk|ten nguoi nhan|nguoi nhan|"
    r"nguoi thu huong|don vi thu huong|thu huong|beneficiary|account name|acc name|ctk)\b"
)
_INVOICE_KW = re.compile(
    r"\b(tong tien|tong cong|thanh tien|tam tinh|hoa don|vat|don gia|so luong|bill|receipt|"
    r"total|subtotal|phai tra|can thanh toan|tien hang|phieu thanh toan)(?=\b|\d)"
)
_TOTAL_AMOUNT_KW = re.compile(
    r"\b(tong tien|tong cong|thanh tien|tong thanh toan|can thanh toan|phai tra|so tien|so tien thanh toan|thanh toan|payable|amount|total|grand total)(?=\b|\d)"
)
_LINE_ITEM_KW = re.compile(
    r"\b(don gia|so luong|tam tinh|tien hang|gia|price|item|sl)(?=\b|\d)"
)
_DONATION_KW = re.compile(r"\b(ung ho|quyen gop|tu thien|donate|cuu tro|gay quy|chung tay|mat tran to quoc)\b")
_PAYMENT_ANCHOR_KW = re.compile(
    r"\b(thanh toan|chuyen khoan|thong tin thanh toan|thong tin chuyen khoan|payment|transfer|qr payment|pay to|quy khach chuyen khoan)\b"
)


# Nhãn tên đứng ĐẦU dòng, chịu được lỗi OCR dính chữ / mất khoảng trắng / mất dấu hai chấm
# (vd "CHU TKTRUNG TAM ANH NGU", "Chủ TK NGUYEN VAN A", "Tên tài khoản: ...").
_NAME_LABEL_PREFIX = re.compile(
    r"^\s*(ten ?chu ?tk|chu ?tai ?khoan|chu ?tk|ten ?tai ?khoan|ten ?tk|ten ?nguoi ?nhan|nguoi ?nhan|"
    r"nguoi ?thu ?huong|don ?vi ?thu ?huong|thu ?huong|beneficiary|account ?name|acc ?name|ctk)\s*[:\-.]?\s*"
)

# Cụm từ cho thấy một dòng IN HOA là tiêu đề / khẩu hiệu / nhãn chứ không phải tên chủ tài khoản.
# Chỉ áp dụng cho ứng viên KHÔNG có nhãn tên (dòng có nhãn "Chủ TK:" luôn được tin).
_NON_NAME_PHRASE = re.compile(
    r"\b(hoa don|thanh toan|chuyen khoan|quet ma|ma qr|vietqr|napas|tong tien|tong cong|so tien|"
    r"ung ho|quyen gop|tu thien|chung tay|cuu tro|dong bao|lu lut|mien trung|cam on|xin cam on|"
    r"thong bao|thong tin|huong dan|dich vu|phieu thu|phieu chi|bien lai|hoc phi|khoa hoc|"
    r"ve thang|phi gui|bai giu xe|giu xe|menu|thuc don|khuyen mai|giam gia|uu dai|mien phi|"
    r"ngan hang|so tai khoan|chu tai khoan|dia chi|hotline|lien he|website|scan|thank you)\b"
)

# Dòng chữ IN HOA hoặc từ khoá thường gặp trên standee/hoá đơn nhưng KHÔNG phải tên người
_UPPER_STOPWORDS = {
    "HOA DON", "TONG TIEN", "TONG CONG", "THANH TOAN", "CHUYEN KHOAN", "QUET MA", "QUET MA QR",
    "VIETQR", "NAPAS", "NAPAS 247", "SCAN", "SCAN ME", "QR CODE", "MA QR", "XIN CAM ON",
    "CAM ON QUY KHACH", "THANK YOU", "NGAN HANG", "SO TAI KHOAN", "CHU TAI KHOAN", "MENU",
    "TONG", "TIEN MAT", "DIA CHI", "HOTLINE", "VND", "VNPAY", "VNPAY QR", "SHOPEEPAY",
    "QUET MA THANH TOAN", "CHUYEN KHOAN NHANH", "MIEN PHI", "QUAY THU NGAN", "THANH TOAN QR",
    "TRA TIEN", "NHAN TIEN", "MOI QUET MA", "STK", "SO TK",
}

# Chuỗi số có thể ngăn cách bằng 1 dấu cách / chấm / gạch / phẩy giữa các nhóm
_NUM_SEQ = re.compile(r"\d(?:\d|[ .,\-](?=\d))*")
_DATE = re.compile(r"\b\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4}\b")
_TIME = re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b")
_CURRENCY_BEFORE = re.compile(r"(vnd|vnđ|₫|tong|total|gia|price)\s*[:=]?\s*$", re.IGNORECASE)
_PHONE = re.compile(r"^(0|84)(3|5|7|8|9)\d{8}$")

_SOURCE_RANK = {
    "keyword": 0,
    "standee_matched": 0,
    "standee_adjacent": 1,
    "standee_near": 1,
    "phone": 2,
    "bare": 3,
    "other": 4,
}


# ─── Tiện ích ─────────────────────────────────────────────────────────────
def _distance(line: TextLine, qr_bbox: Optional[Sequence[float]]) -> Optional[float]:
    """Khoảng cách từ tâm dòng chữ tới tâm QR, chia cho kích thước QR."""
    if qr_bbox is None or line.cx is None or line.cy is None:
        return None
    x, y, w, h = qr_bbox
    size = max(w, h, 1)
    return round(math.hypot(line.cx - (x + w / 2), line.cy - (y + h / 2)) / size, 2)


def _parse_amount(raw: str) -> Optional[int]:
    digits = re.sub(r"\D", "", raw)
    return int(digits) if digits and len(digits) <= 13 else None


# ─── Số tài khoản & số tiền ───────────────────────────────────────────────
def _extract_numbers(
    line: TextLine,
    prev_norm: str,
    dist: Optional[float],
    target_acc: Optional[str] = None,
) -> Tuple[List[AccountCandidate], List[int]]:
    text = _TIME.sub(" ", _DATE.sub(" ", line.text))
    norm = normalize(line.text)
    letters_in_line = re.sub(r"[^a-z]", "", norm)

    # Nhãn STK ở dòng trước chỉ được "thừa kế" khi dòng đó là nhãn trơn (chưa có số nào đủ dài),
    # vd "Số tài khoản:" → dòng sau là số. Nếu dòng trước đã là "STK: 1903..." thì dòng sau
    # (hotline, mã đơn...) không được coi là STK có nhãn.
    prev_has_number = any(
        len(re.sub(r"\D", "", m.group(0))) >= 6 for m in _NUM_SEQ.finditer(prev_norm)
    )
    has_acc_kw = bool(_ACCOUNT_KW.search(norm)) or (
        bool(_ACCOUNT_KW.search(prev_norm)) and len(letters_in_line) <= 3 and not prev_has_number
    )
    has_phone_kw = bool(_PHONE_KW.search(norm))
    has_id_kw = bool(_ID_KW.search(norm))

    accounts: List[AccountCandidate] = []
    money = find_amounts(text)
    amounts: List[int] = [a.value for a in money]

    # Kiểm tra trực tiếp target_acc từ TLV trên dòng này (kể cả không có nhãn STK)
    matched_on_line = False
    if target_acc:
        line_digits = re.sub(r"\D", "", line.text)
        if target_acc == line_digits or target_acc in ocr_numeric_tokens(line.text):
            matched_on_line = True
            accounts.append(
                AccountCandidate(
                    number=target_acc,
                    source="keyword" if has_acc_kw else "standee_matched",
                    distance=dist,
                )
            )

    for m in _NUM_SEQ.finditer(text):
        if any(m.start() < a.end and m.end() > a.start for a in money):
            continue
        raw = m.group(0).strip(" .,-")
        before = text[:m.start()]

        if _CURRENCY_BEFORE.search(before):
            amt = _parse_amount(raw)
            if amt:
                amounts.append(amt)
            continue

        tokens = [t for t in re.split(r"[ .,\-]", raw) if t]
        joined = "".join(tokens)
        joined_cleaned = clean_ocr_digits(joined)

        options = []
        if 6 <= len(joined) <= 19:
            options.append(joined)
        if joined_cleaned != joined and 6 <= len(joined_cleaned) <= 19:
            options.append(joined_cleaned)
        if len(tokens) > 1:
            for t in tokens:
                if 6 <= len(t) <= 19 and t != joined:
                    options.append(t)
                    t_cleaned = clean_ocr_digits(t)
                    if t_cleaned != t and 6 <= len(t_cleaned) <= 19:
                        options.append(t_cleaned)

        for num in options:
            if len(num) == 6 and num in KNOWN_BINS:
                continue
            # Mảnh số của chính STK đã khớp (sau khi sửa lỗi OCR) trên cùng dòng, ví dụ
            # "O123456789" -> regex số chỉ thấy "123456789": không coi là STK cạnh tranh.
            if matched_on_line and num != target_acc and num in target_acc:
                continue

            # Nếu khớp hoàn toàn số tài khoản từ TLV
            if target_acc and num == target_acc:
                src = "keyword" if has_acc_kw else "standee_matched"
            elif has_acc_kw:
                src = "keyword"
            elif (dist is not None and dist <= 2.0) or getattr(line, "relative_pos", None) in ("above", "below", "left", "right"):
                src = "standee_adjacent"
            elif _PHONE.match(num) or has_phone_kw:
                src = "phone"
            elif has_id_kw:
                src = "other"
            else:
                src = "bare"
            accounts.append(AccountCandidate(number=num, source=src, distance=dist))

    return accounts, amounts


# ─── Tên chủ tài khoản ────────────────────────────────────────────────────
def _fix_upper_vertical_bar_ocr(raw: str) -> str:
    """Trên phông không chân, chữ 'I' hoa và 'l' thường đều là một nét sổ thẳng.
    Khi OCR đọc một từ IN HOA (vd 'THỊ', 'BÌNH', 'MINH') nhưng giải mã 'I' thành 'l' thường
    ('THl', 'BlNH', 'MlNH'), việc gọi .upper() trực tiếp sẽ biến 'l' thành 'L' ('THL').
    Khôi phục 'l'/'|' đứng trong ngữ cảnh từ IN HOA về 'I' trước khi .upper()."""
    s = unidecode(raw or "")
    s = re.sub(r"(?<=[A-Z])[l|](?=[A-Z])", "I", s)
    s = re.sub(r"(?<=[A-Z]{2})[l|]\b", "I", s)
    s = re.sub(r"\b[l|](?=[A-Z]{2})", "I", s)
    return s


def _clean_name(raw: str) -> Optional[str]:
    fixed = _fix_upper_vertical_bar_ocr(raw)
    name = re.sub(r"[^A-Z ]", " ", fixed.upper())
    name = re.sub(r"\s+", " ", name).strip()
    words = name.split()
    if not (1 <= len(words) <= 7) or len(name) < 3:
        return None
    return name


_NAME_SOURCE_RANK = {"keyword": 0, "standee_adjacent": 1, "upper": 2}


def _is_non_name(cleaned: str) -> bool:
    """Tiêu đề / khẩu hiệu / nhãn in hoa (không phải tên chủ tài khoản)."""
    low = cleaned.lower()
    return cleaned in _UPPER_STOPWORDS or bool(_NON_NAME_PHRASE.search(low))


def _extract_names(
    lines: List[TextLine],
    acc_anchor_idx: Optional[int] = None,
    target_name: Optional[str] = None,
) -> List[NameCandidate]:
    out: List[NameCandidate] = []
    seen = set()

    def add(name: Optional[str], src: str):
        if not name or name in seen or name in _UPPER_STOPWORDS:
            return
        if src != "keyword" and _is_non_name(name):
            return
        seen.add(name)
        out.append(NameCandidate(name=name, source=src))

    def next_line_name(i: int) -> Optional[str]:
        # Nhãn và giá trị bị OCR tách thành 2 dòng ("Chủ TK:" / "NGUYEN VAN A")
        if i + 1 < len(lines):
            nxt = lines[i + 1].text
            if not re.search(r"\d{3,}", nxt) and not _NAME_KW.search(normalize(nxt)):
                return _clean_name(nxt)
        return None

    for i, line in enumerate(lines):
        norm = normalize(line.text)
        ascii_line = unidecode(line.text)
        prefix_ascii = re.match(_NAME_LABEL_PREFIX.pattern, ascii_line, flags=re.IGNORECASE)
        prefix = _NAME_LABEL_PREFIX.match(norm)
        m = _NAME_KW.search(norm)
        if prefix_ascii or prefix or m:
            if ":" in line.text and line.text.split(":", 1)[1].strip():
                value = _clean_name(line.text.split(":", 1)[1])
            elif prefix_ascii:
                value = _clean_name(ascii_line[prefix_ascii.end():])
            elif prefix:
                value = _clean_name(norm[prefix.end():])
            else:
                value = _clean_name(norm[m.end():].strip(" :-."))
            add(value or next_line_name(i), "keyword")
            continue

        txt = line.text.strip()
        words = [w for w in re.split(r"[\s,\-\.]+", txt) if w]
        letters_only = re.sub(r"[^A-Za-zÀ-ỹ\s]", "", _fix_upper_vertical_bar_ocr(txt)).strip()
        words_clean = letters_only.split()

        # Nhận diện tên: 2–6 từ, in hoa hoặc Title Case (vd: NGUYEN VAN A hoặc Nguyễn Văn A)
        if 2 <= len(words_clean) <= 6 and 4 <= len(letters_only) <= 50:
            is_upper = letters_only == letters_only.upper()
            is_title = all(w[0].isupper() for w in words_clean if w and w[0].isalpha())

            if (is_upper or is_title) and not re.search(r"\d{3,}", txt):
                cleaned = _clean_name(letters_only)
                if cleaned and not find_bank_ids(normalize(cleaned)) and not _is_non_name(cleaned):
                    is_near_anchor = acc_anchor_idx is not None and abs(i - acc_anchor_idx) <= 2
                    is_near_qr = line.relative_pos in ("below", "above") or (
                        line.cx is not None and getattr(line, "distance", None) is not None and line.distance <= 1.8
                    )
                    src = "standee_adjacent" if (is_near_anchor or is_near_qr) else "upper"
                    add(cleaned, src)

    # Ưu tiên theo độ tin cậy (nhãn tên > cạnh STK/QR > chữ in hoa bất kỳ), giữ thứ tự đọc trong cùng hạng
    return sorted(out, key=lambda n: _NAME_SOURCE_RANK.get(n.source, 3))


# ─── Loại ngữ cảnh ────────────────────────────────────────────────────────
def detect_context_type(
    norm_text: str, accounts: List[AccountCandidate], names: List[NameCandidate], bank_ids: List[str]
) -> str:
    if not norm_text.strip():
        return "empty"
    if _INVOICE_KW.search(norm_text):
        return "invoice"
    if _DONATION_KW.search(norm_text):
        return "donation"
    has_keyword_acc = any(a.source in ("keyword", "standee_matched") for a in accounts)
    has_keyword_name = any(n.source in ("keyword", "standee_adjacent") for n in names)
    if has_keyword_acc or has_keyword_name or (bank_ids and (accounts or names)):
        return "payment_info"
    return "general"


# ─── Phân cụm không gian & bóc tách khối bằng chứng thanh toán ───────────
def _cluster_lines(lines: List[TextLine], qr_bbox: Optional[Sequence[float]] = None) -> List[List[TextLine]]:
    """
    Nhóm các dòng chữ thành các khối không gian (Spatial Payment Blocks / evidence groups)
    dựa trên toạ độ không gian 2D hoặc quan hệ kế cận ngữ nghĩa.
    Đồng thời liên kết các dòng viền kề trực tiếp cùng mã QR (standee header & footer).
    """
    if not lines:
        return []

    has_coords = any(ln.cx is not None and ln.cy is not None for ln in lines)
    if not has_coords:
        blocks: List[List[TextLine]] = []
        cur_block: List[TextLine] = []
        for ln in lines:
            norm = normalize(ln.text)
            if cur_block and _ACCOUNT_KW.search(norm) and any(_ACCOUNT_KW.search(normalize(b.text)) for b in cur_block):
                blocks.append(cur_block)
                cur_block = [ln]
            else:
                cur_block.append(ln)
        if cur_block:
            blocks.append(cur_block)
        return blocks

    qr_cx = None
    qr_w = None
    if qr_bbox is not None and len(qr_bbox) == 4:
        qx, qy, qw, qh = qr_bbox
        qr_cx = qx + qw / 2.0
        qr_w = qw

    n = len(lines)
    adj: List[List[int]] = [[] for _ in range(n)]
    for i in range(n):
        l1 = lines[i]
        c1x = l1.cx if l1.cx is not None else 0.0
        c1y = l1.cy if l1.cy is not None else 0.0
        h1 = l1.h or 30.0
        w1 = l1.w or 150.0
        d1 = getattr(l1, "distance", None)

        for j in range(i + 1, n):
            l2 = lines[j]
            c2x = l2.cx if l2.cx is not None else 0.0
            c2y = l2.cy if l2.cy is not None else 0.0
            h2 = l2.h or 30.0
            w2 = l2.w or 150.0
            d2 = getattr(l2, "distance", None)

            dy = abs(c1y - c2y)
            dx = abs(c1x - c2x)
            max_dy = max(100.0, 2.5 * max(h1, h2))
            max_dx = max(350.0, 1.8 * max(w1, w2))

            # 1. Kế cận không gian trực tiếp
            is_adjacent = dy <= max_dy and dx <= max_dx

            # 2. Thành phần viền kề trực tiếp cùng mã QR trên standee (header & footer)
            is_qr_flanker = False
            if qr_cx is not None and qr_w is not None and d1 is not None and d2 is not None:
                if d1 <= 1.2 and d2 <= 1.2:
                    h_span = max(qr_w * 1.3, 250.0)
                    if abs(c1x - qr_cx) <= h_span and abs(c2x - qr_cx) <= h_span:
                        is_qr_flanker = True

            if is_adjacent or is_qr_flanker:
                adj[i].append(j)
                adj[j].append(i)

    visited = [False] * n
    blocks: List[List[TextLine]] = []
    for i in range(n):
        if not visited[i]:
            comp: List[TextLine] = []
            queue = [i]
            visited[i] = True
            while queue:
                curr = queue.pop(0)
                comp.append(lines[curr])
                for neighbor in adj[curr]:
                    if not visited[neighbor]:
                        visited[neighbor] = True
                        queue.append(neighbor)
            comp.sort(key=lambda ln: (ln.cy if ln.cy is not None else 0.0, ln.cx if ln.cx is not None else 0.0))
            blocks.append(comp)

    return blocks



def _extract_block_evidence(
    block_lines: List[TextLine],
    qr_bbox: Optional[Sequence[float]] = None,
    target_acc: Optional[str] = None,
    target_name: Optional[str] = None,
) -> dict:
    """
    Trích xuất bằng chứng thanh toán cho một khối không gian (Spatial Payment Block):
    - Nhận diện neo thanh toán: Số tài khoản (cùng dòng hoặc dòng kế cận theo phương dọc),
      Tên người nhận (nhãn hoặc in hoa), Ngân hàng, Số tiền (tổng tiền vs đơn giá).
    - Tính khoảng cách tới mã QR.
    """
    block_accounts: List[AccountCandidate] = []
    block_amounts: List[int] = []
    total_amount: Optional[int] = None
    line_item_amounts: List[int] = []
    prev_norm = ""
    acc_anchor_idx = None

    # Khoảng cách tối thiểu của khối tới mã QR
    min_dist = None
    for ln in block_lines:
        d = getattr(ln, "distance", None)
        if d is not None:
            if min_dist is None or d < min_dist:
                min_dist = d

    for idx, line in enumerate(block_lines):
        norm = normalize(line.text)
        dist = getattr(line, "distance", None)

        accs, amts = _extract_numbers(line, prev_norm, dist, target_acc=target_acc)
        if any(a.source in ("standee_matched", "keyword") for a in accs):
            acc_anchor_idx = idx
        block_accounts.extend(accs)
        block_amounts.extend(amts)

        line_has_total = bool(_TOTAL_AMOUNT_KW.search(norm)) or bool(
            prev_norm and _TOTAL_AMOUNT_KW.search(prev_norm) and not any(ch.isdigit() for ch in prev_norm)
        )
        line_has_item = bool(_LINE_ITEM_KW.search(norm))
        if amts:
            if line_has_total:
                total_amount = max(amts)
            elif line_has_item:
                line_item_amounts.extend(amts)

        prev_norm = norm

    block_text = " ".join(ln.text for ln in block_lines)
    norm_block_text = normalize(block_text)
    bank_ids = find_bank_ids(norm_block_text)
    bank_names = [bank_display_name(b) for b in bank_ids]

    name_cands = _extract_names(block_lines, acc_anchor_idx=acc_anchor_idx, target_name=target_name)
    chosen_name = None
    for pref_src in ("keyword", "standee_adjacent", "upper"):
        c = next((n.name for n in name_cands if n.source == pref_src), None)
        if c:
            chosen_name = c
            break

    best_accs: dict = {}
    for a in block_accounts:
        cur = best_accs.get(a.number)
        key = (_SOURCE_RANK.get(a.source, 3), a.distance if a.distance is not None else 1e9)
        if cur is None or key < (_SOURCE_RANK.get(cur.source, 3), cur.distance if cur.distance is not None else 1e9):
            best_accs[a.number] = a

    sorted_accs = sorted(
        best_accs.values(),
        key=lambda a: (_SOURCE_RANK.get(a.source, 3), a.distance if a.distance is not None else 1e9),
    )

    has_labeled_acc = any(a.source == "keyword" for a in sorted_accs)
    has_labeled_name = any(n.source == "keyword" for n in name_cands)

    block_dict = {
        "lines": [ln.text for ln in block_lines],
        "distance_to_qr": min_dist,
        "account_candidates": [a.model_dump() for a in sorted_accs],
        "account_numbers": [a.number for a in sorted_accs],
        "bank_ids": bank_ids,
        "bank_names": bank_names,
        "name_candidates": [n.model_dump() for n in name_cands],
        "account_name": chosen_name,
        "total_amount": total_amount,
        "line_item_amounts": line_item_amounts,
        "all_amounts": sorted(set(block_amounts)),
        "has_labeled_account": has_labeled_acc,
        "has_labeled_name": has_labeled_name,
    }
    block_dict["selection_score"] = _score_payment_block(block_dict)
    return block_dict


def _score_payment_block(block: dict) -> float:
    """
    P0-3: Deterministic multi-feature score for payment block selection.
    Combines payment-label anchors, labeled account number, labeled bank,
    labeled recipient, payable/total amount label, number of coherent fields,
    same-block relationships, and spatial proximity to QR.
    QR distance is only ONE feature. No ML, no network.
    """
    score = 0.0

    # 1. Payment-label anchors (e.g. "thanh toan", "chuyen khoan", "payment")
    lines_norm = [normalize(l) for l in block.get("lines", [])]
    has_anchor = any(bool(_PAYMENT_ANCHOR_KW.search(ln)) for ln in lines_norm)
    if has_anchor:
        score += 25.0

    # 2. Labeled account number anchor
    if block.get("has_labeled_account"):
        score += 40.0
    elif block.get("account_numbers"):
        score += 15.0

    # 3. Labeled bank
    if block.get("bank_ids"):
        score += 30.0

    # 4. Labeled recipient / account holder
    if block.get("has_labeled_name"):
        score += 30.0
    elif block.get("account_name"):
        score += 15.0

    # 5. Payable / total amount label
    if block.get("total_amount") is not None:
        score += 30.0

    # 6. Number of coherent payment fields present in this block
    coherent_fields = 0
    if block.get("account_numbers"):
        coherent_fields += 1
    if block.get("bank_ids"):
        coherent_fields += 1
    if block.get("account_name") or block.get("name_candidates"):
        coherent_fields += 1
    if block.get("total_amount") is not None:
        coherent_fields += 1

    score += coherent_fields * 20.0

    # 7. Same-block relationship: has both account and bank/name together
    if block.get("account_numbers") and (block.get("bank_ids") or block.get("account_name")):
        score += 25.0

    # 8. Spatial proximity to QR (QR distance penalty)
    dist = block.get("distance_to_qr")
    if dist is not None:
        score -= min(dist * 15.0, 60.0)
    else:
        score -= 20.0

    return round(score, 2)


# ─── Entry point ──────────────────────────────────────────────────────────
def extract_context(
    lines: Iterable[TextLine],
    qr_bbox: Optional[Sequence[float]] = None,
    source: str = "ocr",
    target_vietqr: Optional[object] = None,
) -> OCRData:
    """
    Trích xuất ngữ cảnh xung quanh mã QR với liên kết bằng chứng không gian:
    - lines: danh sách dòng chữ
    - qr_bbox: (x, y, w, h) của mã QR
    - target_vietqr: VietQRData từ TLV (nếu có) để dò tìm có hướng dẫn (Guided Matching)
    """
    # Tạo bản sao riêng biệt cho từng mã QR để tránh ghi đè/nhiễm độc cache khi ảnh có nhiều mã QR
    lines_list: List[TextLine] = []
    for ln in lines:
        if not ln.text or not ln.text.strip():
            continue
        rel_pos = ln.relative_pos
        if qr_bbox is not None and len(qr_bbox) == 4 and ln.cy is not None and ln.cx is not None:
            qx, qy, qw, qh = qr_bbox
            if ln.cy < qy:
                rel_pos = "above"
            elif ln.cy > qy + qh:
                rel_pos = "below"
            elif ln.cx < qx:
                rel_pos = "left"
            elif ln.cx > qx + qw:
                rel_pos = "right"
            else:
                rel_pos = "inside"

        dist = _distance(ln, qr_bbox)
        fresh_ln = TextLine(
            text=ln.text,
            conf=ln.conf,
            cx=ln.cx,
            cy=ln.cy,
            w=ln.w,
            h=ln.h,
            relative_pos=rel_pos,
        )
        setattr(fresh_ln, "distance", dist)
        lines_list.append(fresh_ln)

    if not lines_list:
        return OCRData(source=source if source != "ocr" else "none", context_type="empty")

    target_acc = None
    target_name = None
    if target_vietqr is not None:
        raw_acc = getattr(target_vietqr, "account_number", None)
        if raw_acc:
            target_acc = re.sub(r"\D", "", raw_acc)
        target_name = getattr(target_vietqr, "account_name", None)

    # Phân cụm không gian thành các khối bằng chứng
    clustered = _cluster_lines(lines_list, qr_bbox=qr_bbox)
    raw_blocks = [
        _extract_block_evidence(blk, qr_bbox=qr_bbox, target_acc=target_acc, target_name=target_name)
        for blk in clustered
    ]
    # P0-3: Sắp xếp các khối theo điểm bằng chứng thanh toán kết hợp cự ly QR
    raw_blocks.sort(
        key=lambda b: (
            -b.get("selection_score", 0.0),
            b["distance_to_qr"] if b["distance_to_qr"] is not None else 1e9,
        )
    )


    # Thu thập dữ liệu trang tổng thể (ưu tiên khối gần QR nhất trước)
    merged_accounts = []
    seen_acc = set()
    for blk in raw_blocks:
        for acc_dict in blk["account_candidates"]:
            cand = AccountCandidate(**acc_dict)
            if cand.number not in seen_acc:
                seen_acc.add(cand.number)
                merged_accounts.append(cand)

    merged_bank_ids = []
    for blk in raw_blocks:
        for bid in blk["bank_ids"]:
            if bid not in merged_bank_ids:
                merged_bank_ids.append(bid)

    merged_names = []
    seen_names = set()
    for blk in raw_blocks:
        for name_dict in blk["name_candidates"]:
            ncand = NameCandidate(**name_dict)
            if ncand.name not in seen_names:
                seen_names.add(ncand.name)
                merged_names.append(ncand)

    merged_names.sort(key=lambda n: _NAME_SOURCE_RANK.get(n.source, 3))
    primary_name = next((n.name for n in merged_names if n.source == "keyword"), None) or next(
        (b["account_name"] for b in raw_blocks if b.get("account_name")), None
    )
    all_page_amounts = sorted(set(amt for blk in raw_blocks for amt in blk["all_amounts"]))

    raw_text = " ".join(ln.text for ln in lines_list)
    norm_text = normalize(raw_text)

    return OCRData(
        raw_text=raw_text,
        source=source,
        context_type=detect_context_type(norm_text, merged_accounts, merged_names, merged_bank_ids),
        bank_ids=merged_bank_ids,
        bank_names=[bank_display_name(b) for b in merged_bank_ids],
        account_candidates=merged_accounts,
        account_numbers=[a.number for a in merged_accounts],
        name_candidates=merged_names,
        account_name=primary_name,
        amounts=all_page_amounts,
        payment_blocks=raw_blocks,
    )
