"""
Context Matching Service
Đối chiếu dữ liệu VietQR (TLV) với thông tin đọc được từ NGỮ CẢNH quanh mã QR.

Nguyên tắc ra quyết định (evidence-based):
- Chỉ báo CRITICAL_MISMATCH khi có BẰNG CHỨNG TÍCH CỰC: ngữ cảnh có STK được
  gắn nhãn rõ ràng (STK / Số tài khoản...) và STK đó KHÁC mã QR.
- Thiếu thông tin (không có STK, ngân hàng chỉ là logo...) → "không biết",
  không bao giờ bị coi là "không khớp".
- "Khớp" chỉ chứng minh mã QR không bị dán đè, KHÔNG đảm bảo người nhận đáng tin.
"""
import re
import logging
from typing import List, Optional, Tuple

from rapidfuzz import fuzz
from unidecode import unidecode

from app.models.schemas import (
    AccountCandidate, AlertCode, FieldCheck, MatchResult, NameCandidate, OCRData, VietQRData,
)
from app.services.amount_parser import find_amounts, format_vnd

logger = logging.getLogger(__name__)

# Ngưỡng
ACCOUNT_NEAR_RATIO = 85
NAME_MATCH_SCORE = 85

COLORS = {
    AlertCode.CONTEXT_CONSISTENT: "#1B5E20",
    AlertCode.CRITICAL_MISMATCH: "#B71C1C",
    AlertCode.PARTIAL_MATCH: "#E65100",
    AlertCode.INSUFFICIENT_CONTEXT: "#1565C0",
    AlertCode.INVALID_PAYLOAD: "#616161",
}

CONTEXT_LABELS = {
    "invoice": "hoá đơn",
    "donation": "poster quyên góp",
    "payment_info": "thông tin chuyển khoản",
    "general": "văn bản chung (menu, quảng cáo...)",
    "empty": "không có văn bản",
    "skipped": "không phân tích",
}

SOURCE_NOTES = {
    "keyword": "có nhãn STK",
    "standee_matched": "khớp số tài khoản trên standee",
    "standee_near": "gần khớp trên standee",
    "standee_adjacent": "tìm thấy cạnh mã QR",
    "phone": "dạng số điện thoại",
    "bare": "số không có nhãn",
    "other": "số không có nhãn",
}


# ─── Tiện ích ─────────────────────────────────────────────────────────────
def normalize_text(text: Optional[str]) -> str:
    """Bỏ dấu, IN HOA, gộp khoảng trắng"""
    if not text:
        return ""
    return re.sub(r"\s+", " ", unidecode(text).upper()).strip()


def _digits(s: Optional[str]) -> str:
    return re.sub(r"\D", "", s or "")


def _same_or_near(qr: str, number: str) -> bool:
    """True nếu `number` là chính STK của QR hoặc chỉ là biến thể OCR (lệch 1–2 chữ số)."""
    if not qr or not number:
        return False
    if number == qr:
        return True
    if (qr in number or number in qr) and abs(len(qr) - len(number)) <= 2:
        return True
    return float(fuzz.ratio(qr, number)) >= ACCOUNT_NEAR_RATIO


def _fmt_amount(value) -> Optional[str]:
    return format_vnd(value)


# ─── Kiểm tra từng trường ─────────────────────────────────────────────────
def check_bank(vietqr: VietQRData, ocr: OCRData) -> FieldCheck:
    chk = FieldCheck(field="bank", label="Ngân hàng", qr_value=vietqr.bank_name)
    if not vietqr.bank_id:
        chk.note = "BIN không có trong danh mục"
        return chk
    if not ocr.bank_ids:
        chk.note = "Không thấy tên ngân hàng dạng chữ (có thể chỉ có logo)"
        return chk
    if vietqr.bank_id in ocr.bank_ids:
        chk.status, chk.score, chk.context_value = "match", 100.0, vietqr.bank_name
    else:
        chk.status, chk.context_value = "mismatch", ", ".join(ocr.bank_names[:2])
    return chk


def check_account(vietqr: VietQRData, ocr: OCRData) -> Tuple[FieldCheck, Optional[AccountCandidate]]:
    label = "Số thẻ" if vietqr.service_code == "QRIBFTTC" else "Số tài khoản"
    chk = FieldCheck(field="account", label=label, qr_value=vietqr.account_number)
    qr = _digits(vietqr.account_number)
    raw_qr = vietqr.account_number or ""
    cands = ocr.account_candidates
    if not raw_qr or not cands:
        chk.note = "Không tìm thấy số tài khoản trong ngữ cảnh"
        return chk, None

    # 1. Trùng khớp tuyệt đối — NHƯNG bằng chứng mâu thuẫn có nhãn được ưu tiên.
    # Kẻ gian có thể in thêm STK của mình (không nhãn) trên sticker dán đè; một exact-match
    # như vậy không được phép che đi STK có nhãn "STK: ..." khác với mã QR.
    exact = [c for c in cands if (qr and c.number == qr) or c.number == raw_qr]
    conflicting = [
        c for c in cands
        if c.source == "keyword" and not _same_or_near(qr or raw_qr, c.number)
    ]
    if exact:
        c = next((e for e in exact if e.source == "keyword"), exact[0])
        if conflicting:
            other = conflicting[0]
            chk.score = float(fuzz.ratio(qr, other.number)) if qr else 0.0
            chk.context_value = other.number
            if c.source == "keyword":
                # Cả hai STK đều có nhãn → không đủ căn cứ kết luận tráo đổi, nhưng không được báo khớp.
                chk.status = "conflict"
                chk.note = (
                    f"Ngữ cảnh có nhiều số tài khoản có nhãn khác nhau ({c.number}, {other.number}); "
                    "không thể xác nhận số nào là đúng"
                )
            else:
                # STK có nhãn khác QR; số trùng QR chỉ là số không nhãn → coi là mâu thuẫn.
                chk.status = "mismatch"
                chk.note = (
                    f"Số tài khoản có nhãn ({other.number}) khác mã QR; số trùng mã QR "
                    f"({c.number}) không có nhãn nên không được tính là khớp"
                )
            return chk, other
        chk.status, chk.score, chk.context_value = "match", 100.0, c.number
        chk.note = SOURCE_NOTES.get(c.source, "khớp số tài khoản trên standee")
        return chk, c

    # 2. Gần khớp — xét STK có nhãn hoặc phát hiện ở lân cận QR (standee)
    eligible = [
        c for c in cands
        if c.source in ("keyword", "standee_matched", "standee_near", "standee_adjacent")
        or (c.distance is not None and c.distance <= 2.0)
    ]
    best_c, best_score = None, 0.0
    for c in eligible:
        if qr and ((qr in c.number or c.number in qr) and abs(len(qr) - len(c.number)) <= 2):
            score = 90.0
        else:
            score = float(fuzz.ratio(qr, c.number)) if qr else 0.0
        if score > best_score:
            best_c, best_score = c, score

    if best_c is not None and best_score >= ACCOUNT_NEAR_RATIO:
        chk.status, chk.score, chk.context_value = "near", best_score, best_c.number
        chk.note = "Khác 1–2 chữ số (có thể do ảnh mờ hoặc OCR nhầm ký tự)"
        return chk, best_c

    # 3. Phát hiện STK khác trong ngữ cảnh (mismatch)
    keyword_cands = [c for c in cands if c.source == "keyword"]
    near_cands = [
        c for c in cands
        if c.source in ("standee_adjacent", "bare", "phone") and (c.distance is not None and c.distance <= 2.0)
    ]
    other_valid_cands = [c for c in cands if c.source != "other"]

    target_cand = None
    if keyword_cands:
        target_cand = keyword_cands[0]
        note = "Số tài khoản in bên cạnh khác mã QR"
    elif near_cands:
        target_cand = near_cands[0]
        note = f"Số tài khoản in trên standee ({target_cand.number}) khác số tài khoản trong mã QR"
    elif ocr.context_type in ("payment_info", "invoice") and other_valid_cands:
        target_cand = other_valid_cands[0]
        note = f"Số tài khoản tìm thấy ({target_cand.number}) khác mã QR"

    if target_cand is not None:
        chk.status = "mismatch"
        chk.score = float(fuzz.ratio(qr, target_cand.number)) if qr else 0.0
        chk.context_value = target_cand.number
        chk.note = note
        return chk, target_cand

    chk.note = "Không tìm thấy số tài khoản phù hợp trong ngữ cảnh để đối chiếu"
    return chk, None


_NAME_RANK = {"keyword": 0, "standee_adjacent": 1, "upper": 2}

# Ký tự OCR hay đọc nhầm trên chữ IN HOA không dấu. Gập ĐỐI XỨNG cả hai phía chỉ để tính điểm
# (vd "LE THL HOA" vs "LE THI HOA"); giá trị hiển thị luôn giữ nguyên văn OCR.
_NAME_OCR_FOLD = str.maketrans({"L": "I", "J": "I", "1": "I", "|": "I", "!": "I", "0": "O", "Q": "O",
                                "5": "S", "8": "B", "2": "Z", "6": "G"})


def _fold_name(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").upper().translate(_NAME_OCR_FOLD)).strip()


def name_similarity(qr_name: str, ocr_name: str) -> float:
    """Điểm giống nhau của tên, chịu được lỗi OCR thường gặp:
    nhầm ký tự (I/L/1, O/0…), dính hoặc tách khoảng trắng ("TAMANH" vs "TAM ANH")."""
    a, b = normalize_text(qr_name), normalize_text(ocr_name)
    fa, fb = _fold_name(a), _fold_name(b)
    return max(
        float(fuzz.token_set_ratio(a, b)),
        float(fuzz.token_set_ratio(fa, fb)),
        float(fuzz.ratio(a.replace(" ", ""), b.replace(" ", ""))),
        float(fuzz.ratio(fa.replace(" ", ""), fb.replace(" ", ""))),
    )


def check_name(vietqr: VietQRData, ocr: OCRData) -> FieldCheck:
    chk = FieldCheck(field="name", label="Tên người nhận", qr_value=vietqr.account_name)
    # Xếp theo độ tin cậy: nhãn "Chủ TK:" > cạnh STK/QR > chữ in hoa bất kỳ (ổn định theo thứ tự đọc)
    cands = sorted(ocr.name_candidates or [], key=lambda n: _NAME_RANK.get(n.source, 3))
    if cands:
        labeled = next((n.name for n in cands if n.source == "keyword"), None)
        chk.context_value = labeled or ocr.account_name or cands[0].name
    if not vietqr.account_name:
        chk.status = "na"
        if chk.context_value:
            chk.note = f"Mã QR không cố định tên; tìm thấy trên standee: {chk.context_value} (hãy kiểm tra trong app ngân hàng)"
        else:
            chk.note = "Mã QR không chứa tên (bình thường với VietQR cá nhân)"
        return chk
    if not cands:
        chk.note = "Không thấy tên trong ngữ cảnh"
        return chk

    scored = [(name_similarity(vietqr.account_name, n.name), n) for n in cands]
    best_score, best = max(scored, key=lambda t: (t[0], -_NAME_RANK.get(t[1].source, 3)))
    chk.score = best_score
    if best_score >= NAME_MATCH_SCORE:
        chk.status, chk.context_value = "match", best.name
        return chk
    elif best_score >= 70:
        chk.status, chk.context_value = "near", best.name
        chk.note = "Tên gần khớp (có thể do viết tắt hoặc OCR sai dấu)"
        return chk

    # Tên khác biệt rõ rệt (dưới ngưỡng 70%): so với ứng viên ĐÁNG TIN NHẤT (có nhãn trước), không phải dòng đầu tiên
    eligible_names = [n for n in cands if n.source in ("keyword", "standee_adjacent")]
    if not eligible_names:
        # Chỉ có chữ in hoa không rõ vai trò → không đủ bằng chứng để kết luận lệch tên
        chk.status = "unknown"
        chk.context_value = None
        chk.note = "Không thấy tên có nhãn (Chủ TK / Người nhận) cạnh mã QR để đối chiếu"
        return chk
    chosen = eligible_names[0]
    chk.status = "mismatch"
    chk.context_value = chosen.name
    chk.note = f"Tên in trên standee ({chosen.name}) khác tên trong mã QR ({vietqr.account_name})"
    return chk


def check_amount(vietqr: VietQRData, ocr: OCRData) -> Optional[FieldCheck]:
    if not vietqr.amount and ocr.context_type != "invoice":
        return None
    chk = FieldCheck(field="amount", label="Số tiền", qr_value=_fmt_amount(vietqr.amount))
    if not vietqr.amount:
        chk.status, chk.note = "na", "Mã QR không cố định số tiền"
        return chk
    if ocr.context_type != "invoice" or not ocr.amounts:
        chk.status = "na"
        chk.note = "Chỉ đối chiếu số tiền với hoá đơn"
        return chk
    qr_amt = int(float(vietqr.amount))
    if qr_amt in ocr.amounts:
        chk.status, chk.score, chk.context_value = "match", 100.0, _fmt_amount(qr_amt)
    else:
        chk.status = "mismatch"
        chk.context_value = _fmt_amount(max(ocr.amounts))
        chk.note = "Không thấy số tiền này trên hoá đơn"
    return chk


def check_description(vietqr: VietQRData) -> Optional[FieldCheck]:
    """
    Đối chiếu số tiền ghi trong NỘI DUNG CHUYỂN KHOẢN (Tag 62.08) với số tiền thật (Tag 54).
    Chuẩn hoá cách viết tắt: 500k = 500.000đ, 5tr = 5.000.000đ, 50000vnd = 50.000đ.
    Thủ đoạn thường gặp: nội dung ghi "50k" nhưng mã QR cố định 500.000đ.
    """
    mentions = find_amounts(vietqr.description)
    if not mentions:
        return None
    values = sorted({m.value for m in mentions})
    shown = ", ".join(f"“{m.raw}” = {format_vnd(m.value)}" for m in mentions[:3])
    chk = FieldCheck(
        field="description", label="Số tiền trong nội dung CK",
        qr_value=_fmt_amount(vietqr.amount) if vietqr.amount else "Không cố định",
        context_value=shown,
    )
    if not vietqr.amount:
        chk.status = "na"
        chk.note = f"Mã QR không cố định số tiền — nội dung ghi {format_vnd(values[0])}, hãy tự nhập đúng"
        return chk
    qr_amt = int(float(vietqr.amount))
    if qr_amt in values:
        chk.status, chk.score = "match", 100.0
        chk.note = "Nội dung CK ghi đúng số tiền sẽ chuyển"
    else:
        chk.status = "mismatch"
        chk.note = f"Nội dung ghi {format_vnd(values[0])} nhưng mã QR sẽ chuyển {_fmt_amount(qr_amt)}"
    return chk


# ─── Ra quyết định + thông điệp UI ────────────────────────────────────────
def _receiver_line(v: VietQRData) -> str:
    parts = [v.bank_name or "Ngân hàng ?", f"STK {v.account_number or '?'}"]
    if v.account_name:
        parts.append(v.account_name)
    return " – ".join(parts)


def determine_alert(
    vietqr: VietQRData, ocr: OCRData, match: MatchResult
) -> Tuple[AlertCode, str, str, str, str]:
    """Returns: (alert_code, color, title, message, recommendation)"""
    ctx_label = CONTEXT_LABELS.get(ocr.context_type, "ngữ cảnh")
    checks = {c.field: c for c in match.checks}
    acc = checks.get("account")
    bank = checks.get("bank")

    def out(code: AlertCode, title: str, message: str, rec: str):
        return code, COLORS[code], title, message, rec

    # 1. Payload hỏng
    if not vietqr.crc_valid or not vietqr.structure_valid:
        reasons = []
        if not vietqr.crc_valid:
            reasons.append("Sai mã kiểm tra toàn vẹn CRC-16")
        reasons.extend(vietqr.structure_errors[:2])
        return out(
            AlertCode.INVALID_PAYLOAD,
            "⚠️ Mã thanh toán không hợp lệ hoặc bị hỏng",
            "\n".join(f"• {r}" for r in reasons) + f"\n• Dữ liệu đọc được: {_receiver_line(vietqr)}",
            "Ứng dụng ngân hàng có thể từ chối hoặc đọc sai mã này. "
            "Hãy yêu cầu người nhận cung cấp mã QR mới.",
        )

    # 2a. Cùng chuỗi STK có nhãn nhưng ngân hàng in bằng chữ khác BIN trong QR.
    # Cùng một dãy số ở ngân hàng khác là một tài khoản khác → tiền đi tới người nhận khác.
    if (
        match.account_status == "match"
        and match.account_source == "keyword"
        and match.bank_status == "mismatch"
    ):
        return out(
            AlertCode.CRITICAL_MISMATCH,
            "🚨 Cùng số tài khoản nhưng KHÁC ngân hàng: nghi vấn mã QR bị tráo đổi",
            f"• Thông tin in bên cạnh ({ctx_label}): STK {acc.context_value} – ngân hàng {bank.context_value}\n"
            f"• Mã QR lại chuyển tiền tới: {_receiver_line(vietqr)}\n"
            "• Cùng một dãy số ở hai ngân hàng khác nhau là hai tài khoản khác nhau",
            "KHÔNG chuyển tiền. Hỏi trực tiếp người bán / người nhận để xác minh "
            "ngân hàng và số tài khoản đúng trước khi thanh toán.",
        )

    # 2b. Bằng chứng tráo đổi: STK khác HOẶC (Ngân hàng khác + Tên khác)
    if match.account_status == "mismatch" or (match.bank_status == "mismatch" and match.name_status == "mismatch"):
        ctx_bank = f" ({bank.context_value})" if bank and bank.context_value else ""
        ctx_acc = f"STK {acc.context_value}" if acc and acc.context_value else ""
        ctx_name = f" – {checks['name'].context_value}" if checks.get("name") and checks["name"].context_value and checks["name"].context_value != "na" else ""
        ctx_info = f"{ctx_acc}{ctx_bank}{ctx_name}".strip()
        return out(
            AlertCode.CRITICAL_MISMATCH,
            "🚨 Nghi vấn mã QR bị tráo đổi / dán đè",
            f"• Thông tin in bên cạnh ({ctx_label}): {ctx_info or 'Khác biệt hoàn toàn với mã QR'}\n"
            f"• Mã QR lại chuyển tiền tới: {_receiver_line(vietqr)}",
            "KHÔNG chuyển tiền. Hỏi trực tiếp người bán / người nhận để xác minh "
            "số tài khoản đúng trước khi thanh toán.",
        )

    issues: List[str] = []
    if match.description_status == "mismatch":
        d = checks["description"]
        issues.append(
            f"Nội dung chuyển khoản ghi {d.context_value} nhưng số tiền thật trong mã QR là {d.qr_value}"
        )
    if match.bank_status == "mismatch":
        issues.append(f"Ngân hàng in bên cạnh ({bank.context_value}) khác ngân hàng trong QR ({vietqr.bank_name})")
    if match.name_status == "mismatch":
        issues.append(f"Tên in bên cạnh ({checks['name'].context_value}) khác tên trong QR ({vietqr.account_name})")
    if match.amount_status == "mismatch":
        issues.append(f"Số tiền trong QR ({checks['amount'].qr_value}) không khớp số tiền thanh toán ghi nhận ({checks['amount'].context_value or 'trên ảnh'})")

    # 3. STK khớp
    if match.account_status == "match":
        if issues:
            return out(
                AlertCode.PARTIAL_MATCH,
                "⚠️ Số tài khoản khớp nhưng có điểm bất thường",
                f"• Số tài khoản khớp: {vietqr.account_number}\n" + "\n".join(f"• {i}" for i in issues),
                "Đối chiếu kỹ tên người nhận hiển thị trong app ngân hàng trước khi xác nhận chuyển tiền.",
            )
        extra = []
        if match.bank_status == "match":
            extra.append(f"• Ngân hàng khớp: {vietqr.bank_name}")
        if match.name_status == "match":
            extra.append(f"• Tên người nhận khớp: {checks['name'].context_value}")
        elif checks.get("name") and checks["name"].context_value:
            extra.append(f"• Tên trên standee/ngữ cảnh: {checks['name'].context_value} (đối chiếu trong app)")
        if match.amount_status == "match":
            extra.append(f"• Số tiền khớp: {checks['amount'].qr_value}")
        return out(
            AlertCode.CONTEXT_CONSISTENT,
            "Thông tin trong mã QR trùng với chữ đọc được trên ảnh",
            f"• Số tài khoản trong QR trùng với số in bên cạnh ({ctx_label}): {vietqr.account_number}\n"
            + ("\n".join(extra) + "\n" if extra else "")
            + f"• Người nhận: {_receiver_line(vietqr)}",
            "Điều này chưa xác nhận tài khoản thuộc đúng người bạn muốn chuyển tiền. "
            "Hãy kiểm tra tên người nhận trong app ngân hàng trước khi xác nhận — nếu thông tin "
            "này do người lạ gửi qua tin nhắn, việc khớp không đảm bảo người nhận đáng tin.",
        )

    # 3b. Nhiều STK có nhãn khác nhau trong ngữ cảnh → không bao giờ báo khớp
    if match.account_status == "conflict":
        return out(
            AlertCode.PARTIAL_MATCH,
            "⚠️ Ảnh có nhiều số tài khoản khác nhau",
            f"• Mã QR chuyển tới: {vietqr.account_number}\n"
            f"• Ảnh còn ghi số tài khoản khác: {acc.context_value}\n"
            + "".join(f"• {i}\n" for i in issues)
            + f"• Người nhận: {_receiver_line(vietqr)}",
            "Không thể xác định số tài khoản nào là đúng. Hỏi trực tiếp người nhận "
            "và kiểm tra tên hiển thị trong app ngân hàng trước khi chuyển tiền.",
        )

    # 4. STK gần khớp
    if match.account_status == "near":
        return out(
            AlertCode.PARTIAL_MATCH,
            "⚠️ Cần kiểm tra lại: số tài khoản gần khớp",
            f"• Mã QR: {vietqr.account_number}\n• In bên cạnh: {acc.context_value} "
            f"(giống {acc.score:.0f}%)\n" + "".join(f"• {i}\n" for i in issues)
            + f"• Người nhận: {_receiver_line(vietqr)}",
            "Có thể do ảnh mờ hoặc chữ bị che. Hãy so từng chữ số bằng mắt trước khi chuyển tiền.",
        )

    # 5. Không tìm thấy STK trong ngữ cảnh
    if issues:
        only_desc = match.description_status == "mismatch" and len(issues) == 1
        return out(
            AlertCode.PARTIAL_MATCH,
            "⚠️ Số tiền trong nội dung chuyển khoản khác số tiền thật" if only_desc
            else "⚠️ Cần kiểm tra lại: thông tin không khớp mã QR",
            "\n".join(f"• {i}" for i in issues)
            + f"\n• Không tìm thấy số tài khoản trong ngữ cảnh để đối chiếu thêm"
            + f"\n• Mã QR chuyển tiền tới: {_receiver_line(vietqr)}",
            "Kiểm tra số tiền hiển thị trong app ngân hàng trước khi xác nhận — "
            "đừng tin vào số tiền ghi trong nội dung." if only_desc
            else "Xác minh lại với người nhận trước khi chuyển tiền.",
        )

    if match.name_status == "match":
        return out(
            AlertCode.PARTIAL_MATCH,
            "⚠️ Tên người nhận khớp, chưa xác minh được số tài khoản",
            f"• Tên in bên cạnh khớp tên trong QR: {checks['name'].context_value}\n"
            f"• Không tìm thấy số tài khoản trong ngữ cảnh\n"
            f"• Người nhận: {_receiver_line(vietqr)}",
            "Kiểm tra số tài khoản và tên hiển thị trong app ngân hàng trước khi xác nhận.",
        )

    if ocr.context_type == "empty":
        reason = "Không có văn bản nào xung quanh mã QR (ảnh có thể đã bị cắt sát mã)."
    elif ocr.context_type == "general":
        reason = f"Văn bản xung quanh là {ctx_label}, không chứa số tài khoản hay tên người nhận."
    else:
        reason = f"Đã đọc được văn bản ({ctx_label}) nhưng không thấy số tài khoản rõ ràng."
    bank_note = f"\n• Ngân hàng khớp: {vietqr.bank_name}" if match.bank_status == "match" else ""
    return out(
        AlertCode.INSUFFICIENT_CONTEXT,
        "ℹ️ Chưa đủ thông tin để đối chiếu",
        f"{reason}{bank_note}\n• Mã QR chuyển tiền tới: {_receiver_line(vietqr)}",
        "Chụp rộng hơn để thấy cả phần chữ in cạnh mã QR (số tài khoản, tên người nhận), "
        "hoặc tự xác nhận tên người nhận trong app ngân hàng trước khi chuyển.",
    )


def fuzzy_match_and_alert(
    vietqr: VietQRData,
    ocr: OCRData,
    matching_mode: str = "spatial",
) -> Tuple[MatchResult, AlertCode, str, str, str, str]:
    """
    Main entry: đối chiếu QR với ngữ cảnh và trả về kết quả.
    Hỗ trợ hook nghiên cứu ablation:
    - matching_mode="spatial" (Mặc định / Production): ràng buộc bằng chứng theo khối không gian 2D,
      phân định tổng tiền vs đơn giá, bảo toàn xung đột tài khoản có nhãn.
    - matching_mode="global" (Đánh giá Ablation): đối chiếu phẳng trên toàn bộ token của tài liệu.
    Returns: (match_result, alert_code, color, title, message, recommendation)
    """
    match = MatchResult()

    if vietqr.crc_valid and vietqr.structure_valid:
        if matching_mode == "spatial" and getattr(ocr, "payment_blocks", None):
            primary_block = ocr.payment_blocks[0]

            # 1. Ngân hàng
            if primary_block.get("bank_ids"):
                if vietqr.bank_id and vietqr.bank_id in primary_block["bank_ids"]:
                    bank = FieldCheck(
                        field="bank", label="Ngân hàng", qr_value=vietqr.bank_name,
                        status="match", score=100.0, context_value=vietqr.bank_name,
                    )
                elif vietqr.bank_id:
                    bank = FieldCheck(
                        field="bank", label="Ngân hàng", qr_value=vietqr.bank_name,
                        status="mismatch", score=0.0,
                        context_value=", ".join(primary_block.get("bank_names", [])[:2]),
                    )
                else:
                    bank = FieldCheck(field="bank", label="Ngân hàng", qr_value=vietqr.bank_name, note="BIN không có trong danh mục")
            else:
                # Không fallback toàn trang trong chế độ production spatial (UNKNOWN / INSUFFICIENT)
                bank = FieldCheck(
                    field="bank", label="Ngân hàng", qr_value=vietqr.bank_name,
                    status="unknown", score=0.0,
                    note="Không tìm thấy tên ngân hàng dạng chữ trong khối thanh toán gắn với mã QR (có thể chỉ có logo)",
                )


            # 2. Số tài khoản (Bảo toàn xung đột tài khoản có nhãn & liên kết không gian)
            qr_num = _digits(vietqr.account_number)
            raw_qr = vietqr.account_number or ""
            primary_cands = [AccountCandidate(**d) for d in primary_block.get("account_candidates", [])]

            if primary_cands:
                temp_ocr = ocr.model_copy()
                temp_ocr.account_candidates = primary_cands
                chk_acc, acc_cand = check_account(vietqr, temp_ocr)

                # Bảo toàn xung đột khi có khối khác cũng ở cự ly gần QR (mơ hồ không gian)
                primary_dist = primary_block.get("distance_to_qr")
                other_ambiguous_conflicts = []
                for b in ocr.payment_blocks[1:]:
                    b_dist = b.get("distance_to_qr")
                    is_near = (b_dist is None and primary_dist is None) or (
                        b_dist is not None and (
                            b_dist <= 2.0 or (primary_dist is not None and b_dist <= 1.5 * max(primary_dist, 0.1))
                        )
                    )
                    if is_near:
                        for d in b.get("account_candidates", []):
                            c = AccountCandidate(**d)
                            if c.source == "keyword" and not _same_or_near(qr_num or raw_qr, c.number):
                                other_ambiguous_conflicts.append(c)

                if chk_acc.status == "match" and other_ambiguous_conflicts:
                    other = other_ambiguous_conflicts[0]
                    chk_acc.status = "conflict"
                    chk_acc.score = float(fuzz.ratio(qr_num, other.number)) if qr_num else 0.0
                    chk_acc.context_value = other.number
                    chk_acc.note = (
                        f"Ngữ cảnh có nhiều số tài khoản có nhãn khác nhau ở các khối cạnh tranh ({chk_acc.context_value}, {other.number}); "
                        "không thể xác nhận số nào là đúng"
                    )
                acc = chk_acc
            else:
                acc_cand = None
                # P0-2: Không fallback toàn trang. Không có STK trong khối đã chọn -> unknown (field is applicable but not observed)
                label = "Số thẻ" if vietqr.service_code == "QRIBFTTC" else "Số tài khoản"
                acc = FieldCheck(
                    field="account", label=label, qr_value=vietqr.account_number,
                    status="unknown", score=0.0,
                    note="Không tìm thấy số tài khoản trong khối thanh toán gắn với mã QR",
                )

            # 3. Tên người nhận
            prim_dicts = list(primary_block.get("name_candidates") or [])
            if not any(d.get("source") == "keyword" for d in prim_dicts):
                # Tên có nhãn tường minh ("Chủ TK: ...") bị OCR xếp vào khối khác: vẫn là bằng chứng mạnh
                prim_dicts += [n.model_dump() for n in (ocr.name_candidates or []) if n.source == "keyword"
                               and all(n.name != d.get("name") for d in prim_dicts)]
            if prim_dicts:
                prim_names = [NameCandidate(**d) for d in prim_dicts]
                temp_ocr = ocr.model_copy()
                temp_ocr.name_candidates = prim_names
                temp_ocr.account_name = next((n.name for n in prim_names if n.source == "keyword"), None) or primary_block.get("account_name")
                name = check_name(vietqr, temp_ocr)
            else:
                # P0-2: Không fallback tên toàn trang trong production (UNKNOWN / INSUFFICIENT)
                name = FieldCheck(
                    field="name", label="Tên người nhận", qr_value=vietqr.account_name,
                    status="unknown", score=0.0,
                    note="Không tìm thấy tên người nhận trong khối thanh toán gắn với mã QR",
                )


            # 4. Số tiền: đối chiếu khi khối thanh toán có neo số tiền rõ ràng hoặc hoá đơn
            if vietqr.amount:
                qr_amt = int(float(vietqr.amount))
                total_amt = primary_block.get("total_amount")
                line_items = primary_block.get("line_item_amounts", [])
                if total_amt is not None:
                    if qr_amt == total_amt:
                        amount = FieldCheck(
                            field="amount", label="Số tiền", qr_value=_fmt_amount(qr_amt),
                            status="match", score=100.0, context_value=_fmt_amount(qr_amt),
                        )
                    elif qr_amt in line_items:
                        amount = FieldCheck(
                            field="amount", label="Số tiền", qr_value=_fmt_amount(qr_amt),
                            status="mismatch", score=0.0, context_value=_fmt_amount(total_amt),
                            note=f"Số tiền trong QR ({_fmt_amount(qr_amt)}) trùng đơn giá món hàng, khác tổng thanh toán ({_fmt_amount(total_amt)})",
                        )
                    else:
                        amount = FieldCheck(
                            field="amount", label="Số tiền", qr_value=_fmt_amount(qr_amt),
                            status="mismatch", score=0.0, context_value=_fmt_amount(total_amt),
                            note=f"Số tiền trong QR ({_fmt_amount(qr_amt)}) khác số tiền thanh toán ghi nhận ({_fmt_amount(total_amt)})",
                        )
                elif line_items and qr_amt in line_items:
                    amount = FieldCheck(
                        field="amount", label="Số tiền", qr_value=_fmt_amount(qr_amt),
                        status="mismatch", score=0.0,
                        note=f"Số tiền trong QR ({_fmt_amount(qr_amt)}) trùng đơn giá món hàng, không phải tổng thanh toán",
                    )
                elif ocr.context_type == "invoice":
                    amount = FieldCheck(
                        field="amount", label="Số tiền", qr_value=_fmt_amount(qr_amt),
                        status="unknown", score=0.0,
                        note="Không tìm thấy nhãn tổng tiền thanh toán trên hoá đơn gắn với mã QR",
                    )
                else:
                    amount = FieldCheck(
                        field="amount", label="Số tiền", qr_value=_fmt_amount(qr_amt),
                        status="na", score=0.0,
                        note="Khối ngữ cảnh quanh mã QR không quy định số tiền thanh toán cố định",
                    )
            else:
                amount = None

            # 5. Nội dung chuyển khoản
            desc = check_description(vietqr)

        else:
            # Chế độ Global: đối chiếu phẳng không gom cụm không gian (Evaluation baseline only)
            bank = check_bank(vietqr, ocr)
            acc, acc_cand = check_account(vietqr, ocr)
            name = check_name(vietqr, ocr)
            amount = check_amount(vietqr, ocr)
            desc = check_description(vietqr)

        match.checks = [c for c in (bank, acc, name, amount, desc) if c is not None]

        match.bank_status, match.bank_score = bank.status, bank.score
        match.account_status, match.account_score = acc.status, acc.score
        match.account_source = acc_cand.source if acc_cand is not None else ""
        match.name_status, match.name_score = name.status, name.score
        match.amount_status = amount.status if amount else "na"
        match.description_status = desc.status if desc else "na"

    alert_code, color, title, message, rec = determine_alert(vietqr, ocr, match)
    return match, alert_code, color, title, message, rec

