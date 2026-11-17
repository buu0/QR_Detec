"""
Unit tests for Standee & Real-World OCR Context Extraction:
- Không có từ khoá 'Số tài khoản' / 'STK'
- Dãy số tài khoản đặt bên trên, bên dưới, bên trái, bên phải QR
- Lỗi OCR phổ biến: ký tự 'O' thay cho '0', 'l' thay cho '1'
- Tên viết dạng Title Case: 'Nguyễn Văn A'
- Trích xuất tên lân cận số tài khoản trên standee
- VietQR không có Tag 59 nhưng standee có tên chủ quán
"""
from app.models.schemas import AlertCode
from app.services.context_extractor import TextLine, extract_context
from app.services.fuzzy_matcher import fuzzy_match_and_alert
from app.services.vietqr_parser import parse_vietqr


def _tlv(tag: str, value: str) -> str:
    return f"{tag}{len(value):02d}{value}"


def _crc(data: str) -> str:
    crc = 0xFFFF
    for b in data.encode("utf-8"):
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return f"{crc:04X}"


def make_vietqr(bin_code: str, account: str, name: str = None) -> str:
    beneficiary = _tlv("00", bin_code) + _tlv("01", account)
    tag38 = _tlv("00", "A000000727") + _tlv("01", beneficiary) + _tlv("02", "QRIBFTTA")
    body = _tlv("00", "01") + _tlv("01", "11") + _tlv("38", tag38) + _tlv("53", "704") + _tlv("58", "VN")
    if name:
        body += _tlv("59", name)
    body += "6304"
    return body + _crc(body)


def test_standee_no_stk_keyword_matches_tlv():
    """
    Standee thực tế không có nhãn 'STK' hay 'Số tài khoản'.
    Chỉ in dãy số và tên bên dưới mã QR.
    Hệ thống dùng TLV target_vietqr để nhận diện chính xác STK.
    """
    v_qr = parse_vietqr(make_vietqr("970422", "0388123456"))  # MBBank
    # Giả lập mã QR ở giữa (100, 100, 200, 200)
    # Phía dưới QR: tên chủ quán, dãy số tài khoản, tên ngân hàng
    ctx_lines = [
        TextLine("QUÉT MÃ THANH TOÁN", cx=200, cy=80, relative_pos="above"),
        TextLine("NGUYỄN VĂN A", cx=200, cy=320, relative_pos="below"),
        TextLine("0388123456", cx=200, cy=350, relative_pos="below"),
        TextLine("MBBank", cx=200, cy=380, relative_pos="below"),
    ]

    ctx = extract_context(ctx_lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, color, title, msg, rec = fuzzy_match_and_alert(v_qr, ctx)

    assert code == AlertCode.CONTEXT_CONSISTENT
    assert match.account_status == "match"
    assert match.bank_status == "match"
    # Tên trên standee được bóc tách và gợi ý người dùng
    assert ctx.account_name == "NGUYEN VAN A"


def test_standee_ocr_typo_letter_o_instead_of_zero():
    """
    OCR bị nhầm chữ 'O' thành số '0' trong dãy số: O388123456 thay vì 0388123456.
    Bộ chuẩn hoá clean_ocr_digits phải tự động phục hồi và khớp thành công.
    """
    v_qr = parse_vietqr(make_vietqr("970436", "0388123456"))  # VCB
    ctx_lines = [
        TextLine("O388123456", cx=200, cy=320, relative_pos="below"),
        TextLine("Trần Văn Bình", cx=200, cy=350, relative_pos="below"),
    ]

    ctx = extract_context(ctx_lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx)

    assert code == AlertCode.CONTEXT_CONSISTENT
    assert match.account_status == "match"
    assert ctx.account_name == "TRAN VAN BINH"


def test_standee_title_case_vietnamese_name():
    """
    Tên người nhận in Title Case có dấu tiếng Việt 'Lê Thị Thu Thảo'
    không có nhãn 'Chủ tài khoản', nằm ngay trên mã QR.
    """
    v_qr = parse_vietqr(make_vietqr("970407", "1903456789"))  # TCB
    ctx_lines = [
        TextLine("Lê Thị Thu Thảo", cx=200, cy=70, relative_pos="above"),
        TextLine("Techcombank", cx=200, cy=90, relative_pos="above"),
        TextLine("1903 456 789", cx=200, cy=330, relative_pos="below"),
    ]

    ctx = extract_context(ctx_lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx)

    assert code == AlertCode.CONTEXT_CONSISTENT
    assert match.account_status == "match"
    assert match.bank_status == "match"
    assert ctx.account_name == "LE THI THU THAO"


def test_standee_personal_qr_without_tag59_surfaces_standee_name():
    """
    Mã VietQR tĩnh cá nhân KHÔNG CÓ Tag 59 (tên chủ thẻ trong QR = None).
    Standee in 'VŨ ĐÌNH TRỌNG'.
    Hệ thống phải gán tên từ standee vào ocr_data.account_name để hiển thị cho người dùng đối soát.
    """
    v_qr = parse_vietqr(make_vietqr("970423", "00001234567"))  # TPBank, không có Tag 59
    assert v_qr.account_name is None

    ctx_lines = [
        TextLine("TPBank", cx=200, cy=60, relative_pos="above"),
        TextLine("00001234567", cx=200, cy=320, relative_pos="below"),
        TextLine("Vũ Đình Trọng", cx=200, cy=350, relative_pos="below"),
    ]

    ctx = extract_context(ctx_lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, color, title, msg, rec = fuzzy_match_and_alert(v_qr, ctx)

    assert code == AlertCode.CONTEXT_CONSISTENT
    assert ctx.account_name == "VU DINH TRONG"
    # Thông điệp alert phải chứa thông tin tên chủ quầy trên standee
    assert "VU DINH TRONG" in msg


def test_standee_fraud_tampered_qr_detects_all_mismatches():
    """
    Kịch bản dán đè mã QR lừa đảo:
    Standee của cửa hàng: BIDV, số tài khoản 7351434495, tên NGUYEN QUOC THINH (không nhãn STK).
    Kẻ gian dán đè mã QR của: TPBank, STK 09392764131, tên HO CHI HAI.
    Hệ thống phải phát hiện MISMATCH trên cả 3 trường và kích hoạt CRITICAL_MISMATCH.
    """
    fake_qr = parse_vietqr(make_vietqr("970423", "09392764131", "HO CHI HAI"))  # TPBank
    ctx_lines = [
        TextLine("BIDV", cx=200, cy=70, relative_pos="above"),
        TextLine("NGUYỄN QUỐC THỊNH", cx=200, cy=320, relative_pos="below"),
        TextLine("7351434495", cx=200, cy=350, relative_pos="below"),
    ]

    ctx = extract_context(ctx_lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=fake_qr)
    match, code, color, title, msg, rec = fuzzy_match_and_alert(fake_qr, ctx)

    assert code == AlertCode.CRITICAL_MISMATCH
    assert match.bank_status == "mismatch"
    assert match.account_status == "mismatch"
    assert match.name_status == "mismatch"
    # Số in trên standee phải được so sánh và hiển thị
    checks = {c.field: c for c in match.checks}
    assert checks["account"].context_value == "7351434495"
    assert checks["account"].status == "mismatch"
    assert checks["bank"].context_value == "BIDV"
    assert checks["name"].context_value == "NGUYEN QUOC THINH"
    assert checks["name"].status == "mismatch"


# ─── Exact match không nhãn không được che STK có nhãn khác QR (Adversary A2) ──────
def test_attacker_printed_account_does_not_hide_labeled_mismatch():
    """
    Sticker dán đè in thêm STK của kẻ gian (không nhãn) ngay dưới QR; QR không có Tag 59.
    Standee gốc vẫn in rõ 'STK: <STK thật>' → phải là CRITICAL_MISMATCH, không được xanh lá.
    """
    fake_qr = parse_vietqr(make_vietqr("970407", "9999988888"))  # TCB, không Tag 59
    ctx_lines = [
        TextLine("Techcombank", cx=200, cy=60, relative_pos="above"),
        TextLine("STK: 1903 6789 0123", cx=200, cy=320, relative_pos="below"),
        TextLine("NGUYEN VAN A", cx=200, cy=350, relative_pos="below"),
        TextLine("9999988888", cx=200, cy=310, relative_pos="below"),
    ]
    ctx = extract_context(ctx_lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=fake_qr)
    match, code, *_ = fuzzy_match_and_alert(fake_qr, ctx)

    assert code == AlertCode.CRITICAL_MISMATCH
    assert match.account_status == "mismatch"
    checks = {c.field: c for c in match.checks}
    assert checks["account"].context_value == "190367890123"


def test_two_labeled_accounts_are_conflict_not_match():
    """Cả STK của QR và một STK khác đều có nhãn → cảnh báo (PARTIAL_MATCH), không báo khớp."""
    v_qr = parse_vietqr(make_vietqr("970407", "9999988888"))
    ctx_lines = [
        TextLine("Techcombank", cx=200, cy=60, relative_pos="above"),
        TextLine("STK: 1903 6789 0123", cx=200, cy=320, relative_pos="below"),
        TextLine("STK: 9999988888", cx=200, cy=350, relative_pos="below"),
    ]
    ctx = extract_context(ctx_lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx)

    assert code == AlertCode.PARTIAL_MATCH
    assert match.account_status == "conflict"



def test_labeled_match_with_unlabeled_other_number_still_matches():
    """STK có nhãn trùng QR + một số không nhãn khác (hotline) → vẫn khớp, không false positive."""
    v_qr = parse_vietqr(make_vietqr("970407", "1903456789"))
    ctx_lines = [
        TextLine("Techcombank", cx=200, cy=60, relative_pos="above"),
        TextLine("STK: 1903 456 789", cx=200, cy=320, relative_pos="below"),
        TextLine("0912345678", cx=200, cy=350, relative_pos="below"),
    ]
    ctx = extract_context(ctx_lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx)

    assert code == AlertCode.CONTEXT_CONSISTENT
    assert match.account_status == "match"


def test_labeled_ocr_variant_of_qr_account_is_not_conflict():
    """STK có nhãn bị OCR đọc lệch 1 chữ số + số không nhãn trùng QR → không coi là mâu thuẫn."""
    v_qr = parse_vietqr(make_vietqr("970407", "1903456789"))
    ctx_lines = [
        TextLine("STK: 1903456780", cx=200, cy=320, relative_pos="below"),
        TextLine("1903456789", cx=200, cy=350, relative_pos="below"),
    ]
    ctx = extract_context(ctx_lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx)

    assert match.account_status == "match"
    assert code == AlertCode.CONTEXT_CONSISTENT

