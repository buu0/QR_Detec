"""
Regression tests: chọn đúng tên người thụ hưởng từ OCR để đối chiếu với Tag 59.

Các lỗi được tái hiện từ ảnh thật:
- Dòng tiêu đề / khẩu hiệu IN HOA đứng trước tên có nhãn ("HOA DON THANH TOAN DICH VU", "CHUNG TAY UNG HO DONG BAO")
- OCR dính nhãn với giá trị ("CHU TKTRUNG TAMANH NGU BINH MINH")
- OCR tách nhãn và giá trị thành 2 dòng ("Chủ TK:" / "NGUYEN VAN AN")
- OCR nhầm ký tự trong tên ("LE THL HOA" thay cho "LE THI HOA")
- Chỉ có chữ in hoa không rõ vai trò → không kết luận "lệch tên"
"""
from app.models.schemas import AlertCode, NameCandidate, OCRData
from app.services.context_extractor import TextLine, extract_context
from app.services.fuzzy_matcher import check_name, fuzzy_match_and_alert, name_similarity
from app.services.vietqr_parser import parse_vietqr

QR_BBOX = (100, 100, 200, 200)


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


def _name_check(match):
    return next(c for c in match.checks if c.field == "name")


def test_labeled_name_wins_over_header_line_when_names_differ():
    """Hoá đơn bị tráo: tên so sánh phải là tên sau 'Chủ TK:', không phải tiêu đề hoá đơn."""
    v = parse_vietqr(make_vietqr("970436", "999988887777", "TRAN VAN GIAN LAN"))
    lines = [
        TextLine("HOÁ ĐƠN THANH TOÁN DỊCH VỤ", cx=200, cy=60, relative_pos="above"),
        TextLine("Ngân hàng: Vietcombank", cx=200, cy=320, relative_pos="below"),
        TextLine("STK: 0123456789", cx=200, cy=350, relative_pos="below"),
        TextLine("Chủ TK: NGUYỄN VĂN AN", cx=200, cy=380, relative_pos="below"),
    ]
    ctx = extract_context(lines, qr_bbox=QR_BBOX, source="ocr", target_vietqr=v)
    assert all(n.name != "HOA DON THANH TOAN DICH VU" for n in ctx.name_candidates)
    assert ctx.account_name == "NGUYEN VAN AN"
    match, code, *_ = fuzzy_match_and_alert(v, ctx)
    name = _name_check(match)
    assert name.status == "mismatch"
    assert name.context_value == "NGUYEN VAN AN"
    assert code == AlertCode.CRITICAL_MISMATCH


def test_donation_slogans_are_not_names():
    v = parse_vietqr(make_vietqr("970436", "1028888999", "DO VAN HUNG"))
    lines = [
        TextLine("CHUNG TAY ỦNG HỘ ĐỒNG BÀO", cx=200, cy=40, relative_pos="above"),
        TextLine("BỊ LŨ LỤT MIỀN TRUNG", cx=200, cy=70, relative_pos="above"),
        TextLine("Ngân hàng: Vietcombank", cx=200, cy=320, relative_pos="below"),
        TextLine("STK: 0011009998877", cx=200, cy=350, relative_pos="below"),
        TextLine("Chủ TK: QUỸ TỪ THIỆN AN BÌNH", cx=200, cy=380, relative_pos="below"),
    ]
    ctx = extract_context(lines, qr_bbox=QR_BBOX, source="ocr", target_vietqr=v)
    names = [n.name for n in ctx.name_candidates]
    assert "CHUNG TAY UNG HO DONG BAO" not in names
    assert "BI LU LUT MIEN TRUNG" not in names
    match, *_ = fuzzy_match_and_alert(v, ctx)
    assert _name_check(match).context_value == "QUY TU THIEN AN BINH"


def test_label_glued_to_value_by_ocr():
    v = parse_vietqr(make_vietqr("970415", "108876543210", "TRUNG TAM ANH NGU BINH MINH"))
    lines = [
        TextLine("Ngân hàng: VietinBank", cx=200, cy=320, relative_pos="below"),
        TextLine("STK: 108876543210", cx=200, cy=350, relative_pos="below"),
        TextLine("CHU TKTRUNG TAMANH NGU BINH MINH", cx=200, cy=380, relative_pos="below"),
    ]
    ctx = extract_context(lines, qr_bbox=QR_BBOX, source="ocr", target_vietqr=v)
    kw = [n for n in ctx.name_candidates if n.source == "keyword"]
    assert kw and kw[0].name == "TRUNG TAMANH NGU BINH MINH"
    match, code, *_ = fuzzy_match_and_alert(v, ctx)
    assert _name_check(match).status == "match"
    assert code == AlertCode.CONTEXT_CONSISTENT


def test_label_and_value_split_across_two_lines():
    v = parse_vietqr(make_vietqr("970436", "0123456789", "NGUYEN VAN AN"))
    lines = [
        TextLine("Vietcombank", cx=200, cy=320, relative_pos="below"),
        TextLine("STK: 0123456789", cx=200, cy=350, relative_pos="below"),
        TextLine("Chủ TK:", cx=150, cy=380, relative_pos="below"),
        TextLine("NGUYỄN VĂN AN", cx=250, cy=382, relative_pos="below"),
    ]
    ctx = extract_context(lines, qr_bbox=QR_BBOX, source="ocr", target_vietqr=v)
    assert any(n.name == "NGUYEN VAN AN" and n.source == "keyword" for n in ctx.name_candidates)
    match, code, *_ = fuzzy_match_and_alert(v, ctx)
    assert _name_check(match).status == "match"
    assert code == AlertCode.CONTEXT_CONSISTENT


def test_common_ocr_character_confusions_still_match():
    assert name_similarity("LE THI HOA", "LE THL HOA") >= 85
    assert name_similarity("TRUNG TAM ANH NGU BINH MINH", "TRUNG TAMANH NGU BINH MINH") >= 85
    # clearly different people must stay different
    assert name_similarity("NGUYEN VAN TUAN", "LE THI HOA") < 70


def test_lowercase_l_in_uppercase_word_restored_to_I():
    """Trên phông không chân, chữ 'I' hoa hay bị OCR giải mã thành 'l' thường trong từ IN HOA ('THl', 'MlNH')."""
    v = parse_vietqr(make_vietqr("970422", "1111222233", "NGUYEN VAN TUAN"))
    lines = [
        TextLine("Ngân hàng: MB Bank", cx=200, cy=320, relative_pos="below"),
        TextLine("STK: 0987654321", cx=200, cy=350, relative_pos="below"),
        TextLine("Chu TK: LE THl HOA", cx=200, cy=380, relative_pos="below"),
    ]
    ctx = extract_context(lines, qr_bbox=QR_BBOX, source="ocr", target_vietqr=v)
    assert ctx.account_name == "LE THI HOA"


def test_glued_amount_label_recognized_as_total_amount():
    """Nhãn 'Số tiền' bị OCR dính sát số ('Só tién3.500.000VND') vẫn được nhận làm tổng tiền thanh toán."""
    lines = [
        TextLine("Ngân hàng: VietinBank", cx=200, cy=320, relative_pos="below"),
        TextLine("STK:108876543210", cx=200, cy=350, relative_pos="below"),
        TextLine("Chü TKTRUNG TAM ANH NGU BINH MINH", cx=200, cy=380, relative_pos="below"),
        TextLine("Só tién3.500.000VND", cx=200, cy=410, relative_pos="below"),
    ]
    ctx = extract_context(lines, qr_bbox=QR_BBOX, source="ocr")
    assert ctx.payment_blocks[0]["total_amount"] == 3_500_000


def test_unlabeled_uppercase_only_is_unknown_not_mismatch():
    """Chỉ thấy tên cửa hàng in hoa, không có nhãn → không đủ bằng chứng để nói 'lệch tên'."""
    v = parse_vietqr(make_vietqr("970407", "19036688990011", "PHAM MINH TUAN"))
    ocr = OCRData(name_candidates=[NameCandidate(name="CA PHE MOC", source="upper")])
    chk = check_name(v, ocr)
    assert chk.status == "unknown"
    assert chk.context_value is None
