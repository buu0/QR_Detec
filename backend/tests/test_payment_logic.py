"""
Unit test cho nhánh thanh toán: parser + trích xuất ngữ cảnh + đối chiếu.
Không cần PaddleOCR/OpenCV — chạy được độc lập:

    cd backend
    pip install pydantic unidecode rapidfuzz pytest
    python -m pytest tests -q
"""
from typing import List, Optional

import pytest

from app.models.schemas import AlertCode
from app.services.amount_parser import find_amounts, parse_vnd
from app.services.bank_registry import find_bank_ids, normalize
from app.services.context_extractor import TextLine, extract_context
from app.services.fuzzy_matcher import fuzzy_match_and_alert
from app.services.vietqr_parser import parse_vietqr, verify_crc16


# ─── Helpers ──────────────────────────────────────────────────────────────
def _tlv(tag: str, value: str) -> str:
    return f"{tag}{len(value):02d}{value}"


def _crc(data: str) -> str:
    crc = 0xFFFF
    for b in data.encode("utf-8"):
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return f"{crc:04X}"


def make_vietqr(bin_code: str, account: str, name: Optional[str] = None,
                amount: Optional[str] = None, desc: Optional[str] = None) -> str:
    beneficiary = _tlv("00", bin_code) + _tlv("01", account)
    tag38 = _tlv("00", "A000000727") + _tlv("01", beneficiary) + _tlv("02", "QRIBFTTA")
    body = _tlv("00", "01") + _tlv("01", "12" if amount else "11") + _tlv("38", tag38) + _tlv("53", "704")
    if amount:
        body += _tlv("54", amount)
    body += _tlv("58", "VN")
    if name:
        body += _tlv("59", name)
    if desc:
        body += _tlv("62", _tlv("08", desc))
    body += "6304"
    return body + _crc(body)


def lines(*texts: str) -> List[TextLine]:
    return [TextLine(text=t) for t in texts]


def run(payload: str, ctx_lines: List[TextLine], bbox=None):
    v = parse_vietqr(payload)
    ctx = extract_context(ctx_lines, bbox, source="ocr")
    match, code, *_ = fuzzy_match_and_alert(v, ctx)
    return code, match, ctx, v


TCB, VCB, MB, LPB = "970407", "970436", "970422", "970462"


# ─── Bank registry ────────────────────────────────────────────────────────
@pytest.mark.parametrize("text,expected", [
    ("Techcombank", ["TCB"]),
    ("Sacombank", ["STB"]),
    ("Eximbank", ["EIB"]),
    ("PVcomBank", ["PVCB"]),
    ("Account number: 123", []),
    ("MB Bank", ["MB"]),
    ("Ngân hàng Nông nghiệp và Phát triển Nông thôn", ["AGRIBANK"]),
])
def test_bank_detection_word_boundary(text, expected):
    assert find_bank_ids(normalize(text)) == expected


# ─── Parser ───────────────────────────────────────────────────────────────
def test_crc_valid_with_trailing_newline():
    v = parse_vietqr(make_vietqr(VCB, "0123456789") + "\n")
    assert v.crc_valid and v.structure_valid
    assert v.bank_id == "VCB" and v.account_number == "0123456789"
    assert v.service_code == "QRIBFTTA"


def test_crc_invalid():
    p = make_vietqr(VCB, "0123456789")
    assert not verify_crc16(p[:-4] + "0000")


def test_truncated_tlv_detected():
    p = make_vietqr(VCB, "0123456789")
    assert p[12:14] == "38"
    broken = p[:14] + "99" + p[16:]          # khai báo độ dài Tag 38 = 99 → vượt payload
    v = parse_vietqr(broken)
    assert not v.structure_valid


def test_invalid_payload_alert():
    p = make_vietqr(VCB, "0123456789")
    code, *_ = run(p[:-4] + "0000", lines("STK: 0123456789"))
    assert code == AlertCode.INVALID_PAYLOAD


# ─── Kịch bản ngữ cảnh ────────────────────────────────────────────────────
def test_menu_without_account_is_insufficient_not_fraud():
    code, _, ctx, _ = run(make_vietqr(VCB, "0123456789"),
                          lines("CÀ PHÊ SỮA ĐÁ 45.000đ", "Bạc xỉu 39000 đ", "Hotline: 0909123456"))
    assert code == AlertCode.INSUFFICIENT_CONTEXT
    assert 45000 in ctx.amounts


def test_empty_context():
    code, _, ctx, _ = run(make_vietqr(VCB, "0123456789"), [])
    assert code == AlertCode.INSUFFICIENT_CONTEXT
    assert ctx.context_type == "empty"


def test_standee_logo_only_name_and_account_matches():
    code, match, *_ = run(make_vietqr(MB, "0123456789"), lines("NGUYEN VAN A", "0123456789"))
    assert code == AlertCode.CONTEXT_CONSISTENT
    assert match.bank_status == "unknown"     # logo → không biết, không phải "không khớp"


def test_phone_number_as_account():
    code, *_ = run(make_vietqr(MB, "0912345678"), lines("Zalo: 0912345678", "TRAN THI B"))
    assert code == AlertCode.CONTEXT_CONSISTENT


def test_grouped_account_digits_and_techcombank():
    code, match, *_ = run(make_vietqr(TCB, "190367890123"),
                          lines("Techcombank", "STK: 1903 6789 0123", "Chủ TK: Nguyễn Văn A"))
    assert code == AlertCode.CONTEXT_CONSISTENT
    assert match.bank_status == "match"


def test_lpbank_name_variants_match():
    code, match, *_ = run(make_vietqr(LPB, "0123456789"),
                          lines("LienViet PostBank", "Số tài khoản: 0123456789"))
    assert code == AlertCode.CONTEXT_CONSISTENT
    assert match.bank_status == "match"


def test_label_on_previous_line():
    code, *_ = run(make_vietqr(VCB, "0123456789"), lines("Số tài khoản", "0123456789"))
    assert code == AlertCode.CONTEXT_CONSISTENT


def test_overlay_sticker_is_critical():
    code, match, *_ = run(make_vietqr(TCB, "9999988888"),
                          lines("Techcombank", "STK: 1903 6789 0123", "NGUYEN VAN A"))
    assert code == AlertCode.CRITICAL_MISMATCH
    assert match.account_status == "mismatch"


def test_unlabeled_numbers_never_trigger_critical():
    code, *_ = run(make_vietqr(VCB, "0123456789"), lines("Mã đơn 88776655", "20251003", "0909123456"))
    assert code == AlertCode.INSUFFICIENT_CONTEXT


def test_near_match_is_partial():
    code, match, *_ = run(make_vietqr(VCB, "0123456789"), lines("STK: 0123456780"))
    assert code == AlertCode.PARTIAL_MATCH
    assert match.account_status == "near"


def test_labeled_account_match_but_bank_differs_is_critical():
    # Cùng dãy STK có nhãn nhưng ngân hàng in bằng chữ khác BIN → tài khoản khác → tráo đổi.
    code, match, *_ = run(make_vietqr(MB, "0123456789"), lines("Vietcombank", "STK: 0123456789"))
    assert match.account_status == "match" and match.account_source == "keyword"
    assert match.bank_status == "mismatch"
    assert code == AlertCode.CRITICAL_MISMATCH


def test_unlabeled_account_match_but_bank_differs_stays_partial():
    # STK không có nhãn là bằng chứng yếu hơn → giữ mức Partial Match.
    code, match, *_ = run(make_vietqr(MB, "0123456789"), lines("Vietcombank", "0123456789"))
    assert match.account_status == "match" and match.account_source != "keyword"
    assert match.bank_status == "mismatch"
    assert code == AlertCode.PARTIAL_MATCH


def test_invoice_amount_mismatch_is_partial():
    code, match, *_ = run(make_vietqr(VCB, "0123456789", amount="500000"),
                          lines("HOÁ ĐƠN BÁN HÀNG", "Tổng tiền: 150.000đ", "STK: 0123456789"))
    assert match.amount_status == "mismatch"
    assert code == AlertCode.PARTIAL_MATCH


def test_qr_name_differs_from_labeled_name():
    code, match, *_ = run(make_vietqr(VCB, "0123456789", name="TRAN VAN HACKER"),
                          lines("Chủ tài khoản: Nguyễn Thị Lan"))
    assert match.name_status == "mismatch"
    assert code == AlertCode.PARTIAL_MATCH


def test_poster_two_qr_uses_nearest_labeled_account():
    # QR A ở (0,0) cạnh STK A; STK B ở xa (cạnh QR B). QR A bị dán đè STK X.
    ctx = [
        TextLine("STK: 1111222233", cx=50, cy=130),
        TextLine("STK: 4444555566", cx=900, cy=130),
    ]
    code, match, *_ = run(make_vietqr(VCB, "7777888899"), ctx, bbox=(0, 0, 100, 100))
    assert code == AlertCode.CRITICAL_MISMATCH
    acc = next(c for c in match.checks if c.field == "account")
    assert acc.context_value == "1111222233"


def test_ui_checks_present():
    _, match, *_ = run(make_vietqr(VCB, "0123456789"), lines("STK: 0123456789"))
    fields = [c.field for c in match.checks]
    assert fields[:3] == ["bank", "account", "name"]


# ─── Chuẩn hoá số tiền ────────────────────────────────────────────────────────
@pytest.mark.parametrize("text,expected", [
    ("500k", 500_000),
    ("500K", 500_000),
    ("500 nghìn", 500_000),
    ("500 ngàn", 500_000),
    ("5tr", 5_000_000),
    ("5 triệu", 5_000_000),
    ("5 củ", 5_000_000),
    ("1tr5", 1_500_000),
    ("1tr250", 1_250_000),
    ("1.5tr", 1_500_000),
    ("1,5tr", 1_500_000),
    ("2k5", 2_500),
    ("2 tỷ", 2_000_000_000),
    ("50000vnd", 50_000),
    ("50000VND", 50_000),
    ("5.000.000vnd", 5_000_000),
    ("5.000.000 đ", 5_000_000),
    ("500.000đ", 500_000),
    ("500,000 VND", 500_000),
    ("VND 500000", 500_000),
    ("50.000 đồng", 50_000),
    ("500.000", 500_000),
    ("CK50000VND", 50_000),
])
def test_parse_vnd_shorthand(text, expected):
    assert parse_vnd(text) == expected


@pytest.mark.parametrize("text", [
    "Thanh toan don hang DH123456",
    "STK 0123456789",
    "Chuyen tien cho 0909123456",
    "Mua 2 kg cam",              # kg không phải nghìn
    "Tra 10 ngay",
    "NGUYEN VAN A chuyen tien",
])
def test_no_false_amount(text):
    assert find_amounts(text) == []


def test_multiple_amounts_in_content():
    vals = [a.value for a in find_amounts("Tien hang 450k + ship 50k")]
    assert vals == [450_000, 50_000]


# ─── Nội dung CK (Tag 62.08) vs số tiền (Tag 54) ──────────────────────────────────
def _desc_check(match):
    return next((c for c in match.checks if c.field == "description"), None)


def test_parser_reads_description():
    v = parse_vietqr(make_vietqr(VCB, "0123456789", amount="500000", desc="Chuyen khoan 500k"))
    assert v.crc_valid and v.structure_valid
    assert v.description == "Chuyen khoan 500k"


@pytest.mark.parametrize("amount,desc", [
    ("500000", "Chuyen khoan 500k"),
    ("500000", "Thanh toan 500.000d"),
    ("500000", "CK 500000vnd"),
    ("5000000", "Tien nha thang 10 5tr"),
    ("5000000", "Hoc phi 5.000.000vnd"),
    ("1500000", "Dat coc 1tr5"),
])
def test_description_amount_matches(amount, desc):
    code, match, *_ = run(make_vietqr(VCB, "0123456789", amount=amount, desc=desc),
                          lines("STK: 0123456789"))
    assert match.description_status == "match"
    assert code == AlertCode.CONTEXT_CONSISTENT


def test_description_amount_mismatch_500k_vs_50000vnd():
    # Số tiền thật 500.000đ nhưng nội dung ghi 50000vnd → cảnh báo
    code, match, *_ = run(
        make_vietqr(VCB, "0123456789", amount="500000", desc="Chuyen khoan 50000vnd"),
        lines("STK: 0123456789"),
    )
    assert match.description_status == "mismatch"
    assert code == AlertCode.PARTIAL_MATCH
    chk = _desc_check(match)
    assert chk.qr_value == "500.000 đ"
    assert "50.000 đ" in chk.context_value


def test_description_mismatch_without_context_is_partial():
    code, match, *_ = run(make_vietqr(VCB, "0123456789", amount="5000000", desc="Ung ho 500k"), [])
    assert match.description_status == "mismatch"
    assert code == AlertCode.PARTIAL_MATCH


def test_description_amount_but_qr_has_no_amount():
    code, match, *_ = run(make_vietqr(VCB, "0123456789", desc="Tien dien 500k"), lines("STK: 0123456789"))
    assert match.description_status == "na"
    assert code == AlertCode.CONTEXT_CONSISTENT


def test_description_without_amount_is_ignored():
    _, match, *_ = run(make_vietqr(VCB, "0123456789", amount="500000", desc="Thanh toan DH123456"),
                       lines("STK: 0123456789"))
    assert match.description_status == "na"
    assert _desc_check(match) is None


def test_context_shorthand_amount_on_invoice():
    # Hoá đơn ghi "Tổng: 500k" phải hiểu là 500.000đ (trước đây bị đọc thành 500)
    code, match, ctx, _ = run(make_vietqr(VCB, "0123456789", amount="500000"),
                              lines("HÓA ĐƠN", "Tổng tiền: 500k", "STK: 0123456789"))
    assert 500_000 in ctx.amounts
    assert match.amount_status == "match"
    assert code == AlertCode.CONTEXT_CONSISTENT


def test_ablation_line_item_vs_total_amount():
    """
    Nghiên cứu Ablation:
    Hoá đơn có đơn giá món hàng 50.000đ nhưng tổng tiền hoá đơn là 500.000đ.
    Mã QR gian lận hoặc sai lệch chỉ nạp số tiền 50.000đ.
    - matching_mode='spatial': phân biệt neo Tổng tiền -> báo mismatch (PARTIAL_MATCH).
    - matching_mode='global': gom phẳng số tiền -> thấy số 50.000đ có trên trang -> báo match!
    """
    v_qr = parse_vietqr(make_vietqr(VCB, "0123456789", amount="50000"))
    ctx_lines = [
        TextLine("HOÁ ĐƠN BÁN HÀNG", cx=200, cy=50),
        TextLine("STK: 0123456789", cx=200, cy=80),
        TextLine("Vietcombank", cx=200, cy=100),
        TextLine("Cà phê Arabica đơn giá: 50.000đ", cx=200, cy=150),
        TextLine("Tổng cộng: 500.000đ", cx=200, cy=200),
    ]
    ctx = extract_context(ctx_lines, qr_bbox=(100, 50, 200, 200), source="ocr", target_vietqr=v_qr)

    # 1. Chế độ Spatial (Production)
    match_sp, code_sp, *_ = fuzzy_match_and_alert(v_qr, ctx, matching_mode="spatial")
    assert match_sp.amount_status == "mismatch"
    assert code_sp == AlertCode.PARTIAL_MATCH

    # 2. Chế độ Global (Ablation baseline)
    match_gl, code_gl, *_ = fuzzy_match_and_alert(v_qr, ctx, matching_mode="global")
    assert match_gl.amount_status == "match"
    assert code_gl == AlertCode.CONTEXT_CONSISTENT


def test_ablation_multi_merchant_overlay_defense():
    """
    Nghiên cứu Ablation:
    Poster có khối thông tin thanh toán của Nạn nhân A (STK 1111222233).
    Kẻ gian dán đè mã QR (STK B: 9999888877) ngay cạnh thông tin của Nạn nhân A,
    đồng thời in dòng số tài khoản của mình ở vị trí xa (cx=900, cy=900).
    - matching_mode='spatial': ràng buộc không gian 2D với khối neo gần QR nhất -> phát hiện STK bị dán đè -> CRITICAL_MISMATCH.
    - matching_mode='global': gom phẳng toàn trang -> nhặt được số 9999888877 ở góc xa -> lừa thành công hệ thống (báo match)!
    """
    qr_attacker = parse_vietqr(make_vietqr(TCB, "9999888877"))
    ctx_lines = [
        # Khối A (ngay sát mã QR của kẻ gian)
        TextLine("QUÁN ĂN BÌNH DÂN", cx=100, cy=50),
        TextLine("STK: 1111222233", cx=100, cy=80),
        TextLine("Techcombank", cx=100, cy=110),
        TextLine("NGUYEN VAN A", cx=100, cy=140),

        # Khối xa ở góc dưới (cũng có nhãn STK)
        TextLine("STK: 9999888877", cx=900, cy=900),
    ]
    ctx = extract_context(ctx_lines, qr_bbox=(50, 50, 100, 100), source="ocr", target_vietqr=qr_attacker)

    # 1. Spatial: liên kết khối kề cận phát hiện ngay dán đè -> CRITICAL_MISMATCH
    match_sp, code_sp, *_ = fuzzy_match_and_alert(qr_attacker, ctx, matching_mode="spatial")
    assert match_sp.account_status == "mismatch"
    assert code_sp == AlertCode.CRITICAL_MISMATCH

    # 2. Global: gom phẳng toàn trang bị mơ hồ xung đột -> PARTIAL_MATCH (không xác định được dán đè)
    match_gl, code_gl, *_ = fuzzy_match_and_alert(qr_attacker, ctx, matching_mode="global")
    assert match_gl.account_status == "conflict"
    assert code_gl == AlertCode.PARTIAL_MATCH


def test_multiple_banks_spatial_isolation():
    """
    Tài liệu có 2 khối ngân hàng: Khối 1 là Vietcombank (STK 1111222233),
    Khối 2 là MBBank (STK 4444555566).
    Mã QR của MBBank đặt cạnh Khối 2:
    Hệ thống phân lập không gian chính xác, khớp với MBBank và không bị nhiễu bởi Vietcombank.
    """
    v_qr = parse_vietqr(make_vietqr(MB, "4444555566"))
    ctx_lines = [
        # Khối 1: VCB (xa)
        TextLine("Vietcombank", cx=100, cy=100),
        TextLine("STK: 1111222233", cx=100, cy=130),

        # Khối 2: MB (gần QR đặt tại 500, 500)
        TextLine("MBBank", cx=500, cy=520),
        TextLine("STK: 4444555566", cx=500, cy=550),
    ]
    ctx = extract_context(ctx_lines, qr_bbox=(450, 450, 100, 100), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx, matching_mode="spatial")

    assert code == AlertCode.CONTEXT_CONSISTENT
    assert match.bank_status == "match"
    assert match.account_status == "match"

