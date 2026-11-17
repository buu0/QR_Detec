"""
Regression tests for P0-2 (Removal of Global Fallback from Production Payment Matching)
and P0-3 (Payment-Block Selection Multi-Feature Scoring).
"""
import pytest

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


def make_test_vietqr(bin_code: str = "970407", account: str = "1903456789", name: str = "NGUYEN VAN A", amount: str = "150000"):
    """Tạo payload VietQR hợp lệ chuẩn EMVCo/VietQR."""
    beneficiary = _tlv("00", bin_code) + _tlv("01", account)
    tag38 = _tlv("00", "A000000727") + _tlv("01", beneficiary) + _tlv("02", "QRIBFTTA")
    body = _tlv("00", "01") + _tlv("01", "12") + _tlv("38", tag38) + _tlv("53", "704")
    if amount:
        body += _tlv("54", amount)
    body += _tlv("58", "VN")
    if name:
        body += _tlv("59", name)
    body += "6304"
    return parse_vietqr(body + _crc(body))


def test_p0_3_coherent_block_wins_over_nearer_unrelated_block():
    """
    P0-3: A slightly farther but semantically coherent payment block
    must win over a nearer unrelated header/ad block.
    """
    v_qr = make_test_vietqr()
    # Unrelated block is close to QR horizontally (dx=150, cy=200)
    # Coherent payment block is farther (cy=500, distance > 1.3)
    lines = [
        # Nearer unrelated block (distance to QR ~ 0.5)
        TextLine("Cảm ơn quý khách", cx=350, cy=180),
        TextLine("Hẹn gặp lại", cx=350, cy=210),

        # Farther coherent payment block (distance to QR ~ 1.5)
        TextLine("THÔNG TIN THANH TOÁN", cx=200, cy=460),
        TextLine("Techcombank", cx=200, cy=480),
        TextLine("STK: 1903456789", cx=200, cy=500),
        TextLine("Chủ TK: NGUYEN VAN A", cx=200, cy=520),
        TextLine("Tổng thanh toán: 150.000 đ", cx=200, cy=540),
    ]

    ctx = extract_context(lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    assert len(ctx.payment_blocks) >= 2

    # Selected primary block must be the coherent payment block (index 0)
    primary = ctx.payment_blocks[0]
    assert "Techcombank" in " ".join(primary["lines"])
    assert "1903456789" in primary["account_numbers"]

    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx, matching_mode="spatial")
    assert code == AlertCode.CONTEXT_CONSISTENT
    assert match.account_status == "match"
    assert match.bank_status == "match"
    assert match.name_status == "match"


def test_p0_2_no_fallback_when_bank_in_unrelated_block():
    """
    P0-2: QR near payment block A (no bank mentioned), same bank appears in unrelated block B far away.
    Production spatial mode must NOT match bank from unrelated block B.
    """
    v_qr = make_test_vietqr()
    lines = [
        # Primary block A: has account and name, but NO bank
        TextLine("STK: 1903456789", cx=200, cy=460),
        TextLine("Chủ TK: NGUYEN VAN A", cx=200, cy=480),

        # Unrelated block B: at top/bottom of invoice, mentions Techcombank as footer/partner
        TextLine("Đối tác Techcombank tài trợ", cx=200, cy=900),
    ]

    ctx = extract_context(lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx, matching_mode="spatial")

    # In spatial mode, bank must be "unknown" or "na" (not matched from block B)
    assert match.bank_status in ("unknown", "na")
    # Account matches within block A
    assert match.account_status == "match"


def test_p0_2_no_fallback_when_name_appears_elsewhere():
    """
    P0-2: Recipient name appears elsewhere on the page (in another block),
    not in the selected payment block. Must NOT match unrelated global name.
    """
    v_qr = make_test_vietqr()
    lines = [
        # Primary block: has bank and account, but NO name
        TextLine("Techcombank", cx=200, cy=460),
        TextLine("STK: 1903456789", cx=200, cy=480),

        # Remote block: contains the person's name as an auditor or author
        TextLine("Người lập phiếu: NGUYEN VAN A", cx=200, cy=950),
    ]

    ctx = extract_context(lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx, matching_mode="spatial")

    # Name in selected block is missing -> status="unknown" or "na"
    assert match.name_status in ("unknown", "na")

    # But bank and account in selected block match
    assert match.account_status == "match"
    assert match.bank_status == "match"


def test_p0_2_amount_equals_line_item_price_not_payable_total():
    """
    RQ2 (S2): QR amount equals a line-item price (50.000)
    but payable total is 150.000. Must detect MISMATCH, not match!
    """
    v_qr = make_test_vietqr(amount="50000")  # QR asks for 50k
    lines = [
        TextLine("HOÁ ĐƠN THANH TOÁN", cx=200, cy=400),
        TextLine("Techcombank STK: 1903456789", cx=200, cy=430),
        TextLine("Món 1: Cà phê sữa - Đơn giá: 50.000 đ", cx=200, cy=460),
        TextLine("Món 2: Bạc xỉu - Đơn giá: 100.000 đ", cx=200, cy=490),
        TextLine("Tổng thanh toán: 150.000 đ", cx=200, cy=520),
    ]

    ctx = extract_context(lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx, matching_mode="spatial")

    assert match.amount_status == "mismatch"
    assert code in (AlertCode.PARTIAL_MATCH, AlertCode.CRITICAL_MISMATCH)


def test_p0_2_multiple_banks_and_multiple_accounts():
    """
    Multiple banks and multiple accounts across blocks.
    Conflicting labeled accounts must yield conflict / partial match.
    """
    v_qr = make_test_vietqr()
    lines = [
        # Block 1
        TextLine("Techcombank STK: 1903456789", cx=200, cy=320),
        # Block 2 nearby with different bank & labeled account
        TextLine("Vietcombank STK: 001100223344", cx=200, cy=380),
    ]

    ctx = extract_context(lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx, matching_mode="spatial")

    # Because there are competing labeled accounts nearby, must be conflict
    assert match.account_status in ("conflict", "mismatch")
    assert code != AlertCode.CONTEXT_CONSISTENT


def test_p0_2_noisy_ocr_conservative_handling():
    """
    P0-2: Noisy OCR with garbled characters in account number.
    Should yield near match or insufficient context, NEVER false confident match.
    """
    v_qr = make_test_vietqr(account="1903456789")
    lines = [
        TextLine("Techcombank", cx=200, cy=320),
        TextLine("STK: 19O345678X", cx=200, cy=340),  # letter O instead of 0, letter X
    ]

    ctx = extract_context(lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx, matching_mode="spatial")

    assert match.account_status in ("near", "match", "mismatch")
    if match.account_status == "near":
        assert code == AlertCode.PARTIAL_MATCH


def test_standee_with_explicit_amount_matching():
    """Item 17: Non-invoice standee with explicit amount anchor must match VietQR amount."""
    v_qr = make_test_vietqr(amount="50000")
    lines = [
        TextLine("QUÉT MÃ THANH TOÁN", cx=200, cy=300),
        TextLine("Techcombank", cx=200, cy=330),
        TextLine("STK: 1903456789", cx=200, cy=360),
        TextLine("Chủ TK: NGUYEN VAN A", cx=200, cy=390),
        TextLine("Số tiền: 50.000 đ", cx=200, cy=420),
    ]

    ctx = extract_context(lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    # Even if context_type is not 'invoice', explicit anchor allows amount comparison
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx, matching_mode="spatial")

    assert match.amount_status == "match"
    assert match.account_status == "match"
    assert code == AlertCode.CONTEXT_CONSISTENT


def test_payment_instruction_fixed_amount():
    """Item 17: Payment instruction with fixed amount anchor must evaluate amount."""
    v_qr = make_test_vietqr(amount="100000")
    lines = [
        TextLine("HƯỚNG DẪN CHUYỂN KHOẢN", cx=200, cy=300),
        TextLine("Techcombank", cx=200, cy=330),
        TextLine("STK: 1903456789", cx=200, cy=360),
        TextLine("Chủ TK: NGUYEN VAN A", cx=200, cy=390),
        TextLine("Thanh toán: 100.000 VNĐ", cx=200, cy=420),
    ]

    ctx = extract_context(lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx, matching_mode="spatial")

    assert match.amount_status == "match"
    assert match.account_status == "match"
    assert code == AlertCode.CONTEXT_CONSISTENT


def test_standee_explicit_amount_mismatch():
    """Item 17: Standee with explicit amount that differs from QR amount must be detected as mismatch."""
    v_qr = make_test_vietqr(amount="200000")
    lines = [
        TextLine("QUÁN CÀ PHÊ ABC", cx=200, cy=300),
        TextLine("Techcombank STK: 1903456789", cx=200, cy=330),
        TextLine("Chủ TK: NGUYEN VAN A", cx=200, cy=360),
        TextLine("Số tiền: 50.000 đ", cx=200, cy=390),
    ]

    ctx = extract_context(lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx, matching_mode="spatial")

    assert match.amount_status == "mismatch"
    assert code in (AlertCode.PARTIAL_MATCH, AlertCode.CRITICAL_MISMATCH)


def test_standee_no_amount_label():
    """Item 17: Physical standee without amount label has amount_status='na'."""
    v_qr = make_test_vietqr(amount="50000")
    lines = [
        TextLine("QUÉT MÃ THANH TOÁN TẠI QUẦY", cx=200, cy=300),
        TextLine("Techcombank", cx=200, cy=330),
        TextLine("STK: 1903456789", cx=200, cy=360),
        TextLine("Chủ TK: NGUYEN VAN A", cx=200, cy=390),
    ]

    ctx = extract_context(lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx, matching_mode="spatial")

    assert match.amount_status == "na"
    assert match.account_status == "match"
    assert code == AlertCode.CONTEXT_CONSISTENT


def test_spatial_missing_account_returns_unknown_not_na():
    """Item 18: When no account candidate is in the selected block, status is 'unknown', NOT 'na'."""
    v_qr = make_test_vietqr()
    lines = [
        # Block with bank and name, but NO account candidate
        TextLine("Techcombank", cx=200, cy=300),
        TextLine("Chủ TK: NGUYEN VAN A", cx=200, cy=330),
    ]

    ctx = extract_context(lines, qr_bbox=(100, 100, 200, 200), source="ocr", target_vietqr=v_qr)
    match, code, *_ = fuzzy_match_and_alert(v_qr, ctx, matching_mode="spatial")

    assert match.account_status == "unknown"
    assert code in (AlertCode.PARTIAL_MATCH, AlertCode.INSUFFICIENT_CONTEXT)
    assert code != AlertCode.CONTEXT_CONSISTENT

