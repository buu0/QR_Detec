"""
Unit tests for VietQR Security & Strict TLV Validation
"""
from app.models.schemas import PayloadType
from app.services.vietqr_parser import (
    classify_payload,
    parse_vietqr,
    parse_tlv_strict,
)


def _tlv(tag: str, val: str) -> str:
    return f"{tag}{len(val):02d}{val}"


def _crc(data: str) -> str:
    crc = 0xFFFF
    for b in data.encode("utf-8"):
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return f"{crc:04X}"


def make_valid_vietqr(bin_code="970436", account="0123456789", amount="50000"):
    beneficiary = _tlv("00", bin_code) + _tlv("01", account)
    tag38 = _tlv("00", "A000000727") + _tlv("01", beneficiary) + _tlv("02", "QRIBFTTA")
    body = (
        _tlv("00", "01")
        + _tlv("01", "12")
        + _tlv("38", tag38)
        + _tlv("53", "704")
        + _tlv("54", amount)
        + _tlv("58", "VN")
        + _tlv("62", _tlv("08", "Thanh toan tien nuoc"))
        + "6304"
    )
    return body + _crc(body)


def test_classify_candidate_even_with_wrong_guid():
    """
    Critical fix:
    Payload starting with 000201 MUST be classified as VIETQR candidate,
    even if NAPAS GUID is missing/tampered, so it undergoes strict parser validation.
    """
    fake_emv = "00020101021138200010MALICIOUS010697043663041234"
    assert classify_payload(fake_emv) == PayloadType.VIETQR

    # Parse must flag error
    parsed = parse_vietqr(fake_emv)
    assert not parsed.structure_valid
    assert any("NAPAS GUID" in err for err in parsed.structure_errors)


def test_duplicate_tlv_detected():
    """
    Duplicate TLV tag must produce structure error, not silent overwrite.
    """
    payload = "000201" + _tlv("54", "10000") + _tlv("54", "999999999")
    data, errors = parse_tlv_strict(payload)
    assert any("trùng lặp" in e.lower() or "tag 54" in e.lower() for e in errors)


def test_wrong_napas_guid_fails_structure():
    beneficiary = _tlv("00", "970436") + _tlv("01", "0123456789")
    # Tampered GUID: B999999999 instead of A000000727
    tag38 = _tlv("00", "B999999999") + _tlv("01", beneficiary) + _tlv("02", "QRIBFTTA")
    body = _tlv("00", "01") + _tlv("01", "11") + _tlv("38", tag38) + _tlv("53", "704") + _tlv("58", "VN") + "6304"
    qr = body + _crc(body)

    v = parse_vietqr(qr)
    assert not v.structure_valid
    assert any("NAPAS GUID" in e for e in v.structure_errors)


def test_unsupported_service_code_fails():
    beneficiary = _tlv("00", "970436") + _tlv("01", "0123456789")
    # Unsupported service code: INVALID_CODE
    tag38 = _tlv("00", "A000000727") + _tlv("01", beneficiary) + _tlv("02", "INVALID_CODE")
    body = _tlv("00", "01") + _tlv("01", "11") + _tlv("38", tag38) + _tlv("53", "704") + _tlv("58", "VN") + "6304"
    qr = body + _crc(body)

    v = parse_vietqr(qr)
    assert not v.structure_valid
    assert any("Mã dịch vụ" in e for e in v.structure_errors)


def test_tag62_malformed_errors_propagated():
    beneficiary = _tlv("00", "970436") + _tlv("01", "0123456789")
    tag38 = _tlv("00", "A000000727") + _tlv("01", beneficiary) + _tlv("02", "QRIBFTTA")
    # Tag 62 with truncated sub-tag length
    malformed_sub62 = "0899truncated"
    body = (
        _tlv("00", "01")
        + _tlv("01", "11")
        + _tlv("38", tag38)
        + _tlv("53", "704")
        + _tlv("58", "VN")
        + _tlv("62", malformed_sub62)
        + "6304"
    )
    qr = body + _crc(body)

    v = parse_vietqr(qr)
    assert not v.structure_valid
    assert any("Tag 62" in e for e in v.structure_errors)


def test_invalid_currency_fails():
    qr = make_valid_vietqr()
    # Replace 5303704 with 5303840 (USD)
    bad_currency_qr = qr.replace("5303704", "5303840")
    # recalculate crc
    body = bad_currency_qr[:-4]
    new_qr = body + _crc(body)

    v = parse_vietqr(new_qr)
    assert not v.structure_valid
    assert any("53" in e for e in v.structure_errors)


def test_unknown_bank_bin_warns_but_not_structurally_invalid():
    """
    Unregistered bank BIN (e.g. 999999) must not be treated as structural corruption.
    It should parse successfully while exposing unregistered bank name.
    """
    beneficiary = _tlv("00", "999999") + _tlv("01", "0123456789")
    tag38 = _tlv("00", "A000000727") + _tlv("01", beneficiary) + _tlv("02", "QRIBFTTA")
    body = _tlv("00", "01") + _tlv("01", "11") + _tlv("38", tag38) + _tlv("53", "704") + _tlv("58", "VN") + "6304"
    qr = body + _crc(body)

    v = parse_vietqr(qr)
    assert v.structure_valid
    assert v.bank_bin == "999999"
    assert "chưa đăng ký" in v.bank_name


def test_classify_payload_urls():
    assert classify_payload("https://google.com") == PayloadType.URL
    assert classify_payload("http://sub.domain.vn/path?q=1") == PayloadType.URL
    assert classify_payload("www.facebook.com") == PayloadType.URL
    assert classify_payload("shopee.vn/product/123") == PayloadType.URL
    assert classify_payload("bit.ly/malicious-link") == PayloadType.URL
    assert classify_payload("plain text note without domain") == PayloadType.OTHER
    assert classify_payload("javascript:alert(1)") == PayloadType.URI


def test_vietnamese_utf8_multibyte_tlv():
    """
    EMVCo length is defined in octets/bytes.
    Vietnamese characters like 'Ủng hộ' have more bytes than characters.
    The strict TLV parser must not corrupt subsequent tag offsets.
    """
    desc = "Ủng hộ đồng bào miền Trung"
    desc_bytes = desc.encode("utf-8")
    sub62 = f"08{len(desc_bytes):02d}{desc}"
    sub62_bytes = sub62.encode("utf-8")

    beneficiary = _tlv("00", "970436") + _tlv("01", "0123456789")
    tag38 = _tlv("00", "A000000727") + _tlv("01", beneficiary) + _tlv("02", "QRIBFTTA")
    body = (
        _tlv("00", "01")
        + _tlv("01", "12")
        + _tlv("38", tag38)
        + _tlv("53", "704")
        + _tlv("54", "100000")
        + _tlv("58", "VN")
        + f"62{len(sub62_bytes):02d}{sub62}"
        + "6304"
    )
    qr = body + _crc(body)
    v = parse_vietqr(qr)
    assert v.structure_valid, f"Structure errors: {v.structure_errors}"
    assert v.crc_valid
    assert v.description == desc
    assert v.amount == "100000"
    assert v.account_number == "0123456789"


def test_candidate_wrong_tag_00_value():
    """Tag 00 has wrong value ('99' instead of '01') -> candidate VIETQR, fails structure."""
    beneficiary = _tlv("00", "970436") + _tlv("01", "0123456789")
    tag38 = _tlv("00", "A000000727") + _tlv("01", beneficiary) + _tlv("02", "QRIBFTTA")
    body = (
        _tlv("00", "99")  # Invalid format indicator
        + _tlv("01", "12")
        + _tlv("38", tag38)
        + _tlv("53", "704")
        + _tlv("58", "VN")
        + "6304"
    )
    qr = body + _crc(body)
    assert classify_payload(qr) == PayloadType.VIETQR
    parsed = parse_vietqr(qr)
    assert not parsed.structure_valid
    assert any("Tag 00" in e for e in parsed.structure_errors)


def test_candidate_missing_tag_00():
    """Missing Tag 00 entirely -> candidate VIETQR via Tag 38 / NAPAS GUID, fails structure."""
    beneficiary = _tlv("00", "970436") + _tlv("01", "0123456789")
    tag38 = _tlv("00", "A000000727") + _tlv("01", beneficiary) + _tlv("02", "QRIBFTTA")
    body = (
        _tlv("01", "12")  # Missing Tag 00
        + _tlv("38", tag38)
        + _tlv("53", "704")
        + _tlv("58", "VN")
        + "6304"
    )
    qr = body + _crc(body)
    assert classify_payload(qr) == PayloadType.VIETQR
    parsed = parse_vietqr(qr)
    assert not parsed.structure_valid
    assert any("Tag 00" in e for e in parsed.structure_errors)


def test_candidate_duplicate_tag_00():
    """Duplicate Tag 00 -> candidate VIETQR, fails structure."""
    beneficiary = _tlv("00", "970436") + _tlv("01", "0123456789")
    tag38 = _tlv("00", "A000000727") + _tlv("01", beneficiary) + _tlv("02", "QRIBFTTA")
    body = (
        _tlv("00", "01")
        + _tlv("00", "01")  # Duplicate Tag 00
        + _tlv("01", "12")
        + _tlv("38", tag38)
        + _tlv("53", "704")
        + _tlv("58", "VN")
        + "6304"
    )
    qr = body + _crc(body)
    assert classify_payload(qr) == PayloadType.VIETQR
    parsed = parse_vietqr(qr)
    assert not parsed.structure_valid
    assert any("trùng lặp" in e.lower() and "00" in e for e in parsed.structure_errors)


def test_candidate_bad_crc():
    """Valid VietQR with corrupted CRC -> candidate VIETQR, crc_valid=False."""
    valid_qr = make_valid_vietqr()
    corrupted_qr = valid_qr[:-4] + "0000"
    assert classify_payload(corrupted_qr) == PayloadType.VIETQR
    parsed = parse_vietqr(corrupted_qr)
    assert not parsed.crc_valid


def test_candidate_malformed_tag38_truncated():
    """Malformed Tag 38 with truncated subfield -> candidate VIETQR, fails structure."""
    body = (
        _tlv("00", "01")
        + _tlv("01", "12")
        + "38250010A0000007270199trunc"  # Truncated subfield
        + _tlv("53", "704")
        + _tlv("58", "VN")
        + "6304"
    )
    qr = body + _crc(body)
    assert classify_payload(qr) == PayloadType.VIETQR
    parsed = parse_vietqr(qr)
    assert not parsed.structure_valid
    assert any("Tag 38" in e for e in parsed.structure_errors)


def test_arbitrary_numeric_strings_remain_other():
    """Arbitrary numbers, phone numbers, or accounts starting with 00 must remain OTHER."""
    assert classify_payload("1234567890") == PayloadType.OTHER
    assert classify_payload("0987654321") == PayloadType.OTHER
    assert classify_payload("001234567890") == PayloadType.OTHER
    assert classify_payload("00998877") == PayloadType.OTHER
    assert classify_payload("8938500012345") == PayloadType.OTHER
    assert classify_payload("0012384567890") == PayloadType.OTHER


# ─── Strict EMVCo/VietQR Semantic Field Validation (RQ2 / A2) ───────────────

import pytest
from app.models.schemas import AlertCode
from app.services.context_extractor import TextLine, extract_context, ocr_numeric_tokens
from app.services.fuzzy_matcher import fuzzy_match_and_alert


def _build_custom_vietqr(guid="A000000727", currency="704", country="VN", amount="50000"):
    beneficiary = _tlv("00", "970436") + _tlv("01", "0123456789")
    tag38 = _tlv("00", guid) + _tlv("01", beneficiary) + _tlv("02", "QRIBFTTA")
    body = _tlv("00", "01") + _tlv("01", "12") + _tlv("38", tag38)
    if currency is not None:
        body += _tlv("53", currency)
    if amount is not None:
        body += _tlv("54", amount)
    if country is not None:
        body += _tlv("58", country)
    body += "6304"
    return body + _crc(body)


def test_valid_vietqr_still_valid():
    v = parse_vietqr(make_valid_vietqr())
    assert v.structure_valid and v.crc_valid
    assert v.amount == "50000"


@pytest.mark.parametrize("guid", ["XXA000000727YY", "A000000727EXTRA", "A0000007270"])
def test_napas_guid_must_match_exactly(guid):
    v = parse_vietqr(_build_custom_vietqr(guid=guid))
    assert not v.structure_valid
    assert any("NAPAS GUID" in e for e in v.structure_errors)


def test_missing_currency_tag_is_invalid():
    v = parse_vietqr(_build_custom_vietqr(currency=None))
    assert not v.structure_valid
    assert any("Tag 53" in e for e in v.structure_errors)


def test_missing_country_tag_is_invalid():
    v = parse_vietqr(_build_custom_vietqr(country=None))
    assert not v.structure_valid
    assert any("Tag 58" in e for e in v.structure_errors)


@pytest.mark.parametrize("amount", ["10000.5", "10000.50", "0.99"])
def test_fractional_vnd_amount_rejected(amount):
    v = parse_vietqr(_build_custom_vietqr(amount=amount))
    assert not v.structure_valid
    assert v.amount is None


@pytest.mark.parametrize("amount,expected", [("10000.00", "10000"), ("10000.0", "10000"), ("10000", "10000")])
def test_whole_vnd_amount_normalised(amount, expected):
    v = parse_vietqr(_build_custom_vietqr(amount=amount))
    assert v.structure_valid
    assert v.amount == expected


# ─── Token-Scoped OCR Confusable Repair (RQ2 & RQ3: S5, S6, S7) ───

def _alert_for_ocr_line(qr_acc, line_text, mode="spatial"):
    v = parse_vietqr(make_valid_vietqr(bin_code="970436", account=qr_acc))
    lines = [
        TextLine(line_text, cx=100, cy=170, w=200, h=20),
        TextLine("Vietcombank", cx=100, cy=195, w=200, h=20),
    ]
    ctx = extract_context(lines, qr_bbox=(50, 50, 100, 100), source="ocr", target_vietqr=v)
    match, code, *_ = fuzzy_match_and_alert(v, ctx, matching_mode=mode)
    return code, match.account_status


@pytest.mark.parametrize("text,expected", [
    ("STK: O123456789", ["0123456789"]),
    ("So TK: 0l23 456 789", ["0123456789"]),
    ("STK: 0123456789", ["0123456789"]),
])
def test_ocr_numeric_tokens_repairs_only_numeric_tokens(text, expected):
    assert ocr_numeric_tokens(text) == expected


@pytest.mark.parametrize("text", ["SOS BLOG", "Ngan hang Sacombank", "Hotline: ZaloOA"])
def test_words_are_not_turned_into_numbers(text):
    assert ocr_numeric_tokens(text) == []


@pytest.mark.parametrize("mode", ["spatial", "global"])
def test_s5_leading_confusable_is_consistent(mode):
    code, status = _alert_for_ocr_line("0123456789", "STK: O123456789", mode)
    assert code == AlertCode.CONTEXT_CONSISTENT and status == "match"


def test_s6_confusable_attacker_account_is_still_a_mismatch():
    code, status = _alert_for_ocr_line("0123456789", "STK: O987654321")
    assert code == AlertCode.CRITICAL_MISMATCH and status == "mismatch"


def test_s7_single_digit_spoof_is_not_auto_repaired():
    code, status = _alert_for_ocr_line("0123456789", "STK: 0123456788")
    assert code == AlertCode.PARTIAL_MATCH and status in ("near", "conflict")
