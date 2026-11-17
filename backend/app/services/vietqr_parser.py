"""
VietQR TLV Parser & CRC-16 Validator
EMVCo / NAPAS Standard - Strict Tag-Length-Value parser and semantic validator
Note: CRC-16 validates message integrity during transmission; it does NOT constitute authenticity verification.
"""
import re
import logging
from typing import Dict, List, Tuple

from app.models.schemas import VietQRData, PayloadType
from app.services.bank_registry import (
    BANK_BIN_MAP,
    bank_id_from_bin,
    bank_display_name,
)

logger = logging.getLogger(__name__)

NAPAS_GUID = "A000000727"
SERVICE_CODES = {
    "QRIBFTTA": "Chuyển khoản tới tài khoản",
    "QRIBFTTC": "Chuyển khoản tới thẻ",
}
_AMOUNT_RE = re.compile(r"^\d{1,13}(\.\d{1,2})?$")
_NON_HTTP_URI_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
_COMMON_DOMAIN_RE = re.compile(
    r"^(?:https?://|www\.|[a-zA-Z0-9-]+\.[a-zA-Z]{2,24}(?:[:/?#]|$))",
    re.IGNORECASE,
)

__all__ = [
    "BANK_BIN_MAP", "NAPAS_GUID", "SERVICE_CODES",
    "classify_payload", "parse_emvco_tlv", "parse_tlv_strict",
    "verify_crc16", "parse_vietqr",
]


def _is_vietqr_candidate(p: str) -> bool:
    r"""
    Phát hiện ứng viên payload VietQR / EMVCo MPM:
    1. Bắt đầu bằng '000201' (canonical EMVCo indicator)
    2. Chứa Tag 38 với NAPAS GUID (A000000727 hoặc sub-tag 0010A000000727)
    3. Bắt đầu bằng '00' + 2 số độ dài (e.g. ^00\d{2}) VÀ có đặc trưng cấu trúc EMVCo
       (chứa NAPAS GUID, hoặc kết thúc bằng mã kiểm tra 6304 / CRC trailer,
       hoặc trường TLV kế tiếp hợp lệ thuộc các tag chuẩn EMVCo).
    4. Cấu trúc TLV dạng EMVCo có kết thúc bằng trailer CRC-16 (6304XXXX) với tag EMVCo.
    """
    if not p or len(p) < 6:
        return False

    # 1. Canonical EMVCo indicator
    if p.startswith("000201"):
        return True

    # 2. Chứa NAPAS GUID (chuẩn nhận diện chuyển tiền liên ngân hàng NAPAS)
    if NAPAS_GUID in p or "0010A000000727" in p:
        return True

    # 3. Bắt đầu bằng Tag 00 ('00' + 2 chữ số độ dài) kèm bằng chứng EMVCo
    if re.match(r"^00\d{2}", p):
        # Có trailer CRC EMVCo hoặc kết thúc bằng 6304
        if re.search(r"6304[0-9A-Fa-f]{4}$", p) or p.endswith("6304"):
            return True
        # Hoặc bóc tách TLV đầu tiên: trường kế tiếp phải là tag EMVCo hợp lệ
        try:
            tlv_len = int(p[2:4])
            if len(p) >= 4 + tlv_len + 4:
                next_tag = p[4 + tlv_len : 4 + tlv_len + 2]
                next_len = p[4 + tlv_len + 2 : 4 + tlv_len + 4]
                if next_tag.isdigit() and next_len.isdigit() and next_tag in (
                    "01", "38", "53", "54", "58", "59", "62", "63"
                ):
                    return True
        except (ValueError, IndexError):
            pass

    # 4. Có trailer CRC EMVCo (6304XXXX) và bắt đầu bằng tag số chuẩn EMVCo
    if re.search(r"6304[0-9A-Fa-f]{4}$", p):
        if len(p) >= 12 and p[:2].isdigit() and p[2:4].isdigit():
            known_emv_tags = {"00", "01", "38", "53", "54", "58", "59", "60", "62", "63"}
            if p[:2] in known_emv_tags:
                return True

    return False


def classify_payload(payload: str) -> PayloadType:
    """
    Phân loại payload QR:
    - VIETQR: bất kỳ payload nào có hình thức EMVCo/VietQR candidate.
              parse_vietqr() sẽ quyết định tính hợp lệ cấu trúc và NAPAS GUID.
    - URL: liên kết web chuẩn HTTP/HTTPS hoặc dạng tên miền (www..., example.com...).
    - URI: các lược đồ URI khác (javascript, data, file, intent, mailto, tel, sms...).
    - OTHER: văn bản thuần, WIFI, vCard, plain text...
    """
    p = payload.strip()

    # Nhánh 1: VietQR candidate (EMVCo payload indicator hoặc cấu trúc VietQR)
    if _is_vietqr_candidate(p):
        return PayloadType.VIETQR

    # Nhánh 2: Web URL (có http/https hoặc bắt đầu bằng www. hoặc tên miền web phổ biến)
    if re.match(r"^https?://", p, re.IGNORECASE):
        return PayloadType.URL

    first_segment = p.split("/")[0].split("?")[0].split("#")[0]
    if not any(c.isspace() for c in first_segment) and _COMMON_DOMAIN_RE.match(p):
        return PayloadType.URL

    # Nhánh 3: Other URI schemes
    if _NON_HTTP_URI_RE.match(p):
        return PayloadType.URI

    # Nhánh 4: Khác (WIFI, vCard, plain text...)
    return PayloadType.OTHER


def parse_tlv_strict(payload: str) -> Tuple[Dict[str, str], List[str]]:
    """
    Bóc tách TLV và phát hiện các lỗi cấu trúc:
    Tuân thủ chuẩn EMVCo MPM: Độ dài trường Length là số lượng BYTE (octets),
    không phải số ký tự Unicode, giúp xử lý chính xác chuỗi UTF-8 có dấu tiếng Việt.
    - Tag không đủ 2 số, length không đủ 2 số
    - Chiều dài khai báo vượt quá phần còn lại của payload
    - Byte dư thừa ở cuối không tạo thành trường TLV
    - Phát hiện trường trùng lặp (duplicate tags) thay vì ghi đè âm thầm
    """
    data: Dict[str, str] = {}
    errors: List[str] = []
    seen_tags: set = set()

    if not payload:
        return data, errors

    raw_bytes = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
    idx, n = 0, len(raw_bytes)

    while idx < n:
        if idx + 4 > n:
            errors.append(f"Dư {n - idx} ký tự cuối không thành trường TLV")
            break
        try:
            tag = raw_bytes[idx: idx + 2].decode("ascii")
            length_str = raw_bytes[idx + 2: idx + 4].decode("ascii")
        except UnicodeDecodeError:
            errors.append(f"Tag/độ dài không hợp lệ tại vị trí {idx}")
            break

        if not (tag.isdigit() and length_str.isdigit()):
            chunk = raw_bytes[idx: min(n, idx + 4)].decode("ascii", errors="replace")
            errors.append(f"Tag/độ dài không hợp lệ tại vị trí {idx}: '{chunk}'")
            break

        length = int(length_str)
        end = idx + 4 + length
        if end > n:
            errors.append(f"Trường {tag} bị cắt cụt (khai báo {length}, còn {n - idx - 4} ký tự)")
            break

        if tag in seen_tags:
            errors.append(f"Phát hiện trường TLV trùng lặp: Tag {tag}")

        seen_tags.add(tag)
        val_bytes = raw_bytes[idx + 4: end]
        data[tag] = val_bytes.decode("utf-8", errors="replace")
        idx = end

    return data, errors


def parse_emvco_tlv(payload: str) -> dict:
    """Giữ tương thích: chỉ trả dict"""
    return parse_tlv_strict(payload)[0]


def verify_crc16(payload: str) -> bool:
    """
    Kiểm tra CRC-16/CCITT-FALSE (Kiểm tra tính toàn vẹn dữ liệu truyền nhận).
    Polynomial: 0x1021, Init: 0xFFFF, No reflection.
    Dữ liệu: toàn bộ payload ngoại trừ 4 ký tự cuối (giá trị CRC).
    """
    if len(payload) < 8 or payload[-8:-4] != "6304":
        return False

    data_bytes = payload[:-4].encode("utf-8")
    expected_crc = payload[-4:].upper()

    crc = 0xFFFF
    for byte in data_bytes:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF

    return f"{crc:04X}" == expected_crc


def parse_vietqr(payload: str) -> VietQRData:
    """
    Phân tích toàn diện payload VietQR:
    1. Kiểm tra tính toàn vẹn CRC-16
    2. Bóc tách TLV cấp 1 + kiểm tra lỗi cấu trúc & trùng lặp
    3. Bóc tách Tag 38 (Merchant Account Info) lồng nhau + kiểm tra NAPAS GUID
    4. Kiểm tra mã dịch vụ (Service Code 38.02)
    5. Kiểm tra các trường ngữ nghĩa: tiền tệ (53), quốc gia (58), BIN 6 số, số tài khoản
    6. Lan truyền toàn bộ lỗi cấu trúc (bao gồm Tag 62)
    """
    payload = payload.strip()
    result = VietQRData()
    errors: List[str] = []

    result.crc_valid = verify_crc16(payload)
    if not result.crc_valid:
        logger.warning("VietQR CRC-16 integrity validation failed")

    tlv, top_errors = parse_tlv_strict(payload)
    errors.extend(top_errors)

    # Tag 00: Payload Format Indicator (bắt buộc = "01")
    if tlv.get("00") != "01":
        errors.append("Thiếu hoặc sai Tag 00 (Payload Format Indicator phải là '01')")

    # Tag 01: Point of Initiation Method ("11": tĩnh, "12": động)
    if "01" in tlv and tlv["01"] not in ("11", "12"):
        errors.append(f"Tag 01 (Point of Initiation Method) không hợp lệ: '{tlv['01']}'")

    # Tag 53: Transaction Currency (704 = VND) — mandatory in EMVCo MPM / VietQR
    if "53" not in tlv:
        errors.append("Thiếu Tag 53 (Mã tiền tệ, yêu cầu 704 cho VND)")
    elif tlv["53"] != "704":
        errors.append(f"Tag 53 (Mã tiền tệ) không hợp lệ: '{tlv['53']}' (yêu cầu 704 cho VND)")

    # Tag 54: Transaction Amount
    if "54" in tlv:
        amount = tlv["54"].strip()
        if _AMOUNT_RE.match(amount):
            try:
                amt_val = float(amount)
                if amt_val <= 0:
                    errors.append(f"Số tiền (Tag 54) phải lớn hơn 0: '{amount}'")
                elif amt_val != int(amt_val):
                    # VND has no minor unit: '10000.50' is not a valid VietQR amount.
                    errors.append(f"Số tiền (Tag 54) không được có phần lẻ thập phân với VND: '{amount}'")
                else:
                    # '10000.00' is normalised to '10000' so amount comparisons stay exact.
                    result.amount = amount.split(".")[0]
            except ValueError:
                errors.append(f"Số tiền (Tag 54) không hợp lệ: '{amount}'")
        else:
            errors.append(f"Số tiền (Tag 54) không đúng định dạng số: '{amount}'")

    # Tag 58: Country Code (VN) — mandatory in EMVCo MPM / VietQR
    if "58" not in tlv:
        errors.append("Thiếu Tag 58 (Mã quốc gia, yêu cầu 'VN')")
    elif tlv["58"].upper() != "VN":
        errors.append(f"Tag 58 (Mã quốc gia) không hợp lệ: '{tlv['58']}' (yêu cầu 'VN')")

    # Tag 59: Merchant Name / Account Name
    if tlv.get("59", "").strip():
        result.account_name = tlv["59"].strip()

    # Tag 62: Additional Data Field Template (nội dung chuyển khoản ở sub-tag 08)
    if "62" in tlv:
        sub62, sub62_errors = parse_tlv_strict(tlv["62"])
        errors.extend(f"Tag 62: {e}" for e in sub62_errors)
        if "08" in sub62:
            result.description = sub62["08"]

    # Tag 38: Merchant Account Information (NAPAS)
    if "38" not in tlv:
        errors.append("Thiếu Tag 38 (thông tin tài khoản NAPAS)")
    else:
        sub38, sub_errors = parse_tlv_strict(tlv["38"])
        errors.extend(f"Tag 38: {e}" for e in sub_errors)

        # NAPAS GUID check
        guid_val = sub38.get("00", "")
        # Exact match: a substring check accepted values such as 'XXA000000727YY'.
        if guid_val.strip().upper() != NAPAS_GUID:
            errors.append(f"Tag 38: Sai hoặc thiếu NAPAS GUID (khai báo: '{guid_val}', yêu cầu: '{NAPAS_GUID}')")

        # Service Code check
        service_code = sub38.get("02")
        if service_code:
            result.service_code = service_code
            if service_code not in SERVICE_CODES:
                errors.append(f"Tag 38.02: Mã dịch vụ không hợp lệ hoặc không được hỗ trợ: '{service_code}'")

        if "01" in sub38:
            beneficiary, ben_errors = parse_tlv_strict(sub38["01"])
            errors.extend(f"Tag 38.01: {e}" for e in ben_errors)

            if "00" in beneficiary:
                result.bank_bin = beneficiary["00"].strip()
                # Validate BIN format (6 digits)
                if not (len(result.bank_bin) == 6 and result.bank_bin.isdigit()):
                    errors.append(f"Tag 38.01.00: BIN ngân hàng không đúng định dạng 6 chữ số: '{result.bank_bin}'")
                else:
                    result.bank_id = bank_id_from_bin(result.bank_bin)
                    result.bank_name = bank_display_name(result.bank_id) or f"Ngân hàng chưa đăng ký (BIN {result.bank_bin})"
                    if not result.bank_id:
                        logger.warning(f"Unknown bank BIN in registry: {result.bank_bin}")

            if "01" in beneficiary:
                acc_val = beneficiary["01"].strip()
                # Validate account number format (3-35 alphanumeric chars)
                if not (3 <= len(acc_val) <= 35 and re.match(r"^[A-Za-z0-9_-]+$", acc_val)):
                    errors.append(f"Tag 38.01.01: Số tài khoản/thẻ không hợp lệ: '{acc_val}'")
                else:
                    result.account_number = acc_val

        if not result.account_number:
            errors.append("Không tìm thấy số tài khoản người nhận (Tag 38.01.01)")

    result.structure_errors = errors
    result.structure_valid = len(errors) == 0
    return result

