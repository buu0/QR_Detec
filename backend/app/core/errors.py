"""
Stable error catalog.

Every user-facing error has:
  1. a stable `error_code` (machine-readable, safe to show)
  2. an HTTP status (or event status)
  3. a short Vietnamese message
  4. a recommended user action
Technical details are written to server logs only — never returned to clients.
"""
from dataclasses import dataclass
from typing import Dict, Optional

from fastapi.responses import JSONResponse


@dataclass(frozen=True)
class ErrorSpec:
    code: str
    http_status: int
    message: str
    action: str


ERRORS: Dict[str, ErrorSpec] = {e.code: e for e in [
    ErrorSpec("FILE_TOO_LARGE", 413, "Tệp quá lớn.", "Hãy chọn ảnh hoặc PDF nhỏ hơn giới hạn cho phép."),
    ErrorSpec("UNSUPPORTED_FILE_TYPE", 415, "Định dạng tệp không được hỗ trợ.", "Hãy chọn ảnh JPG, PNG, WEBP hoặc tệp PDF."),
    ErrorSpec("EMPTY_FILE", 400, "Tệp rỗng hoặc bị hỏng.", "Hãy chụp lại hoặc chọn tệp khác."),
    ErrorSpec("INVALID_FILE", 422, "Không đọc được tệp này. Tệp có thể bị hỏng.", "Hãy chụp lại ảnh rõ hơn hoặc chọn tệp khác."),
    ErrorSpec("FILE_RESOURCE_LIMIT", 422, "Ảnh hoặc PDF vượt quá giới hạn xử lý an toàn.", "Hãy dùng ảnh có độ phân giải thấp hơn hoặc PDF ít trang hơn."),
    ErrorSpec("PDF_ENCRYPTED", 422, "PDF được đặt mật khẩu nên không thể kiểm tra.", "Hãy dùng bản PDF không đặt mật khẩu hoặc chụp ảnh mã QR."),
    ErrorSpec("NO_QR_FOUND", 200, "Không tìm thấy mã QR trong tệp.", "Hãy chụp gần hơn, đủ sáng và giữ mã QR nằm trọn trong khung."),
    ErrorSpec("CSRF_REJECTED", 403, "Yêu cầu không hợp lệ.", "Hãy tải lại trang rồi thử lại."),
    ErrorSpec("JOB_NOT_FOUND", 404, "Không tìm thấy phiên kiểm tra hoặc phiên đã hết hạn.", "Hãy kiểm tra lại mã QR từ đầu."),
    ErrorSpec("TOO_MANY_ACTIVE_JOBS", 429, "Bạn đang có quá nhiều lượt kiểm tra cùng lúc.", "Hãy đợi lượt kiểm tra hiện tại hoàn tất rồi thử lại."),
    ErrorSpec("TOO_MANY_STREAMS", 429, "Có quá nhiều kết nối đang mở.", "Hãy đóng bớt các tab đang kiểm tra rồi thử lại."),
    ErrorSpec("RATE_LIMITED", 429, "Bạn thao tác quá nhanh.", "Hãy đợi vài giây rồi thử lại."),
    ErrorSpec("SERVICE_UNAVAILABLE", 503, "Hệ thống đang bận hoặc tạm gián đoạn.", "Hãy thử lại sau ít phút."),
    ErrorSpec("PROCESSING_ERROR", 500, "Đã xảy ra lỗi khi kiểm tra tệp.", "Hãy thử lại. Nếu vẫn lỗi, đừng vội mở liên kết hoặc chuyển tiền."),
    ErrorSpec("JOB_TIMEOUT", 504, "Việc kiểm tra mất quá nhiều thời gian và đã dừng.", "Hãy thử lại với ảnh nhỏ hơn hoặc chụp riêng mã QR."),
    ErrorSpec("INTERNAL_ERROR", 500, "Đã xảy ra lỗi không mong muốn.", "Hãy thử lại sau."),
]}


def error_body(code: str, message: Optional[str] = None) -> dict:
    spec = ERRORS.get(code, ERRORS["INTERNAL_ERROR"])
    return {
        "error_code": spec.code,
        "message": message or spec.message,
        "recommended_action": spec.action,
        # Backward-compatible field used by older frontend builds
        "detail": message or spec.message,
    }


def error_response(code: str, headers: Optional[dict] = None, message: Optional[str] = None) -> JSONResponse:
    spec = ERRORS.get(code, ERRORS["INTERNAL_ERROR"])
    base_headers = {"Cache-Control": "no-store, private"}
    if headers:
        base_headers.update(headers)
    return JSONResponse(status_code=spec.http_status, content=error_body(code, message), headers=base_headers)


class AppError(Exception):
    """Raised inside request handlers; converted into a safe JSON error response."""

    def __init__(self, code: str, headers: Optional[dict] = None):
        super().__init__(code)
        self.code = code
        self.headers = headers or {}
