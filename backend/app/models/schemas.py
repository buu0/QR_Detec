"""
Pydantic data models for API requests/responses, payment reconciliation, and multi-layer URL security
"""
from enum import Enum
from typing import Optional, List, Any, Dict, Tuple
from pydantic import BaseModel, Field, model_validator


class PayloadType(str, Enum):
    VIETQR = "vietqr"
    URL = "url"
    URI = "uri"
    OTHER = "other"
    UNKNOWN = "unknown"


class SecurityVerdict(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    NO_KNOWN_RISK = "NO_KNOWN_RISK"
    INVALID = "INVALID"
    UNVERIFIABLE = "UNVERIFIABLE"


class AlertCode(str, Enum):
    # Payment / Context reconciliation alerts
    CONTEXT_CONSISTENT = "CONTEXT_CONSISTENT"
    CRITICAL_MISMATCH = "CRITICAL_MISMATCH"
    PARTIAL_MATCH = "PARTIAL_MATCH"
    INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"
    INVALID_PAYLOAD = "INVALID_PAYLOAD"

    # URL Security alerts
    URL_MALICIOUS = "URL_MALICIOUS"
    URL_SUSPICIOUS = "URL_SUSPICIOUS"
    URL_NO_KNOWN_RISK = "URL_NO_KNOWN_RISK"
    URL_UNVERIFIABLE = "URL_UNVERIFIABLE"
    UNSUPPORTED_URI = "UNSUPPORTED_URI"

    # General / Resource alerts
    OTHER_PAYLOAD = "OTHER_PAYLOAD"
    FILE_RESOURCE_LIMIT = "FILE_RESOURCE_LIMIT"


class JobStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ==========================================
# Risk presentation level (backend-owned)
# ==========================================
# The frontend maps ONLY these values to user-facing copy; it never derives risk itself.
#   danger         -> "Nguy hiểm"
#   warning        -> "Có dấu hiệu đáng ngờ"
#   no_known_risk  -> "Chưa phát hiện dấu hiệu nguy hiểm đã biết" (never "safe")
#   unverifiable   -> "Chưa thể kiểm tra đầy đủ"
#   info           -> informational payload (text, contact URI)
#   pending        -> analysis still running
RISK_LEVELS = ("danger", "warning", "no_known_risk", "unverifiable", "info", "pending")

_ALERT_TO_RISK = {
    "URL_MALICIOUS": "danger",
    "CRITICAL_MISMATCH": "danger",
    "URL_SUSPICIOUS": "warning",
    "PARTIAL_MATCH": "warning",
    "URL_NO_KNOWN_RISK": "no_known_risk",
    "CONTEXT_CONSISTENT": "no_known_risk",
    "URL_UNVERIFIABLE": "unverifiable",
    "INVALID_PAYLOAD": "unverifiable",
    "INSUFFICIENT_CONTEXT": "unverifiable",
    "FILE_RESOURCE_LIMIT": "unverifiable",
    "UNSUPPORTED_URI": "info",
    "OTHER_PAYLOAD": "info",
}


def risk_level_for_alert(alert_code: Any) -> str:
    value = alert_code.value if hasattr(alert_code, "value") else str(alert_code)
    return _ALERT_TO_RISK.get(value, "unverifiable")


# ==========================================
# URL Security Evidence & Analysis Models
# ==========================================

class URLSHAPContribution(BaseModel):
    feature: str
    label: str
    value: float
    shap_value: float
    direction: str  # "risk" | "benign"


class URLModelEvidence(BaseModel):
    # NOT_CONFIGURED | LOADING | READY | INCOMPATIBLE_FEATURE_SCHEMA | INVALID_ARTIFACT | INFERENCE_ERROR | NOT_APPLICABLE
    model_status: str = "NOT_CONFIGURED"
    model_score: Optional[float] = None   # None means "not measured", never "risk 0"
    model_id: Optional[str] = None
    n_features: Optional[int] = None
    reason: Optional[str] = None
    # Pure-ML detail. model_score above is the CALIBRATED probability.
    raw_score: Optional[float] = None       # uncalibrated XGBoost probability
    ml_threshold: Optional[float] = None    # operating threshold shipped with the bundle
    ml_prediction: Optional[int] = None     # 1 if calibrated >= threshold (pure ML, not a verdict)
    # Exact TreeSHAP attributions (log-odds space) for local explainability
    shap_base_value: Optional[float] = None
    shap_top_risk: List[URLSHAPContribution] = Field(default_factory=list)
    shap_top_benign: List[URLSHAPContribution] = Field(default_factory=list)


class ThreatIntelEvidence(BaseModel):
    status: str = "unknown"  # known_malicious | suspicious | no_known_risk | unknown
    # Typed Local TI state: MATCH | NO_MATCH | NOT_CONFIGURED | INTEGRITY_FAILED | LOAD_ERROR | NOT_APPLICABLE
    local_ti_status: str = "NOT_CONFIGURED"
    confidence: float = 0.0
    sources: List[str] = Field(default_factory=list)
    malicious_count: int = 0
    suspicious_count: int = 0
    last_checked: Optional[str] = None
    details: Optional[str] = None
    scope: Optional[str] = None  # url | domain | ioc | ioc_embedded
    # Per-source provenance: [{source, indicator, verdict, first_seen, last_seen, expires_at, confidence, stale}]
    provenance: List[Dict[str, Any]] = Field(default_factory=list)
    freshness: Optional[str] = None  # fresh | stale | unknown | None
    distinct_sources: int = 0        # independent sources (duplicates of one feed counted once)


class URLAnalysis(BaseModel):
    original_url: str
    normalized_url: str
    host: str
    scheme: str
    is_provisional: bool = False  # Always False: URL analysis is single-phase
    verdict: SecurityVerdict
    severity: str = "low"  # low | medium | high | critical
    reason_codes: List[str] = Field(default_factory=list)
    model: URLModelEvidence = Field(default_factory=URLModelEvidence)
    threat_intel: ThreatIntelEvidence = Field(default_factory=ThreatIntelEvidence)
    analysis_version: str = "1.0.0"
    policy_version: str = "1.0.0"
    # Which checks actually ran: ml_sensor | local_ioc
    checks_performed: Dict[str, str] = Field(default_factory=dict)
    analysis_completeness: str = "full"  # full | partial
    # Absolute URLs found inside path/query (open-redirect wrappers). Checked against local IOC
    # only; they are never fetched.
    embedded_urls: List[str] = Field(default_factory=list)


# ==========================================
# VietQR & Context Reconciliation Models
# ==========================================

class VietQRData(BaseModel):
    """Dữ liệu bóc tách từ payload VietQR (TLV EMVCo)"""
    bank_bin: Optional[str] = None          # 6-digit BIN
    bank_id: Optional[str] = None           # Mã ngân hàng chuẩn hoá (bank_registry)
    bank_name: Optional[str] = None         # Tên ngân hàng từ BIN mapping
    account_number: Optional[str] = None    # Số tài khoản / số thẻ thụ hưởng
    account_name: Optional[str] = None      # Tên chủ tài khoản (tag 59, nếu có)
    amount: Optional[str] = None            # Số tiền giao dịch
    description: Optional[str] = None       # Nội dung chuyển khoản
    service_code: Optional[str] = None      # 38.02: QRIBFTTA (tài khoản) / QRIBFTTC (thẻ)
    crc_valid: bool = False                 # Kiểm tra CRC-16 hợp lệ (tính toàn vẹn)
    structure_valid: bool = True            # TLV không bị cắt cụt / sai định dạng
    structure_errors: List[str] = Field(default_factory=list)


class AccountCandidate(BaseModel):
    """Số tài khoản ứng viên đọc được từ ngữ cảnh"""
    number: str
    source: str = "bare"        # keyword | phone | bare | other
    distance: Optional[float] = None  # khoảng cách tới QR (đơn vị: kích thước QR)


class NameCandidate(BaseModel):
    name: str                   # đã bỏ dấu, IN HOA
    source: str = "upper"       # keyword | upper


class OCRData(BaseModel):
    """Dữ liệu bóc tách từ văn bản ngữ cảnh xung quanh mã QR"""
    account_numbers: List[str] = Field(default_factory=list)  # sắp theo độ tin cậy
    bank_names: List[str] = Field(default_factory=list)
    account_name: Optional[str] = None
    # Full text read from the image (may contain unrelated personal data). Used in-process
    # only; exclude=True keeps it out of Redis (result / events / cache) and API responses.
    raw_text: str = Field(default="", exclude=True)
    source: str = "none"                    # ocr | pdf_text | pdf_text+ocr | none | skipped
    context_type: str = "empty"             # empty | invoice | donation | payment_info | general | skipped
    bank_ids: List[str] = Field(default_factory=list)
    account_candidates: List[AccountCandidate] = Field(default_factory=list)
    name_candidates: List[NameCandidate] = Field(default_factory=list)
    amounts: List[int] = Field(default_factory=list)
    payment_blocks: List[Dict[str, Any]] = Field(default_factory=list, exclude=True)


class FieldCheck(BaseModel):
    """Một dòng trong bảng đối chiếu hiển thị trên UI"""
    field: str                  # bank | account | name | amount
    label: str
    qr_value: Optional[str] = None
    context_value: Optional[str] = None
    status: str = "unknown"     # match | near | mismatch | unknown | na
    score: float = 0.0
    note: str = ""


class MatchResult(BaseModel):
    """Kết quả đối chiếu giữa QR và ngữ cảnh"""
    bank_score: float = 0.0
    account_score: float = 0.0
    name_score: float = 0.0
    bank_status: str = "unknown"
    account_status: str = "unknown"
    account_source: str = ""    # nguồn STK khớp/mâu thuẫn: keyword | standee_* | bare | phone | ""
    name_status: str = "unknown"
    amount_status: str = "na"
    description_status: str = "na"
    checks: List[FieldCheck] = Field(default_factory=list)



# ==========================================
# Output & API Response Models
# ==========================================

class QRCodeResult(BaseModel):
    """Kết quả giải mã và phân tích 1 mã QR trên ảnh"""
    payload: str
    payload_type: PayloadType
    bbox: Optional[Tuple[int, int, int, int]] = None
    engine: str = "unknown"  # "pyzbar" | "wechat_qrcode" | "ensemble"
    vietqr_data: Optional[VietQRData] = None
    ocr_data: Optional[OCRData] = None
    match_result: Optional[MatchResult] = None
    url_analysis: Optional[URLAnalysis] = None
    alert_code: AlertCode = AlertCode.OTHER_PAYLOAD
    alert_color: str = "#9e9e9e"
    alert_title: str = ""
    alert_message: str = ""
    alert_recommendation: str = ""
    # ── Presentation metadata (backend is source of truth) ──
    is_provisional: bool = False
    risk_level: Optional[str] = None
    analysis_completeness: str = "full"     # full | partial | pending
    reason_codes: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _derive_presentation(self):
        if self.url_analysis is not None:
            if self.url_analysis.is_provisional:
                self.is_provisional = True
            if not self.reason_codes:
                self.reason_codes = list(self.url_analysis.reason_codes)
            if self.analysis_completeness == "full":
                self.analysis_completeness = self.url_analysis.analysis_completeness
        if self.risk_level not in RISK_LEVELS:
            self.risk_level = risk_level_for_alert(self.alert_code)
        # A provisional result must never read as "no known risk": it is still pending.
        if self.is_provisional:
            self.analysis_completeness = "pending"
            if self.risk_level in ("no_known_risk", "info", "unverifiable"):
                self.risk_level = "pending"
        return self


class ProcessingResult(BaseModel):
    """Kết quả toàn bộ phiên xử lý"""
    job_id: str
    status: JobStatus
    file_name: str
    qr_codes: List[QRCodeResult] = Field(default_factory=list)
    processing_steps: List[dict] = Field(default_factory=list)
    error: Optional[str] = None
    # ── Production metadata ──
    error_code: Optional[str] = None
    user_message: Optional[str] = None
    recommended_action: Optional[str] = None
    is_final: bool = True
    analysis_completeness: str = "full"     # full | partial
    warnings: List[str] = Field(default_factory=list)
    created_at: Optional[float] = None
    completed_at: Optional[float] = None
    timings_ms: Dict[str, float] = Field(default_factory=dict)


class UploadResponse(BaseModel):
    job_id: str
    message: str = "Đang xử lý..."

