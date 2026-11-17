"""
XGBoost URL Security Model Service
Singleton service managing model loading, SHA-256 verification, and inference.
Guarantees graceful degradation without failing jobs or crashing workers.

Model Integration Interface (adapter)
-------------------------------------
The model is delivered as a canonical bundle in XGB_MODEL_DIR:

    manifest.json            required  model_id ("qrdetec-url-xgb"), features (81),
                                       sha256, output_type (probability)
    model.ubj                required  native XGBoost model
    feature_names.json       required  must equal manifest.features (same 81, same order)
    feature_schema.json      required  {"n_features": 81, "feature_names": [...]}
    preprocessing_config.json required {"n_features": 81}
    calibrator.json          required  {"type": "isotonic", "X_thresholds": [...], "y_thresholds": [...]}
    thresholds.json          required  {"operating_threshold": ...}
    golden_vectors.json      required  {"records": [{"url", "features", "raw_score", "calibrated_score", "prediction"}]}

Production URL XGBoost bundle (exported by AI/tools/export_model.py)
-------------------------------------------------------------------
Requires "model_id": "qrdetec-url-xgb" and vendored URL extractor
(app/services/url_security/url_model_runtime, 81 features computed from the stripped raw URL).
Fail closed if the bundle does not match the 81-feature canonical contract.

States: NOT_CONFIGURED | LOADING | READY | INCOMPATIBLE_FEATURE_SCHEMA | INVALID_ARTIFACT |
INFERENCE_ERROR (per request).
"""
import hashlib
import json
import logging
import math
import os
import threading
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.models.schemas import URLModelEvidence, URLSHAPContribution
from app.services.url_security.normalizer import NormalizedURL

logger = logging.getLogger(__name__)

FEATURE_VI_LABELS: Dict[str, str] = {
    "url_len": "Tổng độ dài URL",
    "hostname_len": "Độ dài tên miền (hostname)",
    "path_len": "Độ dài đường dẫn (path)",
    "query_len": "Độ dài chuỗi truy vấn (query)",
    "fragment_len": "Độ dài phân đoạn (#fragment)",
    "ratio_digits_url": "Tỷ lệ chữ số trong URL",
    "ratio_letters_url": "Tỷ lệ chữ cái trong URL",
    "ratio_special_url": "Tỷ lệ ký tự đặc biệt trong URL",
    "n_subdomains": "Số tầng tên miền phụ (subdomain)",
    "path_depth": "Độ sâu phân cấp đường dẫn",
    "port_val": "Cổng kết nối (port) chỉ định trong URL",
    "n_dots_url": "Số dấu chấm (.) trong URL",
    "n_hyphens_url": "Số dấu gạch ngang (-) trong URL",
    "n_underscores_url": "Số dấu gạch dưới (_) trong URL",
    "n_slashes_url": "Số dấu gạch chéo (/) trong URL",
    "n_question_url": "Số dấu chấm hỏi (?) trong URL",
    "n_equal_url": "Số dấu bằng (=) trong URL",
    "n_at_url": "Ký tự @ trong URL",
    "n_ampersand_url": "Số ký tự nối tham số (&) trong URL",
    "n_percent_url": "Số ký tự phần trăm (%) trong URL",
    "n_dots_host": "Số dấu chấm (.) trong tên miền",
    "n_hyphens_host": "Số dấu gạch ngang (-) trong tên miền",
    "n_digits_host": "Số chữ số trong tên miền",
    "entropy_url": "Độ ngẫu nhiên (Shannon entropy) toàn URL",
    "entropy_host": "Độ ngẫu nhiên (entropy) của tên miền",
    "entropy_path": "Độ ngẫu nhiên (entropy) của đường dẫn",
    "has_ip_host": "Sử dụng địa chỉ IP trực tiếp thay cho tên miền",
    "tld_len": "Độ dài đuôi tên miền (TLD)",
    "is_suspicious_tld": "Đuôi tên miền (TLD) có tần suất lừa đảo cao",
    "has_userinfo": "Chứa thông tin tài khoản (userinfo@) trước tên miền",
    "scheme_is_https": "Giao thức HTTPS",
    "scheme_is_http": "Giao thức HTTP không mã hóa",
    "scheme_is_other": "Giao thức phi chuẩn (ngoài HTTP/HTTPS)",
    "scheme_missing": "Thiếu tiền tố giao thức (scheme)",
    "n_pct_encoded": "Số chuỗi mã hóa phần trăm (%XX)",
    "decode_depth": "Số lớp mã hóa lồng nhau (decode depth)",
    "has_escape_seq": "Chứa chuỗi thoát (escape sequence)",
    "has_html_entities": "Chứa thực thể mã hóa HTML",
    "has_data_uri": "Sử dụng lược đồ nhúng dữ liệu (data: URI)",
    "has_javascript_pseudo": "Sử dụng mã thực thi (javascript: URI)",
    "has_executable_extension": "Đường dẫn trỏ tới tệp thực thi (.exe, .apk, .msi...)",
    "has_archive_extension": "Đường dẫn trỏ tới tệp nén (.zip, .rar...)",
    "has_redirect_parameter": "Chứa tham số chuyển hướng mở (redirect/url/next)",
    "brand_token_in_hostname": "Chứa tên thương hiệu trong tên miền",
    "brand_token_in_registered_domain": "Chứa tên thương hiệu trong tên miền đăng ký (eTLD+1)",
    "brand_token_in_subdomain": "Chứa tên thương hiệu ở tên miền phụ (subdomain)",
    "brand_token_in_path": "Chứa tên thương hiệu trong đường dẫn (path)",
    "brand_token_in_query": "Chứa tên thương hiệu trong tham số truy vấn (query)",
    "brand_official_domain_match": "Khớp tên miền chính thức của thương hiệu",
    "brand_official_domain_mismatch": "Chứa tên thương hiệu nhưng không phải miền chính thức",
    "brand_lookalike_distance": "Khoảng cách chỉnh sửa (typosquatting) so với thương hiệu",
    "brand_homoglyph_similarity": "Độ tương đồng ký tự đồng dạng (homoglyph) với thương hiệu",
    "brand_plus_security_keyword": "Kết hợp tên thương hiệu và từ khóa bảo mật",
    "brand_plus_payment_keyword": "Kết hợp tên thương hiệu và từ khóa thanh toán",
    "phishing_keyword_count": "Số từ khóa nhạy cảm thường gặp trong lừa đảo",
    "credential_keyword_count": "Số từ khóa yêu cầu thông tin đăng nhập",
    "payment_keyword_count": "Số từ khóa liên quan giao dịch/thanh toán",
    "account_security_keyword_count": "Số từ khóa cảnh báo tài khoản/bảo mật",
    "vietnamese_keyword_count": "Số từ khóa nhạy cảm tiếng Việt",
    "vietnamese_bank_keyword_count": "Số từ khóa ngân hàng tại Việt Nam",
    "vietnamese_otp_keyword_count": "Số từ khóa OTP/mã bảo mật tiếng Việt",
    "vietnamese_public_service_keyword_count": "Số từ khóa dịch vụ công/cơ quan nhà nước",
    "hostname_has_non_ascii": "Tên miền chứa ký tự ngoài bảng mã ASCII",
    "hostname_is_punycode": "Tên miền mã hóa quốc tế hóa Punycode (xn--)",
    "hostname_mixed_script": "Tên miền trộn lẫn nhiều bảng chữ cái (mixed-script)",
    "hostname_confusable_count": "Số ký tự đồng dạng (confusable Unicode) trong tên miền",
    "hostname_confusable_brand_match": "Tên miền chứa ký tự đồng dạng/Punycode giả mạo thương hiệu",
    "hostname_unicode_script_count": "Số hệ chữ cái Unicode trong tên miền",
    "hostname_ascii_normalization_changed": "Tên miền thay đổi sau khi chuẩn hóa về ASCII",
    "tld_in_path": "Chứa đuôi tên miền (TLD) ngụy trang trong đường dẫn (path)",
    "tld_in_subdomain": "Chứa đuôi tên miền (TLD) ngụy trang ở tên miền phụ (subdomain)",
    "abnormal_subdomain": "Cấu trúc tiền tố tên miền phụ bất thường (w[w]?\\d+)",
    "shortening_service": "Sử dụng dịch vụ rút gọn liên kết (URL shortener)",
    "nb_www": "Số lần xuất hiện chuỗi 'www' trong URL",
    "nb_com": "Số lần xuất hiện chuỗi '.com' trong phần đường dẫn/tham số",
    "nb_dslash": "Số dấu gạch chéo kép (//) dư thừa sau giao thức",
    "char_repeat": "Số chuỗi ký tự lặp liên tiếp bất thường trong từ khóa URL",
    "shortest_word_host": "Độ dài từ ngắn nhất trong tên miền (hostname)",
    "avg_word_host": "Độ dài trung bình các từ trong tên miền (hostname)",
    "longest_word_path": "Độ dài từ dài nhất trong đường dẫn/tham số (path/query)",
    "avg_word_path": "Độ dài trung bình các từ trong đường dẫn/tham số (path/query)",
}


def _format_feature_label(name: str, value: float) -> str:
    if abs(value) <= 1e-9:
        if name == "path_len":
            return "Không có đường dẫn phụ (path rỗng)"
        if name == "query_len":
            return "Không có chuỗi truy vấn (query rỗng)"
        if name == "entropy_path":
            return "Độ ngẫu nhiên (entropy) đường dẫn bằng 0"
        if name == "brand_official_domain_mismatch":
            return "Không phát hiện bất khớp tên thương hiệu ASCII trực tiếp"
        if name == "n_subdomains":
            return "Không có tầng tên miền phụ (subdomain = 0)"
        if name == "n_digits_host":
            return "Không có chữ số trong tên miền"
        if name == "n_hyphens_host":
            return "Không có dấu gạch ngang (-) trong tên miền"
    return FEATURE_VI_LABELS.get(name, name)


class ModelStatus:
    NOT_CONFIGURED = "NOT_CONFIGURED"
    LOADING = "LOADING"
    READY = "READY"
    INCOMPATIBLE_FEATURE_SCHEMA = "INCOMPATIBLE_FEATURE_SCHEMA"
    INVALID_ARTIFACT = "INVALID_ARTIFACT"
    INFERENCE_ERROR = "INFERENCE_ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ModelArtifactError(Exception):
    """Raised during bundle validation; carries the resulting status and a safe reason."""

    def __init__(self, status: str, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


class Calibrator:
    """Score calibration loaded from JSON only (no pickle / arbitrary code)."""

    def __init__(self, spec: Optional[dict]):
        spec = spec or {"type": "none"}
        self.kind = str(spec.get("type", "none")).lower()
        if self.kind == "none":
            return
        if self.kind == "platt":
            self.a = float(spec["a"])
            self.b = float(spec["b"])
            if not (math.isfinite(self.a) and math.isfinite(self.b)):
                raise ValueError("non-finite platt parameters")
            return
        if self.kind == "isotonic":
            # {"x","y"} or {"X_thresholds","y_thresholds"} (sklearn knots)
            xs = spec["x"] if "x" in spec else spec["X_thresholds"]
            ys = spec["y"] if "y" in spec else spec["y_thresholds"]
            self.x = [float(v) for v in xs]
            self.y = [float(v) for v in ys]
            if any(not math.isfinite(v) for v in self.x + self.y):
                raise ValueError("non-finite isotonic table")
            if len(self.x) < 2 or len(self.x) != len(self.y) or self.x != sorted(self.x):
                raise ValueError("invalid isotonic table")
            if any(not (0.0 <= v <= 1.0) for v in self.y):
                raise ValueError("isotonic outputs must be probabilities")
            return
        raise ValueError(f"unsupported calibrator type {self.kind}")

    def apply(self, score: float) -> float:
        if self.kind == "none":
            return score
        if self.kind == "platt":
            return 1.0 / (1.0 + math.exp(self.a * score + self.b))
        try:
            import numpy as np
            return float(np.clip(np.interp(score, self.x, self.y), 0.0, 1.0))
        except ImportError:  # pragma: no cover
            pass
        if score <= self.x[0]:
            return self.y[0]
        if score >= self.x[-1]:
            return self.y[-1]
        for i in range(1, len(self.x)):
            if score <= self.x[i]:
                x0, x1, y0, y1 = self.x[i - 1], self.x[i], self.y[i - 1], self.y[i]
                return y0 if x1 == x0 else y0 + (y1 - y0) * (score - x0) / (x1 - x0)
        return self.y[-1]


class URLModelService:
    """
    Singleton service for XGBoost URL security classifier.
    Loads canonical 81-feature native UBJ models safely and validates SHA-256 hashes against manifest.
    """

    _instance = None
    _lock = threading.Lock()

    def __init__(
        self,
        model_path: Optional[str] = None,
        manifest_path: Optional[str] = None,
    ):
        self.model_path = model_path or settings.XGB_MODEL_PATH
        self.manifest_path = manifest_path or settings.XGB_MANIFEST_PATH
        self.bundle_dir = os.path.dirname(os.path.abspath(self.manifest_path))
        self._booster = None
        self._calibrator = Calibrator(None)
        self._features: List[str] = []
        self._output_type = "probability"
        self._model_id: Optional[str] = None
        self._status: str = ModelStatus.NOT_CONFIGURED
        self._load_reason: str = "NOT_INITIALIZED"
        self._initialized = False
        self._model_sha: str = ""
        self._url_runtime = None
        self._feature_schema: Optional[str] = None
        self._ml_threshold: Optional[float] = None
        # (0, 0) = all trees. Canonical bundles pin (0, best_iteration + 1) = XGBClassifier semantics.
        self._iteration_range: Tuple[int, int] = (0, 0)

    # ─────────────────────────────── public state ───────────────────────────────
    @property
    def status(self) -> str:
        if not self._initialized:
            self.initialize()
        return self._status

    @property
    def cache_fingerprint(self) -> str:
        """Short identity of the active model (or its absence) for result-cache keys."""
        if not self._initialized:
            self.initialize()
        if self._status != ModelStatus.READY:
            return f"none-{self._status.lower()}"
        return (self._model_sha or "unpinned")[:12]

    def describe(self) -> Dict[str, Any]:
        """Operator diagnostics (no paths, no secrets)."""
        if not self._initialized:
            self.initialize()
        return {
            "model_status": self._status,
            "reason": self._load_reason,
            "model_id": self._model_id,
            "n_features": len(self._features),
            "num_features": len(self._features),
            "sha256_prefix": self._model_sha[:12] if self._model_sha else None,
            "feature_schema": self._feature_schema,
            "operating_threshold": self._ml_threshold,
        }

    # ─────────────────────────────── loading ───────────────────────────────
    def initialize(self):
        """Loads and verifies the model once at startup."""
        with self._lock:
            if self._initialized:
                return
            self._status = ModelStatus.LOADING
            try:
                self._load_bundle()
                self._status = ModelStatus.READY
                self._load_reason = "LOADED_SUCCESSFULLY"
                logger.info("✓ XGBoost URL Model READY (id=%s, %d features, threshold=%s)",
                            self._model_id, len(self._features), self._ml_threshold)
            except ModelArtifactError as e:
                self._booster = None
                self._status = e.status
                self._load_reason = e.reason
                level = logging.INFO if e.status == ModelStatus.NOT_CONFIGURED else logging.ERROR
                logger.log(level, "URL Model Service: %s (%s) — Local IOC continues", e.status, e.reason)
            except Exception as e:  # never crash the worker
                self._booster = None
                self._status = ModelStatus.INVALID_ARTIFACT
                self._load_reason = f"UNEXPECTED_LOAD_ERROR: {type(e).__name__}"
                logger.error("URL Model Service: %s", self._load_reason)
            finally:
                self._initialized = True

    def _bundle_file(self, name: str) -> str:
        return os.path.join(self.bundle_dir, name)

    def _load_bundle(self) -> None:
        NC, INV, INC = ModelStatus.NOT_CONFIGURED, ModelStatus.INVALID_ARTIFACT, ModelStatus.INCOMPATIBLE_FEATURE_SCHEMA

        if not os.path.exists(self.manifest_path):
            raise ModelArtifactError(NC, "MANIFEST_NOT_FOUND")

        try:
            manifest = _read_json(self.manifest_path)
            if not isinstance(manifest, dict):
                raise ValueError("Manifest root must be an object")
        except Exception as e:
            raise ModelArtifactError(INV, f"MANIFEST_CORRUPT: {type(e).__name__}")

        model_id = manifest.get("model_id")
        if model_id != "qrdetec-url-xgb":
            raise ModelArtifactError(INC, f"UNSUPPORTED_MODEL_ID: {model_id!r}")
        self._model_id = model_id

        if not os.path.exists(self.model_path):
            raise ModelArtifactError(NC, "MODEL_FILE_NOT_FOUND")

        raw_features = manifest.get("features")
        if not isinstance(raw_features, list):
            raise ModelArtifactError(INV, "FEATURES_LIST_MISSING")

        features = [str(f) for f in raw_features]
        if len(set(features)) != len(features):
            raise ModelArtifactError(INV, "DUPLICATE_FEATURE_NAMES")

        declared = manifest.get("n_features") or manifest.get("num_features")
        if declared is not None and int(declared) != len(features):
            raise ModelArtifactError(INV, f"NUM_FEATURES_MISMATCH: manifest {declared} vs list {len(features)}")

        output_type = str(manifest.get("output_type", "probability")).lower()
        if output_type not in ("probability", "margin"):
            raise ModelArtifactError(INV, f"UNSUPPORTED_OUTPUT_TYPE: {output_type}")

        # Checksum of model.ubj
        expected_sha = str(manifest.get("sha256", "") or "").strip().lower()
        if not expected_sha and settings.is_production and settings.XGB_REQUIRE_SHA256:
            raise ModelArtifactError(INV, "CHECKSUM_MISSING")
        if expected_sha:
            try:
                actual_sha = _compute_sha256(self.model_path).lower()
            except Exception as e:
                raise ModelArtifactError(INV, f"CHECKSUM_CALCULATION_ERROR: {type(e).__name__}")
            if actual_sha != expected_sha:
                raise ModelArtifactError(INV, f"CHECKSUM_MISMATCH: expected {expected_sha[:8]} got {actual_sha[:8]}")
            self._model_sha = actual_sha
        else:
            logger.warning("URL Model Service: manifest has no sha256 (unpinned model, development only)")

        if len(features) != 81:
            raise ModelArtifactError(INC, f"NUM_FEATURES_MISMATCH: expected 81, got {len(features)}")

        # Feature schema contract
        declared_contract = manifest.get("feature_contract")
        declared_schema = manifest.get("feature_schema")
        if declared_contract is not None:
            raise ModelArtifactError(INC, f"UNSUPPORTED_FEATURE_SCHEMA: {declared_contract}")
        if declared_schema is not None and declared_schema != "SHA256-VERIFIED":
            raise ModelArtifactError(INC, f"UNSUPPORTED_FEATURE_SCHEMA: {declared_schema}")

        self._validate_model_contract(manifest, features)
        self._load_verified_artifacts(manifest, features)

    def _validate_model_contract(self, manifest: dict, features: List[str]) -> None:
        """81-feature contract against the vendored extractor. No fallback."""
        INV, INC = ModelStatus.INVALID_ARTIFACT, ModelStatus.INCOMPATIBLE_FEATURE_SCHEMA
        try:
            from app.services.url_security import url_model_runtime as ml_runtime
        except Exception as e:
            raise ModelArtifactError(INC, f"RUNTIME_UNAVAILABLE: {type(e).__name__}")

        feature_names = getattr(ml_runtime, "FEATURE_NAMES", None)
        feature_count = int(getattr(ml_runtime, "FEATURE_COUNT", 81))
        if feature_count != 81 or len(features) != 81 or (feature_names and features != list(feature_names)):
            raise ModelArtifactError(INC, "FEATURE_CONTRACT_MISMATCH (names, order or count != 81)")

        for required in ("feature_names.json", "feature_schema.json", "preprocessing_config.json",
                         "thresholds.json", "calibrator.json", "golden_vectors.json"):
            if not os.path.exists(self._bundle_file(required)):
                raise ModelArtifactError(INV, f"BUNDLE_FILE_MISSING: {required}")

        expected_schema_sha = manifest.get("feature_schema_sha256")
        if expected_schema_sha:
            actual_schema_sha = _compute_sha256(self._bundle_file("feature_schema.json"))
            if actual_schema_sha.lower() != str(expected_schema_sha).lower():
                raise ModelArtifactError(INC, "FEATURE_SCHEMA_HASH_MISMATCH")

        expected_names_sha = manifest.get("feature_names_sha256")
        if expected_names_sha:
            actual_names_sha = _compute_sha256(self._bundle_file("feature_names.json"))
            if actual_names_sha.lower() != str(expected_names_sha).lower():
                raise ModelArtifactError(INC, "FEATURE_NAMES_HASH_MISMATCH")

        if [str(n) for n in _read_json(self._bundle_file("feature_names.json"))] != features:
            raise ModelArtifactError(INC, "FEATURE_NAMES_FILE_MISMATCH (names or order)")

        schema = _read_json(self._bundle_file("feature_schema.json"))
        if not isinstance(schema, dict) or int(schema.get("n_features", -1)) != 81 \
                or [str(n) for n in schema.get("feature_names", [])] != features:
            raise ModelArtifactError(INC, "FEATURE_SCHEMA_FILE_MISMATCH (81 / order)")

        prep_cfg = _read_json(self._bundle_file("preprocessing_config.json"))
        if not isinstance(prep_cfg, dict) or int(prep_cfg.get("n_features", -1)) != 81:
            raise ModelArtifactError(INC, "PREPROCESSING_CONFIG_MISMATCH")

        try:
            t_manifest = float(manifest["operating_threshold"])
            t_file = float(_read_json(self._bundle_file("thresholds.json"))["operating_threshold"])
        except Exception as e:
            raise ModelArtifactError(INV, f"OPERATING_THRESHOLD_INVALID: {type(e).__name__}")
        if not (0.0 < t_file < 1.0) or not math.isfinite(t_file) or abs(t_manifest - t_file) > 1e-12:
            raise ModelArtifactError(INV, "OPERATING_THRESHOLD_MISMATCH")

        self._url_runtime = ml_runtime
        self._feature_schema = "SHA256-VERIFIED"
        self._ml_threshold = t_file

    def _load_verified_artifacts(self, manifest: dict, features: List[str]) -> None:
        INV, INC = ModelStatus.INVALID_ARTIFACT, ModelStatus.INCOMPATIBLE_FEATURE_SCHEMA

        # Verify all bundle files SHA256
        files_sha = manifest.get("files_sha256")
        if not isinstance(files_sha, dict) or not files_sha:
            raise ModelArtifactError(INV, "FILES_SHA256_MISSING")
        for name, digest in files_sha.items():
            path = self._bundle_file(os.path.basename(str(name)))
            if not os.path.exists(path):
                raise ModelArtifactError(INV, f"BUNDLE_FILE_MISSING: {os.path.basename(str(name))}")
            if _compute_sha256(path).lower() != str(digest).lower():
                raise ModelArtifactError(INV, f"FILE_CHECKSUM_MISMATCH: {os.path.basename(str(name))}")

        output_type = str(manifest.get("output_type", "probability")).lower()

        # Calibrator
        calib_spec = manifest.get("calibrator")
        calib_path = self._bundle_file("calibrator.json")
        try:
            if isinstance(calib_spec, dict) and calib_spec.get("file"):
                calib_path = self._bundle_file(os.path.basename(str(calib_spec["file"])))
                if calib_spec.get("sha256") and _compute_sha256(calib_path) != str(calib_spec["sha256"]).lower():
                    raise ModelArtifactError(INV, "CALIBRATOR_CHECKSUM_MISMATCH")
                calibrator = Calibrator(_read_json(calib_path))
            elif os.path.exists(calib_path):
                calibrator = Calibrator(_read_json(calib_path))
            else:
                calibrator = Calibrator(calib_spec if isinstance(calib_spec, dict) else None)
        except ModelArtifactError:
            raise
        except Exception as e:
            raise ModelArtifactError(INV, f"CALIBRATOR_INVALID: {type(e).__name__}")

        # Load booster
        try:
            import xgboost as xgb
            booster = xgb.Booster()
            booster.load_model(self.model_path)
        except Exception as e:
            raise ModelArtifactError(INV, f"XGBOOST_LOAD_ERROR: {type(e).__name__}")
        try:
            n_model = int(booster.num_features())
        except Exception:
            n_model = len(features)
        if n_model != len(features):
            raise ModelArtifactError(INC, f"MODEL_EXPECTS_{n_model}_FEATURES_MANIFEST_HAS_{len(features)}")
        if booster.feature_names and list(booster.feature_names) != features:
            raise ModelArtifactError(INC, "BOOSTER_FEATURE_ORDER_MISMATCH")

        bi_manifest = manifest.get("best_iteration")
        bi_attr = booster.attr("best_iteration")
        if bi_manifest is None:
            raise ModelArtifactError(INV, "BEST_ITERATION_MISSING")
        if bi_attr is not None and int(bi_attr) != int(bi_manifest):
            raise ModelArtifactError(INV, "BEST_ITERATION_MISMATCH")
        if not (0 <= int(bi_manifest) < int(booster.num_boosted_rounds())):
            raise ModelArtifactError(INV, "BEST_ITERATION_OUT_OF_RANGE")
        iteration_range = (0, int(bi_manifest) + 1)

        self._booster = booster
        self._iteration_range = iteration_range
        self._calibrator = calibrator
        self._features = features
        self._output_type = output_type

        # Golden vectors
        self._check_golden_vectors(manifest)

    def _check_golden_vectors(self, manifest: dict) -> None:
        INV, INC = ModelStatus.INVALID_ARTIFACT, ModelStatus.INCOMPATIBLE_FEATURE_SCHEMA
        spec = manifest.get("golden_vectors")
        path = self._bundle_file("golden_vectors.json")
        if isinstance(spec, dict) and spec.get("file"):
            path = self._bundle_file(os.path.basename(str(spec["file"])))
        if not os.path.exists(path):
            if settings.is_production and settings.XGB_REQUIRE_GOLDEN_VECTORS:
                self._booster = None
                raise ModelArtifactError(INV, "GOLDEN_VECTORS_MISSING")
            logger.warning("URL Model Service: no golden_vectors.json — feature parity NOT verified")
            return
        if isinstance(spec, dict) and spec.get("sha256") and _compute_sha256(path) != str(spec["sha256"]).lower():
            self._booster = None
            raise ModelArtifactError(INV, "GOLDEN_VECTORS_CHECKSUM_MISMATCH")
        data = _read_json(path)
        if not isinstance(data, dict) or "records" not in data:
            self._booster = None
            raise ModelArtifactError(INV, "GOLDEN_VECTORS_RECORDS_REQUIRED")
        self._check_golden_vectors_records(data)

    def _check_golden_vectors_records(self, data: dict) -> None:
        """Golden records: features, raw score, calibrated score and prediction must all match."""
        INV, INC = ModelStatus.INVALID_ARTIFACT, ModelStatus.INCOMPATIBLE_FEATURE_SCHEMA
        records = data.get("records") or []
        if not records:
            self._booster = None
            raise ModelArtifactError(INV, "GOLDEN_VECTORS_EMPTY")
        tol = float(data.get("tolerance") or settings.XGB_GOLDEN_TOLERANCE)
        extract_fn = getattr(self._url_runtime, "extract_features", None)
        for i, rec in enumerate(records):
            try:
                url = str(rec["url"])
                expected = [float(rec["features"][k]) for k in self._features]
                exp_raw, exp_cal = float(rec["raw_score"]), float(rec["calibrated_score"])
            except Exception:
                self._booster = None
                raise ModelArtifactError(INV, f"GOLDEN_{i}_MALFORMED")
            feats = extract_fn(url)
            vec = [float(feats[k]) for k in self._features]
            if any(abs(a - b) > 1e-6 for a, b in zip(vec, expected)):
                self._booster = None
                raise ModelArtifactError(INC, f"GOLDEN_{i}_FEATURE_MISMATCH (runtime extractor differs from training)")
            detail = self._score_detail(vec)
            if detail is None or abs(detail[0] - exp_raw) > tol or abs(detail[1] - exp_cal) > tol:
                self._booster = None
                raise ModelArtifactError(INV, f"GOLDEN_{i}_SCORE_MISMATCH")
            if "prediction" in rec and self._ml_threshold is not None \
                    and int(detail[1] >= self._ml_threshold) != int(rec["prediction"]):
                self._booster = None
                raise ModelArtifactError(INV, f"GOLDEN_{i}_PREDICTION_MISMATCH")

    # ─────────────────────────────── inference ───────────────────────────────
    def _score_detail(self, features: List[float]) -> Optional[Tuple[float, float]]:
        """Returns (raw_probability, calibrated_probability) or None if not finite."""
        import numpy as np
        import xgboost as xgb

        if any(not math.isfinite(v) for v in features):
            return None
        matrix = xgb.DMatrix(np.array([features], dtype=np.float32), feature_names=self._features)
        preds = self._booster.predict(matrix, output_margin=(self._output_type == "margin"),
                                      iteration_range=self._iteration_range)
        if len(preds) == 0:
            return None
        raw = float(preds[0])
        if not math.isfinite(raw):
            return None
        if self._output_type == "margin":
            raw = 1.0 / (1.0 + math.exp(-raw))
        score = self._calibrator.apply(raw)
        if not math.isfinite(score):
            return None
        return raw, max(0.0, min(1.0, score))

    def _score(self, features: List[float]) -> Optional[float]:
        detail = self._score_detail(features)
        return None if detail is None else detail[1]

    def _compute_shap_contributions(
        self, features: List[float]
    ) -> Tuple[Optional[float], List[URLSHAPContribution], List[URLSHAPContribution]]:
        """Computes exact TreeSHAP log-odds contributions for the 81 features."""
        import numpy as np
        import xgboost as xgb

        try:
            matrix = xgb.DMatrix(np.array([features], dtype=np.float32), feature_names=self._features)
            contribs = self._booster.predict(
                matrix, pred_contribs=True, iteration_range=self._iteration_range
            )
            if contribs is None or len(contribs) == 0:
                return None, [], []
            row = contribs[0]
            if len(row) != len(self._features) + 1:
                return None, [], []
            base_val = float(row[-1])
            if not math.isfinite(base_val):
                return None, [], []

            risk_active: List[URLSHAPContribution] = []
            risk_zero: List[URLSHAPContribution] = []
            benign_all: List[URLSHAPContribution] = []

            for fname, fval, sval in zip(self._features, features, row[:-1]):
                sval_f = float(sval)
                if not math.isfinite(sval_f):
                    continue
                item = URLSHAPContribution(
                    feature=fname,
                    label=_format_feature_label(fname, float(fval)),
                    value=round(float(fval), 4),
                    shap_value=round(sval_f, 4),
                    direction="risk" if sval_f >= 0 else "benign",
                )
                if sval_f >= 0.05:
                    if abs(float(fval)) > 1e-9:
                        risk_active.append(item)
                    else:
                        risk_zero.append(item)
                elif sval_f <= -0.05:
                    benign_all.append(item)

            risk_active.sort(key=lambda x: x.shap_value, reverse=True)
            risk_zero.sort(key=lambda x: x.shap_value, reverse=True)
            benign_all.sort(key=lambda x: x.shap_value)

            top_risk = risk_active[:5]
            top_benign = benign_all[:3]
            return round(base_val, 4), top_risk, top_benign
        except Exception:
            return None, [], []

    def _extract_features(self, norm: NormalizedURL) -> Tuple[Optional[List[float]], Optional[str]]:
        """69 features from the stripped raw URL. Never zero-fills."""
        if norm.error in ("EMPTY_URL", "EXCESSIVE_URL_LENGTH_REJECTED") or not norm.original_url:
            return None, f"URL_NOT_SCORABLE: {norm.error or 'EMPTY_URL'}"
        try:
            extract_strict_fn = getattr(self._url_runtime, "extract_features_strict", None)
            feats = extract_strict_fn(norm.original_url)
            return [float(feats[k]) for k in self._features], None
        except Exception as e:
            return None, f"FEATURE_EXTRACTION_FAILED: {type(e).__name__}"

    def warmup(self):
        """Warm up the model singleton at worker startup."""
        self.initialize()

    def _evidence(
        self,
        status: str,
        score: Optional[float] = None,
        reason: Optional[str] = None,
        raw: Optional[float] = None,
        prediction: Optional[int] = None,
        shap_base_value: Optional[float] = None,
        shap_top_risk: Optional[List[URLSHAPContribution]] = None,
        shap_top_benign: Optional[List[URLSHAPContribution]] = None,
    ) -> URLModelEvidence:
        if prediction is None and status == ModelStatus.READY and score is not None and self._ml_threshold is not None:
            prediction = int(score >= self._ml_threshold)
        return URLModelEvidence(
            model_status=status,
            model_score=score,
            model_id=self._model_id if status == ModelStatus.READY else None,
            n_features=len(self._features) if status == ModelStatus.READY else None,
            reason=reason,
            raw_score=raw,
            ml_threshold=self._ml_threshold if status == ModelStatus.READY else None,
            ml_prediction=prediction,
            shap_base_value=shap_base_value,
            shap_top_risk=shap_top_risk or [],
            shap_top_benign=shap_top_benign or [],
        )

    def predict(self, norm: NormalizedURL) -> URLModelEvidence:
        """
        Runs inference on the normalized URL.
        Guarantees that errors never crash callers and return graceful evidence.
        """
        if not self._initialized:
            self.initialize()

        if self._status != ModelStatus.READY or self._booster is None:
            return self._evidence(self._status, None, self._load_reason)

        features, feat_err = self._extract_features(norm)
        if feat_err or features is None:
            return self._evidence(ModelStatus.INFERENCE_ERROR, None, feat_err or "FEATURE_EXTRACTION_FAILED")

        try:
            detail = self._score_detail(features)
            if detail is None:
                return self._evidence(ModelStatus.INFERENCE_ERROR, None, "NAN_OR_INF_SCORE_DETECTED")
            raw, score = detail
            score_rounded = round(score, 4)
            prediction = int(score_rounded >= self._ml_threshold) if self._ml_threshold is not None else None
            shap_base, shap_risk, shap_benign = self._compute_shap_contributions(features)
            return self._evidence(
                ModelStatus.READY,
                score=score_rounded,
                reason=None,
                raw=round(raw, 6),
                prediction=prediction,
                shap_base_value=shap_base,
                shap_top_risk=shap_risk,
                shap_top_benign=shap_benign,
            )
        except Exception as e:
            logger.warning("Inference exception in URLModelService: %s", type(e).__name__)
            return self._evidence(ModelStatus.INFERENCE_ERROR, None, f"INFERENCE_EXCEPTION: {type(e).__name__}")


# Global singleton
_model_service: Optional[URLModelService] = None


def get_url_model_service() -> URLModelService:
    global _model_service
    if _model_service is None:
        _model_service = URLModelService()
    return _model_service


def validate_bundle(bundle_dir: str) -> Tuple[str, str, Dict[str, Any]]:
    """Validate a model bundle directory with exactly the runtime checks."""
    svc = URLModelService(
        model_path=os.path.join(bundle_dir, "model.ubj"),
        manifest_path=os.path.join(bundle_dir, "manifest.json"),
    )
    svc.initialize()
    return svc._status, svc._load_reason, svc.describe()
