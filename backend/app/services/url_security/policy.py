"""
URL Security Risk Fusion & Decision Policy Engine
Fuses Calibrated XGBoost AI Model (81 features + Isotonic + TreeSHAP) and Local IOC Evidence
into a definitive single-phase SecurityVerdict and structured warnings.
Zero static lexical heuristics. Never marks a URL as absolute 'SAFE'.
"""
from typing import List, Tuple

from app.core.config import settings
from app.models.schemas import (
    AlertCode,
    SecurityVerdict,
    ThreatIntelEvidence,
    URLModelEvidence,
)
from app.services.url_security.normalizer import NormalizedURL


class URLSecurityPolicy:
    """
    Central Decision Policy for URLs and URIs.
    Principles:
    1. Threat Intelligence is authoritative for known malicious threats (verified Local IOC snapshot).
    2. Calibrated 81-feature XGBoost Model (Isotonic Calibration + TreeSHAP) is the core AI detector
       for unseen/zero-day malicious and IDN homograph URLs.
    3. Protocol & Network Guardrails from URLNormalizer catch non-HTTP(S) execution schemes,
       private/local SSRF hosts, and authority userinfo/host obfuscation tricks.
    4. URL evaluation is strictly single-phase.
    5. Clean evaluation outputs NO_KNOWN_RISK, never SAFE.
    """

    POLICY_VERSION = "3.0.0"

    DANGEROUS_SCHEMES = ("javascript", "data", "file", "intent", "blob", "vbscript")
    INFORMATIONAL_SCHEMES = ("mailto", "tel", "sms")

    def __init__(
        self,
        model_high_threshold: float = settings.URL_MODEL_HIGH_THRESHOLD,
        model_medium_threshold: float = settings.URL_MODEL_MEDIUM_THRESHOLD,
    ):
        self.model_high_threshold = model_high_threshold
        self.model_medium_threshold = model_medium_threshold

    def evaluate(
        self,
        norm: NormalizedURL,
        model: URLModelEvidence,
        ti: ThreatIntelEvidence,
    ) -> Tuple[SecurityVerdict, str, List[str], AlertCode, str, str, str, str]:
        """
        Risk Fusion Decision Logic for single-phase URL/URI evaluation.
        Returns:
            (verdict, severity, reason_codes, alert_code, alert_color, alert_title, alert_message, alert_recommendation)
        """
        reason_codes: List[str] = []

        # ------------------------------------------------------------
        # Category A: Invalid URL syntax
        # ------------------------------------------------------------
        if not norm.is_valid:
            reason_codes.append("URL_SYNTAX_INVALID")
            return (
                SecurityVerdict.INVALID,
                "high",
                reason_codes,
                AlertCode.INVALID_PAYLOAD,
                "#616161",
                "⚠️ Liên kết không hợp lệ hoặc bị lỗi cú pháp",
                f"Không thể phân tích cú pháp liên kết: {norm.error or 'Cấu trúc sai định dạng'}",
                "Không mở liên kết này. Hãy yêu cầu người gửi cung cấp mã QR chuẩn.",
            )

        # ------------------------------------------------------------
        # Category B: Informational protocols (mailto, tel, sms)
        # ------------------------------------------------------------
        if norm.scheme in self.INFORMATIONAL_SCHEMES:
            reason_codes.append(f"URI_SCHEME_{norm.scheme.upper()}")
            reason_codes.append("UNSUPPORTED_URI")
            return (
                SecurityVerdict.NO_KNOWN_RISK,
                "low",
                reason_codes,
                AlertCode.UNSUPPORTED_URI,
                "#1565C0",
                f"ℹ️ Liên kết giao thức {norm.scheme.upper()}",
                f"Đây là liên kết mở tác vụ {norm.scheme.upper()} trên thiết bị: {norm.original_url[:120]}",
                "Kiểm tra kỹ thông tin liên hệ trước khi gọi hoặc gửi tin nhắn.",
            )

        # ------------------------------------------------------------
        # Category C: Known dangerous protocols (javascript, data, file, intent, blob, vbscript)
        # ------------------------------------------------------------
        if norm.scheme in self.DANGEROUS_SCHEMES:
            reason_codes.append("DANGEROUS_SCHEME")
            return (
                SecurityVerdict.SUSPICIOUS,
                "critical",
                reason_codes,
                AlertCode.URL_SUSPICIOUS,
                "#C62828",
                "🚨 Liên kết chứa Giao thức Độc hại Nguy hiểm",
                f"Liên kết sử dụng giao thức '{norm.scheme}:' có nguy cơ thực thi mã độc hoặc khai thác lỗ hổng trình duyệt/thiết bị.",
                "TUYỆT ĐỐI KHÔNG mở hoặc quét liên kết này.",
            )

        # ------------------------------------------------------------
        # Category D: Any other unsupported non-HTTP(S) URI scheme (ftp, customscheme, etc.)
        # Never return NO_KNOWN_RISK because web security checks did not evaluate it.
        # ------------------------------------------------------------
        if norm.scheme not in ("http", "https"):
            reason_codes.append("UNSUPPORTED_URI_SCHEME")
            return (
                SecurityVerdict.UNVERIFIABLE,
                "low",
                reason_codes,
                AlertCode.URL_UNVERIFIABLE,
                "#546E7A",
                f"ℹ️ Giao thức không được hỗ trợ phân tích: {norm.scheme.upper() if norm.scheme else 'UNKNOWN'}",
                f"QRDetec chỉ hỗ trợ kiểm tra an ninh chuyên sâu cho liên kết web (HTTP/HTTPS). Giao thức '{norm.scheme}:' không nằm trong phạm vi đánh giá.",
                "Tự kiểm tra tính an toàn của ứng dụng hoặc liên kết trước khi thực hiện.",
            )

        # ------------------------------------------------------------
        # Category E: Valid HTTP/HTTPS URLs — evaluate Normalizer Guardrails, ML Model, Local IOC
        # ------------------------------------------------------------
        has_userinfo = bool(norm.has_userinfo)
        has_private_host = bool(norm.is_private_or_local)
        has_obfuscated_host = bool(getattr(norm, "host_obfuscated", False))

        if has_userinfo:
            reason_codes.append("URL_USERINFO_PRESENT")
        if has_private_host:
            reason_codes.append("PRIVATE_OR_LOCAL_HOST")
        if has_obfuscated_host:
            reason_codes.append("OBFUSCATED_HOST")
        if getattr(norm, "embedded_urls", None):
            reason_codes.append("EMBEDDED_REDIRECT_URL")

        # Calibrated XGBoost AI Model evidence
        model_score = model.model_score
        model_ready = model.model_status == "READY" and model_score is not None
        high_thresh = (
            model.ml_threshold
            if (model.ml_threshold is not None and 0.0 < model.ml_threshold < 1.0)
            else self.model_high_threshold
        )
        has_high_ml = model_ready and (model.ml_prediction == 1 or model_score >= high_thresh)
        has_medium_ml = model_ready and (not has_high_ml) and (model_score >= self.model_medium_threshold)

        if has_high_ml:
            reason_codes.append("URL_XGB_HIGH_SCORE")
        elif has_medium_ml:
            reason_codes.append("URL_XGB_MEDIUM_SCORE")

        # Surface semantic reason codes from TreeSHAP top risk features when ML flags risk
        if has_high_ml or has_medium_ml:
            active_shap_feats = {
                item.feature
                for item in (model.shap_top_risk or [])
                if item.value > 0 and item.shap_value > 0
            }
            if (
                active_shap_feats
                & {
                    "hostname_confusable_brand_match",
                    "hostname_mixed_script",
                    "hostname_is_punycode",
                    "brand_homoglyph_similarity",
                }
                or norm.is_punycode
            ):
                reason_codes.append("IDN_BRAND_HOMOGRAPH")
            if "brand_token_in_subdomain" in active_shap_feats:
                reason_codes.append("BRAND_IN_SUBDOMAIN")
            if active_shap_feats & {
                "brand_official_domain_mismatch",
                "brand_token_in_registered_domain",
                "brand_lookalike_distance",
            }:
                reason_codes.append("BRAND_LOOKALIKE_DOMAIN")

        # Local Threat Intelligence evidence
        local_ti_status = getattr(ti, "local_ti_status", "NOT_CONFIGURED")
        if local_ti_status == "NOT_CONFIGURED":
            if ti.status in ("known_malicious", "malicious"):
                local_ti_status = "MATCH"
            elif ti.status == "suspicious":
                local_ti_status = "MATCH"
            elif ti.status in ("INTEGRITY_FAILED", "LOAD_ERROR"):
                local_ti_status = ti.status
            elif ti.status == "no_known_risk":
                local_ti_status = "NO_MATCH"

        ti_stale = getattr(ti, "freshness", None) == "stale"
        is_known_malicious_ti = (
            local_ti_status == "MATCH"
            and not ti_stale
            and (ti.status in ("known_malicious", "malicious") or ti.malicious_count > 0 or not ti.suspicious_count)
        )
        is_suspicious_ti = local_ti_status == "MATCH" and not ti_stale and not is_known_malicious_ti
        embedded_match = ti.scope == "ioc_embedded"

        if is_known_malicious_ti:
            reason_codes.append("TI_KNOWN_MALICIOUS")
            if embedded_match:
                reason_codes.append("TI_EMBEDDED_URL_MATCH")
        elif is_suspicious_ti:
            reason_codes.append("TI_SUSPICIOUS")
        elif ti_stale:
            reason_codes.append("TI_IOC_STALE")
        elif local_ti_status in ("INTEGRITY_FAILED", "LOAD_ERROR"):
            reason_codes.append("TI_NOT_CONSULTED")
            reason_codes.append(f"TI_{local_ti_status}")
        elif local_ti_status == "NO_MATCH":
            reason_codes.append("LOCAL_IOC_NO_MATCH")
        elif local_ti_status == "NOT_CONFIGURED":
            reason_codes.append("TI_NOT_CONSULTED")
            reason_codes.append("TI_NOT_CONFIGURED")

        # ------------------------------------------------------------
        # Decision Tree for HTTP/HTTPS URLs
        # ------------------------------------------------------------

        # 1. MALICIOUS: Confirmed by Local Threat Intelligence match
        if is_known_malicious_ti:
            sources_str = ", ".join(ti.sources) if ti.sources else "Cơ sở dữ liệu tình báo mối đe dọa cục bộ"
            target = "Địa chỉ đích lồng bên trong liên kết" if embedded_match else "Tên miền / URL"
            return (
                SecurityVerdict.MALICIOUS,
                "critical",
                reason_codes,
                AlertCode.URL_MALICIOUS,
                "#B71C1C",  # Red
                "🚨 Phát hiện Liên kết Độc hại (Threat Intelligence xác nhận)",
                f"• {target}: {norm.hostname}\n"
                f"• Nguồn tình báo: {sources_str} ({ti.malicious_count or 1} nguồn phát hiện)\n"
                f"• Chi tiết: {ti.details or 'Mã độc, lừa đảo hoặc máy chủ đánh cắp thông tin đã được ghi nhận.'}",
                "TUYỆT ĐỐI KHÔNG mở liên kết này. Đây là mã QR giả mạo phục vụ tấn công mạng hoặc đánh cắp tài khoản.",
            )

        # 2. MALICIOUS: Calibrated XGBoost AI Model exceeds operating threshold (ml_prediction == 1)
        if has_high_ml:
            shap_lines = []
            for item in (model.shap_top_risk or [])[:3]:
                shap_lines.append(f"  - {item.label} ({item.feature} = {item.value:g}, SHAP +{item.shap_value:.2f})")
            shap_detail = ("\n• Đặc trưng rủi ro nổi bật (TreeSHAP):\n" + "\n".join(shap_lines)) if shap_lines else ""
            return (
                SecurityVerdict.MALICIOUS,
                "high",
                reason_codes,
                AlertCode.URL_MALICIOUS,
                "#B71C1C",  # Red
                "🚨 Phát hiện Liên kết Độc hại / Lừa đảo (Mô hình AI XGBoost)",
                f"• Địa chỉ đích: {norm.hostname}\n"
                f"• Xác suất độc hại sau hiệu chuẩn (Isotonic): {model_score * 100:.1f}% (Ngưỡng chặn: {high_thresh * 100:.1f}%)"
                f"{shap_detail}",
                "TUYỆT ĐỐI KHÔNG mở liên kết này, không nhập mật khẩu hoặc mã OTP. Đây là liên kết có cấu trúc lừa đảo/giả mạo.",
            )

        # 3. SUSPICIOUS: Protocol/Network Guardrails, Suspicious/Stale Local IOC, or Medium AI Score
        if has_userinfo or has_private_host or has_obfuscated_host or is_suspicious_ti or ti_stale or has_medium_ml:
            reasons_text = []
            if has_userinfo:
                reasons_text.append(f"• Dấu hiệu đánh lừa danh tính: Userinfo '{norm.userinfo}@' nhằm ngụy trang tên miền thật '{norm.hostname}'")
            if has_obfuscated_host:
                reasons_text.append(f"• Địa chỉ máy chủ bị viết dưới dạng che giấu (thực tế: {norm.hostname})")
            if has_private_host:
                reasons_text.append(f"• Máy chủ trỏ về mạng nội bộ hoặc localhost: {norm.hostname}")
            if is_suspicious_ti:
                reasons_text.append(f"• Threat Intelligence ghi nhận nghi vấn ({ti.suspicious_count or 1} nguồn cảnh báo)")
            if ti_stale:
                reasons_text.append("• Tên miền từng bị ghi nhận lừa đảo trong dữ liệu cũ (dữ liệu đã hết hạn, chưa được xác nhận lại)")
            if has_medium_ml:
                reasons_text.append(f"• Mô hình AI phát hiện đặc trưng tương tự trang đáng ngờ (xác suất hiệu chuẩn: {model_score * 100:.1f}%)")
                for item in (model.shap_top_risk or [])[:2]:
                    reasons_text.append(f"  - {item.label} (SHAP +{item.shap_value:.2f})")

            sev = "high" if (has_userinfo or has_private_host or has_obfuscated_host or is_suspicious_ti) else "medium"
            return (
                SecurityVerdict.SUSPICIOUS,
                sev,
                reason_codes,
                AlertCode.URL_SUSPICIOUS,
                "#E65100" if sev == "high" else "#F57C00",
                "⚠️ Liên kết có Dấu hiệu Đáng ngờ & Cần Thận trọng",
                f"• Địa chỉ đích: {norm.hostname}\n" + "\n".join(reasons_text),
                "Cảnh giác cao độ: KHÔNG nhập mật khẩu, mã OTP, số tài khoản hoặc thông tin cá nhân nếu mở trang web này.",
            )

        # 4. UNVERIFIABLE: Local feed integrity/loading error or both AI and TI unavailable
        if local_ti_status in ("INTEGRITY_FAILED", "LOAD_ERROR") or (not model_ready and local_ti_status != "NO_MATCH"):
            reason_codes.append("EVALUATION_INCONCLUSIVE")
            if local_ti_status in ("INTEGRITY_FAILED", "LOAD_ERROR") and f"TI_{local_ti_status}" not in reason_codes:
                reason_codes.append(f"TI_{local_ti_status}")
            return (
                SecurityVerdict.UNVERIFIABLE,
                "low",
                reason_codes,
                AlertCode.URL_UNVERIFIABLE,
                "#546E7A",
                "ℹ️ Chưa đủ dữ liệu để xác minh liên kết",
                f"• Tên miền: {norm.hostname}\n"
                f"• Một phần hệ thống kiểm tra (mô hình AI hoặc cơ sở dữ liệu Local IOC) chưa sẵn sàng ({local_ti_status}).",
                "Hãy tự xác minh tính tin cậy của liên kết trước khi truy cập.",
            )

        # 5. NO_KNOWN_RISK: No known malicious flags detected by AI Model and Local IOC
        reason_codes.append("NO_ANOMALIES_DETECTED")
        done = []
        if model_ready:
            done.append(f"mô hình AI XGBoost 81 đặc trưng ({model_score * 100:.1f}%)")
        if local_ti_status == "NO_MATCH":
            done.append("cơ sở dữ liệu mối đe dọa cục bộ (không trùng khớp)")

        return (
            SecurityVerdict.NO_KNOWN_RISK,
            "low",
            reason_codes,
            AlertCode.URL_NO_KNOWN_RISK,
            "#1B5E20",  # Dark green
            "ℹ️ Chưa phát hiện rủi ro đã biết",
            f"• Tên miền: {norm.hostname}\n"
            f"• Giao thức: {norm.scheme.upper()}\n"
            f"• Đã kiểm tra: {', '.join(done) if done else 'cấu trúc liên kết'} — chưa thấy cảnh báo rõ ràng.",
            "Điều này không có nghĩa liên kết an toàn tuyệt đối. Không cung cấp mật khẩu hoặc mã OTP.",
        )
