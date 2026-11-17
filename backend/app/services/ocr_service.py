"""
OCR Service using PaddleOCR PP-OCRv4 (Vietnamese)
Đọc văn bản NGỮ CẢNH quanh mã QR (hoá đơn, standee, poster, ảnh chụp màn hình...)

Tối ưu tốc độ so với bản cũ:
- Chỉ chạy OCR MỘT lần trên toàn ảnh (bản cũ chạy ROI + toàn trang = 2 lần)
- Trả về dòng chữ kèm toạ độ tâm → ưu tiên thông tin gần QR bằng khoảng cách,
  không cần OCR riêng vùng ROI
- Worker cache kết quả theo ảnh → nhiều QR trên cùng ảnh chỉ OCR 1 lần
- Bóc tách thực thể nằm ở context_extractor (thuần Python)
"""
import logging
import threading
from typing import List, Optional, Tuple

import numpy as np

from app.core.config import settings
from app.services.context_extractor import TextLine

logger = logging.getLogger(__name__)

MIN_CONFIDENCE = 0.30

# ─── Global / Thread-local PaddleOCR singleton (lazy-loaded) ────────────────
_ocr_engine = None
_ocr_tls = threading.local()
_ocr_init_failed = False
_ocr_lock = threading.Lock()   # PaddleOCR predictor is not thread-safe; also caps per-process concurrency


def _get_ocr_engine():
    """Lazy-load PaddleOCR per OS thread so Paddle primitives never cross thread boundaries."""
    global _ocr_engine, _ocr_init_failed
    if _ocr_engine is not None:
        return _ocr_engine
    engine = getattr(_ocr_tls, "engine", None)
    if engine is None and not _ocr_init_failed:
        with _ocr_lock:
            engine = getattr(_ocr_tls, "engine", None)
            if engine is None and not _ocr_init_failed:
                try:
                    from paddleocr import PaddleOCR
                    engine = PaddleOCR(
                        lang=settings.PADDLE_OCR_LANG or "vi",
                        use_angle_cls=True,
                        show_log=False,
                        use_gpu=False,
                        enable_mkldnn=False,  # Tránh JIT compilation 33s trên container CPU
                        cpu_threads=2,        # Giới hạn thread để không tranh tài nguyên Celery
                    )
                    _ocr_tls.engine = engine
                    logger.info("PaddleOCR engine initialized (Vietnamese latin model)")
                except Exception as e:
                    # Remember the failure: do not pay the import/init cost again on every job.
                    _ocr_init_failed = True
                    logger.error("PaddleOCR init failed: %s", type(e).__name__)
    return engine


# Public alias để worker có thể pre-warm
get_ocr_engine = _get_ocr_engine


def warmup_ocr():
    """Chạy thử 1 lần trên ảnh nhỏ để khởi tạo mô hình OCR trước request đầu tiên."""
    ocr = _get_ocr_engine()
    if ocr is None:
        return
    dummy = np.full((64, 256, 3), 255, dtype=np.uint8)
    try:
        ocr.ocr(dummy, cls=True)
    except Exception as e:
        logger.debug(f"OCR warmup run failed: {e}")


def _preprocess_image_for_ocr(image: np.ndarray) -> Tuple[np.ndarray, float]:
    """
    Tiền xử lý ảnh tăng cường chất lượng và tốc độ cho OCR tiếng Việt:
    - Nếu ảnh quá lớn (> 1600px), thu nhỏ để tăng tốc PaddleOCR 3-5 lần mà không giảm độ chính xác
    - Nếu ảnh quá nhỏ (< 700px), phóng to để bắt rõ nét chữ
    - Cân bằng tương phản CLAHE nếu mờ hoặc ngược sáng
    Trả về: (ảnh_tiền_xử_lý, hệ_số_co_giãn)
    """
    if image is None or image.size == 0:
        return image, 1.0
    scale = 1.0
    try:
        import cv2
        h, w = image.shape[:2]
        max_dim = max(h, w)
        if max_dim > 1600:
            scale = 1600.0 / max_dim
            image = cv2.resize(image, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
        elif max_dim < 700 and min(h, w) > 50:
            scale = 800.0 / max_dim
            image = cv2.resize(image, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_CUBIC)

        # Cân bằng tương phản nếu ảnh màu
        if len(image.shape) == 3 and image.shape[2] == 3:
            lab = cv2.cvtColor(image, cv2.COLOR_BGR2LAB)
            l, a, b = cv2.split(lab)
            l_std = float(np.std(l))
            l_mean = float(np.mean(l))
            if l_std < 40 or l_mean < 85 or l_mean > 210:
                clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
                cl = clahe.apply(l)
                enhanced_lab = cv2.merge((cl, a, b))
                return cv2.cvtColor(enhanced_lab, cv2.COLOR_LAB2BGR), scale
        return image, scale
    except Exception as e:
        logger.debug(f"OCR image preprocess fallback: {e}")
        return image, scale


def run_ocr_lines_with_status(
    image: np.ndarray,
    qr_bbox: Optional[Tuple[int, int, int, int]] = None,
) -> Tuple[List[TextLine], str]:
    """
    Same as run_ocr_lines but also returns a status:
    ok | no_text | unavailable | error. Callers must NOT treat unavailable/error as "no mismatch".
    """
    ocr = _get_ocr_engine()
    if ocr is None:
        return [], "unavailable"
    if image is None or image.size == 0:
        return [], "error"
    try:
        lines = run_ocr_lines(image, qr_bbox, _raise=True)
    except Exception as e:
        logger.warning("OCR error: %s", type(e).__name__)
        return [], "error"
    return lines, ("ok" if lines else "no_text")


def run_ocr_lines(
    image: np.ndarray,
    qr_bbox: Optional[Tuple[int, int, int, int]] = None,
    _raise: bool = False,
) -> List[TextLine]:
    """
    OCR ảnh, trả về danh sách dòng chữ kèm toạ độ tâm, kích thước và vị trí tương đối với QR.
    - Áp dụng tiền xử lý tăng tương phản
    - Tối ưu kích thước đầu vào (tăng tốc 3-5x) và quy đổi toạ độ chính xác về ảnh gốc
    - Hạ ngưỡng confidence = 0.30 để không bỏ sót tiếng Việt có dấu
    - Gom dòng thích ứng theo chiều cao chữ trung bình thay vì magic number cố định
    """
    ocr = _get_ocr_engine()
    if ocr is None or image is None or image.size == 0:
        return []

    # Tiền xử lý ảnh và lấy hệ số co giãn
    proc_img, scale = _preprocess_image_for_ocr(image)

    try:
        with _ocr_lock:
            results = ocr.ocr(proc_img, cls=True)
    except Exception as e:
        if _raise:
            raise
        logger.warning("OCR error: %s", type(e).__name__)
        return []

    lines: List[TextLine] = []
    if not results or not results[0]:
        return lines

    for item in results[0]:
        if not item or len(item) < 2:
            continue
        box, (text, conf) = item[0], item[1]
        clean_txt = text.strip()
        if conf < MIN_CONFIDENCE or not clean_txt:
            continue
        pts = np.asarray(box, dtype=np.float32)
        if scale != 1.0 and scale > 0:
            pts = pts / scale
        cx = float(pts[:, 0].mean())
        cy = float(pts[:, 1].mean())
        w = float(np.linalg.norm(pts[1] - pts[0]))
        h = float(np.linalg.norm(pts[2] - pts[1]))

        # Xác định vị trí tương đối với mã QR (nếu có qr_bbox)
        rel_pos = None
        if qr_bbox is not None and len(qr_bbox) == 4:
            qx, qy, qw, qh = qr_bbox
            if cy < qy:
                rel_pos = "above"
            elif cy > qy + qh:
                rel_pos = "below"
            elif cx < qx:
                rel_pos = "left"
            elif cx > qx + qw:
                rel_pos = "right"
            else:
                rel_pos = "inside"

        lines.append(TextLine(
            text=clean_txt,
            conf=float(conf),
            cx=cx,
            cy=cy,
            w=w,
            h=h,
            relative_pos=rel_pos,
        ))

    if not lines:
        return []

    # Gom dòng thông minh dựa theo chiều cao hộp chữ trung bình
    heights = [ln.h for ln in lines if ln.h and ln.h > 4]
    avg_h = float(np.median(heights)) if heights else 20.0
    bucket_size = max(avg_h * 0.65, 8.0)
    lines.sort(key=lambda ln: (round((ln.cy or 0.0) / bucket_size), ln.cx or 0.0))
    return lines
