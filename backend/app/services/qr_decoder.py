"""
Dual-Stage QR Decoder - OPTIMIZED & HARDENED
Stage 1: pyzbar (fast, C library zbar)  ~5-15ms
Stage 2: WeChatQRCode CNN (deep path)    ~100-300ms

Supports two decoding modes configured via QR_DECODE_MODE:
- 'fast' (default): Early-stop as soon as pyzbar succeeds (optimized for latency).
- 'complete': Runs pyzbar + CLAHE + WeChatQRCode ensemble, merging and deduplicating
  detections by payload AND approximate bounding box (for high-assurance evaluation).
"""
import logging
import math
import threading
from typing import List, Optional, Tuple

import cv2
import numpy as np

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    HAS_PYZBAR = True
except Exception as _pyzbar_err:
    pyzbar_decode = None
    HAS_PYZBAR = False

from app.core.config import settings

logger = logging.getLogger(__name__)


MAX_DECODE_DIMENSION = 2000  # px — resize images larger than this


def resize_if_large(image: np.ndarray) -> Tuple[np.ndarray, float]:
    """Resize image to MAX_DECODE_DIMENSION if needed, preserving aspect ratio. Returns (image, scale)."""
    h, w = image.shape[:2]
    max_dim = max(h, w)
    if max_dim <= MAX_DECODE_DIMENSION:
        return image, 1.0
    scale = MAX_DECODE_DIMENSION / max_dim
    return cv2.resize(image, (int(w * scale), int(h * scale)),
                      interpolation=cv2.INTER_AREA), scale


def _are_bboxes_near(b1: Optional[tuple], b2: Optional[tuple]) -> bool:
    """Checks if two bounding boxes are approximately in the same location."""
    if b1 is None or b2 is None:
        return True  # If either has no bbox, assume duplicate of same payload

    x1, y1, w1, h1 = b1
    x2, y2, w2, h2 = b2

    cx1, cy1 = x1 + w1 / 2.0, y1 + h1 / 2.0
    cx2, cy2 = x2 + w2 / 2.0, y2 + h2 / 2.0

    dist = math.hypot(cx1 - cx2, cy1 - cy2)
    avg_size = (w1 + h1 + w2 + h2) / 4.0

    # If center distance is less than 50% of average QR size, consider same location
    return dist < max(20.0, avg_size * 0.5)


def _bbox_iou(b1: Optional[tuple], b2: Optional[tuple]) -> float:
    """Computes Intersection-over-Union (IoU) of two (x, y, w, h) bounding boxes."""
    if b1 is None or b2 is None:
        return 0.0
    x1, y1, w1, h1 = b1
    x2, y2, w2, h2 = b2
    if w1 <= 0 or h1 <= 0 or w2 <= 0 or h2 <= 0:
        return 0.0
    ix1, iy1 = max(x1, x2), max(y1, y2)
    ix2, iy2 = min(x1 + w1, x2 + w2), min(y1 + h1, y2 + h2)
    iw, ih = max(0, ix2 - ix1), max(0, iy2 - iy1)
    inter = iw * ih
    if inter <= 0:
        return 0.0
    union = (w1 * h1) + (w2 * h2) - inter
    return inter / union if union > 0 else 0.0


def _repair_zbar_utf8(text: str) -> str:
    """
    Repairs libzbar mojibake when UTF-8 QR byte streams without an ECI header are
    misinterpreted by zbar as Latin-1, Big5, or Shift-JIS before re-encoding to UTF-8
    (e.g., UTF-8 Cyrillic 'а' 0xD0 0xB0 decoded as Big5 '訄' U+8A04).
    """
    if not text or text.isascii():
        return text
    for enc in ("latin-1", "big5", "shift_jis"):
        try:
            raw = text.encode(enc)
            cand = raw.decode("utf-8", errors="strict")
            if cand != text and all(c.isprintable() or c in "\r\n\t" for c in cand):
                return cand
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
    return text


class DualStageQRDecoder:
    """
    Ensemble Dual-Stage QR Decoder.
    Supports 'fast' (latency-optimized) and 'complete' (high-assurance) modes.
    """

    _lock = threading.Lock()

    def __init__(self, model_dir: Optional[str] = None):
        self._wechat: Optional[cv2.wechat_qrcode_WeChatQRCode] = None
        self._model_dir = model_dir or settings.WECHAT_QR_MODEL_DIR
        self._wechat_loaded = False
        self._cv_detector = None

    def available_engines(self) -> List[str]:
        """Engines actually usable in this process (reported in health/benchmarks)."""
        if not self._wechat_loaded:
            self._load_wechat()
        engines = []
        if HAS_PYZBAR:
            engines.append("pyzbar")
        if self._wechat is not None:
            engines.append("wechat_qrcode")
        engines.append("opencv_qr")
        return engines

    def warmup(self):
        """Pre-warm WeChatQR model at worker startup."""
        self._load_wechat()
        if not HAS_PYZBAR:
            logger.warning("pyzbar/zbar unavailable — relying on WeChatQR/OpenCV decoders")

    def _load_wechat(self):
        """Load WeChatQRCode model (thread-safe)."""
        with self._lock:
            if self._wechat_loaded:
                return
            try:
                self._wechat = cv2.wechat_qrcode_WeChatQRCode(
                    f"{self._model_dir}/detect.prototxt",
                    f"{self._model_dir}/detect.caffemodel",
                    f"{self._model_dir}/sr.prototxt",
                    f"{self._model_dir}/sr.caffemodel",
                )
                self._wechat_loaded = True
                logger.info("WeChatQRCode model loaded successfully")
            except Exception as e:
                logger.warning("WeChatQRCode model load failed: %s", type(e).__name__)
                self._wechat_loaded = True

    def _opencv_decode(self, image: np.ndarray) -> List[dict]:
        """Built-in OpenCV QR detector: last-resort fallback, no extra dependency."""
        try:
            if self._cv_detector is None:
                self._cv_detector = cv2.QRCodeDetector()
            ok, texts, points, _ = self._cv_detector.detectAndDecodeMulti(image)
            results = []
            if ok and points is not None:
                for text, pts in zip(texts, points):
                    if text:
                        x, y, w, h = cv2.boundingRect(np.asarray(pts, dtype=np.float32).astype(np.int32))
                        results.append({
                            "payload": text.strip(),
                            "bbox": (int(x), int(y), int(w), int(h)),
                            "engine": "opencv_qr",
                        })
            return results
        except Exception as e:
            logger.debug("OpenCV QR decode error: %s", type(e).__name__)
            return []

    def _pyzbar_decode_gray(self, gray: np.ndarray) -> List[dict]:
        if not HAS_PYZBAR:
            return []
        try:
            barcodes = pyzbar_decode(gray)
            results = []
            for barcode in barcodes:
                if barcode.type == "QRCODE":
                    pts = np.array(barcode.polygon, dtype=np.int32).reshape((-1, 1, 2))
                    x, y, w, h = cv2.boundingRect(pts)
                    results.append({
                        "payload": _repair_zbar_utf8(barcode.data.decode("utf-8", errors="replace").strip()),
                        "bbox": (int(x), int(y), int(w), int(h)),
                        "engine": "pyzbar",
                    })
            return results
        except Exception as e:
            logger.warning(f"pyzbar error: {e}")
            return []

    def _wechat_decode(self, image: np.ndarray) -> List[dict]:
        if not self._wechat_loaded:
            self._load_wechat()
        if self._wechat is None:
            return []
        try:
            texts, points = self._wechat.detectAndDecode(image)
            results = []
            for text, pts in zip(texts, points):
                if text and pts is not None:
                    x, y, w, h = cv2.boundingRect(pts.astype(int))
                    results.append({
                        "payload": text.strip(),
                        "bbox": (int(x), int(y), int(w), int(h)),
                        "engine": "wechat_qrcode",
                    })
            return results
        except Exception as e:
            logger.warning(f"WeChatQRCode error: {e}")
            return []

    def _deduplicate_results(self, items: List[dict]) -> List[dict]:
        """
        Deduplicates results based on payload AND approximate bounding box.
        Keeps duplicate payloads if they appear at distinctly different coordinates.
        """
        unique: List[dict] = []
        for item in items:
            p = item.get("payload", "").strip()
            if not p:
                continue

            box = item.get("bbox")
            is_dup = False
            for existing in unique:
                if existing.get("payload") != p and _bbox_iou(box, existing.get("bbox")) >= 0.70:
                    if item.get("engine") == "wechat_qrcode" and existing.get("engine") == "pyzbar":
                        existing.update(item)
                    is_dup = True
                    break
                if existing.get("payload") == p:
                    if _are_bboxes_near(box, existing.get("bbox")):
                        is_dup = True
                        break
            if not is_dup:
                unique.append(item)
        return unique

    def decode_array(self, image: np.ndarray, mode: Optional[str] = None) -> List[dict]:
        """
        Smart preprocessing pipeline on resized BGR image.
        Mode:
        - 'fast' (default): Returns as soon as pyzbar or CLAHE succeeds.
        - 'complete': Runs all passes (pyzbar + CLAHE + WeChatQR) and merges results
          deduplicating by payload + approximate bbox.
        """
        if image is None or image.size == 0:
            return []

        decode_mode = (mode or settings.QR_DECODE_MODE).lower()

        # ── Fast Mode: Early-stop pipeline ──────────────────────────
        if decode_mode != "complete":
            # 1. pyzbar on raw image
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            results = self._deduplicate_results(self._pyzbar_decode_gray(gray))

            # 2. CLAHE preprocessing for low contrast/faded QR
            if not results:
                try:
                    clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
                    results = self._deduplicate_results(self._pyzbar_decode_gray(clahe.apply(gray)))
                except Exception as e:
                    logger.debug(f"CLAHE preprocessing failed: {e}")

            if results:
                # Quishing overlays often place a small/rotated sticker QR next to (or on top of)
                # the genuine one. pyzbar regularly finds only the larger code, so a single extra
                # CNN sweep is run and merged instead of returning after the first hit.
                if settings.QR_FAST_MULTI_SWEEP:
                    results = self._deduplicate_results(results + self._wechat_decode(image))
                return results

            # 3. WeChatQRCode CNN fallback
            results = self._deduplicate_results(self._wechat_decode(image))
            if results:
                return results

            # 4. OpenCV built-in detector (covers missing zbar / WeChat model)
            return self._deduplicate_results(self._opencv_decode(image))

        # ── Complete Mode: Full ensemble pipeline ───────────────────
        all_detections: List[dict] = []
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

        # Pass 1: pyzbar
        all_detections.extend(self._pyzbar_decode_gray(gray))

        # Pass 2: CLAHE + pyzbar
        try:
            clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
            all_detections.extend(self._pyzbar_decode_gray(clahe.apply(gray)))
        except Exception as e:
            logger.debug(f"CLAHE failed: {e}")

        # Pass 3: WeChatQRCode CNN
        all_detections.extend(self._wechat_decode(image))

        # Pass 4: OpenCV built-in detector
        all_detections.extend(self._opencv_decode(image))

        # Merge and deduplicate by payload + bbox
        return self._deduplicate_results(all_detections)
