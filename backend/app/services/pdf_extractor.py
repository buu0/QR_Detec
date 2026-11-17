"""
PDF Extraction Service using PyMuPDF (fitz) - HARDENED

Features:
1. Calculates projected pixel dimensions BEFORE rendering with page.get_pixmap.
2. Strictly enforces MAX_PDF_PAGES, MAX_PDF_PAGE_PIXELS, and MAX_TOTAL_RENDERED_PIXELS
   to block PDF decompression bombs and excessive resource exhaustion.
3. Extracts vector text layer with coordinates.
   Only text a human can actually SEE is kept. Spans that are invisible
   (render mode 3 / opacity 0), microscopic, outside the page, or leave no ink on
   the rendered page are dropped and counted (`hidden_text_spans`). The text layer
   is never treated as complete: the worker cross-checks it with OCR.
4. Fail-closed: unreadable / encrypted PDFs raise instead of silently returning nothing.
5. Partial coverage (page cap, page render failure) is reported, never hidden.
"""
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import cv2
import numpy as np

from app.core.config import settings
from app.services.context_extractor import TextLine
from app.services.file_safety import EncryptedPdfError, InvalidFileError, ResourceLimitExceeded

logger = logging.getLogger(__name__)

RENDER_DPI = 200
MIN_VISIBLE_FONT_PT = 3.0      # chữ nhỏ hơn ~3pt không đọc được bằng mắt
MIN_INK_CONTRAST = 40          # độ chênh xám (0-255) tối thiểu trong vùng chữ để coi là "có nét"

__all__ = [
    "ResourceLimitExceeded", "InvalidFileError", "EncryptedPdfError",
    "PdfPage", "PdfExtraction", "extract_pdf", "extract_pages_from_pdf",
]


@dataclass
class PdfPage:
    image: np.ndarray                       # BGR, pixel coordinates at RENDER_DPI
    lines: List[TextLine] = field(default_factory=list)
    page_number: int = 0
    hidden_text_spans: int = 0              # spans dropped as not visible


@dataclass
class PdfExtraction:
    pages: List[PdfPage]
    total_pages: int
    skipped_pages: List[int] = field(default_factory=list)   # 1-based
    page_cap_applied: bool = False

    @property
    def partial(self) -> bool:
        return self.page_cap_applied or bool(self.skipped_pages)


def _invisible_trace_spans(page) -> List[Tuple[str, Tuple[float, float, float, float]]]:
    """(text, bbox) of spans drawn with render mode 3 ("ignore") or zero opacity."""
    out: List[Tuple[str, Tuple[float, float, float, float]]] = []
    try:
        traces = page.get_texttrace()
    except Exception as e:  # older PyMuPDF / damaged content stream
        logger.debug("get_texttrace failed: %s", type(e).__name__)
        return out
    for tr in traces:
        if tr.get("type") == 3 or float(tr.get("opacity", 1.0) or 0.0) <= 0.0:
            text = "".join(chr(c[0]) for c in tr.get("chars", ()) if c and c[0] > 0).strip()
            if text:
                out.append((text, tuple(tr.get("bbox", (0, 0, 0, 0)))))
    return out


def _overlaps(a, b) -> bool:
    return not (a[2] <= b[0] or b[2] <= a[0] or a[3] <= b[1] or b[3] <= a[1])


def _has_ink(gray: Optional[np.ndarray], bbox, zoom: float) -> bool:
    """True if the rendered page shows visible strokes inside bbox (PDF points)."""
    if gray is None:
        return True  # cannot verify → do not drop
    h, w = gray.shape[:2]
    x0 = max(0, int(bbox[0] * zoom)); y0 = max(0, int(bbox[1] * zoom))
    x1 = min(w, int(round(bbox[2] * zoom)) + 1); y1 = min(h, int(round(bbox[3] * zoom)) + 1)
    if x1 - x0 < 1 or y1 - y0 < 1:
        return False
    roi = gray[y0:y1, x0:x1]
    return int(roi.max()) - int(roi.min()) >= MIN_INK_CONTRAST


def _span_visible(span, page_rect, invisible, gray, zoom: float) -> bool:
    text = (span.get("text") or "").strip()
    if not text:
        return False
    bbox = tuple(span.get("bbox", (0, 0, 0, 0)))
    if float(span.get("size", 0.0) or 0.0) < MIN_VISIBLE_FONT_PT:
        return False
    if "alpha" in span and int(span.get("alpha") or 0) == 0:
        return False
    if not _overlaps(bbox, (page_rect.x0, page_rect.y0, page_rect.x1, page_rect.y1)):
        return False
    for inv_text, inv_bbox in invisible:
        if _overlaps(bbox, inv_bbox) and (inv_text in text or text in inv_text):
            return False
    return _has_ink(gray, bbox, zoom)


def _page_text_lines(page, zoom: float, image: Optional[np.ndarray] = None) -> Tuple[List[TextLine], int]:
    """Returns (visible text lines, number of hidden spans dropped)."""
    lines: List[TextLine] = []
    hidden = 0
    try:
        data = page.get_text("dict")
    except Exception as e:
        logger.debug("get_text failed: %s", type(e).__name__)
        return lines, hidden

    invisible = _invisible_trace_spans(page)
    gray = None
    if image is not None and image.size:
        try:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY) if image.ndim == 3 else image
        except Exception:
            gray = None
    page_rect = page.rect

    for block in data.get("blocks", []):
        if block.get("type") != 0:          # 0 = text block
            continue
        for ln in block.get("lines", []):
            visible_spans = []
            for span in ln.get("spans", []):
                if not (span.get("text") or "").strip():
                    continue
                if _span_visible(span, page_rect, invisible, gray, zoom):
                    visible_spans.append(span)
                else:
                    hidden += 1
            text = "".join(span.get("text", "") for span in visible_spans).strip()
            if not text:
                continue
            x0 = min(s["bbox"][0] for s in visible_spans); y0 = min(s["bbox"][1] for s in visible_spans)
            x1 = max(s["bbox"][2] for s in visible_spans); y1 = max(s["bbox"][3] for s in visible_spans)
            lines.append(TextLine(
                text=text,
                conf=1.0,
                cx=(x0 + x1) / 2.0 * zoom,
                cy=(y0 + y1) / 2.0 * zoom,
                w=(x1 - x0) * zoom,
                h=(y1 - y0) * zoom,
            ))
    lines.sort(key=lambda t: (round(t.cy / 15), t.cx))
    if hidden:
        logger.info("PDF page: dropped %d non-visible text span(s)", hidden)
    return lines, hidden


def extract_pdf(pdf_bytes: bytes) -> PdfExtraction:
    import fitz  # PyMuPDF (lazy: keeps the module importable where PyMuPDF is absent)

    zoom = RENDER_DPI / 72.0
    mat = fitz.Matrix(zoom, zoom)

    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception as e:
        logger.warning("Cannot open PDF: %s", type(e).__name__)
        raise InvalidFileError("pdf open failed")

    total_rendered_pixels = 0
    pages: List[PdfPage] = []
    skipped: List[int] = []

    with doc:
        if getattr(doc, "needs_pass", False) or getattr(doc, "is_encrypted", False):
            raise EncryptedPdfError("pdf is password protected")
        page_count = len(doc)
        if page_count <= 0:
            raise InvalidFileError("pdf has no pages")
        cap_applied = page_count > settings.MAX_PDF_PAGES
        if cap_applied:
            logger.info("PDF has %d pages, analysing first %d (PARTIAL_ANALYSIS)", page_count, settings.MAX_PDF_PAGES)

        for page_num in range(min(page_count, settings.MAX_PDF_PAGES)):
            page = doc[page_num]
            rect = page.rect

            # 1. Calculate projected pixel dimensions BEFORE allocating pixmap buffer
            proj_w = int(rect.width * zoom)
            proj_h = int(rect.height * zoom)
            proj_pixels = proj_w * proj_h

            if proj_w > settings.MAX_PDF_PAGE_WIDTH or proj_h > settings.MAX_PDF_PAGE_HEIGHT or proj_pixels > settings.MAX_PDF_PAGE_PIXELS:
                raise ResourceLimitExceeded(
                    f"Trang PDF #{page_num + 1} vượt giới hạn độ phân giải ({proj_w}x{proj_h}px, tối đa {settings.MAX_PDF_PAGE_WIDTH}x{settings.MAX_PDF_PAGE_HEIGHT}px)"
                )

            total_rendered_pixels += proj_pixels
            if total_rendered_pixels > settings.MAX_TOTAL_RENDERED_PIXELS:
                raise ResourceLimitExceeded(
                    f"Tổng dung lượng điểm ảnh PDF vượt giới hạn an toàn ({total_rendered_pixels}px, tối đa {settings.MAX_TOTAL_RENDERED_PIXELS}px)"
                )

            try:
                pix = page.get_pixmap(matrix=mat, alpha=False)
                img = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)
                if pix.n == 1:
                    img = cv2.cvtColor(img, cv2.COLOR_GRAY2BGR)
                else:
                    img = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)
            except Exception as e:
                logger.warning("Render page %d failed: %s", page_num + 1, type(e).__name__)
                skipped.append(page_num + 1)
                continue

            text_lines, hidden = _page_text_lines(page, zoom, img)
            pages.append(PdfPage(image=img, lines=text_lines, page_number=page_num + 1, hidden_text_spans=hidden))

    if not pages:
        raise InvalidFileError("no page could be rendered")

    logger.info("PDF extraction complete: %d/%d pages rendered", len(pages), page_count)
    return PdfExtraction(pages=pages, total_pages=page_count, skipped_pages=skipped, page_cap_applied=cap_applied)


def extract_pages_from_pdf(pdf_bytes: bytes) -> List[PdfPage]:
    """Backward-compatible wrapper returning only the rendered pages."""
    return extract_pdf(pdf_bytes).pages
