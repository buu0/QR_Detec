"""
PDF text layer must only contribute text a human can actually see (Adversary A3).

The unit tests use a fake PyMuPDF page so they run without PyMuPDF installed.
The last test builds a real PDF and is skipped when PyMuPDF (fitz) is absent.
"""
import numpy as np
import pytest

from app.services.pdf_extractor import _page_text_lines


class _Rect:
    def __init__(self, x0, y0, x1, y1):
        self.x0, self.y0, self.x1, self.y1 = x0, y0, x1, y1


class FakePage:
    def __init__(self, spans, traces=(), rect=(0, 0, 400, 200)):
        self._spans = spans
        self._traces = list(traces)
        self.rect = _Rect(*rect)

    def get_text(self, kind):
        assert kind == "dict"
        return {"blocks": [{"type": 0, "lines": [{"spans": [s]} for s in self._spans]}]}

    def get_texttrace(self):
        return self._traces


def _span(text, bbox, size=10.0):
    return {"text": text, "bbox": bbox, "size": size}


def _trace(text, bbox, type_=3, opacity=1.0):
    return {"type": type_, "opacity": opacity, "bbox": bbox,
            "chars": [(ord(c), 0, (0, 0), bbox) for c in text]}


def _page_image(ink_boxes, shape=(200, 400)):
    """White page; black rectangles where glyphs are 'drawn'. zoom = 1."""
    img = np.full((*shape, 3), 255, dtype=np.uint8)
    for x0, y0, x1, y1 in ink_boxes:
        img[y0:y1, x0:x1] = 0
    return img


VISIBLE = (10, 10, 150, 25)


def test_visible_span_is_kept():
    page = FakePage([_span("STK: 1903 6789 0123", VISIBLE)])
    lines, hidden = _page_text_lines(page, 1.0, _page_image([VISIBLE]))
    assert [l.text for l in lines] == ["STK: 1903 6789 0123"]
    assert hidden == 0


def test_render_mode_3_span_is_dropped_even_over_ink():
    """Invisible text placed on top of a visible image of other text is still dropped."""
    page = FakePage(
        [_span("STK: 9999988888", VISIBLE)],
        traces=[_trace("STK: 9999988888", VISIBLE, type_=3)],
    )
    lines, hidden = _page_text_lines(page, 1.0, _page_image([VISIBLE]))
    assert lines == []
    assert hidden == 1


def test_zero_opacity_span_is_dropped():
    page = FakePage(
        [_span("STK: 9999988888", VISIBLE)],
        traces=[_trace("STK: 9999988888", VISIBLE, type_=0, opacity=0.0)],
    )
    lines, hidden = _page_text_lines(page, 1.0, _page_image([VISIBLE]))
    assert lines == [] and hidden == 1


def test_white_on_white_span_is_dropped():
    page = FakePage([_span("STK: 9999988888", (10, 60, 150, 75))])
    lines, hidden = _page_text_lines(page, 1.0, _page_image([]))
    assert lines == [] and hidden == 1


def test_microscopic_span_is_dropped():
    box = (10, 100, 40, 102)
    page = FakePage([_span("9999988888", box, size=0.5)])
    lines, hidden = _page_text_lines(page, 1.0, _page_image([box]))
    assert lines == [] and hidden == 1


def test_off_page_span_is_dropped():
    page = FakePage([_span("9999988888", (500, 500, 600, 520))])
    lines, hidden = _page_text_lines(page, 1.0, _page_image([]))
    assert lines == [] and hidden == 1


def test_mixed_page_keeps_only_visible_text():
    hidden_box = (10, 60, 150, 75)
    page = FakePage(
        [_span("STK: 1903 6789 0123", VISIBLE), _span("STK: 9999988888", hidden_box)],
        traces=[_trace("STK: 9999988888", hidden_box, type_=3)],
    )
    lines, hidden = _page_text_lines(page, 1.0, _page_image([VISIBLE, hidden_box]))
    assert [l.text for l in lines] == ["STK: 1903 6789 0123"]
    assert hidden == 1


def test_real_pdf_invisible_text_layer_is_ignored():
    fitz = pytest.importorskip("fitz")
    from app.services.pdf_extractor import extract_pdf

    doc = fitz.open()
    page = doc.new_page(width=300, height=200)
    page.insert_text((20, 40), "STK: 1903 6789 0123", fontsize=12)                 # visible
    page.insert_text((20, 80), "STK: 9999988888", fontsize=12, render_mode=3)     # invisible
    page.insert_text((20, 120), "STK: 8888877777", fontsize=12, color=(1, 1, 1))  # white on white
    pdf_bytes = doc.tobytes()
    doc.close()

    extraction = extract_pdf(pdf_bytes)
    texts = [l.text for l in extraction.pages[0].lines]
    assert any("1903 6789 0123" in t for t in texts)
    assert not any("9999988888" in t for t in texts)
    assert not any("8888877777" in t for t in texts)
    assert extraction.pages[0].hidden_text_spans >= 2
