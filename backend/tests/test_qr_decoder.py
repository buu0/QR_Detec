"""
Unit tests for DualStageQRDecoder (Fast vs Complete mode & Bounding box deduplication)
"""
from app.services.qr_decoder import DualStageQRDecoder, _are_bboxes_near, _repair_zbar_utf8


def test_are_bboxes_near():
    # Identical bounding boxes
    b1 = (100, 100, 50, 50)
    b2 = (100, 100, 50, 50)
    assert _are_bboxes_near(b1, b2) is True

    # Slightly shifted bounding box (overlapping detection from different engine)
    b3 = (105, 104, 52, 48)
    assert _are_bboxes_near(b1, b3) is True

    # Far away bounding box (e.g. repeated QR code on invoice bottom and top)
    b_far = (600, 800, 50, 50)
    assert _are_bboxes_near(b1, b_far) is False


def test_deduplicate_keeps_distant_bboxes_with_same_payload():
    decoder = DualStageQRDecoder()

    # Two detections of the SAME payload at two DIFFERENT locations on the page
    detections = [
        {"payload": "https://example.com/pay", "bbox": (50, 50, 60, 60), "engine": "pyzbar"},
        {"payload": "https://example.com/pay", "bbox": (500, 700, 60, 60), "engine": "pyzbar"},
    ]

    deduped = decoder._deduplicate_results(detections)
    assert len(deduped) == 2, "Same payload at distant coordinates must NOT be collapsed!"


def test_deduplicate_collapses_overlapping_detections():
    decoder = DualStageQRDecoder()

    # Same payload detected by both pyzbar and wechat at approximately the same coordinates
    detections = [
        {"payload": "https://example.com/pay", "bbox": (100, 100, 80, 80), "engine": "pyzbar"},
        {"payload": "https://example.com/pay", "bbox": (102, 98, 82, 81), "engine": "wechat_qrcode"},
    ]

    deduped = decoder._deduplicate_results(detections)
    assert len(deduped) == 1
    assert deduped[0]["engine"] == "pyzbar"


def test_repair_zbar_utf8_and_same_bbox_dedup():
    assert _repair_zbar_utf8("https://p\u8a04ypal.com") == "https://p\u0430ypal.com"
    assert _repair_zbar_utf8("https://p\u00c3\u00a4ypal.com") == "https://p\u00e4ypal.com"

    decoder = DualStageQRDecoder()
    detections = [
        {"payload": "https://p\u8a04ypal.com", "bbox": (63, 75, 327, 327), "engine": "pyzbar"},
        {"payload": "https://p\u0430ypal.com", "bbox": (60, 72, 331, 331), "engine": "wechat_qrcode"},
    ]
    deduped = decoder._deduplicate_results(detections)
    assert len(deduped) == 1
    assert deduped[0]["payload"] == "https://p\u0430ypal.com"
    assert deduped[0]["engine"] == "wechat_qrcode"
