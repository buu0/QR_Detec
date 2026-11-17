"""
Unit tests for Upload Security Gate (Magic bytes, streaming limits, sanitization)
"""
from app.api.routes import detect_magic_file_type, sanitize_filename


def test_magic_bytes_detection_valid():
    # PDF
    assert detect_magic_file_type(b"%PDF-1.7\r\n\x00") == "pdf"

    # JPEG
    assert detect_magic_file_type(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01") == "image"

    # PNG
    assert detect_magic_file_type(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR") == "image"

    # WebP: RIFF (4b) + size (4b) + WEBP (4b)
    webp_header = b"RIFF\x20\x00\x00\x00WEBPVP8 "
    assert detect_magic_file_type(webp_header) == "image"


def test_magic_bytes_spoofed_file_rejected():
    # Executable or shell script pretending to be image/pdf
    assert detect_magic_file_type(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff") is None
    assert detect_magic_file_type(b"#!/bin/bash\necho bad\n") is None
    assert detect_magic_file_type(b"<html><script>alert(1)</script></html>") is None


def test_filename_sanitization():
    # Directory traversal
    assert sanitize_filename("../../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\windows\\system32\\cmd.exe") == "cmd.exe"

    # Dangerous characters
    assert sanitize_filename('test<script>:file?.pdf') == "testscriptfile.pdf"

    # Length capping
    long_name = "a" * 150 + ".png"
    clean_long = sanitize_filename(long_name)
    assert len(clean_long) <= 100

    # Empty / none
    assert sanitize_filename("") == "upload.bin"
    assert sanitize_filename(None) == "upload.bin"
