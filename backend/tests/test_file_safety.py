"""
Fail-closed file handling: task-path validation (traversal / symlink / foreign path)
and image decoding (malformed, truncated, decompression bomb).
"""
import io
import os
import struct
import uuid
import zlib

import pytest

from app.core.config import settings
from app.services.file_safety import (
    InvalidFileError,
    ResourceLimitExceeded,
    UnsafePathError,
    decode_image_safely,
    read_job_file,
    resolve_job_file,
)


def _png_bytes(w=64, h=64) -> bytes:
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (w, h), (255, 255, 255)).save(buf, format="PNG")
    return buf.getvalue()


def _png_header_only(w: int, h: int) -> bytes:
    """A PNG that *declares* huge dimensions (decompression-bomb style) without pixel data."""
    def chunk(t, data):
        return struct.pack(">I", len(data)) + t + data + struct.pack(">I", zlib.crc32(t + data) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(b"\x00" * 16)) + chunk(b"IEND", b"")


# ─── Path validation ───────────────────────────────────────────────────────
def test_resolve_accepts_server_generated_path(tmp_path):
    job_id = str(uuid.uuid4())
    p = tmp_path / f"{job_id}.img"
    p.write_bytes(b"x")
    assert os.path.normcase(resolve_job_file(job_id, str(p), "image", str(tmp_path))) == os.path.normcase(os.path.realpath(p))


@pytest.mark.parametrize("bad", ["../../etc/passwd", "/etc/passwd", "C:\\Windows\\win.ini"])
def test_resolve_rejects_foreign_paths(tmp_path, bad):
    job_id = str(uuid.uuid4())
    (tmp_path / f"{job_id}.img").write_bytes(b"x")
    with pytest.raises(UnsafePathError):
        resolve_job_file(job_id, bad, "image", str(tmp_path))


def test_resolve_rejects_traversal_back_into_storage(tmp_path):
    job_id = str(uuid.uuid4())
    other = str(uuid.uuid4())
    (tmp_path / f"{other}.img").write_bytes(b"x")
    with pytest.raises(UnsafePathError):
        resolve_job_file(job_id, str(tmp_path / f"{other}.img"), "image", str(tmp_path))


def test_resolve_rejects_wrong_extension_and_type(tmp_path):
    job_id = str(uuid.uuid4())
    (tmp_path / f"{job_id}.img").write_bytes(b"x")
    with pytest.raises(UnsafePathError):
        resolve_job_file(job_id, str(tmp_path / f"{job_id}.img"), "pdf", str(tmp_path))
    with pytest.raises(UnsafePathError):
        resolve_job_file(job_id, str(tmp_path / f"{job_id}.img"), "exe", str(tmp_path))


def test_resolve_rejects_invalid_job_id(tmp_path):
    with pytest.raises(UnsafePathError):
        resolve_job_file("../x", str(tmp_path / "x.img"), "image", str(tmp_path))


def test_resolve_rejects_symlink(tmp_path):
    job_id = str(uuid.uuid4())
    target = tmp_path / "secret.txt"
    target.write_text("secret")
    link = tmp_path / f"{job_id}.img"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform/user")
    with pytest.raises(UnsafePathError):
        resolve_job_file(job_id, str(link), "image", str(tmp_path))


def test_resolve_missing_file(tmp_path):
    job_id = str(uuid.uuid4())
    with pytest.raises(FileNotFoundError):
        resolve_job_file(job_id, str(tmp_path / f"{job_id}.img"), "image", str(tmp_path))


def test_read_job_file_enforces_size(tmp_path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"x" * 100)
    with pytest.raises(ResourceLimitExceeded):
        read_job_file(str(p), 10)
    assert read_job_file(str(p), 1000) == b"x" * 100


# ─── Image decoding (fail-closed) ──────────────────────────────────────────
def test_decode_valid_png_returns_bgr():
    arr = decode_image_safely(_png_bytes(32, 16))
    assert arr.shape == (16, 32, 3)


def test_decode_rejects_truncated_png():
    data = _png_bytes(256, 256)
    with pytest.raises(InvalidFileError):
        decode_image_safely(data[: len(data) // 2])


def test_decode_rejects_garbage_with_valid_magic():
    with pytest.raises(InvalidFileError):
        decode_image_safely(b"\x89PNG\r\n\x1a\n" + os.urandom(200))


def test_decode_rejects_non_image():
    with pytest.raises(InvalidFileError):
        decode_image_safely(b"%PDF-1.7 not an image")


def test_decode_blocks_declared_huge_dimensions():
    with pytest.raises(ResourceLimitExceeded):
        decode_image_safely(_png_header_only(settings.MAX_IMAGE_WIDTH + 1, 10))
    with pytest.raises(ResourceLimitExceeded):
        decode_image_safely(_png_header_only(7000, 7000))  # 49 MP > 36 MP default
