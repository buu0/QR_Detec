"""
File safety primitives shared by the worker (no PyMuPDF / OCR dependency → easy to unit test).

Fail-closed principles:
- A file that Pillow cannot fully parse is rejected; we never "try OpenCV anyway".
- Pixel / dimension limits are checked from the header BEFORE full decode, then again after.
- The worker only opens server-generated paths `{STORAGE_PATH}/{job_id}.(img|pdf)` that are
  regular files (not symlinks) and resolve inside STORAGE_PATH.
"""
import io
import os
import stat
import warnings
from typing import Optional

import numpy as np

from app.core.config import settings
from app.core.security import is_valid_job_id


class ResourceLimitExceeded(ValueError):
    """Raised when PDF or image exceeds strict resource safety boundaries."""


class InvalidFileError(ValueError):
    """Malformed, truncated or unsupported content (fail-closed)."""


class EncryptedPdfError(InvalidFileError):
    """Password-protected PDF: cannot be inspected, so it cannot be judged."""


class UnsafePathError(ValueError):
    """Task message pointed at a path outside the server-controlled storage area."""


_EXT_FOR_TYPE = {"image": ".img", "pdf": ".pdf"}


def resolve_job_file(job_id: str, file_path: str, file_type: str, storage_path: Optional[str] = None) -> str:
    """
    Validate a file path received through the Redis task message.
    Only `{storage}/{job_id}{ext}` is accepted; anything else (traversal, symlink,
    foreign directory, wrong extension, non-regular file) raises UnsafePathError.
    """
    storage = os.path.realpath(storage_path or settings.STORAGE_PATH)
    if not is_valid_job_id(job_id) or file_type not in _EXT_FOR_TYPE:
        raise UnsafePathError("invalid job id or file type")
    expected = os.path.join(storage, f"{job_id}{_EXT_FOR_TYPE[file_type]}")
    try:
        supplied_real = os.path.realpath(file_path)
    except (TypeError, ValueError):
        raise UnsafePathError("invalid path")
    if os.path.normcase(supplied_real) != os.path.normcase(expected):
        raise UnsafePathError("path not in storage")
    try:
        st = os.lstat(expected)
    except FileNotFoundError:
        raise
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise UnsafePathError("not a regular file")
    return expected


def read_job_file(path: str, max_bytes: int) -> bytes:
    """Open without following symlinks where the OS supports it; enforce size again."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as fh:
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ResourceLimitExceeded("file exceeds configured size")
    if not data:
        raise InvalidFileError("empty file")
    return data


def _check_dims(width: int, height: int) -> None:
    if width <= 0 or height <= 0:
        raise InvalidFileError("invalid dimensions")
    if (
        width > settings.MAX_IMAGE_WIDTH
        or height > settings.MAX_IMAGE_HEIGHT
        or width * height > settings.MAX_IMAGE_PIXELS
    ):
        raise ResourceLimitExceeded(f"image {width}x{height} exceeds limits")


def decode_image_safely(file_bytes: bytes) -> np.ndarray:
    """
    Fail-closed image decode:
    1. Header dims check (no pixel allocation).
    2. Pillow verify() (structure / truncation / CRC for PNG).
    3. Full load with Pillow decompression-bomb guard set to our own limit.
    4. Convert to BGR ndarray (OpenCV layout). OpenCV never decodes untrusted bytes directly.
    Animated images: only the first frame is analysed.
    """
    from PIL import Image, ImageFile, UnidentifiedImageError

    ImageFile.LOAD_TRUNCATED_IMAGES = False
    Image.MAX_IMAGE_PIXELS = settings.MAX_IMAGE_PIXELS

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(file_bytes)) as probe:
                if probe.format not in ("JPEG", "PNG", "WEBP", "GIF", "BMP", "TIFF", "MPO"):
                    raise InvalidFileError(f"unsupported format {probe.format}")
                _check_dims(*probe.size)
                probe.verify()

            with Image.open(io.BytesIO(file_bytes)) as img:
                img.seek(0)
                img.load()
                _check_dims(*img.size)
                rgb = img.convert("RGB")
    except (ResourceLimitExceeded, InvalidFileError):
        raise
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise ResourceLimitExceeded("decompression bomb guard triggered")
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError, EOFError) as e:
        raise InvalidFileError(f"image parse failed: {type(e).__name__}")

    arr = np.asarray(rgb, dtype=np.uint8)
    # RGB -> BGR without importing cv2 here
    return np.ascontiguousarray(arr[:, :, ::-1])
