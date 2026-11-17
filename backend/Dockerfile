FROM python:3.11-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive \
    HOME=/home/appuser

# === OS Dependencies: libzbar (pyzbar), OpenCV, PaddleOCR ===
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libzbar0 \
    libzbar-dev \
    libgl1 \
    libglib2.0-0 \
    libgomp1 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    curl \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# === Non-root Application User ===
RUN useradd -m -u 1000 -s /bin/bash appuser && \
    mkdir -p /app /app/models /app/storage /home/appuser/.paddleocr && \
    chown -R appuser:appuser /app /home/appuser

WORKDIR /app

# === Python packages (cached layer) ===
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt

# === Download WeChatQRCode model weights (Verified TLS without -k) ===
# Every file is pinned by SHA-256; a changed/tampered upstream file fails the build.
# Digests recorded from the image built on 2026-10-08 (update deliberately if upstream changes).
RUN mkdir -p /app/models/wechat_qr && \
    curl -f -L "https://github.com/WeChatCV/opencv_3rdparty/raw/wechat_qrcode/detect.prototxt" \
        -o /app/models/wechat_qr/detect.prototxt && \
    curl -f -L "https://github.com/WeChatCV/opencv_3rdparty/raw/wechat_qrcode/detect.caffemodel" \
        -o /app/models/wechat_qr/detect.caffemodel && \
    curl -f -L "https://github.com/WeChatCV/opencv_3rdparty/raw/wechat_qrcode/sr.prototxt" \
        -o /app/models/wechat_qr/sr.prototxt && \
    curl -f -L "https://github.com/WeChatCV/opencv_3rdparty/raw/wechat_qrcode/sr.caffemodel" \
        -o /app/models/wechat_qr/sr.caffemodel && \
    printf '%s\n' \
        "e8acfc395caf443a47f15686a9b9207b36cb8f7e6ceb8fbaf6466665e68a9466  /app/models/wechat_qr/detect.prototxt" \
        "cc49b8c9babaf45f3037610fe499df38c8819ebda29e90ca9f2e33270f6ef809  /app/models/wechat_qr/detect.caffemodel" \
        "8ae41acba97e8b4a8e741ee350481e49b8e01d787193f470a4c95ee1c02d5b61  /app/models/wechat_qr/sr.prototxt" \
        "e5d36889d8e6ef2f1c1f515f807cec03979320ac81792cd8fb927c31fd658ae3  /app/models/wechat_qr/sr.caffemodel" \
        | sha256sum -c -

# === Pre-warm PaddleOCR model download as appuser ===
RUN su - appuser -c "python -c \"from paddleocr import PaddleOCR; PaddleOCR(lang='vi', show_log=False)\"" || true

# Build/download tooling is not needed at runtime. Removing it means code execution in
# the container cannot compile helpers or fetch payloads with curl/wget. (Layers above still
# contain them; a full multi-stage build would also shrink the image.)
RUN apt-get purge -y --auto-remove build-essential libzbar-dev curl wget && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Application code: owned by root, read-only for the runtime user (defense in depth).
# .dockerignore excludes .env, secrets/, .git, tests and caches from the build context.
COPY --chown=root:root . /app
RUN chmod -R a-w /app/app && \
    mkdir -p /app/storage /app/spool && chown appuser:appuser /app/storage /app/spool && chmod 700 /app/storage /app/spool && \
    chown -R appuser:appuser /home/appuser

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).status == 200 else 1)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--no-server-header", "--ws-max-size", "4096"]
