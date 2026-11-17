"""
System security regression suite — application layer.

Grouped by the review checklists used for the QRDetec security assessment
(API security / OWASP API Top 10 2023, business logic, TOCTOU, data exposure, SSRF,
unsafe deserialization). Every test asserts a defensive property of the CURRENT code, so a
future change that weakens it fails CI. Infrastructure/config checks live in
test_security_infra_config.py.
"""
import ast
import json
import os
import socket
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fake_redis import FakeAsyncRedis

from app.core import security as sec
from app.core.config import settings

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
CSRF = {settings.CSRF_HEADER_NAME: "1"}
APP_DIR = Path(__file__).resolve().parents[1] / "app"


@pytest.fixture
def env(tmp_path, monkeypatch):
    import app.api.routes as routes
    from app.main import app

    monkeypatch.setattr(settings, "STORAGE_PATH", str(tmp_path))
    monkeypatch.setattr(settings, "SESSION_COOKIE_SECURE", False)
    monkeypatch.setattr(routes, "_dispatch_job", lambda *a, **k: None)
    fake = FakeAsyncRedis()
    app.state.redis = fake
    return {"app": app, "redis": fake, "storage": tmp_path}


def _client(env):
    return TestClient(env["app"], raise_server_exceptions=False)


def _upload(client, content=PNG, name="q.png", mime="image/png", headers=CSRF):
    return client.post("/api/upload", files={"file": (name, content, mime)}, headers=headers)


# ═══ API1 — Broken Object Level Authorization ═══════════════════════════════
def test_api1_foreign_and_unknown_job_are_indistinguishable(env):
    """No existence oracle: a foreign job and a never-existing job give byte-identical replies."""
    owner, other = _client(env), _client(env)
    job_id = _upload(owner).json()["job_id"]
    _upload(other)
    unknown = "33333333-3333-4333-8333-333333333333"
    for path in ("/api/result/{}", "/api/sse/{}"):
        a = other.get(path.format(job_id))
        b = other.get(path.format(unknown))
        assert (a.status_code, a.content) == (b.status_code, b.content) == (404, a.content)


def test_api1_job_ids_are_unguessable_uuid4(env):
    ids = {_upload(_client(env)).json()["job_id"] for _ in range(5)}
    assert len(ids) == 5
    assert all(sec.JOB_ID_RE.match(i) for i in ids)


def test_api1_owner_is_stored_as_fingerprint_not_session_id(env):
    c = _client(env)
    job_id = _upload(c).json()["job_id"]
    sid = c.cookies.get(settings.SESSION_COOKIE_NAME)
    assert sid not in json.dumps(env["redis"].store)
    assert env["redis"].store[sec.owner_key(job_id)] == sec.session_fingerprint(sid)


# ═══ API2 — Broken Authentication (guest session) ═══════════════════════════
@pytest.mark.parametrize("bad", ["short", "x" * 200, "abc def" * 10, "../../etc/passwd" * 3, "<script>" * 6])
def test_api2_malformed_session_cookie_is_ignored(bad):
    assert sec.read_session_id({settings.SESSION_COOKIE_NAME: bad}) is None


def test_api2_session_ids_have_256_bits():
    sid = sec.new_session_id()
    assert len(sid) >= 43 and sec.read_session_id({settings.SESSION_COOKIE_NAME: sid}) == sid


def test_api2_cookie_flags_in_secure_mode(env, monkeypatch):
    monkeypatch.setattr(settings, "SESSION_COOKIE_SECURE", True)
    cookie = _upload(_client(env)).headers.get("set-cookie", "").lower()
    for flag in ("httponly", "secure", "samesite=strict", "path=/"):
        assert flag in cookie, flag


def test_api2_session_id_never_in_body_or_url(env):
    c = _client(env)
    res = _upload(c)
    sid = c.cookies.get(settings.SESSION_COOKIE_NAME)
    assert sid not in res.text and sid not in res.json()["job_id"]


# ═══ API3 — Broken Object Property Level Authorization / data exposure ══════
def test_api3_payment_blocks_never_serialized():
    """raw_text exclusion is covered in test_api_authorization.py; payment_blocks is not."""
    from app.models.schemas import OCRData

    dumped = OCRData(payment_blocks=[{"account": "0123456789"}]).model_dump_json()
    assert "payment_blocks" not in dumped and "0123456789" not in dumped


def test_api3_upload_response_exposes_only_public_fields(env):
    body = _upload(_client(env)).json()
    assert set(body) == {"job_id", "message"}


def test_api3_health_endpoints_reveal_nothing(env):
    c = _client(env)
    assert c.get("/api/health").json() == {"status": "ok"}
    assert c.get("/api/health/ready").json() == {"status": "ready"}


# ═══ API4 — Unrestricted Resource Consumption ═══════════════════════════════
def test_api4_declared_oversize_rejected_before_admission(env, monkeypatch, ):
    monkeypatch.setattr(settings, "MAX_FILE_SIZE_MB", 1)
    c = _client(env)
    res = c.post("/api/upload", content=b"x", headers={**CSRF, "Content-Type": "multipart/form-data; boundary=x",
                                                       "Content-Length": str(5 * 1024 * 1024)})
    assert res.status_code == 413
    assert not env["redis"].zsets.get(sec.GLOBAL_JOBS_KEY)


def test_api4_streaming_oversize_without_content_length_rejected(env, monkeypatch):
    """Threat Model A3/A4: Even if Content-Length is omitted/small, ASGI BodySizeLimitMiddleware aborts streaming bodies > limit."""
    monkeypatch.setattr(settings, "MAX_FILE_SIZE_MB", 1)
    c = _client(env)
    # 1 MB + 128 KB exceeds MAX_FILE_SIZE_MB * 1MB + 64KB multipart overhead
    oversized_payload = PNG + (b"A" * (1024 * 1024 + 128 * 1024))
    res = _upload(c, content=oversized_payload)
    assert res.status_code == 413
    assert res.json()["error_code"] == "FILE_TOO_LARGE"
    assert not env["redis"].zsets.get(sec.GLOBAL_JOBS_KEY)


def test_api4_websocket_inbound_message_flood_closed(env, monkeypatch):
    """Threat Model A4: Flooding a job WebSocket with inbound messages triggers policy violation close (1008)."""
    from starlette.websockets import WebSocketDisconnect

    monkeypatch.setattr(settings, "WS_MAX_INBOUND_MESSAGES", 3)
    monkeypatch.setattr(settings, "WS_INBOUND_WINDOW_SECONDS", 60.0)
    c = _client(env)
    job_id = _upload(c).json()["job_id"]
    with c.websocket_connect(f"/api/ws/{job_id}", headers={"Origin": "https://testserver"}) as ws:
        for _ in range(3):
            ws.send_text("ping")
        ws.send_text("flood")
        # Drain any queued status frame until close frame arrives
        closed_code = None
        for _ in range(5):
            try:
                msg = ws.receive()
                if msg.get("type") == "websocket.close":
                    closed_code = msg.get("code")
                    break
            except WebSocketDisconnect as exc:
                closed_code = exc.code
                break
        assert closed_code == 1008



def test_api4_resource_limits_are_bounded():
    assert settings.MAX_IMAGE_PIXELS <= 50_000_000
    assert settings.MAX_PDF_PAGES <= 20
    assert settings.MAX_TOTAL_RENDERED_PIXELS <= 100_000_000
    assert settings.MAX_QR_PER_JOB <= 50
    assert settings.STREAM_MAX_SECONDS <= 600
    assert 0 < settings.MAX_ACTIVE_JOBS_PER_SESSION <= settings.MAX_ACTIVE_JOBS_PER_CLIENT <= settings.MAX_GLOBAL_ACTIVE_JOBS


def test_api4_celery_never_retries_poison_files():
    """Static check (other tests replace the celery module with a MagicMock)."""
    src = (APP_DIR / "worker" / "celery_app.py").read_text(encoding="utf-8")
    conf = src.split("celery_app.conf.update(", 1)[1].split("\n)", 1)[0]
    for setting in ('task_serializer="json"', 'result_serializer="json"', 'accept_content=["json"]',
                    "task_reject_on_worker_lost=False", "task_time_limit=", "task_soft_time_limit="):
        assert setting in conf, setting
    assert settings.CELERY_TASK_SOFT_TIME_LIMIT < settings.CELERY_TASK_HARD_TIME_LIMIT


# ═══ API5 — Broken Function Level Authorization / verb tampering ════════════
@pytest.mark.parametrize("method,path", [
    ("PUT", "/api/upload"), ("PATCH", "/api/upload"), ("GET", "/api/upload"),
    ("PUT", "/api/job/33333333-3333-4333-8333-333333333333"),
    ("POST", "/api/result/33333333-3333-4333-8333-333333333333"),
])
def test_api5_unexpected_methods_are_refused_without_leaks(env, method, path):
    res = _client(env).request(method, path, headers=CSRF)
    assert res.status_code >= 400
    assert "error_code" in res.json() and "Traceback" not in res.text


def test_api5_method_override_headers_have_no_effect(env):
    c = _client(env)
    job_id = _upload(c).json()["job_id"]
    res = c.post(f"/api/result/{job_id}", headers={**CSRF, "X-HTTP-Method-Override": "DELETE",
                                                   "X-Method-Override": "DELETE"})
    assert res.status_code >= 400
    assert env["redis"].store.get(sec.cancel_key(job_id)) is None


# ═══ API7 — SSRF: URL analysis never touches the network ════════════════════
@pytest.fixture
def no_network(monkeypatch):
    calls = []

    def deny(*a, **k):
        calls.append(a[:1])
        raise AssertionError("network access attempted during URL analysis")

    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket.socket, "connect", deny)
    return calls


@pytest.fixture(scope="module")
def offline_analyzer():
    from app.services.url_security import URLSecurityAnalyzer
    from app.services.url_security.threat_intel import ThreatIntelService

    return URLSecurityAnalyzer(threat_intel=ThreatIntelService(feed_path=""))


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:6379/",
    "http://[::1]/admin",
    "http://localhost:8000/api/health",
    "https://example.com/redirect?to=http://10.0.0.1/",
    "https://xn--vietcombnk-xyz.example/login",
])
def test_api7_url_analysis_is_offline(offline_analyzer, no_network, url):
    analysis, *_ = offline_analyzer.analyze(url)
    assert analysis.verdict is not None
    assert no_network == []


# ═══ API8 — Security misconfiguration (app level) ═══════════════════════════
def test_api8_api_responses_carry_hardening_headers(env):
    res = _client(env).get("/api/health")
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert res.headers.get("x-frame-options") == "DENY"
    assert res.headers.get("cache-control", "").startswith("no-store")


def test_api8_cors_does_not_reflect_foreign_origin(env):
    res = _client(env).options("/api/upload", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": settings.CSRF_HEADER_NAME})
    assert res.headers.get("access-control-allow-origin") not in ("*", "https://evil.example")


def test_api8_errors_never_leak_internals(env):
    c = _client(env)
    for res in (c.get("/api/nope"), c.post("/api/upload", headers=CSRF, content=b"x")):
        assert "Traceback" not in res.text and "File \"" not in res.text
        assert set(res.json()) >= {"error_code", "message"}


# ═══ API9 — Inventory: only the documented routes exist ═════════════════════
def test_api9_route_inventory_is_exactly_known(env):
    from app.api.routes import router
    from app.main import app

    api_paths = {r.path for r in router.routes}
    app_level = {r.path for r in app.routes if getattr(r, "path", None)}
    assert api_paths == {"/upload", "/result/{job_id}", "/job/{job_id}", "/sse/{job_id}",
                         "/ws/{job_id}", "/health", "/health/ready"}, \
        "route added/removed: review authz + CSRF for it and update this inventory"
    assert app_level == {"/ws/{job_id}"}  # root WebSocket alias matching /api/ws/{job_id}
    assert _client(env).get("/api/health").status_code == 200  # router mounted under /api


# ═══ Upload gate / file handling (TOCTOU, path traversal) ═══════════════════
@pytest.mark.parametrize("name,expected", [
    ("../../etc/passwd", "passwd"),
    ("..\\..\\windows\\win.ini", "win.ini"),
    ("a<b>c|d?.png", "abcd.png"),
    ("\x00\x1f.png", ".png"),
    ("", "upload.bin"),
    ("x" * 500 + ".png", "x" * 100),
])
def test_upload_filename_is_display_only_and_sanitized(name, expected):
    from app.api.routes import sanitize_filename

    assert sanitize_filename(name) == expected


def test_upload_storage_paths_are_server_generated(env):
    c = _client(env)
    job_id = _upload(c, name="../../evil.sh").json()["job_id"]
    assert os.listdir(env["storage"]) == [f"{job_id}.img"]


def test_worker_rejects_paths_outside_storage(tmp_path):
    from app.services.file_safety import UnsafePathError, resolve_job_file

    job = "44444444-4444-4444-8444-444444444444"
    (tmp_path / f"{job}.img").write_bytes(PNG)
    assert resolve_job_file(job, str(tmp_path / f"{job}.img"), "image", str(tmp_path))
    for bad_path, ftype in ((str(tmp_path / ".." / f"{job}.img"), "image"),
                            (str(tmp_path / f"{job}.img"), "pdf"),
                            ("/etc/passwd", "image")):
        with pytest.raises((UnsafePathError, FileNotFoundError)):
            resolve_job_file(job, bad_path, ftype, str(tmp_path))
    with pytest.raises(UnsafePathError):
        resolve_job_file("not-a-uuid", str(tmp_path / f"{job}.img"), "image", str(tmp_path))


def test_worker_rejects_symlinked_job_file(tmp_path):
    from app.services.file_safety import UnsafePathError, resolve_job_file

    job = "55555555-5555-4555-8555-555555555555"
    target = tmp_path / "real.img"
    target.write_bytes(PNG)
    try:
        os.symlink(target, tmp_path / f"{job}.img")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform")
    with pytest.raises(UnsafePathError):
        resolve_job_file(job, str(tmp_path / f"{job}.img"), "image", str(tmp_path))


def test_magic_bytes_are_authoritative():
    from app.api.routes import declared_mime_consistent, detect_magic_file_type

    assert detect_magic_file_type(b"<?php system($_GET[1]); ?>") is None
    assert detect_magic_file_type(b"MZ\x90\x00" + b"\x00" * 60) is None
    assert detect_magic_file_type(b"<svg xmlns='http://www.w3.org/2000/svg'>") is None
    assert not declared_mime_consistent("image/png", "pdf")
    assert not declared_mime_consistent("text/html", "image")


# ═══ Business logic — verdict integrity ═════════════════════════════════════
def test_logic_no_alert_ever_maps_to_a_safe_label():
    from app.models.schemas import RISK_LEVELS, AlertCode, risk_level_for_alert

    assert "safe" not in RISK_LEVELS
    for code in AlertCode:
        assert risk_level_for_alert(code) in RISK_LEVELS


def test_logic_unknown_alert_fails_closed_to_unverifiable():
    from app.models.schemas import risk_level_for_alert

    assert risk_level_for_alert("SOMETHING_NEW") == "unverifiable"


def test_logic_provisional_result_never_reads_as_no_known_risk():
    from app.models.schemas import AlertCode, PayloadType, QRCodeResult

    r = QRCodeResult(payload="x", payload_type=PayloadType.VIETQR,
                     alert_code=AlertCode.CONTEXT_CONSISTENT, is_provisional=True)
    assert r.risk_level == "pending" and r.analysis_completeness == "pending"


# ═══ Unsafe deserialization / dangerous sinks (static guard over app/) ══════
_DANGEROUS_CALLS = {
    ("pickle", "load"), ("pickle", "loads"), ("marshal", "loads"), ("joblib", "load"),
    ("dill", "load"), ("dill", "loads"), ("os", "system"), ("os", "popen"),
}


def _py_files():
    return [p for p in APP_DIR.rglob("*.py") if "__pycache__" not in p.parts]


def test_no_unsafe_deserialization_or_shell_sinks_in_app():
    offenders = []
    for path in _py_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            if isinstance(fn, ast.Name) and fn.id in ("eval", "exec"):
                offenders.append(f"{path.name}:{node.lineno} {fn.id}()")
            if isinstance(fn, ast.Attribute) and isinstance(fn.value, ast.Name):
                if (fn.value.id, fn.attr) in _DANGEROUS_CALLS:
                    offenders.append(f"{path.name}:{node.lineno} {fn.value.id}.{fn.attr}()")
                if fn.value.id == "yaml" and fn.attr == "load":
                    offenders.append(f"{path.name}:{node.lineno} yaml.load()")
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    offenders.append(f"{path.name}:{node.lineno} shell=True")
    assert offenders == []


def test_model_calibrator_accepts_json_types_only():
    from app.services.url_security.model_service import Calibrator

    with pytest.raises(ValueError):
        Calibrator({"type": "pickle"})
    with pytest.raises((ValueError, TypeError)):
        Calibrator({"type": "isotonic", "x": [0, 1], "y": [0, float("nan")]})
