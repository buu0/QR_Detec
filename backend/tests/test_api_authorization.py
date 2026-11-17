"""
Job authorization, CSRF and upload-gate tests (P0 security blockers).

Key regression: Session A must never read Session B's job — via /result, /sse, /ws or DELETE —
even when it knows the job_id.
"""
import json
import os

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from fake_redis import FakeAsyncRedis

from app.core import security as sec
from app.core.config import settings

PNG_MAGIC = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
CSRF = {settings.CSRF_HEADER_NAME: "1"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    import app.api.routes as routes
    from app.main import app

    monkeypatch.setattr(settings, "STORAGE_PATH", str(tmp_path))
    monkeypatch.setattr(settings, "SESSION_COOKIE_SECURE", False)  # TestClient talks plain http
    dispatched = []
    monkeypatch.setattr(routes, "_dispatch_job", lambda *a, **k: dispatched.append(a))

    fake = FakeAsyncRedis()
    app.state.redis = fake
    client_a = TestClient(app, raise_server_exceptions=False)
    client_b = TestClient(app, raise_server_exceptions=False)
    return {"app": app, "redis": fake, "a": client_a, "b": client_b, "dispatched": dispatched, "storage": tmp_path}


def _upload(client, content=PNG_MAGIC, name="qr.png", mime="image/png", headers=CSRF):
    return client.post("/api/upload", files={"file": (name, content, mime)}, headers=headers)


# ─── CSRF / upload gate ─────────────────────────────────────────────────────
def test_upload_requires_csrf_header(env):
    res = _upload(env["a"], headers={})
    assert res.status_code == 403
    assert res.json()["error_code"] == "CSRF_REJECTED"
    assert env["dispatched"] == []


def test_upload_rejects_foreign_origin(env):
    res = _upload(env["a"], headers={**CSRF, "Origin": "https://evil.example"})
    assert res.status_code == 403
    assert res.json()["error_code"] == "CSRF_REJECTED"


def test_upload_sets_httponly_session_cookie_and_binds_owner(env):
    res = _upload(env["a"])
    assert res.status_code == 200, res.text
    job_id = res.json()["job_id"]
    assert sec.is_valid_job_id(job_id)
    cookie_header = res.headers.get("set-cookie", "")
    assert settings.SESSION_COOKIE_NAME in cookie_header
    assert "httponly" in cookie_header.lower()
    assert "samesite=strict" in cookie_header.lower()
    # session id is never placed in the response body or the job id
    sid = env["a"].cookies.get(settings.SESSION_COOKIE_NAME)
    assert sid and sid not in res.text
    # owner stored as fingerprint only
    assert env["redis"].store[sec.owner_key(job_id)] == sec.session_fingerprint(sid)
    assert res.headers.get("cache-control", "").startswith("no-store")
    assert len(env["dispatched"]) == 1


def test_upload_rejects_non_image_and_cleans_up(env):
    res = _upload(env["a"], content=b"#!/bin/sh\necho pwned\n", name="x.png")
    assert res.status_code == 415
    assert res.json()["error_code"] == "UNSUPPORTED_FILE_TYPE"
    assert os.listdir(env["storage"]) == []
    # the job slot was released
    sid = env["a"].cookies.get(settings.SESSION_COOKIE_NAME)
    if sid:
        slots = env["redis"].store.get(sec.job_slots_key(sec.session_fingerprint(sid)), "0")
        assert int(slots) <= 0


def test_upload_rejects_mime_contradiction(env):
    res = _upload(env["a"], content=b"%PDF-1.7\n%...", name="a.png", mime="image/png")
    assert res.status_code == 415


def test_upload_rejects_empty(env):
    res = _upload(env["a"], content=b"", name="a.png")
    assert res.status_code in (400, 415)
    assert os.listdir(env["storage"]) == []


def test_upload_file_too_large(env, monkeypatch):
    monkeypatch.setattr(settings, "MAX_FILE_SIZE_MB", 1)
    big = PNG_MAGIC + b"\x00" * (1024 * 1024 + 10)
    res = _upload(env["a"], content=big)
    assert res.status_code == 413
    assert res.json()["error_code"] == "FILE_TOO_LARGE"
    assert os.listdir(env["storage"]) == []


def test_active_job_limit_per_session(env, monkeypatch):
    monkeypatch.setattr(settings, "MAX_ACTIVE_JOBS_PER_SESSION", 2)
    assert _upload(env["a"]).status_code == 200
    assert _upload(env["a"]).status_code == 200
    res = _upload(env["a"])
    assert res.status_code == 429
    assert res.json()["error_code"] == "TOO_MANY_ACTIVE_JOBS"
    assert "retry-after" in {k.lower() for k in res.headers.keys()}
    # a different session is not affected
    assert _upload(env["b"]).status_code == 200


def test_redis_down_returns_503_without_details(env):
    env["redis"].fail = True
    res = _upload(env["a"])
    assert res.status_code == 503
    body = res.json()
    assert body["error_code"] == "SERVICE_UNAVAILABLE"
    assert "Traceback" not in res.text and "ConnectionError" not in res.text


# ─── Cross-session isolation ────────────────────────────────────────────────
def test_session_b_cannot_read_session_a_result(env):
    job_id = _upload(env["a"]).json()["job_id"]
    env["redis"].store[f"job:{job_id}:result"] = json.dumps({"job_id": job_id, "status": "completed", "qr_codes": []})

    # Owner can read
    ok = env["a"].get(f"/api/result/{job_id}")
    assert ok.status_code == 200
    assert ok.json()["job_id"] == job_id

    # Another session (with its own cookie) cannot, even knowing the job id
    _upload(env["b"])  # gives B a valid session cookie
    denied = env["b"].get(f"/api/result/{job_id}")
    assert denied.status_code == 404
    assert denied.json()["error_code"] == "JOB_NOT_FOUND"
    assert "qr_codes" not in denied.text


def test_no_cookie_cannot_read_result(env):
    from app.main import app

    job_id = _upload(env["a"]).json()["job_id"]
    anon = TestClient(app, raise_server_exceptions=False)
    assert anon.get(f"/api/result/{job_id}").status_code == 404


def test_forged_cookie_cannot_read_result(env):
    from app.main import app

    job_id = _upload(env["a"]).json()["job_id"]
    forged = TestClient(app, raise_server_exceptions=False)
    forged.cookies.set(settings.SESSION_COOKIE_NAME, "A" * 43)
    assert forged.get(f"/api/result/{job_id}").status_code == 404


def test_invalid_job_id_rejected(env):
    _upload(env["a"])
    for bad in ("not-a-uuid", "..%2F..%2Fetc%2Fpasswd", "00000000-0000-0000-0000-000000000000"):
        assert env["a"].get(f"/api/result/{bad}").status_code == 404


def test_session_b_cannot_open_sse_for_session_a(env):
    job_id = _upload(env["a"]).json()["job_id"]
    env["redis"].store[f"job:{job_id}:result"] = json.dumps({"job_id": job_id, "status": "completed"})
    _upload(env["b"])
    denied = env["b"].get(f"/api/sse/{job_id}")
    assert denied.status_code == 404

    allowed = env["a"].get(f"/api/sse/{job_id}")
    assert allowed.status_code == 200
    assert '"type": "result"' in allowed.text


def test_websocket_requires_owner_and_origin(env):
    job_id = _upload(env["a"]).json()["job_id"]
    env["redis"].store[f"job:{job_id}:result"] = json.dumps({"job_id": job_id, "status": "completed"})
    _upload(env["b"])

    # Foreign origin (cross-site WebSocket hijacking) is refused before accept
    with pytest.raises(WebSocketDisconnect):
        with env["a"].websocket_connect(f"/ws/{job_id}", headers={"origin": "https://evil.example"}) as ws:
            ws.receive_text()

    # Other session refused
    with pytest.raises(WebSocketDisconnect):
        with env["b"].websocket_connect(f"/ws/{job_id}", headers={"origin": "http://testserver"}) as ws:
            ws.receive_text()

    # Owner with same-origin receives the result
    with env["a"].websocket_connect(f"/ws/{job_id}", headers={"origin": "http://testserver"}) as ws:
        first = json.loads(ws.receive_text())
        second = json.loads(ws.receive_text())
    assert first["job_id"] == job_id
    assert second["type"] == "result"


def test_partial_results_replayed_on_polling(env):
    job_id = _upload(env["a"]).json()["job_id"]
    ev = {"type": "provisional_result", "job_id": job_id, "qr_index": 0, "result": {"risk_level": "pending"}}
    env["redis"].hashes[sec.events_key(job_id)] = {"0": json.dumps(ev)}
    res = env["a"].get(f"/api/result/{job_id}")
    body = res.json()
    assert body["is_final"] is False
    assert body["partial_results"][0]["qr_index"] == 0


def test_cancel_requires_owner_and_csrf(env):
    job_id = _upload(env["a"]).json()["job_id"]
    stored = [f for f in os.listdir(env["storage"]) if f.startswith(job_id)]
    assert stored, "upload should have stored the file"

    _upload(env["b"])
    assert env["b"].delete(f"/api/job/{job_id}", headers=CSRF).status_code == 404
    assert env["a"].delete(f"/api/job/{job_id}").status_code == 403  # missing CSRF header

    res = env["a"].delete(f"/api/job/{job_id}", headers=CSRF)
    assert res.status_code == 200
    assert res.json()["status"] == "cancelled"
    assert env["redis"].store.get(sec.cancel_key(job_id)) == "1"
    assert not [f for f in os.listdir(env["storage"]) if f.startswith(job_id)]


def test_stream_limit_per_session(env, monkeypatch):
    monkeypatch.setattr(settings, "MAX_STREAMS_PER_SESSION", 1)
    job_id = _upload(env["a"]).json()["job_id"]
    sid = env["a"].cookies.get(settings.SESSION_COOKIE_NAME)
    # simulate one stream already open for this session
    env["redis"].store[sec.stream_slots_key(sec.session_fingerprint(sid))] = "1"
    res = env["a"].get(f"/api/sse/{job_id}")
    assert res.status_code == 429
    assert res.json()["error_code"] == "TOO_MANY_STREAMS"


def test_error_responses_never_leak_internals(env):
    res = env["a"].get("/api/does-not-exist")
    assert res.status_code == 404
    assert "error_code" in res.json()
    assert "Traceback" not in res.text


def test_api_docs_disabled_by_default(env):
    assert env["a"].get("/api/docs").status_code == 404
    assert env["a"].get("/api/openapi.json").status_code == 404


# ─── Global admission control (cookie rotation cannot bypass the queue limit) ───
def test_global_admission_limit_returns_503(env, monkeypatch):
    """BEFORE: only a per-session limit existed; a client dropping its cookie got a fresh
    session and could fill the Celery queue. AFTER: a cross-session cap returns 503."""
    monkeypatch.setattr(settings, "MAX_GLOBAL_ACTIVE_JOBS", 2)
    from app.main import app
    clients = [TestClient(app, raise_server_exceptions=False) for _ in range(3)]  # 3 fresh sessions
    assert _upload(clients[0]).status_code == 200
    assert _upload(clients[1]).status_code == 200
    res = _upload(clients[2])
    assert res.status_code == 503
    assert res.json()["error_code"] == "SERVICE_UNAVAILABLE"
    assert res.headers.get("retry-after") == "20"
    assert len(env["dispatched"]) == 2
    assert len(env["redis"].zsets.get(sec.GLOBAL_JOBS_KEY, {})) == 2  # rejected job not kept


def test_rejected_upload_releases_global_slot(env):
    res = _upload(env["a"], content=b"#!/bin/sh\necho x\n", name="x.png")
    assert res.status_code == 415
    assert len(env["redis"].zsets.get(sec.GLOBAL_JOBS_KEY, {})) == 0



# ─── Multipart parsing gated behind CSRF & admission (Threat Model A4) ──────
@pytest.fixture
def form_calls(monkeypatch):
    from starlette.requests import Request

    calls = []
    original = Request.form

    def tracking_form(self, *a, **k):
        calls.append(1)
        return original(self, *a, **k)

    monkeypatch.setattr(Request, "form", tracking_form)
    return calls


def test_csrf_rejected_upload_never_parses_multipart(env, form_calls):
    res = _upload(env["a"], headers={})
    assert res.status_code == 403
    assert form_calls == []


def test_admission_rejected_upload_never_parses_multipart(env, form_calls, monkeypatch):
    monkeypatch.setattr(settings, "MAX_GLOBAL_ACTIVE_JOBS", 0)
    res = _upload(env["a"])
    assert res.status_code == 503
    assert form_calls == []


def test_non_multipart_upload_rejected_without_slot(env):
    res = env["a"].post("/api/upload", content=b"\x89PNG\r\n\x1a\n" + b"\x00" * 64,
                        headers={**CSRF, "Content-Type": "image/png"})
    assert res.status_code == 422
    assert res.json()["error_code"] == "INVALID_FILE"
    assert len(env["redis"].zsets.get(sec.GLOBAL_JOBS_KEY, {})) == 0


def test_upload_with_extra_file_parts_rejected_and_slot_released(env):
    res = env["a"].post(
        "/api/upload",
        files=[("file", ("a.png", PNG_MAGIC, "image/png")), ("file2", ("b.png", PNG_MAGIC, "image/png"))],
        headers=CSRF,
    )
    assert res.status_code == 422
    assert len(env["redis"].zsets.get(sec.GLOBAL_JOBS_KEY, {})) == 0
    assert os.listdir(env["storage"]) == []


# ─── Admission & Retention Lifetimes (Threat Model A4) ──────────────────────
def test_admission_ttl_covers_queue_wait_and_run_time():
    assert settings.job_admission_ttl > settings.JOB_QUEUE_MAX_WAIT_SECONDS + settings.CELERY_TASK_HARD_TIME_LIMIT
    assert settings.orphan_file_min_age > settings.job_admission_ttl


def test_upload_slot_ttl_uses_admission_ttl(env):
    job_id = _upload(env["a"]).json()["job_id"]
    assert env["redis"].ttls[sec.GLOBAL_JOBS_KEY] == settings.job_admission_ttl
    assert env["redis"].ttls[sec.job_slot_flag_key(job_id)] == settings.job_admission_ttl


# ─── Atomic Redis Lua Admission & Stream Slots (Threat Model A4) ────────────
import asyncio
import logging
import time
import uuid
from fake_redis import FakeSyncRedis
from app.core.config import Settings
from app.models.schemas import OCRData


def _run_coro(coro):
    return asyncio.run(coro)


def test_acquire_slot_is_a_single_eval_round_trip():
    r = FakeAsyncRedis()
    assert _run_coro(sec.acquire_slot(r, "k", 2, 60)) is True
    assert r.eval_calls == [sec.ACQUIRE_SLOT_LUA]


def test_global_slot_is_a_single_eval_round_trip():
    r = FakeAsyncRedis()
    assert _run_coro(sec.acquire_global_slot(r, "job-1", 5, 60)) is True
    assert r.eval_calls == [sec.ACQUIRE_GLOBAL_SLOT_LUA]


def test_release_slot_is_a_single_eval_round_trip():
    r = FakeAsyncRedis()
    _run_coro(sec.acquire_slot(r, "k", 2, 60))
    r.eval_calls.clear()
    _run_coro(sec.release_slot(r, "k"))
    assert r.eval_calls == [sec.RELEASE_SLOT_LUA]


def test_lua_scripts_use_only_acl_allowed_commands():
    forbidden = ("KEYS", "FLUSH", "CONFIG", "DEBUG", "SHUTDOWN", "SCRIPT", "EVAL")
    for script in (sec.ACQUIRE_SLOT_LUA, sec.RELEASE_SLOT_LUA, sec.ACQUIRE_GLOBAL_SLOT_LUA):
        calls = [part.split("'")[1] for part in script.split("redis.call(")[1:]]
        assert calls, "script should call redis"
        for cmd in calls:
            assert not any(cmd.upper().startswith(f) for f in forbidden), cmd


def test_concurrent_acquires_admit_exactly_the_limit():
    r = FakeAsyncRedis()

    async def burst():
        return await asyncio.gather(*(sec.acquire_slot(r, "sess:x:active_jobs", 5, 600) for _ in range(40)))

    results = _run_coro(burst())
    assert sum(results) == 5
    assert int(r.store["sess:x:active_jobs"]) == 5


def test_concurrent_global_admission_admits_exactly_the_limit():
    r = FakeAsyncRedis()

    async def burst():
        return await asyncio.gather(*(sec.acquire_global_slot(r, f"job-{i}", 3, 600) for i in range(25)))

    results = _run_coro(burst())
    assert sum(results) == 3
    assert len(r.zsets[sec.GLOBAL_JOBS_KEY]) == 3


def test_near_limit_burst_does_not_reject_everyone():
    r = FakeAsyncRedis()
    now = time.time()
    r.zsets[sec.GLOBAL_JOBS_KEY] = {f"old-{i}": now for i in range(39)}

    async def burst():
        return await asyncio.gather(*(sec.acquire_global_slot(r, f"new-{i}", 40, 600) for i in range(10)))

    assert sum(_run_coro(burst())) == 1


def test_rejected_acquire_does_not_refresh_ttl():
    r = FakeAsyncRedis()
    assert _run_coro(sec.acquire_slot(r, "k", 1, 600)) is True
    r.ttls["k"] = 42
    assert _run_coro(sec.acquire_slot(r, "k", 1, 600)) is False
    assert r.ttls["k"] == 42
    assert r.store["k"] == "1"


def test_accepted_acquire_always_sets_ttl():
    r = FakeAsyncRedis()
    _run_coro(sec.acquire_slot(r, "k", 3, 123))
    assert r.ttls["k"] == 123


def test_rejected_global_admission_does_not_touch_the_set():
    r = FakeAsyncRedis()
    _run_coro(sec.acquire_global_slot(r, "a", 1, 600))
    r.ttls[sec.GLOBAL_JOBS_KEY] = 7
    assert _run_coro(sec.acquire_global_slot(r, "b", 1, 600)) is False
    assert set(r.zsets[sec.GLOBAL_JOBS_KEY]) == {"a"}
    assert r.ttls[sec.GLOBAL_JOBS_KEY] == 7


def test_release_deletes_counter_at_zero_and_never_goes_negative():
    r = FakeAsyncRedis()
    _run_coro(sec.acquire_slot(r, "k", 2, 60))
    _run_coro(sec.release_slot(r, "k"))
    assert "k" not in r.store
    _run_coro(sec.release_slot(r, "k"))
    assert "k" not in r.store
    assert _run_coro(sec.acquire_slot(r, "k", 1, 60)) is True


def test_global_admission_is_idempotent_for_same_job():
    r = FakeAsyncRedis()
    assert _run_coro(sec.acquire_global_slot(r, "same", 1, 600)) is True
    assert _run_coro(sec.acquire_global_slot(r, "same", 1, 600)) is True
    assert len(r.zsets[sec.GLOBAL_JOBS_KEY]) == 1


def test_stale_global_entries_are_pruned():
    r = FakeAsyncRedis()
    r.zsets[sec.GLOBAL_JOBS_KEY] = {"crashed": time.time() - 10_000}
    assert _run_coro(sec.acquire_global_slot(r, "fresh", 1, 600)) is True
    assert set(r.zsets[sec.GLOBAL_JOBS_KEY]) == {"fresh"}


def test_api_and_worker_release_are_idempotent_together():
    r = FakeAsyncRedis()
    sync = FakeSyncRedis(r)
    fp = "f" * 64
    job = "11111111-1111-4111-8111-111111111111"

    async def admit():
        await sec.acquire_global_slot(r, job, 10, 600)
        await sec.acquire_slot(r, sec.job_slots_key(fp), 3, 600)
        await r.setex(sec.job_slot_flag_key(job), 600, "1")
        await sec.acquire_slot(r, sec.job_slots_key(fp), 3, 600)

    _run_coro(admit())
    r.store[sec.owner_key(job)] = fp
    _run_coro(sec.release_job_slot(r, job, fp))
    sec.release_job_slot_sync(sync, job)
    assert r.store[sec.job_slots_key(fp)] == "1"
    assert job not in r.zsets[sec.GLOBAL_JOBS_KEY]


def test_redis_failure_in_release_never_raises():
    r = FakeAsyncRedis()
    r.fail = True
    _run_coro(sec.release_slot(r, "k"))
    _run_coro(sec.release_job_slot(r, "11111111-1111-4111-8111-111111111111", "f" * 64))


def test_acquire_propagates_redis_failure_so_api_fails_closed():
    r = FakeAsyncRedis()
    r.fail = True
    with pytest.raises(ConnectionError):
        _run_coro(sec.acquire_slot(r, "k", 1, 60))


# ─── Per-Client-Network Active-Job Quotas (Threat Model A4) ─────────────────
@pytest.fixture
def client_quota_env(tmp_path, monkeypatch):
    import app.api.routes as routes
    from app.main import app

    monkeypatch.setattr(settings, "STORAGE_PATH", str(tmp_path))
    monkeypatch.setattr(settings, "SESSION_COOKIE_SECURE", False)
    monkeypatch.setattr(settings, "MAX_ACTIVE_JOBS_PER_CLIENT", 3)
    monkeypatch.setattr(settings, "MAX_ACTIVE_JOBS_PER_SESSION", 3)
    monkeypatch.setattr(settings, "MAX_GLOBAL_ACTIVE_JOBS", 40)
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)
    dispatched = []
    monkeypatch.setattr(routes, "_dispatch_job", lambda *a, **k: dispatched.append(a))
    fake = FakeAsyncRedis()
    app.state.redis = fake
    return {"app": app, "redis": fake, "dispatched": dispatched, "storage": tmp_path}


def _fresh_upload(app, ip="203.0.113.7", content=PNG_MAGIC, extra_headers=None):
    client = TestClient(app, raise_server_exceptions=False)
    headers = {**CSRF, "X-Real-IP": ip, **(extra_headers or {})}
    return client, client.post("/api/upload", files={"file": ("q.png", content, "image/png")}, headers=headers)


def _client_count(cq_env, ip):
    return int(cq_env["redis"].store.get(sec.client_slots_key(sec.client_bucket(ip)), 0) or 0)


def test_cookie_rotation_is_capped_per_client(client_quota_env):
    codes = [_fresh_upload(client_quota_env["app"])[1].status_code for _ in range(6)]
    assert codes[:3] == [200, 200, 200]
    assert set(codes[3:]) == {429}
    assert len(client_quota_env["dispatched"]) == 3
    assert len(client_quota_env["redis"].zsets[sec.GLOBAL_JOBS_KEY]) == 3


def test_rejection_uses_stable_error_and_retry_after(client_quota_env):
    for _ in range(3):
        _fresh_upload(client_quota_env["app"])
    _, res = _fresh_upload(client_quota_env["app"])
    assert res.status_code == 429
    assert res.json()["error_code"] == "TOO_MANY_ACTIVE_JOBS"
    assert res.headers.get("retry-after") == "15"


def test_other_clients_are_not_affected(client_quota_env):
    for _ in range(4):
        _fresh_upload(client_quota_env["app"], ip="203.0.113.7")
    assert _fresh_upload(client_quota_env["app"], ip="198.51.100.20")[1].status_code == 200


def test_ipv6_same_slash64_shares_one_bucket(client_quota_env):
    for i in range(3):
        assert _fresh_upload(client_quota_env["app"], ip=f"2001:db8:1:2::{i + 1}")[1].status_code == 200
    assert _fresh_upload(client_quota_env["app"], ip="2001:db8:1:2:ffff::9")[1].status_code == 429
    assert _fresh_upload(client_quota_env["app"], ip="2001:db8:1:3::1")[1].status_code == 200


def test_ipv4_mapped_ipv6_equals_ipv4():
    assert sec.client_bucket("::ffff:203.0.113.7") == sec.client_bucket("203.0.113.7")


def test_raw_ip_never_stored_in_redis(client_quota_env):
    _fresh_upload(client_quota_env["app"], ip="203.0.113.77")
    blob = json.dumps({"s": client_quota_env["redis"].store, "z": client_quota_env["redis"].zsets}, default=str)
    assert "203.0.113.77" not in blob


def test_cap_disabled_when_zero(client_quota_env, monkeypatch):
    monkeypatch.setattr(settings, "MAX_ACTIVE_JOBS_PER_CLIENT", 0)
    assert all(_fresh_upload(client_quota_env["app"])[1].status_code == 200 for _ in range(5))


def test_proxy_header_ignored_when_not_trusted(client_quota_env, monkeypatch):
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", False)
    codes = [_fresh_upload(client_quota_env["app"], ip=f"198.51.100.{i}")[1].status_code for i in range(5)]
    assert codes.count(200) == 3


def test_client_ip_prefers_real_ip_only_when_trusted(monkeypatch):
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", True)
    assert sec.client_ip({"x-real-ip": " 192.0.2.1 "}, "10.0.0.2") == "192.0.2.1"
    monkeypatch.setattr(settings, "TRUST_PROXY_HEADERS", False)
    assert sec.client_ip({"x-real-ip": "192.0.2.1"}, "10.0.0.2") == "10.0.0.2"


def test_garbage_address_gets_bounded_bucket():
    b = sec.client_bucket("x" * 10_000)
    assert len(b) == 32 and b == sec.client_bucket("x" * 10_000)


def test_rejected_file_releases_client_slot(client_quota_env):
    _fresh_upload(client_quota_env["app"], content=b"#!/bin/sh\n")
    assert _client_count(client_quota_env, "203.0.113.7") == 0


def test_session_cap_rejection_releases_client_slot(client_quota_env, monkeypatch):
    monkeypatch.setattr(settings, "MAX_ACTIVE_JOBS_PER_SESSION", 1)
    client = TestClient(client_quota_env["app"], raise_server_exceptions=False)
    hdr = {**CSRF, "X-Real-IP": "203.0.113.7"}
    assert client.post("/api/upload", files={"file": ("q.png", PNG_MAGIC, "image/png")}, headers=hdr).status_code == 200
    res = client.post("/api/upload", files={"file": ("q.png", PNG_MAGIC, "image/png")}, headers=hdr)
    assert res.status_code == 429
    assert _client_count(client_quota_env, "203.0.113.7") == 1


def test_global_cap_rejection_takes_no_client_slot(client_quota_env, monkeypatch):
    monkeypatch.setattr(settings, "MAX_GLOBAL_ACTIVE_JOBS", 0)
    assert _fresh_upload(client_quota_env["app"])[1].status_code == 503
    assert _client_count(client_quota_env, "203.0.113.7") == 0


def test_cancel_releases_client_slot(client_quota_env):
    client, res = _fresh_upload(client_quota_env["app"])
    job_id = res.json()["job_id"]
    assert _client_count(client_quota_env, "203.0.113.7") == 1
    assert client.delete(f"/api/job/{job_id}", headers=CSRF).status_code == 200
    assert _client_count(client_quota_env, "203.0.113.7") == 0


def test_worker_completion_releases_client_slot_once(client_quota_env):
    client, res = _fresh_upload(client_quota_env["app"])
    job_id = res.json()["job_id"]
    sync = FakeSyncRedis(client_quota_env["redis"])
    sec.release_job_slot_sync(sync, job_id)
    sec.release_job_slot_sync(sync, job_id)
    assert _client_count(client_quota_env, "203.0.113.7") == 0
    _fresh_upload(client_quota_env["app"])
    assert _client_count(client_quota_env, "203.0.113.7") == 1


def test_dispatch_failure_releases_client_slot(client_quota_env, monkeypatch):
    import app.api.routes as routes

    def boom(*a, **k):
        raise RuntimeError("broker down")

    monkeypatch.setattr(routes, "_dispatch_job", boom)
    assert _fresh_upload(client_quota_env["app"])[1].status_code == 503
    assert _client_count(client_quota_env, "203.0.113.7") == 0
    assert len(client_quota_env["redis"].zsets.get(sec.GLOBAL_JOBS_KEY, {})) == 0


def test_redis_failure_mid_admission_releases_taken_slot(client_quota_env, monkeypatch):
    fake = client_quota_env["redis"]
    original = fake.setex

    async def failing_setex(key, ttl, value):
        if key.endswith(":cslot"):
            raise ConnectionError("redis blip")
        return await original(key, ttl, value)

    monkeypatch.setattr(fake, "setex", failing_setex)
    assert _fresh_upload(client_quota_env["app"])[1].status_code == 503
    assert _client_count(client_quota_env, "203.0.113.7") == 0
    assert len(fake.zsets.get(sec.GLOBAL_JOBS_KEY, {})) == 0


# ─── Scheme-Aware Origin Validation & CSRF (Threat Model A4) ────────────────
PROD_ORIGIN = "https://qrguard.example.com"


@pytest.fixture
def prod(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "CORS_ALLOWED_ORIGINS", PROD_ORIGIN)


@pytest.fixture
def dev(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    monkeypatch.setattr(settings, "CORS_ALLOWED_ORIGINS", "http://localhost:5173")


@pytest.mark.parametrize("value,expected", [
    ("https://a.example", ("https", "a.example", 443)),
    ("https://a.example:443", ("https", "a.example", 443)),
    ("http://a.example", ("http", "a.example", 80)),
    ("HTTPS://A.EXAMPLE:8443", ("https", "a.example", 8443)),
    ("https://a.example/", ("https", "a.example", 443)),
    ("http://[::1]:8080", ("http", "::1", 8080)),
])
def test_parse_origin_valid(value, expected):
    assert sec.parse_origin(value) == expected


@pytest.mark.parametrize("value", [
    None, "", "null", "NULL", "file://", "ftp://a.example", "javascript:alert(1)",
    "https://user:pw@a.example", "https://a.example/path", "https://a.example?q=1",
    "https://a.example#f", "https://a.example:99999", "https://", "a.example",
])
def test_parse_origin_rejects_non_origins(value):
    assert sec.parse_origin(value) is None


def test_prod_rejects_http_origin_even_if_host_matches(prod):
    assert not sec.origin_allowed("http://qrguard.example.com", "qrguard.example.com")


def test_prod_accepts_allowlisted_https_origin(prod):
    assert sec.origin_allowed(PROD_ORIGIN, "internal-host:8000")


def test_prod_accepts_https_same_origin(prod):
    assert sec.origin_allowed("https://other.example.org", "other.example.org")


def test_prod_rejects_port_mismatch(prod):
    assert not sec.origin_allowed("https://qrguard.example.com:8443", "qrguard.example.com")
    assert not sec.origin_allowed("https://evil.example:443", "qrguard.example.com:8443")


def test_prod_rejects_lookalike_and_suffix_hosts(prod):
    for o in ("https://qrguard.example.com.evil.example", "https://evilqrguard.example.com",
              "https://qrguard.example.co"):
        assert not sec.origin_allowed(o, "qrguard.example.com"), o


def test_allowlist_is_scheme_sensitive_in_any_environment(dev, monkeypatch):
    monkeypatch.setattr(settings, "CORS_ALLOWED_ORIGINS", "https://app.example")
    assert sec.origin_allowed("https://app.example", "api.internal")
    assert not sec.origin_allowed("http://app.example", "api.internal")


def test_null_origin_rejected(prod):
    assert not sec.origin_allowed("null", "qrguard.example.com")


def test_malformed_host_header_rejected(prod):
    assert not sec.origin_allowed("https://evil.example", "evil.example/@x")
    assert not sec.origin_allowed("https://evil.example", "")


def test_dev_same_origin_http(dev):
    assert sec.origin_allowed("http://testserver", "testserver")
    assert sec.origin_allowed("http://localhost:5173", "api:8000")


def test_dev_ipv6_same_origin(dev):
    assert sec.origin_allowed("http://[::1]:8080", "[::1]:8080")
    assert not sec.origin_allowed("http://[::1]:8080", "[::1]:9090")


def test_csrf_ok_requires_header_and_https_origin_in_prod(prod):
    h = settings.CSRF_HEADER_NAME
    assert sec.csrf_ok({h: "1", "origin": PROD_ORIGIN, "host": "qrguard.example.com"})
    assert not sec.csrf_ok({h: "1", "origin": "http://qrguard.example.com", "host": "qrguard.example.com"})
    assert not sec.csrf_ok({"origin": PROD_ORIGIN, "host": "qrguard.example.com"})


@pytest.fixture
def app_env(tmp_path, monkeypatch):
    import app.api.routes as routes
    from app.main import app

    monkeypatch.setattr(settings, "STORAGE_PATH", str(tmp_path))
    monkeypatch.setattr(settings, "SESSION_COOKIE_SECURE", False)
    monkeypatch.setattr(routes, "_dispatch_job", lambda *a, **k: None)
    fake = FakeAsyncRedis()
    app.state.redis = fake
    return app, fake


def test_upload_with_http_origin_rejected_in_production(app_env, prod):
    app, _ = app_env
    client = TestClient(app, raise_server_exceptions=False)
    res = client.post(
        "/api/upload",
        files={"file": ("q.png", PNG_MAGIC, "image/png")},
        headers={settings.CSRF_HEADER_NAME: "1", "Origin": "http://testserver"},
    )
    assert res.status_code == 403
    assert res.json()["error_code"] == "CSRF_REJECTED"


def test_websocket_with_http_origin_rejected_in_production(app_env, prod):
    app, fake = app_env
    job_id = "22222222-2222-4222-8222-222222222222"
    sid = sec.new_session_id()
    fake.store[sec.owner_key(job_id)] = sec.session_fingerprint(sid)
    fake.store[f"job:{job_id}:result"] = json.dumps({"job_id": job_id, "status": "completed"})
    client = TestClient(app, raise_server_exceptions=False)
    client.cookies.set(settings.SESSION_COOKIE_NAME, sid)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/api/ws/{job_id}", headers={"origin": "http://testserver"}) as ws:
            ws.receive_text()


# ─── Production Configuration Hardening & Hygiene (Threat Model A4) ─────────
def _prod_settings(**kw):
    return Settings(ENVIRONMENT="production", **kw)


def test_production_drops_loopback_and_wildcard_origins():
    s = _prod_settings(CORS_ALLOWED_ORIGINS="http://localhost:5173,http://127.0.0.1,*,https://qrguard.example.com,http://[::1]:8080")
    assert s.cors_origins_list == ["https://qrguard.example.com"]
    assert any("loopback" in w for w in s.production_config_warnings())


def test_production_default_origins_are_all_ignored():
    assert _prod_settings().cors_origins_list == []


def test_development_keeps_localhost_origins():
    s = Settings(ENVIRONMENT="development", CORS_ALLOWED_ORIGINS="http://localhost:5173")
    assert s.cors_origins_list == ["http://localhost:5173"]
    assert s.production_config_errors() == []


def test_production_rejects_insecure_cookie():
    errors = _prod_settings(SESSION_COOKIE_SECURE=False).production_config_errors()
    assert errors and "SESSION_COOKIE_SECURE" in errors[0]


def test_production_secure_cookie_is_ok():
    assert _prod_settings(SESSION_COOKIE_SECURE=True).production_config_errors() == []


def test_production_warns_on_http_origin():
    s = _prod_settings(CORS_ALLOWED_ORIGINS="http://qrguard.example.com")
    assert any("http://" in w for w in s.production_config_warnings())


def test_csrf_origin_check_ignores_localhost_in_production(monkeypatch):
    from app.core import config

    monkeypatch.setattr(config.settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(config.settings, "CORS_ALLOWED_ORIGINS", "http://localhost:5173")
    assert not sec.origin_allowed("http://localhost:5173", "qrguard.example.com")
    assert sec.origin_allowed("https://qrguard.example.com", "qrguard.example.com")


def test_ocr_raw_text_excluded_from_serialisation():
    data = OCRData(raw_text="CCCD 001099012345 Nguyen Van A")
    assert data.raw_text
    assert "raw_text" not in data.model_dump()
    assert "001099012345" not in data.model_dump_json()


def test_csrf_rejection_does_not_log_header_value(caplog):
    caplog.set_level(logging.WARNING)
    assert sec.csrf_ok({settings.CSRF_HEADER_NAME: "evil\nFAKE LOG LINE secret-token"}) is False
    assert "FAKE LOG LINE" not in caplog.text
    assert "secret-token" not in caplog.text


def test_csrf_origin_log_is_bounded(caplog):
    caplog.set_level(logging.WARNING)
    origin = "https://attacker.example/" + "A" * 5000
    assert sec.csrf_ok({settings.CSRF_HEADER_NAME: "1", "origin": origin, "host": "qrguard.example"}) is False
    assert "A" * 200 not in caplog.text


def test_sse_slot_released_even_if_generator_never_started():
    from app.api.routes import _SlotStreamingResponse

    closed, started = [], []

    async def on_close():
        closed.append(1)

    async def gen():
        started.append(1)
        yield "data: x\n\n"

    async def receive():
        await asyncio.sleep(5)
        return {"type": "http.disconnect"}

    async def send(message):
        raise OSError("client went away before the body started")

    async def run():
        resp = _SlotStreamingResponse(gen(), on_close=on_close, media_type="text/event-stream")
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
                 "method": "GET", "path": "/", "headers": []}
        try:
            await resp(scope, receive, send)
        except Exception:
            pass

    asyncio.run(run())
    assert started == []
    assert closed == [1]


# ─── Optional Real-Redis Lua Integration Tests (Skipped unless QRG_TEST_REDIS_URL set) ───
_REAL_REDIS_URL = os.environ.get("QRG_TEST_REDIS_URL")
_skip_without_real_redis = pytest.mark.skipif(
    not _REAL_REDIS_URL, reason="QRG_TEST_REDIS_URL not set (needs a real Redis)"
)


def _run_real_redis(scenario):
    import redis.asyncio as aioredis

    async def main():
        r = aioredis.from_url(_REAL_REDIS_URL, decode_responses=True)
        prefix = f"qrg-test:{uuid.uuid4().hex}:"
        try:
            return await scenario(r, prefix)
        finally:
            keys = [k async for k in r.scan_iter(match=prefix + "*")]
            if keys:
                await r.delete(*keys)
            await r.aclose()

    return asyncio.run(main())


@_skip_without_real_redis
def test_real_acquire_is_exact_under_concurrency():
    async def scenario(r, p):
        key = p + "slots"
        results = await asyncio.gather(*(sec.acquire_slot(r, key, 5, 120) for _ in range(50)))
        return sum(results), await r.get(key), await r.ttl(key)

    admitted, value, ttl = _run_real_redis(scenario)
    assert admitted == 5 and value == "5" and 0 < ttl <= 120


@_skip_without_real_redis
def test_real_rejection_does_not_refresh_ttl():
    async def scenario(r, p):
        key = p + "slots"
        await sec.acquire_slot(r, key, 1, 120)
        await r.expire(key, 30)
        rejected = await sec.acquire_slot(r, key, 1, 120)
        return rejected, await r.ttl(key)

    rejected, ttl = _run_real_redis(scenario)
    assert rejected is False and ttl <= 30


@_skip_without_real_redis
def test_real_release_deletes_at_zero():
    async def scenario(r, p):
        key = p + "slots"
        await sec.acquire_slot(r, key, 3, 120)
        await sec.acquire_slot(r, key, 3, 120)
        await sec.release_slot(r, key)
        mid = await r.get(key)
        await sec.release_slot(r, key)
        await sec.release_slot(r, key)
        return mid, await r.exists(key)

    mid, exists = _run_real_redis(scenario)
    assert mid == "1" and exists == 0


@_skip_without_real_redis
def test_real_global_admission_exact_and_idempotent(monkeypatch):
    async def scenario(r, p):
        monkeypatch.setattr(sec, "GLOBAL_JOBS_KEY", p + "global")
        results = await asyncio.gather(*(sec.acquire_global_slot(r, f"job-{i}", 3, 120) for i in range(20)))
        again = await sec.acquire_global_slot(r, "job-0", 3, 120) if results[0] else None
        return sum(results), await r.zcard(p + "global"), again

    admitted, size, again = _run_real_redis(scenario)
    assert admitted == 3 and size == 3
    assert again in (True, None)

