"""
Regression tests for File Result Cache TTL (P0).
Proves:
1. A completed/full/warning-free result is written to the content-hash cache.
2. The expected TTL is FILE_RESULT_CACHE_TTL (from settings).
3. Changing Local IOC feed hash changes the cache key.
4. No TI_*_TTL variable is required or referenced.
5. Cache write failure is observable in logs / exceptions.
"""
import sys
from unittest.mock import MagicMock, patch
import pytest

if "celery" not in sys.modules:
    try:
        import celery  # noqa: F401
    except ImportError:
        mock_celery = MagicMock()
        mock_signal = MagicMock()
        mock_signal.connect = lambda f: f
        mock_celery.signals.worker_process_init = mock_signal
        mock_celery.signals.worker_ready = mock_signal
        mock_app_instance = MagicMock()
        mock_app_instance.task = lambda *args, **kwargs: (lambda fn: (setattr(fn, "run", (lambda *a, **k: fn(None, *a, **k) if kwargs.get("bind") else fn(*a, **k))) or fn))
        mock_celery.Celery.return_value = mock_app_instance
        sys.modules["celery"] = mock_celery
        sys.modules["celery.signals"] = mock_celery.signals
        sys.modules["celery.exceptions"] = MagicMock()

from app.core.config import settings
from app.models.schemas import JobStatus, ProcessingResult
from app.worker.celery_app import (
    _save_result,
    cache_namespace,
    result_cache_key,
)


def test_file_result_cache_written_with_correct_ttl():
    """Prove that completed, full, warning-free results are written with FILE_RESULT_CACHE_TTL."""
    mock_redis = MagicMock()
    result = ProcessingResult(
        job_id="job-123",
        status=JobStatus.COMPLETED,
        file_name="sample.png",
        analysis_completeness="full",
        warnings=[],
    )

    fhash = "abc123hash"
    _save_result(mock_redis, "job-123", result, fhash)

    # Job-level key write
    mock_redis.setex.assert_any_call(
        "job:job-123:result",
        settings.RESULT_CACHE_TTL,
        result.model_dump_json(),
    )

    # File-hash level key write with FILE_RESULT_CACHE_TTL
    expected_cache_key = result_cache_key(fhash)
    mock_redis.setex.assert_any_call(
        expected_cache_key,
        settings.FILE_RESULT_CACHE_TTL,
        result.model_dump_json(),
    )


def test_no_file_result_cache_on_incomplete_or_warnings():
    """Partial results or results with warnings must NOT be cached to avoid replaying transient states."""
    mock_redis = MagicMock()

    # Case A: with warnings
    res_warn = ProcessingResult(
        job_id="job-warn",
        status=JobStatus.COMPLETED,
        file_name="sample.png",
        analysis_completeness="full",
        warnings=["TI_FEED_UNAVAILABLE"],
    )
    _save_result(mock_redis, "job-warn", res_warn, "fhash-warn")
    assert not any(call[0][0].startswith("file-result:") for call in mock_redis.setex.call_args_list)

    # Case B: partial completeness
    mock_redis.reset_mock()
    res_partial = ProcessingResult(
        job_id="job-part",
        status=JobStatus.COMPLETED,
        file_name="sample.png",
        analysis_completeness="partial",
        warnings=[],
    )
    _save_result(mock_redis, "job-part", res_partial, "fhash-part")
    assert not any(call[0][0].startswith("file-result:") for call in mock_redis.setex.call_args_list)


def test_changing_local_ioc_feed_hash_changes_cache_key():
    """Cache key must incorporate the Local IOC feed identity."""
    fhash = "file123"

    mock_ti_service = MagicMock()
    mock_ti_service.get_feed_sha256.return_value = "aaaaaaaaaaaaaaaa11111111"

    with patch("app.worker.celery_app.get_threat_intel_service", return_value=mock_ti_service):
        key1 = result_cache_key(fhash)

    mock_ti_service.get_feed_sha256.return_value = "bbbbbbbbbbbbbbbb22222222"
    with patch("app.worker.celery_app.get_threat_intel_service", return_value=mock_ti_service):
        key2 = result_cache_key(fhash)

    assert key1 != key2
    assert "ti-aaaaaaaaaaaaaaaa" in key1
    assert "ti-bbbbbbbbbbbbbbbb" in key2


def test_no_ti_ttl_variable_required():
    """Verify settings contains FILE_RESULT_CACHE_TTL and does not rely on removed TI_*_TTL attributes."""
    assert hasattr(settings, "FILE_RESULT_CACHE_TTL")
    assert settings.FILE_RESULT_CACHE_TTL > 0
    assert not hasattr(settings, "TI_UNKNOWN_TTL")
    assert not hasattr(settings, "TI_MALICIOUS_TTL")
    assert not hasattr(settings, "TI_CLEAN_TTL")


def test_cache_write_failure_is_observable():
    """Failure to write to redis during _save_result logs an error and does not raise uncaught exception."""
    mock_redis = MagicMock()
    mock_redis.setex.side_effect = RuntimeError("Redis connection failure")

    result = ProcessingResult(
        job_id="job-err",
        status=JobStatus.COMPLETED,
        file_name="sample.png",
        analysis_completeness="full",
        warnings=[],
    )

    with patch("app.worker.celery_app.logger.error") as mock_log_err:
        _save_result(mock_redis, "job-err", result, "fhash-err")
        mock_log_err.assert_called_once()
        assert "job-err" in mock_log_err.call_args[0][1]


# ─── Session-Scoped Cache Isolation & Stale Queue Guard (Threat Model A4) ───

import time
import uuid
import app.worker.celery_app as celery_worker_mod
from app.core.security import owner_key


class _DictRedis:
    def __init__(self, data=None):
        self.data = dict(data or {})

    def get(self, key):
        return self.data.get(key)

    def exists(self, key):
        return int(key in self.data)


def test_scoped_hash_differs_per_owner():
    fhash = "a" * 64
    r = _DictRedis({
        owner_key("job1"): "owner-A",
        owner_key("job2"): "owner-B",
        owner_key("job3"): b"owner-A",
    })
    h1 = celery_worker_mod.scoped_file_hash(r, "job1", fhash)
    h2 = celery_worker_mod.scoped_file_hash(r, "job2", fhash)
    h3 = celery_worker_mod.scoped_file_hash(r, "job3", fhash)
    assert h1 and h2 and h1 != h2
    assert h1 == h3  # same session -> same cache entry
    assert fhash not in h1


def test_scoped_hash_none_without_owner():
    assert celery_worker_mod.scoped_file_hash(_DictRedis(), "job-x", "b" * 64) is None


def test_scoped_hash_none_on_redis_error():
    class Broken:
        def get(self, key):
            raise ConnectionError("down")

    assert celery_worker_mod.scoped_file_hash(Broken(), "job-x", "c" * 64) is None


def test_stale_queued_job_is_rejected(monkeypatch):
    jid = str(uuid.uuid4())
    assert celery_worker_mod.is_valid_job_id(jid)
    finished, read = [], []
    monkeypatch.setattr(celery_worker_mod, "get_redis", lambda: _DictRedis())
    monkeypatch.setattr(celery_worker_mod, "resolve_job_file", lambda j, p, t: "/nonexistent/qrguard-test")
    monkeypatch.setattr(celery_worker_mod, "read_job_file", lambda *a, **k: read.append(1) or b"")
    monkeypatch.setattr(celery_worker_mod, "publish_progress", lambda *a, **k: None)
    monkeypatch.setattr(celery_worker_mod, "release_job_slot_sync", lambda *a, **k: None)
    monkeypatch.setattr(celery_worker_mod, "_finish", lambda r, j, result, *a, **k: finished.append(result))

    enqueued = time.time() - settings.JOB_QUEUE_MAX_WAIT_SECONDS - 5
    celery_worker_mod.process_qr_file.run(jid, "/app/uploads/x.png", "x.png", "image/png", enqueued)

    assert read == []  # file never processed
    assert len(finished) == 1
    assert "SERVICE_UNAVAILABLE" in finished[0].model_dump_json()
