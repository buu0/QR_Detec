"""
QRDetec integration tests for the exported (81-feature) URL model bundle.

These tests use the REAL exported bundle in models/url_xgb (produced by
AI/tools/export_model.py). Tamper tests operate on copies in tmp_path.
"""
import hashlib
import json
import os
import shutil

import pytest

from app.core.config import settings
from app.models.schemas import SecurityVerdict, ThreatIntelEvidence
from app.services.url_security.model_service import ModelStatus, URLModelService, validate_bundle
from app.services.url_security.normalizer import URLNormalizer
from app.services.url_security.policy import URLSecurityPolicy

BUNDLE = os.path.dirname(settings.XGB_MODEL_PATH)
pytestmark = pytest.mark.skipif(not os.path.exists(settings.XGB_MODEL_PATH),
                                reason="URL model bundle not exported into models/url_xgb")
pytest.importorskip("xgboost")


def _sha(path) -> str:
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def _copy(tmp_path):
    dst = tmp_path / "bundle"
    shutil.copytree(BUNDLE, dst, ignore=shutil.ignore_patterns("*.py", "__pycache__"))
    return dst


def _manifest(d):
    return json.loads((d / "manifest.json").read_text(encoding="utf-8"))


def _write_manifest(d, m, resign=()):
    """Write manifest; optionally re-pin checksums of edited files so a deeper check is reached."""
    for name in resign:
        digest = _sha(d / name)
        m["files_sha256"][name] = digest
        if name == "golden_vectors.json":
            m["golden_vectors"]["sha256"] = digest
        if name == "calibrator.json":
            m["calibrator"]["sha256"] = digest
        if name == "model.ubj":
            m["sha256"] = digest
    (d / "manifest.json").write_text(json.dumps(m), encoding="utf-8")


def _svc(d):
    return URLModelService(model_path=str(d / "model.ubj"), manifest_path=str(d / "manifest.json"))


# ───────────────────────────── shipped bundle ─────────────────────────────

def test_shipped_bundle_is_ready_under_production_rules(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    status, reason, info = validate_bundle(BUNDLE)
    assert status == ModelStatus.READY, reason
    assert info["num_features"] == 81
    assert info["model_id"] == "qrdetec-url-xgb"
    assert 0.0 < info["operating_threshold"] < 1.0


def test_shipped_manifest_contract():
    m = json.loads(open(settings.XGB_MANIFEST_PATH, encoding="utf-8").read())
    assert m["model_id"] == "qrdetec-url-xgb"
    assert m.get("feature_schema_sha256") and m["num_features"] == 81
    assert m["iteration_range"] == [0, m["best_iteration"] + 1]
    thresholds = json.loads(open(os.path.join(BUNDLE, "thresholds.json"), encoding="utf-8").read())
    assert m["operating_threshold"] == thresholds["operating_threshold"]
    names = json.loads(open(os.path.join(BUNDLE, "feature_names.json"), encoding="utf-8").read())
    assert names == m["features"]
    text = json.dumps(m)
    for drive in ("C:\\\\", "D:\\\\", "E:\\\\", "C:/", "D:/", "E:/"):
        assert drive not in text


def test_bundle_contains_only_runtime_files():
    allowed = {"model.ubj", "manifest.json", "feature_schema.json", "feature_names.json",
               "preprocessing_config.json", "calibrator.json", "thresholds.json",
               "golden_vectors.json", "metrics.json", "model_card.md", "SHA256SUMS",
               "import_model.py", "__pycache__"}
    present = set(os.listdir(BUNDLE))
    assert present <= allowed, present - allowed
    for forbidden in (".env", "train.csv", "process_data.csv"):
        assert forbidden not in present


def test_pure_ml_values_are_separately_inspectable():
    svc = URLModelService()
    norm = URLNormalizer()
    for url in ("https://google.com", "http://vietcombank-xacthuc-otp.top/login"):
        ev = svc.predict(norm.normalize(url))
        assert ev.model_status == "READY"
        assert ev.raw_score is not None and 0.0 <= ev.raw_score <= 1.0
        assert ev.model_score is not None and 0.0 <= ev.model_score <= 1.0   # calibrated
        assert ev.ml_threshold == svc.describe()["operating_threshold"]
        assert ev.ml_prediction == int(ev.model_score >= ev.ml_threshold)


def test_ml_model_drives_verdict_directly():
    norm = URLNormalizer().normalize("http://vietcombank-xacthuc-otp.top/login")
    ev = URLModelService().predict(norm)
    assert ev.ml_prediction == 1
    policy = URLSecurityPolicy()
    verdict, _, reasons, *_ = policy.evaluate(
        norm, ev, ThreatIntelEvidence(status="no_known_risk", local_ti_status="NO_MATCH", sources=["Local IOC"])
    )
    assert verdict == SecurityVerdict.MALICIOUS
    assert "URL_XGB_HIGH_SCORE" in reasons


def test_empty_url_is_not_scored():
    ev = URLModelService().predict(URLNormalizer().normalize("   "))
    assert ev.model_score is None and ev.model_status == "INFERENCE_ERROR"


# ───────────────────────────── fail-closed tamper tests ─────────────────────────────

def test_tampered_threshold_file_is_rejected(tmp_path):
    d = _copy(tmp_path)
    th = json.loads((d / "thresholds.json").read_text(encoding="utf-8"))
    th["operating_threshold"] = 0.5
    (d / "thresholds.json").write_text(json.dumps(th), encoding="utf-8")
    svc = _svc(d)
    assert svc.status == ModelStatus.INVALID_ARTIFACT
    assert svc.predict(URLNormalizer().normalize("https://google.com")).model_score is None


def test_resigned_threshold_mismatch_is_still_rejected(tmp_path):
    d = _copy(tmp_path)
    th = json.loads((d / "thresholds.json").read_text(encoding="utf-8"))
    th["operating_threshold"] = 0.5
    (d / "thresholds.json").write_text(json.dumps(th), encoding="utf-8")
    _write_manifest(d, _manifest(d), resign=["thresholds.json"])
    svc = _svc(d)
    assert svc.status == ModelStatus.INVALID_ARTIFACT
    assert "OPERATING_THRESHOLD_MISMATCH" in svc.describe()["reason"]


def test_golden_score_tamper_is_rejected(tmp_path):
    d = _copy(tmp_path)
    gv = json.loads((d / "golden_vectors.json").read_text(encoding="utf-8"))
    gv["records"][0]["raw_score"] += 0.01
    (d / "golden_vectors.json").write_text(json.dumps(gv), encoding="utf-8")
    _write_manifest(d, _manifest(d), resign=["golden_vectors.json"])
    svc = _svc(d)
    assert svc.status == ModelStatus.INVALID_ARTIFACT
    assert "GOLDEN_0_SCORE_MISMATCH" in svc.describe()["reason"]


def test_all_trees_instead_of_best_iteration_is_detected(tmp_path):
    """Using all stored rounds (not best_iteration) changes scores -> golden vectors catch it."""
    d = _copy(tmp_path)
    m = _manifest(d)
    m["best_iteration"] = m["num_boosted_rounds_stored"]
    _write_manifest(d, m)
    svc = _svc(d)
    assert svc.status == ModelStatus.INVALID_ARTIFACT
    assert "BEST_ITERATION_MISMATCH" in svc.describe()["reason"]


def test_missing_best_iteration_is_rejected(tmp_path):
    d = _copy(tmp_path)
    m = _manifest(d)
    del m["best_iteration"]
    _write_manifest(d, m)
    assert _svc(d).describe()["reason"] == "BEST_ITERATION_MISSING"


def test_feature_order_change_is_incompatible(tmp_path):
    d = _copy(tmp_path)
    m = _manifest(d)
    m["features"][0], m["features"][1] = m["features"][1], m["features"][0]
    _write_manifest(d, m)
    svc = _svc(d)
    assert svc.status == ModelStatus.INCOMPATIBLE_FEATURE_SCHEMA
    assert "FEATURE_CONTRACT_MISMATCH" in svc.describe()["reason"]


def test_unknown_feature_schema_is_incompatible(tmp_path):
    d = _copy(tmp_path)
    m = _manifest(d)
    m["feature_schema"] = "E2-v9"
    _write_manifest(d, m)
    svc = _svc(d)
    assert svc.status == ModelStatus.INCOMPATIBLE_FEATURE_SCHEMA
    assert "UNSUPPORTED_FEATURE_SCHEMA" in svc.describe()["reason"]


def test_no_silent_fallback_to_legacy_extractor(tmp_path):
    """Corrupted feature list must not load."""
    d = _copy(tmp_path)
    m = _manifest(d)
    m["features"] = m["features"][:26]
    m["num_features"] = 26
    _write_manifest(d, m)
    svc = _svc(d)
    assert svc.status != ModelStatus.READY
    assert svc.predict(URLNormalizer().normalize("https://google.com")).model_score is None


def test_missing_files_sha256_is_rejected(tmp_path):
    d = _copy(tmp_path)
    m = _manifest(d)
    del m["files_sha256"]
    _write_manifest(d, m)
    assert _svc(d).describe()["reason"] == "FILES_SHA256_MISSING"


def test_threshold_precision_boundary_regression():
    """
    Boundary regression test around operating threshold.
    Ensures prediction comparison uses full-precision calibrated probability
    and does NOT round(score, 4) before comparing against threshold.
    """
    svc = URLModelService()
    svc._status = ModelStatus.READY
    svc._ml_threshold = 0.78506969

    score_below = 0.78505
    ev_below = svc._evidence(
        ModelStatus.READY,
        score=round(score_below, 4),
        prediction=int(score_below >= svc._ml_threshold),
    )
    assert ev_below.model_score == 0.7851
    assert ev_below.ml_prediction == 0

    score_above = 0.78507
    ev_above = svc._evidence(
        ModelStatus.READY,
        score=round(score_above, 4),
        prediction=int(score_above >= svc._ml_threshold),
    )
    assert ev_above.model_score == 0.7851
    assert ev_above.ml_prediction == 1
