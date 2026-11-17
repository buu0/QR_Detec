"""
Model Integration Interface (adapter) tests.
Validates loading, fail-closed security, and manifest contract.
"""
import hashlib
import json
import pytest

from app.core.config import settings
from app.models.schemas import SecurityVerdict, ThreatIntelEvidence
from app.services.url_security.model_service import ModelStatus, URLModelService
from app.services.url_security.normalizer import URLNormalizer
from app.services.url_security.policy import URLSecurityPolicy

from app.services.url_security.url_model_runtime import FEATURE_NAMES

URL = "https://example.org/some/path?q=1"
FEATS_81 = list(FEATURE_NAMES)


@pytest.fixture
def normalizer():
    return URLNormalizer()


def _manifest(tmp_path, **overrides):
    data = {
        "model_name": "QRDetec URL XGBoost",
        "model_id": "qrdetec-url-xgb",
        "n_features": 81,
        "features": list(FEATS_81),
        "output_type": "probability",
    }
    data.update(overrides)
    (tmp_path / "manifest.json").write_text(json.dumps(data), encoding="utf-8")
    return data


def _svc(tmp_path):
    return URLModelService(model_path=str(tmp_path / "model.ubj"),
                           manifest_path=str(tmp_path / "manifest.json"))


def test_no_bundle_is_not_configured_and_never_scores(normalizer, tmp_path):
    svc = _svc(tmp_path)
    ev = svc.predict(normalizer.normalize(URL))
    assert svc.status == ModelStatus.NOT_CONFIGURED
    assert ev.model_status == "NOT_CONFIGURED"
    assert ev.model_score is None
    assert svc.cache_fingerprint == "none-not_configured"


def test_manifest_without_weights_is_not_configured(normalizer, tmp_path):
    _manifest(tmp_path)
    svc = _svc(tmp_path)
    ev = svc.predict(normalizer.normalize(URL))
    assert ev.model_status == "NOT_CONFIGURED" and ev.reason == "MODEL_FILE_NOT_FOUND"
    assert ev.model_score is None


def test_repository_ships_only_the_verified_model_export():
    """Guard against a placeholder model: weights may exist only as the checksummed canonical export."""
    import os
    if not os.path.exists(settings.XGB_MODEL_PATH):
        return
    bundle = os.path.dirname(settings.XGB_MODEL_PATH)
    manifest = json.loads(open(settings.XGB_MANIFEST_PATH, encoding="utf-8").read())
    assert manifest["model_id"] == "qrdetec-url-xgb"
    assert manifest.get("feature_schema_sha256")
    assert manifest["num_features"] == 81 and len(manifest["features"]) == 81
    assert hashlib.sha256(open(settings.XGB_MODEL_PATH, "rb").read()).hexdigest() == manifest["sha256"]
    sums = open(os.path.join(bundle, "SHA256SUMS"), encoding="utf-8").read().split()
    listed = dict(zip(sums[1::2], sums[0::2]))
    assert listed["model.ubj"] == manifest["sha256"]


def test_model_unavailable_does_not_lead_to_safe_conclusion(normalizer, tmp_path):
    ev = _svc(tmp_path).predict(normalizer.normalize("https://vietcombank-xacthuc.com/"))
    norm = normalizer.normalize("https://vietcombank-xacthuc.com/")
    verdict, *_ = URLSecurityPolicy().evaluate(norm, ev, ThreatIntelEvidence(status="unknown"))
    assert verdict == SecurityVerdict.UNVERIFIABLE


def test_unknown_feature_count_is_incompatible(normalizer, tmp_path):
    _manifest(tmp_path, features=[f"feat_{i}" for i in range(26)], n_features=26)
    (tmp_path / "model.ubj").write_bytes(b"placeholder-bytes-for-contract-test")
    svc = _svc(tmp_path)
    ev = svc.predict(normalizer.normalize(URL))
    assert svc.status == ModelStatus.INCOMPATIBLE_FEATURE_SCHEMA
    assert "NUM_FEATURES_MISMATCH" in ev.reason
    assert ev.model_score is None


@pytest.mark.parametrize("overrides,status,reason", [
    ({"features": ["f"] * 81}, ModelStatus.INVALID_ARTIFACT, "DUPLICATE_FEATURE_NAMES"),
    ({"n_features": 63}, ModelStatus.INVALID_ARTIFACT, "NUM_FEATURES_MISMATCH"),
    ({"output_type": "label"}, ModelStatus.INVALID_ARTIFACT, "UNSUPPORTED_OUTPUT_TYPE"),
    ({"model_id": "other-model"}, ModelStatus.INCOMPATIBLE_FEATURE_SCHEMA, "UNSUPPORTED_MODEL_ID"),
])
def test_manifest_contract_violations(tmp_path, overrides, status, reason):
    _manifest(tmp_path, **overrides)
    (tmp_path / "model.ubj").write_bytes(b"x")
    svc = _svc(tmp_path)
    assert svc.status == status
    assert reason in svc.describe()["reason"]


def test_production_requires_checksum(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    _manifest(tmp_path)
    (tmp_path / "model.ubj").write_bytes(b"x")
    svc = _svc(tmp_path)
    assert svc.status == ModelStatus.INVALID_ARTIFACT
    assert svc.describe()["reason"] == "CHECKSUM_MISSING"


def test_checksum_mismatch_is_invalid(tmp_path):
    _manifest(tmp_path, sha256="0" * 64)
    (tmp_path / "model.ubj").write_bytes(b"x")
    svc = _svc(tmp_path)
    assert svc.status == ModelStatus.INVALID_ARTIFACT
    assert "CHECKSUM_MISMATCH" in svc.describe()["reason"]


def test_corrupt_model_file_does_not_crash(tmp_path):
    pytest.importorskip("xgboost")
    _manifest(tmp_path)
    (tmp_path / "model.ubj").write_bytes(b"not-a-real-xgboost-model")
    svc = _svc(tmp_path)
    assert svc.status == ModelStatus.INVALID_ARTIFACT
    assert "RUNTIME_UNAVAILABLE" in svc.describe()["reason"] or "BUNDLE_FILE_MISSING" in svc.describe()["reason"] or "XGBOOST_LOAD_ERROR" in svc.describe()["reason"]
