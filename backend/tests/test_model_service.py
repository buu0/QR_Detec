"""
Unit tests for XGBoost Model Service (Graceful degradation, Manifest validation, SHA-256)
"""
import json
import pytest
from app.services.url_security.model_service import ModelStatus, URLModelService
from app.services.url_security.normalizer import URLNormalizer
from app.services.url_security.url_model_runtime import FEATURE_NAMES


@pytest.fixture
def normalizer():
    return URLNormalizer()


def test_missing_manifest_graceful_degradation(normalizer, tmp_path):
    missing_manifest = str(tmp_path / "non_existent_manifest.json")
    svc = URLModelService(manifest_path=missing_manifest)
    norm = normalizer.normalize("https://example.com/test")

    evidence = svc.predict(norm)
    assert evidence.model_status == "NOT_CONFIGURED"
    assert "MANIFEST_NOT_FOUND" in evidence.reason
    assert evidence.model_score is None


def test_model_service_missing_file_graceful(normalizer, tmp_path):
    manifest_file = tmp_path / "manifest.json"
    manifest_data = {
        "model_name": "QRDetec URL XGBoost",
        "model_id": "qrdetec-url-xgb",
        "n_features": 81,
        "features": list(FEATURE_NAMES),
        "sha256": "",
    }
    manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

    missing_model = str(tmp_path / "non_existent_model.ubj")
    svc = URLModelService(model_path=missing_model, manifest_path=str(manifest_file))
    norm = normalizer.normalize("https://example.com/login")

    evidence = svc.predict(norm)
    assert evidence.model_status != ModelStatus.READY
    assert "MODEL_FILE_NOT_FOUND" in evidence.reason
    assert evidence.model_score is None


def test_model_service_checksum_mismatch(normalizer, tmp_path):
    dummy_model = tmp_path / "model.ubj"
    dummy_model.write_bytes(b"dummy binary model content")

    manifest_file = tmp_path / "manifest.json"
    manifest_data = {
        "model_name": "QRDetec URL XGBoost",
        "model_id": "qrdetec-url-xgb",
        "n_features": 81,
        "features": list(FEATURE_NAMES),
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    }
    manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

    svc = URLModelService(model_path=str(dummy_model), manifest_path=str(manifest_file))
    norm = normalizer.normalize("https://example.com/login")

    evidence = svc.predict(norm)
    assert evidence.model_status == ModelStatus.INVALID_ARTIFACT
    assert "CHECKSUM_MISMATCH" in evidence.reason


def test_unsupported_model_id_rejected(normalizer, tmp_path):
    manifest_file = tmp_path / "manifest.json"
    manifest_data = {
        "model_name": "legacy_model",
        "model_id": "legacy-url-26",
        "n_features": 26,
        "features": [f"f_{i}" for i in range(26)],
    }
    manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

    svc = URLModelService(manifest_path=str(manifest_file))
    norm = normalizer.normalize("https://example.com/login")

    evidence = svc.predict(norm)
    assert evidence.model_status == ModelStatus.INCOMPATIBLE_FEATURE_SCHEMA
    assert "UNSUPPORTED_MODEL_ID" in evidence.reason
