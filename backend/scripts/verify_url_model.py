"""
Verify the QRDetec URL model bundle (backend/models/url_xgb) with the exact
checks the worker runs at start-up, under production rules.

    python backend/scripts/verify_url_model.py

Checks
  1. SHA256SUMS of every bundle file
  2. vendored runtime code matches VENDORED_FROM.json
  3. validate_bundle(): manifest, sha256, 81-feature contract, calibrator,
     operating threshold, booster load, golden vectors  -> must be READY
  4. a few demonstration scores (pure ML values)

Exit code 0 = valid, non-zero = invalid. Never modifies anything.
"""
import hashlib
import json
import os
import sys

BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUNDLE_DIR = os.path.join(BACKEND_DIR, "models", "url_xgb")
RUNTIME_DIR = os.path.join(BACKEND_DIR, "app", "services", "url_security", "url_model_runtime")

DEMO_URLS = (
    "https://google.com",
    "https://vietcombank.com.vn/",
    "http://vietcombank-xacthuc-otp.top/login",
)


def _sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def check_sha256sums() -> list:
    errors = []
    path = os.path.join(BUNDLE_DIR, "SHA256SUMS")
    if not os.path.exists(path):
        return ["SHA256SUMS missing"]
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            digest, name = line.split(None, 1)
            name = os.path.basename(name.strip().lstrip("*"))
            fp = os.path.join(BUNDLE_DIR, name)
            if not os.path.exists(fp):
                errors.append(f"{name}: missing")
            elif _sha(fp) != digest.lower():
                errors.append(f"{name}: checksum mismatch")
    return errors


def check_vendored_runtime() -> list:
    rec_path = os.path.join(RUNTIME_DIR, "VENDORED_FROM.json")
    if not os.path.exists(rec_path):
        return ["url_model_runtime/VENDORED_FROM.json missing"]
    with open(rec_path, encoding="utf-8") as fh:
        rec = json.load(fh)
    errors = []
    for name, info in rec.get("files", {}).items():
        fp = os.path.join(RUNTIME_DIR, name)
        if not os.path.exists(fp):
            errors.append(f"url_model_runtime/{name}: missing")
        elif _sha(fp) != info.get("vendored_sha256"):
            errors.append(f"url_model_runtime/{name}: modified after export")
    return errors


def main() -> int:
    os.environ["ENVIRONMENT"] = "production"     # enforce sha256 + golden vectors
    sys.path.insert(0, BACKEND_DIR)
    from app.services.url_security.model_service import ModelStatus, URLModelService, validate_bundle
    from app.services.url_security.normalizer import URLNormalizer

    print("QRDetec / URL model verification")
    print("--------------------------------")
    ok = True

    errs = check_sha256sums()
    print(f"Bundle checksums (SHA256SUMS): {'PASS' if not errs else 'FAIL'}")
    for e in errs:
        print(f"   - {e}")
    ok &= not errs

    errs = check_vendored_runtime()
    print(f"Vendored runtime code: {'PASS' if not errs else 'FAIL'}")
    for e in errs:
        print(f"   - {e}")
    ok &= not errs

    status, reason, info = validate_bundle(BUNDLE_DIR)
    print(f"Runtime validation: {'PASS' if status == ModelStatus.READY else 'FAIL'} ({status}: {reason})")
    print(f"   model_id      : {info.get('model_id')}")
    print(f"   feature_schema: {info.get('feature_schema')}")
    print(f"   num_features  : {info.get('num_features')}")
    print(f"   threshold     : {info.get('operating_threshold')}")
    ok &= status == ModelStatus.READY
    if info.get("num_features") != 81:
        print("   - expected exactly 81 features")
        ok = False

    if status == ModelStatus.READY:
        svc = URLModelService(model_path=os.path.join(BUNDLE_DIR, "model.ubj"),
                              manifest_path=os.path.join(BUNDLE_DIR, "manifest.json"))
        norm = URLNormalizer()
        print("Demonstration (pure ML output):")
        for url in DEMO_URLS:
            ev = svc.predict(norm.normalize(url))
            print(f"   {url[:48]:<48} raw={ev.raw_score} calibrated={ev.model_score} "
                  f"pred={ev.ml_prediction}")

    print("\nRESULT:")
    print("QRDETEC URL MODEL VALID" if ok else "QRDETEC URL MODEL INVALID")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
