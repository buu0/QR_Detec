"""
Model Bundle Import & Verification Utility for the QR Guard URL XGBoost Classifier.

RECOMMENDED (current URL XGBoost model): export directly from the AI workspace, which verifies
the frozen model bundle first and vendors the matching feature extractor:

  python AI/tools/export_model.py
  python backend/scripts/verify_url_model.py

This utility remains for validating/installing a bundle directory copied from elsewhere:

  python backend/models/url_xgb/import_model.py --bundle /path/to/bundle            # validate only
  python backend/models/url_xgb/import_model.py --bundle /path/to/bundle --install  # validate + install
"""
import argparse
import hashlib
import json
import os
import shutil
import sys

BUNDLE_FILES = (
    "manifest.json", "model.ubj", "golden_vectors.json", "feature_names.json",
    "feature_schema.json", "preprocessing_config.json", "calibrator.json",
    "thresholds.json", "metrics.json", "model_card.md", "SHA256SUMS",
)


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate / install an XGBoost model bundle for QR Guard")
    parser.add_argument("--bundle", required=True, help="Directory containing manifest.json + model.ubj + golden_vectors.json")
    parser.add_argument("--install", action="store_true", help="Copy the bundle into this directory if it is READY")
    parser.add_argument("--expected-sha256", default="", help="SHA-256 of model.ubj communicated out-of-band by the trainer")
    args = parser.parse_args()

    bundle = os.path.abspath(args.bundle)
    for required in ("manifest.json", "model.ubj"):
        if not os.path.exists(os.path.join(bundle, required)):
            print(f"[-] Missing {required} in bundle")
            return 1

    actual_sha = compute_sha256(os.path.join(bundle, "model.ubj"))
    print(f"[*] model.ubj SHA-256: {actual_sha}")
    if args.expected_sha256 and args.expected_sha256.strip().lower() != actual_sha:
        print("[-] SHA-256 does not match the value provided by the trainer (provenance check failed)")
        return 1

    # Enforce production validation rules (sha256 pinned in manifest, golden vectors present).
    os.environ["ENVIRONMENT"] = "production"
    backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    sys.path.insert(0, backend_dir)
    from app.services.url_security.model_service import ModelStatus, validate_bundle  # noqa: E402

    status, reason, info = validate_bundle(bundle)
    print(f"[*] Validation status: {status}")
    print(f"[*] Reason: {reason}")
    print(json.dumps(info, indent=2, ensure_ascii=False))
    if status != ModelStatus.READY:
        print("[-] Bundle rejected. The worker would run without ML (Local IOC continues).")
        return 2

    if not args.install:
        print("[+] Bundle is valid. Re-run with --install to activate it.")
        return 0

    target = os.path.dirname(os.path.abspath(__file__))
    for name in BUNDLE_FILES:
        src = os.path.join(bundle, name)
        if os.path.exists(src):
            shutil.copyfile(src, os.path.join(target, name))
            print(f"[+] Installed {name}")
    print("[+] Installed. Rebuild/restart the worker (docker compose up -d --build processing-worker).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
