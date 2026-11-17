#!/usr/bin/env python3
"""
Generate deployment secrets for QR Guard (never prints secret values).

Creates (all git-ignored, Docker build context excluded):
  secrets/redis_url            -> redis://qrguard:<random>@redis-broker:6379/0   (Docker secret)
  redis/users.acl              -> ACL with only the SHA-256 hash of that password

Usage:
  python scripts/generate_secrets.py                    # first-time setup
  python scripts/generate_secrets.py --rotate           # rotate the Redis password
"""
import argparse
import hashlib
import os
import secrets
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRETS_DIR = os.path.join(ROOT, "secrets")
ACL_PATH = os.path.join(ROOT, "redis", "users.acl")
REDIS_URL_PATH = os.path.join(SECRETS_DIR, "redis_url")


def _write_private(path: str, content: str, mode: int = 0o600) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    os.replace(tmp, path)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rotate", action="store_true", help="overwrite existing Redis credentials")
    ap.add_argument("--redis-host", default="redis-broker")
    args = ap.parse_args()

    if os.path.exists(REDIS_URL_PATH) and not args.rotate:
        print("secrets/redis_url already exists — use --rotate to generate a new Redis password.")
    else:
        password = secrets.token_urlsafe(32)
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        _write_private(REDIS_URL_PATH, f"redis://qrguard:{password}@{args.redis_host}:6379/0\n")
        acl = (
            "user default off\n"
            f"user qrguard on #{digest} ~* &* +@all -@dangerous +info\n"
        )
        # Redis runs as uid 999 inside its container and must be able to read this file.
        _write_private(ACL_PATH, acl, mode=0o644)
        print("Generated Redis ACL (hash only) and secrets/redis_url.")
        del password

    print(
        "\nNext steps:\n"
        "  1. Remove REDIS_URL from .env (secret file takes over).\n"
        "  2. On Linux hosts make the files readable by the container user (uid 1000), e.g.\n"
        "       sudo chown root:1000 secrets/* && sudo chmod 0640 secrets/*\n"
        "  3. docker compose up -d --build"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
