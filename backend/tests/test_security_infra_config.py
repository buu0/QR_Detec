"""
System security regression suite — infrastructure, configuration and supply chain.

Static checks over the deployment files shipped in the repository (docker-compose, Dockerfile,
nginx, redis, .gitignore/.dockerignore, frontend sources, requirements). They encode the
hardening that exists today so it cannot silently regress.

Tests marked `xfail(strict=True)` document open defense-in-depth / supply-chain items (Limitation 16).
They are expected to fail now; when an item is hardened the test starts passing, pytest reports
XPASS as a failure, and the marker must be removed — turning the fix into a permanent guard.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"


def _read(rel: str) -> str:
    path = ROOT / rel
    if not path.exists():
        pytest.skip(f"{rel} not present in this checkout/image")
    return path.read_text(encoding="utf-8", errors="replace")


def _strip_comments(text: str) -> str:
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


@pytest.fixture(scope="module")
def compose():
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(_read("docker-compose.yml"))


# ═══ Container hardening (docker-compose.yml) ═══════════════════════════════
def test_every_service_is_hardened(compose):
    for name, svc in compose["services"].items():
        assert svc.get("read_only") is True, f"{name}: read_only rootfs"
        assert "no-new-privileges:true" in (svc.get("security_opt") or []), f"{name}: no-new-privileges"
        assert "ALL" in (svc.get("cap_drop") or []), f"{name}: cap_drop ALL"
        assert not svc.get("privileged"), f"{name}: privileged"
        assert svc.get("network_mode") != "host" and svc.get("pid") != "host", f"{name}: host namespaces"
        for vol in svc.get("volumes") or []:
            assert "docker.sock" not in str(vol), f"{name}: docker socket mounted"


def test_only_the_reverse_proxy_publishes_ports(compose):
    published = {n for n, s in compose["services"].items() if s.get("ports")}
    assert published == {"pwa-frontend"}


def test_internal_networks_have_no_internet_route(compose):
    nets = compose["networks"]
    assert nets["app"].get("internal") is True
    assert nets["backend"].get("internal") is True
    assert set(compose["services"]["redis-broker"]["networks"]) == {"backend"}
    assert set(compose["services"]["processing-worker"]["networks"]) == {"backend"}


def test_third_party_images_pinned_by_digest(compose):
    for name, svc in compose["services"].items():
        if "image" in svc:
            assert "@sha256:" in svc["image"], f"{name}: image not pinned by digest"


def test_resource_limits_on_compute_services(compose):
    for name in ("api-gateway", "processing-worker", "redis-broker"):
        limits = compose["services"][name]["deploy"]["resources"]["limits"]
        assert limits.get("memory") and limits.get("cpus"), name
    for name in ("api-gateway", "processing-worker"):
        assert compose["services"][name]["deploy"]["resources"]["limits"].get("pids"), name


def test_secrets_injected_as_files_not_env(compose):
    for name in ("api-gateway", "processing-worker"):
        env = compose["services"][name]["environment"]
        assert "REDIS_URL_FILE=/run/secrets/redis_url" in env, name
        assert not any(str(e).startswith("REDIS_URL=") for e in env), name
        assert "redis_url" in compose["services"][name]["secrets"], name


def test_secure_defaults_in_compose(compose):
    env = compose["services"]["api-gateway"]["environment"]
    assert "ENVIRONMENT=${ENVIRONMENT:-production}" in env
    assert "SESSION_COOKIE_SECURE=${SESSION_COOKIE_SECURE:-true}" in env
    cmd = compose["services"]["api-gateway"]["command"]
    assert "--no-server-header" in cmd and "--ws-max-size" in cmd and "--limit-concurrency" in cmd


def test_worker_mounts_ti_feed_read_only(compose):
    vols = compose["services"]["processing-worker"]["volumes"]
    assert any(str(v).endswith("/app/ti_feed:ro") for v in vols)


# ═══ Dockerfile ═════════════════════════════════════════════════════════════
def test_dockerfile_runs_as_non_root_and_verifies_models():
    df = _read("backend/Dockerfile")
    users = re.findall(r"^USER\s+(\S+)", df, flags=re.M)
    assert users and users[-1] not in ("root", "0")
    assert "sha256sum -c" in df
    assert "apt-get purge" in df and "curl" in df.split("apt-get purge", 1)[1].split("\n")[0]
    assert "chmod -R a-w /app/app" in df


@pytest.mark.xfail(strict=True, reason="Supply-chain future work: python base image is not pinned by digest")
def test_dockerfile_base_image_pinned_by_digest():
    froms = re.findall(r"^FROM\s+(\S+)", _read("backend/Dockerfile"), flags=re.M)
    assert froms and all("@sha256:" in f for f in froms)


@pytest.mark.xfail(strict=True, reason="Supply-chain future work: PaddleOCR model download is unverified and failures are ignored")
def test_dockerfile_has_no_ignored_failures():
    assert "|| true" not in _read("backend/Dockerfile")


def test_dockerignore_excludes_secrets():
    di = _read("backend/.dockerignore")
    for pattern in (".env", "secrets"):
        assert pattern in di, pattern


# ═══ Supply chain ═══════════════════════════════════════════════════════════
def _requirements():
    lines = [l.strip() for l in _read("backend/requirements.txt").splitlines()]
    return [l for l in lines if l and not l.startswith("#")]


def test_security_relevant_packages_are_exactly_pinned():
    pinned = {l.split("==")[0].split("[0]")[0].split("[")[0].lower(): l for l in _requirements() if "==" in l}
    for pkg in ("fastapi", "uvicorn", "python-multipart", "pillow", "pymupdf", "celery", "redis", "pydantic"):
        assert pkg in pinned, f"{pkg} must be pinned with =="


def test_multipart_parser_version_has_known_dos_fix():
    req = {l.split("==")[0].lower(): l.split("==")[1] for l in _requirements() if "==" in l}
    major, minor, patch = (int(x) for x in req["python-multipart"].split("."))
    assert (major, minor, patch) >= (0, 0, 18)  # CVE-2024-53981 fixed in 0.0.18


@pytest.mark.xfail(strict=True, reason="Supply-chain future work: some dependencies use version ranges")
def test_all_dependencies_exactly_pinned():
    assert all("==" in l for l in _requirements())


# ═══ Redis ══════════════════════════════════════════════════════════════════
def test_redis_conf_hardening():
    conf = _strip_comments(_read("redis/redis.conf"))
    assert re.search(r"^protected-mode\s+yes", conf, re.M)
    assert re.search(r"^aclfile\s+\S+", conf, re.M)
    assert re.search(r'^save\s+""', conf, re.M), "no RDB persistence of payment data"
    assert re.search(r"^appendonly\s+no", conf, re.M)
    assert re.search(r"^maxmemory-policy\s+noeviction", conf, re.M), "eviction could drop quota keys"
    assert "requirepass" not in conf


def _acl_rules() -> list:
    """Redis ACL: '#' starts a comment only at line start; inside a rule '#<hex>' is a password hash."""
    return [l.strip() for l in _read("redis/users.acl.example").splitlines()
            if l.strip() and not l.strip().startswith("#")]


def test_redis_acl_template_disables_default_and_dangerous():
    rules = _acl_rules()
    assert any(re.match(r"^user\s+default\s+off\b", l) for l in rules)
    app_user = [l for l in rules if l.startswith("user qrguard")]
    assert app_user and "-@dangerous" in app_user[0]
    assert not re.search(r"(^|\s)>\S", app_user[0]), "plaintext password in template"


def test_slot_scripts_compatible_with_acl():
    """Atomic Lua quota scripts need EVAL (@scripting) which `-@dangerous` keeps allowed."""
    acl = _read("redis/users.acl.example")
    assert "-@scripting" not in acl and "-eval" not in acl.lower()


@pytest.mark.xfail(strict=True, reason="Defense-in-depth future work: one Redis user shared by API and worker")
def test_redis_acl_separates_api_and_worker():
    users = [l.split()[1] for l in _acl_rules() if re.match(r"^user\s+\S+\s+on\b", l)]
    assert len(users) >= 2


# ═══ Nginx ══════════════════════════════════════════════════════════════════
def _location_blocks(conf: str):
    return re.findall(r"location\s+[^{]+\{(.*?)\n\}", conf, flags=re.S)


def test_nginx_request_hygiene():
    conf = _strip_comments(_read("nginx/qrguard_server.conf"))
    assert "server_tokens off;" in conf
    assert re.search(r"client_max_body_size 1m;", conf)
    method_rule = re.search(r"\$request_method !~ \^\(([^)]+)\)\$", conf).group(1).split("|")
    assert set(method_rule) == {"GET", "HEAD", "POST", "DELETE", "OPTIONS"}
    assert "$upload_csrf_precheck = 0" in conf


def test_nginx_every_location_includes_security_headers():
    conf = _strip_comments(_read("nginx/qrguard_server.conf"))
    blocks = _location_blocks(conf)
    assert blocks
    for body in blocks:
        assert "security_headers.conf" in body


def test_nginx_every_api_proxy_overwrites_real_ip():
    """Per-client-network quota trusts X-Real-IP: every proxied location MUST overwrite it with $remote_addr."""
    conf = _strip_comments(_read("nginx/qrguard_server.conf"))
    for body in _location_blocks(conf):
        if "proxy_pass" in body:
            assert "proxy_set_header X-Real-IP $remote_addr;" in body


def test_nginx_upload_is_rate_and_concurrency_limited():
    conf = _strip_comments(_read("nginx/qrguard_server.conf"))
    upload = conf.split("location = /api/upload", 1)[1].split("\n}", 1)[0]
    assert "limit_req zone=upload_limit" in upload and "limit_conn conn_per_ip" in upload
    assert "client_max_body_size 51m" in upload


def test_csp_blocks_scripts_framing_and_plugins():
    headers = _read("nginx/security_headers.conf")
    csp = re.search(r'Content-Security-Policy "([^"]+)"', headers).group(1)
    assert "script-src 'self'" in csp and "'unsafe-eval'" not in csp
    assert "object-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert "base-uri 'self'" in csp
    for h in ("X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy", "Strict-Transport-Security"):
        assert h in headers


def test_tls_example_uses_modern_protocols_only():
    tls = _strip_comments(_read("nginx/nginx.tls.conf.example"))
    protos = re.search(r"ssl_protocols ([^;]+);", tls).group(1).split()
    assert set(protos) <= {"TLSv1.2", "TLSv1.3"}
    assert "ssl_session_tickets off;" in tls


def test_hsts_only_over_https():
    common = _read("nginx/qrguard_common.conf")
    assert re.search(r"map \$scheme \$qrg_hsts", common)


@pytest.mark.xfail(strict=True, reason="Defense-in-depth future work: no real-IP configuration for deployments behind an upstream load balancer")
def test_nginx_real_ip_configured():
    assert "set_real_ip_from" in _strip_comments(_read("nginx/qrguard_common.conf"))


def test_nginx_blocks_public_readiness_probe():
    assert "location = /api/health/ready" in _read("nginx/qrguard_server.conf")


@pytest.mark.xfail(strict=True, reason="Defense-in-depth future work: CSP style-src still allows 'unsafe-inline'")
def test_csp_has_no_unsafe_inline():
    assert "'unsafe-inline'" not in _read("nginx/security_headers.conf")


# ═══ Secrets hygiene ════════════════════════════════════════════════════════
def test_gitignore_covers_secrets():
    gi = _read(".gitignore")
    for pattern in (".env", "secrets/", "redis/users.acl", "*.pem", "*.key"):
        assert pattern in gi, pattern


def test_no_secret_files_tracked_by_git():
    if not shutil.which("git") or not (ROOT / ".git").exists():
        pytest.skip("git metadata not available")
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    tracked = out.splitlines()
    bad = [f for f in tracked if f == ".env" or f.startswith("secrets/") or f == "redis/users.acl"
           or f.endswith((".pem", ".key")) or re.match(r"(^|/)\.env\.(?!example$)", f)]
    assert bad == []


def test_env_example_has_no_real_secrets():
    env = _read(".env.example")
    assert not re.search(r"^REDIS_URL=redis://[^<\s]+:[^<\s]+@", env, re.M)
    assert re.search(r"^ENVIRONMENT=production", env, re.M)
    assert re.search(r"^SESSION_COOKIE_SECURE=true", env, re.M)


# ═══ Frontend (client-side injection & token storage) ═══════════════════════
def _frontend_sources():
    src = ROOT / "frontend" / "src"
    if not src.exists():
        pytest.skip("frontend sources not present")
    return [(p, p.read_text(encoding="utf-8", errors="replace"))
            for p in src.rglob("*") if p.suffix in (".js", ".jsx", ".ts", ".tsx")]


@pytest.mark.parametrize("pattern,why", [
    (r"dangerouslySetInnerHTML", "raw HTML injection"),
    (r"\.innerHTML\s*=", "raw HTML injection"),
    (r"\beval\s*\(", "dynamic code"),
    (r"new\s+Function\s*\(", "dynamic code"),
    (r"(local|session)Storage\s*\.", "secrets must not live in web storage"),
    (r"credentials:\s*['\"]include['\"]", "cookies must stay same-origin"),
    (r"document\.write\s*\(", "raw HTML injection"),
])
def test_frontend_has_no_dangerous_sinks(pattern, why):
    hits = [f"{p.name}" for p, text in _frontend_sources() if re.search(pattern, text)]
    assert hits == [], f"{why}: {hits}"


def test_frontend_sends_csrf_header_and_same_origin_credentials():
    api = _read("frontend/src/services/api.js")
    assert "'X-QRGuard-Request': '1'" in api
    assert "credentials: 'same-origin'" in api
    assert "cache: 'no-store'" in api


def test_frontend_external_links_use_noopener():
    for p, text in _frontend_sources():
        for m in re.finditer(r"target=[\"']_blank[\"'][^>]*", text):
            assert "noopener" in m.group(0) or "noreferrer" in m.group(0), p.name
