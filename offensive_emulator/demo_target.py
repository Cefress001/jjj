"""
Built-in Demo Target — "VulnPay", a deliberately vulnerable mock SaaS API.

Served by the app server under /demo/* so the platform can be tried
end-to-end with zero setup.

Three difficulty modes (selected by URL prefix):
  /demo/...            EASY       — everything misconfigured, full kill chain
  /demo/hardened/...   HARDENED   — JWT verified, secrets blocked, one race
                                    condition left; chain breaks at lateral
  /demo/fortified/...  FORTIFIED  — locked down; chain breaks at exploit

When a defense blocks a request, the response carries an `X-Defense` header
(auth_block | waf_block | rate_limit | hidden) which the request tracer
turns into defense events in the console and report.

This is a MOCK. It stores nothing, owns nothing, and exists only to be
attacked inside your own sandbox.
"""

import json
import random
import threading
import time
from typing import Dict, List, Optional, Tuple

APP_NAME = "VulnPay"
APP_TAGLINE = "Payments demo target (intentionally vulnerable)"

MODES = ("easy", "hardened", "fortified")

# ----------------------------------------------------------------------------
# Telemetry (shown live in the console while a run is in progress)
# ----------------------------------------------------------------------------

_lock = threading.Lock()


def _new_mode_telemetry():
    return {
        "requests": 0,
        "by_method": {},
        "defenses": {},      # type -> count
        "recent": [],        # last 25 hits: {t, method, path, status}
    }


_telemetry: Dict[str, object] = {m: _new_mode_telemetry() for m in MODES}


def _record_hit(mode: str, method: str, path: str, status: int, defense: Optional[str]) -> None:
    with _lock:
        t = _telemetry[mode]
        t["requests"] += 1
        t["by_method"][method] = t["by_method"].get(method, 0) + 1
        if defense:
            t["defenses"][defense] = t["defenses"].get(defense, 0) + 1
        t["recent"].append(
            {"t": round(time.time(), 3), "method": method, "path": path,
             "status": status, "defense": defense}
        )
        if len(t["recent"]) > 25:
            t["recent"] = t["recent"][-25:]


def get_telemetry() -> Dict[str, object]:
    with _lock:
        out = {}
        for m in MODES:
            src = _telemetry[m]
            out[m] = {
                "requests": src["requests"],
                "by_method": dict(src["by_method"]),
                "defenses": dict(src["defenses"]),
                "recent": list(src["recent"]),
            }
        out["app"] = APP_NAME
        return out


# ----------------------------------------------------------------------------
# Fake data pools
# ----------------------------------------------------------------------------

_FIRST = ["ada", "alan", "linus", "grace", "ken", "barbara", "margaret", "dennis",
          "katherine", "tim", "john", "radia", "vint", "bjarne", "guido", "brendan"]
_LAST = ["lovelace", "turing", "torvalds", "hopper", "thompson", "liskov", "hamilton",
         "ritchie", "johnson", "bernerslee", "backus", "perlman", "cerf", "stroustrup",
         "rossum", "eich"]


def _user(i: int) -> Dict[str, object]:
    first = _FIRST[i % len(_FIRST)]
    last = _LAST[i % len(_LAST)]
    uid = 1000 + i
    return {
        "id": uid,
        "username": f"{first}.{last}",
        "email": f"{first}.{last}@vulnpay.test",
        "phone": f"+1-555-{1000 + (i % 900)}",
        "tier": random.choice(["free", "free", "basic", "premium"]),
        "balance_usd": round(random.uniform(0, 25000), 2),
        "created_at": f"202{random.randint(2, 5)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}",
    }


def _txn(i: int) -> Dict[str, object]:
    return {
        "id": f"txn_{900000 + i}",
        "user_id": 1000 + random.randint(0, 800),
        "amount_usd": round(random.uniform(5, 4000), 2),
        "currency": "USD",
        "status": random.choice(["settled", "settled", "pending", "refunded"]),
        "card_last4": f"{random.randint(1000, 9999)}",
        "merchant": random.choice(["cloudsrv.io", "notion.so", "aws.amazon.com", "figma.com"]),
    }


_USERS_PER_PAGE = 600
_USERS_PAGES = 2        # 1,200 records -> "High" severity territory
_TXN_COUNT = 340

# ----------------------------------------------------------------------------
# Static file bodies the engines love to find
# ----------------------------------------------------------------------------

_ENV_FILE = """# VulnPay production configuration  (DO NOT COMMIT)
NODE_ENV=production
DATABASE_URL=postgres://vp_admin:Pr0dPg_Sup3rPass@db-internal.vulnpay.test:5432/vulnpay
MONGODB_URI=mongodb://svc_metrics:M0ngo_M3trics!@mongo-internal.vulnpay.test:27017/metrics
REDIS_URL=redis://cache_admin=R3disPw@redis-internal.vulnpay.test:6379/0
STRIPE_API_KEY=demo_fake_stripe_key_not_a_real_secret
JWT_SECRET=changeme-in-production
ADMIN_BOOTSTRAP_TOKEN=adm_boot_9f3ac1d7e2
AWS_REGION=us-east-1
"""

_DOCKER_COMPOSE = """version: "3.9"
services:
  api:
    image: vulnpay/api:2.4.1
    environment:
      DATABASE_URL: postgres://vp_admin:Pr0dPg_Sup3rPass@db-internal:5432/vulnpay
      REDIS_URL: redis://cache_admin:R3disPw@redis-internal:6379/0
  worker:
    image: vulnpay/worker:2.4.1
    environment:
      MONGO_URI: mongodb://svc_metrics:M0ngo_M3trics!@mongo-internal:27017/metrics
"""

_DATABASE_YML = """# config/database.yml
production:
  adapter: postgresql
  host: db-internal.vulnpay.test
  username: vp_admin
  password: Pr0dPg_Sup3rPass
  database: vulnpay
  pool: 25
"""

_SRC_CONFIG_TS = """// src/config.ts
export const CONFIG = {
  apiBase: "https://api.vulnpay.test",
  database: "postgres://vp_admin:Pr0dPg_Sup3rPass@db-internal.vulnpay.test:5432/vulnpay",
  redis: "redis://cache_admin:R3disPw@redis-internal.vulnpay.test:6379/0",
  debug: true,
};
"""

_SETTINGS_PY = """# app/settings.py
import os

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": "db-internal.vulnpay.test",
        "USER": "vp_admin",
        "PASSWORD": "Pr0dPg_Sup3rPass",
    }
}
SECRET_KEY = "django-insecure-8f2a91c3b7de"
"""

_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA7fx3cWJ9kP0mQ2rT5vL8xH1nD4yK6sB3uE7wZ9aC1dF5gH2
jK4lN7pQ0rT8vX3cZ5bM1nA6sD9fG2hJ4kL7pO0iU3yE6wX9cV1bN4mA8sD1fG4
H7jK0lP3oI6uY9tR2eW5qX8cV1bN4m<...FAKE KEY FOR DEMO TARGET...>
-----END RSA PRIVATE KEY-----
"""

# NOTE: AWS's public documentation example values — nothing real
_AWS_CREDENTIALS = """# NOTE: all values are AWS's public documentation examples — nothing real
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

[production]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

_GCP_KEY = json.dumps({
    "type": "service_account",
    "project_id": "vulnpay-prod",
    "client_email": "svc-ops@vulnpay-prod.iam.gserviceaccount.com",
    "private_key_id": "9f3ac1d7e2b45f68a90c1d2e3f4a5b6c",
}, indent=2)


def _ok(body, ctype="application/json", headers=None):
    return 200, ctype, body, headers


def _created(body):
    return 201, "application/json", body, None


def _json(obj):
    return json.dumps(obj)


def _blocked(status: int, dtype: str, detail: str):
    """A defense fired. The X-Defense header is what the tracer reads."""
    return (status, "application/json",
            _json({"error": detail, "blocked_by": dtype}),
            {"X-Defense": dtype})


def _hidden():
    """Properly hardened: 404, revealing nothing."""
    return 404, "application/json", _json({"error": "not found"}), {"X-Defense": "hidden"}


# ----------------------------------------------------------------------------
# Landing pages per mode
# ----------------------------------------------------------------------------

def _landing_page(mode: str) -> str:
    tier = {"easy": ("EASY", "#34d399", "Wide open. Misconfigured on purpose."),
            "hardened": ("HARDENED", "#fbbf24", "JWT verified · secrets locked · one race condition left."),
            "fortified": ("FORTIFIED", "#22d3ee", "Locked down. The chain should break at exploitation.")}[mode]
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>VulnPay — {tier[0]} demo target</title>
<meta name="generator" content="Next.js 14 (App Router)">
<style>
 body{{background:#0b1220;color:#dbe7ff;font-family:system-ui,Segoe UI,sans-serif;
      display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}}
 .card{{max-width:560px;padding:40px;border:1px solid #1f2f52;border-radius:16px;
       background:#0e1730;text-align:center}}
 h1{{margin:0 0 6px;font-size:34px;letter-spacing:2px}}
 p{{color:#7d8db0;margin:6px 0}}
 .tier{{color:{tier[1]};font-weight:700;letter-spacing:3px;font-size:13px}}
 .warn{{color:#f43f5e;font-weight:600}}
 code{{color:#2dd4bf}}
</style></head>
<body><div class="card">
 <h1>⚡ VulnPay</h1>
 <p class="tier">DIFFICULTY: {tier[0]}</p>
 <p>{tier[2]}</p>
 <p>This is the built-in target of Offensive Emulator.<br>
    Launch the console, keep this URL as the target, and press <code>INITIATE ATTACK</code>.</p>
 <p style="font-size:12px;opacity:.6">It stores nothing and talks to no one — it only pretends to be pwned.</p>
</div></body></html>"""


# ----------------------------------------------------------------------------
# Route table
# ----------------------------------------------------------------------------

def handle_demo_request(method: str, path: str, query: Dict[str, List[str]],
                         body: Optional[bytes] = None):
    """
    Handle a request aimed at the demo target.
    `path` is the full path starting with /demo.
    Returns (status, content_type, body, extra_headers).
    """
    # ---- difficulty mode from the path prefix
    mode = "easy"
    if path == "/demo/hardened" or path.startswith("/demo/hardened/"):
        mode, sub = "hardened", path[len("/demo/hardened"):] or "/"
    elif path == "/demo/fortified" or path.startswith("/demo/fortified/"):
        mode, sub = "fortified", path[len("/demo/fortified"):] or "/"
    else:
        sub = path[len("/demo"):] or "/"
    if not sub.startswith("/"):
        sub = "/" + sub

    status, ctype, payload, headers = _route(method, sub, query, body or b"", mode)

    base_headers = {"Server": "nginx/1.22.1", "X-Powered-By": "Express", "X-Cache": "HIT"}
    if headers:
        base_headers.update(headers)
    defense = (headers or {}).get("X-Defense")
    _record_hit(mode, method, sub, status, defense)

    # artificial "network" latency so a run unfolds at a watchable pace
    time.sleep(random.uniform(0.12, 0.4))
    return status, ctype, payload, base_headers


# per-mode flags for a few stateful behaviors
_rate_hits: Dict[str, Dict[str, int]] = {"hardened": {}, "fortified": {}}


def _rate_limited(bucket: str, limit: int = 1) -> bool:
    """Return True when the caller has exceeded `limit` requests in this bucket."""
    n = _rate_hits[bucket].get(bucket, 0)
    _rate_hits[bucket][bucket] = n + 1
    return n >= limit


def _route(method: str, sub: str, query: Dict[str, List[str]], body: bytes, mode: str):
    # flatten query params: {"page": ["2"]} -> {"page": "2"}
    q: Dict[str, str] = {k: v[0] for k, v in (query or {}).items() if v}
    hardened = mode == "hardened"
    fortified = mode == "fortified"

    # ---- root / dashboard ----------------------------------------------
    if sub in ("/", ""):
        return _ok(_landing_page(mode), "text/html; charset=utf-8")
    if sub == "/favicon.ico":
        return 404, "text/plain", "not found", None

    # ============================ FORTIFIED ==============================
    # A properly locked-down app: public docs only, everything else denied.
    if fortified:
        allowed_public = {
            "/openapi.json": {"openapi": "3.0.0", "info": {"title": "VulnPay API", "version": "2.4.1"},
                              "paths": {"/api/v1/health": {}}},
            "/health": {"status": "ok"},
            "/api/v1/health": {"status": "ok"},
        }
        if method == "GET" and sub in allowed_public:
            return _ok(_json(allowed_public[sub]))
        if method == "GET" and sub == "/metrics":
            return _ok("http_requests_total 884213\n", "text/plain")
        # everything else: WAF for injective payloads, 401 for auth-y paths, else 404
        if sub.startswith("/api/v1/promo"):
            return _blocked(403, "waf_block", "request blocked by WAF (rule sqli-0042)")
        if sub.startswith("/api/v1/subscription"):
            if _rate_limited("fortified:sub", 2):
                return _blocked(429, "rate_limit", "too many requests — idempotent retries enforced")
            return _blocked(403, "auth_block", "subscription changes require verified auth")
        if sub.startswith("/api/") or sub.startswith("/admin") or sub.startswith("/debug"):
            return _blocked(401, "auth_block", "authentication required")
        return _hidden()

    # ============================ HARDENED ===============================
    # Fixed the worst stuff, still has a race condition + webhook registration.
    if hardened:
        # public, harmless surfaces
        allowed = {
            "/api/users": {"users": [_user(i) for i in range(5)], "total": _USERS_PER_PAGE * _USERS_PAGES},
            "/api/v1/subscription": {"plans": ["free", "basic", "premium"], "upgrade_path": "/api/v1/subscription/upgrade"},
            "/openapi.json": {"openapi": "3.0.0", "info": {"title": "VulnPay API"}, "paths": {"/api/v1/subscription/upgrade": {}}},
            "/api/v1/health": {"status": "ok"},
            "/health": {"status": "ok"},
        }
        if method == "GET" and sub in allowed:
            return _ok(_json(allowed[sub]))
        if method == "GET" and sub == "/metrics":
            return _ok("http_requests_total 884213\n", "text/plain")
        # the surviving weakness: no idempotency on subscription endpoints
        if sub in ("/api/v1/subscription/upgrade", "/api/v1/subscription") and method == "POST":
            return _ok(_json({"upgraded": True, "tier": "premium", "charged": False, "race_window_ms": 42}))
        # promo: input validated now — injection attempts get WAF'd
        if sub == "/api/v1/promo/validate" and method == "POST":
            try:
                data = json.loads(body.decode() or "{}")
            except Exception:
                data = {}
            code = str(data.get("code") or "")
            if any(tok in code for tok in ("'", "OR", "*", "--", ";")) or data.get("code") is None:
                return _blocked(403, "waf_block", "request blocked by WAF (rule sqli-0042)")
            return _ok(_json({"valid": False, "approved": False, "message": "invalid promo code"}))
        # webhook registration still allowed (the forgotten corner)
        if sub == "/api/v1/webhooks" and method == "POST":
            return _created(_json({"created": True, "url": "https://attacker.example/collect",
                                   "events": ["user.*"], "secret": None}))
        # services are visible (info leak) but hold no credentials
        if sub == "/api/v1/services" and method == "GET":
            return _ok(_json({"services": ["auth-service", "payments-db", "redis-cache"]}))
        # bulk export rate-limited hard
        if sub == "/api/v1/users" and method == "GET":
            if _rate_limited("hardened:exfil", 2):
                return _blocked(429, "rate_limit", "export rate limit exceeded")
            return _ok(_json({"page": 1, "users": [], "total": 0}))
        # everything else is locked: auth, admin, secrets, files
        if sub.startswith("/api/v1/admin") or sub.startswith("/admin"):
            return _blocked(403, "auth_block", "admin area requires verified admin auth")
        if sub.startswith("/api/v1/user") or sub.startswith("/api/v1/account") or sub.startswith("/api/v1/billing"):
            return _blocked(401, "auth_block", "JWT signature verification failed")
        if sub.startswith("/debug") or sub.startswith("/internal") or sub.startswith("/api/debug"):
            return _blocked(403, "auth_block", "debug endpoints disabled")
        if sub.startswith("/api/v1/sessions") or sub.startswith("/api/v1/audit") or \
           sub.startswith("/api/v1/logs") or sub.startswith("/api/v1/security") or \
           sub.startswith("/api/v1/cache") or sub.startswith("/api/v1/uploads") or \
           sub.startswith("/api/v1/events"):
            return _blocked(403, "auth_block", "operation not permitted")
        return _hidden()

    # ============================== EASY =================================
    # (the original pushover)

    # ---- recon: endpoint enumeration --------------------------------------
    recon_json = {
        "/api/users": {"users": [_user(i) for i in range(5)], "total": _USERS_PER_PAGE * _USERS_PAGES},
        "/api/admin": {"admin": True, "panel": "v2", "endpoints": ["/api/admin/users", "/api/admin/reports"]},
        "/api/config": {"env": "production", "region": "us-east-1", "maintenance": False, "debug": True},
        "/api/debug": {"debug": True, "stack": ["node:20", "postgres:15", "redis:7"], "verbose_errors": True},
        "/api/v1/subscription": {"plans": ["free", "basic", "premium", "enterprise"], "upgrade_path": "/api/v1/subscription/upgrade"},
        "/api/v1/payments": {"provider": "stripe", "webhook": "/api/v1/webhooks", "mode": "live"},
        "/api/export": {"formats": ["csv", "json"], "max_rows": 1000000, "auth_required": False},
        "/api/internal/database": {"engine": "postgresql", "host": "db-internal.vulnpay.test", "pool": 25},
        "/api/internal/logs": {"retention_days": 14, "sink": "stdout", "tamper_protection": False},
        "/api/admin/users": {"users": [], "note": "admin listing enabled"},
        "/api/admin/payments": {"total_processed_usd": 8412883.44},
        "/api/admin/reports": {"reports": ["revenue", "fraud", "churn"]},
    }
    if method == "GET" and sub in recon_json:
        return _ok(_json(recon_json[sub]))

    # ---- recon: hidden routes ----------------------------------------------
    if method == "GET" and sub in ("/admin", "/admin/users", "/admin/dashboard", "/admin/config",
                                   "/internal", "/internal/api", "/internal/status",
                                   "/_admin", "/_internal", "/_debug",
                                   "/api/admin", "/api/internal", "/api/debug"):
        if sub in ("/_admin", "/_internal", "/_debug"):
            return 404, "application/json", _json({"error": "not found"}), None
        return _ok(_json({"route": sub, "authenticated": False, "warning": "unprotected admin surface"}))

    if method == "GET" and sub in ("/debug", "/debug/pprof"):
        return _ok(_json({"debug": True, "endpoints": ["/debug/vars", "/debug/config", "/debug/pprof"]}))

    if method == "GET" and sub == "/debug/vars":
        return _ok(_json({"memstats": {"Alloc": 52428800}, "cmdline": ["node", "server.js"], "expvar": True}))

    if method == "GET" and sub == "/debug/config":
        return _ok(_json({"config": {"db": "postgres://vp_admin:Pr0dPg_Sup3rPass@db-internal/vulnpay", "jwt_verify": "lenient"}}))

    if method == "GET" and sub == "/internal/stats":
        return _ok(_json({"rps": 412, "p99_ms": 88, "errors": 12, "authenticated_admins": 3}))

    if method == "GET" and sub == "/metrics":
        return _ok("http_requests_total 884213\nhttp_requests_duration_ms_p99 88\n"
                   "db_connections_active 25\nadmin_logins_total 17\n", "text/plain")

    if method == "GET" and sub in ("/health", "/api/v1/health"):
        return _ok(_json({"status": "ok", "uptime_s": 918273, "checks": {"db": "up", "redis": "up"}}))

    if method == "GET" and sub == "/trace":
        return _ok(_json({"traces": 12, "sampled": ["api", "worker"], "exporter": "jaeger"}))

    if method == "GET" and sub == "/actuator":
        return _ok(_json({"_links": {"health": "/health", "env": "/debug/config", "metrics": "/metrics"}}))

    if method == "GET" and sub == "/.well-known/service-mesh":
        return _ok(_json({"mesh": "istio", "sidecars": ["api", "worker"]}))

    if method == "GET" and sub == "/api/v1/config":
        return _ok(_json({"signing_alg": ["HS256", "RS256"], "token_expiry_s": 86400, "verify_signature": "optional"}))

    # ---- sensitive files ----------------------------------------------------
    text_files = {
        "/.env": _ENV_FILE,
        "/docker-compose.yml": _DOCKER_COMPOSE,
        "/config/database.yml": _DATABASE_YML,
        "/src/config.ts": _SRC_CONFIG_TS,
        "/app/settings.py": _SETTINGS_PY,
        "/app/config/database.yml": _DATABASE_YML,
        "/config/cloud-config.yml": _AWS_CREDENTIALS,
        "/.aws/credentials": _AWS_CREDENTIALS,
        "/.azure/credentials": _AWS_CREDENTIALS.replace("aws_", "azure_"),
        "/.ssh/id_rsa": _PRIVATE_KEY,
        "/.ssh/id_ed25519": _PRIVATE_KEY.replace("RSA", "OPENSSH"),
        "/.ssh/authorized_keys": "ssh-rsa AAAAB3Nzac1yc2E... service@vulnpay\n",
        "/.ssh/config": "Host db-internal\n  User vp_admin\n  IdentityFile ~/.ssh/id_rsa\n",
        "/root/.ssh/id_rsa": _PRIVATE_KEY,
        "/opt/app/.ssh/id_rsa": _PRIVATE_KEY,
        "/etc/ssl/certs/private.key": _PRIVATE_KEY.replace("RSA PRIVATE", "PRIVATE"),
        "/etc/ssl/private/server.key": _PRIVATE_KEY.replace("RSA PRIVATE", "PRIVATE"),
        "/app/certs/tls.key": _PRIVATE_KEY.replace("RSA PRIVATE", "PRIVATE"),
        "/.config/certs/client.key": _PRIVATE_KEY.replace("RSA PRIVATE", "PRIVATE"),
        "/.ssh/id_rsa.pub": "ssh-rsa AAAAB3Nzac1yc2E... deploy@vulnpay\n",
        "/requirements.txt": "fastapi==0.104.0\nuvicorn==0.24.0\naiohttp==3.9.0\n",
        "/package.json": _json({"name": "vulnpay-api", "version": "2.4.1", "private": True}),
        "/.git/config": '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@github.com:vulnpay/api.git\n',
    }
    if method == "GET" and sub in text_files:
        return _ok(text_files[sub], "text/plain")

    json_files = {
        "/config.json": {"database_url": "postgres://vp_admin:Pr0dPg_Sup3rPass@db-internal/vulnpay", "redis_url": "redis://cache_admin:R3disPw@redis-internal:6379/0"},
        "/secrets.json": {"stripe_key": "demo_fake_stripe_key_not_a_real_secret", "admin_token": "adm_boot_9f3ac1d7e2", "jwt_secret": "changeme-in-production"},
        "/swagger.json": {"openapi": "3.0.0", "info": {"title": "VulnPay API"}, "paths": {"/api/v1/users": {}, "/api/v1/admin/users": {}, "/api/v1/promo/validate": {}}},
        "/openapi.json": {"openapi": "3.0.0", "info": {"title": "VulnPay API"}, "paths": {"/api/v1/users": {}, "/api/v1/admin/users": {}}},
        "/gcp-key.json": _GCP_KEY,
    }
    if method == "GET" and sub in json_files:
        return _ok(_json(json_files[sub]))

    # ---- exploitation ---------------------------------------------------------
    if sub == "/api/v1/user/profile":
        if method in ("GET", "PATCH", "PUT"):
            if method in ("PATCH", "PUT"):
                return _ok(_json({"updated": True, "role": "admin", "is_admin": True, "note": "role field is client-controlled"}))
            return _ok(_json({
                "id": 1000, "username": "attacker", "email": "attacker@vulnpay.test",
                "role": "admin", "is_admin": True, "tier": "enterprise",
                "permissions": ["*"], "mfa_enabled": False,
            }))
        return 405, "application/json", _json({"error": "method not allowed"}), None

    if sub == "/api/v1/subscription/upgrade" and method == "POST":
        return _ok(_json({"upgraded": True, "tier": "premium", "charged": False, "race_window_ms": 42}))

    if sub == "/api/v1/billing/subscribe" and method == "POST":
        return _ok(_json({"subscribed": True, "plan": "enterprise", "trial_days": 9999}))

    if sub == "/api/v1/account/tier" and method in ("POST", "GET"):
        return _ok(_json({"tier": "enterprise", "max_seats": 999999, "billing_active": True}))

    if sub == "/api/v1/promo/validate" and method == "POST":
        try:
            data = json.loads(body.decode() or "{}")
        except Exception:
            data = {}
        return _ok(_json({
            "valid": True, "approved": True,
            "discount": data.get("value", 100),
            "code": data.get("code"),
            "message": "promo applied",
        }))

    # ---- persistence ------------------------------------------------------------
    if sub == "/api/v1/admin/users" and method == "POST":
        try:
            data = json.loads(body.decode() or "{}")
        except Exception:
            data = {}
        return _created(_json({"created": True, "username": data.get("username", "unknown"), "role": data.get("role", "admin"), "id": 9001}))

    if sub == "/api/v1/admin/api-keys" and method == "POST":
        return _created(_json({"created": True, "key": "vpk_demo_fake_api_key_not_real", "scopes": ["*"], "expires": "never"}))

    if sub == "/api/v1/webhooks" and method == "POST":
        return _created(_json({"created": True, "url": "https://attacker.example/collect", "events": ["user.*", "payment.*"], "secret": None}))

    if sub == "/api/v1/admin/tasks" and method == "POST":
        return _created(_json({"scheduled": True, "cron": "*/5 * * * *", "command": "/usr/local/bin/sync.sh", "id": "task_77"}))

    # ---- lateral movement ----------------------------------------------------------
    if sub == "/api/v1/services" and method == "GET":
        return _ok(_json({"services": ["auth-service", "payments-db", "redis-cache", "worker-queue", "admin-gateway", "metrics-agent"]}))

    if sub == "/api/v1/cloud/credentials" and method == "GET":
        return _ok(_AWS_CREDENTIALS, "text/plain")

    # ---- exfiltration -----------------------------------------------------------------
    if sub == "/api/v1/users" and method == "GET":
        page = int(q.get("page", 1) or 1)
        limit = min(int(q.get("limit", 100) or 100), 1000)
        start = (page - 1) * limit
        users = [_user(start + i) for i in range(limit)] if page <= _USERS_PAGES else []
        return _ok(_json({"page": page, "limit": limit, "total": _USERS_PER_PAGE * _USERS_PAGES, "users": users}))

    tx_endpoints = {
        "/api/v1/transactions": "transactions",
        "/api/v1/payments/history": "payments",
        "/api/v1/billing/invoices": "invoices",
        "/api/v1/orders": "orders",
    }
    if method == "GET" and sub in tx_endpoints:
        key = tx_endpoints[sub]
        limit = min(int(q.get("limit", 100) or 100), 1000)
        records = [_txn(i) for i in range(min(limit, _TXN_COUNT))]
        return _ok(_json({key: records, "total": _TXN_COUNT}))

    if sub == "/api/v1/data" and method in ("GET", "POST"):
        return _ok(_json({"cached": True, "poisoned": True, "origin": "edge-cache", "note": "cache key ignores auth"}))

    # ---- cover tracks -------------------------------------------------------------------
    cover_ok_posts = {
        "/api/v1/admin/logs/delete", "/api/v1/audit/purge", "/api/v1/logs/clear",
        "/api/v1/admin/events/clear", "/api/v1/admin/temp-files/clear", "/api/v1/uploads/delete",
        "/api/v1/cache/clear", "/api/v1/sessions/logout-all", "/api/v1/admin/staging/delete",
    }
    cover_ok_deletes = {
        "/api/v1/admin/audit/delete", "/api/v1/admin/events/delete",
        "/api/v1/security/events/purge", "/api/v1/admin/login-history/clear",
    }
    if method == "POST" and sub in cover_ok_posts:
        return _ok(_json({"deleted": True, "entries": random.randint(400, 5200), "irreversible": True}))
    if method == "DELETE" and sub in cover_ok_deletes:
        return _ok(_json({"purged": True, "records": random.randint(120, 3300)}))
    if method == "POST" and sub == "/api/v1/admin/logs":
        return _created(_json({"written": True, "entries": 3, "accepted": "unsigned"}))

    # ---- default -------------------------------------------------------------------------
    return 404, "application/json", _json({"error": "not found", "path": sub}), None
