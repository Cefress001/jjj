"""Demo target: three difficulty modes, defense headers, pagination."""

import json


def hit(demo, method, path, query=None, body=None):
    return demo.handle_demo_request(method, path, query or {}, body)


# ---------------------------------------------------------------- easy mode

def test_easy_root(demo):
    st, ct, body, _ = hit(demo, "GET", "/demo/")
    assert st == 200 and "VulnPay" in body


def test_easy_pagination(demo):
    st, _, body, _ = hit(demo, "GET", "/demo/api/v1/users", {"page": ["1"], "limit": ["1000"]})
    assert st == 200
    assert len(json.loads(body)["users"]) == 1000
    st, _, body, _ = hit(demo, "GET", "/demo/api/v1/users", {"page": ["3"], "limit": ["1000"]})
    assert json.loads(body)["users"] == []


def test_easy_full_chain_surfaces(demo):
    """Every endpoint the engines need for a full breach exists in easy mode."""
    checks = [
        ("GET", "/demo/.env", 200),
        ("GET", "/demo/api/users", 200),
        ("PATCH", "/demo/api/v1/user/profile", 200),         # privesc
        ("POST", "/demo/api/v1/promo/validate", 200),         # promo bypass
        ("POST", "/demo/api/v1/subscription/upgrade", 200),   # race
        ("POST", "/demo/api/v1/admin/users", 201),            # hidden admin
        ("POST", "/demo/api/v1/webhooks", 201),
        ("GET", "/demo/api/v1/services", 200),
        ("DELETE", "/demo/api/v1/admin/audit/delete", 200),   # cover tracks
    ]
    for method, path, expect in checks:
        st, _, body, _ = hit(demo, method, path, None, b"{}" if method == "POST" else None)
        assert st == expect, f"{method} {path} -> {st}, expected {expect}"


def test_easy_promo_echoes_client_discount(demo):
    st, _, body, _ = hit(demo, "POST", "/demo/api/v1/promo/validate", None,
                         json.dumps({"code": "ADMIN", "value": 9999}).encode())
    data = json.loads(body)
    assert data["valid"] is True and data["discount"] == 9999


# ------------------------------------------------------------- hardened mode

def test_hardened_landing(demo):
    st, _, body, _ = hit(demo, "GET", "/demo/hardened/")
    assert st == 200 and "HARDENED" in body


def test_hardened_blocks_secrets(demo):
    for path in ("/demo/hardened/.env", "/demo/hardened/secrets.json",
                 "/demo/hardened/.aws/credentials", "/demo/hardened/.ssh/id_rsa",
                 "/demo/hardened/docker-compose.yml"):
        st, _, _, headers = hit(demo, "GET", path)
        assert st == 404, f"{path} should be hidden, got {st}"
        assert headers.get("X-Defense") == "hidden"


def test_hardened_jwt_enforced(demo):
    st, _, _, headers = hit(demo, "GET", "/demo/hardened/api/v1/user/profile")
    assert st == 401
    assert headers.get("X-Defense") == "auth_block"


def test_hardened_waf_on_injection(demo):
    for payload in ({"code": "' OR '1'='1"}, {"code": "**"}, {"code": None}):
        st, _, _, headers = hit(demo, "POST", "/demo/hardened/api/v1/promo/validate", None,
                                json.dumps(payload).encode())
        assert st == 403 and headers.get("X-Defense") == "waf_block", payload


def test_hardened_race_condition_survives(demo):
    """The one surviving weakness: subscription endpoints lack idempotency."""
    for path in ("/demo/hardened/api/v1/subscription/upgrade",
                 "/demo/hardened/api/v1/subscription"):
        st, _, body, _ = hit(demo, "POST", path, None, b'{"tier":"premium"}')
        assert st == 200, f"{path} should still be vulnerable, got {st}"


def test_hardened_webhook_still_allowed(demo):
    st, _, _, _ = hit(demo, "POST", "/demo/hardened/api/v1/webhooks", None, b"{}")
    assert st == 201


def test_hardened_admin_blocked(demo):
    st, _, _, headers = hit(demo, "POST", "/demo/hardened/api/v1/admin/users", None, b"{}")
    assert st == 403 and headers.get("X-Defense") == "auth_block"


# ------------------------------------------------------------- fortified mode

def test_fortified_public_surface_minimal(demo):
    st, _, body, _ = hit(demo, "GET", "/demo/fortified/openapi.json")
    assert st == 200
    st, _, _, _ = hit(demo, "GET", "/demo/fortified/api/users")
    assert st in (401, 403, 404)


def test_fortified_promo_waf(demo):
    st, _, _, headers = hit(demo, "POST", "/demo/fortified/api/v1/promo/validate", None, b'{"code":"x"}')
    assert st == 403 and headers.get("X-Defense") == "waf_block"


def test_fortified_no_lateral_movement(demo):
    for path in ("/demo/fortified/.env", "/demo/fortified/config.json",
                 "/demo/fortified/.ssh/id_rsa", "/demo/fortified/api/v1/services"):
        st, _, _, _ = hit(demo, "GET", path)
        assert st in (401, 403, 404), f"{path} leaked with {st}"


def test_fortified_cover_tracks_blocked(demo):
    st, _, _, _ = hit(demo, "POST", "/demo/fortified/api/v1/admin/logs/delete", None, b"{}")
    assert st in (401, 403, 404)


# ---------------------------------------------------------------- telemetry

def test_telemetry_per_mode(demo):
    hit(demo, "GET", "/demo/")
    hit(demo, "GET", "/demo/hardened/.env")
    hit(demo, "GET", "/demo/fortified/openapi.json")
    t = demo.get_telemetry()
    for m in ("easy", "hardened", "fortified"):
        assert t[m]["requests"] >= 1
        assert isinstance(t[m]["defenses"], dict)
    assert t["hardened"]["defenses"].get("hidden", 0) >= 1
