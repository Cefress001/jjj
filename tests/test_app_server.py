"""HTTP-level tests: boots the real app server on an ephemeral port."""

import json
import threading
import time
import urllib.request

import pytest


@pytest.fixture(scope="module")
def server():
    from app_server import create_server
    srv = create_server("127.0.0.1", 0)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()
    srv.server_close()


def get(base, path, raw=False):
    with urllib.request.urlopen(base + path, timeout=10) as r:
        body = r.read().decode()
        return (r.status, dict(r.headers), body) if raw else json.loads(body)


def post(base, path, payload):
    req = urllib.request.Request(base + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def test_health(server):
    d = get(server, "/api/health")
    assert d["status"] == "ok"
    assert d["engine"] in ("real", "simulation")


def test_configs_payload(server):
    d = get(server, "/api/configs")
    assert {"phases", "presets", "mitre", "demo_targets"} <= set(d)
    assert set(d["demo_targets"]) == {"easy", "hardened", "fortified"}
    assert len(d["phases"]) == 6
    assert set(d["presets"]) == {"stealth", "balanced", "aggressive", "maximum"}


def test_static_served(server):
    for path, marker in (("/", "LAUNCH CONSOLE"),
                         ("/static/js/app.js", "OFFENSIVE EMULATOR"),
                         ("/static/css/app.css", "replay-bar"),
                         ("/static/js/sound.js", "OE_Sound"),
                         ("/static/js/tour.js", "OE_Tour"),
                         ("/static/vendor/three.min.js", "REVISION")):
        with urllib.request.urlopen(server + path, timeout=10) as r:
            body = r.read().decode("utf-8", "replace")
            assert marker in body, f"{path} missing marker {marker!r}"


def test_path_traversal_blocked(server):
    for path in ("/static/../app_server.py", "/static/%2e%2e/app_server.py"):
        try:
            urllib.request.urlopen(server + path, timeout=10)
            raised = False
        except urllib.error.HTTPError as e:
            raised = e.code in (403, 404)
        assert raised, f"{path} should be blocked"


def test_demo_defense_header_over_http(server):
    req = urllib.request.Request(server + "/demo/hardened/.env")
    try:
        urllib.request.urlopen(req, timeout=10)
        status, headers = 200, {}
    except urllib.error.HTTPError as e:
        status, headers = e.code, dict(e.headers)
    assert status == 404
    assert headers.get("X-Defense") == "hidden"


def test_demo_telemetry_endpoint(server):
    d = get(server, "/api/demo/stats")
    assert {"easy", "hardened", "fortified"} <= set(d)


def test_attack_lifecycle_with_cursors(server):
    """Full run through the HTTP API against the built-in demo target."""
    run = post(server, "/api/attack/start",
               {"target": server + "/demo", "preset": "maximum"})
    rid = run["run_id"]
    assert run["status"] in ("queued", "running")

    t0, final = time.time(), None
    while time.time() - t0 < 90:
        snap = get(server, f"/api/attack/{rid}/status?after=-1&after_event=-1")
        if snap["status"] in ("complete", "failed", "aborted"):
            final = snap
            break
        time.sleep(0.5)
    assert final, "run did not finish in time"
    assert final["status"] == "complete"
    assert final["event_total"] > 0
    assert final["log_total"] > 0
    assert final["severity"] in ("Low", "Medium", "High", "Critical")

    # cursor semantics
    half = final["events"][len(final["events"]) // 2]["seq"]
    tail = get(server, f"/api/attack/{rid}/status?after_event={half}")
    assert all(e["seq"] > half for e in tail["events"])

    # report + downloads
    rep = get(server, f"/api/attack/{rid}/report")
    assert "mitre" in rep and "recommendations" in rep and "verdict" in rep
    with urllib.request.urlopen(server + f"/api/attack/{rid}/report.html?print=1", timeout=10) as r:
        html = r.read().decode()
        assert "MITRE ATT" in html and "window.print" in html
    with urllib.request.urlopen(server + f"/api/attack/{rid}/report.json", timeout=10) as r:
        assert json.loads(r.read())["run_id"] == rid


def test_archive_survives_reload(server):
    """Runs are on disk, so list works even for finished runs."""
    runs = get(server, "/api/attack/list")["runs"]
    assert isinstance(runs, list)
