"""Real-target robustness: dead hosts, normal sites, soft-404 SPAs, rate limits.

These spin up local servers that BEHAVE like real-world targets (default
404s, soft-404s, 429 throttling) and drive the REAL engine against them.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

try:
    import aiohttp  # noqa: F401
    HAS_AIOHTTP = True
except Exception:
    HAS_AIOHTTP = False

pytestmark = pytest.mark.skipif(not HAS_AIOHTTP, reason="aiohttp not installed")


# ---------------------------------------------------------------- helpers

def _wait(run, timeout=120):
    t0 = time.time()
    while run.thread and run.thread.is_alive() and time.time() - t0 < timeout:
        time.sleep(0.25)
    return run


class _RecordingHandler(BaseHTTPRequestHandler):
    """Configurable fake 'real website'. Records User-Agents seen."""
    behavior = "notfound"     # notfound | soft200 | ratelimit | challenge
    seen_uas = []

    def log_message(self, *a):
        pass

    def _respond(self):
        _RecordingHandler.seen_uas.append(self.headers.get("User-Agent", ""))
        b = self.behavior
        if b == "soft200":
            body = b"<html><body>welcome</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif b == "challenge":
            # Cloudflare managed challenge: 403 interstitial on EVERY path,
            # official cf-mitigated header + challenge-platform script.
            body = (b"<!DOCTYPE html><html><head><title>Just a moment...</title>"
                    b"<script src='/cdn-cgi/challenge-platform/h/b/orchestrate.js'>"
                    b"</script></head><body>Verify you are human...</body></html>")
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "cloudflare")
            self.send_header("CF-RAY", "8f3e2b1c4a9d1234-LAX")
            self.send_header("cf-mitigated", "challenge")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif b == "ratelimit" and self.path.startswith("/api/v1/users"):
            body = b'{"error": "slow down"}'
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", "1")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b'{"error": "not found"}'
            self.send_response(404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_GET(self):
        self._respond()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self._respond()

    def do_PATCH(self):
        self._respond()

    def do_DELETE(self):
        self._respond()

    def do_PUT(self):
        self._respond()


@pytest.fixture()
def fake_site():
    """A local server that behaves like a normal real website (404s)."""
    _RecordingHandler.behavior = "notfound"
    _RecordingHandler.seen_uas = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _RecordingHandler)
    port = srv.server_address[1]
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield f"http://127.0.0.1:{port}", _RecordingHandler
    srv.shutdown()
    srv.server_close()


# ------------------------------------------------------------------ tests

def test_dead_target_fails_fast_with_clear_error(svc):
    """Unreachable host -> run fails quickly with an actionable message."""
    run = svc.start_run("http://127.0.0.1:9/", "maximum", engine="real")
    _wait(run, timeout=60)
    assert run.status == "failed"
    assert run.error and "unreachable" in run.error.lower(), run.error
    logs = " ".join(e["msg"] for e in run.logs)
    assert "Target unreachable" in logs


def test_bad_dns_fails_fast(svc):
    run = svc.start_run("http://this-domain-does-not-exist-xyz.test/", "maximum", engine="real")
    _wait(run, timeout=60)
    assert run.status == "failed"
    assert "unreachable" in (run.error or "").lower()


def test_normal_site_completes_gracefully(svc, fake_site):
    """A normal website (404 everywhere): full run, no crash, honest report."""
    base, handler = fake_site
    run = svc.start_run(base, "maximum", engine="real")
    _wait(run, timeout=180)
    assert run.status == "complete"
    assert run.report is not None
    # nothing should have been exploited on a 404-everything site
    assert run.report["attack_chain"]["phase_2_exploit"] is False
    assert "DENIED" in run.report["verdict"]
    # recon may legitimately find nothing
    assert run.report["recon_results"]["endpoints_discovered"] == 0
    # requests were traced and reported
    reqs = [e for e in run.events if e["kind"] == "request"]
    assert len(reqs) > 50
    # preflight logged reachability
    logs = " ".join(e["msg"] for e in run.logs)
    assert "Target reachable" in logs


def test_browser_user_agent_is_sent(svc, fake_site):
    """Requests must carry a realistic browser UA, not the aiohttp default.

    (Exception: the cover-tracks engine deliberately signs its false-flag
    entries as a different 'attacker' UA — caller-set UAs are preserved.)
    """
    base, handler = fake_site
    run = svc.start_run(base, "maximum", engine="real")
    _wait(run, timeout=180)
    assert run.status == "complete"
    uas = set(handler.seen_uas)
    assert uas, "no requests reached the fake site"
    for ua in uas:
        assert "aiohttp" not in ua and "python" not in ua.lower(), f"default UA leaked: {ua!r}"
    browser_uas = [u for u in uas if u.startswith("Mozilla/5.0")]
    assert browser_uas, f"no browser UA among: {uas}"


def test_soft404_spa_completes_without_crash(svc, fake_site):
    """SPA-style site returning 200 for everything: no crash, run completes."""
    base, handler = fake_site
    handler.behavior = "soft200"
    run = svc.start_run(base, "maximum", engine="real")
    _wait(run, timeout=180)
    assert run.status == "complete"
    assert run.report is not None
    # soft-404s legitimately fool endpoint discovery; tool must not crash
    # and the report must still be well-formed
    for key in ("recon_results", "exploit_results", "summary"):
        assert key in run.report


def test_soft404_site_zero_false_positives(svc, fake_site):
    """THE real-world test: a catch-all site (every path -> homepage 200).

    Like www.regencycaregroup.com: unknown paths serve the homepage with 200.
    The tool must NOT report fake endpoints, fake exploits, fake backdoors,
    fake file theft or fake log deletion.
    """
    base, handler = fake_site
    handler.behavior = "soft200"
    run = svc.start_run(base, "maximum", engine="real")
    _wait(run, timeout=180)
    assert run.status == "complete"
    rep = run.report
    assert rep["recon_results"]["endpoints_discovered"] == 0, \
        f"soft-404 produced fake endpoints: {rep['recon_results']['endpoints']}"
    assert rep["attack_chain"]["phase_2_exploit"] is False, "soft-404 faked an exploit"
    assert rep["persistence_results"]["backdoors_installed"] == 0, "soft-404 faked a backdoor"
    assert rep["exfiltration_results"]["records_stolen"] == 0, "soft-404 faked data theft"
    assert rep["exfiltration_results"]["data_exfiltrated_mb"] == 0.0, "soft-404 faked file theft"
    assert rep["cover_tracks_results"]["logs_deleted"] == 0, "soft-404 faked log deletion"
    assert "DENIED" in rep["verdict"]
    logs = " ".join(e["msg"] for e in run.logs)
    assert "Soft-404 catch-all detected" in logs, "recon should announce the catch-all"


def test_cloudflare_challenge_site_labeled_honestly(svc, fake_site):
    """THE WAF test: Cloudflare challenges every request (403 interstitial).

    Before challenge detection this reported ~39 fake "endpoints"/"hidden
    routes" (every 403 was "Protected") — the tool must instead report
    nothing found, label the WAF distinctly, and credit it with the blocks.
    """
    base, handler = fake_site
    handler.behavior = "challenge"
    run = svc.start_run(base, "maximum", engine="real")
    _wait(run, timeout=180)
    assert run.status == "complete"
    rep = run.report

    # challenge 403s are NOT protected endpoints / hidden routes
    assert rep["recon_results"]["endpoints_discovered"] == 0, \
        f"challenge 403s produced fake endpoints: {rep['recon_results']['endpoints']}"
    assert rep["recon_results"]["hidden_routes"] == [], \
        f"challenge 403s produced fake hidden routes: {rep['recon_results']['hidden_routes']}"

    # nothing was exploited / installed / stolen / deleted
    assert rep["attack_chain"]["phase_2_exploit"] is False
    assert rep["persistence_results"]["backdoors_installed"] == 0
    assert rep["exfiltration_results"]["records_stolen"] == 0
    assert rep["exfiltration_results"]["data_exfiltrated_mb"] == 0.0
    assert rep["cover_tracks_results"]["logs_deleted"] == 0

    # distinct labeling — a challenge is NOT a soft-404 catch-all
    logs = " ".join(e["msg"] for e in run.logs)
    assert "Cloudflare" in logs and "challenge" in logs.lower(), \
        "the WAF interception must be labeled in the log stream"
    assert "Soft-404 catch-all detected" not in logs, \
        "challenge pages must not be mislabeled as a catch-all"

    # the report carries a waf section and defense credit
    assert rep["waf"], "report must include a waf section"
    assert rep["waf"]["provider"] == "cloudflare"
    assert rep["waf"]["kind"] == "managed_challenge"
    assert rep["waf"]["requests_intercepted"] > 0
    assert rep["defense"]["total_blocks"] > 0
    assert "cloudflare_waf" in rep["defense"]["by_type"]

    # the verdict credits the defenses that repelled the run
    assert rep["verdict"] == "ACCESS DENIED — target defenses repelled every attack"

    # request events carry WAF defense telemetry (cf-mitigated header)
    waf_events = [e for e in run.events if e.get("defense") == "cloudflare_waf"]
    assert waf_events, "tracer should mark cf-mitigated responses as WAF blocks"

    # summary surfaces the interception as a key finding
    assert any("WAF" in f for f in rep["summary"]["key_findings"])


def test_rate_limited_export_finishes_quickly(svc, fake_site):
    """A 429-on-everything export endpoint must not stall the run."""
    base, handler = fake_site
    handler.behavior = "ratelimit"
    t0 = time.time()
    run = svc.start_run(base, "maximum", engine="real")
    _wait(run, timeout=180)
    assert run.status == "complete"
    # 3 retries × 5s backoff ≈ 15s max for the export; whole run stays sane
    assert time.time() - t0 < 120


def test_heartbeat_logs_during_long_runs(svc, fake_site):
    base, handler = fake_site
    run = svc.start_run(base, "maximum", engine="real")
    _wait(run, timeout=180)
    logs = [e["msg"] for e in run.logs]
    beats = [m for m in logs if "requests fired" in m]
    assert beats, "no heartbeat lines were logged"
    assert run._req_count > 50


def test_report_downloads_for_real_target(svc, fake_site):
    base, handler = fake_site
    run = svc.start_run(base, "maximum", engine="real")
    _wait(run, timeout=180)
    snap = run.snapshot(after=-1, after_event=-1, include_report=True)
    assert snap["report"]["run_id"] == run.run_id
    # report serializes cleanly (persistence path)
    text = json.dumps(snap["report"], default=str)
    assert "verdict" in text
