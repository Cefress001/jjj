"""Phase 2 browser worker, adapter, and pipeline data-flow tests."""

import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


def _executable(path, content):
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def test_browser_url_scope_and_safe_navigation_helpers():
    from browser_worker import canonical_browser_url, safe_navigation, same_hostname

    assert canonical_browser_url("HTTPS://Example.TEST:443/app#route") == \
        "https://example.test/app"
    assert same_hostname("https://example.test/api", "EXAMPLE.TEST")
    assert not same_hostname("https://cdn.example.test/api", "example.test")
    assert safe_navigation("https://example.test/payload/view")
    assert not safe_navigation("https://example.test/logout")
    assert not safe_navigation("https://example.test/account/delete?id=1")
    assert not safe_navigation("https://example.test/checkout")


def test_browser_adapter_parses_isolated_worker_result(tmp_path, monkeypatch):
    import browser_adapter

    worker = _executable(tmp_path / "browser-worker", """#!/usr/bin/env python3
import json,sys
config=json.load(open(sys.argv[1]))
print(json.dumps({
  'endpoint_records':[{'url':config['target']+'/api/live','method':'GET','status':200,
                       'content_type':'application/json','resource_type':'fetch'}],
  'endpoints':[config['target']+'/api/live'],
  'forms':[], 'websockets':[], 'pages':[{'url':config['target']}],
  'screenshots':['/outside/not-allowed.png'], 'cross_origin_hosts':['cdn.test'],
  'errors':[], 'stats':{'pages_visited':1,'api_calls_observed':1}
}))
""")
    monkeypatch.setenv("BROWSER_COMMAND", worker)
    result = browser_adapter.run_browser(
        "https://example.test", "balanced", "fixture", lambda *args: None,
        lambda: False, timeout=5)
    assert result["endpoint_records"][0]["url"].endswith("/api/live")
    assert result["stats"]["api_calls_observed"] == 1
    assert result["screenshots"] == []
    assert result["duration_seconds"] >= 0


def test_browser_adapter_rejects_malformed_output(tmp_path, monkeypatch):
    import browser_adapter

    worker = _executable(
        tmp_path / "browser-worker",
        "#!/usr/bin/env python3\nprint('this is not json')\n")
    monkeypatch.setenv("BROWSER_COMMAND", worker)
    with pytest.raises(browser_adapter.BrowserScanError, match="invalid JSON"):
        browser_adapter.run_browser(
            "https://example.test", "balanced", "malformed", lambda *args: None,
            lambda: False, timeout=5)


def test_browser_adapter_cancellation_is_prompt(tmp_path, monkeypatch):
    import browser_adapter

    worker = _executable(
        tmp_path / "browser-worker",
        "#!/usr/bin/env python3\nimport time\ntime.sleep(60)\n")
    monkeypatch.setenv("BROWSER_COMMAND", worker)
    started = time.time()
    with pytest.raises(InterruptedError):
        browser_adapter.run_browser(
            "https://example.test", "balanced", "fixture", lambda *args: None,
            lambda: time.time() - started > 0.15, timeout=5)
    assert time.time() - started < 3


def test_local_javascript_spa_discovers_runtime_only_routes(monkeypatch):
    """Real-browser acceptance fixture; runs when Chromium is installed."""
    import browser_adapter

    monkeypatch.delenv("BROWSER_COMMAND", raising=False)
    browser_adapter._runtime_ready.cache_clear()
    if not browser_adapter.availability()["available"]:
        pytest.skip("Playwright Chromium runtime is unavailable on this host")

    class SpaHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                body = b'<main id="app"></main><script src="/app.js"></script>'
                content_type = "text/html"
            elif self.path == "/app.js":
                body = (b"fetch('/api/runtime?source=spa').then(r=>r.json());"
                        b"document.querySelector('#app').innerHTML="
                        b"'<a href=\"/client-route\">Runtime route</a>';")
                content_type = "application/javascript"
            elif self.path.startswith("/api/runtime"):
                body, content_type = b'{"ok":true}', "application/json"
            elif self.path == "/client-route":
                body, content_type = b"<h1>Client route</h1>", "text/html"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), SpaHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}"
        result = browser_adapter.run_browser(
            target, "stealth", "spa-fixture", lambda *args: None,
            lambda: False, timeout=30)
    finally:
        server.shutdown()
        server.server_close()
    urls = set(result["endpoints"])
    assert any("/api/runtime?source=spa" in url for url in urls)
    assert any("/client-route" in url for url in urls)


def test_browser_discoveries_feed_zap_and_nuclei(tmp_path, monkeypatch):
    import scanner_pipeline

    monkeypatch.setattr(scanner_pipeline, "availability", lambda: {
        "httpx": {"available": False, "reason": "fixture"},
        "katana": {"available": False, "reason": "fixture"},
        "browser": {"available": True},
        "zap": {"available": True},
        "nuclei": {"available": True},
    })
    har = tmp_path / "traffic.har"
    har.write_text('{"log":{"entries":[]}}', encoding="utf-8")

    monkeypatch.setattr(scanner_pipeline.browser_adapter, "run_browser", lambda *args: {
        "_har_path": str(har),
        "har_size_bytes": har.stat().st_size,
        "endpoint_records": [
            {"url": "https://example.test/api/from-browser", "method": "POST",
             "status": 201, "content_type": "application/json"},
        ],
        "endpoints": ["https://example.test/api/from-browser"],
        "forms": [], "websockets": [], "pages": [], "screenshots": [],
        "stats": {"pages_visited": 1, "api_calls_observed": 1},
    })
    observed = {}

    def fake_zap(target, run_id, log, cancelled, timeout=900, har_path=None):
        observed["har_exists_during_zap"] = bool(har_path and har.exists())
        return {
            "summary": {"alerts_total": 0}, "findings": [],
            "recon_results": {"endpoints": []},
        }

    def fake_nuclei(targets, *args):
        observed["nuclei_targets"] = list(targets)
        return {"records_count": 0, "targets_scanned": len(targets), "findings": []}

    monkeypatch.setattr(scanner_pipeline.zap_adapter, "run_baseline", fake_zap)
    monkeypatch.setattr(scanner_pipeline.pd_adapter, "run_nuclei", fake_nuclei)
    results = scanner_pipeline.run_installed(
        "https://example.test", "balanced", "run", lambda *args: None,
        lambda: False, lambda *args: None)

    assert observed["har_exists_during_zap"] is True
    assert har.exists() is False
    assert "https://example.test/api/from-browser" in observed["nuclei_targets"]
    assert results["endpoint_corpus"]["by_source"]["browser"] == 1
    browser = results["browser"]
    assert "_har_path" not in browser
    assert browser["status"] == "complete"


def test_browser_failure_does_not_prevent_downstream_scan(monkeypatch):
    import browser_adapter
    import scanner_pipeline

    monkeypatch.setattr(scanner_pipeline, "availability", lambda: {
        "httpx": {"available": False, "reason": "fixture"},
        "katana": {"available": False, "reason": "fixture"},
        "browser": {"available": True},
        "zap": {"available": False, "reason": "fixture"},
        "nuclei": {"available": True},
    })
    monkeypatch.setattr(
        scanner_pipeline.browser_adapter, "run_browser",
        lambda *args: (_ for _ in ()).throw(browser_adapter.BrowserScanError("crash")))
    called = {}
    monkeypatch.setattr(scanner_pipeline.pd_adapter, "run_nuclei", lambda targets, *args: (
        called.update(targets=list(targets)) or
        {"records_count": 0, "targets_scanned": len(targets), "findings": []}
    ))

    results = scanner_pipeline.run_installed(
        "https://example.test", "balanced", "run", lambda *args: None,
        lambda: False, lambda *args: None)
    assert results["browser"]["status"] == "failed"
    assert results["nuclei"]["status"] == "complete"
    assert called["targets"] == ["https://example.test/"]
