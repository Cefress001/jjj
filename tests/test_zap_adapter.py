"""OWASP ZAP adapter parsing and lifecycle tests (no ZAP install required)."""

import json
import stat
import time

import pytest

SAMPLE = {
    "site": [{
        "@name": "http://example.test",
        "alerts": [
            {
                "pluginid": "10020", "alert": "Missing Anti-clickjacking Header",
                "riskdesc": "Medium (Medium)", "confidence": "Medium",
                "desc": "The response does not include a frame protection policy.",
                "solution": "Set CSP frame-ancestors or X-Frame-Options.",
                "cweid": "1021", "wascid": "15",
                "instances": [{"uri": "http://example.test/", "method": "GET"}],
            },
            {
                "pluginid": "10021", "alert": "X-Content-Type-Options Missing",
                "riskdesc": "Low (Medium)", "confidence": "High",
                "solution": "Set X-Content-Type-Options to nosniff.",
                "instances": [{"uri": "http://example.test/login", "method": "GET"}],
            },
        ],
    }]
}


def _wait(run, timeout=20):
    started = time.time()
    while run.thread and run.thread.is_alive() and time.time() - started < timeout:
        time.sleep(0.05)
    return run


def test_zap_json_is_normalized():
    from zap_adapter import build_report

    report = build_report("http://example.test", "abc123", SAMPLE, 1.25)
    assert report["engine"] == "zap-baseline"
    assert report["summary"]["severity"] == "Medium"
    assert report["summary"]["alerts_total"] == 2
    assert report["summary"]["alerts_by_risk"]["Medium"] == 1
    assert report["findings"][0]["cwe_id"] == 1021
    assert report["findings"][0]["urls"] == ["http://example.test/"]
    assert report["attack_chain"]["phase_2_exploit"] is False
    assert report["recommendations"][0]["fix"]


def test_zap_parser_tolerates_malformed_numeric_metadata():
    from zap_adapter import extract_alerts

    findings = extract_alerts({"alerts": [{
        "alert": "Fixture", "cweid": "not-a-number", "wascid": {},
        "instances": [{"uri": "https://example.test/"}],
    }]})
    assert findings[0]["cwe_id"] == 0
    assert findings[0]["wasc_id"] == 0


def test_zap_cancellation_is_prompt(tmp_path, monkeypatch):
    import zap_adapter

    fake = tmp_path / "zap-baseline.py"
    fake.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(60)\n", encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("ZAP_BASELINE_COMMAND", str(fake))
    started = time.time()
    with pytest.raises(InterruptedError):
        zap_adapter.run_baseline(
            "https://example.test", "run", lambda *args: None,
            lambda: time.time() - started > 0.15, timeout=5)
    assert time.time() - started < 3


def test_zap_run_through_service(svc, tmp_path, monkeypatch):
    report_file = tmp_path / "fixture.json"
    report_file.write_text(json.dumps(SAMPLE), encoding="utf-8")
    fake = tmp_path / "zap-baseline.py"
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import json, pathlib, sys\n"
        "args=sys.argv\n"
        "out=pathlib.Path(args[args.index('-J')+1])\n"
        f"out.write_text(pathlib.Path({str(report_file)!r}).read_text())\n"
        "print('PASS: baseline fixture')\n",
        encoding="utf-8",
    )
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("ZAP_BASELINE_COMMAND", str(fake))

    # ZAP augments the normal workflow automatically; it is not selected as a
    # replacement engine by the caller.
    run = svc.start_run("http://example.test", "maximum", engine="simulation")
    _wait(run)
    assert run.status == "complete", run.error
    assert run.report["engine"] == "simulation"
    assert run.report["scanner_results"]["zap"]["alerts_total"] == 2
    assert "zap" in run.report["tools_run"]
    assert run.phase_states["recon"] == "complete"
    assert any(e["kind"] == "finding" for e in run.events)
    assert any("PASS: baseline fixture" in line["msg"] for line in run.logs)


def test_unavailable_zap_does_not_block_core_scan(svc, monkeypatch):
    monkeypatch.delenv("ZAP_BASELINE_COMMAND", raising=False)
    monkeypatch.setattr(svc.scanner_pipeline.zap_adapter.shutil, "which", lambda _: None)
    run = svc.start_run("http://example.test", "maximum", engine="simulation")
    _wait(run)
    assert run.status == "complete"
    assert run.report["scanner_results"]["zap"]["status"] == "unavailable"
