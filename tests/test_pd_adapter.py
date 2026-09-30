"""ProjectDiscovery adapters and combined-report normalization."""

import stat
import time

import pytest


def _tool(tmp_path, name, json_line):
    path = tmp_path / name
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        f"print(json.dumps({json_line!r}))\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def test_projectdiscovery_jsonl_adapters(tmp_path, monkeypatch):
    import pd_adapter

    httpx = _tool(tmp_path, "httpx", {
        "url": "https://example.test", "status_code": 200,
        "tech": ["nginx", "React"],
    })
    katana = _tool(tmp_path, "katana", {
        "request": {"endpoint": "https://example.test/account"},
    })
    nuclei = _tool(tmp_path, "nuclei", {
        "template-id": "missing-hsts", "matched-at": "https://example.test",
        "info": {
            "name": "Strict-Transport-Security Missing", "severity": "medium",
            "description": "HSTS was not returned.",
            "remediation": "Set a suitable Strict-Transport-Security header.",
            "classification": {"cwe-id": ["CWE-693"]},
        },
    })
    monkeypatch.setenv("HTTPX_COMMAND", httpx)
    monkeypatch.setenv("KATANA_COMMAND", katana)
    monkeypatch.setenv("NUCLEI_COMMAND", nuclei)
    logs = []
    log = lambda message, level: logs.append((level, message))
    active = lambda: False

    hx = pd_adapter.run_httpx("https://example.test", "balanced", log, active)
    ka = pd_adapter.run_katana("https://example.test", "balanced", log, active)
    nu = pd_adapter.run_nuclei("https://example.test", "balanced", log, active)
    assert hx["technologies"] == ["nginx", "React"]
    assert ka["endpoints"] == ["https://example.test/account"]
    assert nu["findings"][0]["severity"] == "Medium"
    assert nu["findings"][0]["cwe_ids"] == ["CWE-693"]
    assert nu["targets_scanned"] == 1


def test_jsonl_runner_caps_output_and_survives_invalid_utf8(tmp_path, monkeypatch):
    import pd_adapter

    tool = tmp_path / "httpx"
    tool.write_bytes(
        b"#!/usr/bin/env python3\n"
        b"import os\n"
        b"os.write(1, b'bad-utf8: \\xff\\n')\n"
        b"for i in range(5): print('{\\\"url\\\": \\\"https://example.test/%d\\\"}' % i)\n"
    )
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("HTTPX_COMMAND", str(tool))
    logs = []
    records = pd_adapter._run_jsonl(
        "httpx", [], lambda message, level: logs.append((level, message)),
        lambda: False, timeout=3, max_records=2)
    assert len(records) == 2
    assert any("output capped" in message for _, message in logs)
    assert any("bad-utf8" in message for _, message in logs)


def test_jsonl_runner_cancellation_is_prompt(tmp_path, monkeypatch):
    import pd_adapter

    tool = tmp_path / "httpx"
    tool.write_text(
        "#!/usr/bin/env python3\nimport time\ntime.sleep(60)\n",
        encoding="utf-8",
    )
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("HTTPX_COMMAND", str(tool))
    started = time.time()
    with pytest.raises(InterruptedError):
        pd_adapter._run_jsonl(
            "httpx", [], lambda *args: None,
            lambda: time.time() - started > 0.15, timeout=5)
    assert time.time() - started < 3


def test_nuclei_target_file_deduplicates_and_rejects_line_injection(tmp_path, monkeypatch):
    import pd_adapter

    captured = tmp_path / "targets.txt"
    tool = tmp_path / "nuclei"
    tool.write_text(
        "#!/usr/bin/env python3\n"
        "import pathlib,sys\n"
        "p=pathlib.Path(sys.argv[sys.argv.index('-l')+1])\n"
        f"pathlib.Path({str(captured)!r}).write_text(p.read_text())\n",
        encoding="utf-8",
    )
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("NUCLEI_COMMAND", str(tool))
    result = pd_adapter.run_nuclei(
        ["https://example.test/a", "https://example.test/a",
         "https://example.test/good\nhttps://outside.test/injected"],
        "balanced", lambda *args: None, lambda: False)
    assert result["targets_scanned"] == 1
    assert captured.read_text().splitlines() == ["https://example.test/a"]


def test_malformed_command_configuration_is_reported_unavailable(monkeypatch):
    import pd_adapter

    monkeypatch.setenv("HTTPX_COMMAND", "'unterminated")
    assert pd_adapter.availability()["httpx"]["available"] is False


def test_connected_pipeline_feeds_discovery_to_nuclei(monkeypatch):
    import scanner_pipeline

    available = {
        "httpx": {"available": True}, "katana": {"available": True},
        "browser": {"available": False, "reason": "fixture"},
        "zap": {"available": False, "reason": "fixture"},
        "nuclei": {"available": True},
    }
    monkeypatch.setattr(scanner_pipeline, "availability", lambda: available)
    monkeypatch.setattr(scanner_pipeline.pd_adapter, "run_httpx", lambda *args: {
        "canonical_target": "https://example.test/home",
        "assets": ["https://example.test/home"],
        "technologies": ["React"],
        "records": [{"url": "https://example.test/home", "status_code": 200}],
    })

    def fake_katana(target, *args):
        assert target == "https://example.test/home"
        return {
            "endpoints": ["https://example.test/api/users", "https://outside.test/escape"],
            "endpoint_records": [
                {"url": "https://example.test/api/users", "method": "GET", "status": 200},
                {"url": "https://outside.test/escape", "method": "GET", "status": 200},
            ],
        }

    received = {}

    def fake_nuclei(targets, *args):
        received["targets"] = list(targets)
        return {"records_count": 0, "targets_scanned": len(targets), "findings": []}

    monkeypatch.setattr(scanner_pipeline.pd_adapter, "run_katana", fake_katana)
    monkeypatch.setattr(scanner_pipeline.pd_adapter, "run_nuclei", fake_nuclei)
    results = scanner_pipeline.run_installed(
        "http://example.test", "balanced", "run1", lambda *args: None,
        lambda: False, lambda *args: None)

    assert "https://example.test/api/users" in received["targets"]
    assert all("outside.test" not in value for value in received["targets"])
    corpus = results["endpoint_corpus"]
    assert corpus["primary_url"] == "https://example.test/home"
    assert corpus["by_source"]["katana"] == 1
    assert corpus["rejected_by_reason"]["out_of_scope"] == 1
    assert corpus["selected_for_nuclei"] == len(received["targets"])


def test_pipeline_continues_when_upstream_tool_fails(monkeypatch):
    import scanner_pipeline

    monkeypatch.setattr(scanner_pipeline, "availability", lambda: {
        "httpx": {"available": True}, "katana": {"available": True},
        "browser": {"available": False, "reason": "fixture"},
        "zap": {"available": False, "reason": "fixture"},
        "nuclei": {"available": True},
    })

    def fail_httpx(*args):
        raise RuntimeError("fixture failure")

    seen = {}
    monkeypatch.setattr(scanner_pipeline.pd_adapter, "run_httpx", fail_httpx)
    monkeypatch.setattr(scanner_pipeline.pd_adapter, "run_katana", lambda target, *args: {
        "endpoints": [target + "/api"], "endpoint_records": [{"url": target + "/api"}],
    })
    monkeypatch.setattr(scanner_pipeline.pd_adapter, "run_nuclei", lambda targets, *args: (
        seen.update(targets=list(targets)) or
        {"records_count": 0, "targets_scanned": len(targets), "findings": []}
    ))
    results = scanner_pipeline.run_installed(
        "https://example.test", "balanced", "run", lambda *args: None,
        lambda: False, lambda *args: None)
    assert results["httpx"]["status"] == "failed"
    assert results["katana"]["status"] == "complete"
    assert "https://example.test/api" in seen["targets"]


def test_pipeline_merge_preserves_existing_report():
    import scanner_pipeline

    report = {
        "engine": "simulation",
        "summary": {"severity": "Low", "key_findings": ["Core result"],
                    "attack_success_rate": "0%"},
        "recon_results": {"endpoints": ["https://example.test/"],
                          "endpoints_discovered": 1, "tech_stack": {}},
        "recommendations": [],
        "attack_chain": {"phase_1_recon": True},
    }
    finding = {
        "source": "Nuclei", "id": "x", "name": "Example issue",
        "severity": "High", "urls": ["https://example.test/admin"],
        "solution": "Fix the issue.",
    }
    results = {
        "httpx": {"status": "complete", "assets": ["https://example.test"],
                  "technologies": ["nginx"]},
        "katana": {"status": "complete", "endpoints": ["https://example.test/admin"]},
        "zap": {"status": "unavailable"},
        "nuclei": {"status": "complete", "findings": [finding]},
    }
    events = []
    merged = scanner_pipeline.merge(report, results,
                                    lambda kind, **data: events.append((kind, data)))
    assert merged["engine"] == "simulation"
    assert merged["attack_chain"] == report["attack_chain"]
    assert merged["summary"]["severity"] == "High"
    assert merged["summary"]["scanner_findings"] == 1
    assert "nuclei" in merged["tools_run"]
    assert "https://example.test/admin" in merged["recon_results"]["endpoints"]
    assert merged["recon_results"]["tech_stack"]["httpx"] == "nginx"
    assert events[0][0] == "finding"
