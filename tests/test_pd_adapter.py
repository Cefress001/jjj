"""ProjectDiscovery adapters and combined-report normalization."""

import stat


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


def test_connected_pipeline_feeds_discovery_to_nuclei(monkeypatch):
    import scanner_pipeline

    available = {
        "httpx": {"available": True}, "katana": {"available": True},
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
