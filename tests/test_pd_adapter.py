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
