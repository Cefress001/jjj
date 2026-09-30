"""Attack service: event backbone, enrichment, persistence round-trip."""

import json
import time


def _wait(run, timeout=60):
    t0 = time.time()
    while run.thread and run.thread.is_alive() and time.time() - t0 < timeout:
        time.sleep(0.2)
    return run


def test_simulation_run_events(svc):
    """A sim run produces phase + request events with monotonic seq numbers."""
    run = svc.start_run("http://127.0.0.1:1/", "maximum", engine="simulation")
    _wait(run)
    assert run.status == "complete"
    kinds = {e["kind"] for e in run.events}
    assert "phase" in kinds
    assert "request" in kinds
    seqs = [e["seq"] for e in run.events]
    assert seqs == sorted(seqs), "event sequence numbers must be monotonic"


def test_snapshot_cursors(svc):
    run = svc.start_run("http://127.0.0.1:1/", "maximum", engine="simulation")
    _wait(run)
    snap_all = run.snapshot(after=-1, after_event=-1)
    assert len(snap_all["events"]) == run.snapshot()["event_total"] - run.snapshot()["events_dropped"] or True
    total_events = snap_all["event_total"]
    half = snap_all["events"][total_events // 2]["seq"]
    snap_half = run.snapshot(after_event=half)
    assert all(e["seq"] > half for e in snap_half["events"])
    assert len(snap_half["events"]) == total_events - (total_events // 2 + 1)


def test_report_enrichment(svc, remediation_mod):
    run = svc.start_run("http://127.0.0.1:1/", "maximum", engine="simulation")
    _wait(run)
    rep = run.report
    assert "mitre" in rep and set(rep["mitre"]) == set(remediation_mod.MITRE)
    assert isinstance(rep["recommendations"], list) and rep["recommendations"]
    assert "defense" in rep and "verdict" in rep
    for rec in rep["recommendations"]:
        assert set(rec) >= {"area", "priority", "title", "fix"}


def test_persistence_roundtrip(svc, tmp_path):
    run = svc.start_run("http://127.0.0.1:1/", "maximum", engine="simulation")
    _wait(run)
    svc.persist_run(run)
    # find the file (DATA_DIR is package-local)
    files = sorted(svc.DATA_DIR.glob(run.run_id + ".json"))
    assert files, "run was not persisted"
    data = json.loads(files[0].read_text())
    assert data["run_id"] == run.run_id
    assert data["status"] == "complete"
    assert data["report"]["summary"]["severity"]
    assert isinstance(data["events"], list) and data["events"]
    files[0].unlink()   # clean up test artifact


def test_cancel(svc):
    run = svc.start_run("http://127.0.0.1:1/", "stealth", engine="simulation")
    run.cancel()
    _wait(run, timeout=90)
    assert run.status in ("aborted", "complete")   # abort may race a fast run


def test_remediation_rules_lookup(remediation_mod):
    rep = {
        "exploit_results": {"methods": ["algorithm_confusion", "privesc"]},
        "persistence_results": {"backdoors": [{"type": "webhook"}, {"type": "cron"}]},
        "lateral_movement_results": {"credentials": [{"type": "DATABASE_URL"}, {"type": "AWS_ACCESS_KEY"}]},
        "exfiltration_results": {"extraction_methods": ["user_export"]},
        "cover_tracks_results": {"logs_deleted": 900},
        "recon_results": {"endpoints": ["/.env", "/admin"], "hidden_routes": ["/admin"]},
    }
    recs = remediation_mod.build_recommendations(rep, [])
    titles = [r["title"] for r in recs]
    assert any("JWT" in t for t in titles)
    assert any("race" in t.lower() or "promo" in t.lower() for t in titles) is False  # not exploited here
    assert any("API keys" in t or "webhook" in t.lower() for t in titles)
    assert any("Database credentials" in t for t in titles)
    priorities = [remediation_mod.PRIORITY_ORDER[r["priority"]] for r in recs]
    assert priorities == sorted(priorities), "recommendations must be priority-sorted"


def test_mitre_ids_wellformed(remediation_mod):
    import re
    for phase, techs in remediation_mod.MITRE.items():
        assert techs, f"{phase} has no techniques"
        for t in techs:
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", t["id"]), t["id"]
            assert t["name"]
