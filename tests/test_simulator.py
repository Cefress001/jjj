"""Simulation engine: determinism, gating, report shape, request events."""

import asyncio


def run_sim(target, preset="maximum", seed=42):
    from simulator import SimulationEngine
    sim = SimulationEngine(target, "testrun", preset, seed=seed)
    phases, reqs = [], []

    report = asyncio.run(sim.run(
        on_phase=lambda k, s: phases.append((k, s)),
        on_log=lambda m, l: None,
        on_request=lambda m, p, s, ms: reqs.append((m, p, s)),
    ))
    return report, phases, reqs


def test_deterministic_with_seed():
    r1, p1, _ = run_sim("http://x")
    r2, p2, _ = run_sim("http://x")
    assert r1["summary"]["severity"] == r2["summary"]["severity"]
    assert p1 == p2
    assert r1["exfiltration_results"]["records_stolen"] == r2["exfiltration_results"]["records_stolen"]


def test_phase_gating():
    """If a prerequisite fails, dependents are skipped."""
    report, phases, _ = run_sim("http://x", seed=7)
    states = {}
    for k, s in phases:
        states[k] = s
    if states.get("recon") == "failed":
        assert states.get("exploit") == "skipped"
    if states.get("exploit") == "failed":
        assert states.get("persistence") == "skipped"
    # cover tracks always runs
    assert "cover_tracks" in states


def test_report_shape():
    report, _, _ = run_sim("http://x")
    for key in ("run_id", "target", "engine", "attack_chain", "phase_timings",
                "recon_results", "exploit_results", "persistence_results",
                "lateral_movement_results", "exfiltration_results",
                "cover_tracks_results", "summary"):
        assert key in report, f"missing report key: {key}"
    assert set(report["attack_chain"]) == {
        "phase_1_recon", "phase_2_exploit", "phase_3_persistence",
        "phase_4_lateral_movement", "phase_5_exfiltration", "phase_6_cover_tracks"}
    assert report["engine"] == "simulation"


def test_request_events_emitted():
    """The simulator emits request events so the inspector works in sim mode."""
    _, _, reqs = run_sim("http://x")
    assert len(reqs) > 10
    assert all(r[2] in (200, 201) for r in reqs)


def test_success_rate_math():
    report, _, _ = run_sim("http://x", seed=3)
    chain = report["attack_chain"]
    counted = [chain["phase_2_exploit"], chain["phase_3_persistence"],
               chain["phase_4_lateral_movement"], chain["phase_5_exfiltration"]]
    expected = sum(counted) / 4 * 100
    assert abs(float(report["summary"]["attack_success_rate"].rstrip("%")) - expected) < 0.1
