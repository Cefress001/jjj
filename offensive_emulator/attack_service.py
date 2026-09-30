"""
Attack Service — the single execution backend for the app.

Manages attack runs in background threads:
  • REAL engine      — the 6 attack_modules driven by UnifiedOffensiveEmulator
                       (requires aiohttp; pip install aiohttp)
  • SIMULATION       — zero-dependency simulator (always available)

Exposes run state: status, phase, progress, streaming logs, final report.
"""

import asyncio
import logging
import random
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

_BASE_DIR = Path(__file__).parent

# Make the engine importable both as a package and flat
if str(_BASE_DIR) not in sys.path:
    sys.path.insert(0, str(_BASE_DIR))

# ---------------------------------------------------------------------------
# Engine availability
# ---------------------------------------------------------------------------

try:
    import aiohttp  # noqa: F401
    _HAS_AIOHTTP = True
except Exception:
    _HAS_AIOHTTP = False

if _HAS_AIOHTTP:
    try:
        from offensive_emulator_unified import UnifiedOffensiveEmulator  # type: ignore
        _HAS_REAL_ENGINES = True
    except Exception:
        _HAS_REAL_ENGINES = False
else:
    _HAS_REAL_ENGINES = False

from simulator import SimulationEngine  # noqa: E402

ENGINE_MODE = "real" if _HAS_REAL_ENGINES else "simulation"

# ---------------------------------------------------------------------------
# Phase metadata (keys match the emulator + simulator)
# ---------------------------------------------------------------------------

PHASES: List[Dict[str, str]] = [
    {"key": "recon",            "num": "01", "name": "Reconnaissance",   "icon": "◉", "desc": "Endpoint mapping · tech fingerprinting · hidden routes"},
    {"key": "exploit",          "num": "02", "name": "Exploitation",     "icon": "⚡", "desc": "JWT tampering · race conditions · privilege escalation"},
    {"key": "persistence",      "num": "03", "name": "Persistence",      "icon": "🔓", "desc": "Hidden admins · API keys · webhooks · cron backdoors"},
    {"key": "lateral_movement", "num": "04", "name": "Lateral Movement", "icon": "⇄", "desc": "Credential harvesting · service discovery · key theft"},
    {"key": "exfiltration",     "num": "05", "name": "Exfiltration",     "icon": "▤", "desc": "Bulk user export · transaction dumps · file extraction"},
    {"key": "cover_tracks",     "num": "06", "name": "Cover Tracks",     "icon": "☄", "desc": "Log deletion · audit purge · false-flag attribution"},
]

PRESETS = {
    "stealth":    {"name": "Stealth",    "tag": "slow · quiet · max evasion",  "color": "#34d399"},
    "balanced":   {"name": "Balanced",   "tag": "normal speed (recommended)",  "color": "#22d3ee"},
    "aggressive": {"name": "Aggressive", "tag": "fast · concurrent · noisy",   "color": "#fbbf24"},
    "maximum":    {"name": "Maximum",    "tag": "full speed · no evasion",     "color": "#f43f5e"},
}


class AttackAborted(Exception):
    pass


# ---------------------------------------------------------------------------
# Log capture: route engine log records into the owning run
# ---------------------------------------------------------------------------

_ENGINE_PREFIXES = ("attack_modules", "offensive_emulator_unified",
                    "offensive_emulator.attack_modules", "offensive_emulator.offensive_emulator_unified")
_thread_ctx = threading.local()


class _RunLogHandler(logging.Handler):
    """Captures log records emitted from attack threads and files them into runs."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            run = getattr(_thread_ctx, "current_run", None)
            if run is None:
                return
            if not record.name.startswith(_ENGINE_PREFIXES):
                return
            run._add_log(record.getMessage(), record.levelname)
        except Exception:
            pass


_log_handler = _RunLogHandler()
logging.getLogger().addHandler(_log_handler)

# Keep the server console quiet — attack logs stream to the web UI instead.
_root = logging.getLogger()
for _h in list(_root.handlers):
    if not isinstance(_h, _RunLogHandler):
        _root.removeHandler(_h)
if not any(isinstance(h, logging.NullHandler) for h in _root.handlers):
    _root.addHandler(logging.NullHandler())

MAX_LOGS = 2600


class AttackRun:
    """One attack execution with live state."""

    def __init__(self, target: str, preset: str, engine: Optional[str] = None):
        self.run_id = uuid.uuid4().hex[:8]
        self.target = target.rstrip("/")
        self.preset = preset if preset in PRESETS else "balanced"
        self.engine = engine or ENGINE_MODE
        self.created_at = time.time()

        self.status = "queued"            # queued | running | complete | failed | aborted
        self.phase_states: Dict[str, str] = {p["key"]: "pending" for p in PHASES}
        self.current_phase: Optional[str] = None
        self.progress = 0.0
        self.error: Optional[str] = None

        self.logs: List[Dict[str, Any]] = []
        self.logs_dropped = 0
        self.report: Optional[Dict[str, Any]] = None

        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self.thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._cancel = threading.Event()

    # ---------------------------------------------------------------- state

    def _add_log(self, message: str, level: str = "INFO") -> None:
        entry = {"i": len(self.logs) + self.logs_dropped, "t": round(time.time(), 3),
                 "level": level, "msg": message}
        with self._lock:
            self.logs.append(entry)
            if len(self.logs) > MAX_LOGS:
                drop = len(self.logs) - MAX_LOGS
                self.logs = self.logs[drop:]
                self.logs_dropped += drop

    def log(self, message: str, level: str = "INFO") -> None:
        self._add_log(message, level)

    def set_phase(self, key: str, state: str) -> None:
        with self._lock:
            self.phase_states[key] = state
            if state == "running":
                self.current_phase = key
            elif key == self.current_phase and state != "running":
                self.current_phase = None
            idx = [p["key"] for p in PHASES].index(key)
            if state == "running":
                self.progress = max(self.progress, idx / len(PHASES) * 100.0)
            elif state in ("complete", "failed", "skipped"):
                self.progress = max(self.progress, (idx + 1) / len(PHASES) * 100.0)

    def cancel(self) -> bool:
        if self.status in ("running", "queued"):
            self._cancel.set()
            return True
        return False

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    # -------------------------------------------------------------- snapshot

    def snapshot(self, after: int = -1, include_report: bool = False) -> Dict[str, Any]:
        with self._lock:
            logs = [e for e in self.logs if e["i"] > after]
            total_logs = len(self.logs) + self.logs_dropped
        snap = {
            "run_id": self.run_id,
            "target": self.target,
            "preset": self.preset,
            "engine": self.engine,
            "status": self.status,
            "progress": round(self.progress, 1),
            "current_phase": self.current_phase,
            "phase_states": dict(self.phase_states),
            "logs": logs,
            "log_total": total_logs,
            "logs_dropped": self.logs_dropped,
            "elapsed_s": round((self.started_at and (self.finished_at or time.time()) - self.started_at) or 0.0, 2),
            "created_at": self.created_at,
            "error": self.error,
        }
        if include_report and self.report:
            snap["report"] = self.report
        if self.report:
            summ = self.report.get("summary", {})
            snap["severity"] = summ.get("severity")
            snap["success_rate"] = summ.get("attack_success_rate")
        return snap


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_runs: Dict[str, AttackRun] = {}
_runs_lock = threading.Lock()
MAX_RUNS_KEPT = 40


def get_run(run_id: str) -> Optional[AttackRun]:
    with _runs_lock:
        return _runs.get(run_id)


def list_runs() -> List[Dict[str, Any]]:
    with _runs_lock:
        runs = sorted(_runs.values(), key=lambda r: r.created_at, reverse=True)
        return [r.snapshot() for r in runs]


def _register(run: AttackRun) -> None:
    with _runs_lock:
        _runs[run.run_id] = run
        if len(_runs) > MAX_RUNS_KEPT:
            for rid in list(_runs)[:-MAX_RUNS_KEPT]:
                if _runs[rid].status in ("complete", "failed", "aborted"):
                    del _runs[rid]


def start_run(target: str, preset: str = "balanced", engine: Optional[str] = None) -> AttackRun:
    """Create a run and launch it in a background thread."""
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    run = AttackRun(target, preset, engine)
    run.thread = threading.Thread(target=_thread_main, args=(run,), daemon=True,
                                  name=f"attack-{run.run_id}")
    _register(run)
    run.thread.start()
    return run


def _thread_main(run: AttackRun) -> None:
    _thread_ctx.current_run = run
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_execute(run))
    except AttackAborted:
        run.status = "aborted"
        run.log("✋ Attack aborted by operator", "WARN")
    except Exception as exc:
        run.status = "failed"
        run.error = str(exc)
        run.log(f"✗ Attack failed: {exc}", "ERROR")
        run.log(traceback.format_exc(limit=3), "ERROR")
    finally:
        if run.status == "running":
            run.status = "complete"
        run.finished_at = time.time()
        run.progress = 100.0 if run.status == "complete" else run.progress
        try:
            loop.close()
        except Exception:
            pass
        _thread_ctx.current_run = None


async def _execute(run: AttackRun) -> None:
    run.status = "running"
    run.started_at = time.time()
    run.log("═" * 62, "PHASE")
    run.log(f"  OFFENSIVE EMULATOR · run {run.run_id}", "PHASE")
    run.log(f"  target  : {run.target}", "INFO")
    run.log(f"  profile : {run.preset} · engine: {run.engine.upper()}", "INFO")
    run.log("═" * 62, "PHASE")

    phase_by_key = {p["key"]: p for p in PHASES}

    def on_phase(key: str, state: str) -> None:
        if run.cancelled:
            raise AttackAborted()
        meta = phase_by_key.get(key, {"num": "?", "name": key})
        run.set_phase(key, state)
        if state == "running":
            run.log(f"━━ [{meta['num']}] {meta['name'].upper()} — engaged", "PHASE")
        elif state == "skipped":
            run.log(f"⊘ [{meta['num']}] {meta['name'].upper()} — skipped (prerequisite failed)", "WARN")
        elif state == "complete":
            run.log(f"✓ [{meta['num']}] {meta['name'].upper()} — objective achieved", "OK")
        else:
            run.log(f"✗ [{meta['num']}] {meta['name'].upper()} — failed", "ERROR")

    def on_sim_log(message: str, level: str) -> None:
        if run.cancelled:
            raise AttackAborted()
        run.log(message, level)

    try:
        if run.engine == "real" and _HAS_REAL_ENGINES:
            emulator = UnifiedOffensiveEmulator(target_url=run.target, run_id=run.run_id)
            report = await emulator.run_full_attack(on_phase=on_phase)
        else:
            sim = SimulationEngine(run.target, run.run_id, run.preset)
            report = await sim.run(on_phase=on_phase, on_log=on_sim_log)
    except AttackAborted:
        raise
    except Exception:
        raise
    finally:
        pass

    run.report = report
    run.status = "complete"
    run.progress = 100.0

    # closing summary in the log stream
    summary = report.get("summary", {})
    run.log("═" * 62, "PHASE")
    run.log(f"  MISSION COMPLETE · severity: {summary.get('severity', '?')} · "
            f"success rate: {summary.get('attack_success_rate', '?')}", "OK")
    run.log("═" * 62, "PHASE")


# ---------------------------------------------------------------------------
# CLI mode
# ---------------------------------------------------------------------------

def run_cli(target: str, preset: str = "balanced") -> Dict[str, Any]:
    """Run one attack synchronously (used by run.py --target)."""
    run = start_run(target, preset)
    assert run.thread is not None
    run.thread.join()
    return run.snapshot(include_report=True)


if __name__ == "__main__":
    import json
    import argparse

    ap = argparse.ArgumentParser(description="Attack service smoke test")
    ap.add_argument("target")
    ap.add_argument("--preset", default="balanced")
    args = ap.parse_args()
    result = run_cli(args.target, args.preset)
    print(json.dumps({k: v for k, v in result.items() if k != "logs"}, indent=2, default=str))
