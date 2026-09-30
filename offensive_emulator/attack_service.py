"""
Attack Service — the single execution backend for the app.

Manages attack runs in background threads:
  • REAL engine      — the 6 attack_modules driven by UnifiedOffensiveEmulator
                       (requires aiohttp; pip install aiohttp)
  • SIMULATION       — zero-dependency simulator (always available)

Structured EVENT stream (backbone for the console, request inspector,
mission replay and defense telemetry):

  {seq, t, kind:"phase",    phase, state}
  {seq, t, kind:"request",  method, path, status, ms, defense?}
  {seq, t, kind:"defense",  type, detail}        (aggregated from requests)

Runs persist to data/runs/<id>.json and are reloaded at boot, so history,
reports and replays survive server restarts.
"""

import asyncio
import json
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
import remediation  # noqa: E402
import scanner_pipeline  # noqa: E402

try:
    from attack_modules.challenge import detect_challenge, challenge_label  # noqa: E402
except Exception:  # pragma: no cover - flat import fallback
    from offensive_emulator.attack_modules.challenge import (  # type: ignore
        detect_challenge, challenge_label)

ENGINE_MODE = "real" if _HAS_REAL_ENGINES else "simulation"


def available_engines() -> Dict[str, Dict[str, Any]]:
    """Core engines; supplemental scanners are automatic, not alternatives."""
    return {
        "simulation": {"name": "Built-in workflow", "available": True},
        "real": {"name": "HTTP workflow", "available": _HAS_REAL_ENGINES},
    }

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
    "stealth":    {"name": "Stealth",    "tag": "slow · quiet · max evasion",  "color": "#34d399", "delay": [0.14, 0.34]},
    "balanced":   {"name": "Balanced",   "tag": "normal speed (recommended)",  "color": "#22d3ee", "delay": [0.04, 0.12]},
    "aggressive": {"name": "Aggressive", "tag": "fast · concurrent · noisy",   "color": "#fbbf24", "delay": [0.0, 0.03]},
    "maximum":    {"name": "Maximum",    "tag": "full speed · no evasion",     "color": "#f43f5e", "delay": [0.0, 0.0]},
}

MAX_LOGS = 2600
MAX_EVENTS = 4000


class AttackAborted(Exception):
    pass


# ---------------------------------------------------------------------------
# Log/event capture: route engine records into the owning run
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

# Attach the capture handler directly to the engine logger trees with explicit
# levels — independent of whatever the root logger's level is (web framework,
# pytest, or an embedding app may all manipulate the root logger).
for _name in _ENGINE_PREFIXES:
    _lg = logging.getLogger(_name)
    _lg.setLevel(logging.INFO)
    _lg.addHandler(_log_handler)

# Keep the server console quiet — attack logs stream to the web UI instead.
_root = logging.getLogger()
for _h in list(_root.handlers):
    if not isinstance(_h, _RunLogHandler):
        _root.removeHandler(_h)
if not any(isinstance(h, logging.NullHandler) for h in _root.handlers):
    _root.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# aiohttp request tracer + preset pacing
# ---------------------------------------------------------------------------

# Real sites and WAFs (Cloudflare et al.) frequently block the default
# "Python/3.x aiohttp/x.x" fingerprint outright — rotate realistic browser UAs.
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

HEARTBEAT_EVERY = 20  # log a liveness line every N requests


def _url_path(u) -> str:
    """Best-effort 'method path' string from a URL-ish object."""
    try:
        s = str(u)
        # yarl URLs expose .path/.query
        path = getattr(u, "path", None)
        if path:
            q = getattr(u, "query", "") or ""
            return str(path) + (("?" + str(q)) if q else "")
        return s[:140]
    except Exception:
        return "<url>"


class _PreflightError(Exception):
    """Target is not reachable — surfaced to the user as a clear failure."""


async def preflight_check(target: str) -> Dict[str, Any]:
    """
    Quick reachability probe before the engines fire.
    Raises _PreflightError with a human explanation when the target cannot
    be reached at all (DNS, refused, TLS, timeout). Any HTTP status counts
    as reachable — 403/404/5xx are still 'up'.
    """
    import aiohttp

    last_err = None
    for attempt in (1, 2):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    target, timeout=aiohttp.ClientTimeout(total=6 + attempt * 4),
                    allow_redirects=True,
                    headers={"User-Agent": random.choice(_USER_AGENTS)},
                ) as resp:
                    challenge = None
                    try:
                        body = await resp.text(errors="replace")
                        challenge = detect_challenge(resp.status, resp.headers, body)
                    except Exception:
                        pass
                    return {
                        "status": resp.status,
                        "server": resp.headers.get("Server", "unknown"),
                        "final_url": str(resp.url),
                        "challenge": challenge,
                    }
        except Exception as exc:
            last_err = exc
            # classify by exception TYPE — aiohttp messages mention "ssl:default"
            # even for plain connection failures, so the message text is unreliable.
            if "SSL" in type(exc).__name__ or "Certificate" in type(exc).__name__:
                raise _PreflightError(
                    f"TLS handshake failed for {target} — the certificate could not be "
                    f"verified. Use a target with a valid certificate. ({exc})")
            if attempt == 1:
                await asyncio.sleep(0.6)

    txt = str(last_err) or type(last_err).__name__
    raise _PreflightError(
        f"Target unreachable: {target} — {txt}. Check the URL, that the host is "
        f"online, and that a firewall is not blocking this machine.")


def _install_request_tracer() -> bool:
    """
    Wrap aiohttp.ClientSession._request so every request the engines make is
    recorded (method/path/status/latency/defense), paced per preset, and sent
    with a realistic browser User-Agent.
    Falls back silently to the unpatched session if anything goes wrong.
    """
    if not _HAS_AIOHTTP:
        return False
    try:
        orig = aiohttp.ClientSession._request

        async def _traced(self, method, str_or_url, **kwargs):
            run = getattr(_thread_ctx, "current_run", None)
            if run is not None:
                # preset pacing — every request, both engines share this
                lo, hi = PRESETS.get(run.preset, PRESETS["balanced"])["delay"]
                if hi > 0:
                    await asyncio.sleep(random.uniform(lo, hi))
                # realistic UA unless the caller set one explicitly
                headers = kwargs.get("headers")
                if headers is None:
                    headers = {}
                    kwargs["headers"] = headers
                try:
                    has_ua = any(str(k).lower() == "user-agent" for k in headers)
                except Exception:
                    has_ua = False
                if not has_ua:
                    headers["User-Agent"] = random.choice(_USER_AGENTS)
            t0 = time.time()
            try:
                resp = await orig(self, method, str_or_url, **kwargs)
            except Exception as exc:
                if run is not None:
                    run._add_request_event(str(method), _url_path(str_or_url), 0,
                                           (time.time() - t0) * 1000.0,
                                           error=str(exc)[:70])
                    run._note_request_for_heartbeat()
                raise
            if run is not None:
                defense = None
                try:
                    defense = resp.headers.get("X-Defense") or None
                    if defense is None and \
                            (resp.headers.get("CF-Mitigated") or "").strip().lower() == "challenge":
                        defense = "cloudflare_waf"   # official Cloudflare signal
                except Exception:
                    pass
                try:
                    shown_url = resp.request_info.url
                except Exception:
                    shown_url = str_or_url
                run._add_request_event(str(method), _url_path(shown_url), resp.status,
                                       (time.time() - t0) * 1000.0, defense=defense)
                run._note_request_for_heartbeat()
            return resp

        aiohttp.ClientSession._request = _traced
        return True
    except Exception:
        return False


TRACER_INSTALLED = _install_request_tracer()


# ---------------------------------------------------------------------------
# Run persistence
# ---------------------------------------------------------------------------

DATA_DIR = _BASE_DIR / "data" / "runs"
MAX_PERSISTED_EVENTS = 2000
MAX_PERSISTED_LOGS = 600
MAX_ARCHIVE_LOAD = 60


def persist_run(run: "AttackRun") -> None:
    """Atomically write a finished run to data/runs/<id>.json."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        payload = {
            "run_id": run.run_id,
            "target": run.target,
            "preset": run.preset,
            "engine": run.engine,
            "status": run.status,
            "created_at": run.created_at,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "phase_states": run.phase_states,
            "progress": run.progress,
            "severity": (run.report or {}).get("summary", {}).get("severity"),
            "report": run.report,
            "events": list(run.events)[:MAX_PERSISTED_EVENTS],
            "logs": list(run.logs)[-MAX_PERSISTED_LOGS:],
        }
        tmp = DATA_DIR / (run.run_id + ".tmp")
        tmp.write_text(json.dumps(payload, default=str), encoding="utf-8")
        tmp.replace(DATA_DIR / (run.run_id + ".json"))
    except Exception:
        pass  # persistence must never break a run


def load_archived_runs() -> int:
    """Load past runs from disk into the registry. Returns count loaded."""
    if not DATA_DIR.is_dir():
        return 0
    count = 0
    files = sorted(DATA_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for fp in files[:MAX_ARCHIVE_LOAD]:
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
            run = AttackRun(data.get("target", "unknown"), data.get("preset", "balanced"),
                            data.get("engine"))
            run.run_id = data.get("run_id", fp.stem)
            run.status = data.get("status", "complete")
            run.created_at = data.get("created_at", 0)
            run.started_at = data.get("started_at")
            run.finished_at = data.get("finished_at")
            run.phase_states = data.get("phase_states", run.phase_states)
            run.progress = data.get("progress", 100.0)
            run.report = data.get("report")
            run.events = list(data.get("events", []))
            run.logs = list(data.get("logs", []))
            run.archived = True
            with _runs_lock:
                _runs[run.run_id] = run
            count += 1
        except Exception:
            continue
    return count


# ---------------------------------------------------------------------------
# AttackRun
# ---------------------------------------------------------------------------

class AttackRun:
    """One attack execution with live state and a structured event stream."""

    def __init__(self, target: str, preset: str, engine: Optional[str] = None):
        self.run_id = uuid.uuid4().hex[:8]
        self.target = target.rstrip("/")
        self.preset = preset if preset in PRESETS else "balanced"
        self.engine = engine or ENGINE_MODE
        self.created_at = time.time()
        self.archived = False

        self.status = "queued"            # queued | running | complete | failed | aborted
        self.phase_states: Dict[str, str] = {p["key"]: "pending" for p in PHASES}
        self.current_phase: Optional[str] = None
        self.progress = 0.0
        self.error: Optional[str] = None

        self.logs: List[Dict[str, Any]] = []
        self.logs_dropped = 0
        self.events: List[Dict[str, Any]] = []
        self.events_dropped = 0
        self.report: Optional[Dict[str, Any]] = None

        self.started_at: Optional[float] = None
        self.finished_at: Optional[float] = None
        self.thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self._req_count = 0
        self._req_sum_ms = 0.0

    # ---------------------------------------------------------------- events

    def _add_event(self, kind: str, **payload) -> None:
        with self._lock:
            ev = {"seq": len(self.events) + self.events_dropped,
                  "t": round(time.time(), 3), "kind": kind}
            ev.update(payload)
            self.events.append(ev)
            if len(self.events) > MAX_EVENTS:
                drop = len(self.events) - MAX_EVENTS
                self.events = self.events[drop:]
                self.events_dropped += drop

    def _add_request_event(self, method: str, path: str, status: int, ms: float,
                           error: Optional[str] = None, defense: Optional[str] = None) -> None:
        self._add_event("request", method=method, path=path[:160], status=int(status),
                        ms=round(ms, 1), phase=self.current_phase,
                        error=error, defense=defense)
        self._req_count += 1
        self._req_sum_ms += ms

    def _note_request_for_heartbeat(self) -> None:
        """Every N requests, log a liveness line so long phases never look dead."""
        if self._req_count and self._req_count % HEARTBEAT_EVERY == 0:
            avg = self._req_sum_ms / max(1, self._req_count)
            self.log(f"▸ {self._req_count} requests fired · avg {avg:.0f}ms · "
                     f"phase: {self.current_phase or 'probing'}", "INFO")

    # ------------------------------------------------------------------ logs

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

    # ----------------------------------------------------------------- phase

    def set_phase(self, key: str, state: str) -> None:
        with self._lock:
            self.phase_states[key] = state
            if state == "running":
                self.current_phase = key
            elif key == self.current_phase and state != "running":
                self.current_phase = None
            idx = [p["key"] for p in PHASES].index(key)
            # Reserve the final 20% for the automatic supplemental scanners.
            # This keeps progress honest after the six core phases complete.
            if state == "running":
                self.progress = max(self.progress, idx / len(PHASES) * 80.0)
            elif state in ("complete", "failed", "skipped"):
                self.progress = max(self.progress, (idx + 1) / len(PHASES) * 80.0)
        self._add_event("phase", phase=key, state=state)

    def cancel(self) -> bool:
        if self.status in ("running", "queued"):
            self._cancel.set()
            return True
        return False

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    # -------------------------------------------------------------- snapshot

    def snapshot(self, after: int = -1, after_event: int = -1,
                 include_report: bool = False) -> Dict[str, Any]:
        with self._lock:
            logs = [e for e in self.logs if e["i"] > after]
            total_logs = len(self.logs) + self.logs_dropped
            events = [e for e in self.events if e["seq"] > after_event]
            total_events = len(self.events) + self.events_dropped
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
            "events": events,
            "event_total": total_events,
            "events_dropped": self.events_dropped,
            "elapsed_s": round((self.started_at and (self.finished_at or time.time()) - self.started_at) or 0.0, 2),
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "archived": self.archived,
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
MAX_RUNS_KEPT = 60


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
            for rid in sorted(_runs, key=lambda k: _runs[k].created_at):
                if len(_runs) <= MAX_RUNS_KEPT:
                    break
                if _runs[rid].status in ("complete", "failed", "aborted"):
                    del _runs[rid]


def start_run(target: str, preset: str = "balanced", engine: Optional[str] = None) -> AttackRun:
    """Create a run and launch it in a background thread."""
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    selected = engine or ENGINE_MODE
    engines = available_engines()
    if selected not in engines:
        raise ValueError(f"unknown engine '{selected}'")
    if not engines[selected]["available"]:
        reason = engines[selected].get("reason") or "engine is not installed"
        raise ValueError(f"{engines[selected]['name']} unavailable: {reason}")
    run = AttackRun(target, preset, selected)
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
        persist_run(run)
        _thread_ctx.current_run = None


async def _execute(run: AttackRun) -> None:
    run.status = "running"
    run.started_at = time.time()
    run.log("═" * 62, "PHASE")
    run.log(f"  OFFENSIVE EMULATOR · run {run.run_id}", "PHASE")
    run.log(f"  target  : {run.target}", "INFO")
    run.log(f"  profile : {run.preset} · engine: {run.engine.upper()}"
            + ("" if TRACER_INSTALLED or run.engine != "real" else " · tracing unavailable"),
            "INFO")
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

    def on_sim_request(method: str, path: str, status: int, ms: float) -> None:
        if run.cancelled:
            raise AttackAborted()
        run._add_request_event(method, path, status, ms)

    if run.engine == "real" and _HAS_REAL_ENGINES:
        # pre-flight: fail fast with a clear reason when the target is dead
        try:
            info = await preflight_check(run.target)
            run.log(f"✓ Target reachable · HTTP {info['status']} · server: {info['server']}", "OK")
            ch = info.get("challenge")
            if ch:
                run.log(f"⚠ Cloudflare {challenge_label(ch)} on the homepage — the WAF is "
                        f"intercepting this client. Results below will reflect WAF "
                        f"responses, not the application.", "WARN")
        except _PreflightError as exc:
            run.log(f"✗ {exc}", "ERROR")
            raise
        emulator = UnifiedOffensiveEmulator(target_url=run.target, run_id=run.run_id)
        report = await emulator.run_full_attack(on_phase=on_phase)
    else:
        sim = SimulationEngine(run.target, run.run_id, run.preset)
        report = await sim.run(on_phase=on_phase, on_log=on_sim_log, on_request=on_sim_request)

    report = remediation.enrich(report, run.events)

    # Every installed scanner augments the same run and report. Scanner errors
    # are isolated so one unavailable integration never discards core results.
    try:
        def on_scanner_progress(done: int, total: int) -> None:
            run.progress = max(run.progress, 80.0 + (done / max(1, total)) * 19.0)
            run._add_event("scanner_progress", completed=done, total=total)

        scanner_results = scanner_pipeline.run_installed(
            run.target, run.preset, run.run_id, run.log, lambda: run.cancelled,
            on_scanner_progress)
    except InterruptedError as exc:
        raise AttackAborted() from exc
    report = scanner_pipeline.merge(report, scanner_results, run._add_event)
    run.report = report
    run.status = "complete"
    run.progress = 100.0

    # closing summary in the log stream
    summary = report.get("summary", {})
    run.log("═" * 62, "PHASE")
    run.log(f"  MISSION COMPLETE · verdict: {report.get('verdict', '?')}", "OK")
    run.log(f"  severity: {summary.get('severity', '?')} · "
            f"success rate: {summary.get('attack_success_rate', '?')}", "OK")
    defense = report.get("defense", {})
    if defense.get("total_blocks"):
        run.log(f"  defenses engaged: {defense['total_blocks']} blocks "
                f"({', '.join(f'{k}×{v}' for k, v in defense['by_type'].items())})", "WARN")
    waf = report.get("waf")
    if waf:
        run.log(f"  WAF: {waf.get('provider', 'unknown')} — {waf.get('requests_intercepted', 0)} requests "
                f"intercepted (challenge pages, not application responses)", "WARN")
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


# Load archived runs at import time (best effort)
try:
    load_archived_runs()
except Exception:
    pass


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Attack service smoke test")
    ap.add_argument("target")
    ap.add_argument("--preset", default="balanced")
    args = ap.parse_args()
    result = run_cli(args.target, args.preset)
    print(json.dumps({k: v for k, v in result.items() if k not in ("logs", "events")}, indent=2, default=str))
