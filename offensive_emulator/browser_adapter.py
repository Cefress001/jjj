"""Playwright browser-discovery adapter with process isolation and limits."""

from __future__ import annotations

import importlib.util
import json
import os
import queue
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from process_utils import popen_group_options, stop_process_tree

_BASE_DIR = Path(__file__).parent
_WORKER = _BASE_DIR / "browser_worker.py"
_ARTIFACT_ROOT = _BASE_DIR / "data" / "artifacts"


class BrowserUnavailable(RuntimeError):
    pass


class BrowserScanError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def _runtime_ready() -> bool:
    if importlib.util.find_spec("playwright") is None:
        return False
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            return Path(playwright.chromium.executable_path).is_file()
    except Exception:
        return False


def command() -> Optional[List[str]]:
    configured = os.environ.get("BROWSER_COMMAND", "").strip()
    if configured:
        try:
            parsed = shlex.split(configured)
        except ValueError:
            return None
        return parsed or None
    if not _runtime_ready():
        return None
    return [sys.executable, str(_WORKER)]


def availability() -> Dict[str, Any]:
    cmd = command()
    return {
        "available": bool(cmd),
        "command": cmd[0] if cmd else None,
        "description": "Rendered browser discovery for JavaScript applications",
        "reason": None if cmd else (
            "Playwright browser runtime is unavailable; use the full image or install "
            "Playwright and Chromium"
        ),
    }


def run_browser(target: str, preset: str, run_id: str,
                log: Callable[[str, str], None],
                cancelled: Callable[[], bool],
                timeout: Optional[int] = None) -> Dict[str, Any]:
    """Run the worker and remove its private HAR on every failed handoff."""
    try:
        return _run_browser(target, preset, run_id, log, cancelled, timeout)
    except BaseException:
        try:
            (_ARTIFACT_ROOT / run_id / "browser" / ".browser-traffic.har").unlink(
                missing_ok=True)
        except OSError:
            pass
        raise


def _run_browser(target: str, preset: str, run_id: str,
                 log: Callable[[str, str], None],
                 cancelled: Callable[[], bool],
                 timeout: Optional[int] = None) -> Dict[str, Any]:
    cmd = command()
    if not cmd:
        raise BrowserUnavailable(availability()["reason"])
    timeout = timeout or {
        "stealth": 120, "balanced": 240, "aggressive": 420, "maximum": 600,
    }.get(preset, 240)
    artifact_dir = _ARTIFACT_ROOT / run_id / "browser"
    screenshots = os.environ.get("BROWSER_SCREENSHOTS", "1").strip().lower() not in {
        "0", "false", "no", "off",
    }
    har_path = artifact_dir / ".browser-traffic.har"
    config = {
        "target": target,
        "preset": preset,
        "artifact_dir": str(artifact_dir),
        "har_path": str(har_path),
        "screenshots": screenshots,
    }
    started = time.time()
    with tempfile.TemporaryDirectory(prefix="oe-browser-") as tmp:
        config_path = Path(tmp) / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        try:
            process = subprocess.Popen(
                cmd + [str(config_path)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
                **popen_group_options(),
            )
        except OSError as exc:
            raise BrowserUnavailable(f"Could not start browser worker: {exc}") from exc

        stdout: "queue.Queue[Optional[str]]" = queue.Queue(maxsize=64)
        stderr: "queue.Queue[Optional[str]]" = queue.Queue(maxsize=64)

        def chunk_reader(stream, destination) -> None:
            try:
                if stream:
                    while True:
                        chunk = stream.read(64 * 1024)
                        if not chunk:
                            break
                        destination.put(chunk)
            finally:
                destination.put(None)

        threading.Thread(
            target=chunk_reader, args=(process.stdout, stdout), daemon=True).start()
        threading.Thread(
            target=chunk_reader, args=(process.stderr, stderr), daemon=True).start()
        out_done = err_done = False
        output: List[str] = []
        output_size = 0
        error_text = ""
        error_tail: List[str] = []
        try:
            while True:
                if cancelled():
                    stop_process_tree(process)
                    raise InterruptedError("browser discovery cancelled")
                if time.time() - started > timeout:
                    stop_process_tree(process)
                    raise BrowserScanError(
                        f"browser discovery exceeded the {timeout}s time limit")
                try:
                    line = stdout.get(timeout=0.05)
                    if line is None:
                        out_done = True
                    else:
                        output_size += len(line.encode("utf-8"))
                        if output_size > 16 * 1024 * 1024:
                            stop_process_tree(process)
                            raise BrowserScanError(
                                "browser result exceeded the 16 MB safety limit")
                        output.append(line)
                except queue.Empty:
                    pass
                while True:
                    try:
                        line = stderr.get_nowait()
                    except queue.Empty:
                        break
                    if line is None:
                        err_done = True
                        break
                    error_text = (error_text + line)[-16 * 1024:]
                    error_tail = [part.strip() for part in error_text.splitlines()[-12:]
                                  if part.strip()]
                    if error_tail:
                        log("browser · " + error_tail[-1][:500], "INFO")
                if process.poll() is not None and out_done and err_done:
                    break
        finally:
            if process.poll() is None:
                stop_process_tree(process, grace_seconds=2)

    if process.returncode != 0:
        raise BrowserScanError(
            f"browser worker exited with {process.returncode}: {' | '.join(error_tail[-4:])}")
    payload = "".join(output).strip()
    if not payload:
        raise BrowserScanError("browser worker completed without a JSON result")
    try:
        result = json.loads(payload)
    except (TypeError, json.JSONDecodeError) as exc:
        raise BrowserScanError(f"browser worker produced invalid JSON: {exc}") from exc
    if not isinstance(result, dict):
        raise BrowserScanError("browser worker result was not an object")

    # Never expose host filesystem roots in persisted reports.
    safe_screenshots = []
    for value in result.get("screenshots", []) or []:
        try:
            relative = Path(value).resolve().relative_to(_BASE_DIR.resolve())
            safe_screenshots.append(str(relative))
        except (OSError, ValueError):
            continue
    result["screenshots"] = safe_screenshots
    if har_path.is_file() and har_path.stat().st_size <= 32 * 1024 * 1024:
        result["_har_path"] = str(har_path)
        result["har_size_bytes"] = har_path.stat().st_size
    elif har_path.exists():
        har_path.unlink()
        result["har_discarded"] = "size_limit"
    result["duration_seconds"] = round(time.time() - started, 2)
    return result
