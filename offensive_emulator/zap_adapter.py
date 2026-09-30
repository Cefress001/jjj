"""OWASP ZAP baseline-scan adapter.

The app deliberately integrates ZAP as an external process rather than
vendoring it. Configure either:

* ``ZAP_BASELINE_COMMAND`` - command used to launch ``zap-baseline.py``; or
* put ``zap-baseline.py`` on PATH.

The command is invoked with ``-t <target> -J <report-file>``. A command may
contain fixed arguments, for example ``/opt/zap/zap-baseline.py -m 2``.
ZAP exit codes 1 and 2 mean findings were reported and are therefore treated
as successful scans; exit code 3 is an operational failure.
"""

from __future__ import annotations

import json
import os
import queue
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from process_utils import popen_group_options, stop_process_tree


class ZapUnavailable(RuntimeError):
    """Raised when no ZAP baseline executable is configured."""


class ZapScanError(RuntimeError):
    """Raised when ZAP cannot complete a scan."""


def command() -> Optional[List[str]]:
    configured = os.environ.get("ZAP_BASELINE_COMMAND", "").strip()
    if configured:
        try:
            parsed = shlex.split(configured)
        except ValueError:
            return None
        return parsed or None
    executable = shutil.which("zap-baseline.py")
    return [executable] if executable else None


def availability() -> Dict[str, Any]:
    cmd = command()
    return {
        "available": bool(cmd),
        "command": cmd[0] if cmd else None,
        "reason": None if cmd else (
            "Install OWASP ZAP and put zap-baseline.py on PATH, or set "
            "ZAP_BASELINE_COMMAND."
        ),
    }


def _risk(alert: Dict[str, Any]) -> str:
    value = str(alert.get("risk") or alert.get("riskdesc") or "Informational")
    value = value.split(" ", 1)[0].strip().lower()
    return {
        "high": "High", "medium": "Medium", "low": "Low",
        "informational": "Informational", "info": "Informational",
    }.get(value, "Informational")


def _confidence(alert: Dict[str, Any]) -> str:
    value = str(alert.get("confidence") or alert.get("confidencedesc") or "").strip()
    return value.split(" ", 1)[0] or "Unknown"


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _instances(alert: Dict[str, Any]) -> List[Dict[str, Any]]:
    instances = alert.get("instances")
    if isinstance(instances, list):
        return [x for x in instances if isinstance(x, dict)][:500]
    # Older ZAP JSON formats put the instance fields directly on the alert.
    return [{k: alert.get(k) for k in ("uri", "url", "method", "param", "evidence", "attack")
             if alert.get(k) not in (None, "")}]


def extract_alerts(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize both packaged-report and API-style ZAP JSON formats."""
    raw: List[Dict[str, Any]] = []
    if isinstance(payload.get("alerts"), list):
        raw.extend(x for x in payload["alerts"] if isinstance(x, dict))
    for site in payload.get("site", []) if isinstance(payload.get("site"), list) else []:
        if isinstance(site, dict) and isinstance(site.get("alerts"), list):
            raw.extend(x for x in site["alerts"] if isinstance(x, dict))

    findings: List[Dict[str, Any]] = []
    for alert in raw[:10000]:
        instances = _instances(alert)
        urls = []
        for instance in instances:
            url = instance.get("uri") or instance.get("url")
            if url and url not in urls:
                urls.append(str(url))
        findings.append({
            "id": str(alert.get("pluginid") or alert.get("alertRef") or alert.get("id") or "zap-alert"),
            "name": str(alert.get("alert") or alert.get("name") or "ZAP alert"),
            "severity": _risk(alert),
            "confidence": _confidence(alert),
            "description": str(alert.get("desc") or alert.get("description") or ""),
            "solution": str(alert.get("solution") or ""),
            "reference": str(alert.get("reference") or ""),
            "cwe_id": _safe_int(alert.get("cweid")),
            "wasc_id": _safe_int(alert.get("wascid")),
            "urls": urls,
            "instances": instances,
            "source": "OWASP ZAP",
        })
    return findings


def build_report(target: str, run_id: str, payload: Dict[str, Any],
                 elapsed: float) -> Dict[str, Any]:
    findings = extract_alerts(payload)
    rank = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
    highest = max((rank.get(f["severity"], 0) for f in findings), default=0)
    severity = {0: "Low", 1: "Low", 2: "Medium", 3: "High"}[highest]
    counts = {key: 0 for key in ("High", "Medium", "Low", "Informational")}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1

    urls: List[str] = []
    for finding in findings:
        for url in finding.get("urls", []):
            if url not in urls:
                urls.append(url)

    key_findings = [
        f"{f['severity']}: {f['name']}" + (f" — {f['urls'][0]}" if f["urls"] else "")
        for f in sorted(findings, key=lambda x: rank.get(x["severity"], 0), reverse=True)[:12]
    ]
    if not key_findings:
        key_findings = [
            "ZAP baseline found no alerts. This passive-oriented scan does not prove the target is secure."
        ]

    recommendations = []
    seen = set()
    priority = {"High": "critical", "Medium": "high", "Low": "medium",
                "Informational": "low"}
    for finding in sorted(findings, key=lambda x: rank.get(x["severity"], 0), reverse=True):
        key = (finding["name"], finding["solution"])
        if key in seen:
            continue
        seen.add(key)
        recommendations.append({
            "area": "ZAP" + (f" / CWE-{finding['cwe_id']}" if finding["cwe_id"] else ""),
            "priority": priority[finding["severity"]],
            "title": finding["name"],
            "fix": finding["solution"] or "Review the evidence, confirm the finding, and apply the relevant secure configuration guidance.",
        })
        if len(recommendations) >= 12:
            break
    if not recommendations:
        recommendations.append({
            "area": "Verification", "priority": "low",
            "title": "No baseline alerts were returned",
            "fix": "Retest authenticated areas and APIs, and use a separately authorized active scan where appropriate.",
        })

    # Keep the established report shape so archived comparisons and the current
    # UI continue to work. A baseline alert is not represented as a successful
    # exploit: discovery completed, while intrusive kill-chain phases did not run.
    return {
        "run_id": run_id,
        "target": target,
        "timestamp": time.time(),
        "engine": "zap-baseline",
        "scan_type": "baseline",
        "total_time_seconds": round(elapsed, 2),
        "verdict": (f"ZAP BASELINE — {len(findings)} alert(s), highest risk {severity}"
                    if findings else "ZAP BASELINE — no alerts found"),
        "summary": {
            "severity": severity,
            "attack_success_rate": "0%",
            "alerts_total": len(findings),
            "alerts_by_risk": counts,
            "key_findings": key_findings,
        },
        "findings": findings,
        "recommendations": recommendations,
        "attack_chain": {
            "phase_1_recon": True,
            "phase_2_exploit": False,
            "phase_3_persistence": False,
            "phase_4_lateral_movement": False,
            "phase_5_exfiltration": False,
            "phase_6_cover_tracks": False,
        },
        "phase_timings": {"recon": round(elapsed, 2)},
        "recon_results": {
            "endpoints_discovered": len(urls), "endpoints": urls,
            "hidden_routes": [], "tech_stack": {},
        },
        "exploit_results": {"access_granted": False, "exploits_successful": 0, "methods": []},
        "persistence_results": {"backdoors_installed": 0, "backdoors": []},
        "lateral_movement_results": {"credentials_extracted": 0, "credentials": []},
        "exfiltration_results": {"records_stolen": 0, "data_exfiltrated_mb": 0.0,
                                  "extraction_methods": []},
        "cover_tracks_results": {"logs_deleted": 0},
        "defense": {"total_blocks": 0, "by_type": {}},
    }


def run_baseline(target: str, run_id: str,
                 log: Callable[[str, str], None],
                 cancelled: Callable[[], bool],
                 timeout: int = 900) -> Dict[str, Any]:
    cmd = command()
    if not cmd:
        raise ZapUnavailable(availability()["reason"])

    started = time.time()
    with tempfile.TemporaryDirectory(prefix="offensive-emulator-zap-") as tmp:
        report_path = Path(tmp) / "zap-report.json"
        full_cmd = cmd + ["-t", target, "-J", str(report_path), "-I"]
        log("Starting OWASP ZAP baseline scan (crawl + passive analysis)", "PHASE")
        log("ZAP baseline does not run the active scanner, but its crawler sends requests.", "WARN")
        try:
            process = subprocess.Popen(
                full_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
                **popen_group_options(),
            )
        except OSError as exc:
            raise ZapUnavailable(f"Could not start OWASP ZAP: {exc}") from exc

        output: List[str] = []
        lines: "queue.Queue[Optional[str]]" = queue.Queue()

        def read_output() -> None:
            try:
                if process.stdout:
                    for item in process.stdout:
                        lines.put(item)
            finally:
                lines.put(None)

        threading.Thread(target=read_output, daemon=True).start()
        reader_done = False
        try:
            while True:
                if cancelled():
                    stop_process_tree(process, grace_seconds=5)
                    raise InterruptedError("ZAP scan cancelled")
                if time.time() - started > timeout:
                    stop_process_tree(process, grace_seconds=5)
                    raise ZapScanError(f"ZAP baseline exceeded the {timeout}s time limit")
                try:
                    line = lines.get(timeout=0.1)
                    if line is None:
                        reader_done = True
                    else:
                        clean = line.rstrip()
                        output.append(clean)
                        if len(output) > 200:
                            del output[:-200]
                        if clean:
                            log("ZAP · " + clean[:500], "INFO")
                except queue.Empty:
                    pass
                if process.poll() is not None and reader_done:
                    break
        finally:
            if process.poll() is None:
                stop_process_tree(process, grace_seconds=2)

        if process.returncode not in (0, 1, 2):
            tail = " | ".join(output[-4:])
            raise ZapScanError(f"ZAP baseline failed with exit code {process.returncode}: {tail}")
        if not report_path.is_file():
            raise ZapScanError("ZAP completed without producing its JSON report")
        if report_path.stat().st_size > 64 * 1024 * 1024:
            raise ZapScanError("ZAP JSON report exceeded the 64 MB safety limit")
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            raise ZapScanError(f"ZAP produced an invalid JSON report: {exc}") from exc

    report = build_report(target, run_id, payload, time.time() - started)
    counts = report["summary"]["alerts_by_risk"]
    log("ZAP findings · " + " · ".join(f"{k} {v}" for k, v in counts.items()), "OK")
    return report
