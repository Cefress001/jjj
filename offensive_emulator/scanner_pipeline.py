"""Automatic multi-tool website assessment pipeline.

External scanners augment the existing workflow; they are not user-selectable
replacement engines. Every installed tool runs for every scan, failures are
isolated, and all findings are normalized into the existing report.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List

import pd_adapter
import zap_adapter


def availability() -> Dict[str, Dict[str, Any]]:
    zap = zap_adapter.availability()
    return {
        "httpx": pd_adapter.availability()["httpx"],
        "katana": pd_adapter.availability()["katana"],
        "zap": {
            "available": zap["available"], "command": zap.get("command"),
            "description": "Web crawling and passive security analysis",
            "reason": zap.get("reason"),
        },
        "nuclei": pd_adapter.availability()["nuclei"],
    }


def _run_tool(name: str, function: Callable[[], Dict[str, Any]],
              log: Callable[[str, str], None]) -> Dict[str, Any]:
    started = time.time()
    log(f"━━ ADD-ON · {name.upper()} — engaged", "PHASE")
    try:
        data = function()
        result = {"status": "complete", "duration_seconds": round(time.time() - started, 2)}
        result.update(data)
        log(f"✓ {name} completed in {result['duration_seconds']:.1f}s", "OK")
        return result
    except InterruptedError:
        raise
    except Exception as exc:
        log(f"⚠ {name} could not complete: {exc}", "WARN")
        return {"status": "failed", "duration_seconds": round(time.time() - started, 2),
                "error": str(exc)}


def run_installed(target: str, preset: str, run_id: str,
                  log: Callable[[str, str], None],
                  cancelled: Callable[[], bool],
                  progress: Callable[[int, int], None]) -> Dict[str, Dict[str, Any]]:
    """Run every installed supplemental scanner in a conservative sequence."""
    installed = availability()
    results: Dict[str, Dict[str, Any]] = {}

    if not any(v["available"] for v in installed.values()):
        log("Supplemental scanners are not installed; continuing with the built-in engine.", "INFO")
        progress(4, 4)
        return {name: {"status": "unavailable", "reason": info.get("reason")}
                for name, info in installed.items()}

    log("═" * 62, "PHASE")
    log("  AUTOMATIC WEB ASSESSMENT · installed tools will run", "PHASE")
    log("  policy: bounded rates · intrusive/DoS/fuzz Nuclei templates excluded", "INFO")
    log("═" * 62, "PHASE")

    if installed["httpx"]["available"]:
        results["httpx"] = _run_tool(
            "httpx", lambda: pd_adapter.run_httpx(target, preset, log, cancelled), log)
    else:
        results["httpx"] = {"status": "unavailable", "reason": installed["httpx"].get("reason")}
    progress(1, 4)
    if cancelled():
        raise InterruptedError("scan cancelled")

    if installed["katana"]["available"]:
        results["katana"] = _run_tool(
            "katana", lambda: pd_adapter.run_katana(target, preset, log, cancelled), log)
    else:
        results["katana"] = {"status": "unavailable", "reason": installed["katana"].get("reason")}
    progress(2, 4)
    if cancelled():
        raise InterruptedError("scan cancelled")

    if installed["zap"]["available"]:
        def zap_run() -> Dict[str, Any]:
            report = zap_adapter.run_baseline(target, run_id, log, cancelled)
            return {
                "alerts_total": report.get("summary", {}).get("alerts_total", 0),
                "findings": report.get("findings", []),
                "endpoints": report.get("recon_results", {}).get("endpoints", []),
            }
        results["zap"] = _run_tool("OWASP ZAP", zap_run, log)
    else:
        results["zap"] = {"status": "unavailable", "reason": installed["zap"].get("reason")}
    progress(3, 4)
    if cancelled():
        raise InterruptedError("scan cancelled")

    if installed["nuclei"]["available"]:
        results["nuclei"] = _run_tool(
            "nuclei", lambda: pd_adapter.run_nuclei(target, preset, log, cancelled), log)
    else:
        results["nuclei"] = {"status": "unavailable", "reason": installed["nuclei"].get("reason")}
    progress(4, 4)

    return results


def _severity_rank(value: str) -> int:
    return {"informational": 0, "info": 0, "low": 1, "medium": 2,
            "high": 3, "critical": 4}.get(str(value).lower(), 0)


def merge(report: Dict[str, Any], results: Dict[str, Dict[str, Any]],
          add_event: Callable[..., None]) -> Dict[str, Any]:
    """Merge all scanner output into the existing report without changing its API."""
    report = dict(report)
    report["scanner_results"] = results
    report["tools_run"] = [name for name, data in results.items()
                           if data.get("status") == "complete"]

    findings = list(report.get("findings") or [])
    for name in ("zap", "nuclei"):
        for finding in results.get(name, {}).get("findings", []) or []:
            findings.append(finding)
            add_event("finding", source=finding.get("source", name),
                      severity=finding.get("severity"), name=finding.get("name"),
                      urls=(finding.get("urls") or [])[:3])
    # Stable deduplication across scanners by source/id/first URL.
    unique = []
    seen = set()
    for finding in findings:
        urls = finding.get("urls") or []
        key = (finding.get("source"), finding.get("id"), urls[0] if urls else "")
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    report["findings"] = unique

    recon = dict(report.get("recon_results") or {})
    endpoints = list(recon.get("endpoints") or [])
    additions = []
    additions.extend(results.get("httpx", {}).get("assets", []) or [])
    additions.extend(results.get("katana", {}).get("endpoints", []) or [])
    additions.extend(results.get("zap", {}).get("endpoints", []) or [])
    for endpoint in additions:
        if endpoint not in endpoints:
            endpoints.append(endpoint)
    recon["endpoints"] = endpoints[:3000]
    recon["endpoints_discovered"] = len(recon["endpoints"])
    tech = dict(recon.get("tech_stack") or {})
    technologies = results.get("httpx", {}).get("technologies", []) or []
    if technologies:
        tech["httpx"] = ", ".join(technologies[:30])
    recon["tech_stack"] = tech
    report["recon_results"] = recon

    summary = dict(report.get("summary") or {})
    current_severity = str(summary.get("severity") or "Low")
    highest = max([current_severity] + [str(f.get("severity") or "Low") for f in unique],
                  key=_severity_rank)
    summary["severity"] = highest.capitalize() if highest.lower() != "informational" else "Low"
    summary["scanner_findings"] = len(unique)
    summary["tools_completed"] = [name for name, data in results.items()
                                  if data.get("status") == "complete"]
    summary["tools_failed"] = [name for name, data in results.items()
                               if data.get("status") == "failed"]
    by_risk = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for finding in unique:
        severity = str(finding.get("severity") or "Informational").capitalize()
        if severity == "Info":
            severity = "Informational"
        by_risk[severity] = by_risk.get(severity, 0) + 1
    summary["scanner_findings_by_risk"] = by_risk
    keys = list(summary.get("key_findings") or [])
    for finding in sorted(unique, key=lambda f: _severity_rank(f.get("severity", "")), reverse=True):
        text = f"{finding.get('source', 'Scanner')} {finding.get('severity', 'Info')}: {finding.get('name', 'Finding')}"
        if text not in keys:
            keys.append(text)
        if len(keys) >= 16:
            break
    summary["key_findings"] = keys
    report["summary"] = summary

    recommendations = list(report.get("recommendations") or [])
    rec_keys = {(r.get("title"), r.get("fix")) for r in recommendations}
    priority = {"critical": "critical", "high": "high", "medium": "high",
                "low": "medium", "informational": "low", "info": "low"}
    for finding in sorted(unique, key=lambda f: _severity_rank(f.get("severity", "")), reverse=True):
        fix = finding.get("solution") or "Validate the scanner evidence and apply the relevant vendor or secure-configuration guidance."
        key = (finding.get("name"), fix)
        if key in rec_keys:
            continue
        rec_keys.add(key)
        recommendations.append({
            "area": finding.get("source", "Scanner"),
            "priority": priority.get(str(finding.get("severity", "low")).lower(), "medium"),
            "title": finding.get("name", "Scanner finding"), "fix": fix,
        })
        if len(recommendations) >= 16:
            break
    report["recommendations"] = recommendations
    return report
