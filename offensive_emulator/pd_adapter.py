"""Adapters for ProjectDiscovery's httpx, Katana, and Nuclei CLIs.

The tools remain independent executables, but their JSON/JSONL output is
normalized here so the application can run them as one scan pipeline. Commands
are never passed through a shell. Environment overrides are useful for custom
install locations and tests:

    HTTPX_COMMAND=/opt/pd/httpx
    KATANA_COMMAND=/opt/pd/katana
    NUCLEI_COMMAND=/opt/pd/nuclei
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
from typing import Any, Callable, Dict, List, Optional, Union


class ToolError(RuntimeError):
    pass


def _command(name: str) -> Optional[List[str]]:
    configured = os.environ.get(name.upper() + "_COMMAND", "").strip()
    if configured:
        return shlex.split(configured)
    executable = shutil.which(name)
    return [executable] if executable else None


def availability() -> Dict[str, Dict[str, Any]]:
    descriptions = {
        "httpx": "HTTP reachability, metadata and technology profiling",
        "katana": "Web crawling and endpoint discovery",
        "nuclei": "Template-based vulnerability and exposure detection",
    }
    result = {}
    for name, description in descriptions.items():
        cmd = _command(name)
        result[name] = {
            "available": bool(cmd), "command": cmd[0] if cmd else None,
            "description": description,
            "reason": None if cmd else f"{name} is not installed or on PATH",
        }
    return result


def _run_jsonl(name: str, args: List[str], log: Callable[[str, str], None],
               cancelled: Callable[[], bool], timeout: int) -> List[Dict[str, Any]]:
    cmd = _command(name)
    if not cmd:
        raise ToolError(f"{name} is not installed")
    started = time.time()
    process = subprocess.Popen(
        cmd + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, bufsize=1,
    )
    stdout: "queue.Queue[Optional[str]]" = queue.Queue()
    stderr: "queue.Queue[Optional[str]]" = queue.Queue()

    def reader(stream, destination) -> None:
        if stream:
            for line in stream:
                destination.put(line)
        destination.put(None)

    threading.Thread(target=reader, args=(process.stdout, stdout), daemon=True).start()
    threading.Thread(target=reader, args=(process.stderr, stderr), daemon=True).start()
    records: List[Dict[str, Any]] = []
    out_done = err_done = False
    error_tail: List[str] = []
    try:
        while True:
            if cancelled():
                process.terminate()
                try:
                    process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    process.kill()
                raise InterruptedError(f"{name} scan cancelled")
            if time.time() - started > timeout:
                process.kill()
                raise ToolError(f"{name} exceeded the {timeout}s time limit")
            try:
                line = stdout.get(timeout=0.05)
                if line is None:
                    out_done = True
                else:
                    text = line.strip()
                    if text:
                        try:
                            item = json.loads(text)
                            if isinstance(item, dict):
                                records.append(item)
                        except json.JSONDecodeError:
                            log(f"{name} · {text[:400]}", "INFO")
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
                text = line.strip()
                if text:
                    error_tail.append(text)
                    error_tail = error_tail[-8:]
                    log(f"{name} · {text[:400]}", "INFO")
            if process.poll() is not None and out_done and err_done:
                break
    finally:
        if process.poll() is None:
            process.kill()
    if process.returncode != 0:
        raise ToolError(f"{name} exited with {process.returncode}: {' | '.join(error_tail[-3:])}")
    return records


def run_httpx(target: str, preset: str, log: Callable[[str, str], None],
              cancelled: Callable[[], bool]) -> Dict[str, Any]:
    rate = {"stealth": "2", "balanced": "5", "aggressive": "10", "maximum": "20"}.get(preset, "5")
    records = _run_jsonl(
        "httpx", ["-u", target, "-json", "-silent", "-tech-detect", "-title",
                  "-status-code", "-content-type", "-follow-redirects", "-rl", rate],
        log, cancelled, 120,
    )
    assets = []
    technologies = []
    canonical_target = target
    for item in records:
        url = item.get("final_url") or item.get("final-url") or item.get("url") or item.get("input")
        if url and url not in assets:
            assets.append(str(url))
        if url and canonical_target == target:
            canonical_target = str(url)
        for tech in item.get("tech", []) or item.get("technologies", []) or []:
            if str(tech) not in technologies:
                technologies.append(str(tech))
    return {"records": records, "assets": assets, "technologies": technologies,
            "canonical_target": canonical_target}


def run_katana(target: str, preset: str, log: Callable[[str, str], None],
               cancelled: Callable[[], bool]) -> Dict[str, Any]:
    rate = {"stealth": "2", "balanced": "5", "aggressive": "10", "maximum": "20"}.get(preset, "5")
    depth = "2" if preset in ("stealth", "balanced") else "3"
    records = _run_jsonl(
        "katana", ["-u", target, "-jsonl", "-silent", "-d", depth,
                   "-rl", rate, "-c", "2", "-p", "2", "-fs", "fqdn"],
        log, cancelled, 300,
    )
    endpoints = []
    endpoint_records = []
    for item in records:
        request = item.get("request") if isinstance(item.get("request"), dict) else {}
        response = item.get("response") if isinstance(item.get("response"), dict) else {}
        url = request.get("endpoint") or item.get("url") or item.get("endpoint")
        if url and url not in endpoints:
            endpoints.append(str(url))
            endpoint_records.append({
                "url": str(url),
                "method": str(request.get("method") or item.get("method") or "GET").upper(),
                "status": response.get("status_code") or response.get("status-code") or item.get("status_code"),
                "content_type": response.get("content_type") or response.get("content-type"),
            })
    return {"records_count": len(records), "endpoints": endpoints[:2000],
            "endpoint_records": endpoint_records[:2000]}


def _nuclei_finding(item: Dict[str, Any]) -> Dict[str, Any]:
    info = item.get("info") if isinstance(item.get("info"), dict) else {}
    classification = info.get("classification") if isinstance(info.get("classification"), dict) else {}
    severity = str(info.get("severity") or item.get("severity") or "info").capitalize()
    if severity == "Info":
        severity = "Informational"
    url = item.get("matched-at") or item.get("host") or item.get("url")
    cwes = classification.get("cwe-id") or []
    if isinstance(cwes, str):
        cwes = [cwes]
    cves = classification.get("cve-id") or []
    if isinstance(cves, str):
        cves = [cves]
    return {
        "id": str(item.get("template-id") or item.get("templateID") or "nuclei-finding"),
        "name": str(info.get("name") or item.get("template-id") or "Nuclei finding"),
        "severity": severity,
        "confidence": "Template match",
        "description": str(info.get("description") or ""),
        "solution": str(info.get("remediation") or ""),
        "reference": info.get("reference") or [],
        "cwe_ids": cwes,
        "cve_ids": cves,
        "urls": [str(url)] if url else [],
        "matcher": item.get("matcher-name"),
        "source": "Nuclei",
    }


def run_nuclei(targets: Union[str, List[str]], preset: str,
               log: Callable[[str, str], None],
               cancelled: Callable[[], bool]) -> Dict[str, Any]:
    """Run Nuclei against a bounded endpoint list produced by the corpus."""
    values = [targets] if isinstance(targets, str) else list(targets)
    values = [str(value).strip() for value in values if str(value).strip()]
    if not values:
        raise ToolError("nuclei received no in-scope targets")
    rate = {"stealth": "2", "balanced": "5", "aggressive": "10", "maximum": "20"}.get(preset, "5")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", prefix="oe-nuclei-",
                                     suffix=".txt") as target_file:
        target_file.write("\n".join(values) + "\n")
        target_file.flush()
        records = _run_jsonl(
            "nuclei", ["-l", target_file.name, "-jsonl", "-silent", "-rl", rate,
                       "-c", "2", "-bs", "1", "-timeout", "8", "-retries", "1",
                       "-etags", "dos,fuzz,intrusive", "-severity",
                       "info,low,medium,high,critical"],
            log, cancelled, 600,
        )
    return {"records_count": len(records), "targets_scanned": len(values),
            "findings": [_nuclei_finding(x) for x in records]}
