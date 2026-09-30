"""
Offensive Emulator — Unified App Server
========================================
ONE server for the whole platform (stdlib only, zero dependencies):

  • Landing page + 3D console        (static files)
  • Attack control API               (start / status / logs / report / cancel)
  • Built-in demo target "VulnPay"   (/demo/*)

Run with:  python run.py          (from the repository root)
"""

import json
import mimetypes
import re
import socketserver
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, unquote, urlparse

_BASE_DIR = Path(__file__).parent
_STATIC_DIR = _BASE_DIR / "static"

sys.path.insert(0, str(_BASE_DIR))

import attack_service  # noqa: E402
from attack_service import PRESETS, PHASES, list_runs, get_run, start_run  # noqa: E402
import demo_target  # noqa: E402
import remediation  # noqa: E402

VERSION = "4.1"

_MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".map": "application/json",
    ".txt": "text/plain; charset=utf-8",
}


class AppHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "OffensiveEmulator/" + VERSION

    # ------------------------------------------------------------- plumbing

    def log_message(self, fmt, *args):  # silence default request logging
        pass

    def _send(self, status: int, body: bytes, ctype: str = "application/json",
              extra_headers: Optional[Dict[str, str]] = None) -> None:
        self.send_response_only(status)
        self.send_header("Date", self.date_time_string())
        self.send_header("Server", "OffensiveEmulator/" + VERSION)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)   # extras may override the defaults above
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _json(self, obj, status: int = 200) -> None:
        self._send(status, json.dumps(obj, default=str).encode("utf-8"))

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return b""
        return self.rfile.read(min(length, 10 * 1024 * 1024))

    def _serve_static(self, rel: str) -> None:
        # path traversal guard
        safe = (_STATIC_DIR / rel).resolve()
        try:
            safe.relative_to(_STATIC_DIR.resolve())
        except ValueError:
            self._json({"error": "forbidden"}, 403)
            return
        if not safe.is_file():
            self._json({"error": "not found", "path": rel}, 404)
            return
        ctype = _MIME.get(safe.suffix.lower(), "application/octet-stream")
        body = safe.read_bytes()
        self._send(200, body, ctype, {"Cache-Control": "public, max-age=300"})

    # ------------------------------------------------------------- routing

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_DELETE(self):
        self._route("DELETE")

    def do_PATCH(self):
        self._route("PATCH")

    def do_PUT(self):
        self._route("PUT")

    def do_HEAD(self):
        self._route("GET")

    def _route(self, method: str) -> None:
        try:
            parsed = urlparse(self.path)
            path = unquote(parsed.path)
            query = parse_qs(parsed.query)

            # ---- demo target ------------------------------------------------
            if path == "/demo" or path.startswith("/demo/"):
                body = self._read_body() if method in ("POST", "PUT", "PATCH") else b""
                status, ctype, payload, headers = demo_target.handle_demo_request(
                    method, path, query, body)
                self._send(status, payload.encode("utf-8"), ctype, headers)
                return

            # ---- API ---------------------------------------------------------
            if path.startswith("/api/"):
                self._route_api(method, path, query)
                return

            # ---- static app ---------------------------------------------------
            if path in ("/", "/index.html", "/app", "/console"):
                self._serve_static("index.html")
                return
            if path == "/favicon.svg":
                self._serve_static("favicon.svg")
                return
            if path.startswith("/static/"):
                self._serve_static(path[len("/static/"):])
                return
            if path == "/robots.txt":
                self._send(200, b"User-agent: *\nDisallow: /\n", "text/plain")
                return

            self._json({"error": "not found", "path": path}, 404)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # keep the server alive no matter what
            try:
                self._json({"error": f"internal error: {exc}"}, 500)
            except Exception:
                pass

    # ------------------------------------------------------------- api impl

    def _route_api(self, method: str, path: str, query: Dict[str, List[str]]) -> None:
        port = self.server.server_address[1]

        if path == "/api/health" and method == "GET":
            self._json({
                "status": "ok",
                "app": "Offensive Emulator",
                "version": VERSION,
                "engine": attack_service.ENGINE_MODE,
                "real_engines_available": attack_service._HAS_REAL_ENGINES,
                "scanners": attack_service.scanner_pipeline.availability(),
                "demo_target_url": f"http://127.0.0.1:{port}/demo",
                "time": time.time(),
            })
            return

        if path == "/api/configs" and method == "GET":
            self._json({
                "version": VERSION,
                "engine": attack_service.ENGINE_MODE,
                "scanners": attack_service.scanner_pipeline.availability(),
                "phases": PHASES,
                "presets": PRESETS,
                "mitre": remediation.MITRE,
                "demo_targets": {
                    "easy": f"http://127.0.0.1:{port}/demo",
                    "hardened": f"http://127.0.0.1:{port}/demo/hardened",
                    "fortified": f"http://127.0.0.1:{port}/demo/fortified",
                },
                "demo_target_url": f"http://127.0.0.1:{port}/demo",
            })
            return

        if path == "/api/demo/stats" and method == "GET":
            self._json(demo_target.get_telemetry())
            return

        if path == "/api/attack/start" and method == "POST":
            body = self._read_body()
            try:
                data = json.loads(body.decode("utf-8") or "{}")
            except Exception:
                self._json({"error": "invalid JSON body"}, 400)
                return
            target = str(data.get("target") or "").strip()
            preset = str(data.get("preset") or "balanced").strip()
            if not target:
                self._json({"error": "target is required"}, 400)
                return
            if preset not in PRESETS:
                self._json({"error": f"unknown preset '{preset}'"}, 400)
                return
            run = start_run(target, preset)
            self._json(run.snapshot(), 201)
            return

        if path == "/api/attack/list" and method == "GET":
            self._json({"runs": list_runs()})
            return

        m = re.match(r"^/api/attack/([A-Za-z0-9_-]+)/(status|report|cancel|report\.html|report\.json)$", path)
        if m:
            run_id, action = m.group(1), m.group(2)
            run = get_run(run_id)
            if run is None:
                self._json({"error": "run not found"}, 404)
                return

            if action == "status":
                after = int((query.get("after") or ["-1"])[0])
                after_event = int((query.get("after_event") or ["-1"])[0])
                include_report = (query.get("report") or ["0"])[0] in ("1", "true")
                self._json(run.snapshot(after=after, after_event=after_event,
                                        include_report=include_report))
                return

            if action == "cancel" and method == "POST":
                ok = run.cancel()
                self._json({"run_id": run_id, "cancel_requested": ok, "status": run.status})
                return

            if run.report is None:
                self._json({"error": "report not ready", "status": run.status}, 202)
                return

            if action == "report":
                self._json(run.report)
                return
            if action == "report.json":
                body = json.dumps(run.report, indent=2, default=str).encode("utf-8")
                self._send(200, body, "application/json",
                           {"Content-Disposition": f'attachment; filename="threat_report_{run_id}.json"'})
                return
            if action == "report.html":
                print_mode = (query.get("print") or ["0"])[0] in ("1", "true")
                html = render_report_html(run.report, print_mode=print_mode).encode("utf-8")
                self._send(200, html, "text/html; charset=utf-8",
                           {"Content-Disposition": f'attachment; filename="threat_report_{run_id}.html"'})
                return

        self._json({"error": "not found", "path": path}, 404)


# ---------------------------------------------------------------------------
# Standalone HTML report
# ---------------------------------------------------------------------------

def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def render_report_html(report: Dict, print_mode: bool = False) -> str:
    chain = report.get("attack_chain", {})
    summ = report.get("summary", {})
    sev = summ.get("severity", "Low")
    sev_color = {"Critical": "#f43f5e", "High": "#fb7185", "Medium": "#fbbf24", "Low": "#34d399"}.get(sev, "#34d399")

    phase_labels = {
        "phase_1_recon": ("Reconnaissance", "recon"), "phase_2_exploit": ("Exploitation", "exploit"),
        "phase_3_persistence": ("Persistence", "persistence"), "phase_4_lateral_movement": ("Lateral Movement", "lateral_movement"),
        "phase_5_exfiltration": ("Exfiltration", "exfiltration"), "phase_6_cover_tracks": ("Cover Tracks", "cover_tracks"),
    }
    mitre = report.get("mitre", {})
    is_zap = report.get("engine") == "zap-baseline"
    phase_rows = ""
    for k, v in chain.items():
        label, mkey = phase_labels.get(k, (k, None))
        techs = [] if is_zap else mitre.get(mkey, [])
        chips = "".join(
            f"<a class='mitre' href='https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}/' "
            f"target='_blank' rel='noopener'>{_esc(t['id'])}</a>" for t in techs)
        state_label = ("✓ COMPLETED" if v else "— NOT RUN") if is_zap else ("✓ SUCCESS" if v else "✗ FAILED")
        phase_rows += (
            f"<tr><td>{_esc(label)}</td>"
            f"<td class='{'ok' if v else ('skip' if is_zap else 'bad')}'>{state_label}</td>"
            f"<td class='techs'>{chips}</td></tr>"
        )

    findings = "".join(f"<li>{_esc(f)}</li>" for f in summ.get("key_findings", []))
    if is_zap:
        risks = summ.get("alerts_by_risk", {}) or {}
        stats = [
            ("Total alerts", summ.get("alerts_total", 0)),
            ("High", risks.get("High", 0)),
            ("Medium", risks.get("Medium", 0)),
            ("Low", risks.get("Low", 0)),
            ("Informational", risks.get("Informational", 0)),
            ("Affected URLs", report.get("recon_results", {}).get("endpoints_discovered", 0)),
            ("Scan type", "ZAP baseline"),
            ("Total time", f"{report.get('total_time_seconds', 0):.2f}s"),
        ]
    else:
        stats = [
            ("Endpoints discovered", report.get("recon_results", {}).get("endpoints_discovered", 0)),
            ("Scanner findings", summ.get("scanner_findings", 0)),
            ("Exploit methods", ", ".join(report.get("exploit_results", {}).get("methods", [])) or "—"),
            ("Backdoors installed", report.get("persistence_results", {}).get("backdoors_installed", 0)),
            ("Credentials extracted", report.get("lateral_movement_results", {}).get("credentials_extracted", 0)),
            ("Records stolen", report.get("exfiltration_results", {}).get("records_stolen", 0)),
            ("Data exfiltrated", f"{report.get('exfiltration_results', {}).get('data_exfiltrated_mb', 0):.2f} MB"),
            ("Logs deleted", report.get("cover_tracks_results", {}).get("logs_deleted", 0)),
            ("Total time", f"{report.get('total_time_seconds', 0):.2f}s"),
        ]
    stat_tiles = "".join(f"<div class='tile'><div class='v'>{_esc(v)}</div><div class='k'>{_esc(k)}</div></div>"
                         for k, v in stats)

    recs = report.get("recommendations", [])
    rec_rows = ""
    for r in recs:
        pr = r.get("priority", "medium")
        rec_rows += (
            f"<div class='rec'><div class='rec-head'><span class='pr pr-{pr}'>{_esc(pr.upper())}</span>"
            f"<span class='rec-area'>{_esc(r.get('area', ''))}</span>"
            f"<b>{_esc(r.get('title', ''))}</b></div>"
            f"<div class='rec-fix'>{_esc(r.get('fix', ''))}</div></div>"
        )
    recs_section = (f"<section><h2>Remediation priorities</h2>{rec_rows}</section>" if recs else "")

    defense = report.get("defense", {}) or {}
    if defense.get("total_blocks"):
        drows = "".join(f"<span class='dchip'>{_esc(k)} × {v}</span>"
                        for k, v in defense.get("by_type", {}).items())
        defense_section = (f"<section><h2>Defense posture</h2>"
                           f"<p class='dtotal'>{defense['total_blocks']} attack requests were blocked by target defenses.</p>"
                           f"<div class='dchips'>{drows}</div></section>")
    else:
        defense_section = ""

    verdict = report.get("verdict", "")
    verdict_html = (f"<div class='verdict'>{_esc(verdict)}</div>" if verdict else "")
    workflow_heading = "Scan workflow" if is_zap else "Attack chain · MITRE ATT&CK"
    print_script = "<script>window.addEventListener('load',function(){setTimeout(function(){window.print()},250)})</script>" if print_mode else ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Threat Report — {_esc(report.get('run_id', ''))}</title>
<style>
 :root {{ color-scheme: dark; }}
 body {{ margin:0; background:#050a16; color:#dbe7ff;
        font-family:'Segoe UI',system-ui,sans-serif; padding:32px; }}
 .wrap {{ max-width:900px; margin:0 auto; }}
 h1 {{ font-size:26px; letter-spacing:3px; margin:0; }}
 .sub {{ color:#7d8db0; font-size:13px; margin-top:6px; }}
 .sev {{ display:inline-block; padding:6px 18px; border-radius:999px; font-weight:700;
        border:1px solid {sev_color}; color:{sev_color}; margin-top:14px; letter-spacing:2px; }}
 .verdict {{ margin-top:12px; padding:10px 16px; border-left:3px solid #22d3ee;
            background:rgba(34,211,238,.06); font-size:14px; color:#cfe6ff; }}
 .grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:12px; margin:26px 0; }}
 .tile {{ background:#0b1428; border:1px solid #1d2c50; border-radius:12px; padding:14px; }}
 .tile .v {{ font-size:20px; font-weight:700; color:#22d3ee; word-break:break-word; }}
 .tile .k {{ font-size:11px; color:#7d8db0; text-transform:uppercase; letter-spacing:1px; margin-top:4px; }}
 section {{ background:#0b1428; border:1px solid #1d2c50; border-radius:14px; padding:20px; margin:14px 0; }}
 h2 {{ font-size:14px; letter-spacing:2px; color:#22d3ee; text-transform:uppercase; margin:0 0 12px; }}
 table {{ width:100%; border-collapse:collapse; font-size:14px; }}
 td {{ padding:8px 10px; border-bottom:1px solid #14203c; vertical-align:top; }}
 td.ok {{ color:#34d399; font-weight:600; white-space:nowrap; }} td.bad {{ color:#f43f5e; font-weight:600; white-space:nowrap; }}
 td.skip {{ color:#7d8db0; font-weight:600; white-space:nowrap; }}
 td.techs {{ text-align:right; }}
 .mitre {{ display:inline-block; margin:1px 0 1px 4px; padding:2px 7px; border-radius:6px; font-size:11px;
          font-family:ui-monospace,monospace; color:#a5f3fc; background:rgba(34,211,238,.09);
          border:1px solid rgba(34,211,238,.25); text-decoration:none; }}
 ul {{ margin:0; padding-left:20px; }} li {{ margin:6px 0; font-size:14px; }}
 .rec {{ border:1px solid #1d2c50; border-radius:10px; padding:12px 14px; margin:8px 0; background:#08101f; }}
 .rec-head {{ display:flex; gap:10px; align-items:baseline; flex-wrap:wrap; }}
 .pr {{ font-size:10px; font-weight:700; letter-spacing:1px; padding:2px 8px; border-radius:999px; }}
 .pr-critical {{ color:#fb7185; border:1px solid #fb7185; }}
 .pr-high {{ color:#f43f5e; border:1px solid rgba(244,63,94,.6); }}
 .pr-medium {{ color:#fbbf24; border:1px solid rgba(251,191,36,.6); }}
 .pr-low {{ color:#34d399; border:1px solid rgba(52,211,153,.6); }}
 .rec-area {{ font-size:11px; color:#7d8db0; text-transform:uppercase; letter-spacing:1px; }}
 .rec-fix {{ margin-top:7px; font-size:13px; color:#b7c6e8; line-height:1.55; }}
 .dtotal {{ color:#b7c6e8; font-size:14px; }}
 .dchip {{ display:inline-block; margin:4px 6px 0 0; padding:4px 12px; border-radius:999px;
          font-size:12px; font-family:ui-monospace,monospace; color:#fbbf24;
          border:1px solid rgba(251,191,36,.45); background:rgba(251,191,36,.06); }}
 .foot {{ text-align:center; color:#54627f; font-size:12px; margin-top:24px; }}
 @media(max-width:760px) {{ .grid {{ grid-template-columns:repeat(2,1fr); }} }}
 @media print {{
   :root {{ color-scheme: light; }}
   body {{ background:#fff; color:#111; padding:0; }}
   .tile {{ background:#f6f8fb; border-color:#d7e0ee; }}
   .tile .v {{ color:#0e7490; }}
   section {{ background:#fff; border-color:#d7e0ee; break-inside:avoid; }}
   h2 {{ color:#0e7490; }}
   td {{ border-bottom-color:#e5eaf2; }}
   td.ok {{ color:#047857; }} td.bad {{ color:#be123c; }}
   .mitre {{ color:#0e7490; background:#ecfeff; border-color:#a5f3fc; }}
   .rec {{ background:#fff; border-color:#d7e0ee; }}
   .rec-fix {{ color:#334155; }}
   .sev {{ background:#fff; }}
   .verdict {{ background:#f6f8fb; color:#0f172a; }}
   .foot {{ color:#64748b; }}
 }}
</style></head><body><div class="wrap">
 <h1>⚠ OFFENSIVE EMULATOR — THREAT REPORT</h1>
 <div class="sub">Run <b>{_esc(report.get('run_id', ''))}</b> · target
   <b>{_esc(report.get('target', ''))}</b> · engine <b>{_esc(report.get('engine', '?'))}</b> ·
   {_esc(report.get('timestamp', ''))}</div>
 <div class="sev">SEVERITY: {_esc(sev)} · SUCCESS RATE {_esc(summ.get('attack_success_rate', '?'))}</div>
 {verdict_html}
 <div class="grid">{stat_tiles}</div>
 <section><h2>{workflow_heading}</h2><table>{phase_rows}</table></section>
 {defense_section}
 <section><h2>Key findings</h2><ul>{findings}</ul></section>
 {recs_section}
 <div class="foot">Generated by Offensive Emulator v{VERSION} — defensive security testing tool.
 Use only against systems you own or are authorized to test.</div>
</div>{print_script}</body></html>"""


# ---------------------------------------------------------------------------
# Server bootstrap
# ---------------------------------------------------------------------------

class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        """Stay quiet about dropped connections (attack clients are chatty)."""
        exc = sys.exc_info()[1]
        if isinstance(exc, (BrokenPipeError, ConnectionResetError, TimeoutError)):
            return
        super().handle_error(request, client_address)


def create_server(host: str = "0.0.0.0", port: int = 8000) -> Server:
    return Server((host, port), AppHandler)


def main() -> None:
    port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 8000
    host = "0.0.0.0"
    server = create_server(host, port)
    print(f"""
╔══════════════════════════════════════════════════════════════════╗
║   OFFENSIVE EMULATOR v{VERSION} — unified app                        ║
║                                                                  ║
║   UI          http://localhost:{port}                            ║
║   Demo target http://localhost:{port}/demo                       ║
║   Engine      {attack_service.ENGINE_MODE:<47s}║
║                                                                  ║
║   Press Ctrl+C to stop                                           ║
╚══════════════════════════════════════════════════════════════════╝
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n✋ Shutting down…")


if __name__ == "__main__":
    main()
