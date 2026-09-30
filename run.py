#!/usr/bin/env python3
"""
Offensive Emulator — ONE app, ONE entry point.
===============================================

    python run.py                 → launch the web app (landing page + 3D console)
    python run.py --port 9000     → launch on another port
    python run.py --target URL    → headless CLI attack, prints + saves the report

Zero dependencies. `pip install aiohttp` upgrades the engine from
simulation to real HTTP attack modules.
"""

import argparse
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).parent
ENGINE_DIR = BASE_DIR / "offensive_emulator"
sys.path.insert(0, str(ENGINE_DIR))

import attack_service  # noqa: E402
from app_server import create_server, VERSION  # noqa: E402


def open_browser(url: str) -> None:
    try:
        import webbrowser
        threading_webbrowser = webbrowser.open(url)
        if not threading_webbrowser:
            print(f"(open {url} in your browser)")
    except Exception:
        print(f"(open {url} in your browser)")


def serve(port: int, no_open: bool) -> None:
    server = create_server("0.0.0.0", port)

    def line(text: str = "") -> str:
        return "║" + text.ljust(64) + "║"

    engine_note = ("real HTTP engines (aiohttp detected)"
                   if attack_service.ENGINE_MODE == "real"
                   else "simulation — `pip install aiohttp` for real engines")
    print()
    print("╔" + "═" * 64 + "╗")
    print(line("  ⚔  OFFENSIVE EMULATOR v" + VERSION + " — unified app"))
    print(line())
    print(line(f"  Landing + console :  http://localhost:{port}"))
    print(line(f"  Built-in target  :  http://localhost:{port}/demo"))
    print(line(f"  Engine           :  {engine_note}"))
    print(line())
    print(line("  Press Ctrl+C to stop"))
    print("╚" + "═" * 64 + "╗")
    print()

    if not no_open:
        open_browser(f"http://localhost:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n✋ Shutting down… bye.")


def cli_attack(target: str, preset: str) -> int:
    print(f"⚔  Offensive Emulator v{VERSION} — headless attack")
    print(f"   target : {target}")
    print(f"   preset : {preset}")
    print(f"   engine : {attack_service.ENGINE_MODE}\n")

    result = attack_service.run_cli(target, preset)
    report = result.get("report") or {}

    # stream a compact human summary
    print("─" * 66)
    print("ATTACK CHAIN")
    for phase, ok in (report.get("attack_chain") or {}).items():
        print(f"   {'✓' if ok else '✗'}  {phase.replace('_', ' ').title()}")
    print("─" * 66)
    summary = report.get("summary") or {}
    print(f"Severity      : {summary.get('severity', '?')}")
    print(f"Success rate  : {summary.get('attack_success_rate', '?')}")
    print(f"Log lines     : {result.get('log_total', 0)}")
    print("Key findings  :")
    for f in summary.get("key_findings", []):
        print(f"   • {f}")

    out_file = BASE_DIR / f"threat_report_{result.get('run_id', 'run')}.json"
    out_file.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"\n📁 Full report saved to: {out_file}")
    print(f"   Logs captured: {result.get('log_total', 0)} lines "
          f"({result.get('logs_dropped', 0)} trimmed)")
    return 0 if result.get("status") == "complete" else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="run.py",
        description="Offensive Emulator — unified red-team simulation app",
    )
    ap.add_argument("--port", type=int, default=8000, help="port for the web app (default 8000)")
    ap.add_argument("--target", metavar="URL", help="headless mode: attack this target and exit")
    ap.add_argument("--preset", default="balanced", choices=list(attack_service.PRESETS),
                    help="attack profile (default balanced)")
    ap.add_argument("--no-open", action="store_true", help="don't auto-open the browser")
    ap.add_argument("--version", action="version", version=f"Offensive Emulator v{VERSION}")
    args = ap.parse_args()

    if args.target:
        return cli_attack(args.target, args.preset)

    serve(args.port, args.no_open)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
