"""
Offensive Emulator v3 - Simplified Web UI
Standalone app that actually works
"""

from fastapi import FastAPI, BackgroundTasks, WebSocket
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import asyncio
import json
import uuid
from pathlib import Path
import sys
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create app
app = FastAPI(title="Offensive Emulator v3")

# Paths
THIS_DIR = Path(__file__).parent
STATIC_DIR = THIS_DIR / "static"
INDEX_FILE = STATIC_DIR / "index.html"

# Global state
active_runs = {}
ws_connections = []


# ============================================================================
# Serve UI
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve dashboard"""
    try:
        with open(INDEX_FILE, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Error: index.html not found</h1>"
    except Exception as e:
        return f"<h1>Error: {e}</h1>"


@app.get("/style.css")
async def get_css():
    """Serve CSS if requested separately"""
    return "/* CSS served inline in HTML */"


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "3.0"}


@app.post("/api/attack/start")
async def start_attack(target: str, config_preset: str = "balanced", background_tasks: BackgroundTasks = None):
    """Start attack"""

    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    run_id = str(uuid.uuid4())[:8]

    # Create mock runner
    runner = {
        "run_id": run_id,
        "target": target,
        "status": "initializing",
        "progress": 0,
        "logs": ["Starting attack...", f"Target: {target}", f"Config: {config_preset}"],
        "report": None
    }

    active_runs[run_id] = runner

    # Start background attack
    async def run_attack():
        try:
            runner["status"] = "running"

            # Try to import and run real attack
            try:
                from offensive_emulator_unified import UnifiedOffensiveEmulator

                runner["logs"].append("[*] Initializing attack modules...")
                emulator = UnifiedOffensiveEmulator(target_url=target, run_id=run_id)

                runner["logs"].append("[*] Running full attack sequence...")
                runner["progress"] = 25

                # Run attack
                report = await emulator.run_full_attack()

                runner["report"] = report
                runner["progress"] = 100
                runner["status"] = "complete"
                runner["logs"].append("[+] Attack complete!")

            except Exception as e:
                runner["logs"].append(f"[!] Attack module error: {e}")
                runner["logs"].append("[*] Running in demo mode...")

                # Demo mode - simulate attack
                phases = ["RECON", "EXPLOIT", "PERSIST", "LATERAL", "EXFIL", "COVER"]
                for i, phase in enumerate(phases):
                    runner["progress"] = int((i + 1) / len(phases) * 100)
                    runner["logs"].append(f"[*] {phase} phase...")
                    await asyncio.sleep(1)

                runner["report"] = {
                    "run_id": run_id,
                    "target": target,
                    "status": "demo",
                    "summary": {
                        "attack_success_rate": "Demo Mode",
                        "severity": "N/A",
                        "key_findings": ["Running in demo mode - attack modules not fully loaded"]
                    }
                }
                runner["status"] = "complete"
                runner["progress"] = 100
                runner["logs"].append("[+] Demo attack complete!")

        except Exception as e:
            runner["status"] = "failed"
            runner["logs"].append(f"[!] Error: {str(e)}")

    background_tasks.add_task(run_attack)

    return {"run_id": run_id, "target": target, "status": "queued"}


@app.get("/api/attack/{run_id}/status")
async def get_status(run_id: str):
    """Get attack status"""
    if run_id not in active_runs:
        return {"error": "not found"}, 404

    runner = active_runs[run_id]
    return {
        "run_id": run_id,
        "status": runner["status"],
        "progress": runner["progress"],
    }


@app.get("/api/attack/{run_id}/logs")
async def get_logs(run_id: str, limit: int = 100):
    """Get attack logs"""
    if run_id not in active_runs:
        return {"error": "not found"}, 404

    runner = active_runs[run_id]
    logs = runner["logs"][-limit:] if runner["logs"] else []

    return {
        "run_id": run_id,
        "logs": logs,
        "total": len(runner["logs"]),
    }


@app.get("/api/attack/{run_id}/report")
async def get_report(run_id: str):
    """Get attack report"""
    if run_id not in active_runs:
        return {"error": "not found"}, 404

    runner = active_runs[run_id]

    if not runner["report"]:
        return {"error": "still running"}, 202

    return runner["report"]


@app.websocket("/ws/{run_id}")
async def websocket_endpoint(websocket, run_id: str):
    """WebSocket for real-time updates"""
    if run_id not in active_runs:
        await websocket.close(code=4004)
        return

    await websocket.accept()
    ws_connections.append(websocket)

    try:
        runner = active_runs[run_id]

        while runner["status"] not in ["complete", "failed"]:
            await websocket.send_json({
                "type": "update",
                "status": runner["status"],
                "progress": runner["progress"],
                "logs": runner["logs"][-10:]
            })
            await asyncio.sleep(1)

        await websocket.send_json({
            "type": "complete",
            "status": runner["status"],
            "progress": runner["progress"],
            "report": runner["report"]
        })
    except Exception as e:
        logger.error(f"WS error: {e}")
    finally:
        if websocket in ws_connections:
            ws_connections.remove(websocket)


if __name__ == "__main__":
    import uvicorn
    print("""
╔════════════════════════════════════════════════════════════════╗
║   Offensive Emulator v3 - Web UI                              ║
║   Opening: http://localhost:8000                              ║
╚════════════════════════════════════════════════════════════════╝
    """)
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
