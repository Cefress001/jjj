"""
Offensive Emulator Web API
FastAPI backend for web UI - run attacks and manage configuration
"""

from fastapi import FastAPI, WebSocket, HTTPException, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

from offensive_emulator_unified import UnifiedOffensiveEmulator
from config import (
    AttackConfig,
    AggressivenessLevel,
    STEALTH_CONFIG,
    BALANCED_CONFIG,
    AGGRESSIVE_CONFIG,
    MAXIMUM_CONFIG
)
from adaptive_learning import AttackLearner
from evasion import EvasionManager
from metrics import MetricsCollector, ReportGenerator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Offensive Emulator v3", version="3.0")

# Global state
active_runs: Dict[str, Dict[str, Any]] = {}
websocket_connections: List[WebSocket] = []


class AttackRunner:
    """Background attack executor"""

    def __init__(self, run_id: str, target: str, config: AttackConfig):
        self.run_id = run_id
        self.target = target
        self.config = config
        self.status = "initializing"
        self.current_phase = None
        self.progress = 0
        self.log_messages = []
        self.report = None

    async def run(self) -> None:
        """Execute attack in background"""
        try:
            self.status = "running"
            await self._broadcast_update()

            # Setup components
            learner = AttackLearner()
            evasion = EvasionManager()
            metrics = MetricsCollector(self.run_id, self.target)

            # Create emulator
            emulator = UnifiedOffensiveEmulator(
                target_url=self.target,
                run_id=self.run_id
            )

            # Monkey-patch log handler to capture
            self._setup_logging()

            # Run attack
            self.report = await emulator.run_full_attack()

            self.status = "complete"
            self.progress = 100

        except Exception as e:
            logger.error(f"Attack failed: {e}")
            self.status = "failed"
            self.log_messages.append(f"ERROR: {str(e)}")

        finally:
            await self._broadcast_update()

    def _setup_logging(self) -> None:
        """Capture logs from attack execution"""
        class LogCapture(logging.Handler):
            def __init__(self, runner):
                super().__init__()
                self.runner = runner

            def emit(self, record):
                msg = self.format(record)
                self.runner.log_messages.append(msg)
                if len(self.runner.log_messages) > 1000:
                    self.runner.log_messages.pop(0)

        handler = LogCapture(self)
        logger.addHandler(handler)

    async def _broadcast_update(self) -> None:
        """Send status update to all connected clients"""
        update = {
            "run_id": self.run_id,
            "status": self.status,
            "progress": self.progress,
            "current_phase": self.current_phase,
            "log_count": len(self.log_messages),
        }

        for ws in websocket_connections:
            try:
                await ws.send_json({"type": "status_update", "data": update})
            except:
                pass


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/api/health")
async def health_check():
    """Health check"""
    return {"status": "ok", "version": "3.0"}


@app.get("/api/configs")
async def get_available_configs():
    """Get available configuration presets"""
    return {
        "presets": {
            "stealth": {"name": "Stealth", "description": "Slow, quiet, evade detection"},
            "balanced": {"name": "Balanced", "description": "Normal speed (recommended)"},
            "aggressive": {"name": "Aggressive", "description": "Fast, concurrent, high noise"},
            "maximum": {"name": "Maximum", "description": "Full speed, no evasion"},
        }
    }


@app.post("/api/attack/start")
async def start_attack(
    target: str,
    config_preset: str = "balanced",
    background_tasks: BackgroundTasks = None
):
    """Start a new attack"""

    # Validate input
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"

    # Select config
    configs = {
        "stealth": STEALTH_CONFIG,
        "balanced": BALANCED_CONFIG,
        "aggressive": AGGRESSIVE_CONFIG,
        "maximum": MAXIMUM_CONFIG,
    }
    config = configs.get(config_preset, BALANCED_CONFIG)

    # Generate run ID
    import uuid
    run_id = str(uuid.uuid4())[:8]

    # Create runner
    runner = AttackRunner(run_id, target, config)
    active_runs[run_id] = runner

    # Schedule background execution
    background_tasks.add_task(runner.run)

    logger.info(f"Started attack {run_id} against {target} with {config_preset} config")

    return {
        "run_id": run_id,
        "target": target,
        "config": config_preset,
        "status": "queued"
    }


@app.get("/api/attack/{run_id}/status")
async def get_attack_status(run_id: str):
    """Get attack status"""
    if run_id not in active_runs:
        raise HTTPException(status_code=404, detail="Run not found")

    runner = active_runs[run_id]
    return {
        "run_id": run_id,
        "status": runner.status,
        "progress": runner.progress,
        "current_phase": runner.current_phase,
        "phase_count": len(runner.log_messages),
    }


@app.get("/api/attack/{run_id}/logs")
async def get_attack_logs(run_id: str, limit: int = 100):
    """Get attack logs"""
    if run_id not in active_runs:
        raise HTTPException(status_code=404, detail="Run not found")

    runner = active_runs[run_id]
    logs = runner.log_messages[-limit:]

    return {
        "run_id": run_id,
        "logs": logs,
        "total": len(runner.log_messages),
    }


@app.get("/api/attack/{run_id}/report")
async def get_attack_report(run_id: str):
    """Get attack report"""
    if run_id not in active_runs:
        raise HTTPException(status_code=404, detail="Run not found")

    runner = active_runs[run_id]

    if not runner.report:
        raise HTTPException(status_code=202, detail="Attack still running")

    return runner.report


@app.get("/api/attack/{run_id}/report.html")
async def download_html_report(run_id: str):
    """Download HTML report"""
    if run_id not in active_runs:
        raise HTTPException(status_code=404, detail="Run not found")

    runner = active_runs[run_id]

    if not runner.report:
        raise HTTPException(status_code=202, detail="Attack still running")

    # Generate HTML report (simplified)
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Attack Report - {run_id}</title>
    <style>
        body {{ font-family: Arial; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #222; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ background: white; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .metric {{ display: inline-block; margin: 10px 20px; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #d9534f; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Offensive Emulator - Attack Report</h1>
        <p>Run ID: {run_id}</p>
    </div>
    <div class="section">
        <h2>Summary</h2>
        <pre>{json.dumps(runner.report, indent=2)}</pre>
    </div>
</body>
</html>
"""

    return FileResponse(
        content=html.encode(),
        media_type="text/html",
        filename=f"report_{run_id}.html"
    )


@app.get("/api/attack/list")
async def list_attacks():
    """List all attacks"""
    return {
        "runs": [
            {
                "run_id": run_id,
                "status": runner.status,
                "progress": runner.progress,
            }
            for run_id, runner in active_runs.items()
        ]
    }


# ============================================================================
# WebSocket for Real-time Updates
# ============================================================================

@app.websocket("/ws/{run_id}")
async def websocket_endpoint(websocket: WebSocket, run_id: str):
    """WebSocket for real-time attack monitoring"""

    if run_id not in active_runs:
        await websocket.close(code=4004, reason="Run not found")
        return

    await websocket.accept()
    websocket_connections.append(websocket)

    try:
        runner = active_runs[run_id]

        # Send initial state
        await websocket.send_json({
            "type": "connected",
            "run_id": run_id,
            "status": runner.status
        })

        # Stream updates every second
        while runner.status not in ["complete", "failed"]:
            update = {
                "type": "status_update",
                "run_id": run_id,
                "status": runner.status,
                "progress": runner.progress,
                "current_phase": runner.current_phase,
                "log_count": len(runner.log_messages),
            }

            await websocket.send_json(update)
            await asyncio.sleep(1)

        # Send final update
        await websocket.send_json({
            "type": "complete",
            "run_id": run_id,
            "status": runner.status,
            "progress": runner.progress,
            "report": runner.report if runner.report else None,
        })

    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        websocket_connections.remove(websocket)


# ============================================================================
# Static Files
# ============================================================================

# Mount static files (web UI)
import os
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
async def index():
    """Serve main UI"""
    index_file = Path(__file__).parent / "static" / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))

    # Fallback if static files not set up yet
    return {"message": "Offensive Emulator v3 API", "docs": "/docs"}


if __name__ == "__main__":
    import uvicorn

    print("""
    ╔════════════════════════════════════════════════════════════════╗
    ║   Offensive Emulator v3 - Web API                              ║
    ║   http://localhost:8000                                        ║
    ║                                                                ║
    ║   - Web UI:   http://localhost:8000/                          ║
    ║   - API Docs: http://localhost:8000/docs                      ║
    ║   - WebSocket: ws://localhost:8000/ws/{run_id}                ║
    ╚════════════════════════════════════════════════════════════════╝
    """)

    uvicorn.run(app, host="0.0.0.0", port=8000)
