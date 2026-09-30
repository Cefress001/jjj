"""Safe subprocess lifecycle helpers shared by external scanner adapters."""

from __future__ import annotations

import os
import signal
import subprocess
from typing import Any, Dict


def popen_group_options() -> Dict[str, Any]:
    """Start scanners in their own process group so cancellation kills children."""
    if os.name == "posix":
        return {"start_new_session": True}
    if os.name == "nt":  # pragma: no cover - production image is Linux
        return {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    return {}


def stop_process_tree(process: subprocess.Popen, grace_seconds: float = 4.0) -> None:
    """Terminate a scanner and any child processes, then always reap it."""
    if process.poll() is not None:
        try:
            process.wait(timeout=0)
        except Exception:
            pass
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:  # pragma: no cover - production image is Linux
            process.terminate()
        process.wait(timeout=grace_seconds)
        return
    except (ProcessLookupError, subprocess.TimeoutExpired):
        pass
    except Exception:
        try:
            process.terminate()
            process.wait(timeout=grace_seconds)
            return
        except Exception:
            pass
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:  # pragma: no cover
            process.kill()
    except ProcessLookupError:
        pass
    finally:
        try:
            process.wait(timeout=max(1.0, grace_seconds))
        except Exception:
            pass
