#!/usr/bin/env python3
"""
Offensive Emulator v3 - Web UI Launcher
Uses Python's built-in HTTP server - NO external dependencies
"""

import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    script_dir = Path(__file__).parent
    simple_server = script_dir / "simple_server.py"

    print("Starting Offensive Emulator v3 Web UI...")
    print(f"Running: {simple_server}")

    # Run the simple server directly
    try:
        subprocess.run([sys.executable, str(simple_server)], check=False)
    except KeyboardInterrupt:
        print("\nShutdown complete")
        sys.exit(0)
