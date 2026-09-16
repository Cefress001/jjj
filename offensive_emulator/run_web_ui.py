#!/usr/bin/env python3
"""
Offensive Emulator v3 - Web UI Launcher
Run this to start the web interface
"""

import sys
import os
import webbrowser
import time
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

def check_dependencies():
    """Check if required packages are installed"""
    required = ['fastapi', 'uvicorn', 'aiohttp']
    missing = []

    for package in required:
        try:
            __import__(package)
        except ImportError:
            missing.append(package)

    if missing:
        print(f"\n❌ Missing dependencies: {', '.join(missing)}")
        print(f"\nInstall with:")
        print(f"   pip install {' '.join(missing)}")
        return False

    return True


def main():
    """Launch the web UI"""

    print("""
    ╔════════════════════════════════════════════════════════════════╗
    ║                                                                ║
    ║         Offensive Emulator v3 - Web UI                        ║
    ║         Red Team Simulation Platform                          ║
    ║                                                                ║
    ║    Starting web interface...                                  ║
    ║                                                                ║
    ╚════════════════════════════════════════════════════════════════╝
    """)

    # Check dependencies
    if not check_dependencies():
        sys.exit(1)

    # Import after dependency check
    import uvicorn
    from web import app

    print("\n📡 Starting API server on http://localhost:8000\n")
    print("🌐 Web UI:    http://localhost:8000/")
    print("📚 API Docs:  http://localhost:8000/docs")
    print("🔌 WebSocket: ws://localhost:8000/ws/{run_id}")
    print("\nPress Ctrl+C to stop\n")

    # Open browser after a short delay
    def open_browser():
        time.sleep(2)
        try:
            webbrowser.open('http://localhost:8000')
            print("🚀 Browser opened automatically")
        except:
            pass

    import threading
    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()

    # Run server
    try:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n\n✋ Shutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
