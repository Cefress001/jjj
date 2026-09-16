#!/usr/bin/env python3
"""
Offensive Emulator - Simple Built-in HTTP Server
No external dependencies - uses Python's built-in http.server
"""

import http.server
import socketserver
import os
import webbrowser
import threading
import time
from pathlib import Path

PORT = 8000
THIS_DIR = Path(__file__).parent
STATIC_DIR = THIS_DIR / "static"
INDEX_FILE = STATIC_DIR / "index.html"

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests"""
        # Serve index.html for root
        if self.path == "/" or self.path == "":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            try:
                with open(INDEX_FILE, 'rb') as f:
                    self.wfile.write(f.read())
            except FileNotFoundError:
                self.wfile.write(b"<h1>index.html not found</h1>")
            return

        # Serve other files from static dir
        if self.path.startswith("/static/"):
            file_path = STATIC_DIR / self.path[8:]  # Remove /static/
        else:
            file_path = STATIC_DIR / self.path.lstrip("/")

        if file_path.exists() and file_path.is_file():
            self.send_response(200)
            # Guess content type
            if str(file_path).endswith('.css'):
                self.send_header("Content-type", "text/css")
            elif str(file_path).endswith('.js'):
                self.send_header("Content-type", "application/javascript")
            elif str(file_path).endswith('.html'):
                self.send_header("Content-type", "text/html")
            else:
                self.send_header("Content-type", "text/plain")
            self.end_headers()
            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
            return

        # 404
        self.send_response(404)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>404 Not Found</h1>")

    def log_message(self, format, *args):
        """Suppress logging"""
        pass

def open_browser():
    """Open browser after delay"""
    time.sleep(1)
    try:
        webbrowser.open(f'http://localhost:{PORT}')
    except:
        pass

if __name__ == "__main__":
    print(f"""
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║         Offensive Emulator v3 - Web UI                        ║
║                                                                ║
║    🌐 Opening http://localhost:{PORT}                       ║
║                                                                ║
║    Press Ctrl+C to stop                                       ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
    """)

    # Check if index.html exists
    if not INDEX_FILE.exists():
        print(f"❌ ERROR: index.html not found at {INDEX_FILE}")
        exit(1)

    # Start browser thread
    browser_thread = threading.Thread(target=open_browser, daemon=True)
    browser_thread.start()

    # Start server
    try:
        with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
            print(f"✅ Server running at http://localhost:{PORT}")
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n✋ Shutting down...")
    except Exception as e:
        print(f"❌ Error: {e}")
