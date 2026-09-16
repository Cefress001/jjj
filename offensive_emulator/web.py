"""
Offensive Emulator v3 - Ultra-Simple Web UI
No complex imports - just serves the dashboard
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import asyncio
from pathlib import Path

app = FastAPI()

# Get HTML file path
HTML_FILE = Path(__file__).parent / "static" / "index.html"

@app.get("/", response_class=HTMLResponse)
async def home():
    """Serve the HTML dashboard"""
    try:
        content = HTML_FILE.read_text(encoding='utf-8')
        return content
    except Exception as e:
        return f"""
        <html>
        <body style="font-family: Arial; padding: 20px;">
        <h1>Offensive Emulator v3</h1>
        <p style="color: red;">Error loading UI: {str(e)}</p>
        <p>Make sure static/index.html exists at: {HTML_FILE}</p>
        </body>
        </html>
        """

@app.get("/health")
async def health():
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
