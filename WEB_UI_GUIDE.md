# Offensive Emulator v3 - Web UI Guide

## Overview

The web UI provides a complete interface to run, monitor, and analyze red team simulations without any command-line or programming knowledge.

---

## Installation & Setup

### Step 1: Install Dependencies

```bash
# Navigate to the project directory
cd offensive_emulator

# Install required packages
pip install -r requirements.txt
```

Required packages:
- `fastapi` - Web framework
- `uvicorn` - ASGI server
- `aiohttp` - HTTP client
- `python-multipart` - Form handling

### Step 2: Start the Web UI

**Option A: Python script (recommended)**
```bash
python run_web_ui.py
```

**Option B: Direct uvicorn**
```bash
uvicorn api:app --reload
```

**Option C: With specific host/port**
```bash
uvicorn api:app --host 0.0.0.0 --port 8000
```

### Step 3: Access the Interface

Once running, open your browser to:
- **Web UI**: http://localhost:8000/
- **API Docs**: http://localhost:8000/docs

The browser should open automatically.

---

## Using the Web UI

### Main Interface Sections

#### 1. Configuration Panel (Left)

**Target URL**
- Enter the target application URL
- Examples:
  - `http://localhost:3004`
  - `http://192.168.1.100:8080`
  - `https://my-app.local`

**Aggressiveness Profile**
- Choose attack intensity:
  - **Stealth** - Slow, quiet, maximum evasion (2-5 minutes)
  - **Balanced** - Normal speed, standard tactics (30-60 seconds) [Recommended]
  - **Aggressive** - Fast, concurrent, high noise (10-30 seconds)
  - **Maximum** - Full speed, no evasion (5-10 seconds)

Each profile shows details:
- Concurrency level
- Expected duration
- Evasion tactics
- Noise level

**Start Button**
- Click to begin attack
- Disabled during execution
- Turns into spinner while starting

#### 2. Status Panel (Right)

**Current Status**
- Shows attack state: Queued → Running → Complete/Failed
- Color-coded badges

**Progress Bar**
- Visual percentage of completion
- Updates in real-time

**Current Phase**
- Shows which attack phase is executing:
  - Reconnaissance
  - Exploitation
  - Persistence
  - Lateral Movement
  - Exfiltration
  - Cover Tracks

**Report Download**
- Available when attack completes
- Download HTML report
- View summary report

#### 3. Live Logs Panel (Bottom)

**Real-time Attack Log**
- Shows all log messages from running attack
- Auto-scrolls to latest
- Green text on dark background (terminal style)
- Last 1000 messages kept

---

## Running an Attack

### Typical Workflow

1. **Enter Target URL**
   - Paste your target application URL
   - Ensure it's accessible from your machine

2. **Select Profile**
   - Choose aggressiveness based on needs:
     - Stealth: If you want minimal detection
     - Balanced: For normal assessment
     - Aggressive: For quick full test
     - Maximum: For stress testing

3. **Start Attack**
   - Click "Start Attack" button
   - UI will show "Queued" status
   - Attack begins within seconds

4. **Monitor Execution**
   - Watch progress bar increase
   - See current phase in status panel
   - View live logs as they happen
   - Real-time updates via WebSocket

5. **Review Results**
   - When complete, status changes to "Complete"
   - Download HTML report or view summary
   - Analyze findings and metrics

---

## Understanding Results

### Attack Status

- **Queued** - Attack is queued, starting soon
- **Running** - Attack is actively executing
- **Complete** - Attack finished successfully
- **Failed** - Attack encountered an error

### Progress Indicator

- 0-20%: Reconnaissance phase
- 20-40%: Exploitation phase
- 40-60%: Persistence phase
- 60-80%: Lateral movement & Exfiltration
- 80-100%: Cover tracks & reporting

### Report Metrics

**Success Rate**
- Percentage of successful attacks
- Higher % = better attack penetration

**Severity**
- Critical: Major findings, significant impact
- High: Serious vulnerabilities found
- Medium: Notable weaknesses
- Low: Minor issues only

**Key Findings**
- Endpoints discovered
- Successful exploit methods
- Backdoors/admin accounts created
- Credentials extracted
- Data stolen
- Evasion effectiveness

---

## Profile Comparison

| Aspect | Stealth | Balanced | Aggressive | Maximum |
|--------|---------|----------|-----------|---------|
| **Duration** | 2-5 min | 30-60 sec | 10-30 sec | 5-10 sec |
| **Concurrency** | 1-2 | 5-10 | 20-50 | 50+ |
| **Evasion** | All tactics | Standard | Basic | None |
| **Detection Risk** | Very Low | Low | Medium | High |
| **Noise Level** | Minimal | Normal | High | Maximum |
| **Use Case** | Stealth testing | Standard | Quick test | Stress test |

---

## API Endpoints (For Integration)

If you want to integrate with other tools:

### Start Attack
```
POST /api/attack/start?target=http://localhost:3004&config_preset=balanced
```

### Get Status
```
GET /api/attack/{run_id}/status
```

### Get Logs
```
GET /api/attack/{run_id}/logs?limit=100
```

### Get Report
```
GET /api/attack/{run_id}/report
```

### Download HTML Report
```
GET /api/attack/{run_id}/report.html
```

### WebSocket (Real-time)
```
WS ws://localhost:8000/ws/{run_id}
```

---

## Troubleshooting

### "Connection refused" error

**Problem**: Target URL is unreachable

**Solutions**:
1. Verify target URL is correct
2. Check firewall allows connection
3. Ensure target application is running
4. Try accessing URL in browser first
5. Check if localhost vs 127.0.0.1 matters

### Attack hangs or never completes

**Problem**: Attack seems stuck

**Solutions**:
1. Check target response time (may be slow)
2. Try STEALTH profile (slower but more thorough)
3. Check firewall isn't blocking requests
4. Restart browser and UI server
5. Check browser console for errors (F12)

### No endpoints found in Recon

**Problem**: Reconnaissance finds nothing

**Solutions**:
1. Verify target URL format
2. Check target application is running
3. Endpoints may require authentication
4. Try accessing URL directly in browser
5. Check network connectivity

### UI not loading

**Problem**: Can't access http://localhost:8000

**Solutions**:
1. Ensure `run_web_ui.py` is running
2. Check console for error messages
3. Try http://127.0.0.1:8000 instead
4. Try different port: `uvicorn api:app --port 8001`
5. Check firewall isn't blocking port 8000

### WebSocket errors

**Problem**: Real-time updates not working

**Solutions**:
1. Hard refresh browser (Ctrl+F5)
2. Check browser console (F12) for errors
3. Ensure browser supports WebSocket
4. Try different browser
5. Disable browser extensions

---

## Advanced Usage

### Custom Profiles

Edit `config.py` to create custom attack profiles:

```python
from config import AttackConfig, AggressivenessLevel

custom_config = AttackConfig(
    aggressiveness=AggressivenessLevel.AGGRESSIVE,
    exploit_jwt_attempts=10,          # More JWT attempts
    exploit_max_retries=5,             # More retries
    exfil_batch_size=5000,             # Larger batches
    evasion_enabled=False,             # Disable evasion
)
```

### Integration with SIEM

Export JSON report for SIEM ingestion:

1. Run attack via web UI
2. API returns JSON report
3. Parse with your SIEM/analytics tool
4. Create dashboards and alerts

### Batch Testing

Test multiple targets via API:

```bash
# Test all internal apps
for target in localhost:3000 localhost:3001 localhost:3002; do
    curl -X POST "http://localhost:8000/api/attack/start?target=http://$target&config_preset=balanced"
done
```

---

## Best Practices

### Before Running

- ✅ Verify you own/control the target
- ✅ Ensure test environment is isolated
- ✅ Disable unnecessary background tasks
- ✅ Close resource-heavy applications
- ✅ Document baseline metrics

### During Execution

- ✅ Monitor the logs
- ✅ Watch for unexpected behavior
- ✅ Note response times
- ✅ Keep browser window open
- ✅ Don't start multiple attacks simultaneously

### After Completion

- ✅ Download and review report
- ✅ Analyze key findings
- ✅ Identify false positives
- ✅ Plan defensive improvements
- ✅ Archive reports for compliance

---

## Security Reminders

⚠️ **IMPORTANT**

- ✅ Only test systems you own or have explicit permission to test
- ✅ Use in closed sandbox/lab environments
- ✅ Don't expose web UI to public internet (firewall it)
- ✅ Don't test production systems unless authorized
- ✅ Use for defensive purposes only

This is a **defensive security testing tool**.

---

## File Structure

```
offensive_emulator/
├── run_web_ui.py              # Launcher script (START HERE)
├── api.py                      # FastAPI backend
├── static/
│   └── index.html             # Web UI frontend
├── config.py                   # Configuration system
├── adaptive_learning.py        # Learning module
├── evasion.py                  # Evasion tactics
├── metrics.py                  # Metrics collection
├── requirements.txt            # Python dependencies
└── offensive_emulator_unified.py  # Main attack orchestrator
```

---

## Performance Tips

**For Faster Attacks:**
- Use AGGRESSIVE or MAXIMUM profile
- Reduce target response time (network optimization)
- Close unnecessary applications
- Run on dedicated hardware

**For Stealthier Attacks:**
- Use STEALTH profile
- Enable all evasion tactics
- Distribute over longer time
- Use custom timing jitter

**For Better Accuracy:**
- Use BALANCED profile (recommended)
- Enable adaptive learning
- Run multiple times to compare
- Review detailed logs

---

## Support & Debugging

### Enable Debug Logging

Restart UI with debug level:
```bash
uvicorn api:app --log-level debug
```

### Check API Health

Visit: http://localhost:8000/api/health

Should return:
```json
{"status": "ok", "version": "3.0"}
```

### View Full API Documentation

Visit: http://localhost:8000/docs

Swagger UI with all endpoints and try-it-out functionality.

---

## Next Steps

1. **Set up lab environment** with target application
2. **Run first attack** using BALANCED profile
3. **Review findings** and understand output
4. **Iterate on defenses** based on results
5. **Retest** after fixes to verify improvements

---

## Useful References

- `README.md` - Full platform documentation
- `ENHANCEMENTS.md` - Advanced modules and features
- `CONSOLIDATION_GUIDE.md` - Architecture overview
- `config.py` - All configuration options
- `api.py` - Available API endpoints

---

**Happy testing!** 🎯

This web UI puts complete red team simulation capability at your fingertips.
