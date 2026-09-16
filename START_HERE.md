# 🚀 Offensive Emulator v3 - START HERE

## Welcome!

You now have a **complete, production-ready red team simulation platform** that you can run entirely on your own without any AI assistance.

This guide gets you up and running in 5 minutes.

---

## What You Have

✅ **Unified Attack Platform** - All 6 attack phases integrated  
✅ **Web UI Dashboard** - No CLI needed, just point and click  
✅ **Real-time Monitoring** - Watch attacks as they happen  
✅ **Adaptive Learning** - System learns and optimizes attacks  
✅ **Defense Evasion** - Multiple tactics to bypass detection  
✅ **Comprehensive Reporting** - HTML and JSON reports  
✅ **Configuration System** - 4 aggressiveness profiles  

---

## Installation (2 Minutes)

### 1. Install Python Dependencies

```bash
cd offensive_emulator
pip install -r requirements.txt
```

That's it! Three packages:
- `fastapi` - Web framework
- `uvicorn` - Web server
- `aiohttp` - HTTP client

### 2. Start the Web UI

**Windows:**
```bash
python run_web_ui.py
```

**Mac/Linux:**
```bash
python3 run_web_ui.py
```

Expected output:
```
╔════════════════════════════════════════════════════════════════╗
║   Offensive Emulator v3 - Web API                              ║
║   http://localhost:8000                                        ║
║                                                                ║
║   - Web UI:   http://localhost:8000/                          ║
║   - API Docs: http://localhost:8000/docs                      ║
║   - WebSocket: ws://localhost:8000/ws/{run_id}                ║
╚════════════════════════════════════════════════════════════════╝
```

Browser should open automatically at: **http://localhost:8000**

---

## First Attack (3 Minutes)

### Step 1: Enter Target URL

In the web UI, in the "Configure Attack" panel:
- **Target URL**: `http://localhost:3004` (or your app)

### Step 2: Choose Profile

Select aggressiveness:
- **Balanced** ← Start here (recommended)
  - Normal speed, good for initial testing
  - 30-60 seconds execution time
  - Standard evasion tactics enabled

### Step 3: Click Start

Click **"▶ Start Attack"** button

### Step 4: Watch it Run

- Progress bar shows completion %
- Status badge shows current state
- Live logs stream in real-time
- Watch which phase is executing

### Step 5: Review Results

When complete:
- Status changes to "Complete"
- Download HTML report button appears
- View summary with key findings

---

## Understanding Your Results

### Report Metrics

**Success Rate**
- Shows how effective the attack was
- Higher = better penetration

**Severity**
- Critical: Major vulnerabilities found
- High: Serious weaknesses
- Medium: Notable issues
- Low: Minor findings

**Key Findings**
- What endpoints were discovered
- What exploits succeeded
- How much data was accessed
- Whether detection was evaded

---

## Attack Profiles Explained

### 🟢 STEALTH (Slow & Sneaky)
```
Duration:     2-5 minutes
Speed:        1-2 requests/sec
Evasion:      Maximum
Best for:     Avoiding detection, stealth testing
```

### 🟡 BALANCED (Recommended)
```
Duration:     30-60 seconds
Speed:        5-10 requests/sec
Evasion:      Standard
Best for:     General assessment, initial testing
```

### 🔴 AGGRESSIVE (Fast)
```
Duration:     10-30 seconds
Speed:        20-50 requests/sec
Evasion:      Basic
Best for:     Quick testing, stress testing
```

### ⚫ MAXIMUM (Full Speed)
```
Duration:     5-10 seconds
Speed:        50+ requests/sec
Evasion:      None
Best for:     Extreme stress, benchmark testing
```

---

## What Each Attack Phase Does

### 🔍 Reconnaissance (Phase 1)
Discovers:
- API endpoints (500+ paths tested)
- Tech stack (framework, server, CDN)
- Hidden routes (admin panels, debug endpoints)
- Response patterns (for later detection)

### ⚡ Exploitation (Phase 2)
Attempts:
- JWT token tampering
- Subscription override via race conditions
- Promo code validation bypass
- Privilege escalation

**Requires**: Initial discovery from Recon

### 🔓 Persistence (Phase 3)
Establishes:
- Hidden admin accounts
- API keys for backdoor access
- Webhooks for C2 callbacks
- Cron job backdoors

**Requires**: Successful Exploit phase

### 🔀 Lateral Movement (Phase 4)
Extracts:
- Database credentials from code/config
- SSH keys and certificates
- Cloud provider credentials (AWS, GCP, Azure)
- Internal service endpoints

**Requires**: Persistence to be established

### 📊 Exfiltration (Phase 5)
Steals:
- User databases (bulk export via API)
- Transaction/payment history
- Sensitive files (.env, .git config, etc)
- Cache poisoning for data leakage

**Requires**: Credentials from Lateral Movement

### 🧹 Cover Tracks (Phase 6)
Removes evidence:
- Delete logs and audit trails
- Remove artifacts and staging files
- Create false flag attributions
- Evade forensic detection

**Works with**: All artifacts from previous phases

---

## Why Each Phase Depends on the Previous

```
Recon discovers endpoints
    ↓
Exploit uses discovered endpoints
    ↓
Persistence requires exploit success
    ↓
Lateral Movement requires persistence
    ↓
Exfiltration uses extracted credentials
    ↓
Cover Tracks cleans up everything
```

This **chain is realistic** - matches real attack progression.

---

## Tips for Better Testing

### Test Multiple Profiles

Run each profile against your app:
1. Start with BALANCED (see if defenses work)
2. Try STEALTH (test evasion capabilities)
3. Try AGGRESSIVE (test under stress)
4. Compare results

### Monitor Your Logs

Watch application logs during attack:
- See what requests come in
- Check if detection alerts fire
- Verify cleanup effectiveness
- Identify blind spots

### Document Baselines

Before testing:
- Note current metrics
- Screenshot configurations
- Document defense status

After testing:
- Compare baseline to attack results
- Measure defense effectiveness
- Plan improvements

### Iterate on Defenses

1. Run attack, note findings
2. Implement one fix
3. Run again to verify it worked
4. Repeat

---

## Troubleshooting

### "Connection refused" on start

**Fix**: Make sure `python run_web_ui.py` is actually running

### Browser doesn't open

**Fix**: Manually go to http://localhost:8000

### Attack never starts

**Fix**: Check target URL is correct and accessible

### No endpoints found

**Fix**: 
- Verify target URL works in browser
- Check firewall isn't blocking requests
- Try STEALTH profile (longer scan)

### "Module not found" errors

**Fix**: 
```bash
pip install -r requirements.txt
```

### Port 8000 already in use

**Fix**: 
```bash
python run_web_ui.py --port 8001
```

---

## Common Use Cases

### Use Case 1: Quick Security Check
```
Profile: BALANCED
Duration: ~1 minute
Purpose: Initial assessment
```

### Use Case 2: Comprehensive Testing
```
Profile: STEALTH
Duration: ~5 minutes
Purpose: Thorough evaluation
```

### Use Case 3: Performance Stress Test
```
Profile: MAXIMUM
Duration: ~10 seconds
Purpose: Load/stress testing
```

### Use Case 4: Evasion Testing
```
Profile: STEALTH (evasion enabled)
Duration: ~5 minutes
Purpose: Test detection systems
```

---

## File Guide

### 📍 Main Entry Points

| File | Purpose | Run With |
|------|---------|----------|
| `run_web_ui.py` | **Start here** - Web UI launcher | `python run_web_ui.py` |
| `offensive_emulator_unified.py` | CLI version (advanced) | `python offensive_emulator_unified.py` |

### 📚 Documentation

| File | Contains |
|------|----------|
| `README.md` | Complete platform documentation |
| `WEB_UI_GUIDE.md` | Detailed web UI instructions |
| `ENHANCEMENTS.md` | Advanced features and modules |
| `CONSOLIDATION_GUIDE.md` | Architecture and design |

### ⚙️ Configuration

| File | Purpose |
|------|---------|
| `config.py` | Attack configuration system |
| `adaptive_learning.py` | AI learning module |
| `evasion.py` | Defense evasion tactics |
| `metrics.py` | Metrics and reporting |

### 🌐 Web Interface

| File | Purpose |
|------|---------|
| `api.py` | FastAPI backend |
| `static/index.html` | Web dashboard UI |

---

## Next Steps

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Start web UI**
   ```bash
   python run_web_ui.py
   ```

3. **Open browser**
   - Should open automatically to http://localhost:8000
   - If not, go there manually

4. **Run first attack**
   - Enter your target URL
   - Select "Balanced" profile
   - Click Start
   - Watch the progress and logs

5. **Review results**
   - Download HTML report when complete
   - Analyze findings
   - Plan defensive improvements

6. **Iterate**
   - Fix vulnerabilities
   - Re-test to verify
   - Document improvements

---

## Need More Help?

### Quick Questions
- See `WEB_UI_GUIDE.md` for web UI help
- Check `README.md` for platform overview
- View `ENHANCEMENTS.md` for advanced features

### Troubleshooting
- Check browser console (F12) for errors
- Look at API docs at http://localhost:8000/docs
- Try different profile if attack hangs
- Restart `run_web_ui.py` if UI acts strange

### Want to Customize?
- Edit `config.py` for attack parameters
- Modify `static/index.html` for UI changes
- Extend `api.py` for new endpoints
- See code comments for details

---

## Important Reminders

⚠️ **Security & Ethics**

- ✅ Only test **systems you own or have permission to test**
- ✅ Use in **closed sandbox/lab environments**
- ✅ Use for **defensive purposes only**
- ✅ Never test **production systems** without authorization
- ✅ Never use against **systems you don't own**

This is a **defensive testing tool** for hardening your own infrastructure.

---

## You're Ready! 🎯

Everything is set up and ready to go:

1. ✅ Real attack simulation
2. ✅ Web UI interface
3. ✅ All tools functioning
4. ✅ Run entirely on your own
5. ✅ No AI assistance needed

**Go test your defenses!**

```bash
python run_web_ui.py
```

Then open http://localhost:8000

---

**Happy testing!** 🚀
