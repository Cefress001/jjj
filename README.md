# ⚔ Offensive Emulator v4 — Unified App

An autonomous red-team simulation platform rebuilt as **one app**:
a cinematic 3D landing page that opens into a live **3D mission console**,
where a six-phase kill chain executes against a target and renders in real time.

```
python run.py
```

That's the whole story — one entry point, one server, one UI.
Open <http://localhost:8000>, press **LAUNCH CONSOLE**, and fire.

---

## What it does

| | |
|---|---|
| **Landing page** | 3D attack-core hero (Three.js, WebGL). Click **LAUNCH CONSOLE** to warp into the app. |
| **Mission console** | Interactive 3D kill-chain: drag to orbit, scroll to zoom, hover/click phase nodes. Live terminal, phase telemetry, HUD, target-side request counter. |
| **6-phase engine** | Recon → Exploit → Persistence → Lateral Movement → Exfiltration → Cover Tracks, with state-dependent gating (a failed phase skips its dependents, like a real attack). |
| **Real or simulated** | With `aiohttp` installed the engines fire **real HTTP requests**. Without it, a zero-dependency simulator produces the same telemetry and reports. |
| **Built-in demo target** | **VulnPay** — a deliberately vulnerable mock SaaS API served at `/demo`. Zero setup: the console pre-fills it as the target. |
| **Reports** | Threat report modal (severity, chain success ring, findings, impact metrics) + downloadable standalone HTML/JSON reports. |
| **CLI mode** | `python run.py --target URL` runs a headless attack and saves `threat_report_<run>.json`. |

## Quick start

```bash
# no dependencies required — simulation engine
python run.py                 # → http://localhost:8000

# optional: real HTTP attack engines
pip install aiohttp
python run.py
```

In the console:

1. **Target** — keep the built-in demo (`http://localhost:8000/demo`) or point at a target you own.
2. **Profile** — pick an aggressiveness preset (below).
3. **INITIATE ATTACK** — watch the 3D chain light up phase by phase, logs streaming live.
4. When the run completes, the threat report opens automatically.

## Attack profiles

| Profile | Behaviour | Best for |
|---|---|---|
| 🟢 **Stealth** | slow, quiet, maximum evasion | testing detection/evasion |
| 🔵 **Balanced** *(recommended)* | normal speed, standard tactics | general assessment |
| 🟡 **Aggressive** | fast, concurrent, noisy | stress testing |
| 🔴 **Maximum** | full speed, no evasion | benchmarking |

## The kill chain

1. **01 · Reconnaissance** — endpoint enumeration, tech-stack fingerprinting, hidden admin routes
2. **02 · Exploitation** — JWT tampering, race conditions, promo bypass, privilege escalation
3. **03 · Persistence** — hidden admin accounts, API keys, webhooks, cron backdoors
4. **04 · Lateral Movement** — database/cloud credentials, SSH keys, internal service discovery
5. **05 · Exfiltration** — bulk user export, transaction dumps, sensitive file extraction
6. **06 · Cover Tracks** — log deletion, audit purge, false-flag attribution

Each phase feeds the next: no access → no persistence → no lateral movement → no exfiltration.

## One app — architecture

```
run.py                          ← THE entry point (server or headless CLI)
offensive_emulator/
├── app_server.py               ← unified server: UI + API + demo target (stdlib only)
├── attack_service.py           ← run manager: threads, progress, log streaming, cancel
├── simulator.py                ← zero-dependency simulation engine (fallback)
├── demo_target.py              ← built-in vulnerable "VulnPay" app + telemetry
├── offensive_emulator_unified.py  ← 6-phase orchestrator (real engines)
├── attack_modules/             ← the real per-phase HTTP attack engines
├── config.py · evasion.py · metrics.py · adaptive_learning.py
└── static/                     ← landing + console (HTML/CSS/JS + vendored Three.js)
```

### HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | status, engine mode, demo target URL |
| `GET` | `/api/configs` | phases + profile presets |
| `POST` | `/api/attack/start` | `{target, preset}` → new run |
| `GET` | `/api/attack/{id}/status?after=N` | live status + logs since cursor `N` |
| `POST` | `/api/attack/{id}/cancel` | abort a run |
| `GET` | `/api/attack/{id}/report` | JSON threat report |
| `GET` | `/api/attack/{id}/report.html` | standalone HTML report (download) |
| `GET` | `/api/attack/list` | run history |
| `GET` | `/api/demo/stats` | requests received by the demo target |

## ⚠ Ethics

This is a **defensive security testing tool**.

- ✅ Test only systems **you own** or are **authorized** to assess
- ✅ Use in closed sandbox/lab environments
- ❌ Never point it at production systems without written authorization

The built-in demo target exists so you always have something safe to attack.
