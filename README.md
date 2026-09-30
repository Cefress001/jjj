# ⚔ Offensive Emulator v4.1 — Unified App

An autonomous red-team simulation platform rebuilt as **one app**:
a cinematic 3D landing page that opens into a live **3D mission console**,
where a six-phase kill chain executes against a target and renders in real time.

```
python run.py
```

That's the whole story — one entry point, one server, one UI.
Open <http://localhost:8000>, press **LAUNCH CONSOLE**, and fire.

---

## What's in v4.1 (the premium pass)

**Console experience**
- **Director camera** — during a run the camera auto-glides to the live phase; any drag hands control back (`D` to toggle)
- **Network inspector** — every request the engines fire, live: method, path, status, latency, filterable; defense blocks flagged 🛡
- **Mission replay** — DVR scrubber under the 3D stage: replay any completed run's terminal, traffic and 3D phase states at 1×/2×/4× (`R`)
- **Sound design** — synthesized launch rumble, phase ticks, defense alarms, completion chimes (`M` to mute; no audio files, pure WebAudio)
- **Onboarding tour** — spotlight walkthrough on first visit (`?` for shortcuts, restartable)
- **Animated count-ups**, keyboard shortcuts (`Enter`, `1–6`, `D`, `R`, `M`, `Esc`, `?`)

**Depth**
- **Three demo difficulties** — EASY (full breach), HARDENED (JWT verified, secrets locked — breach contained), FORTIFIED (target holds). Defenses actually fire: 401/403/404/WAF/rate-limits, counted live
- **MITRE ATT&CK mapping** — every phase and report links its techniques (T1595, T1190, T1136, …)
- **Remediation engine** — prioritized, concrete fixes derived from what *actually succeeded* in each run
- **Run persistence + compare** — runs survive restarts (`data/runs/`); select any two in the archive for a side-by-side before/after-hardenening diff
- **Print-ready reports** — HTML report with print stylesheet + one-click Print/PDF
- **Verdicts** — "FULL BREACH / BREACH CONTAINED / TARGET HELD" at a glance

**Real-world targeting**
- **Pre-flight check** — dead targets fail in ~2s with a clear reason (unreachable / TLS / DNS) instead of silently grinding
- **Soft-404 detection** — many real sites serve the homepage for every unknown path (verified on a live target); the emulator probes a baseline once and filters catch-all responses so reports never contain fake endpoints/exploits/backdoors
- **Cloudflare challenge labeling** — WAF interstitials ("Just a moment…", Under-Attack mode, error-1020 WAF blocks, 1015 rate limits) are detected via the official `cf-mitigated` header and page fingerprints, and labeled distinctly: a challenge 403 is never counted as a "protected endpoint", the report carries a `waf` section (`provider` / `kind` / `requests_intercepted`), the log stream says so from preflight to the closing summary, and the WAF gets defense credit in the verdict
- **Browser User-Agent rotation** — real sites and WAFs block the default `aiohttp` fingerprint; every request now carries a realistic browser UA (caller-set UAs preserved)
- **Real-world timeouts** — engine timeouts raised (3–12s) for real internet latency
- **429 backoff guard** — rate-limiting targets can no longer stall the exfiltration phase
- **Liveness heartbeats** — "▸ 40 requests fired · avg 87ms" keeps the terminal alive during long phases
- **Accurate verdicts** — FULL BREACH / BREACH CONTAINED / ACCESS DENIED based on what actually happened

**Engineering**
- **Event backbone** — structured phase/request/defense events stream to the UI (cursor-based, like logs)
- **Request tracing** — one choke-point wrapper on `aiohttp.ClientSession` records every request; presets now pace *real* requests (stealth is actually slow)
- **Test suite** — `pytest` (66 tests) + a jsdom DOM integration test driving the real UI
- **Dockerfile** — `docker build -t offensive-emulator . && docker run -p 8000:8000 offensive-emulator`

## Development roadmap

See [`MASTER_BUILD_PLAN.md`](MASTER_BUILD_PLAN.md) for the phased plan covering
connected discovery, browser crawling, authentication, schema-driven API tests,
evidence and verification, policy enforcement, vulnerability intelligence,
regression scanning, and operator-defined business workflows.

Phases 1 and 2 are implemented: httpx establishes the canonical target; Katana,
Playwright, and ZAP feed a shared in-scope endpoint corpus; browser traffic is
imported into ZAP passive analysis; and Nuclei consumes a profile-bounded list
of discovered dynamic endpoints instead of scanning only the root URL. See
[`PHASE1_AUDIT.md`](PHASE1_AUDIT.md) for the Phase 1 hardening record and
[`PHASE2_AUDIT.md`](PHASE2_AUDIT.md) for browser safety, coverage, and validation
boundaries. The full container and real-Chromium acceptance smoke remain
release-runner gates.

## Quick start

```bash
# no dependencies required — simulation engine
python run.py                 # → http://localhost:8000

# optional: legacy VulnPay-specific HTTP checks
pip install aiohttp
python run.py
```

### Automatic multi-tool assessment

The standard Docker image includes five automatic assessment stages. They are
internal pipeline stages—not separate modes—so the interface remains one
target, one profile, one launch button, and one combined report:

- **httpx** — reachability, redirects, metadata, and technology profiling
- **Katana** — bounded same-domain crawling and endpoint discovery
- **Playwright + Chromium** — bounded rendered-DOM, fetch/XHR, form, resource,
  and WebSocket discovery for JavaScript applications
- **OWASP ZAP baseline** — crawling plus passive web-security analysis,
  including bounded browser HAR import
- **Nuclei** — signed/community template checks with DoS, fuzz, and intrusive
  tags excluded by policy

```bash
docker build -t offensive-emulator .
docker run --rm -p 8000:8000 offensive-emulator
```

Every installed tool runs automatically on every scan. Output streams into the
existing terminal; endpoints, technologies, ZAP alerts, Nuclei findings,
severity, evidence URLs, CWE/CVE metadata, and remediation are normalized and
deduplicated into the existing report/archive. A failure in one add-on is shown
in `scanner_results` but does not discard results from the other tools.

The app uses conservative per-profile rate limits and excludes explicitly
intrusive Nuclei tags. Browser discovery never submits forms, blocks non-read
HTTP methods, rejects destructive navigation terms, does not follow
cross-origin navigation, and applies page/depth/request/runtime/artifact caps.
These tools still make real requests, and ZAP's crawler can follow application
links. Scan only systems you own or have explicit permission to assess.

For a small simulation-only image:

```bash
docker build -f Dockerfile.lite -t offensive-emulator-lite .
```

When running directly instead of Docker, installed tools are auto-detected on
`PATH`; Playwright is enabled only when its Chromium executable is present.
Custom locations can be supplied through `HTTPX_COMMAND`, `KATANA_COMMAND`,
`BROWSER_COMMAND`, `NUCLEI_COMMAND`, and `ZAP_BASELINE_COMMAND`.

In the console:

1. **Target** — keep the built-in demo and pick a difficulty (EASY / HARDENED / FORTIFIED), or point at a target you own.
2. **Profile** — pick an aggressiveness preset (below).
3. **INITIATE ATTACK** — watch the 3D chain light up phase by phase; flip to the NETWORK tab to watch live traffic.
4. When the run completes: threat report (MITRE + remediation), replay (`R`), print/PDF, and compare against a later run from the archive.

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
Against HARDENED/FORTIFIED targets you'll watch the chain break — and see exactly where.

## One app — architecture

```
run.py                          ← THE entry point (server or headless CLI)
offensive_emulator/
├── app_server.py               ← unified server: UI + API + demo target (stdlib only)
├── attack_service.py               ← run manager: threads, event stream, tracing, persistence
├── scanner_pipeline.py             ← automatic five-stage scanner orchestration + merge
├── browser_adapter.py              ← isolated Playwright runner, cancellation, artifact bounds
├── browser_worker.py               ← safe same-host rendered/network discovery
├── pd_adapter.py · zap_adapter.py  ← safe subprocess runners + JSON/JSONL normalization
├── simulator.py                    ← zero-dependency simulation engine (fallback)
├── demo_target.py                  ← built-in vulnerable "VulnPay" app · 3 difficulty modes
├── remediation.py              ← MITRE mapping + remediation knowledge base
├── offensive_emulator_unified.py  ← 6-phase orchestrator (real engines)
├── attack_modules/             ← the real per-phase HTTP attack engines
├── config.py · evasion.py · metrics.py · adaptive_learning.py
├── data/runs/                  ← persisted runs (gitignored)
└── static/                     ← landing + console (HTML/CSS/JS + vendored Three.js)
tests/                          ← pytest suite + jsdom DOM integration test
Dockerfile
```

### HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | status, engine mode, demo target URL |
| `GET` | `/api/configs` | phases, presets, MITRE map, demo targets |
| `POST` | `/api/attack/start` | `{target, preset}` → new run |
| `GET` | `/api/attack/{id}/status?after=N&after_event=M` | live status + logs/events since cursors |
| `POST` | `/api/attack/{id}/cancel` | abort a run |
| `GET` | `/api/attack/{id}/report` | JSON threat report (MITRE, remediation, defense) |
| `GET` | `/api/attack/{id}/report.html?print=1` | standalone HTML report (auto-print) |
| `GET` | `/api/attack/list` | run history (incl. archived runs) |
| `GET` | `/api/demo/stats` | requests + defense blocks per demo mode |

### Tests

```bash
python -m pytest tests/ -q              # backend: modes, service, server, integrity
npm i jsdom && node tests/js/dom_flow.js  # frontend: full UI flow in a real DOM
```

## ⚠ Ethics

This is a **defensive security testing tool**.

- ✅ Test only systems **you own** or are **authorized** to assess
- ✅ Use in closed sandbox/lab environments
- ❌ Never point it at production systems without written authorization

The built-in demo target (three difficulty modes) exists so you always have something safe to attack.
