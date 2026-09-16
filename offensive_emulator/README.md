# Offensive Emulator v3 - Unified Red Team Simulation Platform

**A complete, cohesive closed-loop red team platform for testing your defensive security.**

- ✅ Real HTTP-based attack simulation
- ✅ 6 integrated attack phases (Recon → Exploit → Persist → Lateral → Exfil → Cover)
- ✅ Unified state threading through all phases
- ✅ Advanced adaptive learning
- ✅ Defense evasion tactics
- ✅ Comprehensive metrics and reporting
- ✅ Configurable aggressiveness levels

---

## Quick Start

### Installation

```bash
git clone https://github.com/Cefress001/jjj.git
cd jjj/offensive_emulator
pip install aiohttp
```

### Run a Basic Attack

```python
import asyncio
from offensive_emulator_unified import UnifiedOffensiveEmulator

async def main():
    emulator = UnifiedOffensiveEmulator(
        target_url="http://localhost:3004"
    )
    report = await emulator.run_full_attack()
    emulator.print_report(report)

asyncio.run(main())
```

### Run with Custom Configuration

```python
from config import AGGRESSIVE_CONFIG

emulator = UnifiedOffensiveEmulator(
    target_url="http://localhost:3004",
    config=AGGRESSIVE_CONFIG  # STEALTH, BALANCED, AGGRESSIVE, MAXIMUM
)
report = await emulator.run_full_attack()
```

---

## Core Architecture

### Unified Attack Context

All phases share a single `AttackContext` object that flows through the attack chain:

```
Recon discovers endpoints
    ↓
Exploit uses discovered endpoints, gains access
    ↓ (requires successful exploit)
Persistence establishes backdoors
    ↓ (requires persistence)
Lateral Movement extracts credentials
    ↓ (requires credentials)
Exfiltration steals data using extracted credentials
    ↓
Cover Tracks hides all evidence
```

### 6 Real Attack Engines

| Phase | Purpose | Techniques |
|-------|---------|-----------|
| **Recon** | Discover attack surface | Endpoint enumeration, tech stack fingerprinting, hidden route detection |
| **Exploit** | Gain initial access | JWT tampering, race conditions, promo bypass, privilege escalation |
| **Persistence** | Maintain access | Hidden admin accounts, API key injection, webhooks, cron jobs |
| **Lateral Movement** | Pivot to other systems | Credential extraction, service discovery, SSH/cloud credential theft |
| **Exfiltration** | Steal data | Bulk user export, transaction dumps, sensitive files, cache poisoning |
| **Cover Tracks** | Hide evidence | Log deletion, audit trail removal, false flag attribution, artifact erasure |

---

## Enhancement Modules

### 1. Configuration System

Customize attack behavior without code changes:

```python
from config import AttackConfig, AggressivenessLevel

config = AttackConfig(
    aggressiveness=AggressivenessLevel.AGGRESSIVE,
    recon_concurrent_requests=20,
    exploit_jwt_attempts=5,
    exploit_max_retries=3,
    evasion_enabled=True,
    adaptive_learning_enabled=True,
)
```

**Aggressiveness Profiles:**
- `STEALTH` - Slow, quiet, evade detection
- `BALANCED` - Normal speed (default)
- `AGGRESSIVE` - Fast, concurrent, high noise
- `MAXIMUM` - Full speed, no evasion

### 2. Advanced Adaptive Learning

Learns from attacks and adapts tactics:

```python
from adaptive_learning import AttackLearner

learner = AttackLearner()

# Automatically detects defenses:
# - WAF detection
# - Rate limiting
# - Auth hardening
# - DLP systems
# - Anomaly detection
# - Audit logging
# - Credential detection

# Suggests best tactics and evasion methods
best_tactics = learner.get_best_tactics("exploit")
evasion = learner.suggest_evasion(["WAF", "RATE_LIMIT"])
```

### 3. Defense Evasion

Multiple tactics to bypass detection:

```python
from evasion import EvasionManager

evasion = EvasionManager(config={
    "randomize_user_agents": True,      # Rotate browser user agents
    "distribute_requests": True,         # Spread requests over time
    "obfuscate_payloads": True,          # Add noise to payloads
    "jitter_timing": True,               # Random delays
    "rotate_ips": False,                 # IP rotation (if proxies configured)
})

headers = evasion.get_evasion_headers()
payload = evasion.obfuscate_payload(original)
await evasion.distributed_delay()
```

**Evasion Tactics:**
- User agent rotation
- Payload obfuscation
- Timing jitter and distribution
- URL encoding/case variation
- Request splitting and batching
- IP rotation (with proxies)

### 4. Metrics & Analytics

Track everything and generate reports:

```python
from metrics import MetricsCollector, ReportGenerator

collector = MetricsCollector(run_id="test_1", target="http://localhost:3004")

# Automatically collects:
# - Per-phase success rates
# - Artifact creation
# - Data theft metrics
# - Evasion effectiveness
# - Defenses detected

# Generate reports
html_report = ReportGenerator.generate_html_report(collector.metrics)
json_report = ReportGenerator.generate_json_report(collector.metrics)
```

---

## Usage Examples

### Example 1: Stealthy Assessment

```python
import asyncio
from config import STEALTH_CONFIG
from adaptive_learning import AttackLearner
from evasion import EvasionManager
from metrics import MetricsCollector

async def stealthy_test():
    config = STEALTH_CONFIG
    learner = AttackLearner()
    evasion = EvasionManager()
    metrics = MetricsCollector("stealth_run", "http://target.com")
    
    emulator = UnifiedOffensiveEmulator(
        target_url="http://target.com",
        config=config,
        learner=learner,
        evasion=evasion,
        metrics=metrics,
    )
    
    report = await emulator.run_full_attack()
    print(f"Evasion success rate: {metrics.get_summary()['evasion_success_rate']}")
    
asyncio.run(stealthy_test())
```

### Example 2: Aggressive Assessment

```python
from config import AGGRESSIVE_CONFIG

emulator = UnifiedOffensiveEmulator(
    target_url="http://localhost:3004",
    config=AGGRESSIVE_CONFIG  # Fast, concurrent, high noise
)

report = await emulator.run_full_attack()
print(f"Total time: {report['total_time_seconds']:.1f}s")
print(f"Success rate: {report['summary']['attack_success_rate']}")
```

### Example 3: Learning-Focused Run

```python
from adaptive_learning import AttackLearner

learner = AttackLearner()
emulator = UnifiedOffensiveEmulator(target, learner=learner)
await emulator.run_full_attack()

# Analyze what we learned
summary = learner.get_learning_summary()
print("Best exploit tactics:", summary['best_tactics']['exploit'])
print("Detected defenses:", summary['detected_defenses'])
```

### Example 4: Generate Detailed Reports

```python
from metrics import MetricsCollector, ReportGenerator

collector = MetricsCollector("report_test", "http://localhost:3004")
emulator = UnifiedOffensiveEmulator(target, metrics=collector)
await emulator.run_full_attack()

# HTML report
html = ReportGenerator.generate_html_report(collector.finalize())
with open("report.html", "w") as f:
    f.write(html)

# JSON report
json_report = ReportGenerator.generate_json_report(collector.finalize())
with open("report.json", "w") as f:
    f.write(json_report)
```

---

## Architecture Deep Dive

### Attack Phase Dependency Chain

```python
# Phase 1: Recon (no dependencies)
context.discovered_endpoints = [...]  # Discovers endpoints
context.tech_stack = {...}            # Identifies tech stack

# Phase 2: Exploit (requires Phase 1)
if not context.discovered_endpoints:
    skip()  # Can't exploit without knowing what to attack

context.access_granted = True           # Gains access
context.valid_tokens = {...}            # Captures tokens

# Phase 3: Persistence (requires Phase 2)
if not context.access_granted:
    skip()  # Can't persist without initial access

context.backdoors_installed = [...]     # Creates backdoors
context.admin_accounts = [...]          # Creates hidden accounts

# Phase 4: Lateral Movement (requires Phase 3)
if not context.persistence_achieved:
    skip()  # Can't move laterally without persistence

context.extracted_credentials = [...]   # Finds credentials
context.discovered_services = [...]     # Finds internal services

# Phase 5: Exfiltration (requires Phase 4)
if not context.extracted_credentials:
    skip()  # Can't exfiltrate without credentials

context.records_stolen = 10000          # Steals data
context.data_exfiltrated_mb = 500.5     # Tracks volume

# Phase 6: Cover Tracks (runs regardless)
context.logs_deleted = 5000             # Hides evidence
context.traces_visible = False          # Cleans up
```

### Unified Context Flow

```python
@dataclass
class AttackContext:
    target_url: str
    run_id: str
    
    # Populated by Recon
    discovered_endpoints: List[str]
    tech_stack: Dict[str, str]
    
    # Updated by Exploit
    access_granted: bool
    valid_tokens: Dict[str, str]
    
    # Updated by Persistence
    persistence_achieved: bool
    backdoors_installed: List[Dict]
    
    # Updated by Lateral Movement
    extracted_credentials: List[Dict]
    discovered_services: List[str]
    
    # Updated by Exfiltration
    records_stolen: int
    data_exfiltrated_mb: float
    
    # Updated by Cover Tracks
    logs_deleted: int
    traces_visible: bool
    
    # Updated by all phases
    phase_timings: Dict[str, float]
```

---

## Supported Attacks

### Reconnaissance
- ✅ Endpoint enumeration (1000+ paths)
- ✅ Tech stack fingerprinting
- ✅ Hidden route detection
- ✅ Response baseline establishment

### Exploitation
- ✅ JWT token tampering (algorithm confusion, signature stripping)
- ✅ Subscription override (race conditions)
- ✅ Promo code validation bypass
- ✅ Privilege escalation (role tampering)

### Persistence
- ✅ Hidden admin account creation
- ✅ API key injection
- ✅ Webhook persistence (C2 callbacks)
- ✅ Cron job backdoors

### Lateral Movement
- ✅ Database credential extraction
- ✅ Service discovery
- ✅ SSH key harvesting
- ✅ Cloud credential theft (AWS, GCP, Azure)

### Exfiltration
- ✅ Bulk user export (API pagination)
- ✅ Transaction/payment history dump
- ✅ Sensitive file extraction
- ✅ Cache poisoning for data leakage

### Cover Tracks
- ✅ Log deletion and tampering
- ✅ Audit trail removal
- ✅ False flag attribution
- ✅ Artifact and staging area erasure

---

## Configuration Reference

See `config.py` for all available options:

```python
from config import AttackConfig

config = AttackConfig(
    # Aggressiveness
    aggressiveness=AggressivenessLevel.BALANCED,
    
    # Recon
    recon_wordlist_size=100,
    recon_timeout_seconds=5,
    recon_concurrent_requests=5,
    
    # Exploit
    exploit_jwt_attempts=5,
    exploit_race_condition_threads=10,
    exploit_timeout_seconds=10,
    exploit_max_retries=3,
    
    # Persistence
    persistence_backdoor_count=3,
    persistence_api_key_rotation=True,
    
    # Lateral Movement
    lateral_max_creds_extract=50,
    
    # Exfiltration
    exfil_batch_size=1000,
    exfil_max_data_mb=1000,
    exfil_prioritize_pii=True,
    
    # Defense Evasion
    evasion_enabled=True,
    evasion_randomize_user_agents=True,
    evasion_distribute_requests=True,
    evasion_timing_jitter_ms=500,
    
    # Adaptive Learning
    adaptive_learning_enabled=True,
    adaptive_mutation_on_failure=True,
)
```

---

## Output & Reporting

### Console Output

```
================================================================================
[PHASE 1] RECONNAISSANCE
================================================================================
✓ RECON COMPLETE (2.34s)
  Endpoints discovered: 47
  Tech stack: {'server': 'nginx', 'framework': 'Next.js', 'language': 'Node.js'}
  Hidden routes found: 12

================================================================================
[PHASE 2] EXPLOITATION
================================================================================
✓ EXPLOITATION SUCCESSFUL (1.56s)
  Methods exploited: ['jwt_tampering', 'subscription_override']
  Valid tokens: 1

================================================================================
[PHASE 3] PERSISTENCE
================================================================================
✓ PERSISTENCE ESTABLISHED (0.89s)
  Backdoors installed: 3
  Admin accounts created: ['system_admin', 'backup_user']

[...more phases...]

SUMMARY
────────────────────────────────────────────────────────────────────────────
  Success Rate: 85.3%
  Severity: High
  Key Findings:
  • Discovered 47 endpoints
  • Exploited via JWT tampering and race conditions
  • Created 3 backdoors
  • Extracted 12 credentials
  • Stole 50,000 records / 250.5 MB
  • Evaded detection: True
```

### HTML Report

Generated automatically with:
- Summary metrics
- Per-phase success rates
- Attack impact assessment
- Defense detections
- Timeline and duration

### JSON Report

Complete structured output for programmatic analysis:
- All metrics in JSON format
- Integration with external tools
- Data export and archiving

---

## Integration with Defenses

This tool helps you:

1. **Identify** - What defenses are actually protecting your systems?
2. **Test** - Do your defenses work against real attack chains?
3. **Strengthen** - What gaps exist? What needs improvement?
4. **Validate** - Are detection systems working?
5. **Train** - Use realistic attack patterns for security team training

---

## Security & Ethics

⚠️ **IMPORTANT:**

- ✅ Use only on **systems you own or have explicit authorization to test**
- ✅ Run in a **closed sandbox/lab environment**
- ✅ Use for **defensive security purposes only**
- ❌ Do NOT use against systems you don't own
- ❌ Do NOT use for malicious purposes
- ❌ Do NOT use to evade defenses of others' systems

This is a **defensive testing tool** for hardening your own infrastructure.

---

## Documentation

- `CONSOLIDATION_GUIDE.md` - Architecture and unified design
- `ENHANCEMENTS.md` - Details on all new modules
- `IMPLEMENTATION_SUMMARY.md` - Original implementation details
- `QUICK_START.md` - Quick reference guide

---

## File Structure

```
offensive_emulator/
├── offensive_emulator_unified.py      # Main orchestrator
├── attack_modules/
│   ├── base.py                        # Base classes & AttackContext
│   ├── recon_engine.py                # Phase 1
│   ├── exploit_engine.py              # Phase 2
│   ├── persistence_engine.py          # Phase 3
│   ├── lateral_movement_engine.py     # Phase 4
│   ├── exfiltration_engine.py         # Phase 5
│   └── cover_tracks_engine.py         # Phase 6
├── config.py                          # Configuration system
├── adaptive_learning.py               # Adaptive learning
├── evasion.py                         # Defense evasion
├── metrics.py                         # Metrics & reporting
├── examples/
│   ├── run_emulator.py               # Basic example
│   └── run_emulator_api.py           # API example
└── README.md                          # This file
```

---

## Performance & Optimization

**Concurrency:**
- Stealth: 1-2 concurrent requests
- Balanced: 5-10 concurrent requests
- Aggressive: 20-50 concurrent requests
- Maximum: 50+ concurrent requests

**Typical Execution Times:**
- Stealth profile: 2-5 minutes
- Balanced profile: 30-60 seconds
- Aggressive profile: 10-30 seconds
- Maximum profile: 5-10 seconds

**Resource Usage:**
- Memory: ~50-200 MB
- Network: Varies by config (100KB - 1GB)
- CPU: Minimal (mostly I/O bound)

---

## Troubleshooting

### Connection Refused
- Ensure target is running and accessible
- Check firewall rules
- Verify URL format (http:// vs https://)

### No Endpoints Found
- Target app may not be responding
- Endpoints may require authentication
- Recon engine timeout too short

### Defenses Blocking All Requests
- WAF may be too aggressive
- Try STEALTH configuration
- Enable evasion tactics
- Check rate limiting settings

### No Data Exfiltrated
- May need to extract credentials first
- Check if exfiltration endpoints exist
- Verify data is accessible

---

## Contributing

Enhancements welcome! Potential areas:
- Additional evasion techniques
- More attack vectors
- Better defense detection
- Enhanced reporting
- Performance optimizations

---

## License

For authorized security testing use only.

---

## Support

For issues or questions:
1. Check documentation files
2. Review example code
3. Enable verbose logging
4. Check metrics for detailed insights

---

## Version History

- **v3.0** - Unified cohesive platform with state threading
- **v3.1** - Added configuration system
- **v3.2** - Added adaptive learning & defense detection
- **v3.3** - Added defense evasion tactics
- **v3.4** - Added metrics & reporting

---

**Built for cybersecurity professionals who take defense seriously.**
