# Offensive Emulator v3 - Enhancement Modules

## Overview

Four powerful new modules have been added to strengthen the unified attack platform:

1. **Configuration System** (`config.py`)
2. **Advanced Adaptive Learning** (`adaptive_learning.py`)
3. **Defense Evasion** (`evasion.py`)
4. **Metrics & Analytics** (`metrics.py`)

---

## 1. Configuration System (`config.py`)

### Purpose
Customize attack behavior, aggressiveness, and tactics without code changes.

### Key Features

**Aggressiveness Levels:**
- `STEALTH` - Slow, quiet, evade detection
- `BALANCED` - Normal speed and tactics (default)
- `AGGRESSIVE` - Fast, concurrent, high noise
- `MAXIMUM` - Full speed, no evasion

**Customizable Parameters:**
```python
from config import AGGRESSIVE_CONFIG, AttackConfig, AggressivenessLevel

config = AttackConfig(
    aggressiveness=AggressivenessLevel.AGGRESSIVE,
    recon_concurrent_requests=20,
    exploit_jwt_attempts=5,
    exploit_max_retries=3,
    exfil_batch_size=5000,
    evasion_enabled=True,
    adaptive_learning_enabled=True,
)
```

### Configuration Categories

**Reconnaissance:**
- Wordlist size, timeout, concurrency

**Exploitation:**
- JWT attempts, race condition threads, retry logic

**Persistence:**
- Backdoor count, stealth delays, API key rotation

**Lateral Movement:**
- Credential patterns, extraction limits, discovery depth

**Exfiltration:**
- Batch size, rate limit handling, max data size, PII prioritization

**Cover Tracks:**
- Log deletion, artifact removal, false flag attribution

**Defense Evasion:**
- User agent rotation, request distribution, timing jitter, proxy rotation

**Adaptive Learning:**
- Enable/disable, mutation on failure, exploit prioritization

---

## 2. Advanced Adaptive Learning (`adaptive_learning.py`)

### Purpose
Learn from attack patterns, detect defenses, and dynamically adjust tactics.

### Key Components

**Defense Detector:**
Automatically detects 7 types of defenses:
- WAF (Web Application Firewall)
- RATE_LIMIT (429, throttling)
- AUTH_HARDENING (JWT/auth validation)
- DLP_SYSTEM (Data Loss Prevention)
- ANOMALY_DETECTION (Behavioral analysis)
- AUDIT_LOGGING (Immutable logs)
- CREDENTIAL_DETECTION (Secret scanning)

**Attack Learner:**
```python
from adaptive_learning import AttackLearner

learner = AttackLearner()

# Record each attack attempt
learner.record_attack(
    phase="exploit",
    method="jwt_tampering",
    success=True,
    response={"status": 200, "data": "admin_token"},
    payload={"token": "crafted_jwt"}
)

# Get best tactics for next attempt
best_tactics = learner.get_best_tactics("exploit", max_tactics=3)
# → ["jwt_tampering", "subscription_override", "promo_bypass"]

# Get evasion suggestions for detected defenses
defenses = learner.defense_detector.get_high_confidence_defenses(threshold=0.7)
evasion = learner.suggest_evasion([d[0] for d in defenses])
# → ["randomize_user_agent", "distribute_requests", "timing_jitter"]

# Get learning summary
summary = learner.get_learning_summary()
# {
#   "total_attempts": 45,
#   "phase_success_rates": {"recon": 0.95, "exploit": 0.78, ...},
#   "detected_defenses": {"WAF": {...}, "RATE_LIMIT": {...}},
#   "best_tactics": {"exploit": ["jwt_tampering", ...]}
# }
```

### Learning in Action

1. **Detect** - Automatically identifies defenses from responses
2. **Track** - Records which tactics work against which defenses
3. **Suggest** - Recommends best tactics and evasion methods
4. **Adapt** - Suggests payload mutations for failed attacks

---

## 3. Defense Evasion (`evasion.py`)

### Purpose
Bypass detection systems through sophisticated evasion techniques.

### Evasion Tactics

**User Agent Rotation:**
```python
from evasion import UserAgentRotation

headers = UserAgentRotation.get_realistic_headers()
# Realistic browser headers with randomized user agent
```

**Request Distribution:**
```python
from evasion import RequestDistribution

distributor = RequestDistribution(concurrent_limit=3, delay_ms=100)
results = await distributor.distribute_requests(requests)
# Distributes requests in batches with delays to evade rate limiting
```

**Payload Obfuscation:**
```python
from evasion import PayloadObfuscation

obfuscated = PayloadObfuscation.obfuscate_json(payload)
# Adds noise, random fields, timing info
# Makes payload harder to detect by DLP/SIEM

split = PayloadObfuscation.split_payload(payload)
# Splits into multiple requests to evade detection

encoded = PayloadObfuscation.encode_sensitive_values(payload)
# Encodes passwords/tokens/keys as hex
```

**Timing Evasion:**
```python
from evasion import TimingEvasion

await TimingEvasion.introduce_jitter(operation, jitter_ms=500)
# Random delay (0-500ms) before operation

await TimingEvasion.slow_execution(items, min_delay_ms=100, max_delay_ms=500)
# Slow, distributed execution
```

**URL Obfuscation:**
```python
from evasion import URLObfuscation

obscured = URLObfuscation.add_query_parameters(url, noise_params=5)
# Adds random query parameters

doubled = URLObfuscation.double_encode_payload(path)
# Double-encodes path components

unicode = URLObfuscation.unicode_encode(text)
# Encodes as unicode escape sequences
```

**Evasion Manager:**
```python
from evasion import EvasionManager

evasion = EvasionManager(config={
    "randomize_user_agents": True,
    "distribute_requests": True,
    "obfuscate_payloads": True,
    "jitter_timing": True,
    "rotate_ips": False,
})

headers = evasion.get_evasion_headers()
payload = evasion.obfuscate_payload(original_payload)
await evasion.distributed_delay()
```

---

## 4. Metrics & Analytics (`metrics.py`)

### Purpose
Track performance, success rates, and generate detailed reports.

### Key Components

**Phase Metrics:**
```python
from metrics import PhaseMetrics, MetricsCollector

# Automatically tracks per-phase:
# - Total/successful/failed attempts
# - Average duration
# - Defenses triggered
# - Evasion tactics used
# - Artifacts created
```

**Metrics Collector:**
```python
from metrics import MetricsCollector

collector = MetricsCollector(run_id="run_123", target="http://target.com")

# Record each attempt
collector.record_phase_attempt(
    phase="exploit",
    success=True,
    duration_ms=45.2,
    defense_triggered="RATE_LIMIT"
)

# Record artifacts
collector.record_artifact("persistence", "backdoor", count=1)
collector.record_artifact("lateral_movement", "credential", count=5)

# Record data theft
collector.record_data_theft(records=10000, data_mb=50.5, pii_count=500)

# Record evasion attempts
collector.record_evasion("exploit", "randomize_user_agent", success=True)

# Record cleanup
collector.record_cleanup(logs_deleted=5000, traces_remaining=0)

# Finalize and get summary
metrics = collector.finalize()
summary = collector.get_summary()
```

**Report Generation:**
```python
from metrics import ReportGenerator

# Generate HTML report
html_report = ReportGenerator.generate_html_report(metrics)
with open("report.html", "w") as f:
    f.write(html_report)

# Generate JSON report
json_report = ReportGenerator.generate_json_report(metrics)
with open("report.json", "w") as f:
    f.write(json_report)
```

### Metrics Tracked

**Per-Phase:**
- Success rate
- Attempt counts
- Duration (avg)
- Defenses triggered
- Evasion tactics used
- Artifacts created

**Attack-Wide:**
- Total duration
- Phases completed
- Overall success rate
- Records stolen
- Data exfiltrated
- Defenses detected
- Evasion success rate

---

## Integration Example

```python
from offensive_emulator_unified import UnifiedOffensiveEmulator
from config import AGGRESSIVE_CONFIG
from metrics import MetricsCollector
from adaptive_learning import AttackLearner
from evasion import EvasionManager

# Setup
config = AGGRESSIVE_CONFIG
learner = AttackLearner()
evasion = EvasionManager(config={
    "randomize_user_agents": True,
    "distribute_requests": True,
    "obfuscate_payloads": True,
})
metrics = MetricsCollector(run_id="attack_001", target="http://localhost:3004")

# Execute with enhancements
emulator = UnifiedOffensiveEmulator(
    target_url="http://localhost:3004",
    config=config,
    learner=learner,
    metrics=metrics,
    evasion=evasion,
)

report = await emulator.run_full_attack()

# Analyze results
print(metrics.get_summary())
print(learner.get_learning_summary())

# Generate reports
html = ReportGenerator.generate_html_report(metrics.metrics)
json_report = ReportGenerator.generate_json_report(metrics.metrics)
```

---

## Quick Start

### 1. Run with Custom Configuration
```python
from config import AttackConfig, AggressivenessLevel

config = AttackConfig(
    aggressiveness=AggressivenessLevel.AGGRESSIVE,
    exploit_concurrent_requests=15,
    evasion_enabled=True,
)
emulator = UnifiedOffensiveEmulator(target, config=config)
```

### 2. Enable Adaptive Learning
```python
from adaptive_learning import AttackLearner

learner = AttackLearner()
# Learner will auto-detect defenses and suggest tactics
```

### 3. Use Advanced Evasion
```python
from evasion import EvasionManager

evasion = EvasionManager()
# Automatically rotates user agents, obfuscates payloads, adds jitter
```

### 4. Track Detailed Metrics
```python
from metrics import MetricsCollector, ReportGenerator

metrics = MetricsCollector(run_id="test_run", target="http://localhost:3004")
# Collects all metrics automatically
# Generate HTML/JSON reports at end
```

---

## Architecture Benefits

✅ **Modular** - Each component is independent and reusable  
✅ **Configurable** - Customize without code changes  
✅ **Intelligent** - Learns and adapts in real-time  
✅ **Stealthy** - Multiple evasion techniques  
✅ **Observable** - Detailed metrics and reporting  
✅ **Resilient** - Retry logic, error handling  

---

## File Summary

| File | Purpose | Key Classes |
|------|---------|------------|
| `config.py` | Configuration management | `AttackConfig`, `AggressivenessLevel` |
| `adaptive_learning.py` | Adaptive learning & defense detection | `AttackLearner`, `DefenseDetector` |
| `evasion.py` | Defense evasion tactics | `EvasionManager`, `PayloadObfuscation`, `TimingEvasion` |
| `metrics.py` | Metrics collection & reporting | `MetricsCollector`, `ReportGenerator` |

---

## Next Steps

1. Update `offensive_emulator_unified.py` to integrate these modules
2. Add configuration to all 6 attack engines
3. Use learner to guide attack selection
4. Apply evasion tactics based on detected defenses
5. Collect metrics throughout execution
6. Generate HTML reports at end

All enhancements work together for a more powerful, adaptive, and stealthy red team platform.
