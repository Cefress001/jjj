# Offensive Emulator v3 Ultra - Quick Start Guide

## Installation

No additional dependencies required beyond existing nexus-core setup. Uses Python's asyncio and aiohttp (already available).

## Running the Platform

### Option 1: Example Script (Easiest)

```bash
cd backend
python examples/run_emulator.py
```

Output includes:
- Per-phase attack progress
- Success rates by persona
- Vulnerabilities discovered
- Business impact estimates
- JSON threat report

### Option 2: Python REPL

```python
import asyncio
import sys
sys.path.insert(0, 'backend')

from offensive_emulator_v3 import OffensiveEmulatorV3, AttackerPersona

async def demo():
    # Test against your app
    emulator = OffensiveEmulatorV3(
        target_url="http://localhost:3004",
        persona=AttackerPersona.SCRIPT_KIDDIE
    )
    
    report = await emulator.run_full_attack()
    
    print(f"✅ Attack Complete")
    print(f"Success Rate: {report.success_rate:.1%}")
    print(f"Vulnerabilities: {len(report.vulnerabilities_found)}")
    print(f"Time to Breach: {report.time_to_breach_hours:.3f} hours")
    
asyncio.run(demo())
```

### Option 3: Multi-Scenario Test

```python
import asyncio
from offensive_emulator_v3 import OffensiveEmulatorV3, AttackerPersona

async def test_all_personas():
    target = "http://localhost:3004"
    
    personas = [
        AttackerPersona.SCRIPT_KIDDIE,
        AttackerPersona.ORGANIZED_CRIME,
        AttackerPersona.NATION_STATE,
    ]
    
    for persona in personas:
        print(f"\n{'='*60}")
        print(f"Testing as: {persona.value.upper()}")
        print(f"{'='*60}")
        
        emulator = OffensiveEmulatorV3(target, persona)
        report = await emulator.run_full_attack()
        
        print(f"✅ Success Rate: {report.success_rate:.1%}")
        print(f"💰 Budget Spent: ${emulator.spent:.2f}")
        print(f"🔓 Vulnerabilities: {len(report.vulnerabilities_found)}")
        print(f"💥 Business Impact: ${report.business_impact_usd:,.0f}")

asyncio.run(test_all_personas())
```

## Attack Phases Explained

### Phase 1: RECON (Reconnaissance)
Scans the target for:
- API endpoints
- Tech stack (framework, database, CDN)
- Hidden admin routes
- Configuration endpoints

### Phase 2: EXPLOIT (Initial Access)
Attempts to breach defenses via:
- JWT tampering (algorithm confusion, signature stripping)
- Race condition exploitation (subscription override)
- Validation bypass (promo codes, input validation)
- Privilege escalation (role tampering)

### Phase 3: PERSIST (Maintain Access)
Establishes backdoors:
- Hidden admin accounts
- API keys that never expire
- Webhooks for C2 communication
- Scheduled tasks/cron jobs

### Phase 4: LATERAL_MOVE (Spread)
Harvests credentials to move sideways:
- Database credentials from config files
- SSH keys and certificates
- Cloud provider credentials (AWS, GCP, Azure)
- Internal service discovery

### Phase 5: EXFILTRATION (Data Theft)
Steals data at scale:
- User database exports
- Transaction/payment history
- Sensitive configuration files
- Cache poisoning for data leakage

### Phase 6: COVER_TRACKS (Evasion)
Hides the attack:
- Deletes logs and audit trails
- Spoofs attribution (blames other attackers)
- Erases staging artifacts
- Removes forensic evidence

## Output: Threat Report

Example report format (JSON):

```json
{
  "run_id": "a1b2c3d4-e5f6-7890",
  "target": "http://localhost:3004",
  "personas_tested": ["organized_crime"],
  "total_attacks": 15,
  "successful_attacks": 10,
  "success_rate": 0.667,
  "time_to_breach_hours": 0.024,
  "vulnerabilities_found": [
    {
      "vector": "jwt_tampering",
      "severity": "CRITICAL",
      "success_rate": 0.85,
      "time_to_exploit": 30,
      "details": "JWT signature validation bypassed"
    }
  ],
  "defense_coverage": {
    "jwt": 0.22,
    "rate_limiting": 0.35,
    "bot_detection": 0.31
  },
  "business_impact_usd": 500000
}
```

## Testing Your App

### Prerequisites
1. App running at http://localhost:3004
2. API endpoints accessible

### Quick Test

```python
import asyncio
from offensive_emulator_v3 import OffensiveEmulatorV3, AttackerPersona

async def test_my_app():
    emulator = OffensiveEmulatorV3(
        target_url="http://localhost:3004",
        persona=AttackerPersona.ORGANIZED_CRIME
    )
    
    report = await emulator.run_full_attack()
    
    if report.success_rate > 0.5:
        print("⚠️  HIGH RISK: App is vulnerable!")
        print(f"   Vulnerabilities: {[v['vector'] for v in report.vulnerabilities_found]}")
    else:
        print("✅ GOOD: App defenses held up well")
    
    return report

asyncio.run(test_my_app())
```

## Interpreting Results

### Success Rate
- **< 20%**: Strong defenses, minimal vulnerabilities
- **20-50%**: Moderate defenses, some exploitable issues
- **50-80%**: Weak defenses, multiple critical vulnerabilities
- **> 80%**: Severe security posture, immediate action needed

### Time to Breach
- **< 5 minutes**: Trivial to compromise
- **5-30 minutes**: Quick compromise possible
- **30 min - 2 hours**: Significant defense investment
- **> 2 hours**: Well-hardened system

### Defense Coverage
- **< 30%**: Minimal defense effectiveness
- **30-50%**: Moderate detection capability
- **50-70%**: Good defense posture
- **> 70%**: Excellent defense mechanisms

### Business Impact
- **< $50K**: Limited data sensitivity
- **$50K-$500K**: Moderate impact (customer data)
- **$500K-$5M**: High impact (financial systems)
- **> $5M**: Critical systems (regulatory, core business)

## Customization

### Change Target
```python
emulator = OffensiveEmulatorV3(
    target_url="https://your-api.com",  # Change URL
    persona=AttackerPersona.SCRIPT_KIDDIE
)
```

### Change Persona
```python
# Different budgets and tactics
personas = [
    AttackerPersona.SCRIPT_KIDDIE,      # $250/month - Simple attacks
    AttackerPersona.ORGANIZED_CRIME,    # $15K/month - Sophisticated
    AttackerPersona.NATION_STATE,       # Unlimited - APT-level
    AttackerPersona.INSIDER_THREAT,     # $0 - Already has access
]
```

### Access Report Details
```python
report = await emulator.run_full_attack()

# Vulnerabilities
for vuln in report.vulnerabilities_found:
    print(f"{vuln['vector']}: {vuln['severity']}")

# Attack chains (multi-step exploits)
for chain in report.attack_chains:
    print(f"Chain: {' -> '.join(chain)}")

# Defense analysis
for defense, coverage in report.defense_coverage.items():
    print(f"{defense}: {coverage:.0%} coverage")
```

## Troubleshooting

### Target Unreachable
```
Error: Cannot connect to target
→ Verify URL is correct and app is running
→ Check firewall/network access
→ Try: curl http://localhost:3004
```

### No Vulnerabilities Found
```
This is actually good - your app is well-defended!
→ Check if defenses are properly logging attempts
→ Review DEFENSE_COVERAGE metrics
→ Consider running more aggressive personas
```

### Rate Limited
```
Normal behavior - the platform respects rate limits
→ Attacks automatically back off and retry
→ Try SCRIPT_KIDDIE persona for lighter load
→ Check attack logs for defense signals
```

## What Gets Tested

✅ **Tested:**
- API endpoints and tech stack
- JWT/auth token validation
- Business logic vulnerabilities
- Config/secret exposure
- Database credential storage
- Admin panel access controls
- Data exfiltration via APIs

❌ **Not Tested:**
- Network-level attacks
- Physical security
- Social engineering
- DDOS/availability attacks
- Client-side exploits
- Side-channel attacks

## Reports Location

Test reports are saved to:
```
backend/examples/threat_report.json
```

Contains detailed JSON for:
- All attack attempts
- Success/failure reasons
- Vulnerabilities discovered
- Defense coverage analysis
- Business impact estimates

## Next Steps

1. **Run against your app** - Identify actual vulnerabilities
2. **Fix discovered issues** - Prioritize by severity and business impact
3. **Re-test for improvement** - Measure defense hardening
4. **Integrate into CI/CD** - Continuous security validation
5. **Train team** - Use results to improve security practices

## Support

- **Documentation**: See `OFFENSIVE_EMULATOR_README.md`
- **Code**: `backend/offensive_emulator_v3.py`
- **Examples**: `backend/examples/run_emulator.py`
- **Architecture**: `IMPLEMENTATION_SUMMARY.md`

---

**Happy Red Teaming! 🔴**
