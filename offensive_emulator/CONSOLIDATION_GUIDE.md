# Offensive Emulator v3 - Unified Cohesive Architecture

## Executive Summary

The original codebase was **6 independent attack engines running in isolation**. They've been consolidated into **ONE cohesive app** with:

✅ **Unified State Threading** - `AttackContext` flows through all 6 phases  
✅ **State-Dependent Phase Progression** - Each phase uses outputs from previous phases  
✅ **Real Attack Simulation** - All HTTP-based attacks are genuine (not mocks)  
✅ **Complete Attack Chains** - Reconnaissance informs Exploit, Exploit enables Persistence, etc.  
✅ **Comprehensive Logging** - Single cohesive execution log with phase timing  
✅ **Unified Reporting** - One threat report showing end-to-end attack success  

---

## What Changed

### Before (Fragmented)
```
Phase 1: Recon       ─────────────► Discovers endpoints
                                    (result discarded)

Phase 2: Exploit     ─────────────► Tries random endpoints
                                    (doesn't know about recon)

Phase 3: Persistence ─────────────► Creates backdoors
                                    (isolated operation)

Phase 4: Lateral Move ────────────► Extracts credentials
                                    (no exploit context)

Phase 5: Exfiltration ───────────► Steals data
                                    (doesn't use extracted credentials)

Phase 6: Cover Tracks ───────────► Hides traces
                                    (no knowledge of what was created)
```

### After (Unified)
```
Phase 1: Recon
  └─→ Discovers endpoints → Stores in AttackContext
      └─→ Phase 2: Exploit (uses discovered endpoints)
          └─→ Gains access → Stores tokens/methods in context
              └─→ Phase 3: Persistence (verifies access first)
                  └─→ Installs backdoors → Stores in context
                      └─→ Phase 4: Lateral Move (requires persistence)
                          └─→ Extracts credentials → Stores in context
                              └─→ Phase 5: Exfiltration (uses credentials)
                                  └─→ Steals data → Stores in context
                                      └─→ Phase 6: Cover Tracks
                                          └─→ Erases all evidence
```

---

## Architecture Changes

### 1. Unified Context Object (`AttackContext`)

**File**: `attack_modules/base.py`

```python
@dataclass
class AttackContext:
    """Unified state that flows through all attack phases"""
    target_url: str
    run_id: str
    
    # Recon → Exploit
    discovered_endpoints: List[str]
    tech_stack: Dict[str, str]
    hidden_routes: List[str]
    
    # Exploit → Persistence
    valid_tokens: Dict[str, str]
    access_granted: bool
    exploited_methods: List[str]
    
    # Persistence → Lateral Move
    backdoors_installed: List[Dict[str, Any]]
    persistence_achieved: bool
    
    # Lateral Move → Exfiltration
    extracted_credentials: List[Dict[str, Any]]
    discovered_services: List[str]
    
    # Exfiltration → Cover Tracks
    records_stolen: int
    data_exfiltrated_mb: float
    extraction_methods: List[str]
    
    # Phase timings
    phase_timings: Dict[str, float]
```

### 2. Updated Engine Signatures

**Old signature:**
```python
async def execute(self, target: str, payload: Dict[str, Any]) -> Dict[str, Any]
```

**New signature:**
```python
async def execute(self, context: AttackContext) -> Dict[str, Any]
```

Each engine now:
- **Receives** the unified context
- **Reads** outputs from previous phases
- **Updates** the context with its results
- **Returns** the same unified context

### 3. State-Dependent Phase Execution

**File**: `offensive_emulator_unified.py`

Each phase now checks prerequisites before running:

```python
async def phase_3_persistence(self) -> bool:
    """Persistence requires Phase 2 success"""
    if not self.context.access_granted:
        logger.info("SKIPPED - No initial access")
        return False
    
    result = await self.persistence_engine.execute(self.context)
    self.context.persistence_achieved = result.get("success")
    return self.context.persistence_achieved
```

### 4. Engine Integration Examples

#### Recon → Exploit
**Recon discovers endpoints**, Exploit uses them:
```python
# Recon populates:
context.discovered_endpoints = ["/api/admin", "/api/users", ...]

# Exploit filters for subscription-related endpoints:
endpoints = [
    e for e in context.discovered_endpoints 
    if "subscri" in e or "billing" in e
]
```

#### Exploit → Persistence
**Exploit gains access**, Persistence verifies:
```python
# Exploit sets:
context.access_granted = True
context.valid_tokens = {"token123": "admin"}

# Persistence checks:
if not context.access_granted:
    return False  # Skip persistence if exploit failed
```

#### Lateral Move → Exfiltration
**Lateral extracts credentials**, Exfiltration uses them:
```python
# Lateral Move finds:
context.extracted_credentials = [
    {"type": "DATABASE_URL", "value": "postgres://..."},
    {"type": "AWS", "value": "AKIA..."}
]

# Exfiltration checks:
if not context.extracted_credentials:
    return False  # Skip if no credentials to use
```

---

## New Entry Point: `offensive_emulator_unified.py`

**Single cohesive app** with:

- `UnifiedOffensiveEmulator` class
- 6 phase methods with prerequisites
- Unified `AttackContext` management
- Complete threat report generation

### Usage

```python
from offensive_emulator_unified import UnifiedOffensiveEmulator

emulator = UnifiedOffensiveEmulator(target_url="http://localhost:3004")
report = await emulator.run_full_attack()
```

### Output

One comprehensive threat report with:
- Attack chain completion (which phases succeeded)
- Phase timings (how long each phase took)
- Recon results (endpoints, tech stack)
- Exploit results (access granted, methods)
- Persistence results (backdoors, admin accounts)
- Lateral movement results (credentials extracted)
- Exfiltration results (records stolen, data size)
- Cover tracks results (traces hidden)

---

## What's Still Real

✅ **HTTP-based reconnaissance** - Actual endpoint discovery  
✅ **JWT tampering** - Real token manipulation attacks  
✅ **Race condition exploits** - Concurrent request handling  
✅ **Credential extraction** - Regex-based secret finding  
✅ **Database dumping** - API pagination for data theft  
✅ **Cache poisoning** - HTTP header injection  
✅ **Log deletion** - Actual log endpoint attempts  

The **only difference** is:
- Attacks are isolated to your **closed sandbox** (configurable target)
- No real damage (test against your own infrastructure)
- Real attack patterns (you see exactly what works/fails)

---

## Integration Checklist

- [x] `AttackContext` dataclass created
- [x] All 6 engines updated to use `execute(context)`
- [x] Recon engine populates context
- [x] Exploit engine uses recon results
- [x] Persistence engine requires exploit success
- [x] Lateral movement requires persistence
- [x] Exfiltration uses lateral movement credentials
- [x] Cover tracks runs regardless (cleanup phase)
- [x] Phase timings tracked
- [x] Unified orchestrator created
- [x] Comprehensive threat reporting added
- [x] Human-readable report printing

---

## File Structure

```
offensive_emulator/
├── attack_modules/
│   ├── base.py                        ← AttackContext defined here
│   ├── recon_engine.py                ← Updated for context
│   ├── exploit_engine.py              ← Updated for context
│   ├── persistence_engine.py          ← Updated for context
│   ├── lateral_movement_engine.py     ← Updated for context
│   ├── exfiltration_engine.py         ← Updated for context
│   └── cover_tracks_engine.py         ← Updated for context
├── offensive_emulator_v3.py           ← Old (still works)
├── offensive_emulator_unified.py      ← NEW - Use this
├── examples/
│   └── run_emulator.py                ← Uses old v3
└── CONSOLIDATION_GUIDE.md             ← You are here
```

---

## Recommended Usage

### Start Here (Unified App)
```bash
python -m offensive_emulator.offensive_emulator_unified
```

### Old Examples Still Work
```bash
python offensive_emulator/examples/run_emulator.py
```

---

## Key Improvements

| Aspect | Before | After |
|--------|--------|-------|
| **State Sharing** | None - 6 isolated modules | Unified context flows through all phases |
| **Phase Dependency** | None - all run independently | Phases skip if prerequisites fail |
| **Recon→Exploit** | Exploit tries random endpoints | Exploit uses discovered endpoints |
| **Credential Usage** | Extracted but unused | Used by exfiltration engine |
| **Attack Chain Visibility** | 6 separate reports | Single end-to-end report |
| **Trace Cleanup** | Doesn't know what to clean | Knows all attack artifacts |
| **Entry Point** | Complex multi-phase orchestration | Single `run_full_attack()` method |

---

## Security Note

This is a **closed-loop red team simulation** designed to:
- ✅ Test your own defenses
- ✅ Identify vulnerabilities before adversaries
- ✅ Strengthen your security posture
- ✅ Validate detection systems

It is **NOT** for:
- ❌ Attacking systems you don't own
- ❌ Production environments without authorization
- ❌ Any use outside your closed sandbox

---

## Next Steps

1. **Test locally** against your own test app
2. **Validate** that attack patterns match your threat model
3. **Iterate** on defenses based on what gets exploited
4. **Monitor** which phases succeed/fail to identify weak points
5. **Strengthen** controls based on the threat report

---

Generated: 2025-09-16
Author: Claude (Unified Consolidation)
