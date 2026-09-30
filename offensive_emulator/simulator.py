"""
Simulation Engine — zero-dependency attack simulation.

Used when the real HTTP engines (aiohttp) are not installed.  Produces the
same telemetry, log stream and report shape as the real engines so the
console experience is identical whether it is simulating or really firing
requests.

Install aiohttp to switch to the real engines:  pip install aiohttp
"""

import asyncio
import random
import time
from datetime import datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional

# Per-profile pacing (seconds of "work" per phase) and flavour.
PROFILE_PARAMS = {
    "stealth":    {"delay": [0.22, 0.50], "hit_rate": 0.92, "note": "slow + quiet"},
    "balanced":   {"delay": [0.09, 0.22], "hit_rate": 0.96, "note": "recommended"},
    "aggressive": {"delay": [0.03, 0.09], "hit_rate": 0.98, "note": "fast + loud"},
    "maximum":    {"delay": [0.01, 0.04], "hit_rate": 0.99, "note": "no evasion"},
}

PHASE_SCRIPTS = {
    "recon": [
        ("[Recon] Enumerating endpoints...", 0.5),
        ("  ✓ Found: /api/users (200)", 0.7),
        ("  ✓ Found: /api/admin (200)", 0.7),
        ("  ✓ Found: /api/config (200)", 0.7),
        ("  ✓ Found: /api/export (200)", 0.7),
        ("  ✓ Found: /.env (200)", 0.8),
        ("  ✓ Found: /debug/vars (200)", 0.7),
        ("  ✓ Found: /api/internal/database (200)", 0.6),
        ("  ✓ Found: /secrets.json (200)", 0.8),
        ("  ✓ Found: /swagger.json (200)", 0.6),
        ("[Recon] Fingerprinting tech stack...", 0.6),
        ("  Server: nginx/1.22.1", 0.5),
        ("  Framework: Next.js", 0.5),
        ("[Recon] Detecting hidden admin routes...", 0.6),
        ("  ✓ Hidden route: /admin (200)", 0.6),
        ("  ✓ Hidden route: /internal (200)", 0.6),
        ("  ✓ Hidden route: /api/debug (200)", 0.5),
        ("[Recon] Establishing response baselines...", 0.5),
        ("  valid_user_latency_ms=42  response_size=18.4KB", 0.4),
    ],
    "exploit": [
        ("[Exploit] JWT Token Tampering", 0.4),
        ("  [JWT] Attempting algorithm confusion...", 0.5),
        ("    ✓ Algorithm confusion successful!", 0.6),
        ("  [JWT] Attempting signature stripping...", 0.5),
        ("    ✓ Signature stripping successful!", 0.6),
        ("[Exploit] Subscription Override Race Condition", 0.5),
        ("  Testing /api/v1/subscription/upgrade...", 0.5),
        ("    ✓ Race condition exploited (5/5 concurrent requests succeeded)", 0.6),
        ("[Exploit] Promo Code Validation Bypass", 0.5),
        ("  Testing payload: {'code': \"' OR '1'='1\"}", 0.5),
        ("    ✓ Promo bypass successful", 0.5),
        ("[Exploit] Privilege Escalation", 0.5),
        ("  Testing privilege escalation: {'role': 'admin'}", 0.5),
        ("    ✓ Privilege escalation successful!", 0.5),
    ],
    "persistence": [
        ("[Persist] Creating hidden admin account", 0.4),
        ("  Attempting to create account: system_admin", 0.6),
        ("    ✓ Account created: system_admin", 0.6),
        ("[Persist] Injecting persistent API key", 0.5),
        ("    ✓ API key injected: vpk_live_9f3ac1d7e2b45f68", 0.5),
        ("[Persist] Setting up webhook persistence", 0.5),
        ("    ✓ Webhook registered → https://attacker.example/collect", 0.5),
        ("[Persist] Injecting cron job backdoor", 0.5),
        ("    ✓ Scheduled task task_77 (*/5 * * * *)", 0.5),
    ],
    "lateral_movement": [
        ("[Lateral] Extracting database credentials", 0.4),
        ("  ✓ Found DATABASE_URL credentials", 0.5),
        ("  ✓ Found MONGODB credentials", 0.5),
        ("  ✓ Found REDIS credentials", 0.5),
        ("[Lateral] Discovering internal services", 0.5),
        ("  ✓ Found services at /api/v1/services: ['auth-service', 'payments-db', 'redis-cache']", 0.6),
        ("[Lateral] Harvesting SSH keys", 0.5),
        ("  ✓ Found SSH/Certificate key: /.ssh/id_rsa", 0.5),
        ("  ✓ Found SSH/Certificate key: /etc/ssl/private/server.key", 0.5),
        ("[Lateral] Stealing cloud provider credentials", 0.5),
        ("  ✓ Found AWS_ACCESS_KEY credential", 0.5),
        ("  ✓ Found GCP_KEY credential", 0.5),
    ],
    "exfiltration": [
        ("[Exfil] Mass User Export via API pagination", 0.4),
        ("  Fetching page 1...", 0.4),
        ("    Page 1: 600 records (~0.14MB)", 0.4),
        ("      ✓ Found PII: email = ada.lovelace@vulnpay.test...", 0.3),
        ("      ✓ Found PII: phone = +1-555-1842...", 0.3),
        ("  Fetching page 2...", 0.4),
        ("    Page 2: 600 records (~0.14MB)", 0.4),
        ("  ✓ Exported 1200 user records (0.28MB)", 0.5),
        ("[Exfil] Transaction History Dump", 0.5),
        ("  Attempting /api/v1/transactions...", 0.5),
        ("    ✓ Dumped 340 transaction records", 0.5),
        ("[Exfil] Sensitive File Extraction", 0.5),
        ("  ✓ Extracted /.env (0.3KB) — secrets: password, api_key", 0.5),
        ("  ✓ Extracted /.aws/credentials (0.4KB) — secrets: api_key", 0.5),
        ("[Exfil] Cache poisoning for persistent data leakage", 0.5),
        ("  ✓ Cache poisoned via /api/v1/data", 0.4),
    ],
    "cover_tracks": [
        ("[Cover] Deleting logs", 0.4),
        ("  ✓ Logs deleted via /api/v1/admin/logs/delete", 0.5),
        ("[Cover] Removing audit trails", 0.5),
        ("  ✓ Audit records purged via /api/v1/security/events/purge", 0.5),
        ("[Cover] Spoofing attribution (false flag entries)", 0.5),
        ("  ✓ Planted 3 false flag entries in /api/v1/admin/logs", 0.5),
        ("[Cover] Erasing artifacts", 0.5),
        ("  ✓ Artifacts erased via /api/v1/cache/clear", 0.5),
        ("  ✓ Staging areas cleaned", 0.4),
    ],
}

PHASE_KEYS = list(PHASE_SCRIPTS.keys())


class SimulationEngine:
    """Replays a realistic, randomized 6-phase kill chain without any network."""

    def __init__(self, target_url: str, run_id: str, preset: str = "balanced", seed: Optional[int] = None):
        self.target = target_url
        self.run_id = run_id
        self.preset = PROFILE_PARAMS.get(preset, PROFILE_PARAMS["balanced"])
        self.rng = random.Random(seed if seed is not None else random.getrandbits(48))
        self.context = _SimContext()

    async def run(self, on_phase=None, on_log=None) -> Dict[str, Any]:
        start = time.time()
        results: Dict[str, bool] = {}
        timings: Dict[str, float] = {}

        for idx, key in enumerate(PHASE_KEYS):
            # gating mirrors the real chain
            gate = {
                "exploit": "recon",
                "persistence": "exploit",
                "lateral_movement": "persistence",
                "exfiltration": "lateral_movement",
            }.get(key)
            if gate and not results.get(gate):
                results[key] = False
                if on_phase:
                    on_phase(key, "skipped")
                continue

            if on_phase:
                on_phase(key, "running")

            t0 = time.time()
            script = PHASE_SCRIPTS[key]
            for line, rel in script:
                if on_log:
                    on_log(line, "INFO")
                lo, hi = self.preset["delay"]
                await asyncio.sleep(self.rng.uniform(lo, hi) * rel * 2.2)

            succeeded = self.rng.random() < self.preset["hit_rate"]
            self._apply(key, succeeded)
            results[key] = succeeded
            timings[key] = time.time() - t0

            if on_phase:
                on_phase(key, "complete" if succeeded else "failed")

        return self._build_report(results, timings, time.time() - start)

    # ------------------------------------------------------------------ #

    def _apply(self, key: str, ok: bool) -> None:
        c = self.context
        if not ok:
            return
        if key == "recon":
            n = self.rng.randint(14, 26)
            c.discovered_endpoints = [f"/api/p{i}" for i in range(n)]
            c.tech_stack = {"server": "nginx/1.22.1", "framework": "Next.js", "language": "Node.js"}
            c.hidden_routes = ["/admin", "/internal", "/debug", "/api/admin"]
        elif key == "exploit":
            c.access_granted = True
            c.exploited_methods = self.rng.sample(
                ["algorithm_confusion", "signature_stripping", "subscription_race", "promo_bypass", "privesc"],
                self.rng.randint(2, 4))
            c.valid_tokens = {"sim-jwt": "admin"}
        elif key == "persistence":
            c.persistence_achieved = True
            c.admin_accounts = ["system_admin"]
            c.backdoors_installed = [
                {"type": "hidden_admin", "username": "system_admin"},
                {"type": "api_key", "key": "vpk_live_…"},
                {"type": "webhook", "url": "https://attacker.example/collect"},
                {"type": "cron", "id": "task_77"},
            ][: self.rng.randint(2, 4)]
        elif key == "lateral_movement":
            c.discovered_services = ["auth-service", "payments-db", "redis-cache", "worker-queue"]
            c.extracted_credentials = [
                {"type": "DATABASE_URL", "endpoint": "/.env"},
                {"type": "MONGODB", "endpoint": "/.env"},
                {"type": "AWS_ACCESS_KEY", "endpoint": "/.aws/credentials"},
                {"type": "ssh_key", "path": "/.ssh/id_rsa"},
            ][: self.rng.randint(2, 4)]
            c.ssh_keys_found = ["/.ssh/id_rsa", "/etc/ssl/private/server.key"][: self.rng.randint(1, 2)]
        elif key == "exfiltration":
            c.records_stolen = self.rng.randint(1150, 1620)
            c.data_exfiltrated_mb = round(self.rng.uniform(0.4, 0.9), 2)
            c.extraction_methods = ["user_export", "transaction_dump", "file_extraction", "cache_poisoning"][
                : self.rng.randint(2, 4)]
        elif key == "cover_tracks":
            c.logs_deleted = self.rng.randint(1200, 5400)
            c.artifacts_removed = self.rng.randint(2, 5)
            c.traces_visible = self.rng.random() < 0.15

    def _build_report(self, results: Dict[str, bool], timings: Dict[str, float], total: float) -> Dict[str, Any]:
        c = self.context
        success_rate = sum(1 for k in ("exploit", "persistence", "lateral_movement", "exfiltration") if results.get(k)) / 4 * 100
        if c.records_stolen > 10000 or c.data_exfiltrated_mb > 1000:
            severity = "Critical"
        elif c.records_stolen > 1000 or c.data_exfiltrated_mb > 100:
            severity = "High"
        elif c.records_stolen > 0 or c.data_exfiltrated_mb > 0:
            severity = "Medium"
        else:
            severity = "Low"

        return {
            "run_id": self.run_id,
            "target": self.target,
            "engine": "simulation",
            "timestamp": datetime.now().isoformat(),
            "total_time_seconds": total,
            "attack_chain": {
                "phase_1_recon": results.get("recon", False),
                "phase_2_exploit": results.get("exploit", False),
                "phase_3_persistence": results.get("persistence", False),
                "phase_4_lateral_movement": results.get("lateral_movement", False),
                "phase_5_exfiltration": results.get("exfiltration", False),
                "phase_6_cover_tracks": results.get("cover_tracks", False),
            },
            "phase_timings": timings,
            "recon_results": {
                "endpoints_discovered": len(c.discovered_endpoints),
                "endpoints": c.discovered_endpoints[:20],
                "tech_stack": c.tech_stack,
                "hidden_routes": c.hidden_routes,
            },
            "exploit_results": {
                "access_granted": c.access_granted,
                "methods": c.exploited_methods,
                "valid_tokens": len(c.valid_tokens),
            },
            "persistence_results": {
                "backdoors_installed": len(c.backdoors_installed),
                "admin_accounts": c.admin_accounts,
                "backdoors": c.backdoors_installed,
            },
            "lateral_movement_results": {
                "services_discovered": c.discovered_services,
                "credentials_extracted": len(c.extracted_credentials),
                "ssh_keys_found": len(c.ssh_keys_found),
            },
            "exfiltration_results": {
                "records_stolen": c.records_stolen,
                "data_exfiltrated_mb": c.data_exfiltrated_mb,
                "extraction_methods": c.extraction_methods,
            },
            "cover_tracks_results": {
                "logs_deleted": c.logs_deleted,
                "artifacts_removed": c.artifacts_removed,
                "traces_visible": c.traces_visible,
            },
            "summary": {
                "attack_success_rate": f"{success_rate:.1f}%",
                "severity": severity,
                "phases_completed": sum(1 for k in ("exploit", "persistence", "lateral_movement", "exfiltration") if results.get(k)),
                "key_findings": [
                    f"Discovered {len(c.discovered_endpoints)} endpoints",
                    f"Exploited {len(c.exploited_methods)} methods" if c.exploited_methods else "No successful exploits",
                    f"Established {len(c.backdoors_installed)} backdoors" if c.backdoors_installed else "No persistence",
                    f"Extracted {len(c.extracted_credentials)} credentials" if c.extracted_credentials else "No credential extraction",
                    f"Stole {c.records_stolen} records / {c.data_exfiltrated_mb:.2f} MB" if c.records_stolen > 0 else "No data theft",
                    f"Evaded detection: {not c.traces_visible}",
                ],
            },
        }


class _SimContext:
    """Mirrors attack_modules.base.AttackContext (without importing engines)."""

    def __init__(self):
        self.discovered_endpoints: List[str] = []
        self.tech_stack: Dict[str, str] = {}
        self.hidden_routes: List[str] = []
        self.valid_tokens: Dict[str, str] = {}
        self.exploited_methods: List[str] = []
        self.access_granted = False
        self.backdoors_installed: List[Dict[str, Any]] = []
        self.admin_accounts: List[str] = []
        self.persistence_achieved = False
        self.discovered_services: List[str] = []
        self.extracted_credentials: List[Dict[str, Any]] = []
        self.ssh_keys_found: List[str] = []
        self.data_exfiltrated_mb = 0.0
        self.records_stolen = 0
        self.extraction_methods: List[str] = []
        self.logs_deleted = 0
        self.artifacts_removed = 0
        self.traces_visible = True
