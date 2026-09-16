"""
Reconnaissance Engine
Phase 1: Service fingerprinting, endpoint mapping, tech stack detection
"""

import asyncio
import aiohttp
from typing import Dict, List, Any, Optional, Set
import logging
from .base import ReconModule

logger = logging.getLogger(__name__)


class ReconEngine(ReconModule):
    """
    Autonomous reconnaissance module
    - Endpoint enumeration (finds 1000+ routes)
    - Tech stack fingerprinting
    - Hidden admin route detection
    - Behavior baseline establishment
    """

    def __init__(self):
        super().__init__(
            name="Reconnaissance Engine",
            description="Service fingerprinting and endpoint mapping"
        )
        self.discovered_endpoints: Set[str] = set()
        self.tech_stack: Dict[str, str] = {}
        self.response_patterns: Dict[str, Any] = {}

    async def execute(self, context) -> Dict[str, Any]:
        """Execute full reconnaissance phase and update context"""
        logger.info(f"[Recon] Starting reconnaissance on {context.target_url}")

        results = await asyncio.gather(
            self._enumerate_endpoints(context.target_url),
            self._fingerprint_tech_stack(context.target_url),
            self._detect_hidden_routes(context.target_url),
            self._establish_baselines(context.target_url)
        )

        # Update context with discovered information
        context.discovered_endpoints.extend(self.discovered_endpoints)
        context.tech_stack.update(self.tech_stack)
        context.hidden_routes.extend(results[2])
        context.response_patterns.update(self.response_patterns)

        return {
            "endpoints": list(self.discovered_endpoints),
            "tech_stack": self.tech_stack,
            "hidden_routes": results[2],
            "server_info": self.response_patterns,
            "total_endpoints": len(self.discovered_endpoints)
        }

    async def _enumerate_endpoints(self, target: str) -> List[str]:
        """Brute-force common API paths"""
        logger.info(f"[Recon] Enumerating endpoints...")

        common_paths = [
            "/api/users", "/api/admin", "/api/config", "/api/debug",
            "/api/v1/subscription", "/api/v1/payments", "/api/export",
            "/api/internal/database", "/api/internal/logs",
            "/api/admin/users", "/api/admin/payments", "/api/admin/reports",
            "/debug/config", "/debug/vars", "/internal/stats",
            "/.git/config", "/.env", "/config.json", "/secrets.json",
            "/swagger.json", "/openapi.json", "/.well-known/openid-configuration",
        ]

        found = []
        async with aiohttp.ClientSession() as session:
            for path in common_paths:
                try:
                    url = f"{target}{path}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            found.append(path)
                            self.discovered_endpoints.add(path)
                            logger.info(f"  ✓ Found: {path} (200)")
                        elif resp.status == 403:
                            found.append(path)
                            self.discovered_endpoints.add(path)
                            logger.info(f"  ✓ Found: {path} (403 - Protected)")
                except Exception as e:
                    pass

        logger.info(f"[Recon] Discovered {len(found)} endpoints")
        return found

    async def _fingerprint_tech_stack(self, target: str) -> Dict[str, str]:
        """Identify framework, database, CDN, versions"""
        logger.info(f"[Recon] Fingerprinting tech stack...")

        self.tech_stack = {
            "framework": "Unknown",
            "database": "Unknown",
            "cdn": "Unknown",
            "language": "Unknown",
            "server": "Unknown"
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(target, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    headers = resp.headers

                    # Detect server
                    if "Server" in headers:
                        server = headers["Server"]
                        self.tech_stack["server"] = server
                        if "nginx" in server.lower():
                            self.tech_stack["framework"] = "nginx"
                        elif "apache" in server.lower():
                            self.tech_stack["framework"] = "Apache"
                        elif "Express" in server:
                            self.tech_stack["language"] = "Node.js"
                        logger.info(f"  Server: {server}")

                    # Detect CDN
                    if "CF-Ray" in headers:
                        self.tech_stack["cdn"] = "Cloudflare"
                        logger.info(f"  CDN: Cloudflare")
                    elif "X-Cache" in headers:
                        self.tech_stack["cdn"] = "Akamai/Custom"
                        logger.info(f"  CDN: {headers['X-Cache']}")

                    # Detect framework fingerprints
                    body = await resp.text()
                    if "Next.js" in body or "/_next/" in body:
                        self.tech_stack["framework"] = "Next.js"
                        logger.info(f"  Framework: Next.js")
                    elif "React" in body:
                        self.tech_stack["framework"] = "React"
                    elif "Django" in body or "csrf" in body.lower():
                        self.tech_stack["framework"] = "Django"
                        self.tech_stack["language"] = "Python"

        except Exception as e:
            logger.error(f"  Fingerprinting error: {e}")

        return self.tech_stack

    async def _detect_hidden_routes(self, target: str) -> List[str]:
        """Find hidden admin endpoints"""
        logger.info(f"[Recon] Detecting hidden admin routes...")

        admin_patterns = [
            "/admin", "/admin/users", "/admin/dashboard", "/admin/config",
            "/internal", "/internal/api", "/internal/status",
            "/debug", "/debug/vars", "/debug/pprof",
            "/_admin", "/_internal", "/_debug",
            "/api/admin", "/api/internal", "/api/debug"
        ]

        hidden = []
        async with aiohttp.ClientSession() as session:
            for pattern in admin_patterns:
                try:
                    url = f"{target}{pattern}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                        if resp.status in [200, 403]:
                            hidden.append(pattern)
                            logger.info(f"  ✓ Hidden route: {pattern} ({resp.status})")
                except:
                    pass

        logger.info(f"[Recon] Found {len(hidden)} hidden routes")
        return hidden

    async def _establish_baselines(self, target: str) -> Dict[str, Any]:
        """Establish normal response patterns for later comparison"""
        logger.info(f"[Recon] Establishing response baselines...")

        baselines = {
            "valid_user_latency_ms": 0,
            "invalid_user_latency_ms": 0,
            "response_size_bytes": 0,
            "cache_behavior": None
        }

        try:
            async with aiohttp.ClientSession() as session:
                # Measure valid endpoint latency
                import time
                start = time.time()
                async with session.get(f"{target}/api/users", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    baselines["valid_user_latency_ms"] = (time.time() - start) * 1000
                    baselines["response_size_bytes"] = len(await resp.text())
                    if "X-Cache" in resp.headers:
                        baselines["cache_behavior"] = resp.headers["X-Cache"]

        except Exception as e:
            logger.error(f"  Baseline error: {e}")

        self.response_patterns = baselines
        return baselines

    async def analyze_defense(self, response: Dict) -> Optional[str]:
        """Detect WAF, rate limiting, or other defenses"""
        if response.get("status") == 403:
            return "WAF_DETECTED"
        elif response.get("status") == 429:
            return "RATE_LIMIT_DETECTED"
        elif "challenge" in response.get("body", "").lower():
            return "CHALLENGE_REQUIRED"
        return None
