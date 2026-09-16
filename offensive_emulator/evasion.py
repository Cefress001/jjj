"""
Defense Evasion Techniques
Advanced tactics to bypass detection and defense systems
"""

import asyncio
import random
import string
import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urlencode
import time

logger = logging.getLogger(__name__)


class UserAgentRotation:
    """Rotate user agents to evade detection"""

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15",
        "Mozilla/5.0 (iPad; CPU OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0)",
    ]

    @staticmethod
    def get_random() -> str:
        """Get random user agent"""
        return random.choice(UserAgentRotation.USER_AGENTS)

    @staticmethod
    def get_realistic_headers() -> Dict[str, str]:
        """Get realistic HTTP headers"""
        return {
            "User-Agent": UserAgentRotation.get_random(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "de-DE,de;q=0.9"]),
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }


class RequestDistribution:
    """Distribute requests to evade rate limiting"""

    def __init__(self, concurrent_limit: int = 3, delay_ms: int = 100):
        self.concurrent_limit = concurrent_limit
        self.delay_ms = delay_ms

    async def distribute_requests(self, requests: List[Dict[str, Any]]) -> List[Any]:
        """Distribute requests with concurrency and delay"""
        results = []

        for i in range(0, len(requests), self.concurrent_limit):
            batch = requests[i:i + self.concurrent_limit]
            logger.debug(f"  [Distribute] Processing batch {i//self.concurrent_limit + 1}/{(len(requests)-1)//self.concurrent_limit + 1}")

            # Execute batch concurrently
            batch_results = await asyncio.gather(
                *[self._execute_with_delay(req) for req in batch],
                return_exceptions=True
            )
            results.extend(batch_results)

            # Delay between batches
            if i + self.concurrent_limit < len(requests):
                await asyncio.sleep(self.delay_ms / 1000.0)

        return results

    async def _execute_with_delay(self, request_info: Dict) -> Any:
        """Execute single request with delay"""
        await asyncio.sleep(random.uniform(0, self.delay_ms / 1000.0))
        # Actual request execution would happen here
        return {"status": 200}


class PayloadObfuscation:
    """Obfuscate payloads to evade detection"""

    @staticmethod
    def obfuscate_json(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Add noise and obfuscation to JSON payload"""
        obfuscated = payload.copy()

        # Add random fields
        obfuscated[f"_{PayloadObfuscation._random_string(5)}"] = PayloadObfuscation._random_string(10)
        obfuscated[f"_{PayloadObfuscation._random_string(5)}"] = random.randint(1, 1000)

        # Add timing info to appear normal
        obfuscated["_ts"] = int(time.time() * 1000)
        obfuscated["_rand"] = random.random()

        return obfuscated

    @staticmethod
    def split_payload(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Split payload into multiple requests"""
        if not payload:
            return [payload]

        keys = list(payload.keys())
        mid = len(keys) // 2

        payload1 = {k: payload[k] for k in keys[:mid]}
        payload2 = {k: payload[k] for k in keys[mid:]}

        return [payload1, payload2]

    @staticmethod
    def encode_sensitive_values(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Encode sensitive values"""
        encoded = {}
        sensitive_keys = ["password", "token", "key", "secret", "api_key", "credential"]

        for k, v in payload.items():
            if any(sensitive in k.lower() for sensitive in sensitive_keys):
                if isinstance(v, str):
                    encoded[k] = v.encode('utf-8').hex()
                else:
                    encoded[k] = v
            else:
                encoded[k] = v

        return encoded

    @staticmethod
    def _random_string(length: int) -> str:
        """Generate random string"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


class TimingEvasion:
    """Evade timing-based detection"""

    @staticmethod
    async def introduce_jitter(operation, jitter_ms: int = 500) -> Any:
        """Execute operation with random delay"""
        delay = random.uniform(0, jitter_ms) / 1000.0
        await asyncio.sleep(delay)
        return await operation if asyncio.iscoroutine(operation) else operation

    @staticmethod
    async def slow_execution(items: List[Any], min_delay_ms: int = 100, max_delay_ms: int = 500) -> List[Any]:
        """Execute items slowly to evade rate limit detection"""
        results = []

        for item in items:
            delay = random.uniform(min_delay_ms, max_delay_ms) / 1000.0
            await asyncio.sleep(delay)
            results.append(item)

        return results

    @staticmethod
    async def align_with_normal_traffic(operation, traffic_pattern: Optional[List[int]] = None) -> Any:
        """Align attack timing with normal traffic patterns"""
        if traffic_pattern is None:
            traffic_pattern = [100, 200, 150, 300, 100, 250]  # Sample pattern

        delay = random.choice(traffic_pattern) / 1000.0
        await asyncio.sleep(delay)
        return await operation if asyncio.iscoroutine(operation) else operation


class IPRotation:
    """Rotate IP addresses (for proxy-based systems)"""

    def __init__(self, proxies: Optional[List[str]] = None):
        self.proxies = proxies or []
        self.current_proxy_idx = 0

    def get_next_proxy(self) -> Optional[str]:
        """Get next proxy"""
        if not self.proxies:
            return None

        proxy = self.proxies[self.current_proxy_idx]
        self.current_proxy_idx = (self.current_proxy_idx + 1) % len(self.proxies)
        return proxy

    def get_rotating_proxy_dict(self) -> Optional[Dict[str, str]]:
        """Get rotating proxy as dict"""
        proxy = self.get_next_proxy()
        if proxy:
            return {"http": proxy, "https": proxy}
        return None


class URLObfuscation:
    """Obfuscate URLs to evade WAF"""

    @staticmethod
    def add_query_parameters(url: str, noise_params: int = 3) -> str:
        """Add random query parameters"""
        separators = ["&", ";", "?"]
        sep = random.choice(separators)

        noise = sep.join([
            f"_{PayloadObfuscation._random_string(4)}={PayloadObfuscation._random_string(8)}"
            for _ in range(noise_params)
        ])

        return f"{url}?{noise}" if "?" not in url else f"{url}&{noise}"

    @staticmethod
    def double_encode_payload(path: str) -> str:
        """Double encode path"""
        return path.replace("/", "%252F").replace(" ", "%2520")

    @staticmethod
    def unicode_encode(text: str) -> str:
        """Encode as unicode"""
        return "".join(f"%u{ord(c):04x}" for c in text)

    @staticmethod
    def case_variation(text: str) -> str:
        """Vary case to bypass signatures"""
        return "".join(random.choice([c.upper(), c.lower()]) for c in text)


class EvasionManager:
    """Coordinate all evasion tactics"""

    def __init__(self, config: Optional[Dict[str, bool]] = None):
        self.config = config or {
            "randomize_user_agents": True,
            "distribute_requests": True,
            "obfuscate_payloads": True,
            "jitter_timing": True,
            "rotate_ips": False,
        }
        self.ip_rotation = IPRotation()

    def get_evasion_headers(self) -> Dict[str, str]:
        """Get headers with evasion"""
        if self.config.get("randomize_user_agents"):
            return UserAgentRotation.get_realistic_headers()
        return {}

    def obfuscate_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Apply payload obfuscation"""
        if self.config.get("obfuscate_payloads"):
            return PayloadObfuscation.obfuscate_json(payload)
        return payload

    async def distributed_delay(self) -> None:
        """Apply distributed delay"""
        if self.config.get("jitter_timing"):
            await TimingEvasion.introduce_jitter(asyncio.sleep(0), jitter_ms=500)

    def get_proxy(self) -> Optional[Dict[str, str]]:
        """Get rotating proxy"""
        if self.config.get("rotate_ips"):
            return self.ip_rotation.get_rotating_proxy_dict()
        return None
