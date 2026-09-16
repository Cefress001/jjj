"""
Configuration system for Offensive Emulator
Customize attack parameters, timeouts, retry logic, and adaptive behavior
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any
from enum import Enum


class AggressivenessLevel(Enum):
    """Attack aggressiveness profile"""
    STEALTH = "stealth"           # Slow, quiet, evade detection
    BALANCED = "balanced"         # Normal speed, standard tactics
    AGGRESSIVE = "aggressive"     # Fast, concurrent, high noise
    MAXIMUM = "maximum"           # Max speed, all at once, no evasion


@dataclass
class AttackConfig:
    """Configuration for attack execution"""

    # Aggressiveness
    aggressiveness: AggressivenessLevel = AggressivenessLevel.BALANCED

    # Recon phase
    recon_wordlist_size: int = 100          # Number of endpoints to try
    recon_timeout_seconds: int = 5
    recon_concurrent_requests: int = 5

    # Exploit phase
    exploit_jwt_attempts: int = 5           # JWT tampering attempts
    exploit_race_condition_threads: int = 10
    exploit_timeout_seconds: int = 10
    exploit_retry_on_failure: bool = True
    exploit_max_retries: int = 3

    # Persistence phase
    persistence_backdoor_count: int = 3     # Multiple backdoors
    persistence_stealth_delay_seconds: float = 0.5
    persistence_api_key_rotation: bool = True

    # Lateral movement
    lateral_credential_patterns: List[str] = field(default_factory=lambda: [
        "DATABASE_URL", "AWS", "MONGODB", "REDIS", "API_KEY", "SECRET"
    ])
    lateral_max_creds_extract: int = 50
    lateral_service_discovery_depth: int = 3

    # Exfiltration
    exfil_batch_size: int = 1000            # Records per request
    exfil_rate_limit_handling: str = "backoff"  # backoff, distributed, skip
    exfil_max_data_mb: float = 1000         # Stop after this much
    exfil_prioritize_pii: bool = True

    # Cover tracks
    cover_delete_logs: bool = True
    cover_remove_artifacts: bool = True
    cover_spoof_attribution: bool = True
    cover_false_flag_count: int = 3

    # Defense evasion
    evasion_enabled: bool = True
    evasion_randomize_user_agents: bool = True
    evasion_distribute_requests: bool = True
    evasion_timing_jitter_ms: int = 500
    evasion_proxy_rotation: bool = False

    # Adaptive learning
    adaptive_learning_enabled: bool = True
    adaptive_mutation_on_failure: bool = True
    adaptive_exploit_prioritization: bool = True

    # Retry and resilience
    connection_timeout_seconds: int = 10
    read_timeout_seconds: int = 10
    max_retries: int = 3
    retry_backoff_multiplier: float = 2.0

    # Logging
    verbose_logging: bool = True
    log_all_requests: bool = False

    def get_timeouts(self) -> Dict[str, int]:
        """Get timeout configuration for phase"""
        return {
            "recon": self.recon_timeout_seconds,
            "exploit": self.exploit_timeout_seconds,
            "connection": self.connection_timeout_seconds,
            "read": self.read_timeout_seconds,
        }

    def get_concurrency(self) -> Dict[str, int]:
        """Get concurrency levels based on aggressiveness"""
        levels = {
            AggressivenessLevel.STEALTH: {
                "recon": 1,
                "exploit": 2,
                "lateral": 2,
                "exfil": 1,
            },
            AggressivenessLevel.BALANCED: {
                "recon": 5,
                "exploit": 5,
                "lateral": 5,
                "exfil": 3,
            },
            AggressivenessLevel.AGGRESSIVE: {
                "recon": 20,
                "exploit": 15,
                "lateral": 15,
                "exfil": 10,
            },
            AggressivenessLevel.MAXIMUM: {
                "recon": 50,
                "exploit": 50,
                "lateral": 50,
                "exfil": 30,
            },
        }
        return levels.get(self.aggressiveness, levels[AggressivenessLevel.BALANCED])

    def get_delays(self) -> Dict[str, float]:
        """Get delay between requests based on aggressiveness"""
        levels = {
            AggressivenessLevel.STEALTH: {"request": 2.0, "phase": 5.0},
            AggressivenessLevel.BALANCED: {"request": 0.5, "phase": 1.0},
            AggressivenessLevel.AGGRESSIVE: {"request": 0.1, "phase": 0.2},
            AggressivenessLevel.MAXIMUM: {"request": 0.0, "phase": 0.0},
        }
        return levels.get(self.aggressiveness, levels[AggressivenessLevel.BALANCED])


# Preset configurations
STEALTH_CONFIG = AttackConfig(aggressiveness=AggressivenessLevel.STEALTH)
BALANCED_CONFIG = AttackConfig(aggressiveness=AggressivenessLevel.BALANCED)
AGGRESSIVE_CONFIG = AttackConfig(aggressiveness=AggressivenessLevel.AGGRESSIVE)
MAXIMUM_CONFIG = AttackConfig(aggressiveness=AggressivenessLevel.MAXIMUM)
