"""
Advanced Adaptive Learning System
Learns from attack patterns, detects defenses, and adjusts tactics in real-time
"""

import json
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class DefenseSignal:
    """Detected defense mechanism"""
    name: str
    confidence: float  # 0.0-1.0
    first_detected: str
    last_detected: str
    count: int
    evasion_tactics: List[str]


class DefenseDetector:
    """Detects defense mechanisms from responses"""

    DEFENSE_PATTERNS = {
        "WAF": {
            "signals": ["403", "WAF", "blocked", "suspicious", "challenge"],
            "evasion": ["randomize_user_agent", "distribute_requests", "timing_jitter", "proxy_rotation"]
        },
        "RATE_LIMIT": {
            "signals": ["429", "rate limit", "too many", "throttle", "quota"],
            "evasion": ["backoff", "distribute_requests", "slow_down", "randomize_timing"]
        },
        "AUTH_HARDENING": {
            "signals": ["401", "invalid", "expired", "revoked", "signature"],
            "evasion": ["algorithm_confusion", "jwt_tampering", "token_refresh", "credential_theft"]
        },
        "DLP_SYSTEM": {
            "signals": ["DLP", "data loss", "blocked", "sensitive", "export"],
            "evasion": ["small_batches", "encoding", "compression", "time_distribution"]
        },
        "ANOMALY_DETECTION": {
            "signals": ["anomaly", "unusual", "suspicious", "behavior"],
            "evasion": ["blend_with_normal", "slow_execution", "mimic_user", "timing_alignment"]
        },
        "AUDIT_LOGGING": {
            "signals": ["audit", "logging", "immutable", "protected"],
            "evasion": ["parallel_operations", "timing_attacks", "false_flags"]
        },
        "CREDENTIAL_DETECTION": {
            "signals": ["credential", "secret", "api_key", "password"],
            "evasion": ["obfuscate", "environment_vars", "external_storage"]
        },
    }

    def __init__(self):
        self.detected_defenses: Dict[str, DefenseSignal] = {}

    def analyze_response(self, response: Dict[str, Any]) -> Optional[str]:
        """Analyze response for defense signals"""
        response_text = json.dumps(response).lower()
        status = response.get("status", 0)

        for defense_name, patterns in self.DEFENSE_PATTERNS.items():
            # Check status codes
            if any(str(s) in str(status) for s in [429, 403, 401]):
                if any(signal in response_text for signal in patterns["signals"]):
                    self._record_detection(defense_name, response)
                    return defense_name

            # Check response body
            if any(signal in response_text for signal in patterns["signals"]):
                self._record_detection(defense_name, response)
                return defense_name

        return None

    def _record_detection(self, defense_name: str, response: Dict) -> None:
        """Record defense detection"""
        now = datetime.now().isoformat()

        if defense_name not in self.detected_defenses:
            signal = DefenseSignal(
                name=defense_name,
                confidence=0.5,
                first_detected=now,
                last_detected=now,
                count=1,
                evasion_tactics=self.DEFENSE_PATTERNS[defense_name]["evasion"]
            )
            self.detected_defenses[defense_name] = signal
        else:
            signal = self.detected_defenses[defense_name]
            signal.last_detected = now
            signal.count += 1
            signal.confidence = min(1.0, signal.confidence + 0.1)  # Increase confidence
            logger.info(f"  [Defense] {defense_name} detected (confidence: {signal.confidence:.1%})")

    def get_defenses(self) -> Dict[str, DefenseSignal]:
        """Get all detected defenses"""
        return self.detected_defenses

    def get_high_confidence_defenses(self, threshold: float = 0.7) -> List[Tuple[str, DefenseSignal]]:
        """Get high-confidence defense detections"""
        return [(name, signal) for name, signal in self.detected_defenses.items()
                if signal.confidence >= threshold]


class AttackLearner:
    """Advanced adaptive learning system"""

    def __init__(self):
        self.defense_detector = DefenseDetector()
        self.attack_history: List[Dict[str, Any]] = []
        self.successful_patterns: Dict[str, List[str]] = defaultdict(list)
        self.failed_patterns: Dict[str, List[str]] = defaultdict(list)
        self.phase_success_rates: Dict[str, float] = defaultdict(float)

    def record_attack(self, phase: str, method: str, success: bool,
                     response: Optional[Dict] = None, payload: Optional[Dict] = None) -> None:
        """Record attack attempt for learning"""
        entry = {
            "phase": phase,
            "method": method,
            "success": success,
            "timestamp": datetime.now().isoformat(),
            "response": response,
            "payload": payload
        }
        self.attack_history.append(entry)

        # Detect defenses
        if response:
            defense = self.defense_detector.analyze_response(response)
            entry["defense_detected"] = defense

        # Track patterns
        key = f"{phase}:{method}"
        if success:
            self.successful_patterns[key].append(json.dumps(payload or {}))
        else:
            self.failed_patterns[key].append(json.dumps(payload or {}))

        self._update_success_rate(phase, success)

    def _update_success_rate(self, phase: str, success: bool) -> None:
        """Update phase success rate"""
        phase_attempts = [a for a in self.attack_history if a["phase"] == phase]
        if phase_attempts:
            successes = sum(1 for a in phase_attempts if a["success"])
            self.phase_success_rates[phase] = successes / len(phase_attempts)

    def get_best_tactics(self, phase: str, max_tactics: int = 3) -> List[str]:
        """Get best-performing tactics for a phase"""
        phase_attempts = [a for a in self.attack_history if a["phase"] == phase]
        if not phase_attempts:
            return []

        tactics_success = defaultdict(lambda: {"success": 0, "total": 0})
        for attempt in phase_attempts:
            method = attempt["method"]
            tactics_success[method]["total"] += 1
            if attempt["success"]:
                tactics_success[method]["success"] += 1

        # Calculate success rates
        ranked = sorted(
            tactics_success.items(),
            key=lambda x: (x[1]["success"] / x[1]["total"]) * x[1]["total"],
            reverse=True
        )

        return [tactic for tactic, _ in ranked[:max_tactics]]

    def suggest_evasion(self, detected_defenses: List[str]) -> List[str]:
        """Suggest evasion tactics for detected defenses"""
        evasion_tactics = set()

        for defense in detected_defenses:
            if defense in self.defense_detector.DEFENSE_PATTERNS:
                tactics = self.defense_detector.DEFENSE_PATTERNS[defense]["evasion"]
                evasion_tactics.update(tactics)
                logger.info(f"  [Evasion] Suggested tactics for {defense}: {tactics}")

        return list(evasion_tactics)

    def should_retry_with_mutation(self, phase: str, method: str) -> bool:
        """Decide if should retry with payload mutation"""
        key = f"{phase}:{method}"
        failures = len(self.failed_patterns.get(key, []))
        successes = len(self.successful_patterns.get(key, []))

        # Retry if we have failures and haven't succeeded yet
        if failures > 0 and successes == 0 and failures < 5:
            return True

        return False

    def get_mutation_suggestion(self, phase: str, method: str, original_payload: Dict) -> Dict:
        """Suggest mutation for failed payload"""
        mutations = {
            "obfuscate_values": lambda p: {k: f"_{v}_" if isinstance(v, str) else v
                                          for k, v in p.items()},
            "add_noise": lambda p: {**p, "noise": "random", "jitter": "true"},
            "encode_payload": lambda p: {k: str(v).encode('utf-8').hex() if isinstance(v, str) else v
                                        for k, v in p.items()},
            "split_payload": lambda p: {"batch": "1", **p},
        }

        # Apply multiple mutations
        mutated = original_payload.copy()
        for mutation_name, mutation_func in mutations.items():
            mutated = mutation_func(mutated)

        return mutated

    def get_learning_summary(self) -> Dict[str, Any]:
        """Get summary of learned patterns"""
        return {
            "total_attempts": len(self.attack_history),
            "phase_success_rates": dict(self.phase_success_rates),
            "detected_defenses": {
                name: {
                    "confidence": signal.confidence,
                    "count": signal.count,
                    "evasion_tactics": signal.evasion_tactics
                }
                for name, signal in self.defense_detector.detected_defenses.items()
            },
            "best_tactics": {
                phase: self.get_best_tactics(phase)
                for phase in set(a["phase"] for a in self.attack_history)
            }
        }
