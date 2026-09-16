"""
Advanced Metrics and Analytics
Track performance, success rates, and generate detailed reports
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from statistics import mean, stdev
import json


@dataclass
class PhaseMetrics:
    """Metrics for a single attack phase"""
    phase_name: str
    total_attempts: int = 0
    successful_attempts: int = 0
    failed_attempts: int = 0
    avg_duration_ms: float = 0.0
    defenses_triggered: int = 0
    evasion_tactics_used: List[str] = field(default_factory=list)
    artifacts_created: int = 0

    @property
    def success_rate(self) -> float:
        """Calculate success rate"""
        if self.total_attempts == 0:
            return 0.0
        return self.successful_attempts / self.total_attempts

    @property
    def defense_trigger_rate(self) -> float:
        """Calculate defense trigger rate"""
        if self.total_attempts == 0:
            return 0.0
        return self.defenses_triggered / self.total_attempts


@dataclass
class AttackChainMetrics:
    """Metrics for complete attack chain"""
    run_id: str
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None

    total_duration_seconds: float = 0.0
    phases_completed: int = 0
    total_success_rate: float = 0.0

    phase_metrics: Dict[str, PhaseMetrics] = field(default_factory=dict)

    # Data theft metrics
    records_stolen: int = 0
    data_exfiltrated_mb: float = 0.0
    pii_records_found: int = 0

    # Attack impact
    admin_accounts_created: int = 0
    backdoors_installed: int = 0
    credentials_extracted: int = 0
    services_compromised: int = 0

    # Defense metrics
    defenses_detected: List[str] = field(default_factory=list)
    successful_evasions: int = 0
    failed_evasions: int = 0

    # Cleanup metrics
    logs_deleted: int = 0
    traces_remaining: int = 0

    def add_phase_metrics(self, phase_name: str, metrics: PhaseMetrics) -> None:
        """Add metrics for a phase"""
        self.phase_metrics[phase_name] = metrics

    def calculate_total_metrics(self) -> None:
        """Calculate aggregate metrics"""
        if not self.phase_metrics:
            return

        # Calculate phases completed
        self.phases_completed = sum(1 for m in self.phase_metrics.values() if m.successful_attempts > 0)

        # Calculate total success rate
        total_attempts = sum(m.total_attempts for m in self.phase_metrics.values())
        if total_attempts > 0:
            total_successful = sum(m.successful_attempts for m in self.phase_metrics.values())
            self.total_success_rate = total_successful / total_attempts

    def get_phase_summary(self, phase_name: str) -> Optional[Dict[str, Any]]:
        """Get summary for a specific phase"""
        if phase_name not in self.phase_metrics:
            return None

        metrics = self.phase_metrics[phase_name]
        return {
            "phase": phase_name,
            "success_rate": f"{metrics.success_rate:.1%}",
            "attempts": f"{metrics.successful_attempts}/{metrics.total_attempts}",
            "duration_ms": f"{metrics.avg_duration_ms:.1f}",
            "defenses_triggered": metrics.defenses_triggered,
            "evasion_tactics": metrics.evasion_tactics_used,
        }


class MetricsCollector:
    """Collect metrics throughout attack execution"""

    def __init__(self, run_id: str, target: str):
        self.run_id = run_id
        self.target = target
        self.metrics = AttackChainMetrics(
            run_id=run_id,
            target=target,
            start_time=datetime.now()
        )
        self.phase_durations: Dict[str, List[float]] = {}

    def record_phase_attempt(self, phase: str, success: bool, duration_ms: float,
                            defense_triggered: Optional[str] = None) -> None:
        """Record single phase attempt"""
        if phase not in self.metrics.phase_metrics:
            self.metrics.phase_metrics[phase] = PhaseMetrics(phase_name=phase)

        phase_m = self.metrics.phase_metrics[phase]
        phase_m.total_attempts += 1

        if success:
            phase_m.successful_attempts += 1
        else:
            phase_m.failed_attempts += 1

        if defense_triggered:
            phase_m.defenses_triggered += 1
            if defense_triggered not in self.metrics.defenses_detected:
                self.metrics.defenses_detected.append(defense_triggered)

        # Track duration
        if phase not in self.phase_durations:
            self.phase_durations[phase] = []
        self.phase_durations[phase].append(duration_ms)
        phase_m.avg_duration_ms = mean(self.phase_durations[phase])

    def record_artifact(self, phase: str, artifact_type: str, count: int = 1) -> None:
        """Record attack artifacts"""
        if phase in self.metrics.phase_metrics:
            self.metrics.phase_metrics[phase].artifacts_created += count

        # Update specific counters
        if artifact_type == "admin_account":
            self.metrics.admin_accounts_created += count
        elif artifact_type == "backdoor":
            self.metrics.backdoors_installed += count
        elif artifact_type == "credential":
            self.metrics.credentials_extracted += count
        elif artifact_type == "service":
            self.metrics.services_compromised += count

    def record_data_theft(self, records: int = 0, data_mb: float = 0.0, pii_count: int = 0) -> None:
        """Record data theft metrics"""
        self.metrics.records_stolen += records
        self.metrics.data_exfiltrated_mb += data_mb
        self.metrics.pii_records_found += pii_count

    def record_evasion(self, phase: str, tactic: str, success: bool) -> None:
        """Record evasion attempt"""
        if phase in self.metrics.phase_metrics:
            if tactic not in self.metrics.phase_metrics[phase].evasion_tactics_used:
                self.metrics.phase_metrics[phase].evasion_tactics_used.append(tactic)

        if success:
            self.metrics.successful_evasions += 1
        else:
            self.metrics.failed_evasions += 1

    def record_cleanup(self, logs_deleted: int = 0, traces_remaining: int = 0) -> None:
        """Record cleanup metrics"""
        self.metrics.logs_deleted += logs_deleted
        self.metrics.traces_remaining += traces_remaining

    def finalize(self) -> AttackChainMetrics:
        """Finalize metrics collection"""
        self.metrics.end_time = datetime.now()
        self.metrics.total_duration_seconds = (
            self.metrics.end_time - self.metrics.start_time
        ).total_seconds()
        self.metrics.calculate_total_metrics()
        return self.metrics

    def get_summary(self) -> Dict[str, Any]:
        """Get metrics summary"""
        return {
            "run_id": self.run_id,
            "target": self.target,
            "total_duration": f"{self.metrics.total_duration_seconds:.2f}s",
            "phases_completed": self.metrics.phases_completed,
            "success_rate": f"{self.metrics.total_success_rate:.1%}",
            "records_stolen": self.metrics.records_stolen,
            "data_mb": f"{self.metrics.data_exfiltrated_mb:.2f}",
            "defenses_detected": self.metrics.defenses_detected,
            "evasion_success_rate": f"{self.metrics.successful_evasions / max(1, self.metrics.successful_evasions + self.metrics.failed_evasions):.1%}",
        }


class ReportGenerator:
    """Generate detailed attack reports"""

    @staticmethod
    def generate_html_report(metrics: AttackChainMetrics) -> str:
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Attack Report - {metrics.run_id}</title>
    <style>
        body {{ font-family: Arial; margin: 20px; background: #f5f5f5; }}
        .header {{ background: #222; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ background: white; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .metric {{ display: inline-block; margin: 10px 20px; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #d9534f; }}
        .phase {{ margin: 10px 0; padding: 10px; background: #f9f9f9; border-left: 4px solid #5cb85c; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
        th {{ background: #f2f2f2; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Offensive Emulator - Attack Report</h1>
        <p>Target: {metrics.target} | Run ID: {metrics.run_id}</p>
    </div>

    <div class="section">
        <h2>Summary Metrics</h2>
        <div class="metric">
            <div>Phases Completed</div>
            <div class="metric-value">{metrics.phases_completed}</div>
        </div>
        <div class="metric">
            <div>Success Rate</div>
            <div class="metric-value">{metrics.total_success_rate:.1%}</div>
        </div>
        <div class="metric">
            <div>Duration</div>
            <div class="metric-value">{metrics.total_duration_seconds:.1f}s</div>
        </div>
    </div>

    <div class="section">
        <h2>Attack Impact</h2>
        <div class="metric">
            <div>Records Stolen</div>
            <div class="metric-value">{metrics.records_stolen}</div>
        </div>
        <div class="metric">
            <div>Data Exfiltrated</div>
            <div class="metric-value">{metrics.data_exfiltrated_mb:.1f} MB</div>
        </div>
        <div class="metric">
            <div>Backdoors</div>
            <div class="metric-value">{metrics.backdoors_installed}</div>
        </div>
    </div>

    <div class="section">
        <h2>Phase Details</h2>
        <table>
            <tr>
                <th>Phase</th>
                <th>Success Rate</th>
                <th>Attempts</th>
                <th>Duration (ms)</th>
                <th>Defenses Triggered</th>
            </tr>
"""

        for phase_name, phase_m in metrics.phase_metrics.items():
            html += f"""
            <tr>
                <td>{phase_name}</td>
                <td>{phase_m.success_rate:.1%}</td>
                <td>{phase_m.successful_attempts}/{phase_m.total_attempts}</td>
                <td>{phase_m.avg_duration_ms:.1f}</td>
                <td>{phase_m.defenses_triggered}</td>
            </tr>
"""

        html += """
        </table>
    </div>

    <div class="section">
        <h2>Defenses Detected</h2>
        <ul>
"""
        for defense in metrics.defenses_detected:
            html += f"            <li>{defense}</li>\n"

        html += """
        </ul>
    </div>
</body>
</html>
"""
        return html

    @staticmethod
    def generate_json_report(metrics: AttackChainMetrics) -> str:
        """Generate JSON report"""
        return json.dumps(asdict(metrics), default=str, indent=2)
