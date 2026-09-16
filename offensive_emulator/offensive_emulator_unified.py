"""
Offensive Emulator v3 - Unified Cohesive Red Team Platform
Single app with real attack simulation and complete state threading

All 6 attack phases share unified context:
  Recon → Exploit → Persist → Lateral Move → Exfil → Cover Tracks
"""

import asyncio
import json
import time
import uuid
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import asdict

# Import attack engines and context
try:
    from .attack_modules import (
        ReconEngine,
        ExploitEngine,
        PersistenceEngine,
        LateralMovementEngine,
        ExfiltrationEngine,
        CoverTracksEngine
    )
    from .attack_modules.base import AttackContext
except ImportError:
    from attack_modules import (
        ReconEngine,
        ExploitEngine,
        PersistenceEngine,
        LateralMovementEngine,
        ExfiltrationEngine,
        CoverTracksEngine
    )
    from attack_modules.base import AttackContext

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class UnifiedOffensiveEmulator:
    """
    Unified Offensive Emulator - Single cohesive red team simulation platform

    Real attack simulation with:
    - Unified context threading through all 6 phases
    - State-dependent phase progression
    - Real HTTP-based attack engines
    - Comprehensive attack chain logging
    - Business impact assessment
    """

    def __init__(self, target_url: str, run_id: str = None):
        self.run_id = run_id or str(uuid.uuid4())
        self.target_url = target_url

        # Initialize unified context
        self.context = AttackContext(
            target_url=target_url,
            run_id=self.run_id
        )

        # Initialize attack engines
        self.recon_engine = ReconEngine()
        self.exploit_engine = ExploitEngine()
        self.persistence_engine = PersistenceEngine()
        self.lateral_movement_engine = LateralMovementEngine()
        self.exfiltration_engine = ExfiltrationEngine()
        self.cover_tracks_engine = CoverTracksEngine()

        logger.info("="*80)
        logger.info(f"[{self.run_id}] Unified Offensive Emulator Initialized")
        logger.info(f"  Target: {target_url}")
        logger.info(f"  Platform: Real HTTP-based attack simulation")
        logger.info("="*80)

    async def phase_1_reconnaissance(self) -> bool:
        """
        Phase 1: Service fingerprinting, endpoint mapping, tech stack detection
        Returns: True if successful
        """
        logger.info("\n" + "="*80)
        logger.info(f"[PHASE 1] RECONNAISSANCE")
        logger.info("="*80)

        phase_start = time.time()

        try:
            result = await self.recon_engine.execute(self.context)

            phase_time = time.time() - phase_start
            self.context.phase_timings["recon"] = phase_time

            logger.info(f"\n✓ RECON COMPLETE ({phase_time:.2f}s)")
            logger.info(f"  Endpoints discovered: {len(self.context.discovered_endpoints)}")
            logger.info(f"  Tech stack: {self.context.tech_stack}")
            logger.info(f"  Hidden routes found: {len(self.context.hidden_routes)}")

            return len(self.context.discovered_endpoints) > 0

        except Exception as e:
            logger.error(f"✗ RECON FAILED: {e}")
            return False

    async def phase_2_exploitation(self) -> bool:
        """
        Phase 2: Gain initial access using discovered endpoints
        Returns: True if access was granted
        """
        logger.info("\n" + "="*80)
        logger.info(f"[PHASE 2] EXPLOITATION")
        logger.info("="*80)

        phase_start = time.time()

        try:
            result = await self.exploit_engine.execute(self.context)

            phase_time = time.time() - phase_start
            self.context.phase_timings["exploit"] = phase_time

            if self.context.access_granted:
                logger.info(f"\n✓ EXPLOITATION SUCCESSFUL ({phase_time:.2f}s)")
                logger.info(f"  Methods exploited: {self.context.exploited_methods}")
                return True
            else:
                logger.info(f"\n✗ Exploitation failed - no access granted")
                return False

        except Exception as e:
            logger.error(f"✗ EXPLOIT PHASE ERROR: {e}")
            return False

    async def phase_3_persistence(self) -> bool:
        """
        Phase 3: Maintain long-term access (requires Phase 2 success)
        Returns: True if persistence was established
        """
        if not self.context.access_granted:
            logger.info("\n⊘ PHASE 3 SKIPPED - No initial access")
            return False

        logger.info("\n" + "="*80)
        logger.info(f"[PHASE 3] PERSISTENCE")
        logger.info("="*80)

        phase_start = time.time()

        try:
            result = await self.persistence_engine.execute(self.context)

            phase_time = time.time() - phase_start
            self.context.phase_timings["persistence"] = phase_time

            if self.context.persistence_achieved:
                logger.info(f"\n✓ PERSISTENCE ESTABLISHED ({phase_time:.2f}s)")
                logger.info(f"  Backdoors installed: {len(self.context.backdoors_installed)}")
                logger.info(f"  Admin accounts created: {self.context.admin_accounts}")
                return True
            else:
                logger.info(f"\n✗ Persistence failed")
                return False

        except Exception as e:
            logger.error(f"✗ PERSISTENCE PHASE ERROR: {e}")
            return False

    async def phase_4_lateral_movement(self) -> bool:
        """
        Phase 4: Pivot to other systems (requires Phase 3 success)
        Returns: True if credentials were extracted
        """
        if not self.context.persistence_achieved:
            logger.info("\n⊘ PHASE 4 SKIPPED - No persistence established")
            return False

        logger.info("\n" + "="*80)
        logger.info(f"[PHASE 4] LATERAL MOVEMENT")
        logger.info("="*80)

        phase_start = time.time()

        try:
            result = await self.lateral_movement_engine.execute(self.context)

            phase_time = time.time() - phase_start
            self.context.phase_timings["lateral_movement"] = phase_time

            if self.context.extracted_credentials:
                logger.info(f"\n✓ LATERAL MOVEMENT SUCCESSFUL ({phase_time:.2f}s)")
                logger.info(f"  Credentials extracted: {len(self.context.extracted_credentials)}")
                logger.info(f"  Services discovered: {self.context.discovered_services}")
                return True
            else:
                logger.info(f"\n✗ Lateral movement failed - no credentials extracted")
                return False

        except Exception as e:
            logger.error(f"✗ LATERAL MOVEMENT ERROR: {e}")
            return False

    async def phase_5_exfiltration(self) -> bool:
        """
        Phase 5: Steal data at scale (requires Phase 4 success)
        Returns: True if data was exfiltrated
        """
        if not self.context.extracted_credentials:
            logger.info("\n⊘ PHASE 5 SKIPPED - No credentials for exfiltration")
            return False

        logger.info("\n" + "="*80)
        logger.info(f"[PHASE 5] EXFILTRATION")
        logger.info("="*80)

        phase_start = time.time()

        try:
            result = await self.exfiltration_engine.execute(self.context)

            phase_time = time.time() - phase_start
            self.context.phase_timings["exfiltration"] = phase_time

            if self.context.records_stolen > 0 or self.context.data_exfiltrated_mb > 0:
                logger.info(f"\n✓ EXFILTRATION SUCCESSFUL ({phase_time:.2f}s)")
                logger.info(f"  Records stolen: {self.context.records_stolen}")
                logger.info(f"  Data exfiltrated: {self.context.data_exfiltrated_mb:.2f} MB")
                logger.info(f"  Methods used: {self.context.extraction_methods}")
                return True
            else:
                logger.info(f"\n✗ Exfiltration failed - no data stolen")
                return False

        except Exception as e:
            logger.error(f"✗ EXFILTRATION ERROR: {e}")
            return False

    async def phase_6_cover_tracks(self) -> bool:
        """
        Phase 6: Delete evidence and evade detection
        Returns: True if traces were successfully covered
        """
        logger.info("\n" + "="*80)
        logger.info(f"[PHASE 6] COVER TRACKS")
        logger.info("="*80)

        phase_start = time.time()

        try:
            result = await self.cover_tracks_engine.execute(self.context)

            phase_time = time.time() - phase_start
            self.context.phase_timings["cover_tracks"] = phase_time

            logger.info(f"\n✓ COVER TRACKS COMPLETE ({phase_time:.2f}s)")
            logger.info(f"  Logs deleted: {self.context.logs_deleted}")
            logger.info(f"  Artifacts removed: {self.context.artifacts_removed}")
            logger.info(f"  Traces visible: {self.context.traces_visible}")
            return True

        except Exception as e:
            logger.error(f"✗ COVER TRACKS ERROR: {e}")
            return False

    async def run_full_attack(self) -> Dict[str, Any]:
        """
        Execute complete attack lifecycle with state threading
        Returns unified threat report
        """
        attack_start = time.time()

        # Execute all phases in sequence with state dependency
        phase1_success = await self.phase_1_reconnaissance()

        if phase1_success:
            phase2_success = await self.phase_2_exploitation()

            if phase2_success:
                phase3_success = await self.phase_3_persistence()

                if phase3_success:
                    phase4_success = await self.phase_4_lateral_movement()

                    if phase4_success:
                        phase5_success = await self.phase_5_exfiltration()
                    else:
                        phase5_success = False
                else:
                    phase4_success = phase5_success = False
            else:
                phase3_success = phase4_success = phase5_success = False
        else:
            phase2_success = phase3_success = phase4_success = phase5_success = False

        # Final cleanup
        phase6_success = await self.phase_6_cover_tracks()

        # Generate comprehensive threat report
        total_time = time.time() - attack_start

        report = {
            "run_id": self.run_id,
            "target": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "total_time_seconds": total_time,

            "attack_chain": {
                "phase_1_recon": phase1_success,
                "phase_2_exploit": phase2_success,
                "phase_3_persistence": phase3_success,
                "phase_4_lateral_movement": phase4_success,
                "phase_5_exfiltration": phase5_success,
                "phase_6_cover_tracks": phase6_success,
            },

            "phase_timings": self.context.phase_timings,

            "recon_results": {
                "endpoints_discovered": len(self.context.discovered_endpoints),
                "endpoints": self.context.discovered_endpoints[:20],  # Sample first 20
                "tech_stack": self.context.tech_stack,
                "hidden_routes": self.context.hidden_routes,
            },

            "exploit_results": {
                "access_granted": self.context.access_granted,
                "methods": self.context.exploited_methods,
                "valid_tokens": len(self.context.valid_tokens),
            },

            "persistence_results": {
                "backdoors_installed": len(self.context.backdoors_installed),
                "admin_accounts": self.context.admin_accounts,
                "backdoors": self.context.backdoors_installed,
            },

            "lateral_movement_results": {
                "services_discovered": self.context.discovered_services,
                "credentials_extracted": len(self.context.extracted_credentials),
                "ssh_keys_found": len(self.context.ssh_keys_found),
            },

            "exfiltration_results": {
                "records_stolen": self.context.records_stolen,
                "data_exfiltrated_mb": self.context.data_exfiltrated_mb,
                "extraction_methods": self.context.extraction_methods,
            },

            "cover_tracks_results": {
                "logs_deleted": self.context.logs_deleted,
                "artifacts_removed": self.context.artifacts_removed,
                "traces_visible": self.context.traces_visible,
            },

            "summary": self._generate_summary(phase2_success, phase3_success, phase4_success, phase5_success),
        }

        return report

    def _generate_summary(self, phase2, phase3, phase4, phase5) -> Dict[str, Any]:
        """Generate attack summary and risk assessment"""
        success_rate = sum([phase2, phase3, phase4, phase5]) / 4 * 100

        impact_levels = {
            "Critical": self.context.records_stolen > 10000 or self.context.data_exfiltrated_mb > 1000,
            "High": self.context.records_stolen > 1000 or self.context.data_exfiltrated_mb > 100,
            "Medium": self.context.records_stolen > 0 or self.context.data_exfiltrated_mb > 0,
            "Low": not (self.context.records_stolen > 0 or self.context.data_exfiltrated_mb > 0)
        }

        severity = next((level for level, triggered in impact_levels.items() if triggered), "Low")

        return {
            "attack_success_rate": f"{success_rate:.1f}%",
            "severity": severity,
            "phases_completed": sum([phase2, phase3, phase4, phase5]),
            "key_findings": [
                f"Discovered {len(self.context.discovered_endpoints)} endpoints",
                f"Exploited {len(self.context.exploited_methods)} methods" if self.context.exploited_methods else "No successful exploits",
                f"Established {len(self.context.backdoors_installed)} backdoors" if self.context.backdoors_installed else "No persistence",
                f"Extracted {len(self.context.extracted_credentials)} credentials" if self.context.extracted_credentials else "No credential extraction",
                f"Stole {self.context.records_stolen} records / {self.context.data_exfiltrated_mb:.2f} MB" if self.context.records_stolen > 0 else "No data theft",
                f"Evaded detection: {not self.context.traces_visible}",
            ]
        }

    def print_report(self, report: Dict[str, Any]) -> None:
        """Print human-readable threat report"""
        print("\n" + "="*80)
        print("UNIFIED OFFENSIVE EMULATOR - THREAT ASSESSMENT REPORT")
        print("="*80)
        print(f"\nRun ID:          {report['run_id']}")
        print(f"Target:          {report['target']}")
        print(f"Total Time:      {report['total_time_seconds']:.2f}s")
        print(f"Timestamp:       {report['timestamp']}")

        print(f"\n{'ATTACK CHAIN':^80}")
        print("-"*80)
        for phase, success in report['attack_chain'].items():
            status = "✓" if success else "✗"
            print(f"  {status} {phase.replace('_', ' ').title()}: {success}")

        print(f"\n{'RECONNAISSANCE PHASE':^80}")
        print("-"*80)
        print(f"  Endpoints: {report['recon_results']['endpoints_discovered']}")
        print(f"  Tech Stack: {report['recon_results']['tech_stack']}")

        if report['exploit_results']['access_granted']:
            print(f"\n{'EXPLOITATION PHASE':^80}")
            print("-"*80)
            print(f"  Methods: {report['exploit_results']['methods']}")

        if report['persistence_results']['admin_accounts']:
            print(f"\n{'PERSISTENCE PHASE':^80}")
            print("-"*80)
            print(f"  Admin Accounts: {report['persistence_results']['admin_accounts']}")
            print(f"  Backdoors: {report['persistence_results']['backdoors_installed']}")

        if report['lateral_movement_results']['credentials_extracted'] > 0:
            print(f"\n{'LATERAL MOVEMENT PHASE':^80}")
            print("-"*80)
            print(f"  Credentials: {report['lateral_movement_results']['credentials_extracted']}")

        if report['exfiltration_results']['records_stolen'] > 0:
            print(f"\n{'EXFILTRATION PHASE':^80}")
            print("-"*80)
            print(f"  Records Stolen: {report['exfiltration_results']['records_stolen']}")
            print(f"  Data: {report['exfiltration_results']['data_exfiltrated_mb']:.2f} MB")

        print(f"\n{'SUMMARY':^80}")
        print("-"*80)
        print(f"  Success Rate: {report['summary']['attack_success_rate']}")
        print(f"  Severity: {report['summary']['severity']}")
        print(f"\nKey Findings:")
        for finding in report['summary']['key_findings']:
            print(f"  • {finding}")

        print("\n" + "="*80)


async def main():
    """Example: Run unified red team simulation"""

    emulator = UnifiedOffensiveEmulator(
        target_url="http://localhost:3004"
    )

    report = await emulator.run_full_attack()

    # Print report
    emulator.print_report(report)

    # Save JSON report
    import json
    report_file = f"threat_report_{emulator.run_id}.json"
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"📁 Detailed report saved to: {report_file}")


if __name__ == "__main__":
    asyncio.run(main())
