"""
Offensive Emulator v3 Ultra - Example Usage
Run autonomous red team attack simulation with concrete attack engines
"""

import asyncio
import sys
import json
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from offensive_emulator_v3 import (
    OffensiveEmulatorV3,
    AttackerPersona,
    AttackPhase
)


async def run_example():
    """Run emulator against example target"""

    print("=" * 80)
    print("OFFENSIVE EMULATOR v3 ULTRA - AUTONOMOUS RED TEAM PLATFORM")
    print("=" * 80)
    print()

    # Example targets
    targets = [
        # "https://api.example.com",
        "http://localhost:3004",  # Local nexus-core app
    ]

    # Personas to test - vary budget and tactics
    personas = [
        AttackerPersona.SCRIPT_KIDDIE,      # Low budget, simple tactics
        # AttackerPersona.ORGANIZED_CRIME,    # Medium budget, sophisticated
        # AttackerPersona.NATION_STATE,       # Unlimited budget, advanced
    ]

    reports = []

    for target in targets:
        print(f"\n{'='*80}")
        print(f"TARGET: {target}")
        print(f"{'='*80}\n")

        for persona in personas:
            print(f"\n📍 ATTACKER PERSONA: {persona.value.upper()}")
            print("-" * 80)

            emulator = OffensiveEmulatorV3(
                target_url=target,
                persona=persona
            )

            try:
                # Execute full attack lifecycle
                report = await emulator.run_full_attack()
                reports.append(report)

                # Print detailed results
                print(f"\n✅ ATTACK COMPLETE\n")
                print(f"  Run ID:              {report.run_id}")
                print(f"  Success Rate:        {report.success_rate:.1%} ({report.successful_attacks}/{report.total_attacks})")
                print(f"  Time to Breach:      {report.time_to_breach_hours:.3f} hours")
                print(f"  Budget Spent:        ${emulator.spent:.2f} / ${emulator.budget:.2f}")
                print(f"  Vulnerabilities:     {len(report.vulnerabilities_found)}")
                print(f"  Attack Methods:      {', '.join([v['vector'] for v in report.vulnerabilities_found][:3])}")
                print(f"  Business Impact:     ${report.business_impact_usd:,.0f}")
                print(f"  Defense Coverage:    {report.defense_coverage}")

            except Exception as e:
                print(f"\n❌ ERROR: {e}")
                import traceback
                traceback.print_exc()

    # Generate aggregate report
    if reports:
        print("\n\n" + "=" * 80)
        print("AGGREGATE THREAT ASSESSMENT REPORT")
        print("=" * 80)

        avg_success = sum(r.success_rate for r in reports) / len(reports) if reports else 0
        max_impact = max(r.business_impact_usd for r in reports) if reports else 0
        total_vulns = sum(len(r.vulnerabilities_found) for r in reports)
        total_attacks = sum(r.total_attacks for r in reports)

        print(f"\n📊 SUMMARY STATISTICS")
        print(f"  Targets Assessed:    {len(targets)}")
        print(f"  Personas Deployed:   {len(personas)}")
        print(f"  Total Attack Vectors: {total_attacks}")
        print(f"  Successful Attacks:   {sum(r.successful_attacks for r in reports)}")
        print(f"  Average Success Rate: {avg_success:.1%}")
        print(f"  Max Business Impact:  ${max_impact:,.0f}")
        print(f"  Total Vulns Found:    {total_vulns}")

        # Save detailed JSON report
        report_path = Path(__file__).parent / "threat_report.json"
        with open(report_path, "w") as f:
            json.dump(
                [
                    {
                        "run_id": r.run_id,
                        "target": r.target,
                        "personas_tested": r.personas_tested,
                        "total_attacks": r.total_attacks,
                        "successful_attacks": r.successful_attacks,
                        "success_rate": r.success_rate,
                        "time_to_breach_hours": r.time_to_breach_hours,
                        "vulnerabilities_found": [
                            {
                                "vector": v["vector"],
                                "severity": v["severity"],
                                "success_rate": v["success_rate"],
                                "time_to_exploit": v["time_to_exploit"]
                            }
                            for v in r.vulnerabilities_found
                        ],
                        "attack_chains": r.attack_chains,
                        "defense_coverage": r.defense_coverage,
                        "business_impact_usd": r.business_impact_usd,
                        "generated_at": r.generated_at
                    }
                    for r in reports
                ],
                f,
                indent=2,
                default=str
            )
        print(f"\n📁 Full report saved to: {report_path}")
        print()


if __name__ == "__main__":
    asyncio.run(run_example())
