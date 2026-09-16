"""
Offensive Emulator v3 Ultra - API Runner
Triggered by Next.js backend, outputs JSON report
"""

import asyncio
import json
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from offensive_emulator_v3 import (
    OffensiveEmulatorV3,
    AttackerPersona,
)


async def main():
    # Get config from environment variables
    target = os.getenv("ATTACK_TARGET", "http://localhost:3004")
    persona_name = os.getenv("ATTACK_PERSONA", "organized_crime")

    # Map persona name to enum
    persona_map = {
        "script_kiddie": AttackerPersona.SCRIPT_KIDDIE,
        "organized_crime": AttackerPersona.ORGANIZED_CRIME,
        "nation_state": AttackerPersona.NATION_STATE,
        "insider_threat": AttackerPersona.INSIDER_THREAT,
    }

    persona = persona_map.get(persona_name, AttackerPersona.ORGANIZED_CRIME)

    try:
        # Create emulator
        emulator = OffensiveEmulatorV3(target_url=target, persona=persona)

        # Run attack
        report = await emulator.run_full_attack()

        # Convert to dict and output as JSON
        import dataclasses

        report_dict = dataclasses.asdict(report)

        # Pretty print for debugging, then output clean JSON
        print(json.dumps(report_dict, indent=2, default=str))

    except Exception as e:
        # Output error as JSON
        error_report = {
            "error": str(e),
            "target": target,
            "persona": persona_name,
        }
        print(json.dumps(error_report), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
