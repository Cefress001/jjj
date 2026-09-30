"""
Offensive Emulator v4 — Unified Red Team Simulation Platform
=============================================================
ONE app:  python run.py   (from the repository root)

  • Landing page → 3D mission console
  • 6-phase kill chain: recon → exploit → persist → lateral → exfil → cover
  • Real HTTP attack engines when `aiohttp` is installed,
    zero-dependency simulation otherwise
  • Built-in demo target (VulnPay) served at /demo
"""

__version__ = "4.0"

try:
    from .offensive_emulator_unified import UnifiedOffensiveEmulator
    from .attack_modules import (
        ReconEngine,
        ExploitEngine,
        PersistenceEngine,
        LateralMovementEngine,
        ExfiltrationEngine,
        CoverTracksEngine
    )
    from .attack_modules.base import AttackContext

    REAL_ENGINES = True

    __all__ = [
        "UnifiedOffensiveEmulator",
        "AttackContext",
        "ReconEngine",
        "ExploitEngine",
        "PersistenceEngine",
        "LateralMovementEngine",
        "ExfiltrationEngine",
        "CoverTracksEngine",
        "REAL_ENGINES",
    ]
except ImportError:  # aiohttp missing — the app runs in simulation mode
    REAL_ENGINES = False
    __all__ = ["REAL_ENGINES"]
