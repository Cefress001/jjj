"""Attack Modules Package - Autonomous attack engines for red teaming"""

from .base import (
    AttackModule,
    ReconModule,
    ExploitModule,
    PersistenceModule,
    LateralMovementModule,
    ExfiltrationModule,
    CoverTracksModule
)
# The concrete HTTP engines require the optional aiohttp dependency.  Keep the
# package importable without it so lightweight helpers (challenge detection,
# report parsing, and the simulation engine) really remain zero-dependency.
try:  # pragma: no branch - availability depends on the installation
    from .recon_engine import ReconEngine
    from .exploit_engine import ExploitEngine
    from .persistence_engine import PersistenceEngine
    from .lateral_movement_engine import LateralMovementEngine
    from .exfiltration_engine import ExfiltrationEngine
    from .cover_tracks_engine import CoverTracksEngine
except ImportError as exc:  # only suppress a missing optional aiohttp
    if getattr(exc, "name", None) != "aiohttp":
        raise
    ReconEngine = ExploitEngine = PersistenceEngine = None
    LateralMovementEngine = ExfiltrationEngine = CoverTracksEngine = None

__all__ = [
    "AttackModule", "ReconModule", "ExploitModule", "PersistenceModule",
    "LateralMovementModule", "ExfiltrationModule", "CoverTracksModule",
    "ReconEngine", "ExploitEngine", "PersistenceEngine",
    "LateralMovementEngine", "ExfiltrationEngine", "CoverTracksEngine",
]
