"""Shared pytest fixtures: paths and imports for the offline test suite."""

import sys
from pathlib import Path

import pytest

BASE_DIR = Path(__file__).parent.parent          # repo root
ENGINE_DIR = BASE_DIR / "offensive_emulator"

sys.path.insert(0, str(ENGINE_DIR))


@pytest.fixture()
def demo():
    import demo_target
    return demo_target


@pytest.fixture()
def svc():
    import attack_service
    return attack_service


@pytest.fixture()
def remediation_mod():
    import remediation
    return remediation
