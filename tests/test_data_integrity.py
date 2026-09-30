"""Data integrity: no real-looking secrets, hygiene of the repo tree."""

import subprocess
from pathlib import Path

BASE = Path(__file__).parent.parent


def _tracked_files():
    out = subprocess.run(["git", "ls-files"], cwd=BASE, capture_output=True, text=True)
    if out.returncode != 0:
        # not a git checkout (e.g. exported archive) — fall back to walking
        return [str(p) for p in (BASE / "offensive_emulator").rglob("*") if p.is_file()]
    return [line for line in out.stdout.splitlines() if line.strip()]


def test_no_realistic_secrets():
    """GitHub's secret scanner blocked us once — never again."""
    # markers are concatenated so this file itself never contains the literals
    forbidden = ("sk" + "_live_", "rk" + "_live_", "gh" + "p_", "github_" + "pat_",
                 "AKIA4" + "VPAY", "-----BEGIN OPEN" + "SSH", "xox" + "b-", "AI" + "za")
    for f in _tracked_files():
        p = BASE / f
        if not p.is_file() or p.stat().st_size > 2_000_000:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for marker in forbidden:
            assert marker not in text, f"secret-like marker {marker!r} found in {f}"


def test_gitignore_covers_runtime_data():
    gi = (BASE / ".gitignore").read_text()
    assert "data/" in gi
    assert "__pycache__" in gi


def test_no_runtime_data_committed():
    for f in _tracked_files():
        assert not f.startswith("offensive_emulator/data/"), f"runtime data committed: {f}"


def test_vendor_threejs_present():
    vendor = BASE / "offensive_emulator" / "static" / "vendor" / "three.min.js"
    assert vendor.is_file() and vendor.stat().st_size > 400_000


def test_entrypoint_exists():
    assert (BASE / "run.py").is_file()
    assert (BASE / "Dockerfile").is_file()
