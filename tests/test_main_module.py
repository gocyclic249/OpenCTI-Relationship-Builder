"""`python -m octirb` must work: the TUI runner launches every step that way."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_python_m_octirb_help_exits_zero() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "octirb", "--help"], cwd=REPO, capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0
    assert "tui" in proc.stdout
