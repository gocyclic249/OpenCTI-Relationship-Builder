"""Coverage for octirb/tui/runner.py: one background subprocess at a time,
its merged stdout/stderr drained line by line into the UI."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from octirb.tui import runner

PRINT_BOTH = "import sys; print('out'); print('err', file=sys.stderr); print('out2')"
DEADLINE_S = 10.0
POLL_S = 0.02


def wait_done(job: runner.Job) -> list[str]:
    lines: list[str] = []
    for _ in range(int(DEADLINE_S / POLL_S)):
        lines += job.drain()
        if not job.running:
            lines += job.drain()
            return lines
        time.sleep(POLL_S)
    raise AssertionError("job did not finish")


def test_job_streams_merged_output_in_order() -> None:
    job = runner.Job()
    job.start([sys.executable, "-c", PRINT_BOTH])
    lines = wait_done(job)
    assert [ln for ln in lines if not ln.startswith("$ ")][:3] == ["out", "err", "out2"]
    assert job.exit_code == 0
    assert lines[-1].startswith("exit 0")


def test_job_reports_nonzero_exit() -> None:
    job = runner.Job()
    job.start([sys.executable, "-c", "raise SystemExit(2)"])
    wait_done(job)
    assert job.exit_code == 2


def test_job_refuses_to_overlap() -> None:
    job = runner.Job()
    job.start([sys.executable, "-c", "import time; time.sleep(0.5)"])
    with pytest.raises(RuntimeError, match="already running"):
        job.start([sys.executable, "-c", "pass"])
    wait_done(job)


def test_job_rejects_empty_argv() -> None:
    with pytest.raises(ValueError):
        runner.Job().start([])


def test_octirb_argv_runs_the_package_with_the_repo_on_pythonpath(tmp_path: Path) -> None:
    cfg = tmp_path / "c.toml"
    argv, env = runner.octirb_command(["status"], config=cfg)
    assert argv[:3] == [sys.executable, "-m", "octirb"]
    assert argv[3:] == ["--config", str(cfg), "status"]
    repo = str(Path(runner.__file__).resolve().parents[2])
    assert env["PYTHONPATH"].split(":")[0] == repo


def test_octirb_argv_without_config_passes_no_flag() -> None:
    argv, _env = runner.octirb_command(["status"], config=None)
    assert argv[3:] == ["status"]


def test_job_runs_in_cwd(tmp_path: Path) -> None:
    job = runner.Job()
    job.start([sys.executable, "-c", "import os; print(os.getcwd())"], cwd=tmp_path)
    lines = wait_done(job)
    assert lines[1] == str(tmp_path.resolve())


def test_job_transform_rewrites_and_drops() -> None:
    job = runner.Job()

    def shout(line: str) -> str | None:
        return None if line == "drop" else line.upper()

    job.start([sys.executable, "-c", "print('keep'); print('drop')"], transform=shout)
    lines = wait_done(job)
    assert "KEEP" in lines
    assert "drop" not in lines
    assert "DROP" not in lines
    assert lines[-1] == "exit 0"


def test_job_transform_error_keeps_exit_code() -> None:
    job = runner.Job()

    def boom(line: str) -> str | None:
        raise ValueError(line)

    job.start([sys.executable, "-c", "print('x')"], transform=boom)
    lines = wait_done(job)
    assert job.exit_code == 0
    assert "[unreadable output] x" in lines
    assert lines[-1] == "exit 0"


class SlowExitJob(runner.Job):
    """Holds the reader thread alive for a moment after it queues `exit N`,
    widening the window between that line and the thread ending."""

    def _put(self, line: str) -> None:
        super()._put(line)
        if line.startswith(runner.DONE_PREFIX):
            time.sleep(0.3)


def test_job_not_running_once_exit_line_drained() -> None:
    """A caller that has drained the `exit N` line must already see
    running == False, with no settling sleep (the wave starts its next step
    right then)."""
    job = SlowExitJob()
    job.start([sys.executable, "-c", "pass"])
    seen = False
    for _ in range(int(DEADLINE_S / POLL_S)):
        if any(line.startswith(runner.DONE_PREFIX) for line in job.drain()):
            seen = True
            break
        time.sleep(POLL_S)
    assert seen, "exit line never arrived"
    assert not job.running
