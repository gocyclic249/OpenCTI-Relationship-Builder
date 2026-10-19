"""End-to-end smoke tests for the curses screen, driven through a pty.

The screen is deliberately thin; these only prove it starts, quits, and
that the review screen writes picks.json through the real key path.
"""

from __future__ import annotations

import contextlib
import json
import os
import pty
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[1]
STARTUP_S = 1.5
DEADLINE_S = 20.0
POLL_S = 0.05


def write_run(runs_dir: Path, run_id: str, linker: str, **files: Any) -> Path:
    d = runs_dir / run_id
    d.mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"run_id": run_id, "linker": linker,
                                             "created": "2026-01-01T00:00:00+00:00", "options": {}}))
    for name, data in files.items():
        (d / name.replace("_json", ".json")).write_text(json.dumps(data))
    return d


def drive_tui(tmp_path: Path, keys: bytes) -> tuple[int, str]:
    """Run `octi-rb tui` on a pty against tmp_path/runs, send keys, return (exit, transcript)."""
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'[runs]\ndir = "{tmp_path / "runs"}"\n')
    master, slave = pty.openpty()
    env = dict(os.environ, TERM="xterm", LINES="40", COLUMNS="120", PYTHONPATH=str(REPO))
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "octirb", "--config", str(cfg), "tui"],
        stdin=slave, stdout=slave, stderr=slave, env=env, cwd=tmp_path, close_fds=True,
    )
    os.close(slave)
    transcript = b""
    try:
        time.sleep(STARTUP_S)
        os.write(master, keys)
        for _ in range(int(DEADLINE_S / POLL_S)):
            # EIO on the master once the child closed its side is the normal end.
            with contextlib.suppress(OSError):
                transcript += os.read(master, 65536)
            if proc.poll() is not None:
                break
            time.sleep(POLL_S)
        else:
            proc.kill()
            raise AssertionError("tui did not exit")
    finally:
        os.close(master)
    return proc.returncode, transcript.decode("utf-8", "replace")


@pytest.mark.skipif(sys.platform == "win32", reason="curses + pty are POSIX only")
def test_tui_starts_and_quits_with_q(tmp_path: Path) -> None:
    write_run(tmp_path / "runs", "r1", "report-location", selection_json=[1])
    code, transcript = drive_tui(tmp_path, b"q")
    assert code == 0
    assert "select" in transcript and "r1" in transcript


@pytest.mark.skipif(sys.platform == "win32", reason="curses + pty are POSIX only")
def test_review_screen_saves_picks(tmp_path: Path) -> None:
    item = {"report_id": "r1", "entity_name": "France", "confidence": "medium", "evidence": "q",
            "title": "t", "review_reasons": ["confidence=medium"], "hard_fail": False}
    run_dir = write_run(tmp_path / "runs", "r1", "report-location", auto_json=[], review_json=[item])
    code, _ = drive_tui(tmp_path, b"v s q")
    assert code == 0
    from octirb import picks

    saved = json.loads((run_dir / "picks.json").read_text())
    assert saved["accepted"] == [picks.item_key(item)]


@pytest.mark.skipif(sys.platform == "win32", reason="curses + pty are POSIX only")
def test_tui_with_no_runs_still_opens(tmp_path: Path) -> None:
    code, transcript = drive_tui(tmp_path, b"q")
    assert code == 0
    assert "no runs yet" in transcript


def test_finished_select_switches_to_the_new_run(tmp_path: Path) -> None:
    """No pty: drive the finish hook directly. A successful select must land
    on the run it created, a failed one must stay put."""
    from octirb.config import Config, RunsCfg
    from octirb.tui import screen

    runs = tmp_path / "runs"
    write_run(runs, "old", "report-vuln")
    app = screen.App(cfg=Config(runs=RunsCfg(dir=str(runs))), config_path=None)
    screen._load_run(app, None)
    assert app.run is not None and app.run.run_id == "old"

    (runs / "old" / "meta.json").write_text(json.dumps({"linker": "report-vuln",
                                                        "created": "2026-01-01T00:00:00+00:00"}))
    d = write_run(runs, "fresh", "report-location")
    (d / "meta.json").write_text(json.dumps({"linker": "report-location",
                                             "created": "2026-03-01T00:00:00+00:00"}))
    app.started, app.job.exit_code = ["select", "--linker", "report-location"], 2
    screen._on_job_finished(app)
    assert app.run.run_id == "old"

    app.started, app.job.exit_code = ["select", "--linker", "report-location"], 0
    screen._on_job_finished(app)
    assert app.run.run_id == "fresh"
    assert [s.key for s in app.steps][:3] == ["select", "fetch", "batch"]


# ---------------------------------------------------------------- waves (no pty)


class FakeJob:
    """Stands in for runner.Job: records start() calls, never spawns."""

    def __init__(self) -> None:
        self.running = False
        self.exit_code: int | None = None
        self.calls: list[dict[str, Any]] = []
        self.terminated = 0

    def start(self, argv: list[str], env: dict[str, str] | None = None, *, label: str = "",
              cwd: Path | None = None, transform: Any = None) -> None:
        self.calls.append({"argv": list(argv), "env": env, "label": label, "cwd": cwd, "transform": transform})
        self.running = True

    def terminate(self) -> None:
        self.terminated += 1

    def drain(self) -> list[str]:
        return []


def make_app(runs: Path, claude: str | None = None) -> tuple[Any, FakeJob]:
    from octirb.config import Config, RunsCfg
    from octirb.tui import screen

    runs.mkdir(parents=True, exist_ok=True)
    job = FakeJob()
    app = screen.App(cfg=Config(runs=RunsCfg(dir=str(runs))), config_path=None)
    app.job = job
    app.claude = claude
    screen._load_run(app, None)
    return app, job


def test_wave_key_refused_while_job_running(tmp_path: Path) -> None:
    from octirb.tui import screen

    app, job = make_app(tmp_path / "runs")
    job.running = True
    screen._key_main(app, ord("1"))
    assert app.wave is None
    assert job.calls == []
    assert "wait before starting a wave" in app.message


def test_enter_on_wave_row_starts_the_wave(tmp_path: Path) -> None:
    from octirb.tui import screen

    app, job = make_app(tmp_path / "runs")
    app.cursor = [s.key for s in app.steps].index("wave1")
    screen._key_main(app, 10)
    assert app.wave is not None
    assert len(job.calls) == 1
    assert "select" in job.calls[0]["argv"] and "report-location" in job.calls[0]["argv"]


def test_enter_refused_while_wave_running(tmp_path: Path) -> None:
    from octirb.tui import screen

    app, job = make_app(tmp_path / "runs")
    screen._key_main(app, ord("1"))
    assert app.wave is not None and len(job.calls) == 1
    job.running = False
    app.cursor = 0
    screen._key_main(app, 10)
    assert app.mode == "main"
    assert len(job.calls) == 1
    assert "x cancels it" in app.message


def test_wave2_without_wave1_says_press_1(tmp_path: Path) -> None:
    from octirb.tui import screen

    app, job = make_app(tmp_path / "runs")
    screen._key_main(app, ord("2"))
    assert app.wave is None
    assert job.calls == []
    assert "press 1" in app.message


def test_extract_row_starts_claude_with_condense(tmp_path: Path) -> None:
    from octirb.tui import extract, screen

    runs = tmp_path / "runs"
    run_dir = write_run(runs, "r1", "report-location", batch_json=[{"report_id": "x"}])
    app, job = make_app(runs, claude="/bin/claude")
    app.cursor = [s.key for s in app.steps].index("extract")
    screen._key_main(app, 10)
    assert len(job.calls) == 1
    call = job.calls[0]
    assert call["cwd"] == run_dir
    assert call["transform"] is extract.condense
    assert call["argv"][0] == "/bin/claude"
    assert "r1" in call["label"]


def test_extract_row_without_claude_shows_hint(tmp_path: Path) -> None:
    from octirb.tui import screen

    runs = tmp_path / "runs"
    write_run(runs, "r1", "report-location", batch_json=[{"report_id": "x"}])
    app, job = make_app(runs, claude=None)
    app.cursor = [s.key for s in app.steps].index("extract")
    screen._key_main(app, 10)
    assert job.calls == []
    assert app.message.startswith("claude not on PATH")


def test_wave_advances_on_job_finish(tmp_path: Path) -> None:
    from octirb.tui import screen

    runs = tmp_path / "runs"
    app, job = make_app(runs)
    screen._key_main(app, ord("1"))
    first = job.calls[0]["argv"]
    assert "select" in first
    run_id = first[first.index("--run-id") + 1]
    assert "-w1-report-location" in run_id
    write_run(runs, run_id, "report-location", selection_json=[{"id": "r"}])
    job.running, job.exit_code = False, 0
    screen._on_job_finished(app)
    second = job.calls[1]["argv"]
    assert "fetch" in second and "--run-id" in second
    assert second[second.index("--run-id") + 1] == run_id


def test_wave_cancel_with_x_ends_wave(tmp_path: Path) -> None:
    from octirb.tui import screen

    app, job = make_app(tmp_path / "runs")
    screen._key_main(app, ord("1"))
    screen._key_main(app, ord("x"))
    assert job.terminated == 1
    assert "wave cancelled" in app.message
    job.running, job.exit_code = False, -15
    screen._on_job_finished(app)
    assert app.wave is None
    assert len(job.calls) == 1
    assert any("wave 1 done" in line for line in app.log)


def test_wave_does_not_switch_run_under_review_screen(tmp_path: Path) -> None:
    from octirb.tui import screen

    runs = tmp_path / "runs"
    write_run(runs, "old", "report-location", review_json=[])
    app, job = make_app(runs)
    screen._key_main(app, ord("1"))
    first = job.calls[0]["argv"]
    run_id = first[first.index("--run-id") + 1]
    write_run(runs, run_id, "report-location", selection_json=[{"id": "r"}])
    app.mode = "review"
    job.running, job.exit_code = False, 0
    screen._on_job_finished(app)
    assert app.run is not None and app.run.run_id == "old"
    assert len(job.calls) == 2


def test_x_without_wave_says_so(tmp_path: Path) -> None:
    from octirb.tui import screen

    app, job = make_app(tmp_path / "runs")
    screen._key_main(app, ord("x"))
    assert app.wave is None
    assert job.terminated == 0
    assert "no wave is running" in app.message


class FailingJob(FakeJob):
    """A job whose launch fails the way Popen does when the binary vanished."""

    def start(self, argv: list[str], env: dict[str, str] | None = None, *, label: str = "",
              cwd: Path | None = None, transform: Any = None) -> None:
        super().start(argv, env, label=label, cwd=cwd, transform=transform)
        self.running = False
        raise FileNotFoundError(2, "No such file or directory", argv[0])


def test_wave_could_not_start_stops_wave(tmp_path: Path) -> None:
    from octirb.tui import screen

    app, _ = make_app(tmp_path / "runs")
    app.job = FailingJob()
    screen._key_main(app, ord("1"))
    assert app.wave is None
    assert any("wave stopped: could not start select" in line for line in app.log)
    assert any("wave 1 done" in line for line in app.log)
    assert any("No such file" in line for line in app.log)


def test_extract_row_launch_error_is_reported(tmp_path: Path) -> None:
    from octirb.tui import screen

    runs = tmp_path / "runs"
    write_run(runs, "r1", "report-location", batch_json=[{"report_id": "x"}])
    app, _ = make_app(runs, claude="/gone/claude")
    app.job = FailingJob()
    app.cursor = [s.key for s in app.steps].index("extract")
    screen._key_main(app, 10)
    assert "could not start" in app.message and "No such file" in app.message


def test_wave_key_refused_while_wave_running(tmp_path: Path) -> None:
    from octirb.tui import screen

    app, job = make_app(tmp_path / "runs")
    screen._key_main(app, ord("1"))
    first_wave = app.wave
    assert first_wave is not None
    job.running = False  # between steps of the wave: the slot is still the wave's
    screen._key_main(app, ord("1"))
    assert app.wave is first_wave
    assert len(job.calls) == 1
    assert app.message == "a wave is running; x cancels it"


def test_wave_runtime_error_is_a_message(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from octirb.tui import screen, wave

    runs = tmp_path / "runs"
    write_run(runs, "20261018T000000Z-w1-report-location", "report-location")
    app, job = make_app(runs)
    monkeypatch.setattr(wave, "MAX_RUN_DIRS", 0)  # latest_wave1_ids now raises RuntimeError
    screen._key_main(app, ord("2"))
    assert app.wave is None
    assert job.calls == []
    assert "more than 0 entries" in app.message


class StaleExitJob(FakeJob):
    """A previous step that exited while the loop sat in getch: its `exit 0`
    line is still queued and `running` is already False."""

    def __init__(self) -> None:
        super().__init__()
        self.exit_code = 0
        self.queued = ["exit 0"]

    def drain(self) -> list[str]:
        lines, self.queued = self.queued, []
        return lines


def test_stale_exit_is_consumed_before_a_key_starts_a_wave(tmp_path: Path) -> None:
    from octirb.tui import screen

    runs = tmp_path / "runs"
    write_run(runs, "old", "report-location", selection_json=[{"id": "r"}])
    app, _ = make_app(runs)
    job = StaleExitJob()
    app.job = job
    app.started = ["fetch", "--run-id", "old"]
    screen._handle_key(app, ord("1"))  # the same path _loop uses for every key
    assert app.wave is not None
    assert len(job.calls) == 1 and "select" in job.calls[0]["argv"]
    log = list(app.log)
    assert log.index("exit 0") < next(i for i, line in enumerate(log) if line.startswith("wave 1:"))
    screen._tick(app)  # next loop pass: nothing stale left to feed the wave
    assert len(job.calls) == 1
    assert app.wave is not None and not app.wave.done
