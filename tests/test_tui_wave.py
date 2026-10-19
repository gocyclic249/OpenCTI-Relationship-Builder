"""Tests for octirb.tui.wave: the pure wave state machine, driven with fake exits."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from octirb.tui import wave
from octirb.tui.wave import Action, Wave

STAMP = "20261019T120000Z"
CLAUDE = "/bin/claude"
MAX_DRIVE = 100


def write_run(runs_dir: Path, run_id: str, linker: str, **files: Any) -> Path:
    d = runs_dir / run_id
    d.mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"run_id": run_id, "linker": linker,
                                             "created": "2026-01-01T00:00:00+00:00", "options": {}}))
    for name, data in files.items():
        (d / name.replace("_json", ".json")).write_text(json.dumps(data))
    return d


def linker_of(run_id: str) -> str:
    return run_id.split("-w", 1)[1].split("-", 1)[1]


def simulate(runs_dir: Path, action: Action, selection: list[Any] | None = None) -> None:
    """Write what the real step would have written."""
    run_dir = runs_dir / action.run_id
    if action.step == "select":
        sel = [{"report_id": "r1"}] if selection is None else selection
        write_run(runs_dir, action.run_id, linker_of(action.run_id), selection_json=sel)
    elif action.step == "structured":
        (run_dir / "extractions.json").write_text("[]")  # cmd_structured always writes, even []
    elif action.step == "extract":
        # Different bytes from structured's `[]`, so the change is visible even on coarse mtimes.
        (run_dir / "extractions.json").write_text(json.dumps([{"report_id": "r1", "entities": []}]))
    elif action.step == "validate":
        (run_dir / "auto.json").write_text(json.dumps([{"a": 1}]))
        (run_dir / "review.json").write_text(json.dumps([]))


Hook = Callable[[Action], int]


def drive(w: Wave, runs_dir: Path, hook: Hook | None = None) -> list[Action]:
    """Run the wave to completion; `hook` may write files itself and returns the exit code."""
    actions: list[Action] = []
    for _ in range(MAX_DRIVE):
        action = w.next_action()
        if action is None:
            return actions
        actions.append(action)
        code = hook(action) if hook is not None else -1
        if code == -1:
            simulate(runs_dir, action)
            code = 0
        w.finished(code)
    raise AssertionError("wave did not finish")


def test_wave1_happy_path_order(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    w = Wave(1, runs, CLAUDE, STAMP)
    actions = drive(w, runs)
    seen = [(linker_of(a.run_id), a.step) for a in actions]
    full = ["select", "fetch", "batch", "structured", "extract", "validate"]
    expected = [(lk, s) for lk in ("report-location", "report-sector", "report-actor") for s in full]
    expected += [("report-vuln", s) for s in ("select", "fetch", "batch", "validate")]
    assert seen == expected
    assert w.done
    assert w.run_ids == [f"{STAMP}-w1-{lk}" for lk in wave.WAVE_LINKERS[1]]
    lines = w.summary()
    assert len(lines) == 4
    assert all("auto 1" in line and "sel 1" in line and "review 0" in line for line in lines)
    extract = next(a for a in actions if a.step == "extract")
    assert extract.kind == "claude"
    assert extract.cwd == runs / extract.run_id
    assert extract.argv[0] == CLAUDE
    select = actions[0]
    assert select.kind == "octirb"
    assert select.cwd is None
    assert select.argv == ["select", "--linker", "report-location", "--run-id", f"{STAMP}-w1-report-location"]
    assert actions[1].argv == ["fetch", "--run-id", f"{STAMP}-w1-report-location"]


def test_wave_empty_selection_skips_linker(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    w = Wave(1, runs, CLAUDE, STAMP)
    first = w.next_action()
    assert first is not None
    simulate(runs, first, selection=[])
    w.finished(0)
    nxt = w.next_action()
    assert nxt is not None
    assert (linker_of(nxt.run_id), nxt.step) == ("report-sector", "select")
    assert "empty" in w.summary()[0]


def test_wave_failure_moves_on(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    w = Wave(1, runs, CLAUDE, STAMP)
    a = w.next_action()
    assert a is not None
    simulate(runs, a)
    w.finished(0)
    fetch = w.next_action()
    assert fetch is not None
    assert fetch.step == "fetch"
    w.finished(3)
    nxt = w.next_action()
    assert nxt is not None
    assert (linker_of(nxt.run_id), nxt.step) == ("report-sector", "select")
    assert w.summary()[0].endswith("failed at fetch (exit 3)")


def test_wave_extract_without_file_fails(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    w = Wave(1, runs, CLAUDE, STAMP)

    def hook(action: Action) -> int:
        if action.step in ("structured", "extract"):
            return 0  # neither step writes: extractions.json is genuinely missing at extract
        return -1

    actions = drive(w, runs, hook)
    location = [a.step for a in actions if linker_of(a.run_id) == "report-location"]
    assert location[-1] == "extract"
    assert "validate" not in location
    assert w.summary()[0].endswith("failed at extract (no extractions.json)")
    assert "auto" in w.summary()[3]  # report-vuln has no extract and still finishes


def test_wave_extract_unchanged_after_structured_fails(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    w = Wave(1, runs, CLAUDE, STAMP)

    def hook(action: Action) -> int:
        if action.step == "extract":
            if not (runs / action.run_id / "extractions.json").is_file():
                raise AssertionError("structured should have written extractions.json first")
            return 0  # claude exits 0 and leaves structured's `[]` untouched
        return -1

    actions = drive(w, runs, hook)
    location = [a.step for a in actions if linker_of(a.run_id) == "report-location"]
    assert location == ["select", "fetch", "batch", "structured", "extract"]
    assert w.summary()[0].endswith("failed at extract (no extractions.json)")
    assert "auto" in w.summary()[3]  # report-vuln has no extract and still finishes


def test_wave_without_claude_stops_at_extract(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    w = Wave(1, runs, None, STAMP)
    actions = drive(w, runs)
    assert all(a.kind == "octirb" for a in actions)
    location = [a.step for a in actions if linker_of(a.run_id) == "report-location"]
    assert location == ["select", "fetch", "batch", "structured"]
    lines = w.summary()
    assert lines[0].endswith("needs extract: claude not on PATH")
    vuln = [a.step for a in actions if linker_of(a.run_id) == "report-vuln"]
    assert vuln[-1] == "validate"
    assert "auto 1" in lines[3]


def test_wave2_requires_wave1(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    write_run(runs, "manual-run", "report-location", selection_json=[{"report_id": "r1"}])
    with pytest.raises(ValueError, match="press 1"):
        Wave(2, runs, CLAUDE, STAMP)


def test_wave2_scopes_actor_target_to_latest_wave1(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    old = "20261001T000000Z"
    new = "20261018T000000Z"
    for lk in ("report-location", "report-actor"):
        write_run(runs, f"{old}-w1-{lk}", lk)
    new_ids = [f"{new}-w1-{lk}" for lk in ("report-sector", "report-location")]
    for rid in new_ids:
        write_run(runs, rid, linker_of(rid))
    assert wave.latest_wave1_ids(runs) == sorted(new_ids)
    w = Wave(2, runs, CLAUDE, STAMP)
    actions = drive(w, runs)
    labels = [a.step for a in actions if linker_of(a.run_id) == "report-labels"]
    assert labels == ["select", "batch", "validate"]
    at_select = next(a for a in actions if linker_of(a.run_id) == "actor-target" and a.step == "select")
    argv = at_select.argv
    assert argv[:5] == ["select", "--linker", "actor-target", "--run-id", f"{STAMP}-w2-actor-target"]
    assert argv[argv.index("--source") + 1] == "report"
    scoped = [argv[i + 1] for i, tok in enumerate(argv) if tok == "--reports-from-run"]
    assert scoped == sorted(new_ids)
    at_steps = [a.step for a in actions if linker_of(a.run_id) == "actor-target"]
    assert at_steps == ["select", "batch", "extract", "validate"]


def test_latest_wave1_ids_missing_dir(tmp_path: Path) -> None:
    assert wave.latest_wave1_ids(tmp_path / "nope") == []


def test_wave_cancel(tmp_path: Path) -> None:
    runs = tmp_path / "runs"
    w = Wave(1, runs, CLAUDE, STAMP)
    assert w.next_action() is not None
    w.cancel()
    assert w.done
    assert w.next_action() is None
    assert all(line.endswith("cancelled") for line in w.summary())
    w.finished(-15)  # the killed step's exit is still accepted after cancel
    assert w.next_action() is None


def test_finished_without_action_raises(tmp_path: Path) -> None:
    w = Wave(1, tmp_path / "runs", CLAUDE, STAMP)
    with pytest.raises(RuntimeError):
        w.finished(0)


def test_bad_inputs_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        Wave(3, tmp_path / "runs", CLAUDE, STAMP)
    with pytest.raises(ValueError):
        Wave(1, tmp_path / "runs", CLAUDE, "not-a-stamp")


def test_next_action_twice_without_finished_raises(tmp_path: Path) -> None:
    w = Wave(1, tmp_path / "runs", CLAUDE, STAMP)
    assert w.next_action() is not None
    with pytest.raises(RuntimeError):
        w.next_action()
