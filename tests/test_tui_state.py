"""Coverage for octirb/tui/state.py: the curses-free model behind the TUI.

Everything here is pure (file inspection, argv building, pick toggling) so
the screen layer in tui/screen.py stays a thin painter over it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from octirb import picks
from octirb.tui import state


def write_run(runs_dir: Path, run_id: str, linker: str, created: str = "2026-01-01T00:00:00+00:00",
              **files: Any) -> Path:
    d = runs_dir / run_id
    d.mkdir(parents=True)
    (d / "meta.json").write_text(json.dumps({"run_id": run_id, "linker": linker, "created": created,
                                             "options": {}}))
    for name, data in files.items():
        (d / name.replace("_json", ".json")).write_text(json.dumps(data))
    return d


# ---------------------------------------------------------------- steps


def test_steps_for_model_linker_has_every_stage() -> None:
    keys = [s.key for s in state.steps_for("report-location")]
    assert keys == ["select", "fetch", "batch", "structured", "extract", "validate", "review",
                    "apply-dry", "apply", "revert-dry", "revert", "doctor", "status", "wave1", "wave2"]


def test_steps_for_deterministic_linkers_skip_model_stages() -> None:
    assert "extract" not in [s.key for s in state.steps_for("report-vuln")]
    assert "structured" not in [s.key for s in state.steps_for("report-vuln")]
    labels = [s.key for s in state.steps_for("report-labels")]
    assert "fetch" not in labels and "extract" not in labels
    actor = [s.key for s in state.steps_for("actor-target")]
    assert "fetch" not in actor and "extract" in actor


def test_steps_for_no_run_offers_only_run_free_steps() -> None:
    assert [s.key for s in state.steps_for(None)] == ["select", "doctor", "status", "wave1", "wave2"]


def test_steps_for_rejects_unknown_linker() -> None:
    with pytest.raises(ValueError, match="unknown linker"):
        state.steps_for("report-bogus")


def test_step_status_reads_run_files(tmp_path: Path) -> None:
    d = write_run(tmp_path, "r1", "report-location", selection_json=[1], fetch_status_json={"a": "ok"},
                  batch_json=[1], extractions_json=[1], auto_json=[1], review_json=[], applied_json=[])
    assert state.step_status("select", d) == state.DONE
    assert state.step_status("fetch", d) == state.DONE
    assert state.step_status("batch", d) == state.DONE
    assert state.step_status("extract", d) == state.DONE
    assert state.step_status("validate", d) == state.DONE
    assert state.step_status("review", d) == state.TODO
    assert state.step_status("apply", d) == state.TODO  # empty ledger = nothing applied
    assert state.step_status("apply-dry", d) == state.NEUTRAL
    assert state.step_status("doctor", d) == state.NEUTRAL


def test_step_status_apply_and_revert_follow_the_ledger(tmp_path: Path) -> None:
    d = write_run(tmp_path, "r1", "report-location", applied_json=[{"kind": "containment"}])
    assert state.step_status("apply", d) == state.DONE
    assert state.step_status("revert", d) == state.TODO
    (d / "applied.json").write_text("[]")
    (d / "reverted.json").write_text(json.dumps([{"kind": "containment"}]))
    assert state.step_status("revert", d) == state.DONE


def test_step_status_batch_for_deterministic_linker_means_extractions(tmp_path: Path) -> None:
    d = write_run(tmp_path, "r1", "report-vuln", extractions_json=[1])
    assert state.step_status("batch", d) == state.DONE


# ---------------------------------------------------------------- runs


def test_list_runs_newest_first_with_counts(tmp_path: Path) -> None:
    write_run(tmp_path, "old", "report-vuln", created="2026-01-01T00:00:00+00:00", selection_json=[1, 2])
    write_run(tmp_path, "new", "report-sector", created="2026-02-01T00:00:00+00:00", review_json=[1])
    (tmp_path / "junk").mkdir()  # not a run: no meta.json
    runs = state.list_runs(tmp_path)
    assert [r.run_id for r in runs] == ["new", "old"]
    assert runs[0].linker == "report-sector"
    assert runs[0].counts["review"] == 1
    assert runs[1].counts["selection"] == 2


def test_list_runs_missing_dir_is_empty(tmp_path: Path) -> None:
    assert state.list_runs(tmp_path / "nope") == []


# ---------------------------------------------------------------- argv


def test_build_argv_for_run_scoped_steps() -> None:
    opts = state.Options(include_review=True, create_missing=False)
    assert state.build_argv("fetch", "r1", opts) == ["fetch", "--run-id", "r1"]
    assert state.build_argv("apply-dry", "r1", opts) == ["apply", "--run-id", "r1", "--dry-run",
                                                           "--include-review"]
    assert state.build_argv("apply", "r1", state.Options(include_review=False, create_missing=True)) == [
        "apply", "--run-id", "r1", "--create-missing"]
    assert state.build_argv("revert-dry", "r1", opts) == ["revert", "--run-id", "r1", "--dry-run"]
    assert state.build_argv("status", None, opts) == ["status"]


def test_build_argv_rejects_non_command_steps() -> None:
    with pytest.raises(ValueError, match="not a command"):
        state.build_argv("review", "r1", state.Options())


def test_build_argv_needs_run_for_run_scoped_steps() -> None:
    with pytest.raises(ValueError, match="needs a run"):
        state.build_argv("fetch", None, state.Options())


def test_select_form_argv_and_validation() -> None:
    form = state.SelectForm()
    assert form.linker == "report-location"
    assert form.error() is None
    assert form.argv() == ["select", "--linker", "report-location"]
    form.limit = "25"
    form.since_days = "14"
    form.all_reports = True
    form.run_id = "loc-test"
    assert form.argv() == ["select", "--linker", "report-location", "--run-id", "loc-test",
                           "--limit", "25", "--since-days", "14", "--all-reports"]
    form.limit = "lots"
    assert form.error() == "limit must be a whole number"


def test_select_form_actor_target_requires_source() -> None:
    form = state.SelectForm()
    form.cycle_linker(+1)
    form.linker = "actor-target"
    assert form.error() == "actor-target needs a source"
    form.cycle_source()
    assert form.source in ("description", "report")
    assert form.error() is None
    assert "--source" in form.argv()


def test_select_form_cycle_linker_wraps() -> None:
    form = state.SelectForm()
    n = len(state.LINKERS)
    for _ in range(n):
        form.cycle_linker(+1)
    assert form.linker == "report-location"
    form.cycle_linker(-1)
    assert form.linker == state.LINKERS[-1]


# ---------------------------------------------------------------- review


def soft(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"report_id": "r1", "entity_name": "France", "confidence": "medium",
                            "evidence": "France was hit", "title": "Some report",
                            "review_reasons": ["confidence=medium"], "hard_fail": False}
    base.update(over)
    return base


def test_review_list_toggle_all_none_and_locked_items() -> None:
    items = [soft(entity_name="A"), soft(entity_name="B"), soft(entity_name="C", hard_fail=True)]
    rl = state.ReviewList(items, accepted=set())
    assert rl.can_toggle(0) and not rl.can_toggle(2)
    rl.toggle(0)
    assert rl.is_accepted(0) and not rl.is_accepted(1)
    rl.toggle(2)  # locked: no-op
    assert not rl.is_accepted(2)
    rl.accept_all()
    assert rl.accepted_count() == 2
    rl.accept_none()
    assert rl.accepted_count() == 0


def test_review_list_round_trips_through_picks(tmp_path: Path) -> None:
    from octirb.runstore import Run

    items = [soft(entity_name="A"), soft(entity_name="B")]
    run = Run(tmp_path / "r1")
    rl = state.ReviewList(items, accepted=set())
    rl.toggle(1)
    rl.save(run)
    assert picks.load_picks(run) == {picks.item_key(items[1])}
    again = state.ReviewList(items, accepted=picks.load_picks(run) or set())
    assert again.is_accepted(1) and not again.is_accepted(0)


def test_review_item_label_prefers_the_linker_key() -> None:
    assert state.item_label({"entity_name": "France", "iso3": "FRA"}) == "France"
    assert state.item_label({"cve": "CVE-2026-1"}) == "CVE-2026-1"
    assert state.item_label({"actor": "APT1"}) == "APT1"
    assert state.item_label({"label": "ICS"}) == "ICS"
    assert state.item_label({"actor_id": "a1", "relationship_type": "targets", "target": "FRA"}) == \
        "a1 targets FRA"
    assert state.item_label({}) == "?"


def test_review_row_fits_width_and_shows_state() -> None:
    rl = state.ReviewList([soft(entity_name="France", title="x" * 200)], accepted=set())
    row = rl.row(0, width=60)
    assert len(row) <= 60
    assert row.startswith("[ ] medium")
    rl.toggle(0)
    assert rl.row(0, width=60).startswith("[x] medium")
    locked = state.ReviewList([soft(hard_fail=True)], accepted=set())
    assert locked.row(0, width=60).startswith("[-] medium")


def test_extract_hint_names_the_skill() -> None:
    hint = state.extract_hint("report-location", Path("/runs/r1"))
    assert "/runs/r1/batch.json" in hint and "octi-link-reports" in hint
    assert "octi-link-actors" in state.extract_hint("actor-target", Path("/runs/r1"))
