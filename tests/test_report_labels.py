"""report-labels linker: sector root walk, label derivation, select/batch,
validate, apply and revert -- all against hand-written fakes, no network."""

from __future__ import annotations

from typing import Any

import pytest

from octirb.linkers.report_labels import (
    build_sector_index,
    labels_for,
    sector_roots,
    start_ids,
)

TREE = [
    {"id": "ics", "name": "ICS", "parent_ids": []},
    {"id": "energy", "name": "Energy", "parent_ids": []},
    {"id": "elec", "name": "Electricity", "parent_ids": ["energy", "ics"]},
    {"id": "grid", "name": "Grid operators", "parent_ids": ["elec"]},
    {"id": "orphan", "name": "Orphan", "parent_ids": ["hidden-parent"]},
    {"id": "dup", "name": "Energy & Utilities", "parent_ids": []},
    {"id": "cyc-a", "name": "A", "parent_ids": ["cyc-b"]},
    {"id": "cyc-b", "name": "B", "parent_ids": ["cyc-a"]},
]
INDEX = build_sector_index(TREE)


def logs() -> tuple[list[str], Any]:
    lines: list[str] = []
    return lines, lines.append


def report(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"id": "r1", "name": "Report One", "labels": [],
                            "countries": [], "sectors": []}
    base.update(over)
    return base


# -- sector_roots ----------------------------------------------------------------


def test_root_sector_is_its_own_root():
    assert sector_roots(INDEX, "ics") == ["ICS"]


def test_dual_parent_yields_every_root():
    assert sector_roots(INDEX, "grid") == ["Energy", "ICS"]


def test_invisible_parent_counts_as_root():
    """Review Focus 3."""
    assert sector_roots(INDEX, "orphan") == ["Orphan"]


def test_cycle_with_no_root_raises():
    with pytest.raises(ValueError, match="cycle"):
        sector_roots(INDEX, "cyc-a")


def test_unknown_sector_raises():
    with pytest.raises(ValueError, match="not on the platform"):
        sector_roots(INDEX, "nope")


# -- start_ids -------------------------------------------------------------------


def test_alias_redirects_walk_start():
    assert start_ids(INDEX, "dup", {"energy & utilities": "Energy"}) == ["energy"]


def test_no_alias_starts_at_sector():
    assert start_ids(INDEX, "grid", {}) == ["grid"]


def test_alias_target_missing_raises():
    with pytest.raises(ValueError, match="alias target"):
        start_ids(INDEX, "dup", {"energy & utilities": "Nope"})


# -- labels_for ------------------------------------------------------------------


def test_countries_and_sector_roots_become_labels():
    lines, log = logs()
    got = labels_for(report(countries=[{"id": "c1", "name": "United States"}],
                            sectors=[{"id": "grid", "name": "Grid operators"}]), INDEX, {}, log)
    assert [(e["label"], e["from"], e["source_entity"]) for e in got] == [
        ("United States", "country", "United States"),
        ("Energy", "sector", "Grid operators"),
        ("ICS", "sector", "Grid operators"),
    ]
    assert all(e["confidence"] == "high" and e["report_id"] == "r1" for e in got)
    assert lines == []


def test_existing_labels_dropped_casefolded():
    """Review Focus 1: `china` on the report already covers Country `China`."""
    _lines, log = logs()
    got = labels_for(report(labels=["china", "ics"], countries=[{"id": "c1", "name": "China"}],
                            sectors=[{"id": "elec", "name": "Electricity"}]), INDEX, {}, log)
    assert [e["label"] for e in got] == ["Energy"]


def test_shared_root_deduped():
    _lines, log = logs()
    got = labels_for(report(sectors=[{"id": "elec", "name": "Electricity"},
                                     {"id": "grid", "name": "Grid operators"}]), INDEX, {}, log)
    assert [e["label"] for e in got] == ["Energy", "ICS"]


def test_alias_applied_before_walk():
    _lines, log = logs()
    got = labels_for(report(sectors=[{"id": "dup", "name": "Energy & Utilities"}]),
                     INDEX, {"energy & utilities": "Energy"}, log)
    assert [e["label"] for e in got] == ["Energy"]


def test_bad_sector_logged_other_labels_kept():
    lines, log = logs()
    got = labels_for(report(countries=[{"id": "c1", "name": "Germany"}],
                            sectors=[{"id": "cyc-a", "name": "A"}]), INDEX, {}, log)
    assert [e["label"] for e in got] == ["Germany"]
    assert len(lines) == 1 and "cyc-a" in lines[0]


def test_nothing_to_add():
    _lines, log = logs()
    assert labels_for(report(), INDEX, {}, log) == []


def test_labels_for_rejects_non_report():
    _lines, log = logs()
    with pytest.raises(TypeError):
        labels_for({"name": "no id"}, INDEX, {}, log)
