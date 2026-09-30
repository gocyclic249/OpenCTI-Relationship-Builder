"""report-labels linker: sector root walk, label derivation, select/batch,
validate, apply and revert -- all against hand-written fakes, no network."""

from __future__ import annotations

from typing import Any

import pytest

from octirb.client import OpenCTIError
from octirb.config import Config, SectorsCfg, SelectionCfg
from octirb.linkers.report_labels import (
    batch,
    build_sector_index,
    labels_for,
    sector_roots,
    select,
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


# -- select / batch --------------------------------------------------------------


def node(rid: str, *, objects: int = 1, published: str = "2026-09-01",
         source: str = "Vendor", name: str = "") -> dict[str, Any]:
    return {
        "id": rid, "name": name or f"Report {rid}", "description": "",
        "created": published, "published": published, "createdBy": {"name": source},
        "objects": {"edges": [{"node": {"entity_type": "Country"}}] * objects},
        "externalReferences": {"edges": []},
    }


class SelectFake:
    def __init__(self, nodes: list[dict[str, Any]]) -> None:
        self._nodes = nodes

    def reports(self) -> Any:
        return iter(self._nodes)


def test_select_requires_objects_and_keeps_textless_reports():
    cfg = Config(selection=SelectionCfg(since_days=0))
    _lines, log = logs()
    got = select(SelectFake([node("r1"), node("r2", objects=0)]), cfg, log, limit=None, since=None)
    assert got == [{"report_id": "r1", "name": "Report r1", "source": "Vendor"}]


def test_select_honours_gates_and_limit():
    cfg = Config(selection=SelectionCfg(since_days=0, exclude_sources=("Noise",),
                                        exclude_title_patterns=("^weekly",)))
    _lines, log = logs()
    nodes = [node("old", published="2020-01-01"), node("n1", source="Noise"),
             node("t1", name="Weekly digest"), node("r1"), node("r2")]
    got = select(SelectFake(nodes), cfg, log, limit=1, since="2026-01-01")
    assert [g["report_id"] for g in got] == ["r1"]


def test_select_rejects_bad_limit():
    _lines, log = logs()
    with pytest.raises(ValueError):
        select(SelectFake([]), Config(), log, limit=0, since=None)


class BatchFake:
    def __init__(self, reports: dict[str, dict[str, Any]]) -> None:
        self._reports = reports

    def sector_parents(self) -> list[dict[str, Any]]:
        return TREE

    def report_label_sources(self, rid: str) -> dict[str, Any]:
        if rid not in self._reports:
            raise OpenCTIError(f"report {rid} not found")
        return self._reports[rid]


def test_batch_skips_vanished_report_and_continues():
    """Review Focus 5."""
    fake = BatchFake({"r2": report(id="r2", countries=[{"id": "c", "name": "France"}])})
    lines, log = logs()
    got = batch(fake, Config(), [{"report_id": "gone"}, {"report_id": "r2"}], log)
    assert [(e["report_id"], e["label"]) for e in got] == [("r2", "France")]
    assert any("gone" in line for line in lines)


def test_batch_applies_config_aliases_casefolded():
    fake = BatchFake({"r1": report(sectors=[{"id": "dup", "name": "Energy & Utilities"}])})
    cfg = Config(sectors=SectorsCfg(aliases={"Energy & Utilities": "Energy"}))
    _lines, log = logs()
    got = batch(fake, cfg, [{"report_id": "r1"}], log)
    assert [e["label"] for e in got] == ["Energy"]
