"""Tests for contrib/migrate-legacy-labels.py's pure planner, plan_migrations.

contrib/ is not a package (its script has no importable directory alongside
it and its filename carries a hyphen), so the module under test is loaded
via importlib.util.spec_from_file_location rather than a normal import --
documented here rather than restructuring contrib/ into a package for one
script. Only plan_migrations is exercised: no network, no Client, no I/O.
"""

from __future__ import annotations

import importlib.util
import pathlib
from types import ModuleType

_SCRIPT_PATH = pathlib.Path(__file__).resolve().parent.parent / "contrib" / "migrate-legacy-labels.py"


def _load_migrate_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("migrate_legacy_labels", _SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load spec for {_SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


migrate = _load_migrate_module()
plan_migrations = migrate.plan_migrations


def geo_row(**over):
    row = {
        "report_id": "r1", "title": "t", "dimension": "location",
        "entity_id": "e1", "entity_name": "Ukraine", "key": "UKR",
        "role": "target", "confidence": "high", "evidence": "q",
        "label_id": "old-label-id", "created": False,
    }
    row.update(over)
    return row


def rel_row(**over):
    row = {
        "actor_id": "a1", "actor": "APT1", "relationship_type": "targets",
        "target_kind": "country", "target_id": "c1", "target_name": "Ukraine",
        "confidence": "high", "evidence": "q", "source": "prose", "source_refs": ["ref1"],
        "relationship_id": "rel1", "preexisted": False, "in_reports": ["ref1"],
        "label_id": "old-rel-label-id", "status": "created",
    }
    row.update(over)
    return row


# -- one action per octi-geo dimension --------------------------------------


def test_location_row_relabels_report():
    plan = plan_migrations([[geo_row(dimension="location", report_id="r1")]], [])
    assert plan == [
        {"action": "relabel-report", "report_id": "r1", "add": "AI-Location", "remove": "octi-geo"}
    ]


def test_sector_row_relabels_report():
    plan = plan_migrations([[geo_row(dimension="sector", report_id="r2")]], [])
    assert plan == [
        {"action": "relabel-report", "report_id": "r2", "add": "AI-Sector", "remove": "octi-geo-ics"}
    ]


def test_actor_row_relabels_report():
    plan = plan_migrations([[geo_row(dimension="actor", report_id="r3")]], [])
    assert plan == [
        {
            "action": "relabel-report", "report_id": "r3",
            "add": "AI-Actor", "remove": "octi-geo-actor",
        }
    ]


# -- created:true additionally mints an entity action -----------------------


def test_created_row_produces_report_and_entity_actions():
    row = geo_row(dimension="actor", report_id="r4", entity_id="e4", created=True)
    plan = plan_migrations([[row]], [])
    assert plan == [
        {"action": "relabel-report", "report_id": "r4", "add": "AI-Actor", "remove": "octi-geo-actor"},
        {"action": "relabel-entity", "entity_id": "e4", "add": "AI-Created", "remove": "octi-geo-actor"},
    ]


def test_non_created_row_produces_no_entity_action():
    row = geo_row(dimension="location", report_id="r5", entity_id="e5", created=False)
    plan = plan_migrations([[row]], [])
    assert all(a["action"] != "relabel-entity" for a in plan)


# -- octi-rel: preexisted gates the relationship action ----------------------


def test_preexisted_false_relabels_relationship():
    plan = plan_migrations([], [[rel_row(relationship_id="rel1", preexisted=False)]])
    assert plan == [
        {
            "action": "relabel-relationship", "relationship_id": "rel1",
            "add": "AI-Relationship", "remove": "octi-rel",
        }
    ]


def test_preexisted_true_produces_nothing():
    plan = plan_migrations([], [[rel_row(relationship_id="rel2", preexisted=True)]])
    assert plan == []


# -- dedupe -------------------------------------------------------------


def test_dedupes_two_rows_on_one_report():
    ledger = [
        geo_row(dimension="location", report_id="rdupe", entity_id="e1"),
        geo_row(dimension="location", report_id="rdupe", entity_id="e2"),
    ]
    plan = plan_migrations([ledger], [])
    assert plan == [
        {"action": "relabel-report", "report_id": "rdupe", "add": "AI-Location", "remove": "octi-geo"}
    ]


def test_dedupes_across_separate_ledgers():
    plan = plan_migrations(
        [
            [geo_row(dimension="sector", report_id="rboth")],
            [geo_row(dimension="sector", report_id="rboth")],
        ],
        [],
    )
    assert len(plan) == 1


# -- mixed batch --------------------------------------------------------


def test_three_row_fixture_covers_each_action():
    geo_ledger = [
        geo_row(dimension="location", report_id="r1"),
        geo_row(dimension="sector", report_id="r2"),
        geo_row(dimension="actor", report_id="r3", entity_id="e3", created=True),
    ]
    rel_ledger = [
        rel_row(relationship_id="relA", preexisted=False),
        rel_row(relationship_id="relB", preexisted=True),
    ]
    plan = plan_migrations([geo_ledger], [rel_ledger])
    kinds = [a["action"] for a in plan]
    assert kinds.count("relabel-report") == 3
    assert kinds.count("relabel-entity") == 1
    assert kinds.count("relabel-relationship") == 1
    assert {"action": "relabel-relationship", "relationship_id": "relA",
            "add": "AI-Relationship", "remove": "octi-rel"} in plan
