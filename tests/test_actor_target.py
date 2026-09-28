"""Ported from opencti-docker/tests/test_rel_validate.py, test_rel_contracts.py
and test_rel_sources.py (the description_packets/prose_packets halves --
octi-geo-ledger-source tests are dropped, "prose" becomes "report"), plus
this task's new coverage: the removed-join property (SOURCES has no
"ledger"), select_report's cache-only read, and select_description/
select_report's own input validation.
"""

from dataclasses import dataclass
from pathlib import Path

import pytest

from octirb.config import Config
from octirb.linkers.actor_target import (
    EXPECTED,
    SOURCES,
    ActorRef,
    Context,
    Schema,
    collapse,
    render,
    select_description,
    select_report,
    validate,
)
from octirb.runstore import TextCache

# -- validate (ported from test_rel_validate.py) ---------------------------


@dataclass(frozen=True)
class T:
    id: str
    name: str


class Dict:
    def __init__(self, table):
        self.table = table

    def resolve(self, key):
        return self.table.get(key.strip()) if isinstance(key, str) else None


def schema():
    mapping = {}
    for f, t, r in EXPECTED:
        mapping.setdefault(f"{f}_{t}", set()).add(r)
    return Schema({k: frozenset(v) for k, v in mapping.items()})


def ctx(selection=None):
    return Context(
        actors={
            "is-1": ActorRef("is-1", "Sandworm Team", "Intrusion-Set"),
            "tag-1": ActorRef("tag-1", "Datacarry", "Threat-Actor-Group"),
        },
        targets={
            "country": Dict({"RUS": T("c-rus", "Russian Federation"), "UKR": T("c-ukr", "Ukraine")}),
            "region": Dict({"Middle East": T("r-me", "Middle East")}),
            "sector": Dict({"Electricity": T("s-el", "Electricity"),
                            "Government and administrations": T("s-gov", "Government and administrations")}),
        },
        schema=schema(),
        selection=selection if selection is not None else {"is-1": frozenset({"is-1"}),
                                                           "tag-1": frozenset({"tag-1"})},
    )


def cand(**over):
    base = {"actor_id": "is-1", "actor": "Sandworm", "relationship": "origin",
            "target_kind": "country", "target": "RUS", "confidence": "high",
            "evidence": "attributed to Russia's GRU", "source": "description", "source_ref": "is-1"}
    base.update(over)
    return base


def test_high_origin_auto_applies_with_concrete_type():
    auto, review = validate([cand()], ctx())
    assert review == []
    assert auto[0]["relationship_type"] == "originates-from"
    assert auto[0]["target_id"] == "c-rus"
    assert auto[0]["actor"] == "Sandworm Team"
    assert auto[0]["source_refs"] == ["is-1"]


def test_threat_actor_group_origin_is_located_at():
    auto, _ = validate([cand(actor_id="tag-1", source_ref="tag-1")], ctx())
    assert auto[0]["relationship_type"] == "located-at"


def test_medium_is_held_but_promotable():
    auto, review = validate([cand(confidence="Medium")], ctx())
    assert auto == []
    assert review[0]["hard_fail"] is False
    assert review[0]["confidence"] == "medium"


def test_unresolved_target_hard_fails():
    _, review = validate([cand(target="XXX")], ctx())
    assert review[0]["hard_fail"] is True


def test_origin_to_sector_hard_fails():
    """Load-bearing invariant, kept verbatim even though sector resolution
    itself moved out of this module: an origin must never point at a
    sector, regardless of whether the sector name resolves."""
    _, review = validate([cand(target_kind="sector", target="Electricity")], ctx())
    assert review[0]["hard_fail"] is True
    assert any("sector" in r for r in review[0]["review_reasons"])


def test_unresolved_sector_hard_fails():
    """Sector aliasing (formerly sectormap.canonical's job) now lives in
    whichever resolver ctx.targets["sector"] is built from; a name that
    resolver doesn't know is simply unresolved, same as any other kind."""
    _, review = validate([cand(relationship="targets", target_kind="sector",
                               target="Government & Defense")], ctx())
    assert review[0]["hard_fail"] is True
    assert any("unresolved sector" in r for r in review[0]["review_reasons"])


def test_unknown_actor_hard_fails():
    _, review = validate([cand(actor_id="nope", source_ref="is-1")], ctx())
    assert review[0]["hard_fail"] is True


def test_missing_evidence_hard_fails():
    _, review = validate([cand(evidence="  ")], ctx())
    assert review[0]["hard_fail"] is True


def test_non_object_and_null_fields_hard_fail():
    expected_review_count = 3
    auto, review = validate(["junk", cand(target=None), {"actor_id": "is-1"}], ctx())
    assert auto == []
    assert len(review) == expected_review_count
    assert all(r["hard_fail"] for r in review)


def test_source_ref_outside_selection_hard_fails():
    _, review = validate([cand(source="report", source_ref="report-x")], ctx())
    assert review[0]["hard_fail"] is True


def test_actor_outside_source_ref_hard_fails():
    sel = {"report-1": frozenset({"tag-1"})}
    _, review = validate([cand(source="report", source_ref="report-1")], ctx(sel))
    assert review[0]["hard_fail"] is True
    assert any("not in" in r for r in review[0]["review_reasons"])


def test_duplicates_collapse_to_highest_confidence_and_union_refs():
    sel = {"r1": frozenset({"is-1"}), "r2": frozenset({"is-1"})}
    items = [
        cand(relationship="targets", target="UKR", confidence="medium", source="report", source_ref="r1"),
        cand(relationship="targets", target="UKR", confidence="high", source="report", source_ref="r2",
             evidence="high one"),
    ]
    auto, review = validate(items, ctx(sel))
    assert review == []
    assert len(auto) == 1
    assert auto[0]["evidence"] == "high one"
    assert auto[0]["source_refs"] == ["r1", "r2"]


def test_collapse_keeps_first_on_tie():
    a = {"actor_id": "a", "relationship_type": "targets", "target_id": "t",
         "confidence": "high", "evidence": "first", "source_refs": ["r1"]}
    b = dict(a, evidence="second", source_refs=["r1", "r2"])
    out = collapse([a, b])
    assert out[0]["evidence"] == "first"
    assert out[0]["source_refs"] == ["r1", "r2"]


def test_invalid_enum_value_is_not_normalised_in_review():
    """review.json should show what the reader actually wrote, not a
    lowercased/stripped value that never validated."""
    _, review = validate([cand(confidence="Definitely-Not-A-Level")], ctx())
    assert review[0]["hard_fail"] is True
    assert review[0]["confidence"] == "Definitely-Not-A-Level"


def test_valid_enum_value_is_still_normalised():
    auto, _ = validate([cand(confidence="HIGH")], ctx())
    assert auto[0]["confidence"] == "high"


def test_missing_resolver_hard_fails():
    c = Context(
        actors={"is-1": ActorRef("is-1", "Sandworm Team", "Intrusion-Set")},
        targets={
            "country": Dict({"RUS": T("c-rus", "Russian Federation")}),
        },
        schema=schema(),
        selection={"is-1": frozenset({"is-1"})},
    )
    _, review = validate([cand(relationship="targets", target_kind="region", target="Middle East")], c)
    assert review[0]["hard_fail"] is True
    assert any("no resolver" in r for r in review[0]["review_reasons"])


def test_unhashable_enum_values_hard_fail_instead_of_crashing():
    """A reader can hand back a list or object where a string belongs.
    That must land in review as a hard fail, never abort the whole apply."""
    bad = [cand(target_kind=["country"]), cand(relationship={"a": 1}),
           cand(confidence=["high"]), cand(source={"x": 1})]
    auto, review = validate(bad, ctx())
    assert auto == []
    assert len(review) == len(bad)
    assert all(r["hard_fail"] for r in review)
    assert review[0]["target_kind"] == ["country"]  # original kept for review.json


# -- the removed-join property (this task's brief, step 2) -----------------


def test_sources_enum_has_no_ledger():
    assert frozenset({"description", "report"}) == SOURCES


# -- contracts (ported from test_rel_contracts.py) --------------------------

SECTORS = ["Electricity", "Government and administrations", "Defense"]
REGIONS = ["Middle East", "South-eastern Asia"]


@pytest.mark.parametrize("source", ["description", "report"])
def test_contract_names_the_fields_and_vocabularies(source):
    text = render(source, SECTORS, REGIONS)
    for field in ("actor_id", "relationship", "target_kind", "target", "confidence",
                  "evidence", "source", "source_ref"):
        assert f'"{field}"' in text
    assert "    - Electricity" in text
    assert "    - Middle East" in text
    assert "Government & Defense" in text  # named in the static trap text, not offered as a value
    assert f'"source":      "{source}"' in text


def test_description_contract_warns_about_citation_links():
    assert "attack.mitre.org" in render("description", SECTORS, REGIONS)


def test_report_contract_warns_about_reporting_vendor():
    assert "vendor" in render("report", SECTORS, REGIONS)


def test_unknown_source_rejected():
    with pytest.raises(ValueError, match="no contract"):
        render("ledger", SECTORS, REGIONS)


def test_render_rejects_empty_vocabularies():
    with pytest.raises(ValueError, match="both vocabularies"):
        render("description", [], REGIONS)
    with pytest.raises(ValueError, match="both vocabularies"):
        render("description", SECTORS, [])


# -- selection sources (new module; packet-shape port of test_rel_sources.py's
# -- description_packets/prose_packets coverage) ----------------------------


class FakeActorClient:
    def __init__(self, actors):
        self._actors = actors

    def actors(self):
        return self._actors


def test_select_description_skips_empty_and_limits():
    actors = [
        {"id": "b", "name": "B", "description": "desc", "entity_type": "Intrusion-Set"},
        {"id": "a", "name": "A", "description": "desc", "entity_type": "Intrusion-Set"},
        {"id": "c", "name": "C", "description": "  ", "entity_type": "Intrusion-Set"},
    ]
    client = FakeActorClient(actors)
    packets = select_description(client, limit=1)
    assert [p["actor_id"] for p in packets] == ["a"]
    assert packets[0]["source"] == "description"
    assert packets[0]["source_ref"] == "a"

    all_packets = select_description(client, None)
    assert [p["actor_id"] for p in all_packets] == ["a", "b"]


def test_select_description_rejects_bad_limit():
    with pytest.raises(ValueError, match="positive"):
        select_description(FakeActorClient([]), 0)


def test_select_description_rejects_non_list_actors():
    """Ported from test_rel_sources.py's test_description_packets_rejects_non_list_actors:
    select_description still guards client.actors() the same way
    description_packets guarded its pre-fetched `actors` parameter."""
    with pytest.raises(TypeError, match=r"client\.actors\(\) must return a list"):
        select_description(FakeActorClient("not a list"), None)  # type: ignore[arg-type]


class FakeReportClient:
    """report_actors ONLY -- any other attribute access proves select_report
    tried an outbound fetch, which the report source must never do."""

    def __init__(self, table):
        self.table = table

    def report_actors(self, report_id):
        return self.table.get(report_id)


def test_report_source_reads_cache_only(tmp_path: Path):
    cache = TextCache(tmp_path)
    cache.write("r1", "some article text")
    cache.write("r2", "no actors mentioned here")
    client = FakeReportClient({
        "r1": {"report_id": "r1", "title": "T1",
               "actors": [{"actor_id": "a1", "name": "X", "entity_type": "Intrusion-Set"}]},
        "r2": {"report_id": "r2", "title": "T2", "actors": []},
    })
    packets = select_report(client, cache, Config(), limit=None)
    assert [p["source_ref"] for p in packets] == ["r1"]
    assert packets[0]["source"] == "report"
    assert packets[0]["title"] == "T1"
    assert packets[0]["actors"][0]["actor_id"] == "a1"
    assert packets[0]["text"] == "some article text"


def test_select_report_respects_limit(tmp_path: Path):
    cache = TextCache(tmp_path)
    cache.write("r1", "text one")
    cache.write("r2", "text two")
    client = FakeReportClient({
        rid: {"report_id": rid, "title": rid,
              "actors": [{"actor_id": "a", "name": "A", "entity_type": "Intrusion-Set"}]}
        for rid in ("r1", "r2")
    })
    packets = select_report(client, cache, Config(), limit=1)
    assert len(packets) == 1


def test_select_report_skips_reports_without_platform_info(tmp_path: Path):
    cache = TextCache(tmp_path)
    cache.write("r1", "text")
    client = FakeReportClient({})  # report_actors returns None for r1
    assert select_report(client, cache, Config(), None) == []


def test_select_report_rejects_bad_inputs(tmp_path: Path):
    cache = TextCache(tmp_path)
    with pytest.raises(TypeError, match="cache"):
        select_report(FakeReportClient({}), "not-a-cache", Config(), None)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="cfg"):
        select_report(FakeReportClient({}), cache, "not-a-config", None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="positive"):
        select_report(FakeReportClient({}), cache, Config(), 0)
