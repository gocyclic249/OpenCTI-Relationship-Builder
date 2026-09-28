"""validate()/create_missing() coverage.

Ported from opencti-docker/tests/test_validate.py and the pipeline-flow
parts of tests/test_create_missing.py, updated for octi-rb:

- `dimensions.get("actor")` -> a hand-built `Linker` (`_actor_linker()`
  below); the registry's real actor Linker needs a live Config/Client to
  build its resolver, which these tests don't need.
- `pipeline.validate(items, vocab, IDS, DIM)` -> `pipeline.validate(items,
  vocab, IDS, linker)` -- same shape, `dim` renamed `linker` (Task 9).
- `create_missing(vocab, review, log, dry_run=...)` gains a required
  `linker=` keyword (the ported fix: read the name via `linker.key_field`,
  not a hard-coded "actor").
- `ActorVocabulary(actors, malware)` -> octirb's constructor requires
  keyword-only `label=`/`create_type=`, and (for the creating tests)
  `client=`.

New (Task 12 brief step 2): crosswalk-fallback and alias-write-back
coverage, which have no upstream analogue -- octigeo never had either.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from octirb import pipeline
from octirb.client import OpenCTIError
from octirb.linkers.base import Linker
from octirb.resolvers.actors import Actor, ActorVocabulary

IDS = {"r1"}
LABEL = "AI-Created"
CREATE_TYPE = "Intrusion-Set"


def _actor_linker() -> Linker:
    return Linker(
        name="report-actor",
        key_field="actor",
        roles=frozenset({"attributed", "mentioned"}),
        label_suffix="Actor",
        entity_kind="Actor",
        write_kind="containment",
        needs_model=True,
        build_resolver=lambda _c, _cfg: None,  # type: ignore[return-value] # unused here
        contract=None,
        alias_field="aliases",
    )


def _location_linker() -> Linker:
    return Linker(
        name="report-location",
        key_field="iso3",
        roles=frozenset({"origin", "target", "mentioned"}),
        label_suffix="Location",
        entity_kind="Country",
        write_kind="containment",
        needs_model=True,
        build_resolver=lambda _c, _cfg: None,  # type: ignore[return-value]
        contract=None,
    )


ACTOR = _actor_linker()
LOCATION = _location_linker()


@pytest.fixture
def sample_actors() -> list[Actor]:
    return [
        Actor(
            id="11111111-1111-1111-1111-111111111111",
            name="APT29",
            entity_type="Intrusion-Set",
            aliases=(
                "IRON RITUAL", "IRON HEMLOCK", "NobleBaron", "Dark Halo",
                "NOBELIUM", "UNC2452", "YTTRIUM", "The Dukes", "Cozy Bear",
                "CozyDuke", "SolarStorm", "Blue Kitsune", "UNC3524",
                "Midnight Blizzard",
            ),
        ),
        Actor(
            id="22222222-2222-2222-2222-222222222222",
            name="Turla",
            entity_type="Intrusion-Set",
            aliases=("Snake", "Venomous Bear", "Secret Blizzard", "Waterbug"),
        ),
        Actor(
            id="33333333-3333-3333-3333-333333333333",
            name="SilentRansomGroup",
            entity_type="Intrusion-Set",
            aliases=("Luna Moth",),
        ),
        Actor(
            id="44444444-4444-4444-4444-444444444444",
            name="ShinyHunters",
            entity_type="Intrusion-Set",
            aliases=("UNC6240", "Bling Libra"),
        ),
    ]


@pytest.fixture
def sample_malware() -> list[str]:
    return ["Clop", "BlackCat", "ALPHV", "Ryuk", "XWORM", "VIDAR"]


class FakeCreateClient:
    """Records create_actor/ensure_label calls so create_missing is testable
    without a platform."""

    def __init__(self) -> None:
        self.created: list[tuple[str, tuple[str, ...], str]] = []
        self.labels_ensured: list[tuple[str, str]] = []

    def ensure_label(self, value: str, color: str) -> str:
        self.labels_ensured.append((value, color))
        return "label-id-1"

    def create_actor(self, _entity_type: str, name: str, aliases: list[str], label_id: str) -> str:
        self.created.append((name, tuple(aliases), label_id))
        return f"new-{len(self.created)}"


@pytest.fixture
def fake_client() -> FakeCreateClient:
    return FakeCreateClient()


def item(**over: Any) -> dict[str, Any]:
    base = {
        "report_id": "r1", "title": "t", "actor": "UNC6293",
        "aliases": ["ICE RELIC", "APT29"], "role": "attributed",
        "confidence": "high", "evidence": "q",
    }
    base.update(over)
    return base


def logs() -> tuple[list[str], Any]:
    sink: list[str] = []
    return sink, sink.append


# ------------------------------------------------------ ported: test_validate


def test_resolves_through_the_alias_chain(sample_actors, sample_malware):
    vocab = ActorVocabulary(sample_actors, sample_malware, label=LABEL, create_type=CREATE_TYPE)
    auto, review = pipeline.validate([item()], vocab, IDS, ACTOR)
    assert len(auto) == 1
    assert auto[0]["entity_name"] == "APT29"
    assert review == []


def test_primary_name_wins_over_aliases(sample_actors, sample_malware):
    vocab = ActorVocabulary(sample_actors, sample_malware, label=LABEL, create_type=CREATE_TYPE)
    auto, _ = pipeline.validate([item(actor="Turla", aliases=["APT29"])], vocab, IDS, ACTOR)
    assert auto[0]["entity_name"] == "Turla"


def test_unresolved_is_marked_creatable(sample_actors, sample_malware):
    vocab = ActorVocabulary(sample_actors, sample_malware, label=LABEL, create_type=CREATE_TYPE)
    auto, review = pipeline.validate([item(actor="WaterPlum", aliases=[])], vocab, IDS, ACTOR)
    assert auto == []
    assert review[0]["creatable"] is True
    assert review[0]["hard_fail"] is True


def test_malware_collision_is_not_creatable(sample_actors, sample_malware):
    vocab = ActorVocabulary(sample_actors, sample_malware, label=LABEL, create_type=CREATE_TYPE)
    _, review = pipeline.validate([item(actor="Clop", aliases=[])], vocab, IDS, ACTOR)
    assert not review[0].get("creatable")
    assert "exists as Malware: Clop" in review[0]["review_reasons"]


def test_location_linker_is_unaffected():
    """alias_field is None there, so behaviour must be byte-identical."""
    assert LOCATION.alias_field is None


def test_creatable_only_when_unresolvability_is_the_sole_defect(sample_actors, sample_malware):
    """--create-missing must not mint an item that is ALSO malformed.

    _reasons_for reports every defect; being unresolved is only one of them.
    Marking creatable on that branch alone let --create-missing mint AND
    write items with an invalid role, no evidence, or a report_id the run
    never selected.
    """
    vocab = ActorVocabulary(sample_actors, sample_malware, label=LABEL, create_type=CREATE_TYPE)
    for label, over in (
        ("outside selection", {"report_id": "rXX"}),
        ("invalid role", {"role": "origin"}),
        ("missing evidence", {"evidence": ""}),
        ("invalid confidence", {"confidence": "maybe"}),
    ):
        _, review = pipeline.validate(
            [item(actor="WaterPlum", aliases=[], **over)], vocab, IDS, ACTOR
        )
        assert not review[0].get("creatable"), label


def test_unresolved_alone_is_still_creatable(sample_actors, sample_malware):
    """Regression guard: the fix must not disable minting altogether."""
    vocab = ActorVocabulary(sample_actors, sample_malware, label=LABEL, create_type=CREATE_TYPE)
    _, review = pipeline.validate([item(actor="WaterPlum", aliases=[])], vocab, IDS, ACTOR)
    assert review[0]["creatable"] is True


# ------------------------------------------------ ported: test_create_missing


def creatable(**over: Any) -> dict[str, Any]:
    base = {
        "report_id": "r1", "title": "t", "actor": "WaterPlum",
        "aliases": [], "role": "attributed", "confidence": "high",
        "evidence": "q", "creatable": True, "hard_fail": True,
    }
    base.update(over)
    return base


def test_creates_high_confidence_items(sample_actors, sample_malware, fake_client):
    vocab = ActorVocabulary(
        sample_actors, sample_malware, client=fake_client, label=LABEL, create_type=CREATE_TYPE
    )
    _, log = logs()
    promoted = pipeline.create_missing(vocab, [creatable()], log, dry_run=False, linker=ACTOR)
    assert len(promoted) == 1
    assert promoted[0]["entity_name"] == "WaterPlum"
    assert promoted[0]["created"] is True


def test_skips_medium_and_low(sample_actors, sample_malware, fake_client):
    vocab = ActorVocabulary(
        sample_actors, sample_malware, client=fake_client, label=LABEL, create_type=CREATE_TYPE
    )
    _, log = logs()
    items = [creatable(confidence="medium"), creatable(confidence="low")]
    assert pipeline.create_missing(vocab, items, log, dry_run=False, linker=ACTOR) == []


def test_skips_items_not_marked_creatable(sample_actors, sample_malware, fake_client):
    vocab = ActorVocabulary(
        sample_actors, sample_malware, client=fake_client, label=LABEL, create_type=CREATE_TYPE
    )
    _, log = logs()
    items = [creatable(creatable=False)]
    assert pipeline.create_missing(vocab, items, log, dry_run=False, linker=ACTOR) == []


def test_dry_run_creates_nothing_but_reports(sample_actors, sample_malware, fake_client):
    vocab = ActorVocabulary(
        sample_actors, sample_malware, client=fake_client, label=LABEL, create_type=CREATE_TYPE
    )
    sink, log = logs()
    promoted = pipeline.create_missing(vocab, [creatable()], log, dry_run=True, linker=ACTOR)
    assert promoted == []
    assert fake_client.created == []
    assert any("WaterPlum" in line for line in sink)


def test_non_creating_resolver_is_a_no_op():
    """Location and sector resolvers must pass straight through."""

    class NotACreator:
        def resolve(self, _key: str) -> None:
            return None

        def probes(self) -> list[str]:
            return []

        def __len__(self) -> int:
            return 0

    _, log = logs()
    assert pipeline.create_missing(NotACreator(), [creatable()], log, dry_run=False, linker=ACTOR) == []


def test_a_failed_creation_does_not_abort_the_batch(sample_actors, sample_malware, fake_client):
    """One bad name must not cost the whole batch.

    A half-written batch is recoverable from the ledger; an aborted run
    that already minted entities is not. This covers the except branch,
    which is otherwise the only unexercised path in the function.
    """

    class Exploding(ActorVocabulary):
        def create(self, name: str, aliases: list[str]) -> Actor:
            if name == "Boom":
                raise OpenCTIError("platform refused")
            return super().create(name, aliases)

    vocab = Exploding(
        sample_actors, sample_malware, client=fake_client, label=LABEL, create_type=CREATE_TYPE
    )
    sink, log = logs()
    items = [creatable(actor="Boom"), creatable(actor="WaterPlum")]
    promoted = pipeline.create_missing(vocab, items, log, dry_run=False, linker=ACTOR)
    assert [p["entity_name"] for p in promoted] == ["WaterPlum"]
    assert any("Boom" in line for line in sink)


def test_a_malware_collision_never_reaches_creation(sample_actors, sample_malware, fake_client):
    """End to end: conflict -> creatable withheld -> nothing minted.

    Goes through validate() rather than hand-setting `creatable`, because a
    real conflict produces an ABSENT key, not creatable=False -- so a gate
    written as `is False` would pass every other test here and still mint.
    """
    vocab = ActorVocabulary(
        sample_actors, sample_malware, client=fake_client, label=LABEL, create_type=CREATE_TYPE
    )
    extraction = {
        "report_id": "r1", "title": "t", "actor": "Clop", "aliases": [],
        "role": "attributed", "confidence": "high", "evidence": "q",
    }
    _, review = pipeline.validate([extraction], vocab, {"r1"}, ACTOR)
    assert "creatable" not in review[0]
    _, log = logs()
    assert pipeline.create_missing(vocab, review, log, dry_run=False, linker=ACTOR) == []
    assert fake_client.created == []


def test_a_malformed_item_never_reaches_creation(sample_actors, sample_malware, fake_client):
    """End to end: validate() -> create_missing() with malformed extractions.

    Each is unresolved AND defective. Before the fix each one both minted a
    permanent entity and was promoted for writing.
    """
    for over in ({"report_id": "rXX"}, {"role": "origin"}, {"evidence": ""}):
        vocab = ActorVocabulary(
            sample_actors, sample_malware, client=fake_client, label=LABEL, create_type=CREATE_TYPE
        )
        extraction = {
            "report_id": "r1", "title": "t", "actor": "WaterPlum", "aliases": [],
            "role": "attributed", "confidence": "high", "evidence": "q",
        }
        extraction.update(over)
        _, review = pipeline.validate([extraction], vocab, {"r1"}, ACTOR)
        _, log = logs()
        assert pipeline.create_missing(vocab, review, log, dry_run=False, linker=ACTOR) == []
    assert fake_client.created == []


def test_two_reports_naming_one_adversary_mint_once(sample_actors, sample_malware, fake_client):
    vocab = ActorVocabulary(
        sample_actors, sample_malware, client=fake_client, label=LABEL, create_type=CREATE_TYPE
    )
    _, log = logs()
    items = [creatable(report_id="r1"), creatable(report_id="r2")]
    promoted = pipeline.create_missing(vocab, items, log, dry_run=False, linker=ACTOR)
    assert len(promoted) == len(items)
    assert len(fake_client.created) == 1
    assert promoted[0]["entity_id"] == promoted[1]["entity_id"]


# ------------------------------------------------------- new (Task 12 brief)


def test_validate_non_dict_item_held():
    vocab = ActorVocabulary([], label=LABEL, create_type=CREATE_TYPE)
    auto, review = pipeline.validate([["not", "a", "dict"]], vocab, IDS, ACTOR)
    assert auto == []
    assert len(review) == 1
    assert review[0]["raw"] == ["not", "a", "dict"]
    assert review[0]["hard_fail"] is True
    assert review[0]["review_reasons"] == ["extraction is not a JSON object"]


@dataclass
class FakeActor:
    id: str
    name: str
    aliases: tuple[str, ...] = ()


@dataclass
class FakeCrosswalkResolver:
    """Minimal Resolver + crosswalk_resolve double, independent of the real
    Crosswalk/ActorVocabulary machinery -- validate()'s crosswalk fallback
    only needs `resolve`/`crosswalk_resolve` to exist with the right shape."""

    resolves: dict[str, FakeActor] = field(default_factory=dict)
    crosswalk_hit: tuple[FakeActor, str] | None = None
    crosswalk_calls: list[str] = field(default_factory=list)

    def resolve(self, key: str) -> FakeActor | None:
        return self.resolves.get(key)

    def probes(self) -> list[str]:
        return []

    def __len__(self) -> int:
        return len(self.resolves)

    def crosswalk_resolve(self, key: str) -> tuple[FakeActor, str] | None:
        self.crosswalk_calls.append(key)
        return self.crosswalk_hit


def test_crosswalk_hit_demotes_to_medium():
    hit_actor = FakeActor(id="e1", name="APT29")
    resolver = FakeCrosswalkResolver(crosswalk_hit=(hit_actor, "APT29"))
    auto, review = pipeline.validate(
        [item(actor="ICE RELIC", aliases=[], confidence="high")], resolver, IDS, ACTOR
    )
    assert auto == []
    assert len(review) == 1
    assert review[0]["via_crosswalk"] == "APT29"
    assert review[0]["confidence"] == "medium"
    assert any("crosswalk cluster 'APT29'" in r for r in review[0]["review_reasons"])


def test_crosswalk_never_consulted_on_direct_hit():
    direct_actor = FakeActor(id="e1", name="APT29")
    resolver = FakeCrosswalkResolver(
        resolves={"APT29": direct_actor}, crosswalk_hit=(FakeActor(id="e2", name="Other"), "cluster")
    )
    auto, review = pipeline.validate(
        [item(actor="APT29", aliases=[], confidence="high")], resolver, IDS, ACTOR
    )
    assert len(auto) == 1
    assert review == []
    assert resolver.crosswalk_calls == []


def test_alias_writes_derived_only_for_unknown_names():
    resolved = FakeActor(id="e1", name="APT29", aliases=())
    resolver = FakeCrosswalkResolver(resolves={"APT29": resolved})
    auto, _ = pipeline.validate(
        [item(actor="APT29", aliases=["ICE RELIC", "APT29"], confidence="high")],
        resolver, IDS, ACTOR, writeback=True,
    )
    assert len(auto) == 1
    assert auto[0]["alias_writes"] == ["ICE RELIC"]


def test_alias_writes_absent_when_writeback_disabled():
    resolved = FakeActor(id="e1", name="APT29", aliases=())
    resolver = FakeCrosswalkResolver(resolves={"APT29": resolved})
    auto, _ = pipeline.validate(
        [item(actor="APT29", aliases=["ICE RELIC", "APT29"], confidence="high")],
        resolver, IDS, ACTOR,
    )
    assert len(auto) == 1
    assert "alias_writes" not in auto[0]
