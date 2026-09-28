"""Ported from opencti-docker/tests/test_actors.py.

Constructor calls are updated to pass the new keyword-only `label` and
`create_type` args (ACTOR_LABEL and the hardcoded Threat-Actor-Group mint
are gone -- see octirb/resolvers/actors.py). `test_create_returns_an_actor_
and_indexes_it` now asserts entity_type == "Intrusion-Set" (the create_type
this file's fixtures pass in) instead of the old hardcoded
"Threat-Actor-Group".

`FakeClient.create_threat_actor_group` is replaced by `create_actor`, which
matches `octirb.client.Client.create_actor(entity_type, name, aliases,
label_id)`.

A `test_load_*` case is added (not present upstream): `ActorVocabulary.load`
now reads the merged, paginated `client.actors()` instead of separate
`intrusion_sets()`/`threat_actor_groups()` calls (Task 8 change 2), so that
behavior needs its own coverage.
"""

from __future__ import annotations

from typing import Any

import pytest

from octirb.config import Config
from octirb.resolvers.actors import Actor, ActorVocabulary, normalise

SAMPLE_ACTOR_COUNT = 4
LABEL = "AI-Created"
CREATE_TYPE = "Intrusion-Set"


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


class FakeClient:
    """Records calls so creation can be tested without a platform."""

    def __init__(self) -> None:
        self.created: list[tuple[str, str, tuple[str, ...], str]] = []
        self.labels_ensured: list[tuple[str, str]] = []

    def ensure_label(self, value: str, color: str) -> str:
        self.labels_ensured.append((value, color))
        return "label-id-1"

    def create_actor(
        self, entity_type: str, name: str, aliases: list[str], label_id: str
    ) -> str:
        self.created.append((entity_type, name, tuple(aliases), label_id))
        return f"new-{len(self.created)}"


@pytest.fixture
def fake_client() -> FakeClient:
    return FakeClient()


def vocab_of(actors: list[Actor], malware: list[str] | None = None, client: Any = None) -> ActorVocabulary:
    return ActorVocabulary(
        actors, malware or (), client=client, label=LABEL, create_type=CREATE_TYPE
    )


def test_normalise_strips_punctuation_and_case() -> None:
    assert normalise("Silent Ransom Group") == "silentransomgroup"
    assert normalise("UNC-6240") == "unc6240"
    assert normalise("  APT29  ") == "apt29"


def test_resolves_by_exact_name(sample_actors: list[Actor]) -> None:
    vocab = vocab_of(sample_actors)
    resolved = vocab.resolve("Turla")
    assert resolved is not None
    assert resolved.name == "Turla"


def test_resolves_by_alias(sample_actors: list[Actor]) -> None:
    vocab = vocab_of(sample_actors)
    blizzard = vocab.resolve("Midnight Blizzard")
    secret = vocab.resolve("Secret Blizzard")
    hunters = vocab.resolve("UNC6240")
    assert blizzard is not None and blizzard.name == "APT29"
    assert secret is not None and secret.name == "Turla"
    assert hunters is not None and hunters.name == "ShinyHunters"


def test_resolves_across_punctuation_difference(sample_actors: list[Actor]) -> None:
    """The live platform stores SilentRansomGroup with no spaces."""
    vocab = vocab_of(sample_actors)
    resolved = vocab.resolve("Silent Ransom Group")
    assert resolved is not None
    assert resolved.name == "SilentRansomGroup"


def test_rename_table_covers_names_newer_than_the_seed(sample_actors: list[Actor]) -> None:
    """APT29 carries 14 aliases on the platform but not GTIG's 2026 rename."""
    vocab = vocab_of(sample_actors)
    resolved = vocab.resolve("ICE RELIC")
    assert resolved is not None
    assert resolved.name == "APT29"


def test_unknown_name_resolves_to_none(sample_actors: list[Actor]) -> None:
    vocab = vocab_of(sample_actors)
    assert vocab.resolve("WaterPlum") is None
    assert vocab.resolve("BREEZE COMET") is None


def test_empty_key_resolves_to_none(sample_actors: list[Actor]) -> None:
    vocab = vocab_of(sample_actors)
    assert vocab.resolve("") is None
    assert vocab.resolve("   ") is None
    assert vocab.resolve("!!!") is None


def test_len_counts_distinct_keys(sample_actors: list[Actor]) -> None:
    vocab = vocab_of(sample_actors)
    assert len(vocab) == SAMPLE_ACTOR_COUNT


def test_probes_are_resolvable(sample_actors: list[Actor]) -> None:
    """doctor prints these; a probe that stops resolving makes doctor lie."""
    vocab = vocab_of(sample_actors)
    assert vocab.probes()
    for probe in vocab.probes():
        assert vocab.resolve(probe) is not None, probe


def test_conflict_flags_existing_malware(sample_actors: list[Actor], sample_malware: list[str]) -> None:
    vocab = vocab_of(sample_actors, sample_malware)
    assert vocab.conflict("Clop") == "Malware: Clop"
    assert vocab.conflict("ALPHV") == "Malware: ALPHV"


def test_conflict_flags_existing_actor(sample_actors: list[Actor], sample_malware: list[str]) -> None:
    vocab = vocab_of(sample_actors, sample_malware)
    assert vocab.conflict("APT29") == "Intrusion-Set: APT29"
    assert vocab.conflict("Midnight Blizzard") == "Intrusion-Set: APT29"


def test_conflict_is_none_for_genuinely_new_names(
    sample_actors: list[Actor], sample_malware: list[str]
) -> None:
    vocab = vocab_of(sample_actors, sample_malware)
    assert vocab.conflict("WaterPlum") is None
    assert vocab.conflict("BREEZE COMET") is None


def test_conflict_normalises_like_resolve(sample_actors: list[Actor], sample_malware: list[str]) -> None:
    vocab = vocab_of(sample_actors, sample_malware)
    assert vocab.conflict("cl0p") is None  # not the same name
    assert vocab.conflict("  clop  ") == "Malware: Clop"


def test_conflict_is_none_for_empty(sample_actors: list[Actor], sample_malware: list[str]) -> None:
    vocab = vocab_of(sample_actors, sample_malware)
    assert vocab.conflict("") is None


def test_conflict_reports_the_actor_when_a_name_is_both() -> None:
    """Precedence: a name present as both actor and malware reports the actor.

    The shared fixtures deliberately do not overlap, so this builds its own
    vocabulary -- without it the precedence rule is asserted only by the
    order of two branches and nothing fails if they are swapped.
    """
    overlap = [Actor(id="x", name="Ryuk", entity_type="Intrusion-Set")]
    vocab = vocab_of(overlap, ["Ryuk"])
    assert vocab.conflict("Ryuk") == "Intrusion-Set: Ryuk"


def test_create_returns_an_actor_and_indexes_it(
    sample_actors: list[Actor], sample_malware: list[str], fake_client: FakeClient
) -> None:
    vocab = vocab_of(sample_actors, sample_malware, client=fake_client)
    actor = vocab.create("WaterPlum", ["Water Plum"])
    assert actor.name == "WaterPlum"
    assert actor.entity_type == CREATE_TYPE
    assert vocab.resolve("WaterPlum") is actor
    assert vocab.resolve("Water Plum") is actor


def test_create_is_idempotent_within_a_run(
    sample_actors: list[Actor], sample_malware: list[str], fake_client: FakeClient
) -> None:
    """Two reports naming the same adversary must mint once."""
    vocab = vocab_of(sample_actors, sample_malware, client=fake_client)
    first = vocab.create("WaterPlum", [])
    second = vocab.create("WaterPlum", [])
    assert first is second
    assert len(fake_client.created) == 1


def test_create_ensures_the_label_once(
    sample_actors: list[Actor], sample_malware: list[str], fake_client: FakeClient
) -> None:
    vocab = vocab_of(sample_actors, sample_malware, client=fake_client)
    vocab.create("WaterPlum", [])
    vocab.create("NightEagle", [])
    assert len(fake_client.labels_ensured) == 1
    assert fake_client.labels_ensured[0][0] == LABEL


def test_create_passes_create_type_to_the_client(
    sample_actors: list[Actor], sample_malware: list[str], fake_client: FakeClient
) -> None:
    vocab = vocab_of(sample_actors, sample_malware, client=fake_client)
    vocab.create("WaterPlum", [])
    assert fake_client.created[0][0] == CREATE_TYPE


def test_create_without_a_client_is_refused(sample_actors: list[Actor]) -> None:
    vocab = vocab_of(sample_actors)
    with pytest.raises(RuntimeError, match="client"):
        vocab.create("WaterPlum", [])


def test_create_refuses_an_empty_name(
    sample_actors: list[Actor], sample_malware: list[str], fake_client: FakeClient
) -> None:
    vocab = vocab_of(sample_actors, sample_malware, client=fake_client)
    with pytest.raises(ValueError, match="name"):
        vocab.create("   ", [])


# -- ActorVocabulary.load(): new in Task 8 -- reads the merged, paginated
# client.actors() instead of separate intrusion_sets()/threat_actor_groups()
# calls, and builds label/create_type from cfg. Not present upstream.


class FakeLoadClient:
    def __init__(self, actor_nodes: list[dict[str, Any]], malware: list[str]) -> None:
        self._actor_nodes = actor_nodes
        self._malware = malware

    def actors(self) -> list[dict[str, Any]]:
        return self._actor_nodes

    def malware_names(self) -> list[str]:
        return self._malware


def test_load_reads_from_paginated_client_actors() -> None:
    client = FakeLoadClient(
        [
            {"id": "i1", "name": "APT29", "aliases": ["Cozy Bear"], "entity_type": "Intrusion-Set"},
            {"id": "t1", "name": "TAG1", "aliases": [], "entity_type": "Threat-Actor-Group"},
        ],
        ["Clop"],
    )
    vocab = ActorVocabulary.load(client, Config(), crosswalk=None)
    assert len(vocab) == 2
    apt29 = vocab.resolve("Cozy Bear")
    assert apt29 is not None
    assert apt29.entity_type == "Intrusion-Set"
    assert vocab.conflict("Clop") == "Malware: Clop"


def test_load_builds_label_and_create_type_from_cfg() -> None:
    client = FakeLoadClient([], [])
    cfg = Config()
    vocab = ActorVocabulary.load(client, cfg, crosswalk=None)
    assert vocab._label == cfg.label("Created")  # white-box: internal state, not part of the public API
    assert vocab._create_type == cfg.actors.create_missing_type
