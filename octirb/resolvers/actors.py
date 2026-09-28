"""Resolve extracted adversary names to actors already on the platform.

The obvious target is wrong here. This platform holds zero Threat-Actor-Group
and zero Threat-Actor-Individual entities: the feeds that stock it model
adversaries as Intrusion Sets, carrying the actor's other names as aliases.
So resolution reads Intrusion-Set and Threat-Actor-Group together -- both are
"an actor that already exists" -- and only creation is specific to one type
(config-driven here: `cfg.actors.create_missing_type`, not hardcoded).

Keys are normalised rather than matched literally because the platform's own
spelling is inconsistent: "Silent Ransom Group" in prose is SilentRansomGroup
on the platform, and nothing matches without stripping the spaces.

Unlike sectors, there is no propagation to exploit: no report_ref_* rule
covers intrusion sets, so one actor write yields exactly one object.

Ported from opencti-docker/octigeo/actors.py, with (Task 8 brief):
1. ACTOR_LABEL is no longer a constant -- __init__ takes `label` and
   `create_type` (from `cfg.label("Created")` and
   `cfg.actors.create_missing_type`), and create() calls the generalized
   `client.create_actor(entity_type, name, aliases, label_id)`.
2. load() reads the merged, paginated `client.actors()` instead of two
   separate 500-cap queries.
3. New `crosswalk_resolve()` -- resolves via a MISP galaxy synonym cluster
   when a direct/renamed platform match (resolve()) misses.
4. Import-cycle rule: crosswalk.py imports `normalise` from this module at
   module level, so this module imports Crosswalk only under
   TYPE_CHECKING -- it is needed purely as a type hint; the instance is
   always passed in by the caller.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..client import Client, JsonDict
from ..config import Config

if TYPE_CHECKING:
    from .crosswalk import Crosswalk

# Color for the label ActorVocabulary.create() ensures on every actor it
# mints, so a platform admin can filter for octi-rb-created entities.
CREATED_LABEL_COLOR = "#6b4fa8"

# Vendor renames the platform's seed predates. Deliberately tiny, and the same
# discipline as gazetteer.COMMON_NAMES: only unambiguous entries belong here.
# Anything debatable is left out so it lands in the review queue instead of
# being guessed at. Every entry is a maintenance liability -- a stale one
# silently mismaps -- so add only when a real report forces it.
#
# ICE RELIC: GTIG's 2026 rename of APT29. The platform carries 14 APT29
# aliases including Midnight Blizzard, UNC2452 and UNC3524, but not this one.
RENAMES: dict[str, str] = {
    "ICE RELIC": "APT29",
}


def normalise(value: str) -> str:
    """Casefold and strip everything that is not a letter or digit."""
    if not isinstance(value, str):
        raise TypeError(f"normalise() takes a str, got {type(value).__name__}")
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _normal_or_none(value: str) -> str | None:
    """Normalised key, or None when there is nothing left to match on."""
    if not value or not value.strip():
        return None
    return normalise(value) or None


@dataclass(frozen=True)
class Actor:
    id: str
    name: str
    entity_type: str
    aliases: tuple[str, ...] = ()


_RENAMES_N: dict[str, str] = {normalise(k): v for k, v in RENAMES.items()}


class ActorVocabulary:
    def __init__(  # noqa: PLR0913 - crosswalk/label/create_type are keyword-only, not a data clump
        self,
        actors: list[Actor],
        malware_names: Iterable[str] = (),
        client: Client | None = None,
        *,
        crosswalk: Crosswalk | None = None,
        label: str,
        create_type: str,
    ) -> None:
        if not isinstance(actors, list):
            raise TypeError("ActorVocabulary: actors must be a list")
        if not label or not label.strip():
            raise ValueError("ActorVocabulary: label must be a non-empty str")
        self._client = client
        self._crosswalk = crosswalk
        self._label = label
        self._create_type = create_type
        self._label_id: str | None = None
        self._actors = list(actors)
        self._by_key: dict[str, Actor] = {}
        for actor in self._actors:
            for spelling in (actor.name, *actor.aliases):
                key = normalise(spelling)
                if key:
                    self._by_key.setdefault(key, actor)
        self._malware: dict[str, str] = {}
        for name in malware_names:
            key = normalise(name)
            if key:
                self._malware.setdefault(key, name)

    def __len__(self) -> int:
        return len(self._actors)

    def resolve(self, key: str) -> Actor | None:
        """Resolve a name, a platform alias, or a curated rename."""
        normal = _normal_or_none(key)
        if normal is None:
            return None
        direct = self._by_key.get(normal)
        if direct is not None:
            return direct
        renamed = _RENAMES_N.get(normal)
        if renamed is None:
            return None
        return self._by_key.get(normalise(renamed))

    def crosswalk_resolve(self, key: str) -> tuple[Actor, str] | None:
        """Resolve via a MISP galaxy synonym cluster when resolve() misses.

        None when there is no crosswalk loaded, or the name matches no
        cluster. On a cluster hit, each name in that cluster (the canonical
        value, then its synonyms) is tried against resolve() in order; the
        first one that matches an actor already on the platform wins.
        """
        if self._crosswalk is None:
            return None
        hit = self._crosswalk.synonyms(key)
        if hit is None:
            return None
        cluster_value, names = hit
        for name in names:
            actor = self.resolve(name)
            if actor is not None:
                return actor, cluster_value
        return None

    def conflict(self, name: str) -> str | None:
        """Why this name must not be minted, or None if it is genuinely new.

        Checked against actors AND malware: ransomware brands live under
        Malware on this platform, so minting "Clop" as a new actor would
        duplicate an entity that already exists under another type.

        Actors are checked before malware: a name that is both reports the
        actor, because that is the entity we would rather point a report at.
        """
        normal = _normal_or_none(name)
        if normal is None:
            return None
        existing = self._by_key.get(normal)
        if existing is not None:
            return f"{existing.entity_type}: {existing.name}"
        malware = self._malware.get(normal)
        if malware is not None:
            return f"Malware: {malware}"
        return None

    def probes(self) -> list[str]:
        return ["APT29", "Midnight Blizzard", "Silent Ransom Group", "ICE RELIC"]

    @classmethod
    def load(cls, client: Client, cfg: Config, crosswalk: Crosswalk | None) -> ActorVocabulary:
        """Read every actor already on the platform.

        Threat-Actor-Group is read alongside Intrusion-Set (via the merged,
        paginated `client.actors()`) so that an actor octi-rb minted on an
        earlier run resolves instead of being minted again -- which is what
        makes creation happen exactly once, ever.
        """
        if not isinstance(cfg, Config):
            raise TypeError("ActorVocabulary.load: cfg must be a Config")
        actors = [_actor_from(node) for node in client.actors()]
        return cls(
            actors,
            client.malware_names(),
            client=client,
            crosswalk=crosswalk,
            label=cfg.label("Created"),
            create_type=cfg.actors.create_missing_type,
        )

    def create(self, name: str, aliases: list[str]) -> Actor:
        """Mint an actor of `create_type` and index it for the rest of this run."""
        if self._client is None:
            raise RuntimeError("ActorVocabulary has no client; load() it before creating")
        if not name or not name.strip():
            raise ValueError("refusing to create an actor with no name")

        existing = self.resolve(name)
        if existing is not None:
            return existing

        if self._label_id is None:
            self._label_id = self._client.ensure_label(self._label, CREATED_LABEL_COLOR)
        new_id = self._client.create_actor(
            self._create_type, name.strip(), list(aliases), self._label_id
        )
        actor = Actor(
            id=new_id,
            name=name.strip(),
            entity_type=self._create_type,
            aliases=tuple(a.strip() for a in aliases if a and a.strip()),
        )
        self._actors.append(actor)
        for spelling in (actor.name, *actor.aliases):
            key = normalise(spelling)
            if key:
                self._by_key.setdefault(key, actor)
        return actor


def _actor_from(node: JsonDict) -> Actor:
    return Actor(
        id=str(node["id"]),
        name=str(node["name"]),
        entity_type=str(node["entity_type"]),
        aliases=tuple(str(a) for a in (node.get("aliases") or [])),
    )
