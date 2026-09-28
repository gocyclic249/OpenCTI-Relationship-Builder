"""The linker registry: every dimension octi-rb can enrich a report with.

Mirrors `opencti-docker/octigeo/dimensions.py`'s `LOCATION`/`SECTOR`/`ACTOR`
blocks, generalized: `build_resolver` closures take the full `Config` (not
just `Client`) because sector/actor vocabularies are config-scoped on this
platform, and `report-vuln` needs no model step at all -- CVE extraction is
deterministic regex, not an LLM contract.

Unlike octi-geo, there is no default: `--linker` is required, so `get(None)`
exits exactly like an unknown name.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from ..resolvers.actors import ActorVocabulary
from ..resolvers.crosswalk import Crosswalk
from ..resolvers.gazetteer import Gazetteer
from ..resolvers.sectors import SectorVocabulary
from .base import Linker, Resolver
from .contracts import actor_contract, location_contract, sector_contract
from .report_vuln import VulnVocabulary

if TYPE_CHECKING:
    from ..client import Client
    from ..config import Config


def _log(msg: str) -> None:
    """Diagnostics go to stderr, matching octi-geo's `_log` in cli.py."""
    print(msg, file=sys.stderr)


def _build_gazetteer(client: Client, cfg: Config) -> Resolver:  # noqa: ARG001 - cfg unused
    return Gazetteer.load(client)


def _build_sectors(client: Client, cfg: Config) -> Resolver:
    return SectorVocabulary.load(client, cfg.sectors)


def _build_actors(client: Client, cfg: Config) -> Resolver:
    crosswalk = Crosswalk.load(cfg.cache_dir, _log) if cfg.actors.crosswalk_enabled else None
    return ActorVocabulary.load(client, cfg, crosswalk=crosswalk)


def _build_vulns(client: Client, cfg: Config) -> Resolver:  # noqa: ARG001 - cfg unused
    return VulnVocabulary(client)


def _build_actor_target(client: Client, cfg: Config) -> Resolver:
    """actor-target has no single-resolver shape: its `Context`
    (`linkers.actor_target.Context`) needs an actor vocabulary, a target
    resolver *per kind* (country/region/sector) and the relationship
    schema all at once -- four collaborators, not the one `Resolver` this
    hook is typed for. Building that Context is CLI-wiring work outside
    this task's scope, so nothing in this codebase calls
    `REGISTRY["actor-target"].build_resolver` yet; this raises rather than
    pretend a single Resolver can stand in for four.
    """
    raise NotImplementedError(
        "actor-target builds its Context (actors + per-kind targets + schema) "
        "directly -- see octirb.linkers.actor_target.Context -- not through "
        "Linker.build_resolver"
    )


REGISTRY: dict[str, Linker] = {
    "report-location": Linker(
        name="report-location",
        key_field="iso3",
        roles=frozenset({"origin", "target", "mentioned"}),
        label_suffix="Location",
        entity_kind="Country",
        write_kind="containment",
        needs_model=True,
        build_resolver=_build_gazetteer,
        contract=location_contract,
    ),
    "report-sector": Linker(
        name="report-sector",
        key_field="sector",
        roles=frozenset({"target", "mentioned"}),
        label_suffix="Sector",
        entity_kind="Sector",
        write_kind="containment",
        needs_model=True,
        build_resolver=_build_sectors,
        contract=sector_contract,
    ),
    "report-actor": Linker(
        name="report-actor",
        key_field="actor",
        roles=frozenset({"attributed", "mentioned"}),
        label_suffix="Actor",
        entity_kind="Actor",
        write_kind="containment",
        needs_model=True,
        build_resolver=_build_actors,
        contract=actor_contract,
        alias_field="aliases",
    ),
    "report-vuln": Linker(
        name="report-vuln",
        key_field="cve",
        roles=frozenset({"mentioned"}),
        label_suffix="Vulnerability",
        entity_kind="Vulnerability",
        write_kind="containment",
        needs_model=False,
        build_resolver=_build_vulns,
        contract=None,
    ),
    "actor-target": Linker(
        name="actor-target",
        key_field="actor_id",
        # Roles ("origin"/"targets") are validated by actor_target.validate's
        # ENUMS against its own RELATIONSHIPS set, not by the pipeline's
        # generic role check -- this linker's apply/validate flow never goes
        # through octirb.pipeline, so an empty set here is correct, not TODO.
        roles=frozenset(),
        label_suffix="Relationship",
        entity_kind="Relationship",
        write_kind="relationship",
        needs_model=True,
        build_resolver=_build_actor_target,
        # actor_target.render(source, sector_names, region_names) is its own
        # per-source contract function, not a Resolver -> str closure like
        # the containment linkers' `contract` field expects -- callers reach
        # it directly instead of through this field.
        contract=None,
    ),
}


def get(name: str | None) -> Linker:
    """Look up a linker by name. Unknown or missing name exits -- no default."""
    if name is not None and not isinstance(name, str):
        raise TypeError("get: name must be a str or None")
    if name is None or name not in REGISTRY:
        raise SystemExit(f"Unknown linker {name!r}. Choose from: {', '.join(sorted(REGISTRY))}")
    return REGISTRY[name]
