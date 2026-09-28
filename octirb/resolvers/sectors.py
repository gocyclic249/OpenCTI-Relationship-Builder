"""Resolve extracted sector names to the sectors this deployment actually owns.

Unlike octi-geo's single hardcoded ICS tree, octi-rb's vocabulary is
author-scoped: every sector this platform's own connector (by default
Filigran's Sectors dataset) created, plus the `part-of` subtree under any
`extra_roots` name from config. A same-named sector authored by someone else
(a different connector's near-duplicate import) is deliberately excluded --
see `cfg.canonical_authors` in octirb/config.py.

The tree is walked from each extra root at load time rather than hardcoded,
so re-parenting a sub-sector in the OpenCTI UI is picked up automatically.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..client import Client, JsonDict
from ..config import SectorsCfg

# The one sector name generic OT/ICS terms ("ot", "ics", "scada", ...) map to
# when it exists among cfg.extra_roots. Not hardcoded as a permanent root --
# a deployment without an ICS extra_root simply leaves these unresolved.
GENERIC_OT_TARGET = "ICS"

# Colloquialisms worth accepting, mapped to the platform's own sector names.
# Deliberately short: anything genuinely ambiguous belongs in the review queue,
# not in a guessing table.
ALIASES: dict[str, str] = {
    # Only unambiguous mappings belong here. Anything that could plausibly
    # resolve to two different verticals is left out deliberately so it lands
    # in the review queue rather than being guessed at.
    "water": "Water distribution and supply",
    "water utility": "Water distribution and supply",
    "water utilities": "Water distribution and supply",
    "wastewater": "Water distribution and supply",
    "power grid": "Electricity",
    "electric grid": "Electricity",
    "electricity grid": "Electricity",
    "nuclear": "Nuclear power (civilian use)",
    "nuclear power": "Nuclear power (civilian use)",
    "petroleum": "Oil",
    "renewables": "Renewable energies",
    "renewable energy": "Renewable energies",
    "manufacturing": "Heavy industries",
    "heavy industry": "Heavy industries",
    "trucking": "Road transport",
    "road freight": "Road transport",
    "ecommerce": "Retail",
    "e-commerce": "Retail",
    # Deliberately NOT aliased -- each is ambiguous or out of scope:
    #   "logistics"  -> Logistics is a top-level sector, usually its own tree
    #   "transport"  -> Transport is top-level; only Road transport is aliased
    #   "utilities"  -> could be Electricity, Gas or Water
    #   "energy"     -> resolves by exact name already; no alias needed
    #   "solar"/"wind" -> use "renewables" or the exact name
}

# Generic OT/ICS terms with no specific vertical. These resolve to
# GENERIC_OT_TARGET only when that name is one of cfg.extra_roots -- see
# resolve() -- otherwise they are deliberately left unresolved.
GENERIC_OT_TERMS = frozenset({
    "ot",
    "ics",
    "scada",
    "industrial control system",
    "industrial control systems",
    "critical infrastructure",
})

# _subtree()'s breadth-first walk bound: each node is expanded at most once,
# so len(nodes) iterations always suffice; the extra +1 keeps a single-node
# tree provably terminating without an off-by-one edge case.
_SUBTREE_BOUND_MARGIN = 1


@dataclass(frozen=True)
class Sector:
    id: str
    name: str
    parents: tuple[str, ...]


class SectorVocabulary:
    def __init__(
        self,
        sectors: list[Sector],
        cfg: SectorsCfg,
        alias_pairs: tuple[tuple[str, str], ...] = (),
    ) -> None:
        if not isinstance(sectors, list):
            raise TypeError("SectorVocabulary: sectors must be a list")
        if not isinstance(cfg, SectorsCfg):
            raise TypeError("SectorVocabulary: cfg must be a SectorsCfg")
        self.cfg = cfg
        self._by_name: dict[str, Sector] = {s.name.casefold(): s for s in sectors}
        self._cfg_aliases: dict[str, str] = {k.casefold(): v for k, v in cfg.aliases.items()}
        self._platform_aliases: dict[str, Sector] = {}
        for alias, target_name in alias_pairs:
            target = self._by_name.get(target_name.casefold())
            if target is not None:
                self._platform_aliases[alias.casefold()] = target

    def __len__(self) -> int:
        return len(self._by_name)

    def names(self) -> list[str]:
        return sorted(s.name for s in self._by_name.values())

    @classmethod
    def load(cls, client: Client, cfg: SectorsCfg) -> SectorVocabulary:
        if not isinstance(cfg, SectorsCfg):
            raise TypeError("SectorVocabulary.load: cfg must be a SectorsCfg")
        q = """{ sectors(first: 500) { edges { node {
          id name x_opencti_aliases
          createdBy { name }
          subSectors { edges { node { id } } }
          parentSectors { edges { node { name } } }
        } } } }"""
        nodes: dict[str, JsonDict] = {
            str(e["node"]["id"]): e["node"] for e in client.gql(q)["sectors"]["edges"]
        }
        canonical_ids = {
            nid
            for nid, n in nodes.items()
            if n.get("createdBy") and n["createdBy"]["name"] in cfg.canonical_authors
        }
        if not canonical_ids:
            raise SystemExit(
                f"no sectors authored by {cfg.canonical_authors} on this platform"
                " — is the OpenCTI Datasets connector enabled?"
            )
        member_ids = set(canonical_ids)
        for root in cfg.extra_roots:
            member_ids |= set(cls._subtree(nodes, root))
        sectors = [
            Sector(
                id=str(n["id"]),
                name=str(n["name"]),
                parents=tuple(p["node"]["name"] for p in n["parentSectors"]["edges"]),
            )
            for nid, n in nodes.items()
            if nid in member_ids
        ]
        alias_pairs = tuple(
            (str(alias), str(nodes[nid]["name"]))
            for nid in canonical_ids
            for alias in (nodes[nid].get("x_opencti_aliases") or [])
        )
        return cls(sectors, cfg, alias_pairs)

    @staticmethod
    def _subtree(nodes: dict[str, JsonDict], root: str) -> dict[str, JsonDict]:
        start = next(
            (n for n in nodes.values() if n["name"].casefold() == root.casefold()), None
        )
        if start is None:
            raise SystemExit(
                f"No sector named {root!r} on the platform. "
                f"octi-rb does not create sectors — make it in OpenCTI first."
            )
        # Breadth-first down the part-of tree. Sub-sectors are frequently
        # dual-parented (Electricity sits under both Energy and ICS), so guard
        # against revisiting. Bounded: each node is expanded at most once.
        members: dict[str, JsonDict] = {}
        queue = [start["id"]]
        for _ in range(len(nodes) * len(nodes) + _SUBTREE_BOUND_MARGIN):
            if not queue:
                break
            nid = queue.pop()
            if nid in members:
                continue
            node = nodes.get(nid)
            if node is None:
                continue
            members[nid] = node
            queue.extend(k["node"]["id"] for k in node["subSectors"]["edges"])
        if queue:
            raise SystemExit("Sector tree walk exceeded its bound; the tree is malformed.")
        return members

    def _builtin_target(self, key: str) -> str | None:
        if key in GENERIC_OT_TERMS:
            has_ics_root = any(r.casefold() == GENERIC_OT_TARGET.casefold() for r in self.cfg.extra_roots)
            return GENERIC_OT_TARGET if has_ics_root else None
        return ALIASES.get(key)

    def resolve(self, key: str) -> Sector | None:
        """Resolve a sector name, a config alias, a built-in alias, or a platform alias.

        Order: exact canonical name -> cfg.aliases target -> built-in ALIASES
        (generic OT terms only when an ICS extra_root exists) -> canonical
        sectors' x_opencti_aliases index -> None.
        """
        if not isinstance(key, str):
            raise TypeError("resolve: key must be a str")
        if not key:
            return None
        k = key.strip().casefold()
        canonical = self._by_name.get(k)
        if canonical is not None:
            return canonical
        # A configured alias always wins once matched, even onto a target
        # that is not canonical: that is a config error `doctor` reports
        # later, not a cue to keep trying other resolution mechanisms.
        if k in self._cfg_aliases:
            return self._by_name.get(self._cfg_aliases[k].casefold())
        builtin_target = self._builtin_target(k)
        if builtin_target is not None:
            resolved = self._by_name.get(builtin_target.casefold())
            if resolved is not None:
                return resolved
        return self._platform_aliases.get(k)

    def probes(self) -> list[str]:
        return self.names()[:3]
