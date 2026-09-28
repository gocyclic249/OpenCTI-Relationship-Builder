"""Relationship schema, candidate validation, extraction contracts, and
selection sources for the actor-target relationship linker.

Ports (single module, per Task 13 brief):
- `opencti-docker/octirel/schema.py`: `ORIGIN_TYPE`, `TARGET_TYPE`,
  `EXPECTED`, `concrete_type`, `Schema` -- unchanged apart from
  `RelClient` -> `Client`.
- `opencti-docker/octirel/validate.py`: `Context`, `collapse`, `validate`,
  `CONFIDENCE_SCORE`, with `SOURCES = frozenset({"description", "report"})`
  (the ledger source is gone -- see below) and sector canonicalisation
  removed from `_check_target`: resolution and aliasing now happen
  entirely inside the target-kind's own resolver (for sectors,
  `resolvers.sectors.SectorVocabulary.resolve`, which already folds in
  platform `x_opencti_aliases`, `cfg.sectors.aliases` and a small built-in
  alias table). `octirel/sectormap.py` and its "Government & Defense is
  not a value" special case are therefore dropped rather than ported.
- `opencti-docker/octirel/contracts.py`: `render`, with `INTRO`/`REF_RULE`/
  `EXTRA_TRAPS` keyed `"description"`/`"report"` (the old `"prose"` text
  becomes `"report"`'s; `"ledger"` had no contract and stays dropped), and
  sector names taken directly from the canonical vocabulary's `names()` --
  no `PREFERRED`/`UNINFORMATIVE`/`AMBIGUOUS` filtering, since that lived in
  `sectormap.py`. Callers are expected to pass an already-canonical
  `sector_names` list (e.g. `SectorVocabulary.names()`), not a raw mix of
  names and aliases.

New (octi-rb design -- no ledger source): `opencti-docker/octirel/sources.py`
read octi-geo's own applied ledger (`join_ledgers`) as a third relationship
source. octi-rb folds that information into the containment linkers
(`report-actor`/`report-location`/`report-sector`) directly instead of
re-deriving it here, so this linker has only two selection sources:
- `select_description`: one packet per actor with a platform description.
- `select_report`: one packet per report with cached text and >=1 actor,
  reading only `runstore.TextCache` and `Client.report_actors` -- never an
  article fetch (`ask_enrichment`/`wait_for_file`/`download` are never
  called here).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ..client import Client, JsonDict
from ..config import Config
from ..runstore import TextCache

# ---------------------------------------------------------------------------
# relationship schema (ported octirel/schema.py, unchanged)
# ---------------------------------------------------------------------------

# "origin" is contract vocabulary; the concrete type depends on the subject.
ORIGIN_TYPE = {"Intrusion-Set": "originates-from", "Threat-Actor-Group": "located-at"}
TARGET_TYPE = {"country": "Country", "region": "Region", "sector": "Sector"}

EXPECTED: list[tuple[str, str, str]] = [
    ("Intrusion-Set", "Country", "originates-from"),
    ("Intrusion-Set", "Region", "originates-from"),
    ("Intrusion-Set", "Country", "targets"),
    ("Intrusion-Set", "Region", "targets"),
    ("Intrusion-Set", "Sector", "targets"),
    ("Threat-Actor-Group", "Country", "located-at"),
    ("Threat-Actor-Group", "Region", "located-at"),
    ("Threat-Actor-Group", "Country", "targets"),
    ("Threat-Actor-Group", "Region", "targets"),
    ("Threat-Actor-Group", "Sector", "targets"),
]


def concrete_type(relationship: str, actor_type: str) -> str | None:
    if actor_type not in ORIGIN_TYPE:
        return None
    if relationship == "targets":
        return "targets"
    if relationship == "origin":
        return ORIGIN_TYPE[actor_type]
    return None


class Schema:
    def __init__(self, mapping: dict[str, frozenset[str]]):
        if not isinstance(mapping, dict):
            raise TypeError("mapping must be a dict")
        self._mapping = mapping

    @classmethod
    def load(cls, client: Client) -> Schema:
        if client is None or not hasattr(client, "relation_schema"):
            raise TypeError("client must not be None and must have a relation_schema method")
        schema = cls(client.relation_schema())
        if not schema._mapping:
            raise SystemExit("The platform returned an empty relationship schema.")
        return schema

    def allows(self, from_type: str, to_type: str, rel_type: str) -> bool:
        if not (from_type and to_type and rel_type):
            return False
        return rel_type in self._mapping.get(f"{from_type}_{to_type}", frozenset())

    def missing(self, expected: list[tuple[str, str, str]]) -> list[str]:
        if not isinstance(expected, list):
            raise TypeError("expected must be a list")
        result = [f"{f}_{t}:{r}" for f, t, r in expected if not self.allows(f, t, r)]
        if result and not all(":" in entry for entry in result):
            raise RuntimeError("missing() returned entries without ':' separator")
        return result


# ---------------------------------------------------------------------------
# candidate validation (ported octirel/validate.py)
# ---------------------------------------------------------------------------

CONFIDENCE_SCORE = {"high": 85, "medium": 50, "low": 15}
RANK = {"low": 0, "medium": 1, "high": 2}
AUTO_CONFIDENCE = "high"
RELATIONSHIPS = frozenset({"origin", "targets"})
# The octirel ledger source is gone (see module docstring): octi-rb folds
# that information into the containment linkers instead of re-deriving it
# here, so a relationship candidate can only come from an actor's own
# platform description or a report's own text.
SOURCES = frozenset({"description", "report"})
ENUMS: tuple[tuple[str, frozenset[str]], ...] = (
    ("relationship", RELATIONSHIPS),
    ("target_kind", frozenset(TARGET_TYPE)),
    ("confidence", frozenset(CONFIDENCE_SCORE)),
    ("source", SOURCES),
)


class Named(Protocol):
    @property
    def id(self) -> str: ...
    @property
    def name(self) -> str: ...


class TargetResolver(Protocol):
    def resolve(self, key: str) -> Named | None: ...


@dataclass(frozen=True)
class ActorRef:
    id: str
    name: str
    entity_type: str


@dataclass(frozen=True)
class Context:
    actors: dict[str, ActorRef]
    targets: dict[str, TargetResolver]
    schema: Schema
    selection: dict[str, frozenset[str]]


def _check_enums(item: JsonDict) -> list[str]:
    """Normalise (strip/lower) only values that turn out valid. An invalid
    value is left exactly as the reader wrote it, so review.json shows
    what was actually submitted instead of a normalised string that never
    validated."""
    reasons: list[str] = []
    for field, allowed in ENUMS:
        value = str(item.get(field) or "").strip().lower()
        if value not in allowed:
            reasons.append(f"invalid {field} {item.get(field)!r}")
            continue
        item[field] = value
    if not str(item.get("evidence") or "").strip():
        reasons.append("missing evidence quote")
    return reasons


def _check_scope(item: JsonDict, ctx: Context) -> list[str]:
    ref = str(item.get("source_ref") or "")
    actor_id = str(item.get("actor_id") or "")
    if ref not in ctx.selection:
        return [f"source_ref {ref!r} is not in this run's selection"]
    if actor_id not in ctx.selection[ref]:
        return [f"actor {actor_id!r} is not in source_ref {ref!r}"]
    return []


def _check_actor(item: JsonDict, ctx: Context) -> list[str]:
    actor = ctx.actors.get(str(item.get("actor_id") or ""))
    if actor is None:
        return [f"unknown actor id {item.get('actor_id')!r}"]
    item["actor"] = actor.name
    item["actor_type"] = actor.entity_type
    return []


def _check_target(item: JsonDict, ctx: Context) -> list[str]:
    """Resolve `item["target"]` through the target-kind's own resolver.

    Sector canonicalisation used to happen here (`sectormap.canonical`,
    including a special-cased rejection of "Government & Defense"); that
    module is gone. The equivalent aliasing now lives entirely inside
    whichever resolver a sector-kind `ctx.targets["sector"]` entry is built
    from (`resolvers.sectors.SectorVocabulary.resolve`), so this function no
    longer needs to know sectors are special -- every target kind resolves
    the same way.
    """
    kind = item["target_kind"]
    key = item.get("target")
    if not isinstance(key, str) or not key.strip():
        return ["missing target"]
    resolver = ctx.targets.get(kind)
    if resolver is None:
        return [f"no resolver for target kind {kind!r}"]
    resolved = resolver.resolve(key)
    if resolved is None:
        return [f"unresolved {kind} {item.get('target')!r}"]
    item["target_id"] = resolved.id
    item["target_name"] = resolved.name
    return []


def _check_type(item: JsonDict, ctx: Context) -> list[str]:
    if item["relationship"] == "origin" and item["target_kind"] == "sector":
        return ["an origin cannot point at a sector"]
    rel_type = concrete_type(item["relationship"], item["actor_type"])
    to_type = TARGET_TYPE[item["target_kind"]]
    if rel_type is None or not ctx.schema.allows(item["actor_type"], to_type, rel_type):
        return [f"schema does not allow {item['actor_type']} -{item['relationship']}-> {to_type}"]
    item["relationship_type"] = rel_type
    return []


def _is_valid(item: JsonDict, field: str, allowed: frozenset[str]) -> bool:
    value = item.get(field)
    return isinstance(value, str) and value in allowed


def _reasons(item: JsonDict, ctx: Context) -> list[str]:
    """Every defect an item has. Later checks need earlier ones to have passed."""
    reasons = _check_enums(item) + _check_scope(item, ctx)
    actor_reasons = _check_actor(item, ctx)
    reasons += actor_reasons
    # _check_enums leaves an invalid value exactly as the reader wrote it, and
    # that may be a list or dict. `in` on a dict/frozenset hashes its operand,
    # so test the type first or one malformed candidate aborts the whole run.
    if _is_valid(item, "target_kind", frozenset(TARGET_TYPE)):
        target_reasons = _check_target(item, ctx)
        reasons += target_reasons
        if not actor_reasons and not target_reasons and _is_valid(item, "relationship", RELATIONSHIPS):
            reasons += _check_type(item, ctx)
    return reasons


def _hold(review: list[JsonDict], item: JsonDict, reasons: list[str], *, hard: bool) -> None:
    item["review_reasons"] = reasons
    item["hard_fail"] = hard
    review.append(item)


def collapse(items: list[JsonDict]) -> list[JsonDict]:
    """One item per (actor, type, target). Highest confidence wins; ties keep the first.

    The survivor's source_refs is the ordered union of every contributor's.
    """
    if not isinstance(items, list):
        raise TypeError("items must be a list")
    kept: dict[tuple[str, str, str], JsonDict] = {}
    for item in items:
        key = (str(item["actor_id"]), str(item["relationship_type"]), str(item["target_id"]))
        refs = list(item.get("source_refs") or [])
        current = kept.get(key)
        if current is None:
            kept[key] = dict(item, source_refs=refs)
            continue
        merged = list(dict.fromkeys([*current["source_refs"], *refs]))
        if RANK[str(item["confidence"])] > RANK[str(current["confidence"])]:
            current = dict(item)
        current["source_refs"] = merged
        kept[key] = current
    return list(kept.values())


def validate(candidates: list[Any], ctx: Context) -> tuple[list[JsonDict], list[JsonDict]]:
    if not isinstance(candidates, list):
        raise TypeError("candidates must be a JSON array")
    valid: list[JsonDict] = []
    review: list[JsonDict] = []
    for raw in candidates:
        if not isinstance(raw, dict):
            _hold(review, {"raw": raw}, ["candidate is not a JSON object"], hard=True)
            continue
        item = dict(raw)
        reasons = _reasons(item, ctx)
        if reasons:
            _hold(review, item, reasons, hard=True)
            continue
        item["source_refs"] = [str(item["source_ref"])]
        valid.append(item)
    auto: list[JsonDict] = []
    for item in collapse(valid):
        if item["confidence"] == AUTO_CONFIDENCE:
            auto.append(item)
        else:
            _hold(review, item, [f"confidence={item['confidence']}"], hard=False)
    if len(auto) + len(review) > len(candidates):
        raise RuntimeError("validate produced more items than it was given")
    return auto, review


# ---------------------------------------------------------------------------
# extraction contracts (ported octirel/contracts.py)
# ---------------------------------------------------------------------------

INTRO = {
    "description": (
        "Each packet is ONE threat actor (an Intrusion Set or Threat-Actor-Group) and\n"
        "its platform description. List where the actor operates from and what it targets."
    ),
    "report": (
        "Each packet is ONE report's article text plus the actors the report contains.\n"
        "List, for those actors only, where they operate from and what they target."
    ),
}

REF_RULE = {
    "description": "source_ref is the packet's actor_id; actor_id must be that same id.",
    "report": "source_ref is the packet's report_id; actor_id must be one of that packet's actors.",
}

EXTRA_TRAPS = {
    "description": (
        "  - Markdown citation links name OTHER groups. In\n"
        "    [Sandworm Team](https://attack.mitre.org/groups/G0034) only statements\n"
        "    about the packet's own actor count."
    ),
    "report": (
        "  - The reporting vendor (Mandiant, GTIG, Kaspersky, CISA ...) is not an actor.\n"
        "  - An actor mentioned only in passing yields no relationships.\n"
        "  - A report names several actors, so evidence must carry BOTH quotes from\n"
        "    the same passage, joined \" | \": the quote naming the actor, then the\n"
        "    quote naming the target, e.g.\n"
        "    \"APT29 has been attributed to the SVR | targeting ministries in Ukraine\".\n"
        "    Both halves must be about the same actor. If the target sentence is\n"
        "    about a different actor than the one named, emit nothing for it."
    ),
}

BODY = """{intro}

Return a JSON array. One object per (actor, relationship, target):

  {{
    "actor_id":    "<copied verbatim from the packet>",
    "actor":       "<actor name, for the audit trail>",
    "relationship":"origin" | "targets",
    "target_kind": "country" | "region" | "sector",
    "target":      "<ISO3 code | exact region name | exact sector name>",
    "confidence":  "high" | "medium" | "low",
    "evidence":    "<short verbatim quote from the packet>",
    "source":      "{source}",
    "source_ref":  "<see below>"
  }}

  {ref_rule}

  - origin = the country or region the actor operates from or for (its sponsor
    or base). Never where its infrastructure happens to be hosted. An origin
    never points at a sector.
  - targets = a country, region or sector the text says the actor attacked or
    set out to attack.
  - Countries are ISO 3166-1 alpha-3 codes (RUS, PRK, CHN), never names.
  - Tag the NARROWEST sector that fits; parent sectors propagate by part-of.
  - Name a region only when the text names a region rather than countries.

Traps, all present in this corpus:
  - Hedged attribution is not high. "Suspected", "assessed with moderate
    confidence", "possibly linked to" -> medium or low. "Attributed to
    Russia's General Staff Main Intelligence Directorate" -> high origin RUS.
  - Comparisons yield nothing: "overlaps with APT28", "similar to Lazarus".
  - Targets must be STATED targets. "Has targeted government and energy
    organisations in Ukraine" -> targets UKR, targets "Government and
    administrations", targets "Energy". A case-study victim list, or "the
    malware runs on Windows servers", -> nothing.
  - "Government & Defense" is not a value: emit "Government and
    administrations" and/or "Defense" as the text states.
{extra}

Sector names (closed vocabulary, exact strings):
{sectors}

Region names (exact strings):
{regions}

Rules:
  - evidence must be a real quote from the packet, not a paraphrase.
  - confidence "high" only when the text states it plainly. Anything inferred,
    hedged or ambiguous is "medium" or "low" -- those go to a review queue.
  - A packet with nothing genuine gets no entries. Empty is the right answer
    more often than not.
"""


def _bullets(names: list[str]) -> str:
    return "\n".join(f"    - {n}" for n in names)


def render(source: str, sector_names: list[str], region_names: list[str]) -> str:
    if source not in INTRO:
        raise ValueError(f"no contract for source {source!r}")
    if not sector_names or not region_names:
        raise ValueError("contract needs both vocabularies")
    text = BODY.format(
        intro=INTRO[source], source=source, ref_rule=REF_RULE[source],
        extra=EXTRA_TRAPS[source], sectors=_bullets(sorted(sector_names)),
        regions=_bullets(sorted(region_names)),
    )
    if '"source_ref"' not in text:
        raise RuntimeError("rendered contract lost its field list")
    return text


# ---------------------------------------------------------------------------
# selection sources (new; packet shapes port octirel/sources.py's
# description_packets/prose_packets, minus the octi-geo-ledger source)
# ---------------------------------------------------------------------------


def select_description(client: Client, limit: int | None) -> list[JsonDict]:
    """One packet per actor with a non-empty platform description.

    Ports `octirel/sources.py`'s `description_packets`, folding in the
    `client.actors()` read it used to take pre-fetched (octi-rb's actor
    linkers each fetch their own actor list rather than sharing a module
    that fetches once, matching the rest of this codebase's `select_*`
    functions).
    """
    if limit is not None and limit < 1:
        raise ValueError("select_description: limit must be a positive int or None")
    actors = client.actors()
    if not isinstance(actors, list):
        raise TypeError("select_description: client.actors() must return a list")
    packets = [
        {
            "source": "description", "source_ref": str(a["id"]), "actor_id": str(a["id"]),
            "actor": str(a["name"]), "entity_type": str(a["entity_type"]),
            "text": str(a.get("description") or ""),
        }
        for a in sorted(actors, key=lambda a: str(a["name"]).casefold())
        if str(a.get("description") or "").strip()
    ]
    result = packets[:limit] if limit else packets
    if limit and len(result) > limit:
        raise RuntimeError(f"select_description: result length {len(result)} exceeds limit {limit}")
    return result


def select_report(client: Client, cache: TextCache, cfg: Config, limit: int | None) -> list[JsonDict]:
    """One packet per report that has cached text AND >=1 actor.

    Cache-only by design: this reads `cache.text_dir` (already-materialized
    article text, written by an earlier `select`/`materialize_text` step)
    and `client.report_actors` (a platform read of a report's existing
    object refs). It never calls `ask_enrichment`/`wait_for_file`/
    `download` -- a report whose text octi-rb has not already captured
    simply yields no packet, rather than triggering a fresh connector run.
    `cfg` is accepted (and validated) for interface symmetry with the
    linker's other config-driven selectors; nothing here is config-tuned yet.
    """
    if not isinstance(cache, TextCache):
        raise TypeError("select_report: cache must be a TextCache")
    if not isinstance(cfg, Config):
        raise TypeError("select_report: cfg must be a Config")
    if limit is not None and limit < 1:
        raise ValueError("select_report: limit must be a positive int or None")
    report_ids = sorted(p.stem for p in cache.text_dir.glob("*.txt"))
    packets: list[JsonDict] = []
    for report_id in report_ids:
        if limit and len(packets) >= limit:
            break
        info = client.report_actors(report_id)
        if not info or not info.get("actors"):
            continue
        text = cache.read(report_id)
        if not text:
            continue
        packets.append({
            "source": "report", "source_ref": report_id,
            "title": info["title"], "actors": info["actors"], "text": text,
        })
    if limit and len(packets) > limit:
        raise RuntimeError(f"select_report: result length {len(packets)} exceeds limit {limit}")
    return packets
