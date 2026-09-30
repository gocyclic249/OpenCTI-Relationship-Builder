"""report-labels: plain value labels mirroring a report's countries and top-level sectors.

Every Country a report contains becomes a label of the same name; every
Sector it contains is walked up its parent sectors to each top-level root,
and each root's name becomes a label. These labels carry no `[labels].prefix`:
the `AI-*` labels record *how* octi-rb processed a report, these record *what
it is about*, for UI filtering and dashboards.

Deterministic, like report-vuln: `batch` writes extractions.json directly and
every extraction is confidence high. It drives from everything a report
contains, whoever added it, so it also backfills reports no other linker
touched. Add-only: nothing here removes a label except `revert_labels`, and
only labels its own run added.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..client import JsonDict

Log = Callable[[str], None]


@dataclass(frozen=True)
class SectorNode:
    id: str
    name: str
    parent_ids: tuple[str, ...]


def build_sector_index(nodes: list[JsonDict]) -> dict[str, SectorNode]:
    """`client.sector_parents()` rows -> {id: SectorNode}."""
    if not isinstance(nodes, list):
        raise TypeError("build_sector_index: nodes must be a list")
    index = {
        str(n["id"]): SectorNode(str(n["id"]), str(n["name"]), tuple(str(p) for p in n["parent_ids"]))
        for n in nodes
    }
    if len(index) > len(nodes):
        raise RuntimeError("build_sector_index invented a sector")
    return index


def sector_roots(index: dict[str, SectorNode], sector_id: str) -> list[str]:
    """Names of every top-level root above `sector_id`, sorted.

    Walks by id: same-named duplicate sectors from different authors exist.
    A sector with no parent in `index` -- none at all, or only parents this
    token cannot see -- is its own root. Dual-parented sectors yield every
    root. Raises ValueError for an unknown id, or when no root is reachable
    (a parent cycle).
    """
    if sector_id not in index:
        raise ValueError(f"sector {sector_id!r} is not on the platform")
    roots: set[str] = set()
    seen: set[str] = set()
    stack = [sector_id]
    # Bounded: each node expands once, so pushes total at most n*n.
    for _ in range(len(index) * len(index) + 1):
        if not stack:
            break
        node = index[stack.pop()]
        if node.id in seen:
            continue
        seen.add(node.id)
        parents = [p for p in node.parent_ids if p in index]
        if parents:
            stack.extend(parents)
        else:
            roots.add(node.name)
    if stack:
        raise ValueError(f"sector walk from {sector_id!r} exceeded its bound")
    if not roots:
        raise ValueError(f"no top-level sector above {sector_id!r} (parent cycle?)")
    return sorted(roots)


def start_ids(index: dict[str, SectorNode], sector_id: str, aliases: dict[str, str]) -> list[str]:
    """Where the root walk starts: the sector itself or, when its name is a
    `[sectors].aliases` key (keys casefolded), every sector named as the alias
    target -- duplicates share a name, so all of them."""
    if sector_id not in index:
        raise ValueError(f"sector {sector_id!r} is not on the platform")
    target = aliases.get(index[sector_id].name.casefold())
    if target is None:
        return [sector_id]
    ids = [n.id for n in index.values() if n.name.casefold() == target.casefold()]
    if not ids:
        raise ValueError(f"alias target {target!r} is not on the platform")
    return ids


def _extraction(report: JsonDict, label: str, source: str, entity: str) -> JsonDict:
    return {
        "report_id": str(report["id"]), "report_name": str(report.get("name") or ""),
        "label": label, "from": source, "source_entity": entity, "confidence": "high",
    }


def _sector_labels(
    report: JsonDict, index: dict[str, SectorNode], aliases: dict[str, str], log: Log
) -> list[tuple[str, str]]:
    """(root name, contained sector name) per contained sector. A sector whose
    walk fails is logged and contributes nothing -- the report's other labels
    still apply."""
    pairs: list[tuple[str, str]] = []
    for sector in report["sectors"]:
        sid, name = str(sector["id"]), str(sector["name"])
        try:
            roots = {r for start in start_ids(index, sid, aliases) for r in sector_roots(index, start)}
        except ValueError as exc:
            log(f"  ! {report['id']} sector {name} ({sid}): {exc}"[:200])
            continue
        pairs.extend((root, name) for root in sorted(roots))
    return pairs


def labels_for(
    report: JsonDict, index: dict[str, SectorNode], aliases: dict[str, str], log: Log
) -> list[JsonDict]:
    """One extraction per label `report` should carry but does not.

    `report` is `client.report_label_sources()`'s shape. Existing labels and
    duplicates compare casefolded: the platform keeps label case, and `China`
    must not gain a sibling `china`.
    """
    if not isinstance(report, dict) or "id" not in report:
        raise TypeError("labels_for: report must be a report_label_sources() dict")
    have = {str(v).casefold() for v in report["labels"]}
    candidates = [(str(c["name"]), "country", str(c["name"])) for c in report["countries"]]
    candidates += [(root, "sector", name) for root, name in _sector_labels(report, index, aliases, log)]
    out: list[JsonDict] = []
    for label, source, entity in candidates:
        if not label or label.casefold() in have:
            continue
        have.add(label.casefold())
        out.append(_extraction(report, label, source, entity))
    if len({str(e["label"]).casefold() for e in out}) != len(out):
        raise RuntimeError("labels_for emitted a duplicate label")
    return out
