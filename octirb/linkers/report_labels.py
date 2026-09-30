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

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .. import ledger, pipeline
from ..client import JsonDict, OpenCTIError

if TYPE_CHECKING:
    from ..client import Client
    from ..config import Config

Log = Callable[[str], None]
Save = Callable[[list[JsonDict]], None]


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


def _log_select(log: Log, counts: dict[str, int], selected: int) -> None:
    log(
        f"  selected {selected} report(s); skipped {counts['empty']} empty, {counts['old']} old, "
        f"{counts['excluded_source']} excluded source, {counts['excluded_title']} excluded title"
    )


def select(
    client: Client, cfg: Config, log: Log, *, limit: int | None, since: str | None
) -> list[JsonDict]:
    """Reports that contain at least one object, newest first.

    Unlike `pipeline.select`, a report with no text is kept -- labels need
    none -- and no text tier is planned. Source/title/since gates are the
    shared `pipeline.basic_skip`. Unlike other linkers, ignores
    `[selection].since_days` — no `since` means the whole corpus (the backfill);
    callers pass `since` for incremental runs.
    """
    if limit is not None and limit <= 0:
        raise ValueError("select: limit must be a positive int or None")
    sel = cfg.selection
    title_res = tuple(re.compile(p, re.IGNORECASE) for p in sel.exclude_title_patterns)
    counts = {"old": 0, "excluded_source": 0, "excluded_title": 0, "empty": 0}
    out: list[JsonDict] = []
    for node in client.reports():
        if pipeline.basic_skip(node, since=since, empty_only=False, sel=sel,
                               title_res=title_res, counts=counts):
            continue
        if not node["objects"]["edges"]:
            counts["empty"] += 1
            continue
        out.append({"report_id": str(node["id"]), "name": str(node.get("name") or ""),
                    "source": pipeline.source_name(node)})
        if limit and len(out) >= limit:
            break
    _log_select(log, counts, len(out))
    if limit and len(out) > limit:
        raise RuntimeError("select returned more reports than its limit")
    return out


def batch(client: Client, cfg: Config, selection: list[JsonDict], log: Log) -> list[JsonDict]:
    """Extractions for every selected report. A report that errors (deleted
    since select, page cap) is logged and skipped; the batch continues."""
    if not isinstance(selection, list):
        raise TypeError("batch: selection must be a list")
    index = build_sector_index(client.sector_parents())
    aliases = {k.casefold(): v for k, v in cfg.sectors.aliases.items()}
    out: list[JsonDict] = []
    for item in selection:
        rid = str(item["report_id"])
        try:
            report = client.report_label_sources(rid)
        except OpenCTIError as exc:
            log(f"  ! {rid}: {exc}"[:200])
            continue
        out.extend(labels_for(report, index, aliases, log))
    wanted = {str(s["report_id"]) for s in selection}
    if any(str(e["report_id"]) not in wanted for e in out):
        raise RuntimeError("batch emitted a label for a report outside the selection")
    return out


# ------------------------------------------------------------------- validate


def _problems(item: Any, selection_ids: set[str]) -> list[str]:
    if not isinstance(item, dict):
        return ["extraction is not a JSON object"]
    reasons: list[str] = []
    if str(item.get("report_id") or "") not in selection_ids:
        reasons.append("report_id is not in this run's selection")
    label = item.get("label")
    if not isinstance(label, str) or not label.strip():
        reasons.append("label is empty or not a string")
    src = item.get("from")
    if not isinstance(src, str) or src not in ledger.LABEL_SOURCES:
        reasons.append(f"from must be one of {sorted(ledger.LABEL_SOURCES)}")
    return reasons


def validate(raw: list[Any], selection_ids: set[str]) -> tuple[list[JsonDict], list[JsonDict]]:
    """Split extractions into (auto, review). Nothing here is a judgement call,
    so anything malformed is a hard fail and everything else auto-applies."""
    if not isinstance(raw, list):
        raise TypeError("validate: raw must be a list")
    auto: list[JsonDict] = []
    review: list[JsonDict] = []
    for item in raw:
        reasons = _problems(item, selection_ids)
        if not reasons:
            auto.append(item)
            continue
        held: JsonDict = dict(item) if isinstance(item, dict) else {"item": item}
        held["review_reasons"] = reasons
        held["hard_fail"] = True
        review.append(held)
    if len(auto) + len(review) != len(raw):
        raise RuntimeError("validate lost an extraction")
    return auto, review


# ---------------------------------------------------------------------- apply


@dataclass
class _LabelState:
    client: Client
    log: Log
    color: str
    dry_run: bool
    ids: dict[str, str] = field(default_factory=dict)  # casefolded value -> label id


def _label_id(state: _LabelState, label: str) -> str:
    """Reuse a platform label equal ignoring case; create one only if none."""
    key = label.casefold()
    if key not in state.ids:
        found = state.client.find_label(label)
        state.ids[key] = found if found is not None else state.client.ensure_label(label, state.color)
    if not state.ids[key]:
        raise OpenCTIError(f"no label id for {label!r}")
    return state.ids[key]


def _row(item: JsonDict, label_id: str | None, *, preexisted: bool) -> JsonDict:
    return ledger.label_row(
        report_id=str(item["report_id"]), label=str(item["label"]), label_id=label_id,
        source=str(item["from"]), source_entity=str(item.get("source_entity") or ""),
        preexisted=preexisted,
    )


def _apply_one(state: _LabelState, item: JsonDict, current: set[str]) -> JsonDict | None:
    """One label onto one report. None when the write failed (logged)."""
    rid, label = str(item["report_id"]), str(item["label"])
    if label.casefold() in current:
        state.log(f"  keep {label} on {rid} (pre-existed)")
        return _row(item, None, preexisted=True)
    if state.dry_run:
        state.log(f"  would label {rid}: {label}")
        return _row(item, None, preexisted=False)
    try:
        label_id = _label_id(state, label)
        state.client.add_label_to_report(rid, label_id)
    except OpenCTIError as exc:
        state.log(f"  ! label {rid} {label}: {exc}"[:200])
        return None
    current.add(label.casefold())
    return _row(item, label_id, preexisted=False)


def apply_labels(  # noqa: PLR0913 - client/items/log/color/dry_run/save, not a data clump
    client: Client, items: list[JsonDict], log: Log, *, color: str, dry_run: bool, save: Save,
) -> list[JsonDict]:
    """Add each item's label to its report; one ledger row per item handled.

    Each report's labels are re-read right before writing, so a label that
    appeared since `batch` is ledgered preexisted and never claimed. `save`
    checkpoints after every successful write.
    """
    if not isinstance(items, list):
        raise TypeError("apply_labels: items must be a list")
    state = _LabelState(client=client, log=log, color=color, dry_run=dry_run)
    by_report: dict[str, list[JsonDict]] = {}
    for item in items:
        by_report.setdefault(str(item["report_id"]), []).append(item)
    rows: list[JsonDict] = []
    for rid, group in by_report.items():
        try:
            current = {v.casefold() for v in client.entity_labels(rid)}
        except OpenCTIError as exc:
            log(f"  ! {rid}: {exc}"[:200])
            continue
        for item in group:
            row = _apply_one(state, item, current)
            if row is None:
                continue
            rows.append(row)
            if not dry_run and not row["preexisted"]:
                save(rows)
    if len(rows) > len(items):
        raise RuntimeError("apply_labels produced more rows than items")
    return rows


# --------------------------------------------------------------------- revert


def revert_labels(
    client: Client, rows: list[JsonDict], log: Log, *, dry_run: bool = False,
    retain: list[JsonDict] | None = None,
) -> int:
    """Undo `apply_labels`' `"label"` rows. Preexisted rows are left alone; a
    removal that raises is appended to `retain` so the caller keeps it in the
    ledger for a retry. Label objects themselves are never deleted."""
    if not isinstance(rows, list):
        raise TypeError("revert_labels: rows must be a list")
    failed = retain if retain is not None else []
    reverted = 0
    for row in rows:
        if row.get("kind") != "label":
            continue
        rid, label = str(row.get("report_id") or ""), str(row.get("label") or "")
        if row.get("preexisted"):
            log(f"  keep {label} on {rid} (pre-existed)")
            continue
        label_id = str(row.get("label_id") or "")
        if not rid or not label_id:
            raise OpenCTIError(f"label row has no report/label id: {str(row)[:160]}")
        if dry_run:
            log(f"  would remove label {label} from {rid}")
            reverted += 1
            continue
        try:
            client.remove_label_from_report(rid, label_id)
        except OpenCTIError as exc:
            log(f"  ! revert label {rid} {label}: {exc}"[:200])
            failed.append(row)
            continue
        reverted += 1
    if reverted > len(rows):
        raise RuntimeError("revert_labels reverted more rows than it was given")
    return reverted
