"""Write, ledger and revert actor-target relationships.

Relationships upsert: creating one identical to an existing relationship
merges into it. So apply checks first and records `preexisted`, and revert
never deletes a relationship this linker did not create.

Ported from `opencti-docker/octirel/writer.py` whole (`WriterClient`,
`ApplyContext`, `_add_to_reports`, `_apply_one`, `apply_items`,
`decide_reverts`, `revert`), with:
- ledger rows via `octirb.ledger.relationship_row` -- the local
  `ledger_row`/`ledger_key` pair, and `merge_ledger`/`_merge_pair`/
  `_collapse_same_key`, now live in `octirb/ledger.py` (Task 5); this module
  no longer defines any of them.
- `should_delete` -> `octirb.ledger.should_delete_relationship`, with the
  label used in its "adopted" reason string (and in `decide_reverts`'
  "labelled" check) supplied by the caller as `ApplyContext.label`
  (`cfg.label("Relationship")`) instead of the old module constant
  `REL_LABEL`.
- `REPORT_SOURCES = frozenset({"report"})` -- the old `{"prose", "ledger"}`
  shrinks to one value: this linker no longer has a ledger source, and an
  actor's own platform description ("description"-sourced items) was never
  tied to a report either, so only report-text-sourced items get linked
  into the report they came from.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from . import ledger
from .client import JsonDict
from .linkers.actor_target import CONFIDENCE_SCORE

Log = Callable[[str], None]
DRY_RUN_ID = "(dry-run)"
REPORT_SOURCES = frozenset({"report"})


class WriterClient(Protocol):
    def find_relationships(self, from_id: str, to_id: str, rel_type: str) -> list[str]: ...
    def create_relationship(  # noqa: PLR0913,PLR0917 - mirrors Client.create_relationship
        self, from_id: str, to_id: str, rel_type: str, confidence: int,
        description: str, label_id: str) -> str: ...
    def add_object_to_report(self, report_id: str, object_id: str) -> None: ...
    def remove_object_from_report(self, report_id: str, object_id: str) -> None: ...
    def relationship_state(self, rel_id: str) -> tuple[bool, list[str]]: ...
    def delete_relationship(self, rel_id: str) -> None: ...


@dataclass(frozen=True)
class ApplyContext:
    """Everything one apply/revert run threads through.

    `label` is the label VALUE (e.g. "AI-Relationship", from
    `cfg.label("Relationship")`) that `decide_reverts` compares against a
    relationship's `objectLabel` to decide ours-vs-adopted; `label_id` is
    that label's platform id, attached via `create_relationship`'s
    `objectLabel` input when a relationship is created. `ours` is apply-only
    bookkeeping (relationship ids this run has already written, so a second
    item for the same key is recognised as "ours" instead of re-created);
    `revert` reuses this same context for `label`/`log`/`dry_run` but never
    reads `ours` -- it derives ownership from each row's `preexisted` flag.
    """

    label_id: str
    label: str
    ours: dict[str, list[str]]
    dry_run: bool
    log: Log


def _add_to_reports(  # noqa: PLR0913,PLR0917 - checkpoint progress needs its own callback
    client: WriterClient, item: JsonDict, rid: str, already: list[str],
    ctx: ApplyContext, on_progress: Callable[[list[str]], None] | None = None,
) -> list[str]:
    if not rid:
        raise ValueError("_add_to_reports needs a relationship id")
    if item["source"] not in REPORT_SOURCES:
        return list(already)
    in_reports = list(already)
    for report_id in item["source_refs"]:
        if report_id not in in_reports:
            if not ctx.dry_run:
                client.add_object_to_report(report_id, rid)
            in_reports.append(report_id)
            if on_progress is not None:
                on_progress(list(in_reports))
    if len(in_reports) < len(already):
        raise RuntimeError("_add_to_reports must never drop a prior report ref")
    return in_reports


def _apply_one(
    client: WriterClient, item: JsonDict, ctx: ApplyContext, checkpoint: Callable[[JsonDict], None]
) -> JsonDict:
    """Write one item. `checkpoint` is called with a ledger row reflecting
    partial progress (right after create, and after each report ref is
    added) so a failure mid-item still leaves a saved ledger that matches
    what the platform holds -- see apply_items."""
    if not (item.get("actor_id") and item.get("target_id") and item.get("relationship_type")):
        raise ValueError("item is missing actor_id, target_id or relationship_type")
    # Relationships upsert on this platform: a feed writing an identical
    # relationship in the window between this find and the create below
    # would be merged into it and recorded here as ours. That window is
    # accepted and narrow.
    existing = client.find_relationships(item["actor_id"], item["target_id"], item["relationship_type"])
    ours = next((rid for rid in existing if rid in ctx.ours), None)
    label = f"{item['actor']} -{item['relationship_type']}-> {item['target_name']}"
    if ours is not None:
        def on_progress(current_reports: list[str]) -> None:
            checkpoint(ledger.relationship_row(item, relationship_id=ours, preexisted=False,
                                               in_reports=current_reports, label_id=ctx.label_id,
                                               status="ours"))
        in_reports = _add_to_reports(client, item, ours, ctx.ours[ours], ctx, on_progress)
        ctx.ours[ours] = list(in_reports)
        ctx.log(f"  = {label} (ours, already written)")
        row = ledger.relationship_row(item, relationship_id=ours, preexisted=False,
                                      in_reports=in_reports, label_id=ctx.label_id, status="ours")
    elif existing:
        ctx.log(f"  = {label} (pre-existing; left untouched)")
        row = ledger.relationship_row(item, relationship_id=existing[0], preexisted=True,
                                      in_reports=[], label_id=ctx.label_id, status="preexisting")
    else:
        rid = DRY_RUN_ID
        if not ctx.dry_run:
            rid = client.create_relationship(
                item["actor_id"], item["target_id"], item["relationship_type"],
                CONFIDENCE_SCORE[item["confidence"]],
                f"\"{item['evidence']}\" — octi-rel, source: {item['source']}", ctx.label_id)
            checkpoint(ledger.relationship_row(item, relationship_id=rid, preexisted=False,
                                               in_reports=[], label_id=ctx.label_id, status="created"))
            ctx.ours[rid] = []

        def on_progress(current_reports: list[str]) -> None:
            checkpoint(ledger.relationship_row(item, relationship_id=rid, preexisted=False,
                                               in_reports=current_reports, label_id=ctx.label_id,
                                               status="created"))
        in_reports = _add_to_reports(client, item, rid, [], ctx, on_progress)
        if not ctx.dry_run:
            ctx.ours[rid] = list(in_reports)
        ctx.log(f"  + {label}")
        row = ledger.relationship_row(item, relationship_id=rid, preexisted=False,
                                      in_reports=in_reports, label_id=ctx.label_id, status="created")
    if not row.get("relationship_id"):
        raise RuntimeError("_apply_one produced a row without a relationship id")
    return row


def apply_items(client: WriterClient, items: list[JsonDict], ctx: ApplyContext,
                save: Callable[[list[JsonDict]], None]) -> list[JsonDict]:
    """Write each item; checkpoint after create and after each report ref
    is added, and save the completed ledger after every item, so a mid-item
    failure (create succeeds, a later add_object_to_report raises) still
    leaves a saved ledger that matches the platform instead of orphaning
    the relationship it just created."""
    if not isinstance(items, list):
        raise TypeError("items must be a list")
    rows: list[JsonDict] = []

    def checkpoint(partial_row: JsonDict) -> None:
        if not ctx.dry_run:
            save([*rows, partial_row])

    for item in items:
        rows.append(_apply_one(client, item, ctx, checkpoint))
        if not ctx.dry_run:
            save(rows)
    if len(rows) != len(items):
        raise RuntimeError("apply produced a different number of rows than items")
    return rows


def decide_reverts(
    client: WriterClient, rows: list[JsonDict], label: str
) -> list[tuple[JsonDict, bool, str, bool]]:
    """Read-only. The dry run and the real run both act on exactly this.

    The fourth element, `exists`, is exposed separately from the delete
    decision so `revert` can strip this run's own report refs from every
    row whose relationship is still on the platform -- including a kept,
    adopted row -- not only the ones that go on to be deleted.
    """
    if not isinstance(rows, list):
        raise TypeError("rows must be a list")
    if not label:
        raise ValueError("decide_reverts needs a non-empty label")
    decisions: list[tuple[JsonDict, bool, str, bool]] = []
    for row in rows:
        if row["preexisted"]:
            decision = ledger.should_delete_relationship(
                preexisted=True, exists=True, labelled=False, label=label)
            decisions.append((row, *decision, True))
            continue
        exists, labels = client.relationship_state(str(row["relationship_id"]))
        decision = ledger.should_delete_relationship(
            preexisted=False, exists=exists, labelled=label in labels, label=label)
        decisions.append((row, *decision, exists))
    if len(decisions) != len(rows):
        raise RuntimeError("decide_reverts lost track of a row")
    return decisions


def revert(client: WriterClient, rows: list[JsonDict], ctx: ApplyContext) -> tuple[int, int]:
    """Order: remove every owned row's report objectRefs first -- including
    a row kept as adopted (label removed) -- then decide deletions. A row
    we never owned (preexisted) or whose relationship is already gone is
    skipped for ref removal; there is nothing there to strip. `ctx.dry_run`
    runs the identical read-only decision pass but performs neither step, so
    the preview matches what a real run will do without mutating anything.
    """
    if not isinstance(rows, list):
        raise TypeError("rows must be a list")
    decisions = decide_reverts(client, rows, ctx.label)
    if not ctx.dry_run:
        for row, _delete, _why, exists in decisions:
            if row["preexisted"] or not exists:
                continue
            rid = str(row["relationship_id"])
            for report_id in row["in_reports"]:
                client.remove_object_from_report(report_id, rid)
    deleted = kept = 0
    for row, delete, why, _exists in decisions:
        rid = str(row["relationship_id"])
        name = f"{row['actor']} -{row['relationship_type']}-> {row['target_name']}"
        if not delete:
            kept += 1
            ctx.log(f"  keep {name}: {why}")
            continue
        if not ctx.dry_run:
            client.delete_relationship(rid)
        deleted += 1
        ctx.log(f"  {'would delete' if ctx.dry_run else 'deleted'} {name}")
    if deleted + kept != len(rows):
        raise RuntimeError("revert lost track of a row")
    return deleted, kept
