"""One typed ledger: containment, relationship, alias and entity rows.

octi-rb used to be two separate pipelines (octigeo: report containment;
octirel: actor relationships) each with its own ledger file and its own
merge/delete rules. This folds both into one ledger of `"kind"`-tagged
rows so a single run can record containment and relationship work side by
side, and a single `merge_ledger` walks the whole thing.

Ports:
- opencti-docker/octirel/writer.py: `ledger_key` (the relationship branch
  of `row_key`), `ledger_row` (-> `relationship_row`), `_collapse_same_key`,
  `merge_ledger` (the relationship-kind half), `_merge_pair`, `should_delete`
  (-> `should_delete_relationship`).
- opencti-docker/octigeo/pipeline.py: `should_delete` (-> `should_delete_entity`,
  rename only) and the dedupe-first-wins shape of its `merge_ledger`, now
  generalised to containment/alias/entity rows via `row_key`.

octigeo's `_ledger_entity` legacy `country_id`/`country_name` fallback is
deliberately NOT ported -- new ledgers only.
"""

from __future__ import annotations

from .client import JsonDict

RowKey = tuple[str, ...]


def containment_row(  # noqa: PLR0913 - named ledger fields, not a data clump
    *, report_id: str, entity_id: str, entity_name: str, linker: str, key: str, role: str,
    confidence: str, evidence: str, label_id: str | None, created: bool, preexisted: bool = False,
) -> JsonDict:
    """A report-contains-entity row (ported octigeo pipeline's per-target record,
    recast as one ledger kind).

    `preexisted` is True when the entity was already among the report's
    objects before this run touched it: the ref is not ours, and revert must
    leave it. Rows written before the field existed carry no key and are
    read as False (ours) -- the only behaviour those runs ever had. On a
    re-apply the prior row wins (`_merge_dedupe_prior_wins`), so a ref this
    run added is never re-stamped preexisted by the second read.
    """
    if not report_id or not entity_id:
        raise ValueError("containment row needs report_id and entity_id")
    row: JsonDict = {
        "kind": "containment", "report_id": report_id, "entity_id": entity_id,
        "entity_name": entity_name, "linker": linker, "key": key, "role": role,
        "confidence": confidence, "evidence": evidence, "label_id": label_id,
        "created": bool(created), "preexisted": bool(preexisted),
    }
    row_key(row)
    return row


def relationship_row(  # noqa: PLR0913 - named ledger fields, not a data clump
    item: JsonDict, *, relationship_id: str, preexisted: bool, in_reports: list[str], label_id: str,
    status: str = "",
) -> JsonDict:
    """Ported from octirel writer.ledger_row, plus `"kind": "relationship"`.

    Built from named fields. `preexisted` is always written explicitly:
    revert depends on it, and nothing downstream may infer it. `status`
    ("created" | "ours" | "preexisting") exists because row data alone
    cannot distinguish "ours, already written" from "newly created" --
    the apply summary needs that distinction and item/preexisted don't
    carry it. It defaults to "" so an older caller (or an older ledger row
    read back from disk) that doesn't supply it still round-trips."""
    if not relationship_id:
        raise ValueError("relationship row needs a relationship id")
    row: JsonDict = {
        "kind": "relationship",
        "actor_id": item["actor_id"], "actor": item["actor"],
        "relationship_type": item["relationship_type"], "target_kind": item["target_kind"],
        "target_id": item["target_id"], "target_name": item["target_name"],
        "confidence": item["confidence"], "evidence": item["evidence"], "source": item["source"],
        "source_refs": list(item["source_refs"]), "relationship_id": relationship_id,
        "preexisted": bool(preexisted), "in_reports": list(in_reports), "label_id": label_id,
        "status": status,
    }
    row_key(row)
    return row


def alias_row(*, entity_id: str, entity_name: str, alias: str, preexisted: bool, evidence: str) -> JsonDict:
    """An adopted-alias row: `alias` was attached to `entity_id` as an
    x_opencti_aliases entry."""
    if not entity_id or not alias:
        raise ValueError("alias row needs entity_id and alias")
    row: JsonDict = {
        "kind": "alias", "entity_id": entity_id, "entity_name": entity_name, "alias": alias,
        "preexisted": bool(preexisted), "evidence": evidence,
    }
    row_key(row)
    return row


def entity_row(*, entity_id: str, entity_type: str, name: str) -> JsonDict:
    """A bare created/adopted entity row, independent of any one report."""
    if not entity_id or not entity_type:
        raise ValueError("entity row needs entity_id and entity_type")
    row: JsonDict = {"kind": "entity", "entity_id": entity_id, "entity_type": entity_type, "name": name}
    row_key(row)
    return row


def row_key(row: JsonDict) -> RowKey:
    """The dedupe/merge key for one row, dispatched on `row["kind"]`.

    containment -> ("containment", report_id, entity_id)
    relationship -> ("relationship", actor_id, relationship_type, target_id) -- the
        ported octirel `ledger_key`.
    alias -> ("alias", entity_id, alias)
    entity -> ("entity", entity_id)
    """
    if not isinstance(row, dict):
        raise TypeError("row must be a dict")
    kind = row.get("kind")
    key: RowKey
    if kind == "containment":
        key = ("containment", str(row["report_id"]), str(row["entity_id"]))
    elif kind == "relationship":
        key = ("relationship", str(row["actor_id"]), str(row["relationship_type"]), str(row["target_id"]))
    elif kind == "alias":
        key = ("alias", str(row["entity_id"]), str(row["alias"]))
    elif kind == "entity":
        key = ("entity", str(row["entity_id"]))
    else:
        raise ValueError(f"row_key: unknown or missing row kind: {kind!r}")
    if not all(key):
        raise ValueError(f"row is missing a key field: {key}")
    return key


def _collapse_same_key(rows: list[JsonDict]) -> JsonDict:
    """Rows sharing a key, in encounter order. Scalar fields come from the
    last row; source_refs and in_reports are the ordered union across all
    of them (successive checkpoints of one item share a relationship_id and
    only grow in_reports, so unioning is safe and keeps the latest state)."""
    result = dict(rows[-1])
    for field in ("source_refs", "in_reports"):
        union: list[str] = []
        for row in rows:
            union.extend(row[field])
        result[field] = list(dict.fromkeys(union))
    return result


def _merge_pair(p: JsonDict, f: JsonDict) -> JsonDict:
    """Decide one key present in both ledgers (see `_merge_relationship_rows`).

    Same id: prior wins, both ref lists unioned. Different id: fresh wins --
    UNLESS prior is ours and fresh says pre-existing. find_relationships can
    miss an owned relationship (page cap, or a second same-key one on the
    platform) and hand back someone else's; replacing the owned row would make
    ours unrevertable, whereas keeping it costs nothing -- if it really
    vanished, revert reports it "already gone".
    """
    if row_key(p) != row_key(f):
        raise ValueError("_merge_pair needs two rows for the same key")
    sources = list(dict.fromkeys([*p["source_refs"], *f["source_refs"]]))
    if p["relationship_id"] == f["relationship_id"]:
        winner = dict(p, source_refs=sources)
        winner["in_reports"] = list(dict.fromkeys([*p["in_reports"], *f["in_reports"]]))
    elif not p["preexisted"] and f["preexisted"]:
        winner = dict(p, source_refs=sources)
    else:
        winner = dict(f, source_refs=sources)
    if winner["relationship_id"] not in (p["relationship_id"], f["relationship_id"]):
        raise RuntimeError("_merge_pair produced a relationship id from neither row")
    return winner


def _merge_relationship_rows(prior: list[JsonDict], fresh: list[JsonDict]) -> dict[RowKey, JsonDict]:
    """One row per key.

    Controller ruling: when both a prior and a fresh row exist for a key,
    the *prior* row wins (keeps its relationship_id and preexisted) only
    when both rows carry the SAME relationship_id -- that is a re-apply of
    octi-rel's own relationship, and letting a fresh read overwrite
    `preexisted: false` with `true` would make it undeletable. When the ids
    differ -- the prior relationship vanished from the platform (deleted
    directly, or a `revert` that died partway) and re-apply created a new
    one under a new id -- the *fresh* row replaces the prior one outright:
    source_refs is still the union of both, but in_reports comes from the
    fresh row alone, since the prior relationship's report links describe
    an object that no longer exists. Without this, a re-created
    relationship orphans: revert keeps pointing at the vanished id and
    reports "already gone" while the relationship actually on the platform
    becomes permanently unrevertable.
    """
    by_key: dict[RowKey, list[JsonDict]] = {}
    for row in prior:
        by_key.setdefault(row_key(row), []).append(row)
    prior_rows = {key: _collapse_same_key(rows) for key, rows in by_key.items()}
    by_key = {}
    for row in fresh:
        by_key.setdefault(row_key(row), []).append(row)
    fresh_rows = {key: _collapse_same_key(rows) for key, rows in by_key.items()}

    merged: dict[RowKey, JsonDict] = {}
    for key in dict.fromkeys([*prior_rows, *fresh_rows]):
        p, f = prior_rows.get(key), fresh_rows.get(key)
        if f is None:
            if p is None:
                raise RuntimeError(f"merge_ledger key {key} has no row in either ledger")
            merged[key] = dict(p)
        elif p is None:
            merged[key] = dict(f)
        else:
            merged[key] = _merge_pair(p, f)
    if len(merged) != len(prior_rows.keys() | fresh_rows.keys()):
        raise RuntimeError("merge_ledger dropped a key")
    return merged


def _merge_dedupe_prior_wins(prior: list[JsonDict], fresh: list[JsonDict]) -> list[JsonDict]:
    """Containment/alias/entity rows: one per row_key, prior kept (ported
    octigeo `merge_ledger` behaviour). `apply` is re-runnable by design --
    dry-run, apply, maybe re-apply with --include-review -- and OpenCTI
    treats adding an existing objectRef as a no-op, so without dedupe the
    ledger grows a row per invocation and stops matching what was actually
    written."""
    merged: list[JsonDict] = []
    seen: set[RowKey] = set()
    for row in [*prior, *fresh]:
        key = row_key(row)
        if key in seen:
            continue
        seen.add(key)
        merged.append(row)
    return merged


def merge_ledger(prior: list[JsonDict], fresh: list[JsonDict]) -> list[JsonDict]:
    """One row per key, across all four row kinds.

    Relationship rows merge via the octirel algorithm (`_merge_relationship_rows`
    / `_merge_pair`). Containment, alias and entity rows dedupe by `row_key`
    with prior kept, first occurrence wins (ported octigeo behaviour).

    Post-condition: the merged ledger's key set is exactly the union of the
    prior and fresh key sets -- a merge must never lose or invent a key.
    """
    if not isinstance(prior, list) or not isinstance(fresh, list):
        raise TypeError("ledgers must be lists")
    prior_rel = [row for row in prior if row.get("kind") == "relationship"]
    fresh_rel = [row for row in fresh if row.get("kind") == "relationship"]
    prior_other = [row for row in prior if row.get("kind") != "relationship"]
    fresh_other = [row for row in fresh if row.get("kind") != "relationship"]

    merged_rel = list(_merge_relationship_rows(prior_rel, fresh_rel).values())
    merged_other = _merge_dedupe_prior_wins(prior_other, fresh_other)
    merged = merged_rel + merged_other

    merged_keys = {row_key(row) for row in merged}
    all_keys = {row_key(row) for row in [*prior, *fresh]}
    if merged_keys != all_keys:
        raise RuntimeError("merge_ledger dropped a key")
    return merged


def should_delete_relationship(*, preexisted: bool, exists: bool, labelled: bool, label: str) -> tuple[bool, str]:
    """Ported from octirel writer.should_delete, renamed; the label used in
    the "adopted" reason string is now a parameter instead of the module
    constant REL_LABEL."""
    if not isinstance(preexisted, bool) or not isinstance(exists, bool) or not isinstance(labelled, bool):
        raise TypeError("should_delete_relationship takes booleans")
    if preexisted:
        decision = (False, "pre-existing; not ours")
    elif not exists:
        decision = (False, "already gone")
    elif not labelled:
        decision = (False, f"no longer labelled {label}; treated as adopted")
    else:
        decision = (True, "ours")
    if decision[0] and not (not preexisted and exists and labelled):
        raise RuntimeError(
            "should_delete_relationship decided True without preexisted=False, exists=True, labelled=True"
        )
    return decision


def should_delete_entity(*, labelled: bool, relationships: int, containers: int) -> tuple[bool, str]:
    """Ported from octigeo pipeline.should_delete, rename only.

    Whether a created entity is safe to remove, and why.

    Pure by design: this is the only destructive decision octi-geo makes, and
    keeping it free of I/O is what makes it exhaustively testable.

    Order matters. The label check comes first because an entity someone has
    relabelled is no longer ours to delete regardless of how isolated it is.
    """
    if relationships < 0 or containers < 0:
        raise ValueError(
            f"reference counts cannot be negative: "
            f"relationships={relationships}, containers={containers}"
        )
    if not labelled:
        return False, "no longer labelled ours"
    if relationships > 0:
        return False, f"{relationships} relationship(s)"
    if containers > 0:
        return False, f"still in {containers} container(s)"
    return True, "orphaned"
