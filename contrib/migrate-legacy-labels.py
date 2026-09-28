#!/usr/bin/env python3
"""contrib/migrate-legacy-labels.py — one-time legacy label migration.

octi-rb replaces two predecessor tools, octi-geo and octi-rel, each of which
tagged the platform objects it touched with its own label. This script reads
their OLD run ledgers (read-only — nothing here ever writes to those
directories) and relabels the reports, minted actor entities and
relationships they recorded onto octi-rb's `AI-*` scheme.

This is contrib/, not the package: it is operator-specific (the default
ledger paths below are this operator's own opencti-docker checkout) and is
meant to be run once, by hand, after octi-rb is otherwise in place.

    python3 contrib/migrate-legacy-labels.py --dry-run
    python3 contrib/migrate-legacy-labels.py

-- Dimension -> label table, derived from the OLD tools' source -----------

octi-geo tagged every report it touched with `dimension.label`
(opencti-docker/octigeo/pipeline.py `apply()`, line ~543:
`label_id = client.ensure_label(dim.label, dim.label_color)`, then every
report in the batch gets that one label — see
opencti-docker/octigeo/dimensions.py):

    Dimension  Dimension.label   (dimensions.py line)
    location   "octi-geo"        LOCATION.label,  line 225
    sector     "octi-geo-ics"    SECTOR.label,    line 236
    actor      "octi-geo-actor"  ACTOR.label,     line 248

octi-geo's actor resolver additionally mints Threat-Actor-Group entities
that do not already exist on the platform (only the actor dimension has a
`Creator`; location/sector never create). Freshly minted entities are
tagged with the SAME string, `ACTOR_LABEL = "octi-geo-actor"`
(opencti-docker/octigeo/actors.py, line 28), applied in
`ActorVocabulary.create()`. A ledger row for this case sets `"created":
true` and its `entity_id` is the minted actor — that row needs BOTH the
report action (dimension "actor" -> report label "octi-geo-actor", per the
table above) AND a second, entity-scoped action removing that same
"octi-geo-actor" label from the entity itself.

octi-rel tagged every relationship IT created (not ones it merely found
pre-existing) with `REL_LABEL = "octi-rel"`
(opencti-docker/octirel/relclient.py, line 13). A ledger row's `preexisted`
field is `False` exactly when octi-rel created it (writer.py); `preexisted:
true` rows are relationships octi-rel found already on the platform and
must be left alone.

Resulting old-label -> new-label pairs this script plans:

    row source                         remove              add
    ---------------------------------  ------------------  ----------------
    geo report,  dimension="location"  "octi-geo"          "AI-Location"
    geo report,  dimension="sector"    "octi-geo-ics"       "AI-Sector"
    geo report,  dimension="actor"     "octi-geo-actor"     "AI-Actor"
    geo entity,  created=true          "octi-geo-actor"     "AI-Created"
    rel  relationship, preexisted=false "octi-rel"          "AI-Relationship"
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from collections.abc import Callable
from typing import cast

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from octirb.client import Client, JsonDict, OpenCTIError
from octirb.config import Config, load_config, resolve_settings

DEFAULT_GEO_RUNS = "/home/gocyclic249/opencti-docker/runs"
DEFAULT_REL_RUNS = "/home/gocyclic249/opencti-docker/runs-rel"
LEDGER_FILENAME = "applied.json"

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_BAD_RUN = 2

# -- old -> new label table (see module docstring for citations) -----------

GEO_REPORT_LABELS: dict[str, tuple[str, str]] = {
    "location": ("AI-Location", "octi-geo"),
    "sector": ("AI-Sector", "octi-geo-ics"),
    "actor": ("AI-Actor", "octi-geo-actor"),
}

ENTITY_CREATED_ADD = "AI-Created"
ENTITY_CREATED_REMOVE = "octi-geo-actor"

RELATIONSHIP_ADD = "AI-Relationship"
RELATIONSHIP_REMOVE = "octi-rel"

_TARGET_FIELD: dict[str, str] = {
    "relabel-report": "report_id",
    "relabel-entity": "entity_id",
    "relabel-relationship": "relationship_id",
}

# -- pure planning -----------------------------------------------------------


def _geo_row_actions(row: JsonDict) -> list[JsonDict]:
    """The relabel-report action (always) and relabel-entity action (only
    when the row minted an entity) implied by one octi-geo ledger row."""
    # Rows written before octi-geo's dimension split carry no "dimension" key
    # at all (they used country_id/country_name). Only location rows predate
    # the split, so a missing key means "location" — never a guess for any
    # other value, which still hard-fails below.
    dimension = row.get("dimension")
    if dimension is None and (row.get("country_id") or row.get("iso3") or row.get("key")):
        dimension = "location"
    if dimension not in GEO_REPORT_LABELS:
        raise ValueError(f"plan_migrations: unknown octi-geo dimension {dimension!r}")
    add, remove = GEO_REPORT_LABELS[str(dimension)]
    report_id = row.get("report_id")
    if not report_id:
        raise ValueError("plan_migrations: octi-geo row missing report_id")
    actions: list[JsonDict] = [
        {"action": "relabel-report", "report_id": str(report_id), "add": add, "remove": remove}
    ]
    if row.get("created"):
        entity_id = row.get("entity_id")
        if not entity_id:
            raise ValueError("plan_migrations: created octi-geo row missing entity_id")
        actions.append({
            "action": "relabel-entity",
            "entity_id": str(entity_id),
            "add": ENTITY_CREATED_ADD,
            "remove": ENTITY_CREATED_REMOVE,
        })
    return actions


def _rel_row_action(row: JsonDict) -> JsonDict | None:
    """The relabel-relationship action implied by one octi-rel ledger row,
    or None for a preexisted:true row (octi-rel did not create it)."""
    if row.get("preexisted"):
        return None
    relationship_id = row.get("relationship_id")
    if not relationship_id:
        raise ValueError("plan_migrations: octi-rel row missing relationship_id")
    return {
        "action": "relabel-relationship",
        "relationship_id": str(relationship_id),
        "add": RELATIONSHIP_ADD,
        "remove": RELATIONSHIP_REMOVE,
    }


def _target_id(action: JsonDict) -> str:
    field = _TARGET_FIELD.get(str(action.get("action")))
    if field is None:
        raise ValueError(f"plan_migrations: unknown action kind {action.get('action')!r}")
    return str(action[field])


def plan_migrations(
    geo_ledgers: list[list[JsonDict]], rel_ledgers: list[list[JsonDict]]
) -> list[JsonDict]:
    """Pure planner: legacy ledgers in, deduplicated migration actions out.

    Never touches the network or the filesystem. Deduplicated by
    (action, target id, add) so re-running the planner over overlapping
    ledgers (a report touched by two runs, a relationship checkpointed
    twice) produces one action per distinct relabel.
    """
    if not isinstance(geo_ledgers, list) or not isinstance(rel_ledgers, list):
        raise TypeError("plan_migrations needs lists of ledgers")

    actions: list[JsonDict] = []
    seen: set[tuple[str, str, str]] = set()

    def _add(action: JsonDict) -> None:
        key = (str(action["action"]), _target_id(action), str(action["add"]))
        if key in seen:
            return
        seen.add(key)
        actions.append(action)

    for geo_ledger in geo_ledgers:
        for row in geo_ledger:
            for action in _geo_row_actions(row):
                _add(action)
    for rel_ledger in rel_ledgers:
        for row in rel_ledger:
            rel_action = _rel_row_action(row)
            if rel_action is not None:
                _add(rel_action)
    return actions


# -- ledger discovery (I/O; not exercised by tests/test_migrate.py) --------


def _read_ledger(path: pathlib.Path) -> list[JsonDict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit(f"{path}: expected a JSON array of ledger rows")
    rows: list[JsonDict] = []
    for row in data:
        if not isinstance(row, dict):
            raise SystemExit(f"{path}: ledger row is not an object")
        rows.append(cast("JsonDict", row))
    return rows


def _discover_ledgers(runs_dir: pathlib.Path) -> list[list[JsonDict]]:
    """Every `<runs_dir>/<run>/applied.json`, one ledger (list of rows) per
    run directory. Read-only: this never writes into `runs_dir`. A missing
    `runs_dir` yields no ledgers rather than an error -- the two directories
    are operator-specific and either may simply not exist here."""
    if not runs_dir.is_dir():
        return []
    ledgers: list[list[JsonDict]] = []
    for child in sorted(runs_dir.iterdir()):
        if not child.is_dir():
            continue
        ledger_path = child / LEDGER_FILENAME
        if ledger_path.is_file():
            ledgers.append(_read_ledger(ledger_path))
    return ledgers


# -- executor: applies one planned action to the platform -------------------
#
# Report labels go through octirb.client.Client's existing
# add_label_to_report/remove_label_from_report. Entity and relationship
# labels have no equivalent on Client, so the two mutation pairs below
# mirror those report variants exactly (relationAdd/relationDelete on
# relationship_type "object-label") against stixCoreObjectEdit and
# stixCoreRelationshipEdit instead of reportEdit.

ENTITY_LABEL_ADD_M = """mutation($id: ID!, $l: StixRef!) {
  stixCoreObjectEdit(id: $id) {
    relationAdd(input: { toId: $l, relationship_type: "object-label" }) { id }
  } }"""

ENTITY_LABEL_REMOVE_M = """mutation($id: ID!, $l: StixRef!) {
  stixCoreObjectEdit(id: $id) {
    relationDelete(toId: $l, relationship_type: "object-label") { id }
  } }"""

RELATIONSHIP_LABEL_ADD_M = """mutation($id: ID!, $l: StixRef!) {
  stixCoreRelationshipEdit(id: $id) {
    relationAdd(input: { toId: $l, relationship_type: "object-label" }) { id }
  } }"""

RELATIONSHIP_LABEL_REMOVE_M = """mutation($id: ID!, $l: StixRef!) {
  stixCoreRelationshipEdit(id: $id) {
    relationDelete(toId: $l, relationship_type: "object-label") { id }
  } }"""


def _entity_relabel(client: Client, entity_id: str, add_id: str, remove_id: str) -> None:
    client.gql(ENTITY_LABEL_ADD_M, {"id": entity_id, "l": add_id})
    client.gql(ENTITY_LABEL_REMOVE_M, {"id": entity_id, "l": remove_id})


def _relationship_relabel(client: Client, relationship_id: str, add_id: str, remove_id: str) -> None:
    client.gql(RELATIONSHIP_LABEL_ADD_M, {"id": relationship_id, "l": add_id})
    client.gql(RELATIONSHIP_LABEL_REMOVE_M, {"id": relationship_id, "l": remove_id})


def _apply_action(client: Client, cfg: Config, action: JsonDict, log: Callable[[str], None]) -> None:
    """Apply one planned action. `ensure_label` looks the old label up by
    value rather than minting a fresh one -- every `remove` value here was
    already created by the predecessor tool that applied it -- and is also
    how the new `add` label gets created on first use."""
    kind = str(action["action"])
    if kind not in _TARGET_FIELD:
        raise OpenCTIError(f"unknown migration action: {kind!r}")
    add_value, remove_value = str(action["add"]), str(action["remove"])
    add_id = client.ensure_label(add_value, cfg.labels.color)
    remove_id = client.ensure_label(remove_value, cfg.labels.color)
    target_id = _target_id(action)
    if kind == "relabel-report":
        client.add_label_to_report(target_id, add_id)
        client.remove_label_from_report(target_id, remove_id)
    elif kind == "relabel-entity":
        _entity_relabel(client, target_id, add_id, remove_id)
    else:
        _relationship_relabel(client, target_id, add_id, remove_id)
    log(f"  {kind}: {target_id} +{add_value} -{remove_value}")


# -- CLI ----------------------------------------------------------------


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="migrate-legacy-labels",
        description=(
            "One-time migration: relabel platform objects the legacy "
            "octi-geo/octi-rel run ledgers touched onto octi-rb's AI-* scheme."
        ),
    )
    parser.add_argument(
        "--geo-runs", default=DEFAULT_GEO_RUNS,
        help=f"octi-geo run ledgers directory, read-only (default: {DEFAULT_GEO_RUNS})",
    )
    parser.add_argument(
        "--rel-runs", default=DEFAULT_REL_RUNS,
        help=f"octi-rel run ledgers directory, read-only (default: {DEFAULT_REL_RUNS})",
    )
    parser.add_argument(
        "--config", help="octi-rb config.toml path (platform URL/token, labels.color)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="print the planned actions as JSON and exit without writing",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    geo_ledgers = _discover_ledgers(pathlib.Path(args.geo_runs))
    rel_ledgers = _discover_ledgers(pathlib.Path(args.rel_runs))
    plan = plan_migrations(geo_ledgers, rel_ledgers)

    if args.dry_run:
        print(json.dumps(plan, indent=2))
        _log(f"# {len(plan)} action(s) planned; --dry-run, nothing written.")
        return EXIT_OK

    if not plan:
        _log("nothing to migrate")
        return EXIT_OK

    cfg = load_config(pathlib.Path(args.config) if args.config else None)
    client = Client(resolve_settings(cfg))
    for action in plan:
        _apply_action(client, cfg, action, _log)
    _log(f"migrated {len(plan)} label action(s)")
    return EXIT_OK


if __name__ == "__main__":
    try:
        _exit_code = main()
    except OpenCTIError as _exc:
        _log(f"OpenCTI error: {_exc}")
        _exit_code = EXIT_FAIL
    except SystemExit as _exc:
        if _exc.code is None or isinstance(_exc.code, int):
            raise
        _log(str(_exc.code))
        _exit_code = EXIT_BAD_RUN
    raise SystemExit(_exit_code)
