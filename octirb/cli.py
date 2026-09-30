"""Command line entry point for octi-rb.

Wires every earlier task's module into the run pipeline: doctor, select,
fetch, structured, batch, validate, apply, revert, status, crosswalk.

Data to stdout, diagnostics to stderr. Exit codes: 0 ok, 1 platform/doctor
failure, 2 bad run/config state. Ported from
`opencti-docker/octirel/cli.py`'s `main()` SystemExit(str) remap and
`cmd_select`'s meta-last / reused-run-id-refusal shape.
"""

from __future__ import annotations

import argparse
import json
import sys
from argparse import Namespace
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import config, ledger, pipeline, structured, writer
from .client import Client, JsonDict, OpenCTIError
from .config import Config
from .linkers import REGISTRY, actor_target, get, report_labels, report_vuln
from .linkers.base import Linker
from .resolvers import crosswalk
from .resolvers.gazetteer import Gazetteer
from .resolvers.sectors import SectorVocabulary
from .runstore import Run, TextCache, new_run_id

if TYPE_CHECKING:  # argparse's generic subparser action is stubs-only
    _SubParsers = argparse._SubParsersAction[argparse.ArgumentParser]

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_BAD_RUN = 2
META = "meta.json"


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def _load_cfg(args: Namespace) -> Config:
    path = Path(args.config) if args.config else None
    return config.load_config(path)


def _client(cfg: Config) -> Client:
    return Client(config.resolve_settings(cfg))


# --------------------------------------------------------------------- select


def _since_iso(since_days: int) -> str:
    return (datetime.now(UTC) - timedelta(days=since_days)).date().isoformat()


def _select_write(client: Client, cfg: Config, run: Run, args: Namespace) -> int:
    """Write selection.json and return the count of items selected."""
    if args.linker == "actor-target":
        cache = TextCache(cfg.cache_dir)
        packets = (
            actor_target.select_description(client, args.limit)
            if args.source == "description"
            else actor_target.select_report(client, cache, cfg, args.limit)
        )
        run.write_json("selection.json", packets)
        return len(packets)
    if args.linker == "report-labels":
        label_since = _since_iso(args.since_days) if args.since_days else None
        rows = report_labels.select(client, cfg, _log, limit=args.limit, since=label_since)
        run.write_json("selection.json", rows)
        return len(rows)
    cache = TextCache(cfg.cache_dir)
    since = _since_iso(args.since_days) if args.since_days else None
    selection = pipeline.select(
        client, cfg, cache, _log, linker_name=args.linker,
        empty_only=not args.all_reports, limit=args.limit, since=since,
    )
    run.write_json("selection.json", pipeline.to_dicts(selection))
    return len(selection)


def cmd_select(args: Namespace) -> int:
    get(args.linker)  # unknown linker -> SystemExit before anything else
    cfg = _load_cfg(args)
    if args.linker == "report-vuln" and not cfg.vulns.enabled:
        raise SystemExit("config: report-vuln is disabled ([vulns].enabled)")
    if args.linker == "report-labels" and not cfg.report_labels.enabled:
        raise SystemExit("config: report-labels is disabled ([report_labels].enabled)")
    if args.linker == "report-labels" and args.all_reports:
        _log("select: --all-reports does not apply to report-labels; ignored")
    if args.linker == "actor-target" and args.source not in ("description", "report"):
        _log("select --linker actor-target requires --source description|report")
        return EXIT_BAD_RUN
    if args.linker == "actor-target" and (args.since_days or args.all_reports):
        _log("select: --since-days/--all-reports do not apply to actor-target; ignored")
    runs_dir = cfg.runs_dir
    if args.run_id and (runs_dir / args.run_id / META).is_file():
        _log(f"run {args.run_id} already exists in {runs_dir} — choose a new --run-id or omit it")
        return EXIT_BAD_RUN
    config.check_disk(cfg, _log)
    client = _client(cfg)
    run = Run(runs_dir / (args.run_id or new_run_id()))
    count = _select_write(client, cfg, run, args)
    options: JsonDict = {
        "limit": args.limit, "all_reports": args.all_reports, "since_days": args.since_days,
    }
    meta: JsonDict = {
        "run_id": run.run_id, "linker": args.linker,
        "created": datetime.now(UTC).isoformat(), "options": options,
    }
    if args.linker == "actor-target":
        meta["source"] = args.source
    # Written last, deliberately: meta.json existing is what marks a run as
    # real to Run.open/latest and to the reused-run-id guard above.
    run.write_json(META, meta)
    print(f"run {run.run_id} [{args.linker}]: {count} item(s) selected")
    _log(f"next: octi-rb batch --run-id {run.run_id}")
    return EXIT_OK


# ---------------------------------------------------------------------- fetch


def cmd_fetch(args: Namespace) -> int:
    cfg = _load_cfg(args)
    run = Run.open(cfg.runs_dir, args.run_id)
    if run.linker() in ("actor-target", "report-labels"):
        _log(f"run {run.run_id} is {run.linker()}; it has no fetch step")
        return EXIT_BAD_RUN
    selection = pipeline.from_dicts(run.read_json("selection.json"))
    client = _client(cfg)
    cache = TextCache(cfg.cache_dir)
    status = pipeline.materialize_text(client, cfg, cache, selection, _log)
    run.write_json("fetch_status.json", status)
    cap_skips = sum(1 for s in status.values() if "fetch cap" in s)
    print(f"run {run.run_id}: {len(status)} report(s) processed, {cap_skips} skipped (fetch cap)")
    return EXIT_OK


# ---------------------------------------------------------------------- batch


def _batch_vuln(run: Run, cfg: Config) -> int:
    cache = TextCache(cfg.cache_dir)
    selection = pipeline.from_dicts(run.read_json("selection.json"))
    batch = pipeline.build_batch(cache, selection)
    extractions = report_vuln.build_extractions(batch)
    run.write_json("extractions.json", extractions)
    print(f"run {run.run_id}: {len(extractions)} extraction(s) written")
    return EXIT_OK


def _batch_labels(run: Run, cfg: Config) -> int:
    extractions = report_labels.batch(_client(cfg), cfg, run.read_json("selection.json"), _log)
    run.write_json("extractions.json", extractions)
    print(f"run {run.run_id}: {len(extractions)} extraction(s) written")
    return EXIT_OK


def _batch_actor_target(cfg: Config, run: Run, client: Client) -> tuple[list[JsonDict], str]:
    meta = run.meta()
    source = str(meta.get("source") or "")
    packets = run.read_json("selection.json")
    sectors = SectorVocabulary.load(client, cfg.sectors).names()
    regions = sorted(str(r["name"]) for r in client.regions())
    contract = actor_target.render(source, sectors, regions)
    return packets, contract


def _batch_containment(
    cfg: Config, run: Run, client: Client, linker: Linker
) -> tuple[list[JsonDict], str]:
    cache = TextCache(cfg.cache_dir)
    selection = pipeline.from_dicts(run.read_json("selection.json"))
    batch = pipeline.build_batch(cache, selection)
    resolver = linker.build_resolver(client, cfg)
    contract = linker.contract(resolver) if linker.contract is not None else ""
    return batch, contract


def cmd_batch(args: Namespace) -> int:
    cfg = _load_cfg(args)
    run = Run.open(cfg.runs_dir, args.run_id)
    linker_name = run.linker()
    if linker_name == "report-vuln":
        return _batch_vuln(run, cfg)
    if linker_name == "report-labels":
        return _batch_labels(run, cfg)
    linker = get(linker_name)
    if not linker.needs_model:
        raise RuntimeError(f"batch: linker {linker_name!r} has no batch step")
    client = _client(cfg)
    batch, contract = (
        _batch_actor_target(cfg, run, client) if linker_name == "actor-target"
        else _batch_containment(cfg, run, client, linker)
    )
    run.write_json("batch.json", batch)
    contract_path = run.root / "CONTRACT.md"
    contract_path.write_text(contract, encoding="utf-8")
    print(str(run.root / "batch.json"))
    print(str(contract_path))
    return EXIT_OK


# ------------------------------------------------------------------ structured


def cmd_structured(args: Namespace) -> int:
    cfg = _load_cfg(args)
    run = Run.open(cfg.runs_dir, args.run_id)
    linker_name = run.linker()
    batch = run.read_json("batch.json")
    extra, covered = structured.parse(batch, linker_name)
    prior = run.read_json("extractions.json") if run.has("extractions.json") else []
    # Re-running structured must not append the same parser output twice.
    seen = {json.dumps(e, sort_keys=True) for e in prior}
    fresh = [e for e in extra if json.dumps(e, sort_keys=True) not in seen]
    merged = [*prior, *fresh]
    run.write_json("extractions.json", merged)
    print(
        f"run {run.run_id}: {covered} packet(s) matched a structured parser; "
        f"{len(fresh)} extraction(s) added ({len(merged)} total)"
    )
    return EXIT_OK


# ------------------------------------------------------------------- validate


@dataclass(frozen=True)
class _Named:
    id: str
    name: str


class _RegionResolver:
    """A minimal TargetResolver over `client.regions()`: exact, case-insensitive name match."""

    def __init__(self, regions: list[JsonDict]) -> None:
        self._by_name = {str(r["name"]).casefold(): _Named(str(r["id"]), str(r["name"])) for r in regions}

    def resolve(self, key: str) -> _Named | None:
        if not isinstance(key, str) or not key.strip():
            return None
        return self._by_name.get(key.strip().casefold())


def _actor_target_selection(packets: list[JsonDict]) -> dict[str, frozenset[str]]:
    selection: dict[str, frozenset[str]] = {}
    for packet in packets:
        ref = str(packet["source_ref"])
        if "actor_id" in packet:
            selection[ref] = frozenset({str(packet["actor_id"])})
        else:
            selection[ref] = frozenset(str(a["actor_id"]) for a in (packet.get("actors") or []))
    return selection


def _validate_actor_target(
    cfg: Config, run: Run, client: Client, extractions: list[Any]
) -> tuple[list[JsonDict], list[JsonDict]]:
    packets = run.read_json("selection.json")
    actors = {
        str(a["id"]): actor_target.ActorRef(str(a["id"]), str(a["name"]), str(a["entity_type"]))
        for a in client.actors()
    }
    ctx = actor_target.Context(
        actors=actors,
        targets={
            "country": Gazetteer.load(client),
            "region": _RegionResolver(client.regions()),
            "sector": SectorVocabulary.load(client, cfg.sectors),
        },
        schema=actor_target.Schema.load(client),
        selection=_actor_target_selection(packets),
    )
    return actor_target.validate(extractions, ctx)


def cmd_validate(args: Namespace) -> int:
    cfg = _load_cfg(args)
    run = Run.open(cfg.runs_dir, args.run_id)
    raw = run.read_json("extractions.json")
    if not isinstance(raw, list):
        _log(f"{run.root / 'extractions.json'} is corrupt; expected a JSON array")
        return EXIT_BAD_RUN
    linker_name = run.linker()
    if linker_name == "report-labels":
        selection_ids = {str(s["report_id"]) for s in run.read_json("selection.json")}
        auto, review = report_labels.validate(raw, selection_ids)
    elif linker_name == "actor-target":
        auto, review = _validate_actor_target(cfg, run, _client(cfg), raw)
    else:
        client = _client(cfg)
        linker = get(linker_name)
        resolver = linker.build_resolver(client, cfg)
        selection_ids = {str(s["report_id"]) for s in run.read_json("selection.json")}
        writeback = linker_name == "report-actor" and cfg.actors.alias_writeback
        auto, review = pipeline.validate(raw, resolver, selection_ids, linker, writeback=writeback)
    run.write_json("auto.json", auto)
    run.write_json("review.json", review)
    print(f"run {run.run_id}: {len(auto)} auto, {len(review)} for review")
    return EXIT_OK


# ---------------------------------------------------------------------- apply


def _apply_labels_cmd(args: Namespace, cfg: Config, run: Run, client: Client) -> int:
    auto = run.read_json("auto.json") if run.has("auto.json") else []
    review = run.read_json("review.json") if run.has("review.json") else []
    items = list(auto)
    if args.include_review:
        items += [r for r in review if not r.get("hard_fail")]
    prior = run.read_json("applied.json") if run.has("applied.json") else []

    def save(fresh: list[JsonDict]) -> None:
        run.write_json("applied.json", ledger.merge_ledger(prior, fresh))

    rows = report_labels.apply_labels(
        client, items, _log, color=cfg.report_labels.color, dry_run=args.dry_run, save=save
    )
    merged = ledger.merge_ledger(prior, rows)
    if not args.dry_run:
        run.write_json("applied.json", merged)
    written = sum(1 for r in rows if not r["preexisted"])
    verb = "would write" if args.dry_run else "wrote"
    print(f"run {run.run_id}: {verb} {written} label(s) ({len(merged)} total in ledger)")
    return EXIT_OK


def _apply_containment_cmd(
    args: Namespace, cfg: Config, run: Run, linker: Linker, client: Client
) -> int:
    auto = run.read_json("auto.json") if run.has("auto.json") else []
    review = run.read_json("review.json") if run.has("review.json") else []
    approved = list(auto)
    if args.include_review:
        approved += [r for r in review if not r.get("hard_fail")]
    if args.create_missing:
        resolver = linker.build_resolver(client, cfg)
        approved += pipeline.create_missing(resolver, review, _log, dry_run=args.dry_run, linker=linker)
    prior = run.read_json("applied.json") if run.has("applied.json") else []

    def save(fresh: list[JsonDict]) -> None:
        run.write_json("applied.json", ledger.merge_ledger(prior, fresh))

    rows = pipeline.apply_containment(
        client, approved, _log, linker, cfg, dry_run=args.dry_run, save=save
    )
    merged = ledger.merge_ledger(prior, rows)
    if not args.dry_run:
        run.write_json("applied.json", merged)
    verb = "would write" if args.dry_run else "wrote"
    print(f"run {run.run_id}: {verb} {len(rows)} row(s) ({len(merged)} total in ledger)")
    return EXIT_OK


def _apply_relationship_cmd(args: Namespace, cfg: Config, run: Run, client: Client) -> int:
    auto = run.read_json("auto.json") if run.has("auto.json") else []
    review = run.read_json("review.json") if run.has("review.json") else []
    items = list(auto)
    if args.include_review:
        items += [r for r in review if not r.get("hard_fail")]
    prior = run.read_json("applied.json") if run.has("applied.json") else []
    ours = {
        str(r["relationship_id"]): list(r["in_reports"])
        for r in prior if r.get("kind") == "relationship" and not r.get("preexisted")
    }
    label = cfg.label("Relationship")
    label_id = "(dry-run)" if args.dry_run else client.ensure_label(label, cfg.labels.color)
    ctx = writer.ApplyContext(label_id=label_id, label=label, ours=ours, dry_run=args.dry_run, log=_log)

    def save(fresh: list[JsonDict]) -> None:
        run.write_json("applied.json", ledger.merge_ledger(prior, fresh))

    rows = writer.apply_items(client, items, ctx, save)
    merged = ledger.merge_ledger(prior, rows)
    created = sum(1 for r in rows if r.get("status") == "created")
    verb = "would write" if args.dry_run else "wrote"
    print(f"run {run.run_id}: {verb} {created} relationship(s) ({len(merged)} total in ledger)")
    return EXIT_OK


def cmd_apply(args: Namespace) -> int:
    cfg = _load_cfg(args)
    run = Run.open(cfg.runs_dir, args.run_id)
    linker_name = run.linker()
    if args.create_missing and linker_name != "report-actor":
        _log("--create-missing is only valid with --linker report-actor")
        return EXIT_BAD_RUN
    linker = get(linker_name)
    client = _client(cfg)
    if linker.write_kind == "label":
        return _apply_labels_cmd(args, cfg, run, client)
    if linker.write_kind == "containment":
        return _apply_containment_cmd(args, cfg, run, linker, client)
    return _apply_relationship_cmd(args, cfg, run, client)


# --------------------------------------------------------------------- revert


def _revert_relationships(
    args: Namespace, cfg: Config, client: Client, rows: list[JsonDict]
) -> tuple[int, int]:
    """writer.revert (unlike pipeline.revert_containment/revert_aliases) does not
    filter by kind itself -- it indexes row["preexisted"]/row["relationship_id"]
    on every row it is given, which KeyErrors on a containment/alias/entity row.
    Filter to this kind before calling it."""
    relationship_rows = [r for r in rows if r.get("kind") == "relationship"]
    if not relationship_rows:
        return (0, 0)
    label = cfg.label("Relationship")
    ctx = writer.ApplyContext(label_id="", label=label, ours={}, dry_run=args.dry_run, log=_log)
    return writer.revert(client, relationship_rows, ctx)


def _revert_entities(
    args: Namespace, cfg: Config, client: Client, rows: list[JsonDict], retain: list[JsonDict]
) -> tuple[int, int]:
    """Purge entities --create-missing minted. The label checked is the one
    minting stamps (`ActorVocabulary.create`: `cfg.label("Created")`), never
    the run's linker label -- which a minted entity does not carry."""
    entity_types = {str(r["entity_id"]): str(r["entity_type"]) for r in rows if r.get("kind") == "entity"}
    if not entity_types:
        return (0, 0)
    return pipeline.purge_created(
        client, rows, _log, dry_run=args.dry_run, label=cfg.label("Created"),
        entity_types=entity_types, retain=retain,
    )


def _split_reverted(rows: list[JsonDict], retain: list[JsonDict]) -> tuple[list[JsonDict], list[JsonDict]]:
    """(still owned, done) -- partitioned by row identity, original order kept.

    "Done" covers rows undone and rows correctly kept (preexisted, adopted,
    already gone); "still owned" is every row whose undo failed or whose
    entity is still referenced, which must stay in applied.json for a retry.
    """
    keep_ids = {id(r) for r in retain}
    owned = [r for r in rows if id(r) in keep_ids]
    done = [r for r in rows if id(r) not in keep_ids]
    if len(owned) + len(done) != len(rows):
        raise RuntimeError("_split_reverted lost a row")
    return owned, done


def cmd_revert(args: Namespace) -> int:
    cfg = _load_cfg(args)
    run = Run.open(cfg.runs_dir, args.run_id)
    raw = run.read_json("applied.json") if run.has("applied.json") else []
    if not isinstance(raw, list):
        _log(f"{run.root / 'applied.json'} is corrupt; expected a JSON array")
        return EXIT_BAD_RUN
    rows: list[JsonDict] = raw
    client = _client(cfg)
    retain: list[JsonDict] = []
    n_contain = pipeline.revert_containment(client, rows, _log, dry_run=args.dry_run, retain=retain)
    n_alias = pipeline.revert_aliases(client, rows, _log, dry_run=args.dry_run, retain=retain)
    n_label = report_labels.revert_labels(client, rows, _log, dry_run=args.dry_run, retain=retain)
    n_rel_del, n_rel_kept = _revert_relationships(args, cfg, client, rows)
    n_ent_del, n_ent_kept = _revert_entities(args, cfg, client, rows, retain)
    owned, done = _split_reverted(rows, retain)
    if not args.dry_run:
        # Only what was actually finished leaves the ledger. A row whose undo
        # failed stays in applied.json, so re-running revert retries it rather
        # than the write becoming permanently unrevertable.
        prior_reverted = run.read_json("reverted.json") if run.has("reverted.json") else []
        run.write_json("reverted.json", [*prior_reverted, *done])
        run.write_json("applied.json", owned)
    print(
        f"run {run.run_id}: containment {n_contain}, aliases {n_alias}, labels {n_label}, "
        f"relationships {n_rel_del}/{n_rel_kept} kept, entities {n_ent_del}/{n_ent_kept} kept"
    )
    if owned and not args.dry_run:
        _log(f"run {run.run_id}: {len(owned)} row(s) still owned; re-run revert to retry them")
    return EXIT_OK


# --------------------------------------------------------------------- status


def _read_meta_safe(d: Path) -> JsonDict:
    try:
        data = json.loads((d / META).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _count(run: Run, name: str) -> int:
    return len(run.read_json(name)) if run.has(name) else 0


def _fetch_summary(run: Run) -> str:
    if not run.has("fetch_status.json"):
        return "-"
    statuses = run.read_json("fetch_status.json")
    if not isinstance(statuses, dict):
        return "-"
    cap_skips = sum(1 for s in statuses.values() if "fetch cap" in str(s))
    return f"{len(statuses)} (cap-skipped {cap_skips})"


def _status_line(d: Path) -> str:
    meta = _read_meta_safe(d)
    run = Run(d)
    linker_name = str(meta.get("linker", "?"))
    created = str(meta.get("created", ""))
    counts = " ".join(
        f"{_count(run, name):>5}"
        for name in ("selection.json", "extractions.json", "auto.json", "review.json", "applied.json")
    )
    return f"{run.run_id:20} {linker_name:14} {created:25} {counts} {_fetch_summary(run)}"


def cmd_status(args: Namespace) -> int:
    cfg = _load_cfg(args)
    runs_dir = cfg.runs_dir
    if not runs_dir.is_dir():
        _log(f"no runs yet in {runs_dir}")
        return EXIT_OK
    dirs = sorted(
        (d for d in runs_dir.iterdir() if d.is_dir() and (d / META).is_file()),
        key=lambda d: str(_read_meta_safe(d).get("created", "")),
    )
    print(f"{'run':20} {'linker':14} {'created':25} {'sel':>5} {'ext':>5} {'auto':>5} {'rev':>5} {'app':>5} fetch")
    for d in dirs:
        print(_status_line(d))
    return EXIT_OK


# -------------------------------------------------------------------- doctor


def _doctor_client(cfg: Config) -> Client | None:
    try:
        settings = config.resolve_settings(cfg)
    except SystemExit as exc:
        _log(f"doctor: {exc}")
        return None
    print(f"doctor: platform url {settings.url}")
    return Client(settings)


def _doctor_reports(client: Client) -> bool:
    try:
        next(iter(client.reports()), None)
    except OpenCTIError as exc:
        _log(f"doctor: reports connectivity failed: {exc}")
        return False
    print("doctor: reports() connectivity OK")
    return True


def _doctor_sectors(client: Client, cfg: Config) -> bool:
    try:
        vocab = SectorVocabulary.load(client, cfg.sectors)
    except (SystemExit, OpenCTIError) as exc:
        _log(f"doctor: sector vocabulary failed to load: {exc}")
        return False
    names = set(vocab.names())
    bad = sorted(target for target in cfg.sectors.aliases.values() if target not in names)
    if bad:
        _log(f"doctor: [sectors].aliases target(s) not canonical: {', '.join(bad)}")
        return False
    print(f"doctor: {len(names)} canonical sector(s); aliases OK")
    return True


def _doctor_linkers(client: Client, cfg: Config) -> bool:
    ok = True
    for name in sorted(REGISTRY):
        if not name.startswith("report-") or REGISTRY[name].write_kind != "containment":
            continue
        linker = REGISTRY[name]
        try:
            resolver = linker.build_resolver(client, cfg)
        except (SystemExit, OpenCTIError) as exc:
            _log(f"doctor: {name} resolver failed to load: {exc}")
            ok = False
            continue
        unresolved = [p for p in resolver.probes() if resolver.resolve(p) is None]
        if unresolved:
            _log(f"doctor: {name} could not resolve probe(s): {', '.join(unresolved)}")
            ok = False
        else:
            print(f"doctor: {name} resolver OK ({len(resolver)} entries)")
    return ok


def _doctor_crosswalk(cfg: Config) -> bool:
    if not cfg.actors.crosswalk_enabled:
        print("doctor: crosswalk disabled ([actors].crosswalk_enabled = false)")
        return True
    age = crosswalk.Crosswalk.age_days(cfg.cache_dir)
    # Warnings, not failures (spec): the crosswalk is an optional resolver tier.
    if age is None:
        _log("doctor: WARNING crosswalk cache missing; run `octi-rb crosswalk refresh`")
        return True
    if age > cfg.actors.crosswalk_max_age_days:
        _log(f"doctor: WARNING crosswalk cache is {age} day(s) old (max {cfg.actors.crosswalk_max_age_days})")
        return True
    print(f"doctor: crosswalk cache OK ({age} day(s) old)")
    return True


def _doctor_fetch_connector(client: Client, cfg: Config) -> bool:
    if not cfg.text.fetch_enabled:
        print("doctor: text fetch disabled ([text].fetch_enabled = false)")
        return True
    try:
        record = client.connector(pipeline.CONNECTOR_NAME)
    except OpenCTIError as exc:
        _log(f"doctor: connector lookup failed: {exc}")
        return False
    if record is None or not record.get("active"):
        # Presence noted, not a failure (spec): only fetch-tier reports need it.
        _log(
            f"doctor: WARNING connector {pipeline.CONNECTOR_NAME} not present/active; "
            "fetch-tier reports will be skipped"
        )
        return True
    print(f"doctor: connector {pipeline.CONNECTOR_NAME} active")
    return True


def cmd_doctor(args: Namespace) -> int:
    cfg = _load_cfg(args)
    client = _doctor_client(cfg)
    ok = client is not None
    if client is not None:
        ok = _doctor_reports(client) and ok
        ok = _doctor_sectors(client, cfg) and ok
        ok = _doctor_linkers(client, cfg) and ok
        ok = _doctor_fetch_connector(client, cfg) and ok
    ok = _doctor_crosswalk(cfg) and ok
    config.check_disk(cfg, _log)
    print(f"doctor: {'OK' if ok else 'FAILED'}")
    return EXIT_OK if ok else EXIT_FAIL


# ----------------------------------------------------------------- crosswalk


def cmd_crosswalk(args: Namespace) -> int:
    cfg = _load_cfg(args)
    if args.action != "refresh":
        raise RuntimeError(f"cmd_crosswalk: unknown action {args.action!r}")
    path = crosswalk.refresh(cfg.cache_dir)
    print(f"crosswalk cache refreshed: {path}")
    return EXIT_OK


# --------------------------------------------------------------------- parser


def _add_common(sub: _SubParsers, name: str, help_text: str) -> argparse.ArgumentParser:
    parser: argparse.ArgumentParser = sub.add_parser(name, help=help_text)
    parser.add_argument("--run-id")
    return parser


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="octi-rb",
        description="Enrich OpenCTI reports with locations, sectors, actors, vulnerabilities and "
        "actor-target relationships.",
    )
    root.add_argument("--config", help="path to config.toml (default: ./config.toml or $OCTI_RB_CONFIG)")
    sub = root.add_subparsers(dest="command", required=True)

    select = _add_common(sub, "select", "select reports or actors for a new run")
    select.add_argument("--linker", required=True, choices=sorted(REGISTRY))
    select.add_argument("--limit", type=int)
    select.add_argument("--all-reports", action="store_true", help="clear the default empty_only filter")
    select.add_argument("--since-days", type=int)
    select.add_argument("--source", choices=("description", "report"), help="required for --linker actor-target")

    _add_common(sub, "fetch", "materialize article text into the shared cache")
    _add_common(sub, "structured", "run deterministic structured-field parsers")
    _add_common(sub, "batch", "write batch.json + CONTRACT.md, or extract deterministically")
    _add_common(sub, "validate", "validate extractions into auto.json/review.json")

    apply_p = _add_common(sub, "apply", "write approved items to the platform")
    apply_p.add_argument("--dry-run", action="store_true")
    apply_p.add_argument("--include-review", action="store_true")
    apply_p.add_argument("--create-missing", action="store_true")

    revert_p = _add_common(sub, "revert", "undo a run's writes")
    revert_p.add_argument("--dry-run", action="store_true")

    sub.add_parser("status", help="summarise every run")
    sub.add_parser("doctor", help="check config, connectivity and resolvers")

    crosswalk_p = sub.add_parser("crosswalk", help="manage the actor synonym cache")
    crosswalk_p.add_argument("action", choices=("refresh",))
    return root


COMMANDS: dict[str, Callable[[Namespace], int]] = {
    "doctor": cmd_doctor,
    "select": cmd_select,
    "fetch": cmd_fetch,
    "structured": cmd_structured,
    "batch": cmd_batch,
    "validate": cmd_validate,
    "apply": cmd_apply,
    "revert": cmd_revert,
    "status": cmd_status,
    "crosswalk": cmd_crosswalk,
}


def main(argv: list[str] | None = None) -> int:
    """argparse itself raises SystemExit(int) for --help/usage errors; that must
    keep propagating unchanged. Every lower layer instead raises SystemExit(str)
    for a bad run/config state, which Python would otherwise print and exit 1,
    discarding EXIT_BAD_RUN. Catching it here and remapping is what makes that
    contract real. Dispatch goes through COMMANDS (not args.func) so a test can
    monkeypatch COMMANDS and have main() see the replacement. `client.py` raises
    `OpenCTIError` for any unreachable-platform/bad-response condition -- reachable
    from every command outside doctor's own local catch -- so it is mapped to a
    one-line stderr message and EXIT_FAIL here rather than left to crash with a
    traceback and an incidental exit(1).
    """
    args = build_parser().parse_args(argv)
    try:
        result: int = COMMANDS[args.command](args)
    except OpenCTIError as exc:
        _log(f"OpenCTI error: {exc}")
        return EXIT_FAIL
    except SystemExit as exc:
        if exc.code is None or isinstance(exc.code, int):
            raise
        _log(str(exc.code))
        return EXIT_BAD_RUN
    if result not in (EXIT_OK, EXIT_FAIL, EXIT_BAD_RUN):
        raise RuntimeError(f"command returned an unknown exit code: {result!r}")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
