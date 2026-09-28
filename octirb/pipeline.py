"""The octi-rb pipeline: select -> fetch -> batch (part 1).

Ported from `opencti-docker/octigeo/pipeline.py`'s `select`/`materialize_text`/
`build_batch`/`to_dicts`/`from_dicts`, generalized for octi-rb:

- Selection is config-driven (`cfg.selection`) rather than fixed allowlists
  baked into a `SelectOptions` dataclass.
- `Selected.text_source` becomes `text_tier`, whose value comes from
  `text.plan_text_tier` -- the tier planner that also knows about the
  "stored-file" and "cache" sources octigeo never had.
- Text capture goes through the shared `runstore.TextCache` rather than a
  single run's directory, so a second run against the same report never
  re-fetches.
- `materialize_text` enforces `cfg.text.max_fetch_per_run`, a cap octigeo did
  not have, and calls `config.check_disk` once at entry.

Part 2 (Task 12) ports the validate/apply/revert half of octigeo's
pipeline.py -- `validate`, `create_missing`, `apply` (-> `apply_containment`),
`revert` (-> `revert_containment`), `should_delete`+`purge_created` (the pure
decision now lives in `octirb.ledger.should_delete_entity`) -- generalized
from a single hardcoded actor Dimension to any `Linker`, plus:

- A crosswalk fallback in `validate`: when the direct resolve chain misses
  and the resolver exposes `crosswalk_resolve`, a MISP galaxy synonym hit
  resolves the item but demotes it out of auto-apply into review, so a
  crosswalk-only match always gets a human look before it is written.
- Alias write-back: an actor item that resolved through an older name (e.g.
  "ICE RELIC" for APT29) records the unknown spellings in its chain as
  `alias_writes`; `apply_containment` adds them to the resolved entity's
  `x_opencti_aliases` (skipping ones already present) and ledgers each as an
  `alias` row, so `revert_aliases` can undo exactly what was added.
- `apply_containment`/`revert_containment` write/read the ledger's
  `"containment"` rows (via `octirb.ledger.containment_row`), not a bespoke
  per-dimension record shape -- containment, alias and (for minted entities)
  entity rows all merge through one `ledger.merge_ledger`.

`config` is imported as a module (not `from .config import check_disk`) so
that tests can monkeypatch `octirb.config.check_disk` and have this module
see the replacement -- CONTROLLER RULING R2.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import date, timedelta
from typing import Any, Literal, cast

from . import config, ledger, linkers
from .client import Client, JsonDict, OpenCTIError
from .config import Config, SelectionCfg, TextCfg
from .linkers.base import Creator, Linker, Resolved, Resolver
from .resolvers.actors import normalise
from .runstore import TextCache
from .text import article_text, description_text, plan_text_tier, title_similarity

CONNECTOR_NAME = "ImportExternalReference"
MARKDOWN_SUFFIX = ".md"
Log = Callable[[str], None]


@dataclass
class Selected:
    report_id: str
    name: str
    source: str
    description_chars: int
    text_tier: str  # one of text.TEXT_TIERS
    external_reference_id: str | None
    url: str | None
    host: str | None
    existing_files: list[str]


# --------------------------------------------------------------------- select


def _best_reference(node: JsonDict) -> tuple[JsonDict | None, str | None]:
    """The first external reference carrying a URL, plus its host."""
    refs = [e["node"] for e in node["externalReferences"]["edges"]]
    ref = next((r for r in refs if r.get("url")), None)
    host = urllib.parse.urlparse(str(ref["url"])).netloc if ref else None
    return ref, host


def _existing_files(ref: JsonDict | None) -> list[str]:
    if not ref:
        return []
    return [e["node"]["name"] for e in ref.get("importFiles", {}).get("edges", [])]


def _source_name(node: JsonDict) -> str:
    return (node.get("createdBy") or {}).get("name") or "<none>"


def _since_from_days(since_days: int) -> str:
    """ISO date `since_days` before today -- the default cutoff when the
    caller does not pass an explicit `since`."""
    return (date.today() - timedelta(days=since_days)).isoformat()


def _downgrade_fetch_tier(tier: str, *, host: str | None, source: str, cfg: TextCfg) -> str:
    """A "fetch" tier downgrades to "none" when config forbids fetching it.

    Two independent gates, either one enough: a non-empty host allowlist
    that this host is not on, or a source on the fetch-exclusion list.
    """
    if tier != "fetch":
        return tier
    if cfg.fetch_hosts and (host is None or host not in cfg.fetch_hosts):
        return "none"
    if source in cfg.fetch_exclude_sources:
        return "none"
    return tier


def _basic_skip(  # noqa: PLR0913 - keyword-only selection-loop gates, not a data clump
    node: JsonDict,
    *,
    since: str | None,
    empty_only: bool,
    sel: SelectionCfg,
    title_res: tuple[re.Pattern[str], ...],
    counts: dict[str, int],
) -> bool:
    """The gates that skip a report outright, before tier planning even
    starts. Split out of `_select_one` so each function stays under both
    the line-count and return-count caps."""
    if since is not None:
        published = str(node.get("published") or node.get("created") or "")
        if published < since:
            counts["old"] += 1
            return True
    if empty_only and node["objects"]["edges"]:
        return True
    source = _source_name(node)
    if sel.sources and source not in sel.sources:
        return True
    if source in sel.exclude_sources:
        counts["excluded_source"] += 1
        return True
    title = str(node.get("name") or "")
    if any(p.search(title) for p in title_res):
        counts["excluded_title"] += 1
        return True
    return False


def _select_one(  # noqa: PLR0913 - keyword-only selection-loop gates, not a data clump
    node: JsonDict,
    cfg: Config,
    cache: TextCache,
    *,
    since: str | None,
    empty_only: bool,
    sel: SelectionCfg,
    title_res: tuple[re.Pattern[str], ...],
    counts: dict[str, int],
) -> Selected | None:
    """One report -> a `Selected`, or None with the matching counter bumped."""
    if _basic_skip(node, since=since, empty_only=empty_only, sel=sel, title_res=title_res,
                    counts=counts):
        return None
    source = _source_name(node)
    ref, host = _best_reference(node)
    desc_len = len(node.get("description") or "")
    existing_files = _existing_files(ref)
    tier = plan_text_tier(
        description_chars=desc_len,
        has_stored_file=bool(existing_files),
        cached=cache.has(str(node["id"])),
        cfg=cfg.text,
    )
    downgraded = _downgrade_fetch_tier(tier, host=host, source=source, cfg=cfg.text)
    if downgraded != tier:
        counts["downgraded"] += 1
    tier = downgraded

    if tier == "none" and desc_len == 0:
        counts["no_text"] += 1
        return None

    return Selected(
        report_id=node["id"],
        name=node["name"],
        source=source,
        description_chars=desc_len,
        text_tier=tier,
        external_reference_id=ref["id"] if ref else None,
        url=ref["url"] if ref else None,
        host=host,
        existing_files=existing_files,
    )


def _log_select_summary(log: Log, counts: dict[str, int], since: str | None) -> None:
    if counts["old"]:
        log(f"  skipped {counts['old']} report(s) published before {since}")
    if counts["excluded_source"]:
        log(f"  skipped {counts['excluded_source']} report(s) from an excluded source")
    if counts["excluded_title"]:
        log(f"  skipped {counts['excluded_title']} report(s) matching an excluded title pattern")
    if counts["downgraded"]:
        log(f"  downgraded {counts['downgraded']} report(s) to text_tier=none (fetch not allowed)")
    if counts["no_text"]:
        log(f"  skipped {counts['no_text']} report(s) (no text)")


def select(  # noqa: PLR0913 - keyword-only selection options, not a data clump
    client: Client,
    cfg: Config,
    cache: TextCache,
    log: Log,
    *,
    linker_name: str,
    empty_only: bool,
    limit: int | None,
    since: str | None,
) -> list[Selected]:
    """Reports eligible for `linker_name`, newest first (report order is
    whatever `client.reports()` yields -- created_at desc per `REPORTS_Q`).

    `cache` sits right after `cfg`, matching `materialize_text`'s parameter
    order: both need the shared TextCache and both take it explicitly rather
    than building one from `cfg.cache_dir` internally, so a test can control
    (or inspect) cache state without touching the filesystem layout `Config`
    would otherwise dictate. See the task report for the full rationale.
    """
    if not isinstance(cfg, Config):
        raise TypeError("select: cfg must be a Config")
    if limit is not None and limit <= 0:
        raise ValueError("select: limit must be a positive int or None")
    linkers.get(linker_name)  # unknown name -> SystemExit; return value unused here

    sel = cfg.selection
    title_res = tuple(re.compile(p, re.IGNORECASE) for p in sel.exclude_title_patterns)
    since_value = since
    if since_value is None and sel.since_days > 0:
        since_value = _since_from_days(sel.since_days)

    out: list[Selected] = []
    counts = {"old": 0, "excluded_source": 0, "excluded_title": 0, "downgraded": 0, "no_text": 0}
    for node in client.reports():
        item = _select_one(
            node, cfg, cache,
            since=since_value, empty_only=empty_only, sel=sel,
            title_res=title_res, counts=counts,
        )
        if item is None:
            continue
        out.append(item)
        if limit and len(out) >= limit:
            break

    _log_select_summary(log, counts, since_value)
    return out


# ---------------------------------------------------------------------- fetch


def _validate_and_clean(
    raw: str, item: Selected, title_match_min: float, *, fetched: bool
) -> tuple[str | None, str]:
    """Return (clean text, status). Text is None when the capture is unusable.

    Shared by the "fetch" and "stored-file" tiers: whatever produced the
    markdown -- a fresh connector fetch or a file stored from an earlier
    run -- the guard against a mismatched article applies equally, since
    both paths ultimately hand the model text keyed off `item.name`.
    """
    similarity = title_similarity(item.name, raw)
    if similarity < title_match_min:
        headline = next((ln for ln in raw.splitlines() if ln.strip()), "")[:60]
        return None, f"title mismatch ({similarity:.2f}) — capture is {headline!r}"
    text = article_text(raw)
    verb = "fetched" if fetched else "stored-file"
    return text, f"{verb} ({len(raw)} -> {len(text)} chars, title {similarity:.2f})"


def _fetched_text(  # noqa: PLR0913,PLR0917 - one argument per fetch parameter, ported from octigeo
    client: Client, item: Selected, connector: str, text_cfg: TextCfg, log: Log, timeout: int
) -> tuple[str | None, str]:
    """Return (clean text, status) for a "fetch"-tier item."""
    files = client.external_reference_files(item.external_reference_id or "")
    if not any(str(f["name"]).endswith(MARKDOWN_SUFFIX) for f in files):
        if not files:
            client.ask_enrichment(item.external_reference_id or "", connector)
            log(f"  fetching {item.host} … {item.name[:58]}")
        files = client.wait_for_file(
            item.external_reference_id or "", timeout=timeout, suffix=MARKDOWN_SUFFIX
        )
    if not files:
        return None, "fetch timed out"

    markdown = next((f for f in files if str(f["name"]).endswith(MARKDOWN_SUFFIX)), None)
    if markdown is None:
        return None, f"no markdown (got {[f['name'] for f in files]})"

    raw = client.download(str(markdown["id"]))
    return _validate_and_clean(raw, item, text_cfg.title_match_min, fetched=True)


def _materialize_description(client: Client, cache: TextCache, item: Selected) -> str:
    node = client.report(item.report_id)
    text = description_text(str(node.get("description") or ""))
    cache.write(item.report_id, text)
    return f"description ({len(text)} chars)"


def _materialize_stored_file(
    client: Client, cache: TextCache, item: Selected, text_cfg: TextCfg
) -> str:
    """"stored-file" tier: download the existing .md importFile directly --
    no `ask_enrichment`/`wait_for_file`, the connector already ran."""
    files = client.external_reference_files(item.external_reference_id or "")
    markdown = next((f for f in files if str(f["name"]).endswith(MARKDOWN_SUFFIX)), None)
    if markdown is None:
        return f"no markdown (got {[f['name'] for f in files]})"
    raw = client.download(str(markdown["id"]))
    text, status = _validate_and_clean(raw, item, text_cfg.title_match_min, fetched=False)
    if text is not None:
        cache.write(item.report_id, text)
    return status


def _materialize_fetch(  # noqa: PLR0913,PLR0917 - one argument per fetch/cap parameter
    client: Client,
    cache: TextCache,
    item: Selected,
    text_cfg: TextCfg,
    log: Log,
    connector: str | None,
    timeout: int,
    max_fetch: int,
    fetch_count: int,
) -> tuple[str, int]:
    """Return (status, updated fetch_count) for a "fetch"-tier item.

    `fetch_count` is only incremented when the connector is actually asked
    to do something -- a cap hit or a missing connector never counts.
    """
    if max_fetch and fetch_count >= max_fetch:
        return "skipped (fetch cap)", fetch_count
    if not connector or not item.external_reference_id:
        return "skipped (no fetch)", fetch_count
    fetch_count += 1
    try:
        text, state = _fetched_text(client, item, connector, text_cfg, log, timeout)
    except OpenCTIError as exc:
        return f"error: {exc}"[:160], fetch_count
    if text is not None:
        cache.write(item.report_id, text)
    return state, fetch_count


def materialize_text(  # noqa: PLR0913 - client/cfg/cache/selection/log/timeout, not a data clump
    client: Client,
    cfg: Config,
    cache: TextCache,
    selection: list[Selected],
    log: Log,
    *,
    timeout: int = 180,
) -> dict[str, str]:
    """Ensure every selected report has clean article text in `cache`."""
    if not isinstance(cfg, Config):
        raise TypeError("materialize_text: cfg must be a Config")
    if timeout <= 0:
        raise ValueError("materialize_text: timeout must be positive")
    config.check_disk(cfg, log)

    connector = client.connector_id(CONNECTOR_NAME)
    if not connector:
        log(f"  ! connector {CONNECTOR_NAME} not active; fetch-backed reports skipped")

    max_fetch = cfg.text.max_fetch_per_run
    fetch_count = 0
    status: dict[str, str] = {}
    for item in selection:
        if cache.has(item.report_id):
            status[item.report_id] = "cached"
        elif item.text_tier == "description":
            status[item.report_id] = _materialize_description(client, cache, item)
        elif item.text_tier == "stored-file":
            status[item.report_id] = _materialize_stored_file(client, cache, item, cfg.text)
        elif item.text_tier == "fetch":
            state, fetch_count = _materialize_fetch(
                client, cache, item, cfg.text, log, connector, timeout, max_fetch, fetch_count
            )
            status[item.report_id] = state
        else:
            status[item.report_id] = "skipped (no fetch)"
    return status


# ---------------------------------------------------------------------- batch


def build_batch(cache: TextCache, selection: list[Selected]) -> list[JsonDict]:
    """Assemble the text packets a linker's extraction step reads."""
    if not isinstance(cache, TextCache):
        raise TypeError("build_batch: cache must be a TextCache")
    if not isinstance(selection, list):
        raise TypeError("build_batch: selection must be a list")
    batch: list[JsonDict] = []
    for item in selection:
        text = cache.read(item.report_id)
        if not text:
            continue
        batch.append(
            {
                "report_id": item.report_id,
                "title": item.name,
                "source": item.source,
                "url": item.url,
                "text": text,
            }
        )
    return batch


def to_dicts(selection: list[Selected]) -> list[JsonDict]:
    if not isinstance(selection, list):
        raise TypeError("to_dicts: selection must be a list")
    rows = [asdict(s) for s in selection]
    if len(rows) != len(selection):
        raise RuntimeError("to_dicts: row count mismatch")
    return rows


def from_dicts(rows: list[JsonDict]) -> list[Selected]:
    if not isinstance(rows, list):
        raise TypeError("from_dicts: rows must be a list")
    selection = [Selected(**r) for r in rows]
    if len(selection) != len(rows):
        raise RuntimeError("from_dicts: row count mismatch")
    return selection


# -------------------------------------------------------------------- validate

VALID_CONFIDENCE = ("high", "medium", "low")
AUTO_CONFIDENCE = "high"

# Both the reason string and the creatable gate are built from this, so they
# cannot drift apart.
UNRESOLVED_PREFIX = "unresolved "


def _entity_fields(item: JsonDict, resolved: Resolved) -> None:
    """Record the resolved entity on the item, under linker-neutral keys."""
    item["entity_id"] = resolved.id
    item["entity_name"] = resolved.name


def _chain_keys(item: JsonDict, linker: Linker) -> list[str]:
    """[key_field value, *alias_field values], empty entries dropped.

    Articles hand us the chain themselves -- "UNC6293 is a sub cluster of ICE
    RELIC (formerly APT29)" -- and the older name is usually the one the
    platform knows. Linkers with no alias_field yield a single-key chain.
    """
    keys = [str(item.get(linker.key_field) or "").strip()]
    if linker.alias_field:
        keys += [str(a).strip() for a in (item.get(linker.alias_field) or []) if str(a).strip()]
    return [k for k in keys if k]


def _resolve_chain(item: JsonDict, linker: Linker, resolver: Resolver) -> Resolved | None:
    """Try every key in the chain against the platform vocabulary in order."""
    for key in _chain_keys(item, linker):
        found = resolver.resolve(key)
        if found is not None:
            return found
    return None


def _crosswalk_chain(item: JsonDict, linker: Linker, resolver: Resolver) -> tuple[Resolved, str] | None:
    """Try every key in the chain against `resolver.crosswalk_resolve`.

    None immediately when the resolver has no such method -- most resolvers
    (location, sector, vuln) don't, and this is the only place that probes
    for it. Only ever consulted after `_resolve_chain` has already missed.
    """
    crosswalk_resolve = cast(
        "Callable[[str], tuple[Resolved, str] | None] | None",
        getattr(resolver, "crosswalk_resolve", None),
    )
    if crosswalk_resolve is None:
        return None
    for key in _chain_keys(item, linker):
        hit = crosswalk_resolve(key)
        if hit is not None:
            return hit
    return None


def _alias_writes(item: JsonDict, linker: Linker, resolved: Resolved) -> list[str]:
    """Chain names that are not already a known spelling of `resolved`.

    Candidates for `client.add_entity_alias` in `apply_containment`: a
    report calling APT29 "ICE RELIC" is new information worth recording as
    an alias, but "APT29" itself or a spelling the platform already lists
    is not.
    """
    known = {normalise(resolved.name)}
    known.update(normalise(a) for a in getattr(resolved, "aliases", ()))
    return [name for name in _chain_keys(item, linker) if normalise(name) not in known]


def _reasons_for(
    item: JsonDict, linker: Linker, resolver: Resolver, selection_ids: set[str], *, writeback: bool
) -> list[str]:
    """Every way this extraction is unwritable. Empty means it is well-formed.

    A crosswalk hit and the alias write-back derivation are both side
    effects on `item`, applied here rather than in `validate` because this
    is the only place holding the resolved entity.
    """
    reasons: list[str] = []

    if item.get("report_id") not in selection_ids:
        reasons.append("report not in this run's selection")

    resolved = _resolve_chain(item, linker, resolver)
    via_crosswalk: str | None = None
    if resolved is None:
        hit = _crosswalk_chain(item, linker, resolver)
        if hit is not None:
            resolved, via_crosswalk = hit
            item["via_crosswalk"] = via_crosswalk
            if str(item.get("confidence") or "").lower() == AUTO_CONFIDENCE:
                item["confidence"] = "medium"

    if resolved is None:
        key = str(item.get(linker.key_field) or "").strip()
        conflict = resolver.conflict(key) if isinstance(resolver, Creator) else None
        if conflict:
            reasons.append(f"exists as {conflict}")
        else:
            reasons.append(f"{UNRESOLVED_PREFIX}{linker.entity_kind.lower()} {key!r}")
    else:
        _entity_fields(item, resolved)
        if via_crosswalk is None and writeback and linker.alias_field:
            item["alias_writes"] = _alias_writes(item, linker, resolved)

    if str(item.get("role") or "").lower() not in linker.roles:
        reasons.append(f"invalid role {item.get('role')!r} (expected one of {sorted(linker.roles)})")

    if str(item.get("confidence") or "").lower() not in VALID_CONFIDENCE:
        reasons.append(f"invalid confidence {item.get('confidence')!r}")

    if not str(item.get("evidence") or "").strip():
        reasons.append("missing evidence quote")

    return reasons


def _hold(review: list[JsonDict], item: JsonDict, reasons: list[str], *, hard: bool) -> None:
    item["review_reasons"] = reasons
    item["hard_fail"] = hard
    review.append(item)


def validate(
    extractions: list[Any],
    resolver: Resolver,
    selection_ids: set[str],
    linker: Linker,
    *,
    writeback: bool = False,
) -> tuple[list[JsonDict], list[JsonDict]]:
    """Split extractions into auto-appliable and review-required.

    Nothing is silently dropped and no entity is ever created: an unresolvable
    key becomes a review item rather than a new entity. A non-dict item (a
    malformed extractor response) is held for review rather than raising,
    same rationale.

    Only one containment write per (report, entity). The same entity can
    legitimately appear twice in one report under different roles -- Russia is
    the actor in one supply-chain example and a victim in another within the
    same write-up -- but both collapse to the same objectRef, so the ledger
    keeps one row rather than two that look like a duplicate write.
    """
    if not isinstance(selection_ids, set):
        raise TypeError("validate: selection_ids must be a set")
    if not isinstance(extractions, list):
        raise TypeError("validate: extractions must be a list")

    auto: list[JsonDict] = []
    review: list[JsonDict] = []
    seen: set[tuple[str, str]] = set()

    for raw in extractions:
        if not isinstance(raw, dict):
            _hold(review, {"raw": raw}, ["extraction is not a JSON object"], hard=True)
            continue
        item = dict(raw)
        reasons = _reasons_for(item, linker, resolver, selection_ids, writeback=writeback)
        if reasons:
            # Creatable ONLY when unresolvability is the sole defect.
            # _reasons_for reports every defect an item has; being unresolved
            # is just one of them. Marking creatable on that branch alone let
            # --create-missing mint AND write items that were also missing
            # evidence, carried an invalid role, or named a report outside
            # this run's selection.
            if (
                len(reasons) == 1
                and reasons[0].startswith(UNRESOLVED_PREFIX)
                and isinstance(resolver, Creator)
            ):
                item["creatable"] = True
            # Hard failure: not writable at all. --include-review must never
            # promote these, only the judgement calls below.
            _hold(review, item, reasons, hard=True)
            continue

        key = (str(item.get("report_id", "")), str(item["entity_id"]))
        if key in seen:
            _hold(review, item, [f"duplicate (report, {linker.name}) — already written"], hard=True)
            continue
        seen.add(key)

        confidence = str(item["confidence"]).lower()
        if confidence == AUTO_CONFIDENCE:
            auto.append(item)
        else:
            hold_reasons = [f"confidence={confidence}"]
            if item.get("via_crosswalk"):
                hold_reasons.append(f"resolved via crosswalk cluster {item['via_crosswalk']!r}")
            _hold(review, item, hold_reasons, hard=False)

    return auto, review


def create_missing(
    resolver: Resolver,
    review: list[JsonDict],
    log: Log,
    *,
    dry_run: bool,
    linker: Linker,
) -> list[JsonDict]:
    """Mint entities for high-confidence unresolved items.

    Returns the items that are now writable. Everything else is left in the
    review queue untouched. A failed creation logs and leaves its item in
    review rather than aborting the run -- a half-written batch is recoverable,
    an aborted one that already minted entities is not.

    Gated on confidence deliberately: a permanent entity minted off a hedged
    guess is the failure mode most worth designing out.
    """
    if not isinstance(review, list):
        raise TypeError("create_missing: review must be a list")
    if not isinstance(resolver, Creator):
        return []

    promoted: list[JsonDict] = []
    for item in review:
        if not item.get("creatable"):
            continue
        if str(item.get("confidence", "")).lower() != AUTO_CONFIDENCE:
            continue
        # Read via linker.key_field, never a hard-coded "actor" -- the
        # ported octigeo bug this fixes: create_missing is only ever reached
        # on a Creator resolver's linker, but hard-coding one linker's key
        # field name here made a second creating linker mint under the wrong
        # key silently.
        name = str(item.get(linker.key_field) or "").strip()
        if not name:
            continue
        if dry_run:
            log(f"  would create {linker.entity_kind.lower()} {name}")
            continue
        aliases = list(item.get(linker.alias_field, []) or []) if linker.alias_field else []
        try:
            entity = resolver.create(name, aliases)
        except (OpenCTIError, ValueError, RuntimeError) as exc:
            log(f"  ! create {name}: {exc}"[:200])
            continue
        item["entity_id"] = entity.id
        item["entity_name"] = entity.name
        # The platform type actually minted (e.g. "Intrusion-Set"), NOT
        # linker.entity_kind ("Actor"): revert's delete_actor dispatches on
        # it, and a display-kind there makes every minted entity undeletable.
        item["entity_type"] = str(getattr(entity, "entity_type", "") or "")
        item["created"] = True
        item.pop("review_reasons", None)
        item.pop("hard_fail", None)
        item.pop("creatable", None)
        promoted.append(item)

    if any(not p.get("created") for p in promoted):
        raise RuntimeError("create_missing produced a promoted item without created=True")
    return promoted


# ----------------------------------------------------------------------- apply


def _apply_write(  # noqa: PLR0913 - client/rid/entity id/label state/dry_run, not a data clump
    client: Client, rid: str, entity_id: str, label_id: str | None, labelled: set[str], *, dry_run: bool
) -> str | None:
    """Add the object to the report and, once per report, its label.

    Returns the label_id that ended up on this row -- None when dry-run (no
    client call at all, port of the octigeo pattern) or when this run isn't
    labelling.
    """
    if dry_run:
        return None
    client.add_object_to_report(rid, entity_id)
    if label_id and rid not in labelled:
        client.add_label_to_report(rid, label_id)
        labelled.add(rid)
    return label_id if rid in labelled else None


def _apply_item_aliases(  # noqa: PLR0913,PLR0917 - client/item/entity id+name/cache/log, not a data clump
    client: Client,
    item: JsonDict,
    entity_id: str,
    entity_name: str,
    cache: dict[str, set[str]],
    log: Log,
    *,
    dry_run: bool,
) -> list[JsonDict]:
    """Write `item["alias_writes"]` to `entity_id`, returning alias ledger rows.

    `cache` holds each entity's known aliases (casefold-normalised), read
    once per entity via `client.entity_aliases` and updated as aliases are
    added within this run, so a second item for the same entity never
    re-queries. Dry-run makes no client call at all -- port of the octigeo
    pattern -- and predicts every write as not-preexisting.
    """
    evidence = str(item.get("evidence") or "")
    aliases = list(item.get("alias_writes") or [])
    if dry_run:
        return [
            ledger.alias_row(
                entity_id=entity_id, entity_name=entity_name, alias=alias,
                preexisted=False, evidence=evidence,
            )
            for alias in aliases
        ]

    if entity_id not in cache:
        try:
            cache[entity_id] = {a.casefold() for a in client.entity_aliases(entity_id)}
        except OpenCTIError as exc:
            log(f"  ! entity_aliases {entity_name}: {exc}"[:200])
            return []
    known = cache[entity_id]

    rows: list[JsonDict] = []
    for alias in aliases:
        if alias.casefold() in known:
            rows.append(ledger.alias_row(
                entity_id=entity_id, entity_name=entity_name, alias=alias,
                preexisted=True, evidence=evidence,
            ))
            continue
        try:
            client.add_entity_alias(entity_id, alias)
        except OpenCTIError as exc:
            log(f"  ! alias {alias} -> {entity_name}: {exc}"[:200])
            continue
        known.add(alias.casefold())
        rows.append(ledger.alias_row(
            entity_id=entity_id, entity_name=entity_name, alias=alias,
            preexisted=False, evidence=evidence,
        ))
    return rows


def _apply_one(  # noqa: PLR0913,PLR0917 - client/item/linker/label state/alias cache/log, not a data clump
    client: Client,
    item: JsonDict,
    linker: Linker,
    label_id: str | None,
    labelled: set[str],
    seen_entities: set[str],
    alias_cache: dict[str, set[str]],
    log: Log,
    *,
    dry_run: bool,
) -> list[JsonDict]:
    """Apply one approved item: containment row, plus entity/alias rows."""
    entity_id = str(item.get("entity_id") or "")
    entity_name = str(item.get("entity_name") or entity_id)
    rid = str(item.get("report_id") or "")
    if not entity_id or not rid:
        raise OpenCTIError(f"approved item has no entity/report id: {str(item)[:160]}")
    created_type = str(item.get("entity_type") or "")
    if item.get("created") and not created_type:
        raise OpenCTIError(f"created item has no minted entity_type: {str(item)[:160]}")

    try:
        row_label = _apply_write(client, rid, entity_id, label_id, labelled, dry_run=dry_run)
    except OpenCTIError as exc:
        log(f"  ! {entity_name} -> {rid}: {exc}"[:200])
        return []

    rows: list[JsonDict] = [ledger.containment_row(
        report_id=rid, entity_id=entity_id, entity_name=entity_name, linker=linker.name,
        key=str(item.get(linker.key_field) or ""), role=str(item.get("role") or ""),
        confidence=str(item.get("confidence") or ""), evidence=str(item.get("evidence") or ""),
        label_id=row_label, created=bool(item.get("created")),
    )]

    if item.get("created") and entity_id not in seen_entities:
        seen_entities.add(entity_id)
        rows.append(ledger.entity_row(entity_id=entity_id, entity_type=created_type, name=entity_name))

    if item.get("alias_writes") and str(item.get("confidence") or "").lower() == AUTO_CONFIDENCE:
        rows.extend(
            _apply_item_aliases(client, item, entity_id, entity_name, alias_cache, log, dry_run=dry_run)
        )
    return rows


def apply_containment(  # noqa: PLR0913 - client/approved/log/linker/cfg/dry_run, not a data clump
    client: Client, approved: list[JsonDict], log: Log, linker: Linker, cfg: Config, *, dry_run: bool
) -> list[JsonDict]:
    """Add each resolved entity to its report's objectRefs (containment).

    Also writes back any derived aliases (`validate`'s `alias_writes`) and
    ledgers newly created entities, so a single `apply_containment` call
    produces every row kind `revert_containment`/`revert_aliases`/
    `purge_created` need to undo this run.
    """
    if not isinstance(approved, list):
        raise TypeError("apply_containment: approved must be a list")
    if not isinstance(cfg, Config):
        raise TypeError("apply_containment: cfg must be a Config")

    label = cfg.label(linker.label_suffix)
    label_id = client.ensure_label(label, cfg.labels.color) if not dry_run else None

    rows: list[JsonDict] = []
    labelled: set[str] = set()
    seen_entities: set[str] = set()
    alias_cache: dict[str, set[str]] = {}
    for item in approved:
        rows.extend(_apply_one(
            client, item, linker, label_id, labelled, seen_entities, alias_cache, log, dry_run=dry_run
        ))

    if any(not isinstance(r, dict) for r in rows):
        raise RuntimeError("apply_containment produced a non-dict row")
    return rows


# ---------------------------------------------------------------------- revert


def revert_containment(
    client: Client, rows: list[JsonDict], log: Log, *, dry_run: bool = False,
    retain: list[JsonDict] | None = None,
) -> int:
    """Undo `apply_containment`'s `"containment"` rows: strip the objectRef
    and, the first time each report's label is seen, its label too.

    A row whose undo raised is appended to `retain` (when given): the write
    is still on the platform and still ours, so the caller keeps it in the
    ledger for a retry instead of forgetting it.
    """
    if not isinstance(rows, list):
        raise TypeError("revert_containment: rows must be a list")
    failed = retain if retain is not None else []

    reverted = 0
    seen_labels: set[tuple[str, str]] = set()
    for row in rows:
        if row.get("kind") != "containment":
            continue
        entity_id = str(row.get("entity_id") or "")
        entity_name = str(row.get("entity_name") or entity_id)
        rid = str(row.get("report_id") or "")
        if not entity_id or not rid:
            raise OpenCTIError(f"containment row has no entity/report id: {str(row)[:160]}")
        if dry_run:
            log(f"  would remove {entity_name} from {rid}")
            reverted += 1
            continue
        try:
            client.remove_object_from_report(rid, entity_id)
            label_id = row.get("label_id")
            if label_id and (rid, str(label_id)) not in seen_labels:
                client.remove_label_from_report(rid, str(label_id))
                seen_labels.add((rid, str(label_id)))
            reverted += 1
        except OpenCTIError as exc:
            log(f"  ! revert {rid}: {exc}"[:200])
            failed.append(row)

    if reverted > len(rows):
        raise RuntimeError("revert_containment reverted more rows than it was given")
    return reverted


def revert_aliases(
    client: Client, rows: list[JsonDict], log: Log, *, dry_run: bool = False,
    retain: list[JsonDict] | None = None,
) -> int:
    """Undo `apply_containment`'s `"alias"` rows.

    A preexisted alias is left alone -- it was on the platform before this
    run touched it, so removing it would destroy data this run doesn't own.
    A row whose removal raised is appended to `retain` (see
    `revert_containment`).
    """
    if not isinstance(rows, list):
        raise TypeError("revert_aliases: rows must be a list")
    failed = retain if retain is not None else []

    reverted = 0
    for row in rows:
        if row.get("kind") != "alias":
            continue
        entity_id = str(row.get("entity_id") or "")
        alias = str(row.get("alias") or "")
        if not entity_id or not alias:
            raise OpenCTIError(f"alias row has no entity id/alias: {str(row)[:160]}")
        name = str(row.get("entity_name") or entity_id)
        if row.get("preexisted"):
            log(f"  keep {alias} on {name} (pre-existing)")
            continue
        if dry_run:
            log(f"  would remove alias {alias} from {name}")
            reverted += 1
            continue
        try:
            client.remove_entity_alias(entity_id, alias)
            reverted += 1
        except OpenCTIError as exc:
            log(f"  ! revert alias {alias}: {exc}"[:200])
            failed.append(row)

    if reverted > len(rows):
        raise RuntimeError("revert_aliases reverted more rows than it was given")
    return reverted


def _purge_decide_one(  # noqa: PLR0913 - client/target/own_refs/log/dry_run/label/type, not a clump
    client: Client,
    target: tuple[str, str],
    own_refs: int,
    log: Log,
    *,
    dry_run: bool,
    label: str,
    entity_type: str,
) -> Literal["deleted", "adopted", "retained"] | None:
    """Inspect and, if orphaned, delete a single created entity.

    `target` is (entity_id, name). Returns "deleted"; "adopted" (kept because
    it no longer carries our label -- no longer ours, nothing to retry);
    "retained" (kept but still ours: still referenced, or inspection/delete
    failed -- a later revert should try again); or None if the entity is
    already gone (which counts as neither, so a second revert is idempotent).
    """
    entity_id, name = target
    try:
        labels = client.entity_labels(entity_id)
        if not labels:
            log(f"  {name}: already gone")
            return None
        relationships, containers = client.entity_reference_counts(entity_id)
    except OpenCTIError as exc:
        log(f"  ! inspect {name}: {exc}"[:200])
        return "retained"

    # In a dry run, revert_containment() has NOT stripped our objectRefs
    # yet, so the container count still includes them and the entity looks
    # referenced. Discount our own so the prediction matches what a real
    # revert will decide -- otherwise --dry-run reports "would delete 0" and
    # the real run then deletes, which is the dangerous direction for the
    # safety mechanism of a destructive command to be wrong in.
    if dry_run:
        containers = max(0, containers - own_refs)

    labelled = label in labels
    ok, why = ledger.should_delete_entity(
        labelled=labelled, relationships=relationships, containers=containers
    )
    if not ok:
        log(f"  kept {name}: {why}")
        return "retained" if labelled else "adopted"
    if dry_run:
        log(f"  would delete {name}: {why}")
        return "deleted"
    try:
        client.delete_actor(entity_type, entity_id)
    except OpenCTIError as exc:
        log(f"  ! delete {name}: {exc}"[:200])
        return "retained"
    else:
        return "deleted"


def purge_created(  # noqa: PLR0913 - client/rows/log/dry_run/label/entity_types, not a data clump
    client: Client,
    rows: list[JsonDict],
    log: Log,
    *,
    dry_run: bool,
    label: str,
    entity_types: dict[str, str],
    retain: list[JsonDict] | None = None,
) -> tuple[int, int]:
    """Delete entities this run created, but only while they stay orphaned.

    MUST run after revert_containment() has stripped objectRefs for the real
    delete path: while our own refs are still in place the container count
    is never zero and nothing would ever be eligible. A dry run discounts
    `own_refs` instead (see `_purge_decide_one`), so its prediction still
    matches what the real run will do even though nothing has actually been
    stripped yet.

    `rows` supplies two things: `"entity"` rows name the targets (one per
    entity `apply_containment` minted), and `"containment"` rows with
    `created=True` count each entity's own-report references for the
    dry-run discount above.

    `label` is the label minting stamps (`cfg.label("Created")`), not the
    run's linker label. An entity kept while still ours (still referenced,
    or inspection/delete failed) has its `"entity"` row appended to `retain`
    (when given), so the caller keeps it in the ledger for a later revert.
    """
    if not isinstance(rows, list):
        raise TypeError("purge_created: rows must be a list")
    if not label:
        raise ValueError("purge_created: label must be non-empty")

    targets = {str(row["entity_id"]): row for row in rows if row.get("kind") == "entity"}
    own_refs: dict[str, int] = {}
    for row in rows:
        if row.get("kind") == "containment" and row.get("created"):
            entity_id = str(row.get("entity_id") or "")
            own_refs[entity_id] = own_refs.get(entity_id, 0) + 1

    deleted = kept = 0
    for entity_id, target_row in targets.items():
        name = str(target_row.get("name") or entity_id)
        entity_type = entity_types.get(entity_id)
        if entity_type is None:
            raise OpenCTIError(f"purge_created: no entity_type given for {name} ({entity_id})")
        outcome = _purge_decide_one(
            client, (entity_id, name), own_refs.get(entity_id, 0), log,
            dry_run=dry_run, label=label, entity_type=entity_type,
        )
        if outcome == "deleted":
            deleted += 1
        elif outcome is not None:
            kept += 1
            if outcome == "retained" and retain is not None:
                retain.append(target_row)

    if deleted + kept > len(targets):
        raise RuntimeError("purge_created counted more outcomes than targets")
    return deleted, kept
