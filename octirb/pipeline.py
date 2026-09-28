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

The validate/apply/revert half of octigeo's pipeline.py is out of scope here
(Task 12) -- octi-rb's write path is a different shape (containment AND
relationship linkers) and belongs with the linker registry, not this module.

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

from . import config, linkers
from .client import Client, JsonDict, OpenCTIError
from .config import Config, SelectionCfg, TextCfg
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
