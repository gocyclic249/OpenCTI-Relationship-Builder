"""Coverage for pipeline.py part 1: select, fetch (materialize_text), batch.

`report_node()` builds a node in the exact shape `client.py`'s `REPORTS_Q`
returns (no fixture for this existed under opencti-docker/tests/, so it is
written fresh here). `FakeClient` only implements `reports()` for the
`select()` tests -- plus fetch methods that raise if called at all, so
`test_cached_text_never_fetches` is a real regression guard rather than a
tautology. `FetchFake` (materialize_text tests) is given verbatim by the
Task 11 brief.
"""

from __future__ import annotations

import dataclasses
from typing import Any

import pytest

from octirb.config import Config, SelectionCfg, TextCfg
from octirb.pipeline import Selected, build_batch, materialize_text, select
from octirb.runstore import TextCache

# A registered, needs_model=False linker keeps these tests from having to
# stand up a resolver/vocabulary just to pass select()'s linker_name check.
LINKER = "report-vuln"


def report_node(
    rid: str,
    name: str,
    source: str,
    desc_len: int,
    host: str | None = "example.com",
    *,
    published: str = "2020-01-01",
    import_files: tuple[str, ...] = (),
    has_objects: bool = False,
) -> dict[str, Any]:
    """A `client.reports()` node, shaped like `client.py`'s `REPORTS_Q`."""
    files_edges = [{"node": {"id": f"f-{n}", "name": n, "size": 10}} for n in import_files]
    refs_edges = []
    if host is not None:
        refs_edges.append(
            {
                "node": {
                    "id": f"ref-{rid}",
                    "url": f"https://{host}/a",
                    "source_name": source,
                    "importFiles": {"edges": files_edges},
                }
            }
        )
    return {
        "id": rid,
        "name": name,
        "description": "x" * desc_len,
        "created": published,
        "published": published,
        "createdBy": {"name": source} if source else None,
        "objectLabel": [],
        "objects": {"edges": [{"node": {"entity_type": "Country"}}] if has_objects else []},
        "externalReferences": {"edges": refs_edges},
    }


class FakeClient:
    """Yields canned nodes from `reports()`; fetch methods must never be
    called by `select()` -- calling one is a bug, not a valid path."""

    def __init__(self, nodes: list[dict[str, Any]]) -> None:
        self._nodes = nodes

    def reports(self):
        return iter(self._nodes)

    def ask_enrichment(self, *_a: Any, **_k: Any) -> str:
        raise AssertionError("select() must never call ask_enrichment")

    def wait_for_file(self, *_a: Any, **_k: Any) -> list[Any]:
        raise AssertionError("select() must never call wait_for_file")

    def download(self, *_a: Any, **_k: Any) -> str:
        raise AssertionError("select() must never call download")


def _cfg(**overrides: Any) -> Config:
    """Config() with since_days disabled (0) so `published` fixtures never
    need to track "today" -- no test here exercises the since-default path."""
    base = Config(selection=SelectionCfg(since_days=0))
    return dataclasses.replace(base, **overrides)


def _select(nodes: list[dict[str, Any]], cache_dir, cfg: Config | None = None, **kwargs: Any):
    client = FakeClient(nodes)
    cache = TextCache(cache_dir)
    cfg = cfg if cfg is not None else _cfg()
    opts = {"linker_name": LINKER, "empty_only": True, "limit": None, "since": None, **kwargs}
    return select(client, cfg, cache, lambda _m: None, **opts)


# --------------------------------------------------------------------- select


def test_all_sources_when_config_empty(tmp_path):
    nodes = [
        report_node("r1", "First", "Source A", 3000),
        report_node("r2", "Second", "Source B", 3000),
    ]
    result = _select(nodes, tmp_path)
    assert {s.report_id for s in result} == {"r1", "r2"}


def test_exclude_sources_skipped(tmp_path):
    nodes = [
        report_node("r1", "Good", "Good Source", 3000),
        report_node("r2", "Bad", "Bad Source", 3000),
    ]
    cfg = _cfg(selection=SelectionCfg(since_days=0, exclude_sources=("Bad Source",)))
    result = _select(nodes, tmp_path, cfg=cfg)
    assert [s.report_id for s in result] == ["r1"]


def test_exclude_title_pattern_skips_stormcast(tmp_path):
    nodes = [
        report_node("r1", "ISC Stormcast For Monday", "SANS", 3000),
        report_node("r2", "ISC diary", "SANS", 3000),
    ]
    cfg = _cfg(selection=SelectionCfg(since_days=0, exclude_title_patterns=("^ISC Stormcast",)))
    result = _select(nodes, tmp_path, cfg=cfg)
    assert [s.report_id for s in result] == ["r2"]


def test_fetch_exclude_source_downgrades_to_none(tmp_path):
    node = report_node("r1", "Some Attack", "Bleeping Computer", 100, host="bleepingcomputer.com")
    cfg = _cfg(text=TextCfg(fetch_exclude_sources=("Bleeping Computer",)))
    result = _select([node], tmp_path, cfg=cfg)
    assert len(result) == 1
    assert result[0].text_tier == "none"


def test_fetch_host_allowlist_downgrades(tmp_path):
    node = report_node("r1", "Some Attack", "Some Source", 100, host="b.com")
    cfg = _cfg(text=TextCfg(fetch_hosts=("a.com",)))
    result = _select([node], tmp_path, cfg=cfg)
    assert len(result) == 1
    assert result[0].text_tier == "none"


def test_tier_recorded_on_selected(tmp_path):
    long_desc = Config().text.fulltext_min_chars
    node = report_node("r1", "Long Report", "Some Source", long_desc)
    result = _select([node], tmp_path)
    assert len(result) == 1
    assert result[0].text_tier == "description"


def test_cached_text_never_fetches(tmp_path):
    node = report_node("r1", "Short Report", "Some Source", 100, host="c.com")
    cache = TextCache(tmp_path)
    cache.write("r1", "already have this")
    client = FakeClient([node])
    cfg = _cfg()
    result = select(
        client, cfg, cache, lambda _m: None,
        linker_name=LINKER, empty_only=True, limit=None, since=None,
    )
    assert len(result) == 1
    assert result[0].text_tier == "cache"
    # FakeClient's fetch methods raise if called; reaching here means they
    # never were.


# -------------------------------------------------------------- materialize


def selected(rid, title="Attack on X"):
    return Selected(
        report_id=rid, name=title, source="Bleeping Computer", description_chars=100,
        text_tier="fetch", external_reference_id=f"ref-{rid}",
        url=f"https://x/{rid}", host="x", existing_files=[],
    )


class FetchFake:
    def __init__(self):
        self.enrichments: list[str] = []

    def connector_id(self, name):
        return "conn-1"

    def external_reference_files(self, ref_id):
        return []

    def ask_enrichment(self, ref_id, connector_id):
        self.enrichments.append(ref_id)
        return "work-1"

    def wait_for_file(self, ref_id, timeout=180, poll=5, suffix=None):
        return [{"id": "f1", "name": "a.md", "size": 1}]

    def download(self, file_id):
        return "# Attack on X\n" + "prose sentence here. " * 200


def test_fetch_cap_marks_remaining_skipped(tmp_path, monkeypatch):
    cfg = dataclasses.replace(Config(), text=TextCfg(max_fetch_per_run=1))
    monkeypatch.setattr("octirb.config.check_disk", lambda _c, _l: None)
    client, cache = FetchFake(), TextCache(tmp_path)
    status = materialize_text(client, cfg, cache, [selected("r1"), selected("r2")], lambda _m: None)  # type: ignore[arg-type]
    assert len(client.enrichments) == 1
    assert status["r2"] == "skipped (fetch cap)"
    assert cache.read("r1") is not None and cache.read("r2") is None


def test_materialize_calls_check_disk_once(tmp_path, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr("octirb.config.check_disk", lambda _c, _l: calls.append("called"))
    client, cache = FetchFake(), TextCache(tmp_path)
    materialize_text(client, Config(), cache, [], lambda _m: None)
    assert calls == ["called"]


def test_materialize_rejects_nonpositive_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr("octirb.config.check_disk", lambda _c, _l: None)
    client, cache = FetchFake(), TextCache(tmp_path)
    with pytest.raises(ValueError, match="timeout"):
        materialize_text(client, Config(), cache, [], lambda _m: None, timeout=0)


def test_one_failed_stored_file_does_not_abort_the_loop(tmp_path, monkeypatch):
    """I2: a 404 on one stored file becomes that item's status; the next
    report is still materialized and a status map is still returned."""
    from octirb.client import OpenCTIError

    class StoredFake(FetchFake):
        def external_reference_files(self, ref_id):
            return [{"id": f"f-{ref_id}", "name": "a.md", "size": 1}]

        def download(self, file_id):
            if file_id == "f-ref-r1":
                raise OpenCTIError("HTTP Error 404")
            return super().download(file_id)

    monkeypatch.setattr("octirb.config.check_disk", lambda _c, _l: None)
    items = [dataclasses.replace(selected(r), text_tier="stored-file") for r in ("r1", "r2")]
    cache = TextCache(tmp_path)
    status = materialize_text(StoredFake(), Config(), cache, items, lambda _m: None)  # type: ignore[arg-type]
    assert status["r1"].startswith("error:")
    assert cache.read("r2") is not None


# -------------------------------------------------------------------- batch


def test_build_batch_reads_from_cache(tmp_path):
    cache = TextCache(tmp_path)
    cache.write("r1", "clean article text")
    item = selected("r1", title="Attack on X")
    batch = build_batch(cache, [item])
    assert batch == [
        {
            "report_id": "r1",
            "title": "Attack on X",
            "source": "Bleeping Computer",
            "url": "https://x/r1",
            "text": "clean article text",
        }
    ]


def test_build_batch_skips_uncached_items(tmp_path):
    cache = TextCache(tmp_path)
    item = selected("r1")
    assert build_batch(cache, [item]) == []
