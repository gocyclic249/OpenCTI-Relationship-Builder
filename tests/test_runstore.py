import json

import pytest

from octirb.runstore import Run, TextCache, new_run_id


def make_run(runs_dir, name, created):
    d = runs_dir / name
    d.mkdir(parents=True)
    (d / "meta.json").write_text(
        json.dumps({"created": created, "linker": "report-location"}), encoding="utf-8"
    )
    return d


def test_latest_by_created_not_name(tmp_path):
    make_run(tmp_path, "zzz-named-run", "2026-01-01T00:00:00Z")
    make_run(tmp_path, "20260901T000000Z", "2026-09-01T00:00:00Z")
    run = Run.latest(tmp_path)
    assert run is not None and run.run_id == "20260901T000000Z"


def test_latest_skips_dir_without_meta(tmp_path):
    (tmp_path / "stray").mkdir()
    make_run(tmp_path, "real", "2026-09-01T00:00:00Z")
    assert Run.latest(tmp_path).run_id == "real"


def test_open_unknown_run_exits(tmp_path):
    with pytest.raises(SystemExit):
        Run.open(tmp_path, "missing")


def test_linker_from_meta(tmp_path):
    Run(make_run(tmp_path, "r1", "2026-09-01T00:00:00Z"))
    assert Run.open(tmp_path, "r1").linker() == "report-location"


def test_open_none_returns_latest(tmp_path):
    make_run(tmp_path, "old", "2026-01-01T00:00:00Z")
    make_run(tmp_path, "new", "2026-09-01T00:00:00Z")
    run = Run.open(tmp_path, None)
    assert run.run_id == "new"


def test_text_cache_roundtrip(tmp_path):
    cache = TextCache(tmp_path)
    assert cache.read("rep-1") is None
    cache.write("rep-1", "article body")
    assert cache.read("rep-1") == "article body"
    assert cache.has("rep-1")


def test_text_cache_rejects_traversal(tmp_path):
    with pytest.raises((ValueError, SystemExit)):
        TextCache(tmp_path).write("../evil", "x")


def test_new_run_id_shape():
    assert len(new_run_id()) == 16 and new_run_id().endswith("Z")
