"""Coverage for octirb/picks.py: per-item review acceptance.

`picks.json` in a run dir names which non-hard_fail review items
`apply --include-review` may write. Without the file, every non-hard_fail
item is eligible (the pre-TUI behaviour).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from octirb import picks
from octirb.runstore import Run


def item(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "report_id": "r1", "entity_id": "e1", "entity_name": "France", "iso3": "FRA",
        "role": "target", "confidence": "medium", "evidence": "q", "title": "t",
        "review_reasons": ["confidence=medium"], "hard_fail": False,
    }
    base.update(over)
    return base


def test_item_key_ignores_review_bookkeeping() -> None:
    a = item(review_reasons=["x"], hard_fail=False)
    b = item(review_reasons=["y", "z"], hard_fail=True)
    assert picks.item_key(a) == picks.item_key(b)


def test_item_key_differs_on_content() -> None:
    assert picks.item_key(item(entity_id="e1")) != picks.item_key(item(entity_id="e2"))


def test_item_key_rejects_non_dict() -> None:
    with pytest.raises(TypeError):
        picks.item_key(["not", "a", "dict"])  # type: ignore[arg-type]


def test_review_to_apply_without_picks_keeps_every_soft_item() -> None:
    review = [item(entity_id="e1"), item(entity_id="e2", hard_fail=True)]
    assert [r["entity_id"] for r in picks.review_to_apply(review, None)] == ["e1"]


def test_review_to_apply_with_picks_keeps_only_accepted() -> None:
    review = [item(entity_id="e1"), item(entity_id="e2"), item(entity_id="e3", hard_fail=True)]
    accepted = {picks.item_key(review[1]), picks.item_key(review[2])}
    assert [r["entity_id"] for r in picks.review_to_apply(review, accepted)] == ["e2"]


def test_review_to_apply_with_empty_picks_applies_nothing() -> None:
    assert picks.review_to_apply([item()], set()) == []


def test_save_and_load_roundtrip(tmp_path: Path) -> None:
    run = Run(tmp_path / "r1")
    assert picks.load_picks(run) is None
    picks.save_picks(run, {"b", "a"})
    assert picks.load_picks(run) == {"a", "b"}
    assert json.loads((run.root / picks.PICKS_FILE).read_text())["accepted"] == ["a", "b"]


def test_load_rejects_malformed_file(tmp_path: Path) -> None:
    run = Run(tmp_path / "r1")
    (run.root / picks.PICKS_FILE).write_text(json.dumps({"accepted": "not-a-list"}))
    with pytest.raises(SystemExit):
        picks.load_picks(run)
