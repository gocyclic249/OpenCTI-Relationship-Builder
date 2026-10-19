"""Per-item acceptance of review-queue items.

`validate` splits extractions into auto.json and review.json; historically
`apply --include-review` wrote *every* non-`hard_fail` review item, so the
only way to accept some and not others was to edit review.json by hand.
`picks.json` makes that choice explicit and durable: it lists the keys of
the review items the operator accepted. The TUI's review screen writes it;
`apply --include-review` honours it when present and falls back to the old
all-soft-items behaviour when absent.

Items carry no stable id, so the key is a digest of the item's content
minus validate's bookkeeping fields (`review_reasons`, `hard_fail`). A
re-run of `validate` over unchanged extractions reproduces the same keys,
so picks survive re-validation; a corrected extraction gets a new key and
must be picked again, which is the right default.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

    from .runstore import Run

JsonDict = dict[str, Any]
PICKS_FILE = "picks.json"
KEY_LENGTH = 16
_BOOKKEEPING = frozenset({"review_reasons", "hard_fail"})


def item_key(item: JsonDict) -> str:
    """A content digest of a review item, stable across re-validation."""
    if not isinstance(item, dict):
        raise TypeError("item_key: item must be a dict")
    body = {k: v for k, v in item.items() if k not in _BOOKKEEPING}
    canon = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    key = hashlib.sha256(canon.encode("utf-8")).hexdigest()[:KEY_LENGTH]
    if len(key) != KEY_LENGTH:
        raise RuntimeError("item_key: digest truncated unexpectedly")
    return key


def review_to_apply(review: list[JsonDict], accepted: set[str] | None) -> list[JsonDict]:
    """The review items `--include-review` may write.

    `hard_fail` items are never eligible, picked or not. With `accepted`
    None (no picks.json) every soft item is eligible; with a set, only the
    soft items whose key is in it.
    """
    if not isinstance(review, list):
        raise TypeError("review_to_apply: review must be a list")
    if accepted is not None and not isinstance(accepted, set):
        raise TypeError("review_to_apply: accepted must be a set or None")
    soft = [r for r in review if isinstance(r, dict) and not r.get("hard_fail")]
    if accepted is None:
        return soft
    chosen = [r for r in soft if item_key(r) in accepted]
    if len(chosen) > len(soft):
        raise RuntimeError("review_to_apply: picked more items than exist")
    return chosen


def load_picks(run: Run) -> set[str] | None:
    """The accepted keys from picks.json, or None when the run has no picks."""
    if not run.has(PICKS_FILE):
        return None
    data = run.read_json(PICKS_FILE)
    accepted = data.get("accepted") if isinstance(data, dict) else None
    if not isinstance(accepted, list) or not all(isinstance(k, str) for k in accepted):
        raise SystemExit(f"{run.root / PICKS_FILE} is corrupt; expected {{\"accepted\": [str, ...]}}")
    return set(accepted)


def save_picks(run: Run, accepted: set[str]) -> Path:
    """Write picks.json (sorted, so diffs are stable) and return its path."""
    if not isinstance(accepted, set):
        raise TypeError("save_picks: accepted must be a set")
    path = run.write_json(PICKS_FILE, {"accepted": sorted(accepted)})
    if not path.is_file():
        raise OSError(f"save_picks: {path} missing after write")
    return path
