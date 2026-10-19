"""Curses-free model behind the TUI: steps, run inspection, argv, picks.

Nothing here touches the terminal or the platform; it reads run directories
and builds argv lists for runner.py. The screen layer only paints what
these functions return.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import picks
from ..linkers import REGISTRY
from ..runstore import Run

JsonDict = dict[str, Any]

# Pipeline order, not alphabetical: the first entry is the form's default.
LINKERS: tuple[str, ...] = (
    "report-location", "report-sector", "report-actor", "report-vuln", "report-labels", "actor-target",
)
if set(LINKERS) != set(REGISTRY):
    raise RuntimeError("tui.state: LINKERS is out of step with linkers.REGISTRY")
SOURCES: tuple[str, ...] = ("description", "report")
DONE = "done"
TODO = "todo"
NEUTRAL = "-"
MAX_RUNS_LISTED = 500
COUNT_FILES: tuple[str, ...] = ("selection", "extractions", "auto", "review", "applied")


@dataclass(frozen=True)
class Step:
    key: str
    label: str
    kind: str  # "command" | "form" | "screen" | "info" | "wave"
    hint: str


_ALL_STEPS: tuple[Step, ...] = (
    Step("select", "select      new run", "form", "pick a linker and selection options"),
    Step("fetch", "fetch       article text -> cache", "command", "materialize report text"),
    Step("batch", "batch       batch.json + CONTRACT.md", "command", "prepare the model input"),
    Step("structured", "structured  fixed-field parsers (opt)", "command",
         "parse fixed-field publishers such as CISA advisories"),
    Step("extract", "extract     Claude writes extractions", "info", "runs claude -p in the background"),
    Step("validate", "validate    -> auto.json / review.json", "command", "check every extraction"),
    Step("review", "review      tick medium/low to accept", "screen", "writes picks.json"),
    Step("apply-dry", "apply       --dry-run", "command", "preview writes, no mutation"),
    Step("apply", "apply       WRITE to platform", "command", "writes auto.json plus accepted picks"),
    Step("revert-dry", "revert      --dry-run", "command", "preview the undo"),
    Step("revert", "revert      UNDO this run's writes", "command", "replays applied.json"),
    Step("doctor", "doctor      config + connectivity", "command", "not run-scoped"),
    Step("status", "status      all runs", "command", "not run-scoped"),
    Step("wave1", "wave 1      UPDATE ALL loc/sec/act/vuln", "wave",
         "new run per linker, select -> validate, never applies (key 1)"),
    Step("wave2", "wave 2      UPDATE ALL labels/actor-tgt", "wave",
         "after wave 1 is applied: labels + actor-target on its reports (key 2)"),
)
_RUN_FREE: frozenset[str] = frozenset({"select", "doctor", "status", "wave1", "wave2"})
_STEP_BY_KEY: dict[str, Step] = {s.key: s for s in _ALL_STEPS}


def _skipped_for(linker: str) -> frozenset[str]:
    if linker == "report-vuln":
        return frozenset({"structured", "extract"})
    if linker == "report-labels":
        return frozenset({"fetch", "structured", "extract"})
    if linker == "actor-target":
        return frozenset({"fetch", "structured"})
    return frozenset()


def steps_for(linker: str | None) -> list[Step]:
    """The steps that apply to a run of `linker`; run-free steps only when None."""
    if linker is None:
        return [s for s in _ALL_STEPS if s.key in _RUN_FREE]
    if linker not in REGISTRY:
        raise ValueError(f"steps_for: unknown linker {linker!r}")
    skipped = _skipped_for(linker)
    steps = [s for s in _ALL_STEPS if s.key not in skipped]
    if not steps:
        raise RuntimeError("steps_for: produced no steps")
    return steps


def step(key: str) -> Step:
    if key not in _STEP_BY_KEY:
        raise ValueError(f"unknown step {key!r}")
    return _STEP_BY_KEY[key]


# ------------------------------------------------------------------ status


def _nonempty_json(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return bool(data)


def step_status(key: str, run_dir: Path) -> str:
    """DONE / TODO from the run dir's files; NEUTRAL for steps with no artefact."""
    if not isinstance(run_dir, Path):
        raise TypeError("step_status: run_dir must be a Path")
    step(key)  # raises on unknown
    linker = _read_meta(run_dir).get("linker")
    deterministic = linker in ("report-vuln", "report-labels")
    marker: dict[str, str] = {
        "select": "meta.json", "fetch": "fetch_status.json",
        "batch": "extractions.json" if deterministic else "batch.json",
        "extract": "extractions.json", "validate": "auto.json",
        "review": picks.PICKS_FILE, "apply": "applied.json", "revert": "reverted.json",
    }
    if key not in marker:
        return NEUTRAL
    if key in ("apply", "revert"):
        return DONE if _nonempty_json(run_dir / marker[key]) else TODO
    return DONE if (run_dir / marker[key]).is_file() else TODO


# -------------------------------------------------------------------- runs


@dataclass(frozen=True)
class RunSummary:
    run_id: str
    linker: str
    created: str
    counts: dict[str, int]
    root: Path


def _read_meta(run_dir: Path) -> JsonDict:
    try:
        data = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _count(path: Path) -> int:
    if not path.is_file():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return 0
    return len(data) if isinstance(data, list | dict) else 0


def summarize_run(run_dir: Path) -> RunSummary | None:
    """A RunSummary for a run dir, or None when it has no readable meta.json."""
    if not isinstance(run_dir, Path):
        raise TypeError("summarize_run: run_dir must be a Path")
    meta = _read_meta(run_dir)
    if not meta:
        return None
    counts = {name: _count(run_dir / f"{name}.json") for name in COUNT_FILES}
    return RunSummary(
        run_id=run_dir.name, linker=str(meta.get("linker", "?")), created=str(meta.get("created", "")),
        counts=counts, root=run_dir,
    )


def list_runs(runs_dir: Path) -> list[RunSummary]:
    """Every run under runs_dir, newest first (by meta.created), capped."""
    if not isinstance(runs_dir, Path):
        raise TypeError("list_runs: runs_dir must be a Path")
    if not runs_dir.is_dir():
        return []
    summaries: list[RunSummary] = []
    for d in sorted(runs_dir.iterdir()):
        if len(summaries) >= MAX_RUNS_LISTED:
            break
        if not d.is_dir():
            continue
        summary = summarize_run(d)
        if summary is not None:
            summaries.append(summary)
    summaries.sort(key=lambda s: s.created, reverse=True)
    return summaries


# -------------------------------------------------------------------- argv


@dataclass
class Options:
    include_review: bool = False
    create_missing: bool = False


def build_argv(key: str, run_id: str | None, opts: Options) -> list[str]:
    """Subcommand argv (no interpreter prefix) for a command step."""
    s = step(key)
    if s.kind != "command":
        raise ValueError(f"build_argv: {key!r} is not a command step")
    if key in _RUN_FREE:
        return [key]
    if run_id is None:
        raise ValueError(f"build_argv: {key!r} needs a run")
    base, _, dry = key.partition("-")
    argv = [base, "--run-id", run_id]
    if dry == "dry":
        argv.append("--dry-run")
    if base == "apply":
        if opts.include_review:
            argv.append("--include-review")
        if opts.create_missing:
            argv.append("--create-missing")
    return argv


@dataclass
class SelectForm:
    """The fields of `select`, edited in the TUI and rendered to argv."""

    linker: str = LINKERS[0]
    source: str = ""
    limit: str = ""
    since_days: str = ""
    all_reports: bool = False
    run_id: str = ""

    def cycle_linker(self, delta: int) -> None:
        if delta not in (-1, 1):
            raise ValueError("cycle_linker: delta must be -1 or 1")
        idx = LINKERS.index(self.linker) if self.linker in LINKERS else 0
        self.linker = LINKERS[(idx + delta) % len(LINKERS)]

    def cycle_source(self) -> None:
        idx = SOURCES.index(self.source) if self.source in SOURCES else -1
        self.source = SOURCES[(idx + 1) % len(SOURCES)]

    def error(self) -> str | None:
        """Why argv() would be rejected by the CLI, or None when it is sound."""
        if self.linker not in LINKERS:
            return f"unknown linker {self.linker!r}"
        if self.linker == "actor-target" and self.source not in SOURCES:
            return "actor-target needs a source"
        for name, value in (("limit", self.limit), ("since-days", self.since_days)):
            if value and not value.isdigit():
                return f"{name} must be a whole number"
        if "/" in self.run_id:
            return "run id must not contain /"
        return None

    def argv(self) -> list[str]:
        if self.error() is not None:
            raise ValueError(f"SelectForm.argv: {self.error()}")
        argv = ["select", "--linker", self.linker]
        if self.run_id:
            argv += ["--run-id", self.run_id]
        if self.linker == "actor-target":
            argv += ["--source", self.source]
        if self.limit:
            argv += ["--limit", self.limit]
        if self.since_days:
            argv += ["--since-days", self.since_days]
        if self.all_reports:
            argv.append("--all-reports")
        return argv


# ------------------------------------------------------------------ review


_LABEL_KEYS: tuple[str, ...] = ("entity_name", "cve", "actor", "label")


def item_label(item: JsonDict) -> str:
    """The one field that names what a review item would link."""
    if not isinstance(item, dict):
        raise TypeError("item_label: item must be a dict")
    for key in _LABEL_KEYS:
        if item.get(key):
            return str(item[key])
    if item.get("actor_id") and item.get("target"):
        rel = str(item.get("relationship_type") or "->")
        return f"{item['actor_id']} {rel} {item['target']}"
    return "?"


@dataclass
class ReviewList:
    """review.json as a checkbox list; `accepted` holds picks.item_key values."""

    items: list[JsonDict]
    accepted: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        if not isinstance(self.items, list):
            raise TypeError("ReviewList: items must be a list")
        self.keys = [picks.item_key(i) if isinstance(i, dict) else "" for i in self.items]

    def can_toggle(self, idx: int) -> bool:
        item = self.items[idx]
        return isinstance(item, dict) and not item.get("hard_fail")

    def is_accepted(self, idx: int) -> bool:
        return self.keys[idx] in self.accepted

    def toggle(self, idx: int) -> None:
        if not 0 <= idx < len(self.items):
            raise IndexError("ReviewList.toggle: index out of range")
        if not self.can_toggle(idx):
            return
        self.accepted.symmetric_difference_update({self.keys[idx]})

    def accept_all(self) -> None:
        self.accepted = {k for i, k in enumerate(self.keys) if self.can_toggle(i)}

    def accept_none(self) -> None:
        self.accepted = set()

    def accepted_count(self) -> int:
        return sum(1 for i in range(len(self.items)) if self.is_accepted(i))

    def save(self, run: Run) -> Path:
        return picks.save_picks(run, set(self.accepted))

    def row(self, idx: int, width: int) -> str:
        """One list line: [x]/[ ]/[-] confidence label | title, cut to width."""
        if width < 1:
            raise ValueError("ReviewList.row: width must be positive")
        item = self.items[idx] if isinstance(self.items[idx], dict) else {}
        box = "[-]" if not self.can_toggle(idx) else ("[x]" if self.is_accepted(idx) else "[ ]")
        conf = str(item.get("confidence") or "?")[:6]
        text = f"{box} {conf:<6} {item_label(item)}  | {item.get('title') or ''}"
        return text[:width]

    def detail(self, idx: int) -> list[str]:
        """The lines for the detail pane: reasons, evidence, ids."""
        item = self.items[idx] if isinstance(self.items[idx], dict) else {"raw": self.items[idx]}
        lines = [f"reasons:  {'; '.join(str(r) for r in item.get('review_reasons') or [])}"]
        if item.get("hard_fail"):
            lines.append("hard_fail: true -- cannot be accepted; fix extractions.json and re-validate")
        for key in ("role", "evidence", "via_crosswalk", "alias_writes", "creatable", "report_id"):
            if key in item:
                lines.append(f"{key}: {item[key]}")
        return lines


def extract_hint(linker: str, run_dir: Path) -> str:
    """What to tell the operator when the TUI cannot run the extract itself."""
    if not isinstance(run_dir, Path):
        raise TypeError("extract_hint: run_dir must be a Path")
    skill = "octi-link-actors" if linker == "actor-target" else "octi-link-reports"
    return (
        f"run the extract in Claude Code instead: open it in this repo and ask it to "
        f"run the {skill} skill for run {run_dir.name}: it reads {run_dir / 'batch.json'} against "
        f"{run_dir / 'CONTRACT.md'} and writes {run_dir / 'extractions.json'}. Then press validate."
    )
