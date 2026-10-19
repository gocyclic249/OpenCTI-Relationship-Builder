"""Update-all waves: which step runs next, and how each linker ended.

A wave runs a fixed list of linkers one after another, each through
select -> fetch -> batch -> structured -> extract -> validate minus whatever
`state.steps_for` skips for it. This module is pure: it emits `Action`s for
the screen to launch and is told each exit code through `finished`; it only
reads run directories (meta.json, selection.json, extractions.json). Nothing
a wave emits applies or reverts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from . import extract, state

WAVE_LINKERS: dict[int, tuple[str, ...]] = {
    1: ("report-location", "report-sector", "report-actor", "report-vuln"),
    2: ("report-labels", "actor-target"),
}
CHAIN: tuple[str, ...] = ("fetch", "batch", "structured", "extract", "validate")
SCOPED_WAVE = 2  # the wave whose actor-target is limited to the latest wave 1
MAX_RUN_DIRS = 10_000  # directory entries scanned by latest_wave1_ids
_STAMP_RE = re.compile(r"^\d{8}T\d{6}Z$")
_WAVE1_RE = re.compile(r"^(\d{8}T\d{6}Z)-w1-")
_SAFE_STEPS: frozenset[str] = frozenset({"select", *CHAIN})
NO_CLAUDE = "needs extract: claude not on PATH"
NO_EXTRACTIONS = "failed at extract (no extractions.json)"

FileSig = tuple[int, int, int]  # (st_ino, st_mtime_ns, st_size) of extractions.json

for _linkers in WAVE_LINKERS.values():
    if not set(_linkers) <= set(state.LINKERS):
        raise RuntimeError("tui.wave: WAVE_LINKERS names an unknown linker")


@dataclass(frozen=True)
class Action:
    kind: str  # "octirb" | "claude"
    argv: list[str]  # octi-rb subcommand argv, or the full claude argv
    run_id: str
    step: str  # "select" | "fetch" | ... | "extract" | "validate"
    cwd: Path | None  # run dir for claude, None for octirb


def latest_wave1_ids(runs_dir: Path) -> list[str]:
    """Run ids of the newest `<stamp>-w1-*` group under runs_dir, sorted; [] if none."""
    if not isinstance(runs_dir, Path):
        raise TypeError("latest_wave1_ids: runs_dir must be a Path")
    if not runs_dir.is_dir():
        return []
    groups: dict[str, list[str]] = {}
    for count, entry in enumerate(runs_dir.iterdir()):
        if count >= MAX_RUN_DIRS:
            raise RuntimeError(f"latest_wave1_ids: more than {MAX_RUN_DIRS} entries in {runs_dir}")
        match = _WAVE1_RE.match(entry.name)
        if match and entry.is_dir():
            groups.setdefault(match.group(1), []).append(entry.name)
    if not groups:
        return []
    ids = sorted(groups[max(groups)])
    if not ids:
        raise RuntimeError("latest_wave1_ids: newest group is empty")
    return ids


def _file_sig(path: Path) -> FileSig | None:
    """Identity of `path` for change detection, or None when it is not a file.

    `structured` always writes extractions.json (even `[]`) before extract, so
    "the file exists" proves nothing; extract succeeded only if this changed.
    The inode catches an atomic replace that lands within one mtime tick.
    """
    if not isinstance(path, Path):
        raise TypeError("wave: path must be a Path")
    if not path.is_file():
        return None
    st = path.stat()
    if st.st_size < 0 or st.st_mtime_ns < 0:
        raise RuntimeError(f"wave: implausible stat for {path}")
    return (st.st_ino, st.st_mtime_ns, st.st_size)


def _chain_for(linker: str) -> list[str]:
    """select, then the CHAIN steps that apply to `linker`, in CHAIN order."""
    present = {s.key for s in state.steps_for(linker)}
    steps = ["select", *(key for key in CHAIN if key in present)]
    if steps[-1] != "validate" or not set(steps) <= _SAFE_STEPS:
        raise RuntimeError(f"wave: unexpected step chain for {linker}: {steps}")
    return steps


class Wave:
    """One wave: emits actions one at a time and records each linker's outcome."""

    def __init__(self, number: int, runs_dir: Path, claude: str | None, stamp: str) -> None:
        if number not in WAVE_LINKERS:
            raise ValueError(f"Wave: no wave {number!r}; waves are {sorted(WAVE_LINKERS)}")
        if not isinstance(stamp, str) or not _STAMP_RE.match(stamp):
            raise ValueError(f"Wave: stamp {stamp!r} is not %Y%m%dT%H%M%SZ")
        if not isinstance(runs_dir, Path):
            raise TypeError("Wave: runs_dir must be a Path")
        self._wave1_ids = latest_wave1_ids(runs_dir) if number == SCOPED_WAVE else []
        if number == SCOPED_WAVE and not self._wave1_ids:
            raise ValueError("wave 2 needs a wave 1 run first: press 1")
        self._runs_dir = runs_dir
        self._claude = claude
        self._linkers = WAVE_LINKERS[number]
        self._ids = {lk: f"{stamp}-w{number}-{lk}" for lk in self._linkers}
        self._outcomes: dict[str, str] = {}
        self._idx = 0
        self._queue: list[str] = []
        self._pending: Action | None = None
        self._cancelled = False
        self._emitted = 0
        self._max_actions = len(self._linkers) * (len(CHAIN) + 1)
        self._run_ids: list[str] = []
        self._extract_sig: FileSig | None = None  # extractions.json as extract found it

    # ------------------------------------------------------------ properties

    @property
    def done(self) -> bool:
        return self._cancelled or (self._idx >= len(self._linkers) and self._pending is None)

    @property
    def run_ids(self) -> list[str]:
        return list(self._run_ids)

    # ---------------------------------------------------------------- driving

    def _linker(self) -> str:
        if not 0 <= self._idx < len(self._linkers):
            raise RuntimeError("wave: no current linker")
        return self._linkers[self._idx]

    def _end_linker(self, outcome: str) -> None:
        """Record the current linker's outcome and move to the next linker."""
        if not outcome:
            raise ValueError("wave: outcome must be non-empty")
        linker = self._linker()
        if linker in self._outcomes:
            raise RuntimeError(f"wave: {linker} already ended")
        self._outcomes[linker] = outcome
        self._idx += 1
        self._queue = []

    def _select_argv(self, linker: str, run_id: str) -> list[str]:
        if linker == "actor-target" and not self._wave1_ids:
            raise RuntimeError("wave: actor-target select without wave 1 ids")
        argv = ["select", "--linker", linker, "--run-id", run_id]
        if linker == "actor-target":
            argv += ["--source", "report"]
            for wave1_id in self._wave1_ids:
                argv += ["--reports-from-run", wave1_id]
        if argv[0] != "select" or "--run-id" not in argv:
            raise RuntimeError("wave: malformed select argv")
        return argv

    def _action(self, linker: str, key: str) -> Action:
        run_id = self._ids[linker]
        run_dir = self._runs_dir / run_id
        if key not in _SAFE_STEPS:
            raise ValueError(f"wave: {key!r} is not a wave step")
        if key == "extract":
            if self._claude is None:
                raise RuntimeError("wave: extract action without claude")
            argv = extract.claude_argv(self._claude, run_dir, extract.extract_prompt(linker, run_dir))
            self._extract_sig = _file_sig(run_dir / "extractions.json")
            return Action("claude", argv, run_id, key, run_dir)
        if key == "select":
            self._run_ids.append(run_id)
            return Action("octirb", self._select_argv(linker, run_id), run_id, key, None)
        return Action("octirb", state.build_argv(key, run_id, state.Options()), run_id, key, None)

    def next_action(self) -> Action | None:
        """The next step to launch, or None when the wave is done or cancelled."""
        if self._pending is not None and not self._cancelled:
            raise RuntimeError("wave: next_action called before finished() for the previous one")
        # Each pass either emits or ends a linker, so len(linkers) + 1 passes suffice.
        for _ in range(len(self._linkers) + 1):
            if self.done:
                return None
            linker = self._linker()
            if not self._queue:
                self._queue = _chain_for(linker)
            key = self._queue.pop(0)
            if key == "extract" and self._claude is None:
                self._end_linker(NO_CLAUDE)
                continue
            self._emitted += 1
            if self._emitted > self._max_actions:
                raise RuntimeError(f"wave: more than {self._max_actions} actions emitted")
            self._pending = self._action(linker, key)
            return self._pending
        raise RuntimeError("wave: next_action did not converge")

    def finished(self, exit_code: int) -> None:
        """Feed the exit code of the action last returned by next_action."""
        if self._pending is None:
            raise RuntimeError("wave: finished() with no outstanding action")
        if not isinstance(exit_code, int):
            raise TypeError("wave: exit_code must be an int")
        action, self._pending = self._pending, None
        if self._cancelled:
            return  # the killed step's exit; outcomes were recorded by cancel()
        run_dir = self._runs_dir / action.run_id
        if exit_code != 0:
            self._end_linker(f"failed at {action.step} (exit {exit_code})")
        elif action.step == "select" and self._selected(run_dir) == 0:
            self._end_linker("empty")
        elif action.step == "extract" and not self._extract_wrote(run_dir):
            self._end_linker(NO_EXTRACTIONS)
        elif not self._queue:
            self._end_linker("ok")

    def _extract_wrote(self, run_dir: Path) -> bool:
        """True when extractions.json exists and differs from before extract ran."""
        if not isinstance(run_dir, Path):
            raise TypeError("wave: run_dir must be a Path")
        if run_dir.parent != self._runs_dir:
            raise ValueError(f"wave: {run_dir} is not a run of this wave")
        after = _file_sig(run_dir / "extractions.json")
        if after is None:
            return False
        return after != self._extract_sig

    @staticmethod
    def _selected(run_dir: Path) -> int:
        if not isinstance(run_dir, Path):
            raise TypeError("wave: run_dir must be a Path")
        summary = state.summarize_run(run_dir)
        count = 0 if summary is None else summary.counts.get("selection", 0)
        if count < 0:
            raise RuntimeError("wave: negative selection count")
        return count

    def cancel(self) -> None:
        """Stop the wave; every linker without an outcome becomes `cancelled`."""
        if self._cancelled:
            return
        self._cancelled = True
        for linker in self._linkers:
            self._outcomes.setdefault(linker, "cancelled")
        if len(self._outcomes) != len(self._linkers):
            raise RuntimeError("wave: cancel left a linker without an outcome")

    # ---------------------------------------------------------------- summary

    def _line(self, linker: str) -> str:
        if linker not in self._ids:
            raise ValueError(f"wave: {linker!r} is not in this wave")
        run_id = self._ids[linker]
        outcome = self._outcomes.get(linker)
        if outcome is None:
            outcome = "running" if self._idx < len(self._linkers) and self._linker() == linker else "pending"
        if outcome != "ok":
            return f"{linker:<16} {run_id}  {outcome}"
        summary = state.summarize_run(self._runs_dir / run_id)
        counts = summary.counts if summary is not None else {}
        sel, auto, review = (counts.get(k, 0) for k in ("selection", "auto", "review"))
        if min(sel, auto, review) < 0:
            raise RuntimeError("wave: negative count in summary")
        return f"{linker:<16} {run_id}  sel {sel}  auto {auto}  review {review}"

    def summary(self) -> list[str]:
        """One line per linker of this wave: counts when ok, else why it stopped."""
        lines = [self._line(linker) for linker in self._linkers]
        if len(lines) != len(self._linkers):
            raise RuntimeError("wave: summary line count mismatch")
        return lines
