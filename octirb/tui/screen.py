"""Curses painting and key handling for the TUI.

Four modes share one loop: `main` (steps + output pane), `select` (the
new-run form), `runs` (pick an existing run), `review` (checkbox list over
review.json), plus a one-key `confirm` gate before a real apply/revert.
All state lives in `App`; `state.py` decides what to show and `runner.py`
runs the step. Every curses call goes through `_put` so a line that would
overrun the window is clipped instead of raising.

Waves: in `main`, `1`/`2` start an update-all wave (`wave.py` decides each
next step; `_on_job_finished` feeds it the exit code and launches the next)
and `x` cancels one. A wave never applies or reverts. The extract row, and a
wave's extract step, run the locked-down `claude -p` from `extract.py` with
the run directory as cwd and its stream-json condensed for the output pane.
One job runs at a time: a wave refuses to start while a step runs, and Enter
on a step is refused while a wave runs.
"""

from __future__ import annotations

import contextlib
import curses
import os
import textwrap
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .. import picks
from ..linkers import REGISTRY
from ..runstore import Run, new_run_id
from . import extract, state
from .runner import Job, octirb_command
from .wave import WAVE_LINKERS, Wave

if TYPE_CHECKING:
    from ..config import Config

Window = Any  # curses windows have no public type in typeshed

MAX_TICKS = 50_000_000  # ~58 days at the 100 ms poll; the loop raises past it
TICK_MS = 100
LOG_LINES = 5_000
STEPS_WIDTH = 46
MIN_ROWS = 12
MIN_COLS = 60
KEY_ENTER_CODES = (curses.KEY_ENTER, 10, 13)
KEY_ESC = 27
ESC_DELAY_MS = "25"  # curses defaults to 1000 ms before it decides Esc was just Esc
KEY_BACKSPACE_CODES = (curses.KEY_BACKSPACE, 127, 8)
ASCII_LIMIT = 128
CONFIRM_STEPS = frozenset({"apply", "revert"})
FORM_FIELDS: tuple[str, ...] = ("linker", "source", "limit", "since_days", "all_reports", "run_id")


@dataclass
class App:
    cfg: Config
    config_path: Path | None
    run: state.RunSummary | None = None
    steps: list[state.Step] = field(default_factory=list)
    cursor: int = 0
    opts: state.Options = field(default_factory=state.Options)
    job: Job = field(default_factory=Job)
    log: deque[str] = field(default_factory=lambda: deque(maxlen=LOG_LINES))
    log_scroll: int = 0
    mode: str = "main"
    message: str = ""
    form: state.SelectForm = field(default_factory=state.SelectForm)
    form_field: int = 0
    runs: list[state.RunSummary] = field(default_factory=list)
    runs_cursor: int = 0
    review: state.ReviewList | None = None
    review_cursor: int = 0
    pending_step: str | None = None
    pending_run_id: str | None = None
    started: list[str] = field(default_factory=list)
    quit: bool = False
    wave: Wave | None = None
    wave_number: int = 0
    claude: str | None = None  # path of `claude` on PATH; set once by run_tui


# ------------------------------------------------------------------ helpers


def _put(win: Window, y: int, x: int, text: str, attr: int = 0) -> None:
    """addstr that clips to the window instead of raising at the edge."""
    rows, cols = win.getmaxyx()
    if y < 0 or y >= rows or x >= cols:
        return
    room = cols - x - 1
    if room <= 0:
        return
    # curses raises when writing the bottom-right cell; the text is already clipped.
    with contextlib.suppress(curses.error):
        win.addstr(y, x, text[:room], attr)


def _say(app: App, text: str) -> None:
    app.message = text
    app.log.append(text)


def _load_run(app: App, run_id: str | None) -> None:
    """Point the app at a run (newest when None) and rebuild its step list."""
    if run_id is not None:
        app.run = state.summarize_run(app.cfg.runs_dir / run_id)
    else:
        latest = Run.latest(app.cfg.runs_dir)
        app.run = state.summarize_run(latest.root) if latest is not None else None
    linker = app.run.linker if app.run is not None else None
    app.steps = state.steps_for(linker) if linker in state.LINKERS or linker is None else state.steps_for(None)
    app.cursor = min(app.cursor, len(app.steps) - 1)
    if app.run is not None and app.run.root.is_dir():
        picked = state.step_status("review", app.run.root) == state.DONE
        app.opts.include_review = picked


def _start(app: App, sub_argv: list[str]) -> bool:
    """Launch one octi-rb step; False (with a message) when it cannot start."""
    if not sub_argv:
        raise ValueError("_start: empty sub-command argv")
    if app.job.running:
        _say(app, "a step is already running; wait for it to finish")
        return False
    argv, env = octirb_command(sub_argv, config=app.config_path)
    try:
        app.job.start(argv, env, label=" ".join(sub_argv))
    except OSError as exc:  # interpreter or cwd unusable: report, do not crash curses
        _say(app, f"could not start {sub_argv[0]}: {exc}")
        return False
    app.started = list(sub_argv)
    app.log_scroll = 0
    app.message = ""
    return True


def _start_claude(app: App, argv: list[str], cwd: Path, label: str) -> bool:
    """Launch the extract `claude -p` in `cwd` with its output condensed."""
    if not argv or not label:
        raise ValueError("_start_claude: argv and label must be non-empty")
    if not cwd.is_dir():
        raise ValueError(f"_start_claude: cwd is not a directory: {cwd}")
    if app.job.running:
        _say(app, "a step is already running; wait for it to finish")
        return False
    try:
        app.job.start(argv, None, label=label, cwd=cwd, transform=extract.condense)
    except OSError as exc:  # e.g. claude removed after find_claude
        _say(app, f"could not start claude: {exc}")
        return False
    app.started = ["extract"]
    app.log_scroll = 0
    app.message = ""
    return True


# --------------------------------------------------------------------- main


def _draw_header(app: App, win: Window, cols: int) -> None:
    if app.run is None:
        title = " octi-rb   no runs yet -- press n to start one"
    else:
        c = app.run.counts
        title = (f" octi-rb   run {app.run.run_id} [{app.run.linker}]   sel {c['selection']}  "
                 f"extr {c['extractions']}  auto {c['auto']}  review {c['review']}  applied {c['applied']}")
    _put(win, 0, 0, title.ljust(cols), curses.A_REVERSE)
    _put(win, 1, 1, f"runs: {app.cfg.runs_dir}", curses.A_DIM)


def _draw_steps(app: App, win: Window, top: int, rows: int) -> None:
    root = app.run.root if app.run is not None else None
    for i, s in enumerate(app.steps):
        if top + i >= rows - 2:
            break
        status = state.step_status(s.key, root) if root is not None else state.NEUTRAL
        mark = {state.DONE: "[ok]", state.TODO: "[  ]", state.NEUTRAL: "    "}[status]
        attr = curses.A_REVERSE if i == app.cursor else 0
        if s.key in CONFIRM_STEPS and i != app.cursor:
            attr |= curses.A_BOLD
        _put(win, top + i, 1, f"{mark} {s.label}"[: STEPS_WIDTH - 3].ljust(STEPS_WIDTH - 3), attr)


def _draw_log(app: App, win: Window, top: int, rows: int, cols: int) -> None:
    x = STEPS_WIDTH
    height = rows - top - 2
    width = cols - x - 1
    if height <= 0 or width <= 0:
        return
    for r in range(height):
        _put(win, top + r, x - 1, "|")
    lines = list(app.log)
    end = max(0, len(lines) - app.log_scroll)
    shown = lines[max(0, end - height):end]
    for r, line in enumerate(shown):
        _put(win, top + r, x, line[:width])
    if app.job.running:
        _put(win, top, cols - 12, " running ", curses.A_BLINK | curses.A_REVERSE)


def _draw_footer(app: App, win: Window, rows: int, cols: int) -> None:
    hint = app.steps[app.cursor].hint if app.steps else ""
    flags = (f"incl-review:{'on' if app.opts.include_review else 'off'}  "
             f"create-missing:{'on' if app.opts.create_missing else 'off'}")
    keys = "Enter run  n new  r runs  v review  1/2 wave  x cancel  i/c opts  PgUp/Dn  q quit"
    _put(win, rows - 2, 1, (app.message or hint)[: cols - 2], curses.A_DIM)
    _put(win, rows - 1, 0, f" {keys}   {flags}".ljust(cols), curses.A_REVERSE)


def _draw_main(app: App, win: Window) -> None:
    rows, cols = win.getmaxyx()
    _draw_header(app, win, cols)
    _draw_steps(app, win, 3, rows)
    _draw_log(app, win, 3, rows, cols)
    _draw_footer(app, win, rows, cols)


def _activate(app: App) -> None:
    """Enter on a step row."""
    if not app.steps:
        return
    s = app.steps[app.cursor]
    run_id = app.run.run_id if app.run is not None else None
    if s.kind == "form":
        app.mode, app.form, app.form_field = "select", state.SelectForm(), 0
    elif s.kind == "screen":
        _open_review(app)
    elif s.kind == "info" and app.run is not None:
        _extract_row(app, app.run)
    elif s.kind == "wave":
        _start_wave(app, 1 if s.key == "wave1" else 2)
    elif s.key in CONFIRM_STEPS:
        app.pending_step, app.mode = s.key, "confirm"
    else:
        _start(app, state.build_argv(s.key, run_id, app.opts))


def _extract_row(app: App, run: state.RunSummary) -> None:
    """Enter on the extract row: run claude when it can, else say why not."""
    if not isinstance(run.root, Path):
        raise TypeError("_extract_row: run root must be a Path")
    entry = REGISTRY.get(run.linker)
    if entry is None or not entry.needs_model:
        _say(app, f"{run.linker} has no model extraction step")
        return
    if app.claude is None:
        _say(app, "claude not on PATH: " + state.extract_hint(run.linker, run.root))
        return
    if not (run.root / "batch.json").is_file():
        _say(app, "no batch.json yet -- run batch first")
        return
    argv = extract.claude_argv(app.claude, run.root, extract.extract_prompt(run.linker, run.root))
    if argv[0] != app.claude:
        raise RuntimeError("_extract_row: claude argv does not start with the claude path")
    _start_claude(app, argv, run.root, f"claude extract ({run.run_id})")


def _toggle_option(app: App, ch: int) -> None:
    if ch == ord("i"):
        app.opts.include_review = not app.opts.include_review
    elif ch == ord("c"):
        if app.run is not None and app.run.linker != "report-actor":
            _say(app, "--create-missing only applies to report-actor runs")
            return
        app.opts.create_missing = not app.opts.create_missing


def _key_main(app: App, ch: int) -> None:
    if ch in (curses.KEY_UP, ord("k")):
        app.cursor = max(0, app.cursor - 1)
    elif ch in (curses.KEY_DOWN, ord("j")):
        app.cursor = min(len(app.steps) - 1, app.cursor + 1)
    elif ch in KEY_ENTER_CODES:
        _enter(app)
    elif ch in (ord("1"), ord("2"), ord("x")):
        _key_wave(app, ch)
    elif ch == ord("n"):
        app.mode, app.form, app.form_field = "select", state.SelectForm(), 0
    elif ch == ord("r"):
        app.runs, app.runs_cursor, app.mode = state.list_runs(app.cfg.runs_dir), 0, "runs"
    elif ch == ord("v"):
        _open_review(app)
    elif ch in (ord("i"), ord("c")):
        _toggle_option(app, ch)
    elif ch in (curses.KEY_PPAGE, curses.KEY_NPAGE):
        _scroll_log(app, 10 if ch == curses.KEY_PPAGE else -10)
    elif ch == ord("g"):
        _load_run(app, app.run.run_id if app.run is not None else None)
    elif ch == ord("q"):
        _request_quit(app)
    elif ch == ord("Q"):
        app.job.terminate()
        app.quit = True


def _enter(app: App) -> None:
    """Enter on a step row: refused while a wave owns the job slot."""
    if app.wave is not None:
        _say(app, "a wave is running; x cancels it")
        return
    _activate(app)


def _scroll_log(app: App, delta: int) -> None:
    """Move the output pane by `delta` lines (positive = back in time)."""
    app.log_scroll = max(0, min(len(app.log), app.log_scroll + delta))


def _key_wave(app: App, ch: int) -> None:
    """`1`/`2` start a wave, `x` cancels the running one."""
    if ch not in (ord("1"), ord("2"), ord("x")):
        raise ValueError(f"_key_wave: not a wave key: {ch}")
    if ch != ord("x"):
        _start_wave(app, int(chr(ch)))
        return
    wave = app.wave
    if wave is None:
        _say(app, "no wave is running")
        return
    wave.cancel()
    if not wave.done:
        raise RuntimeError("_key_wave: wave not done after cancel")
    app.job.terminate()
    _say(app, "wave cancelled")
    if not app.job.running:
        _advance_wave(app)  # nothing to wait for: finish the wave now


def _request_quit(app: App) -> None:
    if app.job.running:
        _say(app, "a step is running: wait, or press Q to kill it and quit")
        return
    app.quit = True


# ------------------------------------------------------------------ confirm


def _draw_confirm(app: App, win: Window) -> None:
    _draw_main(app, win)
    rows, cols = win.getmaxyx()
    verb = {"apply": "WRITE to the platform", "revert": "UNDO this run's platform writes"}
    text = f" {app.pending_step}: this will {verb.get(app.pending_step or '', '?')}. Press y to go, any other key to cancel "
    _put(win, rows // 2, max(0, (cols - len(text)) // 2), text, curses.A_REVERSE | curses.A_BOLD)


def _key_confirm(app: App, ch: int) -> None:
    step_key, app.pending_step, app.mode = app.pending_step, None, "main"
    if ch != ord("y") or step_key is None:
        _say(app, "cancelled")
        return
    run_id = app.run.run_id if app.run is not None else None
    _start(app, state.build_argv(step_key, run_id, app.opts))


# ------------------------------------------------------------------- select


def _form_value(form: state.SelectForm, name: str) -> str:
    value = getattr(form, name)
    if name == "all_reports":
        return "yes" if value else "no"
    if name == "source":
        return value or ("(required)" if form.linker == "actor-target" else "n/a")
    return str(value) or ("(auto)" if name == "run_id" else "(default)")


def _draw_select(app: App, win: Window) -> None:
    rows, cols = win.getmaxyx()
    _put(win, 0, 0, " new run: select ".ljust(cols), curses.A_REVERSE)
    labels = {"linker": "linker      (Left/Right)", "source": "source      (Left/Right; actor-target)",
              "limit": "limit       (digits)", "since_days": "since-days  (digits)",
              "all_reports": "all-reports (Left/Right)", "run_id": "run id      (letters, dash)"}
    for i, name in enumerate(FORM_FIELDS):
        attr = curses.A_REVERSE if i == app.form_field else 0
        _put(win, 2 + i * 2, 2, f"{labels[name]:<40} {_form_value(app.form, name)}", attr)
    err = app.form.error()
    preview = " ".join(app.form.argv()) if err is None else f"error: {err}"
    _put(win, 2 + len(FORM_FIELDS) * 2 + 1, 2, preview, curses.A_DIM)
    _put(win, rows - 1, 0, " Up/Down field  Left/Right cycle  type to edit  Enter run select  Esc back".ljust(cols),
         curses.A_REVERSE)


def _edit_text(value: str, ch: int, allowed: str) -> str:
    if ch in KEY_BACKSPACE_CODES:
        return value[:-1]
    if 0 <= ch < ASCII_LIMIT and chr(ch) in allowed:
        return value + chr(ch)
    return value


def _key_select_cycle(app: App, delta: int) -> None:
    name = FORM_FIELDS[app.form_field]
    if name == "linker":
        app.form.cycle_linker(delta)
    elif name == "source":
        app.form.cycle_source()
    elif name == "all_reports":
        app.form.all_reports = not app.form.all_reports


def _key_select(app: App, ch: int) -> None:
    if ch == KEY_ESC:
        app.mode = "main"
    elif ch == curses.KEY_UP:
        app.form_field = max(0, app.form_field - 1)
    elif ch == curses.KEY_DOWN:
        app.form_field = min(len(FORM_FIELDS) - 1, app.form_field + 1)
    elif ch in (curses.KEY_LEFT, curses.KEY_RIGHT):
        _key_select_cycle(app, 1 if ch == curses.KEY_RIGHT else -1)
    elif ch in KEY_ENTER_CODES:
        err = app.form.error()
        if err is not None:
            _say(app, f"select: {err}")
            return
        app.pending_run_id = app.form.run_id or None
        app.mode = "main"
        _start(app, app.form.argv())
    else:
        name = FORM_FIELDS[app.form_field]
        if name in ("limit", "since_days"):
            setattr(app.form, name, _edit_text(getattr(app.form, name), ch, "0123456789"))
        elif name == "run_id":
            letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
            app.form.run_id = _edit_text(app.form.run_id, ch, letters)


# --------------------------------------------------------------------- runs


def _draw_runs(app: App, win: Window) -> None:
    rows, cols = win.getmaxyx()
    _put(win, 0, 0, " runs (newest first) ".ljust(cols), curses.A_REVERSE)
    _put(win, 1, 2, f"{'run id':<34} {'linker':<16} {'created':<26} sel  extr  auto  rev  appl", curses.A_DIM)
    height = rows - 4
    first = max(0, app.runs_cursor - height + 1)
    for r, summary in enumerate(app.runs[first:first + height]):
        c = summary.counts
        line = (f"{summary.run_id:<34} {summary.linker:<16} {summary.created[:25]:<26} "
                f"{c['selection']:>4} {c['extractions']:>5} {c['auto']:>5} {c['review']:>4} {c['applied']:>5}")
        _put(win, 2 + r, 2, line, curses.A_REVERSE if first + r == app.runs_cursor else 0)
    if not app.runs:
        _put(win, 2, 2, "(no runs yet)")
    _put(win, rows - 1, 0, " Up/Down  Enter open  Esc back".ljust(cols), curses.A_REVERSE)


def _key_runs(app: App, ch: int) -> None:
    if ch == KEY_ESC:
        app.mode = "main"
    elif ch == curses.KEY_UP:
        app.runs_cursor = max(0, app.runs_cursor - 1)
    elif ch == curses.KEY_DOWN:
        app.runs_cursor = min(max(0, len(app.runs) - 1), app.runs_cursor + 1)
    elif ch in KEY_ENTER_CODES and app.runs:
        _load_run(app, app.runs[app.runs_cursor].run_id)
        app.mode = "main"


# ------------------------------------------------------------------- review


def _open_review(app: App) -> None:
    if app.run is None:
        _say(app, "no run selected")
        return
    run = Run(app.run.root)
    if not run.has("review.json"):
        _say(app, "no review.json yet -- run validate first")
        return
    items = run.read_json("review.json")
    if not isinstance(items, list):
        _say(app, "review.json is not a JSON array")
        return
    app.review = state.ReviewList(items, accepted=picks.load_picks(run) or set())
    app.review_cursor, app.mode = 0, "review"


def _draw_review(app: App, win: Window) -> None:
    rows, cols = win.getmaxyx()
    rl = app.review
    if rl is None:
        return
    run_id = app.run.run_id if app.run is not None else "?"
    _put(win, 0, 0, f" review {run_id}: {rl.accepted_count()} of {len(rl.items)} accepted ".ljust(cols),
         curses.A_REVERSE)
    list_rows = max(1, (rows - 4) * 3 // 5)
    first = max(0, app.review_cursor - list_rows + 1)
    for r, idx in enumerate(range(first, min(len(rl.items), first + list_rows))):
        _put(win, 1 + r, 1, rl.row(idx, cols - 2), curses.A_REVERSE if idx == app.review_cursor else 0)
    if not rl.items:
        _put(win, 1, 1, "(review.json is empty: nothing to pick)")
    else:
        _put(win, 1 + list_rows, 0, "-" * (cols - 1), curses.A_DIM)
        wrapped = [w for line in rl.detail(app.review_cursor)
                   for w in textwrap.wrap(line, max(10, cols - 2), subsequent_indent='    ') or ['']]
        for r, line in enumerate(wrapped):
            _put(win, 2 + list_rows + r, 1, line)
    _put(win, rows - 1, 0, " Space toggle  a all  n none  s save+back  Esc back without saving".ljust(cols),
         curses.A_REVERSE)


def _key_review(app: App, ch: int) -> None:
    rl = app.review
    if rl is None or ch == KEY_ESC:
        app.mode = "main"
        return
    last = max(0, len(rl.items) - 1)
    if ch in (curses.KEY_UP, ord("k")):
        app.review_cursor = max(0, app.review_cursor - 1)
    elif ch in (curses.KEY_DOWN, ord("j")):
        app.review_cursor = min(last, app.review_cursor + 1)
    elif ch == ord(" ") and rl.items:
        rl.toggle(app.review_cursor)
    elif ch == ord("a"):
        rl.accept_all()
    elif ch == ord("n"):
        rl.accept_none()
    elif ch in (ord("s"), *KEY_ENTER_CODES) and app.run is not None:
        path = rl.save(Run(app.run.root))
        app.opts.include_review = rl.accepted_count() > 0
        _say(app, f"saved {rl.accepted_count()} pick(s) to {path}; include-review is now "
                  f"{'on' if app.opts.include_review else 'off'}")
        app.mode = "main"


# -------------------------------------------------------------------- waves


def _start_wave(app: App, number: int) -> None:
    """Begin wave `number` unless a step is running or the wave cannot start."""
    if number not in WAVE_LINKERS:
        raise ValueError(f"_start_wave: no wave {number}")
    if app.wave is not None:
        _say(app, "a wave is running; x cancels it")
        return
    if app.job.running:
        _say(app, "a step is running; wait before starting a wave")
        return
    try:
        wave = Wave(number, app.cfg.runs_dir, app.claude, new_run_id())
    except (ValueError, RuntimeError) as exc:  # no wave 1 yet, runs dir too big: a message, not a crash
        _say(app, str(exc))
        return
    if app.wave is not None or app.job.running:
        raise RuntimeError("_start_wave: job slot taken while building the wave")
    app.wave, app.wave_number = wave, number
    _say(app, f"wave {number}: {', '.join(WAVE_LINKERS[number])}")
    _advance_wave(app)


def _finish_wave(app: App, wave: Wave) -> None:
    """Log the summary, drop the wave, and show its newest run."""
    if app.wave is not wave:
        raise RuntimeError("_finish_wave: not the current wave")
    _say(app, f"wave {app.wave_number} done")
    for line in wave.summary():
        app.log.append(line)
    app.wave = None
    ids = [rid for rid in wave.run_ids if (app.cfg.runs_dir / rid / "meta.json").is_file()]
    if ids:
        _show_wave_run(app, ids[-1])


def _show_wave_run(app: App, run_id: str) -> None:
    """Follow the wave onto `run_id`, but only on the main screen: switching
    app.run under the review screen would save picks into the wrong run."""
    if not run_id:
        raise ValueError("_show_wave_run: empty run id")
    if app.mode != "main":
        return
    _load_run(app, run_id)
    if app.run is None:
        raise RuntimeError(f"_show_wave_run: run {run_id} did not load")


def _advance_wave(app: App) -> None:
    """Launch the wave's next step, or finish it when there is none."""
    wave = app.wave
    if wave is None:
        raise RuntimeError("_advance_wave: no wave")
    action = wave.next_action()
    if action is None:
        _finish_wave(app, wave)
        return
    if action.kind not in ("claude", "octirb") or (action.kind == "claude" and action.cwd is None):
        raise RuntimeError(f"_advance_wave: malformed action {action.kind} {action.step}")
    if (app.cfg.runs_dir / action.run_id / "meta.json").is_file():
        _show_wave_run(app, action.run_id)
    if action.cwd is not None and action.kind == "claude":
        started = _start_claude(app, action.argv, action.cwd, f"claude extract ({action.run_id})")
    else:
        started = _start(app, action.argv)
    if not started:  # could not launch: the wave cannot go on
        wave.cancel()
        _say(app, f"wave stopped: could not start {action.step} for {action.run_id}")
        _finish_wave(app, wave)


# --------------------------------------------------------------------- loop


def _on_job_finished(app: App) -> None:
    """After a step exits: re-read the run so the status marks move. A
    successful select switches to the run it created (named or newest).
    During a wave the exit code goes to the wave, which picks the next step."""
    if app.wave is not None:
        code = app.job.exit_code
        app.wave.finished(code if code is not None else -1)
        app.pending_run_id = None
        _advance_wave(app)
        return
    made_new_run = app.started[:1] == ["select"] and app.job.exit_code == 0
    if made_new_run:
        _load_run(app, app.pending_run_id)
    else:
        _load_run(app, app.run.run_id if app.run is not None else None)
    app.pending_run_id = None


def _tick(app: App) -> None:
    fresh = app.job.drain()
    app.log.extend(fresh)
    if any(line.startswith("exit ") for line in fresh):
        _on_job_finished(app)


_DRAW = {"main": _draw_main, "confirm": _draw_confirm, "select": _draw_select,
         "runs": _draw_runs, "review": _draw_review}
_KEYS = {"main": _key_main, "confirm": _key_confirm, "select": _key_select,
         "runs": _key_runs, "review": _key_review}


def _handle_key(app: App, ch: int) -> None:
    """Dispatch one key, first consuming any exit the last getch wait hid.

    A step can exit while the loop sits in getch; without this drain its
    `exit N` line would reach the next _tick after the key started a new
    job (or wave) and be taken as that job's exit.
    """
    if app.mode not in _KEYS:
        raise RuntimeError(f"_handle_key: unknown mode {app.mode!r}")
    _tick(app)
    if app.mode not in _KEYS:
        raise RuntimeError(f"_handle_key: _tick left unknown mode {app.mode!r}")
    _KEYS[app.mode](app, ch)


def _loop(stdscr: Window, app: App) -> None:
    curses.curs_set(0)
    stdscr.timeout(TICK_MS)
    stdscr.keypad(True)
    _load_run(app, None)
    for _ in range(MAX_TICKS):
        if app.quit:
            return
        _tick(app)
        stdscr.erase()
        rows, cols = stdscr.getmaxyx()
        if rows < MIN_ROWS or cols < MIN_COLS:
            _put(stdscr, 0, 0, f"terminal too small ({cols}x{rows}); need {MIN_COLS}x{MIN_ROWS}")
        else:
            _DRAW[app.mode](app, stdscr)
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (-1, curses.KEY_RESIZE):
            continue
        _handle_key(app, ch)
    raise RuntimeError("tui: event loop exceeded MAX_TICKS")


def run_tui(cfg: Config, config_path: Path | None) -> int:
    """Entry point used by `octi-rb tui`. Returns a process exit code."""
    if config_path is not None and not isinstance(config_path, Path):
        raise TypeError("run_tui: config_path must be a Path or None")
    app = App(cfg=cfg, config_path=config_path, claude=extract.find_claude())
    os.environ.setdefault("ESCDELAY", ESC_DELAY_MS)
    curses.wrapper(_loop, app)
    if app.job.running:
        app.job.terminate()
    return 0
