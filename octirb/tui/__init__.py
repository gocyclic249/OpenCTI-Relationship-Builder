"""Terminal UI for octi-rb: one row per pipeline step, a live output pane,
and a checkbox list over review.json that writes picks.json.

Split in three so the curses layer stays thin and the rest is unit-testable:
`state.py` (pure model: steps, run inspection, argv, pick toggling),
`runner.py` (one background subprocess, drained line by line) and
`screen.py` (curses painting and key handling). The TUI never calls into
cli.py in-process: every step is `python -m octirb <args>` so its
stdout/stderr land in the output pane and a crash cannot take the UI down.
"""
