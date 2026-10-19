# octi-rb TUI design (2026-10-17)

## Intent

The operator kept forgetting the command order and the flags. The TUI puts
every pipeline step on screen as a row to press Enter on, shows each
command's output live, and turns `review.json` into a checkbox list so the
medium/low-confidence items to accept are ticked rather than hand-edited.

Frontend decisions were handed to the builder; this document records them.

## Goals

- One row per step, in pipeline order, with a done/pending marker read
  from the run directory. Steps that do not apply to the run's linker are
  not shown.
- Run the real CLI for every step. The TUI is a front end, not a second
  implementation of the pipeline.
- Per-item acceptance of review items that survives re-validation and is
  honoured by the plain CLI.
- Standard library only (`curses`), matching the project rule.

## Non-goals

- Running the Claude extraction step. Its row shows the batch path and
  which skill to invoke, nothing more.
- Editing extractions or review items in place. Fixing an extraction is
  still an edit to `extractions.json` plus `validate`.
- Mouse support, colour themes, Windows.

## Anti-goals

- Any path that lets a `hard_fail` item reach the platform. The review
  screen shows them locked; `picks.review_to_apply` drops them even if a
  hand-edited `picks.json` names them.
- A hidden change to CLI behaviour. Without a `picks.json`,
  `apply --include-review` does exactly what it did before.

## Shape

- `octirb/picks.py`: `item_key` (content digest of a review item minus
  `review_reasons`/`hard_fail`), `review_to_apply`, `load_picks`,
  `save_picks`. `cli._review_items` is the one place apply consults it.
- `octirb/tui/state.py`: pure model. `steps_for(linker)`, `step_status`,
  `list_runs`/`summarize_run`, `build_argv`, `SelectForm`, `ReviewList`,
  `extract_hint`. Fully unit-tested, no curses.
- `octirb/tui/runner.py`: `Job`, one background subprocess at a time,
  merged stdout/stderr drained line by line; `octirb_command` builds
  `python -m octirb ...` with the repo on `PYTHONPATH`. `octirb/__main__.py`
  exists for this.
- `octirb/tui/screen.py`: curses. Modes `main`, `select`, `runs`,
  `review`, `confirm`. Real `apply`/`revert` need a `y`.
- `octi-rb tui` in `cli.py`, importing the screen lazily.

## Builder's calls

- Default linker in the select form is `report-location`; linkers cycle in
  pipeline order, not alphabetically.
- Saving picks flips the include-review toggle on when at least one item
  is ticked, off otherwise; `i` overrides by hand.
- A finished `select` switches the TUI to the run it created.
- Review items default to unticked. Saving with nothing ticked is a valid
  "accept none" and makes `--include-review` write nothing.
- Esc delay is set to 25 ms; the curses default of one second made the
  back key feel broken.

## Addendum (2026-10-19): update-all waves and in-TUI Claude extract

### Intent

When new reports land, the operator wants one action that takes every
linker as far as review, instead of walking six runs by hand, and does not
want to switch to a Claude Code pane for the extract step.

### Waves

- Wave 1 (key `1`): `report-location`, `report-sector`, `report-actor`,
  `report-vuln`, one new run each, run in that order. Each goes select →
  fetch → batch → structured → extract → validate, minus whatever
  `steps_for(linker)` skips for that linker.
- Wave 2 (key `2`): `report-labels`, then `actor-target --source report`.
  It is pressed after Wave 1 has been reviewed and applied, because both
  read objects Wave 1 writes. actor-target is limited to the reports that
  the latest Wave 1's runs selected, through a new
  `select --reports-from-run <id>` (repeatable) option. `--source
  description` is not part of any wave; it stays a manual select.
- `select` uses config defaults (no `--limit`, no `--since-days`, default
  empty-only filter). Run ids are named by the TUI:
  `<UTC %Y%m%dT%H%M%SZ>-w<n>-<linker>`, so Wave 2 can find the latest
  Wave 1 group by name. Wave 2 refuses to start with no Wave 1 group.
- A linker that selects 0 items stops after select ("empty"). A step
  that exits nonzero stops that linker ("failed at <step> (exit N)");
  the wave moves to the next linker. An extract that exits 0 but leaves
  no `extractions.json` counts as failed.
- Nothing in a wave applies or reverts. The wave ends with one summary
  line per run (selected / auto / review, or why it stopped). `x`
  cancels a running wave (kills the current step).

### Claude extract

- The extract row (single run) and the wave's extract step run
  `claude -p <prompt>` with cwd = the run directory and:
  `--tools Read,Write --allowedTools Read Edit(//<abs run dir>/extractions.json)
  --permission-mode dontAsk --strict-mcp-config --output-format stream-json --verbose --restricted`.
  Verified 2026-10-19 on Claude Code 2.1.303: this writes
  `extractions.json` and is denied any other write and any read outside
  the run directory (`--restricted`; without it Read reaches any path,
  and `batch.json` holds untrusted article text). `batch.json` inlines the
  report text, so nothing outside the run directory is needed.
- The prompt asks for the extract only (read `batch.json` +
  `CONTRACT.md`, merge with any existing `extractions.json` that
  `structured` wrote, write `extractions.json`) and says not to run any
  other pipeline step. It does not invoke the `octi-link-*` skills,
  which go on to apply.
- stream-json is condensed for the output pane: one line per tool call
  (`claude: Read batch.json`), one per assistant text block (first line),
  and the final result line.
- `claude` not on PATH: the extract row shows the old hint; a wave stops
  that linker with "needs extract: claude not on PATH".

### Anti-goals

- No `--dangerously-skip-permissions` / `bypassPermissions`, no Bash for
  the extract subprocess.
- No wave step that writes to the platform.
