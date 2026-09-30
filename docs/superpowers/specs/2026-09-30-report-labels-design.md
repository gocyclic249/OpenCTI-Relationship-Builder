# report-labels — value labels for report countries and top-level sectors

Date: 2026-09-30
Status: approved in brainstorming, pending spec review

## Goal

Give every report plain, unprefixed labels that mirror what it contains:

- one label per contained **Country**, named exactly as the Country entity
  (`United States`, `Germany`);
- one label per **top-level sector** reachable from any contained Sector
  (a sector with several parents contributes every top-level root).

Purpose: filtering and search in the OpenCTI UI, and dashboards /
downstream tools that key on labels. Labels carry **no `AI-` prefix** — the
existing `AI-Location` / `AI-Sector` labels already record how a report was
processed; these record *what it is about*.

## Decisions (from brainstorming)

| Question | Decision |
|---|---|
| Label naming | Country: platform Country name. Sector: top-level root sector name. No prefix. |
| Multiple parents / countries | Label every top-level root and every country. |
| What drives labels | **Everything the report contains**, whoever added it — not only what octi-rb applied. Existing reports are backfilled. |
| Staleness | **Add-only.** Reports come from external sources and are not edited; no sync/removal logic. Only `revert` removes labels, and only ones its run added. |
| Shape | A new deterministic linker, `report-labels`, running through the normal run pipeline (dry-run, ledger, checkpoint, revert, `--run-id`, `status`). Chosen partly because it scripts cleanly for automated runs. |
| Marker label | None. No `AI-Labels` marker is added, to keep label count down. |

Out of scope: Regions, Cities and other Location types; mapping a root to a
different label name (e.g. root `Manufacturing` → label `ICS`); removing
stale labels; deleting label objects on revert.

Note: on the current platform the former ICS tree was merged into
`Manufacturing` (see `config.toml` `[sectors]`), so ICS-tree reports will be
labelled `Manufacturing`. A root→label rename table is a possible later
addition, not part of this work.

## Pipeline flow

```
select --linker report-labels [--since-days N] [--limit N] [--run-id ID]
batch        # deterministic; writes extractions.json directly (no CONTRACT.md, no model)
validate     # all extractions are confidence: high -> auto.json
apply [--dry-run]
revert [--dry-run]
```

No `fetch` step — no article text is needed.

### select

Walks `client.reports()` newest first, applying only the source / title /
`since` gates (the reused `_basic_skip` logic; `_basic_skip`, `_source_name` and
`_since_from_days` are made public as `basic_skip`, `source_name`,
`since_from_days`), and requires the report to contain at least one
object. Unlike `pipeline.select`, it does **not** skip reports with no text
and plans no text tier. `--all-reports` is accepted and ignored with a
stderr note (the linker always wants non-empty reports). Writes
`selection.json` as a list of `{report_id, name, source}`.

Refused with the same exit as `report-vuln` when
`[report_labels].enabled = false`.

### batch

1. Load `client.sector_parents()` once: every platform sector (any author)
   as `{id, name, parent_ids: [ids]}`. The walk goes by **id**, because
   same-named duplicate sectors from different authors exist.
2. For each selected report, `client.report_label_sources(report_id)`
   returns its contained Countries and Sectors (id, name) — paginated to
   the end — plus its current label values.
3. Countries → label = country name.
4. Sectors → if the sector's name is a `[sectors].aliases` key (matched
   casefolded), the walk starts from every sector named as the alias
   target instead. `sector_roots()` walks parent ids to every root. A
   sector with no visible parents is its own root. Each root name → label.
5. Drop labels the report already carries (casefold comparison) and
   dedupe (two sectors sharing a root produce one label).
6. Emit one extraction per missing label:

   ```json
   {"report_id": "...", "report_name": "...", "label": "Energy",
    "from": "sector", "source_entity": "Electricity",
    "confidence": "high"}
   ```

   Reports with nothing to add emit nothing.

A report that errors (not found, page cap exceeded) is logged to stderr and
skipped; the batch continues. `batch` prints the extractions path to stdout.

### validate

`report_labels.validate(raw, selection_ids)`: an extraction whose
`report_id` is not in the selection, whose `label` is empty/non-string, or
whose `from` is not `country`/`sector` goes to `review.json` with
`hard_fail: true`. Everything else goes to `auto.json`. No resolver.

### apply

1. For each distinct label value: `client.find_label(value)` reuses an
   existing label whose value matches **casefolded** (exact case
   preferred; the platform preserves case, and labels such as `ICS` and
   `China` already exist from other sources); otherwise
   `client.ensure_label(value, [report_labels].color)` creates it.
   `ensure_label` itself is unchanged. Dry-run creates nothing.
2. Per report, re-read current labels (`client.entity_labels`) immediately
   before writing. A label
   now present is ledgered `preexisted: true` and not written.
3. Otherwise `add_label_to_report`, then checkpoint `applied.json`
   (`ledger.merge_ledger`) after each successful write.
4. A failed write is logged and not ledgered.
5. `--include-review` behaves as for other linkers (non-`hard_fail` only;
   in practice review holds only hard fails). `--create-missing` is refused.

### revert

`revert_labels(client, rows, log, dry_run, retain)` handles `kind: "label"`
rows: `preexisted` rows are left alone; others call
`remove_label_from_report`. A label already absent counts as done. A failed
removal is appended to `retain` so the row stays in `applied.json` for a
retry. Label objects are never deleted. `cmd_revert`'s summary gains
`labels N`.

## Components

| File | Change |
|---|---|
| `octirb/linkers/report_labels.py` (new) | Pure: `sector_roots(parents, name)`, `labels_for(countries, sectors, existing, parents, aliases)`. Flow: `select`, `batch`, `validate`, `apply`, `revert_labels`. |
| `octirb/linkers/__init__.py` | `REGISTRY["report-labels"]`: `key_field="label"`, `roles=frozenset()`, `label_suffix="Labels"` (unused for writes), `entity_kind="Label"`, `write_kind="label"`, `needs_model=False`, `build_resolver` raising `NotImplementedError` (as `actor-target`), `contract=None`. |
| `octirb/client.py` | `report_label_sources(report_id)` (paginated objects filtered to Country/Sector with names, plus `objectLabel` values; `OpenCTIError` on missing report or page cap). `sector_parents()` (paginated all sectors with parent ids). `find_label(value)` casefold lookup, `None` when absent. |
| `octirb/ledger.py` | `label_row(*, report_id, label, label_id, source, source_entity, preexisted)` (`label_id` is `None` for preexisted rows); `row_key` → `("label", report_id, label.casefold())`. |
| `octirb/pipeline.py` | Rename `_basic_skip`/`_source_name`/`_since_from_days` → public names (reused). |
| `octirb/cli.py` | `select`/`batch`/`validate` branch to `report_labels`; `cmd_apply` dispatches `write_kind == "label"`; `cmd_revert` calls `revert_labels`; `cmd_fetch` refuses the linker (no fetch step); `_doctor_linkers` skips non-containment linkers (it would otherwise call the raising `build_resolver`). `status` unchanged. |
| `octirb/config.py`, `config.example.toml` | `[report_labels]`: `enabled = true`, `color = "#5b6abf"` (validated as `#RRGGBB`). Unknown keys fail loud. |
| `README.md`, `CLAUDE.md`, `skills/octi-link-reports/SKILL.md` | Linker table row; "no model step — skip to validate" note like `report-vuln`. |

## Error handling

- `sector_roots`: bounded (n² pops); an unknown id, no reachable root (a
  parent cycle) or exceeding the bound raises `ValueError`. `labels_for`
  logs that sector and skips it — the report's other labels still apply.
- Per-report `OpenCTIError` in `batch`/`apply`: logged, report skipped,
  run continues.
- Every function asserts inputs and a post-condition (NASA rule 5);
  functions ≤ 60 lines; all loops bounded.

## Testing

TDD, hand-written fakes, no network.

- `tests/test_report_labels.py` — `sector_roots`: single root, dual parents
  → two roots, parentless sector is its own root, cycle raises, bound
  raises. `labels_for`: countries + sectors, alias mapping before the walk,
  existing labels dropped casefolded, shared-root dedupe, nothing to add.
  `select`: requires objects, keeps text-less reports, honours gates.
  `validate`: bad `report_id` / empty label / bad `from` → `hard_fail`.
  `apply`: preexisted at apply time, failed write not ledgered, checkpoint
  per write, dry-run zero writes, casefold label reuse. `revert_labels`:
  skips preexisted, retains failures, already-absent counts as done.
- `tests/test_ledger.py` — `label_row` key and merge.
- `tests/test_client.py` — `report_label_sources` pagination and page cap;
  `sector_parents` shape; `find_label` casefold.
- `tests/test_cli.py` — end-to-end select → batch → validate → apply
  `--dry-run` → apply → revert on a fake client; mixed ledger where revert
  removes label rows and leaves containment rows.
- `tests/test_config.py` — `[report_labels]` defaults, bad color, unknown
  key.
- Gate: `ruff check octirb/ tests/ contrib/`, `mypy --strict octirb/`,
  `pytest -q` — zero warnings.
