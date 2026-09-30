# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`octi-rb` enriches an OpenCTI platform: it links reports to the locations, sectors, actors and CVEs they discuss (containment), and builds actor → target relationships. It is a **harness, not an extractor** — there is no LLM call in the code. The CLI selects, fetches, batches, validates, applies and reverts; the extraction step (`batch.json` + `CONTRACT.md` → `extractions.json`) is done by a Claude Code skill in `skills/`. The repo is also a Claude Code plugin (`.claude-plugin/`, `skills/*/SKILL.md`).

Python 3.11+ **standard library only** (`urllib`, `tomllib`) — do not add runtime dependencies (no `pycti`, no `requests`). `pyproject.toml` exists only to pin lint/type settings; there is no `pip install` step.

## Commands

```
bin/octi-rb <cmd>                         # run from a clone (bin/ adds the repo to sys.path)
ruff check octirb/ tests/ contrib/
mypy --strict octirb/
mypy --strict contrib/migrate-legacy-labels.py
pytest -q                                  # whole suite
pytest tests/test_writer.py::test_name -q  # single test
shellcheck install-deps.sh
./install-deps.sh --check                  # report dev-tool presence only
```

Pipeline order: `select --linker <name>` → `fetch` → `batch` (→ optional `structured`) → *model writes `extractions.json`* → `validate` → `apply [--dry-run]` → `revert [--dry-run]`. Every pipeline command takes `--run-id` (for `select` it names a new run; otherwise defaults to the most recent run). `status`, `doctor`, `crosswalk` are not run-scoped. Config is resolved `--config` → `$OCTI_RB_CONFIG` → `./config.toml`; the API token comes only from `$OPENCTI_TOKEN`/`$OPENCTI_ADMIN_TOKEN` or `[platform].env_file`, never from the TOML.

## Architecture

- **`octirb/cli.py`** — argparse wiring and `cmd_*` handlers. Branches on linker: `actor-target` has its own select/batch/validate paths (`_batch_actor_target`, `_validate_actor_target`) that go through `linkers/actor_target.py`, while the four `report-*` linkers share `octirb/pipeline.py`.
- **`octirb/linkers/__init__.py`** — `REGISTRY` of `Linker` records (key field, allowed roles, label suffix, `write_kind` = `containment` | `relationship`, `needs_model`, `build_resolver`, `contract`). Adding a report dimension means a registry entry + a resolver + a contract. `report-vuln` has `needs_model=False` (regex + exact lookup; `batch` writes `extractions.json` directly). `actor-target`'s `build_resolver` intentionally raises — it builds its own `Context`.
- **`octirb/linkers/base.py`** — `Resolver`/`Resolved`/`Creator` Protocols that every vocabulary in `octirb/resolvers/` implements (gazetteer = ISO3 countries, sectors = config-scoped canonical tree + aliases, actors = alias chains + optional MISP galaxy `crosswalk`).
- **`octirb/pipeline.py`** — select/materialize-text/batch (part 1) and validate/create_missing/apply_containment/revert_containment/purge_created (part 2) for containment linkers. Crosswalk-only matches are demoted to review; actor alias write-back records `alias_writes`.
- **`octirb/writer.py`** — relationship apply/revert for `actor-target` (via a `WriterClient` Protocol so tests use fakes).
- **`octirb/ledger.py`** — one ledger of `kind`-tagged rows (containment, relationship, alias, entity), `row_key`/`merge_ledger`, and the pure `should_delete_*` decisions.
- **`octirb/runstore.py`** — `Run` (a run directory of JSON files; `write_json` is atomic) and the shared `TextCache` keyed by report id. Runs default to `$XDG_STATE_HOME/octi-rb/runs` (cache is its sibling `cache/`) unless `[runs].dir` is set.
- **`octirb/text.py`** — text-tier planning: description → stored file → cache → fetch, first hit wins. `octirb/structured.py` — deterministic parsers for publishers with fixed fields (e.g. CISA ICS advisories), always `confidence: high`.
- **`octirb/client.py`** — hand-rolled GraphQL client over `urllib`. **`octirb/config.py`** — typed dataclasses; loading fails loud on unknown keys/wrong types.
- **`contrib/`** — one-off, operator-specific scripts (legacy octi-geo/octi-rel label migration); not part of the package.

Much of the code is ported from predecessor tools `octigeo`/`octirel`; module docstrings record what was ported and what was deliberately changed — read them before restructuring.

## Invariants (enforced in code; don't weaken them)

- `applied.json` in the run dir is the authoritative ledger; `revert` replays it. `AI-*` labels on platform objects are for UI filtering only and are never read to decide what to undo.
- Check pre-existence before every write; rows marked `preexisted: true` are never deleted by revert.
- Checkpoint `applied.json` after every platform write.
- `--dry-run` must run the identical decision pass with zero mutations (including revert's purge prediction).
- Only `confidence: high` auto-applies; `--include-review` never promotes `hard_fail: true`. Unresolved names become review items, never guesses.
- Never create Locations, Sectors or Vulnerabilities. Only Intrusion-Set/Threat-Actor-Group, only under `--create-missing`, only at `confidence: high`.

## Lint conventions

ruff runs a broad rule set (see `pyproject.toml`) plus `mypy --strict`. Suppressions are inline `# noqa: CODE - reason` with a reason, or per-file ignores in `pyproject.toml` with a comment explaining each; approved rule deviations are marked `RULE EXCEPTION:`. Tests use hand-written fake clients mirroring real method signatures (see `tests/conftest.py`'s `fake_gql_client`) — no network.

Design spec and implementation plan: `docs/superpowers/specs/2026-09-28-octi-rb-design.md`, `docs/superpowers/plans/2026-09-28-octi-rb.md`.
