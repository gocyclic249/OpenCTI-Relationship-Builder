# octi-rb — OpenCTI Relationship Builder

`octi-rb` enriches an [OpenCTI](https://filigran.io/solutions/opencti/) platform's
relationships: it links reports to the locations, sectors, actors and CVEs
they discuss, and builds actor → target relationships from what the article
actually says. It ships as a stdlib-only Python CLI plus a Claude Code
plugin that drives it.

## What it is

`octi-rb` is a **harness, not an extractor**. The CLI selects reports,
fetches and cleans their text, and writes a `batch.json` plus a generated
`CONTRACT.md`; a Claude Code skill then reads the batch against the
contract and writes `extractions.json`. There is no NLP model or LLM call
inside the codebase itself — every extraction happens as a Claude Code
step, and the code's job is everything around it: selection, text tiering,
validation, writing, and revert.

That split exists because the properties that matter for touching a
production threat-intel platform are enforced in code, not in a prompt:

- **Nothing is invented by default.** A name the tool can't resolve becomes
  a review item, never a guess. Only `confidence: high` extractions
  auto-apply; `--include-review` can promote judgement calls, but never an
  item marked `hard_fail: true`. Every extraction carries an evidence quote.
- **The run directory is the ledger.** `applied.json` is the authoritative
  record of what this run wrote; `revert` replays it in reverse. Labels on
  platform objects are for UI filtering only — they are never read back to
  decide what to undo.
- **Dry-run runs the identical decision pass with zero mutations**,
  including revert's own prediction of what a purge would delete.
- **Relationships upsert.** Pre-existence is checked before every write, and
  anything that already existed on the platform (`preexisted: true`) is
  never deleted by revert.
- **Checkpoint after every partial write**, so a mid-apply crash never
  leaves a platform write the ledger doesn't own.
- **Zero runtime dependencies.** Python 3.11+ standard library only
  (`urllib`, `tomllib`) — no `pycti`, no `requests`, nothing to audit in a
  supply chain beyond CPython itself.

The CLI never invents platform objects: it never creates a Location, a
Sector, or a Vulnerability. It only creates an Intrusion-Set or
Threat-Actor-Group, and only under `--create-missing`, and only at
`confidence: high`.

## Install

### Option A: Claude Code plugin

Add this repository as a plugin marketplace, then install the plugin:

```
/plugin marketplace add gocyclic249/OpenCTI-Relationship-Builder
/plugin install opencti-relationship-builder
```

This gives you the `octi-setup`, `octi-link-reports`, `octi-link-actors`
and `octi-review` skills, which walk the CLI steps below for you inside a
Claude Code session.

### Option B: clone and run in place

```
git clone https://github.com/gocyclic249/OpenCTI-Relationship-Builder.git
cd OpenCTI-Relationship-Builder
./install-deps.sh          # dev tooling (ruff, mypy, pytest, shellcheck) + crosswalk cache
cp config.example.toml config.toml
```

Either way, `octi-rb` runs as `bin/octi-rb` from the repository root — it
needs no `pip install` step of its own, since it has no runtime
dependencies.

## Quick start

1. **Configure.** Edit `config.toml`: set `[platform].url` to your OpenCTI
   instance, and either set `[platform].env_file` to a `.env` file that
   defines `OPENCTI_TOKEN` (or `OPENCTI_ADMIN_TOKEN`), or export one of
   those two variables directly. The token is never read from
   `config.toml` itself.

   ```
   export OPENCTI_TOKEN=...
   bin/octi-rb doctor
   ```

   `doctor` checks connectivity, the sector/actor/location vocabularies,
   the crosswalk cache age, the text-fetch connector, and disk space. Fix
   anything it flags before continuing.

   `config.toml` is found in this order: the top-level `--config PATH`
   flag, then `$OCTI_RB_CONFIG`, then `./config.toml` in the current
   directory — so you can keep more than one config around (e.g. one per
   platform) and select between them per invocation.

2. **Select** a batch of reports (or actors) for one linker:

   ```
   bin/octi-rb select --linker report-location --limit 25
   ```

   Add `--all-reports` on a second or later pass over the same corpus
   (the default only selects reports that don't already carry this
   linker's containment).

3. **Fetch** article text into the shared cache (report-* linkers only):

   ```
   bin/octi-rb fetch
   ```

4. **Batch.** Writes `batch.json` and `CONTRACT.md` for the model step
   (`report-vuln` skips this — it's deterministic and writes
   `extractions.json` directly):

   ```
   bin/octi-rb batch
   ```

5. **Extract with Claude.** Read `batch.json` against `CONTRACT.md` and
   write `extractions.json` in the run directory — this is the one step
   that isn't a CLI command; it's a Claude Code task (see the
   `octi-link-reports` / `octi-link-actors` skills for the judgement rules
   this step should follow).

6. **Validate**, splitting extractions into auto-applicable and
   review-queue items:

   ```
   bin/octi-rb validate
   ```

7. **Dry-run, inspect, then apply:**

   ```
   bin/octi-rb apply --dry-run
   bin/octi-rb apply
   ```

   Add `--include-review` to also apply non-`hard_fail` review items once
   you've read their evidence, or `--create-missing` (report-actor only)
   to mint a missing Intrusion-Set/Threat-Actor-Group at `confidence: high`.

8. **Revert**, if needed — replays this run's ledger in reverse, in a
   single dry-run-or-real pass:

   ```
   bin/octi-rb revert --dry-run
   bin/octi-rb revert
   ```

`bin/octi-rb status` lists every run directory with its counts at each
stage. Every pipeline command (`select`, `fetch`, `structured`, `batch`,
`validate`, `apply`, `revert`) accepts `--run-id`: for `select` it names
the new run (refused if it already exists); for the rest it selects an
existing run, and omitted resolves to the most recently created one.
`status`, `doctor` and `crosswalk` take no `--run-id` — they aren't
scoped to a single run.

## Linkers

| Linker | Subject → target | Write | Model step? |
|---|---|---|---|
| `report-location` | Report → Country | containment | yes — ISO 3166 alpha-3 codes only |
| `report-sector` | Report → Sector | containment | yes — canonical names only |
| `report-actor` | Report → Intrusion-Set / Threat-Actor-Group | containment | yes — full alias chains |
| `report-vuln` | Report → Vulnerability | containment | no — regex + exact lookup |
| `actor-target` | Actor → Country / Region / Sector | relationship (`targets` / origin) | yes — evidence pairs |

`report-vuln` never guesses at an unresolved CVE ID — with NVD feeds
present on most platforms, an unrecognized ID is more likely wrong than
new, so it goes to review. `actor-target` never infers a pairing from two
actors merely appearing in the same report; each pair needs a quote that
actually connects them.

## Configuration

See [`config.example.toml`](config.example.toml) for every key, its
default, and a comment explaining it — copy it to `config.toml` and edit
what you need. A few keys worth calling out:

- **The OpenCTI token is never stored in config.** Set `$OPENCTI_TOKEN` or
  `$OPENCTI_ADMIN_TOKEN` in the environment, or point
  `[platform].env_file` at a `.env` file that defines one of them.
- `[selection]` and `[text]` control which reports are picked up and how
  their article text is sourced (description → stored file → shared cache
  → fetch, in that order, first hit wins).
- `[sectors]` scopes the canonical sector vocabulary to specific report
  authors (`canonical_authors`) plus your own sector subtrees
  (`extra_roots`), and maps platform duplicate names onto canonical ones
  (`aliases`).
- `[actors]` controls crosswalk-assisted resolution
  (`crosswalk_enabled`, the MISP threat-actor galaxy), alias write-back
  (`alias_writeback`), and what entity type `--create-missing` mints.

Config loading fails loud: an unknown key, wrong type, or out-of-range
value aborts immediately, naming the offending key.

## Safety properties

- **Review queue, not auto-apply-everything.** Only `confidence: high`
  extractions apply by default; anything else sits in `review.json` until
  a human (or the `octi-review` skill) looks at the evidence.
- **`hard_fail` is not overridable.** `--include-review` can promote a
  judgement call, but never an item the validator marked `hard_fail: true`.
- **Dry-run everywhere.** `apply --dry-run` and `revert --dry-run` run the
  exact same decision logic as the real thing, with zero platform writes.
- **The ledger is authoritative, not the labels.** `applied.json` in each
  run directory is what `revert` replays; `AI-*` labels on platform
  objects are for filtering in the OpenCTI UI only.
- **Revert never deletes what it didn't create.** Anything the ledger
  marks `preexisted: true` — a relationship, alias, or containment that
  was already there — is left alone.

## Development

```
ruff check octirb/ tests/
mypy --strict octirb/
pytest -q
shellcheck install-deps.sh
./install-deps.sh --check
```

`install-deps.sh` (no arguments) installs whatever dev tooling is missing
and refreshes the crosswalk cache; `--check` reports presence only and
changes nothing. See [`config.example.toml`](config.example.toml) for the
configuration reference and the design doc under
`docs/superpowers/specs/` for the full architecture.
