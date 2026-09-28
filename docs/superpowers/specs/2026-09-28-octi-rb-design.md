# octi-rb — OpenCTI Relationship Builder

**Date:** 2026-09-28
**Status:** Approved design, pre-implementation
**Supersedes (by generalization):** octi-geo and octi-rel in `~/opencti-docker`

## Intent

octi-geo and octi-rel work, but they grew piece by piece: two CLIs, two run
directories, two ledger formats, constants hard-coded to one operator's stack.
octi-rb is a single, unified rewrite intended for a **public repo**: a Python
CLI plus Claude Code skills that anyone running OpenCTI can use to enrich
their platform's relationships. It generalizes the location work to all
reports, widens sectors beyond the ICS tree, reworks the threat-actor
handling, adds vulnerability linking, and moves every operator-specific
constant into a config file.

**Scope (option B):** report containment for Location, Sector, Actor and
Vulnerability, plus explicit actor → location/sector relationships. Other
subjects (Campaigns, Malware `targets`, `exploits`) are out of scope but the
linker registry is the designed extension point for them.

## Non-negotiable properties (ported, not reinvented)

These were paid for in live incidents on the predecessor tools and carry over
wholesale, with their tests:

1. **Harness, not extractor.** The CLI selects, fetches, validates and
   writes; Claude does the extraction by reading `batch.json` against a
   generated `CONTRACT.md`. No NLP model in the codebase.
2. **Nothing is invented by default.** Unresolved names become review items.
   Only `confidence: high` auto-applies; `--include-review` promotes
   judgement calls but never `hard_fail: true` items. Evidence quotes are
   required.
3. **The run directory is the ledger.** `applied.json` is the authoritative
   record; `revert` replays it. Labels are for UI filtering only.
4. **Zero runtime dependencies.** Python 3.11+ stdlib only (`urllib`,
   `tomllib`; no `pycti`, no `requests`).
5. **Dry-run everywhere**, running the identical decision pass with zero
   mutations — including the purge prediction's own-refs discount.
6. **Relationships upsert**, so pre-existence is checked before every write
   and `preexisted: true` rows are never deleted by revert.
7. **Checkpoint after every partial step** so a mid-apply crash never leaves
   a write the ledger doesn't own.
8. Coding standards: ruff clean, `mypy --strict` clean, shellcheck clean,
   Power-of-10 rules (bounded loops, two checks per function, ≤60-line
   functions), pinned in `pyproject.toml`.

## Repo layout

```
OpenCTI-Relationship-Builder/
├── .claude-plugin/
│   ├── plugin.json              # Claude Code plugin manifest
│   └── marketplace.json         # enables /plugin marketplace add <user>/<repo>
├── skills/
│   ├── octi-setup/              # first-run: config, doctor
│   ├── octi-link-reports/       # report-* containment runs
│   ├── octi-link-actors/        # actor-target relationship runs
│   └── octi-review/             # review queue, alias write-backs
├── octirb/                      # Python package (stdlib only)
│   ├── cli.py                   # argparse, one cmd_* per subcommand
│   ├── config.py                # TOML load + validation (fail loud)
│   ├── client.py                # GraphQL client            [ported: octigeo/client.py + octirel/relclient.py]
│   ├── runstore.py              # run dirs; latest = max meta.json["created"], never lexicographic
│   ├── ledger.py                # unified ledger + merge rules [ported: octirel/writer.py merge/should_delete]
│   ├── pipeline.py              # select → fetch → batch → validate → apply → revert
│   ├── linkers/
│   │   ├── base.py              # Linker protocol
│   │   ├── report_location.py
│   │   ├── report_sector.py
│   │   ├── report_actor.py
│   │   ├── report_vuln.py       # deterministic; no model step
│   │   └── actor_target.py
│   ├── resolvers/
│   │   ├── gazetteer.py         # ISO 3166 countries      [ported: octigeo/gazetteer.py incl. COMMON_NAMES]
│   │   ├── sectors.py           # author-scoped canonical set + config roots
│   │   ├── actors.py            # normalization + platform aliases + crosswalk + conflict()
│   │   └── crosswalk.py         # MISP threat-actor galaxy cache + lookup
│   ├── text.py                  # tiers, cleaning, title guard [ported: octigeo/clean.py]
│   └── structured.py            # per-publisher parsers   [ported: octigeo/structured.py, CISA ships]
├── contrib/
│   └── migrate-legacy-labels.py # one-time octi-geo/octi-rel ledger relabel (operator-specific)
├── bin/octi-rb
├── config.example.toml          # fully commented
├── install-deps.sh              # dev tooling + crosswalk download; Debian/Ubuntu/Fedora; idempotent
├── README.md
└── tests/
```

## Data flow

```
select ──▶ fetch ──▶ batch ──▶ [ Claude extracts against CONTRACT.md ] ──▶ validate ──▶ apply ──▶ revert
              │                                                                ▲
              └── structured (publisher-field parsers) ────────────────────────┘
```

One run directory per run under the runs dir: `meta.json` (records linker,
created timestamp, selection), `batch.json`, `CONTRACT.md`,
`extractions.json`, `review.json`, `applied.json`. `meta.json` is written
last at select time; a linker mismatch between run and command is a hard
error. `report-vuln` runs and structured parsers skip the Claude step.

## Configuration

TOML, stdlib `tomllib`. Located by `--config`, then `$OCTI_RB_CONFIG`, then
`./config.toml`. `config.py` validates on load and fails loud: unknown keys,
bad types, and inconsistent combinations (e.g. `fetch_enabled` with a
malformed host) are startup errors naming the offending key. Credentials are
**never** stored in config: the token comes from `$OPENCTI_TOKEN` /
`$OPENCTI_ADMIN_TOKEN`, or from an env file config points at.

```toml
[platform]
url = "http://localhost:8080"
env_file = ""                      # optional .env path holding the token

[runs]
dir = ""                           # default ~/.local/state/octi-rb/runs (XDG); cache/ lives beside it

[labels]
prefix = "AI-"
color = "#0d7d8c"

[selection]
since_days = 183                   # 0 = no limit
sources = []                       # [] = all report authors
exclude_sources = []               # authors skipped entirely
exclude_title_patterns = []        # case-insensitive regex, e.g. ["^ISC Stormcast"]

[text]
fulltext_min_chars = 2000
title_match_min = 0.5
fetch_enabled = true               # tier 4 only; see text tiers
fetch_exclude_sources = []         # selected but never fetched
fetch_hosts = []                   # [] = any host; non-empty = allowlist
max_fetch_per_run = 50             # hard cap; 0 = unlimited

[disk]
warn_percent = 75                  # 0 disables
paths = []                         # extra mounts to watch, e.g. ["/var/lib/docker"]

[sectors]
canonical_authors = ["Filigran"]
extra_roots = []                   # e.g. ["ICS"] — trees walked via part-of
aliases = {}                       # platform-duplicate mapping, e.g. "Energy & Utilities" = "Energy"

[actors]
create_missing_type = "Intrusion-Set"
crosswalk_enabled = true
crosswalk_max_age_days = 90        # doctor warns beyond this
alias_writeback = true

[vulns]
enabled = true
```

### Text tiers

Per report, in order; the first hit wins and later tiers never run:

1. Description ≥ `fulltext_min_chars` → use it (no request).
2. A usable file already stored on the report in OpenCTI → use it (no request).
3. A capture already in the shared text cache → use it (no request).
4. `fetch_enabled` and the report passes `fetch_exclude_sources` /
   `fetch_hosts` and the run is under `max_fetch_per_run` → fetch via the
   ImportExternalReference connector (wait for the `.md`, not the PDF).

A report with no usable text is skipped and counted in `status`, never
guessed at. The **text cache is shared across runs** at
`cache/text/<report-id>/`, so a second linker's run never re-fetches what an
earlier run captured; re-cleaning from cached files is free. Cleaning keeps
the ported boilerplate stripper (link-density block scoring, multi-line
markdown-link normalisation) and the title-similarity guard
(`title_match_min`), because a fetched capture may be a different article
than the URL named.

### Disk watch

`shutil.disk_usage` over the runs/cache filesystem plus every `[disk].paths`
entry, checked at `doctor`, `select`, and before each fetch batch. Over
`warn_percent` → one warning line to stderr naming mount, percentage and free
bytes; the run continues. (A remote platform's disk is invisible to the API;
`paths` is the operator's way to name what matters, e.g. Docker volumes.)

## Linkers

The registry is fixed and enumerated in-file (`linkers/base.py`); each linker
declares subject, target, resolver, contract text, and write kind.

| Linker | Subject → target | Write | Model? |
|---|---|---|---|
| `report-location` | Report → Country | containment (objectRef) | yes — ISO 3166 alpha-3 codes only |
| `report-sector` | Report → Sector | containment | yes — canonical names only |
| `report-actor` | Report → Intrusion-Set / Threat-Actor | containment | yes — alias chains |
| `report-vuln` | Report → Vulnerability | containment | **no** — regex + exact lookup |
| `actor-target` | Actor → Country / Region / Sector | relationship (`targets` / origin) | yes — evidence pairs |

Shared validation (ported): only `high` auto-applies; review items carry
`hard_fail`; duplicate collapse per (subject, target); evidence quotes
mandatory; selection-membership check.

### report-location

Contract emits ISO 3166 alpha-3 codes, never names. Gazetteer resolution is
exact on ISO2/ISO3 aliases; `COMMON_NAMES` handles structured sources that
emit colloquial names. Never creates a Location. Roles: origin / target /
mentioned. Containment must be written per report (no platform rule pulls a
location in from a contained actor); one country write still pulls parent
regions free via `report_ref_location_located_at`.

### report-sector

**Vocabulary = author-scoped canonical set:** sectors whose author is in
`canonical_authors` (default Filigran) plus every tree reachable via
`part-of` from `extra_roots` (the operator's ICS tree). All other platform
sectors' names and aliases still resolve — through `[sectors].aliases` onto a
canonical sector, or else to review. Nothing outside the canonical set is
ever written. Built-in colloquialism table (ported ICS aliases) stays in
code; platform-duplicate mapping lives in config. "Tag the narrowest sector"
carries over: `report_ref_identity_part_of` propagates parents free.

### report-actor

Resolution order:

1. Exact match on platform names + aliases (both Intrusion-Set and
   Threat-Actor types loaded).
2. **Normalized match**: case-, hyphen-, whitespace-insensitive
   (`Storm-0558` = `STORM 0558`).
3. **Crosswalk**: if the unknown name's MISP galaxy cluster carries a synonym
   that resolves on the platform (steps 1–2), resolve there. Crosswalk hits
   cap at `medium` (review), recording which cluster matched.

The extraction unit is the adversary with its full in-article alias chain
(`Dimension.alias_field` semantics, ported). `conflict()` checks the malware
index before minting, so ransomware brands stay review items. The `RENAMES`
table stays tiny.

**Alias write-back** (`alias_writeback = true`): when the article itself
states an equivalence ("UNC6293, formerly APT29"), the extraction records the
pair; validate requires that the names co-resolve consistently (one resolves,
or both resolve to the same entity); apply adds the missing alias to the
platform entity and writes an `alias` ledger row. An alias already present is
recorded `preexisted: true` and never removed by revert. Write-backs require
`high` confidence in the stated equivalence.

**`--create-missing`** mints `[actors].create_missing_type` (default
Intrusion-Set — matching how feeds actually model adversaries), requires
`high`, labels the entity `<prefix>Created`, writes an `entity` ledger row.

### report-vuln

Deterministic; no model, no contract step. Regex `CVE-\d{4}-\d{4,}` over the
same tiered text, exact name lookup among platform Vulnerability entities.
Resolved → `high`, auto-applies. Unresolved → review (with NVD feeds present,
an unknown CVE ID is more likely wrong than new). Never creates a
Vulnerability.

### actor-target

Two evidence sources (the blind ledger join is **removed** — it produced 26%
wrong pairs on multi-actor reports):

- `description` — one packet per actor's own description.
- `report` — per-report pair extraction: Claude emits explicit
  actor → target pairs, each carrying both quotes from the same passage;
  co-occurrence without a connecting statement is not a pair.

`origin` is contract vocabulary resolved per actor type
(Intrusion-Set → `originates-from`, Threat-Actor-Group → `located-at`);
`origin` + sector target is a hard fail. `targets` applies to both types.

## Crosswalk (MISP threat-actor galaxy)

CC0-licensed cluster file (~900 actors with cross-vendor synonyms). Cached
locally (beside `cache/text/`) by `octi-rb crosswalk refresh` and by
`install-deps.sh`; never fetched implicitly during a run. `doctor` reports
cache presence and age, warning past `crosswalk_max_age_days`.
`crosswalk_enabled = false` removes step 3 of actor resolution entirely.

## Labels

Prefix configurable (default `AI-`); the ledger, not the label, is
authoritative.

| Label | On | Meaning |
|---|---|---|
| `AI-Location` | report | tool added a Country/Region |
| `AI-Sector` | report | tool added a Sector |
| `AI-Actor` | report | tool added an actor |
| `AI-Vulnerability` | report | tool added a CVE (deterministic write; prefix reads "added by this toolkit") |
| `AI-Relationship` | relationship | tool created the relationship |
| `AI-Created` | entity | tool minted it; revert deletes only entities carrying this label, only while orphaned |

`contrib/migrate-legacy-labels.py` reads the operator's legacy `runs/` and
`runs-rel/` ledgers and applies the new labels so old runs filter and revert
consistently. Operator-specific; not part of the public core.

## Ledger

One format, one file per run (`applied.json`), rows typed by `kind`:

```json
{"kind": "containment",  "report_id": "…", "entity_id": "…", "linker": "report-sector", "created": false}
{"kind": "relationship", "relationship_id": "…", "actor_id": "…", "target_id": "…", "rel_type": "targets", "preexisted": false, "in_reports": ["…"]}
{"kind": "alias",        "entity_id": "…", "alias": "UNC6293", "preexisted": false}
{"kind": "entity",       "entity_id": "…", "entity_type": "Intrusion-Set", "name": "…"}
```

Rules (ported from octi-rel's writer, with its tests):

- `apply` stamps `created`/`preexisted` on the row itself — nothing upstream
  is trusted to.
- `merge_ledger` per kind: containment keys on (report, entity);
  relationship keys keep the id-change rule (prior row survives only when
  relationship_ids match; fresh-preexisting never displaces prior-ours);
  re-apply never duplicates or drops rows.
- Checkpoint after every partial write.
- **Revert order:** strip this run's report objectRefs (every still-owned
  row) → remove `preexisted: false` aliases → delete relationships per
  `should_delete` (label still present, not preexisted, still exists) →
  purge created entities only while orphaned and still labeled, with the
  dry-run own-refs discount.

## CLI

```
octi-rb doctor                     # connectivity, config validation, vocabularies, crosswalk age, disk
octi-rb select --linker <name> [--limit N] [--all-reports | --empty-only] [--since-days N] [--run-id ID]
octi-rb fetch      [--run-id ID]
octi-rb batch      [--run-id ID]
octi-rb structured [--run-id ID]
octi-rb validate   [--run-id ID]
octi-rb apply      [--run-id ID] [--dry-run] [--include-review] [--create-missing]
octi-rb revert     [--run-id ID] [--dry-run]
octi-rb status
octi-rb crosswalk refresh
```

Unix rules: data to stdout (line-oriented / JSON), diagnostics to stderr, no
banners or ANSI in pipeable output. Exit codes: 0 success, 1 operational
failure, 2 bad run/config state (`SystemExit(str)` remapped; argparse's own
exits untouched). Omitted `--run-id` = latest by `meta.json["created"]`.
`select` refuses a reused `--run-id` before building a client.

## Claude Code skills

The repo is a **Claude Code plugin** (`.claude-plugin/plugin.json` +
`marketplace.json`); users add it via `/plugin marketplace add`, or clone and
run in-place. Four skills, each a checklist mirroring the CONTRACT.md
workflow:

- **octi-setup** — copy `config.example.toml`, set url/env_file, run
  `doctor`, fix findings.
- **octi-link-reports** — per report-* linker: select → fetch → structured →
  read `batch.json` against `CONTRACT.md` → write `extractions.json` →
  validate → dry-run → apply. Encodes the judgement rules: ISO codes only;
  narrowest sector; roles and inverted-role trap; naming-table trap;
  false-positive traps (cloud regions, currencies, bylines); reserve `high`
  for what the text states plainly.
- **octi-link-actors** — actor-target flow; read every pair's two-quote
  evidence before `--include-review`.
- **octi-review** — work `review.json`: promote or drop items, propose
  `[sectors].aliases` entries for recurring platform duplicates, confirm
  alias write-backs.

## Testing and quality gates

- Ported modules arrive with their existing tests (actors resolution and
  conflict guard, gazetteer, should_delete/purge, merge_ledger rules,
  validate, apply pre-existence and checkpointing, revert parity).
- New seams get dedicated tests: config validation (every error path),
  text-tier ordering (a report with a long description never fetches),
  fetch cap, CVE regex + lookup, normalization, crosswalk resolution
  (including "cluster synonym not on platform → review"), alias write-back
  validate/apply/revert, ledger `kind` dispatch, disk-warn threshold.
- CLI wiring tests in the style of `test_rel_cli.py` — the predecessor's
  two live-only defects both lived in wiring, not units.
- Gate, pinned in `pyproject.toml`: `ruff check` clean, `mypy --strict`
  clean, `pytest -q` green, `shellcheck install-deps.sh` clean, every commit.

## Out of scope (explicit)

- Campaign/Malware subjects and `exploits` relationships (scope C) — the
  linker registry is where they land later.
- Creating Locations, Sectors or Vulnerabilities under any flag.
- Any automated `extract` step; the model pass stays a Claude Code task.
- The legacy repos: `~/opencti-docker` stays untouched; migration touches
  only platform labels, driven by its ledgers read-only.
