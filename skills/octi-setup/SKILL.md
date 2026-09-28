---
name: octi-setup
description: Configure and health-check octi-rb against an OpenCTI platform — copy config.example.toml, set the platform URL and API token, run `octi-rb doctor`, and walk every finding to its fix until doctor is clean. Trigger on "octi setup", "set up octi-rb", "configure OpenCTI Relationship Builder", "enrich OpenCTI", "run doctor", or "octi-rb doctor is failing".
---

# octi-setup

> **Paths.** Commands use `${CLAUDE_PLUGIN_ROOT}/bin/octi-rb` — Claude Code sets
> `CLAUDE_PLUGIN_ROOT` for plugin skills. From a repo clone, run `bin/octi-rb`
> from the repository root instead.

Gets a fresh checkout of `octi-rb` from zero to a clean `${CLAUDE_PLUGIN_ROOT}/bin/octi-rb doctor`
run. Do this once per OpenCTI platform (or per `config.toml` you keep) before
running any of the other skills. Run every command from the directory that
holds your `config.toml` (or point `$OCTI_RB_CONFIG` / `--config` at it).

## Checklist

1. **Copy the example config**, if `config.toml` doesn't already exist:

   ```
   cp "${CLAUDE_PLUGIN_ROOT}/config.example.toml" config.toml
   ```

   Every key in `config.example.toml` is documented inline with its default.
   An unmodified copy behaves identically to no config file at all, so only
   edit the keys you actually need to change.

2. **Point it at the platform.** In `config.toml`, set:

   ```toml
   [platform]
   url = "https://your-opencti-instance"
   ```

3. **Provide the API token — never in `config.toml`.** Pick one:

   - Export it in the environment:

     ```
     export OPENCTI_TOKEN=...
     ```

     (`OPENCTI_ADMIN_TOKEN` also works, and is checked as a fallback.)

   - Or point `config.toml` at a `.env` file that defines one of those two
     names:

     ```toml
     [platform]
     env_file = "/path/to/.env"
     ```

   Config resolution order, if you keep more than one config around (e.g.
   one per platform): the top-level `--config PATH` flag, then
   `$OCTI_RB_CONFIG`, then `./config.toml` in the current directory.

4. **Run doctor:**

   ```
   ${CLAUDE_PLUGIN_ROOT}/bin/octi-rb doctor
   ```

   It checks: platform connectivity, `reports()` connectivity, the sector
   vocabulary, every `report-*` linker's resolver (against a handful of
   probe values), the crosswalk cache age, the `ImportExternalReference`
   fetch connector, and disk space. It exits 0 and prints `doctor: OK` only
   when every check that can fail passes; otherwise it prints
   `doctor: FAILED` and exits 1. Every finding is one line on stderr
   prefixed `doctor: `.

5. **Walk every finding to its fix** — doctor keeps checking everything else
   even after one check fails, so address all of the following that appear
   before re-running:

   - **`no sectors authored by [...] on this platform — is the OpenCTI
     Datasets connector enabled?`** — The canonical sector vocabulary comes
     from sectors whose `createdBy` name is in `[sectors].canonical_authors`
     (default `["Filigran"]`). Either enable the OpenCTI Datasets connector
     on the platform (it seeds Filigran's sector tree), or, if this
     deployment's sectors were authored under a different name, change
     `canonical_authors` in `config.toml` to match.

   - **`[sectors].aliases target(s) not canonical: ...`** — A
     `[sectors].aliases` entry in `config.toml` points at a name that isn't
     in the canonical set. Fix the target name (or add it via
     `extra_roots`/`canonical_authors` above).

   - **`<linker> could not resolve probe(s): ...`** (e.g. `report-actor`,
     `report-location`) — that linker's resolver failed to resolve its own
     sample values. Re-check the underlying vocabulary is populated on the
     platform (locations need the Gazetteer, actors need Intrusion-Sets /
     Threat-Actor-Groups to exist) before continuing.

   - **crosswalk cache: `crosswalk cache missing; run \`octi-rb crosswalk
     refresh\`` or `crosswalk cache is N day(s) old (max M)`** — run:

     ```
     ${CLAUDE_PLUGIN_ROOT}/bin/octi-rb crosswalk refresh
     ```

     This downloads and atomically caches the MISP threat-actor galaxy used
     for actor-name synonym resolution. If you deliberately don't want this
     enrichment, set `[actors].crosswalk_enabled = false` in `config.toml`
     instead — doctor then reports the check as satisfied rather than
     missing.

   - **`connector ImportExternalReference not present/active; fetch-tier
     reports will be skipped`** — Either install/enable the
     `ImportExternalReference` connector on the platform, or, if
     fetch-tier text capture isn't needed for this deployment, set
     `[text].fetch_enabled = false` in `config.toml` so doctor treats fetch
     as intentionally disabled instead of broken.

   - **`reports connectivity failed: ...`** or doctor exits before printing
     `doctor: platform url ...` at all — re-check `[platform].url` and the
     token (step 2–3); a wrong URL, an expired token, or a token env var
     that isn't actually set are the usual causes.

   - **disk space warnings** (`disk: ...` lines from the disk check) —
     doctor still reports `OK` around these; free space on the filesystem
     holding the runs/cache directory, or raise `[disk].warn_percent`
     if the warning is a false positive for this host.

6. **Re-run doctor** after each fix:

   ```
   ${CLAUDE_PLUGIN_ROOT}/bin/octi-rb doctor
   ```

   Repeat until it prints `doctor: OK` and exits 0. Only then move on to
   `octi-link-reports`, `octi-link-actors`, or `octi-review`.
