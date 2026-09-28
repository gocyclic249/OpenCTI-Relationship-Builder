---
name: octi-link-actors
description: Build actor -> target (origin/targets) relationships from an actor's platform description or from report text already populated in the cache. Trigger on "link actors", "actor targeting", "build actor relationships", "run actor-target", "enrich OpenCTI actors", or "link actors to targets".
---

# octi-link-actors

> **Paths.** Commands use `${CLAUDE_PLUGIN_ROOT}/bin/octi-rb` — Claude Code sets
> `CLAUDE_PLUGIN_ROOT` for plugin skills. From a repo clone, run `bin/octi-rb`
> from the repository root instead.

Runs the `actor-target` linker: it builds `origin` (an Intrusion-Set's
`originates-from` / a Threat-Actor-Group's `located-at`) and `targets`
relationships from either an actor's own platform description, or from
report text already in the shared cache. Unlike the `report-*` linkers this
one writes **relationships**, not containment, and has no `fetch` step of
its own. Run `octi-setup` first if `${CLAUDE_PLUGIN_ROOT}/bin/octi-rb doctor` isn't clean.

## Checklist

1. **Select a source and a batch of actors:**

   ```
   ${CLAUDE_PLUGIN_ROOT}/bin/octi-rb select --linker actor-target --source description
   ```

   or, once `report-*` linker runs have populated the text cache with
   article text and actor refs for reports:

   ```
   ${CLAUDE_PLUGIN_ROOT}/bin/octi-rb select --linker actor-target --source report
   ```

   `--source` is required for this linker — `select` refuses with a usage
   message and exit code 2 if it's omitted or given anything else. With
   `--source description`, one packet is written per actor that has a
   non-empty platform description. With `--source report`, one packet is
   written per report that already has cached text *and* at least one
   linked actor (this never triggers a fresh fetch — a report with no
   cached text simply yields no packet). `--limit N` works with either
   source.

2. **Batch** — writes `batch.json` and a generated `CONTRACT.md` (rendered
   for whichever `--source` this run used):

   ```
   ${CLAUDE_PLUGIN_ROOT}/bin/octi-rb batch
   ```

3. **Extract with Claude** — read `batch.json` against `CONTRACT.md` and
   write `extractions.json` in the run directory. Follow the judgement
   rules below, which are the exact rules `CONTRACT.md` states for this
   source.

4. **Validate**, splitting `extractions.json` into `auto.json` and
   `review.json`:

   ```
   ${CLAUDE_PLUGIN_ROOT}/bin/octi-rb validate
   ```

5. **Dry-run, then apply:**

   ```
   ${CLAUDE_PLUGIN_ROOT}/bin/octi-rb apply --dry-run
   ${CLAUDE_PLUGIN_ROOT}/bin/octi-rb apply
   ```

   `actor-target` writes relationships (upsert semantics — pre-existence is
   checked before every write), not containment, so `--create-missing`
   does not apply to this linker.

6. **Before any `apply --include-review`: read every review item's evidence
   pair-by-pair.** A `targets`/`origin` candidate only belongs in
   auto-apply territory when its evidence (for `--source report`, both
   halves of it) is genuinely about the *same* actor — a relationship inferred by juxtaposing two
   separate quotes about two different actors is not a real relationship.
   For each review item you're considering promoting:
   - Read the `evidence` quote and confirm it is actually about the actor
     named in `actor`/`actor_id` for that item, not a neighboring actor
     mentioned nearby in the same packet.
   - With `--source report`, `evidence` carries two quotes joined `" | "`:
     the actor half, then the target half. The two halves must be about the
     same actor — if the target half is about a different actor than the
     actor half names, the pair is false.
   - If the article's evidence conflates two actors, or the quote is
     actually about a *different* actor than the one the candidate claims,
     **drop the item**. `--include-review` writes every non-`hard_fail`
     item left in `review.json`, so dropping means removing it: delete its
     entry from `extractions.json` and re-run `validate` (durable), or
     delete its row from `review.json` after your last `validate` (lost if
     you re-validate). Also record each drop in a `dropped.json` file in
     the run directory (report_id/actor_id/target plus a one-line reason)
     — that file is an audit log only; it stops nothing from being applied.
   - Only after this pass, run `apply --dry-run --include-review`, confirm
     none of your dropped items appear, then `apply --include-review` (this
     still never promotes anything with `hard_fail: true` — see
     `octi-review` for that distinction).

## Judgement rules (embedded from the actor_target contract)

These are the exact rules rendered into `CONTRACT.md` for this linker.

- **origin** = the country or region the actor operates from or for (its
  sponsor or base). Never where its infrastructure happens to be hosted. An
  origin never points at a sector.
- **targets** = a country, region or sector the text says the actor
  attacked or set out to attack.
- Countries are ISO 3166-1 alpha-3 codes (RUS, PRK, CHN), never names.
- Tag the **narrowest** sector that fits; parent sectors propagate by
  part-of.
- Name a region only when the text names a region rather than countries.
- **Hedged attribution is not high.** "Suspected", "assessed with moderate
  confidence", "possibly linked to" → `medium` or `low`. "Attributed to
  Russia's General Staff Main Intelligence Directorate" → `high` origin
  `RUS`.
- **Comparisons yield nothing**: "overlaps with APT28", "similar to
  Lazarus" produce no relationship.
- **Targets must be STATED targets.** "Has targeted government and energy
  organisations in Ukraine" → targets `UKR`, targets "Government and
  administrations", targets "Energy". A case-study victim list, or "the
  malware runs on Windows servers", → nothing.
- **"Government & Defense" is not a value**: emit "Government and
  administrations" and/or "Defense" as the text states.
- With `--source description`: a Markdown citation link naming another
  group (`[Sandworm Team](https://attack.mitre.org/groups/G0034)`) counts
  only if the surrounding statement is about the packet's own actor — links
  to other groups' pages are not statements about this actor.
- With `--source report`: the reporting vendor (Mandiant, GTIG, Kaspersky,
  CISA, ...) is not an actor; an actor mentioned only in passing yields no
  relationships. A report names several actors, so `evidence` must carry
  **both** quotes from the same passage, joined `" | "` — the quote naming
  the actor, then the quote naming the target. The two halves must be about
  the same actor; if the target sentence is about a different actor, emit
  nothing for it.
- evidence must be a real quote from the packet, not a paraphrase.
- confidence "high" only when the text states it plainly — anything
  inferred, hedged or ambiguous is "medium" or "low", and goes to review.
- A packet with nothing genuine gets no entries. Empty is the right answer
  more often than not.
