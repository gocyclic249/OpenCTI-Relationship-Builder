---
name: octi-review
description: Work a run's review.json queue after `validate` — promote, drop, or fix the root cause of each item, propose sector aliases for recurring duplicates, and confirm crosswalk/alias-writeback equivalences against the article. Trigger on "review queue", "work the review queue", "octi review", "check review.json", or "why is this stuck in review".
---

# octi-review

Works a run's `review.json` after `bin/octi-rb validate` has split
`extractions.json` into `auto.json` (writes automatically) and
`review.json` (needs a human look). This is what makes `apply
--include-review` safe to run afterward — never run `--include-review`
against a `review.json` you haven't read.

Every item in `review.json` carries `review_reasons` (why it's here) and
`hard_fail` (`true`/`false`). It may also carry `via_crosswalk` (resolved
only through the MISP synonym cache), `alias_writes` (candidate aliases to
write back to the resolved entity), or `creatable` (eligible for
`--create-missing`, `report-actor` only).

## The hard rule

**`hard_fail: true` is never promotable — by you, and not by
`--include-review` either.** These are structurally unwritable: a missing
evidence quote, an invalid role/confidence value, a report or actor outside
this run's selection, a duplicate write already covered by another item, or
(for `actor-target`) a candidate that failed enum/scope/schema checks. If
you ask "can I just apply this one anyway," the answer for a `hard_fail`
item is always no — fix the extraction (edit `extractions.json` and
re-validate) or drop it; there is no override.

Everything with `hard_fail: false` is a judgement call the tool declined to
make automatically — usually because `confidence` is `medium`/`low`, or the
match came from the crosswalk. These are the ones worth reading carefully.

## Checklist

1. **Read `review.json`** for the run (and `CONTRACT.md` / the original
   article text for context on each item).

2. **For each item, decide one of three things:**

   - **Promote it.** Fix the extraction in `extractions.json` (correct a
     typo, add the missing evidence quote, fix an enum value) and re-run:

     ```
     bin/octi-rb validate
     ```

     to move it into `auto.json`, or include it via
     `bin/octi-rb apply --dry-run --include-review` /
     `bin/octi-rb apply --include-review` once you've confirmed it's
     genuinely correct (never for a `hard_fail: true` item — fix the root
     cause instead, per above).

   - **Drop it.** Leave it in `review.json` (or note it as rejected) if the
     evidence doesn't actually support the extraction. Nothing further
     needs to happen — items left in `review.json` are never applied unless
     explicitly promoted.

   - **Fix the root cause**, when the same defect recurs across items (see
     below) — this is usually the higher-leverage fix over promoting items
     one at a time.

3. **A recurring unresolved sector name → propose a `[sectors].aliases`
   entry.** If several items repeat `unresolved sector '<name>'` for the
   same non-canonical name (a platform duplicate of a canonical sector,
   e.g. an imported "Energy & Utilities" sitting alongside the canonical
   "Energy"), propose adding it to `config.toml`:

   ```toml
   [sectors]
   aliases = { "Energy & Utilities" = "Energy" }
   ```

   Before proposing it, confirm the target name is actually canonical on
   this platform (`bin/octi-rb doctor` reports `[sectors].aliases
   target(s) not canonical` if it isn't — see `octi-setup`), and that the
   two names really are duplicates of the same real-world sector, not two
   different things that happen to sound similar.

4. **An unresolved actor with a crosswalk note → confirm the equivalence
   before accepting.** An item with `via_crosswalk` set (and a review
   reason like `resolved via crosswalk cluster '<cluster>'`) means the
   *only* reason it resolved at all is a MISP galaxy synonym hit — no
   direct platform match. Read the cluster name in `via_crosswalk` and
   confirm the article's own evidence genuinely supports treating that name
   as the same adversary as the resolved platform entity before promoting
   it; the crosswalk is a large, community-maintained set and is not
   infallible. If the equivalence doesn't hold for this article, drop the
   item rather than promote it.

5. **Alias write-back proposals → verify the article states the
   equivalence.** `report-actor` items (with `[actors].alias_writeback =
   true` in `config.toml`, the default) can carry `alias_writes`: names
   from the extraction's alias chain that aren't yet a known spelling of
   the resolved entity. These get written to the entity's
   `x_opencti_aliases` on `apply`, for any item that ends up in
   `auto.json`/is promoted — so before applying, confirm the article text
   itself states the equivalence ("UNC6293 is a sub cluster of ICE RELIC
   (formerly APT29)"), not just that the name appeared somewhere nearby.
   Correct or drop the offending alias from the extraction if it doesn't
   hold up, rather than letting a wrong equivalence get written to the
   platform.

6. **Re-run `validate` after any edit to `extractions.json`**, and finish
   with a **dry-run before applying for real**:

   ```
   bin/octi-rb validate
   bin/octi-rb apply --dry-run --include-review
   bin/octi-rb apply --include-review
   ```

   Read the dry-run output before the real apply — it runs the identical
   decision pass with zero platform writes, so it's the last chance to
   catch a promotion you didn't mean to make.
