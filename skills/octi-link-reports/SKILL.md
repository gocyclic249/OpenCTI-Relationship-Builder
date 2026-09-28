---
name: octi-link-reports
description: Run one report-* linker pass (report-location, report-sector, report-actor or report-vuln) end to end — select, fetch, batch, extract against CONTRACT.md, validate, dry-run and apply. Trigger on "link reports", "enrich OpenCTI", "link locations", "link sectors", "link actors to reports", "run the location linker", "run the sector linker", "run the actor linker", or "link CVEs".
---

# octi-link-reports

Runs one of the four report-scoped linkers — `report-location`,
`report-sector`, `report-actor`, `report-vuln` — through the full pipeline
for one run. Run `octi-setup` first if `bin/octi-rb doctor` isn't clean.
Every command below accepts `--run-id`; omit it once you have a run open and
every later command defaults to the most recently created run.

## Checklist

1. **Pick a linker and select a batch of reports:**

   ```
   bin/octi-rb select --linker report-location --limit 25
   ```

   (substitute `report-sector`, `report-actor`, or `report-vuln`). The
   default only selects reports that don't already carry this linker's
   containment (`objects` is empty for it). Add `--all-reports` on a
   second-or-later pass over the same corpus to clear that filter. Other
   useful flags: `--since-days N` (override `[selection].since_days`),
   `--limit N`. Note the printed `run <id> [...]: N item(s) selected` —
   that's your `--run-id` for the rest of this pass if you need to name it
   explicitly.

2. **Fetch article text into the shared cache** (all four `report-*`
   linkers need this; `actor-target` is the only linker without a fetch
   step):

   ```
   bin/octi-rb fetch
   ```

3. **Batch:**

   ```
   bin/octi-rb batch
   ```

   For `report-location`, `report-sector`, and `report-actor` this writes
   `batch.json` (the text packets) and a generated `CONTRACT.md` in the run
   directory, and prints both paths.

   **`report-vuln` is different: it has no model step.** `batch` extracts
   CVE IDs directly with a regex + exact-lookup pass and writes
   `extractions.json` itself — no `batch.json`, no `CONTRACT.md`, no
   extraction task. For `report-vuln`, skip straight to **step 5 (validate)**
   after this command.

4. **Structured pass, then the extraction task** (report-location /
   report-sector / report-actor only):

   a. Run the deterministic structured-field parser. It only has parsers
      for `report-location` and `report-sector` sourced from CISA
      advisories (fixed `CRITICAL INFRASTRUCTURE SECTORS` /
      `COUNTRIES/AREAS DEPLOYED` fields); for any other source or for
      `report-actor` it is a safe no-op. Run it after `batch` (it reads
      `batch.json`) and before the extraction task below, since it merges
      its output into `extractions.json` and the extraction task should add
      to that, not overwrite it:

      ```
      bin/octi-rb structured
      ```

   b. **Extract with Claude** — this is the one step that isn't a CLI
      command. Read the run directory's `batch.json` against its
      `CONTRACT.md`, and write (merging with anything `structured` already
      put in `extractions.json`, not overwriting it) `extractions.json` in
      the same run directory. Follow the judgement rules below, which are
      the same rules `CONTRACT.md` states for this linker.

5. **Validate**, splitting `extractions.json` into `auto.json` (writes
   automatically) and `review.json` (needs a human look):

   ```
   bin/octi-rb validate
   ```

6. **Dry-run, read the output, then apply:**

   ```
   bin/octi-rb apply --dry-run
   ```

   Read what it says it would write. Then:

   ```
   bin/octi-rb apply
   ```

   Add `--include-review` to also apply non-`hard_fail` review items once
   you've read their evidence (see `octi-review` for how to work the review
   queue first). `report-actor` alone also accepts `--create-missing`, to
   mint a missing Intrusion-Set/Threat-Actor-Group at `confidence: high`.

## Judgement rules (embedded from each linker's contract)

These are the exact rules `CONTRACT.md` states for each linker — apply them
when doing the extraction task in step 4b.

### Shared, every linker

> - evidence must be a real quote from the packet text, not a paraphrase.
> - confidence "high" only when the text states it plainly. Anything
>   inferred, hedged ("suspected", "likely"), or ambiguous is "medium" or
>   "low" -- those go to a review queue instead of being written.
> - A report with nothing genuine to report gets no entries at all. Empty
>   is the right answer more often than not.

Only `confidence: high` extractions auto-apply, so reserve `high` for what
the text states plainly — never for something you inferred to be probably
true.

### report-location

- **`iso3` must be an ISO 3166-1 alpha-3 code, never a country name.** The
  platform stores ISO official names (North Korea is "Democratic People's
  Republic of Korea"), so codes are the only reliable key.
- `role`: `"origin"` = the country the actor operates from or is attributed
  to; `"target"` = a country that was attacked or whose organisations were
  victims; `"mentioned"` = named but neither.
- **Traps** — all of these are noise, not a country:
  - currency names — "1.7 billion Japanese yen"
  - an author byline — "Written by: Jordan Jones" is a person
  - a cloud region in an indicator — "australiaeast", "europe-west3"
  - flag emoji internals (invisible Unicode tag characters, common in
    phishing research)
  - **the reporting agency itself** — CISA, NCSC, the FBI co-authoring an
    advisory is not a victim or an origin; don't invert its role into
    "target" or "origin" just because its country is named
  - **a naming-table** — a taxonomy mapping countries to actor naming
    schemes (PRC→CASTLE, Iran→ION) is a naming scheme, not geography
  - company nationality, standards bodies, sanctions/legal citations

### report-sector

- **Tag the narrowest sector that fits.** OpenCTI propagates a report's
  identity up the part-of chain, so a child sector yields its parents
  automatically.
- Only the exact strings in the closed vocabulary printed in `CONTRACT.md`
  are accepted; a sector not in that list gets no entry.
- `role`: `"target"` = organisations in that sector were attacked,
  compromised, or named as intended victims; `"mentioned"` = named but not
  the subject.
- An IT vendor being compromised is not a manufacturing sector. A retailer
  being phished is retail only if retail organisations were the actual
  targets. Generic enterprise-security or product-marketing content gets no
  entry.
- **Software-vocabulary traps**: "pipeline" almost always means CI/CD, not
  oil or gas; "utility"/"utilities" usually means a software utility;
  "plant", "grid" and "plugin" collide similarly.
- A sentence describing who typically *buys* a product ("used by banks,
  retail corporations, and healthcare providers") is product context, not a
  statement about who was attacked.

### report-actor

- **One entry per adversary, not per name.** "UNC3753 (also tracked as
  'Luna Moth' and 'Silent Ransom Group')" is ONE entry with `actor:
  "UNC3753"` and both other names in `aliases` — not three entries.
- **Put every name you are given in `aliases`, including older and
  vendor-alternate ones** — they are what resolve. An actor named only by
  an old codename resolves only because the article also gives its current
  one (or vice versa) in the alias chain.
- `role`: `"attributed"` = the report is about this actor's activity;
  `"mentioned"` = a passing reference or comparison.
- **Do not emit an actor for**: a naming table (a "cyber threat actor
  naming system" write-up is a taxonomy and yields nothing); the vendor
  doing the reporting (Mandiant, GTIG, Kaspersky GERT, CISA are not
  actors); malware/tool names; extortion brands run by one crew (these are
  aliases of the crew, not separate adversaries); short ambiguous aliases
  ("play", "tick", "zinc", "3am", "rtm") unless the article uses them as a
  proper actor name.

### report-vuln

No extraction task — `batch` extracts every `CVE-YYYY-NNNN[NNN]` it finds
via regex, deduped, `confidence: high`, `role: "mentioned"`, with up to 60
characters of surrounding text on each side as evidence. It never guesses at
an unresolved CVE ID: with NVD feeds present on most platforms, an
unrecognized ID is more likely wrong than new, so it goes to review at
`validate` instead of being invented.
