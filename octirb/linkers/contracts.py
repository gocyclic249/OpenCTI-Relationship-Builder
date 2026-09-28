"""Extraction contracts handed to the model, one per linker.

`location_contract` and `actor_contract` are ported verbatim from
`opencti-docker/octigeo/dimensions.py`'s `_location_contract`/`_actor_contract`
(same trap lists). `sector_contract` is rewritten generic: octi-rb's sector
vocabulary is author-scoped per deployment rather than a single hardcoded ICS
tree, so the contract text no longer assumes ICS specifically.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import Resolver

SHARED_RULES = """\
Rules:
  - evidence must be a real quote from the packet text, not a paraphrase.
  - confidence "high" only when the text states it plainly. Anything inferred,
    hedged ("suspected", "likely"), or ambiguous is "medium" or "low" --
    those go to a review queue instead of being written.
  - A report with nothing genuine to report gets no entries at all. Empty is
    the right answer more often than not.
"""


def location_contract(resolver: Resolver) -> str:
    if not hasattr(resolver, "__len__"):
        raise TypeError("location_contract: resolver must support len()")
    count = len(resolver)
    if count < 0:
        raise ValueError("location_contract: resolver length must be non-negative")
    return f"""\
For each report below, list the countries the ARTICLE ITSELF is about.

Return a JSON array. One object per (report, country) pair:

  {{
    "report_id": "<copied verbatim from the packet>",
    "title":     "<report title, for the audit trail>",
    "iso3":      "<ISO 3166-1 alpha-3, e.g. PRK, RUS, USA>",
    "role":      "origin" | "target" | "mentioned",
    "confidence":"high" | "medium" | "low",
    "evidence":  "<short verbatim quote from the text that justifies this>"
  }}

  - iso3 must be an ISO 3166-1 alpha-3 code, never a country name. The platform
    stores ISO official names (North Korea is "Democratic People's Republic of
    Korea"), so codes are the only reliable key. {len(resolver)} countries resolve.
  - role: "origin" = the country the actor operates from or is attributed to;
    "target" = a country that was attacked or whose organisations were victims;
    "mentioned" = named but neither, e.g. a vendor HQ or a research institute.
  - Do NOT emit a country for incidental mentions. All of these appeared in
    this corpus and all are noise:
      * currency names -- "1.7 billion Japanese yen"
      * an author byline -- "Written by: Jordan Jones" is a person
      * a cloud region in an indicator -- "australiaeast", "europe-west3"
      * flag emoji internals -- the England/Scotland/Wales flags are encoded
        as invisible Unicode tag characters and show up in phishing research
      * the agency doing the reporting -- CISA, NCSC, the FBI co-authoring an
        advisory is not a victim or an origin
      * a taxonomy table -- mapping countries to actor naming schemes
        (PRC->CASTLE, Iran->ION) is a naming scheme, not geography
      * company nationality, standards bodies, sanctions/legal citations

{SHARED_RULES}"""


def sector_contract(resolver: Resolver) -> str:
    if not hasattr(resolver, "__len__"):
        raise TypeError("sector_contract: resolver must support len()")
    names_fn = getattr(resolver, "names", None)
    if names_fn is not None and not callable(names_fn):
        raise TypeError("sector_contract: resolver.names must be callable")
    vocab = "\n".join(f"    - {n}" for n in getattr(resolver, "names", lambda: [])())
    return f"""\
For each report below, list the industry sectors the ARTICLE ITSELF concerns.

Return a JSON array. One object per (report, sector) pair:

  {{
    "report_id": "<copied verbatim from the packet>",
    "title":     "<report title, for the audit trail>",
    "sector":    "<one of the exact names below>",
    "role":      "target" | "mentioned",
    "confidence":"high" | "medium" | "low",
    "evidence":  "<short verbatim quote from the text that justifies this>"
  }}

Closed vocabulary -- these exact strings are the only accepted values:
{vocab}

  - TAG THE NARROWEST SECTOR THAT FITS. OpenCTI propagates a report's identity
    up the part-of chain, so a child sector yields its parents automatically.
  - role: "target" = organisations in that sector were attacked, compromised,
    or named as the intended victims; "mentioned" = the sector appears but was
    not the subject.
  - A sector NOT in the vocabulary gets no entry -- return nothing for that
    report rather than forcing the nearest match.
  - An IT vendor being compromised is not a manufacturing sector. A retailer
    being phished is a retail sector only if retail organisations were the
    actual targets.
  - Generic enterprise-security or product-marketing content gets no entry.
  - Beware software vocabulary that collides with industrial terms:
      * "pipeline" almost always means CI/CD, not oil or gas
      * "utility"/"utilities" usually means a software utility
      * "plant", "grid" and "plugin" collide similarly
  - A sentence describing who typically BUYS a product ("used by banks,
    retail corporations, and healthcare providers") is product context,
    not a statement about who was attacked.

{SHARED_RULES}"""


def actor_contract(resolver: Resolver) -> str:
    if not hasattr(resolver, "__len__"):
        raise TypeError("actor_contract: resolver must support len()")
    count = len(resolver)
    if count < 0:
        raise ValueError("actor_contract: resolver length must be non-negative")
    return f"""\
For each report below, list the threat actors the ARTICLE ITSELF is about.

Return a JSON array. One object per (report, ADVERSARY) pair -- not per name:

  {{
    "report_id": "<copied verbatim from the packet>",
    "title":     "<report title, for the audit trail>",
    "actor":     "<the name the article leads with>",
    "aliases":   ["<every OTHER name the article gives this same adversary>"],
    "role":      "attributed" | "mentioned",
    "confidence":"high" | "medium" | "low",
    "evidence":  "<short verbatim quote from the text that justifies this>"
  }}

  - ONE ENTRY PER ADVERSARY. If the article says "UNC3753 (also tracked as
    'Luna Moth' and 'Silent Ransom Group')", that is ONE entry with actor
    "UNC3753" and both other names in aliases -- not three entries.
  - PUT EVERY NAME YOU ARE GIVEN IN aliases, including older and
    vendor-alternate ones. They are what resolve: {len(resolver)} actors are
    on the platform, and "UNC6293" resolves only because the article also
    says "formerly APT29".
  - role: "attributed" = the report is about this actor's activity;
    "mentioned" = a passing reference or comparison.
  - Do NOT emit an actor for any of these. All appeared in this corpus:
      * a naming TABLE -- the "Updated Cyber Threat Actor Naming System"
        write-up is a taxonomy of cryptonyms and yields nothing at all
      * the vendor doing the reporting -- Mandiant, GTIG, Kaspersky GERT
        and CISA are not actors
      * malware and tool names -- XWORM, VIDAR, COBALTSPIN, BeaverTail
      * extortion BRANDS run by one crew -- Redact, Pink, Helix and Falcon
        are aliases of UNC6671, not four adversaries
      * the short ambiguous aliases "play", "tick", "zinc", "3am" and "rtm"
        unless the article uses them as a proper actor name

{SHARED_RULES}"""
