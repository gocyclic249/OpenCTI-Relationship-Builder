"""Deterministic extraction from publishers that already publish structured fields.

Most sources bury geography and sector in prose, which is why octi-geo hands
text to a model. CISA does not: every ICS advisory carries a fixed block

    CRITICAL INFRASTRUCTURE SECTORS: Critical Manufacturing, Energy, Water and
                                     Wastewater Systems
    COUNTRIES/AREAS DEPLOYED:        Worldwide
    COMPANY HEADQUARTERS LOCATION:   France

Parsing that is exact, needs no judgement, and is far more reliable than
reading the prose around it -- so it should not go through the model at all.
Everything here therefore emits `confidence: high`: the publisher is asserting
the field, we are only transcribing it.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from .client import JsonDict

# CISA classifies against the 16 US critical-infrastructure sectors. Only these
# four have an equivalent inside the ICS tree; the rest (Healthcare, Government
# Facilities, Information Technology, Transportation Systems, Chemical, Dams,
# Commercial Facilities, ...) are deliberately dropped rather than forced into
# a near-match, because a wrong sector is worse than a missing one.
CISA_SECTOR_MAP = {
    "critical manufacturing": "Heavy industries",
    "energy": "Energy",
    "water and wastewater": "Water distribution and supply",
    "nuclear reactors": "Nuclear power (civilian use)",
}

# Values that name no single country and must not become a Location.
NON_COUNTRIES = frozenset({"worldwide", "global", "globally", "unknown", ""})

_FIELD_TAIL = r"\s*\*{0,2}\s*:?\s*\*{0,2}\s*(.{0,220})"
SECTORS_RE = re.compile(r"CRITICAL INFRASTRUCTURE SECTORS?" + _FIELD_TAIL, re.IGNORECASE)
DEPLOYED_RE = re.compile(r"COUNTRIES/AREAS DEPLOYED" + _FIELD_TAIL, re.IGNORECASE)

# Everything after one of these starts the next field, so the value stops there.
_STOP = ("COUNTRIES", "COMPANY", "CRITICAL INFRASTRUCTURE", "**")


def _field_value(pattern: re.Pattern[str], text: str) -> str:
    """The value of one CISA advisory field, or '' when absent."""
    match = pattern.search(text)
    if match is None:
        return ""
    value = re.sub(r"\s+", " ", match.group(1))
    for stop in _STOP:
        value = value.split(stop)[0]
    # CISA renders these fields with non-breaking spaces, so strip those too.
    return value.strip(" .*\u00a0")


def _cisa_sectors(packet: JsonDict) -> list[JsonDict]:
    raw = _field_value(SECTORS_RE, str(packet["text"]))
    if not raw:
        return []
    # Split on commas ONLY. "Water and Wastewater Systems" is a single sector,
    # and splitting on "and" silently lost it from three advisories.
    mapped: list[str] = []
    for part in (p.strip().lower() for p in raw.split(",")):
        hit = next((v for k, v in CISA_SECTOR_MAP.items() if k in part), None)
        if hit and hit not in mapped:
            mapped.append(hit)
    return [
        {
            "report_id": packet["report_id"],
            "title": packet["title"],
            "sector": sector,
            "role": "target",
            "confidence": "high",
            "evidence": f"CRITICAL INFRASTRUCTURE SECTORS: {raw[:150]}",
        }
        for sector in mapped
    ]


def _cisa_locations(packet: JsonDict) -> list[JsonDict]:
    """Deployment countries only.

    COMPANY HEADQUARTERS LOCATION is deliberately ignored: a vendor being
    French says nothing about who was attacked, and the extraction contract
    already classes company nationality as noise.
    """
    raw = _field_value(DEPLOYED_RE, str(packet["text"]))
    if not raw or raw.lower() in NON_COUNTRIES:
        return []
    return [
        {
            "report_id": packet["report_id"],
            "title": packet["title"],
            "iso3": name.strip(),
            "role": "target",
            "confidence": "medium",
            "evidence": f"COUNTRIES/AREAS DEPLOYED: {raw[:150]}",
        }
        for name in raw.split(",")
        if name.strip() and name.strip().lower() not in NON_COUNTRIES
    ]


# source name -> dimension -> parser
PARSERS: dict[str, dict[str, Callable[[JsonDict], list[JsonDict]]]] = {
    "CISA": {"report-sector": _cisa_sectors, "report-location": _cisa_locations},
}


def parse(batch: list[JsonDict], dimension: str) -> tuple[list[JsonDict], int]:
    """Extractions derivable from structured fields, plus the packets covered."""
    if not dimension:
        raise ValueError("dimension is required")
    out: list[JsonDict] = []
    covered = 0
    for packet in batch:
        parser = PARSERS.get(str(packet.get("source", "")), {}).get(dimension)
        if parser is None:
            continue
        found = parser(packet)
        if found:
            covered += 1
            out.extend(found)
    return out, covered
