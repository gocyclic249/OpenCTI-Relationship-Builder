"""Resolve extracted country codes to the Location entities already on-platform.

The platform stores ISO 3166 official names -- North Korea is
"Democratic People's Republic of Korea", Russia is "Russian Federation".
Matching on colloquial names is therefore a dead end, so the extraction
contract is an ISO 3166-1 alpha-3 code and this resolves it exactly against the
250 seeded Country entities (all of which carry unique ISO2/ISO3 aliases).

octi-geo never creates Location entities. A code that does not resolve is a
review item, not a new country.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..client import Client

ISO3_LEN = 3
ISO2_LEN = 2

# The platform stores ISO 3166 official names, so a colloquial name from a
# structured source ("United States", "Russia", "South Korea") matches nothing.
# Claude-authored extractions dodge this by emitting ISO codes, but publishers
# that expose their own fields do not. Only names whose common form differs
# from the official one belong here; everything else already matches exactly.
COMMON_NAMES = {
    "united states": "USA",
    "united states of america": "USA",
    "usa": "USA",
    "u.s.": "USA",
    "us": "USA",
    "united kingdom": "GBR",
    "uk": "GBR",
    "u.k.": "GBR",
    "great britain": "GBR",
    "britain": "GBR",
    "russia": "RUS",
    "south korea": "KOR",
    "republic of korea": "KOR",
    "north korea": "PRK",
    "dprk": "PRK",
    "iran": "IRN",
    "syria": "SYR",
    "vietnam": "VNM",
    "viet nam": "VNM",
    "laos": "LAO",
    "brunei": "BRN",
    "czech republic": "CZE",
    "bolivia": "BOL",
    "venezuela": "VEN",
    "tanzania": "TZA",
    "moldova": "MDA",
    "ivory coast": "CIV",
    "cote d'ivoire": "CIV",
    "palestine": "PSE",
    "vatican": "VAT",
    "vatican city": "VAT",
    "cape verde": "CPV",
    "east timor": "TLS",
    "swaziland": "SWZ",
    "macau": "MAC",
    "hong kong": "HKG",
}


@dataclass(frozen=True)
class Country:
    id: str
    standard_id: str
    name: str
    iso3: str
    iso2: str
    # Further three-letter aliases beyond the first. Taiwan carries
    # ['TWA', 'TW', 'TWN'], so the ISO code is not always the first one.
    alt_iso3: tuple[str, ...] = ()


class Gazetteer:
    def __init__(self, countries: list[Country]):
        self._by_iso3: dict[str, Country] = {}
        self._by_iso2: dict[str, Country] = {}
        self._by_name: dict[str, Country] = {}
        self._by_alt3: dict[str, Country] = {}
        for c in countries:
            if c.iso3:
                self._by_iso3[c.iso3.upper()] = c
            for code in c.alt_iso3:
                self._by_alt3[code.upper()] = c
            if c.iso2:
                self._by_iso2[c.iso2.upper()] = c
            self._by_name[c.name.casefold()] = c

    def __len__(self) -> int:
        return len(self._by_iso3)

    @classmethod
    def load(cls, client: Client) -> Gazetteer:
        countries = []
        for node in client.countries():
            aliases = node.get("x_opencti_aliases") or []
            codes3 = [a for a in aliases if len(a) == ISO3_LEN and a.isalpha() and a.isupper()]
            iso3 = codes3[0] if codes3 else ""
            iso2 = next(
                (a for a in aliases if len(a) == ISO2_LEN and a.isalpha() and a.isupper()), ""
            )
            countries.append(
                Country(
                    id=node["id"],
                    standard_id=node["standard_id"],
                    name=node["name"],
                    iso3=iso3,
                    iso2=iso2,
                    alt_iso3=tuple(codes3[1:]),
                )
            )
        return cls(countries)

    def resolve(self, code: str) -> Country | None:
        """Resolve an ISO3 code (preferred), ISO2 code, or exact platform name."""
        if not code:
            return None
        key = code.strip()
        common = COMMON_NAMES.get(key.casefold(), "")
        return (
            self._by_iso3.get(key.upper())
            or self._by_alt3.get(key.upper())
            or self._by_iso2.get(key.upper())
            or self._by_name.get(key.casefold())
            or (self._by_iso3.get(common) if common else None)
        )

    def probes(self) -> list[str]:
        """Codes `doctor` resolves as a smoke test."""
        return ["PRK", "RUS", "USA"]
