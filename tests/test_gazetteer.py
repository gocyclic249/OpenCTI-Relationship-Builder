"""Gazetteer: every three-letter alias resolves, not just the first.

The platform's Taiwan carries ['TWA', 'TW', 'TWN'] (live, 2026-09-23). Taking
only the first three-letter alias indexed it as TWA, so the ISO code TWN never
resolved -- in octi-geo location runs and in octi-rel alike.
"""

from octirb.resolvers.gazetteer import Gazetteer


class Stub:
    def countries(self):
        return [
            {"id": "c-tw", "standard_id": "location--tw", "name": "Taiwan",
             "x_opencti_aliases": ["TWA", "TW", "TWN"]},
            {"id": "c-us", "standard_id": "location--us", "name": "United States of America",
             "x_opencti_aliases": ["USA", "US"]},
        ]


def test_every_three_letter_alias_resolves():
    gaz = Gazetteer.load(Stub())
    assert gaz.resolve("TWN").id == "c-tw"
    assert gaz.resolve("TWA").id == "c-tw"
    assert gaz.resolve("TW").id == "c-tw"


def test_country_count_is_unchanged_by_extra_codes():
    assert len(Gazetteer.load(Stub())) == len(Stub().countries())
