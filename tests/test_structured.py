import pytest

from octirb.structured import parse

# -- octigeo has no structured-parser tests (grep -l structured tests/*.py in
# -- opencti-docker/tests/ found nothing); this is a new minimal suite
# -- exercising the two load-bearing CISA behaviours: comma-only sector
# -- splitting and the COMPANY HEADQUARTERS LOCATION exclusion.

CISA_TEXT = (
    "CRITICAL INFRASTRUCTURE SECTORS: Critical Manufacturing, Energy, Water and "
    "Wastewater Systems\n"
    "COUNTRIES/AREAS DEPLOYED: United States, Germany\n"
    "COMPANY HEADQUARTERS LOCATION: France\n"
)


def packet(**over):
    base = {"report_id": "r1", "title": "ICS Advisory", "source": "CISA", "text": CISA_TEXT}
    base.update(over)
    return base


def test_cisa_sectors_split_on_comma_only():
    """"Water and Wastewater Systems" must survive as one sector, not be cut
    apart by an "and"-based split, and each of the three listed sectors must
    map through CISA_SECTOR_MAP."""
    found, covered = parse([packet()], "report-sector")
    assert covered == 1
    sectors = {row["sector"] for row in found}
    assert sectors == {"Heavy industries", "Energy", "Water distribution and supply"}


def test_cisa_locations_ignore_company_headquarters():
    """COUNTRIES/AREAS DEPLOYED becomes Locations; COMPANY HEADQUARTERS
    LOCATION (France) must never leak in -- vendor nationality is not a
    target.

    DEPLOYED and COMPANY share one line here, no intervening newline. The
    field-value regex's capture group (`.{0,220}`, no re.DOTALL) only stops
    at a newline on its own, so a fixture that puts COMPANY on its own line
    never exercises the "COMPANY" entry in structured.py's `_STOP` tuple --
    the newline alone would hide the leak regardless of whether `_STOP`
    catches it. This inline variant fails if "COMPANY" is removed from
    `_STOP` (verified against a local copy of `_field_value` with that entry
    dropped: France leaks into the deployed-countries value)."""
    pkt = packet(
        text="COUNTRIES/AREAS DEPLOYED: United States, Germany "
        "COMPANY HEADQUARTERS LOCATION: France\n"
    )
    found, covered = parse([pkt], "report-location")
    assert covered == 1
    countries = {row["iso3"] for row in found}
    assert countries == {"United States", "Germany"}
    assert "France" not in countries


def test_cisa_locations_worldwide_is_excluded():
    pkt = packet(text="COUNTRIES/AREAS DEPLOYED: Worldwide\n")
    found, covered = parse([pkt], "report-location")
    assert found == []
    assert covered == 0


def test_parse_requires_dimension():
    with pytest.raises(ValueError, match="dimension"):
        parse([packet()], "")


def test_parse_skips_unknown_source():
    found, covered = parse([packet(source="OtherPublisher")], "report-sector")
    assert found == []
    assert covered == 0
