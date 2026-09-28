import pytest

from octirb.linkers import REGISTRY, get


def test_registry_names():
    assert set(REGISTRY) >= {"report-location", "report-sector", "report-actor", "report-vuln"}


def test_get_unknown_exits():
    with pytest.raises(SystemExit, match="report-location"):
        get("nope")


def test_get_none_exits():
    with pytest.raises(SystemExit):
        get(None)


def test_vuln_needs_no_model():
    assert REGISTRY["report-vuln"].needs_model is False
    assert REGISTRY["report-vuln"].contract is None


def test_contracts_render():
    class R:
        def names(self):
            return ["Energy", "Health"]

        def __len__(self):
            return 2

    from octirb.linkers.contracts import actor_contract, location_contract, sector_contract

    assert "ISO 3166-1 alpha-3" in location_contract(R())
    text = sector_contract(R())
    assert "- Energy" in text and "NARROWEST" in text
    assert "ONE ENTRY PER ADVERSARY" in actor_contract(R())
