import pytest

from octirb.config import SectorsCfg
from octirb.resolvers.sectors import Sector, SectorVocabulary


def node(nid, name, author, subs=(), parents=(), aliases=()):
    return {"id": nid, "name": name, "x_opencti_aliases": list(aliases),
            "createdBy": {"name": author} if author else None,
            "subSectors": {"edges": [{"node": {"id": s}} for s in subs]},
            "parentSectors": {"edges": [{"node": {"name": p}} for p in parents]}}


class FakeClient:
    def __init__(self, nodes):
        self._nodes = nodes

    def gql(self, query, variables=None):
        return {"sectors": {"edges": [{"node": n} for n in self._nodes]}}


FILIGRAN = [
    node("s1", "Energy", "Filigran", aliases=["Natural Resources"]),
    node("s2", "Electricity", "Filigran", parents=["Energy"]),
    node("s3", "Electric", "CIRCL"),
]


def test_canonical_scoped_to_authors():
    vocab = SectorVocabulary.load(FakeClient(FILIGRAN), SectorsCfg())
    assert vocab.resolve("Energy") is not None
    assert vocab.resolve("Electric") is None          # CIRCL near-duplicate excluded


def test_platform_alias_resolves():
    vocab = SectorVocabulary.load(FakeClient(FILIGRAN), SectorsCfg())
    assert vocab.resolve("Natural Resources").name == "Energy"


def test_config_alias_maps_duplicate():
    cfg = SectorsCfg(aliases={"Energy & Utilities": "Energy"})
    vocab = SectorVocabulary.load(FakeClient(FILIGRAN), cfg)
    assert vocab.resolve("Energy & Utilities").name == "Energy"


def test_extra_root_subtree_included():
    nodes = FILIGRAN + [
        node("i1", "ICS", "me", subs=["i2"]),
        node("i2", "Water distribution and supply", "me", parents=["ICS"]),
    ]
    cfg = SectorsCfg(extra_roots=("ICS",))
    vocab = SectorVocabulary.load(FakeClient(nodes), cfg)
    assert vocab.resolve("ICS") is not None
    assert vocab.resolve("wastewater").name == "Water distribution and supply"
    assert vocab.resolve("scada").name == "ICS"       # generic OT terms → root, only with ICS root


def test_scada_unresolved_without_ics_root():
    vocab = SectorVocabulary.load(FakeClient(FILIGRAN), SectorsCfg())
    assert vocab.resolve("scada") is None


def test_empty_canonical_vocabulary_exits():
    with pytest.raises(SystemExit, match="Filigran"):
        SectorVocabulary.load(FakeClient([node("x", "Foo", "SomeoneElse")]), SectorsCfg())


def test_missing_extra_root_exits():
    with pytest.raises(SystemExit, match="ICS"):
        SectorVocabulary.load(FakeClient(FILIGRAN), SectorsCfg(extra_roots=("ICS",)))
