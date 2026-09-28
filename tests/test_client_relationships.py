"""Relationship-side Client methods: stubbed gql(), no network.

Ported from opencti-docker/tests/test_rel_client.py, which covered the
branching calls on octirel.relclient.RelClient. That class no longer
exists as a subclass -- its methods (actors, regions, relation_schema,
find_relationships, relationship_state, create_relationship,
delete_relationship, report_actors) were folded into octirb.client.Client
directly (see Task 3). Every behavioral assertion in the source file still
applies unchanged to the merged Client, so the whole file is kept, with
only the import path and the Stub base class updated. Nothing in it
referenced REL_LABEL/REL_LABEL_COLOR (dropped -- labels are config-driven
now) or a removed method, so nothing needed to be dropped.
"""

from __future__ import annotations

from typing import Any

import pytest

from octirb.client import Client, OpenCTIError

JsonDict = dict[str, Any]


class Stub(Client):
    """Client with gql() stubbed to pop canned responses -- no network."""

    def __init__(self, responses: list[JsonDict | None]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, JsonDict | None]] = []

    def gql(self, query: str, variables: JsonDict | None = None) -> JsonDict:
        self.calls.append((query, variables))
        return self._responses.pop(0)  # type: ignore[return-value]


def test_create_relationship_returns_id_and_sends_fields() -> None:
    c = Stub([{"stixCoreRelationshipAdd": {"id": "rel-1"}}])
    rid = c.create_relationship("a", "b", "targets", 85, '"q" — octi-rel, source: description', "lbl")
    assert rid == "rel-1"
    sent = c.calls[0][1]["input"]  # type: ignore[index]
    assert sent == {
        "fromId": "a", "toId": "b", "relationship_type": "targets", "confidence": 85,
        "description": '"q" — octi-rel, source: description', "objectLabel": ["lbl"],
    }


def test_create_relationship_null_id_raises() -> None:
    c = Stub([{"stixCoreRelationshipAdd": {"id": None}}])
    with pytest.raises(OpenCTIError):
        c.create_relationship("a", "b", "targets", 85, "d", "lbl")


def test_create_relationship_rejects_bad_confidence() -> None:
    with pytest.raises(ValueError):
        Stub([]).create_relationship("a", "b", "targets", 101, "d", "lbl")


def test_relationship_state_missing() -> None:
    assert Stub([{"stixCoreRelationship": None}]).relationship_state("x") == (False, [])


def test_relationship_state_labels() -> None:
    c = Stub([{"stixCoreRelationship": {"id": "x", "objectLabel": [{"value": "octi-rel"}]}}])
    assert c.relationship_state("x") == (True, ["octi-rel"])


def test_find_relationships_returns_ids() -> None:
    c = Stub([{"stixCoreRelationships": {"edges": [{"node": {"id": "r1"}}, {"node": {"id": "r2"}}]}}])
    assert c.find_relationships("a", "b", "targets") == ["r1", "r2"]
    assert c.calls[0][1] == {"f": ["a"], "t": ["b"], "r": ["targets"]}


def test_relation_schema_parses() -> None:
    c = Stub([{"schemaRelationsTypesMapping": [
        {"key": "Intrusion-Set_Country", "values": ["originates-from", "targets"]}]}])
    assert c.relation_schema() == {"Intrusion-Set_Country": frozenset({"originates-from", "targets"})}


def test_report_actors_shapes_packet() -> None:
    c = Stub([{"report": {"id": "r1", "name": "T", "published": "2026-09-01T00:00:00Z",
        "objects": {"edges": [{"node": {"id": "a1", "name": "APT29", "entity_type": "Intrusion-Set"}},
                              {"node": {}}]}}}])
    assert c.report_actors("r1") == {
        "report_id": "r1", "title": "T", "published": "2026-09-01T00:00:00Z",
        "actors": [{"actor_id": "a1", "name": "APT29", "entity_type": "Intrusion-Set"}],
    }


def test_report_actors_missing_report() -> None:
    assert Stub([{"report": None}]).report_actors("r1") is None


def test_delete_relationship_success() -> None:
    c = Stub([{"stixCoreRelationshipEdit": {"delete": True}}])
    c.delete_relationship("rel-1")
    assert len(c.calls) == 1


def test_delete_relationship_fails_when_not_deleted() -> None:
    c = Stub([{"stixCoreRelationshipEdit": {"delete": None}}])
    with pytest.raises(OpenCTIError):
        c.delete_relationship("rel-1")


def test_delete_relationship_fails_when_result_null() -> None:
    c = Stub([{"stixCoreRelationshipEdit": None}])
    with pytest.raises(OpenCTIError):
        c.delete_relationship("rel-1")


def test_find_relationships_rejects_empty_id() -> None:
    c = Stub([{"stixCoreRelationships": {"edges": [{"node": {"id": ""}}, {"node": {"id": "r1"}}]}}])
    with pytest.raises(OpenCTIError):
        c.find_relationships("a", "b", "targets")


def test_relationship_state_rejects_wrong_id() -> None:
    c = Stub([{"stixCoreRelationship": {"id": "wrong", "objectLabel": []}}])
    with pytest.raises(OpenCTIError):
        c.relationship_state("x")


def test_report_actors_rejects_wrong_id() -> None:
    c = Stub([{"report": {"id": "wrong", "name": "T", "published": "2026-09-01T00:00:00Z",
        "objects": {"edges": []}}}])
    with pytest.raises(OpenCTIError):
        c.report_actors("r1")


def test_actors_normal_page() -> None:
    c = Stub([
        {"intrusionSets": {"pageInfo": {"hasNextPage": False, "endCursor": None},
            "edges": [{"node": {"id": "i1", "name": "APT1", "aliases": [], "description": "test",
                                 "entity_type": "Intrusion-Set"}}]}},
        {"threatActorsGroup": {"pageInfo": {"hasNextPage": False, "endCursor": None},
            "edges": [{"node": {"id": "t1", "name": "TAG1", "aliases": [], "description": "test",
                                 "entity_type": "Threat-Actor-Group"}}]}},
    ])
    result = c.actors()
    assert len(result) == 2
    assert result[0]["id"] == "i1"
    assert result[1]["id"] == "t1"


def test_actors_rejects_missing_id() -> None:
    c = Stub([
        {"intrusionSets": {"pageInfo": {"hasNextPage": False, "endCursor": None},
            "edges": [{"node": {"id": "", "name": "APT1", "aliases": [], "description": "test",
                                 "entity_type": "Intrusion-Set"}}]}},
        {"threatActorsGroup": {"pageInfo": {"hasNextPage": False, "endCursor": None}, "edges": []}},
    ])
    with pytest.raises(OpenCTIError):
        c.actors()


def test_regions_normal_page() -> None:
    c = Stub([{"regions": {"pageInfo": {"hasNextPage": False, "endCursor": None},
        "edges": [{"node": {"id": "r1", "name": "USA"}}]}}])
    result = c.regions()
    assert len(result) == 1
    assert result[0]["name"] == "USA"


def test_regions_rejects_missing_name() -> None:
    c = Stub([{"regions": {"pageInfo": {"hasNextPage": False, "endCursor": None},
        "edges": [{"node": {"id": "r1", "name": ""}}]}}])
    with pytest.raises(OpenCTIError):
        c.regions()
