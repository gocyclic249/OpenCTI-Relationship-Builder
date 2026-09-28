"""Coverage for Client's branching logic: actor create/delete, vulnerability
lookup, and alias mutations.

Most of Client is thin I/O wrapping (gql() stubbed here via the
`fake_gql_client` fixture -- no network, no real Settings needed beyond the
fixture's placeholder ones), which is why the module has few other unit
tests: there is no branching to exercise in a query built once and sent
as-is. The methods below have guards worth a regression test, most notably
the raw-id-before-str check carried over from octigeo's
create_threat_actor_group: str(None) == "None" is truthy, so checking
result.get("id") before str()-ing it is what stops a null id from a failed
mutation sailing into a run ledger as if it were a real entity.

Ported from opencti-docker/tests/test_client.py, which covered exactly one
method: create_threat_actor_group (empty-name guard, null-id guard, and
that name/aliases/label were sent correctly). That method -- and its
delete_threat_actor_group counterpart -- no longer exist on this merged
Client: octi-rb's design generalizes actor creation/deletion to dispatch on
entity_type (Threat-Actor-Group or Intrusion-Set) via create_actor/
delete_actor. The four original tests are kept here in spirit, rewritten
against create_actor, since the regressions they guard against (a null id
reaching the ledger, an empty name slipping through, aliases/label not
being sent) apply identically to the generalized method. Nothing from the
original file tested octigeo's non-paginated intrusion_sets/
threat_actor_groups, so there was nothing to delete on that account.
"""

from __future__ import annotations

import http.client
import io
import urllib.error
import urllib.request
from email.message import Message

import pytest

from octirb.client import ACTOR_MUTATIONS, OpenCTIError

# -- create_actor / delete_actor ---------------------------------------------


def test_create_actor_threat_actor_group_returns_the_id(fake_gql_client):
    client, _calls = fake_gql_client(
        {"threatActorGroupAdd": {"id": "abc-123", "name": "WaterPlum"}}
    )
    assert client.create_actor("Threat-Actor-Group", "WaterPlum", ["Water Plum"], "lbl") == "abc-123"


def test_create_actor_sends_stripped_name_aliases_and_label(fake_gql_client):
    client, calls = fake_gql_client({"threatActorGroupAdd": {"id": "abc-123", "name": "WaterPlum"}})
    client.create_actor("Threat-Actor-Group", "  WaterPlum  ", ["Water Plum", "", "  "], "lbl-1")
    _query, variables = calls[0]
    sent = variables["input"]
    assert sent["name"] == "WaterPlum"  # stripped
    assert sent["aliases"] == ["Water Plum"]  # blanks dropped
    assert sent["objectLabel"] == ["lbl-1"]


def test_create_actor_refuses_an_empty_name(fake_gql_client):
    client, calls = fake_gql_client({"threatActorGroupAdd": {"id": "abc-123"}})
    for blank in ("", "   "):
        with pytest.raises(OpenCTIError):
            client.create_actor("Threat-Actor-Group", blank, [], "lbl")
    assert calls == []  # refusal never touched the network


def test_create_actor_rejects_a_null_or_missing_id(fake_gql_client):
    """str(None) is "None" -- truthy -- so a post-str() guard would pass it.

    Regression test: a fake id reaching the run ledger would make a later
    revert try to delete an actor that was never actually created.
    """
    for bad_response in (
        {"threatActorGroupAdd": {"id": None}},
        {"threatActorGroupAdd": {}},
        {"threatActorGroupAdd": None},
    ):
        client, _calls = fake_gql_client(bad_response)
        with pytest.raises(OpenCTIError):
            client.create_actor("Threat-Actor-Group", "WaterPlum", [], "lbl")


def test_create_actor_intrusion_set(fake_gql_client):
    client, calls = fake_gql_client({"intrusionSetAdd": {"id": "is1", "name": "X"}})
    assert client.create_actor("Intrusion-Set", "X", ["Y"], "lab1") == "is1"
    query, _variables = calls[0]
    assert "intrusionSetAdd" in query


def test_create_actor_unknown_type(fake_gql_client):
    client, calls = fake_gql_client({})
    with pytest.raises(OpenCTIError, match="Malware"):
        client.create_actor("Malware", "X", [], "lab1")
    assert calls == []


def test_create_actor_null_id_raises(fake_gql_client):
    client, _calls = fake_gql_client({"intrusionSetAdd": {"id": None}})
    with pytest.raises(OpenCTIError):
        client.create_actor("Intrusion-Set", "X", [], "lab1")


def test_actor_mutations_table_has_exactly_the_two_supported_types():
    assert set(ACTOR_MUTATIONS) == {"Threat-Actor-Group", "Intrusion-Set"}


def test_delete_actor_unknown_type(fake_gql_client):
    client, calls = fake_gql_client({})
    with pytest.raises(OpenCTIError, match="Malware"):
        client.delete_actor("Malware", "e1")
    assert calls == []


def test_delete_actor_dispatches_to_intrusion_set(fake_gql_client):
    client, calls = fake_gql_client({"intrusionSetEdit": {"delete": True}})
    client.delete_actor("Intrusion-Set", "is1")
    query, variables = calls[0]
    assert "intrusionSetEdit" in query
    assert variables == {"id": "is1"}


def test_delete_actor_needs_an_id(fake_gql_client):
    client, calls = fake_gql_client({})
    with pytest.raises(ValueError):
        client.delete_actor("Intrusion-Set", "")
    assert calls == []


# -- vulnerabilities_by_name --------------------------------------------------


def test_vulnerabilities_by_name_maps_upper(fake_gql_client):
    client, calls = fake_gql_client(
        {"vulnerabilities": {"edges": [{"node": {"id": "v1", "name": "CVE-2026-1111"}}]}}
    )
    out = client.vulnerabilities_by_name(["CVE-2026-1111", "CVE-2026-9999"])
    assert out == {"CVE-2026-1111": {"id": "v1", "name": "CVE-2026-1111"}}
    _query, variables = calls[0]
    assert variables == {"names": ["CVE-2026-1111", "CVE-2026-9999"]}


def test_vulnerabilities_by_name_empty_input_is_error(fake_gql_client):
    client, calls = fake_gql_client({})
    with pytest.raises((OpenCTIError, ValueError)):
        client.vulnerabilities_by_name([])
    assert calls == []


def test_vulnerabilities_by_name_refuses_over_500(fake_gql_client):
    client, calls = fake_gql_client({})
    with pytest.raises(OpenCTIError):
        client.vulnerabilities_by_name([f"CVE-{i}" for i in range(501)])
    assert calls == []


# -- entity aliases ------------------------------------------------------------


def test_add_entity_alias_needs_both(fake_gql_client):
    client, calls = fake_gql_client({})
    with pytest.raises(ValueError):
        client.add_entity_alias("", "APT1")
    assert calls == []


def test_add_entity_alias_sends_add_operation(fake_gql_client):
    client, calls = fake_gql_client({"stixDomainObjectEdit": {"fieldPatch": {"id": "e1"}}})
    client.add_entity_alias("e1", "  APT1  ")
    _query, variables = calls[0]
    assert variables == {"id": "e1", "input": [{"key": "aliases", "value": ["APT1"], "operation": "add"}]}


def test_remove_entity_alias_sends_remove_operation(fake_gql_client):
    client, calls = fake_gql_client({"stixDomainObjectEdit": {"fieldPatch": {"id": "e1"}}})
    client.remove_entity_alias("e1", "APT1")
    assert calls[0][1]["input"][0]["operation"] == "remove"


def test_alias_patch_raises_when_platform_returns_nothing(fake_gql_client):
    client, _calls = fake_gql_client({"stixDomainObjectEdit": None})
    with pytest.raises(OpenCTIError):
        client.add_entity_alias("e1", "APT1")


def test_entity_aliases_reads_intrusion_set_or_tag(fake_gql_client):
    client, _calls = fake_gql_client({"stixCoreObject": {"aliases": ["A", "B"]}})
    assert client.entity_aliases("e1") == ["A", "B"]


def test_entity_aliases_missing_entity_returns_empty(fake_gql_client):
    client, _calls = fake_gql_client({"stixCoreObject": None})
    assert client.entity_aliases("e1") == []


def test_entity_aliases_needs_an_id(fake_gql_client):
    client, calls = fake_gql_client({})
    with pytest.raises(ValueError):
        client.entity_aliases("")
    assert calls == []


# -- report_object_ids (C2: containment pre-existence read) --------------------


def test_report_object_ids_collects_every_page(fake_gql_client):
    client, _calls = fake_gql_client({})
    pages = iter([
        {"report": {"objects": {"pageInfo": {"endCursor": "c1", "hasNextPage": True},
                                "edges": [{"node": {"id": "a"}}, {"node": {}}]}}},
        {"report": {"objects": {"pageInfo": {"endCursor": None, "hasNextPage": False},
                                "edges": [{"node": {"id": "b"}}, {"node": None}]}}},
    ])
    sent: list[object] = []

    def paged(_query, variables=None):
        sent.append(variables)
        return next(pages)

    client.gql = paged
    assert client.report_object_ids("r1") == {"a", "b"}
    assert sent == [{"id": "r1", "after": None}, {"id": "r1", "after": "c1"}]


def test_report_object_ids_missing_report_raises(fake_gql_client):
    client, _calls = fake_gql_client({"report": None})
    with pytest.raises(OpenCTIError):
        client.report_object_ids("r1")


# -- transport error wrapping (I2) --------------------------------------------


def _client():
    from octirb.client import Client
    from octirb.config import Settings

    return Client(Settings(url="http://x", token="t"))  # noqa: S106 - placeholder, not a secret


class _Body(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


@pytest.mark.parametrize(
    "exc",
    [TimeoutError("timed out"), ConnectionResetError("reset"), http.client.RemoteDisconnected("gone"),
     http.client.IncompleteRead(b"")],
)
def test_gql_wraps_transport_errors(monkeypatch, exc):
    def boom(*_a, **_k):
        raise exc

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with pytest.raises(OpenCTIError):
        _client().gql("{ x }")


def test_gql_wraps_a_non_json_body(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", lambda *_a, **_k: _Body(b"<html>502</html>"))
    with pytest.raises(OpenCTIError):
        _client().gql("{ x }")


def test_gql_rejects_a_non_object_payload(monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen", lambda *_a, **_k: _Body(b"[1, 2]"))
    with pytest.raises(OpenCTIError):
        _client().gql("{ x }")


@pytest.mark.parametrize(
    "exc",
    [urllib.error.HTTPError("http://x/storage/get/f1", 404, "Not Found", Message(), None),
     TimeoutError("timed out"), http.client.IncompleteRead(b"")],
)
def test_download_wraps_transport_errors(monkeypatch, exc):
    def boom(*_a, **_k):
        raise exc

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with pytest.raises(OpenCTIError):
        _client().download("f1")
