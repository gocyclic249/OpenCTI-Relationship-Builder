"""Merged stdlib-only OpenCTI GraphQL client for octi-rb.

octi-rb has no runtime dependencies, so this is plain urllib rather than
pycti or requests -- see CLAUDE.md, that is a circumstance, not a rule.

This folds together two clients that used to live in separate packages:
- opencti-docker/octigeo/client.py: reports, containers, labels,
  enrichment polling.
- opencti-docker/octirel/relclient.py (there, `RelClient(Client)`): actors,
  regions, relationship schema/CRUD -- folded in here as plain methods on
  one `Client`, per the octi-rb design, rather than a subclass.

Plus new methods octi-rb needs that neither predecessor had: vulnerability
lookup by name, and generalized actor alias/create/delete that dispatch on
entity_type instead of hardcoding Threat-Actor-Group the way octigeo's
create_threat_actor_group did.
"""

from __future__ import annotations

import http.client
import json
import time
import urllib.parse
import urllib.request
from collections.abc import Iterator
from typing import Any, cast

from .config import Settings

JsonDict = dict[str, Any]

# Relay pagination ceiling. At 100 nodes per page this bounds a walk to one
# million nodes -- far above any collection here, but the loop is provably
# finite rather than trusting the server's hasNextPage to eventually go false.
MAX_PAGES = 10_000

# create_relationship()'s confidence bound (OpenCTI's own 0-100 scale).
MAX_CONFIDENCE = 100

# vulnerabilities_by_name() refuses to look up more names than the query's
# own `first: 500` page size can return in one round trip.
MAX_VULN_NAMES = 500

ALLOWED_SCHEMES = frozenset({"http", "https"})

# Every transport failure urlopen/read can raise: URLError/HTTPError, socket
# timeouts and resets are OSError; a truncated or malformed HTTP response is
# http.client.HTTPException (not an OSError). Wrapped as OpenCTIError so
# callers' per-item handling and main()'s exit contract see one type.
TRANSPORT_ERRORS = (OSError, http.client.HTTPException)


class OpenCTIError(RuntimeError):
    pass


def _checked_request(url: str, token: str, data: bytes | None = None) -> urllib.request.Request:
    """Build a request, refusing any scheme other than http/https.

    The platform URL comes from config.toml, so it is configuration rather
    than a literal. Without this check a file:// or ftp:// value would make
    urlopen read local files. Assertion on input per the project coding
    standards.
    """
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise OpenCTIError(f"Refusing non-HTTP OpenCTI URL {url!r} (scheme {scheme!r})")
    headers = {"Authorization": f"Bearer {token}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    return urllib.request.Request(url, data=data, headers=headers)  # noqa: S310 - scheme checked above


# -- relationship-side queries/mutations (ported unchanged from
# octirel/relclient.py, module-level there and kept that way here) ---------

INTRUSION_SETS_Q = """query($after: ID) {
  intrusionSets(first: 100, after: $after) {
    pageInfo { endCursor hasNextPage }
    edges { node { id name aliases description entity_type } }
  } }"""

THREAT_ACTOR_GROUPS_Q = """query($after: ID) {
  threatActorsGroup(first: 100, after: $after) {
    pageInfo { endCursor hasNextPage }
    edges { node { id name aliases description entity_type } }
  } }"""

REGIONS_Q = """query($after: ID) {
  regions(first: 100, after: $after) {
    pageInfo { endCursor hasNextPage }
    edges { node { id name } }
  } }"""

SCHEMA_Q = "{ schemaRelationsTypesMapping { key values } }"

FIND_Q = """query($f: [String], $t: [String], $r: [String]) {
  stixCoreRelationships(first: 50, fromId: $f, toId: $t, relationship_type: $r) {
    edges { node { id } } } }"""

STATE_Q = """query($id: String!) { stixCoreRelationship(id: $id) {
  id objectLabel { value } } }"""

CREATE_M = """mutation($input: StixCoreRelationshipAddInput!) {
  stixCoreRelationshipAdd(input: $input) { id } }"""

DELETE_M = """mutation($id: ID!) { stixCoreRelationshipEdit(id: $id) { delete } }"""

REPORT_OBJECT_IDS_Q = """query($id: String!, $after: ID) { report(id: $id) {
  objects(first: 500, after: $after) {
    pageInfo { endCursor hasNextPage }
    edges { node { ... on BasicObject { id } ... on BasicRelationship { id } } }
  } } }"""

REPORT_ACTORS_Q = """query($id: String!) { report(id: $id) {
  id name published
  objects(first: 500, types: ["Intrusion-Set", "Threat-Actor-Group"]) { edges { node {
    ... on IntrusionSet { id name entity_type }
    ... on ThreatActorGroup { id name entity_type }
  } } } } }"""

# -- generalized actor create/delete: dispatch on entity_type instead of
# hardcoding Threat-Actor-Group. Replaces octigeo's create_threat_actor_group
# and delete_threat_actor_group, which are gone. ---------------------------

TAG_ADD_M = """mutation ($input: ThreatActorGroupAddInput!) {
  threatActorGroupAdd(input: $input) { id name }
}"""

IS_ADD_M = """mutation ($input: IntrusionSetAddInput!) {
  intrusionSetAdd(input: $input) { id name }
}"""

ACTOR_CREATED_DESCRIPTION = (
    "Created by octi-rb from report text; no matching actor existed on the platform."
)

ACTOR_MUTATIONS: dict[str, tuple[str, str]] = {
    "Threat-Actor-Group": (TAG_ADD_M, "threatActorGroupAdd"),
    "Intrusion-Set": (IS_ADD_M, "intrusionSetAdd"),
}

TAG_DELETE_M = """mutation ($id: ID!) { threatActorGroupEdit(id: $id) { delete } }"""
IS_DELETE_M = """mutation ($id: ID!) { intrusionSetEdit(id: $id) { delete } }"""

ACTOR_DELETES: dict[str, str] = {
    "Threat-Actor-Group": TAG_DELETE_M,
    "Intrusion-Set": IS_DELETE_M,
}


class Client:
    def __init__(self, settings: Settings, timeout: int = 90):
        self.s = settings
        self.timeout = timeout

    # ---------------------------------------------------------------- transport

    def gql(self, query: str, variables: JsonDict | None = None) -> JsonDict:
        if not query.strip():
            raise OpenCTIError("Empty GraphQL query")
        body = json.dumps({"query": query, "variables": variables or {}}).encode()
        req = _checked_request(self.s.graphql_url, self.s.token, data=body)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 - checked
                payload = json.load(r)
        except TRANSPORT_ERRORS as exc:
            raise OpenCTIError(f"OpenCTI unreachable at {self.s.url}: {exc}") from exc
        except ValueError as exc:  # JSONDecodeError/UnicodeDecodeError: an HTML error page, say
            raise OpenCTIError(f"OpenCTI returned a non-JSON response: {exc}") from exc
        if not isinstance(payload, dict):
            raise OpenCTIError(f"GraphQL response is not a JSON object: {str(payload)[:300]}")
        if "errors" in payload:
            raise OpenCTIError(json.dumps(payload["errors"])[:1000])
        data = payload.get("data")
        if data is None:
            raise OpenCTIError(f"GraphQL response carried no data: {str(payload)[:300]}")
        return cast("JsonDict", data)

    def paginate(
        self, query: str, root: str, variables: JsonDict | None = None
    ) -> Iterator[JsonDict]:
        """Walk a relay-style connection, yielding nodes.

        Bounded by MAX_PAGES so a server that never clears hasNextPage cannot
        spin here forever.
        """
        after: str | None = None
        for _page in range(MAX_PAGES):
            v = dict(variables or {})
            v["after"] = after
            conn = self.gql(query, v)[root]
            for edge in conn["edges"]:
                yield edge["node"]
            if not conn["pageInfo"]["hasNextPage"]:
                return
            after = conn["pageInfo"]["endCursor"]
        raise OpenCTIError(f"Pagination of {root!r} exceeded {MAX_PAGES} pages; refusing to continue")

    def download(self, file_id: str) -> str:
        if not file_id:
            raise OpenCTIError("download() needs a file id")
        req = _checked_request(self.s.storage_url(file_id), self.s.token)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310 - checked
                text = r.read().decode("utf-8", errors="replace")
        except TRANSPORT_ERRORS as exc:
            raise OpenCTIError(f"download of file {file_id} failed: {exc}") from exc
        return str(text)

    # ------------------------------------------------------------------- reads

    REPORTS_Q = """
    query($after: ID) {
      reports(first: 100, after: $after, orderBy: created_at, orderMode: desc) {
        pageInfo { endCursor hasNextPage }
        edges { node {
          id name description created published
          createdBy { name }
          objectLabel { id value }
          objects(first: 5) { edges { node { ... on BasicObject { entity_type } } } }
          externalReferences { edges { node {
            id url source_name
            importFiles(first: 10) { edges { node { id name size } } }
          } } }
        } }
      }
    }"""

    def reports(self) -> Iterator[JsonDict]:
        return self.paginate(self.REPORTS_Q, "reports")

    def report(self, report_id: str) -> JsonDict:
        q = """query($id: String!) { report(id: $id) {
          id name description
          objectLabel { id value }
          objects(first: 500) { edges { node { __typename ... on BasicObject { id entity_type } } } }
          externalReferences { edges { node {
            id url source_name
            importFiles(first: 10) { edges { node { id name size } } }
          } } }
        } }"""
        return cast("JsonDict", self.gql(q, {"id": report_id})["report"])

    def report_object_ids(self, report_id: str) -> set[str]:
        """Every object id the report already contains, walked to the end.

        Paginated rather than a single `first: 500` read: containment apply
        uses this to decide whether a ref is ours, and a truncated read would
        stamp a vendor's ref as ours -- which revert would then strip.
        """
        if not report_id:
            raise OpenCTIError("report_object_ids() needs a report id")
        ids: set[str] = set()
        after: str | None = None
        for _page in range(MAX_PAGES):
            report = self.gql(REPORT_OBJECT_IDS_Q, {"id": report_id, "after": after})["report"]
            if report is None:
                raise OpenCTIError(f"report {report_id} not found")
            conn = report["objects"]
            ids.update(str(e["node"]["id"]) for e in conn["edges"] if (e.get("node") or {}).get("id"))
            if not conn["pageInfo"]["hasNextPage"]:
                return ids
            after = conn["pageInfo"]["endCursor"]
        raise OpenCTIError(f"report {report_id} objects exceeded {MAX_PAGES} pages")

    LOCATIONS_Q = """
    query($after: ID) {
      countries(first: 100, after: $after) {
        pageInfo { endCursor hasNextPage }
        edges { node { id standard_id name x_opencti_aliases } }
      }
    }"""

    def countries(self) -> list[JsonDict]:
        return list(self.paginate(self.LOCATIONS_Q, "countries"))

    def connector_id(self, name: str) -> str | None:
        for c in self.gql("{ connectors { id name active } }")["connectors"]:
            if c["name"] == name:
                return str(c["id"]) if c["active"] else None
        return None

    def connector(self, name: str) -> JsonDict | None:
        """Full connector record by name, or None if absent."""
        q = "{ connectors { id name active auto connector_type connector_scope } }"
        for record in self.gql(q)["connectors"]:
            if record["name"] == name:
                return cast("JsonDict", record)
        return None

    def external_reference_files(self, ref_id: str) -> list[JsonDict]:
        q = """query($id: String!) { externalReference(id: $id) {
          importFiles(first: 10) { edges { node { id name size } } } } }"""
        data = self.gql(q, {"id": ref_id})["externalReference"]
        return [cast("JsonDict", e["node"]) for e in data["importFiles"]["edges"]]

    MALWARE_NAMES_Q = """{ malwares(first: 2000) { edges { node {
      name aliases
    } } } }"""

    def malware_names(self) -> list[str]:
        edges = self.gql(self.MALWARE_NAMES_Q)["malwares"]["edges"]
        names: list[str] = []
        for edge in edges:
            node = edge["node"]
            names.append(str(node["name"]))
            names.extend(str(a) for a in (node.get("aliases") or []))
        return names

    def entity_reference_counts(self, entity_id: str) -> tuple[int, int]:
        """(relationships, containers) currently pointing at this entity."""
        q = """query ($id: String!) { stixCoreObject(id: $id) {
          stixCoreRelationships(first: 1) { pageInfo { globalCount } }
          containers(first: 1) { pageInfo { globalCount } }
        } }"""
        node = self.gql(q, {"id": entity_id})["stixCoreObject"]
        if node is None:
            return (0, 0)
        rels = int(node["stixCoreRelationships"]["pageInfo"]["globalCount"])
        containers = int(node["containers"]["pageInfo"]["globalCount"])
        return (rels, containers)

    def entity_labels(self, entity_id: str) -> list[str]:
        q = """query ($id: String!) { stixCoreObject(id: $id) {
          objectLabel { value }
        } }"""
        node = self.gql(q, {"id": entity_id})["stixCoreObject"]
        if node is None:
            return []
        return [str(label["value"]) for label in (node.get("objectLabel") or [])]

    # ------------------------------------------------------------------ writes

    def ask_enrichment(self, ref_id: str, connector_id: str) -> str:
        q = """mutation($id: ID!, $cid: ID!) {
          externalReferenceEdit(id: $id) { askEnrichment(connectorId: $cid) { id } } }"""
        edit = self.gql(q, {"id": ref_id, "cid": connector_id})["externalReferenceEdit"]
        return str(edit["askEnrichment"]["id"])

    def wait_for_file(
        self,
        ref_id: str,
        timeout: int = 180,
        poll: int = 5,
        suffix: str | None = None,
    ) -> list[JsonDict]:
        """Poll an external reference until the connector attaches a file.

        The connector writes the rendered PDF before the markdown, so waiting
        for "any file" returns the PDF and loses the text we actually want.
        When `suffix` is given, keep polling until a file matching it appears
        and only fall back to whatever exists once the timeout is reached.
        """
        if poll <= 0:
            raise OpenCTIError("wait_for_file() needs a positive poll interval")
        attempts = max(1, timeout // poll)
        files: list[JsonDict] = []
        for _ in range(attempts):
            files = self.external_reference_files(ref_id)
            if files and (suffix is None or any(str(f["name"]).endswith(suffix) for f in files)):
                return files
            time.sleep(poll)
        return files

    def add_object_to_report(self, report_id: str, object_id: str) -> None:
        q = """mutation($id: ID!, $to: StixRef!) {
          reportEdit(id: $id) {
            relationAdd(input: { toId: $to, relationship_type: "object" }) { id }
          } }"""
        self.gql(q, {"id": report_id, "to": object_id})

    def remove_object_from_report(self, report_id: str, object_id: str) -> None:
        q = """mutation($id: ID!, $to: StixRef!) {
          reportEdit(id: $id) {
            relationDelete(toId: $to, relationship_type: "object") { id }
          } }"""
        self.gql(q, {"id": report_id, "to": object_id})

    def ensure_label(self, value: str, color: str) -> str:
        q = """query($v: [Any!]!) { labels(filters: { mode: and, filters: [
          { key: "value", values: $v }], filterGroups: [] }) {
          edges { node { id value } } } }"""
        found = self.gql(q, {"v": [value]})["labels"]["edges"]
        for e in found:
            if e["node"]["value"] == value:
                return str(e["node"]["id"])
        m = """mutation($v: String!, $c: String!) {
          labelAdd(input: { value: $v, color: $c }) { id } }"""
        return str(self.gql(m, {"v": value, "c": color})["labelAdd"]["id"])

    def add_label_to_report(self, report_id: str, label_id: str) -> None:
        q = """mutation($id: ID!, $l: StixRef!) {
          reportEdit(id: $id) {
            relationAdd(input: { toId: $l, relationship_type: "object-label" }) { id }
          } }"""
        self.gql(q, {"id": report_id, "l": label_id})

    def remove_label_from_report(self, report_id: str, label_id: str) -> None:
        q = """mutation($id: ID!, $l: StixRef!) {
          reportEdit(id: $id) {
            relationDelete(toId: $l, relationship_type: "object-label") { id }
          } }"""
        self.gql(q, {"id": report_id, "l": label_id})

    # --------------------------------------------------- relationship reads/writes
    # (ported unchanged from octirel/relclient.py's RelClient, folded in here
    # as plain methods -- no subclassing.)

    def actors(self) -> list[JsonDict]:
        out = list(self.paginate(INTRUSION_SETS_Q, "intrusionSets"))
        out.extend(self.paginate(THREAT_ACTOR_GROUPS_Q, "threatActorsGroup"))
        if any(not node.get("id") for node in out):
            raise OpenCTIError("platform returned an actor with no id")
        return out

    def regions(self) -> list[JsonDict]:
        out = list(self.paginate(REGIONS_Q, "regions"))
        if any(not node.get("name") for node in out):
            raise OpenCTIError("platform returned a region with no name")
        return out

    def relation_schema(self) -> dict[str, frozenset[str]]:
        rows = self.gql(SCHEMA_Q)["schemaRelationsTypesMapping"]
        if not isinstance(rows, list):
            raise OpenCTIError("schemaRelationsTypesMapping is not a list")
        return {str(r["key"]): frozenset(str(v) for v in r["values"]) for r in rows}

    def find_relationships(self, from_id: str, to_id: str, rel_type: str) -> list[str]:
        if not (from_id and to_id and rel_type):
            raise ValueError("find_relationships needs from, to and type")
        data = self.gql(FIND_Q, {"f": [from_id], "t": [to_id], "r": [rel_type]})
        ids = [str(e["node"]["id"]) for e in data["stixCoreRelationships"]["edges"]]
        if any(not rel_id for rel_id in ids):
            raise OpenCTIError("find_relationships returned an empty id")
        return ids

    def relationship_state(self, rel_id: str) -> tuple[bool, list[str]]:
        if not rel_id:
            raise ValueError("relationship_state needs an id")
        node = self.gql(STATE_Q, {"id": rel_id})["stixCoreRelationship"]
        if node is None:
            return (False, [])
        if str(node.get("id")) != rel_id:
            raise OpenCTIError(
                f"relationship_state returned wrong id: got {node.get('id')}, expected {rel_id}"
            )
        return (True, [str(label["value"]) for label in (node.get("objectLabel") or [])])

    def create_relationship(  # noqa: PLR0913,PLR0917 - one argument per relationship field
        self, from_id: str, to_id: str, rel_type: str, confidence: int,
        description: str, label_id: str,
    ) -> str:
        if not (from_id and to_id and rel_type and label_id):
            raise ValueError("create_relationship needs from, to, type and label")
        if not 0 <= confidence <= MAX_CONFIDENCE:
            raise ValueError(f"confidence {confidence} outside 0..100")
        payload = {"input": {
            "fromId": from_id, "toId": to_id, "relationship_type": rel_type,
            "confidence": confidence, "description": description, "objectLabel": [label_id],
        }}
        result = self.gql(CREATE_M, payload)["stixCoreRelationshipAdd"]
        # Check before str(): str(None) == "None" is truthy (see tests/test_client.py).
        raw_id = result.get("id") if result else None
        if not raw_id:
            raise OpenCTIError(f"stixCoreRelationshipAdd returned no id for {from_id}->{to_id}")
        return str(raw_id)

    def delete_relationship(self, rel_id: str) -> None:
        if not rel_id:
            raise ValueError("delete_relationship needs an id")
        result = self.gql(DELETE_M, {"id": rel_id})["stixCoreRelationshipEdit"]
        if not result or not result.get("delete"):
            raise OpenCTIError(f"relationship {rel_id} was not deleted")

    def report_actors(self, report_id: str) -> JsonDict | None:
        if not report_id:
            raise ValueError("report_actors needs a report id")
        node = self.gql(REPORT_ACTORS_Q, {"id": report_id})["report"]
        if node is None:
            return None
        if str(node.get("id")) != report_id:
            raise OpenCTIError(
                f"report_actors returned wrong id: got {node.get('id')}, expected {report_id}"
            )
        actors = [
            {"actor_id": str(n["id"]), "name": str(n["name"]), "entity_type": str(n["entity_type"])}
            for n in (e["node"] for e in node["objects"]["edges"])
            if n.get("id")
        ]
        return cast("JsonDict", {
            "report_id": str(node["id"]), "title": str(node["name"]),
            "published": node.get("published"), "actors": actors,
        })

    # ------------------------------------------------------------- vulnerabilities

    VULNS_BY_NAME_Q = """query($names: [Any!]!) {
      vulnerabilities(first: 500, filters: { mode: and, filters: [
        { key: "name", values: $names }], filterGroups: [] }) {
        edges { node { id name } } } }"""

    def vulnerabilities_by_name(self, names: list[str]) -> dict[str, JsonDict]:
        if not names:
            raise ValueError("vulnerabilities_by_name needs at least one name")
        wanted = [n.strip().upper() for n in names if n and n.strip()]
        if len(wanted) > MAX_VULN_NAMES:
            raise OpenCTIError(f"refusing to look up {len(wanted)} names in one query (max 500)")
        edges = self.gql(self.VULNS_BY_NAME_Q, {"names": wanted})["vulnerabilities"]["edges"]
        out: dict[str, JsonDict] = {}
        for e in edges:
            node = e["node"]
            out[str(node["name"]).upper()] = {"id": str(node["id"]), "name": str(node["name"])}
        return out

    # ------------------------------------------------------------------- aliases

    ALIAS_PATCH_M = """mutation($id: ID!, $input: [EditInput]!) {
      stixDomainObjectEdit(id: $id) { fieldPatch(input: $input) { id } } }"""

    ENTITY_ALIASES_Q = """query($id: String!) { stixCoreObject(id: $id) {
      ... on IntrusionSet { aliases }
      ... on ThreatActorGroup { aliases }
    } }"""

    def entity_aliases(self, entity_id: str) -> list[str]:
        if not entity_id:
            raise ValueError("entity_aliases needs an entity id")
        node = self.gql(self.ENTITY_ALIASES_Q, {"id": entity_id})["stixCoreObject"]
        if node is None:
            return []
        return [str(a) for a in (node.get("aliases") or [])]

    def _alias_patch(self, entity_id: str, alias: str, operation: str) -> None:
        if not entity_id or not alias.strip():
            raise ValueError("alias patch needs an entity id and a non-empty alias")
        patch = [{"key": "aliases", "value": [alias.strip()], "operation": operation}]
        result = self.gql(self.ALIAS_PATCH_M, {"id": entity_id, "input": patch})["stixDomainObjectEdit"]
        if not result or not result.get("fieldPatch"):
            raise OpenCTIError(f"alias {operation} on {entity_id} returned nothing")

    def add_entity_alias(self, entity_id: str, alias: str) -> None:
        self._alias_patch(entity_id, alias, "add")

    def remove_entity_alias(self, entity_id: str, alias: str) -> None:
        self._alias_patch(entity_id, alias, "remove")

    # -------------------------------------------------------- actor create/delete

    def create_actor(self, entity_type: str, name: str, aliases: list[str], label_id: str) -> str:
        if entity_type not in ACTOR_MUTATIONS:
            raise OpenCTIError(f"create_actor: unsupported entity_type {entity_type!r}")
        if not name or not name.strip():
            raise OpenCTIError("refusing to create an actor with no name")
        mutation, root = ACTOR_MUTATIONS[entity_type]
        payload = {
            "input": {
                "name": name.strip(),
                "aliases": [a.strip() for a in aliases if a and a.strip()],
                "objectLabel": [label_id],
                "description": ACTOR_CREATED_DESCRIPTION,
            }
        }
        result = self.gql(mutation, payload)[root]
        # Check the raw value BEFORE stringifying: str(None) is "None", which
        # is truthy, so a null id would sail past a post-str() guard and be
        # written to the ledger as a real entity id.
        raw_id = result.get("id") if result else None
        if not raw_id:
            raise OpenCTIError(f"{root} returned no id for {name!r}")
        return str(raw_id)

    def delete_actor(self, entity_type: str, entity_id: str) -> None:
        if entity_type not in ACTOR_DELETES:
            raise OpenCTIError(f"delete_actor: unsupported entity_type {entity_type!r}")
        if not entity_id:
            raise ValueError("delete_actor needs an entity id")
        self.gql(ACTOR_DELETES[entity_type], {"id": entity_id})
