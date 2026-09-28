"""Coverage for cli.py: subcommand wiring, doctor, status, exit codes.

Style follows opencti-docker/tests/test_rel_cli.py: cmd_* functions are
invoked directly with an argparse.Namespace, and `cli._load_cfg`/`cli._client`
are monkeypatched so no real config.toml or network is ever touched.
`cli.main()` itself is only exercised for the argparse-exit and
SystemExit(str)-remap contract, via `cli.COMMANDS` monkeypatching.
"""

from __future__ import annotations

import dataclasses
import json
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest

from octirb import cli, ledger
from octirb.client import ACTOR_DELETES, OpenCTIError
from octirb.config import ActorsCfg, Config, RunsCfg
from octirb.linkers import REGISTRY
from octirb.linkers.base import Linker
from octirb.resolvers.actors import ActorVocabulary
from octirb.runstore import TextCache


def make_cfg(tmp_path: Path, **overrides: Any) -> Config:
    return Config(runs=RunsCfg(dir=str(tmp_path)), **overrides)


def ns(**over: Any) -> Namespace:
    base: dict[str, Any] = {
        "config": None, "run_id": None, "linker": None, "limit": None,
        "all_reports": False, "since_days": None, "source": None,
        "dry_run": False, "include_review": False, "create_missing": False,
        "action": None,
    }
    base.update(over)
    return Namespace(**base)


def write_meta(run_dir: Path, **fields: Any) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    base = {"run_id": run_dir.name, "linker": "report-vuln", "created": "2020-01-01T00:00:00+00:00",
            "options": {}}
    base.update(fields)
    (run_dir / "meta.json").write_text(json.dumps(base))


def report_node(rid: str, name: str, *, host: str | None = "example.com") -> dict[str, Any]:
    refs = []
    if host is not None:
        refs.append({
            "node": {"id": f"ref-{rid}", "url": f"https://{host}/a", "source_name": "Vendor",
                      "importFiles": {"edges": []}},
        })
    return {
        "id": rid, "name": name, "description": "", "created": "2020-01-01",
        "published": "2020-01-01", "createdBy": {"name": "Vendor"},
        "objects": {"edges": []}, "externalReferences": {"edges": refs},
    }


class ReportsClient:
    def __init__(self, nodes: list[dict[str, Any]]) -> None:
        self._nodes = nodes

    def reports(self) -> Any:
        return iter(self._nodes)


# --------------------------------------------------------- main() contract


def test_main_maps_string_systemexit_to_2(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(_args: Namespace) -> int:
        raise SystemExit("no such run")

    monkeypatch.setitem(cli.COMMANDS, "status", boom)
    assert cli.main(["status"]) == cli.EXIT_BAD_RUN


def test_main_leaves_argparse_exits_alone() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0


def test_main_returns_int_exit_code_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(cli.COMMANDS, "status", lambda _args: cli.EXIT_FAIL)
    assert cli.main(["status"]) == cli.EXIT_FAIL


def test_main_catches_opencti_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(_args: Namespace) -> int:
        raise OpenCTIError("platform unreachable at http://localhost:8080")

    monkeypatch.setitem(cli.COMMANDS, "status", boom)
    result = cli.main(["status"])
    assert result == cli.EXIT_FAIL
    err = capsys.readouterr().err
    assert "platform unreachable at http://localhost:8080" in err
    assert "Traceback" not in err


# -------------------------------------------------------------------- select


def test_select_writes_meta_last(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from octirb.runstore import Run

    written: list[str] = []
    original = Run.write_json

    def spy(self: Run, name: str, data: Any) -> Path:
        written.append(name)
        return original(self, name, data)

    monkeypatch.setattr(Run, "write_json", spy)
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    monkeypatch.setattr(cli, "_client", lambda _cfg: ReportsClient([report_node("r1", "Report One")]))

    result = cli.cmd_select(ns(linker="report-vuln", all_reports=True))
    assert result == cli.EXIT_OK
    assert written[-1] == "meta.json"
    assert written[0] == "selection.json"


def test_select_refuses_reused_run_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_meta(tmp_path / "r1")
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)

    def boom(_cfg: Config) -> Any:
        raise AssertionError("_client must not be called when --run-id already has a meta.json")

    monkeypatch.setattr(cli, "_client", boom)
    result = cli.cmd_select(ns(linker="report-vuln", run_id="r1"))
    assert result == cli.EXIT_BAD_RUN


def test_select_vuln_disabled_is_bad_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from octirb.config import VulnsCfg

    cfg = make_cfg(tmp_path, vulns=VulnsCfg(enabled=False))
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    with pytest.raises(SystemExit, match=r"report-vuln is disabled"):
        cli.cmd_select(ns(linker="report-vuln"))


def test_select_actor_target_requires_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    result = cli.cmd_select(ns(linker="actor-target", source=None))
    assert result == cli.EXIT_BAD_RUN


def test_select_unknown_linker_exits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    with pytest.raises(SystemExit):
        cli.cmd_select(ns(linker="bogus"))


# --------------------------------------------------------------------- fetch


def test_fetch_refuses_actor_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_meta(tmp_path / "r1", linker="actor-target", source="description")
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    result = cli.cmd_fetch(ns(run_id="r1"))
    assert result == cli.EXIT_BAD_RUN


# --------------------------------------------------------------------- batch


def test_batch_vuln_writes_extractions_directly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = tmp_path / "r1"
    write_meta(run_dir, linker="report-vuln")
    (run_dir / "selection.json").write_text(json.dumps([
        {"report_id": "r1", "name": "N", "source": "Vendor", "description_chars": 0,
         "text_tier": "description", "external_reference_id": None, "url": None,
         "host": None, "existing_files": []},
    ]))
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    TextCache(cfg.cache_dir).write("r1", "Also mentions CVE-2026-12345 in passing text.")

    result = cli.cmd_batch(ns(run_id="r1"))
    assert result == cli.EXIT_OK
    extractions = json.loads((run_dir / "extractions.json").read_text())
    assert extractions[0]["cve"] == "CVE-2026-12345"
    assert not (run_dir / "batch.json").exists()
    assert not (run_dir / "CONTRACT.md").exists()


class _FakeResolver:
    def __len__(self) -> int:
        return 3

    def resolve(self, _key: str) -> Any:
        return None

    def probes(self) -> list[str]:
        return []


def test_batch_needs_model_writes_batch_and_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "r1"
    write_meta(run_dir, linker="report-location")
    (run_dir / "selection.json").write_text(json.dumps([
        {"report_id": "r1", "name": "N", "source": "Vendor", "description_chars": 0,
         "text_tier": "description", "external_reference_id": None, "url": None,
         "host": None, "existing_files": []},
    ]))
    cfg = make_cfg(tmp_path)
    TextCache(cfg.cache_dir).write("r1", "some article text")
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    monkeypatch.setattr(cli, "_client", lambda _cfg: object())

    fake_linker = Linker(
        name="report-location", key_field="iso3", roles=frozenset({"origin"}),
        label_suffix="Location", entity_kind="Country", write_kind="containment",
        needs_model=True, build_resolver=lambda _c, _cfg: _FakeResolver(),
        contract=lambda r: f"CONTRACT for {len(r)} entries",
    )
    monkeypatch.setitem(REGISTRY, "report-location", fake_linker)

    result = cli.cmd_batch(ns(run_id="r1"))
    assert result == cli.EXIT_OK
    batch = json.loads((run_dir / "batch.json").read_text())
    assert batch[0]["report_id"] == "r1"
    assert (run_dir / "CONTRACT.md").read_text() == "CONTRACT for 3 entries"


# ---------------------------------------------------------------- structured


def test_structured_merges_extractions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = tmp_path / "r1"
    write_meta(run_dir, linker="report-sector")
    (run_dir / "batch.json").write_text(json.dumps([
        {"report_id": "r1", "title": "T", "source": "CISA",
         "text": "CRITICAL INFRASTRUCTURE SECTORS: Energy\nCOUNTRIES/AREAS DEPLOYED: Worldwide"},
    ]))
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)

    result = cli.cmd_structured(ns(run_id="r1"))
    assert result == cli.EXIT_OK
    extractions = json.loads((run_dir / "extractions.json").read_text())
    assert extractions[0]["sector"] == "Energy"


# ---------------------------------------------------------------- validate


def test_cmd_validate_non_array_exit2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = tmp_path / "r1"
    write_meta(run_dir, linker="report-vuln")
    (run_dir / "extractions.json").write_text('{"a": 1}')
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)

    result = cli.cmd_validate(ns(run_id="r1"))
    assert result == cli.EXIT_BAD_RUN


# ------------------------------------------------------------------- apply


class ContainmentFakeClient:
    def __init__(self) -> None:
        self.added_objects: list[tuple[str, str]] = []
        self.added_labels: list[tuple[str, str]] = []
        self.labels_ensured: list[tuple[str, str]] = []

    def ensure_label(self, value: str, color: str) -> str:
        self.labels_ensured.append((value, color))
        return f"label-{value}"

    def add_object_to_report(self, report_id: str, object_id: str) -> None:
        self.added_objects.append((report_id, object_id))

    def add_label_to_report(self, report_id: str, label_id: str) -> None:
        self.added_labels.append((report_id, label_id))


def test_apply_requires_create_missing_on_actor_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_meta(tmp_path / "r1", linker="report-location")
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)

    def boom(_cfg: Config) -> Any:
        raise AssertionError("_client must not be called")

    monkeypatch.setattr(cli, "_client", boom)
    result = cli.cmd_apply(ns(run_id="r1", create_missing=True))
    assert result == cli.EXIT_BAD_RUN


def test_apply_containment_merges_ledger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = tmp_path / "r1"
    write_meta(run_dir, linker="report-location")
    auto_item = {"report_id": "r1", "entity_id": "e1", "entity_name": "France",
                 "iso3": "FRA", "role": "target", "confidence": "high", "evidence": "q"}
    (run_dir / "auto.json").write_text(json.dumps([auto_item]))
    (run_dir / "review.json").write_text(json.dumps([]))
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    fake = ContainmentFakeClient()
    monkeypatch.setattr(cli, "_client", lambda _cfg: fake)

    result = cli.cmd_apply(ns(run_id="r1"))
    assert result == cli.EXIT_OK
    applied = json.loads((run_dir / "applied.json").read_text())
    assert applied[0]["entity_id"] == "e1"
    assert fake.added_objects == [("r1", "e1")]


# ------------------------------------------------------------------- revert


class RevertFakeClient:
    def __init__(self) -> None:
        self.removed_objects: list[tuple[str, str]] = []
        self.removed_labels: list[tuple[str, str]] = []

    def remove_object_from_report(self, report_id: str, object_id: str) -> None:
        self.removed_objects.append((report_id, object_id))

    def remove_label_from_report(self, report_id: str, label_id: str) -> None:
        self.removed_labels.append((report_id, label_id))


def test_revert_containment_clears_applied_and_records_reverted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_dir = tmp_path / "r1"
    write_meta(run_dir, linker="report-location")
    row = ledger.containment_row(
        report_id="r1", entity_id="e1", entity_name="France", linker="report-location",
        key="FRA", role="target", confidence="high", evidence="q", label_id=None, created=False,
    )
    (run_dir / "applied.json").write_text(json.dumps([row]))
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    fake = RevertFakeClient()
    monkeypatch.setattr(cli, "_client", lambda _cfg: fake)

    result = cli.cmd_revert(ns(run_id="r1"))
    assert result == cli.EXIT_OK
    assert fake.removed_objects == [("r1", "e1")]
    assert json.loads((run_dir / "applied.json").read_text()) == []
    reverted = json.loads((run_dir / "reverted.json").read_text())
    assert reverted[0]["entity_id"] == "e1"


def test_revert_rejects_corrupt_applied_ledger(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = tmp_path / "r1"
    write_meta(run_dir, linker="report-location")
    (run_dir / "applied.json").write_text('{"not": "a list"}')
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    result = cli.cmd_revert(ns(run_id="r1"))
    assert result == cli.EXIT_BAD_RUN


class MixedRevertFakeClient:
    """One ledger of every kind at once: proves each revert helper only acts
    on its own kind. Before the fix, _revert_relationships handed writer.revert
    (which never filters by kind) the WHOLE row list, and writer.revert
    KeyErrors on the first non-relationship row's missing "preexisted" key."""

    def __init__(self) -> None:
        self.removed_objects: list[tuple[str, str]] = []
        self.removed_aliases: list[tuple[str, str]] = []
        self.deleted_relationships: list[str] = []
        self.deleted_actors: list[tuple[str, str]] = []

    def remove_object_from_report(self, report_id: str, object_id: str) -> None:
        self.removed_objects.append((report_id, object_id))

    def remove_label_from_report(self, report_id: str, label_id: str) -> None:
        raise AssertionError("no containment row in this test carries a label_id")

    def remove_entity_alias(self, entity_id: str, alias: str) -> None:
        self.removed_aliases.append((entity_id, alias))

    def relationship_state(self, rel_id: str) -> tuple[bool, list[str]]:
        return (True, ["AI-Relationship"])

    def delete_relationship(self, rel_id: str) -> None:
        self.deleted_relationships.append(rel_id)

    def entity_labels(self, entity_id: str) -> list[str]:
        # The label ActorVocabulary.create stamps on a minted entity -- NOT
        # the run's linker label. This fake used to return the linker label
        # (AI-Location), which is what let the C1 label mismatch pass.
        return ["AI-Created"]

    def entity_reference_counts(self, entity_id: str) -> tuple[int, int]:
        return (0, 0)

    def delete_actor(self, entity_type: str, entity_id: str) -> None:
        self.deleted_actors.append((entity_type, entity_id))


def test_revert_filters_rows_by_kind(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = tmp_path / "r1"
    write_meta(run_dir, linker="report-location")
    containment = ledger.containment_row(
        report_id="r1", entity_id="e1", entity_name="France", linker="report-location",
        key="FRA", role="target", confidence="high", evidence="q", label_id=None, created=False,
    )
    alias = ledger.alias_row(
        entity_id="e2", entity_name="APT29", alias="ICE RELIC", preexisted=False, evidence="q"
    )
    rel_item = {
        "actor_id": "a1", "actor": "APT29", "relationship_type": "targets",
        "target_kind": "country", "target_id": "t1", "target_name": "Ukraine",
        "confidence": "high", "evidence": "q", "source": "report", "source_refs": ["r1"],
    }
    relationship = ledger.relationship_row(
        rel_item, relationship_id="rel-1", preexisted=False, in_reports=[], label_id="lbl-2",
        status="created",
    )
    entity = ledger.entity_row(entity_id="e3", entity_type="Intrusion-Set", name="WaterPlum")
    (run_dir / "applied.json").write_text(json.dumps([containment, alias, relationship, entity]))

    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    fake = MixedRevertFakeClient()
    monkeypatch.setattr(cli, "_client", lambda _cfg: fake)

    result = cli.cmd_revert(ns(run_id="r1"))
    assert result == cli.EXIT_OK
    assert fake.removed_objects == [("r1", "e1")]
    assert fake.removed_aliases == [("e2", "ICE RELIC")]
    assert fake.deleted_relationships == ["rel-1"]
    assert fake.deleted_actors == [("Intrusion-Set", "e3")]


class MintRevertFakeClient:
    """Plays both ends of the create-missing seam: apply mints through the
    REAL ActorVocabulary.create (so the label and entity_type on the platform
    are whatever the producer actually stamps), revert purges through
    delete_actor, which -- like the real client -- only accepts the actor
    types it has a delete mutation for, and only the type the entity has."""

    def __init__(self) -> None:
        self.label_values: dict[str, str] = {}
        self.entity_type: dict[str, str] = {}
        self.entity_label: dict[str, list[str]] = {}
        self.report_objects: dict[str, set[str]] = {}
        self.deleted: list[tuple[str, str]] = []

    def ensure_label(self, value: str, color: str) -> str:
        self.label_values[f"label-{value}"] = value
        return f"label-{value}"

    def create_actor(self, entity_type: str, name: str, aliases: list[str], label_id: str) -> str:
        self.entity_type["minted-1"] = entity_type
        self.entity_label["minted-1"] = [self.label_values[label_id]]
        return "minted-1"

    def report_object_ids(self, report_id: str) -> set[str]:
        return set(self.report_objects.get(report_id, set()))

    def add_object_to_report(self, report_id: str, object_id: str) -> None:
        self.report_objects.setdefault(report_id, set()).add(object_id)

    def add_label_to_report(self, report_id: str, label_id: str) -> None:
        return None

    def remove_object_from_report(self, report_id: str, object_id: str) -> None:
        self.report_objects.get(report_id, set()).discard(object_id)

    def remove_label_from_report(self, report_id: str, label_id: str) -> None:
        return None

    def entity_labels(self, entity_id: str) -> list[str]:
        return list(self.entity_label.get(entity_id, []))

    def entity_reference_counts(self, entity_id: str) -> tuple[int, int]:
        containers = sum(1 for objs in self.report_objects.values() if entity_id in objs)
        return (0, containers)

    def delete_actor(self, entity_type: str, entity_id: str) -> None:
        if entity_type not in ACTOR_DELETES or entity_type != self.entity_type.get(entity_id):
            raise OpenCTIError(f"delete_actor: wrong entity_type {entity_type!r} for {entity_id}")
        self.deleted.append((entity_type, entity_id))
        self.entity_label.pop(entity_id, None)


def _minting_actor_linker() -> Linker:
    def build(client: Any, cfg: Config) -> ActorVocabulary:
        return ActorVocabulary(
            [], [], client, label=cfg.label("Created"), create_type=cfg.actors.create_missing_type
        )

    return dataclasses.replace(REGISTRY["report-actor"], build_resolver=build)


def test_revert_purges_entity_minted_by_create_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """C1: apply --create-missing then revert must delete the minted entity.

    Feeds the real producer's output (create_missing -> apply_containment ->
    applied.json) into cmd_revert, rather than a hand-built entity row, so a
    label or entity_type disagreement between the two ends fails here.
    """
    run_dir = tmp_path / "r1"
    write_meta(run_dir, linker="report-actor")
    creatable = {
        "report_id": "rep-1", "actor": "WaterPlum", "aliases": [], "role": "attributed",
        "confidence": "high", "evidence": "WaterPlum did it", "creatable": True,
        "hard_fail": True, "review_reasons": ["unresolved actor 'WaterPlum'"],
    }
    (run_dir / "auto.json").write_text("[]")
    (run_dir / "review.json").write_text(json.dumps([creatable]))
    cfg = make_cfg(tmp_path, actors=ActorsCfg(create_missing_type="Threat-Actor-Group"))
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    fake = MintRevertFakeClient()
    monkeypatch.setattr(cli, "_client", lambda _cfg: fake)
    minting = _minting_actor_linker()
    monkeypatch.setattr(cli, "get", lambda _name: minting)

    assert cli.cmd_apply(ns(run_id="r1", create_missing=True)) == cli.EXIT_OK
    applied = json.loads((run_dir / "applied.json").read_text())
    entity_rows = [r for r in applied if r["kind"] == "entity"]
    assert entity_rows == [
        {"kind": "entity", "entity_id": "minted-1", "entity_type": "Threat-Actor-Group", "name": "WaterPlum"}
    ]

    assert cli.cmd_revert(ns(run_id="r1")) == cli.EXIT_OK
    assert fake.deleted == [("Threat-Actor-Group", "minted-1")]
    assert json.loads((run_dir / "applied.json").read_text()) == []


class FlakyRevertFakeClient(MixedRevertFakeClient):
    """Fails exactly one containment removal and one alias removal."""

    def remove_object_from_report(self, report_id: str, object_id: str) -> None:
        if object_id == "e-bad":
            raise OpenCTIError("transient")
        super().remove_object_from_report(report_id, object_id)

    def remove_entity_alias(self, entity_id: str, alias: str) -> None:
        if alias == "BAD ALIAS":
            raise OpenCTIError("transient")
        super().remove_entity_alias(entity_id, alias)


def _crow(entity_id: str, *, created: bool = False) -> dict[str, Any]:
    return ledger.containment_row(
        report_id="r1", entity_id=entity_id, entity_name=entity_id, linker="report-actor",
        key=entity_id, role="attributed", confidence="high", evidence="q", label_id=None,
        created=created,
    )


def test_revert_keeps_failed_rows_in_applied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """I8: a row whose undo failed stays in applied.json for a retry; rows
    undone (or correctly kept) move to reverted.json."""
    run_dir = tmp_path / "r1"
    write_meta(run_dir, linker="report-actor")
    good, bad = _crow("e-good"), _crow("e-bad")
    alias_ok = ledger.alias_row(entity_id="e2", entity_name="X", alias="OK", preexisted=False, evidence="q")
    alias_bad = ledger.alias_row(entity_id="e2", entity_name="X", alias="BAD ALIAS", preexisted=False, evidence="q")
    (run_dir / "applied.json").write_text(json.dumps([good, bad, alias_ok, alias_bad]))
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    monkeypatch.setattr(cli, "_client", lambda _cfg: FlakyRevertFakeClient())

    assert cli.cmd_revert(ns(run_id="r1")) == cli.EXIT_OK
    assert json.loads((run_dir / "applied.json").read_text()) == [bad, alias_bad]
    assert json.loads((run_dir / "reverted.json").read_text()) == [good, alias_ok]


def test_revert_retains_entity_rows_still_owned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """I8: an entity kept because it is still referenced stays ours -- its row
    stays in applied.json so a later revert can purge it once orphaned."""

    class StillReferenced(MixedRevertFakeClient):
        def entity_reference_counts(self, entity_id: str) -> tuple[int, int]:
            return (1, 0)

    run_dir = tmp_path / "r1"
    write_meta(run_dir, linker="report-actor")
    entity = ledger.entity_row(entity_id="e3", entity_type="Intrusion-Set", name="WaterPlum")
    (run_dir / "applied.json").write_text(json.dumps([_crow("e3", created=True), entity]))
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    fake = StillReferenced()
    monkeypatch.setattr(cli, "_client", lambda _cfg: fake)

    assert cli.cmd_revert(ns(run_id="r1")) == cli.EXIT_OK
    assert fake.deleted_actors == []
    assert json.loads((run_dir / "applied.json").read_text()) == [entity]


# ------------------------------------------------------------------- status


def test_status_tolerates_unknown_linker_in_meta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write_meta(tmp_path / "r1", linker="bogus-linker", created="2020-01-01T00:00:00+00:00")
    d2 = tmp_path / "r2"
    write_meta(d2, linker="report-vuln", created="2020-01-02T00:00:00+00:00")
    (d2 / "selection.json").write_text("[1, 2]")

    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    result = cli.cmd_status(ns())
    assert result == cli.EXIT_OK
    out = capsys.readouterr().out
    assert "r1" in out
    assert "bogus-linker" in out
    assert "r2" in out
    assert "report-vuln" in out


def test_status_no_runs_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_cfg(tmp_path / "does-not-exist")
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    result = cli.cmd_status(ns())
    assert result == cli.EXIT_OK


# ------------------------------------------------------------------- doctor


def test_doctor_missing_token_is_fail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    monkeypatch.delenv("OPENCTI_TOKEN", raising=False)
    monkeypatch.delenv("OPENCTI_ADMIN_TOKEN", raising=False)
    result = cli.cmd_doctor(ns())
    assert result == cli.EXIT_FAIL


# ---------------------------------------------------------------- crosswalk


def test_crosswalk_refresh_dispatches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    calls: list[Path] = []

    def fake_refresh(cache_dir: Path) -> Path:
        calls.append(cache_dir)
        return cache_dir / "threat-actor-galaxy.json"

    monkeypatch.setattr(cli.crosswalk, "refresh", fake_refresh)
    result = cli.cmd_crosswalk(ns(action="refresh"))
    assert result == cli.EXIT_OK
    assert calls == [cfg.cache_dir]
