"""apply_containment()/revert_containment()/revert_aliases()/purge_created()
coverage.

Ported from the purge-FLOW parts of opencti-docker/tests/test_purge.py (the
pure `should_delete` cases already live in tests/test_ledger.py as
`should_delete_entity`) and its `test_apply_stamps_the_created_flag_onto_
the_ledger`. Adapted for octi-rb's shape:

- octigeo's `apply`/`purge_created` worked off one flat `applied: list[dict]`
  that doubled as both "what got written" and "what got created". octi-rb's
  ledger is typed (Task 5): `apply_containment` returns `"containment"`,
  `"alias"` and `"entity"` rows, and `purge_created` reads `"entity"` rows
  for its targets and `"containment"` rows with `created=True` for the
  own-refs dry-run discount, joined by `entity_id`.
- `ACTOR_LABEL`/`delete_threat_actor_group` are gone (Task 8): `label` and
  `entity_types` are now parameters, dispatching to
  `client.delete_actor(entity_type, entity_id)`.
- `dimensions.get("actor")`/`ACTOR` -> a hand-built `Linker`, same rationale
  as test_pipeline_validate.py.

New (Task 12 brief step 2): label-prefixing and alias-write-back execution
coverage, which have no upstream analogue.
"""

from __future__ import annotations

from typing import Any

from octirb import ledger, pipeline
from octirb.client import OpenCTIError
from octirb.config import Config
from octirb.linkers.base import Linker

LABEL = "AI-Created"


def _actor_linker() -> Linker:
    return Linker(
        name="report-actor",
        key_field="actor",
        roles=frozenset({"attributed", "mentioned"}),
        label_suffix="Actor",
        entity_kind="Intrusion-Set",
        write_kind="containment",
        needs_model=True,
        build_resolver=lambda _c, _cfg: None,  # type: ignore[return-value]
        contract=None,
        alias_field="aliases",
    )


def _location_linker() -> Linker:
    return Linker(
        name="report-location",
        key_field="iso3",
        roles=frozenset({"origin", "target", "mentioned"}),
        label_suffix="Location",
        entity_kind="Country",
        write_kind="containment",
        needs_model=True,
        build_resolver=lambda _c, _cfg: None,  # type: ignore[return-value]
        contract=None,
    )


ACTOR = _actor_linker()
LOCATION = _location_linker()


class FakeClient:
    """Records every mutating call; reads answer from the dicts passed in."""

    def __init__(
        self,
        *,
        aliases: dict[str, list[str]] | None = None,
        labels: dict[str, list[str]] | None = None,
        ref_counts: dict[str, tuple[int, int]] | None = None,
    ) -> None:
        self._aliases = {k: list(v) for k, v in (aliases or {}).items()}
        self._labels = labels or {}
        self._ref_counts = ref_counts or {}

        self.added_objects: list[tuple[str, str]] = []
        self.removed_objects: list[tuple[str, str]] = []
        self.labels_ensured: list[tuple[str, str]] = []
        self.added_labels: list[tuple[str, str]] = []
        self.removed_labels: list[tuple[str, str]] = []
        self.added_aliases: list[tuple[str, str]] = []
        self.removed_aliases: list[tuple[str, str]] = []
        self.deleted: list[tuple[str, str]] = []

    def ensure_label(self, value: str, color: str) -> str:
        self.labels_ensured.append((value, color))
        return f"label-{value}"

    def add_object_to_report(self, report_id: str, object_id: str) -> None:
        self.added_objects.append((report_id, object_id))

    def remove_object_from_report(self, report_id: str, object_id: str) -> None:
        self.removed_objects.append((report_id, object_id))

    def add_label_to_report(self, report_id: str, label_id: str) -> None:
        self.added_labels.append((report_id, label_id))

    def remove_label_from_report(self, report_id: str, label_id: str) -> None:
        self.removed_labels.append((report_id, label_id))

    def entity_aliases(self, entity_id: str) -> list[str]:
        return list(self._aliases.get(entity_id, []))

    def add_entity_alias(self, entity_id: str, alias: str) -> None:
        self.added_aliases.append((entity_id, alias))
        self._aliases.setdefault(entity_id, []).append(alias)

    def remove_entity_alias(self, entity_id: str, alias: str) -> None:
        self.removed_aliases.append((entity_id, alias))

    def entity_labels(self, entity_id: str) -> list[str]:
        return list(self._labels.get(entity_id, []))

    def entity_reference_counts(self, entity_id: str) -> tuple[int, int]:
        return self._ref_counts.get(entity_id, (0, 0))

    def delete_actor(self, entity_type: str, entity_id: str) -> None:
        self.deleted.append((entity_type, entity_id))


def logs() -> tuple[list[str], Any]:
    sink: list[str] = []
    return sink, sink.append


def item(**over: Any) -> dict[str, Any]:
    base = {
        "report_id": "r1", "entity_id": "e1", "entity_name": "APT29",
        "actor": "APT29", "role": "attributed", "confidence": "high", "evidence": "q",
    }
    base.update(over)
    return base


# --------------------------------------------------------------- apply: new


def test_apply_labels_report_with_prefixed_label():
    client = FakeClient()
    cfg = Config()
    _, log = logs()
    pipeline.apply_containment(
        client, [item(entity_id="e1", entity_name="France")], log, LOCATION, cfg, dry_run=False
    )
    assert ("AI-Location", cfg.labels.color) in client.labels_ensured
    assert client.added_labels == [("r1", "label-AI-Location")]


def test_alias_writeback_preexisting_not_readded():
    client = FakeClient(aliases={"e1": ["ICE RELIC"]})
    cfg = Config()
    _, log = logs()
    approved = [item(alias_writes=["ICE RELIC"])]
    rows = pipeline.apply_containment(client, approved, log, ACTOR, cfg, dry_run=False)
    assert client.added_aliases == []
    alias_rows = [r for r in rows if r["kind"] == "alias"]
    assert len(alias_rows) == 1
    assert alias_rows[0]["preexisted"] is True
    assert alias_rows[0]["alias"] == "ICE RELIC"


def test_alias_writeback_added_and_row_written():
    client = FakeClient(aliases={"e1": []})
    cfg = Config()
    _, log = logs()
    approved = [item(alias_writes=["ICE RELIC"])]
    rows = pipeline.apply_containment(client, approved, log, ACTOR, cfg, dry_run=False)
    assert client.added_aliases == [("e1", "ICE RELIC")]
    alias_rows = [r for r in rows if r["kind"] == "alias"]
    assert len(alias_rows) == 1
    assert alias_rows[0]["preexisted"] is False


def test_alias_writeback_skipped_below_auto_confidence():
    """Delta 5: alias write-back only runs for confidence == high."""
    client = FakeClient(aliases={"e1": []})
    cfg = Config()
    _, log = logs()
    approved = [item(alias_writes=["ICE RELIC"], confidence="medium")]
    rows = pipeline.apply_containment(client, approved, log, ACTOR, cfg, dry_run=False)
    assert client.added_aliases == []
    assert [r for r in rows if r["kind"] == "alias"] == []


def test_revert_removes_only_non_preexisting_aliases():
    client = FakeClient()
    _, log = logs()
    rows = [
        ledger.alias_row(
            entity_id="e1", entity_name="APT29", alias="ICE RELIC",
            preexisted=False, evidence="q",
        ),
        ledger.alias_row(
            entity_id="e1", entity_name="APT29", alias="Cozy Bear",
            preexisted=True, evidence="q",
        ),
    ]
    reverted = pipeline.revert_aliases(client, rows, log, dry_run=False)
    assert reverted == 1
    assert client.removed_aliases == [("e1", "ICE RELIC")]


def test_dry_run_apply_mutates_nothing():
    client = FakeClient()
    cfg = Config()
    _, log = logs()
    approved = [item(alias_writes=["ICE RELIC"], created=True)]
    rows = pipeline.apply_containment(client, approved, log, ACTOR, cfg, dry_run=True)
    assert client.added_objects == []
    assert client.removed_objects == []
    assert client.labels_ensured == []
    assert client.added_labels == []
    assert client.removed_labels == []
    assert client.added_aliases == []
    assert client.removed_aliases == []
    assert client.deleted == []
    kinds = {r["kind"] for r in rows}
    assert kinds == {"containment", "entity", "alias"}


# ---------------------------------------------------- ported: test_purge.py


def crow(entity_id: str = "e1", report_id: str = "r1", created: bool = True) -> dict[str, Any]:
    return ledger.containment_row(
        report_id=report_id, entity_id=entity_id, entity_name="WaterPlum",
        linker="report-actor", key="WaterPlum", role="attributed",
        confidence="high", evidence="q", label_id=None, created=created,
    )


def erow(entity_id: str = "e1", name: str = "WaterPlum") -> dict[str, Any]:
    return ledger.entity_row(entity_id=entity_id, entity_type="Intrusion-Set", name=name)


ENTITY_TYPES = {"e1": "Intrusion-Set"}


def test_deletes_an_orphaned_entity_we_own():
    client = FakeClient(labels={"e1": [LABEL]}, ref_counts={"e1": (0, 0)})
    _, log = logs()
    result = pipeline.purge_created(
        client, [erow(), crow()], log, dry_run=False, label=LABEL, entity_types=ENTITY_TYPES
    )
    assert result == (1, 0)
    assert client.deleted == [("Intrusion-Set", "e1")]


def test_keeps_an_entity_another_report_still_references():
    client = FakeClient(labels={"e1": [LABEL]}, ref_counts={"e1": (0, 1)})
    _, log = logs()
    result = pipeline.purge_created(
        client, [erow(), crow()], log, dry_run=False, label=LABEL, entity_types=ENTITY_TYPES
    )
    assert result == (0, 1)
    assert client.deleted == []


def test_ignores_rows_we_did_not_create():
    """No entity row (apply_containment only writes one for created=True), so
    nothing to purge even though a containment row references the entity."""
    client = FakeClient(labels={"e1": [LABEL]}, ref_counts={"e1": (0, 0)})
    _, log = logs()
    result = pipeline.purge_created(
        client, [crow(created=False)], log, dry_run=False, label=LABEL, entity_types=ENTITY_TYPES
    )
    assert result == (0, 0)
    assert client.deleted == []


def test_one_entity_across_three_reports_is_deleted_once():
    client = FakeClient(labels={"e1": [LABEL]}, ref_counts={"e1": (0, 0)})
    _, log = logs()
    rows = [erow(), crow(report_id="r1"), crow(report_id="r2"), crow(report_id="r3")]
    result = pipeline.purge_created(
        client, rows, log, dry_run=False, label=LABEL, entity_types=ENTITY_TYPES
    )
    assert result == (1, 0)
    assert client.deleted == [("Intrusion-Set", "e1")]


def test_an_already_gone_entity_is_skipped():
    """No labels means the entity no longer exists.

    This is what makes revert re-runnable: a second revert finds nothing and
    counts it as neither deleted nor kept.
    """
    client = FakeClient(labels={}, ref_counts={"e1": (0, 0)})
    _, log = logs()
    result = pipeline.purge_created(
        client, [erow(), crow()], log, dry_run=False, label=LABEL, entity_types=ENTITY_TYPES
    )
    assert result == (0, 0)
    assert client.deleted == []


def test_an_inspection_failure_keeps_the_entity():
    """An entity that cannot be inspected cannot be proven orphaned.

    Guessing wrong here is unrecoverable, so the conservative answer is the
    only safe one: keep it and say why.
    """

    class Unreachable(FakeClient):
        def entity_reference_counts(self, _entity_id: str) -> tuple[int, int]:
            raise OpenCTIError("platform unreachable")

    client = Unreachable(labels={"e1": [LABEL]})
    _, log = logs()
    result = pipeline.purge_created(
        client, [erow(), crow()], log, dry_run=False, label=LABEL, entity_types=ENTITY_TYPES
    )
    assert result == (0, 1)
    assert client.deleted == []


def test_dry_run_deletes_nothing():
    client = FakeClient(labels={"e1": [LABEL]}, ref_counts={"e1": (0, 0)})
    sink, log = logs()
    result = pipeline.purge_created(
        client, [erow(), crow()], log, dry_run=True, label=LABEL, entity_types=ENTITY_TYPES
    )
    assert result == (1, 0)
    assert client.deleted == []
    assert any("WaterPlum" in line for line in sink)


def test_dry_run_predicts_what_the_real_revert_will_do():
    """A dry run must not under-report destruction.

    revert_containment --dry-run does not strip objectRefs, so the container
    count still includes this run's own. Without discounting them the dry
    run reports "would delete 0" and the real revert then deletes 1.
    """
    client = FakeClient(labels={"e1": [LABEL]}, ref_counts={"e1": (0, 1)})
    _, log = logs()
    result = pipeline.purge_created(
        client, [erow(), crow()], log, dry_run=True, label=LABEL, entity_types=ENTITY_TYPES
    )
    assert result == (1, 0)
    assert client.deleted == []


def test_dry_run_still_keeps_what_another_report_references():
    """Discounting our own refs must not blind us to somebody else's.

    Two containers, one of them ours: the entity survives the real revert,
    so the dry run must say so.
    """
    client = FakeClient(labels={"e1": [LABEL]}, ref_counts={"e1": (0, 2)})
    _, log = logs()
    result = pipeline.purge_created(
        client, [erow(), crow()], log, dry_run=True, label=LABEL, entity_types=ENTITY_TYPES
    )
    assert result == (0, 1)
    assert client.deleted == []


def test_apply_stamps_the_created_flag_onto_the_ledger():
    """apply_containment() must copy create_missing's marker, or
    purge_created has nothing to filter on -- the defect a live end-to-end
    run caught upstream."""
    cfg = Config()
    minted = item(entity_id="e1", entity_name="WaterPlum", created=True)
    ordinary = item(report_id="r2", entity_id="e2", entity_name="SaltTyphoon", created=False)
    _, log = logs()
    rows = pipeline.apply_containment(None, [minted, ordinary], log, ACTOR, cfg, dry_run=True)  # type: ignore[arg-type]
    by_entity = {r["entity_id"]: r for r in rows if r["kind"] == "containment"}
    assert by_entity["e1"]["created"] is True
    assert by_entity["e2"]["created"] is False
