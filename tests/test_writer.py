"""Ported from opencti-docker/tests/test_rel_writer.py's apply/revert halves.

merge_ledger/ledger_key/ledger_row/should_delete unit coverage moved to
octirb/ledger.py in Task 5 (see tests/test_ledger.py) and is not re-ported
here. Tests that exercised the "ledger" relationship source are dropped --
octi-rb's actor-target linker has no ledger source (see SOURCES in
octirb/linkers/actor_target.py).
"""

import pytest

from octirb import writer
from octirb.ledger import merge_ledger, relationship_row
from octirb.writer import ApplyContext

LABEL = "AI-Relationship"


def item(**over):
    base = {"actor_id": "a1", "actor": "APT29", "relationship_type": "targets",
            "target_kind": "country", "target_id": "c1", "target_name": "Ukraine",
            "confidence": "high", "evidence": "q", "source": "report", "source_refs": ["r1", "r2"]}
    base.update(over)
    return base


class Fake:
    def __init__(self, existing=None, state=None):
        self.existing = existing or {}
        self.state = state or {}
        self.created, self.added, self.removed, self.deleted = [], [], [], []
        self.calls = []  # one ordered log across every mutating method, tagged by kind

    def find_relationships(self, f, t, r):
        return self.existing.get((f, t, r), [])

    def create_relationship(self, f, t, r, conf, desc, label):  # noqa: PLR0913,PLR0917 - mirrors Client
        self.created.append((f, t, r, conf, desc, label))
        rid = f"rel-{len(self.created)}"
        self.existing[(f, t, r)] = [rid]
        self.state[rid] = (True, [LABEL])
        self.calls.append(("create", rid))
        return rid

    def add_object_to_report(self, report, obj):
        self.added.append((report, obj))
        self.calls.append(("add", report, obj))

    def remove_object_from_report(self, report, obj):
        self.removed.append((report, obj))
        self.calls.append(("remove", report, obj))

    def relationship_state(self, rid):
        return self.state.get(rid, (False, []))

    def delete_relationship(self, rid):
        self.deleted.append(rid)
        self.calls.append(("delete", rid))


def ctx(ours=None, dry=False, label=LABEL):
    return ApplyContext(label_id="lbl", label=label, ours=ours or {}, dry_run=dry, log=lambda _: None)


def test_creates_labels_and_adds_to_source_reports():
    fake, saved = Fake(), []
    rows = writer.apply_items(fake, [item()], ctx(), saved.append)
    assert fake.created == [("a1", "c1", "targets", 85, '"q" — octi-rel, source: report', "lbl")]
    assert fake.added == [("r1", "rel-1"), ("r2", "rel-1")]
    assert rows[0]["preexisted"] is False
    assert rows[0]["in_reports"] == ["r1", "r2"]
    # saved after the write, not only at the end -- and, since apply now
    # checkpoints (create, then each added report), more than once per item.
    assert len(saved) > 1
    assert saved[-1] == rows


def test_description_source_is_not_added_to_any_report():
    fake = Fake()
    rows = writer.apply_items(fake, [item(source="description", source_refs=["a1"])], ctx(), lambda _: None)
    assert fake.added == []
    assert rows[0]["in_reports"] == []


def test_preexisting_relationship_is_left_untouched():
    fake = Fake(existing={("a1", "c1", "targets"): ["feed-rel"]})
    rows = writer.apply_items(fake, [item()], ctx(), lambda _: None)
    assert fake.created == []
    assert fake.added == []
    assert rows[0]["preexisted"] is True
    assert rows[0]["relationship_id"] == "feed-rel"


def test_dry_run_writes_nothing_and_saves_nothing():
    fake, saved = Fake(), []
    rows = writer.apply_items(fake, [item()], ctx(dry=True), saved.append)
    assert fake.created == []
    assert fake.added == []
    assert saved == []
    assert rows[0]["relationship_id"] == "(dry-run)"


def test_reapply_keeps_ownership():
    fake = Fake()
    first = writer.apply_items(fake, [item(source_refs=["r1"])], ctx(), lambda _: None)
    ours = {first[0]["relationship_id"]: first[0]["in_reports"]}
    second = writer.apply_items(fake, [item(source_refs=["r1", "r3"])], ctx(ours=ours), lambda _: None)
    assert second[0]["preexisted"] is False
    assert fake.added == [("r1", "rel-1"), ("r3", "rel-1")]  # only the new report
    merged = merge_ledger(first, second)
    assert len(merged) == 1
    assert merged[0]["preexisted"] is False
    assert merged[0]["in_reports"] == ["r1", "r3"]
    assert merged[0]["source_refs"] == ["r1", "r3"]


def test_recreated_relationship_is_revertable_after_merge():
    """Mirrors the repro: apply creates rel-1; rel-1 disappears from the
    platform (deleted directly, or a revert that died partway); re-apply
    creates rel-2 and links it to the source report. The merged ledger
    must point revert at rel-2, not the vanished rel-1 -- otherwise revert
    reports "already gone" while rel-2 is permanently orphaned."""
    fake = Fake()
    first = writer.apply_items(fake, [item(source_refs=["r1"])], ctx(), lambda _: None)
    assert first[0]["relationship_id"] == "rel-1"

    # rel-1 vanishes from the platform.
    fake.existing.clear()
    del fake.state["rel-1"]

    second = writer.apply_items(fake, [item(source_refs=["r1"])], ctx(ours={}), lambda _: None)
    assert second[0]["relationship_id"] == "rel-2"

    merged = merge_ledger(first, second)
    assert len(merged) == 1
    assert merged[0]["relationship_id"] == "rel-2"
    assert merged[0]["preexisted"] is False

    deleted, kept = writer.revert(fake, merged, ctx())
    assert (deleted, kept) == (1, 0)
    assert fake.deleted == ["rel-2"]


def _row(rid, preexisted=False, in_reports=("r1",)):
    return relationship_row(item(), relationship_id=rid, preexisted=preexisted,
                            in_reports=list(in_reports), label_id="l")


def test_revert_deletes_ours_and_removes_refs_first():
    fake = Fake(state={"rel-1": (True, [LABEL])})
    deleted, kept = writer.revert(fake, [_row("rel-1")], ctx())
    assert (deleted, kept) == (1, 0)
    assert fake.removed == [("r1", "rel-1")]
    assert fake.deleted == ["rel-1"]
    assert fake.calls.index(("remove", "r1", "rel-1")) < fake.calls.index(("delete", "rel-1"))


def test_revert_never_touches_preexisting():
    fake = Fake(state={"feed": (True, [])})
    assert writer.revert(fake, [_row("feed", preexisted=True, in_reports=())], ctx()) == (0, 1)
    assert fake.deleted == []


def test_revert_skips_vanished_relationship():
    fake = Fake(state={})
    assert writer.revert(fake, [_row("gone")], ctx()) == (0, 1)
    assert fake.removed == []
    assert fake.deleted == []


def test_revert_dry_run_matches_real_decisions():
    rows = [_row("rel-1"), _row("feed", preexisted=True), _row("adopted")]
    state = {"rel-1": (True, [LABEL]), "feed": (True, []), "adopted": (True, [])}
    dry = Fake(state=dict(state))
    real = Fake(state=dict(state))
    assert writer.revert(dry, rows, ctx(dry=True)) == writer.revert(real, rows, ctx(dry=False))
    assert dry.deleted == []
    assert dry.removed == []


# -- two-check-rule coverage: inputs/invariants the brief's floor did not test --


def test_add_to_reports_rejects_empty_relationship_id():
    fake = Fake()
    with pytest.raises(ValueError, match="relationship id"):
        writer._add_to_reports(fake, item(), "", [], ctx())


def test_apply_one_rejects_item_missing_key_fields():
    fake = Fake()
    with pytest.raises(ValueError, match="actor_id"):
        writer.apply_items(fake, [item(actor_id="")], ctx(), lambda _: None)


def test_revert_rejects_non_list_rows():
    fake = Fake()
    with pytest.raises(TypeError):
        writer.revert(fake, "not-a-list", ctx())  # type: ignore[arg-type]


def test_decide_reverts_rejects_non_list_rows():
    fake = Fake()
    with pytest.raises(TypeError):
        writer.decide_reverts(fake, "not-a-list", LABEL)  # type: ignore[arg-type]


def test_decide_reverts_rejects_empty_label():
    fake = Fake()
    with pytest.raises(ValueError, match="label"):
        writer.decide_reverts(fake, [], "")


# -- review round 1 --


class FlakyAddFake(Fake):
    """add_object_to_report succeeds on its first call, raises on its
    second, then behaves normally again -- simulates a platform write
    failing right after create_relationship has already committed."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._add_calls = 0

    def add_object_to_report(self, report, obj):
        self._add_calls += 1
        if self._add_calls == 2:
            raise RuntimeError("boom")
        super().add_object_to_report(report, obj)


def test_partial_failure_after_create_checkpoints_progress():
    fake = FlakyAddFake()
    saved = []
    with pytest.raises(RuntimeError, match="boom"):
        writer.apply_items(fake, [item(source_refs=["r1", "r2"])], ctx(), saved.append)

    # The failure happened on the 2nd add, so only r1 made it onto the
    # platform, and the relationship itself was never orphaned: the last
    # checkpoint before the exception recorded it with what did land.
    assert fake.added == [("r1", "rel-1")]
    last = saved[-1]
    assert len(last) == 1
    assert last[0]["relationship_id"] == "rel-1"
    assert last[0]["preexisted"] is False
    assert last[0]["in_reports"] == ["r1"]

    # Re-apply, built from that saved (partial) ledger: the relationship is
    # still ours (preexisted stays False), and only the missing report is added.
    ours = {last[0]["relationship_id"]: last[0]["in_reports"]}
    second = writer.apply_items(fake, [item(source_refs=["r1", "r2"])], ctx(ours=ours), lambda _: None)
    assert second[0]["preexisted"] is False
    assert fake.added == [("r1", "rel-1"), ("r2", "rel-1")]


def test_medium_confidence_maps_to_50():
    fake = Fake()
    writer.apply_items(fake, [item(confidence="medium")], ctx(), lambda _: None)
    assert fake.created[0][3] == 50


def test_low_confidence_maps_to_15():
    fake = Fake()
    writer.apply_items(fake, [item(confidence="low")], ctx(), lambda _: None)
    assert fake.created[0][3] == 15


def test_revert_logs_already_gone_for_vanished_relationship():
    fake = Fake(state={})
    logs = []
    writer.revert(fake, [_row("gone")], ApplyContext(label_id="lbl", label=LABEL, ours={},
                                                      dry_run=False, log=logs.append))
    assert any("already gone" in line for line in logs)


def test_revert_removes_refs_for_adopted_row_without_deleting():
    """An adopted row (label removed, so should_delete keeps it) must still
    lose the report refs octi-rel added -- only the delete is skipped."""
    fake = Fake(state={"adopted": (True, [])})
    row = _row("adopted", in_reports=("r1", "r2"))
    deleted, kept = writer.revert(fake, [row], ctx())
    assert (deleted, kept) == (0, 1)
    assert fake.removed == [("r1", "adopted"), ("r2", "adopted")]
    assert fake.deleted == []


def test_revert_removes_all_refs_before_any_delete_across_the_batch():
    fake = Fake(state={"rel-1": (True, [LABEL]), "adopted": (True, [])})
    rows = [_row("adopted", in_reports=("rA",)), _row("rel-1", in_reports=("rB",))]
    writer.revert(fake, rows, ctx())
    remove_positions = [i for i, c in enumerate(fake.calls) if c[0] == "remove"]
    delete_positions = [i for i, c in enumerate(fake.calls) if c[0] == "delete"]
    assert remove_positions and delete_positions
    assert max(remove_positions) < min(delete_positions)


def test_revert_dry_run_removes_no_refs_for_adopted_row_either():
    fake = Fake(state={"adopted": (True, [])})
    row = _row("adopted", in_reports=("r1",))
    writer.revert(fake, [row], ctx(dry=True))
    assert fake.removed == []


def test_second_item_same_key_in_one_call_is_treated_as_ours():
    fake = Fake()
    rows = writer.apply_items(fake, [item(), item()], ctx(), lambda _: None)
    assert len(fake.created) == 1  # created once, not twice
    assert rows[0]["preexisted"] is False
    assert rows[1]["preexisted"] is False
    assert rows[1]["relationship_id"] == rows[0]["relationship_id"]


# -- review round 2: row "status" separates created / ours / preexisting --


def test_apply_items_tags_status_created_and_preexisting():
    fake = Fake(existing={("a1", "c-old", "targets"): ["feed-rel"]})
    rows = writer.apply_items(
        fake, [item(), item(target_id="c-old")], ctx(), lambda _: None)
    assert rows[0]["status"] == "created"
    assert rows[1]["status"] == "preexisting"


def test_apply_items_tags_status_ours_on_reapply():
    fake = Fake()
    first = writer.apply_items(fake, [item()], ctx(), lambda _: None)
    assert first[0]["status"] == "created"
    ours = {first[0]["relationship_id"]: first[0]["in_reports"]}
    second = writer.apply_items(fake, [item()], ctx(ours=ours), lambda _: None)
    assert second[0]["status"] == "ours"
