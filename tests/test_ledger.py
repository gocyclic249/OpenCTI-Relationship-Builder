import pytest

from octirb.ledger import (
    alias_row,
    containment_row,
    entity_row,
    label_row,
    merge_ledger,
    relationship_row,
    row_key,
    should_delete_entity,
    should_delete_relationship,
)

# -- ported from opencti-docker/tests/test_rel_writer.py: merge_ledger /
# -- _merge_pair / ledger_key coverage (apply/revert tests are a later task) --


def rel(**over):
    """Build a relationship row from item + row-level defaults, both
    overridable by keyword -- mirrors upstream's `item(**over)` plus the
    ledger_row kwargs it always passed alongside it."""
    item = {
        "actor_id": "a1", "actor": "APT29", "relationship_type": "targets",
        "target_kind": "country", "target_id": "c1", "target_name": "Ukraine",
        "confidence": "high", "evidence": "q", "source": "prose", "source_refs": ["r1", "r2"],
    }
    row_kwargs = {
        "relationship_id": "x", "preexisted": False, "in_reports": [], "label_id": "l", "status": "",
    }
    for key, value in over.items():
        if key in row_kwargs:
            row_kwargs[key] = value
        else:
            item[key] = value
    return relationship_row(item, **row_kwargs)


def test_relationship_row_always_stamps_preexisted():
    row = rel(relationship_id="x", preexisted=False, in_reports=[], label_id="l")
    assert "preexisted" in row
    assert row["preexisted"] is False
    assert row["confidence"] == "high"
    assert row["kind"] == "relationship"


def test_merge_keeps_prior_ownership_even_if_fresh_says_preexisted():
    prior = [rel(relationship_id="x", preexisted=False, in_reports=["r1"], label_id="l")]
    fresh = [rel(relationship_id="x", preexisted=True, in_reports=[], label_id="l")]
    assert merge_ledger(prior, fresh)[0]["preexisted"] is False


def test_merge_replaces_prior_when_relationship_id_differs():
    """Controller ruling: the prior row wins only when both rows carry the
    SAME relationship_id. When the ids differ -- the prior relationship
    vanished from the platform and re-apply created a new one -- the fresh
    row replaces the prior one: source_refs union, but in_reports comes
    from the fresh row alone (the prior relationship's refs describe an
    object that no longer exists)."""
    prior = [rel(source_refs=["r1"], relationship_id="rel-1", preexisted=False,
                 in_reports=["r1"], label_id="l")]
    fresh = [rel(source_refs=["r2"], relationship_id="rel-2", preexisted=False,
                 in_reports=["r2"], label_id="l")]
    merged = merge_ledger(prior, fresh)
    assert len(merged) == 1
    row = merged[0]
    assert row["relationship_id"] == "rel-2"
    assert row["preexisted"] is False
    assert sorted(row["source_refs"]) == ["r1", "r2"]
    assert row["in_reports"] == ["r2"]


@pytest.mark.parametrize(("preexisted", "exists", "labelled", "expected"), [
    (False, True, True, True),
    (True, True, True, False),
    (False, False, True, False),
    (False, True, False, False),
])
def test_should_delete_relationship(preexisted, exists, labelled, expected):
    result = should_delete_relationship(
        preexisted=preexisted, exists=exists, labelled=labelled, label="octi-rel",
    )
    assert result[0] is expected


def test_row_key_rejects_non_dict():
    with pytest.raises(TypeError):
        row_key("not-a-row")  # type: ignore[arg-type]


def test_should_delete_relationship_rejects_non_bool_labelled():
    with pytest.raises(TypeError):
        should_delete_relationship(preexisted=False, exists=True, labelled="yes", label="octi-rel")  # type: ignore[arg-type]


def test_merge_ledger_tolerates_rows_without_status():
    """An older ledger written before the status field existed must not
    make merge_ledger crash."""
    prior_row = rel(relationship_id="x", preexisted=False, in_reports=[], label_id="l", status="created")
    del prior_row["status"]
    fresh = [rel(relationship_id="x", preexisted=False, in_reports=["r1"], label_id="l", status="ours")]
    merged = merge_ledger([prior_row], fresh)
    assert len(merged) == 1


def test_merge_never_lets_a_preexisting_read_displace_an_owned_row():
    """find_relationships can miss an owned relationship (page cap, or a
    second same-key relationship) and return someone else's. Replacing the
    owned row would make ours unrevertable; keeping it costs nothing, since a
    genuinely vanished one reverts as "already gone"."""
    ours = rel(source_refs=["r1"], relationship_id="rel-ours",
               preexisted=False, in_reports=["r1"], label_id="l")
    feed = rel(source_refs=["r2"], relationship_id="rel-feed",
               preexisted=True, in_reports=[], label_id="l")
    merged = merge_ledger([ours], [feed])
    assert len(merged) == 1
    assert merged[0]["relationship_id"] == "rel-ours"
    assert merged[0]["preexisted"] is False
    assert merged[0]["in_reports"] == ["r1"]
    assert merged[0]["source_refs"] == ["r1", "r2"]


# -- ported from opencti-docker/tests/test_purge.py: pure should_delete coverage --


def test_deletes_only_when_fully_orphaned():
    assert should_delete_entity(labelled=True, relationships=0, containers=0) == (
        True, "orphaned",
    )


def test_keeps_when_no_longer_ours():
    ok, why = should_delete_entity(labelled=False, relationships=0, containers=0)
    assert ok is False
    assert "labelled" in why


def test_keeps_when_relationships_remain():
    assert should_delete_entity(labelled=True, relationships=3, containers=0) == (
        False, "3 relationship(s)",
    )


def test_keeps_when_still_in_a_container():
    assert should_delete_entity(labelled=True, relationships=0, containers=2) == (
        False, "still in 2 container(s)",
    )


def test_relationships_take_precedence_over_containers():
    """Both keep-conditions true at once -- the earlier check must win.

    Tested separately from the label case: without this, swapping the
    relationships and containers branches would fail no test.
    """
    assert should_delete_entity(labelled=True, relationships=3, containers=2) == (
        False, "3 relationship(s)",
    )


def test_label_check_takes_precedence():
    ok, why = should_delete_entity(labelled=False, relationships=9, containers=9)
    assert ok is False
    assert "labelled" in why


def test_negative_relationships_are_rejected():
    with pytest.raises(ValueError, match="negative"):
        should_delete_entity(labelled=True, relationships=-1, containers=0)


def test_negative_containers_are_rejected():
    """The other half of the guard.

    If a regression dropped this half of the `or`, containers=-1 would reach
    the `containers > 0` check, be False, and return (True, "orphaned") --
    authorising a permanent deletion on nonsense input.
    """
    with pytest.raises(ValueError, match="negative"):
        should_delete_entity(labelled=True, relationships=0, containers=-1)


# -- new-kind coverage: containment_row/alias_row/entity_row own required-field
# -- validation, not exercised by anything ported above --


def test_containment_row_requires_report_id():
    with pytest.raises(ValueError):
        containment_row(
            report_id="", entity_id="e1", entity_name="France", linker="report-location",
            key="FRA", role="target", confidence="high", evidence="q", label_id=None, created=False,
        )


def test_entity_row_requires_entity_id():
    with pytest.raises(ValueError):
        entity_row(entity_id="", entity_type="Country", name="France")


# -- new-kind tests (brief step 2) --


def crow(report="r1", entity="e1"):
    return containment_row(
        report_id=report, entity_id=entity, entity_name="France", linker="report-location",
        key="FRA", role="target", confidence="high", evidence="q", label_id=None, created=False,
    )


def test_containment_dedupes_prior_wins():
    a, b = crow(), crow()
    b["evidence"] = "different"
    merged = merge_ledger([a], [b])
    assert len(merged) == 1 and merged[0]["evidence"] == "q"


def test_mixed_kinds_survive_merge():
    rows = [crow(), alias_row(entity_id="e1", entity_name="APT29", alias="UNC1",
                              preexisted=False, evidence="q")]
    merged = merge_ledger(rows, [])
    assert {r["kind"] for r in merged} == {"containment", "alias"}


def test_row_key_unknown_kind_raises():
    with pytest.raises(ValueError):
        row_key({"kind": "mystery"})


def test_alias_row_requires_alias():
    with pytest.raises(ValueError):
        alias_row(entity_id="e1", entity_name="x", alias="", preexisted=False, evidence="q")


def lab(**over):
    base = {"report_id": "r1", "label": "China", "label_id": "L1", "source": "country",
            "source_entity": "China", "preexisted": False}
    base.update(over)
    return label_row(**base)


def test_label_row_key_is_casefolded_label():
    assert row_key(lab()) == ("label", "r1", "china")
    assert row_key(lab(label="CHINA")) == row_key(lab())


def test_label_row_rejects_bad_source_and_missing_fields():
    with pytest.raises(ValueError):
        lab(source="region")
    with pytest.raises(ValueError):
        lab(label="")
    with pytest.raises(ValueError):
        lab(report_id="")


def test_label_row_allows_null_label_id_when_preexisted():
    row = lab(label_id=None, preexisted=True)
    assert row["label_id"] is None and row["preexisted"] is True


def test_merge_keeps_prior_owned_label_over_fresh_preexisted():
    """Review Focus 4: a re-apply after a crash sees our own label already on
    the report and stamps it preexisted; the prior (owned) row must win or
    revert would never remove it."""
    prior = [lab(label_id="L1", preexisted=False)]
    fresh = [lab(label_id=None, preexisted=True)]
    merged = merge_ledger(prior, fresh)
    assert merged == prior
