# report-labels Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic `report-labels` linker that labels every report with the plain names of its contained Countries and the top-level roots of its contained Sectors.

**Architecture:** A new module `octirb/linkers/report_labels.py` owns select/batch/validate/apply/revert for the linker, the way `actor_target.py` owns its flow. It runs through the existing run pipeline (`select → batch → validate → apply → revert`), writes a new `kind: "label"` ledger row, and reuses the existing checkpoint/merge/revert machinery. Three small client reads and one config table support it.

**Tech Stack:** Python 3.11+ standard library only; pytest; ruff; mypy --strict.

**Spec:** `docs/superpowers/specs/2026-09-30-report-labels-design.md`

## Global Constraints

- Zero runtime dependencies — stdlib only (`urllib`, `tomllib`). No `pycti`, no `requests`.
- Labels carry **no** `[labels].prefix` — the value is the Country name or the root Sector name verbatim.
- Label comparisons (already-on-report, find-existing, dedupe) are **casefolded**; the platform preserves case.
- Add-only: nothing but `revert` removes a label, and only rows with `preexisted: false`. Label objects are never deleted.
- Dry-run performs zero platform writes (reads are allowed).
- Checkpoint `applied.json` after every successful label write.
- No `AI-Labels` marker label is added.
- Every function ≤ 60 lines, every loop bounded, ≥ 2 raising checks per function (input + invariant/post-condition); `raise`, never bare `assert`, in `octirb/`.
- Diagnostics to stderr (`log`), data to stdout. `noqa` only with `- reason`.
- Gate after every task: `ruff check octirb/ tests/ contrib/`, `mypy --strict octirb/`, `pytest -q` — all clean.

## Review Focus

1. **A label already on the report in different case** (`china` on the report, Country `China`) → no second label, nothing written. Pinned in Task 4 (`labels_for`) and Task 6 (`apply_labels`).
2. **A label object already on the platform in different case** (platform has `ics`, we want `ICS`) → reuse it, never create a near-duplicate. Pinned in Task 3 (`find_label`) and Task 6 (`_label_id` prefers `find_label`).
3. **A sector whose parent is not visible** (parent id missing from `sector_parents()`) → the sector counts as its own root, not an error. Pinned in Task 4.
4. **Re-running `apply` after a mid-run crash**, when the first run's labels are now on the report → fresh rows say `preexisted: true`, but `merge_ledger` keeps the prior row, so revert still removes what the first run wrote. Pinned in Task 2 (merge test).
5. **A report deleted between `select` and `batch`** → logged and skipped; the other reports still get their labels. Pinned in Task 5.

---

### Task 1: `[report_labels]` config table

**Files:**
- Modify: `octirb/config.py` (constants block ~line 23-36; dataclasses ~line 95-114; `SCHEMA` ~line 184-210; builders ~line 318-338)
- Modify: `config.example.toml` (append a table after `[vulns]`)
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `ReportLabelsCfg(enabled: bool = True, color: str = "#5b6abf")`; `Config.report_labels: ReportLabelsCfg`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_config.py`)

```python
def test_report_labels_defaults(tmp_path, monkeypatch):
    monkeypatch.delenv("OCTI_RB_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    cfg = load_config(None)
    assert cfg.report_labels.enabled is True
    assert cfg.report_labels.color == "#5b6abf"


def test_report_labels_parsed(tmp_path):
    p = write(tmp_path, '[report_labels]\nenabled = false\ncolor = "#AABBCC"\n')
    cfg = load_config(p)
    assert cfg.report_labels.enabled is False
    assert cfg.report_labels.color == "#AABBCC"


def test_report_labels_bad_color_rejected(tmp_path):
    p = write(tmp_path, '[report_labels]\ncolor = "blue"\n')
    with pytest.raises(SystemExit, match=r"\[report_labels\]\.color"):
        load_config(p)


def test_report_labels_unknown_key_rejected(tmp_path):
    p = write(tmp_path, "[report_labels]\nprefix = 'x'\n")
    with pytest.raises(SystemExit, match="prefix"):
        load_config(p)
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_config.py -q -k report_labels`
Expected: FAIL — `AttributeError: 'Config' object has no attribute 'report_labels'` / unknown section.

- [ ] **Step 3: Implement**

In `octirb/config.py`, add to the constants block:

```python
HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
```

After `VulnsCfg`:

```python
@dataclass(frozen=True)
class ReportLabelsCfg:
    enabled: bool = True
    color: str = "#5b6abf"
```

In `Config`, after `vulns`:

```python
    report_labels: ReportLabelsCfg = field(default_factory=ReportLabelsCfg)
```

In `SCHEMA`, after `"vulns"`:

```python
    "report_labels": {"enabled": bool, "color": str},
```

After `_build_labels`:

```python
def _build_report_labels(table: dict[str, Any]) -> ReportLabelsCfg:
    cfg = ReportLabelsCfg(**table)
    if not HEX_COLOR_RE.match(cfg.color):
        raise SystemExit(f"config: [report_labels].color must be #RRGGBB (got {cfg.color!r})")
    return cfg
```

In `_build_config`, after `vulns=...`:

```python
        report_labels=_build_report_labels(data.get("report_labels", {})),
```

Append to `config.example.toml`:

```toml

[report_labels]
enabled = true                         # allow select --linker report-labels
color = "#5b6abf"                      # #RRGGBB for country/sector value labels this tool creates
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_config.py -q` then `ruff check octirb/ tests/` and `mypy --strict octirb/`
Expected: all PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add octirb/config.py config.example.toml tests/test_config.py
git commit -m "feat(config): add [report_labels] table"
```

---

### Task 2: `label` ledger row

**Files:**
- Modify: `octirb/ledger.py` (new `LABEL_SOURCES`, `label_row` after `entity_row`; `row_key` branch; `merge_ledger` docstring)
- Test: `tests/test_ledger.py`

**Interfaces:**
- Produces:
  - `LABEL_SOURCES: frozenset[str] = frozenset({"country", "sector"})`
  - `label_row(*, report_id: str, label: str, label_id: str | None, source: str, source_entity: str, preexisted: bool) -> JsonDict` — row fields: `kind="label"`, `report_id`, `label`, `label_id`, `source`, `source_entity`, `preexisted`.
  - `row_key(label row) == ("label", report_id, label.casefold())`

- [ ] **Step 1: Write the failing tests** (append to `tests/test_ledger.py`; add `label_row` to the import list)

```python
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
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_ledger.py -q -k label`
Expected: FAIL — `ImportError: cannot import name 'label_row'`.

- [ ] **Step 3: Implement** in `octirb/ledger.py`

After `entity_row`:

```python
LABEL_SOURCES = frozenset({"country", "sector"})


def label_row(  # noqa: PLR0913 - named ledger fields, not a data clump
    *, report_id: str, label: str, label_id: str | None, source: str, source_entity: str,
    preexisted: bool,
) -> JsonDict:
    """A report-carries-label row (report-labels linker).

    `label_id` is None when nothing was written (the label pre-existed on the
    report). The key is the casefolded label, not the id: pre-existence is
    decided by value, and a preexisted row has no id to key on.
    """
    if not report_id or not label:
        raise ValueError("label row needs report_id and label")
    if source not in LABEL_SOURCES:
        raise ValueError(f"label row source must be one of {sorted(LABEL_SOURCES)} (got {source!r})")
    row: JsonDict = {
        "kind": "label", "report_id": report_id, "label": label, "label_id": label_id,
        "source": source, "source_entity": source_entity, "preexisted": bool(preexisted),
    }
    row_key(row)
    return row
```

In `row_key`, add to the docstring `label -> ("label", report_id, label casefolded)` and add the branch before `else`:

```python
    elif kind == "label":
        key = ("label", str(row["report_id"]), str(row["label"]).casefold())
```

In `merge_ledger`'s docstring change "across all four row kinds" to "across all five row kinds" and "Containment, alias and entity rows" to "Containment, alias, entity and label rows".

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_ledger.py -q` then `ruff check octirb/ tests/` and `mypy --strict octirb/`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add octirb/ledger.py tests/test_ledger.py
git commit -m "feat(ledger): add label row kind"
```

---

### Task 3: client reads — `report_label_sources`, `sector_parents`, `find_label`

**Files:**
- Modify: `octirb/client.py` (module-level query constants next to `REPORT_OBJECT_IDS_Q` ~line 110; methods after `report_object_ids` ~line 266 and after `entity_labels` ~line 333)
- Test: `tests/test_client.py`

**Interfaces:**
- Produces:
  - `Client.report_label_sources(report_id: str) -> JsonDict` returning `{"id": str, "name": str, "labels": list[str], "countries": list[{"id","name"}], "sectors": list[{"id","name"}]}`; raises `OpenCTIError` on missing report or page cap.
  - `Client.sector_parents() -> list[JsonDict]` returning `[{"id": str, "name": str, "parent_ids": list[str]}]`.
  - `Client.find_label(value: str) -> str | None` — id of the label equal to `value` ignoring case (exact case preferred), else `None`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_client.py`)

```python
# -- report-labels reads ---------------------------------------------------------


def _obj_page(edges, *, more, cursor=None, labels=("china",)):
    return {"report": {
        "id": "r1", "name": "Report One",
        "objectLabel": [{"value": v} for v in labels],
        "objects": {"pageInfo": {"endCursor": cursor, "hasNextPage": more}, "edges": edges},
    }}


def test_report_label_sources_splits_countries_and_sectors_across_pages(fake_gql_client):
    client, _calls = fake_gql_client({})
    pages = iter([
        _obj_page([{"node": {"id": "c1", "name": "China", "entity_type": "Country"}},
                   {"node": {}}], more=True, cursor="k1"),
        _obj_page([{"node": {"id": "s1", "name": "Electricity", "entity_type": "Sector"}},
                   {"node": None}], more=False),
    ])
    sent = []

    def paged(_query, variables=None):
        sent.append(variables)
        return next(pages)

    client.gql = paged
    got = client.report_label_sources("r1")
    assert got == {
        "id": "r1", "name": "Report One", "labels": ["china"],
        "countries": [{"id": "c1", "name": "China"}],
        "sectors": [{"id": "s1", "name": "Electricity"}],
    }
    assert sent == [{"id": "r1", "after": None}, {"id": "r1", "after": "k1"}]


def test_report_label_sources_missing_report_raises(fake_gql_client):
    client, _calls = fake_gql_client({"report": None})
    with pytest.raises(OpenCTIError, match="not found"):
        client.report_label_sources("r1")


def test_report_label_sources_needs_an_id(fake_gql_client):
    client, _calls = fake_gql_client({})
    with pytest.raises(OpenCTIError):
        client.report_label_sources("")


def test_sector_parents_shape(fake_gql_client):
    client, _calls = fake_gql_client({"sectors": {
        "pageInfo": {"endCursor": None, "hasNextPage": False},
        "edges": [
            {"node": {"id": "s1", "name": "Electricity",
                      "parentSectors": {"edges": [{"node": {"id": "s0"}}]}}},
            {"node": {"id": "s0", "name": "Energy", "parentSectors": {"edges": []}}},
        ],
    }})
    assert client.sector_parents() == [
        {"id": "s1", "name": "Electricity", "parent_ids": ["s0"]},
        {"id": "s0", "name": "Energy", "parent_ids": []},
    ]


def test_find_label_prefers_exact_then_casefold(fake_gql_client):
    client, _calls = fake_gql_client({"labels": {"edges": [
        {"node": {"id": "L-lower", "value": "ics"}},
        {"node": {"id": "L-exact", "value": "ICS"}},
    ]}})
    assert client.find_label("ICS") == "L-exact"
    assert client.find_label("Ics") == "L-lower"


def test_find_label_absent_and_substring_only(fake_gql_client):
    client, _calls = fake_gql_client({"labels": {"edges": [
        {"node": {"id": "L1", "value": "octi-geo-ics"}},
    ]}})
    assert client.find_label("ICS") is None


def test_find_label_needs_a_value(fake_gql_client):
    client, _calls = fake_gql_client({})
    with pytest.raises(OpenCTIError):
        client.find_label("  ")
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_client.py -q -k "label_sources or sector_parents or find_label"`
Expected: FAIL — `AttributeError: 'Client' object has no attribute 'report_label_sources'`.

- [ ] **Step 3: Implement** in `octirb/client.py`

After `REPORT_OBJECT_IDS_Q`:

```python
REPORT_LABEL_SOURCES_Q = """query($id: String!, $after: ID) { report(id: $id) {
  id name
  objectLabel { value }
  objects(first: 500, after: $after, types: ["Country", "Sector"]) {
    pageInfo { endCursor hasNextPage }
    edges { node {
      ... on Country { id name entity_type }
      ... on Sector { id name entity_type }
    } }
  } } }"""

SECTOR_PARENTS_Q = """query($after: ID) { sectors(first: 500, after: $after) {
  pageInfo { endCursor hasNextPage }
  edges { node { id name parentSectors { edges { node { id } } } } }
} }"""

FIND_LABEL_Q = """query($s: String) { labels(first: 100, search: $s) {
  edges { node { id value } } } }"""

LABEL_SOURCE_TYPES = frozenset({"Country", "Sector"})
```

After `report_object_ids`:

```python
    @staticmethod
    def _label_source_nodes(edges: list[JsonDict], out: dict[str, list[JsonDict]]) -> None:
        """Sort one page of Country/Sector object edges into `out`."""
        for edge in edges:
            node = edge.get("node") or {}
            kind = node.get("entity_type")
            if kind in LABEL_SOURCE_TYPES and node.get("id"):
                out[str(kind)].append({"id": str(node["id"]), "name": str(node.get("name") or "")})

    def report_label_sources(self, report_id: str) -> JsonDict:
        """A report's contained Countries and Sectors, plus its label values.

        Paginated to the end: a truncated read would miss a country and, worse
        for apply, report a label as absent.
        """
        if not report_id:
            raise OpenCTIError("report_label_sources() needs a report id")
        found: dict[str, list[JsonDict]] = {"Country": [], "Sector": []}
        after: str | None = None
        for _page in range(MAX_PAGES):
            report = self.gql(REPORT_LABEL_SOURCES_Q, {"id": report_id, "after": after})["report"]
            if report is None:
                raise OpenCTIError(f"report {report_id} not found")
            conn = report["objects"]
            self._label_source_nodes(conn["edges"], found)
            if not conn["pageInfo"]["hasNextPage"]:
                return {
                    "id": report_id, "name": str(report.get("name") or ""),
                    "labels": [str(lab["value"]) for lab in (report.get("objectLabel") or [])],
                    "countries": found["Country"], "sectors": found["Sector"],
                }
            after = conn["pageInfo"]["endCursor"]
        raise OpenCTIError(f"report {report_id} objects exceeded {MAX_PAGES} pages")

    def sector_parents(self) -> list[JsonDict]:
        """Every platform sector (any author) with its parent sector ids."""
        rows = [
            {
                "id": str(n["id"]), "name": str(n["name"]),
                "parent_ids": [str(e["node"]["id"]) for e in (n.get("parentSectors") or {}).get("edges", [])],
            }
            for n in self.paginate(SECTOR_PARENTS_Q, "sectors")
        ]
        if any(not r["id"] for r in rows):
            raise OpenCTIError("sector_parents: a sector came back without an id")
        return rows
```

After `entity_labels`:

```python
    def find_label(self, value: str) -> str | None:
        """Id of the label equal to `value` ignoring case, exact case preferred.

        `labels(search:)` is a fuzzy match, so every hit is re-checked here --
        `octi-geo-ics` must not stand in for `ICS`.
        """
        if not value.strip():
            raise OpenCTIError("find_label() needs a value")
        nodes = [e["node"] for e in self.gql(FIND_LABEL_Q, {"s": value})["labels"]["edges"]]
        exact = [n for n in nodes if n["value"] == value]
        folded = [n for n in nodes if str(n["value"]).casefold() == value.casefold()]
        for node in [*exact, *folded]:
            return str(node["id"])
        return None
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_client.py -q` then `ruff check octirb/ tests/` and `mypy --strict octirb/`
Expected: PASS / clean. (If ruff flags the `for ... return` idiom as `RUF015`, replace it with `match = next(iter([*exact, *folded]), None)` and `return None if match is None else str(match["id"])`.)

- [ ] **Step 5: Commit**

```bash
git add octirb/client.py tests/test_client.py
git commit -m "feat(client): report label sources, sector parents, casefold label lookup"
```

---

### Task 4: pure core — sector root walk and `labels_for`

**Files:**
- Create: `octirb/linkers/report_labels.py`
- Test: `tests/test_report_labels.py` (new)

**Interfaces:**
- Consumes: `client.sector_parents()` row shape and `client.report_label_sources()` dict shape (Task 3).
- Produces:
  - `SectorNode(id: str, name: str, parent_ids: tuple[str, ...])` (frozen dataclass)
  - `build_sector_index(nodes: list[JsonDict]) -> dict[str, SectorNode]`
  - `sector_roots(index: dict[str, SectorNode], sector_id: str) -> list[str]` — sorted root names; `ValueError` on unknown id / no root / bound.
  - `start_ids(index: dict[str, SectorNode], sector_id: str, aliases: dict[str, str]) -> list[str]` — `aliases` keys already casefolded.
  - `labels_for(report: JsonDict, index: dict[str, SectorNode], aliases: dict[str, str], log: Log) -> list[JsonDict]` — extraction dicts `{"report_id","report_name","label","from","source_entity","confidence": "high"}`.
  - `Log = Callable[[str], None]`

- [ ] **Step 1: Write the failing tests** — create `tests/test_report_labels.py`

```python
"""report-labels linker: sector root walk, label derivation, select/batch,
validate, apply and revert -- all against hand-written fakes, no network."""

from __future__ import annotations

from typing import Any

import pytest

from octirb.linkers.report_labels import (
    build_sector_index,
    labels_for,
    sector_roots,
    start_ids,
)

TREE = [
    {"id": "ics", "name": "ICS", "parent_ids": []},
    {"id": "energy", "name": "Energy", "parent_ids": []},
    {"id": "elec", "name": "Electricity", "parent_ids": ["energy", "ics"]},
    {"id": "grid", "name": "Grid operators", "parent_ids": ["elec"]},
    {"id": "orphan", "name": "Orphan", "parent_ids": ["hidden-parent"]},
    {"id": "dup", "name": "Energy & Utilities", "parent_ids": []},
    {"id": "cyc-a", "name": "A", "parent_ids": ["cyc-b"]},
    {"id": "cyc-b", "name": "B", "parent_ids": ["cyc-a"]},
]
INDEX = build_sector_index(TREE)


def logs() -> tuple[list[str], Any]:
    lines: list[str] = []
    return lines, lines.append


def report(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"id": "r1", "name": "Report One", "labels": [],
                            "countries": [], "sectors": []}
    base.update(over)
    return base


# -- sector_roots ----------------------------------------------------------------


def test_root_sector_is_its_own_root():
    assert sector_roots(INDEX, "ics") == ["ICS"]


def test_dual_parent_yields_every_root():
    assert sector_roots(INDEX, "grid") == ["Energy", "ICS"]


def test_invisible_parent_counts_as_root():
    """Review Focus 3."""
    assert sector_roots(INDEX, "orphan") == ["Orphan"]


def test_cycle_with_no_root_raises():
    with pytest.raises(ValueError, match="cycle"):
        sector_roots(INDEX, "cyc-a")


def test_unknown_sector_raises():
    with pytest.raises(ValueError, match="not on the platform"):
        sector_roots(INDEX, "nope")


# -- start_ids -------------------------------------------------------------------


def test_alias_redirects_walk_start():
    assert start_ids(INDEX, "dup", {"energy & utilities": "Energy"}) == ["energy"]


def test_no_alias_starts_at_sector():
    assert start_ids(INDEX, "grid", {}) == ["grid"]


def test_alias_target_missing_raises():
    with pytest.raises(ValueError, match="alias target"):
        start_ids(INDEX, "dup", {"energy & utilities": "Nope"})


# -- labels_for ------------------------------------------------------------------


def test_countries_and_sector_roots_become_labels():
    lines, log = logs()
    got = labels_for(report(countries=[{"id": "c1", "name": "United States"}],
                            sectors=[{"id": "grid", "name": "Grid operators"}]), INDEX, {}, log)
    assert [(e["label"], e["from"], e["source_entity"]) for e in got] == [
        ("United States", "country", "United States"),
        ("Energy", "sector", "Grid operators"),
        ("ICS", "sector", "Grid operators"),
    ]
    assert all(e["confidence"] == "high" and e["report_id"] == "r1" for e in got)
    assert lines == []


def test_existing_labels_dropped_casefolded():
    """Review Focus 1: `china` on the report already covers Country `China`."""
    _lines, log = logs()
    got = labels_for(report(labels=["china", "ics"], countries=[{"id": "c1", "name": "China"}],
                            sectors=[{"id": "elec", "name": "Electricity"}]), INDEX, {}, log)
    assert [e["label"] for e in got] == ["Energy"]


def test_shared_root_deduped():
    _lines, log = logs()
    got = labels_for(report(sectors=[{"id": "elec", "name": "Electricity"},
                                     {"id": "grid", "name": "Grid operators"}]), INDEX, {}, log)
    assert [e["label"] for e in got] == ["Energy", "ICS"]


def test_alias_applied_before_walk():
    _lines, log = logs()
    got = labels_for(report(sectors=[{"id": "dup", "name": "Energy & Utilities"}]),
                     INDEX, {"energy & utilities": "Energy"}, log)
    assert [e["label"] for e in got] == ["Energy"]


def test_bad_sector_logged_other_labels_kept():
    lines, log = logs()
    got = labels_for(report(countries=[{"id": "c1", "name": "Germany"}],
                            sectors=[{"id": "cyc-a", "name": "A"}]), INDEX, {}, log)
    assert [e["label"] for e in got] == ["Germany"]
    assert len(lines) == 1 and "cyc-a" in lines[0]


def test_nothing_to_add():
    _lines, log = logs()
    assert labels_for(report(), INDEX, {}, log) == []


def test_labels_for_rejects_non_report():
    _lines, log = logs()
    with pytest.raises(TypeError):
        labels_for({"name": "no id"}, INDEX, {}, log)
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_report_labels.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'octirb.linkers.report_labels'`.

- [ ] **Step 3: Implement** — create `octirb/linkers/report_labels.py`

```python
"""report-labels: plain value labels mirroring a report's countries and top-level sectors.

Every Country a report contains becomes a label of the same name; every
Sector it contains is walked up its parent sectors to each top-level root,
and each root's name becomes a label. These labels carry no `[labels].prefix`:
the `AI-*` labels record *how* octi-rb processed a report, these record *what
it is about*, for UI filtering and dashboards.

Deterministic, like report-vuln: `batch` writes extractions.json directly and
every extraction is confidence high. It drives from everything a report
contains, whoever added it, so it also backfills reports no other linker
touched. Add-only: nothing here removes a label except `revert_labels`, and
only labels its own run added.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..client import JsonDict

Log = Callable[[str], None]


@dataclass(frozen=True)
class SectorNode:
    id: str
    name: str
    parent_ids: tuple[str, ...]


def build_sector_index(nodes: list[JsonDict]) -> dict[str, SectorNode]:
    """`client.sector_parents()` rows -> {id: SectorNode}."""
    if not isinstance(nodes, list):
        raise TypeError("build_sector_index: nodes must be a list")
    index = {
        str(n["id"]): SectorNode(str(n["id"]), str(n["name"]), tuple(str(p) for p in n["parent_ids"]))
        for n in nodes
    }
    if len(index) > len(nodes):
        raise RuntimeError("build_sector_index invented a sector")
    return index


def sector_roots(index: dict[str, SectorNode], sector_id: str) -> list[str]:
    """Names of every top-level root above `sector_id`, sorted.

    Walks by id: same-named duplicate sectors from different authors exist.
    A sector with no parent in `index` -- none at all, or only parents this
    token cannot see -- is its own root. Dual-parented sectors yield every
    root. Raises ValueError for an unknown id, or when no root is reachable
    (a parent cycle).
    """
    if sector_id not in index:
        raise ValueError(f"sector {sector_id!r} is not on the platform")
    roots: set[str] = set()
    seen: set[str] = set()
    stack = [sector_id]
    # Bounded: each node expands once, so pushes total at most n*n.
    for _ in range(len(index) * len(index) + 1):
        if not stack:
            break
        node = index[stack.pop()]
        if node.id in seen:
            continue
        seen.add(node.id)
        parents = [p for p in node.parent_ids if p in index]
        if parents:
            stack.extend(parents)
        else:
            roots.add(node.name)
    if stack:
        raise ValueError(f"sector walk from {sector_id!r} exceeded its bound")
    if not roots:
        raise ValueError(f"no top-level sector above {sector_id!r} (parent cycle?)")
    return sorted(roots)


def start_ids(index: dict[str, SectorNode], sector_id: str, aliases: dict[str, str]) -> list[str]:
    """Where the root walk starts: the sector itself or, when its name is a
    `[sectors].aliases` key (keys casefolded), every sector named as the alias
    target -- duplicates share a name, so all of them."""
    if sector_id not in index:
        raise ValueError(f"sector {sector_id!r} is not on the platform")
    target = aliases.get(index[sector_id].name.casefold())
    if target is None:
        return [sector_id]
    ids = [n.id for n in index.values() if n.name.casefold() == target.casefold()]
    if not ids:
        raise ValueError(f"alias target {target!r} is not on the platform")
    return ids


def _extraction(report: JsonDict, label: str, source: str, entity: str) -> JsonDict:
    return {
        "report_id": str(report["id"]), "report_name": str(report.get("name") or ""),
        "label": label, "from": source, "source_entity": entity, "confidence": "high",
    }


def _sector_labels(
    report: JsonDict, index: dict[str, SectorNode], aliases: dict[str, str], log: Log
) -> list[tuple[str, str]]:
    """(root name, contained sector name) per contained sector. A sector whose
    walk fails is logged and contributes nothing -- the report's other labels
    still apply."""
    pairs: list[tuple[str, str]] = []
    for sector in report["sectors"]:
        sid, name = str(sector["id"]), str(sector["name"])
        try:
            roots = {r for start in start_ids(index, sid, aliases) for r in sector_roots(index, start)}
        except ValueError as exc:
            log(f"  ! {report['id']} sector {name} ({sid}): {exc}"[:200])
            continue
        pairs.extend((root, name) for root in sorted(roots))
    return pairs


def labels_for(
    report: JsonDict, index: dict[str, SectorNode], aliases: dict[str, str], log: Log
) -> list[JsonDict]:
    """One extraction per label `report` should carry but does not.

    `report` is `client.report_label_sources()`'s shape. Existing labels and
    duplicates compare casefolded: the platform keeps label case, and `China`
    must not gain a sibling `china`.
    """
    if not isinstance(report, dict) or "id" not in report:
        raise TypeError("labels_for: report must be a report_label_sources() dict")
    have = {str(v).casefold() for v in report["labels"]}
    candidates = [(str(c["name"]), "country", str(c["name"])) for c in report["countries"]]
    candidates += [(root, "sector", name) for root, name in _sector_labels(report, index, aliases, log)]
    out: list[JsonDict] = []
    for label, source, entity in candidates:
        if not label or label.casefold() in have:
            continue
        have.add(label.casefold())
        out.append(_extraction(report, label, source, entity))
    if len({str(e["label"]).casefold() for e in out}) != len(out):
        raise RuntimeError("labels_for emitted a duplicate label")
    return out
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_report_labels.py -q` then `ruff check octirb/ tests/` and `mypy --strict octirb/`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add octirb/linkers/report_labels.py tests/test_report_labels.py
git commit -m "feat(report-labels): sector root walk and label derivation"
```

---

### Task 5: `select` and `batch`

**Files:**
- Modify: `octirb/pipeline.py` — rename `_source_name` → `source_name` (def ~line 94, uses ~138, ~166), `_since_from_days` → `since_from_days` (def ~98, use ~241), `_basic_skip` → `basic_skip` (def ~119, use ~163). Update the `_select_one` docstring reference if it names `_basic_skip`.
- Modify: `octirb/linkers/report_labels.py`
- Test: `tests/test_report_labels.py`

**Interfaces:**
- Consumes: `pipeline.basic_skip(node, *, since, empty_only, sel, title_res, counts) -> bool` (counts keys `old`, `excluded_source`, `excluded_title`), `pipeline.source_name(node) -> str`, `pipeline.since_from_days(days) -> str`; `labels_for`, `build_sector_index` (Task 4); client `reports()`, `sector_parents()`, `report_label_sources()` (Task 3).
- Produces:
  - `select(client: Client, cfg: Config, log: Log, *, limit: int | None, since: str | None) -> list[JsonDict]` — rows `{"report_id", "name", "source"}`.
  - `batch(client: Client, cfg: Config, selection: list[JsonDict], log: Log) -> list[JsonDict]` — extraction dicts.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_report_labels.py`; extend the import to add `batch, select`, and add `from octirb.client import OpenCTIError` and `from octirb.config import Config, SectorsCfg, SelectionCfg`)

```python
# -- select / batch --------------------------------------------------------------


def node(rid: str, *, objects: int = 1, published: str = "2026-09-01",
         source: str = "Vendor", name: str = "") -> dict[str, Any]:
    return {
        "id": rid, "name": name or f"Report {rid}", "description": "",
        "created": published, "published": published, "createdBy": {"name": source},
        "objects": {"edges": [{"node": {"entity_type": "Country"}}] * objects},
        "externalReferences": {"edges": []},
    }


class SelectFake:
    def __init__(self, nodes: list[dict[str, Any]]) -> None:
        self._nodes = nodes

    def reports(self) -> Any:
        return iter(self._nodes)


def test_select_requires_objects_and_keeps_textless_reports():
    cfg = Config(selection=SelectionCfg(since_days=0))
    _lines, log = logs()
    got = select(SelectFake([node("r1"), node("r2", objects=0)]), cfg, log, limit=None, since=None)
    assert got == [{"report_id": "r1", "name": "Report r1", "source": "Vendor"}]


def test_select_honours_gates_and_limit():
    cfg = Config(selection=SelectionCfg(since_days=0, exclude_sources=("Noise",),
                                        exclude_title_patterns=("^weekly",)))
    _lines, log = logs()
    nodes = [node("old", published="2020-01-01"), node("n1", source="Noise"),
             node("t1", name="Weekly digest"), node("r1"), node("r2")]
    got = select(SelectFake(nodes), cfg, log, limit=1, since="2026-01-01")
    assert [g["report_id"] for g in got] == ["r1"]


def test_select_rejects_bad_limit():
    _lines, log = logs()
    with pytest.raises(ValueError):
        select(SelectFake([]), Config(), log, limit=0, since=None)


class BatchFake:
    def __init__(self, reports: dict[str, dict[str, Any]]) -> None:
        self._reports = reports

    def sector_parents(self) -> list[dict[str, Any]]:
        return TREE

    def report_label_sources(self, rid: str) -> dict[str, Any]:
        if rid not in self._reports:
            raise OpenCTIError(f"report {rid} not found")
        return self._reports[rid]


def test_batch_skips_vanished_report_and_continues():
    """Review Focus 5."""
    fake = BatchFake({"r2": report(id="r2", countries=[{"id": "c", "name": "France"}])})
    lines, log = logs()
    got = batch(fake, Config(), [{"report_id": "gone"}, {"report_id": "r2"}], log)
    assert [(e["report_id"], e["label"]) for e in got] == [("r2", "France")]
    assert any("gone" in line for line in lines)


def test_batch_applies_config_aliases_casefolded():
    fake = BatchFake({"r1": report(sectors=[{"id": "dup", "name": "Energy & Utilities"}])})
    cfg = Config(sectors=SectorsCfg(aliases={"Energy & Utilities": "Energy"}))
    _lines, log = logs()
    got = batch(fake, cfg, [{"report_id": "r1"}], log)
    assert [e["label"] for e in got] == ["Energy"]
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_report_labels.py -q -k "select or batch"`
Expected: FAIL — `ImportError: cannot import name 'batch'`.

- [ ] **Step 3: Implement**

In `octirb/pipeline.py`, rename the three helpers and their call sites (pure rename, no behaviour change):

```bash
sed -i 's/\b_source_name\b/source_name/g; s/\b_since_from_days\b/since_from_days/g; s/\b_basic_skip\b/basic_skip/g' octirb/pipeline.py
grep -rn "_source_name\|_since_from_days\|_basic_skip" octirb tests   # expect no output
```

In `octirb/linkers/report_labels.py`, extend the imports:

```python
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .. import pipeline
from ..client import JsonDict, OpenCTIError

if TYPE_CHECKING:
    from ..client import Client
    from ..config import Config
```

Append:

```python
def _log_select(log: Log, counts: dict[str, int], selected: int) -> None:
    log(
        f"  selected {selected} report(s); skipped {counts['empty']} empty, {counts['old']} old, "
        f"{counts['excluded_source']} excluded source, {counts['excluded_title']} excluded title"
    )


def select(
    client: Client, cfg: Config, log: Log, *, limit: int | None, since: str | None
) -> list[JsonDict]:
    """Reports that contain at least one object, newest first.

    Unlike `pipeline.select`, a report with no text is kept -- labels need
    none -- and no text tier is planned. Source/title/since gates are the
    shared `pipeline.basic_skip`.
    """
    if limit is not None and limit <= 0:
        raise ValueError("select: limit must be a positive int or None")
    sel = cfg.selection
    title_res = tuple(re.compile(p, re.IGNORECASE) for p in sel.exclude_title_patterns)
    since_value = since
    if since_value is None and sel.since_days > 0:
        since_value = pipeline.since_from_days(sel.since_days)
    counts = {"old": 0, "excluded_source": 0, "excluded_title": 0, "empty": 0}
    out: list[JsonDict] = []
    for node in client.reports():
        if pipeline.basic_skip(node, since=since_value, empty_only=False, sel=sel,
                               title_res=title_res, counts=counts):
            continue
        if not node["objects"]["edges"]:
            counts["empty"] += 1
            continue
        out.append({"report_id": str(node["id"]), "name": str(node.get("name") or ""),
                    "source": pipeline.source_name(node)})
        if limit and len(out) >= limit:
            break
    _log_select(log, counts, len(out))
    if limit and len(out) > limit:
        raise RuntimeError("select returned more reports than its limit")
    return out


def batch(client: Client, cfg: Config, selection: list[JsonDict], log: Log) -> list[JsonDict]:
    """Extractions for every selected report. A report that errors (deleted
    since select, page cap) is logged and skipped; the batch continues."""
    if not isinstance(selection, list):
        raise TypeError("batch: selection must be a list")
    index = build_sector_index(client.sector_parents())
    aliases = {k.casefold(): v for k, v in cfg.sectors.aliases.items()}
    out: list[JsonDict] = []
    for item in selection:
        rid = str(item["report_id"])
        try:
            report = client.report_label_sources(rid)
        except OpenCTIError as exc:
            log(f"  ! {rid}: {exc}"[:200])
            continue
        out.extend(labels_for(report, index, aliases, log))
    wanted = {str(s["report_id"]) for s in selection}
    if any(str(e["report_id"]) not in wanted for e in out):
        raise RuntimeError("batch emitted a label for a report outside the selection")
    return out
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest -q` (whole suite — the rename touches `pipeline.select`) then `ruff check octirb/ tests/ contrib/` and `mypy --strict octirb/`
Expected: PASS / clean.

- [ ] **Step 5: Commit**

```bash
git add octirb/pipeline.py octirb/linkers/report_labels.py tests/test_report_labels.py
git commit -m "feat(report-labels): select and batch"
```

---

### Task 6: `validate`, `apply_labels`, `revert_labels`

**Files:**
- Modify: `octirb/linkers/report_labels.py`
- Test: `tests/test_report_labels.py`

**Interfaces:**
- Consumes: `ledger.label_row`, `ledger.LABEL_SOURCES` (Task 2); client `entity_labels(rid) -> list[str]` (existing), `find_label(value) -> str | None` (Task 3), `ensure_label(value, color) -> str`, `add_label_to_report(rid, label_id)`, `remove_label_from_report(rid, label_id)` (existing).
- Produces:
  - `validate(raw: list[Any], selection_ids: set[str]) -> tuple[list[JsonDict], list[JsonDict]]` — `(auto, review)`; review items carry `review_reasons: list[str]` and `hard_fail: True`.
  - `apply_labels(client: Client, items: list[JsonDict], log: Log, *, color: str, dry_run: bool, save: Callable[[list[JsonDict]], None]) -> list[JsonDict]` — ledger rows.
  - `revert_labels(client: Client, rows: list[JsonDict], log: Log, *, dry_run: bool = False, retain: list[JsonDict] | None = None) -> int`

- [ ] **Step 1: Write the failing tests** (append to `tests/test_report_labels.py`; extend the import with `apply_labels, revert_labels, validate`, and add `from octirb import ledger`)

```python
# -- validate --------------------------------------------------------------------


def ext(**over: Any) -> dict[str, Any]:
    base = {"report_id": "r1", "report_name": "R", "label": "China", "from": "country",
            "source_entity": "China", "confidence": "high"}
    base.update(over)
    return base


def test_validate_good_items_auto():
    auto, review = validate([ext(), ext(label="ICS", **{"from": "sector"})], {"r1"})
    assert len(auto) == 2 and review == []


@pytest.mark.parametrize("bad", [
    ext(report_id="elsewhere"), ext(label=""), ext(label=None), ext(**{"from": "region"}),
])
def test_validate_bad_items_hard_fail(bad):
    auto, review = validate([bad], {"r1"})
    assert auto == []
    assert review[0]["hard_fail"] is True and review[0]["review_reasons"]


def test_validate_non_object_item_held():
    auto, review = validate(["junk"], {"r1"})
    assert auto == [] and review[0]["hard_fail"] is True


# -- apply -----------------------------------------------------------------------


class ApplyFake:
    def __init__(self, on_report: dict[str, list[str]] | None = None,
                 platform: dict[str, str] | None = None, fail: set[str] | None = None) -> None:
        self.on_report = on_report or {}
        self.platform = platform or {}   # label value -> id already on the platform
        self.fail = fail or set()
        self.created: list[str] = []
        self.added: list[tuple[str, str]] = []

    def entity_labels(self, rid: str) -> list[str]:
        return list(self.on_report.get(rid, []))

    def find_label(self, value: str) -> str | None:
        for existing, lid in self.platform.items():
            if existing.casefold() == value.casefold():
                return lid
        return None

    def ensure_label(self, value: str, color: str) -> str:
        self.created.append(value)
        return f"new-{value}"

    def add_label_to_report(self, rid: str, label_id: str) -> None:
        if label_id in self.fail:
            raise OpenCTIError("boom")
        self.added.append((rid, label_id))


def run_apply(fake: ApplyFake, items: list[dict[str, Any]], *, dry_run: bool = False):
    saves: list[int] = []
    lines, log = logs()
    rows = apply_labels(fake, items, log, color="#5b6abf", dry_run=dry_run,
                        save=lambda rows: saves.append(len(rows)))
    return rows, saves, lines


def test_apply_writes_and_checkpoints_each_write():
    fake = ApplyFake()
    rows, saves, _ = run_apply(fake, [ext(), ext(label="ICS", **{"from": "sector"})])
    assert fake.added == [("r1", "new-China"), ("r1", "new-ICS")]
    assert [r["preexisted"] for r in rows] == [False, False]
    assert [r["label_id"] for r in rows] == ["new-China", "new-ICS"]
    assert saves == [1, 2]


def test_apply_reuses_platform_label_ignoring_case():
    """Review Focus 2."""
    fake = ApplyFake(platform={"ics": "L-ics"})
    rows, _, _ = run_apply(fake, [ext(label="ICS", **{"from": "sector"})])
    assert fake.created == [] and fake.added == [("r1", "L-ics")]
    assert rows[0]["label_id"] == "L-ics"


def test_apply_label_present_at_apply_time_is_preexisted():
    """Review Focus 1, at apply time: someone added `china` since batch."""
    fake = ApplyFake(on_report={"r1": ["china"]})
    rows, saves, _ = run_apply(fake, [ext()])
    assert fake.added == [] and saves == []
    assert rows[0]["preexisted"] is True and rows[0]["label_id"] is None


def test_apply_failed_write_not_ledgered():
    fake = ApplyFake(fail={"new-China"})
    rows, saves, lines = run_apply(fake, [ext(), ext(label="ICS", **{"from": "sector"})])
    assert [r["label"] for r in rows] == ["ICS"]
    assert saves == [1]
    assert any("boom" in line for line in lines)


def test_apply_dry_run_writes_nothing():
    fake = ApplyFake()
    rows, saves, _ = run_apply(fake, [ext()], dry_run=True)
    assert fake.added == [] and fake.created == [] and saves == []
    assert rows[0]["preexisted"] is False


# -- revert ----------------------------------------------------------------------


class RevertFake:
    def __init__(self, fail: set[str] | None = None) -> None:
        self.fail = fail or set()
        self.removed: list[tuple[str, str]] = []

    def remove_label_from_report(self, rid: str, label_id: str) -> None:
        if label_id in self.fail:
            raise OpenCTIError("boom")
        self.removed.append((rid, label_id))


def lrow(label: str, label_id: str | None, *, preexisted: bool = False) -> dict[str, Any]:
    return ledger.label_row(report_id="r1", label=label, label_id=label_id, source="country",
                            source_entity=label, preexisted=preexisted)


def test_revert_removes_ours_keeps_preexisted_and_other_kinds():
    fake = RevertFake()
    other = ledger.entity_row(entity_id="e1", entity_type="Intrusion-Set", name="X")
    _lines, log = logs()
    n = revert_labels(fake, [lrow("China", "L1"), lrow("ICS", None, preexisted=True), other], log)
    assert n == 1 and fake.removed == [("r1", "L1")]


def test_revert_failure_retained_for_retry():
    fake = RevertFake(fail={"L1"})
    retain: list[dict[str, Any]] = []
    _lines, log = logs()
    n = revert_labels(fake, [lrow("China", "L1"), lrow("ICS", "L2")], log, retain=retain)
    assert n == 1 and [r["label"] for r in retain] == ["China"]


def test_revert_dry_run_removes_nothing():
    fake = RevertFake()
    _lines, log = logs()
    assert revert_labels(fake, [lrow("China", "L1")], log, dry_run=True) == 1
    assert fake.removed == []
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_report_labels.py -q -k "validate or apply or revert"`
Expected: FAIL — `ImportError: cannot import name 'apply_labels'`.

- [ ] **Step 3: Implement** in `octirb/linkers/report_labels.py`

Extend imports:

```python
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .. import ledger, pipeline
from ..client import JsonDict, OpenCTIError
```

and after `Log = ...`:

```python
Save = Callable[[list[JsonDict]], None]
```

Append:

```python
# ------------------------------------------------------------------- validate


def _problems(item: Any, selection_ids: set[str]) -> list[str]:
    if not isinstance(item, dict):
        return ["extraction is not a JSON object"]
    reasons: list[str] = []
    if str(item.get("report_id") or "") not in selection_ids:
        reasons.append("report_id is not in this run's selection")
    label = item.get("label")
    if not isinstance(label, str) or not label.strip():
        reasons.append("label is empty or not a string")
    if item.get("from") not in ledger.LABEL_SOURCES:
        reasons.append(f"from must be one of {sorted(ledger.LABEL_SOURCES)}")
    return reasons


def validate(raw: list[Any], selection_ids: set[str]) -> tuple[list[JsonDict], list[JsonDict]]:
    """Split extractions into (auto, review). Nothing here is a judgement call,
    so anything malformed is a hard fail and everything else auto-applies."""
    if not isinstance(raw, list):
        raise TypeError("validate: raw must be a list")
    auto: list[JsonDict] = []
    review: list[JsonDict] = []
    for item in raw:
        reasons = _problems(item, selection_ids)
        if not reasons:
            auto.append(item)
            continue
        held: JsonDict = dict(item) if isinstance(item, dict) else {"item": item}
        held["review_reasons"] = reasons
        held["hard_fail"] = True
        review.append(held)
    if len(auto) + len(review) != len(raw):
        raise RuntimeError("validate lost an extraction")
    return auto, review


# ---------------------------------------------------------------------- apply


@dataclass
class _LabelState:
    client: Client
    log: Log
    color: str
    dry_run: bool
    ids: dict[str, str] = field(default_factory=dict)  # casefolded value -> label id


def _label_id(state: _LabelState, label: str) -> str:
    """Reuse a platform label equal ignoring case; create one only if none."""
    key = label.casefold()
    if key not in state.ids:
        found = state.client.find_label(label)
        state.ids[key] = found if found is not None else state.client.ensure_label(label, state.color)
    if not state.ids[key]:
        raise OpenCTIError(f"no label id for {label!r}")
    return state.ids[key]


def _row(item: JsonDict, label_id: str | None, *, preexisted: bool) -> JsonDict:
    return ledger.label_row(
        report_id=str(item["report_id"]), label=str(item["label"]), label_id=label_id,
        source=str(item["from"]), source_entity=str(item.get("source_entity") or ""),
        preexisted=preexisted,
    )


def _apply_one(state: _LabelState, item: JsonDict, current: set[str]) -> JsonDict | None:
    """One label onto one report. None when the write failed (logged)."""
    rid, label = str(item["report_id"]), str(item["label"])
    if label.casefold() in current:
        state.log(f"  keep {label} on {rid} (pre-existed)")
        return _row(item, None, preexisted=True)
    if state.dry_run:
        state.log(f"  would label {rid}: {label}")
        return _row(item, None, preexisted=False)
    try:
        label_id = _label_id(state, label)
        state.client.add_label_to_report(rid, label_id)
    except OpenCTIError as exc:
        state.log(f"  ! label {rid} {label}: {exc}"[:200])
        return None
    current.add(label.casefold())
    return _row(item, label_id, preexisted=False)


def apply_labels(  # noqa: PLR0913 - client/items/log/color/dry_run/save, not a data clump
    client: Client, items: list[JsonDict], log: Log, *, color: str, dry_run: bool, save: Save,
) -> list[JsonDict]:
    """Add each item's label to its report; one ledger row per item handled.

    Each report's labels are re-read right before writing, so a label that
    appeared since `batch` is ledgered preexisted and never claimed. `save`
    checkpoints after every successful write.
    """
    if not isinstance(items, list):
        raise TypeError("apply_labels: items must be a list")
    state = _LabelState(client=client, log=log, color=color, dry_run=dry_run)
    by_report: dict[str, list[JsonDict]] = {}
    for item in items:
        by_report.setdefault(str(item["report_id"]), []).append(item)
    rows: list[JsonDict] = []
    for rid, group in by_report.items():
        try:
            current = {v.casefold() for v in client.entity_labels(rid)}
        except OpenCTIError as exc:
            log(f"  ! {rid}: {exc}"[:200])
            continue
        for item in group:
            row = _apply_one(state, item, current)
            if row is None:
                continue
            rows.append(row)
            if not dry_run and not row["preexisted"]:
                save(rows)
    if len(rows) > len(items):
        raise RuntimeError("apply_labels produced more rows than items")
    return rows


# --------------------------------------------------------------------- revert


def revert_labels(
    client: Client, rows: list[JsonDict], log: Log, *, dry_run: bool = False,
    retain: list[JsonDict] | None = None,
) -> int:
    """Undo `apply_labels`' `"label"` rows. Preexisted rows are left alone; a
    removal that raises is appended to `retain` so the caller keeps it in the
    ledger for a retry. Label objects themselves are never deleted."""
    if not isinstance(rows, list):
        raise TypeError("revert_labels: rows must be a list")
    failed = retain if retain is not None else []
    reverted = 0
    for row in rows:
        if row.get("kind") != "label":
            continue
        rid, label = str(row.get("report_id") or ""), str(row.get("label") or "")
        if row.get("preexisted"):
            log(f"  keep {label} on {rid} (pre-existed)")
            continue
        label_id = str(row.get("label_id") or "")
        if not rid or not label_id:
            raise OpenCTIError(f"label row has no report/label id: {str(row)[:160]}")
        if dry_run:
            log(f"  would remove label {label} from {rid}")
            reverted += 1
            continue
        try:
            client.remove_label_from_report(rid, label_id)
        except OpenCTIError as exc:
            log(f"  ! revert label {rid} {label}: {exc}"[:200])
            failed.append(row)
            continue
        reverted += 1
    if reverted > len(rows):
        raise RuntimeError("revert_labels reverted more rows than it was given")
    return reverted
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest tests/test_report_labels.py -q` then `ruff check octirb/ tests/` and `mypy --strict octirb/`
Expected: PASS / clean. If ruff reports `PLR0912` (too many branches) on `revert_labels`, extract the `dry_run`/`try` tail into `_revert_one(client, row, log, dry_run) -> bool | None` (True reverted, None failed) rather than adding a `noqa`.

- [ ] **Step 5: Commit**

```bash
git add octirb/linkers/report_labels.py tests/test_report_labels.py
git commit -m "feat(report-labels): validate, apply and revert"
```

---

### Task 7: registry entry and CLI wiring

**Files:**
- Modify: `octirb/linkers/__init__.py` (new builder + `REGISTRY` entry)
- Modify: `octirb/cli.py` — import (~line 27), `_select_write` (~line 63), `cmd_select` (~line 84), `cmd_fetch` (~line 122), new `_batch_labels` + `cmd_batch` (~line 172), `cmd_validate` (~line 269), new `_apply_labels_cmd` + `cmd_apply` (~line 382), `cmd_revert` (~line 410), `_doctor_linkers` (~line 532)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `report_labels.select/batch/validate/apply_labels/revert_labels` (Tasks 5–6), `cfg.report_labels` (Task 1).
- Produces: `REGISTRY["report-labels"]` with `write_kind="label"`, `needs_model=False`; CLI accepts `--linker report-labels`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_cli.py`; add `SelectionCfg` and `ReportLabelsCfg` to the `octirb.config` import)

```python
# ------------------------------------------------------------- report-labels


class LabelsFakeClient:
    """Enough of Client for select -> batch -> validate -> apply -> revert."""

    def __init__(self) -> None:
        self.on_report: dict[str, list[str]] = {"r1": ["china"]}
        self.added: list[tuple[str, str]] = []
        self.removed: list[tuple[str, str]] = []

    def reports(self) -> Any:
        full = dict(report_node("r1", "Report One"),
                    objects={"edges": [{"node": {"entity_type": "Country"}}]})
        return iter([full, report_node("r2", "Empty")])

    def sector_parents(self) -> list[dict[str, Any]]:
        return [{"id": "s-ics", "name": "ICS", "parent_ids": []},
                {"id": "s-man", "name": "Manufacturing", "parent_ids": ["s-ics"]}]

    def report_label_sources(self, rid: str) -> dict[str, Any]:
        return {"id": rid, "name": "Report One", "labels": list(self.on_report.get(rid, [])),
                "countries": [{"id": "c1", "name": "China"}, {"id": "c2", "name": "United States"}],
                "sectors": [{"id": "s-man", "name": "Manufacturing"}]}

    def entity_labels(self, rid: str) -> list[str]:
        return list(self.on_report.get(rid, []))

    def find_label(self, value: str) -> str | None:
        return None

    def ensure_label(self, value: str, color: str) -> str:
        return f"label-{value}"

    def add_label_to_report(self, rid: str, label_id: str) -> None:
        self.added.append((rid, label_id))
        self.on_report.setdefault(rid, []).append(label_id.removeprefix("label-"))

    def remove_label_from_report(self, rid: str, label_id: str) -> None:
        self.removed.append((rid, label_id))


def test_report_labels_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_cfg(tmp_path, selection=SelectionCfg(since_days=0))
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    fake = LabelsFakeClient()
    monkeypatch.setattr(cli, "_client", lambda _cfg: fake)
    run_dir = tmp_path / "L1"

    assert cli.cmd_select(ns(linker="report-labels", run_id="L1")) == cli.EXIT_OK
    assert [s["report_id"] for s in json.loads((run_dir / "selection.json").read_text())] == ["r1"]

    assert cli.cmd_batch(ns(run_id="L1")) == cli.EXIT_OK
    labels = [e["label"] for e in json.loads((run_dir / "extractions.json").read_text())]
    assert labels == ["United States", "ICS"]

    assert cli.cmd_validate(ns(run_id="L1")) == cli.EXIT_OK
    assert len(json.loads((run_dir / "auto.json").read_text())) == 2

    assert cli.cmd_apply(ns(run_id="L1", dry_run=True)) == cli.EXIT_OK
    assert fake.added == [] and not (run_dir / "applied.json").exists()

    assert cli.cmd_apply(ns(run_id="L1")) == cli.EXIT_OK
    assert fake.added == [("r1", "label-United States"), ("r1", "label-ICS")]
    assert len(json.loads((run_dir / "applied.json").read_text())) == 2

    assert cli.cmd_revert(ns(run_id="L1")) == cli.EXIT_OK
    assert sorted(fake.removed) == [("r1", "label-ICS"), ("r1", "label-United States")]
    assert json.loads((run_dir / "applied.json").read_text()) == []


def test_revert_mixed_ledger_touches_each_kind_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_dir = tmp_path / "r1"
    write_meta(run_dir, linker="report-location")
    contain = ledger.containment_row(
        report_id="r1", entity_id="e1", entity_name="France", linker="report-location",
        key="FRA", role="target", confidence="high", evidence="q", label_id=None, created=False,
    )
    label = ledger.label_row(report_id="r1", label="France", label_id="L-fr", source="country",
                             source_entity="France", preexisted=False)
    (run_dir / "applied.json").write_text(json.dumps([contain, label]))
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    fake = RevertFakeClient()
    monkeypatch.setattr(cli, "_client", lambda _cfg: fake)

    assert cli.cmd_revert(ns(run_id="r1")) == cli.EXIT_OK
    assert fake.removed_objects == [("r1", "e1")]
    assert fake.removed_labels == [("r1", "L-fr")]


def test_select_report_labels_disabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = make_cfg(tmp_path, report_labels=ReportLabelsCfg(enabled=False))
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    with pytest.raises(SystemExit, match=r"report-labels is disabled"):
        cli.cmd_select(ns(linker="report-labels"))


def test_fetch_refuses_report_labels(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_meta(tmp_path / "L1", linker="report-labels")
    cfg = make_cfg(tmp_path)
    monkeypatch.setattr(cli, "_load_cfg", lambda _args: cfg)
    assert cli.cmd_fetch(ns(run_id="L1")) == cli.EXIT_BAD_RUN


def test_doctor_linkers_skips_report_labels(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "REGISTRY", {"report-labels": REGISTRY["report-labels"]})
    assert cli._doctor_linkers(object(), make_cfg(tmp_path)) is True  # type: ignore[arg-type]
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/test_cli.py -q -k "report_labels or mixed_ledger"`
Expected: FAIL — `KeyError: 'report-labels'` / `ImportError`.

- [ ] **Step 3: Implement**

`octirb/linkers/__init__.py` — after `_build_actor_target`:

```python
def _build_report_labels(client: Client, cfg: Config) -> Resolver:  # noqa: ARG001 - raises before use
    """report-labels has no resolver: it labels with the names of objects the
    report already contains, so there is nothing to resolve."""
    raise NotImplementedError(
        "report-labels resolves nothing -- see octirb.linkers.report_labels"
    )
```

and in `REGISTRY`, after `"report-vuln"`:

```python
    "report-labels": Linker(
        name="report-labels",
        key_field="label",
        # Label sources ("country"/"sector") are checked by
        # report_labels.validate against ledger.LABEL_SOURCES, not by the
        # pipeline's generic role check.
        roles=frozenset(),
        label_suffix="Labels",
        entity_kind="Label",
        write_kind="label",
        needs_model=False,
        build_resolver=_build_report_labels,
        contract=None,
    ),
```

`octirb/cli.py`:

Import line becomes:

```python
from .linkers import REGISTRY, actor_target, get, report_labels, report_vuln
```

`_select_write` — insert after the `actor-target` block, before `cache = TextCache(...)`:

```python
    if args.linker == "report-labels":
        since = _since_iso(args.since_days) if args.since_days else None
        rows = report_labels.select(client, cfg, _log, limit=args.limit, since=since)
        run.write_json("selection.json", rows)
        return len(rows)
```

`cmd_select` — after the `report-vuln` disabled check:

```python
    if args.linker == "report-labels" and not cfg.report_labels.enabled:
        raise SystemExit("config: report-labels is disabled ([report_labels].enabled)")
    if args.linker == "report-labels" and args.all_reports:
        _log("select: --all-reports does not apply to report-labels; ignored")
```

`cmd_fetch` — replace the actor-target guard with:

```python
    if run.linker() in ("actor-target", "report-labels"):
        _log(f"run {run.run_id} is {run.linker()}; it has no fetch step")
        return EXIT_BAD_RUN
```

New helper after `_batch_vuln`:

```python
def _batch_labels(run: Run, cfg: Config) -> int:
    extractions = report_labels.batch(_client(cfg), cfg, run.read_json("selection.json"), _log)
    run.write_json("extractions.json", extractions)
    print(f"run {run.run_id}: {len(extractions)} extraction(s) written")
    return EXIT_OK
```

`cmd_batch` — after the `report-vuln` branch:

```python
    if linker_name == "report-labels":
        return _batch_labels(run, cfg)
```

`cmd_validate` — replace from `linker_name = run.linker()` through the end of the if/else with:

```python
    linker_name = run.linker()
    if linker_name == "report-labels":
        selection_ids = {str(s["report_id"]) for s in run.read_json("selection.json")}
        auto, review = report_labels.validate(raw, selection_ids)
    elif linker_name == "actor-target":
        auto, review = _validate_actor_target(cfg, run, _client(cfg), raw)
    else:
        client = _client(cfg)
        linker = get(linker_name)
        resolver = linker.build_resolver(client, cfg)
        selection_ids = {str(s["report_id"]) for s in run.read_json("selection.json")}
        writeback = linker_name == "report-actor" and cfg.actors.alias_writeback
        auto, review = pipeline.validate(raw, resolver, selection_ids, linker, writeback=writeback)
```

New helper before `cmd_apply`:

```python
def _apply_labels_cmd(args: Namespace, cfg: Config, run: Run, client: Client) -> int:
    auto = run.read_json("auto.json") if run.has("auto.json") else []
    review = run.read_json("review.json") if run.has("review.json") else []
    items = list(auto)
    if args.include_review:
        items += [r for r in review if not r.get("hard_fail")]
    prior = run.read_json("applied.json") if run.has("applied.json") else []

    def save(fresh: list[JsonDict]) -> None:
        run.write_json("applied.json", ledger.merge_ledger(prior, fresh))

    rows = report_labels.apply_labels(
        client, items, _log, color=cfg.report_labels.color, dry_run=args.dry_run, save=save
    )
    merged = ledger.merge_ledger(prior, rows)
    if not args.dry_run:
        run.write_json("applied.json", merged)
    written = sum(1 for r in rows if not r["preexisted"])
    verb = "would write" if args.dry_run else "wrote"
    print(f"run {run.run_id}: {verb} {written} label(s) ({len(merged)} total in ledger)")
    return EXIT_OK
```

`cmd_apply` — before `if linker.write_kind == "containment":`:

```python
    if linker.write_kind == "label":
        return _apply_labels_cmd(args, cfg, run, client)
```

`cmd_revert` — after `n_alias = ...`:

```python
    n_label = report_labels.revert_labels(client, rows, _log, dry_run=args.dry_run, retain=retain)
```

and the summary print becomes:

```python
    print(
        f"run {run.run_id}: containment {n_contain}, aliases {n_alias}, labels {n_label}, "
        f"relationships {n_rel_del}/{n_rel_kept} kept, entities {n_ent_del}/{n_ent_kept} kept"
    )
```

`_doctor_linkers` — replace the name guard with:

```python
        if not name.startswith("report-") or REGISTRY[name].write_kind != "containment":
            continue
```

- [ ] **Step 4: Run to verify pass**

Run: `pytest -q` then `ruff check octirb/ tests/ contrib/` and `mypy --strict octirb/`
Expected: PASS / clean. If `cmd_validate` or `cmd_revert` now exceed 60 lines or ruff's statement cap, extract the branch into a `_validate_split(cfg, run, raw) -> tuple[list[JsonDict], list[JsonDict]]` helper rather than suppressing.

- [ ] **Step 5: Commit**

```bash
git add octirb/linkers/__init__.py octirb/cli.py tests/test_cli.py
git commit -m "feat(cli): wire report-labels linker through select/batch/validate/apply/revert"
```

---

### Task 8: documentation

**Files:**
- Modify: `README.md` (Linkers table ~line 166-171; Quick start step 4 note ~line 117)
- Modify: `CLAUDE.md` (architecture bullet on `octirb/linkers/__init__.py`)
- Modify: `skills/octi-link-reports/SKILL.md` (frontmatter description, intro list, step notes, new `### report-labels` section after `### report-vuln`)

- [ ] **Step 1: README**

Add a table row after `report-vuln`:

```markdown
| `report-labels` | Report → plain labels | label | no — country names + top-level sector roots |
```

Add a paragraph after the table:

```markdown
`report-labels` labels each report with the **unprefixed** name of every
Country it contains and of every top-level root above every Sector it
contains (a sector with two parents gives both roots). It reads everything a
report contains, whoever added it, so running it with no `--since-days`
backfills the whole corpus; `--since-days N` keeps scheduled runs
incremental. It is add-only — `revert` removes only labels its run added,
never one already on the report — and it has no fetch or model step:
`select`, `batch`, `validate`, `apply`.
```

In Quick start step 4, change "`report-vuln` skips this — it's deterministic and writes `extractions.json` directly" to "`report-vuln` and `report-labels` skip this — they're deterministic and write `extractions.json` directly".

- [ ] **Step 2: CLAUDE.md**

In the `octirb/linkers/__init__.py` bullet, change "`write_kind` = `containment` | `relationship`" to "`write_kind` = `containment` | `relationship` | `label`", and append: "`report-labels` (`linkers/report_labels.py`) is deterministic like `report-vuln` but owns its whole flow like `actor-target`; it writes `kind: \"label\"` ledger rows and its `build_resolver` raises, so `doctor` skips non-containment linkers."

- [ ] **Step 3: SKILL.md**

- Frontmatter `description`: change "(report-location, report-sector, report-actor or report-vuln)" to "(report-location, report-sector, report-actor, report-vuln or report-labels)" and add `"label reports"` to the trigger phrases.
- Intro: "one of the four report-scoped linkers" → "one of the five report-scoped linkers", adding `report-labels` to the list.
- Next to the existing "`report-vuln` is different: it has no model step" note, add:

```markdown
   **`report-labels` has no fetch and no model step.** Skip `fetch`; `batch`
   derives labels deterministically and writes `extractions.json`, so go
   straight to **step 5 (validate)**. It selects reports that already contain
   objects (the reverse of the other linkers' default), so `--all-reports` is
   ignored.
```

- New section after `### report-vuln`:

```markdown
### report-labels

- Labels are the platform Country name and the top-level root Sector name,
  verbatim — no `AI-` prefix.
- Every extraction is `confidence: high`; `review.json` only ever holds
  malformed rows (`hard_fail: true`). Nothing to judge.
- A label already on the report (any case) is never re-added and never
  removed by `revert`.
```

- [ ] **Step 4: Verify**

Run: `pytest -q`, `ruff check octirb/ tests/ contrib/`, `mypy --strict octirb/`, `mypy --strict contrib/migrate-legacy-labels.py`, `shellcheck install-deps.sh`
Expected: all clean. Then `grep -n "four report-scoped\|report-vuln)" README.md CLAUDE.md skills/octi-link-reports/SKILL.md` — expect no stale "four" wording.

- [ ] **Step 5: Commit**

```bash
git add README.md CLAUDE.md skills/octi-link-reports/SKILL.md
git commit -m "docs: document report-labels linker"
```
