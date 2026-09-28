"""octirb/resolvers/crosswalk.py: MISP galaxy cache load/lookup and refresh.

The load/lookup/crosswalk_resolve block below is the brief's test file,
used verbatim. `refresh()` tests are added after it: the brief explicitly
says refresh() gets no test that actually downloads, and to cover its
guards instead -- a bad scheme (no network involved, the scheme check runs
before urlopen) and a bad payload via a monkeypatched urlopen.
"""

import json

from octirb.resolvers.actors import Actor, ActorVocabulary
from octirb.resolvers.crosswalk import CACHE_NAME, Crosswalk

GALAXY = {"values": [
    {"value": "APT29", "meta": {"synonyms": ["Cozy Bear", "Midnight Blizzard", "UNC2452"]}},
    {"value": "Lazarus Group", "meta": {"synonyms": ["HIDDEN COBRA"]}},
]}


def cache(tmp_path, payload):
    (tmp_path / CACHE_NAME).write_text(json.dumps(payload), encoding="utf-8")
    return tmp_path


def test_load_and_lookup(tmp_path):
    xw = Crosswalk.load(cache(tmp_path, GALAXY), lambda _m: None)
    cluster, names = xw.synonyms("midnight-blizzard")
    assert cluster == "APT29" and "Cozy Bear" in names


def test_missing_cache_returns_none(tmp_path):
    logs = []
    assert Crosswalk.load(tmp_path, logs.append) is None
    assert logs and "crosswalk" in logs[0]


def test_corrupt_cache_returns_none(tmp_path):
    (tmp_path / CACHE_NAME).write_text("{not json", encoding="utf-8")
    assert Crosswalk.load(tmp_path, lambda _m: None) is None


def test_crosswalk_resolve_via_platform_synonym(tmp_path):
    xw = Crosswalk.load(cache(tmp_path, GALAXY), lambda _m: None)
    vocab = ActorVocabulary(
        [Actor(id="a1", name="APT29", entity_type="Intrusion-Set", aliases=("Cozy Bear",))],
        crosswalk=xw, label="AI-Created", create_type="Intrusion-Set",
    )
    actor, cluster = vocab.crosswalk_resolve("Midnight Blizzard")
    assert actor.id == "a1" and cluster == "APT29"


def test_crosswalk_miss_returns_none(tmp_path):
    xw = Crosswalk.load(cache(tmp_path, GALAXY), lambda _m: None)
    vocab = ActorVocabulary([], crosswalk=xw, label="AI-Created", create_type="Intrusion-Set")
    assert vocab.crosswalk_resolve("HIDDEN COBRA") is None  # cluster hit, nothing on platform


def test_resolver_without_crosswalk_still_resolves():
    vocab = ActorVocabulary(
        [Actor(id="a1", name="APT29", entity_type="Intrusion-Set")],
        crosswalk=None, label="AI-Created", create_type="Intrusion-Set",
    )
    assert vocab.resolve("apt 29").id == "a1"
    assert vocab.crosswalk_resolve("Midnight Blizzard") is None


# -- Crosswalk.age_days(): not exercised above -- from file mtime.


def test_age_days_missing_cache_is_none(tmp_path):
    assert Crosswalk.age_days(tmp_path) is None


def test_age_days_fresh_cache_is_zero(tmp_path):
    cache(tmp_path, GALAXY)
    assert Crosswalk.age_days(tmp_path) == 0


# -- refresh(): scheme guard needs no network; the JSON/shape guard is
# exercised with a monkeypatched urlopen so no real download happens.


def test_refresh_rejects_non_http_scheme(tmp_path):
    import pytest

    from octirb.resolvers.crosswalk import refresh

    with pytest.raises(SystemExit, match="crosswalk"):
        refresh(tmp_path, url="file:///etc/passwd")


def test_refresh_rejects_payload_without_values(tmp_path, monkeypatch):
    import io

    import pytest

    from octirb.resolvers import crosswalk

    class FakeResponse(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(_request, timeout=60):
        return FakeResponse(json.dumps({"not_values": []}).encode("utf-8"))

    monkeypatch.setattr(crosswalk.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(SystemExit, match="crosswalk"):
        crosswalk.refresh(tmp_path)
    assert not (tmp_path / CACHE_NAME).exists()


def test_refresh_writes_cache_atomically(tmp_path, monkeypatch):
    import io

    from octirb.resolvers import crosswalk

    class FakeResponse(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(_request, timeout=60):
        return FakeResponse(json.dumps(GALAXY).encode("utf-8"))

    monkeypatch.setattr(crosswalk.urllib.request, "urlopen", fake_urlopen)
    target = crosswalk.refresh(tmp_path)
    assert target == tmp_path / CACHE_NAME
    assert not (tmp_path / (CACHE_NAME + ".tmp")).exists()
    assert json.loads(target.read_text(encoding="utf-8")) == GALAXY
