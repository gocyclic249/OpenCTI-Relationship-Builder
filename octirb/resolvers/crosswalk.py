"""MISP galaxy threat-actor crosswalk: a cached synonym lookup.

octi-rb's own actor vocabulary (actors.py) only resolves names already on
the platform, plus a tiny curated rename table. The MISP threat-actor
galaxy is a much larger, community-maintained synonym set (APT29 / Cozy
Bear / Midnight Blizzard / UNC2452 / ...); this module downloads it once,
caches it on disk, and offers a normalised synonym lookup so
`ActorVocabulary.crosswalk_resolve()` can try every name in a matched
cluster against the platform vocabulary before giving up.

Design choices:
- Cached, not live: every report resolution would otherwise cost a network
  round trip to GitHub. `refresh()` is a separate, explicit step (a doctor
  or setup command), and `Crosswalk.load()` only ever reads the cache.
- Fail soft on load: a missing, corrupt, or malformed cache degrades
  resolution to platform-only (one log line), not a crash -- the crosswalk
  is an enrichment, not a hard dependency.
- Fail loud on refresh: a bad URL, network error, or malformed download is
  a `SystemExit` -- silently leaving a stale or half-written cache in place
  would be worse than stopping.
- Atomic write: refresh() writes to a `.tmp` file and `Path.replace()`s it
  into place, so a load() racing a refresh() (or a refresh() that dies
  mid-write) never sees a truncated file.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ..client import ALLOWED_SCHEMES
from .actors import normalise

if TYPE_CHECKING:
    from collections.abc import Callable

JsonDict = dict[str, Any]

GALAXY_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
CACHE_NAME = "threat-actor-galaxy.json"

# Hours-to-seconds-to-days: age_days() truncates rather than rounds, so a
# cache refreshed a minute ago reads as 0 days old, not 1.
_SECONDS_PER_DAY = 86_400


def refresh(cache_dir: Path, url: str = GALAXY_URL, timeout: int = 60) -> Path:
    """Download the MISP galaxy JSON and cache it atomically.

    Any failure (bad scheme, network error, malformed JSON, missing
    "values" list) is a `SystemExit("crosswalk: ...")` -- refresh is an
    explicit, human-triggered step, so failing loud is correct here, unlike
    `Crosswalk.load()`.
    """
    if not isinstance(cache_dir, Path):
        raise TypeError("crosswalk.refresh: cache_dir must be a Path")
    if timeout <= 0:
        raise ValueError("crosswalk.refresh: timeout must be positive")
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SystemExit(f"crosswalk: refusing non-HTTP galaxy URL {url!r} (scheme {scheme!r})")
    request = urllib.request.Request(url)  # noqa: S310 - scheme checked above
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            raw = response.read()
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise SystemExit(f"crosswalk: download of {url!r} failed: {exc}") from exc
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"crosswalk: downloaded payload is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("values"), list):
        raise SystemExit("crosswalk: downloaded payload has no 'values' list")
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_dir / CACHE_NAME
    tmp = target.with_name(target.name + ".tmp")
    tmp.write_bytes(raw)
    tmp.replace(target)
    return target


@dataclass(frozen=True)
class Crosswalk:
    """A loaded MISP galaxy cache: normalised name -> synonym cluster."""

    _clusters: tuple[JsonDict, ...]

    @classmethod
    def load(cls, cache_dir: Path, log: Callable[[str], None]) -> Crosswalk | None:
        """Load the cached galaxy JSON, or None (with one log line) if unusable."""
        if not isinstance(cache_dir, Path):
            raise TypeError("Crosswalk.load: cache_dir must be a Path")
        if not callable(log):
            raise TypeError("Crosswalk.load: log must be callable")
        path = cache_dir / CACHE_NAME
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            log("crosswalk: cache missing/corrupt — resolution is platform-only")
            return None
        values = payload.get("values") if isinstance(payload, dict) else None
        if not isinstance(values, list):
            log("crosswalk: cache missing/corrupt — resolution is platform-only")
            return None
        return cls(tuple(values))

    def synonyms(self, name: str) -> tuple[str, list[str]] | None:
        """(cluster canonical value, [value, *synonyms]) on a normalised hit, else None.

        The cluster list is finite (the MISP galaxy has on the order of a
        few thousand entries), so a plain bounded for loop is the whole
        scan -- no explicit ceiling needed beyond `len(self._clusters)`.
        """
        target = normalise(name)
        if not target:
            return None
        for cluster in self._clusters:
            value = str(cluster.get("value", ""))
            raw_meta = cluster.get("meta")
            meta: JsonDict = raw_meta if isinstance(raw_meta, dict) else {}
            synonym_names = [str(s) for s in (meta.get("synonyms") or [])]
            names = [value, *synonym_names]
            if any(normalise(candidate) == target for candidate in names):
                return value, names
        return None

    @staticmethod
    def age_days(cache_dir: Path) -> int | None:
        """Cache age in whole days from its mtime, or None if it does not exist."""
        if not isinstance(cache_dir, Path):
            raise TypeError("Crosswalk.age_days: cache_dir must be a Path")
        path = cache_dir / CACHE_NAME
        if not path.is_file():
            return None
        age_seconds = time.time() - path.stat().st_mtime
        return max(0, int(age_seconds // _SECONDS_PER_DAY))
