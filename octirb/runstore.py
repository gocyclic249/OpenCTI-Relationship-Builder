"""On-disk run store with shared text cache.

Run is a directory on disk containing metadata and results. TextCache is a
shared directory for caching article text across runs.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def new_run_id() -> str:
    """Return a 16-character run ID: %Y%m%dT%H%M%SZ format."""
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


class Run:
    """A single run directory on disk."""

    def __init__(self, root: Path) -> None:
        if not isinstance(root, Path):
            raise TypeError("root must be a Path")
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    @property
    def run_id(self) -> str:
        """Return the run ID (directory name)."""
        return self.root.name

    def _path(self, name: str) -> Path:
        """Return the full path to a file in this run."""
        if not isinstance(name, str):
            raise TypeError("name must be str")
        return self.root / name

    def write_json(self, name: str, data: Any) -> Path:
        """Write data as JSON to a file in this run."""
        if not isinstance(name, str):
            raise TypeError("name must be str")
        p = self._path(name)
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return p

    def read_json(self, name: str) -> Any:
        """Read JSON from a file in this run."""
        if not isinstance(name, str):
            raise TypeError("name must be str")
        p = self._path(name)
        if not p.is_file():
            raise SystemExit(f"{p} not found — run the earlier step first.")
        return json.loads(p.read_text(encoding="utf-8"))

    def has(self, name: str) -> bool:
        """Check if a file exists in this run."""
        if not isinstance(name, str):
            raise TypeError("name must be str")
        return self._path(name).is_file()

    def meta(self) -> dict[str, Any]:
        """Return the run's metadata from meta.json."""
        result = self.read_json("meta.json")
        if not isinstance(result, dict):
            raise SystemExit(f"{self.root}/meta.json is not an object")
        return result

    def linker(self) -> str:
        """Return the linker name from meta.json or exit if absent."""
        m = self.meta()
        if "linker" not in m:
            raise SystemExit(f"{self.root}/meta.json missing linker field")
        linker_val = m["linker"]
        if not isinstance(linker_val, str):
            raise TypeError("linker must be str")
        return linker_val

    @staticmethod
    def latest(runs_dir: Path) -> Run | None:
        """Return the latest run by created timestamp, or None if no runs."""
        if not isinstance(runs_dir, Path):
            raise TypeError("runs_dir must be a Path")
        if not runs_dir.is_dir():
            return None

        latest_run: Run | None = None
        latest_created: str | None = None

        for d in runs_dir.iterdir():
            if not d.is_dir():
                continue
            try:
                meta_path = d / "meta.json"
                if not meta_path.is_file():
                    continue  # not a run
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                created = meta.get("created")
                if not isinstance(created, str):
                    continue  # not a run
                if latest_created is None or created > latest_created:
                    latest_created = created
                    latest_run = Run(d)
            except (OSError, json.JSONDecodeError, KeyError):
                continue  # not a run

        return latest_run

    @staticmethod
    def open(runs_dir: Path, run_id: str) -> Run:
        """Open a specific run by ID or exit if not found."""
        if not isinstance(runs_dir, Path):
            raise TypeError("runs_dir must be a Path")
        if not isinstance(run_id, str):
            raise TypeError("run_id must be str")
        root = runs_dir / run_id
        if not root.is_dir():
            raise SystemExit(f"No such run: {root}")
        return Run(root)


class TextCache:
    """Shared cache for article text across runs."""

    def __init__(self, cache_dir: Path) -> None:
        if not isinstance(cache_dir, Path):
            raise TypeError("cache_dir must be a Path")
        self.cache_dir = cache_dir
        self.text_dir = cache_dir / "text"
        self.text_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, report_id: str) -> Path:
        """Return the full path to a cached text file."""
        if not isinstance(report_id, str):
            raise TypeError("report_id must be str")
        if "/" in report_id:
            raise ValueError("report_id must not contain /")
        return self.text_dir / f"{report_id}.txt"

    def read(self, report_id: str) -> str | None:
        """Read cached text for a report, or None if not cached."""
        p = self._path(report_id)
        return p.read_text(encoding="utf-8") if p.is_file() else None

    def write(self, report_id: str, text: str) -> Path:
        """Write text to cache and return the path."""
        if not isinstance(text, str):
            raise TypeError("text must be str")
        p = self._path(report_id)
        p.write_text(text, encoding="utf-8")
        return p

    def has(self, report_id: str) -> bool:
        """Check if a report's text is cached."""
        p = self._path(report_id)
        return p.is_file()
