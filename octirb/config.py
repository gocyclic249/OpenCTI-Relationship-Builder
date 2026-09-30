"""TOML configuration for octi-rb: load/validate, Settings, token, disk check.

Fails loud: an unknown key, a wrong type, an out-of-range value, or an
unparsable regex all abort with `SystemExit("config: ...")` naming the
offending key or pattern, rather than silently falling back to a default.

The OpenCTI API token is never read from config.toml -- only from
`$OPENCTI_TOKEN`, `$OPENCTI_ADMIN_TOKEN`, or an env file the config points at.
"""

from __future__ import annotations

import os
import re
import shutil
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

# -- range/bound constants (named so ruff's magic-value check stays quiet and
# so the actual bound is easy to find later) -------------------------------
MIN_SINCE_DAYS = 0
MIN_FULLTEXT_MIN_CHARS = 0
TITLE_MATCH_MIN_BOUND = 0.0
TITLE_MATCH_MAX_BOUND = 1.0
MIN_MAX_FETCH_PER_RUN = 0
MIN_WARN_PERCENT = 0
MAX_WARN_PERCENT = 100
MIN_CROSSWALK_MAX_AGE_DAYS = 1
VALID_CREATE_MISSING_TYPES = frozenset({"Intrusion-Set", "Threat-Actor-Group"})
MAX_DISK_PATHS = 1000
PERCENT_SCALE = 100
BYTES_PER_GB = 1024**3
HEX_COLOR_RE = re.compile(r"^#[0-9a-fA-F]{6}$")


# -- sub-configs -------------------------------------------------------------


@dataclass(frozen=True)
class PlatformCfg:
    url: str = "http://localhost:8080"
    env_file: str = ""


@dataclass(frozen=True)
class RunsCfg:
    dir: str = ""


@dataclass(frozen=True)
class LabelsCfg:
    prefix: str = "AI-"
    color: str = "#0d7d8c"


@dataclass(frozen=True)
class SelectionCfg:
    since_days: int = 183
    sources: tuple[str, ...] = ()
    exclude_sources: tuple[str, ...] = ()
    exclude_title_patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class TextCfg:
    fulltext_min_chars: int = 2000
    title_match_min: float = 0.5
    fetch_enabled: bool = True
    fetch_exclude_sources: tuple[str, ...] = ()
    fetch_hosts: tuple[str, ...] = ()
    max_fetch_per_run: int = 50


@dataclass(frozen=True)
class DiskCfg:
    warn_percent: int = 75
    paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class SectorsCfg:
    canonical_authors: tuple[str, ...] = ("Filigran",)
    extra_roots: tuple[str, ...] = ()
    aliases: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ActorsCfg:
    create_missing_type: str = "Intrusion-Set"
    crosswalk_enabled: bool = True
    crosswalk_max_age_days: int = 90
    alias_writeback: bool = True


@dataclass(frozen=True)
class VulnsCfg:
    enabled: bool = True


@dataclass(frozen=True)
class ReportLabelsCfg:
    enabled: bool = True
    color: str = "#5b6abf"


@dataclass(frozen=True)
class Config:
    platform: PlatformCfg = field(default_factory=PlatformCfg)
    runs: RunsCfg = field(default_factory=RunsCfg)
    labels: LabelsCfg = field(default_factory=LabelsCfg)
    selection: SelectionCfg = field(default_factory=SelectionCfg)
    text: TextCfg = field(default_factory=TextCfg)
    disk: DiskCfg = field(default_factory=DiskCfg)
    sectors: SectorsCfg = field(default_factory=SectorsCfg)
    actors: ActorsCfg = field(default_factory=ActorsCfg)
    vulns: VulnsCfg = field(default_factory=VulnsCfg)
    report_labels: ReportLabelsCfg = field(default_factory=ReportLabelsCfg)

    @property
    def runs_dir(self) -> Path:
        if self.runs.dir:
            return Path(self.runs.dir)
        xdg_state = os.environ.get("XDG_STATE_HOME")
        base = Path(xdg_state) if xdg_state else Path.home() / ".local" / "state"
        return base / "octi-rb" / "runs"

    @property
    def cache_dir(self) -> Path:
        return self.runs_dir.parent / "cache"

    def label(self, suffix: str) -> str:
        if not isinstance(suffix, str):
            raise TypeError("label: suffix must be a str")
        result = self.labels.prefix + suffix
        if not result:
            raise SystemExit("config: label produced an empty string")
        return result


# -- Settings / token resolution (ported from opencti-docker/octigeo/config.py) --


def _load_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


@dataclass(frozen=True)
class Settings:
    url: str
    token: str

    @property
    def graphql_url(self) -> str:
        return self.url.rstrip("/") + "/graphql"

    def storage_url(self, file_id: str) -> str:
        return f"{self.url.rstrip('/')}/storage/get/{quote(file_id, safe='')}"


def resolve_settings(cfg: Config) -> Settings:
    if not isinstance(cfg, Config):
        raise TypeError("resolve_settings: cfg must be a Config")
    token = os.environ.get("OPENCTI_TOKEN") or os.environ.get("OPENCTI_ADMIN_TOKEN")
    if not token and cfg.platform.env_file:
        env = _load_env_file(Path(cfg.platform.env_file))
        token = env.get("OPENCTI_TOKEN") or env.get("OPENCTI_ADMIN_TOKEN")
    if not token:
        raise SystemExit("config: no OPENCTI_TOKEN in environment or env_file")
    settings = Settings(url=cfg.platform.url, token=token)
    if not settings.token:
        raise SystemExit("config: resolved token is empty")
    return settings


# -- schema-driven TOML validation ------------------------------------------

SCHEMA: dict[str, dict[str, type | tuple[type, ...]]] = {
    "platform": {"url": str, "env_file": str},
    "runs": {"dir": str},
    "labels": {"prefix": str, "color": str},
    "selection": {
        "since_days": int,
        "sources": list,
        "exclude_sources": list,
        "exclude_title_patterns": list,
    },
    "text": {
        "fulltext_min_chars": int,
        "title_match_min": (int, float),
        "fetch_enabled": bool,
        "fetch_exclude_sources": list,
        "fetch_hosts": list,
        "max_fetch_per_run": int,
    },
    "disk": {"warn_percent": int, "paths": list},
    "sectors": {"canonical_authors": list, "extra_roots": list, "aliases": dict},
    "actors": {
        "create_missing_type": str,
        "crosswalk_enabled": bool,
        "crosswalk_max_age_days": int,
        "alias_writeback": bool,
    },
    "vulns": {"enabled": bool},
    "report_labels": {"enabled": bool, "color": str},
}


def _check_type(section: str, key: str, value: object, expected: type | tuple[type, ...]) -> None:
    types = expected if isinstance(expected, tuple) else (expected,)
    if bool in types:
        if type(value) is not bool:
            raise SystemExit(f"config: [{section}].{key} must be a bool")
        return
    if isinstance(value, bool):
        raise SystemExit(f"config: [{section}].{key} must not be a bool")
    if not isinstance(value, types):
        names = " or ".join(t.__name__ for t in types)
        raise SystemExit(f"config: [{section}].{key} must be a {names} (got {value!r})")


def _check_str_list(section: str, key: str, value: list[Any]) -> None:
    for item in value:
        if not isinstance(item, str):
            raise SystemExit(f"config: [{section}].{key} entries must be strings")


def _check_str_dict(section: str, key: str, value: dict[Any, Any]) -> None:
    for table_key, table_value in value.items():
        if not isinstance(table_key, str) or not isinstance(table_value, str):
            raise SystemExit(f"config: [{section}].{key} must map str to str")


def _validate_schema(data: dict[str, Any]) -> None:
    for section, table in data.items():
        if section not in SCHEMA:
            raise SystemExit(f"config: unknown section [{section}]")
        if not isinstance(table, dict):
            raise SystemExit(f"config: [{section}] must be a table")
        allowed = SCHEMA[section]
        for key, value in table.items():
            if key not in allowed:
                raise SystemExit(f"config: unknown key [{section}].{key}")
            expected = allowed[key]
            _check_type(section, key, value, expected)
            if expected is list:
                _check_str_list(section, key, value)
            elif expected is dict:
                _check_str_dict(section, key, value)


def _tupleize(table: dict[str, Any], list_keys: tuple[str, ...]) -> dict[str, Any]:
    out = dict(table)
    for key in list_keys:
        if key in out:
            out[key] = tuple(out[key])
    return out


def _build_selection(table: dict[str, Any]) -> SelectionCfg:
    cfg = SelectionCfg(**_tupleize(table, ("sources", "exclude_sources", "exclude_title_patterns")))
    if cfg.since_days < MIN_SINCE_DAYS:
        raise SystemExit(f"config: [selection].since_days must be >= 0 (got {cfg.since_days})")
    for pattern in cfg.exclude_title_patterns:
        try:
            re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise SystemExit(f"config: bad exclude_title_patterns regex {pattern!r}: {exc}") from exc
    return cfg


def _build_text(table: dict[str, Any]) -> TextCfg:
    cfg = TextCfg(**_tupleize(table, ("fetch_exclude_sources", "fetch_hosts")))
    if cfg.fulltext_min_chars < MIN_FULLTEXT_MIN_CHARS:
        raise SystemExit(
            f"config: [text].fulltext_min_chars must be >= 0 (got {cfg.fulltext_min_chars})"
        )
    if not TITLE_MATCH_MIN_BOUND <= cfg.title_match_min <= TITLE_MATCH_MAX_BOUND:
        raise SystemExit(
            f"config: [text].title_match_min must be within 0.0-1.0 (got {cfg.title_match_min})"
        )
    if cfg.max_fetch_per_run < MIN_MAX_FETCH_PER_RUN:
        raise SystemExit(
            f"config: [text].max_fetch_per_run must be >= 0 (got {cfg.max_fetch_per_run})"
        )
    return cfg


def _build_disk(table: dict[str, Any]) -> DiskCfg:
    cfg = DiskCfg(**_tupleize(table, ("paths",)))
    if not MIN_WARN_PERCENT <= cfg.warn_percent <= MAX_WARN_PERCENT:
        raise SystemExit(f"config: [disk].warn_percent must be within 0-100 (got {cfg.warn_percent})")
    return cfg


def _build_sectors(table: dict[str, Any]) -> SectorsCfg:
    return SectorsCfg(**_tupleize(table, ("canonical_authors", "extra_roots")))


def _build_actors(table: dict[str, Any]) -> ActorsCfg:
    cfg = ActorsCfg(**table)
    if cfg.create_missing_type not in VALID_CREATE_MISSING_TYPES:
        raise SystemExit(
            f"config: [actors].create_missing_type must be one of "
            f"{sorted(VALID_CREATE_MISSING_TYPES)} (got {cfg.create_missing_type!r})"
        )
    if cfg.crosswalk_max_age_days < MIN_CROSSWALK_MAX_AGE_DAYS:
        raise SystemExit(
            "config: [actors].crosswalk_max_age_days must be >= 1 "
            f"(got {cfg.crosswalk_max_age_days})"
        )
    return cfg


def _build_labels(table: dict[str, Any]) -> LabelsCfg:
    cfg = LabelsCfg(**table)
    if not cfg.prefix:
        raise SystemExit("config: [labels].prefix must be non-empty")
    return cfg


def _build_report_labels(table: dict[str, Any]) -> ReportLabelsCfg:
    cfg = ReportLabelsCfg(**table)
    if not HEX_COLOR_RE.match(cfg.color):
        raise SystemExit(f"config: [report_labels].color must be #RRGGBB (got {cfg.color!r})")
    return cfg


def _build_config(data: dict[str, Any]) -> Config:
    _validate_schema(data)
    return Config(
        platform=PlatformCfg(**data.get("platform", {})),
        runs=RunsCfg(**data.get("runs", {})),
        labels=_build_labels(data.get("labels", {})),
        selection=_build_selection(data.get("selection", {})),
        text=_build_text(data.get("text", {})),
        disk=_build_disk(data.get("disk", {})),
        sectors=_build_sectors(data.get("sectors", {})),
        actors=_build_actors(data.get("actors", {})),
        vulns=VulnsCfg(**data.get("vulns", {})),
        report_labels=_build_report_labels(data.get("report_labels", {})),
    )


# -- loading ------------------------------------------------------------


def _resolve_config_path(path: Path | None) -> tuple[Path | None, bool]:
    """Return (path_to_read_or_None, explicit).

    `explicit` is True when a missing file at that path must error -- true
    for an argument or `$OCTI_RB_CONFIG`, false for the `./config.toml`
    fallback.
    """
    if path is not None:
        return path, True
    env_path = os.environ.get("OCTI_RB_CONFIG")
    if env_path:
        return Path(env_path), True
    default = Path("config.toml")
    if default.is_file():
        return default, False
    return None, False


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit(f"config: {path}: {exc}") from exc


def load_config(path: Path | None) -> Config:
    if path is not None and not isinstance(path, Path):
        raise TypeError("load_config: path must be a Path or None")
    resolved, explicit = _resolve_config_path(path)
    if resolved is None:
        data: dict[str, Any] = {}
    elif not resolved.is_file():
        if explicit:
            raise SystemExit(f"config: {resolved}: no such file")
        data = {}
    else:
        data = _read_toml(resolved)
    cfg = _build_config(data)
    if not cfg.labels.prefix:
        raise SystemExit("config: labels.prefix must be non-empty")
    return cfg


# -- disk check -----------------------------------------------------------


def _check_one_disk_path(path: Path, warn_percent: int, log: Callable[[str], None]) -> None:
    if warn_percent == 0:
        return
    try:
        total, used, free = shutil.disk_usage(path)
    except OSError:
        log(f"warn: disk path {path} does not exist")
        return
    if total == 0:
        return
    percent = used * PERCENT_SCALE // total
    if percent >= warn_percent:
        free_gb = free / BYTES_PER_GB
        log(f"warn: {path} at {percent}% ({free_gb:.1f} GB free), threshold {warn_percent}%")


def check_disk(cfg: Config, log: Callable[[str], None]) -> None:
    if not isinstance(cfg, Config):
        raise TypeError("check_disk: cfg must be a Config")
    if not callable(log):
        raise TypeError("check_disk: log must be callable")
    paths = (cfg.runs_dir, *(Path(p) for p in cfg.disk.paths))
    if len(paths) > MAX_DISK_PATHS:
        raise SystemExit("config: too many disk paths configured")
    for path in paths:
        _check_one_disk_path(path, cfg.disk.warn_percent, log)
