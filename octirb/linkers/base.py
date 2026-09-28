"""The linkers octi-rb can enrich reports with.

Selecting reports, fetching article text, the run ledger and revert are
identical whatever we are extracting. Only the target vocabulary, the roles
that make sense, and the contract handed to the extractor differ -- so those
are the only things a linker defines. Ported from
`opencti-docker/octigeo/dimensions.py`'s `Dimension` shape, generalized to
`Linker` with a `Config`-aware resolver builder and an optional contract for
linkers that skip the model step entirely (report-vuln).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..client import Client
    from ..config import Config


class Resolved(Protocol):
    """The minimum an entity must expose to be written to a report.

    Read-only properties rather than plain attributes: both implementations
    are frozen dataclasses, which cannot satisfy a settable protocol member.
    """

    @property
    def id(self) -> str: ...

    @property
    def name(self) -> str: ...


class Resolver(Protocol):
    """Maps an extracted key onto an entity that already exists on-platform.

    Both implementations refuse to invent entities: an unresolvable key comes
    back as None and becomes a review item.
    """

    def resolve(self, key: str) -> Resolved | None: ...
    def probes(self) -> list[str]: ...
    def __len__(self) -> int: ...


@runtime_checkable
class Creator(Protocol):
    """A resolver that may also mint an entity when nothing resolves.

    Deliberately separate from Resolver so that resolve() stays
    side-effect-free -- a resolver that created on miss would silently make
    --dry-run write to the platform.
    """

    def conflict(self, name: str) -> str | None: ...
    def create(self, name: str, aliases: list[str]) -> Resolved: ...


@dataclass(frozen=True)
class Linker:
    name: str
    key_field: str
    roles: frozenset[str]
    label_suffix: str
    entity_kind: str
    write_kind: str
    needs_model: bool
    build_resolver: Callable[[Client, Config], Resolver]
    contract: Callable[[Resolver], str] | None
    alias_field: str | None = None
