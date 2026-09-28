import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def fake_gql_client() -> Callable[[dict[str, Any]], tuple[Any, list[tuple[str, Any]]]]:
    """Build an octirb.client.Client whose gql() always returns `response`.

    Returns a (client, calls) factory. `calls` records every
    (query, variables) pair the code under test sent, in call order -- so a
    test can assert both the outcome and what was actually sent over the
    wire, without any network or real OpenCTI settings.
    """

    def factory(response: dict[str, Any]) -> tuple[Any, list[tuple[str, Any]]]:
        from octirb.client import Client
        from octirb.config import Settings

        client = Client(Settings(url="http://x", token="t"))  # noqa: S106 - fixture placeholder, not a secret
        calls: list[tuple[str, Any]] = []

        def fake_gql(query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
            calls.append((query, variables))
            return response

        client.gql = fake_gql  # type: ignore[method-assign]
        return client, calls

    return factory
