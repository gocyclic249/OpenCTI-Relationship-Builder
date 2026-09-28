"""Deterministic CVE extraction and linking from vulnerability reports."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..client import JsonDict

if TYPE_CHECKING:
    from ..client import Client

# Regex to match CVE IDs: CVE-YYYY-NNNNN to CVE-YYYY-NNNNNNN (4-7 digits)
# Word boundary \b rejects overlong IDs (digit-digit never boundary) and
# letter continuations like "CVE-2026-1234ABC"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_cves(text: str) -> list[tuple[str, str]]:
    """Extract CVE IDs and their evidence context from text.

    Args:
        text: The text to search for CVE mentions

    Returns:
        Ordered list of (CVE_ID_UPPER, evidence) tuples, deduped by uppercase ID.
        Evidence is up to 60 chars each side of the match, with whitespace/newlines
        collapsed to single spaces.

    Raises:
        TypeError: If text is not a string
    """
    if not isinstance(text, str):
        raise TypeError(f"extract_cves expects str, got {type(text).__name__}")

    seen: set[str] = set()
    result: list[tuple[str, str]] = []

    for match in CVE_RE.finditer(text):
        cve_id = match.group().upper()
        if cve_id in seen:
            continue
        seen.add(cve_id)

        # Get evidence: up to 60 chars each side, collapse whitespace
        start = max(0, match.start() - 60)
        end = min(len(text), match.end() + 60)
        evidence_text = text[start:end]

        # Collapse whitespace/newlines to single spaces
        evidence = " ".join(evidence_text.split())

        result.append((cve_id, evidence))

    # Post-condition: all IDs are uppercase and unique
    ids = [cid for cid, _ in result]
    if not all(cid.isupper() for cid in ids):
        raise ValueError("CVE IDs must be uppercase")
    if len(ids) != len(set(ids)):
        raise ValueError("CVE IDs must be unique")

    return result


def build_extractions(batch: list[JsonDict]) -> list[JsonDict]:
    """Build extraction items from a batch of reports.

    Args:
        batch: List of report dicts with keys "report_id", "title", "text"

    Returns:
        List of extraction dicts, one per unique CVE found. Each dict contains
        "report_id", "title", "cve", "role", "confidence", "evidence".

    Raises:
        TypeError: If batch is not a list of dicts
    """
    if not isinstance(batch, list):
        raise TypeError(f"build_extractions expects list, got {type(batch).__name__}")

    extractions: list[JsonDict] = []

    for report in batch:
        if not isinstance(report, dict):
            raise TypeError(f"build_extractions batch item must be dict, got {type(report).__name__}")

        report_id = report.get("report_id")
        title = report.get("title")
        text = report.get("text")

        if not text:
            continue

        # Extract CVEs from this report
        cves = extract_cves(text)

        for cve_id, evidence in cves:
            extraction: JsonDict = {
                "report_id": report_id,
                "title": title,
                "cve": cve_id,
                "role": "mentioned",
                "confidence": "high",
                "evidence": evidence,
            }
            extractions.append(extraction)

    # Post-condition: check that extractions were built
    if not isinstance(extractions, list):
        raise TypeError("extractions should be a list")

    return extractions


@dataclass(frozen=True)
class Vuln:
    """A resolved vulnerability record from OpenCTI."""

    id: str
    name: str


class VulnVocabulary:
    """Lazy-loading cache for vulnerability lookups.

    Accumulates unseen keys and resolves them in one query per unique key set.
    Caches both hits and misses to avoid re-querying.
    """

    def __init__(self, client: Client) -> None:
        """Initialize with an OpenCTI client.

        Args:
            client: The OpenCTI client instance
        """
        self.client = client
        self._cache: dict[str, Vuln | None] = {}

    def resolve(self, key: str) -> Vuln | None:
        """Resolve a vulnerability by name, with lazy batching and caching.

        Args:
            key: The vulnerability name to resolve

        Returns:
            A Vuln record (id, name) if found, None if not found or empty key

        Raises:
            ValueError: If key is empty or empty after stripping
        """
        if not key or not key.strip():
            raise ValueError("resolve needs a non-empty key")

        # Check cache first
        if key in self._cache:
            return self._cache[key]

        # Key not cached, query it
        result = self.client.vulnerabilities_by_name([key])

        # Cache the result (hit or miss)
        vuln: Vuln | None = None
        if key.upper() in result:
            node = result[key.upper()]
            vuln = Vuln(id=str(node["id"]), name=str(node["name"]))

        self._cache[key] = vuln

        # Post-condition: key now in cache
        if key not in self._cache:
            raise ValueError(f"key {key} should be in cache after resolve")

        return vuln

    def probes(self) -> list[str]:
        """Return list of probes (always empty for vocabulary).

        Returns:
            Empty list (no probes available without platform data)
        """
        return []

    def __len__(self) -> int:
        """Return number of cached hits (non-None entries).

        Returns:
            Count of successfully resolved vulnerabilities
        """
        return sum(1 for v in self._cache.values() if v is not None)
