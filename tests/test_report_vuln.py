from octirb.linkers.report_vuln import CVE_RE, VulnVocabulary, build_extractions, extract_cves


def test_extract_upper_and_lower():
    ids = [c for c, _q in extract_cves("cve-2026-1234 and CVE-2026-1234 and CVE-2026-99999")]
    assert ids == ["CVE-2026-1234", "CVE-2026-99999"]


def test_extract_rejects_overlong_and_short():
    assert extract_cves("CVE-2026-123 CVE-2026-123456789") == []


def test_evidence_is_context_slice():
    text = "x" * 200 + " exploited via CVE-2026-5555 in the wild " + "y" * 200
    [(cve, quote)] = extract_cves(text)
    assert cve == "CVE-2026-5555" and "exploited via" in quote and len(quote) < 160


def test_build_extractions_one_item_per_cve():
    batch = [{"report_id": "r1", "title": "t", "text": "CVE-2026-1 nope; CVE-2026-1234 yes"}]
    items = build_extractions(batch)
    assert len(items) == 1
    assert items[0] == {
        "report_id": "r1", "title": "t", "cve": "CVE-2026-1234",
        "role": "mentioned", "confidence": "high",
        "evidence": items[0]["evidence"],
    }


class FakeClient:
    def __init__(self, known):
        self.known = known
        self.calls = 0

    def vulnerabilities_by_name(self, names):
        self.calls += 1
        return {n: {"id": f"id-{n}", "name": n} for n in names if n in self.known}


def test_vocabulary_resolves_and_caches():
    client = FakeClient({"CVE-2026-1234"})
    vocab = VulnVocabulary(client)  # type: ignore[arg-type]
    assert vocab.resolve("CVE-2026-1234").id == "id-CVE-2026-1234"
    assert vocab.resolve("CVE-2026-9999") is None
    assert vocab.resolve("CVE-2026-1234").id == "id-CVE-2026-1234"
    assert client.calls == 2  # one per unseen key, none for the cached repeat
