"""Tests for octirb.tui.extract: claude argv, prompt, stream condensing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from octirb.tui import extract


def _line(obj: Any) -> str:
    return json.dumps(obj)


def _assistant(*blocks: dict[str, Any]) -> str:
    return _line({"type": "assistant", "message": {"content": list(blocks)}})


def test_claude_argv_is_locked_down(tmp_path: Path) -> None:
    argv = extract.claude_argv("/usr/bin/claude", tmp_path, "PROMPT")
    assert argv == [
        "/usr/bin/claude", "-p", "PROMPT",
        "--tools", "Read,Write",
        "--allowedTools", "Read", f"Edit(/{tmp_path.resolve()}/extractions.json)",
        "--permission-mode", "dontAsk",
        "--strict-mcp-config",
        "--output-format", "stream-json", "--verbose",
        "--restricted",
    ]
    assert not any("Bash" in a for a in argv)
    assert not any("bypass" in a.lower() for a in argv)


def test_extract_prompt_names_files_and_forbids_apply(tmp_path: Path) -> None:
    run_dir = tmp_path / "run-1"
    prompt = extract.extract_prompt("report-location", run_dir)
    for needle in ("batch.json", "CONTRACT.md", "extractions.json", "do not run", "run-1",
                   "report-location"):
        assert needle in prompt


def test_extract_prompt_rejects_deterministic_linkers(tmp_path: Path) -> None:
    for linker in ("report-vuln", "report-labels", "nope"):
        with pytest.raises(ValueError):
            extract.extract_prompt(linker, tmp_path)


def test_extract_prompt_accepts_model_linkers(tmp_path: Path) -> None:
    for linker in ("actor-target", "report-sector", "report-actor"):
        assert linker in extract.extract_prompt(linker, tmp_path)


def test_condense_tool_use() -> None:
    out = extract.condense(_assistant(
        {"type": "tool_use", "name": "Read", "input": {"file_path": "/a/b/batch.json"}}))
    assert out == "claude: Read batch.json"


def test_condense_tool_use_without_path() -> None:
    out = extract.condense(_assistant({"type": "tool_use", "name": "Read", "input": {}}))
    assert out is not None and out.startswith("claude: Read")


def test_condense_text_first_line() -> None:
    out = extract.condense(_assistant({"type": "text", "text": "\n\nfirst\nsecond"}))
    assert out == "claude: first"


def test_condense_joins_blocks_and_truncates() -> None:
    out = extract.condense(_assistant(
        {"type": "text", "text": "x" * 500},
        {"type": "tool_use", "name": "Write", "input": {"file_path": "/r/extractions.json"}}))
    assert out is not None and len(out) <= 200


def test_condense_assistant_empty_is_none() -> None:
    assert extract.condense(_assistant()) is None
    assert extract.condense(_assistant({"type": "text", "text": "  "})) is None


def test_condense_result() -> None:
    out = extract.condense(_line({"type": "result", "subtype": "success", "result": "wrote 3\nmore"}))
    assert out == "claude: done (success): wrote 3"
    assert extract.condense(_line({"type": "result", "subtype": "success"})) == "claude: done (success)"


def test_condense_error_result() -> None:
    ev = {"type": "user", "message": {"content": [
        {"type": "tool_result", "content": "Permission to use Write has been denied\nx",
         "is_error": True}]}}
    assert extract.condense(_line(ev)) == "claude: denied/error: Permission to use Write has been denied"
    ev2 = {"type": "user", "message": {"content": [
        {"type": "tool_result", "content": [{"type": "text", "text": "boom"}], "is_error": True}]}}
    assert extract.condense(_line(ev2)) == "claude: denied/error: boom"


def test_condense_non_error_tool_result_is_none() -> None:
    ev = {"type": "user", "message": {"content": [
        {"type": "tool_result", "content": "ok", "is_error": False}]}}
    assert extract.condense(_line(ev)) is None


def test_condense_garbage_passes_through() -> None:
    assert extract.condense("not json") == "not json"
    assert extract.condense("[1]") == "[1]"
    assert extract.condense("x" * 500) == "x" * 200


def test_condense_ignores_system_events() -> None:
    assert extract.condense(_line({"type": "system"})) is None


def test_condense_never_raises_on_odd_shapes() -> None:
    odd = [
        {"type": "assistant"},
        {"type": "assistant", "message": "x"},
        {"type": "assistant", "message": {"content": "x"}},
        {"type": "assistant", "message": {"content": [1, None, {"type": "tool_use"}]}},
        {"type": "assistant", "message": {"content": [{"type": "tool_use", "name": "R",
                                                      "input": {"file_path": 5}}]}},
        {"type": "user", "message": {"content": [{"type": "tool_result", "is_error": True}]}},
        {"type": "user", "message": None},
        {"type": "result", "subtype": 3, "result": 4},
        {"type": 7},
    ]
    for ev in odd:
        extract.condense(_line(ev))
    for raw in ("", "{", "null", "\x00", "{}"):
        extract.condense(raw)
