"""Model-extraction helpers for the TUI: claude argv, prompt, stream condensing.

Pure functions, no subprocess. runner.py launches the argv built here; the
`--output-format stream-json` lines it reads back are condensed by `condense`
into one pane line each. The claude process is locked down to reading and to
writing only `extractions.json` in the run directory (no Bash, no bypass).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from ..linkers import REGISTRY

MAX_LINE = 200
MAX_BLOCKS = 50  # content blocks inspected per event; bounds every loop below
_PREFIX = "claude: "


def find_claude() -> str | None:
    """Absolute path of the `claude` executable on PATH, or None."""
    return shutil.which("claude")


def extract_prompt(linker: str, run_dir: Path) -> str:
    """The instruction given to `claude -p` for one run's extraction step."""
    if not isinstance(linker, str) or linker not in REGISTRY:
        raise ValueError(f"extract_prompt: unknown linker {linker!r}")
    if not REGISTRY[linker].needs_model:
        raise ValueError(f"extract_prompt: {linker} has no model extraction step")
    prompt = (
        f"You are doing only the extraction step of octi-rb for run {run_dir.name} "
        f"(linker {linker}). Read batch.json and CONTRACT.md in the current directory "
        "and follow CONTRACT.md exactly. If extractions.json already exists (written by "
        "the structured pass), read it and keep its entries, adding yours. Write the "
        "result as a JSON array to extractions.json. Please do not run commands, do not "
        "run validate or apply, and do not modify any other file. Finish with one line "
        "saying how many entries you wrote."
    )
    if run_dir.name not in prompt or linker not in prompt:
        raise ValueError("extract_prompt: prompt lacks the run name or linker")
    return prompt


def claude_argv(claude: str, run_dir: Path, prompt: str) -> list[str]:
    """Locked-down argv: Read and Write/Edit only <run_dir>/extractions.json, all
    confined to the run dir (the cwd) by --restricted; no Bash, no bypass."""
    if not claude or not prompt:
        raise ValueError("claude_argv: claude path and prompt must be non-empty")
    target = f"Edit(/{run_dir.resolve()}/extractions.json)"
    argv = [
        claude, "-p", prompt,
        "--tools", "Read,Write",
        "--allowedTools", "Read", target,
        "--permission-mode", "dontAsk",
        "--strict-mcp-config",
        "--output-format", "stream-json", "--verbose",
        "--restricted",  # under dontAsk the Read allow rule does not confine reads; this does
    ]
    if any("Bash" in a for a in argv[3:]):
        raise ValueError("claude_argv: Bash must never be granted")
    return argv


def _clip(text: str) -> str:
    return text if len(text) <= MAX_LINE else text[:MAX_LINE]


def _first_line(text: Any) -> str:
    """First non-empty line of `text` (stripped); '' for non-strings."""
    if not isinstance(text, str):
        return ""
    for line in text.splitlines()[:MAX_BLOCKS]:
        if line.strip():
            return line.strip()
    return ""


def _blocks(event: dict[str, Any]) -> list[dict[str, Any]]:
    """The dict content blocks of event['message'], tolerating any shape."""
    message = event.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, list):
        return []
    return [b for b in content[:MAX_BLOCKS] if isinstance(b, dict)]


def _tool_use_text(block: dict[str, Any]) -> str:
    name = block.get("name")
    tool_input = block.get("input")
    path = tool_input.get("file_path") if isinstance(tool_input, dict) else None
    base = Path(path).name if isinstance(path, str) else ""
    return f"{name if isinstance(name, str) else '?'} {base}".rstrip()


def _condense_assistant(event: dict[str, Any]) -> str | None:
    parts: list[str] = []
    for block in _blocks(event):
        kind = block.get("type")
        text = _tool_use_text(block) if kind == "tool_use" else (
            _first_line(block.get("text")) if kind == "text" else "")
        if text:
            parts.append(text)
    return _clip(_PREFIX + "; ".join(parts)) if parts else None


def _condense_result(event: dict[str, Any]) -> str:
    subtype = event.get("subtype")
    out = f"{_PREFIX}done ({subtype if isinstance(subtype, str) else '?'})"
    first = _first_line(event.get("result"))
    return _clip(f"{out}: {first}" if first else out)


def _content_text(content: Any) -> str:
    """Tool-result content as text: a string, or a list of text blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        texts = [b.get("text") for b in content[:MAX_BLOCKS] if isinstance(b, dict)]
        return "\n".join(t for t in texts if isinstance(t, str))
    return ""


def _condense_user(event: dict[str, Any]) -> str | None:
    for block in _blocks(event):
        if block.get("type") == "tool_result" and block.get("is_error") is True:
            return _clip(f"{_PREFIX}denied/error: {_first_line(_content_text(block.get('content')))}")
    return None


def condense(line: str) -> str | None:
    """One stream-json line -> one pane line (<= 200 chars), or None to skip.

    Never raises on any string: non-JSON passes through truncated, unknown
    event types and malformed shapes yield None.
    """
    if not isinstance(line, str):
        raise TypeError("condense: line must be a string")
    try:
        event = json.loads(line)
    except (ValueError, RecursionError):  # not JSON (or absurdly nested): show it raw
        return _clip(line)
    if not isinstance(event, dict):
        return _clip(line)
    kind = event.get("type")
    if kind == "assistant":
        return _condense_assistant(event)
    if kind == "result":
        return _condense_result(event)
    if kind == "user":
        return _condense_user(event)
    return None
