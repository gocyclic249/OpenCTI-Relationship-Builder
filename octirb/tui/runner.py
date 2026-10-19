"""One background subprocess at a time, drained line by line into the UI.

Steps run as `python -m octirb <args>` rather than in-process: the CLI
prints to stdout/stderr and raises SystemExit freely, neither of which a
curses screen can survive. A reader thread pushes merged output onto a
queue; the UI loop drains it between keypresses. Only one Job runs at a
time -- apply checkpoints applied.json after each write and two writers on
the same run would race.
"""

from __future__ import annotations

import contextlib
import os
import queue
import subprocess
import sys
import threading
from collections.abc import Callable
from pathlib import Path

MAX_QUEUED_LINES = 100_000
MAX_DRAIN_PER_CALL = 10_000
DONE_PREFIX = "exit "


def octirb_command(sub_argv: list[str], *, config: Path | None) -> tuple[list[str], dict[str, str]]:
    """The full argv + env that runs `octi-rb <sub_argv>` in the current interpreter.

    PYTHONPATH gets the repo root first so `-m octirb` resolves to this
    checkout (or this plugin install) regardless of the working directory.
    """
    if not isinstance(sub_argv, list) or not sub_argv:
        raise ValueError("octirb_command: sub_argv must be a non-empty list")
    repo = str(Path(__file__).resolve().parents[2])
    env = dict(os.environ)
    prior = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = repo if not prior else f"{repo}{os.pathsep}{prior}"
    argv = [sys.executable, "-m", "octirb"]
    if config is not None:
        argv += ["--config", str(config)]
    argv += sub_argv
    if argv[-len(sub_argv):] != sub_argv:
        raise RuntimeError("octirb_command: argv assembly lost the subcommand")
    return argv, env


class Job:
    """Start one subprocess; poll `running`, `drain()` lines, read `exit_code`."""

    def __init__(self) -> None:
        self._lines: queue.Queue[str] = queue.Queue(maxsize=MAX_QUEUED_LINES)
        self._proc: subprocess.Popen[str] | None = None
        self._thread: threading.Thread | None = None
        self.exit_code: int | None = None
        self._transform: Callable[[str], str | None] | None = None

    @property
    def running(self) -> bool:
        # exit_code is set before the `exit N` line is queued (and reset by
        # start), so whoever drained that line already sees running == False.
        return self._thread is not None and self._thread.is_alive() and self.exit_code is None

    def start(
        self,
        argv: list[str],
        env: dict[str, str] | None = None,
        *,
        label: str = "",
        cwd: Path | None = None,
        transform: Callable[[str], str | None] | None = None,
    ) -> None:
        """Launch argv; `label` is what the output pane echoes (defaults to argv).

        `cwd` is the child's working directory. `transform` rewrites each
        output line in the reader thread (None drops it); the `$ label` echo
        and the final `exit N` line are never transformed.
        """
        if not isinstance(argv, list) or not argv:
            raise ValueError("Job.start: argv must be a non-empty list")
        if self.running:
            raise RuntimeError("Job.start: a job is already running")
        if cwd is not None and not cwd.is_dir():
            raise ValueError(f"Job.start: cwd is not a directory: {cwd}")
        self.exit_code = None
        self._transform = transform
        child_env = dict(os.environ if env is None else env)
        # Merged stdout/stderr only keeps its real order if the child does not
        # block-buffer stdout behind the pipe.
        child_env.setdefault("PYTHONUNBUFFERED", "1")
        self._proc = subprocess.Popen(  # noqa: S603 - argv is a list we built, never a shell string
            argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            text=True, env=child_env, bufsize=1, cwd=cwd,
        )
        self._put(f"$ {label or ' '.join(argv)}")
        self._thread = threading.Thread(target=self._pump, name="octi-rb-job", daemon=True)
        self._thread.start()

    def _put(self, line: str) -> None:
        # A UI log that nobody drains must not stall the child; dropping is safe.
        with contextlib.suppress(queue.Full):
            self._lines.put_nowait(line)

    def _emit(self, line: str) -> None:
        """Queue one output line through the optional display transform."""
        fn = self._transform
        if fn is None:
            self._put(line)
            return
        try:
            shown = fn(line)
        except Exception:  # a display-filter bug must not lose the exit code
            shown = f"[unreadable output] {line[:200]}"
        if shown is not None:
            self._put(shown)

    def _pump(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            raise RuntimeError("Job._pump: no process")
        with proc.stdout as out:
            for raw in iter(out.readline, ""):
                self._emit(raw.rstrip("\n"))
        code = proc.wait()
        if not isinstance(code, int):
            raise TypeError("Job._pump: child exit code is not an int")
        self.exit_code = code
        self._put(f"{DONE_PREFIX}{code}")

    def drain(self) -> list[str]:
        """Every line produced since the last call (bounded per call)."""
        lines: list[str] = []
        for _ in range(MAX_DRAIN_PER_CALL):
            try:
                lines.append(self._lines.get_nowait())
            except queue.Empty:
                break
        return lines

    def terminate(self) -> None:
        if self._proc is not None and self.running:
            self._proc.terminate()
