"""Small helpers for running external commands safely and consistently.

Everything the app does on the radio ultimately shells out to a standard CLI
tool. Centralizing that here means one place handles timeouts, missing-binary
errors, and logging, so the rest of the code can stay readable.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Sequence


LogFn = Callable[[str], None]


@dataclass
class CmdResult:
    """Outcome of a finished command."""

    argv: Sequence[str]
    rc: int
    out: str
    err: str
    started: float
    ended: float

    @property
    def ok(self) -> bool:
        return self.rc == 0

    @property
    def duration(self) -> float:
        return self.ended - self.started

    def text(self) -> str:
        """Combined stdout+stderr, handy for scraping tool output."""
        return (self.out or "") + (("\n" + self.err) if self.err else "")


def which(name: str) -> Optional[str]:
    """Absolute path of an executable on PATH, or None."""
    return shutil.which(name)


def run(
    argv: Sequence[str],
    timeout: float = 30.0,
    input_text: Optional[str] = None,
    log: Optional[LogFn] = None,
) -> CmdResult:
    """Run a command to completion and capture its output.

    Never raises for the ordinary failure modes (missing binary, non-zero exit,
    timeout); those come back as a CmdResult with a non-zero rc so the caller
    can decide what to do and the GUI can surface a readable message.
    """
    argv = [str(a) for a in argv]
    if log:
        log("$ " + " ".join(argv))
    started = time.time()
    try:
        proc = subprocess.run(
            argv,
            input=input_text,
            capture_output=True,
            text=True,
            # 802.11 SSIDs are arbitrary bytes and tools echo them raw; strict
            # UTF-8 decoding would raise mid-capture and silently fail verify.
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        res = CmdResult(argv, proc.returncode, proc.stdout, proc.stderr, started, time.time())
    except FileNotFoundError:
        res = CmdResult(argv, 127, "", f"command not found: {argv[0]}", started, time.time())
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        err = (e.stderr or "") + f"\n(timed out after {timeout:.0f}s)"
        if isinstance(out, bytes):
            out = out.decode(errors="replace")
        if isinstance(err, bytes):
            err = err.decode(errors="replace")
        res = CmdResult(argv, 124, out, err, started, time.time())
    if log and not res.ok:
        log(f"  -> rc={res.rc} {res.err.strip()[:200]}")
    return res


def spawn(
    argv: Sequence[str],
    log: Optional[LogFn] = None,
    out=None,
) -> Optional[subprocess.Popen]:
    """Start a long-running command in the background and return the Popen.

    Used for airodump-ng (scan/capture) which runs until we stop it. Its output
    is NOT piped back to us: airodump is long-running and chatty, so an undrained
    PIPE fills its ~64 KB buffer and blocks the process (freezing the capture).
    Instead we send output to a caller-provided file handle (so a failed launch
    can be diagnosed), or to /dev/null. Parsing is done off the CSV files
    airodump writes, never this stream.
    """
    argv = [str(a) for a in argv]
    if log:
        log("$ " + " ".join(argv) + "  &")
    try:
        return subprocess.Popen(
            argv,
            stdout=(out if out is not None else subprocess.DEVNULL),
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError:
        if log:
            log(f"  -> command not found: {argv[0]} (is it installed / on PATH?)")
        return None


def terminate(proc: Optional[subprocess.Popen], log: Optional[LogFn] = None) -> None:
    """Politely stop a background process, then kill it if it refuses to die."""
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
    except Exception as e:  # pragma: no cover - defensive
        if log:
            log(f"  (failed to stop pid {proc.pid}: {e})")


_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def reown(path: str) -> None:
    """When running under sudo, give a path back to the invoking user so the
    operator's captures/logs in their home aren't left root-owned (best-effort)."""
    uid = os.environ.get("SUDO_UID")
    gid = os.environ.get("SUDO_GID")
    if uid and hasattr(os, "chown"):
        try:
            os.chown(path, int(uid), int(gid) if gid else -1)
        except OSError:
            pass


def is_mac(value: str) -> bool:
    """True if `value` is a well-formed 48-bit MAC like aa:bb:cc:dd:ee:ff.

    Used to validate BSSIDs / client MACs before they reach aireplay-ng or
    airodump-ng as arguments, so a malformed or hostile scan row can't smuggle
    an option-looking token (e.g. starting with '-') onto a command line.
    """
    return bool(value) and bool(_MAC_RE.match(value.strip()))
