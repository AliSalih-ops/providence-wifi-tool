"""The capture-session contract.

Everything the GUI drives on the radio — a handshake capture, a PMKID capture,
their demo stand-ins, and any future capture type — is a "session" that the GUI
treats uniformly through the small interface below. Defining it as a runtime-
checkable Protocol (rather than leaving it implied by duck typing) gives one
place to see the contract, lets type checkers catch drift, and makes it obvious
what a new capture type must provide.

To add a NEW capture type (e.g. a WEP IV collector, a WPA3 downgrade probe):
  1. Write a class implementing this Protocol (see CaptureSession/PmkidSession).
  2. Give it its own argv builder as a pure function in capture.py so it is unit-
     testable and fuzzable by stress.py.
  3. Wire a panel + a start/stop/tick handler trio in gui.py, reusing the timer
     registry (_schedule/_cancel) and generation-token pattern.
No GUI plumbing beyond that panel needs to change.
"""

from __future__ import annotations

from typing import Optional, runtime_checkable, Protocol


@runtime_checkable
class Session(Protocol):
    """A pinned, target-scoped radio capture the GUI can start, poll and stop."""

    def start(self) -> None:
        """Begin capturing. Must fail safe (log + leave running() False) rather
        than raise, and must refuse to run unscoped against an invalid target."""

    def running(self) -> bool:
        """True while the underlying capture process is alive."""

    def stop(self) -> None:
        """Terminate the capture and release its file handles. Idempotent."""

    def log_tail(self, n: int = 8) -> str:
        """Last n lines the underlying tool wrote, for diagnosing an early exit."""

    def cap_file(self) -> Optional[str]:
        """Path to the newest capture artifact, or None if nothing yet."""

    def export_22000(self) -> Optional[str]:
        """Convert the capture to hashcat 22000 (target-scoped), or None."""
