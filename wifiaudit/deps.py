"""Detect the external CLI tools the app orchestrates.

Nothing here touches the radio. It just answers "is the toolchain installed?"
so the GUI can show a clear checklist instead of failing with a cryptic error
the first time you press a button.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .util import which


@dataclass
class Tool:
    name: str          # binary as invoked
    purpose: str       # what this app uses it for
    apt: str           # Kali/Debian package that provides it
    required: bool     # hard requirement vs. nice-to-have

    def present(self) -> bool:
        return which(self.name) is not None


# The core aircrack-ng suite plus iw. hcxpcapngtool is optional (only needed for
# exporting to the hashcat 22000 format).
TOOLS: List[Tool] = [
    Tool("iw", "list adapters, read PHY capabilities, set monitor mode", "iw", True),
    Tool("ip", "bring interfaces up/down for manual monitor mode", "iproute2", True),
    Tool("airmon-ng", "enable/disable monitor mode, kill interfering services", "aircrack-ng", True),
    Tool("airodump-ng", "scan for networks/clients and capture the handshake", "aircrack-ng", True),
    Tool("aireplay-ng", "send targeted deauthentication frames", "aircrack-ng", True),
    Tool("aircrack-ng", "verify a captured 4-way handshake in the .cap", "aircrack-ng", True),
    Tool("hcxpcapngtool", "export capture to hashcat 22000 format (optional)", "hcxtools", False),
    Tool("hcxdumptool", "capture PMKID / clientless (no-deauth) handshakes (optional)", "hcxdumptool", False),
    Tool("macchanger", "randomize or restore the adapter MAC address (optional)", "macchanger", False),
]


def check() -> List[dict]:
    """Return a serializable status list for each known tool."""
    rows = []
    for t in TOOLS:
        rows.append(
            {
                "name": t.name,
                "purpose": t.purpose,
                "apt": t.apt,
                "required": t.required,
                "present": t.present(),
            }
        )
    return rows


def missing_required() -> List[Tool]:
    return [t for t in TOOLS if t.required and not t.present()]


def install_hint() -> str:
    """A copy-pasteable apt line covering whatever core packages are missing."""
    pkgs = sorted({t.apt for t in TOOLS if not t.present()})
    if not pkgs:
        return "All tools present."
    return "sudo apt update && sudo apt install -y " + " ".join(pkgs)
