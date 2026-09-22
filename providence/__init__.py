"""pr0v1dence WiFi Tool - an authorized-pentest handshake capture toolkit.

A single graphical front-end over the standard aircrack-ng suite that walks the
whole WPA/WPA2 handshake-capture workflow:

    adapter -> monitor mode -> scan -> pick target -> deauth -> capture -> verify -> export

It is a convenience wrapper around publicly documented Kali tools (iw, airmon-ng,
airodump-ng, aireplay-ng, aircrack-ng, hcxpcapngtool). It does not implement any
novel attack technique; it just removes the repetitive multi-terminal juggling.

Only use it against networks you are explicitly authorized to test.
"""

__version__ = "1.0.0"
__app_name__ = "pr0v1dence WiFi Tool"
