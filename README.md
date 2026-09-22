# WiFi Audit GUI

A single Linux desktop app that walks the whole WPA/WPA2 **handshake-capture
workflow** in one window, instead of juggling `airmon-ng`, `airodump-ng` and
`aireplay-ng` across three terminals:

```
pick adapter → monitor mode → scan → pick target → deauth → capture → verify → save/export
```

It is a thin GUI over the standard, publicly documented **aircrack-ng** suite
(the same tools `wifite`/`airgeddon` drive). It adds no new attack technique —
it just removes the repetitive terminal work you're doing by hand today.

> ### Authorized use only
> This tool transmits deauthentication frames and captures traffic. Running it
> against a network you don't own or lack **written permission** to test is
> illegal in most places. The app makes you confirm authorization and record a
> scope on every launch. Keep that authorization on file.

---

## Install — one command (Kali / Debian)

```bash
curl -fsSL https://raw.githubusercontent.com/AliSalih-ops/Wifi-Cracker01/main/install.sh | sudo bash
```

That installs the tools it drives, drops the app in `/opt/wifi-cracker01`, and
adds a `wifi-audit` command (and an app-menu entry). Then just:

```bash
wifi-audit           # launch the GUI (asks for your sudo password)
wifi-audit --demo    # simulated data — no radio, no root — preview anywhere
```

Re-run the installer any time to update. Remove it with
`sudo bash /opt/wifi-cracker01/uninstall.sh`.

<details>
<summary><b>Prefer to do it manually?</b> (clone, or pipx)</summary>

There are **no Python dependencies** — only the standard library plus CLI tools
you install with apt:

```bash
sudo apt update
sudo apt install -y python3-tk aircrack-ng iw iproute2 hcxtools hcxdumptool macchanger
git clone https://github.com/AliSalih-ops/Wifi-Cracker01.git
cd Wifi-Cracker01
./run.sh
```

- `aircrack-ng` → `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`
- `hcxtools` → `hcxpcapngtool` (export to hashcat `22000`)
- `hcxdumptool` → clientless **PMKID** capture
- `macchanger` → randomize/restore the adapter **MAC**

Or install the `wifi-audit` command into an isolated environment with pipx
(`sudo apt install pipx`), then run it with sudo:

```bash
pipx install git+https://github.com/AliSalih-ops/Wifi-Cracker01.git
sudo -E env "PATH=$PATH" wifi-audit
```

</details>

## Run

```bash
wifi-audit          # if installed via install.sh / pipx
./run.sh            # from a clone — launches the GUI (re-execs with sudo, radio work needs root)
./run.sh --demo     # simulated data, no radio, no root — preview the UI anywhere
./run.sh --selftest # offline logic tests, then exit
```

Or directly:

```bash
sudo python3 -m wifiaudit          # real
python3 -m wifiaudit --demo        # simulated
python3 -m wifiaudit --selftest    # tests
```

You need a wireless adapter that supports **monitor mode + injection**. Common
known-good chipsets: Atheros AR9271, Ralink RT3070/RT5370, MediaTek MT7612U,
Realtek RTL8812AU (with the `8812au` dkms driver).

## How to use it

1. **Adapter & monitor mode** — pick your card (the list shows driver + whether
   it reports monitor support) and click *Enable monitor mode*. This runs
   `airmon-ng check kill` (stops NetworkManager/wpa_supplicant so they don't
   fight you) and `airmon-ng start`, then detects the resulting `…mon`
   interface. *Test injection* runs `aireplay-ng --test` to confirm the adapter
   can actually inject (a card that can't will never capture a handshake —
   check this before blaming the target). *Restore networking* undoes it.
2. **Scan** — choose a **band** (2.4 GHz / 5 GHz / both — 5 GHz APs are
   invisible unless you scan that band), then *Start scan* to run a
   channel-hopping `airodump-ng` that fills the table live (BSSID, channel,
   privacy, signal, #clients, ESSID). A status line shows the live network
   count. Select your target; its associated clients appear below.
3. **Deauth & capture** — set where captures are saved (defaults to
   `~/wifi-audit-captures`; *Open folder* reveals it). *Start capture* pins
   `airodump-ng` to the target's channel/BSSID and writes a `.cap`; a live timer
   shows elapsed time and handshake state. Pick a client (or tick *broadcast*),
   set a small frame count, and *Send deauth* to nudge a reconnect. The app
   auto-checks every few seconds and flips the indicator to **HANDSHAKE
   CAPTURED** when `aircrack-ng` confirms the 4-way handshake for that BSSID.
4. **PMKID (clientless)** — many WPA2 APs leak a PMKID with no client connected
   and no deauth needed. Select a target, *Start PMKID capture* (runs
   `hcxdumptool` pinned to the channel), and the indicator flips to **PMKID
   CAPTURED** when one is seen. *Export hashcat (.22000)* hands it to `hashcat`.
5. **Save / export** — captures land in your chosen folder; *Save .cap as…*
   copies one elsewhere, and *Export hashcat (.22000)* converts for `hashcat`.

**MAC spoofing** — once in monitor mode, *Randomize MAC* / *Restore MAC*
(via `macchanger`) change the transmitting interface's address; the current MAC
is shown in the adapter bar. Stop any active capture first — the link has to go
down briefly.

> **hcxdumptool note:** its command-line has changed across major versions. This
> app uses the stable `-i`/`-w` (+ `-c` channel) form and **echoes the exact
> command to the log**. If your installed version rejects it or wants the base
> interface instead of the monitor one, the log shows the error so you can
> adjust — the handshake path (steps 1-3) doesn't depend on hcxdumptool.

The one job at a time rule: the radio can either scan, capture a handshake, or
capture a PMKID — not two at once. The app stops the others for you and blocks
conflicting starts.

Cracking itself is intentionally left to you as a separate step, e.g.:

```bash
aircrack-ng -w wordlist.txt capture.cap
# or
hashcat -m 22000 capture.22000 wordlist.txt
```

## Layout

```
wifi-audit-gui/
  run.sh              launcher (handles sudo + tk check)
  selftest.py         offline logic tests
  requirements.txt    system-package notes (no pip deps)
  wifiaudit/
    __main__.py       CLI entry (--demo / --selftest)
    util.py           subprocess helpers (run/spawn/terminate)
    deps.py           external-tool detection + apt hints
    iface.py          adapter discovery + monitor mode + MAC (iw/airmon-ng/macchanger)
    scan.py           airodump-ng scan + CSV parsing
    capture.py        deauth + pinned capture + verify + PMKID (hcxdumptool) + export
    demo.py           simulated data/sessions for --demo
    gui.py            the Tkinter application
    selftest.py       the tests
```

## Notes / limitations

- Everything radio-facing needs **root** and a monitor-capable adapter.
- Deauth defaults are deliberately small and client-targeted — the aim is to
  catch one reconnect, not to hold anyone offline.
- Built and tested for Kali; the parsing/flow logic has offline tests, but the
  live radio path can only be exercised on real hardware.

## License

© 2026 Ali Salih. Source-available under the
**[PolyForm Strict License 1.0.0](LICENSE)** — **not** an open-source license.

- ✅ You may **download and use** it for **personal, non-commercial** purposes.
- ❌ You may **not sell, redistribute, or modify** it (or build on it) without a
  separate license.
- 💼 **Commercial or business use, redistribution, or modifications** require a
  paid license from the author — contact [@AliSalih-ops](https://github.com/AliSalih-ops).

This applies to this project's own code. The external tools it runs
(`aircrack-ng`, `hcxdumptool`, `macchanger`, …) keep their own licenses.
