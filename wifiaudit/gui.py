"""Tkinter GUI that ties the whole workflow together.

Layout, top to bottom:
  * Adapter bar   - pick interface, enable monitor mode, restore networking
  * Scan panel    - start/stop scan, table of APs, table of clients for the pick
  * Capture panel - deauth + capture the selected AP, live handshake indicator
  * Log           - everything the app runs and every tool's reply

All radio work happens on background threads; results are marshalled back to the
Tk main thread through queues (Tkinter is not thread-safe).
"""

from __future__ import annotations

import os
import queue
import shutil
import subprocess
import threading
import time
from typing import Callable, List, Optional

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import __app_name__, __version__, deps
from .capture import (
    CaptureSession, CaptureTarget, PmkidSession, injection_test, is_valid_channel,
)
from .iface import (
    Interface, current_mac, disable_monitor, enable_monitor, list_interfaces, set_mac,
)
from .scan import BANDS, AccessPoint, ScanSession, Station
from .demo import DemoCaptureSession, DemoPmkidSession, DemoScanSession, demo_interfaces


# Catppuccin-ish dark palette.
C = {
    "bg": "#1e1e2e",
    "panel": "#181825",
    "row": "#11111b",
    "fg": "#cdd6f4",
    "muted": "#7f849c",
    "accent": "#89b4fa",
    "good": "#a6e3a1",
    "warn": "#f9e2af",
    "bad": "#f38ba8",
    "sel": "#313244",
}

SCAN_POLL_MS = 2000
AUTOVERIFY_MS = 5000


class App:
    def __init__(self, root: tk.Tk, demo: bool = False):
        self.root = root
        self.demo = demo

        self.interfaces: List[Interface] = []
        self.mon_iface: Optional[str] = None
        self.scan: Optional[object] = None
        self.capture: Optional[object] = None
        self.pmkid: Optional[object] = None
        self.aps: List[AccessPoint] = []
        self.stations: List[Station] = []
        self.armed = False                 # authorization accepted
        self.scope = ""                    # what the user said they're authorized to test
        # Captures persist here (not /tmp) so they're easy to find afterwards.
        self.out_dir = os.path.join(os.path.expanduser("~"), "wifi-audit-captures")

        self._log_q: "queue.Queue[str]" = queue.Queue()
        self._ui_q: "queue.Queue[Callable]" = queue.Queue()
        self._verify_busy = False
        self._cap_start: Optional[float] = None
        self._hs_ok = False                # whether the target's handshake is captured
        self._pmkid_start: Optional[float] = None
        self._pmkid_ok = False
        self._pmkid_busy = False

        self._build_style()
        self._build_widgets()
        self.root.after(100, self._pump)

        self.log(f"{__app_name__} {__version__}" + ("  [DEMO MODE - nothing is transmitted]" if demo else ""))
        if not demo:
            self._require_authorization()
            self._check_deps()
        else:
            self.armed = True
            self.scope = "DEMO"
            self._set_status()
        self.refresh_interfaces()

    # ------------------------------------------------------------------ style
    def _build_style(self) -> None:
        self.root.title(f"{__app_name__} {__version__}")
        self.root.configure(bg=C["bg"])
        self.root.geometry("980x760")
        self.root.minsize(860, 640)

        st = ttk.Style()
        st.theme_use("clam")
        st.configure(".", background=C["bg"], foreground=C["fg"], fieldbackground=C["panel"],
                     bordercolor=C["sel"], focuscolor=C["accent"])
        st.configure("TFrame", background=C["bg"])
        st.configure("Panel.TLabelframe", background=C["bg"], foreground=C["accent"], bordercolor=C["sel"])
        st.configure("Panel.TLabelframe.Label", background=C["bg"], foreground=C["accent"])
        st.configure("TLabel", background=C["bg"], foreground=C["fg"])
        st.configure("Muted.TLabel", background=C["bg"], foreground=C["muted"])
        st.configure("TButton", background=C["sel"], foreground=C["fg"], borderwidth=0, padding=6)
        st.map("TButton",
               background=[("active", C["accent"]), ("disabled", C["panel"])],
               foreground=[("active", C["bg"]), ("disabled", C["muted"])])
        st.configure("Accent.TButton", background=C["accent"], foreground=C["bg"])
        st.map("Accent.TButton", background=[("active", C["good"])])
        st.configure("Danger.TButton", background=C["bad"], foreground=C["bg"])
        st.configure("TCombobox", fieldbackground=C["panel"], background=C["sel"], foreground=C["fg"])
        st.configure("TCheckbutton", background=C["bg"], foreground=C["fg"])
        st.map("TCheckbutton", background=[("active", C["bg"])])
        st.configure("Treeview", background=C["panel"], fieldbackground=C["panel"],
                     foreground=C["fg"], rowheight=24, borderwidth=0)
        st.map("Treeview", background=[("selected", C["accent"])], foreground=[("selected", C["bg"])])
        st.configure("Treeview.Heading", background=C["sel"], foreground=C["fg"], relief="flat")
        st.map("Treeview.Heading", background=[("active", C["sel"])])

    # ---------------------------------------------------------------- widgets
    def _build_widgets(self) -> None:
        pad = dict(padx=8, pady=4)

        # --- adapter bar ---
        bar = ttk.Labelframe(self.root, text="1 - Adapter & monitor mode", style="Panel.TLabelframe")
        bar.pack(fill="x", **pad)
        self.iface_var = tk.StringVar()
        self.iface_combo = ttk.Combobox(bar, textvariable=self.iface_var, state="readonly", width=48)
        self.iface_combo.grid(row=0, column=0, padx=6, pady=8, sticky="w")
        self.iface_combo.bind("<<ComboboxSelected>>", lambda e: self._update_mac_label())
        ttk.Button(bar, text="Refresh", command=self.refresh_interfaces).grid(row=0, column=1, padx=4)
        self.btn_mon = ttk.Button(bar, text="Enable monitor mode", style="Accent.TButton",
                                  command=self.on_enable_monitor)
        self.btn_mon.grid(row=0, column=2, padx=4)
        self.btn_restore = ttk.Button(bar, text="Restore networking", command=self.on_restore)
        self.btn_restore.grid(row=0, column=3, padx=4)
        self.btn_inject = ttk.Button(bar, text="Test injection", command=self.on_injection_test)
        self.btn_inject.grid(row=0, column=4, padx=4)

        ttk.Label(bar, text="MAC:", style="Muted.TLabel").grid(row=1, column=0, padx=6, sticky="e")
        self.mac_lbl = ttk.Label(bar, text="-")
        self.mac_lbl.grid(row=1, column=1, sticky="w")
        self.btn_macrand = ttk.Button(bar, text="Randomize MAC", command=self.on_randomize_mac)
        self.btn_macrand.grid(row=1, column=2, padx=4, pady=2)
        self.btn_macrestore = ttk.Button(bar, text="Restore MAC", command=self.on_restore_mac)
        self.btn_macrestore.grid(row=1, column=3, padx=4)

        self.status_lbl = ttk.Label(bar, text="", style="Muted.TLabel")
        self.status_lbl.grid(row=2, column=0, columnspan=5, padx=6, sticky="w")

        # --- scan panel ---
        scanf = ttk.Labelframe(self.root, text="2 - Scan for networks", style="Panel.TLabelframe")
        scanf.pack(fill="both", expand=True, **pad)
        row = ttk.Frame(scanf)
        row.pack(fill="x")
        self.btn_scan = ttk.Button(row, text="Start scan", command=self.on_scan_toggle)
        self.btn_scan.pack(side="left", padx=6, pady=6)
        ttk.Label(row, text="Band:", style="Muted.TLabel").pack(side="left")
        self.band_var = tk.StringVar(value="2.4 GHz")
        ttk.Combobox(row, textvariable=self.band_var, state="readonly", width=12,
                     values=list(BANDS.keys())).pack(side="left", padx=4)
        self.scan_status = ttk.Label(row, text="", style="Muted.TLabel")
        self.scan_status.pack(side="left", padx=10)

        cols = ("bssid", "ch", "privacy", "pwr", "clients", "essid")
        self.ap_tree = ttk.Treeview(scanf, columns=cols, show="headings", height=8, selectmode="browse")
        for c, w, t in [("bssid", 150, "BSSID"), ("ch", 45, "Ch"), ("privacy", 90, "Privacy"),
                        ("pwr", 55, "Pwr"), ("clients", 65, "Clients"), ("essid", 260, "ESSID")]:
            self.ap_tree.heading(c, text=t)
            self.ap_tree.column(c, width=w, anchor="w")
        self.ap_tree.pack(fill="both", expand=True, padx=6, pady=4)
        self.ap_tree.bind("<<TreeviewSelect>>", self.on_ap_select)

        ttk.Label(scanf, text="Clients on the selected network:", style="Muted.TLabel").pack(anchor="w", padx=8)
        ccols = ("mac", "pwr", "pkts")
        self.cli_tree = ttk.Treeview(scanf, columns=ccols, show="headings", height=4, selectmode="browse")
        for c, w, t in [("mac", 180, "Client MAC"), ("pwr", 60, "Pwr"), ("pkts", 80, "Packets")]:
            self.cli_tree.heading(c, text=t)
            self.cli_tree.column(c, width=w, anchor="w")
        self.cli_tree.pack(fill="x", padx=6, pady=4)

        # --- capture panel ---
        capf = ttk.Labelframe(self.root, text="3 - Deauth & capture handshake", style="Panel.TLabelframe")
        capf.pack(fill="x", **pad)
        r0 = ttk.Frame(capf)
        r0.pack(fill="x", pady=4)
        self.target_lbl = ttk.Label(r0, text="Target: (none selected)")
        self.target_lbl.pack(side="left", padx=6)

        rout = ttk.Frame(capf)
        rout.pack(fill="x", pady=2)
        ttk.Label(rout, text="Save captures to:", style="Muted.TLabel").pack(side="left", padx=6)
        self.outdir_lbl = ttk.Label(rout, text=self.out_dir)
        self.outdir_lbl.pack(side="left")
        ttk.Button(rout, text="Change...", command=self.on_change_outdir).pack(side="left", padx=4)
        ttk.Button(rout, text="Open folder", command=self.on_open_folder).pack(side="left", padx=4)

        r1 = ttk.Frame(capf)
        r1.pack(fill="x", pady=4)
        self.btn_cap = ttk.Button(r1, text="Start capture", style="Accent.TButton", command=self.on_capture_start)
        self.btn_cap.pack(side="left", padx=6)
        ttk.Label(r1, text="Deauth frames:", style="Muted.TLabel").pack(side="left")
        self.deauth_count = tk.IntVar(value=5)
        ttk.Spinbox(r1, from_=1, to=64, width=5, textvariable=self.deauth_count).pack(side="left", padx=4)
        self.bcast_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(r1, text="broadcast (all clients)", variable=self.bcast_var).pack(side="left", padx=6)
        self.btn_deauth = ttk.Button(r1, text="Send deauth", command=self.on_deauth)
        self.btn_deauth.pack(side="left", padx=4)
        self.btn_verify = ttk.Button(r1, text="Verify handshake", command=self.on_verify)
        self.btn_verify.pack(side="left", padx=4)
        self.btn_capstop = ttk.Button(r1, text="Stop capture", style="Danger.TButton", command=self.on_capture_stop)
        self.btn_capstop.pack(side="left", padx=4)

        r2 = ttk.Frame(capf)
        r2.pack(fill="x", pady=6)
        self.hs_lbl = tk.Label(r2, text="  HANDSHAKE: not captured  ", bg=C["sel"], fg=C["fg"],
                               font=("TkDefaultFont", 10, "bold"), padx=10, pady=6)
        self.hs_lbl.pack(side="left", padx=6)
        self.cap_status = ttk.Label(r2, text="", style="Muted.TLabel")
        self.cap_status.pack(side="left", padx=8)
        self.btn_savecap = ttk.Button(r2, text="Save .cap as...", command=self.on_save_cap)
        self.btn_savecap.pack(side="left", padx=4)
        self.btn_export = ttk.Button(r2, text="Export hashcat (.22000)", command=self.on_export)
        self.btn_export.pack(side="left", padx=4)

        # --- PMKID panel ---
        pmf = ttk.Labelframe(self.root, text="4 - PMKID (clientless - often no deauth needed)",
                             style="Panel.TLabelframe")
        pmf.pack(fill="x", **pad)
        pr = ttk.Frame(pmf)
        pr.pack(fill="x", pady=6)
        self.btn_pmkid = ttk.Button(pr, text="Start PMKID capture", command=self.on_pmkid_start)
        self.btn_pmkid.pack(side="left", padx=6)
        self.btn_pmkid_stop = ttk.Button(pr, text="Stop", style="Danger.TButton", command=self.on_pmkid_stop)
        self.btn_pmkid_stop.pack(side="left", padx=4)
        self.btn_pmkid_check = ttk.Button(pr, text="Check PMKID", command=self.on_pmkid_check)
        self.btn_pmkid_check.pack(side="left", padx=4)
        self.btn_pmkid_export = ttk.Button(pr, text="Export hashcat (.22000)", command=self.on_pmkid_export)
        self.btn_pmkid_export.pack(side="left", padx=4)
        self.pmkid_lbl = tk.Label(pr, text="  PMKID: not captured  ", bg=C["sel"], fg=C["fg"],
                                  font=("TkDefaultFont", 10, "bold"), padx=10, pady=6)
        self.pmkid_lbl.pack(side="left", padx=10)
        self.pmkid_status = ttk.Label(pr, text="", style="Muted.TLabel")
        self.pmkid_status.pack(side="left", padx=6)

        # --- log ---
        logf = ttk.Labelframe(self.root, text="Activity log", style="Panel.TLabelframe")
        logf.pack(fill="both", expand=True, **pad)
        self.log_txt = tk.Text(logf, height=9, bg=C["row"], fg=C["fg"], insertbackground=C["fg"],
                               relief="flat", wrap="word")
        self.log_txt.pack(fill="both", expand=True, padx=6, pady=6)
        self.log_txt.configure(state="disabled")

        self._set_capture_enabled(False)

    # ------------------------------------------------------------- auth gate
    def _require_authorization(self) -> None:
        """Block use until the operator affirms authorization + names a scope."""
        dlg = tk.Toplevel(self.root)
        dlg.title("Authorization required")
        dlg.configure(bg=C["bg"])
        dlg.transient(self.root)
        dlg.grab_set()
        dlg.geometry("560x340")

        msg = (
            "This tool sends deauthentication frames and captures traffic.\n\n"
            "Doing that against a network you do not own or lack written\n"
            "permission to test is illegal in most jurisdictions.\n\n"
            "Confirm you have explicit written authorization for the target,\n"
            "and note the scope (client / SSID / engagement) for your own log:"
        )
        tk.Label(dlg, text=msg, bg=C["bg"], fg=C["fg"], justify="left").pack(padx=16, pady=12, anchor="w")
        scope_var = tk.StringVar()
        tk.Entry(dlg, textvariable=scope_var, bg=C["panel"], fg=C["fg"], insertbackground=C["fg"],
                 width=60).pack(padx=16, pady=4, anchor="w")
        agree = tk.BooleanVar(value=False)
        ttk.Checkbutton(dlg, text="I have written authorization to test the network(s) in scope.",
                        variable=agree).pack(padx=16, pady=8, anchor="w")

        btns = ttk.Frame(dlg)
        btns.pack(pady=10)

        def accept():
            if not agree.get() or not scope_var.get().strip():
                messagebox.showwarning("Authorization", "Tick the box and enter a scope to continue.", parent=dlg)
                return
            self.armed = True
            self.scope = scope_var.get().strip()
            self.log(f"Authorization confirmed. Scope: {self.scope}")
            self._set_status()
            dlg.destroy()

        def decline():
            self.log("Authorization declined - radio actions disabled.")
            dlg.destroy()

        ttk.Button(btns, text="I'm authorized - continue", style="Accent.TButton", command=accept).pack(side="left", padx=6)
        ttk.Button(btns, text="Cancel", command=decline).pack(side="left", padx=6)
        self.root.wait_window(dlg)

    # ----------------------------------------------------------- log / pump
    def log(self, msg: str) -> None:
        """Thread-safe: queue a line to be shown on the main thread."""
        self._log_q.put(str(msg))

    def _pump(self) -> None:
        # drain log lines
        drained = False
        while True:
            try:
                line = self._log_q.get_nowait()
            except queue.Empty:
                break
            drained = True
            self.log_txt.configure(state="normal")
            self.log_txt.insert("end", line.rstrip() + "\n")
            self.log_txt.see("end")
            self.log_txt.configure(state="disabled")
        # run any queued UI callbacks from worker threads
        while True:
            try:
                fn = self._ui_q.get_nowait()
            except queue.Empty:
                break
            try:
                fn()
            except Exception as e:  # pragma: no cover - defensive
                self.log(f"UI callback error: {e}")
        self.root.after(100, self._pump)

    def _run_async(self, work: Callable, done: Optional[Callable] = None) -> None:
        """Run `work()` on a thread; when finished, call `done(result)` on main thread."""
        def runner():
            try:
                result = work()
            except Exception as e:
                self.log(f"Error: {e}")
                result = None
            if done:
                self._ui_q.put(lambda: done(result))
        threading.Thread(target=runner, daemon=True).start()

    # --------------------------------------------------------------- deps
    def _check_deps(self) -> None:
        rows = deps.check()
        missing = [r for r in rows if r["required"] and not r["present"]]
        for r in rows:
            mark = "ok" if r["present"] else ("MISSING" if r["required"] else "optional-missing")
            self.log(f"  [{mark}] {r['name']} - {r['purpose']}")
        if missing:
            self.log("Install the toolchain: " + deps.install_hint())
            messagebox.showwarning(
                "Missing tools",
                "Some required tools are not installed:\n\n"
                + "\n".join(f"  {r['name']}  (apt: {r['apt']})" for r in missing)
                + "\n\nInstall with:\n" + deps.install_hint(),
            )

    # ----------------------------------------------------------- interfaces
    def refresh_interfaces(self) -> None:
        def work():
            return demo_interfaces() if self.demo else list_interfaces(log=self.log)

        def done(ifaces):
            self.interfaces = ifaces or []
            labels = [i.label() for i in self.interfaces]
            self.iface_combo["values"] = labels
            if labels:
                self.iface_combo.current(0)
            else:
                self.iface_var.set("")
                if not self.demo:
                    self.log("No wireless interfaces. On this machine you can pass --demo to preview the UI.")
            self._update_mac_label()
        self._run_async(work, done)

    def _selected_interface(self) -> Optional[Interface]:
        idx = self.iface_combo.current()
        if idx < 0 or idx >= len(self.interfaces):
            return None
        return self.interfaces[idx]

    def on_enable_monitor(self) -> None:
        if not self._guard():
            return
        iface = self._selected_interface()
        if not iface:
            messagebox.showinfo("Adapter", "Select a wireless interface first.")
            return
        if not iface.supports_monitor and not self.demo:
            if not messagebox.askyesno("Monitor mode",
                                       f"{iface.name} ({iface.driver}) does not report monitor support.\n"
                                       "Try anyway?"):
                return
        self.btn_mon.configure(state="disabled")

        def work():
            if self.demo:
                return iface.name + "mon"
            return enable_monitor(iface, log=self.log)

        def done(mon):
            self.btn_mon.configure(state="normal")
            if mon:
                self.mon_iface = mon
                self._set_status()
                self._update_mac_label()
            else:
                messagebox.showerror("Monitor mode", "Could not enable monitor mode. See the log.")
        self._run_async(work, done)

    def on_restore(self) -> None:
        if self.demo:
            self.mon_iface = None
            self._set_status()
            self.log("[demo] networking restored")
            return
        self._stop_all()
        mon = self.mon_iface
        if not mon:
            self.log("No monitor interface to restore.")
            return

        def work():
            disable_monitor(mon, log=self.log)
            return True

        def done(_):
            self.mon_iface = None
            self._set_status()
            self._update_mac_label()
        self._run_async(work, done)

    def _set_status(self) -> None:
        parts = []
        parts.append(f"scope: {self.scope}" if self.scope else "scope: -")
        parts.append(f"monitor: {self.mon_iface}" if self.mon_iface else "monitor: off")
        self.status_lbl.configure(text="   ".join(parts),
                                  foreground=C["good"] if self.mon_iface else C["muted"])
        self._set_capture_enabled(bool(self.mon_iface))

    def on_injection_test(self) -> None:
        if not self._guard() or not self._need_monitor():
            return
        if self.demo:
            self.log("[demo] injection test: OK (simulated)")
            messagebox.showinfo("Injection", "Injection is working (demo).")
            return
        mon = self.mon_iface

        def done(ok):
            if ok:
                messagebox.showinfo("Injection", "Injection is working on this adapter.")
            else:
                messagebox.showwarning("Injection",
                                       "Could not confirm injection. If captures never complete, the\n"
                                       "adapter/driver may not support injection (see the log).")
        self._run_async(lambda: injection_test(mon, log=self.log), done)

    def on_change_outdir(self) -> None:
        d = filedialog.askdirectory(initialdir=self.out_dir if os.path.isdir(self.out_dir)
                                    else os.path.expanduser("~"))
        if d:
            self.out_dir = d
            self.outdir_lbl.configure(text=d)
            self.log(f"Captures will be saved to {d}")

    def on_open_folder(self) -> None:
        target = self.out_dir
        try:
            os.makedirs(target, exist_ok=True)
        except OSError as e:
            messagebox.showerror("Open folder", str(e))
            return
        # Best-effort cross-desktop open; harmless no-op if it's unavailable.
        for opener in ("xdg-open", "open"):
            if shutil.which(opener):
                try:
                    subprocess.Popen([opener, target])
                    return
                except OSError:
                    pass
        self.log(f"Capture folder: {target}")

    # ---------------------------------------------------------------- MAC
    def _transmit_iface(self) -> Optional[str]:
        """The interface that actually transmits: the monitor iface if we're in
        monitor mode, otherwise the selected adapter."""
        if self.mon_iface:
            return self.mon_iface
        i = self._selected_interface()
        return i.name if i else None

    def _update_mac_label(self) -> None:
        if self.demo:
            return
        iface = self._transmit_iface()
        self.mac_lbl.configure(text=current_mac(iface) if iface else "-")

    def _change_mac(self, mode: str) -> None:
        if not self._guard():
            return
        iface = self._transmit_iface()
        if not iface:
            messagebox.showinfo("MAC", "Select an interface (or enable monitor mode) first.")
            return
        if self.demo:
            fake = "02:00:00:%02x:%02x:%02x" % (7, 7, 7) if mode == "random" else "de:ad:be:ef:00:11"
            self.mac_lbl.configure(text=fake)
            self.log(f"[demo] MAC {mode} -> {fake}")
            return
        if (self.capture and self.capture.running()) or (self.pmkid and self.pmkid.running()):
            messagebox.showinfo("MAC", "Stop the active capture before changing the MAC "
                                       "(the link has to go down briefly).")
            return
        self.btn_macrand.configure(state="disabled")
        self.btn_macrestore.configure(state="disabled")

        def done(new):
            self.btn_macrand.configure(state="normal")
            self.btn_macrestore.configure(state="normal")
            self._update_mac_label()
            if not new:
                messagebox.showwarning("MAC", "MAC change failed (is macchanger installed? see log).")
        self._run_async(lambda: set_mac(iface, mode, log=self.log), done)

    def on_randomize_mac(self) -> None:
        self._change_mac("random")

    def on_restore_mac(self) -> None:
        self._change_mac("permanent")

    # --------------------------------------------------------------- scan
    def on_scan_toggle(self) -> None:
        if self.scan and self.scan.running():
            self._stop_scan("Scan stopped.")
            return
        if not self._guard() or not self._need_monitor():
            return
        cls = DemoScanSession if self.demo else ScanSession
        self.scan = cls(self.mon_iface, band=self.band_var.get(), log=self.log)
        self.scan.start()
        if not self.demo and not self.scan.running():
            self._stop_scan("Could not start airodump-ng (see log).")
            messagebox.showerror("Scan", "airodump-ng failed to start. Is aircrack-ng installed and "
                                        "are you running as root?")
            return
        self.btn_scan.configure(text="Stop scan")
        self.scan_status.configure(text=f"scanning {self.band_var.get()}...", foreground=C["warn"])
        self.root.after(SCAN_POLL_MS, self._poll_scan)

    def _stop_scan(self, msg: str = "") -> None:
        if self.scan:
            self.scan.stop()
            self.scan = None
        self.btn_scan.configure(text="Start scan")
        self.scan_status.configure(text="", foreground=C["muted"])
        if msg:
            self.log(msg)

    def _poll_scan(self) -> None:
        if not self.scan:
            return
        # airodump can die (bad iface, card yanked out of monitor); notice it,
        # surface why, and reset the button instead of looping silently.
        if not self.scan.running():
            tail = self.scan.log_tail()
            self._stop_scan("Scan process exited unexpectedly.")
            if tail:
                self.log("airodump said:\n" + tail)
            return
        aps, stations = self.scan.latest()
        self.aps = sorted(aps, key=lambda a: _pwr_key(a.power), reverse=True)
        self.stations = stations
        self._refresh_ap_tree()
        self.scan_status.configure(text=f"scanning {self.band_var.get()} - {len(self.aps)} networks",
                                   foreground=C["warn"])
        self.root.after(SCAN_POLL_MS, self._poll_scan)

    def _refresh_ap_tree(self) -> None:
        selected = self._selected_bssid()
        existing = set(self.ap_tree.get_children())
        seen = set()
        for a in self.aps:
            seen.add(a.bssid)
            vals = (a.bssid, a.channel, a.privacy, a.power, a.clients, a.essid)
            if a.bssid in existing:
                self.ap_tree.item(a.bssid, values=vals)
            else:
                self.ap_tree.insert("", "end", iid=a.bssid, values=vals)
        for iid in existing - seen:
            self.ap_tree.delete(iid)
        if selected and selected in seen:
            self.ap_tree.selection_set(selected)

    def on_ap_select(self, _evt=None) -> None:
        bssid = self._selected_bssid()
        ap = next((a for a in self.aps if a.bssid == bssid), None)
        if ap:
            self.target_lbl.configure(text=f"Target: {ap.essid}  [{ap.bssid}]  ch {ap.channel}  {ap.privacy}")
        # refill clients table for this AP
        self.cli_tree.delete(*self.cli_tree.get_children())
        for s in self.stations:
            if s.bssid == bssid:
                self.cli_tree.insert("", "end", iid=s.mac, values=(s.mac, s.power, s.packets))

    def _selected_bssid(self) -> Optional[str]:
        sel = self.ap_tree.selection()
        return sel[0] if sel else None

    def _selected_client(self) -> Optional[str]:
        sel = self.cli_tree.selection()
        return sel[0] if sel else None

    # -------------------------------------------------------------- capture
    def on_capture_start(self) -> None:
        if not self._guard() or not self._need_monitor():
            return
        if self.pmkid and self.pmkid.running():
            messagebox.showinfo("Capture", "Stop the PMKID capture first - the radio can only do "
                                           "one job at a time.")
            return
        bssid = self._selected_bssid()
        ap = next((a for a in self.aps if a.bssid == bssid), None)
        if not ap:
            messagebox.showinfo("Capture", "Select a target network in the scan table first.")
            return
        if not ap.is_wpa() and not self.demo:
            if not messagebox.askyesno("Capture", f"{ap.essid} is {ap.privacy}, not WPA. There is no "
                                                  "WPA handshake to capture. Continue anyway?"):
                return
        if not is_valid_channel(ap.channel) and not self.demo:
            messagebox.showwarning("Capture", f"'{ap.essid}' has no usable channel ({ap.channel!r}). "
                                              "Re-scan until a real channel shows before capturing.")
            return
        # Free the card from channel-hopping scan so capture can pin the channel.
        if self.scan and self.scan.running():
            self._stop_scan("Scan stopped so capture can lock the channel.")

        try:
            os.makedirs(self.out_dir, exist_ok=True)
        except OSError as e:
            messagebox.showerror("Capture", f"Can't create output folder:\n{e}")
            return

        target = CaptureTarget(bssid=ap.bssid, channel=ap.channel, essid=ap.essid)
        cls = DemoCaptureSession if self.demo else CaptureSession
        self.capture = cls(self.mon_iface, target, out_dir=self.out_dir, log=self.log)
        self.capture.start()
        if not self.demo and not self.capture.running():
            tail = self.capture.log_tail()
            self.capture = None
            messagebox.showerror("Capture", "airodump-ng failed to start the capture (see log).")
            if tail:
                self.log(tail)
            return
        self._hs_ok = False
        self._set_handshake(False)
        self._cap_start = time.time()
        self.btn_cap.configure(state="disabled")
        self.root.after(AUTOVERIFY_MS, self._auto_verify)
        self.root.after(1000, self._capture_tick)

    def on_capture_stop(self) -> None:
        if self.capture:
            self.capture.stop()
            self.log("Capture stopped.")
        self._cap_start = None
        self.btn_cap.configure(state="normal")
        self.cap_status.configure(text="")

    def _capture_tick(self) -> None:
        """Once a second: show elapsed time and notice if the capture died."""
        if not self.capture or self._cap_start is None:
            return
        if not self.demo and not self.capture.running():
            tail = self.capture.log_tail()
            self.cap_status.configure(text="capture process exited", foreground=C["bad"])
            self.btn_cap.configure(state="normal")
            self._cap_start = None
            if tail:
                self.log("airodump (capture) said:\n" + tail)
            return
        elapsed = int(time.time() - self._cap_start)
        state = "handshake captured" if self._hs_ok else "waiting for handshake - send a deauth"
        self.cap_status.configure(text=f"{elapsed // 60:02d}:{elapsed % 60:02d}  {state}",
                                  foreground=C["good"] if self._hs_ok else C["muted"])
        self.root.after(1000, self._capture_tick)

    def on_deauth(self) -> None:
        if not self.capture:
            messagebox.showinfo("Deauth", "Start a capture first, then send deauth.")
            return
        client = None if self.bcast_var.get() else self._selected_client()
        if client is None and not self.bcast_var.get():
            if not messagebox.askyesno("Deauth", "No specific client selected. Broadcast deauth to the AP?"):
                return
        count = max(1, int(self.deauth_count.get()))
        cap = self.capture

        def work():
            cap.deauth(client=client, count=count)
            return True
        self._run_async(work)

    def on_verify(self) -> None:
        if not self.capture:
            return
        cap = self.capture
        self._run_async(lambda: cap.has_handshake(), self._set_handshake)

    def _auto_verify(self) -> None:
        if not self.capture or not self.capture.running():
            return
        if not self._verify_busy:
            self._verify_busy = True
            cap = self.capture

            def work():
                return cap.has_handshake()

            def done(ok):
                self._verify_busy = False
                self._set_handshake(ok)
            self._run_async(work, done)
        self.root.after(AUTOVERIFY_MS, self._auto_verify)

    def _set_handshake(self, ok: bool) -> None:
        # Once captured, stay captured for this session even if a later re-verify
        # transiently reads false (e.g. aircrack busy) - avoids a flickering light.
        if ok and not self._hs_ok:
            self._hs_ok = True
            self.hs_lbl.configure(text="  HANDSHAKE CAPTURED  ", bg=C["good"], fg=C["bg"])
            path = self.capture.cap_file() if self.capture else None
            if path:
                self.log(f"Handshake captured -> {path}")
        elif not ok and not self._hs_ok:
            self.hs_lbl.configure(text="  HANDSHAKE: not captured  ", bg=C["sel"], fg=C["fg"])

    # ---------------------------------------------------------------- PMKID
    def on_pmkid_start(self) -> None:
        if not self._guard() or not self._need_monitor():
            return
        if self.capture and self.capture.running():
            messagebox.showinfo("PMKID", "Stop the handshake capture first - the radio can only do "
                                         "one job at a time.")
            return
        bssid = self._selected_bssid()
        ap = next((a for a in self.aps if a.bssid == bssid), None)
        if not ap:
            messagebox.showinfo("PMKID", "Select a target network in the scan table first.")
            return
        if self.scan and self.scan.running():
            self._stop_scan("Scan stopped so PMKID capture can pin the channel.")
        try:
            os.makedirs(self.out_dir, exist_ok=True)
        except OSError as e:
            messagebox.showerror("PMKID", f"Can't create output folder:\n{e}")
            return
        target = CaptureTarget(bssid=ap.bssid, channel=ap.channel, essid=ap.essid)
        cls = DemoPmkidSession if self.demo else PmkidSession
        self.pmkid = cls(self.mon_iface, target, out_dir=self.out_dir, log=self.log)
        self.pmkid.start()
        if not self.demo and not self.pmkid.running():
            tail = self.pmkid.log_tail()
            self.pmkid = None
            messagebox.showerror("PMKID", "hcxdumptool failed to start (is it installed? see log).")
            if tail:
                self.log(tail)
            return
        self._pmkid_ok = False
        self._set_pmkid(False)
        self._pmkid_start = time.time()
        self.btn_pmkid.configure(state="disabled")
        self.root.after(AUTOVERIFY_MS, self._auto_pmkid)
        self.root.after(1000, self._pmkid_tick)

    def on_pmkid_stop(self) -> None:
        if self.pmkid:
            self.pmkid.stop()
            self.log("PMKID capture stopped.")
        self._pmkid_start = None
        self.btn_pmkid.configure(state="normal")
        self.pmkid_status.configure(text="")

    def on_pmkid_check(self) -> None:
        if not self.pmkid:
            return
        pm = self.pmkid
        self._run_async(lambda: pm.check_pmkid(), self._set_pmkid)

    def _auto_pmkid(self) -> None:
        if not self.pmkid or not self.pmkid.running():
            return
        if not self._pmkid_busy:
            self._pmkid_busy = True
            pm = self.pmkid

            def done(ok):
                self._pmkid_busy = False
                self._set_pmkid(ok)
            self._run_async(lambda: pm.check_pmkid(), done)
        self.root.after(AUTOVERIFY_MS, self._auto_pmkid)

    def _pmkid_tick(self) -> None:
        if not self.pmkid or self._pmkid_start is None:
            return
        if not self.demo and not self.pmkid.running():
            tail = self.pmkid.log_tail()
            self.pmkid_status.configure(text="hcxdumptool exited", foreground=C["bad"])
            self.btn_pmkid.configure(state="normal")
            self._pmkid_start = None
            if tail:
                self.log("hcxdumptool said:\n" + tail)
            return
        elapsed = int(time.time() - self._pmkid_start)
        state = "PMKID captured" if self._pmkid_ok else "listening for PMKID..."
        self.pmkid_status.configure(text=f"{elapsed // 60:02d}:{elapsed % 60:02d}  {state}",
                                    foreground=C["good"] if self._pmkid_ok else C["muted"])
        self.root.after(1000, self._pmkid_tick)

    def _set_pmkid(self, ok: bool) -> None:
        if ok and not self._pmkid_ok:
            self._pmkid_ok = True
            self.pmkid_lbl.configure(text="  PMKID CAPTURED  ", bg=C["good"], fg=C["bg"])
            path = self.pmkid.cap_file() if self.pmkid else None
            if path:
                self.log(f"PMKID captured -> {path}")
        elif not ok and not self._pmkid_ok:
            self.pmkid_lbl.configure(text="  PMKID: not captured  ", bg=C["sel"], fg=C["fg"])

    def on_pmkid_export(self) -> None:
        if not self.pmkid:
            return
        pm = self.pmkid

        def done(path):
            if path:
                messagebox.showinfo("Export", f"Wrote hashcat 22000 file:\n{path}")
            else:
                messagebox.showinfo("Export", "Nothing exported yet. Capture a PMKID first "
                                              "(and install hcxtools).")
        self._run_async(lambda: pm.export_22000(), done)

    def on_save_cap(self) -> None:
        if not self.capture:
            return
        src = self.capture.cap_file()
        if not src or (not self.demo and not os.path.exists(src)):
            messagebox.showinfo("Save", "No capture file yet.")
            return
        dst = filedialog.asksaveasfilename(defaultextension=".cap",
                                           initialfile=os.path.basename(src),
                                           filetypes=[("pcap capture", "*.cap"), ("all", "*.*")])
        if not dst:
            return
        try:
            shutil.copy2(src, dst)
            self.log(f"Saved capture to {dst}")
        except OSError as e:
            messagebox.showerror("Save", str(e))

    def on_export(self) -> None:
        if not self.capture:
            return
        cap = self.capture

        def done(path):
            if path:
                messagebox.showinfo("Export", f"Wrote hashcat 22000 file:\n{path}")
            else:
                messagebox.showinfo("Export", "Nothing exported. Need a complete handshake and hcxtools installed.")
        self._run_async(lambda: cap.export_22000(), done)

    # --------------------------------------------------------------- helpers
    def _guard(self) -> bool:
        if not self.armed:
            messagebox.showwarning("Not authorized",
                                   "Radio actions are disabled. Restart and confirm authorization to use them.")
            return False
        return True

    def _need_monitor(self) -> bool:
        if not self.mon_iface:
            messagebox.showinfo("Monitor mode", "Enable monitor mode first.")
            return False
        return True

    def _set_capture_enabled(self, on: bool) -> None:
        state = "normal" if on else "disabled"
        for b in (self.btn_scan, self.btn_cap, self.btn_deauth, self.btn_verify,
                  self.btn_capstop, self.btn_savecap, self.btn_export, self.btn_inject,
                  self.btn_pmkid, self.btn_pmkid_stop, self.btn_pmkid_check, self.btn_pmkid_export,
                  self.btn_macrand, self.btn_macrestore):
            b.configure(state=state)

    def _stop_all(self) -> None:
        self._stop_scan()
        if self.capture:
            self.capture.stop()
            self.capture = None
        if self.pmkid:
            self.pmkid.stop()
            self.pmkid = None
        self._cap_start = None
        self._pmkid_start = None

    def on_close(self) -> None:
        self._stop_all()
        if self.mon_iface and not self.demo:
            if messagebox.askyesno("Quit", "Restore networking (disable monitor mode) before quitting?"):
                try:
                    disable_monitor(self.mon_iface, log=self.log)
                except Exception:
                    pass
        self.root.destroy()


def _pwr_key(power: str) -> int:
    """airodump power is like '-42'; higher (closer to 0) is stronger signal."""
    try:
        return int(power)
    except (TypeError, ValueError):
        return -999


def run_gui(demo: bool = False) -> None:
    root = tk.Tk()
    app = App(root, demo=demo)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
