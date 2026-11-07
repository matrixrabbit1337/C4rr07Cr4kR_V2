#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
 ██████╗██╗  ██╗██████╗ ██████╗  ██████╗ ███████╗ ██████╗██████╗  ██╗  ██╗██████╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═████╗╚════██║██╔════╝██╔══██╗ ██║ ██╔╝██╔══██╗
██║     ███████║██████╔╝██████╔╝██║██╔██║   ██╔╝ ██║     ██████╔╝ █████╔╝ ██████╔╝
██║     ╚════██║██╔══██╗██╔══██╗████╔╝██║  ██╔╝  ██║     ██╔══██╗ ██╔═██╗ ██╔══██╗
╚██████╗     ██║██║  ██║██║  ██║╚██████╔╝  ██║   ╚██████╗██║  ██║ ██║  ██╗██║  ██║
 ╚═════╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝ ╚═╝  ╚═╝╚═╝  ╚═╝

  C4rr07CR4cKR  —  "follow the hash down the rabbit hole"
  A CTF cracking orchestrator for Parrot OS / Kali.

  It figures out WHAT a file is (raw hash, WPA pcap, locked zip/rar/7z,
  office/pdf, ssh key, keepass db, ...), picks the RIGHT tool + hashcat/john
  mode, wires up the best available wordlist, and runs it — all from a GUI.

  Everything is legitimate CTF/defensive tradecraft: it only orchestrates the
  standard crackers already shipped in Kali/Parrot against artifacts you hold.

  Run:   sudo python3 c4rr07cr4ckr.py       (it will self-elevate if you forget)
"""

import os
import re
import sys
import json
import shutil
import struct
import threading
import queue
import subprocess
import tempfile
from pathlib import Path

try:
    from PIL import Image, ImageSequence
    PIL_OK = True
except Exception:  # noqa
    PIL_OK = False
try:
    from PIL import ImageTk           # needs Tk; only used at render time
except Exception:  # noqa
    ImageTk = None

APP_NAME = "C4rr07CR4cKR"


def _add_invoking_user_site_packages():
    """When the app self-elevates to root (pkexec/sudo), Python looks in ROOT's
    site-packages — but the user very likely pip-installed customtkinter/pillow
    into THEIR ~/.local (the common case on Parrot/Kali). Add the invoking
    user's site-packages to sys.path so those imports resolve under root.
    This is the fix for 'installed for my user but the app runs as root'."""
    if os.name == "nt":
        return
    # only relevant when we're root but a real user invoked us
    try:
        is_root = (os.geteuid() == 0)
    except Exception:  # noqa
        return
    invoker_home = None
    su = os.environ.get("SUDO_USER")
    uid = os.environ.get("PKEXEC_UID")
    try:
        import pwd
        if su:
            invoker_home = pwd.getpwnam(su).pw_dir
        elif uid:
            invoker_home = pwd.getpwuid(int(uid)).pw_dir
    except Exception:  # noqa
        invoker_home = None
    homes = []
    if invoker_home:
        homes.append(invoker_home)
    # also try the plain HOME and a few usual suspects, harmlessly
    if os.environ.get("HOME"):
        homes.append(os.environ["HOME"])
    seen = set()
    for h in homes:
        if not h or h in seen:
            continue
        seen.add(h)
        base = os.path.join(h, ".local", "lib")
        if not os.path.isdir(base):
            continue
        # add every pythonX.Y/site-packages under ~/.local/lib
        try:
            for pyd in sorted(os.listdir(base)):
                sp = os.path.join(base, pyd, "site-packages")
                if os.path.isdir(sp) and sp not in sys.path:
                    sys.path.append(sp)
        except Exception:  # noqa
            pass


# --------------------------------------------------------------------------- #
#  CONFIG  (persistent theme + text customization)                             #
# --------------------------------------------------------------------------- #
def _real_home():
    """Resolve the invoking human's home even after pkexec/sudo self-elevation.
    On Windows, expanduser('~') already points at the real profile."""
    if os.name == "nt":
        return os.environ.get("USERPROFILE") or os.path.expanduser("~")
    try:
        import pwd
    except Exception:  # noqa
        return os.path.expanduser("~")
    for var in ("SUDO_USER", "PKEXEC_UID"):
        val = os.environ.get(var)
        if not val:
            continue
        try:
            if var == "PKEXEC_UID":
                return pwd.getpwuid(int(val)).pw_dir
            return pwd.getpwnam(val).pw_dir
        except Exception:  # noqa
            pass
    return os.path.expanduser("~")


def _start_dir():
    """Sensible starting directory for file dialogs — the REAL user's Desktop
    if present, else their home. Without this, dialogs default to the CWD or
    root's home (/root) once the app self-elevates via pkexec/sudo, which
    makes it look like the app 'can't see' the user's files."""
    home = _real_home()
    for candidate in ("Desktop", ""):
        d = os.path.join(home, candidate) if candidate else home
        if os.path.isdir(d):
            return d
    return home


CONFIG_DIR = Path(_real_home()) / ".config" / "c4rr07cr4ckr"
CONFIG_PATH = CONFIG_DIR / "config.json"


def tool(name):
    """Resolve a CLI tool by name. Prefers a full path registered in config
    (set by the Windows installer for hashcat/john/etc.), then falls back to
    PATH. On Windows also tries the portable tools dir. Returns the invocable
    string (full path or bare name)."""
    try:
        paths = CFG.data.get("tool_paths", {})   # CFG defined below; safe at call time
        if name in paths and os.path.exists(paths[name]):
            return paths[name]
    except Exception:  # noqa
        pass
    onpath = shutil.which(name) or (shutil.which(name + ".exe") if os.name == "nt" else None)
    if onpath:
        return onpath
    if os.name == "nt":
        try:
            base = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "c4rr07cr4ckr" / "tools"
            for p in base.rglob(name + ".exe"):
                return str(p)
        except Exception:  # noqa
            pass
    return name   # last resort: bare name (will error clearly if truly missing)


def tool_available(name):
    t = tool(name)
    return os.path.isabs(t) or shutil.which(t) is not None

DEFAULT_CFG = {
    "appearance": "dark",                      # dark | light | system
    "font_family": "JetBrains Mono",
    "font_scale": 1.0,
    "window_opacity": 1.0,                      # 0.30..1.0 whole-window transparency
    "layout": {
        "movable": False,        # allow dragging the crack-tab panels
        "locked": False,         # freeze positions (no dragging) once arranged
        "positions": {},         # saved {panel_name: [relx, rely]} from dragging
    },
    "monitor": {
        "size": 180,             # lock canvas px (120..420); the panel scales with it
        "fullwidth": True,       # stretch the cascade across the whole window width
        "lock_style": "padlock", # padlock | shield | circuit | skull | vault
        "scrambler": "matrix",   # matrix | hex | binary | katakana | glitch | braille
    },
    "colors": {
        "carrot": "#ff985b", "leaf": "#72ead6", "ink": "#0a1019",
        "panel": "#111c2c", "panel2": "#1a2a40", "mute": "#a5b5c9",
        "logbg": "#080f19", "logfg": "#d3e6f5", "danger": "#ff8888",
    },
    "gif": {
        "enabled": False,
        "path": "",
        "log_path": "",          # a SECOND gif animated behind the log/terminal area
        "log_dim": 0.62,         # darkening behind the log so text stays readable
        "header": True,          # animate GIF behind the title band (crisp text)
        "fullbg": True,          # dim GIF as the whole-window backdrop
        "dim": 0.55,             # 0..1 darkening over the full-window backdrop
        "header_dim": 0.25,      # lighter dim behind the header text
        "margin": 16,            # px reveal border so the backdrop shows around content
    },
    "governance": {
        "scope_file": "",        # path to scope.yaml/json (enforced RoE)
        "audit_log": "",         # path to append-only audit trail (blank = default)
        "gpg_key": "",           # key id/email to sign reports with (optional)
    },
    "resource": {
        "temp_abort": 90,        # hashcat --hwmon-temp-abort (°C); 0 = off
    },
    "distributed": {
        "hashtopolis_url": "",
        "hashtopolis_key": "",
    },
    "tool_paths": {},          # {toolname: full path} — set by the Windows installer
    "text": {
        "app_title": "🥕 C4rr07CR4cKR",
        "tagline": "follow the hash down the rabbit hole",
        "tab_crack": "🔍 Analyze & Crack",
        "tab_setup": "⚙ Setup / Install",
        "tab_ref": "📖 Cheat Sheet",
        "tab_custom": "🎨 Customize",
        "lbl_target": "Target file",
        "lbl_wordlist": "Wordlist",
        "lbl_engine": "Engine",
        "lbl_compute": "Compute",
        "btn_browse": "Browse",
        "btn_analyze": "Analyze",
        "btn_custom_wl": "Custom…",
        "btn_crack": "🥕  CRACK",
        "btn_stop": "■ STOP",
        "btn_clear": "clear log",
        "ready_banner": "{app} ready. Paste text or open a file, then select Analyze or Decode / Ciphers.",
    },
}


def _deep_merge(base, over):
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


class Config:
    def __init__(self):
        self.data = json.loads(json.dumps(DEFAULT_CFG))  # deep copy
        self.load()

    def load(self):
        try:
            if CONFIG_PATH.exists():
                _deep_merge(self.data, json.loads(CONFIG_PATH.read_text()))
        except Exception:  # noqa
            pass

    def save(self):
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            CONFIG_PATH.write_text(json.dumps(self.data, indent=2))
            # keep it owned by the real user, not root
            try:
                import pwd
                su = os.environ.get("SUDO_USER")
                if su and os.geteuid() == 0:
                    pw = pwd.getpwnam(su)
                    for p in (CONFIG_DIR, CONFIG_PATH):
                        os.chown(p, pw.pw_uid, pw.pw_gid)
            except Exception:  # noqa
                pass
            return True
        except Exception:  # noqa
            return False

    # convenience accessors
    def c(self, key):
        return self.data["colors"].get(key, "#ffffff")

    def t(self, key):
        return self.data["text"].get(key, key)

    def font(self, size, weight="normal"):
        fam = self.data.get("font_family", "JetBrains Mono")
        return (fam, max(6, int(round(size * self.data.get("font_scale", 1.0)))), weight)

    def validate(self):
        """Light schema check: fill missing sections, coerce obvious types, warn."""
        warnings = []
        for k, v in DEFAULT_CFG.items():
            if k not in self.data:
                self.data[k] = json.loads(json.dumps(v))
                warnings.append(f"missing '{k}' -> default")
            elif isinstance(v, dict) and isinstance(self.data.get(k), dict):
                for kk, vv in v.items():
                    self.data[k].setdefault(kk, vv)
        for hexkey in ("carrot", "leaf", "ink", "panel", "panel2", "mute",
                       "logbg", "logfg", "danger"):
            val = self.data.get("colors", {}).get(hexkey, "")
            if not re.fullmatch(r"#[0-9a-fA-F]{6}", str(val)):
                self.data["colors"][hexkey] = DEFAULT_CFG["colors"][hexkey]
                warnings.append(f"colors.{hexkey} invalid -> default")
        try:
            self.data["font_scale"] = float(self.data.get("font_scale", 1.0))
        except Exception:  # noqa
            self.data["font_scale"] = 1.0
            warnings.append("font_scale invalid -> 1.0")
        return warnings


CFG = Config()
CFG.validate()

# theme constants derived from config (existing code reads these)
CARROT = CFG.c("carrot")
LEAF   = CFG.c("leaf")
INK    = CFG.c("ink")
PANEL  = CFG.c("panel")
MUTE   = CFG.c("mute")


# --------------------------------------------------------------------------- #
#  ANIMATED GIF BACKGROUND                                                      #
# --------------------------------------------------------------------------- #
class GifSource:
    """
    Loads a GIF once and hands out size-cached, dimmed PhotoImage frame sets for
    any number of render targets (full-window backdrop + header canvas).

    Tkinter has no true per-widget alpha, so the working approach is: paint the
    GIF on a base layer / canvas and dim it in Pillow so text stays legible.
    """
    def __init__(self, path):
        self.ok = False
        self.src = []          # list of RGBA PIL frames
        self.durations = []
        self._cache = {}       # (w,h,dim) -> [PhotoImage,...]
        if not PIL_OK or not path or not os.path.exists(path):
            return
        try:
            img = Image.open(path)
            for fr in ImageSequence.Iterator(img):
                self.src.append(fr.convert("RGBA").copy())
                self.durations.append(max(20, fr.info.get("duration", 80)))
            self.ok = len(self.src) > 0
        except Exception:  # noqa
            self.ok = False

    def frames(self, w, h, dim):
        if not self.ok or ImageTk is None or w < 2 or h < 2:
            return []
        key = (w, h, round(dim, 2))
        if key in self._cache:
            return self._cache[key]
        overlay = Image.new("RGBA", (w, h), (0, 0, 0, int(255 * max(0.0, min(1.0, dim)))))
        out = []
        for fr in self.src:
            # cover-fit the frame to the target box
            f = self._cover(fr, w, h)
            f = Image.alpha_composite(f, overlay)
            out.append(ImageTk.PhotoImage(f))
        self._cache[key] = out
        return out

    @staticmethod
    def _cover(frame, w, h):
        fw, fh = frame.size
        scale = max(w / fw, h / fh)
        nw, nh = max(1, int(fw * scale)), max(1, int(fh * scale))
        r = frame.resize((nw, nh))
        left, top = (nw - w) // 2, (nh - h) // 2
        return r.crop((left, top, left + w, top + h)).convert("RGBA")


class GifAnimator:
    """Cycles a GifSource's frames onto a tk widget target (Label or Canvas)."""
    def __init__(self, widget, source: GifSource, dim, mode="label", text_items=None):
        self.w = widget
        self.src = source
        self.dim = dim
        self.mode = mode                 # 'label' | 'canvas'
        self.frames = []
        self.i = 0
        self.size = (0, 0)
        self._img_id = None
        self.text_items = text_items or []
        self._running = False

    def start(self):
        if not self.src.ok:
            return
        self._running = True
        self._tick()

    def stop(self):
        self._running = False

    def _cur_size(self):
        self.w.update_idletasks()
        return max(2, self.w.winfo_width()), max(2, self.w.winfo_height())

    def _tick(self):
        if not self._running or not self.w.winfo_exists():
            return
        size = self._cur_size()
        if size != self.size or not self.frames:
            self.size = size
            self.frames = self.src.frames(size[0], size[1], self.dim)
            self.i = 0
            if self.mode == "canvas":
                if self._img_id is None:
                    self._img_id = self.w.create_image(0, 0, anchor="nw")
                for tid in self.text_items:
                    self.w.tag_raise(tid)
        if self.frames:
            fr = self.frames[self.i % len(self.frames)]
            if self.mode == "canvas":
                self.w.itemconfig(self._img_id, image=fr)
                for tid in self.text_items:
                    self.w.tag_raise(tid)
            else:
                self.w.configure(image=fr)
            dur = self.src.durations[self.i % len(self.src.durations)]
            self.i += 1
            self.w.after(dur, self._tick)
        else:
            self.w.after(200, self._tick)

# --------------------------------------------------------------------------- #
#  ROOT SELF-ELEVATION                                                          #
# --------------------------------------------------------------------------- #
def _is_admin_windows():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:  # noqa
        return False


def ensure_root():
    """Re-exec the app elevated: root on Linux (pkexec/sudo), Administrator on
    Windows (UAC 'runas' via ShellExecuteW)."""
    if os.name == "nt":
        if _is_admin_windows():
            return
        try:
            import ctypes
            script = os.path.abspath(__file__)
            params = " ".join(f'"{a}"' for a in [script, *sys.argv[1:]])
            # relaunch elevated; the UAC prompt appears here
            rc = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1)
            if rc > 32:
                sys.exit(0)   # elevated instance launched; quit this one
            # rc<=32 means the user declined UAC — carry on unelevated
            return
        except Exception:  # noqa
            return
    # ---- POSIX ----
    if os.geteuid() == 0:
        return
    script = os.path.abspath(__file__)
    if shutil.which("pkexec"):
        env_disp = os.environ.get("DISPLAY", ":0")
        env_xauth = os.environ.get("XAUTHORITY", os.path.expanduser("~/.Xauthority"))
        os.execvp("pkexec", [
            "pkexec", "env",
            f"DISPLAY={env_disp}",
            f"XAUTHORITY={env_xauth}",
            sys.executable, script, *sys.argv[1:],
        ])
    elif shutil.which("sudo"):
        os.execvp("sudo", ["sudo", "-E", sys.executable, script, *sys.argv[1:]])
    else:
        print("[!] Not root and neither pkexec nor sudo found. Re-run as root.")
        sys.exit(1)


# --------------------------------------------------------------------------- #
#  HARDWARE / GPU DETECTION                                                     #
# --------------------------------------------------------------------------- #
class Hardware:
    """
    Detects compute devices hashcat can actually use.

    Primary source of truth is `hashcat -I` (it reports the CUDA + OpenCL/HIP
    backends hashcat has loaded). We also probe nvidia-smi / rocm / lspci so we
    can (a) show the user their card even if the ICD runtime is missing and
    (b) recommend the correct OpenCL package to install.
    """

    # (vendor-tag, lspci-regex, apt-package-that-provides-the-OpenCL-runtime)
    ICD = [
        ("nvidia", re.compile(r"nvidia",                re.I), "nvidia-opencl-icd"),
        ("amd",    re.compile(r"amd|ati|radeon|advanced micro", re.I), "mesa-opencl-icd"),
        ("intel",  re.compile(r"intel",                 re.I), "intel-opencl-icd"),
    ]

    def __init__(self):
        self.devices = []          # [{'id','type','name','backend'}]
        self.vendors = set()       # {'nvidia','amd','intel'}
        self.gpu_present = False
        self.hashcat_sees_gpu = False
        self.icd_packages = []     # apt packages to install for detected GPUs
        self.integrated = False    # weak iGPU present (set expectations honestly)
        self.raw = ""

    # -- public ------------------------------------------------------------ #
    def scan(self):
        self.devices, self.vendors = [], set()
        self._scan_lspci()          # what silicon is physically present
        self._scan_nvidia_smi()     # nvidia specifics
        self._scan_hashcat_I()      # what hashcat can *use* right now
        self.gpu_present = any(v in self.vendors for v in ("nvidia", "amd", "intel")) \
            or any(d["type"] == "GPU" for d in self.devices)
        self.hashcat_sees_gpu = any(d["type"] == "GPU" for d in self.devices)
        self.icd_packages = [pkg for tag, _rx, pkg in self.ICD if tag in self.vendors]
        return self

    def summary(self):
        lines = []
        if not self.devices and not self.vendors:
            return "No compute devices detected (no hashcat backend, no GPU on PCI bus)."
        if self.vendors:
            lines.append("PCI/driver vendors: " + ", ".join(sorted(self.vendors)))
        if self.devices:
            lines.append("hashcat-visible devices:")
            for d in self.devices:
                lines.append(f"  #{d['id']:<2} [{d['type']:<3}] {d['name']}  ({d['backend']})")
        else:
            lines.append("hashcat currently sees NO devices — OpenCL/CUDA runtime likely missing.")
        if self.gpu_present and not self.hashcat_sees_gpu:
            pk = ", ".join(self.icd_packages) or "the matching OpenCL ICD"
            lines.append(f"! GPU present but hashcat can't use it yet — install: {pk}")
        if self.integrated:
            lines.append("i Note: an integrated GPU (shared RAM, no discrete VRAM) cracks only "
                         "marginally faster than your CPU. pocl (CPU OpenCL) is a fine choice here; "
                         "big speedups need a discrete NVIDIA/AMD card.")
        return "\n".join(lines)

    def gpu_device_ids(self):
        return [str(d["id"]) for d in self.devices if d["type"] == "GPU"]

    # -- probes ------------------------------------------------------------ #
    def _scan_lspci(self):
        if not shutil.which("lspci"):
            return
        try:
            out = subprocess.run(["lspci"], capture_output=True, text=True, timeout=8).stdout
        except Exception:  # noqa
            return
        for line in out.splitlines():
            # only consider genuine display-controller rows
            if not re.search(r"\b(VGA compatible controller|3D controller|Display controller)\b", line):
                continue
            # match the vendor only within the device description (after the class),
            # so an unrelated 'Advanced...' elsewhere on the line can't false-trigger AMD
            desc = line.split(":", 2)[-1]
            for tag, rx, _pkg in self.ICD:
                if rx.search(desc):
                    self.vendors.add(tag)
                    # flag weak integrated GPUs so we can set expectations honestly
                    if re.search(r"\b(UHD|HD Graphics|Iris|Vega \d|Radeon Graphics|"
                                 r"integrated)\b", desc, re.I):
                        self.integrated = True

    def _scan_nvidia_smi(self):
        if not shutil.which("nvidia-smi"):
            return
        try:
            out = subprocess.run(
                ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                capture_output=True, text=True, timeout=8).stdout.strip()
            if out:
                self.vendors.add("nvidia")
        except Exception:  # noqa
            pass

    def _scan_hashcat_I(self):
        if not tool_available("hashcat"):
            return
        try:
            out = subprocess.run(["hashcat", "-I"], capture_output=True,
                                  text=True, timeout=25).stdout
        except Exception:  # noqa
            return
        self.raw = out
        backend = "OpenCL"
        cur = {}
        for line in out.splitlines():
            s = line.strip()
            bm = re.match(r"(CUDA|OpenCL|HIP) Info", s)
            if bm:
                backend = bm.group(1)
                continue
            m = re.match(r"(?:Backend )?Device ID #?(\d+)", s)
            if m:
                if cur:
                    self.devices.append(cur)
                cur = {"id": int(m.group(1)), "type": "CPU", "name": "?", "backend": backend}
                continue
            if cur:
                nm = re.match(r"Name\.+:\s*(.+)", s)
                if nm:
                    cur["name"] = nm.group(1).strip()
                tm = re.match(r"Type\.+:\s*(\w+)", s)
                if tm:
                    cur["type"] = tm.group(1).strip().upper()[:3]
                    if cur["type"] not in ("GPU", "CPU"):
                        cur["type"] = "GPU" if "GPU" in tm.group(1).upper() else "CPU"
        if cur:
            self.devices.append(cur)
        # infer vendors from device names too
        for d in self.devices:
            for tag, rx, _pkg in self.ICD:
                if rx.search(d["name"]):
                    self.vendors.add(tag)


# --------------------------------------------------------------------------- #
#  DEPENDENCY MANAGER                                                           #
# --------------------------------------------------------------------------- #
class Deps:
    # packages that are commonly absent from modern repos — their failure is
    # expected and harmless (functionality is covered elsewhere).
    OPTIONAL = {"hashcat-utils", "stegseek"}   # not always in default repos; safe to skip
    # apt package  ->  a binary it provides (used to test presence)
    APT = {
        "hashcat":        "hashcat",
        "john":           "john",
        "hashcat-utils":  "cap2hccapx",     # optional legacy helper
        "hcxtools":       "hcxpcapngtool",
        "aircrack-ng":    "aircrack-ng",
        "hydra":          "hydra",            # online login testing (authorized only)
        "gnupg":          "gpg",              # signed reports
        "hashid":         "hashid",
        "tshark":         "tshark",           # deep pcap credential extraction
        "apktool":        "apktool",          # Android APK decompilation (mobile CTF)
        "crunch":         "crunch",           # custom wordlist generation
        "steghide":       "steghide",         # image/audio steganography
        "stegseek":       "stegseek",         # fast steghide passphrase cracker
        "binwalk":        "binwalk",          # embedded-data / firmware carving
        "foremost":       "foremost",         # file carving from images/disks
        "wordlists":      None,             # provides /usr/share/wordlists
        "libimage-exiftool-perl": "exiftool",
        "python3-tk":     None,
        # --- GPU / OpenCL plumbing (vendor ICDs added dynamically at install) --
        "ocl-icd-libopencl1": None,         # the OpenCL ICD loader hashcat needs
        "clinfo":         "clinfo",         # lists OpenCL platforms/devices
        "pocl-opencl-icd": None,            # portable CL -> CPU fallback device
    }
    PIP = ["customtkinter", "name-that-hash", "pillow", "pyyaml"]

    @staticmethod
    def have(binary):
        # honor tool paths registered by the Windows installer, not just PATH
        base = binary[:-4] if binary.endswith(".exe") else binary
        return tool_available(base) or shutil.which(binary) is not None

    @staticmethod
    def _dpkg_installed(pkg):
        """Definitive check for packages with no probeable binary (data-only
        packages like `wordlists`, or loader packages like `ocl-icd-libopencl1`)."""
        try:
            r = subprocess.run(["dpkg-query", "-W", "-f=${Status}", pkg],
                              capture_output=True, text=True, timeout=5)
            return r.returncode == 0 and "install ok installed" in r.stdout
        except Exception:  # noqa
            return None

    # extra existence checks for packages with no single binary to probe
    _FILE_CHECK = {
        "wordlists": lambda: os.path.isdir("/usr/share/wordlists") and
                            any(Path("/usr/share/wordlists").iterdir()),
    }

    @classmethod
    def status(cls):
        rows = []
        for pkg, binary in cls.APT.items():
            if binary is not None:
                ok = cls.have(binary)
            elif pkg in cls._FILE_CHECK:
                try:
                    ok = cls._FILE_CHECK[pkg]()
                except Exception:  # noqa
                    ok = None
            else:
                ok = cls._dpkg_installed(pkg)  # definitive yes/no via dpkg, not a bare "?"
            rows.append((pkg, binary or "(files)", ok))
        return rows

    # ---- Windows portable tool sources (verified current, Aug 2026) --------
    # hashcat & John ship as portable archives on Windows, NOT installer/winget
    # packages, so we download + extract them and register their paths.
    WIN_TOOLS = {
        "hashcat": {
            "probe": "hashcat.exe",
            # current stable (Aug 2025+); 7.x adds 70+ hash types (MetaMask,
            # 1Password, GPG, LUKS2, KeePass KDBX4) and big speedups over 6.2.6.
            "url": "https://github.com/hashcat/hashcat/releases/download/v7.1.2/hashcat-7.1.2.7z",
            "kind": "7z",
        },
        "john": {
            "probe": "john.exe",
            # Openwall's permanent archive has the full, correctly-named file.
            # (The GitHub release assets are just 'win_x64.zip'.)
            "url": "https://download.openwall.net/pub/projects/john/1.9.0/john-1.9.0-jumbo-1-win64.zip",
            "kind": "zip",
        },
    }
    # winget IDs for the pieces that ARE packaged
    WIN_WINGET = {
        "nmap": "Insecure.Nmap",
        "wireshark": "WiresharkFoundation.Wireshark",   # provides tshark
        "7zip": "7zip.7zip",                            # needed to extract hashcat .7z
    }

    @classmethod
    def install(cls, log):
        if os.name == "nt":
            return cls._install_windows(log)
        return cls._install_posix(log)

    # ===================== WINDOWS INSTALL ============================== #
    @classmethod
    def _win_tools_dir(cls):
        base = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "c4rr07cr4ckr" / "tools"
        try:
            base.mkdir(parents=True, exist_ok=True)
        except Exception:  # noqa
            base = Path(_real_home()) / ".c4rr07cr4ckr" / "tools"
            base.mkdir(parents=True, exist_ok=True)
        return base

    @classmethod
    def _install_windows(cls, log):
        import urllib.request
        log("[*] Windows setup — hashcat/john are portable downloads, not winget packages.\n")
        tools = cls._win_tools_dir()
        log(f"[*] Tools directory: {tools}\n")

        # 1) pip deps (customtkinter/pillow/etc.) — same on every OS
        for mod in cls.PIP:
            log(f"[*] pip install {mod} ...\n")
            cls._run([sys.executable, "-m", "pip", "install", "--upgrade", mod], log)

        # 2) winget packages (nmap, wireshark/tshark, 7zip) if winget exists
        if shutil.which("winget"):
            for name, wid in cls.WIN_WINGET.items():
                if name == "wireshark" and shutil.which("tshark"):
                    continue
                if name == "nmap" and shutil.which("nmap"):
                    continue
                if name == "7zip" and (shutil.which("7z") or cls._find_7z()):
                    continue
                log(f"[*] winget install {wid} ...\n")
                cls._run(["winget", "install", "-e", "--id", wid,
                          "--accept-package-agreements", "--accept-source-agreements",
                          "--silent"], log)
        else:
            log("[!] winget not found — install 'App Installer' from the Microsoft Store to\n"
                "    enable nmap/wireshark auto-install. Continuing with hashcat/john.\n")

        # 3) portable tools: hashcat (.7z) + john (.zip)
        for name, spec in cls.WIN_TOOLS.items():
            if cls._win_find_tool(spec["probe"]):
                log(f"[+] {name}: already present on PATH/tools — skipping.\n")
                continue
            dest = tools / f"{name}_download"
            archive = tools / os.path.basename(spec["url"])
            log(f"[*] Downloading {name} from {spec['url']} ...\n")
            try:
                urllib.request.urlretrieve(spec["url"], archive)
                log(f"    saved {archive} ({archive.stat().st_size//1024//1024} MB)\n")
            except Exception as e:  # noqa
                log(f"[!] download failed: {e}\n")
                log(f"    Manually download {spec['url']} and extract into {tools}.\n")
                continue
            log(f"[*] Extracting {name} ...\n")
            ok = cls._win_extract(archive, dest, spec["kind"], log)
            if ok:
                found = cls._win_find_tool(spec["probe"], search_root=dest)
                log(f"[+] {name} ready: {found}\n" if found
                    else f"[!] extracted but {spec['probe']} not found — check {dest}\n")

        # 4) GPU runtime guidance (can't silently auto-install vendor SDKs)
        hw = Hardware().scan()
        log("\n[*] GPU compute runtime (install the one matching your card):\n")
        log("      NVIDIA : latest GeForce/Studio driver + CUDA (bundled) — usually already present\n")
        log("      AMD    : AMD Adrenalin Edition + AMD HIP SDK for Windows\n")
        log("      Intel  : Intel Graphics driver (Compute Runtime / NEO)\n")
        log("      CPU    : Intel CPU Runtime for OpenCL, or PoCL\n")
        if hw.vendors:
            log(f"    detected: {', '.join(sorted(hw.vendors))}\n")

        # 5) persist discovered tool paths into config so the app finds them
        cls._win_register_paths(log)
        log("\n[+] Windows dependency setup complete. Restart the app if paths changed.\n")

    @staticmethod
    def _find_7z():
        for p in (r"C:\Program Files\7-Zip\7z.exe", r"C:\Program Files (x86)\7-Zip\7z.exe"):
            if os.path.exists(p):
                return p
        return shutil.which("7z")

    @classmethod
    def _win_extract(cls, archive, dest, kind, log):
        dest.mkdir(parents=True, exist_ok=True)
        try:
            if kind == "zip":
                import zipfile
                with zipfile.ZipFile(archive) as z:
                    z.extractall(dest)
                return True
            else:  # 7z — needs the 7-Zip binary (use 7z x to preserve paths)
                seven = cls._find_7z()
                if not seven:
                    log("[!] 7-Zip not found to extract hashcat's .7z. Install 7zip "
                        "(winget install 7zip.7zip) and retry.\n")
                    return False
                rc = cls._run([seven, "x", str(archive), f"-o{dest}", "-y"], log)
                return rc == 0
        except Exception as e:  # noqa
            log(f"[!] extract failed: {e}\n")
            return False

    @classmethod
    def _win_find_tool(cls, exe, search_root=None):
        onpath = shutil.which(exe)
        if onpath:
            return onpath
        roots = [search_root] if search_root else [cls._win_tools_dir()]
        for root in roots:
            if not root:
                continue
            for p in Path(root).rglob(exe):
                return str(p)
        return None

    @classmethod
    def _win_register_paths(cls, log):
        """Find hashcat/john/tshark/nmap and store their full paths in config so
        the rest of the app can call them even if they're not on PATH. Also
        registers the common *2john helper scripts from John's 'run' folder."""
        found = {}
        for exe in ("hashcat.exe", "john.exe", "tshark.exe", "nmap.exe"):
            p = cls._win_find_tool(exe)
            if p:
                found[exe.replace(".exe", "")] = p
        # register *2john helpers found next to john.exe (the portable run/ dir)
        john_path = found.get("john")
        if john_path:
            run_dir = Path(john_path).parent
            for script in run_dir.glob("*2john*"):
                if script.is_file():
                    found[script.stem] = str(script)
        if found:
            CFG.data.setdefault("tool_paths", {}).update(found)
            CFG.save()
            for k, v in list(found.items())[:12]:
                log(f"    registered {k}: {v}\n")
            if len(found) > 12:
                log(f"    …and {len(found) - 12} more helpers registered.\n")

    # ===================== POSIX INSTALL =============================== #
    @classmethod
    def _install_posix(cls, log):

        log("[*] apt-get update ...\n")
        rc = cls._run(["apt-get", "update", "-y"], log)
        if rc != 0:
            log(f"[!] apt-get update exited {rc} — package cache may be stale/broken.\n")
            log("    Check your network connection and /etc/apt/sources.list, then retry.\n")

        pkgs = list(cls.APT.keys())
        # detect GPU and add the correct vendor OpenCL runtime
        hw = Hardware().scan()
        if hw.icd_packages:
            log(f"[*] GPU detected ({', '.join(sorted(hw.vendors))}) -> adding OpenCL runtime: "
                f"{', '.join(hw.icd_packages)}\n")
            pkgs += hw.icd_packages
        else:
            log("[*] No discrete GPU vendor matched — installing CPU OpenCL (pocl) only.\n")

        log(f"[*] Installing ({len(pkgs)} packages): {' '.join(pkgs)}\n")
        rc = cls._run(["apt-get", "install", "-y", *pkgs], log)

        results = {}
        if rc == 0:
            log("[+] Batch install succeeded — all packages installed.\n")
            for p in pkgs:
                results[p] = True
        else:
            # One bad/renamed package name can fail the WHOLE batch atomically,
            # silently taking every other package down with it. Fall back to
            # installing one at a time so a single miss doesn't sink the rest.
            log(f"[!] Batch install failed (exit {rc}) — retrying package-by-package "
               "so one bad name doesn't block everything else...\n")
            for p in pkgs:
                r = cls._run(["apt-get", "install", "-y", p], log)
                results[p] = (r == 0)
                log(f"    [{'OK  ' if results[p] else 'FAIL'}] {p}\n")

        failed = [p for p, ok in results.items() if not ok]
        real_failed = [p for p in failed if p not in cls.OPTIONAL]
        opt_failed = [p for p in failed if p in cls.OPTIONAL]
        log("\n[*] Install summary:\n")
        log(f"    succeeded: {len(results) - len(failed)}/{len(results)}\n")
        if opt_failed:
            log(f"    skipped (optional, safe to ignore): {', '.join(opt_failed)}\n")
            log("      → hashcat-utils is deprecated on Kali/Parrot; hcxtools covers its job.\n")
        if real_failed:
            log(f"    FAILED   : {', '.join(real_failed)}\n")
            log("    (usually means that exact package name isn't in your configured repos —\n"
               "     check `apt-cache search <name>` for the right name on your distro/version)\n")

        # pip (best-effort; --break-system-packages for PEP668 distros)
        for mod in cls.PIP:
            log(f"[*] pip install {mod} ...\n")
            r = cls._run([sys.executable, "-m", "pip", "install", "--break-system-packages", mod], log)
            if r != 0:
                log(f"    [!] pip install {mod} failed (exit {r}).\n")

        # Unpack rockyou if only the .gz exists (classic Kali situation)
        gz = Path("/usr/share/wordlists/rockyou.txt.gz")
        txt = Path("/usr/share/wordlists/rockyou.txt")
        if gz.exists() and not txt.exists():
            log("[*] Decompressing rockyou.txt.gz ...\n")
            cls._run(["gunzip", "-k", str(gz)], log)
        log("[+] Dependency setup complete.\n")

    @staticmethod
    def _run(cmd, log):
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in iter(p.stdout.readline, ""):
                log(line)
            p.wait()
            return p.returncode
        except Exception as e:  # noqa
            log(f"[!] {' '.join(cmd)} -> {e}\n")
            return -1


# --------------------------------------------------------------------------- #
#  JOHN *2john HELPER RESOLVER                                                  #
# --------------------------------------------------------------------------- #
_HELPER_CACHE = {}


def _john_run_dir():
    """Directory that holds John's helper scripts, derived from the john binary
    we resolved (works for the Windows portable 'run' folder and Linux installs)."""
    dirs = []
    jb = tool("john")
    if os.path.isabs(jb) and os.path.exists(jb):
        dirs.append(os.path.dirname(jb))          # .../run/ on Windows, /usr/bin on Linux
    return dirs


def resolve_helper(name):
    """
    Locate a *2john helper (e.g. 'zip2john', 'ssh2john', 'office2john',
    'bitcoin2john'). Returns a runnable command list, or None.
    Handles compiled binaries, .py scripts, Linux distro paths, and the
    Windows portable John 'run' directory. Results are cached.
    """
    if name in _HELPER_CACHE:
        return _HELPER_CACHE[name]

    def _cache(v):
        _HELPER_CACHE[name] = v
        return v

    # 1) a full path registered in config (Windows installer / user override)
    tp = CFG.data.get("tool_paths", {}) if 'CFG' in globals() else {}
    for key in (name, name + ".py"):
        p = tp.get(key)
        if p and os.path.exists(p):
            return _cache([sys.executable, p] if p.endswith(".py") else [p])

    # 2) direct binary / script on PATH
    if shutil.which(name):
        return _cache([shutil.which(name)])
    pyp = shutil.which(name + ".py")
    if pyp:
        return _cache([sys.executable, pyp] if pyp.endswith(".py") else [pyp])

    # 3) known directories (Linux distros + the resolved john's own dir + Windows)
    search_dirs = _john_run_dir() + [
        "/usr/share/john", "/usr/lib/john", "/usr/bin", "/usr/local/bin",
        "/opt/john/run", "/usr/share/john/run",
        os.path.expanduser("~/john/run"),
    ]
    if os.name == "nt":
        try:
            base = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "c4rr07cr4ckr" / "tools"
            search_dirs += [str(p.parent) for p in base.rglob("john.exe")]
            search_dirs += [str(p) for p in base.rglob("run") if p.is_dir()]
        except Exception:  # noqa
            pass
    for d in search_dirs:
        for fn in (f"{name}.py", name, f"{name}.exe"):
            c = os.path.join(d, fn)
            if os.path.exists(c):
                return _cache([sys.executable, c] if c.endswith(".py") else [c])

    # 4) last resort: glob under any john dir we know
    for d in search_dirs:
        try:
            for c in Path(d).glob(f"{name}*"):
                if c.is_file():
                    cs = str(c)
                    return _cache([sys.executable, cs] if cs.endswith(".py") else [cs])
        except Exception:  # noqa
            pass
    return _cache(None)


def helper_available(name):
    return resolve_helper(name) is not None


# --------------------------------------------------------------------------- #
#  HASH IDENTIFICATION                                                          #
# --------------------------------------------------------------------------- #
class HashID:
    """Heuristic hash -> (label, hashcat-mode, john-format) candidates."""

    # prefix-anchored formats (unambiguous)
    PREFIX = [
        (re.compile(r"^\$1\$"),                 "md5crypt",        500,  "md5crypt"),
        (re.compile(r"^\$2[aby]\$"),            "bcrypt",          3200, "bcrypt"),
        (re.compile(r"^\$5\$"),                 "sha256crypt",     7400, "sha256crypt"),
        (re.compile(r"^\$6\$"),                 "sha512crypt",     1800, "sha512crypt"),
        (re.compile(r"^\$y\$"),                 "yescrypt",        None, "crypt"),
        (re.compile(r"^\$argon2"),              "argon2",          None, "argon2"),
        (re.compile(r"^\$pbkdf2-sha256\$", re.I), "pbkdf2-sha256", 10900, "pbkdf2-hmac-sha256"),
        (re.compile(r"^\$sha1\$"),              "atlassian/sha1",  None, None),
        (re.compile(r"^\{SSHA\}"),              "ssha (ldap)",     111,  "ssha"),
        (re.compile(r"^\$P\$"), "phpass (WP/phpBB)", 400, "phpass"),
        (re.compile(r"^\$H\$"), "phpass (WP/phpBB)", 400, "phpass"),
        (re.compile(r"^\$krb5tgs\$"),           "kerberos tgs-rep", 13100, "krb5tgs"),
        (re.compile(r"^\$krb5asrep\$"),         "kerberos asrep",   18200, "krb5asrep"),
        (re.compile(r"^\$NT\$"),                "ntlm",             1000, "nt"),
        (re.compile(r"^\$DCC2\$"),              "mscash2",          2100, "mscash2"),
        (re.compile(r"^[0-9a-f]{32}:[0-9a-f]{32}$", re.I), "ntlmv1-ish", 5500, "netntlm"),
    ]

    # length+charset heuristics (ambiguous -> multiple candidates)
    HEX = {
        32:  [("MD5", 0, "raw-md5"), ("NTLM", 1000, "nt"), ("MD4", 900, "raw-md4"),
              ("LM", 3000, "lm")],
        40:  [("SHA1", 100, "raw-sha1"), ("MySQL4.1+", 300, "mysql-sha1"),
              ("RIPEMD-160", 6000, "ripemd-160")],
        56:  [("SHA224", 1300, "raw-sha224")],
        64:  [("SHA256", 1400, "raw-sha256"), ("SHA3-256", 17400, None),
              ("Keccak-256", 17800, None)],
        96:  [("SHA384", 10800, "raw-sha384")],
        128: [("SHA512", 1700, "raw-sha512"), ("Whirlpool", 6100, "whirlpool"),
              ("SHA3-512", 17600, None)],
        16:  [("MySQL323", 200, "mysql")],
    }

    @classmethod
    def identify(cls, h):
        h = h.strip()
        out = []
        for rx, label, mode, jfmt in cls.PREFIX:
            if rx.search(h):
                out.append((label, mode, jfmt))
        if out:
            return out
        # bare hex?
        if re.fullmatch(r"[0-9a-fA-F]+", h):
            out.extend(cls.HEX.get(len(h), []))
        # base64-ish 22 chars w/o prefix -> possibly bcrypt tail, skip
        if not out:
            out.append(("unknown — inspect manually", None, None))
        return out

    @classmethod
    def via_nth(cls, h):
        """Optional cross-check using name-that-hash for hashcat modes."""
        if not shutil.which("nth") and not shutil.which("name-that-hash"):
            return []
        exe = "nth" if shutil.which("nth") else "name-that-hash"
        try:
            r = subprocess.run([exe, "-t", h, "-g"], capture_output=True, text=True, timeout=20)
            data = json.loads(r.stdout or "[]")
            # nth returns {"HASH": [ {name, hashcat, john}, ... ]}
            first = next(iter(data.values())) if isinstance(data, dict) else data
            res = []
            for item in (first or [])[:8]:
                res.append((item.get("name", "?"),
                            _to_int(item.get("hashcat")),
                            item.get("john")))
            return res
        except Exception:  # noqa
            return []

    @classmethod
    def via_hashcat(cls, h):
        """Authoritative mode candidates from `hashcat --identify`."""
        if not tool_available("hashcat"):
            return []
        try:
            tmp = tempfile.NamedTemporaryFile("w", delete=False, suffix=".hash")
            tmp.write(h.strip() + "\n"); tmp.close()
            r = subprocess.run([tool("hashcat"), "--identify", tmp.name],
                               capture_output=True, text=True, timeout=25)
            os.unlink(tmp.name)
            out = []
            for line in (r.stdout or "").splitlines():
                m = re.match(r"\s*(\d{1,6})\s*\|\s*(.+?)\s*\|", line)
                if m:
                    out.append((m.group(2).strip(), int(m.group(1)), None))
            return out[:10]
        except Exception:  # noqa
            return []


def _to_int(x):
    try:
        return int(x)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- #
#  FILE ANALYZER                                                                #
# --------------------------------------------------------------------------- #
class Analysis:
    def __init__(self):
        self.path = None
        self.kind = "unknown"          # hash | pcap | zip | rar | 7z | office | pdf | ssh | keepass | ...
        self.detail = ""
        self.file_out = ""
        self.pipeline = []             # human-readable planned steps
        self.hash_candidates = []      # [(label, hcmode, jformat)]
        self.suggested_engine = "hashcat"   # hashcat | john | aircrack | hcxtools
        self.suggested_mode = None
        self.prep_helper = None        # e.g. ['zip2john']  -> produces a john hash
        self.notes = []


class Analyzer:
    PCAP_MAGICS = {
        b"\xd4\xc3\xb2\xa1": "pcap (LE)",
        b"\xa1\xb2\xc3\xd4": "pcap (BE)",
        b"\x0a\x0d\x0d\x0a": "pcapng",
    }
    ZIP_MAGIC = b"PK\x03\x04"
    RAR_MAGIC = b"Rar!\x1a\x07"
    SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"
    PDF_MAGIC = b"%PDF"
    OLE_MAGIC = b"\xd0\xcf\x11\xe0"      # legacy .doc/.xls
    OOXML_MAGIC = ZIP_MAGIC              # .docx/.xlsx are zip containers

    @classmethod
    def run(cls, path):
        a = Analysis()
        a.path = path
        if not os.path.exists(path):
            a.detail = "file not found"
            return a
        try:
            head = open(path, "rb").read(4096)
        except Exception as e:  # noqa
            a.detail = f"read error: {e}"
            return a

        # `file` for a friendly description
        if shutil.which("file"):
            try:
                a.file_out = subprocess.run(
                    ["file", "-b", path], capture_output=True, text=True, timeout=10
                ).stdout.strip()
            except Exception:  # noqa
                pass

        magic4 = head[:4]
        magic6 = head[:6]
        lower_path = path.lower()

        # ---- binary containers first --------------------------------------
        if magic4 in cls.PCAP_MAGICS:
            return cls._pcap(a, cls.PCAP_MAGICS[magic4])
        if head.startswith(b"LUKS\xba\xbe"):
            return cls._container(a, "luks", "luks2john", 14600)
        if b"-FVE-FS-" in head[:16]:
            return cls._container(a, "bitlocker", "bitlocker2john", 22100)
        if head.startswith(cls.RAR_MAGIC) or head[:4] == b"Rar!":
            return cls._archive(a, "rar", "rar2john")
        if head.startswith(cls.SEVENZ_MAGIC):
            return cls._archive(a, "7z", "7z2john")
        if head.startswith(cls.PDF_MAGIC):
            return cls._doc(a, "pdf", "pdf2john")
        if head.startswith(cls.OLE_MAGIC):
            return cls._doc(a, "office", "office2john")

        # ---- GPG / PGP secret keys ----------------------------------------
        # binary OpenPGP secret-key packets start with 0x95/0x94/0x99 tag bytes,
        # or an armored "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        if head[:1] in (b"\x95", b"\x94", b"\x99") or b"BEGIN PGP PRIVATE KEY" in head:
            return cls._extract(a, "gpg", "gpg2john", None,
                                "GnuPG/PGP secret key — passphrase recovery")

        # low200 is used by the key-store / disk-image detection below
        low200 = head[:400].lower()

        # ---- disk / volume encryption -------------------------------------
        if head.startswith(b"encrcdsa") or head.startswith(b"cdsaencr") or lower_path.endswith(".dmg"):
            return cls._extract(a, "dmg", "dmg2john", None,
                                "macOS encrypted .dmg / sparse image")
        if lower_path.endswith((".tc", ".vc", ".hc")) or cls._maybe_truecrypt(head):
            return cls._truecrypt(a)

        # ---- key / credential stores --------------------------------------
        if head.startswith(b"PuTTY-User-Key-File") or lower_path.endswith(".ppk"):
            return cls._extract(a, "putty", "putty2john", 22911,
                                "PuTTY private key — passphrase recovery")
        if head.startswith(b"PWS3"):
            return cls._extract(a, "pwsafe", "pwsafe2john", 5200,
                                "Password Safe v3 (.psafe3) database")
        if lower_path.endswith((".kdb", ".kdbx")):
            return cls._extract(a, "keepass", "keepass2john", 13400,
                                "KeePass 1.x/2.x database (KDBX v2/v3 = 13400, v4 = newer)")
        # modern password managers (hashcat 7.x)
        if lower_path.endswith(".agilekeychain") or b"agilekeychain" in low200:
            return cls._extract(a, "1password-agile", None, 6600,
                                "1Password (agilekeychain)")
        if lower_path.endswith(".opvault") or b"cloudkeychain" in low200:
            return cls._extract(a, "1password-cloud", None, 8200,
                                "1Password (cloudkeychain / OPVault)")
        if b"$bitwarden$" in head or (b"bitwarden" in low200 and lower_path.endswith(".json")):
            return cls._extract(a, "bitwarden", None, 23400,
                                "Bitwarden vault — master passphrase")
        if lower_path.endswith("_lastpass_") or b"lastpass" in low200:
            return cls._extract(a, "lastpass", None, 6800,
                                "LastPass vault — master passphrase")
        if head.startswith(b"$ANSIBLE_VAULT"):
            return cls._extract(a, "ansible-vault", None, 16900,
                                "Ansible Vault — passphrase")
        if head.startswith(b"-----BEGIN AXCRYPT") or lower_path.endswith(".axx"):
            return cls._extract(a, "axcrypt", None, 13200,
                                "AxCrypt encrypted file — passphrase")
        if head.startswith(b"$argon2"):
            return cls._extract(a, "argon2", None, 34000,
                                "Argon2 hash — passphrase")
        if b"\xfa\x70\x0c\x53" in head[:8] or lower_path.endswith(".keychain") or \
           lower_path.endswith(".keychain-db"):
            return cls._extract(a, "keychain", "keychain2john", 23100,
                                "Apple macOS keychain")
        if b"password-check" in head or lower_path.endswith("key4.db"):
            return cls._extract(a, "mozilla-key4", None, 26100,
                                "Firefox/Thunderbird master password (key4.db)")
        if lower_path.endswith("key3.db"):
            return cls._extract(a, "mozilla-key3", "mozilla2john", 26000,
                                "Firefox/Thunderbird master password (key3.db)")

        # ---- encrypted images / stego -------------------------------------
        if head[:3] == b"\xff\xd8\xff" or head[:8] == b"\x89PNG\r\n\x1a\n":
            # a normal image; offer stego/embedded-data analysis rather than "crack"
            return cls._image(a, path, head)

        # ---- mobile: phone backups, keystores, APKs (offline files you own) -
        # (APK check must precede the generic ZIP_MAGIC branch below, since an
        # APK *is* a zip container and would otherwise be misread as one.)
        if lower_path.endswith(".ab") and head[:2] == b"AB":
            return cls._mobile(a, "android-backup", "ab2john", 18900)
        if lower_path.endswith((".jks", ".keystore")):
            return cls._mobile(a, "android-keystore", "keystore2john", None)
        if lower_path.endswith(".apk") or (head.startswith(cls.ZIP_MAGIC) and cls._looks_apk(path)):
            return cls._apk(a, path)
        if os.path.basename(path) == "Manifest.plist" or \
           (os.path.isdir(os.path.dirname(path)) and
            os.path.exists(os.path.join(os.path.dirname(path), "Manifest.plist"))):
            return cls._mobile(a, "ios-backup", "itunes_backup2john", 14700)

        if head.startswith(cls.ZIP_MAGIC):
            # could be a plain/encrypted zip OR an OOXML office doc
            if cls._looks_ooxml(path):
                return cls._doc(a, "office", "office2john")
            return cls._archive(a, "zip", "zip2john")
        if b"KeePass" in head or head[:4] in (b"\x03\xd9\xa2\x9a", b"\x03\xd9\xa2\x9b"):
            return cls._keepass(a)
        if head.startswith(b"-----BEGIN") and b"PRIVATE KEY" in head:
            return cls._ssh(a)

        # ---- text: is it a hash / hash list? ------------------------------
        text = cls._as_text(head)
        if text is not None:
            return cls._maybe_hash(a, text, path)

        a.kind = "unknown"
        a.detail = a.file_out or "unrecognized binary"
        a.notes.append("Try `file`, `binwalk`, `strings`, or a hex editor manually.")
        return a

    @staticmethod
    def _looks_apk(path):
        try:
            import zipfile
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                return "AndroidManifest.xml" in names or "classes.dex" in names
        except Exception:  # noqa
            return False

    @staticmethod
    def apk_strings(path, log):
        """Pull classes.dex out of the APK and grep for hash/secret-looking strings."""
        import zipfile
        pats = {
            "flag":     re.compile(r"(?:flag|ctf|htb|thm|pico)\{[^}]{2,80}\}", re.I),
            "md5/sha":  re.compile(r"\b[0-9a-fA-F]{32,64}\b"),
            "api key":  re.compile(r"(?:api[_-]?key|secret|token)[\"'=:\s]{1,4}[\w\-]{12,}", re.I),
            "aws key":  re.compile(r"AKIA[0-9A-Z]{16}"),
            "pem":      re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
            "url/host": re.compile(r"https?://[^\s\"'<>]{6,}"),
        }
        try:
            with zipfile.ZipFile(path) as z:
                dex_names = [n for n in z.namelist() if n.endswith(".dex")]
                if not dex_names:
                    log("[!] No classes.dex found — is this a valid APK?\n")
                    return
                found = {k: set() for k in pats}
                for name in dex_names:
                    data = z.read(name)
                    text = data.decode("latin-1", "ignore")
                    for label, rx in pats.items():
                        for m in rx.findall(text):
                            found[label].add(m if isinstance(m, str) else m[0])
                total = 0
                for label, hits in found.items():
                    hits = sorted(hits)[:15]
                    if hits:
                        log(f"\n=== {label} ({len(hits)}) ===\n")
                        for h in hits:
                            log(f"    {h}\n")
                        total += len(hits)
                if total == 0:
                    log("[i] No obvious secrets/hashes found in classes.dex strings.\n")
                log("\n[i] For full decompilation: apktool d <apk> -o out/  or  jadx <apk> -d out_src/\n")
        except Exception as e:  # noqa
            log(f"[!] APK scan failed: {e}\n")

    @staticmethod
    def image_scan(path, log):
        """Analyze an image for hidden/appended data: trailing bytes after the
        image EOF, embedded archive signatures, printable flag strings, and (if
        the tools exist) exiftool/binwalk/zsteg output. Legit stego/CTF work."""
        import re as _re
        try:
            data = open(path, "rb").read()
        except Exception as e:  # noqa
            log(f"[!] {e}\n"); return
        size = len(data)
        log(f"\n[*] Image scan: {os.path.basename(path)} ({size:,} bytes)\n")

        eoi = None
        if data[:3] == b"\xff\xd8\xff":                      # JPEG
            m = data.rfind(b"\xff\xd9")
            if m != -1 and m + 2 < size:
                eoi = m + 2
        elif data[:8] == b"\x89PNG\r\n\x1a\n":               # PNG
            m = data.rfind(b"IEND")
            if m != -1 and m + 8 < size:
                eoi = m + 8
        if eoi and size - eoi > 4:
            log(f"[+] {size - eoi} bytes AFTER image EOF — likely appended/hidden data.\n")
            tail = data[eoi:eoi + 8]
            sigs = {b"PK\x03\x04": "ZIP", b"Rar!": "RAR", b"7z\xbc\xaf": "7z",
                    b"\x1f\x8b": "GZIP", b"BZh": "BZIP2", b"\xfd7zXZ": "XZ"}
            for sig, name in sigs.items():
                if tail.startswith(sig):
                    log(f"    → appended {name}: carve with "
                        f"`dd if='{os.path.basename(path)}' bs=1 skip={eoi} of=hidden.{name.lower()}`\n")

        for sig, name in ((b"PK\x03\x04", "ZIP"), (b"Rar!\x1a\x07", "RAR"),
                          (b"7z\xbc\xaf\x27\x1c", "7z")):
            idx = data.find(sig)
            if idx > 0:
                log(f"[+] {name} signature embedded at offset {idx} — try `binwalk -e <file>`.\n")

        flags = set(_re.findall(rb"(?:flag|ctf|htb|thm|pico)\{[^}]{2,80}\}", data, _re.I))
        for f in list(flags)[:10]:
            log(f"    ★ possible flag: {f.decode('latin-1')}\n")

        for tool_name, args in (("exiftool", [path]),
                                ("binwalk", [path]),
                                ("zsteg", [path] if path.lower().endswith(".png") else None)):
            if args is None:
                continue
            if tool_available(tool_name):
                log(f"\n--- {tool_name} ---\n")
                try:
                    out = subprocess.run([tool(tool_name), *args],
                                         capture_output=True, text=True, timeout=60).stdout
                    for line in out.splitlines()[:40]:
                        log(f"    {line}\n")
                except Exception as e:  # noqa
                    log(f"    [!] {e}\n")
        log("\n[i] Steghide-protected payload? Brute the passphrase: "
            "`stegseek <file> <wordlist>` (very fast), or `steghide extract -sf <file>`.\n")

    # -- category builders ------------------------------------------------- #
    @staticmethod
    def _pcap(a, label):
        a.kind = "pcap"
        a.detail = label
        a.suggested_engine = "hcxtools"
        a.suggested_mode = 22000
        a.pipeline = [
            "hcxpcapngtool -o <capture>.hc22000 <file>   (extract WPA/WPA2 + PMKID)",
            "hashcat -m 22000 <capture>.hc22000 <wordlist>",
            "…or aircrack-ng <file> -w <wordlist>  (classic 4-way handshake)",
        ]
        a.notes.append("hc22000 (mode 22000) covers both PMKID and EAPOL handshakes.")
        return a

    @staticmethod
    def _archive(a, kind, helper):
        a.kind = kind
        a.detail = f"{kind} archive (password-protected likely)"
        a.suggested_engine = "john"
        a.prep_helper = helper
        a.pipeline = [
            f"{helper} <file> > <file>.hash",
            "john --wordlist=<wordlist> <file>.hash    (or feed to hashcat)",
        ]
        return a

    @staticmethod
    def _doc(a, kind, helper):
        a.kind = kind
        a.detail = f"{kind} document"
        a.suggested_engine = "john"
        a.prep_helper = helper
        a.pipeline = [
            f"{helper} <file> > <file>.hash",
            "john --wordlist=<wordlist> <file>.hash",
        ]
        if kind == "office":
            a.notes.append("office2john handles Office 97-2003 (OLE) and 2007+ (OOXML).")
        return a

    @staticmethod
    def _ssh(a):
        a.kind = "ssh"
        a.detail = "OpenSSH/PEM private key"
        a.suggested_engine = "john"
        a.prep_helper = "ssh2john"
        a.pipeline = [
            "ssh2john <keyfile> > key.hash",
            "john --wordlist=<wordlist> key.hash",
        ]
        return a

    @staticmethod
    def _keepass(a):
        a.kind = "keepass"
        a.detail = "KeePass database"
        a.suggested_engine = "john"
        a.prep_helper = "keepass2john"
        a.pipeline = [
            "keepass2john <db.kdbx> > kp.hash",
            "john --wordlist=<wordlist> kp.hash   (hashcat -m 13400 also works)",
        ]
        return a

    @staticmethod
    def _container(a, kind, helper, hcmode):
        a.kind = kind
        a.detail = f"{kind.upper()} encrypted volume"
        a.suggested_engine = "john"
        a.prep_helper = helper
        a.suggested_mode = hcmode
        a.pipeline = [
            f"{helper} <image> > {kind}.hash",
            f"john --wordlist=<wordlist> {kind}.hash   (hashcat -m {hcmode} also works)",
        ]
        a.notes.append(f"{kind.upper()}: extremely slow KDF — only a wordlist hit is realistic, "
                       "brute-force is hopeless. Run ⏱ Estimate.")
        return a

    @staticmethod
    def _mobile(a, kind, helper, hcmode):
        """Offline password recovery for a phone BACKUP FILE you own — not a
        live-device unlock. Same pattern as zip/office/KeePass."""
        label = {"android-backup": "Android backup (.ab)",
                 "android-keystore": "Android keystore/JKS",
                 "ios-backup": "iOS/iTunes backup"}.get(kind, kind)
        a.kind = kind
        a.detail = f"{label} — offline backup-file password recovery"
        a.suggested_engine = "john"
        a.prep_helper = helper
        a.suggested_mode = hcmode
        line2 = (f"john --wordlist=<wordlist> {kind}.hash"
                 + (f"   (hashcat -m {hcmode} also works)" if hcmode else ""))
        a.pipeline = [f"{helper} <file> > {kind}.hash", line2]
        a.notes.append("This targets a backup FILE's password, not a live device's lock "
                       "screen/PIN — that protection isn't something this tool touches.")
        return a

    @staticmethod
    def _extract(a, kind, helper, hcmode, detail):
        """Generic 'encrypted file -> *2john hash -> crack' router used by the
        wallet / key-store / disk-image formats. Honest KDF caveat attached.
        When helper is None the file is fed straight to hashcat at hcmode."""
        a.kind = kind
        a.detail = detail
        a.prep_helper = helper
        a.suggested_mode = hcmode
        if helper:
            a.suggested_engine = "john"
            line2 = (f"john --wordlist=<wordlist> {kind}.hash"
                     + (f"   (hashcat -m {hcmode} also works)" if hcmode else ""))
            a.pipeline = [f"{helper} <file> > {kind}.hash", line2]
        else:
            a.suggested_engine = "hashcat"
            a.pipeline = [
                f"hashcat -m {hcmode} <file> <wordlist>   # extract the hash first if needed",
                "# some wallets need their hash pulled with a tool-specific script; "
                "see hashcat wiki example hashes for the exact format.",
            ]
        a.notes.append(f"{kind}: uses a slow KDF — a wordlist/mask hit is realistic only if "
                       "the passphrase is weak. Run ⏱ Estimate for a feasibility read.")
        return a

    @staticmethod
    def _maybe_truecrypt(head):
        # TrueCrypt/VeraCrypt containers have no magic (by design) but are a
        # multiple of 512 bytes of high-entropy data; only guess on big files.
        return False   # rely on extension (.tc/.vc/.hc) to avoid false positives

    @staticmethod
    def _truecrypt(a):
        a.kind = "truecrypt"
        a.detail = "TrueCrypt / VeraCrypt encrypted volume"
        a.suggested_engine = "hashcat"
        a.suggested_mode = 13721   # VeraCrypt SHA-512 + XTS (one common variant)
        a.pipeline = [
            "# VeraCrypt modes vary by hash+cipher; 137xx/29xxx families.",
            "hashcat -m 13721 <volume>  <wordlist>   # VeraCrypt SHA512/XTS (example)",
            "# TrueCrypt uses 6211+; try `hashcat --help | grep -i crypt` for the exact mode.",
        ]
        a.notes.append("VeraCrypt/TrueCrypt use very heavy KDFs (hundreds of thousands of "
                       "iterations). Only a weak passphrase is recoverable; run ⏱ Estimate.")
        a.notes.append("Feed the raw volume/first 512 bytes to hashcat directly — no *2john step.")
        return a

    @staticmethod
    def _image(a, path, head):
        """A normal JPEG/PNG isn't 'encrypted', but it may hide data (stego) or an
        embedded archive. Offer analysis rather than pretend to 'crack' it."""
        fmt = "JPEG" if head[:3] == b"\xff\xd8\xff" else "PNG"
        a.kind = "image"
        a.detail = f"{fmt} image — stego / embedded-data analysis (not encryption)"
        a.suggested_engine = "none"
        a.pipeline = [
            "🔎 Use the 'Image scan' button to check for embedded archives, strings & metadata.",
            "steghide extract -sf <file>            # if steghide-embedded (needs passphrase)",
            "stegseek <file> <wordlist>             # brute-force a steghide passphrase (fast)",
            "zsteg <file.png> / binwalk <file>      # LSB stego / appended archives",
            "exiftool <file>                        # metadata, comments, GPS",
        ]
        a.notes.append("Images aren't password-encrypted like archives. If a CTF hid a passphrase-"
                       "protected payload with steghide, 'Image scan' + stegseek is the path.")
        return a

    @staticmethod
    def _apk(a, path):
        a.kind = "apk"
        a.detail = "Android APK — mobile CTF analysis"
        a.suggested_engine = "none"
        a.pipeline = [
            "apktool d <file.apk> -o out/     # decompile resources/manifest",
            "jadx <file.apk> -d out_src/      # decompile to readable Java",
            "unzip -p <file.apk> classes.dex | strings | grep -Ei "
            "'flag|secret|api_key|password|BEGIN|[0-9a-f]{32}'",
        ]
        a.notes.append("Use the 🔎 APK scan button to auto-pull candidate strings/hashes now.")
        return a

    @classmethod
    def _maybe_hash(cls, a, text, path):
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        if not lines:
            a.kind = "unknown"
            a.detail = "empty / whitespace"
            return a
        sample = lines[0]
        # /etc/shadow style?  user:$6$...:...
        if ":" in sample and re.search(r":\$[0-9a-z]+\$", sample):
            field = sample.split(":", 2)[1]
            a.kind = "hash"
            a.detail = f"shadow-style line ({len(lines)} entries)"
            a.hash_candidates = HashID.identify(field)
        else:
            first_token = re.split(r"[:\s]", sample)[0]
            a.kind = "hash"
            a.detail = f"hash list ({len(lines)} line(s))"
            a.hash_candidates = HashID.identify(first_token)

        # cross-check with name-that-hash if available
        token = re.split(r"[:\s]", sample)[0]
        nth = HashID.via_nth(token)
        seen = {c[0] for c in a.hash_candidates}
        for c in nth:
            if c[0] not in seen:
                a.hash_candidates.append(c); seen.add(c[0])

        # authoritative cross-check with `hashcat --identify`
        for c in HashID.via_hashcat(token):
            if c[0] not in seen:
                a.hash_candidates.append(c); seen.add(c[0])

        # pick a default hashcat mode from the first candidate that has one
        for label, mode, jfmt in a.hash_candidates:
            if mode is not None:
                a.suggested_engine = "hashcat"
                a.suggested_mode = mode
                break
        a.pipeline = [
            "hashcat -m <mode> <file> <wordlist>",
            "…or john --format=<fmt> --wordlist=<wordlist> <file>",
        ]
        a.notes.append("Hash type is a best-guess — length/charset are ambiguous; pick the mode that matches the CTF context.")
        return a

    # -- helpers ----------------------------------------------------------- #
    @staticmethod
    def _as_text(head):
        try:
            t = head.decode("utf-8")
        except UnicodeDecodeError:
            return None
        printable = sum(c.isprintable() or c in "\r\n\t" for c in t)
        if len(t) and printable / len(t) > 0.9:
            return t
        return None

    @staticmethod
    def _looks_ooxml(path):
        try:
            import zipfile
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                return any(n.startswith("word/") or n.startswith("xl/") or
                           n.startswith("ppt/") or n == "[Content_Types].xml"
                           for n in names)
        except Exception:  # noqa
            return False


# --------------------------------------------------------------------------- #
#  WORDLIST DISCOVERY                                                           #
# --------------------------------------------------------------------------- #
def find_wordlists():
    found = []
    common = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/wordlists/fasttrack.txt",
        "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
        "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
    ]
    for p in common:
        if os.path.exists(p):
            found.append(p)
    # scan seclists dir shallowly
    sl = Path("/usr/share/seclists/Passwords")
    if sl.exists():
        for p in sl.rglob("*.txt"):
            if p.stat().st_size > 0 and str(p) not in found:
                found.append(str(p))
                if len(found) > 40:
                    break
    # include the app's managed wordlist library
    try:
        lib = WordlistManager.library_dir()
        if lib.exists():
            for p in lib.glob("*"):
                if p.is_file() and p.stat().st_size > 0 and str(p) not in found:
                    found.append(str(p))
    except Exception:  # noqa
        pass
    return found or ["/usr/share/wordlists/rockyou.txt"]


def find_rules():
    """Discover hashcat rule files."""
    out = []
    for d in ("/usr/share/hashcat/rules", "/usr/share/doc/hashcat/rules"):
        p = Path(d)
        if p.exists():
            for r in sorted(p.glob("*.rule")):
                out.append(str(r))
    # float the popular ones to the top
    pref = ("best64", "rockyou-30000", "dive", "d3ad0ne", "T0XlC")
    out.sort(key=lambda s: next((i for i, k in enumerate(pref) if k in s), 99))
    return out


class WordlistManager:
    """Fetch & manage a local wordlist/rule library so users aren't hunting for
    lists. Downloads curated public lists from SecLists (raw.githubusercontent).
    Files land in ~/.local/share/c4rr07cr4ckr/wordlists (or /usr/share/wordlists
    when writable/root)."""

    CATALOG = {
        # name -> (url, description). Paths verified against the SecLists master.
        "rockyou-full": (
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
            "Passwords/Leaked-Databases/rockyou.txt.tar.gz",
            "The classic 14M-password RockYou list (compressed ~50MB)."),
        "top-1M": (
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
            "Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt",
            "Top 1,000,000 most common passwords (fast, high-hit)."),
        "top-100k": (
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
            "Passwords/Common-Credentials/xato-net-10-million-passwords-100000.txt",
            "Top 100,000 — a quick first pass."),
        "10k-most-common": (
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
            "Passwords/Common-Credentials/10k-most-common.txt",
            "10,000 most common — near-instant quick wins."),
        "xato-dup": (
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
            "Passwords/Common-Credentials/xato-net-10-million-passwords-dup.txt",
            "xato-net breach compile (~5M, dupes-only)."),
        "000webhost": (
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
            "Passwords/Leaked-Databases/000webhost.txt",
            "000webhost breach list (~720k real passwords)."),
        "usernames-shortlist": (
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
            "Usernames/top-usernames-shortlist.txt",
            "Common usernames — for Hydra/user enumeration."),
    }

    @staticmethod
    def library_dir():
        for cand in ("/usr/share/wordlists",):
            if os.path.isdir(cand) and os.access(cand, os.W_OK):
                return Path(cand) / "c4rr07cr4ckr"
        d = Path(_real_home()) / ".local" / "share" / "c4rr07cr4ckr" / "wordlists"
        return d

    @classmethod
    def local_path(cls, name):
        base = cls.library_dir()
        url = cls.CATALOG[name][0]
        fn = os.path.basename(url)
        # store the decompressed .txt for tar.gz entries
        if fn.endswith(".tar.gz"):
            fn = fn.replace(".tar.gz", "")
        return base / fn

    @classmethod
    def status(cls):
        rows = []
        for name, (url, desc) in cls.CATALOG.items():
            p = cls.local_path(name)
            have = p.exists()
            size = p.stat().st_size if have else 0
            rows.append((name, have, size, desc))
        return rows

    @classmethod
    def fetch(cls, name, log, progress=None):
        import urllib.request
        if name not in cls.CATALOG:
            log(f"[!] Unknown wordlist '{name}'.\n"); return None
        url, desc = cls.CATALOG[name]
        base = cls.library_dir()
        try:
            base.mkdir(parents=True, exist_ok=True)
        except Exception as e:  # noqa
            log(f"[!] Can't create library dir: {e}\n"); return None
        dest = cls.local_path(name)
        if dest.exists() and dest.stat().st_size > 0:
            log(f"[+] Already have {name}: {dest}\n"); return str(dest)
        tmp = base / (os.path.basename(url) + ".part")
        log(f"[*] Downloading {name} …\n    {url}\n")

        def _hook(blocks, bs, total):
            if progress and total > 0:
                progress(min(1.0, blocks * bs / total))
        try:
            urllib.request.urlretrieve(url, tmp, reporthook=_hook)
        except Exception as e:  # noqa
            log(f"[!] Download failed: {e}\n")
            log("    (If your network blocks this, download it manually into "
                f"{base} and it'll be picked up.)\n")
            return None
        # decompress tar.gz -> plain txt if needed
        if str(url).endswith(".tar.gz"):
            try:
                import tarfile
                with tarfile.open(tmp) as tf:
                    member = next((m for m in tf.getmembers()
                                   if m.name.endswith(".txt")), None)
                    if member:
                        member.name = os.path.basename(member.name)
                        tf.extract(member, base)
                        os.replace(base / member.name, dest)
                os.remove(tmp)
            except Exception as e:  # noqa
                log(f"[!] Extract failed: {e}\n"); return None
        else:
            os.replace(tmp, dest)
        n = sum(1 for _ in open(dest, "rb")) if dest.exists() else 0
        log(f"[+] {name} ready: {dest}  (~{n:,} entries)\n")
        return str(dest)


COMMON_MASKS = [
    "?d?d?d?d",                 # 4-digit PIN
    "?d?d?d?d?d?d",             # 6-digit
    "?l?l?l?l?l?l",             # 6 lower
    "?u?l?l?l?l?d?d",           # Word + 2 digits
    "?l?l?l?l?l?l?d?d",
    "?a?a?a?a?a?a",             # any 6
    "?a?a?a?a?a?a?a?a",         # any 8 (slow)
]


# --------------------------------------------------------------------------- #
#  WORDLIST GENERATOR  (crunch wrapper)                                         #
# --------------------------------------------------------------------------- #
class Crunch:
    """
    Wrapper over `crunch` to generate custom wordlists by length + charset or by
    a pattern, with a keyspace/size estimate first so you don't accidentally ask
    for a 40 TB file. Falls back to a pure-Python generator if crunch isn't
    installed.
    """
    # crunch's built-in placeholders: @=lower  ,=upper  %=digit  ^=symbol
    CHARSETS = {
        "lower (a-z)": "abcdefghijklmnopqrstuvwxyz",
        "upper (A-Z)": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "digits (0-9)": "0123456789",
        "alnum lower": "abcdefghijklmnopqrstuvwxyz0123456789",
        "alnum mixed": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "all + symbols": "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*",
    }

    @staticmethod
    def available():
        return tool_available("crunch")

    @staticmethod
    def estimate(minlen, maxlen, charset_size, pattern=None):
        """Return (line_count, approx_bytes). For a pattern, only '@,%^' vary."""
        if pattern:
            varic = sum(1 for ch in pattern if ch in "@,%^")
            fixed = len(pattern) - varic
            # rough: each variable slot contributes its class size; use charset_size
            lines = charset_size ** varic if varic else 1
            linelen = len(pattern) + 1
        else:
            lines = sum(charset_size ** n for n in range(minlen, maxlen + 1))
            linelen = (maxlen + 1)
        return lines, lines * linelen

    @staticmethod
    def human_size(nbytes):
        for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
            if nbytes < 1024 or unit == "PB":
                return f"{nbytes:.1f} {unit}"
            nbytes /= 1024

    @classmethod
    def build(cls, out_path, minlen, maxlen, charset, pattern, log, cap_lines=0):
        """Generate the wordlist. cap_lines>0 limits output (safety for huge sets)."""
        if cls.available():
            cmd = [tool("crunch"), str(minlen), str(maxlen)]
            if charset:
                cmd.append(charset)
            if pattern:
                cmd += ["-t", pattern]
            cmd += ["-o", out_path]
            log(f"$ {' '.join(cmd)}\n")
            try:
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True)
                for line in iter(p.stdout.readline, ""):
                    log(line)
                p.wait()
                if os.path.exists(out_path):
                    n = sum(1 for _ in open(out_path, "rb"))
                    log(f"[+] Wordlist written: {out_path}  ({n:,} lines)\n")
                return out_path
            except Exception as e:  # noqa
                log(f"[!] crunch failed ({e}); using built-in generator.\n")
        # pure-python fallback (no crunch installed)
        import itertools
        if not charset:
            log("[!] No charset for fallback generator.\n"); return None
        written = 0
        try:
            with open(out_path, "w") as f:
                if pattern:
                    slots = []
                    classes = {"@": "abcdefghijklmnopqrstuvwxyz",
                               ",": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                               "%": "0123456789", "^": "!@#$%^&*"}
                    for ch in pattern:
                        slots.append(classes.get(ch, None))
                    pools = [s if s else [c] for s, c in zip(slots, pattern)]
                    for combo in itertools.product(*pools):
                        f.write("".join(combo) + "\n")
                        written += 1
                        if cap_lines and written >= cap_lines:
                            break
                else:
                    for n in range(minlen, maxlen + 1):
                        for combo in itertools.product(charset, repeat=n):
                            f.write("".join(combo) + "\n")
                            written += 1
                            if cap_lines and written >= cap_lines:
                                break
                        if cap_lines and written >= cap_lines:
                            break
            log(f"[+] Wordlist written (builtin): {out_path}  ({written:,} lines)\n")
            return out_path
        except Exception as e:  # noqa
            log(f"[!] generator failed: {e}\n"); return None


# --------------------------------------------------------------------------- #
#  ENCODING PRE-PASS  (mini "magic" decoder)                                    #
# --------------------------------------------------------------------------- #
class Decoder:
    """
    Peels common CTF encodings (base64/base32/hex/url/rot13/gzip/zlib) and scores
    each result so you can see whether a 'hash' is really just wrapped plaintext.
    """
    FLAG_RX = re.compile(r"(flag|ctf|htb|thm|key|picoCTF)\s*\{", re.I)

    @classmethod
    def _printable_ratio(cls, b):
        if not b:
            return 0.0
        try:
            t = b.decode("utf-8")
        except Exception:  # noqa
            return 0.0
        good = sum(c.isprintable() or c in "\r\n\t" for c in t)
        return good / len(t)

    @classmethod
    def _decoders(cls, s):
        import base64 as b64, binascii, codecs, zlib, gzip as gz, urllib.parse as up
        raw = s.strip()
        cand = []
        # base64
        try:
            pad = raw + "=" * (-len(raw) % 4)
            cand.append(("base64", b64.b64decode(pad, validate=False)))
        except Exception:  # noqa
            pass
        # base32
        try:
            cand.append(("base32", b64.b32decode(raw + "=" * (-len(raw) % 8), casefold=True)))
        except Exception:  # noqa
            pass
        # hex
        if re.fullmatch(r"[0-9a-fA-F\s]+", raw) and len(raw.replace(" ", "")) % 2 == 0:
            try:
                cand.append(("hex", binascii.unhexlify(raw.replace(" ", ""))))
            except Exception:  # noqa
                pass
        # url
        if "%" in raw:
            try:
                cand.append(("url", up.unquote_to_bytes(raw)))
            except Exception:  # noqa
                pass
        # rot13
        try:
            cand.append(("rot13", codecs.decode(raw, "rot_13").encode()))
        except Exception:  # noqa
            pass
        # gzip / zlib (need bytes)
        try:
            b = raw.encode("latin-1", "ignore")
            cand.append(("zlib", zlib.decompress(b)))
        except Exception:  # noqa
            pass
        return cand

    @classmethod
    def magic(cls, s, depth=3, _seen=None):
        """Returns a list of (chain, text, score, flagged)."""
        _seen = _seen or set()
        results = []
        if depth <= 0 or not s or s in _seen:
            return results
        _seen.add(s)
        for name, dec in cls._decoders(s):
            ratio = cls._printable_ratio(dec)
            if ratio < 0.75:
                continue
            try:
                txt = dec.decode("utf-8", "replace")
            except Exception:  # noqa
                continue
            if txt.strip() == s.strip():
                continue
            flagged = bool(cls.FLAG_RX.search(txt))
            results.append(([name], txt, ratio, flagged))
            # recurse
            for chain, t2, r2, f2 in cls.magic(txt, depth - 1, _seen):
                results.append(([name] + chain, t2, r2, f2))
        # rank: flags first, then printable ratio, then shorter chains
        results.sort(key=lambda x: (not x[3], -x[2], len(x[0])))
        return results[:12]


# --------------------------------------------------------------------------- #
#  PCAP DEEP INTELLIGENCE  (tshark)                                             #
# --------------------------------------------------------------------------- #
class PcapIntel:
    """Extract credentials / protocol artefacts from a capture with tshark."""

    @staticmethod
    def available():
        return tool_available("tshark")

    @classmethod
    def scan(cls, pcap, log):
        if not cls.available():
            log("[!] tshark not found — apt install tshark (wireshark-common).\n")
            return
        log(f"\n[*] Deep pcap scan: {pcap}\n")
        queries = [
            ("Protocol summary", [tool("tshark"), "-r", pcap, "-q", "-z", "io,phs"]),
            ("Credentials tap",  [tool("tshark"), "-r", pcap, "-q", "-z", "credentials"]),
            ("HTTP basic auth",  [tool("tshark"), "-r", pcap, "-Y", "http.authorization",
                                  "-T", "fields", "-e", "http.authorization"]),
            ("HTTP POST bodies", [tool("tshark"), "-r", pcap, "-Y", "http.request.method==POST",
                                  "-T", "fields", "-e", "http.file_data"]),
            ("FTP USER/PASS",    [tool("tshark"), "-r", pcap, "-Y", "ftp.request.command==USER || ftp.request.command==PASS",
                                  "-T", "fields", "-e", "ftp.request.command", "-e", "ftp.request.arg"]),
            ("Telnet data",      [tool("tshark"), "-r", pcap, "-Y", "telnet.data",
                                  "-T", "fields", "-e", "telnet.data"]),
            ("Kerberos AS-REP",  [tool("tshark"), "-r", pcap, "-Y", "kerberos.msg_type==11",
                                  "-T", "fields", "-e", "kerberos.CNameString"]),
            ("SMB/NTLM users",   [tool("tshark"), "-r", pcap, "-Y", "ntlmssp.auth.username",
                                  "-T", "fields", "-e", "ntlmssp.auth.username",
                                  "-e", "ntlmssp.auth.domain"]),
            ("SNMP community",   [tool("tshark"), "-r", pcap, "-Y", "snmp.community",
                                  "-T", "fields", "-e", "snmp.community"]),
        ]
        for label, cmd in queries:
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                out = (r.stdout or "").strip()
                if out:
                    log(f"\n=== {label} ===\n")
                    # keep it bounded
                    lines = [l for l in out.splitlines() if l.strip()][:40]
                    log("\n".join(lines) + "\n")
            except Exception as e:  # noqa
                log(f"[!] {label}: {e}\n")
        log("\n[+] Deep scan done. (WPA/PMKID handshakes: use the hcxtools engine.)\n")

    @classmethod
    def extract_objects(cls, pcap, outdir, log):
        if not cls.available():
            log("[!] tshark not found.\n"); return
        for proto in ("http", "smb", "tftp", "imf"):
            d = os.path.join(outdir, proto)
            os.makedirs(d, exist_ok=True)
            try:
                subprocess.run([tool("tshark"), "-r", pcap, "--export-objects", f"{proto},{d}"],
                               capture_output=True, text=True, timeout=90)
                got = os.listdir(d)
                if got:
                    log(f"[+] {proto}: extracted {len(got)} object(s) -> {d}\n")
            except Exception as e:  # noqa
                log(f"[!] {proto} export: {e}\n")


# --------------------------------------------------------------------------- #
#  TROPHY  (potfile parsing)                                                    #
# --------------------------------------------------------------------------- #
class Trophy:
    @staticmethod
    def _pot_paths():
        home = Path(_real_home())
        root = Path("/root")
        cands = [
            home / ".local/share/hashcat/hashcat.potfile",
            home / ".hashcat/hashcat.potfile",
            Path.cwd() / "hashcat.potfile",
            home / ".john/john.pot",
            root / ".local/share/hashcat/hashcat.potfile",
            root / ".hashcat/hashcat.potfile",
            root / ".john/john.pot",
        ]
        seen, out = set(), []
        for c in cands:
            if c.exists() and str(c) not in seen:
                seen.add(str(c)); out.append(c)
        return out

    @classmethod
    def entries(cls):
        rows = []
        for p in cls._pot_paths():
            src = "john" if p.name == "john.pot" else "hashcat"
            try:
                for line in p.read_text(errors="replace").splitlines():
                    line = line.rstrip("\n")
                    if ":" not in line:
                        continue
                    h, plain = line.split(":", 1)
                    rows.append((src, h[:48], plain))
            except Exception:  # noqa
                pass
        return rows

    @classmethod
    def export(cls, path, fmt="md"):
        rows = cls.entries()
        with open(path, "w") as f:
            if fmt == "csv":
                f.write("source,hash,plaintext\n")
                for s, h, p in rows:
                    f.write(f'{s},"{h}","{p}"\n')
            else:
                f.write("# C4rr07CR4cKR — cracked trophies\n\n")
                f.write("| Source | Hash (trunc) | Plaintext |\n|---|---|---|\n")
                for s, h, p in rows:
                    f.write(f"| {s} | `{h}` | `{p}` |\n")
        return len(rows)


# --------------------------------------------------------------------------- #
#  KEYSPACE / ETA ESTIMATOR                                                     #
# --------------------------------------------------------------------------- #
class Estimator:
    """Tells you if an attack is even winnable before you burn hours on it."""

    CHARSET = {"l": 26, "u": 26, "d": 10, "s": 33, "a": 95, "b": 256, "h": 16, "H": 16}

    # very rough single modern-GPU H/s by mode (order-of-magnitude only)
    SPEED = {
        0: 5e10, 100: 2e10, 1400: 8e9, 1700: 3e9, 1000: 1e11, 900: 4e10,
        3200: 5e4, 1800: 2e5, 500: 5e6, 7400: 3e5, 22000: 1e6,
        13100: 1e9, 18200: 1e9, 16500: 2e9, 13400: 3e5, 400: 2e6, 3000: 8e10,
    }

    @classmethod
    def mask_keyspace(cls, mask):
        total, i = 1, 0
        while i < len(mask):
            if mask[i] == "?" and i + 1 < len(mask):
                total *= cls.CHARSET.get(mask[i + 1], 95)
                i += 2
            else:
                total *= 1
                i += 1
        return total

    @staticmethod
    def wordlist_lines(path):
        try:
            n = 0
            with open(path, "rb") as f:
                for _ in f:
                    n += 1
            return n
        except Exception:  # noqa
            return 0

    @staticmethod
    def rule_lines(path):
        if not path or not os.path.exists(path):
            return 1
        try:
            return max(1, sum(1 for line in open(path, "rb")
                              if line.strip() and not line.startswith(b"#")))
        except Exception:  # noqa
            return 1

    @staticmethod
    def human_time(seconds):
        if seconds < 1:
            return "< 1 second"
        units = [("year", 31557600), ("day", 86400), ("hour", 3600),
                 ("minute", 60), ("second", 1)]
        if seconds > 31557600 * 100:
            return f"~{seconds / 31557600:.0f} years (infeasible)"
        for name, size in units:
            if seconds >= size:
                v = seconds / size
                return f"~{v:.1f} {name}{'s' if v >= 2 else ''}"
        return f"{seconds:.0f}s"

    @classmethod
    def estimate(cls, mode, attack, wordlist=None, rule=None, mask=None, hps=None):
        mode = int(mode)
        speed = hps or cls.SPEED.get(mode, 1e9)
        if attack == 0:
            ks = cls.wordlist_lines(wordlist) * cls.rule_lines(rule)
        elif attack == 3:
            ks = cls.mask_keyspace(mask or "?a?a?a?a?a?a")
        elif attack in (6, 7):
            ks = cls.wordlist_lines(wordlist) * cls.mask_keyspace(mask or "?d?d")
        else:
            ks = cls.wordlist_lines(wordlist)
        secs = ks / speed if speed else float("inf")
        # verdict
        if secs < 3600:
            verdict = "FAST — go for it"
        elif secs < 86400:
            verdict = "feasible (within a day)"
        elif secs < 31557600 / 12:
            verdict = "slow but possible"
        elif secs < 31557600 * 100:
            verdict = "impractical — prefer a targeted wordlist"
        else:
            verdict = "INFEASIBLE — only a wordlist hit will work, not brute force"
        return {"keyspace": ks, "speed": speed, "seconds": secs,
                "time": cls.human_time(secs), "verdict": verdict}


# --------------------------------------------------------------------------- #
#  ONLINE LOGIN TESTING  (Hydra wrapper — AUTHORIZED TARGETS ONLY)              #
# --------------------------------------------------------------------------- #
class Hydra:
    """
    Thin wrapper over THC-Hydra for online login testing against services you
    are AUTHORIZED to test (CTF boxes, your lab, in-scope engagements).

    An online attack touches a live third-party service, so this class refuses
    to run unless the caller passes authorized=True, and it can enforce a scope
    allowlist of hosts/CIDRs.
    """
    SERVICES = ["ssh", "ftp", "http-get", "http-post-form", "smb", "rdp",
                "mysql", "postgres", "telnet", "vnc", "smtp", "pop3", "imap"]

    def __init__(self, log):
        self.log = log
        self.proc = None
        self.found = []

    @staticmethod
    def available():
        return tool_available("hydra")

    @staticmethod
    def in_scope(target, scope):
        return host_in_scope(target, scope)

    def run(self, target, service, user=None, userlist=None, password=None,
            passlist=None, port=None, threads=16, form=None,
            authorized=False, scope=None, extra=""):
        if not self.available():
            self.log("[!] hydra not installed — apt install hydra.\n"); return False
        if not authorized:
            self.log("[!] BLOCKED: you must confirm you are authorized to test this "
                     "target before any online attack.\n")
            return False
        if not target:
            self.log("[!] No target host.\n"); return False
        if not self.in_scope(target, scope or []):
            self.log(f"[!] BLOCKED: {target} is not in your scope allowlist.\n")
            return False

        self.found = []
        cmd = [tool("hydra")]
        if user:
            cmd += ["-l", user]
        elif userlist:
            cmd += ["-L", userlist]
        else:
            self.log("[!] Provide a username or user list.\n"); return False
        if password:
            cmd += ["-p", password]
        elif passlist:
            cmd += ["-P", _ensure_wordlist(passlist, self.log)]
        else:
            self.log("[!] Provide a password or password list.\n"); return False
        if port:
            cmd += ["-s", str(port)]
        cmd += ["-t", str(max(1, min(int(threads), 64))), "-I", "-f", "-V"]
        if extra:
            cmd += extra.split()

        # target + service (+ form string for http-post-form)
        if service == "http-post-form" and form:
            cmd += [target, "http-post-form", form]
        else:
            cmd += [f"{service}://{target}" + (f":{port}" if port else "")]

        self.log("\n[!] AUTHORIZED online test — hammering a LIVE service. "
                 "Expect lockouts/alerts on real targets.\n")
        self.log(f"$ {' '.join(cmd)}\n")
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in iter(self.proc.stdout.readline, ""):
                self.log(line)
                m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line)
                if m:
                    self.found.append((m.group(1), m.group(2)))
            self.proc.wait()
        except Exception as e:  # noqa
            self.log(f"[!] {e}\n"); return False
        if self.found:
            self.log(f"\n[✓] CREDENTIALS FOUND: "
                     + ", ".join(f"{u}:{p}" for u, p in self.found) + "\n")
        else:
            self.log("\n[×] No valid login found (weak-credential bet failed).\n")
        return bool(self.found)

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.log("\n[!] Hydra terminated.\n")


# --------------------------------------------------------------------------- #
#  SCOPE / RULES-OF-ENGAGEMENT ENFORCEMENT                                      #
# --------------------------------------------------------------------------- #
def host_in_scope(target, scope):
    """scope: list of hostnames / CIDRs. Empty scope = allow (caller asserts auth)."""
    if not scope:
        return True
    import ipaddress
    for entry in scope:
        entry = (entry or "").strip()
        if not entry:
            continue
        if entry == target:
            return True
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if ipaddress.ip_address(target) in net:
                return True
        except Exception:  # noqa
            if target.endswith(entry.lstrip("*.")):
                return True
    return False


def _parse_scope(raw):
    """Load a scope file: JSON, YAML (if pyyaml present), or a minimal subset."""
    raw = raw.strip()
    try:
        return json.loads(raw)
    except Exception:  # noqa
        pass
    try:
        import yaml
        return yaml.safe_load(raw) or {}
    except Exception:  # noqa
        pass
    # minimal YAML subset: `key: value` and `  - item` lists
    data, cur_key = {}, None
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if re.match(r"^\s*-\s+", line):
            if cur_key is not None:
                data.setdefault(cur_key, [])
                if isinstance(data[cur_key], list):
                    data[cur_key].append(line.split("-", 1)[1].strip())
            continue
        m = re.match(r"^(\w[\w_]*):\s*(.*)$", line.strip())
        if m:
            k, v = m.group(1), m.group(2).strip()
            cur_key = k
            if v == "":
                data[k] = []
            elif v.lower() in ("true", "false"):
                data[k] = (v.lower() == "true")
            elif re.fullmatch(r"\d+", v):
                data[k] = int(v)
            else:
                data[k] = v.strip('"\'')
    return data


class Scope:
    """
    Rules-of-engagement gate. A scope file declares which targets are authorized,
    whether online attacks are permitted, thread ceilings, and an expiry — so the
    tool can hard-refuse anything outside an approved engagement.
    """
    def __init__(self, data=None, path=None):
        self.data = data or {}
        self.path = path

    @classmethod
    def load(cls, path):
        return cls(_parse_scope(Path(path).read_text()), str(path))

    @property
    def engagement(self):
        return self.data.get("engagement", "(unnamed)")

    @property
    def targets(self):
        t = self.data.get("targets", [])
        return t if isinstance(t, list) else [t]

    @property
    def allow_online(self):
        return bool(self.data.get("allow_online", False))

    @property
    def allow_offline(self):
        return bool(self.data.get("allow_offline", True))

    @property
    def max_threads(self):
        return int(self.data.get("max_threads", 16))

    @property
    def authorization(self):
        return self.data.get("authorization", "")

    def expired(self):
        exp = self.data.get("expires")
        if not exp:
            return False
        try:
            from datetime import datetime
            return datetime.now() > datetime.fromisoformat(str(exp))
        except Exception:  # noqa
            return False

    def target_ok(self, host):
        if self.expired():
            return False
        return host_in_scope(host, self.targets)

    def summary(self):
        lines = [f"engagement : {self.engagement}",
                 f"targets    : {', '.join(self.targets) or '(none)'}",
                 f"online     : {'allowed' if self.allow_online else 'DENIED'}",
                 f"max threads: {self.max_threads}",
                 f"expires    : {self.data.get('expires', '(none)')}"
                 + ("  [EXPIRED]" if self.expired() else ""),
                 f"authorized : {self.authorization or '(unsigned)'}"]
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  CHAIN OF CUSTODY  (hashing) + TAMPER-EVIDENT AUDIT LOG                        #
# --------------------------------------------------------------------------- #
def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:  # noqa
        return None


class AuditLog:
    """
    Append-only, hash-chained JSONL audit trail. Each record commits to the
    previous record's hash, so any edit/deletion downstream is detectable —
    the integrity property expected of evidentiary logs.
    """
    def __init__(self, path):
        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:  # noqa
            pass

    def _last_hash(self):
        if not self.path.exists():
            return "0" * 64
        last = None
        for line in self.path.read_text(errors="replace").splitlines():
            if line.strip():
                last = line
        if not last:
            return "0" * 64
        try:
            return json.loads(last).get("entry_hash", "0" * 64)
        except Exception:  # noqa
            return "0" * 64

    @staticmethod
    def _core(ts, event, data, prev):
        return json.dumps({"ts": ts, "event": event, "data": data, "prev": prev},
                          sort_keys=True)

    def append(self, event, **data):
        import hashlib
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        prev = self._last_hash()
        body = self._core(ts, event, data, prev)
        entry_hash = hashlib.sha256((prev + body).encode()).hexdigest()
        rec = {"ts": ts, "event": event, "data": data, "prev": prev,
               "entry_hash": entry_hash}
        try:
            with open(self.path, "a") as f:
                f.write(json.dumps(rec) + "\n")
        except Exception:  # noqa
            pass
        return entry_hash

    def verify(self):
        import hashlib
        prev = "0" * 64
        n = 0
        if not self.path.exists():
            return True, 0
        for line in self.path.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            body = self._core(rec["ts"], rec["event"], rec["data"], rec["prev"])
            calc = hashlib.sha256((rec["prev"] + body).encode()).hexdigest()
            if rec["prev"] != prev or calc != rec.get("entry_hash"):
                return False, n
            prev = rec["entry_hash"]
            n += 1
        return True, n


# --------------------------------------------------------------------------- #
#  SIGNED REPORTS                                                               #
# --------------------------------------------------------------------------- #
class Reporter:
    """Write the session report plus a SHA-256 manifest and (if gpg + a key are
    available) a detached signature — so a report can be integrity-checked."""
    @staticmethod
    def write(engine, path, audit=None, gpg_key=None):
        engine.export_report(path)
        digest = sha256_file(path)
        Path(str(path) + ".sha256").write_text(f"{digest}  {os.path.basename(path)}\n")
        sig = None
        if gpg_key and shutil.which("gpg"):
            try:
                subprocess.run(["gpg", "--batch", "--yes", "--local-user", gpg_key,
                                "--armor", "--detach-sign", "--output", str(path) + ".asc",
                                str(path)], check=True, capture_output=True)
                sig = str(path) + ".asc"
            except Exception:  # noqa
                sig = None
        if audit:
            audit.append("report_written", path=str(path), sha256=digest, signed=bool(sig))
        return digest, sig


# --------------------------------------------------------------------------- #
#  DISTRIBUTED CRACKING  (Hashtopolis client)                                   #
# --------------------------------------------------------------------------- #
class Hashtopolis:
    """
    Minimal client for a Hashtopolis server's classic user API (/api/user.php).
    Lets a big job be sharded across a cluster of agents/GPUs. Requires a
    reachable server + access key; untested here without one.
    """
    def __init__(self, url, api_key, log=lambda *_: None):
        self.url = (url or "").rstrip("/")
        self.key = api_key
        self.log = log

    def _call(self, section, request, **kw):
        import urllib.request
        payload = {"section": section, "request": request, "accessKey": self.key}
        payload.update(kw)
        data = json.dumps(payload).encode()
        req = urllib.request.Request(self.url + "/api/user.php", data=data,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())

    def test(self):
        try:
            res = self._call("test", "ping")
            self.log(f"[hashtopolis] {res}\n")
            return res.get("response") == "OK" or "version" in res
        except Exception as e:  # noqa
            self.log(f"[hashtopolis] connection failed: {e}\n")
            return False

    def create_hashlist(self, name, hashfile, hashtype):
        import base64
        blob = base64.b64encode(Path(hashfile).read_bytes()).decode()
        return self._call("hashlist", "createHashlist", name=name, isSalted=False,
                          isSecret=True, isHexSalt=False, separator=":", format=0,
                          accessGroupId=1, data=blob, useBrain=False,
                          brainFeatures=0, hashtypeId=int(hashtype))

    def create_task(self, name, hashlist_id, attack_cmd, priority=5):
        return self._call("task", "createTask", name=name, hashlistId=int(hashlist_id),
                          attackCmd=attack_cmd, chunksize=600, priority=priority,
                          color="ff7a1a", isCpuTask=False, isSmall=False,
                          crackerVersionId=1, files=[], preprocessorId=0,
                          preprocessorCommand="")

    def push_job(self, name, hashfile, hashtype, attack_cmd):
        """Upload a hashlist and create a task in one shot."""
        hl = self.create_hashlist(name, hashfile, hashtype)
        hid = hl.get("hashlistId") or hl.get("hashlist", {}).get("hashlistId")
        if not hid:
            self.log(f"[hashtopolis] createHashlist gave no id: {hl}\n")
            return None
        task = self.create_task(name, hid, attack_cmd)
        self.log(f"[hashtopolis] task queued: {task}\n")
        return task


# --------------------------------------------------------------------------- #
#  PLUGIN SYSTEM                                                                 #
# --------------------------------------------------------------------------- #
class PluginAPI:
    """Passed to each plugin's register(api). Lets community modules extend the app."""
    def __init__(self):
        self.detectors = []     # fn(path, head_bytes, analysis) -> None (mutates analysis)
        self.actions = []       # (label, fn(ctx)) ctx = {'file','log','engine','wordlist'}
        self.names = []

    def add_detector(self, fn):
        self.detectors.append(fn)

    def add_action(self, label, fn):
        self.actions.append((label, fn))


class PluginManager:
    def __init__(self, log=lambda *_: None):
        self.api = PluginAPI()
        self.log = log
        self.loaded = []

    @staticmethod
    def dirs():
        return [
            Path(_real_home()) / ".config/c4rr07cr4ckr/plugins",
            Path("/opt/c4rr07cr4ckr/plugins"),
            Path(__file__).resolve().parent / "plugins",
        ]

    def load(self):
        import importlib.util
        for d in self.dirs():
            if not d.exists():
                continue
            for f in sorted(d.glob("*.py")):
                if f.name.startswith("_"):
                    continue
                try:
                    spec = importlib.util.spec_from_file_location(f"c4plugin_{f.stem}", f)
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    if hasattr(mod, "register"):
                        mod.register(self.api)
                        name = getattr(mod, "PLUGIN_NAME", f.stem)
                        self.loaded.append(name)
                        self.api.names.append(name)
                        self.log(f"[plugin] loaded: {name}\n")
                except Exception as e:  # noqa
                    self.log(f"[plugin] failed {f.name}: {e}\n")
        return self


# --------------------------------------------------------------------------- #
#  CRACK ENGINE                                                                 #
# --------------------------------------------------------------------------- #
class Engine:
    def __init__(self, log):
        self.log = log
        self.proc = None
        self._process_lock = threading.Lock()
        self.cancelled = threading.Event()
        self.last_cracked = []      # plaintext(s) from the most recent job
        self.record = []            # session record for the Markdown report
        self.on_result = None       # optional callback(success: bool, plaintexts: list)
        self.on_progress = None     # optional callback(fraction 0..1) for the monitor ring
        self.audit = None           # optional AuditLog

    def _note(self, kind, text):
        self.record.append((kind, text))

    def stop(self):
        with self._process_lock:
            self.cancelled.set()
            if self.proc and self.proc.poll() is None:
                try:
                    self.proc.terminate()
                except ProcessLookupError:
                    pass
        self.log("\n[i] Stop requested.\n")

    def prepare_hash(self, helper_name, infile):
        """Run a *2john helper -> temp .hash file. Returns path or None."""
        cmd = resolve_helper(helper_name)
        if not cmd:
            self.log(f"[!] Helper '{helper_name}' not found. Install john (jumbo).\n")
            return None
        out = tempfile.NamedTemporaryFile(delete=False, suffix=".hash").name
        self.log(f"[*] {helper_name} {infile} > {out}\n")
        try:
            with open(out, "w") as fo:
                r = subprocess.run(cmd + [infile], stdout=fo, stderr=subprocess.PIPE, text=True, timeout=120)
            if r.stderr:
                self.log(r.stderr)
            if os.path.getsize(out) == 0:
                self.log("[!] Helper produced empty output — wrong file type or unsupported.\n")
                return None
            self.log(f"[+] Hash written: {out}\n")
            return out
        except Exception as e:  # noqa
            self.log(f"[!] {e}\n")
            return None

    def run_hashcat(self, mode, target, wordlist, extra="",
                    backend="auto", workload=None, optimized=False, device_ids=None,
                    attack=0, rule=None, mask=None, session=None):
        """
        attack:  0 straight | 3 mask/brute | 6 hybrid wordlist+mask | 7 hybrid mask+wordlist
        rule:    path to a hashcat .rule file (attack 0 only)
        mask:    hashcat mask string e.g. ?u?l?l?l?d?d (attacks 3/6/7)
        session: --session name so a long run can be --restore'd later
        backend: 'auto' | 'gpu' | 'cpu'   -> hashcat -D (1=CPU,2=GPU)
        """
        if not tool_available("hashcat"):
            self.log("[!] hashcat not installed.\n"); return
        self.last_cracked = []
        cmd = [tool("hashcat"), "-m", str(mode), "-a", str(attack), "--status", "--status-timer=5"]
        if session:
            cmd += [f"--session={session}"]
        if backend == "gpu":
            cmd += ["-D", "2"]
        elif backend == "cpu":
            cmd += ["-D", "1"]
        if device_ids:
            cmd += ["-d", ",".join(device_ids)]
        if workload:
            cmd += ["-w", str(workload)]
        if optimized:
            cmd += ["-O"]
        try:
            ta = int(CFG.data.get("resource", {}).get("temp_abort", 0))
            if ta > 0:
                cmd += [f"--hwmon-temp-abort={ta}"]
        except Exception:  # noqa
            pass

        if attack == 0:
            wl = _ensure_wordlist(wordlist, self.log)
            cmd += [target, wl]
            if rule:
                cmd += ["-r", rule]
        elif attack == 3:
            cmd += [target, mask or "?a?a?a?a?a?a"]
        elif attack == 6:
            wl = _ensure_wordlist(wordlist, self.log)
            cmd += [target, wl, mask or "?d?d"]
        elif attack == 7:
            wl = _ensure_wordlist(wordlist, self.log)
            cmd += [target, mask or "?d?d", wl]
        if extra:
            cmd += extra.split()
        self._stream(cmd)
        self._stream([tool("hashcat"), "-m", str(mode), target, "--show"], tag_hint="crack")
        return self._emit_result()

    def resume_session(self, session):
        if not session:
            self.log("[!] No session name to resume.\n"); return
        self.log(f"[*] Resuming hashcat session '{session}'...\n")
        self._stream([tool("hashcat"), f"--session={session}", "--restore"])

    def preview(self, attack, wordlist, rule=None, mask=None, n=30):
        """Show the first n candidate passwords hashcat would try (`--stdout`)."""
        if not tool_available("hashcat"):
            self.log("[!] hashcat not installed.\n"); return
        cmd = [tool("hashcat"), "--stdout", "-a", str(attack)]
        if attack == 0:
            cmd += [_ensure_wordlist(wordlist, self.log)]
            if rule:
                cmd += ["-r", rule]
        elif attack == 3:
            cmd += [mask or "?a?a?a?a"]
        else:
            cmd += [_ensure_wordlist(wordlist, self.log), mask or "?d?d"]
        self.log(f"\n[*] Candidate preview (first {n}):\n$ {' '.join(cmd)}\n")
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            for i, line in enumerate(p.stdout):
                if i >= n:
                    break
                self.log("    " + line)
            p.terminate()
        except Exception as e:  # noqa
            self.log(f"[!] {e}\n")

    def smart_auto(self, mode, target, wordlist, **hc):
        """Escalate automatically: wordlist -> wordlist+best64 -> common masks."""
        self.log("\n[*] SMART AUTO: escalating until something cracks…\n")
        # step 1 — straight wordlist
        self.log("[*] Stage 1/3: straight wordlist\n")
        if self.run_hashcat(mode, target, wordlist, attack=0, **hc):
            return True
        if self.cancelled.is_set():
            return False
        # step 2 — wordlist + best64 rule
        rule = None
        for r in find_rules():
            if "best64" in r:
                rule = r; break
        if rule:
            self.log("[*] Stage 2/3: wordlist + best64 rules\n")
            if self.run_hashcat(mode, target, wordlist, attack=0, rule=rule, **hc):
                return True
        # step 3 — common masks
        for mask in ("?d?d?d?d?d?d", "?d?d?d?d?d?d?d?d", "?l?l?l?l?l?l"):
            if self.cancelled.is_set():
                return False
            self.log(f"[*] Stage 3/3: mask {mask}\n")
            if self.run_hashcat(mode, target, wordlist, attack=3, mask=mask, **hc):
                return True
        self.log("[×] Smart auto exhausted its stages without a hit.\n")
        return False

    def run_john(self, target, wordlist, jformat=None, rules=None):
        if not tool_available("john"):
            self.log("[!] john not installed.\n"); return
        self.last_cracked = []
        wl = _ensure_wordlist(wordlist, self.log)
        cmd = [tool("john"), f"--wordlist={wl}"]
        if rules:
            cmd.append("--rules" if rules is True else f"--rules={rules}")
        if jformat:
            cmd.append(f"--format={jformat}")
        cmd.append(target)
        self._stream(cmd)
        self._stream([tool("john"), "--show"] + ([f"--format={jformat}"] if jformat else []) + [target],
                     tag_hint="crack")
        return self._emit_result()

    def run_aircrack(self, pcap, wordlist):
        if not tool_available("aircrack-ng"):
            self.log("[!] aircrack-ng not installed.\n"); return
        wl = _ensure_wordlist(wordlist, self.log)
        self._stream([tool("aircrack-ng"), pcap, "-w", wl])

    def run_hcxtools_then_hashcat(self, pcap, wordlist, **hc):
        if not tool_available("hcxpcapngtool"):
            self.log("[!] hcxpcapngtool not installed (apt install hcxtools).\n"); return
        out = tempfile.NamedTemporaryFile(delete=False, suffix=".hc22000").name
        self.log(f"[*] hcxpcapngtool -o {out} {pcap}\n")
        self._stream([tool("hcxpcapngtool"), "-o", out, pcap])
        if os.path.exists(out) and os.path.getsize(out) > 0:
            self.run_hashcat(22000, out, wordlist, **hc)
        else:
            self.log("[!] No WPA/PMKID material extracted from capture.\n")

    def _stream(self, cmd, tag_hint=None):
        proc = None
        try:
            with self._process_lock:
                if self.cancelled.is_set():
                    return
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, errors="replace", bufsize=1)
                self.proc = proc
            self.log(f"\n$ {' '.join(cmd)}\n")
            self._note("cmd", " ".join(cmd))
            with proc.stdout as output:
                for line in output:
                    self.log(line)
                    if tag_hint == "crack":
                        self._maybe_capture(line)
                    if self.on_progress:
                        m = re.match(r"\s*Progress\.+:\s*(\d+)/(\d+)", line)
                        if m and int(m.group(2)):
                            self.on_progress(int(m.group(1)) / int(m.group(2)))
            self.log(f"[exit {proc.wait()}]\n")
        except Exception as exc:
            self.log(f"[!] {exc}\n")
        finally:
            with self._process_lock:
                if self.proc is proc:
                    self.proc = None

    def _maybe_capture(self, line):
        s = line.strip()
        if not s or ":" not in s:
            return
        low = s.lower()
        if any(k in low for k in ("password hash", "no hashes", "exhausted",
                                  "session", "status", "recovered", "started", "using")):
            return
        # hash:plain  (hashcat) or user:plain:... (john)
        parts = s.split(":")
        plain = parts[-1] if len(parts) == 2 else parts[1] if len(parts) > 2 else None
        if plain and plain not in self.last_cracked:
            self.last_cracked.append(plain)

    def _emit_result(self):
        success = bool(self.last_cracked)
        if success:
            self.log(f"\n[✓] CRACKED: {', '.join(self.last_cracked)}\n")
            self._note("crack", ", ".join(self.last_cracked))
        else:
            self.log("\n[×] No plaintext recovered this run.\n")
            self._note("miss", "no result")
        if self.audit:
            self.audit.append("crack_result", success=success,
                              count=len(self.last_cracked))
        if self.on_result:
            try:
                self.on_result(success, list(self.last_cracked))
            except Exception:  # noqa
                pass
        return success

    def export_report(self, path):
        from datetime import datetime
        with open(path, "w") as f:
            f.write(f"# {APP_NAME} — session report\n\n")
            f.write(f"_Generated {datetime.now():%Y-%m-%d %H:%M:%S}_\n\n")
            crk = [t for k, t in self.record if k == "crack"]
            f.write(f"**Cracked:** {len(crk)}\n\n")
            f.write("## Timeline\n\n")
            for kind, text in self.record:
                icon = {"cmd": "`$`", "crack": "✅", "miss": "❌",
                        "note": "•", "analyze": "🔍"}.get(kind, "•")
                f.write(f"- {icon} {text}\n")
            f.write("\n## Trophies (potfiles)\n\n")
            for s, h, p in Trophy.entries():
                f.write(f"- [{s}] `{h}` → `{p}`\n")
        return path


def _ensure_wordlist(wordlist, log):
    """If given rockyou.txt but only .gz exists, gunzip it."""
    if wordlist.endswith(".txt") and not os.path.exists(wordlist):
        gz = wordlist + ".gz"
        if os.path.exists(gz):
            log(f"[*] Decompressing {gz} ...\n")
            subprocess.run(["gunzip", "-k", gz])
    return wordlist


# --------------------------------------------------------------------------- #
#  GUI                                                                          #
# --------------------------------------------------------------------------- #
def launch_gui():
    try:
        import customtkinter as ctk
        import tkinter as tk
        from tkinter import filedialog, colorchooser, font as tkfont
    except Exception as e:  # noqa
        print("[!] customtkinter/tkinter missing. Run the 'Install deps' step or:")
        print("    pip install customtkinter pillow  &&  apt install python3-tk")
        print(f"    ({e})")
        sys.exit(1)

    ctk.set_appearance_mode(CFG.data.get("appearance", "dark"))
    ctk.set_default_color_theme("dark-blue")

    app = ctk.CTk()
    app.title(f"{APP_NAME} — CTF cracking orchestrator")
    app.geometry(f"{min(1120, app.winfo_screenwidth() - 40)}x"
                 f"{min(840, app.winfo_screenheight() - 100)}")
    app.minsize(760, 600)
    app.configure(fg_color=INK)

    # Register on Tk's input classes so CTk's inner entry, combo-box and
    # textbox widgets all use the same clipboard shortcuts and context menu.
    edit_menu = tk.Menu(app, tearoff=False)
    edit_target = None

    def edit_event(widget, action):
        widget.focus_set()
        widget.event_generate(f"<<{action}>>")
        return "break"

    def show_edit_menu(event):
        nonlocal edit_target
        edit_target = event.widget
        edit_target.focus_set()
        try:
            edit_menu.tk_popup(event.x_root, event.y_root)
        finally:
            edit_menu.grab_release()
        return "break"

    for operation in ("Cut", "Copy", "Paste"):
        edit_menu.add_command(label=operation, command=lambda action=operation: edit_event(edit_target, action))
    for widget_class in ("Entry", "Text"):
        app.bind_class(widget_class, "<Button-3>", show_edit_menu, add="+")
        for key, operation in (("x", "Cut"), ("c", "Copy"), ("v", "Paste")):
            app.bind_class(widget_class, f"<Control-{key}>",
                           lambda event, action=operation: edit_event(event.widget, action))


    # whole-window transparency (Tk widgets can't be individually see-through, but
    # the WM/compositor can make the whole window translucent so your desktop —
    # wallpaper or a live GIF — shows through everything, terminal included).
    try:
        _op = float(CFG.data.get("window_opacity", 1.0))
        if 0.2 <= _op < 1.0:
            app.attributes("-alpha", _op)
    except Exception:  # noqa
        pass

    # ---- loading splash: shown immediately, forced to paint, removed once
    # ---- the heavier init (GPU scan, wordlist discovery, tab build) is done
    splash = tk.Frame(app, bg=INK)
    splash.place(x=0, y=0, relwidth=1, relheight=1)
    splash.lift()
    tk.Label(splash, text="🥕", bg=INK, fg=CARROT, font=(CFG.data["font_family"], 48)
            ).pack(pady=(220, 10))
    tk.Label(splash, text=f"Starting {APP_NAME}…", bg=INK, fg=CFG.c("logfg"),
            font=(CFG.data["font_family"], 16, "bold")).pack()
    splash_status = tk.Label(splash, text="Scanning GPU / hardware…", bg=INK, fg=MUTE,
                             font=(CFG.data["font_family"], 11))
    splash_status.pack(pady=(6, 0))
    app.update_idletasks()
    app.update()  # force an actual paint now, before any slow init below runs

    def _splash(msg):
        try:
            splash_status.configure(text=msg)
            app.update_idletasks()
            app.update()
        except Exception:  # noqa
            pass

    state = {"analysis": None, "source": None, "busy": False}
    engine_ref = {"engine": None}
    hw_ref = {"hw": Hardware().scan()}
    anim_ref = {"bg": None, "header": None}
    _splash("Loading GIF background…")

    gcfg = CFG.data["gif"]
    gif_src = GifSource(gcfg.get("path", "")) if (gcfg.get("enabled") and PIL_OK) else GifSource("")

    def restart_app():
        """Re-exec to apply theme/text/GIF changes cleanly."""
        CFG.save()
        try:
            for a in (anim_ref["bg"], anim_ref["header"], anim_ref.get("log")):
                if a:
                    a.stop()
        except Exception:  # noqa
            pass
        os.execv(sys.executable, [sys.executable, os.path.abspath(__file__), *sys.argv[1:]])

    # ---- full-window animated backdrop (optional) ------------------------ #
    if gif_src.ok and gcfg.get("fullbg", True):
        bg_label = tk.Label(app, bd=0, highlightthickness=0, bg=INK)
        bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        bg_label.lower()
        a = GifAnimator(bg_label, gif_src, dim=gcfg.get("dim", 0.55), mode="label")
        a.start()
        anim_ref["bg"] = a
        margin = int(gcfg.get("margin", 16))
    else:
        margin = 0

    # ---- header ---------------------------------------------------------- #
    if os.name == "nt":
        root_ok = _is_admin_windows()
        root_txt = "ADMIN ✓" if root_ok else "NOT ADMIN ✗"
    else:
        root_ok = (os.geteuid() == 0)
        root_txt = "ROOT ✓" if root_ok else "NOT ROOT ✗"
    root_col = LEAF if root_ok else "#ff4d4d"

    if gif_src.ok and gcfg.get("header", True):
        header = tk.Canvas(app, height=88, bd=0, highlightthickness=0, bg=PANEL)
        header.pack(fill="x", padx=margin, pady=(margin, 6))
        t_title = header.create_text(20, 40, anchor="w", text=CFG.t("app_title"),
                                     fill=CARROT, font=CFG.font(24, "bold"))
        t_tag = header.create_text(24, 66, anchor="w", text=CFG.t("tagline"),
                                   fill=CFG.c("logfg"), font=CFG.font(12, "italic"))
        t_root = header.create_text(0, 44, anchor="e", text=root_txt, fill=root_col,
                                    font=CFG.font(13, "bold"))
        header.bind("<Configure>",
                    lambda e: header.coords(t_root, header.winfo_width() - 20, 44))
        a = GifAnimator(header, gif_src, dim=gcfg.get("header_dim", 0.25),
                        mode="canvas", text_items=[t_title, t_tag, t_root])
        a.start()
        anim_ref["header"] = a
    else:
        header = ctk.CTkFrame(app, fg_color=PANEL, corner_radius=0)
        header.pack(fill="x", padx=margin, pady=(margin, 0))
        ctk.CTkLabel(header, text=CFG.t("app_title"), font=CFG.font(26, "bold"),
                     text_color=CARROT).pack(side="left", padx=18, pady=12)
        ctk.CTkLabel(header, text=root_txt, text_color=root_col,
                     font=CFG.font(13, "bold")).pack(side="right", padx=18)
        ctk.CTkLabel(header, text=CFG.t("tagline"), text_color=MUTE,
                     font=CFG.font(12, "italic")).pack(side="right", padx=8)

    # ---- persistent fine-print footer ----------------------------------- #
    footer = ctk.CTkFrame(app, fg_color=PANEL, corner_radius=0, height=24)
    footer.pack(side="bottom", fill="x")
    ctk.CTkLabel(footer, text="⚖ " + FOOTER, text_color=MUTE,
                 font=CFG.font(10)).pack(pady=3)

    nav = ctk.CTkFrame(app, fg_color=PANEL)
    nav.pack(fill="x", padx=max(10, margin), pady=(8, 2))
    pages = ctk.CTkFrame(app, fg_color="transparent")
    pages.pack(fill="both", expand=True, padx=max(10, margin), pady=(4, 10))
    pages.grid_rowconfigure(0, weight=1)
    pages.grid_columnconfigure(0, weight=1)
    names = ["Workbench", "Setup", "Reference", "Trophies", "Online",
             "Wordlists", "Governance", "Plugins", "Appearance"]
    panels = {name: ctk.CTkFrame(pages, fg_color="transparent") for name in names}
    t_crack, t_setup, t_ref, t_trophy, t_online, t_wlgen, t_gov, t_plugins, t_custom = panels.values()
    nav_var = ctk.StringVar(value="Workbench")
    active_panel = None

    def open_page(name):
        nonlocal active_panel
        if active_panel is not None:
            active_panel.grid_remove()
        active_panel = panels[name]
        active_panel.grid(row=0, column=0, sticky="nsew")
        nav_var.set(name)

    ctk.CTkLabel(nav, text="C4 /  OPERATIONS", text_color=LEAF,
                 font=CFG.font(11, "bold")).pack(side="left", padx=14, pady=8)
    for name in ("Workbench", "Setup", "Trophies"):
        ctk.CTkButton(nav, text=name, width=84, fg_color=CFG.c("panel2"),
                      command=lambda page=name: open_page(page)).pack(side="left", padx=3)
    ctk.CTkOptionMenu(nav, values=names, variable=nav_var, width=128,
                      command=open_page).pack(side="right", padx=8)
    open_page("Workbench")

    t_crack.grid_columnconfigure(0, weight=1)
    t_crack.grid_rowconfigure(0, weight=3, minsize=224)
    t_crack.grid_rowconfigure(3, weight=2, minsize=90)
    output = ctk.CTkFrame(t_crack, fg_color=PANEL)
    output.grid(row=3, column=0, sticky="nsew", pady=(5, 0))
    ctk.CTkLabel(output, text="03  /  ACTIVITY & RESULTS", text_color=LEAF,
                 font=CFG.font(11, "bold")).pack(anchor="w", padx=12, pady=(5, 0))

    # shared log box (crack tab) — optionally over a second animated GIF
    _log_parent = output
    _log_over_gif = False
    _log_gif_path = CFG.data["gif"].get("log_path", "")
    if (CFG.data["gif"].get("enabled") and _log_gif_path and PIL_OK
            and os.path.exists(_log_gif_path)):
        try:
            _log_gif_src = GifSource(_log_gif_path)
            if _log_gif_src.ok:
                _logwrap = tk.Frame(output, bg=CFG.c("logbg"))
                _logwrap.pack(fill="both", expand=True, padx=6, pady=6)
                _log_bg_label = tk.Label(_logwrap, bd=0, highlightthickness=0, bg=CFG.c("logbg"))
                _log_bg_label.place(x=0, y=0, relwidth=1, relheight=1)
                _lganim = GifAnimator(_log_bg_label, _log_gif_src,
                                      dim=CFG.data["gif"].get("log_dim", 0.62), mode="label")
                _lganim.start()
                anim_ref["log"] = _lganim
                _log_parent = _logwrap
                _log_over_gif = True
        except Exception:  # noqa
            _log_parent = output

    logbox = ctk.CTkTextbox(_log_parent, fg_color=CFG.c("logbg"), text_color=CFG.c("logfg"),
                            font=CFG.font(12), height=105, wrap="word")
    _TXT = logbox._textbox  # underlying tk.Text, for colored tags

    _HL_TAGS = {
        "crack": (LEAF, True), "flag": (CARROT, True), "warn": ("#ffd27a", False),
        "err": ("#ff6b6b", True), "cmd": ("#7fd6ff", False), "good": (LEAF, False),
        "dim": (MUTE, False), "hdr": (CARROT, True),
    }
    for _name, (_col, _bold) in _HL_TAGS.items():
        try:
            _TXT.tag_configure(_name, foreground=_col,
                               font=CFG.font(12, "bold") if _bold else CFG.font(12))
        except Exception:  # noqa
            pass
    # high-visibility highlight for a recovered secret: black text on a bright
    # carrot/green background so it's impossible to miss in the scrollback.
    try:
        _TXT.tag_configure("hit", foreground="#000000", background=CARROT,
                           font=CFG.font(14, "bold"))
        _TXT.tag_configure("hitline", foreground=LEAF, background="#0a2a17",
                           font=CFG.font(13, "bold"))
    except Exception:  # noqa
        pass

    _FLAG_RX = re.compile(r"(flag|ctf|htb|thm|pico)\s*\{", re.I)

    def _tag_for(line):
        s = line.strip()
        if not s:
            return None
        if _FLAG_RX.search(s):
            return "flag"
        if "CRACKED" in s or "[✓]" in s or "UNLOCKED" in s or "recovered" in s.lower():
            return "crack"
        if s.startswith("$ "):
            return "cmd"
        if "[!]" in s or "[×]" in s or "fail" in s.lower() or "error" in s.lower():
            return "err" if "[×]" in s else "warn"
        if s.startswith("===") or s.startswith("["):
            if "[+]" in s:
                return "good"
            if "[*]" in s:
                return "dim"
            return "hdr" if s.startswith("===") else "dim"
        return None

    ui_queue = queue.Queue()

    def flush_ui_queue():
        for _ in range(100):
            try:
                callback, args = ui_queue.get_nowait()
            except queue.Empty:
                break
            callback(*args)
        app.after(30, flush_ui_queue)

    def on_ui(callback, *args):
        ui_queue.put((callback, args))

    app.after(30, flush_ui_queue)

    def log(msg):
        if threading.current_thread() is not threading.main_thread():
            on_ui(log, msg)
            return
        for line in msg.splitlines(keepends=True):
            start = _TXT.index("end-1c")
            logbox.insert("end", line)
            tag = _tag_for(line)
            if tag:
                try:
                    _TXT.tag_add(tag, start, _TXT.index("end-1c"))
                except Exception:  # noqa
                    pass
        logbox.see("end")

    def highlight_hit(secrets):
        """Draw an impossible-to-miss highlighted banner in the log AND light up
        the persistent results bar when a secret is recovered."""
        if not secrets:
            return
        try:
            bar = "═" * 52
            log("\n")
            s0 = _TXT.index("end-1c")
            logbox.insert("end", f"  ★★★  CRACKED — {len(secrets)} SECRET"
                                 f"{'S' if len(secrets) != 1 else ''} RECOVERED  ★★★  \n")
            _TXT.tag_add("hit", s0, _TXT.index("end-1c"))
            for sec in secrets:
                sl = _TXT.index("end-1c")
                logbox.insert("end", f"    ▸ {sec}\n")
                _TXT.tag_add("hit", sl, _TXT.index("end-1c"))
            log("\n")
            logbox.see("end")
        except Exception:  # noqa
            pass
        # persistent top bar
        try:
            txt = f"  Recovered {len(secrets)} result(s)  ·  See activity or copy"
            results_bar.configure(text=txt, fg_color=CARROT, text_color="#000000")
            results_copy_btn.configure(state="normal")
            results_ref["secrets"] = list(secrets)
        except Exception:  # noqa
            pass

    engine_ref["engine"] = Engine(log)

    # ---- governance: audit trail + scope ------------------------------- #
    gov = CFG.data.get("governance", {})
    audit_path = gov.get("audit_log") or str(CONFIG_DIR / "audit.log.jsonl")
    audit = AuditLog(audit_path)
    engine_ref["engine"].audit = audit
    audit.append("app_start", version="gov", user=os.environ.get("SUDO_USER", "?"))
    scope_ref = {"scope": None}
    if gov.get("scope_file") and os.path.exists(gov["scope_file"]):
        try:
            scope_ref["scope"] = Scope.load(gov["scope_file"])
            audit.append("scope_loaded", file=gov["scope_file"],
                         engagement=scope_ref["scope"].engagement)
        except Exception as e:  # noqa
            log(f"[!] scope load failed: {e}\n")

    # ---- live cracking monitor: scrambling numbers + red/green padlock ---- #
    class CrackMonitor:
        AMBER = "#ffb347"
        RED = "#ff5555"
        DIM = "#2f7d4f"

        SCRAMBLERS = {
            "matrix":   "0123456789ABCDEF@#%&/\\<>{}[]=+*?abcdefghΞΨΩ░▒▓█",
            "hex":      "0123456789abcdef",
            "binary":   "01",
            "katakana": "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎ0123456789",
            "glitch":   "▓▒░█▚▞▜▙▟▛@#%&$!?*<>=/\\|",
            "braille":  "⠁⠂⠃⠄⠅⠆⠇⠈⠉⠊⠋⠌⠍⠎⠏⠐⠑⠒⠓⠔⠕⠖⠗⠘⠙⣿⣾⣽⣻⢿⡿",
        }
        LOCK_STYLES = ("padlock", "shield", "circuit", "skull", "vault")

        def __init__(self, parent, size=None, fullwidth=None,
                     lock_style=None, scrambler=None):
            mcfg = CFG.data.get("monitor", {})
            self.SZ = int(size if size is not None else mcfg.get("size", 180))
            self.SZ = max(120, min(420, self.SZ))
            self.fullwidth = bool(fullwidth if fullwidth is not None
                                  else mcfg.get("fullwidth", True))
            self.lock_style = lock_style or mcfg.get("lock_style", "padlock")
            self.scrambler = scrambler or mcfg.get("scrambler", "matrix")
            self.frame = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=12)
            self.canvas = tk.Canvas(self.frame, width=self.SZ, height=self.SZ, bg=PANEL,
                                    highlightthickness=0, bd=0)
            self.canvas.pack(side="left", padx=(16, 14), pady=10)
            right = ctk.CTkFrame(self.frame, fg_color="transparent")
            right.pack(side="left", fill="both", expand=True, pady=10)
            # cascade rows scale with size; font a touch bigger on bigger canvases
            self._nrows = max(5, self.SZ // 30)
            fsize = 14 + (self.SZ - 180) // 90
            self.rows = []
            for i in range(self._nrows):
                lbl = ctk.CTkLabel(right, text="", anchor="w",
                                   font=(CFG.data["font_family"], max(11, fsize), "bold"),
                                   text_color=(LEAF if i == 0 else self.DIM))
                lbl.pack(anchor="w")
                self.rows.append(lbl)
            self.status = ctk.CTkLabel(right, text="◆ IDLE", font=CFG.font(14, "bold"),
                                       text_color=MUTE, anchor="w")
            self.status.pack(anchor="w", pady=(4, 0))
            self._running = False
            self._phase = 0
            self._solved = 0
            self._target = ""
            self._pct = 0.0
            import random
            self._cols = self.SZ // 12
            self._drops = [random.randint(-14, 0) for _ in range(self._cols)]
            # width of the cascade: fill the window if fullwidth, else fixed
            self._cwidth = 24
            glyph_width = max(1, tkfont.Font(root=app, font=(CFG.data["font_family"], max(11, fsize), "bold")).measure("M"))
            right.bind("<Configure>", lambda event: setattr(
                self, "_cwidth", max(1, min(120 if self.fullwidth else 46, (event.width - 12) // glyph_width))))
            self.draw_lock(self.AMBER, closed=True, ring=False)

        def _charset(self):
            return self.SCRAMBLERS.get(self.scrambler, self.SCRAMBLERS["matrix"])

        def _rain(self, c, color):
            import random
            glyphs = self._charset()
            for i in range(self._cols):
                x = i * 12 + 6
                y = self._drops[i] * 12
                for k in range(4):
                    yy = y - k * 12
                    if 0 <= yy < self.SZ:
                        shade = color if k == 0 else self.DIM
                        c.create_text(x, yy, text=random.choice(glyphs),
                                      fill=shade, font=("monospace", 8))
                self._drops[i] += 1
                if self._drops[i] * 12 > self.SZ + random.randint(0, self.SZ):
                    self._drops[i] = random.randint(-6, 0)

        # ---- lock-style renderers (all scale to self.SZ) ------------------
        def _emblem(self, c, color, closed, cx, cy, u):
            """u = unit scale. Draw the chosen emblem."""
            st = self.lock_style
            if st == "shield":
                pts = [cx, cy-3*u, cx+2.6*u, cy-1.8*u, cx+2.6*u, cy+1.2*u,
                       cx, cy+3.2*u, cx-2.6*u, cy+1.2*u, cx-2.6*u, cy-1.8*u]
                c.create_polygon(pts, outline=color, width=3, fill="")
                if closed:
                    c.create_line(cx, cy-1.2*u, cx, cy+1.4*u, fill=color, width=3)
                    c.create_oval(cx-0.5*u, cy-1.6*u, cx+0.5*u, cy-0.6*u, outline=color, width=2)
                else:
                    c.create_text(cx, cy, text="✓", fill=color, font=("monospace", int(2.4*u)))
                return
            if st == "circuit":
                c.create_rectangle(cx-2.6*u, cy-2.6*u, cx+2.6*u, cy+2.6*u,
                                   outline=color, width=3)
                for dx in (-1.3, 0, 1.3):
                    c.create_line(cx+dx*u, cy-2.6*u, cx+dx*u, cy-3.4*u, fill=color, width=2)
                    c.create_line(cx+dx*u, cy+2.6*u, cx+dx*u, cy+3.4*u, fill=color, width=2)
                    c.create_line(cx-2.6*u, cy+dx*u, cx-3.4*u, cy+dx*u, fill=color, width=2)
                    c.create_line(cx+2.6*u, cy+dx*u, cx+3.4*u, cy+dx*u, fill=color, width=2)
                r = 0.9*u if closed else 1.4*u
                c.create_oval(cx-r, cy-r, cx+r, cy+r, outline=color,
                              width=2, fill=(color if not closed else ""))
                return
            if st == "skull":
                c.create_oval(cx-2.4*u, cy-2.8*u, cx+2.4*u, cy+1.2*u, outline=color, width=3)
                c.create_rectangle(cx-1.4*u, cy+1.0*u, cx+1.4*u, cy+2.6*u, outline=color, width=3)
                eye = "●" if not closed else "○"
                c.create_text(cx-1.1*u, cy-0.9*u, text=eye, fill=color, font=("monospace", int(1.3*u)))
                c.create_text(cx+1.1*u, cy-0.9*u, text=eye, fill=color, font=("monospace", int(1.3*u)))
                c.create_line(cx, cy-0.2*u, cx, cy+0.6*u, fill=color, width=2)
                return
            if st == "vault":
                c.create_oval(cx-3*u, cy-3*u, cx+3*u, cy+3*u, outline=color, width=3)
                c.create_oval(cx-2*u, cy-2*u, cx+2*u, cy+2*u, outline=color, width=2)
                ang = (self._phase * 6) % 360 if closed else 45
                import math
                for a in (ang, ang+90, ang+180, ang+270):
                    rad = math.radians(a)
                    c.create_line(cx, cy, cx+2.6*u*math.cos(rad), cy+2.6*u*math.sin(rad),
                                  fill=color, width=2)
                c.create_oval(cx-0.5*u, cy-0.5*u, cx+0.5*u, cy+0.5*u, outline=color,
                              width=2, fill=color)
                return
            # default: padlock
            c.create_rectangle(cx-1.8*u, cy-0.4*u, cx+1.8*u, cy+3.0*u, outline=color, width=3)
            c.create_oval(cx-0.5*u, cy+0.8*u, cx+0.5*u, cy+1.8*u, outline=color, width=2)
            c.create_line(cx, cy+1.6*u, cx, cy+2.6*u, fill=color, width=3)
            if closed:
                c.create_arc(cx-1.4*u, cy-3.2*u, cx+1.4*u, cy-0.2*u, start=0, extent=180,
                             style="arc", outline=color, width=3)
                c.create_line(cx-1.4*u, cy-1.7*u, cx-1.4*u, cy-0.4*u, fill=color, width=3)
                c.create_line(cx+1.4*u, cy-1.7*u, cx+1.4*u, cy-0.4*u, fill=color, width=3)
            else:
                c.create_arc(cx-0.6*u, cy-4.2*u, cx+2.2*u, cy-1.2*u, start=10, extent=180,
                             style="arc", outline=color, width=3)
                c.create_line(cx-0.6*u, cy-2.7*u, cx-0.6*u, cy-0.6*u, fill=color, width=3)
                c.create_line(cx+2.2*u, cy-2.7*u, cx+2.2*u, cy-1.6*u, fill=color, width=3)

        def draw_lock(self, color, closed=True, ring=True, glow_r=0, rain=False, scan=False):
            c = self.canvas
            c.delete("all")
            cx = cy = self.SZ // 2
            R = self.SZ * 0.43           # ring radius scales with size
            if rain:
                self._rain(c, color)
            if ring:
                start = (self._phase * 12) % 360
                for k, (ext, wid, col, rr) in enumerate(
                        ((110, 3, color, R), (70, 2, self.DIM, R), (50, 2, color, R*0.85))):
                    c.create_arc(cx-rr, cy-rr, cx+rr, cy+rr,
                                 start=start + k*120, extent=ext, style="arc",
                                 outline=col, width=wid)
                if self._pct > 0:
                    pr = R * 0.9
                    c.create_arc(cx-pr, cy-pr, cx+pr, cy+pr, start=90,
                                 extent=-360 * min(1.0, self._pct), style="arc",
                                 outline=LEAF, width=4)
            if glow_r:
                for g in (glow_r, glow_r - 8):
                    if g > 0:
                        c.create_oval(cx-g, cy-g, cx+g, cy+g, outline=color, width=1)
            if scan:
                sy = cy - R*0.6 + ((self._phase * 6) % int(R*1.2))
                c.create_line(cx-R*0.55, sy, cx+R*0.55, sy, fill=color, width=1)
            self._emblem(c, color, closed, cx, cy, self.SZ / 22.0)

        def _tick(self):
            if not self._running:
                return
            import random, math
            self._phase += 1
            glyphs = self._charset()
            width = self._cwidth
            pulse = (math.sin(self._phase / 5.0) + 1) / 2
            glow_r = int(self.SZ*0.29 + pulse * 12)
            self.draw_lock(self.AMBER, closed=True, ring=True, glow_r=glow_r,
                           rain=True, scan=True)
            self._solved = (self._solved + 1) % (width + 12)
            locked = self._target[:self._solved]
            spin = "".join(random.choice(glyphs) for _ in range(max(0, width - len(locked))))
            self.rows[0].configure(text=(locked + spin)[:width], text_color=LEAF)
            shades = ("#39a35f", "#2f7d4f", "#245f3c", "#39a35f", "#2f7d4f")
            for i, r in enumerate(self.rows[1:]):
                r.configure(text="".join(random.choice(glyphs) for _ in range(width)),
                            text_color=shades[i % len(shades)])
            spinner = "⌁⚡✶✷"[self._phase % 4]
            self.status.configure(
                text=(f"{spinner} DECRYPTING… {int(self._pct*100)}%" if self._pct
                      else f"{spinner} DECRYPTING…"),
                text_color=self.AMBER)
            self.frame.after(35, self._tick)

        def set_progress(self, pct):
            try:
                self._pct = max(0.0, min(1.0, float(pct)))
            except Exception:  # noqa
                pass

        def start(self):
            if self._running:
                return
            import random
            self._running = True
            self._solved = 0
            self._phase = 0
            self._pct = 0.0
            self._target = "".join(random.choice("0123456789abcdef")
                                   for _ in range(self._cwidth))
            self.status.configure(text="⌁ DECRYPTING…", text_color=self.AMBER)
            self._tick()

        def success(self, plain=""):
            self._running = False
            self.draw_lock(LEAF, closed=False, ring=True, glow_r=int(self.SZ*0.33))
            self.rows[0].configure(text=("★ CRACKED ▸ " + (plain or "UNLOCKED"))[:self._cwidth],
                                   text_color=LEAF)
            for r in self.rows[1:]:
                r.configure(text="", text_color=MUTE)
            self.status.configure(text="🔓 UNLOCKED", text_color=LEAF)
            self._flash(LEAF, 0)

        def fail(self):
            self._running = False
            self.draw_lock(self.RED, closed=True, ring=False)
            self.rows[0].configure(text="No result from this run", text_color=self.RED)
            for r in self.rows[1:]:
                r.configure(text="", text_color=MUTE)
            self.status.configure(text="RUN ENDED", text_color=self.RED)
            self._flash(self.RED, 0)

        def _flash(self, color, n):
            if n >= 8:
                return
            import math
            r = int(self.SZ*0.28) + int(abs(math.sin(n)) * 22)
            closed = (color == self.RED)
            self.draw_lock(color, closed=closed, ring=not closed, glow_r=r)
            self.frame.after(85, lambda: self._flash(color, n + 1))

    # =====================  ANALYZE & CRACK TAB  ========================== #
    top = ctk.CTkScrollableFrame(t_crack, fg_color=PANEL, corner_radius=10,
                                 label_text="01  /  TARGET & ATTACK SETTINGS",
                                 label_text_color=LEAF, label_font=CFG.font(11, "bold"))
    top.grid(row=0, column=0, sticky="nsew")

    monitor = CrackMonitor(top)

    file_var = ctk.StringVar(value="")
    _splash("Scanning wordlists…")
    wl_lists = find_wordlists()
    wl_var = ctk.StringVar(value=wl_lists[0])
    engine_var = ctk.StringVar(value="auto")
    mode_var = ctk.StringVar(value="")
    backend_var = ctk.StringVar(value="auto")     # auto | gpu | cpu
    workload_var = ctk.StringVar(value="3 (high)")
    opt_var = ctk.BooleanVar(value=False)         # -O optimized kernels
    attack_var = ctk.StringVar(value="0 straight (wordlist)")
    rules_found = find_rules()
    rule_var = ctk.StringVar(value=(rules_found[0] if rules_found else "(none)"))
    mask_var = ctk.StringVar(value="?u?l?l?l?l?d?d")
    session_var = ctk.StringVar(value="c4rr07")

    source_var = ctk.StringVar(value="Paste text")
    source_card = ctk.CTkFrame(top, fg_color="transparent")
    source_card.pack(fill="x", padx=8, pady=(5, 8))
    row1 = ctk.CTkFrame(source_card, fg_color="transparent")
    paste_panel = ctk.CTkFrame(source_card, fg_color="transparent")
    ctk.CTkLabel(row1, text=CFG.t("lbl_target"), width=90, text_color=LEAF,
                 font=CFG.font(12, "bold")).pack(side="left", padx=6)
    ctk.CTkEntry(row1, textvariable=file_var, font=CFG.font(12)).pack(
        side="left", fill="x", expand=True, padx=6)

    def pick_file():
        p = filedialog.askopenfilename(initialdir=_start_dir(), title="Select target file")
        if p:
            file_var.set(p)

    ctk.CTkButton(row1, text=CFG.t("btn_browse"), command=pick_file,
                  width=85).pack(side="left", padx=6)
    ctk.CTkLabel(paste_panel, text="Paste hashes (one per line), encoded text, or a cipher.",
                 text_color=MUTE, font=CFG.font(12)).pack(anchor="w", padx=4)
    paste_box = ctk.CTkTextbox(paste_panel, height=90, wrap="word", fg_color=CFG.c("logbg"),
                              border_width=1, border_color=CFG.c("panel2"), font=CFG.font(12))
    paste_box.pack(fill="x", padx=4, pady=(0, 4))

    def switch_source(value):
        for panel in (row1, paste_panel):
            panel.pack_forget()
        (paste_panel if value == "Paste text" else row1).pack(fill="x", pady=(5, 0))

    ctk.CTkSegmentedButton(source_card, values=["Paste text", "Open file"], variable=source_var,
                           command=switch_source, selected_color="#235a66").pack(anchor="w", padx=4)
    switch_source(source_var.get())

    def current_source():
        if source_var.get() == "Paste text":
            raw = paste_box.get("1.0", "end-1c")
            if not raw.strip():
                raise ValueError("Paste a hash, encoded text, or ciphertext first.")
            if len(raw) > 262144:
                raise ValueError("Text exceeds 256K characters. Use Open file for larger inputs.")
            return ("text", raw)
        p = str(Path(file_var.get().strip()).expanduser().resolve())
        if not os.path.isfile(p):
            raise ValueError("Choose a readable target file first.")
        st = os.stat(p)
        return ("file", p, st.st_mtime_ns, st.st_size)

    def run_job(action, needs_target=False, needs_analysis=False, offline=False):
        if state["busy"]:
            log("[!] Another workbench action is running.\n")
            return
        scope = scope_ref["scope"]
        if offline and scope and (scope.expired() or not scope.allow_offline):
            log("[!] The loaded scope disallows this offline attack.\n")
            return
        try:
            source = current_source() if needs_target else None
        except (OSError, ValueError) as exc:
            log(f"[!] {exc}\n")
            return
        if needs_analysis and source != state["source"]:
            log("[!] Analyze the current target before starting this action.\n")
            return
        state["busy"] = True
        engine = engine_ref["engine"]
        engine.cancelled.clear()
        engine.on_progress = engine.on_result = None
        if needs_analysis:
            _clear_results()
        job_status.configure(text="RUNNING", text_color=LEAF)

        def finish():
            state["busy"] = False
            job_status.configure(text="STOPPED" if engine.cancelled.is_set() else "READY",
                                 text_color=MUTE)
            if monitor._running:
                monitor.fail()

        def worker():
            try:
                if not needs_target:
                    action()
                elif source[0] == "file":
                    action(source[1], source)
                else:
                    with tempfile.TemporaryDirectory(prefix="c4rr07-") as folder:
                        target = Path(folder) / "pasted-input.txt"
                        target.write_bytes(source[1].encode("utf-8"))
                        action(str(target), source)
            except Exception as exc:
                log(f"[!] {exc}\n")
            finally:
                on_ui(finish)

        threading.Thread(target=worker, daemon=True).start()

    def do_analyze(p, source):
        display = p if source[0] == "file" else "Pasted input"
        log(f"\n{'='*60}\n[*] Analyzing: {display}\n")
        a = Analyzer.run(p)
        log(f"[+] file: {a.file_out or 'n/a'}\n")
        log(f"[+] kind: {a.kind}   ({a.detail})\n")
        if a.hash_candidates:
            log("[+] hash candidates (label / hashcat-mode / john-format):\n")
            for label, mode, jfmt in a.hash_candidates:
                log(f"      - {label:<28} m={mode}  --format={jfmt}\n")
        if a.pipeline:
            log("[+] planned pipeline:\n")
            for step in a.pipeline:
                log(f"      → {step}\n")
        for n in a.notes:
            log(f"    ! {n}\n")

        # plugin detectors get a chance to enrich the analysis
        pm = state.get("plugins")
        if pm:
            try:
                head = open(p, "rb").read(4096)
            except Exception:  # noqa
                head = b""
            for det in pm.api.detectors:
                try:
                    det(p, head, a, log)
                except Exception as e:  # noqa
                    log(f"[plugin] detector error: {e}\n")

        # quick encoding peek — flag if this 'hash' is really wrapped text
        if a.kind == "hash":
            try:
                with open(p, "r", errors="replace") as stream:
                    first = stream.readline(16384).strip()
                peel = Decoder.magic(first, depth=2)
                if peel:
                    top1 = peel[0]
                    tag = "FLAG " if top1[3] else ""
                    log(f"    ! looks decodable: {tag}[{' -> '.join(top1[0])}] {top1[1][:60]}\n")
                    log("      (use the 🔓 Decode button for the full peel)\n")
            except Exception:  # noqa
                pass

        engine_ref["engine"]._note("analyze", f"{display} -> {a.kind}")
        try:
            digest = sha256_file(p)
            audit.append("file_analyzed" if source[0] == "file" else "text_analyzed",
                         path=display, sha256=digest, kind=a.kind)
            log(f"[+] sha256: {digest}\n")
        except Exception:  # noqa
            pass

        # auto-fill engine/mode — MUST run on the UI thread, since do_analyze
        # runs in a worker thread and Tk/CTk widget updates (esp. rebuilding an
        # OptionMenu's values) silently fail off-thread. This is why the hashcat
        # mode dropdown was coming up empty.
        def _apply_ui():
            state.update(analysis=a, source=source)
            engine_var.set(a.suggested_engine if a.suggested_engine != "none" else "hashcat")
            mode_var.set(str(a.suggested_mode) if a.suggested_mode is not None else "")
            _refresh_mode_menu(a)
            log("[*] Ready. Review, tweak the mode/wordlist, then hit CRACK.\n")
        on_ui(_apply_ui)

    row2 = ctk.CTkFrame(top, fg_color="transparent"); row2.pack(fill="x", pady=6)
    ctk.CTkLabel(row2, text=CFG.t("lbl_wordlist"), width=90, text_color=LEAF,
                 font=CFG.font(12, "bold")).pack(side="left", padx=6)
    wl_menu = ctk.CTkOptionMenu(row2, variable=wl_var, values=wl_lists,
                                fg_color=CFG.c("panel2"), button_color=CARROT, width=220, dynamic_resizing=False)
    wl_menu.pack(side="left", fill="x", expand=True, padx=6)

    def pick_wl():
        p = filedialog.askopenfilename(initialdir=_start_dir(), title="Select wordlist")
        if p:
            vals = list(dict.fromkeys([p] + wl_lists))
            wl_menu.configure(values=vals)
            wl_var.set(p)

    ctk.CTkButton(row2, text=CFG.t("btn_custom_wl"), fg_color="#2a2f34", hover_color="#3a4048",
                  command=pick_wl, width=90).pack(side="left", padx=6)

    row3 = ctk.CTkFrame(top, fg_color="transparent"); row3.pack(fill="x", pady=6)
    ctk.CTkLabel(row3, text=CFG.t("lbl_engine"), width=90, text_color=LEAF,
                 font=CFG.font(12, "bold")).pack(side="left", padx=6)
    ctk.CTkOptionMenu(row3, variable=engine_var,
                      values=["auto", "hashcat", "john", "aircrack", "hcxtools"],
                      fg_color=CFG.c("panel2"), button_color=CARROT, width=150).pack(side="left", padx=6)
    ctk.CTkLabel(row3, text="hashcat mode", text_color=MUTE,
                 font=CFG.font(12)).pack(side="left", padx=(18, 4))
    # common hashcat modes offered so the dropdown is populated from the start
    COMMON_MODES = [
        "0  (MD5)", "100  (SHA1)", "1400  (SHA256)", "1700  (SHA512)",
        "1000  (NTLM)", "3200  (bcrypt)", "1800  (sha512crypt)", "500  (md5crypt)",
        "22000  (WPA)", "13100  (Kerberoast)", "16500  (JWT HS256)",
    ]
    mode_menu = ctk.CTkComboBox(row3, variable=mode_var, values=COMMON_MODES,
                                  fg_color=CFG.c("panel2"), button_color=CARROT, width=240)
    mode_menu.pack(side="left", padx=6)

    # ---- compute / GPU row ---------------------------------------------- #
    row4 = ctk.CTkFrame(top, fg_color="transparent"); row4.pack(fill="x", pady=6)
    ctk.CTkLabel(row4, text=CFG.t("lbl_compute"), width=90, text_color=LEAF,
                 font=CFG.font(12, "bold")).pack(side="left", padx=6)
    ctk.CTkOptionMenu(row4, variable=backend_var, values=["auto", "gpu", "cpu"],
                      fg_color=CFG.c("panel2"), button_color=CARROT, width=110).pack(side="left", padx=6)
    ctk.CTkLabel(row4, text="workload", text_color=MUTE,
                 font=CFG.font(12)).pack(side="left", padx=(14, 4))
    ctk.CTkOptionMenu(row4, variable=workload_var,
                      values=["1 (low)", "2 (default)", "3 (high)", "4 (nightmare)"],
                      fg_color=CFG.c("panel2"), button_color=CARROT, width=150).pack(side="left", padx=6)
    ctk.CTkCheckBox(row4, text="-O optimized kernels", variable=opt_var,
                    fg_color=CARROT, hover_color="#d9660f",
                    font=CFG.font(12)).pack(side="left", padx=14)

    hw_line = ctk.CTkLabel(top, text="", text_color=MUTE,
                           font=CFG.font(11))
    hw_line.pack(anchor="w", padx=12)

    def _hw_oneliner():
        hw = hw_ref["hw"]
        gpus = [d for d in hw.devices if d["type"] == "GPU"]
        if gpus:
            names = ", ".join(d["name"] for d in gpus[:2])
            return f"🟢 GPU ready: {names}"
        if hw.gpu_present:
            return "🟠 GPU present, runtime missing — see Setup tab"
        return "⚪ CPU only"

    hw_line.configure(text=_hw_oneliner())

    def _workload_num():
        m = re.match(r"\s*(\d)", workload_var.get())
        return int(m.group(1)) if m else 3

    # ---- attack row (rules / masks / hybrid / session) ------------------ #
    row5 = ctk.CTkFrame(top, fg_color="transparent"); row5.pack(fill="x", pady=6)
    ctk.CTkLabel(row5, text="Attack", width=90, text_color=LEAF,
                 font=CFG.font(12, "bold")).pack(side="left", padx=6)
    ctk.CTkOptionMenu(row5, variable=attack_var,
                      values=["0 straight (wordlist)", "3 mask (brute)",
                              "6 hybrid word+mask", "7 hybrid mask+word"],
                      fg_color=CFG.c("panel2"), button_color=CARROT, width=155, dynamic_resizing=False).pack(side="left", padx=6)
    ctk.CTkLabel(row5, text="rule", text_color=MUTE, font=CFG.font(12)).pack(side="left", padx=(12, 2))
    ctk.CTkOptionMenu(row5, variable=rule_var,
                      values=(["(none)"] + rules_found) if rules_found else ["(none)"],
                      fg_color=CFG.c("panel2"), button_color=CARROT, width=160, dynamic_resizing=False).pack(side="left", padx=4)
    row6 = ctk.CTkFrame(top, fg_color="transparent"); row6.pack(fill="x", pady=6)
    ctk.CTkLabel(row6, text="mask", text_color=MUTE, font=CFG.font(12)).pack(side="left", padx=(12, 2))
    ctk.CTkComboBox(row6, variable=mask_var, values=COMMON_MASKS,
                     fg_color=CFG.c("panel2"), button_color=CARROT, width=150).pack(side="left", padx=4)
    ctk.CTkEntry(row6, textvariable=session_var, width=90,
                 font=CFG.font(11)).pack(side="left", padx=(12, 2))
    ctk.CTkLabel(row6, text="session", text_color=MUTE, font=CFG.font(10)).pack(side="left")

    # ---- live monitor (scramble + padlock) ------------------------------ #
    monitor.frame.pack(fill="x", padx=6, pady=(6, 2))

    # ---- persistent RESULTS bar (lights up bright when something cracks) --
    results_ref = {"secrets": []}
    resbar_frame = ctk.CTkFrame(t_crack, fg_color="transparent")
    resbar_frame.grid(row=2, column=0, sticky="ew", pady=(5, 0))
    results_bar = ctk.CTkLabel(resbar_frame, text="  No recovered results yet",
                               anchor="w", fg_color=CFG.c("panel2"), text_color=MUTE,
                               font=CFG.font(13, "bold"), corner_radius=8, height=34)
    results_bar.pack(side="left", fill="x", expand=True, ipady=2)

    def _copy_results():
        secs = results_ref.get("secrets", [])
        if not secs:
            return
        try:
            app.clipboard_clear()
            app.clipboard_append("\n".join(secs))
            results_copy_btn.configure(text="✓ Copied")
            results_copy_btn.after(1500, lambda: results_copy_btn.configure(text="⧉ Copy"))
        except Exception:  # noqa
            pass

    results_copy_btn = ctk.CTkButton(resbar_frame, text="⧉ Copy", width=80,
                                     fg_color="#2a2f34", hover_color="#3a4048",
                                     state="disabled", command=_copy_results)
    results_copy_btn.pack(side="left", padx=(6, 0))

    def _clear_results():
        results_ref["secrets"] = []
        results_bar.configure(text="  No recovered results yet",
                              fg_color=CFG.c("panel2"), text_color=MUTE)
        results_copy_btn.configure(state="disabled")
    ctk.CTkButton(resbar_frame, text="✕", width=36, fg_color="#2a2f34",
                  hover_color="#3a4048", command=_clear_results).pack(side="left", padx=(6, 0))

    def _attack_num():
        m = re.match(r"\s*(\d)", attack_var.get())
        return int(m.group(1)) if m else 0

    # common hashcat modes offered as a fallback so the dropdown is never empty
    def _refresh_mode_menu(a):
        opts = []
        for label, mode, jfmt in a.hash_candidates:
            if mode is not None:
                opts.append(f"{mode}  ({label})")
        if not opts and a.suggested_mode is not None:
            opts = [f"{a.suggested_mode}"]
        # never leave the menu empty — fall back to the common-mode list so the
        # user can always pick something even when auto-ID is uncertain
        full = opts + [m for m in COMMON_MODES if m not in opts]
        mode_menu.configure(values=full)
        if opts:
            mode_var.set(opts[0])
        else:
            mode_var.set("")

    def _selected_mode():
        raw = mode_var.get().strip()
        m = re.match(r"\s*(\d+)", raw)
        return int(m.group(1)) if m else None

    # ---- CRACK / STOP ---------------------------------------------------- #
    btnrow = ctk.CTkFrame(t_crack, fg_color=PANEL)
    btnrow.grid(row=1, column=0, sticky="ew", pady=(5, 0))

    def crack_settings():
        rule = rule_var.get().strip()
        return dict(wordlist=wl_var.get().strip(), engine=engine_var.get(),
                    backend=backend_var.get(), workload=_workload_num(),
                    optimized=opt_var.get(), attack=_attack_num(),
                    rule=None if rule in ("", "(none)") else rule,
                    mask=mask_var.get().strip(), session=session_var.get().strip() or None,
                    mode=_selected_mode())

    def start_attack(action):
        settings = crack_settings()
        run_job(lambda p, source: action(p, source, settings),
                needs_target=True, needs_analysis=True, offline=True)

    def do_crack(p, source, settings):
        a = state["analysis"]
        wl = settings["wordlist"]
        eng = settings["engine"]
        E = engine_ref["engine"]
        if not p:
            log("[!] No file.\n"); return
        if eng == "auto":
            eng = a.suggested_engine if a else "hashcat"
        if eng == "none":
            log("[i] This file type (APK) is for analysis, not cracking — use 🔎 APK scan.\n")
            return

        target = p
        # prep step for archive/office/ssh/keepass
        if a and a.prep_helper:
            hp = E.prepare_hash(a.prep_helper, p)
            if not hp:
                return
            target = hp

        # assemble hashcat compute settings from the GPU row
        hw = hw_ref["hw"]
        backend = settings["backend"]
        if backend == "gpu" and not hw.hashcat_sees_gpu:
            log("[!] GPU backend requested but hashcat sees no GPU device.\n")
            log("    -> Install the OpenCL runtime from the Setup tab, or use 'auto'/'cpu'.\n")
            return
        hc_opts = {key: settings[key] for key in ("backend", "workload", "optimized")}
        if source[0] == "text":
            hc_opts["extra"] = "--restore-disable"
        if hw.hashcat_sees_gpu and backend in ("auto", "gpu"):
            log(f"[*] Using GPU acceleration ({', '.join(hw.gpu_device_ids()) or 'auto'}) "
                f"@ workload {hc_opts['workload']}{' +O' if hc_opts['optimized'] else ''}.\n")

        # attack settings
        attack, rule, mask = (settings[key] for key in ("attack", "rule", "mask"))
        session = settings["session"] if source[0] == "file" else None

        # kick the live monitor (marshalled onto the UI thread)
        on_ui(monitor.start)

        def _result(success, plains):
            E.on_progress = None
            def _apply():
                if E.cancelled.is_set():
                    return
                if success:
                    monitor.success(plains[0] if plains else "")
                    highlight_hit(plains)
                else:
                    monitor.fail()
            on_ui(_apply)
        E.on_result = _result
        E.on_progress = lambda frac: on_ui(monitor.set_progress, frac)

        if eng == "hcxtools":
            E.run_hcxtools_then_hashcat(p, wl, attack=attack, rule=rule, mask=mask,
                                        session=session, **hc_opts)
        elif eng == "aircrack":
            log("[i] aircrack-ng is CPU-only; for GPU WPA cracking use the hcxtools engine (-m 22000).\n")
            E.last_cracked = []
            E.run_aircrack(p, wl)
            E._emit_result()
        elif eng == "john":
            jfmt = None
            if a and a.hash_candidates:
                jfmt = next((c[2] for c in a.hash_candidates if c[2]), None)
            E.run_john(target, wl, jfmt, rules=(True if rule else None))
        else:  # hashcat
            mode = settings["mode"]
            if mode is None:
                log("[!] No hashcat mode selected. Pick one from the dropdown.\n")
                on_ui(monitor.fail); return
            E.run_hashcat(mode, target, wl, attack=attack, rule=rule, mask=mask,
                          session=session, **hc_opts)
        log("\n[*] Job finished.\n")

    def do_decode(p, source):
        if source[0] == "text":
            sample = source[1].strip()[:16384]
        else:
            with open(p, "r", errors="replace") as stream:
                sample = stream.read(16384).strip()
        if not sample:
            log("[!] Empty file.\n"); return
        log("\n[*] Testing encodings and classical ciphers…\n")
        res = Decoder.magic(sample, depth=4)
        if not res:
            log("[i] No printable encoding candidate.\n")
        hits = []
        for chain, txt, score, flagged in res:
            mark = "FLAG " if flagged else ""
            log(f"    {mark}[{' -> '.join(chain)}]  {txt[:80]}\n")
            if flagged:
                hits.append(txt.strip())
        if re.search(r"[A-Za-z]", sample):
            from string import ascii_lowercase as lower, ascii_uppercase as upper
            excerpt = sample[:400]
            log("[i] Classical cipher candidates (preview, unverified):\n")
            log(f"    Atbash  {excerpt.translate(str.maketrans(lower + upper, lower[::-1] + upper[::-1]))}\n")
            for shift in range(1, 26):
                alphabet = lower[shift:] + lower[:shift] + upper[shift:] + upper[:shift]
                decoded = excerpt.translate(str.maketrans(alphabet, lower + upper))
                log(f"    Caesar −{shift:02d}  {decoded}\n")
        if hits:
            on_ui(highlight_hit, hits)

    def do_pcap_scan():
        p = file_var.get().strip() if source_var.get() == "Open file" else ""
        if not p or not os.path.exists(p):
            log("[!] Pick a pcap first.\n"); return
        threading.Thread(target=lambda: PcapIntel.scan(p, log), daemon=True).start()

    def do_apk_scan():
        p = file_var.get().strip() if source_var.get() == "Open file" else ""
        if not p or not os.path.exists(p):
            log("[!] Pick an APK first.\n"); return
        log(f"\n[*] Scanning APK for hardcoded secrets/hashes: {p}\n")
        threading.Thread(target=lambda: Analyzer.apk_strings(p, log), daemon=True).start()

    def do_image_scan():
        p = file_var.get().strip() if source_var.get() == "Open file" else ""
        if not p or not os.path.exists(p):
            log("[!] Pick an image first.\n"); return
        threading.Thread(target=lambda: Analyzer.image_scan(p, log), daemon=True).start()

    def do_resume():
        session = session_var.get().strip()
        run_job(lambda: engine_ref["engine"].resume_session(session), offline=True)

    def do_report():
        path = filedialog.asksaveasfilename(initialdir=_start_dir(), title="Save session report",
                                            initialfile="c4rr07cr4ckr_report.md",
                                            defaultextension=".md")
        if not path:
            return
        try:
            engine_ref["engine"].export_report(path)
            log(f"[+] Report written: {path}\n")
        except Exception as e:  # noqa
            log(f"[!] {e}\n")

    def do_estimate():
        mode = _selected_mode()
        if mode is None:
            log("[!] Analyze first (or pick a hashcat mode) so I know the hash type.\n"); return
        attack = _attack_num()
        rule = rule_var.get().strip()
        rule = None if rule in ("", "(none)") else rule
        est = Estimator.estimate(mode, attack, wordlist=wl_var.get().strip(),
                                 rule=rule, mask=mask_var.get().strip())
        log(f"\n[*] Feasibility estimate (mode {mode}, attack {attack}):\n")
        log(f"      keyspace : {est['keyspace']:,}\n")
        log(f"      speed    : ~{est['speed']:,.0f} H/s (rough single-GPU)\n")
        log(f"      time     : {est['time']}\n")
        log(f"      verdict  : {est['verdict']}\n")
        log("      (run Setup → Benchmark for real H/s on your card)\n")

    def do_preview():
        settings = crack_settings()
        run_job(lambda: engine_ref["engine"].preview(
            settings["attack"], settings["wordlist"], rule=settings["rule"], mask=settings["mask"]))

    def do_auto(p, source, settings):
        a = state["analysis"]
        if not p:
            log("[!] Pick a file first.\n"); return
        E = engine_ref["engine"]
        mode = settings["mode"]
        target = p
        if a and a.prep_helper:
            hp = E.prepare_hash(a.prep_helper, p)
            if not hp:
                return
            target = hp
        if mode is None:
            log("[!] Analyze first so I know the hash mode.\n"); return
        hc = {key: settings[key] for key in ("backend", "workload", "optimized")}
        if source[0] == "text":
            hc["extra"] = "--restore-disable"
        on_ui(monitor.start)
        E.on_result = lambda ok, pl: None  # smart_auto emits per-stage; final below
        won = E.smart_auto(mode, target, settings["wordlist"], **hc)
        def _sa_done():
            if won:
                monitor.success(E.last_cracked[0] if E.last_cracked else "")
                highlight_hit(list(E.last_cracked))
            else:
                monitor.fail()
        on_ui(_sa_done)

    for label, action, color in (
        ("Analyze", lambda: run_job(do_analyze, needs_target=True), CFG.c("panel2")),
        ("Decode / Ciphers", lambda: run_job(do_decode, needs_target=True), CFG.c("panel2")),
        ("Crack", lambda: start_attack(do_crack), "#235a66"),
        ("Stop", lambda: state["busy"] and engine_ref["engine"].stop(), "#512e39"),
    ):
        ctk.CTkButton(btnrow, text=label, command=action, width=84, height=32,
                      fg_color=color).pack(side="left", padx=(6, 0), pady=6)

    tools_menu = {
        "Smart Auto": lambda: start_attack(do_auto),
        "Estimate": do_estimate, "Preview candidates": do_preview,
        "Resume file session": do_resume, "Scan capture": do_pcap_scan,
        "Scan APK": do_apk_scan, "Scan image": do_image_scan,
        "Export report": do_report, "Clear activity": lambda: logbox.delete("1.0", "end"),
    }

    def select_tool(name):
        tool_menu.set("More tools")
        tools_menu[name]()

    tool_menu = ctk.CTkOptionMenu(btnrow, values=list(tools_menu), width=125, command=select_tool)
    tool_menu.set("More tools")
    tool_menu.pack(side="left", padx=8)
    job_status = ctk.CTkLabel(btnrow, text="READY", text_color=MUTE, font=CFG.font(10, "bold"))
    job_status.pack(side="right", padx=10)

    def close_workbench():
        if state["busy"]:
            engine_ref["engine"].stop()
            log("[i] Wait for the active action to finish, then close the window.\n")
        else:
            app.destroy()

    app.protocol("WM_DELETE_WINDOW", close_workbench)

    # place the log: centered over its gif backing, or normal pack otherwise
    if _log_over_gif:
        logbox.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.965, relheight=0.94)
    else:
        logbox.pack(fill="both", expand=True, padx=6, pady=6)
    log(CFG.t("ready_banner").format(app=APP_NAME) + "\n")
    log(f"Detected wordlists: {len(wl_lists)}\n")
    log(f"Compute: {_hw_oneliner()}\n")
    if CFG.data['gif'].get('enabled') and not PIL_OK:
        log("[!] GIF background enabled but Pillow is missing — run Setup → Install.\n")

    # =====================  SETUP / INSTALL TAB  ========================== #
    setlog = ctk.CTkTextbox(t_setup, fg_color=CFG.c("logbg"), text_color=CFG.c("logfg"),
                            font=CFG.font(12))

    def slog(m):
        setlog.insert("end", m); setlog.see("end"); setlog.update_idletasks()

    def refresh_status():
        setlog.delete("1.0", "end")
        slog("=== COMPUTE HARDWARE ===\n")
        slog(hw_ref["hw"].summary() + "\n\n")
        slog("=== DEPENDENCY STATUS ===\n")
        for pkg, binary, ok in Deps.status():
            mark = "✓" if ok else ("?" if ok is None else "✗")
            slog(f"  [{mark}] {pkg:<24} ({binary})\n")

        slog("\n=== *2john EXTRACTORS ===\n")
        helpers = ["zip2john", "rar2john", "7z2john", "office2john", "pdf2john",
                   "ssh2john", "keepass2john", "gpg2john",
                   "putty2john", "pwsafe2john", "keychain2john", "luks2john",
                   "bitlocker2john", "ab2john", "keystore2john", "itunes_backup2john"]
        miss = 0
        for h in helpers:
            cmd = resolve_helper(h)
            if cmd:
                slog(f"  [✓] {h:<20} {cmd[-1]}\n")
            else:
                miss += 1
                slog(f"  [✗] {h:<20} (not found)\n")
        if miss:
            slog(f"  → {miss} extractor(s) missing. Most ship with John jumbo; install/point to it "
                 "(Setup → Install everything, or set john's path).\n")

        slog("\nHit 'Install everything' to apt+pip the missing pieces (needs root).\n")
        slog("The installer auto-adds the OpenCL runtime for the GPU it detects.\n")

    def rescan_hw():
        slog("\n[*] Re-scanning compute hardware ...\n")
        hw_ref["hw"] = Hardware().scan()
        slog(hw_ref["hw"].summary() + "\n")
        try:
            hw_line.configure(text=_hw_oneliner())
        except Exception:  # noqa
            pass

    def benchmark():
        if not tool_available("hashcat"):
            slog("[!] hashcat not installed.\n"); return
        slog("\n[*] hashcat benchmark (MD5/NTLM/bcrypt/WPA) — this takes a minute...\n")
        eng = Engine(slog)
        eng._stream([tool("hashcat"), "-b", "-m", "0"])
        eng._stream([tool("hashcat"), "-b", "-m", "1000"])
        eng._stream([tool("hashcat"), "-b", "-m", "22000"])

    barf = ctk.CTkFrame(t_setup, fg_color=PANEL); barf.pack(fill="x", padx=6, pady=6)
    ctk.CTkButton(barf, text="Refresh status", fg_color="#2a2f34", hover_color="#3a4048",
                  command=refresh_status).pack(side="left", padx=6, pady=8)
    ctk.CTkButton(barf, text="🔁 Rescan GPU", fg_color="#2a2f34", hover_color="#3a4048",
                  command=lambda: threading.Thread(target=rescan_hw, daemon=True).start()
                  ).pack(side="left", padx=6, pady=8)
    ctk.CTkButton(barf, text="📊 Benchmark", fg_color=LEAF, text_color=INK, hover_color="#28a862",
                  command=lambda: threading.Thread(target=benchmark, daemon=True).start()
                  ).pack(side="left", padx=6, pady=8)
    ctk.CTkButton(barf, text="⬇ Install everything", fg_color=CARROT, text_color=INK,
                  hover_color="#d9660f",
                  command=lambda: threading.Thread(
                      target=lambda: Deps.install(slog), daemon=True).start()
                  ).pack(side="left", padx=6, pady=8)
    setlog.pack(fill="both", expand=True, padx=6, pady=6)
    refresh_status()

    # =====================  CHEAT SHEET TAB  ============================== #
    ref = ctk.CTkTextbox(t_ref, fg_color="#0a0c0d", text_color="#dfe7ec",
                         font=("JetBrains Mono", 12))
    ref.pack(fill="both", expand=True, padx=6, pady=6)
    ref.insert("end", CHEAT_SHEET)
    ref.configure(state="disabled")

    # =====================  TROPHY TAB  ================================== #
    trophybar = ctk.CTkFrame(t_trophy, fg_color=PANEL); trophybar.pack(fill="x", padx=6, pady=6)
    trophybox = ctk.CTkTextbox(t_trophy, fg_color=CFG.c("logbg"), text_color=CFG.c("logfg"),
                               font=CFG.font(12))
    _TT = trophybox._textbox
    try:
        _TT.tag_configure("plain", foreground=LEAF, font=CFG.font(12, "bold"))
        _TT.tag_configure("hash", foreground=MUTE)
    except Exception:  # noqa
        pass

    def refresh_trophies():
        trophybox.delete("1.0", "end")
        rows = Trophy.entries()
        if not rows:
            trophybox.insert("end", "No cracked hashes yet. Potfiles are read from\n"
                                    "hashcat.potfile and ~/.john/john.pot after a crack.\n")
            return
        trophybox.insert("end", f"🏆 {len(rows)} cracked\n\n")
        for src, h, plain in rows:
            base = trophybox._textbox.index("end-1c")
            trophybox.insert("end", f"[{src}] {h}  →  ")
            mid = trophybox._textbox.index("end-1c")
            trophybox.insert("end", f"{plain}\n")
            try:
                _TT.tag_add("hash", base, mid)
                _TT.tag_add("plain", mid, trophybox._textbox.index("end-1c"))
            except Exception:  # noqa
                pass

    def export_trophies(fmt):
        out = "/mnt/user-data/outputs" if os.path.isdir("/mnt/user-data/outputs") else _real_home()
        path = os.path.join(out, f"c4rr07cr4ckr_trophies.{fmt}")
        n = Trophy.export(path, fmt)
        trophybox.insert("end", f"\n[+] Exported {n} rows -> {path}\n")

    ctk.CTkButton(trophybar, text="🔁 Refresh", fg_color=CARROT, text_color=INK,
                  hover_color="#d9660f", command=refresh_trophies).pack(side="left", padx=6, pady=8)
    ctk.CTkButton(trophybar, text="⬇ Export .md", fg_color="#2a2f34", hover_color="#3a4048",
                  command=lambda: export_trophies("md")).pack(side="left", padx=6, pady=8)
    ctk.CTkButton(trophybar, text="⬇ Export .csv", fg_color="#2a2f34", hover_color="#3a4048",
                  command=lambda: export_trophies("csv")).pack(side="left", padx=6, pady=8)
    trophybox.pack(fill="both", expand=True, padx=6, pady=6)
    refresh_trophies()

    # =====================  WORDLIST GENERATOR TAB  ===================== #
    wl = ctk.CTkScrollableFrame(t_wlgen, fg_color=INK)
    wl.pack(fill="both", expand=True, padx=6, pady=6)

    # ---- wordlist LIBRARY (fetch curated public lists) -----------------
    ctk.CTkLabel(wl, text="📚 Wordlist library", text_color=CARROT,
                 font=CFG.font(15, "bold")).pack(anchor="w", padx=6, pady=(6, 2))
    ctk.CTkLabel(wl, text=f"Download curated public lists (SecLists) into your library at "
                         f"{WordlistManager.library_dir()}. They then appear in the wordlist "
                         "picker on the Analyze tab.", text_color=MUTE, font=CFG.font(11),
                 justify="left", wraplength=760).pack(anchor="w", padx=6, pady=(0, 6))

    wlib_status = ctk.CTkLabel(wl, text="", text_color=MUTE, font=CFG.font(11), justify="left")

    def _refresh_wlib():
        for w in wlib_rows.winfo_children():
            w.destroy()
        for name, have, size, desc in WordlistManager.status():
            row = ctk.CTkFrame(wlib_rows, fg_color="transparent"); row.pack(fill="x", pady=2)
            mark = "✓" if have else "▸"
            col = LEAF if have else MUTE
            szt = f"  ({size//1024//1024} MB)" if have and size > 1024*1024 else (
                  f"  ({size//1024} KB)" if have else "")
            ctk.CTkLabel(row, text=f" [{mark}] {name}{szt}", width=230, anchor="w",
                         text_color=col, font=CFG.font(12, "bold")).pack(side="left")
            ctk.CTkLabel(row, text=desc, anchor="w", text_color=MUTE,
                         font=CFG.font(10), wraplength=360).pack(side="left", padx=6)
            if not have:
                def _mk(n):
                    def _go():
                        wlib_status.configure(text=f"Fetching {n}…", text_color="#ffd27a")
                        def _run():
                            WordlistManager.fetch(n, log)
                            app.after(0, _refresh_wlib)
                            app.after(0, lambda: wlib_status.configure(
                                text=f"✓ {n} ready — pick it on the Analyze tab.", text_color=LEAF))
                        threading.Thread(target=_run, daemon=True).start()
                    return _go
                ctk.CTkButton(row, text="⬇ Get", width=64, fg_color=CARROT, text_color=INK,
                              hover_color="#d9660f", command=_mk(name)).pack(side="right", padx=4)

    wlib_rows = ctk.CTkFrame(wl, fg_color=PANEL, corner_radius=8)
    wlib_rows.pack(fill="x", padx=6, pady=4)
    _refresh_wlib()
    wlib_status.pack(anchor="w", padx=6, pady=(2, 12))

    ctk.CTkLabel(wl, text="🧬 Custom wordlist generator (crunch)", text_color=CARROT,
                 font=CFG.font(15, "bold")).pack(anchor="w", padx=6, pady=(6, 2))
    ctk.CTkLabel(wl, text="Generate a targeted wordlist by length + charset, or by a fixed "
                         "pattern. It estimates the size FIRST so you never accidentally ask "
                         "for a 40 TB file.", text_color=MUTE, font=CFG.font(11),
                 justify="left", wraplength=760).pack(anchor="w", padx=6, pady=(0, 10))

    if not Crunch.available():
        ctk.CTkLabel(wl, text="⚠ crunch isn't installed yet (Setup → Install everything). "
                             "A slower built-in generator will be used as a fallback.",
                     text_color="#ffd27a", font=CFG.font(11)).pack(anchor="w", padx=6, pady=(0, 8))

    cg_min = ctk.StringVar(value="6")
    cg_max = ctk.StringVar(value="8")
    cg_charset = ctk.StringVar(value="alnum lower")
    cg_pattern = ctk.StringVar(value="")
    cg_out = ctk.StringVar(value=os.path.join(_start_dir(), "custom_wordlist.txt"))

    def _wrow(label, widget_fn):
        r = ctk.CTkFrame(wl, fg_color="transparent"); r.pack(fill="x", padx=6, pady=4)
        ctk.CTkLabel(r, text=label, width=130, anchor="w", text_color=LEAF,
                     font=CFG.font(12)).pack(side="left", padx=6)
        widget_fn(r)
        return r

    _wrow("Min length", lambda r: ctk.CTkEntry(r, textvariable=cg_min, width=80,
          font=CFG.font(12)).pack(side="left", padx=6))
    _wrow("Max length", lambda r: ctk.CTkEntry(r, textvariable=cg_max, width=80,
          font=CFG.font(12)).pack(side="left", padx=6))
    _wrow("Charset", lambda r: ctk.CTkOptionMenu(r, variable=cg_charset,
          values=list(Crunch.CHARSETS.keys()), fg_color=CFG.c("panel2"),
          button_color=CARROT, width=200).pack(side="left", padx=6))
    _wrow("Pattern (opt)", lambda r: ctk.CTkEntry(r, textvariable=cg_pattern, width=260,
          font=CFG.font(12)).pack(side="left", padx=6))
    ctk.CTkLabel(wl, text="   pattern placeholders:  @ = lower   , = upper   % = digit   ^ = symbol"
                         "   (literals stay fixed, e.g.  Pass%%%%  )",
                 text_color=MUTE, font=CFG.font(10)).pack(anchor="w", padx=6)
    _wrow("Output file", lambda r: ctk.CTkEntry(r, textvariable=cg_out, width=420,
          font=CFG.font(11)).pack(side="left", padx=6))

    def pick_wl_out():
        p = filedialog.asksaveasfilename(initialdir=_start_dir(), title="Save wordlist as",
                                         initialfile="custom_wordlist.txt",
                                         defaultextension=".txt")
        if p:
            cg_out.set(p)

    cg_status = ctk.CTkLabel(wl, text="", text_color=MUTE, font=CFG.font(12), justify="left")

    def _cg_params():
        try:
            mn, mx = int(cg_min.get()), int(cg_max.get())
        except ValueError:
            return None
        cs = Crunch.CHARSETS.get(cg_charset.get(), "")
        pat = cg_pattern.get().strip() or None
        return mn, mx, cs, pat

    def cg_estimate():
        prm = _cg_params()
        if not prm:
            cg_status.configure(text="Min/max must be integers.", text_color=CFG.c("danger")); return
        mn, mx, cs, pat = prm
        lines, nbytes = Crunch.estimate(mn, mx, len(cs), pat)
        warn = ""
        if nbytes > 5 * 1024**3:
            warn = "  ⚠ HUGE — consider a pattern or smaller range."
        cg_status.configure(
            text=f"≈ {lines:,} candidates  ·  ≈ {Crunch.human_size(nbytes)} on disk{warn}",
            text_color="#ffd27a" if warn else LEAF)

    def cg_generate():
        prm = _cg_params()
        if not prm:
            cg_status.configure(text="Min/max must be integers.", text_color=CFG.c("danger")); return
        mn, mx, cs, pat = prm
        lines, nbytes = Crunch.estimate(mn, mx, len(cs), pat)
        if nbytes > 20 * 1024**3:
            cg_status.configure(text=f"Refusing: ~{Crunch.human_size(nbytes)} is too large. "
                                     "Use a pattern or tighter range.", text_color=CFG.c("danger"))
            return
        cg_status.configure(text="Generating… (streams to the main log)", text_color=LEAF)
        out = cg_out.get().strip()

        def _run():
            path = Crunch.build(out, mn, mx, cs, pat, log)
            if path:
                app.after(0, lambda: cg_status.configure(
                    text=f"✓ Done → {path}\n   (add it as a Custom wordlist on the Analyze tab)",
                    text_color=LEAF))
        threading.Thread(target=_run, daemon=True).start()

    cbar = ctk.CTkFrame(wl, fg_color="transparent"); cbar.pack(fill="x", padx=6, pady=(10, 4))
    ctk.CTkButton(cbar, text="Browse…", fg_color="#2a2f34", hover_color="#3a4048",
                  command=pick_wl_out).pack(side="left", padx=4)
    ctk.CTkButton(cbar, text="⏱ Estimate size", fg_color="#2a2f34", hover_color="#3a4048",
                  command=cg_estimate).pack(side="left", padx=4)
    ctk.CTkButton(cbar, text="🧬 Generate", fg_color=CARROT, text_color=INK,
                  hover_color="#d9660f", font=CFG.font(13, "bold"),
                  command=cg_generate).pack(side="left", padx=4)
    cg_status.pack(anchor="w", padx=6, pady=6)

    # =====================  PLUGINS TAB  ================================= #
    _splash("Loading plugins…")
    pm = PluginManager(log=lambda m: None).load()
    state["plugins"] = pm
    plug_head = ctk.CTkFrame(t_plugins, fg_color=PANEL); plug_head.pack(fill="x", padx=6, pady=6)
    ctk.CTkLabel(plug_head, text=f"🧩 {len(pm.loaded)} plugin(s) loaded",
                 text_color=CARROT, font=CFG.font(14, "bold")).pack(side="left", padx=10, pady=8)
    ctk.CTkLabel(plug_head, text="  drop .py modules in  ~/.config/c4rr07cr4ckr/plugins",
                 text_color=MUTE, font=CFG.font(11)).pack(side="left")

    plug_body = ctk.CTkScrollableFrame(t_plugins, fg_color=INK)
    plug_body.pack(fill="both", expand=True, padx=6, pady=6)
    if not pm.loaded:
        ctk.CTkLabel(plug_body, text="No plugins found. An example JWT detector ships in the\n"
                                     "plugins/ folder — install it or copy it to the plugins dir.",
                     text_color=MUTE, font=CFG.font(12), justify="left").pack(anchor="w", padx=8, pady=8)
    for nm in pm.loaded:
        ctk.CTkLabel(plug_body, text=f"• {nm}", text_color=LEAF,
                     font=CFG.font(12)).pack(anchor="w", padx=10, pady=2)

    def _plugin_ctx():
        return {"file": file_var.get().strip(), "log": log,
                "engine": engine_ref["engine"], "wordlist": wl_var.get().strip()}

    if pm.api.actions:
        ctk.CTkLabel(plug_body, text="Actions:", text_color=CARROT,
                     font=CFG.font(13, "bold")).pack(anchor="w", padx=8, pady=(12, 4))
        for label, fn in pm.api.actions:
            ctk.CTkButton(plug_body, text=label, fg_color="#2a2f34", hover_color="#3a4048",
                          command=lambda f=fn: threading.Thread(
                              target=lambda: f(_plugin_ctx()), daemon=True).start()
                          ).pack(anchor="w", padx=10, pady=3)

    # =====================  ONLINE (HYDRA) TAB  ========================= #
    hydra_ref = {"h": None}
    ohead = ctk.CTkFrame(t_online, fg_color="#2a1414"); ohead.pack(fill="x", padx=6, pady=6)
    ctk.CTkLabel(ohead, text="⚠ ONLINE login testing — AUTHORIZED targets only",
                 text_color="#ff9a9a", font=CFG.font(13, "bold")).pack(anchor="w", padx=10, pady=(8, 0))
    ctk.CTkLabel(ohead, text="This hits a LIVE service (CTF box, your lab, or an in-scope "
                            "engagement). Hitting anything else is illegal.",
                 text_color=MUTE, font=CFG.font(11), justify="left").pack(anchor="w", padx=10, pady=(0, 8))

    oform = ctk.CTkScrollableFrame(t_online, fg_color=INK); oform.pack(fill="both", expand=True, padx=6, pady=6)

    o_target = ctk.StringVar(); o_service = ctk.StringVar(value="ssh")
    o_user = ctk.StringVar(); o_userlist = ctk.StringVar()
    o_pass = ctk.StringVar(); o_passlist = ctk.StringVar(value=wl_lists[0])
    o_port = ctk.StringVar(); o_threads = ctk.StringVar(value="16")
    o_form = ctk.StringVar(value="/login:user=^USER^&pass=^PASS^:F=incorrect")
    o_scope = ctk.StringVar()
    o_authorized = ctk.BooleanVar(value=False)

    def _orow(label, widget):
        r = ctk.CTkFrame(oform, fg_color="transparent"); r.pack(fill="x", padx=6, pady=3)
        ctk.CTkLabel(r, text=label, width=120, anchor="w", text_color=LEAF,
                     font=CFG.font(12)).pack(side="left", padx=6)
        widget(r)
        return r

    _orow("Target host", lambda r: ctk.CTkEntry(r, textvariable=o_target, width=280,
          font=CFG.font(12)).pack(side="left", padx=6))
    _orow("Service", lambda r: ctk.CTkOptionMenu(r, variable=o_service, values=Hydra.SERVICES,
          fg_color=CFG.c("panel2"), button_color=CARROT, width=180).pack(side="left", padx=6))
    _orow("Port (opt)", lambda r: ctk.CTkEntry(r, textvariable=o_port, width=90,
          font=CFG.font(12)).pack(side="left", padx=6))
    _orow("Username", lambda r: ctk.CTkEntry(r, textvariable=o_user, width=180,
          font=CFG.font(12)).pack(side="left", padx=6))
    _orow("…or user list", lambda r: ctk.CTkEntry(r, textvariable=o_userlist, width=380,
          font=CFG.font(11)).pack(side="left", padx=6))
    _orow("Password", lambda r: ctk.CTkEntry(r, textvariable=o_pass, width=180,
          font=CFG.font(12)).pack(side="left", padx=6))
    _orow("…or pass list", lambda r: ctk.CTkEntry(r, textvariable=o_passlist, width=380,
          font=CFG.font(11)).pack(side="left", padx=6))
    _orow("Threads", lambda r: ctk.CTkEntry(r, textvariable=o_threads, width=80,
          font=CFG.font(12)).pack(side="left", padx=6))
    _orow("http form", lambda r: ctk.CTkEntry(r, textvariable=o_form, width=460,
          font=CFG.font(10)).pack(side="left", padx=6))
    _orow("Scope allowlist", lambda r: ctk.CTkEntry(r, textvariable=o_scope, width=460,
          font=CFG.font(10)).pack(side="left", padx=6))
    ctk.CTkLabel(oform, text="  scope = comma-separated hosts/CIDRs the run is restricted to "
                            "(blank = you assert authorization)",
                 text_color=MUTE, font=CFG.font(10)).pack(anchor="w", padx=6)

    ctk.CTkCheckBox(oform, text="I am authorized to test this target (CTF / lab / in-scope).",
                    variable=o_authorized, fg_color=CARROT, hover_color="#d9660f",
                    text_color="#ff9a9a", font=CFG.font(12, "bold")).pack(anchor="w", padx=10, pady=(10, 4))

    obar = ctk.CTkFrame(oform, fg_color="transparent"); obar.pack(fill="x", padx=6, pady=6)

    def do_hydra():
        if not Hydra.available():
            log("[!] hydra not installed — Setup → Install everything.\n"); return
        target = o_target.get().strip()
        sc = scope_ref["scope"]
        # if a scope file is loaded, it is authoritative and overrides the checkbox
        if sc:
            if not sc.allow_online:
                log("[!] BLOCKED by scope: online attacks are not permitted in this engagement.\n")
                audit.append("online_blocked", reason="scope_denies_online", target=target)
                return
            if not sc.target_ok(target):
                log(f"[!] BLOCKED by scope: {target} is outside the authorized engagement.\n")
                audit.append("online_blocked", reason="out_of_scope", target=target)
                return
        h = Hydra(log); hydra_ref["h"] = h
        scope = [s for s in re.split(r"[,\s]+", o_scope.get()) if s]
        if sc:
            scope = list(set(scope) | set(sc.targets))
        audit.append("online_attempt", target=target, service=o_service.get(),
                     authorized=bool(o_authorized.get()))
        app.after(0, monitor.start)
        ok = h.run(target, o_service.get(),
                   user=o_user.get().strip() or None,
                   userlist=o_userlist.get().strip() or None,
                   password=o_pass.get().strip() or None,
                   passlist=o_passlist.get().strip() or None,
                   port=(o_port.get().strip() or None),
                   threads=o_threads.get().strip() or 16,
                   form=o_form.get().strip(),
                   authorized=o_authorized.get(), scope=scope)
        audit.append("online_result", target=target, success=bool(ok))
        app.after(0, lambda: monitor.success(h.found[0][1] if h.found else "")
                  if ok else monitor.fail())

    ctk.CTkButton(obar, text="🌐 RUN (authorized)", fg_color=CARROT, text_color=INK,
                  hover_color="#d9660f", font=CFG.font(13, "bold"), height=38,
                  command=lambda: threading.Thread(target=do_hydra, daemon=True).start()
                  ).pack(side="left", padx=6)
    ctk.CTkButton(obar, text="■ STOP", fg_color="#3a2020", hover_color="#5a2020",
                  text_color=CFG.c("danger"), height=38,
                  command=lambda: hydra_ref["h"] and hydra_ref["h"].stop()).pack(side="left", padx=6)
    ctk.CTkLabel(oform, text="Output streams to the main log on the Analyze & Crack tab.",
                 text_color=MUTE, font=CFG.font(11)).pack(anchor="w", padx=6, pady=(2, 8))

    # =====================  GOVERNANCE TAB  ============================== #
    govscroll = ctk.CTkScrollableFrame(t_gov, fg_color=INK)
    govscroll.pack(fill="both", expand=True, padx=6, pady=6)

    def _gsection(title):
        ctk.CTkLabel(govscroll, text=title, text_color=CARROT,
                     font=CFG.font(15, "bold")).pack(anchor="w", padx=6, pady=(14, 4))

    def _ghint(msg):
        ctk.CTkLabel(govscroll, text=msg, text_color=MUTE, font=CFG.font(11),
                     justify="left").pack(anchor="w", padx=6)

    # ---- scope / rules of engagement ---
    _gsection("🎯 Scope / Rules of Engagement")
    _ghint("A scope file is authoritative: if loaded, it overrides the Online tab's "
          "checkbox and hard-blocks out-of-scope targets or online attacks entirely.")
    scope_path_var = ctk.StringVar(value=gov.get("scope_file", ""))
    r = ctk.CTkFrame(govscroll, fg_color="transparent"); r.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(r, text="Scope file", width=110, anchor="w", font=CFG.font(12)).pack(side="left")
    ctk.CTkEntry(r, textvariable=scope_path_var, width=420, font=CFG.font(11)).pack(side="left", padx=6)

    scope_status = ctk.CTkTextbox(govscroll, fg_color=CFG.c("logbg"), text_color=CFG.c("logfg"),
                                  font=CFG.font(11), height=130)

    def _scope_refresh_display():
        scope_status.configure(state="normal")
        scope_status.delete("1.0", "end")
        sc = scope_ref["scope"]
        scope_status.insert("end", sc.summary() if sc else "No scope file loaded — "
                            "the Online tab's per-run checkbox is the only gate.\n")
        scope_status.configure(state="disabled")

    def load_scope():
        p = filedialog.askopenfilename(initialdir=_start_dir(), title="Select scope.yaml / scope.json",
                                       filetypes=[("scope", "*.yaml *.yml *.json"), ("all", "*.*")])
        if p:
            scope_path_var.set(p)
            try:
                scope_ref["scope"] = Scope.load(p)
                CFG.data["governance"]["scope_file"] = p
                CFG.save()
                audit.append("scope_loaded", file=p, engagement=scope_ref["scope"].engagement)
                _scope_refresh_display()
            except Exception as e:  # noqa
                scope_status.configure(state="normal")
                scope_status.delete("1.0", "end")
                scope_status.insert("end", f"[!] Failed to load scope: {e}\n")
                scope_status.configure(state="disabled")

    def clear_scope():
        scope_ref["scope"] = None
        CFG.data["governance"]["scope_file"] = ""
        CFG.save()
        audit.append("scope_cleared")
        _scope_refresh_display()

    def new_scope_template():
        out = _real_home()
        path = filedialog.asksaveasfilename(initialdir=_start_dir(), title="Save new scope file",
                                            initialfile="scope.yaml", defaultextension=".yaml") or \
            os.path.join(out, "scope.yaml")
        Path(path).write_text(SCOPE_TEMPLATE)
        scope_path_var.set(path)

    ctk.CTkButton(r, text="Browse", fg_color=CARROT, text_color=INK, hover_color="#d9660f",
                  width=90, command=load_scope).pack(side="left", padx=4)
    ctk.CTkButton(r, text="Clear", fg_color="#2a2f34", hover_color="#3a4048",
                  width=80, command=clear_scope).pack(side="left", padx=4)
    ctk.CTkButton(r, text="+ New template", fg_color="#2a2f34", hover_color="#3a4048",
                  command=new_scope_template).pack(side="left", padx=4)
    scope_status.pack(fill="x", padx=6, pady=(4, 10))
    _scope_refresh_display()

    # ---- audit log ---
    _gsection("📜 Tamper-evident audit log")
    _ghint("Every analyze, crack result, and online attempt is appended as a hash-chained "
          "record. Editing or deleting a past line breaks the chain — Verify detects it.")
    ctk.CTkLabel(govscroll, text=f"Log file: {audit.path}", text_color=MUTE,
                 font=CFG.font(11)).pack(anchor="w", padx=6, pady=(2, 4))
    audit_status = ctk.CTkLabel(govscroll, text="", font=CFG.font(12, "bold"))
    audit_status.pack(anchor="w", padx=6)

    def verify_audit():
        ok, n = audit.verify()
        if ok:
            audit_status.configure(text=f"✓ Chain intact — {n} record(s) verified.", text_color=LEAF)
        else:
            audit_status.configure(text=f"✗ TAMPERING DETECTED after record {n}!",
                                   text_color=CFG.c("danger"))

    ctk.CTkButton(govscroll, text="🔍 Verify chain integrity", fg_color="#2a2f34",
                  hover_color="#3a4048", command=verify_audit).pack(anchor="w", padx=6, pady=(2, 12))
    verify_audit()

    # ---- signed reporting ---
    _gsection("✍ Signed reporting")
    _ghint("Every exported report gets a SHA-256 manifest alongside it. Set a GPG key id "
          "below to also attach a detached .asc signature.")
    gpg_var = ctk.StringVar(value=gov.get("gpg_key", ""))
    r = ctk.CTkFrame(govscroll, fg_color="transparent"); r.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(r, text="GPG key id", width=110, anchor="w", font=CFG.font(12)).pack(side="left")
    ctk.CTkEntry(r, textvariable=gpg_var, width=280, font=CFG.font(12)).pack(side="left", padx=6)

    def save_gpg():
        CFG.data["governance"]["gpg_key"] = gpg_var.get().strip()
        CFG.save()
        audit.append("gpg_key_set", key=gpg_var.get().strip())

    ctk.CTkButton(r, text="Save", fg_color="#2a2f34", hover_color="#3a4048",
                  width=80, command=save_gpg).pack(side="left", padx=4)

    def signed_report():
        out = "/mnt/user-data/outputs" if os.path.isdir("/mnt/user-data/outputs") else _real_home()
        path = filedialog.asksaveasfilename(initialdir=_start_dir(), title="Save signed report",
                                            initialfile="c4rr07cr4ckr_report.md",
                                            defaultextension=".md") or \
            os.path.join(out, "c4rr07cr4ckr_report.md")
        digest, sig = Reporter.write(engine_ref["engine"], path, audit=audit,
                                     gpg_key=gpg_var.get().strip() or None)
        log(f"[+] Signed report -> {path}\n    sha256: {digest}\n"
           + (f"    signature: {sig}\n" if sig else "    (no GPG signature — set a key id above)\n"))

    ctk.CTkButton(govscroll, text="📄 Export signed report", fg_color=LEAF, text_color=INK,
                  hover_color="#28a862", command=signed_report).pack(anchor="w", padx=6, pady=(4, 12))

    # ---- resource guard ---
    _gsection("🌡 Resource guard")
    temp_var = ctk.IntVar(value=int(CFG.data.get("resource", {}).get("temp_abort", 90)))
    r = ctk.CTkFrame(govscroll, fg_color="transparent"); r.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(r, text="GPU temp abort °C", width=140, anchor="w", font=CFG.font(12)).pack(side="left")
    temp_lbl = ctk.CTkLabel(r, text=str(temp_var.get()), width=40, font=CFG.font(12))
    ctk.CTkSlider(r, from_=0, to=100, number_of_steps=100, variable=temp_var, width=220,
                  button_color=CARROT, progress_color=LEAF,
                  command=lambda v: temp_lbl.configure(text=str(int(float(v))))).pack(side="left", padx=6)
    temp_lbl.pack(side="left")
    _ghint("0 disables the guard. Passed to hashcat as --hwmon-temp-abort.")

    def save_temp():
        CFG.data["resource"]["temp_abort"] = int(temp_var.get())
        CFG.save()

    ctk.CTkButton(govscroll, text="Save", fg_color="#2a2f34", hover_color="#3a4048",
                  width=80, command=save_temp).pack(anchor="w", padx=6, pady=(2, 12))

    # ---- distributed cracking ---
    _gsection("🖧 Distributed cracking (Hashtopolis)")
    _ghint("Point at a Hashtopolis server to shard a big job across a cluster's GPUs "
          "instead of just this machine.")
    ht_url = ctk.StringVar(value=CFG.data["distributed"].get("hashtopolis_url", ""))
    ht_key = ctk.StringVar(value=CFG.data["distributed"].get("hashtopolis_key", ""))
    r = ctk.CTkFrame(govscroll, fg_color="transparent"); r.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(r, text="Server URL", width=110, anchor="w", font=CFG.font(12)).pack(side="left")
    ctk.CTkEntry(r, textvariable=ht_url, width=320, font=CFG.font(11)).pack(side="left", padx=6)
    r = ctk.CTkFrame(govscroll, fg_color="transparent"); r.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(r, text="Access key", width=110, anchor="w", font=CFG.font(12)).pack(side="left")
    ctk.CTkEntry(r, textvariable=ht_key, width=320, font=CFG.font(11), show="•").pack(side="left", padx=6)

    def save_ht():
        CFG.data["distributed"]["hashtopolis_url"] = ht_url.get().strip()
        CFG.data["distributed"]["hashtopolis_key"] = ht_key.get().strip()
        CFG.save()

    def test_ht():
        save_ht()
        cli = Hashtopolis(ht_url.get().strip(), ht_key.get().strip(), log=log)
        threading.Thread(target=cli.test, daemon=True).start()

    def push_ht():
        save_ht()
        p = file_var.get().strip()
        a = state.get("analysis")
        if not p or not a:
            log("[!] Analyze a hash file on the Analyze & Crack tab first.\n"); return
        mode = a.suggested_mode or 0
        cli = Hashtopolis(ht_url.get().strip(), ht_key.get().strip(), log=log)
        attack_cmd = f"#HL# -a 0 #WL#"  # Hashtopolis substitutes hashlist/wordlist tokens
        threading.Thread(target=lambda: cli.push_job(
            os.path.basename(p), p, mode, attack_cmd), daemon=True).start()

    rr = ctk.CTkFrame(govscroll, fg_color="transparent"); rr.pack(fill="x", padx=6, pady=(4, 6))
    ctk.CTkButton(rr, text="💾 Save", fg_color="#2a2f34", hover_color="#3a4048",
                  command=save_ht).pack(side="left", padx=6)
    ctk.CTkButton(rr, text="🔌 Test connection", fg_color="#2a2f34", hover_color="#3a4048",
                  command=test_ht).pack(side="left", padx=6)
    ctk.CTkButton(rr, text="⬆ Push current job to cluster", fg_color=CARROT, text_color=INK,
                  hover_color="#d9660f", command=push_ht).pack(side="left", padx=6)
    _ghint("Requires a reachable Hashtopolis server + valid access key.")

    # =====================  CUSTOMIZE TAB  =============================== #
    cust = ctk.CTkScrollableFrame(t_custom, fg_color=INK)
    cust.pack(fill="both", expand=True, padx=6, pady=6)

    def _section(title):
        ctk.CTkLabel(cust, text=title, text_color=CARROT,
                     font=CFG.font(15, "bold")).pack(anchor="w", padx=6, pady=(14, 4))

    def _hint(msg):
        ctk.CTkLabel(cust, text=msg, text_color=MUTE,
                     font=CFG.font(11)).pack(anchor="w", padx=6)

    # --- appearance + fonts ---
    _section("Appearance & fonts")
    appear_var = ctk.StringVar(value=CFG.data.get("appearance", "dark"))
    fam_var = ctk.StringVar(value=CFG.data.get("font_family", "JetBrains Mono"))
    scale_var = ctk.DoubleVar(value=float(CFG.data.get("font_scale", 1.0)))

    r = ctk.CTkFrame(cust, fg_color="transparent"); r.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(r, text="Mode", width=110, anchor="w", font=CFG.font(12)).pack(side="left")
    ctk.CTkOptionMenu(r, variable=appear_var, values=["dark", "light", "system"],
                      fg_color=CFG.c("panel2"), button_color=CARROT, width=160).pack(side="left", padx=6)

    r = ctk.CTkFrame(cust, fg_color="transparent"); r.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(r, text="Font family", width=110, anchor="w", font=CFG.font(12)).pack(side="left")
    ctk.CTkEntry(r, textvariable=fam_var, width=260, font=CFG.font(12)).pack(side="left", padx=6)

    r = ctk.CTkFrame(cust, fg_color="transparent"); r.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(r, text="Font scale", width=110, anchor="w", font=CFG.font(12)).pack(side="left")
    scale_lbl = ctk.CTkLabel(r, text=f"{scale_var.get():.2f}×", width=54, font=CFG.font(12))
    ctk.CTkSlider(r, from_=0.7, to=1.8, variable=scale_var, width=240,
                  button_color=CARROT, progress_color=LEAF,
                  command=lambda v: scale_lbl.configure(text=f"{float(v):.2f}×")
                  ).pack(side="left", padx=6)
    scale_lbl.pack(side="left")

    # window transparency — applies LIVE so you can see your desktop/GIF bleed through
    opac_var = ctk.DoubleVar(value=float(CFG.data.get("window_opacity", 1.0)))
    r = ctk.CTkFrame(cust, fg_color="transparent"); r.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(r, text="Transparency", width=110, anchor="w", font=CFG.font(12)).pack(side="left")
    opac_lbl = ctk.CTkLabel(r, text=f"{int(opac_var.get()*100)}%", width=54, font=CFG.font(12))

    def _apply_opacity(v):
        val = float(v)
        opac_lbl.configure(text=f"{int(val*100)}%")
        try:
            app.attributes("-alpha", max(0.3, min(1.0, val)))
        except Exception:  # noqa
            pass
    ctk.CTkSlider(r, from_=0.3, to=1.0, variable=opac_var, width=240,
                  button_color=CARROT, progress_color=LEAF,
                  command=_apply_opacity).pack(side="left", padx=6)
    opac_lbl.pack(side="left")
    _hint("Whole-window see-through: your desktop wallpaper / live GIF shows through the entire "
          "app, terminal included. (Needs a compositor — Parrot's picom is on by default. "
          "Per-widget transparency isn't possible in this toolkit, so this is the real way to "
          "see a GIF behind the log.)")

    # --- movable / lockable panels ---
    _section("Crack animation")
    mon = CFG.data.setdefault("monitor", {})
    msize_var = ctk.IntVar(value=int(mon.get("size", 180)))
    mfull_var = ctk.BooleanVar(value=bool(mon.get("fullwidth", True)))
    mlock_var = ctk.StringVar(value=mon.get("lock_style", "padlock"))
    mscr_var = ctk.StringVar(value=mon.get("scrambler", "matrix"))

    r = ctk.CTkFrame(cust, fg_color="transparent"); r.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(r, text="Lock size", width=110, anchor="w", font=CFG.font(12)).pack(side="left")
    msize_lbl = ctk.CTkLabel(r, text=f"{msize_var.get()} px", width=70, font=CFG.font(12))

    def _live_size(v):
        msize_lbl.configure(text=f"{int(float(v))} px")
        try:
            monitor.SZ = max(120, min(420, int(float(v))))
            monitor.canvas.configure(width=monitor.SZ, height=monitor.SZ)
            monitor._cols = monitor.SZ // 12
            monitor.draw_lock(monitor.AMBER, closed=True, ring=False)
        except Exception:  # noqa
            pass
    ctk.CTkSlider(r, from_=120, to=420, variable=msize_var, width=240,
                  button_color=CARROT, progress_color=LEAF,
                  command=_live_size).pack(side="left", padx=6)
    msize_lbl.pack(side="left")

    r = ctk.CTkFrame(cust, fg_color="transparent"); r.pack(fill="x", padx=6, pady=4)
    ctk.CTkCheckBox(r, text="Full-width data stream (scrolls across the screen)",
                    variable=mfull_var, fg_color=CARROT, hover_color="#d9660f",
                    font=CFG.font(12)).pack(side="left", padx=6)

    r = ctk.CTkFrame(cust, fg_color="transparent"); r.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(r, text="Lock style", width=110, anchor="w", font=CFG.font(12)).pack(side="left")

    def _live_lock(choice):
        try:
            monitor.lock_style = choice
            monitor.draw_lock(monitor.AMBER, closed=True, ring=True, glow_r=40)
        except Exception:  # noqa
            pass
    ctk.CTkOptionMenu(r, variable=mlock_var, values=list(CrackMonitor.LOCK_STYLES),
                      fg_color=CFG.c("panel2"), button_color=CARROT, width=200,
                      command=_live_lock).pack(side="left", padx=6)

    r = ctk.CTkFrame(cust, fg_color="transparent"); r.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(r, text="Scrambler", width=110, anchor="w", font=CFG.font(12)).pack(side="left")

    def _live_scr(choice):
        try:
            monitor.scrambler = choice
        except Exception:  # noqa
            pass
    ctk.CTkOptionMenu(r, variable=mscr_var, values=list(CrackMonitor.SCRAMBLERS.keys()),
                      fg_color=CFG.c("panel2"), button_color=CARROT, width=200,
                      command=_live_scr).pack(side="left", padx=6)

    def _preview_anim():
        try:
            if state["busy"]:
                return
            open_page("Workbench")
            monitor.lock_style = mlock_var.get()
            monitor.scrambler = mscr_var.get()
            monitor.start()
            monitor.frame.after(2600, lambda: None if state["busy"] else monitor.success("preview"))
        except Exception:  # noqa
            pass
    ctk.CTkButton(cust, text="▶ Preview animation", fg_color=LEAF, text_color=INK,
                  hover_color="#28a862", command=_preview_anim).pack(anchor="w", padx=6, pady=(4, 2))
    _hint("Size, style and scrambler apply live. Full-width makes the number stream run the "
          "whole width of the window. Lock styles: padlock, shield, circuit, skull, vault. "
          "Scramblers: matrix, hex, binary, katakana, glitch, braille.")

    # --- colors ---
    _section("Colors")
    _hint("Click a swatch to pick. Applies after Save & Restart.")
    color_vars = {}
    color_labels = [
        ("carrot", "Accent (carrot)"), ("leaf", "Success (leaf)"),
        ("ink", "Background"), ("panel", "Panel"), ("panel2", "Panel alt"),
        ("mute", "Muted text"), ("logbg", "Log background"),
        ("logfg", "Log text"), ("danger", "Danger"),
    ]
    swatch_ref = {}
    for key, label in color_labels:
        rr = ctk.CTkFrame(cust, fg_color="transparent"); rr.pack(fill="x", padx=6, pady=3)
        ctk.CTkLabel(rr, text=label, width=150, anchor="w", font=CFG.font(12)).pack(side="left")
        var = ctk.StringVar(value=CFG.c(key)); color_vars[key] = var
        ent = ctk.CTkEntry(rr, textvariable=var, width=110, font=CFG.font(12))
        ent.pack(side="left", padx=6)
        sw = ctk.CTkButton(rr, text="", width=42, fg_color=CFG.c(key), hover_color=CFG.c(key))
        swatch_ref[key] = sw

        def _mk(k=key, v=var, s=sw, e=ent):
            def pick():
                init = v.get()
                res = colorchooser.askcolor(color=init, title=f"Pick {k}")
                if res and res[1]:
                    v.set(res[1]); s.configure(fg_color=res[1], hover_color=res[1])
            return pick
        sw.configure(command=_mk())
        sw.pack(side="left", padx=6)

    # --- gif background ---
    _section("Animated GIF background")
    if not PIL_OK:
        _hint("Pillow not installed yet — run Setup → Install everything, then restart.")
    g = CFG.data["gif"]
    gif_enable = ctk.BooleanVar(value=g.get("enabled", False))
    gif_header = ctk.BooleanVar(value=g.get("header", True))
    gif_fullbg = ctk.BooleanVar(value=g.get("fullbg", True))
    gif_path = ctk.StringVar(value=g.get("path", ""))
    gif_logpath = ctk.StringVar(value=g.get("log_path", ""))
    gif_dim = ctk.DoubleVar(value=float(g.get("dim", 0.55)))
    gif_hdim = ctk.DoubleVar(value=float(g.get("header_dim", 0.25)))

    rr = ctk.CTkFrame(cust, fg_color="transparent"); rr.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(rr, text="GIF file", width=110, anchor="w", font=CFG.font(12)).pack(side="left")
    ctk.CTkEntry(rr, textvariable=gif_path, width=420, font=CFG.font(12)).pack(side="left", padx=6)

    def pick_gif():
        p = filedialog.askopenfilename(initialdir=_start_dir(), title="Select a .gif",
                                       filetypes=[("GIF", "*.gif"), ("All", "*.*")])
        if p:
            gif_path.set(p)
    ctk.CTkButton(rr, text="Browse", fg_color=CARROT, text_color=INK,
                  hover_color="#d9660f", width=90, command=pick_gif).pack(side="left", padx=6)

    # second gif: behind the log / terminal area
    rr = ctk.CTkFrame(cust, fg_color="transparent"); rr.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(rr, text="Terminal GIF", width=110, anchor="w", font=CFG.font(12)).pack(side="left")
    ctk.CTkEntry(rr, textvariable=gif_logpath, width=420, font=CFG.font(12)).pack(side="left", padx=6)

    def pick_log_gif():
        p = filedialog.askopenfilename(initialdir=_start_dir(), title="Select a .gif for the log background",
                                       filetypes=[("GIF", "*.gif"), ("All", "*.*")])
        if p:
            gif_logpath.set(p)
    ctk.CTkButton(rr, text="Browse", fg_color=CARROT, text_color=INK,
                  hover_color="#d9660f", width=90, command=pick_log_gif).pack(side="left", padx=6)
    _hint("Terminal GIF animates behind the log panel (needs 'Enable GIF' on). The log text "
          "stays on an opaque panel, so the animation shows as a glowing animated border.")

    rr = ctk.CTkFrame(cust, fg_color="transparent"); rr.pack(fill="x", padx=6, pady=2)
    ctk.CTkCheckBox(rr, text="Enable GIF", variable=gif_enable,
                    fg_color=CARROT, font=CFG.font(12)).pack(side="left", padx=6)
    ctk.CTkCheckBox(rr, text="Header animation", variable=gif_header,
                    fg_color=CARROT, font=CFG.font(12)).pack(side="left", padx=12)
    ctk.CTkCheckBox(rr, text="Full-window backdrop", variable=gif_fullbg,
                    fg_color=CARROT, font=CFG.font(12)).pack(side="left", padx=12)

    rr = ctk.CTkFrame(cust, fg_color="transparent"); rr.pack(fill="x", padx=6, pady=4)
    ctk.CTkLabel(rr, text="Backdrop dim", width=110, anchor="w", font=CFG.font(12)).pack(side="left")
    dim_lbl = ctk.CTkLabel(rr, text=f"{gif_dim.get():.2f}", width=48, font=CFG.font(12))
    ctk.CTkSlider(rr, from_=0.0, to=0.9, variable=gif_dim, width=220, button_color=CARROT,
                  progress_color=LEAF,
                  command=lambda v: dim_lbl.configure(text=f"{float(v):.2f}")).pack(side="left", padx=6)
    dim_lbl.pack(side="left")
    _hint("Higher dim = darker backdrop = more readable text over the animation.")

    # --- text strings ---
    _section("Text & labels")
    _hint("Rebrand every visible string. (The app name is locked and can't be changed.) "
          "Use {app} in the ready banner for the app name.")
    text_vars = {}
    LOCKED_TEXT = {"app_title"}   # app name is not user-editable
    for key in sorted(CFG.data["text"].keys()):
        if key in LOCKED_TEXT:
            continue
        rr = ctk.CTkFrame(cust, fg_color="transparent"); rr.pack(fill="x", padx=6, pady=2)
        ctk.CTkLabel(rr, text=key, width=150, anchor="w",
                     text_color=LEAF, font=CFG.font(11)).pack(side="left")
        v = ctk.StringVar(value=CFG.data["text"][key]); text_vars[key] = v
        ctk.CTkEntry(rr, textvariable=v, width=520, font=CFG.font(11)).pack(side="left", padx=6)

    # --- save / restart / reset ---
    def gather():
        CFG.data["appearance"] = appear_var.get()
        CFG.data["font_family"] = fam_var.get().strip() or "JetBrains Mono"
        CFG.data["font_scale"] = round(float(scale_var.get()), 2)
        CFG.data["window_opacity"] = round(float(opac_var.get()), 2)
        CFG.data.setdefault("layout", {})
        CFG.data.setdefault("monitor", {})
        CFG.data["monitor"]["size"] = int(msize_var.get())
        CFG.data["monitor"]["fullwidth"] = bool(mfull_var.get())
        CFG.data["monitor"]["lock_style"] = mlock_var.get()
        CFG.data["monitor"]["scrambler"] = mscr_var.get()
        for k, v in color_vars.items():
            val = v.get().strip()
            if re.fullmatch(r"#[0-9a-fA-F]{6}", val):
                CFG.data["colors"][k] = val
        CFG.data["gif"].update({
            "enabled": bool(gif_enable.get()), "header": bool(gif_header.get()),
            "fullbg": bool(gif_fullbg.get()), "path": gif_path.get().strip(),
            "log_path": gif_logpath.get().strip(),
            "dim": round(float(gif_dim.get()), 2), "header_dim": round(float(gif_hdim.get()), 2),
        })
        for k, v in text_vars.items():
            if k not in LOCKED_TEXT:
                CFG.data["text"][k] = v.get()
        # app_title is always forced back to the canonical name
        CFG.data["text"]["app_title"] = DEFAULT_CFG["text"]["app_title"]

    status = ctk.CTkLabel(cust, text="", text_color=LEAF, font=CFG.font(12))

    def save_only():
        gather()
        ok = CFG.save()
        status.configure(text="Saved ✓  (restart to apply)" if ok else "Save failed ✗",
                         text_color=LEAF if ok else CFG.c("danger"))

    def save_restart():
        gather()
        if CFG.save():
            restart_app()
        else:
            status.configure(text="Save failed ✗", text_color=CFG.c("danger"))

    def reset_defaults():
        CFG.data = json.loads(json.dumps(DEFAULT_CFG))
        CFG.save()
        restart_app()

    def export_theme():
        gather()
        out = _real_home()
        path = filedialog.asksaveasfilename(initialdir=_start_dir(), title="Export theme pack",
                                            initialfile="mytheme.c4theme",
                                            defaultextension=".c4theme") or \
            os.path.join(out, "mytheme.c4theme")
        pack = {k: CFG.data[k] for k in ("appearance", "font_family", "font_scale",
                                         "colors", "gif", "text")}
        try:
            Path(path).write_text(json.dumps(pack, indent=2))
            status.configure(text=f"Theme exported → {path}", text_color=LEAF)
        except Exception as e:  # noqa
            status.configure(text=f"Export failed: {e}", text_color=CFG.c("danger"))

    def import_theme():
        path = filedialog.askopenfilename(initialdir=_start_dir(), title="Import theme pack",
                                          filetypes=[("theme", "*.c4theme *.json"), ("all", "*.*")])
        if not path:
            return
        try:
            pack = json.loads(Path(path).read_text())
            _deep_merge(CFG.data, pack)
            CFG.save()
            restart_app()
        except Exception as e:  # noqa
            status.configure(text=f"Import failed: {e}", text_color=CFG.c("danger"))

    br = ctk.CTkFrame(cust, fg_color="transparent"); br.pack(fill="x", padx=6, pady=(16, 6))
    ctk.CTkButton(br, text="💾 Save", fg_color="#2a2f34", hover_color="#3a4048",
                  command=save_only).pack(side="left", padx=6)
    ctk.CTkButton(br, text="🔁 Save & Restart", fg_color=CARROT, text_color=INK,
                  hover_color="#d9660f", command=save_restart).pack(side="left", padx=6)
    ctk.CTkButton(br, text="↺ Reset to defaults", fg_color="#3a2020", hover_color="#5a2020",
                  text_color=CFG.c("danger"), command=reset_defaults).pack(side="left", padx=6)

    br2 = ctk.CTkFrame(cust, fg_color="transparent"); br2.pack(fill="x", padx=6, pady=(2, 6))
    ctk.CTkButton(br2, text="⬆ Export theme pack", fg_color="#2a2f34", hover_color="#3a4048",
                  command=export_theme).pack(side="left", padx=6)
    ctk.CTkButton(br2, text="⬇ Import theme pack", fg_color="#2a2f34", hover_color="#3a4048",
                  command=import_theme).pack(side="left", padx=6)
    _hint("Theme packs (.c4theme) are shareable JSON — trade them with the community.")

    status.pack(anchor="w", padx=6, pady=4)
    _hint(f"Config file: {CONFIG_PATH}")

    # ---- everything's built: drop the loading splash --------------------- #
    try:
        splash.destroy()
    except Exception:  # noqa
        pass

    # ---- first-run authorized-use disclaimer (modal) --------------------- #
    if not CFG.data.get("accepted_terms"):
        dlg = ctk.CTkToplevel(app)
        dlg.title("C4rr07CR4cKR — authorized use")
        dlg.geometry("560x460")
        dlg.configure(fg_color=INK)
        dlg.transient(app)
        dlg.grab_set()
        ctk.CTkLabel(dlg, text="🥕 Authorized use only", text_color=CARROT,
                     font=CFG.font(18, "bold")).pack(padx=20, pady=(20, 8))
        box = ctk.CTkTextbox(dlg, fg_color=PANEL, text_color=CFG.c("logfg"),
                             font=CFG.font(12), wrap="word")
        box.pack(fill="both", expand=True, padx=20, pady=8)
        box.insert("end", DISCLAIMER)
        box.configure(state="disabled")

        def _accept():
            CFG.data["accepted_terms"] = True
            CFG.save()
            dlg.destroy()

        def _decline():
            dlg.destroy()
            app.destroy()

        brow = ctk.CTkFrame(dlg, fg_color="transparent"); brow.pack(fill="x", padx=20, pady=14)
        ctk.CTkButton(brow, text="I understand & agree", fg_color=LEAF, text_color=INK,
                      hover_color="#28a862", font=CFG.font(13, "bold"),
                      command=_accept).pack(side="left", padx=6)
        ctk.CTkButton(brow, text="Decline & exit", fg_color="#3a2020", hover_color="#5a2020",
                      text_color=CFG.c("danger"), command=_decline).pack(side="left", padx=6)
        app.wait_window(dlg)
        if not CFG.data.get("accepted_terms"):
            return  # user declined; app already destroyed

    app.mainloop()


CHEAT_SHEET = r"""
C4rr07CR4cKR — quick reference
==============================

WHAT IT AUTODETECTS
  • raw hashes / hash lists / shadow lines   → hashcat (mode guessed) or john
  • .pcap / .pcapng (WPA/WPA2/PMKID)         → hcxpcapngtool → hashcat -m 22000
  • zip / rar / 7z (password-protected)      → zip2john/rar2john/7z2john → john
  • office (doc/docx/xls/xlsx) / pdf         → office2john / pdf2john → john
  • OpenSSH / PEM private keys               → ssh2john → john
  • KeePass .kdbx                            → keepass2john → john (or hashcat -m 13400)

COMMON HASHCAT MODES
  0    MD5           100  SHA1          1400 SHA256        1700 SHA512
  1000 NTLM          3200 bcrypt        1800 sha512crypt   500  md5crypt($1$)
  7400 sha256crypt   22000 WPA-PBKDF2/PMKID   13100 Kerberoast(TGS)   18200 AS-REP
  400  phpass(WP)    13400 KeePass      10900 PBKDF2-SHA256

MANUAL FALLBACKS
  hashcat -m 0 hashes.txt rockyou.txt --status
  john --format=raw-md5 --wordlist=rockyou.txt hashes.txt
  hcxpcapngtool -o cap.hc22000 cap.pcapng && hashcat -m 22000 cap.hc22000 rockyou.txt
  zip2john secret.zip > z.hash && john --wordlist=rockyou.txt z.hash

RULES / SPEED TIPS (CTF)
  • Add hashcat rules for weak hashes:  -r /usr/share/hashcat/rules/best64.rule
  • Show cracked results:               hashcat -m <mode> <file> --show
  • John pot file:                      ~/.john/john.pot  (john --show <file>)
  • rockyou lives at /usr/share/wordlists/rockyou.txt (gunzip the .gz if needed)

GPU / COMPUTE
  • List devices hashcat can use:       hashcat -I
  • Force GPU only / CPU only:           -D 2   /   -D 1
  • Pick specific device ids:            -d 1,2
  • Workload profile (util vs latency):  -w 1..4   (3-4 for a dedicated rig)
  • Optimised kernels (faster, capped):  -O
  • NVIDIA needs nvidia-opencl-icd; AMD needs mesa-opencl-icd; Intel intel-opencl-icd
  • Verify OpenCL platforms:             clinfo | head
  • Benchmark your card:                 hashcat -b -m 22000
  • aircrack-ng is CPU-only → for GPU WPA use hcxtools + hashcat -m 22000

Everything here targets artifacts YOU hold in a CTF/lab. Keep it in scope.
"""


BANNER = r"""
  C4rr07CR4cKR — CTF / authorized-testing cracking orchestrator
  ------------------------------------------------------------------
  Use ONLY on systems, captures, and hashes you own or are explicitly
  authorized to test (CTF, lab, bug-bounty in scope). Cracking or
  intercepting credentials you are not authorized to touch is illegal.
"""

DISCLAIMER = (
    "C4rr07CR4cKR is built for ethical hacking, CTF challenges, and penetration "
    "testing that you are explicitly authorized to perform.\n\n"
    "Only point this tool at systems, networks, accounts, captures, and data that "
    "you own or have written permission to test. Using it to access, crack, or "
    "attack anything you do not have authorization for is illegal, and it is not "
    "what this tool is for.\n\n"
    "You alone are responsible for staying in scope and within the law. By "
    "continuing, you confirm that you have permission to test the targets you use "
    "this tool against, and that you will not conduct any unauthorized or illegal "
    "activity."
)

FOOTER = ("For authorized security testing & CTF use only · stay in scope, stay legal · "
          "never target systems you don't own or have written permission to test")

SCOPE_TEMPLATE = """\
# C4rr07CR4cKR scope / rules-of-engagement file.
# Loaded targets are the ONLY hosts the Online (Hydra) tab will touch.
engagement: "example-engagement-2026"
targets:
  - 10.10.10.0/24
  - ctf.example.com
allow_online: true
allow_offline: true
max_threads: 16
expires: "2026-12-31T23:59:59"
authorization: "Signed off by: <name/role>, <date>"
"""


def _print_banner():
    print(BANNER)


def _ensure_terms():
    """One-time authorized-use acknowledgement, remembered in config."""
    if CFG.data.get("accepted_terms"):
        return
    _print_banner()
    try:
        ans = input("  Type 'yes' to confirm authorized use: ").strip().lower()
    except EOFError:
        ans = "yes"  # non-interactive
    if ans not in ("y", "yes"):
        print("  Declined. Exiting.")
        sys.exit(0)
    CFG.data["accepted_terms"] = True
    CFG.save()


def run_cli(args):
    """Headless mode for scripting / CI."""
    _print_banner()
    audit = AuditLog(args.audit_log or str(CONFIG_DIR / "audit.log.jsonl"))
    E = Engine(lambda m: sys.stdout.write(m))
    E.audit = audit
    audit.append("cli_invoked", argv=sys.argv[1:])
    scope = None
    if args.scope:
        try:
            scope = Scope.load(args.scope)
            print(f"[scope] {scope.engagement} loaded ({len(scope.targets)} target rule(s))")
            audit.append("scope_loaded", file=args.scope, engagement=scope.engagement)
        except Exception as e:  # noqa
            print(f"[!] scope load failed: {e}"); sys.exit(1)

    if args.verify_audit:
        ok, n = audit.verify()
        print(f"audit chain: {'OK' if ok else 'TAMPERED'} ({n} records)")
        return
    if args.analyze:
        a = Analyzer.run(args.analyze)
        print(f"kind: {a.kind} ({a.detail})")
        for lbl, mode, jf in a.hash_candidates:
            print(f"  candidate: {lbl}  hashcat -m {mode}  john --format={jf}")
        digest = sha256_file(args.analyze)
        print(f"sha256: {digest}")
        audit.append("file_analyzed", path=args.analyze, sha256=digest, kind=a.kind)
        pm = PluginManager(log=lambda m: sys.stdout.write(m)).load()
        try:
            head = open(args.analyze, "rb").read(4096)
        except Exception:  # noqa
            head = b""
        for det in pm.api.detectors:
            try:
                det(args.analyze, head, a, lambda m: sys.stdout.write(m))
            except Exception:  # noqa
                pass
        return
    if args.decode:
        src = args.decode
        if os.path.exists(src):
            src = open(src, "r", errors="replace").read().strip().splitlines()[0]
        for chain, txt, score, flagged in Decoder.magic(src, depth=4):
            print(("FLAG " if flagged else "") + f"[{' -> '.join(chain)}] {txt[:100]}")
        return
    if args.pcap:
        PcapIntel.scan(args.pcap, lambda m: sys.stdout.write(m))
        return
    if args.trophy:
        for s, h, p in Trophy.entries():
            print(f"[{s}] {h} -> {p}")
        return
    if args.online_target:
        if scope and not scope.allow_online:
            print("[!] BLOCKED by scope: online attacks not permitted."); sys.exit(1)
        if scope and not scope.target_ok(args.online_target):
            print(f"[!] BLOCKED by scope: {args.online_target} is out of scope."); sys.exit(1)
        if not args.authorized:
            print("[!] Pass --authorized to confirm you may test this target."); sys.exit(1)
        h = Hydra(lambda m: sys.stdout.write(m))
        audit.append("online_attempt", target=args.online_target, service=args.service)
        ok = h.run(args.online_target, args.service, user=args.user, userlist=args.userlist,
                   password=args.password, passlist=args.wordlist, port=args.port,
                   authorized=True, scope=(scope.targets if scope else []))
        audit.append("online_result", target=args.online_target, success=bool(ok))
        return
    if args.crack:
        if scope and not scope.allow_offline:
            print("[!] BLOCKED by scope: offline cracking not permitted."); sys.exit(1)
        a = Analyzer.run(args.crack)
        wl = args.wordlist or (find_wordlists()[0])
        target = args.crack
        if a.prep_helper:
            target = E.prepare_hash(a.prep_helper, args.crack) or args.crack
        mode = args.mode if args.mode is not None else a.suggested_mode
        if a.kind == "pcap":
            E.run_hcxtools_then_hashcat(args.crack, wl, attack=args.attack,
                                        rule=args.rule, mask=args.mask)
        elif mode is not None:
            E.run_hashcat(mode, target, wl, attack=args.attack, rule=args.rule,
                          mask=args.mask, session=args.session)
        else:
            print("[!] Could not determine hashcat mode; pass --mode.")
        if args.report:
            digest, sig = Reporter.write(E, args.report, audit=audit, gpg_key=args.gpg_key)
            print(f"[+] report -> {args.report}  sha256={digest}" + (f"  sig={sig}" if sig else ""))
        return


# --------------------------------------------------------------------------- #
def main():
    import argparse
    ap = argparse.ArgumentParser(prog="c4rr07cr4ckr", add_help=True,
                                 description="CTF cracking orchestrator (GUI + CLI)")
    ap.add_argument("--no-root", action="store_true", help="don't self-elevate")
    ap.add_argument("--cli", action="store_true", help="headless mode (no GUI)")
    ap.add_argument("--analyze", metavar="FILE", help="identify a file/hash and exit")
    ap.add_argument("--crack", metavar="FILE", help="analyze + crack a file")
    ap.add_argument("--decode", metavar="STR|FILE", help="peel encodings (magic)")
    ap.add_argument("--pcap", metavar="FILE", help="deep pcap credential scan")
    ap.add_argument("--trophy", action="store_true", help="list cracked potfile entries")
    ap.add_argument("--wordlist", metavar="PATH")
    ap.add_argument("--mode", type=int, help="hashcat mode override")
    ap.add_argument("--attack", type=int, default=0, help="0/3/6/7")
    ap.add_argument("--rule", metavar="PATH")
    ap.add_argument("--mask", metavar="MASK")
    ap.add_argument("--session", metavar="NAME")
    ap.add_argument("--report", metavar="FILE", help="write a markdown report")
    ap.add_argument("--gpg-key", dest="gpg_key", metavar="KEYID", help="sign report with gpg key")
    ap.add_argument("--scope", metavar="FILE", help="scope.yaml/json — authoritative RoE gate")
    ap.add_argument("--audit-log", dest="audit_log", metavar="FILE",
                     help="path to the tamper-evident audit log (default: ~/.config/.../audit.log.jsonl)")
    ap.add_argument("--verify-audit", action="store_true", help="verify audit chain integrity and exit")
    ap.add_argument("--online-target", metavar="HOST", help="run an authorized online login test")
    ap.add_argument("--service", default="ssh", help="hydra service for --online-target")
    ap.add_argument("--user", metavar="NAME")
    ap.add_argument("--userlist", metavar="PATH")
    ap.add_argument("--password", metavar="PASS")
    ap.add_argument("--port", type=int)
    ap.add_argument("--authorized", action="store_true",
                     help="confirm you are authorized to test --online-target")
    args = ap.parse_args()

    # If we're running elevated, make the invoking user's pip packages importable
    # (fixes 'installed for my user but the app runs as root').
    _add_invoking_user_site_packages()

    cli_wanted = args.cli or any([args.analyze, args.crack, args.decode, args.pcap,
                                  args.trophy, args.online_target, args.verify_audit])

    if not cli_wanted:
        import workbench
        workbench.main([])
        return

    # Early dependency check for GUI mode, BEFORE self-elevation — so a missing
    # tkinter/customtkinter produces a clear message instead of a silent failure
    # (the #1 "app won't launch" cause). CLI mode doesn't need the GUI stack.
    if not cli_wanted:
        missing = []
        try:
            import tkinter  # noqa
        except Exception:  # noqa
            missing.append("python3-tk (system package: sudo apt install python3-tk)")
        try:
            import customtkinter  # noqa
        except Exception:  # noqa
            missing.append("customtkinter (pip install --break-system-packages customtkinter)")
        if missing:
            print("[!] C4rr07CR4cKR can't start — missing GUI dependencies:")
            for m in missing:
                print(f"      - {m}")
            print("\n    Quick fix:")
            print("      sudo apt install python3-tk")
            print("      python3 -m pip install --break-system-packages customtkinter pillow pyyaml")
            print("\n    Or re-run the installer:  sudo ./install.sh")
            sys.exit(1)

    if not args.no_root:
        ensure_root()
    if cli_wanted:
        _ensure_terms()          # terminal acknowledgement
        run_cli(args)
    else:
        launch_gui()             # GUI shows the disclaimer modal on first run


if __name__ == "__main__":
    main()
