#!/usr/bin/env bash
#
#  C4rr07CR4cKR installer
#  Registers the app system-wide, installs the icon into the hicolor theme,
#  adds a launcher to the application menu, and drops a shortcut on your Desktop.
#
#  Usage:   sudo ./install.sh
#
set -euo pipefail

APP_ID="c4rr07cr4ckr"
APP_NAME="C4rr07CR4cKR"
INSTALL_DIR="/opt/${APP_ID}"
BIN_LINK="/usr/local/bin/${APP_ID}"
DESKTOP_SYS="/usr/share/applications/${APP_ID}.desktop"
ICON_DIR="/usr/share/icons/hicolor"

# --- must be root -----------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "[!] Please run with sudo:  sudo ./install.sh"
  exit 1
fi

# --- resolve the real (non-root) user who invoked sudo ----------------------
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
[[ -z "$REAL_HOME" ]] && REAL_HOME="$HOME"

# --- locate source files (this script's directory) --------------------------
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_SRC="${SRC}/${APP_ID}.py"
SVG_SRC="${SRC}/${APP_ID}.svg"

if [[ ! -f "$PY_SRC" ]]; then
  echo "[!] ${APP_ID}.py not found next to this installer."
  exit 1
fi

echo "[*] Installing ${APP_NAME} for user '${REAL_USER}'"

# --- 0. dependencies (the app is useless without these) --------------------
echo "[*] Installing runtime dependencies…"

# 0a. Python 3 itself
if ! command -v python3 >/dev/null 2>&1; then
  echo "    → installing python3"
  apt-get update -y  >/dev/null 2>&1 || true
  apt-get install -y python3 python3-pip >/dev/null 2>&1 || true
fi

# 0b. tkinter — a SYSTEM package (pip cannot provide it). This is the #1 cause
#     of "the app silently won't launch": customtkinter imports tkinter, and
#     without python3-tk the import fails and the window never appears.
NEED_TK=0
python3 -c "import tkinter" >/dev/null 2>&1 || NEED_TK=1
if [[ "$NEED_TK" -eq 1 ]]; then
  echo "    → installing python3-tk (tkinter)"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y python3-tk >/dev/null 2>&1 || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3-tkinter >/dev/null 2>&1 || true
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --noconfirm tk >/dev/null 2>&1 || true
  fi
fi
# verify tkinter now imports; if not, warn loudly (don't fail the whole install)
if ! python3 -c "import tkinter" >/dev/null 2>&1; then
  echo "    [!] WARNING: tkinter still not available. Install it manually:"
  echo "        Debian/Kali/Parrot/Ubuntu:  sudo apt install python3-tk"
  echo "        Fedora:                     sudo dnf install python3-tkinter"
  echo "        Arch:                       sudo pacman -S tk"
else
  echo "    → tkinter OK"
fi

# 0c. pip packages. Two targets that BOTH matter:
#     - the invoking user's ~/.local  (non-elevated launches)
#     - ROOT's environment            (the app self-elevates to root!)
#     On PEP-668 distros (Parrot/Kali/Debian 12+) pip needs --break-system-packages.
PIP_PKGS="customtkinter pillow pyyaml name-that-hash"
echo "    → pip installing: ${PIP_PKGS}"

pip_into_root() {
  python3 -m pip install --upgrade ${PIP_PKGS} >/dev/null 2>&1 && return 0
  python3 -m pip install --break-system-packages --upgrade ${PIP_PKGS} >/dev/null 2>&1 && return 0
  PIP_BREAK_SYSTEM_PACKAGES=1 python3 -m pip install --break-system-packages --upgrade ${PIP_PKGS} >/dev/null 2>&1 && return 0
  return 1
}
pip_into_user() {
  sudo -u "$REAL_USER" python3 -m pip install --user --upgrade ${PIP_PKGS} >/dev/null 2>&1 && return 0
  sudo -u "$REAL_USER" python3 -m pip install --user --break-system-packages --upgrade ${PIP_PKGS} >/dev/null 2>&1 && return 0
  return 1
}

if pip_into_root; then
  echo "    → installed into root env"
else
  echo "    [!] root pip install failing — trying apt fallback"
  apt-get install -y python3-customtkinter python3-pil python3-yaml >/dev/null 2>&1 || true
fi
pip_into_user || true

# verify BOTH root and user can import customtkinter
ROOT_OK=0; USER_OK=0
python3 -c "import customtkinter" >/dev/null 2>&1 && ROOT_OK=1
sudo -u "$REAL_USER" python3 -c "import customtkinter" >/dev/null 2>&1 && USER_OK=1
[[ "$ROOT_OK" -eq 1 ]] && echo "    → customtkinter OK (root)" || echo "    [!] customtkinter missing for root"
[[ "$USER_OK" -eq 1 ]] && echo "    → customtkinter OK (user ${REAL_USER})"
if [[ "$ROOT_OK" -eq 0 && "$USER_OK" -eq 1 ]]; then
  echo "    [i] Installed for '${REAL_USER}' but not root — that's fine now:"
  echo "        the app auto-adds your user site-packages when it elevates."
elif [[ "$ROOT_OK" -eq 0 && "$USER_OK" -eq 0 ]]; then
  echo "    [!] Not importable anywhere. Manual fix:"
  echo "        sudo python3 -m pip install --break-system-packages customtkinter pillow pyyaml"
fi

# --- 1. program ------------------------------------------------------------
install -d "$INSTALL_DIR"
install -m 0755 "${SRC}/workbench.py" "${INSTALL_DIR}/workbench.py"
install -d "${INSTALL_DIR}/workbench_ui"
install -m 0644 "${SRC}/workbench_ui/"* "${INSTALL_DIR}/workbench_ui/"

install -m 0755 "$PY_SRC" "${INSTALL_DIR}/${APP_ID}.py"
ln -sf "${INSTALL_DIR}/${APP_ID}.py" "$BIN_LINK"

# launcher wrapper: on failure, pops up the error (zenity) or opens a terminal
# so the app never "silently does nothing". The .desktop points at this.
LAUNCHER="${INSTALL_DIR}/${APP_ID}-launch.sh"
cat > "$LAUNCHER" <<'LEOF'
#!/usr/bin/env bash
APP="/opt/c4rr07cr4ckr/c4rr07cr4ckr.py"
ERR="$(python3 "$APP" 2>&1 1>/dev/null)"
rc=$?
if [[ $rc -ne 0 && -n "$ERR" ]]; then
  MSG="C4rr07CR4cKR failed to start:\n\n$ERR\n\nMost common fix:\n  sudo apt install python3-tk\n  python3 -m pip install --break-system-packages customtkinter pillow pyyaml"
  if command -v zenity >/dev/null 2>&1; then
    echo -e "$MSG" | zenity --text-info --title="C4rr07CR4cKR error" --width=700 --height=400 2>/dev/null
  elif command -v xterm >/dev/null 2>&1; then
    xterm -hold -e bash -c "echo -e \"$MSG\"" 2>/dev/null
  else
    echo -e "$MSG"
  fi
fi
LEOF
chmod 0755 "$LAUNCHER"
# bundled sample background(s)
shopt -s nullglob
for gif in "${SRC}"/*.gif; do
  install -m 0644 "$gif" "${INSTALL_DIR}/$(basename "$gif")"
  echo "    → background: ${INSTALL_DIR}/$(basename "$gif")"
done
shopt -u nullglob
echo "    → app:   ${INSTALL_DIR}/${APP_ID}.py  (symlinked: ${BIN_LINK})"

# --- tests (kept alongside the app for auditing; not required at runtime) --
if [[ -f "${SRC}/test_${APP_ID}.py" ]]; then
  install -m 0644 "${SRC}/test_${APP_ID}.py" "${INSTALL_DIR}/test_${APP_ID}.py"
  echo "    → tests: ${INSTALL_DIR}/test_${APP_ID}.py  (run: pytest ${INSTALL_DIR})"
fi

# --- plugins ---------------------------------------------------------------
if [[ -d "${SRC}/plugins" ]]; then
  install -d "${INSTALL_DIR}/plugins"
  install -m 0644 "${SRC}/plugins/"*.py "${INSTALL_DIR}/plugins/" 2>/dev/null || true
  echo "    → plugins: ${INSTALL_DIR}/plugins/"
fi

# --- 2. icons --------------------------------------------------------------
# scalable SVG (preferred by modern desktops)
if [[ -f "$SVG_SRC" ]]; then
  install -d "${ICON_DIR}/scalable/apps"
  install -m 0644 "$SVG_SRC" "${ICON_DIR}/scalable/apps/${APP_ID}.svg"
  echo "    → icon:  ${ICON_DIR}/scalable/apps/${APP_ID}.svg"
fi
# raster PNGs at standard sizes (if shipped)
for sz in 32 48 64 128 256; do
  png="${SRC}/icon_${sz}.png"
  if [[ -f "$png" ]]; then
    install -d "${ICON_DIR}/${sz}x${sz}/apps"
    install -m 0644 "$png" "${ICON_DIR}/${sz}x${sz}/apps/${APP_ID}.png"
  fi
done

# --- 3. desktop entry (system menu) ----------------------------------------
cat > "$DESKTOP_SYS" <<EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=${APP_NAME}
GenericName=CTF Cracking Orchestrator
Comment=Detect hashes/pcaps/archives, pick the right tool + wordlist, crack on GPU
Exec=${INSTALL_DIR}/${APP_ID}-launch.sh
Icon=${APP_ID}
Terminal=false
Categories=Security;System;Utility;
Keywords=hashcat;john;crack;ctf;hash;pcap;wifi;wpa;gpu;rabbit;
StartupNotify=true
EOF
chmod 0644 "$DESKTOP_SYS"
echo "    → menu:  ${DESKTOP_SYS}"

# --- 4. desktop shortcut for the real user ---------------------------------
# figure out the Desktop dir (respects localized/xdg config)
DESKTOP_DIR="$(sudo -u "$REAL_USER" bash -lc 'xdg-user-dir DESKTOP 2>/dev/null' || true)"
[[ -z "$DESKTOP_DIR" || ! -d "$DESKTOP_DIR" ]] && DESKTOP_DIR="${REAL_HOME}/Desktop"
mkdir -p "$DESKTOP_DIR"
DESKTOP_LNK="${DESKTOP_DIR}/${APP_ID}.desktop"
cp "$DESKTOP_SYS" "$DESKTOP_LNK"
chown "$REAL_USER":"$REAL_USER" "$DESKTOP_LNK"
chmod 0755 "$DESKTOP_LNK"
# mark trusted so GNOME/Nautilus lets it launch without the "untrusted" nag
sudo -u "$REAL_USER" bash -lc "gio set '$DESKTOP_LNK' metadata::trusted true" 2>/dev/null || true
echo "    → shortcut: ${DESKTOP_LNK}"

# --- 5. refresh caches -----------------------------------------------------
update-desktop-database /usr/share/applications 2>/dev/null || true
gtk-update-icon-cache -f "$ICON_DIR" 2>/dev/null || true

echo
echo "[+] Done. Launch it from your menu (search 'C4rr07CR4cKR'), the Desktop"
echo "    icon, or the terminal:  ${APP_ID}"
echo "    It self-elevates to root via pkexec/sudo on launch."
echo "    First run → 'Setup / Install' tab → 'Install everything' (pulls tools +"
echo "    the OpenCL runtime for your detected GPU)."
