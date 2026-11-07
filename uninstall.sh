#!/usr/bin/env bash
#  Remove C4rr07CR4cKR (app, icon, menu entry, desktop shortcut).
#  Usage:  sudo ./uninstall.sh
set -euo pipefail
APP_ID="c4rr07cr4ckr"
if [[ $EUID -ne 0 ]]; then echo "[!] Run with sudo."; exit 1; fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"; [[ -z "$REAL_HOME" ]] && REAL_HOME="$HOME"
DESKTOP_DIR="$(sudo -u "$REAL_USER" bash -lc 'xdg-user-dir DESKTOP 2>/dev/null' || true)"
[[ -z "$DESKTOP_DIR" || ! -d "$DESKTOP_DIR" ]] && DESKTOP_DIR="${REAL_HOME}/Desktop"

rm -rf "/opt/${APP_ID}"
rm -f  "/usr/local/bin/${APP_ID}"
rm -f  "/usr/share/applications/${APP_ID}.desktop"
rm -f  "${DESKTOP_DIR}/${APP_ID}.desktop"
find /usr/share/icons/hicolor -name "${APP_ID}.*" -delete 2>/dev/null || true

update-desktop-database /usr/share/applications 2>/dev/null || true
gtk-update-icon-cache -f /usr/share/icons/hicolor 2>/dev/null || true
echo "[+] ${APP_ID} removed."
