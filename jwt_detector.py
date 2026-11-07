# C4rr07CR4cKR plugin — JWT detector & decoder
# Drop this file in ~/.config/c4rr07cr4ckr/plugins/ (or /opt/c4rr07cr4ckr/plugins/).
#
# A plugin is any .py exposing register(api). Through `api` you can:
#   api.add_detector(fn)            fn(path, head_bytes, analysis, log) -> enrich analysis
#   api.add_action(label, fn)       fn(ctx)  ctx = {'file','log','engine','wordlist'}
#
# This example recognises JSON Web Tokens and, for HS256, points at the right
# hashcat mode so a weak signing secret can be brute-forced in a CTF.

import re
import json
import base64

PLUGIN_NAME = "JWT detector"

_JWT_RX = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _b64url(seg):
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def _detect(path, head, analysis, log):
    try:
        text = head.decode("utf-8", "ignore")
    except Exception:
        return
    m = _JWT_RX.search(text)
    if not m:
        return
    log("[plugin/JWT] JSON Web Token detected.\n")
    try:
        hdr = json.loads(_b64url(m.group(0).split(".")[0]))
        alg = hdr.get("alg", "?")
        log(f"[plugin/JWT] alg = {alg}\n")
        if str(alg).upper() == "HS256":
            log("[plugin/JWT] HS256 -> crack the secret: hashcat -m 16500 <jwt> <wordlist>\n")
            analysis.notes.append("JWT (HS256) — hashcat -m 16500 to brute the signing secret.")
        elif str(alg).lower() == "none":
            log("[plugin/JWT] alg=none — classic signature-bypass; forge the token directly.\n")
        else:
            analysis.notes.append(f"JWT ({alg}) — inspect with jwt_tool.")
    except Exception:
        analysis.notes.append("JWT present — inspect with jwt_tool.")


def _action(ctx):
    path, log = ctx.get("file"), ctx["log"]
    if not path:
        log("[plugin/JWT] Select a file on the Analyze tab first.\n")
        return
    try:
        data = open(path, "r", errors="replace").read()
    except Exception as e:
        log(f"[plugin/JWT] {e}\n")
        return
    m = _JWT_RX.search(data)
    if not m:
        log("[plugin/JWT] No JWT found in file.\n")
        return
    parts = m.group(0).split(".")
    try:
        log("[plugin/JWT] header : " + json.dumps(json.loads(_b64url(parts[0]))) + "\n")
        log("[plugin/JWT] payload: " + json.dumps(json.loads(_b64url(parts[1]))) + "\n")
    except Exception as e:
        log(f"[plugin/JWT] decode error: {e}\n")


def register(api):
    api.add_detector(_detect)
    api.add_action("🔑 JWT: decode header + payload of selected file", _action)
