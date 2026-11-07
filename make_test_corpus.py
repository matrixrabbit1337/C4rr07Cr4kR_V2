#!/usr/bin/env python3
"""
make_test_corpus.py — build a set of REAL encrypted sample files with KNOWN
passwords, for end-to-end testing of C4rr07CR4cKR.

Everything here is generated locally with a throwaway password ("hunter2" by
default) so you can prove the whole pipeline — detect -> extract -> crack —
actually recovers the known answer, instead of only testing synthetic stubs.

Usage:
    python3 make_test_corpus.py [outdir] [password]

Produces (whichever tools/libs are available on the box):
    corpus/secret.zip            AES/ZipCrypto zip           (needs `zip`)
    corpus/hash_md5.txt          MD5 of the password
    corpus/hash_sha1.txt         SHA1 of the password
    corpus/hash_sha256.txt       SHA256 of the password
    corpus/hash_ntlm.txt         NTLM of the password
    corpus/hash_bcrypt.txt       bcrypt of the password       (needs bcrypt/passlib)
    corpus/hash_sha512crypt.txt  sha512crypt of the password
    corpus/pico_flag.txt         a base64-wrapped CTF flag (for the Decoder)
    corpus/stego.jpg             a JPEG with an appended ZIP (for Image scan)
    corpus/manifest.json         {file: known_password/answer} for the tests
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import zipfile

PASSWORD = "hunter2"


def _try(fn, *a, **k):
    try:
        return fn(*a, **k)
    except Exception as e:  # noqa
        print(f"  [skip] {fn.__name__}: {e}")
        return None


def make_zip(outdir, pw):
    inner = os.path.join(outdir, "_flag.txt")
    with open(inner, "w") as f:
        f.write("flag{zip_cracked_ok}\n")
    out = os.path.join(outdir, "secret.zip")
    if os.path.exists(out):
        os.remove(out)
    # use the system `zip` for a real, crackable encrypted archive
    subprocess.run(["zip", "-P", pw, "-j", out, inner],
                   check=True, capture_output=True)
    os.remove(inner)
    return out


def make_hashes(outdir, pw):
    made = {}
    b = pw.encode()
    specs = {
        "hash_md5.txt": hashlib.md5(b).hexdigest(),
        "hash_sha1.txt": hashlib.sha1(b).hexdigest(),
        "hash_sha256.txt": hashlib.sha256(b).hexdigest(),
    }
    # NTLM = MD4(UTF-16LE) — md4 is disabled in some OpenSSL builds; skip if so
    try:
        specs["hash_ntlm.txt"] = hashlib.new("md4", pw.encode("utf-16le")).hexdigest()
    except Exception as e:  # noqa
        print(f"  [skip] ntlm (md4 unavailable): {e}")
    for name, h in specs.items():
        p = os.path.join(outdir, name)
        with open(p, "w") as f:
            f.write(h + "\n")
        made[p] = pw
    # sha512crypt via crypt (Linux only)
    try:
        import crypt
        h = crypt.crypt(pw, crypt.mksalt(crypt.METHOD_SHA512))
        p = os.path.join(outdir, "hash_sha512crypt.txt")
        with open(p, "w") as f:
            f.write(h + "\n")
        made[p] = pw
    except Exception as e:  # noqa
        print(f"  [skip] sha512crypt: {e}")
    # bcrypt if a lib is present
    try:
        try:
            import bcrypt
            h = bcrypt.hashpw(b, bcrypt.gensalt(rounds=8)).decode()
        except ImportError:
            from passlib.hash import bcrypt as _bc
            h = _bc.hash(pw)
        p = os.path.join(outdir, "hash_bcrypt.txt")
        with open(p, "w") as f:
            f.write(h + "\n")
        made[p] = pw
    except Exception as e:  # noqa
        print(f"  [skip] bcrypt: {e}")
    return made


def make_decoder_flag(outdir):
    p = os.path.join(outdir, "pico_flag.txt")
    payload = base64.b64encode(b"picoCTF{base64_decoded}").decode()
    with open(p, "w") as f:
        f.write(payload + "\n")
    return p, "picoCTF{base64_decoded}"


def make_stego(outdir):
    # a minimal JPEG (valid header+EOI) with a ZIP appended after EOF
    jpg = os.path.join(outdir, "stego.jpg")
    inner = os.path.join(outdir, "_hidden.txt")
    zpath = os.path.join(outdir, "_hidden.zip")
    with open(inner, "w") as f:
        f.write("flag{hidden_in_image}\n")
    with zipfile.ZipFile(zpath, "w") as z:
        z.write(inner, "hidden.txt")
    jpeg_bytes = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
    with open(jpg, "wb") as f:
        f.write(jpeg_bytes)
        with open(zpath, "rb") as z:
            f.write(z.read())
    os.remove(inner)
    os.remove(zpath)
    return jpg


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "corpus"
    pw = sys.argv[2] if len(sys.argv) > 2 else PASSWORD
    os.makedirs(outdir, exist_ok=True)
    manifest = {}

    print(f"[*] Building test corpus in {outdir}/ (password: {pw})")

    z = _try(make_zip, outdir, pw)
    if z:
        manifest[os.path.basename(z)] = {"kind": "zip", "password": pw}
        print(f"  [+] {z}")

    for p, ans in (make_hashes(outdir, pw)).items():
        manifest[os.path.basename(p)] = {"kind": "hash", "password": ans}
        print(f"  [+] {p}")

    fp, flag = make_decoder_flag(outdir)
    manifest[os.path.basename(fp)] = {"kind": "decode", "answer": flag}
    print(f"  [+] {fp}")

    sp = _try(make_stego, outdir)
    if sp:
        manifest[os.path.basename(sp)] = {"kind": "image", "answer": "flag{hidden_in_image}"}
        print(f"  [+] {sp}")

    mpath = os.path.join(outdir, "manifest.json")
    with open(mpath, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"[+] Wrote manifest: {mpath}  ({len(manifest)} entries)")
    print("[i] A known password of 'hunter2' means you can add it to a small "
          "wordlist and watch the full crack succeed on any box with the tools.")


if __name__ == "__main__":
    main()
