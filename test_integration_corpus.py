"""
End-to-end integration tests against a REAL corpus of encrypted files with
known passwords (built by make_test_corpus.py).

These go beyond the synthetic-stub unit tests: they generate genuine encrypted
artifacts and verify that

  1. the Analyzer identifies each real file correctly,
  2. the Decoder recovers a known base64-wrapped flag,
  3. the Image scanner finds data hidden past a JPEG's EOF,
  4. (when the actual crackers are installed) the FULL crack recovers the
     known password "hunter2" — otherwise that step is skipped, not failed.

Run:  pytest test_integration_corpus.py -v
"""
import base64
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
MOD = HERE / "c4rr07cr4ckr.py"
GEN = HERE / "make_test_corpus.py"
PW = "hunter2"


@pytest.fixture(scope="module")
def c4():
    spec = importlib.util.spec_from_file_location("c4_integ", MOD)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture(scope="module")
def corpus():
    d = tempfile.mkdtemp(prefix="c4corpus_")
    subprocess.run([sys.executable, str(GEN), d, PW], check=True, capture_output=True)
    manifest = json.loads(Path(d, "manifest.json").read_text())
    return d, manifest


# --------------------------------------------------------------------------- #
#  1. Detection on real files
# --------------------------------------------------------------------------- #
def test_real_zip_detected(c4, corpus):
    d, man = corpus
    if "secret.zip" not in man:
        pytest.skip("zip not built (no `zip` binary)")
    a = c4.Analyzer.run(os.path.join(d, "secret.zip"))
    assert a.kind == "zip"
    assert a.prep_helper == "zip2john"


def test_real_md5_detected(c4, corpus):
    d, _ = corpus
    a = c4.Analyzer.run(os.path.join(d, "hash_md5.txt"))
    assert a.kind == "hash"
    assert any(mode == 0 for _, mode, _ in a.hash_candidates)


def test_real_sha256_detected(c4, corpus):
    d, _ = corpus
    a = c4.Analyzer.run(os.path.join(d, "hash_sha256.txt"))
    assert a.kind == "hash"
    assert any(mode == 1400 for _, mode, _ in a.hash_candidates)


def test_real_sha512crypt_detected(c4, corpus):
    d, _ = corpus
    p = os.path.join(d, "hash_sha512crypt.txt")
    if not os.path.exists(p):
        pytest.skip("sha512crypt not built")
    a = c4.Analyzer.run(p)
    assert a.kind == "hash"
    # $6$ prefix -> mode 1800
    assert any(mode == 1800 for _, mode, _ in a.hash_candidates)


# --------------------------------------------------------------------------- #
#  2. Decoder recovers a known flag
# --------------------------------------------------------------------------- #
def test_decoder_recovers_known_flag(c4, corpus):
    d, man = corpus
    enc = Path(d, "pico_flag.txt").read_text().strip()
    res = c4.Decoder.magic(enc, depth=3)
    joined = " ".join(r[1] for r in res)
    assert "picoCTF{base64_decoded}" in joined


# --------------------------------------------------------------------------- #
#  3. Image scanner finds hidden appended data
# --------------------------------------------------------------------------- #
def test_image_scan_finds_hidden_zip(c4, corpus):
    d, man = corpus
    if "stego.jpg" not in man:
        pytest.skip("stego image not built")
    logs = []
    c4.Analyzer.image_scan(os.path.join(d, "stego.jpg"), logs.append)
    out = "".join(logs)
    assert "AFTER image EOF" in out
    assert "ZIP" in out


# --------------------------------------------------------------------------- #
#  4. FULL crack (only if the real tools exist) — otherwise skip
# --------------------------------------------------------------------------- #
def _have(binary):
    return shutil.which(binary) is not None


def test_full_zip_crack_if_tools_present(c4, corpus):
    d, man = corpus
    if "secret.zip" not in man:
        pytest.skip("zip not built")
    if not (_have("john") or _have("zip2john")):
        pytest.skip("john/zip2john not installed in this environment")
    # zip2john -> john with a tiny wordlist containing the known password
    wl = os.path.join(d, "wl.txt")
    Path(wl).write_text("password\n123456\n" + PW + "\nqwerty\n")
    hashfile = os.path.join(d, "zip.hash")
    z2j = shutil.which("zip2john") or "zip2john"
    with open(hashfile, "w") as fo:
        subprocess.run([z2j, os.path.join(d, "secret.zip")], stdout=fo, check=True)
    subprocess.run(["john", f"--wordlist={wl}", hashfile], check=True,
                   capture_output=True, timeout=120)
    show = subprocess.run(["john", "--show", hashfile], capture_output=True, text=True)
    assert PW in show.stdout


def test_full_md5_crack_if_hashcat_present(c4, corpus):
    d, _ = corpus
    if not _have("hashcat"):
        pytest.skip("hashcat not installed in this environment")
    wl = os.path.join(d, "wl.txt")
    Path(wl).write_text("password\n123456\n" + PW + "\nqwerty\n")
    hashfile = os.path.join(d, "hash_md5.txt")
    pot = os.path.join(d, "hc.pot")
    subprocess.run(["hashcat", "-m", "0", "-a", "0", hashfile, wl,
                    "--potfile-path", pot, "--quiet"], capture_output=True, timeout=120)
    show = subprocess.run(["hashcat", "-m", "0", hashfile, "--show",
                           "--potfile-path", pot], capture_output=True, text=True)
    assert PW in show.stdout


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
