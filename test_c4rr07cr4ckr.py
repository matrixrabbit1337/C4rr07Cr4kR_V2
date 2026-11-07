"""
Test suite for C4rr07CR4cKR.

Run:  pip install pytest --break-system-packages && pytest -q test_c4rr07cr4ckr.py

These tests exercise the pure logic (detection, decoding, scope enforcement,
audit-chain integrity, config validation, keyspace estimation) without needing
a display, hashcat, or a live network target.
"""
import base64
import codecs
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

_HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("c4rr07cr4ckr", _HERE / "c4rr07cr4ckr.py")
c4 = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(c4)


# --------------------------------------------------------------------------- #
#  Hash identification                                                         #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("h,expect_label", [
    ("5f4dcc3b5aa765d61d8327deb882cf99", "MD5"),
    ("$6$abc$def", "sha512crypt"),
    ("$2a$12$abcdefghijklmnopqrstuv", "bcrypt"),
    ("356a192b7913b04c54574d18c28d46e6395428ab", "SHA1"),
    ("$1$abc$def", "md5crypt"),
])
def test_hashid_identify(h, expect_label):
    cands = c4.HashID.identify(h)
    labels = [c[0] for c in cands]
    assert expect_label in labels


def test_hashid_unknown_falls_back():
    cands = c4.HashID.identify("not-a-hash-at-all-!!!")
    assert cands and cands[0][0].startswith("unknown")


# --------------------------------------------------------------------------- #
#  File analyzer / auto-routing                                                #
# --------------------------------------------------------------------------- #
def test_analyzer_hash_file(tmp_path):
    f = tmp_path / "hashes.txt"
    f.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n")
    a = c4.Analyzer.run(str(f))
    assert a.kind == "hash"
    assert a.suggested_engine == "hashcat"
    assert a.suggested_mode == 0


def test_analyzer_zip(tmp_path):
    f = tmp_path / "x.zip"
    f.write_bytes(b"PK\x03\x04" + b"\x00" * 40)
    a = c4.Analyzer.run(str(f))
    assert a.kind == "zip"
    assert a.prep_helper == "zip2john"
    assert a.suggested_engine == "john"


def test_analyzer_pcap(tmp_path):
    f = tmp_path / "cap.pcap"
    f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)
    a = c4.Analyzer.run(str(f))
    assert a.kind == "pcap"
    assert a.suggested_engine == "hcxtools"
    assert a.suggested_mode == 22000


def test_analyzer_luks(tmp_path):
    f = tmp_path / "vol.luks"
    f.write_bytes(b"LUKS\xba\xbe" + b"\x00" * 100)
    a = c4.Analyzer.run(str(f))
    assert a.kind == "luks"
    assert a.prep_helper == "luks2john"
    assert a.suggested_mode == 14600


def test_analyzer_bitlocker(tmp_path):
    f = tmp_path / "disk.img"
    f.write_bytes(b"\xeb\x58\x90-FVE-FS-" + b"\x00" * 100)
    a = c4.Analyzer.run(str(f))
    assert a.kind == "bitlocker"
    assert a.prep_helper == "bitlocker2john"


def test_analyzer_missing_file():
    a = c4.Analyzer.run("/definitely/not/a/real/path")
    assert "not found" in a.detail


# --------------------------------------------------------------------------- #
#  Encoding pre-pass (Decoder)                                                 #
# --------------------------------------------------------------------------- #
def test_decoder_single_layer_base64_flag():
    enc = base64.b64encode(b"flag{sunshine}").decode()
    res = c4.Decoder.magic(enc, depth=3)
    assert res, "expected at least one decode candidate"
    assert res[0][3] is True  # flagged
    assert "flag{sunshine}" in res[0][1]


def test_decoder_double_layer_rot13_base64():
    enc = base64.b64encode(b"flag{layered}").decode()
    double = codecs.encode(enc, "rot_13")
    res = c4.Decoder.magic(double, depth=4)
    assert any("flag{layered}" in txt for _, txt, _, _ in res)


def test_decoder_no_result_on_real_hash():
    # a genuine random-looking hex hash shouldn't decode to clean printable text
    res = c4.Decoder.magic("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", depth=2)
    for _, txt, _, flagged in res:
        assert not flagged


# --------------------------------------------------------------------------- #
#  Keyspace / ETA estimator                                                    #
# --------------------------------------------------------------------------- #
def test_estimator_mask_keyspace():
    ks = c4.Estimator.mask_keyspace("?d?d?d?d")
    assert ks == 10 ** 4


def test_estimator_verdict_infeasible_for_bcrypt_brute():
    est = c4.Estimator.estimate(3200, 3, mask="?a?a?a?a?a?a?a?a")
    assert "INFEASIBLE" in est["verdict"]


def test_estimator_verdict_fast_for_short_pin_on_fast_hash():
    est = c4.Estimator.estimate(0, 3, mask="?d?d?d?d")
    assert "FAST" in est["verdict"]


def test_estimator_wordlist_keyspace(tmp_path):
    wl = tmp_path / "wl.txt"
    wl.write_text("\n".join(str(i) for i in range(1000)))
    est = c4.Estimator.estimate(0, 0, wordlist=str(wl))
    assert est["keyspace"] == 1000


# --------------------------------------------------------------------------- #
#  Scope / rules-of-engagement enforcement                                     #
# --------------------------------------------------------------------------- #
def test_scope_cidr_and_hostname(tmp_path):
    f = tmp_path / "scope.yaml"
    f.write_text(
        "engagement: \"test\"\n"
        "targets:\n"
        "  - 10.10.10.0/24\n"
        "  - ctf.example.com\n"
        "allow_online: false\n"
        "allow_offline: true\n"
    )
    sc = c4.Scope.load(f)
    assert sc.engagement == "test"
    assert sc.target_ok("10.10.10.5") is True
    assert sc.target_ok("8.8.8.8") is False
    assert sc.allow_online is False
    assert sc.allow_offline is True


def test_scope_expiry(tmp_path):
    f = tmp_path / "scope.yaml"
    f.write_text("engagement: \"expired\"\ntargets:\n  - 1.2.3.4\nexpires: \"2000-01-01T00:00:00\"\n")
    sc = c4.Scope.load(f)
    assert sc.expired() is True
    assert sc.target_ok("1.2.3.4") is False  # expired -> deny even in-scope hosts


def test_host_in_scope_empty_scope_allows():
    assert c4.host_in_scope("anything", []) is True


# --------------------------------------------------------------------------- #
#  Tamper-evident audit log                                                    #
# --------------------------------------------------------------------------- #
def test_audit_log_chain_verifies_clean(tmp_path):
    log = c4.AuditLog(tmp_path / "audit.jsonl")
    log.append("event_a", x=1)
    log.append("event_b", y=2)
    ok, n = log.verify()
    assert ok is True
    assert n == 2


def test_audit_log_detects_tampering(tmp_path):
    p = tmp_path / "audit.jsonl"
    log = c4.AuditLog(p)
    log.append("event_a", x=1)
    log.append("event_b", y=2)
    log.append("event_c", z=3)

    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["data"]["y"] = 999999  # tamper with the middle record
    lines[1] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")

    ok, n = log.verify()
    assert ok is False
    assert n == 1  # breaks starting at the 2nd record (index 1)


def test_audit_log_empty_is_valid(tmp_path):
    log = c4.AuditLog(tmp_path / "does_not_exist_yet.jsonl")
    ok, n = log.verify()
    assert ok is True
    assert n == 0


def test_audit_log_detects_reordering(tmp_path):
    """Swapping record order should break the hash chain even with no field edits."""
    p = tmp_path / "audit.jsonl"
    log = c4.AuditLog(p)
    log.append("event_a", x=1)
    log.append("event_b", y=2)
    lines = p.read_text().splitlines()
    lines.reverse()
    p.write_text("\n".join(lines) + "\n")
    ok, n = log.verify()
    assert ok is False


# --------------------------------------------------------------------------- #
#  Chain-of-custody hashing                                                    #
# --------------------------------------------------------------------------- #
def test_sha256_file(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"hello world")
    import hashlib
    expect = hashlib.sha256(b"hello world").hexdigest()
    assert c4.sha256_file(str(f)) == expect


def test_sha256_file_missing_returns_none():
    assert c4.sha256_file("/no/such/file") is None


# --------------------------------------------------------------------------- #
#  Signed reporting                                                            #
# --------------------------------------------------------------------------- #
def test_reporter_writes_manifest(tmp_path):
    e = c4.Engine(lambda m: None)
    e._note("cmd", "hashcat -m 0 x rockyou")
    e.last_cracked = ["hunter2"]
    e._emit_result()
    out = tmp_path / "report.md"
    audit = c4.AuditLog(tmp_path / "audit.jsonl")
    digest, sig = c4.Reporter.write(e, str(out), audit=audit, gpg_key=None)
    assert out.exists()
    manifest = Path(str(out) + ".sha256")
    assert manifest.exists()
    assert digest in manifest.read_text()
    assert sig is None  # no gpg key supplied


# --------------------------------------------------------------------------- #
#  Config: schema validation / self-repair                                     #
# --------------------------------------------------------------------------- #
def test_config_validate_repairs_bad_color():
    cfg = c4.Config()
    cfg.data["colors"]["carrot"] = "not-a-color"
    warnings = cfg.validate()
    assert any("carrot" in w for w in warnings)
    assert cfg.data["colors"]["carrot"] == c4.DEFAULT_CFG["colors"]["carrot"]


def test_config_validate_restores_missing_section():
    cfg = c4.Config()
    del cfg.data["resource"]
    cfg.validate()
    assert "resource" in cfg.data
    assert cfg.data["resource"]["temp_abort"] == c4.DEFAULT_CFG["resource"]["temp_abort"]


def test_config_font_scaling():
    cfg = c4.Config()
    cfg.data["font_scale"] = 2.0
    fam, size, weight = cfg.font(10, "bold")
    assert size == 20
    assert weight == "bold"


# --------------------------------------------------------------------------- #
#  Rules / masks discovery                                                     #
# --------------------------------------------------------------------------- #
def test_common_masks_nonempty():
    assert len(c4.COMMON_MASKS) > 0
    for m in c4.COMMON_MASKS:
        assert "?" in m


def test_find_rules_returns_list():
    # environment may have zero rule files; just check the call is safe & typed
    rules = c4.find_rules()
    assert isinstance(rules, list)


# --------------------------------------------------------------------------- #
#  Hydra: authorization gate must block by default                            #
# --------------------------------------------------------------------------- #
def test_hydra_refuses_without_authorization():
    h = c4.Hydra(lambda m: None)
    result = h.run("10.0.0.5", "ssh", user="admin", password="admin", authorized=False)
    assert result is False


def test_hydra_refuses_out_of_scope_even_if_authorized():
    h = c4.Hydra(lambda m: None)
    result = h.run("8.8.8.8", "ssh", user="admin", password="admin",
                    authorized=True, scope=["10.0.0.0/24"])
    assert result is False


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


def test_crunch_estimate_digits():
    lines, nbytes = c4.Crunch.estimate(4, 4, 10, None)
    assert lines == 10 ** 4


def test_crunch_builtin_generator(tmp_path):
    out = tmp_path / "wl.txt"
    c4.Crunch.build(str(out), 1, 2, "ab", None, lambda m: None)
    got = out.read_text().split()
    assert "a" in got and "ab" in got and "bb" in got and len(got) == 6


def test_crunch_human_size():
    assert "KB" in c4.Crunch.human_size(2048)


def test_analyzer_putty_key(tmp_path):
    p = tmp_path / "id.ppk"
    p.write_bytes(b"PuTTY-User-Key-File-2: ssh-rsa\n")
    a = c4.Analyzer.run(str(p))
    assert a.kind == "putty"


def test_image_scan_finds_appended_zip(tmp_path):
    p = tmp_path / "pic.jpg"
    p.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 40 + b"\xff\xd9" + b"PK\x03\x04hidden")
    logs = []
    c4.Analyzer.image_scan(str(p), logs.append)
    assert any("AFTER image EOF" in l for l in logs)


def test_wordlist_catalog_shape():
    for name, (url, desc) in c4.WordlistManager.CATALOG.items():
        assert url.startswith("https://raw.githubusercontent.com/")
        assert isinstance(desc, str) and len(desc) > 5


def test_wordlist_status_returns_rows():
    rows = c4.WordlistManager.status()
    assert len(rows) == len(c4.WordlistManager.CATALOG)
    for name, have, size, desc in rows:
        assert isinstance(have, bool)
