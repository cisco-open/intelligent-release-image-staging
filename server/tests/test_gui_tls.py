# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the console TLS certificate override (server/gui_tls.py).

Hermetic and offline: throwaway cert/key pairs come from the openssl CLI
(the test_artifact_server idiom); the age binary is the test_secretfs
fake-age shell script (encrypt = prepend an AGEFAKE header, decrypt = strip
it / exit 1 on a bad header), injected via IRIS_AGE_BIN. Every path is
pointed at tmp_path via IRIS_CONFIG / IRIS_GUI_CERT / IRIS_CERT."""
import os
import stat
import subprocess

import pytest

import gui_tls
import secretfs
import trust

FAKE_AGE = r'''#!/usr/bin/env bash
# fake age: encrypt = prepend a header; decrypt = strip it.
set -euo pipefail
mode="$1"; shift
out=""; inp=""
if [ "$mode" = "-d" ]; then
  # -d -i KEYFILE -o OUTFILE ENCFILE
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -i) shift 2 ;;
      -o) out="$2"; shift 2 ;;
      *) inp="$1"; shift ;;
    esac
  done
  # fail closed if header missing (mimics a bad key / bad ciphertext)
  head -n1 "$inp" | grep -q '^AGEFAKE$' || { echo "age: bad ciphertext" >&2; exit 1; }
  tail -n +2 "$inp" > "$out"
else
  # -r REC [-r REC ...] -o ENCFILE PLAINFILE
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -r) shift 2 ;;
      -o) out="$2"; shift 2 ;;
      *) inp="$1"; shift ;;
    esac
  done
  { echo "AGEFAKE"; cat "$inp"; } > "$out"
fi
'''


def _gen_pair(dirpath, cn):
    """Throwaway self-signed cert+key PEM strings via the openssl CLI (house
    style: small helpers are duplicated per test file)."""
    crt = os.path.join(str(dirpath), cn + "-crt.pem")
    key = os.path.join(str(dirpath), cn + "-key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "2", "-keyout", key, "-out", crt, "-subj", "/CN=" + cn],
        check=True, capture_output=True)
    with open(crt) as f:
        cert_pem = f.read()
    with open(key) as f:
        key_pem = f.read()
    return cert_pem, key_pem


@pytest.fixture
def tls_env(tmp_path, monkeypatch):
    """Point every gui_tls path at tmp_path; no age recipients by default
    (the secretfs plaintext degradation). Returns (config_tls_dir, run_dir)
    as str paths. The built-in IRIS_CERT points at run/cert.pem, which does
    NOT exist unless a test creates it."""
    cfg = tmp_path / "config"
    run = tmp_path / "run" / "tls"
    run.mkdir(parents=True)
    monkeypatch.setenv("IRIS_CONFIG", str(cfg))
    monkeypatch.setenv("IRIS_GUI_CERT", str(run / "gui-cert.pem"))
    monkeypatch.setenv("IRIS_CERT", str(run / "cert.pem"))
    monkeypatch.delenv("IRIS_AGE_RECIPIENTS", raising=False)
    monkeypatch.delenv("IRIS_AGE_BIN", raising=False)
    return str(cfg / "tls"), str(run)


@pytest.fixture
def fake_age(tmp_path, monkeypatch):
    """Enable at-rest encryption for a test: fake-age binary + a recipient."""
    p = tmp_path / "fake-age"
    p.write_text(FAKE_AGE)
    p.chmod(0o755)
    monkeypatch.setenv("IRIS_AGE_BIN", str(p))
    monkeypatch.setenv("IRIS_AGE_RECIPIENTS", "age1fakerecipient")
    return str(p)


# --- combined_path + validate_pair ------------------------------------------

def test_combined_path_env_and_default(monkeypatch):
    monkeypatch.delenv("IRIS_GUI_CERT", raising=False)
    assert gui_tls.combined_path() == "/run/iris/tls/gui-cert.pem"
    monkeypatch.setenv("IRIS_GUI_CERT", "/somewhere/else/gui.pem")
    assert gui_tls.combined_path() == "/somewhere/else/gui.pem"


def test_validate_pair_ok(tls_env, tmp_path):
    cert_pem, key_pem = _gen_pair(tmp_path, "okpair")
    assert gui_tls.validate_pair(cert_pem, key_pem) is None


def test_validate_pair_ok_fullchain(tls_env, tmp_path):
    # leaf + an extra cert appended (intermediates allowed per spec A1):
    # load_cert_chain takes cert #1 as the leaf, the rest as chain extras
    cert_pem, key_pem = _gen_pair(tmp_path, "fullleaf")
    extra_cert, _ = _gen_pair(tmp_path, "fullextra")
    assert gui_tls.validate_pair(cert_pem + extra_cert, key_pem) is None


def test_validate_pair_mismatched_key_message_is_safe(tls_env, tmp_path):
    cert_pem, _ = _gen_pair(tmp_path, "certside")
    _, other_key = _gen_pair(tmp_path, "keyside")
    err = gui_tls.validate_pair(cert_pem, other_key)
    assert err is not None
    # the message must NEVER echo PEM/key material
    key_line = [ln for ln in other_key.splitlines()
                if ln and "-----" not in ln][0]
    assert key_line not in err
    assert "BEGIN" not in err


def _encrypt_key(dirpath, key_pem, passphrase):
    """Passphrase-protect a key PEM via the openssl CLI (PKCS#8 PBES2)."""
    src = os.path.join(str(dirpath), "clear-key.pem")
    dst = os.path.join(str(dirpath), "enc-key.pem")
    with open(src, "w") as f:
        f.write(key_pem)
    subprocess.run(
        ["openssl", "pkey", "-in", src, "-aes-256-cbc",
         "-passout", "pass:" + passphrase, "-out", dst],
        check=True, capture_output=True)
    with open(dst) as f:
        return f.read()


def test_decrypt_key_pem_right_passphrase_roundtrips(tls_env, tmp_path):
    cert_pem, key_pem = _gen_pair(tmp_path, "decpair")
    enc = _encrypt_key(tmp_path, key_pem, "sw0rdfish")
    clear, err = gui_tls.decrypt_key_pem(enc, "sw0rdfish")
    assert err is None
    assert "PRIVATE KEY" in clear and "ENCRYPTED" not in clear
    # the decrypted key must pair with the original cert
    assert gui_tls.validate_pair(cert_pem, clear) is None


def test_decrypt_key_pem_wrong_passphrase_says_so(tls_env, tmp_path):
    _, key_pem = _gen_pair(tmp_path, "wrongpass")
    enc = _encrypt_key(tmp_path, key_pem, "right")
    clear, err = gui_tls.decrypt_key_pem(enc, "wrong")
    assert clear is None
    assert err is not None and "passphrase" in err
    assert "BEGIN" not in err          # never echo PEM material


def test_decrypt_key_pem_unencrypted_passthrough(tls_env, tmp_path):
    _, key_pem = _gen_pair(tmp_path, "plainpass")
    clear, err = gui_tls.decrypt_key_pem(key_pem, "ignored")
    assert err is None and clear == key_pem


def test_validate_pair_encrypted_key_names_the_problem(tls_env, tmp_path):
    """A passphrase-protected key can never load (no way to prompt); the
    message must say so specifically — the generic '(OSError)' fallback sent
    an operator hunting a cert problem that was really a key passphrase.
    Covers both encodings: PKCS#8 'ENCRYPTED PRIVATE KEY' and legacy PEM
    'Proc-Type: 4,ENCRYPTED' headers."""
    cert_pem, _ = _gen_pair(tmp_path, "encpair")
    pkcs8 = ("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
             "MIIFDjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQI\n"
             "-----END ENCRYPTED PRIVATE KEY-----\n")
    legacy = ("-----BEGIN RSA PRIVATE KEY-----\n"
              "Proc-Type: 4,ENCRYPTED\n"
              "DEK-Info: AES-256-CBC,ABCDEF0123456789\n"
              "\nMIIEo\n"
              "-----END RSA PRIVATE KEY-----\n")
    for enc_key in (pkcs8, legacy):
        err = gui_tls.validate_pair(cert_pem, enc_key)
        assert err is not None
        assert "passphrase" in err
        assert "OSError" not in err
        assert "BEGIN" not in err   # never echo PEM material


def test_validate_pair_garbage_cert(tls_env, tmp_path):
    _, key_pem = _gen_pair(tmp_path, "goodkey")
    err = gui_tls.validate_pair(
        "-----BEGIN CERTIFICATE-----\nnot base64 at all\n"
        "-----END CERTIFICATE-----\n", key_pem)
    assert err is not None


def test_validate_pair_truncated_key(tls_env, tmp_path):
    cert_pem, key_pem = _gen_pair(tmp_path, "truncpair")
    err = gui_tls.validate_pair(cert_pem, key_pem[: len(key_pem) // 3])
    assert err is not None


def test_validate_pair_missing_inputs(tls_env, tmp_path):
    cert_pem, key_pem = _gen_pair(tmp_path, "misspair")
    assert gui_tls.validate_pair("", key_pem) is not None
    assert gui_tls.validate_pair(cert_pem, "") is not None
    assert gui_tls.validate_pair(None, key_pem) is not None
    assert gui_tls.validate_pair(cert_pem, None) is not None
    assert gui_tls.validate_pair("   \n", key_pem) is not None


def test_validate_pair_leaves_no_temp_files(tls_env, tmp_path):
    cfg, run = tls_env
    cert_pem, key_pem = _gen_pair(tmp_path, "cleanpair")
    gui_tls.validate_pair(cert_pem, key_pem)          # ok path
    gui_tls.validate_pair(cert_pem, "garbage")        # error path
    assert os.listdir(run) == []   # no droppings in the runtime dir


# --- persist_override / override_active / remove_override -------------------

def test_persist_no_recipients_writes_runtime_only(tls_env, tmp_path):
    cfg, run = tls_env
    cert_pem, key_pem = _gen_pair(tmp_path, "plaincase")
    assert gui_tls.override_active() is False
    gui_tls.persist_override(cert_pem, key_pem)
    assert gui_tls.override_active() is True
    combined = gui_tls.combined_path()
    with open(combined) as f:
        body = f.read()
    # cert(+chain) first, then the key — the shape load_cert_chain and the
    # boot rebuild (cat crt + key) both expect
    assert body.index("BEGIN CERTIFICATE") < body.index("PRIVATE KEY")
    assert stat.S_IMODE(os.stat(combined).st_mode) == 0o600
    # no recipients -> at-rest encryption disabled -> NO durable copy at all
    # (mirrors secretfs.persist_store's no-recipient degradation; a plaintext
    # key must never land on the config volume)
    assert not os.path.exists(os.path.join(cfg, "gui-crt.pem"))
    assert not os.path.exists(os.path.join(cfg, "gui-key.pem.age"))


def test_persist_with_recipients_durable_pair_and_boot_compat(
        tls_env, fake_age, tmp_path):
    cfg, run = tls_env
    cert_pem, key_pem = _gen_pair(tmp_path, "agecase")
    gui_tls.persist_override(cert_pem, key_pem)
    crt = os.path.join(cfg, "gui-crt.pem")
    enc = os.path.join(cfg, "gui-key.pem.age")
    assert os.path.isfile(crt) and os.path.isfile(enc)
    # at rest, the persistent key copy is ciphertext (fake-age header), and
    # the durable crt is the public cert
    with open(enc) as f:
        assert f.read().startswith("AGEFAKE\n")
    with open(crt) as f:
        assert "BEGIN CERTIFICATE" in f.read()
    # boot compatibility (plan-part-7): cat gui-crt.pem + age-decrypted key
    # must reproduce the runtime combined file byte-for-byte
    keyfile = os.path.join(str(tmp_path), "agekey")
    with open(keyfile, "w") as f:
        f.write("AGE-SECRET-KEY-FAKE\n")
    back = os.path.join(str(tmp_path), "key-back.pem")
    subprocess.run([fake_age, "-d", "-i", keyfile, "-o", back, enc],
                   check=True)
    with open(crt) as f:
        rebuilt = f.read()
    with open(back) as f:
        rebuilt += f.read()
    with open(gui_tls.combined_path()) as f:
        assert f.read() == rebuilt
    assert stat.S_IMODE(os.stat(gui_tls.combined_path()).st_mode) == 0o600


def test_persist_rolls_back_when_durable_encrypt_fails(
        tls_env, fake_age, tmp_path, monkeypatch):
    """Durable-FIRST: if the age encrypt raises, NOTHING changes — durable
    pair and runtime file all still hold the previous override."""
    cfg, run = tls_env
    old_cert, old_key = _gen_pair(tmp_path, "oldpair")
    gui_tls.persist_override(old_cert, old_key)
    with open(gui_tls.combined_path()) as f:
        combined_before = f.read()
    with open(os.path.join(cfg, "gui-key.pem.age")) as f:
        enc_before = f.read()
    with open(os.path.join(cfg, "gui-crt.pem")) as f:
        crt_before = f.read()

    def boom(*a, **k):
        raise RuntimeError("age exploded before any durable write")

    monkeypatch.setattr(secretfs, "encrypt_from", boom)
    new_cert, new_key = _gen_pair(tmp_path, "newpair")
    with pytest.raises(RuntimeError):
        gui_tls.persist_override(new_cert, new_key)
    with open(gui_tls.combined_path()) as f:
        assert f.read() == combined_before
    with open(os.path.join(cfg, "gui-key.pem.age")) as f:
        assert f.read() == enc_before
    with open(os.path.join(cfg, "gui-crt.pem")) as f:
        assert f.read() == crt_before


def test_persist_rolls_back_durable_pair_when_runtime_commit_fails(
        tls_env, fake_age, tmp_path, monkeypatch):
    """The persist_store invariant, mirrored: the durable pair must never be
    AHEAD of the runtime file. If the final combined-file commit fails, the
    durable pair is rolled back to the previous upload, so a restart's boot
    rebuild reproduces the PREVIOUS override — not the failed one."""
    cfg, run = tls_env
    old_cert, old_key = _gen_pair(tmp_path, "oldpair2")
    gui_tls.persist_override(old_cert, old_key)
    combined = gui_tls.combined_path()
    with open(combined) as f:
        combined_before = f.read()
    with open(os.path.join(cfg, "gui-key.pem.age")) as f:
        enc_before = f.read()
    with open(os.path.join(cfg, "gui-crt.pem")) as f:
        crt_before = f.read()

    real_replace = os.replace
    calls = {"n": 0}

    def flaky_replace(src, dst):
        # fail ONLY the runtime-combined commit; durable writes and the
        # rollback restores pass through
        if str(dst) == combined:
            calls["n"] += 1
            raise OSError("ENOSPC: no space to commit the runtime file")
        return real_replace(src, dst)

    monkeypatch.setattr(gui_tls.os, "replace", flaky_replace)
    new_cert, new_key = _gen_pair(tmp_path, "newpair2")
    with pytest.raises(OSError):
        gui_tls.persist_override(new_cert, new_key)
    assert calls["n"] == 1, "the runtime commit replace was not exercised"
    monkeypatch.setattr(gui_tls.os, "replace", real_replace)
    with open(combined) as f:
        assert f.read() == combined_before
    with open(os.path.join(cfg, "gui-crt.pem")) as f:
        assert f.read() == crt_before
    with open(os.path.join(cfg, "gui-key.pem.age")) as f:
        assert f.read() == enc_before


def test_remove_override_removes_all_three_and_is_idempotent(
        tls_env, fake_age, tmp_path):
    cfg, run = tls_env
    cert_pem, key_pem = _gen_pair(tmp_path, "rmcase")
    gui_tls.persist_override(cert_pem, key_pem)
    assert gui_tls.override_active() is True
    gui_tls.remove_override()
    assert gui_tls.override_active() is False
    assert not os.path.exists(os.path.join(cfg, "gui-crt.pem"))
    assert not os.path.exists(os.path.join(cfg, "gui-key.pem.age"))
    assert not os.path.exists(gui_tls.combined_path())
    gui_tls.remove_override()   # second call: no-op, must not raise


# --- active_info -------------------------------------------------------------

def test_active_info_none_and_no_openssl_subprocess(tls_env, monkeypatch):
    """Neither the IRIS_GUI_CERT nor the IRIS_CERT file exists: source is
    "none" and NO openssl subprocess is spawned — active_info runs on every
    GET /api/settings, including cert-less pytest servers."""
    def boom(*a, **k):
        raise AssertionError(
            "openssl must not be invoked when no cert file exists")

    monkeypatch.setattr(trust.subprocess, "run", boom)
    info = gui_tls.active_info()
    assert info == {"source": "none", "subject": "unknown",
                    "issuer": "unknown", "not_after": "unknown",
                    "fingerprint_sha256": "unknown"}


def test_active_info_builtin(tls_env, tmp_path):
    cfg, run = tls_env
    cert_pem, key_pem = _gen_pair(tmp_path, "builtincase")
    with open(os.path.join(run, "cert.pem"), "w") as f:
        f.write(cert_pem + key_pem)     # the entrypoint's combined shape
    info = gui_tls.active_info()
    assert info["source"] == "built-in"
    assert "builtincase" in info["subject"]
    assert "builtincase" in info["issuer"]      # self-signed
    assert info["not_after"] != "unknown"
    assert info["fingerprint_sha256"] not in ("", "unknown")


def test_active_info_custom_wins_and_fingerprint_matches_trust(
        tls_env, tmp_path):
    cfg, run = tls_env
    # a built-in file ALSO exists — the override must win
    shadow_cert, shadow_key = _gen_pair(tmp_path, "shadowbuiltin")
    with open(os.path.join(run, "cert.pem"), "w") as f:
        f.write(shadow_cert + shadow_key)
    cert_pem, key_pem = _gen_pair(tmp_path, "customcase")
    gui_tls.persist_override(cert_pem, key_pem)
    info = gui_tls.active_info()
    assert info["source"] == "custom"
    assert "customcase" in info["subject"]
    assert "shadowbuiltin" not in info["subject"]
    # byte-identical normalization with trust.cert_info: the console cert
    # block and the trust-store table must agree on fingerprints
    block = trust.split_pem_certs(cert_pem)[0]
    assert (info["fingerprint_sha256"]
            == trust.cert_info(block)["fingerprint_sha256"])
    assert len(info["fingerprint_sha256"]) == 64
    # and it matches the openssl CLI's own -sha256 fingerprint
    crt_file = os.path.join(str(tmp_path), "customcase-crt.pem")
    out = subprocess.run(
        ["openssl", "x509", "-noout", "-fingerprint", "-sha256",
         "-in", crt_file], check=True, capture_output=True).stdout.decode()
    expected = out.split("=", 1)[1].strip().replace(":", "").lower()
    assert info["fingerprint_sha256"] == expected


def test_active_info_fullchain_first_cert_wins(tls_env, tmp_path):
    cfg, run = tls_env
    leaf_cert, leaf_key = _gen_pair(tmp_path, "fcleaf")
    extra_cert, _ = _gen_pair(tmp_path, "fcintermediate")
    gui_tls.persist_override(leaf_cert + extra_cert, leaf_key)
    info = gui_tls.active_info()
    assert info["source"] == "custom"
    assert "fcleaf" in info["subject"]
    assert "fcintermediate" not in info["subject"]


def test_active_info_never_raises_on_garbage_file(tls_env):
    cfg, run = tls_env
    with open(os.path.join(run, "cert.pem"), "w") as f:
        f.write("total garbage, no PEM here")
    info = gui_tls.active_info()
    assert info["source"] == "built-in"     # the file exists, so it IS serving
    assert info["subject"] == "unknown"
    assert info["issuer"] == "unknown"
    assert info["not_after"] == "unknown"
    assert info["fingerprint_sha256"] == "unknown"
