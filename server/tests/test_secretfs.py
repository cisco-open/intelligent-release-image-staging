# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the at-rest encryption layer (server/secretfs.py).

The real `age` binary is not required: a tiny fake-age shell script that
mimics the two invocations secretfs makes (`-d -i KEY -o OUT ENC` to
decrypt, `-r REC ... -o ENC PLAIN` to encrypt) is injected via the
`age_bin` argument. The fake's "ciphertext" is just the plaintext with a
fixed header line so a test can assert the persistent copy is NOT plaintext.
"""
import errno
import os
import stat
import subprocess

import pytest

import secretfs

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


@pytest.fixture
def fake_age(tmp_path):
    p = tmp_path / "fake-age"
    p.write_text(FAKE_AGE)
    p.chmod(0o755)
    return str(p)


def test_decrypt_to_writes_plaintext(tmp_path, fake_age):
    enc = tmp_path / "secrets.json.age"
    enc.write_text("AGEFAKE\n{\"hello\": 1}\n")
    key = tmp_path / "key"
    key.write_text("AGE-SECRET-KEY-FAKE\n")
    out = tmp_path / "run" / "secrets.json"

    secretfs.decrypt_to(str(enc), str(out), str(key), age_bin=fake_age)

    assert out.read_text() == "{\"hello\": 1}\n"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_encrypt_from_persistent_copy_is_ciphertext(tmp_path, fake_age):
    plain = tmp_path / "run" / "secrets.json"
    plain.parent.mkdir()
    plain.write_text("{\"devices\": {}}\n")
    enc = tmp_path / "secrets.json.age"

    secretfs.encrypt_from(
        str(plain), str(enc),
        "age1primaryrecipient,age1breakglass",
        age_bin=fake_age,
    )

    body = enc.read_text()
    # persistent copy is NOT plaintext (carries the fake-age header)
    assert body.startswith("AGEFAKE\n")
    assert "{\"devices\": {}}" in body


def test_round_trip(tmp_path, fake_age):
    orig = tmp_path / "run" / "secrets.json"
    orig.parent.mkdir()
    orig.write_text("{\"devices\": {\"100.92.9.3\": {}}}\n")
    enc = tmp_path / "secrets.json.age"
    key = tmp_path / "key"
    key.write_text("AGE-SECRET-KEY-FAKE\n")

    secretfs.encrypt_from(str(orig), str(enc), "age1rec", age_bin=fake_age)
    back = tmp_path / "run2" / "secrets.json"
    secretfs.decrypt_to(str(enc), str(back), str(key), age_bin=fake_age)

    assert back.read_text() == orig.read_text()


def test_persist_store_durable_first_leaves_old_on_encrypt_failure(
        tmp_path, fake_age, monkeypatch):
    """If the durable encrypt fails, the live plaintext is left untouched and
    no durable copy is written — the encrypt_from-raises branch."""
    plain = tmp_path / "run" / "secrets.json"
    plain.parent.mkdir()
    plain.write_text("{\"devices\": {\"old\": 1}}")
    enc = tmp_path / "secrets.json.age"

    def boom(*a, **k):
        raise RuntimeError("age exploded before any durable write")

    monkeypatch.setattr(secretfs, "encrypt_from", boom)
    with pytest.raises(RuntimeError):
        secretfs.persist_store(
            {"devices": {"new": 2}}, str(plain),
            recipients_csv="age1rec", enc_path=str(enc), age_bin=fake_age)

    # Live plaintext is untouched and no durable ciphertext was written.
    assert "old" in plain.read_text()
    assert not enc.exists()


def test_persist_store_rolls_durable_back_when_replace_fails(
        tmp_path, fake_age, monkeypatch):
    """The durable-first guarantee must hold even when os.replace fails AFTER a
    successful encrypt: enc_path must NOT be left ahead of the (untouched) live
    plain_path, or a restart would silently materialise the failed rotation.

    The fix re-encrypts the old live plaintext back over enc_path, so both
    copies still decrypt to the OLD store and a restart loses nothing."""
    plain = tmp_path / "run" / "secrets.json"
    plain.parent.mkdir()
    plain.write_text("{\"devices\": {\"old\": 1}}")
    enc = tmp_path / "secrets.json.age"
    # Seed a durable copy of the OLD store (as a real deployment would have).
    secretfs.encrypt_from(str(plain), str(enc), "age1rec", age_bin=fake_age)

    real_replace = os.replace
    calls = {"n": 0}

    def flaky_replace(src, dst):
        # Fail ONLY the commit of the new plaintext over the live store
        # (the temp -> plain_path swap), not the encrypt_from temp -> enc swaps.
        if str(dst) == str(plain):
            calls["n"] += 1
            raise OSError("ENOSPC: no space to commit live plaintext")
        return real_replace(src, dst)

    monkeypatch.setattr(secretfs.os, "replace", flaky_replace)

    with pytest.raises(OSError):
        secretfs.persist_store(
            {"devices": {"new": 2}}, str(plain),
            recipients_csv="age1rec", enc_path=str(enc), age_bin=fake_age)
    assert calls["n"] == 1, "the live-commit replace was not exercised"

    # Live plaintext untouched: still the OLD store.
    assert "old" in plain.read_text()
    assert "new" not in plain.read_text()

    # Durable copy was rolled back to the OLD store (NOT left ahead at NEW), so
    # a restart's decrypt_to would reproduce the OLD live store — no divergence.
    key = tmp_path / "key"
    key.write_text("AGE-SECRET-KEY-FAKE\n")
    back = tmp_path / "restart" / "secrets.json"
    secretfs.decrypt_to(str(enc), str(back), str(key), age_bin=fake_age)
    assert "old" in back.read_text()
    assert "new" not in back.read_text(), (
        "durable copy left ahead of live — a restart would lose the old token")


def test_decrypt_bad_key_fails_closed_no_plaintext(tmp_path, fake_age):
    # ciphertext WITHOUT the fake-age header => the fake age `-d` exits 1,
    # mimicking a missing/invalid master key. Nothing must land at out_path.
    enc = tmp_path / "secrets.json.age"
    enc.write_text("not-real-ciphertext\n")
    key = tmp_path / "key"
    key.write_text("AGE-SECRET-KEY-FAKE\n")
    out = tmp_path / "run" / "secrets.json"

    with pytest.raises(subprocess.CalledProcessError):
        secretfs.decrypt_to(str(enc), str(out), str(key), age_bin=fake_age)
    assert not out.exists()


def test_encrypt_from_timeout_on_hung_age(tmp_path, monkeypatch):
    """If age hangs (e.g., subprocess stalls), timeout kills it and raises
    TimeoutExpired rather than hanging the request thread forever."""
    # Create a fake age binary that sleeps longer than the timeout.
    slow_age = tmp_path / "slow-age"
    slow_age.write_text(r'''#!/usr/bin/env bash
# Fake age that sleeps longer than any reasonable timeout.
sleep 10
exit 0
''')
    slow_age.chmod(0o755)

    plain = tmp_path / "run" / "secrets.json"
    plain.parent.mkdir()
    plain.write_text("{\"test\": 1}\n")
    enc = tmp_path / "secrets.json.age"

    # Monkeypatch the timeout to ~1s so the test finishes quickly.
    monkeypatch.setattr(secretfs, "_AGE_TIMEOUT", 1)

    with pytest.raises(subprocess.TimeoutExpired):
        secretfs.encrypt_from(
            str(plain), str(enc), "age1rec", age_bin=str(slow_age)
        )


def test_decrypt_to_timeout_on_hung_age(tmp_path, monkeypatch):
    """If age hangs during decryption, timeout kills it and raises
    TimeoutExpired instead of hanging."""
    # Create a fake age binary that sleeps longer than the timeout.
    slow_age = tmp_path / "slow-age"
    slow_age.write_text(r'''#!/usr/bin/env bash
# Fake age that sleeps longer than any reasonable timeout.
sleep 10
exit 0
''')
    slow_age.chmod(0o755)

    enc = tmp_path / "secrets.json.age"
    enc.write_text("AGEFAKE\n{\"test\": 1}\n")
    key = tmp_path / "key"
    key.write_text("AGE-SECRET-KEY-FAKE\n")
    out = tmp_path / "run" / "secrets.json"

    # Monkeypatch the timeout to ~1s so the test finishes quickly.
    monkeypatch.setattr(secretfs, "_AGE_TIMEOUT", 1)

    with pytest.raises(subprocess.TimeoutExpired):
        secretfs.decrypt_to(str(enc), str(out), str(key), age_bin=str(slow_age))


# ---------------------------------------------------------------------------
# Durability: the ciphertext is the only copy that survives a restart, so the
# atomic rename must also be a DURABLE one (issue #96).
# ---------------------------------------------------------------------------

def _fsync_spy(monkeypatch):
    """Record (st_dev, st_ino) of every descriptor fsynced, in order.

    Identifying the target by inode rather than by fd number survives the
    rename: after os.replace the synced temp file IS enc_path, so the tuple
    recorded before the rename matches os.stat(enc_path) afterwards.
    """
    synced = []
    real_fsync = os.fsync

    def spy(fd):
        st = os.fstat(fd)
        synced.append((st.st_dev, st.st_ino))
        return real_fsync(fd)

    monkeypatch.setattr(secretfs.os, "fsync", spy)
    return synced


def _ino(path):
    st = os.stat(str(path))
    return (st.st_dev, st.st_ino)


def test_encrypt_from_fsyncs_ciphertext_and_directory(tmp_path, fake_age,
                                                      monkeypatch):
    """Without the fsyncs the ciphertext rename is atomic but not durable: a
    host crash right after a rotation would come back up with the PREVIOUS
    secrets store while the server already reported the rotation complete."""
    plain = tmp_path / "run" / "secrets.json"
    plain.parent.mkdir()
    plain.write_text("{\"devices\": {\"new\": 2}}")
    enc = tmp_path / "durable" / "secrets.json.age"
    enc.parent.mkdir()

    synced = _fsync_spy(monkeypatch)
    secretfs.encrypt_from(str(plain), str(enc), "age1rec", age_bin=fake_age)

    assert _ino(enc) in synced, "ciphertext bytes were never fsynced"
    assert _ino(enc.parent) in synced, "the rename's directory was never fsynced"
    # Bytes first, then the directory entry that publishes them.
    assert synced.index(_ino(enc)) < synced.index(_ino(enc.parent))


def test_persist_store_rotation_is_durable(tmp_path, fake_age, monkeypatch):
    """The whole device-token rotation path (persist_store -> encrypt_from)
    must reach stable storage before the caller can report success."""
    plain = tmp_path / "run" / "secrets.json"
    plain.parent.mkdir()
    plain.write_text("{\"devices\": {\"old\": 1}}")
    enc = tmp_path / "durable" / "secrets.json.age"
    enc.parent.mkdir()

    synced = _fsync_spy(monkeypatch)
    secretfs.persist_store({"devices": {"new": 2}}, str(plain),
                           recipients_csv="age1rec", enc_path=str(enc),
                           age_bin=fake_age)

    assert _ino(enc) in synced, "rotation ciphertext was never fsynced"
    assert _ino(enc.parent) in synced, "rotation rename was never fsynced"


def test_encrypt_from_tolerates_directory_fsync_unsupported(tmp_path, fake_age,
                                                            monkeypatch):
    """A filesystem without directory fsync (EINVAL/ENOTSUP) must not fail the
    write; any OTHER I/O error still surfaces so nothing reports a rotation
    durable that is not."""
    plain = tmp_path / "secrets.json"
    plain.write_text("{}")
    enc = tmp_path / "secrets.json.age"
    real_fsync = os.fsync
    dir_ino = _ino(tmp_path)

    def picky(fd):
        st = os.fstat(fd)
        if (st.st_dev, st.st_ino) == dir_ino:
            raise OSError(errno.EINVAL, "directory fsync unsupported")
        return real_fsync(fd)

    monkeypatch.setattr(secretfs.os, "fsync", picky)
    secretfs.encrypt_from(str(plain), str(enc), "age1rec", age_bin=fake_age)
    assert enc.exists()

    def broken(fd):
        st = os.fstat(fd)
        if (st.st_dev, st.st_ino) == dir_ino:
            raise OSError(errno.EIO, "disk went away")
        return real_fsync(fd)

    monkeypatch.setattr(secretfs.os, "fsync", broken)
    with pytest.raises(OSError):
        secretfs.encrypt_from(str(plain), str(enc), "age1rec",
                              age_bin=fake_age)
