# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import hashlib
import pathlib
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import console_identity


@pytest.fixture
def paths(tmp_path):
    if not shutil.which("age") or not shutil.which("age-keygen"):
        pytest.skip("age tools required")
    identity = tmp_path / "identity"
    subprocess.run(["age-keygen", "-o", str(identity)], check=True, capture_output=True)
    recipient = subprocess.check_output(["age-keygen", "-y", str(identity)], text=True).strip()
    return tmp_path / "config", tmp_path / "run" / "console.pem", str(identity), recipient


def test_identity_survives_runtime_loss(paths):
    config, runtime, identity, recipient = paths
    console_identity.ensure_identity(config, runtime, identity, recipient, "192.0.2.1")
    initial = runtime.read_bytes()
    encrypted = config / "tls" / "console-fallback.pem.age"
    assert b"PRIVATE KEY" not in encrypted.read_bytes()
    assert runtime.stat().st_mode & 0o777 == 0o600
    assert encrypted.stat().st_mode & 0o777 == 0o600
    before = hashlib.sha256(encrypted.read_bytes()).hexdigest()
    runtime.unlink()
    console_identity.ensure_identity(config, runtime, identity, recipient, "192.0.2.1")
    assert runtime.read_bytes() == initial
    assert hashlib.sha256(encrypted.read_bytes()).hexdigest() == before
    assert not list(runtime.parent.glob(".console-identity-*"))


def test_corrupt_ciphertext_does_not_rotate_or_publish(paths):
    config, runtime, identity, recipient = paths
    console_identity.ensure_identity(config, runtime, identity, recipient, "192.0.2.1")
    initial = runtime.read_bytes()
    encrypted = config / "tls" / "console-fallback.pem.age"
    encrypted.write_bytes(b"broken")
    with pytest.raises(subprocess.CalledProcessError):
        console_identity.ensure_identity(config, runtime, identity, recipient, "192.0.2.1")
    assert runtime.read_bytes() == initial
    assert encrypted.read_bytes() == b"broken"


def test_failed_persistence_never_publishes(paths, monkeypatch):
    config, runtime, identity, recipient = paths
    def refuse(*args, **kwargs):
        raise OSError("disk full")
    monkeypatch.setattr(console_identity.secretfs, "encrypt_from", refuse)
    with pytest.raises(OSError, match="disk full"):
        console_identity.ensure_identity(config, runtime, identity, recipient, "192.0.2.1")
    assert not runtime.exists()
