# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Post-install setup status: certificate fingerprinting, IOx package
introspection, and the worst-of status roll-up (spec 2026-08-24)."""
import io
import os
import tarfile

import setup_status

# A tiny self-signed cert generated once and pinned here so the tests need no
# openssl and no network. Any valid PEM works; only its bytes matter.
CERT_A = """-----BEGIN CERTIFICATE-----
MIIBdzCCAR2gAwIBAgIUJ0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0YwCgYIKoZIzj0EAwIwFDES
MBAGA1UEAwwJaXJpcy10ZXN0MB4XDTI2MDgyNDAwMDAwMFoXDTM2MDgyMTAwMDAwMFow
FDESMBAGA1UEAwwJaXJpcy10ZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZ0Z0
Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0
Z0Z0Z6NTMFEwHQYDVR0OBBYEFEZ0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0MB8GA1UdIwQYMBaA
FEZ0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0Z0MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwID
SAAwRQIhAP//////////////////////////////////////AiAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAA==
-----END CERTIFICATE-----
"""


def _make_iox_package(path, pem_text=None, with_artifacts=True):
    """Build a minimal IOx-shaped package: an outer tar containing
    artifacts.tar.gz, which in turn contains iris-catalog.pem."""
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w:gz") as tf:
        if pem_text is not None:
            data = pem_text.encode()
            info = tarfile.TarInfo("iris-catalog.pem")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        junk = b"x" * 16
        other = tarfile.TarInfo("agent/agent_config.py")
        other.size = len(junk)
        tf.addfile(other, io.BytesIO(junk))
    blob = inner.getvalue()
    with tarfile.open(path, mode="w") as outer:
        meta = b"descriptor-schema-version: '2.8'\n"
        mi = tarfile.TarInfo("package.yaml")
        mi.size = len(meta)
        outer.addfile(mi, io.BytesIO(meta))
        if with_artifacts:
            ai = tarfile.TarInfo("artifacts.tar.gz")
            ai.size = len(blob)
            outer.addfile(ai, io.BytesIO(blob))


def test_fingerprint_is_colon_separated_uppercase_sha256():
    fp = setup_status.fingerprint_pem(CERT_A)
    assert fp is not None
    parts = fp.split(":")
    assert len(parts) == 32                      # sha256 = 32 bytes
    assert all(len(p) == 2 for p in parts)
    assert fp == fp.upper()


def test_fingerprint_of_garbage_is_none():
    assert setup_status.fingerprint_pem("not a certificate") is None
    assert setup_status.fingerprint_pem("") is None


def test_read_pem_fingerprint_missing_file_is_none(tmp_path):
    assert setup_status.read_pem_fingerprint(str(tmp_path / "nope.pem")) is None


def test_package_fingerprint_reads_the_baked_cert(tmp_path):
    p = str(tmp_path / "iris-arm64.tar")
    _make_iox_package(p, CERT_A)
    fp, reason = setup_status.package_fingerprint(p)
    assert reason == ""
    assert fp == setup_status.fingerprint_pem(CERT_A)


def test_package_fingerprint_absent_file(tmp_path):
    fp, reason = setup_status.package_fingerprint(str(tmp_path / "gone.tar"))
    assert fp is None and reason == "absent"


def test_package_fingerprint_without_artifacts_member(tmp_path):
    p = str(tmp_path / "iris-arm64.tar")
    _make_iox_package(p, CERT_A, with_artifacts=False)
    fp, reason = setup_status.package_fingerprint(p)
    assert fp is None and reason == "no-artifacts"


def test_package_fingerprint_without_baked_cert(tmp_path):
    p = str(tmp_path / "iris-arm64.tar")
    _make_iox_package(p, None)
    fp, reason = setup_status.package_fingerprint(p)
    assert fp is None and reason == "no-cert"


def test_package_fingerprint_unreadable_tar(tmp_path):
    p = str(tmp_path / "iris-arm64.tar")
    with open(p, "wb") as f:
        f.write(b"this is not a tar at all")
    fp, reason = setup_status.package_fingerprint(p)
    assert fp is None and reason == "unreadable"
