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


def test_package_fingerprint_with_unparseable_cert(tmp_path):
    p = str(tmp_path / "iris-arm64.tar")
    _make_iox_package(p, "not a valid certificate at all")
    fp, reason = setup_status.package_fingerprint(p)
    assert fp is None and reason == "bad-cert"


def test_package_fingerprint_unreadable_tar(tmp_path):
    p = str(tmp_path / "iris-arm64.tar")
    with open(p, "wb") as f:
        f.write(b"this is not a tar at all")
    fp, reason = setup_status.package_fingerprint(p)
    assert fp is None and reason == "unreadable"


# --- status assembly -------------------------------------------------------

def _artifacts(tmp_path, arm_pem, amd_pem, served_pem=CERT_A,
               distributed_pem=None):
    d = tmp_path / "artifacts"
    d.mkdir()
    if arm_pem is not None:
        _make_iox_package(str(d / "iris-arm64.tar"), arm_pem)
    if amd_pem is not None:
        _make_iox_package(str(d / "iris-amd64.tar"), amd_pem)
    served = tmp_path / "cert.pem"
    served.write_text(served_pem)
    # the copy handed to devices; defaults to matching the served cert
    (d / "iris-catalog.pem").write_text(
        distributed_pem if distributed_pem is not None else served_pem)
    return str(d), str(served)


def _call(d, served, admin="admin", stage_host=None):
    return setup_status.build_status(
        d, served, os.path.join(d, "iris-catalog.pem"), admin, stage_host)


def test_all_ok(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served, stage_host={"configured": True, "username": "svc"})
    assert st["admin"]["state"] == "ok"
    assert st["admin"]["username"] == "admin"
    assert st["stage_host"]["state"] == "ok"
    assert st["packages"]["state"] == "ok"
    assert len(st["packages"]["items"]) == 2


def test_stage_host_unset(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served, stage_host={"configured": False, "username": ""})
    assert st["stage_host"]["state"] == "unset"


def test_stale_package_wins_over_ok_sibling(tmp_path):
    # arm64 pins a DIFFERENT cert than the one served -> stale
    other = CERT_A.replace("MIIBdzCCAR2", "MIIBdzCCAR3")
    d, served = _artifacts(tmp_path, other, CERT_A)
    st = _call(d, served)
    assert st["packages"]["state"] == "stale"
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    assert by_name["iris-amd64.tar"]["state"] == "ok"
    assert by_name["iris-arm64.tar"]["state"] == "stale"


def test_absent_package_is_not_ok(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, None)
    st = _call(d, served)
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    assert by_name["iris-amd64.tar"]["state"] == "absent"
    assert st["packages"]["state"] == "absent"


def test_stale_outranks_absent(tmp_path):
    other = CERT_A.replace("MIIBdzCCAR2", "MIIBdzCCAR3")
    d, served = _artifacts(tmp_path, other, None)   # one stale, one absent
    st = _call(d, served)
    assert st["packages"]["state"] == "stale"


def test_unreadable_served_cert_is_unknown_never_ok(tmp_path):
    d, _ = _artifacts(tmp_path, CERT_A, CERT_A)
    st = setup_status.build_status(
        d, str(tmp_path / "missing.pem"),
        os.path.join(d, "iris-catalog.pem"), "admin", None)
    assert st["packages"]["state"] == "unknown"
    assert st["packages"]["reference_fingerprint"] is None


def test_served_vs_distributed_mismatch_is_unknown_not_stale(tmp_path):
    """If the cert we SERVE differs from the one we hand devices, new onboards
    are broken too -- rebuilding packages would not fix it, so this must not be
    reported as a mere stale package."""
    other = CERT_A.replace("MIIBdzCCAR2", "MIIBdzCCAR3")
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, distributed_pem=other)
    st = _call(d, served)
    assert st["packages"]["state"] == "unknown"
    assert st["packages"]["reason"] == "served-vs-distributed-mismatch"


def test_distributed_cert_unavailable_is_unknown(tmp_path):
    """When the distributed cert (iris-catalog.pem handed to devices) is missing,
    we cannot guarantee onboards actually receive the cert we intend. This is
    evidence of a broken state, not a green light."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    # Delete the distributed cert to simulate it being unavailable
    os.remove(os.path.join(d, "iris-catalog.pem"))
    st = _call(d, served)
    assert st["packages"]["state"] == "unknown"
    assert st["packages"]["reason"] == "distributed-cert-unavailable"


def test_stale_package_not_masked_by_missing_distributed_cert(tmp_path):
    """When one package is stale and distributed cert is missing, the stale
    finding must not be masked by the unknown state from missing cert. Stale
    is the more urgent fact: a rebuild is needed."""
    other = CERT_A.replace("MIIBdzCCAR2", "MIIBdzCCAR3")
    d, served = _artifacts(tmp_path, other, CERT_A)  # arm64 stale, amd64 ok
    # Delete the distributed cert to simulate it being unavailable
    os.remove(os.path.join(d, "iris-catalog.pem"))
    st = _call(d, served)
    assert st["packages"]["state"] == "stale"
    assert st["packages"]["reason"] == "distributed-cert-unavailable"
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    assert by_name["iris-arm64.tar"]["state"] == "stale"
    assert by_name["iris-amd64.tar"]["state"] == "ok"


def test_response_carries_no_secret_material(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served, stage_host={"configured": True, "username": "svc"})
    blob = repr(st).lower()
    for banned in ("password", "secret", "token", "private", "begin "):
        assert banned not in blob
