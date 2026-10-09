# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Post-install setup status: runtime trust and package provenance."""
import hashlib
import io
import json
import os
import tarfile

import setup_status

# Two tiny self-signed certificates, generated once and pinned here so the
# live-vs-distributed trust tests need no openssl and no network.
CERT_A = """-----BEGIN CERTIFICATE-----
MIIBfTCCASKgAwIBAgITErjOyrGbWj2MCSGl3JsCCnYoIzAKBggqhkjOPQQDAjAU
MRIwEAYDVQQDDAlpcmlzLXRlc3QwHhcNMjYwODMxMTUyMTMzWhcNMzYwODI4MTUy
MTMzWjAUMRIwEAYDVQQDDAlpcmlzLXRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMB
BwNCAARl74X5YjmZdXu85lF7yiiZ6yK/2phHS8bDSc5/6bvmT1e8VS7J5V8zYML7
qXPAnxLFBC5J77AnycN4YgLiA0a5o1MwUTAdBgNVHQ4EFgQUDx/qTqyJr3SVpOuH
ZVdWPozJD0EwHwYDVR0jBBgwFoAUDx/qTqyJr3SVpOuHZVdWPozJD0EwDwYDVR0T
AQH/BAUwAwEB/zAKBggqhkjOPQQDAgNJADBGAiEAxKR9fRqeSmteizrr0liXRmHd
UyFgIaahTtCo5admpTkCIQDunp+yV941ou62N8CO1s9sLIhY6kqVtDZqcYrn5TNy
Eg==
-----END CERTIFICATE-----
"""

# A DIFFERENT certificate, for the fingerprint-mismatch cases. A second real
# certificate rather than a byte-twiddled copy of the first: a corrupted
# CERT_A tests nothing a genuine rotation would produce.
CERT_B = """-----BEGIN CERTIFICATE-----
MIIBiDCCAS+gAwIBAgIUeqYVgs872IwwIFlZRKeGn0iz1dkwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPaXJpcy10ZXN0LW90aGVyMB4XDTI2MDgzMTE1MjE1N1oXDTM2
MDgyODE1MjE1N1owGjEYMBYGA1UEAwwPaXJpcy10ZXN0LW90aGVyMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAE0dArL9DOeSceKhfGrPLT3SwjaIRwXtopX51Hzddd
jMg8trdWWyCIW6O4r/+wqgQpET+HUU/C0XdqfJuV+Jo1b6NTMFEwHQYDVR0OBBYE
FDqaJrZu91muTG5YiDGzaVIsrhSeMB8GA1UdIwQYMBaAFDqaJrZu91muTG5YiDGz
aVIsrhSeMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgCzWagQaC
GlnxXdVQh386L+2NVnXMVYFeLnJ1Do5P4WcCIHgdOByAQN8abuZaEZ/qhYNDzOkE
V7H1BW7MTLUDQL27
-----END CERTIFICATE-----
"""


def _make_wrapper(path, kind="iox", platform="linux/arm64", payload=None,
                  manifest=True, overrides=None):
    """Write arbitrary wrapper bytes and their real adjacent provenance."""
    path = os.fspath(path)
    name = os.path.basename(path)
    data = payload if payload is not None else ("wrapper:" + name).encode()
    with open(path, "wb") as handle:
        handle.write(data)
    values = {
        "format": "iris-device-wrapper-v1",
        "wrapper_kind": kind,
        "wrapper_file": name,
        "wrapper_sha256": hashlib.sha256(data).hexdigest(),
        "platform": platform,
        "canonical_index_digest": "sha256:" + "1" * 64,
        "canonical_archive_sha256": "2" * 64,
        "canonical_source_sha256": "3" * 64,
    }
    values.update(overrides or {})
    if manifest:
        with open(path + ".manifest", "w") as handle:
            for key, value in values.items():
                handle.write("%s=%s\n" % (key, value))
    return values


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


def _readiness(path, kind="iox", platform="linux/arm64"):
    return setup_status.package_readiness(
        str(path), os.path.basename(path), kind, platform, "rebuild")


def test_package_readiness_binds_readable_bytes_to_provenance(tmp_path):
    p = tmp_path / "iris-arm64.tar"
    expected = _make_wrapper(p)
    item = _readiness(p)
    assert item["state"] == "ok"
    assert item["provenance"]["canonical_index_digest"] == \
        expected["canonical_index_digest"]
    assert "contents and native signatures are not inspected" in item["detail"]


def _write_served_bundle_fixture(tmp_path, root_bytes=b"root trust\n"):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(exist_ok=True)
    bundle = artifacts / "iris-agent.tgz"
    embedded = {
        "iris-signers.allowed_signers": b"ca trust\n",
        "iris-root.allowed_signers": root_bytes,
    }
    with tarfile.open(bundle, "w:gz") as archive:
        for name, data in embedded.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    (artifacts / "iris-agent.tgz.sha256").write_text(digest + "\n")
    (artifacts / "bootstrap.sh").write_bytes(b"bootstrap\n")
    (artifacts / "iris-signers.pem").write_bytes(
        embedded["iris-signers.allowed_signers"])
    status = tmp_path / "served-bundle.json"
    record = {"format": "iris-served-bundle-v1", "state": "ok",
              "reason": "ready"}
    for name in ("iris-agent.tgz", "iris-agent.tgz.sha256",
                 "bootstrap.sh", "iris-signers.pem"):
        record[name] = hashlib.sha256((artifacts / name).read_bytes()).hexdigest()
    for name, data in embedded.items():
        record[name] = hashlib.sha256(data).hexdigest()
    status.write_text(json.dumps(record) + "\n")
    return artifacts, status, record


def test_served_bundle_readiness_binds_raw_sidecar_and_embedded_trust(tmp_path):
    artifacts, status, record = _write_served_bundle_fixture(tmp_path)
    item = setup_status.served_bundle_readiness(
        str(artifacts), str(status), startup_state="ok")
    assert item["state"] == "ok", item

    # Model a replaced bundle whose adjacent digest and top-level provenance
    # were both updated, while its embedded offline-root trust changed.
    _write_served_bundle_fixture(tmp_path, root_bytes=b"substituted root\n")
    bundle = artifacts / "iris-agent.tgz"
    digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
    sidecar = artifacts / "iris-agent.tgz.sha256"
    sidecar.write_text(digest + "\n")
    record["iris-agent.tgz"] = digest
    record["iris-agent.tgz.sha256"] = hashlib.sha256(
        sidecar.read_bytes()).hexdigest()
    status.write_text(json.dumps(record) + "\n")
    item = setup_status.served_bundle_readiness(
        str(artifacts), str(status), startup_state="ok")
    assert item["state"] == "stale"


def test_served_bundle_readiness_rejects_noncanonical_digest_sidecar(tmp_path):
    artifacts, status, record = _write_served_bundle_fixture(tmp_path)
    sidecar = artifacts / "iris-agent.tgz.sha256"
    sidecar.write_text(sidecar.read_text().upper())
    record["iris-agent.tgz.sha256"] = hashlib.sha256(
        sidecar.read_bytes()).hexdigest()
    status.write_text(json.dumps(record) + "\n")
    item = setup_status.served_bundle_readiness(
        str(artifacts), str(status), startup_state="ok")
    assert item["state"] == "stale"


def test_served_bundle_readiness_bounds_digest_sidecar_before_read(tmp_path):
    artifacts, status, record = _write_served_bundle_fixture(tmp_path)
    sidecar = artifacts / "iris-agent.tgz.sha256"
    sidecar.write_bytes(b"x" * 66)
    record["iris-agent.tgz.sha256"] = hashlib.sha256(
        sidecar.read_bytes()).hexdigest()
    status.write_text(json.dumps(record) + "\n")
    item = setup_status.served_bundle_readiness(
        str(artifacts), str(status), startup_state="ok")
    assert item["state"] == "stale"


def test_served_bundle_readiness_cannot_parse_a_replaced_bundle(tmp_path,
                                                               monkeypatch):
    artifacts, status, _ = _write_served_bundle_fixture(tmp_path)
    bundle = artifacts / "iris-agent.tgz"
    replacement = tmp_path / "replacement.tgz"
    members = {
        "iris-signers.allowed_signers": b"ca trust\n",
        "iris-root.allowed_signers": b"root trust\n",
        "agent/iris_agent.py": b"substituted agent bytes\n",
    }
    with tarfile.open(replacement, "w:gz") as archive:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

    real_open = setup_status.tarfile.open
    swapped = []

    def swap_before_parse(*args, **kwargs):
        if not swapped:
            os.replace(str(replacement), str(bundle))
            swapped.append(True)
        return real_open(*args, **kwargs)

    monkeypatch.setattr(setup_status.tarfile, "open", swap_before_parse)
    item = setup_status.served_bundle_readiness(
        str(artifacts), str(status), startup_state="ok")
    assert swapped
    assert item["state"] == "stale"
    assert hashlib.sha256(bundle.read_bytes()).hexdigest() != \
        json.loads(status.read_text())["iris-agent.tgz"]


def test_package_readiness_absent_and_empty_are_not_ok(tmp_path):
    missing = _readiness(tmp_path / "iris-arm64.tar")
    assert missing["state"] == "absent" and missing["reason"] == "absent"
    p = tmp_path / "iris-arm64.tar"
    p.write_bytes(b"")
    empty = _readiness(p)
    assert empty["state"] == "unknown" and empty["reason"] == "empty"


def test_package_readiness_requires_an_adjacent_manifest(tmp_path):
    p = tmp_path / "iris-arm64.tar"
    _make_wrapper(p, manifest=False)
    item = _readiness(p)
    assert item["state"] == "unknown"
    assert item["reason"] == "provenance-absent"


def test_package_readiness_rejects_malformed_or_duplicate_provenance(tmp_path):
    p = tmp_path / "iris-arm64.tar"
    _make_wrapper(p)
    with open(str(p) + ".manifest", "a") as handle:
        handle.write("wrapper_file=other.tar\n")
    item = _readiness(p)
    assert item["state"] == "unknown"
    assert item["reason"] == "provenance-invalid"


def test_package_readiness_detects_wrapper_changed_after_manifest(tmp_path):
    p = tmp_path / "iris-arm64.tar"
    _make_wrapper(p)
    with open(p, "ab") as handle:
        handle.write(b"signed-or-tampered-after-build")
    item = _readiness(p)
    assert item["state"] == "stale"
    assert item["reason"] == "wrapper-digest-mismatch"


def test_package_readiness_validates_kind_platform_and_digest_shapes(tmp_path):
    cases = ({"wrapper_kind": "xr-appmgr"},
             {"platform": "linux/amd64"},
             {"canonical_source_sha256": "not-a-digest"})
    for index, overrides in enumerate(cases):
        p = tmp_path / ("case-%s.tar" % index)
        _make_wrapper(p, overrides=overrides)
        item = setup_status.package_readiness(
            str(p), p.name, "iox", "linux/arm64", "rebuild")
        assert item["state"] == "unknown"
        assert item["reason"] == "provenance-invalid"


# --- status assembly -------------------------------------------------------

def _artifacts(tmp_path, arm_pem, amd_pem, served_pem=CERT_A,
               distributed_pem=None, xr=False):
    d = tmp_path / "artifacts"
    d.mkdir()
    if arm_pem is not None:
        _make_wrapper(d / "iris-arm64.tar")
    if amd_pem is not None:
        _make_wrapper(d / "iris-amd64.tar", platform="linux/amd64")
    served = tmp_path / "cert.pem"
    served.write_text(served_pem)
    if xr:
        _make_wrapper(d / "iris-xr.rpm", kind="xr-appmgr",
                      platform="linux/amd64")
    # the copy handed to devices; defaults to matching the served cert
    (d / "iris-catalog.pem").write_text(
        distributed_pem if distributed_pem is not None else served_pem)
    return str(d), str(served)


def _call(d, served, admin="admin",
         telemetry_override_endpoint=None, telemetry_override_enabled=None,
         telemetry_env_endpoint="", telemetry_env_enabled=False,
         image_verification_last_run=None):
    return setup_status.build_status(
        d, served, os.path.join(d, "iris-catalog.pem"), admin,
        telemetry_override_endpoint, telemetry_override_enabled,
        telemetry_env_endpoint, telemetry_env_enabled,
        image_verification_last_run=image_verification_last_run)


def test_all_ok(tmp_path):
    # xr=True: all three wrappers have readable bytes and matching provenance.
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, xr=True)
    st = _call(d, served)
    assert st["admin"]["state"] == "ok"
    assert st["admin"]["username"] == "admin"
    assert st["packages"]["state"] == "ok"
    assert len(st["packages"]["items"]) == 3


# --- image verification card (KGV / Cisco Bulk Hash reconciler, Task 5) ---

def test_image_verification_unset_when_never_run(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served, image_verification_last_run=None)
    assert st["image_verification"]["state"] == "unset"


def test_image_verification_unset_on_empty_last_run(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served, image_verification_last_run={})
    assert st["image_verification"]["state"] == "unset"


def test_image_verification_ok_after_a_successful_run(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served, image_verification_last_run={
        "at": 1735689600, "source": "manual", "outcome": "ok",
        "matched": 3, "mismatched": 0, "not_in_feed": 0})
    assert st["image_verification"]["state"] == "ok"


def test_image_verification_stays_unset_on_a_failed_run(tmp_path):
    """A run that actually happened but FAILED (fetch/verify/parse/reconcile
    error) must not read as done -- only a genuine "ok" outcome does. The
    detail suffix varies, so this must never be an equality check against a
    literal "fail" (same rule as the console's own last_run rendering)."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served, image_verification_last_run={
        "at": 1735689600, "source": "scheduled",
        "outcome": "fail: signature verification failed",
        "matched": None, "mismatched": None, "not_in_feed": None})
    assert st["image_verification"]["state"] == "unset"


def test_image_verification_unset_when_at_is_missing_even_if_outcome_says_ok(tmp_path):
    """Defensive: a garbled/partial record must not read as done just
    because outcome happens to say "ok" -- at is the evidence that a run
    genuinely completed."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served, image_verification_last_run={
        "at": None, "source": "manual", "outcome": "ok"})
    assert st["image_verification"]["state"] == "unset"


# --- telemetry destination card --------------------------------------
#
# telemetry.read(path) returns {"endpoint": None|str, "enabled": None|bool}
# where None means "inherit the deployment environment" (IRIS_OTLP_ENDPOINT /
# IRIS_OBSERVABILITY). build_status is pure, so the caller (gui_server.py)
# resolves the file and the env and hands both in; these tests exercise that
# resolution the same way the route does.

def test_telemetry_explicit_override_is_ok_and_reported_as_override(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served,
              telemetry_override_endpoint="https://collector.example:4318",
              telemetry_override_enabled=True,
              # a deployment default is ALSO present -- the override must win
              telemetry_env_endpoint="https://env-default:4318",
              telemetry_env_enabled=False)
    assert st["telemetry"]["state"] == "ok"
    assert st["telemetry"]["source"] == "override"
    assert st["telemetry"]["endpoint"] == "https://collector.example:4318"
    assert st["telemetry"]["enabled"] is True


def test_telemetry_deployment_default_is_ok_and_reported_as_env(tmp_path):
    """No console override at all -- the env-supplied endpoint and enabled
    flag are what resolve, and the card must say so (not 'override')."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served,
              telemetry_override_endpoint=None,
              telemetry_override_enabled=None,
              telemetry_env_endpoint="https://otel.example:4318",
              telemetry_env_enabled=True)
    assert st["telemetry"]["state"] == "ok"
    assert st["telemetry"]["source"] == "env"
    assert st["telemetry"]["endpoint"] == "https://otel.example:4318"
    assert st["telemetry"]["enabled"] is True


def test_telemetry_nothing_configured_is_unset(tmp_path):
    """No override and no deployment default anywhere -- nothing is being
    exported, and this must never read as ok."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served,
              telemetry_override_endpoint=None,
              telemetry_override_enabled=None,
              telemetry_env_endpoint="",
              telemetry_env_enabled=False)
    assert st["telemetry"]["state"] == "unset"
    assert st["telemetry"]["endpoint"] == ""


def test_telemetry_export_disabled_is_not_ok_even_with_an_endpoint(tmp_path):
    """An endpoint alone is not enough -- if export is gated off, nothing is
    actually being sent, so this must not read as ok."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served,
              telemetry_override_endpoint="https://collector.example:4318",
              telemetry_override_enabled=False)
    assert st["telemetry"]["state"] != "ok"
    assert st["telemetry"]["state"] == "unset"


def test_stale_provenance_wins_over_ok_sibling(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    with open(os.path.join(d, "iris-arm64.tar"), "ab") as handle:
        handle.write(b"changed after provenance was written")
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
    d, served = _artifacts(tmp_path, CERT_A, None)
    with open(os.path.join(d, "iris-arm64.tar"), "ab") as handle:
        handle.write(b"changed after provenance was written")
    st = _call(d, served)
    assert st["packages"]["state"] == "stale"


def test_unreadable_served_cert_is_unknown_never_ok(tmp_path):
    d, _ = _artifacts(tmp_path, CERT_A, CERT_A)
    st = setup_status.build_status(
        d, str(tmp_path / "missing.pem"),
        os.path.join(d, "iris-catalog.pem"), "admin")
    assert st["packages"]["state"] == "unknown"
    assert st["packages"]["reference_fingerprint"] is None


def test_non_text_served_cert_is_unknown_never_an_unhandled_error(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, xr=True)
    with open(served, "wb") as handle:
        handle.write(b"\xff\xfe corrupt certificate")
    st = _call(d, served)
    assert st["packages"]["state"] == "unknown"
    assert st["packages"]["reason"] == "served-cert-unavailable"
    assert st["packages"]["reference_fingerprint"] is None


def test_served_vs_distributed_mismatch_is_unknown_not_stale(tmp_path):
    """If the cert we SERVE differs from the one we hand devices, new onboards
    are broken too -- rebuilding packages would not fix it, so this must not be
    reported as a mere stale package."""
    other = CERT_B
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


def test_stale_provenance_not_masked_by_missing_distributed_cert(tmp_path):
    """A stale wrapper/manifest pair outranks unavailable runtime trust."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    with open(os.path.join(d, "iris-arm64.tar"), "ab") as handle:
        handle.write(b"changed after provenance was written")
    # Delete the distributed cert to simulate it being unavailable
    os.remove(os.path.join(d, "iris-catalog.pem"))
    st = _call(d, served)
    assert st["packages"]["state"] == "stale"
    assert st["packages"]["reason"] == "distributed-cert-unavailable"
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    assert by_name["iris-arm64.tar"]["state"] == "stale"
    assert by_name["iris-amd64.tar"]["state"] == "ok"


# --- device-packages card: the third row, iris-xr.rpm ----------------------
# All native wrappers use the same byte/provenance contract. The XR RPM no
# longer needs a certificate-age approximation because no certificate is baked
# into the canonical image.


def test_xr_package_absent_is_neutral_and_claims_nothing_checked(tmp_path):
    """A site with no XR devices simply never builds this file -- 'absent',
    same neutral state (not a warning) the tars already use for an
    architecture a deployment does not build. No 'detail' key at all: unlike
    every other non-ok state below, nothing here was actually examined, so
    nothing is said about what was or was not verified."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)   # xr=False (default)
    st = _call(d, served)
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    xr = by_name["iris-xr.rpm"]
    assert xr["state"] == "absent"
    assert xr["reason"] == "absent"
    assert xr["fingerprint"] is None
    assert xr["built_at"] is None
    assert "detail" not in xr


def test_xr_package_ok_when_bytes_match_its_provenance(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, xr=True)
    st = _call(d, served)
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    xr = by_name["iris-xr.rpm"]
    assert xr["state"] == "ok"
    assert xr["fingerprint"] is None
    assert xr["built_at"] is not None
    assert "native signatures are not inspected" in xr["detail"]
    assert xr["provenance"]["canonical_index_digest"].startswith("sha256:")
    assert st["packages"]["state"] == "ok"


def test_xr_package_stale_when_bytes_no_longer_match_provenance(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, xr=True)
    with open(os.path.join(d, "iris-xr.rpm"), "ab") as handle:
        handle.write(b"changed")
    st = _call(d, served)
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    xr = by_name["iris-xr.rpm"]
    assert xr["state"] == "stale"
    assert xr["reason"] == "wrapper-digest-mismatch"
    assert st["packages"]["state"] == "stale"


def test_certificate_rotation_does_not_stale_iox_or_xr_packages(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, xr=True)
    with open(served, "w") as handle:
        handle.write(CERT_B)
    with open(os.path.join(d, "iris-catalog.pem"), "w") as handle:
        handle.write(CERT_B)
    st = _call(d, served)
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    assert {item["state"] for item in by_name.values()} == {"ok"}
    assert st["packages"]["state"] == "ok"


def test_xr_package_unknown_without_provenance(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, xr=True)
    os.remove(os.path.join(d, "iris-xr.rpm.manifest"))
    st = _call(d, served)
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    assert by_name["iris-xr.rpm"]["state"] == "unknown"
    assert by_name["iris-xr.rpm"]["reason"] == "provenance-absent"


def test_unreadable_served_cert_does_not_change_xr_item_readiness(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, xr=True)
    st = setup_status.build_status(
        d, str(tmp_path / "missing.pem"),
        os.path.join(d, "iris-catalog.pem"), "admin")
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    xr = by_name["iris-xr.rpm"]
    assert xr["state"] == "ok"
    assert st["packages"]["state"] == "unknown"
    assert st["packages"]["reason"] == "served-cert-unavailable"


def test_xr_package_carries_its_own_build_script_remedy(tmp_path):
    """The XR RPM and the IOx tars are rebuilt by two DIFFERENT scripts, so
    each item now carries its own remedy command rather than relying on the
    single card-level packages.remedy (which stays the IOx script -- see
    packageRemedy in setup-packages-model.mjs, which reads each item so a stale
    XR row is never handed the wrong rebuild command)."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, xr=True)
    st = _call(d, served)
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    assert by_name["iris-xr.rpm"]["remedy"] == setup_status.REMEDY_XR
    assert by_name["iris-arm64.tar"]["remedy"] == setup_status.REMEDY
    assert by_name["iris-amd64.tar"]["remedy"] == setup_status.REMEDY
    assert setup_status.REMEDY_XR != setup_status.REMEDY


def test_xr_package_absent_does_not_outrank_a_stale_tar(tmp_path):
    """'absent' (rank 1) must not mask a genuinely stale tar (rank 4) just
    because the XR row also rolled up to a non-ok state -- the same
    worst-of guarantee test_stale_outranks_absent already pins for the two
    tars, now with a third, absent-by-default row in the mix."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)  # xr=False -> absent
    with open(os.path.join(d, "iris-arm64.tar"), "ab") as handle:
        handle.write(b"changed after provenance was written")
    st = _call(d, served)
    assert st["packages"]["state"] == "stale"


def test_response_carries_no_secret_material(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served,
              telemetry_override_endpoint="https://collector.example:4318",
              telemetry_override_enabled=True)
    blob = repr(st).lower()
    for banned in ("password", "secret", "token", "private", "begin "):
        assert banned not in blob


# --- route ----------------------------------------------------------------

def test_route_is_registered_and_session_gated():
    """The console route must exist and must sit behind the session check,
    like every other /api/settings read."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # The state-owning route moved behind the Console BFF; inspect the
    # management implementation, not the deliberately state-free proxy.
    src = open(os.path.join(here, "management_api.py")).read()
    assert '"/api/settings/setup-status"' in src
    idx = src.index('"/api/settings/setup-status"')
    window = src[idx:idx + 400]
    assert "session_info" in window          # gated like its neighbours
    assert "setup_status.build_status" in window
    route = src[idx:src.index('if path == "/api/settings/peer-tls"', idx)]
    assert "provision_status_path=" in route
    assert "provision_startup_state=" in route


# --- console pane ---------------------------------------------------------

def _webroot(name):
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return open(os.path.join(here, "webroot", name)).read()


def _react_source(name):
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(here, "console-ui", "src", name), encoding="utf-8") as stream:
        return stream.read()


def test_console_has_a_setup_pane_wired_to_the_endpoint():
    html, adapter = _webroot("index.html"), _webroot("app.js")
    assert "['setup', 'Setup checklist'," in _react_source("settings-navigation.jsx")
    for mount in ("settings-pane-setup", "iris-setup-checklist", "iris-device-packages",
                  "iris-setup-wizard", "iris-setup-nudge", "iris-setup-packages-root"):
        assert 'id="%s"' % mount in html
    assert "setupPackages.select(" in adapter
    assert "'/api/v1/settings/setup-status'" in _react_source("setup-packages-model.mjs")
    assert "mountSetupPackages();" in _react_source("main.jsx")
    assert "function renderPackageStatus" not in adapter


def test_setup_pane_explains_package_evidence_without_claiming_native_signatures():
    source = _react_source("setup-packages.jsx")
    for phrase in ("deployment-neutral", "current server certificate",
                   "does not authenticate that manifest or verify native package signatures",
                   "file modification time", "startup provisioning evidence"):
        assert phrase in source
    assert "function PackageTable(" in source
    assert source.count("<PackageTable ") == 3


def test_setup_pane_telemetry_card_funnels_into_the_setup_flow():
    source = _react_source("setup-packages.jsx")
    card = source.split("setup-td-chip", 1)[1].split("</div>", 1)[0]
    assert 'href="#setup"' in card
    assert "Optional export" in card
    assert "telemetryNote(status?.telemetry)" in card


def test_setup_pane_image_verification_card_now_enters_the_wizard():
    source = _react_source("setup-packages.jsx")
    card = source.split("setup-iv-chip", 1)[1].split("</div>", 1)[0]
    assert 'href="#setup"' in card
    assert "Cisco's Bulk Hash feed" in card
    assert "configured schedule and a successful check" in card


# These integration guards complement executable Node model/controller tests
# and the built React/CSP browser suite in console-ui/tests/setup-packages-*.


def test_mismatch_reason_gets_its_own_guidance_not_the_rebuild_remedy():
    source = _react_source("setup-packages-model.mjs")
    reason = source.split("'served-vs-distributed-mismatch':", 1)[1].split(
        "'distributed-cert-unavailable':", 1)[0]
    assert "Fix the certificate copies" in reason
    assert "tools/" not in reason
    assert "if (pkg.reason !== 'served-vs-distributed-mismatch')" in source
    assert "row.state !== 'ok'" in source


def test_remedy_text_dedupes_and_joins_multiple_package_remedies():
    source = _react_source("setup-packages-model.mjs")
    assert "new Set(pkg.items.filter(" in source
    assert ".map(row => row.remedy)" in source
    assert "remedies.join('; ')" in source


def test_absent_packages_show_complete_host_build_commands():
    assert "row.state !== 'ok'" in _react_source("setup-packages-model.mjs")
    assert setup_status.REMEDY == "tools/provision-iox-packages.sh"
    assert setup_status.REMEDY_XR == "tools/build-xr-package.sh --out artifacts/"


def test_distributed_cert_unavailable_reason_explains_itself():
    source = _react_source("setup-packages-model.mjs")
    reason = source.split("'distributed-cert-unavailable':", 1)[1].split(
        "'served-cert-unavailable':", 1)[0]
    assert "could not be read" in reason
    assert "cannot be confirmed" in reason


def test_refresh_setup_paints_unknown_on_failed_or_thrown_fetch():
    source = _react_source("setup-packages-controller.mjs")
    assert "loading: true, status: null, configured: null" in source
    assert "reply.status !== 200" in source
    assert "validate(await reply.json())" in source
    assert "catch {return null;}" in source
    assert "mine !== this.generation" in source
    assert "abort.signal.aborted" in source
    view = _react_source("setup-packages.jsx")
    assert "state = 'unknown'" in view
    assert "(pkg?.items || [])" in view


def test_fingerprint_reads_a_combined_cert_and_key_file(tmp_path):
    """IRIS_CERT is the SHARED combined file the TLS services load: a
    certificate followed by its private key. ssl.PEM_cert_to_DER_cert rejects
    that (it demands the text END with the certificate footer), so reading the
    reference must extract the leading certificate block rather than hand the
    whole file over. Without this the reference is unreadable in the real
    deployment and every package reports `unknown`/`no-reference` -- correct
    per the never-green rule, but useless."""
    combined = CERT_A + (
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n"
        "-----END PRIVATE KEY-----\n")
    p = tmp_path / "cert.pem"
    p.write_text(combined)
    assert setup_status.read_pem_fingerprint(str(p)) == \
        setup_status.fingerprint_pem(CERT_A)


def test_fingerprint_never_returns_a_key_block(tmp_path):
    """A file holding ONLY a private key must not fingerprint to anything."""
    p = tmp_path / "key.pem"
    p.write_text("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n"
                 "-----END PRIVATE KEY-----\n")
    assert setup_status.read_pem_fingerprint(str(p)) is None


# --- first-run handoff into the checklist ----------------------------------
# Creating the admin IS step one of post-install setup, so the sign-in right
# after first-run setup must continue into Settings > Setup rather than drop the
# operator on the Overview with the remaining steps buried in a submenu.

def test_first_run_setup_hands_off_to_the_wizard():
    setup_js = _webroot("setup.js")
    login_js = _webroot("login.js")

    # armed ONLY on a genuine first-run success, never on the 409
    ok_branch = setup_js.split("if (res.ok) {", 1)[1].split("} else if", 1)[0]
    assert "iris_post_setup" in ok_branch
    conflict = setup_js.split("res.status === 409", 1)[1].split("} else", 1)[0]
    assert "iris_post_setup" not in conflict, \
        "a 409 means setup already ran; it must not arm the handoff"

    # consumed once, and it must land on the setup FLOW -- the checklist sent
    # the operator to a status page and left them to find the forms
    assert "iris_post_setup" in login_js
    assert "'/#setup'" in login_js
    assert "#settings/setup" not in login_js
    assert "removeItem('iris_post_setup')" in login_js, \
        "the handoff must be one-shot, or every later sign-in lands there"


# Setup remains a three-step workflow with shared React form instances.


def test_wizard_steplist_carries_three_steps_including_image_verification():
    source = _react_source("setup-packages-model.mjs")
    steps = source.split("export const setupSteps = [", 1)[1].split("];", 1)[0]
    for key in ("telemetry", "packages", "image_verification"):
        assert "key: '%s'" % key in steps
    assert "stage_host" not in steps
    assert steps.count("{id:") == 3


def test_wizard_step_three_is_image_verification_with_a_form_mount():
    source = _react_source("setup-packages.jsx")
    step = source.split('id="wz-step-imageverification"', 1)[1].split("</div>", 1)[0]
    assert 'id="wz-iv-mount"' in step
    assert "'wz-iv-chip'" in step
    assert "<form" not in step


def test_wizard_uses_the_left_panel_right_content_stepper_anatomy():
    source = _react_source("setup-packages.jsx")
    panel = source.split('className="wz-panel"', 1)[1].split('className="wz-content"', 1)[0]
    assert 'id="wz-steplist"' in panel
    content = source.split('className="wz-content"', 1)[1]
    for marker in ("wz-step-telemetry", "wz-step-packages",
                   "wz-step-imageverification", 'id="wz-nav"'):
        assert marker in content
    assert "wz-step-stagehost" not in content
    assert 'role="listitem"' in panel
    assert "aria-current={current ? 'step' : undefined}" in panel
    css = _webroot("styles.css")
    assert "320px" in css.split(".wz-panel {", 1)[1].split("}", 1)[0]


def test_image_verification_uses_one_react_form_between_setup_and_settings():
    source = _react_source("image-verification.jsx")
    adapter = _webroot("app.js")
    assert "createPortal(" in source
    assert "mountImageVerification('wz-iv-mount')" in adapter
    assert "mountImageVerification('settings-pane-bulkhash')" in adapter
    assert "imageVerification.select(hostId)" in adapter
    assert "cloneNode" not in source
    assert "renderIvStatusFields" not in adapter


def test_m37_configured_but_unrun_schedule_gets_its_own_wording():
    model = _react_source("setup-packages-model.mjs")
    controller = _react_source("setup-packages-controller.mjs")
    assert "'Configured — no successful run yet'" in model
    assert "'/api/v1/settings/image-verification'" in model
    assert "state === 'unset' && configured === true" in model
    assert "read(verificationURL, verificationSettings)" in controller
    assert "annotation === this.annotationGeneration" in controller


def test_setup_pills_route_through_the_real_status_pill_system():
    source = _react_source("setup-packages.jsx")
    assert "className={'status-pill is-' + level}" in source
    assert "setupChip(item, state, configured)" in source
    assert "i-triangle-warn" in source
    assert 'className="badge' not in source


def test_absent_package_state_renders_inactive_not_warning():
    source = _react_source("setup-packages-model.mjs")
    assert "absent: 'inactive'" in source
    assert "absent: 'warning'" not in source


def test_wizard_first_incomplete_step_skips_optional_items():
    source = _react_source("setup-packages-model.mjs")
    first = source.split("export function firstIncomplete(", 1)[1].split("\n", 1)[0]
    assert "status.packages.state !== 'ok' ? 1 : 2" in first
    assert "telemetry" not in first and "image_verification" not in first
    controller = _react_source("setup-packages-controller.mjs")
    assert "initial && navigation === this.navigation" in controller


def test_setup_nudge_is_session_only_and_handles_disabled_browser_storage():
    source = _react_source("setup-packages-controller.mjs")
    assert "iris_setup_nudge_dismissed" in source
    assert "Storage can be unavailable" in source
    assert "Dismiss for this document even if storage is disabled" in source
    assert "['unknown', 'stale'].includes(status.packages.state)" in _react_source(
        "setup-packages-model.mjs")
