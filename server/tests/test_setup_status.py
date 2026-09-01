# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Post-install setup status: certificate fingerprinting, IOx package
introspection, and the worst-of status roll-up (spec 2026-08-24)."""
import io
import os
import tarfile

import setup_status

# Two tiny self-signed certificates, generated once and pinned here so the
# tests need no openssl and no network. These are REAL, well-formed
# certificates: the XR rows read the certificate's own notBefore out of the
# DER, so a hand-edited fixture whose declared lengths no longer match its
# bytes (what used to live here) parses as garbage and can never be "ok".
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
               distributed_pem=None, xr=False):
    d = tmp_path / "artifacts"
    d.mkdir()
    if arm_pem is not None:
        _make_iox_package(str(d / "iris-arm64.tar"), arm_pem)
    if amd_pem is not None:
        _make_iox_package(str(d / "iris-amd64.tar"), amd_pem)
    served = tmp_path / "cert.pem"
    served.write_text(served_pem)
    if xr:
        # Contents are irrelevant -- setup_status never parses this file,
        # only its existence and mtime (see _xr_package_item).
        (d / "iris-xr.rpm").write_bytes(b"not-a-real-rpm")
    # the copy handed to devices; defaults to matching the served cert
    (d / "iris-catalog.pem").write_text(
        distributed_pem if distributed_pem is not None else served_pem)
    return str(d), str(served)


def _call(d, served, admin="admin", stage_host=None,
         telemetry_override_endpoint=None, telemetry_override_enabled=None,
         telemetry_env_endpoint="", telemetry_env_enabled=False,
         image_verification_last_run=None):
    return setup_status.build_status(
        d, served, os.path.join(d, "iris-catalog.pem"), admin, stage_host,
        telemetry_override_endpoint, telemetry_override_enabled,
        telemetry_env_endpoint, telemetry_env_enabled,
        image_verification_last_run=image_verification_last_run)


def test_all_ok(tmp_path):
    # xr=True: a site WITH XR devices, package built fresh (its mtime, like
    # every file this test just wrote, is >= the served cert's) -- the third
    # row must not keep an otherwise-clean packages card from reading 'ok'.
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, xr=True)
    st = _call(d, served, stage_host={"configured": True, "username": "svc"})
    assert st["admin"]["state"] == "ok"
    assert st["admin"]["username"] == "admin"
    assert st["stage_host"]["state"] == "ok"
    assert st["packages"]["state"] == "ok"
    assert len(st["packages"]["items"]) == 3


def test_stage_host_unset(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served, stage_host={"configured": False, "username": ""})
    assert st["stage_host"]["state"] == "unset"


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


def test_stale_package_wins_over_ok_sibling(tmp_path):
    # arm64 pins a DIFFERENT cert than the one served -> stale
    other = CERT_B
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
    other = CERT_B
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


def test_stale_package_not_masked_by_missing_distributed_cert(tmp_path):
    """When one package is stale and distributed cert is missing, the stale
    finding must not be masked by the unknown state from missing cert. Stale
    is the more urgent fact: a rebuild is needed."""
    other = CERT_B
    d, served = _artifacts(tmp_path, other, CERT_A)  # arm64 stale, amd64 ok
    # Delete the distributed cert to simulate it being unavailable
    os.remove(os.path.join(d, "iris-catalog.pem"))
    st = _call(d, served)
    assert st["packages"]["state"] == "stale"
    assert st["packages"]["reason"] == "distributed-cert-unavailable"
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    assert by_name["iris-arm64.tar"]["state"] == "stale"
    assert by_name["iris-amd64.tar"]["state"] == "ok"


# --- device-packages card: the third row, iris-xr.rpm ----------------------
#
# Wave C (post-walk fix): the packages card only ever enumerated the two IOx
# tars, so an operator with Cisco 8000 (IOS-XR) devices in scope had no
# signal that iris-xr.rpm -- which bakes the catalog certificate in exactly
# like the tars do, but can silently ship a stale agent the same way -- was
# never checked at all. Unlike the tars, this module cannot parse the RPM's
# internal layout (no rpm/cpio reader, stdlib only), so it can only compare
# build TIME against the served certificate's own mtime, never pin the
# certificate the RPM actually contains. Every state below is paired with an
# assertion on the item's "detail" text, because that honesty caveat is the
# entire point of doing this differently from the tars.

_BASE_TIME = 1_700_000_000.0
# CERT_A's own notBefore (UTCTime 260831152133Z = 2026-08-31 15:21:33 UTC).
# The XR rows anchor on this rather than on any file's mtime: the certificate's
# creation time is the only baseline a re-copy of the pem cannot move.
_CERT_A_NOT_BEFORE = 1_788_189_693.0


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


def test_xr_package_ok_when_built_after_the_current_certificate(tmp_path):
    """Built after the served certificate came into existence -- the best
    available evidence (build time, not contents) that it was produced against
    the live cert. 'ok' here must still say plainly that contents were never
    inspected, unlike an IOx tar's genuine fingerprint match."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, xr=True)
    os.utime(os.path.join(d, "iris-xr.rpm"),
             (_CERT_A_NOT_BEFORE + 100, _CERT_A_NOT_BEFORE + 100))
    st = _call(d, served)
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    xr = by_name["iris-xr.rpm"]
    assert xr["state"] == "ok"
    assert xr["fingerprint"] is None
    assert xr["built_at"] == int(_CERT_A_NOT_BEFORE + 100)
    assert "not inspected" in xr["detail"]
    assert "certificate" in xr["detail"].lower()
    assert st["packages"]["state"] == "ok"


def test_xr_package_stale_when_built_before_the_current_certificate(tmp_path):
    """Built before the served certificate existed -- it may still pin
    whatever certificate preceded a rotation. This must roll the whole
    packages card up to 'stale', the same as a genuinely mismatched tar
    fingerprint, even though only build time (never contents) was checked
    here."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, xr=True)
    os.utime(os.path.join(d, "iris-xr.rpm"),
             (_CERT_A_NOT_BEFORE - 100, _CERT_A_NOT_BEFORE - 100))
    st = _call(d, served)
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    xr = by_name["iris-xr.rpm"]
    assert xr["state"] == "stale"
    assert xr["built_at"] == int(_CERT_A_NOT_BEFORE - 100)
    assert "not inspected" in xr["detail"]
    assert st["packages"]["state"] == "stale"


def test_xr_package_survives_a_restaged_certificate_file(tmp_path):
    """The operator-reported false positive of 2026-08-31.

    The certificate itself is old -- the RPM was built well after it -- but
    the pem on disk is a STAGED COPY that a later bring-up re-wrote, so its
    mtime now sits far in the future. Baselining on that mtime reported
    'Needs rebuild' for an RPM built eleven minutes after the very certificate
    it was accused of predating. Only the certificate's own notBefore is
    immune, because no re-copy can move it."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, xr=True)
    # RPM built after the cert was created: genuinely fresh.
    os.utime(os.path.join(d, "iris-xr.rpm"),
             (_CERT_A_NOT_BEFORE + 100, _CERT_A_NOT_BEFORE + 100))
    # ...but the pem file was re-staged long afterwards.
    restaged = _CERT_A_NOT_BEFORE + 10_000_000
    os.utime(served, (restaged, restaged))
    st = _call(d, served)
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    xr = by_name["iris-xr.rpm"]
    assert xr["state"] == "ok"
    assert st["packages"]["state"] == "ok"


def test_xr_package_unknown_when_the_certificate_has_no_readable_not_before(tmp_path):
    """Governing rule: never report ok on missing evidence. A pem whose
    notBefore cannot be parsed leaves no honest baseline, so the row degrades
    to unknown rather than silently falling back to a file mtime -- the very
    baseline that produced the false positive above."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, xr=True)
    with open(served, "w") as fh:
        fh.write("-----BEGIN CERTIFICATE-----\nbm90YWNlcnQ=\n"
                 "-----END CERTIFICATE-----\n")
    st = _call(d, served)
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    xr = by_name["iris-xr.rpm"]
    assert xr["state"] == "unknown"


def test_xr_package_unknown_when_served_cert_is_unreadable(tmp_path):
    """No reference certificate to compare build time against -- same
    'no-reference' reason the tars use in this situation, and the same
    never-ok rule (governing rule: never report ok on missing evidence)."""
    d, served = _artifacts(tmp_path, CERT_A, CERT_A, xr=True)
    st = setup_status.build_status(
        d, str(tmp_path / "missing.pem"),
        os.path.join(d, "iris-catalog.pem"), "admin", None)
    by_name = {i["name"]: i for i in st["packages"]["items"]}
    xr = by_name["iris-xr.rpm"]
    assert xr["state"] == "unknown"
    assert xr["reason"] == "no-reference"
    assert "could not be read" in xr["detail"]


def test_xr_package_carries_its_own_build_script_remedy(tmp_path):
    """The XR RPM and the IOx tars are rebuilt by two DIFFERENT scripts, so
    each item now carries its own remedy command rather than relying on the
    single card-level packages.remedy (which stays the IOx script -- see
    setupPkgRemedyText in app.js, which reads the per-item value so a stale
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
    other = CERT_B
    d, served = _artifacts(tmp_path, other, CERT_A)   # xr=False -> absent
    st = _call(d, served)
    assert st["packages"]["state"] == "stale"


def test_response_carries_no_secret_material(tmp_path):
    d, served = _artifacts(tmp_path, CERT_A, CERT_A)
    st = _call(d, served, stage_host={"configured": True, "username": "svc"},
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
    src = open(os.path.join(here, "gui_server.py")).read()
    assert '"/api/settings/setup-status"' in src
    idx = src.index('"/api/settings/setup-status"')
    window = src[idx:idx + 400]
    assert "session_info" in window          # gated like its neighbours
    assert "setup_status.build_status" in window


# --- console pane ---------------------------------------------------------

def _webroot(name):
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return open(os.path.join(here, "webroot", name)).read()


def test_console_has_a_setup_pane_wired_to_the_endpoint():
    html = _webroot("index.html")
    js = _webroot("app.js")
    assert 'id="nav-settings-setup"' in html
    assert 'id="settings-pane-setup"' in html
    assert "'setup'" in js                       # registered in the pane list
    assert "'/api/settings/setup-status'" in js


def test_setup_pane_explains_why_each_step_matters():
    """Each card carries operator-facing rationale, not just a status chip."""
    html = _webroot("index.html")
    for phrase in ("pins this server", "Guest Shell", "stage host"):
        assert phrase.lower() in html.lower()


def test_setup_pane_telemetry_card_funnels_into_the_setup_flow():
    """The card still reports telemetry state -- Settings > Setup survives as
    the status panel -- but its action now enters the setup flow instead of
    dropping the operator on a settings page to find the form themselves."""
    html = _webroot("index.html")
    js = _webroot("app.js")
    assert 'id="setup-td-chip"' in html
    # scope to the card itself (between its heading and the next h3) so this
    # cannot pass merely because the sidebar nav happens to link there too
    card = html.split('id="setup-td-chip"', 1)[1].split("<h3>", 1)[0]
    assert 'href="#setup"' in card
    assert 'href="#settings/telemetry"' not in card
    assert "published anywhere" in card.lower()
    assert "s.telemetry.state" in js
    assert "setupTelemetryNote" in js


def test_setup_pane_image_verification_card_now_enters_the_wizard():
    """Task 9 (USER DIRECTIVE: Setup becomes a real flow) supersedes the
    earlier decision this test used to pin -- image verification was kept
    out of the wizard because a scheduled/manual/offline check "cannot be
    squeezed into first-run setup". Task 9's step 4 proves that decision
    wrong: it mounts the SAME Settings > Image verification controls
    (schedule, Refresh now, offline import) the wizard's telemetry/
    stage-host steps already reuse from Settings, via mountImageVerification
    (a move, not a template clone -- see its own comment in app.js for why).
    So the Setup status card now sends the operator into the wizard, the
    same precedent telemetry/stage-host/packages already follow, instead of
    off to Settings on its own."""
    html = _webroot("index.html")
    js = _webroot("app.js")
    assert 'id="setup-iv-chip"' in html
    card = html.split('id="setup-iv-chip"', 1)[1].split("</div>", 1)[0]
    assert 'href="#setup"' in card
    assert 'href="#settings/bulkhash"' not in card
    assert "cisco" in card.lower()
    assert "s.image_verification.state" in js
    # NOW a real fourth wizard step -- the opposite of the old decision
    assert "image_verification" in js.split(
        "var WIZARD_STEPS = [", 1)[1].split("];", 1)[0]


# --- console pane: packages.reason must not produce the wrong remedy ------
#
# app.js has no runtime test harness in this repo (no node/jsdom driver
# anywhere under server/tests/) -- every existing app.js test asserts on the
# SOURCE TEXT of the function bodies, the same idiom used throughout
# test_onboard_feedback_ux.py / test_tls_page_ux.py. These tests follow that
# idiom: they are source-level, not behavioural -- they cannot execute the
# JS and observe the rendered DOM. What they DO prove is that the specific
# code shape the bug required is gone, and the specific code shape the fix
# requires is present, so reverting either half of the fix fails them.

def _setup_pkg_remedy_fn(js):
    return js.split("function setupPkgRemedyText(pkg) {", 1)[1].split(
        "\n  function setupShowUnknown", 1)[0]


def _setup_pkg_reason_map(js):
    return js.split("var SETUP_PKG_REASON_TEXT = {", 1)[1].split(
        "\n  };", 1)[0]


def test_mismatch_reason_gets_its_own_guidance_not_the_rebuild_remedy():
    """served-vs-distributed-mismatch must render mismatch-specific text,
    and the package-rebuild remedy line must be structurally unreachable
    when that reason is set. Rebuilding does not fix a mismatch
    (setup_status.build_status forces state='unknown', never 'stale', for
    this reason) -- so handing the operator the rebuild remedy here is
    exactly the wrong advice the fix removes."""
    js = _webroot("app.js")
    reason_map = _setup_pkg_reason_map(js)
    assert "'served-vs-distributed-mismatch':" in reason_map
    mismatch_text = reason_map.split(
        "'served-vs-distributed-mismatch':", 1)[1].split(
        "'distributed-cert-unavailable':", 1)[0]
    assert "match" in mismatch_text.lower()
    # The explanation may legitimately SAY rebuilding won't help, but must
    # never contain the rebuild instruction/remedy path itself.
    assert "Rebuild on the Docker host" not in mismatch_text
    assert "provision-iox-packages.sh" not in mismatch_text

    fn = _setup_pkg_remedy_fn(js)
    # Wave C generalized this from a single card-level pkg.remedy (one
    # rebuild command for the whole card) to a per-ITEM remedy, because the
    # IOx tars and the new iris-xr.rpm row are rebuilt by two DIFFERENT
    # scripts -- a cert rotation can leave both families stale at once, and
    # a single hardcoded command could no longer speak for the card. The
    # push must still require BOTH the outer mismatch-reason gate AND each
    # item's own state being 'stale' (not merely non-ok); losing either
    # half of this guard (e.g. falling back to "any non-ok item gets the
    # rebuild line", or dropping the outer mismatch gate) is exactly the
    # bug this test guards against.
    assert "if (pkg.reason !== 'served-vs-distributed-mismatch') {" in fn
    assert "i.state === 'stale'" in fn


def test_remedy_text_dedupes_and_joins_multiple_stale_remedies():
    """A cert rotation can stale an IOx tar and iris-xr.rpm at once (both
    bake the same certificate) -- their two DIFFERENT rebuild scripts must
    both show up, deduplicated (two stale tars sharing REMEDY must not
    print the same command twice), joined into one line rather than one
    remedy silently winning over the other."""
    js = _webroot("app.js")
    fn = _setup_pkg_remedy_fn(js)
    assert "remedies.indexOf(i.remedy) === -1" in fn
    assert "remedies.join('; ')" in fn


def test_distributed_cert_unavailable_reason_explains_itself():
    """distributed-cert-unavailable must say the distributed copy couldn't
    be read and that package state can't be confirmed -- not the generic
    rebuild line, which assumes a package is actually known to be stale."""
    js = _webroot("app.js")
    reason_map = _setup_pkg_reason_map(js)
    assert "'distributed-cert-unavailable':" in reason_map
    text = reason_map.split("'distributed-cert-unavailable':", 1)[1]
    assert "could not be read" in text
    assert "cannot be confirmed" in text


def test_refresh_setup_paints_unknown_on_failed_or_thrown_fetch():
    """A failed status fetch (non-ok response) or a thrown/network error
    must never leave the PREVIOUS render on screen -- that would be
    evidence-free chips still reading "done". Both paths must route
    through the same reset, which must paint all five chips unknown and
    clear the package table and remedy line (spec: never silently render a
    stale/empty checklist as if it were healthy)."""
    js = _webroot("app.js")
    rf = js.split("async function refreshSetup() {", 1)[1].split(
        "\n  async function refreshSettings", 1)[0]
    assert "try {" in rf and "catch (e)" in rf

    ok_branch = rf.split("if (!r.ok)", 1)[1].split("\n", 1)[0]
    assert "setupShowUnknown()" in ok_branch, \
        "a failed (non-ok) fetch must reset the pane, not just bail out"

    catch_branch = rf.split("catch (e) {", 1)[1].split("}", 1)[0]
    assert "setupShowUnknown()" in catch_branch, \
        "a thrown/network error must reset the pane too"

    reset = js.split("function setupShowUnknown() {", 1)[1].split(
        "\n  }", 1)[0]
    for chip_id in ("setup-admin-chip", "setup-td-chip", "setup-sh-chip",
                    "setup-pkg-chip", "setup-iv-chip"):
        assert ("getElementById('%s')" % chip_id) in reset
    assert reset.count("setupChip('unknown')") == 5
    assert "#setup-pkg-table tbody" in reset
    assert "setup-pkg-remedy" in reset


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


# ---------------------------------------------------------------------------
# Task 9: the Magnetic Stepper flow -- a real fourth step (Image
# verification), the left-panel/right-content anatomy, and the M37 fold-in
# (a configured-but-never-succeeded schedule reads differently from a truly
# unconfigured one). Same source-guard idiom as the rest of this file: no JS
# runtime harness exists in this repo, so these assert on the SOURCE TEXT.
# ---------------------------------------------------------------------------

def test_wizard_steplist_carries_four_steps_including_image_verification():
    js = _webroot("app.js")
    steps = js.split("var WIZARD_STEPS = [", 1)[1].split("];", 1)[0]
    for key in ("telemetry", "stage_host", "packages", "image_verification"):
        assert ("key: '%s'" % key) in steps, key
    assert steps.count("{ id:") == 4


def test_wizard_step_four_is_image_verification_with_a_form_mount():
    html = _webroot("index.html")
    wiz = html.split('id="view-setup"', 1)[1].split("</section>", 1)[0]
    assert 'id="wz-step-imageverification"' in wiz
    step = wiz.split('id="wz-step-imageverification"', 1)[1].split(
        "</div>", 1)[0]
    assert 'id="wz-iv-mount"' in step
    assert 'id="wz-iv-chip"' in step
    # a mount point, not inlined markup -- the moved #iv-content supplies the
    # actual controls at runtime (mountImageVerification)
    assert "<form" not in step


def test_wizard_uses_the_left_panel_right_content_stepper_anatomy():
    """Captured anatomy (agentinfo/facelift-2026-08-30-visual-direction.md
    lines 63-70): left step panel ~320px, content area right. wz-steplist
    must live in the panel column and every wz-step-*/wz-nav in the content
    column, not stacked flat above them as the pre-Task-9 layout did."""
    html = _webroot("index.html")
    css = _webroot("styles.css")
    wiz = html.split('id="view-setup"', 1)[1].split("</section>", 1)[0]
    panel = wiz.split('class="wz-panel"', 1)[1].split("</div>", 1)[0]
    assert 'id="wz-steplist"' in panel
    content = wiz.split('class="wz-content"', 1)[1]
    for marker in ("wz-step-telemetry", "wz-step-stagehost", "wz-step-packages",
                   "wz-step-imageverification", 'id="wz-nav"'):
        assert marker in content, marker
    assert ".wz-panel {" in css and "320px" in css.split(".wz-panel {", 1)[1].split("}", 1)[0]


def test_image_verification_content_is_moved_not_cloned_between_setup_and_settings():
    """Unlike the telemetry/stage-host forms (a <template>, cloned fresh per
    mount, re-wired each time via FORM_MOUNTS), the Image verification
    controls bind their handlers once at load -- so relocating them must be a
    live DOM move (appendChild), never a second clone that would duplicate
    ids or leave the original's listeners behind."""
    html = _webroot("index.html")
    js = _webroot("app.js")
    assert 'id="iv-content"' in html
    # #iv-content's static home is inside the Settings pane, not a <template>
    bulkhash_pane = html.split('id="settings-pane-bulkhash" hidden>', 1)[1]
    assert 'id="iv-content"' in bulkhash_pane.split("</section>", 1)[0]
    fn = js.split("function mountImageVerification(hostId) {", 1)[1].split(
        "\n  }", 1)[0]
    assert "cloneNode" not in fn
    assert "appendChild(content)" in fn
    assert "mountImageVerification('wz-iv-mount')" in js
    assert "mountImageVerification('settings-pane-bulkhash')" in js


def test_m37_configured_but_unrun_schedule_gets_its_own_wording():
    """M37 fold-in (carried from the KGV close-out): setup_status.py's
    image_verification card only ever reports ok/unset (a scheduled-but-
    never-run config and a truly unconfigured one both resolve to "unset"
    from that field alone -- see its docstring). The console tells them
    apart using the schedule's own mode, fetched separately from
    /api/settings/image-verification, and renders a distinct label rather
    than conflating the two."""
    js = _webroot("app.js")
    assert "'Configured — no successful run yet'" in js
    assert "function fetchIvScheduleConfigured()" in js
    fn = js.split("function fetchIvScheduleConfigured() {", 1)[1].split(
        "\n  }", 1)[0]
    assert "'/api/settings/image-verification'" in fn
    assert "(iv.mode || 'off') !== 'off'" in fn
    item_fn = js.split("function setupItemChipHTML(key, state, ivScheduleConfigured) {", 1)[1].split(
        "\n  }", 1)[0]
    assert "configured_unrun" in item_fn
    assert "key === 'image_verification'" in item_fn


def test_setup_pills_route_through_the_real_status_pill_system():
    """Task 9: the Setup pane's ad-hoc badge-* chips became real Magnetic
    status pills (levelPillHTML) -- setupChip keeps its name and its pinned
    setupChip('unknown') call (test_refresh_setup_paints_unknown_on_failed_
    or_thrown_fetch above), but its body now renders through the shared pill
    renderer instead of a bespoke <span class="badge ...">."""
    js = _webroot("app.js")
    fn = js.split("function setupChip(state, levelOverride) {", 1)[1].split(
        "\n  }", 1)[0]
    assert "levelPillHTML(" in fn
    assert "class=\"badge " not in fn


def test_absent_package_state_renders_inactive_not_warning():
    """Fix wave (reviewer Critical): 'absent' means a package for an
    architecture this deployment does not build -- console.md's own words,
    "needs no action" -- not an operator gap. setup_status._RANK ranks
    absent ABOVE ok in the worst-of roll-up, so any single-architecture
    deployment (one of iris-amd64.tar/iris-arm64.tar never built on
    purpose) rolls packages.state up to 'absent' and would otherwise paint
    a permanent false amber Warning in both Settings > Setup and wizard
    step 3, with nothing the operator could do to clear it. The server side
    only pins the raw state string (setup_status.py has no concept of a
    client-side pill level at all) -- this is the client-side level pin
    that was missing."""
    js = _webroot("app.js")
    levels = js.split("var SETUP_CHIP_LEVELS = {", 1)[1].split("\n  };", 1)[0]
    assert "absent: 'inactive'" in levels
    assert "absent: 'warning'" not in levels
