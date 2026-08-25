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


def _call(d, served, admin="admin", stage_host=None,
         telemetry_override_endpoint=None, telemetry_override_enabled=None,
         telemetry_env_endpoint="", telemetry_env_enabled=False):
    return setup_status.build_status(
        d, served, os.path.join(d, "iris-catalog.pem"), admin, stage_host,
        telemetry_override_endpoint, telemetry_override_enabled,
        telemetry_env_endpoint, telemetry_env_enabled)


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


def test_setup_pane_has_a_telemetry_card_linked_to_the_telemetry_settings():
    html = _webroot("index.html")
    js = _webroot("app.js")
    assert 'id="setup-td-chip"' in html
    # scope to the card itself (between its heading and the next h3) so this
    # cannot pass merely because the sidebar nav happens to link there too
    card = html.split('id="setup-td-chip"', 1)[1].split("<h3>", 1)[0]
    assert 'href="#settings/telemetry"' in card
    assert "published anywhere" in card.lower()
    assert "s.telemetry.state" in js
    assert "setupTelemetryNote" in js


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
    # The rebuild-remedy push must require BOTH a confirmed-stale state AND
    # that the reason isn't the mismatch. Losing either half of this guard
    # (e.g. falling back to "any non-ok state gets the rebuild line") is
    # exactly the bug this test guards against.
    assert ("pkg.state === 'stale' && "
            "pkg.reason !== 'served-vs-distributed-mismatch'") in fn


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
    through the same reset, which must paint all three chips unknown and
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
                    "setup-pkg-chip"):
        assert ("getElementById('%s')" % chip_id) in reset
    assert reset.count("setupChip('unknown')") == 4
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

def test_first_run_setup_hands_off_to_the_checklist():
    setup_js = _webroot("setup.js")
    login_js = _webroot("login.js")

    # armed ONLY on a genuine first-run success, never on the 409
    ok_branch = setup_js.split("if (res.ok) {", 1)[1].split("} else if", 1)[0]
    assert "iris_post_setup" in ok_branch
    conflict = setup_js.split("res.status === 409", 1)[1].split("} else", 1)[0]
    assert "iris_post_setup" not in conflict, \
        "a 409 means setup already ran; it must not arm the handoff"

    # consumed once, and it must land on the Setup pane
    assert "iris_post_setup" in login_js
    assert "'/#settings/setup'" in login_js
    assert "removeItem('iris_post_setup')" in login_js, \
        "the handoff must be one-shot, or every later sign-in lands there"
