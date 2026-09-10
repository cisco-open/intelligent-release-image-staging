# server/tests/test_gui_onboard.py
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import os
import re
import subprocess
import threading
import time
from types import SimpleNamespace

import catalog as catalog_mod
import gui_fleet
import deployment_records
import gui_onboard
import pytest


class _Fleet:
    def __init__(self, devs):
        self._d = devs
        self.upserts = []

    def get_device(self, did): return self._d.get(did)

    def upsert(self, record):
        self.upserts.append(dict(record))
        did = record["device_id"]
        merged = dict(self._d.get(did, {}))
        merged.update(record)
        self._d[did] = merged
        return merged

    def update_observation(self, device_id, *, model=None, os_family=None):
        record = {"device_id": device_id}
        if model is not None:
            record["model"] = model
        if os_family is not None:
            record["os_family"] = os_family
        return self.upsert(record)


class _Creds:
    def __init__(self, profs): self._p = profs
    def get_secrets(self, pid): return self._p.get(pid)


class _CredsSH(_Creds):
    """A creds store that also has stage-host credentials (like CredentialStore)."""
    def __init__(self, profs, stage_host=None):
        _Creds.__init__(self, profs)
        self._sh = stage_host
    def stage_host_secrets(self): return self._sh


class _CorruptFleet:
    def get_device(self, _device_id):
        raise gui_fleet.FleetStateError("corrupt fleet shard")


def _wait(svc, job_id, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        j = svc.get_job(job_id)
        if j and j["state"] in ("done", "error", "cancelled"):
            return j
        time.sleep(0.01)
    return svc.get_job(job_id)


# Guest Shell now runs a collision preflight at job start, like every other
# platform. The many tests about job MECHANICS would otherwise shell out to a
# real device, so default it to "clean device" here; the tests that exercise
# the preflight itself call the real implementation through this reference.
_REAL_GUESTSHELL_PREFLIGHT = gui_onboard._default_guestshell_preflight


@pytest.fixture(autouse=True)
def _clean_guestshell_preflight(monkeypatch):
    monkeypatch.setattr(
        gui_onboard, "_default_guestshell_preflight",
        lambda dev, env, resolved, repo_root: {
            "status": "passed", "device_identity": "FOC0000TEST"})


def _svc(run_fn, stage_host=None, **kw):
    fleet = _Fleet({"d1": {"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
                           "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                           "guest_ip": "10.0.0.3", "model": "C9300",
                           "management_type": "routed",
                           "credential_profile_id": "lab"}})
    profs = {"lab": {"device_user": "admin", "device_pass": "s3cret",
                     "enable_secret": "en"}}
    # stage_host=None -> a plain _Creds WITHOUT stage_host_secrets, proving the
    # service tolerates credential stores that predate stage-host support
    creds = _Creds(profs) if stage_host is None else _CredsSH(profs, stage_host)
    # This fleet resolves to guestshell, which now gets a live job-start
    # reachability probe (gui_onboard.py's onboard job-start gate). Default
    # it to "reachable" so the many tests unrelated to that gate keep
    # exercising run_fn as before; tests of the gate itself override
    # probe_fn explicitly via **kw.
    kw.setdefault("probe_fn", lambda dev, env: "C9300")
    # Guest Shell now runs the same collision preflight as every other
    # platform, so a job-start would otherwise shell out to a real device.
    # Default it to "clean device" for the many tests that are about job
    # mechanics; tests of the preflight itself override it via **kw.
    kw.setdefault("guestshell_preflight_fn",
                  lambda dev, env, resolved: {"status": "passed",
                                              "device_identity": "FOC0000TEST"})
    kw.setdefault("mint_fn", lambda did: "TOK-" + did)
    return gui_onboard.OnboardService(
        fleet, creds, device_install="/fake/device-install.sh",
        crt_public="/fake/crt.pem", host_ip="10.9.9.9",
        run_fn=run_fn, **kw)


def test_forget_host_key_returns_error_when_fleet_shard_is_corrupt():
    svc = _svc(lambda *_args, **_kwargs: 0)
    svc.fleet = _CorruptFleet()

    assert svc.forget_host_key("d1") == (False, "fleet state unavailable")


def test_onboard_assembles_env_and_streams(tmp_path):
    seen = {}

    def fake_run(install_path, env, on_line):
        seen["install_path"] = install_path
        seen["env"] = env
        on_line("[1/6] flash pre-check")
        on_line("[6/6] done")
        return 0

    svc = _svc(fake_run)
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done" and job["returncode"] == 0
    assert job["lines"][-2:] == ["[1/6] flash pre-check", "[6/6] done"]
    env = seen["env"]
    assert seen["install_path"] == "/fake/device-install.sh"
    assert env["DEVICE_IP"] == "10.0.0.1" and env["DEVICE_ID"] == "d1"
    assert env["VLAN"] == "666" and env["SVI_MASK"] == "255.255.255.252"
    assert env["CATALOG_TOKEN"] == "TOK-d1"
    assert env["CATALOG_URL"] == "https://10.9.9.9:8443"
    assert env["STAGE_HOST"] == "10.9.9.9"
    assert env["DEVICE_USER"] == "admin" and env["DEVICE_PASS"] == "s3cret"
    assert env["DEVICE_ENABLE"] == "en"
    assert env["IRIS_CRT_FILE"] == "/fake/crt.pem"


def test_onboard_nonzero_exit_is_error(tmp_path):
    svc = _svc(lambda p, e, on: (on("boom"), 2)[1])
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error" and job["returncode"] == 2


# --- job-start reachability gate (console onboard of an unreachable device
# must never go silent -- issue: a mistyped device IP produced no visible
# error, no batch-panel job, and no audit record) -----------------------

def test_job_start_reachability_gate_fails_before_run_and_audits():
    run_calls = []
    audit_calls = []
    svc = _svc(lambda p, e, on: run_calls.append(1) or 0,
               probe_fn=lambda dev, env: None,   # unreachable: probe fails
               audit_fn=lambda **kw: audit_calls.append(kw))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error"
    assert any("cannot reach device 10.0.0.1" in l for l in job["lines"])
    assert not run_calls   # the installer must never run against an unreachable box
    finishes = [c for c in audit_calls if c.get("event") == "onboard_finished"]
    assert finishes, "probe failure must still emit the existing onboard audit event"
    assert finishes[0]["category"] == "onboard"
    assert finishes[0]["result"] == "fail"
    assert finishes[0]["target"] == "d1"
    assert "cannot reach device 10.0.0.1" in finishes[0]["detail"]


def test_job_start_reachability_gate_passes_reachable_device_through():
    run_calls = []
    svc = _svc(lambda p, e, on: run_calls.append(1) or 0,
               probe_fn=lambda dev, env: "C9300")
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert run_calls == [1]


def test_onboard_unknown_device_errors(tmp_path):
    svc = _svc(lambda p, e, on: 0)
    job = _wait(svc, svc.start("nope"))
    assert job["state"] == "error"
    assert any("unknown device" in l for l in job["lines"])


def test_onboard_missing_credential_errors(tmp_path):
    fleet = _Fleet({"d1": {"device_id": "d1", "device_ip": "10.0.0.1",
                           "management_type": "routed",
                           "credential_profile_id": "missing"}})
    creds = _Creds({})
    svc = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                     mint_fn=lambda d: "t", run_fn=lambda p, e, on: 0)
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error"
    assert any("credential" in l.lower() for l in job["lines"])


def test_enable_secret_defaults_to_device_pass(tmp_path):
    fleet = _Fleet({"d1": {"device_id": "d1", "device_ip": "10.0.0.1",
                           "model": "C9300", "management_type": "routed",
                           "credential_profile_id": "lab"}})
    creds = _Creds({"lab": {"device_user": "u", "device_pass": "pw",
                            "enable_secret": ""}})
    seen = {}
    svc = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                     mint_fn=lambda d: "t",
                                     run_fn=lambda p, e, on: seen.update(e) or 0,
                                     probe_fn=lambda dev, env: "C9300")
    _wait(svc, svc.start("d1"))
    assert seen["DEVICE_ENABLE"] == "pw"


def test_get_job_unknown_none():
    svc = _svc(lambda p, e, on: 0)
    assert svc.get_job("nope") is None


def test_device_install_env_override(monkeypatch):
    monkeypatch.setenv("IRIS_DEVICE_INSTALL", "/custom/installer.sh")
    svc = gui_onboard.OnboardService(_Fleet({}), _Creds({}), host_ip="10.9.9.9")
    assert svc.device_install == "/custom/installer.sh"
    # explicit arg still wins over the env
    svc2 = gui_onboard.OnboardService(_Fleet({}), _Creds({}), host_ip="10.9.9.9",
                                      device_install="/explicit.sh")
    assert svc2.device_install == "/explicit.sh"


def test_old_terminal_onboard_jobs_evicted():
    clock = {"t": 1000}
    fleet = _Fleet({"d1": {"device_id": "d1", "device_ip": "10.0.0.1",
                           "model": "C9300", "management_type": "routed",
                           "credential_profile_id": "lab"}})
    creds = _Creds({"lab": {"device_user": "u", "device_pass": "p",
                            "enable_secret": ""}})
    svc = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                     mint_fn=lambda d: "t",
                                     run_fn=lambda p, e, on: 0,
                                     now_fn=lambda: clock["t"],
                                     probe_fn=lambda dev, env: "C9300")
    j1 = svc.start("d1")
    assert _wait(svc, j1)["state"] == "done"
    assert svc.get_job(j1) is not None            # retained while fresh
    clock["t"] = 1000 + 3601                       # advance past the TTL
    j2 = svc.start("d1")                            # triggers the sweep
    assert _wait(svc, j2)["state"] == "done"
    assert svc.get_job(j1) is None                 # j1 evicted
    assert svc.get_job(j2) is not None


def test_stage_host_creds_never_reach_the_recipe_env(monkeypatch):
    # Rewritten: this used to assert HOST_USER/HOST_PASS were exported from
    # the store, which encoded the defect -- _build_env forces
    # IRIS_STAGE_LOCAL=1, so no recipe can reach the ssh branch that reads
    # them, and the password was copied into every installer's env for
    # nothing.
    monkeypatch.delenv("HOST_USER", raising=False)
    monkeypatch.delenv("HOST_PASS", raising=False)
    seen = {}

    def fake_run(p, e, on):
        seen["env"] = e
        return 0

    svc = _svc(fake_run, stage_host={"username": "svc", "password": "hostpw"})
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert seen["env"]["IRIS_STAGE_LOCAL"] == "1"
    assert "HOST_USER" not in seen["env"]
    assert "HOST_PASS" not in seen["env"]
    assert "hostpw" not in repr(seen["env"])
    # the password never appears in the streamed job lines
    assert all("hostpw" not in ln for ln in job["lines"])


def test_inherited_stage_host_env_is_dropped_from_the_recipe_env(monkeypatch):
    # Rewritten from the old "process env passes through" contract for the
    # same reason as above: a stage-host password no recipe can use must not
    # ride into the installer and its ssh children from the server's own
    # environment either.
    monkeypatch.setenv("HOST_USER", "envuser")
    monkeypatch.setenv("HOST_PASS", "envpw")
    seen = {}

    def fake_run(p, e, on):
        seen["env"] = e
        return 0

    for stage_host in (None, {"username": "svc", "password": "hostpw"}):
        svc = _svc(fake_run, stage_host=stage_host)
        _wait(svc, svc.start("d1"))
        assert "HOST_USER" not in seen["env"]
        assert "HOST_PASS" not in seen["env"]
        assert "envpw" not in repr(seen["env"])


def test_no_stage_host_no_env_leaves_unset(monkeypatch):
    monkeypatch.delenv("HOST_USER", raising=False)
    monkeypatch.delenv("HOST_PASS", raising=False)
    seen = {}

    def fake_run(p, e, on):
        seen["env"] = e
        return 0

    svc = _svc(fake_run, stage_host=None)
    _wait(svc, svc.start("d1"))
    assert "HOST_USER" not in seen["env"]
    assert "HOST_PASS" not in seen["env"]


def test_build_env_forces_local_staging(monkeypatch):
    # The console always runs co-located with the artifact server, so it must
    # always tell device-install.sh to stage locally (no ssh-to-self, no
    # HOST_USER/HOST_PASS requirement) -- see IRIS_STAGE_LOCAL in
    # device/device-install.sh step [2/6].
    monkeypatch.delenv("IRIS_ARTIFACTS_DIR", raising=False)
    svc = _svc(lambda p, e, on: 0)
    _dev, env = svc._build_env("d1")
    assert env["IRIS_STAGE_LOCAL"] == "1"
    assert env["IRIS_ARTIFACTS_DIR"] == "/srv/artifacts"


def test_build_env_honors_iris_artifacts_dir_env(monkeypatch):
    monkeypatch.setenv("IRIS_ARTIFACTS_DIR", "/custom/artifacts")
    svc = _svc(lambda p, e, on: 0)
    _dev, env = svc._build_env("d1")
    assert env["IRIS_STAGE_LOCAL"] == "1"
    assert env["IRIS_ARTIFACTS_DIR"] == "/custom/artifacts"


def test_build_env_uses_service_artifact_and_certificate_paths(monkeypatch):
    monkeypatch.setenv("IRIS_ARTIFACTS_DIR", "/old/artifacts")
    monkeypatch.setenv("IRIS_CATALOG_CA_FILE", "/old/iris-catalog.pem")
    svc = _svc(lambda p, e, on: 0, artifacts_dir="/current/artifacts")
    _dev, env = svc._build_env("d1", mint=False)
    assert env["IRIS_ARTIFACTS_DIR"] == "/current/artifacts"
    assert env["IRIS_CRT_FILE"] == "/fake/crt.pem"
    assert "IRIS_CATALOG_CA_FILE" not in env


@pytest.mark.parametrize("config,public,explicit,expected", [
    (None, None, None, "/etc/iris/tls/crt.pem"),
    ("", "", None, "/etc/iris/tls/crt.pem"),
    ("/data/config", None, None, "/data/config/tls/crt.pem"),
    ("/data/config", "", None, "/data/config/tls/crt.pem"),
    ("/data/config", "/custom/public.pem", None, "/custom/public.pem"),
    ("/data/config", "/custom/public.pem", "/explicit/public.pem",
     "/explicit/public.pem"),
])
def test_public_certificate_follows_server_config(
        monkeypatch, config, public, explicit, expected):
    for name, value in (("IRIS_CONFIG", config), ("IRIS_CRT_PUBLIC", public)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    # IRIS_CERT includes the server private key and is never a device CA.
    monkeypatch.setenv("IRIS_CERT", "/run/iris/tls/cert.pem")
    svc = gui_onboard.OnboardService(_Fleet({}), _Creds({}), crt_public=explicit)
    assert svc.crt_public == expected


@pytest.mark.parametrize("platform,management_type,model", [
    ("guestshell", "routed", "C9300"),
    ("router", "router-routed", "C8000V"),
    ("router", "router-nat", "C8000V"),
    ("iox", "routed", "IE-3400"),
    ("xr-appmgr", "xr-host", "8010"),
])
@pytest.mark.parametrize("device_log", [None, "on"])
def test_kubernetes_environment_supports_every_installer_dry_run(
        monkeypatch, tmp_path, platform, management_type, model, device_log):
    config = tmp_path / "data" / "config"
    certificate = config / "tls" / "crt.pem"
    certificate.parent.mkdir(parents=True)
    # Guest Shell/router dry-run output embeds this exact public file.
    certificate.write_text("public-device-certificate-fixture\n")
    monkeypatch.setenv("IRIS_CONFIG", str(config))
    monkeypatch.delenv("IRIS_CRT_PUBLIC", raising=False)
    monkeypatch.setenv("IRIS_LOG", "/data/log")
    monkeypatch.setenv("IRIS_STATE", "/data/state")
    monkeypatch.setenv("IRIS_SSH_LEGACY", "1")
    monkeypatch.setenv("IRIS_CRT_FILE", "/stale/crt.pem")
    monkeypatch.setenv("IRIS_CATALOG_CA_FILE", "/stale/catalog.pem")
    monkeypatch.setenv("IRIS_ARTIFACTS_DIR", str(tmp_path / "data" / "artifacts"))
    device = {
        "device_id": "d1", "device_ip": "192.0.2.1", "platform": platform,
        "management_type": management_type, "model": model,
        "credential_profile_id": "lab", "vlan": "666", "svi_ip": "10.0.0.2",
        "svi_mask": "255.255.255.252", "guest_ip": "10.0.0.3",
        "app_ip": "10.0.0.3", "app_mask": "255.255.255.252",
        "app_gateway": "10.0.0.2", "vpg_number": "0",
        "nat_interface": "GigabitEthernet1",
    }
    svc = gui_onboard.OnboardService(
        _Fleet({"d1": device}),
        _Creds({"lab": {"device_user": "admin", "device_pass": "test-only"}}),
        host_ip="192.0.2.10", mint_fn=lambda did: "test-enrollment-token")
    env_extra = {"IRIS_LOG": device_log} if device_log else None
    dev, env = svc._build_env("d1", env_extra=env_extra)
    _, script = svc._resolve("d1", dev, env)
    assert env["IRIS_CRT_FILE"] == str(certificate)
    assert "IRIS_CATALOG_CA_FILE" not in env
    assert env.get("IRIS_LOG") == device_log
    assert env["IRIS_STATE"] == "/data/state"  # persistent device SSH trust
    assert env["IRIS_SSH_LEGACY"] == "1"
    result = subprocess.run(["bash", script, "--dry-run"], env=env,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    if platform in ("guestshell", "router"):
        assert certificate.read_text() in result.stdout
    else:
        assert "IRIS_LOG=%s" % (device_log or "off") in result.stdout
    # The same filtering applies to teardown without minting enrollment.
    _, teardown_env = svc._build_env("d1", mint=False, env_extra=env_extra)
    assert teardown_env.get("IRIS_LOG") == device_log
    assert teardown_env["CATALOG_TOKEN"] == ""


def test_build_env_raises_without_management_type():
    """Task 2 (spec decision 6): _build_env used to default a missing
    attachment/management_type to "routed" -- a PARTIAL rename that kept
    that default would silently retarget teardown scope instead of erroring.
    A target dict (device row or resolved plan) lacking management_type
    must fail loud."""
    fleet = _Fleet({"d1": {"device_id": "d1", "device_ip": "10.0.0.1",
                           "credential_profile_id": "lab"}})
    creds = _Creds({"lab": {"device_user": "u", "device_pass": "p",
                            "enable_secret": "e"}})
    svc = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                     run_fn=lambda p, e, on: 0,
                                     mint_fn=lambda d: "TOK")
    with pytest.raises(KeyError, match="management_type"):
        svc._build_env("d1", mint=False)


# --- resolve_platform ---------------------------------------------------

def test_resolve_platform_explicit_wins_over_model():
    dev = {"device_id": "d1", "platform": "iox", "model": "C9300-48UXM"}
    assert gui_onboard.resolve_platform(dev) == "iox"


def test_resolve_platform_bad_explicit_raises():
    dev = {"device_id": "d1", "platform": "nonsense"}
    try:
        gui_onboard.resolve_platform(dev)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "guestshell" in str(exc) and "iox" in str(exc)


def test_resolve_platform_model_map_iox():
    for model in ("IE-3400", "ie-3400", "IR1101", "IR1800"):
        assert gui_onboard.resolve_platform({"device_id": "d", "model": model}) == "iox", model


def test_resolve_platform_model_map_guestshell():
    for model in ("C9300-48UXM", "c9300-48uxm", "ISR4451", "ASR1001", "CSR1000v"):
        assert gui_onboard.resolve_platform({"device_id": "d", "model": model}) == "guestshell", model


def test_resolve_platform_model_map_catalyst_8000_router():
    for model in ("C8000V", "c8000v", "C8200-1N-4T", "C8300-2N2S-6T", "C8500-12X"):
        assert gui_onboard.resolve_platform({"device_id": "d", "model": model}) == "router", model


def test_c8000_explicit_guestshell_is_rejected():
    with pytest.raises(ValueError, match="platform router or iox"):
        gui_onboard.resolve_platform({"device_id": "d", "model": "C8000V",
                                      "platform": "guestshell"})


def test_resolve_platform_unknown_model_raises_with_guidance():
    dev = {"device_id": "d7", "model": "WS-C2960"}
    try:
        gui_onboard.resolve_platform(dev)
        assert False, "expected ValueError"
    except ValueError as exc:
        msg = str(exc)
        assert "d7" in msg and "platform" in msg and "model" in msg


def test_resolve_platform_no_model_no_probe_raises():
    dev = {"device_id": "d9"}
    try:
        gui_onboard.resolve_platform(dev)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "d9" in str(exc)


def test_resolve_platform_uses_probe_when_no_model():
    dev = {"device_id": "d1"}
    calls = []

    def probe(d):
        calls.append(d)
        return "IE-3400"

    assert gui_onboard.resolve_platform(dev, probe=probe) == "iox"
    assert calls == [dev]


def test_resolve_platform_probe_returning_none_raises():
    dev = {"device_id": "d1"}
    try:
        gui_onboard.resolve_platform(dev, probe=lambda d: None)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "d1" in str(exc)


def test_resolve_platform_xr_family_refuses_xe_recipe():
    # ASR 9000 runs IOS-XR. ^ASR would otherwise map it to guestshell.
    dev = {"device_id": "d1", "model": "ASR-9906"}
    try:
        gui_onboard.resolve_platform(dev, os_family="xr")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "IOS-XR" in str(exc)
        assert "d1" in str(exc)


def test_resolve_platform_xr_family_refuses_even_explicit_xe_platform():
    # An operator forcing platform=guestshell on an XR box is still wrong.
    dev = {"device_id": "d1", "platform": "guestshell", "model": "ASR-9906"}
    try:
        gui_onboard.resolve_platform(dev, os_family="xr")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "IOS-XR" in str(exc)


def test_resolve_platform_refuses_xr_cached_on_device_record():
    # No os_family= argument at all -- only the fleet-stored record carries
    # the cached family. gui_server._plan calls resolve_platform(device) with
    # no keyword, so the record itself must be enough to refuse.
    dev = {"device_id": "d1", "model": "ASR-9906", "os_family": "xr"}
    try:
        gui_onboard.resolve_platform(dev)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "IOS-XR" in str(exc)
        assert "d1" in str(exc)


def test_resolve_platform_record_family_refuses_without_argument_for_explicit_platform():
    # A cached record family must refuse even when the device also carries an
    # explicit platform -- an explicit platform cannot bypass a cached family.
    dev = {"device_id": "d1", "platform": "guestshell", "model": "ASR-9906",
           "os_family": "xr"}
    try:
        gui_onboard.resolve_platform(dev)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "IOS-XR" in str(exc)


def test_resolve_platform_xe_family_still_resolves_asr_to_guestshell():
    # ASR 1000 IS IOS-XE and must keep working exactly as before.
    dev = {"device_id": "d1", "model": "ASR1001-X"}
    assert gui_onboard.resolve_platform(dev, os_family="xe") == "guestshell"


def test_resolve_platform_unknown_family_behaves_as_before():
    # os_family omitted or '' -> unchanged legacy behaviour.
    dev = {"device_id": "d1", "model": "C9300-48UXM"}
    assert gui_onboard.resolve_platform(dev) == "guestshell"
    assert gui_onboard.resolve_platform(dev, os_family="") == "guestshell"


def test_resolve_platform_refuses_xr_discovered_by_probe():
    # First contact: nothing cached, so the entry guard sees os_family=None.
    # The probe learns the family; resolution must refuse on THAT, not fall
    # through to the model map (where ^ASR would return 'guestshell').
    dev = {"device_id": "d1"}

    def probe(d):
        d["os_family"] = "xr"
        return "ASR-9906"

    try:
        gui_onboard.resolve_platform(dev, probe=probe)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "IOS-XR" in str(exc)


def test_resolve_platform_probes_ambiguous_model_for_family():
    # A cached model with no os_family short-circuits on the model map on
    # every later onboard. ^ASR spans both IOS-XE and IOS-XR, so a cached
    # 'ASR-9906' with no classified family must not resolve to guestshell --
    # it must consult the probe first and refuse once the probe learns 'xr'.
    dev = {"device_id": "d1", "model": "ASR-9906"}

    def probe(d):
        d["os_family"] = "xr"

    try:
        gui_onboard.resolve_platform(dev, probe=probe)
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "IOS-XR" in str(exc)


def test_resolve_platform_unambiguous_model_does_not_probe():
    # C9300 is never IOS-XR -- probing it would be a needless SSH round-trip
    # on every onboard.
    dev = {"device_id": "d1", "model": "C9300-48UXM"}
    calls = []

    def probe(d):
        calls.append(d)

    assert gui_onboard.resolve_platform(dev, probe=probe) == "guestshell"
    assert calls == []


def test_resolve_platform_unrecognized_model_refuses_when_record_carries_xr():
    # The entry guard is (os_family or dev.get("os_family")) == "xr": an
    # explicit os_family= argument that disagrees with the cached record
    # short-circuits it before dev's own field is ever consulted. A model
    # this table does not recognize must still refuse honestly instead of
    # advising "set 'platform' (guestshell|iox|router)" -- advice no XR box
    # could ever act on.
    dev = {"device_id": "d1", "model": "N9K-C93180YC-EX", "os_family": "xr"}
    with pytest.raises(ValueError, match="IOS-XR"):
        gui_onboard.resolve_platform(dev, os_family="xe")


# --- IOS-XR: the appmgr container agent ----------------------------------
# IRIS stages to IOS-XR now (a Docker app under appmgr, writing straight to
# harddisk: through a bind mount). The family refusal therefore stops being
# absolute: 'xr-appmgr' is the ONE platform an XR device may run, and every
# IOS-XE recipe stays refused for it.

def test_resolve_platform_xr_resolves_the_appmgr_container():
    dev = {"device_id": "d1", "platform": "xr-appmgr", "model": "8201"}
    assert gui_onboard.resolve_platform(dev, os_family="xr") == "xr-appmgr"
    # and from a cached family, with no os_family argument at all
    cached = {"device_id": "d1", "platform": "xr-appmgr", "model": "8201",
              "os_family": "xr"}
    assert gui_onboard.resolve_platform(cached) == "xr-appmgr"


def test_resolve_platform_xr_without_an_explicit_platform_still_refuses():
    """Auto-resolution cannot pick the XR recipe: the model table is keyed on
    IOS-XE prefixes and an XR box's model is bare digits. The operator sets
    the platform, and the refusal has to say so."""
    dev = {"device_id": "d1", "model": "8201"}
    with pytest.raises(ValueError, match="xr-appmgr"):
        gui_onboard.resolve_platform(dev, os_family="xr")


def test_refuse_xr_message_names_the_platform_to_set():
    """The old message said to wait for XR support. That is no longer true,
    and 'forcing platform will not work' is now actively wrong advice. Since
    xr-host <-> xr-appmgr is now a mutual requirement (gui_fleet.validate_record),
    the operator needs BOTH settings named, not just the platform -- setting
    platform alone still leaves the record unclassified (legacy_routed) and
    unable to plan/deploy."""
    with pytest.raises(ValueError) as exc:
        gui_onboard._refuse_xr("d1")
    message = str(exc.value)
    assert "d1" in message and "IOS-XR" in message and "xr-appmgr" in message
    assert "xr-host" in message and "management type" in message
    assert "wait for" not in message


def test_resolve_platform_refuses_the_xr_recipe_on_an_ios_xe_device():
    """The inverse guardrail: device/xr-install.sh speaks appmgr and IOS-XR
    config mode. Handing it an IOS-XE box is the same class of mistake as
    handing device-install.sh an ASR 9000."""
    dev = {"device_id": "d1", "platform": "xr-appmgr", "model": "C9300-48UXM",
           "os_family": "xe"}
    with pytest.raises(ValueError, match="IOS-XE"):
        gui_onboard.resolve_platform(dev)


def test_xr_recipes_are_registered_and_present():
    assert gui_onboard._PLATFORM_RECIPES["xr-appmgr"] == "device/xr-install.sh"
    assert gui_onboard._UNINSTALL_RECIPES["xr-appmgr"] == "device/xr-uninstall.sh"
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(
        gui_onboard.__file__)))
    for relative in (gui_onboard._PLATFORM_RECIPES["xr-appmgr"],
                     gui_onboard._UNINSTALL_RECIPES["xr-appmgr"]):
        assert os.path.exists(os.path.join(repo_root, relative)), relative


def _xr_show_version(model="8000"):
    return ("Cisco IOS XR Software, Version 25.4.2 LNT\n"
            "cisco %s (VXR)\ncisco 8201-SYS (VXR) processor\n" % model)


def _xr_preflight_stub(monkeypatch, version=None, apps="", sources="",
                       returncode=0, seen=None):
    def run(argv, input=None, **kwargs):
        if seen is not None:
            seen["argv"] = argv
            seen["input"] = input
        return SimpleNamespace(returncode=returncode, stdout=(
            "__IRIS_PREFLIGHT_VERSION__\n"
            + (version if version is not None else _xr_show_version())
            + "\n__IRIS_PREFLIGHT_APPS__\n" + apps
            + "\n__IRIS_PREFLIGHT_SOURCES__\n" + sources))
    monkeypatch.setattr(gui_onboard.subprocess, "run", run)


def test_default_xr_preflight_passes_a_clean_router(monkeypatch):
    seen = {}
    _xr_preflight_stub(monkeypatch, apps="No entries found\n",
                       sources="No entries found\n", seen=seen)
    dev = {"device_id": "8010-R1"}
    evidence = gui_onboard._default_xr_preflight(
        dev, {"DEVICE_IP": "203.0.113.81"}, {}, "/repo")
    assert evidence == {"status": "passed", "detected_model": "8000"}
    assert dev["os_family"] == "xr"
    # driven over the XR transport, not the IOS-XE one
    assert seen["argv"][1].endswith("lab/xr-run.sh")


def test_default_xr_preflight_does_not_reprobe_free_space(monkeypatch):
    """device/xr-install.sh's own step [1/5] reads `dir harddisk:` and refuses
    below its headroom floor. Asking again here would be a second SSH login
    per device to learn a number the recipe re-reads anyway, moments later."""
    seen = {}
    _xr_preflight_stub(monkeypatch, seen=seen)
    gui_onboard._default_xr_preflight({}, {"DEVICE_IP": "10.0.0.1"}, {}, "/repo")
    assert "dir harddisk:" not in seen["input"]


def test_default_xr_preflight_refuses_an_ios_xe_device(monkeypatch):
    _xr_preflight_stub(monkeypatch, version=(
        "Cisco IOS XE Software, Version 17.9.4\n"
        "cisco C9300-48UXM (X86) processor\n"))
    dev = {"device_id": "sw1"}
    with pytest.raises(ValueError, match="IOS-XE"):
        gui_onboard._default_xr_preflight(
            dev, {"DEVICE_IP": "10.0.0.1"}, {}, "/repo")
    assert dev["os_family"] == "xe"


def test_default_xr_preflight_refuses_an_unclassifiable_banner(monkeypatch):
    """Fail closed: an unreadable banner is not proof of anything, and the
    recipe about to run speaks IOS-XR config mode."""
    _xr_preflight_stub(monkeypatch, version="garbage\n")
    with pytest.raises(ValueError, match="could not"):
        gui_onboard._default_xr_preflight(
            {}, {"DEVICE_IP": "10.0.0.1"}, {}, "/repo")


def test_default_xr_preflight_refuses_a_router_that_still_carries_iris(monkeypatch):
    """The IRIS-named collision check every platform runs, in XR's own
    vocabulary: the application and the registered package source."""
    _xr_preflight_stub(monkeypatch,
                       apps="iris  docker  iris-xr  Up  app_manager\n")
    with pytest.raises(ValueError, match="already"):
        gui_onboard._default_xr_preflight(
            {}, {"DEVICE_IP": "10.0.0.1"}, {}, "/repo")

    _xr_preflight_stub(monkeypatch,
                       sources="iris-xr  0.1.0  ThinXR_7.3.15  app_manager\n")
    with pytest.raises(ValueError, match="already"):
        gui_onboard._default_xr_preflight(
            {}, {"DEVICE_IP": "10.0.0.1"}, {}, "/repo")


def test_default_xr_preflight_ignores_a_foreign_app_of_its_own(monkeypatch):
    """Only IRIS's own names are collisions. Another operator app -- or the
    lab's leftover 'irisprobe' source -- is none of IRIS's business."""
    _xr_preflight_stub(monkeypatch,
                       apps="telemetry-agent  docker  ta  Up  app_manager\n",
                       sources="irisprobe  0.1.0  ThinXR_7.3.15  app_manager\n")
    evidence = gui_onboard._default_xr_preflight(
        {}, {"DEVICE_IP": "10.0.0.1"}, {}, "/repo")
    assert evidence["status"] == "passed"


def test_default_xr_preflight_raises_when_the_transport_fails(monkeypatch):
    _xr_preflight_stub(monkeypatch, returncode=1)
    with pytest.raises(ValueError, match="could not run"):
        gui_onboard._default_xr_preflight(
            {}, {"DEVICE_IP": "10.0.0.1"}, {}, "/repo")


def _xr_svc(run_fn, **kw):
    fleet = _Fleet({"d1": {"device_id": "d1", "device_ip": "203.0.113.81",
                           "vlan": "666", "svi_ip": "10.0.0.2",
                           "svi_mask": "255.255.255.252",
                           "guest_ip": "10.0.0.3", "model": "8010",
                           "os_family": "xr", "platform": "xr-appmgr",
                           "management_type": "xr-host",
                           "credential_profile_id": "lab"}})
    creds = _Creds({"lab": {"device_user": "admin", "device_pass": "s3cret"}})
    kw.setdefault("probe_fn", lambda dev, env: "8010")
    kw.setdefault("xr_preflight_fn",
                  lambda dev, env, resolved: {"status": "passed",
                                              "detected_model": "8010"})
    kw.setdefault("mint_fn", lambda did: "TOK-" + did)
    return gui_onboard.OnboardService(
        fleet, creds, crt_public="/fake/crt.pem", host_ip="10.9.9.9",
        run_fn=run_fn, **kw)


def test_xr_onboard_runs_the_xr_recipe_with_the_env_it_documents(tmp_path):
    """The whole point of the wiring: an XR device onboards from the console
    with the same env every other recipe gets -- device/xr-install.sh reads
    DEVICE_IP/DEVICE_ID/CATALOG_URL/CATALOG_TOKEN/DEVICE_USER/DEVICE_PASS and
    finds its RPM under IRIS_ARTIFACTS_DIR."""
    seen = {}

    def fake_run(install_path, env, on_line):
        seen["path"] = install_path
        seen["env"] = env
        return 0

    svc = _xr_svc(fake_run, artifacts_dir=str(tmp_path))
    job = _wait(svc, svc.start("d1", resolved={"platform": "xr-appmgr",
                                               "management_type": "xr-host"}))
    assert job["state"] == "done", job["lines"]
    assert seen["path"].endswith("device/xr-install.sh")
    env = seen["env"]
    assert env["DEVICE_IP"] == "203.0.113.81"
    assert env["DEVICE_ID"] == "d1"
    assert env["CATALOG_TOKEN"] == "TOK-d1"
    assert env["CATALOG_URL"] == "https://10.9.9.9:8443"
    assert env["DEVICE_USER"] == "admin" and env["DEVICE_PASS"] == "s3cret"
    assert env["IRIS_ARTIFACTS_DIR"]


def test_xr_undeploy_runs_the_xr_teardown_recipe(tmp_path):
    seen = {}

    def fake_run(install_path, env, on_line):
        seen["path"] = install_path
        return 0

    svc = _xr_svc(fake_run, artifacts_dir=str(tmp_path))
    job = _wait(svc, svc.start("d1", action="undeploy"))
    assert job["state"] == "done", job["lines"]
    assert seen["path"].endswith("device/xr-uninstall.sh")


def test_xr_onboard_refuses_when_the_preflight_refuses(tmp_path):
    ran = []

    def fake_run(install_path, env, on_line):
        ran.append(install_path)
        return 0

    def refuse(dev, env, resolved):
        dev["os_family"] = "xe"
        raise ValueError("203.0.113.81 reports IOS-XE, not IOS-XR")

    svc = _xr_svc(fake_run, artifacts_dir=str(tmp_path),
                  xr_preflight_fn=refuse)
    job = _wait(svc, svc.start("d1", resolved={"platform": "xr-appmgr",
                                               "management_type": "xr-host"}))
    assert job["state"] == "error"
    assert any("IOS-XE" in line for line in job["lines"]), job["lines"]
    assert ran == []
    # the classification it just learned is cached, like every other platform
    assert svc.fleet._d["d1"]["os_family"] == "xe"


def test_service_preflight_dispatches_the_xr_platform(tmp_path):
    svc = _xr_svc(lambda p, e, on: 0, artifacts_dir=str(tmp_path),
                  xr_preflight_fn=lambda dev, env, resolved: {
                      "status": "passed", "detected_model": "8010"})
    evidence = svc.preflight("d1", {"platform": "xr-appmgr",
                                    "management_type": "xr-host"})
    assert evidence == {"status": "passed", "detected_model": "8010"}


# --- install_options_for / normalize_model -------------------------------

def test_install_options_for_c9k_allows_guestshell_and_iox():
    for model in ("C9300-48UXM", "c9300-48uxm", "C9500-24Y4C"):
        assert gui_onboard.install_options_for(model, "") == ["guestshell", "iox"], model


def test_install_options_for_iox_only_models():
    for model in ("IE-3400", "ie-3400", "IR1101", "IR1800"):
        assert gui_onboard.install_options_for(model, "") == ["iox"], model


def test_install_options_for_c8k_router_first_then_iox():
    # Guest Shell through the VirtualPortGroup is the auto default; the IOx
    # app attaches through the same VPG and is the explicit alternative.
    for model in ("C8000V", "C8200-1N-4T", "C8300-2N2S-6T", "C8500-12X"):
        assert gui_onboard.install_options_for(model, "") == ["router", "iox"], model


def test_install_options_for_legacy_router_family_guestshell():
    for model in ("ISR4451", "ASR1001", "CSR1000v"):
        assert gui_onboard.install_options_for(model, "") == ["guestshell"], model


def test_install_options_for_xr_os_family_offers_only_the_appmgr_container():
    # os_family alone is authoritative, independent of what the model prefix
    # would otherwise suggest -- e.g. an 8000-series device matches no
    # IOS-XE row in the table -- so a blank or XR-shaped model gets the one
    # recipe that IS IOS-XR, never one of the IOS-XE three.
    assert gui_onboard.install_options_for("8201", "xr") == ["xr-appmgr"]
    assert gui_onboard.install_options_for("", "xr") == ["xr-appmgr"]


@pytest.mark.parametrize("model, expected", [
    ("IE-3400-8T2S", "IE3x00"),
    ("IE3300", "IE3x00"),
    ("IR1101", "IR1x00"),
    ("IR1800", "IR1x00"),
    ("C9300-48UXM", "C9xxx"),
    ("C8000V", "C8xxx"),
    ("ISR4451", "ISR/ASR/CSR"),
    ("ASR1001-X", "ISR/ASR/CSR"),
    ("8201-SYS", "XR8000"),
    ("N9K-C93180YC-EX", "unknown"),
    ("", "unknown"),
])
def test_family_reuses_the_install_model_taxonomy(model, expected):
    assert gui_onboard.family(model) == expected


def test_install_options_for_xr_os_family_refuses_non_8000_models():
    # v1 is validated on the Cisco 8000 series only (agentinfo plan scope:
    # "8000-series first, capability-gated"). os_family is still
    # authoritative -- neither of these falls through to an IOS-XE recipe
    # (ASR-9906 matches the ISR/ASR/CSR prefix, C9300-48UXM matches the C9k
    # prefix, and both would otherwise misroute exactly the way the 8201
    # incident did) -- but a non-8000 XR device is refused outright ([]),
    # never left as "no opinion" (None) for validate_record to wave through.
    assert gui_onboard.install_options_for("ASR-9906", "xr") == []
    assert gui_onboard.install_options_for("C9300-48UXM", "xr") == []
    assert gui_onboard.install_options_for("NCS-5501", "xr") == []


def test_install_options_for_8xxx_model_offers_xr_even_without_os_family():
    # Belt-and-suspenders: an XR-shaped model number decides on its own, even
    # when os_family was never probed/cached -- the 8201 incident this
    # guardrail closes (an 8201 offered iox and died on an XE-flavoured arch
    # error).
    for model in ("8201", "8201-SYS", "820", "8999"):
        assert gui_onboard.install_options_for(model, "") == ["xr-appmgr"], model
    # os_family omitted entirely
    assert gui_onboard.install_options_for("8201") == ["xr-appmgr"]


def test_install_options_for_unknown_or_blank_model_returns_none():
    # None means "no guardrail opinion" -- console still offers Auto, and
    # validate_record does not restrict the explicit platform choice.
    assert gui_onboard.install_options_for("", "") is None
    assert gui_onboard.install_options_for(None, None) is None
    assert gui_onboard.install_options_for("WS-C2960", "") is None


def test_install_options_for_matches_model_platforms_table():
    # The guardrail table and the auto-resolution table must not drift: every
    # family's auto-resolution default (what resolve_platform picks) is the
    # FIRST entry install_options_for returns for that same model.
    for model in ("C9300-48UXM", "IE-3400", "IR1101", "C8000V", "ISR4451"):
        options = gui_onboard.install_options_for(model, "")
        assert options[0] == gui_onboard.resolve_platform({"device_id": "d", "model": model})


def test_normalize_model_strips_sys_suffix():
    assert gui_onboard.normalize_model("8201-SYS") == "8201"
    assert gui_onboard.normalize_model("8201") == "8201"
    assert gui_onboard.normalize_model("C9300-48UXM") == "C9300-48UXM"   # untouched
    assert gui_onboard.normalize_model("") == ""
    assert gui_onboard.normalize_model(None) == ""
    assert gui_onboard.normalize_model("  8201-SYS  ") == "8201"         # whitespace trimmed


# --- _iox_arch_env ---------------------------------------------------------

def test_iox_arch_env_refuses_an_8xxx_model():
    # The live incident this closes: an 8201 resolved to iox (no preflight
    # had run yet to catch it) and only failed here, with a confusing "needs
    # a recognized device model" arch-selection error that never named
    # IOS-XR.
    with pytest.raises(ValueError, match="IOS-XR"):
        gui_onboard._iox_arch_env("d1", "8201")


def test_iox_arch_env_refuses_an_8xxx_sys_model_case_insensitively():
    with pytest.raises(ValueError, match="IOS-XR"):
        gui_onboard._iox_arch_env("d1", "8201-sys")


# --- parse_os_family ----------------------------------------------------

def test_parse_os_family_xe_banner():
    text = "Cisco IOS XE Software, Version 17.09.04a\ncisco C9300-48UXM (X86) processor\n"
    assert gui_onboard.parse_os_family(text) == "xe"


def test_parse_os_family_xr_banner():
    text = "Cisco IOS XR Software, Version 24.4.1\ncisco ASR9K (Intel 686 F6M14S4)\n"
    assert gui_onboard.parse_os_family(text) == "xr"


def test_parse_os_family_is_case_insensitive():
    assert gui_onboard.parse_os_family("cisco ios xr software, version 25.1.1") == "xr"


def test_parse_os_family_unknown_returns_empty():
    assert gui_onboard.parse_os_family("Cisco Adaptive Security Appliance Software") == ""
    assert gui_onboard.parse_os_family("") == ""


def test_parse_os_family_xr_not_confused_by_xe_substring():
    # 'IOS XE' and 'IOS XR' differ by one character; a loose match returns the
    # wrong family and silently misroutes the device.
    assert gui_onboard.parse_os_family("Cisco IOS XE Software") == "xe"
    assert gui_onboard.parse_os_family("Cisco IOS XR Software") == "xr"


def test_parse_os_family_classic_ios_is_xe_family():
    # 12.x/15.x Catalysts print no 'XE' token but are driven by the same recipes.
    assert gui_onboard.parse_os_family(
        "Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.0(2)") == "xe"


def test_parse_os_family_matches_virtual_xr_platforms():
    # XRv9000 is a virtual platform whose banner spells the token 'XRv', not
    # 'XR' followed by a boundary; a device that falls through here silently
    # misroutes to the legacy code path instead of the XR one.
    assert gui_onboard.parse_os_family(
        "cisco IOS-XRv 9000 (VXR) processor") == "xr"
    assert gui_onboard.parse_os_family("Cisco IOS XRv Software") == "xr"


def test_parse_os_family_xrv_match_does_not_over_match_xe():
    # Guard against the trailing-'v' allowance in the XR pattern bleeding
    # into XE banners.
    text = "Cisco IOS XE Software, Version 17.09.04a\ncisco C9300-48UXM (X86) processor\n"
    assert gui_onboard.parse_os_family(text) == "xe"


def test_parse_os_family_ignores_an_xr_shaped_hostname():
    # lab/device-run.sh runs `ssh -tt`, so the text handed to the classifier is
    # the whole transcript: MOTD, login banner and the prompt echoed with every
    # command. A C9300 whose hostname happens to be 'ios-xr-lab-01' is IOS-XE,
    # and a false 'xr' is UNRECOVERABLE -- _refuse_xr tells the operator that
    # forcing 'platform' will not work, and the family is cached on the fleet
    # row. Only a banner line may decide the family.
    text = ("\r\nios-xr-lab-01#show version\r\n"
            "Cisco IOS XE Software, Version 17.09.04a\r\n"
            "cisco C9300-48UXM (X86) processor\r\n"
            "ios-xr-lab-01#\r\n")
    assert gui_onboard.parse_os_family(text) == "xe"


def test_parse_os_family_ignores_an_xr_mention_in_the_login_banner():
    # Same failure through the MOTD rather than the prompt: free prose naming
    # the family is not a version banner.
    text = ("*** lab pod 4 -- IOS XR gear lives on 10.9.0.0/24 ***\r\n"
            "sw1#show version\r\n"
            "Cisco IOS XE Software, Version 17.09.04a\r\n"
            "cisco C9300-48UXM (X86) processor\r\n")
    assert gui_onboard.parse_os_family(text) == "xe"


# --- OnboardService: platform-aware recipe selection --------------------

def _iox_fleet(platform=None, model=None):
    dev = {"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
           "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
           "guest_ip": "10.0.0.3", "management_type": "routed",
           "credential_profile_id": "lab"}
    if platform is not None:
        dev["platform"] = platform
    if model is not None:
        dev["model"] = model
    return _Fleet({"d1": dev})


def _iox_creds():
    return _Creds({"lab": {"device_user": "admin", "device_pass": "s3cret",
                           "enable_secret": "en"}})


def _iox_preflight_ok(identity="FDO2547X9AB", model=None):
    """A fake iox_preflight_fn returning passing evidence -- mirrors how the
    router tests fake preflight_fn, so these tests don't make a real 'show
    version' SSH probe over lab/device-run.sh."""
    evidence = {"status": "passed", "device_identity": identity}
    if model:
        evidence["detected_model"] = model
    return lambda dev, env, resolved: evidence


def test_probe_resolves_iox_and_caches_model(tmp_path):
    fleet = _iox_fleet()  # no explicit platform/model -> falls to probe
    raw_runs = []
    controller = _FrozenIoxController()
    svc = _iox_controller_service(
        tmp_path, controller, raw_runs, fleet=fleet,
        probe_fn=lambda dev, env: "IE-3400")
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert raw_runs == []
    request = controller.requests[0]
    assert _request_value(request, "wrapper_path").endswith(
        "iris-arm64.tar")
    target = _request_value(request, "target")
    assert target["model"] == "IE-3400"
    assert "board_identity" not in target
    assert {"device_id": "d1", "model": "IE-3400"} in fleet.upserts
    # the job line reports the model the probe just found, not a placeholder
    assert any("platform: iox (model IE-3400)" in l for l in job["lines"])


def test_probe_normalizes_sys_suffix_before_caching(tmp_path):
    # '8201-SYS' and '8201' must read identically wherever a model is
    # recorded -- gui_fleet.validate_record normalizes it on the console/CSV
    # path; the probe must do the same on ITS path, or the two would drift
    # (a device onboarded via a live probe could carry a suffixed model the
    # fleet UI/API never sees on a console-entered one).
    fleet = _iox_fleet()
    creds = _iox_creds()
    dev = {"device_id": "d1", "credential_profile_id": "lab"}
    env = {"DEVICE_IP": "10.0.0.1"}

    def fake_probe(d, e):
        return "8201-SYS"

    svc = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=lambda *a, **k: 0, probe_fn=fake_probe,
        artifacts_dir=str(tmp_path))
    # '8201' has no _MODEL_PLATFORMS entry (a bare-digit IOS-XR model number),
    # so resolution itself still fails after the probe runs -- what matters
    # here is what got cached onto the fleet row, not whether onboarding
    # proceeds.
    with pytest.raises(ValueError):
        svc._resolve("d1", dev, env, "onboard")
    assert {"device_id": "d1", "model": "8201"} in fleet.upserts


def test_probe_does_not_wipe_cached_os_family(tmp_path):
    # A device previously classified "xr" (however that got recorded) must
    # keep that classification when a LATER probe finds a model but can't
    # parse a family from a truncated/unparseable banner. FleetStore.upsert
    # filters None but keeps "" (server/gui_fleet.py:291), so writing
    # os_family="" here would silently erase the "xr" tag on disk and
    # reopen the ASR9k -> guestshell misroute this guard exists to close.
    #
    # Calls _resolve() directly rather than through svc.start(): once a
    # device's os_family is cached as "xr", resolve_platform's entry guard
    # refuses it before probe() ever runs again, so the full onboard flow
    # can never exercise this closure a second time for that device. This
    # isolates the closure's own invariant -- it must never overwrite a
    # cached family with an empty one -- independent of that guard.
    fleet = _iox_fleet()
    fleet._d["d1"]["os_family"] = "xr"  # already known, from a prior probe
    creds = _iox_creds()
    # This call's dev has no cached model/family of its own -- the same
    # shape probe() always receives on a device's first classification.
    dev = {"device_id": "d1", "credential_profile_id": "lab"}
    env = {"DEVICE_IP": "10.0.0.1"}

    def fake_probe(d, e):
        # Found a model, but the banner didn't parse to a family this time.
        return "ASR-9906"

    svc = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=lambda *a, **k: 0, probe_fn=fake_probe,
        artifacts_dir=str(tmp_path))
    svc._resolve("d1", dev, env, "onboard")
    assert {"device_id": "d1", "model": "ASR-9906"} in fleet.upserts
    assert not any("os_family" in u for u in fleet.upserts)
    # The fake fleet's upsert merges onto the stored dict same as the real
    # one (minus the None/"" filtering) -- the cached family must survive.
    assert fleet._d["d1"]["os_family"] == "xr"


# The console never calls start() bare: gui_server._plan() resolves the platform
# up front, bakes it into plan["resolved"], and start() is handed that dict. So
# _build_env copies platform onto the device, resolve_platform takes the
# EXPLICIT branch, and every family check inside resolution -- the entry guard,
# the ambiguous-model re-probe, the post-probe re-check -- is bypassed. These
# two tests walk that production path; the resolution-level tests above cannot
# see it.

def _xr_probe(d, env):
    """A live probe against an ASR 9000: reads the banner, records the family
    (exactly what _default_probe does) and returns the model string."""
    d["os_family"] = "xr"
    return "ASR-9906"


def test_preresolved_guestshell_platform_still_refuses_an_xr_device(tmp_path):
    ran = []

    def fake_run(install_path, env, on_line):
        ran.append(install_path)
        return 0

    svc = _svc(fake_run, probe_fn=_xr_probe)
    svc.fleet._d["d1"]["model"] = "ASR-9906"
    job = _wait(svc, svc.start("d1", resolved={"platform": "guestshell", "management_type": "routed"}))
    assert job["state"] == "error"
    assert any("IOS-XR" in line for line in job["lines"]), job["lines"]
    # The whole point: device/device-install.sh must never be handed an
    # IOS-XR box.
    assert ran == []


def test_preresolved_onboard_caches_the_family_it_just_learned(tmp_path):
    # Nothing back-fills os_family onto existing fleet rows, so the refusal is
    # only durable if the onboard that discovered the family writes it down.
    # Without this the console re-probes (and re-refuses) on every attempt, and
    # the devices table never shows why.
    svc = _svc(lambda p, e, on: 0, probe_fn=_xr_probe)
    svc.fleet._d["d1"]["model"] = "ASR-9906"
    _wait(svc, svc.start("d1", resolved={"platform": "guestshell", "management_type": "routed"}))
    assert {"device_id": "d1", "os_family": "xr"} in svc.fleet.upserts
    assert svc.fleet._d["d1"]["os_family"] == "xr"


def test_probe_returning_none_errors_without_running(tmp_path):
    fleet = _iox_fleet()
    creds = _iox_creds()
    called = []

    def fake_run(install_path, env, on_line):
        called.append(install_path)
        return 0

    svc = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=fake_run, probe_fn=lambda dev, env: None,
        artifacts_dir=str(tmp_path))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error"
    assert called == []


def test_default_probe_records_os_family_on_dev(monkeypatch):
    banner = ("Cisco IOS XR Software, Version 24.4.1\n"
              "cisco ASR-9906 (Intel 686 F6M14S4)\n")

    class _Out:
        stdout = banner
        returncode = 0

    monkeypatch.setattr(gui_onboard.subprocess, "run", lambda *a, **k: _Out())
    dev = {"device_id": "d1"}
    model = gui_onboard._default_probe(dev, {"DEVICE_IP": "10.0.0.1"}, "/repo")
    assert model == "ASR-9906"
    assert dev["os_family"] == "xr"


def test_default_probe_still_returns_falsy_when_unreachable(monkeypatch):
    # The reachability check at gui_onboard.py:831 does `if not self._probe(...)`.
    # The return value must stay falsy on failure or that check silently breaks.
    def _boom(*a, **k):
        raise OSError("unreachable")

    monkeypatch.setattr(gui_onboard.subprocess, "run", _boom)
    dev = {"device_id": "d1"}
    assert not gui_onboard._default_probe(dev, {"DEVICE_IP": "10.0.0.1"}, "/repo")


def test_default_probe_xe_device_records_xe(monkeypatch):
    class _Out:
        stdout = "Cisco IOS XE Software, Version 17.09.04a\ncisco C9300-48UXM (X86) processor\n"
        returncode = 0

    monkeypatch.setattr(gui_onboard.subprocess, "run", lambda *a, **k: _Out())
    dev = {"device_id": "d1"}
    assert gui_onboard._default_probe(dev, {"DEVICE_IP": "10.0.0.1"}, "/repo") == "C9300-48UXM"
    assert dev["os_family"] == "xe"


def test_iox_env_has_ssh_creds(tmp_path):
    raw_runs = []
    controller = _FrozenIoxController()
    svc = _iox_controller_service(tmp_path, controller, raw_runs)
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert raw_runs == []
    request = controller.requests[0]
    assert _request_value(request, "credential_ref") == "lab"
    target = _request_value(request, "target")
    assert "DEVICE_SSH_PASS" not in target
    assert "DEVICE_SSH_USER" not in target
    assert "s3cret" not in repr(request)


def test_guestshell_env_unchanged_no_ssh_keys(tmp_path):
    seen = {}

    def fake_run(install_path, env, on_line):
        seen["env"] = env
        return 0

    svc = _svc(fake_run)
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert "DEVICE_SSH_PASS" not in seen["env"]
    assert "DEVICE_SSH_USER" not in seen["env"]


def test_router_recipe_and_env_plumbing(tmp_path):
    fleet = _Fleet({"r1": {
        "device_id": "r1", "device_ip": "192.0.2.10", "model": "C8000V",
        "platform": "router", "management_type": "router-nat",
        "vpg_number": "10", "nat_interface": "GigabitEthernet1",
        "app_ip": "10.8.0.2", "app_mask": "255.255.255.252",
        "app_gateway": "10.8.0.1", "credential_profile_id": "lab"}})
    seen = {}
    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=_run_capture(seen), artifacts_dir=str(tmp_path),
        preflight_fn=lambda dev, env, resolved: {
            "status": "passed", "device_identity": "9ABC123",
            "detected_model": "C8000V",
            "nat_interface": "GigabitEthernet1",
            "nat_outside_preexisting": False})
    job = _wait(svc, svc.start("r1"))
    assert job["state"] == "done"
    assert seen["install_path"].endswith("device/router-install.sh")
    assert seen["env"]["MANAGEMENT_TYPE"] == "router-nat"
    assert seen["env"]["VPG_NUMBER"] == "10"
    assert seen["env"]["NAT_INTERFACE"] == "GigabitEthernet1"
    assert seen["env"]["BT_LISTEN_PORT"] == "6881"
    assert seen["env"]["EXPECTED_DEVICE_IDENTITY"] == "9ABC123"
    assert "DEVICE_SSH_PASS" not in seen["env"]


def test_router_undeploy_uses_router_recipe_and_record_ownership(tmp_path):
    fleet = _Fleet({"r1": {
        "device_id": "r1", "device_ip": "192.0.2.10", "model": "C8000V",
        "platform": "router", "credential_profile_id": "lab"}})
    seen = {}
    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=_run_capture(seen), artifacts_dir=str(tmp_path))
    resolved = {"platform": "router", "management_type": "router-nat",
                "device_ip": "192.0.2.10", "device_identity": "9ABC123",
                "vpg_number": "10", "nat_interface": "GigabitEthernet1",
                "app_ip": "10.8.0.2", "app_mask": "255.255.255.252",
                "app_gateway": "10.8.0.1", "swarm_port": "6881",
                "nat_outside_owned": "1", "model": "C8000V"}
    job = _wait(svc, svc.start("r1", action="undeploy", resolved=resolved))
    assert job["state"] == "done"
    assert seen["install_path"].endswith("device/router-uninstall.sh")
    assert seen["env"]["NAT_OUTSIDE_OWNED"] == "1"


def test_router_execution_preflight_runs_before_mint_and_refreshes_env(tmp_path):
    fleet = _Fleet({"r1": {
        "device_id": "r1", "device_ip": "192.0.2.10", "model": "C8000V",
        "platform": "router", "management_type": "router-nat",
        "vpg_number": "10", "nat_interface": "Gi1",
        "app_ip": "10.8.0.2", "app_mask": "255.255.255.252",
        "app_gateway": "10.8.0.1", "credential_profile_id": "lab"}})
    events = []
    seen = {}

    def preflight(dev, env, resolved):
        events.append("preflight")
        return {"status": "passed", "device_identity": "9ABC123",
                "detected_model": "C8000V",
                "nat_interface": "GigabitEthernet1",
                "nat_outside_preexisting": True}

    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9",
        mint_fn=lambda d: events.append("mint") or "TOK",
        run_fn=lambda p, e, on: (events.append("run"), seen.update(e), 0)[2],
        preflight_fn=preflight)
    job = _wait(svc, svc.start("r1"))
    assert job["state"] == "done"
    assert events == ["preflight", "mint", "run"]
    assert seen["NAT_INTERFACE"] == "GigabitEthernet1"
    assert seen["NAT_OUTSIDE_OWNED"] == "0"
    assert seen["EXPECTED_DEVICE_IDENTITY"] == "9ABC123"


# --- fire-time instruction bootstrap custody (Task 18) ------------------

def test_guestshell_materializes_private_envelope_after_mint_before_applying(
        tmp_path):
    events = []
    observed = {}

    def preflight(dev, env, resolved):
        events.append("preflight")
        return {"status": "passed", "device_identity": "FOC0000TEST"}

    def mint(device_id):
        events.append("mint")
        return "TOK-" + device_id

    def bootstrap(device_id):
        events.append("materialize")
        assert events[-2:] == ["mint", "materialize"]
        return b"sealed-bootstrap-envelope"

    def run(_path, env, _line):
        events.append("run")
        capability = env["IRIS_STAGING_CAPABILITY"]
        assert re.fullmatch(r"[0-9a-f]{32}", capability)
        path = (tmp_path / "staging" /
                ("iris-instructions-d1-%s.envelope" % capability))
        assert path.read_bytes() == b"sealed-bootstrap-envelope"
        assert path.stat().st_mode & 0o777 == 0o600
        observed["path"] = path
        return 0

    svc = _svc(
        run, artifacts_dir=str(tmp_path), mint_fn=mint,
        instruction_bootstrap_fn=bootstrap,
        guestshell_preflight_fn=preflight)
    svc._transition_or_note = lambda _jid, _rid, state: (
        events.append(state) or True)

    job = _wait(svc, svc.start("d1", record_id="record-1"))

    assert job["state"] == "done", job["lines"]
    assert events[:5] == [
        "preflight", "mint", "materialize", "applying", "run"]
    assert not observed["path"].exists()


def test_bootstrap_failure_removes_planned_record_before_device_touch(tmp_path):
    events = []
    svc = _svc(
        lambda *_args: events.append("run") or 0,
        artifacts_dir=str(tmp_path),
        mint_fn=lambda _device_id: events.append("mint") or "TOK",
        instruction_bootstrap_fn=lambda _device_id: (_ for _ in ()).throw(
            RuntimeError("private-ciphertext-must-not-escape")))
    svc._transition_or_note = lambda _jid, _rid, state: (
        events.append(state) or True)

    job = _wait(svc, svc.start("d1", record_id="record-1"))

    assert job["state"] == "error"
    assert events == ["mint", "removed"]
    assert not any("private-ciphertext" in line for line in job["lines"])
    assert any("instruction bootstrap unavailable" in line
               for line in job["lines"])


def test_queued_onboard_materializes_only_when_its_worker_fires(tmp_path):
    entered = threading.Event()
    release = threading.Event()
    materialized = []

    def run(_path, env, _line):
        if env["DEVICE_ID"] == "d1":
            entered.set()
            release.wait(5)
        return 0

    svc = _multi_svc(
        2, run, max_concurrent=1, artifacts_dir=str(tmp_path),
        instruction_bootstrap_fn=lambda device_id: (
            materialized.append(device_id) or b"envelope"))
    first = svc.start("d1")
    assert entered.wait(5)
    second = svc.start("d2")
    assert svc.get_job(second)["state"] == "queued"
    assert materialized == ["d1"]
    release.set()
    assert _wait(svc, first)["state"] == "done"
    assert _wait(svc, second)["state"] == "done"
    assert materialized == ["d1", "d2"]


def test_xr_runner_gets_bounded_private_snapshot_and_service_cleans_it(
        tmp_path):
    observed = {}

    def run(_path, env, _line):
        snapshot = env["IRIS_INSTRUCTION_BOOTSTRAP_FILE"]
        observed["path"] = snapshot
        assert os.path.isfile(snapshot)
        assert os.stat(snapshot).st_mode & 0o777 == 0o600
        assert open(snapshot, "rb").read() == b"xr-envelope"
        return 0

    svc = _xr_svc(
        run, artifacts_dir=str(tmp_path),
        instruction_bootstrap_fn=lambda _device_id: b"xr-envelope")
    job = _wait(svc, svc.start(
        "d1", resolved={"platform": "xr-appmgr",
                         "management_type": "xr-host"}))

    assert job["state"] == "done", job["lines"]
    assert not os.path.exists(observed["path"])


def test_router_execution_preflight_failure_never_mints_or_runs(tmp_path):
    fleet = _Fleet({"r1": {
        "device_id": "r1", "device_ip": "192.0.2.10", "model": "C8000V",
        "platform": "router", "management_type": "router-routed",
        "vpg_number": "10", "app_ip": "10.8.0.2",
        "app_mask": "255.255.255.252", "app_gateway": "10.8.0.1",
        "credential_profile_id": "lab"}})
    minted, ran = [], []
    record_store = deployment_records.DeploymentRecordStore(str(tmp_path / "state"))
    record = record_store.create({
        "controller_id": "controller-1", "device_id": "r1",
        "inventory_revision": 1, "plan_hash": "queued-plan",
        "resolved": {"platform": "router", "management_type": "router-routed"},
        "preflight": {"status": "passed"},
        "resources": [{"kind": "virtualportgroup", "name": "10",
                       "ownership": "iris-created"}],
    })
    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9",
        mint_fn=lambda d: minted.append(d) or "TOK",
        run_fn=lambda p, e, on: ran.append(1) or 0,
        record_store=record_store,
        preflight_fn=lambda *args: (_ for _ in ()).throw(
            ValueError("VirtualPortGroup10 appeared while queued")))
    job = _wait(svc, svc.start("r1", prepare=lambda: record["record_id"]))
    assert job["state"] == "error"
    assert minted == [] and ran == []
    assert any("preflight failed" in line for line in job["lines"])
    assert record_store.get(record["record_id"])["state"] == "removed"
    assert record_store.recoverable_for_device("r1") is None


def _router_fleet():
    return _Fleet({"r1": {
        "device_id": "r1", "device_ip": "192.0.2.10", "model": "C8000V",
        "platform": "router", "management_type": "router-nat",
        "vpg_number": "10", "nat_interface": "GigabitEthernet1",
        "app_ip": "10.8.0.2", "app_mask": "255.255.255.252",
        "app_gateway": "10.8.0.1", "credential_profile_id": "lab"}})


def test_router_onboard_persists_xr_family_on_refusal(tmp_path):
    # The router preflight classifies os_family onto a LOCAL dev dict
    # (_default_router_preflight sets dev["os_family"] and then refuses via
    # _refuse_xr) -- nothing here wrote that back to the fleet store, so a
    # retry re-probed the same XR router over SSH instead of short-circuiting
    # at resolve_platform's cached-family guard.
    fleet = _router_fleet()

    def preflight(dev, env, resolved):
        dev["os_family"] = "xr"
        gui_onboard._refuse_xr(dev.get("device_id"))

    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=lambda p, e, on: 0, artifacts_dir=str(tmp_path),
        preflight_fn=preflight)
    job = _wait(svc, svc.start("r1"))
    assert job["state"] == "error"
    assert any("IOS-XR" in line for line in job["lines"]), job["lines"]
    assert {"device_id": "r1", "os_family": "xr"} in fleet.upserts
    assert fleet._d["r1"]["os_family"] == "xr"


def test_iox_onboard_persists_xr_family_on_refusal(tmp_path):
    # Same gap as the router path above, but for the IOx execution preflight.
    # The model is C9k-shaped (not 8xxx) so _resolve's _iox_arch_env lets the
    # device through to the iox preflight itself -- an 8xxx-shaped model
    # would refuse earlier, inside _iox_arch_env, without ever reaching it.
    fleet = _iox_fleet(platform="iox", model="C9300")
    raw_runs = []
    minted = []
    controller = _FrozenIoxController(identity={
        "board_identity": "FDO2547X9AB", "model": "C9300",
        "os_family": "xe", "platform": "iox",
    })

    def iox_preflight(dev, env, resolved):
        dev["os_family"] = "xr"
        gui_onboard._refuse_xr(dev.get("device_id"))

    svc = _iox_controller_service(
        tmp_path, controller, raw_runs, fleet=fleet,
        preflight_fn=iox_preflight,
        mint_fn=lambda device_id: minted.append(device_id) or "TOK",
        artifact_names=("iris-amd64.tar",))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error"
    assert raw_runs == [] and minted == []
    assert [call[0] for call in controller.callback_calls] == ["preflight"]
    assert any("IOS-XR" in line for line in job["lines"]), job["lines"]
    assert {"device_id": "d1", "os_family": "xr"} in fleet.upserts
    assert fleet._d["d1"]["os_family"] == "xr"


def test_router_onboard_second_attempt_short_circuits_on_cached_family(tmp_path):
    # Once the family is persisted (the fix under test above), a later
    # onboard attempt must be refused by resolve_platform's cached-family
    # guard BEFORE the router preflight (or any probe) runs again -- that is
    # the whole point of writing the classification down.
    fleet = _router_fleet()
    calls = []

    def first_preflight(dev, env, resolved):
        calls.append("preflight-1")
        dev["os_family"] = "xr"
        gui_onboard._refuse_xr(dev.get("device_id"))

    def spy_probe(dev, env):
        calls.append("probe")
        return "C8000V"

    def spy_run(p, e, on):
        calls.append("run")
        return 0

    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=spy_run, probe_fn=spy_probe, artifacts_dir=str(tmp_path),
        preflight_fn=first_preflight)
    job1 = _wait(svc, svc.start("r1"))
    assert job1["state"] == "error"
    assert {"device_id": "r1", "os_family": "xr"} in fleet.upserts

    def second_preflight(dev, env, resolved):
        calls.append("preflight-2")
        return {"status": "passed"}

    svc._router_preflight = second_preflight
    job2 = _wait(svc, svc.start("r1"))
    assert job2["state"] == "error"
    assert any("IOS-XR" in line for line in job2["lines"]), job2["lines"]
    # Only the first attempt's preflight ran; the second never reached the
    # router preflight, the probe, or the installer.
    assert calls == ["preflight-1"]


def _router_preflight_stub(monkeypatch, running="", apps="", guest_share="%Error opening",
                            interface="GigabitEthernet1 is up, line protocol is up"):
    outputs = {
        "show version": ("Cisco IOS XE Software\n"
                         "cisco C8000V (VXE) processor\n"
                         "Processor board ID 9ABC123\n"),
        "show running-config": running,
        "show app-hosting list": apps,
        "dir bootflash:guest-share": guest_share,
        "show interfaces Gi1": interface,
    }

    def run(_argv, input=None, **_kwargs):
        chunks = []
        for name, command in (("VERSION", "show version"),
                              ("RUNNING", "show running-config"),
                              ("APPS", "show app-hosting list"),
                              ("GUEST_SHARE", "dir bootflash:guest-share"),
                              ("INTERFACES", "show interfaces Gi1")):
            if command in input:
                chunks.append("__IRIS_PREFLIGHT_%s__\n%s" % (name, outputs[command]))
        return SimpleNamespace(returncode=0, stdout="\n".join(chunks))

    monkeypatch.setattr(gui_onboard.subprocess, "run", run)


def _router_resolved(management_type="router-nat"):
    return {"management_type": management_type, "vpg_number": "10",
            "app_ip": "10.8.0.2", "app_mask": "255.255.255.252",
            "app_gateway": "10.8.0.1", "nat_interface": "Gi1",
            "swarm_port": "6881"}


def test_apply_router_preflight_raises_without_management_type():
    """Task 2 (spec decision 6): apply_router_preflight's own three-level
    fallback (attachment -> management_type -> network_attachment -> "")
    was the 11th silent-default site the Task 1 re-derivation found -- a
    live router-preflight code path. A resolved plan missing management_type
    must fail loud, not silently bind evidence as attachment=""."""
    resolved = {"vpg_number": "10", "app_ip": "10.8.0.2",
                "app_mask": "255.255.255.252", "app_gateway": "10.8.0.1",
                "nat_interface": "Gi1", "swarm_port": "6881"}
    evidence = {"status": "passed", "device_identity": "9ABC123"}
    with pytest.raises(KeyError, match="management_type"):
        gui_onboard.apply_router_preflight(resolved, evidence)


def test_default_router_preflight_canonicalizes_interface_and_records_globals(monkeypatch):
    _router_preflight_stub(
        monkeypatch,
        running=("iox\nfile prompt quiet\ninterface GigabitEthernet1\n"
                 " ip nat outside\n!\n"))
    evidence = gui_onboard._default_router_preflight(
        {}, {"DEVICE_IP": "192.0.2.10"}, _router_resolved(), "/repo")
    assert evidence == {
        "status": "passed", "detected_model": "C8000V",
        "device_identity": "9ABC123", "iox_preexisting": True,
        "file_prompt_quiet_preexisting": True,
        "nat_outside_preexisting": True,
        "nat_interface": "GigabitEthernet1"}


def test_default_router_preflight_uses_one_ssh_session(monkeypatch):
    calls = []

    def run(_argv, input=None, **_kwargs):
        calls.append(input)
        return SimpleNamespace(returncode=0, stdout=(
            "__IRIS_PREFLIGHT_VERSION__\nCisco IOS XE\n"
            "cisco C8000V (VXE) processor\nProcessor board ID 9ABC123\n"
            "__IRIS_PREFLIGHT_RUNNING__\n"
            "__IRIS_PREFLIGHT_APPS__\nNo App found\n"
            "__IRIS_PREFLIGHT_GUEST_SHARE__\n%Error opening\n"))

    monkeypatch.setattr(gui_onboard.subprocess, "run", run)
    evidence = gui_onboard._default_router_preflight(
        {}, {"DEVICE_IP": "192.0.2.10"}, _router_resolved("router-routed"), "/repo")
    assert evidence["status"] == "passed"
    assert len(calls) == 1


def test_default_router_preflight_rejects_secondary_subnet_overlap(monkeypatch):
    _router_preflight_stub(
        monkeypatch,
        running="interface Loopback0\n ip address 10.8.0.1 255.255.255.252 secondary\n!")
    with pytest.raises(ValueError, match="already configured"):
        gui_onboard._default_router_preflight(
            {}, {"DEVICE_IP": "192.0.2.10"}, _router_resolved(), "/repo")


def test_default_router_preflight_rejects_global_address_pat_collision(monkeypatch):
    _router_preflight_stub(
        monkeypatch,
        running=("interface GigabitEthernet1\n!\n"
                 "ip nat inside source static tcp 10.1.1.10 22 198.51.100.10 6881\n"))
    with pytest.raises(ValueError, match="collides with swarm port"):
        gui_onboard._default_router_preflight(
            {}, {"DEVICE_IP": "192.0.2.10"}, _router_resolved(), "/repo")


@pytest.mark.parametrize("collision", [
    "event manager applet IRIS-AGENT authorization bypass\n",
    "logging discriminator IRISQ mnemonics drops IOX_INST_WARN\n",
    "crypto pki trustpoint IRIS\n",
    "ip http client secure-trustpoint IRIS\n",
])
def test_default_router_preflight_rejects_named_global_collisions(monkeypatch, collision):
    _router_preflight_stub(monkeypatch, running=collision)
    with pytest.raises(ValueError, match="already exists"):
        gui_onboard._default_router_preflight(
            {}, {"DEVICE_IP": "192.0.2.10"},
            _router_resolved("router-routed"), "/repo")


def test_default_router_preflight_allows_empty_guest_share(monkeypatch):
    _router_preflight_stub(
        monkeypatch, guest_share=("Directory of bootflash:/guest-share/\n\n"
                                  "No files in directory\n"))
    evidence = gui_onboard._default_router_preflight(
        {}, {"DEVICE_IP": "192.0.2.10"},
        _router_resolved("router-routed"), "/repo")
    assert evidence["status"] == "passed"


def test_default_router_preflight_rejects_populated_guest_share(monkeypatch):
    _router_preflight_stub(
        monkeypatch, guest_share=("Directory of bootflash:/guest-share/\n"
                                  "  12  -rw-  10  Jul 25 2026  operator.txt\n"))
    with pytest.raises(ValueError, match="guest-share is not empty"):
        gui_onboard._default_router_preflight(
            {}, {"DEVICE_IP": "192.0.2.10"},
            _router_resolved("router-routed"), "/repo")


def test_default_router_preflight_refuses_an_ios_xr_device(monkeypatch):
    """The router preflight never probed the family before -- a C8xxx-shaped
    device whose banner actually reads IOS-XR must refuse here (not with the
    unrelated 'router modes support the Catalyst 8000 family only' message)
    before device/router-install.sh ever runs."""
    def run(_argv, input=None, **_kwargs):
        return SimpleNamespace(returncode=0, stdout=(
            "__IRIS_PREFLIGHT_VERSION__\n"
            "Cisco IOS XR Software, Version 24.4.1\n"
            "cisco ASR-9906 (Intel 686 F6M14S4)\n"
            "Processor board ID FOX1234ABCD\n"
            "__IRIS_PREFLIGHT_RUNNING__\nhostname xr1\n"
            "__IRIS_PREFLIGHT_APPS__\nNo App found\n"
            "__IRIS_PREFLIGHT_GUEST_SHARE__\n%Error opening\n"))
    monkeypatch.setattr(gui_onboard.subprocess, "run", run)
    dev = {"device_id": "xr1"}
    with pytest.raises(ValueError, match="IOS-XR"):
        gui_onboard._default_router_preflight(
            dev, {"DEVICE_IP": "192.0.2.10"},
            _router_resolved("router-routed"), "/repo")


def test_default_router_preflight_records_the_family_it_read(monkeypatch):
    _router_preflight_stub(monkeypatch, running="hostname r1\n", apps="No App found\n")
    dev = {"device_id": "r1"}
    gui_onboard._default_router_preflight(
        dev, {"DEVICE_IP": "192.0.2.10"}, _router_resolved("router-routed"), "/repo")
    assert dev["os_family"] == "xe"


# --- IOx preflight: device/iox/install.sh hard-requires EXPECTED_DEVICE_
# IDENTITY (and MODEL) via ':?' on every non-dry-run install -- a guard so a
# typo'd DEVICE_IP can't tear down the app on the wrong switch. The console
# never supplied device_identity for IOx devices (only the router flow
# probed for it), so every console onboard of an IOx device died at that
# guard. These tests cover the fix: a live 'show version' preflight that
# mirrors the router flow and threads device_identity (+ model) through
# resolved -> _build_env -> the installer env.

def _iox_show_version(model="IE-3400", identity="9ABC123"):
    return "Cisco IOS XE Software\ncisco %s (ARMv7) processor\nProcessor board ID %s\n" % (
        model, identity)


def test_default_iox_preflight_extracts_identity_and_model(monkeypatch):
    """IOx now probes running-config and the app list too, so it can run the
    same IRIS-named collision checks as every other platform -- it used to
    ask for `show version` and nothing else."""
    def run(argv, input=None, **kwargs):
        assert "show version" in input
        assert "show running-config" in input
        return SimpleNamespace(returncode=0, stdout=(
            "__IRIS_PREFLIGHT_VERSION__\n" + _iox_show_version() +
            "\n__IRIS_PREFLIGHT_RUNNING__\nhostname sw1\n"
            "\n__IRIS_PREFLIGHT_APPS__\nNo App found\n"))
    monkeypatch.setattr(gui_onboard.subprocess, "run", run)
    evidence = gui_onboard._default_iox_preflight(
        {}, {"DEVICE_IP": "192.0.2.30"}, {}, "/repo")
    assert evidence == {"status": "passed", "device_identity": "9ABC123",
                        "detected_model": "IE-3400"}


def test_default_iox_preflight_refuses_an_ios_xr_device(monkeypatch):
    """The live incident: the IOx path never asked the device what it runs,
    so an XR 8201 sailed through this preflight and only failed later, deep
    inside _iox_arch_env, on a confusing XE-flavoured 'needs a recognized
    device model' arch-selection error that never named IOS-XR."""
    def run(argv, input=None, **kwargs):
        return SimpleNamespace(returncode=0, stdout=(
            "__IRIS_PREFLIGHT_VERSION__\n"
            "Cisco IOS XR Software, Version 24.4.1\n"
            "cisco 8201 (Intel 686 F6M14S4)\n"
            "Processor board ID FOX1234ABCD\n"
            "\n__IRIS_PREFLIGHT_RUNNING__\nhostname xr1\n"
            "\n__IRIS_PREFLIGHT_APPS__\nNo App found\n"))
    monkeypatch.setattr(gui_onboard.subprocess, "run", run)
    dev = {"device_id": "xr1"}
    with pytest.raises(ValueError, match="IOS-XR"):
        gui_onboard._default_iox_preflight(
            dev, {"DEVICE_IP": "192.0.2.30"}, {}, "/repo")


def test_default_iox_preflight_records_the_family_it_read(monkeypatch):
    def run(argv, input=None, **kwargs):
        return SimpleNamespace(returncode=0, stdout=(
            "__IRIS_PREFLIGHT_VERSION__\n" + _iox_show_version() +
            "\n__IRIS_PREFLIGHT_RUNNING__\nhostname sw1\n"
            "\n__IRIS_PREFLIGHT_APPS__\nNo App found\n"))
    monkeypatch.setattr(gui_onboard.subprocess, "run", run)
    dev = {"device_id": "sw1"}
    gui_onboard._default_iox_preflight(
        dev, {"DEVICE_IP": "192.0.2.30"}, {}, "/repo")
    assert dev["os_family"] == "xe"


def test_default_iox_preflight_raises_when_command_fails(monkeypatch):
    def run(argv, input=None, **kwargs):
        return SimpleNamespace(returncode=1, stdout="")
    monkeypatch.setattr(gui_onboard.subprocess, "run", run)
    with pytest.raises(ValueError, match="could not run"):
        gui_onboard._default_iox_preflight(
            {}, {"DEVICE_IP": "192.0.2.30"}, {}, "/repo")


def test_default_iox_preflight_raises_when_identity_unparseable(monkeypatch):
    """A 'show version' that never mentions a Processor board ID (odd
    output, unexpected prompt, truncated capture) must fail closed rather
    than let an empty identity through to the installer's guard."""
    def run(argv, input=None, **kwargs):
        return SimpleNamespace(returncode=0, stdout=(
            "__IRIS_PREFLIGHT_VERSION__\nCisco IOS XE Software\n"
            "cisco IE-3400 (ARMv7) processor\n"
            "\n__IRIS_PREFLIGHT_RUNNING__\nhostname sw1\n"
            "\n__IRIS_PREFLIGHT_APPS__\nNo App found\n"))
    monkeypatch.setattr(gui_onboard.subprocess, "run", run)
    with pytest.raises(ValueError, match="processor board ID"):
        gui_onboard._default_iox_preflight(
            {}, {"DEVICE_IP": "192.0.2.30"}, {}, "/repo")


# --- IOx preflight: a half-finished onboard is resumable (scrubber #78) ----
# A first install of a NEW package version can outrun the installer's activate
# budget while the IOx runtime is still loading the package's docker layers.
# That left the app DEPLOYED and the app-hosting stanza (plus the trustpoint
# the installer pastes in [4/9]) on the device, and preflight then refused
# EVERY retry -- the operator had to undeploy by hand before the console would
# try again. An app that is installed but never started serves nothing, and
# device/iox/install.sh's step [1/9] tears down whatever it finds, so that is a
# resumable retry, not a collision.

def _iox_preflight_stub(monkeypatch, running="hostname sw1\n",
                        apps="No App found\n"):
    def run(_argv, input=None, **_kwargs):
        return SimpleNamespace(returncode=0, stdout=(
            "__IRIS_PREFLIGHT_VERSION__\n" + _iox_show_version() +
            "\n__IRIS_PREFLIGHT_RUNNING__\n" + running +
            "\n__IRIS_PREFLIGHT_APPS__\n" + apps))
    monkeypatch.setattr(gui_onboard.subprocess, "run", run)


# exactly what device/iox/install.sh leaves behind when the activate wait times
# out: its trustpoint from [4/9] and its app-hosting stanza from [7/9]
_IOX_FAILED_ONBOARD = ("hostname sw1\n"
                       "crypto pki trustpoint IRIS\n"
                       " enrollment terminal\n"
                       "ip http client secure-trustpoint IRIS\n"
                       "app-hosting appid iris\n"
                       " app-vnic AppGigabitEthernet trunk\n")


def _iox_app_list(state):
    return ("App id                                   State\n"
            "---------------------------------------------------------\n"
            "iris                                     %s\n" % state)


@pytest.mark.parametrize("state", ["DEPLOYED", "ACTIVATED"])
def test_default_iox_preflight_resumes_an_installed_but_unstarted_app(
        monkeypatch, state):
    _iox_preflight_stub(monkeypatch, running=_IOX_FAILED_ONBOARD,
                        apps=_iox_app_list(state))
    evidence = gui_onboard._default_iox_preflight(
        {}, {"DEVICE_IP": "192.0.2.30"}, {}, "/repo")
    assert evidence["status"] == "passed"
    # recorded on the deployment record, so the retry is visible as a retry
    assert evidence["resumable_app_state"] == state
    assert evidence["device_identity"] == "9ABC123"


def test_default_iox_preflight_still_refuses_a_running_app(monkeypatch):
    """A RUNNING app is a live deployment, not a failed onboard: still refuse
    rather than let a re-onboard tear a working agent down by surprise."""
    _iox_preflight_stub(monkeypatch, running=_IOX_FAILED_ONBOARD,
                        apps=_iox_app_list("RUNNING"))
    with pytest.raises(ValueError,
                       match="the iris app-hosting config already exists"):
        gui_onboard._default_iox_preflight(
            {}, {"DEVICE_IP": "192.0.2.30"}, {}, "/repo")


def test_default_iox_preflight_refuses_a_stanza_with_no_installed_app(
        monkeypatch):
    """Fail closed on anything the app list does not explicitly report as
    installed-but-unstarted -- an unlisted app is not evidence of a failed
    onboard, and the installer already removes its own stanza when the
    install itself fails."""
    _iox_preflight_stub(monkeypatch, running=_IOX_FAILED_ONBOARD,
                        apps="No App found\n")
    with pytest.raises(ValueError, match="already exists"):
        gui_onboard._default_iox_preflight(
            {}, {"DEVICE_IP": "192.0.2.30"}, {}, "/repo")


def test_default_iox_preflight_resume_does_not_waive_guest_shell_artifacts(
        monkeypatch):
    """The waiver covers only what device/iox/install.sh re-creates itself.
    An EEM applet belongs to the Guest Shell recipe, which this installer
    neither owns nor replaces."""
    _iox_preflight_stub(
        monkeypatch,
        running=_IOX_FAILED_ONBOARD + "event manager applet IRIS-AGENT authorization bypass\n",
        apps=_iox_app_list("DEPLOYED"))
    with pytest.raises(ValueError, match="an IRIS EEM applet already exists"):
        gui_onboard._default_iox_preflight(
            {}, {"DEVICE_IP": "192.0.2.30"}, {}, "/repo")


def test_default_iox_preflight_refuses_iris_trustpoint_without_an_app(
        monkeypatch):
    """No app-hosting stanza means no resumable IOx deployment, so the
    IRIS-named leftovers are somebody else's and still refuse."""
    _iox_preflight_stub(monkeypatch,
                        running="hostname sw1\ncrypto pki trustpoint IRIS\n",
                        apps="No App found\n")
    with pytest.raises(ValueError,
                       match="crypto pki trustpoint IRIS already exists"):
        gui_onboard._default_iox_preflight(
            {}, {"DEVICE_IP": "192.0.2.30"}, {}, "/repo")


def test_iox_app_state_ignores_an_app_whose_name_merely_contains_ours():
    apps = ("App id                                   State\n"
            "irisprobe                                RUNNING\n")
    assert gui_onboard._iox_app_state(apps, "iris") == ""
    assert gui_onboard._iox_app_state(
        apps + "iris                                     DEPLOYED\n",
        "iris") == "DEPLOYED"


def test_apply_iox_preflight_binds_identity_and_model():
    result = gui_onboard.apply_iox_preflight(
        {"model": ""}, {"status": "passed", "device_identity": "9ABC123",
                        "detected_model": "IE-3400"})
    assert result["device_identity"] == "9ABC123"
    assert result["model"] == "IE-3400"


def test_apply_iox_preflight_rejects_unsafe_identity():
    with pytest.raises(ValueError, match="safe device identity"):
        gui_onboard.apply_iox_preflight(
            {}, {"status": "passed", "device_identity": "; rm -rf /"})


def test_apply_iox_preflight_rejects_identity_drift_while_queued():
    with pytest.raises(ValueError, match="changed while the job was queued"):
        gui_onboard.apply_iox_preflight(
            {"device_identity": "OLD123"},
            {"status": "passed", "device_identity": "NEW456"})


def test_iox_onboard_runs_preflight_and_exports_identity_and_model(tmp_path):
    """Console onboard of an IOx-platform device runs the preflight and
    binds the discovered device identity and model inside controller custody."""
    events, raw_runs = [], []
    controller = _FrozenIoxController(events=events)
    svc = _iox_controller_service(
        tmp_path, controller, raw_runs,
        mint_fn=lambda d: events.append("mint") or "TOK",
        preflight_fn=lambda dev, env, resolved: (
            events.append("preflight") or {
                "status": "passed", "device_identity": "FDO2547X9AB",
                "detected_model": "IE-3400"}))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert events == ["controller:install", "preflight", "mint"]
    assert raw_runs == []
    bound = controller.preflight_results[0]
    assert _request_value(bound, "device_identity") == "FDO2547X9AB"
    assert _request_value(bound, "model") == "IE-3400"
    assert "board_identity" not in bound


def test_iox_preflight_parse_failure_fails_job_before_installer_runs(tmp_path):
    """A preflight that cannot determine the live identity must fail the
    job (fail-closed) before the installer ever runs or the token is
    minted -- an empty EXPECTED_DEVICE_IDENTITY would make install.sh's
    identity guard a no-op."""
    minted, raw_runs = [], []
    controller = _FrozenIoxController()
    svc = _iox_controller_service(
        tmp_path, controller, raw_runs,
        mint_fn=lambda d: minted.append(d) or "TOK",
        preflight_fn=lambda dev, env, resolved: (_ for _ in ()).throw(
            ValueError("could not determine the device's processor board ID")))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error"
    assert minted == [] and raw_runs == []
    assert [call[0] for call in controller.callback_calls] == ["preflight"]
    assert any("preflight failed" in l for l in job["lines"])


def test_iox_missing_iris_tar_errors_before_run(tmp_path):
    fleet = _iox_fleet(platform="iox", model="IE-3400")
    creds = _iox_creds()
    called = []

    def fake_run(install_path, env, on_line):
        called.append(install_path)
        return 0

    svc = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=fake_run, iox_preflight_fn=_iox_preflight_ok(),
        artifacts_dir=str(tmp_path))  # no iris-arm64.tar written
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error"
    assert called == []
    assert any("iris-arm64.tar not found" in l for l in job["lines"])


def test_iox_present_iris_tar_proceeds(tmp_path):
    raw_runs = []
    controller = _FrozenIoxController()
    svc = _iox_controller_service(tmp_path, controller, raw_runs)
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert raw_runs == []
    assert _request_value(
        controller.requests[0], "wrapper_path") == str(
            tmp_path / "iris-arm64.tar")


def test_job_lines_note_platform_and_recipe(tmp_path):
    raw_runs = []
    controller = _FrozenIoxController()
    svc = _iox_controller_service(tmp_path, controller, raw_runs)
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert raw_runs == []
    assert _request_value(controller.requests[0], "action") == "install"
    assert any("platform: iox" in l and "device/iox/install.sh" in l
               for l in job["lines"])


def test_audit_fn_called_on_finish_ok():
    calls = []
    svc = _svc(lambda p, e, on: (on("ok"), 0)[1],
               audit_fn=lambda **kw: calls.append(kw))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    finishes = [c for c in calls if c.get("event") == "onboard_finished"]
    assert finishes and finishes[0]["result"] == "ok"
    assert finishes[0]["target"] == "d1"


def test_audit_fn_called_on_finish_fail():
    calls = []
    svc = _svc(lambda p, e, on: (on("boom"), 1)[1],
               audit_fn=lambda **kw: calls.append(kw))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error"
    finishes = [c for c in calls if c.get("event") == "onboard_finished"]
    assert finishes and finishes[0]["result"] == "fail"


def test_audit_fn_raising_does_not_break_job():
    def boom(**kw):
        raise OSError("audit sink unavailable")
    svc = _svc(lambda p, e, on: (on("ok"), 0)[1], audit_fn=boom)
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"   # audit_fn failure must never break the job


def test_fmt_dur():
    f = gui_onboard._fmt_dur
    assert f(0) == "0s"
    assert f(52) == "52s"
    assert f(272) == "4m32s"
    assert f(3840) == "1h04m"


def test_finish_audit_detail_has_job_duration_platform_rc():
    """onboard_finished must be self-explanatory: job id (correlates with
    onboard_start), wall duration, resolved platform, rc."""
    clock = {"t": 1000}
    calls = []

    def run_fn(p, e, on):
        clock["t"] += 272            # 4m32s of installer wall time
        on("ok")
        return 0

    svc = _svc(run_fn, audit_fn=lambda **kw: calls.append(kw),
               now_fn=lambda: clock["t"])
    jid = svc.start("d1")
    assert _wait(svc, jid)["state"] == "done"
    fin = [c for c in calls if c["event"] == "onboard_finished"][0]
    assert fin["detail"] == "job %s 4m32s platform=guestshell rc=0" % jid
    assert fin["target"] == "d1" and fin["actor"] == "system"


def test_finish_audit_detail_fail_carries_truncated_error_line():
    calls = []

    def run_fn(p, e, on):
        on("ERROR: " + "x" * 300)    # longer than the 120-char detail cap
        return 1

    svc = _svc(run_fn, audit_fn=lambda **kw: calls.append(kw),
               now_fn=lambda: 1000)
    jid = svc.start("d1")
    assert _wait(svc, jid)["state"] == "error"
    fin = [c for c in calls if c["event"] == "onboard_finished"][0]
    assert fin["result"] == "fail"
    assert fin["detail"].startswith(
        "job %s 0s platform=guestshell rc=1 -- ERROR: " % jid)
    assert fin["detail"].endswith("ERROR: " + "x" * 113)  # err[:120] cap


def test_finish_audit_detail_error_before_resolve():
    """A job that dies before platform resolution (unknown device) still logs
    a usable line: platform=? rc=? plus the ERROR."""
    calls = []
    svc = _svc(lambda p, e, on: 0, audit_fn=lambda **kw: calls.append(kw),
               now_fn=lambda: 1000)
    jid = svc.start("nope")
    assert _wait(svc, jid)["state"] == "error"
    fin = [c for c in calls if c["event"] == "onboard_finished"][0]
    assert fin["detail"] == \
        "job %s 0s platform=? rc=? -- ERROR: unknown device: nope" % jid


# --- bounded onboard pool (parallel onboarding) --------------------------

def _multi_svc(n, run_fn, **kw):
    """A service over n devices d1..dN sharing one credential profile."""
    devs = {}
    for i in range(1, n + 1):
        did = "d%d" % i
        devs[did] = {"device_id": did, "device_ip": "10.0.0.%d" % i,
                     "model": "C9300", "management_type": "routed",
                     "credential_profile_id": "lab"}
    creds = _Creds({"lab": {"device_user": "admin", "device_pass": "s3cret",
                            "enable_secret": "en"}})
    kw.setdefault("probe_fn", lambda dev, env: "C9300")  # see _svc: guestshell reachability gate
    return gui_onboard.OnboardService(
        _Fleet(devs), creds, device_install="/fake/device-install.sh",
        crt_public="/fake/crt.pem", host_ip="10.9.9.9",
        mint_fn=lambda did: "TOK-" + did, run_fn=run_fn, **kw)


def _wait_for(predicate, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_pool_caps_concurrent_onboards():
    release = threading.Event()
    running = []
    reg = threading.Lock()

    def run_fn(p, e, on):
        with reg:
            running.append(e["DEVICE_ID"])
        release.wait(5)
        return 0

    svc = _multi_svc(4, run_fn, max_concurrent=2)
    jids = [svc.start("d%d" % i) for i in range(1, 5)]
    assert _wait_for(lambda: len(running) == 2)
    time.sleep(0.1)   # an unbounded pool would have started the other two
    assert len(running) == 2
    assert sorted(svc.get_job(j)["state"] for j in jids) == \
        ["queued", "queued", "running", "running"]
    release.set()
    assert all(_wait(svc, j)["state"] == "done" for j in jids)
    assert sorted(running) == ["d1", "d2", "d3", "d4"]


def test_queued_job_gets_started_at_only_when_it_runs():
    release = threading.Event()

    def run_fn(p, e, on):
        release.wait(5)
        return 0

    svc = _multi_svc(2, run_fn, max_concurrent=1)
    j1 = svc.start("d1")
    j2 = svc.start("d2")
    assert _wait_for(lambda: svc.get_job(j1)["state"] == "running")
    q = svc.get_job(j2)
    assert q["state"] == "queued"
    assert q["queued_at"] is not None and q["started_at"] is None
    release.set()
    done = _wait(svc, j2)
    assert done["state"] == "done"
    assert done["started_at"] >= done["queued_at"]


def test_default_concurrency_is_25(monkeypatch):
    monkeypatch.delenv("IRIS_ONBOARD_CONCURRENCY", raising=False)
    svc = _svc(lambda p, e, on: 0)
    assert svc.max_concurrent == 25


def test_concurrency_env_override(monkeypatch):
    monkeypatch.setenv("IRIS_ONBOARD_CONCURRENCY", "3")
    svc = _svc(lambda p, e, on: 0)
    assert svc.max_concurrent == 3


def test_list_jobs_summaries_without_lines():
    svc = _svc(lambda p, e, on: (on("hello"), on("world"), 0)[2])
    jid = svc.start("d1")
    assert _wait(svc, jid)["state"] == "done"
    j = [x for x in svc.list_jobs() if x["id"] == jid][0]
    assert j["device_id"] == "d1" and j["state"] == "done"
    assert "lines" not in j
    assert j["last_line"] == "world"
    assert j["queued_at"] is not None


def test_cancel_queued_cancels_only_queued_and_never_runs():
    release = threading.Event()
    ran = []
    reg = threading.Lock()

    def run_fn(p, e, on):
        with reg:
            ran.append(e["DEVICE_ID"])
        release.wait(5)
        return 0

    svc = _multi_svc(3, run_fn, max_concurrent=1)
    j1 = svc.start("d1")
    j2 = svc.start("d2")
    j3 = svc.start("d3")
    assert _wait_for(lambda: svc.get_job(j1)["state"] == "running")
    assert svc.cancel_queued() == 2
    assert svc.get_job(j1)["state"] == "running"     # running jobs untouched
    for j in (j2, j3):
        job = svc.get_job(j)
        assert job["state"] == "cancelled"
        assert job["finished_at"] is not None        # terminal -> evictable
    release.set()
    assert _wait(svc, j1)["state"] == "done"
    time.sleep(0.2)   # give a wrongly-unparked thread the chance to run
    assert ran == ["d1"]                              # cancelled never ran
    assert svc.cancel_queued() == 0                   # nothing left to cancel


def test_cancel_queued_scoped_to_job_ids():
    release = threading.Event()

    def run_fn(p, e, on):
        release.wait(5)
        return 0

    svc = _multi_svc(3, run_fn, max_concurrent=1)
    j1 = svc.start("d1")
    j2 = svc.start("d2")
    j3 = svc.start("d3")
    assert _wait_for(lambda: svc.get_job(j1)["state"] == "running")
    # scoped: only j2 is cancelled; j3 stays queued (another batch's job)
    assert svc.cancel_queued(job_ids=[j2, j1, "nonsense"]) == 1
    assert svc.get_job(j2)["state"] == "cancelled"
    assert svc.get_job(j3)["state"] == "queued"
    release.set()
    assert _wait(svc, j1)["state"] == "done"
    assert _wait(svc, j3)["state"] == "done"


def test_start_dedups_active_device_job():
    """A device with a queued/running job must not get a second concurrent
    installer run — start() returns the existing active job id instead."""
    release = threading.Event()

    def run_fn(p, e, on):
        release.wait(5)
        return 0

    svc = _multi_svc(2, run_fn, max_concurrent=1)
    j1 = svc.start("d1")
    assert _wait_for(lambda: svc.get_job(j1)["state"] == "running")
    assert svc.start("d1") == j1          # running -> reuse
    j2 = svc.start("d2")
    assert svc.start("d2") == j2          # queued -> reuse
    release.set()
    assert _wait(svc, j1)["state"] == "done"
    assert _wait(svc, j2)["state"] == "done"
    j1b = svc.start("d1")                 # terminal -> a fresh job is fine
    assert j1b != j1
    assert _wait(svc, j1b)["state"] == "done"


def test_terminal_jobs_evicted_even_while_a_job_is_active():
    """Terminal records expire independently of active jobs."""
    clock = {"t": 1000}
    release = threading.Event()

    def run_fn(p, e, on):
        if e["DEVICE_ID"] == "d2":
            release.wait(5)
        return 0

    svc = _multi_svc(3, run_fn, max_concurrent=1, now_fn=lambda: clock["t"])
    j1 = svc.start("d1")
    assert _wait(svc, j1)["state"] == "done"
    j2 = svc.start("d2")                   # blocks, keeping the batch active
    assert _wait_for(lambda: svc.get_job(j2)["state"] == "running")
    clock["t"] = 1000 + 7200               # way past the TTL
    j3 = svc.start("d3")                   # would trigger the sweep
    # The old active-job exemption was deliberately removed: it allowed
    # long-running jobs to pin unbounded completed-job state in memory.
    assert svc.get_job(j1) is None
    release.set()
    assert _wait(svc, j2)["state"] == "done"
    assert _wait(svc, j3)["state"] == "done"


# --- undeploy action (shares the pool/job model with onboarding) ----------

def test_undeploy_runs_uninstall_script_without_minting():
    seen = {}
    minted = []

    def fake_run(install_path, env, on_line):
        seen["install_path"] = install_path
        seen["env"] = env
        on_line("undeploy complete: 10.0.0.1 is clean")
        return 0

    svc = _svc(fake_run)
    svc._mint = lambda did: minted.append(did) or "TOK"
    job = _wait(svc, svc.start("d1", action="undeploy"))
    assert job["state"] == "done"
    assert job["action"] == "undeploy"
    assert seen["install_path"].endswith("device/device-uninstall.sh")
    assert minted == []                      # undeploy must not mint tokens
    assert seen["env"]["DEVICE_IP"] == "10.0.0.1"
    assert seen["env"]["DEVICE_PASS"] == "s3cret"
    assert seen["env"]["VLAN"] == "666"


def test_onboard_jobs_carry_action_and_default_onboard():
    svc = _svc(lambda p, e, on: 0)
    jid = svc.start("d1")
    assert _wait(svc, jid)["action"] == "onboard"
    j = [x for x in svc.list_jobs() if x["id"] == jid][0]
    assert j["action"] == "onboard"


def test_undeploy_iox_runs_the_iox_uninstall_script(tmp_path):
    """IOx undeploy selects its recipe and enters controller custody."""
    raw_runs = []
    minted = []
    controller = _FrozenIoxController()
    svc = _iox_controller_service(
        tmp_path, controller, raw_runs,
        mint_fn=lambda d: minted.append(d) or "TOK")
    job = _wait(svc, svc.start(
        "d1", action="undeploy", teardown_mode="force_agent_only"))
    assert job["state"] == "done"
    assert raw_runs == []
    request = controller.requests[0]
    assert _request_value(request, "action") == "uninstall"
    assert _request_value(request, "teardown_mode") == "force_agent_only"
    assert not _request_has(request, "wrapper_path")
    assert minted == []                       # undeploy never mints
    assert any("device/iox/uninstall.sh" in l for l in job["lines"])


def test_undeploy_guestshell_runs_the_guestshell_uninstall_script():
    seen = {}
    svc = _svc(lambda p, e, on: seen.update(install_path=p) or 0)
    job = _wait(svc, svc.start("d1", action="undeploy"))
    assert job["state"] == "done"
    assert seen["install_path"].endswith("device/device-uninstall.sh")


def test_conflicting_action_on_active_job_raises():
    release = threading.Event()

    def run_fn(p, e, on):
        release.wait(5)
        return 0

    svc = _multi_svc(1, run_fn, max_concurrent=1)
    j1 = svc.start("d1")
    assert _wait_for(lambda: svc.get_job(j1)["state"] == "running")
    assert svc.start("d1") == j1                       # same action -> reuse
    try:
        svc.start("d1", action="undeploy")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "onboard" in str(exc)                   # names the busy action
    release.set()
    assert _wait(svc, j1)["state"] == "done"


def test_prepare_runs_once_and_not_on_dedup():
    """start()'s prepare() (used to mint the record) must fire exactly once for
    a genuinely new job and NEVER when a second same-action start dedups onto the
    running job -- otherwise a double-onboard would strand an orphan record."""
    release = threading.Event()

    def run_fn(p, e, on):
        release.wait(5)
        return 0

    svc = _multi_svc(1, run_fn, max_concurrent=1)
    calls = []
    j1 = svc.start("d1", prepare=lambda: calls.append(1) or "rcpt-1")
    assert _wait_for(lambda: svc.get_job(j1)["state"] == "running")
    j2 = svc.start("d1", prepare=lambda: calls.append(1) or "rcpt-2")
    assert j1 == j2                                # deduped onto the running job
    assert calls == [1]                            # prepare fired only once
    assert svc.get_job(j1)["record_id"] == "rcpt-1"
    release.set()
    assert _wait(svc, j1)["state"] == "done"


def test_undeploy_clears_device_state_on_success():
    """A successful undeploy must forget the device's stored heartbeat so the
    console stops showing the wiped box as 'deployed' from its last live
    heartbeat. Onboard must NOT clear (the fresh agent's heartbeat is the
    live state), and a FAILED undeploy must not clear either (the box may
    still be partly deployed)."""
    cleared = []
    svc = _svc(lambda p, e, on: 0)
    svc._clear_state = lambda did: cleared.append(did)
    assert _wait(svc, svc.start("d1", action="undeploy"))["state"] == "done"
    assert cleared == ["d1"]

    cleared.clear()
    assert _wait(svc, svc.start("d1", action="onboard"))["state"] == "done"
    assert cleared == []                      # onboard never clears

    cleared.clear()
    svc_fail = _svc(lambda p, e, on: 1)       # undeploy script fails
    svc_fail._clear_state = lambda did: cleared.append(did)
    assert _wait(svc_fail, svc_fail.start("d1", action="undeploy"))["state"] == "error"
    assert cleared == []                      # failed undeploy leaves state


def test_undeploy_forgets_device_in_real_catalog(tmp_path):
    """End-to-end wiring: a live-looking heartbeat in a real CatalogStore is
    gone after a successful undeploy, so _device_view stops reporting the box
    as 'deployed'. The image assignment (policy) survives for re-onboard."""
    cat = catalog_mod.CatalogStore(str(tmp_path))
    cat.record_heartbeat("d1", {"current_image_id": "img1",
                                "stage_state": "ready"})
    cat.set_policy("d1", approved_image_id="img1")
    svc = _svc(lambda p, e, on: 0, clear_state_fn=cat.forget_device)
    assert _wait(svc, svc.start("d1", action="undeploy"))["state"] == "done"
    assert cat.get_device("d1") is None                 # heartbeat forgotten
    assert cat.get_policy("d1")["approved_image_id"] == "img1"   # assignment kept


def test_latest_jobs_by_device_prefers_active_then_most_recent():
    """The devices view merges each device's LATEST onboard/undeploy job so
    the UI can show 'onboarding…' / 'waiting for heartbeat' instead of a
    misleading 'not enrolled' right after an onboard."""
    release = threading.Event()

    def run_fn(p, e, on):
        if e["DEVICE_ID"] == "d2":
            release.wait(5)
        return 0

    clock = {"t": 1000}
    svc = _multi_svc(2, run_fn, max_concurrent=2, now_fn=lambda: clock["t"])
    j1 = svc.start("d1")
    assert _wait(svc, j1)["state"] == "done"
    clock["t"] = 1200
    j1b = svc.start("d1")                       # a NEWER job for d1
    assert _wait(svc, j1b)["state"] == "done"
    j2 = svc.start("d2")                        # d2 still running
    assert _wait_for(lambda: svc.get_job(j2)["state"] == "running")

    latest = svc.latest_jobs_by_device()
    assert latest["d1"]["state"] == "done"
    assert latest["d1"]["finished_at"] == 1200  # the newer job won
    assert latest["d1"]["action"] == "onboard"
    assert latest["d2"]["state"] == "running"   # active job preferred
    release.set()
    assert _wait(svc, j2)["state"] == "done"


def test_latest_jobs_by_device_empty_when_no_jobs():
    svc = _svc(lambda p, e, on: 0)
    assert svc.latest_jobs_by_device() == {}


def test_undeploy_audit_event_named_by_action():
    calls = []
    svc = _svc(lambda p, e, on: 0, audit_fn=lambda **kw: calls.append(kw))
    jid = svc.start("d1", action="undeploy")
    assert _wait(svc, jid)["state"] == "done"
    fins = [c for c in calls if c.get("event") == "undeploy_finished"]
    assert fins and fins[0]["target"] == "d1" and fins[0]["result"] == "ok"
    assert not any(c.get("event") == "onboard_finished" for c in calls)


def test_cancelled_jobs_evicted_after_ttl():
    clock = {"t": 1000}
    release = threading.Event()

    def run_fn(p, e, on):
        release.wait(5)
        return 0

    svc = _multi_svc(2, run_fn, max_concurrent=1, now_fn=lambda: clock["t"])
    j1 = svc.start("d1")
    j2 = svc.start("d2")
    assert _wait_for(lambda: svc.get_job(j1)["state"] == "running")
    assert svc.cancel_queued() == 1
    release.set()
    assert _wait(svc, j1)["state"] == "done"
    clock["t"] = 1000 + 3601
    j3 = svc.start("d1")                              # triggers the sweep
    assert _wait(svc, j3)["state"] == "done"
    assert svc.get_job(j2) is None                    # cancelled job evicted


def test_guestshell_device_install_override_still_applies(tmp_path):
    """The device_install explicit-arg/env override is a guestshell-only
    override; regression check that it still takes effect for guestshell."""
    seen = {}

    def fake_run(install_path, env, on_line):
        seen["install_path"] = install_path
        return 0

    svc = _svc(fake_run)  # device_install="/fake/device-install.sh" explicit
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert seen["install_path"] == "/fake/device-install.sh"


# --- C9300 amd64 IOx arch derivation ------------------------------------

def _run_capture(seen):
    def fake_run(install_path, env, on_line):
        seen["install_path"] = install_path
        seen["env"] = env
        return 0
    return fake_run


def test_c9k_iox_gets_amd64_env(tmp_path):
    fleet = _iox_fleet(platform="iox", model="C9300-48UXM")
    raw_runs = []
    controller = _FrozenIoxController(identity={
        "board_identity": "FDO2547X9AB", "model": "C9300-48UXM",
        "os_family": "xe", "platform": "iox",
    })
    svc = _iox_controller_service(
        tmp_path, controller, raw_runs, fleet=fleet,
        artifact_names=("iris-amd64.tar",))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert raw_runs == []
    request = controller.requests[0]
    assert _request_value(request, "wrapper_path").endswith(
        "iris-amd64.tar")
    target = _request_value(request, "target")
    assert target["pkg"] == "iris-amd64.tar"
    assert target["app_intf"] == "AppGigabitEthernet1/0/1"
    # Route B: the C9k SSD share is bind-mounted into the app, the scratch
    # lands there at disk speed, and placement targets bootflash like the
    # Guest Shell path — no scp, no CoPP-limited punt traffic.
    assert target["target_fs"] == "flash:"
    assert target["share_host_path"] == "/vol/usb1/iox_host_data_share"
    assert target["share_ios_path"] == "usbflash1:iox_host_data_share"
    assert "board_identity" not in target


def test_ie3k_iox_keeps_arm_defaults(tmp_path):
    fleet = _iox_fleet(model="IE-3400")   # model regex -> iox, arm
    raw_runs = []
    controller = _FrozenIoxController()
    svc = _iox_controller_service(
        tmp_path, controller, raw_runs, fleet=fleet)
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert raw_runs == []
    request = controller.requests[0]
    assert _request_value(request, "wrapper_path").endswith(
        "iris-arm64.tar")
    target = _request_value(request, "target")
    # arm case leaves these unset so install.sh's own defaults apply
    assert "pkg" not in target
    assert "app_intf" not in target
    assert "target_fs" not in target
    # the SSD share mount is a C9k mechanism; IE-3x00 keeps the scp path
    assert "share_host_path" not in target
    assert "share_ios_path" not in target


def test_c9k_guestshell_override_runs_guestshell(tmp_path):
    fleet = _iox_fleet(platform="guestshell", model="C9300-48UXM")
    seen = {}
    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=_run_capture(seen), device_install="/fake/device-install.sh",
        artifacts_dir=str(tmp_path), probe_fn=lambda dev, env: "C9300-48UXM")
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert seen["install_path"] == "/fake/device-install.sh"
    assert "PKG" not in seen["env"] and "DEVICE_SSH_PASS" not in seen["env"]


def test_c9k_stacked_member_app_intf_override_wins(tmp_path, monkeypatch):
    fleet = _iox_fleet(platform="iox", model="C9300-48UXM")
    raw_runs = []
    controller = _FrozenIoxController(identity={
        "board_identity": "FDO2547X9AB", "model": "C9300-48UXM",
        "os_family": "xe", "platform": "iox",
    })
    svc = _iox_controller_service(
        tmp_path, controller, raw_runs, fleet=fleet,
        artifact_names=("iris-amd64.tar",))
    # simulate an operator/env override for a stacked member 2/0/1
    monkeypatch.setenv("APP_INTF", "AppGigabitEthernet2/0/1")
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert raw_runs == []
    target = _request_value(controller.requests[0], "target")
    # setdefault must not clobber the explicit override
    assert target["app_intf"] == "AppGigabitEthernet2/0/1"
    assert target["pkg"] == "iris-amd64.tar"


def test_iox_unclassifiable_model_raises_guard(tmp_path):
    (tmp_path / "iris-arm64.tar").write_text("fake")
    (tmp_path / "iris-amd64.tar").write_text("fake")
    fleet = _iox_fleet(platform="iox", model="ISR4451")  # forced iox, non-IOx family
    called = []
    def fake_run(p, e, on):
        called.append(p)
        return 0
    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=fake_run, artifacts_dir=str(tmp_path))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error"
    assert called == []                       # device untouched
    msg = " ".join(job["lines"])
    assert "d1" in msg and "C9k" in msg and "arm" in msg


def test_undeploy_c9k_uses_resolved_amd64_pkg(tmp_path):
    fleet = _iox_fleet(platform="iox", model="C9300-48UXM")
    raw_runs = []
    controller = _FrozenIoxController(identity={
        "board_identity": "FDO2547X9AB", "model": "C9300-48UXM",
        "os_family": "xe", "platform": "iox",
    })
    svc = _iox_controller_service(
        tmp_path, controller, raw_runs, fleet=fleet,
        artifact_names=("iris-amd64.tar",))
    job = _wait(svc, svc.start(
        "d1", action="undeploy", teardown_mode="force_agent_only"))
    assert job["state"] == "done"
    assert raw_runs == []
    # undeploy never checks the artifacts guard, but _resolve populates PKG so
    # uninstall.sh deletes flash:iris-amd64.tar
    request = controller.requests[0]
    assert not _request_has(request, "wrapper_path")
    assert _request_value(request, "target")["pkg"] == "iris-amd64.tar"


def test_c9k_iox_notfound_names_amd64_tar(tmp_path):
    # no package staged
    fleet = _iox_fleet(platform="iox", model="C9300-48UXM")
    called = []
    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=lambda p, e, on: called.append(p) or 0,
        iox_preflight_fn=_iox_preflight_ok(), artifacts_dir=str(tmp_path))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error"
    assert called == []
    assert any("iris-amd64.tar" in l for l in job["lines"])


def test_abort_terminates_running_job():
    """abort() signals the running installer's process; the job then errors."""
    release = threading.Event()
    proc_ready = threading.Event()
    aborted = {"v": False}

    class FakeProc:
        def terminate(self):
            aborted["v"] = True
            release.set()

    def run_fn(p, e, on, on_proc):
        on_proc(FakeProc())
        proc_ready.set()
        on("running")
        release.wait(5)          # blocks until aborted (or timeout)
        return 137

    svc = _multi_svc(1, run_fn, max_concurrent=1)
    j = svc.start("d1")
    # Wait for the proc to REGISTER, not merely for state=="running": the job
    # reports running before the installer is spawned, and this test pins the
    # direct terminate() path (the pre-registration window has its own tests).
    assert proc_ready.wait(5)
    assert svc.get_job(j)["state"] == "running"
    assert svc.abort(j) is True
    assert aborted["v"] is True
    assert _wait(svc, j)["state"] == "error"
    assert svc.abort(j) is False     # not running anymore -> nothing to abort


def test_abort_before_proc_registration_terminates_on_register():
    """abort() in the window where the job is "running" but the installer has
    not been spawned yet must still take effect: the request is recorded and
    the process is terminated the moment it registers. mint_fn runs after the
    job reports running and just before the installer launches, so blocking
    there lands the abort deterministically inside that window."""
    in_window = threading.Event()
    proceed = threading.Event()
    release = threading.Event()
    aborted = {"v": False}

    class FakeProc:
        def terminate(self):
            aborted["v"] = True
            release.set()

    def mint(did):
        in_window.set()
        assert proceed.wait(5)
        return "TOK"

    def run_fn(p, e, on, on_proc):
        on_proc(FakeProc())      # registration must honor the pending abort
        release.wait(5)
        return 137

    svc = _svc(run_fn, mint_fn=mint)
    j = svc.start("d1")
    assert in_window.wait(5)
    assert svc.get_job(j)["state"] == "running"
    assert svc.abort(j) is True
    proceed.set()
    job = _wait(svc, j)
    assert job["state"] == "error"
    assert aborted["v"] is True
    assert any("abort" in l for l in job["lines"])


def test_abort_during_preflight_never_launches_installer():
    """abort() while the worker is still in preflight stops the job before the
    installer is ever spawned: the device stays untouched."""
    in_probe = threading.Event()
    proceed = threading.Event()
    called = []

    def probe(dev, env):
        in_probe.set()
        assert proceed.wait(5)
        return "C9300"

    def run_fn(p, e, on, on_proc):
        called.append(p)
        return 0

    svc = _svc(run_fn, probe_fn=probe)
    j = svc.start("d1")
    assert in_probe.wait(5)
    assert svc.get_job(j)["state"] == "running"
    assert svc.abort(j) is True
    proceed.set()
    job = _wait(svc, j)
    assert job["state"] == "error"
    assert called == []              # device untouched
    assert any("abort" in l for l in job["lines"])


def test_abort_unknown_job_is_false():
    svc = _svc(lambda p, e, on: 0)
    assert svc.abort("nope") is False


# --- Record lifecycle races in the worker thread: a concurrent action can
# retire (supersede) the record a job bound between the job's start and its
# worker's record transitions. Those transitions then raise — and must not
# kill the worker before _finish(), which would wedge the job "running" and
# the device "busy" until a server restart. ---

def _record_backed_svc(tmp_path, run_fn):
    import deployment_records
    record_store = deployment_records.DeploymentRecordStore(str(tmp_path))
    svc = _svc(run_fn, record_store=record_store)
    return svc, record_store


def _active_record(record_store, rid, device_id="d1"):
    record_store.create({"record_id": rid, "controller_id": "c", "device_id": device_id,
                     "inventory_revision": 1, "plan_hash": "h" * 64,
                     "resolved": {"platform": "guestshell"},
                     "preflight": {}, "resources": []})
    record_store.transition(rid, "applying")
    record_store.transition(rid, "active")


def test_undeploy_with_superseded_record_aborts_cleanly(tmp_path):
    ran = []
    svc, record_store = _record_backed_svc(tmp_path, lambda p, e, on: ran.append(1) or 0)
    _active_record(record_store, "r1")
    _active_record(record_store, "r2")   # supersedes r1 (the race winner)
    job = _wait(svc, svc.start("d1", action="undeploy",
                               resolved={"platform": "guestshell",
                                         "management_type": "routed"},
                               prepare=lambda: "r1"))
    # the worker must FINISH (error), not die mid-thread leaving "running"
    assert job["state"] == "error"
    assert ran == []                  # stale-record teardown never ran
    # _transition_or_note logs "record %s -> %s not applied: %s" on a failed
    # transition (the superseded r1 raises when the worker tries to move it).
    assert any("record" in line for line in job["lines"])


def test_record_retired_during_run_does_not_wedge_the_job(tmp_path):
    holder = {}

    def run_fn(p, e, on):
        # simulate a concurrent reconciliation retiring the in-flight record
        # mid-script (applying -> unknown), so the worker's terminal
        # transition (removed) becomes invalid
        holder["record_store"].transition("r1", "unknown")
        return 0

    svc, record_store = _record_backed_svc(tmp_path, run_fn)
    holder["record_store"] = record_store
    _active_record(record_store, "r1")
    job = _wait(svc, svc.start("d1", action="undeploy",
                               resolved={"platform": "guestshell",
                                         "management_type": "routed"},
                               prepare=lambda: "r1"))
    # script succeeded -> job reports the script's truth; the record
    # discrepancy is surfaced as a job line instead of killing the worker
    assert job["state"] == "done"
    # same "record %s -> %s not applied: %s" line as
    # test_undeploy_with_superseded_record_aborts_cleanly above.
    assert any("record" in line for line in job["lines"])


# ---- telemetry onboarding flags (device transfer telemetry spec 8.1) ----

def test_build_env_applies_telemetry_flags():
    svc = _svc(lambda p, e, on: 0)
    _dev, env = svc._build_env("d1", mint=False,
                               env_extra={"TELEMETRY": "on",
                                          "TELEMETRY_STREAM": "on",
                                          "IRIS_TELEMETRY": "on",
                                          "IRIS_TELEMETRY_STREAM": "on"})
    assert env["TELEMETRY_STREAM"] == "on"
    assert env["IRIS_TELEMETRY_STREAM"] == "on"


def test_build_env_default_is_dark(monkeypatch):
    monkeypatch.delenv("TELEMETRY_STREAM", raising=False)
    svc = _svc(lambda p, e, on: 0)
    _dev, env = svc._build_env("d1", mint=False)
    assert "TELEMETRY_STREAM" not in env           # installer default off


def test_start_threads_env_extra_to_the_runner():
    seen = {}

    def fake_run(p, e, on):
        seen["env"] = e
        return 0

    svc = _svc(fake_run)
    _wait(svc, svc.start("d1", env_extra={"TELEMETRY_STREAM": "on",
                                          "IRIS_TELEMETRY_STREAM": "on"}))
    assert seen["env"]["TELEMETRY_STREAM"] == "on"
    assert seen["env"]["IRIS_TELEMETRY_STREAM"] == "on"


# ---- persistent job logs (log_dir) ---------------------------------------
# In-memory jobs evaporate after _JOB_TTL; with log_dir set, _finish writes
# each finished job's log to disk (best-effort) so yesterday's failure is
# still readable from the console.

def test_finish_persists_log_file_with_header_and_lines(tmp_path):
    log_dir = str(tmp_path / "deploy-logs")
    svc = _svc(lambda p, e, on: (on("[1/6] hi"), on("[6/6] done"), 0)[2],
               log_dir=log_dir)
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    files = os.listdir(log_dir)
    assert files == ["%s-d1-onboard-%s.log" % (job["finished_at"], job["id"])]
    with open(os.path.join(log_dir, files[0])) as f:
        lines = f.read().splitlines()
    assert lines[0] == (
        "# job=%s device=d1 action=onboard state=done rc=0 queued_at=%s "
        "started_at=%s finished_at=%s platform=guestshell"
        % (job["id"], job["queued_at"], job["started_at"],
           job["finished_at"]))
    # Each body line carries its offset from started_at, so a slow job says
    # WHERE it was slow; the in-memory lines the console streams stay bare.
    assert len(lines[1:]) == len(job["lines"])
    for written, raw in zip(lines[1:], job["lines"]):
        m = re.match(r"^\[\+ *(\d+\.\d)s\] (.*)$", written)
        assert m, "no elapsed prefix on %r" % written
        assert m.group(2) == raw
        assert float(m.group(1)) >= 0.0


def test_failed_job_log_persisted_with_error_state(tmp_path):
    log_dir = str(tmp_path / "deploy-logs")
    svc = _svc(lambda p, e, on: (on("boom"), 2)[1], log_dir=log_dir)
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error"
    (name,) = os.listdir(log_dir)
    with open(os.path.join(log_dir, name)) as f:
        head = f.readline()
    assert " state=error rc=2 " in head


def test_persisted_log_filename_sanitizes_device_but_header_keeps_raw(tmp_path):
    log_dir = str(tmp_path / "deploy-logs")
    did = "sw 1/a"          # not filesystem-safe
    fleet = _Fleet({did: {"device_id": did, "device_ip": "10.0.0.1",
                          "model": "C9300", "management_type": "routed",
                          "credential_profile_id": "lab"}})
    creds = _Creds({"lab": {"device_user": "u", "device_pass": "p"}})
    svc = gui_onboard.OnboardService(
        fleet, creds, device_install="/fake/device-install.sh",
        crt_public="/fake/crt.pem", host_ip="10.9.9.9",
        mint_fn=lambda d: "TOK", run_fn=lambda p, e, on: 0,
        probe_fn=lambda dev, env: "C9300", log_dir=log_dir)
    job = _wait(svc, svc.start(did))
    assert job["state"] == "done"
    (name,) = os.listdir(log_dir)
    # filename carries the sanitized id, the header keeps the raw one
    assert name == "%s-sw_1_a-onboard-%s.log" % (job["finished_at"],
                                                 job["id"])
    with open(os.path.join(log_dir, name)) as f:
        assert " device=sw 1/a action=onboard " in f.readline()


def test_persisted_logs_pruned_to_newest(tmp_path, monkeypatch):
    monkeypatch.setattr(gui_onboard, "_MAX_PERSISTED_LOGS", 3)
    log_dir = str(tmp_path / "deploy-logs")
    os.makedirs(log_dir)
    for i in range(4):
        stale = os.path.join(log_dir, "%d-old-onboard-%04d.log" % (i, i))
        with open(stale, "w") as f:
            f.write("# old\n")
        os.utime(stale, (i + 1, i + 1))    # strictly older than the new log
    svc = _svc(lambda p, e, on: 0, log_dir=log_dir)
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    names = sorted(os.listdir(log_dir))
    assert len(names) == 3                 # pruned to the newest N
    assert "%s-d1-onboard-%s.log" % (job["finished_at"], job["id"]) in names
    assert "0-old-onboard-0000.log" not in names
    assert "1-old-onboard-0001.log" not in names


def test_log_persistence_failure_never_fails_the_job(tmp_path):
    # log_dir resolves to an existing FILE: makedirs raises inside
    # _persist_log — the write is best-effort, so the job still finishes
    # and the outcome is unchanged.
    blocked = tmp_path / "not-a-dir"
    blocked.write_text("x")
    svc = _svc(lambda p, e, on: 0, log_dir=str(blocked))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done" and job["returncode"] == 0


def test_a_job_past_the_deadline_stops_blocking_the_device():
    """A recipe whose output pipe never EOFs hangs forever. The job then never
    becomes terminal, is never evicted, and the busy guard refuses BOTH a
    re-onboard and an undeploy for that device -- permanently. That is how
    192.0.2.116 was stranded: onboard_start with no onboard_finished, no log,
    and a device already carrying a live Guest Shell.

    Past the deadline the job must be marked failed so the device frees up.
    """
    svc = _svc(lambda *a, **k: 0)
    svc._jobs["stuck"] = {
        "id": "stuck", "device_id": "dev-x", "action": "onboard",
        "state": "running", "queued_at": 1000, "started_at": 1000,
        "finished_at": None, "log": [],
    }
    # not yet overdue
    assert svc._reap_overdue(1000.0 + gui_onboard._JOB_DEADLINE - 1) == []
    # past the deadline it is reported
    assert svc._reap_overdue(1000.0 + gui_onboard._JOB_DEADLINE + 1) == ["stuck"]


# ---- uniform collision preflight across every platform --------------------
#
# preflight() used to return "not-required" for anything that was not a router,
# so Guest Shell did no checks at all and IOx only probed identity. Three
# platforms behaved three different ways, and a device left carrying IRIS-named
# config was refused on a router and silently accepted elsewhere.

_IRIS_NAMED = [
    "event manager applet IRIS-AGENT authorization bypass\n",
    "logging discriminator IRISQ mnemonics drops IOX_INST_WARN\n",
    "logging buffered discriminator IRISQ\n",
    "crypto pki trustpoint IRIS\n",
    "ip http client secure-trustpoint IRIS\n",
]


def _common_preflight_stub(monkeypatch, running="", apps="", files="",
                           version=None):
    """Feed a marker-delimited transcript to the shared preflight probe."""
    def run(argv, input=None, **kwargs):
        out = []
        for name, body in (("VERSION", version or _iox_show_version()),
                           ("RUNNING", running), ("APPS", apps),
                           ("FILES", files)):
            out.append("__IRIS_PREFLIGHT_%s__\n%s" % (name, body))
        return SimpleNamespace(returncode=0, stdout="\n".join(out))
    monkeypatch.setattr(gui_onboard.subprocess, "run", run)


@pytest.mark.parametrize("collision", _IRIS_NAMED)
def test_guestshell_preflight_rejects_iris_named_collisions(monkeypatch, collision):
    _common_preflight_stub(monkeypatch, running=collision)
    with pytest.raises(ValueError, match="already exists"):
        _REAL_GUESTSHELL_PREFLIGHT(
            {}, {"DEVICE_IP": "192.0.2.20"}, {"platform": "guestshell"}, "/repo")


@pytest.mark.parametrize("collision", _IRIS_NAMED)
def test_iox_preflight_rejects_iris_named_collisions(monkeypatch, collision):
    _common_preflight_stub(monkeypatch, running=collision)
    with pytest.raises(ValueError, match="already exists"):
        gui_onboard._default_iox_preflight(
            {}, {"DEVICE_IP": "192.0.2.30"}, {"platform": "iox"}, "/repo")


def test_guestshell_preflight_passes_on_a_clean_device(monkeypatch):
    _common_preflight_stub(monkeypatch, running="hostname sw1\n", apps="No App found\n",
                           files="Directory of bootflash:/guest-share/\n\nNo files in directory\n")
    evidence = _REAL_GUESTSHELL_PREFLIGHT(
        {}, {"DEVICE_IP": "192.0.2.20"}, {"platform": "guestshell"}, "/repo")
    assert evidence["status"] == "passed"
    assert evidence["device_identity"]


def test_guestshell_preflight_refuses_an_ios_xr_device(monkeypatch):
    """The preflight already holds 'show version', so it can classify without
    another SSH round trip -- and it is the LAST gate before
    device/device-install.sh touches the box. A console onboard arrives with
    the platform already resolved, so nothing inside resolve_platform ever
    looked at the family."""
    _common_preflight_stub(
        monkeypatch,
        version=("Cisco IOS XR Software, Version 24.4.1\n"
                 "cisco ASR-9906 (Intel 686 F6M14S4)\n"
                 "Processor board ID FOX1234ABCD\n"),
        running="hostname xr1\n", apps="No App found\n",
        files="Directory of bootflash:/guest-share/\n\nNo files in directory\n")
    dev = {"device_id": "xr1"}
    with pytest.raises(ValueError, match="IOS-XR"):
        _REAL_GUESTSHELL_PREFLIGHT(dev, {"DEVICE_IP": "192.0.2.20"},
                                   {"platform": "guestshell"}, "/repo")


def test_guestshell_preflight_records_the_family_it_read(monkeypatch):
    _common_preflight_stub(monkeypatch, running="hostname sw1\n", apps="No App found\n",
                           files="Directory of bootflash:/guest-share/\n\nNo files in directory\n")
    dev = {"device_id": "sw1"}
    _REAL_GUESTSHELL_PREFLIGHT(dev, {"DEVICE_IP": "192.0.2.20"},
                               {"platform": "guestshell"}, "/repo")
    assert dev["os_family"] == "xe"


def test_iox_preflight_still_returns_the_identity_it_always_did(monkeypatch):
    _common_preflight_stub(monkeypatch, running="hostname sw1\n", apps="No App found\n")
    evidence = gui_onboard._default_iox_preflight(
        {}, {"DEVICE_IP": "192.0.2.30"}, {"platform": "iox"}, "/repo")
    assert evidence["status"] == "passed"
    assert evidence["device_identity"] == "9ABC123"
    assert evidence["detected_model"] == "IE-3400"


def test_preflight_is_required_on_every_platform():
    """The dispatcher must not hand back 'not-required' for a platform simply
    because it is not a router -- that asymmetry was the bug."""
    svc = _svc(lambda p, e, on: 0)
    seen = {}

    def stub(dev, env, resolved):
        seen[resolved.get("platform")] = True
        return {"status": "passed"}

    svc._router_preflight = stub
    svc._iox_preflight = stub
    svc._guestshell_preflight = stub
    for platform in ("router", "guestshell", "iox"):
        result = svc.preflight("d1", {"platform": platform,
                                      "management_type": "routed"})
        assert result.get("status") != "not-required", \
            "%s still skips the collision preflight" % platform
    assert seen == {"router": True, "guestshell": True, "iox": True}


# ---------------------------------------------------------------------------
# An overdue job must not keep the device it is stuck on busy, and a device
# that leaves the fleet must not bequeath its in-flight work to a namesake.
# ---------------------------------------------------------------------------

def _stuck_job(svc, device_id="d1", action="onboard", state="running",
               started_at=1000):
    jid = "stuck-" + device_id + "-" + action
    svc._jobs[jid] = {
        "id": jid, "device_id": device_id, "action": action, "state": state,
        "queued_at": started_at, "started_at": started_at, "finished_at": None,
        "lines": [], "returncode": None, "_line_bytes": 0,
        "_log_truncated": False, "record_id": None, "resolved": None,
        "env_extra": None}
    return jid


def test_overdue_job_is_reaped_before_the_busy_guard_runs(tmp_path):
    """The reaper used to run AFTER the busy guard, past every path that
    returns or raises -- so it could only ever fire during a start() for some
    OTHER device, never the one actually stuck. A hung job therefore refused
    its own device for the whole deadline window with no way to clear it."""
    svc = _svc(lambda *a, **k: 0, now_fn=lambda: 1000.0 + gui_onboard._JOB_DEADLINE + 5)
    jid = _stuck_job(svc, "d1", action="undeploy")

    # the opposite action on the same device: refused outright before the fix
    new_id = svc.start("d1", action="onboard")

    assert new_id != jid
    assert svc._jobs[jid]["state"] == "error"


def test_reaped_job_records_the_key_every_reader_uses(tmp_path):
    """It wrote an "rc" key. Every reader -- get_job, the console, the persisted
    log header -- reads "returncode", so the failure carried no exit status
    anywhere it could be seen."""
    svc = _svc(lambda *a, **k: 0, now_fn=lambda: 1000.0 + gui_onboard._JOB_DEADLINE + 5)
    jid = _stuck_job(svc)
    svc.reap_overdue_jobs()

    job = svc.get_job(jid)
    assert job["state"] == "error"
    assert job["returncode"] == -1
    assert "rc" not in job, "the stray key is back"


def test_reaped_job_is_persisted_and_audited(tmp_path):
    """Bypassing _finish meant a reaped job wrote no log and emitted no
    *_finished event: it failed with nothing anywhere saying so.

    Rewritten: the old version planted a job with no installer process and
    asserted the handle was gone after the reap, which encoded the defect --
    the reaper dropped a LIVE handle without signalling it. Reaping now
    signals the installer and keeps the handle (abort stays reachable) until
    the worker returns; the log and audit come from that ordinary finish."""
    events = []
    clock = {"t": 1000.0}
    log_dir = str(tmp_path / "deploy-logs")
    proc = threading.Event()
    signalled = []

    class Proc:
        def terminate(self):
            signalled.append("TERM")
            proc.set()

    def run_fn(p, e, on, on_proc):
        on_proc(Proc())
        proc.wait(10)
        return 143

    svc = _svc(run_fn, now_fn=lambda: clock["t"], log_dir=log_dir,
               audit_fn=lambda **kw: events.append(kw))
    jid = svc.start("d1")
    assert _wait_for(lambda: jid in svc._procs)
    clock["t"] = 1000.0 + gui_onboard._JOB_DEADLINE + 5
    assert svc.reap_overdue_jobs() == [jid]
    assert signalled == ["TERM"]
    assert jid in svc._procs, "handle dropped while the installer was alive"

    job = _wait(svc, jid)
    assert job["state"] == "error" and job["returncode"] == 143
    logs = os.listdir(log_dir)
    assert len(logs) == 1, logs
    with open(os.path.join(log_dir, logs[0])) as stream:
        header = stream.readline()
    assert "rc=143" in header and "state=error" in header
    assert [e for e in events if e.get("event") == "onboard_finished"], events
    # and the installer handle is released once the worker has returned
    assert jid not in svc._procs


def test_cancel_device_stops_queued_and_running_work():
    """A job record is keyed on the device id alone, so one left behind by a
    deleted device keeps the busy guard armed against the next device
    registered under that name."""
    svc = _svc(lambda *a, **k: 0)
    queued = _stuck_job(svc, "d1", action="onboard", state="queued")
    other = _stuck_job(svc, "d2", action="onboard", state="queued")

    result = svc.cancel_device("d1")

    assert result["cancelled"] == 1
    assert svc._jobs[queued]["state"] == "cancelled"
    assert svc._jobs[other]["state"] == "queued", "another device was touched"


def test_cancel_device_is_a_no_op_for_an_unknown_device():
    svc = _svc(lambda *a, **k: 0)
    assert svc.cancel_device("never-existed") == {"cancelled": 0, "aborted": 0}


def test_log_is_on_disk_before_the_job_reports_terminal(tmp_path):
    """The deploy log must be fully written BEFORE the job's terminal state is
    visible to pollers. The console (and the API's own tests) poll the job to
    'done' and immediately read /api/deploy-logs; persisting after the state
    flip raced that read — an operator got a created-but-empty file. Pin the
    ordering itself: at the moment _persist_log runs, the job must still be
    reported as running."""
    log_dir = str(tmp_path / "deploy-logs")
    svc = _svc(lambda p, e, on: (on("[1/6] hi"), on("[6/6] done"), 0)[2],
               log_dir=log_dir)
    seen = {}
    real_persist = svc._persist_log

    def spying_persist(job):
        live = svc.get_job(job["id"])
        seen["state_at_persist"] = live["state"] if live else None
        real_persist(job)

    svc._persist_log = spying_persist
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert seen, "persist hook never ran"
    assert seen["state_at_persist"] not in ("done", "error"), (
        "log persisted AFTER the terminal state was already visible: %r"
        % seen["state_at_persist"])


def test_persist_failure_still_finishes_the_job(tmp_path):
    """Persisting before the state flip must not let a persist failure wedge
    the job in 'running' forever — best-effort stays best-effort."""
    log_dir = str(tmp_path / "deploy-logs")
    svc = _svc(lambda p, e, on: (on("[6/6] done"), 0)[1], log_dir=log_dir)

    def broken_persist(job):
        raise OSError("volume is read-only")

    svc._persist_log = broken_persist
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert job["returncode"] == 0


def test_probe_sections_survive_an_input_echoing_transport(monkeypatch):
    """An ssh -tt runner (the XR transport) echoes the whole piped request at
    the TOP of the transcript before any command runs, so every marker appears
    twice: once in the input-echo blob (whose 'section' is just the next typed
    line) and once where it actually executed. Section extraction must read
    the EXECUTED one — first-match returned the typed text and made the XR
    preflight classify an empty banner on the first live onboard."""
    transcript = (
        "echo __IRIS_PREFLIGHT_VERSION__\n"
        "show version\n"
        "echo __IRIS_PREFLIGHT_APPS__\n"
        "show appmgr application-table\n"
        "\n"
        "RP/0/RP0/CPU0:r1#echo __IRIS_PREFLIGHT_VERSION__\n"
        "% Invalid input detected at '^' marker.\n"
        "RP/0/RP0/CPU0:r1#show version\n"
        "Cisco IOS XR Software, Version 25.4.2 LNT\n"
        "RP/0/RP0/CPU0:r1#echo __IRIS_PREFLIGHT_APPS__\n"
        "% Invalid input detected at '^' marker.\n"
        "RP/0/RP0/CPU0:r1#show appmgr application-table\n"
    )

    class _Out:
        returncode = 0
        stdout = transcript

    monkeypatch.setattr(gui_onboard.subprocess, "run", lambda *a, **k: _Out())
    sections = gui_onboard._probe_sections(
        "runner.sh", {"DEVICE_IP": "10.0.0.1"},
        (("version", "show version"), ("apps", "show appmgr application-table")),
        "xr")
    assert "Cisco IOS XR Software" in sections["version"]
    assert gui_onboard.parse_os_family(sections["version"]) == "xr"


# ---------------------------------------------------------------------------
# The deadline reaper: run time is measured from started_at only, a queued
# job is never reaped, and reaping a RUNNING job stops its installer instead
# of abandoning it.
# ---------------------------------------------------------------------------

class _BlockedProc:
    """A fake installer handle (no pid -> _signal_group falls back to the
    Popen methods, exactly like the abort tests above)."""
    def __init__(self, release_on_term=True, release_on_kill=True):
        self.release = threading.Event()
        self.signals = []
        self._on_term = release_on_term
        self._on_kill = release_on_kill

    def terminate(self):
        self.signals.append("TERM")
        if self._on_term:
            self.release.set()

    def kill(self):
        self.signals.append("KILL")
        if self._on_kill:
            self.release.set()


def _blocked_runner(proc, rc=137):
    """A proc-reporting runner that blocks until the fake proc is released."""
    started = threading.Event()

    def run_fn(p, e, on, on_proc):
        on_proc(proc)
        started.set()
        on("running")
        proc.release.wait(10)
        return rc
    return run_fn, started


def test_reaper_never_counts_queue_wait_as_run_time():
    """A queued job's wait is not run time: it has touched nothing and is
    bounded by cancel. Counting it used to make the next start() -- for ANY
    device -- select the queued job, crash on its missing started_at (the
    operator's request died with a traceback) and leave it flagged failed but
    still in the work queue, so it later ran the installer anyway."""
    proc = _BlockedProc()
    run_fn, started = _blocked_runner(proc, rc=0)
    clock = {"t": 1000.0}
    svc = _multi_svc(3, run_fn, max_concurrent=1, now_fn=lambda: clock["t"])
    j1 = svc.start("d1")
    assert started.wait(5)
    j2 = svc.start("d2")
    assert svc.get_job(j2)["state"] == "queued"
    assert svc.get_job(j2)["started_at"] is None

    clock["t"] = 1000.0 + gui_onboard._JOB_DEADLINE + 5
    j3 = svc.start("d3")                      # must not raise
    queued = svc.get_job(j2)
    assert queued["state"] == "queued"
    assert queued["finished_at"] is None
    assert not any("deadline" in ln for ln in queued["lines"])
    assert svc.get_job(j3)["state"] == "queued"

    # only the RUNNING job past its deadline was acted on
    assert svc.get_job(j1)["state"] == "running"
    assert proc.signals == ["TERM"]
    proc.release.set()
    assert _wait(svc, j2)["state"] == "done"
    assert _wait(svc, j3)["state"] == "done"
    assert not any("deadline" in ln for ln in svc.get_job(j2)["lines"])


def test_finish_tolerates_a_job_that_never_started():
    """_finish measured the duration from started_at, which is None for a
    job that never won a slot; it must fall back to the queue stamp."""
    events = []
    svc = _svc(lambda p, e, on: 0, now_fn=lambda: 5000.0,
               audit_fn=lambda **kw: events.append(kw))
    jid = _stuck_job(svc, "d1", state="queued")
    svc._jobs[jid]["started_at"] = None
    svc._jobs[jid]["queued_at"] = 4000
    svc._finish(jid, "error", -1)
    job = svc.get_job(jid)
    assert job["state"] == "error" and job["returncode"] == -1
    assert events and "16m40s" in events[-1]["detail"]


def test_reaping_a_running_job_signals_the_installer_and_keeps_the_device_busy(tmp_path):
    """Reaping used to drop the Popen handle without a signal: the installer
    kept running against the device, abort() went dead, the busy guard
    opened -- so an undeploy was ACCEPTED and ran while the install was still
    executing on the same box -- and the blocked worker was never replaced.

    Now the reaper behaves like an operator abort: the process group is
    signalled, the job stays running (busy guard truthful, abort reachable)
    until the worker returns, and the worker then finishes the job the
    ordinary way with the real rc and a needs-reconcile record."""
    proc = _BlockedProc(release_on_term=False)
    run_fn, started = _blocked_runner(proc, rc=137)
    clock = {"t": 1000.0}
    record_store = deployment_records.DeploymentRecordStore(str(tmp_path / "state"))
    events = []
    svc = _multi_svc(2, run_fn, max_concurrent=1, now_fn=lambda: clock["t"],
                     record_store=record_store,
                     audit_fn=lambda **kw: events.append(kw))
    record = record_store.create({
        "controller_id": "c", "device_id": "d1", "inventory_revision": 1,
        "plan_hash": "h" * 64, "preflight": {"status": "pending"},
        "resolved": {"platform": "guestshell", "management_type": "routed"},
        "resources": []})
    j1 = svc.start("d1", prepare=lambda: record["record_id"])
    assert started.wait(5)
    assert record_store.get(record["record_id"])["state"] == "applying"

    clock["t"] = 1000.0 + gui_onboard._JOB_DEADLINE + 5
    assert svc.reap_overdue_jobs() == [j1]
    assert proc.signals == ["TERM"]
    job = svc.get_job(j1)
    assert job["state"] == "running", "job went terminal with the installer still running"
    assert any("deadline" in ln for ln in job["lines"])
    # the device is still busy: the opposite action is refused, not interleaved
    with pytest.raises(ValueError, match="busy"):
        svc.start("d1", action="undeploy")
    # abort stays reachable while the installer lives
    assert svc.abort(j1) is True
    assert proc.signals == ["TERM", "TERM"]
    # a second reap inside the grace period does nothing more
    assert svc.reap_overdue_jobs() == []

    proc.release.set()                        # the installer finally dies
    job = _wait(svc, j1)
    assert job["state"] == "error" and job["returncode"] == 137
    assert record_store.get(record["record_id"])["state"] == "needs-reconcile"
    assert j1 not in svc._procs
    assert [e for e in events if e.get("event") == "onboard_finished"]
    # and the pool worker is free again: the next job actually runs
    proc2 = _BlockedProc()
    proc2.release.set()
    svc._run = _blocked_runner(proc2, rc=0)[0]
    assert _wait(svc, svc.start("d2"))["state"] == "done"


def test_reaper_escalates_to_kill_and_only_then_marks_failed(tmp_path):
    """An installer that ignores SIGTERM is SIGKILLed after the grace period;
    only when even that leaves the job running is it marked failed -- with
    the ordinary finish bookkeeping (returncode, persisted log, audit)."""
    proc = _BlockedProc(release_on_term=False, release_on_kill=False)
    run_fn, started = _blocked_runner(proc, rc=137)
    clock = {"t": 1000.0}
    events = []
    log_dir = str(tmp_path / "deploy-logs")
    svc = _multi_svc(1, run_fn, max_concurrent=1, now_fn=lambda: clock["t"],
                     log_dir=log_dir, audit_fn=lambda **kw: events.append(kw))
    j1 = svc.start("d1")
    assert started.wait(5)

    clock["t"] = 1000.0 + gui_onboard._JOB_DEADLINE + 5
    assert svc.reap_overdue_jobs() == [j1]
    assert proc.signals == ["TERM"]
    clock["t"] += gui_onboard._REAP_GRACE + 1
    assert svc.reap_overdue_jobs() == [j1]
    assert proc.signals == ["TERM", "KILL"]
    assert svc.get_job(j1)["state"] == "running"
    clock["t"] += gui_onboard._REAP_GRACE + 1
    assert svc.reap_overdue_jobs() == [j1]
    job = svc.get_job(j1)
    assert job["state"] == "error" and job["returncode"] == -1
    assert any("could not be stopped" in ln for ln in job["lines"])
    assert len(os.listdir(log_dir)) == 1
    assert [e for e in events if e.get("event") == "onboard_finished"]
    assert svc.reap_overdue_jobs() == []      # terminal: never reaped again
    proc.release.set()                        # let the worker thread go


def test_a_queued_job_past_the_deadline_is_not_overdue():
    svc = _svc(lambda *a, **k: 0)
    jid = _stuck_job(svc, "dev-q", state="queued", started_at=1000)
    svc._jobs[jid]["started_at"] = None
    assert svc._reap_overdue(1000.0 + gui_onboard._JOB_DEADLINE + 1) == []
    assert svc.reap_overdue_jobs() == []
    assert svc._jobs[jid]["state"] == "queued"


def test_escalation_advances_with_no_idle_worker_and_no_operator_action(monkeypatch):
    """One wedged job on a pool of one: every worker is blocked inside the
    installer, so no idle-worker queue timeout is left to call the reaper, and
    an unattended console makes no further start(). The escalation therefore
    never advanced -- the installer kept running and the device stayed busy
    until an operator clicked something. A maintenance thread now drives it.

    Nothing in this test calls reap_overdue_jobs(), start(), or any other
    service method between the submission and the terminal state."""
    monkeypatch.setattr(gui_onboard, "_MAINTENANCE_INTERVAL", 0.02)
    proc = _BlockedProc(release_on_term=False, release_on_kill=False)
    run_fn, started = _blocked_runner(proc, rc=137)
    clock = {"t": 1000.0}
    svc = _multi_svc(1, run_fn, max_concurrent=1, now_fn=lambda: clock["t"])
    try:
        j1 = svc.start("d1")
        assert started.wait(5)
        assert len(svc._workers) == 1   # the only worker is inside run_fn

        clock["t"] = 1000.0 + gui_onboard._JOB_DEADLINE + 5
        assert _wait_for(lambda: proc.signals == ["TERM"], timeout=5), \
            "the deadline passed and nothing signalled the installer"
        clock["t"] += gui_onboard._REAP_GRACE + 1
        assert _wait_for(lambda: proc.signals == ["TERM", "KILL"], timeout=5), \
            "SIGTERM was ignored and nothing escalated to SIGKILL"
        clock["t"] += gui_onboard._REAP_GRACE + 1
        job = _wait(svc, j1, timeout=5)
        assert job["state"] == "error" and job["returncode"] == -1
        # ... and the busy guard is open again: the device is usable
        assert svc.start("d1") != j1
    finally:
        proc.release.set()
        svc.stop_maintenance()


def test_maintenance_thread_retires_itself_when_no_job_is_left(monkeypatch):
    """It is one timed wait per tick, not a busy loop, and a service that is
    not onboarding anything carries no extra thread at all."""
    monkeypatch.setattr(gui_onboard, "_MAINTENANCE_INTERVAL", 0.02)
    svc = _multi_svc(1, lambda p, e, on: 0)
    assert svc._maintenance is None          # never started before a job
    try:
        assert _wait(svc, svc.start("d1"))["state"] == "done"
        monkeypatch.setattr(gui_onboard, "_JOB_TTL", 0)   # let it be evicted
        assert _wait_for(lambda: svc._maintenance is None, timeout=5), \
            "the maintenance thread outlived the last job"
    finally:
        svc.stop_maintenance()


# ---------------------------------------------------------------------------
# Every platform's preflight evidence is bound into the job's plan (and,
# through pre_apply, onto the deployment record) -- not only the router's.
# ---------------------------------------------------------------------------

def test_guestshell_onboard_binds_preflight_evidence_through_pre_apply():
    """The Guest Shell preflight's evidence used to be discarded, so the
    record never learned which board it described and a later teardown ran
    with an empty EXPECTED_DEVICE_IDENTITY."""
    seen, bound = {}, {}

    def pre_apply(evidence):
        bound["evidence"] = dict(evidence)
        return gui_onboard.bind_preflight(
            {"platform": "guestshell", "management_type": "routed",
             "device_ip": "10.0.0.1"}, evidence)

    svc = _svc(lambda p, e, on: seen.update(e) or 0,
               guestshell_preflight_fn=lambda dev, env, resolved: {
                   "status": "passed", "device_identity": "FOC1111GS",
                   "detected_model": "C9300-48P"})
    job = _wait(svc, svc.start("d1", resolved={
        "platform": "guestshell", "management_type": "routed",
        "device_ip": "10.0.0.1"}, pre_apply=pre_apply))
    assert job["state"] == "done"
    assert bound["evidence"]["device_identity"] == "FOC1111GS"
    assert job["resolved"]["device_identity"] == "FOC1111GS"
    assert seen["EXPECTED_DEVICE_IDENTITY"] == "FOC1111GS"
    assert seen["MODEL"] == "C9300-48P"


def test_guestshell_onboard_fails_closed_without_a_bindable_identity():
    ran = []
    svc = _svc(lambda p, e, on: ran.append(1) or 0,
               guestshell_preflight_fn=lambda dev, env, resolved: {
                   "status": "passed"})
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error" and ran == []
    assert any("device identity" in ln for ln in job["lines"])


def test_bind_preflight_dispatches_on_platform():
    assert gui_onboard.bind_preflight(
        {"platform": "iox"}, {"status": "passed", "device_identity": "A1"}
    )["device_identity"] == "A1"
    assert gui_onboard.bind_preflight(
        {"platform": "guestshell"}, {"status": "passed", "device_identity": "B2"}
    )["device_identity"] == "B2"
    xr = gui_onboard.bind_preflight(
        {"platform": "xr-appmgr"}, {"status": "passed", "detected_model": "8201"})
    assert xr["model"] == "8201" and "device_identity" not in xr
    with pytest.raises(ValueError, match="did not pass"):
        gui_onboard.bind_preflight({"platform": "xr-appmgr"}, {"status": "failed"})
    with pytest.raises(ValueError, match="no preflight binding"):
        gui_onboard.bind_preflight({"platform": "toaster"}, {"status": "passed"})


def test_build_env_takes_device_ip_from_the_resolved_plan_for_every_type():
    """Undeploy renders from the record's resolved plan. Only the router
    types used to take DEVICE_IP from it; Guest Shell and IOx teardowns
    followed the live fleet row, so an inventory edit after deployment
    retargeted the teardown at whatever answered at the new address."""
    svc = _svc(lambda p, e, on: 0)
    svc.fleet.upsert({"device_id": "d1", "device_ip": "203.0.113.99"})
    _dev, env = svc._build_env("d1", mint=False, resolved={
        "platform": "guestshell", "management_type": "routed",
        "device_ip": "10.0.0.1", "device_identity": "FOC1111GS"})
    assert env["DEVICE_IP"] == "10.0.0.1"
    assert env["EXPECTED_DEVICE_IDENTITY"] == "FOC1111GS"
    _dev, env = svc._build_env("d1", mint=False, resolved={
        "platform": "iox", "management_type": "inband",
        "device_ip": "10.0.0.1", "inband_vlan": "120"})
    assert env["DEVICE_IP"] == "10.0.0.1"
    assert env["IOS_SSH_HOST"] == "10.0.0.1"
    # a plan without an address (legacy start) still falls back to the row
    _dev, env = svc._build_env("d1", mint=False)
    assert env["DEVICE_IP"] == "203.0.113.99"


# ---------------------------------------------------------------------------
# svi_igp (issue #85): SVI_IGP used to be settable only as a process-wide env
# var on the server -- wrong for a server that onboards devices into
# different fabrics. A per-device record value now overrides it; a device
# whose record says nothing must still see whatever SVI_IGP the server
# process itself was started with (e.g. server/.env), unchanged.
# ---------------------------------------------------------------------------

def test_build_env_sets_svi_igp_from_the_resolved_record(monkeypatch):
    monkeypatch.delenv("SVI_IGP", raising=False)
    svc = _svc(lambda p, e, on: 0)
    _dev, env = svc._build_env("d1", mint=False, resolved={
        "platform": "guestshell", "management_type": "routed",
        "device_ip": "10.0.0.1", "svi_igp": "isis"})
    assert env["SVI_IGP"] == "isis"


def test_build_env_falls_back_to_the_inherited_svi_igp_env_when_record_is_blank(monkeypatch):
    # server/.env (or any process-wide setting) stays the default for a
    # device whose own record carries no override -- the exact SD-Access
    # workaround issue #85 exists to make unnecessary.
    monkeypatch.setenv("SVI_IGP", "isis")
    svc = _svc(lambda p, e, on: 0)
    _dev, env = svc._build_env("d1", mint=False, resolved={
        "platform": "guestshell", "management_type": "routed",
        "device_ip": "10.0.0.1", "svi_igp": ""})
    assert env["SVI_IGP"] == "isis"
    # and identically when the resolved plan carries no key at all
    _dev, env = svc._build_env("d1", mint=False, resolved={
        "platform": "guestshell", "management_type": "routed",
        "device_ip": "10.0.0.1"})
    assert env["SVI_IGP"] == "isis"


def test_build_env_record_svi_igp_overrides_the_inherited_env_default(monkeypatch):
    # The per-device value wins over the process-wide one when both are set.
    monkeypatch.setenv("SVI_IGP", "isis")
    svc = _svc(lambda p, e, on: 0)
    _dev, env = svc._build_env("d1", mint=False, resolved={
        "platform": "guestshell", "management_type": "routed",
        "device_ip": "10.0.0.1", "svi_igp": "none"})
    assert env["SVI_IGP"] == "none"


# ---- IOx controller custody -------------------------------------------------

def _request_value(request, key):
    if isinstance(request, dict):
        return request.get(key)
    return getattr(request, key)


def _request_has(request, key):
    if isinstance(request, dict):
        return key in request
    return hasattr(request, key)


def _cancel_value(cancel):
    return cancel() if callable(cancel) else cancel.is_set()


class _FrozenIoxController:
    """Small behavioral fake for the frozen controller/service boundary."""

    def __init__(self, events=None, result=None, entered=None, release=None,
                 identity=None):
        self.events = events if events is not None else []
        self.result = result if result is not None else {}
        self.requests = []
        self.callback_calls = []
        self.preflight_results = []
        self.prepare_results = []
        self.entered = entered
        self.release = release
        self.identity = identity or {
            "board_identity": "FDO2547X9AB",
            "model": "IE-3400", "os_family": "xe", "platform": "iox",
        }

    def _run(self, operation, request, prepare, preflight, on_output, cancel):
        self.events.append("controller:" + operation)
        self.requests.append(request)
        job_id = _request_value(request, "job_id")
        assert isinstance(job_id, str) and re.fullmatch(
            r"[0-9a-f]{16}", job_id)
        if self.entered is not None:
            self.entered.set()
        if self.release is not None:
            assert self.release.wait(5.0)
        assert not _cancel_value(cancel)
        identity = dict(self.identity)
        self.callback_calls.append(("preflight", request, identity))
        self.preflight_results.append(preflight(request, identity))
        self.callback_calls.append(("prepare", request, identity))
        record_id = prepare(request, identity)
        self.prepare_results.append(record_id)
        on_output("stdout", b"controller-owned IOx output\n")
        result = {
            "result_code": 0,
            "returncode": 0,
            "recovery_code": None,
            "record_id": record_id,
            "iox_verification": None,
            "iox_session": None,
        }
        result.update(
            self.result(request) if callable(self.result) else self.result)
        return result

    def run_install(self, request, prepare, preflight, on_output, cancel):
        return self._run(
            "install", request, prepare, preflight, on_output, cancel)

    def run_uninstall(self, request, prepare, preflight, on_output, cancel):
        return self._run(
            "uninstall", request, prepare, preflight, on_output, cancel)


class _CancellingIoxController(_FrozenIoxController):
    def __init__(self):
        _FrozenIoxController.__init__(self)
        self.entered = threading.Event()
        self.stop = threading.Event()

    def run_install(self, request, prepare, preflight, on_output, cancel):
        self.requests.append(request)
        self.entered.set()
        deadline = time.time() + 5.0
        while (not _cancel_value(cancel) and not self.stop.is_set()
               and time.time() < deadline):
            time.sleep(0.005)
        assert _cancel_value(cancel), "abort did not reach controller"
        job_id = _request_value(request, "job_id")
        assert isinstance(job_id, str) and re.fullmatch(
            r"[0-9a-f]{16}", job_id)
        return {
            "result_code": 130, "returncode": None, "recovery_code": 0,
            "record_id": None, "iox_verification": None,
            "iox_session": {
                "attempt_id": "b" * 32, "job_id": job_id,
                "device_id": "d1", "board_identity": "FDO2547X9AB",
                "operation": "install", "teardown_mode": "none",
                "record_id": None, "state": "reaped",
                "mutation_blocked": False,
            },
        }


def _iox_controller_service(tmp_path, controller, raw_runs=None,
                            preflight_fn=None, mint_fn=None, fleet=None,
                            probe_fn=None, artifact_names=None, creds=None):
    artifact_names = artifact_names or ("iris-arm64.tar",)
    for name in artifact_names:
        (tmp_path / name).write_bytes(b"frozen-wrapper")
    raw_runs = raw_runs if raw_runs is not None else []

    def legacy_runner(*args, **kwargs):
        raw_runs.append((args, kwargs))
        raise AssertionError("real IOx work escaped controller custody")

    return gui_onboard.OnboardService(
        fleet or _iox_fleet(platform="iox", model="IE-3400"),
        creds or _iox_creds(),
        host_ip="10.9.9.9",
        mint_fn=mint_fn or (lambda device_id: "TOK-" + device_id),
        run_fn=legacy_runner,
        probe_fn=probe_fn,
        iox_preflight_fn=preflight_fn or _iox_preflight_ok(),
        artifacts_dir=str(tmp_path), iox_controller=controller)


def test_iox_console_job_reaches_a_real_controller_and_recipe_peer(tmp_path):
    """Freeze the whole Console -> controller -> private recipe handoff."""
    import test_iox_verification as iox_spec

    board_identity = iox_spec._BOARD
    model = "IE-3400-8T2S"
    wrapper_source = iox_spec._write_wrapper(
        tmp_path, markers=("package.sign", "package.cert"))
    wrapper_path = tmp_path / "iris-arm64.tar"
    with open(wrapper_source, "rb") as source:
        wrapper_path.write_bytes(source.read())

    recipe_event = tmp_path / "recipe-events"
    recipe = iox_spec._write_recipe_peer(
        tmp_path, operations=iox_spec._install_operations(),
        event_path=str(recipe_event))
    state_dir = tmp_path / "state"
    store = deployment_records.DeploymentRecordStore(str(state_dir))
    transport = iox_spec._TransportFactory(board=board_identity)
    credentials = {
        "device_user": "admin",
        "device_pass": "console-device-pass-SECRET",
        "enable_secret": "console-enable-SECRET",
    }
    enrollment_token = "console-catalog-token-SECRET"
    controller = iox_spec._controller(
        tmp_path, store, transport,
        credential_resolver=lambda reference: (
            credentials if reference == "lab" else None),
        enrollment_token_minter=lambda device_id: enrollment_token,
        recipe_argv_by_action={"install": ["/bin/bash", recipe]})
    assert isinstance(controller, iox_spec._module().IoxController)
    legacy_calls = []

    def legacy_runner(*args, **kwargs):
        legacy_calls.append((args, kwargs))
        raise AssertionError("IOx job bypassed controller custody")

    service = gui_onboard.OnboardService(
        _iox_fleet(platform="iox", model=model), _iox_creds(),
        host_ip="10.9.9.9", mint_fn=lambda device_id: enrollment_token,
        run_fn=legacy_runner,
        iox_preflight_fn=_iox_preflight_ok(
            identity=board_identity, model=model),
        artifacts_dir=str(tmp_path), record_store=store,
        iox_controller=controller)

    def prepare_record():
        record = store.create({
            "record_id": "record-1", "controller_id": "controller-1",
            "device_id": "d1", "inventory_revision": 1,
            "plan_hash": "a" * 64,
            "resolved": {
                "platform": "iox", "model": model, "os_family": "xe",
                "device_ip": "10.0.0.1", "management_type": "routed",
                "device_identity": board_identity, "vlan": "666",
                "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                "guest_ip": "10.0.0.3",
                "resources": [
                    {"kind": "iox-app", "ownership": "iris-created"}],
            },
            "preflight": {
                "status": "passed", "device_identity": board_identity,
                "detected_model": model,
            },
            "resources": [
                {"kind": "iox-app", "ownership": "iris-created"}],
        })
        return record["record_id"]

    try:
        job_id = service.start("d1", prepare=prepare_record)
        job = _wait(service, job_id)
    finally:
        controller.close()

    assert re.fullmatch(r"[0-9a-f]{16}", job_id)
    assert legacy_calls == []
    assert job["state"] == "done"
    assert job["result_code"] == 0
    assert job["returncode"] == 0
    assert job["recovery_code"] is None
    assert job["record_id"] == "record-1"
    assert recipe_event.read_bytes() == b"finish_ack\n"

    # Reload through a separate store instance: this must be the durable
    # deployment record and terminal authority journal, not test-fake state.
    persisted_store = deployment_records.DeploymentRecordStore(str(state_dir))
    persisted_record = persisted_store.get("record-1", strict=True)
    assert persisted_record["state"] == "active"
    journal = persisted_record["iox_verification"]
    assert journal["record_id"] == job["record_id"]
    assert journal["controller_id"] == iox_spec._CONTROLLER_ID
    assert journal["board_identity"] == board_identity
    assert journal["phase"] == "unchanged"
    assert journal["unresolved"] is False
    assert set(job["iox_verification"]) == {
        "schema_version", "record_id", "transaction_id", "revision",
        "board_identity", "prior_state", "current_state", "phase",
        "unresolved", "created_at", "updated_at", "observed_at",
        "terminal_at", "error_category"}
    assert job["iox_verification"]["record_id"] == journal["record_id"]
    assert job["iox_verification"]["transaction_id"] == journal[
        "transaction_id"]
    assert job["iox_verification"]["phase"] == journal["phase"]
    assert job["iox_session"]["job_id"] == job_id

    persisted_files = []
    for root, _directories, filenames in os.walk(str(tmp_path)):
        for filename in filenames:
            path = os.path.join(root, filename)
            with open(path, "rb") as stream:
                persisted_files.append(stream.read())
    assert any(job_id.encode("ascii") in body for body in persisted_files), (
        "controller custody never durably associated the Console job ID")
    published = repr(job).encode("utf-8")
    for secret in (credentials["device_pass"], credentials["enable_secret"],
                   enrollment_token):
        needle = secret.encode("utf-8")
        assert needle not in published
        assert all(needle not in body for body in persisted_files)


def test_real_iox_teardown_accepts_restored_predecessor_transition(tmp_path):
    """A restored scheduled predecessor remains usable for real teardown."""
    import test_deployment_records as records_spec
    import test_iox_verification as iox_spec

    board_identity = records_spec._IOX_BOARD
    model = "IE-3400-8T2S"
    state_dir = tmp_path / "state"
    store = deployment_records.DeploymentRecordStore(str(state_dir))
    recipe_event = tmp_path / "teardown-recipe-events"
    recipe = iox_spec._write_recipe_peer(
        tmp_path, event_path=str(recipe_event))
    transport = iox_spec._TransportFactory(board=board_identity)
    controller = iox_spec._controller(
        tmp_path, store, transport,
        credential_resolver=lambda reference: (
            {"device_user": "admin", "device_pass": "device-pass",
             "enable_secret": "enable-pass"}
            if reference == "lab" else None),
        recipe_argv_by_action={"uninstall": ["/bin/bash", recipe]})
    provenance = records_spec._provenance(device_id="d1")
    resolved = {
        "platform": "iox", "model": model, "os_family": "xe",
        "device_ip": "10.0.0.1", "management_type": "routed",
        "device_identity": board_identity,
    }
    resources = [{"kind": "iox-app", "ownership": "iris-created"}]
    store.create(records_spec._record(
        record_id="old", device_id="d1",
        controller_id=records_spec._IOX_CONTROLLER,
        schedule_provenance=provenance, resolved=resolved,
        resources=resources))
    transcript_ref, observation = records_spec._iox_transcript(
        state_dir, state="disabled", board_identity=board_identity)
    journal = store.iox_begin(
        "old", records_spec._IOX_CONTROLLER, board_identity,
        records_spec._iox_wrapper(), observation, transcript_ref)
    store.recover_interrupted()
    terminal_journal = store.iox_event(
        "old", journal["transaction_id"], journal["revision"],
        journal["phase"], "unchanged", {
            "reason": "initially_disabled", "observation": None,
            "transcript_refs": []})
    admitted = store.admit_scheduled(
        records_spec._record(
            record_id="new", device_id="d1",
            controller_id=records_spec._IOX_CONTROLLER,
            resolved=resolved, resources=resources),
        provenance=provenance, attempt=1,
        authorize=lambda *_args: None, resume_record_id="old")
    assert store.get("old", strict=True)["state"] == "abandoned"
    store.retire_planned(admitted["record"]["record_id"])
    restored = store.get("old", strict=True)
    assert restored["state"] == "unknown"
    assert restored["iox_verification"] == terminal_journal

    service = gui_onboard.OnboardService(
        _iox_fleet(platform="iox", model=model), _iox_creds(),
        host_ip="10.9.9.9", mint_fn=lambda device_id: "unused",
        run_fn=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("IOx job bypassed controller custody")),
        iox_preflight_fn=_iox_preflight_ok(
            identity=board_identity, model=model),
        artifacts_dir=str(tmp_path), record_store=store,
        iox_controller=controller)

    try:
        job = _wait(service, service.start(
            "d1", action="undeploy", record_id="old",
            prepare=lambda: "old", teardown_mode="recorded"))
    finally:
        controller.close()

    assert job["state"] == "done", job["lines"]
    assert job["result_code"] == 0
    assert job["record_id"] == "old"
    assert recipe_event.read_bytes() == b"finish_ack\n"
    removed = store.get("old", strict=True)
    assert removed["state"] == "removed"
    assert removed["iox_verification"] == terminal_journal


def test_real_iox_install_routes_only_through_the_controller(tmp_path):
    raw_runs = []
    controller = _FrozenIoxController()
    service = _iox_controller_service(tmp_path, controller, raw_runs)

    job_id = service.start("d1")
    job = _wait(service, job_id)

    assert job["state"] == "done"
    assert raw_runs == []
    assert len(controller.requests) == 1
    request = controller.requests[0]
    assert _request_value(request, "action") == "install"
    assert _request_value(request, "device_id") == "d1"
    assert _request_value(request, "job_id") == job_id
    assert _request_value(request, "credential_ref") == "lab"
    assert _request_value(request, "teardown_mode") == "none"
    assert _request_value(request, "record_id") is None
    assert _request_has(request, "wrapper_path")
    assert _request_value(request, "wrapper_path").endswith("iris-arm64.tar")
    target = _request_value(request, "target")
    assert {key: target[key] for key in ("host", "port", "platform")} == {
        "host": "10.0.0.1", "port": 22, "platform": "iox"}
    assert "controller-owned IOx output" in job["lines"]


def test_iox_runtime_credentials_are_resolved_only_inside_controller(
        tmp_path, monkeypatch):
    class ControllerOwnedCredentials:
        def get_secrets(self, _profile_id):
            raise AssertionError(
                "OnboardService resolved an IOx runtime credential")

    for name in ("DEVICE_USER", "DEVICE_PASS", "DEVICE_ENABLE",
                 "DEVICE_SSH_USER", "DEVICE_SSH_PASS"):
        monkeypatch.setenv(name, "inherited-secret")
    observed_env = {}

    def preflight(_dev, env, _resolved):
        observed_env.update(env)
        return {"status": "passed", "device_identity": "FDO2547X9AB",
                "detected_model": "IE-3400"}

    controller = _FrozenIoxController()
    service = _iox_controller_service(
        tmp_path, controller, creds=ControllerOwnedCredentials(),
        preflight_fn=preflight)

    job = _wait(service, service.start("d1"))

    assert job["state"] == "done", job["lines"]
    assert len(controller.requests) == 1
    assert _request_value(controller.requests[0], "credential_ref") == "lab"
    for name in ("DEVICE_USER", "DEVICE_PASS", "DEVICE_ENABLE",
                 "DEVICE_SSH_USER", "DEVICE_SSH_PASS"):
        assert name not in observed_env


def test_iox_request_target_preserves_device_feature_intent():
    target = gui_onboard.OnboardService._iox_request_target(
        {
            "platform": "iox", "model": "IE-3400", "os_family": "xe",
            "management_type": "routed", "device_ip": "10.0.0.1",
        },
        {
            "DEVICE_IP": "10.0.0.1", "IRIS_TELEMETRY": "off",
            "IRIS_TELEMETRY_STREAM": "on", "IRIS_LOG": "on",
        },
        None)

    assert target["telemetry"] == "off"
    assert target["telemetry_stream"] == "on"
    assert target["log"] == "on"


def test_shutdown_cancels_queued_jobs_and_waits_for_running_job():
    entered = threading.Event()
    release = threading.Event()

    def run(_path, _env, _on_line):
        entered.set()
        assert release.wait(3.0)
        return 0

    service = _svc(run, max_concurrent=1)
    service.fleet._d["d2"] = dict(
        service.fleet._d["d1"], device_id="d2", device_ip="10.0.0.9")
    running = service.start("d1")
    assert entered.wait(2.0)
    queued = service.start("d2")

    stopped = threading.Event()
    shutdown = threading.Thread(
        target=lambda: (service.shutdown(), stopped.set()))
    shutdown.start()
    try:
        deadline = time.time() + 2.0
        while (service.get_job(queued)["state"] != "cancelled" and
               time.time() < deadline):
            time.sleep(0.01)
        assert service.get_job(queued)["state"] == "cancelled"
        assert not stopped.is_set()
        with pytest.raises(ValueError, match="shutting down"):
            service.start("d2")
    finally:
        release.set()
        shutdown.join(3.0)

    assert stopped.is_set()
    assert service.get_job(running)["state"] == "done"
    assert service._workers == []


def test_iox_prepare_is_deferred_inside_controller(tmp_path):
    events = []
    entered = threading.Event()
    release = threading.Event()
    controller = _FrozenIoxController(
        events=events, entered=entered, release=release)

    def preflight(*_args, **_kwargs):
        events.append("preflight")
        return {"status": "passed", "device_identity": "FDO2547X9AB",
                "detected_model": "IE-3400"}

    service = _iox_controller_service(
        tmp_path, controller, preflight_fn=preflight,
        mint_fn=lambda device_id: events.append("mint") or "TOK-" + device_id)

    def prepare():
        events.append("prepare")
        return "record-after-recovery"

    job_id = service.start("d1", prepare=prepare)
    assert entered.wait(2.0)
    try:
        running = service.get_job(job_id)
        assert running["state"] == "running"
        assert running["result_code"] is None
        assert running["returncode"] is None
        assert running["recovery_code"] is None
        assert running["iox_verification"] is None
        assert running["iox_session"] is None
        assert _request_value(controller.requests[0], "job_id") == job_id
        # Queue admission must not create a record. The controller invokes
        # preparation only after entering its board/recovery gate.
        assert "prepare" not in events
        assert "mint" not in events
    finally:
        release.set()
    job = _wait(service, job_id)

    assert job["state"] == "done"
    assert events == ["controller:install", "preflight", "prepare", "mint"]
    assert job["record_id"] == "record-after-recovery"


def test_iox_preapply_failure_restores_recovered_predecessor_authority(
        tmp_path):
    import test_deployment_records as records_spec

    ref, observation = records_spec._iox_transcript(
        tmp_path, state="disabled")
    store = deployment_records.DeploymentRecordStore(str(tmp_path))
    provenance = records_spec._provenance(device_id="d1")
    store.create(records_spec._record(
        record_id="old", device_id="d1",
        controller_id=records_spec._IOX_CONTROLLER,
        schedule_provenance=provenance,
        resolved={"platform": "iox", "device_identity":
                  records_spec._IOX_BOARD}))
    journal = store.iox_begin(
        "old", records_spec._IOX_CONTROLLER, records_spec._IOX_BOARD,
        records_spec._iox_wrapper(), observation, ref)
    store.recover_interrupted()
    store.iox_event(
        "old", journal["transaction_id"], journal["revision"],
        journal["phase"], "unchanged", {
            "reason": "initially_disabled", "observation": None,
            "transcript_refs": []})
    successor = {}

    def prepare():
        admitted = store.admit_scheduled(
            records_spec._record(
                record_id="new", device_id="d1",
                controller_id=records_spec._IOX_CONTROLLER,
                resolved={"platform": "iox", "device_identity":
                          records_spec._IOX_BOARD}),
            provenance=provenance, attempt=1,
            authorize=lambda *_args: None, resume_record_id="old")
        successor.update(admitted["record"])
        return admitted["record"]["record_id"]

    controller = _FrozenIoxController()
    service = _iox_controller_service(tmp_path, controller)
    service.record_store = store
    try:
        job = _wait(service, service.start(
            "d1", prepare=prepare,
            pre_apply=lambda _evidence: (_ for _ in ()).throw(
                ValueError("bind failed"))))
        assert job["state"] == "error"
        assert store.get(successor["record_id"])["state"] == "removed"
        assert store.get("old")["state"] == "unknown"
        assert store.recoverable_for_device("d1")["record_id"] == "old"
    finally:
        service.shutdown()


def test_same_action_iox_submission_deduplicates_while_controller_is_running(
        tmp_path):
    entered = threading.Event()
    release = threading.Event()
    controller = _FrozenIoxController(entered=entered, release=release)
    service = _iox_controller_service(tmp_path, controller)
    prepares = []

    def prepare():
        prepares.append("record-1")
        return "record-1"

    first = service.start("d1", prepare=prepare)
    assert entered.wait(2.0)
    second_result = []
    second_done = threading.Event()

    def submit_again():
        try:
            second_result.append(("ok", service.start("d1", prepare=prepare)))
        except Exception as exc:
            second_result.append(("error", exc))
        finally:
            second_done.set()

    submitter = threading.Thread(target=submit_again)
    submitter.daemon = True
    submitter.start()
    try:
        assert second_done.wait(1.0), (
            "same-action dedupe blocked behind controller execution")
        assert second_result == [("ok", first)]
        assert len(controller.requests) == 1
        assert _request_value(controller.requests[0], "job_id") == first
        assert prepares == []
    finally:
        release.set()
        submitter.join(2.0)
    assert not submitter.is_alive()

    job = _wait(service, first)
    assert job["state"] == "done"
    assert prepares == ["record-1"]


def test_running_iox_abort_reaches_controller_and_preserves_normalized_result(
        tmp_path):
    controller = _CancellingIoxController()
    raw_runs = []
    service = _iox_controller_service(tmp_path, controller, raw_runs)

    job_id = service.start("d1")
    assert controller.entered.wait(2.0)
    abort_result = []
    abort_thread = threading.Thread(
        target=lambda: abort_result.append(service.abort(job_id)))
    abort_thread.daemon = True
    abort_thread.start()
    try:
        abort_thread.join(2.0)
        assert not abort_thread.is_alive(), (
            "abort blocked behind controller work")
        assert abort_result == [True]
    finally:
        controller.stop.set()
        abort_thread.join(2.0)
    job = _wait(service, job_id)

    assert job["state"] == "cancelled"
    assert job["result_code"] == 130
    assert job["returncode"] is None
    assert job["recovery_code"] == 0
    assert set(job["iox_session"]) == {
        "attempt_id", "job_id", "device_id", "board_identity", "operation",
        "teardown_mode", "record_id", "state", "mutation_blocked"}
    assert job["iox_session"]["state"] == "reaped"
    assert job["iox_session"]["mutation_blocked"] is False
    assert job["iox_session"]["job_id"] == job_id
    assert raw_runs == []


def test_iox_terminal_controller_evidence_is_published_without_inference(tmp_path):
    verification = {
        "schema_version": 1, "record_id": "record-1",
        "transaction_id": "1" * 32, "revision": 7,
        "board_identity": "FDO2547X9AB", "prior_state": "enabled",
        "current_state": "disabled", "phase": "restore_intent",
        "unresolved": True, "created_at": 10, "updated_at": 20,
        "observed_at": 19, "terminal_at": None,
        "error_category": "journal_durability",
    }
    evidence = {}

    def controller_result(request):
        session = {
            "attempt_id": "a" * 32,
            "job_id": _request_value(request, "job_id"),
            "device_id": "d1", "board_identity": "FDO2547X9AB",
            "operation": "install", "teardown_mode": "none",
            "record_id": "record-1", "state": "reaped",
            "mutation_blocked": False,
        }
        evidence["session"] = session
        return {
            "result_code": 4, "returncode": -15, "recovery_code": 5,
            "record_id": "record-1", "iox_verification": verification,
            "iox_session": session,
        }

    controller = _FrozenIoxController(result=controller_result)
    service = _iox_controller_service(tmp_path, controller)

    job_id = service.start("d1", prepare=lambda: "record-1")
    job = _wait(service, job_id)

    assert job["state"] == "error"
    assert job["result_code"] == 4
    assert job["returncode"] == -15
    assert job["recovery_code"] == 5
    assert job["record_id"] == "record-1"
    assert job["iox_verification"] == verification
    assert job["iox_session"] == evidence["session"]
    assert job["iox_session"]["job_id"] == job_id


def test_recorded_iox_uninstall_keeps_the_preselected_record_target(tmp_path):
    controller = _FrozenIoxController()
    minted = []
    service = _iox_controller_service(
        tmp_path, controller,
        mint_fn=lambda device_id: minted.append(device_id) or "TOK")
    service.fleet.upsert({"device_id": "d1", "device_ip": "203.0.113.99"})
    recorded = {
        "platform": "iox", "model": "IE-3400", "os_family": "xe",
        "device_ip": "10.0.0.1", "management_type": "routed",
        "device_identity": "FDO2547X9AB", "vlan": "666",
        "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
        "guest_ip": "10.0.0.3",
        "resources": [{"kind": "iox-app", "ownership": "iris-created"}],
    }

    job_id = service.start(
        "d1", action="undeploy", resolved=recorded,
        record_id="record-1", teardown_mode="recorded",
        prepare=lambda: "record-1")
    job = _wait(service, job_id)

    assert job["state"] == "done"
    request = controller.requests[0]
    assert _request_value(request, "action") == "uninstall"
    assert _request_value(request, "device_id") == "d1"
    assert _request_value(request, "job_id") == job_id
    assert _request_value(request, "credential_ref") == "lab"
    assert _request_value(request, "teardown_mode") == "recorded"
    assert _request_value(request, "record_id") == "record-1"
    assert not _request_has(request, "wrapper_path")
    target = _request_value(request, "target")
    assert {key: target[key] for key in ("host", "port", "platform")} == {
        "host": "10.0.0.1", "port": 22, "platform": "iox"}
    assert target["device_identity"] == "FDO2547X9AB"
    assert target["resources"] == recorded["resources"]
    assert minted == []


def test_forced_iox_uninstall_uses_explicit_controller_mode_without_a_record(
        tmp_path):
    controller = _FrozenIoxController()
    minted = []
    service = _iox_controller_service(
        tmp_path, controller,
        mint_fn=lambda device_id: minted.append(device_id) or "TOK")

    job_id = service.start(
        "d1", action="undeploy", resolved={
            "platform": "iox", "model": "IE-3400", "os_family": "xe",
            "device_ip": "10.0.0.1", "management_type": "routed",
        }, record_id=None, teardown_mode="force_agent_only",
        prepare=lambda: None)
    job = _wait(service, job_id)

    assert job["state"] == "done"
    request = controller.requests[0]
    assert _request_value(request, "action") == "uninstall"
    assert _request_value(request, "device_id") == "d1"
    assert _request_value(request, "job_id") == job_id
    assert _request_value(request, "credential_ref") == "lab"
    assert _request_value(request, "teardown_mode") == "force_agent_only"
    assert _request_value(request, "record_id") is None
    assert not _request_has(request, "wrapper_path")
    target = _request_value(request, "target")
    assert {key: target[key] for key in ("host", "port", "platform")} == {
        "host": "10.0.0.1", "port": 22, "platform": "iox"}
    assert minted == []


# Scheduled work shares device exclusion with manual work but only half the pool.
def _schedule_context(did, occurrence="occurrence-1"):
    return {"schema_version": 1, "schedule_id": "schedule-1", "schedule_rev": 3,
            "occurrence_id": occurrence, "device_id": did}


@pytest.mark.parametrize("limit", [1, 2, 3, 25])
def test_scheduled_pool_reserves_manual_workers(limit):
    release = threading.Event()
    started = []
    lock = threading.Lock()

    def run(_path, env, _output):
        with lock:
            started.append(env["DEVICE_ID"])
        assert release.wait(5)
        return 0

    service = _multi_svc(limit + 2, run, max_concurrent=limit)
    try:
        assert service._manual_reservation == (limit + 1) // 2
        assert service._scheduled_limit == limit // 2
        if limit == 1:
            with pytest.raises(gui_onboard.ScheduledAdmissionError) as refused:
                service.start("d1", schedule_context=_schedule_context("d1"))
            assert refused.value.reason == "capacity_unavailable"
            assert service.list_jobs() == []
        else:
            scheduled = [service.start("d%d" % i,
                         schedule_context=_schedule_context("d%d" % i))
                         for i in range(1, limit // 2 + 2)]
            assert _wait_for(lambda: len(started) == limit // 2)
            assert len(service._scheduled_inflight) == limit // 2
            assert service.get_job(scheduled[-1])["state"] == "queued"
        manual_ids = ["d%d" % i for i in range(limit // 2 + 2, limit + 2)]
        for did in manual_ids:
            service.start(did)
        assert _wait_for(lambda: all(did in started for did in manual_ids))
        assert len(started) == limit
    finally:
        release.set()
        service.shutdown()
    assert service._scheduled_inflight == set()
    assert service._scheduled_workers == set()
    assert service._active_work == 0


@pytest.mark.parametrize("limit", [1, 2, 3, 25])
def test_pending_capacity_and_manual_reservation_have_no_prepare_side_effect(monkeypatch, limit):
    service = _multi_svc(1001, lambda *_args: 0, max_concurrent=limit)
    monkeypatch.setattr(service, "_ensure_workers", lambda: None)
    monkeypatch.setattr(service, "_ensure_maintenance", lambda: None)
    prepared = []
    scheduled_count = 0 if limit == 1 else 1000 - (limit + 1) // 2
    try:
        for i in range(1, scheduled_count + 1):
            did = "d%d" % i
            service.start(did, schedule_context=_schedule_context(did))
        if limit > 1:
            did = "d%d" % (scheduled_count + 1)
            with pytest.raises(gui_onboard.ScheduledAdmissionError) as refused:
                service.start(did, schedule_context=_schedule_context(did),
                              prepare=lambda: prepared.append(did))
            assert refused.value.reason == "queue_full"
        for i in range(scheduled_count + 1, 1001):
            service.start("d%d" % i)
        with pytest.raises(ValueError, match="onboarding queue is full"):
            service.start("d1001", prepare=lambda: prepared.append("d1001"))
        assert prepared == []
        assert len(service.list_jobs()) == 1000
        assert len(service._manual_queue) + len(service._scheduled_queue) == 1000
        assert service.cancel_queued() == 1000
        assert service.start("d1001", prepare=lambda: prepared.append("accepted"))
        assert prepared == ["accepted"]
    finally:
        service.shutdown()


def test_manual_dequeue_priority_and_same_device_supersession(monkeypatch):
    order = []
    retired = []
    service = _multi_svc(3, lambda _p, env, _o: order.append(env["DEVICE_ID"]) or 0,
                         max_concurrent=2)
    monkeypatch.setattr(service, "_ensure_workers", lambda: None)
    monkeypatch.setattr(service, "_ensure_maintenance", lambda: None)
    scheduled = service.start("d1", schedule_context=_schedule_context("d1"))
    first = service.start("d2")
    service._work_queue.get_nowait()()
    assert order == ["d2"]
    assert service.get_job(first)["state"] == "done"
    assert service.get_job(scheduled)["state"] == "queued"
    # The record retirement must happen before replacement preparation.
    service._jobs[scheduled]["record_id"] = "scheduled-record"
    service.record_store = SimpleNamespace(
        transition=lambda record, state: retired.append((record, state)))
    replacement = service.start("d1", action="undeploy", prepare=lambda: (
        retired.append("manual-prepare") or None))
    assert replacement != scheduled
    assert retired == [("scheduled-record", "removed"), "manual-prepare"]
    assert service.get_job(scheduled)["state"] == "cancelled"
    assert service.get_job(scheduled)["admission_reason"] == "manual_override"
    assert service.get_job(replacement)["state"] == "queued"
    assert service._scheduled_queue == gui_onboard.deque()
    service.shutdown()


def test_authority_changes_after_reservation_are_rechecked_without_lock_inversion():
    from contextlib import contextmanager
    reserved = threading.Event()
    release = threading.Event()
    authority_lock = threading.Lock()
    valid = [True]
    executions = []
    checked = []
    service = _multi_svc(2, lambda *_args: executions.append(True) or 0,
                         max_concurrent=2)

    @contextmanager
    def guard(phase):
        # A worker waiting for outer authority must not obstruct cancellation
        # or another authority holder acquiring the inner job condition.
        if phase == "execution":
            reserved.set()
            assert release.wait(5)
        with authority_lock:
            yield

    def check(phase):
        assert authority_lock.locked()
        assert service._lock.locked()
        checked.append(phase)
        if not valid[0]:
            raise gui_onboard.ScheduledAdmissionError("device_revoked")

    try:
        jid = service.start("d1", schedule_context=_schedule_context("d1"),
                            authority_guard=guard, authority_check=check)
        assert reserved.wait(2)
        with authority_lock:
            with service._condition:
                assert len(service._scheduled_inflight) == 1
                assert jid in service._reserved
                assert service._jobs[jid]["state"] == "queued"
                valid[0] = False
        # The other half of the pool remains usable while the guard waits.
        manual = service.start("d2")
        assert _wait(service, manual)["state"] == "done"
        release.set()
        result = _wait(service, jid)
        assert result["state"] == "cancelled"
        assert result["admission_reason"] == "device_revoked"
        assert checked == ["admission", "execution"]
        assert executions == [True]
        assert _wait_for(lambda: not service._scheduled_inflight
                         and not service._scheduled_workers)
    finally:
        release.set()
        service.shutdown()


def test_cancellation_releases_reserved_scheduled_capacity_and_scopes_occurrence():
    from contextlib import contextmanager
    reserved = threading.Event()
    release = threading.Event()
    ran = []
    service = _multi_svc(2, lambda _p, env, _o: ran.append(env["DEVICE_ID"]) or 0,
                         max_concurrent=2)

    @contextmanager
    def guard(phase):
        if phase == "execution":
            reserved.set()
            assert release.wait(5)
        yield

    try:
        first = service.start("d1", schedule_context=_schedule_context("d1"),
                              authority_guard=guard)
        assert reserved.wait(2)
        second = service.start("d2", schedule_context=_schedule_context("d2", "other"))
        assert service.get_job(second)["state"] == "queued"
        assert service.cancel_queued([first, second], occurrence_id="wrong") == 0
        assert service.cancel_queued([first, second], occurrence_id="occurrence-1") == 1
        assert service.get_job(first)["state"] == "cancelled"
        with service._condition:
            assert not service._reserved and not service._scheduled_inflight
            assert service._scheduled_workers == {first}
            assert service._jobs[second]["state"] == "queued"
        release.set()
        assert _wait(service, second)["state"] == "done"
        assert _wait_for(lambda: service._active_work == 0)
        assert ran == ["d2"]
        assert not service._reserved and not service._scheduled_inflight
        assert not service._scheduled_workers
    finally:
        release.set()
        service.shutdown()


def test_manual_supersedes_scheduled_worker_waiting_for_authority():
    from contextlib import contextmanager
    reserved = threading.Event()
    release = threading.Event()
    ran = []
    service = _multi_svc(1, lambda *_args: ran.append(True) or 0, max_concurrent=2)

    @contextmanager
    def guard(phase):
        if phase == "execution":
            reserved.set()
            assert release.wait(5)
        yield

    try:
        scheduled = service.start("d1", schedule_context=_schedule_context("d1"),
                                  authority_guard=guard)
        assert reserved.wait(2)
        manual = service.start("d1")
        assert _wait(service, manual)["state"] == "done"
        assert service.get_job(scheduled)["admission_reason"] == "manual_override"
        release.set()
        assert _wait_for(lambda: service._active_work == 0)
        assert ran == [True]
    finally:
        release.set()
        service.shutdown()


def test_schedule_provenance_is_immutable_and_manual_projection_unchanged(monkeypatch):
    service = _multi_svc(2, lambda *_args: 0, max_concurrent=2)
    monkeypatch.setattr(service, "_ensure_workers", lambda: None)
    monkeypatch.setattr(service, "_ensure_maintenance", lambda: None)
    context = _schedule_context("d1")
    jid = service.start("d1", schedule_context=context)
    context["schedule_rev"] = 999
    detached = service.get_schedule_context(jid)
    assert detached["schedule_rev"] == 3
    detached["schedule_id"] = "forged"
    assert service.get_schedule_context(jid)["schedule_id"] == "schedule-1"
    assert [j["id"] for j in service.jobs_for_occurrence("occurrence-1", "d1")] == [jid]
    assert service.jobs_for_occurrence("other") == []
    assert service.latest_jobs_by_device()["d1"]["pending_schedule_id"] == "schedule-1"
    manual = service.start("d2")
    assert service.get_schedule_context(manual) is None
    assert "schedule_id" not in service.get_job(manual)
    assert service.latest_jobs_by_device()["d2"] == {
        "action": "onboard", "state": "queued", "finished_at": None}
    service.shutdown()


@pytest.mark.parametrize("patch", [
    {"schema_version": True}, {"schedule_rev": True}, {"schedule_rev": 0},
    {"device_id": "other"}, {"occurrence_id": ""}, {"schedule_id": "a\nb"},
    {"extra": "forbidden"},
])
def test_schedule_provenance_rejects_invalid_or_extra_fields(patch):
    service = _svc(lambda *_args: 0)
    context = _schedule_context("d1") | patch
    with pytest.raises(ValueError, match="invalid schedule provenance"):
        service.start("d1", schedule_context=context)
    assert service.list_jobs() == []
    service.shutdown()


def test_scheduled_running_join_and_manual_opposite_action_busy():
    entered = threading.Event()
    release = threading.Event()

    def run(*_args):
        entered.set()
        assert release.wait(5)
        return 0

    service = _multi_svc(1, run, max_concurrent=2)
    try:
        scheduled = service.start("d1", schedule_context=_schedule_context("d1"))
        assert entered.wait(2)
        assert service.start("d1", prepare=lambda: pytest.fail("joined prepare")) == scheduled
        assert service.start("d1", schedule_context=_schedule_context("d1")) == scheduled
        with pytest.raises(ValueError, match="busy with an active onboard"):
            service.start("d1", action="undeploy")
        assert service.cancel_queued(occurrence_id="occurrence-1") == 0
    finally:
        release.set()
        service.shutdown()


def test_admission_authority_refusal_creates_no_job_or_record():
    from contextlib import contextmanager
    outer = threading.Lock()
    prepared = []
    service = _multi_svc(1, lambda *_args: 0, max_concurrent=2)

    @contextmanager
    def guard(_phase):
        assert not service._lock.locked()
        with outer:
            yield

    def check(phase):
        assert phase == "admission" and outer.locked() and service._lock.locked()
        raise gui_onboard.ScheduledAdmissionError("vanished")

    try:
        with pytest.raises(gui_onboard.ScheduledAdmissionError) as refused:
            service.start("d1", schedule_context=_schedule_context("d1"),
                          authority_guard=guard, authority_check=check,
                          prepare=lambda: prepared.append(True))
        assert refused.value.reason == "vanished"
        assert prepared == [] and service.list_jobs() == []
        assert not service._reserved and not service._scheduled_inflight
    finally:
        service.shutdown()


@pytest.mark.parametrize("revoke_at_prepare", [False, True])
def test_iox_deferred_authority_recheck_releases_locks_for_controller_and_probe(
        tmp_path, revoke_at_prepare):
    from contextlib import contextmanager
    outer = threading.Lock()
    entered = threading.Event()
    release = threading.Event()
    phases = []
    prepared = []
    valid = [True]
    controller = _FrozenIoxController(entered=entered, release=release)
    service = None

    def assert_unlocked():
        assert outer.acquire(blocking=False)
        outer.release()
        assert service._lock.acquire(blocking=False)
        service._lock.release()

    def preflight(*_args, **_kwargs):
        assert_unlocked()
        return {"status": "passed", "device_identity": "FDO2547X9AB",
                "detected_model": "IE-3400"}

    def mint(_did):
        assert_unlocked()
        return "fixture-token"

    service = _iox_controller_service(tmp_path, controller, preflight_fn=preflight,
                                       mint_fn=mint)

    @contextmanager
    def guard(phase):
        # Guard acquisition itself must never take place under the job lock.
        assert service._lock.acquire(blocking=False)
        service._lock.release()
        with outer:
            phases.append(phase)
            yield

    def check(_phase):
        assert outer.locked() and service._lock.locked()
        if not valid[0]:
            raise gui_onboard.ScheduledAdmissionError("device_revoked")

    def prepare():
        assert outer.locked() and service._lock.locked()
        prepared.append(True)
        return "new-record"

    try:
        jid = service.start("d1", prepare=prepare,
                            schedule_context=_schedule_context("d1"),
                            authority_guard=guard, authority_check=check)
        assert entered.wait(2)
        assert_unlocked()
        request = controller.requests[0]
        assert _request_value(request, "record_id") is None
        assert not _request_has(request, "schedule_context")
        assert not _request_has(request, "schedule_id")
        assert prepared == []
        with outer:
            valid[0] = not revoke_at_prepare
        release.set()
        job = _wait(service, jid)
        assert phases == ["admission", "execution", "iox_prepare"]
        if revoke_at_prepare:
            assert prepared == []
            assert job["state"] == "error"
            assert job["admission_reason"] == "device_revoked"
            assert job["record_id"] is None
        else:
            assert prepared == [True]
            assert job["state"] == "done"
            assert job["record_id"] == "new-record"
    finally:
        release.set()
        service.shutdown()



def test_cancelled_authority_waiter_preserves_physical_manual_worker_slot(monkeypatch):
    """A cancelled reservation cannot free a worker that is still lock-blocked."""
    from contextlib import contextmanager
    outer = threading.Lock()
    first_waiting = threading.Event()
    second_considered = threading.Event()
    executed = []
    service = _multi_svc(
        3, lambda _p, env, _o: executed.append(env["DEVICE_ID"]) or 0,
        max_concurrent=2)
    reserve = service._reserve_work_locked

    def observe_reservation():
        job = reserve()
        # Synchronize after an idle worker has considered the second scheduled
        # job, before submitting manual work. This prevents manual-first dequeue
        # from accidentally hiding the physical-occupancy regression.
        if any(j["device_id"] == "d2" and j["state"] == "queued"
               for j in service._jobs.values()):
            second_considered.set()
        return job

    monkeypatch.setattr(service, "_reserve_work_locked", observe_reservation)

    @contextmanager
    def guard(phase):
        if phase == "execution":
            first_waiting.set()
            with outer:
                yield
        else:
            yield

    outer.acquire()
    try:
        first = service.start("d1", schedule_context=_schedule_context("d1"),
                              authority_guard=guard)
        assert first_waiting.wait(2)
        assert service.cancel_queued([first]) == 1
        second = service.start("d2", schedule_context=_schedule_context("d2"),
                               authority_guard=guard)
        assert second_considered.wait(2)
        manual = service.start("d3")
        # No authority guard performs slow work. The first cancelled worker
        # merely contends on a lock held by this thread. Manual work must finish
        # before that lock is released, while the second schedule stays pending.
        assert _wait(service, manual, timeout=2)["state"] == "done"
        with service._condition:
            assert not service._reserved and not service._scheduled_inflight
            assert service._scheduled_workers == {first}
            assert service._jobs[second]["state"] == "queued"
        assert executed == ["d3"]
    finally:
        outer.release()
        service.shutdown()
    assert not service._scheduled_inflight and not service._scheduled_workers
    assert not service._reserved and service._active_work == 0



def test_catalyst_8000_offers_router_and_iox_and_resolves_the_iox_arch():
    """IOx on a Catalyst 8000: amd64 package, bootflash staging, no SSD share
    -- the installer derives the VirtualPortGroup vnic from the router
    management type, so the arch env carries no AppGig interface."""
    assert gui_onboard.install_options_for("C8000V") == ["router", "iox"]
    env = gui_onboard._iox_arch_env("r1", "C8000V")
    assert env == {"PKG": "iris-amd64.tar", "PKG_FS": "bootflash:", "TARGET_FS": "bootflash:"}
    assert "APP_INTF" not in env and "SHARE_HOST_PATH" not in env
    assert gui_onboard.resolve_platform({"device_id": "r1", "model": "C8000V", "platform": "iox"}) == "iox"
    assert gui_onboard.resolve_platform({"device_id": "r1", "model": "C8000V", "platform": "router"}) == "router"
    with pytest.raises(ValueError, match="router or iox"):
        gui_onboard.resolve_platform({"device_id": "r1", "model": "C8000V", "platform": "guestshell"})


def test_iox_on_a_router_binds_both_preflights():
    """The router evidence owns the VPG/NAT facts, the IOx evidence the
    app-hosting facts; both must name the same box."""
    resolved = {"management_type": "router-nat", "platform": "iox", "app_ip": "10.0.2.5",
                "nat_interface": "GigabitEthernet1", "swarm_port": "6881", "vpg_number": "2"}
    evidence = {"status": "passed", "device_identity": "FDO123", "detected_model": "C8000V",
                "iox_preexisting": False, "file_prompt_quiet_preexisting": True,
                "nat_interface": "GigabitEthernet1", "nat_outside_preexisting": True}
    bound = gui_onboard.bind_preflight(resolved, evidence)
    assert bound["device_identity"] == "FDO123" and bound["model"] == "C8000V"
    assert bound["nat_outside_owned"] == "0" and bound["file_prompt_quiet_preexisting"] == "1"
