# server/tests/test_gui_onboard.py
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import threading
import time

import catalog as catalog_mod
import gui_onboard


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


class _Creds:
    def __init__(self, profs): self._p = profs
    def get_secrets(self, pid): return self._p.get(pid)


class _CredsSH(_Creds):
    """A creds store that also has stage-host credentials (like CredentialStore)."""
    def __init__(self, profs, stage_host=None):
        _Creds.__init__(self, profs)
        self._sh = stage_host
    def stage_host_secrets(self): return self._sh


def _wait(svc, job_id, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        j = svc.get_job(job_id)
        if j and j["state"] in ("done", "error"):
            return j
        time.sleep(0.01)
    return svc.get_job(job_id)


def _svc(run_fn, stage_host=None, **kw):
    fleet = _Fleet({"d1": {"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
                           "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                           "guest_ip": "10.0.0.3", "model": "C9300",
                           "credential_profile_id": "lab"}})
    profs = {"lab": {"device_user": "admin", "device_pass": "s3cret",
                     "enable_secret": "en"}}
    # stage_host=None -> a plain _Creds WITHOUT stage_host_secrets, proving the
    # service tolerates credential stores that predate stage-host support
    creds = _Creds(profs) if stage_host is None else _CredsSH(profs, stage_host)
    return gui_onboard.OnboardService(
        fleet, creds, device_install="/fake/device-install.sh",
        crt_public="/fake/crt.pem", host_ip="10.9.9.9",
        mint_fn=lambda did: "TOK-" + did, run_fn=run_fn, **kw)


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


def test_onboard_unknown_device_errors(tmp_path):
    svc = _svc(lambda p, e, on: 0)
    job = _wait(svc, svc.start("nope"))
    assert job["state"] == "error"
    assert any("unknown device" in l for l in job["lines"])


def test_onboard_missing_credential_errors(tmp_path):
    fleet = _Fleet({"d1": {"device_id": "d1", "device_ip": "10.0.0.1",
                           "credential_profile_id": "missing"}})
    creds = _Creds({})
    svc = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                     mint_fn=lambda d: "t", run_fn=lambda p, e, on: 0)
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error"
    assert any("credential" in l.lower() for l in job["lines"])


def test_enable_secret_defaults_to_device_pass(tmp_path):
    fleet = _Fleet({"d1": {"device_id": "d1", "device_ip": "10.0.0.1",
                           "model": "C9300", "credential_profile_id": "lab"}})
    creds = _Creds({"lab": {"device_user": "u", "device_pass": "pw",
                            "enable_secret": ""}})
    seen = {}
    svc = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                     mint_fn=lambda d: "t",
                                     run_fn=lambda p, e, on: seen.update(e) or 0)
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
                           "model": "C9300", "credential_profile_id": "lab"}})
    creds = _Creds({"lab": {"device_user": "u", "device_pass": "p",
                            "enable_secret": ""}})
    svc = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                     mint_fn=lambda d: "t",
                                     run_fn=lambda p, e, on: 0,
                                     now_fn=lambda: clock["t"])
    j1 = svc.start("d1")
    assert _wait(svc, j1)["state"] == "done"
    assert svc.get_job(j1) is not None            # retained while fresh
    clock["t"] = 1000 + 3601                       # advance past the TTL
    j2 = svc.start("d1")                            # triggers the sweep
    assert _wait(svc, j2)["state"] == "done"
    assert svc.get_job(j1) is None                 # j1 evicted
    assert svc.get_job(j2) is not None


def test_stage_host_creds_injected(monkeypatch):
    monkeypatch.delenv("HOST_USER", raising=False)
    monkeypatch.delenv("HOST_PASS", raising=False)
    seen = {}

    def fake_run(p, e, on):
        seen["env"] = e
        return 0

    svc = _svc(fake_run, stage_host={"username": "svc", "password": "hostpw"})
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert seen["env"]["HOST_USER"] == "svc"
    assert seen["env"]["HOST_PASS"] == "hostpw"
    # the password never appears in the streamed job lines
    assert all("hostpw" not in ln for ln in job["lines"])


def test_stage_host_creds_beat_process_env(monkeypatch):
    monkeypatch.setenv("HOST_USER", "envuser")
    monkeypatch.setenv("HOST_PASS", "envpw")
    seen = {}

    def fake_run(p, e, on):
        seen["env"] = e
        return 0

    svc = _svc(fake_run, stage_host={"username": "svc", "password": "hostpw"})
    _wait(svc, svc.start("d1"))
    assert seen["env"]["HOST_USER"] == "svc"
    assert seen["env"]["HOST_PASS"] == "hostpw"


def test_no_stage_host_keeps_env_passthrough(monkeypatch):
    monkeypatch.setenv("HOST_USER", "envuser")
    monkeypatch.setenv("HOST_PASS", "envpw")
    seen = {}

    def fake_run(p, e, on):
        seen["env"] = e
        return 0

    svc = _svc(fake_run)   # plain _Creds: no stage_host_secrets at all
    _wait(svc, svc.start("d1"))
    assert seen["env"]["HOST_USER"] == "envuser"
    assert seen["env"]["HOST_PASS"] == "envpw"


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
    for model in ("C9300-48UXM", "c9300-48uxm", "ISR4451", "ASR1001", "CSR1000v", "C8000v"):
        assert gui_onboard.resolve_platform({"device_id": "d", "model": model}) == "guestshell", model


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


# --- OnboardService: platform-aware recipe selection --------------------

def _iox_fleet(platform=None, model=None):
    dev = {"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
           "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
           "guest_ip": "10.0.0.3", "credential_profile_id": "lab"}
    if platform is not None:
        dev["platform"] = platform
    if model is not None:
        dev["model"] = model
    return _Fleet({"d1": dev})


def _iox_creds():
    return _Creds({"lab": {"device_user": "admin", "device_pass": "s3cret",
                           "enable_secret": "en"}})


def test_probe_resolves_iox_and_caches_model(tmp_path):
    art_dir = tmp_path
    (art_dir / "iris-arm64.tar").write_text("fake")
    fleet = _iox_fleet()  # no explicit platform/model -> falls to probe
    creds = _iox_creds()
    seen = {}

    def fake_run(install_path, env, on_line):
        seen["install_path"] = install_path
        return 0

    svc = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=fake_run, probe_fn=lambda dev, env: "IE-3400",
        artifacts_dir=str(art_dir))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert seen["install_path"].endswith("device/iox/install.sh")
    assert {"device_id": "d1", "model": "IE-3400"} in fleet.upserts
    # the job line reports the model the probe just found, not a placeholder
    assert any("platform: iox (model IE-3400)" in l for l in job["lines"])


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


def test_iox_env_has_ssh_creds(tmp_path):
    art_dir = tmp_path
    (art_dir / "iris-arm64.tar").write_text("fake")
    fleet = _iox_fleet(platform="iox", model="IE-3400")
    creds = _iox_creds()
    seen = {}

    def fake_run(install_path, env, on_line):
        seen["env"] = env
        return 0

    svc = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=fake_run, artifacts_dir=str(art_dir))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert seen["env"]["DEVICE_SSH_PASS"] == "s3cret"
    assert seen["env"]["DEVICE_SSH_USER"] == "admin"


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


def test_iox_missing_iris_tar_errors_before_run(tmp_path):
    fleet = _iox_fleet(platform="iox", model="IE-3400")
    creds = _iox_creds()
    called = []

    def fake_run(install_path, env, on_line):
        called.append(install_path)
        return 0

    svc = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
  run_fn=fake_run, artifacts_dir=str(tmp_path))  # no iris-arm64.tar written
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error"
    assert called == []
    assert any("iris-arm64.tar not found" in l for l in job["lines"])


def test_iox_present_iris_tar_proceeds(tmp_path):
    (tmp_path / "iris-arm64.tar").write_text("fake")
    fleet = _iox_fleet(platform="iox", model="IE-3400")
    creds = _iox_creds()
    seen = {}

    def fake_run(install_path, env, on_line):
        seen["install_path"] = install_path
        return 0

    svc = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=fake_run, artifacts_dir=str(tmp_path))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert seen["install_path"].endswith("device/iox/install.sh")


def test_job_lines_note_platform_and_recipe(tmp_path):
    (tmp_path / "iris-arm64.tar").write_text("fake")
    fleet = _iox_fleet(platform="iox", model="IE-3400")
    creds = _iox_creds()
    svc = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=lambda p, e, on: 0, artifacts_dir=str(tmp_path))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
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
                     "model": "C9300", "credential_profile_id": "lab"}
    creds = _Creds({"lab": {"device_user": "admin", "device_pass": "s3cret",
                            "enable_secret": "en"}})
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


def test_no_eviction_while_any_job_active():
    """Terminal jobs must survive past the TTL while a batch is still running,
    so the batch panel's done/failed record can't shrink mid-batch."""
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
    assert svc.get_job(j1) is not None     # retained: j2/j3 still active
    release.set()
    assert _wait(svc, j2)["state"] == "done"
    assert _wait(svc, j3)["state"] == "done"
    clock["t"] = 1000 + 7200 + 3601
    j4 = svc.start("d1")                   # all terminal now -> sweep runs
    assert _wait(svc, j4)["state"] == "done"
    assert svc.get_job(j1) is None


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


def test_undeploy_iox_runs_the_iox_uninstall_script():
    """Fleet-wide undeploy: an IOx device runs device/iox/uninstall.sh (NOT the
    Guest Shell teardown, and no longer refused). No token is minted."""
    seen = {}
    minted = []
    fleet = _iox_fleet(platform="iox", model="IE-3400")
    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9",
        mint_fn=lambda d: minted.append(d) or "TOK",
        run_fn=lambda p, e, on: seen.update(install_path=p, env=e) or 0)
    job = _wait(svc, svc.start("d1", action="undeploy"))
    assert job["state"] == "done"
    assert seen["install_path"].endswith("device/iox/uninstall.sh")
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
    """start()'s prepare() (used to mint the receipt) must fire exactly once for
    a genuinely new job and NEVER when a second same-action start dedups onto the
    running job -- otherwise a double-onboard would strand an orphan receipt."""
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
    assert svc.get_job(j1)["receipt_id"] == "rcpt-1"
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
    (tmp_path / "iris-amd64.tar").write_text("fake")
    fleet = _iox_fleet(platform="iox", model="C9300-48UXM")
    seen = {}
    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=_run_capture(seen), artifacts_dir=str(tmp_path))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    env = seen["env"]
    assert env["PKG"] == "iris-amd64.tar"
    assert env["APP_INTF"] == "AppGigabitEthernet1/0/1"
    assert env["TARGET_FS"] == "usbflash1:"


def test_ie3k_iox_keeps_arm_defaults(tmp_path):
    (tmp_path / "iris-arm64.tar").write_text("fake")
    fleet = _iox_fleet(model="IE-3400")   # model regex -> iox, arm
    seen = {}
    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=_run_capture(seen), artifacts_dir=str(tmp_path))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    env = seen["env"]
    # arm case leaves these unset so install.sh's own defaults apply
    assert "PKG" not in env
    assert "APP_INTF" not in env
    assert "TARGET_FS" not in env


def test_c9k_guestshell_override_runs_guestshell(tmp_path):
    fleet = _iox_fleet(platform="guestshell", model="C9300-48UXM")
    seen = {}
    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=_run_capture(seen), device_install="/fake/device-install.sh",
        artifacts_dir=str(tmp_path))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "done"
    assert seen["install_path"] == "/fake/device-install.sh"
    assert "PKG" not in seen["env"] and "DEVICE_SSH_PASS" not in seen["env"]


def test_c9k_stacked_member_app_intf_override_wins(tmp_path):
    (tmp_path / "iris-amd64.tar").write_text("fake")
    fleet = _iox_fleet(platform="iox", model="C9300-48UXM")
    seen = {}
    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=_run_capture(seen), artifacts_dir=str(tmp_path))
    # simulate an operator/env override for a stacked member 2/0/1
    import os as _os
    old = _os.environ.get("APP_INTF")
    _os.environ["APP_INTF"] = "AppGigabitEthernet2/0/1"
    try:
        job = _wait(svc, svc.start("d1"))
    finally:
        if old is None:
            _os.environ.pop("APP_INTF", None)
        else:
            _os.environ["APP_INTF"] = old
    assert job["state"] == "done"
    # setdefault must not clobber the explicit override
    assert seen["env"]["APP_INTF"] == "AppGigabitEthernet2/0/1"
    assert seen["env"]["PKG"] == "iris-amd64.tar"


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
    seen = {}
    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=_run_capture(seen), artifacts_dir=str(tmp_path))
    job = _wait(svc, svc.start("d1", action="undeploy"))
    assert job["state"] == "done"
    # undeploy never checks the artifacts guard, but _resolve populates PKG so
    # uninstall.sh deletes flash:iris-amd64.tar
    assert seen["env"]["PKG"] == "iris-amd64.tar"


def test_c9k_iox_notfound_names_amd64_tar(tmp_path):
    # no package staged
    fleet = _iox_fleet(platform="iox", model="C9300-48UXM")
    called = []
    svc = gui_onboard.OnboardService(
        fleet, _iox_creds(), host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=lambda p, e, on: called.append(p) or 0, artifacts_dir=str(tmp_path))
    job = _wait(svc, svc.start("d1"))
    assert job["state"] == "error"
    assert called == []
    assert any("iris-amd64.tar" in l for l in job["lines"])


def test_abort_terminates_running_job():
    """abort() signals the running installer's process; the job then errors."""
    release = threading.Event()
    aborted = {"v": False}

    class FakeProc:
        def terminate(self):
            aborted["v"] = True
            release.set()

    def run_fn(p, e, on, on_proc):
        on_proc(FakeProc())
        on("running")
        release.wait(5)          # blocks until aborted (or timeout)
        return 137

    svc = _multi_svc(1, run_fn, max_concurrent=1)
    j = svc.start("d1")
    assert _wait_for(lambda: svc.get_job(j)["state"] == "running")
    assert svc.abort(j) is True
    assert aborted["v"] is True
    assert _wait(svc, j)["state"] == "error"
    assert svc.abort(j) is False     # not running anymore -> nothing to abort


def test_abort_unknown_job_is_false():
    svc = _svc(lambda p, e, on: 0)
    assert svc.abort("nope") is False
