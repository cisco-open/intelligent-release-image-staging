# server/tests/test_audit_export.py
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""audit_export.py (F5): unit tests for the pure gate, tolerant settings IO,
filename shape, the mandatory-encryption refusal and the fake-subprocess
export paths -- plus route tests (test_gui_server.py style) for the console
config/run/poll surface with a fake export fn injected, so no test here ever
launches age or scp."""
import http.client
import json
import os
import re
import threading
import time

import audit_export
import gui_app
import gui_creds
import management_api as gui_server


# ---- helpers --------------------------------------------------------------

def _valid_settings(**over):
    base = {"host": "backup.example.com", "port": 22, "user": "iris",
            "path": "/srv/audit", "age_recipient": "age1" + "q" * 58,
            "auto": False, "last_run_ts": None, "last_result": None}
    base.update(over)
    return base


# ---- export_due (pure gate) -----------------------------------------------

def test_export_due_gates_on_auto_and_age():
    assert audit_export.export_due({"auto": True, "last_run_ts": None}, 1000) is True
    assert audit_export.export_due({"auto": False, "last_run_ts": None}, 1000) is False
    assert audit_export.export_due({"auto": True, "last_run_ts": 1000},
                                   1000 + 86399) is False
    assert audit_export.export_due({"auto": True, "last_run_ts": 1000},
                                   1000 + 86400) is True
    # tolerant against garbage: not-a-dict / missing auto / junk timestamp
    assert audit_export.export_due(None, 1000) is False
    assert audit_export.export_due({}, 1000) is False
    assert audit_export.export_due({"auto": "yes"}, 1000) is False
    assert audit_export.export_due({"auto": True, "last_run_ts": "junk"}, 0) is True


# ---- settings IO ----------------------------------------------------------

def test_settings_read_missing_file_gives_defaults(tmp_path):
    p = str(tmp_path / "audit-export-settings.json")
    assert audit_export.read_settings(p) == {
        "host": "", "port": 22, "user": "", "path": "", "age_recipient": "",
        "auto": False, "last_run_ts": None, "last_result": None}


def test_settings_read_tolerates_corrupt_and_wrong_types(tmp_path):
    p = str(tmp_path / "audit-export-settings.json")
    with open(p, "w") as f:
        f.write("{garbage")
    assert audit_export.read_settings(p)["port"] == 22
    with open(p, "w") as f:
        json.dump(["not", "a", "dict"], f)
    assert audit_export.read_settings(p)["auto"] is False
    with open(p, "w") as f:
        json.dump({"host": 5, "port": "2222", "user": None, "auto": "yes",
                   "last_run_ts": True, "last_result": 9}, f)
    got = audit_export.read_settings(p)
    assert got["host"] == "" and got["port"] == 22 and got["user"] == ""
    assert got["auto"] is False
    assert got["last_run_ts"] is None and got["last_result"] is None


def test_settings_write_read_roundtrip_creates_parent_dir(tmp_path):
    p = str(tmp_path / "state" / "audit-export-settings.json")
    want = _valid_settings(port=2222, auto=True, last_run_ts=123,
                           last_result="ok:audit-x.jsonl.age")
    audit_export.write_settings(p, want)
    assert audit_export.read_settings(p) == want


def test_settings_clear_is_idempotent(tmp_path):
    p = str(tmp_path / "audit-export-settings.json")
    audit_export.write_settings(p, _valid_settings())
    audit_export.clear_settings(p)
    assert not os.path.exists(p)
    audit_export.clear_settings(p)      # second clear: no error


# ---- validate_settings (conservative argv shapes) -------------------------

def test_validate_settings_accepts_conservative_shapes():
    assert audit_export.validate_settings(_valid_settings()) is None
    assert audit_export.validate_settings(_valid_settings(path="~/audit")) is None
    assert audit_export.validate_settings(_valid_settings(path="~")) is None
    assert audit_export.validate_settings(_valid_settings(host="10.0.0.9")) is None


def test_validate_settings_rejects_dangerous_values():
    for bad in (_valid_settings(host=""), _valid_settings(host="-evil"),
                _valid_settings(host="a b"), _valid_settings(host="h;x"),
                _valid_settings(user=""), _valid_settings(user="-u"),
                _valid_settings(user="u x"),
                _valid_settings(path="relative"),
                _valid_settings(path="/has space"),
                _valid_settings(path="-o/dir"),
                _valid_settings(port=0), _valid_settings(port=70000),
                _valid_settings(port="22"), _valid_settings(port=True),
                _valid_settings(age_recipient="AGE1XYZ"),
                _valid_settings(age_recipient="notage"),
                "not a dict"):
        assert audit_export.validate_settings(bad) is not None, bad


# ---- export_once ----------------------------------------------------------

def test_export_once_refuses_without_recipient(tmp_path):
    # encryption is mandatory: no recipient means no export, full stop
    audit_export.write_settings(
        audit_export.settings_path(str(tmp_path)),
        _valid_settings(age_recipient=""))
    ok, detail = audit_export.export_once(
        str(tmp_path / "audit.jsonl"), _valid_settings(age_recipient=""),
        "pw", str(tmp_path))
    assert ok is False and detail == "age recipient not configured"
    # the refusal is recorded so the console status line can show it
    got = audit_export.read_settings(audit_export.settings_path(str(tmp_path)))
    assert got["last_result"] == "fail:age recipient not configured"
    assert got["last_run_ts"] is not None


def test_export_once_refuses_without_password(tmp_path):
    ok, detail = audit_export.export_once(
        str(tmp_path / "audit.jsonl"), _valid_settings(), "", str(tmp_path))
    assert ok is False and detail == "password not configured"


def test_export_once_ok_with_fake_subprocess(tmp_path, monkeypatch):
    audit_file = tmp_path / "audit.jsonl"
    audit_file.write_text('{"ts":1,"event":"e"}\n')
    calls = []

    class _Proc:
        returncode = 0
        stderr = b""

    def fake_run(argv, input=None, capture_output=None, timeout=None, env=None):
        calls.append({"argv": list(argv), "input": input, "timeout": timeout,
                      "env": env})
        if argv[0] != "sshpass":            # the age call writes its -o target
            with open(argv[argv.index("-o") + 1], "wb") as f:
                f.write(b"agedata")
        return _Proc()

    monkeypatch.setattr(audit_export.subprocess, "run", fake_run)
    settings = _valid_settings(port=2022)
    audit_export.write_settings(
        audit_export.settings_path(str(tmp_path)), settings)
    ok, detail = audit_export.export_once(
        str(audit_file), settings, "scp-pw", str(tmp_path),
        now_fn=lambda: 1755640000.0)
    assert ok is True
    # filename shape: audit-<UTCyyyymmdd-HHMMSS>-<random>.jsonl.age -- the
    # timestamp from now_fn, plus a suffix so same-second runs never collide
    assert re.match(r"^audit-\d{8}-\d{6}-[0-9a-f]{6}\.jsonl\.age$", detail)
    assert detail.startswith("audit-%s-" % time.strftime(
        "%Y%m%d-%H%M%S", time.gmtime(1755640000.0)))
    age_call, scp_call = calls
    assert age_call["argv"][0] == "age"
    assert age_call["argv"][1:3] == ["-r", settings["age_recipient"]]
    assert age_call["input"] == audit_file.read_bytes()
    assert age_call["timeout"] == 30
    joined = " ".join(scp_call["argv"])
    assert scp_call["argv"][:3] == ["sshpass", "-e", "scp"]
    assert "-P 2022" in joined
    assert "StrictHostKeyChecking=accept-new" in joined
    assert ("UserKnownHostsFile=%s"
            % os.path.join(str(tmp_path), "audit-export-known-hosts")) in joined
    assert scp_call["argv"][-1] == "iris@backup.example.com:/srv/audit/"
    assert scp_call["timeout"] == 120
    # the password rides env SSHPASS, never argv
    assert scp_call["env"]["SSHPASS"] == "scp-pw"
    assert all("scp-pw" not in a for a in scp_call["argv"])
    assert all("scp-pw" not in a for a in age_call["argv"])
    got = audit_export.read_settings(audit_export.settings_path(str(tmp_path)))
    assert got["last_result"] == "ok:%s" % detail
    assert got["last_run_ts"] == 1755640000


def test_export_once_scp_failure_records_capped_detail(tmp_path, monkeypatch):
    def fake_run(argv, input=None, capture_output=None, timeout=None, env=None):
        class _Proc:
            returncode = 0
            stderr = b""
        p = _Proc()
        if argv[0] == "sshpass":
            p.returncode = 1
            p.stderr = b"ssh: connect to host backup.example.com port 22: " \
                       b"Connection refused" + b" x" * 200
        else:
            with open(argv[argv.index("-o") + 1], "wb") as f:
                f.write(b"agedata")
        return p

    monkeypatch.setattr(audit_export.subprocess, "run", fake_run)
    audit_export.write_settings(
        audit_export.settings_path(str(tmp_path)), _valid_settings())
    ok, detail = audit_export.export_once(
        str(tmp_path / "audit.jsonl"), _valid_settings(), "pw", str(tmp_path))
    assert ok is False and "Connection refused" in detail
    got = audit_export.read_settings(audit_export.settings_path(str(tmp_path)))
    assert got["last_result"].startswith("fail:")
    assert len(got["last_result"]) <= len("fail:") + 120


def test_export_once_age_failure_stops_before_scp(tmp_path, monkeypatch):
    calls = []

    def fake_run(argv, input=None, capture_output=None, timeout=None, env=None):
        calls.append(argv[0])

        class _Proc:
            returncode = 1
            stderr = b"age: error: malformed recipient"
        return _Proc()

    monkeypatch.setattr(audit_export.subprocess, "run", fake_run)
    ok, detail = audit_export.export_once(
        str(tmp_path / "audit.jsonl"), _valid_settings(), "pw", str(tmp_path))
    assert ok is False and "malformed recipient" in detail
    assert calls == ["age"]     # nothing unencrypted ever reaches scp


def test_export_once_missing_audit_file_exports_empty(tmp_path, monkeypatch):
    seen = {}

    def fake_run(argv, input=None, capture_output=None, timeout=None, env=None):
        if argv[0] != "sshpass":
            seen["input"] = input
            with open(argv[argv.index("-o") + 1], "wb") as f:
                f.write(b"")

        class _Proc:
            returncode = 0
            stderr = b""
        return _Proc()

    monkeypatch.setattr(audit_export.subprocess, "run", fake_run)
    ok, _detail = audit_export.export_once(
        str(tmp_path / "missing.jsonl"), _valid_settings(), "pw", str(tmp_path))
    assert ok is True and seen["input"] == b""


def test_export_once_missing_binary_is_a_clean_failure(tmp_path, monkeypatch):
    def fake_run(argv, **kw):
        raise FileNotFoundError(argv[0])

    monkeypatch.setattr(audit_export.subprocess, "run", fake_run)
    ok, detail = audit_export.export_once(
        str(tmp_path / "audit.jsonl"), _valid_settings(), "pw", str(tmp_path))
    assert ok is False and "age failed to start" in detail


def test_export_filenames_unique_within_a_second(tmp_path, monkeypatch):
    """Regression: two exports in the same UTC second (a manual run racing
    the daily scheduler) used to produce the SAME destination filename, so
    the second upload silently overwrote the first at the backup host."""
    def fake_run(argv, input=None, capture_output=None, timeout=None, env=None):
        if argv[0] != "sshpass":
            with open(argv[argv.index("-o") + 1], "wb") as f:
                f.write(b"agedata")

        class _Proc:
            returncode = 0
            stderr = b""
        return _Proc()

    monkeypatch.setattr(audit_export.subprocess, "run", fake_run)
    audit_export.write_settings(
        audit_export.settings_path(str(tmp_path)), _valid_settings())
    names = set()
    for _ in range(2):
        ok, detail = audit_export.export_once(
            str(tmp_path / "audit.jsonl"), _valid_settings(), "pw",
            str(tmp_path), now_fn=lambda: 1755640000.0)   # frozen second
        assert ok is True
        assert re.match(r"^audit-\d{8}-\d{6}-[0-9a-f]{6}\.jsonl\.age$", detail)
        names.add(detail)
    assert len(names) == 2


# ---- _record_result vs the config routes (shared settings lock) -----------

def test_record_result_drops_when_settings_deleted_mid_export(tmp_path):
    """Regression: a DELETE landing during a long (~150s) export must stand.
    The finishing export's _record_result used to do an unlocked
    read-modify-write, resurrecting the just-removed settings file with
    defaults plus a stale status line."""
    spath = audit_export.settings_path(str(tmp_path))
    audit_export.write_settings(spath, _valid_settings())
    audit_export.clear_settings(spath)      # the operator's DELETE mid-export
    ok, _detail = audit_export.export_once(
        str(tmp_path / "audit.jsonl"), _valid_settings(age_recipient=""),
        "pw", str(tmp_path))
    assert ok is False
    assert not os.path.exists(spath)        # the delete stands: no file back


def test_record_result_serializes_with_settings_saves(tmp_path, monkeypatch):
    """A console save landing while _record_result is mid read-modify-write
    must wait on SETTINGS_LOCK (the gui_server routes hold the same lock) --
    and afterwards BOTH writes survive: the save's destination edit and the
    record's last_result."""
    spath = audit_export.settings_path(str(tmp_path))
    audit_export.write_settings(spath, _valid_settings())
    entered, release = threading.Event(), threading.Event()
    real_read = audit_export.read_settings

    def slow_read(path):        # holds _record_result's critical section open
        out = real_read(path)
        entered.set()
        release.wait(3.0)
        return out

    monkeypatch.setattr(audit_export, "read_settings", slow_read)
    rec = threading.Thread(
        target=audit_export._record_result,
        args=(spath, True, "audit-x.jsonl.age", time.time), daemon=True)
    rec.start()
    assert entered.wait(3.0)
    saved = threading.Event()

    def save():                 # the POST route's locked read-modify-write
        with audit_export.SETTINGS_LOCK:
            cur = real_read(spath)
            cur["host"] = "other.example.com"
            audit_export.write_settings(spath, cur)
        saved.set()

    threading.Thread(target=save, daemon=True).start()
    assert not saved.wait(0.2)              # blocked behind the record
    release.set()
    assert saved.wait(3.0)
    rec.join(3.0)
    got = real_read(spath)
    assert got["host"] == "other.example.com"           # the save survived
    assert got["last_result"] == "ok:audit-x.jsonl.age"  # and so did the record


# ---- start_export / get_job (one-shot job table) --------------------------

def _wait_job(job_id, timeout=3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = audit_export.get_job(job_id)
        if job and job["state"] in ("done", "error"):
            return job
        time.sleep(0.01)
    raise AssertionError("export job did not finish")


def test_start_export_done_and_audited_before_terminal(tmp_path):
    audits = []
    jid = audit_export.start_export(
        str(tmp_path / "a.jsonl"), _valid_settings(), "pw", str(tmp_path),
        audit_fn=lambda **kw: audits.append(kw),
        export_fn=lambda *a, **k: (True, "audit-x.jsonl.age"))
    job = _wait_job(jid)
    assert job == {"state": "done", "detail": "audit-x.jsonl.age"}
    # audit fired before the job turned terminal (start_ca_refresh contract)
    assert audits == [{"result": "ok", "detail": "audit-x.jsonl.age"}]
    assert audit_export.get_job("nope") is None


def test_start_export_error_state(tmp_path):
    jid = audit_export.start_export(
        str(tmp_path / "a.jsonl"), _valid_settings(), "pw", str(tmp_path),
        export_fn=lambda *a, **k: (False, "scp failed: boom"))
    job = _wait_job(jid)
    assert job["state"] == "error" and "boom" in job["detail"]


def test_start_export_survives_a_raising_audit_fn(tmp_path):
    def bad_audit(**kw):
        raise RuntimeError("audit broke")

    jid = audit_export.start_export(
        str(tmp_path / "a.jsonl"), _valid_settings(), "pw", str(tmp_path),
        audit_fn=bad_audit, export_fn=lambda *a, **k: (True, "f"))
    assert _wait_job(jid)["state"] == "done"


def test_start_export_raising_export_fn_turns_terminal(tmp_path):
    """Regression: an export fn that RAISED (tempfile.TemporaryDirectory on
    a full /tmp, say) killed the worker thread, stranding the job at
    state=running with finished_at=None FOREVER -- TTL eviction only looks
    at finished_at -- and neither the audit trail nor last_result ever
    showed the attempt."""
    audit_export.write_settings(
        audit_export.settings_path(str(tmp_path)), _valid_settings())
    audits = []

    def boom(*a, **k):
        raise OSError("no space left on device")

    jid = audit_export.start_export(
        str(tmp_path / "a.jsonl"), _valid_settings(), "pw", str(tmp_path),
        audit_fn=lambda **kw: audits.append(kw), export_fn=boom)
    job = _wait_job(jid)                    # polls until done/error
    assert job["state"] == "error"
    assert "no space left on device" in job["detail"]
    # the fail audit fired, and last_result moved, just like a (False, ...)
    assert audits == [{"result": "fail", "detail": job["detail"]}]
    got = audit_export.read_settings(audit_export.settings_path(str(tmp_path)))
    assert got["last_result"].startswith("fail:export failed:")
    with audit_export._JOBS_LOCK:
        assert audit_export._JOBS[jid]["finished_at"] is not None
        # age the terminal job past the TTL: the next start must evict it
        audit_export._JOBS[jid]["finished_at"] = \
            time.time() - audit_export._JOB_TTL - 1
    jid2 = audit_export.start_export(
        str(tmp_path / "a.jsonl"), _valid_settings(), "pw", str(tmp_path),
        export_fn=lambda *a, **k: (True, "f"))
    assert audit_export.get_job(jid) is None        # evicted, not immortal
    _wait_job(jid2)


# ---- export_loop (daily scheduler) ----------------------------------------

def test_export_loop_runs_when_due_and_audits_as_system(tmp_path):
    audit_export.write_settings(
        audit_export.settings_path(str(tmp_path)), _valid_settings(auto=True))
    ran = threading.Event()
    calls = []
    audits = []

    def fake_export(audit_path, settings, password, state_dir,
                    now_fn=time.time):
        calls.append((audit_path, settings["host"], password, state_dir))
        ran.set()
        return True, "audit-x.jsonl.age"

    stop = threading.Event()
    t = threading.Thread(
        target=audit_export.export_loop,
        args=(stop, "/fake/audit.jsonl", str(tmp_path),
              lambda: {"password": "pw"}),
        kwargs={"audit_fn": lambda **kw: audits.append(kw),
                "wake": 30, "first_delay": 0.01, "export_fn": fake_export},
        daemon=True)
    t.start()
    assert ran.wait(3.0)
    stop.set(); t.join(3.0)
    assert calls == [("/fake/audit.jsonl", "backup.example.com", "pw",
                      str(tmp_path))]
    assert audits[0]["event"] == "audit_export"
    assert audits[0]["category"] == "settings"
    assert audits[0]["actor"] == "system"
    assert audits[0]["result"] == "ok"
    assert audits[0]["detail"] == "audit-x.jsonl.age"


def test_export_loop_skips_when_auto_off_or_fresh(tmp_path):
    spath = audit_export.settings_path(str(tmp_path))
    calls = []
    for settings in (_valid_settings(auto=False),
                     _valid_settings(auto=True,
                                     last_run_ts=int(time.time()) - 60)):
        audit_export.write_settings(spath, settings)
        stop = threading.Event()
        t = threading.Thread(
            target=audit_export.export_loop,
            args=(stop, "/fake/a", str(tmp_path), lambda: None),
            kwargs={"first_delay": 0.01, "wake": 0.02,
                    "export_fn":
                        lambda *a, **k: calls.append(1) or (True, "f")},
            daemon=True)
        t.start()
        time.sleep(0.2)
        stop.set(); t.join(3.0)
    assert calls == []


def test_export_loop_survives_a_raising_export_fn(tmp_path):
    # Rewritten (IRIS-05-005): the old version asserted an HOURLY retry of a
    # raising export, which was the defect -- nothing recorded the failure,
    # so export_due stayed true and the console kept the stale "ok". Now a
    # raising attempt is recorded like any failed attempt (last_result moves
    # to fail:, last_run_ts advances, the trail gets its fail line) and the
    # loop backs off to the daily cadence; the loop itself still survives.
    spath = audit_export.settings_path(str(tmp_path))
    audit_export.write_settings(
        spath, dict(_valid_settings(auto=True),
                    last_run_ts=1000, last_result="ok:audit-old.jsonl.age"))
    hits = []
    audits = []
    clock = {"t": 10 ** 6}

    def boom(*a, **k):
        hits.append(1)
        raise RuntimeError("kaboom")

    stop = threading.Event()
    t = threading.Thread(
        target=audit_export.export_loop,
        args=(stop, "/fake/a", str(tmp_path), lambda: {"password": "p"}),
        kwargs={"first_delay": 0.01, "wake": 0.02, "export_fn": boom,
                "audit_fn": lambda **kw: audits.append(kw),
                "now_fn": lambda: clock["t"]},
        daemon=True)
    t.start()
    deadline = time.time() + 3.0
    while len(hits) < 1 and time.time() < deadline:
        time.sleep(0.01)
    time.sleep(0.1)
    assert len(hits) == 1                       # no hourly retry storm
    recorded = audit_export.read_settings(spath)
    assert recorded["last_run_ts"] == clock["t"]
    assert recorded["last_result"].startswith("fail:export failed: kaboom")
    assert audits and audits[0]["result"] == "fail" \
        and audits[0]["event"] == "audit_export"
    assert not audit_export.export_due(recorded, clock["t"])
    # A day later the loop (still alive) tries again.
    clock["t"] += 86400 + 1
    deadline = time.time() + 3.0
    while len(hits) < 2 and time.time() < deadline:
        time.sleep(0.01)
    stop.set(); t.join(3.0)
    assert len(hits) == 2 and t.is_alive() is False   # loop outlived the raise


# ---- console routes (test_gui_server.py style) ----------------------------

def _serve_export(tmp_path):
    """gui_server on an ephemeral port with creds + a real audit.jsonl."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    app.set_admin("admin", "pw")
    creds = gui_creds.CredentialStore(secrets_path)
    audit_path = str(tmp_path / "audit.jsonl")
    srv = gui_server.make_server("127.0.0.1", 0, app, creds=creds,
                                 audit_path=audit_path, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, creds, audit_path, srv.shutdown


def _req(host, port, method, path, body=None, headers=None):
    c = http.client.HTTPConnection(host, port, timeout=5)
    hdrs = dict(headers or {})
    payload = None
    if body is not None:
        payload = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    c.request(method, path, body=payload, headers=hdrs)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, dict(r.getheaders()), data


def _auth(host, port):
    s, h, b = _req(host, port, "POST", "/api/login",
                   {"username": "admin", "password": "pw"})
    return h["Set-Cookie"].split(";")[0], json.loads(b)["csrf"]


def _read_audit_lines(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def _cfg_body(**over):
    body = {"host": "backup.example.com", "port": 2022, "user": "iris",
            "path": "/srv/audit", "age_recipient": "age1" + "q" * 58,
            "auto": True, "password": "scp-pw"}
    body.update(over)
    return {k: v for k, v in body.items() if v is not None}


def test_audit_export_routes_are_auth_gated(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _creds, _ap, stop = _serve_export(tmp_path)
    try:
        assert _req(host, port, "GET",
                    "/api/settings/audit-export/run/x")[0] == 401
        assert _req(host, port, "POST", "/api/settings/audit-export",
                    _cfg_body())[0] == 401
        assert _req(host, port, "POST",
                    "/api/settings/audit-export/run", {})[0] == 401
        assert _req(host, port, "DELETE", "/api/settings/audit-export")[0] == 401
        # session without the CSRF header: mutations refuse
        ck, _csrf = _auth(host, port)
        assert _req(host, port, "POST", "/api/settings/audit-export",
                    _cfg_body(), headers={"Cookie": ck})[0] == 403
        assert _req(host, port, "DELETE", "/api/settings/audit-export",
                    headers={"Cookie": ck})[0] == 403
    finally:
        stop()


def test_audit_export_config_roundtrip_and_settings_payload(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, creds, audit_path, stop = _serve_export(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # before any config: defaults + password_set False in /api/settings
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        assert st == 200
        ax = json.loads(b)["audit_export"]
        assert ax == {"host": "", "port": 22, "user": "", "path": "",
                      "age_recipient": "", "auto": False,
                      "last_run_ts": None, "last_result": None,
                      "password_set": False}
        st, _, b = _req(host, port, "POST", "/api/settings/audit-export",
                        _cfg_body(), headers=hh)
        assert st == 200 and json.loads(b) == {"ok": True}
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        ax = json.loads(b)["audit_export"]
        assert ax["host"] == "backup.example.com" and ax["port"] == 2022
        assert ax["user"] == "iris" and ax["path"] == "/srv/audit"
        assert ax["auto"] is True and ax["password_set"] is True
        # the settings file on disk never holds the password
        spath = str(tmp_path / "state" / "audit-export-settings.json")
        with open(spath) as f:
            assert "scp-pw" not in f.read()
        assert creds.audit_export_secrets()["password"] == "scp-pw"
        # audited as audit_export_config, without the password
        events = _read_audit_lines(audit_path)
        cfg_events = [e for e in events if e["event"] == "audit_export_config"]
        assert cfg_events and cfg_events[-1]["category"] == "settings"
        assert cfg_events[-1]["actor"] == "console:admin"
        assert "scp-pw" not in json.dumps(events)
    finally:
        stop()


def test_audit_export_config_validation_400(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _creds, _ap, stop = _serve_export(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        for body in (_cfg_body(host=None),           # missing required field
                     _cfg_body(host=""),
                     _cfg_body(host="-evil"),
                     _cfg_body(user="u x"),
                     _cfg_body(path="relative"),
                     _cfg_body(path="/has space"),
                     _cfg_body(age_recipient="nope"),
                     _cfg_body(port="2022"),
                     _cfg_body(port=0),
                     _cfg_body(auto="yes"),
                     _cfg_body(password=7)):
            st, _, b = _req(host, port, "POST", "/api/settings/audit-export",
                            body, headers=hh)
            assert st == 400, body
            assert "error" in json.loads(b)
    finally:
        stop()


def test_audit_export_absent_password_keeps_stored_one(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, creds, _ap, stop = _serve_export(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        assert _req(host, port, "POST", "/api/settings/audit-export",
                    _cfg_body(), headers=hh)[0] == 200
        # re-save without a password field: the stored secret survives
        assert _req(host, port, "POST", "/api/settings/audit-export",
                    _cfg_body(password=None, host="other.example.com"),
                    headers=hh)[0] == 200
        assert creds.audit_export_secrets()["password"] == "scp-pw"
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        ax = json.loads(b)["audit_export"]
        assert ax["host"] == "other.example.com"
        assert ax["password_set"] is True
    finally:
        stop()


def test_audit_export_delete_clears_settings_and_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, creds, audit_path, stop = _serve_export(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        assert _req(host, port, "POST", "/api/settings/audit-export",
                    _cfg_body(), headers=hh)[0] == 200
        st, _, b = _req(host, port, "DELETE", "/api/settings/audit-export",
                        headers=hh)
        assert st == 200 and json.loads(b) == {"deleted": True}
        assert creds.audit_export_secrets() is None
        assert not os.path.exists(
            str(tmp_path / "state" / "audit-export-settings.json"))
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        ax = json.loads(b)["audit_export"]
        assert ax["host"] == "" and ax["password_set"] is False
        # idempotent second delete
        st, _, b = _req(host, port, "DELETE", "/api/settings/audit-export",
                        headers=hh)
        assert st == 200 and json.loads(b) == {"deleted": False}
        clears = [e for e in _read_audit_lines(audit_path)
                  if e["event"] == "audit_export_config"
                  and e.get("action") == "clear"]
        assert len(clears) == 2
    finally:
        stop()


def test_audit_export_run_unconfigured_409(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, creds, _ap, stop = _serve_export(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # nothing configured at all
        st, _, b = _req(host, port, "POST", "/api/settings/audit-export/run",
                        {}, headers=hh)
        assert st == 409 and "error" in json.loads(b)
        # settings present but no password stored: still refused
        audit_export.write_settings(
            audit_export.settings_path(str(tmp_path / "state")),
            _valid_settings())
        st, _, _b = _req(host, port, "POST", "/api/settings/audit-export/run",
                         {}, headers=hh)
        assert st == 409
        # password present but settings invalid: refused too
        creds.set_audit_export_secret("pw")
        audit_export.write_settings(
            audit_export.settings_path(str(tmp_path / "state")),
            _valid_settings(age_recipient=""))
        st, _, _b = _req(host, port, "POST", "/api/settings/audit-export/run",
                         {}, headers=hh)
        assert st == 409
    finally:
        stop()


def test_audit_export_run_job_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    calls = []

    def fake_export(audit_path, settings, password, state_dir,
                    now_fn=time.time):
        calls.append({"audit_path": audit_path, "host": settings["host"],
                      "password": password, "state_dir": state_dir})
        return True, "audit-20260820-120000.jsonl.age"

    # start_export resolves export_once at call time, so this keeps
    # subprocess entirely out of the route test
    monkeypatch.setattr(audit_export, "export_once", fake_export)
    host, port, _creds, audit_path, stop = _serve_export(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        assert _req(host, port, "POST", "/api/settings/audit-export",
                    _cfg_body(), headers=hh)[0] == 200
        st, _, b = _req(host, port, "POST", "/api/settings/audit-export/run",
                        {}, headers=hh)
        assert st == 200
        jid = json.loads(b)["job_id"]
        deadline = time.time() + 3.0
        job = None
        while time.time() < deadline:
            st, _, b = _req(host, port, "GET",
                            "/api/settings/audit-export/run/" + jid,
                            headers={"Cookie": ck})
            assert st == 200
            job = json.loads(b)
            if job["state"] in ("done", "error"):
                break
            time.sleep(0.02)
        assert job == {"state": "done",
                       "detail": "audit-20260820-120000.jsonl.age"}
        assert calls and calls[0]["password"] == "scp-pw"
        assert calls[0]["audit_path"] == audit_path
        assert calls[0]["state_dir"] == str(tmp_path / "state")
        runs = [e for e in _read_audit_lines(audit_path)
                if e["event"] == "audit_export"]
        assert runs and runs[-1]["actor"] == "console:admin"
        assert runs[-1]["result"] == "ok"
        assert runs[-1]["detail"] == "audit-20260820-120000.jsonl.age"
        # unknown job id -> 404
        assert _req(host, port, "GET", "/api/settings/audit-export/run/nope",
                    headers={"Cookie": ck})[0] == 404
    finally:
        stop()


def test_audit_export_run_error_job_state(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    monkeypatch.setattr(audit_export, "export_once",
                        lambda *a, **k: (False, "scp failed: no route"))
    host, port, _creds, audit_path, stop = _serve_export(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        assert _req(host, port, "POST", "/api/settings/audit-export",
                    _cfg_body(), headers=hh)[0] == 200
        st, _, b = _req(host, port, "POST", "/api/settings/audit-export/run",
                        {}, headers=hh)
        assert st == 200
        jid = json.loads(b)["job_id"]
        deadline = time.time() + 3.0
        job = None
        while time.time() < deadline:
            _st, _, b = _req(host, port, "GET",
                             "/api/settings/audit-export/run/" + jid,
                             headers={"Cookie": ck})
            job = json.loads(b)
            if job["state"] in ("done", "error"):
                break
            time.sleep(0.02)
        assert job["state"] == "error" and "no route" in job["detail"]
        runs = [e for e in _read_audit_lines(audit_path)
                if e["event"] == "audit_export"]
        assert runs and runs[-1]["result"] == "fail"
    finally:
        stop()
