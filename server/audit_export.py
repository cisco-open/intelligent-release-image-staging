# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Audit-trail export (F5): ship audit.jsonl to an operator-configured SCP
destination, age-encrypted to an operator-supplied recipient. Encryption is
mandatory -- there is no plaintext export path -- so a compromised backup host
never yields the trail in the clear.

Settings live in $IRIS_STATE/audit-export-settings.json:
    {"host","port":22,"user","path","age_recipient","auto":false,
     "last_run_ts":null,"last_result":null}
(tolerant read / atomic write, the telemetry_destination.py idiom). The SCP
password is NOT here: it lives in the age-encrypted secrets store (singleton
"audit_export" key via gui_creds.CredentialStore) and rides to sshpass via the
SSHPASS environment variable -- never argv, never a settings file, never a log.

Three run styles, all in this module:
  * export_once()   -- one synchronous attempt, records last_run_ts/last_result;
  * start_export()  -- one-shot daemon-thread job + poll table (the
                       gui_server._CA_JOBS idiom, table hosted here);
  * export_loop()   -- daily scheduler daemon thread (the
                       gui_server.ca_trust_refresh_loop idiom) gated by the
                       pure export_due().
Stdlib only; imports nothing from gui_server (gui_server imports this)."""
import json
import os
import re
import secrets
import subprocess
import tempfile
import threading
import time

BASENAME = "audit-export-settings.json"
KNOWN_HOSTS_BASENAME = "audit-export-known-hosts"
_AGE_TIMEOUT = 30           # age encrypt (s) -- secretfs.py precedent
_SCP_TIMEOUT = 120          # scp upload (s)
_EXPORT_INTERVAL = 86400    # auto cadence: at most one scheduled export a day
_WAKE = 3600                # scheduler wake period (s)
_FIRST_DELAY = 120          # "shortly after start" first pass (s)
_FAIL_DETAIL_MAX = 120      # last_result stores "fail:<detail capped here>"

# Conservative shapes for the operator-entered destination fields: every one
# of these lands on an argv slot of age/scp, so no whitespace anywhere, no
# leading "-" (option smuggling), path absolute or ~-relative only.
_RECIPIENT_RE = re.compile(r"^age1[0-9a-z]+$")
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_PATH_RE = re.compile(r"^(?:/|~(?:/|$))[A-Za-z0-9._/-]*$")

_DEFAULTS = {"host": "", "port": 22, "user": "", "path": "",
             "age_recipient": "", "auto": False,
             "last_run_ts": None, "last_result": None}

# Serializes every read-modify-write of the settings file, here AND in the
# gui_server config routes (POST save / DELETE clear import it): without it a
# _record_result landing mid-save (an export takes up to ~150s) could lose the
# operator's edit -- or resurrect a file a DELETE just removed.
SETTINGS_LOCK = threading.Lock()


def settings_path(state_dir):
    return os.path.join(state_dir, BASENAME)


def read_settings(path):
    """Tolerant read: missing/unreadable file, corrupt JSON, non-dict
    documents and wrong-typed fields all collapse to the defaults -- a
    garbage settings file can only ever disable the export, never break a
    caller. A settings reader never raises."""
    out = dict(_DEFAULTS)
    try:
        with open(path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return out
    if not isinstance(data, dict):
        return out
    for key in ("host", "user", "path", "age_recipient"):
        val = data.get(key)
        if isinstance(val, str):
            out[key] = val.strip()
    port = data.get("port")
    if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536:
        out["port"] = port
    out["auto"] = data.get("auto") is True
    last = data.get("last_run_ts")
    if isinstance(last, (int, float)) and not isinstance(last, bool):
        out["last_run_ts"] = int(last)
    res = data.get("last_result")
    if isinstance(res, str):
        out["last_result"] = res
    return out


def write_settings(path, settings):
    """Atomic write: mkstemp in the same dir + os.replace (house idiom).
    Persists exactly the known keys, filling absent ones with defaults."""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".audit-export-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({k: settings.get(k, _DEFAULTS[k]) for k in _DEFAULTS},
                      f, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def clear_settings(path):
    """Remove the settings file ("stop exporting"). Idempotent."""
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def validate_settings(settings):
    """Conservative shape check of the destination fields -> error string or
    None. Shared by the console POST route and export_once, so any value that
    reaches an age/scp argv slot was validated on both the write AND the use
    path. The missing-recipient message is load-bearing: encryption is
    mandatory, so that refusal names the actual blocker."""
    if not isinstance(settings, dict):
        return "settings must be an object"
    recipient = str(settings.get("age_recipient") or "").strip()
    if not recipient:
        return "age recipient not configured"
    if not _RECIPIENT_RE.match(recipient):
        return "invalid age recipient (expected age1...)"
    if not _HOST_RE.match(str(settings.get("host") or "")):
        return "invalid host"
    if not _USER_RE.match(str(settings.get("user") or "")):
        return "invalid user"
    if not _PATH_RE.match(str(settings.get("path") or "")):
        return "invalid path (absolute or ~-relative, no spaces)"
    port = settings.get("port", 22)
    if not isinstance(port, int) or isinstance(port, bool) \
            or not 0 < port < 65536:
        return "invalid port"
    return None


def export_due(settings, now):
    """Pure daily-cadence gate for the scheduler loop: True only when auto is
    on AND the last recorded run is absent (or unreadable) or a day old.
    No clock, no I/O -- the loop passes now in."""
    if not isinstance(settings, dict) or settings.get("auto") is not True:
        return False
    last = settings.get("last_run_ts")
    if last is None:
        return True
    try:
        return (now - float(last)) >= _EXPORT_INTERVAL
    except (TypeError, ValueError):
        return True


def _stderr_snippet(raw):
    """Single-line, bounded stderr excerpt for details/audit -- tool errors
    only, never secrets (the password is env-only so it cannot appear)."""
    try:
        text = (raw or b"").decode("utf-8", "replace")
    except Exception:
        text = ""
    text = " ".join(text.split())
    return text[:200] or "no error output"


def _record_result(spath, ok, detail, now_fn):
    """Best-effort last_run_ts/last_result update on the settings file so the
    console status line always reflects the latest attempt. Never raises.
    Takes SETTINGS_LOCK (the config routes hold it too), and if the settings
    file is gone -- the operator DELETEd the config mid-export -- the result
    is dropped rather than resurrecting the file with defaults."""
    try:
        with SETTINGS_LOCK:
            if not os.path.exists(spath):
                return
            current = read_settings(spath)
            current["last_run_ts"] = int(now_fn())
            current["last_result"] = ("ok:%s" % detail if ok
                                      else "fail:%s"
                                           % detail[:_FAIL_DETAIL_MAX])
            write_settings(spath, current)
    except Exception:
        pass


def _run_export(audit_path, settings, password, state_dir, now_fn):
    """The attempt itself -> (ok, detail). detail is the uploaded filename on
    success, an operator-actionable error otherwise -- never the password."""
    err = validate_settings(settings)
    if err:
        return False, err
    if not password:
        return False, "password not configured"
    # Lockless read is safe by design: audit.py readers never take the store
    # flock. An empty or missing trail exports as an empty file -- the
    # destination still gets its daily heartbeat artifact.
    try:
        with open(audit_path, "rb") as f:
            data = f.read()
    except (OSError, TypeError):
        data = b""
    # timestamp for the operator, short random suffix so two exports in the
    # same UTC second (manual run racing the scheduler) can't silently
    # overwrite each other at the destination
    filename = "audit-%s-%s.jsonl.age" % (
        time.strftime("%Y%m%d-%H%M%S", time.gmtime(now_fn())),
        secrets.token_hex(3))
    age_bin = os.environ.get("IRIS_AGE_BIN", "age")
    with tempfile.TemporaryDirectory(prefix="audit-export-") as tmpdir:
        enc_path = os.path.join(tmpdir, filename)
        try:
            proc = subprocess.run([age_bin, "-r", settings["age_recipient"],
                                   "-o", enc_path],
                                  input=data, capture_output=True,
                                  timeout=_AGE_TIMEOUT)
        except subprocess.TimeoutExpired:
            return False, "age encryption timed out"
        except OSError as exc:
            return False, "age failed to start: %s" % exc
        if proc.returncode != 0:
            return False, "age failed: %s" % _stderr_snippet(proc.stderr)
        dest = "%s@%s:%s/" % (settings["user"], settings["host"],
                              str(settings["path"]).rstrip("/"))
        env = dict(os.environ)
        env["SSHPASS"] = password       # sshpass -e: env only, never argv
        try:
            proc = subprocess.run(
                ["sshpass", "-e", "scp", "-P", str(settings.get("port", 22)),
                 "-o", "StrictHostKeyChecking=accept-new",
                 "-o", "UserKnownHostsFile=%s"
                       % os.path.join(state_dir, KNOWN_HOSTS_BASENAME),
                 enc_path, dest],
                env=env, capture_output=True, timeout=_SCP_TIMEOUT)
        except subprocess.TimeoutExpired:
            return False, "scp timed out"
        except OSError as exc:
            return False, "scp failed to start: %s" % exc
        if proc.returncode != 0:
            return False, "scp failed: %s" % _stderr_snippet(proc.stderr)
    return True, filename


def export_once(audit_path, settings, password, state_dir, now_fn=time.time):
    """One export attempt -> (ok, detail): encrypt the audit trail to the
    configured age recipient (refusing outright without one -- a plaintext
    audit log never leaves the box), scp it to <user>@<host>:<path>/, and
    record the outcome in the settings file (last_run_ts/last_result) whatever
    happened, so both the daily gate and the console status line move."""
    ok, detail = _run_export(audit_path, settings, password, state_dir, now_fn)
    _record_result(settings_path(state_dir), ok, detail, now_fn)
    return ok, detail


_JOB_TTL = 3600                 # evict terminal export jobs after (s)
# In-memory one-shot jobs (the gui_server._CA_JOBS idiom): id -> dict, a
# daemon thread runs the export, GET /api/settings/audit-export/run/<id>
# polls. Per-process: a restart abandons in-flight jobs.
_JOBS = {}
_JOBS_LOCK = threading.Lock()


def start_export(audit_path, settings, password, state_dir, audit_fn=None,
                 export_fn=None, now_fn=time.time):
    """Run one export on a daemon thread; returns a job id for the poll route
    immediately. audit_fn(result=..., detail=...) is called BEFORE the job
    turns terminal so a poller that sees done/error can rely on the audit
    line already existing. export_fn is a test seam (defaults to
    export_once, resolved at call time)."""
    job_id = secrets.token_hex(8)
    job = {"state": "running", "detail": "", "finished_at": None}
    now = time.time()
    with _JOBS_LOCK:
        stale = [jid for jid, j in _JOBS.items()
                 if j["finished_at"] is not None
                 and j["finished_at"] <= now - _JOB_TTL]
        for jid in stale:
            del _JOBS[jid]
        _JOBS[job_id] = job

    def run():
        try:
            ok, detail = (export_fn or export_once)(audit_path, settings,
                                                    password, state_dir,
                                                    now_fn=now_fn)
        except Exception as exc:
            # A raising export fn (tempfile.TemporaryDirectory on a full
            # /tmp, say) must not strand the job at state=running forever --
            # TTL eviction only looks at finished_at. Treat it as any other
            # failed attempt (the export_loop posture): last_result moves,
            # the audit trail gets its fail line, the job turns terminal.
            ok, detail = False, "export failed: %s" % exc
            _record_result(settings_path(state_dir), ok, detail, now_fn)
        if audit_fn is not None:
            try:
                audit_fn(result="ok" if ok else "fail", detail=detail)
            except Exception:
                pass                # audit must never break the job
        with _JOBS_LOCK:
            job["state"] = "done" if ok else "error"
            job["detail"] = detail
            job["finished_at"] = time.time()

    threading.Thread(target=run, daemon=True).start()
    return job_id


def get_job(job_id):
    """Poll view {"state","detail"}, or None for an unknown id."""
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return None
        return {"state": job["state"], "detail": job["detail"]}


def export_loop(stop_event, audit_path, state_dir, secrets_fn, audit_fn=None,
                wake=_WAKE, first_delay=_FIRST_DELAY, export_fn=None,
                now_fn=time.time):
    """Daily scheduled export (the gui_server.ca_trust_refresh_loop idiom):
    stop-event wait loop on a daemon thread, first pass shortly after start,
    then an hourly wake that re-reads the settings file and exports only when
    export_due says so (auto on, last recorded run a day old -- export_once
    records failures too, so a broken destination retries daily, not hourly).
    secrets_fn() returns the stored audit_export secret record (or None) at
    run time, so a password change needs no restart. Audits completions as
    audit_export with actor system, and never lets a failure kill the
    thread."""
    delay = first_delay
    while not stop_event.wait(delay):
        delay = wake
        try:
            settings = read_settings(settings_path(state_dir))
            if not export_due(settings, now_fn()):
                continue
            password = ((secrets_fn() if secrets_fn is not None else None)
                        or {}).get("password", "")
            try:
                ok, detail = (export_fn or export_once)(
                    audit_path, settings, password, state_dir, now_fn=now_fn)
            except Exception as exc:
                # A raising attempt (tempfile.TemporaryDirectory on a full
                # /tmp, say) is a failed attempt like any other -- the
                # start_export posture: last_result/last_run_ts move so the
                # console stops reporting the previous success and the
                # retry backs off to daily, and the trail gets its fail line.
                ok, detail = False, "export failed: %s" % exc
                _record_result(settings_path(state_dir), ok, detail, now_fn)
            if audit_fn is not None:
                audit_fn(event="audit_export", category="settings",
                         action="export", target="audit-export",
                         actor="system", result="ok" if ok else "fail",
                         detail=detail)
        except Exception:
            pass                    # the scheduler thread must never die
