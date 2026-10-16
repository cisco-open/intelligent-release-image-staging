# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Exercise the real publisher against a finite local terminal subprocess."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import signal
import time

import pytest


SOURCE = Path(__file__).resolve().parents[2] / "lab/guest-publish.py"
CAP = "0123456789abcdef" * 2
ROOT = "/bootflash/guest-share"
ROWS = [str(size) + ":" + char * 64 for size, char in zip(
    (67513, 4096, 0, 1500, 700, 900, 65, 5481493), "abcdefgh")]
# Use hexadecimal digest characters, including distinct digests per slot.
ROWS = [row.replace("g", "0").replace("h", "1") for row in ROWS]
MARKER = "IRIS-INPUTS-PUBLISHED:" + CAP + ":" + ROWS[-1].split(":")[1]

SIMULATOR = r'''
import json, os, select, signal, subprocess, sys, time
mode, logfile, marker = sys.argv[1:]
ios = "router>" if mode == "enable" else "router#"
guest = "[guestshell@guestshell ~]$ "
def emit(value):
    sys.stdout.write(value); sys.stdout.flush()
def record(line):
    with open(logfile, "a") as stream: stream.write(json.dumps(line) + "\n")
def no_input_yet():
    if select.select([sys.stdin], [], [], 0.025)[0]:
        record("PREMATURE-INPUT"); sys.exit(91)
# A correct client waits for the actual prompt, not its own queued commands.
no_input_yet(); emit(ios)
inside = False; published = False
while True:
    line = sys.stdin.readline()
    if not line: record("PREMATURE-EOF"); sys.exit(92)
    line = line.rstrip("\r\n"); record(line)
    if line == "enable" and ios == "router>" and not inside:
        emit("Password: ")
        secret = sys.stdin.readline().rstrip("\r\n"); record("ENABLE-ANSWER")
        if secret != "synthetic-enable": sys.exit(93)
        ios = "router#"; emit(ios); continue
    if line == "terminal length 0" and not inside:
        emit(line + "\r\n" + ios); continue
    if line in ("guestshell", "guestshell run bash") and not inside:
        if mode == "ios-error":
            emit("% Invalid input detected at '^' marker.\r\n" + ios); continue
        inside = True; emit(line + "\r\n" + guest); continue
    if line.startswith("bash ") and inside and not published:
        published = True
        emit(line + "\r\n")
        no_input_yet()
        if mode == "timeout": time.sleep(10); continue
        if mode == "marker-no-prompt": emit(marker + "\r\n"); time.sleep(10); continue
        if mode == "abort":
            descendant = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            record({"child": os.getpid(), "descendant": descendant.pid, "group": os.getpgrp()})
            def stop(signum, frame):
                # The real group signal must reach both ordinary processes.
                # Reap our child before exiting, so absence is independently observable.
                descendant.wait(timeout=2); sys.exit(0)
            signal.signal(signal.SIGTERM, stop)
            time.sleep(30); continue
        if mode == "disconnect": sys.exit(0)
        if mode == "oversized": emit("synthetic-secret-" * 6000)
        elif mode == "duplicate": emit(marker + "\r\n" + marker + "\r\n")
        elif mode == "wrapped": emit(marker[:45] + "\r\n" + marker[45:] + "\r\n")
        elif mode == "refused": emit("IRIS-BOOTSTRAP: input publication refused; inspect retained inputs\r\n")
        elif mode == "python-error": emit("PermissionError: synthetic-secret\r\n")
        elif mode == "missing": emit("synthetic-secret\r\n")
        else: emit(marker + "\r\n")
        emit(guest); continue
    if line == "exit" and inside:
        inside = False; emit("exit\r\n" + ios); continue
    if line == "exit" and not inside:
        sys.exit(7 if mode == "ssh-failure" else 0)
    record("UNEXPECTED-COMMAND"); sys.exit(94)
'''


@pytest.fixture
def publisher():
    spec = importlib.util.spec_from_file_location("actual_guest_publish_transport", SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def terminal(tmp_path, mode):
    log = tmp_path / "terminal.jsonl"
    calls, children = [], []

    def start(argv, **kwargs):
        calls.append((argv, kwargs))
        child = subprocess.Popen([sys.executable, "-u", "-c", SIMULATOR, mode, str(log), MARKER], **kwargs)
        children.append(child)
        return child

    return start, calls, children, log


def lines(log):
    return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []


@pytest.mark.parametrize("mode", ["success", "enable"])
def test_actual_transport_waits_for_prompts_and_delivers_long_command_once(publisher, tmp_path, monkeypatch, mode):
    monkeypatch.setenv("DEVICE_USER", "fixture-user")
    monkeypatch.setenv("DEVICE_PASS", "synthetic-secret")
    monkeypatch.setenv("DEVICE_ENABLE", "synthetic-enable")
    start, calls, children, log = terminal(tmp_path, mode)
    assert publisher.publish("192.0.2.1", ROOT, CAP, ROWS, popen=start, timeout=3) == MARKER
    observed = lines(log)
    commands = [line for line in observed if "--publish-inputs" in line]
    assert len(calls) == len(commands) == 1
    assert commands[0] == "bash " + ROOT + "/.iris-upload-" + CAP + "-bootstrap.sh --publish-inputs " + CAP + " " + " ".join(ROWS)
    assert len(commands[0]) > 650
    enter = next(index for index, line in enumerate(observed) if line in ("guestshell", "guestshell run bash"))
    assert observed.index(commands[0]) > enter
    assert observed[-2:] == ["exit", "exit"]
    assert ("enable" in observed) is (mode == "enable")
    assert "PREMATURE-INPUT" not in observed and "PREMATURE-EOF" not in observed
    assert all(child.poll() is not None for child in children)
    assert "synthetic-secret" not in repr(calls[0][0])
    assert "synthetic-enable" not in repr(calls[0][0])


@pytest.mark.parametrize("mode,category", [
    ("ios-error", "ios-command-rejected"), ("missing", "missing-marker"),
    ("wrapped", "marker-framing"), ("duplicate", "duplicate-marker"),
    ("refused", "bootstrap-refused"), ("python-error", "python-error"),
    ("disconnect", "transport-closed"), ("ssh-failure", "transport-error"),
    ("oversized", "oversized-response"), ("timeout", "transport-timeout"),
    ("marker-no-prompt", "transport-timeout"),
])
def test_unknown_or_invalid_terminal_outcome_refuses_without_replay(publisher, tmp_path, monkeypatch, capsys, mode, category):
    monkeypatch.setenv("DEVICE_USER", "fixture-user")
    monkeypatch.setenv("DEVICE_PASS", "synthetic-secret")
    start, calls, children, log = terminal(tmp_path, mode)
    with pytest.raises(publisher.PublicationError) as caught:
        publisher.publish("192.0.2.1", ROOT, CAP, ROWS, popen=start,
                          timeout=0.4 if mode in ("timeout", "marker-no-prompt", "ios-error") else 3)
    assert len(calls) == 1
    observed = lines(log)
    assert len([line for line in observed if "--publish-inputs" in line]) <= 1
    assert caught.value.category == category
    assert "synthetic-secret" not in str(caught.value)
    assert capsys.readouterr() == ("", "")
    assert "PREMATURE-INPUT" not in observed
    assert all(child.poll() is not None for child in children)
    if mode == "ios-error":
        assert not any("--publish-inputs" in line for line in observed)
    if mode == "marker-no-prompt":
        assert "exit" not in observed


@pytest.mark.parametrize("root,cap,rows", [
    ("/tmp/guest-share", CAP, ROWS), (ROOT + "/../state", CAP, ROWS),
    (ROOT, CAP + ";id", ROWS), (ROOT, CAP, ROWS[:-1]),
    (ROOT, CAP, ["0:" + "a" * 64] + ROWS[1:]),
    (ROOT, CAP, ROWS[:3] + ["1:" + "g" * 64] + ROWS[4:]),
])
def test_closed_inputs_refuse_before_any_connection(publisher, root, cap, rows):
    def forbidden(*args, **kwargs):
        pytest.fail("Invalid selector reached the transport")
    with pytest.raises(publisher.PublicationError):
        publisher.publish("192.0.2.1", root, cap, rows, popen=forbidden, timeout=1)


def test_cli_reports_only_closed_diagnostic_after_real_terminal_failure(publisher, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DEVICE_USER", "fixture-user")
    monkeypatch.setenv("DEVICE_PASS", "synthetic-secret")
    start, calls, children, log = terminal(tmp_path, "python-error")
    actual = publisher.publish
    monkeypatch.setattr(publisher, "publish", lambda *args: actual(*args, popen=start, timeout=3))
    assert publisher.main(["192.0.2.1", ROOT, CAP, *ROWS]) == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert "category=python-error, marker-count=0, transport-status=0" in err
    assert "synthetic-secret" not in err and "PermissionError" not in err and CAP not in err
    assert len(calls) == 1 and all(child.poll() is not None for child in children)


def test_real_existing_ssh_policy_is_applied_without_password_arguments(publisher, tmp_path):
    executable = tmp_path / "sshpass"
    capture = tmp_path / "ssh-argv.json"
    executable.write_text("#!/usr/bin/env python3\nimport json,os,sys\n"
                          "from pathlib import Path\n"
                          "args=sys.argv[1:]\n"
                          "keyfile=next(arg.split('=',1)[1] for arg in args if arg.startswith('UserKnownHostsFile='))\n"
                          "Path(os.environ['CAPTURE']).write_text(json.dumps({'argv':args,'keyfile':keyfile,"
                          "'hostkey':Path(keyfile).read_text(),'passwordEnv':os.environ.get('SSHPASS')=='synthetic-secret'}))\n")
    executable.chmod(0o700)
    env = {"PATH": str(tmp_path) + os.pathsep + os.environ["PATH"], "TMPDIR": str(tmp_path),
           "DEVICE_USER": "fixture-user", "DEVICE_PASS": "synthetic-secret", "CAPTURE": str(capture),
           "IRIS_SSH_HOST_KEY": "ssh-ed25519 c3ludGhldGljLXB1YmxpYy1rZXk="}
    result = subprocess.run(["bash", "-c", publisher.POLICY_SHELL, "iris-guest-publish",
                             str(SOURCE.with_name("iris-ssh-policy.sh")), "192.0.2.1"],
                            env=env, capture_output=True, text=True, timeout=5)
    assert result.returncode == 0 and result.stdout == result.stderr == ""
    observed = json.loads(capture.read_text())
    assert observed["argv"][:2] == ["-e", "ssh"]
    assert "StrictHostKeyChecking=yes" in observed["argv"]
    assert "NumberOfPasswordPrompts=1" in observed["argv"]
    assert observed["argv"][-3:] == ["-l", "fixture-user", "192.0.2.1"]
    assert observed["passwordEnv"] is True
    assert "synthetic-secret" not in json.dumps(observed)
    assert observed["hostkey"] == "192.0.2.1 " + env["IRIS_SSH_HOST_KEY"] + "\n"
    assert not Path(observed["keyfile"]).exists()


def test_sigterm_during_publication_reaps_owned_transport_and_descendant(tmp_path):
    simulator = tmp_path / "terminal.py"
    simulator.write_text(SIMULATOR)
    log = tmp_path / "terminal.jsonl"
    # Execute actual main() and its signal handler in a separate process. The
    # only substituted boundary is the local subprocess standing in for SSH.
    harness = r'''
import importlib.util, subprocess, sys
spec=importlib.util.spec_from_file_location("actual_guest_publish",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
real=module.publish
def terminal(argv,**kwargs):
    return subprocess.Popen([sys.executable,"-u",sys.argv[2],"abort",sys.argv[3],sys.argv[4]],**kwargs)
module.publish=lambda *args:real(*args,popen=terminal,timeout=10)
raise SystemExit(module.main(sys.argv[5:]))
'''
    process = subprocess.Popen([sys.executable, "-u", "-c", harness, str(SOURCE), str(simulator),
                                str(log), MARKER, "192.0.2.1", ROOT, CAP, *ROWS],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               env=dict(os.environ, DEVICE_USER="fixture-user", DEVICE_PASS="synthetic-secret"))
    observed = []
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            observed = lines(log)
            if any(isinstance(row, dict) for row in observed):
                break
            assert process.poll() is None
            time.sleep(0.01)
        owned = next(row for row in observed if isinstance(row, dict))
        assert owned["group"] == owned["child"] != os.getpgrp()
        process.send_signal(signal.SIGTERM)
        out, err = process.communicate(timeout=5)
        assert process.returncode == 1 and out == b""
        assert b"category=aborted" in err and b"synthetic-secret" not in err
        assert not Path("/proc", str(owned["child"])).exists()
        assert not Path("/proc", str(owned["descendant"])).exists()
        observed = lines(log)
        assert len([row for row in observed if isinstance(row, str) and "--publish-inputs" in row]) == 1
        assert "exit" not in observed
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
