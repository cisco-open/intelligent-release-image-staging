# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Actual installers and pending publisher, with only IOS/HTTP transport replaced."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
CAP = "0123456789abcdef0123456789abcdef"
NAMES = ("bootstrap.sh", "iris-agent.conf", "rpc-secret", "iris-catalog.pem",
         "iris-signers.allowed_signers", "iris-instructions.bootstrap",
         "bundle.tgz.sha256", "bundle.tgz")

IOS = r'''#!/usr/bin/env python3
import json, os, pathlib, shlex, shutil, subprocess, sys
root = pathlib.Path(os.environ['TEST_ROOT'])
guest = root / 'guest-share'
commands = sys.stdin.read()
with (root / 'commands').open('a') as stream: stream.write(commands)
mode = os.environ.get('TEST_MODE', '')
if '--publish-inputs ' in commands:
    if mode == 'echo-only':
        print(commands)
        raise SystemExit(0)
    args = shlex.split(commands)
    assert args[:3] == ['guestshell', 'run', 'bash']
    expected_root = '/bootflash/guest-share/' if os.environ['TEST_KIND'] == 'router' else '/flash/guest-share/'
    assert args[3] == expected_root + '.iris-upload-' + os.environ['IRIS_STAGING_CAPABILITY'] + '-bootstrap.sh'
    assert len(commands.strip()) <= 1024
    path = guest / pathlib.Path(args[3]).name
    # IOS can return a successful SSH session even when guestshell reports a
    # command failure. Echo/prompt framing is not a child process exit code.
    marker = 'IRIS-INPUTS-PUBLISHED:' + args[5] + ':' + args[-1].split(':')[1]
    if mode.startswith('ssh-zero-') and mode != 'ssh-zero-bootstrap-refused':
        print('router#' + commands.strip())
        print('synthetic-private-response-do-not-log')
        if mode == 'ssh-zero-cli': print('% Invalid input detected at marker.')
        elif mode == 'ssh-zero-python': print('PermissionError: synthetic-private-response-do-not-log')
        elif mode == 'ssh-zero-wrapped': print(marker[:50] + '\n' + marker[50:])
        elif mode == 'ssh-zero-duplicate': print(marker + '\n' + marker)
        elif mode == 'ssh-zero-oversized': print('x' * 70000)
        else: assert mode == 'ssh-zero-missing'
        print('router#')
        raise SystemExit(0)
    # Match guestshell run: no installer-side SRC/STAGE is exported. The
    # pending script derives its own actual guest-share root and stage.
    environment = {key: value for key, value in os.environ.items() if key not in ('SRC', 'STAGE')}
    if mode == 'ssh-zero-bootstrap-refused':
        # Execute the actual publisher with changed owned input, then frame
        # its rejection as the real IOS transport does: successful SSH.
        with (guest / ('.iris-upload-' + args[5] + '-bundle.tgz')).open('ab') as stream:
            stream.write(b'changed')
        result = subprocess.run(['bash', str(path), *args[4:]],
            env=environment, capture_output=True, text=True)
        assert result.returncode != 0
        print('router#' + commands.strip())
        print(result.stdout + result.stderr)
        print('router#')
        raise SystemExit(0)
    result = subprocess.run(['bash', str(path), *args[4:]],
        env=environment,
        stdout=subprocess.DEVNULL if mode == 'lost-result' else None)
    if mode == 'lost-result': raise SystemExit(1)
    raise SystemExit(result.returncode)
if 'copy https://' in commands:
    for line in commands.splitlines():
        words = shlex.split(line)
        if words[:2] == ['delete', '/force']:
            path = guest / pathlib.Path(words[2]).name
            assert path.name.startswith('.iris-upload-' + os.environ['IRIS_STAGING_CAPABILITY'] + '-')
            path.unlink(missing_ok=True)
        elif words[:1] == ['copy']:
            assert words[1].startswith('https://192.0.2.20:8000/')
            src = root / 'artifacts' / words[1].split(':8000/', 1)[1]
            dst = guest / pathlib.Path(words[2]).name
            raw = src.read_bytes()
            if dst.name.endswith('-bundle.tgz'):
                counter = root / 'copy-count'
                count = int(counter.read_text()) if counter.exists() else 0
                counter.write_text(str(count + 1))
                if mode == 'copy-fails' or mode == 'retry' and count == 0:
                    dst.write_bytes(raw[:2])
                    print('copy failed')
                    raise SystemExit(1)
                if mode == 'changed-bytes': raw += b'changed'
            dst.write_bytes(raw)
            print(str(len(raw)) + ' bytes copied in 0.01 secs')
    raise SystemExit(0)
if '__IRIS_VERIFY_RUNNING__' in commands:
    print('__IRIS_VERIFY_RUNNING__')
    print((root / 'configuration').read_text())
    print('__IRIS_VERIFY_APPS__\nguestshell RUNNING')
    print('__IRIS_VERIFY_FILES__\nbootstrap.sh\niris-agent.conf')
elif '__IRIS_PRECHECK_' in commands:
    print('__IRIS_PRECHECK_FLASH__\nbytes free')
    print('__IRIS_PRECHECK_ROUTING__\nGateway of last resort is 192.0.2.1')
    print('__IRIS_PRECHECK_CLOCK__\nClock is synchronized, stratum 5, reference is 192.0.2.123')
elif 'show ntp status' in commands:
    print('Clock is synchronized, stratum 5, reference is 192.0.2.123')
elif 'show version' in commands:
    print('cisco C8000V (x86) processor\nProcessor board ID SERIAL')
elif 'show app-hosting list' in commands:
    count = root / 'apps'
    if count.exists(): print('guestshell RUNNING')
    count.touch()
elif 'configure terminal' in commands:
    with (root / 'configuration').open('a') as stream: stream.write(commands)
elif 'copy running-config startup-config' in commands:
    (root / 'saved').touch()
    print('[OK]')
elif 'more ' in commands: pass
else: print('bytes free')
'''


def executable(path, content):
    path.write_text(content)
    path.chmod(0o755)


def fixture(tmp_path, kind, mode):
    for name in ("device", "lab", "server", "bin", "artifacts/staging", "guest-share/iris"):
        (tmp_path / name).mkdir(parents=True, exist_ok=True)
    for name in (kind + "-install.sh", "guestshell-publish.sh", "bootstrap.sh"):
        shutil.copyfile(ROOT / "device" / name, tmp_path / "device" / name)
    shutil.copyfile(ROOT / "server/time_preflight.py", tmp_path / "server/time_preflight.py")
    executable(tmp_path / "lab/device-run.sh", IOS)
    executable(tmp_path / "bin/curl", "#!/bin/sh\nexit 0\n")
    executable(tmp_path / "bin/sleep", "#!/bin/sh\nexit 0\n")
    artifacts = tmp_path / "artifacts"
    # The publisher does not qualify archive content. Actual bundle validation
    # and valid/malformed archive transactions run in test_bootstrap.bats.
    (artifacts / "iris-agent.tgz").write_bytes(b"owned bundle transport fixture\n")
    digest = hashlib.sha256((artifacts / "iris-agent.tgz").read_bytes()).hexdigest()
    (artifacts / "iris-agent.tgz.sha256").write_text(digest + "\n")
    (artifacts / "iris-signers.pem").write_text("public signer fixture\n")
    (artifacts / f"staging/iris-instructions-owned-{CAP}.envelope").write_text("sealed fixture\n")
    crt = tmp_path / "certificate.pem"
    crt.write_text("public certificate fixture\n")
    for name in NAMES:
        (tmp_path / "guest-share" / name).write_bytes(b"old input:" + name.encode())
    env = dict(os.environ, PATH=str(tmp_path / "bin") + ":" + os.environ["PATH"],
               TEST_ROOT=str(tmp_path), TEST_MODE=mode, TEST_KIND=kind, IRIS_STAGE_LOCAL="1",
               IRIS_ARTIFACTS_DIR=str(artifacts), IRIS_CRT_FILE=str(crt),
               IRIS_STAGING_CAPABILITY=CAP, MODEL="C8000V" if kind == "router" else "C9300",
               EXPECTED_DEVICE_IDENTITY="SERIAL", DEVICE_IP="192.0.2.10", DEVICE_ID="owned",
               CATALOG_URL="https://192.0.2.20:8443", CATALOG_TOKEN="synthetic-private-value",
               STAGE_HOST="192.0.2.20", MANAGEMENT_TYPE="router-routed" if kind == "router" else "routed",
               VPG_NUMBER="10", APP_IP="10.8.0.2", APP_MASK="255.255.255.252", APP_GATEWAY="10.8.0.1",
               VLAN="10", SVI_IP="10.8.0.1", SVI_MASK="255.255.255.252", GUEST_IP="10.8.0.2")
    return env


@pytest.mark.parametrize("kind", ["router", "device"])
@pytest.mark.parametrize("mode", ["success", "retry", "copy-fails", "changed-bytes", "echo-only", "lost-result"])
def test_actual_installers_publish_only_complete_inputs(tmp_path, kind, mode):
    env = fixture(tmp_path, kind, mode)
    result = subprocess.run(["bash", str(tmp_path / "device" / (kind + "-install.sh"))],
                            env=env, capture_output=True, text=True, timeout=20)
    commands = (tmp_path / "commands").read_text()
    assert "synthetic-private-value" not in commands + result.stdout + result.stderr
    if mode in ("success", "retry"):
        assert result.returncode == 0, result.stdout + result.stderr
        assert (tmp_path / "saved").exists()
        assert "inputs published; bundle acceptance and runtime startup are separate" in result.stdout
        assert not list((tmp_path / "guest-share").glob(".iris-upload-*"))
        assert (tmp_path / "guest-share/bootstrap.sh").read_bytes() == (ROOT / "device/bootstrap.sh").read_bytes()
        assert not (tmp_path / "guest-share/iris/bundle-outcome.json").exists()
    elif mode == "lost-result":
        assert result.returncode != 0 and not (tmp_path / "saved").exists()
        assert (tmp_path / "guest-share/bootstrap.sh").read_bytes() == (ROOT / "device/bootstrap.sh").read_bytes()
        assert "outcome unknown" in result.stderr
    else:
        assert result.returncode != 0
        assert not (tmp_path / "saved").exists()
        for name in NAMES:
            assert (tmp_path / "guest-share" / name).read_bytes() == b"old input:" + name.encode()
    assert commands.count("--publish-inputs ") == (0 if mode == "copy-fails" else 1)
    expected_count = 3 if mode == "copy-fails" else 2 if mode == "retry" else 1
    assert int((tmp_path / "copy-count").read_text()) == expected_count
    deletes = [line for line in commands.splitlines() if line.startswith("delete ")]
    assert all("/.iris-upload-" + CAP + "-" in line for line in deletes)


def test_actual_installer_custom_stage_cannot_redirect_pending_publication(tmp_path):
    env = fixture(tmp_path, "device", "success")
    env["STAGE"] = "/flash/guest-share/custom"
    result = subprocess.run(["bash", str(tmp_path / "device/device-install.sh")],
                            env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    command = next(line for line in (tmp_path / "commands").read_text().splitlines()
                   if "--publish-inputs " in line)
    assert command.startswith("guestshell run bash /flash/guest-share/.iris-upload-")
    assert "custom" not in command
    assert "stage_dir = /flash/guest-share/custom" in (tmp_path / "guest-share/iris-agent.conf").read_text()


@pytest.mark.parametrize("mode,category,count", [
    ("ssh-zero-cli", "ios-command-rejected", "0"),
    ("ssh-zero-python", "python-error", "0"),
    ("ssh-zero-bootstrap-refused", "bootstrap-refused", "0"),
    ("ssh-zero-wrapped", "marker-framing", "0"),
    ("ssh-zero-missing", "missing-marker", "0"),
    ("ssh-zero-duplicate", "duplicate-marker", "2"),
    ("ssh-zero-oversized", "oversized-response", "unknown"),
])
def test_successful_ssh_does_not_prove_guest_publication(tmp_path, mode, category, count):
    env = fixture(tmp_path, "router", mode)
    result = subprocess.run(["bash", str(tmp_path / "device/router-install.sh")],
                            env=env, capture_output=True, text=True, timeout=20)
    assert result.returncode != 0
    assert not (tmp_path / "saved").exists()
    assert f"category={category}, marker-count={count}, transport-status=0" in result.stderr
    assert "publication not proved" in result.stderr
    assert "synthetic-private-response-do-not-log" not in result.stdout + result.stderr
    assert "synthetic-private-value" not in result.stdout + result.stderr
    for name in NAMES:
        assert (tmp_path / "guest-share" / name).read_bytes() == b"old input:" + name.encode()
    assert (tmp_path / "commands").read_text().count("--publish-inputs ") == 1
    assert int((tmp_path / "copy-count").read_text()) == 1


@pytest.mark.parametrize("remote", [False, True])
def test_actual_metadata_binds_each_source_and_empty_rpc(tmp_path, remote):
    artifacts = tmp_path / "iris/artifacts"
    (artifacts / "staging").mkdir(parents=True)
    names = ["bootstrap.sh", "staging/config", "staging/rpc", "iris-catalog.pem",
             "iris-signers.pem", "staging/envelope", "staging/digest", "bundle"]
    for index, name in enumerate(names):
        (artifacts / name).write_bytes(b"" if index == 2 else ("public-" + name).encode())
    # Only the existing SSH boundary is simulated. The exact remotely rendered
    # metadata program executes through bash, with a deliberately unusable ART.
    code = r'''source "$1"
ssh_host() { local command="${1/\"\$HOME\"/\"$TEST_ROOT\"}"; bash -c "$command"; }
guest_input_metadata
'''
    env = dict(os.environ, CONF="config", RPC_SECRET_FILE="rpc", INSTRUCTION_ENVELOPE="envelope",
               BUNDLE_DIGEST_FILE="digest", BUNDLE="bundle", TEST_ROOT=str(tmp_path),
               STAGE_LOCAL="0" if remote else "1", ART="/nonexistent" if remote else str(artifacts))
    def invoke():
        return subprocess.run(["bash", "-c", code, "test", str(ROOT / "device/guestshell-publish.sh")],
                              env=env, capture_output=True, text=True, timeout=5)
    result = invoke()
    assert result.returncode == 0, result.stderr
    expected = [str(len((artifacts / name).read_bytes())) + ":" +
                hashlib.sha256((artifacts / name).read_bytes()).hexdigest() for name in names]
    assert result.stdout.splitlines() == expected
    (artifacts / names[1]).write_bytes(b"")
    assert invoke().returncode != 0
