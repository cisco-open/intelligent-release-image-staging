# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Execute the real router cleanup; replace only its IOS transport boundary."""
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "device/router-uninstall.sh"
CAP = "0123456789abcdef0123456789abcdef"
NAMES = ("bootstrap.sh", "iris-agent.conf", "rpc-secret", "iris-catalog.pem",
         "iris-signers.allowed_signers", "iris-instructions.bootstrap",
         "bundle.tgz.sha256", "bundle.tgz")
PENDING = tuple(".iris-upload-" + CAP + "-" + name for name in NAMES)
FOREIGN = ("operator-image.bin", "bootstrap.sh.operator-copy", "rpc-secret.notes",
           ".iris-upload-" + CAP + "-rpc-secret.notes",
           ".iris-upload-" + CAP.upper() + "-bundle.tgz",
           ".iris-upload-" + CAP[:-1] + "-bootstrap.sh", "iris-operator")


def row(name, *, index=1, mode="-rw-", size="12"):
    return f" {index}  {mode}  {size}  Oct 11 2026 12:00:00 +00:00  {name}"


def listing(rows=()):
    return ("router#terminal width 512\nrouter#dir bootflash:guest-share\n"
            "Directory of bootflash:/guest-share/\n\n"
            + "\n".join(rows) + "\n1000000 bytes total (500000 bytes free)\n"
            + "router#exit\n")


def parse(text, mode="pending"):
    source = SCRIPT.read_text()
    function = "pending_inputs() {\n" + source.split("pending_inputs() {\n", 1)[1].split(
        "\nread_pending_inputs() {", 1)[0]
    return subprocess.run(["bash", "-c", function + '\npending_inputs "$1"\n', "parse", mode],
                          input=text, capture_output=True, timeout=10)


IOS = r'''#!/usr/bin/env python3
import json, os, pathlib, shlex, sys
root = pathlib.Path(os.environ['TEST_ROOT'])
state_path = root / 'state.json'
state = json.loads(state_path.read_text())
commands = sys.stdin.read()
with (root / 'calls.jsonl').open('a') as output:
    output.write(json.dumps(commands) + '\n')
def directory():
    rows = ['Directory of bootflash:/guest-share/', '']
    for index, (name, kind) in enumerate(sorted(state['files'].items()), 1):
        rows.append(' %d %s 12 Oct 11 2026 12:00:00 +00:00 %s' %
                    (index, 'drwx' if kind == 'directory' else '-rw-', name))
    return '\n'.join(rows) + '\n1000000 bytes total (500000 bytes free)\n'
if 'show version' in commands:
    print('cisco C8000V (x86) processor\nProcessor board ID SERIAL')
elif commands == 'terminal width 512\ndir bootflash:guest-share\n':
    state['listings'] += 1
    if state.get('bad_listing') and state['listings'] == state.get('bad_at', 1):
        sys.stdout.write(state['bad_listing'])
    else:
        print('router#terminal width 512\nrouter#dir bootflash:guest-share')
        sys.stdout.write(directory())
        print('router#exit')
    state_path.write_text(json.dumps(state))
    raise SystemExit(state.get('listing_rc', 0))
elif '__IRIS_VERIFY_RUNNING__' in commands:
    print('__IRIS_VERIFY_RUNNING__\nend')
    print('__IRIS_VERIFY_APPS__\nApp id State')
    print('__IRIS_VERIFY_FILES__')
    sys.stdout.write(directory())
    print('%Error opening bootflash:/guest-share/iris (No such file or directory)')
    raise SystemExit(state.get('verification_rc', 0))
elif 'delete /force' in commands:
    for line in commands.splitlines():
        args = shlex.split(line)
        assert args[:2] == ['delete', '/force']
        assert args[-1].startswith('bootflash:guest-share/')
        name = args[-1].split('bootflash:guest-share/', 1)[1]
        assert '/' not in name and '*' not in name and '?' not in name
        if name not in state.get('keep', []):
            state['files'].pop(name, None)
    state_path.write_text(json.dumps(state))
elif 'copy running-config startup-config' in commands:
    (root / 'saved').touch()
    print('[OK]')
elif any(item in commands for item in ('configure terminal', 'guestshell disable',
                                      'guestshell destroy', 'show app-hosting list')):
    pass
else:
    raise SystemExit('unanticipated mock transport command')
'''


def run_script(tmp_path, *, files=None, **options):
    (tmp_path / "device").mkdir()
    (tmp_path / "lab").mkdir()
    shutil.copyfile(SCRIPT, tmp_path / "device/router-uninstall.sh")
    transport = tmp_path / "lab/device-run.sh"
    transport.write_text(IOS)
    transport.chmod(0o755)
    state = {"files": files if files is not None else {
        **{name: "file" for name in (*PENDING, *NAMES, *FOREIGN)}, "iris": "directory"},
        "listings": 0, **options}
    (tmp_path / "state.json").write_text(json.dumps(state))
    environment = {key: value for key, value in os.environ.items() if key not in (
        "IRIS_FORCE_AGENT_ONLY", "NETWORK_ATTACHMENT", "NAT_INTERFACE")}
    environment.update(TEST_ROOT=str(tmp_path), MANAGEMENT_TYPE="router-routed",
                       VPG_NUMBER="10", ROUTER_RESOURCES_OWNED="1",
                       EXPECTED_DEVICE_IDENTITY="SERIAL", DEVICE_IP="192.0.2.10",
                       DEVICE_USER="synthetic-user", DEVICE_PASS="synthetic-password")
    result = subprocess.run(["bash", str(tmp_path / "device/router-uninstall.sh")],
                            env=environment, capture_output=True, text=True, timeout=15)
    calls = [json.loads(line) for line in (tmp_path / "calls.jsonl").read_text().splitlines()]
    return result, calls, json.loads((tmp_path / "state.json").read_text())


def test_names_match_actual_eight_input_publisher():
    # Pin the actual publisher protocol, not a second invented name set.
    source = (ROOT / "device/bootstrap.sh").read_text()
    declaration = source.split("FILES = ", 1)[1].split("\n\n", 1)[0]
    assert tuple(name for name, _ in ast.literal_eval(declaration)) == NAMES
    result = parse(listing(row(name, index=i) for i, name in enumerate(PENDING, 1)).encode())
    assert result.returncode == 0, result.stderr
    assert result.stdout.decode().splitlines() == sorted(PENDING)


@pytest.mark.parametrize("text", [
    b"", b"unrelated successful SSH output\n",
    listing().replace("router#exit\n", "").encode(),
    listing().replace("1000000 bytes total (500000 bytes free)\n", "").encode(),
    listing().replace("Directory of bootflash:/guest-share/", "Directory of bootflash:/other/").encode(),
    ("router#dir bootflash:guest-share\n" + listing()).encode(),
    (listing() + "router#exit\n").encode(),
    listing().replace("1000000 bytes total", "router#exit\n1000000 bytes total").encode(),
    listing().replace("Directory of bootflash:/guest-share/", "Directory of bootflash:/guest-share/\nDirectory of bootflash:/guest-share/").encode(),
    listing().replace("1000000 bytes total (500000 bytes free)", "1000000 bytes total (500000 bytes free)\n1000000 bytes total (500000 bytes free)").encode(),
    ("x" * 262145).encode(), ("\n" * 4097 + listing()).encode(),
    listing([row(PENDING[0]) + "\x00"]).encode(), b"\xff" + listing().encode(),
    listing().replace("router#exit", "another#exit").encode(),
    listing().replace("router#exit", "router>").encode(),
    (listing() + "unparsed remainder\n").encode(),
    listing().replace("router#dir bootflash:guest-share", "router#dir bootflash:guest-share/other").encode(),
    listing().replace("router#dir bootflash:guest-share", "router#dir bootflash:guest-share suffix").encode(),
    listing().replace("router#dir bootflash:guest-share", "untrusted prefix router#dir bootflash:guest-share").encode(),
    ("router#echo __IRIS_PENDING_BEGIN__\n% Invalid input detected at marker.\n"
     "Directory of bootflash:/guest-share/\n1000000 bytes total (500000 bytes free)\n"
     "router#echo __IRIS_PENDING_END__\n% Invalid input detected at marker.\nrouter#exit\n").encode(),
    listing().replace("1000000 bytes total (500000 bytes free)\n", "1000000 bytes total (500000 bytes free)\n" + row(PENDING[0]) + "\n").encode(),
], ids=("missing", "unrelated", "no-end", "no-footer", "wrong-directory",
        "duplicate-command", "duplicate-prompt", "early-prompt", "duplicate-header",
        "duplicate-footer", "oversized", "too-many-lines", "nul", "non-ascii",
        "wrong-prompt", "unprivileged-prompt", "trailing-content", "path-suffix",
        "command-suffix", "command-prefix", "unsupported-ios-echo", "row-after-footer"))
def test_parser_refuses_missing_truncated_oversized_or_ambiguous_listing(text):
    result = parse(text)
    assert result.returncode != 0
    assert result.stdout == b""
    assert result.stderr == b"ERROR: could not identify IRIS pending inputs safely\n"


@pytest.mark.parametrize("rows", [
    [row(PENDING[0]), row(PENDING[0], index=2)],
    [row(PENDING[0], mode="drwx")], [row(PENDING[0], mode="lrwx")],
    [row(PENDING[0], size="unknown")], ["not-a-row " + PENDING[0]],
    [row(f".iris-upload-{i:032x}-bootstrap.sh", index=i + 1) for i in range(129)],
])
def test_parser_refuses_ambiguous_or_nonregular_owned_leaf(rows):
    result = parse(listing(rows).encode())
    assert result.returncode != 0 and result.stdout == b""


def test_parser_preserves_foreign_lookalikes_and_accepts_empty_or_missing_directory():
    for text in (listing(row(name) for name in FOREIGN), listing(),
                 "router#dir bootflash:guest-share\n%Error opening bootflash:/guest-share (No such file or directory)\nrouter#exit\n"):
        result = parse(text.encode())
        assert result.returncode == 0 and result.stdout == b"", result.stderr


def test_parser_final_mode_includes_exact_root_inputs_without_foreign_substrings():
    raw = listing(row(name, index=i) for i, name in enumerate((*NAMES, *PENDING, *FOREIGN), 1)).encode()
    result = parse(raw, "all")
    assert result.returncode == 0, result.stderr
    assert result.stdout.decode().splitlines() == sorted((*NAMES, *PENDING))
    assert parse(raw, "arbitrary").returncode != 0


def test_parser_accepts_actual_crlf_plain_return_prompt_and_maximum_owned_set():
    names = tuple(f".iris-upload-{i:032x}-{name}" for i in range(16) for name in NAMES)
    raw = listing(row(name, index=i) for i, name in enumerate(names, 1)).replace(
        "router#exit", "router#").replace("\n", "\r\n").encode()
    result = parse(raw)
    assert result.returncode == 0 and result.stdout.decode().splitlines() == sorted(names)


def test_real_script_removes_only_exact_owned_leaves_and_finally_preserves_foreign(tmp_path):
    result, calls, state = run_script(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert state["files"] == {name: "file" for name in FOREIGN}
    deletes = [line for call in calls for line in call.splitlines() if line.startswith("delete ")]
    assert set(deletes) == {"delete /force /recursive bootflash:guest-share/iris", *(
        "delete /force bootflash:guest-share/" + name for name in (*NAMES, *PENDING))}
    assert len(deletes) == len(set(deletes))
    assert state["listings"] == 2 and (tmp_path / "saved").exists()
    assert calls.index("terminal width 512\ndir bootflash:guest-share\n") < calls.index(
        next(call for call in calls if "configure terminal" in call))


@pytest.mark.parametrize("options", [
    {"bad_listing": "truncated\n"}, {"listing_rc": 7},
    {"files": {PENDING[0]: "directory"}},
])
def test_real_script_refuses_before_any_mutation_when_census_is_not_proven(tmp_path, options):
    result, calls, _ = run_script(tmp_path, **options)
    assert result.returncode != 0
    assert all(not any(word in call for word in ("configure terminal", "delete /force", "guestshell disable",
                                                "guestshell destroy", "copy running-config")) for call in calls)
    assert not (tmp_path / "saved").exists()


@pytest.mark.parametrize("options", [
    {"keep": [PENDING[0]]}, {"bad_listing": "truncated\n", "bad_at": 2},
])
def test_real_script_requires_independent_complete_pending_absence_without_retry(tmp_path, options):
    result, calls, _ = run_script(tmp_path, **options)
    assert result.returncode != 0
    assert sum("delete /force" in call for call in calls) == 1
    assert not (tmp_path / "saved").exists()


def test_real_script_still_refuses_exact_final_input_residue(tmp_path):
    result, calls, state = run_script(tmp_path, files={"rpc-secret": "file"}, keep=["rpc-secret"])
    assert result.returncode != 0
    assert "inputs remain after undeploy" in result.stderr
    assert state["files"] == {"rpc-secret": "file"}
    assert sum("delete /force" in call for call in calls) == 1
    assert not (tmp_path / "saved").exists()


def test_real_script_rejects_valid_final_output_with_failed_transport(tmp_path):
    result, calls, state = run_script(tmp_path, verification_rc=7)
    assert result.returncode != 0
    assert "undeploy verify session failed" in result.stderr
    assert "undeploy complete" not in result.stdout
    assert state["files"] == {name: "file" for name in FOREIGN}
    assert sum("__IRIS_VERIFY_RUNNING__" in call for call in calls) == 1
    assert not (tmp_path / "saved").exists()
