# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Instruction cache reads must never follow links or wait on special files."""
import errno
import os
from pathlib import Path
import subprocess
import sys

import pytest

import instr


def test_regular_instruction_read_is_bounded_and_missing_is_explicit(tmp_path):
    path = tmp_path / "cache"
    assert instr._read_bytes(str(path), 4) is None
    path.write_bytes(b"abcd")
    assert instr._read_bytes(str(path), 4) == b"abcd"
    path.write_bytes(b"abcde")
    with pytest.raises(instr.InstructionError) as caught:
        instr._read_bytes(str(path), 4)
    assert caught.value.state == "oversize"


@pytest.mark.parametrize("dangling", [False, True])
def test_instruction_read_refuses_symlink_even_when_target_is_missing(tmp_path, dangling):
    target = tmp_path / "outside"
    if not dangling:
        target.write_bytes(b"must not be read")
    path = tmp_path / "cache"
    path.symlink_to(target)
    with pytest.raises(OSError):
        instr._read_bytes(str(path), 1024)


def test_instruction_fifo_cannot_block_the_agent_tick(tmp_path):
    path = tmp_path / "cache"
    os.mkfifo(path)
    # A separate process bounds the regression itself: the old blocking open
    # must fail this test, not leave a hung thread in the pytest worker.
    program = """
import sys
sys.path.insert(0, sys.argv[1])
import instr
try:
    instr._read_bytes(sys.argv[2], 1024)
except OSError:
    sys.exit(0)
sys.exit(1)
"""
    result = subprocess.run(
        [sys.executable, "-c", program, str(Path(instr.__file__).parent), str(path)],
        capture_output=True, timeout=3)
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.parametrize("filename", [
    "iris-instructions.lkg", "iris-instructions.lkg.previous",
    "iris-instruction-keylist.current", "iris-instruction-keylist-state.json",
])
def test_instruction_step_contains_special_file_without_changing_accepted_state(tmp_path, filename):
    path = tmp_path / filename
    os.mkfifo(path)
    program = """
import sys
sys.path.insert(0, sys.argv[1])
import instr
state = {'instructions': {'accepted_epoch': 9, 'accepted_serial': 4}}
writes = []
result = instr.run_instruction_step(
    cfg={'device_id': 'device-1'}, state=state, catalog=object(), hints={},
    catalog_date=None, platform='iox', work_dir=sys.argv[2], boot_id='test-boot',
    monotonic_now=1, verifier=object(), persist_config=writes.append,
    emit=lambda *args: None, cache_only=True)
assert result['instruction'] is None
assert result['attestation']['instr_state'] in ('instr_unavailable', 'lkg_rejected')
assert result['effective_peers'] == {'mode': 'tracker-only', 'include_origin': False}
assert state['instructions']['accepted_epoch'] == 9
assert state['instructions']['accepted_serial'] == 4
assert not writes
"""
    result = subprocess.run(
        [sys.executable, "-c", program, str(Path(instr.__file__).parent), str(tmp_path)],
        capture_output=True, timeout=3)
    assert result.returncode == 0, result.stderr.decode()
    assert path.exists()


def test_instruction_read_refuses_directory(tmp_path):
    with pytest.raises(OSError):
        instr._read_bytes(str(tmp_path), 1024)


def test_instruction_read_fails_closed_without_nofollow(tmp_path, monkeypatch):
    path = tmp_path / "cache"
    path.write_bytes(b"abcd")
    monkeypatch.delattr(instr.os, "O_NOFOLLOW")
    with pytest.raises(OSError):
        instr._read_bytes(str(path), 4)


def test_instruction_read_rejects_file_changed_during_read(tmp_path, monkeypatch):
    path = tmp_path / "cache"
    path.write_bytes(b"abcd")
    real_read = os.read
    changed = []

    def racing_read(fd, size):
        value = real_read(fd, size)
        if not changed:
            changed.append(True)
            path.write_bytes(b"wxyz")
            current = path.stat()
            os.utime(path, ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000_000))
        return value

    monkeypatch.setattr(instr.os, "read", racing_read)
    with pytest.raises(OSError) as caught:
        instr._read_bytes(str(path), 4)
    assert caught.value.errno == errno.ESTALE


def test_instruction_read_requires_nonblocking_open(tmp_path, monkeypatch):
    path = tmp_path / "cache"
    path.write_bytes(b"abcd")
    real_open = os.open
    flags_seen = []

    def checked_open(pathname, flags, *args, **kwargs):
        flags_seen.append(flags)
        return real_open(pathname, flags, *args, **kwargs)

    monkeypatch.setattr(instr.os, "open", checked_open)
    assert instr._read_bytes(str(path), 4) == b"abcd"
    assert len(flags_seen) == 1
    assert flags_seen[0] & os.O_NOFOLLOW
    assert flags_seen[0] & os.O_NONBLOCK
