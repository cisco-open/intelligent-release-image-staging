# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Task 16 — durable agent checkpoints.

`_atomic_write_state(path, state)` factors the existing tmp+fsync+rename+
dir-fsync state writer out of main() with unchanged behavior, and
`Deps.checkpoint(state)` invokes it so run_once can persist identity/sequence
facts BEFORE any network side effect that must survive a crash.
"""
import errno
import json
import os
import stat

import iris_agent


def test_atomic_write_state_persists_and_reads_back(tmp_path):
    path = str(tmp_path / "iris-agent.state")
    state = {"image_id": "img", "n": 42}
    iris_agent._atomic_write_state(path, state)
    with open(path) as f:
        assert json.load(f) == state
    # no temp file left behind
    assert not os.path.exists(path + ".tmp")


def test_atomic_write_state_replaces_existing(tmp_path):
    path = str(tmp_path / "iris-agent.state")
    iris_agent._atomic_write_state(path, {"v": 1})
    iris_agent._atomic_write_state(path, {"v": 2})
    with open(path) as f:
        assert json.load(f) == {"v": 2}


def test_atomic_write_state_fsyncs_bytes_and_dir(tmp_path, monkeypatch):
    path = str(tmp_path / "iris-agent.state")
    fsynced = []
    real_fsync = os.fsync
    monkeypatch.setattr(os, "fsync",
                        lambda fd: fsynced.append(fd) or real_fsync(fd))
    iris_agent._atomic_write_state(path, {"a": 1})
    # both the file descriptor and the directory fd were fsynced
    assert len(fsynced) >= 2


def test_atomic_write_state_tolerates_unsupported_dir_fsync(tmp_path,
                                                            monkeypatch):
    path = str(tmp_path / "iris-agent.state")
    real_fsync = os.fsync
    seen = {"dir": False}

    def fake_fsync(fd):
        # the directory fd is the second/last fsync; simulate a filesystem
        # that does not implement directory fsync (EINVAL) on it.
        try:
            os.fstat(fd)
        except OSError:
            pass
        # Distinguish the dir fd: it was opened O_RDONLY on a directory.
        st = os.fstat(fd)
        if stat.S_ISDIR(st.st_mode):
            seen["dir"] = True
            raise OSError(errno.EINVAL, "no dir fsync")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fake_fsync)
    # must NOT raise despite the unsupported dir fsync
    iris_agent._atomic_write_state(path, {"a": 1})
    assert seen["dir"] is True
    with open(path) as f:
        assert json.load(f) == {"a": 1}


def test_atomic_write_state_reraises_real_dir_fsync_error(tmp_path,
                                                          monkeypatch):
    path = str(tmp_path / "iris-agent.state")
    real_fsync = os.fsync

    def fake_fsync(fd):
        st = os.fstat(fd)
        if stat.S_ISDIR(st.st_mode):
            raise OSError(errno.EIO, "real io error")
        return real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fake_fsync)
    try:
        iris_agent._atomic_write_state(path, {"a": 1})
        raised = False
    except OSError:
        raised = True
    assert raised is True


def test_deps_has_checkpoint_field():
    assert "checkpoint" in iris_agent.Deps._fields


def test_checkpoint_invokes_atomic_write(tmp_path):
    """A real-deps-style checkpoint wired to a state path persists the state."""
    path = str(tmp_path / "iris-agent.state")
    checkpoint = lambda state: iris_agent._atomic_write_state(path, state)
    checkpoint({"image_id": "img", "seq": 3})
    with open(path) as f:
        assert json.load(f)["seq"] == 3


class _Deps:
    def __init__(self, checkpoint=None):
        self.checkpoint = checkpoint
        self.emitted = []

    def emit(self, tag, msg):
        self.emitted.append((tag, msg))


def test_checkpoint_or_skip_true_on_success():
    saved = []
    deps = _Deps(checkpoint=lambda s: saved.append(s))
    assert iris_agent._checkpoint_or_skip(deps, {"a": 1}, "T", "d") is True
    assert saved == [{"a": 1}]


def test_checkpoint_or_skip_false_when_checkpoint_missing():
    deps = _Deps(checkpoint=None)
    assert iris_agent._checkpoint_or_skip(deps, {"a": 1}, "T", "d") is False


def test_checkpoint_exception_prevents_post():
    def boom(_state):
        raise OSError("disk full")

    deps = _Deps(checkpoint=boom)
    # A failed checkpoint returns False so the caller MUST NOT POST, and it is
    # logged rather than raised (never unwinds the tick).
    assert iris_agent._checkpoint_or_skip(deps, {"a": 1}, "CKPT", "det") is False
    assert deps.emitted and deps.emitted[0][0] == "CKPT"
