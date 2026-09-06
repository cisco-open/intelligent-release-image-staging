# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace

import iris_agent


def test_adoption_reads_ios_root_when_guestshell_only_mounts_guest_share():
    """The C9300's /flash root belongs to its container, not IOS flash:."""
    filename = "cat9k.bin"
    image = {"filename": filename, "size": 5, "sha256": "a" * 64,
             "sha512": "b" * 128}
    ios_files = {filename: 5, filename + ".iris-tmp": 5}
    hashed, deleted, emitted = [], [], []

    def reclaim(prefix, names):
        deleted.extend(names)
        for name in names:
            ios_files.pop(name)

    deps = SimpleNamespace(
        # Actual mount shape observed on C9300: there is no local root image.
        file_size=lambda path: None,
        verify=lambda *args: False,
        root_file_size=lambda name, prefix: ios_files.get(name),
        verify_root=lambda name, prefix, digest: hashed.append(
            (name, prefix, digest)) or True,
        running_image=lambda: "packages.conf",
        boot_image=lambda: "packages.conf",
        reclaim_bundle=reclaim,
        emit=lambda *args: emitted.append(args),
    )
    assert iris_agent._try_adopt_guestshell_root(
        {"stage_dir": "/flash/guest-share/iris"}, deps, image, "flash:"
    ) == ("adopted", None)
    assert hashed == [(filename, "flash:", image["sha512"])]
    assert ios_files == {filename: 5}
    assert deleted == [filename + ".iris-tmp"]


import fcntl
import json
from pathlib import Path
import re

import pytest


DIGEST = "b" * 128
ROOT = "flash:cat9k.bin"
HASH_OUTPUT = "....Done!\nverify /sha512 (" + ROOT + ") = " + DIGEST + "\n"


@pytest.mark.parametrize("listing, expected", [
    ("Directory of flash:/cat9k.bin\n123 -rw- 5 Sep 1 2026 cat9k.bin\n", 5),
    ("%Error opening flash:cat9k.bin (No such file or directory)\n", None),
    ("%Error opening flash:/cat9k.bin (No such file or directory)\n", None),
])
def test_native_size_requires_a_real_file_row_or_exact_missing_path(listing, expected):
    commands = []
    assert iris_agent._ios_root_file_size("cat9k.bin", "flash:",
        lambda command: commands.append(command) or listing) == expected
    assert commands == ["dir " + ROOT]


@pytest.mark.parametrize("listing", [
    "", None, "%Error opening flash:cat9k.bin (Permission denied)",
    "%Error opening flash:other.bin (No such file or directory)",
    "123 drw- 5 Sep 1 2026 cat9k.bin\n",
    "123 -rw- 5 Sep 1 2026 cat9k.bin.backup\n",
    "%Error opening flash:cat9k.bin (No such file or directory)\n"
    "123 -rw- 5 Sep 1 2026 cat9k.bin\n",
])
def test_unknown_native_directory_output_never_means_absence(listing):
    with pytest.raises(ValueError):
        iris_agent._ios_root_file_size("cat9k.bin", "flash:", lambda _: listing)


@pytest.mark.parametrize("output", [
    HASH_OUTPUT.replace("cat9k.bin", "other.bin"),
    HASH_OUTPUT.replace("flash:", "bootflash:"),
    HASH_OUTPUT.replace(DIGEST, DIGEST[:-1]),
    HASH_OUTPUT + HASH_OUTPUT,
    HASH_OUTPUT + HASH_OUTPUT.replace("cat9k.bin", "other.bin"),
    HASH_OUTPUT + "%Error reading file\n",
    "verify /sha512 (flash:cat9k.bin) = " + DIGEST + " extra\n",
])
def test_native_hash_response_rejects_ambiguous_or_wrong_file_proof(output):
    with pytest.raises(ValueError):
        iris_agent._parse_ios_sha512(output, ROOT)


def native_hash_harness(tmp_path, monkeypatch, output=HASH_OUTPUT, complete=True,
                        cleanup_error=False, launch_error=False, marker="complete"):
    # Exercise the production lock, durable lease, fresh receipt and poll path
    # on a temporary share; the canonical IOS/local mapping is tested separately.
    monkeypatch.setattr(iris_agent, "_guestshell_root_ios_path", lambda *args: ROOT)
    clock = [1000.0]
    monkeypatch.setattr(iris_agent.time, "time", lambda: clock[0])
    calls = []

    def configure(lines):
        calls.append(lines)
        if len(lines) == 1:
            if cleanup_error:
                raise OSError("policy cleanup failed")
            return
        if launch_error:
            raise OSError("policy launch result lost")
        match = re.search(r"/([^/]+)/result w$", lines[5])
        directory = tmp_path / match.group(1)
        assert directory.is_dir()
        if complete:
            (directory / "result").write_text(output)
            (directory / "done").write_text(marker)

    def sleep(seconds):
        clock[0] += seconds

    def verify():
        return iris_agent._verify_guestshell_root(
            "cat9k.bin", "flash:", DIGEST, str(tmp_path), configure,
            sleep_fn=sleep, poll_attempts=2, poll_interval_s=5)

    return verify, calls, clock


def test_native_hash_uses_fresh_receipt_and_only_read_only_ios_hash(tmp_path, monkeypatch):
    verify, calls, _ = native_hash_harness(tmp_path, monkeypatch)
    assert verify() is True
    assert verify() is True
    first, second = calls[0], calls[2]
    assert first[2] == "event timer countdown time 2 maxrun 600"
    assert first[4] == 'action 020 cli command "verify /sha512 flash:cat9k.bin"'
    assert first[5] != second[5]   # a stale receipt cannot prove a later request
    commands = "\n".join(first)
    assert 'cli command "copy' not in commands
    assert 'cli command "delete' not in commands
    assert "IRIS-COPYROOT" not in commands
    assert calls[1] == calls[3] == ["no event manager applet IRIS-ROOT-HASH"]
    assert not list(tmp_path.glob(".iris-root-hash-*/"))
    assert json.loads((tmp_path / ".iris-root-hash.json").read_text()) == {}


def test_native_hash_compares_actual_digest_with_catalog(tmp_path, monkeypatch):
    verify, _, _ = native_hash_harness(
        tmp_path, monkeypatch, output=HASH_OUTPUT.replace(DIGEST, "c" * 128))
    assert verify() is False


@pytest.mark.parametrize("marker", ["complete", "complete\n", "complete\r\n"])
def test_native_completion_marker_accepts_ios_line_endings(tmp_path, monkeypatch, marker):
    verify, _, _ = native_hash_harness(tmp_path, monkeypatch, marker=marker)
    assert verify() is True


@pytest.mark.parametrize("marker", ["", "complet", "completeX", "complete\nextra"])
def test_partial_or_ambiguous_native_completion_marker_is_not_proof(tmp_path, monkeypatch, marker):
    verify, _, _ = native_hash_harness(tmp_path, monkeypatch, marker=marker)
    with pytest.raises(TimeoutError):
        verify()


def test_native_hash_timeout_retains_lease_until_native_budget_expires(tmp_path, monkeypatch):
    verify, calls, clock = native_hash_harness(tmp_path, monkeypatch, complete=False)
    with pytest.raises(TimeoutError):
        verify()
    assert len(calls) == 2
    assert not list(tmp_path.glob(".iris-root-hash-*/"))
    with pytest.raises(RuntimeError, match="may still be running"):
        verify()
    assert len(calls) == 2  # no overlapping job after a short caller timeout
    clock[0] = 1626
    with pytest.raises(TimeoutError):
        verify()
    assert len(calls) == 4


def test_native_hash_does_not_accept_stale_receipt_after_timeout(tmp_path, monkeypatch):
    old = tmp_path / ".iris-root-hash-old"
    old.mkdir()
    (old / "result").write_text(HASH_OUTPUT)
    (old / "done").write_text("complete")
    verify, _, _ = native_hash_harness(tmp_path, monkeypatch, complete=False)
    with pytest.raises(TimeoutError):
        verify()
    assert old.is_dir()  # caller cleans only the directory it created


def test_native_hash_cleanup_failure_refuses_even_matching_proof(tmp_path, monkeypatch):
    verify, calls, _ = native_hash_harness(tmp_path, monkeypatch, cleanup_error=True)
    with pytest.raises(OSError, match="cleanup failed"):
        verify()
    with pytest.raises(RuntimeError, match="may still be running"):
        verify()
    assert len(calls) == 2


def test_unknown_launch_state_cannot_start_another_native_job(tmp_path, monkeypatch):
    verify, calls, clock = native_hash_harness(tmp_path, monkeypatch, launch_error=True)
    with pytest.raises(OSError, match="launch result lost"):
        verify()
    clock[0] += 3600
    with pytest.raises(RuntimeError, match="launch is unconfirmed"):
        verify()
    assert len(calls) == 2


def test_parallel_native_hash_invocations_are_serialized(tmp_path, monkeypatch):
    verify, calls, _ = native_hash_harness(tmp_path, monkeypatch)
    with (tmp_path / ".iris-root-hash.lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(RuntimeError, match="another IOS root hash"):
            verify()
    assert calls == []


@pytest.mark.parametrize("boot, running", [
    ("cat9k.bin.iris-tmp", "packages.conf"),
    ("packages.conf", "cat9k.bin.iris-tmp"),
    (None, "packages.conf"),
    ("packages.conf", None),
])
def test_attested_root_never_authorizes_reclaim_of_boot_or_unknown_target(boot, running):
    deleted = []
    deps = SimpleNamespace(
        root_file_size=lambda *args: 5,
        verify_root=lambda *args: True,
        running_image=lambda: running,
        boot_image=lambda: boot,
        reclaim_bundle=lambda prefix, names: deleted.extend(names),
        emit=lambda *args: None,
    )
    result, error = iris_agent._try_adopt_guestshell_root(
        {"stage_dir": "/flash/guest-share/iris"}, deps,
        {"filename": "cat9k.bin", "size": 5, "sha512": DIGEST}, "flash:")
    assert result == "blocked"
    assert "cleanup must succeed" in error
    assert deleted == []


@pytest.mark.parametrize("after_size", [None, 4, 6])
def test_root_size_must_still_match_after_hash_before_temp_reclaim(after_size):
    sizes = iter([5, after_size])
    deleted = []
    deps = SimpleNamespace(
        root_file_size=lambda *args: next(sizes),
        verify_root=lambda *args: True,
        reclaim_bundle=lambda *args: deleted.append(args),
        emit=lambda *args: None,
    )
    result, error = iris_agent._try_adopt_guestshell_root(
        {"stage_dir": "/flash/guest-share/iris"}, deps,
        {"filename": "cat9k.bin", "size": 5, "sha512": DIGEST}, "flash:")
    assert result == "blocked"
    assert "size changed" in error
    assert deleted == []


def test_failed_slow_hash_backoff_starts_after_completion(monkeypatch):
    from test_iris_agent import CFG, FakeCatalog, make_deps
    clock = [1000.0]
    monkeypatch.setattr(iris_agent.time, "time", lambda: clock[0])
    cfg = dict(CFG, stage_dir="/flash/guest-share/iris")
    image = {"id": "img1", "filename": "cat9k.bin", "size": 5,
             "sha256": "abc", "sha512": DIGEST}
    catalog = FakeCatalog({"approved_image_id": "img1"}, image)
    deps, _, _, _, copied, _, _, reclaimed = make_deps(
        catalog, {cfg["stage_dir"] + "/cat9k.bin": 5, ROOT: 5}, free=0)
    hashed = []

    def slow_hash(*args):
        hashed.append(args)
        clock[0] += 600
        return False

    deps = deps._replace(verify_root=slow_hash)
    state = {}
    assert iris_agent.run_once(cfg, deps, state) == "complete"
    assert state["img1"]["copy_next_ts"] == 1900
    clock[0] = 1660
    assert iris_agent.run_once(cfg, deps, state) == "complete"
    assert len(hashed) == 1
    assert copied == [] and reclaimed == []
