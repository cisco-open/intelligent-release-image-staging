# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Workstream B transport red freeze.

Binding SHA256:
900586ec0b987b7e9c6751e614d1fa7505eaf2838fcbf77b5cdf9cd054cb5094

Only test adapters below name implementation helpers. Product imports are lazy:
an absent implementation is a test failure, never a collection failure or skip.
The approved adapter seams are IoxTransport(config, transcript, supervisor,
monotonic_fn=None), admit_wrapper(...), _StreamingRedactor.feed/finish,
_encode_frame, _FrameReader.read, and _TranscriptWriter.append/reference.

All archives, peers, credentials, and process trees are tiny temporary fixtures.
The fake SSH executable implements receipt-dependent dialogue; sending commands
early is observable. supervisor=None means the isolated transport owns/reaps its
own children. The crash suite covers the production supervisor and durable fence.
"""

import base64
import errno
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import tarfile
import threading
import time

import pytest


ATTEMPT = "a" * 32
CONTROLLER = "c" * 32
TRANSACTION = "d" * 32
AT = 1788868800
BOARD = "TESTSERIAL0001"
VERIFY = b"show app-hosting infra"


def _module():
    return importlib.import_module("iox_transport")


def test_decision_five_published_wrapper_and_archive_limits_are_exact():
    module = _module()
    expected = {
        "WRAPPER_MAX_BYTES": 256 * 1024 * 1024,
        "WRAPPER_COPY_CHUNK_BYTES": 1024 * 1024,
        "WRAPPER_COPY_MAX_SECONDS": 120,
        "ARCHIVE_MAX_MEMBERS": 4096,
        "ARCHIVE_MAX_NAME_BYTES": 4096,
        "ARCHIVE_MAX_MARKERS_PER_KIND": 1,
        "ARCHIVE_SCAN_WALL_SECONDS": 15,
        "ARCHIVE_SCAN_CPU_SECONDS": 10,
        "ARCHIVE_SCAN_ADDRESS_SPACE_BYTES": 512 * 1024 * 1024,
        "ARCHIVE_SCAN_RESULT_BYTES": 4096,
        "ARCHIVE_TRAILER_MIN_BYTES": 1024,
    }
    assert {name: getattr(module, name) for name in expected} == expected


def _failure():
    # Resolve outside pytest.raises so a missing module never passes a refusal.
    _module()
    return pytest.raises(Exception)


def _category(error):
    return error.value.category


def _value(result, field):
    return result[field] if isinstance(result, dict) else getattr(result, field)


def _admit(path, snapshot_dir, cancel=None, deadline=None, clock=None):
    return _module().admit_wrapper(
        str(path), str(snapshot_dir),
        time.monotonic() + 3 if deadline is None else deadline,
        threading.Event() if cancel is None else cancel,
        monotonic_fn=clock,
    )


def _octal(value, size):
    return ("%0*o" % (size - 1, value)).encode("ascii") + b"\0"


def _checksum(header):
    result = bytearray(header)
    result[148:156] = b" " * 8
    result[148:156] = ("%06o\0 " % sum(result)).encode("ascii")
    return bytes(result)


def _member(name=b"package.yaml", payload=b"test", kind=b"0", prefix=b"",
            version="ustar", overrides=None):
    """A raw header builder, deliberately independent of the product scanner."""
    header = bytearray(512)
    header[0:100] = name.ljust(100, b"\0")
    for start, end, value in ((100, 108, 384), (108, 116, 0),
                              (116, 124, 0), (124, 136, len(payload)),
                              (136, 148, 1)):
        header[start:end] = _octal(value, end - start)
    header[156:157] = kind
    if version == "ustar":
        header[257:265] = b"ustar\x0000"
        header[329:337] = _octal(0, 8)
        header[337:345] = _octal(0, 8)
        header[345:500] = prefix.ljust(155, b"\0")
    for start, end, value in overrides or ():
        header[start:end] = value
    assert len(header) == 512
    return _checksum(header) + payload + b"\0" * (-len(payload) % 512)


def _archive(*members):
    return b"".join(members) + b"\0" * 1024


def _wrapper(tmp_path, data=None):
    path = tmp_path / "wrapper.tar"
    path.write_bytes(_archive(_member()) if data is None else data)
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir(mode=448, exist_ok=True)
    return path, snapshots


def _read_fd(fd):
    position = os.lseek(fd, 0, os.SEEK_CUR)
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    while True:
        chunk = os.read(fd, 4096)
        if not chunk:
            break
        chunks.append(chunk)
    os.lseek(fd, position, os.SEEK_SET)
    return b"".join(chunks)


def _assert_closed(fd):
    with pytest.raises(OSError) as error:
        os.fstat(fd)
    assert error.value.errno == errno.EBADF


@pytest.mark.parametrize("version", ["v7", "ustar"])
def test_admits_minimal_v7_and_ustar_without_extracting(tmp_path, version):
    data = _archive(_member(version=version))
    path, snapshots = _wrapper(tmp_path, data)
    with _admit(path, snapshots) as snapshot:
        fd = snapshot.fd
        assert snapshot.sha256 == hashlib.sha256(data).hexdigest()
        assert snapshot.package_sign_present is False
        assert snapshot.package_cert_present is False
        assert _read_fd(fd) == data
        assert stat.S_ISREG(os.fstat(fd).st_mode)
        assert stat.S_IMODE(os.fstat(fd).st_mode) == 384
        assert os.fstat(fd).st_nlink == 0
        import fcntl
        assert fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        assert list(snapshots.iterdir()) == []
    _assert_closed(fd)


@pytest.mark.parametrize("marker_names,expected", [
    ([], (False, False)),
    ([b"package.sign"], (True, False)),
    ([b"nested/package.cert"], (False, True)),
    ([b"one/package.sign", b"two/package.cert"], (True, True)),
    ([b"PACKAGE.SIGN", b"package.sign.bak"], (False, False)),
])
def test_marker_presence_is_two_exact_outer_regular_basenames(
        tmp_path, marker_names, expected):
    members = [_member(name=name) for name in marker_names] or [_member()]
    path, snapshots = _wrapper(tmp_path, _archive(*members))
    with _admit(path, snapshots) as snapshot:
        assert (snapshot.package_sign_present,
                snapshot.package_cert_present) == expected


def test_current_wrapper_shape_keeps_compressed_nested_payload_opaque(tmp_path):
    nested = io.BytesIO()
    with tarfile.open(fileobj=nested, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
        entry = tarfile.TarInfo("package.sign")
        entry.size = 5
        tar.addfile(entry, io.BytesIO(b"inner"))
    members = [_member(name=name, payload=b"fixture") for name in
               (b"package.yaml", b"artifacts.mf", b".package.metadata", b"package.mf")]
    members.append(_member(name=b"artifacts.tar.gz", payload=nested.getvalue()))
    path, snapshots = _wrapper(tmp_path, _archive(*members))
    with _admit(path, snapshots) as snapshot:
        assert snapshot.package_sign_present is False
        assert snapshot.package_cert_present is False
    assert sorted(item.name for item in tmp_path.iterdir()) == ["snapshots", "wrapper.tar"]


def test_marker_named_directory_does_not_claim_signature(tmp_path):
    path, snapshots = _wrapper(tmp_path, _archive(
        _member(b"package.sign/", payload=b"", kind=b"5")))
    with _admit(path, snapshots) as snapshot:
        assert snapshot.package_sign_present is False


def test_snapshot_survives_source_replacement_and_in_place_rewrite(tmp_path):
    data = _archive(_member(payload=b"original"))
    path, snapshots = _wrapper(tmp_path, data)
    with _admit(path, snapshots) as snapshot:
        path.write_bytes(_archive(_member(payload=b"changed")))
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"not even a tar")
        os.replace(str(replacement), str(path))
        assert _read_fd(snapshot.fd) == data
        assert snapshot.sha256 == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("shape", ["symlink", "directory", "fifo", "socket"])
def test_nonregular_admission_is_immediate_and_leaves_no_snapshot(tmp_path, monkeypatch, shape):
    _module()
    path, snapshots = _wrapper(tmp_path)
    path.unlink()
    sock = None
    if shape == "symlink":
        target = tmp_path / "target"
        target.write_bytes(_archive(_member()))
        path.symlink_to(target)
    elif shape == "directory":
        path.mkdir()
    elif shape == "fifo":
        os.mkfifo(str(path))
    else:
        sock = socket.socket(socket.AF_UNIX)
        sock.bind(str(path))
    original_open = os.open

    def checked_open(name, flags, *args, **kwargs):
        if os.fspath(name) == str(path):
            assert flags & os.O_NONBLOCK, "FIFO inspection must not block in open"
            assert flags & os.O_NOFOLLOW
        return original_open(name, flags, *args, **kwargs)
    monkeypatch.setattr(os, "open", checked_open)
    started = time.monotonic()
    try:
        with _failure() as error:
            with _admit(path, snapshots):
                pytest.fail("nonregular source admitted")
        assert _category(error) in ("wrapper_not_regular", "wrapper_unreadable")
        assert time.monotonic() - started < 1.0
        assert list(snapshots.iterdir()) == []
    finally:
        if sock is not None:
            sock.close()


def test_wrapper_size_cap_uses_injected_small_bound(tmp_path, monkeypatch):
    path, snapshots = _wrapper(tmp_path)
    monkeypatch.setattr(_module(), "WRAPPER_MAX_BYTES", path.stat().st_size - 1)
    with _failure() as error:
        with _admit(path, snapshots):
            pytest.fail("oversized wrapper admitted")
    assert _category(error) == "wrapper_oversize"
    assert list(snapshots.iterdir()) == []


@pytest.mark.parametrize("cancelled", [False, True])
def test_wrapper_admission_honors_cancellation_and_original_deadline(tmp_path, cancelled):
    path, snapshots = _wrapper(tmp_path)
    cancel = threading.Event()
    if cancelled:
        cancel.set()
    with _failure() as error:
        with _admit(path, snapshots, cancel, 9.0 if not cancelled else 20.0,
                    lambda: 10.0):
            pytest.fail("expired or cancelled copy admitted")
    assert _category(error) == ("cancelled" if cancelled else "wrapper_copy_timeout")
    assert list(snapshots.iterdir()) == []


@pytest.mark.parametrize("name", [
    b"/absolute", b"../escape", b"a/../escape", b"a/./b", b"a//b",
    b"a\\b", b"a\nb", b"a\tb", b"", b"file/", b"\xff",
])
def test_scanner_rejects_unsafe_names(tmp_path, name):
    path, snapshots = _wrapper(tmp_path, _archive(_member(name)))
    with _failure() as error:
        with _admit(path, snapshots):
            pytest.fail("unsafe name admitted")
    assert _category(error) == "wrapper_archive_invalid"


@pytest.mark.parametrize("kind", [b"1", b"2", b"3", b"4", b"6", b"7", b"x", b"g", b"L", b"K", b"S"])
def test_scanner_rejects_links_devices_extensions_and_sparse_members(tmp_path, kind):
    path, snapshots = _wrapper(tmp_path, _archive(_member(kind=kind)))
    with _failure() as error:
        with _admit(path, snapshots):
            pytest.fail("unsupported type admitted")
    assert _category(error) == "wrapper_archive_invalid"


@pytest.mark.parametrize("field", [
    (100, 108, b"+000644\0"),
    (108, 116, b"0000008\0"),
    (116, 124, b"       \0"),
    (124, 136, b"\x80" + b"\0" * 11),
    (136, 148, b"000\x001" + b"\0" * 7),
    (157, 257, b"target" + b"\0" * 94),
    (257, 265, b"ustar  \0"),
    (329, 337, b"0000001\0"),
    (337, 345, b"0000001\0"),
    (0, 100, b"ok\0hidden" + b"\0" * 91),
])
def test_raw_header_rejections_survive_valid_recomputed_checksum(tmp_path, field):
    path, snapshots = _wrapper(tmp_path, _archive(_member(overrides=[field])))
    with _failure() as error:
        with _admit(path, snapshots):
            pytest.fail("malformed raw header admitted")
    assert _category(error) == "wrapper_archive_invalid"


@pytest.mark.parametrize("variant", [
    "checksum", "no_terminator", "one_zero", "partial_block", "nonzero_tail",
    "concatenated", "missing_payload", "v7_extension", "directory_data",
])
def test_complete_archive_tail_and_extents_are_mandatory(tmp_path, variant):
    member = _member()
    variants = {
        "checksum": bytes([member[0] ^ 1]) + member[1:] + b"\0" * 1024,
        "no_terminator": member,
        "one_zero": member + b"\0" * 512,
        "partial_block": member + b"\0" * 1023,
        "nonzero_tail": _archive(member) + b"x" + b"\0" * 511,
        "concatenated": _archive(member) + _archive(_member(b"other")),
        "missing_payload": _member(payload=b"x" * 2048)[:512] + b"\0" * 1024,
        "v7_extension": _archive(_member(version="v7", overrides=[(300, 301, b"x")])),
        "directory_data": _archive(_member(b"directory", kind=b"5", payload=b"x")),
    }
    path, snapshots = _wrapper(tmp_path, variants[variant])
    with _failure() as error:
        with _admit(path, snapshots):
            pytest.fail("invalid archive tail admitted")
    assert _category(error) == "wrapper_archive_invalid"


@pytest.mark.parametrize("compression", ["gzip", "bzip2", "xz"])
def test_outer_compression_is_rejected_without_decompression(tmp_path, compression):
    import bz2
    import gzip
    import lzma
    compress = {"gzip": gzip.compress, "bzip2": bz2.compress, "xz": lzma.compress}[compression]
    path, snapshots = _wrapper(tmp_path, compress(_archive(_member())))
    with _failure() as error:
        with _admit(path, snapshots):
            pytest.fail("compressed outer envelope admitted")
    assert _category(error) == "wrapper_archive_invalid"


@pytest.mark.parametrize("members,category", [
    ([_member(b"same"), _member(b"same")], "wrapper_archive_invalid"),
    ([_member(b"dir/", payload=b"", kind=b"5"), _member(b"dir")], "wrapper_archive_invalid"),
    ([_member(b"a/package.sign"), _member(b"b/package.sign")], "wrapper_archive_limit"),
    ([_member(b"a/package.cert"), _member(b"b/package.cert")], "wrapper_archive_limit"),
])
def test_duplicate_paths_and_marker_multiplicity_are_distinct_refusals(tmp_path, members, category):
    path, snapshots = _wrapper(tmp_path, _archive(*members))
    with _failure() as error:
        with _admit(path, snapshots):
            pytest.fail("ambiguous archive admitted")
    assert _category(error) == category


@pytest.mark.parametrize("limit_name,limit,members", [
    ("ARCHIVE_MAX_MEMBERS", 1, [_member(b"package.sign"), _member(b"tail")]),
    ("ARCHIVE_MAX_NAME_BYTES", 8, [_member(b"long-name")]),
])
def test_archive_limits_are_bounded_and_apply_after_an_early_marker(
        tmp_path, monkeypatch, limit_name, limit, members):
    monkeypatch.setattr(_module(), limit_name, limit)
    path, snapshots = _wrapper(tmp_path, _archive(*members))
    with _failure() as error:
        with _admit(path, snapshots):
            pytest.fail("archive bound ignored")
    assert _category(error) == "wrapper_archive_limit"


def test_valid_marker_never_excuses_malformed_tail(tmp_path):
    data = _archive(_member(b"package.sign"), _member(b"../escape"))
    path, snapshots = _wrapper(tmp_path, data)
    with _failure() as error:
        with _admit(path, snapshots):
            pytest.fail("early marker bypassed validation")
    assert _category(error) == "wrapper_archive_invalid"


def test_copy_detects_source_growth_with_bounded_reads_and_closes_descriptors(tmp_path, monkeypatch):
    module = _module()
    path, snapshots = _wrapper(tmp_path)
    monkeypatch.setattr(module, "WRAPPER_COPY_CHUNK_BYTES", 512)
    original_open, original_read = os.open, os.read
    source_fds = []
    mutated = []

    def track_open(name, flags, *args, **kwargs):
        fd = original_open(name, flags, *args, **kwargs)
        if os.fspath(name) == str(path):
            source_fds.append(fd)
        return fd

    def read_and_grow(fd, count):
        if fd in source_fds:
            assert count <= 512
        data = original_read(fd, count)
        if fd in source_fds and data and not mutated:
            with path.open("ab") as handle:
                handle.write(b"changed")
            mutated.append(True)
        return data
    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.setattr(os, "read", read_and_grow)
    with _failure() as error:
        with _admit(path, snapshots):
            pytest.fail("changed source admitted")
    assert mutated == [True]
    assert _category(error) == "wrapper_changed"
    for fd in source_fds:
        _assert_closed(fd)
    assert list(snapshots.iterdir()) == []


@pytest.mark.parametrize("status,payload,stderr,category", [
    (2, {"schema_version": 1, "category": "wrapper_archive_invalid", "reason": "bad_header"}, "", "wrapper_archive_invalid"),
    (3, {"schema_version": 1, "category": "wrapper_archive_limit", "reason": "member_limit"}, "", "wrapper_archive_limit"),
    (0, {"schema_version": 1, "category": "wrapper_archive_invalid", "reason": "bad_header"}, "", "wrapper_scan_failed"),
    (2, {"schema_version": 1, "category": "wrapper_archive_limit", "reason": "member_limit"}, "", "wrapper_scan_failed"),
    (0, {"schema_version": 1, "package_sign_present": False, "package_cert_present": False, "member_count": True}, "", "wrapper_scan_failed"),
    (0, {"schema_version": 1, "package_sign_present": False, "package_cert_present": False, "member_count": 1, "extra": 1}, "", "wrapper_scan_failed"),
    (0, {"schema_version": 1, "package_sign_present": False}, "", "wrapper_scan_failed"),
    (9, {}, "", "wrapper_scan_failed"),
    (0, "not JSON", "", "wrapper_scan_failed"),
    (0, "x" * 4097, "", "wrapper_scan_failed"),
    (0, {"schema_version": 1, "package_sign_present": False, "package_cert_present": False, "member_count": 1}, "x" * 4097, "wrapper_scan_failed"),
])
def test_scanner_parent_requires_exact_status_and_bounded_closed_result(
        tmp_path, monkeypatch, status, payload, stderr, category):
    import subprocess
    _module()
    path, snapshots = _wrapper(tmp_path)
    original_popen = subprocess.Popen
    launches = []
    output = payload if isinstance(payload, str) else json.dumps(payload)

    def scanner_peer(argv, *args, **kwargs):
        assert argv[0] == sys.executable
        assert kwargs.get("preexec_fn") is None
        descriptors = kwargs.get("pass_fds", ())
        assert len(descriptors) == 1
        assert os.fstat(descriptors[0]).st_nlink == 0
        launches.append(True)
        script = "import os,sys;os.write(1,{0});os.write(2,{1});sys.exit({2})".format(
            repr(output.encode("utf-8")), repr(stderr.encode("ascii")), status)
        return original_popen([sys.executable, "-c", script], *args, **kwargs)
    monkeypatch.setattr(subprocess, "Popen", scanner_peer)
    with _failure() as error:
        with _admit(path, snapshots):
            pytest.fail("scanner failure became unsigned admission")
    assert launches == [True]
    assert _category(error) == category
    assert list(snapshots.iterdir()) == []


def _redact(secrets, chunks):
    redactor = _module()._StreamingRedactor(secrets)
    return b"".join([redactor.feed(chunk) for chunk in chunks] + [redactor.finish()])


@pytest.mark.parametrize("secrets,data,expected", [
    ([b"abc", b"abcdef"], b"abcdefabc", b"<redacted><redacted>"),
    ([b"aba", b"bab"], b"abab", b"<redacted>b"),
    ([b"abc", b"abc", b""], b"abcabc", b"<redacted><redacted>"),
    ([b"redacted", b"secret"], b"secret", b"<redacted>"),
    ([b"secret"], b"<redacted>secret", b"<redacted><redacted>"),
    ([b"abcdef", b"abc"], b"abc", b"<redacted>"),
    ([b"secret"], b"sec", b"sec"),
    (["p\u00e4ss".encode("utf-8")], "x p\u00e4ss y".encode("utf-8"), b"x <redacted> y"),
])
@pytest.mark.parametrize("chunk_size", [1, 2, 7, 4096])
def test_redaction_is_streaming_leftmost_longest_and_never_rescans_replacements(
        secrets, data, expected, chunk_size):
    chunks = [data[index:index + chunk_size] for index in range(0, len(data), chunk_size)]
    assert _redact(secrets, chunks) == expected


def test_redactor_releases_safe_prefix_and_keeps_streams_separate():
    out = _module()._StreamingRedactor([b"abcdef"])
    err = _module()._StreamingRedactor([b"abcdef"])
    prefix = out.feed(b"x" * 1024 + b"abc")
    assert len(prefix) >= 1022
    assert err.feed(b"def") + err.finish() == b"def"
    assert prefix + out.feed(b"def") + out.finish() == b"x" * 1024 + b"<redacted>"


def test_redactor_rejects_overlong_secret_before_consuming_streams():
    with _failure():
        _module()._StreamingRedactor([b"x" * 4097])


def _read_frame(wire, deadline=None, clock=None, split=False):
    module = _module()
    left, right = socket.socketpair()
    thread = None
    try:
        if split:
            def send():
                try:
                    for byte in wire:
                        right.sendall(bytes([byte]))
                finally:
                    right.shutdown(socket.SHUT_WR)
            thread = threading.Thread(target=send)
            thread.start()
        else:
            right.sendall(wire)
            right.shutdown(socket.SHUT_WR)
        reader = module._FrameReader(
            left, time.monotonic() + 1 if deadline is None else deadline,
            threading.Event(), monotonic_fn=clock,
        )
        return reader.read()
    finally:
        left.close()
        right.close()
        if thread is not None:
            thread.join(1)
            assert not thread.is_alive()


def test_frame_roundtrip_uses_network_length_and_handles_bytewise_arrival():
    value = {"version": 1, "type": "test", "data": "\u00e9"}
    wire = _module()._encode_frame(value)
    assert struct.unpack("!I", wire[:4])[0] == len(wire) - 4
    assert json.loads(wire[4:].decode("utf-8")) == value
    assert _read_frame(wire, split=True) == value


@pytest.mark.parametrize("wire", [
    b"", b"\0", b"\0\0\0", struct.pack("!I", 0),
    struct.pack("!I", 65537), struct.pack("!I", 7) + b"{}",
    struct.pack("!I", 1) + b"\xff",
    struct.pack("!I", 13) + b'{"a":1,"a":2}',
    struct.pack("!I", 9) + b'{"a":NaN}',
    struct.pack("!I", 14) + b'{"a":Infinity}',
])
def test_frames_reject_invalid_bounds_partial_utf8_duplicates_and_nonfinite(wire):
    with _failure():
        _read_frame(wire)


@pytest.mark.parametrize("value", [{"value": float("nan")}, {"value": float("inf")}, {"value": "x" * 65537}])
def test_frame_encoder_refuses_nonfinite_or_overlong_values(value):
    with _failure():
        _module()._encode_frame(value)


def test_frame_read_does_not_reset_an_expired_absolute_deadline():
    wire = struct.pack("!I", 2) + b"{}"
    with _failure() as error:
        _read_frame(wire, deadline=10, clock=lambda: 11)
    assert _category(error) == "timeout"


def _writer(tmp_path, max_bytes=1048576, reserve=131072):
    return _module()._TranscriptWriter(
        str(tmp_path), ATTEMPT, CONTROLLER, created_at=AT,
        max_bytes=max_bytes, restore_reserve_bytes=reserve,
    )


def _transcript_path(tmp_path):
    return tmp_path / "iox" / "transcripts" / (ATTEMPT + ".transcript")


def _records(data):
    result = []
    cursor = 0
    while cursor < len(data):
        assert len(data) - cursor >= 4
        length = struct.unpack("!I", data[cursor:cursor + 4])[0]
        assert 1 <= length <= 65536
        payload = data[cursor + 4:cursor + 4 + length]
        assert len(payload) == length
        record = json.loads(payload.decode("utf-8"))
        assert payload == json.dumps(record, sort_keys=True, ensure_ascii=True,
                                     separators=(",", ":"), allow_nan=False).encode("utf-8")
        result.append(record)
        cursor += 4 + length
    return result


def _start(purpose="verification_read", board=BOARD, command_id=1):
    return {
        "schema_version": 1, "type": "command_start", "command_id": command_id,
        "kind": "ssh", "purpose": purpose, "board_identity": board,
        "record_id": None, "transaction_id": None, "revision": None,
        "phase": None, "started_at": AT,
    }


def _stream(data, offset=0, stream="stdout", command_id=1):
    return {
        "schema_version": 1, "type": "stream", "command_id": command_id,
        "stream": stream, "offset": offset,
        "data_b64": base64.b64encode(data).decode("ascii"),
    }


def _end(stdout=0, stderr=0, dropped=0, command_id=1):
    return {
        "schema_version": 1, "type": "command_end", "command_id": command_id,
        "finished_at": AT, "returncode": 0, "timed_out": False,
        "stdout_truncated": bool(dropped), "stderr_truncated": False,
        "framing_complete": not bool(dropped), "error_category": None,
        "stdout_observed_bytes": stdout + dropped, "stderr_observed_bytes": stderr,
        "stdout_dropped_bytes": dropped, "stderr_dropped_bytes": 0,
        "payload_spans": [] if dropped else [{"offset": 0, "length": stdout}],
        "observed_state": "unknown", "transition_response": None,
    }


def test_transcript_is_canonical_private_and_reference_counts_physical_prefix(tmp_path):
    writer = _writer(tmp_path)
    path = _transcript_path(tmp_path)
    header_prefix = path.read_bytes()
    assert _records(header_prefix) == [{
        "schema_version": 1, "type": "header", "id": ATTEMPT,
        "attempt_id": ATTEMPT, "controller_id": CONTROLLER, "created_at": AT,
    }]
    writer.append(_start())
    writer.append(_stream(b"payload"))
    writer.append(_stream(b"diagnostic", stream="stderr"))
    writer.append(_end(stdout=7, stderr=10, dropped=3))
    data = path.read_bytes()
    assert data.startswith(header_prefix)
    assert len(_records(data)) == 5
    assert stat.S_IMODE(path.stat().st_mode) == 384
    assert stat.S_IMODE(path.parent.stat().st_mode) == 448
    assert writer.reference() == {
        "id": ATTEMPT, "attempt_id": ATTEMPT, "stored_bytes": len(data),
        "observed_bytes": 20, "dropped_bytes": 3, "truncated": True,
    }


def test_transcript_prefix_accepts_owned_shared_state_root_with_private_iox_tree(
        tmp_path):
    # The established deployment state root is shared by several server
    # components and may be 0775. IOx authority begins below state/iox and
    # remains private at 0700; transcript files remain 0600.
    os.chmod(str(tmp_path), 0o775)
    writer = _writer(tmp_path)

    loaded = _module()._load_transcript_prefix(
        str(tmp_path), writer.reference(), CONTROLLER)

    assert loaded["id"] == ATTEMPT
    assert loaded["controller_id"] == CONTROLLER
    assert stat.S_IMODE((tmp_path / "iox").stat().st_mode) == 0o700
    assert stat.S_IMODE((tmp_path / "iox" / "transcripts").stat().st_mode) == 0o700
    assert stat.S_IMODE(_transcript_path(tmp_path).stat().st_mode) == 0o600


@pytest.mark.parametrize("change", [
    {"unexpected": 1}, {"command_id": True}, {"command_id": 0},
    {"kind": "shell"}, {"purpose": "invented"}, {"board_identity": None},
])
def test_transcript_rejects_open_fields_types_and_null_nonidentity_binding(tmp_path, change):
    writer = _writer(tmp_path)
    before = _transcript_path(tmp_path).read_bytes()
    record = _start()
    record.update(change)
    with _failure():
        writer.append(record)
    assert _transcript_path(tmp_path).read_bytes() == before


def test_preliminary_identity_discovery_allows_null_board_only_in_its_own_record(tmp_path):
    writer = _writer(tmp_path)
    writer.append(_start(purpose="identity_discovery", board=None))
    assert _records(_transcript_path(tmp_path).read_bytes())[-1]["board_identity"] is None


@pytest.mark.parametrize("data,offset,command_id", [(b"", 0, 1), (b"x" * 4097, 0, 1), (b"x", 1, 1), (b"x", 0, 2)])
def test_transcript_rejects_unbounded_noncontiguous_or_unstarted_chunks(tmp_path, data, offset, command_id):
    writer = _writer(tmp_path)
    writer.append(_start())
    before = _transcript_path(tmp_path).read_bytes()
    with _failure():
        writer.append(_stream(data, offset, command_id=command_id))
    assert _transcript_path(tmp_path).read_bytes() == before


def test_transcript_command_end_must_close_once_and_match_retained_bytes(tmp_path):
    writer = _writer(tmp_path)
    writer.append(_start())
    writer.append(_stream(b"abc"))
    with _failure():
        writer.append(_end(stdout=4))
    writer.append(_end(stdout=3))
    before = _transcript_path(tmp_path).read_bytes()
    with _failure():
        writer.append(_end(stdout=3))
    assert _transcript_path(tmp_path).read_bytes() == before


def test_transcript_reserve_and_total_cap_count_json_and_base64_overhead(tmp_path):
    writer = _writer(tmp_path, max_bytes=4096, reserve=2048)
    writer.append(_start())
    writer.append(_stream(b"x" * 512))
    before = _transcript_path(tmp_path).read_bytes()
    assert len(before) < 2048
    with _failure() as error:
        writer.append(_stream(b"x" * 900, offset=512))
    assert _category(error) == "transcript_limit"
    assert _transcript_path(tmp_path).read_bytes() == before
    writer.append(_stream(b"x" * 900, offset=512), restoration=True)
    after = _transcript_path(tmp_path).read_bytes()
    assert after.startswith(before)
    assert 2048 < len(after) <= 4096
    with _failure() as error:
        writer.append(_stream(b"x" * 2000, offset=1412), restoration=True)
    assert _category(error) == "transcript_limit"
    assert _transcript_path(tmp_path).read_bytes() == after


def test_transcript_rejects_symlink_without_touching_target(tmp_path):
    path = _transcript_path(tmp_path)
    path.parent.mkdir(parents=True, mode=448)
    target = tmp_path / "unrelated"
    target.write_bytes(b"owner data")
    path.symlink_to(target)
    with _failure():
        _writer(tmp_path)
    assert target.read_bytes() == b"owner data"


# These are executable peers, not parser mocks. Each writes only the next state
# after it has received the exact previous command. The trace stores secret
# labels, never the configured fake password bytes.
_PEER_SCRIPT = r'''
import hashlib
import json
import os
import select
import signal
import subprocess
import sys
import time

scenario = json.load(open(SCENARIO))
trace_path = TRACE
password = scenario.get("enable_secret", "unit-enable-SECRET")

def trace(event, **values):
    values.update(event=event)
    with open(trace_path, "a") as handle:
        handle.write(json.dumps(values, sort_keys=True) + "\n")

def write(data, stream=1):
    if isinstance(data, str):
        data = data.encode("utf-8")
    width = scenario.get("wire_chunk", 4096)
    for offset in range(0, len(data), width):
        os.write(stream, data[offset:offset + width])

def receive():
    line = b""
    while not line.endswith(b"\n"):
        byte = os.read(0, 1)
        if not byte:
            break
        line += byte
    if not line:
        trace("unexpected_eof")
        sys.exit(93)
    text = line.rstrip(b"\n").decode("ascii")
    trace("received", line="<enable-secret>" if text == password else text)
    return text

def no_early_input():
    if select.select([sys.stdin], [], [], 0)[0]:
        trace("early_input")
        sys.exit(94)

def echo(command, prompt):
    suffix = "\r\n" if scenario.get("crlf") else "\n"
    if scenario.get("echo_style") == "prompt":
        write(command + suffix)
    else:
        write(suffix + command + suffix)

trace("spawn", pid=os.getpid(), binary=os.path.basename(sys.argv[0]),
      argv=sys.argv[1:], env_keys=sorted(os.environ), path=os.environ.get("PATH"),
      tmpdir=os.environ.get("TMPDIR"))
signal.alarm(12 if scenario.get("ignore_term") else 4)
if scenario.get("ignore_term"):
    signal.signal(signal.SIGTERM, lambda number, frame: trace(
        "signal", pid=os.getpid(), number=number, at=time.monotonic()))
if scenario.get("startup_error"):
    write(scenario["startup_error"], 2)
    sys.exit(scenario.get("exit_code", 255))
if os.path.basename(sys.argv[0]) == "scp":
    candidates = [arg for arg in sys.argv[1:] if arg.startswith("/proc/self/fd/")]
    if len(candidates) == 1:
        with open(candidates[0], "rb") as handle:
            content = handle.read(65537)
    elif "-" in sys.argv[1:]:
        content = sys.stdin.buffer.read(65537)
    else:
        trace("unstable_upload_source")
        sys.exit(95)
    trace("uploaded", sha256=hashlib.sha256(content).hexdigest(), size=len(content))
    sys.exit(0)

if scenario.get("child"):
    if scenario.get("ignore_term"):
        child = subprocess.Popen([sys.executable, "-c",
            "import os,signal; signal.alarm(12); signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "os.write(1,b'R'); signal.pause()"], stdout=subprocess.PIPE,
            start_new_session=bool(scenario.get("escaped")))
        assert select.select([child.stdout], [], [], 0.5)[0]
        assert child.stdout.read(1) == b"R"
        child.stdout.close()
    else:
        child = subprocess.Popen([sys.executable, "-c",
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(2)"],
            start_new_session=bool(scenario.get("escaped")))
    trace("spawn", pid=child.pid, binary="descendant", session=os.getsid(child.pid))
if scenario.get("hang") == "login":
    time.sleep(3)
    sys.exit(96)
host = scenario.get("host", "edge-1")
level = scenario.get("level", "#")
prompt = host + level
write(scenario.get("banner", ""))
write(prompt)
if level == ">":
    command = receive()
    if command != "enable":
        sys.exit(97)
    no_early_input()
    echo(command, prompt)
    if scenario.get("enable_password", True):
        write(scenario.get("password_prompt", "Password: "))
        if receive() != password:
            sys.exit(98)
        no_early_input()
        if scenario.get("repeat_password"):
            write("\nPassword: ")
            time.sleep(1)
            sys.exit(99)
        if scenario.get("echo_secret"):
            write(password)
        write("\n")
    prompt = host + "#"
    write(prompt)
for command in ("terminal length 0", "terminal width 512"):
    if receive() != command:
        sys.exit(100)
    no_early_input()
    echo(command, prompt)
    if scenario.get("setup_payload"):
        write(scenario["setup_payload"] + "\n")
    write(prompt)

commands = scenario["commands"]
for index, expected in enumerate(commands):
    command = receive()
    if command != expected:
        trace("wrong_command", expected=expected)
        sys.exit(101)
    no_early_input()
    if scenario.get("hang") == "command":
        if scenario.get("ignore_term"):
            while True:
                signal.pause()
        time.sleep(3)
        sys.exit(102)
    if not scenario.get("missing_echo"):
        echo(command, prompt)
    if scenario.get("duplicate_echo"):
        echo(command, prompt)
    question = scenario.get("question")
    if question and index == scenario.get("question_index", 0):
        write(question)
        answer = receive()
        if answer == "yes":
            write("yes\n")
        elif answer == "":
            write("\n")
        else:
            sys.exit(103)
    payload = scenario.get("payload", "App signature verification: enabled\n")
    if isinstance(payload, list):
        payload = payload[index]
    if scenario.get("stdout_bytes"):
        write(b"x" * scenario["stdout_bytes"] + b"\n")
    write(payload.replace("\n", "\r\n") if scenario.get("crlf") else payload)
    if scenario.get("stderr"):
        write(scenario["stderr"], 2)
    if scenario.get("stderr_bytes"):
        write(b"e" * scenario["stderr_bytes"], 2)
    if command == "configure terminal":
        prompt = host + "(config)#"
    elif command == "end":
        prompt = host + "#"
    elif command.startswith("app-hosting appid"):
        prompt = host + "(config-app-hosting)#"
    if scenario.get("final_prompt"):
        prompt = scenario["final_prompt"]
    write(prompt)

if receive() != "exit":
    sys.exit(104)
no_early_input()
if not scenario.get("missing_exit_echo"):
    echo("exit", prompt)
write(scenario.get("trailing_stdout", ""))
trace("exit", code=scenario.get("exit_code", 0))
sys.exit(scenario.get("exit_code", 0))
'''


class _Peer:
    def __init__(self, root, scenario):
        self.root = root
        self.scenario = root / "scenario.json"
        self.trace = root / "peer.jsonl"
        self.scenario.write_text(json.dumps(scenario))
        self.bin_dir = root / "bin"
        self.bin_dir.mkdir(mode=448)
        script = ("#!" + sys.executable + "\nSCENARIO = " + repr(str(self.scenario))
                  + "\nTRACE = " + repr(str(self.trace)) + "\n" + _PEER_SCRIPT)
        for binary in ("ssh", "scp"):
            path = self.bin_dir / binary
            path.write_text(script)
            path.chmod(448)
        sshpass = self.bin_dir / "sshpass"
        sshpass.write_text(
            "#!" + sys.executable + "\nimport os,sys\n"
            "assert sys.argv[1] == '-e'\n"
            "os.execv(sys.argv[2], sys.argv[2:])\n"
        )
        sshpass.chmod(448)

    def events(self):
        if not self.trace.exists():
            return []
        return [json.loads(line) for line in self.trace.read_text().splitlines()]

    def received(self):
        return [event["line"] for event in self.events() if event["event"] == "received"]

    def assert_reaped(self):
        pids = [event["pid"] for event in self.events() if event["event"] == "spawn"]
        assert pids, "the local peer was never launched"
        for pid in pids:
            assert not Path("/proc/{0}".format(pid)).exists(), "unreaped fixture pid {0}".format(pid)

    def cleanup(self):
        import signal
        for event in self.events():
            if event["event"] == "spawn":
                try:
                    os.kill(event["pid"], signal.SIGKILL)
                except ProcessLookupError:
                    pass


@pytest.fixture
def peer_factory(tmp_path, monkeypatch):
    peers = []
    fixture_home = tmp_path / "fixture-home"
    fixture_home.mkdir(mode=448)
    monkeypatch.setenv("HOME", str(fixture_home))
    monkeypatch.setenv("TMPDIR", str(tmp_path))

    def make(**scenario):
        root = tmp_path / ("peer-{0}".format(len(peers)))
        root.mkdir(mode=448)
        scenario.setdefault("commands", [VERIFY.decode("ascii")])
        peer = _Peer(root, scenario)
        peers.append(peer)
        return peer
    import ctypes
    import signal
    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    assert libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0
    assert libc.prctl(36, 1, 0, 0, 0) == 0
    try:
        yield make
    finally:
        try:
            for peer in peers:
                peer.cleanup()
            # Reap orphaned local shims/peers too when an assertion interrupts
            # the normal transport cleanup; a SIGKILL alone leaves zombies.
            deadline = time.monotonic() + 1
            while True:
                try:
                    pid, unused = os.waitpid(-1, os.WNOHANG)
                except ChildProcessError:
                    break
                if pid:
                    continue
                with open("/proc/self/task/%d/children" % os.getpid()) as stream:
                    children = [int(value) for value in stream.read().split()]
                for pid in children:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                assert time.monotonic() < deadline, "unreaped transport-fixture descendant"
                time.sleep(0.005)
        finally:
            assert libc.prctl(36, previous.value, 0, 0, 0) == 0


def _transport(tmp_path, peer, purpose="verification_read", cancel=None,
               clock=None, context=None, credentials=None, overrides=None, journal_ack=None):
    """The sole adapter for the approved config constructor seam.

    command_contexts maps controller command IDs to immutable command_start
    metadata. Executable paths are injected, while the subprocess PATH remains
    fixed. Credentials use their existing environment names in a closed dict.
    """
    module = _module()
    state = tmp_path / "state"
    state.mkdir(mode=448, exist_ok=True)
    temporary = tmp_path / "private-tmp"
    temporary.mkdir(mode=448, exist_ok=True)
    home = tmp_path / "home"
    home.mkdir(mode=448, exist_ok=True)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("test fixture only\n")
    known_hosts.chmod(384)
    command_context = _start(purpose=purpose) if context is None else context
    if purpose == "upload_wrapper":
        command_context["kind"] = "scp"
    config = {
        "host": "192.0.2.10", "user": "fixture-user", "state_dir": str(state),
        "tmp_dir": str(temporary), "home": str(home),
        "attempt_id": ATTEMPT, "controller_id": CONTROLLER,
        "ssh_binary": str(peer.bin_dir / "ssh"),
        "scp_binary": str(peer.bin_dir / "scp"),
        "sshpass_binary": str(peer.bin_dir / "sshpass"),
        "ssh_policy_path": str(Path(__file__).resolve().parents[2] / "lab" / "iris-ssh-policy.sh"),
        "ssh_policy_env": {"IRIS_SSH_KNOWN_HOSTS": str(known_hosts)},
        "credentials": {
            "DEVICE_PASS": "unit-login-SECRET", "DEVICE_ENABLE": "unit-enable-SECRET",
            "DEVICE_SSH_PASS": "unit-ssh-SECRET", "CATALOG_TOKEN": "unit-token-SECRET",
            "SSHPASS": "unit-login-SECRET",
        },
        "command_contexts": {1: command_context},
        "session_deadline": time.monotonic() + 3,
        "cancel": threading.Event() if cancel is None else cancel,
    }
    if credentials is not None:
        config["credentials"].update(credentials)
    if overrides is not None:
        config.update(overrides)
    writer = _writer(state)
    if journal_ack is not None:
        writer.append(journal_ack)
    return module.IoxTransport(config, writer, None, monotonic_fn=clock), config


def _command(transport, command=VERIFY, timeout=1.5):
    result = transport.command(1, command, time.monotonic() + timeout)
    for field in ("returncode", "timed_out", "stdout", "stderr",
                  "stdout_truncated", "stderr_truncated", "framing_complete",
                  "error_category", "transcript_ref"):
        _value(result, field)
    assert isinstance(_value(result, "stdout"), bytes)
    assert isinstance(_value(result, "stderr"), bytes)
    ref = _value(result, "transcript_ref")
    assert set(ref) == {"id", "attempt_id", "stored_bytes", "observed_bytes", "dropped_bytes", "truncated"}
    assert ref["id"] == ref["attempt_id"] == ATTEMPT
    return result


@pytest.mark.parametrize("level,password,echo_style", [
    ("#", True, "bare"), ("#", True, "prompt"),
    (">", False, "bare"), (">", True, "bare"), (">", True, "prompt"),
])
def test_ssh_sends_only_commands_authorized_by_observed_privilege_dialogue(
        tmp_path, peer_factory, level, password, echo_style):
    peer = peer_factory(level=level, enable_password=password, echo_style=echo_style,
                        crlf=True, banner="Authorized fixture access\r\n")
    transport, config = _transport(tmp_path, peer)
    result = _command(transport)
    expected = [] if level == "#" else ["enable"]
    if level == ">" and password:
        expected.append("<enable-secret>")
    expected += ["terminal length 0", "terminal width 512", VERIFY.decode("ascii"), "exit"]
    assert peer.received() == expected
    assert not any(event["event"] == "early_input" for event in peer.events())
    assert _value(result, "returncode") == 0
    assert _value(result, "framing_complete") is True
    assert _value(result, "timed_out") is False
    assert b"App signature verification: enabled\n" in _value(result, "stdout")
    assert b"\r" not in _value(result, "stdout")
    spawn = [event for event in peer.events() if event["event"] == "spawn"][0]
    assert "-tt" in spawn["argv"]
    assert "ConnectTimeout=15" in spawn["argv"]
    assert "StrictHostKeyChecking=yes" in spawn["argv"]
    assert "UserKnownHostsFile=" + config["ssh_policy_env"]["IRIS_SSH_KNOWN_HOSTS"] in spawn["argv"]
    peer.assert_reaped()


@pytest.mark.parametrize("scenario", [
    {"repeat_password": True, "level": ">"},
    {"echo_secret": True, "level": ">"},
    {"password_prompt": "Password:  ", "level": ">"},
    {"setup_payload": "unexpected terminal diagnostic"},
    {"missing_echo": True}, {"duplicate_echo": True},
    {"final_prompt": "different#"}, {"final_prompt": "edge-1>"},
    {"final_prompt": "edge-1(config)#"},
    {"missing_exit_echo": True}, {"trailing_stdout": "unsolicited\n"},
    {"payload": "App signature verification: enabled\x1b[2K\n"},
    {"payload": "App signature verification: enabled\rX\n"},
    {"payload": "App signature verification: enabled\x00\n"},
    {"payload": "App signature verification: enabled\x08\n"},
    {"payload": "App signature verification: enabled\x7f\n"},
])
def test_ssh_incomplete_or_unrecognized_dialogue_cannot_be_authoritative(
        tmp_path, peer_factory, scenario):
    peer = peer_factory(**scenario)
    transport, unused = _transport(tmp_path, peer)
    result = _command(transport)
    assert _value(result, "framing_complete") is False
    assert _value(result, "error_category") in ("unsupported_response", "timeout", "rejected")
    assert peer.received().count("<enable-secret>") <= 1
    peer.assert_reaped()


@pytest.mark.parametrize("payload,category", [
    ("% Invalid input detected at '^' marker.\n", "unsupported_syntax"),
    ("% Incomplete command.\n", "unsupported_syntax"),
    ("% Ambiguous command.\n", "unsupported_syntax"),
    ("%Error operation failed\n", "rejected"),
    ("% Error operation failed\n", "rejected"),
    ("% Authorization failed\n", "rejected"),
    ("% Access denied\n", "rejected"),
    ("% Unknown native error\nApp signature verification: enabled\n", "unsupported_response"),
])
def test_ios_error_classification_belongs_to_the_command_payload(tmp_path, peer_factory, payload, category):
    peer = peer_factory(payload=payload)
    transport, unused = _transport(tmp_path, peer)
    result = _command(transport)
    assert _value(result, "error_category") == category
    peer.assert_reaped()


@pytest.mark.parametrize("diagnostic,category", [
    ("Permission denied (publickey,password).\n", "ssh_authentication"),
    ("Host key verification failed.\n", "host_key"),
    ("ssh: connect to host 192.0.2.10 port 22: Connection refused\n", "connection"),
])
def test_ssh_startup_errors_retain_separate_stderr_and_no_payload_authority(
        tmp_path, peer_factory, diagnostic, category):
    peer = peer_factory(startup_error=diagnostic)
    transport, unused = _transport(tmp_path, peer)
    result = _command(transport)
    assert _value(result, "error_category") == category
    assert _value(result, "returncode") == 255
    assert _value(result, "framing_complete") is False
    assert _value(result, "stdout") == b""
    assert diagnostic.encode("ascii") in _value(result, "stderr")
    peer.assert_reaped()


def test_nonzero_exit_overrides_an_apparent_successful_payload(tmp_path, peer_factory):
    peer = peer_factory(exit_code=7)
    transport, unused = _transport(tmp_path, peer)
    result = _command(transport)
    assert _value(result, "returncode") == 7
    assert _value(result, "framing_complete") is False
    assert _value(result, "error_category") == "transport"
    ends = [row for row in _records(
        _transcript_path(tmp_path / "state").read_bytes())
            if row["type"] == "command_end"]
    assert len(ends) == 1
    assert ends[0]["observed_state"] == "unknown"
    peer.assert_reaped()


def test_stderr_never_supplies_a_success_field_for_empty_stdout(tmp_path, peer_factory):
    peer = peer_factory(payload="", stderr="App signature verification: enabled\n")
    transport, unused = _transport(tmp_path, peer)
    result = _command(transport)
    assert b"App signature verification" not in _value(result, "stdout")
    assert b"App signature verification" in _value(result, "stderr")
    records = _records(_transcript_path(tmp_path / "state").read_bytes())
    end = [record for record in records if record["type"] == "command_end"][-1]
    assert end["observed_state"] == "unknown"
    peer.assert_reaped()


def test_all_configured_secret_values_are_redacted_before_capture_and_transcript(tmp_path, peer_factory):
    secrets = ["unit-login-SECRET", "unit-enable-SECRET", "unit-ssh-SECRET", "unit-token-SECRET"]
    diagnostic = " ".join(secrets) + "\n"
    peer = peer_factory(payload=diagnostic, stderr=diagnostic, wire_chunk=1)
    transport, unused = _transport(tmp_path, peer)
    result = _command(transport)
    persisted = _transcript_path(tmp_path / "state").read_bytes()
    records = _records(persisted)
    decoded = b"".join(base64.b64decode(record["data_b64"]) for record in records
                       if record["type"] == "stream")
    for secret in secrets:
        encoded = secret.encode("ascii")
        assert encoded not in _value(result, "stdout") + _value(result, "stderr")
        assert encoded not in persisted + decoded
    assert _value(result, "stderr").count(b"<redacted>") == 4
    assert decoded.count(b"<redacted>") == 8
    peer.assert_reaped()


@pytest.mark.parametrize("purpose,limit", [("verification_read", 8192), ("preflight", 32768)])
def test_each_stream_capture_is_capped_drained_counted_and_never_authoritative_when_truncated(
        tmp_path, peer_factory, purpose, limit):
    peer = peer_factory(stdout_bytes=limit + 1024, stderr_bytes=limit + 2048)
    transport, unused = _transport(tmp_path, peer, purpose=purpose)
    result = _command(transport)
    assert len(_value(result, "stdout")) == limit
    assert len(_value(result, "stderr")) == limit
    assert _value(result, "stdout_truncated") is True
    assert _value(result, "stderr_truncated") is True
    assert _value(result, "framing_complete") is False
    ref = _value(result, "transcript_ref")
    assert ref["observed_bytes"] > 2 * limit
    assert ref["dropped_bytes"] == ref["observed_bytes"] - 2 * limit
    assert ref["truncated"] is True
    transcript_path = _transcript_path(tmp_path / "state")
    assert transcript_path.stat().st_size <= 1048576
    ends = [row for row in _records(transcript_path.read_bytes())
            if row["type"] == "command_end"]
    assert len(ends) == 1
    assert ends[0]["observed_state"] == (
        "unknown" if purpose == "verification_read" else None)
    peer.assert_reaped()


def test_upload_uses_original_snapshot_fd_after_path_replacement(tmp_path, peer_factory):
    data = _archive(_member(payload=b"snapshot upload fixture"))
    path, snapshots = _wrapper(tmp_path, data)
    peer = peer_factory()
    transport, unused = _transport(tmp_path, peer, purpose="upload_wrapper")
    with _admit(path, snapshots) as snapshot:
        replacement = tmp_path / "replacement"
        replacement.write_bytes(b"wrong source bytes")
        os.replace(str(replacement), str(path))
        result = transport.upload(snapshot.fd, "sdflash:iris-" + TRANSACTION + ".tar",
                                  time.monotonic() + 1.5)
        assert _value(result, "returncode") == 0
        uploaded = [event for event in peer.events() if event["event"] == "uploaded"]
        assert uploaded == [{"event": "uploaded", "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}]
        assert not any(event["event"] == "unstable_upload_source" for event in peer.events())
    peer.assert_reaped()


@pytest.mark.parametrize("command", [b"x" * 321, b"show\x00infra", b"show\rinfra", b"show\x7finfra", b"show\tinfra"])
def test_rendered_command_bounds_refuse_before_starting_transport(tmp_path, peer_factory, command):
    peer = peer_factory()
    transport, unused = _transport(tmp_path, peer)
    result = _command(transport, command)
    assert _value(result, "error_category") == "unsupported_syntax"
    assert _value(result, "framing_complete") is False
    assert peer.events() == []


@pytest.mark.parametrize("secret", ["invalid\nsecret", "invalid\rsecret", "invalid\x00secret", "x" * 4097])
def test_invalid_enable_secret_is_refused_before_transport(tmp_path, peer_factory, secret):
    peer = peer_factory(level=">")
    _module()
    try:
        transport, unused = _transport(tmp_path, peer, credentials={"DEVICE_ENABLE": secret})
    except Exception as error:
        assert error.category in ("rejected", "unsupported_syntax")
    else:
        result = _command(transport)
        assert _value(result, "error_category") in ("rejected", "unsupported_syntax")
        assert _value(result, "framing_complete") is False
    assert peer.events() == []


@pytest.mark.parametrize("payload", ["", "[OK]", "[OK]\n[OK]\n", "[OK]\nextra\n"])
def test_save_requires_one_complete_ok_line_and_no_extra_payload(tmp_path, peer_factory, payload):
    peer = peer_factory(commands=["write memory"],
                        question="Destination filename [startup-config]?", payload=payload)
    transport, unused = _transport(tmp_path, peer, purpose="save")
    result = _command(transport, b"write memory")
    assert _value(result, "error_category") == "unsupported_response"
    assert _value(result, "framing_complete") is False
    peer.assert_reaped()


@pytest.mark.parametrize("purpose,command,question,answer,payload", [
    ("mkdir_share", b"mkdir sdflash:iris", "Create directory filename [sdflash:iris]?", "", "Created directory sdflash:iris\n"),
    ("save", b"write memory", "Destination filename [startup-config]?", "", "[OK]\n"),
])
def test_only_operation_bound_interactive_questions_receive_an_answer(
        tmp_path, peer_factory, purpose, command, question, answer, payload):
    peer = peer_factory(commands=[command.decode("ascii")], question=question, payload=payload)
    transport, unused = _transport(tmp_path, peer, purpose=purpose)
    result = _command(transport, command)
    assert peer.received() == ["terminal length 0", "terminal width 512", command.decode("ascii"), answer, "exit"]
    assert _value(result, "framing_complete") is True
    peer.assert_reaped()


@pytest.mark.parametrize("question", ["Continue? [yes/no]:", "Password:", "Destination filename [other]?", "Create directory filename [sdflash:other]?"])
def test_unknown_or_wrong_operation_question_gets_no_answer(tmp_path, peer_factory, question):
    peer = peer_factory(question=question)
    transport, unused = _transport(tmp_path, peer)
    result = _command(transport, timeout=0.25)
    assert _value(result, "framing_complete") is False
    assert peer.received() == ["terminal length 0", "terminal width 512", VERIFY.decode("ascii")]
    peer.assert_reaped()


def test_configuration_batch_is_sent_one_line_at_a_time_with_bound_submode_prompts(tmp_path, peer_factory):
    commands = ["configure terminal", "app-hosting appid iris", "no app-vnic gateway0", "end"]
    peer = peer_factory(commands=commands, payload=[
        "Enter configuration commands, one per line.  End with CNTL/Z.\n", "", "", "",
    ])
    transport, unused = _transport(tmp_path, peer, purpose="cleanup_config")
    command = b"configure terminal\n! fixture comment\n\napp-hosting appid iris\nno app-vnic gateway0\nend"
    result = _command(transport, command)
    assert _value(result, "framing_complete") is True
    assert peer.received() == ["terminal length 0", "terminal width 512"] + commands + ["exit"]
    peer.assert_reaped()


def test_cleanup_confirmation_is_answered_once_in_the_config_step(tmp_path, peer_factory):
    commands = ["configure terminal", "no app-hosting appid iris", "end"]
    peer = peer_factory(commands=commands, question_index=1,
                        question="Are you sure you want to do this? [yes/no]:",
                        payload=["", "", ""])
    transport, unused = _transport(tmp_path, peer, purpose="cleanup_config")
    result = _command(transport, "\n".join(commands).encode("ascii"))
    assert _value(result, "framing_complete") is True
    assert peer.received() == ["terminal length 0", "terminal width 512", commands[0], commands[1], "yes", commands[2], "exit"]
    peer.assert_reaped()


@pytest.mark.parametrize("hang", ["login", "command"])
def test_phase_timeout_covers_dialogue_and_reaps_before_return(tmp_path, peer_factory, hang):
    peer = peer_factory(hang=hang)
    transport, unused = _transport(tmp_path, peer)
    started = time.monotonic()
    result = _command(transport, timeout=0.25)
    assert time.monotonic() - started < 1.0
    assert _value(result, "timed_out") is True
    assert _value(result, "framing_complete") is False
    assert _value(result, "error_category") == "timeout"
    ends = [row for row in _records(
        _transcript_path(tmp_path / "state").read_bytes())
            if row["type"] == "command_end"]
    assert len(ends) == 1
    assert ends[0]["observed_state"] == "unknown"
    assert ends[0]["payload_spans"] == []
    peer.assert_reaped()


def test_cancellation_stops_work_and_cancel_and_reap_does_not_extend_deadline(tmp_path, peer_factory):
    peer = peer_factory(hang="command")
    cancel = threading.Event()
    transport, unused = _transport(tmp_path, peer, cancel=cancel)
    timer = threading.Timer(0.1, cancel.set)
    timer.start()
    try:
        result = _command(transport, timeout=0.5)
    finally:
        timer.cancel()
        timer.join(1)
    assert _value(result, "error_category") == "cancelled"
    assert _value(result, "framing_complete") is False
    deadline = time.monotonic() + 0.1
    transport.cancel_and_reap(deadline)
    assert time.monotonic() < deadline + 0.1
    peer.assert_reaped()


def test_cancel_and_reap_enforces_separate_term_and_kill_reap_ceilings(
        tmp_path, peer_factory, monkeypatch):
    import signal
    import subprocess
    _module()
    # Decision 6 fixes the two time ceilings, but names no product constants.
    # Observe the real grace periods through the existing public method.
    term_limit, reap_limit, tolerance = 5, 5, 0.15
    peer = peer_factory(hang="command", child=True, ignore_term=True)
    sent = []
    original_popen = subprocess.Popen
    original_kill, original_killpg = os.kill, os.killpg

    def observe(number, target, route):
        if number in (signal.SIGTERM, signal.SIGKILL):
            sent.append((number, time.monotonic(), target, route))

    def launch(*args, **kwargs):
        child = original_popen(*args, **kwargs)
        send_signal, terminate, kill = child.send_signal, child.terminate, child.kill
        def send(number):
            observe(number, child.pid, "Popen.send_signal")
            return send_signal(number)
        def term():
            observe(signal.SIGTERM, child.pid, "Popen.terminate")
            return terminate()
        def force():
            observe(signal.SIGKILL, child.pid, "Popen.kill")
            return kill()
        child.send_signal, child.terminate, child.kill = send, term, force
        return child

    def kill(pid, number):
        observe(number, pid, "os.kill")
        return original_kill(pid, number)

    def killpg(pgid, number):
        observe(number, pgid, "os.killpg")
        return original_killpg(pgid, number)

    monkeypatch.setattr(subprocess, "Popen", launch)
    monkeypatch.setattr(os, "kill", kill)
    monkeypatch.setattr(os, "killpg", killpg)
    deadline = time.monotonic() + 12
    transport, unused = _transport(tmp_path, peer,
                                   overrides={"session_deadline": deadline})
    results, errors = [], []
    def command():
        try:
            results.append(transport.command(1, VERIFY, deadline))
        except BaseException as error:
            errors.append(error)
    worker = threading.Thread(target=command)
    worker.daemon = True
    worker.start()
    try:
        ready_deadline = min(deadline, time.monotonic() + 0.5)
        while VERIFY.decode("ascii") not in peer.received():
            assert worker.is_alive(), "command exited before cancellation barrier: %r" % errors
            assert time.monotonic() < ready_deadline, "peer never reached cancellation barrier"
            threading.Event().wait(0.002)
        # Both the real peer and its child now ignore TERM. Observers delegate
        # every signal unchanged; an implementation cannot pass with a mocked
        # return code or by merely waiting for the peer to exit naturally.
        assert len([row for row in peer.events() if row["event"] == "spawn"]) == 2
        started = time.monotonic()
        transport.cancel_and_reap(deadline)
        finished = time.monotonic()
        terms = [row[1] for row in sent if row[0] == signal.SIGTERM]
        kills = [row[1] for row in sent if row[0] == signal.SIGKILL]
        assert terms and kills, "cancellation must send TERM then escalate to KILL"
        assert started <= min(terms) < min(kills) <= finished < deadline
        assert min(terms) - started <= tolerance
        assert max(kills) - min(terms) <= term_limit + tolerance
        assert finished - min(kills) <= reap_limit + tolerance
        assert finished - started <= term_limit + reap_limit + tolerance
        assert any(row["event"] == "signal" and row["number"] == signal.SIGTERM
                   for row in peer.events()), "peer never observed the graceful termination signal"
        peer.assert_reaped()
        worker.join(0.1)
        assert not worker.is_alive() and not errors
        assert len(results) == 1 and _value(results[0], "framing_complete") is False
    finally:
        peer.cleanup()
        worker.join(0.5)
        assert not worker.is_alive(), "transport command worker did not stop after fixture cleanup"


def test_expired_deadline_and_precancelled_session_never_spawn_a_peer(tmp_path, peer_factory):
    peer = peer_factory()
    cancel = threading.Event()
    cancel.set()
    transport, unused = _transport(tmp_path, peer, cancel=cancel)
    result = transport.command(1, VERIFY, time.monotonic() - 1)
    assert _value(result, "error_category") in ("timeout", "cancelled")
    assert _value(result, "framing_complete") is False
    assert peer.events() == []


def test_leader_exit_does_not_report_clean_completion_with_a_living_descendant(tmp_path, peer_factory):
    peer = peer_factory(child=True)
    transport, unused = _transport(tmp_path, peer)
    started = time.monotonic()
    result = _command(transport, timeout=0.5)
    assert time.monotonic() - started < 0.9
    live = [event for event in peer.events() if event["event"] == "spawn"
            and Path("/proc/{0}".format(event["pid"])).exists()]
    if live:
        assert _value(result, "error_category") == "descendant_unreaped"
        assert _value(result, "framing_complete") is False
        transport.cancel_and_reap(time.monotonic() + 0.5)
    peer.assert_reaped()


def test_shell_environment_is_allowlisted_and_private(tmp_path, peer_factory, monkeypatch):
    peer = peer_factory()
    poison = tmp_path / "poison.sh"
    touched = tmp_path / "injected"
    poison.write_text("touch " + str(touched) + "\n")
    for key, value in {"BASH_ENV": str(poison), "ENV": str(poison),
                       "CDPATH": str(tmp_path), "LD_PRELOAD": "/nonexistent/fixture.so",
                       "PYTHONPATH": str(tmp_path), "PYTHONSTARTUP": str(poison),
                       "IRIS_DEVICE_ENABLE_ALWAYS": "1"}.items():
        monkeypatch.setenv(key, value)
    transport, unused = _transport(tmp_path, peer)
    result = _command(transport)
    assert _value(result, "framing_complete") is True
    spawn = [event for event in peer.events() if event["event"] == "spawn"][0]
    forbidden = {"BASH_ENV", "ENV", "SHELLOPTS", "CDPATH", "PYTHONPATH", "PYTHONSTARTUP"}
    assert not forbidden.intersection(spawn["env_keys"])
    assert not any(key.startswith("LD_") for key in spawn["env_keys"])
    assert not touched.exists()
    assert "enable" not in peer.received()
    assert str(tmp_path) not in spawn["path"]
    assert str(tmp_path) in spawn["tmpdir"]
    peer.assert_reaped()


@pytest.mark.parametrize("aggregate_extra", [0, 13])
def test_composite_ipc_packs_two_maximum_streams_across_constituent_boundaries(
        tmp_path, aggregate_extra):
    """Exercise actual controller IPC, including aggregate-only truncation."""
    importlib.import_module("iox_verification")
    # Reuse the frozen real-store and four-argument factory adapters; these
    # helpers create durable evidence and do not mock protocol serialization.
    import test_iox_verification_crash as crash
    crash._authority_layout(tmp_path)
    crash._durable_fixture_json(str(tmp_path / "deployment_records.json"), {"records": {}})
    store = crash._FakeStore(tmp_path, existing=True)
    wrapper, unused = _wrapper(tmp_path)
    phase_path = tmp_path / "recipe-phase"
    capture_path = tmp_path / "composite-response.json"
    expected = {"stdout": [], "stderr": []}
    # Neither of the first two constituents ends at a response-frame boundary.
    stdout_sizes = [4095, 4097 + aggregate_extra, 4096, 4096, 4096, 4096, 8192]
    stderr_sizes = [4097, 4095 + aggregate_extra, 4096, 4096, 4096, 4096, 8192]
    assert sum(stdout_sizes) == sum(stderr_sizes) == 32768 + aggregate_extra

    class PackingTransport(crash._FakeTransport):
        def __init__(self):
            crash._FakeTransport.__init__(self, crash._Device("enabled"), [])
            self.constituents = 0
            self.disable_sends = 0

        def command(self, command_id, command_bytes, phase_deadline):
            if not phase_path.exists() or phase_path.read_text() != "begin_install":
                return crash._FakeTransport.command(self, command_id, command_bytes, phase_deadline)
            assert phase_deadline is not None
            index = self.constituents
            assert index < 7, "unbounded composite retry"
            purpose = self._purpose(command_bytes)
            expected_purpose = "disable" if index in (1, 3, 5) else "read"
            assert purpose == expected_purpose
            self.constituents += 1
            transition = None
            category = None
            if purpose == "disable":
                self.disable_sends += 1
                if self.disable_sends < 3:
                    payload = b"The process for the command is not responding or is otherwise unavailable\n"
                    transition, category = "caf_transient", "caf_transient"
                else:
                    self.device.state = "disabled"
                    payload = b"App hosting verification disabled successfully\n"
                    transition = "disabled_successfully"
            else:
                payload = ("App signature verification: %s\n" % self.device.state).encode("ascii")
            stdout = payload + b"\n" * (stdout_sizes[index] - len(payload))
            stderr = bytes([ord("a") + index]) * stderr_sizes[index]
            expected["stdout"].append(stdout)
            expected["stderr"].append(stderr)
            context = dict(self.config["command_contexts"][command_id])
            self.transcript.append(context)
            for stream, body in (("stdout", stdout), ("stderr", stderr)):
                for offset in range(0, len(body), 4096):
                    self.transcript.append({
                        "schema_version": 1, "type": "stream", "command_id": command_id,
                        "stream": stream, "offset": offset,
                        "data_b64": base64.b64encode(body[offset:offset+4096]).decode("ascii")})
            self.transcript.append({
                "schema_version": 1, "type": "command_end", "command_id": command_id,
                "finished_at": 100, "returncode": 0, "timed_out": False,
                "stdout_truncated": False, "stderr_truncated": False,
                "framing_complete": True, "error_category": category,
                "stdout_observed_bytes": len(stdout), "stderr_observed_bytes": len(stderr),
                "stdout_dropped_bytes": 0, "stderr_dropped_bytes": 0,
                "payload_spans": [{"offset": 0, "length": len(stdout)}],
                "observed_state": self.device.state if purpose == "read" else None,
                "transition_response": transition})
            self.transcript_ref = self.transcript.reference()
            return crash._AttrDict(returncode=0, timed_out=False, stdout=stdout, stderr=stderr,
                stdout_truncated=False, stderr_truncated=False, framing_complete=True,
                error_category=category, transcript_ref=self.transcript_ref)

    # Use the existing bounded v1 recipe driver, observing bytes received from
    # the production controller before any test decoding/concatenation.
    recipe = crash._INSTALL_RECIPE.replace(
        '    ready=receive()',
        '    open(PHASE_PATH,"w").write(operation)\n    frames=[]\n    ready=receive()')
    recipe = recipe.replace('        response=receive()',
        '        response=receive()\n        frames.append(response)')
    recipe = recipe.replace('    if not response["ok"]:',
        '    if operation=="begin_install":\n'
        '        with open(CAPTURE_PATH,"w") as handle: json.dump(frames,handle)\n'
        '    if not response["ok"]:')
    recipe = "PHASE_PATH=%r\nCAPTURE_PATH=%r\n" % (str(phase_path), str(capture_path)) + recipe
    transport = PackingTransport()
    controller, factory = crash._controller(tmp_path, store, transport,
        recipe_argv_by_action={"install": [sys.executable, "-c", recipe]})
    request = crash._AttrDict(action="install", device_id=crash._DEVICE,
        job_id="0123456789abcdef",
        target=crash._AttrDict(host=crash._HOST, port=22, platform="iox",
                              model="C9300-48UXM", os_family="xe"),
        credential_ref="credential-packing", record_id=None, teardown_mode="none",
        wrapper_path=str(wrapper))

    def prepare(*args):
        store.delegate.create(crash._deployment_record())
        return crash._RECORD

    def preflight(*args):
        return crash._AttrDict(device_identity=crash._BOARD, platform="iox",
                               model="C9300-48UXM", os_family="xe")

    try:
        result = controller.run_install(request, prepare, preflight, lambda *args: None, crash._Cancel())
    finally:
        controller.close()
    assert result["result_code"] == result["returncode"] == 0
    assert transport.constituents == 7 and transport.disable_sends == 3
    assert factory.calls and all(len(call) == 4 for call in factory.calls)
    assert capture_path.stat().st_size <= 131072
    frames = json.loads(capture_path.read_text())
    assert len(frames) == 17
    assert [frame["type"] for frame in frames].count("result") == 1
    final = frames[-1]
    assert final["type"] == "result"
    assert set(final) == set("version type sequence ok operation_code revision phase returncode timed_out stdout_truncated stderr_truncated framing_complete error_category detail transcript_ref recipe_returncode recovery_code".split())
    assert final["version"] == 1 and final["ok"] is True
    assert final["operation_code"] == 0 and final["returncode"] is None
    assert final["recipe_returncode"] is None and final["timed_out"] is False
    assert final["framing_complete"] is True
    assert final["stdout_truncated"] is bool(aggregate_extra)
    assert final["stderr_truncated"] is bool(aggregate_extra)
    for stream in ("stdout", "stderr"):
        chunks = [frame for frame in frames[:-1] if frame["stream"] == stream]
        assert len(chunks) == 8
        assert [frame["index"] for frame in chunks] == list(range(8))
        reconstructed = []
        for frame in chunks:
            assert set(frame) == {"version", "type", "sequence", "stream", "index", "data_b64"}
            assert frame["version"] == 1 and frame["type"] == "output"
            assert frame["sequence"] == final["sequence"]
            decoded = base64.b64decode(frame["data_b64"], validate=True)
            assert len(decoded) == 4096
            assert base64.b64encode(decoded).decode("ascii") == frame["data_b64"]
            assert len(json.dumps(frame, separators=(",", ":")).encode("utf-8")) <= 65536
            reconstructed.append(decoded)
        assert b"".join(reconstructed) == b"".join(expected[stream])[:32768]
    # Presentation overflow does not retroactively truncate durable commands or
    # invalidate the authoritative disabled confirmation and completed restore.
    assert store.journal["phase"] == "restored"
    assert store.journal["disable_confirmation"] is not None


@pytest.mark.parametrize("payload,state", [
    ("App signature verification: enabled\n", "enabled"),
    ("\nApp signature verification: enabled\n\n", "enabled"),
    ("APP SIGNATURE VERIFICATION: ENABLED\n", "enabled"),
    ("aPp SiGnAtUrE vErIfIcAtIoN: DiSaBlEd\n", "disabled"),
    ("App signature verification: disabled\n", "disabled"),
    ("", "unknown"), ("unrelated status\n", "unknown"),
    ("App signature verification: enabled\n" * 2, "unknown"),
    ("App signature verification: enabled\nApp signature verification: disabled\n", "unknown"),
    ("App signature verification: enabled \n", "unknown"),
    (" App signature verification: enabled\n", "unknown"),
    ("App signature verification: enabled extra\n", "unknown"),
    ("App signature verification: ENABLE\n", "unknown"),
    ("App signature verification:enabled\n", "unknown"),
])
def test_executable_closed_parser_records_recomputed_state(tmp_path, peer_factory, payload, state):
    peer = peer_factory(payload=payload)
    transport, unused = _transport(tmp_path, peer)
    _command(transport)
    ends = [row for row in _records(_transcript_path(tmp_path / "state").read_bytes())
            if row["type"] == "command_end"]
    assert len(ends) == 1 and ends[0]["observed_state"] == state
    if state != "unknown":
        assert ends[0]["framing_complete"] is True
        assert ends[0]["returncode"] == 0
        assert len(ends[0]["payload_spans"]) == 1
    peer.assert_reaped()


@pytest.mark.parametrize("purpose,command,payload,exit_code,transition,category", [
    ("verification_disable", b"app-hosting verification disable",
     "App hosting verification disabled successfully\n", 0,
     "disabled_successfully", None),
    ("verification_disable", b"app-hosting verification disable",
     "\nApp hosting verification disabled successfully\n\n", 0,
     "disabled_successfully", None),
    ("verification_disable", b"app-hosting verification disable",
     "APP HOSTING VERIFICATION DISABLED SUCCESSFULLY\n", 0,
     "disabled_successfully", None),
    ("verification_enable", b"app-hosting verification enable",
     "App hosting verification enabled successfully\n", 0,
     "enabled_successfully", None),
    ("verification_enable", b"app-hosting verification enable",
     "aPP hOSTING vERIFICATION eNABLED sUCCESSFULLY\n", 0,
     "enabled_successfully", None),
    ("verification_disable", b"app-hosting verification disable",
     "The process for the command is not responding or is otherwise unavailable\n",
     0, "caf_transient", "caf_transient"),
    ("verification_disable", b"app-hosting verification disable",
     "App hosting verification is already disabled\n", 0,
     "other", "unsupported_response"),
    ("verification_disable", b"app-hosting verification disable",
     "prefix App hosting verification disabled successfully suffix\n", 0,
     "other", "unsupported_response"),
    ("verification_disable", b"app-hosting verification disable",
     "App hosting verification disabled successfully\nextra status\n", 0,
     "other", "unsupported_response"),
    ("verification_disable", b"app-hosting verification disable",
     "prefix The process for the command is not responding or is otherwise unavailable suffix\n",
     0, "other", "unsupported_response"),
    ("verification_enable", b"app-hosting verification enable",
     "App hosting verification enabled successfully\n", 7,
     "other", "transport"),
    ("verification_disable", b"app-hosting verification disable",
     "App hosting verification disabled successfully\n", 7,
     "other", "transport"),
    ("verification_disable", b"app-hosting verification disable",
     "App hosting verification disabled successful\n", 0,
     "other", "unsupported_response"),
    ("verification_enable", b"app-hosting verification enable",
     "App hosting verification enabled successful\n", 0,
     "other", "unsupported_response"),
    ("verification_enable", b"app-hosting verification enable",
     "App hosting verification disabled successfully\n", 0,
     "other", "unsupported_response"),
])
def test_executable_transition_parser_accepts_only_the_closed_native_grammar(
        tmp_path, peer_factory, purpose, command, payload, exit_code,
        transition, category):
    """Classify retained native output; fixture labels grant no authority."""
    peer = peer_factory(
        commands=[command.decode("ascii")], payload=payload,
        exit_code=exit_code)
    phase = "disable_intent" if purpose == "verification_disable" else "restore_intent"
    context = _start(purpose=purpose)
    context.update(record_id="transition-record", transaction_id=TRANSACTION,
                   revision=1, phase=phase)
    acknowledgement = {
        "schema_version": 1, "type": "journal_ack", "record_id": "transition-record",
        "transaction_id": TRANSACTION, "revision": 1, "phase": phase,
        "event": phase, "at": AT,
    }
    transport, unused = _transport(tmp_path, peer, purpose=purpose,
        context=context, journal_ack=acknowledgement)
    result = _command(transport, command=command)
    ends = [row for row in _records(
        _transcript_path(tmp_path / "state").read_bytes())
            if row["type"] == "command_end"]
    assert len(ends) == 1
    assert ends[0]["transition_response"] == transition
    assert ends[0]["error_category"] == category
    assert _value(result, "error_category") == category
    assert ends[0]["observed_state"] is None
    assert ends[0]["returncode"] == exit_code
    if transition.endswith("_successfully"):
        assert ends[0]["framing_complete"] is True
        assert ends[0]["timed_out"] is False
        assert ends[0]["stdout_truncated"] is ends[0]["stderr_truncated"] is False
        assert _value(result, "framing_complete") is True
    else:
        assert ends[0]["transition_response"] not in ("disabled_successfully", "enabled_successfully")
    if exit_code:
        assert ends[0]["framing_complete"] is False
        assert _value(result, "framing_complete") is False
    peer.assert_reaped()


@pytest.mark.parametrize("scenario", [
    {"duplicate_echo": True}, {"missing_echo": True},
    {"final_prompt": "foreign#"}, {"missing_exit_echo": True},
])
def test_executable_framing_failure_records_unknown_not_payload_success(tmp_path, peer_factory, scenario):
    peer = peer_factory(**scenario)
    transport, unused = _transport(tmp_path, peer)
    result = _command(transport)
    ends = [row for row in _records(_transcript_path(tmp_path / "state").read_bytes())
            if row["type"] == "command_end"]
    assert len(ends) == 1
    assert ends[0]["observed_state"] == "unknown"
    assert ends[0]["framing_complete"] is False
    assert _value(result, "framing_complete") is False
    peer.assert_reaped()


def test_escaped_session_descendant_never_outlives_clean_transport_result(tmp_path, peer_factory):
    peer = peer_factory(child=True, escaped=True)
    transport, unused = _transport(tmp_path, peer)
    started = time.monotonic()
    result = _command(transport, timeout=0.4)
    assert time.monotonic() - started < 0.8
    escaped = [row for row in peer.events() if row.get("binary") == "descendant"]
    assert len(escaped) == 1 and escaped[0]["session"] == escaped[0]["pid"]
    if Path("/proc/%d" % escaped[0]["pid"]).exists():
        assert _value(result, "error_category") == "descendant_unreaped"
        assert _value(result, "framing_complete") is False
        transport.cancel_and_reap(time.monotonic() + 0.3)
    peer.assert_reaped()


def test_transport_clips_later_phase_deadline_to_original_session(tmp_path, peer_factory):
    peer = peer_factory(hang="command")
    session_deadline = time.monotonic() + 0.25
    transport, unused = _transport(tmp_path, peer, overrides={"session_deadline": session_deadline})
    result = _command(transport, timeout=2)
    assert time.monotonic() < session_deadline + 0.35
    assert _value(result, "timed_out") is True
    assert _value(result, "error_category") == "timeout"
    peer.assert_reaped()


@pytest.mark.parametrize("failure", ["timeout", "signal", "memory"])
def test_scanner_process_resource_failures_never_become_unsigned_admission(tmp_path, monkeypatch, failure):
    import subprocess
    module = _module()
    path, snapshots = _wrapper(tmp_path)
    monkeypatch.setattr(module, "ARCHIVE_SCAN_WALL_SECONDS", 0.1)
    original = subprocess.Popen
    children = []
    scripts = {
        "timeout": "import signal; signal.alarm(2); signal.pause()",
        "signal": "import os,signal; os.kill(os.getpid(),signal.SIGKILL)",
        "memory": "import resource; resource.setrlimit(resource.RLIMIT_AS,(16777216,16777216)); x=bytearray(33554432)",
    }
    def launch(argv, *args, **kwargs):
        child = original([sys.executable, "-c", scripts[failure]], *args, **kwargs)
        children.append(child)
        return child
    monkeypatch.setattr(subprocess, "Popen", launch)
    started = time.monotonic()
    try:
        with _failure() as error:
            with _admit(path, snapshots):
                pytest.fail("failed scanner admitted a wrapper")
        assert _category(error) == "wrapper_scan_failed"
        assert time.monotonic() - started < 1
        assert len(children) == 1 and children[0].poll() is not None
        assert list(snapshots.iterdir()) == []
    finally:
        for child in children:
            if child.poll() is None: child.kill()
            child.wait(timeout=1)


def test_policy_helper_split_overlapping_secrets_are_sanitized_without_raw_temp_capture(tmp_path, peer_factory, monkeypatch):
    _module()
    peer = peer_factory()
    real_policy = Path(__file__).resolve().parents[2] / "lab" / "iris-ssh-policy.sh"
    policy = tmp_path / "policy-fixture.sh"
    # The wrapper produces helper diagnostics, then delegates all SSH policy
    # decisions to the unchanged real helper. No output-capture file is used.
    program = "import os; data=b'overlap-SECRETabc overlap-SECRET\\n'; [(os.write(fd,bytes([c]))) for fd in (1,2) for c in data]"
    import shlex
    policy.write_text(shlex.quote(sys.executable) + " -c " + shlex.quote(program) + "\n. " + shlex.quote(str(real_policy)) + "\n")
    credentials = {"DEVICE_PASS": "overlap-SECRET", "DEVICE_SSH_PASS": "overlap-SECRETabc"}
    # Observe create/move events at launch, including files removed before the
    # command returns. The fixed known-hosts policy needs no temporary key file.
    import ctypes
    import subprocess
    libc = ctypes.CDLL(None, use_errno=True)
    notify_fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
    assert notify_fd >= 0
    original_popen = subprocess.Popen
    observed_launches = []
    def launch(*args, **kwargs):
        directory = tmp_path / "private-tmp"
        for item in [directory] + list(directory.rglob("*")):
            if item.is_dir():
                assert libc.inotify_add_watch(notify_fd, os.fsencode(str(item)), 0x100 | 0x80) >= 0
        observed_launches.append(True)
        return original_popen(*args, **kwargs)
    monkeypatch.setattr(subprocess, "Popen", launch)
    try:
        transport, config = _transport(tmp_path, peer, credentials=credentials,
                                      overrides={"ssh_policy_path": str(policy)})
        result = _command(transport)
        events = bytearray()
        while True:
            try:
                chunk = os.read(notify_fd, 4096)
            except BlockingIOError:
                break
            if not chunk: break
            events.extend(chunk)
            assert len(events) <= 16384, "unbounded filesystem activity"
        assert observed_launches
        assert events == b"", "transport created a temporary capture, even if later removed"
    finally:
        os.close(notify_fd)
    raw = _value(result, "stdout") + _value(result, "stderr")
    records = _records(_transcript_path(tmp_path / "state").read_bytes())
    raw += b"".join(base64.b64decode(row["data_b64"]) for row in records if row["type"] == "stream")
    assert b"overlap-SECRET" not in raw
    assert raw.count(b"<redacted>") >= 4
    # All remaining files in the transport's private temporary tree must be
    # policy key material only; no stdout/stderr output capture may remain.
    temporary = Path(config["tmp_dir"])
    if temporary.exists():
        assert not [p for p in temporary.rglob("*") if p.is_file()]
    peer.assert_reaped()



def test_real_scanner_sets_all_resource_limits_before_importing_tarfile(tmp_path, monkeypatch):
    import subprocess
    module = _module()
    path, snapshots = _wrapper(tmp_path)
    report = tmp_path / "scanner-limits.jsonl"
    original = subprocess.Popen
    def launch(argv, *args, **kwargs):
        assert argv[0] == sys.executable
        program = (
            "import json,resource,runpy,sys\n"
            "original=resource.setrlimit\n"
            "def record(which,limits):\n"
            "    with open(%r,'a') as handle: handle.write(json.dumps([which,list(limits),'tarfile' in sys.modules])+'\\n')\n"
            "    return original(which,limits)\n"
            "resource.setrlimit=record\n"
            "args=%r\n"
            "if args[0]=='-m':\n"
            "    name=args[1];sys.argv=args[1:];runpy.run_module(name,run_name='__main__')\n"
            "else:\n"
            "    sys.argv=args;runpy.run_path(args[0],run_name='__main__')\n"
        ) % (str(report), list(argv[1:]))
        return original([sys.executable, "-c", program], *args, **kwargs)
    monkeypatch.setattr(subprocess, "Popen", launch)
    with _admit(path, snapshots) as snapshot:
        assert snapshot.package_sign_present is False
    import resource
    rows = [json.loads(line) for line in report.read_text().splitlines()]
    expected = {resource.RLIMIT_AS: 512*1024*1024, resource.RLIMIT_CPU: 10,
                resource.RLIMIT_CORE: 0, resource.RLIMIT_NOFILE: 16}
    for kind, limit in expected.items():
        matches = [row for row in rows if row[0] == kind]
        assert matches and all(row == [kind, [limit, limit], False] for row in matches)



class _SnapshotWriteFault(object):
    """Intercept only writable snapshot-file I/O, without a private product hook."""
    def __init__(self, monkeypatch, source, directory, boundary):
        import builtins
        import fcntl
        self.source = str(source)
        self.directory = str(directory)
        self.boundary = boundary
        self.injected = []
        self.opened = set()
        self.snapshot_inodes = set()
        original_open, original_fdopen = os.open, os.fdopen
        original_builtin_open, original_io_open = builtins.open, io.open
        original_write, original_fsync = os.write, os.fsync

        def identify(fd):
            try:
                metadata = os.fstat(fd)
                path = os.readlink("/proc/self/fd/%d" % fd)
                if not stat.S_ISREG(metadata.st_mode): return False
                identity = (metadata.st_dev, metadata.st_ino)
                snapshot = os.path.dirname(path) == self.directory
                if path == self.source or snapshot:
                    self.opened.add(identity)
                writable = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
                if snapshot and writable:
                    self.snapshot_inodes.add(identity)
                    return True
            except (OSError, ValueError):
                pass
            return False

        def fail(fd):
            assert identify(fd), "fault was not on the writable regular snapshot"
            metadata = os.fstat(fd)
            self.injected.append((boundary, metadata.st_dev, metadata.st_ino))
            raise OSError(errno.ENOSPC if boundary == "write" else errno.EIO,
                          "injected writable snapshot %s failure" % boundary)

        class File(object):
            def __init__(self, stream): self.stream = stream
            def __getattr__(self, name): return getattr(self.stream, name)
            def __iter__(self): return self
            def __next__(self): return next(self.stream)
            def __enter__(self): self.stream.__enter__(); return self
            def __exit__(self, *args): return self.stream.__exit__(*args)
            def write(self, data):
                if boundary == "write" and identify(self.stream.fileno()) and not self_fault.injected:
                    fail(self.stream.fileno())
                return self.stream.write(data)
            def flush(self):
                if boundary == "flush" and identify(self.stream.fileno()) and not self_fault.injected:
                    fail(self.stream.fileno())
                return self.stream.flush()
        self_fault = self

        def wrap(stream):
            return File(stream) if identify(stream.fileno()) else stream
        def open_fd(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            identify(fd)
            return fd
        def write(fd, data):
            if boundary == "write" and identify(fd) and not self.injected: fail(fd)
            return original_write(fd, data)
        def fsync(fd):
            if boundary == "fsync" and identify(fd) and not self.injected: fail(fd)
            return original_fsync(fd)
        monkeypatch.setattr(os, "open", open_fd)
        monkeypatch.setattr(os, "fdopen", lambda *a, **kw: wrap(original_fdopen(*a, **kw)))
        monkeypatch.setattr(builtins, "open", lambda *a, **kw: wrap(original_builtin_open(*a, **kw)))
        monkeypatch.setattr(io, "open", lambda *a, **kw: wrap(original_io_open(*a, **kw)))
        monkeypatch.setattr(os, "write", write)
        monkeypatch.setattr(os, "fsync", fsync)

    def assert_reached_and_cleaned(self):
        assert len(self.injected) == 1
        assert self.snapshot_inodes and self.opened
        assert Path(self.directory).is_dir()
        assert list(Path(self.directory).iterdir()) == []
        # Descriptor numbers can be reused by unrelated logging/store work;
        # compare inode identities rather than incorrectly requiring EBADF on
        # every historical integer descriptor.
        for name in os.listdir("/proc/self/fd"):
            try:
                metadata = os.fstat(int(name))
            except OSError:
                continue
            assert (metadata.st_dev, metadata.st_ino) not in self.opened, "leaked wrapper/snapshot descriptor"


@pytest.mark.parametrize("boundary", ["write", "flush", "fsync"])
@pytest.mark.parametrize("through_controller", [False, True])
def test_snapshot_write_durability_failure_never_admits_or_advances_controller(
        tmp_path, monkeypatch, boundary, through_controller):
    _module()
    body = _archive(_member(payload=b"snapshot durability fixture"))
    source = tmp_path / "wrapper.tar"
    source.write_bytes(body)
    if through_controller:
        importlib.import_module("iox_verification")
        import test_iox_verification_crash as crash
        crash._authority_layout(tmp_path)
        crash._durable_fixture_json(str(tmp_path / "deployment_records.json"), {"records": {}})
        snapshots = tmp_path / "iox" / "snapshots"
    else:
        snapshots = tmp_path / "snapshots"
        snapshots.mkdir(mode=0o700)
    fault = _SnapshotWriteFault(monkeypatch, source, snapshots, boundary)
    if not through_controller:
        with _failure() as error:
            with _admit(source, snapshots):
                pytest.fail("incomplete snapshot became admitted authority")
        assert _category(error) in ("wrapper_unreadable", "journal_durability")
    else:
        trace, callbacks = [], []
        store = crash._FakeStore(tmp_path, existing=True)
        transport = crash._FakeTransport(crash._Device("enabled"), trace)
        def prepare(*args):
            callbacks.append("prepare")
            pytest.fail("snapshot failure crossed record preparation")
        def mint(*args):
            callbacks.append("token")
            pytest.fail("snapshot failure minted enrollment credentials")
        controller, unused = crash._controller(tmp_path, store, transport,
            enrollment_token_minter=mint,
            credential_resolver=lambda ref: {"device_user": "fixture-user", "device_pass": "fixture-pass", "enable_secret": "fixture-enable"})
        request = crash._AttrDict(action="install", device_id=crash._DEVICE, job_id=crash._JOB,
            target=crash._AttrDict(host=crash._HOST, port=22, platform="iox", model="C9300-48UXM", os_family="xe"),
            credential_ref="credential-crash", record_id=None, teardown_mode="none", wrapper_path=str(source))
        try:
            result = controller.run_install(request, prepare,
                lambda *args: crash._AttrDict(device_identity=crash._BOARD, platform="iox", model="C9300-48UXM", os_family="xe"),
                lambda *args: None, crash._Cancel())
        finally:
            controller.close()
        assert result["result_code"] != 0
        assert result["error_category"] in ("wrapper_unreadable", "journal_durability")
        assert result["record_id"] is None and callbacks == []
        assert all(row[1] == "identity" for row in trace if row[0] == "command_start")
        assert not any(row[0] == "upload" for row in trace)
        assert transport.device.mutations == []
        assert crash._read_json(store.path) == {"records": {}}
    fault.assert_reached_and_cleaned()
    assert source.read_bytes() == body
