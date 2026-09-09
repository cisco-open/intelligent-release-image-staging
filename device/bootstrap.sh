#!/usr/bin/env bash

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

# IRIS bootstrap — run by the IRIS-AGENT EEM timer (60s) inside Guest Shell.
# Self-contained and idempotent; this is the ONLY thing the installer needs to start.
#
# The installer drops files (bundle.tgz, iris-agent.conf, rpc-secret, this script)
# at the guest-share ROOT via IOS copy. Directories created by IOS `mkdir` are
# root-owned and the guest user cannot write into them (SELinux mount), so THIS
# script — running as the guest user — creates the working dir itself and moves
# the dropped files in. Then:
#   1. a freshly dropped bundle.tgz is unpacked (SELinux-safe flags)
#      -> dropping a new bundle on the device IS the agent install/upgrade.
#   2. the aria2c RPC daemon is (re)launched if it isn't running.
#   3. the agent runs once (poll catalog -> download -> verify -> EEM copy-to-root).
set -u
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
case "$SCRIPT_DIR" in
  */guest-share) DEFAULT_SRC="$SCRIPT_DIR" ;;
  *) DEFAULT_SRC="/flash/guest-share" ;;
esac
SRC="${SRC:-$DEFAULT_SRC}"
STAGE="${STAGE:-$SRC/iris}"
export STAGE_DIR="${STAGE_DIR:-$STAGE}"
export IRIS_AGENT_CONF="${IRIS_AGENT_CONF:-$STAGE/iris-agent.conf}"
export IRIS_AGENT_STATE="${IRIS_AGENT_STATE:-$STAGE/iris-agent.state}"

# --- cadence jitter + failure backoff (issue #59) -------------------------
# The EEM watchdog fires this script every 60s on IOS's own clock -- fixed,
# not ours to jitter -- so a fleet installed or reloaded together keeps every
# device's timer in the same phase indefinitely: that is what turns an
# ordinary tick into a fleet-wide burst of policy GETs, heartbeats, and
# tracker re-announces. Two independent, small guards:
#   * JITTER_MAX: a per-tick sleep (0..JITTER_MAX-1s, uniform) right before
#     step 5 spreads the ACTUAL catalog contact within the tick, so
#     simultaneous EEM fires do not turn into a simultaneous burst.
#   * BACKOFF_FILE: after the agent fails outright (catalog unreachable,
#     timed out, or a non-2xx status -- the same shape a saturated server
#     produces), step 5 is SKIPPED on some ticks, exponentially longer up to
#     BACKOFF_MAX, without the EEM timer's own cadence changing. Steps 0-4
#     (local bundle/aria2c/log upkeep) still run every tick regardless --
#     only catalog contact backs off. Bounded well inside the token's
#     multi-day refresh slack (iris_agent.py's needs_refresh docstring), so
#     a run of skipped ticks never strands the device.
JITTER_MAX="${IRIS_TICK_JITTER_MAX:-8}"
BACKOFF_MAX="${IRIS_TICK_BACKOFF_MAX:-600}"
BACKOFF_FILE="$STAGE/.iris-tick-backoff"

# rand_below N -- uniform 0..N-1. python3 is already a hard dependency of
# step 5 below.
rand_below() {
  python3 -c 'import random,sys; print(random.randrange(int(sys.argv[1])))' "$1"
}

# 0. collect freshly dropped files into OUR (guest-owned) working dir. The
# digest is collected before the archive and the installer sends the archive
# last, so a timer tick can wait on an orphan digest but never unpack an
# archive whose evidence has not arrived.
mkdir -p "$STAGE" \
  || { echo "IRIS-BOOTSTRAP: stage is not writable; repair guest-share/iris ownership" >&2; exit 1; }

# EEM can fire again while a slow flash transaction is still in progress. An
# atomic mkdir plus a live PID keeps concurrent ticks out; a process death
# leaves a stale PID that the next tick can remove before transaction recovery.
LOCK="$STAGE/.bundle-lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  lock_pid="$(cat "$LOCK/pid" 2>/dev/null || true)"
  case "$lock_pid" in
    ''|*[!0-9]*) lock_pid="" ;;
  esac
  if [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null; then
    exit 0
  fi
  rm -f "$LOCK/pid" 2>/dev/null || true
  rmdir "$LOCK" 2>/dev/null \
    || { echo "IRIS-BOOTSTRAP: stage is not writable; repair guest-share/iris ownership" >&2; exit 1; }
  mkdir "$LOCK" 2>/dev/null \
    || { echo "IRIS-BOOTSTRAP: stage is not writable; repair guest-share/iris ownership" >&2; exit 1; }
fi
printf '%s\n' "$$" > "$LOCK/pid" \
  || { rmdir "$LOCK" 2>/dev/null || true
       echo "IRIS-BOOTSTRAP: stage is not writable; repair guest-share/iris ownership" >&2; exit 1; }
release_bundle_lock() {
  rm -f "$LOCK/pid" 2>/dev/null || true
  rmdir "$LOCK" 2>/dev/null || true
}
trap release_bundle_lock EXIT
trap 'exit 1' HUP INT TERM

collect_file() {
  _name="$1"
  _destination="${2:-$_name}"
  if [ -e "$SRC/$_name" ] || [ -L "$SRC/$_name" ]; then
    if ! mv -f "$SRC/$_name" "$STAGE/$_destination" 2>/dev/null; then
      # IOS guest-share and the guest-owned stage can be separate filesystems.
      cp -f "$SRC/$_name" "$STAGE/$_destination" 2>/dev/null \
        && rm -f "$SRC/$_name" 2>/dev/null \
        || { echo "IRIS-BOOTSTRAP: stage is not writable; repair guest-share/iris ownership" >&2; return 1; }
    fi
  fi
}
for f in bundle.tgz.sha256 iris-agent.conf rpc-secret iris-catalog.pem \
         iris-instructions.bootstrap; do
  collect_file "$f" || exit 1
done
collect_file iris-signers.allowed_signers .incoming-iris-signers.allowed_signers \
  || exit 1
collect_file bundle.tgz || exit 1
unset f

# All archive inspection, extraction, snapshotting, and promotion happens in
# one Python helper so the archive is hashed and parsed through the same open
# file descriptor. It never asks tar to write a pathname. The only promoted
# paths are the frozen bundle footprint below.
bundle_transaction() {
  python3 - "$@" <<'PY'
import hashlib
import gzip
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import zlib

MAX_ARCHIVE = 32 * 1024 * 1024
MAX_MEMBER = 16 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_MEMBERS = 64
# Include tar headers, per-member block padding, end markers, and ordinary tar
# record padding without allowing gzip metadata or concatenated streams to
# expand without a hard ceiling before tarfile sees them.
MAX_EXPANDED = MAX_TOTAL + 2 * 1024 * 1024
AGENT_FILES = (
    "agent_config.py", "catalog_client.py", "cli_ssh.py",
    "flash_target.py", "flashcheck.py", "instr.py", "iris_agent.py",
    "peer-transfer-hook.sh", "telemetry_report.py", "verify_image.py",
    "xr_deps.py",
)
ROOT_FILES = (
    "aria2c", "bootstrap.sh", "guestshell-start.sh", "rotate-logs.sh",
    "iris-signers.allowed_signers", "iris-root.allowed_signers",
)
ARCHIVE_FILES = tuple("agent/" + name for name in AGENT_FILES) + ROOT_FILES
TOP_LEVEL = (
    "agent", "aria2c", "bootstrap.sh", "guestshell-start.sh",
    "rotate-logs.sh", "iris-signers.allowed_signers",
    "iris-root.allowed_signers",
)


class BundleError(Exception):
    def __init__(self, reason):
        self.reason = reason


def lexists(path):
    return os.path.lexists(path)


def remove_path(path):
    if not lexists(path):
        return
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.unlink(path)


def fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        # Some Guest Shell shared-flash filesystems do not implement directory
        # fsync. Atomic rename remains the required same-filesystem primitive.
        pass


def open_created(path, flags, mode):
    previous_umask = os.umask(0)
    try:
        return os.open(path, flags, mode)
    finally:
        os.umask(previous_umask)


def mkdir_mode(path, mode):
    previous_umask = os.umask(0)
    try:
        os.mkdir(path, mode)
    finally:
        os.umask(previous_umask)


def write_phase(tx, value):
    tmp = os.path.join(tx, ".phase-%d" % os.getpid())
    with open(tmp, "wb") as stream:
        stream.write((value + "\n").encode("ascii"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, os.path.join(tx, "phase"))
    fsync_dir(tx)


def read_phase(tx):
    path = os.path.join(tx, "phase")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return "preparing"
    except OSError:
        return "invalid"
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 32:
            return "invalid"
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(33)
    except OSError:
        return "invalid"
    finally:
        os.close(descriptor)
    try:
        value = data.decode("ascii").strip()
    except UnicodeDecodeError:
        return "invalid"
    return value


def open_regular(path, max_bytes):
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError:
        raise BundleError("invalid-evidence")
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            raise BundleError("invalid-evidence")
        identity = (info.st_dev, info.st_ino, info.st_size,
                    info.st_mtime_ns, info.st_ctime_ns)
        return os.fdopen(fd, "rb"), identity
    except Exception:
        os.close(fd)
        raise


def stream_identity(stream):
    info = os.fstat(stream.fileno())
    return (info.st_dev, info.st_ino, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def files_equal_regular(first, second, max_bytes):
    left = None
    right = None
    try:
        left, left_identity = open_regular(first, max_bytes)
        right, right_identity = open_regular(second, max_bytes)
        if left_identity[2] == 0 or left_identity[2] != right_identity[2]:
            return False
        copied = 0
        while True:
            left_chunk = left.read(65536)
            right_chunk = right.read(65536)
            if left_chunk != right_chunk:
                return False
            if not left_chunk:
                if copied != left_identity[2] \
                        or stream_identity(left) != left_identity \
                        or stream_identity(right) != right_identity:
                    raise BundleError("invalid-evidence")
                return True
            copied += len(left_chunk)
            if copied > max_bytes:
                raise BundleError("invalid-evidence")
    finally:
        if left is not None:
            left.close()
        if right is not None:
            right.close()


def checked_digest(bundle_path, digest_path, directory):
    try:
        digest_stream, digest_identity = open_regular(digest_path, 65)
        with digest_stream:
            raw = digest_stream.read(66)
            if stream_identity(digest_stream) != digest_identity:
                raise BundleError("invalid-evidence")
    except BundleError:
        raise BundleError("invalid-digest")
    if len(raw) != 65 or raw[64:] != b"\n" \
            or re.match(br"\A[0-9a-f]{64}\n\Z", raw) is None:
        raise BundleError("invalid-digest")
    try:
        bundle_stream, bundle_identity = open_regular(bundle_path, MAX_ARCHIVE)
    except BundleError:
        raise BundleError("invalid-archive")
    if bundle_identity[2] == 0:
        bundle_stream.close()
        raise BundleError("invalid-archive")
    try:
        snapshot = tempfile.TemporaryFile(
            prefix=".bundle-compressed-", dir=directory)
    except OSError:
        bundle_stream.close()
        raise BundleError("invalid-archive")
    actual = hashlib.sha256()
    copied = 0
    try:
        while copied < bundle_identity[2]:
            chunk = bundle_stream.read(
                min(1024 * 1024, bundle_identity[2] - copied))
            if not chunk:
                raise BundleError("invalid-archive")
            copied += len(chunk)
            actual.update(chunk)
            snapshot.write(chunk)
        if bundle_stream.read(1) \
                or stream_identity(bundle_stream) != bundle_identity:
            raise BundleError("invalid-archive")
        if actual.hexdigest().encode("ascii") != raw[:64]:
            raise BundleError("digest-mismatch")
        snapshot.flush()
        snapshot.seek(0)
    except Exception:
        snapshot.close()
        raise
    finally:
        bundle_stream.close()
    return snapshot


def tar_number(field):
    # Reject GNU/base-256 numbers and every non-canonical octal form. The
    # production packer emits ordinary octal fields on every supported host.
    if not field or field[0] & 0x80:
        raise BundleError("invalid-archive")
    index = 0
    while index < len(field) and field[index:index + 1] == b" ":
        index += 1
    start = index
    while index < len(field) and field[index:index + 1] in b"01234567":
        index += 1
    if index == start or any(byte not in (0, 32)
                             for byte in bytearray(field[index:])):
        raise BundleError("invalid-archive")
    return int(field[start:index], 8)


def tar_text(field):
    terminator = field.find(b"\0")
    if terminator < 0:
        raw = field
    else:
        if field[terminator + 1:].strip(b"\0"):
            raise BundleError("invalid-archive")
        raw = field[:terminator]
    try:
        value = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise BundleError("invalid-archive")
    if value.encode("utf-8") != raw:
        raise BundleError("invalid-archive")
    return value


def read_exact(stream, size):
    result = bytearray()
    while len(result) < size:
        chunk = stream.read(size - len(result))
        if not chunk:
            break
        result.extend(chunk)
    return bytes(result)


def scan_tar(stream, expanded_size):
    raw_members = []
    seen = set()
    total = 0
    cursor = 0
    zero_blocks = 0
    stream.seek(0)
    while cursor < expanded_size:
        header = read_exact(stream, 512)
        if len(header) != 512:
            raise BundleError("invalid-archive")
        cursor += 512
        if header == b"\0" * 512:
            zero_blocks += 1
            if zero_blocks == 2:
                trailer = stream.read()
                if len(trailer) % 512 or any(byte != 0
                                             for byte in bytearray(trailer)):
                    raise BundleError("invalid-archive")
                break
            continue
        if zero_blocks or len(raw_members) >= MAX_MEMBERS:
            raise BundleError("invalid-archive")

        magic = header[257:263]
        version = header[263:265]
        if magic == b"ustar\0" and version == b"00":
            prefix = tar_text(header[345:500])
        elif magic == b"ustar " and version == b" \0":
            # GNU format uses this area for extensions. Plain short-name
            # archives from the production packer leave it empty.
            if header[345:500] != b"\0" * 155:
                raise BundleError("invalid-archive")
            prefix = ""
        elif header[257:512] == b"\0" * 255:
            prefix = ""
        else:
            raise BundleError("invalid-archive")

        for start, end in ((100, 108), (108, 116), (116, 124),
                           (124, 136), (136, 148), (148, 156)):
            tar_number(header[start:end])
        stored_checksum = tar_number(header[148:156])
        checksum = sum(bytearray(header[:148] + b" " * 8 + header[156:]))
        if checksum != stored_checksum:
            raise BundleError("invalid-archive")

        typeflag = header[156:157]
        if typeflag not in (b"\0", b"0", b"5") \
                or header[157:257] != b"\0" * 100:
            # This rejects PAX/GNU extension records, sparse files, links,
            # devices, and FIFOs before Python's archive parser runs.
            raise BundleError("invalid-archive")
        size = tar_number(header[124:136])
        directory = typeflag == b"5"
        if directory and size:
            raise BundleError("invalid-archive")
        if size > MAX_MEMBER:
            raise BundleError("invalid-archive")

        name = tar_text(header[0:100])
        if prefix:
            name = prefix + "/" + name
        if directory and name.endswith("/"):
            name = name[:-1]
        elif not directory and name.endswith("/"):
            raise BundleError("invalid-archive")
        parts = name.split("/")
        if (not name or name.startswith("/") or "\\" in name
                or any(part in ("", ".", "..") for part in parts)
                or any(ord(char) < 32 or ord(char) == 127 for char in name)
                or name in seen):
            raise BundleError("invalid-archive")
        seen.add(name)

        total += size
        if total > MAX_TOTAL:
            raise BundleError("invalid-archive")
        data_offset = cursor
        padded = ((size + 511) // 512) * 512
        if cursor + padded > expanded_size:
            raise BundleError("invalid-archive")
        raw_members.append((name, directory, size, data_offset))
        stream.seek(padded, os.SEEK_CUR)
        cursor += padded
    if zero_blocks < 2:
        raise BundleError("invalid-archive")
    return raw_members


def bounded_tar_stream(stream, directory):
    expanded = tempfile.TemporaryFile(prefix=".bundle-expanded-", dir=directory)
    expanded_size = 0
    try:
        try:
            with gzip.GzipFile(fileobj=stream, mode="rb") as compressed:
                while True:
                    remaining = MAX_EXPANDED - expanded_size
                    chunk = compressed.read(min(1024 * 1024, remaining + 1))
                    if not chunk:
                        break
                    expanded_size += len(chunk)
                    if expanded_size > MAX_EXPANDED:
                        raise BundleError("invalid-archive")
                    expanded.write(chunk)
        except (OSError, EOFError, zlib.error):
            raise BundleError("invalid-archive")
        expanded.flush()
        raw_members = scan_tar(expanded, expanded_size)
        expanded.seek(0)
        return expanded, raw_members
    except Exception:
        expanded.close()
        raise


def inspect_and_extract(bundle_path, digest_path, new_dir):
    stream = checked_digest(
        bundle_path, digest_path, os.path.dirname(new_dir))
    expected = set(ARCHIVE_FILES)
    seen = set()
    total = 0
    try:
        with stream:
            expanded, raw_members = bounded_tar_stream(
                stream, os.path.dirname(new_dir))
            with expanded:
                try:
                    archive = tarfile.open(fileobj=expanded, mode="r:")
                except (tarfile.TarError, EOFError, OSError):
                    raise BundleError("invalid-archive")
                with archive:
                    members = []
                    for member in archive:
                        members.append(member)
                        if len(members) > MAX_MEMBERS:
                            raise BundleError("invalid-archive")
                    if len(members) != len(raw_members):
                        raise BundleError("invalid-archive")
                    for member, raw_member in zip(members, raw_members):
                        normalized = (member.name[:-1]
                                      if member.isdir()
                                      and member.name.endswith("/")
                                      else member.name)
                        if (normalized, member.isdir(), member.size,
                                member.offset_data) != raw_member:
                            raise BundleError("invalid-archive")
                    for member in members:
                        name = (member.name[:-1]
                                if member.isdir() and member.name.endswith("/")
                                else member.name)
                        parts = name.split("/")
                        if (not name or name.startswith("/") or "\\" in name
                                or any(part in ("", ".", "..")
                                       for part in parts)):
                            raise BundleError("invalid-archive")
                        if name in seen:
                            raise BundleError("invalid-archive")
                        seen.add(name)
                        if name == "agent":
                            if not member.isdir():
                                raise BundleError("invalid-archive")
                            continue
                        if name not in expected or not member.isreg() \
                                or getattr(member, "sparse", None):
                            raise BundleError("invalid-archive")
                        if member.size < 0 or member.size > MAX_MEMBER:
                            raise BundleError("invalid-archive")
                        total += member.size
                        if total > MAX_TOTAL:
                            raise BundleError("invalid-archive")
                    if seen != expected | {"agent"}:
                        raise BundleError("invalid-archive")

                    os.mkdir(new_dir, 0o700)
                    os.mkdir(os.path.join(new_dir, "agent"), 0o700)
                    by_name = dict(((member.name[:-1]
                                     if member.isdir()
                                     and member.name.endswith("/")
                                     else member.name), member)
                                   for member in members)
                    for name in ARCHIVE_FILES:
                        member = by_name[name]
                        source = archive.extractfile(member)
                        if source is None:
                            raise BundleError("invalid-archive")
                        destination = os.path.join(new_dir, *name.split("/"))
                        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        if hasattr(os, "O_NOFOLLOW"):
                            flags |= os.O_NOFOLLOW
                        executable = name in (
                            "aria2c", "bootstrap.sh", "guestshell-start.sh",
                            "rotate-logs.sh", "agent/peer-transfer-hook.sh",
                        )
                        out_fd = os.open(destination, flags,
                                         0o700 if executable else 0o600)
                        copied = 0
                        try:
                            with os.fdopen(out_fd, "wb") as target:
                                while True:
                                    chunk = source.read(1024 * 1024)
                                    if not chunk:
                                        break
                                    copied += len(chunk)
                                    if copied > member.size \
                                            or copied > MAX_MEMBER:
                                        raise BundleError("invalid-archive")
                                    target.write(chunk)
                                target.flush()
                                os.fsync(target.fileno())
                        finally:
                            source.close()
                        if copied != member.size:
                            raise BundleError("invalid-archive")
                    fsync_dir(os.path.join(new_dir, "agent"))
                    fsync_dir(new_dir)
    except BundleError:
        raise
    except (OSError, tarfile.TarError, EOFError):
        raise BundleError("invalid-archive")


def validate_prior(prior):
    files = os.path.join(prior, "files")
    absent = os.path.join(prior, "absent")
    if not os.path.isdir(files) or os.path.islink(files) \
            or not os.path.isdir(absent) or os.path.islink(absent):
        raise BundleError("transaction-invalid")
    allowed = set(TOP_LEVEL)
    try:
        if not set(os.listdir(files)).issubset(allowed) \
                or not set(os.listdir(absent)).issubset(allowed):
            raise BundleError("transaction-invalid")
    except OSError:
        raise BundleError("transaction-invalid")
    for name in TOP_LEVEL:
        saved = os.path.join(files, name)
        marker = os.path.join(absent, name)
        has_saved = lexists(saved)
        has_marker = lexists(marker)
        if has_saved == has_marker:
            raise BundleError("transaction-invalid")
        if has_marker:
            try:
                marker_info = os.lstat(marker)
            except OSError:
                raise BundleError("transaction-invalid")
            if not stat.S_ISREG(marker_info.st_mode) \
                    or marker_info.st_size != 0:
                raise BundleError("transaction-invalid")


def validate_capture_prior(prior):
    files = os.path.join(prior, "files")
    absent = os.path.join(prior, "absent")
    if not os.path.isdir(prior) or os.path.islink(prior) \
            or set(os.listdir(prior)) != {"files", "absent"} \
            or not os.path.isdir(files) or os.path.islink(files) \
            or not os.path.isdir(absent) or os.path.islink(absent):
        raise BundleError("transaction-invalid")
    allowed = set(TOP_LEVEL)
    try:
        saved_names = set(os.listdir(files))
        absent_names = set(os.listdir(absent))
    except OSError:
        raise BundleError("transaction-invalid")
    if not saved_names.issubset(allowed) \
            or not absent_names.issubset(allowed) \
            or saved_names & absent_names:
        raise BundleError("transaction-invalid")
    for name in absent_names:
        try:
            marker_info = os.lstat(os.path.join(absent, name))
        except OSError:
            raise BundleError("transaction-invalid")
        if not stat.S_ISREG(marker_info.st_mode) or marker_info.st_size != 0:
            raise BundleError("transaction-invalid")


def copy_snapshot(source, destination):
    try:
        before = os.lstat(source)
    except OSError:
        raise BundleError("transaction-invalid")
    if stat.S_ISLNK(before.st_mode):
        try:
            target = os.readlink(source)
            os.symlink(target, destination)
            after = os.lstat(source)
        except OSError:
            raise BundleError("transaction-invalid")
        if (before.st_dev, before.st_ino, before.st_mode,
                before.st_mtime_ns, before.st_ctime_ns) != \
                (after.st_dev, after.st_ino, after.st_mode,
                 after.st_mtime_ns, after.st_ctime_ns):
            raise BundleError("transaction-invalid")
        return
    if stat.S_ISREG(before.st_mode):
        source_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            source_flags |= os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            source_flags |= os.O_NONBLOCK
        source_fd = None
        destination_fd = None
        try:
            source_fd = os.open(source, source_flags)
            opened = os.fstat(source_fd)
            if not stat.S_ISREG(opened.st_mode) \
                    or (opened.st_dev, opened.st_ino) != \
                    (before.st_dev, before.st_ino):
                raise BundleError("transaction-invalid")
            destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                destination_flags |= os.O_NOFOLLOW
            destination_fd = open_created(
                destination, destination_flags, stat.S_IMODE(opened.st_mode))
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_fd, view)
                    if written <= 0:
                        raise BundleError("transaction-invalid")
                    view = view[written:]
            after = os.fstat(source_fd)
            if (opened.st_dev, opened.st_ino, opened.st_size,
                    opened.st_mtime_ns, opened.st_ctime_ns) != \
                    (after.st_dev, after.st_ino, after.st_size,
                     after.st_mtime_ns, after.st_ctime_ns):
                raise BundleError("transaction-invalid")
            os.fsync(destination_fd)
        except BundleError:
            raise
        except OSError:
            raise BundleError("transaction-invalid")
        finally:
            if destination_fd is not None:
                os.close(destination_fd)
            if source_fd is not None:
                os.close(source_fd)
        return
    if stat.S_ISDIR(before.st_mode):
        try:
            mkdir_mode(destination, stat.S_IMODE(before.st_mode))
            for name in sorted(os.listdir(source)):
                if name in ("", ".", "..") or "/" in name:
                    raise BundleError("transaction-invalid")
                copy_snapshot(os.path.join(source, name),
                              os.path.join(destination, name))
            fsync_dir(destination)
            after = os.lstat(source)
        except BundleError:
            raise
        except OSError:
            raise BundleError("transaction-invalid")
        if (before.st_dev, before.st_ino, before.st_mode,
                before.st_mtime_ns, before.st_ctime_ns) != \
                (after.st_dev, after.st_ino, after.st_mode,
                 after.st_mtime_ns, after.st_ctime_ns):
            raise BundleError("transaction-invalid")
        return
    raise BundleError("transaction-invalid")


def prepare_restore(tx, files):
    restore = os.path.join(tx, "restore")
    remove_path(restore)
    os.mkdir(restore, 0o700)
    for name in TOP_LEVEL:
        saved = os.path.join(files, name)
        if lexists(saved):
            copy_snapshot(saved, os.path.join(restore, name))
    fsync_dir(restore)
    fsync_dir(tx)
    return restore


def complete_rollback(stage, tx):
    completed = os.path.join(stage, ".bundle-rollback-complete")
    remove_path(completed)
    fsync_dir(stage)
    os.replace(tx, completed)
    fsync_dir(stage)
    remove_path(completed)
    fsync_dir(stage)


def rollback(stage, tx):
    prior = os.path.join(tx, "prior")
    validate_prior(prior)
    files = os.path.join(prior, "files")
    restore = prepare_restore(tx, files)
    for name in TOP_LEVEL:
        saved = os.path.join(files, name)
        live = os.path.join(stage, name)
        remove_path(live)
        if lexists(saved):
            restored = os.path.join(restore, name)
            if not lexists(restored):
                raise BundleError("transaction-invalid")
            os.replace(restored, live)
    fsync_dir(stage)
    complete_rollback(stage, tx)


def rollback_capture(stage, tx):
    # No new runtime path is installed before phase=promoting. Restore any
    # old path already moved during an interrupted capture. Rebuild every
    # restore from the immutable captured bytes so another interruption can
    # retry without consuming the only copy.
    prior = os.path.join(tx, "prior")
    validate_capture_prior(prior)
    files = os.path.join(prior, "files")
    restore = prepare_restore(tx, files)
    for name in TOP_LEVEL:
        saved = os.path.join(files, name)
        marker = os.path.join(prior, "absent", name)
        live = os.path.join(stage, name)
        if lexists(saved):
            remove_path(live)
            os.replace(os.path.join(restore, name), live)
        elif lexists(marker):
            remove_path(live)
    fsync_dir(stage)
    complete_rollback(stage, tx)


def discard_preparing(stage, tx):
    # Capture has not begun, so no live runtime path has moved yet.
    complete_rollback(stage, tx)


def recover(stage):
    tx = os.path.join(stage, ".bundle-transaction")
    completed = os.path.join(stage, ".bundle-rollback-complete")
    if lexists(completed):
        remove_path(completed)
        fsync_dir(stage)
    if not lexists(tx):
        print("none")
        return
    if not os.path.isdir(tx) or os.path.islink(tx):
        raise BundleError("transaction-invalid")
    phase = read_phase(tx)
    if phase == "committed":
        print("committed")
        return
    if phase in ("promoting",):
        rollback(stage, tx)
        print("rolled-back")
        return
    if phase == "capturing":
        rollback_capture(stage, tx)
        print("rolled-back")
        return
    if phase == "preparing":
        discard_preparing(stage, tx)
        print("rolled-back")
        return
    raise BundleError("transaction-invalid")


def install(stage, bundle_path, digest_path, signer_path):
    tx = os.path.join(stage, ".bundle-transaction")
    if lexists(tx):
        raise BundleError("transaction-invalid")
    os.mkdir(tx, 0o700)
    write_phase(tx, "preparing")
    try:
        new_dir = os.path.join(tx, "new")
        inspect_and_extract(bundle_path, digest_path, new_dir)
        try:
            signer_matches = files_equal_regular(
                signer_path,
                os.path.join(new_dir, "iris-signers.allowed_signers"),
                65536,
            )
        except BundleError:
            raise BundleError("invalid-signer")
        if not signer_matches:
            raise BundleError("signer-mismatch")
        prior = os.path.join(tx, "prior")
        files = os.path.join(prior, "files")
        absent = os.path.join(prior, "absent")
        os.makedirs(files, 0o700)
        os.makedirs(absent, 0o700)
        write_phase(tx, "capturing")
        for name in TOP_LEVEL:
            live = os.path.join(stage, name)
            if lexists(live):
                os.replace(live, os.path.join(files, name))
            else:
                marker = os.path.join(absent, name)
                with open(marker, "wb") as stream:
                    stream.flush()
                    os.fsync(stream.fileno())
        fsync_dir(files)
        fsync_dir(absent)
        write_phase(tx, "promoting")

        # Put every dependency in place before the executable agent entrypoint.
        for name in ROOT_FILES:
            os.replace(os.path.join(new_dir, name), os.path.join(stage, name))
        new_agent = os.path.join(new_dir, "agent")
        live_agent = os.path.join(stage, "agent")
        os.mkdir(live_agent, 0o700)
        for name in AGENT_FILES:
            if name == "iris_agent.py":
                continue
            os.replace(os.path.join(new_agent, name), os.path.join(live_agent, name))
        os.replace(os.path.join(new_agent, "iris_agent.py"),
                   os.path.join(live_agent, "iris_agent.py"))
        fsync_dir(live_agent)
        fsync_dir(stage)
        print("promoted")
    except Exception as original:
        phase = read_phase(tx) if lexists(tx) else "invalid"
        try:
            if phase == "promoting":
                rollback(stage, tx)
            elif phase == "capturing":
                rollback_capture(stage, tx)
            elif phase == "preparing":
                discard_preparing(stage, tx)
            elif lexists(tx):
                raise BundleError("transaction-invalid")
        except Exception:
            raise BundleError("rollback-failed")
        raise original


def commit(stage):
    tx = os.path.join(stage, ".bundle-transaction")
    if read_phase(tx) != "promoting":
        raise BundleError("transaction-invalid")
    write_phase(tx, "committed")
    print("committed")


def finalize(stage):
    tx = os.path.join(stage, ".bundle-transaction")
    if read_phase(tx) != "committed":
        raise BundleError("transaction-invalid")
    prior = os.path.join(tx, "prior")
    previous = os.path.join(stage, ".bundle-previous")
    if lexists(prior):
        remove_path(previous)
        os.replace(prior, previous)
    elif not lexists(previous):
        raise BundleError("transaction-invalid")
    remove_path(tx)
    fsync_dir(stage)
    print("finalized")


def main():
    operation = sys.argv[1]
    stage = sys.argv[2]
    if operation == "recover":
        recover(stage)
    elif operation == "install":
        install(stage, sys.argv[3], sys.argv[4], sys.argv[5])
    elif operation == "rollback":
        tx = os.path.join(stage, ".bundle-transaction")
        rollback(stage, tx)
        print("rolled-back")
    elif operation == "commit":
        commit(stage)
    elif operation == "finalize":
        finalize(stage)
    else:
        raise BundleError("transaction-invalid")


try:
    main()
except BundleError as exc:
    print(exc.reason)
    sys.exit(1)
except Exception:
    print("install-failed")
    sys.exit(1)
PY
}

sync_eem_bootstrap() {
  [ -f "$STAGE/bootstrap.sh" ] && [ ! -L "$STAGE/bootstrap.sh" ] || return 1
  cp -f "$STAGE/bootstrap.sh" "$SRC/bootstrap.sh.new" 2>/dev/null \
    && mv -f "$SRC/bootstrap.sh.new" "$SRC/bootstrap.sh" 2>/dev/null
}

recovery="$(bundle_transaction recover "$STAGE")" || {
  echo "IRIS-BOOTSTRAP: bundle transaction recovery failed" >&2
  exit 1
}
case "$recovery" in
  rolled-back)
    # A crash may have happened after the EEM-facing rename but before commit.
    # Restore that entry from the recovered runtime when one existed.
    if [ -f "$STAGE/bootstrap.sh" ] && [ ! -L "$STAGE/bootstrap.sh" ]; then
      sync_eem_bootstrap \
        || { echo "IRIS-BOOTSTRAP: bundle transaction recovery failed" >&2; exit 1; }
    fi
    echo "IRIS-BOOTSTRAP: recovered interrupted bundle install" ;;
  committed)
    sync_eem_bootstrap \
      || { echo "IRIS-BOOTSTRAP: bundle transaction recovery failed" >&2; exit 1; }
    bundle_transaction finalize "$STAGE" >/dev/null \
      || { echo "IRIS-BOOTSTRAP: bundle transaction recovery failed" >&2; exit 1; }
    rm -f "$STAGE/bundle.tgz" "$STAGE/bundle.tgz.sha256" \
          "$STAGE/.incoming-iris-signers.allowed_signers" 2>/dev/null || true ;;
  none) ;;
  *) echo "IRIS-BOOTSTRAP: bundle transaction recovery failed" >&2; exit 1 ;;
esac

reject_bundle() {
  _reason="$1"
  rm -f "$STAGE/bundle.tgz" "$STAGE/bundle.tgz.sha256" \
        "$STAGE/.incoming-iris-signers.allowed_signers" \
        "$SRC/bundle.tgz" "$SRC/bundle.tgz.sha256" \
        "$SRC/iris-signers.allowed_signers" 2>/dev/null || true
  echo "IRIS-BOOTSTRAP: bundle rejected ($_reason)" >&2
}

# 1. Verify, inspect, and promote a newly dropped bundle. A digest by itself
# waits for the installer's bundle-last copy. Every definitive rejection
# removes the pair and falls through to the prior runnable agent.
bundle_updated=0
bundle_rejected=0
if [ -e "$STAGE/bundle.tgz" ] || [ -L "$STAGE/bundle.tgz" ]; then
  if [ ! -e "$STAGE/bundle.tgz.sha256" ] && [ ! -L "$STAGE/bundle.tgz.sha256" ]; then
    reject_bundle missing-digest
    bundle_rejected=1
  else
    result="$(bundle_transaction install "$STAGE" "$STAGE/bundle.tgz" \
               "$STAGE/bundle.tgz.sha256" \
               "$STAGE/.incoming-iris-signers.allowed_signers")" || {
      case "$result" in
        invalid-digest|digest-mismatch|invalid-archive|invalid-signer|signer-mismatch)
          reason="$result" ;;
        rollback-failed)
          reject_bundle install-failed
          echo "IRIS-BOOTSTRAP: bundle rollback failed; refusing to launch" >&2
          exit 1 ;;
        *) reason="install-failed" ;;
      esac
      reject_bundle "$reason"
      bundle_rejected=1
    }
    if [ "$bundle_rejected" -eq 0 ]; then
      # Commit the staged runtime before changing the EEM-facing launcher. If
      # the sibling rename then fails, retain phase=committed so the next old
      # launcher tick retries that rename and finalizes; do not roll a durable
      # runtime back or launch through a mixed pair.
      if ! bundle_transaction commit "$STAGE" >/dev/null; then
        bundle_transaction rollback "$STAGE" >/dev/null 2>&1 \
          || { echo "IRIS-BOOTSTRAP: bundle rollback failed; refusing to launch" >&2; exit 1; }
        reject_bundle install-failed
        bundle_rejected=1
      elif ! sync_eem_bootstrap; then
        echo "IRIS-BOOTSTRAP: bundle transaction recovery failed" >&2
        exit 1
      else
        rm -f "$STAGE/bundle.tgz" "$STAGE/bundle.tgz.sha256" \
              "$STAGE/.incoming-iris-signers.allowed_signers" 2>/dev/null || true
        bundle_transaction finalize "$STAGE" >/dev/null \
          || { echo "IRIS-BOOTSTRAP: bundle transaction recovery failed" >&2; exit 1; }
        bundle_updated=1
      fi
    fi
  fi
fi

if [ "$bundle_rejected" -eq 1 ] \
    && { [ ! -f "$STAGE/agent/iris_agent.py" ] || [ -L "$STAGE/agent/iris_agent.py" ]; }; then
  exit 1
fi

# 2. reconcile aria2c's RPC secret with the one the agent uses.
# The installer bakes rpc-secret EMPTY; the agent fetches the real value on its
# first token-refresh and writes it into iris-agent.conf. guestshell-start.sh
# seeds aria2c from the rpc-secret FILE, so sync the file from the conf and
# bounce a stale aria2c — otherwise aria2c runs with the wrong secret and the
# agent's addTorrent is rejected (the device never joins the swarm).
if [ -f "$STAGE/iris-agent.conf" ]; then
  conf_sec="$(sed -n 's/^[[:space:]]*rpc_secret[[:space:]]*=[[:space:]]*//p' \
                "$STAGE/iris-agent.conf" | tr -d '[:space:]')"
  file_sec="$(tr -d '[:space:]' < "$STAGE/rpc-secret" 2>/dev/null || true)"
  if [ -n "$conf_sec" ] && [ "$conf_sec" != "$file_sec" ]; then
    printf '%s\n' "$conf_sec" > "$STAGE/rpc-secret"
    pkill -f 'aria2c.*enable-rpc' 2>/dev/null || true   # relaunched below with the new secret
    # wait for the dying process so pgrep in step 3 does not see it and skip the relaunch
    _w=0
    while pgrep -f 'aria2c.*enable-rpc' >/dev/null 2>&1 && [ "$_w" -lt 5 ]; do
      sleep 1; _w=$((_w + 1))
    done
    unset _w
  fi
fi

# 2b. persist optional aria2c launch overrides an operator set in
# iris-agent.conf into guestshell-start.sh's process environment (issue
# #122). Guest Shell has no other route for these: guestshell-start.sh only
# reads its OWN live process environment on each 60s EEM tick, so a value
# set any other way (e.g. edited into the guest user's shell profile) is
# lost the moment that tick's process exits, and never survives a reload at
# all. iris-agent.conf is already the agent's persisted, reboot-durable
# config file (rpc_secret above is synced from the very same file) and
# agent_config.load()/write_conf() already round-trip a key they don't
# recognize (device/agent/agent_config.py), so an operator can set
# `iris_log = on` (or `rpc_port`) there with nothing more than
# a text edit, on an already-deployed device, with no reinstall and no
# change to a file the agent rewrites out from under them -- the NEXT EEM
# tick picks it up. This covers `RPC_PORT` too: it had the identical gap
# before `IRIS_LOG` made it operator-relevant.
#
# Read raw with sed, exactly like the rpc_secret line above -- never eval'd,
# so there is no path from a malformed or hostile conf value to shell
# execution -- and validated before export. An invalid value is dropped
# (with a warning) rather than exported, so guestshell-start.sh's own
# built-in default takes over: the same fail-closed posture IRIS_LOG already
# documents there (garbage stays off, never on).
conf_value() {
  # $1 = key. Last matching line wins, matching agent_config.load()'s
  # last-value-wins semantics for a repeated key. Never eval'd, and $1 is
  # always one of our own literal key names below, never conf content.
  sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" \
      "$STAGE/iris-agent.conf" 2>/dev/null | tail -n1 | tr -d '[:space:]'
}

if [ -f "$STAGE/iris-agent.conf" ]; then
  _v="$(conf_value iris_log)"
  if [ -n "$_v" ]; then
    case "$_v" in
      *[!A-Za-z0-9]*)
        echo "IRIS-BOOTSTRAP: ignoring invalid iris_log in iris-agent.conf: $_v" >&2 ;;
      *) export IRIS_LOG="$_v" ;;
    esac
  fi

  _v="$(conf_value rpc_port)"
  if [ -n "$_v" ]; then
    case "$_v" in
      *[!0-9]*)
        echo "IRIS-BOOTSTRAP: ignoring invalid rpc_port in iris-agent.conf: $_v" >&2 ;;
      *)
        if [ "$_v" -ge 1 ] && [ "$_v" -le 65535 ]; then
          export RPC_PORT="$_v"
        else
          echo "IRIS-BOOTSTRAP: ignoring out-of-range rpc_port in iris-agent.conf: $_v" >&2
        fi
        ;;
    esac
  fi

  unset _v
fi

# 3. keep the BitTorrent daemon up.
# Delegate unconditionally: guestshell-start.sh is idempotent — it probes the
# RPC first and exits 0 when aria2c is already SERVING. Gating this on
# `pgrep aria2c` instead (process existence) deadlocked devices in the field
# (2026-08-20): an aria2c that was alive but not answering RPC blocked its own
# relaunch, so the agent hit ECONNREFUSED on every 60s tick and crashed before
# its first heartbeat — invisible until the stale process happened to die.
# Health, not liveness, is the thing worth checking.
# A FAILED launch must not abort bootstrap: the agent (step 5) is the device's
# only path back to the catalog, so exiting here turns any aria2c launch
# regression into a silent device (the 2026-08-20 empty-rpc-secret incident
# was invisible for exactly this reason). Record the failure and continue —
# the agent tolerates a down RPC and heartbeats stage_error instead.
if [ -f "$STAGE/guestshell-start.sh" ]; then
  if bash "$STAGE/guestshell-start.sh"; then
    rm -f "$STAGE/aria2c-launch-failed"
  else
    echo "IRIS-BOOTSTRAP: failed to launch aria2c; continuing so the agent still heartbeats" >&2
    date -u '+%Y-%m-%dT%H:%M:%SZ' > "$STAGE/aria2c-launch-failed" 2>/dev/null || :
  fi
fi

# 4. trim the aria2c log so it never fills flash (Guest Shell mode)
# Rotation is ancillary maintenance: a permissions/mktemp/filesystem error
# here must not stop step 5 — the agent is the device's only path back to the
# catalog (same rationale as the daemon-launch handling above), so warn and
# keep going rather than silencing the device on every EEM tick.
if [ -f "$STAGE/rotate-logs.sh" ]; then
  bash "$STAGE/rotate-logs.sh" "$STAGE/aria2c.log" \
    || echo "IRIS-BOOTSTRAP: log rotation failed; continuing so the agent still heartbeats" >&2
fi

# 5. run the agent control plane once -- jittered, and skipped while backing
#    off from a recent failure (see the block near the top of this script).
if [ -f "$STAGE/agent/iris_agent.py" ]; then
  now="$(date +%s)"
  skip_until=0; streak=0
  if [ -f "$BACKOFF_FILE" ]; then
    read -r skip_until streak < "$BACKOFF_FILE" 2>/dev/null || { skip_until=0; streak=0; }
  fi
  case "$skip_until" in ''|*[!0-9]*) skip_until=0 ;; esac
  case "$streak" in ''|*[!0-9]*) streak=0 ;; esac
  if [ "$now" -lt "$skip_until" ]; then
    echo "IRIS-BOOTSTRAP: backing off catalog contact for $((skip_until - now))s more (failure streak $streak)"
    exit 0
  fi
  jitter="$(rand_below "$JITTER_MAX" 2>/dev/null || echo 0)"
  [ "$jitter" -le 0 ] || sleep "$jitter"
  # Not `exec`: this process needs the exit status back to update the
  # backoff file below, so it must remain a plain wait-able child call.
  python3 "$STAGE/agent/iris_agent.py" --once
  agent_status=$?
  if [ "$agent_status" -eq 0 ]; then
    rm -f "$BACKOFF_FILE"
  else
    streak=$((streak + 1))
    [ "$streak" -le 10 ] || streak=10   # 2**10 * 60s is already far past BACKOFF_MAX
    mult=1; i=0
    while [ "$i" -lt "$streak" ]; do mult=$((mult * 2)); i=$((i + 1)); done
    delay=$((60 * mult))
    [ "$delay" -le "$BACKOFF_MAX" ] || delay="$BACKOFF_MAX"
    printf '%s %s\n' "$(($(date +%s) + delay))" "$streak" > "$BACKOFF_FILE"
  fi
  exit "$agent_status"
fi
[ "$bundle_updated" -eq 0 ] || {
  echo "IRIS-BOOTSTRAP: unpacked bundle lacks $STAGE/agent/iris_agent.py" >&2
  exit 1
}
