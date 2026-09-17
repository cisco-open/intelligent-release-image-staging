#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Authenticated XR-host HTTPS staging; no secrets in SSH/curl arguments."""
import contextlib
import base64
import hashlib
import os
from pathlib import Path
import re
import secrets
import selectors
import select
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit


def artifact_base(env):
    catalog = urlsplit(env["CATALOG_URL"])
    host = catalog.hostname
    if not host:
        raise ValueError("missing artifact host")
    if ":" in host:
        host = "[" + host + "]"
    base = env.get("IRIS_ARTIFACT_URL") or "https://%s:%s" % (
        host, env.get("IRIS_ARTIFACTS_PORT", "8000"))
    parsed = urlsplit(base)
    if (parsed.scheme != "https" or not parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment or
            parsed.path not in ("", "/") or
            re.search(r'[\s"\\]', base) or not 1 <= (parsed.port or 443) <= 65535):
        raise ValueError("invalid artifact HTTPS origin")
    return base.rstrip("/")


@contextlib.contextmanager
def publish(root, device, sources):
    """Private, device-bound snapshots removed on every normal exit."""
    directory = Path(root)
    if not directory.is_absolute() or directory.resolve() != directory:
        raise ValueError("artifact root must be an absolute non-symlink path")
    for part in ("staging", device):
        directory = directory / part
        directory.mkdir(mode=0o700, exist_ok=True)
        st = directory.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
            raise ValueError("unsafe artifact staging directory")
    paths = []
    try:
        entries = []
        for source, destination in sources:
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as src:
                before = os.fstat(src.fileno())
                if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 2**31:
                    raise ValueError("invalid artifact source")
                out, path = tempfile.mkstemp(prefix="iris-xr-", dir=directory)
                paths.append(path)
                digest = hashlib.sha256()
                total = 0
                with os.fdopen(out, "wb") as dst:
                    while True:
                        block = src.read(65536)
                        if not block:
                            break
                        total += len(block)
                        if total > before.st_size:
                            raise ValueError("artifact changed")
                        digest.update(block)
                        dst.write(block)
                    dst.flush()
                    os.fsync(dst.fileno())
                after = os.fstat(src.fileno())
                if (total != before.st_size or any(getattr(before, key) != getattr(after, key)
                        for key in ("st_size", "st_mtime_ns", "st_ctime_ns"))):
                    raise ValueError("artifact changed")
                entries.append(("staging/%s/%s" % (device, Path(path).name),
                                destination, digest.hexdigest()))
        yield entries
    finally:
        for path in paths:
            os.unlink(path)


def remote_script(base, device, token, certificate, entries):
    for value in (device, token):
        if not re.fullmatch(r"[A-Za-z0-9._~+:/=-]+", value):
            raise ValueError("unsafe authentication value")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", device):
        raise ValueError("unsafe device id")
    if (len(certificate) > 65536 or "PRIVATE KEY" in certificate or
            "-----BEGIN CERTIFICATE-----" not in certificate):
        raise ValueError("public certificate required")
    # A quoted heredoc keeps certificate/authentication bytes out of process argv.
    boundary = "IRIS_" + secrets.token_hex(16)
    if boundary in certificate:
        raise ValueError("invalid certificate delimiter")
    lines = ["set -eu", "umask 077", "command -v curl >/dev/null",
             "command -v sha256sum >/dev/null",
             "work=$(mktemp -d /misc/disk1/.iris-https.XXXXXXXX)",
             "trap 'rm -rf -- \"$work\"' EXIT",
             "cat >\"$work/ca.pem\" <<'" + boundary + "'",
             certificate.rstrip(), boundary]
    for index, (relative, destination, digest) in enumerate(entries):
        if (not re.fullmatch(r"staging/[A-Za-z0-9._:-]+/iris-xr-[A-Za-z0-9_-]+", relative) or
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", destination) or
                not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("invalid transfer plan")
        url = base + "/v1/devices/" + device + "/artifacts/" + relative
        lines += [
            # -q must be first: ignore any operator curlrc (including insecure).
            'curl -q --fail --silent --show-error --proto =https --connect-timeout 15 --max-time 300 --cacert "$work/ca.pem" --output "$work/file%d" --config - 2>"$work/error" <<\'%s\'' % (index, boundary),
            'url = "%s"' % url, 'user = "%s:%s"' % (device, token), boundary,
            'printf \'%s  %%s/file%d\\n\' "$work" | sha256sum -c - >/dev/null' % (digest, index),
            '[ ! -L /misc/disk1/%s ] && [ ! -d /misc/disk1/%s ]' % (destination, destination)]
    lines += ['[ ! -L /misc/disk1/iris-catalog.pem ] && [ ! -d /misc/disk1/iris-catalog.pem ]']
    for index, (_, destination, _) in enumerate(entries):
        lines.append('mv -f -- "$work/file%d" /misc/disk1/%s' % (index, destination))
    lines += ['mv -f -- "$work/ca.pem" /misc/disk1/iris-catalog.pem', 'exit 0']
    # Parse the whole function before executing: a failed fetch must not leave
    # unread shell lines behind for the XR CLI to interpret after bash exits.
    return "iris_fetch() {\n" + "\n".join(lines) + "\n}\niris_fetch\n"


def transfer(argv, script, timeout=660):
    """Enter XR bash with echo off before sending any secret input.

    SSH retains the caller's host-key policy. Raw terminal output is never
    printed: even an unexpected remote echo must not leak a credential.
    """
    nonce = secrets.token_hex(16)
    ready = ("IRIS_READY_" + nonce).encode()
    done = ("IRIS_DONE_" + nonce + ":").encode()
    child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(child.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    os.set_blocking(child.stdin.fileno(), False)

    def send(data):
        remaining = memoryview(data)
        while remaining:
            budget = deadline - time.monotonic()
            if budget <= 0:
                raise RuntimeError("XR HTTPS input timed out")
            if select.select([], [child.stdin.fileno()], [], min(1, budget))[1]:
                try:
                    count = os.write(child.stdin.fileno(), remaining[:4096])
                except BlockingIOError:
                    continue
                remaining = remaining[count:]

    tail = b""
    state = "login"
    prompt = None
    total = 0
    try:
        while time.monotonic() < deadline:
            if not selector.select(min(1, max(0, deadline - time.monotonic()))):
                continue
            data = os.read(child.stdout.fileno(), 8192)
            if not data:
                break
            total += len(data)
            if total > 256 * 1024:
                raise RuntimeError("XR HTTPS output exceeded limit")
            tail = (tail + data.replace(b"\r", b""))[-16384:]
            if state == "login":
                match = re.search(rb"(?:^|\n)(RP/[A-Za-z0-9_./-]+:[A-Za-z0-9_.-]+#)[ \t]*$", tail)
                if match:
                    prompt = match.group(1)
                    bootstrap = ('stty -echo </dev/tty || exit; printf "\\n%s\\n"; '
                                 '/bin/bash /dev/stdin </dev/tty; rc=$?; '
                                 'stty echo </dev/tty; printf "\\n%s%%s\\n" "$rc"\n') % (ready.decode(), done.decode())
                    # XR CLI treats '?' as help and consumes backslashes even
                    # inside quotes. Encode only this PUBLIC shell bootstrap.
                    # Secrets follow on stdin after its echo-disabled marker.
                    command = "echo %s | base64 -d | /bin/bash" % base64.b64encode(bootstrap.encode()).decode()
                    send(("run /bin/bash -c " + shlex.quote(command) + "\n").encode())
                    tail = b""
                    state = "ready"
            elif state == "ready" and re.search(rb"(?:^|\n)" + ready + rb"\n", tail):
                send(script.encode())
                tail = b""
                state = "done"
            elif state == "done":
                match = re.search(rb"(?:^|\n)" + done + rb"([0-9]+)\n", tail)
                if match:
                    if match.group(1) != b"0":
                        raise RuntimeError("XR HTTPS fetch, integrity check, or placement failed")
                    state = "logout"
            if state == "logout" and tail.rstrip().endswith(prompt):
                send(b"exit\n")
                child.stdin.close()
                child.wait(timeout=min(10, max(.1, deadline - time.monotonic())))
                if child.returncode != 0:
                    raise RuntimeError("XR SSH logout failed")
                return
        raise RuntimeError("XR HTTPS session incomplete or timed out during " + state)
    finally:
        selector.close()
        if child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        child.wait()
        if not child.stdin.closed:
            child.stdin.close()
        child.stdout.close()


def main():
    def cancelled(signum, frame):
        raise InterruptedError("XR HTTPS staging cancelled")
    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGHUP, cancelled)
    env = os.environ
    device = env["DEVICE_ID"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", device):
        raise ValueError("unsafe device id")
    base = artifact_base(env)
    with publish(env["IRIS_ARTIFACTS_DIR"], device, [
            (env["XR_RPM_FILE"], env["SOURCE_NAME"] + ".rpm"),
            (env["INSTRUCTION_SNAPSHOT_FILE"], "iris-instructions.bootstrap")]) as entries:
        script = remote_script(base, device, env["CATALOG_TOKEN"],
                               Path(env["CATALOG_CA_FILE"]).read_text(), entries)
        transfer(sys.argv[1:], script)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Neither remote transcripts nor subprocess commands belong in logs.
        print("ERROR: XR HTTPS staging failed (%s); check HTTPS reachability, trust, authentication and storage" % type(exc).__name__, file=sys.stderr)
        sys.exit(1)
