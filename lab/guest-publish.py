#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Publish the eight fixed Guest Shell inputs through a prompt-aware session."""
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time

MAX_OUTPUT = 65536
SESSION_TIMEOUT = 240
PROMPT_TIMEOUT = 30
PUBLISH_TIMEOUT = 180
IOS_PROMPT = re.compile(r"(?:^|\n)([A-Za-z0-9_./:-]+[>#])[ \t]*$")
GUEST_PROMPT = re.compile(r"(?:^|\n)(\[[A-Za-z0-9_@ .~:/-]{1,120}\][#$])[ \t]*$")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
POLICY_SHELL = r'''
set -eu
. "$1"
iris_ssh_policy "$2"
trap iris_ssh_cleanup EXIT
export SSHPASS="$DEVICE_PASS"
sshpass -e ssh -tt -o ConnectTimeout=15 -o NumberOfPasswordPrompts=1 \
  "${IRIS_SSH_OPTS[@]}" -l "$DEVICE_USER" "$2"
'''


class PublicationError(Exception):
    """Only a closed, nonsecret diagnostic is exposed to callers."""

    def __init__(self, category, marker_count=0, transport_status=1):
        self.category = category
        self.marker_count = marker_count
        self.transport_status = transport_status
        super().__init__(category)


def request(host, root, capability, expected):
    if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]{0,252}", host) \
            or root not in ("/flash/guest-share", "/bootflash/guest-share") \
            or not isinstance(capability, str) or not re.fullmatch(r"[0-9a-f]{32}", capability) \
            or not isinstance(expected, (list, tuple)) or len(expected) != 8:
        raise PublicationError("invalid-request")
    maxima = (262144, 65536, 65536, 65536, 65536, 262144, 65, 33554432)
    for index, (row, maximum) in enumerate(zip(expected, maxima)):
        if not isinstance(row, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,7}):[0-9a-f]{64}", row):
            raise PublicationError("invalid-request")
        if not (0 if index == 2 else 1) <= int(row.split(":")[0]) <= maximum:
            raise PublicationError("invalid-request")
    command = "bash " + root + "/.iris-upload-" + capability + "-bootstrap.sh --publish-inputs " + capability
    command += " " + " ".join(expected)
    if len(command) > 1024:
        raise PublicationError("invalid-request")
    return command, "IRIS-INPUTS-PUBLISHED:" + capability + ":" + expected[-1].split(":")[1]


def failure(text, marker):
    """Keep the installer's bounded public classifications, never raw output."""
    count = text.splitlines().count(marker)
    if count > 1:
        return PublicationError("duplicate-marker", count, 0)
    known = (
        ("IRIS-BOOTSTRAP: input publication lock busy; no inputs published", "bootstrap-lock-busy"),
        ("IRIS-BOOTSTRAP: input publication refused; inspect retained inputs", "bootstrap-refused"),
        ("IRIS-BOOTSTRAP: stage is not writable; repair guest-share/iris ownership", "stage-unwritable"),
    )
    for message, category in known:
        if message in text:
            return PublicationError(category, count, 0)
    if re.search(r"% (?:Invalid input|Incomplete command|Ambiguous command)", text):
        return PublicationError("ios-command-rejected", count, 0)
    if re.search(r"(?m)^(?:PermissionError|FileNotFoundError|OSError|ValueError|SyntaxError|TypeError|NameError):", text):
        return PublicationError("python-error", count, 0)
    if not count and marker in text.replace("\n", ""):
        return PublicationError("marker-framing", count, 0)
    return PublicationError("missing-marker", count, 0)


class Session:
    def __init__(self, process, deadline):
        self.process = process
        self.deadline = deadline
        self.selector = selectors.DefaultSelector()
        self.selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        self.selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        self.total = 0
        self.stdout = b""
        self.stderr = b""

    def send(self, command):
        self.process.stdin.write((command + "\n").encode())
        self.process.stdin.flush()

    def read(self, seconds):
        remaining = min(self.deadline, seconds) - time.monotonic()
        if remaining <= 0:
            raise PublicationError("transport-timeout")
        for key, _ in self.selector.select(min(remaining, 0.2)):
            raw = os.read(key.fd, 4096)
            if not raw:
                self.selector.unregister(key.fileobj)
                continue
            self.total += len(raw)
            if self.total > MAX_OUTPUT:
                raise PublicationError("oversized-response", "unknown")
            if key.data == "stdout":
                self.stdout += raw
            else:
                self.stderr += raw

    def receive(self, pattern, seconds=PROMPT_TIMEOUT):
        end = time.monotonic() + seconds
        while True:
            text = ANSI.sub("", self.stdout.decode("utf-8", errors="replace").replace("\r", ""))
            match = pattern.search(text)
            if match:
                self.stdout = b""
                return text, match
            if not self.selector.get_map():
                raise PublicationError("transport-closed")
            self.read(end)

    def finish(self):
        end = time.monotonic() + 15
        while self.selector.get_map():
            self.read(end)


def publish(host, root, capability, expected, *, popen=None, timeout=SESSION_TIMEOUT):
    command, marker = request(host, root, capability, expected)
    env = dict(os.environ)
    user = env.get("DEVICE_USER", "")
    password = env.get("DEVICE_PASS", "")
    enable = env.get("DEVICE_ENABLE") or password
    if not user or len(user) > 128 or any(ord(c) < 32 for c in user) \
            or any(not value or len(value) > 4096 or "\n" in value or "\r" in value or "\0" in value
                   for value in (password, enable)):
        raise PublicationError("invalid-credentials")
    env["LANG"] = "C.UTF-8"
    policy = str(Path(__file__).resolve().with_name("iris-ssh-policy.sh"))
    process = None
    session = None
    reaped = False
    try:
        process = (popen or subprocess.Popen)(
            ["bash", "-c", POLICY_SHELL, "iris-guest-publish", policy, host],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, start_new_session=True, bufsize=0)
        session = Session(process, time.monotonic() + timeout)
        _, match = session.receive(IOS_PROMPT)
        ios = match.group(1)
        if ios.endswith(">"):
            session.send("enable")
            text, match = session.receive(re.compile(r"(?i)password:[ \t]*$|" + IOS_PROMPT.pattern))
            if re.search(r"(?i)password:[ \t]*$", text):
                session.send(enable)
                _, match = session.receive(IOS_PROMPT)
            ios = match.group(1)
        if not ios.endswith("#"):
            raise PublicationError("privilege-refused")
        ios_prompt = re.compile(r"(?:^|\n)" + re.escape(ios) + r"[ \t]*$")
        session.send("terminal length 0")
        session.receive(ios_prompt)
        session.send("guestshell")
        _, match = session.receive(re.compile(GUEST_PROMPT.pattern + "|" + ios_prompt.pattern))
        if match.group(1) is None:
            raise PublicationError("ios-command-rejected", 0, 0)
        guest_prompt = re.compile(r"(?:^|\n)" + re.escape(match.group(1)) + r"[ \t]*$")
        # The long typed line is sent only inside Guest Shell, never through
        # the IOS line editor. There is exactly one publication dispatch.
        session.send(command)
        text, _ = session.receive(guest_prompt, PUBLISH_TIMEOUT)
        if text.splitlines().count(marker) != 1:
            raise failure(text, marker)
        session.send("exit")
        session.receive(ios_prompt)
        session.send("exit")
        session.finish()
        status = process.wait(timeout=5)
        reaped = True
        if status != 0:
            raise PublicationError("transport-error", 1, status)
        return marker
    finally:
        if session is not None:
            session.selector.close()
        if process is not None and not reaped:
            # This unreaped child created its own session. Its PID cannot be
            # reused here; signals target only that owned SSH process group.
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    def abort(signum, frame):
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, signal.SIG_IGN)
        raise PublicationError("aborted", 0, 128 + signum)
    previous = {sig: signal.signal(sig, abort) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        if len(args) != 11:
            raise PublicationError("invalid-request")
        marker = publish(args[0], args[1], args[2], args[3:])
    except PublicationError as error:
        label = "outcome unknown" if error.transport_status else "not proved"
        print("ERROR: Guest Shell publication %s (category=%s, marker-count=%s, transport-status=%d); inspect before retrying" %
              (label, error.category, error.marker_count, error.transport_status), file=sys.stderr)
        return 1
    except Exception:
        print("ERROR: Guest Shell publication outcome unknown (category=transport-error); inspect before retrying", file=sys.stderr)
        return 1
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    print(marker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
