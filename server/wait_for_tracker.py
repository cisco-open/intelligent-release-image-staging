# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Wait for the local tracker listener, then replace this supervised child."""
import os
import queue
import signal
import socket
import sys
import threading
import time


STARTUP_TIMEOUT = 30.0
CONNECT_TIMEOUT = 0.25
RETRY_INTERVAL = 0.1


def _ipv4_addresses(host, port, deadline):
    """Resolve within the same deadline as connect, without a lingering child."""
    if host in ("", "0.0.0.0"):
        host = "127.0.0.1"
    try:
        socket.inet_pton(socket.AF_INET, host)
    except OSError:
        pass
    else:
        return [(host, port)]

    # A socket timeout does not bound getaddrinfo. A daemon thread lets the
    # supervised process exit on timeout or a signal even if DNS is stuck.
    resolved = queue.Queue(maxsize=1)

    def resolve():
        try:
            result = socket.getaddrinfo(
                host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
            addresses = list(dict.fromkeys(
                item[4] for item in result
                if item[0] == socket.AF_INET and item[1] == socket.SOCK_STREAM))
        except Exception:
            addresses = []
        resolved.put(addresses)

    threading.Thread(target=resolve, daemon=True).start()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return []
    try:
        return resolved.get(timeout=remaining)
    except queue.Empty:
        return []


def wait_for_tracker(host, port, timeout=STARTUP_TIMEOUT):
    """True only after an IPv4 TCP connection succeeds before the deadline.

    This probe carries no credentials. The seeder still verifies TLS when it
    announces; the probe only prevents launching it before the tracker binds.
    """
    deadline = time.monotonic() + timeout
    addresses = _ipv4_addresses(host, port, deadline)
    if not addresses:
        return False
    while True:
        for address in addresses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.settimeout(min(CONNECT_TIMEOUT, remaining))
                    probe.connect(address)
                return time.monotonic() <= deadline
            except OSError:
                pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(RETRY_INTERVAL, remaining))


def main(argv=None):
    # Background shell jobs can inherit ignored SIGINT. Keep both shutdown
    # signals immediate during DNS/connect waits and after the final exec.
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    command = list(sys.argv[1:] if argv is None else argv)
    try:
        if not command:
            raise ValueError()
        host = os.environ.get("IRIS_TRACKER_HOST", "0.0.0.0")
        port = int(os.environ.get("IRIS_TRACKER_PORT", "6969"))
        if not 1 <= port <= 65535:
            raise ValueError()
    except (TypeError, ValueError):
        print("FATAL: invalid tracker startup configuration; refusing seeder launch",
              file=sys.stderr)
        return 1
    try:
        ready = wait_for_tracker(host, port)
    except Exception:
        ready = False
    if not ready:
        print("FATAL: tracker listener did not become ready; refusing seeder launch",
              file=sys.stderr)
        return 1
    try:
        os.execvp(command[0], command)
    except (OSError, ValueError):
        # Neither the command nor an exception is safe to echo: keep startup
        # diagnostics independent of environment values and command arguments.
        print("FATAL: seeder command could not start", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
