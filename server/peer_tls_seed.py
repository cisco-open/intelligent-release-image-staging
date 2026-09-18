# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Renew the origin's local identity and restart only its seeder on rotation."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading

from peer_tls_issuer import Issuer

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'device' / 'agent'))
from peer_tls import ensure


def main():
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    runtime = Path(os.environ.get('IRIS_RUN', '/run/iris')) / 'peer-origin'
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    cfg = {'stage_dir': str(runtime), 'device_id': '__iris_origin__',
           'peer_tls_mode': 'required'}

    class LocalClient:
        def enroll_peer_tls(self, device_id, csr):
            return Issuer().issue(device_id, csr)

    child = None
    current = None

    def shutdown():
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()

    try:
        while not stop.is_set():
            try:
                fragment = ensure(cfg, LocalClient())
            except Exception:
                shutdown()
                print('peer seeder identity unavailable; transport stopped', file=sys.stderr)
                return 1
            if child is not None and child.poll() is not None:
                return child.returncode or 1
            if fragment != current:
                shutdown()
                path = runtime / 'aria2.conf'
                fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, 'w') as stream:
                    stream.write(fragment)
                env = dict(os.environ, IRIS_PEER_TLS_SUPERVISED='1',
                           IRIS_PEER_TLS_CONF=str(path))
                child = subprocess.Popen(['bash', sys.argv[1]], env=env)
                current = fragment
            stop.wait(30)
    finally:
        shutdown()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
