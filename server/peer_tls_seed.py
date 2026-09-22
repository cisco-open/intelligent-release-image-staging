# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Apply the persisted peer mode and renew the origin's private identity."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

from peer_tls_issuer import Issuer
import peer_tls_settings as settings

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
    next_identity_check = 0

    def shutdown():
        nonlocal child
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        child = None

    def report(state, active=None):
        settings.atomic_json(settings.status_path(), {
            'state': state, 'active_mode': active, 'updated_at': time.time()})

    try:
        while not stop.is_set():
            try:
                wanted = settings.mode()
                if current is not None and current[0] != wanted:
                    # Stop the old transport before obtaining a new identity:
                    # an enrollment failure must never leave plaintext running.
                    shutdown()
                    current = None
                if child is not None and child.poll() is not None:
                    raise RuntimeError('origin exited')
                fragment = current[1] if current is not None else ''
                if wanted == 'required' and (current is None or time.monotonic() >= next_identity_check):
                    fragment = ensure(cfg, LocalClient())
                    next_identity_check = time.monotonic() + 30
                identity = (wanted, fragment)
                if identity != current:
                    shutdown()
                    report('starting')
                    if stop.is_set():
                        break
                    env = dict(os.environ, IRIS_PEER_TLS_SUPERVISED='1', IRIS_PEER_TLS_MODE=wanted)
                    env.pop('IRIS_PEER_TLS_CONF', None)
                    if wanted == 'required':
                        path = runtime / 'aria2.conf'
                        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        with os.fdopen(fd, 'w') as stream:
                            stream.write(fragment)
                        env['IRIS_PEER_TLS_CONF'] = str(path)
                    child = subprocess.Popen(['bash', sys.argv[1]], env=env)
                    current = identity
                else:
                    report('running', wanted)
            except Exception:
                shutdown()
                current = None
                report('error')
            stop.wait(2)
    finally:
        shutdown()
        report('stopped')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
