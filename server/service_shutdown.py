# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bounded, fail-closed shutdown for managed HTTP services and their writers."""
import signal
import sys
import threading
import time


class WriterThread(threading.Thread):
    """Keep sticky evidence of abnormal completion, including daemon crashes."""

    def __init__(self, *args, stop_event, **kwargs):
        super().__init__(*args, **kwargs)
        self.stop_event = stop_event
        self.clean_exit = False

    def run(self):
        try:
            super().run()
        except BaseException:
            print("IRIS background writer failed; clean shutdown cannot be attested",
                  file=sys.stderr, flush=True)
        else:
            # A spontaneously dead writer is not made clean by a later TERM.
            self.clean_exit = self.stop_event.is_set()


def stop_thread(thread, stop_event, timeout):
    """Request termination and prove the current write completed."""
    stop_event.set()
    thread.join(timeout=max(0, timeout))
    return not thread.is_alive() and thread.clean_exit


def _bounded(callback, deadline):
    """Never let a broken cleanup callback turn TERM into an unbounded wait."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return False
    result = []

    def run():
        try:
            result.append(callback(remaining) is not False)
        except BaseException:
            result.append(False)

    thread = threading.Thread(target=run, name="service-drain", daemon=True)
    thread.start()
    thread.join(timeout=max(0, deadline - time.monotonic()))
    return not thread.is_alive() and result == [True]


def drain(servers, writers=(), timeout=25):
    """Fence admission, drain requests, then join writers within ONE deadline.

    A writer callback takes its remaining seconds and must return True only
    when its thread has finished. Failure is not a clean shutdown, even if
    other writers finish. Incomplete daemon work is abandoned only on the
    resulting nonzero process exit, never attested as a consistent backup.
    """
    deadline = time.monotonic() + timeout
    clean = True
    for server in servers:
        clean = _bounded(lambda _left, s=server: s.stop_request_admission(),
                         deadline) and clean
    for server in servers:
        clean = _bounded(lambda _left, s=server: s.shutdown(), deadline) and clean
    for server in servers:
        clean = _bounded(lambda left, s=server: s.drain_requests(left) is True,
                         deadline) and clean
    for writer in writers:
        clean = _bounded(lambda left, w=writer: w(left) is True, deadline) and clean
    for server in servers:
        clean = _bounded(lambda _left, s=server: s.server_close(), deadline) and clean
    return clean


def serve(servers, writers=(), *, timeout=25, stop_event=None):
    """Serve until TERM/INT; return zero only with complete writer drains.

    Signal handlers only assign a flag. Accept loops run in daemon threads so
    even a stuck accept loop cannot prevent a bounded, nonzero shutdown.
    ``stop_event`` provides the same stop request for embedded callers/tests.
    """
    requested = False
    stopping = False
    previous = {}
    threads = []
    failed_listeners = []

    def request_stop(_number, _frame):
        nonlocal requested
        requested = True

    def listen(server):
        try:
            server.serve_forever()
        except BaseException:
            failed_listeners.append(server)
        finally:
            if not stopping:
                failed_listeners.append(server)

    def join_listeners(left):
        deadline = time.monotonic() + left
        for thread in threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        return not failed_listeners and not any(t.is_alive() for t in threads)

    if threading.current_thread() is threading.main_thread():
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, request_stop)
    clean = False
    try:
        for server in servers:
            thread = threading.Thread(target=listen, args=(server,),
                                      name="service-listener", daemon=True)
            threads.append(thread)
            thread.start()
        while not requested and not (stop_event and stop_event.is_set()):
            if not all(thread.is_alive() for thread in threads):
                break
            time.sleep(0.05)
        expected = requested or bool(stop_event and stop_event.is_set())
        stopping = True
        clean = drain(servers, [join_listeners, *writers], timeout) and expected
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    if not clean:
        print("IRIS service shutdown incomplete; refusing clean-stop proof",
              file=sys.stderr, flush=True)
    return 0 if clean else 1
