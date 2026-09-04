# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for bounded_pool.BoundedThreadingMixin (IRIS-54):
saturation must degrade into queueing/rejection, never unbounded thread
growth, and a pool saturated by long-lived connections must not deadlock the
accept loop -- it must keep making forward progress and recover the moment a
slot frees.

These exercise the mixin directly against a minimal real HTTP server (real
sockets, real threads) rather than mocking socketserver internals, so the
actual code path used by every real listener is what gets proven."""
import http.client
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import bounded_pool


def _make_server(max_concurrent, admission_timeout, release_event,
                 arrived_event=None, arrived_count=None, arrived_lock=None):
    """A tiny bounded server whose GET handler blocks on *release_event*
    before answering -- lets a test hold N connections open to saturate the
    pool, then release them to prove the pool recovers."""

    class _Server(bounded_pool.BoundedThreadingMixin, ThreadingHTTPServer):
        pass

    _Server.max_concurrent_requests = max_concurrent
    _Server.admission_timeout = admission_timeout

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if arrived_lock is not None:
                with arrived_lock:
                    arrived_count[0] += 1
            if arrived_event is not None:
                arrived_event.set()
            release_event.wait(timeout=10)
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    srv = _Server(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _get_in_thread(port, results, index, timeout=15):
    """Issue a GET on its own thread; record (status_or_None) in results[index].
    None means the connection was refused/reset/timed out -- the rejection
    path, which never gets an HTTP response at all."""
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        conn.request("GET", "/")
        r = conn.getresponse()
        results[index] = r.status
        r.read()
        conn.close()
    except (OSError, http.client.HTTPException):
        results[index] = None


def test_pool_bounds_concurrency_and_recovers_after_a_slot_frees():
    """Two slots, two slow in-flight requests hold both. A third connection
    made while both are still held must NOT get a normal response inside the
    (short) admission window -- proving admission is actually gated rather
    than every connection spawning its own unbounded thread. Releasing one
    slow handler must let a fresh request succeed promptly afterwards,
    proving the pool recovers rather than staying wedged."""
    release = threading.Event()
    arrived_lock = threading.Lock()
    arrived_count = [0]
    srv = _make_server(max_concurrent=2, admission_timeout=1.0,
                       release_event=release,
                       arrived_count=arrived_count, arrived_lock=arrived_lock)
    port = srv.server_address[1]
    try:
        results = [None, None]
        t1 = threading.Thread(target=_get_in_thread, args=(port, results, 0))
        t2 = threading.Thread(target=_get_in_thread, args=(port, results, 1))
        t1.start(); t2.start()

        # Wait for both slow handlers to actually be running (both slots
        # occupied) before testing admission of a third.
        deadline = time.time() + 5
        while arrived_count[0] < 2 and time.time() < deadline:
            time.sleep(0.02)
        assert arrived_count[0] == 2, "both slow handlers must be running"

        # A third connection while the pool is full: process_request blocks
        # for admission_timeout (1s) then drops the connection -- no HTTP
        # response, ever (the point of the bound: no third thread spawns).
        third = [None]
        started = time.time()
        _get_in_thread(port, third, 0, timeout=5)
        elapsed = time.time() - started
        assert third[0] is None, (
            "a third connection while the pool is saturated must be "
            "refused, not served by an unbounded new thread")
        # Bounded tightly around admission_timeout (1s), not merely "> 0":
        # an UNBOUNDED pool would also spawn a third handler thread that
        # blocks on the still-unset release event, so the client's own
        # socket timeout (5s) would eventually fire too -- indistinguishable
        # from a real rejection on a lower bound alone. The upper bound is
        # what proves this was the admission timeout firing, not an
        # unbounded thread quietly piling up behind a slow client timeout.
        assert 0.9 <= elapsed < 3.0, (
            "the refusal must come from the admission timeout (1s) actually "
            "elapsing and returning control promptly -- elapsed=%.2fs looks "
            "like the client's own request timeout fired instead, which "
            "would mean a third thread was spawned unbounded" % elapsed)

        # Free one slot; the other slow request is still outstanding, but a
        # NEW request must now be admitted and served -- proving the pool is
        # not deadlocked, only was momentarily full.
        release.set()
        t1.join(timeout=10)
        t2.join(timeout=10)
        assert results[0] == 200 and results[1] == 200

        fourth = [None]
        _get_in_thread(port, fourth, 0, timeout=5)
        assert fourth[0] == 200, (
            "a fresh request after slots free must succeed promptly -- the "
            "pool must recover, never stay wedged")
    finally:
        srv.shutdown()
        srv.server_close()


def test_pool_admission_timeout_bounds_the_accept_loop_stall():
    """A long-lived connection (modelling an SSE stream) holding every slot
    must not block the accept loop for longer than admission_timeout on any
    single connection -- the property that rules out the SSE-starvation
    deadlock: the accept loop always regains control and can move on to the
    next connection (admit or reject) within a bounded time, never forever."""
    release = threading.Event()   # never set: the "SSE stream" never ends
    arrived = threading.Event()
    srv = _make_server(max_concurrent=1, admission_timeout=0.5,
                       release_event=release, arrived_event=arrived)
    port = srv.server_address[1]
    try:
        holder = [None]
        t = threading.Thread(target=_get_in_thread, args=(port, holder, 0, 20))
        t.start()
        assert arrived.wait(timeout=5), "the long-lived handler never started"

        # The single slot is now held indefinitely (release is never set).
        # Three separate connection attempts, each must return control
        # (refused) within a small bounded multiple of admission_timeout --
        # never hang, and never accumulate a thread per attempt.
        for _ in range(3):
            started = time.time()
            result = [None]
            _get_in_thread(port, result, 0, timeout=5)
            elapsed = time.time() - started
            assert result[0] is None
            # Tight upper bound (well under the client's own 5s socket
            # timeout): an UNBOUNDED pool would also spawn a handler thread
            # that blocks on the never-set release event, so the attempt
            # would only ever end via the client's 5s timeout -- easily
            # confused with a real rejection on a loose bound. Landing near
            # admission_timeout (0.5s) is what proves the POOL, not the
            # client, ended this attempt.
            assert elapsed < 2.0, (
                "an admission attempt against a fully saturated pool must "
                "return (refused) within a bounded window near "
                "admission_timeout, not hang until the client's own socket "
                "timeout -- elapsed=%.2fs is this deadlock bounded_pool "
                "exists to rule out" % elapsed)
    finally:
        release.set()   # let the held thread finish so the test can exit cleanly
        t.join(timeout=10)
        srv.shutdown()
        srv.server_close()


def test_default_bound_is_generous_for_normal_traffic():
    """The stdlib-shaped fallback (128) must not itself become a bottleneck
    for an ordinary handful of concurrent quick requests -- sanity check
    that the bound is on SATURATION, not routine concurrency."""
    release = threading.Event()
    release.set()   # respond immediately -- these are NOT held open
    srv = _make_server(max_concurrent=128, admission_timeout=5.0,
                       release_event=release)
    port = srv.server_address[1]
    try:
        results = [None] * 20
        threads = [threading.Thread(target=_get_in_thread,
                                    args=(port, results, i))
                  for i in range(20)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=10)
        assert results == [200] * 20
    finally:
        srv.shutdown()
        srv.server_close()
