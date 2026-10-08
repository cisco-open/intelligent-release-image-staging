#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bounded thread-per-connection admission for the threaded HTTP listeners.

``socketserver.ThreadingMixIn`` (the base under every listener in this repo
-- tracker, catalog, console, artifact server, metrics) spawns one OS thread
per accepted connection with NO upper bound. A burst of slow clients, or
handlers blocked on a shared file lock (``keyed_state.py``), accumulates
arbitrarily many threads and their stacks -- eventually exhausting memory or
the OS thread limit, at which point new connections fail outright rather
than degrading gracefully. ``request_queue_size`` (already raised to 128 on
the fleet-facing listeners) only bounds the KERNEL accept backlog; it does
nothing once a connection is accepted and handed to a thread -- that hand-off
is exactly what this module bounds.

``BoundedThreadingMixin`` caps the number of CONCURRENTLY RUNNING handler
threads at ``max_concurrent_requests`` per listener. Admission is gated by a
semaphore acquired in ``process_request`` -- called synchronously from the
single accept loop (``BaseServer.serve_forever`` -> ``_handle_request_noblock``
-> ``get_request()`` then ``process_request()``) -- so once the pool is full
the listener simply stops accepting new connections for a while and they
queue in the (already-enlarged) kernel backlog instead of spawning another
thread.

The one thing a blocking semaphore must never do is wait forever: these
listeners also serve connections with no natural end within a single
request/response -- most notably the console's onboard-log SSE stream
(``gui_server.py``, `text/event-stream`), which can stay open for the
lifetime of a multi-hour deployment job. If enough of those saturate the
pool, an indefinite ``acquire()`` would leave ``process_request`` blocked
forever, and the SAME accept loop that owns admission would never call
``accept()`` again -- freezing the listener for every OTHER client,
including ones with nothing to do with the stuck connections. That is a
self-inflicted denial of service, not backpressure, and the one failure
mode this module exists to rule out.

So acquisition is bounded by ``admission_timeout``: a burst of ordinary
short-lived requests waits out the timeout and is then served normally
(well within it under any realistic load, since a slot frees in
milliseconds to seconds); a listener saturated by long-lived connections
instead times out and the WAITING connection is dropped -- socket closed,
no application response, since a slot was never available to hand it one --
rather than the accept loop blocking indefinitely. Either way
``process_request`` always returns within ``admission_timeout``, so the
listener always keeps accepting. Each listener sizes
``max_concurrent_requests`` comfortably above its own expected count of
concurrent long-lived connections (see each subclass), so that timeout path
is reached only under genuine overload, not ordinary peak legitimate use.
"""
import threading
import sys
import time
import ssl
import functools
import socket
import socketserver


class BoundedThreadingMixin:
    """Mix in BEFORE ``ThreadingHTTPServer`` (or any ``ThreadingMixIn``
    subclass) so this class's ``process_request`` overrides the stdlib one:
    ``class _FooServer(BoundedThreadingMixin, ThreadingHTTPServer):``.

    Subclasses may still override ``process_request_thread`` (e.g. for a
    per-connection TLS handshake, as catalog/console/artifact already do) --
    that override keeps running unchanged; this only gates HOW MANY of them
    may run at once, and releases the slot when the whole per-connection
    handler (including any TLS handshake) has finished.
    """

    # Conservative stdlib-default-shaped fallback; every real listener
    # overrides this to a value sized for its own traffic (see each
    # make_server()/_*Server class).
    max_concurrent_requests = 128
    # How long a connection waits for a free slot before being dropped.
    admission_timeout = 10.0

    def process_request(self, request, client_address):
        lifecycle = self._request_lifecycle_state()
        with lifecycle['condition']:
            closing = lifecycle['closing']
        if closing:
            self.close_request(request)
            return
        sem = self._bounded_admission_semaphore()
        if not sem.acquire(timeout=self.admission_timeout):
            # The pool has been continuously full for the whole timeout --
            # either a genuine burst beyond capacity, or long-lived
            # connections (an SSE stream, a slow device transfer) holding
            # every slot. Drop this one connection rather than block the
            # accept loop -- and therefore every OTHER client -- any
            # further. Best-effort counter for tests/diagnostics only, not
            # synchronized: an exact count is not the point, "it moves
            # under saturation" is.
            self.rejected_requests = getattr(self, "rejected_requests", 0) + 1
            threading.Thread(target=self.shutdown_request,
                             args=(request,), daemon=True).start()
            return

        # Register before starting a thread: a TERM during Thread.start must
        # not erase a writer whose ident has not yet become visible.
        token = object()
        with lifecycle['condition']:
            admitted = not lifecycle['closing']
            if admitted:
                lifecycle['active'].add(token)
        if not admitted:
            sem.release()
            self.close_request(request)
            return

        def _run():
            try:
                self.process_request_thread(request, client_address)
            except BaseException:
                with lifecycle['condition']:
                    lifecycle['failed'] = True
                print('IRIS request worker failed; clean shutdown cannot be attested',
                      file=sys.stderr, flush=True)
            finally:
                sem.release()
                with lifecycle['condition']:
                    lifecycle['active'].discard(token)
                    lifecycle['condition'].notify_all()

        t = threading.Thread(target=_run)
        t.daemon = self.daemon_threads
        if not t.daemon and self.block_on_close:
            if self._threads is None:
                self._threads = []
            self._threads.append(t)
        try:
            t.start()
        except Exception:
            # Thread.start's ordinary failure never admitted a writer. Keep
            # the failure evidence, but release the unused concurrency slot.
            sem.release()
            with lifecycle['condition']:
                lifecycle['failed'] = True
                lifecycle['active'].discard(token)
                lifecycle['condition'].notify_all()
            raise
        except BaseException:
            # An asynchronous termination may interrupt start after launch;
            # only the worker's finally block may clear its admission token.
            with lifecycle['condition']:
                lifecycle['failed'] = True
            raise

    def _request_lifecycle_state(self):
        state = self.__dict__.get('_request_lifecycle')
        if state is None:
            state = self.__dict__.setdefault('_request_lifecycle', {
                'condition': threading.Condition(), 'closing': False,
                'active': set(), 'failed': False})
        return state

    def handle_error(self, request, client_address):
        """Retain handler failures swallowed by stdlib ThreadingMixIn.

        Normal peer disconnects do not imply an incomplete application write.
        Other errors, including filesystem OSError and timeout failures, cannot
        produce a clean backup shutdown proof. Never log request/private data.
        """
        self._record_request_error(sys.exc_info()[1], request)

    def _record_request_error(self, error, request=None):
        if isinstance(error, (BrokenPipeError, ConnectionResetError,
                              ConnectionAbortedError, ssl.SSLEOFError,
                              ssl.SSLZeroReturnError)):
            return
        if isinstance(error, TimeoutError) and request is not None:
            # A body read occurs inside do_POST, unlike the header read in
            # BaseHTTPRequestHandler. Exempt only an actual I/O frame bound
            # to this inbound socket, never arbitrary filesystem/outbound
            # operation timeouts that merely share the same exception type.
            trace = error.__traceback__
            while trace is not None:
                frame = trace.tb_frame
                owner = frame.f_locals.get('self')
                if ((frame.f_code in (socket.SocketIO.readinto.__code__,
                                      socketserver._SocketWriter.write.__code__)
                     and getattr(owner, '_sock', None) is request)
                        or (frame.f_code in (ssl.SSLSocket.read.__code__,
                                             ssl.SSLSocket.write.__code__)
                            and owner is request)):
                    return
                trace = trace.tb_next
        state = self._request_lifecycle_state()
        with state['condition']:
            already_failed = state['failed']
            state['failed'] = True
        if not already_failed:
            print('IRIS request handler failed; clean shutdown cannot be attested',
                  file=sys.stderr, flush=True)

    def finish_request(self, request, client_address):
        # BaseHTTPRequestHandler also catches TimeoutError around BOTH socket
        # reads and application do_* callbacks. Observe application exceptions
        # before that broad catch without changing their type or public text.
        # Ordinary idle-peer read timeouts never enter these wrappers.
        handler = self.__dict__.get('_tracked_request_handler')
        if handler is None:
            original = self.RequestHandlerClass
            overrides = {}
            def observed(method):
                @functools.wraps(method)
                def call(instance, *args, **kwargs):
                    try:
                        return method(instance, *args, **kwargs)
                    except BaseException as error:
                        instance.server._record_request_error(error, instance.connection)
                        raise
                return call
            for name in dir(original):
                method = getattr(original, name)
                if name.startswith('do_') and callable(method):
                    overrides[name] = observed(method)
            handler = self.__dict__.setdefault('_tracked_request_handler',
                type(original.__name__, (original,), overrides))
        handler(request, client_address, self)

    def stop_request_admission(self):
        """Fence new handler writers before taking a shutdown snapshot."""
        state = self._request_lifecycle_state()
        with state['condition']:
            state['closing'] = True

    def drain_requests(self, timeout=30):
        """Bounded completion proof, including daemon handlers and start races."""
        self.stop_request_admission()
        state = self._request_lifecycle_state()
        deadline = time.monotonic() + timeout
        with state['condition']:
            while state['active']:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                state['condition'].wait(remaining)
            return not state['failed']

    def _bounded_admission_semaphore(self):
        # Lazily built on the instance (not the class) so every server
        # instance -- including several created in one test process -- gets
        # its own pool, sized from THIS instance's max_concurrent_requests.
        sem = self.__dict__.get("_admission_semaphore")
        if sem is None:
            sem = threading.BoundedSemaphore(self.max_concurrent_requests)
            self.__dict__["_admission_semaphore"] = sem
        return sem
