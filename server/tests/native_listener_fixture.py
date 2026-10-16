# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Finish owned native request workers before another test changes globals."""

import socket
import threading
import time

import pytest


def https_fixture_url(server):
    """Address the reserved IPv4 listener, not a second localhost family."""
    host, port = server.server_address[:2]
    if server.address_family != socket.AF_INET or host != "127.0.0.1":
        raise ValueError("expected an explicitly bound IPv4 loopback fixture")
    return "https://%s:%d" % (host, port)


class NativeListenerFixture:
    """Keep owned socket handles even after TLS takes the accepted descriptor."""

    drain_seconds = 2

    def __init__(self, server, listener):
        self.server, self.listener = server, listener
        self.lock = threading.Lock()
        self.sockets, self.workers = {}, set()
        self.closed = False
        self.original_get = server.get_request
        self.original_process = server.process_request_thread
        self.original_close_request = server.close_request
        self.original_close = server.server_close
        server.get_request = self.get_request
        server.process_request_thread = self.process_request_thread
        server.close_request = self.close_request
        server.server_close = self.close

    def get_request(self):
        request, address = self.original_get()
        try:
            # Retain the actual descriptor, not its integer value: TLS can
            # detach it from request and the OS may later reuse that number.
            duplicate = request.dup()
        except BaseException:
            self.original_close_request(request)
            raise
        with self.lock:
            self.sockets[request] = duplicate
        return request, address

    def drop_socket(self, request):
        with self.lock:
            duplicate = self.sockets.pop(request, None)
        if duplicate is not None:
            duplicate.close()

    def close_request(self, request):
        try:
            return self.original_close_request(request)
        finally:
            self.drop_socket(request)

    def process_request_thread(self, request, address):
        with self.lock:
            self.workers.add(threading.current_thread())
        try:
            return self.original_process(request, address)
        finally:
            self.drop_socket(request)

    def close_owned_sockets(self):
        with self.lock:
            duplicates = list(self.sockets.values())
            self.sockets.clear()
        for duplicate in duplicates:
            try:
                duplicate.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                duplicate.close()

    def close(self):
        if self.closed:
            return
        self.server.stop_request_admission()
        shutdown_failed = []

        def stop_listener():
            try:
                self.server.shutdown()
            except BaseException:
                shutdown_failed.append(True)

        stopper = None
        if self.listener.is_alive():
            stopper = threading.Thread(target=stop_listener, daemon=True)
            stopper.start()
        try:
            clean = self.server.drain_requests(timeout=self.drain_seconds)
            self.close_owned_sockets()
            if not clean:
                clean = self.server.drain_requests(timeout=self.drain_seconds)
        finally:
            self.close_owned_sockets()
            self.original_close()
        with self.lock:
            workers = list(self.workers)
        threads = workers + [self.listener] + ([stopper] if stopper else [])
        deadline = time.monotonic() + self.drain_seconds
        for thread in threads:
            if thread.ident is not None:
                thread.join(timeout=max(0, deadline - time.monotonic()))
        active = self.server._request_lifecycle_state()['active']
        if active or any(thread.is_alive() for thread in threads):
            # Python cannot safely kill a handler blocked in arbitrary code.
            # Do not run another test against globals that it can still use.
            pytest.exit('Owned native fixture workers survived bounded cleanup', returncode=1)
        self.closed = True
        assert clean and not shutdown_failed, 'Native fixture handler failed; owned workers and sockets were drained'


def start_fixture_server(server, request=None):
    """Register native cleanup before startup, including failed Thread.start."""
    listener = threading.Thread(target=server.serve_forever, daemon=True)
    if hasattr(server, 'drain_requests'):
        server._test_listener_fixture = NativeListenerFixture(server, listener)
    if request is not None:
        request.addfinalizer(server.server_close)
    try:
        listener.start()
    except BaseException:
        server.server_close()
        raise
    return listener
