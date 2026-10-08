# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Ordered, fresh management read projections within one server instance.

Reading many small fleet/catalog files concurrently makes these projections
slower. Order entire projections, not individual store reads, without caching
their results or taking a lock shared with writers. The HTTP worker pool already
bounds the number of callers; a bounded wait prevents a stuck reader from
holding all other projection requests indefinitely. This is not a rate limit.
"""
from collections import deque
from contextlib import contextmanager
from functools import wraps
import threading


class ProjectionBusy(RuntimeError):
    """The request did not begin its projection within the queue wait bound."""


class ReadProjectionGate:
    """FIFO admission for synchronous reads; never nest or wrap a mutation.

The wait bound covers time before entry, not execution or filesystem I/O. A
caller that times out is removed without running its projection. Every admitted
caller reads current authorities itself, after entry. Separate server instances
have separate gates; this does not coordinate replicas or make store snapshots
atomic across files.
    """

    def __init__(self, wait_timeout=10.0):
        self._condition = threading.Condition()
        self._queue = deque()
        self._owner = None
        self._wait_timeout = wait_timeout

    @contextmanager
    def enter(self):
        ticket = object()
        with self._condition:
            if self._owner == threading.get_ident():
                raise RuntimeError("read projection gate cannot be nested")
            self._queue.append(ticket)
            try:
                if not self._condition.wait_for(
                        lambda: self._queue[0] is ticket,
                        timeout=self._wait_timeout):
                    raise ProjectionBusy("read projection queue timed out")
                self._owner = threading.get_ident()
            except BaseException:
                self._queue.remove(ticket)
                self._condition.notify_all()
                raise
        try:
            yield
        finally:
            with self._condition:
                self._owner = None
                self._queue.popleft()
                self._condition.notify_all()

    def ordered(self, read):
        @wraps(read)
        def invoke(*args, **kwargs):
            with self.enter():
                return read(*args, **kwargs)
        return invoke
