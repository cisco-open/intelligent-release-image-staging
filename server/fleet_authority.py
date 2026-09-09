# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""One cross-process fleet lifetime lock with safe same-thread nesting."""
import contextlib
import os
import threading

import secrets_store


_LOCAL = threading.local()


@contextlib.contextmanager
def membership_guard(fleet):
    """Hold fleet membership authority across related durable operations.

    Fleet mutations acquire this guard internally. Coordinators may already
    hold it across a larger transaction, so nesting by the owning thread is a
    no-op while other threads and processes still block on the same flock.
    """
    path = os.fspath(fleet.path) + ".membership"
    depths = getattr(_LOCAL, "depths", None)
    if depths is None:
        depths = {}
        _LOCAL.depths = depths
    if depths.get(path, 0):
        depths[path] += 1
        try:
            yield
        finally:
            depths[path] -= 1
        return
    with secrets_store.store_lock(path):
        depths[path] = 1
        try:
            yield
        finally:
            depths.pop(path, None)
