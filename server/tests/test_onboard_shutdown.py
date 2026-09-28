# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shutdown cannot hide an onboarding maintenance writer after a bounded join."""

import queue
import threading
from types import SimpleNamespace

import pytest

from gui_onboard import OnboardService


@pytest.mark.parametrize('alive', [False, True])
def test_shutdown_retains_maintenance_completion_after_pool_cleanup(alive):
    service = OnboardService.__new__(OnboardService)
    service._lock = threading.Lock()
    service._condition = threading.Condition(service._lock)
    service._maintenance_stop = threading.Event()
    joined = []
    service._maintenance = SimpleNamespace(
        join=lambda timeout: joined.append(('maintenance', timeout)),
        is_alive=lambda: alive)
    service._work_queue = queue.Queue()
    service._workers = [SimpleNamespace(join=lambda: joined.append(('worker', None)))]
    service.cancel_queued = lambda: joined.append(('cancel', None))
    if alive:
        with pytest.raises(RuntimeError, match='active writer'):
            service.shutdown()
    else:
        service.shutdown()
    assert service._closing and service._maintenance_stop.is_set()
    assert service._workers == []
    assert joined == [('cancel', None), ('maintenance', 5), ('worker', None)]
