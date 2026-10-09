# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Put the server/ dir on sys.path so tests can `import bencode`, `import
tracker`, etc. (flat-import style)."""
import os
import sys
from collections import deque

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def console_transport_failures(monkeypatch):
    """Keep diagnostics available to every importer of the two-tier fixture."""
    import api_problem
    from test_api_split import _console_transport_failure

    failures = deque(maxlen=8)
    original = api_problem.send

    def observe(handler, status, code, *args, **kwargs):
        if status == 503 and code == "management-api-unavailable":
            failures.append(_console_transport_failure(sys.exc_info()[1]))
        return original(handler, status, code, *args, **kwargs)

    monkeypatch.setattr(api_problem, "send", observe)
    return failures
