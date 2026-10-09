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
    import gui_server
    from test_api_split import _console_transport_failure

    failures = deque(maxlen=8)
    original = api_problem.send
    original_request = gui_server._management_request

    def observe_request(*args, **kwargs):
        try:
            return original_request(*args, **kwargs)
        except Exception as error:
            # Startup may legitimately use its independent certificate after
            # this failure. Keep the safe classification before it is swallowed.
            # Read only code identity, never frame locals or request arguments.
            frame = sys._getframe(1)
            startup = False
            while frame is not None:
                if frame.f_globals.get("__name__") == "gui_server":
                    if frame.f_code.co_name == "_proxy":
                        startup = False  # A browser-triggered reload is not startup.
                        break
                    if frame.f_code.co_name == "fetch_console_certificate":
                        startup = True
                frame = frame.f_back
            if startup:
                failures.append(dict(_console_transport_failure(error),
                                     operation="startup-certificate"))
            raise

    def observe(handler, status, code, *args, **kwargs):
        if status == 503 and code == "management-api-unavailable":
            failures.append(dict(_console_transport_failure(sys.exc_info()[1]),
                                 operation="browser-request"))
        return original(handler, status, code, *args, **kwargs)

    monkeypatch.setattr(api_problem, "send", observe)
    monkeypatch.setattr(gui_server, "_management_request", observe_request)
    return failures
