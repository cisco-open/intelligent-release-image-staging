# server/tests/test_onboard_feedback_ux.py
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Source guards for the onboard submit-time rejection UX (operator report:
"can we put like a 'can't reach the device' or something, not just go quiet").
When the onboard/undeploy batch endpoint refuses a device (router preflight
failure, busy-device conflict, an unreachable device, ...), Inventory must paint
it as prominent red text -- not a silent no-op -- listing "<device_id>:
<reason>" for each refusal, using the page's existing .err error idiom
(see styles.css). Client-side rendering only -- no server endpoint of its
own -- so these assert React owns the markup and the adapter passes outcomes
without writing workflow DOM."""
import os
from pathlib import Path

import management_api as gui_server


def _read(name):
    with open(os.path.join(gui_server.WEBROOT, name)) as f:
        return f.read()


def _react(name):
    return (Path(gui_server.WEBROOT).parent / "console-ui/src" / name).read_text()


def test_dev_status_area_present_for_rejection_rendering():
    """The status live region remains at its established position via a portal."""
    html = _read("index.html")
    assert 'id="iris-inventory-status-root"' in html
    assert 'id="dev-status"' not in html
    jsx = _react("inventory.jsx")
    assert 'id="dev-status" role="status" aria-live="polite"' in jsx
    assert "{state.outcome.message}</div>, statusRoot)" in jsx


def test_app_js_defines_onboard_outcome_render_hook():
    """Activity publishes state; React renders the standard refusal styling."""
    js = _read("app.js")
    assert "outcome: function (message, failed) { inventory.report(message, failed); }" in js
    assert "state.outcome.failed ? 'err' : 'muted'" in _react("inventory.jsx")
    assert "this.update({outcome:" in _react("inventory-controller.mjs")


def test_adapter_cannot_write_operational_text_or_markup():
    """Only the bootstrap failure fallback may paint before React is ready."""
    import re

    js = _read("app.js")
    assignments = re.findall(r"\b\w+\.(?:textContent|innerHTML|outerHTML|innerText)\s*=.*", js)
    assert len(assignments) == 1
    assert assignments[0].startswith("notice.textContent = 'Console initialization failed: '")
    assert "insertAdjacentHTML" not in js
    assert "devStatus" not in js


def test_app_js_startbatch_uses_the_render_hook_and_device_reason_format():
    """The Activity controller routes batch results through the adapter,
    retaining each refused device and its reason."""
    body = _react("activity-controller.mjs").split("async start(action, ids, options = {})", 1)[1]
    assert "this.services.outcome?.(message, !!(refused.length || unknown.length))" in body
    # "<device_id>: <reason>" -- not the old "<device_id> (<reason>)" shape
    assert "refused.push(`${id}: ${error.message}`)" in body


def test_app_js_never_swallows_a_refused_device():
    """Every device the batch POST refuses (r.ok falsy) must be pushed onto
    the failed list that feeds the render hook -- a refusal must never be
    dropped on the floor between the fetch and the status line."""
    controller = _react("activity-controller.mjs")
    assert "if (!response.ok)" in controller
    assert "throw new Error(body.error)" in controller
    body = controller.split("async start(action, ids, options = {})", 1)[1]
    assert "unknown.push(id)" in body and "refused.push" in body
    assert "submissionMessage(action, accepted.length, refused, unknown)" in body
