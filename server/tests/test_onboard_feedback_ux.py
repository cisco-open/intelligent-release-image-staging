# server/tests/test_onboard_feedback_ux.py
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Source guards for the onboard submit-time rejection UX (operator report:
"can we put like a 'can't reach the device' or something, not just go quiet").
When the onboard/undeploy batch endpoint refuses a device (router preflight
failure, busy-device conflict, an unreachable device, ...), app.js must paint
it as prominent red text -- not a silent no-op -- listing "<device_id>:
<reason>" for each refusal, using the page's existing .err error idiom
(see styles.css). Client-side rendering only -- no server endpoint of its
own -- so these assert the markup/wiring stays intact, mirroring the
open-the-webroot-file idiom in test_tls_page_ux.py / test_gui_server.py."""
import os

import management_api as gui_server


def _read(name):
    with open(os.path.join(gui_server.WEBROOT, name)) as f:
        return f.read()


def test_dev_status_area_present_for_rejection_rendering():
    """The devices status area app.js paints refusals into must exist and be
    reachable by its id -- if this id ever moves/renames, the rendering hook
    below would silently target nothing."""
    html = _read("index.html")
    assert 'id="dev-status"' in html


def test_app_js_defines_onboard_outcome_render_hook():
    """The error-rendering hook: a named function (not an inline one-off)
    that toggles the page's standard .err class based on whether any device
    was refused, so a submission rejection reads as loud, red text instead
    of blending into the muted status line."""
    js = _read("app.js")
    assert "function renderOnboardOutcome(" in js
    hook = js.split("function renderOnboardOutcome(", 1)[1].split("\n  async function startBatch", 1)[0]
    assert "classList.toggle('err'" in hook
    assert "classList.toggle('muted'" in hook
    assert "devStatus.textContent" in hook


def test_app_js_startbatch_uses_the_render_hook_and_device_reason_format():
    """startBatch (fired by the "Start onboard" and "Start undeploy"
    primaries in the bulk bar's modals) must route through the hook above -- not print a bare
    success count with failures silently dropped -- and each refusal must
    read "<device_id>: <reason>", not a bare id or a mystery blob."""
    js = _read("app.js")
    body = js.split("async function startBatch(action) {", 1)[1].split(
        "\n  // The bulk-bar buttons open their modal", 1)[0]
    assert "renderOnboardOutcome(action, Object.keys(batchJobs).length, failed)" in body
    # "<device_id>: <reason>" -- not the old "<device_id> (<reason>)" shape
    assert "id + ': ' + reason" in body
    assert "id + ' (' + reason + ')'" not in body


def test_app_js_never_swallows_a_refused_device():
    """Every device the batch POST refuses (r.ok falsy) must be pushed onto
    the failed list that feeds the render hook -- a refusal must never be
    dropped on the floor between the fetch and the status line."""
    js = _read("app.js")
    body = js.split("async function startBatch(action) {", 1)[1].split(
        "\n  // The bulk-bar buttons open their modal", 1)[0]
    assert "if (r.ok) { batchJobs[(await r.json()).job_id] = id; } else {" in body
    branch = body.split("if (r.ok) { batchJobs[(await r.json()).job_id] = id; } else {", 1)[1]
    branch = branch.split("} catch (e) { failed.push(id); }", 1)[0]
    assert "failed.push(" in branch
