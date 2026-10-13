# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import inspect
import json
import os
from pathlib import Path
import re

import management_api as gui_server
import pytest


def test_management_sigterm_runs_ordered_shutdown_cleanup(tmp_path):
    """Container stop must enter the same cleanup path as normal return."""
    import subprocess
    import sys
    import time

    ready = tmp_path / "ready"
    cleaned = tmp_path / "cleaned"
    program = r'''
import os
import signal
import sys
import management_api

ready, cleaned = sys.argv[1:]

class Server:
    def serve_forever(self):
        with open(ready, "w"):
            pass
        while True:
            signal.pause()

def cleanup():
    with open(cleaned, "w") as stream:
        stream.write("drained")

management_api._serve_with_shutdown(Server(), cleanup)
'''
    proc = subprocess.Popen(
        [sys.executable, "-c", program, str(ready), str(cleaned)],
        cwd=os.path.dirname(gui_server.__file__),
        env=dict(os.environ), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    try:
        deadline = time.time() + 3.0
        while not ready.exists() and proc.poll() is None and time.time() < deadline:
            time.sleep(0.01)
        assert ready.exists(), proc.communicate(timeout=1)
        proc.terminate()
        stdout, stderr = proc.communicate(timeout=3)
        assert proc.returncode == 0, (stdout, stderr)
        assert cleaned.read_text() == "drained"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_management_sigterm_is_latched_before_local_admission(tmp_path):
    import subprocess
    import sys
    import time

    ready = tmp_path / "startup-ready"
    cleaned = tmp_path / "startup-cleaned"
    served = tmp_path / "served"
    admitted = tmp_path / "admitted"
    program = r'''
import signal
import sys
import time
import management_api

ready, cleaned, served, admitted = sys.argv[1:]
latch = management_api._SigtermLatch()
latch.install()
with open(ready, "w"):
    pass
time.sleep(0.3)

class Server:
    def serve_forever(self):
        with open(served, "w"):
            pass

management_api._serve_with_shutdown(
    Server(), lambda: open(cleaned, "w").write("drained"), latch=latch,
    start_admission=lambda: open(admitted, "w").write("accepted"))
'''
    proc = subprocess.Popen(
        [sys.executable, "-c", program, str(ready), str(cleaned), str(served),
         str(admitted)],
        cwd=os.path.dirname(gui_server.__file__),
        env=dict(os.environ), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    try:
        deadline = time.time() + 3.0
        while not ready.exists() and proc.poll() is None and time.time() < deadline:
            time.sleep(0.01)
        assert ready.exists(), proc.communicate(timeout=1)
        proc.terminate()
        stdout, stderr = proc.communicate(timeout=3)
        assert proc.returncode == 0, (stdout, stderr)
        assert cleaned.read_text() == "drained"
        assert not served.exists()
        assert not admitted.exists()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def test_role_column_panel_and_modal_are_scoped_and_accessible():
    html, js, css = (_webroot(n) for n in ("index.html", "app.js", "styles.css"))
    component = _react_shell("inventory.jsx")
    assert "['Device', 'Role', 'IP'" in component
    assert '<td className="dev-role">{device.role' in component
    assert 'colSpan={12}' in component
    assert "['role', 'role'" in component and "['peer', 'peer'" in component
    assert "peer-intent badge" in component and "Quarantined intent" in component
    assert "bulkButton('set-role-selected', 'Set role…')" in component
    modal = _react_shell('role-actions.jsx')
    assert 'id="iris-role-actions-root" data-role-actions-react' in html
    assert 'role="dialog" aria-modal="true" aria-labelledby="role-modal-title"' in modal
    for cid in ('role-modal-title', 'role-selected', 'role-modal-msg', 'role-preview', 'role-modal-cancel', 'role-modal-x', 'apply-role-selected'):
        assert 'id="%s"' % cid in modal
    assert 'aria-live="polite"' in modal
    assert "controller.close()" in modal and "event.key === 'Escape'" in modal
    assert "wireModal('role-modal'" not in js and "BULK_MODALS" not in js
    assert "'apply-role-selected'" in js.split('var BULK_BTNS = [', 1)[1].split(']', 1)[0]
    assert "'set-role-selected'" in js.split('var BULK_OPENERS = [', 1)[1].split(']', 1)[0]
    panel = _react_shell('policy-dialogs.jsx')
    assert 'id="peer-policy-panel"' in panel
    assert 'id="role-capability-banner"' in _react_shell('policies.jsx')
    assert '<textarea' not in panel and '<textarea' not in modal
    assert '.policy-counts' in css and 'minmax(' in css
    assert _react_shell('role-actions-controller.mjs').count("'/api/v1/devices/bulk-role'") == 1
    assert "'/api/v1/devices/bulk-role'" not in js


def _run_policies_node(pattern):
    """Run shipped controller regressions, never a duplicate state machine."""
    import subprocess
    tests = Path(gui_server.WEBROOT).parent / "console-ui/tests/policies.test.mjs"
    result = subprocess.run(
        ["node", "--test", "--test-name-pattern", pattern, str(tests)],
        text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert re.search(r"# pass [1-9][0-9]*", result.stdout), result.stdout


def test_role_definition_editor_previews_then_commits_with_the_preview_token():
    _run_policies_node("definition create previews|definition commit")


def test_role_definition_editor_edit_discards_a_stale_preview_and_carries_qos_state():
    _run_policies_node("existing editor holds|editing after preview")


def test_role_definition_delete_and_import_preview_then_confirm():
    _run_policies_node("delete |CSV |role exports")


def test_role_definition_controls_follow_the_capability_banner():
    _run_policies_node("capability, degraded policy")


def test_role_actions_execute_captured_targets_and_checked_response_regressions():
    """Use the shipped controller, not a second implementation of its behavior."""
    import subprocess
    from pathlib import Path
    tests = Path(gui_server.WEBROOT).parent / "console-ui/tests/role-actions.test.mjs"
    result = subprocess.run(["node", "--test", str(tests)], text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


def test_peer_policy_panel_distinguishes_unknown_preflight_from_zero():
    _run_policies_node("preflight diagnostics")


def test_peer_policy_panel_count_only_and_capability_banner_behavior():
    _run_policies_node("diagnostics keep|capability warnings")


def test_role_policy_startup_signal_identifies_lost_state_without_addresses(tmp_path, capsys):
    import peer_policy
    state_dir = str(tmp_path)
    auth = str(tmp_path / 'peer-policy.json')
    gui_server._log_peer_policy_startup(state_dir)
    assert 'roles supported' in capsys.readouterr().err
    peer_policy._write_roles_watermark(auth)
    gui_server._log_peer_policy_startup(state_dir)
    warning = capsys.readouterr().err
    assert 'role state lost' in warning
    assert 'quarantine' in warning and 'downgrade' in warning
    warning_lower = warning.lower()
    assert re.search(r"older|predating", warning_lower)
    assert "independent quarantine" in warning_lower
    assert re.search(r"independent quarantine.{0,140}"
                     r"(?:not sufficient|insufficient|cannot|ignore)",
                     warning_lower, re.DOTALL)
    assert "pre-d" not in warning_lower
    assert "quarantine restricted devices before any downgrade" not in warning_lower
    main = open(gui_server.__file__).read().split('def main():', 1)[1]
    assert '_log_peer_policy_startup(state_dir)' in main


@pytest.mark.parametrize('state,phrase', [
    ('healthy', 'peer policy is healthy'), ('degraded', 'policy is degraded'),
    ('fail_closed', 'policy is fail_closed'), ('unavailable', 'policy is unavailable')])
def test_role_policy_startup_distinguishes_supported_policy_states(tmp_path, capsys, monkeypatch, state, phrase):
    import peer_policy
    doc = peer_policy.base_document()
    doc['roles'] = {'defs': {}, 'role_of': {}}
    def load(*_):
        if state == 'unavailable':
            raise OSError('sensitive storage detail 192.0.2.8')
        return peer_policy.PolicyResult(doc, state in ('degraded', 'fail_closed'),
                                        state == 'fail_closed')
    monkeypatch.setattr(peer_policy, 'load_policy', load)
    gui_server._log_peer_policy_startup(str(tmp_path))
    logged = capsys.readouterr().err
    assert 'roles supported' in logged and phrase in logged
    assert 'role state lost' not in logged and '192.0.2.8' not in logged


def test_webroot_assets_exist():
    for name in ("login.html", "index.html", "styles.css", "login.js", "app.js",
                 "setup.html", "setup.js"):
        assert os.path.isfile(os.path.join(gui_server.WEBROOT, name)), name


def test_login_page_does_not_disclose_first_run_credentials():
    with open(os.path.join(gui_server.WEBROOT, "login.html")) as f:
        html = f.read()
    assert gui_server.DEFAULT_SETUP_USER not in html
    assert gui_server.DEFAULT_SETUP_PASS not in html


def test_no_orphaned_control_ids():
    """Owner constraint for the toolbar rework: every element id referenced
    from app.js must exist in HTML or a mounted component. An unwired control
    would silently do nothing; a deleted element with a live binding would
    throw at load and kill every later binding."""
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert 'id="iris-device-details-root"' in html
    assert 'mountDeviceDetails();' in _react_shell("main.jsx")
    html += _react_shell("device-details.jsx")
    assert 'id="iris-activity-root"' in html
    assert 'mountActivity();' in _react_shell("main.jsx")
    html += _react_shell("activity.jsx")
    assert 'id="iris-inventory-root"' in html
    html += _react_shell("inventory.jsx")
    assert 'id="iris-certificates-root"' in html
    assert 'mountCertificates();' in _react_shell("main.jsx")
    html += _react_shell("certificates.jsx")
    ids = set(re.findall(r"getElementById\('([^']+)'\)", js))
    ids |= set(re.findall(r"querySelector(?:All)?\('#([A-Za-z0-9_-]+)", js))
    # The adapter shrinks as views move to React. Pin actual cross-owner
    # references rather than demanding an arbitrary number of legacy IDs.
    assert {'view-swarm', 'view-devices', 'settings-pane-certificates'} <= ids
    missing = sorted(i for i in ids if ('id="%s"' % i) not in html)
    assert not missing, \
        "app.js references ids missing from index.html: %s" % missing


def test_csv_download_buttons_and_multiselect_onboard_wired():
    component, js = _react_shell("inventory.jsx"), _webroot("app.js")
    csv = component.split('id="csv-menu"', 1)[1].split('</div>', 1)[0]
    for action in ('import-csv', 'export-csv', 'example-csv'):
        assert "['" + action + "'," in csv
        assert "onInventoryAction('" + action + "'," in js
    assert '<button key={id} type="button"' in csv and 'href=' not in csv and 'download=' not in csv
    assert "bulkButton('onboard-selected'" in component and 'id="mark-all"' in component
    assert 'function downloadCsv(' in js
    assert "controller.edit(id, 'credential', event.target.value)" in component
    assert 'onKeyDown={event =>' in component and 'controller.toggle(id)' in component
    assert 'post: jpost' in js


def test_devices_toolbar_regrouped():
    html, component, js = _webroot("index.html"), _react_shell("inventory.jsx"), _webroot("app.js")
    assert 'className="selbar" id="sel-bar" hidden={!state.selected.size}' in component
    modal = _react_shell('inventory-actions.jsx')
    for cid in ('onboard-telemetry', 'onboard-telemetry-stream'):
        assert "'%s'" % cid in modal
    assert "id={action + '-confirm'}" in modal
    assert 'id="onboard-pop"' not in html and 'id="undeploy-pop"' not in html
    assert "bulkButton('delete-selected', 'Delete…', 'menu-item danger menu-close')" in component
    headers = component.split("{['Device',", 1)[1].split('].map(label', 1)[0]
    assert len(re.findall(r"'[^']+'", headers)) == 10  # plus Device and Status
    assert "'Role'" in headers and "'Instructions'" in headers and '<th>Status' in component
    assert 'function wireMenu(' not in js and 'function updateSelBar(' in js
    for old in ('#dev-rows .onboard', '#dev-rows .adopt', "#dev-rows .del'", 'function startOnboard('):
        assert old not in js
    assert 'onclick=' not in js + html + component


def test_peer_policy_console_controls_are_typed_and_safe():
    html, js = _webroot("index.html"), _webroot("app.js")
    component, controller, model = (_react_shell(name) for name in ('inventory.jsx', 'inventory-controller.mjs', 'inventory-model.mjs'))
    assert "'Peer policy'" in component
    assert 'id="legacy-peer-warning" hidden' in _react_shell('swarm-view.jsx')
    assert "function refreshPeerPolicy()" not in js
    assert "'/api/v1/peer-policy'" in controller
    assert "'/api/v1/peer-policy/quarantine/' + encodeURIComponent(id)" in controller
    assert "method: 'PUT', headers: this.services.headers" in controller
    assert 'if_revision: policy.revision' in controller
    assert 'Existing device-to-device transfers may continue' in controller and 'Device software is unchanged' in controller
    assert 'Quarantined intent' in component and 'desired_ip_count' in model and 'conflict_types' in model
    swarm = _react_shell('swarm-view-model.mjs')
    assert "tracker.principal_type === 'legacy'" in swarm
    assert 'const tracker = peer.tracker' in swarm and 'device_ip' not in swarm.split('export function')[1]
    assert 'otlp_export.signals' in js and 'dropped_total' in js
    assert "method: 'DELETE'" not in controller and 'acl' not in controller.lower()


def test_import_from_disk_panel_wired():
    """Source guards for importing images already on disk: an Images-view panel
    fed by GET /api/images/importable, a per-row import posting the candidate's
    exact path with the CSRF header, and reuse of the existing publish poll."""
    component = _react_shell("images.jsx")
    controller = _react_shell("images-controller.mjs")
    js = _webroot("app.js")
    assert 'id="import-panel"' in component and 'id="import-rows"' in component
    assert 'data-path={item.path}' in component
    assert 'onClick={() => controller.importFile(item.path)}' in component
    assert '>{item.path}</td>' in component
    assert 'hidden={!state.importAvailable || (!state.importable.length && !state.skipped.length)}' in component
    assert "this.services.post('/api/v1/images/import', {path})" in controller
    assert "this.pollJob(body.job_id" in controller
    assert 'post: jpost' in js  # shared authenticated/CSRF transport
    shared_post = js.split('async function jpost(url, body)', 1)[1].split('\n  }', 1)[0]
    assert "headers: csrfHdr({ 'Content-Type': 'application/json' })" in shared_post
    assert 'else await this.refreshLists();' in controller
    assert "Promise.all([this.refresh(), this.refresh('importable')])" in controller


def test_publish_jobs_surface_automatic_hash_verification():
    """Both disk imports and uploads show the new verifying phase and verdict."""
    result = _react_shell("image-model.mjs")
    assert "job.verification" in result
    assert "verified against Cisco Bulk Hash" in result
    assert "Cisco hash mismatch — quarantined" in result
    assert "not found in Cisco Bulk Hash feed" in result
    assert "Cisco hash verification incomplete" in result
    controller = _react_shell("images-controller.mjs")
    assert "this.pollJob(job.job_id" in controller  # uploads
    assert "this.pollJob(body.job_id" in controller  # disk imports
    assert "job.state === 'verifying'" in controller
    assert "checking Cisco Bulk Hash" in controller
    assert "ui.done(publishedJobText(job))" in controller


def test_bulk_row_actions_wired():
    """Adopt/delete selected and a bulk credential assign, with a confirmation
    on the destructive delete. Per-row action links were removed by the
    toolbar rework (2026-08-12 spec) — a single row is deleted by checking
    its row and using the selection bar's Delete, the same path as a bulk
    delete, so there is exactly one confirm(delWarning(...)) call site."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    for action in ('adopt-selected', 'delete-selected'):
        assert "bulkButton('" + action + "'" in _react_shell('inventory.jsx')
    assert 'id="cred-selected"' in _react_shell('assignments.jsx')
    assert "'apply-cred-selected'" in _react_shell('assignments.jsx')

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "'adopt-selected'" in js and "'delete-selected'" in js
    assert "'apply-cred-selected'" in js
    controller = _react_shell('inventory-actions-controller.mjs')
    assert "/adopt'" in controller and "acknowledge_adopt: true" in controller
    # the per-row credential dropdown still uses the single-device route...
    assert "controller.edit(id, 'credential', event.target.value)" in _react_shell('inventory.jsx')
    # ...but the bulk credential action (issue #125) posts ONE request
    # carrying every selected id, not one per-device request each --
    # see bulkApply and gui_server.py's /api/devices/bulk-credential.
    assert "'/api/v1/devices/bulk-credential'" in _react_shell('assignments-controller.mjs')
    assert "bulkCredentialResult(response" in _react_shell('assignments-controller.mjs')
    # the single delete path confirms first
    assert controller.count("confirm(actionConfirmation(action, ids))") == 1
    # the warning must say deletion is not an undeploy — the dangerous part
    assert "does NOT undeploy" in _react_shell('inventory-actions-model.mjs')
    # creating or deleting a profile re-renders the device rows, so a device
    # imported before any profile existed becomes assignable immediately
    assert "await this.refreshCredentials(); await this.refreshInventory();" in _react_shell('device-forms-controller.mjs')
    assert "inventory.update(state);" in js
    assert "assignments.prerequisites(inventory.snapshot())" in js


def test_all_selected_actions_share_one_busy_lock():
    """Every selected-action must hold the same lock. Onboard/undeploy used to
    guard only each other, so a delete could remove inventory out from under a
    starting onboard batch."""
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "var BULK_BTNS = [" in js
    block = js.split("var BULK_BTNS = [")[1].split("]")[0]
    actions = re.findall(r"'([a-z-]+)'", block)
    # Onboard and undeploy now FIRE from inside their modal (Magnetic Dropdown
    # sends bulk-bar options to a modal rather than a menu), so the ids that
    # claim the lock are the modal primaries.
    for el in ("onboard-confirm", "undeploy-confirm", "adopt-selected",
               "delete-selected", "apply-cred-selected", "assign-images-selected"):
        assert el in actions, "%s is not covered by the bulk busy lock" % el
    # The bar's own Onboard…/Undeploy…/Set credential… only OPEN those modals,
    # so they claim nothing -- but a batch already starting must not be able to
    # hand out a second one, so setBulkBusy has to disable them too.
    openers = re.findall(r"'([a-z-]+)'",
                         js.split("var BULK_OPENERS = [")[1].split("]")[0])
    for el in ("onboard-selected", "undeploy-selected", "set-cred-selected"):
        assert el in openers, "%s is not disabled while a bulk action runs" % el
    assert "BULK_BTNS.concat(BULK_OPENERS).forEach" in js
    # Controllers claim the common adapter lock, never another button's state.
    assert "claimSelection()" not in js
    for name in ('assignments', 'inventory-actions', 'schedules', 'role-actions'):
        owner = _react_shell(name + '-controller.mjs')
        assert "this.services.claimBulk(" in owner and "this.services.releaseBulk()" in owner
    assert "roleActions.quarantine(selectedIds(), true)" in js
    assert "roleActions.quarantine(selectedIds(), false)" in js
    assert "onBtn.disabled" not in js and "unBtn.disabled" not in js
    # Migrated actions all claim the same lock through their controller.
    controller = _react_shell('inventory-actions-controller.mjs')
    assert "this.services.claimBulk()" in controller and "this.services.releaseBulk()" in controller
    assert "inventoryActions.act('delete', selectedIds())" in js
    assert "inventoryActions.act('adopt', selectedIds())" in js


def test_batch_onboard_panel_wired():
    """Source guards for parallel onboarding: bulk-onboard opens a batch panel
    with per-device live status (polled from GET /api/onboard/jobs), a per-row
    log action reusing the SSE log panel, and a cancel-queued control."""
    html = _react_shell("activity.jsx")
    assert 'id="batch-panel"' in html
    assert 'id="batch-rows"' in html
    assert 'id="batch-summary"' in html
    assert 'id="batch-cancel"' in html

    js = _react_shell("activity-controller.mjs")
    assert "'/api/v1/onboard/jobs'" in js or '"/api/v1/onboard/jobs"' in js
    assert "/api/v1/onboard/cancel-queued" in js
    assert "controller.cancelQueued()" in html and "controller.openLog(job.id)" in html
    # cancel is SCOPED to this panel's jobs — a bare cancel-all would nuke
    # other sessions' queued batches
    assert "{job_ids: ids}" in js
    assert "activityRows(this.state).filter(job => job.state === 'queued')" in js
    # durations come from the server clock in the listing, not Date.now()
    assert "now: body.now ?? null" in js
    assert "job.finished_at ?? state.now" in _react_shell("activity-model.mjs")
    # a reload re-attaches to still-running onboards instead of losing them
    assert "async setVisible(visible)" in js and "return this.refresh()" in js


def test_undeploy_and_status_ui_wired():
    """Source guards for the console-feedback round: (1) an Undeploy-selected
    button that confirms before firing (destructive), (2) batch rows labeled
    with the job action, (3) queue position on queued rows, (4) a real
    deployed/staging indicator in the devices table."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert "bulkButton('undeploy-selected'" in _react_shell('inventory.jsx')

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "undeploy-selected" in js
    assert "inventoryActions.open('undeploy', selectedIds())" in js
    assert "action === 'undeploy' && !await this.services.confirm" in _react_shell('activity-controller.mjs')
    assert "actionLabel(job.action)" in _react_shell("activity.jsx")
    assert "queued.indexOf(job) + 1" in _react_shell("activity-model.mjs")
    assert "deployed" in js                      # devices tab staged indicator
    # job-aware statuses: post-onboard boot gap must not read as "not enrolled"
    assert "waiting for heartbeat" in js
    assert "onboarding…" in js and "undeploying…" in js
    assert "Waiting for heartbeat" in js         # overview card


def test_status_display_map_covers_every_status():
    """Task 4: statusDisplay()/statusPillHTML() are the ONE derivation of the
    Magnetic 12-level status grammar, built next to deviceStatus() itself
    (same "one derivation feeds both" reasoning as
    test_every_status_the_cell_can_show_is_filterable below) so the rendered
    pill and the filter dropdown can never disagree about a status. Every
    key deviceStatus() can produce (DEVICE_STATUS_OPTIONS, app.js:62-76),
    plus the 'offline' freshness modifier deviceIsOffline() applies on top,
    must be covered. 'deployed' keeps its WIRE key unchanged -- only the
    pill/dropdown DISPLAY text becomes "Staged" (spec: derivation in app.js
    unchanged)."""
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "function statusDisplay(" in js
    assert "function statusPillHTML(" in js
    for key in ("onboarding", "undeploying", "waiting-heartbeat",
                "onboard-failed", "undeploy-failed", "deployed",
                "placement-failed", "image-failed", "copying", "staging",
                "enrolled", "not-enrolled", "offline"):
        assert "'%s'" % key in js, key
    # the wire key is untouched; only the DISPLAY label changes
    assert "['deployed', 'Staged']" in js
    # the 8 pill levels the CSS/sprite must supply (Warning/Severe split by
    # N-of-M severity for image-failed; Disabled has no producible key yet,
    # so it only ever appears as a bare map key, not a quoted value)
    for level in ("positive", "progress", "negative", "warning", "severe",
                  "info", "inactive", "disabled"):
        assert level in js, level
    for icon in ("i-check-circle", "i-dash-circle", "i-octagon-x",
                 "i-triangle-warn", "i-diamond-severe", "i-square-info",
                 "i-minus-circle", "i-slash-circle"):
        assert icon in js, icon


def test_monitoring_timeline_wired():
    """React owns Monitoring; its narrow bridge shares authenticated polling."""
    assert 'id="iris-monitoring-root"' in _webroot("index.html")
    assert "mountMonitoring();" in _react_shell()
    component = _react_shell("monitoring.jsx")
    assert '<Timeline kind="audit"' in component
    assert '<Timeline kind="deploylogs"' in component
    assert 'id={`${id}-range-chips`}' in component
    assert "dangerouslySetInnerHTML" not in component
    js = _webroot("app.js")
    assert "await monitoringCommand('connect', {fetch: fetch});" in js
    assert "poll = pollMonitoring;" in js
    assert "document.getElementById('audit-" not in js
    assert "document.getElementById('dl-" not in js


def test_monitoring_brush_wired():
    """Shared React brush retains independent bar/selection layers and cancel."""
    component = _react_shell("monitoring.jsx")
    for suffix in ("bars", "brush", "clear-selection"):
        assert 'id={`${id}-%s`}' % suffix in component
    for handler in ("onPointerDown", "onPointerMove", "onPointerUp",
                    "onPointerCancel", "onLostPointerCapture", "onKeyDown"):
        assert handler in component
    assert "setPointerCapture" in component and "releasePointerCapture" in component
    assert "'Escape'" in component
    model = _react_shell("monitoring-model.mjs")
    assert "histogram.set('since_ts'" in model and "histogram.set('until_ts'" in model
    assert "bucketCount(state.selection.end - state.selection.start)" in model
    assert "bucket_seconds" in _react_shell("monitoring-controller.mjs")


def test_audit_message_composer_wired():
    """Audit text is rendered as React text, with all existing event verbs."""
    component = _react_shell("monitoring.jsx")
    assert "['Time', 'Actor', 'Message', 'Result']" in component
    js = _react_shell("monitoring-model.mjs")
    assert "function auditMessage(" in js
    # verb coverage: console + legacy broker events
    for ev in ("login_fail", "password_change_fail", "revoke_other_sessions",
               "device_csv_import", "device_credential_change",
               "onboard_finished", "credential_profile_delete",
               "image_publish_finished", "request_report",
               "mint", "refresh_fail", "auth_fail", "revoke"):
        assert ev in js, ev
    # legacy fallbacks: device_id fills actor/target; token rotation detail
    assert "`device:${event.device_id}`" in js
    assert "event.secret_name" in js and "event.old_id" in js and "event.new_id" in js
    assert "badge-ok" in component and "badge-fail" in component
    assert "cat-tag" in component
    assert "function formatAgo(" in js
    # empty non-append result shows the empty state AND resets the pager cursor
    assert "No events in this range." in component

    with open(os.path.join(gui_server.WEBROOT, "styles.css")) as f:
        css = f.read()
    assert ".badge-ok" in css and ".badge-fail" in css
    assert ".cat-token" in css and ".brush-handle" in css


def test_buttons_have_tactile_states():
    """Guard: console buttons must keep hover/active/focus-visible affordance
    (styles.css) so the press feels tactile instead of dead -- a future edit
    that strips these rules should fail this test, not just look worse."""
    with open(os.path.join(gui_server.WEBROOT, "styles.css")) as f:
        css = f.read()
    assert ':active' in css
    assert ':focus-visible' in css
    assert '.chip' in css


def test_device_form_has_model_field():
    """The explicit series input bounds install choices and is sent on save."""
    form = _react_shell('device-forms.jsx')
    assert 'id="df-model"' in form
    assert "controller.setDevice('model', event.target.value)" in form
    assert 'model: form.model.trim()' in _react_shell('device-forms-model.mjs')


def test_settings_tls_trust_and_destination_sections_wired():
    """React owns these forms, their state and guarded writes; the router
    only selects a pane and supplies authenticated services. Runtime tests
    exercise labels, confirmations, bounded requests and uncertain replies."""
    html, js = _webroot("index.html"), _webroot("app.js")
    component = _react_shell("settings.jsx")
    model = _react_shell("settings-model.mjs")
    controller = _react_shell("settings-controller.mjs")
    for name in ("general", "tls", "audit"):
        assert 'id="iris-settings-%s"' % name in html
    assert "mountSettings();" in _react_shell()
    assert "settings.connect({" in js and "fetch: fetch, headers: csrfHdr" in js
    for endpoint in ("gui-cert", "trust", "ca-trust", "ca-trust/refresh",
                     "telemetry-destination", "audit-export", "password",
                     "sessions/revoke-others", "peer-tls"):
        assert "'" + endpoint + "'" in model
    assert "this.services.headers(" in controller
    assert "checkedSettingsResult(request, response, body)" in controller
    assert "this.clearSecrets(group)" in controller
    assert "this.state.unknown[group]" in controller
    for old in ("mountSettingsForm(", "wireTelemetryForm(", "pollCaRefresh(",
                "getElementById('cert-form')", "getElementById('pw-form')"):
        assert old not in js
    assert "never returned by the server" in component
    assert "no longer trust it" in model
    assert "certificate and key will be removed" in model
    assert "uses deployment settings from the next sample" in model
    assert "createPortal(telemetry," in component
    assert " style=" not in html and "onclick=" not in html
    verbs = _react_shell("monitoring-model.mjs").split("const verbs = {")[1].split("};")[0]
    for event in ("gui-cert-replace", "gui-cert-revert", "trust-add", "trust-remove",
                  "ca-trust-config", "ca-trust-refresh", "telemetry-destination-set",
                  "telemetry-destination-clear"):
        assert "'%s'" % event in verbs
    assert ".inline-form textarea" in _webroot("styles.css")


def _react_shell(name="main.jsx"):
    path = os.path.join(gui_server.WEBROOT, "..", "console-ui", "src", name)
    with open(path, encoding="utf-8") as stream:
        return stream.read()


def test_settings_uses_react_section_navigation():
    """A single rail entry leads to local sections without remounting forms."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    side = _react_shell("settings-navigation.jsx")
    assert "link('settings/general', 'Settings', 'gear', route.startsWith('settings'))" in _react_shell()
    assert 'aria-label="Settings sections"' in side
    for sub in ("general", "tls", "telemetry"):
        assert ("['%s'," % sub) in side, sub
    assert 'href={`#settings/${id}`}' in side
    settings = html.split('id="view-settings"')[1].split("</section>")[0]
    assert 'id="iris-settings-navigation-root"' in settings
    for pane_id in ("settings-pane-general", "settings-pane-tls", "settings-pane-telemetry"):
        assert ('id="%s"' % pane_id) in settings, pane_id
    # exactly one pane is visible in the static markup: General (the default)
    hidden_panes = [p for p in ("settings-pane-general", "settings-pane-tls",
                                 "settings-pane-telemetry")
                    if ('id="%s" hidden' % p) in settings]
    assert hidden_panes == ["settings-pane-tls", "settings-pane-telemetry"]
    assert 'id="settings-pane-general" hidden' not in settings

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    # app.js builds the six ids by concatenation ('settings-pane-' + t) rather
    # than spelling each one out, so assert the prefixes plus the sub-name
    # array that drives the concatenation (mirrors the orphan guard's own
    # getElementById/querySelector extraction, which only catches literals).
    assert "'settings-pane-' + t" in js
    assert "'nav-settings-' + t" not in js
    assert re.search(
        r"SETTINGS_SUBS\s*=\s*\[\s*'general'\s*,\s*'tls'\s*,\s*'telemetry'\s*\]", js)
    # the router owns sub-page selection: #settings/<sub> deep-links resolve
    assert "showSettingsSub(" in js
    assert "window.addEventListener('hashchange', update)" in side


def test_device_packages_have_a_persistent_settings_view():
    """Package readiness remains inspectable after first-run setup closes."""
    html = _webroot("index.html")
    js = _webroot("app.js")
    component = _react_shell('setup-packages.jsx')
    controller = _react_shell('setup-packages-controller.mjs')
    model = _react_shell('setup-packages-model.mjs')
    assert 'href="#settings/packages"' in component
    assert "['packages', 'Device packages'," in _react_shell("settings-navigation.jsx")
    assert 'id="settings-pane-packages" hidden' in html
    assert 'id="iris-device-packages"' in html
    assert 'prefix="device-packages"' in component
    assert "recheck('device-packages-recheck'" in component
    assert "SETTINGS_SUBS.push('packages')" in js
    assert "setupPackages.select(sub === 'setup' || sub === 'packages' ? sub : null)" in js
    assert "'/api/v1/settings/setup-status'" in model and 'read(setupURL, setupStatus)' in controller
    assert component.count('<PackageTable pkg=') == 3
    assert 'row.detail || row.reason' in component and 'packageRemedy(pkg)' in component
    assert 'deployment-neutral' in component
    assert 'does not authenticate that manifest or verify native package signatures' in component
    assert "pins this server's certificate when they are built" not in component


def test_read_version_env_handling(monkeypatch):
    monkeypatch.setenv("IRIS_VERSION", " 2026.07.02\n")
    assert gui_server._read_version() == "2026.07.02"
    # compose passes "${IRIS_VERSION:-}": an EMPTY or blank env var must be
    # treated as unset (fall through to a VERSION file / "unknown") and must
    # NEVER surface as an empty version string on the Settings page.
    for blank in ("", "   ", "\n"):
        monkeypatch.setenv("IRIS_VERSION", blank)
        v = gui_server._read_version()
        assert v and v == v.strip()


import http.client
import json
import threading

import gui_app
import deployment_records


def _serve(tmp_path):
    """Start gui_server on an ephemeral port (no TLS) with a preset admin.
    Returns (host, port, app, stop_fn)."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    app.set_admin("admin", "pw")
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return "127.0.0.1", port, app, srv.shutdown


def _req(host, port, method, path, body=None, headers=None, raw=None):
    c = http.client.HTTPConnection(host, port, timeout=5)
    hdrs = dict(headers or {})
    if raw is not None:
        payload = raw
    elif body is not None:
        payload = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    else:
        payload = None
    c.request(method, path, body=payload, headers=hdrs)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, dict(r.getheaders()), data


def test_login_bad_credentials_401(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, _, _ = _req(host, port, "POST", "/api/login",
                            {"username": "admin", "password": "nope"})
        assert status == 401
    finally:
        stop()


def test_canonical_quarantine_keeps_gui_filter_explain_and_event_wire_shape(
        role_api):
    """The canonical quarantine map has the legacy API's stable projections."""
    import auth
    import peer_endpoints
    import peer_policy

    request, _fleet, cat = role_api
    policy_path = os.path.join(cat.state_dir, "peer-policy.json")
    lkg_path = os.path.join(cat.state_dir, "peer-policy.lkg.json")
    doc = peer_policy.load_policy(policy_path, lkg_path).document
    doc["acls"]["manual"] = {"rules": [
        {"seq": 20, "action": "permit", "match": {"type": "any"}},
    ]}
    doc["assignments"] = {"d1": "manual", "d2": "quarantine"}
    doc["roles"]["role_of"] = {"d1": "boat", "d2": "boat"}
    doc["quarantined_devices"] = {"d1": True}
    for path in (policy_path, lkg_path):
        with open(path, "w") as stream:
            json.dump(doc, stream, sort_keys=True)
    endpoints = os.path.join(cat.state_dir, "peer-endpoints.json")
    peer_endpoints.record_endpoint(
        endpoints, auth.Principal("device", "d1"), "192.0.2.1", 6881,
        time.time())
    peer_endpoints.record_endpoint(
        endpoints, auth.Principal("device", "d2"), "192.0.2.2", 6881,
        time.time())

    status, _headers, view = request("GET", "/api/peer-policy")
    assert status == 200
    assert view["quarantine_assignments"] == ["d1", "d2"]
    assert "quarantined_devices" not in json.dumps(view)

    status, _headers, filtered = request(
        "GET", "/api/devices?peer=quarantined")
    assert status == 200
    assert filtered["total"] == 2
    assert [row["device_id"] for row in filtered["devices"]] == ["d1", "d2"]

    status, _headers, explained = request(
        "GET", "/api/peer-policy/explain?a=device:d1&b=device:d2")
    assert status == 200
    assert set(explained["a"]) == {
        "principal", "acl_name", "acl_source", "matched_seq", "decision",
        "role", "role_unknown", "role_shadowed_by"}
    assert explained["a"]["acl_name"] == "quarantine"
    assert explained["a"]["acl_source"] == "assignment:quarantine"
    assert explained["a"]["decision"] == "deny"
    assert explained["a"]["role"] == "boat"
    assert explained["a"]["role_shadowed_by"] == "boat"

    revision = peer_policy.load_policy(policy_path, lkg_path).document["revision"]
    before_events = list(peer_policy.load_policy(
        policy_path, lkg_path).document["operation_outbox"])
    status, _headers, _ = request(
        "PUT", "/api/peer-policy/quarantine/d2",
        {"quarantined": True, "if_revision": revision})
    assert status == 200
    saved = peer_policy.load_policy(policy_path, lkg_path).document
    assert saved["quarantined_devices"] == {"d1": True, "d2": True}
    assert saved["assignments"] == {"d1": "manual"}
    assert "d2" not in saved["assignments"]
    assert saved["operation_outbox"][:-1] == before_events
    event = saved["operation_outbox"][-1]
    assert set(event) == {"event_id", "revision", "action", "target",
                          "actor", "created_at"}
    assert event["action"] == "assign" and event["target"] == "d2"


def test_login_sets_cookie_and_returns_csrf(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, headers, body = _req(host, port, "POST", "/api/login",
                                     {"username": "admin", "password": "pw"})
        assert status == 200
        assert "iris_sid=" in headers.get("Set-Cookie", "")
        assert "HttpOnly" in headers["Set-Cookie"]
        assert "SameSite=Strict" in headers["Set-Cookie"]
        # Rewritten (IRIS-06-003): this fixture serves plain HTTP, and a
        # Secure cookie set over http:// is discarded by every browser except
        # on localhost -- the old assertion encoded a login loop. Secure is
        # asserted over TLS in test_login_cookie_is_secure_over_tls.
        assert "Secure" not in headers["Set-Cookie"]
        assert "Path=/" in headers["Set-Cookie"]
        assert json.loads(body)["csrf"]
    finally:
        stop()


def test_session_requires_cookie(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, _, _ = _req(host, port, "GET", "/api/session")
        assert status == 401
    finally:
        stop()


def test_full_login_session_logout_flow(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, headers, body = _req(host, port, "POST", "/api/login",
                                     {"username": "admin", "password": "pw"})
        cookie = headers["Set-Cookie"].split(";")[0]           # iris_sid=...
        csrf = json.loads(body)["csrf"]

        status, _, body = _req(host, port, "GET", "/api/session",
                               headers={"Cookie": cookie})
        assert status == 200 and json.loads(body)["username"] == "admin"

        # logout without CSRF -> 403
        status, _, _ = _req(host, port, "POST", "/api/logout",
                            headers={"Cookie": cookie})
        assert status == 403

        # logout with CSRF -> 200, then session is dead
        status, _, _ = _req(host, port, "POST", "/api/logout",
                            headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 200
        status, _, _ = _req(host, port, "GET", "/api/session",
                            headers={"Cookie": cookie})
        assert status == 401
    finally:
        stop()


def test_static_index_served_and_traversal_blocked(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, headers, body = _req(host, port, "GET", "/")
        assert status == 200 and b"Intelligent Release" in body
        assert "text/html" in headers.get("Content-Type", "")
        # SPA assets must revalidate so a redeploy is not masked by a stale
        # browser cache (else new UI like the Monitoring tab stays invisible).
        assert "no-cache" in headers.get("Cache-Control", "")
        status, _, _ = _req(host, port, "GET", "/../secrets.json")
        assert status == 404
    finally:
        stop()


def test_oversized_login_body_rejected(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        big = {"username": "admin", "password": "x" * 70000}
        status, _, _ = _req(host, port, "POST", "/api/login", big)
        assert status == 413
    finally:
        stop()


def test_logout_unknown_session_401(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, _, _ = _req(host, port, "POST", "/api/logout",
                            headers={"Cookie": "iris_sid=bogus"})
        assert status == 401
    finally:
        stop()


def test_login_non_ascii_username_401(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, _, _ = _req(host, port, "POST", "/api/login",
                            {"username": "admén", "password": "pw"})
        assert status == 401
    finally:
        stop()


def test_security_headers_present(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, headers, _ = _req(host, port, "GET", "/")
        assert status == 200
        assert headers.get("X-Content-Type-Options") == "nosniff"
        assert headers.get("X-Frame-Options") == "DENY"
        assert "default-src 'self'" in headers.get("Content-Security-Policy", "")
    finally:
        stop()


import socket
import subprocess
import sys
import time

_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _wait_for_port(host, port, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def test_module_run_as_script_actually_starts_the_server(tmp_path):
    # Regression: gui_server.py defines main() but must also call it when run
    # as `python3 gui_server.py` (the container entrypoint). Without the
    # `if __name__ == "__main__"` guard, the process exits immediately and
    # the container crash-loops.
    host = "127.0.0.1"
    port = _free_port()
    secrets_path = str(tmp_path / "secrets.json")
    env = dict(os.environ)
    env["IRIS_GUI_HOST"] = host
    env["IRIS_GUI_PORT"] = str(port)
    env["IRIS_SECRETS"] = secrets_path
    env["IRIS_STATE"] = str(tmp_path / "state")
    env["IRIS_IMAGES_DIR"] = str(tmp_path / "images")
    env["IRIS_CERT"] = "/nonexistent-so-plain-http"
    env["IRIS_GUI_CERT"] = "/nonexistent-so-plain-http-too"
    env["IRIS_MANAGEMENT_API_URL"] = "https://127.0.0.1:1"
    token_file = tmp_path / "management-token"
    token_file.write_text(json.dumps({"scope": "management", "token": "t" * 64}))
    token_file.chmod(0o600)
    env["IRIS_MANAGEMENT_API_TOKEN_FILE"] = str(token_file)
    ca_file = tmp_path / "management-ca.pem"
    ca_file.write_text("unusable-for-a-live-connection")
    env["IRIS_MANAGEMENT_API_CA"] = str(ca_file)
    # Without the exact development opt-in the state-free BFF refuses to
    # start when it cannot fetch a serving identity from management.
    env.pop("IRIS_GUI_ALLOW_PLAINTEXT", None)
    refused = subprocess.run([sys.executable, "gui_server.py"], cwd=_SERVER_DIR,
                             env=env, capture_output=True, timeout=30)
    assert refused.returncode == 2
    assert b"refusing to start" in refused.stderr
    assert not _wait_for_port(host, port, timeout=0.5)
    # The explicit opt-in is what this plain-HTTP harness needs.
    env["IRIS_GUI_ALLOW_PLAINTEXT"] = "1"

    proc = subprocess.Popen(
        [sys.executable, "gui_server.py"],
        cwd=_SERVER_DIR,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert _wait_for_port(host, port, timeout=5.0), (
            "gui_server.py did not start listening on %s:%d -- process likely "
            "exited immediately (missing __main__ guard)" % (host, port)
        )
        status, _, body = _req(host, port, "GET", "/healthz")
        assert status == 200 and json.loads(body) == {"ok": True}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


import gui_images


def _serve_with_images(tmp_path, publish_fn=None, tracker_url="http://t/announce?key=k",
                       import_root=None):
    """Start gui_server with a preset admin AND an ImageService (fake publish)."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    app.set_admin("admin", "pw")

    def default_publish(image_path, store, url, **kw):
        entry = {"id": "img1", "filename": os.path.basename(image_path),
                 "size": os.path.getsize(image_path), "sha256": "ab" * 32,
                 "sha512": "cd" * 64, "cisco_signature_verified": False,
                 "info_hash_hex": "ee" * 20, "published_at": 1}
        store.save_image(entry)
        return entry

    images = gui_images.ImageService(
        str(tmp_path / "state"), str(tmp_path / "imgs"),
        tracker_url_fn=lambda: tracker_url,
        publish_fn=publish_fn or default_publish,
        import_root=import_root or str(tmp_path / "opt-images"))
    srv = gui_server.make_server("127.0.0.1", 0, app, images, certfile=None)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return "127.0.0.1", port, app, images, srv.shutdown


def _login(host, port):
    status, headers, body = _req(host, port, "POST", "/api/login",
                                 {"username": "admin", "password": "pw"})
    assert status == 200
    return headers["Set-Cookie"].split(";")[0], json.loads(body)["csrf"]


def test_images_list_requires_auth(tmp_path):
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        status, _, _ = _req(host, port, "GET", "/api/images")
        assert status == 401
    finally:
        stop()


def test_upload_streams_publishes_and_lists(tmp_path):
    host, port, _, images, stop = _serve_with_images(tmp_path)
    try:
        cookie, csrf = _login(host, port)
        status, _, body = _req(
            host, port, "PUT", "/api/images/upload/img.bin",
            raw=b"IMAGE-CONTENTS",
            headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 200
        job_id = json.loads(body)["job_id"]
        assert os.path.isfile(str(tmp_path / "imgs" / "img.bin"))
        import time as _t
        deadline = _t.time() + 3
        state = None
        while _t.time() < deadline:
            s, _, jb = _req(host, port, "GET", "/api/images/jobs/" + job_id,
                            headers={"Cookie": cookie})
            assert s == 200
            state = json.loads(jb)["state"]
            if state in ("done", "error"):
                break
            _t.sleep(0.02)
        assert state == "done"
        s, _, lb = _req(host, port, "GET", "/api/images", headers={"Cookie": cookie})
        assert s == 200
        ids = [i["id"] for i in json.loads(lb)["images"]]
        assert "img1" in ids
    finally:
        stop()


def _seed_importable(tmp_path, name="staged.26.01.01.SPA.bin"):
    """Drop an unpublished image into the read-only-style import root."""
    d = tmp_path / "opt-images" / "iosxe" / "c9300"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(b"STAGED-ON-DISK")
    return str(d / name)


def test_importable_list_requires_auth(tmp_path):
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/images/importable")[0] == 401
    finally:
        stop()


def test_importable_lists_unpublished_disk_images(tmp_path):
    _seed_importable(tmp_path)
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        cookie, _csrf = _login(host, port)
        status, _, body = _req(host, port, "GET", "/api/images/importable",
                               headers={"Cookie": cookie})
        assert status == 200
        found = json.loads(body)["importable"]
        assert [c["filename"] for c in found] == ["staged.26.01.01.SPA.bin"]
        assert found[0]["root"] == "import"
    finally:
        stop()


def test_import_requires_csrf(tmp_path):
    path = _seed_importable(tmp_path)
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        cookie, _csrf = _login(host, port)
        status, _, _ = _req(host, port, "POST", "/api/images/import",
                            {"path": path}, headers={"Cookie": cookie})
        assert status == 403
    finally:
        stop()


def test_import_requires_a_session(tmp_path):
    path = _seed_importable(tmp_path)
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        assert _req(host, port, "POST", "/api/images/import",
                    {"path": path})[0] in (401, 403)
    finally:
        stop()


def test_importable_reports_skipped_with_reason(tmp_path):
    """A file the operator expects must not silently fail to appear: an
    ambiguous same-named pair is reported as skipped, with the reason."""
    _seed_importable(tmp_path)
    (tmp_path / "imgs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "imgs" / "staged.26.01.01.SPA.bin").write_bytes(b"twin")
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        cookie, _csrf = _login(host, port)
        s, _, body = _req(host, port, "GET", "/api/images/importable",
                          headers={"Cookie": cookie})
        assert s == 200
        out = json.loads(body)
        assert out["importable"] == []
        assert {c["reason"] for c in out["skipped"]} == {
            "ambiguous name in more than one location"}
    finally:
        stop()


def test_import_rejection_is_audited(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        cookie, csrf = _login(host, port)
        st, _, _ = _req(host, port, "POST", "/api/images/import",
                        {"path": "/etc/shadow"},
                        headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert st == 400
        ev = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "image_import" and e.get("result") == "fail"]
        assert ev and "/etc/shadow" in ev[0]["detail"]
    finally:
        stop()


def test_import_publishes_in_place_without_copying(tmp_path):
    path = _seed_importable(tmp_path)
    seen = {}

    def publish_fn(image_path, store, url, **kw):
        seen["path"] = image_path
        entry = {"id": "staged.26.01.01", "filename": os.path.basename(image_path),
                 "size": 14, "published_at": 1}
        store.save_image(entry)
        return entry

    host, port, _, _, stop = _serve_with_images(tmp_path, publish_fn=publish_fn)
    try:
        cookie, csrf = _login(host, port)
        status, _, body = _req(host, port, "POST", "/api/images/import",
                               {"path": path},
                               headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 200
        job_id = json.loads(body)["job_id"]
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            s, _, jb = _req(host, port, "GET", "/api/images/jobs/" + job_id,
                            headers={"Cookie": cookie})
            if json.loads(jb)["state"] in ("done", "error"):
                break
            _t.sleep(0.02)
        assert json.loads(jb)["state"] == "done"
        # published from where it already lived — never copied into the volume
        assert seen["path"] == path
        assert not os.path.exists(str(tmp_path / "imgs" / "staged.26.01.01.SPA.bin"))
        # and it drops out of the importable set once catalogued
        _s, _h, lb = _req(host, port, "GET", "/api/images/importable",
                          headers={"Cookie": cookie})
        assert json.loads(lb)["importable"] == []
    finally:
        stop()


def test_import_rejects_path_outside_the_candidate_set(tmp_path):
    _seed_importable(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(b"not-ours")
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        cookie, csrf = _login(host, port)
        hdrs = {"Cookie": cookie, "X-CSRF-Token": csrf}
        for bad in (str(outside / "secret.bin"),
                    # starts inside a real root but escapes via traversal, so a
                    # prefix check would wrongly accept it
                    str(tmp_path / "opt-images" / ".." / "outside" / "secret.bin"),
                    "/etc/shadow", ""):
            status, _, _ = _req(host, port, "POST", "/api/images/import",
                                {"path": bad}, headers=hdrs)
            assert status == 400, "expected 400 for %r" % bad
    finally:
        stop()


def test_import_of_vanished_file_is_404(tmp_path):
    path = _seed_importable(tmp_path)
    host, port, _, images, stop = _serve_with_images(tmp_path)
    try:
        cookie, csrf = _login(host, port)
        real_check = images.is_importable_path
        # authorize the path, then delete it before start_publish runs
        def racy(p):
            ok = real_check(p)
            os.remove(path)
            return ok
        images.is_importable_path = racy
        status, _, body = _req(host, port, "POST", "/api/images/import",
                               {"path": path},
                               headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 404
        # specifically the vanished-file branch, not a generic route miss
        assert json.loads(body)["error"] == "image no longer on disk"
    finally:
        stop()


def test_import_emits_audit_event(tmp_path):
    path = _seed_importable(tmp_path)
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        cookie, csrf = _login(host, port)
        st, _, _ = _req(host, port, "POST", "/api/images/import", {"path": path},
                        headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert st == 200
        ev = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "image_import"]
        assert ev and ev[0]["actor"] == "console:admin"
        assert ev[0]["target"] == "staged.26.01.01.SPA.bin"
        assert path in ev[0]["detail"]
    finally:
        stop()


def test_upload_requires_csrf(tmp_path):
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        cookie, _csrf = _login(host, port)
        status, _, _ = _req(host, port, "PUT", "/api/images/upload/img.bin",
                            raw=b"x", headers={"Cookie": cookie})
        assert status == 403
    finally:
        stop()


def test_upload_rejects_bad_filename(tmp_path):
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        cookie, csrf = _login(host, port)
        status, _, _ = _req(host, port, "PUT", "/api/images/upload/bad%20name",
                            raw=b"x", headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 400
    finally:
        stop()


import socket as _socket


def test_upload_rejects_truncated_body(tmp_path):
    host, port, _, _, stop = _serve_with_images(tmp_path)
    try:
        cookie, csrf = _login(host, port)
        s = _socket.create_connection((host, port), timeout=5)
        head = ("PUT /api/images/upload/trunc.bin HTTP/1.0\r\n"
                "Host: x\r\n"
                "Cookie: %s\r\n"
                "X-CSRF-Token: %s\r\n"
                "Content-Length: 100\r\n"
                "\r\n" % (cookie, csrf)).encode()
        s.sendall(head + b"12345")        # promises 100 bytes, sends 5
        s.shutdown(_socket.SHUT_WR)        # EOF: server sees only 5 of 100
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        assert b" 400 " in resp.split(b"\r\n", 1)[0]        # status line is 400
        assert not os.path.isfile(str(tmp_path / "imgs" / "trunc.bin"))
    finally:
        stop()


import gui_fleet
import gui_creds
import catalog as catalog_mod
import keyed_state
import peer_enforcement


def _serve_full(tmp_path, record_store=None, now_fn=time.time):
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    images = gui_images.ImageService(state, str(tmp_path / "imgs"),
                                     tracker_url_fn=lambda: "http://t/announce?key=k",
                                     publish_fn=lambda p, s, u, **k: s.save_image(
                                         {"id": "img1", "filename": "img1.bin",
                                          "sha256": "ab", "published_at": 1}) or
                                     {"id": "img1"},
                                     import_root=str(tmp_path / "opt-images"))
    fleet = gui_fleet.FleetStore(state)
    creds = gui_creds.CredentialStore(secrets_path)
    cat = catalog_mod.CatalogStore(state)
    cat.save_image({"id": "img1", "filename": "img1.bin", "sha256": "ab",
                    "published_at": 1})
    srv = gui_server.make_server(
        "127.0.0.1", 0, app, images, fleet, creds, cat, certfile=None,
        record_store=record_store, now_fn=now_fn)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, (app, fleet, creds, cat), srv.shutdown


def _auth(host, port):
    s, h, b = _req(host, port, "POST", "/api/login",
                   {"username": "admin", "password": "pw"})
    return h["Set-Cookie"].split(";")[0], json.loads(b)["csrf"]


def _policy_device(fleet, device_id="d1"):
    return fleet.upsert({"device_id": device_id, "device_ip": "10.0.0.1",
                         "model": "C9300"})


def test_peer_policy_get_and_durable_quarantine_operation(tmp_path):
    host, port, (_, fleet, _, cat), stop = _serve_full(tmp_path)
    try:
        _policy_device(fleet)
        assert _req(host, port, "GET", "/api/peer-policy")[0] == 401
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, get_headers, raw = _req(
            host, port, "GET", "/api/peer-policy",
            headers={"Cookie": cookie})
        assert status == 200
        assert get_headers["ETag"] == '"iris-peer-policy-1"'
        view = json.loads(raw)
        assert view["revision"] == 1
        assert view["quarantine_assignments"] == []
        assert "rules" not in view["quarantine"]
        assert "aria_session_id" not in view["enforcement"]
        mismatch = dict(headers, **{"If-Match": '"iris-peer-policy-999"'})
        status, mismatch_headers, _ = _req(
            host, port, "PUT", "/api/peer-policy/quarantine/d1",
            {"quarantined": True, "if_revision": 1}, mismatch)
        assert status == 412
        assert mismatch_headers["ETag"] == '"iris-peer-policy-1"'
        preferred = dict(headers, **{"If-Match": get_headers["ETag"]})
        status, response_headers, raw = _req(
            host, port, "PUT", "/api/peer-policy/quarantine/d1",
            {"quarantined": True, "if_revision": 1}, preferred)
        assert status == 200
        assert response_headers["ETag"] == '"iris-peer-policy-2"'
        assert json.loads(raw) == {"ok": True, "revision": 2, "quarantined": True}
        with open(os.path.join(cat.state_dir, "peer-policy.json")) as f:
            doc = json.load(f)
        assert doc["assignments"] == {}
        assert doc["quarantined_devices"] == {"d1": True}
        event = doc["operation_outbox"][-1]
        assert set(event) == {"event_id", "revision", "action", "target", "actor", "created_at"}
        assert event["action"] == "assign" and event["target"] == "d1"
        assert event["actor"] == "console:admin"
        tracker_status = peer_enforcement.build_status(
            "pending", None, None, 1, 3, 10,
            last_operation_exported_revision=2,
            operation_ack_epoch=doc["operation_ack_epoch"],
            conflicts=[{"reason": "shared_permit_deny", "ipv4": "10.0.0.99",
                        "permitted_principal_type": "service",
                        "permitted_principal_id": "seeder",
                        "denied_principal_type": "device",
                        "denied_principal_id": "d1",
                        "global_block_applied": False}],
            last_effect={"disconnected_peers": 1, "removed_peers": 0})
        # A GUI reader must not blindly expose future/untrusted status fields.
        tracker_status["raw_ips"] = ["10.0.0.99"]
        peer_enforcement.write_status(
            os.path.join(cat.state_dir, "peer-enforcement.json"), tracker_status)
        status, _, raw = _req(host, port, "GET", "/api/peer-policy",
                              headers={"Cookie": cookie})
        observed = json.loads(raw)["enforcement"]
        assert status == 200 and observed["conflict_count"] == 1
        assert observed["conflict_types"] == ["shared_permit_deny"]
        assert "10.0.0.99" not in raw.decode()
        # The tracker acknowledgement is consumed only by the next durable
        # mutation, which prunes the acknowledged operation from the outbox.
        status, compat_headers, _ = _req(
            host, port, "PUT", "/api/peer-policy/quarantine/d1",
            {"quarantined": False, "if_revision": 2}, headers)
        assert status == 200
        assert compat_headers["Deprecation"] == "true"
        assert compat_headers["Sunset"] == "Sat, 04 Sep 2027 00:00:00 GMT"
        with open(os.path.join(cat.state_dir, "peer-policy.json")) as f:
            released = json.load(f)
        assert [e["revision"] for e in released["operation_outbox"]] == [3]
        assert released["assignments"] == {}
        assert "quarantined_devices" not in released
        status, _, raw = _req(host, port, "PUT", "/api/peer-policy/quarantine/d1",
                              {"quarantined": False, "if_revision": 2}, headers)
        assert status == 409
        assert json.loads(raw)["revision"] == 3
    finally:
        stop()


@pytest.mark.parametrize("count,device_ids", [
    (2, ["preflight-a", "preflight-b"]), (0, []), (None, None),
])
def test_peer_policy_view_projects_preflight_count_and_safe_origin_qos(
        tmp_path, count, device_ids):
    host, port, (_, _, _, cat), stop = _serve_full(tmp_path)
    try:
        cookie, _ = _auth(host, port)
        tracker_status = peer_enforcement.build_status(
            "enforced", "session-1", "block-hash", 1, 0, 1000.0,
            mutual_origin={
                "mode": "preflight",
                "newly_denied_device_count": count,
                "newly_denied_device_ids": device_ids,
            })
        tracker_status["endpoint_ips"] = ["10.0.0.99"]
        peer_enforcement.write_status(
            os.path.join(cat.state_dir, "peer-enforcement.json"), tracker_status)
        with open(os.path.join(cat.state_dir, "origin-qos.json"), "w") as handle:
            json.dump({
                "schema": 1, "updated_at": 1000.0, "state": "enforced",
                "aria_session_id": "session-1", "desired_hash": "qos-hash",
                "global_option_count": 1, "target_download_count": 2,
                "applied_download_count": 2, "last_reconciled_at": 1000.0,
                "last_error": "RpcError.10.0.0.97",
                # Readers must not blindly pass through future identifier fields.
                "gids": ["secret-target"], "addresses": ["10.0.0.98"],
            }, handle)

        status, _, raw = _req(host, port, "GET", "/api/peer-policy",
                              headers={"Cookie": cookie})
        assert status == 200
        view = json.loads(raw)
        assert view["enforcement"]["mutual_origin"] == {
            "mode": "preflight", "newly_denied_device_count": count,
        }
        # A syntactically valid file with an impossible enforced state is
        # neutral as a unit; redaction cannot leave a false success claim.
        assert view["origin_qos"] == {
            "state": None, "global_option_count": 0,
            "target_download_count": 0, "applied_download_count": 0,
            "last_reconciled_at": None, "last_error": None,
        }
        body = raw.decode()
        for forbidden in ("preflight-a", "preflight-b", "endpoint_ips",
                          "10.0.0.99", "secret-target", "10.0.0.98",
                          "RpcError.10.0.0.97", "10.0.0.97",
                          "aria_session_id", "desired_hash"):
            assert forbidden not in body
    finally:
        stop()


def test_peer_policy_enforcement_stale_flag(tmp_path):
    """IRIS-99: the tracker reconciler can freeze (its degraded-pass write
    itself failing, or the process dying) with peer-enforcement.json's last
    recorded state left at "enforced" -- looking healthy forever. The
    console must say so via enforcement.stale rather than showing a frozen
    claim as current, whether the frozen state is "enforced" or anything
    else, and whether last_reconciled_at is old or altogether absent."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    creds = gui_creds.CredentialStore(secrets_path)
    cat = catalog_mod.CatalogStore(state)
    now_box = {"t": 1_000_000.0}
    srv = gui_server.make_server(
        "127.0.0.1", 0, app, fleet=fleet, creds=creds, catalog=cat,
        certfile=None, now_fn=lambda: now_box["t"])
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cookie, _ = _auth("127.0.0.1", port)
        headers = {"Cookie": cookie}

        # No enforcement file at all -- never proven current -> stale.
        status, _, raw = _req("127.0.0.1", port, "GET", "/api/peer-policy",
                              headers=headers)
        assert status == 200
        e = json.loads(raw)["enforcement"]
        assert e["last_reconciled_at"] is None
        assert e["stale"] is True

        # A fresh "enforced" pass, recorded at the current now_fn() time.
        enforcement_path = os.path.join(cat.state_dir, "peer-enforcement.json")
        peer_enforcement.write_status(enforcement_path, peer_enforcement.build_status(
            "enforced", "sess-1", "hash-1", 1, 0, now_box["t"]))
        status, _, raw = _req("127.0.0.1", port, "GET", "/api/peer-policy",
                              headers=headers)
        e = json.loads(raw)["enforcement"]
        assert e["state"] == "enforced"
        assert e["stale"] is False

        # Time advances well past the staleness threshold with NO further
        # reconcile pass (the frozen-reconciler scenario): the same
        # "enforced" status must now read stale, not healthy.
        now_box["t"] += gui_server._PEER_POLICY_STALE_AFTER + 1
        status, _, raw = _req("127.0.0.1", port, "GET", "/api/peer-policy",
                              headers=headers)
        e = json.loads(raw)["enforcement"]
        assert e["state"] == "enforced"      # the frozen claim is unchanged
        assert e["stale"] is True            # but the console now flags it
    finally:
        srv.shutdown()


def test_peer_policy_rejects_unknown_device_and_bad_csrf(tmp_path):
    host, port, (_, fleet, _, _), stop = _serve_full(tmp_path)
    try:
        _policy_device(fleet)
        cookie, csrf = _auth(host, port)
        assert _req(host, port, "PUT", "/api/peer-policy/quarantine/d1",
                    {"quarantined": True, "if_revision": 1},
                    {"Cookie": cookie})[0] == 403
        assert _req(host, port, "PUT", "/api/peer-policy/quarantine/missing",
                    {"quarantined": True, "if_revision": 1},
                    {"Cookie": cookie, "X-CSRF-Token": csrf})[0] == 422
        # There is no DELETE policy API.
        assert _req(host, port, "DELETE", "/api/peer-policy/quarantine/d1",
                    headers={"Cookie": cookie, "X-CSRF-Token": csrf})[0] == 404
    finally:
        stop()


def test_devices_crud_and_list_requires_auth(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/devices")[0] == 401
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices",
                        {"device_id": "d1", "device_ip": "10.0.0.1",
                         "management_type": "routed", "iris_vlan": "666",
                         "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                         "app_ip": "10.0.0.3", "app_mask": "255.255.255.252",
                         "app_gateway": "10.0.0.1"}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        devs = json.loads(b)["devices"]
        assert devs and devs[0]["device_id"] == "d1"
        st, _, _ = _req(host, port, "DELETE", "/api/devices/d1", headers=hh)
        assert st == 200
        assert json.loads(_req(host, port, "GET", "/api/devices",
                               headers={"Cookie": ck})[2])["devices"] == []
    finally:
        stop()


def test_device_create_idempotency_replays_and_conflicts(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        headers = {"Cookie": ck, "X-CSRF-Token": csrf,
                   "Idempotency-Key": "create-device-d1"}
        body = {"device_id": "d1", "device_ip": "10.0.0.1"}
        first = _req(host, port, "POST", "/api/devices", body,
                     headers=headers)
        assert first[0] == 200
        replay = _req(host, port, "POST", "/api/devices", body,
                      headers=headers)
        assert replay[0] == 200
        assert replay[2] == first[2]
        assert replay[1]["Idempotency-Replayed"] == "true"
        conflict = _req(
            host, port, "POST", "/api/devices",
            {"device_id": "d1", "device_ip": "10.0.0.2"},
            headers=headers)
        assert conflict[0] == 409
        assert json.loads(conflict[2])["code"] == "resource-conflict"
    finally:
        stop()


def test_idempotency_capacity_never_evicts_in_flight_work():
    active = {"response": None, "created": 1}
    cache = {"active": active}
    assert gui_server._idempotency_make_room(cache, 1) is False
    assert cache == {"active": active}

    completed = {"response": (200, "application/json", b"{}", ()),
                 "created": 0}
    cache["completed"] = completed
    assert gui_server._idempotency_make_room(cache, 1) is True
    assert cache == {"active": active}


def test_device_upsert_rejects_machine_determined_fields(tmp_path):
    """Public input cannot claim server-owned observation or stamp fields."""
    host, port, (_, fleet, _, _), stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/devices",
                        {"device_id": "d1", "device_ip": "10.0.0.1",
                         "model": "C9300", "os_family": "xr",
                         "registered_at": 7}, headers=hh)
        assert st == 422
        assert "server-owned fleet field" in json.loads(b)["error"]
        assert fleet.get_device("d1") is None
        st, _, b = _req(host, port, "POST", "/api/devices",
                        {"device_id": "d2", "device_ip": "10.0.0.2",
                         "future_inventory_field": "surprise"}, headers=hh)
        assert st == 422
        assert "unknown fleet field" in json.loads(b)["error"]
        assert fleet.get_device("d2") is None
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        fleet.update_observation("d1", os_family="xe")
        st, _, b = _req(host, port, "POST", "/api/devices",
                        {"device_id": "d1", "os_family": "xr"}, headers=hh)
        assert st == 422
        assert fleet.get_device("d1")["os_family"] == "xe"
    finally:
        stop()


def test_device_delete_purges_catalog_state(tmp_path):
    # Deleting a device must clear its catalog-side state too — a device
    # that is deleted and added back comes back UNASSIGNED, never with a
    # resurrected stale assignment that would silently restage an image.
    host, port, (_, _, _, cat), stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        dev = {"device_id": "d1", "device_ip": "10.0.0.1",
               "management_type": "routed", "iris_vlan": "666",
               "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
               "app_ip": "10.0.0.3", "app_mask": "255.255.255.252",
               "app_gateway": "10.0.0.1"}
        st, _, _ = _req(host, port, "POST", "/api/devices", dev, headers=hh)
        assert st == 200
        cat.set_policy("d1", approved_image_id="img1")
        cat.record_heartbeat("d1", {"current_image_id": "img1"}, now=1)
        cat.record_telemetry("d1", {"event": "staging-complete"})
        st, _, b = _req(host, port, "DELETE", "/api/devices/d1", headers=hh)
        assert st == 200 and json.loads(b)["deleted"] is True
        assert cat.get_policy("d1") == {"approved_image_id": None,
                                        "approved_image_ids": []}
        assert cat.get_device("d1") is None
        assert cat.get_telemetry("d1") == []
        st, _, _ = _req(host, port, "POST", "/api/devices", dev, headers=hh)
        assert st == 200
        assert cat.get_policy("d1")["approved_image_id"] is None
    finally:
        stop()


def test_device_assign_empty_unassigns(tmp_path):
    # Selecting the empty option in the console dropdown must UNASSIGN —
    # before this, delete+re-add was the only way to clear an assignment.
    host, port, (_, _, _, cat), stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices",
                        {"device_id": "d1", "device_ip": "10.0.0.1",
                         "management_type": "routed", "iris_vlan": "666",
                         "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                         "app_ip": "10.0.0.3", "app_mask": "255.255.255.252",
                         "app_gateway": "10.0.0.1"}, headers=hh)
        assert st == 200
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_id": "img1"}, headers=hh)
        assert st == 200
        assert cat.get_policy("d1")["approved_image_id"] == "img1"
        st, _, b = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_id": ""}, headers=hh)
        assert st == 200 and json.loads(b)["ok"] is True
        assert cat.get_policy("d1")["approved_image_id"] is None
        # idempotent: unassigning an unassigned device is still ok
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_id": None}, headers=hh)
        assert st == 200
        assert cat.get_policy("d1")["approved_image_id"] is None
    finally:
        stop()


def test_device_post_requires_csrf(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, _ = _req(host, port, "POST", "/api/devices",
                        {"device_id": "d1", "device_ip": "1.2.3.4"},
                        headers={"Cookie": ck})
        assert st == 403
    finally:
        stop()


def test_csv_import_export(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        csv_body = ("device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip\n"
                    "d9,10.9.9.1,666,10.9.9.2,255.255.255.252,10.9.9.3\n")
        st, _, b = _req(host, port, "POST", "/api/devices/import-csv",
                        raw=csv_body.encode(),
                        headers={"Cookie": ck, "X-CSRF-Token": csrf,
                                 "Content-Type": "text/csv"})
        assert st == 200 and json.loads(b)["imported"] == 1
        st, hd, b = _req(host, port, "GET", "/api/devices/export-csv",
                         headers={"Cookie": ck})
        assert st == 200 and "text/csv" in hd.get("Content-Type", "")
        assert b.decode().splitlines()[0] == \
                ("device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,"
                 "app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,"
                 "vpg_number,nat_interface,svi_igp,role,platform")
        assert "d9,10.9.9.1" in b.decode()
    finally:
        stop()


def test_credentials_crud_never_leaks_password(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, saved = _req(host, port, "POST", "/api/credentials",
                        {"id": "lab", "name": "Lab", "device_user": "admin",
                         "device_pass": "topsecret"}, headers=hh)
        assert st == 200
        assert json.loads(saved)["profile"]["id"] == "lab"
        assert b"topsecret" not in saved
        st, _, b = _req(host, port, "GET", "/api/credentials", headers={"Cookie": ck})
        body = b.decode()
        assert "lab" in body and "admin" in body
        assert "topsecret" not in body     # password NEVER returned
        st, _, deleted = _req(host, port, "DELETE", "/api/credentials/lab", headers=hh)
        assert st == 200
        assert json.loads(deleted) == {"deleted": True}
        st, _, deleted = _req(host, port, "DELETE", "/api/credentials/lab", headers=hh)
        assert st == 200 and json.loads(deleted) == {"deleted": False}
    finally:
        stop()


def test_assign_image_sets_policy(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_id": "img1"}, headers=hh)
        assert st == 200
        pol = cat.get_policy("d1")
        assert pol["approved_image_id"] == "img1"
        # Approval IS the whole policy. This used to assert install_allowed was
        # False; the flag gated nothing, was never read, and reading as False
        # beside an approved image implied a second gate an operator had to open.
        assert pol == {"approved_image_id": "img1",
                       "approved_image_ids": ["img1"]}
        # unknown image -> 400
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_id": "nope"}, headers=hh)
        assert st == 400
    finally:
        stop()


def test_assign_accepts_image_id_list_and_caps_at_ten(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        for i in range(2, 12):    # img2..img11, alongside _serve_full's img1
            cat.save_image({"id": "img%d" % i, "filename": "img%d.bin" % i,
                            "sha256": "s%d" % i, "published_at": i})
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": ["img1", "img2"]}, headers=hh)
        assert st == 200
        pol = cat.get_policy("d1")
        assert pol["approved_image_ids"] == ["img1", "img2"]
        assert pol["approved_image_id"] == "img1"
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        row = [d for d in json.loads(b)["devices"] if d["device_id"] == "d1"][0]
        assert row["assigned_image_ids"] == ["img1", "img2"]
        assert row["assigned_image_id"] == "img1"
        eleven = ["img%d" % i for i in range(1, 12)]
        st, _, b = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": eleven}, headers=hh)
        assert st == 400
        assert "at most 10" in json.loads(b)["error"]
        # a rejected assignment must not have mutated the existing policy
        assert cat.get_policy("d1")["approved_image_ids"] == ["img1", "img2"]
    finally:
        stop()


def test_assign_rejects_malformed_image_ids(tmp_path):
    """image_ids must be validated as a shape -- a JSON array of non-empty
    strings -- BEFORE anything iterates it. A non-list value used to raise a
    TypeError that killed the connection instead of answering 400 (a bare
    int wasn't iterable at all; a bare string iterated into characters); a
    list with a falsy/non-string element used to be silently filtered
    instead of rejected. All four shapes must now answer 400 with a JSON
    body, and the connection must still be alive to read it."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        # a bare int: previously raised TypeError and dropped the connection
        st, _, b = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": 5}, headers=hh)
        assert st == 400
        assert json.loads(b)["error"] == "image_ids must be a list of image ids"
        assert json.loads(b)["code"] == "invalid-request"
        # a bare string: previously iterated into one-character "ids"
        st, _, b = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": "img-a"}, headers=hh)
        assert st == 400
        assert json.loads(b)["error"] == "image_ids must be a list of image ids"
        # a falsy element: previously silently dropped instead of rejected
        st, _, b = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": ["img-a", ""]}, headers=hh)
        assert st == 400
        assert json.loads(b)["error"] == "image_ids must be a list of image ids"
        # a non-string element
        st, _, b = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": ["img-a", 123]}, headers=hh)
        assert st == 400
        assert json.loads(b)["error"] == "image_ids must be a list of image ids"
        # none of the rejected bodies touched the device's policy
        assert cat.get_policy("d1") == {"approved_image_id": None,
                                        "approved_image_ids": []}
    finally:
        stop()


def test_assign_singular_body_still_works(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_id": "img1"}, headers=hh)
        assert st == 200
        assert cat.get_policy("d1")["approved_image_ids"] == ["img1"]
    finally:
        stop()


def test_assign_unknown_fleet_device_is_422_without_catalog_write(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    _app, _fleet, _creds, cat = _ctx
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/devices/ghost/assign",
                        {"image_ids": ["img1"]}, headers=hh)
        assert st == 422
        assert json.loads(b)["error"] == "no such fleet device"
        assert cat._policies.get("ghost") is None
        events = [e for e in _read_audit_lines(audit_path)
                  if e.get("event") == "device_assign"]
        assert len(events) == 1
        assert events[0]["target"] == "ghost"
        assert events[0]["result"] == "fail"
        prefix, before, after, removed = _assignment_audit_parts(events[0])
        assert prefix == "assignment failed: no such fleet device"
        assert before == [] and after == [] and removed == []
    finally:
        stop()


def test_unassign_clears_the_whole_set(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    _app, fleet, _creds, cat = _ctx
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        cat.save_image({"id": "img3", "filename": "img3.bin", "sha256": "ef",
                        "size": 5, "published_at": 3})
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        cat.set_policy("d1", approved_image_ids=["img1", "img2", "img3"])
        assert len(cat.get_policy("d1")["approved_image_ids"]) == 3
        st, _, b = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_id": None}, headers=hh)
        assert st == 200 and json.loads(b)["ok"] is True
        assert cat.get_policy("d1") == {"approved_image_id": None,
                                        "approved_image_ids": []}
        events = [e for e in _read_audit_lines(audit_path)
                 if e.get("action") == "unassign"]
        # every image the unassign actually removed, not just the set's first:
        # the audit trail is the record of what was done to this device, and
        # "(was img1.bin)" hid two of the three images that were dropped.
        prefix, before, after, removed = _assignment_audit_parts(events[-1])
        assert prefix == "unassigned (was img1.bin, img2.bin, img3.bin)"
        assert before == ["img1", "img2", "img3"]
        assert after == []
        assert removed == before
    finally:
        stop()


def test_assign_honours_an_expected_set_and_409s_on_a_stale_one(tmp_path):
    """Review finding: nothing guarded two operators editing the same
    device's images. Both open the picker on {A}, one applies {A,B}, the
    other applies {A,C} a moment later, and the first edit is gone with no
    sign it ever happened -- while the peer-policy PUT next door has carried
    an if_revision compare-and-set all along.

    The picker now sends the set it was opened on. A stored set that has
    moved on is refused with 409 and the CURRENT set, nothing is written, and
    one failed outcome is audited. A body without the field keeps the unconditional
    write, so older clients and API callers are unaffected."""
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    _app, fleet, _creds, cat = _ctx
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        # the expectation holds (nothing assigned yet) -> the write goes in
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": ["img1"], "expect_image_ids": []},
                        headers=hh)
        assert st == 200
        # the second operator still believes it is unassigned -> refused
        st, _, b = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": ["img2"], "expect_image_ids": []},
                        headers=hh)
        assert st == 409
        body = json.loads(b)
        assert body["error"] == "assignment_conflict"
        assert body["assigned_image_ids"] == ["img1"]      # what it really is
        assert cat.get_policy("d1")["approved_image_ids"] == ["img1"]
        # The shared service records one sanitized outcome for the refusal.
        assigns = [e for e in _read_audit_lines(audit_path)
                  if e.get("action") == "assign"]
        assert len(assigns) == 2
        assert assigns[-1]["result"] == "fail"
        prefix, before, after, removed = _assignment_audit_parts(assigns[-1])
        assert prefix == "assignment failed: assignment conflict"
        assert before == ["img1"] and after == ["img1"] and removed == []

        # unassign is guarded the same way
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": [], "expect_image_ids": ["img2"]},
                        headers=hh)
        assert st == 409
        assert cat.get_policy("d1")["approved_image_ids"] == ["img1"]

        # a malformed expectation is a 400, never a silently ignored guard
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": ["img2"], "expect_image_ids": "img1"},
                        headers=hh)
        assert st == 400
        assert cat.get_policy("d1")["approved_image_ids"] == ["img1"]

        # omitting it entirely keeps the old unconditional write
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": ["img2"]}, headers=hh)
        assert st == 200
        assert cat.get_policy("d1")["approved_image_ids"] == ["img2"]
    finally:
        stop()


def test_assign_audit_names_the_images_it_removed(tmp_path):
    """Review finding: narrowing a device from {A,B,C} to {A} logged only
    "assigned 1 image(s): A". The audit trail is the record of what an
    operator did to a device, and the two images the operator dropped -- the
    consequential half of that edit -- appeared nowhere in it.

    A plural assign now names what it removed as well as what it set, and
    only when it actually removed something. Ids whose catalog entry is gone
    still get named (by id), since a policy row can outlive the image."""
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    _app, fleet, _creds, cat = _ctx
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        cat.save_image({"id": "img3", "filename": "img3.bin", "sha256": "ef",
                        "size": 5, "published_at": 3})
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        cat.set_policy("d1", approved_image_ids=["img1", "img2", "img3"])
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": ["img1"]}, headers=hh)
        assert st == 200
        events = [e for e in _read_audit_lines(audit_path)
                 if e.get("action") == "assign"]
        prefix, before, after, removed = _assignment_audit_parts(events[-1])
        assert prefix == \
            "assigned 1 image(s): img1.bin; removed: img2.bin, img3.bin"
        assert before == ["img1", "img2", "img3"]
        assert after == ["img1"]
        assert removed == ["img2", "img3"]

        # widening removes nothing, so nothing is claimed to have been removed
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": ["img1", "img2"]}, headers=hh)
        assert st == 200
        events = [e for e in _read_audit_lines(audit_path)
                 if e.get("action") == "assign"]
        prefix, before, after, removed = _assignment_audit_parts(events[-1])
        assert prefix == "assigned 2 image(s): img1.bin, img2.bin"
        assert before == ["img1"] and after == ["img1", "img2"]
        assert removed == []
    finally:
        stop()


def test_assign_audit_detail_pins_plural_wording(tmp_path):
    """The plural (image_ids) assign path's audit detail is distinct wording
    from the singular compat path's -- pin the exact "assigned N image(s):"
    phrasing plus both filenames so a rewording doesn't slip by unnoticed."""
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    _app, fleet, _creds, cat = _ctx
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": ["img1", "img2"]}, headers=hh)
        assert st == 200
        events = [e for e in _read_audit_lines(audit_path)
                 if e.get("action") == "assign"]
        assert events
        detail = events[-1]["detail"]
        assert "assigned 2 image(s):" in detail
        assert "img1.bin" in detail and "img2.bin" in detail
    finally:
        stop()


def test_assign_refuses_a_quarantined_image_with_the_verdict_in_the_400(tmp_path):
    """KGV reconciler: an image the Cisco Bulk Hash reconciler has
    quarantined (a NEW sha512 mismatch) must be refused at the /assign
    route, with the verdict that caused it surfaced in the 400 body so the
    operator sees why -- not just a bare error string."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        cat.apply_hash_verification(
            {"img1": {"state": "mismatch", "feed_sha512": "b" * 128,
                      "publish_date": "2026-08-01", "deferral": False}},
            source="scheduled", now=1000)
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        st, _, b = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_id": "img1"}, headers=hh)
        assert st == 400
        body = json.loads(b)
        assert body["error"] == "image_quarantined"
        assert body["image_id"] == "img1"
        assert body["verdict"] == {
            "state": "mismatch", "checked_at": 1000,
            "feed_published_at": "2026-08-01", "source": "scheduled",
            "deferral": False}
        assert cat.get_policy("d1")["approved_image_ids"] == []
        # the plural (image_ids) shape is refused the same way
        st, _, b = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": ["img1"]}, headers=hh)
        assert st == 400
        assert json.loads(b)["error"] == "image_quarantined"
    finally:
        stop()


def test_device_rows_carry_the_list(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        cat.save_image({"id": "img2", "filename": "img2.bin", "sha256": "cd",
                        "published_at": 2})
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        cat.set_policy("d1", approved_image_ids=["img1", "img2"])
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        assert st == 200
        row = [d for d in json.loads(b)["devices"] if d["device_id"] == "d1"][0]
        assert row["assigned_image_ids"] == ["img1", "img2"]
        assert row["assigned_image_id"] == "img1"
    finally:
        stop()


def test_rollout_counts_a_device_under_every_assigned_image(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        cat.save_image({"id": "img2", "filename": "img2.bin", "sha256": "cd",
                        "published_at": 2})
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        cat.set_policy("d1", approved_image_ids=["img1", "img2"])
        st, _, b = _req(host, port, "GET", "/api/overview", headers={"Cookie": ck})
        assert st == 200
        rollout = {r["image_id"]: r for r in json.loads(b)["rollout"]}
        assert rollout["img1"]["assigned"] == 1
        assert rollout["img2"]["assigned"] == 1
    finally:
        stop()


def test_rollout_staged_uses_heartbeat_staged_image_ids(tmp_path):
    # Task 3 lands staged_image_ids on the heartbeat; rollout must read it
    # directly rather than the single current_image_id/stage_state pair, so a
    # device staging TWO images at once counts as staged under both.
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        cat.save_image({"id": "img2", "filename": "img2.bin", "sha256": "cd",
                        "published_at": 2})
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        cat.set_policy("d1", approved_image_ids=["img1", "img2"])
        # a synthetic heartbeat carrying the new field, as a Task-3 agent
        # would send it -- current_image_id/stage_state deliberately say
        # something that would NOT count under the legacy fallback logic
        cat.record_heartbeat("d1", {"staged_image_ids": ["img1", "img2"],
                                    "current_image_id": None,
                                    "stage_state": "staging"}, now=10)
        st, _, b = _req(host, port, "GET", "/api/overview", headers={"Cookie": ck})
        assert st == 200
        rollout = {r["image_id"]: r for r in json.loads(b)["rollout"]}
        assert rollout["img1"]["staged"] == 1
        assert rollout["img2"]["staged"] == 1
    finally:
        stop()


def test_overview_totals_count_devices_not_image_pairs(tmp_path):
    """Overview's aggregate cards ('Devices staged', rendered in app.js as a
    device count) must count each DEVICE once, not once per assigned image.
    A device with two images assigned and BOTH staged adds exactly 1 to
    staged_total, not 2 -- and it adds 1 to assigned_total, not 2."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        cat.save_image({"id": "img2", "filename": "img2.bin", "sha256": "cd",
                        "published_at": 2})
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        cat.set_policy("d1", approved_image_ids=["img1", "img2"])
        cat.record_heartbeat("d1", {"staged_image_ids": ["img1", "img2"],
                                    "current_image_id": None,
                                    "stage_state": "staging"}, now=10)
        st, _, b = _req(host, port, "GET", "/api/overview", headers={"Cookie": ck})
        assert st == 200
        ov = json.loads(b)
        assert ov["assigned"] == 1   # one device, not one per assigned image
        assert ov["staged"] == 1     # fully staged device counts once
    finally:
        stop()


def test_overview_staged_total_excludes_partially_staged_device(tmp_path):
    """A device with only SOME of its assigned images staged must not count
    toward staged_total at all -- staged_total is whole-set-or-nothing per
    device. The per-image rollout row for the image that IS staged still
    shows it; only the aggregate is device-deduped."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        cat.save_image({"id": "img2", "filename": "img2.bin", "sha256": "cd",
                        "published_at": 2})
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        cat.set_policy("d1", approved_image_ids=["img1", "img2"])
        cat.record_heartbeat("d1", {"staged_image_ids": ["img1"],
                                    "current_image_id": None,
                                    "stage_state": "staging"}, now=10)
        st, _, b = _req(host, port, "GET", "/api/overview", headers={"Cookie": ck})
        assert st == 200
        ov = json.loads(b)
        assert ov["assigned"] == 1
        assert ov["staged"] == 0     # not fully staged -> device doesn't count
        rollout = {r["image_id"]: r for r in ov["rollout"]}
        assert rollout["img1"]["staged"] == 1   # per-image row still shows it
        assert rollout["img2"]["staged"] == 0
    finally:
        stop()


def test_real_heartbeat_ingest_feeds_overview_staged_logic(tmp_path):
    """End-to-end guard: a heartbeat posted through the REAL catalog HTTP
    ingest route (catalog.route_post's field whitelist), not via a direct
    record_heartbeat() call, must still be visible to the console's
    deployed/staged derivation (rollout + staged_total in /api/overview).

    Every other rollout/staged test in this file (e.g.
    test_rollout_staged_uses_heartbeat_staged_image_ids above) calls
    cat.record_heartbeat() directly, which bypasses catalog.py's HTTP
    ingest handler entirely -- so those tests would keep passing even if the
    ingest handler's whitelist silently dropped staged_image_ids /
    errored_image_ids in production. This test posts over the real wire, the
    same as a device agent would, to close that gap."""
    import secrets_store

    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    secrets_path = str(tmp_path / "secrets.json")
    dev_srv = catalog_mod.make_server("127.0.0.1", 0, cat, secrets_path)
    dev_port = dev_srv.server_address[1]
    threading.Thread(target=dev_srv.serve_forever, daemon=True).start()
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        cat.save_image({"id": "img2", "filename": "img2.bin", "sha256": "cd",
                        "published_at": 2})
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        cat.set_policy("d1", approved_image_ids=["img1", "img2"])

        # Mint the device's real catalog_token and POST the heartbeat over
        # the real ingest HTTP path -- the exact code the review finding
        # flagged as dropping staged_image_ids/errored_image_ids.
        store = secrets_store.load(secrets_path)
        tok = secrets_store.mint(store, "d1", "catalog_token", time.time())
        secrets_store.save(store, secrets_path)
        conn = http.client.HTTPConnection("127.0.0.1", dev_port, timeout=5)
        conn.request(
            "POST", "/v1/devices/d1/heartbeat",
            body=json.dumps({"current_image_id": None,
                             "stage_state": "staging",
                             "staged_image_ids": ["img1", "img2"]}),
            headers={"Authorization": "Bearer " + tok,
                     "Content-Type": "application/json"})
        hb_resp = conn.getresponse()
        assert hb_resp.status == 200
        hb_resp.read()
        conn.close()

        st, _, b = _req(host, port, "GET", "/api/overview",
                        headers={"Cookie": ck})
        assert st == 200
        ov = json.loads(b)
        # Only a stored (not dropped) staged_image_ids covering the whole
        # assigned set makes this device count as fully staged.
        assert ov["staged"] == 1
        rollout = {r["image_id"]: r for r in ov["rollout"]}
        assert rollout["img1"]["staged"] == 1
        assert rollout["img2"]["staged"] == 1
    finally:
        dev_srv.shutdown()
        stop()


def test_csv_import_accepts_large_body(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        rows = ["device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip"]
        for i in range(2000):   # ~2000 rows -> well over the 64 KiB JSON cap
            rows.append("d%d,10.0.%d.%d,666,10.0.0.2,255.255.255.252,10.0.0.3"
                        % (i, i // 256, i % 256))
        body = ("\n".join(rows) + "\n").encode()
        assert len(body) > 64 * 1024
        st, _, b = _req(host, port, "POST", "/api/devices/import-csv", raw=body,
                        headers={"Cookie": ck, "X-CSRF-Token": csrf,
                                 "Content-Type": "text/csv"})
        assert st == 200 and json.loads(b)["imported"] == 2000
    finally:
        stop()


def test_device_view_merges_policy_and_heartbeat(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        cat.set_policy("d1", approved_image_id="img1")
        peer_tls = {"configured_mode": "required", "runtime_mode": "disabled",
                    "runtime_source": "aria2_rpc"}
        cat.record_heartbeat("d1", {"stage_state": "verified", "stage_error": "copy denied", "model": "C9300", "peer_tls": peer_tls}, now=123)
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        row = [d for d in json.loads(b)["devices"] if d["device_id"] == "d1"][0]
        assert row["assigned_image_id"] == "img1"
        assert row["stage_state"] == "verified"
        assert row["stage_error"] == "copy denied"
        assert row["last_seen"] == 123
        assert row["heartbeat_model"] == "C9300"
        assert row["peer_tls"] == peer_tls
    finally:
        stop()


def test_device_view_mixed_policy_defaults(tmp_path):
    """Devices WITHOUT a policy entry still get assigned_image_id: null in the
    /api/devices rows — the single list_policies() read must yield the same
    output as the old per-device get_policy() (which defaulted the field)."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d2", "device_ip": "10.0.0.2"}, headers=hh)
        cat.set_policy("d1", approved_image_id="img1")   # d2 has NO policy
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        assert st == 200
        rows = {d["device_id"]: d for d in json.loads(b)["devices"]}
        assert rows["d1"]["assigned_image_id"] == "img1"
        assert "assigned_image_id" in rows["d2"]
        assert rows["d2"]["assigned_image_id"] is None
    finally:
        stop()


def test_policy_read_once_per_request(tmp_path):
    """The policy store is read exactly once per /api/devices or /api/overview
    request, regardless of fleet size — the console polls both endpoints, so
    a per-device get_policy() re-read would grow linearly with the fleet.

    Policy is keyed per device now, so the one read is the whole-fleet
    ``list_policies()`` snapshot rather than one parse of ``policy.json``."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = deps
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        for i in range(3):
            _req(host, port, "POST", "/api/devices",
                 {"device_id": "d%d" % i, "device_ip": "10.0.0.%d" % (i + 1)},
                 headers=hh)
        cat.set_policy("d0", approved_image_id="img1")

        reads = {"policy": 0}
        orig_list = cat.list_policies

        def counting_read():
            reads["policy"] += 1
            return orig_list()

        cat.list_policies = counting_read
        st, _, _ = _req(host, port, "GET", "/api/devices",
                        headers={"Cookie": ck})
        assert st == 200
        assert reads["policy"] == 1
        reads["policy"] = 0
        st, _, _ = _req(host, port, "GET", "/api/overview",
                        headers={"Cookie": ck})
        assert st == 200
        assert reads["policy"] == 1
    finally:
        stop()


def test_csv_import_rejects_oversized(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        s = _socket.create_connection((host, port), timeout=5)
        head = ("POST /api/devices/import-csv HTTP/1.0\r\nHost: x\r\n"
                "Cookie: %s\r\nX-CSRF-Token: %s\r\nContent-Type: text/csv\r\n"
                "Content-Length: 9000000\r\n\r\n" % (ck, csrf)).encode()
        s.sendall(head + b"device_id,device_ip\n")   # declares 9 MB, sends a few bytes
        s.shutdown(_socket.SHUT_WR)
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        assert b" 413 " in resp.split(b"\r\n", 1)[0]
    finally:
        stop()


import gui_onboard


# Guest Shell now runs the same collision preflight as every other platform at
# job start. These harnesses exist to exercise routes and job mechanics, so
# default the preflight to a clean device; a test about the preflight itself
# overrides guestshell_preflight_fn explicitly.
_CLEAN_GUESTSHELL_PREFLIGHT = (
    lambda dev, env, resolved: {"status": "passed",
                                "device_identity": "FOC0000TEST"})


def _serve_onboard(tmp_path, run_fn, **svc_kw):
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1", "model": "C9300",
                  "management_type": "routed", "iris_vlan": "666",
                  "svi_ip": "10.0.0.10", "svi_mask": "255.255.255.0",
                  "app_ip": "10.0.0.11", "app_mask": "255.255.255.0",
                  "app_gateway": "10.0.0.1",
                  "credential_profile_id": "lab"})
    fleet.upsert({"device_id": "d2", "device_ip": "10.0.0.2", "model": "C9300",
                  "management_type": "routed", "iris_vlan": "666",
                  "svi_ip": "10.0.1.10", "svi_mask": "255.255.255.0",
                  "app_ip": "10.0.1.11", "app_mask": "255.255.255.0",
                  "app_gateway": "10.0.1.1",
                  "credential_profile_id": "lab"})
    creds = gui_creds.CredentialStore(secrets_path)
    creds.set_profile("lab", {"name": "L", "device_user": "u", "device_pass": "p"})
    # These devices resolve to guestshell, which now gets a live job-start
    # reachability probe (gui_onboard.py's onboard job-start gate) before
    # run_fn is invoked. Default it to "reachable" so tests of unrelated
    # onboard behavior keep exercising run_fn as before; a test of the gate
    # itself would override probe_fn via svc_kw.
    svc_kw.setdefault("probe_fn", lambda dev, env: "C9300")
    svc_kw.setdefault("guestshell_preflight_fn", _CLEAN_GUESTSHELL_PREFLIGHT)
    onboard = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                         mint_fn=lambda d: "TOK", run_fn=run_fn,
                                         **svc_kw)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, srv.shutdown


@pytest.mark.parametrize("detailed", [False, True])
def test_onboard_start_status_and_stream(tmp_path, detailed):
    def run_fn(p, e, on):
        on("[1/6] hello"); on("[3/6] deploy"); on("[6/6] done"); return 0
    host, port, stop = _serve_onboard(tmp_path, run_fn)
    try:
        ck, csrf = _auth(host, port)
        # start requires CSRF
        assert _req(host, port, "POST", "/api/devices/d1/onboard",
                    {}, headers={"Cookie": ck})[0] == 403
        st, _, b = _req(host, port, "POST", "/api/devices/d1/onboard", {"log": detailed},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200
        job_id = json.loads(b)["job_id"]
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            s, _, jb = _req(host, port, "GET", "/api/onboard/jobs/" + job_id,
                            headers={"Cookie": ck})
            job = json.loads(jb)
            if job["state"] in ("done", "error"):
                break
            _t.sleep(0.02)
        assert job["state"] == "done"
        for line in ("[1/3] Prepare onboarding", "[2/3] Deploy IRIS agent",
                     "[3/3] Finalize onboarding", "Onboard completed."):
            assert line in job["lines"]
        assert ("[6/6] done" in job["lines"]) is detailed
        # SSE stream returns text/event-stream and the data lines + an end event
        s, hd, sb = _req(host, port, "GET",
                         "/api/onboard/jobs/" + job_id + "/stream",
                         headers={"Cookie": ck})
        assert s == 200 and "text/event-stream" in hd.get("Content-Type", "")
        body = sb.decode()
        assert "data: [1/3] Prepare onboarding" in body and "event: end" in body
        assert ("data: [1/6] hello" in body) is detailed
    finally:
        stop()


def test_onboard_status_requires_auth(tmp_path):
    host, port, stop = _serve_onboard(tmp_path, lambda p, e, on: 0)
    try:
        assert _req(host, port, "GET", "/api/onboard/jobs/x")[0] == 401
        assert _req(host, port, "GET", "/api/onboard/jobs/x/stream")[0] == 401
    finally:
        stop()


def test_onboard_jobs_list_endpoint(tmp_path):
    host, port, stop = _serve_onboard(tmp_path, lambda p, e, on: 0,
                                      max_concurrent=7)
    try:
        assert _req(host, port, "GET", "/api/onboard/jobs")[0] == 401
        ck, csrf = _auth(host, port)
        st, _, b = _req(host, port, "POST", "/api/devices/d1/onboard", {},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200
        job_id = json.loads(b)["job_id"]
        st, _, lb = _req(host, port, "GET", "/api/onboard/jobs",
                         headers={"Cookie": ck})
        assert st == 200
        listing = json.loads(lb)
        assert listing["max_concurrent"] == 7
        # server clock rides along so the UI's running-duration math never
        # mixes client and server clocks (skewed lab VMs)
        assert isinstance(listing["now"], int)
        mine = [j for j in listing["jobs"] if j["id"] == job_id]
        assert mine and mine[0]["device_id"] == "d1"
        assert "lines" not in mine[0]
    finally:
        stop()


def test_onboard_unknown_device_is_404(tmp_path):
    """Unknown device ids are rejected at the route, BEFORE a job (and its
    parked worker thread) is created — no thread/job accumulation from junk."""
    host, port, stop = _serve_onboard(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        st, _, _b = _req(host, port, "POST", "/api/devices/ghost/onboard", {},
                         headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 404
        _, _, lb = _req(host, port, "GET", "/api/onboard/jobs",
                        headers={"Cookie": ck})
        assert json.loads(lb)["jobs"] == []
    finally:
        stop()


def test_onboard_cancel_queued_endpoint_and_sse_end(tmp_path):
    release = threading.Event()

    def run_fn(p, e, on):
        release.wait(5); return 0

    host, port, audit_path, stop = _serve_onboard_audit(
        tmp_path, run_fn, max_concurrent=1)
    try:
        ck, csrf = _auth(host, port)
        # CSRF-gated like every state-changing POST
        assert _req(host, port, "POST", "/api/onboard/cancel-queued", {},
                    headers={"Cookie": ck})[0] == 403
        jids = []
        for did in ("d1", "d2"):
            st, _, b = _req(host, port, "POST",
                            "/api/devices/%s/onboard" % did, {},
                            headers={"Cookie": ck, "X-CSRF-Token": csrf})
            assert st == 200
            jids.append(json.loads(b)["job_id"])
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            _, _, jb = _req(host, port, "GET", "/api/onboard/jobs/" + jids[0],
                            headers={"Cookie": ck})
            if json.loads(jb)["state"] == "running":
                break
            _t.sleep(0.02)
        # scoped to job_ids: an unrelated id cancels nothing...
        st, _, b = _req(host, port, "POST", "/api/onboard/cancel-queued",
                        {"job_ids": ["deadbeef"]},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200 and json.loads(b)["cancelled"] == 0
        # ...and the queued job's id cancels exactly it
        st, _, b = _req(host, port, "POST", "/api/onboard/cancel-queued",
                        {"job_ids": jids},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200 and json.loads(b)["cancelled"] == 1
        # the cancelled job is terminal: its SSE stream ends immediately
        s, hd, sb = _req(host, port, "GET",
                         "/api/onboard/jobs/" + jids[1] + "/stream",
                         headers={"Cookie": ck})
        assert s == 200 and "event: end\ndata: cancelled" in sb.decode()
        # the cancel is audited
        events = _read_audit_lines(audit_path)
        cancels = [e for e in events if e.get("event") == "onboard_cancel"]
        assert cancels and "1" in (cancels[0].get("detail") or "")
    finally:
        release.set()
        stop()


def test_devices_view_carries_onboard_state_and_overview_awaits_heartbeat(
        tmp_path, monkeypatch):
    """After a successful onboard, the device has no heartbeat yet (the agent
    needs a couple of minutes to bootstrap) — the devices view must carry the
    job outcome so the UI shows 'waiting for heartbeat' instead of the
    misleading 'not enrolled', and the overview counts such devices."""
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, stop = _serve_onboard(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        st, _, b = _req(host, port, "POST", "/api/devices/d1/onboard", {},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200
        jid = json.loads(b)["job_id"]
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            _, _, jb = _req(host, port, "GET", "/api/onboard/jobs/" + jid,
                            headers={"Cookie": ck})
            if json.loads(jb)["state"] == "done":
                break
            _t.sleep(0.02)
        _, _, db = _req(host, port, "GET", "/api/devices",
                        headers={"Cookie": ck})
        rows = {r["device_id"]: r for r in json.loads(db)["devices"]}
        assert rows["d1"]["onboard_state"] == "done"
        assert rows["d1"]["onboard_action"] == "onboard"
        assert rows["d1"]["onboard_finished_at"] is not None
        assert "onboard_state" not in rows["d2"] or rows["d2"].get("onboard_state") is None
        # no catalog heartbeat in this harness -> d1 is awaiting its first one
        _, _, ob = _req(host, port, "GET", "/api/overview",
                        headers={"Cookie": ck})
        assert json.loads(ob)["awaiting_heartbeat"] == 1
    finally:
        stop()


def test_undeploy_route_starts_job_and_conflicts_409(tmp_path):
    release = threading.Event()

    def run_fn(p, e, on):
        release.wait(5); return 0

    host, port, stop = _serve_onboard(tmp_path, run_fn, max_concurrent=1)
    try:
        ck, csrf = _auth(host, port)
        assert _req(host, port, "POST", "/api/devices/ghost/undeploy", {},
                    headers={"Cookie": ck, "X-CSRF-Token": csrf})[0] == 404
        st, _, b = _req(host, port, "POST", "/api/devices/d1/undeploy", {},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200
        jid = json.loads(b)["job_id"]
        # same action again -> joins the active job
        st, _, b2 = _req(host, port, "POST", "/api/devices/d1/undeploy", {},
                         headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200 and json.loads(b2)["job_id"] == jid
        # opposite action while active -> 409 with a self-explanatory error
        st, _, b3 = _req(host, port, "POST", "/api/devices/d1/onboard", {},
                         headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 409 and "undeploy" in json.loads(b3)["error"]
        # the jobs listing tags the action so the batch panel can label rows
        _, _, lb = _req(host, port, "GET", "/api/onboard/jobs",
                        headers={"Cookie": ck})
        mine = [j for j in json.loads(lb)["jobs"] if j["id"] == jid]
        assert mine and mine[0]["action"] == "undeploy"
    finally:
        release.set()
        stop()


def test_sse_stream_survives_queue_wait(tmp_path, monkeypatch):
    """The SSE idle cap must not count time spent queued for a pool slot: an
    operator opens a deep-queued job's log, the stream stays open (with
    keepalives) until the job runs, then delivers the lines and the end event."""
    monkeypatch.setattr(gui_server, "_SSE_IDLE", 1)      # 1s idle cap
    monkeypatch.setattr(gui_server, "_SSE_KEEPALIVE", 0.2)
    release = threading.Event()

    def run_fn(p, e, on):
        release.wait(5); on("hello from " + e["DEVICE_ID"]); return 0

    host, port, stop = _serve_onboard(tmp_path, run_fn, max_concurrent=1)
    try:
        ck, csrf = _auth(host, port)
        jids = []
        for did in ("d1", "d2"):
            st, _, b = _req(host, port, "POST",
                            "/api/devices/%s/onboard" % did, {},
                            headers={"Cookie": ck, "X-CSRF-Token": csrf})
            assert st == 200
            jids.append(json.loads(b)["job_id"])
        # d2 is queued behind blocked d1; stream its log while it waits
        import http.client
        conn = http.client.HTTPConnection(host, port, timeout=15)
        conn.request("GET", "/api/onboard/jobs/" + jids[1] + "/stream",
                     headers={"Cookie": ck})
        resp = conn.getresponse()
        chunks = []
        done_reading = threading.Event()

        def read_all():
            while True:
                b = resp.read1(4096)
                if not b:
                    break
                chunks.append(b)
            done_reading.set()

        t = threading.Thread(target=read_all, daemon=True)
        t.start()
        # 2.75 s: deliberately OFF-PHASE with the handler's 0.5 s poll (2.5 s
        # landed release.set() exactly on a poll tick, IRIS-06-005).
        time.sleep(2.75)                      # >2x the idle cap, still queued
        assert not done_reading.is_set()      # queue wait didn't close it
        assert b": keepalive" in b"".join(chunks)
        release.set()
        assert done_reading.wait(10)
        body = b"".join(chunks).decode()
        assert "data: hello from d2" in body
        assert "event: end\ndata: done" in body
        conn.close()
    finally:
        release.set()
        stop()


def test_plan_refuses_device_with_cached_xr_family(tmp_path):
    """A fleet-stored device whose record already carries os_family='xr' must
    not plan onto an IOS-XE platform. The /plan route calls
    gui_onboard.resolve_platform(device) with no os_family= argument (see
    gui_server._plan), so the refusal must come from the device record
    itself, not a caller-supplied argument."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    fleet.upsert({"device_id": "xr1", "device_ip": "10.0.0.9",
                  "model": "ASR-9906", "credential_profile_id": "lab",
                  "management_type": "routed", "iris_vlan": "666",
                  "svi_ip": "10.0.0.10", "svi_mask": "255.255.255.0",
                  "app_ip": "10.0.0.11", "app_mask": "255.255.255.0",
                  "app_gateway": "10.0.0.1"})
    fleet.update_observation("xr1", os_family="xr")
    creds = gui_creds.CredentialStore(secrets_path)
    creds.set_profile("lab", {"name": "L", "device_user": "u", "device_pass": "p"})
    onboard = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                         mint_fn=lambda d: "TOK",
                                         run_fn=lambda p, e, on: 0)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host = "127.0.0.1"
    try:
        ck, csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/devices/xr1/plan",
                        headers={"Cookie": ck})
        # Not 200 with an IOS-XE platform (guestshell/iox/router) -- refused.
        assert st == 409, b
        assert "IOS-XR" in json.loads(b)["error"]
    finally:
        srv.shutdown()


def test_xr_host_plan_carries_no_addressing_fields(tmp_path):
    """A fully-validated xr-host record (Task 1: xr-host <-> xr-appmgr is
    mutually required) must plan cleanly -- the enum gate at gui_server._plan
    accepts xr-host, and the resolved network dict carries ONLY device_ip/
    model/platform plus the handful of non-addressing keys every plan
    carries (management_type, swarm_port, renderer). Every XE addressing key
    (iris_vlan/svi_*/app_*/inband_vlan/vpg_number/nat_interface/ios_ssh_host)
    must be ABSENT -- not even present with an empty string -- because
    xr-host's appmgr container uses the router's own network stack.

    This also proves the router-coupling checks (gui_server.py:746-758) do
    not fire for xr-host: model 8201 is not a Catalyst 8000 shape and the
    resolved platform is 'xr-appmgr', not 'router', so none of the three
    router-only gates raise, and the route returns 200 rather than 409."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "xr1", "device_ip": "10.0.0.9",
                      "model": "8201",
                      "platform": "xr-appmgr", "management_type": "xr-host",
                      "credential_profile_id": "lab"})
        fleet.update_observation("xr1", os_family="xr")
        ck, csrf = _auth(host, port)
        status, _, body = _req(host, port, "GET", "/api/devices/xr1/plan",
                               headers={"Cookie": ck})
        assert status == 200, body
        plan = json.loads(body)["plan"]
        assert plan["resolved"] == {
            "management_type": "xr-host", "device_ip": "10.0.0.9",
            "swarm_port": "6881", "model": "8201", "platform": "xr-appmgr",
            "renderer": "v1"}
        for key in ("iris_vlan", "svi_ip", "svi_mask", "svi_igp", "app_ip",
                    "app_mask", "app_gateway", "inband_vlan", "vpg_number",
                    "nat_interface", "ios_ssh_host"):
            assert key not in plan["resolved"], key
        assert plan["ownership"] == (
            "XR host networking — the agent shares the router's own "
            "network stack; no app-network fields")
        assert isinstance(plan["plan_hash"], str) and len(plan["plan_hash"]) == 64
    finally:
        stop()


def test_plan_refuses_xr_appmgr_platform_without_xr_host_management_type(tmp_path):
    """The mutual xr-host <-> xr-appmgr requirement (Task 1's
    validate_record) is enforced only on a fully-classified record --
    fleet.upsert on a bare {"platform": ...} payload (the /platform route;
    also reachable via legacy CSV import) leaves management_type at
    legacy_routed, which _plan converts straight to 'routed' before this
    fix ever consulted platform again. That let an IOS-XR box plan as a
    plain IOS-XE routed device: 10 XE addressing keys, a VLAN/SVI ownership
    narrative, and owned resources [vlan, svi, guestshell] -- on hardware
    that has none of those. _plan must gate on the RESOLVED platform vs.
    management_type directly, the same way it already gates 'router'."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.import_csv(
            "device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip,model,platform\n"
            "xr1,10.0.0.9,666,10.0.0.10,255.255.255.0,10.0.0.11,8201,\n")
        fleet.upsert({"device_id": "xr1", "credential_profile_id": "lab"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/xr1/platform",
                        {"platform": "xr-appmgr"}, headers=hh)
        assert st == 200
        status, _, body = _req(host, port, "GET", "/api/devices/xr1/plan",
                               headers={"Cookie": ck})
        assert status == 409, body
        assert json.loads(body)["error"] == (
            "platform xr-appmgr requires management_type xr-host "
            "(the two are mutually required)")
    finally:
        stop()


def test_plan_ignores_the_network_attachment_alias_and_falls_to_legacy_routed(tmp_path):
    """A retired alias cannot make incomplete legacy inventory deployable."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        with open(fleet.path, "w") as stream:
            json.dump({"revision": 1, "devices": {"d1": {
                "device_id": "d1", "device_ip": "10.0.0.1", "platform": "guestshell",
                "network_attachment": "inband", "inband_vlan": "120",
                "registered_at": 1000,
            }}}, stream)
        ck, _csrf = _auth(host, port)
        status, _, body = _req(host, port, "GET", "/api/devices/d1/plan",
                               headers={"Cookie": ck})
        assert status == 409, body
        assert json.loads(body)["error"] == "unclassified_management_type"
    finally:
        stop()


def test_plan_carries_svi_igp_through_to_the_resolved_record(tmp_path):
    """issue #85: a routed device's per-record svi_igp override must reach
    the resolved plan gui_onboard._build_env reads for the installer env --
    not just live in the fleet row. A device with no override plans with an
    empty svi_igp, so device-install.sh's own SVI_IGP env var default still
    decides for it."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1",
                      "management_type": "routed", "iris_vlan": "666",
                      "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                      "app_ip": "10.0.0.1", "app_mask": "255.255.255.252",
                      "app_gateway": "10.0.0.2", "svi_igp": "isis",
                      "model": "C9300", "platform": "guestshell"})
        fleet.upsert({"device_id": "d2", "device_ip": "10.0.0.9",
                      "management_type": "routed", "iris_vlan": "667",
                      "svi_ip": "10.0.0.10", "svi_mask": "255.255.255.252",
                      "app_ip": "10.0.0.9", "app_mask": "255.255.255.252",
                      "app_gateway": "10.0.0.10",
                      "model": "C9300", "platform": "guestshell"})
        ck, _csrf = _auth(host, port)
        status, _, body = _req(host, port, "GET", "/api/devices/d1/plan",
                               headers={"Cookie": ck})
        assert status == 200, body
        assert json.loads(body)["plan"]["resolved"]["svi_igp"] == "isis"
        status, _, body = _req(host, port, "GET", "/api/devices/d2/plan",
                               headers={"Cookie": ck})
        assert status == 200, body
        assert json.loads(body)["plan"]["resolved"]["svi_igp"] == ""
    finally:
        stop()


def test_plan_refuses_xr_appmgr_platform_on_a_network_attachment_alias_only_row(tmp_path):
    """An alias-only XR row is still unclassified and cannot onboard."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        with open(fleet.path, "w") as stream:
            json.dump({"revision": 1, "devices": {"xr1": {
                "device_id": "xr1", "device_ip": "10.0.0.9",
                "network_attachment": "xr-host", "platform": "xr-appmgr",
                "model": "8201", "registered_at": 1000,
            }}}, stream)
        ck, _csrf = _auth(host, port)
        status, _, body = _req(host, port, "GET", "/api/devices/xr1/plan",
                               headers={"Cookie": ck})
        assert status == 409, body
        assert json.loads(body)["error"] == "unclassified_management_type"
    finally:
        stop()


def test_owned_resources_for_xr_host_matches_the_uninstall_recipe(tmp_path):
    """_owned_resources must claim exactly what device/xr-uninstall.sh
    actually removes: the appmgr application, its registered package
    source, the RPM staged at harddisk: root, and the agent's iris-work/
    control-file directory -- and it must NOT claim a guestshell resource,
    which XR hardware has no such thing as (the bug the unconditional
    guestshell entry at gui_server.py:813 introduced for every management
    type before this branch existed)."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None)
    try:
        resources = srv.RequestHandlerClass._owned_resources(
            {"management_type": "xr-host"})
        kinds = [r["kind"] for r in resources]
        assert kinds == ["appmgr-application", "appmgr-source",
                          "agent-rpm", "agent-work-dir", "agent-peer-identity"]
        assert "guestshell" not in kinds
        assert all(r["ownership"] == "iris-created" for r in resources)
        # Names are gui_onboard's own constants, not re-hardcoded here, so a
        # rename of APPID/SOURCE_NAME cannot silently drift the record.
        by_kind = {r["kind"]: r for r in resources}
        assert by_kind["appmgr-application"]["name"] == gui_onboard._XR_APPID
        assert by_kind["appmgr-source"]["name"] == gui_onboard._XR_SOURCE_NAME
        assert by_kind["agent-peer-identity"]["paths"] == [
            "harddisk:peer-tls/current.json", "harddisk:peer-tls/node.key",
            "harddisk:peer-tls/enrollment.lock"]
    finally:
        srv.server_close()


def test_owned_resources_for_iox_claim_only_the_iox_application(tmp_path):
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None)
    try:
        assert srv.RequestHandlerClass._owned_resources({
            "platform": "iox", "management_type": "routed",
        }) == [{"kind": "iox-app", "ownership": "iris-created"}]
    finally:
        srv.server_close()


def test_owned_resources_raises_without_management_type(tmp_path):
    """Task 2 (spec decision 6): resolved["management_type"] is read as a
    direct subscript, never a defaulted .get() -- a resolved dict missing
    the key must fail loud instead of silently resolving to some guessed
    scope. A PARTIAL rename that kept the old .get(..., None) default would
    make this pass through as attachment=None -> the plain-VLAN/SVI teardown
    branch, which can delete an operator-owned resource it never proved it
    owns."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None)
    try:
        with pytest.raises(KeyError, match="management_type"):
            srv.RequestHandlerClass._owned_resources({})
    finally:
        srv.server_close()


def test_router_teardown_resolved_raises_without_management_type(tmp_path):
    """Task 2 fix-wave (Minor 5): unlike the other eight reader sites, the
    three management_type reads inside _router_teardown_resolved sit behind
    an except ValueError in the undeploy route (gui_server.py:3084-3098),
    which marks the record needs-reconcile and answers a clean 409. A bare
    KeyError there would escape as an unhandled 500 instead -- so this one
    function raises ValueError, not KeyError, on a resolved dict missing the
    key."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None)
    try:
        with pytest.raises(ValueError, match="management_type"):
            srv.RequestHandlerClass._router_teardown_resolved(
                {"resolved": {"platform": "router"}})
    finally:
        srv.server_close()


def _serve_inband(tmp_path, run_fn, device=None, iox_controller=None):
    import deployment_records
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    fleet.upsert(device or {"device_id": "edge", "device_ip": "192.0.2.10",
                  "management_type": "inband", "inband_vlan": "120",
                  "app_ip": "192.0.2.11", "app_mask": "255.255.255.0",
                  "app_gateway": "192.0.2.1", "model": "C9300",
                  "platform": "guestshell", "credential_profile_id": "lab"})
    creds = gui_creds.CredentialStore(secrets_path)
    creds.set_profile("lab", {"name": "L", "device_user": "u", "device_pass": "p"})
    record_store = deployment_records.DeploymentRecordStore(state)
    art = str(tmp_path / "artifacts"); os.makedirs(art, exist_ok=True)
    for pkg in ("iris-arm64.tar", "iris-amd64.tar"):
        open(os.path.join(art, pkg), "w").close()   # IOx package-presence gate
    onboard_kwargs = {}
    if iox_controller is not None:
        onboard_kwargs["iox_controller"] = iox_controller
    onboard = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                         mint_fn=lambda d: "TOK", run_fn=run_fn,
                                         record_store=record_store, artifacts_dir=art,
                                         # The default Guest Shell device uses
                                         # the job-start reachability probe.
                                         probe_fn=lambda dev, env: "C9300",
                                         guestshell_preflight_fn=_CLEAN_GUESTSHELL_PREFLIGHT,
                                         iox_preflight_fn=lambda dev, env, resolved: {
                                             "status": "passed",
                                             "device_identity": "FCW0000TEST",
                                             "detected_model": "IE-3400"},
                                         **onboard_kwargs)
    server_kwargs = {"certfile": None, "record_store": record_store}
    if iox_controller is not None:
        server_kwargs["iox_controller"] = iox_controller
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, **server_kwargs)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, srv.shutdown


def test_inband_iox_onboard_defaults_ssh_host_to_mgmt_ip(tmp_path):
    """Inband IOx resolves the iox platform and, with no explicit ios_ssh_host,
    the app SSHes to the switch's management IP (device_ip)."""
    raw_runs = []
    controller = _HttpIoxController()
    host, port, stop = _serve_inband(
        tmp_path,
        lambda *args, **kwargs: raw_runs.append((args, kwargs)) or 0,
        device={"device_id": "ie", "device_ip": "192.0.2.30",
                "management_type": "inband", "inband_vlan": "120",
                "app_ip": "192.0.2.31", "app_mask": "255.255.255.0",
                "app_gateway": "192.0.2.1", "model": "IE-3400", "platform": "iox",
                "credential_profile_id": "lab"},
        iox_controller=controller)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "GET", "/api/devices/ie/plan",
                        headers={"Cookie": ck})
        assert st == 200
        resolved = json.loads(b)["plan"]["resolved"]
        assert resolved["management_type"] == "inband" and resolved["platform"] == "iox"
        assert resolved["ios_ssh_host"] == "192.0.2.30"    # defaults to device_ip
        st, _, b = _req(host, port, "POST", "/api/devices/ie/onboard", {}, headers=hh)
        assert st == 200
        job_id = json.loads(b)["job_id"]
        assert _wait_onboard_job(host, port, ck, job_id)["state"] == "done"
        assert raw_runs == []
        assert len(controller.requests) == 1
        request = controller.requests[0]
        assert _internal_request_value(request, "action") == "install"
        assert _internal_request_value(request, "device_id") == "ie"
        assert _internal_request_value(request, "job_id") == job_id
        assert _internal_request_value(request, "credential_ref") == "lab"
        assert _internal_request_value(request, "teardown_mode") == "none"
        assert _internal_request_value(request, "record_id") is None
        assert _internal_request_has(request, "wrapper_path")
        assert _internal_request_value(
            request, "wrapper_path").endswith("iris-arm64.tar")
        target = _internal_request_value(request, "target")
        assert {key: target[key] for key in ("host", "port", "platform")} == {
            "host": "192.0.2.30", "port": 22, "platform": "iox"}
        assert target["management_type"] == "inband"
        assert target["ios_ssh_host"] == "192.0.2.30"
        assert not _internal_request_has(request, "recipe_env")
        for raw_key in ("credential", "credentials", "credential_profile_id",
                        "username", "password", "device_user", "device_pass",
                        "ios_ssh_user", "ios_ssh_pass"):
            assert not _internal_request_has(request, raw_key)
            assert raw_key not in target
    finally:
        stop()


def test_reonboard_then_undeploy_starts(tmp_path):
    """Re-onboarding a device (idempotent redeploy) and then undeploying it
    must work: the second onboard's record supersedes the first, so the
    undeploy start finds exactly one active record. This is the lab-observed
    failure: two active records made active_for_device() raise and the
    Console reported 'failed to start' with no reason."""
    host, port, stop = _serve_inband(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        import time as _t

        def _wait_done(jid):
            deadline = _t.time() + 3
            while _t.time() < deadline:
                _, _, jb = _req(host, port, "GET", "/api/onboard/jobs/" + jid,
                                headers={"Cookie": ck})
                if json.loads(jb)["state"] in ("done", "error"):
                    return json.loads(jb)["state"]
                _t.sleep(0.02)
            return "timeout"

        for _ in range(2):    # onboard TWICE — the re-onboard mints record #2
            st, _, b = _req(host, port, "POST", "/api/devices/edge/onboard", {},
                            headers=hh)
            assert st == 200
            assert _wait_done(json.loads(b)["job_id"]) == "done"
        st, _, b = _req(host, port, "POST", "/api/devices/edge/undeploy", {},
                        headers=hh)
        assert st == 200, "undeploy refused after re-onboard: %s" % b
    finally:
        stop()


def test_inband_onboard_is_one_click_and_drives_inband_renderer(tmp_path):
    """Inband onboards exactly like routed: a plain POST starts a job, persists a
    record, and runs the installer with MANAGEMENT_TYPE=inband."""
    ran = []
    host, port, stop = _serve_inband(
        tmp_path, lambda p, e, on: (ran.append(dict(e)), 0)[1])
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # plan preview reports the inband management type
        st, _, b = _req(host, port, "GET", "/api/devices/edge/plan",
                        headers={"Cookie": ck})
        assert st == 200 and json.loads(b)["plan"]["resolved"]["management_type"] == "inband"
        # a plain onboard POST starts the job (no gate, no acknowledgement dance)
        st, _, b = _req(host, port, "POST", "/api/devices/edge/onboard", {},
                        headers=hh)
        assert st == 200
        jid = json.loads(b)["job_id"]
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            _, _, jb = _req(host, port, "GET", "/api/onboard/jobs/" + jid,
                            headers={"Cookie": ck})
            if json.loads(jb)["state"] in ("done", "error"):
                break
            _t.sleep(0.02)
        assert ran and ran[-1]["MANAGEMENT_TYPE"] == "inband"
    finally:
        stop()


def test_onboard_job_status_wire_uses_record_id_not_receipt_id(tmp_path):
    """get_job()/list_jobs() serialize the job dict WHOLESALE, so whatever key
    binds the job to its deployment record is live public wire on
    GET /api/onboard/jobs and /api/onboard/jobs/<id> -- not an
    internal-only detail. It must speak record_id only; a lingering
    receipt_id key would leak the retired vocabulary onto the console's
    polling response."""
    host, port, stop = _serve_inband(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/devices/edge/onboard", {},
                        headers=hh)
        assert st == 200
        jid = json.loads(b)["job_id"]
        job = _wait_onboard_job(host, port, ck, jid)
        assert job["state"] == "done"
        assert "record_id" in job and job["record_id"]
        assert "receipt_id" not in job
        # the list endpoint serializes the same job dicts (minus 'lines')
        _, _, lb = _req(host, port, "GET", "/api/onboard/jobs",
                        headers={"Cookie": ck})
        listed = json.loads(lb)["jobs"]
        assert listed and "record_id" in listed[0] and listed[0]["record_id"]
        assert "receipt_id" not in listed[0]
    finally:
        stop()


def _serve_router(tmp_path, run_fn, preflight_fn=None, mint_fn=None, device=None,
                  audit_path=None):
    """Record-backed server with one C8000V router inventory row."""
    import deployment_records
    os.makedirs(tmp_path, exist_ok=True)
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    fleet.upsert(device or {
        "device_id": "r1", "device_ip": "192.0.2.10", "model": "C8000V",
        "management_type": "router-nat", "vpg_number": "10",
        "nat_interface": "GigabitEthernet1", "app_ip": "10.8.0.2",
        "app_mask": "255.255.255.252", "app_gateway": "10.8.0.1",
        "credential_profile_id": "lab"})
    creds = gui_creds.CredentialStore(secrets_path)
    creds.set_profile("lab", {"name": "L", "device_user": "u", "device_pass": "p"})
    record_store = deployment_records.DeploymentRecordStore(state)
    onboard = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=mint_fn or (lambda d: "TOK"),
        run_fn=run_fn, record_store=record_store, preflight_fn=preflight_fn)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, certfile=None, record_store=record_store,
                                 audit_path=audit_path)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, fleet, record_store, srv.shutdown


def _wait_onboard_job(host, port, cookie, job_id):
    # Allow scheduling and durable record writes on a busy test host.
    deadline = time.monotonic() + 10
    job = None
    while time.monotonic() < deadline:
        _, _, body = _req(host, port, "GET", "/api/onboard/jobs/" + job_id,
                          headers={"Cookie": cookie})
        job = json.loads(body)
        if job["state"] in ("done", "error", "cancelled"):
            return job
        time.sleep(0.02)
    raise AssertionError("onboard job did not finish: %s (last state: %s)" % (
        job_id, job.get("state") if job else "not received"))


def test_c8000v_router_plan_auto_resolves_blank_platform_and_fields(tmp_path):
    host, port, _fleet, record_store, stop = _serve_router(
        tmp_path, lambda p, e, on: 0,
        preflight_fn=lambda dev, env, resolved: {
            "status": "passed", "device_identity": "9ABC123",
            "detected_model": "C8000V"},
        device={"device_id": "r1", "device_ip": "192.0.2.10", "model": "C8000V",
                "management_type": "router-routed", "vpg_number": "7",
                "app_ip": "10.7.0.2", "app_mask": "255.255.255.252",
                "app_gateway": "10.7.0.1", "credential_profile_id": "lab"})
    try:
        cookie, csrf = _auth(host, port)
        status, _, body = _req(host, port, "GET", "/api/devices/r1/plan",
                               headers={"Cookie": cookie})
        assert status == 200
        plan = json.loads(body)["plan"]
        assert plan["ownership"] == "creates only a clean IRIS-owned VirtualPortGroup"
        assert plan["resolved"] == {
            "management_type": "router-routed", "device_ip": "192.0.2.10",
            "iris_vlan": "", "svi_ip": "",
            "svi_mask": "", "svi_igp": "", "app_ip": "10.7.0.2",
            "app_mask": "255.255.255.252",
            "app_gateway": "10.7.0.1", "inband_vlan": "", "vpg_number": "7",
            "nat_interface": "", "swarm_port": "6881", "ios_ssh_host": "",
            "model": "C8000V", "platform": "router", "renderer": "v1"}
        status, _, body = _req(host, port, "POST", "/api/devices/r1/onboard", {},
                               headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 200
        assert _wait_onboard_job(host, port, cookie, json.loads(body)["job_id"])["state"] == "done"
        assert [resource["kind"] for resource in record_store.active_for_device("r1")["resources"]] == [
            "virtualportgroup", "eem-applets", "agent-files",
            "logging-discriminator", "pki-trustpoint", "http-client-trustpoint",
            "iox-global", "file-prompt-quiet",
            "guestshell"]
    finally:
        stop()


def test_router_onboard_uses_router_recipe_env_and_router_resource_kinds(tmp_path):
    events, ran = [], []
    host, port, _fleet, record_store, stop = _serve_router(
        tmp_path, lambda path, env, on: (ran.append((path, dict(env))), 0)[1],
        preflight_fn=lambda dev, env, resolved: (events.append("preflight") or {
            "status": "passed", "device_identity": "9ABC123",
            "detected_model": "C8000V", "nat_interface": "GigabitEthernet1",
            "nat_outside_preexisting": False}),
        mint_fn=lambda did: events.append("mint") or "TOK")
    try:
        cookie, csrf = _auth(host, port)
        status, _, body = _req(host, port, "POST", "/api/devices/r1/onboard", {},
                               headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 200
        job = _wait_onboard_job(host, port, cookie, json.loads(body)["job_id"])
        assert job["state"] == "done"
        assert events == ["preflight", "mint"]
        path, env = ran[-1]
        assert path.endswith("device/router-install.sh")
        assert {key: env[key] for key in ("MANAGEMENT_TYPE", "VPG_NUMBER",
                                           "NAT_INTERFACE", "BT_LISTEN_PORT")} == {
            "MANAGEMENT_TYPE": "router-nat", "VPG_NUMBER": "10",
            "NAT_INTERFACE": "GigabitEthernet1", "BT_LISTEN_PORT": "6881"}
        record = record_store.active_for_device("r1")
        assert [resource["kind"] for resource in record["resources"]] == [
            "virtualportgroup", "eem-applets", "agent-files",
            "logging-discriminator", "pki-trustpoint", "http-client-trustpoint",
            "iox-global", "file-prompt-quiet",
            "guestshell",
            "nat-acl", "nat-overload", "nat-static", "nat-outside-marking"]
        assert record["resources"][-1]["ownership"] == "iris-created"
    finally:
        stop()


def test_router_preflight_failure_is_reported_by_the_queued_job(tmp_path):
    minted, ran = [], []

    def reject(*_args):
        raise ValueError("VirtualPortGroup10 already exists")

    host, port, _fleet, record_store, stop = _serve_router(
        tmp_path, lambda p, e, on: ran.append(1) or 0, preflight_fn=reject,
        mint_fn=lambda did: minted.append(did) or "TOK")
    try:
        cookie, csrf = _auth(host, port)
        status, _, body = _req(host, port, "POST", "/api/devices/r1/onboard", {},
                               headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 200
        job = _wait_onboard_job(host, port, cookie, json.loads(body)["job_id"])
        assert job["state"] == "error"
        assert any("preflight failed" in line for line in job["lines"])
        assert minted == [] and ran == []
        assert record_store.list("r1")[0]["state"] == "removed"
    finally:
        stop()


def test_router_nat_preflight_ownership_persists_and_undeploy_uses_record(tmp_path):
    for preexisting, expected in ((True, "0"), (False, "1")):
        ran = []
        host, port, _fleet, record_store, stop = _serve_router(
            tmp_path / ("existing" if preexisting else "created"),
            lambda path, env, on: (ran.append((path, dict(env))), 0)[1],
            preflight_fn=lambda dev, env, resolved, preexisting=preexisting: {
                "status": "passed", "device_identity": "9ABC123",
                "detected_model": "C8000V", "nat_interface": "GigabitEthernet1",
                "nat_outside_preexisting": preexisting})
        try:
            cookie, csrf = _auth(host, port)
            headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
            _, _, body = _req(host, port, "POST", "/api/devices/r1/onboard", {},
                              headers=headers)
            onboard_job = _wait_onboard_job(host, port, cookie, json.loads(body)["job_id"])
            assert onboard_job["state"] == "done"
            record = record_store.active_for_device("r1")
            assert record["resolved"]["nat_outside_owned"] == expected
            marking = [r for r in record["resources"] if r["kind"] == "nat-outside-marking"]
            assert marking == [{"kind": "nat-outside-marking", "interface": "GigabitEthernet1",
                                "ownership": "pre-existing" if preexisting else "iris-created"}]
            _, _, body = _req(host, port, "POST", "/api/devices/r1/undeploy", {},
                              headers=headers)
            job = _wait_onboard_job(host, port, cookie, json.loads(body)["job_id"])
            assert job["state"] == "done"
            assert ran[-1][0].endswith("device/router-uninstall.sh")
            assert ran[-1][1]["NAT_OUTSIDE_OWNED"] == expected
        finally:
            stop()


def test_platform_endpoint_allows_router_for_router_management_types(tmp_path):
    host, port, fleet, _record_store, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        fleet.upsert({"device_id": "switch", "device_ip": "192.0.2.20",
                      "management_type": "routed", "iris_vlan": "120",
                      "svi_ip": "10.20.0.1", "svi_mask": "255.255.255.252",
                      "app_ip": "10.20.0.2", "app_mask": "255.255.255.252",
                      "app_gateway": "10.20.0.1", "model": "C9300"})
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        assert _req(host, port, "POST", "/api/devices/r1/platform", {"platform": "router"},
                    headers=headers)[0] == 200
        assert _req(host, port, "POST", "/api/devices/r1/platform", {"platform": "guestshell"},
                    headers=headers)[0] == 400
        assert _req(host, port, "POST", "/api/devices/switch/platform", {"platform": "router"},
                    headers=headers)[0] == 400
    finally:
        stop()


def test_router_adopt_is_refused_without_live_ownership_evidence(tmp_path):
    host, port, _fleet, record_store, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        cookie, csrf = _auth(host, port)
        status, _, body = _req(
            host, port, "POST", "/api/devices/r1/adopt",
            {"acknowledge_adopt": True},
            headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 409 and "cannot be adopted" in json.loads(body)["error"]
        assert record_store.list("r1") == []
    finally:
        stop()


def test_router_undeploy_uses_record_ip_after_inventory_edit(tmp_path):
    ran = []
    evidence = {"status": "passed", "device_identity": "9ABC123",
                "detected_model": "C8000V", "nat_interface": "GigabitEthernet1",
                "nat_outside_preexisting": False}
    host, port, fleet, _record_store, stop = _serve_router(
        tmp_path, lambda path, env, on: (ran.append(dict(env)), 0)[1],
        preflight_fn=lambda *args: dict(evidence))
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        _, _, body = _req(host, port, "POST", "/api/devices/r1/onboard", {},
                          headers=headers)
        assert _wait_onboard_job(host, port, cookie,
                                 json.loads(body)["job_id"])["state"] == "done"
        fleet.upsert({"device_id": "r1", "device_ip": "192.0.2.99"})
        _, _, body = _req(host, port, "POST", "/api/devices/r1/undeploy", {},
                          headers=headers)
        assert _wait_onboard_job(host, port, cookie,
                                 json.loads(body)["job_id"])["state"] == "done"
        assert ran[-1]["DEVICE_IP"] == "192.0.2.10"
        assert ran[-1]["EXPECTED_DEVICE_IDENTITY"] == "9ABC123"
        assert ran[-1]["ROUTER_RESOURCES_OWNED"] == "1"
    finally:
        stop()


def _serve_nonrouter(tmp_path, run_fn, device, iox_controller=None):
    """Record-backed server for a Guest Shell or IOx device, handing back the
    fleet and record store so a test can edit the inventory and read the
    record the way the router variant above does."""
    import deployment_records
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    fleet.upsert(device)
    creds = gui_creds.CredentialStore(secrets_path)
    creds.set_profile("lab", {"name": "L", "device_user": "u", "device_pass": "p"})
    record_store = deployment_records.DeploymentRecordStore(state)
    art = str(tmp_path / "artifacts"); os.makedirs(art, exist_ok=True)
    for pkg in ("iris-arm64.tar", "iris-amd64.tar"):
        open(os.path.join(art, pkg), "w").close()
    onboard_kwargs = {}
    if iox_controller is not None:
        onboard_kwargs["iox_controller"] = iox_controller
    onboard = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=run_fn, record_store=record_store, artifacts_dir=art,
        probe_fn=lambda dev, env: "C9300",
        guestshell_preflight_fn=lambda dev, env, resolved: {
            "status": "passed", "device_identity": "FOC0000GS",
            "detected_model": "C9300-48P"},
        iox_preflight_fn=lambda dev, env, resolved: {
            "status": "passed", "device_identity": "FCW0000IOX",
            "detected_model": "IE-3400"}, **onboard_kwargs)
    server_kwargs = {"certfile": None, "record_store": record_store}
    if iox_controller is not None:
        server_kwargs["iox_controller"] = iox_controller
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, **server_kwargs)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, fleet, record_store, srv.shutdown


_GS_ROW = {"device_id": "edge", "device_ip": "192.0.2.10",
           "management_type": "inband", "inband_vlan": "120",
           "app_ip": "192.0.2.11", "app_mask": "255.255.255.0",
           "app_gateway": "192.0.2.1", "model": "C9300",
           "platform": "guestshell", "credential_profile_id": "lab"}
_IOX_ROW = dict(_GS_ROW, device_id="ie1", model="IE-3400", platform="iox")


class _HttpIoxController:
    def __init__(self):
        self.requests = []

    def _run(self, operation, request, prepare, preflight, on_output, cancel):
        self.requests.append(request)
        assert not (cancel() if callable(cancel) else cancel.is_set())
        identity = {
            "board_identity": "FCW0000IOX",
            "model": "IE-3400", "os_family": "xe", "platform": "iox",
        }
        preflight(request, identity)
        record_id = prepare(request, identity)
        on_output("stdout", b"controller-authorized IOx work\n")
        job_id = (request.get("job_id") if isinstance(request, dict)
                  else getattr(request, "job_id"))
        assert isinstance(job_id, str)
        assert re.fullmatch(r"[0-9a-f]{16}", job_id)
        device_id = (request.get("device_id") if isinstance(request, dict)
                     else getattr(request, "device_id"))
        teardown_mode = (
            request.get("teardown_mode") if isinstance(request, dict)
            else getattr(request, "teardown_mode"))
        return {"result_code": 0, "returncode": 0,
                "recovery_code": None, "record_id": record_id,
                "iox_verification": None,
                "iox_session": {
                    "attempt_id": ("a" if operation == "install" else "b") * 32,
                    "job_id": job_id,
                    "device_id": device_id, "board_identity": "FCW0000IOX",
                    "operation": operation,
                    "teardown_mode": teardown_mode, "record_id": record_id,
                    "state": "reaped", "mutation_blocked": False}}

    def run_install(self, request, prepare, preflight, on_output, cancel):
        return self._run(
            "install", request, prepare, preflight, on_output, cancel)

    def run_uninstall(self, request, prepare, preflight, on_output, cancel):
        return self._run(
            "uninstall", request, prepare, preflight, on_output, cancel)

    def summary_for_device(self, _device_id):
        return {"iox_verification_obligations": [], "iox_sessions": []}


def _internal_request_value(request, key):
    if isinstance(request, dict):
        return request.get(key)
    return getattr(request, key)


def _internal_request_has(request, key):
    if isinstance(request, dict):
        return key in request
    return hasattr(request, key)


def test_http_iox_force_passes_explicit_controller_mode_without_record_or_vlan(
        tmp_path):
    controller = _HttpIoxController()
    raw_runs = []
    device = {
        "device_id": "ie-force", "device_ip": "192.0.2.10",
        "management_type": "legacy_routed", "model": "IE-3400",
        "platform": "iox", "credential_profile_id": "lab",
    }
    host, port, _fleet, record_store, stop = _serve_nonrouter(
        tmp_path,
        lambda *args, **kwargs: raw_runs.append((args, kwargs)) or 0,
        device, iox_controller=controller)
    try:
        cookie, csrf = _auth(host, port)
        status, _, body = _req(
            host, port, "POST", "/api/devices/ie-force/undeploy",
            {"force": True},
            headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 200, body
        job_id = json.loads(body)["job_id"]
        job = _wait_onboard_job(host, port, cookie, job_id)
        assert job["state"] == "done"
        assert job["record_id"] is None
        assert job["result_code"] == 0
        assert job["returncode"] == 0
        assert job["recovery_code"] is None
        assert set(job["iox_session"]) == {
            "attempt_id", "job_id", "device_id", "board_identity",
            "operation", "teardown_mode", "record_id", "state",
            "mutation_blocked"}
        assert job["iox_session"]["job_id"] == job_id
        assert raw_runs == []
        assert record_store.list("ie-force") == []
        assert len(controller.requests) == 1
        request = controller.requests[0]
        assert _internal_request_value(request, "action") == "uninstall"
        assert _internal_request_value(
            request, "teardown_mode") == "force_agent_only"
        assert _internal_request_value(request, "record_id") is None
        assert _internal_request_value(request, "device_id") == "ie-force"
        assert _internal_request_value(request, "job_id") == job_id
        assert _internal_request_value(request, "credential_ref") == "lab"
        assert not _internal_request_has(request, "wrapper_path")
        target = _internal_request_value(request, "target")
        assert {key: target[key] for key in ("host", "port", "platform")} == {
            "host": "192.0.2.10", "port": 22, "platform": "iox"}
        assert not target.get("vlan")
    finally:
        stop()


@pytest.mark.parametrize("device, identity", [(_GS_ROW, "FOC0000GS"),
                                              (_IOX_ROW, "FCW0000IOX")])
def test_nonrouter_undeploy_uses_record_ip_and_identity_after_inventory_edit(
        tmp_path, device, identity):
    """The router path was hardened against a post-deploy inventory edit
    retargeting its teardown, and the route's comment claimed the guarantee
    for every undeploy -- but Guest Shell and IOx records were written with
    preflight 'not-required' and no identity, and their teardown took
    DEVICE_IP from the live fleet row. The recorded teardown could then
    remove an operator VLAN/SVI and IRIS-named config from whatever box
    answered at the edited address, with an empty EXPECTED_DEVICE_IDENTITY."""
    raw_runs = []
    is_iox = device["platform"] == "iox"
    controller = _HttpIoxController() if is_iox else None
    did = device["device_id"]
    host, port, fleet, record_store, stop = _serve_nonrouter(
        tmp_path,
        lambda path, env, on: (raw_runs.append(dict(env)), 0)[1],
        device, iox_controller=controller)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        _, _, body = _req(host, port, "POST", "/api/devices/%s/onboard" % did,
                          {}, headers=headers)
        install_job_id = json.loads(body)["job_id"]
        assert _wait_onboard_job(host, port, cookie,
                                 install_job_id)["state"] == "done"
        if is_iox:
            assert raw_runs == []
            assert len(controller.requests) == 1
            install_request = controller.requests[0]
            assert _internal_request_value(install_request, "action") == "install"
            assert _internal_request_value(install_request, "device_id") == did
            assert _internal_request_value(
                install_request, "job_id") == install_job_id
            assert _internal_request_value(
                install_request, "credential_ref") == "lab"
            assert _internal_request_value(
                install_request, "teardown_mode") == "none"
            assert _internal_request_value(install_request, "record_id") is None
            assert _internal_request_has(install_request, "wrapper_path")
            install_target = _internal_request_value(install_request, "target")
            assert {key: install_target[key]
                    for key in ("host", "port", "platform")} == {
                        "host": "192.0.2.10", "port": 22, "platform": "iox"}
        else:
            assert raw_runs[-1]["DEVICE_IP"] == "192.0.2.10"
            assert raw_runs[-1]["EXPECTED_DEVICE_IDENTITY"] == identity
        record = record_store.active_for_device(did)
        # the record now carries the evidence of the check that ran
        assert record["preflight"]["status"] == "passed"
        assert record["preflight"]["device_identity"] == identity
        assert record["resolved"]["device_identity"] == identity
        assert record["resolved"]["device_ip"] == "192.0.2.10"
        assert record["resolved"]["management_type"] == "inband"

        fleet.upsert({"device_id": did, "device_ip": "203.0.113.99"})
        _, _, body = _req(host, port, "POST", "/api/devices/%s/undeploy" % did,
                          {}, headers=headers)
        uninstall_job_id = json.loads(body)["job_id"]
        assert _wait_onboard_job(host, port, cookie,
                                 uninstall_job_id)["state"] == "done"
        if is_iox:
            assert raw_runs == []
            assert len(controller.requests) == 2
            uninstall_request = controller.requests[1]
            assert _internal_request_value(
                uninstall_request, "action") == "uninstall"
            assert _internal_request_value(uninstall_request, "device_id") == did
            assert _internal_request_value(
                uninstall_request, "job_id") == uninstall_job_id
            assert _internal_request_value(
                uninstall_request, "credential_ref") == "lab"
            assert _internal_request_value(
                uninstall_request, "teardown_mode") == "recorded"
            assert _internal_request_value(
                uninstall_request, "record_id") == record["record_id"]
            assert not _internal_request_has(uninstall_request, "wrapper_path")
            uninstall_target = _internal_request_value(
                uninstall_request, "target")
            assert uninstall_target["host"] == "192.0.2.10", (
                "teardown followed the edited row")
            assert uninstall_target["device_identity"] == identity
            assert uninstall_target["management_type"] == "inband"
            assert uninstall_target["resources"] == record["resources"]
        else:
            assert raw_runs[-1]["DEVICE_IP"] == "192.0.2.10", (
                "teardown followed the edited row")
            assert raw_runs[-1]["EXPECTED_DEVICE_IDENTITY"] == identity
            assert raw_runs[-1]["MANAGEMENT_TYPE"] == "inband"
        assert record_store.get(record["record_id"])["state"] == "removed"
    finally:
        stop()


def test_nonrouter_onboard_record_starts_pending_not_not_required(tmp_path):
    """The planned record's preflight is 'pending' for every platform now;
    'not-required' misdescribed a check that runs in the worker pool."""
    gate = threading.Event()
    host, port, _fleet, record_store, stop = _serve_nonrouter(
        tmp_path, lambda path, env, on: (gate.wait(5), 0)[1], _GS_ROW)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        _, _, body = _req(host, port, "POST", "/api/devices/edge/onboard", {},
                          headers=headers)
        jid = json.loads(body)["job_id"]
        deadline = time.time() + 3
        while time.time() < deadline:
            states = [r["state"] for r in record_store.list("edge")]
            if states == ["applying"]:
                break
            time.sleep(0.01)
        (record,) = record_store.list("edge")
        assert record["state"] == "applying"
        assert record["preflight"]["status"] == "passed"     # already bound
        gate.set()
        assert _wait_onboard_job(host, port, cookie, jid)["state"] == "done"
    finally:
        stop()


def test_router_undeploy_refuses_incomplete_or_mismatched_record(tmp_path):
    host, port, _fleet, record_store, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        plan = {"platform": "router", "management_type": "router-routed",
                "device_ip": "192.0.2.10", "device_identity": "9ABC123",
                "vpg_number": "10", "model": "C8000V"}
        record = record_store.create({"controller_id": "iris", "device_id": "r1",
            "inventory_revision": 1, "plan_hash": "a" * 64,
            "resolved": plan, "preflight": {"status": "passed"},
            "resources": [{"kind": "virtualportgroup", "ownership": "iris-created",
                           "id": "99"}]})
        record_store.transition(record["record_id"], "applying")
        record_store.transition(record["record_id"], "active")
        status, _, body = _req(host, port, "POST", "/api/devices/r1/undeploy", {},
                               headers=headers)
        assert status == 409 and "does not prove ownership" in json.loads(body)["error"]
        assert record_store.get(record["record_id"])["state"] == "needs-reconcile"
    finally:
        stop()


def test_router_routes_fail_closed_without_record_store(tmp_path):
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    fleet = gui_fleet.FleetStore(str(tmp_path / "state"))
    fleet.upsert({"device_id": "r1", "device_ip": "192.0.2.10",
                  "model": "C8000V", "management_type": "router-routed",
                  "vpg_number": "10", "app_ip": "10.8.0.2",
                  "app_mask": "255.255.255.252", "app_gateway": "10.8.0.1",
                  "credential_profile_id": "lab"})
    creds = gui_creds.CredentialStore(secrets_path)
    creds.set_profile("lab", {"name": "L", "device_user": "u", "device_pass": "p"})
    onboard = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=lambda p, e, on: 0)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, certfile=None, record_store=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cookie, csrf = _auth("127.0.0.1", port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        for action in ("onboard", "undeploy"):
            status, _, body = _req(
                "127.0.0.1", port, "POST", "/api/devices/r1/" + action, {},
                headers=headers)
            problem = json.loads(body)
            assert status == 503
            assert problem["code"] == "service-unavailable"
            assert problem["error"] == "service unavailable"
    finally:
        srv.shutdown()


def _serve_onboard_audit(tmp_path, run_fn, **svc_kw):
    """_serve_onboard, but the OnboardService is built with an audit_fn wired
    to a real audit.jsonl under tmp_path (via gui_server's audit_path kwarg,
    same file the route-level emissions use)."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    audit_path = str(tmp_path / "audit.jsonl")
    fleet = gui_fleet.FleetStore(state)
    fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1", "model": "C9300",
                  "management_type": "routed", "iris_vlan": "666",
                  "svi_ip": "10.0.0.10", "svi_mask": "255.255.255.0",
                  "app_ip": "10.0.0.11", "app_mask": "255.255.255.0",
                  "app_gateway": "10.0.0.1",
                  "credential_profile_id": "lab"})
    fleet.upsert({"device_id": "d2", "device_ip": "10.0.0.2", "model": "C9300",
                  "management_type": "routed", "iris_vlan": "666",
                  "svi_ip": "10.0.1.10", "svi_mask": "255.255.255.0",
                  "app_ip": "10.0.1.11", "app_mask": "255.255.255.0",
                  "app_gateway": "10.0.1.1",
                  "credential_profile_id": "lab"})
    creds = gui_creds.CredentialStore(secrets_path)
    creds.set_profile("lab", {"name": "L", "device_user": "u", "device_pass": "p"})

    def audit_fn(**kw):
        audit_mod.append_event(audit_path, kw.pop("event"), **kw)

    svc_kw.setdefault("probe_fn", lambda dev, env: "C9300")  # see _serve_onboard
    svc_kw.setdefault("guestshell_preflight_fn", _CLEAN_GUESTSHELL_PREFLIGHT)
    onboard = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                         mint_fn=lambda d: "TOK", run_fn=run_fn,
                                         audit_fn=audit_fn, **svc_kw)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, audit_path=audit_path, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, audit_path, srv.shutdown


def test_onboard_start_and_finish_emit_audit(tmp_path):
    def run_fn(p, e, on):
        on("ok"); return 0
    host, port, audit_path, stop = _serve_onboard_audit(tmp_path, run_fn)
    try:
        ck, csrf = _auth(host, port)
        st, _, b = _req(host, port, "POST", "/api/devices/d1/onboard", {},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200
        job_id = json.loads(b)["job_id"]
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            lines = _read_audit_lines(audit_path)
            if any(e.get("event") == "onboard_finished" for e in lines):
                break
            _t.sleep(0.02)
        lines = _read_audit_lines(audit_path)
        onboard_events = [e for e in lines if e.get("category") == "onboard"]
        started = [e for e in onboard_events if e.get("event") == "onboard_start"]
        finished = [e for e in onboard_events if e.get("event") == "onboard_finished"]
        assert started and started[0]["target"] == "d1"
        # start/finish correlate through the job id (concurrent onboards)
        assert started[0]["detail"] == "job " + job_id
        assert finished and finished[0]["result"] == "ok"
        assert finished[0]["detail"].startswith("job %s " % job_id)
        assert "platform=guestshell rc=0" in finished[0]["detail"]
    finally:
        stop()


def _serve_overview(tmp_path, swarm_fetch=None):
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
    fleet.upsert({"device_id": "d2", "device_ip": "10.0.0.2"})
    fleet.upsert({"device_id": "d3", "device_ip": "10.0.0.3"})
    cat = catalog_mod.CatalogStore(state)
    cat.save_image({"id": "img1", "filename": "img1.bin", "sha256": "ab",
                    "published_at": 1})
    cat.set_policy("d1", approved_image_id="img1")
    cat.set_policy("d2", approved_image_id="img1")
    cat.set_policy("d3", approved_image_id="img1")
    # d1 finished staging (stage_state=ready); d3 is mid-download (staging); d2 never checked in
    cat.record_heartbeat("d1", {"current_image_id": "img1", "stage_state": "ready"}, now=10)
    cat.record_heartbeat("d3", {"current_image_id": "img1", "stage_state": "staging"}, now=11)
    # clock injected just past the heartbeats, so both devices read as fresh
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, None, cat, None,
                                 swarm_fetch, certfile=None, now_fn=lambda: 100)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, srv.shutdown


def test_overview_aggregates(tmp_path):
    host, port, stop = _serve_overview(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/overview")[0] == 401
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/overview", headers={"Cookie": ck})
        assert st == 200
        ov = json.loads(b)
        assert ov["images"] == 1 and ov["devices"] == 3
        assert ov["assigned"] == 3 and ov["staged"] == 1   # only d1 (ready) counts
        # only d3 is ACTUALLY staging (heartbeating, stage_state=staging);
        # d2 never checked in — an inventory row is not a staging device
        assert ov["staging_now"] == 1
        r = [x for x in ov["rollout"] if x["image_id"] == "img1"][0]
        assert r["assigned"] == 3 and r["staged"] == 1
    finally:
        stop()


def test_overview_staging_counts_only_heartbeating_stagers(tmp_path):
    """Regression (operator report): an install with 6 inventory rows and NO
    device ever heartbeating showed '6 staging'. staging_now was computed as
    assigned - staged, i.e. it counted fleet/policy rows, not devices. It must
    count devices that are ACTUALLY staging: enrolled (heartbeat present) with
    a non-terminal stage_state — not inventory-only rows, not unassigned
    agents, not ready/seeding devices (those feed the staged count)."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    cat = catalog_mod.CatalogStore(state)
    cat.save_image({"id": "img1", "filename": "img1.bin", "sha256": "ab",
                    "published_at": 1})
    for i in range(6):
        did = "sw%d" % i
        fleet.upsert({"device_id": did, "device_ip": "10.0.0.%d" % (i + 1)})
        cat.set_policy(did, approved_image_id="img1")
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, None, cat,
                                 None, None, certfile=None,
                                 now_fn=lambda: 100)   # heartbeats stay fresh
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ck, _csrf = _auth("127.0.0.1", port)
        ov = json.loads(_req("127.0.0.1", port, "GET", "/api/overview",
                             headers={"Cookie": ck})[2])
        assert ov["devices"] == 6 and ov["assigned"] == 6
        assert ov["staging_now"] == 0     # nothing has ever heartbeated
        # devices actively staging ARE counted...
        cat.record_heartbeat("sw0", {"stage_state": "staging"}, now=10)
        cat.record_heartbeat("sw1", {"stage_state": "downloading"}, now=11)
        # ...but a ready (seeding) device counts as staged, not staging,
        # and an unassigned agent is not staging anything
        cat.record_heartbeat("sw2", {"current_image_id": "img1",
                                     "stage_state": "ready"}, now=12)
        cat.record_heartbeat("sw3", {"stage_state": "unassigned"}, now=13)
        ov = json.loads(_req("127.0.0.1", port, "GET", "/api/overview",
                             headers={"Cookie": ck})[2])
        assert ov["staging_now"] == 2     # sw0 + sw1 only
        assert ov["staged"] == 1          # sw2: ready with its assigned image
    finally:
        srv.shutdown()


def test_overview_staging_excludes_stale_and_error_devices(tmp_path):
    """Regression: staging_now counted devices whose LAST heartbeat said
    'staging' no matter how old it was — a device that died mid-stage read
    as staging forever — and counted terminal stage_state=error rows too.
    Only devices fresh within the UI's 600s offline horizon count, error is
    out, but a retryable condition (flash_full) on a live agent still
    counts."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    cat = catalog_mod.CatalogStore(state)
    for did in ("fresh", "stale", "err", "flash"):
        fleet.upsert({"device_id": did, "device_ip": "10.0.0.1"})
    now = 10000
    cat.record_heartbeat("fresh", {"stage_state": "staging"}, now=now - 30)
    cat.record_heartbeat("stale", {"stage_state": "staging"}, now=now - 601)
    cat.record_heartbeat("err", {"stage_state": "error"}, now=now - 30)
    cat.record_heartbeat("flash", {"stage_state": "flash_full"}, now=now - 30)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, None, cat,
                                 None, None, certfile=None,
                                 now_fn=lambda: now)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ck, _csrf = _auth("127.0.0.1", port)
        ov = json.loads(_req("127.0.0.1", port, "GET", "/api/overview",
                             headers={"Cookie": ck})[2])
        # fresh + flash only: the stale stager is offline, error is terminal
        assert ov["staging_now"] == 2
    finally:
        srv.shutdown()


def test_overview_staging_counts_one_errored_image_with_others_in_flight(tmp_path):
    """Regression (Task 3 review finding): Task 3's set heartbeat
    (_send_set_heartbeat) reports the single MOST ACTIONABLE stage_state
    across every image in the tick, so one failed image pins the whole
    heartbeat to "error" even while another assigned image is still
    downloading. The old staging_now check treated any stage_state=="error"
    as terminal and dropped a device like that out of the staging count
    entirely, mid-transfer. A device holding a multi-image set is wholly
    failed only once nothing else in the set is still outstanding -- here,
    "a" errored but "b" is still going, so the device must still count."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    cat = catalog_mod.CatalogStore(state)
    cat.save_image({"id": "a", "filename": "a.bin", "sha256": "aa",
                    "published_at": 1})
    cat.save_image({"id": "b", "filename": "b.bin", "sha256": "bb",
                    "published_at": 2})
    fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
    cat.set_policy("d1", approved_image_ids=["a", "b"])
    # "a" errored, "b" is still downloading: the aggregate stage_state the
    # agent sends is "error" (Task 3's priority order over "staging"),
    # staged_image_ids is empty (neither image is done yet), and only one
    # message rides stage_error.
    cat.record_heartbeat("d1", {"stage_state": "error",
                                "stage_error": "a: no space",
                                "staged_image_ids": [],
                                "current_image_id": "b"}, now=10)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, None, cat,
                                 None, None, certfile=None,
                                 now_fn=lambda: 100)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ck, _csrf = _auth("127.0.0.1", port)
        ov = json.loads(_req("127.0.0.1", port, "GET", "/api/overview",
                             headers={"Cookie": ck})[2])
        assert ov["staging_now"] == 1     # b is still in flight
        assert ov["staged"] == 0          # not fully staged either
    finally:
        srv.shutdown()


def test_overview_staging_excludes_error_when_nothing_else_is_outstanding(tmp_path):
    """Companion to the above: once every OTHER assigned image is already
    staged, the single remaining unstaged one IS the one that errored --
    nothing else could still be in flight, so the device is wholly failed
    and must not count as staging."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    cat = catalog_mod.CatalogStore(state)
    cat.save_image({"id": "a", "filename": "a.bin", "sha256": "aa",
                    "published_at": 1})
    cat.save_image({"id": "b", "filename": "b.bin", "sha256": "bb",
                    "published_at": 2})
    fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
    cat.set_policy("d1", approved_image_ids=["a", "b"])
    # "b" is already staged; "a" is the one and only outstanding image, and
    # it errored -- nothing else this device could still be doing.
    cat.record_heartbeat("d1", {"stage_state": "error",
                                "stage_error": "a: no space",
                                "staged_image_ids": ["b"],
                                "current_image_id": "a"}, now=10)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, None, cat,
                                 None, None, certfile=None,
                                 now_fn=lambda: 100)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ck, _csrf = _auth("127.0.0.1", port)
        ov = json.loads(_req("127.0.0.1", port, "GET", "/api/overview",
                             headers={"Cookie": ck})[2])
        assert ov["staging_now"] == 0
    finally:
        srv.shutdown()


def test_overview_staging_all_errored_is_not_staging(tmp_path):
    """Review finding on the two tests above: _send_set_heartbeat collapses a
    multi-image tick's per-image statuses into ONE stage_state, so
    "1 errored, 2 in flight" and "all 3 errored" used to look identical to
    the server -- a device stuck on every assigned image counted as staging
    forever. errored_image_ids (this fix) names the images that actually
    failed THIS tick, so a device where every assigned image is accounted
    for by staged_image_ids or errored_image_ids has nothing left in flight
    and must not count."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    cat = catalog_mod.CatalogStore(state)
    for iid in ("a", "b", "c"):
        cat.save_image({"id": iid, "filename": iid + ".bin", "sha256": iid,
                        "published_at": 1})
    fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
    cat.set_policy("d1", approved_image_ids=["a", "b", "c"])
    # every assigned image is either staged (none are) or errored (all are)
    cat.record_heartbeat("d1", {"stage_state": "error",
                                "stage_error": "everything failed",
                                "staged_image_ids": [],
                                "errored_image_ids": ["a", "b", "c"],
                                "current_image_id": "a"}, now=10)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, None, cat,
                                 None, None, certfile=None,
                                 now_fn=lambda: 100)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ck, _csrf = _auth("127.0.0.1", port)
        ov = json.loads(_req("127.0.0.1", port, "GET", "/api/overview",
                             headers={"Cookie": ck})[2])
        assert ov["staging_now"] == 0
    finally:
        srv.shutdown()


def test_overview_staging_counts_a_flash_full_set_as_still_staging(tmp_path):
    """Review minor: Tier 3 treats every id in errored_image_ids as accounted
    for -- but the agent files flash_full there too, and flash_full is the one
    failure this count has always deliberately kept ("the agent is alive and
    retrying"). Tiers 1 and 2 both count it; Tier 3 dropped the same device
    out of staging_now entirely the moment its agent grew the field, so
    freeing space on the box looked like nothing was happening."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    cat = catalog_mod.CatalogStore(state)
    for iid in ("a", "b"):
        cat.save_image({"id": iid, "filename": iid + ".bin", "sha256": iid,
                        "published_at": 1})
    fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
    cat.set_policy("d1", approved_image_ids=["a", "b"])
    # both images are waiting on room: accounted for, but not finished with
    cat.record_heartbeat("d1", {"stage_state": "flash_full",
                                "stage_error": "no room for b.bin",
                                "staged_image_ids": [],
                                "errored_image_ids": ["a", "b"],
                                "current_image_id": "a"}, now=10)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, None, cat,
                                 None, None, certfile=None,
                                 now_fn=lambda: 100)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ck, _csrf = _auth("127.0.0.1", port)
        ov = json.loads(_req("127.0.0.1", port, "GET", "/api/overview",
                             headers={"Cookie": ck})[2])
        assert ov["staging_now"] == 1
    finally:
        srv.shutdown()


def test_overview_staging_one_errored_two_outstanding_counts(tmp_path):
    """Companion to the above: with errored_image_ids naming only the ONE
    image that actually failed, the other two -- neither staged nor errored
    -- are genuinely still in flight, so the device counts as staging."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    cat = catalog_mod.CatalogStore(state)
    for iid in ("a", "b", "c"):
        cat.save_image({"id": iid, "filename": iid + ".bin", "sha256": iid,
                        "published_at": 1})
    fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
    cat.set_policy("d1", approved_image_ids=["a", "b", "c"])
    cat.record_heartbeat("d1", {"stage_state": "error",
                                "stage_error": "a: no space",
                                "staged_image_ids": [],
                                "errored_image_ids": ["a"],
                                "current_image_id": "b"}, now=10)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, None, cat,
                                 None, None, certfile=None,
                                 now_fn=lambda: 100)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ck, _csrf = _auth("127.0.0.1", port)
        ov = json.loads(_req("127.0.0.1", port, "GET", "/api/overview",
                             headers={"Cookie": ck})[2])
        assert ov["staging_now"] == 1
    finally:
        srv.shutdown()


def test_swarm_proxy_and_error(tmp_path):
    host, port, stop = _serve_overview(tmp_path, swarm_fetch=lambda: b'{"peers":[1,2,3]}')
    try:
        assert _req(host, port, "GET", "/api/swarm")[0] == 401
        ck, _csrf = _auth(host, port)
        st, hd, b = _req(host, port, "GET", "/api/swarm", headers={"Cookie": ck})
        assert st == 200 and json.loads(b)["peers"] == [1, 2, 3]
    finally:
        stop()

    def boom():
        raise OSError("tracker down")
    host, port, stop = _serve_overview(tmp_path, swarm_fetch=boom)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/swarm", headers={"Cookie": ck})
        assert st == 200 and "error" in json.loads(b)   # graceful on tracker down
    finally:
        stop()


def _serve_fresh(tmp_path):
    """A server whose store has NO admin yet (first-run/setup state)."""
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, app, srv.shutdown


def _setup_headers(host, port):
    return {"Origin": "http://%s:%d" % (host, port)}


def _default_login_grant(host, port):
    """Exchange the documented default pair for a one-time setup grant."""
    st, hd, b = _req(host, port, "POST", "/api/login",
                     {"username": gui_server.DEFAULT_SETUP_USER,
                      "password": gui_server.DEFAULT_SETUP_PASS})
    assert st == 200
    body = json.loads(b)
    assert body["setup"] is True and body["setup_grant"]
    assert "Set-Cookie" not in hd            # no session for the default pair
    return body["setup_grant"]


def test_default_setup_pair_is_stable():
    assert gui_server.DEFAULT_SETUP_USER == "iris"
    assert gui_server.DEFAULT_SETUP_PASS == "irisisgreat!"


def test_setup_serves_wizard_and_creates_admin(tmp_path):
    host, port, app, stop = _serve_fresh(tmp_path)
    try:
        # while no admin exists, GET / serves the LOGIN page; the documented
        # default pair mints the setup grant. The setup
        # page itself stays reachable as a static page for the redirect.
        st, hd, b = _req(host, port, "GET", "/")
        assert st == 200 and b'id="login-form"' in b
        st, hd, b = _req(host, port, "GET", "/setup.html")
        assert st == 200 and b'id="setup-form"' in b
        # The server hands back a one-time grant instead of a session.
        grant = _default_login_grant(host, port)
        st, _, _ = _req(host, port, "POST", "/api/setup",
                        {"username": "admin", "password": "password",
                         "setup_grant": grant},
                        headers=_setup_headers(host, port))
        assert st == 200
        assert app.needs_setup() is False
        # it is now self-disabled (409) and the login flow works
        st, _, _ = _req(host, port, "POST", "/api/setup",
                        {"username": "x", "password": "password",
                         "setup_grant": grant},
                        headers=_setup_headers(host, port))
        assert st == 409
        st, _, _ = _req(host, port, "POST", "/api/login",
                        {"username": "admin", "password": "password"})
        assert st == 200
    finally:
        stop()


def test_setup_requires_fields(tmp_path):
    host, port, _app, stop = _serve_fresh(tmp_path)
    try:
        st, _, _ = _req(host, port, "POST", "/api/setup", {"username": "", "password": ""})
        assert st == 400
    finally:
        stop()


def test_normal_mode_serves_login_not_setup(tmp_path):
    # Once an admin exists, / serves the React Console shell; login stays separate.
    app = gui_app.GuiApp(str(tmp_path / "secrets.json")); app.set_admin("admin", "pw")
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        st, _, b = _req("127.0.0.1", port, "GET", "/login.html")
        assert st == 200 and b"Sign in" in b
        # GET / serves the current module entrypoint, not the setup wizard.
        st, _, b = _req("127.0.0.1", port, "GET", "/")
        assert st == 200
        assert b'<script type="module" src="/assets/console.js"></script>' in b
        assert b'id="setup-form"' not in b and b'id="login-form"' not in b
        # setup is refused now, even with a syntactically plausible grant
        st, _, _ = _req("127.0.0.1", port, "POST", "/api/setup",
                        {"username": "x", "password": "password",
                         "setup_grant": "unavailable-after-setup"},
                        headers=_setup_headers("127.0.0.1", port))
        assert st == 409
        # The default pair is not special once an admin exists: it is an
        # ordinary failed login, not a setup grant.
        st, _, b = _req("127.0.0.1", port, "POST", "/api/login",
                        {"username": gui_server.DEFAULT_SETUP_USER,
                         "password": gui_server.DEFAULT_SETUP_PASS})
        assert st == 401
        assert "setup" not in json.loads(b)
    finally:
        srv.shutdown()


def test_setup_requires_and_consumes_grant(tmp_path):
    host, port, app, stop = _serve_fresh(tmp_path)
    try:
        headers = _setup_headers(host, port)
        payload = {"username": "admin", "password": "password"}

        st, _, _ = _req(host, port, "POST", "/api/setup", payload, headers=headers)
        assert st == 403                         # no grant

        grant = _default_login_grant(host, port)
        st, _, _ = _req(host, port, "POST", "/api/setup",
                        payload | {"setup_grant": "wrong-grant"}, headers=headers)
        assert st == 403                         # wrong grant

        st, _, _ = _req(host, port, "POST", "/api/setup",
                        payload | {"setup_grant": grant + "\n"}, headers=headers)
        assert st == 200 and app.needs_setup() is False  # stray whitespace is stripped

        st, _, _ = _req(host, port, "POST", "/api/setup",
                        {"username": "other", "password": "password",
                         "setup_grant": grant}, headers=headers)
        assert st == 409                         # grant cannot be reused
    finally:
        stop()


def test_setup_grant_expires(tmp_path, monkeypatch):
    host, port, app, stop = _serve_fresh(tmp_path)
    try:
        monkeypatch.setattr(gui_server.time, "time", lambda: 10000.0)
        grant = _default_login_grant(host, port)
        monkeypatch.setattr(gui_server.time, "time",
                            lambda: 10000.0 + gui_server._SETUP_GRANT_TTL)
        st, _, _ = _req(host, port, "POST", "/api/setup",
                        {"username": "admin", "password": "password",
                         "setup_grant": grant},
                        headers=_setup_headers(host, port))
        assert st == 403
        assert app.needs_setup() is True
    finally:
        stop()


def test_setup_grant_regenerated_on_each_default_login_latest_wins(tmp_path):
    host, port, app, stop = _serve_fresh(tmp_path)
    try:
        grant1 = _default_login_grant(host, port)
        grant2 = _default_login_grant(host, port)
        assert grant1 != grant2
        headers = _setup_headers(host, port)
        # the superseded grant no longer works
        st, _, _ = _req(host, port, "POST", "/api/setup",
                        {"username": "admin", "password": "password",
                         "setup_grant": grant1}, headers=headers)
        assert st == 403
        # the latest grant does
        st, _, _ = _req(host, port, "POST", "/api/setup",
                        {"username": "admin", "password": "password",
                         "setup_grant": grant2}, headers=headers)
        assert st == 200
    finally:
        stop()


def test_only_exact_default_pair_mints_setup_grant(tmp_path):
    """Either correct field alone is an ordinary failed login."""
    host, port, app, stop = _serve_fresh(tmp_path)
    try:
        for creds in (
            {"username": gui_server.DEFAULT_SETUP_USER, "password": "wrong"},
            {"username": "not-iris",
             "password": gui_server.DEFAULT_SETUP_PASS},
        ):
            st, _, b = _req(host, port, "POST", "/api/login", creds)
            assert st == 401
            assert "setup" not in json.loads(b)
        assert app.needs_setup() is True
    finally:
        stop()


def test_default_credential_full_happy_path(tmp_path):
    """End to end: default login -> grant -> setup -> real session."""
    host, port, app, stop = _serve_fresh(tmp_path)
    try:
        grant = _default_login_grant(host, port)
        st, _, _ = _req(host, port, "POST", "/api/setup",
                        {"username": "opuser", "password": "opuserpassword",
                         "setup_grant": grant},
                        headers=_setup_headers(host, port))
        assert st == 200
        assert app.needs_setup() is False
        st, hd, b = _req(host, port, "POST", "/api/login",
                         {"username": "opuser", "password": "opuserpassword"})
        assert st == 200 and "iris_sid=" in hd.get("Set-Cookie", "")
        assert json.loads(b)["username"] == "opuser"
    finally:
        stop()


def test_admin_may_be_named_iris(tmp_path):
    """The default username remains legal for the persistent admin account."""
    host, port, app, stop = _serve_fresh(tmp_path)
    try:
        grant = _default_login_grant(host, port)
        st, _, _ = _req(host, port, "POST", "/api/setup",
                        {"username": "iris", "password": "a-real-password",
                         "setup_grant": grant},
                        headers=_setup_headers(host, port))
        assert st == 200
        assert app.needs_setup() is False

        # iris + the real chosen password -> ordinary successful login
        st, hd, b = _req(host, port, "POST", "/api/login",
                         {"username": "iris", "password": "a-real-password"})
        assert st == 200 and "iris_sid=" in hd.get("Set-Cookie", "")
        assert json.loads(b)["username"] == "iris"

        # The default pair no longer means anything special post-setup, and
        # does not match this admin's real password.
        st, _, b = _req(host, port, "POST", "/api/login",
                        {"username": gui_server.DEFAULT_SETUP_USER,
                         "password": gui_server.DEFAULT_SETUP_PASS})
        assert st == 401
        assert "setup" not in json.loads(b)
    finally:
        stop()


def test_admin_named_iris_with_default_password(tmp_path):
    """After setup, the same pair uses only the persisted admin hash."""
    host, port, app, stop = _serve_fresh(tmp_path)
    try:
        grant = _default_login_grant(host, port)
        st, _, _ = _req(host, port, "POST", "/api/setup",
                        {"username": "iris",
                         "password": gui_server.DEFAULT_SETUP_PASS,
                         "setup_grant": grant},
                        headers=_setup_headers(host, port))
        assert st == 200
        assert app.needs_setup() is False

        st, hd, b = _req(host, port, "POST", "/api/login",
                         {"username": gui_server.DEFAULT_SETUP_USER,
                          "password": gui_server.DEFAULT_SETUP_PASS})
        assert st == 200 and "iris_sid=" in hd.get("Set-Cookie", "")
        assert json.loads(b)["username"] == "iris"
        assert "setup" not in json.loads(b)
    finally:
        stop()


def test_bootstrap_token_strings_removed_repo_wide():
    """The earlier file-backed GUI bootstrap-token mechanism stays removed."""
    repo_root = os.path.normpath(os.path.join(gui_server.WEBROOT, "..", ".."))
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=repo_root, capture_output=True,
        text=True, check=True).stdout.splitlines()
    needles = ("gui-bootstrap-token", "bootstrap_token")
    self_path = "server/tests/" + os.path.basename(__file__)
    hits = []
    for rel in tracked:
        if rel in (self_path, "CHANGELOG.md"):
            continue
        try:
            with open(os.path.join(repo_root, rel), "rb") as f:
                data = f.read()
        except OSError:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue                      # binary file, not a text reference
        for needle in needles:
            if needle in text:
                hits.append("%s: %s" % (rel, needle))
    assert not hits, hits


def test_delete_image_route(tmp_path):
    host, port, images, _stop = None, None, None, None
    host, port, _app, images, stop = _serve_with_images(tmp_path)
    try:
        ck, csrf = _login(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # publish img1 through the fake publish path
        store = images._store()
        store.save_image({"id": "img1", "filename": "img1.bin", "info_hash_hex": "x",
                          "published_at": 1})
        # delete requires CSRF
        assert _req(host, port, "DELETE", "/api/images/img1",
                    headers={"Cookie": ck})[0] == 403
        # 404 for unknown
        assert _req(host, port, "DELETE", "/api/images/nope", headers=hh)[0] == 404
        # blocked (409) when assigned
        store.set_policy("d1", approved_image_id="img1")
        st, _, b = _req(host, port, "DELETE", "/api/images/img1", headers=hh)
        assert st == 409 and "d1" in json.loads(b)["assigned"]
        # unassign -> deletes (200)
        store.set_policy("d1", approved_image_id=None)
        st, _, _ = _req(host, port, "DELETE", "/api/images/img1", headers=hh)
        assert st == 200
        assert store.get_image("img1") is None
    finally:
        stop()


def test_delete_image_stale_policy_after_device_removed(tmp_path):
    # A policy for a device that was later removed from the fleet must NOT keep an
    # image permanently un-deletable: the route intersects the assigned check with
    # the live fleet inventory.
    host, port, ctx, stop = _serve_full(tmp_path)
    _app, fleet, _creds, cat = ctx
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # img1 preexists in _serve_full's catalog; add d1 and assign it img1
        assert _req(host, port, "POST", "/api/devices",
                    {"device_id": "d1", "device_ip": "10.0.0.1",
                     "management_type": "routed", "iris_vlan": "666",
                     "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                     "app_ip": "10.0.0.3", "app_mask": "255.255.255.252",
                     "app_gateway": "10.0.0.1"}, headers=hh)[0] == 200
        cat.set_policy("d1", approved_image_id="img1")
        # a live assigned device blocks deletion (409)
        st, _, b = _req(host, port, "DELETE", "/api/images/img1", headers=hh)
        assert st == 409 and "d1" in json.loads(b)["assigned"]
        # remove d1 from the fleet -> its policy is now stale
        assert _req(host, port, "DELETE", "/api/devices/d1", headers=hh)[0] == 200
        # the stale policy must no longer block: the image is deletable (200)
        st, _, _ = _req(host, port, "DELETE", "/api/images/img1", headers=hh)
        assert st == 200
        assert cat.get_image("img1") is None
    finally:
        stop()


def test_settings_get(tmp_path):
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/settings")[0] == 401   # no session
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/settings", headers={"Cookie": ck})
        assert st == 200
        s = json.loads(b)
        assert s["admin_username"] == "admin"
        assert s["ports"]["console"] == 8080 and s["ports"]["catalog"] == 8443
        assert "enabled" in s["observability"]
        assert s["sessions"]["active"] >= 1
        assert "version" in s and "host_ip" in s
    finally:
        stop()


import setup_status


def test_setup_status_route_requires_auth(tmp_path, monkeypatch):
    """test_setup_status.py::test_route_is_registered_and_session_gated only
    greps gui_server.py for the session-check string -- it would still pass
    if the check were dead code. Prove it over real HTTP: no session cookie
    must get refused, not a crash or a 200 with data."""
    monkeypatch.setenv("IRIS_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        status, _, _ = _req(host, port, "GET", "/api/settings/setup-status")
        assert status == 401
    finally:
        stop()


def test_setup_status_route_returns_documented_shape(tmp_path, monkeypatch):
    """Authenticated GET must actually reach setup_status.build_status and
    return its four-card shape wired to the real session + credential
    store -- unlike the source-scan test, this fails if the route raises,
    returns the wrong shape, or never calls the builder at all."""
    monkeypatch.setenv("IRIS_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        status, _, body = _req(host, port, "GET", "/api/settings/setup-status",
                               headers={"Cookie": ck})
        assert status == 200
        st = json.loads(body)
        assert set(("admin", "telemetry", "packages", "image_verification")) <= set(st)
        # the session's real username must flow through, not a placeholder
        assert st["admin"]["username"] == "admin"
        pkgs = st["packages"]
        assert set(("state", "items", "remedy")) <= set(pkgs)
        # +2: the IOS-XR RPM plus the verified Guest Shell agent bundle.
        assert len(pkgs["items"]) == len(setup_status.IOX_PACKAGES) + 2
        assert {item['name'] for item in pkgs['items']} == {
            'iris-amd64.tar', 'iris-arm64.tar', 'iris-xr.rpm', 'iris-agent.tgz'}
        for item in pkgs["items"]:
            assert "name" in item and "state" in item
    finally:
        stop()


import bulkhash_refresh


def test_setup_status_route_carries_the_image_verification_card(tmp_path, monkeypatch):
    """The route's image_verification card (KGV / Cisco Bulk Hash reconciler,
    console Task 5) must actually be wired to the real bulkhash settings
    file on IRIS_STATE, not just present in setup_status.build_status's pure
    unit tests -- unset with no recorded run, ok once one succeeded, and
    still unset after one that failed (never an equality check against the
    literal "fail", since the detail suffix always differs)."""
    monkeypatch.setenv("IRIS_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    state_dir = str(tmp_path / "state")
    monkeypatch.setenv("IRIS_STATE", state_dir)
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        status, _, body = _req(host, port, "GET", "/api/settings/setup-status",
                               headers={"Cookie": ck})
        assert status == 200
        assert json.loads(body)["image_verification"]["state"] == "unset"

        spath = bulkhash_refresh.settings_path(state_dir)
        bulkhash_refresh.write_settings(
            spath, "off", 0, {"at": 1735689600, "source": "scheduled",
                              "outcome": "fail: signature verification failed",
                              "matched": None, "mismatched": None,
                              "not_in_feed": None})
        status, _, body = _req(host, port, "GET", "/api/settings/setup-status",
                               headers={"Cookie": ck})
        assert json.loads(body)["image_verification"]["state"] == "unset"

        bulkhash_refresh.write_settings(
            spath, "off", 0, {"at": 1735689600, "source": "manual",
                              "outcome": "ok", "matched": 3, "mismatched": 0,
                              "not_in_feed": 0})
        status, _, body = _req(host, port, "GET", "/api/settings/setup-status",
                               headers={"Cookie": ck})
        assert json.loads(body)["image_verification"]["state"] == "ok"
    finally:
        stop()


def test_settings_console_port_is_dynamic(tmp_path, monkeypatch):
    """The Settings page must show the actual published console port
    (IRIS_GUI_PUBLISH), not a hardcoded 8080."""
    monkeypatch.setenv("IRIS_GUI_PUBLISH", "8082")
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/settings", headers={"Cookie": ck})
        assert st == 200 and json.loads(b)["ports"]["console"] == 8082
    finally:
        stop()


@pytest.mark.parametrize("url, port", [
    ("https://console.example.com:9080/", 9080),
    ("https://console.example.com", 443),
])
def test_settings_reports_independent_console_origin(tmp_path, monkeypatch, url, port):
    monkeypatch.setenv("IRIS_HOST_IP", "192.0.2.10")
    monkeypatch.setenv("IRIS_GUI_PUBLISH", "8080")
    monkeypatch.setenv("IRIS_CONSOLE_URL", url)
    host, bound_port, _ctx, stop = _serve_full(tmp_path)
    try:
        ck, _csrf = _auth(host, bound_port)
        status, _, body = _req(host, bound_port, "GET", "/api/settings",
                               headers={"Cookie": ck})
        assert status == 200
        settings = json.loads(body)
        assert settings["host_ip"] == "192.0.2.10"
        assert settings["console_url"] == url.rstrip("/")
        assert settings["ports"]["console"] == port
    finally:
        stop()


@pytest.mark.parametrize("url", [
    "https://user:private@console.example.com:8080",
    "https://console.example.com:bad", "http://console.example.com:8080",
    "https://console.example.com:8080/?token=private",
])
def test_settings_does_not_echo_invalid_console_url(tmp_path, monkeypatch, url):
    monkeypatch.setenv("IRIS_HOST_IP", "192.0.2.10")
    monkeypatch.setenv("IRIS_GUI_PUBLISH", "8082")
    monkeypatch.setenv("IRIS_CONSOLE_URL", url)
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        status, _, body = _req(host, port, "GET", "/api/settings",
                               headers={"Cookie": ck})
        assert status == 200
        settings = json.loads(body)
        assert settings["console_url"] == "https://192.0.2.10:8082"
        assert settings["ports"]["console"] == 8082
        assert b"private" not in body
    finally:
        stop()


def test_settings_password_change(tmp_path):
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        ck2, _ = _auth(host, port)                       # a 2nd session to be revoked
        # CSRF required
        assert _req(host, port, "POST", "/api/settings/password",
                    {"current": "pw", "new": "newlongpw", "confirm": "newlongpw"},
                    headers={"Cookie": ck})[0] == 403
        # too short / mismatch / wrong current -> 400
        assert _req(host, port, "POST", "/api/settings/password",
                    {"current": "pw", "new": "short", "confirm": "short"}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/password",
                    {"current": "pw", "new": "newlongpw", "confirm": "nope12345"}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/password",
                    {"current": "bad", "new": "newlongpw", "confirm": "newlongpw"}, headers=hh)[0] == 400
        # success
        assert _req(host, port, "POST", "/api/settings/password",
                    {"current": "pw", "new": "newlongpw", "confirm": "newlongpw"}, headers=hh)[0] == 200
        # old password rejected, new accepted
        assert _req(host, port, "POST", "/api/login",
                    {"username": "admin", "password": "pw"})[0] == 401
        assert _req(host, port, "POST", "/api/login",
                    {"username": "admin", "password": "newlongpw"})[0] == 200
        # caller kept, other session revoked
        assert _req(host, port, "GET", "/api/settings", headers={"Cookie": ck})[0] == 200
        assert _req(host, port, "GET", "/api/settings", headers={"Cookie": ck2})[0] == 401
    finally:
        stop()


def test_settings_revoke_others(tmp_path):
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        ck2, _ = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/settings/sessions/revoke-others", {},
                        headers=hh)
        assert st == 200 and json.loads(b)["revoked"] >= 1
        assert _req(host, port, "GET", "/api/settings", headers={"Cookie": ck})[0] == 200
        assert _req(host, port, "GET", "/api/settings", headers={"Cookie": ck2})[0] == 401
    finally:
        stop()


def test_json_body_non_object_returns_400(tmp_path):
    # A valid-JSON-but-non-object body (list/int/str/bool/null) must yield a clean
    # 400, not an AttributeError that drops the connection with no HTTP response.
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf, "Content-Type": "application/json"}
        for bad in (b"[]", b"123", b'"x"', b"true", b"null"):
            st, _, _ = _req(host, port, "POST", "/api/settings/password",
                            raw=bad, headers=hh)
            assert st == 400, (bad, st)
        # a pre-session endpoint takes the same guard
        st, _, _ = _req(host, port, "POST", "/api/login", raw=b"[]",
                        headers={"Content-Type": "application/json"})
        assert st == 400
    finally:
        stop()


def test_devices_example_csv_download(tmp_path):
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/devices/example-csv")[0] == 401
        ck, _csrf = _auth(host, port)
        st, hd, b = _req(host, port, "GET", "/api/devices/example-csv",
                         headers={"Cookie": ck})
        assert st == 200
        assert "filename=devices-example.csv" in hd.get("Content-Disposition", "")
        assert "device_id,device_ip,management_type,iris_vlan" in b.decode()
    finally:
        stop()


# ---- issue #13: console swarm map + device telemetry reports ----

import re

_MAP_FIXTURE = """<!DOCTYPE html>
<html><head><title>map</title>
<style>
  body { background: #000; }
</style>
</head><body>
<script>
window.IRIS_MAP_CFG = null;
const MAP = window.IRIS_MAP_CFG || {swarmUrl: "/swarm", pull: false};
</script>
</body></html>
"""

_CANNED_REPORT = {
    "ts": 1783000000, "image_id": "img1", "event": "staging-complete",
    "transfer": {"total_bytes": 1234, "elapsed_s": 60, "avg_bps": 20,
                 "sha_ok": True, "stage_state": "ready"},
    "link": {"tier": "good", "rtt_ms_median": 12, "rtt_samples": 8,
             "hb_failures": 0, "trimmed": False},
    "peers": [{"ip": "10.0.0.7"}],
    "peers_total": 1,
    "agent": {"version": "x", "runtime_mode": "guestshell"},
}


def _serve_reports(tmp_path):
    """gui_server wired to a real CatalogStore (telemetry ring + pull
    directives live in JSON files under tmp_path/state)."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    cat = catalog_mod.CatalogStore(str(tmp_path / "state"))
    fleet = gui_fleet.FleetStore(str(tmp_path / "state"))
    _policy_device(fleet)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, None, cat,
                                 certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, cat, srv.shutdown


def test_swarmmap_requires_session(tmp_path):
    host, port, _cat, stop = _serve_reports(tmp_path)
    try:
        status, _, _ = _req(host, port, "GET", "/swarmmap")
        assert status == 401
    finally:
        stop()


def test_swarmmap_injects_cfg_nonce_and_csp(tmp_path, monkeypatch):
    map_path = tmp_path / "swarmmap.html"
    map_path.write_text(_MAP_FIXTURE)
    monkeypatch.setattr(gui_server, "SWARMMAP_PATH", str(map_path))
    host, port, _cat, stop = _serve_reports(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, hd, b = _req(host, port, "GET", "/swarmmap", headers={"Cookie": ck})
        assert st == 200 and "text/html" in hd.get("Content-Type", "")
        body = b.decode()
        cfg = ('window.IRIS_MAP_CFG = {"swarmUrl":"/api/v1/swarm","pull":true,'
               '"eventsUrlTemplate":""};')
        assert body.count(cfg) == 1                       # substituted exactly once
        assert "window.IRIS_MAP_CFG = null;" not in body  # placeholder consumed
        m = re.search(r'<script nonce="([^"]+)">', body)
        assert m, "script tag did not get a nonce"
        nonce = m.group(1)
        assert '<style nonce="%s">' % nonce in body
        assert hd.get("Content-Security-Policy", "") == (
            "default-src 'self'; script-src 'nonce-%s'; style-src 'nonce-%s'; "
            "connect-src 'self'; img-src 'self'" % (nonce, nonce))
        # the console embeds this page in a same-origin iframe: the global
        # DENY / frame-ancestors 'none' policy must NOT apply to this route
        assert hd.get("X-Frame-Options") != "DENY"
        assert "frame-ancestors" not in hd.get("Content-Security-Policy", "")
        # nonce is per-request: a second GET carries a different one
        _, _, b2 = _req(host, port, "GET", "/swarmmap", headers={"Cookie": ck})
        m2 = re.search(r'<script nonce="([^"]+)">', b2.decode())
        assert m2 and m2.group(1) != nonce
    finally:
        stop()


def test_swarmmap_serves_real_file_with_nonced_csp(tmp_path):
    # Serve the real generated React map with the native nonce/CSP boundary.
    # Run npm ci && npm run build in server/console-ui before Python tests.
    host, port, _cat, stop = _serve_reports(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, hd, b = _req(host, port, "GET", "/swarmmap", headers={"Cookie": ck})
        assert st == 200 and "text/html" in hd.get("Content-Type", "")
        assert "script-src 'nonce-" in hd.get("Content-Security-Policy", "")
        assert b'<script nonce="' in b and b'<style nonce="' in b
        assert b'iris-swarm-map-root' in b
    finally:
        stop()


def test_device_reports_roundtrip(tmp_path):
    host, port, cat, stop = _serve_reports(tmp_path)
    cat.record_telemetry("d1", dict(_CANNED_REPORT))
    try:
        assert _req(host, port, "GET", "/api/devices/d1/reports")[0] == 401
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/devices/d1/reports",
                        headers={"Cookie": ck})
        assert st == 200
        reports = json.loads(b)["reports"]
        assert len(reports) == 1
        assert reports[0]["image_id"] == "img1"
        assert reports[0]["event"] == "staging-complete"
        assert reports[0]["peers"][0]["ip"] == "10.0.0.7"
        assert "received_at" in reports[0]      # stamped by record_telemetry
        # Reports are only available for known fleet devices.
        st, _, b = _req(host, port, "GET", "/api/devices/ghost/reports",
                        headers={"Cookie": ck})
        assert st == 422 and json.loads(b)["error"] == "device is not in fleet"
    finally:
        stop()


def test_request_report_session_csrf_and_429(tmp_path):
    host, port, cat, stop = _serve_reports(tmp_path)
    try:
        # no session -> 401; session without CSRF -> 403
        assert _req(host, port, "POST", "/api/devices/d1/request-report",
                    {})[0] == 401
        ck, csrf = _auth(host, port)
        assert _req(host, port, "POST", "/api/devices/d1/request-report",
                    {}, headers={"Cookie": ck})[0] == 403
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/devices/d1/request-report",
                        {}, headers=hh)
        assert st == 200
        res = json.loads(b)
        assert res["ok"] is True and res["expires_at"] > time.time()
        assert res["device_id"] == "d1"
        assert res["request_id"] == cat.pending_request("d1", time.time())["request_id"]
        assert res["requested_at"] + cat.PULL_TTL == res["expires_at"]
        st, _, b = _req(host, port, "GET", "/api/devices/d1/reports", headers=hh)
        reviewed = json.loads(b)
        assert st == 200 and reviewed["device_id"] == "d1"
        assert reviewed["pending_request"]["request_id"] == res["request_id"]
        assert reviewed["observed_at"] >= res["requested_at"]
        assert cat.pending_report(
            "d1", time.time())["report_requested"] is True
        # duplicate while pending -> 429
        st, _, b = _req(host, port, "POST", "/api/devices/d1/request-report",
                        {}, headers=hh)
        assert st == 429 and json.loads(b)["error"] == "request already pending"
        # a report arriving clears the directive; a new request succeeds again
        cat.record_telemetry("d1", dict(_CANNED_REPORT))
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/request-report",
                        {}, headers=hh)
        assert st == 200
    finally:
        stop()


def test_request_report_rejects_unknown_fleet_device(tmp_path):
    host, port, _cat, stop = _serve_reports(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        st, _, body = _req(host, port, "POST", "/api/devices/ghost/request-report",
                           {}, headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 422 and json.loads(body)["error"] == "device is not in fleet"
    finally:
        stop()


def test_request_report_reply_keeps_created_identity_after_immediate_completion(tmp_path, monkeypatch):
    host, port, cat, stop = _serve_reports(tmp_path)
    original = cat.request_report_details
    created = []

    def completed_before_reply(device_id, now):
        directive = original(device_id, now)
        created.append(directive)
        cat.clear_report_request(device_id, request_id=directive["request_id"])
        replacement = original(device_id, now + .001)
        assert replacement["request_id"] != directive["request_id"]
        return directive

    monkeypatch.setattr(cat, "request_report_details", completed_before_reply)
    try:
        cookie, csrf = _auth(host, port)
        status, _, raw = _req(host, port, "POST", "/api/devices/d1/request-report",
                             {}, headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 200
        assert json.loads(raw) == {"ok": True, "device_id": "d1", **created[0]}
        assert cat.pending_request("d1", time.time())["request_id"] != created[0]["request_id"]
    finally:
        stop()


def test_overview_swarm_map_url_is_console_relative(tmp_path):
    host, port, stop = _serve_overview(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/overview", headers={"Cookie": ck})
        assert st == 200
        assert json.loads(b)["swarm_map_url"] == "/swarmmap"
    finally:
        stop()


# ---- per-device credential profile selection ----

def test_device_credential_requires_session_and_csrf(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/credential",
                        {"credential_profile_id": "lab"})
        assert st == 401
        ck, _csrf = _auth(host, port)
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/credential",
                        {"credential_profile_id": "lab"}, headers={"Cookie": ck})
        assert st == 403
    finally:
        stop()


def test_device_credential_unknown_device_404(tmp_path):
    host, port, _deps, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/nope/credential",
                        {"credential_profile_id": "lab"}, headers=hh)
        assert st == 404
    finally:
        stop()


def test_device_credential_unknown_profile_400(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/credential",
                        {"credential_profile_id": "nope"}, headers=hh)
        assert st == 400
    finally:
        stop()


def test_device_credential_happy_path_preserves_other_fields(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, creds, _cat = deps
    try:
        fleet.import_csv(
            "device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip,model,platform\n"
            "d1,10.0.0.1,666,10.0.0.2,255.255.255.252,10.0.0.3,,\n")
        creds.set_profile("lab", {"name": "Lab", "device_user": "admin",
                                  "device_pass": "pw"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/credential",
                        {"credential_profile_id": "lab"}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        dev = json.loads(b)["devices"][0]
        assert dev["credential_profile_id"] == "lab"
        # other fields must survive the patch untouched
        assert dev["device_ip"] == "10.0.0.1"
        assert dev["vlan"] == "666"
        assert dev["svi_ip"] == "10.0.0.2"
        assert dev["svi_mask"] == "255.255.255.252"
        assert dev["guest_ip"] == "10.0.0.3"
    finally:
        stop()


def test_device_credential_empty_string_clears_profile(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1",
                     "credential_profile_id": "lab"})
        creds.set_profile("lab", {"name": "Lab", "device_user": "admin",
                                  "device_pass": "pw"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/credential",
                        {"credential_profile_id": ""}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        dev = json.loads(b)["devices"][0]
        assert dev.get("credential_profile_id") == ""
        assert dev["device_ip"] == "10.0.0.1"   # untouched
    finally:
        stop()


# ---- bulk credential reassignment (issue #125) ----

def test_bulk_credential_requires_session_and_csrf(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        st, _, _ = _req(host, port, "POST", "/api/devices/bulk-credential",
                        {"device_ids": ["d1"], "credential_profile_id": "lab"})
        assert st == 401
        ck, _csrf = _auth(host, port)
        st, _, _ = _req(host, port, "POST", "/api/devices/bulk-credential",
                        {"device_ids": ["d1"], "credential_profile_id": "lab"},
                        headers={"Cookie": ck})
        assert st == 403
    finally:
        stop()


def test_bulk_credential_rejects_bad_device_ids_body(tmp_path):
    host, port, _deps, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        for body in ({"device_ids": []}, {"device_ids": "d1"},
                     {"device_ids": [1, 2]}, {"device_ids": [""]}, {}):
            st, _, _ = _req(host, port, "POST", "/api/devices/bulk-credential",
                            body, headers=hh)
            assert st == 400, body
    finally:
        stop()


def test_bulk_credential_unknown_profile_400_applies_nothing(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/bulk-credential",
                        {"device_ids": ["d1"], "credential_profile_id": "nope"},
                        headers=hh)
        assert st == 400
        assert fleet.get_device("d1").get("credential_profile_id") in (None, "")
    finally:
        stop()


def test_bulk_credential_happy_path_one_audit_record(tmp_path):
    """The whole point of the bulk endpoint: ONE request, ONE audit record,
    applied to every selected device -- not one request/record per device."""
    host, port, deps, audit_path, stop = _serve_full_audit(tmp_path)
    _app, fleet, creds, _cat = deps
    try:
        for i in range(5):
            fleet.upsert({"device_id": "d%d" % i, "device_ip": "10.0.0.%d" % i})
        creds.set_profile("lab", {"name": "Lab", "device_user": "admin",
                                  "device_pass": "pw"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        ids = ["d%d" % i for i in range(5)]
        st, _, b = _req(host, port, "POST", "/api/devices/bulk-credential",
                        {"device_ids": ids, "credential_profile_id": "lab"},
                        headers=hh)
        assert st == 200, b
        result = json.loads(b)
        assert result == {"ok": True, "applied": 5, "failed": {}}
        for did in ids:
            assert fleet.get_device(did)["credential_profile_id"] == "lab"
        events = [json.loads(l) for l in open(audit_path) if l.strip()]
        creds_events = [e for e in events
                       if e.get("event") == "device_credential_bulk_change"]
        assert len(creds_events) == 1, creds_events
        assert "5/5" in creds_events[0]["detail"]
    finally:
        stop()


def test_bulk_credential_partial_failure_names_the_missing_device(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        creds.set_profile("lab", {"name": "Lab", "device_user": "admin",
                                  "device_pass": "pw"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/devices/bulk-credential",
                        {"device_ids": ["d1", "ghost"],
                         "credential_profile_id": "lab"}, headers=hh)
        assert st == 200, b
        result = json.loads(b)
        assert result["ok"] is True
        assert result["applied"] == 1
        assert result["failed"] == {"ghost": "no such device"}
        assert fleet.get_device("d1")["credential_profile_id"] == "lab"
    finally:
        stop()


def test_bulk_credential_matches_select_all_matching_at_scale(tmp_path):
    """The scenario issue #125 is actually about: the console's "Select all
    N matching devices" bulk action fires this ONE request for the whole
    filtered set. A few hundred devices is enough to prove correctness end
    to end over HTTP without making the test itself slow."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, creds, _cat = deps
    try:
        n = 300
        for i in range(n):
            fleet.upsert({"device_id": "d%03d" % i, "device_ip": "10.0.%d.%d" % (i // 256, i % 256)})
        creds.set_profile("lab", {"name": "Lab", "device_user": "admin",
                                  "device_pass": "pw"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        ids = ["d%03d" % i for i in range(n)]
        st, _, b = _req(host, port, "POST", "/api/devices/bulk-credential",
                        {"device_ids": ids, "credential_profile_id": "lab"},
                        headers=hh)
        assert st == 200, b
        result = json.loads(b)
        assert result == {"ok": True, "applied": n, "failed": {}}
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        devs = json.loads(b)["devices"]
        assert len(devs) == n
        assert all(d["credential_profile_id"] == "lab" for d in devs)
    finally:
        stop()


# ---- per-device platform override selection ----

def test_device_platform_requires_session_and_csrf(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/platform",
                        {"platform": "iox"})
        assert st == 401
        ck, _csrf = _auth(host, port)
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/platform",
                        {"platform": "iox"}, headers={"Cookie": ck})
        assert st == 403
    finally:
        stop()


def test_device_platform_unknown_device_404(tmp_path):
    host, port, _deps, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/nope/platform",
                        {"platform": "iox"}, headers=hh)
        assert st == 404
    finally:
        stop()


def test_device_platform_invalid_value_400(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/platform",
                        {"platform": "bogus"}, headers=hh)
        assert st == 400
    finally:
        stop()


def test_device_platform_accepts_the_xr_agent_on_xr_hardware(tmp_path):
    """The devices table lets an operator change a row's agent install. It
    must be able to SET xr-appmgr on an IOS-XR box before its management type
    is classified (the legacy short-circuit; platform xr-appmgr is now
    mutually bound to management_type xr-host on any fully-validated row,
    so xr1 stays unclassified here) -- and the fleet guard still refuses
    xr-appmgr on hardware that is not IOS-XR."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        routed = {"management_type": "routed", "iris_vlan": "120",
                  "svi_ip": "10.20.0.1", "svi_mask": "255.255.255.252",
                  "app_ip": "10.20.0.2", "app_mask": "255.255.255.252",
                  "app_gateway": "10.20.0.1"}
        fleet.upsert({"device_id": "xr1", "device_ip": "10.0.0.9", "model": "8201"})
        fleet.upsert(dict(routed, device_id="sw1", device_ip="10.0.0.8",
                          model="C9300-48UXM"))
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/xr1/platform",
                        {"platform": "xr-appmgr"}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        rows = {d["device_id"]: d for d in json.loads(b)["devices"]}
        assert rows["xr1"]["platform"] == "xr-appmgr"
        st, _, _ = _req(host, port, "POST", "/api/devices/sw1/platform",
                        {"platform": "xr-appmgr"}, headers=hh)
        assert st == 400
    finally:
        stop()


def test_device_platform_happy_path_and_clear(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.import_csv(
            "device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip,model,platform\n"
            "d1,10.0.0.1,666,10.0.0.2,255.255.255.252,10.0.0.3,,\n")
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # set iox
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/platform",
                        {"platform": "iox"}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        dev = json.loads(b)["devices"][0]
        assert dev["platform"] == "iox"
        assert dev["vlan"] == "666"          # other fields untouched
        # empty clears back to auto
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/platform",
                        {"platform": ""}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        dev = json.loads(b)["devices"][0]
        assert dev.get("platform") == ""
    finally:
        stop()


def test_device_platform_iox_on_inband_is_allowed(tmp_path):
    """Setting platform=iox on an inband device now succeeds and persists (the
    app SSHes to the switch's management IP by default)."""
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "edge", "device_ip": "192.0.2.10",
                      "management_type": "inband", "inband_vlan": "120",
                      "app_ip": "192.0.2.11", "app_mask": "255.255.255.0",
                      "app_gateway": "192.0.2.1", "platform": "guestshell"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/edge/platform",
                        {"platform": "iox"}, headers=hh)
        assert st == 200
        assert fleet.get_device("edge")["platform"] == "iox"
    finally:
        stop()


# ---- audit-trail wiring: /api/audit + emission points ----

import audit as audit_mod


def _read_audit_lines(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def _assignment_audit_parts(event):
    """Split the stable human prefix from exact machine-readable ID sets."""
    prefix, rest = event["detail"].split("; before_ids=", 1)
    before_raw, rest = rest.split("; after_ids=", 1)
    after_raw, removed_raw = rest.split("; removed_ids=", 1)
    return (prefix, json.loads(before_raw), json.loads(after_raw),
            json.loads(removed_raw))


# ---- forget SSH host key (issue #84) --------------------------------------
#
# A re-imaged/replaced device presents a new SSH host key; accept-new mode's
# persistent known_hosts (lab/iris-ssh-policy.sh) then refuses every session
# with a changed-key error, and that file lives inside the IRIS state
# volume -- not somewhere an operator always has shell access to. The console
# route below shells out to the real lab/iris-ssh-policy.sh (OnboardService's
# repo_root, unless overridden, is the real repo root), so every test here
# points IRIS_SSH_STATE_DIR at an isolated tmp_path -- never the host's own
# IRIS_STATE -- via monkeypatch.setenv.

def _serve_forget_host_key(tmp_path, monkeypatch, ssh_state_dir=None,
                           audit_path=None, devices=None):
    monkeypatch.setenv("IRIS_SSH_STATE_DIR",
                       str(ssh_state_dir or (tmp_path / "sshstate")))
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    fleet = gui_fleet.FleetStore(state)
    for dev in (devices or [{"device_id": "d1", "device_ip": "192.0.2.10"}]):
        fleet.upsert(dev)
    creds = gui_creds.CredentialStore(secrets_path)
    onboard = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                         mint_fn=lambda d: "TOK")
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, certfile=None, audit_path=audit_path)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, fleet, srv.shutdown


def test_forget_host_key_requires_session_and_csrf(tmp_path, monkeypatch):
    host, port, _fleet, stop = _serve_forget_host_key(tmp_path, monkeypatch)
    try:
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/forget-host-key", {})
        assert st == 401
        ck, _csrf = _auth(host, port)
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/forget-host-key",
                        {}, headers={"Cookie": ck})
        assert st == 403
    finally:
        stop()


def test_forget_host_key_unknown_device_404(tmp_path, monkeypatch):
    host, port, _fleet, stop = _serve_forget_host_key(tmp_path, monkeypatch)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/nope/forget-host-key",
                        {}, headers=hh)
        assert st == 404
    finally:
        stop()


@pytest.mark.parametrize("hashed", [False, True])
def test_forget_host_key_removes_only_that_devices_entry_and_re_pins_next_time(
        tmp_path, monkeypatch, hashed):
    """The persistent known_hosts holds two devices; forgetting d1 must drop
    ONLY d1's line, leave d2's trust untouched, and leave the file in a state
    where the NEXT session re-verifies and re-pins d1's new key (plain
    trust-on-first-use) rather than disabling verification for it."""
    ssh_state = tmp_path / "sshstate"
    known_hosts = ssh_state / "known_hosts"
    ssh_state.mkdir()
    known_hosts.write_text(
        "192.0.2.10 ssh-ed25519 AAAAOLDKEYFORD1==\n"
        "192.0.2.20 ssh-ed25519 AAAAKEYFORD2==\n")
    import subprocess
    if hashed:
        subprocess.run(["ssh-keygen", "-H", "-f", str(known_hosts)],
                       check=True, capture_output=True, timeout=10)
    control = known_hosts.read_text().splitlines()[1]
    host, port, fleet, stop = _serve_forget_host_key(
        tmp_path, monkeypatch, ssh_state_dir=ssh_state,
        devices=[{"device_id": "d1", "device_ip": "192.0.2.10"},
                {"device_id": "d2", "device_ip": "192.0.2.20"}])
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/devices/d1/forget-host-key",
                        {}, headers=hh)
        assert st == 200
        assert json.loads(b) == {"ok": True, "peer": "192.0.2.10"}
        assert known_hosts.read_text().splitlines() == [control]
        for peer, expected in [("192.0.2.10", 1), ("192.0.2.20", 0)]:
            assert subprocess.run(["ssh-keygen", "-F", peer, "-f", str(known_hosts)],
                                  capture_output=True, timeout=10).returncode == expected
    finally:
        stop()


def test_forget_host_key_is_idempotent_when_nothing_was_recorded(tmp_path, monkeypatch):
    """A peer with no recorded entry (never contacted, or already forgotten)
    is success, not an error -- the desired end state (no stale entry)
    already holds."""
    host, port, _fleet, stop = _serve_forget_host_key(tmp_path, monkeypatch)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/devices/d1/forget-host-key",
                        {}, headers=hh)
        assert st == 200
        assert json.loads(b) == {"ok": True, "peer": "192.0.2.10"}
    finally:
        stop()


def test_forget_host_key_audits_the_device_and_actor(tmp_path, monkeypatch):
    audit_path = str(tmp_path / "audit.jsonl")
    ssh_state = tmp_path / "sshstate"
    known_hosts = ssh_state / "known_hosts"
    ssh_state.mkdir()
    known_hosts.write_text("192.0.2.10 ssh-ed25519 AAAAOLDKEY==\n")
    host, port, _fleet, stop = _serve_forget_host_key(
        tmp_path, monkeypatch, ssh_state_dir=ssh_state, audit_path=audit_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/forget-host-key",
                        {}, headers=hh)
        assert st == 200
        events = _read_audit_lines(audit_path)
        forget_events = [e for e in events if e.get("event") == "device_forget_host_key"]
        assert len(forget_events) == 1
        entry = forget_events[0]
        assert entry["target"] == "d1"           # the device
        assert entry["actor"] == "console:admin"  # the actor
        assert entry["result"] == "ok"
        assert "192.0.2.10" in (entry.get("detail") or "")
    finally:
        stop()


def test_forget_host_key_never_touches_an_operator_pinned_known_hosts(tmp_path, monkeypatch):
    """IRIS_SSH_HOST_KEY (a per-device pin) and IRIS_SSH_KNOWN_HOSTS (an
    operator-supplied file) are not IRIS-managed state -- forget-host-key
    must act only on the persistent accept-new file, never on either."""
    ssh_state = tmp_path / "sshstate"
    ssh_state.mkdir()
    pinned = tmp_path / "operator-known-hosts"
    pinned.write_text("192.0.2.10 ssh-ed25519 AAAAOPERATORPINNED==\n")
    host, port, _fleet, stop = _serve_forget_host_key(
        tmp_path, monkeypatch, ssh_state_dir=ssh_state,
        devices=[{"device_id": "d1", "device_ip": "192.0.2.10"}])
    monkeypatch.setenv("IRIS_SSH_KNOWN_HOSTS", str(pinned))
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/forget-host-key",
                        {}, headers=hh)
        assert st == 200
        assert "192.0.2.10" in pinned.read_text()   # the operator's file is untouched
    finally:
        stop()


def _serve_full_audit(tmp_path):
    """_serve_full, but wired to a real audit.jsonl at tmp_path so emission
    points can be asserted against the raw file."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    audit_path = str(tmp_path / "audit.jsonl")
    images = gui_images.ImageService(state, str(tmp_path / "imgs"),
                                     tracker_url_fn=lambda: "http://t/announce?key=k",
                                     publish_fn=lambda p, s, u, **k: s.save_image(
                                         {"id": "img1", "filename": "img1.bin",
                                          "sha256": "ab", "published_at": 1}) or
                                     {"id": "img1"},
                                     import_root=str(tmp_path / "opt-images"))
    fleet = gui_fleet.FleetStore(state)
    creds = gui_creds.CredentialStore(secrets_path)
    cat = catalog_mod.CatalogStore(state)
    cat.save_image({"id": "img1", "filename": "img1.bin", "sha256": "ab",
                    "size": 3, "published_at": 1})
    cat.save_image({"id": "img2", "filename": "img2.bin", "sha256": "cd",
                    "size": 1288490188, "published_at": 2})
    srv = gui_server.make_server("127.0.0.1", 0, app, images, fleet, creds, cat,
                                 audit_path=audit_path, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, (app, fleet, creds, cat), audit_path, srv.shutdown


def test_api_audit_requires_session(tmp_path):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/audit")[0] == 401
    finally:
        stop()


def test_api_audit_bad_category_400(tmp_path):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit?category=nonsense", headers={"Cookie": ck})
        assert st == 400
        assert "error" in json.loads(b)
    finally:
        stop()


def test_api_audit_happy_path_newest_first(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        audit_mod.append_event(audit_path, "e1", category="device", ts=1000)
        audit_mod.append_event(audit_path, "e2", category="device", ts=2000)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/audit", headers={"Cookie": ck})
        assert st == 200
        events = json.loads(b)["events"]
        # login itself emits an event, so just check relative order + presence
        evnames = [e["event"] for e in events]
        assert evnames.index("e2") < evnames.index("e1")
    finally:
        stop()


def test_api_audit_limit_cap(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        for i in range(10):
            audit_mod.append_event(audit_path, "e%d" % i, category="device",
                                   ts=1000 + i)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit?limit=999999&category=device",
                        headers={"Cookie": ck})
        assert st == 200
        events = json.loads(b)["events"]
        assert len(events) <= 500
    finally:
        stop()


def test_api_audit_before_ts_and_category_filter(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        audit_mod.append_event(audit_path, "e1", category="device", ts=1000)
        audit_mod.append_event(audit_path, "e2", category="image", ts=2000)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit?category=device", headers={"Cookie": ck})
        assert st == 200
        events = json.loads(b)["events"]
        assert all(e["category"] == "device" for e in events)
        assert any(e["event"] == "e1" for e in events)
    finally:
        stop()


def test_api_audit_after_ts_window(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        audit_mod.append_event(audit_path, "e1", category="device", ts=1000)
        audit_mod.append_event(audit_path, "e2", category="device", ts=2000)
        audit_mod.append_event(audit_path, "e3", category="device", ts=3000)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit?category=device&after_ts=2000",
                        headers={"Cookie": ck})
        assert st == 200
        events = json.loads(b)["events"]
        evnames = {e["event"] for e in events}
        assert evnames == {"e2", "e3"}
    finally:
        stop()


def test_api_audit_after_ts_unparseable_ignored(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        audit_mod.append_event(audit_path, "e1", category="device", ts=1000)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit?category=device&after_ts=notanumber",
                        headers={"Cookie": ck})
        assert st == 200
        events = json.loads(b)["events"]
        assert any(e["event"] == "e1" for e in events)
    finally:
        stop()


def test_api_audit_cursor_keeps_timestamp_ties_and_detects_retention(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        for name in ("first", "second", "third"):
            audit_mod.append_event(audit_path, name, category="device", ts=1000)
        ck, _csrf = _auth(host, port)
        route = "/api/audit?limit=1&category=device&after_ts=900&before_ts=1100"
        def page(cursor=None):
            status, _, body = _req(host, port, "GET", route + (
                "&cursor=" + cursor if cursor is not None else ""), headers={"Cookie": ck})
            return status, json.loads(body)
        status, first = page()
        assert status == 200 and first["events"][0]["event"] == "third"
        audit_mod.append_event(audit_path, "newer", category="device", ts=1000)
        status, second = page(first["next_cursor"])
        assert status == 200 and second["events"][0]["event"] == "second"
        status, last = page(second["next_cursor"])
        assert status == 200 and last["events"][0]["event"] == "first"
        assert last["next_cursor"] is None
        assert page("malformed")[0] == 400
        assert page("")[0] == 400
        # Retention publishes a replacement file; a position in the old file
        # must never silently continue in the replacement, even if bytes match.
        replacement = tmp_path / "replacement.jsonl"
        replacement.write_bytes(Path(audit_path).read_bytes())
        replacement.replace(audit_path)
        status, expired = page(first["next_cursor"])
        assert status == 409
        assert "audit_cursor_expired" in json.dumps(expired)
        assert page()[0] == 200
    finally:
        stop()


# ---- audit histogram: /api/audit/histogram ----

def test_api_audit_histogram_requires_session(tmp_path):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/audit/histogram")[0] == 401
    finally:
        stop()


def test_api_audit_histogram_bad_category_400(tmp_path):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit/histogram?category=nonsense",
                        headers={"Cookie": ck})
        assert st == 400
        assert "error" in json.loads(b)
    finally:
        stop()


def test_api_audit_histogram_happy_path_shape(tmp_path, monkeypatch):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        monkeypatch.setattr(gui_server.time, "time", lambda: 10000.0)
        audit_mod.append_event(audit_path, "e1", category="device", ts=9000)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit/histogram?window=1000&buckets=10&category=device",
                        headers={"Cookie": ck})
        assert st == 200
        body = json.loads(b)
        assert body["now"] == 10000
        assert len(body["buckets"]) == 10
        assert sum(bk["count"] for bk in body["buckets"]) >= 1
        assert all(set(bk) == {"start", "count"} for bk in body["buckets"])
    finally:
        stop()


def test_api_audit_histogram_defaults(tmp_path, monkeypatch):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        monkeypatch.setattr(gui_server.time, "time", lambda: 50000.0)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/audit/histogram",
                        headers={"Cookie": ck})
        assert st == 200
        body = json.loads(b)
        assert len(body["buckets"]) == 30  # default buckets
        assert body["now"] == 50000
    finally:
        stop()


def test_api_audit_histogram_buckets_capped(tmp_path):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit/histogram?buckets=99999",
                        headers={"Cookie": ck})
        assert st == 200
        body = json.loads(b)
        assert len(body["buckets"]) == 200
    finally:
        stop()


def test_login_failure_and_success_emit_audit(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        st, _, _ = _req(host, port, "POST", "/api/login",
                        {"username": "admin", "password": "wrong"})
        assert st == 401
        st, _, _ = _req(host, port, "POST", "/api/login",
                        {"username": "admin", "password": "pw"})
        assert st == 200
        lines = _read_audit_lines(audit_path)
        auth_events = [e for e in lines if e.get("category") == "auth"]
        fail = [e for e in auth_events if e["result"] == "fail"]
        ok = [e for e in auth_events if e["result"] == "ok"
              and e.get("action") == "login"]
        assert fail and fail[0]["src_ip"] == "127.0.0.1"
        assert fail[0]["detail"] == "invalid credentials"
        assert ok and ok[0]["actor"] == "console:admin"
    finally:
        stop()


def test_device_assign_credential_and_request_report_emit_audit(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_id": "img1"}, headers=hh)
        assert st == 200
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/credential",
                        {"credential_profile_id": ""}, headers=hh)
        assert st == 200
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/request-report",
                        {}, headers=hh)
        assert st == 200
        lines = _read_audit_lines(audit_path)
        cats = [e.get("category") for e in lines]
        assert "device" in cats
        assert "telemetry" in cats
        assign_events = [e for e in lines if e.get("category") == "device"
                         and e.get("action") == "assign"]
        assert assign_events and assign_events[0]["target"] == "d1"
        # detail names the image, while the suffix pins authoritative ID sets.
        prefix, before, after, removed = _assignment_audit_parts(assign_events[0])
        assert prefix == "assigned img1.bin (3 B) id=img1"
        assert before == [] and after == ["img1"] and removed == []
        cred_events = [e for e in lines if e.get("action") == "credential"]
        assert cred_events[0]["detail"] == "profile (none) -> (cleared)"
        report_events = [e for e in lines if e.get("category") == "telemetry"]
        assert report_events[0]["detail"] == \
            "fresh telemetry report requested (valid 10m)"
    finally:
        stop()


def test_device_assign_detail_notes_previous_image(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        assert _req(host, port, "POST", "/api/devices/d1/assign",
                    {"image_id": "img1"}, headers=hh)[0] == 200
        assert _req(host, port, "POST", "/api/devices/d1/assign",
                    {"image_id": "img2"}, headers=hh)[0] == 200
        assigns = [e for e in _read_audit_lines(audit_path)
                   if e.get("action") == "assign"]
        prefix, before, after, removed = _assignment_audit_parts(assigns[-1])
        assert prefix == "assigned img2.bin (1.2 GiB) id=img2, was img1.bin"
        assert before == ["img1"] and after == ["img2"]
        assert removed == ["img1"]
    finally:
        stop()


def test_audit_emission_failure_does_not_break_route(tmp_path, monkeypatch):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        monkeypatch.setattr(audit_mod, "append_event",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("boom")))
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices",
                        {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        assert st == 200
    finally:
        stop()


# ---- audit histogram: explicit since_ts/until_ts window (timeline brush) ----

def test_api_audit_histogram_since_until_window(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        audit_mod.append_event(audit_path, "e1", category="device", ts=1000)
        audit_mod.append_event(audit_path, "e2", category="device", ts=2000)
        audit_mod.append_event(audit_path, "e3", category="device", ts=3000)
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/audit/histogram?since_ts=1500&until_ts=3500"
                        "&buckets=2&category=device",
                        headers={"Cookie": ck})
        assert st == 200
        body = json.loads(b)
        assert body["bucket_seconds"] == 1000.0
        assert [bk["start"] for bk in body["buckets"]] == [1500, 2500]
        assert [bk["count"] for bk in body["buckets"]] == [1, 1]  # e2, e3; not e1
    finally:
        stop()


def test_api_audit_histogram_until_not_after_since_400(tmp_path):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        for q in ("since_ts=100&until_ts=100", "since_ts=200&until_ts=100"):
            st, _, b = _req(host, port, "GET", "/api/audit/histogram?" + q,
                            headers={"Cookie": ck})
            assert st == 400
            assert "error" in json.loads(b)
    finally:
        stop()


def test_api_audit_histogram_single_bound_falls_back_to_window(tmp_path,
                                                               monkeypatch):
    """since_ts/until_ts only define the window when BOTH are present (and
    parseable); otherwise the window=<secs>-ending-now behavior applies."""
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        monkeypatch.setattr(gui_server.time, "time", lambda: 10000.0)
        audit_mod.append_event(audit_path, "old", category="device", ts=500)
        audit_mod.append_event(audit_path, "recent", category="device", ts=9500)
        ck, _csrf = _auth(host, port)
        for q in ("since_ts=1&", "until_ts=9600&", "since_ts=abc&until_ts=def&"):
            st, _, b = _req(host, port, "GET",
                            "/api/audit/histogram?%swindow=1000&buckets=10"
                            "&category=device" % q,
                            headers={"Cookie": ck})
            assert st == 200
            body = json.loads(b)
            assert body["bucket_seconds"] == 100.0
            assert body["buckets"][0]["start"] == 9000
            assert sum(bk["count"] for bk in body["buckets"]) == 1  # 'recent' only
    finally:
        stop()


def test_api_audit_histogram_default_window_bucket_seconds(tmp_path):
    host, port, _ctx, _audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/audit/histogram",
                        headers={"Cookie": ck})
        assert st == 200
        assert json.loads(b)["bucket_seconds"] == 604800 / 30
    finally:
        stop()


# ---- enriched emissions: operator-readable details (issue #19) ----

def test_fmt_bytes():
    f = gui_server._fmt_bytes
    assert f(3) == "3 B"
    assert f(12 * 1024) == "12 KiB"
    assert f(356515840) == "340 MiB"
    assert f(1288490188) == "1.2 GiB"
    assert f(None) == "?"          # audit details must never raise
    assert f("garbage") == "?"


def test_setup_emits_enriched_audit(tmp_path):
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)          # no admin yet -> needs_setup
    audit_path = str(tmp_path / "audit.jsonl")
    srv = gui_server.make_server("127.0.0.1", 0, app, audit_path=audit_path,
                                 certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        grant = _default_login_grant("127.0.0.1", port)
        st, _, _ = _req("127.0.0.1", port, "POST", "/api/setup",
                        {"username": "root", "password": "pw12345678",
                         "setup_grant": grant},
                        headers=_setup_headers("127.0.0.1", port))
        assert st == 200
        ev = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "setup"][0]
        assert ev["target"] == "root"
        assert ev["detail"] == "initial admin account created"
        assert ev["src_ip"] == "127.0.0.1"
        # The default-credential login that produced the grant is itself
        # audited as an ordinary successful login (category "auth")
        login_ev = [e for e in _read_audit_lines(audit_path)
                    if e.get("event") == "login"][0]
        assert login_ev["actor"] == (
            "console:" + gui_server.DEFAULT_SETUP_USER)
        assert login_ev["category"] == "auth" and login_ev["result"] == "ok"
    finally:
        srv.shutdown()


def test_setup_wrong_grant_is_audited(tmp_path):
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)          # no admin yet -> needs_setup
    audit_path = str(tmp_path / "audit.jsonl")
    srv = gui_server.make_server("127.0.0.1", 0, app, audit_path=audit_path,
                                 certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        st, _, _ = _req("127.0.0.1", port, "POST", "/api/setup",
                        {"username": "admin", "password": "password",
                         "setup_grant": "bogus"},
                        headers=_setup_headers("127.0.0.1", port))
        assert st == 403
        ev = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "setup_fail"][0]
        assert ev["category"] == "auth" and ev["result"] == "fail"
    finally:
        srv.shutdown()


def test_default_login_failure_is_audited_category_auth(tmp_path):
    """A failed default login is an ordinary audited authentication failure."""
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    audit_path = str(tmp_path / "audit.jsonl")
    srv = gui_server.make_server("127.0.0.1", 0, app, audit_path=audit_path,
                                 certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        st, _, _ = _req("127.0.0.1", port, "POST", "/api/login",
                        {"username": gui_server.DEFAULT_SETUP_USER,
                         "password": "wrong"})
        assert st == 401
        ev = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "login_fail"][0]
        assert ev["category"] == "auth" and ev["result"] == "fail"
    finally:
        srv.shutdown()


def test_auth_ops_emit_enriched_audit(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)     # session A
        _auth(host, port)                # session B (to be revoked)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/settings/password",
                        {"current": "wrong", "new": "newpass123",
                         "confirm": "newpass123"}, headers=hh)
        assert st == 400
        st, _, _ = _req(host, port, "POST", "/api/settings/password",
                        {"current": "pw", "new": "newpass123",
                         "confirm": "newpass123"}, headers=hh)
        assert st == 200
        st, _, _ = _req(host, port, "POST",
                        "/api/settings/sessions/revoke-others", {}, headers=hh)
        assert st == 200
        st, _, _ = _req(host, port, "POST", "/api/logout", {}, headers=hh)
        assert st == 200
        lines = _read_audit_lines(audit_path)
        by_event = {}
        for e in lines:
            by_event.setdefault(e["event"], e)
        assert by_event["password_change_fail"]["detail"] == \
            "current password incorrect"
        assert by_event["password_change_fail"]["src_ip"] == "127.0.0.1"
        assert by_event["password_change"]["detail"] == \
            "password changed; 1 other session(s) revoked"
        assert by_event["password_change"]["src_ip"] == "127.0.0.1"
        assert by_event["revoke_other_sessions"]["detail"] == \
            "revoked 0 other session(s)"
        assert by_event["logout"]["src_ip"] == "127.0.0.1"
    finally:
        stop()


def test_device_upsert_create_and_update_details(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1", "iris_vlan": "666",
              "model": "C9300"}, headers=hh)
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "model": "IE-3400"}, headers=hh)
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "model": "IE-3400"}, headers=hh)
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.9", "iris_vlan": "777",
              "svi_ip": "1.1.1.1", "app_ip": "2.2.2.2"}, headers=hh)
        ups = [e for e in _read_audit_lines(audit_path)
               if e.get("event") == "device_upsert"]
        assert [e["action"] for e in ups] == \
            ["create", "update", "update", "update"]
        assert ups[0]["detail"] == "ip 10.0.0.1, vlan 666, model C9300"
        assert ups[1]["detail"] == "changed model: C9300 -> IE-3400"
        assert ups[2]["detail"] == "no fields changed"
        # 4 changed fields -> first 3 alphabetically + a (+1 more) suffix
        assert ups[3]["detail"] == ("changed app_ip: (none) -> 2.2.2.2, "
                                    "device_ip: 10.0.0.1 -> 10.0.0.9, "
                                    "iris_vlan: 666 -> 777 (+1 more)")
    finally:
        stop()


def test_device_form_xr_host_body_creates_a_clean_record_with_honest_audit(tmp_path):
    """Wire-path coverage for the console's xr-host submit branch: POST the
    EXACT body app.js's devForm submit handler builds for xr-host --
    device_id, device_ip, management_type, model, platform,
    credential_profile_id, nothing else, no addressing keys at all --
    straight to the same /api/devices endpoint the form posts to. The
    device must come back as a clean xr-host/xr-appmgr record with none of
    the ten addressing fields, and the create audit line -- whose detail
    reports vlan by falling back through iris_vlan/inband_vlan/vlan --
    must show '-' honestly rather than fabricating one."""
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        body = {"device_id": "xr1", "device_ip": "10.0.0.9",
                "management_type": "xr-host", "model": "8201",
                "platform": "xr-appmgr", "credential_profile_id": ""}
        st, _, b = _req(host, port, "POST", "/api/devices", body, headers=hh)
        assert st == 200, b
        saved = json.loads(b)["device"]
        assert saved["management_type"] == "xr-host"
        assert saved["platform"] == "xr-appmgr"
        for key in ("iris_vlan", "svi_ip", "svi_mask", "app_ip", "app_mask",
                    "app_gateway", "vpg_number", "nat_interface", "inband_vlan"):
            assert not saved.get(key), "%s should be absent/empty, got %r" % (
                key, saved.get(key))
        ups = [e for e in _read_audit_lines(audit_path)
               if e.get("event") == "device_upsert"]
        assert ups and ups[-1]["action"] == "create"
        assert ups[-1]["detail"] == "ip 10.0.0.9, vlan -, model 8201"
    finally:
        stop()


def test_csv_import_route_stats_and_detail(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.9"}, headers=hh)
        csv_in = ("device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip\n"
                  "# comment\n"
                  "d1,10.0.0.1,666,10.0.0.2,255.255.255.252,10.0.0.3\n"
                  "d2,10.0.0.5,777,10.0.0.6,255.255.255.252,10.0.0.7\n")
        st, _, b = _req(host, port, "POST", "/api/devices/import-csv",
                        headers=dict(hh, **{"Content-Type": "text/csv"}),
                        raw=csv_in.encode())
        assert st == 200
        body = json.loads(b)
        assert body == {"imported": 2, "new": 1, "updated": 1, "skipped": 2,
                        "roles_cleared": 0}
        ev = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "device_csv_import"][0]
        assert ev["detail"] == \
            "imported 2 devices (1 new, 1 updated; 2 rows skipped)"
    finally:
        stop()


def test_device_delete_details_ok_and_fail(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        assert _req(host, port, "DELETE", "/api/devices/d1", headers=hh)[0] == 200
        assert _req(host, port, "DELETE", "/api/devices/d1", headers=hh)[0] == 200
        dels = [e for e in _read_audit_lines(audit_path)
                if e.get("event") == "device_delete"]
        assert dels[0]["result"] == "ok"
        # the record outcome is named too: it used to be the one thing delete
        # changed (or in this case did not change) without saying so
        assert dels[0]["detail"] == (
            "removed (ip 10.0.0.1, model -), endpoints retained, "
            "no deployment record")
        # deleting a device that never existed is a FAIL, not a phantom ok
        assert dels[1]["result"] == "fail"
        assert dels[1]["detail"] == "no such device"
    finally:
        stop()


def test_credential_profile_set_and_delete_details(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/credentials",
             {"id": "lab", "name": "Lab", "device_user": "admin",
              "device_pass": "supersecretpw"}, headers=hh)
        _req(host, port, "POST", "/api/credentials",
             {"id": "lab", "name": "Lab2", "device_user": "admin",
              "device_pass": "supersecretpw"}, headers=hh)
        assert _req(host, port, "DELETE", "/api/credentials/lab",
                    headers=hh)[0] == 200
        assert _req(host, port, "DELETE", "/api/credentials/lab",
                    headers=hh)[0] == 200
        lines = _read_audit_lines(audit_path)
        sets = [e for e in lines if e.get("event") == "credential_profile_set"]
        dels = [e for e in lines
                if e.get("event") == "credential_profile_delete"]
        assert [e["action"] for e in sets] == ["create", "update"]
        assert sets[0]["detail"] == "name 'Lab', device user admin"
        assert dels[0]["result"] == "ok"
        assert dels[0]["detail"] == "removed profile 'Lab2'"
        assert dels[1]["result"] == "fail"
        assert dels[1]["detail"] == "no such profile"
        assert "supersecretpw" not in open(audit_path).read()
    finally:
        stop()


def test_image_delete_details_and_blocked_emission(tmp_path):
    host, port, ctx, audit_path, stop = _serve_full_audit(tmp_path)
    _app, fleet, _creds, _cat = ctx
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1"}, headers=hh)
        assert _req(host, port, "POST", "/api/devices/d1/assign",
                    {"image_id": "img1"}, headers=hh)[0] == 200
        # blocked delete (409) must leave an audit trace, not stay silent
        assert _req(host, port, "DELETE", "/api/images/img1",
                    headers=hh)[0] == 409
        fleet.delete("d1")                 # stale policy no longer blocks
        assert _req(host, port, "DELETE", "/api/images/img1",
                    headers=hh)[0] == 200
        dels = [e for e in _read_audit_lines(audit_path)
                if e.get("event") == "image_delete"]
        assert dels[0]["result"] == "fail"
        assert dels[0]["detail"] == "blocked: assigned to 1 device(s): d1"
        assert dels[1]["result"] == "ok"
        assert dels[1]["detail"] == "deleted img1.bin (3 B)"
    finally:
        stop()


def test_image_upload_success_detail_names_publish_job(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf,
              "Content-Type": "application/octet-stream"}
        st, _, b = _req(host, port, "PUT", "/api/images/upload/new.bin",
                        headers=hh, raw=b"xyz")
        assert st == 200
        job_id = json.loads(b)["job_id"]
        ev = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "image_upload"][0]
        assert ev["target"] == "new.bin"
        assert ev["detail"] == "3 B uploaded, publish job %s started" % job_id
    finally:
        stop()


def test_image_upload_oversized_emits_fail_audit(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        s = _socket.create_connection((host, port), timeout=5)
        head = ("PUT /api/images/upload/huge.bin HTTP/1.0\r\nHost: x\r\n"
                "Cookie: %s\r\nX-CSRF-Token: %s\r\n"
                "Content-Length: 4294967297\r\n\r\n" % (ck, csrf)).encode()
        s.sendall(head)                    # declares >4 GiB; sends nothing
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        assert b" 413 " in resp.split(b"\r\n", 1)[0]
        ev = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "image_upload"][0]
        assert ev["result"] == "fail"
        assert ev["target"] == "huge.bin"
        assert ev["detail"] == "rejected: oversized (cap 4 GiB)"
    finally:
        stop()


def test_source_guard_monitoring_nav_and_view():
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert "['monitoring', 'Monitoring', 'pulse'" in _react_shell()
    assert 'id="view-monitoring"' in html
    assert "System" in _react_shell()
    component = _react_shell("monitoring.jsx")
    assert 'id="audit-load-older"' in component
    assert "Load older" in component
    assert 'id="audit-category"' in component

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "'monitoring'" in js
    assert "refreshMonitoring" in js
    assert "iris:monitoring-command" in js


# ---- stream tuning API + export-health proxy (device transfer telemetry) ----

def test_telemetry_stream_tune_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _cat, stop = _serve_reports(tmp_path)
    try:
        assert _req(host, port, "POST", "/api/telemetry/stream",
                    {"every": 4, "pause": True})[0] == 401
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/telemetry/stream",
                        {"every": 4, "pause": True}, headers=hh)
        assert st == 200 and json.loads(b)["ok"] is True
        with open(str(tmp_path / "state" / "telemetry-settings.json")) as f:
            assert json.load(f) == {"stream_every": 4, "stream_pause": True}
    finally:
        stop()


def test_telemetry_stream_tune_bad_values_400(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _cat, stop = _serve_reports(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        for body in ({"every": 0}, {"every": 61}, {"every": True},
                     {"every": "4"}, {"pause": "yes"}):
            st, _, _ = _req(host, port, "POST", "/api/telemetry/stream",
                            body, headers=hh)
            assert st == 400, body
    finally:
        stop()


def test_telemetry_health_proxy_fallback(tmp_path, monkeypatch):
    # point the proxy at a dead port: the endpoint still answers 200 with
    # ok:false so the console badge can render "unknown" rather than erroring
    monkeypatch.setenv("IRIS_METRICS_PORT", "9")
    host, port, _cat, stop = _serve_reports(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/telemetry/health")[0] == 401
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/telemetry/health",
                        headers={"Cookie": ck})
        assert st == 200
        assert json.loads(b)["ok"] is False
    finally:
        stop()


def test_map_cfg_line_escapes_script_terminator(monkeypatch):
    # An inline <script> block must never see a literal '</script>' from the
    # injected template value (operator-trusted env, sealed anyway).
    monkeypatch.setenv("IRIS_EVENTS_URL_TEMPLATE",
                       "https://x/e?ip={ip}</script><script>alert(1)</script>")
    line = gui_server._map_cfg_line()
    assert "</script>" not in line          # cannot break out of the block
    assert "\\u003c" in line                # '<' escaped


def test_device_view_exposes_telemetry_flags(tmp_path):
    """The devices table shows whether an agent is streaming live samples.
    Both flags come from the device's own heartbeat, so they reflect what is
    actually deployed — not what the console asked for at onboard time."""
    host, port, (_app, _fleet, _creds, cat), stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        for did in ("d-stream", "d-quiet", "d-old"):
            _req(host, port, "POST", "/api/devices",
                 {"device_id": did, "device_ip": "10.0.0.1"}, headers=hh)
        cat.record_heartbeat("d-stream", {"stage_state": "ready",
                                          "telemetry_enabled": True,
                                          "telemetry_stream_enabled": True})
        cat.record_heartbeat("d-quiet", {"stage_state": "ready",
                                         "telemetry_enabled": True,
                                         "telemetry_stream_enabled": False})
        cat.record_heartbeat("d-old", {"stage_state": "ready"})  # pre-feature agent
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        assert st == 200
        rows = {r["device_id"]: r for r in json.loads(b)["devices"]}
        assert rows["d-stream"]["telemetry_stream_enabled"] is True
        assert rows["d-quiet"]["telemetry_stream_enabled"] is False
        # unknown stays None (tri-state): a pre-feature agent is not "off"
        assert rows["d-old"]["telemetry_stream_enabled"] is None
        assert rows["d-stream"]["telemetry_enabled"] is True
    finally:
        stop()


# ---- gui-cert TLS resolution + hot reload (make_server) ----

import ssl


def _gen_cert_pair(tmp_path, cn, tag):
    """Self-signed cert+key PEM pair via the openssl CLI (guaranteed in the
    image; iris-bootstrap generates the builtin identity the same way)."""
    key = str(tmp_path / ("pair-%s-key.pem" % tag))
    crt = str(tmp_path / ("pair-%s-crt.pem" % tag))
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "2", "-keyout", key, "-out", crt, "-subj", "/CN=%s" % cn],
        check=True, capture_output=True)
    with open(crt) as f:
        cert_pem = f.read()
    with open(key) as f:
        key_pem = f.read()
    return cert_pem, key_pem


def test_gui_cert_resolution_order(tmp_path, monkeypatch):
    """Serve-time resolution: gui-cert override > IRIS_CERT combined file >
    None (plain-HTTP fallback). File EXISTENCE decides, not the env being
    set. Unit-level parallel of the subprocess fallback test
    test_module_run_as_script_actually_starts_the_server above."""
    gui = tmp_path / "gui-cert.pem"
    combined = tmp_path / "cert.pem"
    monkeypatch.setenv("IRIS_GUI_CERT", str(gui))
    monkeypatch.setenv("IRIS_CERT", str(combined))
    # neither file exists -> plain-HTTP fallback (unchanged behavior)
    assert gui_server._resolve_certfile() is None
    # only the shared combined file -> IRIS_CERT
    combined.write_text("x")
    assert gui_server._resolve_certfile() == str(combined)
    # both present -> the console-specific override wins
    gui.write_text("y")
    assert gui_server._resolve_certfile() == str(gui)
    # override removed -> back on IRIS_CERT (the revert path)
    os.unlink(str(gui))
    assert gui_server._resolve_certfile() == str(combined)


def _serve_tls(tmp_path, certfile):
    """Start gui_server over TLS on an ephemeral port. Returns
    (host, port, srv, stop_fn) -- srv is exposed so tests can call
    srv.reload_tls() directly (the endpoints call the same closure)."""
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=certfile)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, srv, srv.shutdown


def _peer_cert_der(host, port):
    """Fresh TLS handshake; returns the server certificate in DER.
    binary_form=True works without validation (the dict form would be
    empty under CERT_NONE)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True)


def _first_cert_der(pem_text):
    """DER of the first CERTIFICATE block (combined files carry cert+key)."""
    m = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                  pem_text, re.S)
    return ssl.PEM_cert_to_DER_cert(m.group(0))


def test_reload_tls_false_on_plain_http_server(tmp_path, monkeypatch):
    """Every pytest _serve* server runs certfile=None; reload_tls() must be
    a safe no-op there, EVEN when a valid override file exists on disk
    (upload-while-plain-HTTP: the persisted config takes effect at next
    restart -- the message the gui-cert endpoint surfaces)."""
    cert_pem, key_pem = _gen_cert_pair(tmp_path, "would-be-served", "plain")
    gui = tmp_path / "gui-cert.pem"
    gui.write_text(cert_pem + key_pem)
    monkeypatch.setenv("IRIS_GUI_CERT", str(gui))
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None)
    try:
        assert srv.reload_tls() is False
    finally:
        srv.server_close()


def test_reload_tls_serves_new_cert_and_reverts(tmp_path, monkeypatch):
    """Handshake before/after: replacing the gui-cert file + reload_tls()
    serves the NEW certificate to fresh handshakes; removing the file +
    reload_tls() lands back on IRIS_CERT (revert path)."""
    bi_cert, bi_key = _gen_cert_pair(tmp_path, "iris-builtin", "builtin")
    cu_cert, cu_key = _gen_cert_pair(tmp_path, "iris-custom", "custom")
    builtin = tmp_path / "cert.pem"
    builtin.write_text(bi_cert + bi_key)
    gui = tmp_path / "gui-cert.pem"          # absent for now
    monkeypatch.setenv("IRIS_CERT", str(builtin))
    monkeypatch.setenv("IRIS_GUI_CERT", str(gui))
    host, port, srv, stop = _serve_tls(tmp_path, str(builtin))
    try:
        assert srv.tls_active is True
        assert _peer_cert_der(host, port) == _first_cert_der(bi_cert)
        # the upload flow drops the combined override, then hot-reloads
        gui.write_text(cu_cert + cu_key)
        assert srv.reload_tls() is True
        assert _peer_cert_der(host, port) == _first_cert_der(cu_cert)
        # revert: override removed -> reload resolves back to IRIS_CERT
        os.unlink(str(gui))
        assert srv.reload_tls() is True
        assert _peer_cert_der(host, port) == _first_cert_der(bi_cert)
    finally:
        stop()


def test_reload_tls_corrupt_file_keeps_old_cert(tmp_path, monkeypatch):
    """A corrupt combined file must not crash serving and must not leave the
    live context half-swapped: reload_tls() returns False and fresh
    handshakes still get the OLD certificate (throwaway-context probe runs
    before the live load)."""
    bi_cert, bi_key = _gen_cert_pair(tmp_path, "iris-builtin", "corrupt-bi")
    builtin = tmp_path / "cert.pem"
    builtin.write_text(bi_cert + bi_key)
    gui = tmp_path / "gui-cert.pem"
    monkeypatch.setenv("IRIS_CERT", str(builtin))
    monkeypatch.setenv("IRIS_GUI_CERT", str(gui))
    host, port, srv, stop = _serve_tls(tmp_path, str(builtin))
    try:
        gui.write_text("-----BEGIN CERTIFICATE-----\nnot a cert\n"
                       "-----END CERTIFICATE-----\n")
        assert srv.reload_tls() is False
        assert _peer_cert_der(host, port) == _first_cert_der(bi_cert)
    finally:
        stop()


def test_make_server_falls_back_to_iris_cert_when_gui_cert_is_corrupt(
        tmp_path, monkeypatch):
    """Startup crash-window guard (Task 6 review finding): a durable
    mismatched cert/key pair can land in the gui-cert override file (e.g. a
    crash between writing the cert and the key). _resolve_certfile() picks
    it on existence alone, so make_server must not crash trying to load it
    -- it probes with a throwaway context first, and on failure falls back
    to the next candidate (IRIS_CERT) rather than taking the console down."""
    bi_cert, bi_key = _gen_cert_pair(tmp_path, "iris-builtin", "startup-fb-bi")
    builtin = tmp_path / "cert.pem"
    builtin.write_text(bi_cert + bi_key)
    gui = tmp_path / "gui-cert.pem"
    gui.write_text("-----BEGIN CERTIFICATE-----\nnot a cert\n"
                   "-----END CERTIFICATE-----\n")
    monkeypatch.setenv("IRIS_CERT", str(builtin))
    monkeypatch.setenv("IRIS_GUI_CERT", str(gui))
    certfile = gui_server._resolve_certfile()  # picks the corrupt override
    assert certfile == str(gui)
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=certfile)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert _peer_cert_der("127.0.0.1", port) == _first_cert_der(bi_cert)
    finally:
        srv.shutdown()


def test_make_server_refuses_plaintext_when_all_candidates_corrupt(
        tmp_path, monkeypatch):
    """Rewritten (IRIS-06-003 / IRIS-01-004): both the gui-cert override and
    IRIS_CERT are unusable at startup. The old contract silently served
    plain HTTP -- accepting the admin password in cleartext and then unable
    to keep a session in any remote browser (Secure cookie over http://).
    Now make_server fails CLOSED with ConsoleTLSError unless
    IRIS_GUI_ALLOW_PLAINTEXT=1 opts in explicitly; with the opt-in it serves
    plain HTTP as before (no tls context, reload_tls a safe no-op)."""
    builtin = tmp_path / "cert.pem"
    builtin.write_text("-----BEGIN CERTIFICATE-----\nnot a cert\n"
                       "-----END CERTIFICATE-----\n")
    gui = tmp_path / "gui-cert.pem"
    gui.write_text("-----BEGIN CERTIFICATE-----\nalso not a cert\n"
                   "-----END CERTIFICATE-----\n")
    monkeypatch.setenv("IRIS_CERT", str(builtin))
    monkeypatch.setenv("IRIS_GUI_CERT", str(gui))
    monkeypatch.delenv("IRIS_GUI_ALLOW_PLAINTEXT", raising=False)
    certfile = gui_server._resolve_certfile()  # picks the corrupt override
    assert certfile == str(gui)
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    with pytest.raises(gui_server.ConsoleTLSError) as ei:
        gui_server.make_server("127.0.0.1", 0, app, certfile=certfile)
    assert "IRIS_GUI_ALLOW_PLAINTEXT=1" in str(ei.value)
    monkeypatch.setenv("IRIS_GUI_ALLOW_PLAINTEXT", "1")
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=certfile)
    try:
        assert srv.reload_tls() is False  # no live TLS context to hot-swap
        assert srv.tls_active is False
        assert not isinstance(srv.socket, ssl.SSLSocket)
    finally:
        srv.server_close()


def test_make_server_serves_gui_cert_when_both_candidates_valid(
        tmp_path, monkeypatch):
    """When both gui-cert and IRIS_CERT files exist and are valid, make_server
    serves the gui-cert (first candidate in the probe loop), not the IRIS_CERT.
    Handshake DER proves the correct cert was loaded."""
    bi_cert, bi_key = _gen_cert_pair(tmp_path, "iris-builtin", "both-valid-bi")
    gu_cert, gu_key = _gen_cert_pair(tmp_path, "iris-guicert", "both-valid-gu")
    builtin = tmp_path / "cert.pem"
    builtin.write_text(bi_cert + bi_key)
    gui = tmp_path / "gui-cert.pem"
    gui.write_text(gu_cert + gu_key)
    monkeypatch.setenv("IRIS_CERT", str(builtin))
    monkeypatch.setenv("IRIS_GUI_CERT", str(gui))
    certfile = gui_server._resolve_certfile()  # picks gui-cert on existence
    assert certfile == str(gui)
    host, port, srv, stop = _serve_tls(tmp_path, certfile)
    try:
        assert srv.tls_active is True
        # Handshake proves we got the GUI cert, not the builtin IRIS_CERT
        assert _peer_cert_der(host, port) == _first_cert_der(gu_cert)
    finally:
        stop()


# ---- console TLS cert replacement + root-CA trust store (Settings API) ----

def _gui_cert_env(tmp_path, monkeypatch):
    """Point every gui_tls path at tmp_path: durable override files under
    $IRIS_CONFIG/tls, runtime combined file at $IRIS_GUI_CERT, and no age
    recipients (plaintext degradation, the secretfs no-recipients test mode)."""
    cfg = tmp_path / "config" / "tls"
    run = tmp_path / "run" / "tls"
    cfg.mkdir(parents=True)
    run.mkdir(parents=True)
    monkeypatch.setenv("IRIS_CONFIG", str(tmp_path / "config"))
    monkeypatch.setenv("IRIS_GUI_CERT", str(run / "gui-cert.pem"))
    monkeypatch.delenv("IRIS_AGE_RECIPIENTS", raising=False)
    return run


def test_settings_gui_cert_roundtrip(tmp_path, monkeypatch):
    run = _gui_cert_env(tmp_path, monkeypatch)
    # a distinct "built-in" combined cert so the revert path is observable
    bi_cert, bi_key = _gen_cert_pair(tmp_path, "iris-builtin", "builtin")
    builtin = run / "cert.pem"
    builtin.write_text(bi_cert + bi_key)
    monkeypatch.setenv("IRIS_CERT", str(builtin))
    cert_pem, key_pem = _gen_cert_pair(tmp_path, "iris-custom", "custom")

    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        # auth: no session -> 401; session without CSRF -> 403
        assert _req(host, port, "POST", "/api/settings/gui-cert",
                    {"cert_pem": cert_pem, "key_pem": key_pem})[0] == 401
        ck, csrf = _auth(host, port)
        assert _req(host, port, "POST", "/api/settings/gui-cert",
                    {"cert_pem": cert_pem, "key_pem": key_pem},
                    headers={"Cookie": ck})[0] == 403
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # per-field validation -> 400
        assert _req(host, port, "POST", "/api/settings/gui-cert",
                    {"key_pem": key_pem}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/gui-cert",
                    {"cert_pem": cert_pem}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/gui-cert",
                    {"cert_pem": "", "key_pem": key_pem}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/gui-cert",
                    {"cert_pem": 42, "key_pem": key_pem}, headers=hh)[0] == 400
        # before any upload the settings view shows the built-in cert
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        assert st == 200
        assert json.loads(b)["gui_cert"]["source"] == "built-in"
        # replace
        st, _, b = _req(host, port, "POST", "/api/settings/gui-cert",
                        {"cert_pem": cert_pem, "key_pem": key_pem}, headers=hh)
        assert st == 200
        gc = json.loads(b)["gui_cert"]
        assert gc["source"] == "custom"
        # this fixture serves plain HTTP: the answer must say the file was
        # saved but NOT applied (takes effect at restart), not imply it is live
        assert json.loads(b)["applied"] is False
        assert "next restart" in json.loads(b)["note"]
        assert "iris-custom" in gc["subject"]
        assert gc["fingerprint_sha256"] not in ("", "unknown")
        # GET reflects it — and NEVER echoes key material
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        got = json.loads(b)["gui_cert"]
        assert got["source"] == "custom" and "iris-custom" in got["subject"]
        assert b"PRIVATE KEY" not in b
        # audit: the replace row carries subject+fingerprint, never the key
        rows = [e for e in _read_audit_lines(audit_path)
                if e.get("event") == "gui-cert-replace"]
        assert rows and rows[-1]["result"] == "ok"
        assert rows[-1]["category"] == "settings"
        assert rows[-1]["target"] == "gui-cert"
        assert gc["fingerprint_sha256"] in rows[-1]["detail"]
        assert "PRIVATE KEY" not in open(audit_path).read()
        # revert
        st, _, b = _req(host, port, "DELETE", "/api/settings/gui-cert",
                        headers=hh)
        assert st == 200 and json.loads(b)["deleted"] is True
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        got = json.loads(b)["gui_cert"]
        assert got["source"] == "built-in" and "iris-builtin" in got["subject"]
        rows = [e for e in _read_audit_lines(audit_path)
                if e.get("event") == "gui-cert-revert"]
        assert rows and rows[-1]["result"] == "ok"
        # a second revert still answers 200 (idempotent), deleted False
        st, _, b = _req(host, port, "DELETE", "/api/settings/gui-cert",
                        headers=hh)
        assert st == 200 and json.loads(b)["deleted"] is False
    finally:
        stop()


def test_settings_gui_cert_rejects_bad_pairs(tmp_path, monkeypatch):
    _gui_cert_env(tmp_path, monkeypatch)
    cert_a, _key_a = _gen_cert_pair(tmp_path, "pair-a", "a")
    _cert_b, key_b = _gen_cert_pair(tmp_path, "pair-b", "b")
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # key does not match the cert
        st, _, b = _req(host, port, "POST", "/api/settings/gui-cert",
                        {"cert_pem": cert_a, "key_pem": key_b}, headers=hh)
        assert st == 400 and json.loads(b)["error"]
        # garbage PEM
        st, _, _ = _req(host, port, "POST", "/api/settings/gui-cert",
                        {"cert_pem": "hello", "key_pem": key_b}, headers=hh)
        assert st == 400
        # both rejections audited as failures; no key material in the file;
        # no override was persisted
        rows = [e for e in _read_audit_lines(audit_path)
                if e.get("event") == "gui-cert-replace"]
        assert len(rows) == 2 and all(e["result"] == "fail" for e in rows)
        assert "PRIVATE KEY" not in open(audit_path).read()
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        assert json.loads(b)["gui_cert"]["source"] != "custom"
    finally:
        stop()


def test_settings_gui_cert_persist_failure_audited(tmp_path, monkeypatch):
    """When gui_tls.persist_override raises (e.g. age subprocess fails or
    disk-full OSError), the POST route must audit the failure, respond 500
    with a static error message, and never expose key material."""
    import subprocess
    import gui_tls
    _gui_cert_env(tmp_path, monkeypatch)
    cert_pem, key_pem = _gen_cert_pair(tmp_path, "iris-custom", "custom")
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # Monkeypatch persist_override to raise CalledProcessError (simulating
        # age subprocess failure or similar).
        orig_persist = gui_tls.persist_override
        def failing_persist(c, k):
            raise subprocess.CalledProcessError(1, ["age"])
        monkeypatch.setattr(gui_tls, "persist_override", failing_persist)
        # POST a valid cert/key pair: should return 500
        st, _, b = _req(host, port, "POST", "/api/settings/gui-cert",
                        {"cert_pem": cert_pem, "key_pem": key_pem}, headers=hh)
        assert st == 500, "expected 500 on persist_override failure, got %d" % st
        resp = json.loads(b)
        assert resp["code"] == "internal-error"
        assert resp["error"] == "internal server error"
        assert b"PRIVATE KEY" not in b, "key material leaked in error response"
        # Audit log must contain a fail row with CalledProcessError in detail,
        # but NO key material.
        rows = [e for e in _read_audit_lines(audit_path)
                if e.get("event") == "gui-cert-replace"]
        fail_rows = [e for e in rows if e.get("result") == "fail"]
        assert fail_rows, "no fail audit row for persist_override exception"
        assert "CalledProcessError" in fail_rows[-1]["detail"]
        assert "PRIVATE KEY" not in open(audit_path).read()
        assert key_pem not in open(audit_path).read(), \
            "key material must never appear in audit log"
    finally:
        stop()


def test_gui_cert_upload_encrypted_key_with_passphrase(tmp_path, monkeypatch):
    """A passphrase-protected key uploads successfully when key_passphrase is
    supplied (decrypted at import, stored age-encrypted like any key); a
    wrong passphrase and a missing passphrase both fail with messages that
    say 'passphrase' and never echo PEM or the passphrase itself."""
    _gui_cert_env(tmp_path, monkeypatch)
    cert_pem, key_pem = _gen_cert_pair(tmp_path, "iris-encpass", "encpass")
    src = tmp_path / "clear.pem"; dst = tmp_path / "enc.pem"
    src.write_text(key_pem)
    subprocess.run(["openssl", "pkey", "-in", str(src), "-aes-256-cbc",
                    "-passout", "pass:s3same!", "-out", str(dst)],
                   check=True, capture_output=True)
    enc_key = dst.read_text()
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # no passphrase -> 400 naming the problem
        st, _, b = _req(host, port, "POST", "/api/settings/gui-cert",
                        {"cert_pem": cert_pem, "key_pem": enc_key}, headers=hh)
        assert st == 400 and b"passphrase" in b
        # wrong passphrase -> 400, safe message
        st, _, b = _req(host, port, "POST", "/api/settings/gui-cert",
                        {"cert_pem": cert_pem, "key_pem": enc_key,
                         "key_passphrase": "nope"}, headers=hh)
        assert st == 400 and b"passphrase" in b and b"BEGIN" not in b
        # right passphrase -> accepted
        st, _, _ = _req(host, port, "POST", "/api/settings/gui-cert",
                        {"cert_pem": cert_pem, "key_pem": enc_key,
                         "key_passphrase": "s3same!"}, headers=hh)
        assert st == 200
        # neither the passphrase nor key material may reach the audit log
        audit = open(audit_path).read()
        assert "s3same!" not in audit and "PRIVATE KEY" not in audit
    finally:
        stop()


# ---- trust-store add/remove + settings listing ----

def _trust_env(tmp_path, monkeypatch):
    """Point the trust store at tmp_path: durable PEMs in $IRIS_TRUST_DIR,
    runtime concat bundle at $IRIS_CA_BUNDLE."""
    trust_dir = tmp_path / "trust"
    run = tmp_path / "trun"
    run.mkdir()
    monkeypatch.setenv("IRIS_TRUST_DIR", str(trust_dir))
    monkeypatch.setenv("IRIS_CA_BUNDLE", str(run / "ca-bundle.pem"))
    return trust_dir, run / "ca-bundle.pem"


def test_settings_trust_roundtrip(tmp_path, monkeypatch):
    trust_dir, bundle = _trust_env(tmp_path, monkeypatch)
    ca_pem, _key = _gen_cert_pair(tmp_path, "corp-root-ca", "ca")
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        # auth: no session -> 401; session without CSRF -> 403
        assert _req(host, port, "POST", "/api/settings/trust",
                    {"pem": ca_pem})[0] == 401
        ck, csrf = _auth(host, port)
        assert _req(host, port, "POST", "/api/settings/trust",
                    {"pem": ca_pem}, headers={"Cookie": ck})[0] == 403
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # validation -> 400: missing / empty / non-string / no PEM blocks
        assert _req(host, port, "POST", "/api/settings/trust",
                    {}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/trust",
                    {"pem": ""}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/trust",
                    {"pem": 42}, headers=hh)[0] == 400
        st, _, _ = _req(host, port, "POST", "/api/settings/trust",
                        {"pem": "this is not a certificate"}, headers=hh)
        assert st == 400
        fails = [e for e in _read_audit_lines(audit_path)
                 if e.get("event") == "trust-add"]
        assert fails and fails[-1]["result"] == "fail"
        # install
        st, _, b = _req(host, port, "POST", "/api/settings/trust",
                        {"pem": ca_pem}, headers=hh)
        assert st == 200
        entry = json.loads(b)["entry"]
        assert re.fullmatch(r"[0-9a-f]{64}\.pem", entry["name"])
        assert entry["source"] == "manual" and entry["cert_count"] == 1
        assert "corp-root-ca" in entry["subject"]
        # GET reflects the store; the runtime bundle was rebuilt
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        listed = json.loads(b)["trust"]
        assert [e["name"] for e in listed] == [entry["name"]]
        assert "BEGIN CERTIFICATE" in bundle.read_text()
        ok_rows = [e for e in _read_audit_lines(audit_path)
                   if e.get("event") == "trust-add" and e["result"] == "ok"]
        assert ok_rows and ok_rows[-1]["target"] == entry["name"]
        assert ok_rows[-1]["category"] == "settings"
        # remove: unknown name answers 200/deleted:false with a fail audit row
        st, _, b = _req(host, port, "DELETE",
                        "/api/settings/trust/" + "0" * 64 + ".pem", headers=hh)
        assert st == 200 and json.loads(b)["deleted"] is False
        # remove the real entry: store empties, bundle disappears
        st, _, b = _req(host, port, "DELETE",
                        "/api/settings/trust/" + entry["name"], headers=hh)
        assert st == 200 and json.loads(b)["deleted"] is True
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        assert json.loads(b)["trust"] == []
        assert not bundle.exists()
        rm = [e for e in _read_audit_lines(audit_path)
              if e.get("event") == "trust-remove"]
        assert [e["result"] for e in rm] == ["fail", "ok"]
    finally:
        stop()


def test_settings_trust_delete_rejects_traversal(tmp_path, monkeypatch):
    trust_dir, _bundle = _trust_env(tmp_path, monkeypatch)
    ca_pem, _key = _gen_cert_pair(tmp_path, "keep-me", "keep")
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/settings/trust",
                        {"pem": ca_pem}, headers=hh)
        assert st == 200
        name = json.loads(b)["entry"]["name"]
        # every traversal shape -> 400, before any store access
        for bad in ("..%2F..%2Fsecrets.json",   # ../../secrets.json
                    "..", ".",
                    "..%5C..%5Csecrets.json",   # ..\..\secrets.json
                    "%2e%2e%2fx.pem"):          # ../x.pem
            st, _, _ = _req(host, port, "DELETE",
                            "/api/settings/trust/" + bad, headers=hh)
            assert st == 400, bad
        # nothing was deleted, nothing was audited as a remove
        assert (trust_dir / name).is_file()
        assert not [e for e in _read_audit_lines(audit_path)
                    if e.get("event") == "trust-remove"]
    finally:
        stop()


def test_settings_trust_add_includes_fingerprint_in_audit(tmp_path, monkeypatch):
    """Verify that trust-add success audit detail includes fingerprint_sha256."""
    trust_dir, bundle = _trust_env(tmp_path, monkeypatch)
    ca_pem, _key = _gen_cert_pair(tmp_path, "corp-root-ca", "ca")
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/settings/trust",
                        {"pem": ca_pem}, headers=hh)
        assert st == 200
        entry = json.loads(b)["entry"]
        # verify audit detail includes fingerprint alongside name/count/subject
        ok_rows = [e for e in _read_audit_lines(audit_path)
                   if e.get("event") == "trust-add" and e["result"] == "ok"]
        assert ok_rows, "no success audit row found"
        detail = ok_rows[-1]["detail"]
        assert "fingerprint" in detail, "fingerprint not in detail: %s" % detail
        assert entry["fingerprint_sha256"] in detail, \
            "fingerprint_sha256 value not in detail: %s" % detail
    finally:
        stop()


def test_settings_trust_add_audits_os_error(tmp_path, monkeypatch):
    """Verify that OSError from trust.add_pem is caught and audited correctly."""
    trust_dir, bundle = _trust_env(tmp_path, monkeypatch)
    ca_pem, _key = _gen_cert_pair(tmp_path, "corp-root-ca", "ca")
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # monkeypatch trust.add_pem to raise OSError
        import trust as trust_mod
        orig_add_pem = trust_mod.add_pem
        def mock_add_pem(pem):
            raise OSError("disk full")
        monkeypatch.setattr(trust_mod, "add_pem", mock_add_pem)
        # send valid PEM; should get 500 with static error body
        st, _, b = _req(host, port, "POST", "/api/settings/trust",
                        {"pem": ca_pem}, headers=hh)
        assert st == 500
        resp = json.loads(b)
        assert resp["code"] == "internal-error"
        assert resp["error"] == "internal server error"
        # verify audit contains class name only, not "disk full" or PEM text
        fail_rows = [e for e in _read_audit_lines(audit_path)
                     if e.get("event") == "trust-add" and e["result"] == "fail"]
        assert fail_rows, "no fail audit row found"
        detail = fail_rows[-1]["detail"]
        assert "OSError" in detail, "OSError class name not in detail: %s" % detail
        assert "disk full" not in detail, "error message leaked to detail: %s" % detail
        assert "BEGIN CERTIFICATE" not in detail, "PEM text leaked to detail"
    finally:
        stop()


def test_settings_trust_delete_rejects_null_and_no_suffix(tmp_path, monkeypatch):
    """Verify DELETE /api/settings/trust/<name> rejects names with null bytes
    and names without .pem suffix."""
    trust_dir, _bundle = _trust_env(tmp_path, monkeypatch)
    ca_pem, _key = _gen_cert_pair(tmp_path, "keep-me", "keep")
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/settings/trust",
                        {"pem": ca_pem}, headers=hh)
        assert st == 200
        name = json.loads(b)["entry"]["name"]
        # test null-byte-encoded and no-suffix names -> 400, no audit
        for bad in ("%00name.pem",  # null byte encoded
                    "somename"):     # no .pem suffix
            st, _, _ = _req(host, port, "DELETE",
                            "/api/settings/trust/" + bad, headers=hh)
            assert st == 400, bad
        # nothing was deleted, nothing was audited as a remove
        assert (trust_dir / name).is_file()
        assert not [e for e in _read_audit_lines(audit_path)
                    if e.get("event") == "trust-remove"]
    finally:
        stop()


# ---- CA-trust settings + refresh job + daily thread (server TLS trust) ----

import trust as trust_mod

# Built-in default CA-bundle source (spec update after the brief was
# drafted): a missing/null/blank configured url falls back to this so
# "Download now" (and auto-refresh, once enabled) work with zero
# configuration. Pinned as a literal here so a change to the constant in
# gui_server.py is caught by test failures, not silently drifts.
_CA_DEFAULT_URL = "https://www.cisco.com/security/pki/trs/ios.p7b"


def test_ca_trust_default_url_is_prefilled(tmp_path, monkeypatch):
    """Spec update: nothing configured -> the reader AND the console's
    settings view both surface the built-in Cisco CA-bundle URL, not None,
    so the UI shows it prefilled and 'Download now' works out of the box."""
    assert gui_server._CA_TRUST_DEFAULT_URL == _CA_DEFAULT_URL
    assert "export const CISCO_CA = '" + _CA_DEFAULT_URL + "';" in _react_shell("settings-model.mjs")
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    p = str(tmp_path / "state" / "ca-trust-settings.json")
    assert gui_server.read_ca_trust_settings(p) == {
        "url": _CA_DEFAULT_URL, "auto": False}
    host, port, _deps, stop = _serve_full(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        assert st == 200
        assert json.loads(b)["ca_trust"] == {
            "url": _CA_DEFAULT_URL, "auto": False}
    finally:
        stop()


def test_settings_ca_trust_roundtrip_and_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _deps, stop = _serve_full(tmp_path)
    try:
        # auth: no session -> 401; session without CSRF -> 403
        assert _req(host, port, "POST", "/api/settings/ca-trust",
                    {"url": "https://ca.example/bundle.pem",
                     "auto": True})[0] == 401
        ck, csrf = _auth(host, port)
        assert _req(host, port, "POST", "/api/settings/ca-trust",
                    {"url": "https://ca.example/bundle.pem", "auto": True},
                    headers={"Cookie": ck})[0] == 403
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # defaults before any write: the built-in URL, auto off
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        assert st == 200
        assert json.loads(b)["ca_trust"] == {
            "url": _CA_DEFAULT_URL, "auto": False}
        # validation: https only, host required, auto must be a real bool
        for bad in ({"url": "http://ca.example/b.pem", "auto": True},
                    {"url": "ftp://ca.example/b.pem", "auto": True},
                    {"url": "https://", "auto": True},
                    {"url": "ca.example/b.pem", "auto": True},
                    {"url": 42, "auto": True},
                    {"url": "https://ca.example/b.pem", "auto": "yes"},
                    {"url": "https://ca.example/b.pem", "auto": 1}):
            st, _, _ = _req(host, port, "POST", "/api/settings/ca-trust",
                            bad, headers=hh)
            assert st == 400, bad
        hh_json = dict(hh); hh_json["Content-Type"] = "application/json"
        assert _req(host, port, "POST", "/api/settings/ca-trust",
                    raw=b"[]", headers=hh_json)[0] == 400
        # save, then the settings view reflects it
        st, _, b = _req(host, port, "POST", "/api/settings/ca-trust",
                        {"url": "https://ca.example/bundle.pem", "auto": True},
                        headers=hh)
        assert st == 200
        assert json.loads(b)["ca_trust"] == {
            "url": "https://ca.example/bundle.pem", "auto": True}
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        assert json.loads(b)["ca_trust"] == {
            "url": "https://ca.example/bundle.pem", "auto": True}
        # the settings file is atomic JSON under IRIS_STATE
        with open(str(tmp_path / "state" / "ca-trust-settings.json")) as f:
            assert json.load(f) == {"url": "https://ca.example/bundle.pem",
                                    "auto": True}
        # null url clears it (unset is first-class on disk: {"url": null});
        # but a cleared url is not "no source" -- it falls back to the
        # built-in default, both in the save response and on GET
        st, _, b = _req(host, port, "POST", "/api/settings/ca-trust",
                        {"url": None, "auto": False}, headers=hh)
        assert st == 200
        assert json.loads(b)["ca_trust"] == {
            "url": _CA_DEFAULT_URL, "auto": False}
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        assert json.loads(b)["ca_trust"] == {
            "url": _CA_DEFAULT_URL, "auto": False}
        with open(str(tmp_path / "state" / "ca-trust-settings.json")) as f:
            assert json.load(f) == {"url": None, "auto": False}
    finally:
        stop()


def test_ca_trust_settings_reader_tolerant(tmp_path):
    p = str(tmp_path / "ca-trust-settings.json")
    # missing file -> the built-in default url, auto off
    assert gui_server.read_ca_trust_settings(p) == {
        "url": _CA_DEFAULT_URL, "auto": False}
    # garbage -> same defaults (a settings reader never raises)
    with open(p, "w") as f:
        f.write("{not json")
    assert gui_server.read_ca_trust_settings(p) == {
        "url": _CA_DEFAULT_URL, "auto": False}
    # wrong types -> same defaults
    with open(p, "w") as f:
        json.dump({"url": 42, "auto": "yes"}, f)
    assert gui_server.read_ca_trust_settings(p) == {
        "url": _CA_DEFAULT_URL, "auto": False}
    # roundtrip through the atomic writer: an explicit url is returned as-is
    gui_server.write_ca_trust_settings(p, "https://ca.example/b.pem", True)
    assert gui_server.read_ca_trust_settings(p) == {
        "url": "https://ca.example/b.pem", "auto": True}
    # writing an explicit null (first-class "unset") falls back to the
    # default url again; auto is independent and is preserved as written
    gui_server.write_ca_trust_settings(p, None, True)
    assert gui_server.read_ca_trust_settings(p) == {
        "url": _CA_DEFAULT_URL, "auto": True}


def test_settings_ca_trust_config_audited(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # Fresh state → POST url: audit shows "(none)" -> url, not default
        assert _req(host, port, "POST", "/api/settings/ca-trust",
                    {"url": "https://ca.example/bundle.pem", "auto": True},
                    headers=hh)[0] == 200
        evs = [e for e in _read_audit_lines(audit_path)
               if e["event"] == "ca-trust-config"]
        assert len(evs) == 1
        ev = evs[0]
        assert ev["category"] == "settings" and ev["result"] == "ok"
        assert ev["actor"] == "console:admin" and ev["target"] == "ca-trust"
        # Audit logs the raw stored value, not the resolved default:
        # never-configured renders as "(none)"
        assert "url (none) -> https://ca.example" in ev["detail"]
        assert "auto False -> True" in ev["detail"]
        # POST different url: detail contains first url as before-value
        assert _req(host, port, "POST", "/api/settings/ca-trust",
                    {"url": "https://ca.other/bundle.pem", "auto": True},
                    headers=hh)[0] == 200
        evs = [e for e in _read_audit_lines(audit_path)
               if e["event"] == "ca-trust-config"]
        assert len(evs) == 2
        ev = evs[1]
        assert "url https://ca.example -> https://ca.other" in ev["detail"]
        # Clearing (url null) → after-side "(none)"
        assert _req(host, port, "POST", "/api/settings/ca-trust",
                    {"url": None, "auto": False},
                    headers=hh)[0] == 200
        evs = [e for e in _read_audit_lines(audit_path)
               if e["event"] == "ca-trust-config"]
        assert len(evs) == 3
        ev = evs[2]
        assert "url https://ca.other -> (none)" in ev["detail"]
    finally:
        stop()


def test_settings_ca_trust_persist_failure_audited(tmp_path, monkeypatch):
    """When write_ca_trust_settings raises (e.g. disk-full OSError), the
    POST route must audit the failure and respond 500 with a static error
    message rather than dropping the connection."""
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}

        def failing_write(path, url, auto):
            raise OSError("disk full")
        monkeypatch.setattr(gui_server, "write_ca_trust_settings",
                            failing_write)
        st, _, b = _req(host, port, "POST", "/api/settings/ca-trust",
                        {"url": "https://ca.example/bundle.pem",
                         "auto": True}, headers=hh)
        assert st == 500
        resp = json.loads(b)
        assert resp["code"] == "internal-error"
        assert resp["error"] == "internal server error"
        fail_rows = [e for e in _read_audit_lines(audit_path)
                     if e.get("event") == "ca-trust-config"
                     and e.get("result") == "fail"]
        assert fail_rows, "no fail audit row for write_ca_trust_settings exception"
        detail = fail_rows[-1]["detail"]
        assert "OSError" in detail
        assert "disk full" not in detail
    finally:
        stop()


def _poll_ca_job(host, port, ck, jid, timeout=3):
    deadline = time.time() + timeout
    job = None
    while time.time() < deadline:
        s, _, jb = _req(host, port, "GET",
                        "/api/settings/ca-trust/refresh/" + jid,
                        headers={"Cookie": ck})
        assert s == 200
        job = json.loads(jb)
        if job["state"] != "running":
            return job
        time.sleep(0.02)
    return job


def test_ca_trust_refresh_job_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # poll route is session-gated; unknown id -> 404
        assert _req(host, port, "GET",
                    "/api/settings/ca-trust/refresh/deadbeef")[0] == 401
        assert _req(host, port, "GET",
                    "/api/settings/ca-trust/refresh/deadbeef",
                    headers={"Cookie": ck})[0] == 404
        # nothing configured yet -- refresh uses the built-in default url
        # ("Download now" works out of the box); stub the downloader (no
        # network in unit tests, and never the real Cisco URL)
        seen = {}

        def fake_download(url):
            seen["url"] = url
            return {"ok": True, "certs": 3, "error": None}

        monkeypatch.setattr(trust_mod, "download_bundle", fake_download)
        st, _, b = _req(host, port, "POST", "/api/settings/ca-trust/refresh",
                        {}, headers=hh)
        assert st == 200
        jid = json.loads(b)["job"]
        job = _poll_ca_job(host, port, ck, jid)
        assert job == {"state": "done", "certs": 3,
                       "detail": "downloaded 3 certificate(s) from "
                                 "configured endpoint"}
        assert seen["url"] == _CA_DEFAULT_URL

        # configuring an explicit url overrides the default
        assert _req(host, port, "POST", "/api/settings/ca-trust",
                    {"url": "https://ca.example/bundle.pem", "auto": False},
                    headers=hh)[0] == 200
        st, _, b = _req(host, port, "POST", "/api/settings/ca-trust/refresh",
                        {}, headers=hh)
        assert st == 200
        jid = json.loads(b)["job"]
        job = _poll_ca_job(host, port, ck, jid)
        assert job == {"state": "done", "certs": 3,
                       "detail": "downloaded 3 certificate(s) from "
                                 "configured endpoint"}
        assert seen["url"] == "https://ca.example/bundle.pem"

        # the audit event is emitted BEFORE the job turns terminal, so a
        # poller that saw done can rely on the line being there already
        evs = [e for e in _read_audit_lines(audit_path)
               if e["event"] == "ca-trust-refresh"]
        assert len(evs) == 2
        assert all(e["result"] == "ok" for e in evs)
        assert all(e["category"] == "settings" for e in evs)
        assert all(e["actor"] == "console:admin" for e in evs)
        assert all(e["target"] == "ca-trust" for e in evs)
        assert "3 certificate(s)" in evs[0]["detail"]
        assert "3 certificate(s)" in evs[1]["detail"]
    finally:
        stop()


def test_ca_trust_refresh_failure_reported_and_audited(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        assert _req(host, port, "POST", "/api/settings/ca-trust",
                    {"url": "https://ca.example/bundle.pem", "auto": False},
                    headers=hh)[0] == 200
        monkeypatch.setattr(
            trust_mod, "download_bundle",
            lambda url: {"ok": False, "certs": 0, "error": "no PEM blocks"})
        st, _, b = _req(host, port, "POST", "/api/settings/ca-trust/refresh",
                        {}, headers=hh)
        assert st == 200
        jid = json.loads(b)["job"]
        job = _poll_ca_job(host, port, ck, jid)
        assert job == {"state": "failed", "certs": None,
                       "detail": "CA bundle download failed"}
        evs = [e for e in _read_audit_lines(audit_path)
               if e["event"] == "ca-trust-refresh"]
        assert len(evs) == 1 and evs[0]["result"] == "fail"
        assert "CA bundle download failed" in evs[0]["detail"]
    finally:
        stop()


def test_ca_refresh_due_pure_decision():
    """The daily thread's 'should this cycle download' decision is a pure
    function so it is testable without threads or sleeping."""
    due = gui_server.ca_refresh_due
    assert due({"url": "https://ca.example/b.pem", "auto": True}) == \
        "https://ca.example/b.pem"
    assert due({"url": " https://ca.example/b.pem ", "auto": True}) == \
        "https://ca.example/b.pem"
    assert due({"url": "https://ca.example/b.pem", "auto": False}) is None
    assert due({"url": None, "auto": True}) is None
    assert due({"url": "   ", "auto": True}) is None
    assert due({"url": "https://ca.example/b.pem", "auto": 1}) is None
    assert due({}) is None
    assert due(None) is None


# ---- editable telemetry destination (feature B, console side) ----

def test_authenticated_telemetry_destination_requires_https(monkeypatch):
    monkeypatch.setenv("IRIS_OTLP_HEADERS", "Authorization=Bearer secret")
    assert gui_server._validate_otlp_endpoint(
        "http://collector:4318", authenticated=True)[0] is None
    assert gui_server._validate_otlp_endpoint(
        "https://collector:4318", authenticated=True) == (
            "https://collector:4318", None)

def test_settings_telemetry_destination_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("IRIS_OTLP_ENDPOINT", "http://env-collector:4318")
    monkeypatch.setenv("IRIS_OBSERVABILITY", "1")
    host, port, _deps, stop = _serve_full(tmp_path)
    try:
        # auth: no session -> 401; session without CSRF -> 403 (POST + DELETE)
        assert _req(host, port, "POST", "/api/settings/telemetry-destination",
                    {"endpoint": "https://c:4318", "enabled": True})[0] == 401
        ck, csrf = _auth(host, port)
        assert _req(host, port, "POST", "/api/settings/telemetry-destination",
                    {"endpoint": "https://c:4318", "enabled": True},
                    headers={"Cookie": ck})[0] == 403
        assert _req(host, port, "DELETE",
                    "/api/settings/telemetry-destination",
                    headers={"Cookie": ck})[0] == 403
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # no override yet: env is both the source and the effective config
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        assert st == 200
        assert json.loads(b)["telemetry_destination"] == {
            "endpoint": None, "enabled": None, "source": "env",
            "effective_endpoint": "http://env-collector:4318",
            "effective_enabled": True}
        # validation -> 400: bad types, bad scheme, missing netloc,
        # query/fragment, bool pedantry, credentials, hostless netloc
        for bad in ({"endpoint": 42, "enabled": True},
                    {"endpoint": "ftp://c:4318", "enabled": True},
                    {"endpoint": "https://", "enabled": True},
                    {"endpoint": "collector:4318", "enabled": True},
                    {"endpoint": "https://c:4318?x=1", "enabled": True},
                    {"endpoint": "https://c:4318#frag", "enabled": True},
                    {"endpoint": "", "enabled": True},
                    {"endpoint": "https://c:4318", "enabled": 1},
                    {"endpoint": "https://c:4318", "enabled": "on"},
                    {"endpoint": "http://user:pass@collector:4318", "enabled": True},
                    {"endpoint": "http://a@b", "enabled": True},
                    {"endpoint": "https://:4318", "enabled": True}):
            st, _, _ = _req(host, port, "POST",
                            "/api/settings/telemetry-destination", bad,
                            headers=hh)
            assert st == 400, bad
        hh_json = dict(hh); hh_json["Content-Type"] = "application/json"
        assert _req(host, port, "POST",
                    "/api/settings/telemetry-destination",
                    raw=b"[]", headers=hh_json)[0] == 400
        # set: the trailing slash is stripped before persisting
        st, _, b = _req(host, port, "POST",
                        "/api/settings/telemetry-destination",
                        {"endpoint": "https://collector:4318/",
                         "enabled": True}, headers=hh)
        assert st == 200
        assert json.loads(b) == {"ok": True,
                                 "endpoint": "https://collector:4318",
                                 "enabled": True}
        with open(str(tmp_path / "state"
                      / "telemetry-destination.json")) as f:
            assert json.load(f) == {"endpoint": "https://collector:4318",
                                    "enabled": True}
        # IPv6 addresses still work (guard case)
        st, _, b = _req(host, port, "POST",
                        "/api/settings/telemetry-destination",
                        {"endpoint": "https://[::1]:4318", "enabled": True},
                        headers=hh)
        assert st == 200
        assert json.loads(b) == {"ok": True,
                                 "endpoint": "https://[::1]:4318",
                                 "enabled": True}
        # Set back to collector:4318 for subsequent tests
        assert _req(host, port, "POST",
                    "/api/settings/telemetry-destination",
                    {"endpoint": "https://collector:4318", "enabled": True},
                    headers=hh)[0] == 200
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        assert json.loads(b)["telemetry_destination"] == {
            "endpoint": "https://collector:4318", "enabled": True,
            "source": "override",
            "effective_endpoint": "https://collector:4318",
            "effective_enabled": True}
        # per-field inherit: a null endpoint keeps the env endpoint effective
        assert _req(host, port, "POST",
                    "/api/settings/telemetry-destination",
                    {"endpoint": None, "enabled": False},
                    headers=hh)[0] == 200
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        assert json.loads(b)["telemetry_destination"] == {
            "endpoint": None, "enabled": False, "source": "override",
            "effective_endpoint": "http://env-collector:4318",
            "effective_enabled": False}
        # DELETE reverts the GET reflection to the deployment default (env)
        st, _, b = _req(host, port, "DELETE",
                        "/api/settings/telemetry-destination", headers=hh)
        assert st == 200 and json.loads(b)["deleted"] is True
        assert not os.path.exists(str(tmp_path / "state"
                                      / "telemetry-destination.json"))
        st, _, b = _req(host, port, "GET", "/api/settings",
                        headers={"Cookie": ck})
        dest = json.loads(b)["telemetry_destination"]
        assert dest["source"] == "env"
        assert dest["effective_endpoint"] == "http://env-collector:4318"
        assert dest["effective_enabled"] is True
        # a second DELETE reports there was nothing to delete
        st, _, b = _req(host, port, "DELETE",
                        "/api/settings/telemetry-destination", headers=hh)
        assert st == 200 and json.loads(b)["deleted"] is False
    finally:
        stop()


def test_settings_telemetry_destination_audited(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        assert _req(host, port, "POST",
                    "/api/settings/telemetry-destination",
                    {"endpoint": "https://collector:4318", "enabled": True},
                    headers=hh)[0] == 200
        assert _req(host, port, "DELETE",
                    "/api/settings/telemetry-destination",
                    headers=hh)[0] == 200
        events = _read_audit_lines(audit_path)
        set_ev = [e for e in events
                  if e["event"] == "telemetry-destination-set"]
        clr_ev = [e for e in events
                  if e["event"] == "telemetry-destination-clear"]
        assert len(set_ev) == 1 and len(clr_ev) == 1
        assert set_ev[0]["category"] == "telemetry"
        assert set_ev[0]["actor"] == "console:admin"
        assert set_ev[0]["target"] == "otlp-endpoint"
        # non-secret before -> after (endpoint URLs are not secrets; headers
        # stay env-only and never pass through this route)
        assert ("endpoint (inherit) -> https://collector:4318"
                in set_ev[0]["detail"])
        assert "enabled (inherit) -> True" in set_ev[0]["detail"]
        assert clr_ev[0]["category"] == "telemetry"
        assert ("was endpoint https://collector:4318"
                in clr_ev[0]["detail"])
    finally:
        stop()


def test_settings_telemetry_destination_persist_failure_audited(tmp_path, monkeypatch):
    """When telemetry_destination.write raises (e.g. disk-full OSError), the
    POST route must audit the failure and respond 500 with a static error
    message rather than dropping the connection."""
    import telemetry_destination
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}

        def failing_write(path, endpoint, enabled):
            raise OSError("disk full")
        monkeypatch.setattr(telemetry_destination, "write", failing_write)
        st, _, b = _req(host, port, "POST",
                        "/api/settings/telemetry-destination",
                        {"endpoint": "https://collector:4318",
                         "enabled": True}, headers=hh)
        assert st == 500
        resp = json.loads(b)
        assert resp["code"] == "internal-error"
        assert resp["error"] == "internal server error"
        fail_rows = [e for e in _read_audit_lines(audit_path)
                     if e.get("event") == "telemetry-destination-set"
                     and e.get("result") == "fail"]
        assert fail_rows, "no fail audit row for telemetry_destination.write exception"
        detail = fail_rows[-1]["detail"]
        assert "OSError" in detail
        assert "disk full" not in detail
    finally:
        stop()


def test_settings_telemetry_destination_credentials_rejected(tmp_path, monkeypatch):
    """Verify credentialed endpoints are rejected and credentials don't leak
    into response or audit logs. Endpoints with embedded userinfo are rejected
    at validation time before any audit event is generated."""
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # Attempt 1: user:pass@ format
        st, _, b = _req(host, port, "POST",
                        "/api/settings/telemetry-destination",
                        {"endpoint": "http://user:pass@collector:4318",
                         "enabled": True},
                        headers=hh)
        assert st == 400
        # Verify "pass" doesn't leak into response body
        assert b"pass" not in b.lower()
        # Attempt 2: user@ format
        st, _, b = _req(host, port, "POST",
                        "/api/settings/telemetry-destination",
                        {"endpoint": "http://a@b", "enabled": True},
                        headers=hh)
        assert st == 400
        assert b"a@b" not in b
        # Check audit log: no telemetry-destination-set event should be created
        # (validation happens before audit logging)
        events = _read_audit_lines(audit_path)
        set_ev = [e for e in events
                  if e["event"] == "telemetry-destination-set"]
        assert len(set_ev) == 0, "rejected endpoint should not create audit event"
        # Verify "pass" and other credential markers don't appear anywhere in audit
        audit_text = json.dumps(events)
        assert "pass" not in audit_text
        assert "user:pass" not in audit_text
    finally:
        stop()


def test_settings_telemetry_destination_malformed_ipv6_rejected(tmp_path, monkeypatch):
    """Verify malformed IPv6 URLs in endpoint validators are safely rejected
    with a clean 400 error, not a ValueError crash that drops the connection."""
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _deps, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # Malformed IPv6 bracket URLs must be rejected, not crash the request thread
        for bad in ("http://[::1:4318", "http://[bad"):
            st, _, b = _req(host, port, "POST",
                            "/api/settings/telemetry-destination",
                            {"endpoint": bad, "enabled": True},
                            headers=hh)
            assert st == 400, f"malformed IPv6 {bad!r} should return 400, not crash"
            # Response must be valid JSON with an error message (proves connection stayed alive)
            data = json.loads(b)
            assert "error" in data, f"response should contain error key"
        # Valid IPv6 must still work
        st, _, b = _req(host, port, "POST",
                        "/api/settings/telemetry-destination",
                        {"endpoint": "https://[::1]:4318", "enabled": True},
                        headers=hh)
        assert st == 200, "valid IPv6 https://[::1]:4318 should return 200"
        assert json.loads(b) == {"ok": True,
                                 "endpoint": "https://[::1]:4318",
                                 "enabled": True}
    finally:
        stop()


def test_settings_ca_trust_malformed_ipv6_rejected(tmp_path, monkeypatch):
    """Verify malformed IPv6 URLs in ca-trust validator are safely rejected
    with a clean 400 error, not a ValueError crash that drops the connection."""
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _deps, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # Malformed IPv6 bracket URLs must be rejected, not crash the request thread
        st, _, b = _req(host, port, "POST", "/api/settings/ca-trust",
                        {"url": "https://[bad", "auto": False},
                        headers=hh)
        assert st == 400, f"malformed IPv6 https://[bad should return 400, not crash"
        # Response must be valid JSON with an error message (proves connection stayed alive)
        data = json.loads(b)
        assert "error" in data, f"response should contain error key"
        # Valid IPv6 must still work
        st, _, b = _req(host, port, "POST", "/api/settings/ca-trust",
                        {"url": "https://[::1]:4318/ca.pem", "auto": False},
                        headers=hh)
        assert st == 200, "valid IPv6 https://[::1]:4318/ca.pem should return 200"
        assert json.loads(b)["ca_trust"] == {
            "url": "https://[::1]:4318/ca.pem", "auto": False}
    finally:
        stop()


# ---- GET /api/devices/<id>/deployment (deployment config visibility) ------

class _DeploymentProjectionController:
    def __init__(self, result=None, error=None):
        self.result = (result if result is not None else {
            "iox_verification_obligations": [], "iox_sessions": []})
        self.error = error
        self.requested = []

    def summary_for_device(self, device_id):
        self.requested.append(device_id)
        if self.error is not None:
            raise self.error
        # Return a detached value, as the real controller does across its
        # read-only authority boundary.
        return json.loads(json.dumps(self.result))


_READABLE_IOX_AUTHORITY = object()


def _serve_records(tmp_path, now_fn=None,
                   iox_controller=_READABLE_IOX_AUTHORITY,
                   record_store_override=None):
    """Serve deployment records with explicit readable IOx authority."""
    import deployment_records
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    record_store = record_store_override or (
        deployment_records.DeploymentRecordStore(state, now_fn=now_fn)
        if now_fn else deployment_records.DeploymentRecordStore(state))
    if iox_controller is _READABLE_IOX_AUTHORITY:
        iox_controller = _DeploymentProjectionController()
    server_kwargs = {"certfile": None, "record_store": record_store}
    if iox_controller is not None:
        server_kwargs["iox_controller"] = iox_controller
    srv = gui_server.make_server("127.0.0.1", 0, app, **server_kwargs)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, record_store, srv.shutdown


def _record_stub(device_id):
    return {"controller_id": "iris", "device_id": device_id,
            "inventory_revision": 1, "plan_hash": "h",
            "resolved": {"management_type": "routed", "platform": "guestshell"},
            "preflight": {"status": "not-required"},
            "resources": [{"kind": "guestshell", "ownership": "iris-created"}]}


def test_deployment_route_auth_and_records_unavailable(tmp_path):
    # no record store wired at all -> 404 "records unavailable"
    host, port, _app, stop = _serve(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/devices/d1/deployment")[0] == 401
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/devices/d1/deployment",
                        headers={"Cookie": ck})
        assert st == 404 and json.loads(b)["error"] == "records unavailable"
    finally:
        stop()


def test_deployment_route_null_then_newest_then_active(tmp_path):
    clock = {"t": 100}
    host, port, record_store, stop = _serve_records(tmp_path,
                                                 now_fn=lambda: clock["t"])
    try:
        ck, _csrf = _auth(host, port)
        # no records for the device: record is null, total 0
        st, _, b = _req(host, port, "GET", "/api/devices/d1/deployment",
                        headers={"Cookie": ck})
        assert st == 200
        assert json.loads(b) == {
            "record": None, "total": 0,
            "iox_verification_obligations": [], "iox_sessions": []}
        # two non-active, non-recoverable records -> the newest by
        # timestamps.planned_at wins
        r1 = record_store.create(_record_stub("d1"))
        record_store.transition(r1["record_id"], "removed")
        clock["t"] = 200
        r2 = record_store.create(_record_stub("d1"))
        _, _, b = _req(host, port, "GET", "/api/devices/d1/deployment",
                       headers={"Cookie": ck})
        got = json.loads(b)
        assert got["total"] == 2
        assert got["record"]["record_id"] == r2["record_id"]
        assert got["record"]["state"] == "planned"
        # the response is the stored record as-is (resolved/preflight/
        # resources ride along)
        assert got["record"]["resolved"]["platform"] == "guestshell"
        assert got["record"]["preflight"] == {"status": "not-required"}
        assert got["record"]["resources"][0]["kind"] == "guestshell"
        assert got["record"]["timestamps"]["planned_at"] == 200
        # once a record goes active it wins regardless of age
        record_store.transition(r2["record_id"], "applying")
        record_store.transition(r2["record_id"], "active")
        clock["t"] = 300
        r3 = record_store.create(_record_stub("d1"))     # newer, but only planned
        _, _, b = _req(host, port, "GET", "/api/devices/d1/deployment",
                       headers={"Cookie": ck})
        got = json.loads(b)
        assert got["total"] == 3
        assert got["record"]["record_id"] == r2["record_id"]
        assert got["record"]["state"] == "active"
        assert r3["record_id"] != r2["record_id"]
        # records are per-device: another device still sees null
        _, _, b = _req(host, port, "GET", "/api/devices/other/deployment",
                       headers={"Cookie": ck})
        assert json.loads(b) == {
            "record": None, "total": 0,
            "iox_verification_obligations": [], "iox_sessions": []}
    finally:
        stop()


def test_deployment_route_recoverable_beats_newer_planned(tmp_path):
    clock = {"t": 100}
    host, port, record_store, stop = _serve_records(tmp_path,
                                                 now_fn=lambda: clock["t"])
    try:
        ck, _csrf = _auth(host, port)
        r1 = record_store.create(_record_stub("d1"))
        record_store.transition(r1["record_id"], "needs-reconcile")
        clock["t"] = 200
        record_store.create(_record_stub("d1"))          # newer, merely planned
        _, _, b = _req(host, port, "GET", "/api/devices/d1/deployment",
                       headers={"Cookie": ck})
        got = json.loads(b)
        # the recoverable record still describes what is ON the box
        assert got["record"]["record_id"] == r1["record_id"]
        assert got["record"]["state"] == "needs-reconcile"
        assert got["total"] == 2
    finally:
        stop()


class _RawProjectionRecordStore:
    def __init__(self, records, selected):
        self.records = list(records)
        self.selected = selected

    def list(self, device_id, *args, **kwargs):
        return [record for record in self.records
                if record["device_id"] == device_id]

    def recoverable_for_device(self, device_id, *args, **kwargs):
        return (self.selected
                if self.selected["device_id"] == device_id else None)


class _StrictProjectionRecordStore(_RawProjectionRecordStore):
    def __init__(self, records, selected):
        _RawProjectionRecordStore.__init__(self, records, selected)
        self.strict_reads = []

    def list(self, device_id, *args, **kwargs):
        self.strict_reads.append(("list", kwargs.get("strict")))
        if kwargs.get("strict") is not True:
            raise AssertionError("deployment list was not a strict read")
        return _RawProjectionRecordStore.list(
            self, device_id, *args, **kwargs)

    def recoverable_for_device(self, device_id, *args, **kwargs):
        self.strict_reads.append(("recoverable", kwargs.get("strict")))
        if kwargs.get("strict") is not True:
            raise AssertionError("deployment selection was not a strict read")
        return _RawProjectionRecordStore.recoverable_for_device(
            self, device_id, *args, **kwargs)


def _verification_observation(state="enabled", at=10, command_id=1):
    return {
        "state": state, "observed_at": at, "command_id": command_id,
        "transcript_id": "d" * 32, "stdout_offset": 0,
        "stdout_length": 7, "stderr_offset": 0, "stderr_length": 0,
        "returncode": 0, "timed_out": False, "truncated": False,
        "framing_complete": True,
    }


def _internal_terminal_verification():
    return {
        "schema_version": 1, "transaction_id": "a" * 32, "revision": 1,
        "record_id": "record-1", "controller_id": "b" * 32,
        "board_identity": "FDO2547X9AB", "wrapper_sha256": "c" * 64,
        # An enabled initial observation may close directly as unchanged when
        # either native marker is present.
        "package_sign_present": True, "package_cert_present": False,
        "prior_state": "enabled", "current_state": "enabled",
        "phase": "unchanged", "unresolved": False, "created_at": 10,
        "updated_at": 12, "observed_at": 10, "terminal_at": 12,
        "initial_observation": _verification_observation(),
        "pre_disable_observation": None, "disable_confirmation": None,
        "restore_observation": None, "error": None,
        "transcript_refs": [{
            "id": "d" * 32, "attempt_id": "d" * 32,
            "stored_bytes": 4096, "observed_bytes": 7,
            "dropped_bytes": 0, "truncated": False,
        }],
    }


def _internal_indeterminate_verification():
    value = _internal_terminal_verification()
    value.update({
        "transaction_id": "e" * 32, "revision": 2,
        "record_id": "record-2", "package_sign_present": False,
        "current_state": "disabled", "phase": "indeterminate",
        "unresolved": True, "updated_at": 13, "observed_at": 12,
        "terminal_at": None,
        "pre_disable_observation": _verification_observation(
            state="enabled", at=11, command_id=2),
        "restore_observation": _verification_observation(
            state="disabled", at=12, command_id=3),
        "error": {
            "category": "reconciliation_required",
            "detail": "disabled state requires operator reconciliation",
            "at": 13, "transcript_id": "d" * 32,
        },
    })
    value["transcript_refs"][0].update({"observed_bytes": 21})
    return value


def _public_verification(record_id="record-1", transaction_id=None,
                         revision=1, current_state="enabled",
                         phase="unchanged", unresolved=False,
                         updated_at=12, observed_at=10,
                         error_category=None):
    return {
        "schema_version": 1, "record_id": record_id,
        "transaction_id": transaction_id or "a" * 32,
        "revision": revision,
        "board_identity": "FDO2547X9AB", "prior_state": "enabled",
        "current_state": current_state, "phase": phase,
        "unresolved": unresolved, "created_at": 10,
        "updated_at": updated_at, "observed_at": observed_at,
        "terminal_at": None if unresolved else updated_at,
        "error_category": error_category,
    }


def test_deployment_route_projects_only_safe_iox_authority_fields(tmp_path):
    internal_terminal = _internal_terminal_verification()
    internal_terminal_before = json.loads(json.dumps(internal_terminal))
    raw_record = {
        "record_id": "record-1", "controller_id": "iris",
        "device_id": "d1", "inventory_revision": 1,
        "plan_hash": "h" * 64, "state": "active",
        "resolved": {"platform": "iox", "device_ip": "10.0.0.1"},
        "preflight": {"status": "passed"}, "resources": [],
        "timestamps": {"planned_at": 1},
        "iox_verification": internal_terminal,
    }
    obligation = _public_verification(
        record_id="record-2", transaction_id="e" * 32,
        revision=2, current_state="disabled", phase="indeterminate",
        unresolved=True, updated_at=13, observed_at=12,
        error_category="reconciliation_required")
    unresolved_record = {
        "record_id": "record-2", "controller_id": "iris",
        "device_id": "d1", "inventory_revision": 1,
        "plan_hash": "i" * 64, "state": "abandoned",
        "resolved": {"platform": "iox", "device_ip": "10.0.0.2",
                     "device_identity": "FDO2547X9AB"},
        "preflight": {"status": "passed"}, "resources": [],
        "timestamps": {"planned_at": 2},
        "iox_verification": _internal_indeterminate_verification(),
    }
    session = {
        "attempt_id": "f" * 32, "job_id": "fedcba9876543210",
        "device_id": "d1",
        "board_identity": "FDO2547X9AB", "operation": "install",
        "teardown_mode": "none", "record_id": "record-2",
        "state": "active", "mutation_blocked": True,
    }
    controller = _DeploymentProjectionController({
        "iox_verification_obligations": [obligation],
        "iox_sessions": [session],
    })
    host, port, _store, stop = _serve_records(
        tmp_path, iox_controller=controller,
        record_store_override=_RawProjectionRecordStore(
            [raw_record, unresolved_record], raw_record))
    try:
        cookie, _csrf = _auth(host, port)
        status, _, body = _req(
            host, port, "GET", "/api/devices/d1/deployment",
            headers={"Cookie": cookie})
        assert status == 200, body
        result = json.loads(body)
        assert controller.requested == ["d1"]
        assert set(result) == {
            "record", "total", "iox_verification_obligations", "iox_sessions"}
        assert result["total"] == 2
        assert result["iox_verification_obligations"] == [obligation]
        assert result["iox_sessions"] == [session]
        assert result["record"]["iox_verification"] == _public_verification()
        # Projection is copy-only: serving it must not replace authority in
        # the record-store object supplied to the controller.
        assert raw_record["iox_verification"] == internal_terminal_before
        assert raw_record["iox_verification"]["controller_id"] == "b" * 32
        public_bytes = json.dumps(result, sort_keys=True)
        for private_value in ("b" * 32, "c" * 64, "transcript_refs",
                              "initial_observation", "command_id",
                              "package_sign_present", "package_cert_present"):
            assert private_value not in public_bytes
    finally:
        stop()


def test_deployment_route_uses_strict_record_reads(tmp_path):
    raw_record = {
        "record_id": "record-1", "controller_id": "iris",
        "device_id": "d1", "inventory_revision": 1,
        "plan_hash": "h" * 64, "state": "active",
        "resolved": {"platform": "iox", "device_ip": "10.0.0.1"},
        "preflight": {"status": "passed"}, "resources": [],
        "timestamps": {"planned_at": 1},
    }
    store = _StrictProjectionRecordStore([raw_record], raw_record)
    host, port, _unused, stop = _serve_records(
        tmp_path, record_store_override=store)
    try:
        cookie, _csrf = _auth(host, port)
        status, _, body = _req(
            host, port, "GET", "/api/devices/d1/deployment",
            headers={"Cookie": cookie})
        assert status == 200, body
        assert store.strict_reads == [("list", True), ("recoverable", True)]
    finally:
        stop()


def test_local_recovery_deduplicates_one_board_across_authority_sources():
    class Fleet:
        @staticmethod
        def get_device(device_id):
            return ({"device_id": "d1", "credential_profile_id": "lab"}
                    if device_id == "d1" else None)

    class Credentials:
        @staticmethod
        def list_profiles():
            return [{"id": "lab"}]

    class Controller:
        @staticmethod
        def summary_for_device(device_id):
            assert device_id == "d1"
            return {
                "iox_verification_obligations": [{
                    "board_identity": "FCW0000IOX",
                    "record_id": "record-1",
                }],
                "iox_sessions": [{
                    "board_identity": "FCW0000IOX",
                    "record_id": None,
                }],
            }

    class Onboard:
        def __init__(self):
            self.recoveries = []

        def start_iox_recovery(self, device_id, credential_ref,
                               board_identity, record_id=None):
            self.recoveries.append((device_id, credential_ref,
                                    board_identity, record_id))
            return "0123456789abcdef"

        @staticmethod
        def get_job(job_id):
            return {"id": job_id, "state": "queued", "record_id": None}

    onboard = Onboard()
    adapter = gui_server._OnboardSubmissionAdapter(
        Fleet(), Credentials(), None, onboard, Controller(),
        lambda *_args: None, lambda *_args: None, lambda *_args: None,
        lambda *_args: None, None, lambda: 0)

    result = adapter.dispatch({
        "operation": "recover", "device_id": "d1", "wait": False,
    })

    assert result == {
        "accepted": True, "job_id": "0123456789abcdef", "state": "queued",
        "terminal": False, "record_id": None, "result_code": None,
    }
    assert onboard.recoveries == [
        ("d1", "lab", "FCW0000IOX", "record-1")]


def test_deployment_route_returns_503_when_iox_authority_is_unreadable(tmp_path):
    controller = _DeploymentProjectionController(
        error=OSError("/private/authority/token-super-secret"))
    host, port, _record_store, stop = _serve_records(
        tmp_path, iox_controller=controller)
    try:
        cookie, _csrf = _auth(host, port)
        status, _, body = _req(
            host, port, "GET", "/api/devices/d1/deployment",
            headers={"Cookie": cookie})
        assert status == 503
        result = json.loads(body)
        assert controller.requested == ["d1"]
        assert isinstance(result.get("error"), str)
        assert "token-super-secret" not in result["error"]
    finally:
        stop()


def test_deployment_route_returns_503_without_an_authority_controller(tmp_path):
    host, port, _record_store, stop = _serve_records(
        tmp_path, iox_controller=None)
    try:
        cookie, _csrf = _auth(host, port)
        status, _, body = _req(
            host, port, "GET", "/api/devices/d1/deployment",
            headers={"Cookie": cookie})
        assert status == 503
        assert isinstance(json.loads(body).get("error"), str)
    finally:
        stop()


# ---- GET /api/deploy-logs (persistent deployment logs) --------------------

@pytest.mark.parametrize("detailed", [False, True])
def test_deploy_logs_routes_list_filter_and_serve(tmp_path, detailed):
    log_dir = str(tmp_path / "deploy-logs")

    def run_fn(p, e, on):
        on("[1/6] hello"); on("[6/6] done"); return 0

    host, port, stop = _serve_onboard(tmp_path, run_fn, log_dir=log_dir)
    try:
        assert _req(host, port, "GET", "/api/deploy-logs")[0] == 401
        ck, csrf = _auth(host, port)
        st, _, b = _req(host, port, "POST", "/api/devices/d1/onboard", {"log": detailed},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200
        jid = json.loads(b)["job_id"]
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            _, _, jb = _req(host, port, "GET", "/api/onboard/jobs/" + jid,
                            headers={"Cookie": ck})
            if json.loads(jb)["state"] in ("done", "error"):
                break
            _t.sleep(0.02)
        st, _, b = _req(host, port, "GET", "/api/deploy-logs",
                        headers={"Cookie": ck})
        assert st == 200
        logs = json.loads(b)["logs"]
        assert len(logs) == 1
        entry = logs[0]
        assert entry["device_id"] == "d1" and entry["action"] == "onboard"
        assert entry["state"] == "done" and entry["rc"] == 0
        assert entry["file"].endswith("-d1-onboard-%s.log" % jid)
        assert entry["finished_at"] and entry["size"] > 0
        # the device filter compares the raw id from the header
        _, _, b = _req(host, port, "GET", "/api/deploy-logs?device_id=d1",
                       headers={"Cookie": ck})
        assert len(json.loads(b)["logs"]) == 1
        _, _, b = _req(host, port, "GET", "/api/deploy-logs?device_id=ghost",
                       headers={"Cookie": ck})
        assert json.loads(b)["logs"] == []
        # the full text is served as text/plain: header line + job lines
        assert _req(host, port, "GET",
                    "/api/deploy-logs/" + entry["file"])[0] == 401
        st, hd, body = _req(host, port, "GET",
                            "/api/deploy-logs/" + entry["file"],
                            headers={"Cookie": ck})
        assert st == 200 and hd["Content-Type"].startswith("text/plain")
        text = body.decode()
        first = text.splitlines()[0]
        assert first.startswith("# job=%s device=d1 action=onboard "
                                "state=done rc=0" % jid)
        assert "[1/3] Prepare onboarding" in text and "Onboard completed." in text
        assert ("[1/6] hello" in text) is detailed
        assert ("[6/6] done" in text) is detailed
    finally:
        stop()


def test_deploy_logs_survive_job_eviction(tmp_path):
    """The whole point of persistence: after the in-memory job is TTL-evicted
    (server restart, or an hour passing), the log is still listed and
    readable."""
    log_dir = str(tmp_path / "deploy-logs")
    clock = {"t": 1000.0}
    host, port, stop = _serve_onboard(tmp_path, lambda p, e, on: 0,
                                      log_dir=log_dir,
                                      now_fn=lambda: clock["t"])
    try:
        ck, csrf = _auth(host, port)
        st, _, b = _req(host, port, "POST", "/api/devices/d1/onboard", {},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200
        jid = json.loads(b)["job_id"]
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            st, _, jb = _req(host, port, "GET", "/api/onboard/jobs/" + jid,
                             headers={"Cookie": ck})
            if st == 200 and json.loads(jb)["state"] in ("done", "error"):
                break
            _t.sleep(0.02)
        clock["t"] += 3600 * 2 + 1     # push the job past _JOB_TTL
        st, _, _b = _req(host, port, "GET", "/api/onboard/jobs/" + jid,
                         headers={"Cookie": ck})
        assert st == 404               # in-memory job gone
        _, _, b = _req(host, port, "GET", "/api/deploy-logs",
                       headers={"Cookie": ck})
        logs = json.loads(b)["logs"]
        assert len(logs) == 1 and logs[0]["device_id"] == "d1"
        st, _, body = _req(host, port, "GET",
                           "/api/deploy-logs/" + logs[0]["file"],
                           headers={"Cookie": ck})
        assert st == 200 and b"# job=" in body
    finally:
        stop()


def test_deploy_logs_list_falls_back_to_filename_and_skips_garbage(tmp_path):
    log_dir = str(tmp_path / "deploy-logs")
    os.makedirs(log_dir)
    # headerless file: metadata comes from the filename fields
    with open(os.path.join(log_dir, "50-legacy-undeploy-aaaa.log"), "w") as f:
        f.write("some output\n")
    # a proper header wins over the (sanitized) filename
    with open(os.path.join(log_dir, "99-sw_1-onboard-bbbb.log"), "w") as f:
        f.write("# job=bbbb device=sw 1 action=onboard state=error rc=7 "
                "queued_at=90 started_at=91 finished_at=99 platform=iox\n")
        f.write("ERROR: boom\n")
    # unparseable either way -> skipped
    with open(os.path.join(log_dir, "junk.log"), "w") as f:
        f.write("not a header\n")
    host, port, stop = _serve_onboard(tmp_path, lambda p, e, on: 0,
                                      log_dir=log_dir)
    try:
        ck, _csrf = _auth(host, port)
        _, _, b = _req(host, port, "GET", "/api/deploy-logs",
                       headers={"Cookie": ck})
        logs = json.loads(b)["logs"]
        assert [e["file"] for e in logs] == [       # newest first
            "99-sw_1-onboard-bbbb.log", "50-legacy-undeploy-aaaa.log"]
        assert logs[0]["device_id"] == "sw 1"       # RAW id from the header
        assert logs[0]["state"] == "error" and logs[0]["rc"] == 7
        assert logs[1] == {"file": "50-legacy-undeploy-aaaa.log",
                           "device_id": "legacy", "action": "undeploy",
                           "state": None, "rc": None, "finished_at": 50,
                           "size": logs[1]["size"]}
        # filtering on the raw header id finds the header-borne row only
        _, _, b = _req(host, port, "GET", "/api/deploy-logs?device_id=sw%201",
                       headers={"Cookie": ck})
        assert [e["file"] for e in json.loads(b)["logs"]] == [
            "99-sw_1-onboard-bbbb.log"]
    finally:
        stop()


def test_deploy_log_file_route_rejects_traversal_and_bad_names(tmp_path):
    log_dir = str(tmp_path / "deploy-logs")
    os.makedirs(log_dir)
    with open(str(tmp_path / "outside.log"), "w") as f:
        f.write("must never be served\n")
    # a symlink INSIDE log_dir pointing outside must not escape either
    os.symlink(str(tmp_path / "outside.log"),
               os.path.join(log_dir, "1-esc-onboard-cafe.log"))
    host, port, stop = _serve_onboard(tmp_path, lambda p, e, on: 0,
                                      log_dir=log_dir)
    try:
        ck, _csrf = _auth(host, port)
        for name in ("../outside.log", "..%2Foutside.log", "no.txt",
                     "missing.log", "1-esc-onboard-cafe.log"):
            st, _, _b = _req(host, port, "GET", "/api/deploy-logs/" + name,
                             headers={"Cookie": ck})
            assert st == 404, name
    finally:
        stop()


def test_deploy_logs_empty_without_log_dir(tmp_path):
    # no onboard service at all (plain _serve): listing is empty, files 404
    host, port, _app, stop = _serve(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/deploy-logs",
                        headers={"Cookie": ck})
        assert st == 200 and json.loads(b) == {"logs": []}
        st, _, _b = _req(host, port, "GET", "/api/deploy-logs/x.log",
                         headers={"Cookie": ck})
        assert st == 404
    finally:
        stop()


# ---- GET /api/help + instance id + static guide pages (help "?" feature) ---

def test_read_instance_id_minted_once_mode_0600(tmp_path):
    state = str(tmp_path / "state")  # dir does not exist yet: reader creates it
    first = gui_server.read_instance_id(state)
    assert re.fullmatch(r"[0-9a-f]{32}", first)
    p = os.path.join(state, "instance-id")
    assert os.path.isfile(p)
    assert os.stat(p).st_mode & 0o777 == 0o600
    # stable across calls, and the file content matches (newline stripped)
    assert gui_server.read_instance_id(state) == first
    with open(p) as f:
        assert f.read().strip() == first
    # a pre-existing id is read back verbatim, never rewritten
    with open(p, "w") as f:
        f.write("deadbeef" * 4 + "\n")
    assert gui_server.read_instance_id(state) == "deadbeef" * 4


def test_help_route_auth_shape_and_stable_deployment_id(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, _app, stop = _serve(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/help")[0] == 401
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/help",
                        headers={"Cookie": ck})
        assert st == 200
        doc = json.loads(b)
        assert doc["version"] == gui_server._read_version()
        assert re.fullmatch(r"[0-9a-f]{32}", doc["deployment_id"])
        assert doc["docs_url"] == gui_server._DOCS_URL
        assert doc["docs_url"].startswith("https://")
        assert doc["guides"] == {"device": "/help-device.html",
                                 "server": "/help-server.html"}
        # deployment id is durable: same value on every later call
        st2, _, b2 = _req(host, port, "GET", "/api/help",
                          headers={"Cookie": ck})
        assert st2 == 200
        assert json.loads(b2)["deployment_id"] == doc["deployment_id"]
    finally:
        stop()


def test_help_guide_pages_exist_and_header_help_control_wired():
    """Source guard for the "?" help feature: both static guide pages exist
    in the webroot (the /api/help "guides" links must not 404), each is a
    standalone CSP-clean page linking the shared stylesheet, and index.html
    carries the header "?" control that opens the popover."""
    for name in ("help-device.html", "help-server.html"):
        p = os.path.join(gui_server.WEBROOT, name)
        assert os.path.isfile(p), name
        with open(p) as f:
            page = f.read()
        assert "SPDX-License-Identifier: Apache-2.0" in page, name
        assert '<link rel="stylesheet" href="/styles.css">' in page, name
        assert 'href="/"' in page, name           # link back to the console
        assert gui_server._DOCS_URL in page, name  # link to the official docs
        # CSP: no inline handlers/styles/scripts on the static guide pages
        assert " style=" not in page and "onclick=" not in page, name
        assert "<script" not in page, name
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    shell = _react_shell()
    assert 'aria-controls="iris-help-panel"' in shell
    assert "safeLink(help.guides?.device, '/help-device.html')" in shell
    assert "safeLink(help.guides?.server, '/help-server.html')" in shell
    # The bundled API reference is a Console-served page too; the menu must
    # use the canonical trailing-slash path (bare /swagger only redirects).
    assert 'href="/swagger/" target="_blank" rel="noopener noreferrer"' in shell
    with open(os.path.join(gui_server.WEBROOT, "help-server.html")) as f:
        server_guide = f.read()
    assert 'href="/swagger/"' in server_guide
    assert 'href="/openapi.yaml"' in server_guide


def test_help_pages_link_only_current_docs_pages():
    """Every published-docs link on the two static help pages must resolve
    to a page that still exists under docs/zensical and is not a redirect
    stub (front matter ``template: redirect.html``) -- a stub means the old
    slug moved, and the help page should already carry the new one. A
    folder link (no trailing filename) resolves to that folder's
    ``index.md``."""
    repo_root = os.path.normpath(os.path.join(gui_server.WEBROOT, "..", ".."))
    docs_root = os.path.join(repo_root, "docs", "zensical")
    prefix = ("https://cisco-open.github.io/intelligent-release-image-staging"
              "/docs/")
    link_re = re.compile(re.escape(prefix) + r"([^\"'\s]*)")

    def is_redirect_stub(path):
        with open(path, encoding="utf-8") as f:
            text = f.read()
        if not text.startswith("---"):
            return False
        end = text.find("\n---", 3)
        front_matter = text[:end] if end != -1 else text
        return "template: redirect.html" in front_matter

    checked = 0
    for name in ("help-server.html", "help-device.html"):
        with open(os.path.join(gui_server.WEBROOT, name)) as f:
            page = f.read()
        for match in link_re.finditer(page):
            slug = match.group(1)
            slug = slug.split("#", 1)[0]   # anchors are not files on disk
            if not slug:
                continue                    # the bare docs/ site root
            checked += 1
            rel = slug.rstrip("/")
            candidate = os.path.join(docs_root, rel + ".md")
            if not os.path.isfile(candidate):
                candidate = os.path.join(docs_root, rel, "index.md")
            assert os.path.isfile(candidate), (
                "%s links %s%s, which resolves to no page under "
                "docs/zensical (%s)" % (name, prefix, slug, candidate))
            assert not is_redirect_stub(candidate), (
                "%s links %s%s, which is a redirect stub (%s) -- update the "
                "help page to link the page's new location" %
                (name, prefix, slug, candidate))
    assert checked >= 10   # sanity: the loop actually walked real links


@pytest.mark.parametrize("options,expected", [
    ({}, "off"), ({"log": False}, "off"), ({"log": True}, "on"),
], ids=["default", "off", "on"])
def test_job_log_option_reaches_onboard_and_recorded_undeploy(
        tmp_path, monkeypatch, options, expected):
    monkeypatch.setenv("IRIS_LOG", str(tmp_path / "server-log"))
    seen = []

    def run_fn(path, env, output):
        seen.append(env.copy())
        return 0

    host, port, stop = _serve_inband(tmp_path, run_fn)
    try:
        ck, csrf = _auth(host, port)
        headers = {"Cookie": ck, "X-CSRF-Token": csrf}
        for action in ("onboard", "undeploy"):
            body = dict(options)
            if action == "onboard":
                body.update(telemetry=False, telemetry_stream=True)
            status, _, response = _req(
                host, port, "POST", "/api/devices/edge/" + action,
                body, headers=headers)
            assert status == 200, response
            job = _wait_onboard_job(
                host, port, ck, json.loads(response)["job_id"])
            assert job["state"] == "done", job
            assert seen[-1].get("IRIS_LOG") == expected, action
            assert "IRIS_FORCE_AGENT_ONLY" not in seen[-1], action
            if action == "onboard":
                assert seen[-1]["IRIS_TELEMETRY"] == "off"
                assert seen[-1]["IRIS_TELEMETRY_STREAM"] == "on"
        assert len(seen) == 2
    finally:
        stop()


@pytest.mark.parametrize("action,force", [
    ("onboard", False), ("undeploy", False), ("undeploy", True),
], ids=["onboard", "recorded-undeploy", "forced-undeploy"])
@pytest.mark.parametrize("value", [
    None, 0, 1, 0.0, "on", "false", [], {},
], ids=["null", "zero", "one", "float", "on", "false", "list", "object"])
def test_job_log_option_rejects_non_boolean_before_planning_or_enqueue(
        tmp_path, monkeypatch, action, force, value):
    reached = []

    def forbidden(*args, **kwargs):
        reached.append(True)
        raise ValueError("unexpected planning or enqueue")

    host, port, stop = _serve_inband(tmp_path, forbidden)
    adapter = stop.__self__.onboard_submission
    for owner, name in (
            (adapter, "_plan"), (adapter, "_teardown_plan"),
            (adapter.record_store, "recoverable_for_device"),
            (adapter.record_store, "create"), (adapter.onboard, "start")):
        monkeypatch.setattr(owner, name, forbidden)
    try:
        ck, csrf = _auth(host, port)
        status, _, response = _req(
            host, port, "POST", "/api/devices/edge/" + action,
            {"log": value, "force": force},
            headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert status == 400, response
        assert json.loads(response)["error"] == "log must be a bool"
        assert reached == []
    finally:
        stop()


@pytest.mark.parametrize("options,expected", [
    ({}, "off"), ({"log": False}, "off"), ({"log": True}, "on"),
], ids=["default", "off", "on"])
def test_force_undeploy_delivers_the_force_flag_to_the_recipe(
        tmp_path, options, expected):
    """A forced undeploy must reach the teardown recipe with
    IRIS_FORCE_AGENT_ONLY=1.

    env_extra is the ONLY channel into the recipe, and the undeploy branch is
    the only place the flag is ever set. Dropping env_extra for that action
    silently downgrades a forced teardown to the full recorded one: on Guest
    Shell and IOx that removes Vlan$VLAN, the IRISQ discriminators and the PKI
    trustpoint using inventory values no record has proven -- precisely the
    harm the flag exists to prevent -- while the audit trail records that the
    operator's network was left untouched."""
    seen = {}

    def run_fn(p, e, on):
        seen.update(e)
        return 0

    host, port, stop = _serve_inband(tmp_path, run_fn)
    try:
        ck, csrf = _auth(host, port)
        st, _, b = _req(host, port, "POST", "/api/devices/edge/undeploy",
                        dict(options, force=True),
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200, b
        _wait_onboard_job(host, port, ck, json.loads(b)["job_id"])
        assert seen.get("IRIS_FORCE_AGENT_ONLY") == "1", (
            "forced undeploy reached the recipe without the force flag")
        assert seen.get("IRIS_LOG") == expected
    finally:
        stop()


@pytest.mark.parametrize("options,expected", [
    ({}, "off"), ({"log": False}, "off"), ({"log": True}, "on"),
], ids=["default", "off", "on"])
def test_force_undeploy_delivers_the_force_flag_to_xr_uninstall(
        tmp_path, options, expected):
    """The same force-flag delivery test above, but for an xr-host/xr-appmgr
    device: force must resolve to device/xr-uninstall.sh (not one of the
    IOS-XE teardown scripts) and IRIS_FORCE_AGENT_ONLY=1 must reach it the
    same way it reaches the Guest Shell/IOx recipes. XR force never touches
    a record -- model 8201 + platform xr-appmgr resolve straight to the XR
    recipe with no probe or preflight involved, so a bare device record is
    enough here, unlike an onboard test. os_family remains server-owned."""
    seen = {}
    ran_script = {}

    def run_fn(p, e, on):
        seen.update(e)
        ran_script["path"] = p
        return 0

    host, port, stop = _serve_inband(
        tmp_path, run_fn,
        device={"device_id": "xr1", "device_ip": "10.0.0.9", "model": "8201",
                "platform": "xr-appmgr", "management_type": "xr-host",
                "credential_profile_id": "lab"})
    try:
        ck, csrf = _auth(host, port)
        st, _, b = _req(host, port, "POST", "/api/devices/xr1/undeploy",
                        dict(options, force=True),
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200, b
        _wait_onboard_job(host, port, ck, json.loads(b)["job_id"])
        assert seen.get("IRIS_FORCE_AGENT_ONLY") == "1", (
            "forced XR undeploy reached the recipe without the force flag")
        assert seen.get("IRIS_LOG") == expected
        assert ran_script.get("path", "").endswith("device/xr-uninstall.sh"), (
            "forced XR undeploy did not run device/xr-uninstall.sh: %r"
            % ran_script.get("path"))
    finally:
        stop()


def test_undeploy_force_help_and_confirm_text_cover_xr_alongside_router():
    """Keep cleanup warnings concise and platform-neutral in both dialogs.

    Staged-file retention describes undeploy only, not agent republishing.
    Per-platform file inventories belong in the manual, not this popup.
    """
    component = _react_shell("inventory-actions.jsx")
    modal = component.split("</> : <>", 1)[1].split("</>}", 1)[0]
    confirm = _react_shell("activity-controller.mjs").split("async start(action,", 1)[1].split(
        "this.invalidateRead();", 1)[0]
    for text in (modal, confirm):
        for warning in ("resources listed as IRIS-owned", "staged images in device storage",
                        "Does not stop running jobs", "record and device identity checks",
                        "IRIS-marked VirtualPortGroups and related NAT settings on routers",
                        "Keeps unrelated networking", "Retires the old record on success"):
            assert warning in text
        assert "keeps VirtualPortGroup" not in text
        assert "never otherwise" not in text
    assert len(re.sub(r"<[^>]+>", " ", modal).split()) < 100


def test_telemetry_health_badge_lives_on_overview_not_monitoring():
    """Telemetry export health belongs on the Overview dashboard.

    The Monitoring page is about the audit trail and deployment logs; a
    telemetry-export badge in its heading described something that page has
    nothing to do with. Overview is the dashboard, so the badge moves there
    and must refresh with the Overview, not with Monitoring."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    # the badge is declared inside the Overview heading
    overview = html.split('id="view-overview"', 1)[1].split("</section>", 1)[0]
    assert 'id="iris-overview-root"' in overview
    component = (Path(gui_server.WEBROOT).parent / "console-ui/src/overview.jsx").read_text()
    assert 'id="telemetry-health"' in component
    # ...and no longer anywhere in the Monitoring section
    monitoring = html.split('id="view-monitoring"', 1)[1].split("</section>", 1)[0]
    assert 'id="telemetry-health"' not in monitoring
    # it refreshes with the Overview, not as part of refreshMonitoring()
    monitoring_fn = js.split("function refreshMonitoring()", 1)[1].split("}", 1)[0]
    assert "refreshTelemetryHealth" not in monitoring_fn
    overview_fn = js.split("async function refreshOverview()", 1)[1].split("\n  }", 1)[0]
    assert "refreshTelemetryHealth" in overview_fn


def test_console_refreshes_the_visible_view_periodically():
    """The console had no periodic refresh at all — `setInterval` appeared
    nowhere — so a view only updated on navigation or after an explicit
    action. Device state that changes server-side (heartbeats, staging
    progress, deployment state) was invisible until the operator navigated
    away and back. refreshDevices() already preserved batch checkbox
    selections "across the periodic re-render" that never existed.

    The poll must also stop: on view change, and while the tab is hidden, so
    a backgrounded console does not keep hitting the server."""
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "setInterval" in js, "no periodic refresh wired up"
    assert "clearInterval" in js, "poll is never cancelled"
    # a backgrounded tab must not keep polling
    assert "visibilitychange" in js or "document.hidden" in js
    # the poll re-runs the CURRENT view, so it must go through the same router
    assert "startViewPoll" in js and "stopViewPoll" in js


def test_devices_filter_every_column_and_act_on_the_filtered_set():
    component = _react_shell("inventory.jsx")
    for key in ('managementType', 'platform', 'status', 'cred', 'telemetry', 'peer', 'role', 'modelFamily', 'osFamily'):
        assert "['" + key + "'," in component
    assert 'id="dev-filter-q"' in component and 'id="dev-filter-clear"' in component
    assert "bulkButton('quarantine-selected'" in component and "bulkButton('release-selected'" in component
    assert 'value={state.filters[spec[0]]}' in component and 'controller.setFilter(spec[0], event.target.value)' in component
    assert 'pageQuery(this.state.filters, offset)' in _react_shell('inventory-controller.mjs')
    assert 'deviceMatchesFilters' not in _webroot('app.js'), 'The server owns target matching; pages are not silently narrowed again'


def test_agent_install_rename_and_inventory_only_label():
    html, component, model, controller = _webroot('index.html'), _react_shell('inventory.jsx'), _react_shell('inventory-model.mjs'), _react_shell('inventory-controller.mjs')
    assert "['platform', 'platform', 'agent install', 'Agent install: any'" in component
    assert "['legacy', 'Inventory only — management type not chosen']" in component
    assert "'Agent install'" in component and 'aria-label={`Agent install for ${id}`}' in component
    form, form_model = _react_shell('device-forms.jsx'), _react_shell('device-forms-model.mjs')
    assert '<option value="" disabled>' in form and 'Choose an agent install' in form
    assert 'id="df-platform"' in form
    for value in ('guestshell', 'iox', 'router', 'xr-appmgr'):
        assert "'" + value + "'" in form_model
        assert "'" + value + "'" in component
    assert "type === 'legacy' || type === 'legacy_routed'" in model
    assert "'Inventory only — management type not chosen'" in model
    assert "kind === 'platform' ? 'Agent install'" in controller
    assert "row('Agent install', lookup(platforms, res.platform" in _react_shell('device-details-model.mjs')
    assert '>Platform<' not in html and 'Platform: any' not in component


def test_agent_install_labels_name_the_runtime_not_router_networking():
    """The `router` recipe runs Guest Shell; VPG is a management choice."""
    html = _webroot("index.html")
    js = _webroot("app.js")
    label_fn = js.split("function agentInstallLabel(platform) {", 1)[1].split(
        "\n  }", 1)[0]
    label_map = js.split("var AGENT_INSTALL_LABELS = {", 1)[1].split("\n  };", 1)[0]
    assert "router: 'Guest Shell'" in label_map
    assert "AGENT_INSTALL_LABELS[platform]" in label_fn
    assert "router: 'Guest Shell'" in _react_shell('device-forms-model.mjs')
    assert "Router (VPG)" not in html + js
    assert "Router (Guest Shell via VirtualPortGroup)" not in html + js
    assert '{installLabels[value]}' in _react_shell('device-forms.jsx')
    details = _react_shell("device-details-model.mjs")
    assert "router: 'Guest Shell'" in details
    assert "row('Agent install', lookup(platforms, res.platform" in details


def test_add_device_form_model_field_precedes_agent_install_select():
    """Model compatibility is entered before choosing an agent install."""
    html = _react_shell('device-forms.jsx')
    assert html.index('id="df-model"') < html.index('id="df-platform"')


def test_add_device_form_filters_install_options_live_by_model():
    """Model lookup narrows the selected management type's install choices.
    The behavior tests cover changes, failures and late lookup responses."""
    js = _react_shell('device-forms-controller.mjs')
    assert "controller.setDevice('model', event.target.value)" in _react_shell('device-forms.jsx')
    assert "/api/v1/install-options?model=" in js
    assert "no agent install available yet" not in js
    assert "'xr-appmgr'" in _react_shell('device-forms-model.mjs')
    assert "refreshOptions" in js


def test_xr_host_management_type_option_added_to_both_selects():
    html, component = _webroot('index.html'), _react_shell('inventory.jsx')
    assert "['xr-host', 'XR host']" in component
    assert '[\'xr-host\', "XR host - router\'s own network stack"]' in _react_shell('device-forms-model.mjs')


# Management-type visibility and model lookup behavior are exercised against
# the shipped JavaScript in test_add_device_fields.py. The former source
# assertions required model/platform edits to change management type, which
# is precisely the behavior the operator now requires us to remove.


def test_device_form_submit_sends_no_addressing_fields_for_xr_host():
    """The submit handler used to fall through to an 'else' branch that
    sent iris_vlan/svi_ip/svi_mask for anything not inband or router-* --
    an unhandled xr-host would have wrongly carried routed-mode addressing.
    An explicit xr-host branch must send NONE of the addressing keys at
    all: not the routed ones, not app_ip/app_mask/app_gateway either."""
    js = _react_shell('device-forms-model.mjs').split('export function deviceBody(form)', 1)[1]
    assert "if (managementType === 'xr-host') return body;" in js
    xr_branch = js.split("if (managementType === 'xr-host') return body;", 1)[0]
    for key in ("iris_vlan", "svi_ip", "svi_mask", "app_ip", "app_mask",
                "app_gateway", "vpg_number", "nat_interface", "inband_vlan"):
        assert key not in xr_branch, "xr-host submit branch sends %s" % key


def test_devices_table_renders_honest_xr_host_label():
    model = _react_shell('inventory-model.mjs')
    function = model.split('export function managementLabel(device)', 1)[1].split('export function telemetryBadge', 1)[0]
    assert "if (type === 'xr-host') return 'XR host';" in function
    assert function.index("type === 'xr-host'") < function.index("type.startsWith('router-')")
    assert "type === 'legacy' || type === 'legacy_routed'" in function
    assert 'Inventory only — management type not chosen' in function
    assert 'managementLabel(device)' in _react_shell('inventory.jsx')


def test_deploy_info_panel_hides_meaningless_rows_and_labels_xr_host():
    """The per-row (i) deployment-details panel rendered raw 'xr-host' as
    the Attachment value and four rows of dashes -- Management VLAN / VPG,
    SVI, App IP, NAT interface -- that mean nothing for an xr-host record,
    since the appmgr container carries none of them. xr-host now renders
    the honest 'XR host' label, and the four addressing rows are dropped
    from the table entirely for it rather than shown as em-dashes (which
    read as "unknown", not "not applicable")."""
    js = _react_shell("device-details-model.mjs")
    fn = js.split("function recordRows(rec, total = 0) {", 1)[1].split(
        "export function imageRows", 1)[0]
    # Pins the DATA KEY, not just the rendered label: a reader still keyed
    # off the retired res.attachment would read undefined for every device
    # (deployment_records never wrote res.attachment) and this whole test
    # would stay green testing a dead code path -- Task 2's fix-wave gap.
    assert "res.management_type" in fn
    assert "res.attachment" not in fn
    assert "xrHost = managementType === 'xr-host'" in fn
    assert "'XR host'" in fn
    assert "if (!xrHost) {" in fn
    guarded = fn.split("if (!xrHost) {", 1)[1].split("\n  }", 1)[0]
    for row in ("Management VLAN / VPG", "SVI", "App IP", "NAT interface"):
        assert row in guarded, "%r must be inside the !xrHost guard" % row
    # State/Record/Planned/Finished/Preflight/Management type stay
    # unconditional (every record has them); so do Swarm port/Agent
    # install/Device identity, which are outside the guard, after it closes
    unguarded = fn.split("if (!xrHost) {", 1)[0]
    for row in ("State", "Record", "Planned", "Finished", "Preflight",
                "Management type"):
        assert row in unguarded
    after_guard = fn.split("if (!xrHost) {", 1)[1].split("\n  }", 1)[1]
    for row in ("Swarm port", "Agent install", "Device identity"):
        assert row in after_guard
    hardware = js.split("function hardwareRows", 1)[1].split(
        "function validRecordResponse", 1)[0]
    assert "Chassis model" in hardware and "Series" in hardware
    assert "xrHost" not in hardware


def test_install_options_api_requires_auth_and_matches_model_matrix(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        assert _req(host, port, "GET",
                    "/api/install-options?model=C9300-48UXM")[0] == 401
        cookie, _ = _login(host, port)
        headers = {"Cookie": cookie}

        st, _, b = _req(host, port, "GET",
                        "/api/install-options?model=C9300-48UXM", headers=headers)
        assert st == 200
        assert json.loads(b)["options"] == ["guestshell", "iox"]

        # the 8201 incident: an IOS-XR model gets the ONE install it can run
        # (never an IOS-XE one), not null
        st, _, b = _req(host, port, "GET", "/api/install-options?model=8201",
                        headers=headers)
        assert st == 200
        assert json.loads(b)["options"] == ["xr-appmgr"]

        # blank/unrecognized model -> None ("auto only", no guardrail opinion)
        st, _, b = _req(host, port, "GET", "/api/install-options?model=",
                        headers=headers)
        assert json.loads(b)["options"] is None
        st, _, b = _req(host, port, "GET", "/api/install-options",
                        headers=headers)
        assert json.loads(b)["options"] is None
    finally:
        stop()


def test_deploy_logs_paging_graph_search_and_side_drawer():
    """The deployment-logs pane listed every log in one unpaged table, could
    only filter by exact device id, had no sense of when deployments happened,
    and opened a log in a <pre> BELOW the table — pushing the list off screen.

    It gets: a time graph over the logs it holds, free-text search across
    device/action/result plus action and result pickers, paging, and a
    right-hand drawer so the list stays put while a log is open."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    with open(os.path.join(gui_server.WEBROOT, "styles.css")) as f:
        css = f.read()
    pane = _react_shell("monitoring.jsx").split('id="monitoring-pane-deploylogs"', 1)[1]
    # the timeline is the audit timeline's FEATURE -- chips pick a window, a
    # brush selects a range, and the selection filters the table. A static
    # sparkline is not the same thing.
    assert '<Timeline kind="deploylogs"' in pane
    model = _react_shell("monitoring-model.mjs")
    assert "list.set('after_ts', state.selection?.start" in model
    for control in ("dl-search", "dl-action", "dl-result",
                    "dl-prev", "dl-next", "dl-page", "dl-drawer", "dl-drawer-close"):
        assert 'id="%s"' % control in pane, "missing deploy-log control: %s" % control
    # the log body lives in the drawer now, not loose under the table
    drawer = pane.split('id="dl-drawer"', 1)[1]
    assert 'id="dl-text"' in drawer
    # paging + client-side matching exist
    assert "function deploymentRows(state)" in model and "rows.slice(page * PAGE_SIZE" in model
    # the drawer slides in from the right, and respects reduce-motion
    assert "#dl-drawer" in css
    assert "prefers-reduced-motion" in css


def test_first_run_setup_is_a_wizard_not_a_linking_checklist():
    """Setup was four cards that reported status and sent the operator off to
    Settings > General / > Telemetry to actually do anything. First run is a
    flow, so it becomes a stepped wizard that hosts the forms in place.

    Steps -- telemetry, device packages, image verification -- with admin
    shown as already complete, because first-run just created it. Every step can be
    skipped. A new wizard visit starts at step one, and status refreshes leave
    the operator's current step alone. Package preparation happens outside
    the Console, so navigation must not require every step to be complete."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    with open(os.path.join(gui_server.WEBROOT, "login.js")) as f:
        login = f.read()

    # a top-level view, not a settings sub-pane
    assert 'id="view-setup"' in html
    assert "'setup'" in js.split("var VIEWS =", 1)[1].split("]", 1)[0]

    wiz = _react_shell('setup-packages.jsx')
    # the telemetry form step mounts the SHARED template rather than copying it
    assert 'id="wz-td-mount"' in wiz
    assert "settings.select('telemetry', 'wz-td-mount')" in js
    # packages is detect-and-instruct, never a form
    assert "recheck('wz-pkg-recheck'" in wiz
    assert "<form" not in wiz.split('id="wz-step-packages"', 1)[1]
    # Skippable, with an explicit step-one entry instead of status-based jumps.
    # The controller's Node tests exercise navigation and refresh behavior.
    assert 'id="wz-skip"' in wiz and 'id="wz-next"' in wiz and 'id="wz-back"' in wiz
    controller = _react_shell('setup-packages-controller.mjs')
    assert "step: changed && mode === 'wizard' ? 0 : this.state.step" in controller
    assert 'this.update({step, navigating: false})' in controller
    # the nudge that brings an operator back
    assert 'id="setup-nudge"' in wiz
    # first-run hands off to the wizard, not to the old checklist
    assert "'/#setup'" in login or '"/#setup"' in login
    assert "#settings/setup" not in login


def test_every_hidden_toggled_element_survives_its_display_rule():
    """`el.hidden = true` only hides an element if no CSS rule outranks the UA
    stylesheet's `[hidden] { display: none }`. A class or id selector setting
    `display:` beats it, so the element stays on screen while the code believes
    it is gone.

    This bit the setup nudge: `.nudge { display:flex }` meant the banner could
    never hide, and because updateSetupNudge() returns early once the count is
    zero, it sat there showing a stale "1 setup step still needs attention"
    over a fully configured server."""
    with open(os.path.join(gui_server.WEBROOT, "styles.css")) as f:
        css = f.read()
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()

    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    # Every element that can be hidden -- i.e. carries a `hidden` attribute in
    # the markup -- contributes its id and its classes. Keying off the markup
    # rather than off `getElementById(x).hidden` is deliberate: the nudge is
    # hidden through a local variable, which a call-site scan misses entirely.
    toggled = set()
    for tag in re.findall(r"<[a-zA-Z][^>]*\shidden[\s/>]", html):
        m = re.search(r'id="([\w-]+)"', tag)
        if m:
            toggled.add(m.group(1))
        m = re.search(r'class="([^"]+)"', tag)
        if m:
            toggled.update(m.group(1).split())

    offenders = []
    for sel_group, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        if not re.search(r"display\s*:\s*(?!none)[a-z-]+", body):
            continue
        for sel in sel_group.split(","):
            sel = sel.strip()
            if not sel:
                continue
            # `.x:not([hidden]) { display:flex }` is the other correct pattern --
            # the rule simply stops applying once the attribute is set.
            if ":not([hidden])" in sel or "[hidden]" in sel:
                continue
            # Only the LAST compound is what the rule targets: in
            # `.menu label { display:block }` the target is the label, not .menu.
            target = re.split(r"[\s>+~]+", sel)[-1]
            for token in re.findall(r"[.#]([\w-]+)", target):
                if token not in toggled:
                    continue
                guard = re.search(
                    r"[.#]" + re.escape(token) +
                    r"(?::not\(\[hidden\]\)|\[hidden\])[^{}]*\{[^{}]*display",
                    css)
                if not guard:
                    offenders.append(token)
    assert not offenders, (
        "these elements are toggled with .hidden but a display rule outranks "
        "[hidden], so they never actually hide: %s" % sorted(set(offenders)))


def test_setup_wizard_shows_every_step_even_when_already_complete():
    """The wizard renders one step at a time and opens on the first incomplete
    one. On a server whose telemetry destination already comes from the
    deployment environment (IRIS_OTLP_ENDPOINT), telemetry resolves to 'ok',
    so the wizard opened on the next step and the telemetry step was never
    visible at all -- it looked missing.

    Every step must therefore be listed and reachable, whatever its state."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    wiz = _react_shell('setup-packages.jsx')
    assert 'id="wz-steplist"' in wiz, "no step list: completed steps stay invisible"
    # the list is built from the same step table the wizard navigates
    assert 'setupSteps.map((row, index)' in wiz
    # and any step can be opened directly, not just the first incomplete one
    assert 'wz-steplist-item' in wiz and 'onClick={() => c.chooseStep(index)}' in wiz


def test_onboard_category_chip_does_not_read_as_the_sentence_subject():
    """auditRowHtml puts the category chip immediately before the verb phrase,
    so an undeploy event rendered as "onboard started undeploying <device>" --
    the chip labels the SUBSYSTEM, but it sits where a sentence subject goes.

    One service handles both onboard and undeploy jobs, so the stored category
    is legitimately "onboard" and must stay that way: it is persisted in
    audit.jsonl and drives the category filter. Only the visible label changes."""
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()

    model = _react_shell("monitoring-model.mjs")
    component = _react_shell("monitoring.jsx")
    assert "categoryLabel: category === 'onboard' ? 'deployment' : category" in model
    assert "cat-${text.category}`}>{text.categoryLabel}" in component
    # the filter still SENDS onboard, whatever it displays
    assert "value={category}>{category === 'onboard' ? 'deployment' : category}" in component
    # and the label an operator reads is no longer the bare subsystem name
    assert ">onboard</option>" not in component


def _write_deploy_log(log_dir, finished_at, device, action="onboard",
                      state="done", rc=0, job="abc123"):
    """Synthesise a persisted deploy log with a controlled finished_at, so a
    histogram can be tested without running jobs at real timestamps."""
    os.makedirs(log_dir, exist_ok=True)
    name = "%d-%s-%s-%s.log" % (finished_at, device, action, job)
    header = ("# job=%s device=%s action=%s state=%s rc=%s queued_at=%d "
              "started_at=%d finished_at=%d platform=guestshell\n"
              % (job, device, action, state, rc, finished_at - 2,
                 finished_at - 1, finished_at))
    with open(os.path.join(log_dir, name), "w") as f:
        f.write(header + "line one\n")
    return name


def test_deploy_log_histogram_bins_and_the_list_takes_a_time_window(tmp_path):
    """The deployment-logs timeline must be the audit timeline's feature, not a
    lookalike: the server bins into buckets over a window, and the list route
    accepts the brush's range so a selection actually filters the table."""
    log_dir = str(tmp_path / "deploy-logs")
    base = 1_700_000_000
    for i, dev in enumerate(("d1", "d2", "d3")):
        _write_deploy_log(log_dir, base + i * 3600, dev, job="job%d" % i)
    _write_deploy_log(log_dir, base + 50 * 3600, "d4", action="undeploy",
                      job="jobfar")

    host, port, stop = _serve_onboard(tmp_path, lambda p, e, on: 0,
                                      log_dir=log_dir)
    try:
        assert _req(host, port, "GET", "/api/deploy-logs/histogram")[0] == 401
        ck, _ = _auth(host, port)

        st, _, b = _req(host, port, "GET",
                        "/api/deploy-logs/histogram?since_ts=%d&until_ts=%d&buckets=4"
                        % (base, base + 4 * 3600), headers={"Cookie": ck})
        assert st == 200, b
        buckets = json.loads(b)["buckets"]
        assert len(buckets) == 4
        assert sum(x["count"] for x in buckets) == 3      # the far one is outside
        assert all("start" in x for x in buckets)

        # the brush range narrows the LIST too
        _, _, b = _req(host, port, "GET",
                       "/api/deploy-logs?after_ts=%d&before_ts=%d"
                       % (base, base + 3600), headers={"Cookie": ck})
        got = json.loads(b)["logs"]
        assert [l["device_id"] for l in got] == ["d2", "d1"]   # newest first

        # a nonsense window is refused, exactly as the audit route refuses it
        assert _req(host, port, "GET",
                    "/api/deploy-logs/histogram?since_ts=200&until_ts=100",
                    headers={"Cookie": ck})[0] == 400
    finally:
        stop()


# ---------------------------------------------------------------------------
# A deleted device must not bequeath its deployment to the next device
# registered under the same id, and a replaced box must always be escapable.
# ---------------------------------------------------------------------------

_ROUTER_ROW = {"device_id": "r1", "device_ip": "192.0.2.10", "model": "C8000V",
               "management_type": "router-nat", "vpg_number": "10",
               "nat_interface": "GigabitEthernet1", "app_ip": "10.8.0.2",
               "app_mask": "255.255.255.252", "app_gateway": "10.8.0.1",
               "credential_profile_id": "lab"}

_OWNED = [{"kind": k, "ownership": "iris-created"} for k in (
    "virtualportgroup", "eem-applets", "agent-files", "logging-discriminator",
    "pki-trustpoint", "http-client-trustpoint", "iox-global",
    "file-prompt-quiet", "guestshell", "nat-acl", "nat-overload",
    "nat-static", "nat-outside-marking")]


def _stranded_record(record_store, resources=None):
    """A record in the state a died-mid-teardown router is left in."""
    rid = record_store.create({
        "controller_id": "iris", "device_id": "r1", "inventory_revision": 1,
        "plan_hash": "b" * 64,
        "resolved": {"platform": "router", "management_type": "router-nat",
                     "device_ip": "192.0.2.10", "vpg_number": "10",
                     "nat_interface": "GigabitEthernet1", "app_ip": "10.8.0.2",
                     "app_mask": "255.255.255.252", "app_gateway": "10.8.0.1"},
        "preflight": {"status": "passed", "device_identity": "OLDBOARDID"},
        "resources": _OWNED if resources is None else resources})["record_id"]
    record_store.transition(rid, "applying")
    record_store.transition(rid, "needs-reconcile")
    return rid


def test_delete_abandons_records_so_a_readded_device_can_onboard(tmp_path, monkeypatch):
    """Delete must be terminal for a device id.

    Every other per-device store is purged on delete -- assignment, heartbeat,
    telemetry, pull directive, report ledger -- but the record store was never
    touched, and it is the one that gates onboard. A device deleted and added
    back under the same id therefore inherited its predecessor's deployment:
    onboard refused with "undeploy it first", and the undeploy it named refused
    the box, because a rebuilt VM keeps the id and the address but reports a new
    board ID. Neither door opened, and delete was no way out either."""
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, fleet, record_store, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        rid = _stranded_record(record_store)

        st, _, b = _req(host, port, "POST", "/api/devices/r1/onboard", {}, headers=hh)
        assert st == 409 and b"deployment record" in b

        st, _, b = _req(host, port, "DELETE", "/api/devices/r1", headers=hh)
        assert st == 200, b
        assert record_store.get(rid)["state"] == "abandoned"
        assert record_store.recoverable_for_device("r1") is None

        st, _, b = _req(host, port, "POST", "/api/devices", dict(_ROUTER_ROW),
                        headers=hh)
        assert st == 200, b
        st, _, b = _req(host, port, "POST", "/api/devices/r1/onboard", {},
                        headers=hh)
        assert st == 200, b
    finally:
        stop()


@pytest.mark.parametrize("pause", ["before_records", "after_records"])
def test_delete_finishes_old_cleanup_before_replacement_can_onboard(
        tmp_path, monkeypatch, pause):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    paused, continue_delete = threading.Event(), threading.Event()
    preflight_entered, continue_job = threading.Event(), threading.Event()
    replacement_started, replacement_submitted = threading.Event(), threading.Event()
    executed, outcomes = [], {}

    def preflight(dev, env, resolved):
        preflight_entered.set()
        assert continue_job.wait(5)
        return {"status": "passed", "device_identity": "NEWBOARDID",
                "detected_model": "C8000V", "nat_interface": "GigabitEthernet1"}

    def runner(path, env, output, on_proc):
        executed.append(True)
        return 0

    host, port, fleet, records, stop = _serve_router(
        tmp_path, runner, preflight_fn=preflight)
    threads = []
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        old = _stranded_record(records)
        if pause == "before_records":
            # No old recoverable record masks the first gap. The other case
            # pauses just after retiring a genuinely stranded predecessor.
            records.transition(old, "abandoned")
        real_retire = records.retire_device

        def retire(device_id, reason, *args, **kwargs):
            if pause == "after_records":
                value = real_retire(device_id, reason, *args, **kwargs)
            paused.set()
            assert continue_delete.wait(5)
            if pause == "before_records":
                value = real_retire(device_id, reason, *args, **kwargs)
            return value

        monkeypatch.setattr(records, "retire_device", retire)

        def delete():
            outcomes["delete"] = _req(
                host, port, "DELETE", "/api/devices/r1", headers=headers)[0]

        def replace():
            replacement_started.set()
            outcomes["add"] = _req(
                host, port, "POST", "/api/devices", dict(_ROUTER_ROW),
                headers=headers)[0]
            status, _, body = _req(
                host, port, "POST", "/api/devices/r1/onboard", {},
                headers=headers)
            outcomes["onboard"] = status
            outcomes["job_id"] = json.loads(body).get("job_id")
            replacement_submitted.set()

        threads = [threading.Thread(target=delete), threading.Thread(target=replace)]
        threads[0].start()
        assert paused.wait(3)
        assert fleet.get_device("r1") is None
        threads[1].start()
        assert replacement_started.wait(3)
        blocked_during_cleanup = not replacement_submitted.wait(0.15)
        continue_delete.set()
        for thread in threads:
            thread.join(3)
            assert not thread.is_alive()
        assert outcomes["delete"] == outcomes["add"] == outcomes["onboard"] == 200
        assert preflight_entered.wait(3)
        new = next(record["record_id"] for record in records.list(device_id="r1")
                   if record["record_id"] != old)
        state_after_delete = records.get(new)["state"]
        continue_job.set()
        job = _wait_onboard_job(host, port, cookie, outcomes["job_id"])
        assert blocked_during_cleanup
        assert records.get(old)["state"] == "abandoned"
        assert state_after_delete != "abandoned"
        assert job["state"] == "done"
        assert records.get(new)["state"] == "active"
        assert "[abort requested by operator]" not in job["lines"]
        assert executed == [True]
    finally:
        continue_delete.set()
        continue_job.set()
        for thread in threads:
            if thread.ident is not None:
                thread.join(3)
        stop()


@pytest.mark.parametrize("failure", ["records", "jobs"])
def test_delete_cleanup_failure_retains_degraded_response_and_releases_guard(
        tmp_path, monkeypatch, failure):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    audit_path = str(tmp_path / "audit.jsonl")
    host, port, fleet, records, stop = _serve_router(
        tmp_path, lambda path, env, output: 0, audit_path=audit_path)
    called = []

    def retire(device_id, reason):
        called.append("records")
        if failure == "records":
            raise OSError("injected record failure")
        return []

    def cancel(service, device_id):
        called.append("jobs")
        if failure == "jobs":
            raise OSError("injected job failure")
        return {"cancelled": 0, "aborted": 0}

    monkeypatch.setattr(records, "retire_device", retire)
    monkeypatch.setattr(gui_onboard.OnboardService, "cancel_device", cancel)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, body = _req(
            host, port, "DELETE", "/api/devices/r1", headers=headers)
        assert status == 207
        assert json.loads(body) == {"deleted": True, "degraded": [failure]}
        assert called == ["records", "jobs"]
        assert fleet.get_device("r1") is None
        assert _req(host, port, "POST", "/api/devices", dict(_ROUTER_ROW),
                    headers=headers)[0] == 200
        events = _read_audit_lines(audit_path)
        deletion = next(event for event in events if event["event"] == "device_delete")
        assert deletion["result"] == "degraded"
        assert "partial cleanup: " + failure in deletion["detail"]
    finally:
        stop()


def test_delete_audit_names_the_record_outcome(tmp_path, monkeypatch):
    """The delete audit line already names what it revoked and what it retained.
    Records were the one thing it changed silently."""
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    audit_path = str(tmp_path / "audit.jsonl")
    host, port, fleet, record_store, stop = _serve_router(
        tmp_path, lambda p, e, on: 0, audit_path=audit_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _stranded_record(record_store)
        assert _req(host, port, "DELETE", "/api/devices/r1", headers=hh)[0] == 200
        with open(audit_path) as stream:
            events = [json.loads(line) for line in stream if line.strip()]
        deletes = [e for e in events if e.get("event") == "device_delete"]
        assert deletes, "no device_delete audit event"
        assert "1 deployment record abandoned" in deletes[0]["detail"], \
            deletes[0]["detail"]
    finally:
        stop()


def test_forced_undeploy_is_honoured_when_a_record_exists(tmp_path):
    """Force is the rescue path for a box that no longer matches its record --
    which is exactly a case where a record EXISTS. It used to be consulted only
    on the no-record branch, so a replaced device ran the full recorded
    teardown, hit the recipe's identity guard on the new board ID, and failed
    every single time with no way to ask for anything else."""
    seen = {}

    def run_fn(p, e, on):
        seen.update(e)
        return 0

    audit_path = str(tmp_path / "audit.jsonl")
    host, port, fleet, record_store, stop = _serve_router(tmp_path, run_fn, audit_path=audit_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        rid = _stranded_record(record_store)

        st, _, b = _req(host, port, "POST", "/api/devices/r1/undeploy",
                        {"force": True}, headers=hh)
        assert st == 200, b
        _wait_onboard_job(host, port, ck, json.loads(b)["job_id"])
        assert seen.get("IRIS_FORCE_AGENT_ONLY") == "1", (
            "a forced undeploy ran the recorded teardown instead")
        # and the record it deliberately did not use as authority is retired,
        # or the very next onboard is refused on it again.
        assert record_store.get(rid)["state"] == "abandoned"
        assert record_store.recoverable_for_device("r1") is None
        events = _read_audit_lines(audit_path)
        forced = [event for event in events if event["event"] == "undeploy_forced"]
        assert len(forced) == 1
        assert "IRIS-marked VPG/NAT configuration" in forced[0]["detail"]
        assert "untouched" not in forced[0]["detail"]
    finally:
        stop()


def test_forced_undeploy_retires_records_only_on_success(tmp_path):
    """A failure to reach the device is not proof that the record is wrong.
    Voiding a healthy deployment's record on a network blip would strand it the
    way this path exists to prevent, so retirement waits for a clean exit."""
    host, port, fleet, record_store, stop = _serve_router(
        tmp_path, lambda p, e, on: 1)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        rid = _stranded_record(record_store)
        st, _, b = _req(host, port, "POST", "/api/devices/r1/undeploy",
                        {"force": True}, headers=hh)
        assert st == 200, b
        _wait_onboard_job(host, port, ck, json.loads(b)["job_id"])
        assert record_store.get(rid)["state"] != "abandoned"
    finally:
        stop()


def test_forced_undeploy_escapes_multiple_recoverable_records(tmp_path):
    """Two recoverable records refuse onboard, undeploy and adopt alike, and
    nothing in the product resolved them. The refusal now names force, and force
    reaches the teardown instead of being rejected ahead of it."""
    host, port, fleet, record_store, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        first = _stranded_record(record_store)
        second = _stranded_record(record_store)

        st, _, b = _req(host, port, "POST", "/api/devices/r1/undeploy", {},
                        headers=hh)
        assert st == 409
        assert b"multiple recoverable records" in b and b"force" in b

        st, _, b = _req(host, port, "POST", "/api/devices/r1/undeploy",
                        {"force": True}, headers=hh)
        assert st == 200, b
        _wait_onboard_job(host, port, ck, json.loads(b)["job_id"])
        assert record_store.get(first)["state"] == "abandoned"
        assert record_store.get(second)["state"] == "abandoned"
    finally:
        stop()


def test_undeploy_reports_a_corrupt_record_store_instead_of_adopt_it_first(
        tmp_path):
    """A record store that cannot be parsed is a SERVER fault, not proof that
    the device has no deployment. It used to read as "no record", so the console
    told the operator to adopt a device IRIS may already own -- which would
    write a record asserting an unverified deployment on top of a repairable
    file. The undeploy gate now reads strictly and reports the real fault."""
    host, port, fleet, record_store, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _stranded_record(record_store)          # IRIS DOES own this device
        with open(record_store.path, "w") as f: # ... and then the file rots
            f.write("{\"records\": {truncated")

        st, _, b = _req(host, port, "POST", "/api/devices/r1/undeploy", {},
                        headers=hh)
        assert st == 503, b
        problem = json.loads(b)
        assert problem["code"] == "service-unavailable"
        assert problem["error"] == "service unavailable"
        assert b"adopt it first" not in b, (
            "an unreadable store was reported as an unowned device")
    finally:
        stop()


def test_undeploy_still_says_adopt_when_there_is_genuinely_no_record(tmp_path):
    """The corrupt-store branch must not swallow the real no-record advice:
    an EMPTY (or absent) store still means the device was never deployed."""
    host, port, fleet, record_store, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/devices/r1/undeploy", {},
                        headers=hh)
        assert st == 409, b
        assert b"adopt it first" in b
    finally:
        stop()


def test_repeated_unusable_record_undeploy_stays_409(tmp_path):
    """The 409 path marks the record needs-reconcile on its way out. Doing that
    to a record already in needs-reconcile is not a legal transition, and the
    raise escaped do_POST -- so the first retry answered with a traceback and no
    JSON body instead of the reason."""
    host, port, fleet, record_store, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _stranded_record(record_store, resources=[])   # proves ownership of nothing
        for attempt in range(3):
            st, _, b = _req(host, port, "POST", "/api/devices/r1/undeploy", {},
                            headers=hh)
            assert st == 409, "attempt %d answered %s" % (attempt, st)
            assert b"does not prove ownership" in b
    finally:
        stop()


# ---------------------------------------------------------------------------
# Devices table: status filter parity, bulk image assignment, details drawer
# ---------------------------------------------------------------------------

def _webroot(name):
    with open(os.path.join(gui_server.WEBROOT, name)) as stream:
        return stream.read()


def test_every_status_the_cell_can_show_is_filterable():
    js = _webroot('app.js')
    body = js.split('function deviceStatus(d, devNow) {', 1)[1].split('\n  function ', 1)[0]
    rendered = set(re.findall(r"key: '([a-z-]+)'", body))
    options = js.split('var DEVICE_STATUS_OPTIONS = [', 1)[1].split('];', 1)[0]
    offered = set(re.findall(r"\['([a-z-]+)',", options))
    assert rendered and rendered <= offered and offered - rendered == {'offline'}
    assert 'statusOptions: DEVICE_STATUS_OPTIONS' in js
    component = _react_shell('inventory.jsx')
    assert "key === 'status'" in component and 'services.statusOptions' in component
    assert "status: 'status'" in _react_shell('inventory-model.mjs')


def test_assignment_models_and_controller_behavior():
    """Run actual ES modules, including all former picker source-pin behavior."""
    import shutil
    import subprocess
    from pathlib import Path
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for assignment client regressions")
    tests = Path(gui_server.WEBROOT).parent / "console-ui/tests/assignments.test.mjs"
    result = subprocess.run([node, "--test", str(tests)], text=True,
                            capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "# fail 0" in result.stdout


def test_row_and_bulk_assignment_share_the_react_picker():
    component, js = _react_shell('inventory.jsx'), _webroot('app.js')
    assert '<button type="button" className="linkish assign-btn"' in component
    assert 'onClick={() => services.assign?.(id)}' in component and 'assign: openRowAssign' in js
    assert "'— assign —'" in component and '`${assigned.length} image(s)`' in component
    assert '<select className="assign"' not in component
    assert 'assignments.openImages([id], true)' in js
    assert 'assignments.openImages(selectedIds())' in js
    assert 'id="iris-assignments-root" data-assignments-react' in _webroot('index.html')
    assert "function openImagePicker" not in js and "function assignImagesTo" not in js
    controller = _react_shell('assignments-controller.mjs')
    assert 'expect_image_ids: expect.get(id)' in controller
    assert 'const chosen = checkedIds(state.chosen, 10), ids = state.ids.slice()' in controller
    assert 'this.services.claimBulk(state.ids)' in controller
    assert 'inventory.rowBusy.size > 0' in controller
    assert "beginImageRead: function () { return assignments.beginImageRead(); }" in js
    assert 'assignments.prerequisites(inventory.snapshot())' in js


def test_assignment_picker_and_drawer_show_filename_once():
    model = _react_shell('assignments-model.mjs')
    assert 'row.filename !== row.id' in model
    assert '`${row.id} — ${row.filename}`' in model
    assert 'image.label' in _react_shell('assignments.jsx')
    drawer = _react_shell('device-details-model.mjs')
    assert '`${id} — ${filename}`' in drawer


def test_deployed_badge_requires_every_assigned_image_staged():
    """"Deployed" used to compare the single current_image_id/assigned_image_id
    pair, so a device with two images assigned could read "deployed" the
    moment just ONE of them finished. It must require every id in the
    assigned set to be in the heartbeat's staged_image_ids; an agent that
    predates the field (staged_image_ids absent) falls back to the old
    single-image check, unchanged."""
    app_js = _webroot("app.js")
    body = app_js.split("function deviceStatus(d, devNow) {", 1)[1]
    body = body.split("\n  function ", 1)[0]
    assert "rowAssignedIds(d)" in body
    assert "rowHasStaged" in body
    # EVERY assigned image, not just one -- pin the .every( call itself so a
    # regression to .some() (any image staged is "deployed") fails here
    # instead of only showing up as a wrong badge in the console.
    assert ".every(" in body
    staged_fn = app_js.split("function rowHasStaged", 1)[1][:300]
    assert "staged_image_ids" in staged_fn
    # the legacy fallback (no staged_image_ids on the heartbeat) is preserved
    assert "stage_state" in staged_fn and "current_image_id" in staged_fn


def test_deployment_drawer_lists_one_row_per_assigned_image():
    """The drawer said nothing about which images were staged where. One row
    per assigned image: id + state -- ready via staged_image_ids, error via
    errored_image_ids, everything else outstanding still in flight, with the
    tick's own stage_error carried alongside. Parked is deliberately NOT a
    console state: a parked image is simply absent from the assigned set, so
    it never gets a row here at all."""
    html = _react_shell("device-details.jsx")
    app_js = _webroot("app.js")
    assert 'id="di-img-rows"' in html
    body = _react_shell("device-details-model.mjs").split("function imageRows", 1)[1].split("export function boundarySteps", 1)[0]
    assert "assignedIds(device)" in body
    assert "staged.includes(id)" in body
    assert "stage_error" in body
    assert "parked" not in body.lower()
    assert "'di-img-rows').innerHTML" not in app_js
    assert "imageRows(state?.device" in html


def test_devices_side_reads_the_per_image_errors_the_agent_reports():
    """Review finding: the agent has reported errored_image_ids since this
    branch landed it, the swarm map's drawer reads it -- and the Devices side
    never did. deviceStatus() returned "deployed" before it looked at any
    error, and deployImageRows() called every non-current image "queued", so
    the console could say "A ready, B queued" for the same tick the map showed
    as "B — error", with the stage_error attached to no row at all.

    Both now resolve membership in errored_image_ids, in the SAME precedence
    the map uses (current errors override retained staged membership),
    and an errored image blocks the all-green "deployed" badge and
    gets its own filterable state instead."""
    app_js = _webroot("app.js")
    assert "function rowErroredIds(d)" in app_js
    errored_fn = app_js.split("function rowErroredIds(d) {", 1)[1][:300]
    assert "errored_image_ids" in errored_fn

    drawer = _react_shell("device-details-model.mjs").split("function imageRows", 1)[1].split("export function boundarySteps", 1)[0]
    assert "device.errored_image_ids" in drawer
    assert "'error'" in drawer
    # rowHasStaged rejects a current per-image error before consulting the
    # retained staged set, so drawer and device verdict cannot disagree.
    staged = app_js.split("function rowHasStaged(d, iid) {", 1)[1].split("\n  }", 1)[0]
    assert staged.index("errored_image_ids") < staged.index("staged_image_ids")
    assert drawer.index("errored.includes(id)") < drawer.index("staged.includes(id)")
    # Multi-image state is never derived from the identity pointer.
    # current_image_id is the first image of the set that produced heartbeat
    # data this tick (typically one already STAGED), not the one in flight, so
    # reading it as "currently transferring" mislabels whichever image it
    # lands on and leaves the real failure reading "queued".
    legacy_branch = drawer.split("else if (!perImage)", 1)[1]
    assert "device.current_image_id !== id" in legacy_branch

    body = app_js.split("function deviceStatus(d, devNow) {", 1)[1]
    body = body.split("\n  function ", 1)[0]
    assert "rowErroredIds(d)" in body
    # "deployed" is gated on no assigned image having errored...
    assert "!erroredIds.length" in body
    # ...and the errored set reads as its own state rather than falling
    # through to whatever the collapsed stage_state happens to be
    assert "key: 'image-failed'" in body


def test_deployment_details_open_in_a_right_hand_drawer():
    """It used to render below the devices table, so opening it on a fleet of
    any size put the details off-screen and made the operator scroll away from
    the row they had just clicked."""
    html = _react_shell("device-details.jsx")
    css = _webroot("styles.css")
    app_js = _webroot("app.js")
    panel = html.split('id="deploy-info-panel"', 1)[1].split(">", 1)[0]
    assert 'className="drawer"' in panel, panel
    drawer = css.split(".drawer {", 1)[1].split("}", 1)[0]
    assert "position:fixed" in drawer and "right:0" in drawer
    assert "top:0" in drawer and "bottom:0" in drawer
    # reduced motion is honoured, like the deployment-log drawer
    assert ".drawer { transition:none; }" in css
    # and Escape gets the operator out without aiming for the close control
    assert "closeDeployInfo" in app_js
    assert "event.key === 'Escape'" in html
    assert "controller.close()" in html


# ---------------------------------------------------------------------------
# In-flight work and deployment logs must not outlive the device they describe
# ---------------------------------------------------------------------------

def _serve_router_jobs(tmp_path, run_fn=None, now_fn=None):
    """_serve_router, but handing back the onboard service, its log dir and an
    audit file so a test can plant in-flight work and persisted logs."""
    import deployment_records
    os.makedirs(tmp_path, exist_ok=True)
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path); app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    audit_path = str(tmp_path / "audit.jsonl")
    log_dir = os.path.join(state, "deploy-logs")
    kw = {} if now_fn is None else {"now_fn": now_fn}
    fleet = gui_fleet.FleetStore(state, **kw)
    fleet.upsert(dict(_ROUTER_ROW))
    creds = gui_creds.CredentialStore(secrets_path)
    creds.set_profile("lab", {"name": "L", "device_user": "u", "device_pass": "p"})
    record_store = deployment_records.DeploymentRecordStore(state)
    onboard = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=run_fn or (lambda p, e, on: 0), record_store=record_store,
        log_dir=log_dir)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, certfile=None, record_store=record_store,
                                 audit_path=audit_path)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return ("127.0.0.1", port, fleet, onboard, log_dir, audit_path,
            srv.shutdown)


def _plant_deploy_log(log_dir, device_id, finished_at, action="onboard",
                      job_id="deadbeefcafe0001"):
    os.makedirs(log_dir, exist_ok=True)
    name = "%s-%s-%s-%s.log" % (finished_at, device_id, action, job_id)
    with open(os.path.join(log_dir, name), "w") as stream:
        stream.write(
            "# job=%s device=%s action=%s state=done rc=0 queued_at=%s "
            "started_at=%s finished_at=%s platform=router\n"
            % (job_id, device_id, action, finished_at - 2, finished_at - 1,
               finished_at))
        stream.write("done\n")
    return name


def test_delete_stops_the_device_s_in_flight_jobs(tmp_path, monkeypatch):
    """A job record is keyed on the bare device id, and delete never looked at
    one. A job left behind kept the busy guard armed against the NEXT device
    registered under that name: the opposite action was refused 409, the same
    action silently joined the dead job, and it cleared only after the job
    deadline -- two hours."""
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, fleet, onboard, _log_dir, audit_path, stop = _serve_router_jobs(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        onboard._jobs["ghost"] = {
            "id": "ghost", "device_id": "r1", "action": "onboard",
            "state": "queued", "queued_at": 1, "started_at": None,
            "finished_at": None, "lines": [], "returncode": None,
            "_line_bytes": 0, "_log_truncated": False, "record_id": None,
            "resolved": None, "env_extra": None}

        assert _req(host, port, "DELETE", "/api/devices/r1", headers=hh)[0] == 200

        assert onboard._jobs["ghost"]["state"] == "cancelled"
        with open(audit_path) as stream:
            events = [json.loads(l) for l in stream if l.strip()]
        detail = [e for e in events if e["event"] == "device_delete"][0]["detail"]
        assert "1 in-flight job stopped" in detail, detail

        # and the re-added device is not busy
        assert _req(host, port, "POST", "/api/devices", dict(_ROUTER_ROW),
                    headers=hh)[0] == 200
        st, _, b = _req(host, port, "POST", "/api/devices/r1/undeploy",
                        {"force": True}, headers=hh)
        assert st == 200, b
    finally:
        stop()


def test_deploy_logs_flag_a_previous_device_s_runs(tmp_path):
    """Logs deliberately survive a delete -- they are the record of what ran.
    So a rebuilt box added back under the same name inherited its
    predecessor's history and the console showed it as the new device's own."""
    clock = [1000]
    host, port, fleet, onboard, log_dir, _audit, stop = _serve_router_jobs(
        tmp_path, now_fn=lambda: clock[0])
    try:
        ck, _csrf = _auth(host, port)
        old = _plant_deploy_log(log_dir, "r1", 500, job_id="aaaaaaaaaaaa0001")
        recent = _plant_deploy_log(log_dir, "r1", 1500, job_id="bbbbbbbbbbbb0002")

        _, _, b = _req(host, port, "GET", "/api/deploy-logs?device_id=r1",
                       headers={"Cookie": ck})
        by_file = {l["file"]: l for l in json.loads(b)["logs"]}

        assert by_file[old]["previous_registration"] is True
        assert by_file[recent]["previous_registration"] is False
        # kept, never hidden: the run happened, just to a different machine
        assert len(by_file) == 2
    finally:
        stop()


def test_deploy_logs_flag_nothing_without_a_registration_stamp(tmp_path):
    """Devices registered before the stamp existed have none. Guessing would be
    worse than saying nothing, so nothing is flagged."""
    host, port, fleet, onboard, log_dir, _audit, stop = _serve_router_jobs(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        # a row as it looked before the stamp existed. FleetStore is
        # sharded per device now (see keyed_state.py) -- _serve_router_jobs
        # already upserted r1 before the server even started, so fleet.path
        # (fleet.json) is the retired legacy document, not the live store;
        # r1's row lives in its own shard.
        shard = os.path.join(keyed_state.shard_dir(fleet.path),
                             "%02x.json" % keyed_state.bucket_of("r1"))
        with open(shard) as stream:
            raw = json.load(stream)
        raw["r1"].pop("registered_at", None)
        with open(shard, "w") as stream:
            json.dump(raw, stream)
        _plant_deploy_log(log_dir, "r1", 500, job_id="cccccccccccc0003")

        _, _, b = _req(host, port, "GET", "/api/deploy-logs?device_id=r1",
                       headers={"Cookie": ck})
        entries = json.loads(b)["logs"]
        assert entries and all("previous_registration" not in e for e in entries)
    finally:
        stop()


def test_previous_registration_logs_are_labelled_in_the_console():
    app_js = _react_shell("device-details.jsx")
    assert "previous_registration" in app_js
    block = app_js.split("previous_registration", 1)[1][:400]
    assert "previous device" in block


def test_deploy_log_unknown_timestamp_is_not_a_previous_registration(tmp_path):
    name = _plant_deploy_log(str(tmp_path), "d1", 1000)
    log = tmp_path / name
    log.write_text(log.read_text().replace("finished_at=1000", "finished_at=unknown"))
    rows = gui_server._list_deploy_logs(str(tmp_path), device_id="d1", registered_at=1500)
    assert len(rows) == 1
    assert rows[0]["finished_at"] is None
    assert rows[0]["previous_registration"] is False
    # A missing header still has a known timestamp in its filename, but an
    # unknown result. Neither field should be invented by the Console.
    log.write_text("saved output without a header\n")
    rows = gui_server._list_deploy_logs(str(tmp_path), device_id="d1", registered_at=1500)
    assert rows[0]["finished_at"] == 1000
    assert rows[0]["state"] is None
    assert rows[0]["previous_registration"] is True


def test_console_fonts_are_served_with_woff2_type(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        names = [
            "Inter-Regular.woff2", "Inter-Medium.woff2",
            "Inter-SemiBold.woff2", "RobotoMono-Regular.woff2", "RobotoMono-Medium.woff2",
        ]
        # Sharp Sans is Cisco-licensed and deliberately untracked (staged at
        # deploy time); assert it only where the file is actually present so a
        # fresh public clone stays green while deployed trees keep the pin.
        if os.path.exists(os.path.join(gui_server.WEBROOT, "fonts", "SharpSans-Bold.woff2")):
            names.append("SharpSans-Bold.woff2")
        for name in names:
            status, headers, body = _req(host, port, "GET", f"/fonts/{name}")
            assert status == 200, name
            assert headers.get("Content-Type") == "font/woff2", name
            assert body[:4] == b"wOF2", name
    finally:
        stop()


def test_stylesheet_registers_selfhosted_faces_only():
    css = _webroot("styles.css")
    assert 'font-family: "Inter"' in css
    # The Console uses one family; standalone pages retain their own fonts.
    assert 'font-family: "Roboto Mono"' not in css
    assert 'font-family: "Sharp Sans"' not in css
    assert "https://" not in css  # CSP: no remote assets in the stylesheet
    assert "DM Sans" not in css


# ---------------------------------------------------------------------------
# Magnetic token layer, base typography, monospace restriction (facelift Task 3)
# ---------------------------------------------------------------------------

def test_stylesheet_defines_the_magnetic_token_layer():
    css = _webroot("styles.css")
    for tok in (
        "--canvas: #F0F1F2", "--surface: #FFFFFF", "--text-heading: #23282E",
        "--text-body: #373C42", "--text-secondary: #6F7680", "--rule: #E1E4E8",
        "--action: #2774D9", "--action-hover: #1D69CC", "--action-active: #0051AF",
        "--danger: #D93843", "--success: #398519", "--progress: #8D4EED",
        # yellow-95 / lavender-50 / lavender-95 extracted from magnetic.css --
        # this token file has no "indigo" family; "lavender" is its
        # blue-purple scale and is what the spec's indigo-50/indigo-95
        # placeholder values were sampled from (near-exact match).
        "--warning-tint: #FAEFB9", "--info: #5A68E5", "--info-tint: #EBEDFF",
        "--font-sans:", "--font-mono:", "--font-display:",
    ):
        assert tok in css, tok


def test_rainbow_stripe_is_retired():
    css = _webroot("styles.css")
    assert "linear-gradient(90deg,#00bceb" not in css
    # Every page in webroot shares this stylesheet, so an orphaned
    # class="stripe" hook can survive in any of them, not just index.html --
    # check them all, not just the page most people think to look at.
    html_names = sorted(
        n for n in os.listdir(gui_server.WEBROOT) if n.endswith(".html"))
    assert html_names, "no .html files found under WEBROOT"
    for name in html_names:
        assert 'class="stripe"' not in _webroot(name), name


def test_machine_class_replaces_blanket_table_monospace():
    css = _webroot("styles.css")
    # Wave A Magnetic fixes gave .machine its own type-role size/line-height
    # (P3: 14/20, uniform mono everywhere it's used) rather than leaving it
    # a bare font-family switch.
    assert ".machine { font-family: var(--font-mono); font-size:14px; line-height:20px; }" in css
    # the blanket rule that used to force every table cell into monospace,
    # regardless of whether the cell held prose or machine data, is gone
    tbl_td = css.split(".tbl td {", 1)[1].split("}", 1)[0]
    assert "font-family" not in tbl_td


# ---------------------------------------------------------------------------
# Responsive + accessibility foundations (facelift Task 6)
# ---------------------------------------------------------------------------

def test_console_declares_responsive_and_a11y_foundations():
    """Step-1 pin from the task brief: the four foundations must exist
    somewhere in the console webroot before any of the more targeted tests
    below can mean anything."""
    html = _webroot("index.html")
    css = _webroot("styles.css")
    assert 'id="iris-menu-toggle"' in _react_shell()
    assert "@media" in css and "prefers-reduced-motion" in css
    assert 'className="table-scroll"' in _react_shell('setup-packages.jsx')
    assert 'aria-live="polite"' in _react_shell('inventory.jsx')


def test_off_canvas_nav_toggle_wired():
    """React owns responsive navigation state, focus and route-close behavior."""
    js = _react_shell()
    css = _react_shell("shell.css")
    assert 'id="iris-menu-toggle"' in js
    assert 'aria-expanded={expanded}' in js
    assert 'aria-controls="iris-navigation"' in js
    assert 'aria-label="Toggle navigation"' in js
    assert "@media (max-width: 800px)" in css
    assert "transform: translateX(-100%)" in css
    assert ".iris-nav-open #iris-navigation-root" in css
    assert "transform: translateX(0)" in css
    assert "onClick={toggleNavigation}" in js
    assert "closeNavigation(true)" in js
    assert "window.addEventListener('hashchange', change)" in js
    assert "if (event.key === 'Tab')" in js
    assert "event.key === 'Escape'" in js
    assert "first?.focus()" in js and "last?.focus()" in js
    # Existing operational drawers retain their narrow-screen geometry.
    legacy = _webroot("styles.css")
    assert "width: 100vw;" in legacy


def test_every_operational_table_gets_a_scroll_wrapper():
    """Every <table> in the console -- Overview rollout, Images, the
    credential list, Devices, the deployment-details drawer's three
    tables, the onboarding batch panel, both setup/settings package
    tables, Server & build, Trusted CAs, Audit trail and Deployment logs --
    scrolls in its own box below its own natural width, rather than
    forcing the whole page to scroll sideways. Density and ids are
    untouched: this only wraps, it never rewrites a table's own markup."""
    html = _webroot("index.html")
    packages = _react_shell('setup-packages.jsx')
    for prefix in ('wz-pkg', 'setup-pkg', 'device-packages'):
        assert 'prefix="%s"' % prefix in packages
    assert 'aria-label="Package readiness evidence"><table className="tbl" id={prefix + \'-table\'}>' in packages
    # The unnamed credential table gets a wrapper too.
    assert html.count('<div class="table-scroll"') == html.count("<table")
    settings = _react_shell("settings.jsx")
    for tid in ("settings-info", "trust-tbl"):
        before = settings.split('id="%s"' % tid, 1)[0]
        assert "</div>" not in before[before.rfind('<div className="table-scroll"'):]
    component = (Path(gui_server.WEBROOT).parent / "console-ui/src/overview.jsx").read_text()
    assert '<div className="table-scroll" tabIndex={0} role="region" aria-label="Image rollout">' in component
    assert '<table className="tbl" id="ov-rollout">' in component
    images = _react_shell("images.jsx")
    for label, tid in (("Images available for import", "importable"), ("Image catalog", "images")):
        region = images.split('aria-label="%s">' % label, 1)[1].split('</div>', 1)[0]
        assert '<table className="tbl" id="%s">' % tid in region
    assert images.count('className="table-scroll" tabIndex={0} role="region"') == 2
    monitoring = _react_shell("monitoring.jsx")
    for label, tid in (("Audit events", "audit-tbl"), ("Deployment logs", "dl-tbl")):
        region = monitoring.split('aria-label="%s">' % label, 1)[1].split('</div>', 1)[0]
        assert '<table className="tbl" id="%s">' % tid in region
    assert monitoring.count('className="table-scroll" tabIndex={0} role="region"') == 2
    details = _react_shell("device-details.jsx")
    for label, tid in (("Device images", "di-img-tbl"), ("Deployment record", "di-tbl"),
                       ("Device deployment logs", "di-log-tbl")):
        region = details.split('aria-label="%s">' % label, 1)[1].split('</div>', 1)[0]
        assert '<table className="tbl" id="%s">' % tid in region
    assert details.count('className="table-scroll" tabIndex={0} role="region"') == 3
    activity = _react_shell("activity.jsx")
    region = activity.split('aria-label="Device jobs">', 1)[1].split('</div>', 1)[0]
    assert '<table className="tbl" id="batch-table">' in region
    assert 'className="table-scroll" tabIndex={0} role="region"' in activity
    inventory = _react_shell('inventory.jsx')
    region = inventory.split('aria-label="Device inventory">', 1)[1].split('</div>', 1)[0]
    assert '<table className="tbl dense" id="devices">' in region
    css = _webroot("styles.css")
    assert ".table-scroll {" in css and "overflow-x: auto;" in css


def test_dialogs_get_dialog_role_honestly():
    """Fix wave (reviewer Critical, controller-adjudicated): the image-detail
    drawer, the deployment-details drawer and the deployment-log drawer are
    NON-modal -- no backdrop, the page behind stays fully interactive while
    one is open (openImageInfo/openDeployInfo can each be called again for
    another row while their drawer is still showing the last one), so they
    get role=dialog WITHOUT aria-modal and WITHOUT a Tab-trap: either would
    be dishonest ARIA and would wrongly lock keyboard/screen-reader users
    out of the still-interactive page behind the drawer. The image-picker
    IS a real modal (a translucent backdrop, a choice to make and confirm)
    and keeps aria-modal + the Tab-trap unchanged.

    All four still move focus in on open and restore it to the opener on
    close -- that part of a dialog's contract holds regardless of modality."""
    html = _webroot("index.html")
    js = _webroot("app.js")
    picker = _react_shell('assignments.jsx')
    assert 'role="dialog" aria-modal="true"' in picker
    assert "function trapDialogFocus(container) {" in js
    assert "event.key !== 'Tab'" in picker and 'first?.focus()' in picker and 'last?.focus()' in picker
    # focus moves in on open and is restored to the opener on close, for
    # all four -- modal or not
    assert 'const active = document.activeElement' in picker and 'target.focus()' in picker
    assert "'#img-picker-cancel')?.focus()" in picker
    images = _react_shell("images.jsx")
    tag = images.split('id="img-info-panel"', 1)[1].split('>', 1)[0]
    assert 'role="dialog"' in tag and 'aria-modal' not in tag
    assert "trapDialogFocus" not in images
    assert "opener.current = event.currentTarget" in images
    assert "close.current?.focus()" in images and "opener.current.focus()" in images
    monitoring = _react_shell("monitoring.jsx")
    tag = monitoring.split('id="dl-drawer"', 1)[1].split('>', 1)[0]
    assert 'role="dialog"' in tag and 'aria-modal' not in tag
    assert "trapDialogFocus" not in monitoring
    assert "opener.current = event.currentTarget" in monitoring
    assert "close.current?.focus()" in monitoring and "opener.current.focus()" in monitoring
    details = _react_shell("device-details.jsx")
    tag = details.split('id="deploy-info-panel"', 1)[1].split('>', 1)[0]
    assert 'role="dialog"' in tag and 'aria-modal' not in tag
    assert "trapDialogFocus" not in details
    assert "controller.opener = document.activeElement" in details
    assert "close.current?.focus()" in details and "controller.opener.focus()" in details
    activity = _react_shell("activity.jsx")
    tag = activity.split('id="activity-panel"', 1)[1].split('>', 1)[0]
    assert 'role="dialog"' in tag and 'aria-modal' not in tag
    assert "trapDialogFocus" not in activity
    assert "close.current?.focus()" in activity
    assert "document.getElementById('dev-activity')?.focus()" in activity


def test_forms_get_persistent_field_labels():
    """Every operational input inside the console's ten <form> elements gets
    a real, persistent <label> -- not just a placeholder, which disappears
    the moment the operator starts typing and is not a reliable accessible
    name. Filter-toolbar controls (dev-filter-*, dl-action, iv-hour, ...)
    already carry aria-label from earlier work and are intentionally left
    as-is here; this only targets the ten <form>s the task brief scopes."""
    html = _webroot("index.html")
    css = _webroot("styles.css")
    assert ".field {" in css and ".field-label {" in css
    assert "font-size: 12px" in css.split(".field-label {", 1)[1].split("}", 1)[0]
    # a representative sample across different forms, not every field
    samples = {
        "iv-schedule-form": ("iv-mode", "iv-hour"),
    }
    for form_id, field_ids in samples.items():
        form = _react_shell('image-verification.jsx').split('id="%s"' % form_id, 1)[1].split("</form>", 1)[0]
        for fid in field_ids:
            assert 'htmlFor="%s"' % fid in form, "%s: no label for=%r" % (form_id, fid)
    form = _react_shell('device-forms.jsx')
    assert '<label className="field" htmlFor={id}' in form
    for fid in ('df-id', 'df-management-type', 'df-cred'):
        assert '<Field id="%s" label=' % fid in form
    for fid in ('cf-id', 'cf-pass'):
        assert "'%s'," % fid in form
    assert '<Field id={id} label={label}>' in form
    settings = _react_shell("settings.jsx")
    assert '<label className="field" htmlFor={id}' in settings
    assert '<label className="field field-wide" htmlFor={id}' in settings
    for fid in ("pw-cur", "pw-new", "pw-confirm", "cert-pem", "cert-key",
                "trust-pem", "ca-url", "td-endpoint", "ae-host", "ae-port", "ae-recipient"):
        assert "'%s', '" % fid in settings
    assert 'htmlFor="ca-source"' in settings


def test_error_and_status_regions_carry_live_roles():
    """Async status text gets role=status/aria-live=polite; the inline
    per-form error/outcome spans (reused for both a failure message and an
    .err.ok success message -- see the .err.ok source-order comment in
    styles.css) get role=alert, so either outcome is announced without the
    operator having to go find the message by sight."""
    html = _webroot("index.html")
    verification = _react_shell('image-verification.jsx')
    assert 'id={`iv-${action}-msg`}' in verification
    for action in ('schedule', 'refresh', 'offline'):
        assert '<Outcome state={state} action="%s" />' % action in verification
    assert 'role="status" aria-live="polite">{message?.text' in verification
    form = _react_shell('device-forms.jsx')
    for eid in ('df-err', 'cf-err'):
        assert 'role="alert"' in form.split('id="%s"' % eid, 1)[1].split('>', 1)[0]
    for source, sid in ((_react_shell('inventory.jsx'), 'dev-status'), (_react_shell('setup-packages.jsx'), 'wz-progress'),
                        (_react_shell('swarm-view.jsx'), 'swarm-summary')):
        tag = source.split('id="%s"' % sid, 1)[1].split(">", 1)[0]
        assert 'role="status"' in tag and 'aria-live="polite"' in tag, sid
    setup = _react_shell('setup-packages.jsx')
    assert "message('wz-msg')" in setup and 'id={id} role="status" aria-live="polite"' in setup
    settings = _react_shell("settings.jsx")
    assert 'id={id} role="status" aria-live="polite" tabIndex={-1}' in settings
    for sid in ("cert-status", "td-status", "ae-status", "sessions-info", "peer-tls-status"):
        tag = settings.split('id="%s"' % sid, 1)[1].split(">", 1)[0]
        assert 'role="status"' in tag and 'aria-live="polite"' in tag, sid
    details = _react_shell("device-details.jsx")
    for sid in ("di-note", "di-forget-host-key-status"):
        tag = details.split('id="%s"' % sid, 1)[1].split(">", 1)[0]
        assert 'role="status"' in tag and 'aria-live="polite"' in tag, sid
    # progress bars are exposed as progressbar, not silent divs. #prog
    # (the legacy publish progress bar this pin used to also cover) was
    # removed in the Wave A Magnetic fixes -- dead markup, never unhidden,
    # superseded by the per-file upload rows' own rowProg element (see the
    # rowProg assertions right below) -- so only the offline-upload bar
    # remains here.
    for pid in ("iv-offline-progress",):
        tag = verification.split('id="%s"' % pid, 1)[1].split(">", 1)[0]
        assert 'role="progressbar"' in tag, pid
        assert 'aria-valuemin={0}' in tag and 'aria-valuemax={100}' in tag, pid
    images = _react_shell("images.jsx")
    for eid in ("ii-override-note", "ii-release-msg"):
        assert 'role="alert"' in images.split('id="%s"' % eid, 1)[1].split('>', 1)[0]
    tag = images.split('id="status"', 1)[1].split('>', 1)[0]
    assert 'role="status"' in tag and 'aria-live="polite"' in tag
    assert 'role="progressbar" aria-valuemin={0} aria-valuemax={100}' in images
    assert 'aria-valuenow={Math.round(row.percent)}' in images


def test_reduced_motion_covers_more_than_the_two_drawers_and_shadows_are_tokenized():
    """Task 3/5 already pinned '.drawer { transition:none; }' verbatim
    (test_deployment_details_open_in_a_right_hand_drawer) -- this asserts
    the SAME line survives byte-for-byte while a second reduced-motion
    block widens the exemption to the nav rail and the other micro-
    interaction transitions this task's off-canvas nav and forms
    introduce. Also: the drawer/modal shadows migrate off the old
    Cisco-navy rgba() literals onto --shadow-lg (Task 6 owned-minors item);
    the modal backdrop keeps an rgba() scrim but de-branded to neutral
    black."""
    css = _webroot("styles.css")
    assert ".drawer { transition:none; }" in css
    assert "rgba(11,37,69" not in css
    assert "box-shadow:var(--shadow-lg);" in css
    assert "background:rgba(0,0,0,.35);" in css
    reduced_motion_blocks = css.count("@media (prefers-reduced-motion: reduce)")
    assert reduced_motion_blocks >= 3
    last_block = css.rsplit("@media (prefers-reduced-motion: reduce)", 1)[1]
    for selector in (".nav-rail", ".btn", ".chip", ".dropzone", ".progress .bar"):
        assert selector in last_block.split("}\n", 1)[0], selector


# ---------------------------------------------------------------------------
# Overview + Images hierarchy, Staging Boundary (facelift Task 7)
# ---------------------------------------------------------------------------

def test_staging_boundary_component_exists_and_ends_at_operator_control():
    """Keep the lifecycle labels and operator-control terminus in the React
    component, independent of the model supplying its states."""
    js = _react_shell("device-details.jsx")
    assert "function StagingBoundary(" in js
    for label in ("'Catalogued'", "'Source checked'", "'Assigned'",
                  "'Transferring'", "'Verified'", "'Staged'", "Operator control"):
        assert label in js, label


def test_staging_boundary_step_states_are_css_backed():
    """Brief Step 3: circles = done/current/upcoming/na CSS states, plus the
    status-pill substitution for a failed step. Every state StagingBoundary
    can render must have a real selector -- a typo'd class here would render
    invisibly rather than fail loudly."""
    js = _react_shell("device-details.jsx")
    fn = js.split("function BoundaryMarker", 1)[1].split("function StagingBoundary", 1)[0]
    for cls in ("boundary-circle is-done", "boundary-circle is-current",
                "boundary-dot", "boundary-circle is-na", "boundary-circle is-upcoming",
                "boundary-marker"):
        assert cls in fn, cls
    css = _webroot("styles.css")
    for selector in (".boundary-circle.is-done", ".boundary-circle.is-current",
                     ".boundary-dot", ".boundary-circle.is-na",
                     ".boundary-circle.is-upcoming", ".boundary-marker",
                     ".boundary-terminus", ".boundary-connector"):
        assert selector in css, selector
    # hatched terminus: repeating-linear-gradient on --surface-subtle, never
    # a literal inline style= (CSP) -- the marker/step/terminus builders
    # themselves emit no style= attribute anywhere.
    assert "repeating-linear-gradient" in css
    assert "style=" not in fn
    assert "style=" not in js.split("function StagingBoundary", 1)[1].split("function DeviceDetails", 1)[0]


def test_device_boundary_scoped_to_staging_lifecycle_not_agent_deployment():
    """HANDOFF §2: IRIS agent deployment (onboard/undeploy) and target-
    software staging are two different lifecycles. The Staging Boundary is
    about the second one only -- its failed-step derivation must key off
    placement-failed/image-failed, never onboard-failed/undeploy-failed.

    This used to pin Overview's own fleet-wide instance
    (overviewBoundarySteps); that band (#ov-boundary, "Active staging") was
    removed per operator decision (Wave C post-walk fix) along with the
    function that derived its steps. The device drawer's per-device
    instance (boundarySteps) is the sole survivor of the Staging
    Boundary's per-view step derivation and carries the exact same
    invariant, so the pin moves here rather than disappearing."""
    js = _react_shell("device-details-model.mjs")
    fn = js.split("function boundarySteps", 1)[1]
    assert "'placement-failed'" in fn
    assert "'image-failed'" in fn
    assert "'onboard-failed'" not in fn
    assert "'undeploy-failed'" not in fn
    # no assigned images collapses every step but 'assigned' to 'na', never
    # a guessed 'done'
    assert "if (!ids.length) return ['na', 'na', 'upcoming', 'na', 'na', 'na'];" in fn
    # no distinct on-device post-transfer verification signal exists in this
    # build -- admitted honestly as 'na', not inferred from a proxy
    assert "return ['done', source, 'done', transfer, 'na', staged];" in fn


def test_overview_needs_attention_is_worst_of_group_and_excludes_offline():
    """Spec: "Overview rollups = combined worst-of-group". Offline is a
    freshness modifier (Inactive), not a negative/severe/warning problem, so
    it must never be tallied into this band."""
    js = _webroot("app.js")
    fn = js.split("function overviewDeviceAttention(devs, devNow) {", 1)[1].split(
        "\n  }", 1)[0]
    assert "ATTENTION_LEVEL_RANK" in fn
    assert "deviceIsOffline" not in fn
    rank = js.split("var ATTENTION_LEVEL_RANK = {", 1)[1].split("}", 1)[0]
    assert "negative" in rank and "severe" in rank and "warning" in rank
    assert "'positive'" not in rank and "'inactive'" not in rank and "'info'" not in rank
    # the quarantine count feeds the images half of the same band
    img_fn = js.split("function overviewImageAttention(imgs) {", 1)[1].split(
        "\n  }", 1)[0]
    assert "i.quarantined" in img_fn


def test_devices_attention_filter_is_appended_not_added_to_the_status_options():
    js = _webroot('app.js')
    options = js.split('var DEVICE_STATUS_OPTIONS = [', 1)[1].split('];', 1)[0]
    assert '__attention' not in options
    assert ".concat([['__attention', 'Needs attention (any)']])" in _react_shell('inventory.jsx')
    assert "status: 'status'" in _react_shell('inventory-model.mjs')
    # Actual server matching is covered by test_devices_status_offline_and_attention_filters.
    assert 'deviceMatchesFilters' not in js


def test_images_catalog_leads_with_filename_and_verdict_pill():
    """Brief Step 5: catalog rows lead with the exact filename (.machine) +
    Cisco source-verification verdict pill; image id stays adjacent
    (.machine)."""
    component = _react_shell("images.jsx")
    thead = component.split('id="images">', 1)[1].split("</thead>", 1)[0]
    headers = [h.split("</th>")[0] for h in thead.split('<th scope="col">')[1:]]
    assert headers[:3] == ["File", "Verification", "Image ID"], headers
    row = component.split('<tbody id="rows">', 1)[1].split('</tbody>', 1)[0]
    assert row.index("{item.filename || '—'}") < row.index('<Verdict image={item} />') < row.index('>{item.id}</td>')


def test_images_needs_attention_toggle_filters_client_side_no_refetch():
    """Filtering uses the existing catalog; no new request or write."""
    component = _react_shell("images.jsx")
    controller = _react_shell("images-controller.mjs")
    assert 'state.images.filter(item => !!item.quarantined)' in component
    assert 'onChange={event => controller.setAttention(event.target.checked)}' in component
    assert 'setAttention(value) { this.update({attentionOnly: !!value}); }' in controller


def test_overview_fetches_devices_and_images_alongside_overview():
    """The attention band needs per-device and per-image rows Overview did
    not fetch before Task 7 -- all three requests must be issued together
    (Promise.all), not serially, so the dashboard is not three round trips
    slower than it used to be. (The aggregate Staging Boundary this test
    used to also cite was the other original consumer of /api/devices and
    /api/images here; it was removed per operator decision -- Wave C -- but
    the attention band alone still needs both, so the three-way Promise.all
    stays exactly as load-bearing as before.)"""
    js = _webroot("app.js")
    fn = js.split("async function refreshOverview() {", 1)[1].split("\n  }", 1)[0]
    assert "Promise.all(" in fn
    # Task 10 added an AbortController signal to each fetch call (generation/
    # abort protection); these check the endpoint is still fetched, not the
    # exact argument list.
    assert "fetch('/api/v1/overview'" in fn
    assert "fetch('/api/v1/devices'" in fn
    assert "fetch('/api/v1/images'" in fn
    assert "renderOverviewAttention(" in fn
    assert "renderOverviewBoundary(" not in fn


def test_overview_fleet_totals_carry_precise_denominators():
    """Brief Step 4, band 3: fleet totals with precise denominators. Every
    ratio card names what it is a fraction OF, not a bare count."""
    model = (Path(gui_server.WEBROOT).parent / "console-ui/src/overview-model.mjs").read_text()
    assert "'Waiting for heartbeat'" in model
    for sub in ("of ${ov.devices}", "of ${ov.assigned}"):
        assert sub in model, sub


def test_card_component_matches_spec_padding_radius_and_elevation():
    """spec §4 card rules: 24px padding, --radius-card, --shadow-xs."""
    css = _webroot("styles.css")
    card_rule = css.split(".card {", 1)[1].split("}", 1)[0]
    assert "padding:var(--sp-xl)" in card_rule
    assert "border-radius:var(--radius-card)" in card_rule
    assert "box-shadow:var(--shadow-xs)" in card_rule


def test_overview_attention_band_distinguishes_no_data_from_all_clear():
    """The controller reports each failed secondary; React renders it neutrally.

    Executable model/browser checks also cover failed, clean and mixed results.
    """
    js = _webroot("app.js")
    model = (Path(gui_server.WEBROOT).parent / "console-ui/src/overview-model.mjs").read_text()
    unavailable_card = model.split("if (unavailable) cards.push(", 1)[1].split("else if (!cards.length)", 1)[0]
    assert "level: 'inactive'" in unavailable_card
    assert "Fleet status unavailable" in unavailable_card
    assert "positive" not in unavailable_card and "All clear" not in unavailable_card
    assert "else if (!cards.length)" in model

    overview_fn = js.split("async function refreshOverview() {", 1)[1].split("\n  }", 1)[0]
    assert "failed: true" in overview_fn
    assert "dbody.failed || imgsBody.failed" in overview_fn
    assert "renderOverviewAttention(devs, devNow, imgs, fleetDataUnavailable)" in overview_fn
    bridge = js.split("function renderOverviewAttention(", 1)[1].split("\n  }", 1)[0]
    assert "unavailable: fleetDataUnavailable" in bridge


# ---------------------------------------------------------------------------
# Task 8: Devices density + the three carried status fixes (facelift Phase
# 4b/5) -- Step 1 pins, written against real recon (facelift-contracts.md §7
# for M2, §8 for job wiring), watched RED before the fix landed.
# ---------------------------------------------------------------------------

def test_devices_filter_offers_only_producible_options():
    assert "['legacy', 'Inventory only — management type not chosen']" in _react_shell('inventory.jsx')
    assert "managementType: 'management_type'" in _react_shell('inventory-model.mjs')
    row = {'device_id': 'old', 'management_type': 'legacy_routed'}
    assert gui_server.target_row_matches(row, {'management_type': 'legacy'}, now=1)
    assert not gui_server.target_row_matches(row, {'management_type': 'xr-host'}, now=1)


def test_device_status_cell_carries_job_step_and_elapsed():
    """jobPhaseSuffix(job) formats the "[n/m] · Xm" suffix an in-progress
    onboard/undeploy pill carries, e.g. "Undeploying [3/5] · 12 min"; at or
    above 60 minutes it switches to "1 h 12 min". Elapsed derives from the
    job's own SERVER started_at timestamp (never a client-clock delta that
    would reset on refresh) -- LAST_DEV_NOW is the same server clock
    refreshDevices() already reads for offline-freshness math."""
    js = _webroot("app.js")
    assert "function jobPhaseSuffix(job) {" in js
    fn = js.split("function jobPhaseSuffix(job) {", 1)[1].split("\n  }", 1)[0]
    assert "job.started_at" in fn
    assert "LAST_DEV_NOW" in fn
    assert "' min'" in fn
    assert "' h '" in fn
    assert "60" in fn
    assert "[" in fn and "]" in fn
    # A queued job never carries started_at server-side (gui_onboard.py only
    # stamps it once the job actually starts running) -- this early-return
    # guard is what keeps a queued job from ever rendering an elapsed
    # duration it hasn't accrued yet.
    assert fn.strip().startswith("if (!job || !job.started_at) return '';")
    # wired into the status cell for an active job only, matched by action
    assert "jobPhaseSuffix(activeJob)" in js
    assert "LAST_JOBS_BY_DEVICE" in js


def test_offline_is_expected_during_active_undeploy():
    """A device mid-undeploy that has already gone stale/offline (its agent
    is deactivated at undeploy step [1/5], well before the rest of teardown
    runs) must not read as a bare, alarming "Offline (no recent
    heartbeat)" -- that is the expected shape of a healthy undeploy, not a
    fault. The pill stays visible (never hidden) with an honest label and a
    title explaining why.

    Review finding (fix wave 1): deviceStatus() sets st.key 'undeploying'
    for BOTH a queued and a running job -- it only reads d.onboard_state,
    never the job record itself -- so gating on st.key alone mislabeled a
    device stuck behind the onboard concurrency cap (job still queued, never
    touched the device) as "expected offline" before teardown had even
    started. The gate must additionally require the CROSS-REFERENCED job's
    own state === 'running': a queued undeploy job's offline device keeps
    the normal, honest "no recent heartbeat" pill."""
    js = _webroot("app.js")
    fn = js.split("function deviceStatusPresentation(d, devNow) {", 1)[1].split(
        "\n  }", 1)[0]
    assert "Offline (expected during undeploy)" in fn
    assert "[1/5]" in fn
    # the actual gate: job state 'running' AND the status key, not either alone
    assert "if (activeJob && activeJob.state === 'running' && st.key === 'undeploying') {" in fn
    # regression guard: the old, insufficient gate (bare st.key, no job-state
    # check) must not be what decides the label any more
    assert "if (st.key === 'undeploying') {" not in fn


# ---------------------------------------------------------------------------
# Task 9: Setup/Settings/Monitoring get the Magnetic card hierarchy. Same
# source-guard idiom throughout this file (no JS runtime harness exists in
# this repo).
# ---------------------------------------------------------------------------

def test_settings_forms_are_wrapped_in_bounded_card_sections():
    """Settings headings belong to live card ancestors, including TLS cards
    with additional classes; a closed earlier card must not satisfy this."""
    from html.parser import HTMLParser

    class CardHeadings(HTMLParser):
        void_tags = {"area", "base", "br", "col", "embed", "hr", "img",
                     "input", "link", "meta", "param", "source", "track", "wbr"}

        def __init__(self):
            super().__init__()
            self.stack = []
            self.heading = None
            self.headings = {}

        def handle_starttag(self, tag, attrs):
            classes = dict(attrs).get("class", "").split()
            if tag == "h3":
                self.heading = ([], any("card" in node[1]
                                        for node in self.stack))
            if tag not in self.void_tags:
                self.stack.append((tag, classes))

        def handle_data(self, data):
            if self.heading is not None:
                self.heading[0].append(data)

        def handle_endtag(self, tag):
            if tag == "h3" and self.heading is not None:
                text, in_card = self.heading
                self.headings["".join(text).strip()] = in_card
                self.heading = None
            for index in range(len(self.stack) - 1, -1, -1):
                if self.stack[index][0] == tag:
                    del self.stack[index:]
                    break

    html = _webroot("index.html")
    settings = html.split('id="view-settings"')[1].split("</section>")[0]
    parsed = CardHeadings()
    parsed.feed(settings)
    for heading in ("Telemetry destination",):
        assert parsed.headings.get(heading) is True, \
            "%s must have an open card ancestor" % heading
    component = _react_shell("settings.jsx")
    assert '<div className="card" data-iv-action="schedule"><h3>Schedule</h3>' in _react_shell('image-verification.jsx')
    for group, heading in (("peer", "Peer transfer TLS"), ("cert", "Console browser certificate"),
                           ("trust", "Trusted certificate authorities"), ("ca", "Public CA bundle"),
                           ("ae", "Audit export")):
        assert ('data-setting="%s"><h3>%s</h3>' % (group, heading)) in component
    # Runtime card ancestry and action hierarchy are checked in settings-smoke.mjs.


def test_settings_card_never_wraps_a_template_root():
    """The telemetry card wraps a React portal target, never inert markup."""
    html = _webroot("index.html")
    assert 'id="tpl-td-form"' not in html
    assert '<div class="card"><h3>Telemetry destination</h3><div id="td-mount">' in html
    assert 'id="wz-td-mount"' in _react_shell('setup-packages.jsx')


def test_monitoring_panes_carry_a_scope_tag_and_stay_distinct():
    html = _react_shell("monitoring.jsx")
    css = _webroot("styles.css")
    audit_pane = html.split('id="monitoring-pane-audit"', 1)[1]
    assert 'id="audit-scope-tag"' in audit_pane.split("<h3>", 1)[1].split(
        "</h3>", 1)[0]
    dl_pane = html.split('id="monitoring-pane-deploylogs"', 1)[1]
    assert 'id="dl-scope-tag"' in dl_pane.split("<h3>", 1)[1].split("</h3>", 1)[0]
    # each pane keeps its own description, distinct from the other's
    assert "Every settings change" in audit_pane.split("<h3>", 1)[1][:600]
    assert "Onboarding and undeployment logs" in dl_pane.split("<h3>", 1)[1][:600]
    assert ".scope-tag {" in css
    assert "ranges[audit.range].label" in html and "ranges[logs.range].label" in html
    assert "return monitoringCommand('select', null, sub);" in _webroot("app.js")


def test_table_scroll_fade_color_is_parameterized_for_cards():
    """Carried seam: .table-scroll's fade used to hardcode --canvas, which
    reads as a visible seam now that several sit inside a --surface .card
    (Task 9). A --scroll-fade custom property defaults to --canvas and is
    overridden inside .card, so every table-scroll NOT inside a card is
    visually unchanged."""
    css = _webroot("styles.css")
    rule = css.split(".table-scroll {", 1)[1].split("\n}", 1)[0]
    assert "--scroll-fade: var(--canvas);" in rule
    assert "var(--scroll-fade)" in rule
    assert ".card .table-scroll { --scroll-fade: var(--surface); }" in css


def test_bulk_bar_names_selection_scope():
    component, model, controller = (_react_shell(name) for name in ('inventory.jsx', 'inventory-model.mjs', 'inventory-controller.mjs'))
    assert 'id="sel-scope-text" hidden={!scope.text}' in component
    assert 'id="sel-scope-all" hidden={!scope.offerAll}' in component
    assert 'controller.selectAll()' in component and 'controller.clearSelection()' in component
    assert 'matchIds.filter(id => selected.has(id)).length' in model
    assert 'total > 0 && complete && matched === total' in model
    assert 'selected outside this' in model and 'matches are unconfirmed' in model
    assert 'pageQuery(this.state.filters, offset, 1000)' in controller
    assert 'new Set([...this.state.selected, ...ids])' in controller
    assert "'sel-scope-all'" not in _webroot('app.js'), 'No legacy mutation inside the React root'


def test_table_type_roles_are_magnetic_p3_p4():
    """Wave A Magnetic table-fidelity fixes (post-walk audit, root cause of
    the "fonts are off" complaint): .tbl body copy is P3 (14/20), dense
    machine-data cells inside a table step down to P4 (12/18) via a scoped
    .tbl .machine override, and headers use sentence case (the markup is
    already written sentence-case) rather than an uppercase/letter-spaced
    treatment."""
    css = _webroot("styles.css")
    assert ".tbl { width:100%; border-collapse:collapse; font-size:14px; line-height:20px; }" in css
    assert ".tbl .machine { font-size:12px; line-height:18px; }" in css
    tbl_th = css.split(".tbl th {", 1)[1].split("}", 1)[0]
    assert "text-transform:uppercase" not in tbl_th


# ---------------------------------------------------------------------------
# Left nav: Magnetic anatomy fixes (post-walk audit, Wave B)
# ---------------------------------------------------------------------------

def test_nav_icon_symbols_vendored_in_sprite():
    """Wave B fix 1: the 8 Phosphor BOLD glyphs the left nav needs (the six
    primary destinations, the Setup sub-item, and the off-canvas hamburger)
    are vendored as <symbol> entries in the existing icon-sprite <svg> --
    same convention as the status-pill icons (Task 4): fill="currentColor",
    viewBox 0 0 256 256, referenced by id from the nav's own anchors."""
    html = _webroot("index.html")
    sprite = html.split('<svg class="icon-sprite"', 1)[1].split("</svg>", 1)[0]
    for icon in ("i-nav-gauge", "i-nav-stack", "i-nav-hard-drives",
                 "i-nav-share-network", "i-nav-gear", "i-nav-pulse",
                 "i-nav-list-checks", "i-nav-list"):
        assert ('<symbol id="%s" viewBox="0 0 256 256" fill="currentColor">' % icon) \
            in sprite, icon


def test_nav_items_carry_leading_icons():
    """React destinations retain local sprite icons and readable labels."""
    js = _react_shell()
    for icon in ("gauge", "stack", "hard-drives", "share-network", "gear", "pulse"):
        assert "'%s'" % icon in js
    assert '<svg className="iris-shell-icon" aria-hidden="true">' in js
    assert '<use href={`#i-nav-${name}`}' in js
    assert '<span>{label}</span>' in js
    assert 'aria-label={label}' in js
    assert 'items.map(([child, name]) => link(`${id}/${child}`, name))' in js


def test_hamburger_uses_sprite_glyph_and_product_name_drops_diamond():
    """React preserves the local menu glyph without an invented logomark."""
    js = _react_shell()
    assert "☰" not in js and "◈" not in js
    assert '<Icon name="list" />' in js
    assert 'Intelligent Release &amp; Image Staging' in js


def test_monitoring_group_stays_inside_react_navigation():
    """Monitoring uses an in-rail accordion; Settings has local sections."""
    js = _react_shell()
    css = _react_shell("shell.css")
    assert 'className="iris-navigation-children" hidden={!expanded[id]}' in js
    assert 'aria-controls={`iris-group-${id}`}' in js
    assert 'aria-expanded={expanded[id]}' in js
    assert ".iris-navigation-children[hidden] { display: none; }" in css
    assert ".iris-navigation-children .iris-navigation-link" in css


def test_bulk_bar_action_buttons_capped_via_more_menu():
    component = _react_shell('inventory.jsx')
    actions = component.split('className="selbar-actions"', 1)[1].split('id="more-pop"', 1)[0]
    assert re.findall(r"bulkButton\('([^']+)'", actions) == ['assign-images-selected', 'undeploy-selected', 'onboard-selected']
    assert actions.count('id="more-menu-btn"') == 1 and 'aria-label="More actions"' in actions
    assert "bulkButton('onboard-selected', 'Onboard…', 'btn')" in actions
    menu = component.split('id="more-pop"', 1)[1].split('</div>', 1)[0]
    for action in ('adopt-selected', 'quarantine-selected', 'release-selected', 'set-cred-selected', 'set-role-selected', 'schedule-selected', 'delete-selected'):
        assert "bulkButton('" + action + "'" in menu
    assert 'className="menu-divider"' in menu and "'menu-item danger menu-close'" in menu
    assert 'id="cred-selected"' not in menu
    modal = _react_shell('assignments.jsx')
    assert 'id="cred-selected"' in modal and "'apply-cred-selected'" in modal


def test_bulk_modals_close_cleanly_and_the_total_agrees_with_the_total():
    """Three defects found reviewing the Magnetic action-layout pass, all in
    the new modal/filter-bar code and none of them reachable by the static
    guards around them.

    1. The merged filter-bar Total agreed its noun with the MATCHED count, so
       filtering twelve devices down to one read "1 of 12 result". In the
       "X of N" form the noun belongs to N, and #dev-count is the page's only
       count now, so the wrong form sat on screen for the most common thing
       the search box is used for.
    2. openModal captured document.activeElement as the element to restore
       focus to -- but "Set credential…" lives inside the #more-pop dropdown
       and carries .menu-close, so wireMenu hides it immediately afterwards.
       focus() on a display:none element is a no-op, so keyboard focus was
       dropped to the document every single time that modal closed. The opener
       is resolved to the popover's own trigger, which stays visible.
    3. A backdrop `e.target === overlay` click-closer misfires on the second
       click of a double-click (the backdrop the first click raised is now
       under the pointer) and on a drag-selection released past the dialog
       edge (a click is dispatched at the mousedown/mouseup common ancestor) --
       the latter closing the undeploy modal while its force help text is
       being read. There is no backdrop closer; ✕ / Cancel / Escape are the
       ways out, matching the pre-existing image picker on this same page."""
    js = _webroot("app.js")

    # 1 -- both branches pluralise on `total`
    component = _react_shell('inventory.jsx')
    assert "state.rows.length === state.total ? state.total : state.rows.length + ' of ' + state.total" in component
    assert "result${state.total === 1 ? '' : 's'}" in component
    # the old form agreed with the matched count
    assert "((devs.length === total ? total : devs.length) === 1 ? '' : 's')" not in js

    # React actions return focus to the stable menu trigger and trap Tab.
    actions = _react_shell('inventory-actions.jsx')
    assert "opener.current" in actions and "[aria-expanded]" in actions
    assert "function openModal(" not in js and "function wireModal(" not in js
    for name in ('inventory-actions.jsx', 'role-actions.jsx', 'policy-dialogs.jsx'):
        modal = _react_shell(name)
        assert "event.key === 'Escape'" in modal
        assert "event.key !== 'Tab'" in modal
        assert "controller.close()" in modal
        assert "event.target === event.currentTarget" not in modal
    # every modal still offers an explicit close control, per Magnetic Modal
    component = _react_shell('inventory-actions.jsx')
    assert "id={action + '-cancel'}" in component and "id={action + '-modal-x'}" in component
    assert "controller.close()" in component and "event.key === 'Escape'" in component
    assert "opener.current.focus()" in component and "first?.focus()" in component


def test_nav_divider_grid_spacing_and_compact_anatomy_comment():
    """The independent React shell owns navigation spacing and grouping."""
    from pathlib import Path
    source = Path(gui_server.WEBROOT).parent / "console-ui" / "src"
    jsx = (source / "main.jsx").read_text()
    css = (source / "shell.css").read_text()
    assert '<div className="iris-nav-divider" />' in jsx
    assert jsx.index('primary.map(') < jsx.index('iris-nav-divider') < jsx.index("link('settings/general'")
    assert '.iris-nav-divider' in css
    assert '.iris-header { position: fixed;' in css and 'height: 56px;' in css
    assert '#iris-navigation-root { flex: 0 0 280px;' in css
    assert '.iris-navigation-children .iris-navigation-link' in css


# ---------------------------------------------------------------------------
# Wave D: post-walk fixes (dense Devices type, flyout outside-click close,
# Images import blurb)
# ---------------------------------------------------------------------------

def test_devices_table_gets_the_dense_type_modifier():
    """Wave D fix 1 (operator, AFTER the Wave A type-role fix had already
    landed: "still different fonts"). Devices is a 12-data-column table where a
    single row mixed 14px sans (.dev-id, plain-text cells like Management
    type), 12px mono (.machine), and 14px inherited control text (row
    selects/buttons) -- individually "correct" per type role, but
    heterogeneous enough to read as inconsistent. .tbl.dense steps every
    cell's TEXT SIZE to one P4 scale (12/18); family still varies by data
    kind (sans vs --font-mono), weight 500 stays on .dev-id. Scoped to
    #devices only -- Images (5 columns) stays on the base 14px .tbl scale,
    unmodified."""
    html = _webroot("index.html")
    css = _webroot("styles.css")
    assert '<table className="tbl dense" id="devices">' in _react_shell('inventory.jsx')
    # Images keeps the base (non-dense) table scale this wave
    assert '<table className="tbl" id="images">' in _react_shell("images.jsx")
    assert ".tbl.dense td { font-size:12px; line-height:18px; }" in css
    # row controls (selects/buttons) match the row's own 12px text
    assert "#dev-rows select, #dev-rows button { font-size:12px; }" in css
    # .dev-id steps down from 14px to 12/18, weight 500 preserved
    assert "#dev-rows .dev-id { font-family: var(--font-sans); font-size: 12px; " \
        "line-height: 18px; font-weight: 500; color: var(--text-heading); }" in css


def test_react_navigation_groups_toggle_without_legacy_menu_mutation():
    """Accordion groups and modal mobile navigation have separate ownership."""
    js = _react_shell()
    legacy = _webroot("app.js")
    assert "function toggleGroup(id)" in js
    assert "onClick={() => toggleGroup(id)}" in js
    assert "hidden={!expanded[id]}" in js
    assert "setExpanded(previous => ({ ...previous, [id]: !previous[id] }))" in js
    assert "window.addEventListener('hashchange', change)" in js
    assert "onClick={() => closeNavigation()}" in js
    assert 'aria-label="Close navigation"' in js
    assert "closeNavigation(true)" in js
    assert "wireMenu('nav-settings'" not in legacy
    assert "wireMenu('nav-monitoring'" not in legacy
    # Help remains a dismissible popover, including keyboard focus return.
    assert "document.addEventListener('pointerdown', click)" in js
    assert "if (event.key === 'Escape')" in js
    assert "trigger.current?.focus()" in js


def test_images_import_blurb_drops_the_subdirectory_examples():
    """Wave D fix 3 (operator: wanted the worked examples gone from the
    Images import blurb -- the mechanism (a real subdirectory, the scanned
    extensions, IMAGES_ROOT) stays, only the illustrative "such as
    /opt/images/iosxe/c9300/ or /opt/images/iosxr/" clause goes."""
    html = _react_shell("images.jsx")
    # the worked examples are gone outright -- these substrings do not
    # appear anywhere else in the page
    assert "such as" not in html
    assert "iosxe/c9300" not in html
    assert "/opt/images/iosxr/" not in html
    assert 'Images copied onto the server under' in html
    assert '/opt/images</span> — including any subdirectory — are offered for import below without uploading.' in html
    for suffix in ('.bin', '.iso', '.tar', '.rpm'):
        assert '<span className="machine">%s</span>' % suffix in html
    assert '<span className="machine">IMAGES_ROOT</span> to scan a different directory.' in html


# ---- fix-wave regressions: HTTP layer, session lifecycle, console sources ----

def test_negative_content_length_rejected_before_any_read(tmp_path):
    """IRIS-06-001: int() accepts a sign and rfile.read(-1) reads until EOF
    with no cap, pre-auth. The server must answer 400 without reading. At
    the review commit this recv blocks for the 60 s handler timeout."""
    host, port, _, stop = _serve(tmp_path)
    try:
        s = socket.create_connection((host, port), timeout=5)
        s.sendall(b"POST /api/login HTTP/1.1\r\nHost: x\r\n"
                  b"Content-Type: application/json\r\nContent-Length: -1\r\n\r\n")
        resp = b""
        while True:
            chunk = s.recv(4096)           # server answers and closes
            if not chunk:
                break
            resp += chunk
        s.close()
        assert b" 400 " in resp.split(b"\r\n", 1)[0]
        assert b"bad content-length" in resp
    finally:
        stop()


def test_unauthenticated_post_rejected_before_body_is_buffered(tmp_path):
    """IRIS-06-004: session + CSRF are checked BEFORE the body is read. The
    client declares the 8 MiB CSV cap but sends only the 64 KiB drain
    allowance; the 401 must arrive without the rest. At the review commit
    the server read all 8 MiB first, so this recv timed out."""
    host, port, _, stop = _serve(tmp_path)
    try:
        s = socket.create_connection((host, port), timeout=5)
        declared = 8 * 1024 * 1024
        head = ("POST /api/devices/import-csv HTTP/1.1\r\nHost: x\r\n"
                "Content-Type: text/csv\r\nContent-Length: %d\r\n\r\n"
                % declared).encode()
        s.sendall(head + b"x" * (64 * 1024))
        resp = s.recv(4096)
        s.close()
        assert b" 401 " in resp.split(b"\r\n", 1)[0]
        # a session without CSRF is rejected the same way, before the read
        ck, _ = _auth(host, port)
        s = socket.create_connection((host, port), timeout=5)
        head = ("POST /api/devices/import-csv HTTP/1.1\r\nHost: x\r\nCookie: %s\r\n"
                "Content-Type: text/csv\r\nContent-Length: %d\r\n\r\n"
                % (ck, declared)).encode()
        s.sendall(head + b"x" * (64 * 1024))
        resp = s.recv(4096)
        s.close()
        assert b" 403 " in resp.split(b"\r\n", 1)[0]
    finally:
        stop()


def test_tls_handshake_is_not_on_the_accept_thread(tmp_path, monkeypatch):
    """IRIS-06-002: one idle TCP connection (no ClientHello) used to park the
    whole console in accept() until it went away. With the handshake in the
    worker thread, a second client's TLS request still completes."""
    cert, key = _gen_cert_pair(tmp_path, "iris-builtin", "accept-thread")
    builtin = tmp_path / "cert.pem"
    builtin.write_text(cert + key)
    monkeypatch.setenv("IRIS_CERT", str(builtin))
    monkeypatch.setenv("IRIS_GUI_CERT", str(tmp_path / "absent-gui-cert.pem"))
    host, port, srv, stop = _serve_tls(tmp_path, str(builtin))
    try:
        assert srv.tls_active is True
        assert not isinstance(srv.socket, ssl.SSLSocket)   # listener stays plain
        idle = socket.create_connection((host, port), timeout=5)  # never handshakes
        time.sleep(0.3)
        assert _peer_cert_der(host, port) == _first_cert_der(cert)  # 5 s timeout
        idle.close()
    finally:
        stop()


def _serve_tls_admin(tmp_path, certfile):
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    app.set_admin("admin", "pw")
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=certfile)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", srv.server_address[1], srv.shutdown


def _https_req(host, port, method, path, body=None, headers=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c = http.client.HTTPSConnection(host, port, context=ctx, timeout=5)
    hdrs = dict(headers or {})
    payload = None
    if body is not None:
        payload = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    c.request(method, path, body=payload, headers=hdrs)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r.status, dict(r.getheaders()), data


def test_login_cookie_is_secure_over_tls(tmp_path, monkeypatch):
    """The Secure attribute follows the listener: present under TLS (login
    and the logout expiry cookie alike), absent on the plaintext opt-in."""
    cert, key = _gen_cert_pair(tmp_path, "iris-builtin", "secure-cookie")
    builtin = tmp_path / "cert.pem"
    builtin.write_text(cert + key)
    monkeypatch.setenv("IRIS_CERT", str(builtin))
    monkeypatch.setenv("IRIS_GUI_CERT", str(tmp_path / "absent-gui-cert.pem"))
    host, port, stop = _serve_tls_admin(tmp_path, str(builtin))
    try:
        st, h, b = _https_req(host, port, "POST", "/api/login",
                              {"username": "admin", "password": "pw"})
        assert st == 200
        assert "Secure" in h["Set-Cookie"] and "HttpOnly" in h["Set-Cookie"]
        ck = h["Set-Cookie"].split(";")[0]
        st, h, _ = _https_req(host, port, "POST", "/api/logout",
                              headers={"Cookie": ck,
                                       "X-CSRF-Token": json.loads(b)["csrf"]})
        assert st == 200 and "Secure" in h["Set-Cookie"] and "Max-Age=0" in h["Set-Cookie"]
    finally:
        stop()


def test_sse_idle_expiry_emits_terminal_end_frame(tmp_path, monkeypatch):
    """IRIS-06-005: the idle exit used to close the stream silently, so the
    client could not tell a stalled job from a dead server. It now ends
    with `event: end / data: idle`."""
    monkeypatch.setattr(gui_server, "_SSE_IDLE", 1)
    monkeypatch.setattr(gui_server, "_SSE_KEEPALIVE", 0.2)
    release = threading.Event()

    def run_fn(p, e, on):
        release.wait(10); return 0          # running, silent

    host, port, stop = _serve_onboard(tmp_path, run_fn)
    try:
        ck, csrf = _auth(host, port)
        st, _, b = _req(host, port, "POST", "/api/devices/d1/onboard", {},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200
        jid = json.loads(b)["job_id"]
        conn = http.client.HTTPConnection(host, port, timeout=15)
        conn.request("GET", "/api/onboard/jobs/%s/stream" % jid,
                     headers={"Cookie": ck})
        resp = conn.getresponse()
        started = time.time()
        body = resp.read()                    # server closes on idle expiry
        assert time.time() - started < 8
        conn.close()
        assert b"event: end\ndata: idle\n\n" in body
        assert b"event: end\ndata: done" not in body
    finally:
        release.set()
        stop()


def test_api_responses_are_no_store_and_static_assets_revalidate(tmp_path):
    """IRIS-06-006: session-gated JSON never lands in a disk cache; the
    un-hashed SPA assets revalidate cheaply (Last-Modified -> 304)."""
    host, port, _, stop = _serve(tmp_path)
    try:
        ck, _ = _auth(host, port)
        st, h, _ = _req(host, port, "GET", "/api/session", headers={"Cookie": ck})
        assert st == 200 and h["Cache-Control"] == "private, no-store"
        st, h, _ = _req(host, port, "GET", "/api/session")
        assert st == 401 and h["Cache-Control"] == "no-store"
        st, h, body = _req(host, port, "GET", "/app.js")
        assert st == 200 and body and "Last-Modified" in h
        assert "no-cache" in h["Cache-Control"]
        st, h2, body2 = _req(host, port, "GET", "/app.js",
                             headers={"If-Modified-Since": h["Last-Modified"]})
        assert st == 304 and body2 == b""
        st, _, _ = _req(host, port, "GET", "/app.js",
                        headers={"If-Modified-Since": "garbage"})
        assert st == 200
    finally:
        stop()


def test_poll_header_does_not_refresh_idle_expiry(tmp_path):
    """IRIS-08-004: a GET carrying X-IRIS-Poll: 1 validates the session but
    does not count as operator activity, so an unattended polled view
    reaches the idle timeout; an ordinary GET still refreshes it."""
    import gui_auth
    clock = [1000.0]
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"), now_fn=lambda: clock[0],
                         sessions=gui_auth.SessionStore(idle_ttl=100))
    app.set_admin("admin", "pw")
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None)
    host, port = "127.0.0.1", srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        ck, _ = _auth(host, port)
        clock[0] = 1060
        st, _, _ = _req(host, port, "GET", "/api/session",
                        headers={"Cookie": ck, "X-IRIS-Poll": "1"})
        assert st == 200                               # valid, but not touched
        clock[0] = 1110
        st, _, _ = _req(host, port, "GET", "/api/session", headers={"Cookie": ck})
        assert st == 401                               # 110 s since login
        clock[0] = 1200
        ck, _ = _auth(host, port)
        clock[0] = 1260
        st, _, _ = _req(host, port, "GET", "/api/session", headers={"Cookie": ck})
        assert st == 200                               # touched
        clock[0] = 1310
        st, _, _ = _req(host, port, "GET", "/api/session",
                        headers={"Cookie": ck, "X-IRIS-Poll": "1"})
        assert st == 200                               # 50 s since the touch
    finally:
        srv.shutdown()


def test_corrupt_secrets_store_fails_closed_with_503(tmp_path):
    """A truncated live store must not turn into first-run setup."""
    host, port, app, stop = _serve(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        with open(app.secrets_path, "w") as f:
            f.write("{ truncated")
        st, _, b = _req(host, port, "GET", "/api/session", headers={"Cookie": ck})
        assert st == 503
        assert json.loads(b)["code"] == "service-unavailable"
        assert b"secrets store" not in b
        st, _, b = _req(host, port, "POST", "/api/login",
                        {"username": gui_server.DEFAULT_SETUP_USER,
                         "password": gui_server.DEFAULT_SETUP_PASS})
        assert st == 503 and b"setup_grant" not in b
        with open(app.secrets_path) as f:
            assert f.read() == "{ truncated"         # nothing persisted over it
    finally:
        stop()


def test_break_glass_reset_ends_live_console_session(tmp_path):
    """IRIS-01-003 end to end: a session minted before an out-of-process
    admin reset is refused on its next request."""
    host, port, app, stop = _serve(tmp_path)
    try:
        ck, _ = _auth(host, port)
        assert _req(host, port, "GET", "/api/session", headers={"Cookie": ck})[0] == 200
        # No sleeps: the floor and created_at keep sub-second precision, so
        # a reset right after the login still drops it, and a login right
        # after the reset is honoured immediately.
        cli = gui_app.GuiApp(app.secrets_path)         # the iris-gui-admin process
        cli.set_admin("admin", "reset-pw", invalidate_sessions=True)
        assert _req(host, port, "GET", "/api/session", headers={"Cookie": ck})[0] == 401
        st, h, _ = _req(host, port, "POST", "/api/login",
                        {"username": "admin", "password": "reset-pw"})
        assert st == 200
    finally:
        stop()


def test_login_busy_verifier_is_503_not_a_failed_login(tmp_path):
    """IRIS-01-006: with both scrypt slots taken the route answers 503 +
    Retry-After instead of "invalid credentials" (which penalised the
    limiter and audited a failure that never happened)."""
    import gui_auth
    host, port, _, stop = _serve(tmp_path)
    sem = gui_auth._PASSWORD_VERIFY_SLOTS
    assert sem.acquire(blocking=False) and sem.acquire(blocking=False)
    try:
        st, h, b = _req(host, port, "POST", "/api/login",
                        {"username": "admin", "password": "pw"})
        assert st == 503 and h.get("Retry-After") == "1"
        assert b"invalid credentials" not in b
    finally:
        sem.release(); sem.release()
    try:
        st, _, _ = _req(host, port, "POST", "/api/login",
                        {"username": "admin", "password": "pw"})
        assert st == 200
    finally:
        stop()


def _webroot(name):
    with open(os.path.join(gui_server.WEBROOT, name)) as f:
        return f.read()


def test_console_fetch_wrapper_handles_session_loss_polls_and_stale_state():
    """Source guard (IRIS-08-003/004): one fetch for the whole console --
    401 anywhere redirects to login, 5xx/network marks the header as stale,
    background polls carry X-IRIS-Poll and the telemetry badge never turns
    a proxy failure into "off"."""
    js = _webroot("app.js")
    html = _webroot("index.html")
    assert "function fetch(url, opts)" in js
    assert "if (r.status === 401) onSessionLost();" in js
    assert "window.location.href = '/login.html';" in js
    assert "h.set('X-IRIS-Poll', '1');" in js
    assert js.count("backgroundPoll = true;") == 2          # view poll + batch poll
    assert "function markConnection(ok)" in js
    assert 'className="iris-connection" role="status"' in _react_shell()
    assert "new CustomEvent('iris:shell-state', { detail: { connection: connection } })" in js
    assert "if (!r.ok) throw new Error('health proxy '" in js
    assert "poll = pollMonitoring;" in js
    monitoring = _react_shell("monitoring-controller.mjs")
    assert "fromPoll && (state.olderPages > 0 || state.olderBusy)" in monitoring
    assert "state.interacting" in monitoring


def test_bulk_credential_modal_untouched_is_noop_and_clear_confirms():
    """Source guard (IRIS-08-001): the resting placeholder is disabled (an
    untouched Apply does nothing), clearing is a distinct sentinel that is
    confirmed, and the modal refuses to open without a profile list."""
    js, component = _react_shell('assignments-controller.mjs'), _react_shell('assignments.jsx')
    assert '<option value="" disabled>' in component
    assert "'cred-modal-msg'" in component
    assert "choice.startsWith('profile:') ? choice.slice(8) : ''" in js
    assert 'Clear the credential on ${ids.length} reviewed device(s)?' in js
    assert "if (!choice) {" in js


def test_credential_list_failure_is_not_rendered_as_no_credential():
    """Source guard (IRIS-08-002): a failed /api/credentials keeps the last
    good list, disables the pickers and says so, instead of matching every
    row to "no credential"."""
    js = _webroot("app.js")
    assert "var credListOk = false;" in js
    assert 'credentials: credentialsOk ? credentials.body.profiles : this.state.credentials' in _react_shell('inventory-controller.mjs')
    assert 'disabled={busy || state.bulkBusy || !state.credentialsOk}' in _react_shell('inventory.jsx')
    assert 'Credential list unavailable; showing the assignment as recorded' in _react_shell('inventory.jsx')
    assert "credential list unavailable; assign later" in _react_shell('device-forms.jsx')
    assert "Credential list unavailable; not opening the picker." in _react_shell('assignments-controller.mjs')


def test_console_id_keyed_maps_are_prototype_free():
    """Operator-chosen IDs use null-prototype objects, Map or Set."""
    js = _webroot("app.js")
    for decl in ("var LAST_JOBS_BY_DEVICE = Object.create(null);",
                 "var best = Object.create(null);",
                 "var imageFilenames = Object.create(null);",
                 "var imageQuarantined = Object.create(null);",
                 "imageFilenames = Object.create(null);",
                 "imageQuarantined = Object.create(null);"):
        assert decl in js, decl
    assert "var SELECTED = {};" not in js and "var checkedSet = {};" not in js
    model = _react_shell('inventory-controller.mjs')
    assert 'selected: new Set()' in model and 'rowBusy: new Set()' in model
    picker = _react_shell('assignments-model.mjs')
    controller = _react_shell('assignments-controller.mjs')
    assert 'const expect = new Map(ids.map(id =>' in picker
    assert 'const records = new Map(), seen = new Set(), targets = new Set(ids)' in controller
    assert 'const chosen = new Set(this.state.chosen)' in controller


def test_telemetry_filter_has_unknown_bucket():
    """Source guard (IRIS-08-008): the filter's tri-state matches the cell's."""
    js = _webroot("app.js")
    html = _webroot("index.html")
    assert "['unknown', 'unknown (no heartbeat yet)']" in _react_shell('inventory.jsx')
    assert "telemetry: 'telemetry'" in _react_shell('inventory-model.mjs')


def test_swarm_map_treats_error_body_as_failed_poll():
    """Source guard (IRIS-08-005): the proxy's 200-with-error shape is a
    failed poll in the map, and its poll is marked as background."""
    model = _react_shell('swarm-map-model.mjs')
    controller = _react_shell('swarm-map-controller.mjs')
    assert 'if (!validSnapshot(data)) throw Error(' in controller
    assert 'data.error' in model.split('function validSnapshot(data)', 1)[1].split('export ', 1)[0]
    assert "'X-IRIS-Poll': '1'" in controller


def test_login_page_distinguishes_throttling_and_network_errors():
    """Source guard (IRIS-08-010)."""
    js = _webroot("login.js")
    assert "res.status === 429" in js and "Retry-After" in js
    assert "Could not reach the server" in js
    assert "res.status === 401" in js


def test_corrupt_catalog_state_fails_closed_with_503(tmp_path):
    """IRIS-02-001 at the console HTTP layer: a corrupt catalog state file
    must not reach the operator as a dropped connection and a traceback.

    catalog.CatalogStore raises StateFileError for a present-but-unreadable
    state file so no reader mistakes it for empty and no writer overwrites
    it. gui_server had no mapping for that, so the console answered nothing
    at all. The contract is the same fail-closed 503 the secrets store gets.
    """
    host, port, (_, fleet, _, _), stop = _serve_full(tmp_path)
    try:
        _policy_device(fleet)
        cookie, csrf = _auth(host, port)
        with open(str(tmp_path / "state" / "policy.json"), "w") as f:
            f.write("{ truncated")
        st, _, b = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_id": "img1"},
                        headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert st == 503
        problem = json.loads(b)
        assert problem["code"] == "service-unavailable"
        assert problem["error"] == "service unavailable"
        with open(str(tmp_path / "state" / "policy.json")) as f:
            assert f.read() == "{ truncated"      # nothing written over it
    finally:
        stop()


# --- paginated read projections (#57) --------------------------------------
# /api/devices and /api/swarm can be asked for a PAGE. Paging is opt-in and
# every response says how much there is in total, so no caller can mistake a
# page for the fleet.

def _fleet_of(fleet, n):
    for i in range(n):
        fleet.upsert({"device_id": "dev-%02d" % i,
                      "device_ip": "10.0.0.%d" % (i + 1),
                      "management_type": "inband", "inband_vlan": "120",
                      "app_ip": "10.9.0.%d" % (i + 2), "app_mask": "255.255.255.0",
                      "app_gateway": "10.9.0.1", "platform": "guestshell",
                      "model": "C9300" if i % 2 else "C9500"})


def test_devices_unpaged_response_carries_totals(tmp_path):
    """The whole-fleet call is unchanged in content and now states its own
    size: a client that never pages can still prove what it holds is
    complete (len(devices) == total), which is what stops a page from ever
    being mistaken for the fleet."""
    host, port, stores, stop = _serve_full(tmp_path)
    fleet = stores[1]
    try:
        _fleet_of(fleet, 5)
        ck, _ = _login(host, port)
        st, _, b = _req(host, port, "GET", "/api/devices",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert st == 200
        assert len(body["devices"]) == body["total"] == 5
        assert body["offset"] == 0 and body["limit"] is None
        assert body["revision"] == fleet.revision()
    finally:
        stop()


def test_devices_pages_cover_the_fleet_exactly_once(tmp_path):
    """Sequential pages of a stable fleet reconstruct it with no gap and no
    repeat, and every page reports the same total and revision."""
    host, port, stores, stop = _serve_full(tmp_path)
    try:
        _fleet_of(stores[1], 5)
        ck, _ = _login(host, port)
        seen, revisions = [], set()
        for offset in (0, 2, 4, 6):
            st, _, b = _req(host, port, "GET",
                            "/api/devices?limit=2&offset=%d" % offset,
                            headers={"Cookie": ck})
            body = json.loads(b)
            assert st == 200 and body["total"] == 5
            assert body["offset"] == offset and body["limit"] == 2
            revisions.add(body["revision"])
            seen += [d["device_id"] for d in body["devices"]]
        assert seen == ["dev-%02d" % i for i in range(5)]   # sorted, no dupes
        assert len(revisions) == 1
    finally:
        stop()


def test_devices_page_keeps_the_merged_projection(tmp_path):
    """A page is the same row shape as the full projection -- policy and
    heartbeat merged in -- not a thinner record."""
    host, port, stores, stop = _serve_full(tmp_path)
    _, fleet, _, cat = stores
    try:
        _fleet_of(fleet, 3)
        cat.set_policy("dev-01", "img1")
        ck, _ = _login(host, port)
        st, _, b = _req(host, port, "GET", "/api/devices?limit=1&offset=1",
                        headers={"Cookie": ck})
        row = json.loads(b)["devices"][0]
        assert row["device_id"] == "dev-01"
        assert row["assigned_image_id"] == "img1"
        assert "last_seen" in row and "stage_state" in row
    finally:
        stop()


def test_devices_page_params_are_rejected_not_defaulted(tmp_path):
    """Serving a different page than the one asked for is how a client comes
    to believe it walked a fleet it never walked, so an unusable limit or
    offset is a 400."""
    host, port, stores, stop = _serve_full(tmp_path)
    try:
        _fleet_of(stores[1], 3)
        ck, _ = _login(host, port)
        for qs in ("limit=0", "limit=-1", "limit=abc", "offset=-1",
                   "offset=abc", "limit=2&offset=x"):
            st, _, b = _req(host, port, "GET", "/api/devices?" + qs,
                            headers={"Cookie": ck})
            assert st == 400, qs
            assert json.loads(b)["error"]
    finally:
        stop()


def test_devices_limit_is_clamped_and_echoed(tmp_path):
    host, port, stores, stop = _serve_full(tmp_path)
    try:
        _fleet_of(stores[1], 3)
        ck, _ = _login(host, port)
        st, _, b = _req(host, port, "GET", "/api/devices?limit=999999",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert st == 200 and body["limit"] == gui_server.MAX_PAGE_LIMIT
        assert body["total"] == 3 and len(body["devices"]) == 3
    finally:
        stop()


def test_devices_filter_counts_matches_not_the_page(tmp_path):
    """q filters server-side over the same fields the console's search box
    covers; total is the number of MATCHES, so a filtered page is still
    self-describing."""
    host, port, stores, stop = _serve_full(tmp_path)
    try:
        _fleet_of(stores[1], 6)
        ck, _ = _login(host, port)
        st, _, b = _req(host, port, "GET", "/api/devices?q=c9500&limit=2",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert st == 200 and body["total"] == 3 and len(body["devices"]) == 2
        assert all(d["model"] == "C9500" for d in body["devices"])
        st, _, b = _req(host, port, "GET", "/api/devices?q=10.0.0.4",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert [d["device_id"] for d in body["devices"]] == ["dev-03"]
        st, _, b = _req(host, port, "GET", "/api/devices?q=dev-0",
                        headers={"Cookie": ck})
        assert json.loads(b)["total"] == 6
    finally:
        stop()


def test_devices_offset_past_the_end_is_an_empty_page_not_an_error(tmp_path):
    host, port, stores, stop = _serve_full(tmp_path)
    try:
        _fleet_of(stores[1], 2)
        ck, _ = _login(host, port)
        st, _, b = _req(host, port, "GET", "/api/devices?limit=5&offset=99",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert st == 200 and body["devices"] == [] and body["total"] == 2
    finally:
        stop()


# --- server-side parity for the nine console column filters (#112) ---------
# app.js's deviceMatchesFilters() decides these client-side over the whole
# fleet; a paged table can only offer a filter the server can also apply, or
# a page would silently disagree with what the filter bar promises. Every
# test below pins the server's decision against the SAME semantics
# deviceMatchesFilters documents for that field (see the comments in
# gui_server.Handler._row_matches_extra_filters, which mirror it condition
# for condition).

def test_devices_platform_filter_matches_console_semantics(tmp_path):
    host, port, stores, stop = _serve_full(tmp_path)
    fleet = stores[1]
    try:
        fleet.upsert({"device_id": "gs1", "device_ip": "10.0.0.1",
                      "platform": "guestshell"})
        fleet.upsert({"device_id": "iox1", "device_ip": "10.0.0.2",
                      "platform": "iox"})
        fleet.upsert({"device_id": "bare1", "device_ip": "10.0.0.3"})
        ck, _ = _login(host, port)
        st, _, b = _req(host, port, "GET", "/api/devices?platform=guestshell",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert st == 200 and body["total"] == 1
        assert body["devices"][0]["device_id"] == "gs1"
        st, _, b = _req(host, port, "GET", "/api/devices?platform=__none",
                        headers={"Cookie": ck})
        assert json.loads(b)["total"] == 1
        assert json.loads(b)["devices"][0]["device_id"] == "bare1"
    finally:
        stop()


def test_devices_management_type_filter_folds_legacy_routed(tmp_path):
    """Mirrors deviceMatchesFilters' own legacy_routed/legacy equivalence: an
    unclassified device is always stored as the truthy 'legacy_routed', so
    the ?management_type=legacy filter must fold it in exactly like the
    filter bar's "Inventory only" option does."""
    host, port, stores, stop = _serve_full(tmp_path)
    fleet = stores[1]
    try:
        fleet.upsert({"device_id": "unclassified", "device_ip": "10.0.0.1"})
        fleet.upsert({"device_id": "inband1", "device_ip": "10.0.0.2",
                      "management_type": "inband", "inband_vlan": "120",
                      "app_ip": "10.9.0.2", "app_mask": "255.255.255.252",
                      "app_gateway": "10.9.0.1"})
        ck, _ = _login(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/devices?management_type=legacy",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert st == 200 and body["total"] == 1
        assert body["devices"][0]["device_id"] == "unclassified"
        st, _, b = _req(host, port, "GET",
                        "/api/devices?management_type=inband",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert body["total"] == 1 and body["devices"][0]["device_id"] == "inband1"
    finally:
        stop()


def test_devices_credential_filter_and_none(tmp_path):
    host, port, stores, stop = _serve_full(tmp_path)
    fleet, creds = stores[1], stores[2]
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        fleet.upsert({"device_id": "d2", "device_ip": "10.0.0.2"})
        creds.set_profile("prof1", {"name": "P", "device_user": "u",
                                    "device_pass": "p"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/devices/d1/credential",
                        {"credential_profile_id": "prof1"}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/devices?cred=prof1",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert body["total"] == 1 and body["devices"][0]["device_id"] == "d1"
        st, _, b = _req(host, port, "GET", "/api/devices?cred=__none",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert body["total"] == 1 and body["devices"][0]["device_id"] == "d2"
    finally:
        stop()


def test_devices_telemetry_filter_is_tri_state(tmp_path):
    """Same tri-state as the console's telemetryCell/filter: "on" only once
    the device has actually reported telemetry; a device that never
    heartbeated is 'unknown', never bucketed with 'off'."""
    host, port, stores, stop = _serve_full(tmp_path)
    fleet, cat = stores[1], stores[3]
    try:
        fleet.upsert({"device_id": "never", "device_ip": "10.0.0.1"})
        fleet.upsert({"device_id": "on1", "device_ip": "10.0.0.2"})
        fleet.upsert({"device_id": "off1", "device_ip": "10.0.0.3"})
        cat.record_heartbeat("on1", {"telemetry_enabled": True}, now=time.time())
        cat.record_heartbeat("off1", {"telemetry_enabled": False}, now=time.time())
        ck, _ = _login(host, port)
        for value, expect in (("unknown", "never"), ("on", "on1"), ("off", "off1")):
            st, _, b = _req(host, port, "GET",
                            "/api/devices?telemetry=" + value,
                            headers={"Cookie": ck})
            body = json.loads(b)
            assert body["total"] == 1, (value, body)
            assert body["devices"][0]["device_id"] == expect
    finally:
        stop()


def test_devices_peer_filter_uses_quarantine_assignments(tmp_path):
    """?peer=quarantined/not-quarantined reads the same peer-policy
    assignment set /api/peer-policy exposes as quarantine_assignments -- the
    console's peer filter and the peer-policy panel can never disagree about
    which devices are quarantined."""
    host, port, stores, stop = _serve_full(tmp_path)
    fleet = stores[1]
    try:
        fleet.upsert({"device_id": "q1", "device_ip": "10.0.0.1"})
        fleet.upsert({"device_id": "nq1", "device_ip": "10.0.0.2"})
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "PUT", "/api/peer-policy/quarantine/q1",
                        {"quarantined": True, "if_revision": 1}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/devices?peer=quarantined",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert body["total"] == 1 and body["devices"][0]["device_id"] == "q1"
        st, _, b = _req(host, port, "GET", "/api/devices?peer=not-quarantined",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert body["total"] == 1 and body["devices"][0]["device_id"] == "nq1"
    finally:
        stop()


# ---------------------------------------------------------------------------
# Phase 0 declared device roles: coordinated API writes and filter parity
# ---------------------------------------------------------------------------

def _define_device_role(cat, name="boat", restricted=True, **extra):
    import peer_policy
    definition = {"restricted": restricted, "peers": [name]}
    definition.update(extra)
    return peer_policy.define_role(
        os.path.join(cat.state_dir, "peer-policy.json"),
        os.path.join(cat.state_dir, "peer-policy.lkg.json"),
        name, definition, actor="test", now=1.0)


def _loaded_peer_policy(cat):
    import peer_policy
    return peer_policy.load_policy(
        os.path.join(cat.state_dir, "peer-policy.json"),
        os.path.join(cat.state_dir, "peer-policy.lkg.json"))


def test_device_role_and_bulk_role_routes_coordinate_fleet_and_policy(tmp_path):
    host, port, (_, fleet, _, cat), stop = _serve_full(tmp_path)
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        fleet.upsert({"device_id": "d2", "device_ip": "10.0.0.2"})
        _define_device_role(cat)
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        hh["If-Match"] = gui_server._revision_etag(
            "peer-policy", _loaded_peer_policy(cat).document["revision"])
        preview = json.loads(_req(host, port, "POST", "/api/devices/d1/role?dry_run=1",
                                  {"role": "boat"}, headers=hh)[2])
        st, _, b = _req(host, port, "POST", "/api/devices/d1/role",
                        {"role": "boat", "confirm_token": preview["confirm_token"]}, headers=hh)
        assert st == 200, b
        assert fleet.get_device("d1")["role"] == "boat"
        assert _loaded_peer_policy(cat).roles.role_of["d1"] == "boat"
        before = _loaded_peer_policy(cat).document
        hh["If-Match"] = gui_server._revision_etag("peer-policy", before["revision"])
        body = {"device_ids": ["d1", "d2"], "role": "boat"}
        preview = json.loads(_req(host, port, "POST", "/api/devices/bulk-role?dry_run=1",
                                  body, headers=hh)[2])
        st, _, b = _req(host, port, "POST", "/api/devices/bulk-role",
                        dict(body, confirm_token=preview["confirm_token"]), headers=hh)
        assert st == 200, b
        body = json.loads(b)
        assert body["applied"] == 2 and body["role_drift"]["count"] == 0
        after = _loaded_peer_policy(cat).document
        assert after["revision"] == before["revision"] + 1
        assert len(after["operation_outbox"]) == \
            len(before["operation_outbox"]) + 1
    finally:
        stop()


def test_device_role_routes_refuse_unknown_role_before_either_write(tmp_path):
    host, port, (_, fleet, _, cat), stop = _serve_full(tmp_path)
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        ck, csrf = _auth(host, port)
        before = fleet.snapshot(), _loaded_peer_policy(cat).document
        st, _, b = _req(
            host, port, "POST", "/api/devices/d1/role", {"role": "missing"},
            headers={"Cookie": ck, "X-CSRF-Token": csrf, "If-Match":
                     gui_server._revision_etag("peer-policy", before[1]["revision"])})
        assert st == 404
        assert json.loads(b)["error"] == "role_not_found"
        assert (fleet.snapshot(), _loaded_peer_policy(cat).document) == before
    finally:
        stop()


def test_device_role_ingress_rejects_nonstring_and_surrounding_whitespace(
        tmp_path):
    host, port, (_, fleet, _, cat), stop = _serve_full(tmp_path)
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        _define_device_role(cat)
        ck, csrf = _auth(host, port)
        headers = {"Cookie": ck, "X-CSRF-Token": csrf}
        before = fleet.snapshot(), _loaded_peer_policy(cat).document
        headers["If-Match"] = gui_server._revision_etag("peer-policy", before[1]["revision"])
        for value in (123, " boat", "boat\t"):
            st, _, body = _req(
                host, port, "POST", "/api/devices/d1/role",
                {"role": value}, headers=headers)
            assert st == 422, body
            assert json.loads(body)["error"] == "bad_role"
        st, _, body = _req(
            host, port, "POST", "/api/devices",
            {"device_id": "new", "device_ip": "10.0.0.9", "role": 123},
            headers=headers)
        assert st == 400, body
        assert (fleet.snapshot(), _loaded_peer_policy(cat).document) == before
    finally:
        stop()


def test_generic_device_post_and_csv_import_with_roles_are_coordinated(tmp_path):
    host, port, (_, fleet, _, cat), stop = _serve_full(tmp_path)
    try:
        _define_device_role(cat, restricted=False)
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "POST", "/api/devices",
                        {"device_id": "d1", "device_ip": "10.0.0.1",
                         "role": "boat"}, headers=hh)
        assert st == 200, b
        assert _loaded_peer_policy(cat).roles.role_of["d1"] == "boat"

        row = fleet.get_device("d1")
        text = ",".join(gui_fleet.CSV_V2_COLS) + "\n" + \
            ",".join(str(row.get(key, ""))
                     for key in gui_fleet.CSV_V2_COLS) + "\n"
        before = _loaded_peer_policy(cat).document["revision"]
        st, _, b = _req(host, port, "POST", "/api/devices/import-csv",
                        raw=text.encode(), headers=dict(hh, **{
                            "Content-Type": "text/csv"}))
        assert st == 200, b
        assert json.loads(b)["roles_cleared"] == 0
        # An unchanged role import does not manufacture a membership event.
        assert _loaded_peer_policy(cat).document["revision"] == before
    finally:
        stop()


def test_role_compile_failure_returns_partial_and_bounded_drift(
        tmp_path, monkeypatch):
    import peer_policy
    host, port, (_, fleet, _, cat), stop = _serve_full(tmp_path)
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        _define_device_role(cat)
        ck, csrf = _auth(host, port)
        headers = {"Cookie": ck, "X-CSRF-Token": csrf, "If-Match":
                   gui_server._revision_etag("peer-policy", _loaded_peer_policy(cat).document["revision"])}
        preview = json.loads(_req(host, port, "POST", "/api/devices/d1/role?dry_run=1",
                                  {"role": "boat"}, headers=headers)[2])
        original = peer_policy.commit_mutation
        def fail_real_commit(*args, **kwargs):
            if kwargs.get("dry_run"):
                return original(*args, **kwargs)
            raise peer_policy.OperationBacklogFull("full")
        monkeypatch.setattr(peer_policy, "commit_mutation", fail_real_commit)
        st, _, b = _req(
            host, port, "POST", "/api/devices/d1/role",
            {"role": "boat", "confirm_token": preview["confirm_token"]}, headers=headers)
        body = json.loads(b)
        assert st == 409 and body["partial"] is True
        assert body["role_drift"] == {
            "count": 1, "device_ids": ["d1"], "truncated": False}
        assert fleet.get_device("d1")["role"] == "boat"
    finally:
        stop()


def test_device_delete_cleans_role_membership_and_device_qos(tmp_path):
    import peer_policy
    host, port, (_, fleet, _, cat), stop = _serve_full(tmp_path)
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
        _define_device_role(cat)
        auth_path = os.path.join(cat.state_dir, "peer-policy.json")
        lkg_path = os.path.join(cat.state_dir, "peer-policy.lkg.json")

        def seed(candidate):
            roles = candidate["roles"]
            roles["role_of"]["d1"] = "boat"
            roles["qos_device"]["d1"] = {"max_peers": 4}
        peer_policy.commit_mutation(
            auth_path, lkg_path, "seed", "d1", "test", 2, seed)
        ck, csrf = _auth(host, port)
        st, _, b = _req(
            host, port, "DELETE", "/api/devices/d1",
            headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200, b
        doc = _loaded_peer_policy(cat).document
        assert "d1" not in doc.get("assignments", {})
        assert "d1" not in doc["roles"]["role_of"]
        assert "d1" not in doc["roles"]["qos_device"]
    finally:
        stop()


def test_devices_role_filter_matches_exact_role_and_unassigned(tmp_path):
    host, port, (_, fleet, _, _cat), stop = _serve_full(tmp_path)
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1",
                      "role": "boat"})
        fleet.upsert({"device_id": "d2", "device_ip": "10.0.0.2"})
        ck, _ = _auth(host, port)
        for value, expected in (("boat", "d1"), ("__none", "d2")):
            st, _, b = _req(host, port, "GET", "/api/devices?role=" + value,
                            headers={"Cookie": ck})
            body = json.loads(b)
            assert st == 200 and body["total"] == 1
            assert body["devices"][0]["device_id"] == expected
    finally:
        stop()


def test_declared_role_filter_has_server_and_client_parity():
    component = _react_shell('inventory.jsx')
    assert "['role', 'role'" in component and "['__none', '— no role —']" in component
    assert 'state.policy?.roles?.members' in component
    assert 'values.concat([[state.filters[key], state.filters[key]]])' in component
    assert "role: 'role'" in _react_shell('inventory-model.mjs')
    assert gui_server.target_row_matches({'role': 'boat'}, {'role': 'boat'}, now=1)
    assert gui_server.target_row_matches({'role': ''}, {'role': '__none'}, now=1)
    assert not gui_server.target_row_matches({'role': 'boat'}, {'role': '__none'}, now=1)


def test_target_filters_use_fleet_and_deployment_facts_not_heartbeat(tmp_path):
    class Records:
        def list(self, strict=False):
            assert strict is True
            return [{
                "record_id": "r1", "device_id": "auto-1", "state": "active",
                "timestamps": {"planned_at": 10, "finished_at": 11},
                "resolved": {"platform": "guestshell", "os_family": "xe"},
            }]

    host, port, (_, fleet, _, cat), stop = _serve_full(
        tmp_path, record_store=Records(), now_fn=lambda: 4242.9)
    try:
        fleet.upsert({"device_id": "auto-1", "device_ip": "10.0.0.1",
                      "model": "C9300", "role": "boat"})
        fleet.upsert({"device_id": "missing-os", "device_ip": "10.0.0.2",
                      "model": "IE-3400", "role": "boat"})
        # A device controls heartbeat_model. It may be displayed and searched,
        # but it must never change a targeting family.
        cat.record_heartbeat("auto-1", {"model": "8201"}, now=4000)
        ck, _ = _login(host, port)
        st, _, raw = _req(
            host, port, "GET",
            "/api/devices?role=boat&model_family=C9xxx&os_family=xe&platform=guestshell",
            headers={"Cookie": ck})
        body = json.loads(raw)
        assert st == 200
        assert [row["device_id"] for row in body["devices"]] == ["auto-1"]
        assert body["devices"][0]["model_family"] == "C9xxx"
        assert body["devices"][0]["platform_resolved"] == "guestshell"
        assert body["devices"][0]["heartbeat_model"] == "8201"
        assert body["total"] == 1
        assert body["revision"] == fleet.revision()
        assert body["now"] == 4242
        assert body["target_facts"] == {
            "missing_os_family": 0, "role_drift": 1}

        # The missing fact is counted inside the other target dimensions even
        # though os_family=xe necessarily excludes that row from total.
        st, _, raw = _req(
            host, port, "GET", "/api/devices?role=boat&os_family=xe",
            headers={"Cookie": ck})
        body = json.loads(raw)
        assert st == 200 and body["total"] == 1
        assert body["target_facts"]["missing_os_family"] == 1
        assert "1 devices have no os_family yet" in body["target_warnings"]

        # Targeting follows the declared fleet role even while compiled
        # enforcement is absent/drifted.
        assert body["target_facts"]["role_drift"] == 1
        assert "1 devices have declared role drift" in body["target_warnings"]

        # Missing-fact counting composes with the peer quarantine predicate;
        # the row is relevant to every other target dimension even though the
        # absent OS fact keeps it out of the final xe result.
        ck, csrf = _auth(host, port)
        revision = _loaded_peer_policy(cat).document["revision"]
        st, _, raw = _req(
            host, port, "PUT",
            "/api/peer-policy/quarantine/missing-os",
            {"quarantined": True, "if_revision": revision},
            headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200, raw
        st, _, raw = _req(
            host, port, "GET", "/api/devices?peer=quarantined&os_family=xe",
            headers={"Cookie": ck})
        body = json.loads(raw)
        assert st == 200 and body["total"] == 0
        assert body["target_facts"]["missing_os_family"] == 1
    finally:
        stop()


def test_target_role_drift_includes_ordinary_assignment_shadowing(tmp_path):
    import peer_policy

    host, port, (_, fleet, _, cat), stop = _serve_full(tmp_path)
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1",
                      "model": "C9300", "role": "boat"})
        _define_device_role(cat)

        def shadow_role(document):
            document["roles"]["role_of"]["d1"] = "boat"
            document["acls"]["manual"] = {
                "rules": [{"seq": 17, "action": "deny",
                           "match": {"type": "any"}}]}
            document["assignments"]["d1"] = "manual"

        peer_policy.commit_mutation(
            os.path.join(cat.state_dir, "peer-policy.json"),
            os.path.join(cat.state_dir, "peer-policy.lkg.json"),
            action="shadow", target="d1", actor="test", now=2,
            mutate=shadow_role)
        cookie, _ = _login(host, port)
        status, _, raw = _req(
            host, port, "GET", "/api/devices?role=boat",
            headers={"Cookie": cookie})
        body = json.loads(raw)
        assert status == 200 and body["total"] == 1
        assert body["target_facts"]["role_drift"] == 1
        assert "1 devices have declared role drift" in body["target_warnings"]
    finally:
        stop()


def test_record_backed_target_facts_are_stable_across_preview_filters(tmp_path):
    class Records:
        def __init__(self):
            self.calls = []

        def list(self, strict=False):
            self.calls.append(strict)
            return [{
                "record_id": "r1", "device_id": "record-backed",
                "state": "active", "timestamps": {"planned_at": 10},
                "resolved": {"platform": "guestshell", "os_family": "xe"},
            }]

    records = Records()
    host, port, (_, fleet, _, _cat), stop = _serve_full(
        tmp_path, record_store=records)
    try:
        fleet.upsert({"device_id": "record-backed",
                      "device_ip": "10.0.0.1", "model": "C9300",
                      "role": "boat"})
        fleet.upsert({"device_id": "missing", "device_ip": "10.0.0.2",
                      "model": "C9300", "role": "boat"})
        cookie, _ = _login(host, port)
        for query in ("", "?role=boat", "?role=boat&os_family=xe"):
            status, _, raw = _req(
                host, port, "GET", "/api/devices" + query,
                headers={"Cookie": cookie})
            body = json.loads(raw)
            assert status == 200
            by_id = {row["device_id"]: row for row in body["devices"]}
            if "record-backed" in by_id:
                assert by_id["record-backed"]["os_family"] == "xe"
                assert by_id["record-backed"]["platform_resolved"] == \
                    "guestshell"
            assert body["target_facts"]["missing_os_family"] == 1
            assert "1 devices have no os_family yet" in \
                body["target_warnings"]
        assert records.calls == [True, True, True]
    finally:
        stop()


def test_device_type_filters_have_server_and_client_preview_parity():
    component, model, controller = (_react_shell(name) for name in
        ('inventory.jsx', 'inventory-model.mjs', 'inventory-controller.mjs'))
    assert "['modelFamily', 'model-family'" in component
    assert "['osFamily', 'os-family'" in component
    assert "modelFamily: 'model_family'" in model and "osFamily: 'os_family'" in model
    assert 'target_warnings' in controller and 'id="dev-target-warning"' in component
    assert 'Device target preview unavailable' in controller
    assert 'rows: [], total: 0, offset: 0, now: 0, readOk: false' in controller
    assert "'Results unavailable'" in component and 'disabled={!state.rows.length}' in component
    assert 'matchQuery: null, matchIds: null' in controller

    # Task 22 consumes this same pure predicate; the HTTP handler delegates to
    # it rather than owning a second copy of the target language.
    row = {"device_id": "d1", "role": "boat", "model_family": "C9xxx",
           "os_family": "xe", "platform": "",
           "platform_resolved": "guestshell"}
    assert gui_server.target_row_matches(
        row, {"role": "boat", "model_family": "C9xxx",
              "os_family": "xe", "platform": "guestshell"}, now=1)
    assert not gui_server.target_row_matches(
        row, {"role": "fiber"}, now=1)
    with pytest.raises(
            ValueError, match="peer targeting requires quarantine assignments"):
        gui_server.target_row_matches(
            row, {"peer": "not-quarantined"}, now=1)
    assert gui_server.target_row_matches(
        row, {"peer": "not-quarantined"}, now=1,
        quarantined_ids=set())
    projected = gui_server.trusted_target_projection(
        {"model": "C9300", "heartbeat_model": "8201", "os_family": "xe"},
        {"platform": "guestshell"})
    assert projected == {"model_family": "C9xxx", "os_family": "xe",
                         "platform_resolved": "guestshell"}
    assert "return target_row_matches(" in inspect.getsource(
        gui_server.make_server)


def test_failed_target_preview_cannot_be_replayed_from_selection_cache():
    import subprocess
    model = (Path(gui_server.WEBROOT).parent / 'console-ui/src/inventory-model.mjs').as_uri()
    controller = (Path(gui_server.WEBROOT).parent / 'console-ui/src/inventory-controller.mjs').as_uri()
    program = f"import {{InventoryController}} from {json.dumps(controller)}; import {{selectionScope}} from {json.dumps(model)};" + r"""
import assert from 'node:assert/strict';
const c = new InventoryController(); let reads = 0;
c.connect({fetch: async () => { reads++; return {ok: false, status: 503}; }});
c.update({rows: [{device_id: 'stale'}], now: 77, total: 1, matchQuery: '', selected: new Set(['keep'])});
await c.refresh();
assert.deepEqual(c.snapshot().rows, []); assert.equal(c.snapshot().now, 0);
assert.equal(c.snapshot().total, 0); assert.equal(c.snapshot().offset, 0);
assert.match(c.snapshot().error, /preview unavailable/);
assert.match(selectionScope(c.snapshot()).text, /unconfirmed/);
assert.equal(selectionScope(c.snapshot()).offerAll, false);
const n = reads; await c.selectAll(); assert.equal(reads, n);
assert.deepEqual(c.selectedIds(), ['keep']); c.dispose();
"""
    result = subprocess.run(['node', '--input-type=module', '-'], input=program, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


def test_resolved_type_filter_fails_visible_on_unreadable_record_state(tmp_path):
    calls = []

    class BrokenRecords:
        def list(self, strict=False):
            calls.append(strict)
            raise deployment_records.RecordStoreUnreadable("broken")

    host, port, (_, fleet, _, _cat), stop = _serve_full(
        tmp_path, record_store=BrokenRecords())
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1",
                      "model": "C9300"})
        ck, _ = _login(host, port)
        st, _, raw = _req(host, port, "GET", "/api/devices",
                          headers={"Cookie": ck})
        assert st == 503 and calls == [True]
        problem = json.loads(raw)
        assert problem["code"] == "service-unavailable"
    finally:
        stop()


def test_role_filter_facet_is_complete_when_role_is_absent_from_current_page(
        tmp_path):
    host, port, (_, fleet, _, cat), stop = _serve_full(tmp_path)
    try:
        _define_device_role(cat, "alpha", restricted=False)
        _define_device_role(cat, "zeta", restricted=True)
        for index in range(201):
            fleet.upsert({"device_id": "d%03d" % index,
                          "device_ip": "10.0.%d.%d" %
                          (index // 250, index % 250 + 1),
                          "role": "zeta" if index == 200 else "alpha"})
        ck, _ = _auth(host, port)
        st, _, raw = _req(
            host, port, "GET", "/api/devices?limit=200&offset=0",
            headers={"Cookie": ck})
        page = json.loads(raw)
        assert st == 200 and len(page["devices"]) == 200
        assert all(row.get("role") != "zeta" for row in page["devices"])
        st, _, raw = _req(host, port, "GET", "/api/peer-policy",
                          headers={"Cookie": ck})
        assert st == 200
        assert set(json.loads(raw)["roles"]["members"]) == {"alpha", "zeta"}
    finally:
        stop()



def test_devices_status_filter_matches_every_key_deviceStatus_can_produce(tmp_path):
    """Server-side _device_status_key mirrors app.js deviceStatus()'s key
    derivation; this pins several of its branches against the SAME rows a
    real console poll would classify identically."""
    host, port, stores, stop = _serve_full(tmp_path)
    fleet, cat = stores[1], stores[3]
    try:
        fleet.upsert({"device_id": "never", "device_ip": "10.0.0.1"})
        fleet.upsert({"device_id": "unassigned1", "device_ip": "10.0.0.2"})
        fleet.upsert({"device_id": "deployed1", "device_ip": "10.0.0.3"})
        fleet.upsert({"device_id": "copying1", "device_ip": "10.0.0.4"})
        fleet.upsert({"device_id": "placement1", "device_ip": "10.0.0.5"})
        cat.record_heartbeat("unassigned1", {}, now=time.time())
        cat.set_policy("deployed1", approved_image_id="img1")
        cat.record_heartbeat("deployed1", {"stage_state": "ready",
                                           "current_image_id": "img1"},
                             now=time.time())
        cat.set_policy("copying1", approved_image_id="img1")
        cat.record_heartbeat("copying1", {"stage_state": "transferring_to_ios",
                                          "target_fs": "bootflash:"},
                             now=time.time())
        cat.set_policy("placement1", approved_image_id="img1")
        cat.record_heartbeat("placement1", {"stage_error": "disk full"},
                             now=time.time())
        ck, _ = _login(host, port)
        for status, expect in (("not-enrolled", "never"),
                               ("unassigned", "unassigned1"),
                               ("deployed", "deployed1"),
                               ("copying", "copying1"),
                               ("placement-failed", "placement1")):
            st, _, b = _req(host, port, "GET", "/api/devices?status=" + status,
                            headers={"Cookie": ck})
            body = json.loads(b)
            assert body["total"] == 1, (status, body)
            assert body["devices"][0]["device_id"] == expect, (status, body)
    finally:
        stop()


def test_devices_status_offline_and_attention_filters(tmp_path):
    """?status=offline is the freshness MODIFIER (deviceIsOffline), never a
    deviceStatus() key on its own; ?status=__attention is the "needs
    attention" rollup over negative/severe/warning levels -- both mirror
    app.js exactly (deviceIsOffline / statusDisplay's level, respectively)."""
    host, port, stores, stop = _serve_full(tmp_path)
    fleet, cat = stores[1], stores[3]
    try:
        fleet.upsert({"device_id": "stale1", "device_ip": "10.0.0.1"})
        fleet.upsert({"device_id": "fresh1", "device_ip": "10.0.0.2"})
        fleet.upsert({"device_id": "failed1", "device_ip": "10.0.0.3"})
        # 10+ minutes stale by real wall clock -> offline
        cat.record_heartbeat("stale1", {}, now=1)
        cat.record_heartbeat("fresh1", {}, now=time.time())
        cat.set_policy("failed1", approved_image_id="img1")
        cat.record_heartbeat("failed1", {"stage_error": "disk full"},
                             now=time.time())
        ck, _ = _login(host, port)
        st, _, b = _req(host, port, "GET", "/api/devices?status=offline",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert body["total"] == 1 and body["devices"][0]["device_id"] == "stale1"
        st, _, b = _req(host, port, "GET", "/api/devices?status=__attention",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert body["total"] == 1 and body["devices"][0]["device_id"] == "failed1"
    finally:
        stop()


def test_devices_filters_compose_with_q_and_paging(tmp_path):
    """Every filter narrows the SAME match set q and paging operate over --
    total is the count of rows matching ALL active filters together, not
    just the last one applied."""
    host, port, stores, stop = _serve_full(tmp_path)
    fleet = stores[1]
    try:
        fleet.upsert({"device_id": "dev-01", "device_ip": "10.0.0.1",
                      "platform": "guestshell", "model": "C9300"})
        fleet.upsert({"device_id": "dev-02", "device_ip": "10.0.0.2",
                      "platform": "guestshell", "model": "C9500"})
        fleet.upsert({"device_id": "other-01", "device_ip": "10.0.0.3",
                      "platform": "guestshell", "model": "C9300"})
        ck, _ = _login(host, port)
        st, _, b = _req(host, port, "GET",
                        "/api/devices?q=dev-&platform=guestshell&limit=1",
                        headers={"Cookie": ck})
        body = json.loads(b)
        assert st == 200 and body["total"] == 2 and len(body["devices"]) == 1
        assert body["devices"][0]["device_id"] == "dev-01"
    finally:
        stop()


_SWARM_BODY = json.dumps({
    "server": {"rpc_up": True},
    "images": [
        {"image": "a.bin", "info_hash": "aa", "peers": [{"ip": "1.1.1.%d" % i}
                                                        for i in range(3)]},
        {"image": "b.bin", "info_hash": "bb", "peers": [{"ip": "2.2.2.%d" % i}
                                                        for i in range(2)]},
    ]}).encode()


def _serve_swarm(tmp_path, body=_SWARM_BODY):
    secrets_path = str(tmp_path / "secrets.json")
    app = gui_app.GuiApp(secrets_path)
    app.set_admin("admin", "pw")
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None,
                                 swarm_fetch=lambda: body)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", srv.server_address[1], srv.shutdown


def test_swarm_unpaged_is_byte_for_byte_passthrough(tmp_path):
    host, port, stop = _serve_swarm(tmp_path)
    try:
        ck, _ = _login(host, port)
        st, _, b = _req(host, port, "GET", "/api/swarm", headers={"Cookie": ck})
        assert st == 200 and b == _SWARM_BODY
    finally:
        stop()


def test_swarm_page_slices_peers_across_images(tmp_path):
    """Peers flatten across images in image order; the image entries all
    survive (the map builds its selector from them) with only their peer
    lists sliced, and peers_total states the real size."""
    host, port, stop = _serve_swarm(tmp_path)
    try:
        ck, _ = _login(host, port)
        seen = []
        for offset in (0, 2, 4):
            st, _, b = _req(host, port, "GET",
                            "/api/swarm?limit=2&offset=%d" % offset,
                            headers={"Cookie": ck})
            body = json.loads(b)
            assert st == 200 and body["peers_total"] == 5
            assert body["peers_limit"] == 2 and body["peers_offset"] == offset
            assert [i["info_hash"] for i in body["images"]] == ["aa", "bb"]
            assert body["server"] == {"rpc_up": True}
            for image in body["images"]:
                seen += [p["ip"] for p in image["peers"]]
        assert seen == ["1.1.1.0", "1.1.1.1", "1.1.1.2", "2.2.2.0", "2.2.2.1"]
    finally:
        stop()


def test_swarm_page_reports_an_unpaginatable_payload(tmp_path):
    """A hub payload that is not the documented shape must never be passed
    through WHOLE to a caller that asked for a page."""
    host, port, stop = _serve_swarm(tmp_path, body=b'{"peers": [1, 2, 3]}')
    try:
        ck, _ = _login(host, port)
        st, _, b = _req(host, port, "GET", "/api/swarm?limit=1",
                        headers={"Cookie": ck})
        assert st == 200
        assert json.loads(b)["error"] == "swarm data not paginatable"
    finally:
        stop()


def test_swarm_page_params_are_rejected_not_defaulted(tmp_path):
    host, port, stop = _serve_swarm(tmp_path)
    try:
        ck, _ = _login(host, port)
        st, _, _ = _req(host, port, "GET", "/api/swarm?limit=0",
                        headers={"Cookie": ck})
        assert st == 400
    finally:
        stop()


@pytest.fixture
def role_api(tmp_path):
    host, port, (_, fleet, _, cat), stop = _serve_full(tmp_path)
    fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1"})
    fleet.upsert({"device_id": "d2", "device_ip": "10.0.0.2"})
    _define_device_role(cat)
    ck, csrf = _auth(host, port)
    headers = {"Cookie": ck, "X-CSRF-Token": csrf}

    def request(method, path, body=None, match=True):
        hh = dict(headers)
        if match:
            hh["If-Match"] = (gui_server._revision_etag(
                "peer-policy", _loaded_peer_policy(cat).document["revision"])
                if match is True else match)
        status, response_headers, raw = _req(
            host, port, method, path, body, headers=hh)
        return status, response_headers, json.loads(raw) if raw else None

    def request_raw(method, path):
        return _req(host, port, method, path, headers=dict(headers))

    request.raw = request_raw
    yield request, fleet, cat
    stop()


@pytest.mark.parametrize("method,path,body", [
    ("POST", "/api/devices/d1/peer-telemetry", {"interval_s": 10}),
    ("PUT", "/api/peer-policy/roles/fiber", {"restricted": False}),
    ("DELETE", "/api/peer-policy/roles/boat", None),
    ("POST", "/api/peer-policy/roles/import-csv", {"csv": "role\nboat\n"}),
    ("PUT", "/api/peer-policy/qos", {"qos": {"numwant": 25}}),
    ("POST", "/api/devices/d1/role", {"role": "boat"}),
    ("POST", "/api/devices/bulk-role", {"device_ids": ["d1"], "role": "boat"}),
])
def test_role_qos_routes_require_exact_strong_cas(role_api, method, path, body):
    request, fleet, cat = role_api
    before = fleet.snapshot(), _loaded_peer_policy(cat).document
    status, headers, problem = request(method, path, body, match=False)
    assert status == 428
    assert problem["code"] == "precondition_required"
    assert problem["type"].endswith("#precondition_required")
    current = gui_server._revision_etag("peer-policy", before[1]["revision"])
    assert headers["ETag"] == current
    for supplied in ('*', 'W/' + current, current + ', ' + current,
                     '"iris-peer-policy-0"'):
        status, headers, problem = request(method, path, body, match=supplied)
        assert status == 412
        assert problem["type"].endswith("#precondition_failed")
        assert headers["ETag"] == current
    assert (fleet.snapshot(), _loaded_peer_policy(cat).document) == before


def test_peer_telemetry_setting_requires_capability_and_preserves_other_qos(role_api):
    request, fleet, cat = role_api
    import peer_policy
    peer_policy.set_qos(os.path.join(cat.state_dir, "peer-policy.json"),
        os.path.join(cat.state_dir, "peer-policy.lkg.json"),
        {"max_peers": 17}, actor="test", now=1, device_id="d1")
    path = "/api/devices/d1/peer-telemetry"
    assert request("POST", path, {"interval_s": 10})[0] == 422
    cat.record_heartbeat("d1", {"peer_telemetry_v": 1})
    status, _, preview = request("POST", path + "?dry_run=1", {"interval_s": 10})
    assert status == 200
    before = _loaded_peer_policy(cat).document
    assert not before.get("roles", {}).get("qos_device", {}).get("d1", {}).get("peer_telemetry_interval_s")
    status, _, result = request("POST", path, {"interval_s": 10,
        "confirm_token": preview["confirm_token"]})
    assert status == 200 and result["requested_interval_s"] == 10
    assert _loaded_peer_policy(cat).document["roles"]["qos_device"]["d1"]["peer_telemetry_interval_s"] == 10
    for invalid in (True, "10", 11, 0, None):
        assert request("POST", path, {"interval_s": invalid})[0] == 422
    # Clearing acceleration remains possible even if the device goes offline.
    cat.record_heartbeat("d1", {}, now=1)
    status, _, preview = request("POST", path + "?dry_run=1", {"interval_s": 60})
    assert status == 200
    status, _, result = request("POST", path, {"interval_s": 60,
        "confirm_token": preview["confirm_token"]})
    assert status == 200
    assert "peer_telemetry_interval_s" not in _loaded_peer_policy(cat).document["roles"]["qos_device"]["d1"]
    assert _loaded_peer_policy(cat).document["roles"]["qos_device"]["d1"]["max_peers"] == 17


def test_role_qos_preview_confirmation_and_delete(role_api):
    from pathlib import Path
    request, fleet, cat = role_api
    request("GET", "/api/peer-policy")
    def snapshot():
        return {str(p.relative_to(cat.state_dir)): p.read_bytes()
                for p in Path(cat.state_dir).rglob('*')
                if p.is_file() and not p.name.endswith('.lock')}
    before = snapshot()
    status, headers, preview = request("PUT", "/api/peer-policy/qos?dry_run=1",
                                       {"qos": {"numwant": 25}})
    assert status == 200
    assert snapshot() == before
    assert preview["dry_run"] and preview["qos_changed"]
    assert preview["requires_confirmation"]
    assert all(preview[key] == 0 for key in (
        "member_delta", "origin_access_lost", "empty_permitted_sets",
        "role_pairs_stopped"))
    status, _, problem = request("PUT", "/api/peer-policy/qos",
                                 {"qos": {"numwant": 25}, "confirm": True})
    assert status in (422, 428)
    status, _, problem = request("PUT", "/api/peer-policy/qos",
                                 {"qos": {"numwant": 24},
                                  "confirm_token": preview["confirm_token"]})
    assert status == 428 and problem["code"] == "confirmation_required"
    status, headers, committed = request("PUT", "/api/peer-policy/qos",
        {"qos": {"numwant": 25}, "confirm_token": preview["confirm_token"]})
    assert status == 200
    assert headers["ETag"] == gui_server._revision_etag(
        "peer-policy", committed["revision"])
    assert request("PUT", "/api/peer-policy/roles/empty",
                   {"restricted": False})[0] == 200
    status, _, preview = request("DELETE", "/api/peer-policy/roles/empty?dry_run=1")
    assert status == 200
    status, headers, body = request("DELETE", "/api/peer-policy/roles/empty",
                                    {"confirm_token": preview["confirm_token"]})
    assert status == 204 and body is None and "ETag" in headers


ROLES_CSV = (
    "role,restricted,peers,origin,nets,on_stale,seed_up_bps,telemetry_pause\n"
    "boat,true,boat;fiber,true,10.20.0.0/16,keep,12500000,false\n"
    "fiber,true,fiber;boat,,,,,\n")


def test_role_definitions_csv_import_previews_then_replaces_every_definition(role_api):
    """#222: the Console's Import CSV is one atomic replacement in the
    iris-role grammar, behind the same CAS + preview + confirmation contract
    as every other policy write; the export is that grammar byte for byte."""
    import role_csv
    request, fleet, cat = role_api
    before = _loaded_peer_policy(cat).document
    status, headers, preview = request(
        "POST", "/api/peer-policy/roles/import-csv?dry_run=1", {"csv": ROLES_CSV})
    assert status == 200, preview
    assert preview["dry_run"] is True and preview["roles"] == 2
    assert preview["confirm_token"]
    assert _loaded_peer_policy(cat).document == before
    status, headers, committed = request(
        "POST", "/api/peer-policy/roles/import-csv",
        {"csv": ROLES_CSV, "confirm_token": preview["confirm_token"]})
    assert status == 200, committed
    assert committed["dry_run"] is False and committed["roles"] == 2
    assert headers["ETag"] == gui_server._revision_etag(
        "peer-policy", committed["revision"])
    doc = _loaded_peer_policy(cat).document
    assert set(doc["roles"]["defs"]) == {"boat", "fiber"}
    assert doc["roles"]["defs"]["boat"] == {
        "restricted": True, "peers": ["boat", "fiber"], "origin": True,
        "nets": ["10.20.0.0/16"], "on_stale": "keep",
        "qos": {"seed_up_bps": 12500000, "telemetry_pause": False}}
    status, headers, raw = request.raw("GET", "/api/peer-policy/roles/export-csv")
    assert status == 200
    assert headers["Content-Type"].startswith("text/csv")
    assert headers["Content-Disposition"].endswith("; filename=roles.csv")
    assert headers["ETag"] == gui_server._revision_etag(
        "peer-policy", committed["revision"])
    assert raw.decode("utf-8") == role_csv.export_roles_csv(doc)
    # The export re-imports as a no-op candidate: same definitions, same file.
    assert role_csv.parse_roles_csv(raw.decode("utf-8")) == doc["roles"]["defs"]


def test_role_definitions_csv_import_refuses_bad_grammar_with_the_cell_named(role_api):
    request, fleet, cat = role_api
    before = _loaded_peer_policy(cat).document
    status, _, problem = request(
        "POST", "/api/peer-policy/roles/import-csv?dry_run=1",
        {"csv": "role,bogus\nboat,1\n"})
    assert status == 422
    assert problem["code"] == "invalid_roles_csv"
    assert problem["detail"] == "unknown roles CSV field: bogus"
    status, _, problem = request(
        "POST", "/api/peer-policy/roles/import-csv?dry_run=1",
        {"csv": "role,seed_up_bps\nboat,fast\n"})
    assert status == 422 and problem["code"] == "invalid_roles_csv"
    assert problem["detail"] == "seed_up_bps must be an integer"
    # A well-formed file with a policy refusal keeps the policy code, and the
    # message still reaches the operator.
    status, _, problem = request(
        "POST", "/api/peer-policy/roles/import-csv?dry_run=1",
        {"csv": "role,peers\nboat,boat;ghost\n"})
    assert status == 422 and problem["code"] == "invalid_policy"
    assert problem["detail"] == "peer references unknown role"
    status, _, problem = request(
        "POST", "/api/peer-policy/roles/import-csv?dry_run=1", {"csv": 7})
    assert status == 422 and problem["code"] == "invalid_policy_request"
    status, _, problem = request(
        "POST", "/api/peer-policy/roles/import-csv?dry_run=1",
        {"csv": "role\nboat\n", "extra": 1})
    assert status == 422 and problem["code"] == "invalid_policy_request"
    assert _loaded_peer_policy(cat).document == before


def test_role_definitions_csv_import_cannot_drop_a_declared_role(role_api):
    request, fleet, cat = role_api
    fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1", "role": "boat"})
    before = _loaded_peer_policy(cat).document
    status, _, problem = request(
        "POST", "/api/peer-policy/roles/import-csv?dry_run=1",
        {"csv": "role,restricted\nfiber,true\n"})
    assert status == 409, problem
    assert problem["code"] == "role_in_use"
    assert problem["roles"] == ["boat"]
    assert _loaded_peer_policy(cat).document == before


def test_role_definitions_export_refuses_degraded_policy(role_api):
    request, fleet, cat = role_api
    path = os.path.join(cat.state_dir, "peer-policy.json")
    with open(path, "w") as f:
        f.write("{not json")
    status, headers, raw = request.raw("GET", "/api/peer-policy/roles/export-csv")
    assert status == 503
    assert headers["Content-Type"] == "application/problem+json"
    assert json.loads(raw)["code"] == "policy_unavailable"


def test_role_definitions_editor_wired_in_console():
    """#222: definitions are created, edited, deleted, imported and exported
    from the Console through the Set role contract (dry run, then commit with
    the preview token), not through a JSON blob."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    panel = _react_shell('policy-dialogs.jsx')
    for cid in ('role-def-new', 'role-def-import', 'role-def-export',
                'role-def-file', 'role-def-rows', 'role-def-status',
                'rd-name', 'rd-peers', 'rd-nets', 'rd-on-stale',
                'rd-restricted', 'rd-origin', 'rd-rates', 'rd-swarm',
                'role-def-preview', 'role-def-save'):
        assert cid in panel
    assert 'id="iris-policies-root" data-policies-react' in html
    assert 'id="role-def-modal"' not in html
    assert "managed through the API or CLI" not in panel
    controller = _react_shell('policies-controller.mjs')
    assert "/api/v1/peer-policy/roles/import-csv" in controller
    assert "/api/v1/peer-policy/roles/export-csv" in controller
    assert "?dry_run=1" in controller and "confirm_token" in controller
    assert "'If-Match'" in controller
    import role_csv
    model = _react_shell('policy-definitions-model.mjs')
    fields = model.split("export const roleQosFields = [")[1].split("];")[0]
    for key in role_csv.ROLE_QOS_FIELDS:
        assert "['%s'," % key in fields, key
    for key in ("origin_up_bps", "origin_per_torrent_up_bps", "origin_max_peers"):
        assert "'%s'" % key not in fields


def test_role_policy_view_and_effective_qos(role_api):
    request, fleet, cat = role_api
    for i in range(12):
        fleet.upsert({"device_id": "drift%02d" % i,
                      "device_ip": "10.1.0.%d" % (i + 1), "role": "boat"})
    status, _, view = request("GET", "/api/peer-policy")
    assert status == 200
    assert view["roles_present"] is True
    assert view["roles"] == {"defined": 1, "restricted": 1,
                              "members": {"boat": 0}}
    assert view["role_drift"] == {"count": 12,
        "device_ids": ["drift%02d" % i for i in range(10)], "truncated": True}
    assert view["outbox"] == {"unacknowledged": 1, "capacity": 256}
    assert view["fleet_rollup"] == {"issued_revision": None, "applied": {},
                                   "states": {"pre-instructions": 14}}
    assert "10.1.0." not in json.dumps(view)
    status, _, qos = request("GET", "/api/devices/d1/effective-qos")
    assert status == 200 and qos["delivery_state"] == "pre-instructions"
    assert qos["instruction"]["display_state"] == "pre-instructions"
    assert qos["instruction"]["accepted_identity"] is None
    assert qos["qos"]["numwant"]["source"] == "builtin"
    assert qos["qos"]["numwant"]["effective_ceiling"] == 50
    assert qos["qos"]["announce_min_interval_s"] == {"value": 30, "source": "builtin"}
    assert qos["qos"]["catalog_tick_s"]["offline_horizon_s"] == 600
    assert qos["qos"]["catalog_tick_s"]["heartbeat_always"] is True
    assert request("GET", "/api/devices/missing/effective-qos")[0] == 404


def test_effective_qos_uses_one_keyed_heartbeat_read_and_projects_identity(
        role_api, monkeypatch):
    request, _, cat = role_api
    cat.record_heartbeat("d1", {
        "instr_protocol": 1, "instr_state": "applied",
        "instr_epoch": 9, "instr_serial": 17,
        "instr_policy_revision": 4, "verify_level": "sig",
        "pointer_skew": False, "private": "must-not-cross-projection",
    }, now=time.time())
    original_get = cat.get_device
    calls = []

    def keyed_get(device_id):
        calls.append(device_id)
        return original_get(device_id)

    def forbid_bulk_read(*args, **kwargs):
        raise AssertionError("effective-QoS must not scan all heartbeats")

    monkeypatch.setattr(cat, "get_device", keyed_get)
    monkeypatch.setattr(cat, "list_devices", forbid_bulk_read)
    status, _, body = request("GET", "/api/devices/d1/effective-qos")
    assert status == 200
    assert calls == ["d1"]
    assert body["instruction"]["display_state"] == "applied"
    assert body["instruction"]["accepted_identity"] == {
        "epoch": 9, "instr_serial": 17, "policy_revision": 4}
    assert "private" not in body["instruction"]
    assert body["delivery_state"] == "pre-instructions"


def test_effective_qos_keeps_desired_explanation_when_heartbeat_is_unreadable(
        role_api, monkeypatch):
    request, _, cat = role_api
    calls = []

    def unreadable(device_id):
        calls.append(device_id)
        raise catalog_mod.StateFileError("unreadable heartbeat shard")

    monkeypatch.setattr(cat, "get_device", unreadable)
    status, _, body = request("GET", "/api/devices/d1/effective-qos")
    assert status == 200
    assert calls == ["d1"]
    assert body["qos"]["numwant"]["source"] == "builtin"
    assert body["instruction"]["display_state"] == "unknown"
    assert body["instruction"]["evidence"] == "server-observed"
    assert body["delivery_state"] == "pre-instructions"


def test_effective_qos_keeps_underlying_report_when_revocation_is_unavailable(
        role_api, monkeypatch):
    request, _, cat = role_api
    cat.record_heartbeat("d1", {
        "instr_protocol": 1, "instr_state": "applied",
        "instr_epoch": 9, "instr_serial": 17,
        "instr_policy_revision": 4, "last_seen": time.time(),
    })
    monkeypatch.setattr(
        gui_server, "_instruction_revoked_principals", lambda store: None)
    status, _, body = request("GET", "/api/devices/d1/effective-qos")
    assert status == 200
    assert body["instruction"]["display_state"] == "unknown"
    assert body["instruction"]["underlying_state"] == "applied"
    assert body["instruction"]["accepted_identity"] == {
        "epoch": 9, "instr_serial": 17, "policy_revision": 4}
    assert body["instruction"]["revoked"] is None
    assert body["qos"]["numwant"]["source"] == "builtin"


# Task 19: the state-owning management API provides one bounded instruction
# projection to both the Devices rows and the fleet roll-up.  These tests are
# intentionally written against the final producer field names from the frozen
# Task 19 preflight addendum; the producer workstream supplies their ingest.

def _task19_stamp(policy_revision, serial=1, epoch=100):
    import instructions
    issued, expires = epoch, epoch + 100
    stamp = {
        "epoch": epoch, "instr_serial": serial,
        "policy_revision": policy_revision, "platform": "guestshell",
        "role": "default", "role_gen": "1" * 64,
        "role_body_sha256": "2" * 64, "key_id": "3" * 64,
        "verify_level": "sig", "issued_at": issued,
        "expires_at": expires, "degraded": False,
        "part": {
            "peers": {"mode": "tracker-only", "include_origin": False,
                      "allowed_expires_at": expires},
            "qos_override": {}, "control_override": {},
            "server_time": issued,
        },
    }
    instructions.validate_stamp(stamp)
    return stamp


@pytest.mark.parametrize("raw_state,display_state,label", [
    ("applied", "applied", "applied r9223372036854775807"),
    ("reasserted", "applied", "applied r9223372036854775807"),
    ("lkg", "lkg", "lkg"),
    ("stale_expired", "stale", "stale"),
    ("allowlist_expired", "stale", "stale"),
    ("rollback_rejected", "rejected", "rejected"),
    ("audience_mismatch", "rejected", "rejected"),
    ("key_rejected", "rejected", "rejected"),
    ("tamper_rejected", "rejected", "rejected"),
    ("verifier_missing", "unavailable", "verifier unavailable"),
    ("lkg_rejected", "rejected", "rejected"),
    ("lkg_unreadable", "unavailable", "LKG unavailable"),
    ("oversize", "rejected", "rejected"),
    ("tracker-only", "tracker-only", "tracker-only"),
    ("instr_pending", "pending", "pending"),
    ("instr_unavailable", "unavailable", "unavailable"),
    ("instr_forbidden", "forbidden", "forbidden"),
    ("floor_reset", "floor_reset", "floor reset"),
    ("none", "none", "no accepted instruction"),
])
def test_instruction_chip_projection_covers_closed_device_states(
        raw_state, display_state, label):
    heartbeat = {
        "last_seen": 100.0, "instr_protocol": 1,
        "instr_state": raw_state, "instr_epoch": 11,
        "instr_serial": (1 << 63) - 1, "instr_policy_revision": 44,
        "verify_level": "sig", "pointer_skew": False,
    }
    if raw_state == "key_rejected":
        heartbeat["instr_reason"] = "unknown_key"
    projected = gui_server._instruction_device_projection(
        heartbeat, revoked=False, observed_at=200.0)
    assert projected["display_state"] == display_state
    assert projected["label"] == label
    assert projected["underlying_state"] == raw_state
    assert projected["accepted_identity"] == {
        "epoch": 11, "instr_serial": (1 << 63) - 1,
        "policy_revision": 44,
    }
    assert projected["report_age_seconds"] == 100
    assert projected["report_stale"] is False
    assert projected["pointer_skew"] is False
    assert projected["evidence"] == "agent-asserted"


def test_instruction_projection_distinguishes_capability_identity_and_revocation():
    legacy = gui_server._instruction_device_projection(
        {"instr_serial": 9, "instr_state": "applied"}, False, 10)
    assert legacy["display_state"] == "pre-instructions"
    assert legacy["reported_instr_serial"] == 9
    assert legacy["accepted_identity"] is None

    for marker in (None, True, "1", 2, {"future": 2}):
        projected = gui_server._instruction_device_projection(
            {"instr_protocol": marker, "instr_state": "applied",
             "instr_epoch": 1, "instr_serial": 2,
             "instr_policy_revision": 3}, False, 10)
        assert projected["display_state"] == "unknown"
        assert projected["label"] == "unknown"

    partial = gui_server._instruction_device_projection(
        {"instr_protocol": 1, "instr_state": "applied",
         "instr_serial": 44, "private": "do-not-project",
         "instr_reason": "<img src=x onerror=alert(1)>"}, False, 10)
    assert partial["display_state"] == "unknown"
    assert partial["accepted_identity"] is None
    assert "private" not in str(partial)
    assert "<img" not in str(partial)

    raw_lkg = {"instr_protocol": 1, "instr_state": "lkg", "instr_epoch": 8,
               "instr_serial": 9, "instr_policy_revision": 10,
               "pointer_skew": "yes", "last_seen": 9}
    lkg = gui_server._instruction_device_projection(raw_lkg, True, 10)
    assert lkg["display_state"] == "revoked"
    assert lkg["label"] == "revoked"
    assert lkg["underlying_state"] == "lkg"
    assert lkg["accepted_identity"]["policy_revision"] == 10
    assert lkg["revoked"] is True
    assert lkg["pointer_skew"] is None
    assert lkg["evidence"] == "server-observed"
    assert lkg["underlying_evidence"] == "agent-asserted"
    assert gui_server._instruction_device_projection(
        raw_lkg, revoked=None, observed_at=10)["display_state"] == "unknown"

    stale = gui_server._instruction_device_projection(
        {"instr_protocol": 1, "instr_state": "applied", "instr_epoch": 8,
         "instr_serial": 9, "instr_policy_revision": 10, "last_seen": 1},
        False, 1000)
    assert stale["display_state"] == "stale"
    assert stale["label"] == "stale · last reported applied r9"
    assert stale["underlying_state"] == "applied"
    assert stale["accepted_identity"]["policy_revision"] == 10
    assert stale["report_age_seconds"] == 999
    assert stale["report_stale"] is True
    assert stale["evidence"] == "server-observed"
    assert stale["underlying_evidence"] == "agent-asserted"
    for bad_last_seen in (None, float("inf"), 1001):
        report = {"instr_protocol": 1, "instr_state": "applied",
                  "instr_epoch": 8, "instr_serial": 9,
                  "instr_policy_revision": 10,
                  "last_seen": bad_last_seen}
        unknown_age = gui_server._instruction_device_projection(
            report, False, 1000)
        assert unknown_age["display_state"] == "unknown"
        assert unknown_age["report_age_seconds"] is None
        assert unknown_age["evidence"] == "server-observed"
    for hostile_last_seen in (-1, -0.5, 10 ** 400):
        hostile_age = gui_server._instruction_device_projection(
            {"instr_protocol": 1, "instr_state": "applied",
             "instr_epoch": 8, "instr_serial": 9,
             "instr_policy_revision": 10, "last_seen": hostile_last_seen},
            False, 1000)
        assert hostile_age["display_state"] == "unknown"
        assert hostile_age["report_age_seconds"] is None


@pytest.mark.parametrize("hostile_reason", [[], {}])
def test_instruction_projection_rejects_unhashable_key_reason_without_raising(
        hostile_reason):
    projected = gui_server._instruction_device_projection(
        {"instr_protocol": 1, "instr_state": "key_rejected",
         "instr_reason": hostile_reason, "last_seen": 9}, False, 10)
    assert projected["display_state"] == "unknown"
    assert projected["underlying_state"] is None
    assert projected["reason"] is None


@pytest.mark.parametrize("hostile_reason", [[], {}])
def test_instruction_chip_api_contains_unhashable_key_reason(tmp_path,
                                                             hostile_reason):
    import json
    import time
    host, port, (_, fleet, _, cat), stop = _serve_full(tmp_path)
    try:
        fleet.upsert({"device_id": "a", "device_ip": "10.0.0.1"})
        cat.record_heartbeat("a", {
            "instr_protocol": 1, "instr_state": "key_rejected",
            "instr_reason": hostile_reason,
        }, now=time.time())
        cookie, _ = _auth(host, port)
        status, _, body = _req(host, port, "GET", "/api/devices",
                               headers={"Cookie": cookie})
        assert status == 200
        instruction = json.loads(body)["devices"][0]["instruction"]
        assert instruction["display_state"] == "unknown"
        assert instruction["underlying_state"] is None
        assert instruction["reason"] is None
    finally:
        stop()


@pytest.mark.parametrize("hostile_drift", [
    {}, [], "bad", {"options": "bad"},
    {"options": [{"option": "bt_max_peers", "expected": 1}]},
])
def test_instruction_projection_keeps_malformed_present_drift_unknown(
        hostile_drift):
    projected = gui_server._instruction_device_projection(
        {"instr_protocol": 1, "instr_state": "applied",
         "instr_epoch": 1, "instr_serial": 2, "instr_policy_revision": 3,
         "last_seen": 9, "qos_drift": hostile_drift}, False, 10)
    assert projected["qos_drift_count"] is None


def test_instruction_projection_counts_absent_supported_drift_as_zero():
    projected = gui_server._instruction_device_projection(
        {"instr_protocol": 1, "instr_state": "applied",
         "instr_epoch": 1, "instr_serial": 2, "instr_policy_revision": 3,
         "last_seen": 9}, False, 10)
    assert projected["qos_drift_count"] == 0


def test_instruction_rollup_unavailable_sources_are_not_zero_evidence():
    inventory = [{"device_id": "a"}, {"device_id": "b"}]
    result = gui_server._instruction_fleet_projection(
        inventory, heartbeat_rows=None, raw_policies=None,
        revoked_principals=None, observed_at=123)
    assert result["fleet_rollup"] == {
        "issued_revision": None, "applied": {}, "states": {"unknown": 2}}
    assert result["instruction_status"] == {
        "observed_at": 123, "instr_stamp_missing": None,
        "pointer_skew": None, "issued_revision_label": None,
    }

    invalid = {"a": {"instr": {"policy_revision": 99}}, "b": {}}
    result = gui_server._instruction_fleet_projection(
        inventory, heartbeat_rows=[], raw_policies=invalid,
        revoked_principals=set(), observed_at=123)
    assert result["fleet_rollup"]["issued_revision"] is None
    assert result["instruction_status"]["instr_stamp_missing"] is None
    assert result["fleet_rollup"]["states"] == {"pre-instructions": 2}

    maximum = (1 << 63) - 1
    result = gui_server._instruction_fleet_projection(
        [{"device_id": "a"}], [],
        {"a": {"instr": _task19_stamp(maximum)}}, set(), 123)
    assert result["fleet_rollup"]["issued_revision"] == maximum
    assert result["instruction_status"]["issued_revision_label"] == (
        "r9223372036854775807")


def test_instruction_rollup_mixed_context_revocation_and_orphans():
    inventory = [{"device_id": name} for name in "abcdefgh"]
    def hb(device_id, state, epoch, serial, revision, **extra):
        row = {"device_id": device_id, "last_seen": 990,
               "instr_protocol": 1, "instr_state": state,
               "instr_epoch": epoch, "instr_serial": serial,
               "instr_policy_revision": revision}
        row.update(extra)
        return row
    heartbeats = [
        hb("a", "applied", 1, 10, 7, pointer_skew=True),
        hb("b", "lkg", 2, 11, 7),
        hb("c", "tamper_rejected", 2, 12, 8),
        hb("d", "instr_pending", 3, 13, 8),
        {"device_id": "e", "last_seen": 990, "instr_protocol": 1,
         "instr_state": "applied", "instr_serial": 14},
        hb("f", "applied", 4, 15, 9, last_seen=1),
        hb("g", "lkg", 4, 16, 9),
        hb("orphan-heartbeat", "applied", 99, 99, 99,
           pointer_skew=True),
    ]
    raw = {
        "a": {"instr": _task19_stamp(7, 10, 100)},
        "b": {"instr": _task19_stamp(8, 11, 101)},
        "orphan-policy": {"instr": _task19_stamp(999, 999, 102)},
    }
    result = gui_server._instruction_fleet_projection(
        inventory, heartbeats, raw, {"device:g"}, 1000)
    assert result["fleet_rollup"] == {
        "issued_revision": 8,
        "applied": {"7": 2, "8": 2, "9": 2},
        "states": {"applied": 1, "lkg": 1, "pending": 1,
                   "pre-instructions": 1, "rejected": 1, "revoked": 1,
                   "stale": 1, "unknown": 1},
    }
    assert sum(result["fleet_rollup"]["states"].values()) == len(inventory)
    assert result["instruction_status"] == {
        "observed_at": 1000, "instr_stamp_missing": 6,
        "pointer_skew": 1, "issued_revision_label": "r8",
    }

    no_revocation = gui_server._instruction_fleet_projection(
        inventory, heartbeats, raw, None, 1000)
    assert no_revocation["fleet_rollup"]["states"] == {"unknown": 8}
    unknown = gui_server._instruction_device_projection(
        heartbeats[0], revoked=None, observed_at=1000)
    assert unknown["display_state"] == "unknown"
    assert unknown["evidence"] == "server-observed"
    assert unknown["revoked"] is None
    assert unknown["underlying_state"] == "applied"
    assert unknown["underlying_evidence"] == "agent-asserted"

    # Map insertion order is the O(n) server contract. The browser owns the
    # display sort, including exact decimal strings above JS's safe integers.
    ordered = gui_server._instruction_fleet_projection(
        [{"device_id": "x"}, {"device_id": "y"}],
        [hb("x", "applied", 1, 1, 9),
         hb("y", "applied", 1, 2, 7)], {}, set(), 1000)
    assert list(ordered["fleet_rollup"]["applied"]) == ["9", "7"]


@pytest.mark.parametrize("store", [
    {"devices": []},
    {"devices": {"bad/id": {"catalog_token": {"revoked": True}}}},
    {"devices": {"a": {"catalog_token": "not-a-record"}}},
    {"devices": {"a": {"catalog_token": {"revoked": "yes"}}}},
])
def test_instruction_revocation_corruption_is_unknown_not_not_revoked(store):
    revoked = gui_server._instruction_revoked_principals(store)
    assert revoked is None
    projected = gui_server._instruction_device_projection(
        {"instr_protocol": 1, "instr_state": "lkg", "instr_epoch": 1,
         "instr_serial": 2, "instr_policy_revision": 3, "last_seen": 9},
        revoked, 10)
    assert projected["display_state"] == "unknown"
    assert projected["revoked"] is None
    assert projected["underlying_state"] == "lkg"


def test_instruction_rollup_uses_one_bulk_snapshot_at_10000_devices(
        tmp_path, monkeypatch):
    import json
    import threading
    import gui_app

    rows = [{"device_id": "dev-%05d" % i, "device_ip": "10.0.0.1"}
            for i in range(10000)]
    heartbeats = []
    for i in range(5000):
        heartbeats.append({
            "device_id": "dev-%05d" % i, "last_seen": 49999,
            "instr_protocol": 1, "instr_state": "applied",
            "instr_epoch": 100 + (i % 2), "instr_serial": i + 1,
            "instr_policy_revision": 7,
            "pointer_skew": i % 100 == 0,
        })
    raw = {"dev-%05d" % (i * 1000): {
        "instr": _task19_stamp(i + 1, serial=i + 1, epoch=100 + i)}
        for i in range(10)}

    class FleetProbe:
        calls = 0
        def snapshot(self):
            self.calls += 1
            return 77, list(rows)

    class CatalogProbe:
        def __init__(self, state_dir):
            self.state_dir = state_dir
            self.heartbeat_calls = 0
            self.raw_policy_calls = 0
        def list_devices(self):
            self.heartbeat_calls += 1
            return list(heartbeats)
        def list_raw_policies(self):
            self.raw_policy_calls += 1
            return dict(raw)
        def list_policies(self):
            raise AssertionError("strict or second policy read is forbidden")

    fleet = FleetProbe()
    catalog = CatalogProbe(str(tmp_path / "state"))
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    app.set_admin("admin", "pw")
    custody_calls = []
    monkeypatch.setattr(gui_server, "instruction_custody_view",
                        lambda _path: custody_calls.append(True) or None)
    original_revoked = gui_server.secrets_store.revoked_device_principals
    revocation_calls = []
    def revoked_once(store):
        revocation_calls.append(True)
        return original_revoked(store)
    monkeypatch.setattr(gui_server.secrets_store,
                        "revoked_device_principals", revoked_once)
    srv = gui_server.make_server(
        "127.0.0.1", 0, app, fleet=fleet, catalog=catalog,
        certfile=None, now_fn=lambda: 50000)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cookie, _ = _auth("127.0.0.1", srv.server_address[1])
        status, _, body = _req(
            "127.0.0.1", srv.server_address[1], "GET", "/api/peer-policy",
            headers={"Cookie": cookie})
        view = json.loads(body)
        assert status == 200
        assert view["fleet_rollup"] == {
            "issued_revision": 10, "applied": {"7": 5000},
            "states": {"applied": 5000, "pre-instructions": 5000},
        }
        assert view["instruction_status"] == {
            "observed_at": 50000, "instr_stamp_missing": 9990,
            "pointer_skew": 50, "issued_revision_label": "r10",
        }
        assert fleet.calls == 1
        assert catalog.heartbeat_calls == 1
        assert catalog.raw_policy_calls == 1
        assert len(revocation_calls) == 1
        assert len(custody_calls) == 1
    finally:
        srv.shutdown()


def test_instruction_rollup_marks_unreadable_bulk_sources_unavailable(
        tmp_path):
    import gui_app
    import json
    import threading
    import catalog as catalog_mod
    class Fleet:
        def snapshot(self):
            return 1, [{"device_id": "a", "device_ip": "10.0.0.1"}]
    class BrokenCatalog:
        state_dir = str(tmp_path / "state")
        def list_devices(self):
            raise catalog_mod.StateFileError("broken heartbeat snapshot")
        def list_raw_policies(self):
            raise catalog_mod.StateFileError("broken raw policy snapshot")
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    app.set_admin("admin", "pw")
    srv = gui_server.make_server(
        "127.0.0.1", 0, app, fleet=Fleet(), catalog=BrokenCatalog(),
        certfile=None, now_fn=lambda: 123)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cookie, _ = _auth("127.0.0.1", srv.server_address[1])
        status, _, body = _req(
            "127.0.0.1", srv.server_address[1], "GET", "/api/peer-policy",
            headers={"Cookie": cookie})
        response = json.loads(body)
        assert status == 200
        assert response["fleet_rollup"] == {
            "issued_revision": None, "applied": {},
            "states": {"unknown": 1}}
        assert response["instruction_status"] == {
            "observed_at": 123, "instr_stamp_missing": None,
            "pointer_skew": None, "issued_revision_label": None}
    finally:
        srv.shutdown()


def test_instruction_chip_is_in_each_paged_device_row_with_revocation_precedence(
        tmp_path):
    import json
    import time
    import secrets_store
    host, port, (app, fleet, _, cat), stop = _serve_full(tmp_path)
    try:
        for device_id in ("a", "b"):
            fleet.upsert({"device_id": device_id,
                          "device_ip": "10.0.0.%s" % (1 if device_id == "a" else 2)})
        now = time.time()
        cat.record_heartbeat("a", {
            "instr_protocol": 1, "instr_state": "applied",
            "instr_epoch": 4, "instr_serial": (1 << 63) - 1,
            "instr_policy_revision": 7, "private": "must-not-leak",
        }, now=now)
        cat.record_heartbeat("b", {
            "instr_protocol": 1, "instr_state": "lkg", "instr_epoch": 5,
            "instr_serial": 6, "instr_policy_revision": 7,
        }, now=now)
        store = secrets_store.load(app.secrets_path)
        store["devices"]["b"] = {
            "catalog_token": {"revoked": True}}
        secrets_store.save(store, app.secrets_path)
        cookie, _ = _auth(host, port)
        pages = []
        for offset in (0, 1):
            status, _, body = _req(
                host, port, "GET", "/api/devices?limit=1&offset=%d" % offset,
                headers={"Cookie": cookie})
            response = json.loads(body)
            assert status == 200
            assert response["total"] == 2 and len(response["devices"]) == 1
            pages.append(response["devices"][0])
        assert [row["device_id"] for row in pages] == ["a", "b"]
        assert pages[0]["instruction"]["label"] == (
            "applied r9223372036854775807")
        assert pages[0]["instruction"]["display_state"] == "applied"
        assert "private" not in json.dumps(pages[0]["instruction"])
        assert pages[1]["instruction"]["display_state"] == "revoked"
        assert pages[1]["instruction"]["evidence"] == "server-observed"
        assert pages[1]["instruction"]["underlying_state"] == "lkg"
        assert pages[1]["instruction"]["underlying_evidence"] == "agent-asserted"
    finally:
        stop()


def test_devices_preserves_fail_closed_heartbeat_snapshot_behavior(tmp_path):
    import gui_app
    import threading
    import catalog as catalog_mod
    class Fleet:
        def snapshot(self):
            return 1, [{"device_id": "a", "device_ip": "10.0.0.1"}]
    class BrokenCatalog:
        state_dir = str(tmp_path / "state")
        def list_devices(self):
            raise catalog_mod.StateFileError("broken heartbeat snapshot")
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    app.set_admin("admin", "pw")
    srv = gui_server.make_server(
        "127.0.0.1", 0, app, fleet=Fleet(), catalog=BrokenCatalog(),
        certfile=None)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cookie, _ = _auth("127.0.0.1", srv.server_address[1])
        status, _, body = _req(
            "127.0.0.1", srv.server_address[1], "GET", "/api/devices",
            headers={"Cookie": cookie})
        assert status == 503
        assert "unavailable" in json.loads(body)["error"]
    finally:
        srv.shutdown()


def test_role_drift_accepts_preloaded_rows_without_a_second_fleet_read(
        tmp_path):
    import peer_policy
    import role_management
    result = peer_policy.load_policy(
        str(tmp_path / "missing.json"), str(tmp_path / "missing-lkg.json"))
    class FleetMustNotBeRead:
        def snapshot(self):
            raise AssertionError("preloaded rows must be authoritative")
    report = role_management.drift_report(
        FleetMustNotBeRead(), result,
        rows=[{"device_id": "a", "role": "missing-role"}])
    assert report == {"count": 1, "device_ids": ["a"], "truncated": False}


def _run_instruction_console_js(script):
    import subprocess
    root = Path(gui_server.WEBROOT).parent / 'console-ui/src'
    imports = (f"import {{instructionBadge}} from {json.dumps((root / 'inventory-model.mjs').as_uri())};\n"
               f"import {{instructionDiagnostics}} from {json.dumps((root / 'policy-model.mjs').as_uri())};\n")
    result = subprocess.run(["node", "--input-type=module", "-"], input=imports + r'''
import assert from 'node:assert/strict';
let panel;
function renderInstructionPanel(policy) {
  panel = instructionDiagnostics(policy, value => 'time:' + value);
}
''' + script, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr


def test_instruction_console_structure_labels_and_no_new_fetch_or_timer():
    component = _react_shell('policy-dialogs.jsx')
    assert "'Instructions'" in _react_shell('inventory.jsx')
    assert 'colSpan={12}' in _react_shell('inventory.jsx')
    for identifier in (
            "policy-issued-revision", "policy-applied-revisions",
            "policy-instruction-states", "policy-instr-stamp-missing",
            "policy-pointer-skew", "policy-instruction-observed",
            "instruction-key-state", "instruction-cert-days",
            "instruction-keylist-age", "instruction-root-ceremony",
            "instruction-root-quorum", "instruction-key-actions"):
        assert identifier in component
    for label in ("Server-observed", "Device-authored", "Agent-asserted",
                  "violation = 0 does not mean compliant"):
        assert label in component
    model = _react_shell('policy-model.mjs')
    assert "fetch(" not in model
    assert "setTimeout(" not in model


def test_instruction_console_renders_exact_escaped_chip_rollup_and_custody():
    _run_instruction_console_js(r'''
let cell = instructionBadge({instruction: {
  label: 'stale · last reported applied r9223372036854775807<img>', display_state: 'stale',
  underlying_state: 'applied', evidence: 'server-observed',
  report_age_seconds: 601, report_stale: true, pointer_skew: true,
  qos_drift_count: 0
}});
assert.equal(cell.label, 'stale · last reported applied r9223372036854775807<img>');
assert.doesNotMatch(cell.label, /9223372036854776000/);
// React escapes these text fields; the browser suite verifies no HTML executes.
assert.match(cell.detail, /server-observed/);
assert.match(cell.detail, /last agent report \(agent-asserted\): applied/);
assert.match(cell.detail, /report 601s old/);
assert.match(cell.detail, /pointer skew/);
let rejected = instructionBadge({instruction: {label: 'rejected',
  display_state: 'rejected', underlying_state: 'key_rejected',
  evidence: 'agent-asserted', reason: 'unknown_key', report_age_seconds: 1}});
assert.match(rejected.detail, /reason: unknown_key/);

renderInstructionPanel({
  fleet_rollup: {issued_revision: 12,
    applied: {'7': 2, '9223372036854775807': 1},
    states: {applied: 3, unknown: 1}},
  instruction_status: {observed_at: 456, instr_stamp_missing: 4,
    pointer_skew: 1},
  instruction_keys: {state: 'signing_refused',
    enabled: true, certificate_renewal_due: true, signing_refused: true,
    keylist_resign_due: true,
    certificate_days_to_expiry: -2, keylist_age_days: 136,
    root_ceremony_overdue: 'critical', root_quorum_degraded: true,
    roots_attested_180d: 1, roots_configured: 2}
});
assert.equal(panel.cells['policy-issued-revision'], 'r12');
assert.deepEqual(panel.applied, [{label: 'r7', count: 2}, {label: 'r9223372036854775807', count: 1}]);
assert.equal(panel.cells['policy-instr-stamp-missing'], '4 devices');
assert.equal(panel.cells['policy-pointer-skew'], '1 device');
assert.equal(panel.cells['policy-instruction-observed'], 'time:456');
assert.equal(panel.cells['instruction-cert-days'], '-2 days');
assert.equal(panel.cells['instruction-key-state'], 'Signing stopped');
assert.match(panel.cells['instruction-root-ceremony'], /Review overdue/);
assert.match(panel.cells['instruction-root-quorum'], /Confirmation needed/);
assert.match(panel.cells['instruction-key-actions'], /Renew signing certificate/);
assert.match(panel.cells['instruction-key-actions'], /Signing is stopped/);
assert.match(panel.cells['instruction-key-actions'], /Re-sign revocation list/);

renderInstructionPanel({fleet_rollup: {issued_revision: null, applied: {}, states: {}},
  instruction_status: {observed_at: 500, instr_stamp_missing: null,
    pointer_skew: null}, instruction_keys: null});
assert.equal(panel.cells['policy-instr-stamp-missing'], 'unavailable');
assert.equal(panel.cells['policy-pointer-skew'], 'unavailable');
assert.equal(panel.cells['instruction-cert-days'], 'unavailable');
assert.equal(panel.cells['instruction-root-ceremony'], 'Unavailable');
assert.equal(panel.cells['instruction-key-actions'], 'Unavailable');
assert.deepEqual(panel.applied, [{label: 'unavailable'}]);

let unknownDrift = instructionBadge({instruction: {label: 'unknown',
  display_state: 'unknown', evidence: 'agent-asserted',
  report_age_seconds: 1, qos_drift_count: null}});
assert.match(unknownDrift.detail, /QoS drift unavailable/);

renderInstructionPanel({fleet_rollup: {issued_revision: 0, applied: {'0': 1}, states: {applied: 1}},
  instruction_status: {observed_at: 501, instr_stamp_missing: 0,
    pointer_skew: 0}, instruction_keys: {state: 'ready',
    enabled: true, certificate_renewal_due: false, signing_refused: false,
    keylist_resign_due: true,
    certificate_days_to_expiry: 0, keylist_age_days: 100,
    root_ceremony_overdue: 'warn', root_quorum_degraded: false,
    roots_attested_180d: 2, roots_configured: 2}});
assert.equal(panel.cells['policy-issued-revision'], 'r0');
assert.equal(panel.cells['policy-instr-stamp-missing'], '0 devices');
assert.equal(panel.cells['policy-pointer-skew'], '0 devices');
assert.equal(panel.cells['instruction-cert-days'], '0 days');
assert.match(panel.cells['instruction-root-ceremony'], /Review due/);
assert.match(panel.cells['instruction-root-quorum'], /Confirmed/);
assert.equal(panel.cells['instruction-key-actions'], 'Re-sign revocation list');

renderInstructionPanel({fleet_rollup: {issued_revision: null, applied: {}, states: {}},
  instruction_status: {observed_at: 502, instr_stamp_missing: 0,
    pointer_skew: 0}, instruction_keys: {state: 'phase0', enabled: false,
    certificate_renewal_due: false, signing_refused: false,
    keylist_resign_due: false, certificate_days_to_expiry: null,
    keylist_age_days: null, root_ceremony_overdue: 'unknown',
    root_quorum_degraded: false, roots_attested_180d: 0,
    roots_configured: 0}});
assert.equal(panel.cells['instruction-root-quorum'], 'Not enabled');
assert.equal(panel.cells['instruction-key-actions'], 'Not enabled');
''')


def test_role_explain_requires_current_unambiguous_typed_endpoints(role_api):
    import auth
    import peer_endpoints
    request, fleet, cat = role_api
    path = os.path.join(cat.state_dir, "peer-endpoints.json")
    assert request("GET", "/api/peer-policy/explain?a=d1&b=d2")[0] == 422
    for device_id, ip in (("d1", "192.0.2.1"), ("d2", "192.0.2.2")):
        peer_endpoints.record_endpoint(path, auth.Principal("device", device_id),
                                       ip, 6881, time.time())
    status, _, result = request("GET", "/api/peer-policy/explain?a=device:d1&b=d2")
    assert status == 200 and result["mutual"] is True
    assert result["a"]["principal"] == {"type": "device", "id": "d1"}
    assert result["a"]["acl_source"] == "none"
    assert "192.0.2." not in json.dumps(result)
    assert request("GET", "/api/peer-policy/explain?a=legacy:d1&b=d2")[0] == 422
    peer_endpoints.record_endpoint(path, auth.Principal("device", "d2"),
                                   "192.0.2.1", 6881, time.time())
    assert request("GET", "/api/peer-policy/explain?a=d1&b=d2")[0] == 422


@pytest.mark.parametrize("name", ["default", "quarantine", "origin", "seeder", "legacy"])
def test_role_reserved_problem_identity(role_api, name):
    request, _, _ = role_api
    status, _, problem = request("PUT", "/api/peer-policy/roles/" + name,
                                 {"restricted": False})
    assert status == 409
    assert problem["code"] == "role_reserved_name"
    assert problem["type"].endswith("#role_reserved_name")


def test_role_locked_race_backlog_and_invalid_qos(role_api, monkeypatch):
    import peer_policy
    request, fleet, cat = role_api
    original = peer_policy.commit_mutation
    def racing(*args, **kwargs):
        raise peer_policy.RevisionConflict(99)
    monkeypatch.setattr(peer_policy, "commit_mutation", racing)
    status, headers, problem = request("PUT", "/api/peer-policy/qos",
                                       {"qos": {"numwant": 25}})
    assert status == 409 and problem["code"] == "revision_conflict"
    assert headers["ETag"] == '"iris-peer-policy-99"'
    def backlog(*args, **kwargs):
        raise peer_policy.OperationBacklogFull("private path")
    monkeypatch.setattr(peer_policy, "commit_mutation", backlog)
    status, _, problem = request("PUT", "/api/peer-policy/qos", {"qos": {}})
    assert status == 409 and problem["code"] == "operation_backlog_full"
    assert problem["capacity"] == 256 and "private" not in json.dumps(problem)
    monkeypatch.setattr(peer_policy, "commit_mutation", original)
    for qos in ({"numwant": -1}, {"catalog_tick_s": 61}, {"http_rate": 123}):
        status, _, problem = request("PUT", "/api/peer-policy/qos", {"qos": qos})
        assert status == 422
        assert problem["type"].endswith("#" + problem["code"])


def test_role_single_bulk_confirm_and_shadow(role_api):
    import peer_policy
    request, fleet, cat = role_api
    path = "/api/devices/bulk-role"
    body = {"device_ids": ["d2", "missing", "d1"], "role": "boat"}
    status, _, preview = request("POST", path + "?dry_run=1", body)
    assert status == 200 and preview["requires_confirmation"]
    assert preview["failed"] == {"missing": "no such device"}
    assert not fleet.get_device("d1").get("role")
    status, _, problem = request("POST", path, body)
    assert status == 428 and problem["code"] == "confirmation_required"
    status, headers, result = request("POST", path,
        dict(body, confirm_token=preview["confirm_token"]))
    assert status == 200 and result["applied"] == 2
    assert result["failed"] == {"missing": "no such device"}
    assert request("POST", "/api/devices/missing/role", {"role": "boat"})[0] == 404
    assert request("POST", "/api/devices/d1/role", {"role": "unknown"})[0] == 404
    status, _, problem = request("DELETE", "/api/peer-policy/roles/boat")
    assert status == 409 and problem["member_count"] == 2
    assert problem["referring_roles"] == []
    def assign(doc):
        doc["acls"]["manual"] = {"rules": [{"seq": 17, "action": "deny",
                                               "match": {"type": "any"}}]}
        doc["assignments"]["d1"] = "manual"
    peer_policy.commit_mutation(os.path.join(cat.state_dir, "peer-policy.json"),
        os.path.join(cat.state_dir, "peer-policy.lkg.json"), action="assign",
        target="d1", actor="test", now=1, mutate=assign)
    for path, body in (("/api/devices/d1/role", {"role": "boat"}),
                       ("/api/devices/bulk-role", {"device_ids": ["d1"], "role": "boat"})):
        status, _, problem = request("POST", path, body)
        assert status == 409 and problem["code"] == "role_shadowed_by_assignment"
        assert request("POST", path, dict(body, allow_shadow=True))[0] == 422


def test_role_explain_loaded_roles_shadow_quarantine_and_fail_closed(role_api, monkeypatch):
    import auth
    import peer_policy
    import peer_endpoints
    request, fleet, cat = role_api
    endpoints = os.path.join(cat.state_dir, "peer-endpoints.json")
    for kind, did, ip in (("device", "d1", "192.0.2.1"),
                          ("device", "d2", "192.0.2.2"),
                          ("service", "seeder", "192.0.2.3")):
        peer_endpoints.record_endpoint(endpoints, auth.Principal(kind, did), ip, 6881, time.time())
    doc = _loaded_peer_policy(cat).document
    doc["roles"]["role_of"] = {"d1": "boat", "d2": "boat"}
    compiled = peer_policy.compile_roles(doc)
    policy = peer_policy.PolicyResult(doc, False, False, compiled)
    original = peer_policy.evaluate_for
    seen = []
    def evaluate(*args, **kwargs):
        assert kwargs["compiled"] is policy.roles
        seen.append(args[1].id)
        return original(*args, **kwargs)
    monkeypatch.setattr(peer_policy, "evaluate_for", evaluate)
    monkeypatch.setattr(peer_policy, "load_policy", lambda *_: policy)
    status, _, result = request("GET", "/api/peer-policy/explain?a=d1&b=d2")
    assert status == 200 and result["mutual"] and seen == ["d1", "d2"]
    assert result["a"]["matched_seq"] == 10
    assert result["a"]["acl_name"] == "role:boat"
    assert result["a"]["role_shadowed_by"] is None
    assert request("GET", "/api/peer-policy/explain?a=d1&b=service:seeder")[2]["a"]["matched_seq"] == 20
    doc["acls"]["manual"] = {"rules": [{"seq": 17, "action": "deny",
                        "match": {"type": "cidr", "value": "192.0.2.0/24"}}]}
    doc["assignments"]["d1"] = "manual"
    policy = policy._replace(roles=peer_policy.compile_roles(doc))
    result = request("GET", "/api/peer-policy/explain?a=d1&b=d2")[2]
    assert not result["mutual"]
    assert result["a"]["acl_name"] == "manual" and result["a"]["matched_seq"] == 17
    assert result["a"]["role_shadowed_by"] == "boat"
    doc["assignments"]["d1"] = "quarantine"
    policy = policy._replace(roles=peer_policy.compile_roles(doc))
    result = request("GET", "/api/peer-policy/explain?a=d1&b=d2")[2]
    assert result["a"]["role_shadowed_by"] is None
    assert result["a"]["acl_name"] == "quarantine" and result["a"]["decision"] == "deny"
    doc["assignments"].clear()
    doc["roles"]["role_of"]["d1"] = "missing"
    policy = policy._replace(roles=peer_policy.compile_roles(doc))
    result = request("GET", "/api/peer-policy/explain?a=d1&b=d2")[2]
    assert result["a"]["role_unknown"] is True
    assert result["a"]["decision"] == "deny" and result["a"]["matched_seq"] == 40
    policy = policy._replace(fail_closed=True, degraded=True)
    result = request("GET", "/api/peer-policy/explain?a=d1&b=d2")[2]
    assert not result["mutual"]
    assert all(result[side]["decision"] == "deny" and result[side]["matched_seq"] is None
               for side in ("a", "b"))


def test_role_policy_view_effective_outbox_and_status_redaction(role_api):
    request, _, cat = role_api
    status_path = os.path.join(cat.state_dir, "peer-enforcement.json")
    with open(status_path, "w") as stream:
        json.dump({"last_operation_exported_revision": 999,
                   "last_error": "10.0.0.8", "conflicts": [{"reason": "device:private"}]}, stream)
    view = request("GET", "/api/peer-policy")[2]
    assert view["outbox"]["unacknowledged"] == 1
    assert "10.0.0.8" not in json.dumps(view) and "device:private" not in json.dumps(view)
    with open(status_path, "w") as stream:
        json.dump({"last_operation_exported_revision": view["revision"]}, stream)
    assert request("GET", "/api/peer-policy")[2]["outbox"]["unacknowledged"] == 1
    assert request("PUT", "/api/peer-policy/roles/fiber", {"restricted": True})[0] == 200
    current = _loaded_peer_policy(cat).document
    assert len(current["operation_outbox"]) == 2
    peer_enforcement.write_status(status_path, peer_enforcement.build_status(
        "enforced", "s", "h", None, 0, time.time(),
        last_operation_exported_revision=current["revision"],
        operation_ack_epoch=current.get("operation_ack_epoch")))
    view = request("GET", "/api/peer-policy")[2]
    assert view["enforcement"]["state"] == "enforced"
    assert view["outbox"]["unacknowledged"] == 0
    assert request("PUT", "/api/peer-policy/roles/copper", {"restricted": True})[0] == 200
    assert len(_loaded_peer_policy(cat).document["operation_outbox"]) == 1


def test_role_put_normalizes_reciprocal_edges_and_reports_isolation(role_api):
    request, _, cat = role_api
    before = _loaded_peer_policy(cat).document
    for query in ("", "?dry_run=1"):
        status, _, problem = request("PUT", "/api/peer-policy/roles/boat" + query,
                                     {"restricted": True, "peers": ["boat", "boat"]})
        assert status == 422 and problem["code"] == "invalid_policy"
        assert _loaded_peer_policy(cat).document == before
    assert request("PUT", "/api/peer-policy/roles/fiber", {"restricted": True})[0] == 200
    definition = {"restricted": True, "peers": ["boat", "fiber"],
                  "nets": ["192.0.2.1", "192.0.2.1/024", "192.0.2.1/255.255.255.0",
                           "192.0.2.1/0.0.0.255"]}
    status, _, preview = request("PUT", "/api/peer-policy/roles/boat?dry_run=1", definition)
    assert status == 200
    status, _, _ = request("PUT", "/api/peer-policy/roles/boat",
                           dict(definition, confirm_token=preview["confirm_token"]))
    assert status == 200
    assert _loaded_peer_policy(cat).document["roles"]["defs"]["fiber"]["peers"] == ["fiber", "boat"]
    assert _loaded_peer_policy(cat).document["roles"]["defs"]["boat"]["nets"] == definition["nets"]
    status, _, problem = request("PUT", "/api/peer-policy/roles/boat",
                                 {"restricted": True, "peers": []})
    assert status == 409 and problem["code"] == "role_isolated"


def test_role_qos_confirmation_expires_after_another_revision(role_api):
    request, _, _ = role_api
    body = {"qos": {"numwant": 25}}
    status, _, preview = request("PUT", "/api/peer-policy/qos?dry_run=1", body)
    assert status == 200
    assert request("PUT", "/api/peer-policy/roles/fiber", {"restricted": False})[0] == 200
    status, _, problem = request("PUT", "/api/peer-policy/qos",
                                 dict(body, confirm_token=preview["confirm_token"]))
    assert status == 428 and problem["code"] == "confirmation_required"


def test_role_mutation_preserves_failure_audit_and_preview_is_read_only(tmp_path):
    host, port, (_, fleet, _, cat), audit_path, stop = _serve_full_audit(tmp_path)
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "192.0.2.1"})
        _define_device_role(cat)
        ck, csrf = _auth(host, port)
        headers = {"Cookie": ck, "X-CSRF-Token": csrf, "If-Match":
                   gui_server._revision_etag("peer-policy", _loaded_peer_policy(cat).document["revision"])}
        def events():
            with open(audit_path) as stream:
                return [json.loads(line) for line in stream if line.strip()]
        before = events()
        assert _req(host, port, "POST", "/api/devices/d1/role?dry_run=1",
                    {"role": "boat"}, headers=headers)[0] == 200
        assert events() == before
        assert _req(host, port, "POST", "/api/devices/d1/role",
                    {"role": "unknown"}, headers=headers)[0] == 404
        row = events()[-1]
        assert row["event"] == "device_role_change" and row["result"] == "fail"
        assert row["target"] == "d1" and "role_not_found" in row["detail"]
    finally:
        stop()


@pytest.mark.parametrize("filename,payload", [
    ("peer-enforcement.json", {"state": "enforced", "last_reconciled_at": 1}),
    ("peer-enforcement.json", {"conflicts": [{"reason": []}]}),
    ("peer-enforcement.json", {"conflicts": [{"reason": {}}]}),
    ("peer-enforcement.json", {"last_error": "abc123deadbeef"}),
    ("origin-qos.json", {"state": "enforced", "global_option_count": 0,
                         "target_download_count": 2, "applied_download_count": 2}),
    ("origin-qos.json", {"state": [], "last_error": "abc123deadbeef"}),
])
def test_policy_contract_invalid_auxiliary_status_is_neutral(role_api, filename, payload):
    request, _, cat = role_api
    with open(os.path.join(cat.state_dir, filename), "w") as stream:
        json.dump(payload, stream)
    status, _, view = request("GET", "/api/peer-policy")
    assert status == 200
    key = "origin_qos" if filename == "origin-qos.json" else "enforcement"
    assert view[key]["state"] is None
    assert view[key]["last_error"] is None
    assert "abc123deadbeef" not in json.dumps(view)


def test_policy_contract_roles_capability_is_independent_of_presence(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        cookie, _ = _auth(host, port)
        status, _, raw = _req(host, port, "GET", "/api/peer-policy", headers={"Cookie": cookie})
        view = json.loads(raw)
        assert status == 200 and view["roles_supported"] is True
        assert view["roles_present"] is False
    finally:
        stop()


def test_policy_contract_live_success_and_request_schemas(role_api):
    from openapi_schema_validator import OAS32Validator
    import openapi_contract
    request, _, cat = role_api
    spec = openapi_contract.build_document()
    cases = [
        ("PUT", "/api/peer-policy/roles/new?dry_run=1", "/peer-policy/roles/{name}", {"restricted": False}),
        ("DELETE", "/api/peer-policy/roles/boat?dry_run=1", "/peer-policy/roles/{name}", {}),
        ("PUT", "/api/peer-policy/qos?dry_run=1", "/peer-policy/qos", {"qos": {"max_peers": 4}}),
        ("PUT", "/api/peer-policy/qos?dry_run=1", "/peer-policy/qos", {"qos": {}}),
        ("POST", "/api/devices/d1/role?dry_run=1", "/devices/{device_id}/role", {"role": None}),
        ("POST", "/api/devices/bulk-role?dry_run=1", "/devices/bulk-role", {"role": None, "device_ids": ["d1"]}),
        ("POST", "/api/devices/d1/role?dry_run=1", "/devices/{device_id}/role", {"role": "boat"}),
        ("POST", "/api/devices/d1/role", "/devices/{device_id}/role", {"role": None}),
        ("POST", "/api/devices/bulk-role", "/devices/bulk-role", {"role": None, "device_ids": ["d1"]}),
    ]
    for method, path, suffix, body in cases:
        operation = spec["paths"]["/api/v1" + suffix][method.lower()]
        OAS32Validator(operation["requestBody"]["content"]["application/json"]["schema"]).validate(body)
        status, _, payload = request(method, path, body)
        assert status == 200, payload
        schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
        OAS32Validator(schema).validate(payload)


@pytest.mark.parametrize("origin", [False, True])
def test_policy_contract_complete_auxiliary_semantics_and_known_errors(role_api, origin):
    import origin_qos
    request, _, cat = role_api
    if origin:
        base = origin_qos.build_status("enforced", "session", "hash", 1, 2, 2, 1000)
        filename, key = "origin-qos.json", "origin_qos"
        mutations = [{"global_option_count": 0}, {"applied_download_count": 3},
                     {"target_download_count": True}]
    else:
        base = peer_enforcement.build_status("enforced", "session", "hash", 2, 3, 1000)
        filename, key = "peer-enforcement.json", "enforcement"
        mutations = [{"desired_ip_count": -1}, {"applied_revision": True},
                     {"conflicts": [{"reason": []}]}]
    def view(payload):
        with open(os.path.join(cat.state_dir, filename), "w") as stream:
            json.dump(payload, stream)
        status, _, result = request("GET", "/api/peer-policy")
        assert status == 200
        return result[key]
    assert view(base)["state"] == "enforced"
    error = "origin_reconcile_failed" if origin else "peer_reconcile_failed"
    degraded = dict(base, state="degraded", last_error=error)
    assert view(degraded)["last_error"] == error
    mutations += [{"aria_session_id": None}, {"desired_hash": None},
                  {"last_reconciled_at": float("nan")},
                  {"state": "degraded", "last_error": "abc123deadbeef"},
                  {"state": []}, {"last_error": {}}]
    for change in mutations:
        projected = view(dict(base, **change))
        assert projected["state"] is None, change
        assert projected["last_error"] is None, change


def test_policy_contract_actual_reads_confirmed_qos_and_role_definition(role_api):
    import auth
    import peer_endpoints
    import openapi_contract
    from openapi_schema_validator import OAS32Validator
    request, _, cat = role_api
    spec = openapi_contract.build_document()
    def check(method, path, pattern, body=None):
        operation = spec["paths"]["/api/v1" + pattern][method.lower()]
        if body is not None:
            OAS32Validator(operation["requestBody"]["content"]["application/json"]["schema"]).validate(body)
        status, headers, payload = request(method, "/api" + path, body)
        assert status == 200, payload
        OAS32Validator(operation["responses"]["200"]["content"]["application/json"]["schema"]).validate(payload)
        assert "ETag" in headers
        return payload
    definition = {"restricted": False, "peers": ["complete"], "origin": True,
                  "nets": ["192.0.2.0/24"], "on_stale": "defaults", "qos": {}}
    preview = check("PUT", "/peer-policy/roles/complete?dry_run=1", "/peer-policy/roles/{name}", definition)
    check("PUT", "/peer-policy/roles/complete", "/peer-policy/roles/{name}",
          dict(definition, confirm_token=preview["confirm_token"]))
    check("GET", "/peer-policy", "/peer-policy")
    check("GET", "/peer-policy/roles", "/peer-policy/roles")
    check("GET", "/devices/d1/effective-qos", "/devices/{device_id}/effective-qos")
    for did, address in (("d1", "192.0.2.1"), ("d2", "192.0.2.2")):
        peer_endpoints.record_endpoint(os.path.join(cat.state_dir, "peer-endpoints.json"),
                                      auth.Principal("device", did), address, 6881, time.time())
    check("GET", "/peer-policy/explain?a=d1&b=d2", "/peer-policy/explain")
    preview = check("PUT", "/peer-policy/qos?dry_run=1", "/peer-policy/qos", {"qos": {"max_peers": 4}})
    assert preview["requires_confirmation"]
    check("PUT", "/peer-policy/qos", "/peer-policy/qos",
          {"qos": {"max_peers": 4}, "confirm_token": preview["confirm_token"]})


def test_tracker_state_write_retains_success_failure_audit_and_read_only_preview(tmp_path):
    host, port, (_, fleet, _, cat), audit_path, stop = _serve_full_audit(tmp_path)
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "192.0.2.1"})
        _define_device_role(cat)
        cookie, csrf = _auth(host, port)

        def request(path, body):
            headers = {"Cookie": cookie, "X-CSRF-Token": csrf, "If-Match":
                       gui_server._revision_etag("peer-policy",
                           _loaded_peer_policy(cat).document["revision"])}
            status, response_headers, raw = _req(
                host, port, "PUT", path, body, headers=headers)
            return status, response_headers, json.loads(raw)

        def events():
            with open(audit_path) as stream:
                return [json.loads(line) for line in stream if line.strip()]

        before = events()
        prior = _loaded_peer_policy(cat).document
        body = {"qos_state": {"seeder": {"numwant": 4}}}
        status, _, preview = request("/api/peer-policy/qos?dry_run=1", body)
        assert status == 200 and preview["qos_changed"] is True
        assert events() == before
        assert _loaded_peer_policy(cat).document == prior
        status, _, committed = request("/api/peer-policy/qos",
            dict(body, confirm_token=preview["confirm_token"]))
        assert status == 200 and committed["revision"] == prior["revision"] + 1
        after = events()
        assert len(after) == len(before) + 1
        assert after[-1]["event"] == "peer_policy_change"
        assert after[-1]["action"] == "put" and after[-1]["target"] == "qos"
        assert after[-1]["result"] == "ok"
        before_policy = _loaded_peer_policy(cat).document
        status, _, problem = request("/api/peer-policy/qos", {
            "qos_state": {"seeder": {"numwant": 3}}})
        assert status == 422 and problem["code"] == "invalid_policy"
        failed = events()
        assert len(failed) == len(after) + 1
        assert failed[-1]["event"] == "peer_policy_change"
        assert failed[-1]["target"] == "qos" and failed[-1]["result"] == "fail"
        assert "invalid_policy" in failed[-1]["detail"]
        assert _loaded_peer_policy(cat).document == before_policy
    finally:
        stop()


# ---------------------------------------------------------------------------
# Phase 2, Task 25: schedules list and the "Schedule…" bulk action
# ---------------------------------------------------------------------------

def _schedule_projections():
    """The console's own schedule projections, run under Node.

    They are pure string builders over the schedule/occurrence documents the
    API returns, so they are executed here rather than pattern-matched: a
    console that renders a wave's counts or an orphaned creator wrongly is a
    console the operator cannot plan a window from.
    """
    import shutil
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for console schedule projection tests")
    from pathlib import Path
    module = (Path(gui_server.WEBROOT).parent / "console-ui/src/schedules-model.mjs").as_uri()
    names = "scheduleTargetSummary, scheduleNextFireText, scheduleDeltaText, scheduleWaveText, scheduleCreatorText, scheduleTargetFromFilters, scheduleDefinitionFromForm, pendingScheduleText"
    return node, "import {" + names + "} from " + json.dumps(module) + ";"


def _run_schedule_projections(script):
    import json as _json
    import subprocess
    node, block = _schedule_projections()
    program = (block + "\nconst esc = value => String(value);\n" + script)
    result = subprocess.run([node, "--input-type=module"], input=program, text=True,
                            capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    return _json.loads(result.stdout)


_SCHEDULE_ROW = {
    "id": "s-core", "kind": "assign", "state": "pending",
    "target": {"filters": {"role": "core", "status": "deployed"},
               "device_ids": [], "bind": "late"},
    "payload": {"image_ids": ["image-a"], "mode": "merge"},
    "when": {"kind": "recurring", "weekday": 6, "hour": 2, "minute": 30,
             "tz": "Europe/Stockholm", "window_seconds": 3600},
    "created_by": "console:alice", "created_at": 1788883200, "rev": 1,
    "generation": "0" * 32, "creator_exists": True,
    "preview": {"revision": 2, "now": 1788883200,
                "device_ids": ["edge-1", "edge-2"]},
    "etag": '"iris-schedule-s-core-1"',
    "next_fire": {"scheduled_at": 1789000200, "window_end": 1789003800,
                  "status": "future", "resolution": "normal",
                  "tz": "Europe/Stockholm", "local_time": "2026-09-13T02:30",
                  "next_at": 1789605000},
}

_SCHEDULE_OCCURRENCE = {
    "id": "a" * 32, "schedule_id": "s-core", "state": "running",
    "scheduled_at": 1788940200, "window_end": 1788943800,
    "delta": {"added": 3, "removed": 1},
    "annotations": {"wave": {
        "schedule_id": "s-before", "occurrence_id": "b" * 32, "total": 10,
        "staged": 7, "errored": 1, "missing": 2, "gate": "held",
        "observed_at": 1788940260}},
}


def test_schedules_panel_lists_the_schedule_facts_an_operator_plans_from():
    html = _react_shell("schedules.jsx")
    assert "['manage-schedules', 'Schedules']" in _react_shell('inventory.jsx')
    panel = html.split('id="sched-panel"', 1)[1]
    for column in ("Action", "Target", "Next run", "State",
                   "Latest run", "Created by"):
        assert "'" + column + "'" in panel, column
    assert 'id="sched-rows"' in html and 'id="sched-close"' in html

    js = _react_shell("schedules-controller.mjs")
    assert "async refresh(" in js
    assert "'/api/v1/schedules'" in js
    # The list reads the schedule's own next-fire slot rather than
    # recomputing DST-aware weekly arithmetic in the browser.
    assert "row.next_fire" in _react_shell("schedules-model.mjs")


def test_schedule_row_projections_report_target_delta_and_wave_counts():
    out = _run_schedule_projections(
        "const row = " + json.dumps(_SCHEDULE_ROW) + ";"
        "const occ = " + json.dumps(_SCHEDULE_OCCURRENCE) + ";"
        "process.stdout.write(JSON.stringify({"
        "target: scheduleTargetSummary(row),"
        "fleet: scheduleTargetSummary({target: {filters: {}, device_ids: [],"
        " bind: 'late'}}),"
        "next: scheduleNextFireText(row),"
        "paused: scheduleNextFireText({state: 'paused', next_fire: null}),"
        "delta: scheduleDeltaText(occ),"
        "nodelta: scheduleDeltaText(null),"
        "wave: scheduleWaveText(occ),"
        "nowave: scheduleWaveText({id: 'x'})}));")
    assert out["target"] == \
        "role=core, status=deployed · resolved at each run"
    assert out["fleet"] == "whole fleet · resolved at each run"
    assert out["next"] == "2026-09-13T02:30 Europe/Stockholm (future)"
    assert out["paused"] == "paused"
    assert out["delta"] == "+3 / −1 since preview"
    assert out["nodelta"] == ""
    # Missing is reported apart from errored, and the gate says whether the
    # wave is still waiting on them.
    assert out["wave"] == ("wave held · 7 staged / 1 errored / "
                           "2 missing of 10")
    assert out["nowave"] == ""


def test_orphaned_schedule_names_the_missing_actor_and_can_be_reaffirmed():
    out = _run_schedule_projections(
        "const row = " + json.dumps(_SCHEDULE_ROW) + ";"
        "process.stdout.write(JSON.stringify({"
        "present: scheduleCreatorText(row),"
        "gone: scheduleCreatorText(Object.assign({}, row,"
        " {created_by: 'console:departed', creator_exists: false}))}));")
    assert out["present"] == "console:alice"
    assert out["gone"] == "console:departed (actor no longer exists)"

    js = _react_shell("schedules-controller.mjs")
    assert "'/reaffirm'" in js
    # Re-affirming rewrites created_by and bumps rev, so it carries the
    # revision the operator was looking at.
    reaffirm = js.split("async reaffirm(", 1)[1]
    assert "'If-Match': row.etag" in reaffirm and "this.services.headers(" in reaffirm
    assert "method: 'POST'" in reaffirm
    assert "sched-reaffirm" in _react_shell("schedules.jsx") and "controller.reaffirm(row.id)" in _react_shell("schedules.jsx")


def test_schedule_bulk_action_targets_the_current_device_filter():
    html = _react_shell("schedules.jsx")
    assert "bulkButton('schedule-selected'" in _react_shell('inventory.jsx')
    for element in ('id="sched-modal"', "select('scope', 'scope'",
                    "select('kind', 'kind'", "select('when', 'when'",
                    'id="sched-modal-preview"', 'id="create-schedule"'):
        assert element in html, element

    js = _webroot("app.js")
    block = js.split("var BULK_BTNS = [")[1].split("]")[0]
    assert "'create-schedule'" in block
    assert "'schedule-selected'" in js.split("var BULK_OPENERS = [")[1] \
        .split("]")[0]

    out = _run_schedule_projections(
        "const f = {q: 'edge', role: 'core', status: 'deployed',"
        " managementType: '', platform: '', cred: '', telemetry: '',"
        " peer: '', modelFamily: '', osFamily: ''};"
        "process.stdout.write(JSON.stringify({"
        "filter: scheduleTargetFromFilters(f, ['edge-1'], 'filter'),"
        "selection: scheduleTargetFromFilters(f, ['edge-1', 'edge-2'],"
        " 'selection')}));")
    # The filter itself is the target: it is re-resolved at each run, which
    # is the whole reason to schedule against it rather than a row list.
    assert out["filter"] == {
        "filters": {"q": "edge", "role": "core", "status": "deployed"},
        "device_ids": [], "bind": "late"}
    assert out["selection"] == {
        "filters": {}, "device_ids": ["edge-1", "edge-2"], "bind": "late"}


def test_schedule_creation_posts_one_normalized_definition():
    out = _run_schedule_projections(
        "const target = {filters: {role: 'core'}, device_ids: [],"
        " bind: 'late'};"
        "process.stdout.write(JSON.stringify({"
        "once: scheduleDefinitionFromForm({id: 'win-1', kind: 'assign',"
        " target: target, imageIds: ['image-a'], mode: 'merge',"
        " recurring: false, at: 1789000200, tz: 'UTC', windowSeconds: 3600}),"
        "weekly: scheduleDefinitionFromForm({id: 'win-2', kind: 'onboard',"
        " target: target, maxDevices: 20, telemetry: true,"
        " telemetryStream: false, recurring: true, weekday: 6, hour: 2,"
        " minute: 30, tz: 'Europe/Stockholm', windowSeconds: 3600})}));")
    assert out["once"] == {
        "id": "win-1", "kind": "assign",
        "target": {"filters": {"role": "core"}, "device_ids": [],
                   "bind": "late"},
        "payload": {"image_ids": ["image-a"], "mode": "merge"},
        "when": {"kind": "once", "at": 1789000200, "tz": "UTC",
                 "window_seconds": 3600}}
    assert out["weekly"] == {
        "id": "win-2", "kind": "onboard",
        "target": {"filters": {"role": "core"}, "device_ids": [],
                   "bind": "late"},
        "payload": {"telemetry": True, "telemetry_stream": False,
                    "mode": "new-only", "max_devices": 20},
        "when": {"kind": "recurring", "weekday": 6, "hour": 2, "minute": 30,
                 "tz": "Europe/Stockholm", "window_seconds": 3600}}


def test_device_row_shows_a_pending_schedule_before_a_manual_conflict():
    out = _run_schedule_projections(
        "const rows = [" + json.dumps(_SCHEDULE_ROW) + ","
        " Object.assign({}, " + json.dumps(_SCHEDULE_ROW) +
        ", {id: 'paused-one', state: 'paused'})];"
        "process.stdout.write(JSON.stringify({"
        "hit: pendingScheduleText('edge-1', rows),"
        "miss: pendingScheduleText('edge-9', rows),"
        "none: pendingScheduleText('edge-1', [])}));")
    # A paused schedule is not pending work, and must not read as a conflict.
    assert out["hit"] == "Scheduled: s-core"
    assert out["miss"] == "" and out["none"] == ""

    js = _webroot("app.js")
    assert "schedules.scheduled(id)" in js
    assert "pendingScheduleText(id, this.state.rows)" in _react_shell("schedules-controller.mjs")
    assert "sched-chip" in _react_shell('inventory.jsx')


def test_schedule_view_carries_its_own_next_fire_slot(tmp_path):
    """The console must not recompute DST-aware weekly arithmetic itself."""
    import schedules
    row = {"id": "s-core", "generation": "0" * 32, "rev": 1,
           "created_by": "console:alice", "created_at": 1788883200,
           "preview": {"revision": 1, "now": 1788883200, "device_ids": []},
           "kind": "assign",
           "target": {"filters": {}, "device_ids": [], "bind": "late"},
           "payload": {"image_ids": ["image-a"], "mode": "merge"},
           "when": {"kind": "recurring", "weekday": 6, "hour": 2,
                    "minute": 30, "tz": "Europe/Stockholm",
                    "window_seconds": 3600},
           "state": "pending"}
    slot = schedules.occurrence_slot(row, 1788883200)
    assert slot["tz"] == "Europe/Stockholm" and slot["local_time"]
    source = inspect.getsource(gui_server.make_server)
    assert 'view["next_fire"] = schedules.occurrence_slot(' in source


def test_schedule_next_run_never_renders_an_unreadable_row_as_undefined():
    out = _run_schedule_projections(
        "process.stdout.write(JSON.stringify({"
        "empty: scheduleNextFireText({}),"
        "missing: scheduleNextFireText(null),"
        "done: scheduleNextFireText({state: 'completed', next_fire: null})}));")
    assert out["empty"] == "no further run"
    assert out["missing"] == "no further run"
    assert out["done"] == "completed"


def test_agent_install_dropdown_offers_only_what_the_row_can_take():
    component, controller, js = _react_shell('inventory.jsx'), _react_shell('inventory-controller.mjs'), _webroot('app.js')
    assert "['', 'guestshell', 'iox', 'router', 'xr-appmgr'].map" in component
    assert 'Array.isArray(device.install_options)' in component and '!device.install_options.includes(value)' in component
    assert 'value !== platform' in component and 'disabled={!!refused}' in component
    assert 'services.installRefusal?.(device, value)' in component
    refusal = js.split('function installRefusal(d, platform) {', 1)[1].split('\n  }', 1)[0]
    assert 'router-routed' in refusal and 'router-nat' in refusal and 'xr-host' in refusal
    assert 'update refused' in controller and 'body?.error' in controller and 'await this.refresh()' in controller
    assert 'row["install_options"] = gui_fleet.install_options_for_record(d)' in inspect.getsource(gui_server.make_server)
