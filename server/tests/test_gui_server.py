# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import os
import re

import gui_server


def test_webroot_assets_exist():
    for name in ("login.html", "index.html", "styles.css", "login.js", "app.js",
                 "setup.html", "setup.js"):
        assert os.path.isfile(os.path.join(gui_server.WEBROOT, name)), name


def test_no_orphaned_control_ids():
    """Owner constraint for the toolbar rework: every element id referenced
    from app.js must exist in index.html. A relocated-but-unwired control
    would silently do nothing; a deleted element with a live binding would
    throw at load and kill every later binding."""
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    ids = set(re.findall(r"getElementById\('([^']+)'\)", js))
    ids |= set(re.findall(r"querySelector(?:All)?\('#([A-Za-z0-9_-]+)", js))
    assert len(ids) > 30, "id extraction matched too little — patterns drifted"
    missing = sorted(i for i in ids if ('id="%s"' % i) not in html)
    assert not missing, \
        "app.js references ids missing from index.html: %s" % missing


def test_csv_download_buttons_and_multiselect_onboard_wired():
    """Source guards for two console fixes:
    (1) Export/Example CSV must be plain <button>s, not <a download> anchors —
        Chrome blocks download-attribute navigations over connections with
        certificate errors (self-signed labs), which made the old anchors dead.
    (2) The devices table supports selecting multiple rows and bulk-onboarding
        them via a shared 'Onboard selected' button."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert '<button class="menu-item menu-close" id="export-csv">' in html
    assert '<button class="menu-item menu-close" id="example-csv">' in html
    assert 'id="export-csv" href' not in html
    assert 'id="example-csv" href' not in html
    assert 'download' not in html.split('id="example-csv"')[1].split('>')[0]
    assert 'id="onboard-selected"' in html
    assert 'id="mark-all"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "function downloadCsv(" in js
    assert "'export-csv'" in js and "'example-csv'" in js
    assert "#dev-rows .cred" in js
    assert "/credential'" in js or '/credential"' in js
    assert "onboard-selected" in js
    assert "#dev-rows .mark" in js


def test_devices_toolbar_regrouped():
    """Option-A layout (2026-08-12 spec §1-§4): quiet permanent toolbar; bulk
    actions live in a selection bar that is hidden in static HTML; the three
    CSV controls live inside the CSV menu; the telemetry checkboxes live
    inside the onboard popover; Delete carries destructive styling; the
    per-row action-links column is gone."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert '<div class="selbar" id="sel-bar" hidden>' in html
    csv_menu = html.split('id="csv-menu"')[1].split('</div>')[0]
    for cid in ('id="import-csv"', 'id="export-csv"', 'id="example-csv"'):
        assert cid in csv_menu, cid + " must live inside the CSV menu"
    pop = html.split('id="onboard-pop"')[1].split('</div>')[0]
    for cid in ('id="onboard-telemetry"', 'id="onboard-telemetry-stream"',
                'id="onboard-selected"'):
        assert cid in pop, cid + " must live inside the onboard popover"
    assert 'class="btn danger push" id="delete-selected"' in html
    devices_thead = html.split('id="devices"')[1].split('</thead>')[0]
    # '<th' alone also matches the '<thead>' tag itself; use '<th>' to count
    # only real header cells.
    assert devices_thead.count('<th>') == 11, "peer-policy column added without row action links"

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "function wireMenu(" in js and "function updateSelBar(" in js
    assert "#dev-rows .onboard" not in js and "#dev-rows .adopt" not in js \
        and "#dev-rows .del'" not in js, "per-row action links must be gone"
    assert "function startOnboard(" not in js, "dead single-row path removed"
    assert "onclick=" not in js and "onclick=" not in html


def test_peer_policy_console_controls_are_typed_and_safe():
    """Device inventory gets one CSRF-protected quarantine/release action; it
    exposes intent separately from count-only tracker enforcement, never a
    generic ACL/seeder editor or IP-derived legacy identity."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert '<th>Peer policy</th>' in html
    assert 'id="legacy-peer-warning" hidden' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    # refreshDevices owns the policy snapshot, so an older peer-policy request
    # cannot overwrite the generation that rendered the device table.
    assert "function refreshPeerPolicy()" not in js
    assert "fetch('/api/peer-policy', { signal: signal })" in js
    assert "'/api/peer-policy/quarantine/' + encodeURIComponent(id)" in js
    assert "method: 'PUT', headers: csrfHdr" in js
    assert "if_revision: peerPolicy.revision" in js
    assert "r.status === 409" in js and "operation_backlog_full" in js
    assert "may not terminate existing device-to-device sessions immediately" in js
    assert "never installs or reloads a device" in js
    assert "Quarantined intent" in js and "desired_ip_count" in js and "conflict_types" in js
    assert "participant_class === 'legacy_unattributed'" in js
    assert "p.tracker" in js and "device_ip" not in js.split("function refreshSwarm()")[1].split("// ---- Settings ----")[0]
    assert "otlp_export.signals" in js and "dropped_total" in js
    policy_area = js.split("function setQuarantine(")[1].split("async function refreshDevices")[0]
    assert "method: 'DELETE'" not in policy_area and "acl" not in policy_area.lower()


def test_import_from_disk_panel_wired():
    """Source guards for importing images already on disk: an Images-view panel
    fed by GET /api/images/importable, a per-row import posting the candidate's
    exact path with the CSRF header, and reuse of the existing publish poll."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert 'id="import-panel"' in html
    assert 'id="import-rows"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "'/api/images/importable'" in js or '"/api/images/importable"' in js
    assert "/api/images/import'" in js or '/api/images/import"' in js
    assert "#import-rows .do-import" in js
    # the exact discovered path is echoed back — the server authorizes on
    # candidate identity, so the client must not reconstruct or edit it
    assert "data-path" in js
    # the import POST carries the CSRF header, like every other mutating call
    post_call = js.split("/api/images/import'")[1][:400]
    assert "csrfHdr(" in post_call
    # publish progress reuses the upload path's poller rather than a second one
    assert "pollJob((await res.json()).job_id)" in js
    # the panel stays hidden only when there is nothing to show at all
    assert "cands.length === 0 && skipped.length === 0" in js
    # the distinguishing path is rendered — two roots can hold one basename
    assert "esc(c.path)" in js
    # deleting a catalogued image makes its name importable again
    assert "refreshImages(); refreshImportable();" in js


def test_bulk_row_actions_wired():
    """Adopt/delete selected and a bulk credential assign, with a confirmation
    on the destructive delete. Per-row action links were removed by the
    toolbar rework (2026-08-12 spec) — a single row is deleted by checking
    its row and using the selection bar's Delete, the same path as a bulk
    delete, so there is exactly one confirm(delWarning(...)) call site."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    for el in ('id="adopt-selected"', 'id="delete-selected"',
               'id="cred-selected"', 'id="apply-cred-selected"'):
        assert el in html, el

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "'adopt-selected'" in js and "'delete-selected'" in js
    assert "'apply-cred-selected'" in js
    assert "/adopt'" in js and "acknowledge_adopt: true" in js
    # bulk assign reuses the per-device credential route
    assert "'/credential'" in js or "+ '/credential'" in js
    # the single delete path confirms first
    assert "function delWarning(" in js
    assert js.count("confirm(delWarning(") == 1
    # the warning must say deletion is not an undeploy — the dangerous part
    assert "does NOT " in js and "undeploy" in js
    # creating or deleting a profile re-renders the device rows, so a device
    # imported before any profile existed becomes assignable immediately
    assert js.count("renderCreds(); refreshDevices();") == 2
    assert "function syncCredSelected(" in js


def test_all_selected_actions_share_one_busy_lock():
    """Every selected-action must hold the same lock. Onboard/undeploy used to
    guard only each other, so a delete could remove inventory out from under a
    starting onboard batch."""
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "var BULK_BTNS = [" in js
    block = js.split("var BULK_BTNS = [")[1].split("]")[0]
    actions = re.findall(r"'([a-z-]+)'", block)
    for el in ("onboard-selected", "undeploy-selected", "adopt-selected",
               "delete-selected", "apply-cred-selected", "assign-images-selected"):
        assert el in actions, "%s is not covered by the bulk busy lock" % el
    # Every action claims the lock rather than reading another button's state.
    # Counted against BULK_BTNS itself rather than a fixed number, so a new bulk
    # action cannot be added without also claiming the lock -- quarantine and
    # release are the two exceptions, guarded inside bulkQuarantine instead.
    claimers = [a for a in actions
                if a not in ("quarantine-selected", "release-selected")]
    assert js.count("claimSelection()") == len(claimers), (
        "%d actions but %d claim the lock"
        % (len(claimers), js.count("claimSelection()")))
    assert "onBtn.disabled" not in js and "unBtn.disabled" not in js
    # a declined confirmation must release the lock, not wedge the toolbar
    assert js.count("setBulkBusy(false); return;") >= 2


def test_batch_onboard_panel_wired():
    """Source guards for parallel onboarding: bulk-onboard opens a batch panel
    with per-device live status (polled from GET /api/onboard/jobs), a per-row
    log action reusing the SSE log panel, and a cancel-queued control."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert 'id="batch-panel"' in html
    assert 'id="batch-rows"' in html
    assert 'id="batch-summary"' in html
    assert 'id="batch-cancel"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "'/api/onboard/jobs'" in js or '"/api/onboard/jobs"' in js
    assert "/api/onboard/cancel-queued" in js
    assert "batch-rows" in js and "batch-cancel" in js
    # cancel is SCOPED to this panel's jobs — a bare cancel-all would nuke
    # other sessions' queued batches
    assert "job_ids: Object.keys(batchJobs)" in js
    # durations come from the server clock in the listing, not Date.now()
    assert "listing.now" in js
    # a reload re-attaches to still-running onboards instead of losing them
    assert "restoreBatch" in js


def test_undeploy_and_status_ui_wired():
    """Source guards for the console-feedback round: (1) an Undeploy-selected
    button that confirms before firing (destructive), (2) batch rows labeled
    with the job action, (3) queue position on queued rows, (4) a real
    deployed/staging indicator in the devices table."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert 'id="undeploy-selected"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "undeploy-selected" in js
    assert "startBatch('undeploy')" in js        # button fires the undeploy action
    assert "confirm(" in js                      # destructive: must confirm
    assert "j.action" in js                      # batch rows show the action
    assert "queuePos" in js                      # queued rows show #N in line
    assert "deployed" in js                      # devices tab staged indicator
    # job-aware statuses: post-onboard boot gap must not read as "not enrolled"
    assert "waiting for heartbeat" in js
    assert "onboarding…" in js and "undeploying…" in js
    assert "Waiting for heartbeat" in js         # overview card


def test_monitoring_timeline_wired():
    """Source guards for the Monitoring time-travel timeline:
    (1) index.html has the timeline container + range-preset chips.
    (2) app.js talks to /api/audit/histogram, builds bars from it, and the
        audit code has no inline on*= handlers (nonce-only CSP in console
        mode forbids them -- everything must go through addEventListener)."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert 'id="audit-timeline"' in html
    assert 'id="audit-range-chips"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "/api/audit/histogram" in js
    assert "addEventListener" in js
    # No inline event handler attributes anywhere in the audit/timeline code
    import re
    assert not re.search(r'\bon[a-z]+\s*=\s*["\']', js)


def test_monitoring_brush_wired():
    """Source guards for the draggable time brush (#19):
    (1) index.html carries the two-layer SVG (bars layer re-rendered per fetch,
        persistent brush overlay layer) plus the clear affordance.
    (2) app.js drives the brush with Pointer Events registered via
        addEventListener (nonce CSP forbids inline on*=), refetches the
        histogram with since_ts/until_ts on selection change, auto-rezooms
        via pickBucketCount, and clears the selection on Escape."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert 'id="audit-bars"' in html
    assert 'id="audit-brush"' in html
    assert 'id="audit-clear-selection"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    for ev in ("'pointerdown'", "'pointermove'", "'pointerup'",
               "'pointercancel'", "'lostpointercapture'"):
        assert "addEventListener(" + ev in js, ev
    assert "setPointerCapture" in js and "releasePointerCapture" in js
    # selection refetch uses the explicit-window contract + auto-rezoom
    assert "since_ts=" in js and "until_ts=" in js
    assert "function pickBucketCount(" in js
    assert "bucket_seconds" in js
    # selection lifecycle: commit/clear plumbing + Escape
    assert "function commitSelection(" in js and "function clearSelection(" in js
    assert "'Escape'" in js
    # bars render into their own layer so the brush overlay survives refetches
    assert "barsG.innerHTML" in js
    import re
    assert not re.search(r'\bon[a-z]+\s*=\s*["\']', js)


def test_audit_message_composer_wired():
    """Source guards for the operator-readable audit table (#19): 4-column
    layout (Time | Actor | Message | Result), a verb map covering console
    events plus the legacy broker shapes (mint/refresh/auth_fail carry
    device_id instead of actor/target/detail), colored category tags and
    result badges — everything composed through esc()."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert "<th>Time</th><th>Actor</th><th>Message</th><th>Result</th>" in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "function auditVerb(" in js
    # verb coverage: console + legacy broker events
    for ev in ("login_fail", "password_change_fail", "stage_host_clear",
               "device_csv_import", "device_credential_change",
               "onboard_finished", "credential_profile_delete",
               "image_publish_finished", "request_report",
               "mint", "refresh_fail", "auth_fail", "revoke"):
        assert ev in js, ev
    # legacy fallbacks: device_id fills actor/target; token rotation detail
    assert "'device:' + e.device_id" in js
    assert "e.secret_name" in js and "e.old_id" in js and "e.new_id" in js
    # badges + category tags come from esc()'d helpers, relative time on hover
    assert "badge-ok" in js and "badge-fail" in js
    assert "cat-tag" in js
    assert "function fmtAgo(" in js
    # empty non-append result shows the empty state AND resets the pager cursor
    assert "No events in this range." in js

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
    """Source guard: the add-device form must expose a model input (used for
    platform auto-detection; see gui_onboard.resolve_platform) and post it."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert 'id="df-model"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "df-model" in js
    assert "model:" in js


def test_settings_tls_trust_and_destination_sections_wired():
    """Source guards for the 2026-08-19 TLS/trust/telemetry-destination spec:
    the Settings view gains three sections — Certificate (replace/revert the
    console cert), Trusted CAs (install/remove CA PEMs + public-bundle
    download with job polling), Telemetry destination (editable OTLP
    override). Conventions pinned: jpost + csrfHdr on every mutation, one
    solid .btn per form (the ca-form has none — Add CA is that section's
    primary), danger links confirm with consequence-naming text, no inline
    handlers/styles, key material never echoed or left in the DOM."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    # section headings, in the Settings view
    settings = html.split('id="view-settings"')[1].split("</section>")[0]
    assert "<h3>Certificate</h3>" in settings
    assert "<h3>Trusted CAs</h3>" in settings
    assert "<h3>Telemetry destination</h3>" in settings
    # element inventory (the global orphan guard checks the JS side)
    for el in ('id="cert-status"', 'id="cert-form"', 'id="cert-pem"',
               'id="cert-key"', 'id="cert-msg"', 'id="cert-revert"',
               'id="trust-tbl"', 'id="trust-rows"', 'id="trust-form"',
               'id="trust-pem"', 'id="trust-msg"', 'id="ca-form"',
               'id="ca-url"', 'id="ca-auto"', 'id="ca-msg"',
               'id="ca-refresh"', 'id="td-status"', 'id="td-form"',
               'id="td-endpoint"', 'id="td-enabled"', 'id="td-msg"',
               'id="td-revert"'):
        assert el in settings, el
    # revert affordances start hidden — no flash before the first render
    assert 'id="cert-revert" hidden' in settings
    assert 'id="td-revert" hidden' in settings
    # one solid button per form; auxiliaries are ghost or linkish.
    # ('class="btn"' does NOT substring-match 'class="btn ghost"'.)
    cert_form = settings.split('id="cert-form"')[1].split('</form>')[0]
    assert cert_form.count('class="btn"') == 1            # Replace certificate
    assert 'class="linkish danger-link"' in cert_form     # Use built-in cert
    trust_form = settings.split('id="trust-form"')[1].split('</form>')[0]
    assert trust_form.count('class="btn"') == 1           # Add CA
    ca_form = settings.split('id="ca-form"')[1].split('</form>')[0]
    assert ca_form.count('class="btn"') == 0              # no second primary
    assert ca_form.count('class="btn ghost"') == 2        # Save + Download now
    td_form = settings.split('id="td-form"')[1].split('</form>')[0]
    assert td_form.count('class="btn"') == 1              # Save
    assert 'class="linkish danger-link"' in td_form       # Revert to default
    # trust table columns: subject/expiry/fingerprint/source/count
    assert ("<th>Subject</th><th>Expires</th><th>SHA-256</th>"
            "<th>Source</th><th>Certs</th>") in settings
    # the operator is told the key is write-only and that the bundle URL
    # gates both download paths
    assert "never shown again" in settings
    assert "https:// URL" in settings
    # CSP: still no inline styles or handlers anywhere in the page
    assert " style=" not in html and "onclick=" not in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    # endpoint literals — POST via jpost (csrfHdr inside), DELETE via fetch
    assert js.count("'/api/settings/gui-cert'") == 2          # POST + DELETE
    assert "'/api/settings/trust'" in js                      # POST add
    assert "'/api/settings/trust/' + encodeURIComponent(" in js   # DELETE row
    assert "'/api/settings/ca-trust'" in js                   # POST config
    assert "'/api/settings/ca-trust/refresh'" in js           # POST job start
    assert "'/api/settings/ca-trust/refresh/' + encodeURIComponent(" in js
    assert js.count("'/api/settings/telemetry-destination'") == 2
    # every DELETE carries the CSRF header (4 pre-existing + 3 new)
    assert js.count("{ method: 'DELETE', headers: csrfHdr() }") >= 7
    # per-row remove is a danger link rendered into the trust table
    assert "#trust-rows .trust-del" in js
    assert "danger-link trust-del" in js
    # destructive paths confirm with consequence-naming messages
    assert "serves the bootstrap certificate again" in js     # cert revert
    assert "stops trusting certificates issued" in js         # trust remove
    assert "goes back to the environment configuration" in js # dest revert
    # download-now polls the job like the image publish poller
    assert "function pollCaRefresh(" in js
    assert "j.state === 'failed'" in js
    # settings render consumes the new GET blocks; the old read-only
    # Observability row is gone (superseded by the editable block)
    assert "s.gui_cert" in js and "s.trust" in js and "s.ca_trust" in js
    assert "s.telemetry_destination" in js
    assert "effective_endpoint" in js and "fingerprint_sha256" in js
    assert "['Observability'" not in js
    # key hygiene: submit posts the PEMs, success wipes the textareas
    assert "cert_pem" in js and "key_pem" in js
    assert "getElementById('cert-form').reset()" in js
    # all 8 new audit events have human verbs (keys quoted — hyphens)
    verbs = js.split("var AUDIT_VERBS = {")[1].split("};")[0]
    for ev in ("gui-cert-replace", "gui-cert-revert", "trust-add",
               "trust-remove", "ca-trust-config", "ca-trust-refresh",
               "telemetry-destination-set", "telemetry-destination-clear"):
        assert "'%s'" % ev in verbs, ev
    # no inline on*= crept into the new JS-built markup
    assert not re.search(r'\bon[a-z]+\s*=\s*["\']', js)

    with open(os.path.join(gui_server.WEBROOT, "styles.css")) as f:
        css = f.read()
    assert ".inline-form textarea" in css


def test_settings_uses_sidebar_feature_submenus():
    """Source guard for the Settings navigation: the three feature sub-pages
    (General / TLS & trust / Telemetry) are reached from an indented sidebar
    sub-menu under Settings — deep-linkable as #settings/<sub> — not from an
    in-page tab strip. Panes stay siblings inside #view-settings, toggled
    with the `hidden` attribute; the sub-menu lives in the sidebar and is
    revealed only while a settings sub-page is active."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    side = html.split('<nav class="side">')[1].split("</nav>")[0]
    # the sub-menu container starts hidden (revealed by the router) and holds
    # one deep-linkable entry per feature sub-page
    assert 'id="settings-submenu" hidden' in side
    for sub in ("general", "tls", "telemetry"):
        assert ('id="nav-settings-%s"' % sub) in side, sub
        assert ('href="#settings/%s"' % sub) in side, sub
    settings = html.split('id="view-settings"')[1].split("</section>")[0]
    # the old in-page tab strip is gone everywhere
    assert "settings-tab" not in html
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
    assert "'nav-settings-' + t" in js
    assert re.search(
        r"SETTINGS_SUBS\s*=\s*\[\s*'general'\s*,\s*'tls'\s*,\s*'telemetry'\s*\]", js)
    # the router owns sub-page selection: #settings/<sub> deep-links resolve
    assert "showSettingsSub(" in js
    assert "settings-submenu" in js


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


def test_login_sets_cookie_and_returns_csrf(tmp_path):
    host, port, _, stop = _serve(tmp_path)
    try:
        status, headers, body = _req(host, port, "POST", "/api/login",
                                     {"username": "admin", "password": "pw"})
        assert status == 200
        assert "iris_sid=" in headers.get("Set-Cookie", "")
        assert "HttpOnly" in headers["Set-Cookie"]
        assert "SameSite=Strict" in headers["Set-Cookie"]
        assert "Secure" in headers["Set-Cookie"]
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
        status, _, _ = _req(host, port, "GET", "/api/session")
        assert status == 401
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
import peer_enforcement


def _serve_full(tmp_path):
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
    srv = gui_server.make_server("127.0.0.1", 0, app, images, fleet, creds, cat,
                                 certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, (app, fleet, creds, cat), srv.shutdown


def _auth(host, port):
    s, h, b = _req(host, port, "POST", "/api/login",
                   {"username": "admin", "password": "pw"})
    return h["Set-Cookie"].split(";")[0], json.loads(b)["csrf"]


def _policy_device(fleet, device_id="d1"):
    return fleet.upsert({"device_id": device_id, "device_ip": "10.0.0.1",
                         "vlan": "666", "svi_ip": "10.0.0.2",
                         "svi_mask": "255.255.255.0", "guest_ip": "10.0.0.3",
                         "model": "C9300", "platform": "c9300"})


def test_peer_policy_get_and_durable_quarantine_operation(tmp_path):
    host, port, (_, fleet, _, cat), stop = _serve_full(tmp_path)
    try:
        _policy_device(fleet)
        assert _req(host, port, "GET", "/api/peer-policy")[0] == 401
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, _, raw = _req(host, port, "GET", "/api/peer-policy",
                              headers={"Cookie": cookie})
        assert status == 200
        view = json.loads(raw)
        assert view["revision"] == 1
        assert view["quarantine_assignments"] == []
        assert "rules" not in view["quarantine"]
        assert "aria_session_id" not in view["enforcement"]
        status, _, raw = _req(host, port, "PUT", "/api/peer-policy/quarantine/d1",
                              {"quarantined": True, "if_revision": 1}, headers)
        assert status == 200
        assert json.loads(raw) == {"ok": True, "revision": 2, "quarantined": True}
        with open(os.path.join(cat.state_dir, "peer-policy.json")) as f:
            doc = json.load(f)
        assert doc["assignments"] == {"d1": "quarantine"}
        event = doc["operation_outbox"][-1]
        assert set(event) == {"event_id", "revision", "action", "target", "actor", "created_at"}
        assert event["action"] == "assign" and event["target"] == "d1"
        assert event["actor"] == "console:admin"
        tracker_status = peer_enforcement.build_status(
            "pending", None, None, 1, 3, 10,
            last_operation_exported_revision=2,
            conflicts=[{"reason": "shared_permit_deny", "ipv4": "10.0.0.99"}],
            last_effect={"disconnected_peers": 1})
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
        status, _, _ = _req(host, port, "PUT", "/api/peer-policy/quarantine/d1",
                            {"quarantined": False, "if_revision": 2}, headers)
        assert status == 200
        with open(os.path.join(cat.state_dir, "peer-policy.json")) as f:
            assert [e["revision"] for e in json.load(f)["operation_outbox"]] == [3]
        status, _, raw = _req(host, port, "PUT", "/api/peer-policy/quarantine/d1",
                              {"quarantined": False, "if_revision": 2}, headers)
        assert status == 409
        assert json.loads(raw)["revision"] == 3
    finally:
        stop()


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
                        {"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
                         "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                         "guest_ip": "10.0.0.3"}, headers=hh)
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


def test_device_delete_purges_catalog_state(tmp_path):
    # Deleting a device must clear its catalog-side state too — a device
    # that is deleted and added back comes back UNASSIGNED, never with a
    # resurrected stale assignment that would silently restage an image.
    host, port, (_, _, _, cat), stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        dev = {"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
               "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
               "guest_ip": "10.0.0.3"}
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
                        {"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
                         "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                         "guest_ip": "10.0.0.3"}, headers=hh)
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
             "vpg_number,nat_interface,platform")
        assert "d9,10.9.9.1" in b.decode()
    finally:
        stop()


def test_credentials_crud_never_leaks_password(tmp_path):
    host, port, _, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/credentials",
                        {"id": "lab", "name": "Lab", "device_user": "admin",
                         "device_pass": "topsecret"}, headers=hh)
        assert st == 200
        st, _, b = _req(host, port, "GET", "/api/credentials", headers={"Cookie": ck})
        body = b.decode()
        assert "lab" in body and "admin" in body
        assert "topsecret" not in body     # password NEVER returned
        st, _, _ = _req(host, port, "DELETE", "/api/credentials/lab", headers=hh)
        assert st == 200
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
        assert json.loads(b) == {"error": "image_ids must be a list of image ids"}
        # a bare string: previously iterated into one-character "ids"
        st, _, b = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": "img-a"}, headers=hh)
        assert st == 400
        assert json.loads(b) == {"error": "image_ids must be a list of image ids"}
        # a falsy element: previously silently dropped instead of rejected
        st, _, b = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": ["img-a", ""]}, headers=hh)
        assert st == 400
        assert json.loads(b) == {"error": "image_ids must be a list of image ids"}
        # a non-string element
        st, _, b = _req(host, port, "POST", "/api/devices/d1/assign",
                        {"image_ids": ["img-a", 123]}, headers=hh)
        assert st == 400
        assert json.loads(b) == {"error": "image_ids must be a list of image ids"}
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
        assert events and events[-1]["detail"] == "unassigned (was img1.bin)"
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
        cat.record_heartbeat("d1", {"stage_state": "verified", "stage_error": "copy denied", "model": "C9300"}, now=123)
        st, _, b = _req(host, port, "GET", "/api/devices", headers={"Cookie": ck})
        row = [d for d in json.loads(b)["devices"] if d["device_id"] == "d1"][0]
        assert row["assigned_image_id"] == "img1"
        assert row["stage_state"] == "verified"
        assert row["stage_error"] == "copy denied"
        assert row["last_seen"] == 123
        assert row["heartbeat_model"] == "C9300"
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
    """policy.json is parsed exactly once per /api/devices or /api/overview
    request, regardless of fleet size — the console polls both endpoints, so
    a per-device get_policy() re-read would grow linearly with the fleet."""
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
        orig_read = cat._read

        def counting_read(path):
            if path == cat.policy_path:
                reads["policy"] += 1
            return orig_read(path)

        cat._read = counting_read
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
                  "credential_profile_id": "lab"})
    fleet.upsert({"device_id": "d2", "device_ip": "10.0.0.2", "model": "C9300",
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


def test_onboard_start_status_and_stream(tmp_path):
    def run_fn(p, e, on):
        on("[1/6] hello"); on("[6/6] done"); return 0
    host, port, stop = _serve_onboard(tmp_path, run_fn)
    try:
        ck, csrf = _auth(host, port)
        # start requires CSRF
        assert _req(host, port, "POST", "/api/devices/d1/onboard",
                    {}, headers={"Cookie": ck})[0] == 403
        st, _, b = _req(host, port, "POST", "/api/devices/d1/onboard", {},
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
        assert "[6/6] done" in job["lines"]
        # SSE stream returns text/event-stream and the data lines + an end event
        s, hd, sb = _req(host, port, "GET",
                         "/api/onboard/jobs/" + job_id + "/stream",
                         headers={"Cookie": ck})
        assert s == 200 and "text/event-stream" in hd.get("Content-Type", "")
        body = sb.decode()
        assert "data: [1/6] hello" in body and "event: end" in body
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


def test_devices_view_carries_onboard_state_and_overview_awaits_heartbeat(tmp_path):
    """After a successful onboard, the device has no heartbeat yet (the agent
    needs a couple of minutes to bootstrap) — the devices view must carry the
    job outcome so the UI shows 'waiting for heartbeat' instead of the
    misleading 'not enrolled', and the overview counts such devices."""
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
        time.sleep(2.5)                       # 2.5x the idle cap, still queued
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
    fleet.upsert({"device_id": "xr1", "device_ip": "10.0.0.9", "model": "ASR-9906",
                  "os_family": "xr", "credential_profile_id": "lab"})
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


def _serve_inband(tmp_path, run_fn, device=None):
    import deployment_receipts
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
    receipts = deployment_receipts.ReceiptStore(state)
    art = str(tmp_path / "artifacts"); os.makedirs(art, exist_ok=True)
    for pkg in ("iris-arm64.tar", "iris-amd64.tar"):
        open(os.path.join(art, pkg), "w").close()   # IOx package-presence gate
    onboard = gui_onboard.OnboardService(fleet, creds, host_ip="10.9.9.9",
                                         mint_fn=lambda d: "TOK", run_fn=run_fn,
                                         receipts=receipts, artifacts_dir=art,
                                         # this device is platform=guestshell, so
                                         # the job-start reachability gate (see
                                         # gui_onboard.py) probes it before run_fn
                                         probe_fn=lambda dev, env: "C9300",
                                         guestshell_preflight_fn=_CLEAN_GUESTSHELL_PREFLIGHT,
                                         iox_preflight_fn=lambda dev, env, resolved: {
                                             "status": "passed",
                                             "device_identity": "FCW0000TEST",
                                             "detected_model": "IE-3400"})
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, certfile=None, receipts=receipts)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, srv.shutdown


def test_inband_iox_onboard_defaults_ssh_host_to_mgmt_ip(tmp_path):
    """Inband IOx resolves the iox platform and, with no explicit ios_ssh_host,
    the app SSHes to the switch's management IP (device_ip)."""
    ran = []
    host, port, stop = _serve_inband(
        tmp_path, lambda p, e, on: (ran.append(dict(e)), 0)[1],
        device={"device_id": "ie", "device_ip": "192.0.2.30",
                "management_type": "inband", "inband_vlan": "120",
                "app_ip": "192.0.2.31", "app_mask": "255.255.255.0",
                "app_gateway": "192.0.2.1", "model": "IE-3400", "platform": "iox",
                "credential_profile_id": "lab"})
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, b = _req(host, port, "GET", "/api/devices/ie/plan",
                        headers={"Cookie": ck})
        assert st == 200
        resolved = json.loads(b)["plan"]["resolved"]
        assert resolved["attachment"] == "inband" and resolved["platform"] == "iox"
        assert resolved["ios_ssh_host"] == "192.0.2.30"    # defaults to device_ip
        st, _, b = _req(host, port, "POST", "/api/devices/ie/onboard", {}, headers=hh)
        assert st == 200
        import time as _t
        deadline = _t.time() + 3
        while _t.time() < deadline:
            if ran:
                break
            _t.sleep(0.02)
        assert ran and ran[-1]["NETWORK_ATTACHMENT"] == "inband"
        assert ran[-1]["IOS_SSH_HOST"] == "192.0.2.30"
    finally:
        stop()


def test_reonboard_then_undeploy_starts(tmp_path):
    """Re-onboarding a device (idempotent redeploy) and then undeploying it
    must work: the second onboard's receipt supersedes the first, so the
    undeploy start finds exactly one active receipt. This is the lab-observed
    failure: two active receipts made active_for_device() raise and the
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

        for _ in range(2):    # onboard TWICE — the re-onboard mints receipt #2
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
    """Inband onboards exactly like routed: a plain POST starts a job, records a
    receipt, and runs the installer with NETWORK_ATTACHMENT=inband."""
    ran = []
    host, port, stop = _serve_inband(
        tmp_path, lambda p, e, on: (ran.append(dict(e)), 0)[1])
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # plan preview reports the inband attachment
        st, _, b = _req(host, port, "GET", "/api/devices/edge/plan",
                        headers={"Cookie": ck})
        assert st == 200 and json.loads(b)["plan"]["resolved"]["attachment"] == "inband"
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
        assert ran and ran[-1]["NETWORK_ATTACHMENT"] == "inband"
    finally:
        stop()


def _serve_router(tmp_path, run_fn, preflight_fn=None, mint_fn=None, device=None,
                  audit_path=None):
    """Receipt-backed server with one C8000V router inventory row."""
    import deployment_receipts
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
    receipts = deployment_receipts.ReceiptStore(state)
    onboard = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=mint_fn or (lambda d: "TOK"),
        run_fn=run_fn, receipts=receipts, preflight_fn=preflight_fn)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, certfile=None, receipts=receipts,
                                 audit_path=audit_path)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, fleet, receipts, srv.shutdown


def _wait_onboard_job(host, port, cookie, job_id):
    deadline = time.time() + 3
    while time.time() < deadline:
        _, _, body = _req(host, port, "GET", "/api/onboard/jobs/" + job_id,
                          headers={"Cookie": cookie})
        job = json.loads(body)
        if job["state"] in ("done", "error", "cancelled"):
            return job
        time.sleep(0.02)
    raise AssertionError("onboard job did not finish: %s" % job_id)


def test_c8000v_router_plan_auto_resolves_blank_platform_and_fields(tmp_path):
    host, port, _fleet, receipts, stop = _serve_router(
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
            "attachment": "router-routed", "device_ip": "192.0.2.10",
            "iris_vlan": "", "svi_ip": "",
            "svi_mask": "", "app_ip": "10.7.0.2", "app_mask": "255.255.255.252",
            "app_gateway": "10.7.0.1", "inband_vlan": "", "vpg_number": "7",
            "nat_interface": "", "swarm_port": "6881", "ios_ssh_host": "",
            "model": "C8000V", "platform": "router", "renderer": "v1"}
        status, _, body = _req(host, port, "POST", "/api/devices/r1/onboard", {},
                               headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 200
        assert _wait_onboard_job(host, port, cookie, json.loads(body)["job_id"])["state"] == "done"
        assert [resource["kind"] for resource in receipts.active_for_device("r1")["resources"]] == [
            "virtualportgroup", "eem-applets", "agent-files",
            "logging-discriminator", "pki-trustpoint", "http-client-trustpoint",
            "iox-global", "file-prompt-quiet",
            "guestshell"]
    finally:
        stop()


def test_router_onboard_uses_router_recipe_env_and_router_resource_kinds(tmp_path):
    events, ran = [], []
    host, port, _fleet, receipts, stop = _serve_router(
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
        assert {key: env[key] for key in ("NETWORK_ATTACHMENT", "VPG_NUMBER",
                                           "NAT_INTERFACE", "BT_LISTEN_PORT")} == {
            "NETWORK_ATTACHMENT": "router-nat", "VPG_NUMBER": "10",
            "NAT_INTERFACE": "GigabitEthernet1", "BT_LISTEN_PORT": "6881"}
        receipt = receipts.active_for_device("r1")
        assert [resource["kind"] for resource in receipt["resources"]] == [
            "virtualportgroup", "eem-applets", "agent-files",
            "logging-discriminator", "pki-trustpoint", "http-client-trustpoint",
            "iox-global", "file-prompt-quiet",
            "guestshell",
            "nat-acl", "nat-overload", "nat-static", "nat-outside-marking"]
        assert receipt["resources"][-1]["ownership"] == "iris-created"
    finally:
        stop()


def test_router_preflight_failure_is_reported_by_the_queued_job(tmp_path):
    minted, ran = [], []

    def reject(*_args):
        raise ValueError("VirtualPortGroup10 already exists")

    host, port, _fleet, receipts, stop = _serve_router(
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
        assert receipts.list("r1")[0]["state"] == "removed"
    finally:
        stop()


def test_router_nat_preflight_ownership_persists_and_undeploy_uses_receipt(tmp_path):
    for preexisting, expected in ((True, "0"), (False, "1")):
        ran = []
        host, port, _fleet, receipts, stop = _serve_router(
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
            receipt = receipts.active_for_device("r1")
            assert receipt["resolved"]["nat_outside_owned"] == expected
            marking = [r for r in receipt["resources"] if r["kind"] == "nat-outside-marking"]
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


def test_platform_endpoint_allows_router_only_for_router_management_types(tmp_path):
    host, port, fleet, _receipts, stop = _serve_router(tmp_path, lambda p, e, on: 0)
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
    host, port, _fleet, receipts, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        cookie, csrf = _auth(host, port)
        status, _, body = _req(
            host, port, "POST", "/api/devices/r1/adopt",
            {"acknowledge_adopt": True},
            headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 409 and "cannot be adopted" in json.loads(body)["error"]
        assert receipts.list("r1") == []
    finally:
        stop()


def test_router_undeploy_uses_receipt_ip_after_inventory_edit(tmp_path):
    ran = []
    evidence = {"status": "passed", "device_identity": "9ABC123",
                "detected_model": "C8000V", "nat_interface": "GigabitEthernet1",
                "nat_outside_preexisting": False}
    host, port, fleet, _receipts, stop = _serve_router(
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


def test_router_undeploy_refuses_incomplete_or_mismatched_receipt(tmp_path):
    host, port, _fleet, receipts, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        cookie, csrf = _auth(host, port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        plan = {"platform": "router", "attachment": "router-routed",
                "device_ip": "192.0.2.10", "device_identity": "9ABC123",
                "vpg_number": "10", "model": "C8000V"}
        receipt = receipts.create({"controller_id": "iris", "device_id": "r1",
            "inventory_revision": 1, "plan_hash": "a" * 64,
            "resolved": plan, "preflight": {"status": "passed"},
            "resources": [{"kind": "virtualportgroup", "ownership": "iris-created",
                           "id": "99"}]})
        receipts.transition(receipt["receipt_id"], "applying")
        receipts.transition(receipt["receipt_id"], "active")
        status, _, body = _req(host, port, "POST", "/api/devices/r1/undeploy", {},
                               headers=headers)
        assert status == 409 and "does not prove ownership" in json.loads(body)["error"]
        assert receipts.get(receipt["receipt_id"])["state"] == "needs-reconcile"
    finally:
        stop()


def test_router_routes_fail_closed_without_receipt_store(tmp_path):
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
                                 onboard, certfile=None, receipts=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cookie, csrf = _auth("127.0.0.1", port)
        headers = {"Cookie": cookie, "X-CSRF-Token": csrf}
        for action in ("onboard", "undeploy"):
            status, _, body = _req(
                "127.0.0.1", port, "POST", "/api/devices/r1/" + action, {},
                headers=headers)
            assert status == 503 and "receipt" in json.loads(body)["error"]
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
                  "credential_profile_id": "lab"})
    fleet.upsert({"device_id": "d2", "device_ip": "10.0.0.2", "model": "C9300",
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
    """Sign in with the documented default first-run credential
    (iris/irisisgreat!) and return the one-time setup grant from the
    response. No session cookie is issued for this login."""
    st, hd, b = _req(host, port, "POST", "/api/login",
                     {"username": gui_server.DEFAULT_SETUP_USER,
                      "password": gui_server.DEFAULT_SETUP_PASS})
    assert st == 200
    body = json.loads(b)
    assert body["setup"] is True and body["setup_grant"]
    assert "Set-Cookie" not in hd            # no session for the default pair
    return body["setup_grant"]


def test_setup_serves_wizard_and_creates_admin(tmp_path):
    host, port, app, stop = _serve_fresh(tmp_path)
    try:
        # while no admin exists, GET / serves the LOGIN page (the default
        # iris credential there is what mints the setup grant); the setup
        # page itself stays reachable as a static page for the redirect.
        st, hd, b = _req(host, port, "GET", "/")
        assert st == 200 and b'id="login-form"' in b
        st, hd, b = _req(host, port, "GET", "/setup.html")
        assert st == 200 and b'id="setup-form"' in b
        # The operator signs in with the documented default credential; the
        # server hands back a one-time grant instead of a session.
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
    # once an admin exists, / serves the console shell (app.js), /login.html the login
    app = gui_app.GuiApp(str(tmp_path / "secrets.json")); app.set_admin("admin", "pw")
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        st, _, b = _req("127.0.0.1", port, "GET", "/login.html")
        assert st == 200 and b"Sign in" in b
        # GET / serves the console shell (app.js), NOT the setup wizard, once set up
        st, _, b = _req("127.0.0.1", port, "GET", "/")
        assert st == 200 and b"/app.js" in b and b"First-run setup" not in b
        # setup is refused now, even with a syntactically plausible grant
        st, _, _ = _req("127.0.0.1", port, "POST", "/api/setup",
                        {"username": "x", "password": "password",
                         "setup_grant": "unavailable-after-setup"},
                        headers=_setup_headers("127.0.0.1", port))
        assert st == 409
        # the default credential is not special once an admin exists: it is
        # an ordinary failed login (no special-case leak), not a setup grant
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


def test_wrong_default_credentials_are_ordinary_failed_login(tmp_path):
    """A near-miss on the default pair (right user/wrong password or vice
    versa) while needs_setup does NOT mint a grant -- it is an ordinary
    failed login, audited like any other (spec: default-cred-setup, Feature
    1: "Failed default-credential attempts while needs_setup are audited as
    category 'auth'")."""
    host, port, app, stop = _serve_fresh(tmp_path)
    try:
        for creds in (
            {"username": gui_server.DEFAULT_SETUP_USER, "password": "wrong"},
            {"username": "not-iris", "password": gui_server.DEFAULT_SETUP_PASS},
        ):
            st, _, b = _req(host, port, "POST", "/api/login", creds)
            assert st == 401
            assert "setup" not in json.loads(b)
        assert app.needs_setup() is True
    finally:
        stop()


def test_default_credential_full_happy_path(tmp_path):
    """End to end: default login -> grant -> /api/setup -> real session."""
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
    """The default-credential special case is gated purely on needs_setup(),
    never on the chosen username: an operator may legitimately name the real
    admin account "iris" (even reusing "irisisgreat!" as its password). Once
    that admin exists, iris/irisisgreat! is checked against the stored admin
    hash like any other login -- no reserved word, no special-casing."""
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

        # iris/irisisgreat! no longer means anything special post-setup, and
        # does not match this admin's real (different) password
        st, _, b = _req(host, port, "POST", "/api/login",
                        {"username": gui_server.DEFAULT_SETUP_USER,
                         "password": gui_server.DEFAULT_SETUP_PASS})
        assert st == 401
        assert "setup" not in json.loads(b)
    finally:
        stop()


def test_admin_named_iris_with_default_password(tmp_path):
    """Degenerate but legal case: the operator's chosen admin password IS
    "irisisgreat!". Post-setup, iris/irisisgreat! must succeed as an
    ordinary authenticated login (it matches the real stored credential),
    not be diverted into the setup flow -- needs_setup() is false, so the
    default-credential branch never triggers."""
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
    """Source guard (spec: default-cred-setup-and-tls-ux, Feature 1): the old
    bootstrap-token mechanism -- the runtime file, its basename, the startup
    banner -- is fully removed from every live file. CHANGELOG.md is exempt:
    it documents the change, including the removed path, as project history.
    This test's own file is exempt too: its name and this docstring
    necessarily spell out the strings it is checking are gone everywhere
    else. Scoped to git-tracked files so it never walks build output,
    caches, or unrelated local directories."""
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
                    {"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
                     "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                     "guest_ip": "10.0.0.3"}, headers=hh)[0] == 200
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
    return its three-card shape wired to the real session + credential
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
        assert set(("admin", "stage_host", "packages")) <= set(st)
        # the session's real username must flow through, not a placeholder
        assert st["admin"]["username"] == "admin"
        pkgs = st["packages"]
        assert set(("state", "items", "remedy")) <= set(pkgs)
        assert len(pkgs["items"]) == len(setup_status.IOX_PACKAGES)
        for item in pkgs["items"]:
            assert "name" in item and "state" in item
    finally:
        stop()


def test_setup_status_route_response_has_no_secret_material(tmp_path, monkeypatch):
    """The card exists to be trustworthy about system state; it must never
    leak stage-host credentials onto the wire, even after a real stage-host
    password has been set through the credential store it reads from."""
    monkeypatch.setenv("IRIS_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    host, port, _ctx, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        status, _, _ = _req(host, port, "POST", "/api/settings/stage-host",
                            {"username": "svc-iris", "password": "hostpw-s3cr3t"},
                            headers=hh)
        assert status == 200
        status, _, body = _req(host, port, "GET", "/api/settings/setup-status",
                               headers={"Cookie": ck})
        assert status == 200
        blob = body.decode().lower()
        for banned in ("password", "secret", "token", "private", "begin "):
            assert banned not in blob
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


def test_settings_stage_host_roundtrip(tmp_path):
    host, port, _deps, stop = _serve_full(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        # auth: no session -> 401; session without CSRF -> 403
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    {"username": "u", "password": "p"})[0] == 401
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    {"username": "u", "password": "p"},
                    headers={"Cookie": ck})[0] == 403
        # starts unconfigured; GET /api/settings shows the redacted view
        st, _, b = _req(host, port, "GET", "/api/settings", headers={"Cookie": ck})
        assert st == 200
        assert json.loads(b)["stage_host"] == {"configured": False, "username": ""}
        # validation: missing/null/non-string fields and non-object JSON -> 400
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    {"username": "", "password": "p"}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    {"username": "u", "password": ""}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    {"username": "u", "password": None}, headers=hh)[0] == 400
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    {"username": 42, "password": "p"}, headers=hh)[0] == 400
        hh_json = dict(hh); hh_json["Content-Type"] = "application/json"
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    raw=b"[]", headers=hh_json)[0] == 400
        # set, then the settings view reflects it — but NEVER the password
        assert _req(host, port, "POST", "/api/settings/stage-host",
                    {"username": "svc-iris", "password": "hostpw"},
                    headers=hh)[0] == 200
        st, _, b = _req(host, port, "GET", "/api/settings", headers={"Cookie": ck})
        assert json.loads(b)["stage_host"] == {"configured": True,
                                               "username": "svc-iris"}
        assert b"hostpw" not in b
        # clear
        st, _, b = _req(host, port, "DELETE", "/api/settings/stage-host", headers=hh)
        assert st == 200 and json.loads(b)["deleted"] is True
        st, _, b = _req(host, port, "GET", "/api/settings", headers={"Cookie": ck})
        assert json.loads(b)["stage_host"]["configured"] is False
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
        cfg = ('window.IRIS_MAP_CFG = {"swarmUrl":"/api/swarm","pull":true,'
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
    # Against the checked-in server/swarmmap.html (single-source file). Only
    # the nonce/CSP mechanics are asserted here — the CFG substitution is
    # covered by the fixture test above, so this stays green whether or not
    # the swarmmap.html client-side task has landed yet.
    host, port, _cat, stop = _serve_reports(tmp_path)
    try:
        ck, _csrf = _auth(host, port)
        st, hd, b = _req(host, port, "GET", "/swarmmap", headers={"Cookie": ck})
        assert st == 200 and "text/html" in hd.get("Content-Type", "")
        assert "script-src 'nonce-" in hd.get("Content-Security-Policy", "")
        assert b'<script nonce="' in b and b'<style nonce="' in b
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
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
                     "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                     "guest_ip": "10.0.0.3"})
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


def test_device_platform_happy_path_and_clear(tmp_path):
    host, port, deps, stop = _serve_full(tmp_path)
    _app, fleet, _creds, _cat = deps
    try:
        fleet.upsert({"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666"})
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
        # detail names the image (filename + size + retrievable id), not a bare id
        assert assign_events[0]["detail"] == "assigned img1.bin (3 B) id=img1"
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
        assert assigns[-1]["detail"] == \
            "assigned img2.bin (1.2 GiB) id=img2, was img1.bin"
    finally:
        stop()


def test_stage_host_set_emits_without_password_in_file(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        st, _, _ = _req(host, port, "POST", "/api/settings/stage-host",
                        {"username": "svc-iris", "password": "supersecretpw"},
                        headers=hh)
        assert st == 200
        raw = open(audit_path).read()
        assert "supersecretpw" not in raw
        lines = _read_audit_lines(audit_path)
        settings_events = [e for e in lines if e.get("category") == "settings"]
        # the username belongs in detail (before -> after); target is the key
        ev = [e for e in settings_events if e.get("event") == "stage_host_set"]
        assert ev and ev[0]["target"] == "stage-host"
        assert ev[0]["detail"] == "user (none) -> svc-iris"
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
        # the default-credential login that produced the grant is itself
        # audited as an ordinary successful login (category "auth")
        login_ev = [e for e in _read_audit_lines(audit_path)
                    if e.get("event") == "login"][0]
        assert login_ev["actor"] == "console:" + gui_server.DEFAULT_SETUP_USER
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
    """The Problem section's explicit requirement: a failed attempt at the
    default credential while needs_setup is audited as category "auth" --
    exercised here through the ordinary login_fail path (no grant issued)."""
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


def test_stage_host_update_and_clear_details(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/settings/stage-host",
             {"username": "svc-a", "password": "stagepw1"}, headers=hh)
        _req(host, port, "POST", "/api/settings/stage-host",
             {"username": "svc-b", "password": "stagepw2"}, headers=hh)
        _req(host, port, "DELETE", "/api/settings/stage-host", headers=hh)
        _req(host, port, "DELETE", "/api/settings/stage-host", headers=hh)
        sets = [e for e in _read_audit_lines(audit_path)
                if e.get("event") == "stage_host_set"]
        clears = [e for e in _read_audit_lines(audit_path)
                  if e.get("event") == "stage_host_clear"]
        assert [e["detail"] for e in sets] == \
            ["user (none) -> svc-a", "user svc-a -> svc-b"]
        assert [e["detail"] for e in clears] == \
            ["cleared (was user svc-b)", "nothing was configured"]
        assert all(e["target"] == "stage-host" for e in sets + clears)
        raw = open(audit_path).read()
        assert "stagepw1" not in raw and "stagepw2" not in raw
    finally:
        stop()


def test_device_upsert_create_and_update_details(tmp_path):
    host, port, _ctx, audit_path, stop = _serve_full_audit(tmp_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
              "model": "C9300"}, headers=hh)
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "model": "IE-3400"}, headers=hh)
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "model": "IE-3400"}, headers=hh)
        _req(host, port, "POST", "/api/devices",
             {"device_id": "d1", "device_ip": "10.0.0.9", "vlan": "777",
              "svi_ip": "1.1.1.1", "guest_ip": "2.2.2.2"}, headers=hh)
        ups = [e for e in _read_audit_lines(audit_path)
               if e.get("event") == "device_upsert"]
        assert [e["action"] for e in ups] == \
            ["create", "update", "update", "update"]
        assert ups[0]["detail"] == "ip 10.0.0.1, vlan 666, model C9300"
        assert ups[1]["detail"] == "changed model: C9300 -> IE-3400"
        assert ups[2]["detail"] == "no fields changed"
        # 4 changed fields -> first 3 alphabetically + a (+1 more) suffix
        assert ups[3]["detail"] == ("changed device_ip: 10.0.0.1 -> 10.0.0.9, "
                                    "guest_ip: (none) -> 2.2.2.2, "
                                    "svi_ip: (none) -> 1.1.1.1 (+1 more)")
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
        assert body == {"imported": 2, "new": 1, "updated": 1, "skipped": 2}
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
        # the receipt outcome is named too: it used to be the one thing delete
        # changed (or in this case did not change) without saying so
        assert dels[0]["detail"] == (
            "removed (ip 10.0.0.1, model -), endpoints retained, "
            "no deployment receipt")
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
    assert 'id="nav-monitoring"' in html
    assert 'id="view-monitoring"' in html
    assert "System" in html
    assert 'id="audit-load-older"' in html
    assert "Load older" in html
    assert 'id="audit-category"' in html

    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "'monitoring'" in js
    assert "refreshMonitoring" in js
    assert "audit-load-older" in js
    assert "audit-category" in js


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
                 {"device_id": did, "device_ip": "10.0.0.1", "vlan": "666",
                  "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
                  "guest_ip": "10.0.0.3"}, headers=hh)
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


def test_make_server_falls_back_to_plain_http_when_all_candidates_corrupt(
        tmp_path, monkeypatch):
    """Both the gui-cert override and IRIS_CERT are unusable at startup --
    make_server must still not crash; it serves plain HTTP (no tls_ctx),
    same as the certfile=None path, rather than taking the process down."""
    builtin = tmp_path / "cert.pem"
    builtin.write_text("-----BEGIN CERTIFICATE-----\nnot a cert\n"
                       "-----END CERTIFICATE-----\n")
    gui = tmp_path / "gui-cert.pem"
    gui.write_text("-----BEGIN CERTIFICATE-----\nalso not a cert\n"
                   "-----END CERTIFICATE-----\n")
    monkeypatch.setenv("IRIS_CERT", str(builtin))
    monkeypatch.setenv("IRIS_GUI_CERT", str(gui))
    certfile = gui_server._resolve_certfile()  # picks the corrupt override
    assert certfile == str(gui)
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
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
        assert resp["error"] == "certificate install failed"
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
        assert resp["error"] == "trust install failed"
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
        assert "url (none) -> https://ca.example/bundle.pem" in ev["detail"]
        assert "auto False -> True" in ev["detail"]
        # POST different url: detail contains first url as before-value
        assert _req(host, port, "POST", "/api/settings/ca-trust",
                    {"url": "https://ca.other/bundle.pem", "auto": True},
                    headers=hh)[0] == 200
        evs = [e for e in _read_audit_lines(audit_path)
               if e["event"] == "ca-trust-config"]
        assert len(evs) == 2
        ev = evs[1]
        assert "url https://ca.example/bundle.pem -> https://ca.other/bundle.pem" in ev["detail"]
        # Clearing (url null) → after-side "(none)"
        assert _req(host, port, "POST", "/api/settings/ca-trust",
                    {"url": None, "auto": False},
                    headers=hh)[0] == 200
        evs = [e for e in _read_audit_lines(audit_path)
               if e["event"] == "ca-trust-config"]
        assert len(evs) == 3
        ev = evs[2]
        assert "url https://ca.other/bundle.pem -> (none)" in ev["detail"]
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
        assert resp["error"] == "settings save failed"
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
                                 + _CA_DEFAULT_URL}
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
                                 "https://ca.example/bundle.pem"}
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
                       "detail": "no PEM blocks"}
        evs = [e for e in _read_audit_lines(audit_path)
               if e["event"] == "ca-trust-refresh"]
        assert len(evs) == 1 and evs[0]["result"] == "fail"
        assert "no PEM blocks" in evs[0]["detail"]
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
        assert resp["error"] == "settings save failed"
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

def _serve_receipts(tmp_path, now_fn=None):
    """A server with ONLY a receipt store wired (the deployment route needs
    nothing else). Returns the store so tests can seed records directly."""
    import deployment_receipts
    app = gui_app.GuiApp(str(tmp_path / "secrets.json"))
    app.set_admin("admin", "pw")
    state = str(tmp_path / "state")
    receipts = (deployment_receipts.ReceiptStore(state, now_fn=now_fn)
                if now_fn else deployment_receipts.ReceiptStore(state))
    srv = gui_server.make_server("127.0.0.1", 0, app, certfile=None,
                                 receipts=receipts)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return "127.0.0.1", port, receipts, srv.shutdown


def _receipt_stub(device_id):
    return {"controller_id": "iris", "device_id": device_id,
            "inventory_revision": 1, "plan_hash": "h",
            "resolved": {"attachment": "routed", "platform": "guestshell"},
            "preflight": {"status": "not-required"},
            "resources": [{"kind": "guestshell", "ownership": "iris-created"}]}


def test_deployment_route_auth_and_receipts_unavailable(tmp_path):
    # no receipt store wired at all -> 404 "receipts unavailable"
    host, port, _app, stop = _serve(tmp_path)
    try:
        assert _req(host, port, "GET", "/api/devices/d1/deployment")[0] == 401
        ck, _csrf = _auth(host, port)
        st, _, b = _req(host, port, "GET", "/api/devices/d1/deployment",
                        headers={"Cookie": ck})
        assert st == 404 and json.loads(b)["error"] == "receipts unavailable"
    finally:
        stop()


def test_deployment_route_null_then_newest_then_active(tmp_path):
    clock = {"t": 100}
    host, port, receipts, stop = _serve_receipts(tmp_path,
                                                 now_fn=lambda: clock["t"])
    try:
        ck, _csrf = _auth(host, port)
        # no receipts for the device: record is null, total 0
        st, _, b = _req(host, port, "GET", "/api/devices/d1/deployment",
                        headers={"Cookie": ck})
        assert st == 200
        assert json.loads(b) == {"receipt": None, "total": 0}
        # two non-active, non-recoverable receipts -> the newest by
        # timestamps.planned_at wins
        r1 = receipts.create(_receipt_stub("d1"))
        receipts.transition(r1["receipt_id"], "removed")
        clock["t"] = 200
        r2 = receipts.create(_receipt_stub("d1"))
        _, _, b = _req(host, port, "GET", "/api/devices/d1/deployment",
                       headers={"Cookie": ck})
        got = json.loads(b)
        assert got["total"] == 2
        assert got["receipt"]["receipt_id"] == r2["receipt_id"]
        assert got["receipt"]["state"] == "planned"
        # the record is the stored receipt as-is (resolved/preflight/
        # resources ride along)
        assert got["receipt"]["resolved"]["platform"] == "guestshell"
        assert got["receipt"]["preflight"] == {"status": "not-required"}
        assert got["receipt"]["resources"][0]["kind"] == "guestshell"
        assert got["receipt"]["timestamps"]["planned_at"] == 200
        # once a receipt goes active it wins regardless of age
        receipts.transition(r2["receipt_id"], "applying")
        receipts.transition(r2["receipt_id"], "active")
        clock["t"] = 300
        r3 = receipts.create(_receipt_stub("d1"))     # newer, but only planned
        _, _, b = _req(host, port, "GET", "/api/devices/d1/deployment",
                       headers={"Cookie": ck})
        got = json.loads(b)
        assert got["total"] == 3
        assert got["receipt"]["receipt_id"] == r2["receipt_id"]
        assert got["receipt"]["state"] == "active"
        assert r3["receipt_id"] != r2["receipt_id"]
        # receipts are per-device: another device still sees null
        _, _, b = _req(host, port, "GET", "/api/devices/other/deployment",
                       headers={"Cookie": ck})
        assert json.loads(b) == {"receipt": None, "total": 0}
    finally:
        stop()


def test_deployment_route_recoverable_beats_newer_planned(tmp_path):
    clock = {"t": 100}
    host, port, receipts, stop = _serve_receipts(tmp_path,
                                                 now_fn=lambda: clock["t"])
    try:
        ck, _csrf = _auth(host, port)
        r1 = receipts.create(_receipt_stub("d1"))
        receipts.transition(r1["receipt_id"], "needs-reconcile")
        clock["t"] = 200
        receipts.create(_receipt_stub("d1"))          # newer, merely planned
        _, _, b = _req(host, port, "GET", "/api/devices/d1/deployment",
                       headers={"Cookie": ck})
        got = json.loads(b)
        # the recoverable receipt still describes what is ON the box
        assert got["receipt"]["receipt_id"] == r1["receipt_id"]
        assert got["receipt"]["state"] == "needs-reconcile"
        assert got["total"] == 2
    finally:
        stop()


# ---- GET /api/deploy-logs (persistent deployment logs) --------------------

def test_deploy_logs_routes_list_filter_and_serve(tmp_path):
    log_dir = str(tmp_path / "deploy-logs")

    def run_fn(p, e, on):
        on("[1/6] hello"); on("[6/6] done"); return 0

    host, port, stop = _serve_onboard(tmp_path, run_fn, log_dir=log_dir)
    try:
        assert _req(host, port, "GET", "/api/deploy-logs")[0] == 401
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
        assert "[1/6] hello" in text and "[6/6] done" in text
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
    assert 'id="help-btn"' in html
    assert 'href="/help-device.html"' in html
    assert 'href="/help-server.html"' in html


def test_force_undeploy_delivers_the_force_flag_to_the_recipe(tmp_path):
    """A forced undeploy must reach the teardown recipe with
    IRIS_FORCE_AGENT_ONLY=1.

    env_extra is the ONLY channel into the recipe, and the undeploy branch is
    the only place the flag is ever set. Dropping env_extra for that action
    silently downgrades a forced teardown to the full receipted one: on Guest
    Shell and IOx that removes Vlan$VLAN, the IRISQ discriminators and the PKI
    trustpoint using inventory values no receipt has proven -- precisely the
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
                        {"force": True},
                        headers={"Cookie": ck, "X-CSRF-Token": csrf})
        assert st == 200, b
        _wait_onboard_job(host, port, ck, json.loads(b)["job_id"])
        assert seen.get("IRIS_FORCE_AGENT_ONLY") == "1", (
            "forced undeploy reached the recipe without the force flag")
    finally:
        stop()


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
    assert 'id="telemetry-health"' in overview
    # ...and no longer anywhere in the Monitoring section
    monitoring = html.split('id="view-monitoring"', 1)[1].split("</section>", 1)[0]
    assert 'id="telemetry-health"' not in monitoring
    # it refreshes with the Overview, not as part of refreshMonitoring()
    monitoring_fn = js.split("async function refreshMonitoring()", 1)[1].split("}", 1)[0]
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
    """The devices table could not be filtered, so an operator working a
    subset had to hand-pick rows. Every meaningful column gets a filter, the
    row count reports the match, and 'select all' marks the FILTERED rows so
    every bulk action -- quarantine included -- operates on exactly what the
    filter selected."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    devices = html.split('id="view-devices"', 1)[1].split("</section>", 1)[0]
    # one control per meaningful column, plus free text across the row
    for control in ("dev-filter-q", "dev-filter-attachment", "dev-filter-platform",
                    "dev-filter-cred", "dev-filter-telemetry", "dev-filter-peer",
                    "dev-filter-status", "dev-filter-clear"):
        assert 'id="%s"' % control in devices, "missing filter control: %s" % control
    # quarantine is available as a BULK action, not only per row
    assert 'id="quarantine-selected"' in devices
    assert 'id="release-selected"' in devices
    # the predicate exists and is applied before the rows are rendered
    assert "deviceMatchesFilters" in js
    # filters re-render, and the periodic poll must not wipe them
    assert "applyDeviceFilters" in js


def test_agent_install_rename_and_inventory_only_label():
    """Vocabulary fix: the 'platform' field (guestshell/iox/router) read as
    networking hardware to operators, so its DISPLAY text becomes "Agent
    install" everywhere it appears -- the add-form placeholder, the devices-
    table header, and the filter label. Separately, the 'legacy'/
    'legacy_routed' attachment value displayed as the word "legacy", which
    reads like a real inventory state rather than "attachment not chosen
    yet" -- it becomes "Inventory only — attachment not chosen". Both are
    display-only: the wire field name 'platform', its values (guestshell/
    iox/router), and the attachment values (legacy/legacy_routed) are
    unchanged."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()

    # index.html: filter option, filter label, table header, add-form select
    assert '<option value="legacy">Inventory only — attachment not chosen</option>' in html
    assert 'aria-label="Filter by agent install"' in html
    assert '<option value="">Agent install: any</option>' in html
    assert '<th>Agent install</th>' in html
    assert 'Agent install - auto by model' in html
    # the old wording is gone everywhere it used to appear as a label
    assert '>Platform<' not in html
    assert 'Platform: any' not in html
    assert 'Filter by platform"' not in html
    assert '>legacy</option>' not in html

    # the field id, its values, and the attachment values are untouched
    assert 'id="df-platform"' in html and 'id="dev-filter-platform"' in html
    assert 'value="guestshell"' in html and 'value="iox"' in html
    assert 'value="router"' in html
    assert '<option value="legacy"' in html

    # app.js: the row-attachment display and the status/detail lines
    assert "'Inventory only — attachment not chosen'" in js
    assert "attachment === 'legacy_routed' || attachment === 'legacy'" in js
    assert "'Agent install updated for '" in js
    assert "'Agent install update failed: '" in js
    assert "['Agent install', esc(res.platform" in js


def test_add_device_form_model_field_precedes_agent_install_select():
    """Agent-install options depend on the model (gui_onboard.
    install_options_for), so the model input must render BEFORE the agent-
    install select in the add-device form's DOM order -- app.js's
    refreshInstallOptions reads df-model's live value to filter df-platform's
    options as the operator types, before the field it is about to filter
    even exists otherwise."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    assert html.index('id="df-model"') < html.index('id="df-platform"')


def test_add_device_form_filters_install_options_live_by_model():
    """Source guard for the /api/install-options wiring: as the operator
    types a model, the agent-install select is refetched and repainted --
    disabled with explanatory text when the model has no valid install
    option (IOS-XR today), reset to the full set when the model is blank or
    unrecognized."""
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    assert "getElementById('df-model').addEventListener('input'" in js
    assert "/api/install-options?model=" in js
    assert "IOS-XR — no agent install available yet" in js
    assert "refreshInstallOptions" in js


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

        # the 8201 incident: an IOS-XR model gets an empty list, not null
        st, _, b = _req(host, port, "GET", "/api/install-options?model=8201",
                        headers=headers)
        assert st == 200
        assert json.loads(b)["options"] == []

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
    pane = html.split('id="monitoring-pane-deploylogs"', 1)[1].split("</div>\n      </section>", 1)[0]
    # the timeline is the audit timeline's FEATURE -- chips pick a window, a
    # brush selects a range, and the selection filters the table. A static
    # sparkline is not the same thing.
    for control in ("dl-range-chips", "dl-histogram", "dl-bars", "dl-brush",
                    "dl-window-label", "dl-clear-selection"):
        assert 'id="%s"' % control in pane, "missing timeline control: %s" % control
    assert "dlCommitSelection" in js and "after_ts=" in js
    for control in ("dl-search", "dl-action", "dl-result",
                    "dl-prev", "dl-next", "dl-page", "dl-drawer", "dl-drawer-close"):
        assert 'id="%s"' % control in pane, "missing deploy-log control: %s" % control
    # the log body lives in the drawer now, not loose under the table
    drawer = pane.split('id="dl-drawer"', 1)[1]
    assert 'id="dl-text"' in drawer
    # paging + client-side matching exist
    assert "dlPage" in js and "deployLogMatches" in js
    # the drawer slides in from the right, and respects reduce-motion
    assert "#dl-drawer" in css
    assert "prefers-reduced-motion" in css


def test_first_run_setup_is_a_wizard_not_a_linking_checklist():
    """Setup was four cards that reported status and sent the operator off to
    Settings > General / > Telemetry to actually do anything. First run is a
    flow, so it becomes a stepped wizard that hosts the forms in place.

    Three steps -- telemetry, stage host, device packages -- with admin shown
    as already complete, because first-run just created it. Every step can be
    skipped and the wizard resumes at the first incomplete one, because the
    packages step can NEVER complete in-console (no Docker socket), so a
    wizard that insisted on completion could never be finished."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    with open(os.path.join(gui_server.WEBROOT, "login.js")) as f:
        login = f.read()

    # a top-level view, not a settings sub-pane
    assert 'id="view-setup"' in html
    assert "'setup'" in js.split("var VIEWS =", 1)[1].split("]", 1)[0]

    wiz = html.split('id="view-setup"', 1)[1].split("</section>", 1)[0]
    # the two form steps mount the SHARED templates rather than copying them
    assert 'id="wz-td-mount"' in wiz and 'id="wz-sh-mount"' in wiz
    assert "mountSettingsForm('td', 'wz-td-mount')" in js
    assert "mountSettingsForm('sh', 'wz-sh-mount')" in js
    # packages is detect-and-instruct, never a form
    assert 'id="wz-pkg-recheck"' in wiz
    assert "<form" not in wiz.split('id="wz-step-packages"', 1)[1]
    # skippable, resumable, and it reports where you are
    assert 'id="wz-skip"' in wiz and 'id="wz-next"' in wiz and 'id="wz-back"' in wiz
    assert "wizardFirstIncompleteStep" in js
    # the nudge that brings an operator back
    assert 'id="setup-nudge"' in html
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
    so the wizard opened on stage host and the telemetry step was never
    visible at all -- it looked missing.

    Every step must therefore be listed and reachable, whatever its state."""
    with open(os.path.join(gui_server.WEBROOT, "index.html")) as f:
        html = f.read()
    with open(os.path.join(gui_server.WEBROOT, "app.js")) as f:
        js = f.read()
    wiz = html.split('id="view-setup"', 1)[1].split("</section>", 1)[0]
    assert 'id="wz-steplist"' in wiz, "no step list: completed steps stay invisible"
    # the list is built from the same step table the wizard navigates
    assert "renderWizardStepList" in js
    # and any step can be opened directly, not just the first incomplete one
    assert "wz-steplist-item" in js


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

    # a display-label map exists and the chip renders through it
    assert "AUDIT_CAT_LABELS" in js
    chip = js.split("function auditRowHtml", 1)[1].split("return", 1)[0]
    assert "AUDIT_CAT_LABELS" in chip, "the chip still prints the raw category"
    # ...while the class stays keyed on the real category, for the styling
    assert "cat-' + esc(category)" in chip, \
        "the chip class must stay keyed on the REAL category, for styling"
    # the filter still SENDS onboard, whatever it displays
    assert 'value="onboard"' in html
    # and the label an operator reads is no longer the bare subsystem name
    assert ">onboard</option>" not in html


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


def _stranded_receipt(receipts, resources=None):
    """A receipt in the state a died-mid-teardown router is left in."""
    rid = receipts.create({
        "controller_id": "iris", "device_id": "r1", "inventory_revision": 1,
        "plan_hash": "b" * 64,
        "resolved": {"platform": "router", "attachment": "router-nat",
                     "device_ip": "192.0.2.10", "vpg_number": "10",
                     "nat_interface": "GigabitEthernet1", "app_ip": "10.8.0.2",
                     "app_mask": "255.255.255.252", "app_gateway": "10.8.0.1"},
        "preflight": {"status": "passed", "device_identity": "OLDBOARDID"},
        "resources": _OWNED if resources is None else resources})["receipt_id"]
    receipts.transition(rid, "applying")
    receipts.transition(rid, "needs-reconcile")
    return rid


def test_delete_abandons_receipts_so_a_readded_device_can_onboard(tmp_path, monkeypatch):
    """Delete must be terminal for a device id.

    Every other per-device store is purged on delete -- assignment, heartbeat,
    telemetry, pull directive, report ledger -- but the receipt store was never
    touched, and it is the one that gates onboard. A device deleted and added
    back under the same id therefore inherited its predecessor's deployment:
    onboard refused with "undeploy it first", and the undeploy it named refused
    the box, because a rebuilt VM keeps the id and the address but reports a new
    board ID. Neither door opened, and delete was no way out either."""
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, fleet, receipts, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        rid = _stranded_receipt(receipts)

        st, _, b = _req(host, port, "POST", "/api/devices/r1/onboard", {}, headers=hh)
        assert st == 409 and b"deployment receipt" in b

        st, _, b = _req(host, port, "DELETE", "/api/devices/r1", headers=hh)
        assert st == 200, b
        assert receipts.get(rid)["state"] == "abandoned"
        assert receipts.recoverable_for_device("r1") is None

        st, _, b = _req(host, port, "POST", "/api/devices", dict(_ROUTER_ROW),
                        headers=hh)
        assert st == 200, b
        st, _, b = _req(host, port, "POST", "/api/devices/r1/onboard", {},
                        headers=hh)
        assert st == 200, b
    finally:
        stop()


def test_delete_audit_names_the_receipt_outcome(tmp_path, monkeypatch):
    """The delete audit line already names what it revoked and what it retained.
    Receipts were the one thing it changed silently."""
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    audit_path = str(tmp_path / "audit.jsonl")
    host, port, fleet, receipts, stop = _serve_router(
        tmp_path, lambda p, e, on: 0, audit_path=audit_path)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _stranded_receipt(receipts)
        assert _req(host, port, "DELETE", "/api/devices/r1", headers=hh)[0] == 200
        with open(audit_path) as stream:
            events = [json.loads(line) for line in stream if line.strip()]
        deletes = [e for e in events if e.get("event") == "device_delete"]
        assert deletes, "no device_delete audit event"
        assert "1 deployment receipt abandoned" in deletes[0]["detail"], \
            deletes[0]["detail"]
    finally:
        stop()


def test_forced_undeploy_is_honoured_when_a_receipt_exists(tmp_path):
    """Force is the rescue path for a box that no longer matches its receipt --
    which is exactly a case where a receipt EXISTS. It used to be consulted only
    on the no-receipt branch, so a replaced device ran the full receipted
    teardown, hit the recipe's identity guard on the new board ID, and failed
    every single time with no way to ask for anything else."""
    seen = {}

    def run_fn(p, e, on):
        seen.update(e)
        return 0

    host, port, fleet, receipts, stop = _serve_router(tmp_path, run_fn)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        rid = _stranded_receipt(receipts)

        st, _, b = _req(host, port, "POST", "/api/devices/r1/undeploy",
                        {"force": True}, headers=hh)
        assert st == 200, b
        _wait_onboard_job(host, port, ck, json.loads(b)["job_id"])
        assert seen.get("IRIS_FORCE_AGENT_ONLY") == "1", (
            "a forced undeploy ran the receipted teardown instead")
        # and the receipt it deliberately did not use as authority is retired,
        # or the very next onboard is refused on it again.
        assert receipts.get(rid)["state"] == "abandoned"
        assert receipts.recoverable_for_device("r1") is None
    finally:
        stop()


def test_forced_undeploy_retires_receipts_only_on_success(tmp_path):
    """A failure to reach the device is not proof that the receipt is wrong.
    Voiding a healthy deployment's receipt on a network blip would strand it the
    way this path exists to prevent, so retirement waits for a clean exit."""
    host, port, fleet, receipts, stop = _serve_router(
        tmp_path, lambda p, e, on: 1)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        rid = _stranded_receipt(receipts)
        st, _, b = _req(host, port, "POST", "/api/devices/r1/undeploy",
                        {"force": True}, headers=hh)
        assert st == 200, b
        _wait_onboard_job(host, port, ck, json.loads(b)["job_id"])
        assert receipts.get(rid)["state"] != "abandoned"
    finally:
        stop()


def test_forced_undeploy_escapes_multiple_recoverable_receipts(tmp_path):
    """Two recoverable receipts refuse onboard, undeploy and adopt alike, and
    nothing in the product resolved them. The refusal now names force, and force
    reaches the teardown instead of being rejected ahead of it."""
    host, port, fleet, receipts, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        first = _stranded_receipt(receipts)
        second = _stranded_receipt(receipts)

        st, _, b = _req(host, port, "POST", "/api/devices/r1/undeploy", {},
                        headers=hh)
        assert st == 409
        assert b"multiple recoverable receipts" in b and b"force" in b

        st, _, b = _req(host, port, "POST", "/api/devices/r1/undeploy",
                        {"force": True}, headers=hh)
        assert st == 200, b
        _wait_onboard_job(host, port, ck, json.loads(b)["job_id"])
        assert receipts.get(first)["state"] == "abandoned"
        assert receipts.get(second)["state"] == "abandoned"
    finally:
        stop()


def test_repeated_unusable_receipt_undeploy_stays_409(tmp_path):
    """The 409 path marks the receipt needs-reconcile on its way out. Doing that
    to a receipt already in needs-reconcile is not a legal transition, and the
    raise escaped do_POST -- so the first retry answered with a traceback and no
    JSON body instead of the reason."""
    host, port, fleet, receipts, stop = _serve_router(tmp_path, lambda p, e, on: 0)
    try:
        ck, csrf = _auth(host, port)
        hh = {"Cookie": ck, "X-CSRF-Token": csrf}
        _stranded_receipt(receipts, resources=[])   # proves ownership of nothing
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
    """The Status filter must offer every state the Status cell can render.

    The filter used to derive its own status from a three-branch copy of the
    cell's logic, so a device reading "onboarding…", "placement failed" or
    "copying to bootflash:" could not be selected at all, and asking for
    "enrolled" quietly swept them in. One derivation now feeds both, and the
    dropdown is generated from it -- this guards that they cannot drift."""
    app_js = _webroot("app.js")
    body = app_js.split("function deviceStatus(d, devNow) {", 1)[1]
    body = body.split("\n  function ", 1)[0]
    rendered = set(re.findall(r"key: '([a-z-]+)'", body))
    assert rendered, "deviceStatus() returned no recognisable keys"

    options = app_js.split("var DEVICE_STATUS_OPTIONS = [", 1)[1].split("];", 1)[0]
    offered = set(re.findall(r"\['([a-z-]+)',", options))
    assert rendered <= offered, (
        "renderable but not filterable: %s" % sorted(rendered - offered))
    # "offline" is a modifier on top of the cell, not one of its branches
    assert offered - rendered == {"offline"}, sorted(offered - rendered)
    # the filter compares the shared key, never a second derivation
    assert "deviceStatus(d, devNow).key !== f.status" in app_js
    assert "deviceStatusKey" not in app_js
    # and the markup no longer carries a hand-written subset
    html = _webroot("index.html")
    picker = html.split('id="dev-filter-status"', 1)[1].split("</select>", 1)[0]
    assert picker.count("<option") == 1, "status options are hardcoded again"


def test_image_can_be_assigned_to_the_selection():
    """Assigning an image was per-row only, which does not scale past a handful
    of devices -- and the devices table gained filters precisely so an operator
    could act on a subset. Bulk assignment now opens the SAME image picker the
    per-row button uses (Task 4: an ordered multi-image set, not a single
    <select>), and shares the selected-action lock with every other bulk
    action, or a delete could fire mid-assignment.

    NOTE: this test used to pin the single-image <select id="image-selected">
    + <button id="apply-image-selected"> pair with an "__unassign" sentinel
    value. Task 4 replaces that control with the shared image-set picker
    (openImagePicker) per its own spec, which is why this test's assertions
    changed rather than only gaining new ones -- the control it pinned no
    longer exists by design, not by drift."""
    html = _webroot("index.html")
    app_js = _webroot("app.js")
    assert '<select id="image-selected"' not in html, \
        "old single-image bulk picker still wired -- was it really replaced?"
    assert 'id="apply-image-selected"' not in html
    assert 'id="assign-images-selected"' in html
    assert "'assign-images-selected'" in app_js.split("BULK_BTNS", 1)[1][:400], \
        "bulk image assign is not under the shared selected-action lock"
    # two occurrences of the bare getElementById() exist (updateSelBar's
    # live label text, and the click handler below) -- split on the
    # listener registration specifically so this pins the handler, not the
    # label update.
    handler = app_js.split(
        "getElementById('assign-images-selected').addEventListener", 1)[1][:3200]
    assert "openImagePicker(" in handler
    assert "claimSelection()" in handler
    # the intersection of the selection's current sets, not the union of them
    # (union would silently ADD an image to a device that lacks it) and not
    # one device's set either (that would silently DROP one from the rest)
    assert "reduce(" in handler and "indexOf(" in handler
    apply_fn = app_js.split("function assignImagesTo", 1)[1][:500]
    assert "'/assign'" in apply_fn
    assert "image_ids:" in apply_fn


def test_empty_apply_confirms_before_unassigning(tmp_path):
    """Review finding: two selected devices with DIFFERENT image sets
    intersect to an EMPTY picker selection, which opens with nothing
    pre-checked -- clicking Apply without touching a box then silently wipes
    every selected device's assignment, no confirmation. Both the bulk path
    and the single-device (per-row) path must confirm before POSTing an
    empty image_ids body; a device that already has nothing assigned is a
    harmless extra prompt, not a special case to detect."""
    app_js = _webroot("app.js")
    bulk_handler = app_js.split(
        "getElementById('assign-images-selected').addEventListener", 1)[1][:3200]
    assert "!imgIds.length" in bulk_handler
    assert "confirm('Unassign all images from ' + claimed.length + ' device(s)?')" \
        in bulk_handler
    # cancelling the confirm must release the bulk selected-action lock, the
    # same way the existing delete-selected cancel path does
    assert "setBulkBusy(false)" in bulk_handler.split(
        "Unassign all images from", 1)[1][:200]
    row_handler = app_js.split("openImagePicker(rowAssignedIds(d)", 1)[1][:400]
    assert "!ids.length" in row_handler
    assert "confirm('Unassign all images from ' + id + '?')" in row_handler


def test_bulk_picker_notes_and_confirms_whenever_the_sets_differ():
    """Review finding: the note (and nothing else) used to fire only when the
    INTERSECTION of the selection's sets came out EMPTY. dev1=[A,B] with
    dev2=[A] intersects to a NON-empty [A], so that selection got no note and
    no confirm -- Apply posted [A] to both and dev1 silently lost B.

    The rule is about the SETS, not their intersection: Apply writes one set
    to every selected device, so whenever the selected devices' assignments
    are not all identical, applying replaces them all and can drop images the
    operator never saw. That case now gets BOTH the picker note and a confirm
    on Apply, from one shared derivation. Identical sets (including every
    device unassigned) stay a plain, unconfirmed apply."""
    html = _webroot("index.html")
    app_js = _webroot("app.js")
    assert 'id="img-picker-note"' in html
    bulk_handler = app_js.split(
        "getElementById('assign-images-selected').addEventListener", 1)[1][:3200]
    # ONE derivation of "the selected devices disagree", read by both the note
    # and the confirm -- they cannot drift apart into two different rules.
    assert "setsDiffer" in bulk_handler
    assert "sets.some(" in bulk_handler
    # ...and it is no longer the empty-intersection test
    assert "!intersection.length &&" not in bulk_handler, \
        "the note still fires only on an EMPTY intersection"
    assert "if (setsDiffer) {" in bulk_handler
    assert "Selected devices have differing assignments" in bulk_handler
    # Apply confirms before it replaces differing sets, and cancelling that
    # confirm releases the shared selected-action lock like every other one.
    guard = bulk_handler.split("} else if (setsDiffer &&", 1)
    assert len(guard) == 2, "Apply does not confirm when the sets differ"
    assert "confirm(" in guard[1][:200]
    assert "setBulkBusy(false)" in guard[1][:900]
    # the picker itself resets any stale note on every open, so a note left
    # over from one bulk pick never bleeds into the next (bulk or per-row)
    picker = app_js.split("function openImagePicker(currentIds, onApply) {", 1)[1]
    picker = picker.split("\n  function closeImagePicker", 1)[0]
    assert "img-picker-note" in picker


def test_image_picker_and_drawer_show_filename_not_just_id():
    """Review finding: the picker and the deployment drawer showed a bare
    image id, forcing the operator to go find it in the Images tab to see
    what it actually is. Both now render 'id — filename', escaped like every
    other interpolation in this file, matching how the catalog list already
    shows both facts about an image."""
    app_js = _webroot("app.js")
    assert "function imageLabel(id)" in app_js
    label_fn = app_js.split("function imageLabel(id) {", 1)[1][:300]
    assert "esc(id)" in label_fn and "esc(fn)" in label_fn
    picker = app_js.split("function openImagePicker(currentIds, onApply) {", 1)[1]
    picker = picker.split("\n  function closeImagePicker", 1)[0]
    assert "imageLabel(id)" in picker
    drawer = app_js.split("function deployImageRows(d) {", 1)[1][:700]
    assert "imageLabel(iid)" in drawer


def test_image_picker_is_one_function_shared_by_both_entry_points():
    """The row select and the bulk dropdown used to be two separate ways to
    assign the same thing, through two different code paths that could (and
    did) drift apart. Task 4 replaces both with ONE picker function -- pin
    that there is exactly one definition, that both the per-row button and
    the bulk toolbar action call it, and that it enforces the 10-image cap
    itself (the 11th checkbox disabled, not just the server's 400)."""
    app_js = _webroot("app.js")
    assert app_js.count("function openImagePicker(currentIds, onApply)") == 1
    # definition + at least two call sites (per-row, bulk)
    assert app_js.count("openImagePicker(") >= 3
    picker = app_js.split("function openImagePicker(currentIds, onApply) {", 1)[1]
    picker = picker.split("\n  function closeImagePicker", 1)[0]
    assert ">= 10" in picker, "unchecked boxes are never disabled at the cap"
    assert ".disabled = " in picker
    # checked-first: the device's current set renders before the rest of the
    # catalog, so it is never buried below the fold
    assert "checked" in picker.lower()


def test_row_assign_is_a_button_not_a_select():
    """The per-row image control used to be a <select class="assign">: one
    change event picked exactly one image. It cannot express an ORDERED SET,
    so it is replaced by a button that opens the shared picker with the
    row's current assigned set."""
    html = _webroot("index.html")
    app_js = _webroot("app.js")
    assert '<select class="assign"' not in app_js
    assert 'class="linkish assign-btn"' in app_js
    assert "#dev-rows .assign-btn" in app_js
    assert "openImagePicker(rowAssignedIds(d)" in app_js
    assert 'id="mark-all"' in html   # the checkbox column stays untouched


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
    per assigned image: id + state -- ready via staged_image_ids, the
    in-flight one via current_image_id/stage_state with stage_error shown on
    it, everything else outstanding read as queued. Parked is deliberately
    NOT a console state: a parked image is simply absent from the assigned
    set, so it never gets a row here at all."""
    html = _webroot("index.html")
    app_js = _webroot("app.js")
    assert 'id="di-img-rows"' in html
    assert "function deployImageRows(d)" in app_js
    body = app_js.split("function deployImageRows(d) {", 1)[1][:700]
    assert "rowAssignedIds(d)" in body
    assert "rowHasStaged(d, iid)" in body
    assert "current_image_id" in body and "stage_error" in body
    assert "parked" not in body.lower()
    assert "document.getElementById('di-img-rows').innerHTML = deployImageRows(d)" in app_js


def test_deployment_details_open_in_a_right_hand_drawer():
    """It used to render below the devices table, so opening it on a fleet of
    any size put the details off-screen and made the operator scroll away from
    the row they had just clicked."""
    html = _webroot("index.html")
    css = _webroot("styles.css")
    app_js = _webroot("app.js")
    panel = html.split('id="deploy-info-panel"', 1)[1].split(">", 1)[0]
    assert 'class="drawer"' in panel, panel
    drawer = css.split(".drawer {", 1)[1].split("}", 1)[0]
    assert "position:fixed" in drawer and "right:0" in drawer
    assert "top:0" in drawer and "bottom:0" in drawer
    # reduced motion is honoured, like the deployment-log drawer
    assert ".drawer { transition:none; }" in css
    # and Escape gets the operator out without aiming for the close control
    assert "closeDeployInfo" in app_js
    escape = app_js.split("function closeDeployInfo", 1)[1][:700]
    assert "'Escape'" in escape


# ---------------------------------------------------------------------------
# In-flight work and deployment logs must not outlive the device they describe
# ---------------------------------------------------------------------------

def _serve_router_jobs(tmp_path, run_fn=None, now_fn=None):
    """_serve_router, but handing back the onboard service, its log dir and an
    audit file so a test can plant in-flight work and persisted logs."""
    import deployment_receipts
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
    receipts = deployment_receipts.ReceiptStore(state)
    onboard = gui_onboard.OnboardService(
        fleet, creds, host_ip="10.9.9.9", mint_fn=lambda d: "TOK",
        run_fn=run_fn or (lambda p, e, on: 0), receipts=receipts,
        log_dir=log_dir)
    srv = gui_server.make_server("127.0.0.1", 0, app, None, fleet, creds, None,
                                 onboard, certfile=None, receipts=receipts,
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
            "_line_bytes": 0, "_log_truncated": False, "receipt_id": None,
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
        # a row as it looked before the stamp existed
        with open(fleet.path) as stream:
            raw = json.load(stream)
        raw["devices"]["r1"].pop("registered_at", None)
        with open(fleet.path, "w") as stream:
            json.dump(raw, stream)
        _plant_deploy_log(log_dir, "r1", 500, job_id="cccccccccccc0003")

        _, _, b = _req(host, port, "GET", "/api/deploy-logs?device_id=r1",
                       headers={"Cookie": ck})
        entries = json.loads(b)["logs"]
        assert entries and all("previous_registration" not in e for e in entries)
    finally:
        stop()


def test_previous_registration_logs_are_labelled_in_the_console():
    app_js = _webroot("app.js")
    assert "previous_registration" in app_js
    block = app_js.split("previous_registration", 1)[1][:400]
    assert "previous device" in block
