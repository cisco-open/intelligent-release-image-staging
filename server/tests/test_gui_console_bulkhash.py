# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Source guards for the console UI of the KGV / Cisco Bulk Hash reconciler
(spec Task 5): the Settings > Image verification pane (schedule, Refresh
now, offline upload), the Images page verdict badges + image-detail drawer
(release / typed-confirm override), and the multi-image picker's quarantine
blocking. Client-side only -- app.js/index.html have no JS test harness in
this repo, so these assert the markup/wiring stays intact (the SOURCE TEXT
of the function bodies), the same idiom as test_tls_page_ux.py /
test_onboard_feedback_ux.py / the picker tests in test_gui_server.py. The
HTTP endpoints these panes call are already covered end-to-end by
test_gui_server_bulkhash.py (Task 4); nothing here re-tests the server."""
import os

import gui_server


def _read(name):
    with open(os.path.join(gui_server.WEBROOT, name)) as f:
        return f.read()


def _slice(container, start_marker, end_marker):
    return container.split(start_marker, 1)[1].split(end_marker, 1)[0]


# --- Settings sub-menu / sub-page registration -----------------------------

def test_settings_submenu_has_image_verification_entry():
    html = _read("index.html")
    side = _slice(html, '<div id="settings-submenu" hidden>', "</div>")
    assert 'id="nav-settings-bulkhash"' in side
    assert 'href="#settings/bulkhash"' in side
    assert ">Image verification<" in side


def test_app_js_registers_the_bulkhash_settings_sub_via_push_not_the_pinned_literal():
    """House rule: the original SETTINGS_SUBS trio stays a literal (a
    different source guard pins it exactly); every pane added since is
    appended with its own SETTINGS_SUBS.push(...) call, never by editing
    that array. This pane follows the same convention as 'audit'/'setup'."""
    js = _read("app.js")
    assert re_pinned_trio_intact(js)
    assert "SETTINGS_SUBS.push('bulkhash')" in js


def re_pinned_trio_intact(js):
    import re
    return bool(re.search(
        r"SETTINGS_SUBS\s*=\s*\[\s*'general'\s*,\s*'tls'\s*,\s*'telemetry'\s*\]", js))


# --- Settings > Image verification pane: markup -----------------------------

def _bulkhash_pane(html):
    return _slice(html, 'id="settings-pane-bulkhash" hidden>', "</section>")


def test_pane_present_and_hidden_by_default():
    html = _read("index.html")
    assert 'id="settings-pane-bulkhash" hidden' in html


def test_schedule_controls_have_the_binding_copy():
    """UI copy decisions (binding): the weekly option must name its Monday
    UTC anchor, the daily option must say UTC, and the hour is 00:00-23:00
    UTC."""
    pane = _bulkhash_pane(_read("index.html"))
    assert 'id="iv-mode"' in pane
    mode = _slice(pane, 'id="iv-mode"', "</select>")
    assert '<option value="off">Off</option>' in mode
    assert '<option value="daily">Daily (UTC)</option>' in mode
    assert '<option value="weekly">Weekly (Mondays, UTC)</option>' in mode
    assert 'id="iv-hour"' in pane


def test_hour_select_is_built_client_side_for_00_00_through_23_00_utc():
    js = _read("app.js")
    assert "getElementById('iv-hour')" in js
    assert "for (var h = 0; h < 24; h++)" in js
    assert ":00</option>" in js


def test_refresh_now_button_and_last_run_line_present():
    pane = _bulkhash_pane(_read("index.html"))
    assert 'id="iv-refresh"' in pane
    btn = _slice(pane, 'id="iv-refresh"', "</button>")
    assert "Refresh now" in btn
    assert 'id="iv-last-run"' in pane


def test_offline_dropzone_present_and_accessible():
    pane = _bulkhash_pane(_read("index.html"))
    assert 'id="iv-offline-dropzone"' in pane
    open_tag = _slice(pane, 'id="iv-offline-dropzone"', ">")
    assert 'tabindex="0"' in open_tag
    assert 'role="button"' in open_tag
    assert 'aria-label="' in open_tag
    zone = _slice(pane, 'id="iv-offline-dropzone"', "</div>")
    assert 'id="iv-offline-dropzone-input"' in zone
    assert 'type="file"' in zone


# --- Settings > Image verification pane: app.js wiring ----------------------

def test_app_js_wires_the_dropzone_via_the_shared_wireDropzone_helper():
    """Drag-drop pattern mirrored from the TLS pane, per the brief."""
    js = _read("app.js")
    assert "wireDropzone(document.getElementById('iv-offline-dropzone')" in js
    assert "function uploadOfflineTar(file)" in js


def test_offline_upload_is_a_raw_body_post_not_multipart():
    """Endpoint contract (Task 4): raw binary POST, not RFC 2046 multipart
    and not form-encoded -- mirrors the PUT /api/images/upload/<name> XHR
    idiom (xhr.send(file) sends the raw File body)."""
    js = _read("app.js")
    fn = js.split("function uploadOfflineTar(file) {", 1)[1].split(
        "\n  wireDropzone(document.getElementById('iv-offline-dropzone')", 1)[0]
    assert "'/api/image-verification/offline'" in fn
    assert "xhr.open('POST'" in fn
    assert "setRequestHeader('X-CSRF-Token'" in fn
    assert "xhr.send(file)" in fn
    assert "FormData" not in fn
    assert "multipart" not in fn.lower()


def test_refresh_now_disables_while_in_flight_and_handles_already_running():
    js = _read("app.js")
    fn = js.split(
        "document.getElementById('iv-refresh').addEventListener('click'", 1)[1][:1600]
    assert "btn.disabled = true" in fn
    assert "btn.disabled = false" in fn
    assert "r.status === 409" in fn
    assert "already in progress" in fn
    assert "'/api/image-verification/refresh'" in fn


def test_last_run_rendering_never_equals_fail_it_checks_the_prefix():
    """Binding rule from the endpoint contract: last_run.outcome is "ok" or
    "fail: <detail>" -- an equality check against the literal "fail" would
    never match, so this must be a startswith-style prefix check."""
    js = _read("app.js")
    fn = js.split("function bulkhashOutcomeFailed(outcome) {", 1)[1].split(
        "\n  }", 1)[0]
    assert "slice(0, 4) === 'fail'" in fn
    assert "=== 'fail'" not in js.split(
        "function fmtBulkhashLastRun(lr) {", 1)[1].split("\n  }", 1)[0], \
        "the last-run renderer must route failure detection through the " \
        "prefix helper, never a bare equality check"


def test_schedule_form_posts_mode_and_hour_utc():
    js = _read("app.js")
    fn = js.split(
        "document.getElementById('iv-schedule-form').addEventListener('submit'", 1)[1][:900]
    assert "'/api/settings/image-verification'" in fn
    assert "mode: mode" in fn
    assert "hour_utc: hour" in fn


# --- Images page: verdict badges --------------------------------------------

def test_images_table_has_a_verification_column():
    html = _read("index.html")
    images_section = _slice(html, 'id="images">', "</table>")
    assert "<th>Verification</th>" in images_section


def test_verdict_badge_texts_match_the_binding_copy():
    js = _read("app.js")
    fn = js.split("function bulkhashVerdictBadge(hv, quarantined) {", 1)[1].split(
        "\n  }", 1)[0]
    assert ">Verified<" in fn
    assert "MISMATCH — quarantined" in fn
    assert "Not in Cisco" in fn  # apostrophe escaped, don't pin the escaping style
    assert ">Not checked<" in fn
    assert "Deferred by Cisco" in fn


def test_null_verdict_state_reads_as_not_checked_not_hidden():
    js = _read("app.js")
    fn = js.split("function bulkhashVerdictBadge(hv, quarantined) {", 1)[1].split(
        "\n  }", 1)[0]
    assert "if (!state) {" in fn


def test_deferral_warning_is_additive_to_whatever_state_is_shown():
    js = _read("app.js")
    fn = js.split("function bulkhashVerdictBadge(hv, quarantined) {", 1)[1].split(
        "\n  }", 1)[0]
    # the deferral branch appends to html rather than replacing it -- so it
    # can accompany verified/mismatch/not_in_feed alike
    assert "html +=" in fn
    assert "hv.deferral" in fn


def test_images_row_renders_the_badge_and_an_info_button():
    js = _read("app.js")
    fn = js.split("async function refreshImages() {", 1)[1].split(
        "\n  // ---- Image detail drawer", 1)[0]
    assert "bulkhashVerdictBadge(i.hash_verification, i.quarantined)" in fn
    assert "img-info" in fn


# --- Image picker: quarantined ids visibly blocked --------------------------

def _picker_body(js):
    return js.split("function openImagePicker(currentIds, onApply) {", 1)[1].split(
        "\n  function closeImagePicker", 1)[0]


def test_picker_marks_quarantined_rows_with_a_badge():
    js = _read("app.js")
    picker = _picker_body(js)
    assert "imageQuarantined[id]" in picker
    assert "quarantined</span>" in picker


def test_picker_disables_a_quarantined_id_only_when_not_already_assigned():
    """Blocks NEW selection (disabled + badge, per the brief) without
    trapping an operator who needs to uncheck an image that was assigned
    before it became quarantined -- that removal must stay possible."""
    js = _read("app.js")
    picker = _picker_body(js)
    assert "var blocked = !!imageQuarantined[id] && !checkedSet[id]" in picker
    assert "data-blocked=\"1\"" in picker
    # the pinned "unknown" disabling stays intact, untouched by this addition
    assert "unknown ? ' disabled' : ''" in picker


def test_picker_cap_logic_never_re_enables_a_blocked_checkbox():
    """updateCount() re-evaluates every unchecked box's disabled state on
    every change (for the 10-image cap) -- it must never blanket-clear the
    quarantine block just because the count dropped."""
    js = _read("app.js")
    picker = _picker_body(js)
    fn = picker.split("function updateCount() {", 1)[1].split("\n    }", 1)[0]
    assert "cb.dataset.blocked === '1'" in fn


def test_images_list_populates_the_quarantine_map_alongside_imageIds():
    js = _read("app.js")
    fn = js.split("async function refreshDevices() {", 1)[1][:2200]
    assert "imageQuarantined[i.id] = !!i.quarantined" in fn


# --- Image detail drawer: release + typed-confirm override ------------------

def test_drawer_present_with_release_and_override_controls():
    html = _read("index.html")
    assert 'id="img-info-panel" class="drawer" hidden' in html
    drawer = _slice(html, 'id="img-info-panel" class="drawer" hidden', "</div>\n      </section>")
    assert 'id="ii-release"' in drawer
    assert 'id="ii-confirm-text"' in drawer
    assert 'id="ii-release-override"' in drawer
    assert 'id="ii-override-block" hidden' in drawer


def test_release_block_hidden_unless_the_image_is_actually_quarantined():
    js = _read("app.js")
    fn = js.split("function openImageInfo(id) {", 1)[1].split(
        "\n  function closeImageInfo", 1)[0]
    assert "getElementById('ii-release-block').hidden = !img.quarantined" in fn


def test_normal_release_first_then_override_path_on_409_still_mismatching():
    """Endpoint contract (Task 4): override=False first; a 409 body carries
    error 'quarantine_still_mismatched', which is when the typed-confirm
    override path (override=true + confirm_text) is offered."""
    js = _read("app.js")
    fn = js.split("async function attemptReleaseQuarantine(override, confirmText) {", 1)[1].split(
        "\n  document.getElementById('ii-release')", 1)[0]
    assert "'/api/images/' + encodeURIComponent(imgInfoId) + '/release-quarantine'" in fn
    assert "override: override" in fn
    assert "confirm_text: confirmText" in fn
    assert "r.status === 409" in fn
    assert "quarantine_still_mismatched" in fn
    # every other failure surfaces the API's own message, not a made-up one
    assert "body.error ||" in fn


def test_release_button_sends_no_override_the_override_button_sends_the_typed_text():
    js = _read("app.js")
    normal = js.split(
        "document.getElementById('ii-release').addEventListener('click'", 1)[1][:200]
    assert "attemptReleaseQuarantine(false, '')" in normal
    override = js.split(
        "document.getElementById('ii-release-override').addEventListener('click'", 1)[1][:250]
    assert "attemptReleaseQuarantine(true, document.getElementById('ii-confirm-text').value)" in override


def test_confirm_text_input_is_never_prefilled_with_the_filename():
    """Typed-confirm means the OPERATOR types it -- pre-filling the input
    with the expected value would defeat the point of the confirmation."""
    js = _read("app.js")
    fn = js.split("function openImageInfo(id) {", 1)[1].split(
        "\n  function closeImageInfo", 1)[0]
    assert "getElementById('ii-confirm-text').value = ''" in fn
    assert "img.filename" not in fn.split("getElementById('ii-confirm-text')", 1)[1][:5]
