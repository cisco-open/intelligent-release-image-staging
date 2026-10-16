# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Console image verification ownership and executable workflow guards.

Native HTTP, signed-feed parsing and quarantine remain covered separately.
This suite runs the shipped React controller's exact-result, scheduling,
bounded raw upload and stale/unknown request regression tests.
"""
import os

import management_api as gui_server


def _read(name):
    with open(os.path.join(gui_server.WEBROOT, name)) as f:
        return f.read()


def _slice(container, start_marker, end_marker):
    return container.split(start_marker, 1)[1].split(end_marker, 1)[0]


def _verification_source(name):
    with open(os.path.join(os.path.dirname(gui_server.WEBROOT),
                           "console-ui", "src", name), encoding="utf-8") as f:
        return f.read()


def test_image_verification_navigation_and_single_react_mount():
    nav = _verification_source("settings-navigation.jsx")
    assert "['bulkhash', 'Image verification'," in nav
    assert 'href={`#settings/${id}`}' in nav
    html = _read("index.html")
    assert html.count('id="iris-image-verification-root"') == 1
    assert 'id="settings-pane-bulkhash" hidden' in html
    assert 'id="iv-content"' not in html
    assert "mountImageVerification" in _verification_source("main.jsx")


def test_react_owns_both_settings_and_wizard_with_authenticated_adapter():
    js = _read("app.js")
    assert "SETTINGS_SUBS.push('bulkhash')" in js
    assert "var imageVerification = window.irisImageVerification;" in js
    assert "fetch: fetch, headers: csrfHdr, formatDate: fmtDate" in js
    assert "imageVerification.select(hostId)" in js
    assert "imageVerification.refresh()" in js
    assert "imageVerification.select(null)" in js
    adapter = _slice(js, "var imageVerification =", "// React owns certificate inventory")
    assert "refreshImages().catch" in adapter
    assert "refreshDevices().catch" in adapter
    assert "assignments.services.publishImages(assignments.acceptImages({ok: false}, assignments.beginImageRead()))" in adapter
    for removed in ("function uploadOfflineTar(", "function renderIvStatusFields(",
                    "function fmtBulkhashLastRun(", "function wireDropzone("):
        assert removed not in js


def test_schedule_keeps_utc_anchor_and_accessible_native_controls():
    component = _verification_source("image-verification.jsx")
    assert '<option value="off">Off</option>' in component
    assert '<option value="daily">Daily (UTC)</option>' in component
    assert '<option value="weekly">Weekly (Mondays, UTC)</option>' in component
    assert "Array.from({length: 24}" in component
    assert "padStart(2, '0')}:00" in component
    assert 'htmlFor="iv-mode"' in component
    assert 'htmlFor="iv-hour"' in component
    assert 'id="iv-refresh"' in component
    assert 'id="iv-last-run" role="status" aria-live="polite"' in component
    assert 'id="iv-offline-dropzone" tabIndex={0} role="button" aria-disabled={!canWrite}' in component
    assert 'aria-label="Choose or drop a Cisco Bulk Hash feed tar file"' in component
    assert 'id="iv-offline-dropzone-input"' in component
    assert "event.target.value = ''" in component
    assert "Upload sent. Waiting for signature verification and catalog results." in component


def test_offline_archive_stays_raw_and_never_treated_as_verified_at_upload_completion():
    controller = _verification_source("image-verification-controller.mjs")
    model = _verification_source("image-verification-model.mjs")
    assert "xhr.open('POST', verificationPaths.offline)" in controller
    assert "Object.entries(this.services.headers({}))" in controller
    assert "xhr.send(file)" in controller
    assert "FormData" not in controller
    assert "256 * 1024 * 1024" in model
    assert "body.outcome === 'ok'" in model
    assert "body.outcome === 'already_running'" in model
    assert "body.outcome === 'fail'" in model
    assert "run.outcome.startsWith('fail: ')" in model


def test_success_message_css_wins_inside_and_outside_forms():
    css = _read("styles.css")
    assert css.index(".err.ok {") > css.rindex(".inline-form .err {")


def test_image_verification_controller_executes_race_and_result_contracts():
    import shutil
    import subprocess
    import pytest
    if not shutil.which("node"):
        pytest.skip("Node is required for the image verification controller tests")
    path = os.path.join(os.path.dirname(gui_server.WEBROOT), "console-ui",
                        "tests", "image-verification.test.mjs")
    result = subprocess.run(["node", "--test", path], capture_output=True,
                            text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


# --- Images page: verdict badges --------------------------------------------

def test_images_table_has_a_verification_column():
    component = _images_source("images.jsx")
    images_section = _slice(component, 'id="images">', "</table>")
    assert '<th scope="col">Verification</th>' in images_section


def test_verdict_badge_texts_match_the_binding_copy():
    """Task 7: the verdict badge became a status PILL (bulkhashVerdictBadge
    -> bulkhashVerdictPillHTML, levelPillHTML markup instead of .badge), but
    it still owes the same verdict text. MISMATCH went from all-caps to
    sentence case (Magnetic pill grammar: "sentence case ALL labels") --
    that is a deliberate copy change, not a regression."""
    js = _read("app.js")
    fn = js.split("function bulkhashVerdictPillHTML(hv, quarantined) {", 1)[1].split(
        "\n  }", 1)[0]
    assert "'Verified'" in fn
    assert "Mismatch — quarantined" in fn
    assert "Not in Cisco" in fn  # apostrophe escaped, don't pin the escaping style
    assert "'Not checked'" in fn
    assert "Deferred by Cisco" in fn


def test_null_verdict_state_reads_as_not_checked_not_hidden():
    js = _read("app.js")
    fn = js.split("function bulkhashVerdictPillHTML(hv, quarantined) {", 1)[1].split(
        "\n  }", 1)[0]
    assert "if (!state) {" in fn


def test_mismatch_badge_ternary_keys_off_the_live_quarantined_flag():
    """Regression guard: a mismatch verdict must only say "quarantined" while
    it actually still is (quarantined=true); an override-released mismatch
    (quarantined=false, hash_verification.state still "mismatch" forever --
    release_quarantine() never rewrites it) must say "released" instead, or
    the badge lies about still blocking something it no longer blocks. A
    regression that always renders "Mismatch — quarantined" regardless of
    the quarantined flag must fail this."""
    js = _read("app.js")
    fn = js.split("function bulkhashVerdictPillHTML(hv, quarantined) {", 1)[1].split(
        "\n  }", 1)[0]
    assert ("quarantined\n        ? levelPillHTML('negative', "
            "'Mismatch — quarantined')\n        : "
            "levelPillHTML('negative', 'Mismatch — released')") in fn


def test_not_in_feed_is_an_explicit_branch_with_a_neutral_unknown_fallback():
    """Regression guard: not_in_feed must be matched explicitly, not by a
    catch-all else -- a garbage/unrecognized state (a future bulkhash.py
    state this badge hasn't been taught, or corrupted data) must render as
    an admitted-unknown, not be silently mislabeled as the specific,
    plausible-sounding "Not in Cisco's feed" verdict it may not actually be."""
    js = _read("app.js")
    fn = js.split("function bulkhashVerdictPillHTML(hv, quarantined) {", 1)[1].split(
        "\n  }", 1)[0]
    assert "state === 'not_in_feed'" in fn
    assert "Unknown verification state" in fn
    # the not_in_feed branch and the neutral fallback are two DIFFERENT
    # branches, not the same string reused -- a regression that collapses
    # them back into one catch-all (dropping the explicit not_in_feed
    # check) must fail this
    assert fn.count("else if (state === 'not_in_feed')") == 1
    assert "Not in Cisco" not in fn.split("else if (state === 'not_in_feed')", 1)[0], \
        "the 'not in Cisco's feed' text must live in the not_in_feed branch, not earlier"


def test_deferral_warning_is_additive_to_whatever_state_is_shown():
    js = _read("app.js")
    fn = js.split("function bulkhashVerdictPillHTML(hv, quarantined) {", 1)[1].split(
        "\n  }", 1)[0]
    # the deferral branch appends to html rather than replacing it -- so it
    # can accompany verified/mismatch/not_in_feed alike
    assert "html +=" in fn
    assert "hv.deferral" in fn


def test_images_row_renders_the_pill_and_an_info_button():
    """The React-owned row keeps its verification pill and details action."""
    component = _images_source("images.jsx")
    assert "imageVerdicts(image.hash_verification, image.quarantined)" in component
    assert '<Verdict image={item} />' in component
    assert 'img-info' in component


# --- Image picker: quarantined ids visibly blocked --------------------------

def _picker_source(name):
    with open(os.path.join(os.path.dirname(gui_server.WEBROOT), "console-ui", "src", name)) as stream:
        return stream.read()


def test_picker_marks_quarantined_rows_with_a_badge():
    picker = _picker_source('assignments.jsx')
    assert "image.quarantined" in picker
    assert "quarantined</span>" in picker


def test_picker_disables_a_quarantined_id_only_when_not_already_assigned():
    """Blocks NEW selection (disabled + badge, per the brief) without
    trapping an operator who needs to uncheck an image that was assigned
    before it became quarantined -- that removal must stay possible."""
    picker = _picker_source('assignments-model.mjs')
    assert "quarantined: !!image?.quarantined" in picker
    assert "(!checked && (unknown || image?.quarantined || state.chosen.length >= 10))" in picker
    assert "data-blocked={image.quarantined ? '1' : undefined}" in _picker_source('assignments.jsx')
    # the pinned "unknown" disabling stays intact, untouched by this addition
    assert "const retained = unknown && state.original?.includes(id)" in picker


def test_picker_tags_every_quarantined_row_not_just_ones_blocked_at_render_time():
    """Regression: an already-CHECKED quarantined row (assigned before it
    became quarantined) must still carry data-blocked="1", even though it
    is not `disabled` at render time (the operator can uncheck it to remove
    the bad assignment). Gating data-blocked on the same render-time
    `blocked` expression as `disabled` -- true only while UNCHECKED -- was
    the actual bug: unchecking such a row produced a plain, undisabled
    checkbox indistinguishable from any other image, so it could be
    re-checked and Apply would POST the quarantined id right back in.
    `disabled` stays render-time (blocked && !unknown); `data-blocked`
    must be unconditional on `quarantined` alone, so updateCount's sweep
    (input:not(:checked) -> disabled) catches it the instant it is
    unchecked."""
    picker = _picker_source('assignments.jsx')
    assert "disabled={image.disabled}" in picker
    assert "data-blocked={image.quarantined ? '1' : undefined}" in picker
    # the regression this guards: data-blocked gated on `blocked` (render-
    # time-unchecked-only) instead of `quarantined` (every quarantined row)
    assert "blocked ? ' data-blocked" not in picker
    assert "blocked && !unknown ? ' disabled data-blocked" not in picker


def test_picker_cap_logic_never_re_enables_a_blocked_checkbox():
    """updateCount() re-evaluates every unchecked box's disabled state on
    every change (for the 10-image cap) -- it must never blanket-clear the
    quarantine block just because the count dropped, and it is what must
    disable a quarantined row the moment it is unchecked (see the
    render-time-tagging test above)."""
    picker = _picker_source('assignments-model.mjs')
    assert "(!checked && (unknown || image?.quarantined || state.chosen.length >= 10))" in picker
    assert "disabled: state.busy || !state.ready || !state.imagesOk || retained" in picker


def test_images_list_populates_the_quarantine_map_alongside_imageIds():
    js = _read("app.js")
    fn = js.split("publish: function (state, policyTicket) {", 1)[1].split(
        "selectionChanged: updateSelBar", 1)[0]
    assert "imageQuarantined[image.id] = !!image.quarantined" in fn
    assert "imageListOk = state.imagesOk" in fn


# --- Image detail drawer: release + typed-confirm override ------------------

def _images_source(name):
    with open(os.path.join(os.path.dirname(gui_server.WEBROOT), "console-ui", "src", name)) as stream:
        return stream.read()


def test_drawer_present_with_release_and_override_controls():
    component = _images_source("images.jsx")
    assert 'id="img-info-panel" className="drawer" hidden={!details} role="dialog"' in component
    for identifier in ("ii-release", "ii-confirm-text", "ii-release-override"):
        assert 'id="%s"' % identifier in component
    assert 'id="ii-override-block" hidden={!details?.override}' in component
    assert 'id="ii-release-block" hidden={!image.quarantined}' in component
    assert "onClick={() => controller.release(false)}" in component
    assert "onClick={() => controller.release(true)}" in component
    assert "details.confirmText !== image.filename" in component


def test_images_controller_executes_quarantine_upload_import_and_race_contracts():
    """Run behavior tests for the migrated workflow, not removed DOM strings."""
    import shutil
    import subprocess
    import pytest
    if not shutil.which("node"):
        pytest.skip("Node is required for the Images controller tests")
    path = os.path.join(os.path.dirname(gui_server.WEBROOT), "console-ui", "tests", "images-controller.test.mjs")
    result = subprocess.run(["node", "--test", path], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
