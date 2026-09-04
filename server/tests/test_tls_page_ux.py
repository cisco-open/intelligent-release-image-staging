# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Source guards for the TLS & trust page UX additions:
drag-and-drop onto the Certificate / Trusted CAs drop zones, and the CA
bundle source preset <select>. Client-side only — no backend surface change
— so these assert the markup/wiring stays intact rather than exercising a
server endpoint. Mirrors the open-the-webroot-file idiom in
test_gui_server.py."""
import os

import management_api as gui_server


def _read(name):
    with open(os.path.join(gui_server.WEBROOT, name)) as f:
        return f.read()


def _tls_pane(html):
    """Slice out the TLS & trust settings pane so assertions stay scoped to
    it and can't accidentally match an unrelated id elsewhere on the page."""
    return html.split('id="settings-pane-tls"', 1)[1].split('id="settings-pane-telemetry"', 1)[0]


def _tag_slice(container, start_marker, end_marker):
    """Everything from start_marker up to (not including) the next
    end_marker — used to scope attribute/content checks to one element."""
    return container.split(start_marker, 1)[1].split(end_marker, 1)[0]


def test_cert_dropzone_present_and_accessible():
    pane = _tls_pane(_read("index.html"))
    assert 'id="cert-dropzone"' in pane
    open_tag = _tag_slice(pane, 'id="cert-dropzone"', '>')
    assert 'tabindex="0"' in open_tag
    assert 'role="button"' in open_tag
    assert 'aria-label="' in open_tag
    zone = _tag_slice(pane, 'id="cert-dropzone"', '</div>')
    assert 'id="cert-dropzone-input"' in zone
    assert 'type="file"' in zone
    assert 'multiple' in zone
    assert 'hidden' in zone
    # Drop zone must precede the existing cert-form so it reads as "fills
    # the textareas below", and the existing paste-based form/endpoint must
    # remain — drag-and-drop is additive, not a replacement.
    assert pane.index('id="cert-dropzone"') < pane.index('id="cert-form"')
    assert 'id="cert-pem"' in pane and 'id="cert-key"' in pane


def test_trust_dropzone_present_and_accessible():
    pane = _tls_pane(_read("index.html"))
    assert 'id="trust-dropzone"' in pane
    open_tag = _tag_slice(pane, 'id="trust-dropzone"', '>')
    assert 'tabindex="0"' in open_tag
    assert 'role="button"' in open_tag
    assert 'aria-label="' in open_tag
    zone = _tag_slice(pane, 'id="trust-dropzone"', '</div>')
    assert 'id="trust-dropzone-input"' in zone
    assert 'type="file"' in zone
    assert 'multiple' in zone
    assert 'hidden' in zone
    # Sits between the trust table and the paste-based Add-CA form, which
    # stays present (drag-and-drop is additive here too).
    assert pane.index('id="trust-tbl"') < pane.index('id="trust-dropzone"') < pane.index('id="trust-form"')


def test_app_js_wires_both_dropzones():
    js = _read("app.js")
    for dropzone_id in ("cert-dropzone", "cert-dropzone-input", "trust-dropzone", "trust-dropzone-input"):
        assert ("'%s'" % dropzone_id) in js, "app.js does not reference #%s" % dropzone_id
    assert "function wireDropzone(" in js
    assert "addEventListener('drop'" in js
    assert "addEventListener('keydown'" in js, "drop zones must stay keyboard-openable (Enter/Space)"
    assert "classList.add('drag')" in js and "classList.remove('drag')" in js


def test_app_js_classifies_pem_by_content():
    """Recognition is by PEM block content, not filename/extension — the
    private-key regex from the design doc must be present verbatim, and a
    combined file (both blocks) must be able to fill both textareas."""
    js = _read("app.js")
    assert "-----BEGIN [A-Z ]*PRIVATE KEY-----" in js
    assert "-----BEGIN CERTIFICATE-----" in js
    assert "getElementById('cert-pem')" in js
    assert "getElementById('cert-key')" in js
    # No auto-submit from the drop handler: the existing Upload button (the
    # cert-form submit listener) must remain the only path to
    # /api/v1/settings/gui-cert from this section.
    drop_wiring = js.split("wireDropzone(document.getElementById('cert-dropzone')", 1)[1]
    drop_wiring = drop_wiring.split("document.getElementById('cert-form').addEventListener('submit'", 1)[0]
    assert "jpost('/api/v1/settings/gui-cert'" not in drop_wiring, \
        "drop handler must not itself call the gui-cert save endpoint"


def test_app_js_trust_drop_posts_sequentially_and_refreshes():
    js = _read("app.js")
    drop_wiring = js.split("wireDropzone(document.getElementById('trust-dropzone')", 1)[1]
    assert "/api/v1/settings/trust" in drop_wiring
    assert "refreshSettings()" in drop_wiring


def test_ca_source_select_present_with_three_presets():
    pane = _tls_pane(_read("index.html"))
    assert 'id="ca-source"' in pane
    select = _tag_slice(pane, 'id="ca-source"', '</select>')
    for value in ("cisco", "mozilla", "custom"):
        assert ('value="%s"' % value) in select, "missing ca-source option %r" % value
    assert "Cisco Trusted Root Store" in select
    assert "Mozilla CA bundle" in select
    assert "curl.se" in select
    assert "Custom URL" in select
    # The free-text URL input stays for the custom case but starts hidden —
    # a preset select without it would leave no way to enter a custom URL.
    assert 'id="ca-url"' in pane
    url_tag = _tag_slice(pane, 'id="ca-url"', '>')
    assert "hidden" in url_tag


def test_app_js_ca_source_uses_mozilla_url_and_reflects_stored_state():
    js = _read("app.js")
    assert "https://curl.se/ca/cacert.pem" in js
    assert "getElementById('ca-source')" in js
    # Save must still go through the one existing endpoint.
    assert "/api/v1/settings/ca-trust" in js
    # Selecting a preset must not bypass the Save button (no direct POST
    # wired to a 'change' listener on the select).
    change_wiring = js.split("getElementById('ca-source').addEventListener('change'", 1)[1].split(");\n", 1)[0]
    assert "/api/v1/settings/ca-trust" not in change_wiring


def test_no_inline_event_handlers_introduced():
    html = _read("index.html")
    assert "onclick=" not in html
    assert "onchange=" not in html
    assert "onsubmit=" not in html
