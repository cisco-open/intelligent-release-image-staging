# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""TLS forms have one React owner. Runtime regressions use shipped controllers."""
from pathlib import Path
import re
import subprocess

SOURCE = Path(__file__).parents[1] / "console-ui/src"
COMPONENT = (SOURCE / "settings.jsx").read_text()
MODEL = (SOURCE / "settings-model.mjs").read_text()
CONTROLLER = (SOURCE / "settings-controller.mjs").read_text()


def _runtime(pattern):
    tests = SOURCE.parent / "tests/settings.test.mjs"
    result = subprocess.run(["node", "--test", "--test-reporter=tap", "--test-name-pattern", pattern, str(tests)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert re.search(r"# pass [1-9][0-9]*", result.stdout)


def test_cert_dropzone_present_and_accessible():
    assert '<Dropzone id="cert-dropzone"' in COMPONENT
    assert "tabIndex={0} role=\"button\" aria-label={label}" in COMPONENT
    assert 'id={id + \'-input\'} ref={file} multiple hidden' in COMPONENT
    assert COMPONENT.index('id="cert-dropzone"') < COMPONENT.index("form('cert-form'")
    assert "'cert-pem', 'Certificate PEM" in COMPONENT
    assert "'cert-key', 'Private key PEM" in COMPONENT


def test_trust_dropzone_present_and_accessible():
    assert COMPONENT.index('id="trust-tbl"') < COMPONENT.index('id="trust-dropzone"') < COMPONENT.index("form('trust-form'")
    assert "onFiles={files => c.trustFiles(files)}" in COMPONENT
    assert "event.target.value = ''" in COMPONENT


def test_react_wires_both_dropzones():
    for event in ("onClick={choose}", "onKeyDown=", "onDragOver=", "onDragLeave=", "onDrop="):
        assert event in COMPONENT
    assert "event.key === 'Enter' || event.key === ' '" in COMPONENT
    assert "classList.add('drag')" in COMPONENT and "classList.remove('drag')" in COMPONENT
    for name in ("cert-dropzone", "trust-dropzone"):
        assert "getElementById('" + name + "')" not in (SOURCE.parents[1] / "webroot/app.js").read_text()


def test_file_classification_is_bounded_and_keeps_private_material_separate():
    _runtime("combined PEM|late file result|payloads enforce")
    method = CONTROLLER.split("async certificateFiles(", 1)[1].split("async trustFiles(", 1)[0]
    assert "pemFileFields(value)" in method
    assert "this.submit(" not in method and "this.perform(" not in method


def test_trust_drop_posts_sequentially_and_stops_after_uncertainty():
    _runtime("trust batch")
    assert "const result = await this.submit(request)" in CONTROLLER
    assert "if (this.visible()) await this.refresh()" in CONTROLLER


def test_ca_source_select_present_with_three_presets():
    select = COMPONENT.split('id="ca-source"', 1)[1].split("</select>", 1)[0]
    for value in ("cisco", "mozilla", "custom"):
        assert 'value="%s"' % value in select
    assert "Cisco Trusted Root Store" in select and "Mozilla CA bundle (curl.se)" in select
    assert "Custom URL" in select
    assert "hidden: f.ca.source !== 'custom'" in COMPONENT


def test_ca_source_uses_mozilla_url_and_preserves_unsaved_state():
    assert "https://curl.se/ca/cacert.pem" in MODEL
    assert "onChange={event => c.field('ca', 'source', event.target.value)}" in COMPONENT
    assert "path = 'ca-trust'" in MODEL
    _runtime("ca confirms|ca empty|starting and completing jobs")


def test_no_inline_event_handlers_or_html_injection_introduced():
    html = (SOURCE.parents[1] / "webroot/index.html").read_text()
    for handler in ("onclick=", "onchange=", "onsubmit="):
        assert handler not in html
    assert "dangerouslySetInnerHTML" not in COMPONENT
