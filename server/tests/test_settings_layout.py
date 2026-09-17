# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Source contracts for the incremental Settings layout; not API integration tests."""

import json
from pathlib import Path
import re


SERVER = Path(__file__).resolve().parents[1]
UI = SERVER / "console-ui"
HTML = (SERVER / "webroot/index.html").read_text()
APP = (SERVER / "webroot/app.js").read_text()
NAV = (UI / "src/settings-navigation.jsx").read_text()
SHELL = (UI / "src/main.jsx").read_text()
CSS = (UI / "src/shell.css").read_text()
SECTIONS = {"general", "tls", "telemetry", "bulkhash", "packages", "audit", "setup"}


def test_settings_navigation_targets_all_existing_panes():
    navigation_sections = re.search(r"const sections = \[(.*?)\n\];", NAV, re.S).group(1)
    section_ids = re.findall(r"\['([^']+)'", navigation_sections)
    assert len(section_ids) == len(SECTIONS)
    assert set(section_ids) == SECTIONS
    initial_routes = re.search(r"var SETTINGS_SUBS = \[(.*?)\];", APP).group(1)
    legacy_routes = set(re.findall(r"'([^']+)'", initial_routes))
    legacy_routes.update(re.findall(r"SETTINGS_SUBS\.push\('([^']+)'\)", APP))
    assert legacy_routes == SECTIONS
    assert set(re.findall(r'id="settings-pane-([^\"]+)"', HTML)) == SECTIONS
    assert 'href={`#settings/${id}`}' in NAV
    assert 'aria-label="Settings sections"' in NAV
    assert "aria-current={id === active[0] ? 'page' : undefined}" in NAV
    assert "window.addEventListener('hashchange', update)" in NAV
    assert "window.removeEventListener('hashchange', update)" in NAV


def test_settings_navigation_mount_does_not_own_legacy_forms():
    assert HTML.count('<div id="iris-settings-navigation-root"></div>') == 1
    assert HTML.index('id="view-settings"') < HTML.index('id="iris-settings-navigation-root"')
    assert HTML.index('id="iris-settings-navigation-root"') < HTML.index('id="settings-pane-setup"')
    assert "import { mountSettingsNavigation } from './settings-navigation.jsx';" in SHELL
    assert "mountSettingsNavigation();" in SHELL
    assert "document.getElementById('iris-settings-navigation-root')" in NAV
    assert "createRoot(root).render(<SettingsNavigation />)" in NAV
    assert "<form" not in NAV
    assert "fetch(" not in NAV


def test_checkbox_sizing_is_native_and_excludes_text_controls():
    selector = '.iris-react-shell input[type="checkbox"]'
    rule = re.search(re.escape(selector) + r"\s*\{([^}]+)\}", CSS).group(1)
    declarations = dict(re.findall(r"([\w-]+)\s*:\s*([^;]+);", rule))
    assert declarations["appearance"] == "auto"
    for dimension in ("width", "height", "min-width", "max-width", "min-height"):
        assert declarations[dimension] == "16px"
    assert declarations["padding"] == "0"
    assert declarations["flex"] == "0 0 16px"
    assert f"{selector}:focus-visible" in CSS
    assert f"{selector}:disabled" in CSS
    assert '.tbl :is(th,td):has(> input[type="checkbox"])' in CSS
    assert '.inline-form :is(input:not([type="checkbox"]),select,textarea)' in CSS
    assert not re.search(r"\.iris-react-shell\s+input\s*\{", CSS)


def test_settings_form_ids_and_submit_handlers_remain_intact():
    for form_id in ("pw-form", "cert-form", "trust-form", "ca-form", "td-form", "ae-form", "iv-schedule-form"):
        assert len(re.findall(r'<form\b[^>]*\bid="' + form_id + r'"', HTML)) == 1
        assert f"document.getElementById('{form_id}').addEventListener('submit'" in APP
    for control_id in (
        "pw-cur", "pw-new", "pw-confirm", "revoke-others", "cert-pem", "cert-key",
        "cert-passphrase", "cert-passphrase-row", "trust-pem", "ca-url", "ca-auto",
        "td-enabled", "td-endpoint", "ae-recipient", "ae-pass", "ae-auto", "iv-mode", "iv-hour",
    ):
        assert HTML.count(f'id="{control_id}"') == 1
        assert f"'{control_id}'" in APP
    assert '.inline-form:not([hidden])' in CSS
    assert '.inline-form .field[hidden]' in CSS
    assert '.inline-form .field:has(> [hidden])' in CSS


def test_settings_navigation_adds_no_internal_ui_dependencies():
    manifest = json.loads((UI / "package.json").read_text())
    assert set(manifest["dependencies"]) == {"react", "react-dom"}
    assert not re.search(r"@(?:harbor|magnetic)(?:/|\b)|\bhbr[-A-Z]|\bagentinfo\b", NAV, re.I)
    imports = re.findall(r"\bfrom\s*['\"]([^'\"]+)['\"]", NAV)
    assert imports
    assert all(item in {"react", "react-dom/client"} or item.startswith("./") for item in imports)
