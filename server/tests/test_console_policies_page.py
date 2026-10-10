# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Policies routing, React ownership, and read races; no live server writes."""

from html.parser import HTMLParser
from pathlib import Path

from test_gui_server import _run_policies_node


WEBROOT = Path(__file__).resolve().parents[1] / "webroot"
SOURCE = WEBROOT.parent / "console-ui/src"


class ViewOwnership(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sections = []
        self.owners = {}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "section":
            self.sections.append(attrs.get("id"))
        if "id" in attrs:
            assert attrs["id"] not in self.owners, "duplicate DOM id"
            self.owners[attrs["id"]] = tuple(self.sections)

    def handle_endtag(self, tag):
        if tag == "section":
            self.sections.pop()


def test_policy_definitions_and_editor_belong_to_the_policies_page():
    parser = ViewOwnership()
    parser.feed((WEBROOT / "index.html").read_text())
    assert parser.owners["iris-policies-root"] == ("view-policies",)
    for element in ("iris-inventory-capability-root", "iris-inventory-root",
                    "iris-role-actions-root", "iris-inventory-selection-root"):
        assert "view-devices" in parser.owners[element], element
    assert parser.owners["iris-settings-navigation-root"] == ("view-settings",)
    dialogs = (SOURCE / "policy-dialogs.jsx").read_text()
    for element in ("peer-policy-panel", "role-def-new", "role-def-modal",
                    "role-def-rows", "role-def-save"):
        assert element not in parser.owners
        assert f'id="{element}"' in dialogs
    assert "<PolicyDialogs" in (SOURCE / "policies.jsx").read_text()


def test_policy_navigation_loads_once_without_recurring_form_refreshes():
    js = (WEBROOT / "app.js").read_text()
    shell = (SOURCE / "main.jsx").read_text()
    assert "['policies', 'Policies', 'list-checks']" in shell
    assert "else if (view === 'policies') { refreshPolicies(); }" in js
    assert "poll = refreshPolicies" not in js
    assert "if (view !== 'policies') {" in js
    assert "function cancelPolicyReads() { policies.hide(); }" in js
    assert "roleActions.hide(); policies.pause();" in js
    assert "function refreshPolicies() { return policies.refresh(); }" in js
    assert "setInterval" not in (SOURCE / "origin-enforcement.jsx").read_text()
    assert "closeModal('role-def-modal')" not in js
    assert "policyTicket === peerPolicyReadGeneration" in js.split(
        "publish: function (state, policyTicket) {", 1)[1].split(
            "selectionChanged: updateSelBar", 1)[0]


def test_expiry_choices_explain_transfer_settings_not_expiring_role_or_stop_timer():
    model = (SOURCE / "policy-definitions-model.mjs").read_text()
    for phrase in ("Follow the server setting", "Keep last verified settings",
                   "Use built-in device settings", "no upload or download speed limit",
                   "not your current role or server defaults", "Server-wide overrides"):
        assert phrase in model
    dialogs = (SOURCE / "policy-dialogs.jsx").read_text()
    for phrase in ("Each message has an expiry time", "before a valid replacement arrives",
                   "Transfers can continue with either choice",
                   "does not extend expired peer permissions"):
        assert phrase in dialogs
    assert 'aria-describedby="role-expiry-help role-expiry-choice role-expiry-scope"' in dialogs


def test_policy_reads_reject_late_bodies_hidden_routes_and_old_shared_tickets():
    _run_policies_node("policy reads are latest-only")


def test_editor_preserves_draft_and_blocks_writes_until_matching_definitions():
    _run_policies_node("existing editor holds|mismatched policy/definition")


def test_inventory_retains_the_same_fail_closed_warning():
    js = (WEBROOT / "app.js").read_text()
    assert "return policies.capability(peerPolicy, peerPolicyReadOk)" in js
    assert "roleCapabilityMessage: message" in js
    assert "inventory-role-capability-banner" not in js
    jsx = (SOURCE / "inventory.jsx").read_text()
    assert 'id="inventory-role-capability-banner" role="status" aria-live="polite"' in jsx
    assert "hidden={!state.roleCapabilityMessage}>{state.roleCapabilityMessage}</p>, capabilityRoot)" in jsx
    _run_policies_node("capability warnings")


def test_empty_inventory_role_picker_points_to_policies():
    controller = (SOURCE / "role-actions.jsx").read_text()
    assert "Open Policies and choose New role" in controller
