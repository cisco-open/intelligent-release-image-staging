# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Policies routing, DOM ownership, and read races; no live server writes."""

from html.parser import HTMLParser
from pathlib import Path
import subprocess

from test_gui_server import _run_role_console_js


WEBROOT = Path(__file__).resolve().parents[1] / "webroot"


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
    html = (WEBROOT / "index.html").read_text()
    parser.feed(html)
    for element in ("role-capability-banner", "peer-policy-panel", "role-def-new",
                    "role-def-modal", "role-def-rows", "role-def-save"):
        assert "view-policies" in parser.owners[element], element
        assert "view-devices" not in parser.owners[element], element
    for element in ("inventory-role-capability-banner", "set-role-selected",
                    "role-modal", "apply-role-selected", "dev-filter-role"):
        assert "view-devices" in parser.owners[element], element
    assert parser.owners["iris-settings-navigation-root"] == ("view-settings",)
    assert 'class="policy-diagnostics"' in html


def test_policy_navigation_and_visible_poll_are_wired():
    js = (WEBROOT / "app.js").read_text()
    shell = (WEBROOT.parent / "console-ui/src/main.jsx").read_text()
    assert "['policies', 'Policies', 'list-checks']" in shell
    assert "else if (view === 'policies') { refreshPolicies(); poll = refreshPolicies; }" in js
    assert "if (view !== 'policies') {\n      cancelPolicyReads();" in js
    assert "closeModal('role-def-modal');" in js
    assert "policyMine === peerPolicyReadGeneration" in js.split(
        "async function refreshDevices() {", 1)[1].split(
            "// Populate the credential filter", 1)[0]


def _run_policy_reads(script):
    js = (WEBROOT / "app.js").read_text().split(
        "// ---- Policies view reads ----", 1)[1].split(
            "// ---- End Policies view reads ----", 1)[0]
    result = subprocess.run(["node", "-"], input=r'''
const assert = require('node:assert/strict');
const elements = new Map([
  ['view-policies', {hidden: false}], ['peer-policy-panel', {open: true}]
]);
const document = {getElementById: id => elements.get(id)};
let peerPolicyReadGeneration = 0, peerPolicyReadOk = false, peerPolicy = {};
let roleDefinitionsOk = false, roleDefinitionsRevision = null, roleDefBusy = false;
let roleDefinitionsGeneration = 0, roleDefinitionsController = null, roleDefinitionsLoading = false;
let renders = 0, loads = 0;
function renderPeerPolicyPanel() { renders++; }
async function loadRoleDefinitions() { loads++; }
let reads = [];
function fetch(url, options) {
  return new Promise((resolve, reject) => reads.push({url, options, resolve, reject}));
}
function reply(index, body, status = 200) {
  reads[index].resolve({ok: status < 400, status, json: async () => body});
}
''' + js + "\n(async () => {\n" + script + r'''
})().catch(error => { console.error(error); process.exit(1); });
''', text=True, capture_output=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr


def test_policy_reads_are_independent_and_latest_response_wins():
    _run_policy_reads(r'''
const first = refreshPolicies();
const second = refreshPolicies();
assert.equal(reads[0].options.signal.aborted, true);
assert.deepEqual(reads.map(read => read.url), ['/api/v1/peer-policy', '/api/v1/peer-policy']);
reply(1, {revision: 8, roles_supported: true});
await second;
reply(0, {revision: 7, roles_supported: true});
await first;
assert.equal(peerPolicy.revision, 8);
assert.equal(peerPolicyReadOk, true);
assert.equal(renders, 1);
assert.equal(loads, 1);
''')


def test_policy_route_leave_ignores_a_late_read_and_cancels_definitions():
    _run_policy_reads(r'''
roleDefinitionsController = new AbortController();
roleDefinitionsLoading = true;
const pending = refreshPolicies();
elements.get('view-policies').hidden = true;
cancelPolicyReads();
assert.equal(reads[0].options.signal.aborted, true);
assert.equal(roleDefinitionsController.signal.aborted, true);
assert.equal(roleDefinitionsLoading, false);
reply(0, {revision: 9});
await pending;
assert.equal(renders, 0);
assert.equal(loads, 0);
await refreshPolicies();
assert.equal(reads.length, 1, 'a hidden page does not keep polling');
''')


def test_new_inventory_read_supersedes_a_policy_read():
    _run_policy_reads(r'''
const pending = refreshPolicies();
peerPolicyReadGeneration++;
peerPolicy = {revision: 12};
reply(0, {revision: 11});
await pending;
assert.equal(peerPolicy.revision, 12);
assert.equal(renders, 0);
''')


def test_policy_read_failure_disables_writes_without_replacing_an_editor():
    _run_policy_reads(r'''
roleDefBusy = true;
peerPolicyReadOk = true;
peerPolicy = {revision: 12};
const pending = refreshPolicies();
reads[0].reject(new Error('Network unavailable'));
await pending;
assert.equal(peerPolicyReadOk, false);
assert.equal(peerPolicy.revision, 12);
assert.equal(renders, 1);
assert.equal(loads, 0, 'never replace definition data during an active write');
''')


def test_canceled_definition_read_cannot_overwrite_the_current_route():
    _run_role_console_js(r'''
roleDefinitions = {current: {peers: ['current']}};
roleDefinitionsRevision = 10;
roleDefinitionsOk = true;
let finish;
replies.push(() => new Promise(resolve => { finish = resolve; }));
const pending = loadRoleDefinitions();
roleDefinitionsGeneration++;
roleDefinitionsController.abort();
roleDefinitionsLoading = false;
finish({ok: true, status: 200, json: async () => ({revision: 9, roles: {stale: {}}})});
await pending;
assert.equal(roleDefinitionsRevision, 10);
assert.deepEqual(Object.keys(roleDefinitions), ['current']);
assert.equal(roleDefinitionsLoading, false);
''')


def test_inventory_retains_the_same_fail_closed_warning():
    _run_role_console_js(r'''
peerPolicyReadOk = false;
renderPeerPolicyPanel();
assert.equal(el('inventory-role-capability-banner').hidden, false);
assert.equal(el('inventory-role-capability-banner').textContent, el('role-capability-banner').textContent);
assert.equal(el('set-role-selected').disabled, true);
''')


def test_empty_inventory_role_picker_points_to_policies():
    _run_role_console_js(r'''
peerPolicy.roles = {members: {}};
await el('set-role-selected').listeners.click();
assert.match(el('role-modal-msg').textContent, /Open Policies and choose New role/);
''')
