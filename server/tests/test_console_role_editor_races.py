# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Run the real role editor against controlled form and response races."""
import pytest

from test_gui_server import _run_role_console_js


@pytest.mark.parametrize("event", ["input", "change"])
def test_edit_while_preview_is_pending_requires_a_new_preview(event):
    _run_role_console_js(r'''
openRoleDefinitionEditor(null);
el('rd-name').value = 'boat';
el('rd-nets').value = '10.0.0.0/24';
let finishPreview;
replies.push(() => new Promise(resolve => { finishPreview = resolve; }));
const pending = el('role-def-save').listeners.click();
assert.equal(roleDefBusy, true);
el('rd-nets').value = '10.1.0.0/24';
el('role-def-modal').listeners.EVENT({target: {}});
finishPreview({ok: true, status: 200, json: async () => preview(), headers: {get: () => null}});
await pending;
assert.equal(roleDefPreview, null, 'the late response cannot approve a candidate that differs from the form');
assert.equal(el('role-def-preview').hidden, true);
assert.equal(el('role-def-save').textContent, 'Preview change');
assert.match(el('role-def-msg').textContent, /Preview again/);
reply(preview());
await el('role-def-save').listeners.click();
assert.equal(calls.length, 2);
assert.equal(calls[1].url, '/api/v1/peer-policy/roles/boat?dry_run=1');
assert.deepEqual(calls[1].body.nets, ['10.1.0.0/24']);
assert.equal(calls[1].body.confirm_token, undefined);
'''.replace("EVENT", event))


def test_existing_editor_keeps_its_read_revision_and_unedited_overlay():
    _run_role_console_js(r'''
roleDefinitions = {boat: {restricted: false, peers: ['boat'], origin: true,
  qos_state: {seeder: {numwant: 4}}}};
roleDefinitionsRevision = 7;
roleDefinitionsOk = true;
openRoleDefinitionEditor('boat');
peerPolicy.revision = 8;
roleDefinitions.boat.qos_state.seeder.numwant = 9;
roleDefinitions = {boat: {restricted: true, peers: ['boat'], origin: false,
  qos_state: {seeder: {numwant: 12}}}};
roleDefinitionsRevision = 8;
reply({code: 'revision_conflict', revision: 8}, 412);
await el('role-def-save').listeners.click();
assert.equal(calls[0].headers['If-Match'], '"iris-peer-policy-7"');
assert.deepEqual(calls[0].body.qos_state, {seeder: {numwant: 4}});
assert.equal(roleDefPreview, null);
assert.match(el('role-def-msg').textContent, /reopen/i);
openRoleDefinitionEditor('boat');
reply(preview());
await el('role-def-save').listeners.click();
assert.equal(calls[1].headers['If-Match'], '"iris-peer-policy-8"');
assert.equal(calls[1].body.restricted, true);
assert.equal(calls[1].body.origin, false);
assert.deepEqual(calls[1].body.qos_state, {seeder: {numwant: 12}});
''')


def test_existing_editor_refuses_an_unknown_definition_revision():
    _run_role_console_js(r'''
roleDefinitions = {boat: {restricted: false, peers: ['boat']}};
roleDefinitionsRevision = null;
roleDefinitionsOk = true;
openRoleDefinitionEditor('boat');
reply(preview());
await el('role-def-save').listeners.click();
assert.equal(calls.length, 0, 'the current policy revision cannot substitute for the unknown definition revision');
assert.match(el('role-def-msg').textContent, /revision unknown/i);
''')
