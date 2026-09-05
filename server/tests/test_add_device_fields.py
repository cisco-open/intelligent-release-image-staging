# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exercise the shipped Add Device controller without HTTP or npm packages."""
from pathlib import Path
import json
import re
import shutil
import subprocess

import pytest


APP = Path(__file__).resolve().parents[1] / "webroot" / "app.js"
HARNESS = r"""
const assert = require('node:assert/strict');
const nodes = {};
class Field {
  constructor(id) { this.id = id; this._value = ''; this.hidden = false;
    this.disabled = false; this.textContent = ''; this.listeners = {}; }
  get value() { return this._value; }
  set value(v) { this._value = this.options && !this.options.includes(v) ? '' : v; }
  set innerHTML(html) {
    this.options = Array.from(html.matchAll(/<option\b([^>]*)>/g)).map(m => {
      const value = /value="([^"]*)"/.exec(m[1]);
      return { value: value ? value[1] : '', selected: /\bselected\b/.test(m[1]) };
    });
    this._value = (this.options.find(o => o.selected) || this.options[0] || {}).value || '';
    this.options = this.options.map(o => o.value);
  }
  addEventListener(event, fn) { this.listeners[event] = fn; }
  async dispatch(event) { if (this.listeners[event]) await this.listeners[event].call(this); }
}
const document = { getElementById(id) {
  assert.ok(htmlIds.includes(id), 'controller refers to missing HTML control: ' + id);
  return nodes[id] || (nodes[id] = new Field(id));
} };
const AGENT_INSTALL_LABELS = {guestshell: 'Guest Shell', iox: 'IOx', router: 'Guest Shell', 'xr-appmgr': 'XR appmgr container'};
const esc = value => String(value);
const networkIds = ['df-vlan', 'df-svi', 'df-vpg', 'df-nat-interface', 'df-guest', 'df-mask', 'df-gateway'];
const visible = () => networkIds.filter(id => !document.getElementById(id).hidden);
let fetchImpl = async () => ({ok: true, json: async () => ({options: null})});
const fetch = (...args) => fetchImpl(...args);
const mgmt = document.getElementById('df-management-type');
const model = document.getElementById('df-model');
const platform = document.getElementById('df-platform');
platform.innerHTML = '<option value="" selected></option>' + Object.keys(AGENT_INSTALL_LABELS).map(k => '<option value="'+k+'"></option>').join('');
async function chooseManagement(value) { mgmt.value = value; await mgmt.dispatch('change'); }
async function typeModel(value, options) {
  fetchImpl = async () => ({ok: true, json: async () => ({options})});
  model.value = value; await model.dispatch('input');
}
"""


def run_controller(scenario):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node is required for the Add Device controller behavior tests")
    source = APP.read_text()
    html_ids = re.findall(r'\bid="([^"]+)"', APP.with_name("index.html").read_text())
    start = source.index("  var devForm = document.getElementById('dev-form');")
    end = source.index("  document.getElementById('add-dev').addEventListener", start)
    result = subprocess.run(
        [node], input="const htmlIds = " + json.dumps(html_ids) + ";\n" + HARNESS
        + source[start:end] + "\n(async () => {\n" + scenario
        + "\n})().catch(e => { console.error(e); process.exitCode = 1; });\n",
        text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_typing_or_clearing_xr_model_never_changes_management_or_network_fields():
    run_controller("""
      await chooseManagement('xr-host');
      for (const [value, options] of [['', null], ['8', null], ['80', null],
          ['800', ['xr-appmgr']], ['8000', ['xr-appmgr']], ['C3650', null]]) {
        await typeModel(value, options);
        assert.equal(mgmt.value, 'xr-host', 'model keystroke changed management type');
        assert.deepEqual(visible(), [], 'XR network fields reappeared');
        assert.equal(platform.value, 'xr-appmgr');
      }
    """)


@pytest.mark.parametrize("management, fields", [
    ("", []),
    ("xr-host", []),
    ("routed", ["df-vlan", "df-svi", "df-guest", "df-mask", "df-gateway"]),
    ("inband", ["df-vlan", "df-guest", "df-mask", "df-gateway"]),
    ("router-routed", ["df-vpg", "df-guest", "df-mask", "df-gateway"]),
    ("router-nat", ["df-vpg", "df-nat-interface", "df-guest", "df-mask", "df-gateway"]),
])
def test_management_type_alone_selects_the_network_fields(management, fields):
    run_controller("""
      await chooseManagement(%s);
      const expected = %s;
      assert.deepEqual(visible(), expected);
      await typeModel('8000', ['xr-appmgr']);
      assert.equal(mgmt.value, %s);
      assert.deepEqual(visible(), expected);
      await typeModel('C9300', ['guestshell', 'iox']);
      assert.equal(mgmt.value, %s);
      assert.deepEqual(visible(), expected);
      await platform.dispatch('change');
      assert.deepEqual(visible(), expected);
    """ % (json.dumps(management), json.dumps(fields), json.dumps(management), json.dumps(management)))


def test_model_lookup_failures_preserve_management_fields_and_selected_install():
    run_controller("""
      await chooseManagement('xr-host');
      model.value = '8000';
      for (const lookup of [
        async () => ({ok: false}),
        async () => { throw Error('offline'); },
        async () => ({ok: true, json: async () => { throw Error('bad JSON'); }})
      ]) {
        fetchImpl = lookup;
        await model.dispatch('input');
        assert.equal(mgmt.value, 'xr-host');
        assert.deepEqual(visible(), []);
        assert.equal(platform.value, 'xr-appmgr');
      }
    """)


def test_known_model_conflict_does_not_switch_management_or_offer_wrong_installer():
    run_controller("""
      await chooseManagement('routed');
      await typeModel('8000', ['xr-appmgr']);
      assert.equal(mgmt.value, 'routed');
      assert.equal(platform.value, '');
      assert.equal(platform.disabled, true);
      assert.match(document.getElementById('df-platform-hint').textContent, /management type/);
      await chooseManagement('xr-host');
      assert.equal(platform.value, 'xr-appmgr');
      assert.deepEqual(visible(), []);
    """)


def test_late_json_or_failed_lookup_cannot_replace_a_newer_choice():
    run_controller("""
      for (const fail of [false, true]) {
        model.value = ''; await chooseManagement('xr-host');
        let resolveOld, rejectOld;
        const oldJSON = new Promise((resolve, reject) => { resolveOld=resolve; rejectOld=reject; });
        fetchImpl = async () => ({ok: true, json: () => oldJSON});
        model.value = '8000';
        const oldRequest = model.dispatch('input');
        await Promise.resolve();
        model.value = ''; await chooseManagement('routed');
        await typeModel('C9300', ['guestshell', 'iox']);
        platform.value = 'iox';
        if (fail) rejectOld(Error('old lookup failed'));
        else resolveOld({options: ['xr-appmgr']});
        await oldRequest;
        assert.equal(mgmt.value, 'routed');
        assert.equal(platform.value, 'iox');
        assert.deepEqual(platform.options.filter(Boolean), ['guestshell', 'iox']);
      }
    """)
