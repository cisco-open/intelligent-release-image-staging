# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Run shipped Settings code against isolated, authenticated server state."""
import json
from pathlib import Path
import re
import subprocess

from test_gui_server import _serve_full_audit, _gui_cert_env, _gen_cert_pair, _trust_env


def test_shipped_settings_controller_against_authenticated_api(tmp_path, monkeypatch):
    _gui_cert_env(tmp_path, monkeypatch)
    (tmp_path / "settings-state").mkdir()
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "settings-state"))
    _trust_env(tmp_path, monkeypatch)
    certificate, key = _gen_cert_pair(tmp_path, "settings-fixture", "fixture")
    builtin = tmp_path / "builtin.pem"
    builtin.write_text(certificate + key)
    monkeypatch.setenv("IRIS_CERT", str(builtin))
    host, port, _, audit_path, stop = _serve_full_audit(tmp_path)
    module = Path(__file__).parents[1] / "console-ui/src/settings-controller.mjs"
    program = """
import assert from 'node:assert/strict';
import {SettingsController} from MODULE;
const origin = ORIGIN, certificate = CERTIFICATE, key = KEY;
const login = async password => {
  const r = await fetch(origin + '/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({username: 'admin', password})});
  assert.equal(r.status, 200); return {cookie: r.headers.get('set-cookie').split(';')[0], csrf: (await r.json()).csrf};
};
const auth = await login('pw'), other = await login('pw'), c = new SettingsController();
const writes = [];
c.connect({visible: () => true, confirm: () => true, setTimeout: () => 1, clearTimeout: () => {},
  headers: extra => ({...extra, 'X-CSRF-Token': auth.csrf}),
  fetch: async (path, options = {}) => {
    if (options.method) writes.push({path, body: options.body});
    return fetch(origin + path.replace('/api/v1/', '/api/'), {...options, headers: {...options.headers, Cookie: auth.cookie}});
  }});
const show = async pane => {c.select(pane); await c.refresh(); assert.equal(c.state.valid[pane], true, pane);};
const save = async (action, group = action, name) => {
  await c.perform(action, name); assert.equal(c.state.messages[group].kind, 'success', action + ': ' + c.state.messages[group].text);
};
await show('general'); await save('revoke');
assert.equal((await fetch(origin + '/api/session', {headers: {Cookie: other.cookie}})).status, 401);
c.field('pw', 'current', 'wrong'); c.field('pw', 'next', 'fixture-password-next'); c.field('pw', 'confirm', 'fixture-password-next');
await c.perform('pw'); assert.match(c.state.messages.pw.text, /Current password is incorrect/);
c.field('pw', 'current', 'pw'); c.field('pw', 'next', 'fixture-password-next'); c.field('pw', 'confirm', 'fixture-password-next');
await save('pw'); assert.equal(c.state.forms.pw.next, ''); await login('fixture-password-next');
await show('telemetry'); c.field('td', 'endpoint', 'https://collector.invalid:4318/'); c.field('td', 'enabled', true);
await save('td'); assert.equal(c.state.data.telemetry_destination.effective_endpoint, 'https://collector.invalid:4318');
await save('tdDefault', 'td'); assert.equal(c.state.data.telemetry_destination.source, 'env');
await show('audit');
for (const [key, value] of Object.entries({host: 'archive.invalid', user: 'fixture', path: '/exports', port: '2222', recipient: 'age1fixture', password: 'fixture-scp-password'})) c.field('ae', key, value);
await save('ae'); assert.equal(c.state.data.audit_export.password_set, true); assert.equal(c.state.forms.ae.password, '');
await save('ae'); assert.equal(c.state.data.audit_export.password_set, true, 'Blank password preserves stored secret');
await save('aeClear', 'ae'); assert.equal(c.state.data.audit_export.password_set, false);
await show('tls'); c.field('ca', 'source', 'mozilla'); c.field('ca', 'auto', true); await save('ca');
assert.equal(c.state.data.ca_trust.url, 'https://curl.se/ca/cacert.pem');
c.field('trust', 'pem', certificate); await save('trust'); assert.equal(c.state.data.trust.length, 1);
await save('trustDelete', 'trust', c.state.data.trust[0].name); assert.equal(c.state.data.trust.length, 0);
c.field('cert', 'pem', certificate); c.field('cert', 'key', key); await save('cert');
assert.match(c.state.messages.cert.text, /saved; restart/, 'Plain HTTP fixture cannot claim a TLS hot reload');
assert.equal(c.state.forms.cert.key, '');
assert.ok(writes.length >= 11);
console.log('Authenticated Settings controller round-trip passed');
""".replace("MODULE", json.dumps(module.as_uri())).replace(
        "ORIGIN", json.dumps(f"http://{host}:{port}")).replace(
        "CERTIFICATE", json.dumps(certificate)).replace("KEY", json.dumps(key))
    try:
        result = subprocess.run(["node", "--input-type=module"], input=program,
                                text=True, capture_output=True, timeout=40)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "round-trip passed" in result.stdout
        audit = Path(audit_path).read_text()
        for secret in ("fixture-password-next", "fixture-scp-password", key):
            assert secret not in audit
    finally:
        stop()


def test_shipped_settings_controller_regressions():
    tests = Path(__file__).parents[1] / "console-ui/tests/settings.test.mjs"
    result = subprocess.run(["node", "--test", "--test-reporter=tap", str(tests)], text=True,
                            capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert re.search(r"# pass [1-9][0-9]*", result.stdout)
