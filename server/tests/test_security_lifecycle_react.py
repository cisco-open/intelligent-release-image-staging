# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shipped lifecycle controller against native crypto, HTTP and consumers."""
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import ssl
import subprocess
import sys
import threading

import pytest

import gui_server
import secrets_store
import telemetry
import tls_rotation
from test_api_split import _certificate, policy_tiers
from test_gui_server import _serve_full
from test_service_credentials import store
from test_tls_rotation import environment


def test_shipped_lifecycle_with_real_crypto_authenticated_http_and_consumers(store, environment, monkeypatch):
    old = environment / "mounted-token"
    old.write_text("a" * 64)
    old.chmod(0o600)
    monkeypatch.setenv("IRIS_OBSERVABILITY_TOKEN_FILE", str(old))
    metrics = telemetry.make_metrics_server("127.0.0.1", 0, lambda: "fixture_metric 1\n",
        observability_token_file=str(old))
    cert, key = _certificate(environment, "collector")
    delivered = []

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            valid = self.headers.get("Authorization") == "Bearer fixture-only"
            if valid:
                delivered.append(self.path)
            self.send_response(200 if valid else 401)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    collector = HTTPServer(("127.0.0.1", 0), Collector)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    collector.socket = context.wrap_socket(collector.socket, server_side=True)
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in (metrics, collector)]
    for thread in threads:
        thread.start()
    host, port, _, stop = _serve_full(environment)
    server = Path(__file__).parents[1]
    config = dict(origin=f"http://{host}:{port}", directory=str(environment), python=sys.executable,
        server=str(server), ca=str(cert), metrics=f"http://127.0.0.1:{metrics.server_port}/metrics",
        collector=f"https://127.0.0.1:{collector.server_port}")
    program = r'''
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {randomUUID} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import {SecurityLifecycleController} from MODULE;
const config = CONFIG;
const login = await fetch(config.origin + '/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username: 'admin', password: 'pw'})});
assert.equal(login.status, 200);
const cookie = login.headers.get('set-cookie').split(';')[0], csrf = (await login.json()).csrf;
const c = new SecurityLifecycleController(), downloads = {}, writes = [];
c.connect({visible: () => true, uuid: randomUUID, confirm: () => true, formatDate: String, hostname: 'console.example',
  randomToken: () => 'b'.repeat(64), headers: extra => ({...extra, 'X-CSRF-Token': csrf}),
  download: (name, bytes) => {downloads[name] = bytes;},
  fetch: async (path, options = {}) => {
    if (options.method) writes.push(JSON.parse(options.body));
    return fetch(config.origin + path.replace('/api/v1/', '/api/'), {...options, headers: {...options.headers, Cookie: cookie}});
  }});
await c.refreshAll(); assert.equal(c.state.valid.tls, true); assert.equal(c.state.valid.credentials, true);
c.field('names', 'console.example, 127.0.0.1, 2001:db8::1');
await c.perform('tls', 'prepare'); assert.equal(c.state.tls.state, 'awaiting-approval', c.state.messages.tls.text);
c.download('csr'); const directory = config.directory;
fs.writeFileSync(directory + '/approval.csr', downloads['iris-console.csr']);
execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-subj', '/CN=Fixture CA', '-keyout', directory + '/approval.key', '-out', directory + '/approval.crt', '-days', '365'], {stdio: 'pipe'});
const leaf = execFileSync('openssl', ['x509', '-req', '-in', directory + '/approval.csr', '-CA', directory + '/approval.crt', '-CAkey', directory + '/approval.key', '-set_serial', '17', '-days', '90', '-copy_extensions', 'copyall'], {encoding: 'utf8', stdio: 'pipe'});
const approval = leaf + fs.readFileSync(directory + '/approval.crt', 'utf8');
c.file({size: Buffer.byteLength(approval), text: async () => approval});
await c.perform('tls', 'approve'); assert.equal(c.state.tls.state, 'approved', c.state.messages.tls.text);
c.download('certificate'); assert.equal(downloads['iris-console.crt'], approval);
await c.perform('tls', 'apply'); assert.equal(c.state.tls.state, 'published', c.state.messages.tls.text);
assert.match(c.state.messages.tls.text, /has not confirmed reload/, 'HTTP-only fixture must not claim TLS reload');
await c.perform('tls', 'apply'); assert.match(c.state.messages.tls.text, /has not confirmed reload/);
c.field('mode', 'self-signed'); await c.perform('tls', 'prepare');
assert.equal(c.state.tls.state, 'approved', c.state.messages.tls.text);
await c.perform('tls', 'cancel'); assert.equal(c.state.tls.state, 'cancelled');
c.generateToken(); c.download('token'); assert.equal(downloads['iris-metrics-token'], 'b'.repeat(64) + '\n');
await c.perform('credentials', 'replace'); assert.match(c.state.messages['metrics-token'].text, /Replacement saved/);
assert.equal(c.state.token, ''); assert.equal(c.canCredential('retire'), false);
const scrape = async token => {const response = await fetch(config.metrics, {headers: {Authorization: 'Bearer ' + token}}); await response.text(); return response.status;};
assert.equal(await scrape('a'.repeat(64)), 200); await c.refresh('credentials', true); assert.equal(c.canCredential('retire'), false);
assert.equal(await scrape('b'.repeat(64)), 200);
for (let i = 0; i < 30 && !c.canCredential('retire'); i++) {await c.refresh('credentials', true); if (!c.canCredential('retire')) await new Promise(resolve => setTimeout(resolve, 20));}
assert.equal(c.canCredential('retire'), true);
await c.perform('credentials', 'retire'); assert.equal(c.item().state, 'completed', c.state.messages['metrics-token'].text);
assert.equal(await scrape('a'.repeat(64)), 401); assert.equal(await scrape('b'.repeat(64)), 200);
c.field('token', 'c'.repeat(64)); await c.perform('credentials', 'replace');
await c.perform('credentials', 'revert'); assert.equal(c.item().state, 'reverted', c.state.messages['metrics-token'].text);
assert.equal(await scrape('c'.repeat(64)), 401); assert.equal(await scrape('b'.repeat(64)), 200);
c.family('collector-headers'); c.field('endpoint', config.collector); c.header(c.state.headers[0].id, 'value', 'Bearer fixture-only');
await c.perform('credentials', 'replace'); assert.match(c.state.messages['collector-headers'].text, /Replacement saved/);
assert.equal(c.canCredential('retire'), false); assert.equal(c.state.headers[0].value, '');
// Use the actual IRIS OTLP transport with an explicitly trusted local CA.
// It reads the encrypted-store override and records only successful delivery.
const transport = `import ssl, sys, otlp, service_credentials\notlp.trust.ssl_context = lambda: ssl.create_default_context(cafile=sys.argv[2])\nheaders, _ = service_credentials.collector_headers(sys.argv[1], {})\notlp._http_post(sys.argv[1] + '/v1/logs', b'{}', headers=headers)\n`;
execFileSync(config.python, ['-c', transport, config.collector, config.ca], {cwd: config.server, stdio: 'pipe'});
await c.refresh('credentials', true); assert.equal(c.canCredential('retire'), true);
await c.perform('credentials', 'retire'); assert.equal(c.item().state, 'completed', c.state.messages['collector-headers'].text);
c.field('endpoint', 'https://other.example'); c.header(c.state.headers[0].id, 'value', 'second-fixture');
await c.perform('credentials', 'replace'); await c.perform('credentials', 'revert');
assert.equal(c.item().state, 'reverted', c.state.messages['collector-headers'].text); assert.equal(c.item().endpoint, config.collector);
execFileSync(config.python, ['-c', transport, config.collector, config.ca], {cwd: config.server, stdio: 'pipe'});
assert.ok(writes.every(body => !JSON.stringify(body).includes('PRIVATE KEY')));
assert.deepEqual(c.pending, {}); assert.equal(writes.length, 14);
console.log('Native TLS approvals, encrypted credentials, metrics overlap and verified collector delivery passed.');
'''.replace("MODULE", json.dumps((server / "console-ui/src/security-lifecycle-controller.mjs").as_uri())).replace("CONFIG", json.dumps(config))
    try:
        result = subprocess.run(["node", "--input-type=module"], input=program, text=True, capture_output=True, timeout=60)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "verified collector delivery passed" in result.stdout
        assert delivered == ["/v1/logs", "/v1/logs"]
        assert old.read_text() == "a" * 64
        plain = subprocess.check_output(["age", "-d", "-i", os.environ["IRIS_AGE_KEY_FILE"], str(store[1])])
        assert json.loads(plain) == secrets_store.load(str(store[0]))
    finally:
        stop()
        for listener, thread in zip((metrics, collector), threads):
            listener.shutdown()
            listener.server_close()
            thread.join(5)


@pytest.mark.parametrize("tier", ["console", "management"])
def test_browser_approval_transport_cap_is_scoped_authenticated_and_bounded(policy_tiers, monkeypatch, tier):
    request, _, _ = policy_tiers
    calls = []
    monkeypatch.setattr(tls_rotation, "operate", lambda body: calls.append(body) or {"transport_probe": True})
    endpoint = "/settings/certificates/browser/rotation"
    body = {"action": "approve", "certificate": "a\n" * 32760}
    assert request(tier, "POST", endpoint, body, authorized=False, match=False)[0] == 401
    assert not calls
    status, _, result = request(tier, "POST", endpoint, body, match=False)
    assert status == 200 and result["transport_probe"] and calls == [body]
    assert request(tier, "POST", endpoint, declared_length=128 * 1024 + 1, match=False)[0] == 413
    assert request(tier, "POST", "/settings/service-credentials", declared_length=64 * 1024 + 1, match=False)[0] == 413
    assert len(calls) == 1


def test_security_lifecycle_has_single_react_owner_and_scoped_limits():
    server = Path(__file__).parents[1]
    html = (server / "webroot/index.html").read_text()
    app = (server / "webroot/app.js").read_text()
    component = (server / "console-ui/src/security-lifecycle.jsx").read_text()
    for name in ("security-lifecycle-root", "browser-tls", "service-credentials"):
        assert f'id="iris-{name}"' in html
    for name in ("browser-tls-prepare-form", "service-credential-family", "service-credential-token"):
        assert f'id="{name}"' not in html
        assert f'id="{name}"' in component
        assert f"getElementById('{name}')" not in app
    assert "window.irisSecurityLifecycle" in app and "securityLifecycle.hide()" in app
    assert "function browserTlsAction" not in app and "function changeServiceCredential" not in app
    assert gui_server._body_limit("/internal/v1/settings/certificates/browser/rotation") == 128 * 1024
    assert gui_server._body_limit("/internal/v1/settings/service-credentials") == 64 * 1024


def test_shipped_security_lifecycle_controller_regressions():
    suite = Path(__file__).parents[1] / "console-ui/tests/security-lifecycle.test.mjs"
    result = subprocess.run(["node", "--test", str(suite)], text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
