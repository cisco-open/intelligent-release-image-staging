# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Shipped certificate controller, native custody and bounded authenticated APIs."""
import http.client
import json
from pathlib import Path
import subprocess

import pytest

import certificate_lifecycle
import gui_server
import instruction_rotation
from test_instruction_rotation import custody
from test_instruction_keys import NOW, _stamp
from test_gui_server import _serve_full
from test_api_split import policy_tiers


def test_shipped_controller_with_real_age_openssh_and_authenticated_http(custody, tmp_path, monkeypatch):
    paths, roots = custody
    rotate = instruction_rotation.operate
    renew = certificate_lifecycle.renew
    monkeypatch.setattr(instruction_rotation, "operate", lambda body: rotate(body, paths=paths, now=NOW))
    monkeypatch.setattr(certificate_lifecycle, "renew", lambda body: renew(body, paths=paths, now=NOW))
    before = {path: Path(path).read_bytes() for path in (paths.epoch, str(Path(paths.instructions_dir) / "replay.fixture"))}
    host, port, _, stop = _serve_full(tmp_path)
    module = Path(__file__).parents[1] / "console-ui/src/certificates-controller.mjs"
    program = r"""
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import {randomUUID} from 'node:crypto';
import {CertificatesController} from MODULE;
const origin = ORIGIN, directory = DIRECTORY, root = ROOT, validity = VALIDITY;
const login = await fetch(origin + '/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({username: 'admin', password: 'pw'})});
assert.equal(login.status, 200);
const cookie = login.headers.get('set-cookie').split(';')[0], csrf = (await login.json()).csrf;
const c = new CertificatesController(), downloads = {}, writes = [];
c.connect({visible: () => true, uuid: randomUUID, confirm: () => true, formatDate: String,
  headers: extra => ({...extra, 'X-CSRF-Token': csrf}), download: (name, bytes) => {downloads[name] = bytes;},
  fetch: async (path, options = {}) => {
    if (options.method) writes.push({path, body: options.body});
    return fetch(origin + path.replace('/api/v1/', '/api/'), {...options, headers: {...options.headers, Cookie: cookie}});
  }});
const file = text => ({size: Buffer.byteLength(text), text: async () => text});
const approve = name => {
  const target = directory + '/' + name + '.pub'; fs.writeFileSync(target, downloads[name + '.pub']);
  execFileSync('ssh-keygen', ['-q', '-s', root, '-I', 'iris-online', '-n', 'iris-server', '-V', validity, target], {env: {...process.env, TZ: 'UTC'}, stdio: 'pipe'});
  return fs.readFileSync(directory + '/' + name + '-cert.pub', 'utf8');
};
await c.refreshAll(); assert.equal(c.state.valid.inventory, true); assert.equal(c.state.valid.signer, true);
await c.renewalRequest(); assert.ok(c.state.request); c.file('renew', file(approve('iris-online')));
await c.perform('renew'); assert.match(c.state.messages.renew.text, /Renewal applied/, c.state.messages.renew.text);
await c.perform('prepare'); assert.equal(c.state.signer.state, 'awaiting-approval', c.state.messages.signer.text);
const request = c.state.signer.request_id; c.downloadSigner(); c.file('activate', file(approve('iris-replacement')));
await c.perform('activate'); assert.equal(c.state.signer.state, 'retirement-pending', c.state.messages.signer.text);
await c.perform('retirement-request'); const payload = Buffer.from(downloads['keylist.payload']);
assert.ok(payload.toString().startsWith('IRIS-KEYLIST/1\n'));
const signature = execFileSync('ssh-keygen', ['-Y', 'sign', '-f', root, '-n', 'iris-keylist-v1'], {input: payload, stdio: ['pipe', 'pipe', 'pipe']});
c.file('retire', file(payload.toString() + signature.toString('base64') + '\n'));
await c.perform('retire'); assert.equal(c.state.signer.state, 'completed', c.state.messages.signer.text);
assert.equal(c.state.signer.request_id, request); assert.equal(c.state.signer.retired_keylist_seq, 1);
assert.ok(writes.every(row => !row.body.includes('PRIVATE KEY'))); assert.equal(writes.length, 6);
console.log('Shipped certificate controller: native renewal, preparation, approval, activation and retirement passed.');
""".replace("MODULE", json.dumps(module.as_uri())).replace("ORIGIN", json.dumps(f"http://{host}:{port}"))
    program = program.replace("DIRECTORY", json.dumps(str(tmp_path))).replace("ROOT", json.dumps(str(roots["root-a"]))).replace(
        "VALIDITY", json.dumps(_stamp(NOW) + ":" + _stamp(NOW + 30 * 86400)))
    try:
        result = subprocess.run(["node", "--input-type=module"], input=program, text=True, capture_output=True, timeout=45)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "retirement passed" in result.stdout
        for path, value in before.items():
            assert Path(path).read_bytes() == value
    finally:
        stop()


@pytest.mark.parametrize("tier", ["console", "management"])
@pytest.mark.parametrize("suffix", ["rotation", "renew"])
def test_signing_approval_transport_cap_is_scoped_authenticated_and_bounded(policy_tiers, monkeypatch, tier, suffix):
    request, _, _ = policy_tiers
    calls = []
    handler = lambda body: calls.append(body) or {"transport_probe": True}
    monkeypatch.setattr(instruction_rotation if suffix == "rotation" else certificate_lifecycle, "operate" if suffix == "rotation" else "renew", handler)
    endpoint = "/settings/certificates/instruction/" + suffix
    # Keep domain validation in its real tests; here capture the exact bytes
    # through both authenticated HTTP tiers, including base64-sized approvals.
    body = {"action": "retire", "artifact": "a" * (176 * 1024)}
    raw = json.dumps(body).encode()
    request_line = ("POST " + ("/internal/v1" if tier == "management" else "/api/v1")
                    + endpoint + " HTTP/1.1").encode()
    sent = []
    endheaders = http.client.HTTPConnection.endheaders

    def capture_endheaders(conn, message_body=None, *, encode_chunked=False):
        # Observe this client's real HTTP serialization, excluding the
        # Console's separate management authorization/forwarding requests.
        if conn._buffer[0] == request_line:
            length = next(value for value in conn._buffer
                          if value.startswith(b"Content-Length: "))
            sent.append((length, message_body))
        return endheaders(conn, message_body, encode_chunked=encode_chunked)

    monkeypatch.setattr(http.client.HTTPConnection, "endheaders", capture_endheaders)
    # The server rejects absent session credentials before reading the body.
    # Sending a large body concurrently races its legitimate TLS close and
    # can fail in SSL.write before this client gets to read the 401 response.
    # Announce the complete payload, withhold its bytes, and require a reply.
    assert request(tier, "POST", endpoint, authorized=False,
                   declared_length=len(raw), match=False)[0] == 401
    assert sent == [(b"Content-Length: " + str(len(raw)).encode(), None)]
    assert not calls
    status, _, result = request(tier, "POST", endpoint, raw, match=False)
    assert status == 200 and result["transport_probe"] and calls == [body]
    assert sent == [(b"Content-Length: " + str(len(raw)).encode(), None),
                    (b"Content-Length: " + str(len(raw)).encode(), raw)]
    assert request(tier, "POST", endpoint, declared_length=192 * 1024 + 1, match=False)[0] == 413
    assert len(calls) == 1
    assert request(tier, "POST", "/settings/certificates/instruction/request", declared_length=64 * 1024 + 1, match=False)[0] == 413


def test_certificate_ownership_and_proxy_limits():
    server = Path(__file__).parents[1]
    html = (server / "webroot/index.html").read_text()
    app = (server / "webroot/app.js").read_text()
    component = (server / "console-ui/src/certificates.jsx").read_text()
    for name in ("inventory", "renewal", "signer"):
        assert f'id="iris-certificates-{name}"' in html
    for name in ("certificate-rows", "certificate-renew-form", "rotation-prepare", "rotation-certificate"):
        assert f'id="{name}"' not in html
        assert f"getElementById('{name}')" not in app
    assert 'id="certificate-renew-form"' in component
    assert "window.irisCertificates" in app and "certificates.hide()" in app
    assert "function rotateSigner" not in app
    for suffix in ("rotation", "renew"):
        assert gui_server._body_limit("/internal/v1/settings/certificates/instruction/" + suffix) == 192 * 1024
    assert gui_server._body_limit("/internal/v1/settings/certificates/instruction/request") == 64 * 1024
    assert gui_server._body_limit("/internal/v1/settings/certificates/browser/rotation") == 128 * 1024
    assert gui_server._body_limit("/internal/v1/settings/service-credentials") == 64 * 1024


def test_shipped_certificate_controller_regressions():
    suite = Path(__file__).parents[1] / "console-ui/tests/certificates.test.mjs"
    result = subprocess.run(["node", "--test", str(suite)], text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
