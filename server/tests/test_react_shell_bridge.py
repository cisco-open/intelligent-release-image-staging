# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Execute the real legacy client bridge without any React-owned DOM nodes."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest


APP = Path(__file__).resolve().parents[1] / "webroot" / "app.js"


def test_session_status_and_logout_bridge_preserves_csrf_and_idle_semantics():
    if not shutil.which("node"):
        pytest.skip("Node is required for the browser-client bridge test")
    prefix = APP.read_text().split("  function esc(s) {", 1)[0]
    script = r'''
const assert = require('node:assert/strict');
const events = [], calls = [], listeners = {};
global.CustomEvent = class { constructor(type, options) { this.type = type; this.detail = options.detail; } };
global.document = {addEventListener() {}};
global.window = {
  location: {href: ''},
  dispatchEvent(event) { events.push(event); },
  addEventListener(name, handler) { listeners[name] = handler; },
  async fetch(url, options) {
    calls.push({url, options});
    return {ok: true, status: 200, json: async () => ({username: 'operator', csrf: 'test-csrf'})};
  }
};
(async () => {
  await eval(PREFIX + `
    global.bridge = {markConnection, fetch, background: () => { backgroundPoll = true; }};
  } catch (e) { throw e; }
})();`);
  assert.deepEqual(events[0].detail, {username: 'operator'});
  assert.equal(events[0].type, 'iris:shell-state');
  bridge.markConnection(false);
  assert.match(events.at(-1).detail.connection, /Live data unavailable since .*last known state/);
  bridge.markConnection(true);
  assert.deepEqual(events.at(-1).detail, {connection: ''});
  bridge.background();
  await bridge.fetch('/api/v1/devices');
  assert.equal(calls.at(-1).options.headers.get('X-IRIS-Poll'), '1');
  await listeners['iris:logout']();
  assert.equal(calls.at(-1).url, '/api/v1/logout');
  assert.equal(calls.at(-1).options.method, 'POST');
  assert.equal(calls.at(-1).options.headers['X-CSRF-Token'], 'test-csrf');
  assert.equal(window.location.href, '/login.html');
  assert.ok(events.every(event => !('csrf' in event.detail)));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''.replace("PREFIX", json.dumps(prefix))
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_legacy_router_does_not_mutate_react_navigation():
    js = APP.read_text()
    for identifier in ("who", "logout", "help-btn", "nav-settings", "nav-monitoring", "nav-toggle"):
        assert "getElementById('%s')" % identifier not in js
    assert "getElementById('nav-'" not in js
    assert "getElementById('nav-settings-'" not in js
    assert "getElementById('nav-monitoring-'" not in js
    assert "setNavOpen" not in js
    assert "document.getElementById('view-' + v).hidden = v !== view" in js
    assert "window.addEventListener('hashchange'" in js
    assert js.count("setInterval(") == 1


def test_console_boots_local_react_before_legacy_workflows():
    html = APP.with_name("index.html").read_text()
    assert '<div id="iris-header-root"></div>' in html
    assert '<div id="iris-navigation-root"></div>' in html
    assert '<main class="main" id="iris-main-content" tabindex="-1">' in html
    assert '<script type="module" src="/assets/console.js"></script>' in html
    assert '<script src="/app.js">' not in html
    assert html.index('href="/styles.css"') < html.index('href="/assets/console.css"')
    for view in ("overview", "images", "devices", "swarm", "settings", "monitoring", "setup"):
        assert 'id="view-%s"' % view in html
