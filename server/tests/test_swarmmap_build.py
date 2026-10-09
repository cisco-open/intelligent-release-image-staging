# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Build and serving contracts for the standalone, nonced React map."""
import importlib.util
import json
from pathlib import Path
import re
import subprocess

import pytest

import gui_app
import gui_server
import management_api
from test_api_split import _certificate, _request, _thread, _write_secret
from test_gui_server import _MAP_FIXTURE, _auth, _req, _serve_reports


ROOT = Path(__file__).resolve().parents[2]
BUILD_INPUTS = (
    "server/console-ui/package.json", "server/console-ui/package-lock.json",
    "server/console-ui/vite.config.js", "server/console-ui/scripts/build-map.mjs",
    "server/console-ui/templates/swarmmap.html", "server/console-ui/src/swarm-map.jsx",
    "server/console-ui/src/swarm-map.css", "server/console-ui/src/swarm-map-graph.mjs",
    "server/console-ui/src/swarm-map-model.mjs", "server/console-ui/src/swarm-map-controller.mjs",
)


def test_default_map_is_generated_and_not_an_old_runnable_source():
    assert Path(management_api.SWARMMAP_PATH) == ROOT / "server/console-ui/dist/swarmmap.html"
    generated = Path(management_api.SWARMMAP_PATH)
    assert generated.is_file(), "Run npm ci && npm run build in server/console-ui before the serving tests"
    source = generated.read_text()
    assert source.count(management_api._MAP_PLACEHOLDER) == 1
    assert '<div id="iris-swarm-map-root"></div>' in source
    assert "Bundled third-party notices" in source


@pytest.mark.parametrize("contents", [None, b"\xff", b"incomplete build",
    _MAP_FIXTURE.replace(management_api._MAP_PLACEHOLDER, "").encode(),
    (_MAP_FIXTURE + '<script src="unexpected.js"></script>').encode(),
    _MAP_FIXTURE.replace("<style>", "<style nonce=old>").encode()])
def test_missing_or_invalid_build_is_authenticated_unavailable(tmp_path, monkeypatch, contents):
    target = tmp_path / "generated-map.html"
    if contents is not None:
        target.write_bytes(contents)
    monkeypatch.setattr(management_api, "SWARMMAP_PATH", str(target))
    host, port, _cat, stop = _serve_reports(tmp_path)
    try:
        assert _req(host, port, "GET", "/swarmmap")[0] == 401
        cookie, _csrf = _auth(host, port)
        status, headers, raw = _req(host, port, "GET", "/swarmmap", headers={"Cookie": cookie})
        assert status == 503
        assert headers["Content-Type"] == "application/problem+json"
        assert headers["Cache-Control"] == "no-store"
        body = json.loads(raw)
        assert body["code"] == "swarm-map-unavailable"
        assert body["detail"] == "Rebuild the server image."
        assert str(target).encode() not in raw
    finally:
        stop()


def test_generated_map_injects_safe_config_and_one_nonce_per_request(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_EVENTS_URL_TEMPLATE", 'https://events.example/device/{device_id}?note=</script><script>alert(1)</script>&ip={ip}')
    host, port, _cat, stop = _serve_reports(tmp_path)
    try:
        cookie, _csrf = _auth(host, port)
        nonces = []
        for _ in range(2):
            status, headers, raw = _req(host, port, "GET", "/swarmmap", headers={"Cookie": cookie})
            assert status == 200
            assert len(raw) > 65536, "Exercise the complete bundled page, not a tiny source fixture"
            body = raw.decode()
            nonce, = re.findall(r'<script nonce="([^"]+)">', body)
            nonces.append(nonce)
            assert body.count('<style nonce="%s">' % nonce) == 1
            assert management_api._MAP_PLACEHOLDER not in body
            assert '\\u003c/script\\u003e' in body
            assert body.count('</script>') == 1
            assert '"pull":true' in body and '"swarmUrl":"/api/v1/swarm"' in body
            assert headers["Cache-Control"] == "private, no-store"
            assert headers["X-Frame-Options"] == "SAMEORIGIN"
            assert headers["Content-Length"] == str(len(raw))
            assert headers["Content-Security-Policy"] == (
                "default-src 'self'; script-src 'nonce-%s'; style-src 'nonce-%s'; "
                "connect-src 'self'; img-src 'self'" % (nonce, nonce))
        assert nonces[0] != nonces[1]
    finally:
        stop()


def test_console_proxy_streams_complete_generated_map_and_preserves_nonce_policy(tmp_path, monkeypatch, request):
    cert, key = _certificate(tmp_path, "map-management")
    token = tmp_path / "tier-token"
    _write_secret(token, "t" * 64)
    app = gui_app.GuiApp(str(tmp_path / "map-secrets.json"))
    app.set_admin("admin", "pw")

    def start(server):
        thread = _thread(server)
        def stop():
            try:
                server.shutdown()
            finally:
                server.server_close()
                thread.join(timeout=3)
        request.addfinalizer(stop)
        return server.server_address[1]

    management_port = start(management_api.make_server(
        "127.0.0.1", 0, app, certfile=str(cert), keyfile=str(key), management_token_file=str(token)))
    monkeypatch.setenv("IRIS_GUI_ALLOW_PLAINTEXT", "1")
    console_port = start(gui_server.make_server(
        "127.0.0.1", 0, f"https://localhost:{management_port}", str(token), str(cert)))
    assert _request(console_port, "/swarmmap")[0] == 401
    status, headers, _ = _request(console_port, "/api/v1/login", method="POST",
        headers={"Content-Type": "application/json"}, body=json.dumps({"username": "admin", "password": "pw"}).encode())
    assert status == 200
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    status, headers, body = _request(console_port, "/swarmmap", headers={"Cookie": cookie})
    assert status == 200 and len(body) > 65536
    nonce, = re.findall(rb'<script nonce="([^"]+)">', body)
    source = Path(management_api.SWARMMAP_PATH).read_text()
    expected = source.replace(management_api._MAP_PLACEHOLDER, management_api._map_cfg_line())
    for tag in ("script", "style"):
        expected = expected.replace(f"<{tag}>", f'<{tag} nonce="{nonce.decode()}">')
    assert body == expected.encode()
    assert headers["Content-Length"] == str(len(body))
    assert headers["Cache-Control"] == "private, no-store"
    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert f"script-src 'nonce-{nonce.decode()}'" in headers["Content-Security-Policy"]
    assert "unsafe-inline" not in headers["Content-Security-Policy"]


def test_server_builds_map_without_shipping_node_or_stale_generated_inputs():
    source = (ROOT / "server/Dockerfile").read_text()
    builder, runtime = source.split("FROM python:3.12-slim-trixie", 1)
    stage = builder.split("AS swarm-map-build", 1)[1]
    assert "RUN npm ci --no-audit --no-fund" in stage
    assert "RUN npm run build:map" in stage
    for folder in ("src", "scripts", "templates"):
        assert f"COPY server/console-ui/{folder}/ ./{folder}/" in stage
    assert "COPY --from=swarm-map-build /build/console-ui/dist/swarmmap.html /opt/iris/server/console-ui/dist/swarmmap.html" in runtime
    assert "npm" not in runtime and "node_modules" not in runtime
    result = subprocess.run(["git", "check-ignore", "--no-index", "server/console-ui/dist/swarmmap.html"],
                            cwd=ROOT, text=True, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr
    assert not subprocess.check_output(["git", "ls-files", "server/console-ui/dist/"], cwd=ROOT)


def test_source_release_and_installer_retain_recursive_map_build_inputs():
    specification = importlib.util.spec_from_file_location("map_installer_package", ROOT / "tools/build-installer-package.py")
    packager = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(packager)
    for path in BUILD_INPUTS:
        assert (ROOT / path).is_file(), path
        assert packager.selected(path), path
    release = (ROOT / "tools/make-release.sh").read_text()
    assert re.search(r"^  server$", release, re.M)
    assert "git -C \"$REPO\" ls-files" in release
    workflow = (ROOT / ".github/workflows/tests.yml").read_text().split("  test:\n", 1)[1]
    assert workflow.index("npm ci --no-audit --no-fund") < workflow.index("npm run build:map") < workflow.index("- name: pytest")
