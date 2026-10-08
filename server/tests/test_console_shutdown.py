# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The Console must handle TERM itself, including when it is container PID 1."""
import http.client
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time

import pytest

import gui_server


SERVER = Path(gui_server.__file__).parent


def _environment(port):
    return dict(os.environ, IRIS_GUI_HOST="127.0.0.1", IRIS_GUI_PORT=str(port),
                IRIS_GUI_ALLOW_PLAINTEXT="1",
                IRIS_MANAGEMENT_API_URL="https://127.0.0.1:1",
                PYTHONPATH=str(SERVER))


def _stop(process):
    if process.poll() is None:
        process.kill()
    return process.communicate(timeout=5)


def _wait_file(path, process):
    deadline = time.monotonic() + 5
    while not path.exists():
        assert process.poll() is None, process.communicate(timeout=1)
        assert time.monotonic() < deadline
        time.sleep(0.01)


def test_console_script_handles_sigterm_and_exits_zero():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    process = subprocess.Popen([sys.executable, str(SERVER / "gui_server.py")],
                               env=_environment(port), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 5
        while True:
            assert process.poll() is None, process.communicate(timeout=1)
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.3)
            try:
                connection.request("GET", "/healthz")
                response = connection.getresponse()
                assert response.status == 200
                response.read()
                break
            except (ConnectionError, TimeoutError):
                assert time.monotonic() < deadline
                time.sleep(0.01)
            finally:
                connection.close()
        process.terminate()
        _, stderr = process.communicate(timeout=3)
        assert process.returncode == 0, stderr.decode()
    finally:
        _stop(process)


_MAIN_WITH_ACTIVE_PROXY = r'''
import pathlib, sys, time
import gui_server

root = pathlib.Path(sys.argv[1])
original = gui_server.make_server
def make(*args, **kwargs):
    server = original(*args, **kwargs)
    def proxy(handler):
        (root / 'active').write_text('proxy running')
        while not (root / 'release').exists():
            time.sleep(.01)
        (root / 'complete').write_text('proxy finished')
        handler._send(200, 'text/plain', b'complete')
    server.RequestHandlerClass._proxy = proxy
    (root / 'port').write_text(str(server.server_port))
    return server
gui_server.make_server = make
original_serve = gui_server.service_shutdown.serve
gui_server.service_shutdown.serve = lambda servers: original_serve(
    servers, timeout=float(sys.argv[2]))
sys.exit(gui_server.main())
'''


@pytest.mark.parametrize("method,complete", [("POST", True), ("FROB", True),
                                             ("POST", False)])
def test_console_main_drains_even_dynamic_proxy_methods(tmp_path, method, complete):
    process = subprocess.Popen(
        [sys.executable, "-c", _MAIN_WITH_ACTIVE_PROXY, str(tmp_path),
         "2" if complete else "0.2"], env=_environment(0),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    connection = None
    try:
        _wait_file(tmp_path / "port", process)
        port = int((tmp_path / "port").read_text())
        connection = socket.create_connection(("127.0.0.1", port), timeout=3)
        connection.sendall((method + " /api/fixture HTTP/1.0\r\n\r\n").encode())
        _wait_file(tmp_path / "active", process)
        process.terminate()
        if complete:
            time.sleep(0.15)
            assert process.poll() is None
            (tmp_path / "release").write_text("finish")
        _, stderr = process.communicate(timeout=5)
        assert process.returncode == (0 if complete else 1), stderr.decode()
        assert (tmp_path / "complete").exists() is complete
    finally:
        if connection is not None:
            connection.close()
        _stop(process)


def test_console_image_copies_complete_shutdown_import_closure(tmp_path):
    dockerfile = (SERVER / "Dockerfile.console").read_text().replace("\\\n", " ")
    files = []
    for line in dockerfile.splitlines():
        if line.startswith("COPY ") and line.endswith(" /opt/iris/server/"):
            files.extend(re.findall(r"server/[a-z_]+\.py", line))
    assert "server/service_shutdown.py" in files
    for relative in files:
        shutil.copyfile(SERVER.parent / relative, tmp_path / Path(relative).name)
    # Isolated mode excludes the repository and PYTHONPATH. Only modules copied
    # by the Console Dockerfile may satisfy its runtime imports.
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c",
         "import sys; sys.path.insert(0, sys.argv[1]); import gui_server", str(tmp_path)],
        capture_output=True, timeout=5)
    assert result.returncode == 0, result.stderr.decode()
