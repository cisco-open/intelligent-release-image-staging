# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import base64
import hashlib
import http.server
import importlib.util
import os
from pathlib import Path
import ssl
import subprocess
import sys
import threading

import pytest

spec = importlib.util.spec_from_file_location("xr_https", Path(__file__).parents[2] / "xr_https.py")
xr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(xr)


@pytest.fixture
def https(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
        "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(key), "-out", str(cert),
        "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
        check=True, capture_output=True)
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Authorization"))
            if seen[-1] != "Basic " + base64.b64encode(b"edge-1:test-token").decode():
                self.send_error(401)
                return
            body = b"fixture RPM bytes"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
    thread.start()
    try:
        yield "https://localhost:%s" % server.server_port, cert.read_text(), seen
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


@pytest.mark.parametrize("failure", [None, "auth", "digest", "certificate"])
def test_real_https_download_fails_closed(tmp_path, https, failure):
    base, cert, seen = https
    token = "wrong" if failure == "auth" else "test-token"
    digest = hashlib.sha256(b"fixture RPM bytes").hexdigest()
    if failure == "digest":
        digest = "0" * 64
    if failure == "certificate":
        cert = "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"
    script = xr.remote_script(base, "edge-1", token, cert,
        [("staging/edge-1/iris-xr-fixture", "iris-xr.rpm", digest)])
    disk = tmp_path / "disk"
    disk.mkdir()
    destination = disk / "iris-xr.rpm"
    destination.write_bytes(b"previous")
    script = script.replace("/misc/disk1", str(disk))
    result = subprocess.run(["bash", "-s"], input=script, text=True,
                            capture_output=True, timeout=10)
    assert "test-token" not in result.stdout + result.stderr
    assert not list(disk.glob(".iris-https.*"))
    if failure:
        assert result.returncode != 0
        assert destination.read_bytes() == b"previous"
    else:
        assert result.returncode == 0, result.stderr
        assert destination.read_bytes() == b"fixture RPM bytes"
        assert (disk / "iris-catalog.pem").read_text() == cert
        assert seen


def test_snapshot_private_bound_immutable_and_removed(tmp_path):
    source = tmp_path / "rpm"
    source.write_bytes(b"rpm")
    with xr.publish(str(tmp_path), "edge-1", [(str(source), "iris-xr.rpm")]) as entries:
        relative, destination, digest = entries[0]
        path = tmp_path / relative
        assert path.stat().st_mode & 0o777 == 0o600
        source.write_bytes(b"changed")
        assert path.read_bytes() == b"rpm"
        assert digest == hashlib.sha256(b"rpm").hexdigest()
    assert not path.exists()


def test_snapshot_rejects_symlink_staging(tmp_path):
    (tmp_path / "staging").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError):
        with xr.publish(str(tmp_path), "edge-1", []):
            pass


@pytest.mark.parametrize("base", ["http://host", "https://user:token@host", "https://host/?secret=1", "https://host/\n"])
def test_artifact_origin_requires_safe_https(base):
    with pytest.raises(ValueError):
        xr.artifact_base({"CATALOG_URL": "https://host:8443", "IRIS_ARTIFACT_URL": base})


def test_ipv6_artifact_origin():
    assert xr.artifact_base({"CATALOG_URL": "https://[2001:db8::1]:8443"}) == "https://[2001:db8::1]:8000"


def test_dialogue_waits_for_echo_disabled_marker_and_redacts_output(tmp_path, capsys):
    fake = tmp_path / "ssh.py"
    fake.write_text('''import re,sys,base64
print("RP/0/RP0/CPU0:router#",end="",flush=True)
command=sys.stdin.readline()
assert "test-token" not in command
decoded=base64.b64decode(re.search(r"echo ([A-Za-z0-9+/=]+)",command).group(1)).decode()
ready=re.search(r"IRIS_READY_[a-f0-9]+",decoded).group()
done=re.search(r"IRIS_DONE_[a-f0-9]+:",decoded).group()
print(command,end="",flush=True)
print("\\n"+ready,flush=True)
assert sys.stdin.readline()=="test-token\\n"
print("test-token",flush=True) # malicious/unexpected remote echo
print(done+"0",flush=True)
print("RP/0/RP0/CPU0:router#",end="",flush=True)
assert sys.stdin.readline()=="exit\\n"
''')
    xr.transfer([sys.executable, str(fake)], "test-token\n", timeout=3)
    assert "test-token" not in capsys.readouterr().out


def test_stalled_ssh_has_a_deadline_and_is_reaped():
    with pytest.raises(RuntimeError, match="timed out"):
        xr.transfer([sys.executable, "-c", "import time; time.sleep(10)"],
                    "never send a credential\n", timeout=.1)
