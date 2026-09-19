#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Run inside a built device image with Python; needs no installer or pytest.

Example: docker run --rm --entrypoint python --network none \
  -v "$PWD/device/container/tests:/checks:ro" IMAGE /checks/check_runtime.py
"""

import importlib
import importlib.metadata
import importlib.util
import json
import pathlib
import platform
import shutil
import subprocess
import sysconfig
import tempfile
import threading
import unittest


def command(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=30, **kwargs)


class RuntimeSecurity(unittest.TestCase):
    def test_expat_version_and_both_xml_consumers(self):
        import pyexpat
        import _elementtree
        import xml.etree.ElementTree as etree
        from xml.dom import minidom

        self.assertGreaterEqual(pyexpat.version_info, (2, 8, 4))
        # ElementTree otherwise silently falls back to Python when the rebuilt
        # pyexpat C capsule is incompatible with the original C accelerator.
        self.assertIs(etree.XMLParser, _elementtree.XMLParser)
        xml = '<image name="staged">caf&#233;</image>'
        self.assertEqual(etree.fromstring(xml).text, "café")
        self.assertEqual(minidom.parseString(xml).documentElement.getAttribute("name"), "staged")
        with self.assertRaises(etree.ParseError):
            etree.fromstring("<image></broken>")

    def test_xz_package_and_python_compression(self):
        import lzma

        installed = command("apk", "--no-network", "list", "--installed", "xz-libs", text=True).stdout.strip()
        version = installed.split()[0].removeprefix("xz-libs-")
        self.assertIn(command("apk", "--no-network", "version", "-t", version, "5.8.4-r0", text=True).stdout.strip(), ("=", ">"))
        for fmt in (lzma.FORMAT_XZ, lzma.FORMAT_ALONE):
            data = b"IRIS staging runtime\n" * 100
            self.assertEqual(lzma.decompress(lzma.compress(data, format=fmt)), data)

    def test_installer_modules_and_metadata_absent(self):
        for name in ("pip", "ensurepip", "setuptools", "pkg_resources", "wheel"):
            self.assertIsNone(importlib.util.find_spec(name), name)
        names = {d.metadata["Name"].lower() for d in importlib.metadata.distributions()}
        self.assertFalse(names & {"pip", "setuptools", "wheel"}, names)

    def test_installer_files_absent(self):
        lib = pathlib.Path(sysconfig.get_path("stdlib"))
        forbidden = []
        for path in lib.rglob("*"):
            if path.name in ("pip", "ensurepip", "_vendor") or path.suffix == ".whl" or path.name.startswith("pip-"):
                forbidden.append(str(path))
        forbidden.extend(str(p) for p in pathlib.Path("/usr/local/bin").glob("pip*"))
        self.assertEqual(forbidden, [])

    def test_agent_modules_import(self):
        for name in ("iris_agent", "agent_config", "catalog_client", "cli_ssh", "flashcheck", "flash_target", "instr", "peer_tls", "runtime_verifier", "telemetry_report", "verify_image", "xr_deps"):
            with self.subTest(module=name):
                importlib.import_module(name)

    def test_stdlib_storage_and_hashing(self):
        import gzip
        import hashlib
        import sqlite3
        import tarfile
        import io

        payload = b"staged-image"
        self.assertEqual(gzip.decompress(gzip.compress(payload)), payload)
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tf:
            info = tarfile.TarInfo("image")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
        archive.seek(0)
        with tarfile.open(fileobj=archive, mode="r:gz") as tf:
            self.assertEqual(tf.extractfile("image").read(), payload)
        self.assertEqual(len(hashlib.sha512(payload).digest()), 64)
        with sqlite3.connect(":memory:") as db:
            self.assertEqual(db.execute("select 1").fetchone(), (1,))

    def test_https_verification(self):
        import http.server
        import ssl
        import urllib.request
        import urllib.error

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"verified")

            def log_message(self, *_args):
                pass

        with tempfile.TemporaryDirectory() as directory:
            cert, key = (str(pathlib.Path(directory) / name) for name in ("cert.pem", "key.pem"))
            command("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost", "-keyout", key, "-out", cert)
            with http.server.HTTPServer(("127.0.0.1", 0), Handler) as server:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert, key)
                server.socket = context.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    url = "https://localhost:%d/" % server.server_port
                    with urllib.request.urlopen(url, context=ssl.create_default_context(cafile=cert), timeout=10) as reply:
                        self.assertEqual(reply.read(), b"verified")
                    with self.assertRaises(urllib.error.URLError) as untrusted:
                        urllib.request.urlopen(url, context=ssl.create_default_context(), timeout=10)
                    self.assertIsInstance(untrusted.exception.reason, ssl.SSLCertVerificationError)
                finally:
                    server.shutdown()
                    thread.join(timeout=10)

    def test_ssh_signature_and_tools(self):
        for executable in ("ssh", "scp", "sshpass", "curl", "openssl", "ps", "top", "free", "kill"):
            self.assertIsNotNone(shutil.which(executable), executable)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            key, message, allowed = (root / name for name in ("key", "message", "allowed"))
            command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key))
            message.write_bytes(b"IRIS signed instruction")
            allowed.write_text("runtime " + (root / "key.pub").read_text())
            command("ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "iris", str(message))
            args = ("ssh-keygen", "-Y", "verify", "-f", str(allowed), "-I", "runtime", "-n", "iris", "-s", str(message) + ".sig")
            command(*args, input=message.read_bytes())
            with self.assertRaises(subprocess.CalledProcessError):
                command(*args, input=b"changed instruction")


if __name__ == "__main__":
    import pyexpat
    import ssl

    print(json.dumps({"architecture": platform.machine(), "python": platform.python_version(), "expat": pyexpat.EXPAT_VERSION, "openssl": ssl.OPENSSL_VERSION}), flush=True)
    unittest.main(verbosity=2)
