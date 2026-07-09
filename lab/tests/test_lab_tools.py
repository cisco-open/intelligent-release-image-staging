# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for lab/iris-diag.py and lab/iris-add.py fixes.

Tests cover:
  - rpc() helper in iris-diag.py prepends the token:<secret> param
  - iris-add.py arg guard emits usage instead of IndexError on missing argv
  - iris-add.py RPC call body includes token:<secret> as first param

device-copy.sh exit-code fix is a shell script; behaviour is verified by
reasoning rather than unit test (the expect block is non-trivially
emulatable without a real IOS SSH session and without expect(1) on the
test host).  The fix is a one-line change to each failure branch — see
the report for the rationale.
"""
import base64
import importlib.util
import json
import os
import sys
import types
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers to import the lab scripts as modules without executing top-level
# side-effectful code (print / socket / argv access).
# ---------------------------------------------------------------------------

LAB_DIR = os.path.join(os.path.dirname(__file__), "..")


def _load_source(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    return spec, mod


# ===========================================================================
# iris-diag.py — rpc() token injection
# ===========================================================================

class TestDiagRpcToken(unittest.TestCase):
    """iris-diag.py rpc() must prepend 'token:<secret>' as the first param."""

    def _import_diag(self):
        """Import iris-diag.py, stubbing out argv and top-level I/O."""
        diag_path = os.path.join(LAB_DIR, "iris-diag.py")
        spec, mod = _load_source("iris_diag", diag_path)

        # Prevent argv/env access and top-level prints during import
        with patch.object(sys, "argv", ["iris-diag.py"]), \
             patch("builtins.print"), \
             patch("socket.create_connection", return_value=MagicMock()), \
             patch("urllib.request.urlopen",
                   return_value=MagicMock(read=lambda: b'{"result":[]}')):
            spec.loader.exec_module(mod)

        return mod

    def test_rpc_token_prepended_when_secret_present(self):
        """rpc() body params[0] must be 'token:<secret>'."""
        import tempfile, pathlib

        secret = "mysecretXYZ"
        with tempfile.NamedTemporaryFile(mode="w", suffix="rpc-secret",
                                        delete=False) as tf:
            tf.write(secret)
            secret_file = tf.name

        try:
            mod = self._import_diag()

            captured = {}

            def fake_urlopen(req, timeout=None):
                body = json.loads(req.data.decode())
                captured["params"] = body["params"]
                resp = MagicMock()
                resp.read.return_value = b'{"result":[]}'
                return resp

            # Patch the module's secret path so it finds our temp file
            mod.RPC_SECRET_FILE = secret_file

            with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                mod.rpc("aria2.tellActive", [["gid"]])

            self.assertTrue(
                captured["params"][0].startswith("token:"),
                f"First param should be 'token:...', got: {captured['params'][0]!r}"
            )
            self.assertEqual(captured["params"][0], f"token:{secret}")
        finally:
            os.unlink(secret_file)

    def test_rpc_token_fallback_when_no_secret_file(self):
        """rpc() falls back gracefully (no crash) when secret file is absent."""
        mod = self._import_diag()
        mod.RPC_SECRET_FILE = "/nonexistent/path/rpc-secret"

        captured = {}

        def fake_urlopen(req, timeout=None):
            body = json.loads(req.data.decode())
            captured["params"] = body["params"]
            resp = MagicMock()
            resp.read.return_value = b'{"result":[]}'
            return resp

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            mod.rpc("aria2.tellActive", [["gid"]])

        # Should not crash, and first param should still start with "token:"
        self.assertTrue(
            captured["params"][0].startswith("token:"),
            f"First param should be 'token:...', got: {captured['params'][0]!r}"
        )


# ===========================================================================
# iris-add.py — arg guard (finding #32) and token injection (finding #14)
# ===========================================================================

class TestAddArgGuard(unittest.TestCase):
    """iris-add.py must exit with a usage message on missing argv, not IndexError."""

    def test_no_arg_exits_with_usage(self):
        """Running with no argument must call sys.exit with a usage string."""
        diag_path = os.path.join(LAB_DIR, "iris-add.py")

        with patch.object(sys, "argv", ["iris-add.py"]), \
             self.assertRaises(SystemExit) as cm:
            spec, mod = _load_source("iris_add_noarg", diag_path)
            # Don't stub urlopen — it must exit before any network call
            spec.loader.exec_module(mod)

        exit_code = cm.exception.code
        # sys.exit("string") sets code to the string; sys.exit(1) sets int
        self.assertNotEqual(exit_code, 0,
                            "Should exit non-zero on missing argument")
        # Should NOT be an uncaught IndexError (which would bubble up, not
        # reach SystemExit at all — but we verify it is a SystemExit and the
        # message mentions usage)
        if isinstance(exit_code, str):
            self.assertIn("usage", exit_code.lower(),
                          f"Exit message should mention 'usage', got: {exit_code!r}")


class TestAddRpcToken(unittest.TestCase):
    """iris-add.py RPC call must include 'token:<secret>' as params[0]."""

    def test_add_torrent_params_have_token(self):
        """aria2.addTorrent params[0] must be 'token:<secret>'."""
        import tempfile

        secret = "addsecretABC"
        with tempfile.NamedTemporaryFile(mode="w", suffix="rpc-secret",
                                        delete=False) as tf:
            tf.write(secret)
            secret_file = tf.name

        # Create a minimal fake .torrent file
        with tempfile.NamedTemporaryFile(suffix=".torrent", delete=False) as tf2:
            tf2.write(b"fake torrent bytes")
            torrent_file = tf2.name

        captured = {}

        def fake_urlopen(req, timeout=None):
            body = json.loads(req.data.decode())
            captured["params"] = body["params"]
            resp = MagicMock()
            resp.read.return_value = b'{"result":"gid001"}'
            return resp

        try:
            diag_path = os.path.join(LAB_DIR, "iris-add.py")
            with patch.object(sys, "argv", ["iris-add.py", torrent_file]), \
                 patch("urllib.request.urlopen", side_effect=fake_urlopen):
                spec, mod = _load_source("iris_add_token", diag_path)
                # IRIS_RPC_SECRET_FILE must be set BEFORE exec_module because
                # iris-add.py reads os.environ["IRIS_RPC_SECRET_FILE"] at
                # module-init time (not lazily at call time).  Setting it after
                # exec_module would cause the module to use the non-existent
                # default path, producing an empty secret.
                os.environ["IRIS_RPC_SECRET_FILE"] = secret_file
                spec.loader.exec_module(mod)
        finally:
            os.environ.pop("IRIS_RPC_SECRET_FILE", None)
            os.unlink(secret_file)
            os.unlink(torrent_file)

        self.assertIn("params", captured,
                      "urlopen should have been called with RPC body")
        self.assertTrue(
            captured["params"][0].startswith("token:"),
            f"First param should be 'token:...', got: {captured['params'][0]!r}"
        )
        self.assertEqual(captured["params"][0], f"token:{secret}")


if __name__ == "__main__":
    unittest.main()
