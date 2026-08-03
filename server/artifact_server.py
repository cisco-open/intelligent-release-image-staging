#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""IRIS artifact server: serve the agent bundle + per-device install files over
HTTPS. Mirrors catalog.py's exact stdlib TLS pattern (ThreadingHTTPServer +
SSLContext(PROTOCOL_TLS_SERVER) + load_cert_chain(IRIS_CERT) + wrap_socket),
reusing the SAME combined cert (IRIS_CERT) the catalog already serves with, but on
its own port (IRIS_ARTIFACTS_PORT, default 8000; the catalog defaults to 8443). The
only differences from the catalog are the request handler (static files from the
artifacts dir) and the port. NO auth is added: the device's
PKI trustpoint gives confidentiality + server authentication, and the payload IS the
credential bundle, fetched by a device the operator is actively installing over an
SSH session they already hold (spec §4.1). Stdlib only."""
import os
import ssl
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

# Subdirectory (relative to the artifacts root) that holds per-device staging
# configs.  Files under this prefix are swept lazily after STAGING_MAX_AGE_SECONDS
# rather than deleted immediately after the first GET.  This lets device-install.sh
# retry 'copy https://' up to 3 times (with 10 s sleeps) within the install window
# if the SSH pipe drops the first transfer's output — while still bounding how long
# per-device credentials are reachable from the network.
_STAGING_PREFIX = "staging" + os.sep

# How long (seconds) a staging file is retained after creation.  Must be long
# enough for device-install.sh's 3-attempt retry loop (2 × 10 s sleep = at least
# 20 s needed; 600 s gives ample headroom for SSH reconnects and slow IOS copies).
STAGING_MAX_AGE_SECONDS = 600


def sweep_staging(directory, now=None):
    """Delete staging/ files whose mtime is older than STAGING_MAX_AGE_SECONDS.

    Called lazily on each incoming GET for a staging path so no background
    thread is needed.  Ignores errors (e.g. concurrent deletion by another
    process) so it never raises.
    """
    if now is None:
        now = time.time()
    staging_dir = os.path.join(directory, "staging")
    try:
        entries = os.listdir(staging_dir)
    except OSError:
        return
    cutoff = now - STAGING_MAX_AGE_SECONDS
    for name in entries:
        path = os.path.join(staging_dir, name)
        try:
            if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                os.unlink(path)
        except OSError:
            pass


def make_server(host, port, directory, certfile=None):
    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)

        def list_directory(self, path):
            """Directory listing disabled — 404 on all directory requests."""
            self.send_error(404, "Not Found")
            return None

        def do_GET(self):
            """Serve the file; lazily sweep expired staging files."""
            resolved = self.translate_path(self.path)
            # Sweep staging/ for expired files before serving — this limits
            # credential exposure without breaking retries within the window.
            if (os.path.isfile(resolved) and
                    os.path.relpath(resolved, directory).startswith(
                        _STAGING_PREFIX)):
                sweep_staging(directory)
            super().do_GET()

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer((host, port), Handler)
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


def main():
    host = os.environ.get("IRIS_ARTIFACTS_HOST", "0.0.0.0")
    port = int(os.environ.get("IRIS_ARTIFACTS_PORT", "8000"))
    directory = os.environ.get("IRIS_ARTIFACTS_DIR", "/srv/artifacts")
    cert = os.environ.get("IRIS_CERT", "/etc/iris/tls/cert.pem")
    certfile = cert if os.path.exists(cert) else None
    srv = make_server(host, port, directory, certfile=certfile)
    scheme = "https" if certfile else "http"
    print("artifacts on %s://%s:%d (dir %s)" % (scheme, host, port, directory),
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
