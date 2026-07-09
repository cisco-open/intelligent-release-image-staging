# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import http.client
import os
import ssl
import subprocess
import threading
import urllib.request

import pytest

import artifact_server


def _throwaway_cert(tmp_path):
    """Generate a throwaway self-signed cert (bare crt + combined cert+key) with
    SAN=IP:127.0.0.1, mirroring the server's real cert shape (CN=iris, IP SAN).
    Returns (crt_path, combined_path)."""
    crt = tmp_path / "crt.pem"
    key = tmp_path / "key.pem"
    combined = tmp_path / "cert.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-keyout", str(key), "-out", str(crt), "-subj", "/CN=iris",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True)
    combined.write_bytes(crt.read_bytes() + key.read_bytes())
    return str(crt), str(combined)


@pytest.fixture
def tls_server(tmp_path):
    served = tmp_path / "artifacts"
    served.mkdir()
    (served / "bootstrap.sh").write_text("#!/bin/sh\necho iris\n")
    crt, combined = _throwaway_cert(tmp_path)
    srv = artifact_server.make_server("127.0.0.1", 0, str(served),
                                      certfile=combined)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv, srv.server_address[1], crt
    srv.shutdown()


def test_serves_a_file_over_tls(tls_server):
    # A client trusting the throwaway cert GETs a served file over HTTPS.
    srv, port, crt = tls_server
    ctx = ssl.create_default_context(cafile=crt)
    with urllib.request.urlopen(
            "https://127.0.0.1:%d/bootstrap.sh" % port, context=ctx,
            timeout=5) as r:
        assert r.status == 200
        assert r.read() == b"#!/bin/sh\necho iris\n"


def test_refuses_plain_http(tls_server):
    # The #2 server-side assertion: a plain-HTTP request to the TLS port FAILS —
    # the server speaks TLS only and never serves cleartext.
    srv, port, crt = tls_server
    with pytest.raises((http.client.HTTPException, ConnectionError, OSError)):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        c.request("GET", "/bootstrap.sh")
        c.getresponse().read()


def test_directory_listing_returns_404(tls_server):
    # A GET to the root (directory path) must return 404, not an HTML index.
    srv, port, crt = tls_server
    ctx = ssl.create_default_context(cafile=crt)
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(
            "https://127.0.0.1:%d/" % port, context=ctx, timeout=5)
    assert exc_info.value.code == 404


def test_staging_conf_swept_after_window(tmp_path):
    # Staging confs are swept (deleted) once they are older than the exposure
    # window — not immediately after a single GET.  This lets device-install.sh
    # retry the 'copy https://' up to 3 times within the install window while
    # still limiting how long the credential file is reachable.
    import time
    served_dir = tmp_path / "artifacts"
    staging = served_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    conf = staging / "iris-agent-DEADBEEF.conf"
    conf.write_text("catalog_token=SECRETTOKEN\n")

    now = time.time()
    # Back-date mtime to beyond the sweep window.
    expired = now - (artifact_server.STAGING_MAX_AGE_SECONDS + 1)
    os.utime(str(conf), (expired, expired))

    artifact_server.sweep_staging(str(served_dir), now=now)

    assert not conf.exists(), (
        "staging conf must be swept once it exceeds STAGING_MAX_AGE_SECONDS"
    )


def test_non_staging_file_not_deleted_after_delivery(tls_server, tmp_path):
    # Files outside staging/ (e.g. bootstrap.sh) are NOT deleted after serving.
    srv, port, crt = tls_server
    ctx = ssl.create_default_context(cafile=crt)
    with urllib.request.urlopen(
            "https://127.0.0.1:%d/bootstrap.sh" % port, context=ctx, timeout=5) as r:
        assert r.status == 200

    served_dir = tmp_path / "artifacts"
    assert (served_dir / "bootstrap.sh").exists(), (
        "non-staging files must NOT be deleted after serving")


def test_rejects_wrong_cafile(tls_server, tmp_path):
    # A client using a DIFFERENT cert as its trust anchor rejects the connection.
    srv, port, crt = tls_server
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    wrong_crt, _ = _throwaway_cert(other_dir)
    ctx = ssl.create_default_context(cafile=wrong_crt)
    with pytest.raises(urllib.error.URLError):
        urllib.request.urlopen(
            "https://127.0.0.1:%d/bootstrap.sh" % port, context=ctx, timeout=5)


def test_staging_retry_within_window_succeeds(tls_server, tmp_path):
    # device-install.sh retries each 'copy https://' up to 3 times.  A second
    # GET of a staging file within the install window must still return 200 with
    # content — the file must not be deleted by the first successful response.
    srv, port, crt = tls_server
    served_dir = tmp_path / "artifacts"
    staging = served_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    conf = staging / "iris-agent-RETRY.conf"
    conf.write_text("catalog_token=RETRYTOKEN\n")

    ctx = ssl.create_default_context(cafile=crt)
    url = "https://127.0.0.1:%d/staging/iris-agent-RETRY.conf" % port

    # First GET (simulates the installer's attempt 1).
    with urllib.request.urlopen(url, context=ctx, timeout=5) as r:
        assert r.status == 200
        assert b"catalog_token" in r.read()

    # Second GET within the install window (installer retry attempt 2).
    # Must succeed — the file must still be on disk.
    with urllib.request.urlopen(url, context=ctx, timeout=5) as r:
        assert r.status == 200, (
            "staging file must survive the first GET so retries can succeed "
            "(device-install.sh retries copy https:// up to 3 times)"
        )
        assert b"catalog_token" in r.read()


def test_staging_304_does_not_delete(tls_server, tmp_path):
    # A conditional GET that triggers a 304 Not Modified must NOT delete the
    # staging file — the device received no body on a 304 response.
    srv, port, crt = tls_server
    served_dir = tmp_path / "artifacts"
    staging = served_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    conf = staging / "iris-agent-304.conf"
    conf.write_text("catalog_token=304TOKEN\n")

    ctx = ssl.create_default_context(cafile=crt)
    url = "https://127.0.0.1:%d/staging/iris-agent-304.conf" % port

    # First GET to capture the Last-Modified header.
    with urllib.request.urlopen(url, context=ctx, timeout=5) as r:
        assert r.status == 200
        last_modified = r.headers.get("Last-Modified")
        r.read()

    # Ensure file is still present after first GET (time-bounded design).
    assert conf.exists(), "staging file must still exist after first GET"

    if last_modified:
        # Issue a conditional GET that should produce a 304.
        req = urllib.request.Request(url)
        req.add_header("If-Modified-Since", last_modified)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=5):
                pass  # 200 still acceptable; 304 will raise HTTPError(304)
        except urllib.error.HTTPError as e:
            assert e.code == 304, "expected 304 Not Modified"

        # The staging file must still exist — no body was delivered on 304.
        assert conf.exists(), (
            "staging file must NOT be deleted by a 304 response "
            "(no content delivered to the device)"
        )


def test_staging_file_swept_after_window(tmp_path):
    # Exposure is time-bounded: staging files older than STAGING_MAX_AGE_SECONDS
    # are swept.  We call the sweep function directly with a fake clock to avoid
    # sleeping in tests.
    served_dir = tmp_path / "artifacts"
    staging = served_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    old_conf = staging / "iris-agent-OLD.conf"
    new_conf = staging / "iris-agent-NEW.conf"
    old_conf.write_text("catalog_token=OLD\n")
    new_conf.write_text("catalog_token=NEW\n")

    import time
    now = time.time()
    # Back-date old_conf's mtime to beyond the sweep window.
    old_mtime = now - (artifact_server.STAGING_MAX_AGE_SECONDS + 60)
    os.utime(str(old_conf), (old_mtime, old_mtime))
    # new_conf has a fresh mtime (just written).

    artifact_server.sweep_staging(str(served_dir), now=now)

    assert not old_conf.exists(), (
        "staging file older than STAGING_MAX_AGE_SECONDS must be swept"
    )
    assert new_conf.exists(), (
        "staging file within the window must NOT be swept"
    )
