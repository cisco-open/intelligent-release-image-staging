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


def test_device_id_alone_cannot_fetch_staging_conf(tls_server, tmp_path):
    srv, port, crt = tls_server
    staging = tmp_path / "artifacts" / "staging"
    staging.mkdir()
    (staging / ("iris-agent-device-1-" + "a" * 32 + ".conf")).write_text(
        "catalog_token=SECRET\n")
    ctx = ssl.create_default_context(cafile=crt)
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(
            "https://127.0.0.1:%d/staging/iris-agent-device-1.conf" % port,
            context=ctx, timeout=5)
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
    conf = staging / ("iris-agent-DEADBEEF-" + "a" * 32 + ".conf")
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
    conf = staging / ("iris-agent-RETRY-" + "b" * 32 + ".conf")
    conf.write_text("catalog_token=RETRYTOKEN\n")

    ctx = ssl.create_default_context(cafile=crt)
    url = ("https://127.0.0.1:%d/staging/iris-agent-RETRY-" + "b" * 32
           + ".conf") % port

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
    conf = staging / ("iris-agent-304-" + "c" * 32 + ".conf")
    conf.write_text("catalog_token=304TOKEN\n")

    ctx = ssl.create_default_context(cafile=crt)
    url = ("https://127.0.0.1:%d/staging/iris-agent-304-" + "c" * 32
           + ".conf") % port

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


def test_staging_file_served_when_foreign_owned_but_mode_already_tight(
        tls_server, tmp_path, monkeypatch):
    # Staged files written from OUTSIDE the container (remote SSH staging via
    # device-install.sh, or a stage-host-local CLI run) are owned by a
    # foreign uid.  chmod by a non-owner always raises EPERM.  If the file's
    # mode is ALREADY tight (installers write with umask 077 => no
    # group/other access), that's not a reason to fail the request — the
    # security property (least privilege) already holds without our chmod.
    srv, port, crt = tls_server
    served_dir = tmp_path / "artifacts"
    staging = served_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    conf = staging / ("iris-agent-FOREIGN-" + "f" * 32 + ".conf")
    conf.write_text("catalog_token=FOREIGNTOKEN\n")
    os.chmod(str(conf), 0o600)

    real_chmod = os.chmod
    conf_path = os.path.abspath(str(conf))

    def fake_chmod(path, mode, *args, **kwargs):
        if os.path.abspath(path) == conf_path:
            raise PermissionError(1, "Operation not permitted")
        return real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(artifact_server.os, "chmod", fake_chmod)

    ctx = ssl.create_default_context(cafile=crt)
    url = ("https://127.0.0.1:%d/staging/iris-agent-FOREIGN-" + "f" * 32
           + ".conf") % port
    with urllib.request.urlopen(url, context=ctx, timeout=5) as r:
        assert r.status == 200, (
            "a foreign-owned staging file with an already-tight mode (0600) "
            "must still be served even though this process cannot chmod it"
        )
        assert b"catalog_token" in r.read()


def test_staging_file_403_when_foreign_owned_and_mode_loose(
        tls_server, tmp_path, monkeypatch):
    # A foreign-owned staging file with a LOOSE mode (group/other accessible)
    # must still fail closed with 403 when we cannot chmod it — the failure
    # mode changes (from "chmod raised" to "mode is loose and unfixable"),
    # but the security outcome (403, not served) does not.
    srv, port, crt = tls_server
    served_dir = tmp_path / "artifacts"
    staging = served_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    conf = staging / ("iris-agent-LOOSE-" + "g" * 32 + ".conf")
    conf.write_text("catalog_token=LOOSETOKEN\n")
    os.chmod(str(conf), 0o644)

    real_chmod = os.chmod
    conf_path = os.path.abspath(str(conf))

    def fake_chmod(path, mode, *args, **kwargs):
        if os.path.abspath(path) == conf_path:
            raise PermissionError(1, "Operation not permitted")
        return real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(artifact_server.os, "chmod", fake_chmod)

    ctx = ssl.create_default_context(cafile=crt)
    url = ("https://127.0.0.1:%d/staging/iris-agent-LOOSE-" + "g" * 32
           + ".conf") % port
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(url, context=ctx, timeout=5)
    assert exc_info.value.code == 403, (
        "a foreign-owned staging file with a loose mode (0644) that cannot "
        "be chmod'd must fail closed with 403"
    )


def test_startup_sweep_keeps_foreign_owned_tight_staging_file(
        tmp_path, monkeypatch):
    # The startup sweep must apply the same contract as request-time serving:
    # a staged file owned by a foreign uid (remote SSH staging, stage-host
    # CLI run) raises EPERM on chmod, but when its mode is ALREADY tight the
    # least-privilege property holds without our chmod — deleting it here
    # would destroy a valid credential before the server even starts.
    staging = tmp_path / "staging"
    staging.mkdir()
    conf = staging / ("iris-agent-BOOT-" + "h" * 32 + ".conf")
    conf.write_text("catalog_token=BOOTTOKEN\n")
    os.chmod(str(conf), 0o600)

    real_chmod = os.chmod
    conf_path = os.path.abspath(str(conf))

    def fake_chmod(path, mode, *args, **kwargs):
        if os.path.abspath(path) == conf_path:
            raise PermissionError(1, "Operation not permitted")
        return real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(artifact_server.os, "chmod", fake_chmod)
    artifact_server.secure_staging_permissions(str(tmp_path))
    assert conf.exists(), (
        "the startup sweep must not delete a foreign-owned staging file "
        "whose mode is already tight (0600)"
    )


def test_startup_sweep_deletes_foreign_owned_loose_staging_file(
        tmp_path, monkeypatch):
    # ...but a foreign-owned file that is group/other-accessible and cannot
    # be tightened must still fail closed: delete it.
    staging = tmp_path / "staging"
    staging.mkdir()
    conf = staging / ("iris-agent-LOOSEBOOT-" + "i" * 32 + ".conf")
    conf.write_text("catalog_token=LOOSEBOOT\n")
    os.chmod(str(conf), 0o644)

    real_chmod = os.chmod
    conf_path = os.path.abspath(str(conf))

    def fake_chmod(path, mode, *args, **kwargs):
        if os.path.abspath(path) == conf_path:
            raise PermissionError(1, "Operation not permitted")
        return real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(artifact_server.os, "chmod", fake_chmod)
    artifact_server.secure_staging_permissions(str(tmp_path))
    assert not conf.exists(), (
        "a loose (0644) staging file that cannot be chmod'd must be removed "
        "by the startup sweep"
    )


def test_startup_sweep_tightens_owned_loose_staging_file(tmp_path):
    # Unchanged behavior: a file this process owns is tightened in place.
    staging = tmp_path / "staging"
    staging.mkdir()
    conf = staging / ("iris-agent-OWNED-" + "j" * 32 + ".conf")
    conf.write_text("catalog_token=OWNED\n")
    os.chmod(str(conf), 0o644)

    artifact_server.secure_staging_permissions(str(tmp_path))
    assert conf.exists()
    assert (os.stat(str(conf)).st_mode & 0o777) == 0o600


def test_staging_file_swept_after_window(tmp_path):
    # Exposure is time-bounded: staging files older than STAGING_MAX_AGE_SECONDS
    # are swept.  We call the sweep function directly with a fake clock to avoid
    # sleeping in tests.
    served_dir = tmp_path / "artifacts"
    staging = served_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    old_conf = staging / ("iris-agent-OLD-" + "d" * 32 + ".conf")
    new_conf = staging / ("iris-agent-NEW-" + "e" * 32 + ".conf")
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
