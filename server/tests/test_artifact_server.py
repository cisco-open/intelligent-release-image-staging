# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import http.client
import os
import ssl
import subprocess
import sys
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


def test_staging_ttl_outlives_the_install_that_has_to_use_it():
    """The staging TTL must cover the whole span from staging a file to the
    LAST retry of fetching it -- not just the retry loop.

    It was sized for the retry loop alone ("2 x 10 s sleep = at least 20 s
    needed"), on the unstated assumption that a device fetches its config
    shortly after it is staged. It does not: router-install.sh stages at step
    2 and fetches at step 5, with `guestshell enable` in between, and that
    step's own poll budget is larger than the TTL was. Four routers failed
    this way -- the device's GET triggered the lazy sweep, which deleted the
    very file the request was for, then served a 404.

    The budget is parsed out of the recipe so the two cannot drift apart
    silently again."""
    import re as _re
    recipe = os.path.join(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))), "device", "router-install.sh")
    with open(recipe) as f:
        body = f.read()
    # every `for _ in $(seq 1 N); do ... sleep M` poll between stage and fetch
    budget = 0
    for count, sleep_s in _re.findall(
            r"seq 1 (\d+)\s*\)?;\s*do(?:(?!done).)*?sleep (\d+)", body, _re.DOTALL):
        budget += int(count) * int(sleep_s)
    assert budget > 0, "could not parse the recipe's poll budget"
    # The polls are only PART of the span: SSH round-trips (~3 s each, and the
    # recipe makes many), applying IOS config, and the copy retry loop all sit
    # outside those loops. A measured router onboard took 900 s against a 570 s
    # poll budget -- about 1.6x -- so merely exceeding the budget is not
    # enough. The old 600 s cleared it by thirty seconds and still expired
    # mid-install on all four routers.
    assert artifact_server.STAGING_MAX_AGE_SECONDS >= 2 * budget, (
        "staging TTL (%ds) leaves no room over the install's own poll budget "
        "(%ds) between staging a file and fetching it. Polls are only part of "
        "the span; a measured onboard ran ~1.6x its poll budget, and the TTL "
        "expiring mid-install makes the device's own GET sweep the file it is "
        "asking for."
        % (artifact_server.STAGING_MAX_AGE_SECONDS, budget))


def _tls_get_raw(port, crt, path):
    ctx = ssl.create_default_context(cafile=crt)
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5)
    conn.request("GET", path)
    r = conn.getresponse()
    body = r.read()
    conn.close()
    return r.status, body


def _tls_head_raw(port, crt, path):
    ctx = ssl.create_default_context(cafile=crt)
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5)
    conn.request("HEAD", path)
    r = conn.getresponse()
    r.read()
    conn.close()
    return r.status


def test_symlink_inside_root_cannot_escape_it(tmp_path):
    """IRIS-06-008: translate_path strips dotted segments but follows
    symlinks; containment is decided on the real path."""
    served = tmp_path / "artifacts"
    served.mkdir()
    (served / "inside.txt").write_text("INSIDE\n")
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("OUTSIDE-THE-ROOT\n")
    os.symlink(str(outside), str(served / "link.txt"))
    os.symlink(str(tmp_path), str(served / "dirlink"))
    crt, combined = _throwaway_cert(tmp_path)
    srv = artifact_server.make_server("127.0.0.1", 0, str(served), certfile=combined)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        assert _tls_get_raw(port, crt, "/inside.txt") == (200, b"INSIDE\n")
        assert _tls_get_raw(port, crt, "/link.txt")[0] == 404
        assert _tls_get_raw(port, crt, "/dirlink/outside-secret.txt")[0] == 404
    finally:
        srv.shutdown()


def test_head_applies_same_symlink_containment_as_get(tmp_path):
    """IRIS-118: HEAD used to fall straight through to the stock
    SimpleHTTPRequestHandler.do_HEAD and skip the containment check GET
    applies -- a HEAD against a path escaping the root through a symlink
    answered 200 (with headers for the OUTSIDE file) where GET would have
    404'd. No body ever crossed (HEAD never sends one), but existence and
    metadata (Content-Length, Last-Modified) did."""
    served = tmp_path / "artifacts"
    served.mkdir()
    (served / "inside.txt").write_text("INSIDE\n")
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("OUTSIDE-THE-ROOT\n")
    os.symlink(str(outside), str(served / "link.txt"))
    crt, combined = _throwaway_cert(tmp_path)
    srv = artifact_server.make_server("127.0.0.1", 0, str(served), certfile=combined)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        assert _tls_head_raw(port, crt, "/inside.txt") == 200
        assert _tls_head_raw(port, crt, "/link.txt") == 404
    finally:
        srv.shutdown()


def test_head_applies_same_staging_permission_check_as_get(
        tls_server, tmp_path, monkeypatch):
    """IRIS-118: HEAD against a foreign-owned, loose-permission staging/
    file must 403 like GET does, not silently answer 200 with headers for a
    credential file a GET would have refused to serve. The file is created
    AFTER the server (and its startup sweep) is already running -- same
    setup as test_staging_file_403_when_foreign_owned_and_mode_loose --
    so only the per-request check is exercised, not the startup sweep."""
    srv, port, crt = tls_server
    served_dir = tmp_path / "artifacts"
    staging = served_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    conf = staging / ("iris-agent-HEAD-" + "h" * 32 + ".conf")
    conf.write_text("catalog_token=HEADTOKEN\n")
    os.chmod(str(conf), 0o644)          # loose

    real_chmod = os.chmod
    conf_path = os.path.abspath(str(conf))

    def fake_chmod(path, mode, *args, **kwargs):
        if os.path.abspath(path) == conf_path:
            raise PermissionError(1, "Operation not permitted")
        return real_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(artifact_server.os, "chmod", fake_chmod)

    assert _tls_head_raw(
        port, crt, "/staging/iris-agent-HEAD-" + "h" * 32 + ".conf") == 403


def test_staging_path_is_redacted_in_access_log(tls_server, tmp_path, capsys):
    """IRIS-06-007: the staging basename IS the device's credential
    capability; it must never reach stdout (docker logs)."""
    srv, port, crt = tls_server
    served = tmp_path / "artifacts"
    (served / "staging").mkdir(exist_ok=True)
    cap = "iris-agent-d1-" + "ab" * 16 + ".conf"
    (served / "staging" / cap).write_text("secret=1\n")
    os.chmod(str(served / "staging" / cap), 0o600)
    status, _ = _tls_get_raw(port, crt, "/staging/" + cap)
    assert status == 200
    out = capsys.readouterr().out
    assert cap not in out
    assert "/staging/<redacted>" in out
    assert artifact_server.redact_log_path("/bootstrap.sh") == "/bootstrap.sh"
    assert artifact_server.redact_log_path("/staging/x.conf") == "/staging/<redacted>"


def test_idle_post_handshake_connection_is_released(tmp_path, monkeypatch):
    """IRIS-06-008: a client that completes the handshake and never sends a
    request line must not hold its worker thread and socket forever."""
    monkeypatch.setattr(artifact_server, "REQUEST_IDLE_TIMEOUT_SECONDS", 1)
    served = tmp_path / "artifacts"
    served.mkdir()
    crt, combined = _throwaway_cert(tmp_path)
    srv = artifact_server.make_server("127.0.0.1", 0, str(served), certfile=combined)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        import socket
        ctx = ssl.create_default_context(cafile=crt)
        raw = socket.create_connection(("127.0.0.1", srv.server_address[1]), timeout=5)
        tls = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
        tls.settimeout(5)
        try:
            data = tls.recv(16)          # server closes after the idle timeout
        except (ssl.SSLError, OSError):
            data = b""
        assert data == b""
        tls.close()
    finally:
        srv.shutdown()


_SERVER_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_main_refuses_plaintext_without_opt_in_then_serves_with_it(tmp_path):
    """IRIS-105: artifact_server.main() used to silently fall back to plain
    HTTP whenever no certificate was found -- staging URLs are the ONLY
    authorization on capability-bearing enrollment files, so a plaintext
    artifact server serves them in the clear. Now it fails CLOSED (exit 2,
    naming the opt-in) exactly like the console's IRIS_GUI_ALLOW_PLAINTEXT
    contract and the catalog's IRIS_CATALOG_ALLOW_PLAINTEXT, unless
    IRIS_ARTIFACTS_ALLOW_PLAINTEXT=1 opts in explicitly; port 0 so no fixed
    port is ever bound."""
    host = "127.0.0.1"
    served = tmp_path / "artifacts"
    served.mkdir()
    env = dict(os.environ)
    env["IRIS_ARTIFACTS_HOST"] = host
    env["IRIS_ARTIFACTS_PORT"] = "0"
    env["IRIS_ARTIFACTS_DIR"] = str(served)
    env["IRIS_CERT"] = str(tmp_path / "nonexistent-cert.pem")
    env.pop("IRIS_ARTIFACTS_ALLOW_PLAINTEXT", None)
    refused = subprocess.run([sys.executable, "artifact_server.py"],
                             cwd=_SERVER_DIR, env=env, capture_output=True,
                             timeout=30)
    assert refused.returncode == 2
    assert b"IRIS_ARTIFACTS_ALLOW_PLAINTEXT=1" in refused.stderr

    env["IRIS_ARTIFACTS_ALLOW_PLAINTEXT"] = "1"
    proc = subprocess.Popen([sys.executable, "artifact_server.py"],
                            cwd=_SERVER_DIR, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    try:
        line = proc.stdout.readline()
        assert b"artifacts on http://" in line, (line, proc.stderr.read())
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
