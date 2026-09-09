#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""IRIS artifact server: serve agent and package artifacts over
HTTPS. Mirrors catalog.py's exact stdlib TLS pattern (ThreadingHTTPServer +
SSLContext(PROTOCOL_TLS_SERVER) + load_cert_chain(IRIS_CERT) + wrap_socket),
reusing the SAME combined cert (IRIS_CERT) the catalog already serves with, but on
its own port (IRIS_ARTIFACTS_PORT, default 8000; the catalog defaults to 8443).
The versioned API uses resource-bound HTTP Basic auth: username=device id and
password=that device's catalog enrollment token. Sensitive API staging paths
are additionally partitioned by device id. A deliberately narrow compatibility
surface retains the exact static/capability GETs used by unchanged IOS Guest
Shell ``copy https:`` onboarding; new clients must use the versioned API.
main() refuses to start over plain HTTP unless
IRIS_ARTIFACTS_ALLOW_PLAINTEXT=1 opts in explicitly. Stdlib only."""
import base64
import binascii
import hmac
import os
import re
import ssl
import sys
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

import api_problem
import api_routes
import auth
import bounded_pool
import credential_cache
import secrets_store

# Subdirectory (relative to the artifacts root) that holds per-device staging
# configs. Files under this prefix are swept on a timer (start_sweeper) after
# STAGING_MAX_AGE_SECONDS. Guest Shell installers fetch flat, high-entropy
# capability names here via IOS ``copy https:``; authenticated API consumers
# use one-level per-device directories.
_STAGING_PREFIX = "staging" + os.sep
_PUBLIC_ARTIFACT = re.compile(
    r"^(?:bootstrap\.sh|iris-[A-Za-z0-9._-]+\.(?:tgz|tar|rpm|pem))$")
_LEGACY_STATIC_ARTIFACTS = frozenset((
    "bootstrap.sh", "iris-agent.tgz", "iris-agent-arm.tgz",
    "iris-catalog.pem", "iris-signers.pem",
))
_LEGACY_STAGING_ARTIFACT = re.compile(
    r"^(?:iris-agent-[A-Za-z0-9._:-]+-[0-9A-Fa-f]{32}\.conf|"
    r"rpc-secret-[0-9A-Fa-f]{32}|"
    r"iris-instructions-[A-Za-z0-9._:-]+-[0-9a-f]{32}\.envelope|"
    r"bundle-sha256-[0-9a-f]{32})$")


def _legacy_guest_shell_target(request_path):
    """Return a safe legacy relative path, or ``None``.

    These paths are an explicit compatibility exception for IOS Guest Shell,
    whose ``copy https:`` client cannot attach the resource-bound Basic header.
    Enrollment files authenticate through an unguessable 128-bit filename and
    are time-swept; static bootstrap/bundle/CA files contain no credential.
    Decode exactly once and reject residual escapes so the stock handler's
    second decode cannot turn a capability into traversal.
    """
    raw = urlsplit(str(request_path)).path
    decoded = unquote(raw)
    if "%" in decoded or "\\" in decoded or "//" in decoded:
        return None
    relative = decoded.lstrip("/")
    if relative in _LEGACY_STATIC_ARTIFACTS:
        return relative
    if relative.startswith("staging/"):
        parts = relative.split("/")
        if len(parts) == 2 and _LEGACY_STAGING_ARTIFACT.fullmatch(parts[1]):
            return relative
    return None

# How long (seconds) a staging file is retained after creation.  This must cover
# the whole span from STAGING a file to the LAST retry of FETCHING it -- not, as
# it was originally sized, the copy retry loop alone.  A recipe stages at step 2
# and fetches at step 5, with `guestshell enable` in between: router-install.sh
# alone budgets 12x10 s + a ramped 32-step wait (~431 s) = ~551 s of polling
# there, and that is before
# any SSH round-trip (~3 s each, and it makes many), the IOS config apply, or
# the copy retries.  A measured router onboard ran 900 s against that 570 s
# budget.  At 600 s the file expired mid-install and the device's own GET
# triggered the lazy sweep that deleted the file it was asking for, which
# failed four routers at step 5 with an opaque "copy ... failed after 3
# attempts".  An hour still bounds how long a per-device credential is
# reachable from the network, which is the point of sweeping at all.
STAGING_MAX_AGE_SECONDS = 3600


def _staging_files(directory):
    """Yield direct legacy files and one-level per-device files, no symlinks."""
    staging_dir = os.path.join(directory, "staging")
    try:
        entries = list(os.scandir(staging_dir))
    except OSError:
        return
    for entry in entries:
        try:
            if entry.is_file(follow_symlinks=False):
                yield entry.path
            elif entry.is_dir(follow_symlinks=False):
                for child in os.scandir(entry.path):
                    if child.is_file(follow_symlinks=False):
                        yield child.path
        except OSError:
            continue


def sweep_staging(directory, now=None):
    """Delete staging/ files whose mtime is older than STAGING_MAX_AGE_SECONDS.

    Driven by start_sweeper's timer thread.  It used to run inline on each
    incoming GET for a staging path, which put a directory scan on the request
    path and let a device trigger the deletion of the file it was fetching.
    Ignores errors (e.g. concurrent deletion by another process) so it never
    raises.
    """
    if now is None:
        now = time.time()
    cutoff = now - STAGING_MAX_AGE_SECONDS
    for path in _staging_files(directory):
        try:
            if os.path.isfile(path) and os.path.getmtime(path) < cutoff:
                os.unlink(path)
        except OSError:
            pass


def secure_staging_permissions(directory):
    """Restrict existing credential files before they can be served.

    Same contract as the request-time check in do_GET: files staged from
    OUTSIDE this container (remote SSH staging, or a stage-host-local CLI
    run) are owned by a foreign uid, so chmod by this process always raises
    EPERM even though the installer wrote them with umask 077. What matters
    is the file's actual permission bits — a foreign-owned file whose mode is
    already tight stays; only a LOOSE file that cannot be tightened is
    removed. Deleting on every chmod failure would destroy valid staged
    credentials at server start."""
    for path in _staging_files(directory):
        try:
            if not os.path.isfile(path):
                continue
            st = os.stat(path)
        except OSError:
            # Cannot even stat it — fail closed rather than serve unknown
            # permissions later.
            try:
                os.unlink(path)
            except OSError:
                pass
            continue
        mode_already_tight = (st.st_mode & 0o077) == 0
        try:
            os.chmod(path, 0o600)
        except OSError:
            if mode_already_tight:
                continue
            # A loose credential file whose permissions cannot be restricted
            # must not remain available to either local users or HTTP
            # clients.
            try:
                os.unlink(path)
            except OSError:
                pass


# In-flight GET accounting, reported on every access-log line. The artifact
# server is the one component a fleet onboard hits simultaneously, and the
# concurrency at the moment of a slow fetch is the number you actually need to
# diagnose it -- a duration on its own does not distinguish "the server is
# slow" from "twenty devices arrived at once".
_inflight = 0
_inflight_lock = threading.Lock()

# How long a client gets to complete the TLS handshake. Bounded because an
# unbounded handshake is what let one stalled device hold up the whole fleet
# (see _Server.process_request_thread). Generous: the peers are embedded IOS
# TLS clients on a management network, not browsers.
HANDSHAKE_TIMEOUT_SECONDS = 30

# Socket INACTIVITY timeout for a connection that has completed its
# handshake (the request line, headers, and each send of the body). Without
# it a client that handshakes and then never sends a request line holds its
# worker thread and file descriptor forever. An inactivity timeout does not
# cut a slow-but-healthy transfer: bytes flowing in either direction reset
# it, only a stall this long ends the connection.
REQUEST_IDLE_TIMEOUT_SECONDS = 120

# Opt-in to serve the artifact server over plain HTTP when no certificate is
# available. Same name pattern as gui_server's IRIS_GUI_ALLOW_PLAINTEXT and
# catalog's IRIS_CATALOG_ALLOW_PLAINTEXT, so an operator learns one
# convention for every listener. Only main() consults this -- make_server()
# itself still accepts certfile=None unconditionally, which the test suite
# relies on to run a plain-HTTP server without opting in globally.
_PLAINTEXT_OPT_IN_ENV = "IRIS_ARTIFACTS_ALLOW_PLAINTEXT"


def _plaintext_allowed():
    return os.environ.get(_PLAINTEXT_OPT_IN_ENV, "") == "1"


def redact_log_path(path):
    """The access-log form of a request path; never expose staging names."""
    # Authorization accepts one percent-decoded spelling, so redaction must
    # inspect the same representation. Otherwise /%73taging/... and an encoded
    # slash in the versioned hierarchy would serve successfully yet disclose
    # the high-entropy capability in the access log.
    stripped = unquote(urlsplit(str(path)).path).lstrip("/")
    if stripped.startswith("staging/") or stripped == "staging":
        return "/staging/<redacted>"
    if re.match(r"^v1/devices/[^/]+/artifacts/staging(?:/|$)", stripped):
        return "/v1/devices/<device_id>/artifacts/staging/<redacted>"
    return path


class _Server(bounded_pool.BoundedThreadingMixin, ThreadingHTTPServer):
    """ThreadingHTTPServer that completes TLS in the WORKER thread and bounds
    the pool of concurrently running handler threads.

    The obvious spelling -- ``srv.socket = ctx.wrap_socket(srv.socket)`` --
    wraps the LISTENING socket, and ``socketserver`` then reaches the
    handshake through ``self.socket.accept()``. On an ``SSLSocket`` that call
    performs the entire handshake before it returns, on the single accept
    thread, so the per-connection threads only ever start once the expensive
    part is already done: every handshake in a fleet onboard serialized behind
    every other one, and one client that stalled mid-handshake blocked every
    other device's `copy` for as long as it cared to. That is the mechanism
    behind the 75x latency spike device/router-install.sh's artifact_preflight
    comment records at 30 simultaneous fetches.

    So ``get_request`` hands back the plain accepted socket and the wrap
    happens in ``process_request_thread``, which is already per-connection.
    """

    # socketserver's default of 5 is a listen backlog, not a worker count: in a
    # 20-device wave connections 6+ were SYN-dropped and left to TCP's own
    # 1s/3s/7s retry, which the serialized handshake above kept full.
    request_queue_size = 128

    tls_context = None
    # A device transfer can legitimately run for a while (a large image over
    # a slow WAN link), so this bounds CONCURRENT handler threads rather than
    # duration -- see bounded_pool.py. IRIS_ONBOARD_CONCURRENCY (default 25)
    # already caps how many devices one onboard job can be fetching for at
    # once; this is sized well above that so the admission timeout is only
    # ever reached under genuine overload, not ordinary fleet-onboard peaks.
    max_concurrent_requests = 256

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.tls_context is not None:
            # Bounds the handshake only; cleared below so a slow but healthy
            # transfer to an embedded client is never cut off mid-file.
            sock.settimeout(HANDSHAKE_TIMEOUT_SECONDS)
        return sock, addr

    def process_request_thread(self, request, client_address):
        if self.tls_context is not None:
            try:
                request = self.tls_context.wrap_socket(
                    request, server_side=True)
            except (ssl.SSLError, OSError, ValueError):
                # A failed or timed-out handshake is this connection's problem
                # and nobody else's -- which is the entire point of doing it
                # here rather than in accept().
                self.shutdown_request(request)
                return
            try:
                request.settimeout(None)
            except OSError:
                pass
        super().process_request_thread(request, client_address)


def make_server(host, port, directory, certfile=None, secrets_path=None,
                token_grace=None):
    credentials = (credential_cache.CredentialResolver(secrets_path)
                   if secrets_path else None)
    grace = (int(os.environ.get("IRIS_TOKEN_SKEW_GRACE", "300"))
             if token_grace is None else int(token_grace))

    class Handler(SimpleHTTPRequestHandler):
        timeout = REQUEST_IDLE_TIMEOUT_SECONDS

        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=directory, **kwargs)

        def end_headers(self):
            if getattr(self, "_legacy_guest_shell", False):
                self.send_header("Deprecation", "true")
            if getattr(self, "_sensitive_staging", False):
                self.send_header("Cache-Control", "private, no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
            super().end_headers()

        def send_error(self, code, message=None, explain=None):
            """Keep the static-handler error surface on RFC 9457 JSON."""
            problems = {
                400: ("invalid-request", "Invalid request"),
                403: ("artifact-forbidden", "Artifact forbidden"),
                404: ("artifact-not-found", "Artifact not found"),
                416: ("range-not-satisfiable", "Range not satisfiable"),
                501: ("method-not-allowed", "Method not allowed"),
            }
            problem_code, title = problems.get(
                code, ("artifact-request-failed", "Artifact request failed"))
            api_problem.send(self, code, problem_code, title)

        def _basic(self):
            value = self.headers.get("Authorization", "")
            if not value.startswith("Basic ") or value.count(" ") != 1:
                return None, None
            try:
                decoded = base64.b64decode(value[6:], validate=True).decode("utf-8")
            except (binascii.Error, UnicodeError):
                return None, None
            if ":" not in decoded:
                return None, None
            return decoded.split(":", 1)

        def _authenticate(self):
            """Authenticate before parsing or translating the artifact path."""
            username, presented = self._basic()
            if credentials is None:
                return username  # legacy unit-test construction only
            if username is None or presented is None:
                return None
            try:
                store, index = credentials.view(
                    "catalog", secrets_store.build_catalog_auth_index)
            except (secrets_store.StoreCorruptError,
                    secrets_store.DuplicateCredentialError):
                api_problem.send(self, 503, "credential-store-unavailable",
                                 "Credential store unavailable")
                return False
            context = auth.resolve_catalog_auth(
                store, index, presented, time.time(), grace)
            if context is None or context.principal.type != "device" \
                    or context.scope != "catalog" \
                    or context.secret_name not in (
                        "catalog_token", "catalog_token_prev") \
                    or not hmac.compare_digest(
                        username.encode("utf-8"),
                        context.principal.id.encode("utf-8")):
                return None
            return context.principal.id

        def _authorize_and_map(self):
            # Preserve the exact GET/HEAD flow of already-deployed Guest Shell
            # installers.  Matching is syntactic and happens before filesystem
            # lookup; a capability never authorizes an arbitrary sibling path.
            legacy_target = _legacy_guest_shell_target(self.path)
            if legacy_target is not None:
                self._legacy_guest_shell = True
                self._sensitive_staging = legacy_target.startswith("staging/")
                self._request_log_path = self.path
                self.path = "/" + legacy_target
                return True
            principal = self._authenticate()
            if principal is False:
                return False
            if principal is None and credentials is not None:
                api_problem.send(
                    self, 401, "artifact-authentication-required",
                    "Artifact authentication required",
                    headers=(("WWW-Authenticate", 'Basic realm="iris-artifacts", charset="UTF-8"'),))
                return False
            if credentials is None:
                # Existing isolated unit tests exercise filesystem hardening
                # directly. Production main() always supplies a secret store.
                return True
            raw = urlsplit(self.path).path
            if api_routes.match("artifact", self.command, self.path) is None:
                api_problem.send(self, 404, "route-not-found", "Route not found")
                return False
            parts = raw.split("/", 5)
            if len(parts) != 6 or parts[1:3] != ["v1", "devices"] \
                    or parts[4] != "artifacts" or not parts[5]:
                api_problem.send(self, 404, "route-not-found", "Route not found")
                return False
            resource_device = unquote(parts[3])
            if "/" in resource_device or "%" in resource_device \
                    or not hmac.compare_digest(
                    resource_device.encode("utf-8"), principal.encode("utf-8")):
                api_problem.send(self, 403, "artifact-resource-forbidden",
                                 "Artifact resource forbidden")
                return False
            self._request_log_path = self.path
            relative = unquote(parts[5])
            # SimpleHTTPRequestHandler would percent-decode once more in
            # translate_path. Reject any residual escape so a double-encoded
            # slash or '..' can never cross the authenticated device root.
            if "%" in relative or "\\" in relative:
                api_problem.send(self, 403, "artifact-resource-forbidden",
                                 "Artifact resource forbidden")
                return False
            if relative.startswith("staging/"):
                staging_parts = relative.split("/")
                if len(staging_parts) != 3 or not staging_parts[2] \
                        or staging_parts[1] != principal:
                    api_problem.send(self, 403,
                                     "artifact-resource-forbidden",
                                     "Artifact resource forbidden")
                    return False
                self._sensitive_staging = True
                relative = os.path.join("staging", principal,
                                        staging_parts[2])
            elif "/" in relative or not _PUBLIC_ARTIFACT.fullmatch(relative):
                api_problem.send(self, 403, "artifact-resource-forbidden",
                                 "Artifact resource forbidden")
                return False
            self.path = "/" + relative
            return True

        def _unsupported(self):
            """Authenticate before disclosing method handling or route shape."""
            principal = self._authenticate()
            if principal is False:
                return
            if principal is None and credentials is not None:
                api_problem.send(
                    self, 401, "artifact-authentication-required",
                    "Artifact authentication required",
                    headers=(("WWW-Authenticate",
                              'Basic realm="iris-artifacts", charset="UTF-8"'),))
                return
            api_problem.send(self, 405, "method-not-allowed",
                             "Method not allowed",
                             headers=(("Allow", "GET, HEAD"),))

        do_POST = _unsupported
        do_PUT = _unsupported
        do_DELETE = _unsupported
        do_PATCH = _unsupported
        do_OPTIONS = _unsupported

        def __getattr__(self, name):
            if name.startswith("do_"):
                return self._unsupported
            raise AttributeError(name)

        def list_directory(self, path):
            """Directory listing disabled — 404 on all directory requests."""
            self.send_error(404, "Not Found")
            return None

        def send_response_only(self, code, message=None):
            # Stashed so the access-log line below can report the status the
            # response actually carried, including errors raised by send_error.
            self._status = code
            super().send_response_only(code, message)

        def _access_checked(self):
            """Containment + staging-permission checks shared by GET and
            HEAD (IRIS-118). HEAD used to fall straight through to the stock
            SimpleHTTPRequestHandler.do_HEAD and skip both: a maliciously
            symlinked path or a loose-permission staging/ file leaked
            response HEADERS (Content-Length, Last-Modified, Content-Type)
            for a target a GET would have refused with 404/403. No body
            ever crossed either way -- HEAD never sends one -- but existence
            and metadata did, on the sensitive staging enrollment surface.
            Returns True iff the caller may
            proceed to super().do_GET()/do_HEAD(); on False the error
            response has already been sent."""
            resolved = self.translate_path(self.path)
            # translate_path strips dotted segments but never resolves
            # symlinks: a link inside the artifacts root would be followed
            # to any readable file outside it. Containment is decided on
            # the real path (the gui_server._read_deploy_log idiom).
            root = os.path.realpath(directory)
            real = os.path.realpath(resolved)
            if real != root and not real.startswith(root + os.sep):
                self.send_error(404, "Not Found")
                return False
            # Sweep staging/ for expired files before serving — this limits
            # credential exposure without breaking retries within the window.
            if (os.path.isfile(resolved) and
                    os.path.relpath(resolved, directory).startswith(
                        _STAGING_PREFIX)):
                # Files staged from OUTSIDE this container (remote SSH
                # staging, or a stage-host-local CLI run) are owned by a
                # foreign uid: chmod by a non-owner always raises EPERM, even
                # though the installer wrote the file with umask 077 (already
                # group/other-inaccessible). What matters is the file's
                # actual permission bits, not whether THIS process can
                # tighten them — so only attempt the chmod when we own the
                # file, and only fail closed when the mode is actually loose.
                try:
                    st = os.stat(resolved)
                except OSError:
                    self.send_error(403, "Staging file permissions are unsafe")
                    return False
                mode_already_tight = (st.st_mode & 0o077) == 0
                if os.geteuid() == st.st_uid:
                    # Co-located path: the installer (this process's own uid)
                    # created the file, so enforce least-privilege immediately
                    # before this process reads it — unchanged behavior. A
                    # chmod failure only fails the request when the mode is
                    # actually loose; if it's already tight the security
                    # property holds regardless of why the chmod failed.
                    try:
                        os.chmod(resolved, 0o600)
                    except OSError:
                        if not mode_already_tight:
                            self.send_error(
                                403, "Staging file permissions are unsafe")
                            return False
                elif not mode_already_tight:
                    # Foreign-owned (e.g. staged via remote SSH or a
                    # stage-host-local CLI run) and group/other-accessible:
                    # we cannot chmod a file we don't own, and the loose mode
                    # is unsafe, so fail closed.
                    self.send_error(403, "Staging file permissions are unsafe")
                    return False
                # else: foreign-owned but already mode-tight (installers
                # write with umask 077) — acceptable as-is, no chmod
                # attempted. If this uid still can't read it, that surfaces
                # as its own read failure below rather than a gratuitous 403
                # here.
                #
                # The sweep itself used to run HERE, once per staging GET: a
                # listdir + getmtime over the whole directory on the request
                # path, twice per device (iris-agent.conf and rpc-secret both
                # live under staging/), and able to unlink a file another
                # device was mid-fetch on -- the failure this function's own
                # STAGING_MAX_AGE_SECONDS comment records. It runs on a timer
                # from main() now; the permission check above, which is a
                # security property of THIS response, stays where it is.
            return True

        def _timed(self, run):
            """Shared inflight accounting + access-log line for GET and
            HEAD (factored out for IRIS-118, when HEAD gained the same
            checks as GET and therefore the same need for this wrapper)."""
            global _inflight
            with _inflight_lock:
                _inflight += 1
                peak = _inflight
            started = time.time()
            try:
                run()
            finally:
                with _inflight_lock:
                    _inflight -= 1
                # The one thing this server never recorded. Without a duration
                # here the only evidence a fetch was slow is the whole
                # onboarding job's wall clock, which is why the [5/7] share of
                # a slow fleet onboard could only ever be inferred.
                print("artifacts %s %s -> %s in %.3fs (inflight %d)"
                      % (self.command, redact_log_path(
                          getattr(self, "_request_log_path", self.path)),
                         getattr(self, "_status", "?"),
                         time.time() - started, peak),
                      flush=True)

        def do_GET(self):
            """Serve the file, with the staging permission check in front."""
            if self._authorize_and_map():
                self._timed(self._do_GET)

        def _do_GET(self):
            if self._access_checked():
                super().do_GET()

        def do_HEAD(self):
            """Same fail-closed treatment as do_GET (IRIS-118): HEAD must
            not disclose existence, size or mtime for a path GET would have
            refused."""
            if self._authorize_and_map():
                self._timed(self._do_HEAD)

        def _do_HEAD(self):
            if self._access_checked():
                super().do_HEAD()

        def log_message(self, *args):
            pass

    secure_staging_permissions(directory)
    ctx = None
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile)
    srv = _Server((host, port), Handler)
    # Set AFTER construction: _Server.get_request consults it, and nothing can
    # be accepted before serve_forever().
    srv.tls_context = ctx
    return srv


def start_sweeper(directory, interval=300):
    """Sweep staging/ on a timer instead of on the request path.

    Returns the daemon thread (started). The sweep is a directory scan that
    deletes credentials past STAGING_MAX_AGE_SECONDS; nothing about it needs
    to be synchronous with a fetch, and doing it per-GET meant a device could
    trigger the deletion of the very file it was asking for."""
    def _loop():
        while True:
            try:
                sweep_staging(directory)
            except Exception:
                pass    # a sweep failure must never take the server down
            time.sleep(interval)

    t = threading.Thread(target=_loop, name="staging-sweeper", daemon=True)
    t.start()
    return t


def main():
    host = os.environ.get("IRIS_ARTIFACTS_HOST", "0.0.0.0")
    port = int(os.environ.get("IRIS_ARTIFACTS_PORT", "8000"))
    directory = os.environ.get("IRIS_ARTIFACTS_DIR", "/srv/artifacts")
    cert = os.environ.get("IRIS_CERT", "/etc/iris/tls/cert.pem")
    certfile = cert if os.path.exists(cert) else None
    if certfile is None and not _plaintext_allowed():
        # Artifact requests carry resource-bound HTTP Basic credentials; a
        # plaintext listener puts them on the wire in clear text. Same
        # fail-closed contract as the console
        # (gui_server.main / IRIS_GUI_ALLOW_PLAINTEXT) and the catalog
        # (catalog.main / IRIS_CATALOG_ALLOW_PLAINTEXT): refuse to start
        # rather than silently downgrade. The shipped docker-entrypoint.sh
        # always provisions IRIS_CERT, so this is only reachable running
        # artifact_server.py directly outside the supported deployment.
        print("iris-artifacts: no certificate found (IRIS_CERT=%s); "
              "refusing to serve the artifact server over plain HTTP -- "
              "artifact requests carry device credentials. Set "
              "%s=1 to opt in deliberately (loopback or an isolated lab "
              "network only)." % (cert, _PLAINTEXT_OPT_IN_ENV),
              file=sys.stderr, flush=True)
        sys.exit(2)
    secrets_path = os.environ.get("IRIS_SECRETS", "/run/iris/secrets.json")
    srv = make_server(host, port, directory, certfile=certfile,
                      secrets_path=secrets_path)
    start_sweeper(directory)
    scheme = "https" if certfile else "http"
    print("artifacts on %s://%s:%d (dir %s)" % (scheme, host, port, directory),
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
