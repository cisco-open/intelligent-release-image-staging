# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""State-free static console and authenticated management-API BFF.

This process has no catalog, fleet, device, image, credential-store, or audit
mount.  Browsers retain the established HttpOnly session-cookie and CSRF
contract, but those controls are evaluated by the state-owning management
process after this BFF authenticates the tier hop.  Authorization supplied by
a browser is always discarded; only the file-mounted management credential is
sent upstream.
"""

import email.utils
import hashlib
import http.client
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import api_problem
import api_routes
import bounded_pool
import tier_auth


WEBROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webroot")
_SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy",
     "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"),
)
_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript",
    ".css": "text/css",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
}
_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "expect",
    "forwarded", "x-forwarded-for", "x-forwarded-host",
    "x-forwarded-proto", "x-real-ip", "x-iris-client-ip",
    "x-iris-client-scheme",
}
_RESPONSE_DROP = _HOP_HEADERS | {"server", "date"}
_HANDSHAKE_TIMEOUT = 30
_MAX_BODY = 64 * 1024
_MAX_CSV = 8 * 1024 * 1024
_MAX_BULK_DEVICE_IDS = 2 * 1024 * 1024
_MAX_OFFLINE_TAR = 256 * 1024 * 1024
_MAX_UPLOAD = 4 * 1024 * 1024 * 1024
_BODY_IDLE_TIMEOUT = 30
_BODY_TOTAL_MAX = 4 * 60 * 60


def _body_limit(target):
    """Mirror the state owner's established caps before proxy streaming."""
    path = urlsplit(target).path
    if path.startswith("/internal/v1/images/upload/"):
        return _MAX_UPLOAD
    if path == "/internal/v1/image-verification/offline":
        return _MAX_OFFLINE_TAR
    if path in ("/internal/v1/devices/import-csv",
                "/internal/v1/peer-policy/roles/import-csv"):
        return _MAX_CSV
    if path in ("/internal/v1/devices/bulk-credential",
                "/internal/v1/devices/bulk-role"):
        return _MAX_BULK_DEVICE_IDS
    return _MAX_BODY


class ConsoleConfigurationError(RuntimeError):
    """The BFF cannot establish its authenticated, verified upstream."""


def _tls_client_context(ca_file):
    if not ca_file:
        raise ConsoleConfigurationError("management CA is not configured")
    try:
        context = ssl.create_default_context(cafile=ca_file)
    except (OSError, ssl.SSLError):
        raise ConsoleConfigurationError("management CA is unavailable") from None
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def _backend_parts(url):
    try:
        parts = urlsplit(url)
    except ValueError:
        raise ConsoleConfigurationError("management API URL is invalid") from None
    if parts.scheme != "https" or not parts.hostname or parts.username \
            or parts.password or parts.query or parts.fragment:
        raise ConsoleConfigurationError("management API URL must be an https origin")
    prefix = parts.path.rstrip("/")
    return parts.hostname, parts.port or 443, prefix


def _token_pair(path, previous_path=None):
    try:
        current, previous = tier_auth.load_pair(path, previous_path)
        tokens = (current.decode("utf-8"),
                  previous.decode("utf-8") if previous is not None else None)
    except UnicodeError:
        raise ConsoleConfigurationError("management credential is invalid") from None
    # Bearer credentials must fit a single HTTP header without whitespace or
    # control characters. Reject malformed mounted values before networking,
    # where header-validation errors might otherwise include the credential.
    if any(token is not None and any(not 33 <= ord(char) <= 126 for char in token)
           for token in tokens):
        raise ConsoleConfigurationError("management credential is invalid")
    return tokens


def _current_token(path):
    return _token_pair(path)[0]


def _management_request(host, port, context, method, target, headers, tokens,
                        *, body=None, timeout=10):
    """Retry only a rejected tier credential, before any browser body is read.

    Callers may supply only a bodyless request or the bounded authorization
    preflight document. A streamed browser mutation never enters this helper.
    Return the accepted credential so preflight and mutation use the same one.
    """
    current, previous = tokens
    candidates = (current,) if previous is None else (current, previous)
    for token in candidates:
        conn = http.client.HTTPSConnection(host, port, context=context,
                                           timeout=timeout)
        try:
            outgoing = dict(headers, Authorization="Bearer " + token)
            conn.request(method, target, body=body, headers=outgoing)
            response = conn.getresponse()
            prefix = b""
            if (token == current and previous is not None
                    and response.status == 401
                    and response.getheader("WWW-Authenticate", "").strip() == "Bearer"
                    and response.getheader("Content-Type", "").split(";", 1)[0]
                    == "application/problem+json"):
                prefix = response.read(_MAX_BODY + 1)
                try:
                    problem = json.loads(prefix) if len(prefix) <= _MAX_BODY else None
                except (ValueError, UnicodeError):
                    problem = None
                if (isinstance(problem, dict) and problem.get("type") ==
                        api_problem.TYPE_BASE + "management-authentication-required"):
                    conn.close()
                    continue
            return conn, response, token, prefix
        except Exception:
            conn.close()
            raise


def _atomic_write(path, data):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".console-tls-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    finally:
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass


def _certificate_info(path, source):
    """Read public metadata for the identity loaded by this Console."""
    info = {"source": source if path else "none", "subject": "unknown",
            "issuer": "unknown", "not_after": "unknown",
            "fingerprint_sha256": "unknown"}
    if not path:
        return info
    try:
        with open(path, encoding="ascii") as stream:
            text = stream.read(2 * 1024 * 1024)
        start = text.index("-----BEGIN CERTIFICATE-----")
        end = text.index("-----END CERTIFICATE-----", start) + 25
        leaf = text[start:end]
        info["fingerprint_sha256"] = hashlib.sha256(
            ssl.PEM_cert_to_DER_cert(leaf)).hexdigest()
        # Pass only the public leaf to openssl, never the combined private key.
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate"],
            input=leaf, text=True, capture_output=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                name, _, value = line.partition("=")
                name = {"notAfter": "not_after"}.get(name, name)
                if name in ("subject", "issuer", "not_after") and value.strip():
                    info[name] = value.strip()
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        pass
    return info


def fetch_console_certificate(api_url, token_file, ca_file, output_path,
                              timeout=10, default_certfile=None,
                              default_keyfile=None, allow_unavailable_default=True,
                              previous_token_file=None):
    """Fetch the active console identity through the authenticated API.

    The combined PEM is written only to the console's runtime filesystem.  It
    never enters a persistent/shared volume and is never returned to a browser.
    """
    host, port, prefix = _backend_parts(api_url)
    context = _tls_client_context(ca_file)
    tokens = _token_pair(token_file, previous_token_file)
    conn = None
    use_default = False
    try:
        headers = {"Accept": "application/x-pem-file"}
        if default_certfile:
            headers["X-IRIS-Default-Certificate"] = "available"
        conn, response, _, buffered = _management_request(
            host, port, context, "GET", prefix + "/internal/v1/console-certificate",
            headers, tokens, timeout=timeout)
        body = buffered + response.read(1024 * 1024 + 1 - len(buffered))
        source = response.getheader("X-IRIS-Certificate-Source", "")
    except (OSError, ssl.SSLError, http.client.HTTPException):
        # Console readiness must not depend on the server tier during a cold
        # start. Kubernetes supplies an independent browser identity, so a
        # transport-unavailable management API may fall back to it. An API
        # response that is authenticated but invalid is handled below and is
        # never masked by this fallback.
        if not default_certfile or not allow_unavailable_default:
            raise ConsoleConfigurationError(
                "management API is unavailable") from None
        use_default = True
        body, source = b"", "default"
    finally:
        if conn is not None:
            conn.close()
    if not use_default:
        if response.status == 204 and source == "default" and default_certfile:
            use_default = True
        elif (response.status != 200 or source not in ("custom", "built-in")
              or len(body) > 1024 * 1024 or b"CERTIFICATE" not in body
              or b"PRIVATE KEY" not in body):
            raise ConsoleConfigurationError("console certificate is unavailable")
        elif default_certfile and source != "custom":
            # A default-aware management API must answer 204 without sending
            # its server/catalog private key. Do not silently accept a server
            # identity that crossed this trust boundary unexpectedly.
            raise ConsoleConfigurationError("console certificate is unavailable")
    if use_default:
        try:
            with open(default_certfile, "rb") as stream:
                body = stream.read(1024 * 1024 + 1)
            if default_keyfile:
                with open(default_keyfile, "rb") as stream:
                    body += b"\n" + stream.read(1024 * 1024 + 1)
        except OSError:
            raise ConsoleConfigurationError(
                "default console TLS identity is unavailable") from None
        if len(body) > 2 * 1024 * 1024:
            raise ConsoleConfigurationError(
                "default console TLS identity is oversized")
    # Validate before the atomic replacement so a bad upstream response can
    # never poison a previously usable runtime identity.
    directory = os.path.dirname(output_path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, probe_path = tempfile.mkstemp(dir=directory, prefix=".console-tls-probe-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(body)
        os.chmod(probe_path, 0o600)
        probe = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        probe.load_cert_chain(probe_path)
    except (OSError, ssl.SSLError):
        raise ConsoleConfigurationError("console certificate is unusable") from None
    finally:
        try:
            os.remove(probe_path)
        except FileNotFoundError:
            pass
    _atomic_write(output_path, body)
    return "custom" if not use_default and source == "custom" else "default"


class _ConsoleServer(bounded_pool.BoundedThreadingMixin, ThreadingHTTPServer):
    request_queue_size = 128
    max_concurrent_requests = 256
    tls_context = None

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.tls_context is not None:
            sock.settimeout(_HANDSHAKE_TIMEOUT)
        return sock, addr

    def process_request_thread(self, request, client_address):
        if self.tls_context is not None:
            try:
                request = self.tls_context.wrap_socket(request, server_side=True)
                request.settimeout(None)
            except (ssl.SSLError, OSError, ValueError):
                self.shutdown_request(request)
                return
        super().process_request_thread(request, client_address)


def make_server(host, port, api_url, token_file, ca_file, certfile=None,
                default_certfile=None, default_keyfile=None,
                cert_source="built-in", previous_token_file=None):
    backend_host, backend_port, backend_prefix = _backend_parts(api_url)

    class Handler(BaseHTTPRequestHandler):
        timeout = 60

        def _send(self, status, content_type, body, headers=()):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for name, value in _SECURITY_HEADERS:
                self.send_header(name, value)
            for name, value in headers:
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _probe(self, ready):
            doc = json.dumps({"ok": ready}, separators=(",", ":")).encode()
            headers = [("Cache-Control", "no-store")]
            if not ready:
                headers.append(("Retry-After", "1"))
            self._send(200 if ready else 503, "application/json", doc,
                       headers)

        def _serve_static(self, raw_path):
            path = urlsplit(raw_path).path
            rel = "index.html" if path in ("", "/") else path.lstrip("/")
            full = os.path.normpath(os.path.join(WEBROOT, rel))
            if not full.startswith(WEBROOT + os.sep) or not os.path.isfile(full):
                api_problem.send(self, 404, "route-not-found", "Route not found")
                return
            try:
                stat_result = os.stat(full)
                stamp = email.utils.formatdate(int(stat_result.st_mtime), usegmt=True)
                modified = self.headers.get("If-Modified-Since")
                if modified:
                    try:
                        since = email.utils.parsedate_to_datetime(modified).timestamp()
                    except (TypeError, ValueError, OverflowError):
                        since = -1
                    if int(since) >= int(stat_result.st_mtime):
                        self.send_response(304)
                        for name, value in _SECURITY_HEADERS:
                            self.send_header(name, value)
                        self.send_header("Cache-Control", "no-cache")
                        self.send_header("Last-Modified", stamp)
                        self.end_headers()
                        return
                with open(full, "rb") as stream:
                    body = stream.read()
            except OSError:
                api_problem.send(self, 404, "route-not-found", "Route not found")
                return
            self._send(200, _CONTENT_TYPES.get(os.path.splitext(full)[1],
                                               "application/octet-stream"),
                       body, (("Cache-Control", "no-cache"),
                              ("Last-Modified", stamp)))

        def _request_framing(self):
            """Return one unambiguous request length and any wire error.

            ``email.message.Message.get()`` returns only one occurrence, so
            using it for proxy framing lets a second Content-Length reach the
            upstream with different parsing semantics.  The BFF does not
            implement chunked request decoding; reject that syntax, and any
            TE/CL ambiguity, before forwarding a byte.
            """
            lengths = self.headers.get_all("Content-Length", [])
            encodings = self.headers.get_all("Transfer-Encoding", [])
            if encodings and lengths:
                return 0, (400, "invalid-content-length",
                           "Ambiguous request framing")
            if len(lengths) > 1:
                return 0, (400, "invalid-content-length",
                           "Ambiguous request framing")
            if encodings:
                return 0, (411, "content-length-required",
                           "Content-Length required")
            if not lengths:
                return 0, None
            raw = lengths[0]
            # Reject comma-joined duplicates, signs, whitespace and exotic
            # Unicode decimal characters.  Twenty ASCII digits already
            # exceed every supported body limit and bounds int conversion.
            if not raw or len(raw) > 20 or any(
                    char < "0" or char > "9" for char in raw):
                return 0, (400, "invalid-content-length",
                           "Invalid Content-Length")
            return int(raw), None

        def _upstream_headers(self, request_length, token):
            outgoing = {}
            for name, value in self.headers.items():
                low = name.lower()
                if low in _HOP_HEADERS or low in (
                        "authorization", "content-length", "if-match"):
                    continue
                outgoing[name] = value
            matches = self.headers.get_all("If-Match", [])
            if matches:
                # Preserve every conditional field across the dict-based hop.
                # The state owner's exact-singleton guard rejects the combined
                # list, including identical duplicates, with its current ETag.
                outgoing["If-Match"] = ", ".join(matches)
            outgoing["Authorization"] = "Bearer " + token
            # Exactly one BFF-validated framing header crosses the tier hop.
            outgoing["Content-Length"] = str(request_length)
            outgoing["Host"] = self.headers.get("Host", "")
            outgoing["X-IRIS-Client-IP"] = self.client_address[0]
            outgoing["X-IRIS-Client-Scheme"] = (
                "https" if srv.tls_active else "http")
            return outgoing

        def _authorize_mutation(self, target):
            """Ask the state owner to authorize headers before body transfer."""
            context = _tls_client_context(ca_file)
            payload = json.dumps({"method": self.command, "path": target},
                                 separators=(",", ":")).encode()
            headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(payload)),
            }
            for name in ("Cookie", "X-CSRF-Token"):
                if self.headers.get(name) is not None:
                    headers[name] = self.headers[name]
            for name in ("Host", "Origin", "Sec-Fetch-Site"):
                if self.headers.get(name) is not None:
                    headers[name] = self.headers[name]
            headers["X-IRIS-Client-IP"] = self.client_address[0]
            headers["X-IRIS-Client-Scheme"] = (
                "https" if srv.tls_active else "http")
            conn = None
            try:
                conn, response, token, buffered = _management_request(
                    backend_host, backend_port, context, "POST",
                    backend_prefix + "/internal/v1/authorizations", headers,
                    _token_pair(token_file, previous_token_file),
                    body=payload, timeout=self.timeout)
                body = buffered + response.read(_MAX_BODY + 1 - len(buffered))
                if len(body) > _MAX_BODY:
                    raise ConsoleConfigurationError("authorization response is oversized")
                response_headers = response.getheaders()
                status, reason = response.status, response.reason
            finally:
                if conn is not None:
                    conn.close()
            if status == 204:
                return token
            # Do not drain an untrusted rejected body: a client can declare a
            # length and then trickle nothing, pinning a worker before it gets
            # the already-known 401/403.  Close after the header-only verdict.
            self.send_response(status, reason)
            for name, value in response_headers:
                if name.lower() not in _RESPONSE_DROP:
                    self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD" and len(body) <= 64 * 1024:
                self.wfile.write(body)
            self.close_connection = True
            return None

        def _proxy(self):
            target = api_routes.console_to_management(self.command, self.path)
            if target is None:
                api_problem.send(self, 404, "route-not-found", "Route not found")
                return
            request_length, framing_error = self._request_framing()
            # Malformed framing is treated as body-bearing for the header-only
            # authorization gate.  Thus a known and unknown browser route
            # retain identical session/CSRF behavior before the uniform wire
            # error is disclosed.
            declared_body = framing_error is not None or request_length != 0
            authorized_token = None
            # HEAD responses omit the problem document that distinguishes
            # tier authentication from browser authentication. Select its
            # credential through the same header-only preflight as mutations.
            if self.command in ("POST", "PUT", "PATCH", "DELETE", "HEAD") \
                    or declared_body:
                try:
                    authorized_token = self._authorize_mutation(target)
                    if authorized_token is None:
                        return
                except (OSError, ssl.SSLError, http.client.HTTPException,
                        tier_auth.CredentialUnavailable,
                        ConsoleConfigurationError):
                    api_problem.send(self, 503, "management-api-unavailable",
                                     "Management API unavailable",
                                     headers=(("Retry-After", "1"),))
                    self.close_connection = True
                    return
            if framing_error is not None:
                status, code, title = framing_error
                api_problem.send(self, status, code, title)
                self.close_connection = True
                return
            if request_length > _body_limit(target):
                api_problem.send(self, 413, "payload-too-large",
                                 "Payload too large")
                self.close_connection = True
                return
            if self.command in ("GET", "HEAD") and request_length:
                api_problem.send(self, 400, "request-body-not-supported",
                                 "Request body not supported")
                self.close_connection = True
                return
            conn = None
            try:
                context = _tls_client_context(ca_file)
                buffered = b""
                if authorized_token is None:
                    tokens = _token_pair(token_file, previous_token_file)
                    conn, response, _, buffered = _management_request(
                        backend_host, backend_port, context, self.command,
                        backend_prefix + target,
                        self._upstream_headers(request_length, tokens[0]),
                        tokens, timeout=self.timeout)
                else:
                    conn = http.client.HTTPSConnection(
                        backend_host, backend_port, context=context,
                        timeout=self.timeout)
                    conn.putrequest(self.command, backend_prefix + target,
                                    skip_host=True, skip_accept_encoding=True)
                    for name, value in self._upstream_headers(
                            request_length, authorized_token).items():
                        conn.putheader(name, value)
                    conn.endheaders()
                    remaining = request_length
                    # A byte arriving just inside the inactivity timeout must not
                    # occupy one of the bounded BFF workers forever. Small JSON
                    # requests get 30s total; larger operator uploads receive a
                    # bounded allowance proportional to size, capped at four hours.
                    body_deadline = time.monotonic() + min(
                        _BODY_TOTAL_MAX,
                        30 + request_length / float(64 * 1024))
                    while remaining > 0:
                        budget = body_deadline - time.monotonic()
                        if budget <= 0:
                            raise TimeoutError("request body deadline exceeded")
                        self.connection.settimeout(min(_BODY_IDLE_TIMEOUT, budget))
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ConnectionError("request body ended early")
                        conn.send(chunk)
                        remaining -= len(chunk)
                    self.connection.settimeout(self.timeout)
                    response = conn.getresponse()
                public_path = urlsplit(self.path).path
                refresh = (response.status < 300 and public_path ==
                           "/api/v1/settings/gui-cert" and
                           self.command in ("POST", "DELETE"))
                local_settings = (response.status == 200 and
                                  self.command == "GET" and
                                  public_path == "/api/v1/settings")
                body = None
                if refresh or local_settings:
                    raw = response.read(4 * 1024 * 1024 + 1)
                    if len(raw) > 4 * 1024 * 1024:
                        raise ConsoleConfigurationError("settings response is oversized")
                    try:
                        payload = json.loads(raw)
                        if not isinstance(payload, dict):
                            raise ValueError()
                    except (ValueError, UnicodeError):
                        raise ConsoleConfigurationError("settings response is invalid") from None
                    if refresh:
                        applied = False
                        with srv.certificate_lock:
                            try:
                                if not certfile:
                                    raise ConsoleConfigurationError("Console TLS is disabled")
                                source = fetch_console_certificate(
                                    api_url, token_file, ca_file, certfile,
                                    default_certfile=default_certfile,
                                    default_keyfile=default_keyfile,
                                    allow_unavailable_default=False,
                                    previous_token_file=previous_token_file)
                                applied = srv.reload_tls(source)
                            except (ConsoleConfigurationError,
                                    tier_auth.CredentialUnavailable):
                                pass
                        payload["applied"] = applied
                        payload["note"] = (None if applied else
                            "saved; restart the Console to apply the certificate")
                    payload["gui_cert"] = dict(srv.certificate_info)
                    body = json.dumps(payload, separators=(",", ":")).encode()
                self.send_response(response.status, response.reason)
                has_cache = False
                for name, value in response.getheaders():
                    low = name.lower()
                    if low in _RESPONSE_DROP:
                        continue
                    if body is not None and low in ("content-length", "etag"):
                        continue
                    if low == "location":
                        if "/internal/v1/" in value:
                            value = value.replace("/internal/v1/", "/api/v1/", 1)
                        elif "/api/" in value:
                            value = value.replace("/api/", "/api/v1/", 1)
                    has_cache = has_cache or low == "cache-control"
                    self.send_header(name, value)
                for name, value in _SECURITY_HEADERS:
                    if not any(name.lower() == n.lower()
                               for n, _ in response.getheaders()):
                        self.send_header(name, value)
                if not has_cache:
                    self.send_header("Cache-Control", "private, no-store")
                if body is not None:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body is not None:
                    self.wfile.write(body)
                    return
                if buffered and self.command != "HEAD":
                    self.wfile.write(buffered)
                reader = getattr(response, "read1", response.read)
                while True:
                    chunk = reader(65536)
                    if not chunk:
                        break
                    if self.command != "HEAD":
                        self.wfile.write(chunk)
                        self.wfile.flush()
            except (OSError, ssl.SSLError, http.client.HTTPException,
                    tier_auth.CredentialUnavailable,
                    ConsoleConfigurationError):
                if not getattr(self, "_headers_buffer", None):
                    api_problem.send(self, 503, "management-api-unavailable",
                                     "Management API unavailable",
                                     headers=(("Retry-After", "1"),))
                self.close_connection = True
                return
            finally:
                if conn is not None:
                    conn.close()

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/healthz":
                self._probe(True)
            elif path == "/readyz":
                ready = os.path.isdir(WEBROOT) and os.path.isfile(ca_file)
                try:
                    _token_pair(token_file, previous_token_file)
                except (tier_auth.CredentialUnavailable,
                        ConsoleConfigurationError):
                    ready = False
                self._probe(ready)
            elif path.startswith("/api/") or path == "/swarmmap":
                self._proxy()
            else:
                self._serve_static(self.path)

        def do_POST(self):
            self._proxy()

        def do_PUT(self):
            self._proxy()

        def do_DELETE(self):
            self._proxy()

        def do_PATCH(self):
            self._proxy()

        def do_HEAD(self):
            self._proxy()

        def do_OPTIONS(self):
            self._proxy()

        def __getattr__(self, name):
            # BaseHTTPRequestHandler otherwise synthesizes an unauthenticated
            # 501 for arbitrary methods before the BFF can consult the state
            # owner. Route all method tokens through the same authenticated
            # proxy boundary.
            if name.startswith("do_"):
                return self._proxy
            raise AttributeError(name)

        def log_message(self, *args):
            pass

    srv = _ConsoleServer((host, port), Handler)
    context = None
    if certfile:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile)
        except (OSError, ssl.SSLError):
            srv.server_close()
            raise ConsoleConfigurationError("console TLS identity is unusable") from None
    elif os.environ.get("IRIS_GUI_ALLOW_PLAINTEXT", "") != "1":
        srv.server_close()
        raise ConsoleConfigurationError(
            "console TLS identity is unavailable; refusing plaintext")
    srv.tls_context = context
    srv.tls_active = context is not None
    srv.certificate_lock = threading.RLock()
    srv.certificate_info = _certificate_info(certfile, cert_source)

    def reload_tls(source=None):
        if context is None or not certfile:
            return False
        try:
            probe = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            probe.load_cert_chain(certfile)
            with srv.certificate_lock:
                info = _certificate_info(
                    certfile, "custom" if source == "custom" else
                    "built-in" if source == "default" else
                    srv.certificate_info["source"])
                srv.tls_context = probe
                srv.certificate_info = info
        except (OSError, ssl.SSLError):
            return False
        return True

    srv.reload_tls = reload_tls
    return srv


def main():
    host = os.environ.get("IRIS_GUI_HOST", "0.0.0.0")
    port = int(os.environ.get("IRIS_GUI_PORT", "8080"))
    api_url = os.environ.get("IRIS_MANAGEMENT_API_URL", "").strip()
    token_file = os.environ.get("IRIS_MANAGEMENT_API_TOKEN_FILE", "").strip()
    previous_token_file = os.environ.get(
        "IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE", "").strip() or None
    ca_file = os.environ.get("IRIS_MANAGEMENT_API_CA", "").strip()
    certfile = os.environ.get("IRIS_GUI_CERT", "/run/iris-console/cert.pem")
    default_certfile = os.environ.get("IRIS_GUI_DEFAULT_CERT", "").strip() or None
    default_keyfile = os.environ.get("IRIS_GUI_DEFAULT_KEY", "").strip() or None
    try:
        plaintext = os.environ.get("IRIS_GUI_ALLOW_PLAINTEXT", "") == "1"
        source = "none"
        if not plaintext:
            source = fetch_console_certificate(
                api_url, token_file, ca_file, certfile,
                default_certfile=default_certfile,
                default_keyfile=default_keyfile,
                previous_token_file=previous_token_file)
        server = make_server(host, port, api_url, token_file, ca_file,
                             certfile=None if plaintext else certfile,
                             default_certfile=default_certfile,
                             default_keyfile=default_keyfile,
                             cert_source="custom" if source == "custom" else "built-in",
                             previous_token_file=previous_token_file)
    except (ConsoleConfigurationError, tier_auth.CredentialUnavailable) as exc:
        print("iris-console: %s; refusing to start" % exc,
              file=sys.stderr, flush=True)
        sys.exit(2)
    print("iris-console on %s://%s:%d/" % (
        "http" if plaintext else "https", host, port), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
