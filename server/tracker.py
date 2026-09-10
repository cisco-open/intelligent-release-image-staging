#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Private BitTorrent tracker for IRIS. Token-gated /announce + /scrape,
peer lifecycle via peer_registry, bencoded responses, optional compact peers.
Stdlib only. Run as a service: python3 tracker.py (reads IRIS_* env)."""
import binascii
import collections
import ipaddress
import json
import os
import random
import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote_to_bytes, urlparse

import auth
import api_routes
import bencode
import blocklist_reconciler as _reconciler
import bounded_pool
import credential_cache
import peer_endpoints as _peer_endpoints
import peer_handouts as _peer_handouts
import peer_enforcement as _peer_enforcement
import peer_policy as _peer_policy
import origin_qos as _origin_qos
import reconciler_status as _status_codes
import secrets_store
import telemetry
from peer_registry import PeerRegistry, INTERVAL, NUMWANT_CAP

MIN_INTERVAL = 10
MAX_INTERVAL = 300

LegacyAttributions = collections.namedtuple(
    "LegacyAttributions", ["by_ip", "unreadable", "revoked"])


def _stat_key(path):
    """Return a replacement-sensitive identity for one durable file."""
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size, st.st_ino)
    except OSError:
        return None


class PolicySnapshot:
    """Thread-safe cache of one complete peer-policy load result.

    Both authoritative and LKG identities participate in the key. A restat
    after loading prevents publishing a result assembled while either path
    was replaced.
    """

    def __init__(self, authoritative_path, lkg_path, loader=None):
        self._paths = (authoritative_path, lkg_path)
        self._loader = loader or _peer_policy.load_policy
        self._key = None
        self._result = None
        self._lock = threading.Lock()

    def _keys(self):
        return tuple(_stat_key(path) for path in self._paths)

    def load(self):
        with self._lock:
            while True:
                before = self._keys()
                if self._result is not None and before == self._key:
                    return self._result
                result = self._loader(*self._paths)
                after = self._keys()
                if before == after:
                    self._key = after
                    self._result = result
                    return result


def jittered_interval(interval, factor=None):
    """Apply per-announce ±10 percent jitter and schema-bound the result."""
    if factor is None:
        factor = random.uniform(0.9, 1.1)
    return max(MIN_INTERVAL, min(MAX_INTERVAL, int(round(interval * factor))))

# Per-connection socket inactivity timeout (seconds), same posture as the
# catalog handler: a client that opens a connection and never completes its
# request line must not hold a thread and a file descriptor for the life of
# the server. IRIS_HTTP_TIMEOUT overrides; garbage/non-positive -> default.
HANDLER_TIMEOUT = 30.0

# A TCP client that never sends a TLS ClientHello must occupy only its bounded
# worker, never the single accept loop.  Keep the bound independent from the
# HTTP request timeout: the latter is re-armed by BaseHTTPRequestHandler after
# the handshake completes.
_HANDSHAKE_TIMEOUT = 30


def handler_timeout(env=None):
    raw = (os.environ if env is None else env).get("IRIS_HTTP_TIMEOUT")
    try:
        value = float(raw) if raw else HANDLER_TIMEOUT
    except (TypeError, ValueError):
        return HANDLER_TIMEOUT
    return value if value > 0 else HANDLER_TIMEOUT


class _TrackerServer(bounded_pool.BoundedThreadingMixin, ThreadingHTTPServer):
    """ThreadingHTTPServer with a fleet-sized accept backlog and a bounded
    pool of concurrently running handler threads.  TLS handshakes happen in
    those workers, not on the listening socket.

    The stdlib default ``request_queue_size`` is 5. Every peer in the swarm
    re-announces on the same interval, so a rollout burst overflows the
    accept queue and the kernel answers with RSTs -- a peer then sees a
    connection reset instead of a slow answer, and drops out of the swarm.
    Matches gui_server._ConsoleServer and catalog._CatalogServer.

    ``ThreadingMixIn.process_request`` spawns one thread per connection with
    no cap -- see bounded_pool.py for why that is unsafe and how the mixin
    bounds it without risking a deadlock on a long-lived connection.
    """

    request_queue_size = 128
    tls_context = None
    # No long-lived connections here -- announce/scrape are bounded bencoded
    # exchanges. Sized to the fleet-sized accept backlog above.
    max_concurrent_requests = 256

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.tls_context is not None:
            sock.settimeout(_HANDSHAKE_TIMEOUT)
        return sock, addr

    def process_request_thread(self, request, client_address):
        if self.tls_context is not None:
            try:
                request = self.tls_context.wrap_socket(request,
                                                       server_side=True)
            except (ssl.SSLError, OSError, ValueError):
                # A failed or timed-out handshake is this connection's
                # problem and must not stall announces from the rest of the
                # fleet.
                self.shutdown_request(request)
                return
            try:
                request.settimeout(None)   # Handler.timeout re-arms it
            except OSError:
                pass
        super().process_request_thread(request, client_address)


def _valid_ipv4(addr):
    """Return True iff *addr* is a valid dotted-quad IPv4 address whose four
    octets are each in 0-255.  socket.inet_aton accepts some non-dotted-quad
    forms on some platforms, so we verify the structure explicitly."""
    try:
        parts = addr.split(".")
        if len(parts) != 4:
            return False
        socket.inet_aton(addr)          # raises OSError for garbage
        return all(0 <= int(p) <= 255 for p in parts)
    except (OSError, ValueError):
        return False


# Exactly the address space a fleet peer may claim: the three RFC1918
# networks plus carrier-grade NAT. `is_private` would be broader — it also
# admits loopback, link-local, unspecified and reserved ranges, which would
# then be advertised to every other peer as a download endpoint.
_OVERRIDE_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))


def _private_override(addr):
    """Allow NAT overrides only for non-routable fleet address space.

    Containerized seeders need this because their socket source is loopback or
    bridge-local. RFC1918 and carrier-grade NAT (used by deployed fleets) are
    accepted; everything else — public endpoints, loopback, link-local — is
    not.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.version == 4 and any(ip in net for net in _OVERRIDE_NETS)


def parse_announce(query):
    """Parse /announce query, preserving the BINARY info_hash (unquote_to_bytes —
    a raw 20-byte hash is not valid UTF-8). Returns a dict of typed fields."""
    raw = {}
    for kv in query.split("&"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            raw[k] = v

    def as_int(name, default):
        try:
            return int(raw.get(name, default))
        except (TypeError, ValueError):
            return default

    def as_nonnegative(name):
        value = as_int(name, None)
        return value if value is not None and value >= 0 else None
    # Port must be in 1-65535; clamp to default on bad input.
    raw_port = as_int("port", 6881)
    port = raw_port if 1 <= raw_port <= 65535 else None

    # BEP3 optional ip= override — retain it for container/NAT deployments, but
    # only for private/CGNAT dotted-quad IPv4. Public endpoints always come
    # from the authenticated connection's socket source. The tracker further
    # honours it ONLY for a service principal (the containerized seeder, whose
    # socket source is loopback/bridge-local): see _handle_announce.
    raw_ip = raw.get("ip") or None
    ip = raw_ip if raw_ip is not None and _valid_ipv4(raw_ip) \
        and _private_override(raw_ip) else None

    return {
        "info_hash": binascii.hexlify(
            unquote_to_bytes(raw.get("info_hash", ""))).decode(),
        "peer_id": unquote_to_bytes(raw.get("peer_id", "")).decode(
            "latin1", "replace"),
        "port": port,
        "left": as_int("left", None) if "left" in raw else None,
        "event": raw.get("event"),
        "numwant": as_int("numwant", 50),
        "compact": raw.get("compact") == "1",
        "ip": ip,
        "uploaded": as_nonnegative("uploaded"),
        "downloaded": as_nonnegative("downloaded"),
    }


def compact_peers(peers):
    """Encode *peers* in BEP3 compact format (4-byte IP + 2-byte port each).
    Entries whose ip is not a valid dotted-quad IPv4 or whose port is outside
    0-65535 are silently skipped so one bad peer cannot abort the entire
    response for the rest of the swarm."""
    out = bytearray()
    for p in peers:
        try:
            ip_bytes = bytes(int(o) for o in p["ip"].split("."))
            if len(ip_bytes) != 4:
                continue
            port = p["port"]
            port_bytes = bytes([port >> 8, port & 0xFF])
            out += ip_bytes + port_bytes
        except (ValueError, TypeError):
            continue
    return bytes(out)


def build_announce_response(peers, compact=False, interval=INTERVAL,
                            min_interval=None):
    if compact:
        peers_value = compact_peers(peers)
    else:
        peers_value = [{"ip": p["ip"], "peer id": "", "port": p["port"]}
                       for p in peers]
    if min_interval is None:
        min_interval = interval
    return bencode.encode({
        "interval": interval,
        "min interval": min_interval,
        "peers": peers_value,
    })


def build_scrape_response(info_hash_hex, stats):
    # files key is the RAW info_hash bytes (BEP 48)
    raw = binascii.unhexlify(info_hash_hex)
    return bencode.encode({"files": {raw: stats}})


def build_failure(reason):
    return bencode.encode({"failure reason": reason})


def _legacy_id(peer_ip, peer_port):
    """The nonsecret endpoint-derived key for a legacy principal (spec §0a):
    ``<ipv4>:<port>``. Derived from the effective endpoint, never a token."""
    return "%s:%s" % (peer_ip, peer_port if peer_port is not None else "")


def _catalog_scrape_authorizer(state_dir):
    """Return a fail-closed device assignment check for ``/scrape``.

    The tracker and catalog share the server tier's durable state, but remain
    separate listeners. Reuse CatalogStore's sharded/locked reads instead of
    adding a second parser for policy.json and catalog.json here.
    """
    # Keep the tracker module lightweight for callers that only use its BEP
    # parsing and registry helpers.
    import catalog as _catalog

    store = _catalog.CatalogStore(state_dir)

    def allowed(device_id, info_hash):
        try:
            image_ids = store.get_policy(device_id)["approved_image_ids"]
            return any(
                str((store.get_image(image_id) or {}).get(
                    "info_hash_hex", "")).lower() == info_hash.lower()
                for image_id in image_ids)
        except (_catalog.StateFileError, OSError, ValueError, TypeError):
            return False

    return allowed


def _bounded_legacy_retention(policy, revoked, now, role_until):
    """Retain deny evidence indefinitely and role-only evidence temporarily."""
    compiled = policy.roles

    def keep(principal_type, principal_id, ipv4):
        principal_key = "%s:%s" % (principal_type, principal_id)
        if principal_key in revoked:
            return True
        if policy.fail_closed or principal_type != "device":
            return False
        principal = auth.Principal(principal_type, principal_id)
        if _peer_policy.evaluate(
                policy.document, principal, ipv4,
                compiled=compiled)[0] == "deny":
            return True
        role = compiled.role_of.get(principal_id)
        role_active = now < role_until
        return role_active and role in compiled.restricted

    return keep


def _legacy_token_deadline(store, grace=0):
    """Last instant at which any previous seeder token can authenticate."""
    deadlines = []
    previous = store.get("seeder", {}).get("announce_token_previous", [])
    for record in previous if isinstance(previous, list) else ():
        if not isinstance(record, dict) or record.get("revoked"):
            continue
        expires_at = record.get("expires_at")
        if isinstance(expires_at, (int, float)) and not isinstance(
                expires_at, bool) and expires_at > 0:
            deadlines.append(expires_at + grace)
    return max(deadlines) if deadlines else 0


def legacy_attributions(policy, endpoints_path, store, now, grace=0):
    """Return all durable device principals attributable to each IPv4.

    Shared addresses retain every principal so callers can apply universal,
    deny-wins policy evaluation. A corrupt or unreadable store is represented
    explicitly and makes legacy discovery fail closed.
    """
    if endpoints_path is None:
        return LegacyAttributions({}, False, frozenset())
    revoked = set(secrets_store.revoked_device_principals(store))
    role_until = _legacy_token_deadline(store, grace)
    try:
        durable = _peer_endpoints.fresh_endpoints(
            endpoints_path, now, keep=_bounded_legacy_retention(
                policy, revoked, now=now, role_until=role_until))
    except (OSError, _peer_endpoints.EndpointStoreError):
        return LegacyAttributions({}, True, frozenset(revoked))
    by_ip = {}
    for entry in durable.values():
        if entry.get("principal_type") != "device":
            continue
        principal = auth.Principal("device", entry.get("principal_id", ""))
        for endpoint in entry.get("endpoints", ()):
            by_ip.setdefault(endpoint.get("ipv4"), set()).add(principal)
    return LegacyAttributions({
        ip: tuple(sorted(principals)) for ip, principals in by_ip.items()
        if ip is not None
    }, False, frozenset(revoked))


def make_server(host, port, secrets_path, registry=None, on_announce=None,
                policy_paths=None, endpoints_path=None, pending_queue=None,
                record_endpoint=None, on_endpoint_failure=None,
                on_endpoint_change=None, on_announce_refused=None,
                scrape_authorizer=None, certfile=None, handout_path=None,
                record_handout=None, on_handout_failure=None):
    """Build the tracker server (TLS when *certfile* is supplied).

    Typed identity/policy integration (spec §6/§7):

    * ``policy_paths`` — ``(authoritative, lkg)`` for ``peer_policy``. When
      given, candidate discovery is filtered by the typed mutual-permit
      predicate; a ``fail_closed`` policy yields zero candidates. When absent,
      discovery is unfiltered (legacy/open behaviour).
    * ``endpoints_path`` — durable ``peer-endpoints.json`` written on an
      attributable (device/service) valid-port announce. Legacy principals are
      never persisted.
    * ``pending_queue`` — the tracker-owned :class:`PendingEndpointQueue`; on a
      durable endpoint write failure the latest tuple is enqueued for retry and
      ``on_endpoint_failure`` is invoked (degrade signal / local wake) without
      changing the HTTP 200 or the policy filtering.
    * ``record_endpoint`` — injectable endpoint writer (defaults to
      ``peer_endpoints.record_endpoint``); used for failure-injection tests.
    * ``on_announce_refused`` — called with one keyword, ``expired`` (bool),
      whenever an /announce or /scrape credential is refused (IRIS-111): a
      403 answers with no operator-visible signal otherwise, and
      ``iris_legacy_announce_participants`` reads 0 identically whether the
      fleet fully migrated or every un-migrated device just aged out of
      SEEDER_PREV_TTL and can no longer authenticate to be counted.
      ``expired=True`` means the presented credential resolved to a known,
      non-revoked record that failed only because it timed out -- the
      SEEDER_PREV_TTL overlap case this counter exists for.
    * ``scrape_authorizer`` — ``(device_id, info_hash_hex) -> bool`` binding a
      device scrape to its current catalog assignment. Missing/failing checks
      deny device principals; service and bounded legacy principals retain
      their compatibility-wide tracker view.
    """
    registry = registry or PeerRegistry()
    # One stat-validated snapshot of the secret store and its strict announce
    # index, shared by every announce. Every announce used to re-parse the
    # whole store and rebuild a fleet-wide index to resolve one credential;
    # the snapshot rebuilds only when the store file changes on disk, which
    # every mint/rotate/revoke causes. See credential_cache.
    _credentials = credential_cache.CredentialResolver(secrets_path)
    _grace = int(os.environ.get("IRIS_TOKEN_SKEW_GRACE", "300"))
    _record_endpoint = record_endpoint or _peer_endpoints.record_endpoint
    _record_handout = record_handout or _peer_handouts.record_handout
    _policy_snapshot = (PolicySnapshot(*policy_paths)
                        if policy_paths is not None else None)

    def _load_policy():
        if _policy_snapshot is None:
            return None
        return _policy_snapshot.load()

    class Handler(BaseHTTPRequestHandler):
        # Socket inactivity timeout (see HANDLER_TIMEOUT): a stalled read
        # raises TimeoutError inside handle_one_request, which closes the
        # connection and releases the thread.
        timeout = handler_timeout()

        def _send(self, status, body):
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            if status in (401, 403):
                self.send_header("WWW-Authenticate", "Bearer")
            if status == 503:
                self.send_header("Retry-After", "1")
            if getattr(self, "_legacy_query_auth", False):
                # Unchanged Guest Shell aria2 bundles cannot attach a
                # per-download HTTP header.  Make the bounded compatibility
                # path visible to operators and caches while new IOx/XR agents
                # use the preferred Bearer transport.
                self.send_header("Deprecation", "true")
                self.send_header("Vary", "Authorization")
            self.end_headers()
            self.wfile.write(body)

        def _extract_token(self):
            value = self.headers.get("Authorization", "")
            if not value.startswith("Bearer ") or value.count(" ") != 1:
                return None
            return value[7:] or None

        def _resolve_principal(self, token, query, store, index, now,
                               peer_ip=None, peer_port=None):
            """Resolve Bearer first, or the Guest Shell query fallback.

            Presence of any Authorization header disables query fallback, so
            a malformed/invalid preferred credential cannot be downgraded to
            a URL credential.  The legacy id is an endpoint-derived nonsecret
            key, never the presented token.
            """
            try:
                if self.headers.get("Authorization") is not None:
                    return auth.resolve_announce_bearer(
                        token, index, store, now, _grace,
                        legacy_id=_legacy_id(peer_ip, peer_port))
                ctx = auth.resolve_announce_principal(
                    query, index, store, now, _grace,
                    legacy_id=_legacy_id(peer_ip, peer_port))
                self._legacy_query_auth = True
                return ctx
            except auth.AnnounceAuthError as exc:
                if on_announce_refused is not None:
                    on_announce_refused(expired=exc.expired)
                return None

        def do_GET(self):
            parsed = urlparse(self.path)
            query = parsed.query
            try:
                store, index = _credentials.view(
                    "announce", secrets_store.build_announce_index)
            except (secrets_store.DuplicateCredentialError,
                    secrets_store.StoreCorruptError, OSError):
                # A hard configuration error (two records share a value) is a
                # token-free 403 — never a silent overwrite (spec §6).
                self._send(503, build_failure("credential store unavailable"))
                return
            now = time.time()
            # Resolve authentication before route matching or request-shape
            # validation. Authorization is preferred; query credentials are a
            # bounded compatibility path for unchanged Guest Shell bundles.
            ctx = self._resolve_principal(
                self._extract_token(), query, store, index, now)
            if ctx is None:
                self._send(401 if self.headers.get("Authorization") is not None
                           else 403,
                           build_failure("missing or invalid token"))
                return
            if api_routes.match("tracker", "GET", self.path) is None:
                self._send(404, build_failure("not found"))
                return
            if parsed.path == "/announce":
                self._handle_announce(query, store, index, now, ctx)
            elif parsed.path == "/scrape":
                self._handle_scrape(query, ctx)
            else:
                self._send(404, build_failure("not found"))

        def _unsupported(self):
            """Authenticate before returning a method/route result."""
            try:
                store, index = _credentials.view(
                    "announce", secrets_store.build_announce_index)
            except (secrets_store.DuplicateCredentialError,
                    secrets_store.StoreCorruptError, OSError):
                self._send(503, build_failure("credential store unavailable"))
                return
            ctx = self._resolve_principal(
                self._extract_token(), urlparse(self.path).query,
                store, index, time.time())
            if ctx is None:
                self._send(401 if self.headers.get("Authorization") is not None
                           else 403,
                           build_failure("missing or invalid token"))
                return
            body = build_failure("method not allowed")
            self.send_response(405)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Allow", "GET")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_POST = _unsupported
        do_PUT = _unsupported
        do_DELETE = _unsupported
        do_PATCH = _unsupported
        do_HEAD = _unsupported
        do_OPTIONS = _unsupported

        def __getattr__(self, name):
            if name.startswith("do_"):
                return self._unsupported
            raise AttributeError(name)

        def _handle_announce(self, query, store, index, now, ctx):
            a = parse_announce(query)
            state = "seeder" if a["left"] == 0 else "leecher"
            socket_ip = self.client_address[0]
            # The legacy id is derived from the SOCKET endpoint: a legacy
            # credential never earns the ip= override (below), so this is
            # its effective endpoint.
            if ctx.principal.type == "legacy":
                ctx = auth.AuthContext(
                    auth.Principal("legacy", _legacy_id(socket_ip, a["port"])),
                    ctx.secret_name, ctx.scope)
            if on_announce is not None:
                on_announce()
            # Validate info_hash AFTER auth so an unauthenticated caller learns
            # nothing about the request shape.
            if len(a["info_hash"]) != 40:
                self._send(400, build_failure("info_hash must be 20 bytes"))
                return
            principal = ctx.principal
            # Effective peer IP: the explicit override (already allowlisted to
            # RFC1918 + CGNAT by parse_announce) is honoured ONLY for a
            # service principal -- the containerized seeder, whose socket
            # source is loopback/bridge-local. A device's durable endpoint is
            # what the seeder blocklist is derived from, so a device that
            # could name its own address could plant a permitted row on a
            # quarantined device's address (lifting that block through the
            # shared permit/deny conflict) or have arbitrary fleet addresses
            # blocked; devices therefore always get the socket source.
            if a["ip"] and principal.type == "service":
                peer_ip = a["ip"]
            else:
                peer_ip = socket_ip
            policy = _load_policy()
            attribution_cache = []

            def get_attributions():
                if not attribution_cache:
                    attribution_cache.append(legacy_attributions(
                        policy, endpoints_path, store, now, grace=_grace))
                return attribution_cache[0]

            qos = self._announce_qos(
                policy, principal, peer_ip, get_attributions, state)
            issued_interval = jittered_interval(
                qos.get("announce_min_interval_s", INTERVAL))
            effective_numwant = min(
                max(a["numwant"], 0), qos.get("numwant", 50))
            legacy_restricted = self._legacy_restricted(
                policy, principal, peer_ip, get_attributions)
            # port=None means the client sent an out-of-range value. Registering
            # a substitute port would advertise a wrong endpoint; skip
            # registration AND any durable endpoint write, but still 200.
            if a["port"] is None:
                peers = self._select(
                    a, principal, peer_ip, policy, get_attributions,
                    effective_numwant)
                peers = self._record_selected(
                    principal, peers, a["info_hash"], now)
                self._send(200, build_announce_response(
                    peers, compact=a["compact"], interval=issued_interval,
                    min_interval=issued_interval))
                return
            peer_port = a["port"]
            # Register the typed peer BEFORE candidate filtering so a valid
            # (even quarantined) announce is 200 and visible in the swarm.
            registry.announce(a["info_hash"], a["peer_id"], peer_ip, peer_port,
                              event=a["event"], left=a["left"],
                              principal=principal, now=now,
                              interval=issued_interval,
                              uploaded=a["uploaded"],
                              downloaded=a["downloaded"],
                              legacy_restricted=legacy_restricted)
            # Durable endpoint write for attributable principals only. Failure
            # never changes the HTTP 200 or the policy filtering: enqueue the
            # latest pending tuple and signal a degrade / local wake.
            self._persist_endpoint(principal, peer_ip, peer_port, now)
            peers = self._select(
                a, principal, peer_ip, policy, get_attributions,
                effective_numwant)
            peers = self._record_selected(
                principal, peers, a["info_hash"], now)
            self._send(200, build_announce_response(
                peers, compact=a["compact"], interval=issued_interval,
                min_interval=issued_interval))

        @staticmethod
        def _record_selected(principal, peers, info_hash, now):
            """Persist device disclosure evidence before response encoding.

            Service and compatibility principals are outside this ledger.
            With no ledger path the constructor retains its legacy/test
            behavior; production always supplies one.
            """
            if principal.type != "device" or not peers or handout_path is None:
                return peers
            try:
                covered = _record_handout(
                    handout_path, principal, peers, info_hash, now)
                if covered is False:
                    raise _peer_handouts.HandoutStoreError(
                        "handout persistence refused")
            except Exception:
                if on_handout_failure is not None:
                    try:
                        on_handout_failure()
                    except Exception:
                        pass
                return []
            return peers

        def _persist_endpoint(self, principal, peer_ip, peer_port, now):
            if endpoints_path is None:
                return
            if principal.type not in ("device", "service"):
                return  # legacy is never persisted as an attributable endpoint
            try:
                _record_endpoint(endpoints_path, principal, peer_ip,
                                 peer_port, now)
            except (OSError, _peer_endpoints.EndpointStoreError):
                # A corrupt store (EndpointStoreError) is a write failure like
                # any other for this path: the announce still gets its 200
                # and peer list, the tuple waits in the pending queue (which
                # the reconciler also derives from), and the reconciler
                # reports the store state. Mirrors retry_pending.
                if pending_queue is not None:
                    pending_queue.enqueue(principal, peer_ip, peer_port, now)
                if on_endpoint_failure is not None:
                    on_endpoint_failure()
                return
            # A tracker-authored durable change: wake the reconciler for
            # immediate (sub-poll) application.
            if on_endpoint_change is not None:
                on_endpoint_change()

        @staticmethod
        def _attributed_principals(principal, peer_ip, attributions):
            if principal is None or principal.type != "legacy":
                return (principal,)
            if attributions is None:
                return (principal,)
            if attributions.unreadable:
                return ()
            return attributions.by_ip.get(peer_ip, (principal,))

        @staticmethod
        def _announce_qos(policy, principal, peer_ip, get_attributions,
                          state):
            if policy is None:
                return {"announce_min_interval_s": INTERVAL,
                        "numwant": NUMWANT_CAP}
            if principal.type == "device":
                return _peer_policy.compile_tracker_qos(
                    policy.document, principal.id, state)
            if principal.type == "legacy":
                attributions = get_attributions()
            else:
                attributions = None
            if attributions is not None and not attributions.unreadable:
                attributed = attributions.by_ip.get(peer_ip, ())
                if attributed:
                    values = [_peer_policy.compile_tracker_qos(
                        policy.document, item.id, state)
                              for item in attributed]
                    # A shared NAT address receives the slowest cadence and
                    # smallest handout ceiling of every possible owner.
                    result = dict(values[0])
                    result["announce_min_interval_s"] = max(
                        item["announce_min_interval_s"] for item in values)
                    result["numwant"] = min(item["numwant"] for item in values)
                    return result
            return _peer_policy.compile_tracker_qos(
                policy.document, None, state)

        @staticmethod
        def _legacy_restricted(policy, principal, peer_ip, get_attributions):
            if policy is None or principal.type != "legacy":
                return False
            attributions = get_attributions()
            if policy.fail_closed or attributions.unreadable:
                return True
            for attributed in attributions.by_ip.get(peer_ip, ()):
                key = "%s:%s" % (attributed.type, attributed.id)
                if key in attributions.revoked:
                    return True
                role = policy.roles.role_of.get(attributed.id)
                if role in policy.roles.restricted:
                    return True
                if _peer_policy.evaluate(
                        policy.document, attributed, peer_ip,
                        compiled=policy.roles)[0] == "deny":
                    return True
            return False

        @staticmethod
        def _restricted_candidates(policy, principal):
            """Return sparse registry indexes for a virtual-role requester."""
            if principal.type != "device":
                return None
            if principal.id in policy.document.get("assignments", {}) or \
                    _peer_policy.is_quarantined(policy.document, principal.id):
                return None
            compiled = policy.roles
            role = compiled.role_of.get(principal.id)
            if role not in compiled.restricted:
                return None
            definitions = policy.document.get("roles", {}).get("defs", {})
            definition = definitions.get(role, {})
            allowed_roles = set(definition.get("peers", [role]))
            allowed_roles.add(role)
            principals = set()
            if _peer_policy.role_origin_enabled(policy.document, role):
                principals.add(("service", "seeder"))
            return frozenset(allowed_roles), frozenset(principals)

        def _select(self, a, principal, peer_ip, policy, get_attributions,
                    numwant):
            if policy is None:
                return registry.peers(a["info_hash"], a["peer_id"],
                                      numwant=numwant)
            if policy.fail_closed:
                return []
            doc = policy.document
            if self._legacy_restricted(
                    policy, principal, peer_ip, get_attributions):
                return []

            def predicate(req_p, req_ip, cand_p, cand_ip):
                if ((req_p is not None and req_p.type == "legacy") or
                        cand_p.type == "legacy"):
                    attributions = get_attributions()
                else:
                    attributions = None
                requesters = self._attributed_principals(
                    req_p, req_ip, attributions)
                candidates = self._attributed_principals(
                    cand_p, cand_ip, attributions)
                if not requesters or not candidates:
                    return False
                if attributions is not None and any(
                        "%s:%s" % (item.type, item.id) in attributions.revoked
                        for item in requesters + candidates):
                    return False
                return all(
                    _peer_policy.mutual_permit(
                        doc, requester, req_ip, candidate, cand_ip,
                        compiled=policy.roles)
                    for requester in requesters for candidate in candidates)

            sparse = self._restricted_candidates(policy, principal)
            kwargs = {}
            if sparse is not None:
                kwargs["candidate_roles"] = sparse[0]
                kwargs["candidate_principals"] = sparse[1]
                kwargs["candidate_types"] = frozenset({"legacy"})
                kwargs["compiled_roles"] = policy.roles
            return registry.select_peers(
                a["info_hash"], a["peer_id"], principal, peer_ip,
                predicate=predicate, numwant=numwant, **kwargs)

        def _handle_scrape(self, query, ctx):
            # Parse the RAW query like parse_announce: a real info_hash is 20
            # raw SHA-1 bytes and not valid UTF-8, so parse_qs (which decodes
            # escapes as UTF-8) mangled it — crash on high bytes, silent
            # corruption on accidentally-valid multibyte sequences.
            quoted = None
            for kv in query.split("&"):
                if kv.startswith("info_hash="):
                    quoted = kv.split("=", 1)[1]
                    break
            if not quoted:
                self._send(400, build_failure("scrape requires info_hash"))
                return
            info_hex = binascii.hexlify(unquote_to_bytes(quoted)).decode()
            if len(info_hex) != 40:
                self._send(400, build_failure("info_hash must be 20 bytes"))
                return
            principal = ctx.principal
            if principal.type == "device":
                try:
                    allowed = (scrape_authorizer is not None and
                               bool(scrape_authorizer(principal.id,
                                                      info_hex)))
                except Exception:
                    # A state/read failure cannot broaden a device's view.
                    allowed = False
                if not allowed:
                    # Cross-assignment and nonexistent hashes are identical
                    # after authentication, preventing resource enumeration.
                    self._send(404, build_failure("not found"))
                    return
            # The seeder service retains whole-swarm visibility. A bounded
            # previous-seeder query token has no attributable device id and is
            # retained as the explicit unchanged Guest Shell exception.
            stats = registry.scrape(info_hex)
            self._send(200, build_scrape_response(info_hex, stats))

        def log_message(self, *args):
            pass

    tls_context = None
    if certfile:
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_context.load_cert_chain(certfile)
    srv = _TrackerServer((host, port), Handler)
    srv.tls_context = tls_context
    return srv


def _start_pruner(registry):
    def tick():
        try:
            registry.prune_all()
        except Exception:
            pass        # one bad pass must not end periodic pruning
        t = threading.Timer(INTERVAL, tick)
        t.daemon = True
        t.start()
    tick()


# ---------------------------------------------------------------------------
# Sole tracker blocklist reconciler (spec §0 / §7 / §13)
# ---------------------------------------------------------------------------

RECONCILE_POLL = 2.0   # max seconds before durable cross-process changes apply

# Upper bound on how long the loop may go without a full recompute even when
# nothing on disk changed and no wake arrived. A bare ≤2s poll with unchanged
# stat keys, an empty pending queue, a healthy known RPC/session and no dirty
# flag performs only the lightweight QoS target-set probe; it suppresses the
# full snapshot, session probe, and apply RPCs. Endpoint TTL expiry and periodic
# RPC/session recovery are time-driven and have
# no file-change signal — so we still force a maintenance pass at least this
# often. A pass that runs because this deadline passed also prunes expired
# rows from the durable endpoint map (peer_endpoints.prune); a wake- or
# change-driven pass only reads it. Bounded to one endpoint-TTL horizon
# (capped) so pruning is timely without blindly never running.
MAINTENANCE_INTERVAL_CAP = 60.0   # seconds
_NO_QOS_TARGETS = object()


class Aria2BlocklistAdapter:
    """Thin adapter exposing the reconciler's ``aria`` contract over the local
    aria2 JSON-RPC. It calls ``aria2.getSessionInfo`` for the counter epoch and
    ``aria2.setBtPeerBlocklist`` for the sole full-replace apply (spec §0), plus
    the narrowly-scoped origin QoS target and option calls. The
    RPC secret rides through the injected caller; no token is ever surfaced in
    an error (the reconciler records only the exception TYPE name)."""

    def __init__(self, rpc):
        self._rpc = rpc

    def get_session_id(self):
        session = self._rpc("aria2.getSessionInfo", [])
        return str((session or {}).get("sessionId") or "")

    def set_blocklist(self, ips):
        return self._rpc("aria2.setBtPeerBlocklist", [list(ips)]) or {}

    def get_active_download_gids(self):
        active = self._rpc("aria2.tellActive", [["gid"]])
        if not isinstance(active, list):
            raise ValueError("bad tellActive result")
        gids = []
        for row in active:
            if not isinstance(row, dict) or "gid" not in row:
                raise ValueError("bad tellActive row")
            gids.append(row["gid"])
        try:
            return _origin_qos.validate_target_gids(gids)
        except _origin_qos.OriginQosError as exc:
            raise ValueError("bad active gid set") from exc

    def set_global_options(self, options):
        if not isinstance(options, dict) \
                or set(options) != _origin_qos.GLOBAL_OPTION_KEYS \
                or any(not isinstance(value, str) for value in options.values()):
            raise ValueError("bad origin global options")
        return self._rpc("aria2.changeGlobalOption", [dict(options)])

    def set_download_options(self, gid, options):
        if not isinstance(gid, str) or not gid:
            raise ValueError("bad origin download gid")
        if not isinstance(options, dict) \
                or set(options) != _origin_qos.DOWNLOAD_OPTION_KEYS \
                or any(not isinstance(value, str) for value in options.values()):
            raise ValueError("bad origin download options")
        return self._rpc("aria2.changeOption", [gid, dict(options)])


class TrackerReconciler:
    """The single serialized reconcile loop. Constructed ONLY by the tracker
    process (spec §0): the GUI/catalog/CLI never instantiate it, never call
    ``setBtPeerBlocklist``, and never compute a denied set.

    Each pass (spec §7/§13): retry pending endpoint writes even without a new
    announce; recompute the desired denied set from durable endpoints + pending
    + the active registry + the credential-revocation view + the ``PolicyResult``
    + the protected current service-seeder address; full-replace apply; write the
    exact count-only enforcement status; and export the policy operation outbox
    in revision order above the ack, advancing
    ``last_operation_exported_revision`` only after the audit contract succeeds.
    The same serialized pass reconciles origin QoS with separate success memory
    and a separately persisted, identifier-free status.

    Startup and every aria RPC transition to reachable / session change force a
    full valid desired apply (including a valid-empty list). ``fail_closed``
    never clears blocks from corruption and applies the emergency deny list; with
    no known address it stays fail-closed with no false ``enforced`` claim.
    """

    def __init__(self, policy_paths, endpoints_path, enforcement_path, aria,
                  pending_queue, active_participants, revoked_principals,
                  protected_seeder_ip=None, audit_export=None,
                  emit_policy_event=None, now=None,
                  legacy_retention_until=None, origin_qos_path=None):
        self._policy_paths = policy_paths
        self._endpoints_path = endpoints_path
        self._enforcement_path = enforcement_path
        self._origin_qos_path = origin_qos_path or os.path.join(
            os.path.dirname(enforcement_path), "origin-qos.json")
        self._aria = aria
        self._pending = pending_queue
        self._active_participants = active_participants
        self._revoked_principals = revoked_principals
        self._legacy_retention_until = legacy_retention_until or (lambda: 0)
        self._protected_seeder_ip = protected_seeder_ip
        self._audit_export = audit_export
        # The telemetry hub injects this to avoid a tracker -> OTLP import
        # cycle. It queues the pre-built canonical record on its stable queue.
        self._emit_policy_event = emit_policy_event or (lambda entry, status: True)
        self._now = now or time.time
        self._record_endpoint = _peer_endpoints.record_endpoint

        # Force-apply memory (never a source of desired state; spec §0 recomputes
        # from durable files each pass). None until the first successful apply.
        self._last_session = None
        self._last_hash = None
        self._rpc_ok = None            # None=unknown, then True/False
        self._qos_last_session = None
        self._qos_last_hash = None
        self._qos_last_targets = None
        self._qos_rpc_ok = None
        self._prefetched_qos_targets = _NO_QOS_TARGETS
        self._qos_enabled = all(hasattr(aria, name) for name in (
            "get_active_download_gids", "set_global_options",
            "set_download_options"))

        # Serialization: exactly one reconcile at a time; a change during a run
        # schedules exactly one rerun (dirty flag).
        self._run_lock = threading.Lock()
        self._running = False
        self._dirty = False
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = None
        self._poll_keys = (None, None)
        # Bounded next-maintenance deadline (never None-forever / never disabled):
        # forces a periodic full recompute so endpoint TTL prune and RPC/session
        # recovery happen even with no file change and no wake. Scheduled after
        # every run_once (see _schedule_maintenance). None => "run at once".
        self._next_maintenance = None

    # -- public wake / lifecycle -------------------------------------------

    def wake(self):
        """Local wake for a tracker-authored durable change (immediate)."""
        self._wake.set()

    def request_run(self):
        """Attempt to claim a run. If one is already running, mark dirty and
        return False; otherwise return True (caller proceeds to run)."""
        with self._run_lock:
            if self._running:
                self._dirty = True
                return False
            self._running = True
            return True

    def drain_pending(self):
        """If a rerun was scheduled while running, run exactly once more.
        Returns True iff a rerun happened."""
        with self._run_lock:
            if not self._dirty:
                return False
            self._dirty = False
        self.run_once()
        return True

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _loop(self):
        # Startup always applies once (force full valid desired).
        self._safe_run()
        while not self._stop.is_set():
            # Local wake (tracker-authored) OR the ≤2s poll deadline, whichever
            # comes first, then also poll durable stat keys for other-process
            # changes (spec §0 ≤2s max latency).
            waked = self._wake.wait(timeout=RECONCILE_POLL)
            self._wake.clear()
            if self._stop.is_set():
                break
            # Dead-poll gate: a wake always runs; a bare poll runs only when
            # something actually needs reconciling (durable stat change, pending
            # work, unhealthy RPC/session, or the bounded maintenance deadline).
            if self._poll_should_run(waked):
                self._safe_run()

    def _safe_run(self):
        """One guarded pass that survives an unexpected exception. This is
        the SOLE enforcement loop: if it died (ENOSPC from write_status, an
        exception escaping derivation), announces would keep flowing while
        peer-enforcement.json froze on its last -- possibly ``enforced`` --
        claim and no later quarantine or revocation ever reached the seeder.
        A failed pass is recorded as ``degraded`` (best effort) and the next
        poll retries."""
        try:
            self._guarded_run()
        except Exception as exc:
            self._note_pass_failure(exc)

    def _note_pass_failure(self, exc):
        # Force the next bare poll to run (the deadline is the cheapest lever
        # that does not pretend to know the RPC state), then try to say so in
        # the status file. Source-owned codes never include exception data.
        self._next_maintenance = None
        try:
            prior = _peer_enforcement.read_status(self._enforcement_path) or {}
            policy = _peer_policy.load_policy(*self._policy_paths)
            count = prior.get("desired_ip_count", 0)
            status = _peer_enforcement.build_status(
                state="degraded",
                aria_session_id=prior.get("aria_session_id"),
                desired_hash=prior.get("desired_hash"),
                applied_revision=prior.get("applied_revision"),
                desired_ip_count=count if isinstance(count, int)
                and not isinstance(count, bool) else 0,
                now=self._now(),
                last_operation_exported_revision=_peer_policy.effective_acked(
                    policy.document, prior),
                operation_ack_epoch=policy.document.get("operation_ack_epoch"),
                conflicts=prior.get("conflicts"),
                last_effect=prior.get("last_effect"),
                last_error=_status_codes.PEER_RECONCILE_FAILED,
                mutual_origin=self._prior_mutual_origin(prior))
            _peer_enforcement.write_status(self._enforcement_path, status)
        except Exception:
            pass
        if self._qos_enabled:
            self._write_origin_qos_failure(_status_codes.ORIGIN_RECONCILE_FAILED)

    def _write_origin_qos_failure(self, error):
        """Best-effort degraded QoS status preserving only validated scalars."""
        try:
            prior = _origin_qos.read_status(self._origin_qos_path) or {}

            def count(name):
                value = prior.get(name, 0)
                return value if isinstance(value, int) \
                    and not isinstance(value, bool) and value >= 0 else 0

            session = prior.get("aria_session_id")
            session = session if isinstance(session, str) and session else None
            desired_hash = prior.get("desired_hash")
            desired_hash = (desired_hash if isinstance(desired_hash, str)
                            and desired_hash else None)
            global_count = min(
                count("global_option_count"),
                len(_origin_qos.GLOBAL_OPTION_KEYS))
            target_count = count("target_download_count")
            applied_count = min(count("applied_download_count"), target_count)
            status = _origin_qos.build_status(
                state="degraded" if session and desired_hash
                else "rpc_unavailable",
                aria_session_id=session, desired_hash=desired_hash,
                global_option_count=global_count,
                target_download_count=target_count,
                applied_download_count=applied_count,
                now=self._now(), last_error=error)
            _origin_qos.write_status(self._origin_qos_path, status)
        except Exception:
            pass

    def _persist_origin_qos_status(self, status):
        """Write QoS status without changing a truthful blocklist result.

        The files and their success memories are independent. If only the QoS
        status write fails, leave the peer-enforcement status intact, mark QoS
        unhealthy, and force a complete QoS retry on the next poll.
        """
        try:
            _origin_qos.write_status(self._origin_qos_path, status)
        except Exception:
            self._qos_rpc_ok = False
            self._next_maintenance = None
            return False
        return True

    def _current_poll_keys(self):
        return (_stat_key(self._policy_paths[0]),
                # The durable endpoint map is a keyed shard directory, not one
                # document, so its change key is the directory's.
                _peer_endpoints.change_key(self._endpoints_path))

    def _poll_should_run(self, waked):
        """Decide whether this loop iteration should reconcile.

        Wakes always run. On a bare (unwaked) poll we run only when there is a
        genuine reason: an external durable stat change, outstanding pending
        work, an unhealthy RPC/session (recovery must be detected without a file
        change), or the bounded maintenance deadline has passed (endpoint TTL
        prune / periodic reconciliation). Otherwise the poll is a no-op — no
        run_once, no getSessionInfo, no apply — so a steady idle loop performs
        no full reconcile RPC. A healthy idle pass performs only the required
        ``tellActive`` GID-set probe for origin QoS churn."""
        keys = self._current_poll_keys()
        changed = keys != self._poll_keys
        self._poll_keys = keys
        if waked:
            return True
        if changed:
            return True
        if len(self._pending) > 0:
            return True
        if self._rpc_ok is not True:
            return True
        if self._qos_enabled and self._qos_rpc_ok is not True:
            return True
        if self._next_maintenance is None:
            return True
        if self._now() >= self._next_maintenance:
            return True

        # QoS target membership can change without touching policy/endpoints
        # (for example, seeder credential rotation removes and re-adds GIDs).
        # One light tellActive(gid) probe on an otherwise-idle poll keeps that
        # change within RECONCILE_POLL without rebuilding the full snapshot.
        if not self._qos_enabled:
            return False
        targets = self._probe_qos_targets()
        if targets is None or targets != self._qos_last_targets:
            self._prefetched_qos_targets = targets
            return True
        return False

    def _schedule_maintenance(self):
        """Arm the bounded next-maintenance deadline after a reconcile pass. The
        horizon is the effective endpoint TTL, capped at
        :data:`MAINTENANCE_INTERVAL_CAP`, so TTL-driven prune and periodic
        recovery are timely but the idle loop is not woken every 2s."""
        interval = min(float(_peer_endpoints.endpoint_ttl()),
                       MAINTENANCE_INTERVAL_CAP)
        self._next_maintenance = self._now() + interval

    def _guarded_run(self):
        if not self.request_run():
            return
        try:
            self.run_once()
        finally:
            with self._run_lock:
                self._running = False
            # Coalesced rerun if a change landed mid-run.
            self.drain_pending()

    # -- one reconcile pass -------------------------------------------------

    def run_once(self):
        now = self._now()

        # 1) Snapshot pending BEFORE retry so a pending tuple affects the
        #    desired set immediately (spec §7), then retry the durable writes
        #    even without a new announce. Outstanding-after-retry drives the
        #    degrade signal (status degraded until the write is durable).
        pending_snapshot = self._pending.snapshot()
        self._retry_pending(now)
        pending_outstanding = len(self._pending) > 0

        # 2) Recompute desired from durable + pending + active + revocation +
        #    policy + protected seeder (never in-memory residue).
        policy = _peer_policy.load_policy(*self._policy_paths)
        revoked = set(self._revoked_principals() or set())
        # Rows of revoked principals and of principals the policy denies at
        # that address outlive ENDPOINT_TTL (spec 7 retirement): the seeder
        # block for a device that stopped announcing must not lapse while it
        # is still quarantined or revoked.
        keep = _bounded_legacy_retention(
            policy, revoked, now=now,
            role_until=self._legacy_retention_until())
        if self._next_maintenance is None or now >= self._next_maintenance:
            # Maintenance-driven pass: TTL prune of the durable map. A wake
            # or change-driven pass only reads it (no per-announce rewrite).
            try:
                _peer_endpoints.prune(self._endpoints_path, now, keep=keep)
            except (OSError, _peer_endpoints.EndpointStoreError):
                pass    # the read below reports the store's state
        try:
            durable = _peer_endpoints.fresh_endpoints(
                self._endpoints_path, now, keep=keep)
        except _peer_endpoints.EndpointStoreError:
            qos_status = None
            if self._qos_enabled:
                session = self._probe_session()
                desired_qos, qos_outcome, qos_error = \
                    self._prepare_origin_qos(policy, session)
                session_stable = bool(session) and \
                    self._probe_session() == session
                qos_status = self._finish_origin_qos(
                    now, session, session_stable, desired_qos, qos_outcome,
                    qos_error)
            prior = _peer_enforcement.read_status(self._enforcement_path) or {}
            status = _peer_enforcement.build_status(
                state="fail_closed",
                aria_session_id=prior.get("aria_session_id"),
                desired_hash=prior.get("desired_hash"),
                applied_revision=prior.get("applied_revision"),
                desired_ip_count=prior.get("desired_ip_count", 0), now=now,
                last_operation_exported_revision=_peer_policy.effective_acked(
                    policy.document, prior),
                operation_ack_epoch=policy.document.get("operation_ack_epoch"),
                conflicts=prior.get("conflicts"),
                last_effect=prior.get("last_effect"),
                last_error=_status_codes.ENDPOINT_STORE_UNAVAILABLE,
                mutual_origin=self._prior_mutual_origin(prior))
            _peer_enforcement.write_status(self._enforcement_path, status)
            qos_status_written = True
            if qos_status is not None:
                qos_status_written = self._persist_origin_qos_status(qos_status)
            if qos_status_written:
                self._schedule_maintenance()
            return status
        active = list(self._active_participants() or [])
        derived = _reconciler.derive_denied_set(
            policy, durable, pending_snapshot, active, revoked,
            self._protected_seeder_ip)

        # 3) Decide whether to force a full apply (startup / session change /
        #    RPC recovery) — otherwise skip a redundant identical apply.
        desired_hash = _reconciler.canonical_hash(derived.denied_ips)
        session = self._probe_session()
        desired_qos = qos_outcome = None
        qos_error = None
        if self._qos_enabled:
            desired_qos, qos_outcome, qos_error = \
                self._prepare_origin_qos(policy, session)
        force = (self._last_hash is None
                 or session != self._last_session
                 or self._rpc_ok is not True
                 or desired_hash != self._last_hash)

        outcome = None
        if force:
            outcome = _reconciler.apply_blocklist(
                self._aria, derived.denied_ips, derived.apply_empty,
                session_id=session) if self._qos_enabled else \
                _reconciler.apply_blocklist(
                    self._aria, derived.denied_ips, derived.apply_empty)

        qos_status = None
        if self._qos_enabled:
            session_stable = bool(session) and self._probe_session() == session
            if not session_stable:
                self._rpc_ok = False
                if outcome is not None:
                    outcome = outcome._replace(
                        success=False,
                        last_error=(_status_codes.ARIA_SESSION_CHANGED if session
                                    else _status_codes.ARIA_SESSION_UNAVAILABLE))
            qos_status = self._finish_origin_qos(
                now, session, session_stable, desired_qos, qos_outcome,
                qos_error)

        # 4) Persist the exact count-only enforcement status.
        status = self._build_status(
            now, policy, derived, desired_hash, outcome, pending_outstanding)

        # 5) Export the policy operation outbox (revision order, ack-gated).
        #    Read the prior ack watermark once (centralized) and carry it
        #    forward so a status-only / non-operation pass can never reset it.
        acked = {"last_operation_exported_revision": self._read_acked_revision(policy),
                 "operation_ack_epoch": policy.document.get("operation_ack_epoch")}
        exported_rev = self._export_outbox(policy, acked, status)
        status["last_operation_exported_revision"] = exported_rev
        epoch = policy.document.get("operation_ack_epoch")
        if epoch is not None:
            status["operation_ack_epoch"] = epoch

        _peer_enforcement.write_status(self._enforcement_path, status)
        qos_status_written = True
        if qos_status is not None:
            qos_status_written = self._persist_origin_qos_status(qos_status)
        # Arm the bounded next-maintenance deadline so a subsequent idle bare
        # poll stays a no-op until either something changes or the deadline
        # passes (TTL prune / periodic recovery).
        if qos_status_written:
            self._schedule_maintenance()
        return status

    def _retry_pending(self, now):
        # Reuse peer_endpoints.retry_pending with the (possibly injected) writer
        # so failure injection is honored AND the endpoint's ORIGINAL
        # observed_at is preserved — a stuck retry must never extend endpoint
        # TTL past first observation (spec §7). ``now`` is intentionally unused
        # for the persisted timestamp.
        _peer_endpoints.retry_pending(
            self._endpoints_path, self._pending, writer=self._record_endpoint)

    def _probe_session(self):
        try:
            return self._aria.get_session_id() or None
        except Exception:
            return None

    def _probe_qos_targets(self):
        try:
            return _origin_qos.validate_target_gids(
                self._aria.get_active_download_gids())
        except Exception:
            return None

    def _take_qos_targets(self):
        targets = self._prefetched_qos_targets
        self._prefetched_qos_targets = _NO_QOS_TARGETS
        if targets is _NO_QOS_TARGETS:
            return self._probe_qos_targets()
        return targets

    def _prepare_origin_qos(self, policy, session):
        targets = self._take_qos_targets()
        if targets is None:
            self._qos_rpc_ok = False
            return None, None, _status_codes.TARGET_DISCOVERY_UNAVAILABLE
        try:
            desired = _origin_qos.build_desired(policy.document, targets)
        except Exception:
            self._qos_rpc_ok = False
            return None, None, _status_codes.ORIGIN_DESIRED_STATE_FAILED
        if policy.fail_closed:
            self._qos_rpc_ok = False
            return desired, None, _status_codes.POLICY_FAIL_CLOSED
        force = (self._qos_last_hash is None
                 or session != self._qos_last_session
                 or self._qos_rpc_ok is not True
                 or desired.desired_hash != self._qos_last_hash
                 or desired.target_gids != self._qos_last_targets)
        outcome = (_origin_qos.apply_desired(self._aria, desired, session)
                   if force else None)
        return desired, outcome, None

    def _finish_origin_qos(self, now, session, session_stable, desired,
                           outcome, preparation_error=None):
        desired_hash = desired.desired_hash if desired is not None else None
        target_count = len(desired.target_gids) if desired is not None else 0
        global_count = 0
        applied_count = 0
        last_error = preparation_error

        if outcome is not None:
            global_count = 1 if outcome.global_applied else 0
            applied_count = outcome.applied_download_count
            last_error = outcome.last_error

        if not session_stable:
            last_error = (_status_codes.ARIA_SESSION_CHANGED if session
                          else _status_codes.ARIA_SESSION_UNAVAILABLE)
            state = "degraded" if session else "rpc_unavailable"
            self._qos_rpc_ok = False
        elif preparation_error is not None:
            state = ("rpc_unavailable"
                     if preparation_error == _status_codes.TARGET_DISCOVERY_UNAVAILABLE
                     or not session else "degraded")
            self._qos_rpc_ok = False
        elif outcome is not None and outcome.success:
            self._qos_last_session = session
            self._qos_last_hash = desired_hash
            self._qos_last_targets = desired.target_gids
            self._qos_rpc_ok = True
            state = "enforced"
        elif outcome is not None:
            self._qos_rpc_ok = False
            state = "degraded" if session else "rpc_unavailable"
        elif self._qos_rpc_ok is True and session \
                and desired_hash == self._qos_last_hash \
                and desired.target_gids == self._qos_last_targets:
            state = "enforced"
            global_count = len(_origin_qos.GLOBAL_OPTION_KEYS)
            applied_count = target_count
            last_error = None
        else:
            self._qos_rpc_ok = False
            state = "degraded" if session else "rpc_unavailable"

        return _origin_qos.build_status(
            state=state,
            aria_session_id=session,
            desired_hash=desired_hash,
            global_option_count=global_count,
            target_download_count=target_count,
            applied_download_count=applied_count,
            now=now,
            last_error=last_error)

    def _prior_mutual_origin(self, prior):
        """Preserve a validated observation only while its required IP is known."""
        if not _reconciler.valid_protected_seeder_ipv4(self._protected_seeder_ip):
            prior = {}
        return _peer_enforcement.mutual_origin_from_status(prior)

    def _build_status(self, now, policy, derived, desired_hash, outcome,
                      pending_outstanding):
        applied_revision = None
        last_effect = None
        last_error = None
        session = None

        if outcome is not None:
            session = outcome.aria_session_id
            applied_revision = outcome.applied_revision
            last_effect = outcome.last_effect
            last_error = outcome.last_error
            rpc_ok = outcome.success or (
                not outcome.applied and not derived.apply_empty
                and not derived.fail_closed)
        else:
            # No apply this pass (nothing changed) => prior state stands.
            session = self._last_session
            rpc_ok = self._rpc_ok is True

        # Decide the state (spec §13).
        if derived.fail_closed:
            state = "fail_closed"
        elif pending_outstanding:
            state = "degraded"
        elif policy.degraded:
            state = "degraded"
        elif derived.conflicts:
            state = "degraded"
        elif outcome is not None and outcome.applied and not outcome.success:
            state = "degraded" if session else "rpc_unavailable"
        elif rpc_ok and session:
            state = "enforced"
        elif outcome is not None and not outcome.applied \
                and not derived.apply_empty:
            # fail-closed handled above; valid empty with no session:
            state = "degraded"
        else:
            state = "degraded"

        # Update force-apply memory only on a real successful apply.
        if outcome is not None and outcome.success:
            self._last_session = session
            self._last_hash = desired_hash
            self._rpc_ok = True
        elif outcome is not None and outcome.applied and not outcome.success:
            self._rpc_ok = False

        conflicts = derived.conflicts
        # `enforced` requires a current session + desired hash (build_status
        # enforces this invariant and rejects a false claim).
        eff_hash = desired_hash if session else None
        if state == "enforced" and (not session or not eff_hash):
            state = "degraded"
        if policy.fail_closed:
            mutual_origin = self._prior_mutual_origin(
                _peer_enforcement.read_status(self._enforcement_path) or {})
        else:
            ids = derived.newly_denied_device_ids
            mutual_origin = {
                "mode": _peer_enforcement.MUTUAL_ORIGIN_MODE,
                "newly_denied_device_count": None if ids is None else len(ids),
                "newly_denied_device_ids": None if ids is None else list(ids),
            }
        return _peer_enforcement.build_status(
            state=state, aria_session_id=session, desired_hash=eff_hash,
            applied_revision=applied_revision,
            desired_ip_count=len(derived.denied_ips), now=now,
            conflicts=conflicts, last_effect=last_effect, last_error=last_error,
            mutual_origin=mutual_origin)

    def _read_acked_revision(self, policy=None):
        """Reduce validated status against the exact policy snapshot for a pass.

        A history/epoch mismatch or future revision contributes zero, including
        when a failure or no-work pass subsequently persists this watermark.
        """
        prior = _peer_enforcement.read_status(self._enforcement_path)
        if not prior:
            return 0
        policy = policy or _peer_policy.load_policy(*self._policy_paths)
        return _peer_policy.effective_acked(policy.document, prior)

    def _export_outbox(self, policy, acked, status):
        """Export outbox entries with revision > the acked revision, in revision
        order, then advance the ack ONLY after local audit append AND stable
        queue acceptance. On either failure the prior ``acked`` watermark is
        retained and the persisted event ids replay next pass / restart."""
        entries = _peer_policy.pending_exports(policy.document, acked)
        acked = _peer_policy.effective_acked(policy.document, acked)
        if not entries:
            return acked
        if self._audit_export is None:
            return acked
        try:
            self._audit_export(entries)
        except Exception:
            return acked   # audit best-effort failed -> replay next pass
        try:
            for entry in entries:
                if self._emit_policy_event(entry, status) is False:
                    return acked
        except Exception:
            return acked
        # Never regress below the prior watermark.
        return max(acked, max(e["revision"] for e in entries))


def _build_reconciler_from_env(env, registry, emit_policy_event=None):
    """Construct the sole tracker reconciler from IRIS_* env (spec §0). The
    cross-process channel files live under ``IRIS_STATE``; the RPC secret rides
    through the injected JSON-RPC caller and is never surfaced in an error."""
    state_dir = env.get("IRIS_STATE", "/var/lib/iris")
    policy_path = os.path.join(state_dir, "peer-policy.json")
    lkg_path = os.path.join(state_dir, "peer-policy.lkg.json")
    endpoints_path = os.path.join(state_dir, "peer-endpoints.json")
    enforcement_path = os.path.join(state_dir, "peer-enforcement.json")
    origin_qos_path = os.path.join(state_dir, "origin-qos.json")
    audit_path = env.get("IRIS_AUDIT", "/etc/iris/audit.jsonl")
    secrets_path = env.get("IRIS_SECRETS", "/run/iris/secrets.json")
    try:
        token_grace = int(env.get("IRIS_TOKEN_SKEW_GRACE", "300"))
    except (TypeError, ValueError):
        token_grace = 300

    rpc = telemetry.make_jsonrpc_caller(
        env.get("IRIS_RPC", telemetry.DEFAULT_RPC_URL),
        telemetry._read_rpc_secret(env))
    aria = Aria2BlocklistAdapter(rpc)

    def audit_export(entries):
        import audit
        for e in entries:
            audit.append_event(
                audit_path, "peer-policy-operation", actor=e.get("actor"),
                action=e.get("action"), target=e.get("target"),
                new_id=e.get("event_id"), ts=e.get("created_at"))

    return TrackerReconciler(
        policy_paths=(policy_path, lkg_path),
        endpoints_path=endpoints_path, enforcement_path=enforcement_path,
        origin_qos_path=origin_qos_path,
        aria=aria, pending_queue=_peer_endpoints.PendingEndpointQueue(),
        active_participants=lambda: _active_participants(registry),
        # Revocation view (spec §7 retirement): a device principal whose every
        # secret record is durably revoked is derived-denied regardless of
        # policy. The provider reads the durable secrets store fresh each pass;
        # a corrupt/unreadable store must never silently permit a known-revoked
        # device, so it fails safe by retaining the last-known revoked set.
        revoked_principals=_make_revoked_view(secrets_path),
        legacy_retention_until=_make_legacy_retention_view(
            secrets_path, token_grace),
        protected_seeder_ip=env.get("IRIS_HOST_IP") or None,
        audit_export=audit_export, emit_policy_event=emit_policy_event)


def _make_revoked_view(secrets_path):
    """Build the reconciler's ``revoked_principals`` provider over the durable
    secrets store (spec §7 retirement).

    Each call reads the store fresh (revocation must be picked up without a
    tracker restart). To stay fail-closed, a read/parse failure NEVER shrinks
    the revoked set: the last successfully-derived set is retained so a
    transient corrupt read cannot silently re-permit a known-revoked device.
    The RPC secret and other secret values never leave this closure — only the
    ``"<type>:<id>"`` keys do — and no exception message is surfaced.
    """
    last_known = {"keys": set()}

    def view():
        try:
            with open(secrets_path) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("not a dict")
            data.setdefault("devices", {})
            keys = secrets_store.revoked_device_principals(data)
        except (OSError, ValueError):
            # Fail-safe: a corrupt/unreadable store must never SHRINK the deny
            # set (that would silently re-permit a known-revoked device), so we
            # keep denying every principal the last GOOD read knew was revoked.
            return set(last_known["keys"])
        # A successful read is authoritative: it reflects the true current
        # revoke state, so a legitimately re-onboarded device (fresh, non-revoked
        # credentials) correctly drops out of the deny set.
        last_known["keys"] = keys
        return set(keys)

    return view


def _make_legacy_retention_view(secrets_path, grace):
    """Cache the previous-token deadline and fail safe across read errors."""
    resolver = credential_cache.CredentialResolver(secrets_path)
    last_known = {"deadline": float("inf")}

    def view():
        try:
            deadline = _legacy_token_deadline(resolver.store(), grace)
        except (OSError, ValueError, secrets_store.StoreCorruptError):
            return last_known["deadline"]
        last_known["deadline"] = deadline
        return deadline

    return view


def _active_participants(registry):
    """Flatten the live registry into ``{principal_type, principal_id, ipv4}``
    rows for the emergency (fail-closed) derivation.

    Defensive by contract: a malformed or legacy row with missing typed fields
    must never crash the emergency fail-closed pass. Rows are read with
    ``.get()``; a row without a usable ``ip`` contributes no denied address and
    is skipped (the emergency derivation keys on ``ipv4``), while missing
    type/id default to ``None`` so the downstream ``.get()`` handling stays
    valid."""
    rows = []
    for peers in (registry.snapshot() or {}).values():
        for p in peers or []:
            if not isinstance(p, dict):
                continue
            ip = p.get("ip")
            if not ip:
                continue
            rows.append({"principal_type": p.get("principal_type"),
                         "principal_id": p.get("principal_id"),
                         "ipv4": ip})
    return rows


def main():
    host = os.environ.get("IRIS_TRACKER_HOST", "0.0.0.0")
    port = int(os.environ.get("IRIS_TRACKER_PORT", "6969"))
    secrets_path = os.environ.get("IRIS_SECRETS", "/run/iris/secrets.json")
    certfile = os.environ.get("IRIS_CERT", "/run/iris/tls/cert.pem")
    if not os.path.isfile(certfile):
        print("iris-tracker: TLS certificate unavailable; refusing plaintext "
              "tracker transport", file=sys.stderr, flush=True)
        sys.exit(2)

    # Telemetry owns a registry wired to its event hook. The hub always
    # runs; its OTLP destination is resolved per sample pass (deployment
    # env, overridable from the console's telemetry-destination.json).
    # Prometheus /metrics exposure stays startup-gated below.
    hub = telemetry.from_env()
    registry = hub.registry
    _start_pruner(registry)
    hub.start()
    mport = telemetry.metrics_port()
    if mport is not None:
        # External Prometheus-format /metrics is gated on IRIS_OBSERVABILITY
        # (default off) — IRIS doesn't assume any observability stack is
        # around. Swarm JSON always requires the management-tier credential;
        # the map page moved into the console. The listener is TLS-only in
        # production because both management and observability credentials can
        # cross it.
        obs = telemetry.observability_enabled()
        mhost = os.environ.get("IRIS_METRICS_HOST", "0.0.0.0")
        try:
            msrv = telemetry.make_metrics_server(
                mhost, mport,
                hub.metrics_text if obs else None,
                swarm_provider=hub.swarm_snapshot,
                health=hub.export_health.as_dict,
                # What /readyz TCP-probes. /healthz answering 200 only ever
                # proved :9101 was alive, so a dead artifact server or tracker
                # left the container "healthy" and, under Kubernetes, never
                # restarted. Overridable with IRIS_HEALTH_LISTENERS
                # ("name:port,..." or "off") for a deployment that runs a
                # subset of the services.
                listeners=telemetry.parse_health_listeners(
                    os.environ.get("IRIS_HEALTH_LISTENERS"),
                    default={
                        "tracker": port,
                        "catalog": int(os.environ.get(
                            "IRIS_CATALOG_PORT", "8443")),
                        "artifacts": int(os.environ.get(
                            "IRIS_ARTIFACTS_PORT", "8000")),
                        "management": int(os.environ.get(
                            "IRIS_MANAGEMENT_API_PORT", "9443")),
                    }),
                management_token_file=os.environ.get(
                    "IRIS_MANAGEMENT_API_TOKEN_FILE") or None,
                management_previous_token_file=os.environ.get(
                    "IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE") or None,
                observability_token_file=os.environ.get(
                    "IRIS_OBSERVABILITY_TOKEN_FILE") or None,
                observability_previous_token_file=os.environ.get(
                    "IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE") or None,
                certfile=os.environ.get("IRIS_TELEMETRY_CERT")
                or os.environ.get("IRIS_CERT", "/run/iris/tls/cert.pem"),
                keyfile=os.environ.get("IRIS_TELEMETRY_KEY") or None)
            threading.Thread(target=msrv.serve_forever, daemon=True).start()
            print("swarm JSON on https://%s:%d/swarm "
                  "(management bearer required)%s"
                  % (mhost, mport,
                     "  (metrics on /metrics)" if obs else
                     "  (Prometheus /metrics disabled — IRIS_OBSERVABILITY=1 "
                     "to enable)"), flush=True)
        except OSError as e:
            # telemetry must never take down the tracker — a bound port etc.
            # is logged and skipped, the announce service still comes up.
            print("metrics server disabled: %s" % e, flush=True)

    # The tracker is the SOLE blocklist reconciler (spec §0). Construct and
    # start it here; the announce path shares its pending queue and wakes it on
    # a tracker-authored durable endpoint change.
    reconciler = _build_reconciler_from_env(
        os.environ, registry, emit_policy_event=hub.emit_policy_event)
    state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
    policy_paths = (os.path.join(state_dir, "peer-policy.json"),
                    os.path.join(state_dir, "peer-policy.lkg.json"))
    endpoints_path = os.path.join(state_dir, "peer-endpoints.json")
    handout_path = os.path.join(state_dir, "peer-handouts.json")

    try:
        srv = make_server(
            host, port, secrets_path, registry=registry,
            on_announce=hub.note_announce,
            policy_paths=policy_paths, endpoints_path=endpoints_path,
            pending_queue=reconciler._pending,
            on_endpoint_failure=reconciler.wake,
            on_endpoint_change=reconciler.wake,
            on_announce_refused=hub.note_announce_refused,
            scrape_authorizer=_catalog_scrape_authorizer(state_dir),
            handout_path=handout_path,
            certfile=certfile)
    except (OSError, ssl.SSLError, ValueError):
        print("iris-tracker: TLS certificate unusable; refusing plaintext "
              "tracker transport", file=sys.stderr, flush=True)
        sys.exit(2)
    reconciler.start()
    print("tracker on https://%s:%d/announce" % (host, port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
