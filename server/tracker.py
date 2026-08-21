#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Private BitTorrent tracker for IRIS. Token-gated /announce + /scrape,
peer lifecycle via peer_registry, bencoded responses, optional compact peers.
Stdlib only. Run as a service: python3 tracker.py (reads IRIS_* env)."""
import binascii
import ipaddress
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote_to_bytes, urlparse

import auth
import bencode
import peer_endpoints as _peer_endpoints
import peer_policy as _peer_policy
import secrets_store
import telemetry
from peer_registry import PeerRegistry, INTERVAL

MIN_INTERVAL = 10


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
    # Port must be in 1-65535; clamp to default on bad input.
    raw_port = as_int("port", 6881)
    port = raw_port if 1 <= raw_port <= 65535 else None

    # BEP3 optional ip= override — retain it for container/NAT deployments, but
    # only for private/CGNAT dotted-quad IPv4. Public endpoints always come
    # from the authenticated connection's socket source.
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


def build_announce_response(peers, compact=False, interval=INTERVAL):
    if compact:
        peers_value = compact_peers(peers)
    else:
        peers_value = [{"ip": p["ip"], "peer id": "", "port": p["port"]}
                       for p in peers]
    return bencode.encode({
        "interval": interval,
        "min interval": MIN_INTERVAL,
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


def make_server(host, port, secrets_path, registry=None, on_announce=None,
                policy_paths=None, endpoints_path=None, pending_queue=None,
                record_endpoint=None, on_endpoint_failure=None):
    """Build the tracker HTTP server.

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
    """
    registry = registry or PeerRegistry()
    _grace = int(os.environ.get("IRIS_TOKEN_SKEW_GRACE", "300"))
    _record_endpoint = record_endpoint or _peer_endpoints.record_endpoint

    def _load_policy():
        if policy_paths is None:
            return None
        return _peer_policy.load_policy(policy_paths[0], policy_paths[1])

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status, body):
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _resolve_principal(self, query, store, index, now, peer_ip=None,
                               peer_port=None):
            """Resolve the announce credential to a typed AuthContext, or None
            on any missing/invalid/ambiguous outcome (=> token-free 403). The
            legacy id is the effective endpoint (spec §6), never a token."""
            try:
                return auth.resolve_announce_principal(
                    query, index, store, now, _grace,
                    legacy_id=_legacy_id(peer_ip, peer_port))
            except auth.AnnounceAuthError:
                return None

        def do_GET(self):
            parsed = urlparse(self.path)
            query = parsed.query
            store = secrets_store.load(secrets_path)
            try:
                index = secrets_store.build_announce_index(store)
            except secrets_store.DuplicateCredentialError:
                # A hard configuration error (two records share a value) is a
                # token-free 403 — never a silent overwrite (spec §6).
                self._send(403, build_failure("credential configuration error"))
                return
            now = time.time()
            if parsed.path == "/announce":
                self._handle_announce(query, store, index, now)
            elif parsed.path == "/scrape":
                # Scrape auth stays valid but its semantics are unchanged: we
                # only require a valid announce credential, discarding the
                # typed context (spec §6 scrape).
                if self._resolve_principal(query, store, index, now) is None:
                    self._send(403, build_failure("missing or invalid token"))
                    return
                self._handle_scrape(query)
            else:
                self._send(404, build_failure("not found"))

        def _handle_announce(self, query, store, index, now):
            a = parse_announce(query)
            # Effective peer IP retains the explicit override allowlist
            # (RFC1918 + CGNAT only, via parse_announce). ip=None means the
            # override was absent/invalid: fall back to the socket source.
            peer_ip = a["ip"] or self.client_address[0]
            ctx = self._resolve_principal(query, store, index, now, peer_ip,
                                          a["port"])
            if ctx is None:
                self._send(403, build_failure("missing or invalid token"))
                return
            if on_announce is not None:
                on_announce()
            # Validate info_hash AFTER auth so an unauthenticated caller learns
            # nothing about the request shape.
            if len(a["info_hash"]) != 40:
                self._send(400, build_failure("info_hash must be 20 bytes"))
                return
            principal = ctx.principal
            # port=None means the client sent an out-of-range value. Registering
            # a substitute port would advertise a wrong endpoint; skip
            # registration AND any durable endpoint write, but still 200.
            if a["port"] is None:
                peers = self._select(a, principal, peer_ip)
                self._send(200, build_announce_response(
                    peers, compact=a["compact"]))
                return
            peer_port = a["port"]
            # Register the typed peer BEFORE candidate filtering so a valid
            # (even quarantined) announce is 200 and visible in the swarm.
            registry.announce(a["info_hash"], a["peer_id"], peer_ip, peer_port,
                              event=a["event"], left=a["left"],
                              principal=principal)
            # Durable endpoint write for attributable principals only. Failure
            # never changes the HTTP 200 or the policy filtering: enqueue the
            # latest pending tuple and signal a degrade / local wake.
            self._persist_endpoint(principal, peer_ip, peer_port, now)
            peers = self._select(a, principal, peer_ip)
            self._send(200, build_announce_response(
                peers, compact=a["compact"]))

        def _persist_endpoint(self, principal, peer_ip, peer_port, now):
            if endpoints_path is None:
                return
            if principal.type not in ("device", "service"):
                return  # legacy is never persisted as an attributable endpoint
            try:
                _record_endpoint(endpoints_path, principal, peer_ip,
                                 peer_port, now)
            except OSError:
                if pending_queue is not None:
                    pending_queue.enqueue(principal, peer_ip, peer_port, now)
                if on_endpoint_failure is not None:
                    on_endpoint_failure()

        def _select(self, a, principal, peer_ip):
            policy = _load_policy()
            if policy is None:
                return registry.peers(a["info_hash"], a["peer_id"],
                                      numwant=a["numwant"])
            if policy.fail_closed:
                return []
            doc = policy.document

            def predicate(req_p, req_ip, cand_p, cand_ip):
                return _peer_policy.mutual_permit(
                    doc, req_p, req_ip, cand_p, cand_ip)

            return registry.select_peers(
                a["info_hash"], a["peer_id"], principal, peer_ip,
                predicate=predicate, numwant=a["numwant"])

        def _handle_scrape(self, query):
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
            stats = registry.scrape(info_hex)
            self._send(200, build_scrape_response(info_hex, stats))

        def log_message(self, *args):
            pass

    return ThreadingHTTPServer((host, port), Handler)


def _start_pruner(registry):
    def tick():
        registry.prune_all()
        t = threading.Timer(INTERVAL, tick)
        t.daemon = True
        t.start()
    tick()


def main():
    host = os.environ.get("IRIS_TRACKER_HOST", "0.0.0.0")
    port = int(os.environ.get("IRIS_TRACKER_PORT", "6969"))
    secrets_path = os.environ.get("IRIS_SECRETS", "/run/iris/secrets.json")

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
        # around. The swarm JSON (/swarm) answers loopback peers only unless
        # IRIS_SWARM_PUBLIC opens it (the console proxies it over container
        # loopback); the map PAGE moved into the console (:8080), so /swarmmap
        # and / point there instead. IRIS_METRICS_HOST (default unchanged
        # 0.0.0.0) remains the HARD control for this surface: a peer-address
        # gate is namespace-scoped, the bind host is not (security.md).
        obs = telemetry.observability_enabled()
        mhost = os.environ.get("IRIS_METRICS_HOST", "0.0.0.0")
        swarm_public = os.environ.get(
            "IRIS_SWARM_PUBLIC", "").strip().lower() in (
                "1", "true", "yes", "on")
        try:
            msrv = telemetry.make_metrics_server(
                mhost, mport,
                hub.metrics_text if obs else None,
                swarm_provider=hub.swarm_snapshot,
                html=telemetry.moved_page,   # map page retired -> console pointer
                health=hub.export_health.as_dict,
                swarm_public=swarm_public)
            threading.Thread(target=msrv.serve_forever, daemon=True).start()
            print("swarm JSON on http://%s:%d/swarm %s%s"
                  % (mhost, mport,
                     "(open to any peer — IRIS_SWARM_PUBLIC)" if swarm_public
                     else "(loopback only — console-gated; "
                          "IRIS_SWARM_PUBLIC=1 to open)",
                     "  (metrics on /metrics)" if obs else
                     "  (Prometheus /metrics disabled — IRIS_OBSERVABILITY=1 "
                     "to enable)"), flush=True)
        except OSError as e:
            # telemetry must never take down the tracker — a bound port etc.
            # is logged and skipped, the announce service still comes up.
            print("metrics server disabled: %s" % e, flush=True)

    srv = make_server(host, port, secrets_path, registry=registry,
                      on_announce=hub.note_announce)
    print("tracker on http://%s:%d/announce" % (host, port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
