#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Private BitTorrent tracker for IRIS. Token-gated /announce + /scrape,
peer lifecycle via peer_registry, bencoded responses, optional compact peers.
Stdlib only. Run as a service: python3 tracker.py (reads IRIS_* env)."""
import binascii
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote_to_bytes, urlparse

import auth
import bencode
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

    # BEP3 optional ip= override — accept ONLY valid dotted-quad IPv4 so a
    # client cannot inject an IPv6 address or hostname that would later cause
    # compact_peers to raise when encoding the peer list for other clients.
    raw_ip = raw.get("ip") or None
    ip = raw_ip if raw_ip is not None and _valid_ipv4(raw_ip) else None

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


def make_server(host, port, secrets_path, registry=None, on_announce=None):
    registry = registry or PeerRegistry()
    _grace = int(os.environ.get("IRIS_TOKEN_SKEW_GRACE", "300"))

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status, body):
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            query = parsed.query
            store = secrets_store.load(secrets_path)
            index = secrets_store.build_index(store)
            now = time.time()
            if not auth.check_announce_key(query, index, store, now, _grace):
                self._send(403, build_failure("missing or invalid token"))
                return
            if parsed.path == "/announce":
                self._handle_announce(query)
            elif parsed.path == "/scrape":
                self._handle_scrape(query)
            else:
                self._send(404, build_failure("not found"))

        def _handle_announce(self, query):
            if on_announce is not None:
                on_announce()
            a = parse_announce(query)
            # ip=None means the override was absent or invalid; fall back to
            # the socket source address.
            # port=None means the client sent an out-of-range value (>65535 or
            # <=0).  Registering the peer with a substitute port (e.g. 6881)
            # would advertise a reachable-looking but wrong port to every
            # leecher, causing silent connection failures during image staging.
            # Instead we skip registration entirely so the peer never appears
            # in compact_peers responses.
            peer_ip = a["ip"] or self.client_address[0]
            if a["port"] is None:
                # Out-of-range port: acknowledge the announce (200) but do not
                # register the peer so it is never returned to other clients.
                peers = registry.peers(a["info_hash"], a["peer_id"],
                                       numwant=a["numwant"])
                self._send(200, build_announce_response(
                    peers, compact=a["compact"]))
                return
            peer_port = a["port"]
            registry.announce(a["info_hash"], a["peer_id"],
                              peer_ip, peer_port,
                              event=a["event"], left=a["left"])
            peers = registry.peers(a["info_hash"], a["peer_id"],
                                   numwant=a["numwant"])
            self._send(200, build_announce_response(peers, compact=a["compact"]))

        def _handle_scrape(self, query):
            hashes = parse_qs(query).get("info_hash", [])
            if not hashes:
                self._send(400, build_failure("scrape requires info_hash"))
                return
            info_hex = binascii.hexlify(
                unquote_to_bytes(hashes[0].encode("latin1") if isinstance(
                    hashes[0], str) else hashes[0])).decode()
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

    # Telemetry owns a registry wired to its event hook; it is inert unless
    # IRIS_OTLP_ENDPOINT / IRIS_METRICS_PORT are configured.
    hub = telemetry.from_env()
    registry = hub.registry
    _start_pruner(registry)
    hub.start()
    mport = telemetry.metrics_port()
    if mport is not None:
        # External Prometheus /metrics is gated on IRIS_OBSERVABILITY (default
        # off) — IRIS doesn't assume a Grafana/Prometheus stack is around. The
        # self-contained swarm JSON (/swarm) is ALWAYS on; the map PAGE moved
        # into the console (:8080), so /swarmmap and / point there instead.
        obs = telemetry.observability_enabled()
        try:
            msrv = telemetry.make_metrics_server(
                "0.0.0.0", mport,
                hub.metrics_text if obs else None,
                swarm_provider=hub.swarm_snapshot,
                html=telemetry.moved_page)   # map page retired -> console pointer
            threading.Thread(target=msrv.serve_forever, daemon=True).start()
            print("swarm JSON on http://0.0.0.0:%d/swarm "
                  "(map page moved to the console :8080)%s"
                  % (mport, "  (metrics on /metrics)" if obs else
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
