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
import blocklist_reconciler as _reconciler
import peer_endpoints as _peer_endpoints
import peer_enforcement as _peer_enforcement
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
                record_endpoint=None, on_endpoint_failure=None,
                on_endpoint_change=None):
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
                return
            # A tracker-authored durable change: wake the reconciler for
            # immediate (sub-poll) application.
            if on_endpoint_change is not None:
                on_endpoint_change()

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


# ---------------------------------------------------------------------------
# Sole tracker blocklist reconciler (spec §0 / §7 / §13)
# ---------------------------------------------------------------------------

RECONCILE_POLL = 2.0   # max seconds before durable cross-process changes apply


class Aria2BlocklistAdapter:
    """Thin adapter exposing the reconciler's ``aria`` contract over the local
    aria2 JSON-RPC. It calls ``aria2.getSessionInfo`` for the counter epoch and
    ``aria2.setBtPeerBlocklist`` for the sole full-replace apply (spec §0). The
    RPC secret rides through the injected caller; no token is ever surfaced in
    an error (the reconciler records only the exception TYPE name)."""

    def __init__(self, rpc):
        self._rpc = rpc

    def get_session_id(self):
        session = self._rpc("aria2.getSessionInfo", [])
        return str((session or {}).get("sessionId") or "")

    def set_blocklist(self, ips):
        return self._rpc("aria2.setBtPeerBlocklist", [list(ips)]) or {}


def _stat_key(path):
    """Cheap change-detection key (mtime + size) for a durable file; missing
    file -> a sentinel. Same discipline as the console's StreamSettings poll."""
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


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

    Startup and every aria RPC transition to reachable / session change force a
    full valid desired apply (including a valid-empty list). ``fail_closed``
    never clears blocks from corruption and applies the emergency deny list; with
    no known address it stays fail-closed with no false ``enforced`` claim.
    """

    def __init__(self, policy_paths, endpoints_path, enforcement_path, aria,
                 pending_queue, active_participants, revoked_principals,
                 protected_seeder_ip=None, audit_export=None, now=None):
        self._policy_paths = policy_paths
        self._endpoints_path = endpoints_path
        self._enforcement_path = enforcement_path
        self._aria = aria
        self._pending = pending_queue
        self._active_participants = active_participants
        self._revoked_principals = revoked_principals
        self._protected_seeder_ip = protected_seeder_ip
        self._audit_export = audit_export
        self._now = now or time.time
        self._record_endpoint = _peer_endpoints.record_endpoint

        # Force-apply memory (never a source of desired state; spec §0 recomputes
        # from durable files each pass). None until the first successful apply.
        self._last_session = None
        self._last_hash = None
        self._rpc_ok = None            # None=unknown, then True/False

        # Serialization: exactly one reconcile at a time; a change during a run
        # schedules exactly one rerun (dirty flag).
        self._run_lock = threading.Lock()
        self._running = False
        self._dirty = False
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = None
        self._poll_keys = (None, None)

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
        self._guarded_run()
        while not self._stop.is_set():
            # Local wake (tracker-authored) OR the ≤2s poll deadline, whichever
            # comes first, then also poll durable stat keys for other-process
            # changes (spec §0 ≤2s max latency).
            self._wake.wait(timeout=RECONCILE_POLL)
            self._wake.clear()
            if self._stop.is_set():
                break
            keys = (_stat_key(self._policy_paths[0]),
                    _stat_key(self._endpoints_path))
            changed = keys != self._poll_keys
            self._poll_keys = keys
            # Always run on wake; on a bare poll only run when something changed.
            self._guarded_run()

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
        durable = _peer_endpoints.fresh_endpoints(self._endpoints_path, now)
        active = list(self._active_participants() or [])
        revoked = set(self._revoked_principals() or set())
        derived = _reconciler.derive_denied_set(
            policy, durable, pending_snapshot, active, revoked,
            self._protected_seeder_ip)

        # 3) Decide whether to force a full apply (startup / session change /
        #    RPC recovery) — otherwise skip a redundant identical apply.
        desired_hash = _reconciler.canonical_hash(derived.denied_ips)
        session = self._probe_session()
        force = (self._last_hash is None
                 or session != self._last_session
                 or self._rpc_ok is not True
                 or desired_hash != self._last_hash)

        outcome = None
        if force:
            outcome = _reconciler.apply_blocklist(
                self._aria, derived.denied_ips, derived.apply_empty)

        # 4) Persist the exact count-only enforcement status.
        status = self._build_status(
            now, policy, derived, desired_hash, outcome, pending_outstanding)

        # 5) Export the policy operation outbox (revision order, ack-gated).
        exported_rev = self._export_outbox(policy, status)
        status["last_operation_exported_revision"] = exported_rev

        _peer_enforcement.write_status(self._enforcement_path, status)
        return status

    def _retry_pending(self, now):
        # Local retry using the (possibly injected) endpoint writer so failure
        # injection is honored; mirrors peer_endpoints.retry_pending semantics.
        for key, ptype, pid, endpoint in self._pending.items():
            principal = auth.Principal(ptype, pid)
            try:
                self._record_endpoint(
                    self._endpoints_path, principal, endpoint["ipv4"],
                    endpoint["port"], now)
            except OSError:
                continue
            self._pending._drop_key(key)

    def _probe_session(self):
        try:
            return self._aria.get_session_id()
        except Exception:
            return None

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
        return _peer_enforcement.build_status(
            state=state, aria_session_id=session, desired_hash=eff_hash,
            applied_revision=applied_revision,
            desired_ip_count=len(derived.denied_ips), now=now,
            conflicts=conflicts, last_effect=last_effect, last_error=last_error)

    def _export_outbox(self, policy, status):
        """Export outbox entries with revision > the acked revision, in revision
        order, then advance the ack ONLY after the audit contract succeeds
        (spec §7/§13). On any audit failure the ack is not advanced so the
        entries replay on the next pass / after restart."""
        prior = _peer_enforcement.read_status(self._enforcement_path)
        acked = 0
        if prior:
            acked = prior.get("last_operation_exported_revision", 0) or 0
        entries = _peer_policy.pending_exports(policy.document, acked)
        if not entries:
            return acked
        if self._audit_export is None:
            return acked
        try:
            self._audit_export(entries)
        except Exception:
            return acked   # audit best-effort failed -> replay next pass
        return max(e["revision"] for e in entries)


def _build_reconciler_from_env(env, registry):
    """Construct the sole tracker reconciler from IRIS_* env (spec §0). The
    cross-process channel files live under ``IRIS_STATE``; the RPC secret rides
    through the injected JSON-RPC caller and is never surfaced in an error."""
    state_dir = env.get("IRIS_STATE", "/var/lib/iris")
    policy_path = os.path.join(state_dir, "peer-policy.json")
    lkg_path = os.path.join(state_dir, "peer-policy.lkg.json")
    endpoints_path = os.path.join(state_dir, "peer-endpoints.json")
    enforcement_path = os.path.join(state_dir, "peer-enforcement.json")
    audit_path = env.get("IRIS_AUDIT", "/etc/iris/audit.jsonl")

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
        aria=aria, pending_queue=_peer_endpoints.PendingEndpointQueue(),
        active_participants=lambda: _active_participants(registry),
        revoked_principals=lambda: set(),   # revocation view wired at Task 15
        protected_seeder_ip=env.get("IRIS_HOST_IP") or None,
        audit_export=audit_export)


def _active_participants(registry):
    """Flatten the live registry into ``{principal_type, principal_id, ipv4}``
    rows for the emergency (fail-closed) derivation."""
    rows = []
    for peers in registry.snapshot().values():
        for p in peers:
            rows.append({"principal_type": p["principal_type"],
                         "principal_id": p["principal_id"],
                         "ipv4": p["ip"]})
    return rows


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

    # The tracker is the SOLE blocklist reconciler (spec §0). Construct and
    # start it here; the announce path shares its pending queue and wakes it on
    # a tracker-authored durable endpoint change.
    reconciler = _build_reconciler_from_env(os.environ, registry)
    state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
    policy_paths = (os.path.join(state_dir, "peer-policy.json"),
                    os.path.join(state_dir, "peer-policy.lkg.json"))
    endpoints_path = os.path.join(state_dir, "peer-endpoints.json")

    srv = make_server(
        host, port, secrets_path, registry=registry,
        on_announce=hub.note_announce,
        policy_paths=policy_paths, endpoints_path=endpoints_path,
        pending_queue=reconciler._pending,
        on_endpoint_failure=reconciler.wake,
        on_endpoint_change=reconciler.wake)
    reconciler.start()
    print("tracker on http://%s:%d/announce" % (host, port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
