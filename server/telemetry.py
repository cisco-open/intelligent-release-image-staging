# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""IRIS telemetry orchestration (stdlib only).

Ties the tracker's in-process PeerRegistry to two emitters:
  * Prometheus `/metrics` (pull)  -- served by make_metrics_server()
  * OTLP/HTTP-JSON swarm events   -- pushed to the collector via otlp

A sampler loop polls the local seeder's aria2 RPC for serving throughput and
periodically flushes queued events. Everything here is best-effort and off the
announce critical path."""
import hashlib
import json
import os
import secrets
import socket
import ssl
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import audit
import auth
import bounded_pool
import api_problem
import api_routes
import tier_auth
import keyed_state
import live_samples
import metrics
import otlp
import peer_enforcement as _peer_enforcement
import peer_ledger as _peer_ledger
import peer_policy as _peer_policy
import telemetry_destination
import transfer_lifecycle as _transfer_lifecycle
from peer_registry import PeerRegistry

DEFAULT_INTERVAL = 15
# Sampling cadence while any connection is live. aria2's per-peer counters are
# per-connection and vanish with the connection, so the sample rate IS the
# attribution rate: measured against the origin's own uploadLength on the
# 7-router pull, 3 s sampling attributed 73.3 % of the bytes actually sent and
# 2 s sampling 88.1 %. 2 s is where that curve stops paying for its RPC cost;
# what is still missed is surfaced as residue rather than spread around. An
# idle swarm has nothing to miss, so the pass falls back to `interval` there.
ACTIVE_INTERVAL = 2
# How long the peer ledger keeps a torrent. These are cumulative counters and a
# pruned torrent restarts from zero, so retention sits well past the window any
# dashboard charts.
PEER_LEDGER_RETENTION = 30 * 86400
# Pruning takes the store lock and rewrites the file; hourly is far more often
# than a 30-day window needs.
PEER_LEDGER_PRUNE_INTERVAL = 3600
DEFAULT_METRICS_PORT = 9101
DEFAULT_RPC_URL = "http://127.0.0.1:6800/jsonrpc"
DEFAULT_RPC_SECRET_FILE = "/etc/iris/rpc-secret"
TELEMETRY_HANDSHAKE_TIMEOUT = 30


def local_tls_context(env=None):
    """Pinned TLS context for same-host calls to the telemetry listener."""
    env = os.environ if env is None else env
    cafile = env.get("IRIS_TELEMETRY_CA", "").strip()
    if not cafile:
        combined = env.get("IRIS_CERT", "/run/iris/tls/cert.pem")
        cafile = os.path.join(os.path.dirname(combined), "crt.pem")
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # The local client dials 127.0.0.1 while the device-facing certificate is
    # issued for IRIS_HOST_IP. Trust remains pinned to that certificate/CA;
    # only hostname comparison is inapplicable on this loopback hop.
    context.check_hostname = False
    return context


class _NoLocalRedirect(urllib.request.HTTPRedirectHandler):
    """Keep the scoped management bearer on its single local origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_local_swarm_url(raw, env=None, expected_path="/swarm"):
    """Return a strict same-container telemetry URL or raise ValueError."""
    env = os.environ if env is None else env
    value = (raw or "").strip()
    try:
        parts = urlparse(value)
        configured_port = int(env.get("IRIS_METRICS_PORT") or
                              DEFAULT_METRICS_PORT)
        port = parts.port or 443
    except (TypeError, ValueError):
        raise ValueError("invalid local swarm URL") from None
    if (parts.scheme != "https" or parts.hostname not in
            ("127.0.0.1", "localhost", "::1")
            or port != configured_port or parts.path != expected_path
            or parts.params or parts.query or parts.fragment
            or parts.username is not None or parts.password is not None):
        raise ValueError("invalid local swarm URL")
    return value


def local_swarm_get(url, token, timeout=3, env=None, expected_path="/swarm"):
    """Fetch an authenticated local telemetry document without redirects."""
    target = validate_local_swarm_url(
        url, env=env, expected_path=expected_path)
    request = urllib.request.Request(
        target, headers={"Authorization": "Bearer " + token})
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoLocalRedirect(),
        urllib.request.HTTPSHandler(context=local_tls_context(env)))
    with opener.open(request, timeout=timeout) as response:
        return response.read()


def _int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _report_event_id(report, device_id):
    """Return a persisted report id or a deterministic legacy fallback.

    Pre-event-id v1 rings are still exportable without minting a different id on
    every scan/restart. Copy only for that legacy fallback so the catalog state
    itself remains untouched.
    """
    key = "report_id" if report.get("schema") == "v2" \
        or report.get("report_id") is not None else "_event_id"
    event_id = report.get(key)
    if event_id is not None and str(event_id):
        return str(event_id), report
    try:
        encoded = json.dumps(
            {"device_id": device_id, "report": report}, sort_keys=True,
            separators=(",", ":"), default=str).encode()
    except Exception:
        encoded = (device_id + repr(report)).encode()
    event_id = "legacy-" + hashlib.sha256(encoded).hexdigest()
    record = dict(report)
    record[key] = event_id
    return event_id, record


def _otlp_record_event_id(record):
    """Return an OTLP LogRecord event.id attribute, if present."""
    if not isinstance(record, dict) or "timeUnixNano" not in record:
        return None
    for attr in record.get("attributes", []):
        if isinstance(attr, dict) and attr.get("key") == "event.id":
            value = attr.get("value", {})
            return value.get("stringValue") if isinstance(value, dict) else None
    return None


def poll_seeder(rpc):
    """Query the seeder aria2 RPC. `rpc(method, params)` returns the result.
    Returns (stats_dict, names, totals) where names maps info_hash -> image
    filename and totals maps info_hash -> total image bytes (for swarm-map
    progress). Any RPC failure yields ({"rpc_up": False}, {}, {})."""
    try:
        g = rpc("aria2.getGlobalStat", [])
        active = rpc("aria2.tellActive",
                      [["gid", "connections", "infoHash", "totalLength",
                        "uploadSpeed", "files"]])
    except Exception:
        return {"rpc_up": False}, {}, {}
    connections = sum(_int(d.get("connections")) for d in active)
    names, totals, upload_bps = {}, {}, {}
    for d in active:
        ih = d.get("infoHash")
        if not ih:
            continue
        files = d.get("files") or []
        path = files[0].get("path") if files else None
        if path:
            names[ih] = os.path.basename(path)
        if d.get("totalLength"):
            totals[ih] = _int(d.get("totalLength"))
        upload_bps[ih] = _int(d.get("uploadSpeed"))
    return {
        "rpc_up": True,
        "upload_speed": _int(g.get("uploadSpeed")),
        "download_speed": _int(g.get("downloadSpeed")),
        "active_torrents": _int(g.get("numActive")),
        # Torrents aria2 is holding back behind its concurrency cap. A seeding
        # torrent never completes, so a queued one is never served at all and
        # aria2 raises no error about it -- a device assigned that image just
        # reports staging forever. Non-zero here means the seeder is refusing
        # to serve a published image, which is otherwise invisible.
        "queued_torrents": _int(g.get("numWaiting")),
        "connections": connections,
        "torrent_upload_bps": upload_bps,
    }, names, totals


def _flag(value):
    """aria2's JSON-RPC renders booleans as the strings "true"/"false"."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


# getPeers keys the origin poll asks for. ``uploaded`` is aria2-next 2.5.6's
# per-connection cumulative counter (peer->getSessionUploadLength());
# ``seeder`` is peer->isSeeder(). Never ``bitfield``: per-piece state is large, changes
# every sample and answers no question this telemetry asks.
_PEER_KEYS = ["ip", "port", "uploadSpeed", "uploaded", "seeder"]


def poll_seeder_peers(rpc):
    """The server seeder's per-peer CURRENT send rate and per-CONNECTION
    cumulative bytes sent, plus the per-torrent control-state uploadLength
    gauge, tagged with aria2's session id so the caller can detect a counter
    epoch (session change / decrease).

    Returns (peer_up, upload_lengths, session_id, peer_bytes):
      * peer_up: {info_hash: {(ip, port): upload_bps}} — what the aria endpoint
        is INSTANTANEOUSLY sending to each connected device.
      * upload_lengths: {info_hash: bytes} — aria2's BitTorrent piece-payload
        uploadLength for that torrent over its control-state lifetime. It is a
        GAUGE: it can exceed the image size (re-sends/multiple leechers) and
        can decrease on control-state loss. It is never split across peers.
      * session_id: aria2.getSessionInfo's session id ("" when unavailable),
        identifying the counter epoch.
      * peer_bytes: {info_hash: {(ip, port): {"uploaded", "seeder"}}} — the
        cumulative bytes this origin has sent over that CONNECTION, and the
        peer's measured role. aria2 1.37 had no such counter, which is why this
        poll was rate-only for so long; aria2-next 2.5.6 (the build IRIS ships,
        pinned in tools/aria2c.sha256) does. It remains a per-CONNECTION
        counter — there is still no cross-connection per-peer total, and the
        torrent-wide counter is still never divided across peers. The caller
        accumulates these readings into peer_ledger instead, because the
        counter is EPHEMERAL: getPeers returns only LIVE connections, so a
        connection that opens and closes between two samples is never seen and
        its bytes stay in the unattributed residue.

    A failed control-state poll yields (None, None, session_id, None) — a
    caller must not present a retained view as a current observation."""
    peer_up, upload_lengths, peer_bytes = {}, {}, {}
    try:
        session = rpc("aria2.getSessionInfo", [])
        # An ABSENT sessionId is unknown too, not a new epoch. Both a failed
        # probe and a reply without the field collapse to the same "we do not
        # know" -- only a real, non-empty id is allowed to signal a restart.
        session_id = str((session or {}).get("sessionId") or "") or None
    except Exception:
        # UNKNOWN, not "". An empty string is a value, and the ledger reads a
        # changed value as an aria2 restart: it banks every connection
        # baseline, so the next sample re-counts each live connection's full
        # cumulative counter. One transient RPC hiccup would inflate every
        # peer's total. None says "no epoch information", which the ledger
        # leaves alone.
        session_id = None
    try:
        active = rpc("aria2.tellActive", [["gid", "infoHash", "uploadLength"]])
    except Exception:
        return None, None, session_id, None
    for d in active:
        ih, gid = d.get("infoHash"), d.get("gid")
        if not ih or not gid:
            continue
        upload_lengths[ih] = _int(d.get("uploadLength"))
        try:
            peers = rpc("aria2.getPeers", [gid, _PEER_KEYS])
        except Exception:
            continue
        m = peer_up.setdefault(ih, {})
        sent = peer_bytes.setdefault(ih, {})
        for p in peers:
            ip = p.get("ip")
            port = p.get("port")
            try:
                port = int(port)
            except (TypeError, ValueError):
                port = None
            if not (ip and port and 0 < port <= 65535):
                continue
            m[(ip, port)] = m.get((ip, port), 0) + _int(p.get("uploadSpeed"))
            seen = sent.get((ip, port))
            if seen is None:
                sent[(ip, port)] = {"uploaded": _int(p.get("uploaded")),
                                    "seeder": _flag(p.get("seeder"))}
            else:
                # One endpoint is one connection, so a repeated (ip, port) in a
                # single reply is two views of the same counter, not two
                # connections to add up. Rates do add; a counter does not.
                got = _int(p.get("uploaded"))
                seen["uploaded"] = max(seen["uploaded"], got)
                seen["seeder"] = seen["seeder"] or _flag(p.get("seeder"))
    return peer_up, upload_lengths, session_id, peer_bytes


def build_swarm(reg_stats, names):
    """Turn registry.stats() + a name map into metrics.render() rows."""
    rows = []
    for info_hash, s in reg_stats.items():
        row = dict(s)
        row["info_hash"] = info_hash
        row["image"] = names.get(info_hash, info_hash)
        rows.append(row)
    return rows


def make_jsonrpc_caller(rpc_url, secret):
    """Build an rpc(method, params) caller for an aria2 JSON-RPC endpoint."""
    def rpc(method, params=None):
        params = list(params or [])
        if secret:
            params = ["token:" + secret] + params
        body = json.dumps({"jsonrpc": "2.0", "id": "t",
                           "method": method, "params": params}).encode()
        req = urllib.request.Request(
            rpc_url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            out = json.loads(r.read().decode())
        if "error" in out:
            raise RuntimeError(out["error"])
        return out.get("result")
    return rpc


class ExportHealth:
    """Per-signal OTLP export health (design §10.10). Logs and metrics are
    INDEPENDENT signals, each ``off | ok | degraded``; the aggregate is
    ``worst_of`` so a metrics success can NEVER mask a logs failure. Each
    signal starts ``off`` until its first attempt. Audit transitions fire the
    callback exactly once per aggregate degraded edge, never carrying a secret.
    Disabling a signal sets it ``off`` while
    retaining its historic ``last_success_ts``. ``logs`` additionally surfaces
    the bounded-retry queue depth (``queued``) and overflow drops
    (``dropped_total``) from the hub-owned LogQueue."""

    _RANK = {"off": 0, "ok": 1, "degraded": 2}   # worst-of ordering

    def __init__(self, on_transition=None, log_queue=None):
        self._on = on_transition
        self._log_queue = log_queue
        self._sig = {
            "logs": {"state": "off", "last_success_ts": 0.0,
                     "fail_streak": 0, "failures_total": 0},
            "metrics": {"state": "off", "last_success_ts": 0.0,
                        "fail_streak": 0, "failures_total": 0},
        }
        self._aggregate = "off"

    def _fire(self, name):
        if self._on:
            self._on(name)

    def _recompute_aggregate(self):
        worst = max(self._sig.values(),
                    key=lambda s: self._RANK[s["state"]])["state"]
        if worst != self._aggregate:
            previous = self._aggregate
            self._aggregate = worst
            if previous != "degraded" and worst == "degraded":
                self._fire("otlp-export-degraded")
            elif previous == "degraded" and worst == "ok":
                self._fire("otlp-export-recovered")

    def record(self, ok, signal, now):
        s = self._sig.setdefault(
            signal, {"state": "off", "last_success_ts": 0.0,
                     "fail_streak": 0, "failures_total": 0})
        if ok:
            s["last_success_ts"] = now
            s["fail_streak"] = 0
            s["state"] = "ok"
        else:
            s["failures_total"] += 1
            s["fail_streak"] += 1
            s["state"] = "degraded"
        self._recompute_aggregate()

    def disable(self, signal):
        """Mark a signal ``off`` (destination disabled) while RETAINING its
        historic last-success timestamp (design §10.10)."""
        s = self._sig.get(signal)
        if s is None:
            return
        if s["state"] == "degraded":
            # leaving a degraded state for off is not a recovery to ok.
            pass
        s["state"] = "off"
        s["fail_streak"] = 0
        self._recompute_aggregate()

    def _signal_dict(self, signal):
        s = dict(self._sig[signal])
        if signal == "logs" and self._log_queue is not None:
            try:
                s["queued"] = int(self._log_queue.queued)
                s["dropped_total"] = int(self._log_queue.dropped_total)
            except Exception:
                pass
        return s

    def as_dict(self):
        signals = {name: self._signal_dict(name) for name in self._sig}
        # Top-level compatibility fields (worst-of aggregate): newest success
        # across signals + total failures across signals.
        last_success = max((s["last_success_ts"]
                            for s in self._sig.values()), default=0.0)
        failures_total = sum(s["failures_total"]
                             for s in self._sig.values())
        fail_streak = max((s["fail_streak"] for s in self._sig.values()),
                          default=0)
        return {
            "state": self._aggregate,
            "aggregate_rule": "worst_of",
            "signals": signals,
            "last_success_ts": last_success,
            "fail_streak": fail_streak,
            "failures_total": failures_total,
        }


# (OTLP metric name, unit, kind, stats() key) for the durable plan store.
# The bounds this store applies are only bounds an operator can check if the
# numbers behind them leave the process, so every counter TransferLifecycle
# keeps is published here: occupancy against its cap, the rollout signal
# (awaiting_report), the delivery backlog (unconfirmed) and the four ways a
# record or a row can be lost. Flat, attribute-free gauges and sums -- plan,
# device and image ids are high-cardinality and belong to the OTLP logs
# pipeline (design §10.8/§10.9), never to a metric label.
_LIFECYCLE_METRICS = (
    ("iris.transfer.lifecycle.plans", "{plan}", "gauge", "plans"),
    ("iris.transfer.lifecycle.plan_cap", "{plan}", "gauge", "plan_cap"),
    ("iris.transfer.lifecycle.awaiting_report", "{plan}", "gauge",
     "plans_awaiting_report"),
    ("iris.transfer.lifecycle.unconfirmed", "{event}", "gauge",
     "plans_unconfirmed"),
    ("iris.transfer.lifecycle.dropped_unemitted", "{plan}", "sum",
     "plans_dropped_unemitted"),
    ("iris.transfer.lifecycle.live_evicted", "{plan}", "sum",
     "plans_live_evicted"),
    ("iris.transfer.lifecycle.retired_undelivered", "{event}", "sum",
     "events_retired_undelivered"),
    ("iris.transfer.lifecycle.promoted_recovered", "{plan}", "sum",
     "plans_promoted_recovered"),
)


def _metric_points(rows, extras, now, export_signals=None, peer_status=None,
                   legacy_participants=None, seeder_torrents=None,
                   lifecycle=None):
    """Canonical OTLP metric points (design §10.9). OTLP dotted names, units,
    and low-cardinality image-level attrs ONLY. Ambiguous active/stalled and
    all per-device/per-peer gauges are RETIRED (high-cardinality history lives
    in OTLP logs, §10.8). Business gauges (throughput, progress) are OMITTED for
    a stale image; the freshness age is always emitted so omission is
    explainable."""
    pts = []
    for torrent in seeder_torrents or ():
        pts.append({"name": "iris.seeder.torrent.upload_length", "unit": "By",
                    "kind": "gauge", "value": _int(torrent["upload_length"]),
                    "attrs": {"iris.image.id": torrent["image_id"],
                              "iris.torrent.info_hash": torrent["info_hash"]},
                    "ts": now})
        # Origin -> swarm send rate, MEASURED by the origin's aria2 poll. It is
        # a LOWER BOUND on total swarm throughput: device-to-device reseed
        # traffic is invisible from here. It is emitted because the
        # device-reported iris.transfer.throughput is structurally unable to
        # observe a transfer shorter than one 60 s agent tick.
        pts.append({"name": "iris.seeder.torrent.upload_rate", "unit": "By/s",
                    "kind": "gauge", "value": _int(torrent.get("upload_bps")),
                    "attrs": {"iris.image.id": torrent["image_id"],
                              "iris.torrent.info_hash": torrent["info_hash"]},
                    "ts": now})
    for r in rows:
        base = {"iris.image.id": r["image"],
                "iris.torrent.info_hash": r["info_hash"]}
        pts.append({"name": "iris.transfer.devices", "unit": "{device}",
                    "kind": "gauge", "value": _int(r.get("devices")),
                    "attrs": base, "ts": now})
        if not r.get("stale"):
            for direction, key in (("receive", "receive_bps"),
                                   ("transmit", "transmit_bps")):
                pts.append({"name": "iris.transfer.throughput", "unit": "By/s",
                            "kind": "gauge", "value": _int(r.get(key)),
                            "attrs": dict(base, **{"network.io.direction":
                                                   direction}), "ts": now})
            pts.append({"name": "iris.transfer.progress", "unit": "1",
                        "kind": "gauge",
                        "value": float(r.get("progress_ratio") or 0.0),
                        "float": True, "attrs": base, "ts": now})
        pts.append({"name": "iris.transfer.zero_receive_devices",
                    "unit": "{device}", "kind": "gauge",
                    "value": 0 if r.get("stale")
                    else _int(r.get("zero_receive_devices")),
                    "attrs": base, "ts": now})
        pts.append({"name": "iris.transfer.freshness_age", "unit": "s",
                    "kind": "gauge",
                    "value": _int(r.get("freshness_age_seconds")),
                    "attrs": base, "ts": now})
        for sc in ("good", "constrained"):
            pts.append({"name": "iris.stream.devices", "unit": "{device}",
                        "kind": "gauge",
                        "value": _int(r.get("sampling_class_%s" % sc)),
                        "attrs": dict(base, **{"sampling_class": sc}),
                        "ts": now})
    pts.append({"name": "iris.telemetry.samples.rejected",
                "unit": "{sample}", "kind": "sum",
                "value": extras.get("samples_rejected_total", 0),
                "attrs": {}, "ts": now})
    if legacy_participants is not None:
        pts.append({"name": "iris.legacy.announce_participants",
                    "unit": "{participant}", "kind": "gauge",
                    "value": _int(legacy_participants), "attrs": {}, "ts": now})
    for signal, s in (export_signals or {}).items():
        if not isinstance(s, dict):
            continue
        attrs = {"signal": signal}
        pts.append({"name": "iris.telemetry.export.failures",
                    "unit": "{error}", "kind": "sum",
                    "value": _int(s.get("failures_total")),
                    "attrs": attrs, "ts": now})
        pts.append({"name": "iris.telemetry.export.dropped",
                    "unit": "{record}", "kind": "sum",
                    "value": _int(s.get("dropped_total")),
                    "attrs": attrs, "ts": now})
    for name, unit, key in (
        ("iris.peer.policy.revision", "1", "policy_revision"),
        ("iris.peer.enforcement.applied_revision", "1", "applied_revision"),
        ("iris.peer.enforcement.desired_ips", "{ip}", "desired_ip_count"),
        ("iris.peer.enforcement.health", "1", "health"),
    ):
        val = (peer_status or {}).get(key)
        if val is None:
            continue
        pts.append({"name": name, "unit": unit, "kind": "gauge",
                    "value": _int(val), "attrs": {}, "ts": now})
    for name, unit, kind, key in _LIFECYCLE_METRICS:
        val = (lifecycle or {}).get(key)
        if val is None:
            continue
        pts.append({"name": name, "unit": unit, "kind": kind,
                    "value": _int(val), "attrs": {}, "ts": now})
    return pts


TRANSFER_RECORD_SOURCE_CLASSES = ("origin", "device", "unknown")


def transfer_record_source_class(ip, origin_ips, device_by_ip):
    """Who sent the bytes in one ``peer_transfer_records`` row: ``"origin"`` (the
    authenticated ``service:seeder``), ``"device"`` (a device whose heartbeat
    claims that swarm address), or ``"unknown"``.

    THREE answers, never two. The origin seeder is an ordinary BitTorrent peer
    of every device, so it owns a transfer-record row like anyone else; an address that
    resolves to neither the origin nor a known device is UNKNOWN and stays
    unknown -- folding it into either side would be inventing the very
    attribution this function exists to establish. (Unknown is normal, not a
    bug: a device announcing from an address it never heartbeats, a peer that
    left the swarm before the report arrived, or a registry we could not read.)

    The row's own ``has_complete_file`` flag is deliberately NOT consulted:
    aria2 raises it for any peer holding the whole file, so in a multi-device
    wave every device that finishes early looks like a seeder by that test. Only
    the server can answer this, and only from authenticated identity."""
    key = str(ip)
    is_origin = key in (origin_ips or ())
    is_device = key in (device_by_ip or {})
    if is_origin and is_device:
        # One address claimed by both the origin and a device heartbeat: the
        # two claims cannot both be the sender, so we assert neither.
        return "unknown"
    if is_origin:
        return "origin"
    if is_device:
        return "device"
    return "unknown"


def classify_peer_transfer_records(block, origin_ips, device_by_ip):
    """Aggregate one stored ``peer_transfer_records`` block by sender class, or None
    when there is no block to classify (NOT MEASURED -- never a zeroed answer).

    The device measured exact bytes per BitTorrent peer and, correctly, made no
    claim about which peer was the origin: ``bytes_from_all_senders_total``
    includes the origin's bytes. This is where that total is split, using the
    two things only the server has -- the ``service:seeder`` principal's
    addresses and the swarm-IP -> device_id join.

    Four figures come back, and they are kept apart on purpose:
      * ``origin_bytes``      -- measured, from the origin seeder.
      * ``device_bytes``      -- measured, from other devices. THIS is the
        peer-to-peer number an operator means by "bytes from peers"; nothing
        else in this pipeline may carry that name.
      * ``unknown_bytes``     -- measured bytes whose sender we cannot name.
      * ``unattributed_omitted_bytes`` -- bytes real and measured, but belonging
        to rows a row cap dropped, so no address survives to classify them.
        Reported, never redistributed: spreading them across the named buckets
        pro rata is exactly the even-split fabrication removed in 2026.08.20.

    The four sum to ``bytes_from_all_senders_total`` -- restated here so a
    reader can check the split rather than trust it."""
    if not isinstance(block, dict):
        return None
    rows = block.get("rows")
    rows = rows if isinstance(rows, list) else []
    out = {"origin_rows": 0, "origin_bytes": 0,
           "device_rows": 0, "device_bytes": 0,
           "unknown_rows": 0, "unknown_bytes": 0}
    for row in rows:
        if not isinstance(row, dict):
            continue
        cls = transfer_record_source_class(row.get("ip"), origin_ips, device_by_ip)
        got = _int(row.get("session_bytes_from_peer"))
        out[cls + "_rows"] += 1
        out[cls + "_bytes"] += got
    out["unattributed_omitted_rows"] = _int(block.get("rows_omitted"))
    out["unattributed_omitted_bytes"] = _int(
        block.get("bytes_from_all_senders_omitted"))
    out["bytes_from_all_senders_total"] = _int(
        block.get("bytes_from_all_senders_total"))
    # complete=False means the capture itself missed peers, so every figure
    # above is a floor. Carried alongside so no consumer computes a percentage
    # out of a partial capture without seeing it.
    out["capture_complete"] = bool(block.get("complete"))
    return out


class Telemetry:
    """Owns the live state behind /metrics and drives event export."""

    def __init__(self, registry=None, exporter=None, rpc=None,
                 interval=DEFAULT_INTERVAL, device_info=None,
                 reports_info=None, live_info=None, images_info=None,
                 metrics_exporter=None, export_health=None,
                 device_metrics=False, dest_settings=None,
                 env_endpoint="", env_enabled=False, headers=None,
                 policy_info=None, enforcement_info=None, peer_ledger=None,
                 assignments_info=None, transfer_lifecycle=None,
                 attestations_info=None):
        self.exporter = exporter
        self._seen_report_event_ids = set()
        # event.id -> (plan_id, event, transfer_id) for every lifecycle record
        # this process has put on the queue and not yet seen acknowledged. The
        # queue's delivered-callback hands back event.ids and nothing else, so
        # this is how a delivery is turned back into the durable marker it
        # confirms. Bounded by the store's outstanding set, and pruned to it on
        # every pass that enumerates it (_emit_transfer_lifecycle). Declared
        # BEFORE configure_dedupe below, because that wires the callback that
        # reads it.
        self._lifecycle_queued = {}
        self._lifecycle_lock = threading.Lock()
        # Task 22: the OTLP log queue is a STABLE object owned by the hub for
        # the whole process; only the destination transport is mutable and
        # swapped on a console destination change/disable/re-enable, so
        # already-queued events survive the swap (design §8). The mutable
        # transport lives in self._log_transport (None when disabled / no
        # endpoint). Legacy direct-construction callers may still pass a
        # combined `exporter`; when they do we adopt its inner queue/transport
        # so the two code paths share one queue object.
        if exporter is not None and hasattr(exporter, "queue"):
            self.log_queue = exporter.queue
            self._log_transport = exporter.transport
        else:
            self.log_queue = otlp.LogQueue()
            self._log_transport = None
        # ONE delivered-callback slot, two consumers: report ids advance the
        # in-process replay guard, lifecycle ids write the durable delivery
        # marker. They are fanned out from a single wrapper rather than
        # competing for the slot -- whichever registered last would otherwise
        # silently disable the other.
        self.log_queue.configure_dedupe(
            _otlp_record_event_id, self._log_delivered)
        # Sender override hook (tests). Applied to every rebuilt transport.
        self._log_sender = None
        self.rpc = rpc
        self.interval = interval
        # OTLP metrics push (design §10.9) + shared export-health tracker.
        # device_metrics is RETIRED: per-device/per-peer metric gauges are
        # forbidden (§10.9 — that history lives in OTLP logs §10.8). The
        # constructor arg is retained for call-site compatibility but has no
        # effect on export.
        self.metrics_exporter = metrics_exporter
        self.export_health = export_health or ExportHealth()
        # Surface the hub-owned LogQueue depth/drops on the logs health signal
        # (design §10.10). Attaching post-construction keeps ExportHealth
        # constructable without the queue (tests).
        try:
            self.export_health._log_queue = self.log_queue
        except Exception:
            pass
        self.device_metrics = bool(device_metrics)
        # Console-editable OTLP destination (design 2026-08-19 feature B):
        # dest_settings is a telemetry_destination.DestinationSettings the
        # sampler consults at the top of every pass; a non-null file field
        # overrides the deployment env captured here, per field. None
        # (tests, direct construction) -> the explicitly passed exporters
        # are kept as-is forever. Headers stay startup-env (secrets) and are
        # re-applied to every rebuilt exporter.
        self._dest = dest_settings
        self._env_endpoint = (env_endpoint or "").strip()
        self._env_enabled = bool(env_enabled)
        self._headers = dict(headers or {})
        self._effective = None      # (endpoint, enabled) the exporters match
        # Optional callable -> the catalog's live-samples.json doc (spec 6.3);
        # aggregated per image each sample() pass. None -> no live streaming
        # surface (tests/standalone keep working unchanged).
        self._live_info = live_info
        # Optional callable -> catalog.json's images map, for the inner join
        # (spec 7.2 — second cardinality fence behind ingest).
        self._images_info = images_info
        self._transfers = []
        self._extras = {"stream_devices": 0, "samples_rejected_total": 0}
        # Optional callable -> {device_id: heartbeat record}. The catalog writes
        # these (one process over); we read them to label each swarm peer with
        # its device model, joined by the heartbeat's source IP (== swarm peer
        # IP). None in tests/standalone -> peers simply carry no model.
        self._device_info = device_info
        # Optional callable -> {device_id: [oldest..newest stored reports]}
        # (the catalog's telemetry.json ring, issue #13). Read fresh per use.
        # None in tests/standalone -> peers carry no report summary, nothing
        # is exported and the stored-reports gauge reads 0.
        self._reports_info = reports_info
        # Optional callables giving the tracker's CURRENT durable policy and
        # enforcement facts, so each typed device peer row carries its
        # per-participant peer_policy (operator intent) and peer_enforcement
        # (factual block state) from the tracker — the GUI/map never computes an
        # IP list or derives enforcement itself (spec §7/§10.3). Read fresh per
        # snapshot in the SAME (tracker) process; no cross-process identity
        # assumption. None (tests/standalone) -> rows carry no policy/enforcement.
        #   policy_info() -> peer_policy.PolicyResult (or None)
        #   enforcement_info() -> peer-enforcement.json dict (or None)
        self._policy_info = policy_info
        self._enforcement_info = enforcement_info
        # Optional callable -> the catalog's policy.json ({device_id: {…,
        # "plans": {image_id: {plan_id, transfer_id, planned_at,
        # info_hash}}}}), and the tracker's own TransferLifecycle
        # store. Together they drive the iris.transfer.lifecycle events
        # (planned -> seeding_started).
        #
        # `assignments_info` is NOT `policy_info`: that one is peer-policy
        # (per-participant network intent) and is a different file, a different
        # shape and a different subsystem. The names are one letter of intent
        # apart and would be silently interchangeable at the call site, so they
        # are deliberately kept distinct here rather than overloaded.
        #
        # Both default to None, and every lifecycle stage returns immediately
        # when either is unwired, so direct-construction callers (the whole
        # test suite, standalone runs) behave exactly as they did before this
        # existed: no store touched, no records queued.
        self._assignments_info = assignments_info
        self.transfer_lifecycle = transfer_lifecycle
        # The catalog's durable per-device transfer attestations. Read
        # alongside the report ring, never instead of it: the ring is capped
        # at five entries shared by every image on a device, so a terminal
        # report can rotate out of it between two sample passes and the
        # checksum precondition would then be unrecoverable. See
        # transfer_lifecycle.verified_facts.
        self._attestations_info = attestations_info
        # Per-process report ids already queued. Bound this set to the current
        # stored ring universe on every scan: a new hub deliberately replays the
        # ring at-least-once, while equal received_at values never shadow one
        # another behind a timestamp watermark.
        self._seeder = {"rpc_up": False}
        self._names = {}                    # last good info_hash -> name
        self._totals = {}                   # last good info_hash -> total bytes
        self._peer_up = {}          # info_hash -> {(ip, port): server upload bps}
        self._upload_len = {}               # info_hash -> control-state uploadLength gauge (epoch-baselined)
        self._torrent_upload_bps = {}       # info_hash -> aria2 current uploadSpeed
        self._torrent_observed_at = 0.0     # last successful control-state poll
        self._session_id = None             # aria2 session id bound to _upload_len; a change is a new epoch
        # Durable origin->peer attribution (peer_ledger.PeerLedger). None in
        # tests/standalone -> the poll still runs, nothing is accumulated.
        self.peer_ledger = peer_ledger
        self._ledger_pruned_at = 0.0
        self._counters = {"announces_total": 0, "announces_refused_total": 0,
                          "announces_refused_expired_total": 0}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        # When no registry is supplied, own one wired to our event hook — this
        # breaks the construction cycle (registry needs the hook, hook needs us).
        if registry is None:
            registry = PeerRegistry(on_event=self.on_swarm_event)
        self.registry = registry
        self._registry = registry

    # --- hooks called from the tracker (announce path) ---
    def on_swarm_event(self, event):
        # Task 22: always enqueue into the stable hub-owned queue; the queue is
        # never swapped by a destination change, so an event emitted here is
        # never lost to a transport swap. (A legacy `exporter` passed directly
        # shares this queue — see __init__.)
        self.log_queue.emit(event)

    def _emit_peer_rates(self, peer_up, now):
        """One ``iris.swarm.peer_rate`` record per measured connection.

        aria2 reports the socket endpoint, so match the announced endpoint
        first and fall back to the address when it is unambiguous — the same
        rule the swarm document uses. A peer we cannot attribute is skipped
        rather than guessed at.
        """
        if not peer_up:
            return
        try:
            snap = self._registry.snapshot(now=now)
        except Exception:
            return                      # telemetry is never on the critical path
        for info_hash, endpoints in (peer_up or {}).items():
            peers = snap.get(info_hash) or []
            by_ip = {}
            for row in peers:
                by_ip.setdefault(row.get("ip"), []).append(row)
            image_id = self._names.get(info_hash)
            for (ip, port), bps in (endpoints or {}).items():
                cands = by_ip.get(ip) or []
                match = next((c for c in cands if c.get("port") == port), None)
                if match is None and len(cands) == 1:
                    match = cands[0]
                if match is None:
                    continue
                ptype = match.get("principal_type")
                pid = match.get("principal_id")
                principal = ("%s:%s" % (ptype, pid)) if ptype and pid else None
                left = match.get("left")
                try:
                    # evictable: a sampled record (one per connection per
                    # 2 s pass) may be dropped under pressure; it must never
                    # evict a lifecycle/report/policy/tracker record.
                    self.log_queue.emit(otlp.build_peer_rate_record({
                        "principal": principal, "info_hash": info_hash,
                        "image_id": image_id, "ip": ip, "port": port,
                        "send_bps": bps, "left": left,
                        "role": "seeder" if left == 0 else "leecher",
                        "ts": now, "event_id": secrets.token_hex(16)}),
                        evictable=True)
                except Exception:
                    pass

    def emit_policy_event(self, entry, status):
        """Queue the canonical policy-operation record on this stable queue.
        This remains accepting when the OTLP transport is disabled."""
        return self.log_queue.emit(otlp.build_policy_record(entry, status))

    def note_announce(self):
        with self._lock:
            self._counters["announces_total"] += 1

    def note_announce_refused(self, expired=False):
        """A /announce or /scrape credential was refused (IRIS-111): the
        operator-visible half of the fix. Without this a rotated-out
        credential expiring past SEEDER_PREV_TTL produces a 403 with no
        counter anywhere -- iris_legacy_announce_participants then reads 0
        identically whether the fleet fully migrated or every un-migrated
        device just aged out and can no longer authenticate to be counted.
        ``expired`` (see auth.AnnounceAuthError.expired) narrows that to
        credentials that are KNOWN and simply timed out, as opposed to
        garbage/unknown ones."""
        with self._lock:
            self._counters["announces_refused_total"] += 1
            if expired:
                self._counters["announces_refused_expired_total"] += 1

    # --- /metrics provider ---
    def metrics_text(self):
        swarm = build_swarm(self._registry.stats(), self._names)
        with self._lock:
            counters = dict(self._counters)
        extras = dict(self._extras)
        extras["legacy_announce_participants"] = \
            self._legacy_participant_count()
        return metrics.render(swarm, self._seeder, counters,
                              reports_stored=self._reports_stored(),
                              transfers=self._transfers,
                               extras=extras,
                               otlp_health=self.export_health.as_dict(),
                               peer_status=self._peer_status_numbers(),
                               # Without this the whole ledger block in
                               # metrics.render() is dead at runtime and every
                               # aggregate panel on both dashboards is empty.
                               # render() was covered directly by tests, so
                               # nothing caught it -- test the ENDPOINT.
                               swarm_bytes=self.peer_ledger_totals(),
                               lifecycle=self._transfer_lifecycle_numbers(),
                               image_sizes=self._image_size_metrics(),
                               seeder_torrents=self._seeder_torrent_metrics(
                                   time.time()))

    def _seeder_torrent_metrics(self, now):
        """Current control-state gauges, inner-joined to the image catalog.

        A failed/vanished peer poll clears ``_upload_len`` in ``sample()``, so
        this never republishes a retained value as a zero or stale observation.
        """
        if (not self._seeder.get("rpc_up") or not self._upload_len
                or not self._torrent_observed_at
                or now - self._torrent_observed_at > 2 * self.interval):
            return []
        try:
            images = self._images_info() if self._images_info else {}
        except Exception:
            return []
        if not isinstance(images, dict):
            return []
        known = {str(entry.get("info_hash_hex")): (str(image_id),
                 entry.get("filename", image_id))
                 for image_id, entry in images.items()
                 if isinstance(entry, dict) and entry.get("info_hash_hex")}
        return [{"image_id": image_id, "image": image,
                 "info_hash": info_hash, "upload_length": upload_length,
                 # Measured by the origin's own aria2 poll every `interval`
                 # seconds, independent of any device tick. This is what makes
                 # a transfer visible at all: the device-reported rate is
                 # sampled once per 60 s agent tick, and a 929 MB image at lab
                 # speed finishes in 7-33 s, so the device tick can never land
                 # inside the transfer window.
                 "upload_bps": _int(
                     (self._torrent_upload_bps or {}).get(info_hash))}
                for info_hash, upload_length in self._upload_len.items()
                for image_id, image in [known.get(str(info_hash), (None, None))]
                if image_id is not None]

    def _image_size_metrics(self):
        """Catalog image sizes for the iris_image_size_bytes family. Exact by
        construction -- publish.py records os.path.getsize of the file itself
        -- and static per image, so unlike the seeder gauges there is no
        freshness window to respect. Rows without both a size and an
        info_hash are skipped: a partial row would be a guess, and the boards
        prefer "no data" over one."""
        try:
            images = self._images_info() if self._images_info else {}
        except Exception:
            return []
        if not isinstance(images, dict):
            return []
        return [{"image": entry.get("filename", image_id),
                 "info_hash": str(entry.get("info_hash_hex")),
                 "size": entry["size"]}
                for image_id, entry in sorted(images.items())
                if isinstance(entry, dict) and entry.get("info_hash_hex")
                and isinstance(entry.get("size"), int) and entry["size"] > 0]

    def _legacy_participant_count(self):
        """Distinct current ``legacy_unattributed`` announce participants
        (design §10.9). Any announce on a previous/legacy token, IP-independent;
        a rollout-completeness signal (0 = fully migrated). Counted from the
        registry snapshot — never a per-peer/per-IP label. Never breaks."""
        try:
            seen = set()
            for peers in self._registry.snapshot().values():
                for p in peers:
                    if p.get("principal_type") == "legacy":
                        seen.add((p.get("ip"), p.get("port")))
            return len(seen)
        except Exception:
            return 0

    def _reports_stored(self):
        """Total stored device reports (all devices), derived fresh at render
        time from the catalog's telemetry.json — the two processes only share
        the state file. 0 when unwired or unreadable (never breaks)."""
        if self._reports_info is None:
            return 0
        try:
            data = self._reports_info() or {}
            return sum(len(v) for v in data.values() if isinstance(v, list))
        except Exception:
            return 0

    # --- sampler ---
    def _refresh_exporters(self):
        """Re-resolve the effective OTLP destination (console override file
        overrides deployment env, per field — design 2026-08-19 feature B)
        and build/swap/drop the exporters when it changed. With no exporters
        the pass's export stages exit early (the existing None checks below).
        CPython attribute assignment is atomic, so the announce-path reader
        (on_swarm_event) is race-benign across object→object swaps — worst
        case one event lands in the old exporter's queue (bounded, best-effort
        by design). Readers must snapshot the attribute once (e.g. exp =
        self.exporter) because a swap-to-None is not otherwise safe.
        ExportHealth is hub-owned and survives every swap: a destination
        change while degraded gives the new endpoint a fresh chance on the
        next pass. No-op when no DestinationSettings is wired (direct
        construction: tests and standalone keep their explicit exporters)."""
        if self._dest is None:
            return
        file_endpoint, file_enabled = self._dest.current()
        endpoint = self._env_endpoint if file_endpoint is None \
            else file_endpoint
        enabled = self._env_enabled if file_enabled is None else file_enabled
        effective = (endpoint, bool(enabled))
        if effective == self._effective:
            return
        self._effective = effective
        sender = self._log_sender
        authenticated_plaintext = bool(
            self._headers and endpoint
            and urlparse(endpoint).scheme.lower() != "https")
        if enabled and endpoint and not authenticated_plaintext:
            # Task 22: swap ONLY the mutable transport; the hub-owned
            # log_queue is untouched, so events queued under the previous
            # destination flush to the new one. Metrics stay conflating (no
            # queue) and are rebuilt wholesale.
            self._log_transport = otlp.OTLPLogTransport(
                endpoint, sender=sender, headers=self._headers)
            self.metrics_exporter = otlp.OTLPMetricsExporter(
                endpoint, headers=self._headers)
        else:
            # Disabled, or no endpoint anywhere: drop the transport but RETAIN
            # the queue (no fake success — queued events wait for a live
            # destination). The rest of the pass still runs (seeder poll, live
            # aggregation) — the swarm map and /metrics text don't depend on
            # OTLP export.
            self._log_transport = None
            self.metrics_exporter = None
            # Destination disabled/absent: mark both signals off while
            # retaining historic last-success (design §10.10).
            try:
                self.export_health.disable("logs")
                self.export_health.disable("metrics")
            except Exception:
                pass
        # `self.exporter` remains the "logs export enabled" gate used across
        # the sampler; it is truthy exactly when a transport is wired.
        self.exporter = self._log_transport

    def _flush_logs(self, now):
        """Flush the stable log queue through the current transport (if any),
        recording per-signal export health. A disabled/absent transport is NOT
        a success and NOT a failure — the queue is simply retained. Returns the
        delivered count (or None when no attempt was made)."""
        transport = self._log_transport
        if transport is None:
            return None
        delivered = self.log_queue.flush(transport.send)
        if delivered is not None:           # None = empty queue, no attempt
            self.export_health.record(delivered > 0, "logs", now)
        return delivered

    def sample_seeder(self, now=None):
        """The aria2 half of a pass: poll the origin, refresh the control-state
        view, accumulate per-edge attribution and queue the measured peer
        records. Split out of sample() because it runs on its OWN, faster
        cadence (see ACTIVE_INTERVAL) — the per-connection counters it reads
        are ephemeral, while report export, log flush and the metrics push it
        deliberately leaves behind are unaffected by how often we look."""
        if self.rpc is None:
            return
        now = time.time() if now is None else now
        seeder, names, totals = poll_seeder(self.rpc)
        self._seeder = seeder
        peer_up, upload_lengths, session_id, peer_bytes = \
            poll_seeder_peers(self.rpc)
        polls_ok = seeder.get("rpc_up") and upload_lengths is not None
        if polls_ok:
            # A successful tellActive is a complete replacement snapshot:
            # vanished torrents are no longer current control state.
            self._names = names
            self._totals = totals
            self._torrent_upload_bps = seeder.get("torrent_upload_bps", {})
        # Per-peer CURRENT send rate (measured) + the per-torrent control-state
        # uploadLength gauge, tagged with aria2's session id. The gauge is
        # reported VERBATIM every pass -- increases, image-size overshoot and
        # a reset to a lower value after an aria2 restart are all simply the
        # current reading; nothing here bridges across a counter epoch. The
        # DURABLE per-edge attribution built alongside it is where epochs
        # matter, and peer_ledger.observe handles them: the ledger banks each
        # observed delta as it happens, so a session change that invalidates
        # every baseline costs the bytes of one sample interval, not the
        # accumulated history.
        if polls_ok:
            self._peer_up = peer_up
            self._upload_len = {}
            self._torrent_observed_at = now
            # Peer-labelled history belongs in the OTLP LOG stream, not in
            # metrics: one record per measured edge, per sample, so a
            # backend can chart origin -> peer speed over time without the
            # cardinality a per-peer metric label would create.
            self._emit_peer_rates(peer_up, now)
            self._observe_peer_bytes(peer_bytes, upload_lengths, session_id,
                                     now)
        else:
            # Do not present retained gauges/rates as a current observation
            # after a failed control-state poll.
            self._peer_up = {}
            self._upload_len = {}
            self._torrent_upload_bps = {}
            self._torrent_observed_at = 0.0
            self._seeder = {"rpc_up": False}
        self._session_id = session_id
        for info_hash, now_len in (upload_lengths or {}).items():
            self._upload_len[info_hash] = now_len

    def _observe_peer_bytes(self, peer_bytes, upload_lengths, session_id, now):
        """Bank this sample's per-connection counters and queue one
        ``iris.swarm.peer_bytes`` record per edge that gained bytes.

        The ledger is the record of truth here, not the log stream: it is
        written before anything is queued, so a dropped or undelivered record
        costs a data point on a chart, never an accounting of where the load
        went. The origin's torrent-wide total and the edge counters are banked
        in one ledger transaction, after applying any aria2 session change, so
        both readings belong to the same counter epoch."""
        ledger = self.peer_ledger
        if ledger is None:
            return
        devices = self._device_by_ip(self._read_device_info())
        for info_hash in sorted(set(upload_lengths or {})
                                | set(peer_bytes or {})):
            image_id = self._names.get(info_hash)
            conns = (peer_bytes or {}).get(info_hash) or {}
            try:
                rows = ledger.observe(
                    info_hash, image_id,
                    {key: obs["uploaded"] for key, obs in conns.items()},
                    session_id, now=now,
                    upload_length=(upload_lengths or {}).get(info_hash))
            except Exception:
                continue        # telemetry is never on the critical path
            # The ledger accumulates per IP; the role is per connection. A peer
            # seeding on any of its connections is a seeder.
            roles = {}
            for (ip, _port), obs in conns.items():
                roles[ip] = roles.get(ip, False) or bool(obs["seeder"])
            for row in rows:
                record = dict(row, ts=now, event_id=secrets.token_hex(16))
                device_id = devices.get(row["ip"])
                if device_id:
                    record["device_id"] = device_id
                role = roles.get(row["ip"])
                if role is not None:
                    record["role"] = "seeder" if role else "leecher"
                try:
                    # evictable: the ledger already holds these bytes
                    # durably; the record is a chart point, not the account.
                    self.log_queue.emit(otlp.build_peer_bytes_record(record),
                                        evictable=True)
                except Exception:
                    pass
        self._prune_peer_ledger(now)

    def _prune_peer_ledger(self, now):
        """Drop torrents nobody has observed inside the retention window."""
        if self.peer_ledger is None or \
                now - self._ledger_pruned_at < PEER_LEDGER_PRUNE_INTERVAL:
            return
        self._ledger_pruned_at = now
        try:
            self.peer_ledger.prune(now - PEER_LEDGER_RETENTION)
        except Exception:
            pass

    def peer_ledger_totals(self):
        """Per-torrent origin/attributed/unattributed byte totals for the
        aggregate metric series, or {} when no ledger is wired. Cumulative and
        durable, so a completed transfer keeps its history after the swarm
        goes idle — the panels do not blank out."""
        if self.peer_ledger is None:
            return {}
        try:
            return self.peer_ledger.torrent_totals()
        except Exception:
            return {}

    def sample(self, now=None):
        now = time.time() if now is None else now
        self._refresh_exporters()
        self.sample_seeder(now)
        if self._live_info is not None:
            try:
                live_doc = self._live_info()
                transfers, extras = aggregate_transfers(
                    live_doc,
                    self._images_info() if self._images_info else {}, now)
                if not isinstance(live_doc, dict):
                    # No snapshot to read: the catalog's cumulative rejected
                    # count is UNKNOWN, not zero. It is exported as a
                    # monotonic sum / Prometheus counter, and a 0 here would
                    # read as a counter reset followed by a phantom burst of
                    # rejections when the value comes back. Carry the last
                    # known value (a stale-but-present snapshot carries its
                    # own last-written count, see aggregate_transfers).
                    extras["samples_rejected_total"] = self._extras.get(
                        "samples_rejected_total", 0)
                self._transfers, self._extras = transfers, extras
            except Exception:
                pass                        # telemetry never breaks on bad input
        # Latch OUTSIDE the exporter guard (see _observe_transfer_lifecycle):
        # the facts behind a seeding event are durable observations, and a
        # deployment that enables OTLP export later must be able to publish the
        # plans that were already in flight while it was off.
        try:
            self._observe_transfer_lifecycle(now)
        except Exception:
            pass                            # telemetry never breaks on bad input
        if self.exporter is not None and self._reports_info is not None:
            try:
                self._export_new_reports()
            except Exception:
                pass                        # telemetry never breaks on bad input
        if self.exporter is not None:
            try:
                self._emit_transfer_lifecycle()
            except Exception:
                pass                        # telemetry never breaks on bad input
            delivered = self._flush_logs(now)
        if self.metrics_exporter is not None:
            # Every pass exports the latest snapshot (conflation, spec 7.5) —
            # NOT gated on transfers existing: the rejected-samples counter and
            # export sums must flow even on a quiet fleet. Per-device gauges are
            # RETIRED (design §10.9 forbids device/peer labels on metrics — that
            # history lives in OTLP logs §10.8).
            signals = self.export_health.as_dict().get("signals")
            ok = self.metrics_exporter.export(_metric_points(
                self._transfers, self._extras, now,
                export_signals=signals,
                peer_status=self._peer_status_numbers(),
                legacy_participants=self._legacy_participant_count(),
                seeder_torrents=self._seeder_torrent_metrics(now),
                lifecycle=self._transfer_lifecycle_numbers()))
            self.export_health.record(ok, "metrics", now)

    def _observe_transfer_lifecycle(self, now):
        """Latch this pass's transfer-lifecycle facts into the durable store.

        The tracker is the only process that can do this at all: it owns the
        PeerRegistry (precondition 3 — this device is announcing left=0 on the
        image's torrent under its own authenticated principal) while the
        catalog's policy.json and telemetry.json give it the plan set and the
        device's verified terminal reports (preconditions 1+2). No other
        process sees all three at once.

        Called OUTSIDE sample()'s exporter guard on purpose. Latching is a
        durable observation, not an export: a fleet running with OTLP export
        switched off still accumulates its facts, so turning the destination on
        later publishes the plans that were already in flight instead of
        silently losing their start instants. Emission is the separate
        `_emit_transfer_lifecycle` stage, which does sit behind the guard.

        `observe()` is called on EVERY pass, including one that finds no live
        plans: it is also what cancels a row whose assignment was withdrawn and
        what prunes retired rows, so short-circuiting on an empty plan set
        would leave a fleet's worth of rows open forever. (A transiently
        unreadable policy.json therefore reads as "nothing assigned" for one
        pass; the store reopens such a row when the plan reappears, which is
        why that read failure is survivable rather than terminal.)
        """
        store = self.transfer_lifecycle
        if store is None or self._assignments_info is None:
            return
        live = _transfer_lifecycle.live_plans_from_policy(
            self._assignments_info())
        # Each fact source is read defensively on its own: these are separate
        # cross-process JSON files plus one in-process registry, and losing one
        # of them must cost only the facts it carries. An empty reports map
        # simply latches no checksum this pass; an empty snapshot latches no
        # seeder. Both latches are first-write-wins and durable, so a pass that
        # sees less than the last one can never retract what was already
        # observed.
        try:
            reports = (self._reports_info() or {}) \
                if self._reports_info is not None else {}
        except Exception:
            reports = {}
        try:
            images = self._images_info() if self._images_info else {}
        except Exception:
            images = {}
        try:
            snapshot = self._registry.snapshot(now=now)
        except Exception:
            snapshot = {}
        try:
            attestations = (self._attestations_info() or {}) \
                if self._attestations_info is not None else {}
        except Exception:
            attestations = {}
        verified = _transfer_lifecycle.verified_facts(live, reports,
                                                      attestations)
        seeder = _transfer_lifecycle.seeder_facts(live, snapshot, images)
        store.observe(live, verified, seeder, now)

    def _emit_transfer_lifecycle(self):
        """Queue every lifecycle record the collector has not acknowledged.

        MARK AFTER THE EFFECT, NEVER BEFORE. `LogQueue.emit` returns a bool and
        `is not False` is the house signal for "the queue accepted it" (the
        same test `tracker._export_outbox` uses to advance its watermark). On a
        refusal — a zero-capacity queue — the marker stays unwritten and the
        next pass retries with a byte-identical record, because both the
        timestamps and the deterministic `event.id` were latched into the row
        before any record was built. Writing the marker first would instead
        lose the event for good.

        ACCEPTANCE IS NOT DELIVERY, so the enqueue marker is not the end of it.
        A FULL queue does not refuse: it evicts its oldest record and returns
        True, and a record already queued can be evicted by later announce
        traffic before any flush succeeds. The store therefore keeps a row
        outstanding until `mark_delivered_many` confirms a successful send, and
        this pass re-queues any outstanding record the queue no longer holds —
        `contains` first, exactly as `_export_new_reports` does, so a record
        still waiting is never queued twice.

        The retry only runs with a live transport. With no destination wired
        nothing can ever be acknowledged, so re-queueing evicted records would
        do nothing but churn a bounded queue and evict other signals to make
        room for records that cannot leave either.

        The residual window is a crash between a successful send and its
        marker, which re-emits the SAME record under the SAME `event.id` —
        at-least-once with a backend-dedupable id, the contract peer_policy's
        outbox already states.
        """
        store = self.transfer_lifecycle
        if store is None:
            return
        retry = self._log_transport is not None
        due = store.outstanding_emissions() if retry \
            else store.pending_emissions()
        # Build first, register second, emit third. Registering before the
        # emit closes the window where a flush delivers a record whose
        # event.id is not yet in the map and the delivery is lost.
        records = []
        for plan_id, row, event in due:
            record = otlp.build_transfer_lifecycle_record(row, event)
            event_id = _otlp_record_event_id(record)
            if event_id is None:
                continue                # unkeyed: nothing could confirm it
            emitted = row.get("emitted")
            records.append((event_id, record,
                            (plan_id, event, row.get("transfer_id")),
                            isinstance(emitted, dict) and event in emitted))
        with self._lifecycle_lock:
            for event_id, _record, item, _marked in records:
                self._lifecycle_queued[event_id] = item
            # Anything else in the map belongs to a row that has since been
            # acknowledged, evicted or pruned, so the map stays the size of
            # what the store still owes rather than growing an entry per plan
            # for the life of the process. Dropping an entry costs nothing:
            # only a delivery consumes one, a delivery needs a transport, and
            # with a transport the next pass re-registers the whole
            # outstanding set anyway.
            live = {event_id for event_id, _r, _i, _m in records}
            for event_id in [key for key in self._lifecycle_queued
                             if key not in live]:
                del self._lifecycle_queued[event_id]
        marks = []
        for event_id, record, item, marked in records:
            if self.log_queue.contains(event_id):
                continue                # still queued or in flight
            if self.log_queue.emit(record) is False:
                continue                # refused: stays pending for next pass
            if not marked:
                marks.append(item)
        # One locked read-modify-write for the whole pass. Marking one at a
        # time re-serialised and re-renamed the entire store per event, on the
        # thread that then has to flush telemetry. Each item carries its
        # expected transfer_id, which makes the mark refuse a row that was
        # replaced by a NEW plan for the same device+image between the read
        # above and this write: without it the new plan would inherit the old
        # one's marker and never be published.
        store.mark_emitted_many(marks)

    def _export_new_reports(self):
        """Emit one OTLP log record per stored device report not yet queued.
        Identity, not received_at, is the cursor so reports sharing a server
        timestamp are all exported. A fresh hub replays the bounded ring with
        the same IDs for backend deduplication.
        Each record is enriched from the device's last heartbeat (model,
        flash, stage state — capped/coerced inside build_report_record) plus
        the swarm IP->device_id join for peer-row resolution (spec 7.6)."""
        devices = self._read_device_info()
        device_by_ip = self._device_by_ip(devices)
        origin_ips = self._origin_swarm_ips()
        reports = self._reports_info() or {}
        candidates = []
        ring_event_ids = set()
        for device_id, ring in reports.items():
            if not isinstance(ring, list):
                continue
            rec = devices.get(device_id)
            rec = rec if isinstance(rec, dict) else {}
            enrich = {"model": rec.get("model"),
                      "free_flash_bytes": rec.get("free_flash_bytes"),
                      "stage_state": rec.get("stage_state"),
                      "peer_devices": device_by_ip}
            for rep in ring:
                if not isinstance(rep, dict):
                    continue
                # peer_transfer_records is per REPORT, not per device, so its
                # origin/device/unknown split rides with the report it
                # describes. Absent block -> absent key: not measured is not
                # zero, and an all-zero split would read as "no peer bytes".
                split = classify_peer_transfer_records(
                    rep.get("peer_transfer_records"), origin_ips, device_by_ip)
                rep_enrich = enrich if split is None else dict(
                    enrich, peer_transfer_record_attribution=split)
                event_id, record = _report_event_id(rep, str(device_id))
                ring_event_ids.add(event_id)
                try:
                    received_at = float(rep.get("received_at", 0) or 0)
                except (TypeError, ValueError):
                    received_at = 0.0
                candidates.append((received_at, event_id, str(device_id),
                                   record, rep_enrich))
        # Delivered report IDs need only cover the current durable ring. Queued
        # records are independently deduped by LogQueue, so forgetting an ID
        # that has left the ring cannot cause a scan-time re-enqueue.
        self._seen_report_event_ids.intersection_update(ring_event_ids)
        for _, event_id, device_id, report, enrich in sorted(
                candidates, key=lambda row: row[:3]):
            if (event_id not in self._seen_report_event_ids
                    and not self.log_queue.contains(event_id)):
                self.log_queue.emit(otlp.build_report_record(
                    report, device_id, enrich=enrich))
                # Fan the transfer-record block out into one record per peer. Without
                # this the exact device-side measurement stops in the catalog
                # and only the per-transfer rollups leave the server -- the
                # lossy sampled estimate (iris.swarm.peer_bytes) would be the
                # only per-edge data a backend ever saw, which is the wrong way
                # round. classify is bound here, not inside otlp: a second copy
                # of the origin/device identity rule would drift, and the copy
                # that drifts is the one an operator reads a peer share off.
                for peer_record in otlp.build_peer_transfer_records(
                        report, device_id, enrich=enrich,
                        classify=lambda ip: transfer_record_source_class(
                            ip, origin_ips, device_by_ip)):
                    self.log_queue.emit(peer_record)

    def _read_device_info(self):
        """The catalog's {device_id: heartbeat record}, or {} when unwired or
        unreadable. Read fresh per use (cheap JSON file)."""
        if self._device_info is None:
            return {}
        try:
            devices = self._device_info() or {}
        except Exception:
            return {}
        return devices if isinstance(devices, dict) else {}

    def _origin_swarm_ips(self):
        """The addresses the origin is currently announcing from -- the typed
        ``service:seeder`` principal's registry rows, the same identity source
        _seeder_torrent_metrics uses.

        Identity comes from the authenticated principal, never from an address
        list or a peer's own seeder flag. Never breaks: an unreadable registry
        yields an empty set, which sends every transfer-record row to ``unknown``
        rather than quietly promoting the origin's bytes to peer-delivered."""
        ips = set()
        try:
            snapshot = self._registry.snapshot()
        except Exception:
            return ips
        for peers in snapshot.values():
            if not isinstance(peers, list):
                continue
            for peer in peers:
                if not isinstance(peer, dict):
                    continue
                if peer.get("principal_type") == "service" \
                        and peer.get("principal_id") == "seeder" \
                        and peer.get("ip"):
                    ips.add(str(peer["ip"]))
        return ips

    @staticmethod
    def _device_by_ip(devices):
        """The swarm IP -> device_id join (spec 7.6). A heartbeat with no
        swarm_ip cannot be joined to a peer and is left out rather than
        matched on something weaker."""
        return {rec.get("swarm_ip"): str(did)
                for did, rec in devices.items()
                if isinstance(rec, dict) and rec.get("swarm_ip")}

    def _log_delivered(self, event_ids):
        """The queue's single delivered-callback, fanned out to both owners.

        Called from `LogQueue.flush` ONLY after a send succeeded, with the
        event.ids of the batch that went out. Reports first: that guard is a
        plain set update and cannot fail, so the lifecycle store's file write
        can never cost the report path its cursor.
        """
        self._reports_delivered(event_ids)
        self._lifecycle_delivered(event_ids)

    def _reports_delivered(self, event_ids):
        self._seen_report_event_ids.update(event_ids)

    def _lifecycle_delivered(self, event_ids):
        """Turn delivered event.ids back into durable delivery markers.

        This is the ONLY thing that retires a lifecycle event: everything
        before it says the record reached a queue that may still drop it. A
        failed write leaves the row outstanding, so the next pass re-queues the
        same record under the same event.id — at-least-once, backend-dedupable,
        which is the right way round to fail.
        """
        store = self.transfer_lifecycle
        marks = []
        with self._lifecycle_lock:
            for event_id in event_ids or ():
                item = self._lifecycle_queued.pop(event_id, None)
                if item is not None:
                    marks.append(item)
        if store is None or not marks:
            return
        try:
            store.mark_delivered_many(marks)
        except Exception:
            pass                        # telemetry is never on the critical path

    # --- live per-peer swarm view (for the swarm map) ---
    def swarm_snapshot(self, now=None):
        """Canonical source-grouped swarm snapshot (spec §10.3). Every value
        sits under a NAMED source object with its own observation time:

          * ``server`` — the origin seeder/hub (its own ``server_observation``:
            global rates, per-torrent control-state ``upload_length_bytes``
            gauge). Never a peer node in the rings.
          * ``images[].peers[]`` — each participant grouped by source:
            ``tracker`` (authenticated presence), optional ``device_observation``
            (freshness-gated live snapshot), optional current
            ``server_observation.peer`` (this-connection rate), optional
            ``latest_report``, optional ``peer_policy``/``peer_enforcement``,
            optional heartbeat staging state (``current_image_id``,
            ``stage_state``, ``staged_image_ids``, ``errored_image_ids`` --
            issue: multi-image assignment) for a typed device principal.

        Identity joins (device_observation / latest_report / policy /
        enforcement) are keyed ONLY by the authenticated device **principal id**
        from the registry — NEVER by source IP. A heartbeat ``swarm_ip`` may not
        establish identity. Legacy-credential rows are ``legacy_unattributed``
        and carry no device attribution or quarantine control.
        """
        now = time.time() if now is None else now
        # Identity-keyed joins: device_id -> record / report / live sample.
        # Keyed by device_id (== the authenticated device principal id), NOT by
        # any heartbeat/source IP (spec §10.3: no IP-based identity join).
        devices_by_id = self._devices_by_id()
        report_by_device = self._reports_by_device()
        live_by_device = self._live_by_device()
        policy = self._policy_snapshot()
        enforcement = self._enforcement_snapshot()
        derived_denied = _derived_denied_ids(enforcement)

        images = []
        for info_hash, peers in self._registry.snapshot(now=now).items():
            total = self._totals.get(info_hash)
            up_now = self._peer_up.get(info_hash, {}) \
                if (self._torrent_observed_at and
                    now - self._torrent_observed_at <= 2 * self.interval) else {}
            out = []
            for p in peers:
                ptype = p.get("principal_type")
                pid = p.get("principal_id")
                # The current, non-legacy service seeder is the central hub, not
                # a peer node: dedupe it out of the rings (labelled seeder lives
                # under `server`). A device literally named `seeder`
                # (device:seeder) stays a device peer.
                if ptype == "service" and pid == "seeder":
                    continue
                out.append(_peer_row(
                    p, total, up_now, devices_by_id, report_by_device,
                    live_by_device, policy, enforcement, derived_denied, now,
                    self._torrent_observed_at))
            images.append({
                "image": self._names.get(info_hash, info_hash),
                "info_hash": info_hash,
                "total_bytes": total,
                "seeders": sum(1 for p in peers if p["is_seeder"]),
                "leechers": sum(1 for p in peers if not p["is_seeder"]),
                "peers": out,
            })
        return {
            "now": now,
            "server": self._server_source(now),
            "images": images,
        }

    def _server_source(self, now):
        """The ``server`` source object (spec §10.3): the origin seeder's own
        ``server_observation`` — global current rates/connections/active
        torrents plus per-torrent control-state ``upload_length_bytes`` gauges.
        No secret, no session token; ``aria_session_id`` is the nonsecret epoch
        id already surfaced by the seeder poll."""
        torrents = []
        for info_hash in sorted(self._upload_len):
            torrents.append({
                "info_hash": info_hash,
                "image": self._names.get(info_hash, info_hash),
                # control-state uploadLength gauge (BitTorrent piece payload over
                # the torrent's control-state lifetime — may exceed image size,
                # never a per-device total).
                "upload_length_bytes": self._upload_len.get(info_hash, 0),
                "upload_bps": self._torrent_upload_bps.get(info_hash, 0),
                "lifetime": "control-state",
            })
        service = []
        # Per-torrent facts from current typed service:seeder registry rows.
        # Do not infer identity from IP/token or let one fresh announce stand in
        # for a different torrent during a credential-rotation proof.
        last_seen_by_info_hash = {}
        latest_seen = None
        for info_hash, peers in self._registry.snapshot(now=now).items():
            for peer in peers:
                if peer.get("principal_type") == "service" \
                        and peer.get("principal_id") == "seeder":
                    service.append(info_hash)
                    seen = peer.get("last_seen")
                    if isinstance(seen, (int, float)):
                        last_seen_by_info_hash[info_hash] = seen
                    if seen is not None and (latest_seen is None or seen > latest_seen):
                        latest_seen = seen
                    break
        observation = {
            "observed_at": self._torrent_observed_at,
            "rpc_up": bool(self._seeder.get("rpc_up")),
            "unavailable": not bool(self._seeder.get("rpc_up")),
            "aria_session_id": self._session_id,
        }
        if self._seeder.get("rpc_up"):
            observation["global"] = {
                "send_bps": self._seeder["upload_speed"],
                "receive_bps": self._seeder["download_speed"],
                "connections": self._seeder["connections"],
                "active_torrents": self._seeder["active_torrents"],
                "queued_torrents": self._seeder.get("queued_torrents", 0),
            }
            observation["torrent"] = torrents
        if service:
            observation["tracker_observation"] = {
                "principal_type": "service", "principal_id": "seeder",
                "observed_info_hashes": sorted(service),
                "last_seen": latest_seen,
                "last_seen_by_info_hash": last_seen_by_info_hash,
            }
        return {
            "host": os.environ.get("IRIS_HOST_IP", ""),
            "server_observation": observation,
        }

    def _devices_by_id(self):
        """{device_id: heartbeat record}. The catalog's devices.json is keyed by
        device_id; we key our join on the authenticated principal id (device_id),
        never on any ``swarm_ip``. Telemetry never breaks on bad input."""
        out = {}
        if self._device_info is None:
            return out
        try:
            for device_id, rec in (self._device_info() or {}).items():
                if isinstance(rec, dict):
                    out[str(device_id)] = rec
        except Exception:
            pass
        return out

    def _reports_by_device(self):
        out = {}
        if self._reports_info is None:
            return out
        try:
            for device_id, ring in (self._reports_info() or {}).items():
                summary = _report_summary(ring)
                if summary is not None:
                    out[str(device_id)] = summary
        except Exception:
            pass
        return out

    def _live_by_device(self):
        if self._live_info is None:
            return {}
        try:
            doc = self._live_info() or {}
            samples = doc.get("samples") or {}
            return samples if isinstance(samples, dict) else {}
        except Exception:
            return {}

    def _policy_snapshot(self):
        if self._policy_info is None:
            return None
        try:
            return self._policy_info()
        except Exception:
            return None

    def _enforcement_snapshot(self):
        if self._enforcement_info is None:
            return None
        try:
            data = self._enforcement_info()
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    # Numeric enforcement health mapping (design §10.9): a single gauge, not a
    # one-hot label set. `fail_closed` is a degraded-security posture and maps
    # to -1 (degraded) so no false "enforced" is ever reported.
    _ENFORCEMENT_HEALTH = {"enforced": 1, "pending": 0, "degraded": -1,
                           "fail_closed": -1, "rpc_unavailable": -2}

    def _peer_status_numbers(self):
        """Low-cardinality numeric peer-policy/enforcement facts for the metric
        gauges (§10.9): current policy revision + enforcement applied revision,
        desired-IP count, and numeric health. None entries are omitted by the
        renderer. Reads the tracker's own durable stores fresh; never a raw IP
        list, never per-IP labels."""
        out = {}
        policy = self._policy_snapshot()
        doc = getattr(policy, "document", None)
        if isinstance(doc, dict) and isinstance(doc.get("revision"), int) \
                and not isinstance(doc.get("revision"), bool):
            out["policy_revision"] = doc["revision"]
        enf = self._enforcement_snapshot()
        if isinstance(enf, dict):
            if isinstance(enf.get("applied_revision"), int) \
                    and not isinstance(enf.get("applied_revision"), bool):
                out["applied_revision"] = enf["applied_revision"]
            if isinstance(enf.get("desired_ip_count"), int) \
                    and not isinstance(enf.get("desired_ip_count"), bool):
                out["desired_ip_count"] = enf["desired_ip_count"]
            health = self._ENFORCEMENT_HEALTH.get(enf.get("state"))
            if health is not None:
                out["health"] = health
        return out or None

    def _transfer_lifecycle_numbers(self):
        """``TransferLifecycle.stats()`` for the metric surfaces, or None.

        The store applies two hard bounds (MAX_PLANS, PLAN_RETENTION) and
        counts every row and record they cost. Until this existed nothing read
        those counters, so a fleet past its cap, or a collector outage long
        enough to age out unacknowledged records, presented to an operator as
        lifecycle events that simply never arrived -- indistinguishable from a
        fleet that never seeded. Read fresh each pass; the store is small and
        the tracker is its only writer.

        None on any failure, and the renderers omit the whole block rather
        than publishing zeros: an unreadable store is NOT a store with nothing
        in it, and a fabricated zero here would read as "the bound never bit".
        """
        store = self.transfer_lifecycle
        if store is None:
            return None
        try:
            stats = store.stats()
        except Exception:
            return None
        return stats if isinstance(stats, dict) else None

    def _sample_interval(self):
        """Seconds until the next pass. Fast while any connection is live —
        the per-connection counters are ephemeral, so a slow tick is bytes
        nobody can ever attribute — and back to the configured interval when
        the swarm is idle and there is nothing to catch."""
        if any(self._peer_up.values()):
            return min(ACTIVE_INTERVAL, self.interval)
        return self.interval

    def run_forever(self):
        next_full = 0.0
        while not self._stop.wait(self._sample_interval()):
            try:
                now = time.time()
                if now >= next_full:
                    next_full = now + self.interval
                    self.sample(now)
                else:
                    # Between full passes only the aria2 poll runs. Export
                    # cadence is unchanged: the records it queues wait on the
                    # bounded LogQueue for the next flush, and the ledger they
                    # came from is already durable if that queue overflows.
                    self.sample_seeder(now)
            except Exception:
                pass                        # never let the sampler die

    def start(self):
        threading.Thread(target=self.run_forever, daemon=True).start()

    def stop(self):
        self._stop.set()


def _read_rpc_secret(env):
    secret = env.get("IRIS_RPC_SECRET")
    if secret is not None:
        return secret
    try:
        with open(env.get("IRIS_RPC_SECRET_FILE", DEFAULT_RPC_SECRET_FILE)) as f:
            return f.read().strip()
    except OSError:
        return ""


def from_env(env=None):
    """Build a Telemetry hub from IRIS_* env vars. The seeder RPC is always
    wired (it is local; failures just surface as iris_seeder_rpc_up 0) so the
    swarm map keeps working, and the hub is ALWAYS constructed — the sampler
    always runs. External OTLP export is resolved per sample PASS from the
    effective config: the console's telemetry-destination.json override when
    a field is non-null, else the deployment env (IRIS_OBSERVABILITY AND
    IRIS_OTLP_ENDPOINT both required — the default-off posture). IRIS makes
    no assumptions about any observability stack being around."""
    env = os.environ if env is None else env
    endpoint = env.get("IRIS_OTLP_ENDPOINT", "").strip()
    # Headers stay startup-env only (they are secrets with an existing
    # file-based path — never console-editable); read unconditionally so a
    # console enable-from-off still authenticates to the collector.
    headers = otlp.read_headers_env(env)
    device_metrics = env.get("IRIS_OTLP_DEVICE_METRICS",
                             "").strip().lower() in ("1", "true", "yes", "on")
    audit_path = env.get("IRIS_AUDIT", "/etc/iris/audit.jsonl")

    def _on_transition(name):
        try:
            # category so the console's audit filter can find these; actor
            # system; no device_id (the old "tracker" pseudo-device made
            # the event look like a device's).
            audit.append_event(audit_path, name, category="telemetry",
                               actor="system", target="otlp-export",
                               detail="otlp export state change")
        except Exception:
            pass                            # audit must never break telemetry
    export_health = ExportHealth(on_transition=_on_transition)
    rpc = make_jsonrpc_caller(env.get("IRIS_RPC", DEFAULT_RPC_URL),
                              _read_rpc_secret(env))
    interval = _int(env.get("IRIS_SAMPLE_INTERVAL")) or DEFAULT_INTERVAL
    # Read the catalog's per-device heartbeat records (written by the catalog
    # process in the same container) so the swarm map can label peers by model.
    state_dir = env.get("IRIS_STATE", "/var/lib/iris")
    device_info = lambda: _read_devices(state_dir)
    reports_info = lambda: _read_reports(state_dir)
    # The catalog's durable per-device transfer attestations, written at
    # ingest. The report ring alone cannot carry the checksum precondition:
    # it holds five entries per DEVICE, shared by every image and report kind,
    # so a burst of completions evicts a terminal report before the tracker's
    # next pass reads it.
    attestations_info = lambda: _read_attestations(state_dir)
    live_info = lambda: _read_live_samples(state_dir)
    images_info = lambda: _read_images(state_dir)
    # The catalog's assignment file, carrying the plan ids minted by
    # set_policy. Read fresh per pass like every other cross-process file here.
    assignments_info = lambda: _read_assignments(state_dir)
    # Per-participant policy/enforcement facts (spec §7/§10.3). Read the tracker
    # process's own durable stores — same process, no cross-process identity
    # assumption. peer-policy resolves the current authoritative/LKG/fail-closed
    # PolicyResult; peer-enforcement reads the tracker-written status file.
    policy_paths = (os.path.join(state_dir, "peer-policy.json"),
                    os.path.join(state_dir, "peer-policy.lkg.json"))
    enforcement_path = os.path.join(state_dir, "peer-enforcement.json")
    policy_info = lambda: _read_policy(policy_paths)
    enforcement_info = lambda: _peer_enforcement.read_status(enforcement_path)
    dest = telemetry_destination.DestinationSettings(
        telemetry_destination.settings_path(state_dir))
    # Durable origin->peer attribution. An unwritable state dir is not fatal:
    # the rest of the telemetry keeps working, minus per-edge accumulation.
    try:
        ledger = _peer_ledger.PeerLedger(state_dir)
    except OSError:
        ledger = None
    # Durable plan lifecycle. Same rule as the ledger: an unwritable state dir
    # costs the lifecycle events and nothing else, and the identity those
    # events carry lives in policy.json regardless, so nothing is lost that a
    # later pass over a writable directory cannot rebuild.
    try:
        lifecycle = _transfer_lifecycle.TransferLifecycle(state_dir)
    except OSError:
        lifecycle = None
    hub = Telemetry(rpc=rpc, interval=interval,
                    device_info=device_info, reports_info=reports_info,
                    live_info=live_info, images_info=images_info,
                    export_health=export_health,
                    device_metrics=device_metrics,
                    dest_settings=dest,
                    env_endpoint=endpoint,
                    env_enabled=observability_enabled(env),
                    headers=headers,
                    policy_info=policy_info,
                    enforcement_info=enforcement_info,
                    peer_ledger=ledger,
                    assignments_info=assignments_info,
                    transfer_lifecycle=lifecycle,
                    attestations_info=attestations_info)
    # Build the initial exporters NOW (not on the first pass) so swarm events
    # from the announce path are captured from process start, exactly as the
    # construction-time exporters were before the destination became editable.
    hub._refresh_exporters()
    return hub


def _read_devices(state_dir):
    """The catalog's heartbeat records ({device_id: record}) or {} if they
    aren't there yet / are unreadable. Read fresh each call.

    The catalog writes this as KEYED state (``devices.d/``, see
    keyed_state.read_all), one row per device rather than one whole-fleet
    document; read_all also still reads a legacy ``devices.json`` that has not
    been migrated yet, so this reader spans both."""
    return keyed_state.read_all(os.path.join(state_dir, "devices.json"))


def _read_assignments(state_dir):
    """The catalog's policy.json ({device_id: assignment record, including its
    per-image ``plans`` map}) or {} if it isn't there yet / unreadable / not a
    dict. Read fresh each call, like _read_devices.

    This is the ASSIGNMENT policy written by CatalogStore.set_policy — not
    peer-policy.json, which _read_policy handles and which is an unrelated
    subsystem. Returning {} on an unreadable file is safe here only because the
    lifecycle store reopens a plan that reappears: no id lives in this
    process, so a transient read failure costs one pass, never an identity."""
    return keyed_state.read_all(os.path.join(state_dir, "policy.json"))


def _read_attestations(state_dir):
    """The catalog's transfer-attestations.json ({device_id: [attestation,
    ...]}) or {} if it isn't there yet / unreadable / not a dict. Read fresh
    each call (small, bounded file). Telemetry never breaks on bad input."""
    return keyed_state.read_all(
        os.path.join(state_dir, "transfer-attestations.json"))


def _read_reports(state_dir):
    """The catalog's telemetry.json ({device_id: [oldest..newest stored
    reports]}) or {} if it isn't there yet / unreadable / not a dict. Read
    fresh each call (small, ring-bounded file — 5 reports x <=16 KB per
    device). Telemetry never breaks on bad input."""
    return keyed_state.read_all(os.path.join(state_dir, "telemetry.json"))


def _peer_row(p, total, up_now, devices_by_id, report_by_device,
              live_by_device, policy, enforcement, derived_denied, now,
              server_observed_at=None):
    """One canonical peer row (spec §10.3), source-grouped. All device
    attribution joins on the authenticated device principal id, never on the
    source IP."""
    ptype = p.get("principal_type")
    pid = p.get("principal_id")
    left = p.get("left")
    if p["is_seeder"]:
        progress = 1.0
    elif total and left is not None:
        progress = max(0.0, min(1.0, 1.0 - left / total))
    else:
        progress = None

    tracker = {
        "principal_type": ptype,
        "role": "seeder" if p["is_seeder"] else "leecher",
        "left": left,
        "last_seen": p.get("last_seen"),
        "progress": progress,
    }
    # principal_id present for attributable (device/service) principals; omitted
    # for legacy (spec §0a/§10.3).
    if ptype != "legacy" and pid is not None:
        tracker["principal_id"] = pid

    row = {"ip": p["ip"], "port": p["port"], "tracker": tracker}

    # Legacy-credential participant: no device to attribute (regardless of IP).
    # No device_observation / latest_report / peer_policy / model; cannot be
    # individually quarantined until it re-downloads a personalized torrent.
    if ptype == "legacy":
        tracker["participant_class"] = p.get(
            "participant_class", "legacy_unattributed")
        row["warning"] = "legacy_unattributed"
        row["device_id"] = None
        row["quarantine_available"] = False
        return row

    # Measured current this-connection send rate to this peer, scoped under the
    # server_observation.peer source (never an inferred cumulative per-peer
    # total — that machinery is retired). Present only when measured (>0 or a
    # known connection); we surface it whenever the seeder poll saw the ip.
    #
    # aria2 reports the SOCKET endpoint. A leecher dials the origin seeder, so
    # the port aria2 sees is that peer's ephemeral source port, not the listen
    # port it announced to the tracker. Matching on (ip, port) alone therefore
    # drops the rate for every incoming connection — i.e. every normal transfer.
    # Prefer the exact endpoint; fall back to the address when it is
    # unambiguous. When one address really does carry several connections, sum
    # them but SAY SO, so the row is never a silent merge.
    endpoint = (p["ip"], p["port"])
    measured, same_ip = None, None
    if endpoint in up_now:
        measured = up_now[endpoint]
    else:
        same_ip = [bps for (ip_, _port), bps in up_now.items()
                   if ip_ == p["ip"]]
        if len(same_ip) == 1:
            measured = same_ip[0]
        elif len(same_ip) > 1:
            measured = sum(same_ip)
    if measured is not None:
        peer_obs = {"send_bps": measured, "observed_at": server_observed_at}
        if same_ip is not None and len(same_ip) > 1:
            peer_obs["aggregated_connections"] = len(same_ip)
        row["server_observation"] = {"peer": peer_obs}

    # Attributable device principals only: identity-keyed joins by principal id.
    if ptype == "device" and pid is not None:
        device_id = pid
        rec = devices_by_id.get(device_id) or {}
        model = rec.get("model")
        dobs = _device_observation(live_by_device.get(device_id), now)
        if dobs is not None:
            row["device_observation"] = dobs
        report = report_by_device.get(device_id)
        if report is not None:
            row["latest_report"] = report
        pol = _peer_policy_fact(policy, ptype, device_id, p["ip"])
        if pol is not None:
            row["peer_policy"] = pol
        enf = _peer_enforcement_fact(
            enforcement, derived_denied, ptype, device_id, p["ip"])
        if enf is not None:
            row["peer_enforcement"] = enf
        # model + device_id ONLY for typed device principals (spec §10.3).
        if model is not None:
            row["model"] = model
        row["device_id"] = device_id
        # Multi-image staging state, straight from the same heartbeat record
        # (issue: multi-image assignment) -- unmodified, so the swarm-map
        # drawer can list every image this device's agent is currently
        # tracking state for. Omitted (not None-valued) when the heartbeat
        # never carried the field, matching model/device_observation/etc
        # above: absence is a fact, never invented as null.
        if rec.get("current_image_id") is not None:
            row["current_image_id"] = rec.get("current_image_id")
        if rec.get("stage_state") is not None:
            row["stage_state"] = rec.get("stage_state")
        if rec.get("staged_image_ids") is not None:
            row["staged_image_ids"] = rec.get("staged_image_ids")
        if rec.get("errored_image_ids") is not None:
            row["errored_image_ids"] = rec.get("errored_image_ids")
    return row


def _device_observation(entry, now):
    """The ``device_observation`` source object (spec §3/§10.3) built from the
    canonical live-samples state (Task 20 LiveTable snapshot). Interprets v1/v2
    freshness exactly:

      * ``valid = observed_received_at + LIVE_VALUE_VALIDITY(120s) >= now`` and
        only for a currently-``observed`` entry. A valid observed row surfaces
        the current rates/counters. Once invalid it is ``stale`` retained
        context: it keeps ``age_s`` but OMITS receive/send/connections/current
        counters (the map greys the last value, never a fresh zero).
      * ``zero_receive_rate`` is a fresh-snapshot boolean — true ONLY when a
        currently-valid observed aria snapshot reports ``receive_bps==0`` while
        ``aria.status=="active"``; never asserted from a stale value.
      * paused/disabled/not_active/rpc_unavailable are non-observed states
        represented WITHOUT fresh rates.

    v1 entries are projected under a ``schema:"v1"`` marker using their mapped
    legacy fields with explicit names/source — never reinterpreted as v2."""
    if not isinstance(entry, dict):
        return None
    schema = entry.get("schema", "v2")
    obs_state = entry.get("obs_state", "observed")
    try:
        base = float(entry.get("observed_received_at",
                               entry.get("received_at", 0.0)))
    except (TypeError, ValueError):
        base = 0.0
    age_s = int(now - base) if base else None
    # Recompute freshness against OUR now (the live-samples.json is written on
    # the catalog's own cadence, so a stored ``valid`` flag can lag): the value
    # is valid only for a currently-observed entry within LIVE_VALUE_VALIDITY of
    # its observed receipt (spec §3B/§4). A withdrawn/non-observed state is never
    # valid regardless of age.
    valid = (obs_state in (None, "observed")
             and bool(entry.get("valid"))
             and base + live_samples.LIVE_VALUE_VALIDITY >= now)

    out = {"schema": schema, "obs_state": obs_state,
           "observed_at": entry.get("observed_at"),
           "valid": valid, "stale": not valid, "age_s": age_s}

    if not valid:
        # Stale / withdrawn: retained context only; omit all fresh counters.
        return out

    if schema == "v1":
        # v1 rollout: map its legacy fields with explicit v1-source names; do
        # NOT reinterpret them as v2 measurements.
        out["receive_bps"] = _int(entry.get("down_bps"))
        out["send_bps"] = _int(entry.get("up_bps"))
        out["completed_content_bytes"] = _int(entry.get("done_bytes"))
        # v1 has no aria.status; zero_receive_rate needs an active aria status.
        out["zero_receive_rate"] = False
        return out

    aria = entry.get("aria") if isinstance(entry.get("aria"), dict) else {}
    receive_bps = _int(aria.get("receive_bps"))
    out["receive_bps"] = receive_bps
    out["send_bps"] = _int(aria.get("send_bps"))
    out["connections"] = _int(aria.get("connections"))
    out["completed_content_bytes"] = _int(aria.get("completed_content_bytes"))
    out["zero_receive_rate"] = (aria.get("status") == "active"
                                and receive_bps == 0)
    return out


def _peer_policy_fact(policy, principal_type, device_id, ipv4):
    """Per-participant ``peer_policy`` fact (operator intent) for a typed device
    principal, evaluated against the tracker's CURRENT PolicyStore (spec §7).
    Exposes the decision, matched rule sequence, the assigned ACL name, and
    whether the reserved quarantine ACL is assigned. ``fail_closed`` is explicit.
    None when no policy is wired."""
    if policy is None:
        return None
    doc = getattr(policy, "document", None)
    if not isinstance(doc, dict):
        return None
    fail_closed = bool(getattr(policy, "fail_closed", False))
    principal = auth.Principal(principal_type, device_id)
    try:
        decision, matched_seq = _peer_policy.evaluate(doc, principal, ipv4)
    except Exception:
        decision, matched_seq = ("permit", None)
    assignment = doc.get("assignments", {}).get(device_id)
    return {
        "decision": "deny" if fail_closed else decision,
        "matched_seq": matched_seq,
        "assignment": assignment,
        "quarantined": assignment == _peer_policy.RESERVED_QUARANTINE,
        "fail_closed": fail_closed,
    }


def _derived_denied_ids(enforcement):
    """The set of device ids the tracker DIRECTLY tells us it globally blocked
    via typed conflicts (never a raw IP list — the enforcement status
    intentionally exposes only a count and typed conflicts). A conflict is only
    a block fact when its ``global_block_applied`` is truthy; a recorded
    shared_permit_deny conflict with ``global_block_applied`` false means the
    tracker did NOT block this IP (spec §5/§7 Day1 semantics), so it must NOT
    be inferred as denied. The count-only enforcement path lacks the actual
    denied principal list, so membership is never inferred from conflict
    presence or the aggregate desired count. Returns a set of denied device ids."""
    denied = set()
    if not isinstance(enforcement, dict):
        return denied
    for c in enforcement.get("conflicts") or []:
        if not isinstance(c, dict):
            continue
        if c.get("denied_principal_type") == "device" \
                and c.get("global_block_applied"):
            did = c.get("denied_principal_id")
            if did is not None:
                denied.add(did)
    return denied


def _peer_enforcement_fact(enforcement, derived_denied, principal_type,
                           device_id, ipv4):
    """Per-participant ``peer_enforcement`` fact (spec §7/§10.3). Factual, not a
    causal claim: ``blocked`` is asserted only when this device's typed conflict
    carries ``global_block_applied`` true. Aggregate state (including
    ``fail_closed``), policy intent, and counts cannot prove an ordinary device
    was blocked, so ``blocked`` is omitted without that direct fact. A recorded
    shared_permit_deny conflict with ``global_block_applied`` false is surfaced
    with ``blocked`` false. The raw denied-IP list is never read (it is not
    exposed). ``state`` mirrors the tracker's aggregate enforcement state. None
    when unwired."""
    if not isinstance(enforcement, dict):
        return None
    state = enforcement.get("state")
    fact = {"state": state}
    # Surface a shared-IP conflict for this participant when the tracker
    # published one (typed, count-safe — no raw list).
    for c in enforcement.get("conflicts") or []:
        if isinstance(c, dict) \
                and c.get("denied_principal_type") == "device" \
                and c.get("denied_principal_id") == device_id:
            fact["conflict"] = {
                "reason": c.get("reason"),
                "global_block_applied": c.get("global_block_applied"),
            }
            # This typed conflict is the only per-device block evidence. The
            # aggregate state and policy intent cannot prove this peer's block.
            fact["blocked"] = bool(c.get("global_block_applied"))
            break
    return fact


def _report_summary(ring):
    """The ``latest_report`` summary of a device's LATEST stored report. v2
    reports (spec §10.2) surface the taxonomy-correct fields
    (report_id/event/content_sha256_state/ios_copy_verify_state/received_at,
    schema:"v2"). v1 reports get a SAFE legacy summary only (event/tier and
    legacy link/transfer fields, schema:"v1") and are NEVER reinterpreted as v2
    (e.g. a v1 ``avg_bps`` is never surfaced as a v2 field). Full per-peer rows
    stay in the console drawer (payload discipline). None on empty/garbage."""
    try:
        rep = ring[-1]
        if not isinstance(rep, dict):
            return None
    except Exception:
        return None
    schema = rep.get("schema")
    is_v2 = schema == "v2" or rep.get("v") == 2 or "report_id" in rep
    if is_v2:
        sha = rep.get("content_sha256")
        sha = sha if isinstance(sha, dict) else {}
        ios = rep.get("ios_copy_verify")
        ios = ios if isinstance(ios, dict) else {}
        return {
            "schema": "v2",
            "report_id": rep.get("report_id"),
            "event": rep.get("event"),
            "content_sha256_state": sha.get("state"),
            "ios_copy_verify_state": ios.get("state"),
            "received_at": rep.get("received_at"),
        }
    # v1 SAFE summary only — legacy fields kept under an explicit v1 marker,
    # never mapped onto a v2 field name.
    link = rep.get("link")
    link = link if isinstance(link, dict) else {}
    return {
        "schema": "v1",
        "event": rep.get("event"),
        "tier": link.get("tier"),
        "rtt_ms_median": link.get("rtt_ms_median"),
        "received_at": rep.get("received_at"),
        "ts": rep.get("ts"),
    }


def _read_live_samples(state_dir):
    """The catalog's live-samples.json snapshot (spec 6.3) or None when
    absent/unreadable. Read fresh each call, like _read_devices."""
    try:
        with open(os.path.join(state_dir, "live-samples.json")) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _read_images(state_dir):
    """catalog.json's images map ({image_id: entry}); {} when unreadable."""
    try:
        with open(os.path.join(state_dir, "catalog.json")) as f:
            data = json.load(f)
        images = data.get("images")
        return images if isinstance(images, dict) else {}
    except Exception:
        return {}


def _read_policy(policy_paths):
    """Resolve the current peer-policy PolicyResult (authoritative/LKG/
    fail-closed) for per-participant intent facts. None on any error so
    telemetry never breaks (rows simply carry no peer_policy)."""
    try:
        return _peer_policy.load_policy(policy_paths[0], policy_paths[1])
    except Exception:
        return None


def aggregate_transfers(live_doc, images, now, write_interval=None):
    """Per-image canonical rollup of the live table snapshot (design §10.9),
    freshness-aware. INNER join on the image catalog: samples with unknown
    image_ids are dropped (second cardinality fence behind ingest). A stale
    SNAPSHOT (written_at older than 2 x the snapshot WRITE interval) is treated
    as empty.

    Per-image the row carries ONLY low-cardinality canonical facts:
      * ``devices`` — FRESH streaming devices (a currently-valid observed v2
        entry within ``LIVE_VALUE_VALIDITY`` of its observed receipt).
      * ``receive_bps``/``transmit_bps`` — aggregate rate over the fresh
        observed devices (business gauges; the renderer omits them when stale).
      * ``progress_ratio`` — sum(completed)/sum(total) over fresh devices.
      * ``zero_receive_devices`` — fresh observed devices with an ACTIVE aria
        status and receive_bps==0 (never asserted from a stale value).
      * ``sampling_class_good``/``sampling_class_constrained`` — fresh devices
        by sampling class (replaces the old link "tier").
      * ``freshness_age_seconds`` — age of the newest valid observation for the
        image (always reported so a stale omission is explainable).
      * ``stale`` — True when NO device for the image is currently fresh; the
        renderer then omits throughput/progress and never emits a fresh zero.

    v1 rollout samples (mapped to obs_state=observed, schema v1) contribute via
    their legacy ``down_bps``/``up_bps``/``done_bytes`` under the same freshness
    rule; they carry no aria.status so they never count as zero_receive.
    """
    if write_interval is None:
        write_interval = live_samples.SNAPSHOT_WRITE_INTERVAL
    empty = ([], {"stream_devices": 0, "samples_rejected_total": 0})
    if not isinstance(live_doc, dict):
        # Unknown, not zero: the hub latches its last known count (sample()).
        return empty
    # The rejected count is the catalog's cumulative counter as last WRITTEN.
    # A stale snapshot makes the live rows unknown (they are omitted below),
    # but the counter it carries is still the newest value anyone has -- the
    # catalog never resets it while running and simply stops writing once
    # the table empties -- so it is reported from a stale document too.
    # Emitting 0 there made every wake-from-idle look like a counter reset
    # followed by a burst of rejections that never happened.
    try:
        rejected = int((live_doc.get("counters") or {}).get(
            "samples_rejected_total") or 0)
    except (TypeError, ValueError, AttributeError):
        rejected = 0
    try:
        written_at = float(live_doc.get("written_at", 0))
        if now - written_at > 2 * write_interval:
            stale_rows = []
            for image_id in {s.get("image_id") for s in
                             (live_doc.get("samples") or {}).values()
                             if isinstance(s, dict)}:
                entry = images.get(image_id)
                if entry:
                    stale_rows.append({
                        "image": entry.get("filename", image_id),
                        "info_hash": entry.get("info_hash_hex", ""),
                        "devices": 0, "sampling_class_good": 0,
                        "sampling_class_constrained": 0,
                        "zero_receive_devices": 0, "stale": True,
                        "freshness_age_seconds": int(now - written_at)})
            return stale_rows, {"stream_devices": 0,
                                "samples_rejected_total": rejected}
    except (TypeError, ValueError):
        return empty
    counters = live_doc.get("counters") or {}
    rows = {}
    streaming = 0
    for sample in (live_doc.get("samples") or {}).values():
        if not isinstance(sample, dict):
            continue
        entry = images.get(sample.get("image_id"))
        if not entry:
            continue
        streaming += 1
        image_id = sample["image_id"]
        row = rows.setdefault(image_id, {
            "image": entry.get("filename", image_id),
            "info_hash": entry.get("info_hash_hex", ""),
            "devices": 0, "receive_bps": 0, "transmit_bps": 0,
            "zero_receive_devices": 0, "sampling_class_good": 0,
            "sampling_class_constrained": 0, "_done": 0, "_total": 0,
            "_newest": None})

        # Freshness: only a currently-valid OBSERVED entry within
        # LIVE_VALUE_VALIDITY of its observed receipt is fresh (spec §3B/§4).
        obs_state = sample.get("obs_state", "observed")   # v1 -> observed
        try:
            base = float(sample.get("observed_received_at",
                                    sample.get("received_at", 0.0)))
        except (TypeError, ValueError):
            base = 0.0
        fresh = (obs_state in (None, "observed")
                 and bool(sample.get("valid", True))
                 and base + live_samples.LIVE_VALUE_VALIDITY >= now)
        if base:
            age = now - base
            if row["_newest"] is None or age < row["_newest"]:
                row["_newest"] = age
        if not fresh:
            continue

        row["devices"] += 1
        schema = sample.get("schema", "v2")
        if schema == "v1":
            receive = _int(sample.get("down_bps"))
            send = _int(sample.get("up_bps"))
            done = _int(sample.get("done_bytes"))
            status = None
        else:
            aria = sample.get("aria") if isinstance(
                sample.get("aria"), dict) else {}
            receive = _int(aria.get("receive_bps"))
            send = _int(aria.get("send_bps"))
            done = _int(aria.get("completed_content_bytes"))
            status = aria.get("status")
        row["receive_bps"] += receive
        row["transmit_bps"] += send
        row["_done"] += done
        row["_total"] += _int(entry.get("size"))
        if status == "active" and receive == 0:
            row["zero_receive_devices"] += 1
        sc_key = "sampling_class_%s" % sample.get("sampling_class")
        if sc_key in row:
            row[sc_key] += 1
    out = []
    for row in rows.values():
        total = row.pop("_total")
        done = row.pop("_done")
        newest = row.pop("_newest")
        row["progress_ratio"] = (done / total) if total else 0.0
        row["freshness_age_seconds"] = int(newest) if newest is not None else 0
        row["stale"] = row["devices"] == 0
        out.append(row)
    return out, {"stream_devices": streaming,
                 "samples_rejected_total":
                     _int(counters.get("samples_rejected_total"))}


def observability_enabled(env=None):
    """Is the EXTERNAL observability surface (Prometheus-format /metrics +
    OTLP push) turned on? Default OFF: IRIS doesn't assume any observability
    stack exists. Swarm JSON always requires the management-tier credential;
    the map page lives in the authenticated console."""
    env = os.environ if env is None else env
    return env.get("IRIS_OBSERVABILITY", "").strip().lower() in (
        "1", "true", "yes", "on")


def metrics_port(env=None):
    """Resolve the metrics listener port; None disables it (empty or '0')."""
    env = os.environ if env is None else env
    raw = env.get("IRIS_METRICS_PORT", str(DEFAULT_METRICS_PORT)).strip()
    return int(raw) if raw and raw != "0" else None


def _probe_listeners(listeners):
    """TCP-connect each name->port on loopback. Returns {name: "up"|"down"}.

    Loopback only, 2s, never raises: this is called from a probe handler, so a
    failure to MEASURE must not itself look like a failure of the thing being
    measured (an unknown port is reported "down" only because it could not be
    connected to, which is exactly the question being asked).
    """
    out = {}
    for name, prt in sorted((listeners or {}).items()):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            sock.connect(("127.0.0.1", int(prt)))
            out[name] = "up"
        except Exception:
            out[name] = "down"
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return out


def parse_health_listeners(spec, default=None):
    """Parse "name:port,name:port" (IRIS_HEALTH_LISTENERS) -> {name: port}.

    Blank/unset -> *default*. The literal "off" -> {} (checks nothing), for a
    deployment that runs a subset of the services and does not want the
    missing ones reported down."""
    text = (spec or "").strip()
    if not text:
        return dict(default or {})
    if text.lower() == "off":
        return {}
    out = {}
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        name, _, prt = part.partition(":")
        try:
            out[name.strip()] = int(prt)
        except ValueError:
            continue        # ignore a malformed entry rather than fail closed
    return out


class _MetricsServer(bounded_pool.BoundedThreadingMixin, ThreadingHTTPServer):
    """ThreadingHTTPServer with a bounded pool of concurrently running
    handler threads -- see bounded_pool.py. TLS handshakes happen in those
    workers rather than the accept thread, so one stalled scrape cannot block
    probes. Every route answers one JSON/text body and closes."""

    request_queue_size = 128
    max_concurrent_requests = 64
    tls_context = None

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.tls_context is not None:
            sock.settimeout(TELEMETRY_HANDSHAKE_TIMEOUT)
        return sock, addr

    def process_request_thread(self, request, client_address):
        if self.tls_context is not None:
            try:
                request = self.tls_context.wrap_socket(
                    request, server_side=True)
                request.settimeout(None)
            except (ssl.SSLError, OSError, ValueError):
                self.shutdown_request(request)
                return
        super().process_request_thread(request, client_address)


def make_metrics_server(host, port, provider, swarm_provider=None, html=None,
                        health=None, listeners=None,
                        management_token_file=None,
                        management_previous_token_file=None,
                        observability_token_file=None,
                        observability_previous_token_file=None,
                        certfile=None, keyfile=None):
    """Build the authenticated telemetry HTTPS server used in production.

    Only `/healthz` and `/readyz` are anonymous, and their bodies contain the
    single `ok` boolean. Readiness dependency details affect the status code
    without disclosing listener topology. `/metrics` requires an observability
    token before its enabled state is revealed; `/swarm` requires a management
    token. Every other path authenticates before returning RFC 9457 404.

    `listeners` is a mapping or callable used by `/readyz`; `health` supplies
    the detailed exporter state returned only by the management-authenticated
    `/status` route. The retired `html` argument remains accepted solely for
    source compatibility and cannot add unauthenticated response data."""
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status, body, ctype):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "private, no-store")
            if status == 503:
                self.send_header("Retry-After", "1")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlparse(self.path).path
            if path in ("/healthz", "/readyz"):
                pass
            elif path == "/metrics":
                try:
                    allowed = tier_auth.authorized(
                        self.headers, observability_token_file,
                        observability_previous_token_file,
                        scope="observability")
                except tier_auth.CredentialUnavailable:
                    allowed = False
                if not allowed:
                    api_problem.send(
                        self, 401, "observability-authentication-required",
                        "Observability authentication required",
                        headers=(("WWW-Authenticate", "Bearer"),))
                    return
                if provider is None:
                    api_problem.send(self, 404, "route-not-found",
                                     "Route not found")
                    return
            elif path in ("/swarm", "/status"):
                try:
                    allowed = tier_auth.authorized(
                        self.headers, management_token_file,
                        management_previous_token_file)
                except tier_auth.CredentialUnavailable:
                    allowed = False
                if not allowed:
                    api_problem.send(
                        self, 401, "management-authentication-required",
                        "Management authentication required",
                        headers=(("WWW-Authenticate", "Bearer"),))
                    return
            else:
                # Authenticate unknown non-probe paths before admitting that a
                # route does not exist. Retired pointer pages are not APIs.
                try:
                    allowed = tier_auth.authorized(
                        self.headers, management_token_file,
                        management_previous_token_file)
                except tier_auth.CredentialUnavailable:
                    allowed = False
                if not allowed:
                    api_problem.send(
                        self, 401, "management-authentication-required",
                        "Management authentication required",
                        headers=(("WWW-Authenticate", "Bearer"),))
                    return
                api_problem.send(self, 404, "route-not-found", "Route not found")
                return
            if api_routes.match("telemetry", "GET", self.path) is None:
                api_problem.send(self, 404, "route-not-found", "Route not found")
                return
            if path == "/metrics" and provider is not None:
                self._send(200, provider().encode(),
                           "text/plain; version=0.0.4; charset=utf-8")
            elif path == "/healthz":
                # Anonymous probes deliberately disclose no exporter or
                # listener topology. /healthz proves this process can answer;
                # /readyz retains the dependency status in its HTTP code.
                self._send(200, json.dumps({"ok": True}).encode(),
                           "application/json; charset=utf-8")
            elif path == "/readyz":
                want = listeners() if callable(listeners) else listeners
                state = _probe_listeners(want) if want else {}
                down = sorted(n for n, v in state.items() if v != "up")
                self._send(503 if down else 200,
                           json.dumps({"ok": not down}).encode(),
                           "application/json; charset=utf-8")
            elif path == "/swarm" and swarm_provider is not None:
                try:
                    # allow_nan=False: the console proxies this body to a
                    # browser JSON.parse, which rejects NaN/Infinity tokens.
                    body = json.dumps(swarm_provider(),
                                      allow_nan=False).encode()
                except Exception:
                    body = b"{}"
                self._send(200, body, "application/json; charset=utf-8")
            elif path == "/status":
                try:
                    export = health() if callable(health) else {
                        "state": "off", "signals": {}}
                    body = json.dumps({"ok": True,
                                       "otlp_export": export},
                                      allow_nan=False).encode()
                except Exception:
                    api_problem.send(self, 503, "telemetry-status-unavailable",
                                     "Telemetry status unavailable")
                    return
                self._send(200, body, "application/json; charset=utf-8")
            else:
                api_problem.send(self, 404, "route-not-found", "Route not found")

        def _unsupported(self):
            """Authenticate before disclosing unsupported method handling."""
            path = urlparse(self.path).path
            if path == "/metrics":
                current = observability_token_file
                previous = observability_previous_token_file
                scope = "observability"
                code = "observability-authentication-required"
                title = "Observability authentication required"
            else:
                current = management_token_file
                previous = management_previous_token_file
                scope = "management"
                code = "management-authentication-required"
                title = "Management authentication required"
            try:
                allowed = tier_auth.authorized(
                    self.headers, current, previous, scope=scope)
            except tier_auth.CredentialUnavailable:
                allowed = False
            if not allowed:
                api_problem.send(self, 401, code, title,
                                 headers=(("WWW-Authenticate", "Bearer"),))
                return
            api_problem.send(self, 405, "method-not-allowed",
                             "Method not allowed",
                             headers=(("Allow", "GET"),))

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

        def log_message(self, *args):
            pass

    server = _MetricsServer((host, port), Handler)
    if certfile:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile, keyfile)
        server.tls_context = context
    return server
