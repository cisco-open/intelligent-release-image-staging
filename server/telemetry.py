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
import json
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import audit
import auth
import ipaddress
import live_samples
import metrics
import otlp
import peer_enforcement as _peer_enforcement
import peer_policy as _peer_policy
import telemetry_destination
from peer_registry import PeerRegistry

DEFAULT_INTERVAL = 15
DEFAULT_METRICS_PORT = 9101
DEFAULT_RPC_URL = "http://127.0.0.1:6800/jsonrpc"
DEFAULT_RPC_SECRET_FILE = "/etc/iris/rpc-secret"


def _int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def poll_seeder(rpc):
    """Query the seeder aria2 RPC. `rpc(method, params)` returns the result.
    Returns (stats_dict, names, totals) where names maps info_hash -> image
    filename and totals maps info_hash -> total image bytes (for swarm-map
    progress). Any RPC failure yields ({"rpc_up": False}, {}, {})."""
    try:
        g = rpc("aria2.getGlobalStat", [])
        active = rpc("aria2.tellActive",
                     [["gid", "connections", "infoHash", "totalLength",
                       "files"]])
    except Exception:
        return {"rpc_up": False}, {}, {}
    connections = sum(_int(d.get("connections")) for d in active)
    names, totals = {}, {}
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
    return {
        "rpc_up": True,
        "upload_speed": _int(g.get("uploadSpeed")),
        "download_speed": _int(g.get("downloadSpeed")),
        "active_torrents": _int(g.get("numActive")),
        "connections": connections,
    }, names, totals


def poll_seeder_peers(rpc):
    """The server seeder's per-peer CURRENT send rate plus the per-torrent
    control-state uploadLength gauge, tagged with aria2's session id so the
    caller can detect a counter epoch (session change / decrease).

    Returns (peer_up, upload_lengths, session_id):
      * peer_up: {info_hash: {ip: upload_bps}} — how fast THIS server is
        INSTANTANEOUSLY sending to each connected device, from
        getPeers(gid, ["ip","uploadSpeed"]) (rate-only; never bitfield, never
        cumulative per-peer counters — aria2 has no cross-connection per-peer
        total, and inferring one from the torrent-wide counter was division,
        not measurement).
      * upload_lengths: {info_hash: bytes} — aria2's BitTorrent piece-payload
        uploadLength for that torrent over its control-state lifetime. It is a
        GAUGE: it can exceed the image size (re-sends/multiple leechers) and
        can decrease on control-state loss. It is never split across peers.
      * session_id: aria2.getSessionInfo's session id ("" when unavailable),
        identifying the counter epoch."""
    peer_up, upload_lengths = {}, {}
    try:
        session = rpc("aria2.getSessionInfo", [])
        session_id = str((session or {}).get("sessionId") or "")
    except Exception:
        session_id = ""
    try:
        active = rpc("aria2.tellActive", [["gid", "infoHash", "uploadLength"]])
    except Exception:
        return peer_up, upload_lengths, session_id
    for d in active:
        ih, gid = d.get("infoHash"), d.get("gid")
        if not ih or not gid:
            continue
        upload_lengths[ih] = _int(d.get("uploadLength"))
        try:
            peers = rpc("aria2.getPeers", [gid, ["ip", "uploadSpeed"]])
        except Exception:
            continue
        m = peer_up.setdefault(ih, {})
        for p in peers:
            ip = p.get("ip")
            if ip:
                m[ip] = m.get(ip, 0) + _int(p.get("uploadSpeed"))
    return peer_up, upload_lengths, session_id


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
    """Export health per R7: degrade silently in operation, loudly in
    visibility. State transitions (ok<->degraded) fire on_transition exactly
    once per edge — a dead collector cannot spam the audit log. 'off' until
    the first attempt."""

    def __init__(self, on_transition=None):
        self._on = on_transition
        self._state = "off"
        self._last_success = 0.0
        self._streak = 0
        self._failures = {"logs": 0, "metrics": 0}   # per-signal (spec 7.5)

    def record(self, ok, signal, now):
        if ok:
            self._last_success = now
            self._streak = 0
            if self._state == "degraded" and self._on:
                self._on("otlp-export-recovered")
            self._state = "ok"
        else:
            self._failures[signal] = self._failures.get(signal, 0) + 1
            self._streak += 1
            if self._state != "degraded" and self._on:
                self._on("otlp-export-degraded")
            self._state = "degraded"

    def as_dict(self):
        return {"state": self._state, "last_success_ts": self._last_success,
                "fail_streak": self._streak,
                "failures_total": sum(self._failures.values()),
                "failures_by_signal": dict(self._failures)}


def _metric_points(rows, extras, now, per_device=None, images=None,
                   device_models=None, export_failures=None):
    """Spec 7.5 table, encoded literally. Names/units are contract."""
    pts = []
    for r in rows:
        base = {"iris.image.id": r["image"],
                "iris.torrent.info_hash": r["info_hash"]}
        pts.append({"name": "iris.transfer.active", "unit": "{transfer}",
                    "kind": "gauge", "value": r["active"], "attrs": base,
                    "ts": now})
        for direction, key in (("receive", "down_bps"),
                               ("transmit", "up_bps")):
            pts.append({"name": "iris.transfer.throughput", "unit": "By/s",
                        "kind": "gauge", "value": r[key],
                        "attrs": dict(base, **{"network.io.direction":
                                               direction}), "ts": now})
        pts.append({"name": "iris.transfer.progress", "unit": "1",
                    "kind": "gauge", "value": r["progress_ratio"],
                    "float": True, "attrs": base, "ts": now})
        pts.append({"name": "iris.transfer.stalled", "unit": "{transfer}",
                    "kind": "gauge", "value": r["stalled"], "attrs": base,
                    "ts": now})
        for tier in ("good", "constrained"):
            pts.append({"name": "iris.stream.devices", "unit": "{device}",
                        "kind": "gauge", "value": r["tier_%s" % tier],
                        "attrs": dict(base, **{"iris.link.tier": tier}),
                        "ts": now})
    pts.append({"name": "iris.telemetry.samples.rejected",
                "unit": "{sample}", "kind": "sum",
                "value": extras.get("samples_rejected_total", 0),
                "attrs": {}, "ts": now})
    for signal, n in (export_failures or {}).items():
        pts.append({"name": "iris.telemetry.export.failures",
                    "unit": "{error}", "kind": "sum", "value": n,
                    "attrs": {"iris.telemetry.signal": signal}, "ts": now})
    for device_id, s in (per_device or {}).items():
        if not isinstance(s, dict):
            continue
        dattrs = {"device.id": device_id,
                  "iris.image.id": s.get("image_id", "")}
        model = (device_models or {}).get(device_id)
        if model:
            dattrs["device.model.identifier"] = str(model)[:128]
        for direction, key in (("receive", "down_bps"),
                               ("transmit", "up_bps")):
            pts.append({"name": "iris.device.transfer.throughput",
                        "unit": "By/s", "kind": "gauge",
                        "value": s.get(key, 0),
                        "attrs": dict(dattrs, **{"network.io.direction":
                                                 direction}), "ts": now})
        pts.append({"name": "iris.device.transfer.received", "unit": "By",
                    "kind": "gauge", "value": s.get("done_bytes", 0),
                    "attrs": dattrs, "ts": now})
        entry = (images or {}).get(s.get("image_id") or "")
        size = entry.get("size") if isinstance(entry, dict) else 0
        pts.append({"name": "iris.device.transfer.progress", "unit": "1",
                    "kind": "gauge", "float": True,
                    "value": (s.get("done_bytes", 0) / size) if size else 0.0,
                    "attrs": dattrs, "ts": now})
    return pts


class Telemetry:
    """Owns the live state behind /metrics and drives event export."""

    def __init__(self, registry=None, exporter=None, rpc=None,
                 interval=DEFAULT_INTERVAL, device_info=None,
                 reports_info=None, live_info=None, images_info=None,
                 metrics_exporter=None, export_health=None,
                 device_metrics=False, dest_settings=None,
                 env_endpoint="", env_enabled=False, headers=None,
                 policy_info=None, enforcement_info=None):
        self.exporter = exporter
        self.rpc = rpc
        self.interval = interval
        # OTLP metrics push (spec 7.5) + shared export-health tracker (7.7).
        # device_metrics gates the per-device gauges (IRIS_OTLP_DEVICE_METRICS,
        # default off — cardinality warning documented).
        self.metrics_exporter = metrics_exporter
        self.export_health = export_health or ExportHealth()
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
        # received_at watermark: every stored report newer than this gets one
        # OTLP log record on the next sample(); advancing it makes the export
        # exactly-once per process lifetime (a restart replays at most the
        # ring's 5 reports per device — acceptable, and OTLP is default-off).
        self._report_seen = 0.0
        self._seeder = {"rpc_up": False}
        self._names = {}                    # last good info_hash -> name
        self._totals = {}                   # last good info_hash -> total bytes
        self._peer_up = {}                  # info_hash -> {ip: server upload bps}
        self._upload_len = {}               # info_hash -> control-state uploadLength gauge (epoch-baselined)
        self._session_id = None             # aria2 session id bound to _upload_len; a change is a new epoch
        self._counters = {"announces_total": 0}
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
        exp = self.exporter
        if exp is not None:
            exp.emit(event)

    def note_announce(self):
        with self._lock:
            self._counters["announces_total"] += 1

    # --- /metrics provider ---
    def metrics_text(self):
        swarm = build_swarm(self._registry.stats(), self._names)
        with self._lock:
            counters = dict(self._counters)
        return metrics.render(swarm, self._seeder, counters,
                              reports_stored=self._reports_stored(),
                              transfers=self._transfers,
                              extras=self._extras,
                              otlp_health=self.export_health.as_dict())

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
        if enabled and endpoint:
            self.exporter = otlp.OTLPLogExporter(endpoint,
                                                 headers=self._headers)
            self.metrics_exporter = otlp.OTLPMetricsExporter(
                endpoint, headers=self._headers)
        else:
            # Disabled, or no endpoint anywhere: drop the exporters. The
            # rest of the pass still runs (seeder poll, live aggregation) —
            # the swarm map and /metrics text don't depend on OTLP export.
            self.exporter = None
            self.metrics_exporter = None

    def sample(self, now=None):
        now = time.time() if now is None else now
        self._refresh_exporters()
        if self.rpc is not None:
            seeder, names, totals = poll_seeder(self.rpc)
            self._seeder = seeder
            if names:                       # keep last good values on RPC blips
                self._names = names
            if totals:
                self._totals = totals
            # Per-peer CURRENT send rate (measured) + the per-torrent
            # control-state uploadLength gauge, tagged with aria2's session id.
            # No per-peer cumulative bytes are inferred: the gauge is surfaced
            # as-is on an unchanged session (increases and image-size overshoot
            # are legitimate), and RE-BASELINED — never bridged — on a changed
            # session id OR an observed decrease without a session change (both
            # mean a new counter epoch / control-state loss). Because nothing is
            # integrated into a per-peer allocation, an epoch reset loses no
            # attributed bytes: there is simply nothing to carry.
            self._peer_up, upload_lengths, session_id = \
                poll_seeder_peers(self.rpc)
            new_epoch = (self._session_id is not None
                         and session_id != self._session_id)
            self._session_id = session_id
            for info_hash, now_len in upload_lengths.items():
                last = self._upload_len.get(info_hash)
                # On a new session epoch, or a decrease within the same epoch,
                # report the current counter verbatim (re-baseline). Otherwise
                # the gauge simply tracks the counter.
                self._upload_len[info_hash] = now_len
                if not new_epoch and last is not None and now_len < last:
                    continue                # decrease: rebaseline, do not bridge
        if self._live_info is not None:
            try:
                self._transfers, self._extras = aggregate_transfers(
                    self._live_info(),
                    self._images_info() if self._images_info else {}, now)
            except Exception:
                pass                        # telemetry never breaks on bad input
        if self.exporter is not None and self._reports_info is not None:
            try:
                self._export_new_reports()
            except Exception:
                pass                        # telemetry never breaks on bad input
        if self.exporter is not None:
            delivered = self.exporter.flush()
            if delivered is not None:       # None = empty queue, no attempt
                self.export_health.record(delivered > 0, "logs", now)
        if self.metrics_exporter is not None:
            # Every pass exports the latest snapshot (conflation, spec 7.5) —
            # NOT gated on transfers existing: the rejected-samples counter
            # and export.failures sums must flow even on a quiet fleet.
            per_device = None
            models = {}
            if self.device_metrics:
                per_device = (self._live_info() or {}).get("samples") \
                    if self._live_info else None
                if self._device_info is not None:
                    try:
                        models = {d: (rec or {}).get("model")
                                  for d, rec in
                                  (self._device_info() or {}).items()}
                    except Exception:
                        models = {}
            ok = self.metrics_exporter.export(_metric_points(
                self._transfers, self._extras, now, per_device=per_device,
                images=self._images_info() if self._images_info else {},
                device_models=models,
                export_failures=self.export_health.as_dict()
                    .get("failures_by_signal")))
            self.export_health.record(ok, "metrics", now)

    def _export_new_reports(self):
        """Emit one OTLP log record per stored device report not yet
        exported (received_at watermark, exactly-once per process; compared
        against its value at pass entry and advanced only at the end, so
        rings scanned later in the same pass cannot shadow earlier ones).
        Each record is enriched from the device's last heartbeat (model,
        flash, stage state — capped/coerced inside build_report_record) plus
        the swarm IP->device_id join for peer-row resolution (spec 7.6)."""
        seen = self._report_seen
        high = seen
        devices = {}
        if self._device_info is not None:
            try:
                devices = self._device_info() or {}
            except Exception:
                devices = {}
        device_by_ip = {rec.get("swarm_ip"): str(did)
                        for did, rec in devices.items()
                        if isinstance(rec, dict) and rec.get("swarm_ip")}
        for device_id, ring in (self._reports_info() or {}).items():
            if not isinstance(ring, list):
                continue
            rec = devices.get(device_id)
            rec = rec if isinstance(rec, dict) else {}
            enrich = {"model": rec.get("model"),
                      "free_flash_bytes": rec.get("free_flash_bytes"),
                      "stage_state": rec.get("stage_state"),
                      "peer_devices": device_by_ip}
            for rep in ring:
                try:
                    rcv = float(rep.get("received_at", 0) or 0)
                except (TypeError, ValueError, AttributeError):
                    continue
                if rcv > seen:
                    self.exporter.emit(otlp.build_report_record(
                        rep, str(device_id), enrich=enrich))
                    if rcv > high:
                        high = rcv
        self._report_seen = high

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
            ``latest_report``, optional ``peer_policy``/``peer_enforcement``.

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
            up_now = self._peer_up.get(info_hash, {})
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
                    live_by_device, policy, enforcement, derived_denied, now))
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
                "lifetime": "control-state",
            })
        return {
            "host": os.environ.get("IRIS_HOST_IP", ""),
            "server_observation": {
                "observed_at": now,
                "rpc_up": bool(self._seeder.get("rpc_up")),
                "aria_session_id": self._session_id,
                "global": {
                    "send_bps": self._seeder.get("upload_speed", 0),
                    "receive_bps": self._seeder.get("download_speed", 0),
                    "connections": self._seeder.get("connections", 0),
                    "active_torrents": self._seeder.get("active_torrents", 0),
                },
                "torrent": torrents,
            },
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

    def run_forever(self):
        while not self._stop.wait(self.interval):
            try:
                self.sample()
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
            audit.append_event(audit_path, name, "tracker",
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
    live_info = lambda: _read_live_samples(state_dir)
    images_info = lambda: _read_images(state_dir)
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
                    enforcement_info=enforcement_info)
    # Build the initial exporters NOW (not on the first pass) so swarm events
    # from the announce path are captured from process start, exactly as the
    # construction-time exporters were before the destination became editable.
    hub._refresh_exporters()
    return hub


def _read_devices(state_dir):
    """The catalog's devices.json ({device_id: heartbeat record}) or {} if it
    isn't there yet / unreadable. Read fresh each call (cheap JSON file)."""
    try:
        with open(os.path.join(state_dir, "devices.json")) as f:
            return json.load(f)
    except Exception:
        return {}


def _read_reports(state_dir):
    """The catalog's telemetry.json ({device_id: [oldest..newest stored
    reports]}) or {} if it isn't there yet / unreadable / not a dict. Read
    fresh each call (small, ring-bounded file — 5 reports x <=16 KB per
    device). Telemetry never breaks on bad input."""
    try:
        with open(os.path.join(state_dir, "telemetry.json")) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _peer_row(p, total, up_now, devices_by_id, report_by_device,
              live_by_device, policy, enforcement, derived_denied, now):
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
    if p["ip"] in up_now:
        row["server_observation"] = {
            "peer": {"send_bps": up_now.get(p["ip"], 0)}}

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
    """The tracker's current derived-denied set expressed as principal ids
    (never a raw IP list — the enforcement status intentionally exposes only a
    count and typed conflicts). We compose per-participant block facts from the
    typed conflicts the tracker DID publish. Returns a set of denied device ids."""
    denied = set()
    if not isinstance(enforcement, dict):
        return denied
    for c in enforcement.get("conflicts") or []:
        if not isinstance(c, dict):
            continue
        if c.get("denied_principal_type") == "device":
            did = c.get("denied_principal_id")
            if did is not None:
                denied.add(did)
    return denied


def _peer_enforcement_fact(enforcement, derived_denied, principal_type,
                           device_id, ipv4):
    """Per-participant ``peer_enforcement`` fact (spec §7/§10.3). Factual, not a
    causal claim: ``blocked`` iff this device principal is in the tracker's
    current derived-denied set (composed from typed conflicts + the current
    aggregate ``state``); we never claim a disconnect cause. The raw denied-IP
    list is never read (it is not exposed). ``state`` mirrors the tracker's
    aggregate enforcement state (``fail_closed`` explicit). None when unwired."""
    if not isinstance(enforcement, dict):
        return None
    state = enforcement.get("state")
    blocked = device_id in derived_denied or state == "fail_closed"
    fact = {"blocked": bool(blocked), "state": state}
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
    """Per-image rollup of the live table snapshot (spec 7.2). INNER join on
    the image catalog: samples with unknown image_ids are dropped (second
    cardinality fence behind ingest). A stale snapshot (written_at older
    than 2 x the snapshot WRITE interval — the catalog writer's cadence,
    deliberately NOT the hub's sample interval) is treated as empty — with
    the keep-fresh write rule that genuinely means the catalog stopped
    writing."""
    if write_interval is None:
        write_interval = live_samples.SNAPSHOT_WRITE_INTERVAL
    empty = ([], {"stream_devices": 0, "samples_rejected_total": 0})
    if not isinstance(live_doc, dict):
        return empty
    try:
        if now - float(live_doc.get("written_at", 0)) > 2 * write_interval:
            return empty
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
        row = rows.setdefault(sample["image_id"], {
            "image": entry.get("filename", sample["image_id"]),
            "info_hash": entry.get("info_hash_hex", ""),
            "active": 0, "down_bps": 0, "up_bps": 0, "_done": 0,
            "_total": 0, "stalled": 0, "tier_good": 0,
            "tier_constrained": 0})
        row["active"] += 1
        row["down_bps"] += _int(sample.get("down_bps"))
        row["up_bps"] += _int(sample.get("up_bps"))
        row["_done"] += _int(sample.get("done_bytes"))
        row["_total"] += _int(entry.get("size"))
        if sample.get("phase") == "downloading" \
                and _int(sample.get("down_bps")) == 0:
            row["stalled"] += 1
        tier_key = "tier_%s" % sample.get("tier")
        if tier_key in row:
            row[tier_key] += 1
    out = []
    for row in rows.values():
        total = row.pop("_total")
        done = row.pop("_done")
        row["progress_ratio"] = (done / total) if total else 0.0
        out.append(row)
    return out, {"stream_devices": streaming,
                 "samples_rejected_total":
                     _int(counters.get("samples_rejected_total"))}


def observability_enabled(env=None):
    """Is the EXTERNAL observability surface (Prometheus-format /metrics +
    OTLP push) turned on? Default OFF: IRIS doesn't assume any observability
    stack exists. The swarm JSON (/swarm) is served to loopback peers only by
    default (IRIS_SWARM_PUBLIC opens it) — the map PAGE lives in the
    authenticated console (:8080); :9101 serves a static pointer there
    (moved_page)."""
    env = os.environ if env is None else env
    return env.get("IRIS_OBSERVABILITY", "").strip().lower() in (
        "1", "true", "yes", "on")


def metrics_port(env=None):
    """Resolve the metrics listener port; None disables it (empty or '0')."""
    env = os.environ if env is None else env
    raw = env.get("IRIS_METRICS_PORT", str(DEFAULT_METRICS_PORT)).strip()
    return int(raw) if raw and raw != "0" else None


def _console_url():
    """Resolve the operator console URL: IRIS_CONSOLE_URL override verbatim
    when non-empty (e.g. shared hosts publishing the console on a non-default
    port; garbage tolerant, used as-is), else the IRIS_HOST_IP-derived
    https://<host>:8080/ default. Read per call so it works without a restart.
    Shared by the retired-map pointer page and the /swarm 403 body — both
    surfaces already publish this URL, so echoing it leaks nothing new."""
    override = os.environ.get("IRIS_CONSOLE_URL", "").strip()
    if override:
        return override
    host = os.environ.get("IRIS_HOST_IP", "").strip() or "localhost"
    return "https://%s:8080/" % host


def swarm_peer_allowed(peer_host, swarm_public):
    """Is this TCP peer allowed to read /swarm? True when swarm_public is on,
    else only for a loopback source (all of 127.0.0.0/8, ::1, and IPv4-mapped
    forms). Defense-in-depth scoped to the container network namespace: under
    a rootless engine or host networking a source-address check is meaningless
    — the hard control is IRIS_METRICS_HOST / not publishing 9101 (documented
    in security.md). Fails CLOSED on any unparseable address."""
    if swarm_public:
        return True
    try:
        addr = ipaddress.ip_address((peer_host or "").partition("%")[0])
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return addr.is_loopback


def moved_page():
    """Static pointer page for the retired :9101 map URLs (/swarmmap and /).
    The live swarm map is inside the authenticated console — this keeps old
    bookmarks failing helpfully instead of 404ing. Reads env vars per request
    (via _console_url) so it works without a restart once they're set."""
    console = _console_url()
    return ("<!doctype html>\n<html><head><meta charset=\"utf-8\">"
            "<title>intelligent-release-image-staging swarm map has moved"
            "</title></head><body>"
            "<h1>The swarm map moved into the "
            "intelligent-release-image-staging Console</h1>"
            "<p>Open <a href=\"%s\">%s</a> and sign in &mdash; the live map "
            "is on the Swarm tab.</p></body></html>\n"
            % (console, console)).encode("ascii")


def make_metrics_server(host, port, provider, swarm_provider=None, html=None,
                        health=None, swarm_public=False):
    """HTTP server. `/healthz` is always served (JSON; `health` is an optional
    zero-arg callable adding the otlp_export block — spec 7.7. Status stays
    200: container HEALTHCHECK and orchestrator probes are status-code based);
    `/metrics` is served only when `provider` is given (None -> 404, the
    observability-off posture); /swarm answers only loopback peers unless
    `swarm_public` (the console proxies it over container loopback — swarm
    data is console-gated by default); /swarmmap serves the pointer page when
    `html` is given.

    `html` may be a string, bytes, or a zero-arg callable returning either; a
    callable is read per request, so the page can be hot-updated without a
    restart."""
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status, body, ctype):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/metrics" and provider is not None:
                self._send(200, provider().encode(),
                           "text/plain; version=0.0.4; charset=utf-8")
            elif path == "/healthz":
                doc = {"ok": True}
                if health is not None:
                    try:
                        doc["otlp_export"] = health()
                    except Exception:
                        pass
                self._send(200, json.dumps(doc).encode(),
                           "application/json; charset=utf-8")
            elif path == "/swarm" and swarm_provider is not None:
                if not swarm_peer_allowed(self.client_address[0],
                                          swarm_public):
                    body = json.dumps(
                        {"error": "swarm data is served through the "
                                  "authenticated console; set "
                                  "IRIS_SWARM_PUBLIC=1 to expose it here",
                         "console": _console_url()}).encode()
                    self._send(403, body, "application/json; charset=utf-8")
                    return
                try:
                    body = json.dumps(swarm_provider()).encode()
                except Exception:
                    body = b"{}"
                self._send(200, body, "application/json; charset=utf-8")
            elif path in ("/swarmmap", "/") and html is not None:
                page = html() if callable(html) else html
                if isinstance(page, str):
                    page = page.encode()
                self._send(200, page or b"", "text/html; charset=utf-8")
            else:
                self._send(404, b"not found\n", "text/plain")

        def log_message(self, *args):
            pass

    return ThreadingHTTPServer((host, port), Handler)
