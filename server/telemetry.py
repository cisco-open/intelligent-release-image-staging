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

import metrics
import otlp
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
    """The server seeder's per-peer upload view, plus the exact per-torrent
    upload counter to calibrate it against. Returns (peer_up, upload_lengths):
      * peer_up: {info_hash: {ip: upload_bps}} — from aria2 tellActive
        (gid+infoHash) -> getPeers(gid).uploadSpeed, i.e. how fast THIS server
        is INSTANTANEOUSLY sending to each connected device.
      * upload_lengths: {info_hash: bytes} — aria2's own EXACT cumulative
        uploadLength for that torrent since aria2 start. aria2 has no
        per-peer cumulative byte counter, so callers distribute this exact
        per-torrent total across peers proportional to their instantaneous
        uploadSpeed (see Telemetry.sample) instead of integrating the noisy
        instantaneous rate directly, which overcounts on bursty transfers."""
    peer_up, upload_lengths = {}, {}
    try:
        active = rpc("aria2.tellActive", [["gid", "infoHash", "uploadLength"]])
    except Exception:
        return peer_up, upload_lengths
    for d in active:
        ih, gid = d.get("infoHash"), d.get("gid")
        if not ih or not gid:
            continue
        upload_lengths[ih] = _int(d.get("uploadLength"))
        try:
            peers = rpc("aria2.getPeers", [gid])
        except Exception:
            continue
        m = peer_up.setdefault(ih, {})
        for p in peers:
            ip = p.get("ip")
            if ip:
                m[ip] = m.get(ip, 0) + _int(p.get("uploadSpeed"))
    return peer_up, upload_lengths


def _distribute_upload_delta(delta, weights):
    """Split `delta` exact bytes across connected peers proportional to their
    instantaneous uploadSpeed `weights` ({ip: bps}). This is how we calibrate
    the per-peer sent-bytes display against aria2's exact per-torrent
    uploadLength counter instead of integrating the (noisy, bursty)
    instantaneous rate directly.

    Returns {ip: bytes} summing to exactly `delta` (integer division leaves a
    remainder of at most len(weights)-1 bytes, which is handed to the
    largest-share peer), or None if there are no connected peers at all — the
    caller carries the delta into the next window rather than dropping it.
    Ties in "largest share" break on dict iteration order (Python 3.7+
    insertion order), which is stable enough for byte-accounting purposes."""
    if not weights:
        return None
    total_bps = sum(weights.values())
    ips = list(weights.keys())
    if total_bps <= 0:
        # No peer is reporting a nonzero rate this sample (e.g. every peer is
        # momentarily idle) but bytes were still sent -> split evenly rather
        # than attributing them all to one arbitrary peer.
        n = len(ips)
        base = delta // n
        shares = {ip: base for ip in ips}
        remainder = delta - base * n
    else:
        shares = {ip: delta * bps // total_bps for ip, bps in weights.items()}
        remainder = delta - sum(shares.values())
    if remainder:
        largest_ip = max(ips, key=lambda ip: weights.get(ip, 0))
        shares[largest_ip] += remainder
    return shares


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


class Telemetry:
    """Owns the live state behind /metrics and drives event export."""

    def __init__(self, registry=None, exporter=None, rpc=None,
                 interval=DEFAULT_INTERVAL, device_info=None,
                 reports_info=None):
        self.exporter = exporter
        self.rpc = rpc
        self.interval = interval
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
        # received_at watermark: every stored report newer than this gets one
        # OTLP log record on the next sample(); advancing it makes the export
        # exactly-once per process lifetime (a restart replays at most the
        # ring's 5 reports per device — acceptable, and OTLP is default-off).
        self._report_seen = 0.0
        self._seeder = {"rpc_up": False}
        self._names = {}                    # last good info_hash -> name
        self._totals = {}                   # last good info_hash -> total bytes
        self._peer_up = {}                  # info_hash -> {ip: server upload bps}
        self._peer_sent = {}                # info_hash -> {ip: bytes sent this cycle}
        self._peer_sent_since = {}          # info_hash -> {ip: joined_at the sent counter is anchored to}
        self._last_upload_len = {}          # info_hash -> aria2's uploadLength as of the last sample
        self._unattributed = {}             # info_hash -> bytes from a delta with nowhere to go yet (no connected peers), carried to the next window
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
        if self.exporter is not None:
            self.exporter.emit(event)
        # Prune per-IP accumulators when a peer leaves (stopped or stale) so
        # _peer_sent/_peer_sent_since don't grow unbounded over a long run.
        if event.get("event") in ("stop", "stale"):
            ih = event.get("info_hash")
            ip = event.get("ip")
            if ih and ip:
                self._peer_sent.get(ih, {}).pop(ip, None)
                self._peer_sent_since.get(ih, {}).pop(ip, None)

    def note_announce(self):
        with self._lock:
            self._counters["announces_total"] += 1

    # --- /metrics provider ---
    def metrics_text(self):
        swarm = build_swarm(self._registry.stats(), self._names)
        with self._lock:
            counters = dict(self._counters)
        return metrics.render(swarm, self._seeder, counters,
                              reports_stored=self._reports_stored())

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
    def sample(self, now=None):
        now = time.time() if now is None else now
        if self.rpc is not None:
            seeder, names, totals = poll_seeder(self.rpc)
            self._seeder = seeder
            if names:                       # keep last good values on RPC blips
                self._names = names
            if totals:
                self._totals = totals
            # Reset each peer's integrated bytes-sent when it starts a NEW
            # download cycle, so the swarm map shows what this server sent for
            # the CURRENT download — not a lifetime sum across re-downloads. The
            # registry's joined_at is the authoritative cycle marker (it advances
            # when a finished peer re-announces with bytes left to fetch); when it
            # changes for a peer, zero that peer's accumulator. First sighting of
            # a peer (anchor unset) just records the anchor — no spurious reset.
            joined = self._joined_at_by_ip(now)
            for info_hash, jmap in joined.items():
                acc = self._peer_sent.setdefault(info_hash, {})
                anchor = self._peer_sent_since.setdefault(info_hash, {})
                for ip, j in jmap.items():
                    if j is None:
                        continue
                    if anchor.get(ip) is not None and anchor[ip] != j:
                        acc[ip] = 0
                    anchor[ip] = j
            # per-device server upload: current rate (display) + calibrated
            # bytes-sent (distributed from aria2's exact per-torrent counter —
            # see _distribute_upload_delta for why we don't integrate the rate).
            self._peer_up, upload_lengths = poll_seeder_peers(self.rpc)
            for info_hash, now_len in upload_lengths.items():
                # Unexplained jumps are BASELINED, never distributed: on the
                # first sighting of a hash (telemetry start) the counter's
                # history is unattributable — whoever happens to be connected
                # right now didn't necessarily receive it, so distributing it
                # would spike one peer's row. Same on a counter DECREASE
                # (aria2 restarted): re-baseline and lose at most one window
                # rather than misattribute. Deltas only flow between two
                # consecutive samples of the same counter epoch.
                last = self._last_upload_len.get(info_hash)
                self._last_upload_len[info_hash] = now_len
                if last is None or now_len < last:
                    continue
                delta = now_len - last
                delta += self._unattributed.pop(info_hash, 0)
                if delta <= 0:
                    continue
                weights = self._peer_up.get(info_hash, {})
                shares = _distribute_upload_delta(delta, weights)
                if shares is None:
                    # no connected peers to attribute this delta to -> carry it
                    # into the next window so bytes are never dropped.
                    self._unattributed[info_hash] = \
                        self._unattributed.get(info_hash, 0) + delta
                    continue
                acc = self._peer_sent.setdefault(info_hash, {})
                for ip, share in shares.items():
                    acc[ip] = acc.get(ip, 0) + share
        if self.exporter is not None and self._reports_info is not None:
            try:
                self._export_new_reports()
            except Exception:
                pass                        # telemetry never breaks on bad input
        if self.exporter is not None:
            self.exporter.flush()

    def _export_new_reports(self):
        """Emit one OTLP log record per stored device report not yet exported,
        tracked by a received_at watermark so each report goes out exactly
        once. The watermark is compared against its value at pass entry and
        advanced only at the end, so rings scanned later in the same pass
        cannot shadow earlier ones."""
        seen = self._report_seen
        high = seen
        for device_id, ring in (self._reports_info() or {}).items():
            if not isinstance(ring, list):
                continue
            for rep in ring:
                try:
                    rcv = float(rep.get("received_at", 0) or 0)
                except (TypeError, ValueError, AttributeError):
                    continue
                if rcv > seen:
                    self.exporter.emit(
                        otlp.build_report_record(rep, str(device_id)))
                    if rcv > high:
                        high = rcv
        self._report_seen = high

    def _joined_at_by_ip(self, now):
        """info_hash -> {ip: current-cycle joined_at}, from the registry, so the
        sampler can spot when a peer begins a fresh download cycle."""
        out = {}
        for info_hash, peers in self._registry.snapshot(now=now).items():
            out[info_hash] = {p["ip"]: p.get("joined_at") for p in peers}
        return out

    # --- live per-peer swarm view (for the swarm map) ---
    def swarm_snapshot(self, now=None):
        now = time.time() if now is None else now
        # device model + id per swarm IP, joined from the catalog's heartbeat
        # records by the heartbeat source IP (== the agent's swarm/announce
        # IP); then each device id's LATEST stored report as a small summary.
        model_by_ip, device_by_ip, tele_by_ip = {}, {}, {}
        if self._device_info is not None:
            try:
                for device_id, rec in (self._device_info() or {}).items():
                    ip = rec.get("swarm_ip")
                    if not ip:
                        continue
                    device_by_ip[ip] = str(device_id)
                    if rec.get("model"):
                        model_by_ip[ip] = rec["model"]
                    # True/False/None (unknown — absent or pre-telemetry agent);
                    # the console drawer branches its "no report yet" text on
                    # this, so preserve all three states (don't drop on falsy).
                    tele_by_ip[ip] = rec.get("telemetry_enabled")
            except Exception:
                pass                        # telemetry never breaks on bad input
        report_by_device = {}
        if self._reports_info is not None:
            try:
                for device_id, ring in (self._reports_info() or {}).items():
                    summary = _report_summary(ring)
                    if summary is not None:
                        report_by_device[str(device_id)] = summary
            except Exception:
                pass                        # telemetry never breaks on bad input
        images = []
        for info_hash, peers in self._registry.snapshot(now=now).items():
            total = self._totals.get(info_hash)
            up_now = self._peer_up.get(info_hash, {})
            sent = self._peer_sent.get(info_hash, {})
            out = []
            for p in peers:
                left = p.get("left")
                if p["is_seeder"]:
                    progress = 1.0
                elif total and left is not None:
                    progress = max(0.0, min(1.0, 1.0 - left / total))
                else:
                    progress = None
                did = device_by_ip.get(p["ip"])
                out.append({**p, "progress": progress,
                            # how fast / how much THIS server is sending to it
                            "server_up_bps": up_now.get(p["ip"], 0),
                            "server_sent_bytes": sent.get(p["ip"], 0),
                            "model": model_by_ip.get(p["ip"]),
                            # joined by swarm IP; summary of the device's
                            # LATEST stored report (full rows stay in the
                            # console drawer — /swarm payload discipline)
                            "device_id": did,
                            "telemetry_enabled": tele_by_ip.get(p["ip"]),
                            "report": (report_by_device.get(did)
                                       if did is not None else None)})
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
            # the server's own IP (the seeder/hub) so the swarm map can dedupe it
            # out of the per-image peer rings — it's the central hub, not a node.
            "host": os.environ.get("IRIS_HOST_IP", ""),
            "images": images,
            "seeder": {
                "upload_bps": self._seeder.get("upload_speed", 0),
                "download_bps": self._seeder.get("download_speed", 0),
                "connections": self._seeder.get("connections", 0),
                "active_torrents": self._seeder.get("active_torrents", 0),
                "rpc_up": bool(self._seeder.get("rpc_up")),
            },
        }

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
    swarm map keeps working. External event export to OTLP/Loki is enabled
    ONLY when IRIS_OBSERVABILITY=1 AND IRIS_OTLP_ENDPOINT is set — IRIS makes
    no assumptions about a Grafana/Prometheus stack being around."""
    env = os.environ if env is None else env
    endpoint = env.get("IRIS_OTLP_ENDPOINT", "").strip()
    exporter = (otlp.OTLPLogExporter(endpoint)
                if endpoint and observability_enabled(env) else None)
    rpc = make_jsonrpc_caller(env.get("IRIS_RPC", DEFAULT_RPC_URL),
                              _read_rpc_secret(env))
    interval = _int(env.get("IRIS_SAMPLE_INTERVAL")) or DEFAULT_INTERVAL
    # Read the catalog's per-device heartbeat records (written by the catalog
    # process in the same container) so the swarm map can label peers by model.
    state_dir = env.get("IRIS_STATE", "/var/lib/iris")
    device_info = lambda: _read_devices(state_dir)
    reports_info = lambda: _read_reports(state_dir)
    return Telemetry(exporter=exporter, rpc=rpc, interval=interval,
                     device_info=device_info, reports_info=reports_info)


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


def _report_summary(ring):
    """The swarm-map summary of a device's LATEST stored report ({ts, event,
    tier, rtt_ms_median, avg_bps}) or None when the ring is empty/garbage.
    Full per-peer rows are deliberately NOT inlined into /swarm (payload
    discipline) — the console drawer fetches them on demand."""
    try:
        rep = ring[-1]
        link = rep.get("link")
        link = link if isinstance(link, dict) else {}
        transfer = rep.get("transfer")
        transfer = transfer if isinstance(transfer, dict) else {}
        return {"ts": rep.get("ts"), "event": rep.get("event"),
                "tier": link.get("tier"),
                "rtt_ms_median": link.get("rtt_ms_median"),
                "avg_bps": transfer.get("avg_bps")}
    except Exception:
        return None


def observability_enabled(env=None):
    """Is the EXTERNAL observability surface (Prometheus /metrics + OTLP push)
    turned on? Default OFF: IRIS doesn't assume a Grafana/Prometheus stack
    exists. The self-contained swarm JSON (/swarm) stays on regardless — the
    map PAGE lives in the authenticated console (:8080); :9101 serves a
    static pointer there (moved_page)."""
    env = os.environ if env is None else env
    return env.get("IRIS_OBSERVABILITY", "").strip().lower() in (
        "1", "true", "yes", "on")


def metrics_port(env=None):
    """Resolve the metrics listener port; None disables it (empty or '0')."""
    env = os.environ if env is None else env
    raw = env.get("IRIS_METRICS_PORT", str(DEFAULT_METRICS_PORT)).strip()
    return int(raw) if raw and raw != "0" else None


def moved_page():
    """Static pointer page for the retired :9101 map URLs (/swarmmap and /).
    The live swarm map is inside the authenticated console — this keeps old
    bookmarks failing helpfully instead of 404ing. Reads env vars per request
    so it works without a restart once they're set.

    IRIS_CONSOLE_URL, when non-empty, overrides the console URL verbatim —
    e.g. shared hosts publishing the console on a non-default port. Garbage
    tolerant: any non-empty string is used as-is, no validation. Otherwise
    falls back to the IRIS_HOST_IP-derived https://<host>:8080/ default."""
    override = os.environ.get("IRIS_CONSOLE_URL", "").strip()
    if override:
        console = override
    else:
        host = os.environ.get("IRIS_HOST_IP", "").strip() or "localhost"
        console = "https://%s:8080/" % host
    return ("<!doctype html>\n<html><head><meta charset=\"utf-8\">"
            "<title>intelligent-release-image-staging swarm map has moved"
            "</title></head><body>"
            "<h1>The swarm map moved into the "
            "intelligent-release-image-staging Console</h1>"
            "<p>Open <a href=\"%s\">%s</a> and sign in &mdash; the live map "
            "is on the Swarm tab.</p></body></html>\n"
            % (console, console)).encode("ascii")


def make_metrics_server(host, port, provider, swarm_provider=None, html=None):
    """HTTP server. `/healthz` is always served; `/metrics` is served only when
    `provider` is given (None -> 404, the observability-off posture); /swarm
    and /swarmmap are served when their handlers are given. This is how the
    swarm map stays always-on while the Prometheus surface is opt-in.

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
                self._send(200, b"ok\n", "text/plain")
            elif path == "/swarm" and swarm_provider is not None:
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
