# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Minimal OTLP/HTTP-JSON log exporter for IRIS swarm lifecycle events
(stdlib only). Events are queued and flushed in batches to the collector's
`/v1/logs` endpoint; per-device (high-cardinality) detail flows through the
OTLP logs pipeline.

Best-effort by design: a bounded queue drops the oldest events when the
collector is unreachable, and send failures are swallowed — telemetry must
never block or break the announce path. Periodic flushing is driven by the
caller (the telemetry sampler loop), so there is no thread in here."""
import collections
import json
import os
import threading
import urllib.request

import trust

# OTLP severityNumber for INFO (see logs proto)
_SEVERITY_INFO = 9


def default_resource():
    """Resource attrs per spec 7.9: stable service identity + repo version."""
    version = "unknown"
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "..", "VERSION")) as f:
            version = f.read().strip()
    except OSError:
        pass
    return {"service.name": "iris-tracker", "service.namespace": "iris",
            "service.version": version}


DEFAULT_RESOURCE = default_resource()

# swarm lifecycle event fields -> semconv attribute names (spec 7.6/7.9);
# network.transport is constant tcp (the conventions require naming the
# transport whenever a peer port is set).
_EVENT_ATTRS = (("ip", "network.peer.address"),
                ("port", "network.peer.port"),
                ("info_hash", "iris.torrent.info_hash"),
                ("peer_id", "iris.torrent.peer_id"),
                ("left", "iris.torrent.left"))


def _any_value(value):
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        # OTLP/JSON encodes int64 as a string
        return {"intValue": str(value)}
    return {"stringValue": str(value)}


def _attr(key, value):
    return {"key": key, "value": _any_value(value)}


def build_log_record(event):
    """Map a swarm lifecycle event dict to one OTLP LogRecord. Event identity
    lives in the top-level eventName field (iris.swarm.<start|complete|stop|
    stale>); the body stays a short display string (spec 7.6/7.9)."""
    ts_nano = str(int(float(event.get("ts", 0)) * 1e9))
    attrs = [_attr(sem, event[key]) for key, sem in _EVENT_ATTRS
             if event.get(key) is not None]
    if event.get("port") is not None:
        attrs.append(_attr("network.transport", "tcp"))
    name = str(event.get("event", "unknown"))
    return {
        "timeUnixNano": ts_nano,
        "eventName": "iris.swarm." + name,
        "severityNumber": _SEVERITY_INFO,
        "severityText": "INFO",
        "body": {"stringValue": "swarm " + name},
        "attributes": attrs,
    }


_ENRICH_STR_MAX = 128


def _enrich_str(value):
    return str(value)[:_ENRICH_STR_MAX] if value is not None else None


def _enrich_int(value):
    try:
        if isinstance(value, bool):
            return None
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def build_report_record(report, device_id, enrich=None):
    """One stored device report -> one OTLP LogRecord (spec 7.6). Attribute
    names follow the semantic conventions (device.id is the sanctioned
    enterprise-managed-device identifier); the peers observed during the
    transfer ride as the structured attribute iris.transfer.peers
    (participation only — per-peer bytes are not measured), with
    iris.transfer.peers_total carrying the exact distinct count. enrich
    (optional): {model, free_flash_bytes, stage_state,
    peer_devices: {ip: device_id}} — heartbeat-sourced values are stored
    verbatim from devices, so they are capped/coerced HERE at the export
    boundary. Garbage-tolerant throughout."""
    if not isinstance(report, dict):
        report = {}
    enrich = enrich if isinstance(enrich, dict) else {}
    try:
        ts_nano = str(int(float(report.get("ts", 0)) * 1e9))
    except (TypeError, ValueError):
        ts_nano = "0"
    link = report.get("link")
    link = link if isinstance(link, dict) else {}
    transfer = report.get("transfer")
    transfer = transfer if isinstance(transfer, dict) else {}
    agent = report.get("agent")
    agent = agent if isinstance(agent, dict) else {}
    pairs = (("device.id", _enrich_str(device_id)),
             ("iris.image.id", _enrich_str(report.get("image_id"))),
             ("iris.link.tier", _enrich_str(link.get("tier"))),
             ("iris.transfer.throughput_avg",
              _enrich_int(transfer.get("avg_bps"))),
             ("iris.transfer.peers_total",
              _enrich_int(report.get("peers_total"))),
             ("device.model.identifier", _enrich_str(enrich.get("model"))),
             ("iris.device.flash.free",
              _enrich_int(enrich.get("free_flash_bytes"))),
             ("iris.stage.state", _enrich_str(enrich.get("stage_state"))),
             ("iris.agent.runtime", _enrich_str(agent.get("runtime_mode"))),
             ("iris.agent.version", _enrich_str(agent.get("version"))))
    attrs = [_attr(k, v) for k, v in pairs if v is not None]
    peer_devices = enrich.get("peer_devices")
    peer_devices = peer_devices if isinstance(peer_devices, dict) else {}
    rows = []
    peers = report.get("peers")
    for row in (peers if isinstance(peers, list) else []):
        if not isinstance(row, dict):
            continue
        kv = [("network.peer.address", _enrich_str(row.get("ip"))),
              ("device.id", _enrich_str(peer_devices.get(row.get("ip"))))]
        rows.append({"kvlistValue": {"values": [
            {"key": k, "value": _any_value(v)}
            for k, v in kv if v is not None]}})
    if rows:
        attrs.append({"key": "iris.transfer.peers",
                      "value": {"arrayValue": {"values": rows}}})
    return {
        "timeUnixNano": ts_nano,
        "eventName": "iris.device.report",
        "severityNumber": _SEVERITY_INFO,
        "severityText": "INFO",
        "body": {"stringValue": "device transfer report"},
        "attributes": attrs,
    }


def build_logs_payload(events, resource_attrs):
    """Wrap log records in the OTLP/HTTP-JSON ExportLogsServiceRequest shape.
    The queue (OTLPLogExporter.emit/flush) carries two shapes: raw swarm
    lifecycle events (mapped here via build_log_record) and already-built
    LogRecords queued pre-formed by the telemetry sampler (build_report_record,
    issue #13) — recognisable by the timeUnixNano key no raw event has. Passing
    a pre-built record through build_log_record a second time would find none
    of its expected keys and silently produce an empty record, so it is passed
    through unchanged instead."""
    def _record(e):
        return e if isinstance(e, dict) and "timeUnixNano" in e \
            else build_log_record(e)
    return {
        "resourceLogs": [{
            "resource": {
                "attributes": [_attr(k, v) for k, v in resource_attrs.items()],
            },
            "scopeLogs": [{
                "scope": {"name": "iris.tracker"},
                "logRecords": [_record(e) for e in events],
            }],
        }],
    }


def parse_headers(spec):
    """'Name=Value,Name2=Value2' -> dict. Malformed pairs are skipped.
    Values are SECRETS: callers must never log or interpolate them."""
    out = {}
    for pair in (spec or "").split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out


def read_headers_env(env):
    """IRIS_OTLP_HEADERS, or IRIS_OTLP_HEADERS_FILE (k8s secret mounts —
    the IRIS_RPC_SECRET_FILE pattern)."""
    spec = env.get("IRIS_OTLP_HEADERS", "")
    if not spec:
        path = env.get("IRIS_OTLP_HEADERS_FILE", "")
        if path:
            try:
                with open(path) as f:
                    spec = f.read().strip()
            except OSError:
                spec = ""
    return parse_headers(spec)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse ALL redirects: urllib's default handler re-sends the original
    headers — collector auth included — to whatever cross-origin Location a
    (compromised or plain-http) endpoint returns. Any 3xx is an export
    failure (spec 7.8)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_post(url, body, headers=None):
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=hdrs)
    # Opener built per call so HTTPS verifies against trust.ssl_context()
    # (system roots + the IRIS bundle): a console trust-store edit reaches
    # the next export without a restart. trust.ssl_context() is mtime-cached,
    # so per-call cost is opener assembly only (2 POSTs per sampler pass).
    try:
        opener = urllib.request.build_opener(
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=trust.ssl_context()))
        with opener.open(req, timeout=5) as resp:
            resp.read()
    except Exception:
        # Deliberately generic: exception text from urllib can embed request
        # details; never let a header value ride out in an error message.
        raise RuntimeError("OTLP POST to %s failed" % url) from None


def _send(sender, url, body, headers):
    """Call sender with headers when it accepts them; keep 2-arg senders
    (existing tests, simple stubs) working."""
    try:
        sender(url, body, headers=headers)
    except TypeError:
        sender(url, body)


class LogQueue:
    """Stable, bounded, thread-safe FIFO of OTLP log events, deliberately
    SEPARATE from the mutable destination transport (design §8, Task 22). The
    telemetry hub owns exactly ONE LogQueue for the process lifetime and swaps
    only the transport when the console changes / disables / re-enables the
    OTLP destination — so already-queued events are never dropped or reordered
    by a destination change.

    Durability contract:
      * ``emit`` appends FIFO; when the queue is full the OLDEST event is
        dropped BEFORE the append (bounded best-effort, Day-1 in-process), and
        ``dropped_total`` is incremented per drop. FIFO order of the kept
        events is preserved.
      * ``flush(send)`` hands a snapshot batch to ``send`` and removes those
        events from the queue ONLY after ``send`` returns without raising.
        On failure the exact original batch (same order, same identities) is
        left in place, and any events emitted concurrently during the in-flight
        send are preserved after it — nothing is lost or reordered.
      * ``flush`` returns None on an empty queue (no attempt), else the count
        of events confirmed delivered (0 on a failed send)."""

    def __init__(self, max_queue=1000):
        self._queue = collections.deque()
        self._max = int(max_queue)
        self._dropped = 0
        self._lock = threading.Lock()

    def emit(self, event):
        with self._lock:
            while len(self._queue) >= self._max:
                self._queue.popleft()       # drop oldest, preserve FIFO
                self._dropped += 1
            self._queue.append(event)

    @property
    def queued(self):
        with self._lock:
            return len(self._queue)

    @property
    def dropped_total(self):
        with self._lock:
            return self._dropped

    def snapshot(self):
        with self._lock:
            return list(self._queue)

    def flush(self, send):
        """Deliver the current batch via ``send(batch)`` (which must raise on
        failure); remove exactly those events on confirmed success, otherwise
        restore them at the FRONT preserving order and any concurrent emits at
        the back. Returns None (empty), the delivered count, or 0 (failure)."""
        with self._lock:
            n = len(self._queue)
            if n == 0:
                return None
            batch = [self._queue.popleft() for _ in range(n)]
        try:
            send(batch)
        except Exception:
            with self._lock:
                # restore the exact original batch ahead of anything that
                # landed while the send was in flight — no loss, no reorder.
                self._queue.extendleft(reversed(batch))
            return 0
        return len(batch)


class OTLPLogTransport:
    """The MUTABLE OTLP/HTTP-JSON logs destination (endpoint + headers +
    resource + sender), holding NO queue. ``send(batch)`` posts one batch and
    RAISES on failure so the caller's LogQueue can retain the batch for retry.
    The hub constructs a fresh transport on every destination change; the
    LogQueue it feeds is unchanged (Task 22)."""

    def __init__(self, endpoint, resource_attrs=None, sender=None,
                 headers=None):
        self.url = endpoint.rstrip("/") + "/v1/logs"
        self._resource = dict(resource_attrs or DEFAULT_RESOURCE)
        self._sender = sender or _http_post
        self._headers = dict(headers or {})

    def send(self, batch):
        """POST one batch; raise on failure. Returns the delivered count."""
        body = json.dumps(build_logs_payload(batch, self._resource)).encode()
        _send(self._sender, self.url, body, self._headers)
        return len(batch)


class OTLPLogExporter:
    """Backwards-compatible composition of a stable LogQueue and a mutable
    OTLPLogTransport, preserving the historical emit()/flush() single-object
    API used by direct callers and older tests. New code (the hub) drives a
    LogQueue and OTLPLogTransport separately so a destination swap keeps the
    queue (Task 22)."""

    def __init__(self, endpoint, resource_attrs=None, max_queue=1000,
                 sender=None, headers=None):
        self.queue = LogQueue(max_queue=max_queue)
        self.transport = OTLPLogTransport(
            endpoint, resource_attrs=resource_attrs, sender=sender,
            headers=headers)
        self.url = self.transport.url

    def emit(self, event):
        self.queue.emit(event)

    def flush(self):
        """Send all queued events in one request. Returns None when the queue
        was empty (no attempt — nothing to report), 0 when a send was tried
        and failed (best-effort, swallowed), else the count delivered."""
        return self.queue.flush(self.transport.send)


def build_metrics_payload(points, resource_attrs):
    """OTLP/HTTP-JSON ExportMetricsServiceRequest. `points`:
    {"name","unit","kind":"gauge"|"sum","value","attrs",["float":True]}.
    Sums are monotonic cumulative (aggregationTemporality 2) and — per the
    semantic conventions — never carry a _total suffix on the wire."""
    metrics_out = []
    for p in points:
        dp = {"timeUnixNano": str(int(float(p.get("ts", 0)) * 1e9)),
              "attributes": [_attr(k, v)
                             for k, v in sorted(p.get("attrs", {}).items())]}
        if p.get("float"):
            dp["asDouble"] = float(p["value"])
        else:
            dp["asInt"] = str(int(p["value"]))
        m = {"name": p["name"], "unit": p.get("unit", "")}
        if p.get("kind") == "sum":
            m["sum"] = {"dataPoints": [dp], "isMonotonic": True,
                        "aggregationTemporality": 2}
        else:
            m["gauge"] = {"dataPoints": [dp]}
        metrics_out.append(m)
    return {"resourceMetrics": [{
        "resource": {"attributes": [
            _attr(k, v) for k, v in resource_attrs.items()]},
        "scopeMetrics": [{"scope": {"name": "iris.tracker"},
                          "metrics": metrics_out}],
    }]}


class OTLPMetricsExporter:
    """Conflating metrics push: export() sends the CURRENT snapshot, drops on
    failure (gauges have no history worth buffering — spec 7.5/R8)."""

    def __init__(self, endpoint, resource_attrs=None, headers=None,
                 sender=None):
        self.url = endpoint.rstrip("/") + "/v1/metrics"
        self._resource = dict(resource_attrs or DEFAULT_RESOURCE)
        self._headers = dict(headers or {})
        self._sender = sender or _http_post

    def export(self, points):
        if not points:
            return True
        body = json.dumps(
            build_metrics_payload(points, self._resource)).encode()
        try:
            _send(self._sender, self.url, body, self._headers)
        except Exception:
            return False
        return True
