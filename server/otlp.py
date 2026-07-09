# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Minimal OTLP/HTTP-JSON log exporter for IRIS swarm lifecycle events
(stdlib only). Events are queued and flushed in batches to the collector's
`/v1/logs` endpoint; per-device (high-cardinality) audit lands in Loki.

Best-effort by design: a bounded queue drops the oldest events when the
collector is unreachable, and send failures are swallowed — telemetry must
never block or break the announce path. Periodic flushing is driven by the
caller (the telemetry sampler loop), so there is no thread in here."""
import collections
import json
import threading
import urllib.request

# OTLP severityNumber for INFO (see logs proto)
_SEVERITY_INFO = 9

DEFAULT_RESOURCE = {"service.name": "iris-tracker"}

# event fields surfaced as log-record attributes (ts -> timeUnixNano,
# event -> body, and event is also kept as an attribute for easy filtering)
_ATTR_KEYS = ("event", "info_hash", "peer_id", "ip", "port", "left")


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
    """Map a swarm lifecycle event dict to a single OTLP LogRecord."""
    ts_nano = str(int(float(event.get("ts", 0)) * 1e9))
    attrs = [_attr(k, event[k]) for k in _ATTR_KEYS
             if event.get(k) is not None]
    return {
        "timeUnixNano": ts_nano,
        "severityNumber": _SEVERITY_INFO,
        "severityText": "INFO",
        "body": {"stringValue": str(event.get("event", ""))},
        "attributes": attrs,
    }


def build_report_record(report, device_id):
    """Map one stored device telemetry report (issue #13) to a single OTLP
    LogRecord. Sibling of build_log_record: same severity/int64-as-string
    rules; the constant event='device-report' attribute lets Loki queries
    split report records from swarm lifecycle events. Garbage-tolerant:
    missing or mis-typed report sections are skipped, never raised —
    telemetry must never break on bad input."""
    if not isinstance(report, dict):
        report = {}
    try:
        ts_nano = str(int(float(report.get("ts", 0)) * 1e9))
    except (TypeError, ValueError):
        ts_nano = "0"
    link = report.get("link")
    link = link if isinstance(link, dict) else {}
    transfer = report.get("transfer")
    transfer = transfer if isinstance(transfer, dict) else {}
    pairs = (("event", "device-report"),
             ("device_id", device_id),
             ("image_id", report.get("image_id")),
             ("tier", link.get("tier")),
             ("avg_bps", transfer.get("avg_bps")))
    return {
        "timeUnixNano": ts_nano,
        "severityNumber": _SEVERITY_INFO,
        "severityText": "INFO",
        "body": {"stringValue": "device-report"},
        "attributes": [_attr(k, v) for k, v in pairs if v is not None],
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


def _http_post(url, body):
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read()


class OTLPLogExporter:
    """Queue events with emit(); deliver them in one batch per flush()."""

    def __init__(self, endpoint, resource_attrs=None, max_queue=1000,
                 sender=None):
        self.url = endpoint.rstrip("/") + "/v1/logs"
        self._resource = dict(resource_attrs or DEFAULT_RESOURCE)
        self._queue = collections.deque(maxlen=max_queue)
        self._sender = sender or _http_post
        self._lock = threading.Lock()

    def emit(self, event):
        with self._lock:
            self._queue.append(event)   # deque(maxlen) drops oldest when full

    def flush(self):
        """Send all queued events in one request. Returns count delivered
        (0 if nothing queued or the send failed — best-effort)."""
        with self._lock:
            batch = list(self._queue)
            self._queue.clear()
        if not batch:
            return 0
        body = json.dumps(build_logs_payload(batch, self._resource)).encode()
        try:
            self._sender(self.url, body)
        except Exception:
            return 0   # collector down / network error — dropped, never raised
        return len(batch)
