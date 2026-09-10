# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Pinned sender classification per exported device report.

``telemetry._export_new_reports`` classifies every ``peer_transfer_records``
row of a report -- ``origin`` / ``device`` / ``unknown`` -- against two
VOLATILE inputs: the addresses the ``service:seeder`` principal is announcing
from, and the catalog's current swarm-address -> device join. The report
itself is replayed under the SAME ``event.id`` after every process start
(at-least-once delivery, deduplicated by id in the backend), and the replay
runs before the seeder's first re-announce has reached the fresh registry, so
it classified the origin's rows ``unknown`` where the first export had said
``origin``. Two records, one id, different content: no backend can collapse
them, and an operator reading the per-peer table saw the same transfer twice.

This store pins the classification. The identity view a report's rows were
first exported against -- the origin addresses and the address -> device join,
cut down to the report's own rows -- is written once and read back on every
later export of that report, so a replay carries a byte-identical record.

A classification made while the server knew NO origin address at all and left
a row ``unknown`` is not pinned: the likeliest reason for that combination is
the startup gap itself, and pinning it would make the degraded answer the
permanent one. Such a report is classified live again on its next export and
pinned as soon as an origin is known.

Bounded by the report ring: an entry whose report has left the ring is
dropped on the same pass that forgets its delivered id. Every write is an
atomic temp + ``os.replace``, a per-module copy of the peer_ledger idiom on
purpose (each durable store owns its own semantics). An unreadable or corrupt
file reads as empty: identity was never kept here, only a classification the
next pass can make again.
"""
import json
import os
import tempfile
import time

FILENAME = "report-attribution.json"
_SCHEMA = 1


def _atomic_write_json(path, obj):
    directory = os.path.dirname(path) or "."
    mode = None
    try:
        mode = os.stat(path).st_mode
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".report-attribution-",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(obj, stream, indent=2, sort_keys=True)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def identity_view(block, origin_ips, device_by_ip):
    """The part of the live identity view a transfer-record block actually
    uses: ``(origin_ips, device_by_ip)`` restricted to the block's row
    addresses, so a pinned entry is bounded by the row cap rather than by
    the fleet. Row addresses are keyed as strings, exactly as
    ``telemetry.transfer_record_source_class`` looks them up."""
    ips = set()
    rows = block.get("rows") if isinstance(block, dict) else None
    for row in rows if isinstance(rows, list) else ():
        if isinstance(row, dict) and row.get("ip") is not None:
            ips.add(str(row["ip"]))
    origin = {ip for ip in ips if ip in (origin_ips or ())}
    devices = {ip: str((device_by_ip or {})[ip])
               for ip in ips if ip in (device_by_ip or {})}
    return origin, devices


def is_provisional(split, origin_ips):
    """True when a live classification may have been degraded by the startup
    gap: no origin address was known AND at least one row went ``unknown``.
    Anything else is pinned as classified -- a device-only wave classified
    without an origin is exact, and an ``unknown`` row classified while the
    origin WAS known is a genuine unknown, not a gap."""
    if origin_ips:
        return False
    if not isinstance(split, dict):
        return False
    try:
        return int(split.get("unknown_rows") or 0) > 0
    except (TypeError, ValueError):
        return False


class ReportAttributionStore:
    """``{event_id: (origin_ips, device_by_ip)}`` on disk, see the module
    docstring. ``state_dir`` is created if missing; a directory that cannot
    be created raises ``OSError`` so the caller can run without pinning, the
    same posture as the peer ledger."""

    def __init__(self, state_dir, now_fn=time.time):
        os.makedirs(state_dir, exist_ok=True)
        self.path = os.path.join(state_dir, FILENAME)
        self._now = now_fn

    # --- storage -----------------------------------------------------------

    def _read(self):
        try:
            with open(self.path) as stream:
                data = json.load(stream)
        except (OSError, ValueError):
            return {}
        reports = data.get("reports") if isinstance(data, dict) else None
        return reports if isinstance(reports, dict) else {}

    def _write(self, reports):
        _atomic_write_json(self.path, {"schema": _SCHEMA, "reports": reports})

    @staticmethod
    def _view(entry):
        if not isinstance(entry, dict):
            return None
        origin = entry.get("origin")
        devices = entry.get("devices")
        if not isinstance(origin, list) or not isinstance(devices, dict):
            return None
        return ({str(ip) for ip in origin},
                {str(ip): str(did) for ip, did in devices.items()})

    def _entry(self, origin_ips, device_by_ip):
        return {
            "origin": sorted(str(ip) for ip in origin_ips or ()),
            "devices": {str(ip): str(did)
                        for ip, did in (device_by_ip or {}).items()},
            "pinned_at": float(self._now()),
        }

    # --- API ---------------------------------------------------------------
    #
    # The export pass uses ``snapshot`` once at its start and ``sync`` once at
    # its end: two reads and at most one write per pass, whatever the fleet
    # size. ``get``/``pin``/``prune`` are the same operations one report at a
    # time, for callers that have only one.

    def snapshot(self):
        """``{event_id: (origin_ips, device_by_ip)}`` for every pinned
        report. A corrupt entry is simply not pinned."""
        out = {}
        for key, entry in self._read().items():
            view = self._view(entry)
            if view is not None:
                out[key] = view
        return out

    def sync(self, keep, pins):
        """Drop every entry whose report id is not in ``keep`` (the current
        ring) and add ``pins`` (``{event_id: (origin_ips, device_by_ip)}``)
        for reports not yet pinned -- the first pin wins, because the whole
        point is that a classification never changes once exported. One
        read-modify-write; the file is rewritten only when it changed.
        Returns True when it was."""
        keep = {str(k) for k in keep}
        reports = self._read()
        kept = {k: v for k, v in reports.items() if k in keep}
        changed = len(kept) != len(reports)
        for event_id, (origin_ips, device_by_ip) in (pins or {}).items():
            key = str(event_id)
            if self._view(kept.get(key)) is not None:
                continue
            kept[key] = self._entry(origin_ips, device_by_ip)
            changed = True
        if changed:
            self._write(kept)
        return changed

    def get(self, event_id):
        """The pinned ``(origin_ips, device_by_ip)`` for a report, or None."""
        return self._view(self._read().get(str(event_id)))

    def pin(self, event_id, origin_ips, device_by_ip):
        """Record the identity view for one report. Returns True when a write
        happened; a report already pinned is left as it was."""
        reports = self._read()
        key = str(event_id)
        if self._view(reports.get(key)) is not None:
            return False
        reports[key] = self._entry(origin_ips, device_by_ip)
        self._write(reports)
        return True

    def prune(self, keep):
        """Drop every entry whose report id is not in ``keep``. Writes only
        when something was dropped."""
        return self.sync(keep, {})
