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
import time
import urllib.request
from urllib.parse import urlsplit

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


def _any_value(value):
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        # OTLP/JSON encodes int64 as a string
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, list):
        return {"arrayValue": {"values": [_any_value(v) for v in value]}}
    return {"stringValue": str(value)}


def _attr(key, value):
    return {"key": key, "value": _any_value(value)}


def build_log_record(event):
    """Map a raw swarm lifecycle event dict (from PeerRegistry.on_event) to one
    OTLP LogRecord. Per design §10.8 the canonical name is ``iris.tracker.peer``
    with typed attributes; ``event.id`` is the registry's in-process random id.
    The role is derived from ``left`` (a seeder has ``left==0``). The principal
    is composed as ``<type>:<id>`` from the typed registry principal."""
    if not isinstance(event, dict):
        event = {}
    ptype = event.get("principal_type")
    pid = event.get("principal_id")
    principal = None
    if ptype is not None:
        principal = "%s:%s" % (ptype, pid if pid is not None else "")
    role = None
    left = event.get("left")
    if left is not None:
        try:
            role = "seeder" if int(left) == 0 else "leecher"
        except (TypeError, ValueError):
            role = None
    mapped = {
        "event_id": event.get("event_id"),
        "principal": principal,
        "device_role": event.get("device_role")
            if ptype == "device" else None,
        "info_hash": event.get("info_hash"),
        "role": role,
        "ip": event.get("ip"),
        "received_at": event.get("received_at", event.get("ts")),
    }
    return build_tracker_record(mapped)


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


_SCHEMA_ATTR = "iris.telemetry.schema.version"

# Who sent the bytes in one transfer-record row, mirroring
# telemetry.TRANSFER_RECORD_SOURCE_CLASSES:
#   origin  -- the authenticated service:seeder.
#   device  -- a device whose heartbeat claims that swarm address.
#   unknown -- neither, or nobody classified the row at all.
# Only the server can answer this, and an unclassified row stays unknown --
# folding it into "device" is how a wave the origin fed 71% of gets reported as
# ~100% peer-delivered.
_PEER_ATTRIBUTIONS = ("origin", "device", "unknown")


def _peer_attribution(value):
    return value if value in _PEER_ATTRIBUTIONS else "unknown"


# The value ``iris.peer.device_id`` carries for a row the origin sent. Not the
# seeder principal's id ("seeder"): a device may legitimately be NAMED seeder
# (``device:seeder`` is a different principal from ``service:seeder``), and a
# column an operator groups senders by must not let the two collide.
ORIGIN_SOURCE_ID = "origin"


def _peer_source_id(attribution, peer_device_id):
    """One groupable sender column: the attributed device's id, ``origin`` for
    the seeder, and NOTHING for an unknown row -- an unknown sender has no id,
    and inventing a placeholder would put a non-identity in an id column."""
    if attribution == "device":
        return peer_device_id
    if attribution == "origin":
        return ORIGIN_SOURCE_ID
    return None


def _transfer_record_split_pairs(enrich):
    """Attribute pairs for ``telemetry.classify_peer_transfer_records``'s four figures,
    or [] when the block was never classified.

    The four are exported as four. ``bytes_from_devices_total`` is the only one
    an operator may read as peer-to-peer delivery; the origin's bytes and the
    bytes whose sender is unknown are named as what they are, and the mass
    belonging to rows a cap dropped is reported rather than redistributed.
    Deriving a peer share from anything less than all four is how the origin
    ends up counted as a peer."""
    if not isinstance(enrich, dict):
        return []
    split = enrich.get("peer_transfer_record_attribution")
    if not isinstance(split, dict):
        return []
    return [
        ("iris.transfer.bytes_from_origin_total",
         _enrich_int(split.get("origin_bytes"))),
        ("iris.transfer.bytes_from_devices_total",
         _enrich_int(split.get("device_bytes"))),
        ("iris.transfer.bytes_from_unknown_total",
         _enrich_int(split.get("unknown_bytes"))),
        ("iris.transfer.bytes_unattributed_omitted",
         _enrich_int(split.get("unattributed_omitted_bytes"))),
        ("iris.transfer.peer_records.origin_rows",
         _enrich_int(split.get("origin_rows"))),
        ("iris.transfer.peer_records.device_rows",
         _enrich_int(split.get("device_rows"))),
        ("iris.transfer.peer_records.unknown_rows",
         _enrich_int(split.get("unknown_rows"))),
    ]


def _record(name, ts_nano, attrs, event_id=None, body=None):
    """Assemble one OTLP LogRecord with the canonical envelope. ``event.id`` is
    retained unchanged through retry (design §10.8)."""
    rec = {
        "timeUnixNano": ts_nano,
        "eventName": name,
        "severityNumber": _SEVERITY_INFO,
        "severityText": "INFO",
        "body": {"stringValue": body or name},
        "attributes": attrs,
    }
    if event_id is not None:
        rec["attributes"].append(_attr("event.id", str(event_id)))
    return rec


def _ts_nano(value):
    try:
        return str(int(float(value) * 1e9))
    except (TypeError, ValueError):
        return "0"


def _rfc3339_millis(value):
    """Epoch seconds -> ``2026-09-02T14:03:11.482Z``: UTC, EXACTLY three
    fractional digits, a literal trailing ``Z``.

    Three properties the operator-facing Splunk extraction
    ``%Y-%m-%dT%H:%M:%S.%N%Z`` depends on, none of them incidental:
      1. UTC via ``time.gmtime``, never the container's local zone -- the
         exported instant must not change meaning when a host is re-zoned.
      2. The fractional field is ALWAYS present and ALWAYS exactly three
         digits, so ``%N`` never faces a missing or variable-width field. A
         whole-second instant rendered as ``...:11Z`` fails the pattern
         outright, which is why the millis are formatted unconditionally.
      3. A literal ``Z``, never ``+00:00``: ``%Z`` matches a zone NAME and
         will not consume a numeric offset.
    The date part is assembled with explicit ``%`` conversions off the
    ``time.gmtime`` fields rather than ``strftime``, whose output is
    locale-sensitive in some builds; an operator's LANG must not be able to
    change the shape of an exported timestamp.

    Returns None for anything uncoercible -- ``bool`` included, since it is an
    ``int`` subclass and would otherwise render True as
    ``1970-01-01T00:00:01.000Z``. None means the caller DROPS the attribute
    pair (``attrs = [_attr(k, v) for k, v in pairs if v is not None]``), which
    is the house rule here: a builder never raises on bad input, and an absent
    attribute is honest where a fabricated instant is not."""
    if isinstance(value, bool):
        return None
    try:
        ts = float(value)
    except (TypeError, ValueError):
        return None
    # NaN is the only value unequal to itself; an infinity would blow up
    # int() below. A negative epoch is not a thing IRIS can observe -- it
    # means a corrupt row, not a pre-1970 transfer.
    if ts != ts or abs(ts) == float("inf") or ts < 0:
        return None
    whole = int(ts)
    millis = int(round((ts - whole) * 1000))
    if millis == 1000:
        # The rounding carried: 1.9996 is ...:02.000Z, never ...:01.1000Z,
        # which would be four fractional digits and break property 2 above.
        whole += 1
        millis = 0
    try:
        tm = time.gmtime(whole)
    except (OverflowError, ValueError, OSError):
        # A year outside the platform's time_t range. Same contract as every
        # other rejection: drop the attribute rather than raise inside an
        # exporter that must never break the caller.
        return None
    return "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ" % (
        tm.tm_year, tm.tm_mon, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec, millis)


def _build_v2_report_record(report, device_id, enrich=None):
    """v2 terminal report -> ``iris.device.transfer.report`` (design §10.8).
    OTLP event time = server ``received_at`` (device ``observed_at`` rides as an
    attribute). ``event.id`` = the stable random ``report_id``. Typed content
    SHA / IOS-copy states and content-at-end bytes; participation IPs only."""
    content = report.get("content") if isinstance(
        report.get("content"), dict) else {}
    sha = report.get("content_sha256") if isinstance(
        report.get("content_sha256"), dict) else {}
    ios = report.get("ios_copy_verify") if isinstance(
        report.get("ios_copy_verify"), dict) else {}
    transfer_records = report.get("peer_transfer_records") if isinstance(
        report.get("peer_transfer_records"), dict) else {}
    pairs = [
        ("otel.log.name", "iris.device.transfer.report"),
        (_SCHEMA_ATTR, 2),
        ("device.id", _enrich_str(device_id)),
        ("iris.image.id", _enrich_str(report.get("image_id"))),
        ("iris.transfer.id", _enrich_str(report.get("transfer_id"))),
        ("iris.report.event", _enrich_str(report.get("event"))),
        ("iris.transfer.content_sha256.state", _enrich_str(sha.get("state"))),
        ("iris.transfer.ios_copy_verify.state", _enrich_str(ios.get("state"))),
        ("iris.transfer.completed_content_bytes",
         _enrich_int(content.get("completed_content_bytes"))),
        ("iris.transfer.peers_total", _enrich_int(report.get("peers_total"))),
        # Summary of the device-measured transfer-record block; the per-peer detail is
        # its own event (build_peer_transfer_records). All None-skipped, so a
        # report that carries no transfer records adds nothing -- absent means NOT
        # MEASURED, and a zero here would claim a measurement nobody made.
        ("iris.transfer.peer_records.capture_complete",
         transfer_records.get("complete")),
        ("iris.transfer.peer_records.rows_total",
         _enrich_int(transfer_records.get("rows_total"))),
        ("iris.transfer.peer_records.rows_omitted",
         _enrich_int(transfer_records.get("rows_omitted"))),
        ("iris.transfer.peer_records.rows_dropped_by_server",
         _enrich_int(transfer_records.get("rows_dropped_by_server"))),
        # Keeps the device's own name: this total counts EVERY sender the
        # device received from, the origin seeder included, because the origin
        # is an ordinary BitTorrent peer of every device. Nothing in this
        # record may call it bytes "from peers".
        ("iris.transfer.bytes_from_all_senders_total",
         _enrich_int(transfer_records.get("bytes_from_all_senders_total"))),
        ("iris.transfer.bytes_from_all_senders_omitted",
         _enrich_int(transfer_records.get("bytes_from_all_senders_omitted"))),
        # A cap the SERVER applied to the participation table. It used to be
        # invisible (the stored report kept the device's own truncation flag),
        # and an invisible trim reads as a complete list.
        ("iris.transfer.peers_rows_dropped",
         _enrich_int(report.get("peers_rows_dropped"))),
    ]
    # The origin/device/unknown split of that total, when the sampler has run
    # telemetry.classify_peer_transfer_records over the block. It is the ONLY thing
    # taken out of `enrich`: everything else there is high-cardinality device
    # detail that was deliberately dropped from this event. The four figures
    # stay four -- an absent split adds nothing rather than zeroing a bucket.
    pairs.extend(_transfer_record_split_pairs(enrich))
    attrs = [_attr(k, v) for k, v in pairs if v is not None]
    window = report.get("window") if isinstance(report.get("window"), dict) \
        else {}
    observed = window.get("end")
    if observed is None:
        observed = report.get("report_created_at")
    try:
        if observed is not None:
            attrs.append(_attr("iris.device.observed_at", float(observed)))
    except (TypeError, ValueError):
        pass
    ips = [_enrich_str(row.get("ip"))
           for row in (report.get("peers") or [])
           if isinstance(row, dict) and row.get("ip") is not None]
    if ips:
        attrs.append(_attr("network.peer.address", ips))
    return _record("iris.device.transfer.report",
                   _ts_nano(report.get("received_at")), attrs,
                   event_id=report.get("report_id"),
                   body="device transfer report")


def _build_v1_report_record(report, device_id):
    """v1 legacy report -> ``iris.device.report`` (design §10.8) with the SAFE
    SUBSET only. OTLP event time = server ``received_at``; ``event.id`` = the
    catalog-stamped random ``_event_id``. The ambiguous v1 avg_bps/total_bytes/
    sha_ok are NEVER projected as v2-named attributes."""
    pairs = [
        ("otel.log.name", "iris.device.report"),
        (_SCHEMA_ATTR, 1),
        ("device.id", _enrich_str(device_id)),
        ("iris.image.id", _enrich_str(report.get("image_id"))),
        ("iris.report.event", _enrich_str(report.get("event"))),
        ("iris.transfer.peers_total", _enrich_int(report.get("peers_total"))),
    ]
    attrs = [_attr(k, v) for k, v in pairs if v is not None]
    ips = [_enrich_str(row.get("ip"))
           for row in (report.get("peers") or [])
           if isinstance(row, dict) and row.get("ip") is not None]
    if ips:
        attrs.append(_attr("network.peer.address", ips))
    ts = report.get("received_at")
    if ts is None:
        ts = report.get("ts")
    return _record("iris.device.report", _ts_nano(ts), attrs,
                   event_id=report.get("_event_id"),
                   body="device transfer report")


def build_report_record(report, device_id, enrich=None):
    """One stored device report -> one OTLP LogRecord (design §10.8). Branches
    on report schema: a v2 report (``report_id`` present, or ``schema=="v2"``)
    exports the typed ``iris.device.transfer.report``; anything else is treated
    as a legacy v1 projection under ``iris.device.report`` with a safe subset.
    Of ``enrich`` only ``peer_transfer_record_attribution`` is folded in (the
    origin/device/unknown split of the transfer-record block, which the record cannot
    compute for itself); the high-cardinality model/flash/stage detail stays
    out of the canonical report event. Garbage-tolerant throughout."""
    if not isinstance(report, dict):
        report = {}
    is_v2 = report.get("schema") == "v2" or report.get("report_id") is not None
    if is_v2:
        return _build_v2_report_record(report, device_id, enrich)
    return _build_v1_report_record(report, device_id)


def build_policy_record(entry, status=None):
    """Peer-policy operation outbox entry -> ``iris.peer.policy`` (design
    §10.8, emitted by the tracker). ``event.id`` = the outbox ``event_id``
    persisted in the policy transaction. Carries ONLY the single acted target
    and count-only enforcement facts — never rule text, an IP list, or a
    device-id list beyond the acted device."""
    if not isinstance(entry, dict):
        entry = {}
    status = status if isinstance(status, dict) else {}
    pairs = [
        ("otel.log.name", "iris.peer.policy"),
        (_SCHEMA_ATTR, 2),
        ("iris.policy.revision", _enrich_int(entry.get("revision"))),
        ("iris.policy.action", _enrich_str(entry.get("action"))),
        ("iris.enforcement.state", _enrich_str(status.get("state"))),
        ("iris.enforcement.applied_revision",
         _enrich_int(status.get("applied_revision"))),
        ("iris.enforcement.desired_ip_count",
         _enrich_int(status.get("desired_ip_count"))),
    ]
    attrs = [_attr(k, v) for k, v in pairs if v is not None]
    return _record("iris.peer.policy", _ts_nano(entry.get("created_at")),
                   attrs, event_id=entry.get("event_id"),
                   body="peer policy operation")


_LIFECYCLE_NAME = "iris.transfer.lifecycle"

# The two transitions a transfer plan can report, in the only order they can
# occur. ``planned`` is minted with the assignment; ``seeding_started`` is the
# server's observation that the device holds verified content AND is announcing
# as a seeder for it. There is deliberately no "downloading" between them: the
# server has no honest instant for one.
_LIFECYCLE_EVENTS = ("planned", "seeding_started")


def build_transfer_lifecycle_record(row, event):
    """One ``transfer_lifecycle`` store row -> ``iris.transfer.lifecycle``,
    the server-side plan lifecycle event (``event`` is one of
    ``_LIFECYCLE_EVENTS``).

    OTLP event time is the SOURCE instant -- ``planned_at`` for ``planned``,
    ``seeding_started_at`` for ``seeding_started`` -- never the emit instant
    and never an ingestion time. This is a deliberate departure from
    ``_build_v2_report_record``, which times off the server's ``received_at``
    because the only thing it knows for certain about a device report is when
    it arrived. Here the server itself minted and observed both instants, so
    timing the record off the emit would report a queue delay as a transfer
    fact, and a crash-replay would then move an already-exported timestamp.

    ``event.id`` is DERIVED from the plan (``<plan_id>.<event>``), never minted
    per emission, so a replay after a crash between the queue accepting the
    record and the durable marker landing carries a byte-identical record. The
    two events MUST therefore differ in that suffix: ``LogQueue.emit`` refuses
    a key already in ``_keys``/``_inflight_keys``, so a shared id would make
    the second record vanish silently rather than fail loudly.

    Both device-id spellings ride on purpose. ``iris.device.transfer.report``
    carries ``device.id`` and ``iris.swarm.peer_bytes`` carries
    ``iris.device.id``; emitting both here lets either join be written without
    a coalesce. An attribute cannot be withdrawn additively, so this is a
    permanent commitment, made knowingly.

    WHAT IS AN INGEST INSTANT SAYS SO. ``iris.transfer.checksum_verified_at``
    is the server's ``received_at`` for the attesting report, so the same value
    also ships as ``iris.transfer.report_received_at`` -- the honest name. The
    device reports no verification instant at all, so nothing is back-dated to
    stand in for one; what ships instead is the device's own
    ``report_created_at``, beside its ``observed_at``, on the device's clock,
    so an operator can see how much delivery latency a plan-to-seed duration
    is carrying rather than reading it as transfer time.

    ``iris.transfer.recovered_promotion`` rides only when the row was promoted
    on a pass that REBUILT it from a lost store. Such a record's
    ``seeding_started_at`` is the durable pair alone, which may be earlier than
    what an earlier emission under the identical ``event.id`` carried; the flag
    is what lets a backend attribute that difference instead of silently
    holding two values.

    Garbage-tolerant throughout: a non-dict row reads as empty, every
    uncoercible timestamp drops its own attribute pair (see
    ``_rfc3339_millis``), and ``_ts_nano`` yields ``"0"`` rather than raising.
    An absent attribute means NOT KNOWN -- nothing here is defaulted, because a
    defaulted plan id or instant is worse than a missing one."""
    if not isinstance(row, dict):
        row = {}
    seeding = event == "seeding_started"
    pairs = [
        ("otel.log.name", _LIFECYCLE_NAME),
        (_SCHEMA_ATTR, 2),
        ("event", _enrich_str(event)),
        # The four correlation ids. ``iris.plan.id`` is the join key an
        # operator groups on: it is stable across both events of one plan and
        # distinct across two plans for the same device and image.
        ("iris.transfer.id", _enrich_str(row.get("transfer_id"))),
        ("iris.plan.id", _enrich_str(row.get("plan_id"))),
        ("iris.device.id", _enrich_str(row.get("device_id"))),
        ("device.id", _enrich_str(row.get("device_id"))),
        ("iris.image.id", _enrich_str(row.get("image_id"))),
        ("iris.torrent.info_hash", _enrich_str(row.get("info_hash"))),
        # Repeated on BOTH events so plan-to-seeding duration is computable
        # from the seeding_started record alone, without joining back to the
        # planned record that may have been dropped by a bounded queue.
        ("iris.transfer.planned_at", _rfc3339_millis(row.get("planned_at"))),
    ]
    at = row.get("planned_at")
    if seeding:
        at = row.get("seeding_started_at")
        pairs.extend([
            ("iris.transfer.seeding_started_at",
             _rfc3339_millis(row.get("seeding_started_at"))),
            # The two preconditions that produced it, exported separately so
            # an operator can see WHICH one was the laggard: a device whose
            # sha256 of a ~1.2 GB image runs minutes after aria2 first
            # announced left=0 shows tracker_seeder_at well before
            # checksum_verified_at, and the reverse ordering means the swarm,
            # not the device, was the wait. Both are honest per-transfer
            # facts, latched once by the store and never recomputed.
            ("iris.transfer.checksum_verified_at",
             _rfc3339_millis(row.get("checksum_verified_at"))),
            # THE SAME INSTANT, UNDER THE NAME THAT SAYS WHAT IT IS. The
            # value above is the server's INGEST of the attesting report --
            # the first moment the server knew the checksum had verified --
            # not the moment the device verified it. The device reports no
            # verification instant, so nothing here back-dates a guess; the
            # inflation is instead made legible. It is not marginal: the agent
            # arms the terminal report at completion but defers the whole send
            # on a bad link, backing off to ~16 minutes, so on exactly the
            # constrained devices IRIS exists for the ingest instant can sit
            # that far behind the physical one. `checksum_verified_at` keeps
            # shipping because an exported attribute cannot be withdrawn.
            ("iris.transfer.report_received_at",
             _rfc3339_millis(row.get("checksum_verified_at"))),
            ("iris.transfer.tracker_seeder_at",
             _rfc3339_millis(row.get("tracker_seeder_at"))),
        ])
    attrs = [_attr(k, v) for k, v in pairs if v is not None]
    if seeding:
        # The DEVICE's own clocks for the attesting report, kept as float
        # epochs and named exactly as ``_build_v2_report_record`` names them,
        # so the two records answer "what did the device think the time was"
        # the same way: the end of its measurement window, and the instant it
        # composed the report. The second is the closest thing to "when the
        # device verified" that the device actually reports, and read against
        # ``iris.transfer.report_received_at`` it shows how long that report
        # spent getting here -- the whole magnitude of a plan-to-seed duration
        # inflated by delivery backoff. These are a SECOND CLOCK: the
        # difference is that latency PLUS whatever skew stands between them,
        # and neither is ever subtracted from a server instant above as though
        # it were exact. Each is absent when the report carried none.
        for key, field in (("iris.device.observed_at", "observed_at"),
                           ("iris.device.report_created_at",
                            "report_created_at")):
            value = row.get(field)
            try:
                if value is not None:
                    attrs.append(_attr(key, float(value)))
            except (TypeError, ValueError):
                pass
        if row.get("recovered_promotion") is True:
            # This record REBUILT a lost store row, so its
            # seeding_started_at is max(checksum_verified_at, planned_at) --
            # the durable pair only. The original emission under this same
            # event.id may have carried a LATER instant taken from
            # tracker_seeder_at, and no rebuild can reproduce it: the peer
            # registry is in memory. The flag is how a backend tells the
            # replay from the original instead of holding two disagreeing
            # values with nothing to attribute the difference to; it also
            # says that tracker_seeder_at on THIS record is a post-loss
            # re-announce, so recomputing max() over the three attributes
            # here will not reproduce seeding_started_at. Absent -- never
            # false -- on an ordinary promotion.
            attrs.append(_attr("iris.transfer.recovered_promotion", True))
    return _record(_LIFECYCLE_NAME, _ts_nano(at), attrs,
                   event_id="%s.%s" % (row.get("plan_id"), event),
                   body="transfer lifecycle %s" % event)


def build_tracker_record(event):
    """Tracker-lifecycle event -> ``iris.tracker.peer`` (design §10.8). OTLP
    event time = server ``received_at`` (tracker server ts). ``event.id`` = a
    random id minted once per lifecycle transition, retained only in-process
    (cross-restart loss accepted under Day-1)."""
    if not isinstance(event, dict):
        event = {}
    pairs = [
        ("otel.log.name", "iris.tracker.peer"),
        (_SCHEMA_ATTR, 2),
        ("iris.principal", _enrich_str(event.get("principal"))),
        ("iris.device.role", _enrich_str(event.get("device_role")))
            if str(event.get("principal") or "").startswith("device:")
            else ("iris.device.role", None),
        ("iris.torrent.info_hash", _enrich_str(event.get("info_hash"))),
        ("iris.peer.role", _enrich_str(event.get("role"))),
        ("network.peer.address", _enrich_str(event.get("ip"))),
    ]
    attrs = [_attr(k, v) for k, v in pairs if v is not None]
    ts = event.get("received_at")
    if ts is None:
        ts = event.get("ts")
    return _record("iris.tracker.peer", _ts_nano(ts), attrs,
                   event_id=event.get("event_id"), body="tracker peer event")


def build_peer_rate_record(row):
    """Measured origin -> peer send rate -> ``iris.swarm.peer_rate``.

    The rate is what aria2 actually measured for this connection; no per-peer
    cumulative byte total is derived from it (that machinery is retired). This
    is a LOG record, not a metric, so peer- and device-labelled history does not
    multiply metric cardinality.
    """
    if not isinstance(row, dict):
        row = {}
    pairs = [
        ("otel.log.name", "iris.swarm.peer_rate"),
        (_SCHEMA_ATTR, 2),
        ("iris.principal", _enrich_str(row.get("principal"))),
        ("iris.device.role", _enrich_str(row.get("device_role")))
            if str(row.get("principal") or "").startswith("device:")
            else ("iris.device.role", None),
        ("iris.torrent.info_hash", _enrich_str(row.get("info_hash"))),
        ("iris.image.id", _enrich_str(row.get("image_id"))),
        ("network.peer.address", _enrich_str(row.get("ip"))),
        ("network.peer.port", _enrich_int(row.get("port"))),
        ("iris.transfer.peer_send_bps", _enrich_int(row.get("send_bps"))),
        ("iris.torrent.left", _enrich_int(row.get("left"))),
        ("iris.peer.role", _enrich_str(row.get("role"))),
    ]
    attrs = [_attr(k, v) for k, v in pairs if v is not None]
    return _record("iris.swarm.peer_rate", _ts_nano(row.get("ts")), attrs,
                   event_id=row.get("event_id"), body="measured peer rate")


def build_peer_bytes_record(row):
    """Durably attributed origin -> peer bytes -> ``iris.swarm.peer_bytes``.

    One record per edge that gained bytes since the previous sample, built
    from ``peer_ledger.PeerLedger.observe`` rows. Unlike ``peer_rate`` (an
    instantaneous reading that is worthless once the sample passes), the
    cumulative value here is the ledger's accumulated total: aria2's per-peer
    counter is per CONNECTION and disappears with the connection, so what is
    exported is what was banked as it was observed, never a scrape-time read.

    A LOG record, not a metric, for the reason at metrics.py:14-18 — per-peer
    and per-device labels belong in the logs pipeline. The aggregate
    counterparts (origin total, attributed sum, and the honest unattributed
    residue) are the Prometheus series.

    Both byte attributes are int64 and therefore ride the OTLP/JSON wire as
    STRINGS (see ``_any_value``); a backend query that sums them must coerce.
    """
    if not isinstance(row, dict):
        row = {}
    pairs = [
        ("otel.log.name", "iris.swarm.peer_bytes"),
        (_SCHEMA_ATTR, 2),
        ("iris.torrent.info_hash", _enrich_str(row.get("info_hash"))),
        ("iris.image.id", _enrich_str(row.get("image_id"))),
        ("network.peer.address", _enrich_str(row.get("ip"))),
        ("iris.device.id", _enrich_str(row.get("device_id"))),
        ("iris.device.role", _enrich_str(row.get("device_role")))
            if row.get("device_id") else ("iris.device.role", None),
        ("iris.transfer.peer_sent_bytes",
         _enrich_int(row.get("peer_sent_bytes"))),
        ("iris.transfer.peer_sent_delta_bytes",
         _enrich_int(row.get("peer_sent_delta_bytes"))),
        ("iris.peer.role", _enrich_str(row.get("role"))),
    ]
    attrs = [_attr(k, v) for k, v in pairs if v is not None]
    return _record("iris.swarm.peer_bytes", _ts_nano(row.get("ts")), attrs,
                   event_id=row.get("event_id"), body="attributed peer bytes")


def build_peer_transfer_record(row):
    """Device-MEASURED per-peer received bytes -> ``iris.device.peer_transfer_record``.

    One record per row of a v2 report's ``peer_transfer_records`` block. The value is
    aria2-next's own cumulative per-peer session counter
    (``peer->getSessionDownloadLength()``), read ONCE by the
    ``--on-bt-download-complete`` hook at the instant the last piece landed and
    before ``enableSeedOnly()`` — the client's own tally, not a rate integrated
    over samples.

    Deliberately a DIFFERENT log name from ``iris.swarm.peer_bytes``, which
    carries the origin-side SAMPLED estimate of the same bytes and is measured
    to lose 26.7% (3s) / 11.9% (2s) of the origin's real ``uploadLength``.
    Summing the two names together counts one transfer twice, once exactly and
    once badly; a query picks one, and this is the exact one.

    ``iris.peer.attribution`` is what keeps the record honest. A transfer-record row is
    bytes from A PEER — not evidence that the bytes came from a peer DEVICE.
    The origin seeder is an ordinary peer of every device, so its bytes sit in
    this list like any other peer's, and only the server can tell them apart
    (it holds the ``service:seeder`` principal and the device address map). The
    split therefore rides as ``origin`` | ``device`` | ``unknown``, and a row
    the server did not resolve stays ``unknown`` rather than being folded into
    ``device``. ``unknown`` is a normal outcome (a peer that has not
    heartbeated, a NAT address, a non-IRIS seeder), not an error — the bytes
    are still exported, the peer is just not named.

    ``iris.peer.has_complete_file`` is aria2's ``seeder`` flag and does NOT
    identify the origin: ``RpcMethodImpl.cc:1166`` reports it for any peer
    holding the complete file, which in a 7-router wave is every device that
    finished early. It answers "complete vs partial", a different question, and
    is named for the answer it gives.

    Absence of a record is NOT zero: a device that reported no transfer records emits
    nothing here, while a measured zero appears as an explicit 0. Both byte
    attributes are int64 and so ride the OTLP/JSON wire as STRINGS (see
    ``_any_value``); a backend that sums them must coerce.
    """
    if not isinstance(row, dict):
        row = {}
    attribution = _peer_attribution(row.get("peer_attribution"))
    peer_device_id = _enrich_str(row.get("peer_device_id"))
    pairs = [
        ("otel.log.name", "iris.device.peer_transfer_record"),
        (_SCHEMA_ATTR, 2),
        # The RECEIVING device -- the one that measured these bytes.
        ("device.id", _enrich_str(row.get("device_id"))),
        ("iris.image.id", _enrich_str(row.get("image_id"))),
        # The catalog filename behind the id, looked up at export time.
        # Presentation, not identity: an image that has left the catalog by
        # then has an id and no name, and the id is still the join key.
        ("iris.image.name", _enrich_str(row.get("image_name"))),
        ("iris.transfer.id", _enrich_str(row.get("transfer_id"))),
        ("network.peer.address", _enrich_str(row.get("ip"))),
        ("network.peer.port", _enrich_int(row.get("port"))),
        # Omitted when the join did not resolve; the attribution still says so.
        ("iris.peer.device.id", peer_device_id),
        ("iris.peer.attribution", attribution),
        # The SENDER in one column: the device id for a device row, ``origin``
        # for the seeder's row, absent for an unknown. ``iris.peer.device.id``
        # stays as it was (device rows only); this is the column a per-source
        # table groups by without a coalesce over attribution.
        ("iris.peer.device_id", _peer_source_id(attribution, peer_device_id)),
        ("iris.peer.has_complete_file", row.get("has_complete_file")),
        ("iris.transfer.session_bytes_from_peer",
         _enrich_int(row.get("session_bytes_from_peer"))),
        ("iris.transfer.session_bytes_to_peer",
         _enrich_int(row.get("session_bytes_to_peer"))),
        ("iris.transfer_record.source", _enrich_str(row.get("source"))),
        # About the CAPTURE, not this row: False means a peer disconnected
        # before the snapshot, so the block is a floor. The row itself is exact
        # either way.
        ("iris.transfer_record.capture_complete", row.get("capture_complete")),
    ]
    attrs = [_attr(k, v) for k, v in pairs if v is not None]
    return _record("iris.device.peer_transfer_record",
                   _ts_nano(row.get("captured_at")), attrs,
                   event_id=row.get("event_id"), body="device peer transfer record")


def build_peer_transfer_records(report, device_id=None, enrich=None,
                               classify=None):
    """Fan a stored report's ``peer_transfer_records`` block out into one
    ``iris.device.peer_transfer_record`` record per row, so the exact measurement
    reaches a collector instead of stopping in the catalog.

    Returns [] for any report without a transfer-record block. The sanitizer never
    synthesizes an empty block, so "no block" means NOT MEASURED and an empty
    list is how that stays distinguishable from a measured zero.

    ``classify(ip) -> "origin"|"device"|"unknown"`` supplies the sender class;
    pass ``telemetry.transfer_record_source_class`` bound to the current origin
    addresses and swarm-IP join. Without it every row goes out ``unknown``:
    this module does not re-implement that identity rule, because a second copy
    of it drifts and the copy that drifts is the one an operator reads a peer
    share off. ``enrich["peer_devices"]`` names the device behind an address,
    and the name is attached only where the class already says ``device`` --
    naming a peer we did not classify would assert the join twice over.
    ``enrich["image_name"]`` is the catalog filename for the report's image
    (``iris.image.name``), presentation only.

    Event time is the hook's own ``captured_at`` (the instant the counters were
    read), not the server's ingest time minutes later on the next EEM tick.
    ``event.id`` joins the report id to the peer address: stable across a retry
    of the same report (design §10.8 requires ids to survive retry) and unique
    per row within it.
    """
    if not isinstance(report, dict):
        return []
    block = report.get("peer_transfer_records")
    if not isinstance(block, dict):
        return []
    rows = block.get("rows")
    if not isinstance(rows, list):
        return []
    peer_devices = {}
    if isinstance(enrich, dict) and isinstance(enrich.get("peer_devices"),
                                               dict):
        peer_devices = enrich["peer_devices"]
    report_id = report.get("report_id")
    records = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ip = row.get("ip")
        ctx = dict(row)
        ctx["device_id"] = device_id
        ctx["image_id"] = report.get("image_id")
        ctx["transfer_id"] = report.get("transfer_id")
        ctx["source"] = block.get("source")
        ctx["captured_at"] = block.get("captured_at")
        ctx["capture_complete"] = block.get("complete")
        # The catalog filename for the report's image, resolved by the caller
        # (telemetry._image_names); None when the image is not in the catalog.
        ctx["image_name"] = enrich.get("image_name") \
            if isinstance(enrich, dict) else None
        if classify is not None:
            try:
                ctx["peer_attribution"] = classify(ip)
            except Exception:
                # Telemetry is never on the critical path, and a join that
                # raised has told us nothing -- which is exactly "unknown".
                ctx["peer_attribution"] = "unknown"
        ctx["peer_device_id"] = peer_devices.get(str(ip)) \
            if _peer_attribution(ctx.get("peer_attribution")) == "device" \
            else None
        if report_id is not None and ip is not None:
            ctx["event_id"] = "%s:%s" % (report_id, ip)
        records.append(build_peer_transfer_record(ctx))
    return records


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
    if headers and urlsplit(url).scheme.lower() != "https":
        # Collector credentials must never cross a plaintext hop. Anonymous
        # OTLP/HTTP remains compatible for isolated deployments.
        raise RuntimeError("authenticated OTLP requires HTTPS")
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
      * ``emit`` appends FIFO; when the queue is full the OLDEST EVICTABLE
        event is dropped BEFORE the append (bounded best-effort, Day-1
        in-process), and ``dropped_total`` is incremented per drop. FIFO
        order of the kept events is preserved. ``emit(event, evictable=True)``
        marks a SAMPLED record (the per-connection ``iris.swarm.peer_rate`` /
        ``peer_bytes`` stream, which the hub queues on every 2 s seeder pass
        and which the durable ledger already holds): those are evicted first,
        so a burst of them can never push a tracker peer lifecycle event, a
        policy operation, a device report or its exact per-peer fan-out out
        of the queue. Only when nothing evictable is queued is the oldest
        durable-intent event dropped.
      * ``flush(send)`` hands a snapshot batch to ``send`` and removes those
        events from the queue ONLY after ``send`` returns without raising.
        On failure the batch remains in place. Concurrent emits remain
        non-blocking; if they fill the bounded queue, drop-oldest may discard
        events from the in-flight prefix as well as any other oldest event.
        Concurrent flushes are serialized, preserving delivery order.
      * ``flush`` returns None on an empty queue (no attempt), else the count
        of events confirmed delivered (0 on a failed send)."""

    def __init__(self, max_queue=1000, event_key=None,
                 delivered_callback=None):
        self._queue = collections.deque()
        self._max = max(0, int(max_queue))
        self._dropped = 0
        self._lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._next_id = 0
        self._event_key = event_key
        self._keys = set()
        self._inflight_ids = set()
        self._inflight_keys = set()
        self._delivered_callback = delivered_callback

    def _key(self, event):
        if self._event_key is None:
            return None
        try:
            return self._event_key(event)
        except Exception:
            return None

    def contains(self, key):
        with self._lock:
            return key in self._keys or key in self._inflight_keys

    def configure_dedupe(self, event_key, delivered_callback=None):
        """Enable key dedupe before producers begin emitting."""
        with self._lock:
            self._event_key = event_key
            self._delivered_callback = delivered_callback
            self._queue = collections.deque(
                (event_id, event, self._key(event), evictable)
                for event_id, event, _, evictable in self._queue)
            self._keys = {key for _, _, key, _ in self._queue}
            self._keys.discard(None)

    def _evict_one(self):
        """Drop one queued event to make room: the oldest evictable
        (sampled) one if any, else the oldest event. Caller holds the lock."""
        victim = None
        for index, (_, _, _, evictable) in enumerate(self._queue):
            if evictable:
                victim = index
                break
        if victim is None:
            _, _, dropped_key, _ = self._queue.popleft()
        else:
            _, _, dropped_key, _ = self._queue[victim]
            del self._queue[victim]
        if dropped_key is not None:
            self._keys.discard(dropped_key)
        self._dropped += 1

    def emit(self, event, evictable=False):
        with self._lock:
            key = self._key(event)
            if key is not None and (key in self._keys or
                                    key in self._inflight_keys):
                return False
            if self._max == 0:
                self._dropped += 1
                return False
            while len(self._queue) >= self._max:
                self._evict_one()
            self._queue.append((self._next_id, event, key, bool(evictable)))
            if key is not None:
                self._keys.add(key)
            self._next_id += 1
            return True

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
            return [event for _, event, _, _ in self._queue]

    def flush(self, send):
        """Deliver the current FIFO prefix via ``send(batch)`` (which must
        raise on failure). The snapshot stays logically queued during the
        network call, so emits never wait for transport and capacity remains
        enforced. Returns None (empty), the delivered count, or 0 (failure)."""
        with self._flush_lock:
            with self._lock:
                queued_batch = list(self._queue)
                self._inflight_ids = {event_id
                                      for event_id, _, _, _ in queued_batch}
                self._inflight_keys = {key for _, _, key, _ in queued_batch
                                       if key is not None}
            if not queued_batch:
                return None
            batch = [event for _, event, _, _ in queued_batch]
            try:
                send(batch)
            except Exception:
                with self._lock:
                    self._inflight_ids.clear()
                    self._inflight_keys.clear()
                return 0
            sent_ids = {event_id for event_id, _, _, _ in queued_batch}
            sent_keys = {key for _, _, key, _ in queued_batch
                         if key is not None}
            with self._lock:
                retained_sent_ids = {event_id
                                     for event_id, _, _, _ in self._queue
                                     if event_id in sent_ids}
                # Overflow may have dropped part of this in-flight prefix
                # (evictable records anywhere in it, or the oldest). Remove
                # every still-retained sent event; later concurrent emits have
                # distinct IDs and stay queued in order.
                self._queue = collections.deque(
                    item for item in self._queue if item[0] not in sent_ids)
                for _, _, key, _ in queued_batch:
                    if key is not None:
                        self._keys.discard(key)
                # Events evicted while this successful send was in flight were
                # delivered, not lost. Undo only those provisional drop counts.
                self._dropped -= len(sent_ids - retained_sent_ids)
                self._inflight_ids.clear()
                self._inflight_keys.clear()
            if self._delivered_callback is not None and sent_keys:
                try:
                    self._delivered_callback(sent_keys)
                except Exception:
                    pass
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
