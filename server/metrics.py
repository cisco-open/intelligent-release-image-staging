# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Render IRIS telemetry as Prometheus text exposition (stdlib only).

`render(swarm, seeder, counters, reports_stored=0)` is a pure function:
  swarm    -- list of per-image dicts: info_hash, image, seeders, leechers,
              peers, bytes_remaining, completed
  seeder   -- dict: upload_speed, download_speed, active_torrents,
              connections, rpc_up (bool)
  counters -- dict: announces_total
  reports_stored -- int: device telemetry reports currently stored
              across ALL devices (flat gauge; no per-device labels)
  swarm_bytes -- peer-ledger byte attribution, either the ledger's
              `torrent_totals()` mapping or a list of equivalent rows

Aggregate metrics are labelled by image only (info_hash + image name) to keep
Prometheus cardinality low; per-device detail goes to the OTLP logs pipeline,
not here."""


def _esc(value):
    """Escape a label value per the exposition format (backslash, quote, NL)."""
    return (str(value).replace("\\", "\\\\")
            .replace('"', '\\"').replace("\n", "\\n"))


def _labels(image, info_hash):
    return '{image="%s",info_hash="%s"}' % (_esc(image), _esc(info_hash))


def _int(value):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


# (metric name, source key, HELP) for the flat seeder gauges
_SEEDER_GAUGES = (
    ("iris_seeder_upload_bytes_per_second", "upload_speed",
     "Seeder aggregate upload rate (bytes/sec)"),
    ("iris_seeder_download_bytes_per_second", "download_speed",
     "Seeder aggregate download rate (bytes/sec)"),
    ("iris_seeder_active_torrents", "active_torrents",
     "Number of torrents the seeder is actively serving"),
    ("iris_seeder_queued_torrents", "queued_torrents",
     "Published torrents the seeder is NOT serving, held behind its "
     "concurrency cap (non-zero starves any device assigned that image)"),
    ("iris_seeder_connections", "connections",
     "Total peer connections across the seeder's active torrents"),
)

# (metric name, swarm-dict key, HELP) for the per-image swarm gauges
_SWARM_GAUGES = (
    ("iris_swarm_seeders", "seeders", "Seeders (left==0) per image"),
    ("iris_swarm_leechers", "leechers", "Leechers (left!=0) per image"),
    ("iris_swarm_peers", "peers", "Total peers in the swarm per image"),
    ("iris_swarm_bytes_remaining", "bytes_remaining",
     "Sum of bytes left to download across leechers per image"),
)


def _ledger_rows(swarm_bytes):
    """Normalise the peer ledger's `torrent_totals()` mapping into rows.

    A list is accepted too, so a caller that has already inner-joined the
    image catalog (as `_seeder_torrent_metrics` does) can pass its own rows.
    The catalog join is the caller's, not ours: this module never learns what
    an image id means, it only prints the label it is handed."""
    if isinstance(swarm_bytes, dict):
        return [dict(rec, info_hash=info_hash)
                for info_hash, rec in sorted(swarm_bytes.items())
                if isinstance(rec, dict)]
    return [row for row in swarm_bytes if isinstance(row, dict)]


# (Prometheus family, type, TransferLifecycle.stats() key, HELP) for the
# durable plan store. Flat and unlabelled on purpose: plan/device/image ids
# are high-cardinality and live in the OTLP logs pipeline, not here.
_LIFECYCLE_FAMILIES = (
    ("iris_transfer_lifecycle_plans", "gauge", "plans",
     "Plan rows currently held in the durable transfer-lifecycle store"),
    ("iris_transfer_lifecycle_plan_cap", "gauge", "plan_cap",
     "Hard row cap of the transfer-lifecycle store (MAX_PLANS)"),
    ("iris_transfer_lifecycle_awaiting_report", "gauge",
     "plans_awaiting_report",
     "Plans this tracker has watched seed for which no terminal report "
     "bearing that plan's transfer_id has arrived (0 = every seeding device "
     "is reporting)"),
    ("iris_transfer_lifecycle_unconfirmed", "gauge", "plans_unconfirmed",
     "Lifecycle events queued for export but never acknowledged by a send "
     "(a steady non-zero value is a collector problem, not a fleet one)"),
    ("iris_transfer_lifecycle_dropped_unemitted_total", "counter",
     "plans_dropped_unemitted",
     "Plan rows evicted by the size bound while still owing an event that "
     "had never reached the export queue"),
    ("iris_transfer_lifecycle_live_evicted_total", "counter",
     "plans_live_evicted",
     "Rows of STILL-ASSIGNED plans evicted because the live set alone "
     "exceeds the cap (non-zero means MAX_PLANS is too small for this fleet)"),
    ("iris_transfer_lifecycle_retired_undelivered_total", "counter",
     "events_retired_undelivered",
     "Lifecycle events lost: queued, never acknowledged, and their row "
     "retired by retention or the size bound before an acknowledgement came"),
    ("iris_transfer_lifecycle_promoted_recovered_total", "counter",
     "plans_promoted_recovered",
     "Promotions that rebuilt a lost store row and therefore replayed the "
     "durable instant rather than the tracker's own seeder observation"),
)


def render(swarm, seeder, counters, reports_stored=0, transfers=None,
           extras=None, otlp_health=None, peer_status=None,
           seeder_torrents=None, swarm_bytes=None, image_sizes=None,
           lifecycle=None, instruction_status=None):
    out = []

    def family(name, mtype, help_text):
        out.append("# HELP %s %s" % (name, help_text))
        out.append("# TYPE %s %s" % (name, mtype))

    # --- tracker meta ---
    family("iris_tracker_up", "gauge",
           "1 while the tracker telemetry surface is serving")
    out.append("iris_tracker_up 1")
    family("iris_tracker_announces_total", "counter",
           "Total /announce requests handled since start")
    out.append("iris_tracker_announces_total %d"
               % _int(counters.get("announces_total", 0)))
    family("iris_tracker_announces_refused_total", "counter",
           "Total /announce or /scrape requests refused for a missing, "
           "invalid, ambiguous, revoked or expired credential since start "
           "(IRIS-111) -- nonzero here means iris_legacy_announce_participants "
           "reading 0 is not on its own evidence of a fully migrated fleet")
    out.append("iris_tracker_announces_refused_total %d"
               % _int(counters.get("announces_refused_total", 0)))
    family("iris_tracker_announces_refused_expired_total", "counter",
           "Subset of iris_tracker_announces_refused_total refused because "
           "the presented credential was a KNOWN, non-revoked record that "
           "simply timed out -- the SEEDER_PREV_TTL overlap-window case: a "
           "device still on a rotated-out seeder token that missed the "
           "personalisation window")
    out.append("iris_tracker_announces_refused_expired_total %d"
               % _int(counters.get("announces_refused_expired_total", 0)))
    family("iris_device_reports_stored", "gauge",
           "Device telemetry reports currently stored across all devices "
           "(ring-bounded server-side; no per-device labels)")
    out.append("iris_device_reports_stored %d" % _int(reports_stored))

    # --- catalog image sizes ---
    # The catalog entry's own size field, republished so a board can price
    # per-image figures without a hardcoded constant. Both dashboards ship
    # panels that deliberately read "no data" until this family exists --
    # pricing a fleet total at a fixed 928 MiB is wrong the moment a
    # differently sized image is selected. Emitted only for images whose size
    # and info_hash are both known: a partial row would be a guess.
    if image_sizes:
        family("iris_image_size_bytes", "gauge",
               "Size of the published image in bytes, from the catalog entry "
               "(exact: recorded at publish time from the file itself)")
        for row in image_sizes:
            out.append("iris_image_size_bytes%s %d" % (
                _labels(row["image"], row["info_hash"]), _int(row["size"])))

    # --- seeder (from aria2 RPC) ---
    family("iris_seeder_rpc_up", "gauge",
           "1 if the most recent aria2 RPC poll succeeded")
    out.append("iris_seeder_rpc_up %d" % (1 if seeder.get("rpc_up") else 0))
    for name, key, help_text in _SEEDER_GAUGES:
        if seeder.get("rpc_up") and key in seeder:
            family(name, "gauge", help_text)
            out.append("%s %d" % (name, _int(seeder[key])))
    if seeder_torrents:
        family("iris_seeder_torrent_upload_length_bytes", "gauge",
               "Seeder torrent control-state upload length (bytes)")
        for torrent in seeder_torrents:
            out.append("iris_seeder_torrent_upload_length_bytes%s %d" % (
                _labels(torrent["image"], torrent["info_hash"]),
                _int(torrent.get("upload_length"))))
        family("iris_seeder_torrent_upload_bytes_per_second", "gauge",
               "Origin seeder send rate per torrent, measured (lower bound: "
               "device-to-device reseed traffic is not counted)")
        for torrent in seeder_torrents:
            out.append("iris_seeder_torrent_upload_bytes_per_second%s %d" % (
                _labels(torrent["image"], torrent["info_hash"]),
                _int(torrent.get("upload_bps"))))

    # --- swarm (per image) ---
    for name, key, help_text in _SWARM_GAUGES:
        family(name, "gauge", help_text)
        for s in swarm:
            out.append("%s%s %d" % (name, _labels(s["image"], s["info_hash"]),
                                    _int(s[key])))
    family("iris_swarm_completed_total", "counter",
           "Cumulative completed downloads per image")
    for s in swarm:
        out.append("iris_swarm_completed_total%s %d"
                   % (_labels(s["image"], s["info_hash"]),
                      _int(s["completed"])))

    # --- swarm byte attribution (peer ledger) ---
    # AGGREGATE ONLY. The edges these numbers are summed from are keyed by peer
    # IP, and a peer IP is a per-device label: it belongs in the OTLP logs
    # pipeline (iris.swarm.peer_bytes), never in a Prometheus label. What
    # survives the aggregation is how much the origin sent (exact), how much
    # of that we could trace to a specific device, and how much went out to a
    # recipient we could not name.
    #
    # Counters, not gauges, because the operator requirement is that a finished
    # transfer keeps its history: a swarm that goes idle stops advancing these
    # series, it does not blank the panel drawing them.
    if swarm_bytes is not None:
        rows = _ledger_rows(swarm_bytes)

        def _row_labels(row):
            return _labels(row.get("image") or row.get("image_id") or "",
                           row.get("info_hash", ""))

        family("iris_origin_sent_bytes_total", "counter",
               "Bytes the origin seeder has sent for this torrent: the exact "
               "total, counted at the sender (monotonic: aria2's gauge is "
               "banked on control-state loss)")
        for row in rows:
            out.append("iris_origin_sent_bytes_total%s %d"
                       % (_row_labels(row), _int(row.get("origin_total"))))
        family("iris_peer_attributed_bytes_total", "counter",
               "Origin bytes we could trace to a specific device, summed "
               "over devices. Traced from aria2's per-connection counters, "
               "which we can only read while the connection is open")
        for row in rows:
            out.append("iris_peer_attributed_bytes_total%s %d"
                       % (_row_labels(row), _int(row.get("attributed"))))
        # A GAUGE, not a counter, though the name keeps its historical
        # _total suffix for dashboard compatibility: the residue is the
        # difference of two counters and steps DOWN whenever a device is
        # traced late. Declared as a counter, Prometheus rate()/increase()
        # and any cumulative-to-delta pipeline read each step-down as a reset
        # and invent a burst of untraced bytes exactly when tracing improved.
        family("iris_peer_unattributed_bytes_total", "gauge",
               "Origin bytes whose recipient we could not identify: the "
               "connection opened and closed between two samples, or the peer "
               "was refused at the ledger's cap. The bytes did leave the "
               "origin; only the recipient is unknown. Difference of two "
               "counters, so tracing a device late can step it down -- a "
               "gauge: graph the value, never rate()")
        for row in rows:
            # Prefer the ledger's own residue; a hand-built row that omits it
            # still gets the honest difference rather than a silent zero.
            residue = row.get("unattributed")
            if residue is None:
                residue = _int(row.get("origin_total")) \
                    - _int(row.get("attributed"))
            # Floored here as well as in the ledger: the exposition must never
            # print a negative byte count, whoever assembled the row.
            out.append("iris_peer_unattributed_bytes_total%s %d"
                       % (_row_labels(row), max(0, _int(residue))))
        family("iris_swarm_peers_attributed", "gauge",
               "Distinct devices we could trace a nonzero byte total to for "
               "this torrent")
        for row in rows:
            out.append("iris_swarm_peers_attributed%s %d"
                       % (_row_labels(row), _int(row.get("peers_attributed"))))
        # Without this the residue is unreadable: it cannot be told apart from
        # missed short-lived connections once the cap starts refusing peers.
        family("iris_swarm_peers_saturated", "gauge",
               "1 when the ledger's per-torrent peer cap refused new peers, "
               "so some untraced bytes went to peers the cap turned away "
               "rather than to connections that ended between samples")
        for row in rows:
            out.append("iris_swarm_peers_saturated%s %d"
                       % (_row_labels(row), 1 if row.get("saturated") else 0))

    # --- live transfer streaming (canonical low-cardinality families,
    #     design §10.9). Ambiguous "active"/"stalled" and the old
    #     down/up_bps_sum / tier families are RETIRED. Business gauges
    #     (throughput, progress) are OMITTED for a STALE image; the freshness
    #     age is always reported so the omission is explainable. No
    #     device/peer/report labels ever appear here (they live in OTLP logs).
    if transfers is not None:
        family("iris_transfer_devices", "gauge",
               "Fresh streaming devices per image")
        for row in transfers:
            out.append("iris_transfer_devices%s %d" % (
                _labels(row["image"], row["info_hash"]),
                _int(row.get("devices"))))
        family("iris_transfer_throughput_bytes_per_second", "gauge",
               "Aggregate transfer rate per image (bytes/sec); omitted when "
               "stale")
        for row in transfers:
            if row.get("stale"):
                continue
            for direction, key in (("receive", "receive_bps"),
                                   ("transmit", "transmit_bps")):
                out.append(
                    'iris_transfer_throughput_bytes_per_second'
                    '{image="%s",info_hash="%s",direction="%s"} %d'
                    % (_esc(row["image"]), _esc(row["info_hash"]), direction,
                       _int(row.get(key))))
        family("iris_transfer_progress_ratio", "gauge",
               "Fleet progress per image (0..1); omitted when stale")
        for row in transfers:
            if row.get("stale"):
                continue
            out.append("iris_transfer_progress_ratio%s %.4g" % (
                _labels(row["image"], row["info_hash"]),
                float(row.get("progress_ratio") or 0.0)))
        family("iris_transfer_zero_receive_devices", "gauge",
               "Devices with a fresh zero receive rate per image (never from "
               "stale)")
        for row in transfers:
            out.append("iris_transfer_zero_receive_devices%s %d" % (
                _labels(row["image"], row["info_hash"]),
                0 if row.get("stale") else _int(row.get("zero_receive_devices"))))
        family("iris_transfer_freshness_age_seconds", "gauge",
               "Age of the newest valid observation per image (seconds)")
        for row in transfers:
            out.append("iris_transfer_freshness_age_seconds%s %d" % (
                _labels(row["image"], row["info_hash"]),
                _int(row.get("freshness_age_seconds"))))
        family("iris_stream_devices", "gauge",
               "Streaming devices per image by sampling class")
        for row in transfers:
            for sc in ("good", "constrained"):
                out.append(
                    'iris_stream_devices{image="%s",info_hash="%s",'
                    'sampling_class="%s"} %d'
                    % (_esc(row["image"]), _esc(row["info_hash"]), sc,
                       _int(row.get("sampling_class_%s" % sc))))
    if extras is not None:
        family("iris_telemetry_samples_rejected_total", "counter",
               "Live samples rejected at ingest (catalog-originated)")
        out.append("iris_telemetry_samples_rejected_total %d"
                   % _int(extras.get("samples_rejected_total")))
        family("iris_legacy_announce_participants", "gauge",
               "Current legacy_unattributed announce participants. A "
               "credential must still authenticate to be counted here, so "
               "0 means EITHER fully migrated OR every un-migrated device "
               "has aged past SEEDER_PREV_TTL and can no longer announce at "
               "all -- cross-check "
               "iris_tracker_announces_refused_expired_total (nonzero there "
               "means the latter)")
        out.append("iris_legacy_announce_participants %d"
                   % _int(extras.get("legacy_announce_participants")))
    if lifecycle is not None:
        # Omitted entirely when the store is absent or unreadable: a missing
        # store is not a store with nothing in it, and a zero here would read
        # as "the bound never bit".
        for name, mtype, key, help_text in _LIFECYCLE_FAMILIES:
            val = lifecycle.get(key)
            if val is None:
                continue
            family(name, mtype, help_text)
            out.append("%s %d" % (name, _int(val)))
    if peer_status is not None:
        for name, key, help_text in (
            ("iris_peer_policy_revision", "policy_revision",
             "Current committed peer-policy revision"),
            ("iris_peer_enforcement_applied_revision", "applied_revision",
             "aria-returned applied enforcement revision"),
            ("iris_peer_enforcement_desired_ips", "desired_ip_count",
             "Count of addresses in the derived denied set (no per-IP labels)"),
            ("iris_peer_enforcement_health", "health",
             "Numeric enforcement health: 1=enforced 0=pending -1=degraded "
             "-2=rpc_unavailable"),
        ):
            val = peer_status.get(key)
            if val is None:
                continue
            family(name, "gauge", help_text)
            out.append("%s %d" % (name, _int(val)))
    if isinstance(instruction_status, dict):
        for name, key, help_text in (
            ("iris_instruction_certificate_days_to_expiry",
             "certificate_days_to_expiry",
             "Days until the online instruction-signing certificate expires"),
            ("iris_instruction_keylist_age_days", "keylist_age_days",
             "Age in days of the installed root-signed instruction KRL"),
            ("iris_instruction_roots_attested_180d",
             "roots_attested_180d",
             "Configured offline roots independently attested in 180 days"),
        ):
            val = instruction_status.get(key)
            if not isinstance(val, int) or isinstance(val, bool):
                continue
            family(name, "gauge", help_text)
            out.append("%s %d" % (name, val))
        overdue = {"ok": 0, "warn": 1, "critical": 2}.get(
            instruction_status.get("root_ceremony_overdue"))
        if overdue is not None:
            family("iris_instruction_root_ceremony_overdue", "gauge",
                   "Root ceremony state: 0=ok 1=warn 2=critical")
            out.append("iris_instruction_root_ceremony_overdue %d" % overdue)
        degraded = instruction_status.get("root_quorum_degraded")
        if isinstance(degraded, bool):
            family("iris_instruction_root_quorum_degraded", "gauge",
                   "1 when fewer than two roots attested in 180 days")
            out.append("iris_instruction_root_quorum_degraded %d"
                       % (1 if degraded else 0))
    if otlp_health is not None:
        # Per-signal export failures / drops (design §10.9/§10.10): the
        # `signal` label separates logs from metrics; counters are monotonic
        # over the process lifetime. Last-success is a per-signal gauge.
        signals = otlp_health.get("signals") \
            if isinstance(otlp_health, dict) else None
        signals = signals if isinstance(signals, dict) else {}
        family("iris_telemetry_export_failures_total", "counter",
               "Failed OTLP export attempts per signal since start")
        for signal in sorted(signals):
            out.append(
                'iris_telemetry_export_failures_total{signal="%s"} %d'
                % (_esc(signal),
                   _int(signals[signal].get("failures_total"))))
        family("iris_telemetry_export_dropped_total", "counter",
               "Bounded-retry queue overflow drops per signal since start")
        for signal in sorted(signals):
            out.append(
                'iris_telemetry_export_dropped_total{signal="%s"} %d'
                % (_esc(signal),
                   _int(signals[signal].get("dropped_total"))))
        family("iris_telemetry_export_last_success_seconds", "gauge",
               "Epoch seconds of the last successful export per signal "
               "(0 = never)")
        for signal in sorted(signals):
            out.append(
                'iris_telemetry_export_last_success_seconds{signal="%s"} %d'
                % (_esc(signal),
                   _int(signals[signal].get("last_success_ts"))))

    return "\n".join(out) + "\n"
