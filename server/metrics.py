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


def render(swarm, seeder, counters, reports_stored=0, transfers=None,
           extras=None, otlp_health=None, peer_status=None,
           seeder_torrents=None):
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

    # --- device telemetry reports (issue #13) ---
    family("iris_device_reports_stored", "gauge",
           "Device telemetry reports currently stored across all devices "
           "(ring-bounded server-side; no per-device labels)")
    out.append("iris_device_reports_stored %d" % _int(reports_stored))

    # --- seeder (from aria2 RPC) ---
    family("iris_seeder_rpc_up", "gauge",
           "1 if the most recent aria2 RPC poll succeeded")
    out.append("iris_seeder_rpc_up %d" % (1 if seeder.get("rpc_up") else 0))
    for name, key, help_text in _SEEDER_GAUGES:
        family(name, "gauge", help_text)
        out.append("%s %d" % (name, _int(seeder.get(key))))
    if seeder_torrents:
        family("iris_seeder_torrent_upload_length_bytes", "gauge",
               "Seeder torrent control-state upload length (bytes)")
        for torrent in seeder_torrents:
            out.append("iris_seeder_torrent_upload_length_bytes%s %d" % (
                _labels(torrent["image"], torrent["info_hash"]),
                _int(torrent.get("upload_length"))))

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
               "Current legacy_unattributed announce participants (0 = fully "
               "migrated)")
        out.append("iris_legacy_announce_participants %d"
                   % _int(extras.get("legacy_announce_participants")))
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
