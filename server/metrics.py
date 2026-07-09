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
Prometheus cardinality low; per-device detail goes to Loki, not here."""


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


def render(swarm, seeder, counters, reports_stored=0):
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

    return "\n".join(out) + "\n"
