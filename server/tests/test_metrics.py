# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import metrics


def _swarm():
    return [{"info_hash": "abc", "image": "cat9k.bin", "seeders": 2,
             "leechers": 3, "peers": 5, "bytes_remaining": 1024,
             "completed": 7}]


def test_render_emits_tracker_up_gauge_with_help_and_type():
    out = metrics.render([], {}, {})
    assert "# HELP iris_tracker_up" in out
    assert "# TYPE iris_tracker_up gauge" in out
    assert "iris_tracker_up 1" in out


def test_render_swarm_gauges_with_labels():
    out = metrics.render(_swarm(), {}, {})
    assert 'iris_swarm_seeders{image="cat9k.bin",info_hash="abc"} 2' in out
    assert 'iris_swarm_leechers{image="cat9k.bin",info_hash="abc"} 3' in out
    assert 'iris_swarm_peers{image="cat9k.bin",info_hash="abc"} 5' in out
    assert ('iris_swarm_bytes_remaining{image="cat9k.bin",info_hash="abc"} '
            '1024' in out)


def test_render_completed_is_a_counter():
    out = metrics.render(_swarm(), {}, {})
    assert "# TYPE iris_swarm_completed_total counter" in out
    assert ('iris_swarm_completed_total{image="cat9k.bin",info_hash="abc"} 7'
            in out)


def test_render_seeder_stats():
    seeder = {"upload_speed": 1000, "download_speed": 0, "active_torrents": 1,
              "connections": 4, "rpc_up": True}
    out = metrics.render([], seeder, {})
    assert "iris_seeder_upload_bytes_per_second 1000" in out
    assert "iris_seeder_connections 4" in out
    assert "iris_seeder_rpc_up 1" in out


def test_render_seeder_rpc_down_is_zero():
    out = metrics.render([], {"rpc_up": False}, {})
    assert "iris_seeder_rpc_up 0" in out


def test_render_seeder_torrent_upload_length_gauge_is_catalog_fenced():
    out = metrics.render([], {"rpc_up": True}, {}, seeder_torrents=[
        {"image": "cat9k.bin", "info_hash": "known", "upload_length": 1500},
    ])
    assert "# TYPE iris_seeder_torrent_upload_length_bytes gauge" in out
    assert ('iris_seeder_torrent_upload_length_bytes{image="cat9k.bin",'
            'info_hash="known"} 1500' in out)


def test_render_announces_total_counter():
    out = metrics.render([], {}, {"announces_total": 42})
    assert "# TYPE iris_tracker_announces_total counter" in out
    assert "iris_tracker_announces_total 42" in out


def test_label_values_are_escaped():
    swarm = [{"info_hash": "a", "image": 'na"me\\x', "seeders": 0,
              "leechers": 0, "peers": 0, "bytes_remaining": 0, "completed": 0}]
    out = metrics.render(swarm, {}, {})
    # backslash and double-quote in a label value must be escaped
    assert r'image="na\"me\\x"' in out


def test_output_ends_with_newline():
    # Prometheus exposition requires a trailing newline on the last line
    assert metrics.render([], {}, {}).endswith("\n")


# --- iris_device_reports_stored gauge ---

def test_render_reports_stored_gauge():
    out = metrics.render([], {}, {}, reports_stored=7)
    assert "# HELP iris_device_reports_stored" in out
    assert "# TYPE iris_device_reports_stored gauge" in out
    assert "iris_device_reports_stored 7" in out


def test_render_reports_stored_defaults_to_zero():
    # existing three-arg callers keep working; the gauge simply reads 0
    out = metrics.render([], {}, {})
    assert "iris_device_reports_stored 0" in out


def test_render_reports_stored_bad_value_is_zero():
    out = metrics.render([], {}, {}, reports_stored="garbage")
    assert "iris_device_reports_stored 0" in out


class TestTransferFamilies:
    # Task 23: canonical low-cardinality families (design §10.9). A fresh row
    # carries the business gauges; a stale row OMITS them but still reports
    # freshness age so the omission is explainable.
    ROWS = [{"image": "cat9k.bin", "info_hash": "aa11", "devices": 2,
             "receive_bps": 100, "transmit_bps": 10, "progress_ratio": 0.375,
             "zero_receive_devices": 1, "freshness_age_seconds": 5,
             "sampling_class_good": 1, "sampling_class_constrained": 1,
             "stale": False}]
    EXTRAS = {"stream_devices": 3, "samples_rejected_total": 7,
              "legacy_announce_participants": 0}

    def _render(self, rows=None, extras=None, health=None):
        return metrics.render([], {"rpc_up": True}, {"announces_total": 0},
                              transfers=rows if rows is not None else self.ROWS,
                              extras=extras if extras is not None
                              else self.EXTRAS,
                              otlp_health=health)

    def test_canonical_family_names_and_labels(self):
        text = self._render()
        for needle in (
            'iris_transfer_devices{image="cat9k.bin",info_hash="aa11"} 2',
            'iris_transfer_throughput_bytes_per_second{image="cat9k.bin",'
            'info_hash="aa11",direction="receive"} 100',
            'iris_transfer_throughput_bytes_per_second{image="cat9k.bin",'
            'info_hash="aa11",direction="transmit"} 10',
            'iris_transfer_progress_ratio{image="cat9k.bin",'
            'info_hash="aa11"} 0.375',
            'iris_transfer_zero_receive_devices{image="cat9k.bin",'
            'info_hash="aa11"} 1',
            'iris_transfer_freshness_age_seconds{image="cat9k.bin",'
            'info_hash="aa11"} 5',
            'iris_stream_devices{image="cat9k.bin",info_hash="aa11",'
            'sampling_class="good"} 1',
            'iris_stream_devices{image="cat9k.bin",info_hash="aa11",'
            'sampling_class="constrained"} 1',
        ):
            assert needle in text, needle

    def test_retired_ambiguous_names_absent(self):
        text = self._render()
        for gone in ("iris_transfer_active", "iris_transfer_stalled",
                     "iris_transfer_down_bps_sum", "iris_transfer_up_bps_sum",
                     "iris_transfer_tier", "iris_transfer_samples_rejected"):
            assert gone not in text, gone

    def test_stale_row_omits_business_gauges_but_keeps_freshness(self):
        row = dict(self.ROWS[0], stale=True)
        text = self._render(rows=[row])
        # freshness + devices still reported
        assert 'iris_transfer_freshness_age_seconds{image="cat9k.bin",' \
               'info_hash="aa11"} 5' in text
        # throughput + progress gauges omitted for this image
        assert 'iris_transfer_throughput_bytes_per_second{image="cat9k.bin"' \
               not in text
        assert 'iris_transfer_progress_ratio{image="cat9k.bin"' not in text
        # zero_receive_devices is never asserted from stale
        assert 'iris_transfer_zero_receive_devices{image="cat9k.bin",' \
               'info_hash="aa11"} 0' in text

    def test_samples_rejected_and_legacy_participants(self):
        text = self._render()
        assert "# TYPE iris_telemetry_samples_rejected_total counter" in text
        assert "iris_telemetry_samples_rejected_total 7" in text
        assert "iris_legacy_announce_participants 0" in text

    def test_absent_when_none(self):
        text = metrics.render([], {}, {})
        assert "iris_transfer_" not in text and "iris_stream_" not in text


class TestPerSignalExportHealthMetrics:
    # Task 23: per-signal export failures / drops / last-success, with `signal`
    # label; counters monotonic; enforcement + policy numeric gauges.
    HEALTH = {
        "state": "degraded", "aggregate_rule": "worst_of",
        "signals": {
            "logs": {"state": "degraded", "last_success_ts": 100.0,
                     "fail_streak": 3, "queued": 12, "dropped_total": 4,
                     "failures_total": 3},
            "metrics": {"state": "ok", "last_success_ts": 200.0,
                        "fail_streak": 0, "failures_total": 0},
        },
    }

    def test_per_signal_failure_drop_last_success_names(self):
        text = metrics.render([], {}, {}, otlp_health=self.HEALTH)
        assert ('iris_telemetry_export_failures_total{signal="logs"} 3'
                in text)
        assert ('iris_telemetry_export_dropped_total{signal="logs"} 4'
                in text)
        assert "# TYPE iris_telemetry_export_failures_total counter" in text
        assert "# TYPE iris_telemetry_export_dropped_total counter" in text

    def test_enforcement_and_policy_gauges(self):
        text = metrics.render(
            [], {}, {}, peer_status={
                "policy_revision": 7, "applied_revision": 6,
                "desired_ip_count": 3, "health": 1})
        assert "iris_peer_policy_revision 7" in text
        assert "iris_peer_enforcement_applied_revision 6" in text
        assert "iris_peer_enforcement_desired_ips 3" in text
        assert "iris_peer_enforcement_health 1" in text
