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
    ROWS = [{"image": "cat9k.bin", "info_hash": "aa11", "active": 2,
             "down_bps": 100, "up_bps": 10, "progress_ratio": 0.375,
             "stalled": 1, "tier_good": 1, "tier_constrained": 1}]
    EXTRAS = {"stream_devices": 3, "samples_rejected_total": 7}

    def test_rendered_when_given(self):
        text = metrics.render([], {"rpc_up": True}, {"announces_total": 0},
                              transfers=self.ROWS, extras=self.EXTRAS,
                              otlp_health={"failures_total": 2,
                                           "last_success_ts": 12345})
        for needle in (
            'iris_transfer_active{image="cat9k.bin",info_hash="aa11"} 2',
            'iris_transfer_down_bps_sum{image="cat9k.bin",info_hash="aa11"} 100',
            'iris_transfer_progress_ratio{image="cat9k.bin",info_hash="aa11"} 0.375',
            'iris_transfer_tier{image="cat9k.bin",info_hash="aa11",tier="good"} 1',
            "iris_stream_devices 3",
            "iris_transfer_samples_rejected_total 7",
            "iris_otlp_export_failures_total 2",
            "iris_otlp_last_export_success_seconds 12345",
        ):
            assert needle in text, needle

    def test_absent_when_none(self):
        text = metrics.render([], {}, {})
        assert "iris_transfer_" not in text and "iris_stream_" not in text
