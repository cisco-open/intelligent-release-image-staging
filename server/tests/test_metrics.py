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
