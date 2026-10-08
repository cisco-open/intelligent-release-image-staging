# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import copy

import pytest

import swarm_edges


def peer(name, ip, port=6881, kind="device"):
    return {"principal_type": kind, "principal_id": name, "ip": ip, "port": port}


PEERS = [peer("a", "192.0.2.1"), peer("b", "192.0.2.2")]


def sample(ip="192.0.2.1", **rates):
    return {"schema": "v2", "image_id": "os", "obs_state": "observed",
            "valid": True, "observed_received_at": 100, "observed_at": 99,
            "peer_connections": [{"ip": ip, "port": 50000, **rates}]}


def project(samples, peers=PEERS, now=100, image="os"):
    return swarm_edges.project(peers, samples, image, now)


def test_receiver_direction_and_address_provenance():
    edge, = project({"b": sample(receive_bps=123)})["peer_edges"]
    assert (edge["source_device_id"], edge["target_device_id"]) == ("a", "b")
    assert edge["identity_basis"] == "unique_tracker_address"
    assert edge["bytes_per_second"] == 123
    assert edge["reporter_device_id"] == "b"


def test_two_sides_are_not_added_and_receiver_zero_suppresses_sender():
    samples = {"a": sample("192.0.2.2", send_bps=150),
               "b": sample(receive_bps=123)}
    assert project(samples)["peer_edges"][0]["bytes_per_second"] == 123
    samples["b"]["peer_connections"][0]["receive_bps"] = 0
    assert not project(samples)["peer_edges"]


@pytest.mark.parametrize("change", [
    {"schema": "v1"}, {"image_id": "other"}, {"valid": False},
    {"obs_state": "paused"}, {"obs_state": "not_due"},
    {"observed_received_at": -21}, {"observed_received_at": 101},
    {"observed_received_at": float("nan")}, {"observed_received_at": None},
])
def test_stale_withdrawn_wrong_image_and_invalid_times_are_not_edges(change):
    row = sample(receive_bps=123)
    row.update(change)
    assert not project({"b": row})["peer_edges"]


def test_no_catalog_mapping_or_authenticated_reporter_means_no_edge():
    assert not project({"b": sample(receive_bps=123)}, image=None)["peer_edges"]
    assert not project({"unknown": sample(receive_bps=123)})["peer_edges"]


def test_shared_address_and_endpoint_fail_closed_including_service_claims():
    for kind in ("device", "service", "legacy"):
        peers = PEERS + [peer("c", "192.0.2.1", kind=kind)]
        result = project({"b": sample(receive_bps=123)}, peers)
        assert not result["peer_edges"]
        assert result["unattributed_peer_connections"] == 1
        row = sample(receive_bps=123)
        row["peer_connections"][0]["port"] = 6881
        assert not project({"b": row}, peers)["peer_edges"]


def test_exact_endpoint_can_disambiguate_shared_address():
    peers = PEERS + [peer("c", "192.0.2.1", 6882)]
    row = sample(receive_bps=123)
    row["peer_connections"][0]["port"] = 6881
    edge, = project({"b": row}, peers)["peer_edges"]
    assert edge["source_device_id"] == "a"
    assert edge["identity_basis"] == "tracker_endpoint"


def test_distinct_sockets_sum_but_duplicates_do_not():
    row = sample(receive_bps=123)
    duplicate = copy.deepcopy(row["peer_connections"][0])
    row["peer_connections"] += [duplicate, dict(duplicate, port=50001)]
    edge, = project({"b": row})["peer_edges"]
    assert edge["bytes_per_second"] == 246
    assert edge["connection_count"] == 2


@pytest.mark.parametrize("value", [None, True, -1, "123", float("inf"), 10 ** 12 + 1])
def test_invalid_or_missing_rate_does_not_become_zero_or_edge(value):
    assert not project({"b": sample(receive_bps=value)})["peer_edges"]


def test_bidirectional_rates_are_separate_and_expire():
    samples = {"b": sample(send_bps=7, receive_bps=9)}
    edges = project(samples)["peer_edges"]
    assert [(x["source_device_id"], x["bytes_per_second"]) for x in edges] == [
        ("a", 9), ("b", 7)]
    assert not project(samples, now=221)["peer_edges"]


def test_limits_and_truncation_are_explicit(monkeypatch):
    monkeypatch.setattr(swarm_edges, "MAX_EDGES", 1)
    row = sample(send_bps=7, receive_bps=9)
    result = project({"b": row})
    assert len(result["peer_edges"]) == 1 and result["peer_edges_truncated"]
    row["peer_connections_truncated"] = True
    assert project({"b": row})["peer_edges_truncated"]
