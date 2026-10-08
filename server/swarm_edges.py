# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bounded, sampled device-to-device rates, joined to current tracker identities.

An authenticated reporter observes a socket address, not a remote credential.
Expose the matching basis; never turn a shared address into guessed identity.
"""
import ipaddress
import math

import live_samples

MAX_EDGES = 1024


def _address(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None


def project(peers, samples, image_id, now):
    result = {"peer_edges": [], "peer_edges_truncated": False,
              "unattributed_peer_connections": 0}
    if not image_id:
        return result
    by_ip, by_endpoint, devices = {}, {}, {}
    for peer in peers:
        address = _address(peer.get("ip"))
        if address is None:
            continue
        # Include services and unattributed participants when detecting address
        # collisions. Only a uniquely matched device may become an edge node.
        by_ip.setdefault(address, []).append(peer)
        by_endpoint.setdefault((address, peer.get("port")), []).append(peer)
        if peer.get("principal_type") == "device" and peer.get("principal_id"):
            devices.setdefault(peer["principal_id"], []).append(peer)

    candidates = {}
    for reporter in sorted(devices):
        if len(devices[reporter]) != 1:
            continue
        sample = samples.get(reporter)
        if not isinstance(sample, dict) or sample.get("schema", "v2") != "v2" \
                or sample.get("image_id") != image_id \
                or sample.get("obs_state") != "observed" \
                or sample.get("valid") is not True:
            continue
        received = sample.get("observed_received_at")
        if isinstance(received, bool) or not isinstance(received, (int, float)) \
                or not math.isfinite(received) \
                or not 0 <= now - received <= live_samples.LIVE_VALUE_VALIDITY:
            continue
        connections = sample.get("peer_connections")
        if not isinstance(connections, list):
            continue
        if sample.get("peer_connections_truncated") or len(connections) > 32:
            result["peer_edges_truncated"] = True
        grouped, seen = {}, set()
        for connection in connections[:32]:
            if not isinstance(connection, dict):
                continue
            address = _address(connection.get("ip"))
            port = connection.get("port")
            endpoint = (address, port)
            if endpoint in seen:
                continue  # the same socket never adds its rates twice
            seen.add(endpoint)
            matches = by_endpoint.get(endpoint, [])
            basis = "tracker_endpoint"
            if not matches:
                matches = by_ip.get(address, [])
                basis = "unique_tracker_address"
            remote = matches[0] if len(matches) == 1 else {}
            remote_id = remote.get("principal_id")
            if remote.get("principal_type") != "device" \
                    or len(devices.get(remote_id, [])) != 1:
                result["unattributed_peer_connections"] += 1
                continue
            if remote_id == reporter:
                continue
            for field, source, target in (
                    ("receive_bps", remote_id, reporter),
                    ("send_bps", reporter, remote_id)):
                value = connection.get(field)
                if type(value) is not int or not 0 <= value <= 10 ** 12:
                    continue
                key = (source, target, field)
                item = grouped.setdefault(key, {
                    "source_device_id": source, "target_device_id": target,
                    "bytes_per_second": 0, "connection_count": 0,
                    "reporter_device_id": reporter, "rate_field": field,
                    "identity_basis": basis, "received_at": received,
                    "observed_at": sample.get("observed_at"),
                    "age_s": max(0, int(now - received)),
                    "valid_for_s": live_samples.LIVE_VALUE_VALIDITY})
                item["bytes_per_second"] += value
                item["connection_count"] += 1
                if basis == "unique_tracker_address":
                    item["identity_basis"] = basis
        for (source, target, field), item in grouped.items():
            key = (source, target)
            prior = candidates.get(key)
            # Receiver evidence is authoritative for this sampled view,
            # including a fresh explicit zero. Never sum both ends of a flow.
            if prior is None or (field == "receive_bps" and
                                 prior["rate_field"] != "receive_bps"):
                candidates[key] = item
    edges = [candidates[key] for key in sorted(candidates)
             if candidates[key]["bytes_per_second"] > 0]
    result["peer_edges"] = edges[:MAX_EDGES]
    result["peer_edges_truncated"] |= len(edges) > MAX_EDGES
    return result
