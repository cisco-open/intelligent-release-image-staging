# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Torrent TLS observations must not turn desired policy into encryption claims."""
from pathlib import Path
import shutil
import subprocess

import pytest

import auth
import catalog
import otlp
import telemetry
from peer_registry import PeerRegistry


@pytest.mark.parametrize("value,expected", [
    (None, None), (True, None), ({}, None),
    ({"configured_mode": []}, None),
    ({"configured_mode": "required", "runtime_mode": "required",
      "runtime_source": "config"},
     {"configured_mode": "required", "runtime_mode": "unknown", "runtime_source": "unknown"}),
    ({"configured_mode": "disabled", "runtime_mode": {}, "runtime_source": "aria2_rpc"},
     {"configured_mode": "disabled", "runtime_mode": "unknown", "runtime_source": "unknown"}),
])
def test_heartbeat_tls_unknown_is_not_off_or_required(value, expected):
    assert catalog.sanitize_heartbeat({"peer_tls": value}, "192.0.2.1")["peer_tls"] == expected


@pytest.mark.parametrize("configured,runtime", [("required", "required"),
    ("required", "disabled"), ("disabled", "required"), ("disabled", "disabled")])
def test_tls_round_trip_and_identity_join(configured, runtime):
    fact = {"configured_mode": configured, "runtime_mode": runtime,
            "runtime_source": "aria2_rpc"}
    record = catalog.sanitize_heartbeat({"peer_tls": dict(fact, secret="discard")}, "192.0.2.1")
    assert record["peer_tls"] == fact
    record["last_seen"] = 10
    hub = telemetry.Telemetry(PeerRegistry(), device_info=lambda: {"d1": record})
    for name in ("d1", "other"):
        hub._registry.announce("abc", name, "192.0.2.1", 6881, left=0, now=0,
                               principal=auth.Principal("device", name))
    rows = {row["device_id"]: row for row in hub.swarm_snapshot(now=20)["images"][0]["peers"]}
    assert rows["d1"]["peer_tls"] == dict(fact, reported_at=10)
    assert "peer_tls" not in rows["other"]
    assert "reported_at" not in record["peer_tls"]


def test_console_and_swarm_tls_labels_execute():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node required for UI behavior test")
    root = Path(__file__).resolve().parents[1]
    app = (root / "webroot/app.js").read_text()
    block = app[app.index("  function peerTlsCell("):app.index("  function telemetryCell(")]
    swarm = (root / "swarmmap.html").read_text()
    block += swarm[swarm.index("function peerTlsLabel("):swarm.index("function peerStatus(")]
    program = '''const assert = require('node:assert/strict');
const DATA = {now: 1000}; Date.now = () => 1000000;
const esc = value => String(value).replace(/</g, '&lt;');
const fmtDate = value => String(value);
''' + block + '''
const required = {configured_mode:'required',runtime_mode:'required',runtime_source:'aria2_rpc',reported_at:990};
const off = {...required,runtime_mode:'disabled'};
const unverified = {...required,runtime_source:'unknown'};
assert.match(peerTlsCell({}), /TLS unknown/);
assert.match(peerTlsCell({peer_tls:required,last_seen:990}), />TLS required</);
assert.match(peerTlsCell({peer_tls:off,last_seen:990}), />TLS off</);
assert.match(peerTlsCell({peer_tls:unverified,last_seen:990}), /TLS unknown/);
assert.match(peerTlsCell({peer_tls:required,last_seen:1}), /TLS required \\(stale\\)/);
assert.match(peerTlsCell({peer_tls:required,last_seen:990}), /not a negotiated connection/);
assert.equal(peerTlsLabel({}), 'TLS unknown');
assert.equal(peerTlsLabel({peer_tls:required}), 'TLS required');
assert.equal(peerTlsLabel({peer_tls:off}), 'TLS off');
assert.equal(peerTlsLabel({peer_tls:unverified}), 'TLS unknown');
assert.equal(peerTlsLabel({peer_tls:{...required,reported_at:1}}), 'TLS required (stale)');
console.log('ok');
'''
    result = subprocess.run([node], input=program, text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


@pytest.mark.parametrize("option,expected", [("required", "required"),
    ("disabled", "disabled"), (None, "unknown"), (True, "unknown"),
    ({}, "unknown")])
def test_origin_reads_runtime_policy_once_per_sample(option, expected):
    calls = []
    def rpc(method, params):
        calls.append(method)
        if method == "aria2.getGlobalOption":
            return {"bt-peer-tls": option} if option is not None else {}
        if method == "aria2.tellActive":
            return []
        return {}
    hub = telemetry.Telemetry(PeerRegistry(), rpc=rpc)
    hub.sample_seeder(now=100)
    observation = hub.swarm_snapshot(now=110)["server"]["server_observation"]["peer_tls"]
    assert observation == {"runtime_mode": expected,
                           "runtime_source": "unknown" if expected == "unknown" else "aria2_rpc",
                           "reported_at": 100}
    hub.swarm_snapshot(now=120)
    assert calls.count("aria2.getGlobalOption") == 1
    def down(*args):
        raise OSError("unreachable")
    hub.rpc = down
    hub.sample_seeder(now=130)
    observation = hub.swarm_snapshot(now=140)["server"]["server_observation"]["peer_tls"]
    assert observation["runtime_mode"] == "unknown"


def test_optional_tls_rpc_failure_preserves_rate_observation():
    def rpc(method, params):
        if method == "aria2.getGlobalOption":
            raise OSError("old daemon")
        return [] if method == "aria2.tellActive" else {"uploadSpeed": "123"}
    stats, _, _ = telemetry.poll_seeder(rpc)
    assert stats["rpc_up"] is True
    assert stats["upload_speed"] == 123
    assert stats["peer_tls"]["runtime_mode"] == "unknown"


def _attrs(record):
    return {item["key"]: next(iter(item["value"].values()))
            for item in record["attributes"]}


@pytest.mark.parametrize("builder,row", [
    (otlp.build_tracker_record, {"principal": "device:d1", "received_at": 20}),
    (otlp.build_peer_rate_record, {"principal": "device:d1", "ts": 20}),
    (otlp.build_peer_bytes_record, {"device_id": "d1", "ts": 20}),
])
def test_splunk_peer_records_carry_tls_policy_observation(builder, row):
    row["peer_tls"] = {"configured_mode": "required",
                       "runtime_mode": "required",
                       "runtime_source": "aria2_rpc", "reported_at": 10}
    attrs = _attrs(builder(row))
    assert attrs["iris.peer.tls.configured_mode"] == "required"
    assert attrs["iris.peer.tls.runtime_mode"] == "required"
    assert attrs["iris.peer.tls.runtime_source"] == "aria2_rpc"
    assert attrs["iris.peer.tls.reported_at"] == 10.0


def test_tracker_event_reads_tls_only_from_stored_device_heartbeat():
    heartbeat = {"last_seen": 10, "peer_tls": {
        "configured_mode": "required", "runtime_mode": "required",
        "runtime_source": "aria2_rpc"}}
    hub = telemetry.Telemetry(PeerRegistry(), device_info=lambda: {"d1": heartbeat})
    hub.on_swarm_event({"event": "join", "event_id": "tls-event",
                        "principal_type": "device", "principal_id": "d1",
                        "info_hash": "abc", "ip": "192.0.2.1", "left": 1,
                        "received_at": 20,
                        "peer_tls": {"configured_mode": "disabled"}})
    attrs = _attrs(otlp.build_log_record(hub.log_queue.snapshot()[0]))
    assert attrs["iris.peer.tls.configured_mode"] == "required"
    assert attrs["iris.peer.tls.runtime_mode"] == "required"
    assert attrs["iris.peer.tls.reported_at"] == 10.0
