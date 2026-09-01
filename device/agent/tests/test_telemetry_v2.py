# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Task 17 — persisted transfer identity, sample_seq, and the state-first
v2 telemetry_observation envelope (spec section 2 / 3A / 10.1).

Identities are persisted random values (secrets.token_hex(16) -> 32 lowercase
hex). transfer_id is minted once per acquisition-cycle boundary; sample_seq is
monotonic per transfer and incremented+persisted before the observed heartbeat
POST that carries it. The envelope is state-first: aria/peer/sampling appear
only under obs_state==observed.
"""
import re

import pytest

import telemetry_report

HEX32 = re.compile(r"^[a-f0-9]{32}$")


# ---- transfer_id minting at acquisition-cycle boundaries ----

def test_ensure_transfer_id_mints_on_first_assignment():
    state = {}
    tid = telemetry_report.ensure_transfer_id(state, "imgA")
    assert HEX32.match(tid)
    assert state["imgA"]["tele"]["transfer_id"] == tid


def test_ensure_transfer_id_stable_across_ticks_same_image():
    state = {}
    a = telemetry_report.ensure_transfer_id(state, "imgA")
    b = telemetry_report.ensure_transfer_id(state, "imgA")
    assert a == b


def test_ensure_transfer_id_distinct_on_image_change():
    state = {}
    a = telemetry_report.ensure_transfer_id(state, "imgA")
    b = telemetry_report.ensure_transfer_id(state, "imgB")
    assert a != b
    assert HEX32.match(a) and HEX32.match(b)


def test_a_b_a_mints_three_distinct_transfer_ids():
    # A->B->A is three acquisitions: the return to A is a NEW cycle, so the old
    # A transfer state must be cleared when B took over. This is the LEGACY pure
    # unit check of clear_transfer() in isolation; the PRODUCTION reassignment
    # path (run_once's state.pop) is proven by
    # test_reassignment_a_b_a_mints_three_distinct_transfer_ids below.
    state = {}
    a1 = telemetry_report.ensure_transfer_id(state, "imgA")
    telemetry_report.clear_transfer(state, "imgA")   # image changed away from A
    b = telemetry_report.ensure_transfer_id(state, "imgB")
    telemetry_report.clear_transfer(state, "imgB")
    a2 = telemetry_report.ensure_transfer_id(state, "imgA")
    assert len({a1, b, a2}) == 3


def test_ensure_transfer_id_reuses_on_changed_hash_p1():
    # P1: same image_id, changed content — Day-1 reuses the existing id
    # (dedupe/freshness still advance via report_id/sample_seq).
    state = {}
    a = telemetry_report.ensure_transfer_id(state, "imgA")
    # simulate a re-verify with new content but same image id: id persists
    b = telemetry_report.ensure_transfer_id(state, "imgA")
    assert a == b


# ---- sample_seq: monotonic per transfer, never rewinds ----

def test_next_sample_seq_starts_at_one_and_increments():
    state = {}
    telemetry_report.ensure_transfer_id(state, "imgA")
    assert telemetry_report.next_sample_seq(state, "imgA") == 1
    assert telemetry_report.next_sample_seq(state, "imgA") == 2


def test_next_sample_seq_persisted_in_state():
    state = {}
    telemetry_report.ensure_transfer_id(state, "imgA")
    telemetry_report.next_sample_seq(state, "imgA")
    assert state["imgA"]["tele"]["sample_seq"] == 1


def test_sample_seq_resets_for_a_new_transfer():
    state = {}
    telemetry_report.ensure_transfer_id(state, "imgA")
    telemetry_report.next_sample_seq(state, "imgA")
    telemetry_report.next_sample_seq(state, "imgA")
    telemetry_report.clear_transfer(state, "imgA")
    telemetry_report.ensure_transfer_id(state, "imgA")
    assert telemetry_report.next_sample_seq(state, "imgA") == 1


# ---- state-first telemetry_observation envelope ----

def _observed_stats():
    return {"status": "active", "completedLength": "734003200",
            "totalLength": "1288490188", "downloadSpeed": "11534336",
            "uploadSpeed": "262144", "connections": "5"}


def test_build_observation_observed_full_shape():
    env = telemetry_report.build_observation(
        obs_state="observed", observed_at=1755743100.12,
        transfer_id="a" * 32, image_id="cat9k.bin", sample_seq=42,
        aria_session_id="b1d9c0a2f4e6", sampling_class="good",
        stats=_observed_stats(),
        peers=[{"ip": "100.92.100.14", "send_bps": 131072, "receive_bps": 0}])
    assert env["v"] == 2
    assert env["obs_state"] == "observed"
    assert env["observed_at"] == 1755743100.12
    assert env["transfer_id"] == "a" * 32
    assert env["image_id"] == "cat9k.bin"
    assert env["sample_seq"] == 42
    assert env["aria_session_id"] == "b1d9c0a2f4e6"
    assert env["sampling_class"] == "good"
    assert env["aria"] == {
        "status": "active", "completed_content_bytes": 734003200,
        "total_content_bytes": 1288490188, "receive_bps": 11534336,
        "send_bps": 262144, "connections": 5}
    assert env["peer_connections"] == [
        {"ip": "100.92.100.14", "send_bps": 131072, "receive_bps": 0}]


def test_build_observation_state_only_invents_no_transfer_fields():
    for st in ("paused", "disabled", "not_active", "not_due", "rpc_unavailable"):
        env = telemetry_report.build_observation(
            obs_state=st, observed_at=1755743100.12,
            transfer_id="a" * 32, image_id="cat9k.bin")
        assert env["v"] == 2
        assert env["obs_state"] == st
        assert "aria" not in env
        assert "peer_connections" not in env
        assert "sampling_class" not in env
        assert "phase" not in env
        assert "tier" not in env


def test_build_observation_not_active_omits_transfer_id_and_image():
    env = telemetry_report.build_observation(
        obs_state="not_active", observed_at=1.0,
        transfer_id=None, image_id=None)
    assert "transfer_id" not in env
    assert "image_id" not in env


def test_build_observation_state_only_keeps_transfer_id_when_present():
    env = telemetry_report.build_observation(
        obs_state="paused", observed_at=1.0,
        transfer_id="a" * 32, image_id="img")
    assert env["transfer_id"] == "a" * 32
    assert env["image_id"] == "img"


def test_build_observation_rejects_unknown_state():
    with pytest.raises(ValueError):
        telemetry_report.build_observation(
            obs_state="bogus", observed_at=1.0, transfer_id=None, image_id=None)


def test_build_observation_observed_requires_sampling_class():
    with pytest.raises(ValueError):
        telemetry_report.build_observation(
            obs_state="observed", observed_at=1.0, transfer_id="a" * 32,
            image_id="img", sample_seq=1, stats=_observed_stats())


def test_build_observation_peer_rows_capped():
    peers = [{"ip": "10.0.0.%d" % i, "send_bps": 0, "receive_bps": 0}
             for i in range(100)]
    env = telemetry_report.build_observation(
        obs_state="observed", observed_at=1.0, transfer_id="a" * 32,
        image_id="img", sample_seq=1, sampling_class="good",
        stats=_observed_stats(), peers=peers,
        peer_rows_max=32)
    assert len(env["peer_connections"]) == 32


def test_build_observation_preserves_only_measured_peer_fields():
    env = telemetry_report.build_observation(
        obs_state="observed", observed_at=1.0, transfer_id="a" * 32,
        image_id="img", sample_seq=1, sampling_class="good",
        stats=_observed_stats(), peers=[
            {"ip": "10.0.0.1", "receive_bps": 12,
             "peer_client_name": "aria2", "progress": 50.5},
            {"ip": "10.0.0.2"}])
    assert env["peer_connections"] == [
        {"ip": "10.0.0.1", "receive_bps": 12,
         "peer_client_name": "aria2", "progress": 50.5},
        {"ip": "10.0.0.2"}]


# ---- run_once integration: v2 envelope on assigned heartbeats ----

import time as _time

import iris_agent

iris_agent._SLEEP = lambda s: None

_CFG = {"device_id": "sw1", "stage_dir": "/stage",
        "token_expires_at": str(int(_time.time()) + 604_800),
        "telemetry": "on", "telemetry_stream": "on"}
_IMG = {"id": "img1", "filename": "img1.bin", "size": 5, "sha256": "abc"}


class _Cat:
    def __init__(self, policy, image, images=None):
        self._policy, self._image = policy, image
        # Rows this catalog can answer for BY ID. A real catalog answers every
        # id with its own row; the single-image default below is kept for the
        # cases that only ever ask about one image.
        self._images = {i["id"]: i for i in (images or ())}
        self.heartbeats, self.telemetry, self.order = [], [], []
        self.hb_response = None

    def get_policy(self, sid):
        return self._policy

    def get_image(self, iid):
        return self._images.get(iid, self._image)

    def download_torrent(self, iid, dest):
        pass

    def heartbeat(self, sid, data):
        self.order.append("heartbeat")
        self.heartbeats.append(data)
        return self.hb_response

    def post_telemetry(self, sid, report):
        self.telemetry.append((sid, report))
        return {"ok": True}


def _deps(cat, sizes, **over):
    order = cat.order
    base = dict(
        catalog=cat, emit=lambda *a: None, ios=lambda c: "",
        aria_add=lambda t, d: None, file_size=lambda p: sizes.get(p),
        verify=lambda p, sha: True, free_bytes=lambda prefix="flash:": 9_000_000_000,
        version=lambda: "17", copy_to_root=lambda f, tp="flash:", expected_size=None: True,
        purge_others=lambda k, i: None, reclaim=lambda: None,
        root_present=lambda f, prefix="flash:", expected_size=None: True,
        remove_stage=lambda p: sizes.pop(p, None), aria_remove=lambda f: None,
        detect_mode=lambda: "bundle", target_fs=lambda: ("flash:", 9_000_000_000),
        running_image=lambda: "running.bin",
        reclaimable=lambda pre, pro: [], reclaim_bundle=lambda pre, n: None,
        model=lambda: "C9300", refresh=lambda: None,
        aria_stats=lambda p: None, aria_peers=lambda p: [], io_transfer=False,
        copy_in_place=False,
        checkpoint=lambda s: order.append("checkpoint"),
        aria_session=lambda: None)
    base.update(over)
    return iris_agent.Deps(**base)


def test_unassigned_heartbeat_carries_not_active_observation():
    cat = _Cat({"approved_image_id": None}, None)
    iris_agent.run_once(_CFG, _deps(cat, {}), {})
    obs = cat.heartbeats[-1]["telemetry_observation"]
    assert obs["obs_state"] == "not_active"
    assert "transfer_id" not in obs and "aria" not in obs


def test_disabled_toggle_heartbeat_carries_disabled_observation():
    cat = _Cat({"approved_image_id": "img1"}, _IMG)
    cfg = dict(_CFG, telemetry="off")
    iris_agent.run_once(cfg, _deps(cat, {"/stage/img1.bin": 5}), {})
    assert cat.heartbeats[-1]["telemetry_observation"]["obs_state"] == "disabled"


def test_stream_off_downloading_heartbeat_is_paused_state_only():
    cat = _Cat({"approved_image_id": "img1"}, _IMG)
    cfg = dict(_CFG, telemetry_stream="off")
    deps = _deps(cat, {"/stage/img1.bin": 2, "/stage/img1.bin.aria2": 1})
    iris_agent.run_once(cfg, deps, {"image_id": "img1", "img1": {"tele": {}}})
    obs = cat.heartbeats[-1]["telemetry_observation"]
    assert obs["obs_state"] == "paused"
    assert "aria" not in obs and obs["sample_seq"] == 1
    assert HEX32.match(obs["transfer_id"])


def test_observed_envelope_carries_aria_seq_and_checkpoints_before_post():
    cat = _Cat({"approved_image_id": "img1"}, _IMG)
    stats = {"gid": "g", "status": "active", "completedLength": "2",
             "totalLength": "5", "downloadSpeed": "10", "uploadSpeed": "1",
             "connections": "3"}
    deps = _deps(cat, {"/stage/img1.bin": 2, "/stage/img1.bin.aria2": 1},
                 aria_stats=lambda p: stats,
                 aria_peers=lambda p: [{"ip": "10.0.0.9", "send_bps": 5,
                                        "receive_bps": 0}],
                 aria_session=lambda: "sess123")
    state = {"image_id": "img1", "img1": {"tele": {}}}
    assert iris_agent.run_once(_CFG, deps, state) == "downloading"
    obs = cat.heartbeats[-1]["telemetry_observation"]
    assert obs["obs_state"] == "observed"
    assert obs["sample_seq"] == 1
    assert obs["aria_session_id"] == "sess123"
    assert obs["aria"]["receive_bps"] == 10 and obs["aria"]["connections"] == 3
    assert obs["peer_connections"] == [
        {"ip": "10.0.0.9", "send_bps": 5, "receive_bps": 0}]
    assert state["img1"]["tele"]["sample_seq"] == 1
    # checkpoint fired BEFORE the heartbeat POST carrying the seq
    assert cat.order.index("checkpoint") < cat.order.index("heartbeat")


def test_checkpoint_failure_downgrades_observed_to_not_due_without_rewind():
    cat = _Cat({"approved_image_id": "img1"}, _IMG)
    stats = {"gid": "g", "status": "active", "completedLength": "2",
             "totalLength": "5", "downloadSpeed": "10", "uploadSpeed": "1",
             "connections": "3"}

    def boom(_s):
        raise OSError("disk full")

    deps = _deps(cat, {"/stage/img1.bin": 2, "/stage/img1.bin.aria2": 1},
                 aria_stats=lambda p: stats,
                 aria_peers=lambda p: [], checkpoint=boom)
    state = {"image_id": "img1", "img1": {"tele": {}}}
    iris_agent.run_once(_CFG, deps, state)
    assert "telemetry_observation" not in cat.heartbeats[-1]
    # the un-persisted seq increment was rolled back (stays at 0)
    assert state["img1"]["tele"].get("sample_seq", 0) == 0


def test_reassignment_a_b_a_mints_three_distinct_transfer_ids():
    tids = []
    state = {}

    def run(img_id):
        rows = [{"id": i, "filename": i + ".bin", "size": 5, "sha256": "abc"}
                for i in ("imgA", "imgB")]
        img = next(r for r in rows if r["id"] == img_id)
        # The catalog answers each id with ITS OWN row, as the real one does:
        # the park pass has to name the departing image's staged file before it
        # can stop that torrent and delete the file.
        cat = _Cat({"approved_image_id": img_id}, img, images=rows)
        deps = _deps(cat, {"/stage/%s.bin" % img_id: 2,
                           "/stage/%s.bin.aria2" % img_id: 1},
                     purge_others=lambda k, i: None)
        cfg = dict(_CFG, telemetry_stream="off")
        iris_agent.run_once(cfg, deps, state)
        tids.append(cat.heartbeats[-1]["telemetry_observation"]["transfer_id"])

    run("imgA")
    a1 = state["imgA"]["tele"]["transfer_id"]
    run("imgB")
    # PRODUCTION reassignment: an image that leaves the assignment set is
    # PARKED — its record survives (root copy kept), so the park pass is what
    # ends the acquisition cycle, clearing the transfer identity. Prove the old
    # A cycle is truly gone, so the return to A below re-mints rather than
    # reusing.
    assert state["imgA"]["parked"] is True
    assert "transfer_id" not in state["imgA"].get("tele", {})
    run("imgA")
    a2 = state["imgA"]["tele"]["transfer_id"]
    assert len(set(tids)) == 3
    # ...and the two A acquisitions really are distinct cycles, not a reuse.
    assert a1 != a2


def test_aria_down_keeps_staging_heartbeat_with_rpc_unavailable_obs():
    cat = _Cat({"approved_image_id": "img1"}, _IMG)

    def refuse(*a, **k):
        raise OSError("aria2 down")

    deps = _deps(cat, {}, aria_add=refuse)
    assert iris_agent.run_once(_CFG, deps, {}) == "aria2-down"
    obs = cat.heartbeats[-1]["telemetry_observation"]
    assert obs["obs_state"] == "rpc_unavailable"
    assert HEX32.match(obs["transfer_id"]) and "aria" not in obs
