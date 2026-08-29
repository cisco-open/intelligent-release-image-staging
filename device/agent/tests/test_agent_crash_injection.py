# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Crash-injection: the durable-before-POST rule (spec §2).

Because the agent CHECKPOINTS the frozen report (body + report_id) and the
incremented sample_seq BEFORE the network POST, a crash AFTER the POST but
BEFORE the outer final state save must restart from the checkpointed state and
re-send the SAME frozen report/id with a NON-REGRESSING sample_seq — the server
dedupes by report_id, so the retry is idempotent. We model the crash by only
persisting via the checkpoint file (the outer main() save is skipped) and then
re-loading that file for the restart tick.
"""
import json
import time as _time

import iris_agent
import telemetry_report

iris_agent._SLEEP = lambda s: None

_CFG = {"device_id": "sw1", "stage_dir": "/stage",
        "token_expires_at": str(int(_time.time()) + 604_800),
        "telemetry": "on", "telemetry_stream": "on"}
_IMG = {"id": "img1", "filename": "img1.bin", "size": 5, "sha256": "abc"}


class _Cat:
    def __init__(self, policy, image):
        self._policy, self._image = policy, image
        self.heartbeats, self.telemetry = [], []
        self.hb_response = None

    def get_policy(self, sid):
        return self._policy

    def get_image(self, iid):
        return self._image

    def download_torrent(self, iid, dest):
        pass

    def heartbeat(self, sid, data):
        self.heartbeats.append(data)
        return self.hb_response

    def post_telemetry(self, sid, report):
        self.telemetry.append((sid, report))
        return {"ok": True}


def _deps(cat, sizes, state_path, **over):
    def checkpoint(state):
        iris_agent._atomic_write_state(state_path, state)

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
        aria_stats=lambda p: {"gid": "g", "completedLength": "5",
                              "totalLength": "5", "downloadSpeed": "0",
                              "uploadSpeed": "0", "connections": "0"},
        aria_peers=lambda p: [], io_transfer=False, copy_in_place=False,
        checkpoint=checkpoint, aria_session=lambda: None)
    base.update(over)
    return iris_agent.Deps(**base)


def _load(state_path):
    try:
        with open(state_path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def test_crash_after_report_post_restarts_with_same_frozen_report(tmp_path):
    state_path = str(tmp_path / "iris-agent.state")
    cat = _Cat({"approved_image_id": "img1"}, _IMG)
    deps = _deps(cat, {"/stage/img1.bin": 5}, state_path)

    # --- tick 1: completes, freezes+checkpoints the report, POSTs it, then we
    # simulate a crash by discarding the in-memory state and NOT doing the outer
    # final save. The checkpoint file is the only durable survivor. ---
    state = _load(state_path)
    assert iris_agent.run_once(_CFG, deps, state) == "complete"
    assert len(cat.telemetry) == 1
    first_report_id = cat.telemetry[0][1]["report_id"]
    assert len(first_report_id) == 32
    # the frozen report + id were checkpointed BEFORE the POST
    persisted = _load(state_path)
    assert persisted["img1"]["tele"]["frozen_report"]["report_id"] \
        == first_report_id
    # crash: in-memory `state` is thrown away; outer save never ran.

    # --- restart: reload ONLY the checkpointed file and run again. The server
    # already got the report, so it may pull again / the agent may re-send; the
    # frozen id must be IDENTICAL and sample_seq must not regress. ---
    restart_state = _load(state_path)
    frozen_before = restart_state["img1"]["tele"]["frozen_report"]
    seq_before = restart_state["img1"]["tele"].get("sample_seq", 0)

    cat2 = _Cat({"approved_image_id": "img1"}, _IMG)
    deps2 = _deps(cat2, {"/stage/img1.bin": 5}, state_path)
    iris_agent.run_once(_CFG, deps2, restart_state)
    # no NEW report id was minted for the same completion
    assert restart_state["img1"]["tele"]["frozen_report"]["report_id"] \
        == first_report_id
    assert restart_state["img1"]["tele"]["frozen_report"] == frozen_before
    # sample_seq never rewinds
    assert restart_state["img1"]["tele"].get("sample_seq", 0) >= seq_before


def test_crash_before_outer_save_preserves_sample_seq(tmp_path):
    state_path = str(tmp_path / "iris-agent.state")
    cat = _Cat({"approved_image_id": "img1"}, _IMG)
    # a live download (not yet complete) so an observed heartbeat increments and
    # checkpoints sample_seq BEFORE the heartbeat POST.
    deps = _deps(cat, {"/stage/img1.bin": 2, "/stage/img1.bin.aria2": 1},
                 state_path)
    state = _load(state_path)
    assert iris_agent.run_once(_CFG, deps, state) == "downloading"
    seq_after_post = _load(state_path)["img1"]["tele"]["sample_seq"]
    assert seq_after_post == 1
    # crash before the outer save; restart from the checkpoint file.
    restart = _load(state_path)
    cat2 = _Cat({"approved_image_id": "img1"}, _IMG)
    deps2 = _deps(cat2, {"/stage/img1.bin": 2, "/stage/img1.bin.aria2": 1},
                  state_path)
    iris_agent.run_once(_CFG, deps2, restart)
    # the next observed sample advances to 2 — never rewinds to 1.
    assert restart["img1"]["tele"]["sample_seq"] >= 2


def test_pull_new_request_new_report_repeat_reuses(tmp_path):
    state_path = str(tmp_path / "iris-agent.state")
    cat = _Cat({"approved_image_id": "img1"}, _IMG)
    deps = _deps(cat, {"/stage/img1.bin": 5}, state_path)
    # steady state: done + copied + root present.
    state = {"schema_version": iris_agent._STATE_SCHEMA, "image_id": "img1",
             "stage_fs": "flash:",
             "img1": {"done": True, "copied": True, "sha": "abc",
                      "tele": {"report_pending": False, "event": "staging-complete",
                               "transfer_id": "a" * 32,
                               "content_sha256_state": "verified",
                               "ios_copy_verify_state": "ok"}}}
    # pull request R1
    cat.hb_response = {"ok": True, "report_requested": True,
                       "report_request_id": "1" * 32}
    iris_agent.run_once(_CFG, deps, state)
    assert cat.telemetry[-1][1]["report_request_id"] == "1" * 32
    r1_id = cat.telemetry[-1][1]["report_id"]
    # repeat the SAME request R1 -> identical frozen body/id reused
    iris_agent.run_once(_CFG, deps, state)
    assert cat.telemetry[-1][1]["report_id"] == r1_id
    # a NEW request R2 -> fresh random report id + body
    cat.hb_response = {"ok": True, "report_requested": True,
                       "report_request_id": "2" * 32}
    iris_agent.run_once(_CFG, deps, state)
    assert cat.telemetry[-1][1]["report_request_id"] == "2" * 32
    assert cat.telemetry[-1][1]["report_id"] != r1_id
