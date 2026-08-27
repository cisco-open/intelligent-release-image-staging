# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Task 18 — explicit persisted verification outcomes (spec §3D).

content_sha256_state (verified|mismatch|not_checked) is written WHEN run_once
makes the content-hash verify decision; ios_copy_verify_state
(ok|failed|not_run|unsupported) is written WHEN it makes the IOS copy /verify
decision. The report reads them verbatim — never inferred from done/copied or
absence, never 'false' for unchecked, and the two facts are independent.
"""
import time as _time

import iris_agent
import telemetry_report

iris_agent._SLEEP = lambda s: None

_CFG = {"device_id": "sw1", "stage_dir": "/stage",
        "token_expires_at": str(int(_time.time()) + 604_800)}
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


def _deps(cat, sizes, **over):
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
        checkpoint=lambda s: None, aria_session=lambda: None)
    base.update(over)
    return iris_agent.Deps(**base)


# ---- reader defaults (never inferred) ----

def test_content_sha256_state_defaults_not_checked():
    assert telemetry_report.content_sha256_state({}, "img") == "not_checked"
    # a done/copied image with no persisted verify fact is STILL not_checked
    state = {"img": {"done": True, "copied": True}}
    assert telemetry_report.content_sha256_state(state, "img") == "not_checked"


def test_ios_copy_verify_state_defaults_not_run():
    assert telemetry_report.ios_copy_verify_state({}, "img") == "not_run"
    state = {"img": {"copied": True}}
    assert telemetry_report.ios_copy_verify_state(state, "img") == "not_run"


def test_reader_rejects_garbage_values():
    state = {"img": {"tele": {"content_sha256_state": "true",
                              "ios_copy_verify_state": "yes"}}}
    assert telemetry_report.content_sha256_state(state, "img") == "not_checked"
    assert telemetry_report.ios_copy_verify_state(state, "img") == "not_run"


# ---- decision-point persistence in run_once ----

def test_verify_pass_persists_verified_and_copy_ok():
    cat = _Cat({"approved_image_id": "img1"}, _IMG)
    state = {}
    assert iris_agent.run_once(_CFG, _deps(cat, {"/stage/img1.bin": 5}),
                               state) == "complete"
    assert telemetry_report.content_sha256_state(state, "img1") == "verified"
    assert telemetry_report.ios_copy_verify_state(state, "img1") == "not_run"


def test_verify_mismatch_persists_mismatch():
    cat = _Cat({"approved_image_id": "img1"}, _IMG)
    state = {}
    deps = _deps(cat, {"/stage/img1.bin": 5}, verify=lambda p, sha: False)
    assert iris_agent.run_once(_CFG, deps, state) == "bad-sha"
    assert telemetry_report.content_sha256_state(state, "img1") == "mismatch"
    # no copy decision was reached -> copy state stays not_run
    assert telemetry_report.ios_copy_verify_state(state, "img1") == "not_run"


def test_copy_failure_persists_failed_independent_of_sha():
    cat = _Cat({"approved_image_id": "img1"}, _IMG)
    state = {}
    deps = _deps(cat, {"/stage/img1.bin": 5},
                 copy_to_root=lambda f, tp="flash:", expected_size=None: False)
    iris_agent.run_once(_CFG, deps, state)
    # content verify still passed (independent fact)
    assert telemetry_report.content_sha256_state(state, "img1") == "verified"
    assert telemetry_report.ios_copy_verify_state(state, "img1") == "not_run"


def test_running_image_unknown_is_not_a_copy_decision():
    cat = _Cat({"approved_image_id": "img1"}, _IMG)
    state = {}
    deps = _deps(
        cat, {"/stage/img1.bin": 5},
        copy_to_root=lambda f, tp="flash:", expected_size=None:
            iris_agent.ROOT_COPY_RUNNING_IMAGE_UNKNOWN)
    iris_agent.run_once(_CFG, deps, state)
    # verify passed, but the transient running-image-unknown is NOT a
    # copy /verify decision -> copy state remains not_run (no false 'failed').
    assert telemetry_report.content_sha256_state(state, "img1") == "verified"
    assert telemetry_report.ios_copy_verify_state(state, "img1") == "not_run"
