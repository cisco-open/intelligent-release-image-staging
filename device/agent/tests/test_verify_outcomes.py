# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Task 18 — explicit persisted verification outcomes (spec §3D).

content_sha256_state (verified|mismatch|not_checked) is written WHEN run_once
makes the content-hash verify decision, and the report reads it VERBATIM —
never inferred from done/copied or absence, never 'false' for unchecked.

ios_copy_verify_state (ok|failed|not_run|unsupported) is retained for wire
compatibility only. There is no copy-verify step anymore, nothing writes the
key, and its reader is AUTHORITATIVE rather than verbatim: it answers
'not_run' unconditionally so an upgraded device cannot keep reporting the
stale 'ok' its previous agent persisted. The two facts stay independent.
"""
import time as _time

import pytest

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
        catalog=cat, emit=lambda *a: None, boot_image=lambda: "running.bin",
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
        checkpoint=lambda s: None, aria_session=lambda: None)
    base.update(over)
    return iris_agent.Deps(**base)


# ---- reader defaults (never inferred) ----

def test_content_sha256_state_defaults_not_checked():
    assert telemetry_report.content_sha256_state({}, "img") == "not_checked"
    # a done/copied image with no persisted verify fact is STILL not_checked
    state = {"img": {"done": True, "copied": True}}
    assert telemetry_report.content_sha256_state(state, "img") == "not_checked"


def test_ios_copy_verify_state_is_always_not_run():
    assert telemetry_report.ios_copy_verify_state({}, "img") == "not_run"
    state = {"img": {"copied": True}}
    assert telemetry_report.ios_copy_verify_state(state, "img") == "not_run"


def test_ios_copy_verify_state_ignores_a_legacy_persisted_ok():
    # An in-place upgrade keeps the state file the PREVIOUS agent wrote, which
    # recorded 'ok' back when the placement really did run a copy-verify step.
    # Echoing that would make every already-staged device claim a verification
    # the code no longer performs, forever. The reader is authoritative.
    state = {"img": {"copied": True, "tele": {"ios_copy_verify_state": "ok"}}}
    assert telemetry_report.ios_copy_verify_state(state, "img") == "not_run"
    # every other legacy value is dropped the same way
    for legacy in ("failed", "unsupported", "not_run"):
        stale = {"img": {"tele": {"ios_copy_verify_state": legacy}}}
        assert telemetry_report.ios_copy_verify_state(stale, "img") == "not_run"


def test_report_emits_not_run_over_a_legacy_persisted_ok():
    # End-to-end through the wire body: the field is still present (the server
    # schema requires it) but never carries the stale verdict.
    state = {"img1": {"copied": True,
                      "tele": {"transfer_id": "a" * 32,
                               "content_sha256_state": "verified",
                               "ios_copy_verify_state": "ok"}}}
    report = telemetry_report.build_report_v2(
        {"device_id": "sw1"}, state, "img1", "staging-complete", 1200.5,
        "a" * 32, "b" * 32)
    assert report["ios_copy_verify"] == {"state": "not_run"}
    # the independent content fact IS still read verbatim
    assert report["content_sha256"]["state"] == "verified"


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
    # verify passed, but the transient running-image-unknown is not a copy
    # decision either -> copy state remains not_run (no false 'failed').
    assert telemetry_report.content_sha256_state(state, "img1") == "verified"
    assert telemetry_report.ios_copy_verify_state(state, "img1") == "not_run"


# ---- the verdict is scoped to the TRANSFER it describes (board #28) ----
#
# content_sha256_state says "THIS transfer hashed THESE bytes and they
# matched". It is stored under the image id, so without an explicit drop it
# outlives the transfer it describes and is then read VERBATIM into a report
# for a transfer in which sha256_matches() never ran. The three boundaries
# below are where the bytes it describes stop being the bytes on disk. The
# repair is always the same one: DROP the verdict, never invent a fresh one —
# absence reads back as 'not_checked', which is the honest wire shape for "not
# measured".

_IMG2 = {"id": "img2", "filename": "img2.bin", "size": 7, "sha256": "def"}


class _SetCat(_Cat):
    """A catalog for a two-image fleet whose assignment set can be reassigned
    between ticks (the park pass only runs for a NON-empty set)."""

    def get_image(self, iid):
        return {"img1": _IMG, "img2": _IMG2}.get(iid)


def _assign(cat, *ids):
    cat._policy = {"approved_image_id": ids[0] if ids else None,
                   "approved_image_ids": list(ids)}


def test_clear_transfer_drops_the_verify_verdict_with_the_identity():
    """The park pass IS the acquisition-cycle boundary, and the verdict is
    scoped to the acquisition, not to the image id."""
    state = {"img1": {"done": True, "copied": True,
                      "tele": {"transfer_id": "a" * 32, "sample_seq": 4,
                               "content_sha256_state": "verified",
                               "started_ts": 1000.0}}}
    telemetry_report.clear_transfer(state, "img1")
    tele = state["img1"]["tele"]
    assert "transfer_id" not in tele
    assert "sample_seq" not in tele
    assert "content_sha256_state" not in tele
    assert telemetry_report.content_sha256_state(state, "img1") == "not_checked"
    # everything that is NOT scoped to the transfer stays exactly as it was
    assert tele["started_ts"] == 1000.0
    assert state["img1"]["done"] is True and state["img1"]["copied"] is True


def test_a_parked_and_reassigned_image_reports_no_stale_verified():
    """The full park -> re-acquire cycle. A fresh transfer_id is minted and
    aria2 re-downloads from zero, so every report built while those bytes are
    in flight must say 'not_checked' — the previous cycle's verdict describes
    a file park deleted."""
    cat = _SetCat({}, _IMG)
    _assign(cat, "img1")
    sizes = {"/stage/img1.bin": 5}
    state = {}
    assert iris_agent.run_once(_CFG, _deps(cat, sizes), state) == "complete"
    assert telemetry_report.content_sha256_state(state, "img1") == "verified"
    first_tid = state["img1"]["tele"]["transfer_id"]

    # img1 leaves the set: park stops the torrent and deletes the stage copy.
    _assign(cat, "img2")
    iris_agent.run_once(_CFG, _deps(cat, sizes), state)
    assert state["img1"]["parked"] is True
    assert "/stage/img1.bin" not in sizes

    # ...and comes back. Nothing is staged, so this is a fresh acquisition.
    _assign(cat, "img1")
    assert iris_agent.run_once(_CFG, _deps(cat, sizes), state) == "downloading"
    assert state["img1"]["tele"]["transfer_id"] != first_tid
    assert telemetry_report.content_sha256_state(state, "img1") == "not_checked"
    report = telemetry_report.build_report_v2(
        _CFG, state, "img1", "pull", 1200.0,
        state["img1"]["tele"]["transfer_id"], "b" * 32)
    assert report["content_sha256"] == {"state": "not_checked"}


def test_a_local_loss_drops_the_verdict_while_keeping_the_transfer_id():
    """The other half of the same rule, and the one the park drop cannot
    cover: a changed-content / local-loss boundary deliberately REUSES the
    stored transfer_id, so the verdict left behind would be read back for the
    very same transfer that is now re-downloading the file."""
    cat = _Cat({"approved_image_id": "img1"}, _IMG)
    sizes = {"/stage/img1.bin": 5}
    state = {}
    assert iris_agent.run_once(_CFG, _deps(cat, sizes), state) == "complete"
    tid = state["img1"]["tele"]["transfer_id"]

    sizes.pop("/stage/img1.bin")          # the staged copy is gone (no unassign)
    assert iris_agent.run_once(_CFG, _deps(cat, sizes), state) == "downloading"
    assert state["img1"]["tele"]["transfer_id"] == tid   # same cycle, same id
    assert telemetry_report.content_sha256_state(state, "img1") == "not_checked"


def test_a_root_only_loss_re_measures_rather_than_inheriting_the_verdict():
    """The guard on the other side: dropping the verdict costs nothing, because
    a staged file that is still complete is HASHED again on the very same tick.
    The 'verified' that comes out the other end is a measurement, not the
    previous one kept because it was probably still true."""
    cat = _Cat({"approved_image_id": "img1"}, _IMG)
    sizes = {"/stage/img1.bin": 5}
    state = {}
    assert iris_agent.run_once(_CFG, _deps(cat, sizes), state) == "complete"

    present = {"n": 0}
    hashed = []

    def _root_present(f, prefix="flash:", expected_size=None):
        present["n"] += 1
        return present["n"] > 1           # missing on the first look this tick

    def _verify(path, sha):
        hashed.append((path, sha))
        return True

    iris_agent.run_once(_CFG, _deps(cat, sizes, root_present=_root_present,
                                    verify=_verify), state)
    assert hashed == [("/stage/img1.bin", "abc")]
    assert telemetry_report.content_sha256_state(state, "img1") == "verified"


def test_a_mismatch_lowers_done_so_the_record_cannot_claim_both():
    """'done' means "content verified against the catalog"; a mismatch is the
    proof it is not. Left set, the record reads done=True beside
    content_sha256_state='mismatch' for the same bytes."""
    cat = _Cat({"approved_image_id": "img1"}, _IMG)
    # done from a PREVIOUS cycle, placement never finished, so the tick falls
    # through the steady-state short-circuit into the download path's verify.
    state = {"schema_version": 2, "img1": {"done": True, "sha": "abc"}}
    deps = _deps(cat, {"/stage/img1.bin": 5}, verify=lambda p, sha: False)
    assert iris_agent.run_once(_CFG, deps, state) == "bad-sha"
    assert telemetry_report.content_sha256_state(state, "img1") == "mismatch"
    assert state["img1"]["done"] is False


@pytest.mark.parametrize("platform,io_transfer,copy_in_place,target_fs", [
    ("", False, False, "flash:"),          # Guest Shell on a switch
    ("iox", True, False, "sdflash:"),      # IOx placement through IOS
    ("", False, False, "bootflash:"),      # router Guest Shell
    ("xr-appmgr", False, True, "harddisk:"),
])
@pytest.mark.parametrize("replan", [False, True])
def test_hash_failure_heartbeats_immediately_and_next_tick_can_retry(
        platform, io_transfer, copy_in_place, target_fs, replan):
    """A failed verification must replace the previous visible stage state.

    Exercise both the ordinary download verification and the already-staged
    replan path through the shared loop used by every device runtime.
    """
    policy = {"approved_image_id": "img1"}
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "stage_fs": target_fs}
    if replan:
        state["img1"] = {"done": True, "copied": True, "sha": "abc",
                         "tele": {"plan_id": "1" * 32,
                                  "transfer_id": "a" * 32}}
        policy["plans"] = {"img1": {"plan_id": "2" * 32,
                                    "transfer_id": "b" * 32}}
    cfg = dict(_CFG, device_platform=platform, announce_token="test-announce")
    cat = _Cat(policy, _IMG)
    sizes = {"/stage/img1.bin": 5}
    deps = _deps(cat, sizes, verify=lambda p, sha: False,
                 io_transfer=io_transfer, copy_in_place=copy_in_place,
                 target_fs=lambda: (target_fs, 9_000_000_000))

    assert iris_agent.run_once(cfg, deps, state) == "bad-sha"
    assert len(cat.heartbeats) == 1
    failed = cat.heartbeats[-1]
    assert failed["current_image_id"] == "img1"
    assert failed["stage_state"] == "error"
    assert "SHA-256" in failed["stage_error"]
    assert failed["target_fs"] == target_fs
    assert "/stage/img1.bin" not in sizes
    assert cat.telemetry == []              # a failure is no completion report

    assert iris_agent.run_once(cfg, deps, state) == "downloading"
    assert cat.heartbeats[-1]["stage_state"] == "staging"
    assert cat.heartbeats[-1]["stage_error"] is None


@pytest.mark.parametrize("failed_id", ["img1", "img2"])
@pytest.mark.parametrize("replan", [False, True])
def test_hash_failure_is_counted_in_set_heartbeat(failed_id, replan):
    """A good sibling must not hide an image whose bytes failed verification."""
    good_id = "img2" if failed_id == "img1" else "img1"
    cat = _SetCat({}, _IMG)
    _assign(cat, "img1", "img2")
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             good_id: {"done": True, "copied": True}}
    if replan:
        state[failed_id] = {"done": True, "copied": True,
                            "tele": {"plan_id": "1" * 32,
                                     "transfer_id": "a" * 32}}
        cat._policy["plans"] = {
            failed_id: {"plan_id": "2" * 32, "transfer_id": "b" * 32}}
    sizes = {"/stage/img1.bin": 5, "/stage/img2.bin": 7}
    deps = _deps(cat, sizes, verify=lambda p, sha: False)

    expected = ("multi:bad-sha,complete" if failed_id == "img1"
                else "multi:complete,bad-sha")
    assert iris_agent.run_once(_CFG, deps, state) == expected
    assert len(cat.heartbeats) == 1
    hb = cat.heartbeats[-1]
    assert hb["stage_state"] == "error"
    assert hb["staged_image_ids"] == [good_id]
    assert hb["errored_image_ids"] == [failed_id]
    assert "SHA-256" in hb["stage_error"]
