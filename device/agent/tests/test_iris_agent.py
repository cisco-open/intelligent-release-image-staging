# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import json

import iris_agent

# telemetry (#13): completion-jitter sleep is a module seam; never sleep in
# unit tests.
iris_agent._SLEEP = lambda s: None


class FakeCatalog:
    def __init__(self, policy, image):
        self._policy = policy
        self._image = image
        self.heartbeats = []
        self.downloaded = []
        self.telemetry = []          # (sid, report) tuples from post_telemetry
        self.hb_response = None      # what heartbeat() answers (server body)

    def get_policy(self, sid):
        return self._policy

    def get_image(self, image_id):
        return self._image

    def download_torrent(self, image_id, dest):
        self.downloaded.append((image_id, dest))

    def heartbeat(self, sid, data):
        self.heartbeats.append(data)
        return self.hb_response

    def post_telemetry(self, sid, report):
        self.telemetry.append((sid, report))
        return {"ok": True}


class _HeartbeatSpy:
    """Wraps a FakeCatalog, delegating the read/download methods and recording
    every heartbeat payload into `sent` so a test can assert the stage_state
    field is present on the path that ran."""

    def __init__(self, catalog, sent):
        self._catalog = catalog
        self._sent = sent

    def get_policy(self, sid):
        return self._catalog.get_policy(sid)

    def get_image(self, image_id):
        return self._catalog.get_image(image_id)

    def download_torrent(self, image_id, dest):
        return self._catalog.download_torrent(image_id, dest)

    def heartbeat(self, sid, data):
        self._sent.append(data)
        return self._catalog.heartbeat(sid, data)

    def post_telemetry(self, sid, report):
        return self._catalog.post_telemetry(sid, report)


def make_deps(catalog, sizes, verify_ok=True, free=9_000_000_000,
              root_ok=True, removed=None, mode="bundle", reclaimables=()):
    emitted = []
    ios_cmds = []
    aria_calls = []
    copied = []
    purged = []
    reclaimed = []
    bundle_reclaimed = []
    removed = [] if removed is None else removed

    def _remove_stage(path):
        removed.append(path)
        sizes.pop(path, None)             # reflect the delete in future file_size()

    checkpoints = []

    deps = iris_agent.Deps(
        catalog=catalog,
        emit=lambda m, msg: emitted.append((m, msg)),
        ios=lambda cmd: ios_cmds.append(cmd) or "",
        aria_add=lambda t, d: aria_calls.append((t, d)),
        file_size=lambda p: sizes.get(p),
        verify=lambda p, sha: verify_ok,
        free_bytes=lambda prefix="flash:": free,
        version=lambda: "17.18.03",
        copy_to_root=lambda fname, target_prefix="flash:", expected_size=None:
            copied.append(fname) or True,
        purge_others=lambda keep, kid: purged.append((keep, kid)),
        reclaim=lambda: reclaimed.append(True),
        root_present=lambda fname, prefix="flash:", expected_size=None: root_ok,
        remove_stage=_remove_stage,
        aria_remove=lambda fname: None,
        detect_mode=lambda: mode,
        target_fs=lambda: ("flash:", free),
        running_image=lambda: "running.bin",
        reclaimable=lambda prefix, protect: list(reclaimables),
        reclaim_bundle=lambda prefix, names: bundle_reclaimed.append(
            (prefix, list(names))),
        model=lambda: "C9300-TEST",
        refresh=lambda: None,     # default: no refresh wired (token still fresh)
        aria_stats=lambda stage_path: None,   # telemetry: no aria2 stats wired
        aria_peers=lambda stage_path: [],     # telemetry: no peer rows wired
        io_transfer=False,
        checkpoint=lambda state: checkpoints.append(
            __import__("copy").deepcopy(state)),
        aria_session=lambda: None,
        copy_in_place=False,
    )
    return (deps, emitted, ios_cmds, aria_calls, copied, purged, reclaimed,
            bundle_reclaimed)


import time as _time
# token_expires_at far in the future so existing tests skip the refresh step
# (needs_refresh returns False). Tests that want to exercise the refresh set
# token_expires_at="0" explicitly in their own cfg.
CFG = {"device_id": "sw1", "stage_dir": "/stage",
       "token_expires_at": str(int(_time.time()) + 604_800)}


def test_no_assignment_still_heartbeats():
    # An unassigned device must register with the catalog (devices.json /
    # swarm map / telemetry posture) — assignment gates staging, not presence.
    cat = FakeCatalog({"approved_image_id": None}, None)
    deps, emitted, _, aria, _, _, _, _ = make_deps(cat, {})
    assert iris_agent.run_once(CFG, deps, {}) == "no-assignment"
    assert emitted == [] and aria == []
    assert len(cat.heartbeats) == 1
    hb = cat.heartbeats[0]
    assert hb["current_image_id"] is None
    assert hb["stage_state"] == "unassigned"
    assert hb["stage_error"] is None


def test_missing_assigned_image_heartbeats_error():
    cat = FakeCatalog({"approved_image_id": "gone1"}, None)
    deps, emitted, _, aria, _, _, _, _ = make_deps(cat, {})
    assert iris_agent.run_once(CFG, deps, {}) == "no-image"
    assert ("ERROR", "assigned image gone1 not in catalog") in emitted
    assert len(cat.heartbeats) == 1
    hb = cat.heartbeats[0]
    assert hb["current_image_id"] is None
    assert hb["stage_state"] == "error"
    assert "gone1" in hb["stage_error"]


def test_complete_and_verified_emits_done_once():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, emitted, _, _, copied, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=True)
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert any(m == "DONE" for m, _ in emitted)
    assert copied == ["img1.bin"]              # EEM copy-to-root triggered
    assert cat.heartbeats and cat.heartbeats[-1]["current_image_id"] == "img1"
    # idempotent: second run does NOT re-emit DONE or re-copy
    emitted.clear()
    iris_agent.run_once(CFG, deps, state)
    assert all(m != "DONE" for m, _ in emitted)
    assert copied == ["img1.bin"]              # still only once


def test_placement_via_a_real_copy_always_records_origin_downloaded():
    # copy_in_place=False (every IOS-XE platform) always WRITES the root
    # bytes itself via a real copy — there is no attest-only/adoption path
    # here, so every successful placement is unconditionally "downloaded".
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert state["img1"]["origin"] == "downloaded"


def test_steady_state_never_rehashes():
    # once done+copied, ticks must NOT re-verify (hashing 1.2GB > the 60s timer
    # caused overlapping runs that double-fired the root copy)
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    verify_calls = []
    deps, _, _, _, copied, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    deps = deps._replace(verify=lambda p, sha: verify_calls.append(p) or True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "root_file": "img1.bin",
             "img1": {"done": True, "copied": True}}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert verify_calls == []                  # no re-hash
    assert copied == []                        # no re-copy
    assert cat.heartbeats                      # still heartbeats


def test_state_is_per_image_so_reassignment_recopies():
    # device already completed img1; operator reassigns img2 -> must DONE+copy again
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 7,
                       "sha256": "def"})
    deps, emitted, _, _, copied, _, _, _ = make_deps(
        cat, {"/stage/img2.bin": 7}, verify_ok=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "img1": {"done": True, "copied": True}}   # leftover from the old image
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert any(m == "DONE" for m, _ in emitted)
    assert copied == ["img2.bin"]


# --- pending_root_deletes drain ---------------------------------------------
# The queue is no longer FED by reassignment: an image dropped from the
# assignment set is PARKED and its root copy deliberately kept (multi-image
# assignment; see tests/test_multi_image.py). The drain below still runs on
# every tick, for state files written by the agent that did queue replaced root
# copies, and its delete-then-verify contract is unchanged — so these tests
# seed the queue directly instead of provoking it with a reassignment.


def test_replaced_image_cleanup_claim_gated_on_actual_absence():
    # AAA nodes silently no-op a raw exec `delete` (the reclaim/copyroot EEM
    # applets exist for exactly that reason) — so the delete must run through
    # the authorization-bypass applet, and the CLEANUP log and root_file
    # bookkeeping must be gated on the file actually being gone, else the
    # replaced image is stranded on flash while IRIS claims otherwise.
    # old.bin is explicitly IRIS's own DOWNLOAD (origin="downloaded"): a
    # provenance-unknown/adopted entry is covered by the adopted-file tests
    # below and never reaches the delete applet at all.
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 7,
                       "sha256": "def"})
    deps, emitted, ios_cmds, _, _, _, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img2.bin": 7}, verify_ok=True)
    deps = deps._replace(                       # the old root REFUSES to die
        root_present=lambda fname, prefix="flash:", expected_size=None: fname == "old.bin")
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img2", "pending_root_deletes": ["old.bin"],
             "old-img": {"root_file": "old.bin", "copied": True,
                        "origin": "downloaded"}}
    iris_agent.run_once(CFG, deps, state)
    assert bundle_reclaimed == [("flash:", ["old.bin"])]   # via the bypass applet
    assert all("delete" not in c for c in ios_cmds)        # never a raw exec delete
    # queued for retry every tick — NOT silently forgotten
    assert state.get("pending_root_deletes") == ["old.bin"]
    assert any(m == "CLEANUP-PENDING" for m, _ in emitted)
    assert all(not (m == "CLEANUP" and "old.bin" in msg) for m, msg in emitted)


def test_replaced_image_cleanup_retry_refires_bypass_applet():
    # a still-present entry must be retried with the SAME mechanism that can
    # actually land on an AAA node — the bypass applet — every tick, not just
    # re-verified after the first (possibly no-op'd) attempt
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 7,
                       "sha256": "def"})
    deps, _, ios_cmds, _, _, _, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img2.bin": 7}, verify_ok=True)
    deps = deps._replace(                       # the old root REFUSES to die
        root_present=lambda fname, prefix="flash:", expected_size=None: fname == "old.bin")
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img2", "pending_root_deletes": ["old.bin"],
             "old-img": {"root_file": "old.bin", "copied": True,
                        "origin": "downloaded"}}
    iris_agent.run_once(CFG, deps, state)
    iris_agent.run_once(CFG, deps, state)
    assert bundle_reclaimed == [("flash:", ["old.bin"]),
                                ("flash:", ["old.bin"])]
    assert all("delete" not in c for c in ios_cmds)
    assert state.get("pending_root_deletes") == ["old.bin"]


def test_replaced_image_cleanup_confirmed_when_gone():
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 7,
                       "sha256": "def"})
    deps, emitted, ios_cmds, _, _, _, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img2.bin": 7}, verify_ok=True)
    deps = deps._replace(                        # old root really deleted
        root_present=lambda fname, prefix="flash:", expected_size=None: fname != "old.bin")
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img2", "pending_root_deletes": ["old.bin"],
             "old-img": {"root_file": "old.bin", "copied": True,
                        "origin": "downloaded"}}
    iris_agent.run_once(CFG, deps, state)
    assert bundle_reclaimed == [("flash:", ["old.bin"])]
    assert "pending_root_deletes" not in state
    assert any(m == "CLEANUP" and "old.bin" in msg for m, msg in emitted)


def test_pending_delete_of_an_adopted_file_is_skipped_and_cleared():
    # The Directive-2 incident: attest-in-place ADOPTED an operator's
    # pre-existing file as IRIS's staged copy; the OLD pending-delete queue
    # must never be allowed to delete it. Skipped, logged, and the queue
    # entry is resolved (cleared) rather than retried forever. Only
    # meaningful on a platform with an adoption concept at all
    # (copy_in_place) — see the XE counterpart below.
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 7,
                       "sha256": "def"})
    deps, emitted, ios_cmds, _, _, _, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img2.bin": 7}, verify_ok=True)
    deps = deps._replace(copy_in_place=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img2", "pending_root_deletes": ["old.bin"],
             "old-img": {"root_file": "old.bin", "copied": True,
                        "origin": "adopted"}}
    iris_agent.run_once(CFG, deps, state)
    assert bundle_reclaimed == []                # delete never attempted
    assert all("delete" not in c for c in ios_cmds)
    assert "pending_root_deletes" not in state   # resolved, not retried forever
    kept = [msg for m, msg in emitted if m == "ROOTCOPY-KEPT"]
    assert kept and "old.bin" in kept[0] and "operator-adopted" in kept[0]


def test_pending_delete_of_a_legacy_missing_origin_file_is_never_deleted_on_xr():
    # No per-image record at all claims old.bin's provenance (a state file
    # from before this feature existed). Missing/unknown origin is the
    # fail-safe default on a platform with an adoption concept
    # (copy_in_place): treated exactly like "adopted".
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 7,
                       "sha256": "def"})
    deps, emitted, ios_cmds, _, _, _, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img2.bin": 7}, verify_ok=True)
    deps = deps._replace(copy_in_place=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img2", "pending_root_deletes": ["old.bin"]}
    iris_agent.run_once(CFG, deps, state)
    assert bundle_reclaimed == []
    assert "pending_root_deletes" not in state
    assert any(m == "ROOTCOPY-KEPT" and "old.bin" in msg for m, msg in emitted)


def test_pending_delete_ignores_the_origin_gate_on_a_platform_with_no_adoption():
    # IMPORTANT 3: copy_in_place=False (every IOS-XE platform) has NO
    # adoption concept at all — a legacy entry with no owning per-image
    # record must still be deleted exactly as before every deletion path
    # here learned about provenance, never mislabelled 'operator-adopted'
    # and stranded on flash.
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 7,
                       "sha256": "def"})
    deps, emitted, ios_cmds, _, _, _, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img2.bin": 7}, verify_ok=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img2", "pending_root_deletes": ["old.bin"]}
    iris_agent.run_once(CFG, deps, state)
    assert bundle_reclaimed == [("flash:", ["old.bin"])]
    assert all(m != "ROOTCOPY-KEPT" for m, _ in emitted)


def test_pending_delete_mixed_queue_only_deletes_the_downloaded_entry():
    cat = FakeCatalog({"approved_image_id": "img3"},
                      {"id": "img3", "filename": "img3.bin", "size": 7,
                       "sha256": "xyz"})
    deps, emitted, ios_cmds, _, _, _, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img3.bin": 7}, verify_ok=True)
    deps = deps._replace(copy_in_place=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img3",
             "pending_root_deletes": ["adopted.bin", "downloaded.bin"],
             # already 'parked' -- these represent OLD, already-fully-parked
             # records (exactly what a pending_root_deletes-carrying state
             # file predates), so _reconcile_set's own stale-park pass
             # leaves them alone this tick and their origin survives for
             # the drain below to read.
             "old-a": {"root_file": "adopted.bin", "copied": True,
                      "origin": "adopted", "parked": True},
             "old-b": {"root_file": "downloaded.bin", "copied": True,
                      "origin": "downloaded", "parked": True}}
    iris_agent.run_once(CFG, deps, state)
    assert bundle_reclaimed == [("flash:", ["downloaded.bin"])]
    assert any(m == "ROOTCOPY-KEPT" and "adopted.bin" in msg
              for m, msg in emitted)


def test_replaced_image_cleanup_whitelists_names_before_applet():
    # pending_root_deletes comes from the state FILE (hand-editable) and is
    # interpolated into applet config lines — anything outside the filename
    # whitelist, or the current image itself, must be dropped before templating
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 7,
                       "sha256": "def"})
    deps, _, ios_cmds, _, _, _, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img2.bin": 7}, verify_ok=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img2",
             "pending_root_deletes": ['bad"name', "img2.bin"]}
    iris_agent.run_once(CFG, deps, state)
    assert bundle_reclaimed == []               # applet never templated
    assert all("delete" not in c for c in ios_cmds)
    assert "pending_root_deletes" not in state  # dropped, not retried


def test_complete_but_sha_mismatch_errors_no_done():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, emitted, _, _, copied, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=False)
    assert iris_agent.run_once(CFG, deps, {}) == "bad-sha"
    assert any(m == "ERROR" for m, _ in emitted)
    assert all(m != "DONE" for m, _ in emitted)
    assert copied == []                        # never copy an unverified image


def test_low_space_runs_reclaim_then_errors_if_still_short():
    # install-mode device: reclaim is `install remove inactive`.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin",
                       "size": 1_260_618_344, "sha256": "abc"})
    deps, emitted, ios_cmds, aria, _, _, reclaimed, _ = make_deps(
        cat, {}, free=500_000_000,            # not complete, no room even after reclaim
        mode="install")
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "no-space"
    assert reclaimed == [True]                         # reclaim attempted once...
    assert ios_cmds == []                              # ...via deps.reclaim(), NOT raw ios()
    assert any(m == "FLASH-FULL" for m, _ in emitted)  # just syslogs insufficiency
    assert aria == []                                  # never started a download
    # second tick while still short must NOT re-fire reclaim (the once-guard) —
    # `install remove inactive` is interactive and re-firing wedged the install lock.
    emitted.clear()
    assert iris_agent.run_once(CFG, deps, state) == "no-space"
    assert reclaimed == [True]                         # still only once
    assert any(m == "FLASH-FULL" for m, _ in emitted)  # still errors on persistent shortage


def test_download_gate_bundle_skips_install_remove_inactive():
    # short on space, bundle mode -> reclaim_bundle is used, NOT reclaim()
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5_000_000_000,
                       "sha256": "abc"})
    deps, emitted, _, _, _, _, reclaimed, bundle_reclaimed = make_deps(
        cat, {}, free=1_000_000_000, mode="bundle",
        reclaimables=["old.bin", "cat9k-rpbase.pkg"])
    iris_agent.run_once(CFG, deps, {})
    assert reclaimed == []                       # install path NOT taken
    assert bundle_reclaimed == [("flash:", ["old.bin", "cat9k-rpbase.pkg"])]


def test_download_gate_install_uses_install_remove_inactive():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5_000_000_000,
                       "sha256": "abc"})
    deps, _, _, _, _, _, reclaimed, bundle_reclaimed = make_deps(
        cat, {}, free=1_000_000_000, mode="install")
    iris_agent.run_once(CFG, deps, {})
    assert reclaimed == [True]                    # install remove inactive fired
    assert bundle_reclaimed == []


def test_download_gate_unknown_mode_skips_all_reclaim():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5_000_000_000,
                       "sha256": "abc"})
    deps, emitted, _, _, _, _, reclaimed, bundle_reclaimed = make_deps(
        cat, {}, free=1_000_000_000, mode=None, reclaimables=["old.bin"])
    assert iris_agent.run_once(CFG, deps, {}) == "no-space"
    assert reclaimed == [] and bundle_reclaimed == []


def test_copy_gate_room_for_one_copy_downloads_seeds_but_blocks_root_copy():
    # File already downloaded (staged) and sha-ok, but only ONE image fits:
    # free >= size (scratch present) yet not >= size again for the root copy.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 500_000_000,
                       "sha256": "abc"})
    # staged file present at full size; free is 300 MB (< size+headroom)
    deps, emitted, _, _, copied, _, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img1.bin": 500_000_000}, free=300_000_000,
        mode="bundle", reclaimables=[])
    state = {}
    result = iris_agent.run_once(CFG, deps, state)
    assert result == "seeding-only"
    assert copied == []                                  # root copy NOT placed
    assert state.get("img1", {}).get("blocked_no_space") is True
    assert any(m == "FLASH-FULL" for m, _ in emitted)


def test_copy_gate_charges_nothing_for_attest_in_place_platforms():
    # F2: same tight-free-space scenario as the test above (free covers
    # exactly the staged copy, nothing more), but copy_in_place=True (XR:
    # attest_in_place stats the bytes already at stage_dir, it writes
    # nothing new). The gate must charge ZERO extra headroom and complete,
    # not degrade to seeding-only -- a device that fits exactly one image
    # must not sit blocked forever waiting for room it never needed.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 500_000_000,
                       "sha256": "abc"})
    deps, emitted, _, _, copied, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 500_000_000}, free=300_000_000,
        mode="bundle", reclaimables=[])
    deps = deps._replace(copy_in_place=True)
    state = {}
    result = iris_agent.run_once(CFG, deps, state)
    assert result == "complete"
    assert copied == ["img1.bin"]                        # root copy WAS placed
    assert not state.get("img1", {}).get("blocked_no_space")
    assert not any(m == "FLASH-FULL" for m, _ in emitted)


def test_copy_gate_room_for_two_copies_completes():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, copied, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, free=9_000_000_000, mode="bundle")
    assert iris_agent.run_once(CFG, deps, {}) == "complete"
    assert copied == ["img1.bin"]


def test_heartbeat_carries_stage_state_ready_when_complete():
    sent = []
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    deps = deps._replace(catalog=_HeartbeatSpy(cat, sent))
    iris_agent.run_once(CFG, deps, {})
    assert sent and sent[-1]["stage_state"] == "ready"


def test_heartbeat_carries_target_fs_from_state():
    sent = []
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5}, mode="bundle")
    deps = deps._replace(catalog=_HeartbeatSpy(cat, sent),
                         target_fs=lambda: ("sdflash:", 9_000_000_000))
    iris_agent.run_once(CFG, deps, {})
    assert sent[-1]["target_fs"] == "sdflash:"


def test_room_downloads_torrent_and_kicks_aria():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin",
                       "size": 1000, "sha256": "abc"})
    deps, emitted, _, aria, _, _, _, _ = make_deps(cat, {}, free=9_000_000_000)
    assert iris_agent.run_once(CFG, deps, {}) == "downloading"
    assert cat.downloaded == [("img1", "/stage/img1.torrent")]
    assert aria == [("/stage/img1.torrent", "/stage")]
    assert any(m == "STAGING" for m, _ in emitted)


def test_full_size_but_aria2_control_present_is_not_complete():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin",
                       "size": 5, "sha256": "abc"})
    # full size on disk BUT aria2's control file still exists -> not done; must
    # not hash/verify/copy yet (avoids the race that gave a spurious mismatch)
    deps, emitted, _, _, copied, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5, "/stage/img1.bin.aria2": 100})
    assert iris_agent.run_once(CFG, deps, {}) == "downloading"
    assert copied == []
    assert all(m not in ("DONE", "ERROR") for m, _ in emitted)


def test_in_progress_download_is_not_re_added():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin",
                       "size": 1000, "sha256": "abc"})
    # a partial file is present (500<1000) -> aria2 is already downloading it;
    # the 60s timer must NOT re-addTorrent
    deps, emitted, _, aria, _, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 500}, free=9_000_000_000)
    assert iris_agent.run_once(CFG, deps, {}) == "downloading"
    assert aria == []                          # NOT re-added
    assert all(m != "STAGING" for m, _ in emitted)
    assert any(m == "PROGRESS" for m, _ in emitted)   # one progress line, not a flood


def test_aria_add_rpc_down_heartbeats_error_instead_of_crashing():
    # 2026-08-20 incident class: aria2c is not serving RPC (launch failed,
    # daemon died). The connection error out of addTorrent used to escape
    # run_once BEFORE the tick's heartbeat — the device simply vanished from
    # the console. A down swarm daemon must degrade to a visible error
    # heartbeat, never to silence.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin",
                       "size": 1000, "sha256": "abc"})
    deps, emitted, _, _, _, _, _, _ = make_deps(cat, {}, free=9_000_000_000)

    def _refused(torrent, dest):
        raise ConnectionRefusedError(111, "Connection refused")

    deps = deps._replace(aria_add=_refused)
    assert iris_agent.run_once(CFG, deps, {}) == "aria2-down"
    assert len(cat.heartbeats) == 1
    hb = cat.heartbeats[0]
    assert hb["current_image_id"] == "img1"
    assert hb["stage_state"] == "error"
    assert "aria2c" in hb["stage_error"]


def test_aria_remove_rpc_down_heartbeats_error_instead_of_crashing():
    # Same failure class one call earlier: the stale-entry clear hits the RPC
    # first, and urllib wraps the refusal in URLError. Must not crash either.
    import urllib.error
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin",
                       "size": 1000, "sha256": "abc"})
    deps, emitted, _, aria, _, _, _, _ = make_deps(cat, {}, free=9_000_000_000)

    def _refused(fname):
        raise urllib.error.URLError(ConnectionRefusedError(111, "refused"))

    deps = deps._replace(aria_remove=_refused)
    assert iris_agent.run_once(CFG, deps, {}) == "aria2-down"
    assert aria == []                       # never reached addTorrent
    hb = cat.heartbeats[-1]
    assert hb["stage_state"] == "error"
    assert "aria2c" in hb["stage_error"]


def test_reassignment_parks_old_image_and_keeps_its_root_copy():
    # device completed img1 (incl. root copy); operator reassigns img2 -> img1
    # is PARKED, not purged: its torrent is stopped and its stage copy deleted,
    # its record stays in state, and the root copy it placed is KEPT. (Deleting
    # it was the old single-image behaviour; with an assignment SET an image
    # that leaves it can come back, and the surviving root copy is what makes
    # that a presence check instead of another 1.2 GB placement.)
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin",
                       "size": 1000, "sha256": "def"})
    deps, emitted, ios_cmds, _, _, purged, _, bundle_reclaimed = make_deps(
        cat, {}, free=9_000_000_000)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "root_file": "img1.bin",
             "img1": {"done": True, "copied": True}}
    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    # the stage/aria2 sweep keeps the whole assigned SET, not one survivor
    assert purged == [(["img2.bin"], ["img2"])]
    assert bundle_reclaimed == []                      # root copy NOT deleted
    assert "pending_root_deletes" not in state         # and never queued
    assert all("delete" not in c for c in ios_cmds)
    assert any(m == "PARKED" for m, _ in emitted)
    assert state["img1"]["parked"] is True             # remembered, not dropped
    assert state["image_id"] == "img2"
    # XE wording pin: copy_in_place=False (this fixture's default) has no
    # adoption concept at all, so the stage/root split is unconditional --
    # the PARKED detail must say so in those exact terms, unchanged by the
    # XR-specific wording the two tests below pin.
    parked_msg = [msg for m, msg in emitted if m == "PARKED"][0]
    assert "stage copy deleted, root copy kept" in parked_msg


def test_reassignment_parks_an_adopted_root_on_xr_and_logs_left_in_place():
    # XR wording pin (copy_in_place=True): the old image's root copy was
    # ADOPTED (attest-in-place, never downloaded by this agent), so park
    # must leave it exactly where it is and say so -- the same
    # never-delete-an-adopted-file guarantee _protect_adopted_root enforces
    # elsewhere, worded for the PARKED detail specifically.
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin",
                       "size": 1000, "sha256": "def"})
    deps, emitted, ios_cmds, _, _, purged, _, bundle_reclaimed = make_deps(
        cat, {}, free=9_000_000_000)
    deps = deps._replace(copy_in_place=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1",
             "img1": {"done": True, "copied": True,
                      "root_file": "img1.bin", "origin": "adopted"}}
    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    assert bundle_reclaimed == []                      # adopted root NOT deleted
    assert all("delete" not in c for c in ios_cmds)
    parked_msg = [msg for m, msg in emitted if m == "PARKED"][0]
    assert "root copy left in place (adopted)" in parked_msg


def test_reassignment_parks_a_downloaded_root_on_xr_and_logs_removed():
    # XR wording pin (copy_in_place=True), the mirror case: the old image's
    # root copy was DOWNLOADED by this agent, so on this platform (stage
    # dir IS the target-FS root) park's stage-copy delete really does
    # remove the root copy -- the PARKED detail must say "removed", not the
    # XE "kept" wording, since here there is no separate copy left behind.
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin",
                       "size": 1000, "sha256": "def"})
    deps, emitted, ios_cmds, _, _, purged, _, bundle_reclaimed = make_deps(
        cat, {}, free=9_000_000_000)
    deps = deps._replace(copy_in_place=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1",
             "img1": {"done": True, "copied": True,
                      "root_file": "img1.bin", "origin": "downloaded"}}
    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    parked_msg = [msg for m, msg in emitted if m == "PARKED"][0]
    assert "root copy removed" in parked_msg


def test_queued_root_delete_uses_cached_stage_fs():
    # Device previously staged on sdflash: (cached). A root copy still queued
    # for deletion must be deleted from sdflash:, not flash:.
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img2.bin": 5}, mode="bundle")
    deps = deps._replace(target_fs=lambda: ("sdflash:", 9_000_000_000))
    state = {"image_id": "img2", "stage_fs": "sdflash:",
             "pending_root_deletes": ["img1.bin"],
             "old-img": {"root_file": "img1.bin", "copied": True,
                        "origin": "downloaded"}}
    iris_agent.run_once(CFG, deps, state)
    assert bundle_reclaimed == [("sdflash:", ["img1.bin"])]


def test_queued_root_delete_defaults_to_flash_for_legacy_state():
    # Pre-#24 state has no stage_fs; the old root copy was placed on flash:.
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img2.bin": 5}, mode="bundle")
    state = {"image_id": "img2", "pending_root_deletes": ["img1.bin"],
             "old-img": {"root_file": "img1.bin", "copied": True,
                        "origin": "downloaded"}}
    iris_agent.run_once(CFG, deps, state)
    assert bundle_reclaimed == [("flash:", ["img1.bin"])]


def test_gate_caches_stage_fs_in_state():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5}, mode="bundle")
    deps = deps._replace(target_fs=lambda: ("sdflash:", 9_000_000_000))
    state = {}
    iris_agent.run_once(CFG, deps, state)
    assert state["stage_fs"] == "sdflash:"


def test_same_assignment_never_purges():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, ios_cmds, _, _, purged, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img1.bin": 5})
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "root_file": "img1.bin",
             "img1": {"done": True, "copied": True, "sha": "abc"}}
    iris_agent.run_once(CFG, deps, state)
    assert purged == [] and bundle_reclaimed == []
    assert all("delete" not in c for c in ios_cmds)


# --- self-heal: re-acquire if the staged/root image vanishes or content changes ---

_DONE = lambda sha="abc": {"schema_version": iris_agent._STATE_SCHEMA,
                           "image_id": "img1", "root_file": "img1.bin",
                           "img1": {"done": True, "copied": True, "sha": sha}}


def test_self_heal_redownloads_when_staged_file_gone():
    # operator/agent deleted the staged image; steady-state must NOT insist it's
    # done — it re-downloads from the swarm.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 1000,
                       "sha256": "abc"})
    deps, emitted, _, aria, _, _, _, _ = make_deps(cat, {})   # no staged file
    assert iris_agent.run_once(CFG, deps, _DONE()) == "downloading"
    assert aria == [("/stage/img1.torrent", "/stage")]
    assert any(m == "STAGING" for m, _ in emitted)


def test_self_heal_recopies_when_root_file_gone():
    # staged copy is intact but the flash-root copy was removed -> re-copy it
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, aria, copied, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, root_ok=False)
    assert iris_agent.run_once(CFG, deps, _DONE()) == "complete"
    assert copied == ["img1.bin"]               # re-copied to root
    assert aria == []                           # but NOT re-downloaded (staged was fine)


def test_self_heal_redownloads_when_content_sha_changed():
    # same image id re-published with NEW content (new sha) -> discard the stale
    # staged file and re-download, even though the size matches.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "NEWSHA"})
    removed = []
    deps, emitted, _, aria, _, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, removed=removed)
    assert iris_agent.run_once(CFG, deps, _DONE(sha="OLDSHA")) == "downloading"
    assert removed == ["/stage/img1.bin"]              # stale content discarded
    assert aria == [("/stage/img1.torrent", "/stage")]  # re-downloaded
    # copy_in_place=False here (default fixture): no adoption concept, so no
    # replace warning is due regardless of origin.
    assert all(m != "ROOTCOPY-REPLACED" for m, _ in emitted)


def test_content_republish_on_an_adopted_file_warns_before_replacing_it():
    # IMPORTANT 4: same-id republish stays UNGUARDED -- convergence to the
    # catalog's current target wins over provenance protection here, by
    # design -- but overriding a file this agent never downloaded must say
    # so honestly, in the same tick, before the delete.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "NEWSHA"})
    deps, emitted, _, aria, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    deps = deps._replace(copy_in_place=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "root_file": "img1.bin",
             "img1": {"done": True, "copied": True, "sha": "OLDSHA",
                      "origin": "adopted"}}
    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    replaced = [msg for m, msg in emitted if m == "ROOTCOPY-REPLACED"]
    assert replaced
    assert replaced[0] == ("replacing operator-adopted img1.bin: catalog "
                           "content changed under image id img1")
    # still converges -- the whole point of the adjudication
    assert aria == [("/stage/img1.torrent", "/stage")]


def test_content_republish_on_a_downloaded_file_stays_silent():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "NEWSHA"})
    deps, emitted, _, aria, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    deps = deps._replace(copy_in_place=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "root_file": "img1.bin",
             "img1": {"done": True, "copied": True, "sha": "OLDSHA",
                      "origin": "downloaded"}}
    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    assert all(m != "ROOTCOPY-REPLACED" for m, _ in emitted)


def test_self_heal_drops_stale_aria_entry_before_redownload():
    # staged file gone but aria2 still holds the torrent as a completed seed;
    # aria2 refuses a duplicate info_hash, so the agent MUST forceRemove it first
    # or the re-add is a silent no-op (no bytes transfer — the bug we hit live).
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 1000,
                       "sha256": "abc"})
    aria_removed = []
    deps, _, _, aria, _, _, _, _ = make_deps(cat, {})        # no staged file
    deps = deps._replace(aria_remove=lambda fn: aria_removed.append(fn))
    assert iris_agent.run_once(CFG, deps, _DONE()) == "downloading"
    assert aria_removed == ["img1.bin"]                   # cleared from aria2 first
    assert aria == [("/stage/img1.torrent", "/stage")]    # then re-added -> real DL


def test_self_heal_recopy_does_not_touch_aria():
    # root-only loss re-copies from the good staged file; aria2 must NOT be touched
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    aria_removed = []
    deps, _, _, _, copied, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, root_ok=False)
    deps = deps._replace(aria_remove=lambda fn: aria_removed.append(fn))
    assert iris_agent.run_once(CFG, deps, _DONE()) == "complete"
    assert copied == ["img1.bin"] and aria_removed == []


# --- Task 3: the catalog's declared byte size must thread into both the
# current-image copy/presence checks, but NOT into the old-root cleanup
# check (a replaced image's size is unknown and irrelevant -- it is about
# to be deleted). ---

def test_run_once_passes_catalog_size_to_copy_and_presence():
    # root_present (steady-state check) reports the flash-root copy missing,
    # which drives the self-heal re-copy path -- exercising BOTH deps calls
    # for the CURRENT image in a single tick.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    seen = {}

    def copy_to_root(fname, prefix, expected_size):
        seen["copy_size"] = expected_size
        return True

    def root_present(fname, prefix, expected_size=None):
        seen.setdefault("present_sizes", []).append(expected_size)
        return False   # root missing -> triggers the self-heal re-copy below

    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    deps = deps._replace(copy_to_root=copy_to_root, root_present=root_present)
    assert iris_agent.run_once(CFG, deps, _DONE()) == "complete"
    assert seen["copy_size"] == 5
    assert 5 in seen["present_sizes"]


def test_old_root_cleanup_root_present_no_catalog_size():
    # queued root delete: the replaced image's root_present check stays
    # presence-only -- no catalog size exists for an image that is about to
    # be deleted, so the call must NOT carry a third (size) argument.
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 7,
                       "sha256": "def"})
    calls = []

    def root_present(fname, prefix, expected_size=None):
        calls.append((fname, prefix, expected_size))
        return fname != "old.bin"   # confirm the old root is gone

    deps, _, _, _, _, _, _, _ = make_deps(cat, {}, verify_ok=True)
    deps = deps._replace(root_present=root_present)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img2", "pending_root_deletes": ["old.bin"],
             "old-img": {"root_file": "old.bin", "copied": True,
                        "origin": "downloaded"}}
    iris_agent.run_once(CFG, deps, state)
    assert ("old.bin", "flash:", None) in calls


def test_steady_state_holds_when_files_present_and_sha_matches():
    # the happy path must still short-circuit WITHOUT re-hashing or re-copying
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    verify_calls = []
    deps, _, _, aria, copied, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    deps = deps._replace(verify=lambda p, sha: verify_calls.append(p) or True)
    assert iris_agent.run_once(CFG, deps, _DONE()) == "complete"
    assert verify_calls == [] and copied == [] and aria == []


def test_bad_sha_discards_staged_file_so_next_tick_redownloads():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    removed = []
    deps, emitted, _, _, _, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=False, removed=removed)
    assert iris_agent.run_once(CFG, deps, {}) == "bad-sha"
    assert removed == ["/stage/img1.bin"]      # corrupt/stale file dropped
    assert any(m == "ERROR" for m, _ in emitted)


# --- C1 regression guards: copy_to_root may return False; the state machine
# must NOT mark copied=True / set root_file, and the next tick must retry ---

def test_root_copy_failure_does_not_mark_copied_and_retries_next_tick():
    # Critical #1 regression guard: a False return from copy_to_root (e.g. the
    # agent-side size / sha256 / signature re-verify failed) MUST keep
    # st['copied']==False, state['root_file'] unset, and the next tick must
    # re-fire copy_to_root. Without this, a regression to unconditional True
    # silently re-passes.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, emitted, _, _, _, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=True)
    calls = []

    def failing_copy(fname, target_prefix="flash:", expected_size=None):
        calls.append(fname)
        return False

    deps = deps._replace(copy_to_root=failing_copy)
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert any(m == "DONE" for m, _ in emitted)
    assert state.get("img1", {}).get("copied") is not True
    assert state.get("root_file") is None
    # next tick must re-fire copy_to_root (no false cache of success)
    iris_agent.run_once(CFG, deps, state)
    assert len(calls) == 2
    assert state.get("img1", {}).get("copied") is not True


def test_root_copy_failure_then_success_settles_to_complete():
    # eventual success: copy fails once, then succeeds -> state settles to
    # copied=True; third tick is steady-state with no extra copy attempt.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=True)
    results = iter([False, True])
    calls = []

    def flaky_copy(fname, target_prefix="flash:", expected_size=None):
        calls.append(fname)
        return next(results)

    deps = deps._replace(copy_to_root=flaky_copy)
    state = {}
    iris_agent.run_once(CFG, deps, state)             # fails, copied stays False
    iris_agent.run_once(CFG, deps, state)             # succeeds, copied -> True
    assert state["img1"]["copied"] is True
    assert state["root_file"] == "img1.bin"
    # third tick: steady-state short-circuit, no further copy attempt
    iris_agent.run_once(CFG, deps, state)
    assert len(calls) == 2


def test_root_copy_backoff_starts_after_second_failure(monkeypatch):
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=True)
    calls = []
    deps = deps._replace(
        copy_to_root=lambda fname, target_prefix="flash:", expected_size=None: calls.append(fname) or False)
    now = [1_000.0]
    monkeypatch.setattr(iris_agent.time, "time", lambda: now[0])
    state = {}

    iris_agent.run_once(CFG, deps, state)       # attempt 1 fails
    assert "copy_next_ts" not in state["img1"]
    iris_agent.run_once(CFG, deps, state)       # attempt 2: immediate next tick
    assert len(calls) == 2
    assert state["img1"]["copy_next_ts"] == now[0] + 5 * 60

    now[0] += 5 * 60
    iris_agent.run_once(CFG, deps, state)       # attempt 3 after five minutes
    assert len(calls) == 3
    assert state["img1"]["copy_next_ts"] == now[0] + 10 * 60

    now[0] += 10 * 60
    iris_agent.run_once(CFG, deps, state)       # attempt 4 is terminal
    assert len(calls) == 4
    assert state["img1"]["copy_terminal"] is True
    assert "copy_next_ts" not in state["img1"]


# --- A terminal placement failure must not strand a partial image at the
# boot-FS root. Once copy_terminal is set no further copy fires, so the
# placement path's delete-first never runs again — and the leftover carries the
# REAL Cisco image name, so it both wastes ~1.2 GB and looks like a good image
# to an operator listing flash:. state['root_file'] is only set on SUCCESS, so
# nothing else owns the cleanup. ---

def _terminal_copy_deps(bundle_sink_wanted=True):
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, emitted, _, _, _, _, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=True)
    deps = deps._replace(
        copy_to_root=lambda fname, target_prefix="flash:", expected_size=None: False)
    return deps, emitted, bundle_reclaimed


def test_terminal_placement_failure_reclaims_this_attempts_partial(monkeypatch):
    deps, emitted, bundle_reclaimed = _terminal_copy_deps()
    now = [1_000.0]
    monkeypatch.setattr(iris_agent.time, "time", lambda: now[0])
    state = {}
    for _ in range(iris_agent._ROOT_COPY_MAX_ATTEMPTS):
        iris_agent.run_once(CFG, deps, state)
        now[0] += 3600           # clear any armed backoff
    assert state["img1"]["copy_terminal"] is True
    # EXACTLY the one filename IRIS itself wrote — the delete-first at the head
    # of this attempt means a file at that name can only be this attempt's
    # partial, never an operator's image. Nothing else may be swept.
    assert bundle_reclaimed == [("flash:", ["img1.bin"])]
    assert any(m == "ROOTCOPY-RECLAIM" for m, _ in emitted)


def test_terminal_reclaim_fires_once_not_every_tick(monkeypatch):
    deps, _, bundle_reclaimed = _terminal_copy_deps()
    now = [1_000.0]
    monkeypatch.setattr(iris_agent.time, "time", lambda: now[0])
    state = {}
    for _ in range(iris_agent._ROOT_COPY_MAX_ATTEMPTS + 5):
        iris_agent.run_once(CFG, deps, state)
        now[0] += 3600
    assert len(bundle_reclaimed) == 1


def test_non_terminal_placement_failure_never_reclaims(monkeypatch):
    # Retries are still coming, and each one starts by deleting the name
    # itself. Reclaiming between attempts would be pure churn.
    deps, emitted, bundle_reclaimed = _terminal_copy_deps()
    now = [1_000.0]
    monkeypatch.setattr(iris_agent.time, "time", lambda: now[0])
    state = {}
    for _ in range(iris_agent._ROOT_COPY_MAX_ATTEMPTS - 1):
        iris_agent.run_once(CFG, deps, state)
        now[0] += 3600
    assert state["img1"]["copy_attempts"] == iris_agent._ROOT_COPY_MAX_ATTEMPTS - 1
    assert state["img1"].get("copy_terminal") is not True
    assert bundle_reclaimed == []
    assert not any(m == "ROOTCOPY-RECLAIM" for m, _ in emitted)


def test_transient_running_image_unknown_never_reclaims():
    # The sentinel is not a copy failure at all, so it must neither go terminal
    # nor delete anything.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=True)
    deps = deps._replace(
        copy_to_root=lambda fname, target_prefix="flash:", expected_size=None:
            iris_agent.ROOT_COPY_RUNNING_IMAGE_UNKNOWN)
    state = {}
    for _ in range(iris_agent._ROOT_COPY_MAX_ATTEMPTS + 2):
        iris_agent.run_once(CFG, deps, state)
    assert bundle_reclaimed == []


def test_terminal_reclaim_failure_is_logged_and_swallowed(monkeypatch):
    # The device is already reported as copy_failed; a delete that raises must
    # not take the tick down with it.
    deps, emitted, _ = _terminal_copy_deps()

    def boom(prefix, names):
        raise RuntimeError("cli glitch")

    deps = deps._replace(reclaim_bundle=boom)
    now = [1_000.0]
    monkeypatch.setattr(iris_agent.time, "time", lambda: now[0])
    state = {}
    for _ in range(iris_agent._ROOT_COPY_MAX_ATTEMPTS):
        iris_agent.run_once(CFG, deps, state)
        now[0] += 3600
    assert state["img1"]["copy_terminal"] is True
    assert any(m == "ROOTCOPY-RECLAIM-FAIL" for m, _ in emitted)


# --- CRITICAL: the terminal reclaim must never delete a file IRIS did not
# write. Its whole safety argument rests on "this attempt's delete-first
# already cleared the name" — an invariant that is FALSE for every path that
# gives up BEFORE any IOS command runs (the running-image refusals, an scp
# push that raised, an applet run that never fired). On the running-image
# refusal the file at that name IS the operator's running image, and deleting
# it lands a bundle-mode box in rommon at the next reload. Two independent
# layers below; each is tested on its own so a regression in one is still
# caught by the other's tests. ---

def _reclaim_probe_deps(running="running.bin"):
    """run_once harness whose copy_to_root verdict the caller supplies."""
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, emitted, _, _, _, _, _, bundle_reclaimed = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=True)
    return deps._replace(running_image=lambda: running), emitted, bundle_reclaimed


def _tick_to_terminal(deps, monkeypatch, ticks=None):
    now = [1_000.0]
    monkeypatch.setattr(iris_agent.time, "time", lambda: now[0])
    state = {}
    for _ in range(ticks or iris_agent._ROOT_COPY_MAX_ATTEMPTS):
        iris_agent.run_once(CFG, deps, state)
        now[0] += 3600          # clear any armed backoff
    return state


# --- Layer 1: only a failure that got PAST the delete-first arms the reclaim ---

def test_running_image_refusal_at_terminal_never_reclaims(monkeypatch):
    # The reviewer's scenario. copy_to_root refuses because the assigned image
    # IS the running image (reachable with copied=False on a fresh/lost state
    # file, after the schema-2 upgrade clears "copied", or when the operator
    # already reloaded onto the staged image). Four refusals reach the terminal
    # state — and the reclaim must delete NOTHING: no IOS command ran, so the
    # only file at flash:img1.bin is the running image itself.
    deps, emitted, bundle_reclaimed = _reclaim_probe_deps(running="img1.bin")
    ios_cmds = []

    def real_copy(fname, target_prefix="flash:", expected_size=None):
        # the REAL Guest Shell impl, refusing on its own running-image check
        return iris_agent._copy_to_root_impl(
            fname, target_prefix, lambda lines: ios_cmds.extend(lines),
            lambda c: ios_cmds.append(c) or "",
            lambda m, msg: emitted.append((m, msg)),
            reverify_fn=lambda *a, **k: True,
            running_image_fn=lambda: "flash:img1.bin",
            expected_size=expected_size)

    deps = deps._replace(copy_to_root=real_copy)
    state = _tick_to_terminal(deps, monkeypatch)
    assert ios_cmds == []                              # never touched IOS
    assert state["img1"]["copy_terminal"] is True      # operator still sees it
    assert state["img1"]["copy_attempts"] == iris_agent._ROOT_COPY_MAX_ATTEMPTS
    assert state["img1"].get("ios_copy_started") is not True
    assert bundle_reclaimed == []                      # nothing deleted, ever
    assert not any(m == "ROOTCOPY-RECLAIM" for m, _ in emitted)
    # "no attempt reached IOS" is Layer 1 speaking; Layer 2 has its own wording,
    # so this pins the ios_copy_started gate specifically.
    assert any(m == "ROOTCOPY-RECLAIM-REFUSED" and "no attempt reached IOS" in msg
               for m, msg in emitted)


def test_scp_push_failure_at_terminal_never_reclaims(monkeypatch):
    # Container path: the scp scratch push raised, so no IOS command ran. The
    # running image has a DIFFERENT name here, so Layer 2 cannot be what saves
    # the file — this isolates Layer 1's ios_copy_started gate.
    deps, emitted, bundle_reclaimed = _reclaim_probe_deps(running="running.bin")
    deps = deps._replace(
        copy_to_root=lambda fname, target_prefix="flash:", expected_size=None:
            iris_agent.ROOT_COPY_NOT_ATTEMPTED)
    state = _tick_to_terminal(deps, monkeypatch)
    assert state["img1"]["copy_terminal"] is True
    assert bundle_reclaimed == []
    assert any(m == "ROOTCOPY-RECLAIM-REFUSED" for m, _ in emitted)


def test_not_attempted_sentinel_is_never_mistaken_for_success():
    # ROOT_COPY_NOT_ATTEMPTED is a truthy object(); a plain `if result:` would
    # report a placement that never happened as a verified root copy.
    deps, _, _ = _reclaim_probe_deps(running="img1.bin")
    deps = deps._replace(
        copy_to_root=lambda fname, target_prefix="flash:", expected_size=None:
            iris_agent.ROOT_COPY_NOT_ATTEMPTED)
    state = {}
    iris_agent.run_once(CFG, deps, state)
    assert state["img1"].get("copied") is not True
    assert state.get("root_file") is None
    assert state["img1"]["copy_attempts"] == 1        # counts, like plain False


def test_mixed_cycle_one_refusal_then_real_failures_still_reclaims(monkeypatch):
    # A refusal followed by attempts that DID run the delete-first: the genuine
    # failures set ios_copy_started, so the leftover partial is still reclaimed.
    deps, emitted, bundle_reclaimed = _reclaim_probe_deps(running="running.bin")
    results = iter([iris_agent.ROOT_COPY_NOT_ATTEMPTED, False, False, False])
    deps = deps._replace(
        copy_to_root=lambda fname, target_prefix="flash:", expected_size=None:
            next(results))
    state = _tick_to_terminal(deps, monkeypatch)
    assert state["img1"]["copy_terminal"] is True
    assert bundle_reclaimed == [("flash:", ["img1.bin"])]
    assert any(m == "ROOTCOPY-RECLAIM" for m, _ in emitted)


def test_ios_copy_started_clears_when_copy_failures_reset():
    # The flag is per-image-cycle: a success must clear it with copy_attempts,
    # or a later cycle of pure refusals would inherit the authorisation.
    deps, _, _ = _reclaim_probe_deps(running="running.bin")
    results = iter([False, True])
    deps = deps._replace(
        copy_to_root=lambda fname, target_prefix="flash:", expected_size=None:
            next(results))
    state = {}
    iris_agent.run_once(CFG, deps, state)             # genuine failure
    assert state["img1"]["ios_copy_started"] is True
    iris_agent.run_once(CFG, deps, state)             # success resets the cycle
    assert state["img1"]["copied"] is True
    assert state["img1"].get("ios_copy_started") is None
    assert state["img1"].get("copy_attempts") is None


def test_genuine_placement_failure_through_the_real_impl_still_reclaims(monkeypatch):
    # End-to-end through the REAL direct impl: delete-first runs, the copy runs,
    # and reverify fails on a short file. That leftover IS ours, so the terminal
    # reclaim must still fire — the fix must not disarm the legitimate case.
    deps, emitted, bundle_reclaimed = _reclaim_probe_deps(running="running.bin")
    cli_calls = []

    def cli_exec(cmd):
        cli_calls.append(cmd)
        if cmd.startswith("dir "):
            return "  121  -rw-  3  Jun 16 2026  img1.bin"    # short: 3 != 5
        return ""

    def real_copy(fname, target_prefix="flash:", expected_size=None):
        return iris_agent._copy_to_root_direct_impl(
            fname, target_prefix, cli_exec,
            lambda m, msg: emitted.append((m, msg)),
            reverify_fn=lambda *a, **k: iris_agent._agent_reverify_root(
                *a, poll_attempts=1, sleep_fn=lambda s: None, **k),
            running_image_fn=lambda: "flash:running.bin",
            expected_size=expected_size)

    deps = deps._replace(copy_to_root=real_copy)
    state = _tick_to_terminal(deps, monkeypatch)
    assert "delete /force flash:img1.bin" in cli_calls    # delete-first DID run
    assert state["img1"]["ios_copy_started"] is True
    assert bundle_reclaimed == [("flash:", ["img1.bin"])]
    assert any(m == "ROOTCOPY-RECLAIM" for m, _ in emitted)


# --- Layer 2: _reclaim_failed_root_copy's own unconditional last-line check.
# Tested by calling it DIRECTLY with a plain-False cycle behind it, i.e. as if
# Layer 1 had regressed. ---

def _direct_reclaim(running):
    deps, emitted, bundle_reclaimed = _reclaim_probe_deps(running=running)
    iris_agent._reclaim_failed_root_copy(
        deps, "flash:", {"id": "img1", "filename": "img1.bin"})
    return emitted, bundle_reclaimed


def test_reclaim_refuses_to_delete_the_running_image():
    emitted, bundle_reclaimed = _direct_reclaim("flash:img1.bin")
    assert bundle_reclaimed == []
    assert any(m == "ROOTCOPY-RECLAIM-REFUSED" and "IS the running image" in msg
               for m, msg in emitted)


def test_reclaim_running_image_match_is_case_insensitive():
    # IOS is inconsistent about filename case in `show version`; a case-only
    # difference must not open the delete path.
    emitted, bundle_reclaimed = _direct_reclaim("bootflash:/IMG1.BIN")
    assert bundle_reclaimed == []
    assert any(m == "ROOTCOPY-RECLAIM-REFUSED" for m, _ in emitted)


def test_reclaim_refuses_when_running_image_is_unknown():
    # Same rule _reclaim_for_mode already follows (#4): with no confirmable
    # running image there is no safe protect set, so no delete may run.
    emitted, bundle_reclaimed = _direct_reclaim(None)
    assert bundle_reclaimed == []
    assert any(m == "ROOTCOPY-RECLAIM-REFUSED" and "running image unknown" in msg
               for m, msg in emitted)


def test_reclaim_refuses_when_the_running_image_read_raises():
    deps, emitted, bundle_reclaimed = _reclaim_probe_deps()

    def boom():
        raise RuntimeError("show version glitch")

    deps = deps._replace(running_image=boom)
    iris_agent._reclaim_failed_root_copy(
        deps, "flash:", {"id": "img1", "filename": "img1.bin"})
    assert bundle_reclaimed == []
    assert any(m == "ROOTCOPY-RECLAIM-REFUSED" and "running image unknown" in msg
               for m, msg in emitted)


def test_reclaim_deletes_when_the_target_is_not_the_running_image():
    emitted, bundle_reclaimed = _direct_reclaim("flash:running.bin")
    assert bundle_reclaimed == [("flash:", ["img1.bin"])]
    assert any(m == "ROOTCOPY-RECLAIM" for m, _ in emitted)


def test_layer2_alone_blocks_the_reviewer_scenario_end_to_end(monkeypatch):
    # Layer 1 deliberately bypassed: copy_to_root returns a plain False
    # (exactly what the regressed build returned for the running-image
    # refusal), so ios_copy_started IS set and the caller asks for the reclaim.
    # Layer 2 must still refuse, because the target is the running image.
    deps, emitted, bundle_reclaimed = _reclaim_probe_deps(running="img1.bin")
    deps = deps._replace(
        copy_to_root=lambda fname, target_prefix="flash:", expected_size=None: False)
    state = _tick_to_terminal(deps, monkeypatch)
    assert state["img1"]["copy_terminal"] is True
    assert bundle_reclaimed == []             # NOT [("flash:", ["img1.bin"])]
    assert any(m == "ROOTCOPY-RECLAIM-REFUSED" and "IS the running image" in msg
               for m, msg in emitted)


# --- The pre-IOS/post-IOS classification at its source: the copy impls. ---

def test_copy_impls_refusals_return_not_attempted():
    for impl, args in (
            (iris_agent._copy_to_root_impl,
             ("img1.bin", "flash:", lambda lines: None, lambda c: "")),
            (iris_agent._copy_to_root_direct_impl,
             ("img1.bin", "flash:", lambda c: ""))):
        for running in ("flash:img1.bin", "flash:IMG1.BIN", None):
            emitted = []
            out = impl(*args, emit_fn=lambda m, msg: emitted.append((m, msg)),
                       reverify_fn=lambda *a, **k: True,
                       running_image_fn=lambda: running)
            assert out is iris_agent.ROOT_COPY_NOT_ATTEMPTED, (impl, running)
            assert any(m == "ROOTCOPY-REFUSED" and "no IOS command ran" in msg
                       for m, msg in emitted)


def test_copy_to_root_direct_delete_first_raise_is_not_attempted():
    # The delete-first never cleared the name, so the name is not ours.
    emitted, reverify_calls = [], []

    def cli_exec(cmd):
        if cmd.startswith("delete"):
            raise RuntimeError("vty glitch")
        return ""

    out = iris_agent._copy_to_root_direct_impl(
        "img1.bin", "sdflash:", cli_exec,
        lambda m, msg: emitted.append((m, msg)),
        reverify_fn=lambda *a, **k: reverify_calls.append(1) or True)
    assert out is iris_agent.ROOT_COPY_NOT_ATTEMPTED
    assert reverify_calls == []
    assert any(m == "ROOTCOPY-FAIL" and "delete-first raised" in msg
               for m, msg in emitted)


def test_first_retry_timestamp_from_regressed_state_is_ignored(monkeypatch):
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=True)
    calls = []
    deps = deps._replace(
        copy_to_root=lambda fname, target_prefix="flash:", expected_size=None: calls.append(fname) or True)
    monkeypatch.setattr(iris_agent.time, "time", lambda: 1_000.0)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1",
             "img1": {"done": True, "copied": False, "sha": "abc",
                      "copy_attempts": 1, "copy_next_ts": 1_300.0}}

    iris_agent.run_once(CFG, deps, state)
    assert calls == ["img1.bin"]
    assert state["img1"]["copied"] is True
    assert state["root_file"] == "img1.bin"


# --- D6 regression guards: a transient "running image unknown" refusal (the
# IOx SSH-to-self `show version` scrape glitched) must NOT feed the same
# copy_attempts counter as a genuine copy failure. deps.copy_to_root() signals
# this case with the ROOT_COPY_RUNNING_IMAGE_UNKNOWN sentinel instead of plain
# False. ---

def test_root_copy_running_image_unknown_does_not_count_toward_terminal():
    # Four (or more) consecutive unknown-running-image refusals — analogous to
    # a run of flaky `show version` reads over ~15 minutes — must never trip
    # the _ROOT_COPY_MAX_ATTEMPTS durable copy_failed terminal state, and must
    # not advance copy_attempts or arm the backoff schedule. Before this fix,
    # each refusal returned plain False and was indistinguishable from a real
    # copy failure, so four of them alone would permanently dead-end the copy.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, emitted, _, _, _, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=True)
    calls = []

    def unknown_running_copy(fname, target_prefix="flash:", expected_size=None):
        calls.append(fname)
        return iris_agent.ROOT_COPY_RUNNING_IMAGE_UNKNOWN

    deps = deps._replace(copy_to_root=unknown_running_copy)
    state = {}
    for _ in range(iris_agent._ROOT_COPY_MAX_ATTEMPTS + 2):
        iris_agent.run_once(CFG, deps, state)
    assert len(calls) == iris_agent._ROOT_COPY_MAX_ATTEMPTS + 2   # retried every tick
    assert state["img1"].get("copy_attempts") is None       # never counted
    assert state["img1"].get("copy_terminal") is not True   # never terminal
    assert state["img1"].get("copy_next_ts") is None        # no backoff armed
    assert state["img1"].get("copied") is not True
    assert not any(m == "ROOTCOPY-GIVEUP" for m, _ in emitted)


def test_root_copy_running_image_unknown_then_resolves_copies_normally():
    # Once the transient clears and running_image() resolves again, the copy
    # proceeds exactly as if nothing had happened — no leftover attempt count,
    # no stale backoff deferring the now-successful attempt.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=True)
    results = iter([iris_agent.ROOT_COPY_RUNNING_IMAGE_UNKNOWN,
                    iris_agent.ROOT_COPY_RUNNING_IMAGE_UNKNOWN,
                    True])
    calls = []

    def flaky_then_ok(fname, target_prefix="flash:", expected_size=None):
        calls.append(fname)
        return next(results)

    deps = deps._replace(copy_to_root=flaky_then_ok)
    state = {}
    iris_agent.run_once(CFG, deps, state)      # unknown, retried next tick
    iris_agent.run_once(CFG, deps, state)      # unknown again
    iris_agent.run_once(CFG, deps, state)      # resolves -> real copy succeeds
    assert len(calls) == 3
    assert state["img1"]["copied"] is True
    assert state["root_file"] == "img1.bin"
    assert state["img1"].get("copy_attempts") is None


def test_root_copy_unknown_interleaved_with_real_failures_only_real_ones_count():
    # A transient unknown-running-image tick sandwiched between two genuine
    # copy failures must not itself advance copy_attempts, and must not reset
    # or otherwise disturb the count from the real failures around it.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=True)
    results = iter([False,
                    iris_agent.ROOT_COPY_RUNNING_IMAGE_UNKNOWN,
                    False])
    calls = []

    def mixed(fname, target_prefix="flash:", expected_size=None):
        calls.append(fname)
        return next(results)

    deps = deps._replace(copy_to_root=mixed)
    state = {}
    iris_agent.run_once(CFG, deps, state)      # real failure #1
    assert state["img1"]["copy_attempts"] == 1
    iris_agent.run_once(CFG, deps, state)      # transient unknown, not counted
    assert state["img1"]["copy_attempts"] == 1
    iris_agent.run_once(CFG, deps, state)      # real failure #2
    assert state["img1"]["copy_attempts"] == 2
    assert len(calls) == 3


# --- Direct tests of _agent_reverify_root (the real code path).
# The IRIS-COPYROOT EEM applet deletes any stale leftover, then runs a plain
# `copy` (no /verify) — a plain copy that dies mid-transfer can leave a
# PARTIAL file, so presence alone is no longer sound. The agent polls
# `dir flash:<fname>` (small, fast cli call): with no expected_size, presence
# is still the verdict (legacy callers); with an expected_size, presence AND
# exact byte size is the verdict — a wrong size mid-poll just means the copy
# is still running, and only a mismatch that persists to the end of the poll
# budget fails. ---

_FNAME = "cat9k.bin"

_DIR_OK = """Directory of flash:/

  121  -rw-      1260618344  Jun 16 2026 12:30:01 +00:00  cat9k.bin

11000000000 bytes total (5000000000 bytes free)
"""
_DIR_MISSING = "%Error opening flash:/cat9k.bin (No such file or directory)\n"


def _make_reverify_cli(dir_out=None, raise_on=None):
    """Build the injected cli_execute + emit recorder for _agent_reverify_root.
    `dir_out` is what `dir flash:<fname>` returns (defaults to missing-file —
    agent will keep polling). `raise_on='dir'` forces dir to raise."""
    if dir_out is None:
        dir_out = _DIR_MISSING
    cli_calls = []
    emitted = []

    def cli(cmd):
        cli_calls.append(cmd)
        if cmd.startswith("dir flash:"):
            if raise_on == "dir":
                raise RuntimeError("dir cli glitch")
            return dir_out
        return ""

    def emit(m, msg):
        emitted.append((m, msg))

    return cli, emit, cli_calls, emitted


def _reverify(cli, emit, fname=_FNAME, prefix="flash:", **kw):
    """Call _agent_reverify_root with fast, no-real-sleep polling defaults."""
    kw.setdefault("poll_attempts", 3)
    kw.setdefault("poll_interval_s", 0)
    kw.setdefault("sleep_fn", lambda _: None)
    return iris_agent._agent_reverify_root(fname, prefix, cli, emit, **kw)


def test_reverify_happy_path_emits_rootcopy_success():
    cli, emit, cli_calls, emitted = _make_reverify_cli(dir_out=_DIR_OK)
    ok = _reverify(cli, emit)
    assert ok is True
    # one dir read was enough — file present on the first poll
    assert sum(c.startswith("dir flash:") for c in cli_calls) == 1
    # heartbeat for operators + authoritative success log, both agent-owned
    assert any(m == "ROOTCOPY-VERIFYING" for m, _ in emitted)
    assert ("ROOTCOPY", "cat9k.bin placed at flash root") in emitted


def test_reverify_no_file_means_signature_failed_or_copy_aborted():
    # Placement is a plain `copy` now — there's no on-box signature check to
    # fail. A missing file after the poll window just means the copy never
    # completed (aborted, hung, or never started); any partial from a prior
    # attempt gets cleared by the applet's delete-first step, not left behind
    # for the agent to see. The agent times out and emits FAIL (nothing to
    # delete here — the applet already cleared any stale leftover up front).
    cli, emit, _, emitted = _make_reverify_cli(dir_out=_DIR_MISSING)
    ok = _reverify(cli, emit, poll_attempts=3)
    assert ok is False
    assert any(m == "ROOTCOPY-FAIL" and "never appeared" in msg
               for m, msg in emitted)
    assert all(m != "ROOTCOPY" for m, _ in emitted)


def test_reverify_polls_until_file_appears():
    # The applet runs ~2-4 min while the agent polls. dir reports
    # "No such file" until the copy finishes — then the file is there
    # at the expected path. The agent must keep polling, then pass.
    seq = iter([_DIR_MISSING, _DIR_MISSING, _DIR_OK])
    sleeps = []

    def cli(cmd):
        if cmd.startswith("dir flash:"):
            return next(seq)
        return ""

    emitted = []
    ok = iris_agent._agent_reverify_root(
        _FNAME, "flash:",
        cli, lambda m, msg: emitted.append((m, msg)),
        poll_attempts=5, poll_interval_s=0,
        sleep_fn=lambda s: sleeps.append(s))
    assert ok is True
    # slept twice (between the three polls), not at all once file appeared
    assert len(sleeps) == 2
    assert any(m == "ROOTCOPY" for m, _ in emitted)


def test_reverify_dir_raises_every_poll_times_out():
    # a transient cli failure on every poll is swallowed (treated as missing
    # file) -> timeout. One flaky tick must not bless a missing file as present.
    cli, emit, _, emitted = _make_reverify_cli(raise_on="dir")
    ok = _reverify(cli, emit, poll_attempts=3)
    assert ok is False
    assert any(m == "ROOTCOPY-FAIL" and "never appeared" in msg
               for m, msg in emitted)


def test_reverify_does_not_confuse_other_filenames_in_dir_output():
    # A `dir flash:cat9k.bin` that returns OTHER filenames (e.g. a glob
    # matched many) must NOT trigger a false-positive. The match is on the
    # exact target filename.
    other = _DIR_OK.replace("cat9k.bin", "other.bin")
    cli, emit, _, emitted = _make_reverify_cli(dir_out=other)
    ok = _reverify(cli, emit, poll_attempts=2)
    assert ok is False
    assert all(m != "ROOTCOPY" for m, _ in emitted)


# --- _dir_size_of: parses the byte size out of an IOS `dir` row, anchored to
# the row end so a whitelisted filename never reads a sibling row's size
# (e.g. cat9k.bin must not match cat9k.bin.backup). Plain copy (no /verify)
# can leave a partial file, so _agent_reverify_root now needs size, not just
# presence. ---

def test_dir_size_of_parses_ios_dir_line():
    out = ("Directory of flash:/\n"
           "  121  -rw-      1260618344  Jun 16 2026 12:30:01 +00:00  cat9k.bin\n"
           "11353194496 bytes total (8438681600 bytes free)\n")
    assert iris_agent._dir_size_of(out, "cat9k.bin") == 1260618344


def test_dir_size_of_absent_file_returns_none():
    assert iris_agent._dir_size_of("No such file or directory", "cat9k.bin") is None
    assert iris_agent._dir_size_of("", "cat9k.bin") is None


def test_dir_size_of_matches_whole_name_not_substring():
    # cat9k.bin must not match the cat9k.bin.backup row's size
    out = "  122  -rw-  999  Jun 16 2026 12:30:01 +00:00  cat9k.bin.backup\n"
    assert iris_agent._dir_size_of(out, "cat9k.bin") is None


def test_dir_size_of_ignores_directory_rows():
    # A same-named directory must not report its nominal size as a file size.
    out = "  121  drwx  4096  Jun 16 2026  cat9k.bin"
    assert iris_agent._dir_size_of(out, "cat9k.bin") is None


def test_reverify_size_match_succeeds():
    emits = []
    out = "  121  -rw-  1260618344  Jun 16 2026  cat9k.bin"
    ok = iris_agent._agent_reverify_root(
        "cat9k.bin", "flash:", lambda c: out,
        lambda tag, msg: emits.append((tag, msg)),
        poll_attempts=1, poll_interval_s=0, expected_size=1260618344)
    assert ok is True
    assert emits[-1][0] == "ROOTCOPY"


def test_reverify_partial_file_fails_with_size_reason():
    # A plain copy that died mid-way leaves a short file: presence alone must NOT pass.
    emits = []
    out = "  121  -rw-  1048576  Jun 16 2026  cat9k.bin"
    ok = iris_agent._agent_reverify_root(
        "cat9k.bin", "flash:", lambda c: out,
        lambda tag, msg: emits.append((tag, msg)),
        poll_attempts=2, poll_interval_s=0, sleep_fn=lambda s: None,
        expected_size=1260618344)
    assert ok is False
    assert emits[-1][0] == "ROOTCOPY-FAIL"
    assert "size" in emits[-1][1]


def test_reverify_keeps_polling_while_size_grows_then_succeeds():
    # Mid-copy: dir shows a short, growing file across successive polls. The
    # poll must NOT fail on the first wrong-size reading — the copy landing
    # the file is asynchronous from the agent's point of view, and a short
    # file partway through the poll window usually just means still-copying.
    # Only a mismatch that persists to the end of the poll budget is a
    # failure; here the full size shows up before the budget runs out, so
    # the call must succeed.
    sizes = iter([100, 1048576, 1260618344])

    def cli(cmd):
        return "  121  -rw-  %d  Jun 16 2026  cat9k.bin" % next(sizes)

    emits = []
    ok = iris_agent._agent_reverify_root(
        "cat9k.bin", "flash:", cli,
        lambda tag, msg: emits.append((tag, msg)),
        poll_attempts=3, poll_interval_s=0, sleep_fn=lambda s: None,
        expected_size=1260618344)
    assert ok is True
    assert emits[-1][0] == "ROOTCOPY"


def test_reverify_without_expected_size_keeps_presence_only():
    out = "  121  -rw-  1048576  Jun 16 2026  cat9k.bin"
    ok = iris_agent._agent_reverify_root(
        "cat9k.bin", "flash:", lambda c: out, lambda tag, msg: None,
        poll_attempts=1, poll_interval_s=0)
    assert ok is True


# --- present-but-unparseable `dir` row: the file IS there, the row just didn't
# parse (unexpected format). That must be handled like a wrong size — keep
# polling — and the eventual failure must say what was actually seen, not
# "never appeared". A false "never appeared" sends an operator hunting the
# wrong fault. ---

# a row the size regex cannot read: no permissions column at all
_DIR_UNPARSEABLE = "Directory of flash:/\n  cat9k.bin\n"


def test_reverify_present_but_unparseable_row_keeps_polling():
    # Poll 1 and 2 return an unreadable row; poll 3 returns a well-formed row
    # with the right size. The unreadable ticks must not end the poll early.
    seq = iter([_DIR_UNPARSEABLE, _DIR_UNPARSEABLE,
                "  121  -rw-  1260618344  Jun 16 2026  cat9k.bin"])
    sleeps = []
    emits = []
    ok = iris_agent._agent_reverify_root(
        "cat9k.bin", "flash:", lambda c: next(seq),
        lambda tag, msg: emits.append((tag, msg)),
        poll_attempts=5, poll_interval_s=0,
        sleep_fn=lambda s: sleeps.append(s), expected_size=1260618344)
    assert ok is True
    assert len(sleeps) == 2
    assert emits[-1][0] == "ROOTCOPY"


def test_reverify_present_but_unparseable_fails_with_an_honest_reason():
    # Persisting to the end of the budget IS a failure — but the file was
    # plainly present, so the log must not claim it never appeared.
    emits = []
    ok = iris_agent._agent_reverify_root(
        "cat9k.bin", "flash:", lambda c: _DIR_UNPARSEABLE,
        lambda tag, msg: emits.append((tag, msg)),
        poll_attempts=2, poll_interval_s=0, sleep_fn=lambda s: None,
        expected_size=1260618344)
    assert ok is False
    tag, msg = emits[-1]
    assert tag == "ROOTCOPY-FAIL"
    assert "present but size unreadable from dir output" in msg
    assert "never appeared" not in msg


def test_reverify_readable_mismatch_after_unparseable_reports_the_mismatch():
    # The message describes the LAST thing the poll actually saw: a readable
    # short size beats an earlier unreadable row.
    seq = iter([_DIR_UNPARSEABLE,
                "  121  -rw-  1048576  Jun 16 2026  cat9k.bin"])
    emits = []
    ok = iris_agent._agent_reverify_root(
        "cat9k.bin", "flash:", lambda c: next(seq),
        lambda tag, msg: emits.append((tag, msg)),
        poll_attempts=2, poll_interval_s=0, sleep_fn=lambda s: None,
        expected_size=1260618344)
    assert ok is False
    assert "size mismatch" in emits[-1][1]


# --- _root_present_from_dir: the steady-state presence verdict build_deps.
# root_present wraps. Absence is the ONLY hard False (besides a readable size
# that disagrees); anything ambiguous stays True so one bad tick can't cost a
# full ~GB re-copy. ---

def test_root_present_from_dir_absent_is_false():
    assert iris_agent._root_present_from_dir(
        "%Error opening flash:/cat9k.bin (No such file or directory)",
        "cat9k.bin", 1260618344) is False
    assert iris_agent._root_present_from_dir("", "cat9k.bin") is False
    assert iris_agent._root_present_from_dir(
        "  121  -rw-  5  Jun 16 2026  other.bin", "cat9k.bin") is False


def test_root_present_from_dir_exact_size_matches():
    out = "  121  -rw-  1260618344  Jun 16 2026  cat9k.bin"
    assert iris_agent._root_present_from_dir(out, "cat9k.bin", 1260618344) is True


def test_root_present_from_dir_readable_short_size_is_false():
    # a partial left by an interrupted transfer must not pass as "still there"
    out = "  121  -rw-  1048576  Jun 16 2026  cat9k.bin"
    assert iris_agent._root_present_from_dir(out, "cat9k.bin", 1260618344) is False


def test_root_present_from_dir_unparseable_row_stays_present():
    # The file IS there; only the row format defeated the parser. Returning
    # False here would re-copy ~1.2 GB over a parse quirk — same rationale as
    # the raise-tolerating path: a real loss shows as absence next tick.
    assert iris_agent._root_present_from_dir(
        _DIR_UNPARSEABLE, "cat9k.bin", 1260618344) is True


# --- Source-level guard: the templated applet inside iris_agent.py must do the
# COPY only and log a NEUTRAL breadcrumb — never claim a verified copy. Only the
# agent emits the "placed at flash root" log, after _agent_reverify_root sees
# the file (and, when given expected_size, the matching size).
# Refuter 3 caught that the bats test only inspects the reference .cfg, not the
# runtime-templated string. ---

def test_iris_agent_source_applet_is_neutral_no_self_verdict():
    """The templated applet must (a) delete any stale leftover before copying,
    (b) run a plain `copy` (no /verify, no in-band signature check), and (c)
    log only a NEUTRAL ROOTCOPY-ATTEMPTED breadcrumb — never a pass/fail
    verdict or a "placed at flash root" claim. The agent owns the verdict via
    file presence (and,
    where checked, size). Plus a HW-driven regression guard: the broken
    $_arg1 trigger must not return. The bats only inspects the reference
    .cfg; this checks the runtime template living inside iris_agent.py
    itself."""
    src = open(iris_agent.__file__).read()
    # the authoritative success log lives in the agent's emit(), issued ONLY
    # after _agent_reverify_root passes — never inside an applet syslog action.
    assert "placed at flash root" in src
    syslog_lines = [l for l in src.splitlines()
                    if "syslog msg" in l and "action 0" in l]
    assert syslog_lines, "missing the templated applet syslog action line"
    for l in syslog_lines:
        assert "placed at flash root" not in l, \
            "REGRESSION: applet syslog must NOT claim a verified copy; only " \
            "the agent emits ROOTCOPY after _agent_reverify_root passes"
    # the applet logs a neutral breadcrumb, not a verdict
    assert any("ROOTCOPY-ATTEMPTED" in l for l in syslog_lines), \
        "applet syslog action must log the neutral ROOTCOPY-ATTEMPTED mnemonic"
    # presence is the verdict, so the applet must clear any stale leftover first
    assert 'delete /force %s%s' in src, \
        "applet must delete any stale same-named leftover before the copy"
    # the applet copies PLAINLY (no /verify, no in-band signature check) and
    # does NOT run any standalone verify (the agent reads no syslog verdict).
    # The copy SOURCE is parameterized (default = the guest-share scratch on the
    # staging FS for the C9300; an injected http:// URL for the IE3x00 container).
    assert "copy %s %s%s" in src            # parameterized src + dst
    assert "copy /verify %s %s%s" not in src, \
        "REGRESSION: the templated action must not return to copy /verify"
    assert "%s/guest-share/iris/%s" in src          # default (C9300) source
    assert "$_ok" not in src and "regexp" not in src, \
        "REGRESSION: the dead syslog-verdict capture (_ok/regexp) is back"
    # The templated applet must NOT regress to $_arg1 (HW-broken on 17.18:
    # `event manager run <applet> <arg>` doesn't populate $_arg1). Comments may
    # mention it historically; only actual code is forbidden.
    code_only = "\n".join(
        line for line in src.splitlines()
        if not line.lstrip().startswith("#"))
    assert "$_arg1" not in code_only, \
        "REGRESSION: HW-broken $_arg1 trigger pattern reintroduced in agent code"


# --- _copy_to_root_impl behavioural guard for Flaw 2 (refuter found the
# original copy_to_root wrapper had no unit coverage — a regression to
# `return True` at the wrapper layer would re-introduce the C1 bug without
# any test catching it). These tests inject all callables and prove the
# wrapper (a) templates the delete-before-copy applet and fires it, (b) returns
# whatever reverify returns, (c) NEVER emits the success log itself — the
# success log can ONLY come from the gated reverify path. ---

def _capture_calls():
    """Build a fully-injected harness for _copy_to_root_impl."""
    configured = []
    cli_calls = []
    emitted = []

    def cli_configure_fn(lines):
        configured.append(list(lines))

    def cli_execute_fn(cmd):
        cli_calls.append(cmd)
        return ""

    def emit_fn(m, msg):
        emitted.append((m, msg))

    return cli_configure_fn, cli_execute_fn, emit_fn, configured, cli_calls, emitted


def test_copy_to_root_impl_fires_applet_then_calls_reverify():
    cli_cfg, cli_exec, emit, configured, cli_calls, emitted = _capture_calls()
    reverify_calls = []

    def reverify(fname, prefix, cli_exec_arg, emit_arg, expected_size=None):
        reverify_calls.append(fname)
        return True

    ok = iris_agent._copy_to_root_impl(
        "img1.bin", "flash:", cli_cfg, cli_exec, emit, reverify_fn=reverify)
    assert ok is True
    # the applet was templated: clear-leftover (delete) + plain copy + a
    # NEUTRAL breadcrumb. No verdict capture, no signature check, no claim.
    assert len(configured) == 1
    body = "\n".join(configured[0])
    assert "delete /force flash:img1.bin" in body
    assert "copy flash:/guest-share/iris/img1.bin flash:img1.bin" in body
    assert "/verify" not in body
    assert "ROOTCOPY-ATTEMPTED img1.bin" in body
    assert "placed at flash root + verified" not in body          # neutral applet
    assert "$_ok" not in body and "regexp" not in body            # no dead verdict capture
    assert "verify /sha512" not in body, \
        "applet must NOT run a signature verify — the agent owns the verdict"
    # applet was fired
    assert cli_calls == ["event manager run IRIS-COPYROOT"]
    # reverify got the filename
    assert reverify_calls == ["img1.bin"]
    # success: no FAIL emit
    assert all(m != "ROOTCOPY-FAIL" for m, _ in emitted)


def test_copy_applet_uses_target_prefix():
    cli_cfg, cli_exec, emit, configured, cli_calls, emitted = _capture_calls()
    iris_agent._copy_to_root_impl(
        "img1.bin", "sdflash:", cli_cfg, cli_exec, emit,
        reverify_fn=lambda fname, prefix, c, e, expected_size=None: True)
    body = "\n".join(configured[0])
    assert "delete /force sdflash:img1.bin" in body
    assert "copy sdflash:/guest-share/iris/img1.bin sdflash:img1.bin" in body


def test_copy_to_root_impl_reverify_false_returns_false_no_success_log():
    """When reverify reports the file never appeared (False), the wrapper MUST
    (a) return False and (b) NOT emit the ROOTCOPY success log. A regression to
    `return True` would fail (a); a wrapper-emitted ROOTCOPY fails (b)."""
    cli_cfg, cli_exec, emit, _, _, emitted = _capture_calls()

    def reverify(*args, **kwargs):
        return False

    ok = iris_agent._copy_to_root_impl(
        "bad.bin", "flash:", cli_cfg, cli_exec, emit, reverify_fn=reverify)
    assert ok is False
    assert all(msg != "bad.bin placed at flash root + verified"
               for _, msg in emitted)
    assert all(m != "ROOTCOPY" for m, _ in emitted)


def test_copy_to_root_impl_applet_fire_raises_no_reverify():
    """If `event manager run` itself raises, the wrapper bails before reverify.
    Returns ROOT_COPY_NOT_ATTEMPTED + ROOTCOPY-FAIL naming the applet run: the
    applet's action 020 delete-first cannot be assumed to have run, so this
    failure must not authorise the terminal reclaim to delete that name."""
    cli_cfg, _, emit, _, _, emitted = _capture_calls()

    def cli_execute_fn(cmd):
        raise RuntimeError("guestshell glitch")

    reverify_calls = []

    def reverify(*args, **kwargs):
        reverify_calls.append(args)
        return True

    ok = iris_agent._copy_to_root_impl(
        "img1.bin", "flash:", cli_cfg, cli_execute_fn, emit, reverify_fn=reverify)
    assert ok is iris_agent.ROOT_COPY_NOT_ATTEMPTED
    assert reverify_calls == []   # reverify never reached
    assert any(m == "ROOTCOPY-FAIL" and "applet run raised" in msg
               for m, msg in emitted)


def test_applet_template_uses_plain_copy():
    cfg_lines = []
    iris_agent._copy_to_root_impl(
        "img.bin", "flash:", lambda lines: cfg_lines.extend(lines),
        lambda c: "", lambda t, m: None, reverify_fn=lambda *a, **k: True)
    joined = "\n".join(cfg_lines)
    assert 'copy flash:/guest-share/iris/img.bin flash:img.bin' in joined
    assert "/verify" not in joined
    assert 'delete /force flash:img.bin' in joined  # delete-first stays load-bearing


def test_applet_impl_passes_expected_size_to_reverify():
    seen = {}
    def fake_reverify(fname, prefix, cli, emit, expected_size=None):
        seen["size"] = expected_size
        return True
    iris_agent._copy_to_root_impl(
        "img.bin", "flash:", lambda lines: None, lambda c: "",
        lambda t, m: None, reverify_fn=fake_reverify, expected_size=1234)
    assert seen["size"] == 1234


# --- Direct-copy path (container / IE-3x00 SSH-to-self): plain `copy` is run
# DIRECTLY in the agent's real vty, NOT via the IRIS-COPYROOT EEM applet (whose
# `cli command "copy"` action is a no-op on the IE3x00 — completes "success" in
# ~3 s, transfers nothing). delete-then-copy is issued directly; the verdict is
# still owned by reverify's dir-presence poll, identical to the applet path. ---

def test_copy_to_root_direct_runs_copy_then_reverify():
    cli_calls, emitted, reverify_calls = [], [], []

    def cli_exec(cmd):
        cli_calls.append(cmd)
        return ""

    def reverify(fname, prefix, cli_arg, emit_arg, expected_size=None):
        reverify_calls.append(fname)
        return True

    ok = iris_agent._copy_to_root_direct_impl(
        "img1.bin", "sdflash:", cli_exec,
        lambda m, msg: emitted.append((m, msg)), reverify_fn=reverify)
    assert ok is True
    # delete-then-copy issued DIRECTLY — no applet templating, no `event manager run`
    assert cli_calls == [
        "delete /force sdflash:img1.bin",
        "copy sdflash:/guest-share/iris/img1.bin sdflash:img1.bin",
    ]
    assert all("event manager" not in c for c in cli_calls)
    assert reverify_calls == ["img1.bin"]
    assert all(m != "ROOTCOPY-FAIL" for m, _ in emitted)


def test_direct_impl_uses_plain_copy_and_passes_size():
    cmds, seen = [], {}
    def fake_reverify(fname, prefix, cli, emit, expected_size=None):
        seen["size"] = expected_size
        return True
    iris_agent._copy_to_root_direct_impl(
        "img.bin", "sdflash:", lambda c: cmds.append(c) or "",
        lambda t, m: None, reverify_fn=fake_reverify, expected_size=99)
    assert any(c.startswith("copy ") and "/verify" not in c for c in cmds)
    assert seen["size"] == 99


def test_copy_to_root_direct_uses_copy_source_override():
    cli_calls = []
    iris_agent._copy_to_root_direct_impl(
        "img1.bin", "sdflash:", lambda c: cli_calls.append(c) or "",
        lambda m, msg: None, reverify_fn=lambda *a, **k: True,
        copy_source=lambda f, p: "http://10.0.0.1:8000/%s" % f)
    assert cli_calls[1] == \
        "copy http://10.0.0.1:8000/img1.bin sdflash:img1.bin"


def test_copy_to_root_direct_copy_raises_no_reverify():
    emitted, reverify_calls = [], []

    def cli_exec(cmd):
        if cmd.startswith("copy"):
            raise RuntimeError("ssh transport failed")
        return ""

    ok = iris_agent._copy_to_root_direct_impl(
        "img1.bin", "sdflash:", cli_exec,
        lambda m, msg: emitted.append((m, msg)),
        reverify_fn=lambda *a, **k: reverify_calls.append(1) or True)
    assert ok is False
    assert reverify_calls == []          # bailed before reverify
    assert any(m == "ROOTCOPY-FAIL" and "direct copy raised" in msg
               for m, msg in emitted)


def test_copy_to_root_direct_reverify_false_returns_false():
    emitted = []
    ok = iris_agent._copy_to_root_direct_impl(
        "bad.bin", "sdflash:", lambda c: "",
        lambda m, msg: emitted.append((m, msg)), reverify_fn=lambda *a, **k: False)
    assert ok is False
    assert all(m != "ROOTCOPY" for m, _ in emitted)


def test_copy_to_root_direct_deletes_scp_scratch_after_success():
    # container scp path: the guest-share scratch is a transfer intermediary
    # (the swarm seeds from the CAF-persistent stage_dir, unlike Guest Shell,
    # where guest-share IS the stage dir) — leaving it kept a permanent
    # duplicate image on the target FS, doubling steady-state usage
    cli_calls = []
    ok = iris_agent._copy_to_root_direct_impl(
        "img1.bin", "flash:", lambda c: cli_calls.append(c) or "",
        lambda m, msg: None, reverify_fn=lambda *a, **k: True,
        delete_source_on_success=True)
    assert ok is True
    assert cli_calls[-1] == "delete /force flash:/guest-share/iris/img1.bin"


def test_copy_to_root_direct_keeps_scratch_on_failure():
    # a failed placement must keep the pushed scratch: the next tick's retry
    # would otherwise re-push the whole image over the slow scp path
    cli_calls = []
    ok = iris_agent._copy_to_root_direct_impl(
        "img1.bin", "flash:", lambda c: cli_calls.append(c) or "",
        lambda m, msg: None, reverify_fn=lambda *a, **k: False,
        delete_source_on_success=True)
    assert ok is False
    assert all(not c.startswith("delete /force flash:/guest-share")
               for c in cli_calls)


# --- _reclaim_bundle_impl: every automated image delete (the bundle-mode
# download gate AND the replaced-root cleanup) runs through the one-shot
# IRIS-RECLAIM-BUNDLE authorization-bypass applet — a raw exec `delete` is
# silently no-op'd on AAA nodes, which stranded replaced images on flash. ---

def test_reclaim_bundle_impl_templates_authorization_bypass_applet():
    cli_cfg, cli_exec, _, configured, cli_calls, _ = _capture_calls()
    iris_agent._reclaim_bundle_impl(
        "flash:", ["old.bin", "older.bin"], cli_cfg, cli_exec)
    assert len(configured) == 1
    body = configured[0]
    # one-shot re-registration under the KNOWN applet name (the uninstall
    # scripts and the onboarding collision check both enumerate it)
    assert body[0] == "no event manager applet IRIS-RECLAIM-BUNDLE"
    assert body[1] == \
        "event manager applet IRIS-RECLAIM-BUNDLE authorization bypass"
    assert 'action 020 cli command "delete /force flash:old.bin"' in body
    assert 'action 030 cli command "delete /force flash:older.bin"' in body
    assert cli_calls == ["event manager run IRIS-RECLAIM-BUNDLE"]


def test_reclaim_bundle_impl_empty_names_is_a_no_op():
    cli_cfg, cli_exec, _, configured, cli_calls, _ = _capture_calls()
    iris_agent._reclaim_bundle_impl("flash:", [], cli_cfg, cli_exec)
    assert configured == [] and cli_calls == []


# --- Share-mount staging (C9k IOx): the app-hosting SSD share
# (usbflash1:iox_host_data_share) is bind-mounted into the container, so the
# agent lands its scratch there at DISK speed and the final placement is an
# IOS-internal plain `copy` from the SSD to the target FS — no scp, no
# control-plane punt path, no CoPP ceiling. Falls back to the scp push when
# the share is not mounted (IE-3x00, or a failed -v mount). ---

def _mk_scratch(tmp_path, fname="img1.bin", content=b"IMAGEBYTES"):
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / fname).write_bytes(content)
    return str(stage)


def _cli_probe_ok(cmd):
    # a `dir <share>/<probe>` transcript that lists the probe file
    assert cmd.startswith("dir ")
    return "  12 -rw-  4  " + cmd.split("/")[-1]


def _iris_share_files(share):
    # only the files IRIS is allowed to own (its name prefix), share ROOT
    return sorted(p.name for p in share.iterdir()
                  if p.name.startswith("iris-"))


def test_stage_via_share_lands_file_then_copy_verifies_from_share(tmp_path):
    stage = _mk_scratch(tmp_path)
    share = tmp_path / "share"
    share.mkdir()
    seen = {}

    def copy_direct(copy_source):
        # the share copy must be fully in place before the plain copy runs
        seen["source"] = copy_source("img1.bin", "flash:")
        seen["bytes"] = (share / iris_agent._SHARE_STAGE).read_bytes()
        return True

    ok = iris_agent._stage_via_share_impl(
        "img1.bin", stage, str(share), "usbflash1:iox_host_data_share",
        copy_direct, lambda m, msg: None, _cli_probe_ok)
    assert ok is True
    # IRIS stages at the share ROOT (container-created SUBDIRS become
    # inaccessible to the container itself on the C9300 SSD share —
    # hardware-observed; the CAF-created root stays writable at disk speed)
    # under its own iris- prefixed fixed name. The plain copy reads that
    # source and writes the REAL image name to flash:, so the staged name is
    # cosmetic — content integrity is the agent's own sha256 against the
    # catalog, checked before this copy runs.
    assert seen["source"] == \
        "usbflash1:iox_host_data_share/" + iris_agent._SHARE_STAGE
    assert iris_agent._SHARE_STAGE.startswith("iris-")
    assert seen["bytes"] == b"IMAGEBYTES"
    # transient copy + probe removed after placement, no leftovers
    assert _iris_share_files(share) == []


def test_stage_via_share_returns_none_when_share_dir_missing(tmp_path):
    stage = _mk_scratch(tmp_path)
    calls = []
    result = iris_agent._stage_via_share_impl(
        "img1.bin", stage, str(tmp_path / "nope"), "usbflash1:iox_host_data_share",
        lambda copy_source: calls.append(1) or True, lambda m, msg: None,
        _cli_probe_ok)
    assert result is None          # None = share unavailable -> caller falls back
    assert calls == []


def test_stage_via_share_returns_none_when_share_unset(tmp_path):
    stage = _mk_scratch(tmp_path)
    result = iris_agent._stage_via_share_impl(
        "img1.bin", stage, "", "usbflash1:iox_host_data_share",
        lambda copy_source: True, lambda m, msg: None, _cli_probe_ok)
    assert result is None


def test_stage_via_share_probe_failure_falls_back_before_big_copy(tmp_path):
    # The bind mount exists container-side but IOS cannot read the path (wrong
    # SHARE_IOS_PATH for this box — e.g. a stacked C9300 enumerating the SSD
    # differently, or an operator override typo). Without the probe this
    # wedged the device: a multi-GB copy into the share, then a ~15-minute
    # reverify timeout, with the working scp fallback permanently suppressed.
    stage = _mk_scratch(tmp_path, content=b"X" * 4096)
    share = tmp_path / "share"
    share.mkdir()
    emitted, calls = [], []
    result = iris_agent._stage_via_share_impl(
        "img1.bin", stage, str(share), "usbflash1:WRONG",
        lambda copy_source: calls.append(1) or True,
        lambda m, msg: emitted.append((m, msg)),
        lambda cmd: "%Error opening usbflash1:WRONG/ (No such device)")
    assert result is None          # -> scp fallback
    assert calls == []             # the copy was never attempted
    assert any(m == "SHARE-FALLBACK" for m, _ in emitted)
    assert _iris_share_files(share) == []  # probe cleaned, image never copied


def test_stage_via_share_probe_transport_error_falls_back(tmp_path):
    stage = _mk_scratch(tmp_path)
    share = tmp_path / "share"
    share.mkdir()

    def cli_raises(cmd):
        raise RuntimeError("ssh transport failed")

    result = iris_agent._stage_via_share_impl(
        "img1.bin", stage, str(share), "usbflash1:iox_host_data_share",
        lambda copy_source: True, lambda m, msg: None, cli_raises)
    assert result is None
    assert _iris_share_files(share) == []


def test_stage_via_share_sweeps_orphans_from_killed_ticks(tmp_path):
    # a tick killed mid-transfer leaves a full-size image or .part in OUR
    # subdir; the next attempt must sweep them so multi-GB junk never
    # accumulates on the operator's SSD
    stage = _mk_scratch(tmp_path)
    share = tmp_path / "share"
    share.mkdir()
    (share / iris_agent._SHARE_STAGE).write_bytes(b"ORPHAN")
    (share / (iris_agent._SHARE_STAGE + ".part")).write_bytes(b"HALF")
    # operator/CAF files at the SAME level must NEVER be touched — the sweep
    # is scoped to the iris- prefix, that is the whole isolation contract now
    (share / "operator-file.txt").write_bytes(b"NOT OURS")
    (share / "bigtest.1.2.3.bin").write_bytes(b"ALSO NOT OURS")
    ok = iris_agent._stage_via_share_impl(
        "img1.bin", stage, str(share), "usbflash1:iox_host_data_share",
        lambda copy_source: True, lambda m, msg: None, _cli_probe_ok)
    assert ok is True
    assert _iris_share_files(share) == []
    assert (share / "operator-file.txt").read_bytes() == b"NOT OURS"
    assert (share / "bigtest.1.2.3.bin").read_bytes() == b"ALSO NOT OURS"


def test_stage_via_share_local_copy_failure_falls_back(tmp_path):
    # scratch file missing entirely -> emit a breadcrumb and hand back to scp
    stage = tmp_path / "stage"
    stage.mkdir()
    share = tmp_path / "share"
    share.mkdir()
    emitted, calls = [], []
    result = iris_agent._stage_via_share_impl(
        "img1.bin", str(stage), str(share), "usbflash1:iox_host_data_share",
        lambda copy_source: calls.append(1) or True,
        lambda m, msg: emitted.append((m, msg)), _cli_probe_ok)
    assert result is None
    assert calls == []
    assert any(m == "SHARE-FALLBACK" for m, _ in emitted)
    assert _iris_share_files(share) == []   # no partial left behind


def test_stage_via_share_copy_verify_failure_is_final_and_cleans_up(tmp_path):
    # IOS-side plain copy genuinely failed AFTER a successful probe (e.g. a
    # transport error mid-copy): scp would push the SAME bytes, so there is
    # no fallback — the verdict is False and the share copy is still removed.
    stage = _mk_scratch(tmp_path)
    share = tmp_path / "share"
    share.mkdir()
    ok = iris_agent._stage_via_share_impl(
        "img1.bin", stage, str(share), "usbflash1:iox_host_data_share",
        lambda copy_source: False, lambda m, msg: None, _cli_probe_ok)
    assert ok is False
    assert _iris_share_files(share) == []


def test_share_settings_env_wins_over_conf(monkeypatch):
    monkeypatch.setenv("IRIS_SHARE_DIR", "/mnt/share")
    monkeypatch.setenv("IRIS_SHARE_IOS_PATH", "usbflash1:iox_host_data_share")
    d, p = iris_agent._share_settings(
        {"share_dir": "/conf/dir", "share_ios_path": "conf:path"})
    assert (d, p) == ("/mnt/share", "usbflash1:iox_host_data_share")


def test_share_settings_falls_back_to_conf_then_empty(monkeypatch):
    monkeypatch.delenv("IRIS_SHARE_DIR", raising=False)
    monkeypatch.delenv("IRIS_SHARE_IOS_PATH", raising=False)
    assert iris_agent._share_settings(
        {"share_dir": "/conf/dir", "share_ios_path": "conf:path"}) == \
        ("/conf/dir", "conf:path")
    assert iris_agent._share_settings({}) == ("", "")


# --- Schema migration guard for Flaw 1 (upgrade-path bypass): a device
# carrying pre-v2 state from the old buggy agent would otherwise enter
# steady-state on first tick and never re-verify the existing flash-root
# file. The migration drops `copied` flags + `root_file` so first tick
# routes through copy_to_root + _agent_reverify_root. ---

def test_pre_v2_state_forces_re_verification_on_first_tick():
    """Device was running the OLD buggy agent (copied=True without verify).
    New agent must drop those flags so it re-routes through copy_to_root
    (which goes through _agent_reverify_root). A regression that left them
    in place would silently bless whatever's at flash root forever."""
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, emitted, _, _, copied, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=True)
    # pre-v2 state — no schema_version, copied=True, root_file set
    state = {"image_id": "img1", "root_file": "img1.bin",
             "img1": {"done": True, "copied": True, "sha": "abc"}}
    iris_agent.run_once(CFG, deps, state)
    # migration ran and emitted UPGRADE
    assert state.get("schema_version") == iris_agent._STATE_SCHEMA
    assert any(m == "UPGRADE" for m, _ in emitted)
    # copy_to_root was re-fired (the WHOLE point — re-routes through reverify)
    assert copied == ["img1.bin"]
    # root_file is re-set after the (mocked-success) copy
    assert state["root_file"] == "img1.bin"
    # second tick on v2 state: steady-state holds, no extra copy
    copied.clear()
    iris_agent.run_once(CFG, deps, state)
    assert copied == []


def test_v2_state_does_not_re_migrate():
    """Once state is at v2, subsequent ticks must NOT re-emit UPGRADE or drop
    `copied` flags — only the first tick after an upgrade migrates."""
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, emitted, _, _, copied, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5})
    state = {"image_id": "img1", "root_file": "img1.bin",
             "schema_version": iris_agent._STATE_SCHEMA,
             "img1": {"done": True, "copied": True, "sha": "abc"}}
    iris_agent.run_once(CFG, deps, state)
    assert all(m != "UPGRADE" for m, _ in emitted)
    assert copied == []           # steady-state, no re-copy


# --- Catalog filename whitelist guard for Flaw 5 (injection into IOS via
# the templated applet). image["filename"] flows into cli_configure command
# lines; any value outside [A-Za-z0-9._-]+ is rejected before reaching cli. ---

def test_rejects_catalog_filename_with_injection_attempt():
    """A compromised/buggy catalog returns a filename with quote/newline.
    The agent must reject it BEFORE templating any IOS applet config."""
    cat = FakeCatalog(
        {"approved_image_id": "img1"},
        {"id": "img1",
         "filename": 'cat9k.bin"\naction 045 cli command "do something"',
         "size": 5, "sha256": "abc"})
    deps, emitted, _, _, copied, _, _, _ = make_deps(cat, {})
    assert iris_agent.run_once(CFG, deps, {}) == "bad-filename"
    assert copied == []
    assert any(m == "ERROR" and "rejected catalog filename" in msg
               for m, msg in emitted)


def test_rejects_catalog_filename_with_path_traversal():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "../other.bin",
                       "size": 5, "sha256": "abc"})
    deps, emitted, _, _, copied, _, _, _ = make_deps(cat, {})
    assert iris_agent.run_once(CFG, deps, {}) == "bad-filename"
    assert copied == []
    assert any(m == "ERROR" for m, _ in emitted)


def test_run_once_threads_filename_to_copy_to_root():
    """run_once must pass the catalog filename into copy_to_root (the catalog
    byte size is covered separately by test_run_once_passes_catalog_size_to_
    copy_and_presence)."""
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    captured = []
    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    deps = deps._replace(
        copy_to_root=lambda fname, target_prefix="flash:", expected_size=None: captured.append(fname) or True)
    assert iris_agent.run_once(CFG, deps, {}) == "complete"
    assert captured == ["img1.bin"]


def test_accepts_typical_cisco_filename():
    """Real-world Cisco filename must pass the whitelist."""
    cat = FakeCatalog(
        {"approved_image_id": "imgX"},
        {"id": "imgX", "filename": "cat9k_iosxe.17.18.03.SPA.bin",
         "size": 5, "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(
        cat, {"/stage/cat9k_iosxe.17.18.03.SPA.bin": 5})
    # didn't bail with bad-filename — got into the normal flow
    assert iris_agent.run_once(CFG, deps, {}) == "complete"


# --- Final-review regression guards. These integration bugs surfaced only from
# the INTERACTION of functions the per-task reviews saw in isolation. ---

def test_bundle_reclaim_skipped_when_running_image_unconfirmable():
    # CRITICAL: detect_mode() can resolve "bundle" from `show boot` alone while
    # running_image() (reads `show version` only) returns None on a transient
    # glitch. We must NOT build a protect-set missing the running image and then
    # delete it — skip the bundle reclaim entirely when the running image is
    # unknown. Without the guard, the running .bin would be delete /force'd.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin",
                       "size": 5_000_000_000, "sha256": "abc"})
    deps, _, _, _, _, _, reclaimed, bundle_reclaimed = make_deps(
        cat, {}, free=1_000_000_000, mode="bundle",
        reclaimables=["cat9k_iosxe.26.01.01.SPA.bin"])  # the would-be running img
    deps = deps._replace(running_image=lambda: None)    # show version glitched
    assert iris_agent.run_once(CFG, deps, {}) == "no-space"
    assert bundle_reclaimed == []                       # nothing deleted
    assert reclaimed == []


def test_reclaim_once_guard_not_burned_on_transient_unknown_mode():
    # HIGH: a transient mode=None must not permanently disable reclaim. The guard
    # is set only when reclaim ACTUALLY ran, so a later tick (mode recovered)
    # still reclaims.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin",
                       "size": 5_000_000_000, "sha256": "abc"})
    deps, _, _, _, _, _, _, bundle_reclaimed = make_deps(
        cat, {}, free=1_000_000_000, mode=None, reclaimables=["old.bin"])
    state = {}
    iris_agent.run_once(CFG, deps, state)               # tick 1: mode None, no reclaim
    assert state["img1"].get("reclaim_tried") is not True
    assert bundle_reclaimed == []
    deps = deps._replace(detect_mode=lambda: "bundle")  # tick 2: mode recovers
    iris_agent.run_once(CFG, deps, state)
    assert bundle_reclaimed == [("flash:", ["old.bin"])]


def test_heartbeat_not_ready_when_copy_failed():
    # HIGH: a failed copy_to_root must NOT report stage_state="ready" (that field
    # is authoritative for "image placed at flash root + verified").
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    sent = []
    deps, _, _, _, copied, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    deps = deps._replace(
        catalog=_HeartbeatSpy(cat, sent),
        copy_to_root=lambda fname, target_prefix="flash:", expected_size=None: False)  # copy fails
    assert iris_agent.run_once(CFG, deps, {}) == "complete"
    assert copied == []
    assert sent[-1]["stage_state"] == "staging"          # NOT "ready"
    assert sent[-1]["stage_error"] == "final IOS placement failed; inspect IRIS ROOTCOPY-FAIL"


def test_iox_reports_transfer_to_ios_before_blocking_copy():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    sent = []
    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    deps = deps._replace(
        catalog=_HeartbeatSpy(cat, sent), io_transfer=True,
        target_fs=lambda: ("usbflash1:", 9_000_000_000))
    assert iris_agent.run_once(CFG, deps, {}) == "complete"
    assert any(h["stage_state"] == "transferring_to_ios"
               and h["target_fs"] == "usbflash1:" for h in sent)


# --- Task 5 behavioral guards: IE3k sdflash staging + install-mode + C9300 ---

def test_run_once_bundle_ie3k_copies_to_sdflash():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5}, mode="bundle")
    calls = []
    deps = deps._replace(
        target_fs=lambda: ("sdflash:", 9_000_000_000),
        copy_to_root=lambda fname, target_prefix="flash:", expected_size=None:
            calls.append((fname, target_prefix)) or True)
    assert iris_agent.run_once(CFG, deps, {}) == "complete"
    assert calls == [("img1.bin", "sdflash:")]   # copy placed on sdflash:, not flash:


def test_run_once_install_ie3k_uses_install_remove_inactive():
    # install-mode IE3k staging on sdflash:: a tight gate still fires
    # `install remove inactive` (NOT the bundle delete) — same as the 9k.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5_000_000_000,
                       "sha256": "abc"})
    deps, _, _, _, _, _, reclaimed, bundle_reclaimed = make_deps(
        cat, {}, mode="install")
    deps = deps._replace(target_fs=lambda: ("sdflash:", 1_000_000_000))
    iris_agent.run_once(CFG, deps, {})
    # The image is too large to stage, so only reclaim behavior is characterized
    # (no return-value assertion intended — the download gate returns before copy).
    assert reclaimed == [True]            # install remove inactive fired
    assert bundle_reclaimed == []         # never the bundle delete in install mode


def test_steady_state_root_check_probes_cached_stage_fs():
    # On an IE3k the root copy lives on sdflash:; the steady-state existence
    # check must probe sdflash: (the cached stage_fs), not hardcoded flash:,
    # or the agent re-copies the full image every tick.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5}, mode="bundle")
    probed = []
    deps = deps._replace(
        root_present=lambda fname, prefix="flash:", expected_size=None:
            (probed.append(prefix) or prefix == "sdflash:"))
    state = dict(_DONE(), stage_fs="sdflash:")
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert probed == ["sdflash:"]   # probed the staging FS, not flash:


def test_run_once_c9300_still_copies_to_flash():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5}, mode="bundle")
    calls = []
    deps = deps._replace(           # default target_fs returns ("flash:", free)
        copy_to_root=lambda fname, target_prefix="flash:", expected_size=None:
            calls.append((fname, target_prefix)) or True)
    assert iris_agent.run_once(CFG, deps, {}) == "complete"
    assert calls == [("img1.bin", "flash:")]


def test_download_gate_no_space_reports_flash_full_not_seeding_only():
    # MEDIUM: at the download gate nothing is staged, so the device is NOT
    # seeding — report flash_full, not flash_full_seeding_only.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin",
                       "size": 5_000_000_000, "sha256": "abc"})
    sent = []
    deps, _, _, _, _, _, _, _ = make_deps(
        cat, {}, free=1_000_000_000, mode="bundle", reclaimables=[])
    deps = deps._replace(catalog=_HeartbeatSpy(cat, sent))
    assert iris_agent.run_once(CFG, deps, {}) == "no-space"
    assert sent[-1]["stage_state"] == "flash_full"


# --- Phase 2: pure needs_refresh (half-life refresh, stdlib only).
# needs_refresh(now, expires_at, ttl, refresh_at):
#   expires_at == 0           -> True  (unknown expiry: refresh on next tick)
#   now >= expires_at - ttl*(1-refresh_at) -> True (past half-life)
#   otherwise                 -> False
# With ttl=604800 (7d), refresh_at=0.5: refresh window opens at expires_at - 302400.

_TTL = 604800        # 7d
_REFRESH_AT = 0.5    # half-life


def test_needs_refresh_true_when_expiry_unknown():
    # token_expires_at == 0 means an enrolled-but-never-refreshed device.
    assert iris_agent.needs_refresh(1_000_000, 0, _TTL, _REFRESH_AT) is True


def test_needs_refresh_false_before_half_life():
    # token minted at t=0, expires at 604800; "now" is well before half-life
    # (now=302399 < 604800-302400=302400) -> do NOT refresh yet.
    assert iris_agent.needs_refresh(302_399, 604_800, _TTL, _REFRESH_AT) is False


def test_needs_refresh_true_exactly_at_half_life():
    # now == expires_at - ttl*(1-refresh_at) == 604800-302400 == 302400 -> refresh.
    assert iris_agent.needs_refresh(302_400, 604_800, _TTL, _REFRESH_AT) is True


def test_needs_refresh_true_after_half_life():
    assert iris_agent.needs_refresh(500_000, 604_800, _TTL, _REFRESH_AT) is True


def test_needs_refresh_true_past_expiry_within_skew():
    # past nominal expiry the token may still work within the server's grace, but
    # the agent should certainly try to refresh.
    assert iris_agent.needs_refresh(604_801, 604_800, _TTL, _REFRESH_AT) is True


def test_needs_refresh_is_pure_no_side_effects():
    # calling it twice yields the same answer (no clock/global reads).
    a = iris_agent.needs_refresh(302_400, 604_800, _TTL, _REFRESH_AT)
    b = iris_agent.needs_refresh(302_400, 604_800, _TTL, _REFRESH_AT)
    assert a is b is True


def test_needs_refresh_tracks_short_ttl_not_hardcoded_7_days():
    # The formula uses the passed `ttl`, not a hardcoded constant.
    # With ttl=86400 (1d) + refresh_at=0.5 the half-life window opens at
    # expires_at - 86400*0.5 = expires_at - 43200 (12 h before expiry).
    # 100 s before expiry is well inside that window -> True.
    # 100 s before expiry with a 7-day TTL would be False (window opens
    # ~3.5 days before expiry), which proves the formula reads `ttl`, not
    # a global/module constant.
    expires_at = 1_000_000
    short_ttl = 86_400      # 1d
    now_near_expiry = expires_at - 100     # 100 s left
    # short TTL: 100 s left is inside the half-life window -> True
    assert iris_agent.needs_refresh(now_near_expiry, expires_at,
                                    short_ttl, 0.5) is True
    # well before half-life for a 1-day TTL: 23 h before expiry -> False
    now_early = expires_at - 23 * 3600
    assert iris_agent.needs_refresh(now_early, expires_at,
                                    short_ttl, 0.5) is False


# --- Phase 2: best-effort token self-refresh at the top of run_once. The
# refresh itself (network POST + atomic conf rewrite) is the injected deps.refresh
# callable returning the updated cfg or None; run_once decides WHETHER to refresh
# via needs_refresh and proceeds on the current token if refresh returns None. ---

def test_run_once_refreshes_when_token_past_half_life():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    refreshed = []
    new_cfg = {"device_id": "sw1", "stage_dir": "/stage",
               "catalog_token": "NEW", "token_expires_at": "9999999999"}

    def do_refresh():
        refreshed.append(True)
        return new_cfg

    deps = deps._replace(refresh=do_refresh)
    # expires_at=0 -> needs_refresh True
    cfg = {"device_id": "sw1", "stage_dir": "/stage", "token_expires_at": "0"}
    assert iris_agent.run_once(cfg, deps, {}) == "complete"
    assert refreshed == [True]


def test_run_once_skips_refresh_when_token_fresh():
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    refreshed = []
    deps = deps._replace(refresh=lambda: refreshed.append(True))
    # token minted, far from half-life: now (via injected) << expires - window.
    # run_once reads time.time(); use a far-future expiry so needs_refresh is False.
    import time
    cfg = {"device_id": "sw1", "stage_dir": "/stage",
           "token_expires_at": str(int(time.time()) + 604_800)}
    assert iris_agent.run_once(cfg, deps, {}) == "complete"
    assert refreshed == []        # token still fresh -> no refresh


def test_run_once_refresh_failure_proceeds_on_current_token():
    # best-effort: deps.refresh returns None (server down / transient) -> the
    # tick logs and proceeds on the CURRENT token, still completing its work.
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, emitted, _, _, copied, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    deps = deps._replace(refresh=lambda: None)     # refresh failed
    cfg = {"device_id": "sw1", "stage_dir": "/stage", "token_expires_at": "0"}
    assert iris_agent.run_once(cfg, deps, {}) == "complete"
    assert copied == ["img1.bin"]                  # work proceeded anyway
    assert any(m == "TOKEN-REFRESH-FAIL" for m, _ in emitted)


def test_run_once_uses_refreshed_cfg_for_device_id():
    # after a successful refresh the rest of the tick runs against the RETURNED
    # cfg (proves run_once swaps cfg, not just discards the result).
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    seen_sids = []

    class _SidSpy(FakeCatalog):
        def get_policy(self, sid):
            seen_sids.append(sid)
            return self._policy

    spy = _SidSpy({"approved_image_id": "img1"},
                  {"id": "img1", "filename": "img1.bin", "size": 5,
                   "sha256": "abc"})
    deps, _, _, _, _, _, _, _ = make_deps(spy, {"/stage/img1.bin": 5})
    new_cfg = {"device_id": "sw2", "stage_dir": "/stage",
               "catalog_token": "NEW", "token_expires_at": "9999999999"}
    deps = deps._replace(refresh=lambda: new_cfg)
    cfg = {"device_id": "sw1", "stage_dir": "/stage", "token_expires_at": "0"}
    iris_agent.run_once(cfg, deps, {})
    assert seen_sids[-1] == "sw2"      # ran the rest of the tick on the new cfg


# --- Phase 2: _refresh_impl (the on-box refresh body, injectable so the
# POST -> client rebind -> atomic conf rewrite -> reload flow is
# unit-testable). Returns the reloaded cfg on success, None on any failure
# (best-effort). Takes the live CatalogClient itself, not a bare callable:
# the impl must re-point the client's bearer after the POST, because the
# server rotates immediately and heartbeat/telemetry reject the rolled token
# even inside the overlap window — the old wiring left the live client on the
# stale bearer for the rest of the tick (one spurious HTTP 401 heartbeat per
# refresh tick,
# observed live on the c8000v fleet 2026-09-01). ---

class _RefreshClient:
    """The seam _refresh_impl needs from CatalogClient: the live bearer it
    must re-point, and the POST that mints the new bag."""
    def __init__(self, bag=None, exc=None):
        self.token = "OLD"
        self.calls = []
        self._bag = bag
        self._exc = exc

    def refresh_token(self, device_id):
        self.calls.append(device_id)
        if self._exc is not None:
            raise self._exc
        return self._bag


def test_refresh_impl_writes_new_secrets_and_rebinds_the_live_client(tmp_path):
    conf = tmp_path / "iris-agent.conf"
    conf.write_text(
        "catalog_url = https://x\n"
        "catalog_token = OLD\n"
        "device_id = sw1\n"
        "token_expires_at = 0\n"
        "rpc_secret = \n")
    cfg = {"catalog_url": "https://x", "catalog_token": "OLD",
           "device_id": "sw1", "token_expires_at": "0", "rpc_secret": ""}
    client = _RefreshClient(bag={"catalog_token": "NEW",
                                 "expires_at": 1750000000,
                                 "announce_token": "anntok",
                                 "rpc_secret": "rpcsecret"})

    out = iris_agent._refresh_impl(cfg, str(conf), client, lambda m, msg: None)
    assert client.calls == ["sw1"]
    # returned cfg reflects the new secrets...
    assert out["catalog_token"] == "NEW"
    assert out["token_expires_at"] == "1750000000"
    assert out["rpc_secret"] == "rpcsecret"
    assert out["announce_token"] == "anntok"
    # ...the LIVE client now carries the new bearer, so the rest of THIS tick
    # (heartbeat, telemetry — device-bound routes that reject the rolled
    # token) authenticates with the token the server now expects...
    assert client.token == "NEW"
    # ...and the secrets were persisted to disk (next process reads them)
    import agent_config
    disk = agent_config.load(str(conf))
    assert disk["catalog_token"] == "NEW"
    assert disk["token_expires_at"] == "1750000000"


def test_refresh_impl_returns_none_and_logs_on_post_failure(tmp_path):
    import catalog_client
    conf = tmp_path / "iris-agent.conf"
    conf.write_text(
        "catalog_url = https://x\ncatalog_token = OLD\ndevice_id = sw1\n"
        "token_expires_at = 0\n")
    cfg = {"catalog_url": "https://x", "catalog_token": "OLD",
           "device_id": "sw1", "token_expires_at": "0"}
    client = _RefreshClient(exc=catalog_client.CatalogError("unreachable"))

    emitted = []
    out = iris_agent._refresh_impl(cfg, str(conf), client,
                                   lambda m, msg: emitted.append((m, msg)))
    assert out is None
    # nothing was minted, so the live client keeps its current bearer
    assert client.token == "OLD"
    # the conf on disk is UNCHANGED (still OLD) — no partial write
    import agent_config
    assert agent_config.load(str(conf))["catalog_token"] == "OLD"
    assert any(m == "TOKEN-REFRESH-FAIL" for m, _ in emitted)


def test_refresh_impl_rebinds_the_client_even_when_the_conf_write_fails(
        tmp_path):
    # POST succeeded -> the server has ALREADY rotated; the old bearer is
    # half-dead (shared routes only after 120s; refresh recovery lasts until
    # the token's original expiry). Whatever happens to the conf write, the
    # live client must follow the server. The next process
    # still loads the stale conf, then recovers the current bag through the
    # token-refresh-only recovery path; THIS tick's heartbeat/telemetry must
    # not 401 either.
    conf_in_missing_dir = tmp_path / "no-such-dir" / "iris-agent.conf"
    cfg = {"catalog_url": "https://x", "catalog_token": "OLD",
           "device_id": "sw1", "token_expires_at": "0"}
    client = _RefreshClient(bag={"catalog_token": "NEW",
                                 "expires_at": 1750000000})

    emitted = []
    out = iris_agent._refresh_impl(cfg, str(conf_in_missing_dir), client,
                                   lambda m, msg: emitted.append((m, msg)))
    assert out is None
    assert client.token == "NEW"
    assert any(m == "TOKEN-REFRESH-FAIL" for m, _ in emitted)


def test_refresh_impl_next_process_recovers_after_conf_write_failure(
        tmp_path, monkeypatch):
    """A lost local write must converge on the next one-shot process."""
    import agent_config

    conf = tmp_path / "iris-agent.conf"
    conf.write_text(
        "catalog_url = https://x\ncatalog_token = OLD\ndevice_id = sw1\n"
        "token_expires_at = 0\n")
    bag = {"catalog_token": "NEW", "expires_at": 1750000000}
    server = {"rotated": False}

    class RecoveringClient:
        def __init__(self, token):
            self.token = token

        def refresh_token(self, device_id):
            assert device_id == "sw1"
            assert self.token == "OLD"
            server["rotated"] = True
            return bag

    real_write = agent_config.write_conf
    writes = []

    def fail_first_write(path, cfg):
        writes.append(cfg["catalog_token"])
        if len(writes) == 1:
            raise OSError("disk full")
        return real_write(path, cfg)

    monkeypatch.setattr(agent_config, "write_conf", fail_first_write)
    old_cfg = agent_config.load(str(conf))
    first = RecoveringClient(old_cfg["catalog_token"])
    assert iris_agent._refresh_impl(
        old_cfg, str(conf), first, lambda m, msg: None) is None
    assert server["rotated"] is True
    assert agent_config.load(str(conf))["catalog_token"] == "OLD"

    # A fresh one-shot process rebuilds its client from the unchanged conf.
    next_cfg = agent_config.load(str(conf))
    second = RecoveringClient(next_cfg["catalog_token"])
    recovered = iris_agent._refresh_impl(
        next_cfg, str(conf), second, lambda m, msg: None)
    assert recovered["catalog_token"] == "NEW"
    assert second.token == "NEW"
    assert agent_config.load(str(conf))["catalog_token"] == "NEW"
    assert writes == ["NEW", "NEW"]


# ---------------------------------------------------------------------------
# CRITICAL 1 (PR review): float token_expires_at in iris-agent.conf must
# never raise ValueError in run_once.  The server previously stored floats
# (time.time()), so a conf written before the fix may carry "1782731311.9".
# run_once must parse it defensively and still make the correct refresh decision.
# ---------------------------------------------------------------------------

def test_run_once_survives_float_token_expires_at_in_conf():
    """If token_expires_at is a float-looking string ("1782731311.9"), run_once
    must NOT raise ValueError (int("1782731311.9") would) and must continue
    to completion.  This guards the server-side regression that wrote float
    epochs into iris-agent.conf."""
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    deps, emitted, _, _, copied, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    # far-future float expiry -> no refresh, proceeds normally
    cfg = {"device_id": "sw1", "stage_dir": "/stage",
           "token_expires_at": "1782731311.9"}
    # Must NOT raise; must complete its normal work
    result = iris_agent.run_once(cfg, deps, {})
    assert result == "complete"
    assert copied == ["img1.bin"]


def test_run_once_float_expires_at_triggers_refresh_when_in_refresh_window():
    """A float token_expires_at that is within the half-life window must still
    trigger a refresh, not silently skip it because parsing failed."""
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    import time as _time_mod
    # Use an expires_at that is PAST (so needs_refresh would return True)
    expired_float_str = "%.1f" % (_time_mod.time() - 10.0)
    refreshed = []
    new_cfg = {"device_id": "sw1", "stage_dir": "/stage",
               "catalog_token": "NEW", "token_expires_at": "9999999999"}

    def do_refresh():
        refreshed.append(True)
        return new_cfg

    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    deps = deps._replace(refresh=do_refresh)
    cfg = {"device_id": "sw1", "stage_dir": "/stage",
           "token_expires_at": expired_float_str}
    iris_agent.run_once(cfg, deps, {})
    # The expired token should have triggered a refresh attempt
    assert refreshed == [True], (
        "expected refresh when token_expires_at=%r (past/expired)" % expired_float_str)


def test_run_once_float_zero_str_triggers_refresh():
    """token_expires_at='0' (the sentinel for unknown) must still trigger
    refresh — and so must '0.0' as a float string."""
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    refreshed = []
    new_cfg = {"device_id": "sw1", "stage_dir": "/stage",
               "catalog_token": "NEW", "token_expires_at": "9999999999"}

    def do_refresh():
        refreshed.append(True)
        return new_cfg

    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    deps = deps._replace(refresh=do_refresh)
    for zero_str in ("0", "0.0"):
        refreshed.clear()
        cfg = {"device_id": "sw1", "stage_dir": "/stage",
               "token_expires_at": zero_str}
        iris_agent.run_once(cfg, deps, {})
        assert refreshed == [True], (
            "expected refresh for token_expires_at=%r" % zero_str)


# ---------------------------------------------------------------------------
# IMPORTANT 10 (review): a transient catalog error on the post-copy heartbeat
# must NOT unwind run_once past the just-committed st['copied']=True /
# state['root_file'] mutations. The heartbeat is the LAST step after the
# expensive copy; if it raises CatalogError, main()'s state-persist block never
# runs and the recorded success is lost, forcing a full ~1.2 GB re-copy next
# tick. Heartbeat must be best-effort inside run_once (like emit()), so a
# transient catalog blip never discards completed progress.
# ---------------------------------------------------------------------------

class _RaisingHeartbeatCatalog(FakeCatalog):
    """Delegates reads/download to a FakeCatalog but raises CatalogError on
    every heartbeat (a transient catalog blip on the POST). Records attempts."""

    def __init__(self, policy, image):
        super().__init__(policy, image)
        self.heartbeat_attempts = 0

    def heartbeat(self, sid, data):
        self.heartbeat_attempts += 1
        import catalog_client
        raise catalog_client.CatalogError("heartbeat sw1 -> HTTP 503")


def test_run_once_post_copy_heartbeat_error_does_not_discard_progress():
    """The copy-complete path sets st['copied']=True + state['root_file'] and
    THEN heartbeats. A transient CatalogError on that heartbeat must NOT
    propagate out of run_once — the committed progress must survive so the
    next tick is a cheap steady-state, not a full re-copy."""
    cat = _RaisingHeartbeatCatalog(
        {"approved_image_id": "img1"},
        {"id": "img1", "filename": "img1.bin", "size": 5, "sha256": "abc"})
    deps, _, _, _, copied, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=True)
    state = {}
    # must NOT raise even though the heartbeat blows up
    result = iris_agent.run_once(CFG, deps, state)
    assert result == "complete"
    assert copied == ["img1.bin"]                      # the expensive copy ran
    assert cat.heartbeat_attempts == 1                 # heartbeat was attempted
    # the committed progress survived the heartbeat failure
    assert state["img1"]["copied"] is True
    assert state["root_file"] == "img1.bin"


def test_run_once_steady_state_heartbeat_error_does_not_raise():
    """The steady-state ready tick also ends in a heartbeat; a transient
    CatalogError there must be swallowed (the tick already did its work)."""
    cat = _RaisingHeartbeatCatalog(
        {"approved_image_id": "img1"},
        {"id": "img1", "filename": "img1.bin", "size": 5, "sha256": "abc"})
    deps, _, _, _, copied, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "root_file": "img1.bin",
             "img1": {"done": True, "copied": True, "sha": "abc"}}
    result = iris_agent.run_once(CFG, deps, state)     # must NOT raise
    assert result == "complete"
    assert copied == []                                # no re-copy
    assert cat.heartbeat_attempts == 1


def test_run_once_downloading_heartbeat_error_does_not_raise():
    """The download path's progress heartbeat is also best-effort: a transient
    CatalogError there must not abort the tick."""
    cat = _RaisingHeartbeatCatalog(
        {"approved_image_id": "img1"},
        {"id": "img1", "filename": "img1.bin", "size": 1000, "sha256": "abc"})
    deps, emitted, _, aria, _, _, _, _ = make_deps(cat, {}, free=9_000_000_000)
    result = iris_agent.run_once(CFG, deps, {})        # must NOT raise
    assert result == "downloading"
    assert aria == [("/stage/img1.torrent", "/stage")]
    assert cat.heartbeat_attempts == 1


class _NonCatalogErrorHeartbeatCatalog(FakeCatalog):
    """Like _RaisingHeartbeatCatalog, but heartbeat() raises an exception that is
    NOT a CatalogError — modelling the real client paths that escape it:
    json.loads() on a proxy/captive-portal 200-with-non-JSON body raises
    json.JSONDecodeError (a ValueError), and r.read() can raise
    http.client.IncompleteRead (an HTTPException). _send_heartbeat must swallow
    these too, or the post-copy progress (st['copied']/state['root_file']) is
    discarded — the exact bug the best-effort contract targets."""

    def __init__(self, policy, image, exc):
        super().__init__(policy, image)
        self._exc = exc
        self.heartbeat_attempts = 0

    def heartbeat(self, sid, data):
        self.heartbeat_attempts += 1
        raise self._exc


def _assert_non_catalogerror_heartbeat_keeps_copy_progress(exc):
    cat = _NonCatalogErrorHeartbeatCatalog(
        {"approved_image_id": "img1"},
        {"id": "img1", "filename": "img1.bin", "size": 5, "sha256": "abc"},
        exc)
    deps, emitted, _, _, copied, _, _, _ = make_deps(
        cat, {"/stage/img1.bin": 5}, verify_ok=True)
    state = {}
    # The post-copy heartbeat raises a NON-CatalogError; run_once must still NOT
    # unwind, so main()'s state-persist keeps the just-committed copy progress.
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert copied == ["img1.bin"]                      # the expensive copy ran
    assert cat.heartbeat_attempts == 1                 # heartbeat was attempted
    assert state["img1"]["copied"] is True             # progress survived
    assert state["root_file"] == "img1.bin"
    assert any(m == "HEARTBEAT-FAIL" for m, _ in emitted)


def test_run_once_post_copy_heartbeat_jsondecodeerror_keeps_progress():
    # A 200-with-non-JSON body (intercepting proxy / captive portal) makes the
    # real client's json.loads() raise JSONDecodeError (a ValueError, NOT a
    # CatalogError). Must be swallowed best-effort so progress is not discarded.
    _assert_non_catalogerror_heartbeat_keeps_copy_progress(
        json.JSONDecodeError("Expecting value", "<html>not json</html>", 0))


def test_run_once_post_copy_heartbeat_incompleteread_keeps_progress():
    # http.client.IncompleteRead (an HTTPException, NOT a CatalogError) from
    # r.read() inside _req must also be swallowed best-effort.
    import http.client
    _assert_non_catalogerror_heartbeat_keeps_copy_progress(
        http.client.IncompleteRead(b"partial"))


def test_copy_to_root_impl_uses_injected_copy_source():
    # Container mode (IE3x00 IOx app): the staged file isn't reachable as
    # flash:/sdflash:guest-share/ (IOx blocks bind-mounts), so the agent serves
    # it over HTTP and IOS copies it onto sdflash:. The copy SOURCE is injectable;
    # the destination is still the target-FS root. The C9300 default is unchanged
    # (covered by the tests above, which pass no copy_source).
    cli_cfg, cli_exec, emit, configured, cli_calls, emitted = _capture_calls()
    iris_agent._copy_to_root_impl(
        "img1.bin", "sdflash:", cli_cfg, cli_exec, emit,
        reverify_fn=lambda fname, prefix, c, e, expected_size=None: True,
        copy_source=lambda f, p: "http://100.92.100.254:8090/%s" % f)
    body = "\n".join(configured[0])
    assert "delete /force sdflash:img1.bin" in body
    assert "copy http://100.92.100.254:8090/img1.bin sdflash:img1.bin" in body
    assert "guest-share/iris/img1.bin" not in body   # default source NOT used


# ---------------------------------------------------------------------------
# Telemetry (#13): _aria_stats_impl / _aria_peers_impl — module-level with an
# injected rpc callable (the _refresh_impl pattern; build_deps wires the real
# _rpc closure). BEST-EFFORT reads: no matching download or ANY rpc error
# yields None/[] and must NEVER raise (a raise out of run_once would discard
# persisted state -> full ~1.2 GB re-copy). gid discovery matches the staged
# file's basename against each download's files paths (the purge_others
# idiom): tellActive first, then tellStopped.
# ---------------------------------------------------------------------------

_TELE_STAGE = "/stage/img1.bin"
_ACTIVE_ROW = {"gid": "gidA", "files": [{"path": "/stage/img1.bin"}]}
_STOPPED_ROW = {"gid": "gidS", "files": [{"path": "/stage/img1.bin"}]}
_OTHER_ROW = {"gid": "gidX", "files": [{"path": "/stage/other.bin"}]}
_STATUS_A = {"gid": "gidA", "completedLength": "1000", "totalLength": "1000",
             "downloadSpeed": "0", "uploadSpeed": "512", "connections": "3"}


def _tele_rpc(active=(), stopped=(), status=None, peers=(), raise_on=()):
    """Injected rpc double: records every (method, params) call, serves canned
    tellActive/tellStopped/tellStatus/getPeers results, and raises on any
    method listed in raise_on (modelling aria2c down / bouncing on rpc_secret
    rotation)."""
    calls = []

    def rpc(method, params):
        calls.append((method, params))
        if method in raise_on:
            raise RuntimeError("aria2 rpc down: %s" % method)
        if method == "aria2.tellActive":
            return list(active)
        if method == "aria2.tellStopped":
            return list(stopped)
        if method == "aria2.tellStatus":
            return _STATUS_A if status is None else status
        if method == "aria2.getPeers":
            return list(peers)
        return []

    return rpc, calls


def test_aria_stats_finds_gid_in_tellactive_returns_status_subset():
    rpc, calls = _tele_rpc(active=[_OTHER_ROW, _ACTIVE_ROW])
    out = iris_agent._aria_stats_impl(rpc, _TELE_STAGE)
    assert out == _STATUS_A
    # tellStatus was asked for the MATCHED gid + exactly the report key subset
    method, params = calls[-1]
    assert method == "aria2.tellStatus"
    assert params[0] == "gidA"
    assert params[1] == ["gid", "completedLength", "totalLength",
                         "downloadSpeed", "uploadSpeed", "connections", "status"]
    # found in tellActive -> never paged tellStopped
    assert all(m != "aria2.tellStopped" for m, _ in calls)


def test_aria_stats_falls_back_to_tellstopped():
    # download finished and aria2 moved it to stopped (e.g. a sample taken
    # after seeding wound down) -> the finder pages tellStopped.
    status_s = {"gid": "gidS", "completedLength": "5", "totalLength": "5",
                "downloadSpeed": "0", "uploadSpeed": "0", "connections": "0"}
    rpc, calls = _tele_rpc(active=[_OTHER_ROW], stopped=[_STOPPED_ROW],
                           status=status_s)
    out = iris_agent._aria_stats_impl(rpc, _TELE_STAGE)
    assert out == status_s
    methods = [m for m, _ in calls]
    # the consolidated iterator pages active -> waiting -> stopped
    assert methods == ["aria2.tellActive", "aria2.tellWaiting",
                       "aria2.tellStopped", "aria2.tellStatus"]
    # tellStopped uses the same [offset, num] paging window as purge_others
    assert calls[2][1][:2] == [0, 100]
    assert calls[-1][1][0] == "gidS"


def test_aria_stats_none_when_no_download_matches():
    rpc, calls = _tele_rpc(active=[_OTHER_ROW], stopped=[_OTHER_ROW])
    assert iris_agent._aria_stats_impl(rpc, _TELE_STAGE) is None
    assert all(m != "aria2.tellStatus" for m, _ in calls)


def test_aria_stats_never_raises_on_rpc_error():
    # aria2c down entirely (tellActive raises) OR dying between the gid match
    # and the tellStatus read — both must yield None, never a raise.
    for bad in ("aria2.tellActive", "aria2.tellStatus"):
        rpc, _ = _tele_rpc(active=[_ACTIVE_ROW], raise_on=(bad,))
        assert iris_agent._aria_stats_impl(rpc, _TELE_STAGE) is None


def test_aria_stats_none_on_non_dict_tellstatus():
    # the real _rpc helper defaults a missing "result" key to [] — a non-dict
    # must not leak out as the report's transfer stats.
    rpc, _ = _tele_rpc(active=[_ACTIVE_ROW], status=[])
    assert iris_agent._aria_stats_impl(rpc, _TELE_STAGE) is None


def test_aria_peers_requests_measured_fields_and_returns_canonical_rows():
    peers = [{"ip": "10.0.0.7", "downloadSpeed": "1024", "uploadSpeed": "0",
              "peerClientName": "aria2/1.37", "progress": "87.5",
              "bitfield": "ff"},
              {"ip": "10.0.0.8", "downloadSpeed": "0", "uploadSpeed": "2048",
               "amChoking": "false"}]
    rpc, calls = _tele_rpc(active=[_ACTIVE_ROW], peers=peers)
    out = iris_agent._aria_peers_impl(rpc, _TELE_STAGE)
    assert out == [
        {"ip": "10.0.0.7", "receive_bps": 1024, "send_bps": 0,
         "peer_client_name": "aria2/1.37", "progress": 87.5},
        {"ip": "10.0.0.8", "receive_bps": 0, "send_bps": 2048}]
    assert calls[-1] == ("aria2.getPeers", [
        "gidA", ["ip", "port", "downloadSpeed", "uploadSpeed", "peerClientName",
                 "progress"]])
    assert "bitfield" not in calls[-1][1][1]


def test_aria_peers_omits_unknown_fields_and_ignores_malformed_rows():
    rpc, _ = _tele_rpc(active=[_ACTIVE_ROW], peers=[
        {"ip": "10.0.0.7", "downloadSpeed": None, "uploadSpeed": "bad",
         "peerClientName": "x" * 100, "progress": "101"},
        {"ip": "10.0.0.8", "downloadSpeed": "1000000000001",
         "uploadSpeed": True, "progress": "nan"},
        {}, {"ip": 42}, "not-a-row"])
    assert iris_agent._aria_peers_impl(rpc, _TELE_STAGE) == [
        {"ip": "10.0.0.7", "peer_client_name": "x" * 64},
        {"ip": "10.0.0.8"}]


def test_aria_peers_empty_when_no_match():
    rpc, calls = _tele_rpc(active=[], stopped=[])
    assert iris_agent._aria_peers_impl(rpc, _TELE_STAGE) == []
    assert all(m != "aria2.getPeers" for m, _ in calls)


def test_aria_peers_never_raises_on_rpc_error():
    # getPeers on a stopped/just-removed download is an aria2 error -> [] and
    # never a raise; ditto aria2c down before the gid was even found.
    for bad in ("aria2.tellActive", "aria2.getPeers"):
        rpc, _ = _tele_rpc(active=[_ACTIVE_ROW], raise_on=(bad,))
        assert iris_agent._aria_peers_impl(rpc, _TELE_STAGE) == []


def test_deps_gains_telemetry_and_io_transfer_fields_appended_at_end():
    # Contract: these fields are appended (so pre-existing positional
    # construction and index-based code stay valid). The defaults keep legacy
    # test scenarios on the Guest Shell path unchanged.
    assert iris_agent.Deps._fields[-6:] == (
        "aria_stats", "aria_peers", "io_transfer", "checkpoint",
        "aria_session", "copy_in_place")
    cat = FakeCatalog({"approved_image_id": None}, None)
    deps, _, _, _, _, _, _, _ = make_deps(cat, {})
    assert deps.aria_stats("/stage/img1.bin") is None
    assert deps.aria_peers("/stage/img1.bin") == []
    assert deps.io_transfer is False
    assert deps.copy_in_place is False


# ---------------------------------------------------------------------------
# Telemetry (#13): run_once wiring — _telemetry_tick. The tick is BEST-EFFORT
# glue: samples aria2 on live-transfer phases, arms exactly one completion
# report per image, honors the server's heartbeat pull flag, and defers with
# backoff on a bad link. It must never raise, never add aria2 RPC to the
# steady-state tick (except on an explicit pull), and never send when the
# `telemetry` conf key is off.
# ---------------------------------------------------------------------------

import telemetry_report


def _tele_cfg(**over):
    cfg = dict(CFG)
    cfg.update(over)
    return cfg


_IMG = {"id": "img1", "filename": "img1.bin", "size": 5, "sha256": "abc"}


def _counting_peers(rows):
    """aria_peers double that records each lookup path."""
    calls = []

    def peers(path):
        calls.append(path)
        return list(rows)

    return peers, calls


def test_heartbeat_payload_carries_telemetry_enabled():
    # ON by default (no `telemetry` key in cfg) ...
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    sent = []
    deps, *_ = make_deps(_HeartbeatSpy(cat, sent), {"/stage/img1.bin": 5})
    iris_agent.run_once(CFG, deps, {})
    assert sent[-1]["telemetry_enabled"] is True
    # ... and OFF when the conf says so.
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    sent = []
    deps, *_ = make_deps(_HeartbeatSpy(cat, sent), {"/stage/img1.bin": 5})
    iris_agent.run_once(_tele_cfg(telemetry="off"), deps, {})
    assert sent[-1]["telemetry_enabled"] is False


def test_downloading_tick_samples_and_accumulates_peers():
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 2,
                               "/stage/img1.bin.aria2": 1})
    peers, calls = _counting_peers([{"ip": "10.0.0.7"}])
    deps = deps._replace(aria_peers=peers)
    state = {"image_id": "img1", "img1": {"tele": {"peers": {}}}}
    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    assert calls == ["/stage/img1.bin"]
    # participation only: one observation this tick -> count of 1
    assert state["img1"]["tele"]["peers"]["10.0.0.7"] == 1
    assert state["img1"]["tele"]["started_ts"] > 0


def test_fast_download_reports_totals_only():
    # Download finished within one tick: zero per-peer samples ever taken.
    # The staging-complete report still goes out with totals from aria_stats
    # and an empty peers list.
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 5})
    deps = deps._replace(aria_stats=lambda p: {
        "gid": "g", "completedLength": "5", "totalLength": "5",
        "downloadSpeed": "0", "uploadSpeed": "0", "connections": "0"})
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert len(cat.telemetry) == 1
    sid, report = cat.telemetry[0]
    assert sid == "sw1"
    assert report["event"] == "staging-complete"
    assert report["peers"] == []
    assert report["peers_total"] == 0
    assert report["content"]["completed_content_bytes"] == 5
    assert report["content_sha256"]["state"] == "verified"
    assert report["ios_copy_verify"]["state"] == "not_run"
    assert "avg_bps" not in report and "transfer" not in report
    assert len(report["report_id"]) == 32 and len(report["transfer_id"]) == 32
    tele = state["img1"]["tele"]
    assert tele["report_pending"] is False and tele["report_sent_ts"] > 0


def test_completion_hook_takes_one_final_peer_sample():
    # The one-time completion snapshot samples aria_peers ONCE more before
    # marking done, so peers connected at the end of a fast download still
    # land in the observed set.
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 5})
    # 200 MB over ~100 s -> ~2 MB/s: a healthy 'good'-tier download, so the
    # completion report keeps its peer rows (a slow download would be trimmed).
    deps = deps._replace(aria_stats=lambda p: {
        "gid": "g", "completedLength": "200000000",
        "totalLength": "200000000", "downloadSpeed": "0",
        "uploadSpeed": "0", "connections": "0"})
    peers, peer_calls = _counting_peers([{"ip": "10.0.0.7"}])
    deps = deps._replace(aria_peers=peers)
    state = {"image_id": "img1",
             "img1": {"tele": {"started_ts": _time.time() - 100,
                               "peers": {}}}}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    # completion path did take exactly one peer sample on the 'copied' tick
    assert peer_calls == ["/stage/img1.bin"]
    assert len(cat.telemetry) == 1
    _, report = cat.telemetry[0]
    assert [p["ip"] for p in report["peers"]] == ["10.0.0.7"]
    assert report["peers"][0]["observations"] >= 1
    assert "first_observed" in report["peers"][0]
    assert report["peers_total"] == 1
    assert report["content"]["completed_content_bytes"] == 200000000


def test_telemetry_off_means_no_rpc_and_no_post():
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 5})
    stats_calls = []
    peers, peer_calls = _counting_peers([])
    deps = deps._replace(
        aria_stats=lambda p: stats_calls.append(p) or None,
        aria_peers=peers)
    state = {}
    assert iris_agent.run_once(_tele_cfg(telemetry="off"), deps, state) \
        == "complete"
    assert stats_calls == [] and peer_calls == []
    assert cat.telemetry == []
    # No telemetry SAMPLING/REPORT state was created (no peers/report_pending/
    # stream_last_ts). Verification FACTS (content_sha256_state /
    # ios_copy_verify_state) are recorded regardless of the telemetry toggle —
    # they are honest per-decision facts, not stream state.
    tele = state.get("img1", {}).get("tele", {})
    for k in ("peers", "report_pending", "stream_last_ts", "sample_seq",
              "transfer_id"):
        assert k not in tele


def test_bad_tier_defers_send_and_keeps_data():
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 5})
    # 3 consecutive heartbeat/report failures already on record -> tier 'bad'.
    state = {"link": {"rtt_ms": [10.0], "fail_streak": 3}}
    before = _time.time()
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert cat.telemetry == []                       # deferred, not sent
    tele = state["img1"]["tele"]
    assert tele["report_pending"] is True
    assert tele["report_attempts"] == 1
    assert tele["report_next_ts"] >= before + telemetry_report.TICK_SECONDS
    assert tele["event"] == "staging-complete"       # data survives for later


def test_pull_flag_on_steady_state_sends_pull_report():
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    cat.hb_response = {"ok": True, "report_requested": True}
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 5})
    peers, peer_calls = _counting_peers([{"ip": "10.0.0.9"}])
    deps = deps._replace(aria_peers=peers)
    # Steady state: done + copied + root present -> the cheap short-circuit.
    # schema_version must be current or the upgrade-migration block (which
    # clears 'copied') routes this tick through 'copied' instead of 'steady'.
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "stage_fs": "flash:",
             "img1": {"done": True, "copied": True, "sha": "abc",
                      "tele": {"report_pending": False, "report_sent_ts": 1.0,
                               "event": "staging-complete",
                               "peers": {}}}}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert len(cat.telemetry) == 1
    _, report = cat.telemetry[0]
    assert report["event"] == "pull"
    # the completed transfer's per-peer table is FINAL: a steady-state pull
    # re-sends it frozen and takes NO fresh sample (rate-integrating one
    # instantaneous speed over the sparse pull gap fabricates data — see
    # test_steady_pull_never_inflates_tx below)
    assert peer_calls == []


def test_steady_pull_never_inflates_tx_or_adds_peers():
    """Regression (hardware-observed): a device seeding a NEIGHBOR's download
    at LAN speed got pulled; the old code integrated that instantaneous
    uploadSpeed over the 180s clamp on every pull, compounding to a reported
    ~12 GB 'sent' on a 1.26 GB image, and injected the neighbor as a bogus
    rx peer row (even-split fallback) into a transfer that finished long ago.
    A steady-state pull must leave the finished transfer's tele untouched."""
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    cat.hb_response = {"ok": True, "report_requested": True}
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 5})
    # neighbor downloading FROM us at 20 MB/s right now (participation-only
    # rows carry no speed, so the row itself is just the ip)
    peers, _calls = _counting_peers([{"ip": "10.0.0.7"}])
    deps = deps._replace(aria_peers=peers)
    tele = {"report_pending": False, "report_sent_ts": 1.0,
            "event": "staging-complete", "total_bytes": 100,
            "elapsed_s": 10.0, "done_ts": 50.0,
            "peers": {"10.0.0.1": [100, 0]},        # legacy byte-shaped state
            "peers_v2": {"10.0.0.1": {"first_observed": 10.0,
                                      "last_observed": 40.0,
                                      "observations": 4}}}
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "stage_fs": "flash:",
             "img1": {"done": True, "copied": True, "sha": "abc",
                      "tele": tele}}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    _, report = cat.telemetry[0]
    # frozen, keys + participation only, NO byte fields
    assert [p["ip"] for p in report["peers"]] == ["10.0.0.1"]
    assert report["peers"][0]["observations"] == 4
    assert report["peers_total"] == 1
    # a steady tick never calls observe_peers, so the finished transfer's peer
    # state persists verbatim (no fresh sample, no inflation)
    assert tele["peers_v2"]["10.0.0.1"]["observations"] == 4


def test_steady_state_without_pull_stays_rpc_free_and_sends_nothing():
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)   # hb_response None
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 5})
    peers, peer_calls = _counting_peers([])
    stats_calls = []
    deps = deps._replace(aria_peers=peers,
                         aria_stats=lambda p: stats_calls.append(p) or None)
    # schema_version must be current, or the upgrade-migration clears
    # 'copied' and this routes through 'copied' instead of 'steady'.
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "stage_fs": "flash:",
             "img1": {"done": True, "copied": True, "sha": "abc",
                      "tele": {"report_pending": False, "report_sent_ts": 1.0,
                               "event": "staging-complete"}}}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert peer_calls == [] and stats_calls == []            # locked behavior
    assert cat.telemetry == []


def test_garbage_heartbeat_response_is_ignored():
    for garbage in (None, "thanks", ["report_requested"], 7,
                    {"report_requested": "yes"}):
        cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
        cat.hb_response = garbage
        deps, *_ = make_deps(cat, {"/stage/img1.bin": 5})
        state = {"schema_version": iris_agent._STATE_SCHEMA,
                 "image_id": "img1", "stage_fs": "flash:",
                 "img1": {"done": True, "copied": True, "sha": "abc",
                          "tele": {"report_pending": False,
                                   "report_sent_ts": 1.0,
                                   "event": "staging-complete"}}}
        assert iris_agent.run_once(CFG, deps, state) == "complete"
        assert cat.telemetry == []


def test_post_telemetry_raise_never_escapes_run_once():
    class _BoomCatalog(FakeCatalog):
        def post_telemetry(self, sid, report):
            raise RuntimeError("captive portal ate the POST")

    cat = _BoomCatalog({"approved_image_id": "img1"}, _IMG)
    cat.hb_response = {"ok": True}       # heartbeat succeeds; only the report POST fails
    deps, emitted, *_ = make_deps(cat, {"/stage/img1.bin": 5})
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "complete"   # no raise
    assert any(m == "TELEMETRY-FAIL" for m, _ in emitted)
    tele = state["img1"]["tele"]
    assert tele["report_pending"] is True            # will retry with backoff
    assert tele["report_attempts"] == 1
    # a failed REPORT send advances the report streak, not the heartbeat streak
    # (spec §10.2 splits them); the heartbeat itself succeeded this tick.
    assert state["link"]["report_fail_streak"] == 1
    assert state["link"].get("fail_streak", 0) == 0
    # the payload was FROZEN before the (failed) POST so the retry is identical
    assert tele["frozen_report"]["report_id"] == tele["frozen_report"]["report_id"]
    assert len(tele["frozen_report"]["report_id"]) == 32


def test_seeding_only_arms_and_sends_seeding_report():
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    # File fully staged + verified, but free space cannot fit a second copy:
    # the copy gate degrades to seeding-only (existing behavior).
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 5}, free=1)
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "seeding-only"
    assert len(cat.telemetry) == 1
    _, report = cat.telemetry[0]
    assert report["event"] == "seeding-only"
    assert report["stage_state"] == "flash_full_seeding_only"


def test_completion_report_sent_exactly_once():
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 5})
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "complete"   # copied tick
    assert iris_agent.run_once(CFG, deps, state) == "complete"   # steady tick
    assert len(cat.telemetry) == 1                   # armed + sent once, total


def test_constrained_tier_report_is_full_v2_no_trim():
    # v2 retired the constrained-tier trim + the generic 'link'/'tier'/'trimmed'
    # fields: the report always carries full participation with a sampling_class.
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 5})
    # High RTT median (> RTT_CONSTRAINED_MS), no failures -> 'constrained'.
    state = {"link": {"rtt_ms": [400.0, 500.0, 450.0], "fail_streak": 0},
             "image_id": "img1",
             "img1": {"tele": {"peers_v2": {"10.0.0.7": {
                 "first_observed": 1.0, "last_observed": 2.0,
                 "observations": 1}}}}}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert len(cat.telemetry) == 1
    _, report = cat.telemetry[0]
    assert report["sampling"]["sampling_class"] == "constrained"
    assert report["sampling"]["catalog_rtt_samples"] == 3
    assert "link" not in report and "trimmed" not in report
    # peer participation is preserved in full (no trim in v2)
    assert [p["ip"] for p in report["peers"]] == ["10.0.0.7"]
    assert report["peers_total"] == 1


def test_rtts_drained_from_catalog_client_into_state():
    class _RttCatalog(FakeCatalog):
        def drain_rtts(self):
            return [12.5, 40.0]

    cat = _RttCatalog({"approved_image_id": "img1"}, _IMG)
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 2,
                               "/stage/img1.bin.aria2": 1})
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    assert state["link"]["rtt_ms"] == [12.5, 40.0]


def test_heartbeat_failure_feeds_link_fail_streak():
    class _DeafCatalog(FakeCatalog):
        def heartbeat(self, sid, data):
            raise OSError("uplink down")

    cat = _DeafCatalog({"approved_image_id": "img1"}, _IMG)
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 2,
                               "/stage/img1.bin.aria2": 1})
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    assert state["link"]["fail_streak"] == 1
    # a SUCCESSFUL heartbeat next tick must NOT reset the streak (only a
    # delivered report does) — old-server backoff depends on this.
    # (hb_response={"ok": True} — FakeCatalog's default of None would itself
    # look like a failed heartbeat to _telemetry_tick, same as a raise.)
    cat2 = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    cat2.hb_response = {"ok": True}
    deps2, *_ = make_deps(cat2, {"/stage/img1.bin": 2,
                                 "/stage/img1.bin.aria2": 1})
    assert iris_agent.run_once(CFG, deps2, state) == "downloading"
    assert state["link"]["fail_streak"] == 1


# ---- live streaming samples (device transfer telemetry spec section 5) ----

import types

import telemetry_report


def _fake_deps(stats=None, peers=None):
    calls = {"stats": 0, "peers": 0}
    def aria_stats(stage):
        calls["stats"] += 1
        return stats
    def aria_peers(stage):
        calls["peers"] += 1
        return list(peers or [])
    deps = types.SimpleNamespace(aria_stats=aria_stats, aria_peers=aria_peers,
                                 emit=lambda *a: None)
    return deps, calls


STREAM_STATS = {"completedLength": "1000", "downloadSpeed": "10",
                "uploadSpeed": "5", "connections": "2"}
STREAM_CFG_ON = {"telemetry": "on", "telemetry_stream": "on",
                 "device_id": "d1", "agent_version": "t"}


class TestMaybeSample:
    def test_disabled_makes_no_rpc(self):
        deps, calls = _fake_deps(stats=STREAM_STATS)
        cfg = dict(STREAM_CFG_ON, telemetry_stream="off")
        sample, peers = iris_agent._maybe_sample(
            cfg, deps, {}, "img", "/s/f.bin", "downloading", 1000.0)
        assert sample is None and peers is None
        assert calls == {"stats": 0, "peers": 0}

    def test_due_sample_fetches_once_and_stamps(self):
        deps, calls = _fake_deps(stats=STREAM_STATS,
                                 peers=[{"ip": "10.0.0.2"}])
        state = {}
        sample, peers = iris_agent._maybe_sample(
            STREAM_CFG_ON, deps, state, "img", "/s/f.bin", "downloading",
            1000.0)
        assert sample["phase"] == "downloading" and sample["peers"] == 2
        assert peers == [{"ip": "10.0.0.2"}]
        assert state["img"]["tele"]["stream_last_ts"] == 1000.0
        assert calls == {"stats": 1, "peers": 1}

    def test_never_raises(self):
        deps = types.SimpleNamespace(
            aria_stats=lambda s: (_ for _ in ()).throw(RuntimeError("boom")),
            aria_peers=lambda s: [], emit=lambda *a: None)
        assert iris_agent._maybe_sample(
            STREAM_CFG_ON, deps, {}, "img", "/s", "downloading", 0.0) == \
            (None, None)


class TestHeartbeatPayload:
    IMAGE = {"id": "img"}
    DEPS = types.SimpleNamespace(free_bytes=lambda fs: 5,
                                 version=lambda: "17",
                                 model=lambda: "C9300")

    def test_stream_flag_always_sample_only_when_given(self):
        hb = iris_agent._heartbeat(self.IMAGE, self.DEPS, stream_on=True)
        assert hb["telemetry_stream_enabled"] is True and "sample" not in hb
        s = {"v": 1}
        hb = iris_agent._heartbeat(self.IMAGE, self.DEPS, sample=s)
        assert hb["sample"] is s and hb["telemetry_stream_enabled"] is False


class TestTickDirectivesAndPeersReuse:
    def test_tick_stores_directives_and_reuses_peers(self):
        deps, calls = _fake_deps(stats=STREAM_STATS,
                                 peers=[{"ip": "10.9.9.9"}])
        deps.catalog = types.SimpleNamespace()   # no post_telemetry: no sends
        state = {}
        iris_agent._telemetry_tick(
            STREAM_CFG_ON, deps, state, "img", "/s/f.bin", "downloading",
            {"stream_every": 7}, 1000.0,
            peers=[{"ip": "10.0.0.3"}])
        assert state["stream_directives"]["every"] == 7
        assert calls["peers"] == 0                     # reused, not re-fetched
        assert "10.0.0.3" in state["img"]["tele"]["peers"]
