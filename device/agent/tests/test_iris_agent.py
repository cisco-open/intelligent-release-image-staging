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

    deps = iris_agent.Deps(
        catalog=catalog,
        emit=lambda m, msg: emitted.append((m, msg)),
        ios=lambda cmd: ios_cmds.append(cmd) or "",
        aria_add=lambda t, d: aria_calls.append((t, d)),
        file_size=lambda p: sizes.get(p),
        verify=lambda p, sha: verify_ok,
        free_bytes=lambda prefix="flash:": free,
        version=lambda: "17.18.03",
        copy_to_root=lambda fname, target_prefix="flash:": copied.append(fname) or True,
        purge_others=lambda keep, kid: purged.append((keep, kid)),
        reclaim=lambda: reclaimed.append(True),
        root_present=lambda fname, prefix="flash:": root_ok,
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
    )
    return (deps, emitted, ios_cmds, aria_calls, copied, purged, reclaimed,
            bundle_reclaimed)


import time as _time
# token_expires_at far in the future so existing tests skip the refresh step
# (needs_refresh returns False). Tests that want to exercise the refresh set
# token_expires_at="0" explicitly in their own cfg.
CFG = {"device_id": "sw1", "stage_dir": "/stage",
       "token_expires_at": str(int(_time.time()) + 604_800)}


def test_no_assignment_does_nothing():
    cat = FakeCatalog({"approved_image_id": None}, None)
    deps, emitted, _, aria, _, _, _, _ = make_deps(cat, {})
    assert iris_agent.run_once(CFG, deps, {}) == "no-assignment"
    assert emitted == [] and aria == []


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


def test_replaced_image_cleanup_claim_gated_on_actual_absence():
    # AAA nodes silently no-op a raw exec `delete` (the reclaim/copyroot EEM
    # applets exist for exactly that reason) — so the CLEANUP log and the
    # root_file bookkeeping must be gated on the file actually being gone,
    # else the replaced image is stranded on flash while IRIS claims otherwise
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 7,
                       "sha256": "def"})
    deps, emitted, ios_cmds, _, _, _, _, _ = make_deps(
        cat, {"/stage/img2.bin": 7}, verify_ok=True)
    deps = deps._replace(                       # the old root REFUSES to die
        root_present=lambda fname, prefix="flash:": fname == "old.bin")
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "root_file": "old.bin"}
    iris_agent.run_once(CFG, deps, state)
    assert any("delete /force flash:old.bin" in c for c in ios_cmds)
    # queued for retry every tick — NOT silently forgotten
    assert state.get("pending_root_deletes") == ["old.bin"]
    assert any(m == "CLEANUP-PENDING" for m, _ in emitted)
    assert all(not (m == "CLEANUP" and "old.bin" in msg) for m, msg in emitted)


def test_replaced_image_cleanup_confirmed_when_gone():
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 7,
                       "sha256": "def"})
    deps, emitted, ios_cmds, _, _, _, _, _ = make_deps(
        cat, {"/stage/img2.bin": 7}, verify_ok=True)
    deps = deps._replace(                        # old root really deleted
        root_present=lambda fname, prefix="flash:": fname != "old.bin")
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "root_file": "old.bin"}
    iris_agent.run_once(CFG, deps, state)
    assert "pending_root_deletes" not in state
    assert any(m == "CLEANUP" and "old.bin" in msg for m, msg in emitted)


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


def test_reassignment_purges_old_image_everywhere():
    # device completed img1 (incl. root copy); operator reassigns img2 ->
    # the agent must purge the old torrent/files and delete the old root copy
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin",
                       "size": 1000, "sha256": "def"})
    deps, emitted, ios_cmds, _, _, purged, _, _ = make_deps(cat, {}, free=9_000_000_000)
    deps = deps._replace(   # the delete genuinely lands: old root reads absent
        root_present=lambda fname, prefix="flash:": fname != "img1.bin")
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "root_file": "img1.bin",
             "img1": {"done": True, "copied": True}}
    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    assert purged == [("img2.bin", "img2")]            # old torrent/files purged
    assert "delete /force flash:img1.bin" in ios_cmds  # old ROOT copy removed (ours)
    assert any(m == "CLEANUP" for m, _ in emitted)
    assert "img1" not in state and state["image_id"] == "img2"


def test_reassignment_purges_old_root_on_cached_stage_fs():
    # Device previously staged on sdflash: (cached). Reassigned to a new image ->
    # the old root copy must be deleted from sdflash:, not flash:.
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, ios_cmds, _, _, _, _, _ = make_deps(
        cat, {"/stage/img2.bin": 5}, mode="bundle")
    deps = deps._replace(target_fs=lambda: ("sdflash:", 9_000_000_000))
    state = {"image_id": "img1", "root_file": "img1.bin", "stage_fs": "sdflash:",
             "img1": {"done": True, "copied": True}}
    iris_agent.run_once(CFG, deps, state)
    assert "delete /force sdflash:img1.bin" in ios_cmds
    assert "delete /force flash:img1.bin" not in ios_cmds


def test_reassignment_purge_defaults_to_flash_for_legacy_state():
    # Pre-#24 state has no stage_fs; the old root copy was placed on flash:.
    cat = FakeCatalog({"approved_image_id": "img2"},
                      {"id": "img2", "filename": "img2.bin", "size": 5,
                       "sha256": "abc"})
    deps, _, ios_cmds, _, _, _, _, _ = make_deps(
        cat, {"/stage/img2.bin": 5}, mode="bundle")
    state = {"image_id": "img1", "root_file": "img1.bin",
             "img1": {"done": True, "copied": True}}
    iris_agent.run_once(CFG, deps, state)
    assert "delete /force flash:img1.bin" in ios_cmds


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
    deps, _, ios_cmds, _, _, purged, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "root_file": "img1.bin",
             "img1": {"done": True, "copied": True, "sha": "abc"}}
    iris_agent.run_once(CFG, deps, state)
    assert purged == []
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

    def failing_copy(fname, target_prefix="flash:"):
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

    def flaky_copy(fname, target_prefix="flash:"):
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


# --- Direct tests of _agent_reverify_root (the real code path).
# The IRIS-COPYROOT EEM applet deletes any stale leftover, then runs
# `copy /verify` — copy + Cisco signature in one IOS-enforced step. A failed
# signature fails the copy and deletes the dest, and the pre-copy delete scopes
# the result to THIS attempt, so file presence at flash root IS the verdict.
# The agent polls `dir flash:<fname>` (small, fast cli call) and blesses on
# presence — no syslog parsing required. ---

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
    assert ("ROOTCOPY", "cat9k.bin placed at flash root + verified") in emitted


def test_reverify_no_file_means_signature_failed_or_copy_aborted():
    # Cisco `copy /verify` deletes the destination on a failed signature, so a
    # missing file means signature failed (or the copy never ran). The agent
    # times out and emits FAIL (nothing to delete — the applet cleared any
    # stale leftover up front).
    cli, emit, _, emitted = _make_reverify_cli(dir_out=_DIR_MISSING)
    ok = _reverify(cli, emit, poll_attempts=3)
    assert ok is False
    assert any(m == "ROOTCOPY-FAIL" and "no file appeared" in msg
               for m, msg in emitted)
    assert all(m != "ROOTCOPY" for m, _ in emitted)


def test_reverify_polls_until_file_appears():
    # The applet runs ~2-4 min while the agent polls. dir reports
    # "No such file" until the copy /verify finishes — then the file is there
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
    assert any(m == "ROOTCOPY-FAIL" and "no file appeared" in msg
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


# --- Source-level guard: the templated applet inside iris_agent.py must do the
# COPY only and log a NEUTRAL breadcrumb — never claim a verified copy. Only the
# agent emits the "+ verified" log, after _agent_reverify_root sees the file.
# Refuter 3 caught that the bats test only inspects the reference .cfg, not the
# runtime-templated string. ---

def test_iris_agent_source_applet_is_neutral_no_self_verdict():
    """The templated applet must (a) delete any stale leftover before copying,
    (b) run `copy /verify` (copy + Cisco signature), and (c) log only a NEUTRAL
    ROOTCOPY-ATTEMPTED breadcrumb — never a pass/fail verdict or a "+ verified"
    claim. The agent owns the verdict via file presence. Plus a HW-driven
    regression guard: the broken $_arg1 trigger must not return. The bats only
    inspects the reference .cfg; this checks the runtime template living inside
    iris_agent.py itself."""
    src = open(iris_agent.__file__).read()
    # the authoritative success log lives in the agent's emit(), issued ONLY
    # after _agent_reverify_root passes — never inside an applet syslog action.
    assert "placed at flash root + verified" in src
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
    # the applet copies WITH /verify (copy + Cisco signature in one step) and
    # does NOT run a second standalone verify (the agent reads no syslog verdict).
    # The copy SOURCE is parameterized (default = the guest-share scratch on the
    # staging FS for the C9300; an injected http:// URL for the IE3x00 container).
    assert "copy /verify %s %s%s" in src            # parameterized src + dst
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

    def reverify(fname, prefix, cli_exec_arg, emit_arg):
        reverify_calls.append(fname)
        return True

    ok = iris_agent._copy_to_root_impl(
        "img1.bin", "flash:", cli_cfg, cli_exec, emit, reverify_fn=reverify)
    assert ok is True
    # the applet was templated: clear-leftover (delete) + copy /verify + a
    # NEUTRAL breadcrumb. No verdict capture, no second verify, no claim.
    assert len(configured) == 1
    body = "\n".join(configured[0])
    assert "delete /force flash:img1.bin" in body
    assert "copy /verify flash:/guest-share/iris/img1.bin flash:img1.bin" in body
    assert "ROOTCOPY-ATTEMPTED img1.bin" in body
    assert "placed at flash root + verified" not in body          # neutral applet
    assert "$_ok" not in body and "regexp" not in body            # no dead verdict capture
    assert "verify /sha512" not in body, \
        "applet must NOT run a second verify — copy /verify is the verification"
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
        reverify_fn=lambda fname, prefix, c, e: True)
    body = "\n".join(configured[0])
    assert "delete /force sdflash:img1.bin" in body
    assert "copy /verify sdflash:/guest-share/iris/img1.bin sdflash:img1.bin" in body


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
    Returns False + ROOTCOPY-FAIL with `applet run raised:` reason."""
    cli_cfg, _, emit, _, _, emitted = _capture_calls()

    def cli_execute_fn(cmd):
        raise RuntimeError("guestshell glitch")

    reverify_calls = []

    def reverify(*args, **kwargs):
        reverify_calls.append(args)
        return True

    ok = iris_agent._copy_to_root_impl(
        "img1.bin", "flash:", cli_cfg, cli_execute_fn, emit, reverify_fn=reverify)
    assert ok is False
    assert reverify_calls == []   # reverify never reached
    assert any(m == "ROOTCOPY-FAIL" and "applet run raised" in msg
               for m, msg in emitted)


# --- Direct-copy path (container / IE-3x00 SSH-to-self): `copy /verify` is run
# DIRECTLY in the agent's real vty, NOT via the IRIS-COPYROOT EEM applet (whose
# `cli command "copy"` action is a no-op on the IE3x00 — completes "success" in
# ~3 s, transfers nothing). delete-then-copy is issued directly; the verdict is
# still owned by reverify's dir-presence poll, identical to the applet path. ---

def test_copy_to_root_direct_runs_copy_then_reverify():
    cli_calls, emitted, reverify_calls = [], [], []

    def cli_exec(cmd):
        cli_calls.append(cmd)
        return ""

    def reverify(fname, prefix, cli_arg, emit_arg):
        reverify_calls.append(fname)
        return True

    ok = iris_agent._copy_to_root_direct_impl(
        "img1.bin", "sdflash:", cli_exec,
        lambda m, msg: emitted.append((m, msg)), reverify_fn=reverify)
    assert ok is True
    # delete-then-copy issued DIRECTLY — no applet templating, no `event manager run`
    assert cli_calls == [
        "delete /force sdflash:img1.bin",
        "copy /verify sdflash:/guest-share/iris/img1.bin sdflash:img1.bin",
    ]
    assert all("event manager" not in c for c in cli_calls)
    assert reverify_calls == ["img1.bin"]
    assert all(m != "ROOTCOPY-FAIL" for m, _ in emitted)


def test_copy_to_root_direct_uses_copy_source_override():
    cli_calls = []
    iris_agent._copy_to_root_direct_impl(
        "img1.bin", "sdflash:", lambda c: cli_calls.append(c) or "",
        lambda m, msg: None, reverify_fn=lambda *a: True,
        copy_source=lambda f, p: "http://10.0.0.1:8000/%s" % f)
    assert cli_calls[1] == \
        "copy /verify http://10.0.0.1:8000/img1.bin sdflash:img1.bin"


def test_copy_to_root_direct_copy_raises_no_reverify():
    emitted, reverify_calls = [], []

    def cli_exec(cmd):
        if cmd.startswith("copy"):
            raise RuntimeError("ssh transport failed")
        return ""

    ok = iris_agent._copy_to_root_direct_impl(
        "img1.bin", "sdflash:", cli_exec,
        lambda m, msg: emitted.append((m, msg)),
        reverify_fn=lambda *a: reverify_calls.append(1) or True)
    assert ok is False
    assert reverify_calls == []          # bailed before reverify
    assert any(m == "ROOTCOPY-FAIL" and "direct copy /verify raised" in msg
               for m, msg in emitted)


def test_copy_to_root_direct_reverify_false_returns_false():
    emitted = []
    ok = iris_agent._copy_to_root_direct_impl(
        "bad.bin", "sdflash:", lambda c: "",
        lambda m, msg: emitted.append((m, msg)), reverify_fn=lambda *a: False)
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
        lambda m, msg: None, reverify_fn=lambda *a: True,
        delete_source_on_success=True)
    assert ok is True
    assert cli_calls[-1] == "delete /force flash:/guest-share/iris/img1.bin"


def test_copy_to_root_direct_keeps_scratch_on_failure():
    # a failed placement must keep the pushed scratch: the next tick's retry
    # would otherwise re-push the whole image over the slow scp path
    cli_calls = []
    ok = iris_agent._copy_to_root_direct_impl(
        "img1.bin", "flash:", lambda c: cli_calls.append(c) or "",
        lambda m, msg: None, reverify_fn=lambda *a: False,
        delete_source_on_success=True)
    assert ok is False
    assert all(not c.startswith("delete /force flash:/guest-share")
               for c in cli_calls)


# --- Share-mount staging (C9k IOx): the app-hosting SSD share
# (usbflash1:iox_host_data_share) is bind-mounted into the container, so the
# agent lands its scratch there at DISK speed and the final placement is an
# IOS-internal `copy /verify` from the SSD to the target FS — no scp, no
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
        # the share copy must be fully in place when copy /verify fires
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
    # under its own iris- prefixed fixed name. copy /verify reads that source
    # and writes the REAL image name to flash:, verifying the signature from
    # the bytes, so the staged name is cosmetic.
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
    assert calls == []             # copy /verify never attempted
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
    # IOS-side copy /verify genuinely failed AFTER a successful probe (e.g.
    # signature rejection): scp would push the SAME bytes, so there is no
    # fallback — the verdict is False and the share copy is still removed.
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
    """run_once must pass the catalog filename into copy_to_root. Nothing else
    is needed — `copy /verify` is the verification (the signature covers the
    content), so no size or per-image sha needs to thread through."""
    cat = FakeCatalog({"approved_image_id": "img1"},
                      {"id": "img1", "filename": "img1.bin", "size": 5,
                       "sha256": "abc"})
    captured = []
    deps, _, _, _, _, _, _, _ = make_deps(cat, {"/stage/img1.bin": 5})
    deps = deps._replace(
        copy_to_root=lambda fname, target_prefix="flash:": captured.append(fname) or True)
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
        copy_to_root=lambda fname, target_prefix="flash:": False)  # copy fails
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
        copy_to_root=lambda fname, target_prefix="flash:":
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
        root_present=lambda fname, prefix="flash:":
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
        copy_to_root=lambda fname, target_prefix="flash:":
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
# POST -> atomic conf rewrite -> reload flow is unit-testable). Returns the
# reloaded cfg on success, None on any failure (best-effort). ---

def test_refresh_impl_writes_new_secrets_and_returns_reloaded_cfg(tmp_path):
    conf = tmp_path / "iris-agent.conf"
    conf.write_text(
        "catalog_url = https://x\n"
        "catalog_token = OLD\n"
        "device_id = sw1\n"
        "token_expires_at = 0\n"
        "rpc_secret = \n")
    cfg = {"catalog_url": "https://x", "catalog_token": "OLD",
           "device_id": "sw1", "token_expires_at": "0", "rpc_secret": ""}
    bag = {"catalog_token": "NEW", "expires_at": 1750000000,
           "announce_token": "anntok", "rpc_secret": "rpcsecret"}
    written = []

    def refresh_token_fn(device_id):
        written.append(device_id)
        return bag

    out = iris_agent._refresh_impl(
        cfg, str(conf), refresh_token_fn, lambda m, msg: None)
    assert written == ["sw1"]
    # returned cfg reflects the new secrets...
    assert out["catalog_token"] == "NEW"
    assert out["token_expires_at"] == "1750000000"
    assert out["rpc_secret"] == "rpcsecret"
    assert out["announce_token"] == "anntok"
    # ...and they were persisted to disk (next process reads them)
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

    def boom(device_id):
        raise catalog_client.CatalogError("unreachable")

    emitted = []
    out = iris_agent._refresh_impl(cfg, str(conf), boom,
                                   lambda m, msg: emitted.append((m, msg)))
    assert out is None
    # the conf on disk is UNCHANGED (still OLD) — no partial write
    import agent_config
    assert agent_config.load(str(conf))["catalog_token"] == "OLD"
    assert any(m == "TOKEN-REFRESH-FAIL" for m, _ in emitted)


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
        reverify_fn=lambda fname, prefix, c, e: True,
        copy_source=lambda f, p: "http://100.92.100.254:8090/%s" % f)
    body = "\n".join(configured[0])
    assert "delete /force sdflash:img1.bin" in body
    assert "copy /verify http://100.92.100.254:8090/img1.bin sdflash:img1.bin" in body
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
                         "downloadSpeed", "uploadSpeed", "connections"]
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


def test_aria_peers_returns_simplified_rows():
    peers = [{"ip": "10.0.0.7", "downloadSpeed": "1024", "uploadSpeed": "0",
              "peerId": "aria2%2F1.37", "seeder": "true", "bitfield": "ff"},
             {"ip": "10.0.0.8", "downloadSpeed": "0", "uploadSpeed": "2048",
              "amChoking": "false"}]
    rpc, calls = _tele_rpc(active=[_ACTIVE_ROW], peers=peers)
    out = iris_agent._aria_peers_impl(rpc, _TELE_STAGE)
    # exactly the three keys the report integrator consumes; extras dropped
    assert out == [
        {"ip": "10.0.0.7", "downloadSpeed": "1024", "uploadSpeed": "0"},
        {"ip": "10.0.0.8", "downloadSpeed": "0", "uploadSpeed": "2048"}]
    assert calls[-1] == ("aria2.getPeers", ["gidA"])


def test_aria_peers_tolerates_missing_row_keys():
    rpc, _ = _tele_rpc(active=[_ACTIVE_ROW], peers=[{}])
    assert iris_agent._aria_peers_impl(rpc, _TELE_STAGE) == \
        [{"ip": "", "downloadSpeed": "0", "uploadSpeed": "0"}]


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
    assert iris_agent.Deps._fields[-3:] == ("aria_stats", "aria_peers", "io_transfer")
    cat = FakeCatalog({"approved_image_id": None}, None)
    deps, _, _, _, _, _, _, _ = make_deps(cat, {})
    assert deps.aria_stats("/stage/img1.bin") is None
    assert deps.aria_peers("/stage/img1.bin") == []
    assert deps.io_transfer is False


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
    peers, calls = _counting_peers(
        [{"ip": "10.0.0.7", "downloadSpeed": "1024", "uploadSpeed": "0"}])
    deps = deps._replace(aria_peers=peers)
    # Pre-seed a sample 100 s ago so this tick's integration window is real
    # (first-ever sample integrates over elapsed=0 by design).
    state = {"image_id": "img1",
             "img1": {"tele": {"last_sample_ts": _time.time() - 100,
                               "peers": {}}}}
    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    assert calls == ["/stage/img1.bin"]
    rx, tx = state["img1"]["tele"]["peers"]["10.0.0.7"]
    # ~1024 B/s over ~100 s; generous bounds absorb wall-clock jitter.
    assert 90_000 < rx < 190_000 and tx == 0
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
    assert report["transfer"]["total_bytes"] == 5
    assert report["transfer"]["sha_ok"] is True
    tele = state["img1"]["tele"]
    assert tele["report_pending"] is False and tele["report_sent_ts"] > 0


def test_completion_hook_takes_one_final_peer_sample():
    # The one-time completion snapshot samples aria_peers ONCE more before
    # marking done, so at least one real-elapsed per-peer sample lands (share
    # accuracy). With a prior sample already on record, that final window makes
    # the peer visible and it is attributed the accurate total.
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 5})
    # 200 MB over ~100 s -> ~2 MB/s: a healthy 'good'-tier download, so the
    # completion report keeps its peer rows (a slow download would be trimmed).
    deps = deps._replace(aria_stats=lambda p: {
        "gid": "g", "completedLength": "200000000",
        "totalLength": "200000000", "downloadSpeed": "0",
        "uploadSpeed": "0", "connections": "0"})
    peers, peer_calls = _counting_peers(
        [{"ip": "10.0.0.7", "downloadSpeed": "2000000", "uploadSpeed": "0"}])
    deps = deps._replace(aria_peers=peers)
    # A prior sample 100 s ago -> the completion sample integrates a real
    # window (not elapsed 0), so 10.0.0.7 accrues non-zero rx weight.
    state = {"image_id": "img1",
             "img1": {"tele": {"last_sample_ts": _time.time() - 100,
                               "started_ts": _time.time() - 100,
                               "peers": {}}}}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    # completion path did take exactly one peer sample on the 'copied' tick
    assert peer_calls == ["/stage/img1.bin"]
    assert len(cat.telemetry) == 1
    _, report = cat.telemetry[0]
    # the lone peer is attributed the whole accurate total, with avg_bps
    assert report["peers"] == [{"ip": "10.0.0.7", "rx_bytes": 200000000,
                                "tx_bytes": 0,
                                "avg_bps": report["peers"][0]["avg_bps"]}]
    assert report["peers"][0]["avg_bps"] > 0
    assert report["transfer"]["total_bytes"] == 200000000


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
    assert "tele" not in state.get("img1", {})


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
    peers, peer_calls = _counting_peers(
        [{"ip": "10.0.0.9", "downloadSpeed": "0", "uploadSpeed": "2048"}])
    deps = deps._replace(aria_peers=peers)
    # Steady state: done + copied + root present -> the cheap short-circuit.
    # schema_version must be current or the upgrade-migration block (which
    # clears 'copied') routes this tick through 'copied' instead of 'steady'.
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "stage_fs": "flash:",
             "img1": {"done": True, "copied": True, "sha": "abc",
                      "tele": {"report_pending": False, "report_sent_ts": 1.0,
                               "event": "staging-complete",
                               "last_sample_ts": _time.time() - 30,
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
    # neighbor downloading FROM us at 20 MB/s right now
    peers, _calls = _counting_peers(
        [{"ip": "10.0.0.7", "downloadSpeed": "0", "uploadSpeed": "20971520"}])
    deps = deps._replace(aria_peers=peers)
    tele = {"report_pending": False, "report_sent_ts": 1.0,
            "event": "staging-complete", "total_bytes": 100,
            "elapsed_s": 10.0, "done_ts": 50.0,
            "last_sample_ts": _time.time() - 420,   # last sample: minutes ago
            "peers": {"10.0.0.1": [100, 0]}}        # the real transfer table
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img1", "stage_fs": "flash:",
             "img1": {"done": True, "copied": True, "sha": "abc",
                      "tele": tele}}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    _, report = cat.telemetry[0]
    rows = {p["ip"]: p for p in report["peers"]}
    assert "10.0.0.7" not in rows          # neighbor never enters the table
    assert rows["10.0.0.1"]["tx_bytes"] == 0
    assert rows["10.0.0.1"]["rx_bytes"] == 100   # frozen, not redistributed
    assert tele["peers"] == {"10.0.0.1": [100, 0]}  # state untouched


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
    assert state["link"]["fail_streak"] == 1


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
    assert report["transfer"]["stage_state"] == "flash_full_seeding_only"


def test_completion_report_sent_exactly_once():
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 5})
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "complete"   # copied tick
    assert iris_agent.run_once(CFG, deps, state) == "complete"   # steady tick
    assert len(cat.telemetry) == 1                   # armed + sent once, total


def test_constrained_tier_sends_trimmed_report():
    cat = FakeCatalog({"approved_image_id": "img1"}, _IMG)
    deps, *_ = make_deps(cat, {"/stage/img1.bin": 5})
    # High RTT median (> RTT_CONSTRAINED_MS), no failures -> 'constrained'.
    state = {"link": {"rtt_ms": [400.0, 500.0, 450.0], "fail_streak": 0},
             "image_id": "img1",
             "img1": {"tele": {"peers": {"10.0.0.7": [999, 0]},
                               "last_sample_ts": 1.0}}}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert len(cat.telemetry) == 1
    _, report = cat.telemetry[0]
    assert report["peers"] == []                     # rows dropped
    assert report["link"]["trimmed"] is True
    # the accumulated rows are NOT lost — still in state for a later pull
    assert state["img1"]["tele"]["peers"]["10.0.0.7"] == [999, 0]


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
