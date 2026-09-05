# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The agent stages the WHOLE assigned image set (ordered, max 10), not just
one image.

Fakes are built locally rather than imported from test_iris_agent.py — the
convention in this suite is that each module owns its own Deps builder — but
they mirror that module's shapes so a behaviour proved here means the same
thing there.

The one-image compat contract (a single-image set behaves EXACTLY as the
pre-multi-image agent did) is proved in depth by test_iris_agent.py's 300-odd
single-image cases; test_single_image_set_behaves_exactly_as_before below is
the sanity marker for the fields this feature touches."""

import time as _time
from pathlib import Path

import pytest

import iris_agent

# completion-jitter sleep is a module seam; never sleep in unit tests.
iris_agent._SLEEP = lambda s: None

CFG = {"device_id": "sw1", "stage_dir": "/stage",
       # far-future expiry so needs_refresh() skips the token refresh step
       "token_expires_at": str(int(_time.time()) + 604_800)}


def _img(iid, size=5, sha=None):
    return {"id": iid, "filename": iid + ".bin", "size": size,
            "sha256": sha or (iid + "-sha")}


class MultiCatalog:
    """Catalog serving an ORDERED image set — the policy shape the server
    grew in Task 2 (`approved_image_ids`, with `approved_image_id` kept as the
    first-or-None back-compat mirror)."""

    def __init__(self, images, ids=None):
        self.images = {i["id"]: i for i in images}
        self.ids = list(self.images) if ids is None else list(ids)
        self.heartbeats = []
        self.downloaded = []
        self.hb_response = None
        # ids whose lookup RAISES this tick (a 5xx/timeout), as opposed to
        # answering None (the image is genuinely gone from the catalog).
        self.raises = set()
        # ids whose TORRENT the catalog refuses this tick (404 missing file,
        # 503 deployment gate closed, 500 no announce credential).
        self.torrent_raises = set()

    def get_policy(self, sid):
        return {"approved_image_id": self.ids[0] if self.ids else None,
                "approved_image_ids": list(self.ids)}

    def get_image(self, image_id):
        if image_id in self.raises:
            raise RuntimeError("catalog unreachable for %s" % image_id)
        return self.images.get(image_id)

    def download_torrent(self, image_id, dest):
        if image_id in self.torrent_raises:
            raise OSError("torrent %s -> HTTP 503" % image_id)
        self.downloaded.append((image_id, dest))

    def heartbeat(self, sid, data):
        self.heartbeats.append(data)
        return self.hb_response


def make_deps(catalog, sizes, free=9_000_000_000, root_ok=True,
              verify_ok=True, mode="bundle", reclaimables=()):
    """Fake Deps + a `rec` dict of everything the agent did to the device."""
    rec = {"emitted": [], "boot": {"image": "running.bin"}, "aria_added": [],
           "aria_removed": [],
           "copied": [], "purged": [], "reclaimed": [], "bundle_reclaimed": [],
           "removed": [], "verified": []}

    def _remove_stage(path):
        rec["removed"].append(path)
        sizes.pop(path, None)             # reflect the delete in future file_size()

    def _verify(path, sha):
        rec["verified"].append(path)
        return verify_ok

    def _copy_to_root(fname, target_prefix="flash:", expected_size=None):
        rec["copied"].append(fname)
        return True

    deps = iris_agent.Deps(
        catalog=catalog,
        emit=lambda m, msg: rec["emitted"].append((m, msg)),
        boot_image=lambda: rec["boot"]["image"],
        aria_add=lambda t, d: rec["aria_added"].append((t, d)),
        file_size=lambda p: sizes.get(p),
        verify=_verify,
        free_bytes=lambda prefix="flash:": free,
        version=lambda: "17.18.03",
        copy_to_root=_copy_to_root,
        purge_others=lambda keep, kid: rec["purged"].append((keep, kid)),
        reclaim=lambda: rec["reclaimed"].append(True),
        root_present=lambda fname, prefix="flash:", expected_size=None: root_ok,
        remove_stage=_remove_stage,
        aria_remove=lambda fname: rec["aria_removed"].append(fname),
        detect_mode=lambda: mode,
        target_fs=lambda: ("flash:", free),
        running_image=lambda: "running.bin",
        reclaimable=lambda prefix, protect: list(reclaimables),
        reclaim_bundle=lambda prefix, names: rec["bundle_reclaimed"].append(
            (prefix, list(names))),
        model=lambda: "C9300-TEST",
        refresh=lambda: None,
        aria_stats=lambda stage_path: None,
        aria_peers=lambda stage_path: [],
        io_transfer=False,
        checkpoint=lambda state: None,
        aria_session=lambda: None,
        copy_in_place=False,
    )
    return deps, rec


def _emits(rec, mnemonic):
    return [msg for m, msg in rec["emitted"] if m == mnemonic]


def test_two_images_both_stage_and_heartbeat_lists_them():
    # Two images assigned; drive ticks until both are staged. aria2c runs both
    # torrents in one session, so the agent's job is to ask for both, verify
    # both, and place both — in the order the server assigned them.
    cat = MultiCatalog([_img("img-a", size=5), _img("img-b", size=7)],
                       ids=["img-a", "img-b"])
    sizes = {}
    deps, rec = make_deps(cat, sizes)
    state = {}

    assert iris_agent.run_once(CFG, deps, state) == "multi:downloading,downloading"
    assert rec["aria_added"] == [("/stage/img-a.torrent", "/stage"),
                                 ("/stage/img-b.torrent", "/stage")]
    assert cat.downloaded == [("img-a", "/stage/img-a.torrent"),
                              ("img-b", "/stage/img-b.torrent")]
    assert len(cat.heartbeats) == 1                # ONE heartbeat per tick

    # aria2c finishes both transfers
    sizes["/stage/img-a.bin"] = 5
    sizes["/stage/img-b.bin"] = 7

    assert iris_agent.run_once(CFG, deps, state) == "multi:complete,complete"
    assert rec["verified"] == ["/stage/img-a.bin", "/stage/img-b.bin"]
    assert rec["copied"] == ["img-a.bin", "img-b.bin"]     # placed IN ORDER
    assert [m for m, _ in rec["emitted"]].count("DONE") == 2

    assert len(cat.heartbeats) == 2
    hb = cat.heartbeats[-1]
    assert hb["staged_image_ids"] == ["img-a", "img-b"]
    assert hb["current_image_id"] == "img-a"      # compat: the FIRST checked
    assert hb["stage_state"] == "ready"           # every image staged
    # per-image state, per-image root copy
    assert state["img-a"]["root_file"] == "img-a.bin"
    assert state["img-b"]["root_file"] == "img-b.bin"


def test_single_image_set_behaves_exactly_as_before():
    # A one-image set must be byte-identical to the pre-multi-image agent:
    # same return string, same single heartbeat with the same keys (no
    # staged_image_ids — the server falls back to current_image_id/stage_state
    # for one-image agents and rollouts), same top-level state bookkeeping.
    cat = MultiCatalog([_img("img1")], ids=["img1"])
    deps, rec = make_deps(cat, {"/stage/img1.bin": 5})
    state = {}

    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert rec["copied"] == ["img1.bin"]
    assert len(cat.heartbeats) == 1
    hb = cat.heartbeats[0]
    assert set(hb) == {"current_image_id", "free_flash_bytes", "version",
                       "model", "stage_state", "stage_error", "target_fs",
                       "telemetry_enabled", "telemetry_stream_enabled",
                       "telemetry_observation"}
    assert hb["current_image_id"] == "img1"
    assert hb["stage_state"] == "ready"
    # top-level bookkeeping the old agent wrote, still written
    assert state["image_id"] == "img1"
    assert state["root_file"] == "img1.bin"
    assert state["img1"]["root_file"] == "img1.bin"


def test_unchecked_image_is_parked_not_deleted():
    # An image dropped from the set is PARKED: its torrent is stopped and its
    # stage copy deleted, but the root copy it already placed STAYS (re-adding
    # the image later must not mean re-copying 1.2 GB).
    cat = MultiCatalog([_img("img-a"), _img("img-b")], ids=["img-a"])
    deps, rec = make_deps(cat, {"/stage/img-a.bin": 5})
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "complete"

    cat.ids = ["img-b"]                            # img-a dropped from the set
    rec["bundle_reclaimed"].clear()
    iris_agent.run_once(CFG, deps, state)

    assert "img-a.bin" in rec["aria_removed"]      # torrent stopped
    assert "/stage/img-a.bin" in rec["removed"]    # stage copy deleted
    assert state["img-a"]["parked"] is True        # remembered, not forgotten
    # the root copy is KEPT: nothing queued for deletion, nothing deleted
    assert "pending_root_deletes" not in state
    assert all("img-a.bin" not in names
               for _fs, names in rec["bundle_reclaimed"])
    assert any("img-a" in msg for msg in _emits(rec, "PARKED"))


@pytest.mark.parametrize("image_ids", [["img-a"], ["img-a", "img-b"]])
@pytest.mark.parametrize("platform,io_transfer,copy_in_place,target_fs,origin", [
    ("", False, False, "flash:", "downloaded"),
    ("", False, False, "bootflash:", "downloaded"),
    ("iox", True, False, "sdflash:", "downloaded"),
    ("xr-appmgr", False, True, "harddisk:", "downloaded"),
    ("xr-appmgr", False, True, "harddisk:", "adopted"),
    ("xr-appmgr", False, True, "harddisk:", None),
])
def test_clearing_all_assignments_parks_the_last_images(
        tmp_path, image_ids, platform, io_transfer, copy_in_place, target_fs, origin):
    """The final unchecked image has the same ownership rules as any other.

    XR runs the actual sidecar sweep too: an empty keep set must still leave
    operator-adopted and provenance-unknown root images intact.
    """
    cat = MultiCatalog([_img(iid) for iid in image_ids])
    deps, rec = make_deps(cat, {})
    cfg = dict(CFG, stage_dir=str(tmp_path), target_fs=target_fs,
               device_platform=platform, announce_token="test-announce")
    state = {"schema_version": iris_agent._STATE_SCHEMA, "stage_fs": target_fs}
    for iid in image_ids:
        (tmp_path / (iid + ".bin")).write_bytes(b"image")
        state[iid] = {"done": True, "copied": True, "root_file": iid + ".bin"}
        if origin is not None:
            state[iid]["origin"] = origin

    def remove_stage(path):
        rec["removed"].append(path)
        Path(path).unlink(missing_ok=True)

    def purge(keep, ids):
        rec["purged"].append((keep, ids))
        if copy_in_place:
            import xr_deps
            xr_deps.purge_others(str(tmp_path), keep, ids)

    deps = deps._replace(
        file_size=lambda path: Path(path).stat().st_size if Path(path).exists() else None,
        remove_stage=remove_stage, purge_others=purge,
        io_transfer=io_transfer, copy_in_place=copy_in_place)
    iris_agent.run_once(cfg, deps, state)
    assert cat.heartbeats[-1]["stage_state"] == "ready"
    cat.ids = []
    rec["aria_removed"].clear()
    # An unrelated operator file and an IRIS sidecar verify the XR sweep's
    # empty-set behavior independently of the state-owned park delete.
    (tmp_path / "operator.iso").write_bytes(b"operator")
    (tmp_path / "old.torrent").write_bytes(b"sidecar")
    assert iris_agent.run_once(cfg, deps, state) == "no-assignment"
    assert rec["aria_removed"] == [iid + ".bin" for iid in image_ids]
    assert rec["purged"][-1] == ([], [])
    for iid in image_ids:
        assert state[iid]["parked"] is True
        assert state[iid]["root_file"] == iid + ".bin"
        assert (tmp_path / (iid + ".bin")).exists() is (
            copy_in_place and origin != "downloaded")
    assert (tmp_path / "operator.iso").read_bytes() == b"operator"
    if copy_in_place:
        assert not (tmp_path / "old.torrent").exists()
    assert rec["bundle_reclaimed"] == []
    assert "pending_root_deletes" not in state
    assert cat.heartbeats[-1]["stage_state"] == "unassigned"
    assert cat.heartbeats[-1]["current_image_id"] is None
    assert cat.heartbeats[-1]["telemetry_observation"]["obs_state"] == "not_active"


@pytest.mark.parametrize("platform,io_transfer,copy_in_place", [
    ("", False, False), ("router", False, False),
    ("iox", True, False), ("xr-appmgr", False, True),
])
def test_clearing_last_assignment_stops_an_incomplete_download(
        platform, io_transfer, copy_in_place):
    cat = MultiCatalog([_img("img-a")], ids=[])
    sizes = {"/stage/img-a.bin": 3}
    deps, rec = make_deps(cat, sizes)
    deps = deps._replace(io_transfer=io_transfer, copy_in_place=copy_in_place)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "img-a": {"done": False, "copied": False, "download_started": True}}
    cfg = dict(CFG, device_platform=platform, announce_token="test-announce")
    assert iris_agent.run_once(cfg, deps, state) == "no-assignment"
    assert rec["aria_removed"] == ["img-a.bin"]
    assert "/stage/img-a.bin" not in sizes
    assert state["img-a"]["parked"] is True
    assert not state["img-a"].get("download_started")


# --- park on a stage==root platform (copy_in_place, e.g. XR) --------------
# park's "delete the stage copy, keep the root copy" promise above assumes
# separate directories (every IOS-XE platform). On a platform whose staging
# dir IS the root (deps.copy_in_place=True — XR's attest-in-place), deleting
# the "stage" copy IS deleting the root copy, so an unassign must never do
# that to a file this agent did not prove it downloaded (Directive 2: the
# 2026-08-29 XR incident was exactly this — an operator-adopted ISO deleted
# by an unassign/teardown).


def test_park_keeps_an_adopted_root_copy_when_stage_is_root():
    cat = MultiCatalog([_img("img-a"), _img("img-b")], ids=["img-a"])
    deps, rec = make_deps(cat, {"/stage/img-a.bin": 5})
    deps = deps._replace(copy_in_place=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "img-a": {"done": True, "copied": True, "root_file": "img-a.bin",
                       "origin": "adopted"}}

    cat.ids = ["img-b"]                            # img-a dropped from the set
    iris_agent.run_once(CFG, deps, state)

    assert "/stage/img-a.bin" not in rec["removed"]     # never deleted
    assert state["img-a"]["parked"] is True             # still parked
    kept = _emits(rec, "ROOTCOPY-KEPT")
    assert any("img-a.bin" in msg and "operator-adopted" in msg for msg in kept)


def test_park_keeps_a_legacy_missing_origin_root_copy_when_stage_is_root():
    # No 'origin' at all (a state file predating this feature) is the
    # fail-safe default: treated exactly like "adopted".
    cat = MultiCatalog([_img("img-a"), _img("img-b")], ids=["img-a"])
    deps, rec = make_deps(cat, {"/stage/img-a.bin": 5})
    deps = deps._replace(copy_in_place=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "img-a": {"done": True, "copied": True, "root_file": "img-a.bin"}}

    cat.ids = ["img-b"]
    iris_agent.run_once(CFG, deps, state)

    assert "/stage/img-a.bin" not in rec["removed"]
    assert state["img-a"]["parked"] is True


def test_park_still_deletes_a_downloaded_root_copy_when_stage_is_root():
    cat = MultiCatalog([_img("img-a"), _img("img-b")], ids=["img-a"])
    deps, rec = make_deps(cat, {"/stage/img-a.bin": 5})
    deps = deps._replace(copy_in_place=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "img-a": {"done": True, "copied": True, "root_file": "img-a.bin",
                       "origin": "downloaded"}}

    cat.ids = ["img-b"]
    iris_agent.run_once(CFG, deps, state)

    assert "/stage/img-a.bin" in rec["removed"]         # IRIS's own file: freed
    assert state["img-a"]["parked"] is True


def test_park_deletes_an_uncopied_partial_regardless_of_origin_when_stage_is_root():
    # An in-progress (never successfully attested) download has no placement
    # to have provenance about — park's ordinary cleanup of an abandoned
    # partial must be unaffected by the adopted-file guard.
    cat = MultiCatalog([_img("img-a"), _img("img-b")], ids=["img-a"])
    deps, rec = make_deps(cat, {"/stage/img-a.bin": 3})   # short: still mid-transfer
    deps = deps._replace(copy_in_place=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "img-a": {"done": False, "copied": False}}

    cat.ids = ["img-b"]
    iris_agent.run_once(CFG, deps, state)

    assert "/stage/img-a.bin" in rec["removed"]
    assert state["img-a"]["parked"] is True


def test_park_keeps_an_adopted_root_copy_even_when_copied_reads_false():
    # Reviewer PROBE1: 'copied' is RECOMPUTED every tick from a fresh
    # root_present() call (iris_agent.py's steady-state check) and goes
    # False on nothing more than a transient size drift or a single XR
    # root_present miss -- while 'origin' and 'root_file' are durable facts
    # about what THIS record placed and do not move with that noise. Keying
    # protection on 'copied' failed OPEN exactly when a placement's
    # provenance was most in doubt.
    cat = MultiCatalog([_img("img-a"), _img("img-b")], ids=["img-a"])
    deps, rec = make_deps(cat, {"/stage/img-a.bin": 5})
    deps = deps._replace(copy_in_place=True)
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "img-a": {"done": True, "copied": False, "root_file": "img-a.bin",
                       "origin": "adopted"}}

    cat.ids = ["img-b"]
    iris_agent.run_once(CFG, deps, state)

    assert "/stage/img-a.bin" not in rec["removed"]
    kept = _emits(rec, "ROOTCOPY-KEPT")
    assert any("img-a.bin" in msg and "operator-adopted" in msg for msg in kept)


def test_a_restaged_file_is_never_deleted_after_a_park_and_reassign_cycle():
    # Reviewer PROBE2, the full incident-recurrence sequence, driven through
    # real ticks throughout:
    #   1. IRIS genuinely downloads img-a (origin='downloaded').
    #   2. Unassigned -> park correctly deletes IRIS's own download.
    #   3. An operator restages a byte-identical img-a.bin under the SAME
    #      name (the exact shape of the 2026-08-29 incident).
    #   4. img-a is reassigned. done/copied were never touched by park, so
    #      this hits the steady-state short-circuit -- copy_to_root/origin
    #      is never re-derived for the file actually sitting there now.
    #   5. Unassigned again: the stale 'downloaded' origin must NOT survive
    #      to authorise deleting what is now the operator's file.
    cat = MultiCatalog([_img("img-a"), _img("img-b")], ids=["img-a"])
    sizes = {}
    deps, rec = make_deps(cat, sizes)
    deps = deps._replace(copy_in_place=True)
    state = {}

    # 1. genuine download + placement, over two real ticks: absent -> this
    #    agent's own aria2 session starts the fetch (sets download_started)
    #    -> the file "arrives" -> copy_to_root succeeds on the next tick.
    iris_agent.run_once(CFG, deps, state)
    assert rec["aria_added"]                        # genuinely downloading
    sizes["/stage/img-a.bin"] = 5
    iris_agent.run_once(CFG, deps, state)
    assert state["img-a"]["origin"] == "downloaded"

    # 2. unassign -> park deletes the genuinely-downloaded copy
    cat.ids = ["img-b"]
    iris_agent.run_once(CFG, deps, state)
    assert "/stage/img-a.bin" in rec["removed"]
    assert state["img-a"]["parked"] is True

    # 3. operator restages a byte-identical file under the same name
    sizes["/stage/img-a.bin"] = 5
    rec["removed"].clear()

    # 4. reassigned -> greets the restage via the steady-state short-circuit
    cat.ids = ["img-a", "img-b"]
    iris_agent.run_once(CFG, deps, state)
    assert state["img-a"]["copied"] is True         # short-circuit confirmed it

    # 5. unassigned again -> must NOT delete the operator's restage
    cat.ids = ["img-b"]
    iris_agent.run_once(CFG, deps, state)
    assert "/stage/img-a.bin" not in rec["removed"]
    assert any("img-a.bin" in msg for msg in _emits(rec, "ROOTCOPY-KEPT"))


def test_park_then_unpark_reuses_the_surviving_root_copy():
    # Park -> un-park driven through REAL ticks (a park deletes the stage copy,
    # so a state with parked=True AND the stage file still present is a state
    # the agent can never be in).
    #
    # Coming back into the set IS a real re-download: the stage copy is gone
    # and seeding a checked image needs it. PLACEMENT is the part parking was
    # designed to save — the root copy was deliberately kept, so the
    # steady-state presence+size confirm settles it and no second ~1.2 GB copy
    # runs. A root copy that is genuinely gone must still be re-placed.
    cat = MultiCatalog([_img("img-a"), _img("img-b")], ids=["img-a", "img-b"])
    sizes = {"/stage/img-a.bin": 5, "/stage/img-b.bin": 5}
    root_ok = {}
    deps, rec = make_deps(cat, sizes)
    deps = deps._replace(
        root_present=lambda fname, prefix="flash:", expected_size=None:
        root_ok.get(fname, True))
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "multi:complete,complete"
    assert rec["copied"] == ["img-a.bin", "img-b.bin"]

    cat.ids = ["img-b"]                            # img-a leaves the set
    iris_agent.run_once(CFG, deps, state)
    assert state["img-a"]["parked"] is True
    assert sizes.get("/stage/img-a.bin") is None   # stage copy really is gone
    assert state["img-a"]["root_file"] == "img-a.bin"      # root copy kept

    # --- back in the set, root copy intact: re-download, NO re-placement ---
    cat.ids = ["img-a", "img-b"]
    rec["aria_added"].clear()
    rec["copied"].clear()
    assert iris_agent.run_once(CFG, deps, state) == "multi:downloading,complete"
    assert rec["aria_added"] == [("/stage/img-a.torrent", "/stage")]
    sizes["/stage/img-a.bin"] = 5                  # aria2 finishes the transfer
    assert iris_agent.run_once(CFG, deps, state) == "multi:complete,complete"
    assert rec["copied"] == []                     # confirmed, never re-copied

    # --- park it again, and lose the root copy while it is out of the set ---
    cat.ids = ["img-b"]
    iris_agent.run_once(CFG, deps, state)
    root_ok["img-a.bin"] = False
    cat.ids = ["img-a", "img-b"]
    rec["copied"].clear()
    assert iris_agent.run_once(CFG, deps, state) == "multi:downloading,complete"
    sizes["/stage/img-a.bin"] = 5
    assert iris_agent.run_once(CFG, deps, state) == "multi:complete,complete"
    assert rec["copied"] == ["img-a.bin"]          # genuinely gone -> re-placed


def test_park_interrupted_before_its_actions_is_retried_next_tick():
    # "parked" means the park ACTIONS ran. A tick that could not name the
    # dropped image's file (a transient catalog failure) and then died staging
    # another image must not leave the record flagged: the flag is what takes a
    # record out of the stale list, so a false one strands a live aria2
    # download and its partial on flash with no way back but hand-editing
    # state.
    cat = MultiCatalog([_img("img-a"), _img("img-b")], ids=["img-a", "img-b"])
    sizes = {}
    deps, rec = make_deps(cat, sizes)
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "multi:downloading,downloading"
    sizes["/stage/img-a.bin"] = 3                  # a partial, mid-transfer

    # img-a drops out on the very tick the catalog goes bad: nothing can be
    # named, so nothing is stopped or deleted. img-b reports the lookup error.
    cat.ids = ["img-b"]
    cat.raises = {"img-a", "img-b"}
    rec["aria_removed"].clear()
    rec["removed"].clear()
    assert iris_agent.run_once(CFG, deps, state) == "image-unavailable"
    assert cat.heartbeats[-1]["stage_state"] == "error"
    assert cat.heartbeats[-1]["current_image_id"] == "img-b"
    assert rec["aria_removed"] == [] and rec["removed"] == []   # nothing ran...
    assert "parked" not in state["img-a"]                       # ...so not parked

    cat.raises = set()                             # next healthy tick
    iris_agent.run_once(CFG, deps, state)
    # (img-b.bin is also force-removed on this tick — the stale-entry clear
    # every re-add does — so this checks membership, not the whole list.)
    assert "img-a.bin" in rec["aria_removed"]      # the park actually happens
    assert rec["removed"] == ["/stage/img-a.bin"]
    assert state["img-a"]["parked"] is True        # and only THEN is it flagged


def test_park_moves_the_legacy_root_file_into_the_parked_record():
    # The top-level root_file is the legacy mirror for the set's FIRST image.
    # Parking that image makes it stale: _protect_set and any legacy reader
    # would pair one image's file with another image's image_id.
    cat = MultiCatalog([_img("img-a"), _img("img-b")], ids=["img-a"])
    deps, rec = make_deps(cat, {"/stage/img-a.bin": 5})
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert state["root_file"] == "img-a.bin"

    cat.ids = ["img-b"]                            # img-a parked, img-b staging
    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    assert "root_file" not in state                # moved out of the top level
    assert state["img-a"]["root_file"] == "img-a.bin"      # into its owner


def test_protect_set_offers_parked_root_copies_to_reclaim():
    """The uncheck contract keeps a parked image's ROOT copy, but only until a
    newly checked image needs the room: "the reclaim-bundle download gate may
    consume parked root copies for space exactly as it does replaced ones
    today". _protect_set protected EVERY state entry's root_file, parked
    included, so a device with a full boot filesystem could never free
    anything IRIS had placed and stayed flash_full forever."""
    state = {"img-a": {"root_file": "img-a.bin", "parked": True},
             "img-b": {"root_file": "img-b.bin"},
             "img-c": {"root_file": "img-c.bin", "done": True, "copied": True}}
    keep = iris_agent._protect_set(_img("img-b"), state)
    assert "img-a.bin" not in keep          # parked -> reclaimable
    assert "img-b.bin" in keep              # the image being staged
    assert "img-c.bin" in keep              # another image of the LIVE set
    assert "img-b.bin.aria2" in keep and "img-b.torrent" in keep


def test_bundle_reclaim_offers_the_parked_copy_and_protects_the_running_image():
    """The same rule through the gate that actually deletes: the parked root
    copy reaches reclaimable(), while the running image and the live set's own
    placed copies never do."""
    cat = MultiCatalog([_img("img-a"), _img("img-b")], ids=["img-b"])
    deps, rec = make_deps(cat, {})
    seen = {}
    deps = deps._replace(reclaimable=lambda prefix, protect:
                         (seen.update(protect=set(protect)) or ["img-a.bin"]))
    state = {"img-a": {"root_file": "img-a.bin", "parked": True},
             "img-b": {"root_file": "img-b.bin"}}
    assert iris_agent._reclaim_for_mode(
        deps, "bundle", "flash:", _img("img-b"), state) is True
    assert "img-a.bin" not in seen["protect"]     # parked -> offered up
    assert "running.bin" in seen["protect"]       # never the running image
    assert "img-b.bin" in seen["protect"]         # never the live set's own
    assert rec["bundle_reclaimed"] == [("flash:", ["img-a.bin"])]


def test_legacy_image_id_pointer_waits_for_a_valid_catalog_answer():
    # The old agent advanced the top-level pointer only AFTER the catalog
    # answered for the image and its filename passed the whitelist. A device
    # assigned an image the catalog does not have staged nothing, so it must
    # not end up pointing at that image.
    cat = MultiCatalog([_img("img1")], ids=["img1"])
    deps, rec = make_deps(cat, {"/stage/img1.bin": 5})
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert state["image_id"] == "img1"

    cat.ids = ["img-gone"]
    assert iris_agent.run_once(CFG, deps, state) == "no-image"
    assert state["image_id"] == "img1"


def test_heartbeat_is_not_ready_while_an_image_errors_this_tick():
    # staged_image_ids is read from STATE, so it still counts an image that was
    # staged on an earlier tick but failed on THIS one. "ready" alongside a
    # stage_error is a contradiction the console cannot act on.
    cat = MultiCatalog([_img("img-a"), _img("img-b")], ids=["img-a", "img-b"])
    deps, rec = make_deps(cat, {"/stage/img-a.bin": 5, "/stage/img-b.bin": 5})
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "multi:complete,complete"
    assert cat.heartbeats[-1]["stage_state"] == "ready"

    del cat.images["img-b"]                        # the catalog drops one
    assert iris_agent.run_once(CFG, deps, state) == "multi:complete,no-image"
    hb = cat.heartbeats[-1]
    assert hb["staged_image_ids"] == ["img-a", "img-b"]   # state still says both
    assert hb["stage_state"] != "ready"
    assert hb["stage_state"] == "error"                   # what it actually hit
    assert hb["stage_error"] == "assigned image img-b not in catalog"


def test_rejected_filename_reports_its_error_without_hiding_a_good_sibling():
    # An invalid catalog filename must still produce an error heartbeat,
    # without creating an image state record or suppressing the good sibling.
    bad = _img("img-a")
    bad["filename"] = "img a.bin"                  # space: fails the whitelist
    cat = MultiCatalog([bad, _img("img-b")], ids=["img-a", "img-b"])
    deps, rec = make_deps(cat, {"/stage/img-b.bin": 5})
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "multi:bad-filename,complete"
    hb = cat.heartbeats[-1]
    assert hb["current_image_id"] == "img-a"
    assert hb["stage_state"] == "error"
    assert hb["staged_image_ids"] == ["img-b"]
    assert hb["errored_image_ids"] == ["img-a"]
    assert "filename" in hb["stage_error"]
    assert "img-a" not in state


@pytest.mark.parametrize("failed_id", ["img-a", "img-b"])
def test_image_lookup_failure_preserves_sibling_progress(failed_id):
    good_id = "img-b" if failed_id == "img-a" else "img-a"
    cat = MultiCatalog([_img("img-a"), _img("img-b")])
    cat.raises = {failed_id}
    deps, rec = make_deps(cat, {"/stage/img-a.bin": 5, "/stage/img-b.bin": 5})
    state = {}

    expected = ("multi:image-unavailable,complete" if failed_id == "img-a"
                else "multi:complete,image-unavailable")
    assert iris_agent.run_once(CFG, deps, state) == expected
    assert state[good_id]["copied"] is True
    assert failed_id not in state
    assert rec["copied"] == [good_id + ".bin"]
    assert len(cat.heartbeats) == 1
    hb = cat.heartbeats[-1]
    assert hb["stage_state"] == "error"
    assert hb["staged_image_ids"] == [good_id]
    assert hb["errored_image_ids"] == [failed_id]

    cat.raises.clear()
    assert iris_agent.run_once(CFG, deps, state) == "multi:complete,complete"
    assert cat.heartbeats[-1]["stage_state"] == "ready"
    assert rec["copied"].count(good_id + ".bin") == 1


@pytest.mark.parametrize("failure", ["lookup", "filename"])
def test_invalid_catalog_image_reports_without_creating_image_state(failure):
    cat = MultiCatalog([_img("img-a")])
    if failure == "lookup":
        def unavailable(image_id):
            raise ValueError("https://catalog/private?token=do-not-disclose")
        cat.get_image = unavailable
    else:
        cat.images["img-a"]["filename"] = "../outside.bin"
    deps, rec = make_deps(cat, {})
    state = {}

    expected = "image-unavailable" if failure == "lookup" else "bad-filename"
    assert iris_agent.run_once(CFG, deps, state) == expected
    assert "img-a" not in state
    assert "image_id" not in state
    assert rec["copied"] == []
    assert rec["aria_added"] == []
    assert len(cat.heartbeats) == 1
    hb = cat.heartbeats[-1]
    assert hb["current_image_id"] == "img-a"
    assert hb["stage_state"] == "error"
    assert hb["telemetry_observation"]["obs_state"] == "not_active"
    assert "do-not-disclose" not in repr(hb) + repr(rec["emitted"])


def test_missing_catalog_image_keeps_its_failure_identity():
    cat = MultiCatalog([], ids=["missing"])
    deps, rec = make_deps(cat, {})
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "no-image"
    assert cat.heartbeats[-1]["current_image_id"] == "missing"
    assert cat.heartbeats[-1]["stage_state"] == "error"
    assert "missing" not in state
    assert rec["aria_added"] == []


@pytest.mark.parametrize("image_ids", [
    ["img-a"], ["img-a", "img-b"], ["img-b", "img-a"],
])
@pytest.mark.parametrize("reply", [
    b'{"error":{"code":1,"message":"token=do-not-disclose"}}',
    b'not JSON: token=do-not-disclose',
    b'{"result":null}',
])
def test_rpc_rejection_reports_error_preserves_siblings_and_retries(image_ids, reply):
    cat = MultiCatalog([_img(iid) for iid in image_ids])
    deps, rec = make_deps(cat, {"/stage/img-b.bin": 5})
    reject = True

    def add(torrent, directory):
        # Exercise the actual response parser: HTTP 200 does not mean that
        # aria2 accepted addTorrent, and its error may contain credentials.
        result = iris_agent._aria_add_result(
            reply if reject else b'{"result":"accepted-gid"}')
        rec["aria_added"].append((torrent, directory))
        return result

    deps = deps._replace(aria_add=add)
    state = {}
    statuses = ["aria2-down" if iid == "img-a" else "complete" for iid in image_ids]
    expected = statuses[0] if len(statuses) == 1 else "multi:" + ",".join(statuses)
    assert iris_agent.run_once(CFG, deps, state) == expected
    assert len(cat.heartbeats) == 1
    assert cat.heartbeats[-1]["stage_state"] == "error"
    assert not state["img-a"].get("download_started")
    assert rec["aria_added"] == []
    if len(image_ids) > 1:
        assert cat.heartbeats[-1]["staged_image_ids"] == ["img-b"]
        assert cat.heartbeats[-1]["errored_image_ids"] == ["img-a"]
        assert rec["copied"] == ["img-b.bin"]
    else:
        assert cat.heartbeats[-1]["current_image_id"] == "img-a"
    assert "do-not-disclose" not in repr(cat.heartbeats) + repr(rec["emitted"])

    reject = False
    statuses = ["downloading" if iid == "img-a" else "complete" for iid in image_ids]
    expected = statuses[0] if len(statuses) == 1 else "multi:" + ",".join(statuses)
    assert iris_agent.run_once(CFG, deps, state) == expected
    assert cat.heartbeats[-1]["stage_state"] == "staging"
    assert cat.heartbeats[-1]["stage_error"] is None
    assert state["img-a"]["download_started"] is True
    assert rec["aria_added"] == [("/stage/img-a.torrent", "/stage")]
    assert rec["copied"].count("img-b.bin") <= 1


def test_flash_full_on_one_image_does_not_block_the_next():
    # One image that cannot fit must not stop the rest of the set: it reports
    # its own headroom state and the loop carries on.
    cat = MultiCatalog([_img("img-a", size=2_000_000_000), _img("img-b", size=7)],
                       ids=["img-a", "img-b"])
    deps, rec = make_deps(cat, {"/stage/img-b.bin": 7}, free=1_000_000_000)
    state = {}

    assert iris_agent.run_once(CFG, deps, state) == "multi:no-space,complete"
    assert any("img-a.bin" in msg for msg in _emits(rec, "FLASH-FULL"))
    assert rec["copied"] == ["img-b.bin"]          # the one that fits is placed
    assert len(cat.heartbeats) == 1
    hb = cat.heartbeats[-1]
    assert hb["staged_image_ids"] == ["img-b"]
    assert hb["stage_state"] == "flash_full"       # some image had no room


def test_return_string_for_multi_set():
    # N>1 returns "multi:" + the per-image statuses in checked order.
    cat = MultiCatalog([_img("img-a", size=5), _img("img-b", size=7)],
                       ids=["img-a", "img-b"])
    deps, rec = make_deps(cat, {"/stage/img-a.bin": 5})
    state = {}
    out = iris_agent.run_once(CFG, deps, state)
    assert out.startswith("multi:")
    assert out.split(":", 1)[1].split(",") == ["complete", "downloading"]


def test_multi_image_heartbeat_names_the_errored_image():
    # Review finding: _row_is_staging (server) cannot tell "1 errored, 2 in
    # flight" from "all 3 errored" from stage_state alone. img-a has no room
    # (a terminal per-image failure this tick), img-b is already fully
    # staged, img-c is still downloading -- the set heartbeat must name
    # exactly the one that is actually stuck, not the whole set.
    cat = MultiCatalog([_img("img-a", size=2_000_000_000), _img("img-b", size=5),
                        _img("img-c", size=5)],
                       ids=["img-a", "img-b", "img-c"])
    deps, rec = make_deps(cat, {"/stage/img-b.bin": 5}, free=1_000_000_000)
    state = {}

    iris_agent.run_once(CFG, deps, state)
    hb = cat.heartbeats[-1]
    assert hb["errored_image_ids"] == ["img-a"]
    assert hb["staged_image_ids"] == ["img-b"]      # img-c is still in flight


def test_single_image_heartbeat_omits_errored_image_ids():
    # Compat: a one-image set's heartbeat is byte-identical to the
    # pre-multi-image agent -- no errored_image_ids key, same as it has no
    # staged_image_ids key (test_single_image_set_behaves_exactly_as_before
    # pins the full key set; this is the narrow marker for this one field).
    cat = MultiCatalog([_img("img1")], ids=["img1"])
    deps, rec = make_deps(cat, {"/stage/img1.bin": 5})
    state = {}

    iris_agent.run_once(CFG, deps, state)
    assert "errored_image_ids" not in cat.heartbeats[0]


def test_parked_root_copy_that_is_the_boot_target_survives_the_reclaim_gate():
    """IRIS-09-002 through the park contract: a parked image's root copy is
    deliberately reclaimable — but not when the operator has pointed BOOT at
    it. Bundle reclaim for the newly checked image protects the BOOT target
    on the same footing as the running image, and the space comes from
    something else (or nowhere)."""
    cat = MultiCatalog([_img("img-a"), _img("img-b", size=5_000_000_000)],
                       ids=["img-b"])
    deps, rec = make_deps(cat, {}, free=500_000_000)
    rec["boot"]["image"] = "flash:img-a.bin"
    seen = {}

    def reclaimable(prefix, protect):
        seen["protect"] = set(protect)
        return [n for n in ("img-a.bin", "stale.bin") if n not in protect]

    deps = deps._replace(reclaimable=reclaimable)
    state = {"img-a": {"root_file": "img-a.bin", "parked": True,
                       "done": False, "copied": True}}
    assert iris_agent.run_once(CFG, deps, state) == "no-space"
    assert "img-a.bin" in seen["protect"]            # the BOOT target
    assert "running.bin" in seen["protect"]
    assert rec["bundle_reclaimed"] == [("flash:", ["stale.bin"])]
    assert state["img-a"]["root_file"] == "img-a.bin"   # record untouched


def test_one_image_torrent_fetch_failure_does_not_abort_the_set_tick():
    """IRIS-09-004: the catalog refuses ONE image's torrent (503 behind the
    deployment gate). The sibling's work still completes and is reported, the
    set heartbeat still goes out carrying the error, and nothing raises — so
    main() persists the sibling's done/copied instead of re-hashing and
    re-copying ~1.2 GB every tick."""
    cat = MultiCatalog([_img("img-a"), _img("img-b")], ids=["img-a", "img-b"])
    cat.torrent_raises = {"img-b"}
    deps, rec = make_deps(cat, {"/stage/img-a.bin": 5})
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == \
        "multi:complete,torrent-unavailable"
    assert state["img-a"]["done"] and state["img-a"]["copied"]
    assert rec["copied"] == ["img-a.bin"]
    assert rec["aria_added"] == []
    assert len(cat.heartbeats) == 1
    hb = cat.heartbeats[0]
    assert hb["stage_state"] == "error"
    assert hb["staged_image_ids"] == ["img-a"]
    assert hb["errored_image_ids"] == ["img-b"]
    assert "torrent" in hb["stage_error"]
    assert _emits(rec, "TORRENT-UNAVAILABLE")
    # next tick, gate open: img-b starts, img-a stays steady (no re-copy)
    cat.torrent_raises = set()
    rec["copied"].clear()
    assert iris_agent.run_once(CFG, deps, state) == "multi:complete,downloading"
    assert rec["copied"] == []
    assert rec["aria_added"] == [("/stage/img-b.torrent", "/stage")]
