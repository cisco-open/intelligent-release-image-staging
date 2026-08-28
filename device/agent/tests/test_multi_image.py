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

    def get_policy(self, sid):
        return {"approved_image_id": self.ids[0] if self.ids else None,
                "approved_image_ids": list(self.ids)}

    def get_image(self, image_id):
        return self.images.get(image_id)

    def download_torrent(self, image_id, dest):
        self.downloaded.append((image_id, dest))

    def heartbeat(self, sid, data):
        self.heartbeats.append(data)
        return self.hb_response


def make_deps(catalog, sizes, free=9_000_000_000, root_ok=True,
              verify_ok=True, mode="bundle", reclaimables=()):
    """Fake Deps + a `rec` dict of everything the agent did to the device."""
    rec = {"emitted": [], "ios": [], "aria_added": [], "aria_removed": [],
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
        ios=lambda cmd: rec["ios"].append(cmd) or "",
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


def test_recheck_of_parked_image_unparks_and_confirms_root():
    # The image comes back into the set. Its root copy survived parking, so
    # placement is the cheap presence+size confirm the steady-state
    # short-circuit already does — no re-download, no re-copy.
    cat = MultiCatalog([_img("img-a")], ids=["img-a"])
    deps, rec = make_deps(cat, {"/stage/img-a.bin": 5})
    state = {"schema_version": iris_agent._STATE_SCHEMA,
             "image_id": "img-a",
             "img-a": {"done": True, "copied": True, "sha": "img-a-sha",
                       "root_file": "img-a.bin", "parked": True,
                       "copy_terminal": True, "copy_attempts": 4}}

    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert "parked" not in state["img-a"]                  # un-parked
    assert "copy_terminal" not in state["img-a"]           # _reset_copy_failures
    assert "copy_attempts" not in state["img-a"]
    assert rec["aria_added"] == []                         # no re-download
    assert rec["copied"] == []                             # no re-copy


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
