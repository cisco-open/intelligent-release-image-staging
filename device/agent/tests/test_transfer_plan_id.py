# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The device ADOPTS the server-minted transfer identity instead of minting its
own (`plans` in the policy body -> telemetry_report.adopt_plan).

WHY THIS FILE EXISTS. A device-minted transfer_id could not answer "when was
this transfer decided, and when did it start seeding": the id was minted by
ensure_transfer_id inside _build_observation, which the download path reaches
only AFTER deps.aria_add() has already started the transfer, and an
unassign+reassign of the same image inside one ~60 s tick window is invisible
to the park pass, so the second plan silently inherited the first plan's id.
Both facts are now the server's, minted once at assignment; these tests pin the
device half of that contract against the REAL run_once path, not against
adopt_plan in isolation.

Fakes are built locally rather than imported from test_iris_agent.py or
test_telemetry_v2.py — the convention in this suite is that each module owns its
own Deps builder — but they mirror those modules' shapes, so a behaviour proved
here means the same thing there.

NOT PROVEN HERE, deliberately: the replan re-verify (test_replan_verify.py owns
the steady-state re-hash) and the server-side promotion rules
(server/tests/test_transfer_lifecycle.py owns those). What this file guarantees
FOR that server half is narrower and load-bearing: every report the agent builds
carries exactly the transfer_id of the plan currently in force, and never the
previous plan's — which is what makes the server's strict "a plan is promoted
only by a report bearing ITS transfer_id" match safe.
"""
import re
import time as _time

import iris_agent
import telemetry_report

# completion-jitter sleep is a module seam; never sleep in unit tests.
iris_agent._SLEEP = lambda s: None

HEX32 = re.compile(r"^[a-f0-9]{32}$")

# Server-minted ids are secrets.token_hex(16). These stand-ins are the same
# shape (32 lowercase hex) and are visibly NOT random, so a value that leaks
# from the wrong plan into an assertion is readable at a glance.
PLAN_A = "1a" * 16
XFER_A = "2b" * 16
PLAN_B = "3c" * 16
XFER_B = "4d" * 16

CFG = {"device_id": "sw1", "stage_dir": "/stage",
       # far-future expiry so needs_refresh() skips the token refresh step
       "token_expires_at": str(int(_time.time()) + 604_800),
       "telemetry": "on", "telemetry_stream": "on",
       "agent_version": "2026.09.02"}

IMG = {"id": "img1", "filename": "img1.bin", "size": 5, "sha256": "img1-sha"}


def _plan(plan_id, transfer_id):
    """One row of the policy body's `plans` map — the WIRE projection, which
    carries the two device-visible fields only (planned_at and info_hash stay
    server-side, the device has no use for them)."""
    return {"plan_id": plan_id, "transfer_id": transfer_id}


class PlanCatalog:
    """Catalog whose policy body carries the server's `plans` map beside the
    assignment.

    `plans=None` is the OLD server (and the legacy-bootstrap policy row): the
    body has exactly the two keys it has always had, so the agent must behave
    byte-for-byte as it does today.
    """

    def __init__(self, ids, plans=None, images=(IMG,)):
        self.ids = list(ids)
        self.plans = plans
        self.images = {i["id"]: i for i in images}
        self.heartbeats, self.telemetry, self.order = [], [], []
        self.hb_response = None
        self.post_ok = True

    def get_policy(self, sid):
        self.order.append("get_policy")
        body = {"approved_image_id": self.ids[0] if self.ids else None,
                "approved_image_ids": list(self.ids)}
        if self.plans is not None:
            body["plans"] = self.plans
        return body

    def get_image(self, iid):
        return self.images.get(iid)

    def download_torrent(self, iid, dest):
        pass

    def heartbeat(self, sid, data):
        self.order.append("heartbeat")
        self.heartbeats.append(data)
        return self.hb_response

    def post_telemetry(self, sid, report):
        self.telemetry.append(report)
        if not self.post_ok:
            raise RuntimeError("collector unreachable")
        return {"ok": True}


def make_deps(cat, sizes, **over):
    """Fake Deps + the `rec` dict of everything the agent did to the device."""
    rec = {"emitted": [], "aria_added": [], "verified": [], "copied": []}
    order = cat.order

    def _aria_add(torrent, dest):
        order.append("aria_add")
        rec["aria_added"].append((torrent, dest))

    def _verify(path, sha):
        rec["verified"].append((path, sha))
        return True

    base = dict(
        catalog=cat,
        emit=lambda m, msg: rec["emitted"].append((m, msg)),
        boot_image=lambda: "running.bin",
        aria_add=_aria_add,
        file_size=lambda p: sizes.get(p),
        verify=_verify,
        free_bytes=lambda prefix="flash:": 9_000_000_000,
        version=lambda: "17.18.03",
        copy_to_root=lambda f, tp="flash:", expected_size=None: (
            rec["copied"].append(f) or True),
        purge_others=lambda keep, kid: None,
        reclaim=lambda: None,
        root_present=lambda f, prefix="flash:", expected_size=None: True,
        remove_stage=lambda p: sizes.pop(p, None),
        aria_remove=lambda f: None,
        detect_mode=lambda: "bundle",
        target_fs=lambda: ("flash:", 9_000_000_000),
        running_image=lambda: "running.bin",
        reclaimable=lambda prefix, protect: [],
        reclaim_bundle=lambda prefix, names: None,
        model=lambda: "C9300-TEST",
        refresh=lambda: None,
        aria_stats=lambda p: None,
        aria_peers=lambda p: [],
        io_transfer=False,
        checkpoint=lambda s: order.append("checkpoint"),
        aria_session=lambda: None,
        copy_in_place=False)
    base.update(over)
    return iris_agent.Deps(**base), rec


def _tele(state, img_id="img1"):
    return state.get(img_id, {}).get("tele", {})


def _emits(rec, mnemonic):
    return [msg for m, msg in rec["emitted"] if m == mnemonic]


# ---- adoption happens before the bytes move (requirement 3) ----

def test_server_plan_id_is_adopted_before_any_download_starts():
    """The whole point of moving the mint to the server: the transfer must be
    identified at the moment it is DECIDED, not once aria2 is already pulling
    bytes. Asserted at the strongest point available — the value visible in
    state at the instant deps.aria_add() is called."""
    cat = PlanCatalog(["img1"], plans={"img1": _plan(PLAN_A, XFER_A)})
    state = {}
    seen = []

    def spy_aria_add(torrent, dest):
        # Snapshot what the agent had already committed to state when it told
        # aria2 to start. A device-minted id would still be absent here.
        cat.order.append("aria_add")
        seen.append(dict(_tele(state)))

    deps, rec = make_deps(cat, {}, aria_add=spy_aria_add)

    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    assert seen and seen[0]["transfer_id"] == XFER_A
    assert seen[0]["plan_id"] == PLAN_A
    # ...and adoption is downstream of the policy read that carried the plan.
    assert cat.order.index("get_policy") < cat.order.index("aria_add")
    assert _emits(rec, "REPLAN") == ["img1 adopted plan %s" % PLAN_A]


def test_the_adopted_id_rides_every_ensure_transfer_id_call_site():
    """ensure_transfer_id is a get-or-mint and the ONLY writer of
    tele['transfer_id'] in the tree, so seeding the key at adoption is the whole
    of the plumbing: the observation envelope, the heartbeat sample and the
    frozen v2 report all inherit the server's id with no further code."""
    cat = PlanCatalog(["img1"], plans={"img1": _plan(PLAN_A, XFER_A)})
    state = {}

    # Tick 1: the download is in flight (partial file + .aria2 control file).
    sizes = {"/stage/img1.bin": 2, "/stage/img1.bin.aria2": 1}
    deps, _ = make_deps(cat, sizes)
    assert iris_agent.run_once(CFG, deps, state) == "downloading"

    # The get-or-mint returns the SERVER's id and mints nothing.
    assert telemetry_report.ensure_transfer_id(state, "img1") == XFER_A
    assert cat.heartbeats[-1]["telemetry_observation"]["transfer_id"] == XFER_A

    # Tick 2: the transfer completes, so the terminal v2 report is armed,
    # frozen and posted — under the same server-minted id.
    sizes.clear()
    sizes["/stage/img1.bin"] = IMG["size"]
    deps, _ = make_deps(cat, sizes)
    iris_agent.run_once(CFG, deps, state)
    assert cat.telemetry, "the completion tick posted no v2 report"
    assert cat.telemetry[-1]["transfer_id"] == XFER_A
    assert cat.telemetry[-1]["event"] == "staging-complete"
    # plan_id is stored device-side and NEVER echoed: the server owns the
    # transfer_id -> plan_id mapping, so the ingest whitelist needs no change.
    assert "plan_id" not in cat.telemetry[-1]
    assert all("plan_id" not in hb for hb in cat.heartbeats)


def test_the_adopted_id_passes_server_side_report_validation():
    """The server re-validates transfer_id against 32-lowercase-hex at ingest
    and a failure there costs the device its WHOLE report, so the shape the
    server mints (secrets.token_hex(16)) and the shape the server accepts must
    be the same shape. Proved by running the agent's own posted body back
    through the real ingest sanitiser."""
    # Imported here rather than at module scope: server/ is not on the device
    # test path by default (conftest.py adds only device/ and device/agent/),
    # and this is the one test in the file that needs the server half.
    import os
    import sys
    # tests/ -> agent/ -> device/ -> the repository root, then server/.
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    server_dir = os.path.join(repo_root, "server")
    if server_dir not in sys.path:
        sys.path.insert(0, server_dir)
    import catalog as server_catalog

    cat = PlanCatalog(["img1"], plans={"img1": _plan(PLAN_A, XFER_A)})
    state = {}
    sizes = {"/stage/img1.bin": 2, "/stage/img1.bin.aria2": 1}
    deps, _ = make_deps(cat, sizes)
    iris_agent.run_once(CFG, deps, state)
    sizes.clear()
    sizes["/stage/img1.bin"] = IMG["size"]
    # Completion-tick stats so the report carries MEASURED content: an
    # unmeasured completion now omits the byte fields (IRIS-10-002), a shape
    # the server ingest tolerates separately; this test is about the id.
    deps, _ = make_deps(cat, sizes, aria_stats=lambda p: {
        "completedLength": str(IMG["size"]), "totalLength": str(IMG["size"])})
    iris_agent.run_once(CFG, deps, state)

    posted = cat.telemetry[-1]
    stored = server_catalog._sanitize_report_v2(posted)
    assert stored["transfer_id"] == XFER_A
    assert HEX32.match(stored["transfer_id"])


# ---- a steady tick is a no-op (requirement 3: never re-minted) ----

def test_adoption_is_idempotent_across_ticks_and_never_resets_sample_seq():
    """Every steady tick re-reads the policy and re-adopts. Rewriting the bag
    on an unchanged plan would reset sample_seq, disarm a pending report and
    drop a frozen payload mid-retry — i.e. break a live transfer once a minute."""
    cat = PlanCatalog(["img1"], plans={"img1": _plan(PLAN_A, XFER_A)})
    cat.post_ok = False          # the report stays pending and frozen
    state = {}
    sizes = {"/stage/img1.bin": 2, "/stage/img1.bin.aria2": 1}

    deps, rec = make_deps(cat, sizes)
    iris_agent.run_once(CFG, deps, state)
    assert _tele(state)["sample_seq"] == 1

    # Complete the transfer: the terminal report is armed and frozen, and the
    # POST fails, so it is still pending when the next tick re-adopts.
    sizes.clear()
    sizes["/stage/img1.bin"] = IMG["size"]
    deps, rec = make_deps(cat, sizes)
    iris_agent.run_once(CFG, deps, state)
    frozen = telemetry_report.frozen_report(state, "img1")
    assert frozen is not None and frozen["transfer_id"] == XFER_A
    assert _tele(state)["report_pending"] is True
    seq = _tele(state)["sample_seq"]

    # A third tick on the SAME plan: adoption returns 'same' and touches
    # nothing. The frozen body is the identical object, so the retry is
    # byte-for-byte the report the server may already have seen.
    deps, rec = make_deps(cat, sizes)
    iris_agent.run_once(CFG, deps, state)
    assert telemetry_report.adopt_plan(state, "img1", PLAN_A, XFER_A) == "same"
    assert telemetry_report.frozen_report(state, "img1") is frozen
    assert _tele(state)["report_pending"] is True
    assert _tele(state)["transfer_id"] == XFER_A
    assert _tele(state)["sample_seq"] >= seq
    # No plan boundary was crossed after the first tick, so no further REPLAN.
    assert _emits(rec, "REPLAN") == []


# ---- an old server, and garbage, both leave today's behaviour alone ----

def test_absent_plans_key_falls_back_to_device_minting():
    """An un-upgraded server sends the two-key policy body it always sent. The
    agent must then behave byte-for-byte as it does today: ensure_transfer_id
    mints, and nothing in the bag gains a plan_id."""
    cat = PlanCatalog(["img1"], plans=None)
    state = {}
    deps, rec = make_deps(cat, {"/stage/img1.bin": 2,
                                "/stage/img1.bin.aria2": 1})
    assert iris_agent.run_once(CFG, deps, state) == "downloading"

    tid = _tele(state)["transfer_id"]
    assert HEX32.match(tid)
    assert tid not in (XFER_A, XFER_B)
    assert "plan_id" not in _tele(state)
    assert _emits(rec, "REPLAN") == []


def test_a_non_hex_or_malformed_plan_row_is_ignored():
    """Anything that does not validate is refused while touching NO state, so a
    hand-edited policy.json, a captive portal, or a half-upgraded server cannot
    poison the id — a non-hex transfer_id adopted here would be rejected by the
    server at ingest and cost the device its telemetry, not just its plan."""
    bad_pairs = [
        (None, None),                                 # nothing sent
        (PLAN_A, None),                               # no transfer_id
        (None, XFER_A),                               # no plan_id
        (PLAN_A, "2b" * 15 + "2"),                    # 31 hex
        (PLAN_A, XFER_A.upper()),                     # uppercase hex
        ("2b" * 15 + "2", XFER_A),                    # 31 hex plan_id
        (PLAN_A, "g" * 32),                           # non-hex
        (PLAN_A, " " + XFER_A[1:]),                   # right length, not hex
        (12345, XFER_A),                              # not a string
        (PLAN_A, {"transfer_id": XFER_A}),            # not a string
    ]
    for plan_id, transfer_id in bad_pairs:
        state = {}
        assert telemetry_report.adopt_plan(
            state, "img1", plan_id, transfer_id) is None
        assert state == {}, "a refused plan must touch no state: %r" \
            % ((plan_id, transfer_id),)

    bad_rows = [
        None,                                        # no row at all
        "1a" * 16,                                   # a bare string, not a row
        [],                                          # a list
        {},                                          # empty row
    ] + [{"plan_id": p, "transfer_id": t} for p, t in bad_pairs]

    # ...and the same garbage arriving on the wire leaves the tick working: the
    # agent mints its own id exactly as it does today, and nothing escapes.
    for row in bad_rows:
        cat = PlanCatalog(["img1"], plans={"img1": row})
        state = {}
        deps, rec = make_deps(cat, {"/stage/img1.bin": 2,
                                    "/stage/img1.bin.aria2": 1})
        assert iris_agent.run_once(CFG, deps, state) == "downloading"
        assert HEX32.match(_tele(state)["transfer_id"])
        assert "plan_id" not in _tele(state)
        assert _emits(rec, "REPLAN") == []

    # A `plans` value that is not a map at all is skipped wholesale.
    for plans in ("nope", [], 7):
        cat = PlanCatalog(["img1"], plans=plans)
        state = {}
        deps, rec = make_deps(cat, {"/stage/img1.bin": 2,
                                    "/stage/img1.bin.aria2": 1})
        assert iris_agent.run_once(CFG, deps, state) == "downloading"
        assert HEX32.match(_tele(state)["transfer_id"])
        assert "plan_id" not in _tele(state)


# ---- restart / state loss (requirement 4, device half) ----

def test_a_lost_state_file_re_adopts_the_same_id_from_the_policy():
    """The agent is a one-shot process, so every tick is already a restart —
    and an unreadable state file (STATE-LOAD-FAIL) starts run_once from {}.
    Before, that split one physical transfer across two minted ids; now the id
    comes back from the server on every poll, so it is strictly better than a
    device-minted id, which could never survive this."""
    cat = PlanCatalog(["img1"], plans={"img1": _plan(PLAN_A, XFER_A)})
    sizes = {"/stage/img1.bin": 2, "/stage/img1.bin.aria2": 1}

    first = {}
    deps, _ = make_deps(cat, sizes)
    iris_agent.run_once(CFG, deps, first)

    # State lost between ticks — the STATE-LOAD-FAIL path hands run_once {}.
    second = {}
    deps, _ = make_deps(cat, sizes)
    iris_agent.run_once(CFG, deps, second)

    assert _tele(first)["transfer_id"] == _tele(second)["transfer_id"] == XFER_A
    assert cat.heartbeats[0]["telemetry_observation"]["transfer_id"] \
        == cat.heartbeats[-1]["telemetry_observation"]["transfer_id"] == XFER_A


# ---- a plan boundary really is a boundary (requirement 7) ----

def test_a_new_plan_id_replaces_the_transfer_and_resets_the_tele_bag():
    """An unassign+reassign inside one tick window is invisible to the park
    pass, so the SERVER's new plan is the only signal that the previous
    transfer is over. Everything scoped to that transfer must go: carrying any
    of it forward would attest the new transfer with the old one's evidence."""
    state = {"img1": {
        # facts about the FILE on disk — these legitimately survive
        "done": True, "copied": True, "sha": "img1-sha",
        "root_file": "img1.bin",
        # everything below is scoped to the transfer that is now over
        "tele": {"plan_id": PLAN_A, "transfer_id": XFER_A,
                 "sample_seq": 9, "frozen_report": {"report_id": "f" * 32},
                 "event": "staging-complete", "report_pending": True,
                 "report_attempts": 2, "report_next_ts": 1234.0,
                 "report_sent_ts": 1200.0, "started_ts": 1000.0,
                 "done_ts": 1100.0, "content_sha256_state": "verified",
                 "peers": {"10.0.0.9": 1}, "peers_v2": {"10.0.0.9": {}},
                 "peer_transfer_records": [{"ip": "10.0.0.9"}]}}}

    assert telemetry_report.adopt_plan(state, "img1", PLAN_B, XFER_B) == "new"

    tele = _tele(state)
    assert tele["plan_id"] == PLAN_B and tele["transfer_id"] == XFER_B
    for gone in ("sample_seq", "event", "report_sent_ts", "started_ts",
                 "done_ts", "content_sha256_state", "peers", "peers_v2",
                 "peer_transfer_records"):
        assert gone not in tele, "%s survived a plan boundary" % gone
    # The one exception, and it is not an attestation (board #44). A frozen,
    # still-retrying report is a FINISHED statement about the previous
    # transfer, carrying that transfer_id in its own body, so it can never
    # attest this one. Destroying it would drop the old transfer's only
    # completion telemetry -- nothing re-arms it, because the image is still
    # done+copied and _stage_image takes the steady-state short-circuit. Only
    # the delivery machinery travels, and only while a send is still owed.
    assert tele["report_pending"] is True
    assert tele["frozen_report"] == {"report_id": "f" * 32}
    assert tele["report_attempts"] == 2 and tele["report_next_ts"] == 1234.0
    # The file is still on disk, so the image record's own facts are untouched.
    assert state["img1"]["done"] is True and state["img1"]["copied"] is True
    assert state["img1"]["sha"] == "img1-sha"
    assert state["img1"]["root_file"] == "img1.bin"
    # An already-staged image needs a re-hash under the new transfer, because
    # _stage_image's steady-state short-circuit never re-hashes and a terminal
    # report is armed only on phase 'copied'/'seeding-only'. Consumed exactly
    # once (test_replan_verify.py owns the short-circuit itself).
    assert tele["replan_verify"] is True
    assert telemetry_report.take_replan_verify(state, "img1") is True
    assert telemetry_report.take_replan_verify(state, "img1") is False


def test_a_same_plan_id_with_a_new_transfer_id_is_still_a_boundary():
    """Equality of BOTH ids is the 'same' test. An identical plan_id carrying a
    different transfer_id can only be a server that re-minted, and that is a
    real boundary — treating it as steady would attest the new transfer with
    the old transfer's evidence."""
    state = {"img1": {"tele": {"plan_id": PLAN_A, "transfer_id": XFER_A,
                              "sample_seq": 4}}}
    assert telemetry_report.adopt_plan(state, "img1", PLAN_A, XFER_B) == "new"
    assert _tele(state) == {"plan_id": PLAN_A, "transfer_id": XFER_B}


def test_a_report_after_a_plan_boundary_carries_only_the_new_transfer_id():
    """The device-side half of the server's STRICT promotion match: a plan is
    promoted only by a report bearing ITS transfer_id, which is only safe
    because a report can never carry an id the current plan did not supply. A
    report gathered under plan A must therefore be unable to name plan B, and
    vice versa."""
    state = {"img1": {"done": True, "copied": True,
                      "tele": {"plan_id": PLAN_A, "transfer_id": XFER_A,
                               "content_sha256_state": "verified",
                               "started_ts": 1000.0, "done_ts": 1100.0}}}
    before = telemetry_report.build_report_v2(
        CFG, state, "img1", "staging-complete", 1200.0,
        telemetry_report.ensure_transfer_id(state, "img1"), "b" * 32)
    assert before["transfer_id"] == XFER_A

    telemetry_report.adopt_plan(state, "img1", PLAN_B, XFER_B)
    after = telemetry_report.build_report_v2(
        CFG, state, "img1", "staging-complete", 1300.0,
        telemetry_report.ensure_transfer_id(state, "img1"), "c" * 32)
    assert after["transfer_id"] == XFER_B
    # The previous transfer's verification did NOT ride along: the new plan is
    # attested by evidence gathered under the new plan, or by nothing.
    assert after["content_sha256"]["state"] == "not_checked"


def test_two_images_adopt_their_own_plans_independently():
    """One plan per (device, image). Two assigned images must not share, swap
    or overwrite each other's identity."""
    img2 = {"id": "img2", "filename": "img2.bin", "size": 7,
            "sha256": "img2-sha"}
    cat = PlanCatalog(["img1", "img2"],
                      plans={"img1": _plan(PLAN_A, XFER_A),
                             "img2": _plan(PLAN_B, XFER_B)},
                      images=(IMG, img2))
    state = {}
    deps, rec = make_deps(cat, {})
    iris_agent.run_once(CFG, deps, state)

    for img_id, plan_id, transfer_id in (("img1", PLAN_A, XFER_A),
                                         ("img2", PLAN_B, XFER_B)):
        assert _tele(state, img_id)["plan_id"] == plan_id
        assert _tele(state, img_id)["transfer_id"] == transfer_id
    assert sorted(_emits(rec, "REPLAN")) == sorted(
        ["img1 adopted plan %s" % PLAN_A, "img2 adopted plan %s" % PLAN_B])


# ---- a plan never materialises a record the device cannot retire ----

def test_a_plan_for_an_image_the_catalog_lacks_leaves_no_record():
    """Adoption sits BEHIND the catalog lookup and the filename whitelist, so
    a plan for an image this device cannot stage writes nothing at all.

    It used to run as a loop over the assigned ids, straight off the policy
    body — which wrote state[<id>]['tele'] for an id the agent had never
    resolved. 'tele' is one of iris_agent._IMAGE_ENTRY_FIELDS, so that bare
    {'tele': {...}} entry is indistinguishable from a real image record to
    everything downstream (see the companion test below for what that cost)."""
    cat = PlanCatalog(["img1", "ghost"],
                      plans={"img1": _plan(PLAN_A, XFER_A),
                             "ghost": _plan(PLAN_B, XFER_B)})
    state = {}
    deps, rec = make_deps(cat, {})

    assert iris_agent.run_once(CFG, deps, state) == "multi:downloading,no-image"

    # The stageable image adopted its plan exactly as before...
    assert _tele(state, "img1")["transfer_id"] == XFER_A
    assert _tele(state, "img1")["plan_id"] == PLAN_A
    # ...and the unstageable one left no trace to adopt anything into.
    assert "ghost" not in state
    assert _emits(rec, "REPLAN") == ["img1 adopted plan %s" % PLAN_A]
    # Belt and braces on the reason it matters: had a record been written, it
    # would have read as a genuine image record here.
    assert iris_agent._is_image_entry({"tele": {"transfer_id": XFER_B}})


def test_a_plan_for_an_unstageable_image_cannot_become_a_park_deferred_loop():
    """The failure the record above would have caused, pinned end to end.

    A phantom record has no 'root_file', and the catalog cannot name the file
    of an id it does not have — so the park pass could neither name nor retire
    it, and deliberately leaves such a record alone for the next tick to
    re-try. With nothing able to change that answer, the device emitted
    PARK-DEFERRED for a file that never existed on it, on every 60 s tick, for
    as long as the agent ran."""
    cat = PlanCatalog(["img1", "ghost"],
                      plans={"img1": _plan(PLAN_A, XFER_A),
                             "ghost": _plan(PLAN_B, XFER_B)})
    state = {}
    deps, _ = make_deps(cat, {})
    iris_agent.run_once(CFG, deps, state)

    # The operator drops the unstageable id from the assignment set.
    cat.ids = ["img1"]
    deps, rec = make_deps(cat, {"/stage/img1.bin": 2,
                                "/stage/img1.bin.aria2": 1})
    for _ in range(3):
        assert iris_agent.run_once(CFG, deps, state) == "downloading"

    assert _emits(rec, "PARK-DEFERRED") == []
    assert "ghost" not in state
    assert _tele(state, "img1")["transfer_id"] == XFER_A


def test_a_plan_boundary_carries_an_armed_report_but_never_its_attestation():
    """Board #44's data-loss half.

    A frozen, still-retrying terminal report is a finished statement about the
    PREVIOUS transfer -- it carries that transfer_id in its own body, so the
    server files it against the old plan. Nothing ever re-arms it once the
    image is done+copied (_stage_image takes the steady-state short-circuit),
    so dropping it at a plan boundary loses the old transfer's only completion
    evidence outright. That happens fleet-wide on the first tick after an agent
    upgrade, where every staged image crosses a boundary at once.

    What must NOT travel is the attestation: content_sha256_state 'verified'
    inherited across the boundary would claim this transfer hashed content it
    never touched.
    """
    old_plan, new_plan = "c" * 32, "d" * 32
    old_tid, new_tid = "a" * 32, "b" * 32
    state = {"img-a": {"done": True, "copied": True, "sha": "beef", "tele": {
        "plan_id": old_plan, "transfer_id": old_tid, "sample_seq": 7,
        "frozen_report": {"transfer_id": old_tid, "event": "staging-complete"},
        "report_pending": True, "report_attempts": 2, "report_next_ts": 1234.0,
        "avg_bps": 5e6, "content_sha256_state": "verified",
        "event": "staging-complete", "peers": {"10.0.0.1": 3}}}}

    assert telemetry_report.adopt_plan(
        state, "img-a", new_plan, new_tid) == "new"
    tele = state["img-a"]["tele"]

    # the retry loop (iris_agent.py:525-543) can still finish the delivery
    assert tele["report_pending"] is True
    assert tele["report_attempts"] == 2
    assert tele["report_next_ts"] == 1234.0
    assert tele["avg_bps"] == 5e6
    # and the body still names the transfer it actually describes
    assert tele["frozen_report"]["transfer_id"] == old_tid

    # the previous transfer's attestation and measurements do NOT travel
    for key in ("content_sha256_state", "sample_seq", "event", "peers"):
        assert key not in tele, key

    # identity is the new plan's
    assert tele["plan_id"] == new_plan
    assert tele["transfer_id"] == new_tid


def test_a_boundary_with_no_armed_report_carries_no_delivery_state():
    """The carry-over is scoped to a report still awaiting delivery; a report
    already sent (or never armed) leaves nothing behind to confuse the new
    transfer's telemetry."""
    old_plan, new_plan = "c" * 32, "d" * 32
    old_tid, new_tid = "a" * 32, "b" * 32
    state = {"img-a": {"done": True, "copied": True, "tele": {
        "plan_id": old_plan, "transfer_id": old_tid,
        "frozen_report": {"transfer_id": old_tid}, "report_pending": False,
        "content_sha256_state": "verified"}}}

    assert telemetry_report.adopt_plan(
        state, "img-a", new_plan, new_tid) == "new"
    tele = state["img-a"]["tele"]
    assert "frozen_report" not in tele
    assert "report_pending" not in tele
    assert "content_sha256_state" not in tele
