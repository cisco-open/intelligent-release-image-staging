# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The steady-state REPLAN RE-VERIFY (iris_agent._stage_image, the branch
guarded by telemetry_report.take_replan_verify).

THE GAP THIS PINS. An operator unassigns an image and re-assigns it; the
server mints a second plan with a second transfer_id; the device already has
the file staged AND placed. `_stage_image` short-circuits on the image
record's `done`/`copied` flags with phase 'steady', and `_telemetry_tick` arms
a terminal report only on phase 'copied'/'seeding-only' — so, with no fix, the
new transfer could NEVER produce a verified terminal report and the tracker's
`iris.transfer.lifecycle` plan would sit at `planned` forever while the bytes
it is waiting for sat on the device the whole time. `done`/`copied` live in
the IMAGE record, not in the telemetry bag, so adopt_plan's wholesale reset of
that bag structurally cannot reach them.

THE FIX AND ITS TWO EDGES. On a plan boundary for an already-staged image,
adopt_plan raises `tele['replan_verify']`; the short-circuit consumes it once,
re-hashes the staged file, and arms the report under the NEW transfer_id. The
two edges that matter are both asserted below: the hash must happen EXACTLY
once per boundary (a flag that survived its own consumption would re-hash a
~1.2 GB file every 60 s for the life of the assignment, which is precisely the
overlapping-hash failure the steady-state short-circuit exists to prevent),
and an ordinary steady tick must hash ZERO times (a fleet-wide accidental
re-hash would be the same outage arriving all at once).

WHY THE EVIDENCE IS RE-GATHERED RATHER THAN INHERITED. Accepting the previous
transfer's checksum would be cheaper and is exactly the thing this must not
do: it would attest one transfer with another transfer's verification. The
report armed here carries the NEW transfer_id and a content_sha256 state
computed under it — see
test_the_replan_report_carries_the_new_transfer_id_not_the_old_one.

Fakes are built locally rather than imported from test_iris_agent.py or
test_multi_image.py — the convention in this suite is that each module owns
its own Deps builder — but they mirror those modules' shapes."""

import time as _time

import iris_agent
import telemetry_report

# completion-jitter sleep is a module seam; never sleep in unit tests.
iris_agent._SLEEP = lambda s: None

CFG = {"device_id": "sw1", "stage_dir": "/stage",
       # far-future expiry so needs_refresh() skips the token refresh step
       "token_expires_at": str(int(_time.time()) + 604_800)}

IMG = "img-a"
STAGE = "/stage/img-a.bin"
SIZE = 5

# Server-minted ids: secrets.token_hex(16) shape, which is what adopt_plan
# validates against (_HEX32) and what the server re-validates at ingest.
PLAN_A = "1" * 32
TID_A = "a" * 32
PLAN_B = "2" * 32
TID_B = "b" * 32


def _plan(plan_id, transfer_id):
    """The device-visible projection of a policy `plans` row: the two ids and
    nothing else (planned_at and info_hash stay server-side)."""
    return {IMG: {"plan_id": plan_id, "transfer_id": transfer_id}}


class PlanCatalog:
    """Catalog serving the policy body the server grew for this feature: the
    ordered image set PLUS the per-image `plans` map the agent adopts."""

    def __init__(self, plans):
        self.plans = plans
        self.image = {"id": IMG, "filename": "img-a.bin", "size": SIZE,
                      "sha256": "img-a-sha"}
        self.heartbeats = []
        self.downloaded = []
        # A dict (not None) so record_failure never runs: a heartbeat-failure
        # streak would tip classify() to 'bad' and defer the report with
        # backoff, which has nothing to do with what these tests measure.
        self.hb_response = {}

    def get_policy(self, sid):
        return {"approved_image_id": IMG, "approved_image_ids": [IMG],
                "plans": self.plans}

    def get_image(self, image_id):
        return self.image if image_id == IMG else None

    def download_torrent(self, image_id, dest):
        self.downloaded.append((image_id, dest))

    def heartbeat(self, sid, data):
        self.heartbeats.append(data)
        return self.hb_response


class Verifier:
    """deps.verify with a call log and a settable answer, so a test can flip
    the staged file from good to corrupt between ticks."""

    def __init__(self, ok=True):
        self.ok = ok
        self.calls = []

    def __call__(self, path, sha):
        self.calls.append((path, sha))
        return self.ok


def make_deps(catalog, sizes, verifier, root_ok=True):
    """Fake Deps + a `rec` dict of everything the agent did to the device."""
    rec = {"emitted": [], "removed": [], "copied": [], "aria_added": []}

    def _remove_stage(path):
        rec["removed"].append(path)
        sizes.pop(path, None)             # reflect the delete in future file_size()

    def _copy_to_root(fname, target_prefix="flash:", expected_size=None):
        rec["copied"].append(fname)
        return True

    deps = iris_agent.Deps(
        catalog=catalog,
        emit=lambda m, msg: rec["emitted"].append((m, msg)),
        boot_image=lambda: "running.bin",
        aria_add=lambda t, d: rec["aria_added"].append((t, d)),
        file_size=lambda p: sizes.get(p),
        verify=verifier,
        free_bytes=lambda prefix="flash:": 9_000_000_000,
        version=lambda: "17.18.03",
        copy_to_root=_copy_to_root,
        purge_others=lambda keep, kid: None,
        reclaim=lambda: None,
        root_present=lambda fname, prefix="flash:", expected_size=None: root_ok,
        remove_stage=_remove_stage,
        aria_remove=lambda fname: None,
        detect_mode=lambda: "bundle",
        target_fs=lambda: ("flash:", 9_000_000_000),
        running_image=lambda: "running.bin",
        reclaimable=lambda prefix, protect: [],
        reclaim_bundle=lambda prefix, names: None,
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


def _tele(state):
    return state[IMG]["tele"]


def _staged_under_plan_a():
    """Drive the image to fully staged (done AND copied) under plan A, then
    hand back everything a replan test needs. The staging tick itself is the
    ONE legitimate hash, and it is cleared from the log here so every later
    assertion counts only re-hashes."""
    cat = PlanCatalog(_plan(PLAN_A, TID_A))
    sizes = {STAGE: SIZE}
    verifier = Verifier()
    deps, rec = make_deps(cat, sizes, verifier)
    state = {}

    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert state[IMG]["done"] and state[IMG]["copied"]
    assert _tele(state)["transfer_id"] == TID_A
    assert len(verifier.calls) == 1          # the download path's own hash
    verifier.calls.clear()
    rec["emitted"].clear()
    return cat, deps, rec, state, verifier, sizes


# --- the fix ------------------------------------------------------------

def test_a_new_plan_on_an_already_staged_image_rehashes_once_and_arms_a_terminal_report():
    cat, deps, rec, state, verifier, _sizes = _staged_under_plan_a()

    # The operator unassigned and re-assigned: a SECOND plan for the same
    # (device, image), with a second transfer_id.
    cat.plans = _plan(PLAN_B, TID_B)
    assert iris_agent.run_once(CFG, deps, state) == "complete"

    # Exactly one re-hash, of the staged file, against the catalog sha.
    assert verifier.calls == [(STAGE, cat.image["sha256"])]
    tele = _tele(state)
    assert tele["transfer_id"] == TID_B
    assert tele["plan_id"] == PLAN_B
    assert tele["content_sha256_state"] == "verified"
    # The terminal report is ARMED under the new transfer — the whole point of
    # the fix. It stays pending because this fake catalog has no
    # post_telemetry (a quiet no-send), which is irrelevant to arming.
    assert tele["event"] == "staging-complete"
    assert tele["report_pending"] is True
    assert _emits(rec, "REPLAN")            # the boundary was announced
    assert _emits(rec, "REPLAN-VERIFY")     # and so was the re-verification
    # The file itself was never touched: a replan is not a re-download.
    assert rec["removed"] == []
    assert rec["aria_added"] == []
    assert state[IMG]["done"] and state[IMG]["copied"]


def test_the_replan_report_carries_the_new_transfer_id_not_the_old_one():
    """The evidence must be gathered UNDER the new transfer, never inherited.

    The frozen report is the artefact the server actually promotes a plan on,
    and the server matches it to a plan by transfer_id alone: a report bearing
    any other id attests nothing about this plan. So the id on the frozen body
    is the load-bearing assertion, not the id sitting in the state bag."""
    cat, deps, rec, state, verifier, _sizes = _staged_under_plan_a()

    cat.plans = _plan(PLAN_B, TID_B)
    iris_agent.run_once(CFG, deps, state)

    frozen = telemetry_report.frozen_report(state, IMG)
    assert frozen is not None
    assert frozen["transfer_id"] == TID_B
    assert frozen["transfer_id"] != TID_A
    assert frozen["event"] == "staging-complete"
    assert frozen["image_id"] == IMG


def test_the_replan_verify_flag_is_consumed_and_the_next_tick_does_not_rehash():
    """One hash per boundary, not one per tick.

    take_replan_verify POPS the flag, so a ~1.2 GB image is re-hashed once and
    then never again while the plan stands. A flag that survived would put a
    multi-minute hash on every 60 s tick — the overlapping-run failure the
    steady-state short-circuit exists to prevent."""
    cat, deps, rec, state, verifier, _sizes = _staged_under_plan_a()

    cat.plans = _plan(PLAN_B, TID_B)
    for _ in range(3):
        assert iris_agent.run_once(CFG, deps, state) == "complete"

    assert len(verifier.calls) == 1
    assert "replan_verify" not in _tele(state)
    assert len(_emits(rec, "REPLAN-VERIFY")) == 1
    # Only the FIRST of the three ticks crossed a boundary; the other two saw
    # the same plan and adopt_plan answered 'same'.
    assert len(_emits(rec, "REPLAN")) == 1


def test_a_replan_verify_mismatch_discards_the_stage_and_never_arms_a_report():
    """A failed re-hash is a decision, not a retry.

    The bytes on disk do not match the catalog, whatever the previous transfer
    believed, so the staged copy goes and both flags are lowered — the next
    tick falls out of the short-circuit and re-acquires. Nothing is attested:
    arming a terminal report here would tell the server a transfer completed
    on content the device just discarded."""
    cat, deps, rec, state, verifier, _sizes = _staged_under_plan_a()

    verifier.ok = False                     # the staged file went bad
    cat.plans = _plan(PLAN_B, TID_B)
    assert iris_agent.run_once(CFG, deps, state) == "bad-sha"

    assert len(verifier.calls) == 1
    tele = _tele(state)
    assert tele["content_sha256_state"] == "mismatch"
    assert tele.get("event") is None
    # No report is armed FOR THIS transfer: 'event' is unset and the body still
    # awaiting delivery is the PREVIOUS transfer's, carried across the boundary
    # by adopt_plan (board #44) and naming TID_A, not TID_B. Plan A really did
    # complete and verify; plan B's failed re-hash does not retract that.
    assert tele["frozen_report"]["transfer_id"] == TID_A
    assert tele["frozen_report"].get("content_sha256", {}).get(
        "state") == "verified"
    assert state[IMG]["done"] is False
    assert state[IMG]["copied"] is False
    assert rec["removed"] == [STAGE]
    assert _emits(rec, "ERROR")
    assert _emits(rec, "REPLAN-VERIFY") == []


def test_a_mismatch_does_not_rehash_again_on_the_following_tick():
    """The flag was popped BEFORE the hash ran, so a corrupt file cannot pin
    the device to a hash-per-tick loop for the life of the assignment."""
    cat, deps, rec, state, verifier, _sizes = _staged_under_plan_a()

    verifier.ok = False
    cat.plans = _plan(PLAN_B, TID_B)
    assert iris_agent.run_once(CFG, deps, state) == "bad-sha"
    verifier.calls.clear()

    # Next tick: done/copied are down, so this is the ordinary re-acquire
    # path, not another trip through the replan branch.
    iris_agent.run_once(CFG, deps, state)
    assert "replan_verify" not in _tele(state)


# --- the guard on the other side ---------------------------------------

def test_steady_state_without_a_replan_flag_never_rehashes():
    """The fleet-wide guard. An ordinary steady tick — same plan, image
    already staged and placed — must hash ZERO times; the short-circuit's
    whole reason for existing is that hashing a 1.2 GB image takes longer than
    the 60 s timer and the overlapping runs double-fired the root copy."""
    cat, deps, rec, state, verifier, _sizes = _staged_under_plan_a()

    for _ in range(3):
        assert iris_agent.run_once(CFG, deps, state) == "complete"

    assert verifier.calls == []
    assert _emits(rec, "REPLAN-VERIFY") == []
    assert _emits(rec, "REPLAN") == []
    # The steady tick leaves the transfer identity exactly as adopted.
    assert _tele(state)["transfer_id"] == TID_A
    assert _tele(state)["plan_id"] == PLAN_A


def test_a_server_that_sends_no_plans_never_rehashes_a_staged_image():
    """Back-compat: an older server's two-key policy body reaches adopt_plan
    with nothing to adopt, so no boundary is ever crossed and the steady-state
    short-circuit behaves byte-for-byte as it did before this feature."""
    cat = PlanCatalog(_plan(PLAN_A, TID_A))
    sizes = {STAGE: SIZE}
    verifier = Verifier()
    deps, rec = make_deps(cat, sizes, verifier)
    state = {}
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    verifier.calls.clear()

    # The policy body loses its plans map entirely (old server / legacy row).
    cat.plans = {}
    for _ in range(2):
        assert iris_agent.run_once(CFG, deps, state) == "complete"

    assert verifier.calls == []
    assert _emits(rec, "REPLAN-VERIFY") == []


def test_a_replan_on_an_image_that_is_not_yet_staged_arms_no_extra_hash():
    """replan_verify is raised ONLY when the image is already done AND copied.
    A plan boundary crossed mid-download has nothing to re-verify: the ordinary
    download path will hash the file once when it completes, and raising the
    flag as well would hash it twice."""
    cat = PlanCatalog(_plan(PLAN_A, TID_A))
    sizes = {}                              # nothing staged yet
    verifier = Verifier()
    deps, rec = make_deps(cat, sizes, verifier)
    state = {}

    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    assert verifier.calls == []
    assert "replan_verify" not in _tele(state)

    # The operator replans while the download is still in flight.
    cat.plans = _plan(PLAN_B, TID_B)
    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    assert "replan_verify" not in _tele(state)
    assert verifier.calls == []

    # aria2c finishes; the download path hashes exactly once, under plan B.
    sizes[STAGE] = SIZE
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert len(verifier.calls) == 1
    assert _tele(state)["transfer_id"] == TID_B


# --- the flag must not outlive the bytes it was raised over -------------

def test_a_stale_replan_flag_is_dropped_when_the_staged_file_is_gone():
    """replan_verify is a one-shot permission to hash content that is SITTING
    RIGHT THERE, and it must not survive a re-acquisition.

    adopt_plan raises the flag on the image record's `done`/`copied` flags,
    which are what this record last BELIEVED — not a stat. The park pass
    leaves both set while deleting the staged copy (it keeps only the root
    copy), so a park-then-replan raises the flag over a file the device no
    longer has. Left in the bag, the flag rides through the whole ~1.2 GB
    re-download and fires the tick AFTER the download path's own verify()
    already hashed those very bytes under that very transfer_id: a second
    multi-minute pass that can only agree with the first. The re-acquire
    fall-through drops it instead."""
    cat, deps, rec, state, verifier, sizes = _staged_under_plan_a()

    # The staged file is gone while done/copied still read true — exactly what
    # a park leaves behind — and the operator's re-assignment mints plan B.
    sizes.pop(STAGE)
    cat.plans = _plan(PLAN_B, TID_B)

    # Tick 1: the short-circuit's self-heal sees the missing file and
    # re-acquires. Nothing is hashed, and the flag does not ride along.
    assert iris_agent.run_once(CFG, deps, state) == "downloading"
    assert verifier.calls == []
    assert "replan_verify" not in _tele(state)
    assert _emits(rec, "RECHECK")
    assert _emits(rec, "REPLAN-VERIFY") == []
    assert rec["aria_added"], "the re-download never started"

    # Tick 2: the re-download lands. The ORDINARY download path hashes it
    # once and arms the terminal report under the new transfer_id, so the
    # dropped flag cost the plan no attestation whatsoever.
    sizes[STAGE] = SIZE
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert len(verifier.calls) == 1
    assert _tele(state)["transfer_id"] == TID_B
    assert _tele(state)["event"] == "staging-complete"

    # Tick 3: a surviving flag would have fired HERE, re-reading the whole
    # image to re-confirm what tick 2 confirmed under the same transfer_id.
    assert iris_agent.run_once(CFG, deps, state) == "complete"
    assert len(verifier.calls) == 1
    assert _emits(rec, "REPLAN-VERIFY") == []


def test_the_park_pass_clears_a_replan_flag_along_with_the_transfer():
    """The durability net for the same stale flag.

    A raise and its consume normally happen inside one _stage_image call, but
    state is checkpointed only at a few points in a tick, so a process killed
    between them can persist the flag. If the image then leaves the set, park
    deletes the staged copy and there is nothing left to hash — so park drops
    the flag exactly where it drops the transfer identity. plan_id survives
    both, and is harmless: adopt_plan compares BOTH ids, and the transfer_id
    it needs to match is now gone, so the next assignment is a boundary."""
    state = {IMG: {"done": True, "copied": True, "sha": "img-a-sha",
                   "root_file": "img-a.bin",
                   "tele": {"plan_id": PLAN_A, "transfer_id": TID_A,
                            "replan_verify": True}}}
    cat = PlanCatalog(_plan(PLAN_A, TID_A))
    deps, rec = make_deps(cat, {STAGE: SIZE}, Verifier())

    iris_agent._reconcile_set(deps, state, [], "/stage")

    assert state[IMG]["parked"] is True
    tele = state[IMG]["tele"]
    assert "replan_verify" not in tele
    assert "transfer_id" not in tele
    assert tele["plan_id"] == PLAN_A
    assert telemetry_report.adopt_plan(state, IMG, PLAN_A, TID_A) == "new"
