# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""The durable plan state machine: planned -> seeding, emitted exactly once.

These tests drive the real pipeline the tracker drives -- policy.json through
``live_plans_from_policy``, the device's report ring through
``verified_facts``, the peer registry snapshot through ``seeder_facts``, and
all three into ``TransferLifecycle.observe`` -- rather than hand-building rows,
so a change to any one of those pure functions surfaces here as a promotion
that stops happening rather than as a passing test over invented data.

The clock is always injected. Every timestamp this module latches is compared,
floored, or pruned against another, so a test that let the wall clock in would
be asserting on arithmetic it does not control.
"""
import json
import os

import transfer_lifecycle


IH = "a" * 40
OTHER_IH = "b" * 40
IMAGE = "cat9k_iosxe.17.15.01.SPA.bin"
OTHER_IMAGE = "cat9k_iosxe.17.12.04.SPA.bin"
DEV = "sw-lab-01"


def _id(n):
    """A well-formed id. Both ids are 32 lowercase hex on the wire -- the
    device echoes transfer_id back on every report and both ingest paths
    re-validate the shape -- so the tests use ids that would survive that."""
    return "%032x" % n


PLAN_A = _id(0xa1)
XFER_A = _id(0xa2)
PLAN_B = _id(0xb1)
XFER_B = _id(0xb2)


class Clock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def tick(self, seconds=30.0):
        self.now += seconds
        return self.now


def _store(tmp_path, clock=None, name="state"):
    directory = os.path.join(str(tmp_path), name)
    return transfer_lifecycle.TransferLifecycle(directory,
                                                now_fn=clock or Clock())


def _policy(plans=((IMAGE, PLAN_A, XFER_A),), device_id=DEV,
            planned_at=1000.0, info_hash=IH):
    """policy.json exactly as CatalogStore.set_policy writes it."""
    ids = [image_id for image_id, _, _ in plans]
    return {device_id: {
        "approved_image_id": ids[0] if ids else None,
        "approved_image_ids": ids,
        "plans": {image_id: {"plan_id": plan_id,
                             "transfer_id": transfer_id,
                             "planned_at": planned_at,
                             "info_hash": info_hash}
                  for image_id, plan_id, transfer_id in plans}}}


def _report(transfer_id=XFER_A, image_id=IMAGE, event="staging-complete",
            state="verified", received_at=1300.0, window_end=1290.0,
            report_created_at=None):
    """One v2 terminal report as the catalog stores it in telemetry.json.

    ``report_created_at`` is the DEVICE's own clock for composing the report
    and defaults just after the window end, the way a real agent writes it;
    ``received_at`` is the SERVER's ingest clock and is deliberately a
    different number, because the gap between them is the whole point of
    exporting both."""
    return {"image_id": image_id,
            "transfer_id": transfer_id,
            "event": event,
            "content_sha256": {"algo": "sha256", "state": state},
            "window": {"start": window_end - 60.0, "end": window_end},
            "report_created_at": (window_end + 1.0
                                  if report_created_at is None
                                  else report_created_at),
            "received_at": received_at}


def _ring(*reports, **kwargs):
    return {kwargs.get("device_id", DEV): list(reports)}


def _ledger(*reports, **kwargs):
    """The catalog's durable attestation ledger for a device, built the way
    CatalogStore._remember_attestation builds it -- through the one shared
    rule, so a test cannot invent a ledger row the ingest path would not
    write."""
    rows = [transfer_lifecycle.attestation_from_report(rep)
            for rep in reports]
    return {kwargs.get("device_id", DEV): [r for r in rows if r is not None]}


def _swarm(device_id=DEV, info_hash=IH, completed_at=1200.0, last_seen=1205.0,
           is_seeder=True, principal_type="device"):
    """One PeerRegistry.snapshot() row, field for field."""
    return {info_hash: [{"ip": "10.0.0.7", "port": 6881,
                         "left": 0 if is_seeder else 12345,
                         "last_seen": last_seen,
                         "is_seeder": is_seeder,
                         "joined_at": 1100.0,
                         "completed_at": completed_at,
                         "principal_type": principal_type,
                         "principal_id": device_id,
                         "participant_class": "device",
                         "download_seconds": 100.0}]}


def _images(image_id=IMAGE, info_hash=IH):
    return {image_id: {"info_hash_hex": info_hash}}


def _observe(store, policy, reports=None, snapshot=None, images=None,
             now=None, attestations=None):
    """One tracker pass: the three pure functions, then the store."""
    live = transfer_lifecycle.live_plans_from_policy(policy)
    verified = transfer_lifecycle.verified_facts(live, reports or {},
                                                 attestations or {})
    seeder = transfer_lifecycle.seeder_facts(live, snapshot or {},
                                             images or {}, now=now)
    return store.observe(live, verified, seeder, now=now)


def _events(store):
    return [(plan_id, event) for plan_id, _, event in
            store.pending_emissions()]


# --- promotion ------------------------------------------------------------


def test_promotion_requires_all_three_preconditions(tmp_path):
    """Complete content, a verified checksum, and this tracker seeing the
    device itself seed.

    The first two arrive together and cannot be separated: a terminal report
    is structurally reachable on the device only after the staged file passed
    the size check with no .aria2 control file left and was then hashed, so
    one verified terminal report carries both. The third is the tracker's own
    authenticated observation, which the device can neither see nor claim.
    Any one of them missing leaves the plan at 'planned'.
    """
    clock = Clock()
    store = _store(tmp_path, clock)
    policy = _policy()

    # Nothing observed at all.
    assert _observe(store, policy, now=clock.now) == []
    assert store.get(PLAN_A)["state"] == "planned"

    # The tracker sees it seed, but nobody has attested a checksum. This is
    # the multi-minute window where aria2 already announces left=0 and the
    # agent's sha256 of a ~1.2 GB image has not run yet.
    clock.tick()
    assert _observe(store, policy, snapshot=_swarm(), images=_images(),
                    now=clock.now) == []
    row = store.get(PLAN_A)
    assert row["state"] == "planned"
    assert row["tracker_seeder_at"] == 1200.0
    assert row["checksum_verified_at"] is None
    assert store.stats()["plans_awaiting_report"] == 1

    # The report lands. Both latches are now present, so the plan promotes.
    clock.tick()
    assert _observe(store, policy, reports=_ring(_report()),
                    snapshot=_swarm(), images=_images(),
                    now=clock.now) == [PLAN_A]
    row = store.get(PLAN_A)
    assert row["state"] == "seeding"
    assert row["checksum_verified_at"] == 1300.0
    assert row["seeding_started_at"] == 1300.0
    assert row["observed_at"] == 1290.0
    assert store.stats()["plans_awaiting_report"] == 0


def test_a_verified_report_without_a_tracker_seeder_never_promotes(tmp_path):
    """A device can attest its own checksum; it cannot attest that this
    tracker ever saw it serve a byte. Without the swarm row the plan stays
    planned however many passes go by."""
    clock = Clock()
    store = _store(tmp_path, clock)
    policy = _policy()
    for _ in range(3):
        clock.tick()
        assert _observe(store, policy, reports=_ring(_report()),
                        images=_images(), now=clock.now) == []
    row = store.get(PLAN_A)
    assert row["state"] == "planned"
    assert row["checksum_verified_at"] == 1300.0
    assert row["tracker_seeder_at"] is None


def test_a_mismatch_report_never_promotes(tmp_path):
    """content_sha256.state is the whole of preconditions 1+2. A report whose
    hash did not match is proof the content is WRONG, and must never be read
    as proof the transfer completed."""
    clock = Clock()
    store = _store(tmp_path, clock)
    assert _observe(store, _policy(),
                    reports=_ring(_report(state="mismatch")),
                    snapshot=_swarm(), images=_images(),
                    now=clock.now) == []
    row = store.get(PLAN_A)
    assert row["state"] == "planned"
    assert row["checksum_verified_at"] is None
    assert row["tracker_seeder_at"] == 1200.0


def test_a_pull_event_report_never_promotes(tmp_path):
    """'pull' is a console-requested snapshot of whatever the device happens
    to hold, not a completion claim, so it attests nothing -- even carrying
    the plan's own transfer_id and a verified checksum."""
    clock = Clock()
    store = _store(tmp_path, clock)
    assert _observe(store, _policy(),
                    reports=_ring(_report(event="pull")), snapshot=_swarm(),
                    images=_images(), now=clock.now) == []
    assert store.get(PLAN_A)["checksum_verified_at"] is None


def test_a_report_bearing_another_transfers_id_never_promotes(tmp_path):
    """The binding is STRICT and transfer-scoped: only a report carrying this
    plan's own transfer_id attests it.

    A report from an agent that minted its own id -- one too old to adopt the
    server's plan -- proves a checksum for a DIFFERENT transfer. Promoting on
    it would publish 'seeding' on the strength of a hash computed for other
    work, which is the one guarantee this module exists to make. Such a plan
    emits 'planned' and then stays silent; silence is the honest answer.
    """
    clock = Clock()
    store = _store(tmp_path, clock)
    foreign = _report(transfer_id=_id(0xdead))
    assert _observe(store, _policy(), reports=_ring(foreign),
                    snapshot=_swarm(), images=_images(),
                    now=clock.now) == []
    row = store.get(PLAN_A)
    assert row["state"] == "planned"
    assert row["checksum_verified_at"] is None
    # It never promotes, no matter how many passes run.
    for _ in range(3):
        clock.tick()
        assert _observe(store, _policy(), reports=_ring(foreign),
                        snapshot=_swarm(), images=_images(),
                        now=clock.now) == []
    assert store.get(PLAN_A)["state"] == "planned"
    assert _events(store) == [(PLAN_A, "planned")]


def test_a_report_for_another_image_never_promotes(tmp_path):
    """Both halves of the join matter. A report for a different image, even on
    the right device with a verified checksum, attests nothing about this
    plan."""
    clock = Clock()
    store = _store(tmp_path, clock)
    assert _observe(store, _policy(),
                    reports=_ring(_report(image_id=OTHER_IMAGE)),
                    snapshot=_swarm(), images=_images(),
                    now=clock.now) == []
    assert store.get(PLAN_A)["checksum_verified_at"] is None


def test_the_seeder_fact_requires_the_authenticated_device_principal(tmp_path):
    """Precondition 3 is an AUTHENTICATED observation.

    The announce token baked into the device's personalised torrent resolves
    to Principal("device", <device_id>), and that id is the catalog's own
    device id. A legacy-token announce resolves to Principal("legacy", ...)
    and proves no identity; another device's row proves the wrong identity;
    is_seeder false means the peer still has bytes left. None of them latch.
    """
    clock = Clock()
    for name, snapshot in (
            ("legacy", _swarm(principal_type="legacy")),
            ("other-device", _swarm(device_id="sw-lab-99")),
            ("leecher", _swarm(is_seeder=False))):
        store = _store(tmp_path, clock, name=name)
        assert _observe(store, _policy(), reports=_ring(_report()),
                        snapshot=snapshot, images=_images(),
                        now=clock.now) == []
        assert store.get(PLAN_A)["tracker_seeder_at"] is None
        assert store.get(PLAN_A)["state"] == "planned"


# --- latches --------------------------------------------------------------


def test_latches_are_first_write_wins(tmp_path):
    """Both facts latch at the FIRST observation and never move afterwards.

    A device that reconnects gets a fresh aria2 peer_id and therefore a fresh
    registry row with a later completed_at, and a device that keeps reporting
    keeps stamping later received_at values. Neither may rewrite history: the
    honest answer is the first moment the fact was true.
    """
    clock = Clock()
    store = _store(tmp_path, clock)
    policy = _policy()
    _observe(store, policy, reports=_ring(_report()), snapshot=_swarm(),
             images=_images(), now=clock.now)
    first = store.get(PLAN_A)

    clock.tick()
    _observe(store, policy,
             reports=_ring(_report(received_at=9000.0, window_end=8990.0)),
             snapshot=_swarm(completed_at=9100.0, last_seen=9105.0),
             images=_images(), now=clock.now)
    again = store.get(PLAN_A)
    assert again["checksum_verified_at"] == first["checksum_verified_at"]
    assert again["tracker_seeder_at"] == first["tracker_seeder_at"]
    assert again["observed_at"] == first["observed_at"]
    assert again["seeding_started_at"] == first["seeding_started_at"]


def test_the_earliest_attesting_report_in_the_ring_is_the_one_latched(
        tmp_path):
    """The ring holds several reports for one transfer. Latching the EARLIEST
    keeps the latched value independent of how much of the ring a given pass
    happens to see, which is what makes first-write-wins stable across a
    restart that reads a longer ring."""
    clock = Clock()
    store = _store(tmp_path, clock)
    ring = _ring(_report(received_at=1700.0, window_end=1690.0),
                 _report(received_at=1300.0, window_end=1290.0),
                 _report(received_at=1500.0, window_end=1490.0))
    _observe(store, _policy(), reports=ring, snapshot=_swarm(),
             images=_images(), now=clock.now)
    row = store.get(PLAN_A)
    assert row["checksum_verified_at"] == 1300.0
    assert row["observed_at"] == 1290.0


def test_seeding_started_at_is_the_later_of_the_two_latches_floored_at_planned_at(
        tmp_path):
    """seeding_started_at is the instant the LAST precondition became true,
    floored at the plan's own creation.

    The floor exists so a dashboard can never render a negative
    planned->seeding duration from a report or an announce that predates the
    assignment -- a re-assignment of an image the device already held. There
    is deliberately no upper clamp to 'now': clamping against a live clock
    would make a crash-replay emit a different timestamp under an identical
    event.id.
    """
    clock = Clock()

    # The report is the last fact to arrive.
    late_report = _store(tmp_path, clock, name="late-report")
    _observe(late_report, _policy(), reports=_ring(_report(received_at=1400.0)),
             snapshot=_swarm(completed_at=1200.0), images=_images(),
             now=clock.now)
    assert late_report.get(PLAN_A)["seeding_started_at"] == 1400.0

    # The announce is the last fact to arrive.
    late_seed = _store(tmp_path, clock, name="late-seed")
    _observe(late_seed, _policy(), reports=_ring(_report(received_at=1400.0)),
             snapshot=_swarm(completed_at=1800.0), images=_images(),
             now=clock.now)
    assert late_seed.get(PLAN_A)["seeding_started_at"] == 1800.0

    # The attesting report predates the plan: floored at planned_at, never
    # negative. The registry row predates it too, so it is not this plan's
    # evidence at all and the pass's own observation stands in (see
    # seeder_facts) -- which is why the seeder fact is exactly `now` here.
    floored = _store(tmp_path, clock, name="floored")
    _observe(floored, _policy(planned_at=5000.0),
             reports=_ring(_report(received_at=1400.0)),
             snapshot=_swarm(completed_at=1200.0), images=_images(),
             now=5000.0)
    row = floored.get(PLAN_A)
    assert row["tracker_seeder_at"] == 5000.0
    assert row["seeding_started_at"] == 5000.0
    assert row["seeding_started_at"] - row["planned_at"] == 0.0


def test_a_report_evicted_from_the_ring_still_promotes_from_the_ledger(
        tmp_path):
    """The catalog's report ring is FIVE entries per DEVICE, shared by every
    image assigned to it and every report kind, while the tracker reads it at
    most once per sample pass. A device finishing several images inside one
    agent tick pushes the earliest terminal report out before any pass sees
    it, and that fact used to be derivable from nowhere else: the plan latched
    its seeder observation, never its checksum, and sat at `planned` with no
    seeding_started ever emitted, forever.

    The catalog records the attestation at INGEST, keyed per transfer, so it
    outlives the ring. Here plan A's report has already rotated out behind
    five later ones and only the ledger still carries it.
    """
    clock = Clock()
    policy = _policy(plans=((IMAGE, PLAN_A, XFER_A),
                            (OTHER_IMAGE, PLAN_B, XFER_B)))
    evicted = _report(received_at=1300.0, window_end=1290.0)
    later = [_report(transfer_id=XFER_B, image_id=OTHER_IMAGE,
                     received_at=1300.0 + n, window_end=1290.0 + n)
             for n in range(1, 6)]
    ring = _ring(*later)                        # the five that survived
    assert len(ring[DEV]) == 5

    # Without the ledger the fact is gone: the ring no longer holds it.
    ringonly = _store(tmp_path, clock, name="ring-only")
    _observe(ringonly, policy, reports=ring, snapshot=_swarm(),
             images=_images(), now=clock.now)
    assert ringonly.get(PLAN_A)["checksum_verified_at"] is None
    assert ringonly.get(PLAN_A)["state"] == "planned"
    assert ringonly.stats()["plans_awaiting_report"] == 1

    # With it, the plan promotes on the instant the catalog took the report
    # in -- the same value the ring would have carried.
    store = _store(tmp_path, clock, name="ledger")
    _observe(store, policy, reports=ring, snapshot=_swarm(),
             images=_images(), attestations=_ledger(evicted), now=clock.now)
    row = store.get(PLAN_A)
    assert row["checksum_verified_at"] == 1300.0
    assert row["observed_at"] == 1290.0
    assert row["state"] == "seeding"
    assert store.stats()["plans_awaiting_report"] == 0


def test_the_ring_and_the_ledger_are_folded_by_one_rule_earliest_wins(
        tmp_path):
    """Two sources, one binding. The ledger is read ALONGSIDE the ring, never
    instead of it -- a state directory written before the ledger existed, or a
    ledger write that failed after the ring write succeeded, must still
    promote. Whichever source carries the earliest attesting instant is the
    one latched, because the store latches first-write-wins and the value must
    not depend on which source a given pass happened to see."""
    clock = Clock()

    ledger_first = _store(tmp_path, clock, name="ledger-first")
    _observe(ledger_first, _policy(),
             reports=_ring(_report(received_at=1700.0, window_end=1690.0)),
             attestations=_ledger(_report(received_at=1300.0,
                                          window_end=1290.0)),
             snapshot=_swarm(), images=_images(), now=clock.now)
    assert ledger_first.get(PLAN_A)["checksum_verified_at"] == 1300.0
    assert ledger_first.get(PLAN_A)["observed_at"] == 1290.0

    ring_first = _store(tmp_path, clock, name="ring-first")
    _observe(ring_first, _policy(),
             reports=_ring(_report(received_at=1300.0, window_end=1290.0)),
             attestations=_ledger(_report(received_at=1700.0,
                                          window_end=1690.0)),
             snapshot=_swarm(), images=_images(), now=clock.now)
    assert ring_first.get(PLAN_A)["checksum_verified_at"] == 1300.0

    # An absent ledger is not an error: the ring alone still promotes.
    no_ledger = _store(tmp_path, clock, name="no-ledger")
    _observe(no_ledger, _policy(), reports=_ring(_report()),
             snapshot=_swarm(), images=_images(), now=clock.now)
    assert no_ledger.get(PLAN_A)["state"] == "seeding"


def test_the_ledger_obeys_the_same_strict_binding_as_the_ring(tmp_path):
    """The durable ledger is not a shortcut past the transfer-scoped binding.
    A row for another transfer or another image attests nothing, and a row
    whose ids or instant will not coerce is dropped rather than allowed to
    promote a plan on a value nothing can subtract."""
    clock = Clock()
    store = _store(tmp_path, clock)
    junk = {DEV: [{"transfer_id": XFER_B, "image_id": IMAGE,
                   "received_at": 1300.0},        # another transfer
                  {"transfer_id": XFER_A, "image_id": OTHER_IMAGE,
                   "received_at": 1300.0},        # another image
                  {"transfer_id": "not-hex", "image_id": IMAGE,
                   "received_at": 1300.0},        # malformed id
                  {"transfer_id": XFER_A, "image_id": IMAGE,
                   "received_at": "soon"},        # uncoercible instant
                  "not-a-dict"]}
    _observe(store, _policy(), snapshot=_swarm(), images=_images(),
             attestations=junk, now=clock.now)
    assert store.get(PLAN_A)["checksum_verified_at"] is None
    assert store.get(PLAN_A)["state"] == "planned"


def test_a_non_attesting_report_yields_no_attestation(tmp_path):
    """attestation_from_report is the ONE place the rule lives, and the ingest
    path writes exactly what it returns. A pull snapshot is not a completion
    claim, a mismatch is not a verification, and a report with no transfer id
    binds to no plan."""
    for rep in (_report(event="pull"),
                _report(state="mismatch"),
                _report(state="pending"),
                _report(transfer_id="nope"),
                {"event": "staging-complete"},
                "not-a-dict"):
        assert transfer_lifecycle.attestation_from_report(rep) is None, rep
    fact = transfer_lifecycle.attestation_from_report(
        _report(received_at=1300.0, window_end=1290.0,
                report_created_at=1291.5))
    assert fact == {"transfer_id": XFER_A, "image_id": IMAGE,
                    "received_at": 1300.0, "observed_at": 1290.0,
                    "report_created_at": 1291.5}
    # seeding-only is terminal too: a flash-full transfer is complete and
    # verified even though it never reached the flash root.
    assert transfer_lifecycle.attestation_from_report(
        _report(event="seeding-only")) is not None


def test_the_devices_own_report_instant_is_latched_beside_the_ingest_instant(
        tmp_path):
    """checksum_verified_at is an INGEST instant -- when the SERVER took the
    attesting report in, not when the device verified. The device reports no
    verification instant, so none is invented; what is latched beside it is
    the device's own report_created_at, on the device's clock, so the delivery
    lag folded into a plan-to-seed duration is visible instead of silently
    read as transfer time. The agent defers a whole report on a bad link with
    a backoff reaching ~16 minutes, which is what that gap is here."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(),
             reports=_ring(_report(received_at=2260.0, window_end=1290.0,
                                   report_created_at=1300.0)),
             snapshot=_swarm(), images=_images(), now=clock.now)
    row = store.get(PLAN_A)
    assert row["checksum_verified_at"] == 2260.0    # server ingest
    assert row["report_created_at"] == 1300.0       # device clock
    assert row["observed_at"] == 1290.0             # device clock
    # Latched together and first-write-wins, like every other fact here.
    clock.tick()
    _observe(store, _policy(),
             reports=_ring(_report(received_at=3000.0, window_end=2900.0,
                                   report_created_at=2910.0)),
             snapshot=_swarm(), images=_images(), now=clock.now)
    assert store.get(PLAN_A)["report_created_at"] == 1300.0
    # A report that carried no device instant latches None, never a stand-in.
    bare = _report(received_at=1300.0)
    del bare["report_created_at"]
    other = _store(tmp_path, clock, name="bare")
    _observe(other, _policy(), reports=_ring(bare), snapshot=_swarm(),
             images=_images(), now=clock.now)
    assert other.get(PLAN_A)["report_created_at"] is None


def test_the_seeder_fact_falls_back_from_completed_at_to_last_seen(tmp_path):
    """completed_at is the registry's own latch for 'the moment left first hit
    0 this cycle'. A row that has been re-stamped without one -- a tracker
    restart re-observing an already-complete peer -- still proves the device
    is seeding now, so last_seen stands in rather than the fact being lost."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), snapshot=_swarm(completed_at=None,
                                              last_seen=1234.0),
             images=_images(), now=clock.now)
    assert store.get(PLAN_A)["tracker_seeder_at"] == 1234.0


def test_a_registry_row_from_the_previous_transfer_never_dates_the_new_plan(
        tmp_path):
    """A peer row belongs to a PEER, not to a plan.

    Unassign and re-assign an image inside one agent tick and aria2 never
    stops: the registry row survives with the PREVIOUS transfer's
    completed_at, minted before the new plan existed. Latching it would export
    iris.transfer.tracker_seeder_at BEFORE iris.transfer.planned_at -- the
    tracker claiming it watched this plan seed before the plan was written --
    and the observability page tells operators to read exactly those two
    against each other to see which precondition was the laggard. The stale
    instant is not this plan's evidence; the pass's own observation is.
    """
    clock = Clock(5000.0)
    store = _store(tmp_path, clock)
    stale = _swarm(completed_at=1200.0, last_seen=1205.0)
    _observe(store, _policy(planned_at=5000.0), snapshot=stale,
             images=_images(), now=clock.now)

    row = store.get(PLAN_A)
    assert row["tracker_seeder_at"] == 5000.0
    assert row["tracker_seeder_at"] >= row["planned_at"]

    # ... and last_seen is skipped for the same reason, not just completed_at.
    fresh = _store(tmp_path, clock, name="last-seen")
    _observe(fresh, _policy(planned_at=5000.0),
             snapshot=_swarm(completed_at=None, last_seen=1205.0),
             images=_images(), now=5100.0)
    assert fresh.get(PLAN_A)["tracker_seeder_at"] == 5100.0

    # A row whose completed_at is at or after the plan is this plan's own
    # evidence and is latched verbatim -- the fix bounds the fact, it does not
    # replace it with "now".
    honest = _store(tmp_path, clock, name="honest")
    _observe(honest, _policy(planned_at=5000.0),
             snapshot=_swarm(completed_at=5200.0, last_seen=5205.0),
             images=_images(), now=9000.0)
    assert honest.get(PLAN_A)["tracker_seeder_at"] == 5200.0


def test_the_info_hash_captured_at_mint_joins_a_plan_with_no_catalog_entry(
        tmp_path):
    """The join key comes from the catalog entry, falling back to the hash
    captured in the policy row when the plan was minted. The fallback is what
    keeps an in-flight plan joinable after its image has been withdrawn from
    the catalog; with neither, the plan simply yields no fact rather than a
    guess."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), reports=_ring(_report()), snapshot=_swarm(),
             images={}, now=clock.now)
    assert store.get(PLAN_A)["state"] == "seeding"

    unjoinable = _store(tmp_path, clock, name="unjoinable")
    _observe(unjoinable, _policy(info_hash=None), reports=_ring(_report()),
             snapshot=_swarm(), images={}, now=clock.now)
    assert unjoinable.get(PLAN_A)["tracker_seeder_at"] is None


# --- markers -------------------------------------------------------------


def test_pending_emissions_orders_planned_before_seeding_started(tmp_path):
    """A backend must never see a transfer start before it was planned, so the
    pair is always yielded in that order for the same plan."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), reports=_ring(_report()), snapshot=_swarm(),
             images=_images(), now=clock.now)
    assert _events(store) == [(PLAN_A, "planned"),
                              (PLAN_A, "seeding_started")]


def test_mark_emitted_is_idempotent(tmp_path):
    """The marker is written after the queue accepted the record, and a pass
    that partially applied is simply retried. A second mark must not duplicate
    the marker or move its timestamp."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), now=clock.now)
    assert store.mark_emitted(PLAN_A, "planned", XFER_A, now=1111.0) is True
    assert store.get(PLAN_A)["emitted"] == {"planned": 1111.0}
    assert store.mark_emitted(PLAN_A, "planned", XFER_A, now=2222.0) is True
    assert store.get(PLAN_A)["emitted"] == {"planned": 1111.0}
    assert _events(store) == []


def test_mark_emitted_refuses_a_stale_transfer_id(tmp_path):
    """The guard closes the window between reading a row and marking it. If
    the row now belongs to a different transfer, writing the marker would
    silence the NEW plan's events forever, so the mark is refused and the
    caller retries against the row it will then read."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), now=clock.now)
    assert store.mark_emitted(PLAN_A, "planned", XFER_B, now=1111.0) is False
    assert store.get(PLAN_A)["emitted"] == {}
    assert _events(store) == [(PLAN_A, "planned")]
    assert store.mark_emitted(PLAN_A, "planned", XFER_A, now=1111.0) is True


def test_mark_emitted_refuses_an_unknown_plan_or_event(tmp_path):
    """Neither is reachable from the emitter, which only ever marks a triple
    pending_emissions handed it -- but a store that wrote a marker for a row
    it does not have would grow junk that no reconcile pass can clean up."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), now=clock.now)
    assert store.mark_emitted(PLAN_B, "planned", now=1111.0) is False
    assert store.mark_emitted(PLAN_A, "cancelled", now=1111.0) is False
    assert store.get(PLAN_A)["emitted"] == {}


def test_markers_and_latches_survive_a_fresh_store_over_the_same_state_dir(
        tmp_path):
    """Restart is the case the in-memory machinery already loses: LogQueue
    discards its dedupe key on flush and Telemetry._seen_report_event_ids is a
    plain in-process set, so both are at-most-once per PROCESS. The markers
    here are on disk, so a brand-new tracker over the same state dir owes
    nothing."""
    clock = Clock()
    directory = os.path.join(str(tmp_path), "state")
    first = transfer_lifecycle.TransferLifecycle(directory, now_fn=clock)
    _observe(first, _policy(), reports=_ring(_report()), snapshot=_swarm(),
             images=_images(), now=clock.now)
    for plan_id, _, event in first.pending_emissions():
        assert first.mark_emitted(plan_id, event, XFER_A, now=clock.now)

    clock.tick()
    second = transfer_lifecycle.TransferLifecycle(directory, now_fn=clock)
    assert second.pending_emissions() == []
    row = second.get(PLAN_A)
    assert row["state"] == "seeding"
    assert row["checksum_verified_at"] == 1300.0
    assert row["tracker_seeder_at"] == 1200.0
    assert sorted(row["emitted"]) == ["planned", "seeding_started"]

    # And another pass over the same live plan changes none of it.
    _observe(second, _policy(), reports=_ring(_report()), snapshot=_swarm(),
             images=_images(), now=clock.now)
    assert second.pending_emissions() == []


def test_seeding_started_at_is_latched_once_and_never_recomputed_after_restart(
        tmp_path):
    """The timestamp is written into the row BEFORE any record is built.

    If it were computed at emission time, a crash between an accepted emit and
    its marker would re-emit a DIFFERENT seeding_started_at under an
    IDENTICAL event.id, and a backend keeping first-write would hold two
    disagreeing values under one id with no way to reconcile them. Later facts
    and a later clock must move nothing.
    """
    clock = Clock()
    directory = os.path.join(str(tmp_path), "state")
    first = transfer_lifecycle.TransferLifecycle(directory, now_fn=clock)
    _observe(first, _policy(), reports=_ring(_report()), snapshot=_swarm(),
             images=_images(), now=clock.now)
    latched = first.get(PLAN_A)["seeding_started_at"]

    clock.tick(600.0)
    second = transfer_lifecycle.TransferLifecycle(directory, now_fn=clock)
    _observe(second, _policy(),
             reports=_ring(_report(received_at=9000.0, window_end=8990.0)),
             snapshot=_swarm(completed_at=9100.0, last_seen=9105.0),
             images=_images(), now=clock.now)
    assert second.get(PLAN_A)["seeding_started_at"] == latched


# --- reconcile ------------------------------------------------------------


def test_a_live_plan_missing_from_the_store_is_reopened_by_reconcile(tmp_path):
    """Identity lives in policy.json, so this store is derived state: delete
    it and the next pass rebuilds every live row with the SAME ids and the
    SAME planned_at. Only the markers are lost, and the re-emission that
    follows carries identical event.ids -- a backend-side duplicate rather
    than a second event."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), now=clock.now)
    assert store.mark_emitted(PLAN_A, "planned", XFER_A, now=clock.now)
    os.remove(store.path)

    clock.tick()
    _observe(store, _policy(), now=clock.now)
    row = store.get(PLAN_A)
    assert row["plan_id"] == PLAN_A
    assert row["transfer_id"] == XFER_A
    assert row["device_id"] == DEV
    assert row["image_id"] == IMAGE
    assert row["info_hash"] == IH
    # Opened at the POLICY row's planned_at, never at the moment this process
    # first noticed the plan -- the decision happened when the assignment was
    # written.
    assert row["planned_at"] == 1000.0
    assert row["state"] == "planned"
    assert _events(store) == [(PLAN_A, "planned")]


def test_a_cancelled_plan_still_emits_planned_and_never_emits_seeding_started(
        tmp_path):
    """An assignment that was withdrawn before the device finished still
    happened: the decision is published. But nothing attests a transfer that
    never completed, so the row is terminal at 'planned' and no accumulation
    of facts can promote it afterwards."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), now=clock.now)

    clock.tick()
    empty = {DEV: {"approved_image_id": None, "approved_image_ids": [],
                   "plans": {}}}
    assert _observe(store, empty, now=clock.now) == []
    assert store.get(PLAN_A)["state"] == "cancelled"
    assert _events(store) == [(PLAN_A, "planned")]

    assert store.mark_emitted(PLAN_A, "planned", XFER_A, now=clock.now)
    # Facts arriving for a cancelled plan latch nothing into a promotion.
    clock.tick()
    store.observe({}, {PLAN_A: {"checksum_verified_at": 1300.0,
                                "observed_at": 1290.0}},
                  {PLAN_A: 1200.0}, now=clock.now)
    assert store.get(PLAN_A)["state"] == "cancelled"
    assert store.get(PLAN_A)["seeding_started_at"] is None
    assert store.pending_emissions() == []


def test_a_cancelled_row_reopens_when_its_plan_is_live_again(tmp_path):
    """plan_ids are minted with secrets.token_hex and a re-assignment mints a
    new one, so a cancelled id cannot legitimately come back. Seeing it live
    again therefore means the pass that cancelled it was reading a policy
    document it could not read at all -- and without the reopen one transient
    read failure would strand every in-flight transfer in the fleet at
    'cancelled' forever. The markers are kept, so 'planned' is not
    re-emitted."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), now=clock.now)
    assert store.mark_emitted(PLAN_A, "planned", XFER_A, now=clock.now)

    clock.tick()
    _observe(store, {}, now=clock.now)
    assert store.get(PLAN_A)["state"] == "cancelled"

    clock.tick()
    _observe(store, _policy(), reports=_ring(_report()), snapshot=_swarm(),
             images=_images(), now=clock.now)
    assert store.get(PLAN_A)["state"] == "seeding"
    assert _events(store) == [(PLAN_A, "seeding_started")]


def test_a_seeding_plan_is_never_cancelled_by_a_later_unassign(tmp_path):
    """A later unassign does not un-happen a transfer that already occurred.
    'seeding' is terminal, and the row keeps its latched timestamps so the
    event it still owes is emitted with the instant it really started."""
    clock = Clock()
    store = _store(tmp_path, clock)
    assert _observe(store, _policy(), reports=_ring(_report()),
                    snapshot=_swarm(), images=_images(),
                    now=clock.now) == [PLAN_A]

    clock.tick()
    _observe(store, {}, now=clock.now)
    row = store.get(PLAN_A)
    assert row["state"] == "seeding"
    assert row["seeding_started_at"] == 1300.0
    assert _events(store) == [(PLAN_A, "planned"),
                              (PLAN_A, "seeding_started")]


def test_two_plans_for_the_same_device_and_image_are_tracked_independently(
        tmp_path):
    """Requirement 7: unassign then re-assign the same image and the second
    transfer is a genuinely separate plan with its own ids, its own row and
    its own pair of events. The first plan's report can never promote the
    second, which is exactly what device-minted ids could not guarantee."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), reports=_ring(_report()), snapshot=_swarm(),
             images=_images(), now=clock.now)

    # The clock advances past the re-assignment: planned_at is stamped off
    # the same server clock, so a pass can never observe a plan minted in its
    # own future.
    clock.tick(1000.0)
    replan = _policy(plans=((IMAGE, PLAN_B, XFER_B),), planned_at=2000.0)
    # The device is still seeding and the OLD report is still in the ring.
    assert _observe(store, replan, reports=_ring(_report()),
                    snapshot=_swarm(), images=_images(), now=clock.now) == []
    rows = store.rows()
    assert rows[PLAN_A]["state"] == "seeding"
    assert rows[PLAN_B]["state"] == "planned"
    assert rows[PLAN_B]["checksum_verified_at"] is None
    assert rows[PLAN_B]["planned_at"] == 2000.0

    # Only a report bearing the NEW transfer_id promotes the new plan.
    clock.tick(600.0)
    assert _observe(store, replan,
                    reports=_ring(_report(),
                                  _report(transfer_id=XFER_B,
                                          received_at=2500.0,
                                          window_end=2490.0)),
                    snapshot=_swarm(), images=_images(),
                    now=clock.now) == [PLAN_B]
    rows = store.rows()
    assert rows[PLAN_A]["seeding_started_at"] == 1300.0
    assert rows[PLAN_B]["seeding_started_at"] == 2500.0
    assert _events(store) == [(PLAN_A, "planned"), (PLAN_A, "seeding_started"),
                              (PLAN_B, "planned"), (PLAN_B, "seeding_started")]


# --- bounds and retention -------------------------------------------------


def _bulk_policy(count, planned_at=1000.0, first=0):
    plans = [("img-%04d" % n, _id(0x10000 + n), _id(0x20000 + n))
             for n in range(first, first + count)]
    return _policy(plans=plans, planned_at=planned_at)


def test_max_plans_bound_is_exact(tmp_path):
    """The cap is a hard count of rows on disk, asserted against the raw JSON
    so the test cannot be satisfied by a reader that filters. A dropped row
    only ever costs markers: identity lives in policy.json, so a still-live
    plan is rebuilt on the very next pass."""
    clock = Clock()
    store = _store(tmp_path, clock)
    over = transfer_lifecycle.MAX_PLANS + 1
    _observe(store, _bulk_policy(over), now=clock.now)
    with open(store.path) as stream:
        raw = json.load(stream)
    assert len(raw["plans"]) == transfer_lifecycle.MAX_PLANS
    assert store.stats()["plans"] == transfer_lifecycle.MAX_PLANS
    assert store.stats()["plan_cap"] == transfer_lifecycle.MAX_PLANS
    # Nothing retirable existed, so the one row that had to go was one that
    # still owed an event -- and that is counted, never silent.
    assert store.stats()["plans_dropped_unemitted"] == 1


def test_eviction_prefers_terminal_emitted_rows_and_counts_unemitted_drops(
        tmp_path):
    """A row that owes nothing -- terminal AND fully emitted -- is only
    history, so it goes first and is counted as a prune. A row still carrying
    a pending emission is evicted only when nothing else can be."""
    clock = Clock()
    store = _store(tmp_path, clock)
    full = _bulk_policy(transfer_lifecycle.MAX_PLANS)
    _observe(store, full, now=clock.now)
    retirable = _id(0x10000)
    assert store.mark_emitted(retirable, "planned", now=clock.now)

    # Unassign that one image: its row goes terminal, fully emitted, and is
    # now the only row in the store that owes nothing.
    clock.tick()
    _observe(store, _bulk_policy(transfer_lifecycle.MAX_PLANS - 1, first=1),
             now=clock.now)
    assert store.get(retirable)["state"] == "cancelled"

    # One more plan takes the store over the cap.
    clock.tick()
    _observe(store, _bulk_policy(transfer_lifecycle.MAX_PLANS, first=1),
             now=clock.now)
    assert store.get(retirable) is None
    stats = store.stats()
    assert stats["plans"] == transfer_lifecycle.MAX_PLANS
    assert stats["plans_pruned"] == 1
    assert stats["plans_dropped_unemitted"] == 0


def test_prune_drops_only_terminal_fully_emitted_rows_past_retention(tmp_path):
    """Age alone is not enough. A row that still owes an event is kept however
    old it is, because dropping it would discard an event the backend has
    never been told about."""
    clock = Clock()
    store = _store(tmp_path, clock)
    policy = _policy(plans=((IMAGE, PLAN_A, XFER_A),
                            (OTHER_IMAGE, PLAN_B, XFER_B)))
    _observe(store, policy, now=clock.now)
    assert store.mark_emitted(PLAN_A, "planned", XFER_A, now=clock.now)

    clock.tick()
    _observe(store, {}, now=clock.now)          # both rows cancelled
    assert store.prune(clock.now - 1.0) == []   # not yet past the cutoff
    assert store.prune(clock.now + 1.0) == [PLAN_A]
    assert sorted(store.rows()) == [PLAN_B]
    assert store.stats()["plans_pruned"] == 1
    assert _events(store) == [(PLAN_B, "planned")]


def test_retention_runs_on_the_observation_pass(tmp_path):
    """observe() applies PLAN_RETENTION itself, so a tracker that is never
    asked to prune still does not grow a year of markers."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), now=clock.now)
    assert store.mark_emitted(PLAN_A, "planned", XFER_A, now=clock.now)
    clock.tick()
    _observe(store, {}, now=clock.now)
    assert store.get(PLAN_A)["state"] == "cancelled"

    clock.tick(transfer_lifecycle.PLAN_RETENTION + 60.0)
    _observe(store, {}, now=clock.now)
    assert store.get(PLAN_A) is None
    assert store.stats()["plans_pruned"] == 1


# --- robustness -----------------------------------------------------------


def test_a_corrupt_store_reads_as_empty_and_does_not_raise(tmp_path):
    """Corruption costs markers, never identity. Every reader answers 'empty'
    instead of raising, and the next pass rebuilds every live row from
    policy.json -- with the same ids, so the bounded re-emission carries
    identical event.ids."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), now=clock.now)
    assert store.mark_emitted(PLAN_A, "planned", XFER_A, now=clock.now)
    with open(store.path, "w") as stream:
        stream.write("{ not json")

    assert store.get(PLAN_A) is None
    assert store.rows() == {}
    assert store.pending_emissions() == []
    assert store.stats()["plans"] == 0
    assert store.prune(clock.now + 1.0) == []

    clock.tick()
    _observe(store, _policy(), reports=_ring(_report()), snapshot=_swarm(),
             images=_images(), now=clock.now)
    row = store.get(PLAN_A)
    assert row["plan_id"] == PLAN_A
    assert row["planned_at"] == 1000.0
    assert row["state"] == "seeding"
    assert _events(store) == [(PLAN_A, "planned"), (PLAN_A, "seeding_started")]


def test_garbage_in_the_policy_document_is_skipped_not_promoted(tmp_path):
    """policy.json is operator-editable. A row whose ids are not 32 lowercase
    hex, or that cannot be honestly timestamped, yields no plan at all: a
    record stamped at the epoch, or an id the ingest path would reject on the
    device's next report, is worse than silence."""
    doc = {"d1": "not-a-dict",
           "d2": {"approved_image_ids": [IMAGE], "plans": "not-a-dict"},
           "d3": {"approved_image_ids": [IMAGE],
                  "plans": {IMAGE: {"plan_id": "NOTHEX", "transfer_id": XFER_A,
                                    "planned_at": 1000.0}}},
           "d4": {"approved_image_ids": [IMAGE],
                  "plans": {IMAGE: {"plan_id": PLAN_A, "transfer_id": PLAN_A,
                                    "planned_at": "yesterday"}}},
           "d5": {"approved_image_ids": [],
                  "plans": {IMAGE: {"plan_id": PLAN_B, "transfer_id": XFER_B,
                                    "planned_at": 1000.0}}}}
    assert transfer_lifecycle.live_plans_from_policy(doc) == {}
    store = _store(tmp_path)
    assert _observe(store, doc, now=1000.0) == []
    assert store.rows() == {}


def test_readers_return_copies(tmp_path):
    """get(), rows() and pending_emissions() hand out deep copies. A caller
    that mutates a row -- the emitter builds a record straight off one -- must
    not be able to reach into the durable store."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), now=clock.now)

    row = store.get(PLAN_A)
    row["state"] = "seeding"
    row["emitted"]["planned"] = 1.0
    assert store.get(PLAN_A)["state"] == "planned"
    assert store.get(PLAN_A)["emitted"] == {}

    rows = store.rows()
    rows[PLAN_A]["planned_at"] = 0.0
    assert store.rows()[PLAN_A]["planned_at"] == 1000.0

    _, pending, _ = store.pending_emissions()[0]
    pending["transfer_id"] = XFER_B
    assert store.get(PLAN_A)["transfer_id"] == XFER_A


# --- delivery, batched writes, and the rows a bound may not touch ---------
#
# Appended as a pure block: nothing above this line is touched, so the
# assertions written against the original semantics stay the regression guard
# they were written to be. Everything here covers a way the store could still
# lose an event or thrash a live plan.


def _write_counter(monkeypatch):
    """Count the store's atomic writes while still performing them.

    The number of read-modify-write cycles is the property under test in this
    block: a marker pass that writes once per event does N full serialise +
    rename cycles on the thread that also has to flush telemetry, and no
    assertion about the resulting document can see that.
    """
    writes = []
    real = transfer_lifecycle._atomic_write_json

    def counted(path, obj):
        writes.append(path)
        return real(path, obj)

    monkeypatch.setattr(transfer_lifecycle, "_atomic_write_json", counted)
    return writes


def test_delivery_not_the_queue_is_what_retires_an_event(tmp_path):
    """Acceptance by the queue is not delivery.

    LogQueue.emit returns False only for a duplicate key or a zero-capacity
    queue -- a FULL queue evicts its oldest record and returns True -- so a row
    that is retired the moment the queue took the record can have that record
    dropped afterwards with nothing left to notice. The enqueue marker
    therefore only stops it being queued twice; the row stays OUTSTANDING until
    a successful send is confirmed.
    """
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), reports=_ring(_report()), snapshot=_swarm(),
             images=_images(), now=clock.now)

    assert store.mark_emitted(PLAN_A, "planned", XFER_A, now=clock.now)
    assert _events(store) == [(PLAN_A, "seeding_started")]
    assert [(p, e) for p, _r, e in store.unconfirmed_emissions()] \
        == [(PLAN_A, "planned")]
    assert [(p, e) for p, _r, e in store.outstanding_emissions()] \
        == [(PLAN_A, "planned"), (PLAN_A, "seeding_started")]
    assert store.stats()["plans_unconfirmed"] == 1

    clock.tick()
    assert store.mark_delivered_many(
        [(PLAN_A, "planned", XFER_A)], now=clock.now) == [True]
    assert store.get(PLAN_A)["delivered"] == {"planned": clock.now}
    assert store.unconfirmed_emissions() == []
    assert [(p, e) for p, _r, e in store.outstanding_emissions()] \
        == [(PLAN_A, "seeding_started")]
    assert store.stats()["plans_unconfirmed"] == 0


def test_a_delivery_writes_the_enqueue_marker_it_implies(tmp_path):
    """A record the collector acknowledged was necessarily queued. The window
    is a crash between an accepted emit and its marker: the send still
    succeeds, and the delivery must retire the event outright rather than
    leaving a row that looks like it was never queued at all."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), now=clock.now)

    clock.tick()
    assert store.mark_delivered_many([(PLAN_A, "planned", XFER_A)],
                                     now=clock.now) == [True]
    row = store.get(PLAN_A)
    assert row["emitted"] == {"planned": clock.now}
    assert row["delivered"] == {"planned": clock.now}
    assert store.pending_emissions() == []
    assert store.outstanding_emissions() == []


def test_marking_a_whole_pass_costs_one_write_and_still_refuses_a_stale_row(
        monkeypatch, tmp_path):
    """One locked read-modify-write for every marker in the pass.

    The per-item transfer_id guard survives the batching: an item naming a
    transfer the row no longer carries is refused on its own, without taking
    the rest of the batch down with it and without inheriting a marker that
    would silence the plan that really is there.
    """
    clock = Clock()
    store = _store(tmp_path, clock)
    policy = _policy(plans=((IMAGE, PLAN_A, XFER_A),
                            (OTHER_IMAGE, PLAN_B, XFER_B)))
    _observe(store, policy, now=clock.now)

    writes = _write_counter(monkeypatch)
    results = store.mark_emitted_many([(PLAN_A, "planned", XFER_A),
                                       (PLAN_B, "planned", XFER_A),
                                       (PLAN_B, "planned", XFER_B)],
                                      now=clock.now)
    assert results == [True, False, True]
    assert len(writes) == 1
    assert store.get(PLAN_A)["emitted"] == {"planned": clock.now}
    assert store.get(PLAN_B)["emitted"] == {"planned": clock.now}


def test_a_batch_that_changes_nothing_does_not_write(monkeypatch, tmp_path):
    """Re-marking is idempotent, and idempotent must also mean quiet: a retry
    after a partially-applied pass rewrites nothing."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), now=clock.now)
    assert store.mark_emitted(PLAN_A, "planned", XFER_A, now=clock.now)

    writes = _write_counter(monkeypatch)
    assert store.mark_emitted_many([(PLAN_A, "planned", XFER_A)],
                                   now=clock.now + 5.0) == [True]
    assert store.mark_emitted_many([], now=clock.now) == []
    assert writes == []
    assert store.get(PLAN_A)["emitted"] == {"planned": clock.now}


def test_a_pass_that_observes_nothing_new_does_not_rewrite_the_store(
        monkeypatch, tmp_path):
    """The steady state is the common case: a fleet mid-rollout re-observes
    the same facts every pass and latches none of them. Writing anyway would
    mean one full serialise + rename of the whole store per pass forever, on
    the thread that also has to flush telemetry."""
    clock = Clock()
    store = _store(tmp_path, clock)
    policy = _policy()
    facts = dict(reports=_ring(_report()), snapshot=_swarm(),
                 images=_images())
    _observe(store, policy, now=clock.now, **facts)
    latched = store.get(PLAN_A)

    writes = _write_counter(monkeypatch)
    clock.tick()
    assert _observe(store, policy, now=clock.now, **facts) == []
    assert writes == []
    assert store.get(PLAN_A) == latched

    # And a pass that DOES observe something writes exactly once.
    clock.tick()
    _observe(store, _policy(plans=((IMAGE, PLAN_A, XFER_A),
                                   (OTHER_IMAGE, PLAN_B, XFER_B))),
             now=clock.now, **facts)
    assert len(writes) == 1
    assert store.get(PLAN_B)["state"] == "planned"


def test_a_live_plan_is_never_evicted_to_make_room(tmp_path):
    """Evicting a LIVE row frees nothing: the next pass rebuilds it from
    policy.json with an empty marker map, so `planned` is re-emitted for as
    long as the plan stays assigned and the two latches never get to meet in
    one row for it to promote. A row whose assignment was withdrawn is the one
    that can go, even though it is younger than every live row it displaces.
    """
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _bulk_policy(transfer_lifecycle.MAX_PLANS), now=clock.now)

    # Withdraw the oldest plan and assign one more: the store is now one row
    # over the cap, and the only non-live row is the youngest thing in it.
    clock.tick()
    withdrawn = _id(0x10000)
    live = _bulk_policy(transfer_lifecycle.MAX_PLANS, first=1)
    _observe(store, live, now=clock.now)

    rows = store.rows()
    assert len(rows) == transfer_lifecycle.MAX_PLANS
    assert withdrawn not in rows
    for plan_id in transfer_lifecycle.live_plans_from_policy(live):
        assert plan_id in rows, "a live plan was evicted and will re-emit"
    assert store.stats()["plans_live_evicted"] == 0
    assert store.stats()["plans_dropped_unemitted"] == 1


def test_a_live_set_over_the_cap_is_evicted_but_counted_as_saturation(
        tmp_path):
    """MAX_PLANS is a hard count of rows on disk, so a live set that exceeds it
    on its own still has to give -- but that is the cap being wrong for the
    fleet, not a row ageing out, and it is counted where an operator can see
    it rather than presenting as events that quietly never arrive."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _bulk_policy(transfer_lifecycle.MAX_PLANS + 2),
             now=clock.now)

    stats = store.stats()
    assert stats["plans"] == transfer_lifecycle.MAX_PLANS
    assert stats["plans_live_evicted"] == 2
    assert stats["plans_dropped_unemitted"] == 2


def test_a_live_plan_is_never_pruned_by_retention(tmp_path):
    """A long rollout is the case: a plan that seeded on day one and is still
    assigned a week later is terminal AND fully emitted, so age alone would
    retire it -- and the next pass would rebuild it empty and re-emit both
    events, every week, forever."""
    clock = Clock()
    store = _store(tmp_path, clock)
    policy = _policy()
    _observe(store, policy, reports=_ring(_report()), snapshot=_swarm(),
             images=_images(), now=clock.now)
    for _plan_id, _row, event in store.pending_emissions():
        assert store.mark_emitted(PLAN_A, event, XFER_A, now=clock.now)
    latched = store.get(PLAN_A)

    clock.tick(transfer_lifecycle.PLAN_RETENTION + 60.0)
    _observe(store, policy, reports=_ring(_report()), snapshot=_swarm(),
             images=_images(), now=clock.now)

    assert store.get(PLAN_A) == latched
    assert store.pending_emissions() == []
    assert store.stats()["plans_pruned"] == 0


def test_prune_never_drops_a_live_plan(tmp_path):
    """The manual hook obeys the same rule as retention and the size bound.

    A `seeding` row is TERMINAL while its assignment still stands, so age
    alone would retire a plan that is very much alive; observe() would then
    re-open it from policy.json with an empty marker map and re-emit both
    events, every time this is called. The guard is a correctness rule, not a
    courtesy -- and it is selective: a row whose assignment was withdrawn
    still goes.
    """
    clock = Clock()
    store = _store(tmp_path, clock)
    policy = _policy(plans=((IMAGE, PLAN_A, XFER_A),
                            (OTHER_IMAGE, PLAN_B, XFER_B)))
    _observe(store, policy, reports=_ring(_report()), snapshot=_swarm(),
             images=_images(), now=clock.now)
    for plan_id, _row, event in store.outstanding_emissions():
        assert store.mark_delivered_many(
            [(plan_id, event, None)], now=clock.now) == [True]
    assert store.get(PLAN_A)["state"] == "seeding"

    # PLAN_B loses its assignment; PLAN_A keeps its own.
    clock.tick()
    live = transfer_lifecycle.live_plans_from_policy(_policy())
    _observe(store, _policy(), now=clock.now)
    assert store.get(PLAN_B)["state"] == "cancelled"

    clock.tick(transfer_lifecycle.PLAN_RETENTION + 60.0)
    assert store.prune(clock.now, live_plans=live) == [PLAN_B]
    assert sorted(store.rows()) == [PLAN_A]
    assert store.pending_emissions() == []


def test_retiring_an_unacknowledged_event_counts_the_records_it_loses(
        tmp_path):
    """Retirement is keyed on `emitted`, never on `delivered` -- requiring
    delivery would hold every row forever while a collector is down. The price
    is that a collector outage longer than PLAN_RETENTION retires rows whose
    records were queued and never acknowledged, and by then the 1000-slot
    LogQueue no longer holds them: those events are gone. A bounded loss is
    defensible; a SILENT one is not, so the store counts the records it drops
    on the floor.
    """
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), now=clock.now)
    assert store.mark_emitted(PLAN_A, "planned", XFER_A, now=clock.now)

    clock.tick()
    _observe(store, {}, now=clock.now)              # cancelled, never acked
    assert store.stats()["plans_unconfirmed"] == 1
    assert store.stats()["events_retired_undelivered"] == 0

    clock.tick(transfer_lifecycle.PLAN_RETENTION + 60.0)
    _observe(store, {}, now=clock.now)
    assert store.get(PLAN_A) is None
    stats = store.stats()
    assert stats["plans_unconfirmed"] == 0          # the row is gone with it
    assert stats["events_retired_undelivered"] == 1
    assert stats["plans_pruned"] == 1


def test_an_acknowledged_event_costs_nothing_when_its_row_retires(tmp_path):
    """The counter must mean "records lost", not "rows retired". A row the
    collector acknowledged owes nobody anything, and ageing it out is ordinary
    housekeeping -- if that incremented too, the number could never be
    alerted on."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _policy(), now=clock.now)
    assert store.mark_delivered_many([(PLAN_A, "planned", XFER_A)],
                                     now=clock.now) == [True]

    clock.tick()
    _observe(store, {}, now=clock.now)
    clock.tick(transfer_lifecycle.PLAN_RETENTION + 60.0)
    _observe(store, {}, now=clock.now)

    assert store.get(PLAN_A) is None
    assert store.stats()["plans_pruned"] == 1
    assert store.stats()["events_retired_undelivered"] == 0


def test_evicting_a_live_row_is_a_replay_not_a_lost_record(tmp_path):
    """A live row evicted by the cap is rebuilt from policy.json on the very
    next pass and its records are re-queued under the same event.id, so its
    unacknowledged markers cost nothing. Counting that as a loss would make
    the number unusable exactly on the fleet that saturates the cap."""
    clock = Clock()
    store = _store(tmp_path, clock)
    _observe(store, _bulk_policy(transfer_lifecycle.MAX_PLANS + 2),
             now=clock.now)
    stats = store.stats()
    assert stats["plans_live_evicted"] == 2
    assert stats["events_retired_undelivered"] == 0


def test_a_recovered_row_replays_one_instant_not_whatever_the_registry_says_now(
        tmp_path):
    """The one input a lost store cannot reproduce is tracker_seeder_at: the
    PeerRegistry is in memory, so the device's next announce stamps a fresh,
    later instant. Re-deriving from it would publish a DIFFERENT timestamp
    under an IDENTICAL event.id on every recovery, and a backend keeping
    first-write would hold disagreeing values under one id. A row opened on a
    pass that DETECTED the loss therefore takes the durable pair only, which
    every later recovery reproduces exactly.
    """
    clock = Clock()
    store = _store(tmp_path, clock)
    policy = _policy()
    # The announce is the later fact, so the first-ever promotion times off it
    # -- a store that never existed is not a loss and has nothing to disagree
    # with.
    _observe(store, policy, reports=_ring(_report(received_at=1400.0)),
             snapshot=_swarm(completed_at=1800.0), images=_images(),
             now=clock.now)
    assert store.get(PLAN_A)["seeding_started_at"] == 1800.0
    assert "recovered_promotion" not in store.get(PLAN_A)

    instants = []
    for announced in (9000.0, 12000.0):
        with open(store.path, "w") as stream:
            stream.write("{ not json")          # the store is lost
        clock.tick()
        _observe(store, policy, reports=_ring(_report(received_at=1400.0)),
                 snapshot=_swarm(completed_at=announced), images=_images(),
                 now=clock.now)
        row = store.get(PLAN_A)
        assert row["state"] == "seeding"
        assert row["recovered_promotion"] is True
        assert store.stats()["plans_promoted_recovered"] == 1
        instants.append(row["seeding_started_at"])

    # Both recoveries agree with each other, on the durable facts alone.
    assert instants == [1400.0, 1400.0]


def test_a_vanished_store_is_a_loss_and_an_absent_one_is_not(tmp_path):
    """Same rebuild, two different situations. A file this object has already
    read or written and can no longer find was LOST -- its rows may have been
    published. A store that never existed is a first-ever pass, and suppressing
    the registry fact there would understate every promotion a new deployment
    ever makes."""
    clock = Clock()
    facts = dict(reports=_ring(_report(received_at=1400.0)),
                 snapshot=_swarm(completed_at=1800.0), images=_images())

    lost = _store(tmp_path, clock, name="lost")
    _observe(lost, _policy(), now=clock.now)        # writes the store
    os.remove(lost.path)
    clock.tick()
    _observe(lost, _policy(), now=clock.now, **facts)
    assert lost.get(PLAN_A)["seeding_started_at"] == 1400.0
    assert lost.get(PLAN_A)["recovered_promotion"] is True

    fresh = _store(tmp_path, clock, name="fresh")
    _observe(fresh, _policy(), now=clock.now, **facts)
    assert fresh.get(PLAN_A)["seeding_started_at"] == 1800.0
    assert "recovered_promotion" not in fresh.get(PLAN_A)
    assert fresh.stats()["plans_promoted_recovered"] == 0
