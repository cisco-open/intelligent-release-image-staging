# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durable per-plan transfer lifecycle: planned -> seeding, emitted once.

A "plan" is the server's decision that one device should hold one image. Its
identity -- ``plan_id``, ``transfer_id``, ``planned_at`` and the torrent
``info_hash`` -- is minted by ``CatalogStore.set_policy`` and lives in the
device's row in ``policy.json``, atomically with the assignment itself. THIS
MODULE OWNS NO IDENTITY. Everything it keeps beneath
``$IRIS_STATE/transfer-lifecycle.json`` is DERIVED state: the three latched
observations behind the seeding decision, and the markers saying which
lifecycle records have already reached the OTLP queue and which of those the
collector has since acknowledged. Delete this file and the next ``observe()``
pass rebuilds every row from policy.json with the same ids; the only thing
lost is the markers, so a bounded set of records is re-emitted under the same
deterministic ``event.id``, which is what makes the re-emission a backend-side
duplicate rather than a second event. See RECOVERED PROMOTION below for the
one value a rebuilt row cannot reproduce from a lost store, and for the rule
that keeps the replay from carrying a DIFFERENT instant under that same id.

SINGLE WRITER. The tracker process is the only writer. The catalog writes
identity into policy.json and touches nothing here, so there is no
cross-process read-modify-write race on this store at all. ``store_lock`` is
still taken on every write, for the same reason ``peer_ledger`` takes it: the
GUI or a future CLI may grow a read of it, and a half-written JSON document is
not something a reader should ever have to cope with.

WHAT IS LATCHED, AND WHY EACH FACT IS LATCHED SEPARATELY
--------------------------------------------------------
A plan is promoted to ``seeding`` only when BOTH of these have been observed,
each latched independently and durably at the FIRST observation:

  * ``checksum_verified_at`` -- a v2 terminal report from that device, bearing
    THAT PLAN'S ``transfer_id``, whose ``content_sha256.state`` is
    ``"verified"``. Both terminal events are structurally reachable only after
    the agent hashed the fully-downloaded staged file, so this one fact
    carries both "the content is complete locally" and "the checksum
    verified".
  * ``tracker_seeder_at`` -- this tracker saw the device itself announce
    ``left=0`` on the image's torrent, authenticated by the personalised
    announce token that resolves to ``Principal("device", <device_id>)``.

Neither fact alone is honest. aria2 starts announcing ``left=0`` the instant
the last piece lands, while the agent's sha256 of a ~1.2 GB image does not run
until its next tick and then takes minutes: "tracker says seeder" alone would
publish a seeding event for content nobody has verified yet. Conversely the
device can neither see nor attest the tracker fact -- it never talks to the
tracker; only its aria2 announces.

Latching is MANDATORY, not an optimisation. The registry prunes a peer row at
``2 * INTERVAL`` (60 s), pops it outright on ``event=stopped``, and erases
``completed_at`` in place when a re-download cycle starts. Requiring both
facts to be visible in the SAME pass would mean a row that vanished between
the seeder observation and the verified report blocks the event permanently.
Latching also defuses the aria2-restart trap: the registry key includes the
peer_id and aria2 mints a fresh one on restart, so a naive "first time I see
this key seed" trigger double-fires. The latch is keyed on the PLAN and is
first-write-wins, so the re-announce is a no-op.

STRICT BINDING ONLY. A report attests a plan only when it carries that plan's
``transfer_id``. There is deliberately no fallback that promotes a plan from a
report bearing some OTHER transfer's id: accepting such a report would mean
publishing "seeding" on the strength of a checksum computed for a different
transfer, which is exactly the guarantee this module exists to make. An agent
too old to adopt the server's plan therefore emits ``planned`` and never
``seeding_started`` -- silence, never a wrong answer.

EXACTLY-ONCE, AND THE WINDOWS WHERE IT DEGRADES
-----------------------------------------------
Each row carries TWO marker maps, keys absent until written::

    "emitted":   {"planned": ts, "seeding_started": ts}   # the queue took it
    "delivered": {"planned": ts, "seeding_started": ts}   # the collector did

They are separate because ACCEPTANCE BY THE QUEUE IS NOT DELIVERY.
``LogQueue.emit`` returns False only for a duplicate key or a zero-capacity
queue; a FULL queue evicts its oldest record and returns True, and a record
already queued can still be evicted by later traffic before any flush
succeeds. A single enqueue-time marker would therefore be written for a record
that never left the process, and since nothing else ever revisits a marked
row, that event would be lost forever -- the failure mode is worst exactly
when it matters most, an unreachable collector with a queue that stays full.
So:

    * ``pending_emissions()`` yields events with NO ``emitted`` marker. The
      caller marks AFTER the queue accepted the record, never before: marking
      first would lose the event the moment the queue refused it.
    * ``unconfirmed_emissions()`` yields events that were queued but not yet
      delivered, and ``outstanding_emissions()`` yields both together in
      ``_EVENTS`` order. The caller re-queues an outstanding record whenever
      the queue no longer holds it (``LogQueue.contains``), so an evicted
      record comes back instead of vanishing.
    * ``mark_delivered_many()`` is driven from ``LogQueue``'s
      delivered-callback, which fires only after a successful send. Delivery
      implies acceptance, so it writes both markers.

Only ``emitted`` retires a row (see ``_retirable``): retention and the size
bound are about markers the store owes, and a row that has been queued has
done everything this module can do about it. A collector down for longer than
PLAN_RETENTION therefore loses the event -- by then the record is long gone
from the 1000-slot queue anyway, and holding rows forever would trade a
bounded loss for an unbounded store. That loss is COUNTED, never silent:
every retirement of a row still holding an unacknowledged marker adds to
``events_retired_undelivered`` (:meth:`TransferLifecycle._note_dropped`),
which is exported alongside ``plans_unconfirmed`` -- the standing backlog and
the records that backlog has already cost.

The guarantee is exactly-once in every normal path INCLUDING process restart,
degrading to at-least-once-with-a-stable-``event.id`` in three windows: a
crash between a successful send and its ``delivered`` write, a failed marker
write, and a corrupt store file. Nothing existing gives even this much --
``LogQueue`` discards its dedupe key after a successful flush and lives in
memory, and ``Telemetry._seen_report_event_ids`` is a plain in-process
``set``; both are at-most-once per PROCESS lifetime.

``seeding_started_at`` is latched into the row BEFORE any record is built, and
never recomputed. If it were computed at emission time, a crash between the
emit and the marker would re-emit a DIFFERENT timestamp under an IDENTICAL
``event.id``, and the backend would hold two disagreeing values under one id
with no way to reconcile them. Latch, then emit, then mark.

RECOVERED PROMOTION -- WHAT A LOST STORE CANNOT REPRODUCE
---------------------------------------------------------
Of the three inputs to ``seeding_started_at`` only two are durable outside
this store: ``planned_at`` (policy.json) and ``checksum_verified_at`` (the
server-stamped ``received_at`` of a report in the catalog's telemetry.json
ring). ``tracker_seeder_at`` comes from the PeerRegistry, which is in memory:
the same device announcing again after a restart produces a fresh
``completed_at``, so a row rebuilt from nothing latches a LATER seeder instant
than the row that was lost. If that later instant wins the ``max()``, the
replayed ``seeding_started`` carries a DIFFERENT timestamp under an IDENTICAL
``event.id`` -- exactly the two-disagreeing-values case the latch exists to
prevent, and one a backend keeping first-write cannot reconcile.

A store LOSS is therefore detected rather than assumed: the file is present
but unparseable, or it has vanished after this object already read or wrote
it. A row opened during such a pass and promoted in that same pass is a
RECOVERED promotion -- it may be the rebuild of a row whose event was already
published -- and it takes its instant from the DURABLE pair only:
``max(checksum_verified_at, planned_at)``, flagged ``recovered_promotion:
true`` on the row and counted in ``plans_promoted_recovered``. That value
replays identically because both of its inputs do. In the ordinary case it is
also the same answer the full rule gives: aria2 announces ``left=0`` the
instant the last piece lands and the sha256 finishes minutes later, so
``checksum_verified_at`` is normally the later fact anyway. A first-ever pass
over a store that never existed is NOT a loss, and uses the ordinary rule --
there is no earlier emission for it to disagree with.

What this buys is that every replay agrees with every other replay, which is
what makes the re-emission a duplicate. It does NOT make a lost row's replay
byte-identical to what was published before the loss, and the residue is
stated here rather than glossed:

  * if the ORIGINAL promotion's instant came from ``tracker_seeder_at`` (the
    announce landing after the verified report), no rebuild can reproduce it,
    and the recovered replay carries the durable instant instead -- the same
    ``event.id`` with an EARLIER value. It is at least a real server
    observation of that plan and bounded below by ``planned_at``, where the
    alternative is an unbounded drift into whenever the device happened to
    re-announce;
  * a store file deleted between two processes is indistinguishable from a
    first-ever start, so its rebuild uses the ordinary rule;
  * if the earliest attesting report has ROTATED out of the catalog's bounded
    ring since the row was lost, the rebuild latches the next-earliest
    report's instant instead (or, with no attesting report left, cannot
    promote at all and stays silent).

All three live outside this store, which is why the contract is a stable
``event.id`` with a replay-stable value -- not byte-identity in every
conceivable state. ``plans_promoted_recovered`` in :meth:`stats` counts every
promotion that took this path, so a disagreement a backend surfaces can be
traced to a loss rather than guessed at.

BOUNDS
------
``MAX_PLANS`` and ``PLAN_RETENTION`` are the store's only growth limits; each
carries its rationale at its definition. Eviction prefers rows that are both
terminal and fully emitted, and an eviction that drops a row with a pending
emission is counted in ``plans_dropped_unemitted`` rather than disappearing
silently -- the ``peer_ledger`` discipline that a bound the store applies is a
bound the store reports. REPORTS means exported, not merely counted:
:meth:`TransferLifecycle.stats` is read every sample pass by
``Telemetry._transfer_lifecycle_numbers`` and published as
``iris.transfer.lifecycle.*`` metric points and the matching
``iris_transfer_lifecycle_*`` Prometheus families. A counter nothing reads is
a bound nobody can check.

NEITHER BOUND MAY TOUCH A LIVE ROW. A plan still backed by an assignment is
re-opened by the very next ``observe()`` pass, with a fresh, empty marker map:
dropping such a row does not free a slot, it starts an infinite loop that
re-emits ``planned`` on every pass and can never let the plan promote (the
row is destroyed before both latches can meet in it). So both ``_retain`` and
``_bound`` skip live plan ids outright. The only exception is a live set that
on its own exceeds ``MAX_PLANS``: the cap is a hard count of rows on disk, so
live rows are evicted as the last resort, and that saturation is counted in
``plans_live_evicted`` -- the number to look at before raising the cap.
"""
import copy
import json
import os
import re
import tempfile
import time

import secrets_store


# Plans retained. Sized against the fleet this ships to: up to 10 images
# assigned per device (the multi-image assignment cap) across a few hundred
# devices is ~2-3k live plans at the very top end, and the remaining headroom
# holds the terminal rows of images that have come and gone until
# PLAN_RETENTION collects them. A deployment past that reads
# plans_live_evicted in stats() and raises this number; the store never
# silently thrashes to stay under it.
# Past the cap the oldest terminal, fully-emitted, NOT-live rows go first (see
# _bound); a non-live evicted row can only ever cost markers, because identity
# lives in policy.json.
MAX_PLANS = 4096
# Terminal AND fully-emitted rows older than a week are pruned. A week is long
# enough that an operator investigating "when did this device start seeding"
# still finds the row after a weekend, and short enough that a fleet churning
# assignments does not carry a year of markers.
PLAN_RETENTION = 7 * 24 * 3600

# Row states. "seeding" and "cancelled" are TERMINAL: a plan that has been
# observed seeding is never un-seeded by a later unassign (the transfer really
# happened), and a cancelled plan can never be promoted.
_TERMINAL = frozenset(("seeding", "cancelled"))

# The two lifecycle events, in emission order. They MUST stay distinct and
# ordered: otlp.build_transfer_lifecycle_record derives event.id from
# "<plan_id>.<event>", and LogQueue.emit refuses a key already queued or
# in flight, so a shared id would silently drop the second record.
_EVENTS = ("planned", "seeding_started")

# Report events that can attest completed, verified content. "pull" is a
# console-requested snapshot, not a completion claim, and is deliberately not
# here. Both of these are reachable on the device only after the staged file
# was size-checked, found to have no .aria2 control file, and hashed.
_TERMINAL_REPORT_EVENTS = frozenset(("staging-complete", "seeding-only"))

_HEX32 = re.compile(r"^[a-f0-9]{32}$")
_HEX40 = re.compile(r"^[a-f0-9]{40}$")


def _atomic_write_json(path, obj):
    """Replace *path* with *obj*, preserving the target's mode.

    A per-module copy of the peer_ledger idiom on purpose: the store each
    module owns is its own, and sharing one helper would invite a future
    change to one store's durability semantics to silently retune another's.
    """
    directory = os.path.dirname(path) or "."
    mode = None
    try:
        mode = os.stat(path).st_mode
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".transfer-lifecycle-",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(obj, stream, indent=2, sort_keys=True)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _hex32(value):
    """The value as a 32-lowercase-hex id, or None. The shape is not cosmetic:
    the device echoes ``transfer_id`` back on every report and envelope, and
    both ingest paths re-validate it against the same pattern -- a
    non-conforming id would fail the WHOLE report, not just this event."""
    if not isinstance(value, str) or not _HEX32.match(value):
        return None
    return value


def _info_hash(value):
    """A 40-hex torrent info_hash, lowercased, or None.

    The tracker keys its registry on ``binascii.hexlify`` of the raw announce
    bytes, i.e. lowercase 40-hex. Anything that cannot be that string cannot
    join to a swarm row, so rejecting it here costs nothing and keeps a
    malformed catalog entry from silently matching nothing further down.
    """
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value if _HEX40.match(value) else None


def _ts(value):
    """A finite, non-negative epoch float, or None.

    Booleans are rejected outright (bool is an int subclass) and NaN/inf/
    negative readings are dropped rather than propagated: a timestamp this
    module cannot subtract is one the dashboards cannot chart, and a dropped
    fact reads as "not observed yet", which is the honest answer.
    """
    if isinstance(value, bool):
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    if out != out or out in (float("inf"), float("-inf")) or out < 0:
        return None
    return out


# --- pure decision functions ----------------------------------------------
#
# These carry the whole promotion rule and take nothing but plain data, so the
# state machine can be tested without constructing a telemetry hub, a
# registry, or a catalog.


def live_plans_from_policy(doc):
    """``{plan_id: plan}`` for every plan currently backed by an assignment.

    *doc* is policy.json as the catalog writes it::

        {device_id: {"approved_image_id": ..., "approved_image_ids": [...],
                     "plans": {image_id: {"plan_id", "transfer_id",
                                          "planned_at", "info_hash"}}}}

    Only image ids that are BOTH in ``approved_image_ids`` and carry a valid
    plan row are live. An id that left the assigned set leaves no plan behind:
    its lifecycle row is cancelled on the next pass, and a later re-assignment
    mints a genuinely new plan rather than resurrecting this one.

    A row whose ids are not 32-lowercase-hex, or whose ``planned_at`` is not a
    usable epoch, is skipped entirely. A plan we cannot timestamp is a plan we
    cannot honestly place on a timeline, and silence beats a record stamped at
    the epoch. Devices are walked in sorted order so that a (structurally
    impossible) duplicate plan_id resolves the same way on every pass.
    """
    out = {}
    for device_id, rec in sorted((doc or {}).items()):
        if not isinstance(rec, dict):
            continue
        ids = rec.get("approved_image_ids")
        plans = rec.get("plans")
        if not isinstance(ids, list) or not isinstance(plans, dict):
            continue
        for image_id in ids:
            if not isinstance(image_id, str) or not image_id:
                continue
            row = plans.get(image_id)
            if not isinstance(row, dict):
                continue
            plan_id = _hex32(row.get("plan_id"))
            transfer_id = _hex32(row.get("transfer_id"))
            planned_at = _ts(row.get("planned_at"))
            if plan_id is None or transfer_id is None or planned_at is None:
                continue
            if plan_id in out:
                continue
            out[plan_id] = {"plan_id": plan_id,
                            "transfer_id": transfer_id,
                            "device_id": str(device_id),
                            "image_id": image_id,
                            "planned_at": planned_at,
                            "info_hash": _info_hash(row.get("info_hash"))}
    return out


def verified_facts(live, reports):
    """Preconditions 1+2 per plan, from the durable v2 report rings.

    *reports* is telemetry.json as the catalog stores it -- ``{device_id:
    [report, ...]}``. A report attests a plan when ALL of:

      * ``rep["image_id"]`` is the plan's image;
      * ``rep["transfer_id"]`` is the plan's transfer id -- the STRICT
        transfer-scoped binding. A report bearing any other id attests
        nothing here, deliberately: promoting on it would mean publishing a
        seeding event on the strength of a checksum computed for a different
        transfer;
      * ``rep["event"]`` is a terminal event, never ``"pull"``;
      * ``rep["content_sha256"]["state"] == "verified"``.

    ``stage_state`` is deliberately NOT consulted: that describes the copy to
    the flash root, and a legitimate flash-full ``seeding-only`` transfer is
    complete and verified while reporting ``stage_state ==
    "flash_full_seeding_only"``. ``ios_copy_verify`` is not consulted either --
    the agent returns it as the constant ``"not_run"`` and it carries no
    signal.

    Returns ``{plan_id: {"checksum_verified_at": <float>, "observed_at":
    <float|None>}}``. ``checksum_verified_at`` is the server-stamped
    ``received_at`` of the EARLIEST attesting report in the ring, and
    ``observed_at`` the end of that same report's measurement window. Earliest
    rather than latest because the store latches first-write-wins: picking the
    earliest makes the value the caller latches independent of how much of the
    ring it happens to be looking at on any given pass.
    """
    wanted = {}
    for plan_id, plan in (live or {}).items():
        wanted[(plan["device_id"], plan["transfer_id"], plan["image_id"])] = \
            plan_id
    out = {}
    for device_id, ring in (reports or {}).items():
        if not isinstance(ring, list):
            continue
        for rep in ring:
            if not isinstance(rep, dict):
                continue
            if rep.get("event") not in _TERMINAL_REPORT_EVENTS:
                continue
            csha = rep.get("content_sha256")
            if not isinstance(csha, dict) or csha.get("state") != "verified":
                continue
            plan_id = wanted.get((str(device_id), rep.get("transfer_id"),
                                  rep.get("image_id")))
            if plan_id is None:
                continue
            received_at = _ts(rep.get("received_at"))
            if received_at is None:
                # The ring stamps received_at on the server clock at write
                # time; a row without one predates that or was hand-edited,
                # and there is no defensible instant to latch for it.
                continue
            previous = out.get(plan_id)
            if previous is not None \
                    and previous["checksum_verified_at"] <= received_at:
                continue
            window = rep.get("window")
            observed_at = _ts(window.get("end")) if isinstance(window, dict) \
                else None
            out[plan_id] = {"checksum_verified_at": received_at,
                            "observed_at": observed_at}
    return out


def seeder_facts(live, snapshot, images, now=None):
    """Precondition 3 per plan, from the tracker's own peer registry.

    *snapshot* is ``PeerRegistry.snapshot()`` -- ``{info_hash: [peer, ...]}``.
    A plan's device counts as a seeder when a row on that plan's torrent has
    ``principal_type == "device"``, ``principal_id`` equal to the plan's
    device, and ``is_seeder`` true. That principal is the AUTHENTICATED join:
    the announce token baked into the device's personalised torrent resolves
    to ``Principal("device", <device_id>)``, and that id is the catalog's own
    device id. A device announcing on a legacy or previous seeder token
    resolves to ``Principal("legacy", ...)`` and can never satisfy this --
    intentional, because such an announce proves no identity.

    ``is_seeder`` is literally ``left == 0`` in the registry, and an announce
    that OMITS ``left`` stores ``None`` (``None == 0`` is False), so a peer
    that never declared what it had left is correctly never a seeder.

    The info_hash comes from the catalog entry (``images[image_id]
    ["info_hash_hex"]``), falling back to the hash captured in the plan row at
    mint time -- which is what keeps a plan joinable after its image has been
    withdrawn from the catalog. With neither, the plan simply yields no fact:
    no join key, no event, never a guess.

    Returns ``{plan_id: <float>}`` -- the EARLIEST ``completed_at`` among the
    matching rows (the registry's own latch for "the moment ``left`` first hit
    0 this cycle"), falling back to ``last_seen`` and finally to *now* for a
    row carrying neither. Earliest, because a device that reconnects gets a
    fresh peer_id and therefore a fresh row: the first moment it seeded is the
    honest answer, not the moment of its latest reconnection.

    EVERY candidate is bounded below by the plan's own ``planned_at``. The
    registry row belongs to a PEER, not to a plan: a device already seeding an
    image when a NEW plan for it is minted (an unassign and re-assign inside
    one agent tick, so aria2 never stops and the row keeps its old
    ``completed_at``; or an operator-adopted pre-staged image) still carries
    the PREVIOUS transfer's instant. Latching it would publish
    ``tracker_seeder_at`` BEFORE ``planned_at`` -- the tracker claiming it saw
    this plan seed before the plan existed -- and the observability page tells
    operators to read those two against ``checksum_verified_at`` to see which
    precondition was the laggard. A candidate that predates the plan is
    therefore not this plan's evidence and falls through to the next one; with
    every candidate behind the plan (only reachable if the server clock ran
    backwards) the plan yields no fact at all, which is this function's
    standing rule: no honest join, no event, never a guess.
    """
    by_image = {}
    for image_id, entry in (images or {}).items():
        if not isinstance(entry, dict):
            continue
        info_hash = _info_hash(entry.get("info_hash_hex"))
        if info_hash is not None:
            by_image[str(image_id)] = info_hash
    fallback = time.time() if now is None else now
    out = {}
    for plan_id, plan in (live or {}).items():
        info_hash = by_image.get(plan["image_id"]) or plan.get("info_hash")
        if not info_hash:
            continue
        floor = _ts(plan.get("planned_at"))
        rows = (snapshot or {}).get(info_hash)
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            if row.get("principal_type") != "device":
                continue
            if str(row.get("principal_id")) != plan["device_id"]:
                continue
            if row.get("is_seeder") is not True:
                continue
            at = None
            for candidate in (row.get("completed_at"), row.get("last_seen"),
                              fallback):
                at = _ts(candidate)
                if at is not None and (floor is None or at >= floor):
                    break
                at = None
            if at is None:
                continue
            if plan_id not in out or at < out[plan_id]:
                out[plan_id] = at
    return out


class TransferLifecycle:
    """The tracker's durable plan rows beneath ``IRIS_STATE``.

    Row shape::

        {"plan_id", "transfer_id", "device_id", "image_id", "info_hash",
         "planned_at", "state": "planned"|"seeding"|"cancelled",
         "checksum_verified_at", "tracker_seeder_at", "seeding_started_at",
         "observed_at", "updated_at", "emitted": {}, "delivered": {},
         ["recovered_promotion": True]}
    """

    def __init__(self, state_dir, now_fn=time.time):
        os.makedirs(state_dir, exist_ok=True)
        self.path = os.path.join(state_dir, "transfer-lifecycle.json")
        self._now = now_fn
        # True once this object has seen a store document on disk (read or
        # written). It is what separates "this store never existed" from
        # "this store was lost", which decides whether a rebuilt row may take
        # its promotion instant from the volatile registry fact -- see
        # RECOVERED PROMOTION in the module docstring.
        self._seen_store = False

    # --- storage -----------------------------------------------------------

    def _read(self):
        """The store, or an empty skeleton when it is missing or unreadable."""
        return self._read_doc()[0]

    def _read_doc(self):
        """``(document, lost)`` -- the store plus whether it was LOST.

        Swallowing ``(OSError, ValueError)`` is the house rule for a derived
        store, and here it is also the self-healing path: a corrupt file reads
        as "nothing emitted", every live plan's row is rebuilt from policy.json
        on this same pass, and the bounded re-emission that follows carries
        identical ``event.id``s. Identity is never at risk, because identity
        was never kept here.

        ``lost`` distinguishes the two ways to read an empty store: a file that
        is present but unparseable, or one that has vanished since this object
        last saw it, versus a store that simply never existed yet. Only the
        first two mean a row rebuilt on this pass may be a REBUILD of one whose
        event was already published.
        """
        present = True
        try:
            with open(self.path) as stream:
                data = json.load(stream)
        except OSError:
            data, present = None, False
        except ValueError:
            data = None
        lost = (present or self._seen_store) and not isinstance(data, dict)
        if not isinstance(data, dict):
            return {"plans": {}, "counters": {}}, lost
        self._seen_store = True
        plans = data.get("plans")
        counters = data.get("counters")
        return ({"plans": plans if isinstance(plans, dict) else {},
                 "counters": counters if isinstance(counters, dict) else {}},
                False)

    def _write(self, data):
        """Persist the store. Every write also proves the file exists, which
        is what makes a LATER read finding it gone a detected loss rather than
        a first-ever start (see :meth:`_read_doc`)."""
        _atomic_write_json(self.path, data)
        self._seen_store = True

    @staticmethod
    def _counter(data, name, delta=1):
        value = data["counters"].get(name)
        data["counters"][name] = (value if isinstance(value, int) else 0) + delta

    @staticmethod
    def _marker_map(row, name):
        """The row's ``emitted``/``delivered`` map, created if absent.

        Repaired in place rather than read defensively at every use: a row
        written by an older shape (before ``delivered`` existed) or hand-edited
        to something that is not a dict would otherwise make every marker write
        silently vanish.
        """
        markers = row.get(name)
        if not isinstance(markers, dict):
            markers = {}
            row[name] = markers
        return markers

    @staticmethod
    def _markers(row, name):
        """The row's ``emitted``/``delivered`` map for READING -- never
        created, so a reader cannot make a copied row look different from the
        stored one."""
        markers = row.get(name)
        return markers if isinstance(markers, dict) else {}

    @classmethod
    def _emitted(cls, row):
        return cls._marker_map(row, "emitted")

    @classmethod
    def _wanted_events(cls, row):
        """The events this row owes, given its state. A row that never reached
        ``seeding`` owes only ``planned``: the decision was real and is
        published, but nothing attests a transfer that never happened."""
        if row.get("state") == "seeding":
            return _EVENTS
        return _EVENTS[:1]

    @classmethod
    def _fully_emitted(cls, row):
        emitted = row.get("emitted")
        emitted = emitted if isinstance(emitted, dict) else {}
        return all(event in emitted for event in cls._wanted_events(row))

    @classmethod
    def _undelivered(cls, row):
        """The events this row put on the queue that no send ever
        acknowledged. Retiring such a row LOSES those records: by then they are
        long gone from the 1000-slot LogQueue, and nothing re-queues an event
        whose row no longer exists. The number is the whole point -- see
        :meth:`_note_dropped`."""
        emitted = cls._markers(row, "emitted")
        delivered = cls._markers(row, "delivered")
        return [event for event in cls._wanted_events(row)
                if event in emitted and event not in delivered]

    @classmethod
    def _note_dropped(cls, data, row):
        """Count what dropping *row* costs, before it is deleted.

        ``events_retired_undelivered`` is the loss retention CANNOT avoid:
        ``_retirable`` is keyed on ``emitted`` and deliberately not on
        ``delivered`` (requiring delivery would hold every row forever
        whenever the collector is down), so a collector outage longer than
        PLAN_RETENTION retires rows whose records were queued and never
        acknowledged. That trade is defensible only while it is VISIBLE: the
        counter is exported next to ``plans_unconfirmed``, so an outage shows
        up as a rising number rather than as terminal records that quietly
        never arrived. It counts EVENTS, not rows -- one row can lose both.
        """
        count = len(cls._undelivered(row))
        if count:
            cls._counter(data, "events_retired_undelivered", count)

    @classmethod
    def _retirable(cls, row):
        """True when a row owes nothing further -- terminal AND fully emitted.
        Only such rows are pruned or preferentially evicted; anything else
        still has an event the backend has not been told about.

        DELIVERY is deliberately not required here (see EXACTLY-ONCE in the
        module docstring): retirement is about what the store still owes the
        queue, and a row whose records are queued but unacknowledged is held by
        PLAN_RETENTION, not forever. A live row is never retirable in the sense
        that matters either -- both callers skip live plan ids before they ever
        consult this.
        """
        return row.get("state") in _TERMINAL and cls._fully_emitted(row)

    # --- the observation pass ----------------------------------------------

    def observe(self, live_plans, verified, seeder, now=None):
        """Reconcile against the live plan set, latch facts, promote, bound.

        One locked read-modify-write per pass, in a fixed order:

          1. every live plan gets a row (opened at the POLICY row's own
             ``planned_at``, never at "now" -- the decision happened when the
             assignment was written, not when this process first noticed it);
          2. a ``planned`` row whose plan is no longer live is cancelled;
             a ``seeding`` row is NEVER cancelled, because a later unassign
             does not un-happen a transfer that already occurred;
          3. facts latch first-write-wins;
          4. a ``planned`` row holding both latches is promoted, and its
             ``seeding_started_at`` is computed ONCE, here, before any record
             exists;
          5. retention and the size bound, neither of which may touch a live
             row (see BOUNDS in the module docstring).

        The store is rewritten only when something actually changed. A steady
        fleet re-observes the same facts on every pass and latches none of
        them, so an unconditional write would mean one full serialise + fsync-
        ordered rename of the whole store per pass forever, on the thread that
        also has to flush telemetry.

        Returns the plan ids promoted on this pass, which is what a caller
        would log; emission is driven separately off
        :meth:`pending_emissions` / :meth:`outstanding_emissions`.
        """
        now = self._now() if now is None else now
        live_plans = live_plans or {}
        verified = verified or {}
        seeder = seeder or {}
        promoted = []
        dirty = False
        # Rows opened by THIS pass. When the pass also DETECTED a lost store,
        # such a row may be the rebuild of one whose event was already
        # published, and promoting it is a recovered promotion -- see
        # RECOVERED PROMOTION in the module docstring for why its instant may
        # not then use tracker_seeder_at.
        opened = set()
        with secrets_store.store_lock(self.path):
            data, lost = self._read_doc()
            plans = data["plans"]

            for plan_id, plan in sorted(live_plans.items()):
                row = plans.get(plan_id)
                if not isinstance(row, dict):
                    plans[plan_id] = self._open(plan, now)
                    opened.add(plan_id)
                    dirty = True
                    continue
                dirty = self._refresh(row, plan) or dirty
                if row.get("state") == "cancelled":
                    # A cancelled plan_id cannot legitimately come back: ids
                    # are minted with secrets.token_hex and a re-assignment
                    # mints a new one. So seeing this plan live again means
                    # the pass that cancelled it was working from a policy
                    # document it could not read -- a transient empty dict
                    # would otherwise strand every in-flight transfer in the
                    # fleet. Reopen rather than strand; the markers are kept,
                    # so `planned` is not re-emitted.
                    row["state"] = "planned"
                    row["updated_at"] = now
                    dirty = True

            for plan_id, row in plans.items():
                if not isinstance(row, dict):
                    continue
                if plan_id not in live_plans and row.get("state") == "planned":
                    row["state"] = "cancelled"
                    row["updated_at"] = now
                    dirty = True

            for plan_id, fact in verified.items():
                row = plans.get(plan_id)
                if not isinstance(row, dict) or not isinstance(fact, dict):
                    continue
                if row.get("checksum_verified_at") is None:
                    at = _ts(fact.get("checksum_verified_at"))
                    if at is not None:
                        row["checksum_verified_at"] = at
                        row["observed_at"] = _ts(fact.get("observed_at"))
                        row["updated_at"] = now
                        dirty = True

            for plan_id, at in seeder.items():
                row = plans.get(plan_id)
                if not isinstance(row, dict):
                    continue
                if row.get("tracker_seeder_at") is None:
                    at = _ts(at)
                    if at is not None:
                        row["tracker_seeder_at"] = at
                        row["updated_at"] = now
                        dirty = True

            for plan_id in sorted(plans):
                row = plans.get(plan_id)
                if not isinstance(row, dict) or row.get("state") != "planned":
                    continue
                verified_at = row.get("checksum_verified_at")
                seeder_at = row.get("tracker_seeder_at")
                if verified_at is None or seeder_at is None:
                    continue
                row["state"] = "seeding"
                if row.get("seeding_started_at") is None:
                    # The instant the LAST precondition became true, floored
                    # at the plan's own creation so a dashboard can never
                    # render a negative planned->seeding duration. There is
                    # deliberately NO upper clamp to "now": clamping against a
                    # live clock would make a crash-replay emit a different
                    # timestamp under an identical event.id. All three inputs
                    # are server-clock instants from this same container, so
                    # the subtraction stays on one clock.
                    #
                    # RECOVERED PROMOTION (module docstring): a row this pass
                    # had to OPEN, on a pass that also found the store LOST,
                    # may be the rebuild of a row whose seeding_started was
                    # already published. tracker_seeder_at is the one input
                    # that cannot survive that loss -- the PeerRegistry is in
                    # memory, so the device's re-announce stamps a LATER
                    # instant -- and using it here would replay a DIFFERENT
                    # timestamp under an identical event.id. The durable pair
                    # replays identically, and in the ordinary case it is
                    # already the answer: the sha256 finishes minutes after
                    # aria2 first announced left=0. A store that simply never
                    # existed is NOT a loss: there is no earlier emission for
                    # its first promotion to disagree with, so it takes the
                    # ordinary rule.
                    if lost and plan_id in opened:
                        row["recovered_promotion"] = True
                        self._counter(data, "plans_promoted_recovered")
                        last = verified_at
                    else:
                        last = max(verified_at, seeder_at)
                    row["seeding_started_at"] = max(
                        last, row.get("planned_at") or 0)
                row["updated_at"] = now
                dirty = True
                promoted.append(plan_id)

            dirty = self._retain(data, now, live_plans) or dirty
            dirty = self._bound(data, live_plans) or dirty
            if dirty:
                self._write(data)
        return promoted

    @staticmethod
    def _open(plan, now):
        return {"plan_id": plan["plan_id"],
                "transfer_id": plan["transfer_id"],
                "device_id": plan["device_id"],
                "image_id": plan["image_id"],
                "info_hash": plan.get("info_hash"),
                "planned_at": plan["planned_at"],
                "state": "planned",
                "checksum_verified_at": None,
                "tracker_seeder_at": None,
                "seeding_started_at": None,
                "observed_at": None,
                "updated_at": now,
                "emitted": {},
                "delivered": {}}

    @staticmethod
    def _refresh(row, plan):
        """Re-seat the identity fields policy.json owns; True when any moved.

        policy.json is authoritative for identity, so a row rebuilt from an
        older shape (or one whose image had no catalog entry, and therefore no
        info_hash, when it was first opened) picks the current values up here.
        ``planned_at`` is re-seated too and that is safe: set_policy never
        re-mints a plan that stayed in the assigned set, so the value cannot
        move under a live plan.

        The return value is what keeps observe()'s dirty check honest: the
        steady-state pass re-seats every live row with the value it already
        holds, so an unconditional "I touched it" would make every pass write.
        """
        changed = False
        for field in ("transfer_id", "device_id", "image_id", "planned_at"):
            if row.get(field) != plan[field]:
                row[field] = plan[field]
                changed = True
        if plan.get("info_hash") and not row.get("info_hash"):
            row["info_hash"] = plan["info_hash"]
            changed = True
        return changed

    def _retain(self, data, now, live_plans=()):
        """Drop rows that owe nothing and have aged past PLAN_RETENTION.

        A LIVE plan is never dropped, however old and however fully emitted:
        the next pass would re-open it with an empty marker map and re-emit
        `planned` -- weekly, forever, for a plan that never changed. Returns
        True when anything was removed.
        """
        cutoff = now - PLAN_RETENTION
        removed = False
        for plan_id, row in list(data["plans"].items()):
            if not isinstance(row, dict):
                del data["plans"][plan_id]
                removed = True
                continue
            if plan_id in live_plans:
                continue
            if self._retirable(row) and (row.get("updated_at") or 0) < cutoff:
                self._note_dropped(data, row)
                del data["plans"][plan_id]
                self._counter(data, "plans_pruned")
                removed = True
        return removed

    def _bound(self, data, live_plans=()):
        """Enforce MAX_PLANS, oldest retirable rows first; True when it bit.

        Eviction order is: retirable rows (terminal AND fully emitted, so only
        history), then rows that still owe an emission, and LIVE rows last of
        all. Live last is not a preference but a correctness rule -- a live
        row is rebuilt from policy.json on the very next pass with a fresh,
        empty marker map, so evicting one frees nothing and re-emits `planned`
        for as long as the plan stays assigned, while destroying the row the
        two latches have to meet in for it ever to promote.

        Every eviction is counted: a bound the store applies is a bound the
        store reports, so a fleet that outgrew MAX_PLANS shows up as a number
        on the dashboard rather than as events that quietly never arrived. A
        live row evicted because the LIVE SET ALONE exceeds the cap is counted
        separately in ``plans_live_evicted`` -- that one means the cap itself
        is wrong for this fleet, not that a row aged out -- and records the
        eviction took off the queue unacknowledged are counted in
        ``events_retired_undelivered`` (see :meth:`_note_dropped`).
        """
        plans = data["plans"]
        excess = len(plans) - MAX_PLANS
        if excess <= 0:
            return False
        ordered = sorted(
            plans.items(),
            key=lambda item: (2 if item[0] in live_plans
                              else (0 if self._retirable(item[1]) else 1),
                              item[1].get("updated_at") or 0,
                              item[0]))
        for plan_id, row in ordered[:excess]:
            live = plan_id in live_plans
            if not live:
                # A LIVE row is re-opened from policy.json on the very next
                # pass and its outstanding records are re-queued under the
                # same event.id, so its unacknowledged markers are a replay,
                # not a loss. Only a row that can never come back costs
                # records, and only that is counted as one.
                self._note_dropped(data, row)
            del plans[plan_id]
            if live:
                self._counter(data, "plans_live_evicted")
            if self._retirable(row):
                self._counter(data, "plans_pruned")
            else:
                self._counter(data, "plans_dropped_unemitted")
        return True

    # --- emission ----------------------------------------------------------

    def _emissions(self, due):
        """``[(plan_id, row, event), ...]`` for every event *due* selects.

        ``due(emitted, delivered, event)`` decides; one read of the store
        serves the whole enumeration. ``planned`` always precedes
        ``seeding_started`` for the same plan, so a backend can never see a
        transfer start before it was planned, and plans are ordered by
        ``planned_at`` so the stream reads chronologically across a fleet.
        Rows are copies: a caller that mutates one cannot reach the store.
        """
        rows = []
        for plan_id, row in self._read()["plans"].items():
            if not isinstance(row, dict):
                continue
            rows.append((row.get("planned_at") or 0, plan_id, row))
        out = []
        for _, plan_id, row in sorted(rows, key=lambda item: item[:2]):
            emitted = self._markers(row, "emitted")
            delivered = self._markers(row, "delivered")
            for event in self._wanted_events(row):
                if due(emitted, delivered, event):
                    out.append((plan_id, copy.deepcopy(row), event))
        return out

    def pending_emissions(self):
        """Events with no ``emitted`` marker -- never queued at all."""
        return self._emissions(
            lambda emitted, delivered, event: event not in emitted)

    def unconfirmed_emissions(self):
        """Events the queue took but no send has acknowledged.

        The record may still be sitting in the queue, or it may have been
        evicted by later traffic while the collector was unreachable -- the
        store cannot tell the two apart, and deliberately does not try. The
        caller checks ``LogQueue.contains`` and re-queues only what the queue
        no longer holds.
        """
        return self._emissions(
            lambda emitted, delivered, event: (event in emitted
                                               and event not in delivered))

    def outstanding_emissions(self):
        """Everything not yet acknowledged: pending + unconfirmed, in one read
        and in ``_EVENTS`` order per plan, so a re-queue after an eviction can
        never put ``seeding_started`` on the wire ahead of ``planned``."""
        return self._emissions(
            lambda emitted, delivered, event: event not in delivered)

    def _mark(self, data, plan_id, event, expect_transfer_id, now, confirm):
        """Apply one marker to *data* in place. ``(ok, changed)``.

        ``ok`` says the marker is (now, or already) recorded -- the historical
        return of :meth:`mark_emitted`. ``changed`` says the document actually
        moved, and is what decides whether the caller writes at all.
        """
        if event not in _EVENTS:
            return False, False
        row = data["plans"].get(plan_id)
        if not isinstance(row, dict):
            return False, False
        if expect_transfer_id is not None \
                and row.get("transfer_id") != expect_transfer_id:
            return False, False
        changed = False
        emitted = self._marker_map(row, "emitted")
        if event not in emitted:
            # Written on the delivery path too: a record the collector
            # acknowledged was necessarily queued, even when the enqueue-time
            # marker was lost to a crash in between.
            emitted[event] = now
            changed = True
        if confirm:
            delivered = self._marker_map(row, "delivered")
            if event not in delivered:
                delivered[event] = now
                changed = True
        if changed:
            row["updated_at"] = now
        return True, changed

    def _mark_many(self, items, now, confirm):
        """Apply every ``(plan_id, event, expect_transfer_id)`` in ONE locked
        read-modify-write, returning a per-item list of ``ok`` flags.

        Batched because the alternative is quadratic: a pass with N events
        marking one at a time re-reads, re-serialises and re-renames the whole
        store N times, on the same thread that then has to flush telemetry.
        The write is skipped entirely when no marker moved.
        """
        items = list(items or ())
        if not items:
            return []
        now = self._now() if now is None else now
        results = []
        dirty = False
        with secrets_store.store_lock(self.path):
            data = self._read()
            for plan_id, event, expect_transfer_id in items:
                ok, changed = self._mark(data, plan_id, event,
                                         expect_transfer_id, now, confirm)
                results.append(ok)
                dirty = dirty or changed
            if dirty:
                self._write(data)
        return results

    def mark_emitted(self, plan_id, event, expect_transfer_id=None,
                     now=None):
        """Record that *event* reached the queue for *plan_id*.

        Called ONLY after the queue accepted the record. Idempotent: a second
        mark neither duplicates the marker nor moves its timestamp, so a
        retry after a partially-applied pass changes nothing.

        *expect_transfer_id* guards the read-modify-write window: if the row
        has been replaced by a different transfer since the caller read it,
        the mark is REFUSED. Without that check a new plan could inherit the
        previous plan's marker and its events would never be published.

        Returns True when the marker is (now, or already) recorded.
        """
        return self._mark_many([(plan_id, event, expect_transfer_id)],
                               now, False)[0]

    def mark_emitted_many(self, items, now=None):
        """:meth:`mark_emitted` for a whole pass, in one write. *items* are
        ``(plan_id, event, expect_transfer_id)`` triples."""
        return self._mark_many(items, now, False)

    def mark_delivered_many(self, items, now=None):
        """Record that the collector ACKNOWLEDGED these events, in one write.

        Driven from ``LogQueue``'s delivered-callback, which fires only after
        a successful send -- this, not the enqueue marker, is what says the
        event has left the process for good. Same triples as
        :meth:`mark_emitted_many`; the ``emitted`` marker is written too when
        it is missing, because delivery implies the queue took it.
        """
        return self._mark_many(items, now, True)

    # --- readers -----------------------------------------------------------

    def get(self, plan_id):
        """One row as a copy, or None."""
        row = self._read()["plans"].get(plan_id)
        return copy.deepcopy(row) if isinstance(row, dict) else None

    def rows(self):
        """Every row, as copies, keyed by plan_id."""
        return copy.deepcopy({plan_id: row
                              for plan_id, row in self._read()["plans"].items()
                              if isinstance(row, dict)})

    def stats(self):
        """Store occupancy and the counters behind the bounds.

        ``plans_awaiting_report`` is the one an operator reads during a rollout:
        a plan the tracker has already watched seed but for which no report
        bearing that plan's transfer_id has arrived. A fleet still running
        agents too old to adopt the server's plan sits there, visibly, instead
        of presenting as a silent absence of events.

        ``plans_unconfirmed`` counts events queued but never acknowledged by a
        send: a steady non-zero number is a collector problem, not a fleet one,
        and ``events_retired_undelivered`` is its terminal end -- events whose
        row was retired before any acknowledgement arrived, i.e. records that
        are gone (see :meth:`_note_dropped`). ``plans_live_evicted`` is the
        saturation signal for MAX_PLANS -- see BOUNDS in the module docstring;
        anything but 0 means the cap is too small for this fleet.

        Every number here is exported:
        ``Telemetry._transfer_lifecycle_numbers`` feeds them to the OTLP metric
        points and the Prometheus exposition on :9101, which is what makes a
        bound this store applies a bound an operator can actually read.
        """
        data = self._read()
        plans = [row for row in data["plans"].values() if isinstance(row, dict)]
        counters = data["counters"]
        return {"plans": len(plans),
                "plan_cap": MAX_PLANS,
                "plans_open": sum(1 for row in plans
                                  if row.get("state") == "planned"),
                "plans_seeding": sum(1 for row in plans
                                     if row.get("state") == "seeding"),
                "plans_cancelled": sum(1 for row in plans
                                       if row.get("state") == "cancelled"),
                "plans_awaiting_report": sum(
                    1 for row in plans
                    if row.get("state") == "planned"
                    and row.get("tracker_seeder_at") is not None
                    and row.get("checksum_verified_at") is None),
                "plans_unconfirmed": sum(
                    1 for row in plans
                    for event in self._wanted_events(row)
                    if event in self._markers(row, "emitted")
                    and event not in self._markers(row, "delivered")),
                "plans_pruned": int(counters.get("plans_pruned") or 0),
                "plans_promoted_recovered": int(
                    counters.get("plans_promoted_recovered") or 0),
                "plans_live_evicted": int(
                    counters.get("plans_live_evicted") or 0),
                "plans_dropped_unemitted": int(
                    counters.get("plans_dropped_unemitted") or 0),
                "events_retired_undelivered": int(
                    counters.get("events_retired_undelivered") or 0)}

    # --- retention ---------------------------------------------------------

    def prune(self, before_ts, live_plans=()):
        """Drop rows that owe nothing and were last touched before *before_ts*.

        Only terminal, fully-emitted rows go: a row still carrying a pending
        emission is kept regardless of age, because dropping it would discard
        an event the backend has never been told about. Returns the dropped
        plan ids.

        *live_plans* is any container of currently-assigned plan ids, and rows
        in it are NEVER dropped -- the same correctness rule ``_retain`` and
        ``_bound`` obey (see BOUNDS in the module docstring), not a courtesy.
        A `seeding` row is terminal while its assignment still stands, so
        without the guard age alone retires a LIVE plan, observe() re-opens it
        from policy.json with an empty marker map, and both events are
        re-emitted -- every time this is called, for as long as the plan stays
        assigned. The argument defaults to empty because a caller with no live
        set at hand is exactly the caller that must supply one; nothing in the
        tracker calls this today (observe() applies PLAN_RETENTION itself,
        with the live set in hand), so a future caller reading only the
        signature now sees the parameter it has to fill in.

        Records this drop takes off the queue unacknowledged are counted in
        ``events_retired_undelivered`` (see :meth:`_note_dropped`).
        """
        dropped = []
        with secrets_store.store_lock(self.path):
            data = self._read()
            for plan_id, row in list(data["plans"].items()):
                if not isinstance(row, dict):
                    continue
                if plan_id in live_plans:
                    continue
                if self._retirable(row) \
                        and (row.get("updated_at") or 0) < before_ts:
                    self._note_dropped(data, row)
                    del data["plans"][plan_id]
                    self._counter(data, "plans_pruned")
                    dropped.append(plan_id)
            if dropped:
                self._write(data)
        return sorted(dropped)
