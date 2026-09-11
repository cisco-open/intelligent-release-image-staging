# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Inert, server-side schedule runner with durable per-device evidence.

The owner calls run(stop_event) from one daemon thread after deployment recovery.
Imports and construction start no threads and read/write no stores. New-window
countdowns read definitions/progress only; target resolution happens at fire.

resolve_target(schedule) returns revision/now/device_ids, optionally accompanied
by transient validation facts. role_guard(schedule) is a context manager that
validates authoritative role state under the owner's role-management lock. That
lock surrounds claim/rechecks, never executor calls. The guard must raise
ExecutionRefused with a safe reason code when authority is unavailable.

The injected executor is nonblocking:
  validate(schedule, snapshot, phase='window_start') -> None or refusal result
  dispatch(schedule, occurrence, device_id, prior_receipt) -> result
  poll(receipt) -> result
  cancel_queued(occurrence_id, job_ids) -> ignored (poll confirms each outcome)

A result has status and reason. Durable statuses are ok/skipped/error or
submitted/running (submitted requires job_id). Deferred results retain the
current receipt with a safe reason and optional transient retry_at. A retry
result from poll means authoritative recovery found no work requiring continued
polling; it must carry manual_generation for a durable successor attempt.
Prepared results may bind manual_generation/before_image_ids to an intent before
any external action. Dispatch must reconcile an existing intent by its immutable
occurrence/device identity before admitting work: an earlier call may have
succeeded immediately before the process lost its result.

The runner owns persistence/timing; Task23 owns actual assignment/onboarding,
recovery provenance, policy checks, and bounded admission. Task24 owns gate math.
No executor or gate is treated as success merely because it is unavailable.

A schedule may carry an `after` wave gate. The executor then also supplies
wave_counts(schedule, occurrence) -> {schedule_id, occurrence_id, total,
staged, errored, missing} for the preceding schedule's own occurrence. The
gate is re-evaluated at every wake inside the window until it opens, and it
is an operational signal, not a security boundary: it decides only WHEN work
is admitted, never what that work may do, and every per-device authority
check still runs afterwards. It admits work and never retracts it, absent
corroboration is never read as a refusal, and an unopened gate ends its
occurrence stalled at deadline_seconds rather than waiting silently.
"""
import contextlib
import copy
import heapq
import re
import threading
import time

import schedules


_ACTIVE = frozenset(("pending", "running", "interrupted"))
_METADATA = frozenset(("job_id", "record_id", "predecessor_record_id",
    "manual_generation", "fleet_registered_at", "fleet_registration_id",
    "before_image_ids",
    "after_image_ids", "removed_image_ids", "notes"))
_REASON = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


class ExecutionRefused(RuntimeError):
    """Expected refusal carrying a public, non-diagnostic reason code."""
    def __init__(self, reason):
        if not isinstance(reason, str) or not _REASON.fullmatch(reason):
            raise ValueError("invalid execution refusal reason")
        self.reason = reason
        super().__init__(reason)


class UnavailableExecutor:
    """Safe placeholder until Task23 supplies the real executor."""
    def validate(self, schedule, snapshot, phase):
        return {"status": "skipped", "reason": "executor_unavailable"}

    def dispatch(self, schedule, occurrence, device_id, prior_receipt):
        raise ExecutionRefused("executor_unavailable")

    def poll(self, receipt):
        # Existing evidence could belong to work admitted by an earlier build.
        return {"status": "deferred", "reason": "executor_unavailable"}

    def wave_counts(self, schedule, occurrence):
        raise ExecutionRefused("executor_unavailable")

    def cancel_queued(self, occurrence_id, job_ids):
        return None

    def acknowledge(self, receipt):
        return None


def _wave_open(after, counts):
    """Whether a preceding occurrence's counts satisfy the operator's gate.

    Ratios are compared by multiplying the threshold out, so no count is
    rounded into or out of a decision. A preceding occurrence that bound an
    empty target has nothing left to wait for; one that does not exist yet
    reports no occurrence id and holds, because absent evidence is not
    evidence of staging.
    """
    if counts["occurrence_id"] is None:
        return False
    total = counts["total"]
    if not total:
        return True
    return (counts["staged"] >= after["min_staged_ratio"] * total
            and counts["errored"] <= after["max_errored_ratio"] * total
            and counts["missing"] <= after["max_missing_ratio"] * total)


@contextlib.contextmanager
def _default_role_guard(schedule):
    if schedule["target"]["filters"].get("role") not in (None, "", "__none"):
        raise ExecutionRefused("role_authority_unavailable")
    yield


class ScheduleRunner:
    """One state-owner runner; tests drive run_once with an injected clock."""
    def __init__(self, store, resolve_target, *, executor=None, role_guard=None,
                 now_fn=time.time, wake_event=None, idle_recheck=30,
                 poll_interval=1, max_claims=32, max_dispatches=100,
                 error_fn=None, wave_recheck=15):
        for value in (idle_recheck, poll_interval, wave_recheck):
            if type(value) not in (int, float) or not 0 < value <= 300:
                raise ValueError("runner intervals must be positive and bounded")
        for value in (max_claims, max_dispatches):
            if type(value) is not int or value < 1:
                raise ValueError("runner budgets must be positive integers")
        self.store = store
        self.occurrences = schedules.OccurrenceStore(store.state_dir)
        self.receipts = schedules.ReceiptStore(store.state_dir)
        self.resolve_target = resolve_target
        self.executor = executor if executor is not None else UnavailableExecutor()
        self.role_guard = role_guard if role_guard is not None else _default_role_guard
        self.now_fn = now_fn
        self.wake_event = wake_event if wake_event is not None else threading.Event()
        self.idle_recheck = idle_recheck
        self.poll_interval = poll_interval
        # A held gate keeps its occurrence active, so the runner wakes on the
        # poll interval. Reading the whole heartbeat authority and the swarm
        # once per second for the length of a maintenance window would cost
        # far more than it could learn: devices report on their own cadence.
        self.wave_recheck = wave_recheck
        self.max_claims = max_claims
        self.max_dispatches = max_dispatches
        self.error_fn = error_fn
        self.last_error = None
        self._failures = 0
        self._recovered = False
        self._active = set()
        self._service_order = []
        self._validated = set()
        self._facts = {}
        self._retry_at = {}
        self._wave_at = {}
        self._pending_acknowledgements = set()
        self._position = {}
        self._stop = threading.Event()
        self._external_stop = None

    def _now(self):
        value = self.now_fn()
        if type(value) not in (int, float) or not 0 <= value <= schedules.MAX_EPOCH:
            raise ValueError("invalid runner clock")
        return int(value)

    def wake(self):
        self.wake_event.set()

    def stop(self):
        self._stop.set()
        self.wake()

    def _stopping(self):
        return self._stop.is_set() or (self._external_stop is not None and self._external_stop.is_set())

    def recover(self):
        """Mark interrupted once, retaining active work even for deleted rows."""
        if self._recovered:
            return []
        recovered = self.occurrences.recover_interrupted(now=self._now())
        self._active.update(row["id"] for row in self.occurrences.list() if row["state"] in _ACTIVE)
        self._recovered = True
        return recovered

    def run(self, stop_event):
        self._external_stop = stop_event
        try:
            while not self._stopping():
                # A write during the scan must remain visible to this wait.
                self.wake_event.clear()
                delay = self.run_once()
                if not self._stopping():
                    self.wake_event.wait(delay)
        finally:
            self._external_stop = None

    def run_once(self):
        """Run one bounded pass, returning a positive, stop-aware wait delay.

        This guard includes recovery, definitions, math, claims, receipt writes
        and error reporting. A corrupt store is never interpreted as empty.
        """
        if self._stopping():
            return self.idle_recheck
        try:
            self.recover()
            delay = self._pass()
        except Exception as exc:
            self.last_error = exc.reason if isinstance(exc, ExecutionRefused) else "schedule_runner_error"
            self._failures = min(self._failures + 1, 10)
            if self.error_fn is not None:
                try:
                    self.error_fn(self.last_error)
                except Exception:
                    pass
            return min(self.idle_recheck, self.poll_interval * 2 ** (self._failures - 1))
        self._failures = 0
        self.last_error = None
        return max(0.01, min(self.idle_recheck, delay))

    def _slot(self, row, now):
        progress = self.store.progress(row["id"])
        cursor = progress["last_slot"] if progress else None
        # On first startup, start at creation rather than discarding earlier
        # weekly slots. Subsequent scans use the durable last-claimed cursor.
        anchor = row["created_at"] if cursor is None and row["when"]["kind"] == "recurring" else now
        slot = schedules.occurrence_slot(row, anchor, after_epoch=cursor)
        if slot is not None:
            slot["status"] = ("future" if now < slot["scheduled_at"] else
                              "due" if now < slot["window_end"] else "missed")
        return slot

    def _pass(self):
        now = self._now()
        pending = []
        for row in self.store.list():
            slot = self._slot(row, now)
            if slot is not None:
                heapq.heappush(pending, (slot["scheduled_at"], row["id"], row, slot))
        claims = 0
        errors = []
        while pending and pending[0][0] <= self._now() and claims < self.max_claims and not self._stopping():
            _, _, row, slot = heapq.heappop(pending)
            claims += 1
            try:
                claimed = self._claim(row, slot)
            except schedules.ScheduleConflict:
                # Definition edited/deleted during resolution. A fresh pass
                # recomputes from its new authority; this stale row cannot fire.
                continue
            except Exception as exc:
                errors.append(exc)
                continue
            if claimed["state"] in _ACTIVE:
                self._active.add(claimed["id"])
            current = self.store.get(row["id"])
            if current is not None:
                upcoming = self._slot(current, self._now())
                if upcoming is not None:
                    heapq.heappush(pending, (upcoming["scheduled_at"], current["id"], current, upcoming))
        self._remaining = self.max_dispatches
        # First service follows earliest due order. Keep a rotating order for
        # subsequent passes so one deferring occurrence cannot repeatedly spend
        # the global dispatch budget before younger occurrences get a turn.
        order = [oid for oid in self._service_order if oid in self._active]
        known = set(order)
        order.extend(sorted(self._active - known,
            key=lambda oid: (self.occurrences.get(oid)["scheduled_at"], oid)))
        self._service_order = order[1:] + order[:1]
        for oid in order:
            if self._stopping():
                break
            try:
                self._process(self.occurrences.get(oid))
            except Exception as exc:
                errors.append(exc)
        if errors:
            raise errors[0]
        delay = self.poll_interval if self._active else self.idle_recheck
        if pending:
            delay = min(delay, max(0.01, pending[0][0] - self._now()))
        return delay

    def _claim(self, row, slot):
        existing = self.occurrences.get(schedules.occurrence_id(row, slot["scheduled_at"]))
        facts = None
        if existing is not None:
            snapshot = existing.get("target_snapshot")
        elif self._now() >= slot["window_end"]:
            snapshot = None
        else:
            # Role authority must cover both target resolution and its durable
            # claim. Otherwise a role/fleet writer could expose a target from
            # one side of a coordinated edit and a claim from the other.
            with self.role_guard(row):
                facts = self.resolve_target(copy.deepcopy(row))
                snapshot = {
                    key: facts[key]
                    for key in ("revision", "now", "device_ids")}
                bound_ids = (row["preview"]["device_ids"]
                             if row["target"]["bind"] == "early"
                             else snapshot["device_ids"])
                # Early binding keeps the creation-time target even when a
                # later resolver no longer sees one of those devices.  Never
                # combine those IDs with a different late-resolution set.
                snapshot["device_ids"] = list(bound_ids)
                bindings = facts.get("registration_ids")
                if isinstance(bindings, dict):
                    snapshot["registration_ids"] = {
                        device_id: bindings.get(device_id)
                        for device_id in bound_ids}
                snapshot = schedules.normalize_snapshot(snapshot)
                # Resolution can cross the end boundary; never publish a
                # fabricated fired set for a slot already missed.
                if self._now() >= slot["window_end"]:
                    snapshot = None
                claimed = self.store.claim_occurrence(
                    row["id"], expected_rev=row["rev"],
                    expected_generation=row["generation"], slot=slot,
                    target_snapshot=snapshot, now=self._now())
        if existing is not None or snapshot is None and facts is None:
            claimed = self.store.claim_occurrence(
                row["id"], expected_rev=row["rev"],
                expected_generation=row["generation"], slot=slot,
                target_snapshot=snapshot, now=self._now())
        if facts is not None and claimed["state"] in _ACTIVE:
            # Facts are diagnostic/validation input, not additional durable
            # authority. Core binding remains the store's closed snapshot.
            self._facts[claimed["id"]] = dict(facts, **claimed["target_snapshot"])
        return claimed

    def _wave(self, occurrence):
        """Evaluate an after-gate at this wake, or None once work is admitted.

        Any durable evidence for the occurrence is the latch: the gate has
        already opened for it, and a later regression in the preceding
        occurrence must not retract work this one has begun. The latch is the
        stored evidence itself, so it survives a restart mid-window.
        """
        oid = occurrence["id"]
        if self.receipts.list(oid, limit=1)["total"]:
            return None
        after = occurrence["schedule"]["after"]
        now = self._now()
        stored = ((self.occurrences.get(oid) or {}).get("annotations") or {}).get("wave")
        if stored is not None and stored["gate"] == "open":
            # A pass can open the gate and be interrupted before it admits
            # anything. The decision is durable, so it is not re-litigated
            # against counts that moved after it was taken.
            return {"gate": "open", "counts": stored,
                    "expired": now >= occurrence["scheduled_at"] + after["deadline_seconds"]}
        expired = now >= occurrence["scheduled_at"] + after["deadline_seconds"]
        # A throttled wake is necessarily still held: the latch above returns
        # early once anything has been admitted. The deadline is never
        # throttled, so the counts that stall an occurrence are freshly read.
        if not expired and self._wave_at.get(oid, 0) > now:
            return {"gate": "held", "counts": None, "expired": False}
        self._wave_at[oid] = now + self.wave_recheck
        counter = getattr(self.executor, "wave_counts", None)
        if not callable(counter):
            return {"gate": "unavailable", "counts": None, "expired": expired}
        try:
            counted = counter(copy.deepcopy(occurrence["schedule"]),
                              copy.deepcopy(occurrence))
        except ExecutionRefused:
            # Evidence loss delays a wave; it must not hold one past its
            # deadline, and it may never be reported as an all-clear.
            if not expired:
                raise
            return {"gate": "held", "expired": True,
                    "counts": stored or self._wave_record(occurrence, {
                        "schedule_id": after["schedule_id"],
                        "occurrence_id": None, "total": 0, "staged": 0,
                        "errored": 0, "missing": 0})}
        counts = self._wave_record(occurrence, counted)
        if _wave_open(after, counts):
            counts["gate"] = "open"
        self.occurrences.annotate_wave(oid, counts, now=self._now())
        return {"gate": counts["gate"], "counts": counts, "expired": expired}

    def _wave_record(self, occurrence, counted):
        if not isinstance(counted, dict) or set(counted) != {
                "schedule_id", "occurrence_id", "total"} | set(schedules.WAVE_COUNTS):
            raise ValueError("invalid wave gate counts")
        if counted["schedule_id"] != occurrence["schedule"]["after"]["schedule_id"]:
            raise ValueError("wave counts name another schedule")
        return schedules.normalize_wave(
            dict(counted, gate="held", observed_at=self._now()))

    def _wave_held(self, occurrence):
        """True when a gated occurrence is ending without its gate opening.

        An occurrence whose window closed before the gate could even be read
        is held too: nothing admitted its work, and reporting that as a
        completed wave would claim an ordering that never happened.
        """
        if "after" not in occurrence["schedule"]:
            return False
        row = self.occurrences.get(occurrence["id"]) or {}
        wave = (row.get("annotations") or {}).get("wave")
        return wave is None or wave["gate"] != "open"

    def _closed_reason(self, occurrence):
        if self._stopping():
            return "runner_stopping"
        now = self._now()
        if now < occurrence["scheduled_at"]:
            return "window_not_open"
        if now >= occurrence["window_end"]:
            return "window_closed"
        live = self.store.get(occurrence["schedule_id"])
        original = occurrence["schedule"]
        # Re-affirm changes the audit label/revision, not a frozen operation.
        if (live is None or live["generation"] != occurrence["schedule_generation"] or
                any(live.get(key) != original.get(key) for key in schedules.DEFINITION_KEYS)):
            return "schedule_changed"
        return None

    def _admission_reason(self, occurrence):
        reason = self._closed_reason(occurrence)
        if reason is not None:
            return reason
        try:
            with self.role_guard(occurrence["schedule"]):
                return self._closed_reason(occurrence)
        except ExecutionRefused as exc:
            return exc.reason

    @staticmethod
    def _result(result):
        if not isinstance(result, dict) or set(result) - ({"status", "reason", "retry_at"} | _METADATA):
            raise ValueError("invalid executor result fields")
        if result.get("status") not in schedules.RECEIPT_STATES | {"deferred", "retry", "prepared"}:
            raise ValueError("invalid executor result status")
        if not isinstance(result.get("reason"), str) or not _REASON.fullmatch(result["reason"]):
            raise ValueError("invalid executor result reason")
        if result["status"] == "intent":
            raise ValueError("use prepared or deferred for an executor intent result")
        if "retry_at" in result and (type(result["retry_at"]) is not int or not 0 <= result["retry_at"] <= schedules.MAX_EPOCH):
            raise ValueError("invalid executor retry time")
        return result

    def _save(self, occurrence, did, prior, result):
        result = self._result(result)
        status = result["status"]
        if status == "retry":
            raise ValueError("retry needs recovery handling")
        if status in ("deferred", "prepared"):
            status = prior["status"]
        if status in ("submitted", "running") and not result.get("job_id", prior.get("job_id")):
            raise ValueError("admitted result requires job identity")
        metadata = {key: value for key, value in result.items() if key in _METADATA}
        saved = self.receipts.record(occurrence["id"], did, status=status,
            reason=result["reason"], now=self._now(), expected_rev=prior["rev"], **metadata)
        key = (occurrence["id"], did)
        if result["status"] in ("deferred", "prepared"):
            self._retry_at[key] = max(self._now()+self.poll_interval, result.get("retry_at", 0))
        else:
            self._retry_at.pop(key, None)
        if saved["status"] in schedules.TERMINAL_RECEIPT_STATES:
            self._acknowledge(saved)
        return saved

    def _acknowledge(self, receipt):
        """Best-effort cleanup only after terminal evidence is durable.

        A crash or transient cleanup failure leaves replay evidence in place.
        Completed receipts retry this acknowledgement on later passes.
        """
        callback = getattr(self.executor, "acknowledge", None)
        key = (receipt["occurrence_id"], receipt["device_id"])
        if not callable(callback):
            self._pending_acknowledgements.discard(key)
            return True
        try:
            callback(copy.deepcopy(receipt))
        except Exception:
            self._pending_acknowledgements.add(key)
            return False
        self._pending_acknowledgements.discard(key)
        return True

    def _finish_unsubmitted(self, occurrence, did, prior, reason, status="skipped", wave=None):
        saved = self.receipts.record(occurrence["id"], did, status=status,
            reason=reason, now=self._now(), expected_rev=prior["rev"] if prior else None,
            wave=wave)
        self._acknowledge(saved)
        return saved

    def _retry(self, occurrence, did, prior, result, closed):
        if closed == "window_not_open":
            return self._save(occurrence, did, prior,
                {"status": "deferred", "reason": closed})
        if closed:
            return self._finish_unsubmitted(occurrence, did, prior, closed)
        # A retry is explicit authoritative recovery, never inferred from
        # absent in-memory jobs. Preserve the old attempt before admission.
        if "manual_generation" not in result:
            raise ValueError("recovery retry requires manual generation")
        if prior["attempt"] >= schedules.MAX_RECEIPT_ATTEMPTS:
            return self._finish_unsubmitted(occurrence, did, prior,
                "retry_limit_exceeded", "error")
        successor = self.receipts.successor_attempt(occurrence["id"], did,
            expected_rev=prior["rev"], now=self._now(),
            manual_generation=result["manual_generation"],
            predecessor_record_id=result.get("predecessor_record_id"),
            before_image_ids=result.get("before_image_ids"))
        self._retry_at.pop((occurrence["id"], did), None)
        return successor

    def _poll(self, occurrence, did, prior, closed):
        if self._retry_at.get((occurrence["id"], did), 0) > self._now():
            return prior
        result = self._result(self.executor.poll(copy.deepcopy(prior)))
        if result["status"] == "retry":
            return self._retry(occurrence, did, prior, result, closed)
        return self._save(occurrence, did, prior, result)

    def _cancel_closed(self, occurrence, attempted):
        closed = self._closed_reason(occurrence)
        if not closed or closed == "window_not_open":
            return
        # Polling can fail or be deferred beyond the window end. Cancellation
        # therefore has its own path and only carries this occurrence's IDs.
        owned = set()
        for did in occurrence["target_snapshot"]["device_ids"]:
            receipt = self.receipts.get(occurrence["id"], did)
            if receipt and receipt["status"] == "submitted" and receipt.get("job_id"):
                owned.add(receipt["job_id"])
        new = owned - attempted
        if new:
            attempted.update(new)
            self.executor.cancel_queued(occurrence["id"], sorted(new))

    def _process(self, occurrence):
        if occurrence["state"] not in _ACTIVE:
            self._active.discard(occurrence["id"])
            return
        attempted, cancellation_errors = set(), []

        def cancel_closed():
            try:
                self._cancel_closed(occurrence, attempted)
            except Exception as exc:
                # An unavailable cancellation endpoint must not prevent receipt
                # reconciliation. The whole-pass guard still reports/backoffs.
                cancellation_errors.append(exc)

        cancel_closed()
        try:
            self._process_devices(occurrence)
        finally:
            # Also cover a clock crossing the boundary during dispatch/poll,
            # including an exception before that operation could return.
            cancel_closed()
        if cancellation_errors:
            raise cancellation_errors[0]

    def _process_devices(self, occurrence):
        oid = occurrence["id"]
        if occurrence["state"] not in _ACTIVE:
            self._active.discard(oid)
            return
        if occurrence["state"] != "running":
            occurrence = self.occurrences.transition(oid, "running", now=self._now(), expected_state=occurrence["state"])
        targets = occurrence["target_snapshot"]["device_ids"]
        complete = self.receipts.completed_device_ids(oid)
        closed = self._admission_reason(occurrence)
        refusal = None
        wave = None
        if closed is None and (len(complete) < len(targets) or not targets):
            if targets and "after" in occurrence["schedule"]:
                gate = self._wave(occurrence)
                if gate is not None and gate["gate"] != "open":
                    if gate["gate"] == "unavailable":
                        refusal = {"status":"skipped", "reason":"gate_unavailable"}
                    elif not gate["expired"]:
                        return  # held: re-evaluated at the next wake
                    else:
                        refusal = {"status":"skipped", "reason":"wave_deadline"}
                        wave = gate["counts"]
            if refusal is None and oid not in self._validated:
                validation_snapshot = copy.deepcopy(
                    self._facts.get(oid, occurrence["target_snapshot"]))
                validation_snapshot["occurrence_id"] = oid
                refusal = self.executor.validate(copy.deepcopy(occurrence["schedule"]),
                    validation_snapshot, "window_start")
                if refusal is not None:
                    refusal = self._result(refusal)
                    if refusal["status"] not in ("skipped", "error"):
                        raise ValueError("validation must allow or refuse without admission")
                else:
                    self._validated.add(oid)
        start = self._position.get(oid, 0)
        order = list(enumerate(targets))
        order = order[start:] + order[:start]
        for position, did in order:
            if self._stopping():
                break
            if did in complete:
                terminal = self.receipts.get(oid, did)
                if terminal is not None:
                    self._acknowledge(terminal)
                continue
            prior = self.receipts.get(oid, did)
            closed = self._admission_reason(occurrence)
            if prior and prior["status"] in ("submitted", "running"):
                self._position[oid] = (position + 1) % max(1, len(targets))
                self._poll(occurrence, did, prior, closed)
                continue
            if closed == "window_not_open":
                continue  # wall clock moved backwards; do not dispatch or close
            if closed:
                if prior is not None:
                    # Intent may precede a successful but unrecorded admission.
                    self._poll(occurrence, did, prior, closed)
                else:
                    self._finish_unsubmitted(occurrence, did, None, closed)
                continue
            if refusal is not None:
                if prior is not None:
                    self._poll(occurrence, did, prior, refusal["reason"])
                else:
                    self._finish_unsubmitted(occurrence, did, None, refusal["reason"],
                                             refusal["status"], wave=wave)
                continue
            if self._remaining <= 0 or self._retry_at.get((oid,did), 0) > self._now():
                continue
            self._remaining -= 1
            self._position[oid] = (position + 1) % max(1, len(targets))
            intent = prior if prior is not None else self.receipts.begin(oid, did, now=self._now())
            closed = self._admission_reason(occurrence)
            if closed:
                if prior is not None:
                    self._poll(occurrence, did, intent, closed)
                else:
                    self._finish_unsubmitted(occurrence, did, intent, closed)
                continue
            result = self._result(self.executor.dispatch(copy.deepcopy(occurrence["schedule"]),
                copy.deepcopy(occurrence), did, copy.deepcopy(intent)))
            if result["status"] == "retry":
                self._retry(occurrence, did, intent, result, self._admission_reason(occurrence))
            else:
                self._save(occurrence, did, intent, result)
        done = self.receipts.completed_device_ids(oid)
        acknowledgement_pending = any(
            (oid, did) in self._pending_acknowledgements for did in targets)
        if len(done) == len(targets) and not acknowledgement_pending:
            reasons = {refusal["reason"]} if refusal else set()
            statuses = {refusal["status"]} if refusal else set()
            for did in targets:
                result = self.receipts.get(oid, did)
                reasons.add(result["reason"])
                statuses.add(result["status"])
            state = ("stalled" if reasons & {"gate_unavailable", "wave_deadline"}
                     or self._wave_held(occurrence) else
                     "failed" if "error" in statuses or "executor_unavailable" in reasons else
                     "cancelled" if "schedule_changed" in reasons else "completed")
            self.occurrences.transition(oid, state, now=self._now(), expected_state="running")
            self._active.discard(oid)
            self._validated.discard(oid)
            self._facts.pop(oid, None)
            self._position.pop(oid, None)
            self._wave_at.pop(oid, None)
            for did in targets:
                self._retry_at.pop((oid, did), None)
