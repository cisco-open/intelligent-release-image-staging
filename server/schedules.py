# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Stage-only schedule authority and durable occurrence evidence.

Definitions use per-row CAS; runtime progress never changes a definition's
revision. Callers coordinate role-reference validation with the existing outer
role-management lock before definition writes. This module never contacts a
device. Receipt pagination caps responses, not durable completion evidence.

Weekdays use Python's Monday=0 convention. Windows are half-open. The sole
wall-clock arithmetic lives inside next_fire; all persisted times are epochs.
"""
import copy
import hashlib
import os
import re
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import keyed_state
import secrets_store


MAX_INTEGER = (1 << 63) - 1
# End of year 9998 leaves a year of datetime arithmetic headroom.
MAX_EPOCH = 253370764799
MAX_WINDOW_SECONDS = 7 * 86400
MAX_TARGETS = 20000
MAX_RECEIPT_PAGE = 1000
KINDS = frozenset(("assign", "onboard"))
SCHEDULE_STATES = frozenset(("pending", "paused", "completed"))
FILTER_KEYS = frozenset(("q", "management_type", "platform", "cred", "telemetry",
                         "peer", "role", "model_family", "os_family", "status"))
DEFINITION_KEYS = frozenset(("kind", "target", "payload", "when", "after", "state"))
ROW_KEYS = DEFINITION_KEYS | {"id", "generation", "rev", "created_by", "created_at", "preview"}
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_IMAGE_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_HEX_RE = re.compile(r"[0-9a-f]{32}\Z")
_ROLE_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}\Z")
_REASON_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
OCCURRENCE_TRANSITIONS = {
    "pending": frozenset(("running", "missed", "cancelled", "stalled", "failed")),
    "running": frozenset(("interrupted", "completed", "cancelled", "stalled", "failed")),
    "interrupted": frozenset(("running", "missed", "cancelled", "stalled", "failed")),
    "completed": frozenset(), "missed": frozenset(), "cancelled": frozenset(),
    "stalled": frozenset(), "failed": frozenset(),
}
TERMINAL_RECEIPT_STATES = frozenset(("ok", "skipped", "error"))
RECEIPT_STATES = TERMINAL_RECEIPT_STATES | {"intent", "submitted", "running"}
MAX_RECEIPT_ATTEMPTS = 16


class ScheduleValidationError(ValueError):
    status = 422
    code = "invalid_schedule"


class ScheduleConflict(ValueError):
    status = 409
    code = "schedule_conflict"


class ScheduleNotFound(ScheduleConflict):
    status = 404
    code = "schedule_not_found"


class ScheduleRevisionConflict(ScheduleConflict):
    status = 412
    code = "precondition_failed"

    def __init__(self, schedule_id, revision):
        self.schedule_id = schedule_id
        self.revision = revision
        super().__init__("schedule revision does not match")


class ScheduleStateError(RuntimeError):
    status = 503
    code = "schedule_state_unavailable"


def _object(value, keys, field, required=()):
    if not isinstance(value, dict) or set(value) - set(keys) or set(required) - set(value):
        raise ScheduleValidationError("invalid %s fields" % field)


def _integer(value, field, minimum=0, maximum=MAX_INTEGER):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ScheduleValidationError("invalid %s integer" % field)
    return value


def _text(value, field, limit=256, empty=False):
    if (not isinstance(value, str) or (not value and not empty) or
            value != value.strip() or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)):
        raise ScheduleValidationError("invalid %s text" % field)
    try:
        if len(value.encode("utf-8")) > limit:
            raise ScheduleValidationError("%s is too long" % field)
    except UnicodeError:
        raise ScheduleValidationError("invalid %s text" % field) from None
    return value


def _identifier(value, field="id"):
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ScheduleValidationError("invalid %s" % field)
    return value


def _hex(value, field):
    if not isinstance(value, str) or not _HEX_RE.fullmatch(value):
        raise ScheduleValidationError("invalid %s" % field)
    return value


def _ids(value, field="device_ids", maximum=MAX_TARGETS, empty=True):
    if not isinstance(value, list) or len(value) > maximum or (not empty and not value):
        raise ScheduleValidationError("invalid %s list" % field)
    for item in value:
        if field == "image_ids":
            if not isinstance(item, str) or not _IMAGE_ID_RE.fullmatch(item):
                raise ScheduleValidationError("invalid catalog image id")
        else:
            _device_id(item)
    if len(set(value)) != len(value):
        raise ScheduleValidationError("duplicate %s" % field)
    return list(value)


def _device_id(value):
    _identifier(value, "device id")
    try:
        secrets_store.validate_device_id(value)
    except ValueError as exc:
        raise ScheduleValidationError(str(exc)) from None
    return value


def _actor(actor):
    _text(actor, "actor", 256)
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}:.+", actor):
        raise ScheduleValidationError("actor needs a namespace and identity")
    return actor


def normalize_snapshot(value):
    _object(value, {"revision", "now", "device_ids"}, "snapshot", {"revision", "now", "device_ids"})
    return {"revision": _integer(value["revision"], "snapshot revision"),
            "now": _integer(value["now"], "snapshot now", maximum=MAX_EPOCH),
            "device_ids": _ids(value["device_ids"])}


def normalize_definition(value):
    """Return a detached, fully defaulted, closed operator definition.

    Empty filters and IDs explicitly select the whole fleet. Nonempty IDs
    narrow (AND) the filters; they never override a filter mismatch.
    """
    _object(value, DEFINITION_KEYS, "schedule", {"kind", "target", "payload", "when"})
    if not isinstance(value["kind"], str) or value["kind"] not in KINDS:
        raise ScheduleValidationError("kind must be assign or onboard")
    state = value.get("state", "pending")
    if not isinstance(state, str) or state not in SCHEDULE_STATES:
        raise ScheduleValidationError("invalid schedule state")
    target = value["target"]
    _object(target, {"filters", "device_ids", "bind"}, "target")
    filters = target.get("filters", {})
    _object(filters, FILTER_KEYS, "target filters")
    for key, item in filters.items():
        _text(item, key, 256, empty=True)
        if key == "role" and item not in ("", "__none") and not _ROLE_RE.fullmatch(item):
            raise ScheduleValidationError("invalid target role")
    bind = target.get("bind", "late")
    if bind not in ("late", "early"):
        raise ScheduleValidationError("invalid target binding")
    target = {"filters": dict(filters), "device_ids": _ids(target.get("device_ids", [])), "bind": bind}
    payload = value["payload"]
    if value["kind"] == "assign":
        _object(payload, {"image_ids", "mode"}, "assignment payload", {"image_ids"})
        mode = payload.get("mode", "merge")
        if mode not in ("merge", "replace"):
            raise ScheduleValidationError("invalid assignment mode")
        payload = {"image_ids": _ids(payload["image_ids"], "image_ids", maximum=10, empty=False), "mode": mode}
    else:
        _object(payload, {"telemetry", "telemetry_stream", "mode", "max_devices"}, "onboarding payload", {"max_devices"})
        payload = {"telemetry": payload.get("telemetry", True),
                   "telemetry_stream": payload.get("telemetry_stream", False),
                   "mode": payload.get("mode", "new-only"), "max_devices": payload["max_devices"]}
        if payload["mode"] != "new-only" or any(type(payload[k]) is not bool for k in ("telemetry", "telemetry_stream")):
            raise ScheduleValidationError("invalid onboarding mode or telemetry flags")
        _integer(payload["max_devices"], "max_devices", 1, MAX_TARGETS)
    when = value["when"]
    _object(when, {"kind", "at", "weekday", "hour", "minute", "tz", "window_seconds"}, "when", {"kind", "window_seconds"})
    when = dict(when)
    when.setdefault("tz", "UTC")
    _text(when["tz"], "timezone", 128)
    try:
        ZoneInfo(when["tz"])
    except (ValueError, ZoneInfoNotFoundError):
        raise ScheduleValidationError("unknown IANA timezone") from None
    _integer(when["window_seconds"], "window_seconds", 1, MAX_WINDOW_SECONDS)
    if when["kind"] == "once":
        _object(when, {"kind", "at", "tz", "window_seconds"}, "once", {"at"})
        _integer(when["at"], "at", maximum=MAX_EPOCH - MAX_WINDOW_SECONDS)
    elif when["kind"] == "recurring":
        _object(when, {"kind", "weekday", "hour", "minute", "tz", "window_seconds"}, "recurring", {"weekday", "hour", "minute"})
        for field, maximum in (("weekday", 6), ("hour", 23), ("minute", 59)):
            _integer(when[field], field, maximum=maximum)
    else:
        raise ScheduleValidationError("invalid when kind")
    result = {"kind": value["kind"], "target": target, "payload": payload, "when": when, "state": state}
    if "after" in value:
        after = value["after"]
        keys = {"schedule_id", "condition", "min_staged_ratio", "max_errored_ratio", "max_missing_ratio", "deadline_seconds"}
        _object(after, keys, "after", keys)
        _identifier(after["schedule_id"], "preceding schedule id")
        if after["condition"] != "min_staged_ratio":
            raise ScheduleValidationError("invalid wave condition")
        for field in ("min_staged_ratio", "max_errored_ratio", "max_missing_ratio"):
            number = after[field]
            if type(number) not in (float, int) or not 0 <= number <= 1:
                raise ScheduleValidationError("invalid wave ratio")
        _integer(after["deadline_seconds"], "wave deadline", 1, MAX_WINDOW_SECONDS)
        result["after"] = dict(after)
    return result


def validate_schedule(schedule_id, row):
    _object(row, ROW_KEYS, "stored schedule", ROW_KEYS - {"after"})
    _identifier(schedule_id, "schedule id")
    if row["id"] != schedule_id:
        raise ScheduleValidationError("schedule key mismatch")
    _hex(row["generation"], "generation")
    _integer(row["rev"], "rev", 1)
    _actor(row["created_by"])
    _integer(row["created_at"], "created_at", maximum=MAX_EPOCH)
    normalize_snapshot(row["preview"])
    definition = {key: row[key] for key in DEFINITION_KEYS if key in row}
    if normalize_definition(definition) != definition:
        raise ScheduleValidationError("stored schedule is not normalized")
    if row.get("after", {}).get("schedule_id") == schedule_id:
        raise ScheduleValidationError("schedule cannot follow itself")


def schedule_etag(row):
    return '"iris-schedule-%s-%d"' % (_identifier(row["id"]), _integer(row["rev"], "rev", 1))


def _compare(schedule_id, old, expected_rev):
    if old is None:
        raise ScheduleNotFound("no such schedule")
    if expected_rev != "*":
        _integer(expected_rev, "expected_rev", 1)
        if old["rev"] != expected_rev:
            raise ScheduleRevisionConflict(schedule_id, old["rev"])


def _progress_valid(key, row):
    _identifier(key)
    _object(row, {"generation", "last_slot", "active_occurrence_id"}, "schedule progress", {"generation", "last_slot", "active_occurrence_id"})
    _hex(row["generation"], "generation")
    _integer(row["last_slot"], "last_slot", maximum=MAX_EPOCH)
    _hex(row["active_occurrence_id"], "occurrence id")


def _retired_valid(key, row):
    _identifier(key)
    _object(row, {"revision"}, "retired schedule", {"revision"})
    _integer(row["revision"], "retired revision", 1)


class ScheduleStore:
    def __init__(self, state_dir):
        self.state_dir = os.fspath(state_dir)
        self._rows = keyed_state.KeyedState(os.path.join(self.state_dir, "schedules.json"),
            error=ScheduleStateError, validate=validate_schedule, durable=True)
        self._progress = keyed_state.KeyedState(os.path.join(self.state_dir, "schedule-progress.json"),
            error=ScheduleStateError, validate=_progress_valid, durable=True)
        self._retired = keyed_state.KeyedState(os.path.join(self.state_dir, "schedule-retired.json"),
            error=ScheduleStateError, validate=_retired_valid, durable=True)

    def get(self, schedule_id):
        return self._rows.get(_identifier(schedule_id))

    def list(self):
        return sorted(self._rows.snapshot().values(), key=lambda row: row["id"])

    def create(self, schedule_id, definition, *, actor, now, preview=None):
        _identifier(schedule_id)
        normalized = normalize_definition(definition)
        preview = normalize_snapshot(preview)
        def mutate(old):
            if old is not None:
                raise ScheduleConflict("schedule already exists")
            floor = (self._retired.get(schedule_id) or {}).get("revision", 0)
            row = dict(normalized, id=schedule_id, generation=uuid.uuid4().hex,
                       rev=floor + 1, created_by=actor, created_at=now, preview=preview)
            validate_schedule(schedule_id, row)
            return copy.deepcopy(row)
        return self._rows.update(schedule_id, mutate)

    def _edit(self, schedule_id, expected_rev, change):
        _identifier(schedule_id)
        def mutate(old):
            _compare(schedule_id, old, expected_rev)
            row = copy.deepcopy(old)
            change(row)
            row["rev"] += 1
            validate_schedule(schedule_id, row)
            return row
        return self._rows.update(schedule_id, mutate)

    def put(self, schedule_id, definition, *, expected_rev, preview=None):
        normalized = normalize_definition(definition)
        def change(row):
            if normalized["target"] != row["target"] and preview is None:
                raise ScheduleValidationError("retargeting requires a new server preview")
            for key in DEFINITION_KEYS:
                row.pop(key, None)
            row.update(copy.deepcopy(normalized))
            if preview is not None:
                row["preview"] = normalize_snapshot(preview)
        return self._edit(schedule_id, expected_rev, change)

    def patch(self, schedule_id, patch, *, expected_rev, preview=None):
        _object(patch, DEFINITION_KEYS, "schedule patch")
        def change(row):
            definition = {key: row[key] for key in DEFINITION_KEYS if key in row}
            # PATCH replaces complete top-level subobjects; no hidden deep merge.
            definition.update(copy.deepcopy(patch))
            if definition.get("after", False) is None:
                definition.pop("after")
            normalized = normalize_definition(definition)
            if normalized["target"] != row["target"] and preview is None:
                raise ScheduleValidationError("retargeting requires a new server preview")
            for key in DEFINITION_KEYS:
                row.pop(key, None)
            row.update(normalized)
            if preview is not None:
                row["preview"] = normalize_snapshot(preview)
        return self._edit(schedule_id, expected_rev, change)

    def reaffirm(self, schedule_id, actor, *, expected_rev):
        _actor(actor)
        return self._edit(schedule_id, expected_rev, lambda row: row.update(created_by=actor))

    def delete(self, schedule_id, *, expected_rev):
        _identifier(schedule_id)
        def mutate(old):
            _compare(schedule_id, old, expected_rev)
            # Persist the floor before physical deletion while the schedule
            # shard excludes create/edit. A crash here leaves the live row
            # intact; a completed delete can never recycle its strong ETag.
            prior = self._retired.get(schedule_id)
            self._retired.put(schedule_id, {"revision": max(old["rev"], (prior or {}).get("revision", 0))})
            return keyed_state.DELETE
        self._rows.update(schedule_id, mutate)
        return True

    def referring_schedules(self, role):
        """Include paused/completed definitions until deleted or retargeted."""
        return [row["id"] for row in self.list() if row["target"]["filters"].get("role") == role and role != "__none"]

    def progress(self, schedule_id):
        row = self.get(schedule_id)
        progress = self._progress.get(schedule_id)
        return progress if row and progress and progress["generation"] == row["generation"] else None

    def claim_occurrence(self, schedule_id, *, expected_rev, expected_generation, slot, target_snapshot, now):
        """Recheck live authority; freeze a claim before advancing its cursor.

        Lock order: schedule shard -> occurrence shard -> progress shard.
        The latter two locks are released before acquiring the next. A crash
        after the claim but before progress is repaired by the identical claim.
        """
        _identifier(schedule_id)
        _integer(expected_rev, "expected_rev", 1)
        _hex(expected_generation, "expected_generation")
        claimed = []
        def mutate(row):
            _compare(schedule_id, row, expected_rev)
            if row["generation"] != expected_generation:
                raise ScheduleConflict("schedule generation changed")
            if row["state"] != "pending":
                raise ScheduleConflict("schedule is not pending")
            _integer(now, "now", maximum=MAX_EPOCH)
            _validate_slot(slot)
            if now < slot["scheduled_at"]:
                raise ScheduleConflict("schedule window has not opened")
            occurrences = OccurrenceStore(self.state_dir)
            existing = occurrences.get(occurrence_id(row, slot["scheduled_at"]))
            if existing is None:
                current_slot = occurrence_slot(row, slot["scheduled_at"])
                if current_slot is None or any(current_slot[key] != slot[key] for key in (
                        "scheduled_at", "window_end", "resolution", "tz", "local_time", "next_at")):
                    raise ScheduleConflict("schedule slot changed")
            occurrence = existing or occurrences.create(row, slot, target_snapshot, now=now)
            progress = self._progress.get(schedule_id)
            if not progress or progress["generation"] != row["generation"] or progress["last_slot"] <= slot["scheduled_at"]:
                candidate = {"generation": row["generation"], "last_slot": slot["scheduled_at"], "active_occurrence_id": occurrence["id"]}
                _progress_valid(schedule_id, candidate)
                self._progress.put(schedule_id, candidate)
            claimed.append(occurrence)
            return None
        self._rows.update(schedule_id, mutate)
        return claimed[0]


def next_fire(schedule, now_epoch, *, after_epoch=None, metadata=False):
    """Return next firing epoch (including in-window catch-up), or None.

    ``metadata=True`` additionally exposes the slot's resolution and missed
    outcome; occurrence_slot is its named wrapper. A cursor requests the first
    slot strictly after it, allowing bounded, durable catch-up across downtime.
    No cursor selects the current/latest slot, constrained by creation time.
    """
    import datetime as dt

    _integer(now_epoch, "now", maximum=MAX_EPOCH)
    if after_epoch is not None:
        _integer(after_epoch, "after_epoch", maximum=MAX_EPOCH)
    definition = normalize_definition({key: schedule[key] for key in DEFINITION_KEYS if key in schedule})
    if definition["state"] != "pending":
        return None
    created = _integer(schedule.get("created_at", 0), "created_at", maximum=MAX_EPOCH)
    when = definition["when"]
    zone = ZoneInfo(when["tz"])
    window = when["window_seconds"]

    def resolve(local):
        def valid(candidate):
            stamps = set()
            for fold in (0, 1):
                aware = candidate.replace(tzinfo=zone, fold=fold)
                stamp = int(aware.timestamp())
                if dt.datetime.fromtimestamp(stamp, zone).replace(tzinfo=None) == candidate:
                    stamps.add(stamp)
            return sorted(stamps)
        stamps = valid(local)
        if stamps:
            return stamps[0], "fold" if len(stamps) == 2 else "normal"
        # A gap can be a half hour or a skipped civil day. UTC round trips
        # bracket its end. Binary search seconds, not a minute-by-minute scan.
        roundtrips = [dt.datetime.fromtimestamp(local.replace(tzinfo=zone, fold=fold).timestamp(), zone).replace(tzinfo=None) for fold in (0, 1)]
        upper = min(value for value in roundtrips if value > local)
        low, high = 0, int((upper - local).total_seconds())
        while low < high:
            middle = (low + high) // 2
            if valid(local + dt.timedelta(seconds=middle)):
                high = middle
            else:
                low = middle + 1
        return valid(local + dt.timedelta(seconds=low))[0], "gap"

    def weekly_at(day):
        local = dt.datetime.combine(day, dt.time(when["hour"], when["minute"]))
        stamp, resolution = resolve(local)
        return stamp, resolution, local.isoformat(timespec="minutes")

    if when["kind"] == "once":
        stamp = when["at"]
        if after_epoch is not None and stamp <= after_epoch:
            return None
        resolution = "normal"
        local_label = dt.datetime.fromtimestamp(stamp, zone).isoformat(timespec="seconds")
        next_at = None
    else:
        anchor = max(created, after_epoch + 1 if after_epoch is not None else now_epoch)
        date = dt.datetime.fromtimestamp(anchor, zone).date()
        day = date - dt.timedelta(days=(date.weekday() - when["weekday"]) % 7)
        stamp, resolution, local_label = weekly_at(day)
        floor = max(created, after_epoch + 1 if after_epoch is not None else 0)
        while stamp < floor:
            day += dt.timedelta(days=7)
            stamp, resolution, local_label = weekly_at(day)
        if after_epoch is None and stamp > now_epoch:
            prior_day = day - dt.timedelta(days=7)
            prior_stamp, prior_resolution, prior_label = weekly_at(prior_day)
            if prior_stamp >= created and prior_stamp <= now_epoch < prior_stamp + window:
                day, stamp, resolution, local_label = prior_day, prior_stamp, prior_resolution, prior_label
        # Today's later local slot is the future slot; otherwise this is
        # the most recent slot, including a missed slot after downtime.
        next_at = weekly_at(day + dt.timedelta(days=7))[0]
    end = stamp + window
    status = "future" if now_epoch < stamp else "due" if now_epoch < end else "missed"
    if metadata:
        return {"scheduled_at": stamp, "window_end": end, "status": status,
                "resolution": resolution, "tz": when["tz"], "local_time": local_label,
                "next_at": next_at}
    if status != "missed":
        return stamp
    if next_at is None:
        return None
    # Cursor-based callers use metadata to record each missed slot. The
    # scalar interface still promises a dispatchable/future instant.
    if next_at + window <= now_epoch:
        return next_fire(schedule, now_epoch)
    return next_at


def occurrence_slot(schedule, now_epoch, *, after_epoch=None):
    return next_fire(schedule, now_epoch, after_epoch=after_epoch, metadata=True)


def occurrence_id(schedule, scheduled_at):
    _hex(schedule["generation"], "generation")
    _integer(scheduled_at, "scheduled_at", maximum=MAX_EPOCH)
    return hashlib.sha256((schedule["generation"] + ":" + str(scheduled_at)).encode("ascii")).hexdigest()[:32]


def _validate_slot(slot):
    keys = {"scheduled_at", "window_end", "status", "resolution", "tz", "local_time", "next_at"}
    _object(slot, keys, "slot", keys)
    _integer(slot["scheduled_at"], "scheduled_at", maximum=MAX_EPOCH)
    _integer(slot["window_end"], "window_end", slot["scheduled_at"] + 1, slot["scheduled_at"] + MAX_WINDOW_SECONDS)
    if slot["status"] not in ("future", "due", "missed") or slot["resolution"] not in ("normal", "gap", "fold"):
        raise ScheduleValidationError("invalid slot state")
    _text(slot["tz"], "timezone", 128)
    _text(slot["local_time"], "local_time", 64)
    if slot["next_at"] is not None:
        _integer(slot["next_at"], "next_at", slot["scheduled_at"] + 1, MAX_EPOCH)


def _validate_occurrence(key, row):
    keys = {"id", "schedule_id", "schedule_generation", "schedule_rev", "schedule", "actor", "slot", "scheduled_at", "window_end", "state", "preview", "target_snapshot", "delta", "created_at", "updated_at"}
    _object(row, keys, "occurrence", keys - {"target_snapshot", "delta"})
    _hex(key, "occurrence id")
    validate_schedule(row["schedule_id"], row["schedule"])
    if (row["id"] != key or occurrence_id(row["schedule"], row["scheduled_at"]) != key or
            row["schedule_generation"] != row["schedule"]["generation"] or
            type(row["schedule_rev"]) is not int or row["schedule_rev"] != row["schedule"]["rev"] or
            row["actor"] != "schedule:" + row["schedule_id"]):
        raise ScheduleValidationError("occurrence authority mismatch")
    _validate_slot(row["slot"])
    _integer(row["scheduled_at"], "scheduled_at", maximum=MAX_EPOCH)
    _integer(row["window_end"], "window_end", maximum=MAX_EPOCH)
    if row["scheduled_at"] != row["slot"]["scheduled_at"] or row["window_end"] != row["slot"]["window_end"]:
        raise ScheduleValidationError("occurrence window mismatch")
    if not isinstance(row["state"], str) or row["state"] not in OCCURRENCE_TRANSITIONS:
        raise ScheduleValidationError("invalid occurrence state")
    normalize_snapshot(row["preview"])
    _integer(row["created_at"], "occurrence created_at", maximum=MAX_EPOCH)
    _integer(row["updated_at"], "occurrence updated_at", row["created_at"], MAX_EPOCH)
    if row["state"] == "missed":
        if ("target_snapshot" in row or "delta" in row or row["created_at"] < row["window_end"]
                or row["slot"]["status"] != "missed"):
            raise ScheduleValidationError("missed occurrence must be expired and unbound")
    else:
        if not {"target_snapshot", "delta"} <= set(row):
            raise ScheduleValidationError("dispatchable occurrence needs a bound target")
        normalize_snapshot(row["target_snapshot"])
        _object(row["delta"], {"added", "removed"}, "target delta", {"added", "removed"})
        prior, fired = set(row["preview"]["device_ids"]), set(row["target_snapshot"]["device_ids"])
        for field, expected in (("added", len(fired - prior)), ("removed", len(prior - fired))):
            _integer(row["delta"][field], field, maximum=MAX_TARGETS)
            if row["delta"][field] != expected:
                raise ScheduleValidationError("occurrence target delta mismatch")


class OccurrenceStore:
    def __init__(self, state_dir):
        self._rows = keyed_state.KeyedState(os.path.join(os.fspath(state_dir), "schedule-occurrences.json"),
            error=ScheduleStateError, validate=_validate_occurrence, durable=True)

    def get(self, identifier):
        return self._rows.get(_hex(identifier, "occurrence id"))

    def list(self, schedule_id=None):
        if schedule_id is not None:
            _identifier(schedule_id)
        return sorted((row for row in self._rows.snapshot().values() if schedule_id is None or row["schedule_id"] == schedule_id), key=lambda row: (row["scheduled_at"], row["id"]))

    def create(self, schedule, slot, target_snapshot, *, now):
        validate_schedule(schedule["id"], schedule)
        _validate_slot(slot)
        _integer(now, "now", maximum=MAX_EPOCH)
        identifier = occurrence_id(schedule, slot["scheduled_at"])
        def mutate(old):
            if old is not None:
                return old
            preview = normalize_snapshot(schedule["preview"])
            missed = now >= slot["window_end"]
            if missed and target_snapshot is not None:
                raise ScheduleValidationError("missed occurrence must not claim a target snapshot")
            frozen_slot = dict(slot, status="missed" if missed else "future" if now < slot["scheduled_at"] else "due")
            row = {"id": identifier, "schedule_id": schedule["id"],
                   "schedule_generation": schedule["generation"], "schedule_rev": schedule["rev"],
                   "schedule": copy.deepcopy(schedule), "actor": "schedule:" + schedule["id"],
                   "slot": frozen_slot, "scheduled_at": slot["scheduled_at"],
                   "window_end": slot["window_end"], "state": "missed" if missed else "pending", "preview": preview,
                   "created_at": now, "updated_at": now}
            if not missed:
                snapshot = normalize_snapshot(target_snapshot)
                if schedule["target"]["bind"] == "early":
                    snapshot["device_ids"] = list(preview["device_ids"])
                prior, fired = set(preview["device_ids"]), set(snapshot["device_ids"])
                row.update(target_snapshot=snapshot, delta={"added": len(fired - prior), "removed": len(prior - fired)})
            _validate_occurrence(identifier, row)
            return row
        return self._rows.update(identifier, mutate)

    def transition(self, identifier, state, *, now, expected_state=None):
        _hex(identifier, "occurrence id")
        _integer(now, "now", maximum=MAX_EPOCH)
        def mutate(old):
            if old is None:
                raise ScheduleNotFound("no such occurrence")
            if expected_state is not None and old["state"] != expected_state:
                raise ScheduleConflict("occurrence state changed")
            if state == old["state"]:
                return old
            if state == "missed":
                raise ScheduleConflict("a bound occurrence cannot become an unbound missed slot")
            if not isinstance(state, str) or state not in OCCURRENCE_TRANSITIONS[old["state"]]:
                raise ScheduleConflict("invalid occurrence transition")
            row = dict(old, state=state, updated_at=max(now, old["updated_at"]))
            _validate_occurrence(identifier, row)
            return row
        return self._rows.update(identifier, mutate)

    def recover_interrupted(self, *, now):
        recovered = []
        for row in self.list():
            if row["state"] == "running":
                try:
                    self.transition(row["id"], "interrupted", now=now, expected_state="running")
                except ScheduleConflict:
                    continue
                recovered.append(row["id"])
        return recovered

    def latest_slot(self, schedule):
        slots = [row["scheduled_at"] for row in self.list(schedule["id"]) if row["schedule_generation"] == schedule["generation"]]
        return max(slots) if slots else None


_RECEIPT_REQUIRED = {"occurrence_id", "device_id", "rev", "attempt", "attempt_started_at",
                     "predecessors", "status", "reason", "created_at", "updated_at", "completed_at", "notes"}
_RECEIPT_OPTIONAL = {"job_id", "record_id", "predecessor_record_id", "manual_generation",
                     "before_image_ids", "after_image_ids", "removed_image_ids"}


def _validate_receipt(key, row, *, history=True):
    _object(row, _RECEIPT_REQUIRED | _RECEIPT_OPTIONAL, "receipt", _RECEIPT_REQUIRED)
    _device_id(key)
    if row["device_id"] != key:
        raise ScheduleValidationError("receipt key mismatch")
    _hex(row["occurrence_id"], "occurrence id")
    _integer(row["rev"], "receipt rev", 1)
    _integer(row["attempt"], "receipt attempt", 1, MAX_RECEIPT_ATTEMPTS)
    if not isinstance(row["status"], str) or row["status"] not in RECEIPT_STATES:
        raise ScheduleValidationError("invalid receipt status")
    if not isinstance(row["reason"], str) or not _REASON_RE.fullmatch(row["reason"]):
        raise ScheduleValidationError("invalid receipt reason")
    _integer(row["created_at"], "receipt created_at", maximum=MAX_EPOCH)
    _integer(row["updated_at"], "receipt updated_at", row["created_at"], MAX_EPOCH)
    _integer(row["attempt_started_at"], "attempt_started_at", row["created_at"], row["updated_at"])
    if row["status"] in TERMINAL_RECEIPT_STATES:
        _integer(row["completed_at"], "completed_at", row["attempt_started_at"], row["updated_at"])
    elif row["completed_at"] is not None:
        raise ScheduleValidationError("nonterminal receipt has completion time")
    if not isinstance(row["notes"], list) or len(row["notes"]) > 16:
        raise ScheduleValidationError("invalid receipt notes")
    for note in row["notes"]:
        if not isinstance(note, str) or not _REASON_RE.fullmatch(note):
            raise ScheduleValidationError("invalid receipt note")
    for field in ("job_id", "record_id", "predecessor_record_id"):
        if field in row:
            _identifier(row[field], field)
    if "manual_generation" in row:
        _integer(row["manual_generation"], "manual_generation")
    for field in ("before_image_ids", "after_image_ids", "removed_image_ids"):
        if field in row:
            _ids(row[field], "image_ids", maximum=10)
    if {"after_image_ids", "removed_image_ids"} & set(row) and row["status"] not in TERMINAL_RECEIPT_STATES:
        raise ScheduleValidationError("assignment outcomes require a terminal receipt")
    if {"before_image_ids", "after_image_ids", "removed_image_ids"} <= set(row):
        if set(row["removed_image_ids"]) != set(row["before_image_ids"]) - set(row["after_image_ids"]):
            raise ScheduleValidationError("assignment removal evidence disagrees")
    predecessors = row["predecessors"]
    if not isinstance(predecessors, list) or len(predecessors) >= MAX_RECEIPT_ATTEMPTS:
        raise ScheduleValidationError("invalid receipt predecessors")
    if not history:
        if predecessors:
            raise ScheduleValidationError("nested receipt predecessors")
        return
    if row["attempt"] != len(predecessors) + 1:
        raise ScheduleValidationError("receipt attempt lineage disagrees")
    last_rev = 0
    for index, prior in enumerate(predecessors, 1):
        _object(prior, (_RECEIPT_REQUIRED | _RECEIPT_OPTIONAL) - {"predecessors"}, "predecessor receipt", _RECEIPT_REQUIRED - {"predecessors"})
        _validate_receipt(key, dict(prior, predecessors=[]), history=False)
        if (prior["attempt"] != index or prior["occurrence_id"] != row["occurrence_id"] or
                prior["created_at"] != row["created_at"] or not last_rev < prior["rev"] < row["rev"] or
                prior["status"] in TERMINAL_RECEIPT_STATES or prior["updated_at"] > row["attempt_started_at"]):
            raise ScheduleValidationError("invalid predecessor provenance")
        last_rev = prior["rev"]


class ReceiptStore:
    """Per-occurrence evidence with CAS-protected, bounded attempt lineage.

    Every nonterminal update requires its current revision. Ownership fields
    bind once per attempt. A successor retains the old attempt in full and
    cannot be created after a terminal outcome. Response caps never prune the
    durable terminal IDs used to suppress replay.
    """
    def __init__(self, state_dir):
        self.state_dir = os.fspath(state_dir)
        self.directory = os.path.join(self.state_dir, "schedule-receipts")

    def _rows(self, identifier):
        _hex(identifier, "occurrence id")
        def validate(key, row):
            _validate_receipt(key, row)
            if row["occurrence_id"] != identifier:
                raise ScheduleValidationError("receipt occurrence mismatch")
        return keyed_state.KeyedState(os.path.join(self.directory, identifier + ".json"),
            error=ScheduleStateError, validate=validate, durable=True)

    def _admit(self, identifier, device_id):
        _device_id(device_id)
        occurrence = OccurrenceStore(self.state_dir).get(identifier)
        if occurrence is None:
            raise ScheduleNotFound("no such occurrence")
        if occurrence["state"] == "missed" or device_id not in occurrence["target_snapshot"]["device_ids"]:
            raise ScheduleConflict("device has no bound occurrence target")

    def get(self, identifier, device_id):
        return self._rows(identifier).get(_device_id(device_id))

    def begin(self, identifier, device_id, *, now, manual_generation=None,
              before_image_ids=None, predecessor_record_id=None):
        return self.record(identifier, device_id, status="intent", reason="pending", now=now,
                           manual_generation=manual_generation, before_image_ids=before_image_ids,
                           predecessor_record_id=predecessor_record_id)

    def record(self, identifier, device_id, *, status, reason, now, notes=None,
               expected_status=None, expected_rev=None, job_id=None, record_id=None,
               predecessor_record_id=None, manual_generation=None, before_image_ids=None,
               after_image_ids=None, removed_image_ids=None):
        self._admit(identifier, device_id)
        _integer(now, "now", maximum=MAX_EPOCH)
        if not isinstance(status, str) or status not in RECEIPT_STATES:
            raise ScheduleValidationError("invalid receipt status")
        if notes is not None and not isinstance(notes, list):
            raise ScheduleValidationError("receipt notes must be a list")
        if expected_rev is not None:
            _integer(expected_rev, "expected receipt rev", 1)
        supplied = {key: value for key, value in {
            "job_id": job_id, "record_id": record_id, "predecessor_record_id": predecessor_record_id,
            "manual_generation": manual_generation, "before_image_ids": before_image_ids,
            "after_image_ids": after_image_ids, "removed_image_ids": removed_image_ids}.items() if value is not None}
        def mutate(old):
            if old is not None and old["status"] in TERMINAL_RECEIPT_STATES:
                return old
            if old is not None and status == "intent":
                # begin is create-if-absent, never an implicit attempt reset.
                return old
            if old is not None and (expected_rev is None or old["rev"] != expected_rev):
                raise ScheduleConflict("receipt revision is required and must match")
            if old is None and expected_rev is not None:
                raise ScheduleConflict("receipt revision changed")
            if expected_status is not None and (old or {}).get("status") != expected_status:
                raise ScheduleConflict("receipt state changed")
            if old is not None:
                for field in ("job_id", "record_id", "predecessor_record_id", "manual_generation", "before_image_ids"):
                    if field in old and field in supplied and old[field] != supplied[field]:
                        raise ScheduleConflict("receipt attempt ownership is immutable")
                if status not in TERMINAL_RECEIPT_STATES:
                    ranks = {"intent": 0, "submitted": 1, "running": 2}
                    if ranks[status] < ranks[old["status"]]:
                        raise ScheduleConflict("invalid receipt transition")
            timestamp = max(now, old["updated_at"]) if old else now
            row = dict(old or {}, occurrence_id=identifier, device_id=device_id, status=status,
                       rev=old["rev"] + 1 if old else 1, attempt=old["attempt"] if old else 1,
                       attempt_started_at=old["attempt_started_at"] if old else now,
                       predecessors=copy.deepcopy(old["predecessors"]) if old else [],
                       reason=reason, created_at=old["created_at"] if old else now,
                       updated_at=timestamp, completed_at=timestamp if status in TERMINAL_RECEIPT_STATES else None,
                       notes=copy.deepcopy(notes) if notes is not None else (old or {}).get("notes", []))
            row.update(copy.deepcopy(supplied))
            _validate_receipt(device_id, row)
            return row
        return self._rows(identifier).update(device_id, mutate)

    def successor_attempt(self, identifier, device_id, *, expected_rev, now,
                          manual_generation, predecessor_record_id=None, before_image_ids=None):
        """Start a recovery attempt with new CAS and immutable predecessor evidence."""
        self._admit(identifier, device_id)
        _integer(expected_rev, "expected receipt rev", 1)
        _integer(now, "now", maximum=MAX_EPOCH)
        _integer(manual_generation, "manual_generation")
        def mutate(old):
            if old is None or old["rev"] != expected_rev:
                raise ScheduleConflict("receipt revision changed")
            if old["status"] in TERMINAL_RECEIPT_STATES or old["attempt"] >= MAX_RECEIPT_ATTEMPTS:
                raise ScheduleConflict("receipt cannot start another attempt")
            predecessor = predecessor_record_id if predecessor_record_id is not None else old.get("record_id")
            if old.get("record_id") is not None and predecessor != old["record_id"]:
                raise ScheduleConflict("predecessor record ownership changed")
            timestamp = max(now, old["updated_at"])
            row = {"occurrence_id": identifier, "device_id": device_id,
                   "rev": old["rev"] + 1, "attempt": old["attempt"] + 1,
                   "attempt_started_at": timestamp, "created_at": old["created_at"], "updated_at": timestamp,
                   "status": "intent", "reason": "pending", "completed_at": None, "notes": [],
                   "manual_generation": manual_generation,
                   "predecessors": copy.deepcopy(old["predecessors"]) + [{key: copy.deepcopy(value) for key, value in old.items() if key != "predecessors"}]}
            if predecessor is not None:
                row["predecessor_record_id"] = predecessor
            before = before_image_ids if before_image_ids is not None else old.get("before_image_ids")
            if before is not None:
                row["before_image_ids"] = copy.deepcopy(before)
            _validate_receipt(device_id, row)
            return row
        return self._rows(identifier).update(device_id, mutate)

    def list(self, identifier, *, limit=MAX_RECEIPT_PAGE, offset=0):
        _integer(limit, "receipt limit", 1, MAX_RECEIPT_PAGE)
        _integer(offset, "receipt offset")
        rows = sorted(self._rows(identifier).snapshot().values(), key=lambda row: row["device_id"])
        return {"receipts": rows[offset:offset + limit], "total": len(rows),
                "offset": offset, "truncated": offset > 0 or offset + limit < len(rows)}

    def completed_device_ids(self, identifier):
        return {key for key, row in self._rows(identifier).snapshot().items() if row["status"] in TERMINAL_RECEIPT_STATES}
