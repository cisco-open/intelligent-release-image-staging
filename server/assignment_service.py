# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Fleet-aware assignment operations shared by operator entry points.

Lock order is role coordinator outer lock -> membership_guard -> catalog's
self-acquired image-policy lock -> shard locks. The membership guard is a
NON-REENTRANT cross-process flock: never acquire it twice or hold an image-policy
lock before calling apply/set_policy. Retirement must hold the same guard from
fleet deletion through catalog purge. Direct CatalogStore.set_policy remains a
low-level bootstrap operation and deliberately has no fleet prerequisite.
"""
import contextlib
from dataclasses import dataclass
import json
import math
import sqlite3

import audit
import catalog
import secrets_store


class MissingFleetDevice(ValueError):
    """An assignment target is absent from the operator fleet."""


class AssignmentAuthorityUnavailable(RuntimeError):
    """Durable assignment authority cannot safely authorize scheduled work."""


@dataclass(frozen=True)
class ScheduledAssignmentContext:
    """Internal occurrence identity; commit_guard holds final external authority.

    The caller may hold the role coordinator. The optional factory acquires
    secrets/revocation authority AFTER this service acquires fleet membership,
    and must retain it through the catalog commit. It must not reacquire fleet
    membership or perform network operations.
    """

    schedule_id: str
    schedule_rev: int
    occurrence_id: str
    expected_manual_generation: int
    commit_guard: object = None

    def __post_init__(self):
        for value in (self.schedule_id, self.occurrence_id):
            if not isinstance(value, str) or not value or len(value) > 256:
                raise ValueError("invalid assignment occurrence identity")
        if type(self.schedule_rev) is not int or self.schedule_rev < 1:
            raise ValueError("invalid schedule revision")
        if (type(self.expected_manual_generation) is not int
                or self.expected_manual_generation < 0):
            raise ValueError("invalid manual generation")
        if self.commit_guard is not None and not callable(self.commit_guard):
            raise ValueError("invalid assignment commit guard")


@dataclass(frozen=True)
class ScheduledAssignmentRefusal:
    """A terminal scheduled refusal, never an ordinary retryable CAS error."""

    reason: str
    before_ids: list
    after_ids: list
    removed_ids: list


def membership_guard(fleet):
    """Return the non-reentrant fleet lifetime lock; see module lock order."""
    return secrets_store.store_lock(fleet.path + ".membership")


def _safe(value, limit=256):
    return "".join(c for c in str(value) if c.isprintable())[:limit]


def _size(value):
    try:
        number = float(value)
        if not math.isfinite(number):
            return "?"
    except (TypeError, ValueError, OverflowError):
        return "?"
    if number < 1024:
        return "%d B" % int(number)
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        number /= 1024.0
        if number < 1024 or unit == "TiB":
            return "%s %s" % (("%.1f" % number).rstrip("0").rstrip("."), unit)


class AssignmentService:
    def __init__(self, store, fleet, audit_path=None, *, authority_path=None):
        """Use one authority_path under IRIS_STATE for every production caller.

        The optional default preserves legacy/manual construction, but cannot
        capture or execute scheduled work. Authority does not belong beside
        fleet.path, which can refer to separately mounted operator inventory.
        """
        self.store = store
        self.fleet = fleet
        self.audit_path = audit_path
        self.authority_path = authority_path

    @contextlib.contextmanager
    def _authority(self):
        """Open strict durable authority only inside the membership guard.

        SQLite commits each intent/result before proceeding. It does not make
        the separate catalog transaction atomic: incomplete claims are a
        conflict, and incomplete manual writes block scheduling until another
        accepted manual operation establishes explicit operator intent.
        """
        if self.authority_path is None:
            raise AssignmentAuthorityUnavailable("assignment authority unavailable")
        try:
            conn = sqlite3.connect(self.authority_path, isolation_level=None)
            try:
                conn.execute("PRAGMA synchronous=FULL")
                version = conn.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, 1):
                    raise AssignmentAuthorityUnavailable("unsupported assignment authority")
                conn.execute("CREATE TABLE IF NOT EXISTS authority ("
                             "device_id TEXT PRIMARY KEY, "
                             "manual_generation INTEGER NOT NULL CHECK(manual_generation >= 0), "
                             "manual_pending INTEGER NOT NULL CHECK(manual_pending IN (0, 1)))")
                conn.execute("CREATE TABLE IF NOT EXISTS claims ("
                             "occurrence_id TEXT NOT NULL, device_id TEXT NOT NULL, "
                             "schedule_id TEXT NOT NULL, "
                             "request_json TEXT NOT NULL, result_json TEXT, "
                             "PRIMARY KEY (occurrence_id, device_id))")
                conn.execute("CREATE INDEX IF NOT EXISTS claims_schedule_device "
                             "ON claims (schedule_id, device_id)")
                conn.execute("PRAGMA user_version=1")
                yield conn
            finally:
                conn.close()
        except sqlite3.Error as exc:
            raise AssignmentAuthorityUnavailable("assignment authority unavailable") from exc

    @staticmethod
    def _generation(conn, device_id):
        conn.execute("INSERT OR IGNORE INTO authority VALUES (?, 0, 0)", (device_id,))
        row = conn.execute("SELECT manual_generation, manual_pending FROM authority "
                           "WHERE device_id=?", (device_id,)).fetchone()
        if (row is None or type(row[0]) is not int or row[0] < 0
                or type(row[1]) is not int or row[1] not in (0, 1)):
            raise AssignmentAuthorityUnavailable("invalid assignment authority")
        return row

    def capture_schedule_state(self, device_id):
        """Capture durable manual generation and policy under fleet exclusion."""
        if self.fleet is None:
            raise MissingFleetDevice("no such fleet device")
        with membership_guard(self.fleet):
            if self.fleet.get_device(device_id) is None:
                raise MissingFleetDevice("no such fleet device")
            with self._authority() as conn:
                generation, pending = self._generation(conn, device_id)
                if pending:
                    raise AssignmentAuthorityUnavailable("manual assignment outcome uncertain")
                return {"manual_generation": generation,
                        "before_image_ids": self.store.get_policy(device_id)["approved_image_ids"]}

    def acknowledge_schedule_result(self, occurrence_id, device_id):
        """Release replay evidence only AFTER a durable terminal receipt save.

        The runner must never dispatch an acknowledged terminal receipt again.
        Returns True for a removed/already absent claim, False for an incomplete
        claim, which remains conservative conflict evidence. No implicit expiry
        or newer occurrence can remove an unacknowledged result. A retired
        device's completed claims can still be acknowledged.
        """
        if not all(isinstance(value, str) and value for value in (occurrence_id, device_id)):
            raise ValueError("invalid assignment claim identity")
        if self.fleet is None:
            raise AssignmentAuthorityUnavailable("assignment authority unavailable")
        with membership_guard(self.fleet):
            with self._authority() as conn:
                conn.execute("DELETE FROM claims WHERE occurrence_id=? AND device_id=? "
                             "AND result_json IS NOT NULL", (occurrence_id, device_id))
                return conn.execute("SELECT 1 FROM claims WHERE occurrence_id=? AND device_id=?",
                                    (occurrence_id, device_id)).fetchone() is None

    def _apply_guarded(self, device_id, requested, mode, expect_image_ids,
                       retry_conflict, scheduled_context, before):
        # Legacy callers without a configured authority keep manual behavior;
        # scheduled work must never fall back to volatile authority.
        authority = (self._authority() if self.authority_path is not None
                     or scheduled_context is not None else contextlib.nullcontext(None))
        with authority as conn:
            generation, pending = self._generation(conn, device_id) if conn is not None else (0, 0)
            context = scheduled_context
            if context is not None:
                request = json.dumps({"schema_version": 1,
                    "schedule_id": context.schedule_id, "schedule_rev": context.schedule_rev,
                    "occurrence_id": context.occurrence_id, "device_id": device_id,
                    "manual_generation": context.expected_manual_generation,
                    "mode": mode, "image_ids": requested,
                    "expect_image_ids": expect_image_ids,
                    "retry_conflict": retry_conflict}, sort_keys=True)
                claim = conn.execute("SELECT request_json, result_json FROM claims "
                                     "WHERE occurrence_id=? AND device_id=?",
                                     (context.occurrence_id, device_id)).fetchone()
                if claim is not None:
                    if claim[0] != request or claim[1] is None:
                        return ScheduledAssignmentRefusal("conflict", before, before, []), False
                    try:
                        saved = json.loads(claim[1])
                        if (not isinstance(saved, dict)
                                or set(saved) != {"before_ids", "after_ids", "removed_ids"}
                                or not all(isinstance(ids, list) and all(isinstance(i, str) for i in ids)
                                           for ids in saved.values())):
                            raise ValueError("invalid result")
                        return catalog.AssignmentResult(**saved), True
                    except (TypeError, ValueError) as exc:
                        raise AssignmentAuthorityUnavailable("invalid assignment result") from exc
                if generation != context.expected_manual_generation:
                    return ScheduledAssignmentRefusal("manual_override", before, before, []), False
                if pending:
                    return ScheduledAssignmentRefusal("conflict", before, before, []), False
                # A result can precede its durable terminal runner receipt.
                # Newer occurrences must retain that replay evidence until the
                # runner explicitly acknowledges the receipt after saving it.
                conn.execute("INSERT INTO claims VALUES (?, ?, ?, ?, NULL)",
                             (context.occurrence_id, device_id, context.schedule_id, request))
            elif conn is not None:
                conn.execute("UPDATE authority SET manual_pending=1 WHERE device_id=?", (device_id,))
            try:
                for attempt in range(2 if retry_conflict else 1):
                    ids = list(dict.fromkeys(before + requested)) if mode == "merge" else requested
                    expected = before if mode == "merge" or retry_conflict else expect_image_ids
                    for iid in ids:
                        if self.store.get_image(iid) is None:
                            raise ValueError("no such image")
                    try:
                        result = self.store.set_policy(
                            device_id, approved_image_ids=ids,
                            expect_image_ids=expected, skip_unchanged=True)
                        break
                    except catalog.PolicyConflict as exc:
                        before[:] = exc.current_ids
                        if not retry_conflict or attempt == 1:
                            raise
                        before[:] = self.store.get_policy(device_id)["approved_image_ids"]
            except (ValueError, catalog.PolicyConflict, catalog.QuarantinedImage):
                # These catalog exceptions are known refusals before mutation.
                # Other failures retain intent, since commit may have happened.
                if context is not None:
                    conn.execute("DELETE FROM claims WHERE occurrence_id=? AND device_id=?",
                                 (context.occurrence_id, device_id))
                elif conn is not None:
                    conn.execute("UPDATE authority SET manual_pending=? WHERE device_id=?",
                                 (pending, device_id))
                raise
            if context is not None:
                conn.execute("UPDATE claims SET result_json=? WHERE occurrence_id=? AND device_id=?",
                             (json.dumps({"before_ids": result.before_ids,
                                          "after_ids": result.after_ids,
                                          "removed_ids": result.removed_ids}),
                              context.occurrence_id, device_id))
            elif conn is not None:
                conn.execute("UPDATE authority SET manual_generation=manual_generation+1, "
                             "manual_pending=0 WHERE device_id=?", (device_id,))
            return result, False

    def apply(self, device_id, image_ids, *, actor, mode="replace",
              expect_image_ids=None, retry_conflict=False, plural=True,
              scheduled_context=None):
        """Apply replacement or ordered-unique merge, with one outcome audit.

        CLI and scheduled callers opt into retry_conflict: at most two CAS attempts,
        rebuilding a merge from the new snapshot after the first conflict.
        API replacement retains its caller-supplied CAS and does not retry.
        The returned before/after/removed IDs come from the successful shard
        callback, never the optimistic pre-read. Audit append is best-effort,
        separate from the assignment commit, and never retried.
        """
        before = []
        requested = []
        try:
            if mode not in ("merge", "replace"):
                raise ValueError("unknown assignment mode")
            if not isinstance(image_ids, list) or not all(
                    isinstance(iid, str) and iid for iid in image_ids):
                raise ValueError("image_ids must be a list of image ids")
            requested = list(image_ids)
            if self.fleet is None:
                raise MissingFleetDevice("no such fleet device")
            with membership_guard(self.fleet):
                if self.fleet.get_device(device_id) is None:
                    raise MissingFleetDevice("no such fleet device")
                before = self.store.get_policy(device_id)["approved_image_ids"]
                if scheduled_context is not None and not isinstance(
                        scheduled_context, ScheduledAssignmentContext):
                    raise ValueError("invalid scheduled assignment context")
                guard = (scheduled_context.commit_guard() if scheduled_context is not None
                         and scheduled_context.commit_guard is not None else contextlib.nullcontext())
                with guard:
                    result, replayed = self._apply_guarded(
                        device_id, requested, mode, expect_image_ids,
                        retry_conflict, scheduled_context, before)
        except Exception as exc:
            if isinstance(exc, MissingFleetDevice):
                reason = "no such fleet device"
            elif isinstance(exc, catalog.PolicyConflict):
                reason = "assignment conflict"
            elif isinstance(exc, catalog.QuarantinedImage):
                reason = "image quarantined"
            elif isinstance(exc, ValueError):
                reason = "invalid assignment"
                if str(exc) in ("no such image", "duplicate image id in assignment",
                                "at most %d images per device" % catalog.MAX_ASSIGNED_IMAGES):
                    reason = str(exc)
            else:
                reason = "assignment state unavailable"
            self._audit(device_id, actor, requested, before, before, [],
                        "assignment failed: " + reason, "fail")
            raise
        if isinstance(result, ScheduledAssignmentRefusal):
            self._audit(device_id, actor, requested, before, before, [],
                        "assignment failed: " + result.reason, "fail")
        elif not replayed:
            self._audit_success(device_id, actor, result, plural)
        return result

    def _names(self, ids):
        return ", ".join(_safe((self.store.get_image(iid) or {}).get("filename") or iid)
                         for iid in ids)

    def _audit_success(self, device_id, actor, result, plural):
        # A post-commit lookup or logging failure must not turn success into a
        # reported failure and invite a second operation from the caller.
        try:
            ids = result.after_ids
            if not ids:
                detail = "unassigned (was %s)" % (self._names(result.before_ids) or "none")
            elif plural:
                detail = "assigned %d image(s): %s" % (len(ids), self._names(ids))
                if result.removed_ids:
                    detail += "; removed: " + self._names(result.removed_ids)
            else:
                entry = self.store.get_image(ids[0]) or {}
                detail = "assigned %s (%s) id=%s" % (
                    _safe(entry.get("filename") or ids[0]), _size(entry.get("size")), _safe(ids[0]))
                old = result.before_ids[0] if result.before_ids else None
                if old and old != ids[0]:
                    detail += ", was " + self._names([old])
        except Exception:
            detail = "assigned %d image(s)" % len(result.after_ids) if result.after_ids else "unassigned"
        self._audit(device_id, actor, result.after_ids, result.before_ids,
                    result.after_ids, result.removed_ids, detail, "ok")

    def _audit(self, device_id, actor, requested, before, after, removed, detail, result):
        if self.audit_path is None:
            return
        try:
            for name, ids in (("before_ids", before), ("after_ids", after),
                              ("removed_ids", removed)):
                detail += "; %s=%s" % (name, json.dumps([_safe(iid) for iid in ids]))
            audit.append_event(
                self.audit_path, "device_assign", actor=_safe(actor), category="device",
                action="assign" if requested else "unassign", target=_safe(device_id),
                detail=_safe(detail, 16384), result=result)
        except Exception:
            pass
