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
import json
import math

import audit
import catalog
import secrets_store


class MissingFleetDevice(ValueError):
    """An assignment target is absent from the operator fleet."""


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
    def __init__(self, store, fleet, audit_path=None):
        self.store = store
        self.fleet = fleet
        self.audit_path = audit_path

    def apply(self, device_id, image_ids, *, actor, mode="replace",
              expect_image_ids=None, retry_conflict=False, plural=True):
        """Apply replacement or ordered-unique merge, with one outcome audit.

        Only CLI callers opt into retry_conflict: at most two CAS attempts,
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
                for attempt in range(2 if retry_conflict else 1):
                    ids = list(dict.fromkeys(before + requested)) if mode == "merge" else requested
                    expected = before if mode == "merge" or retry_conflict else expect_image_ids
                    # Application entry points require published images even
                    # when catalog.json is absent (low-level bootstrap does not).
                    for iid in ids:
                        if self.store.get_image(iid) is None:
                            raise ValueError("no such image")
                    try:
                        result = self.store.set_policy(
                            device_id, approved_image_ids=ids,
                            expect_image_ids=expected, skip_unchanged=True)
                        break
                    except catalog.PolicyConflict as exc:
                        before = list(exc.current_ids)
                        if not retry_conflict or attempt == 1:
                            raise
                        before = self.store.get_policy(device_id)["approved_image_ids"]
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
