# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Coordinate declared fleet roles with compiled peer-policy membership.

Fleet inventory and peer policy deliberately remain separate stores.  Every
writer that changes role membership enters this coordinator first so the
cross-store transaction is serialized across both API threads and direct CLI
processes.

Lock order is a hard invariant::

    role-management transaction lock
      -> fleet membership guard
        -> catalog image-policy lock
          -> keyed-state shard locks

Role-only operations may go directly from the role transaction lock to the
fleet/keyed-state or peer-policy locks. Device retirement uses the complete
order above so an assignment cannot land after fleet deletion.

No callback from either inner store may enter this coordinator.  In
particular, callers must never hold the peer-policy umbrella lock before
calling a method here; that reverse order can deadlock another process which
has already declared the fleet phase and is waiting to compile policy.
"""
import contextlib
import json
import os
import time

import assignment_service
import gui_fleet
import peer_policy
import secrets_store


DRIFT_ID_LIMIT = 10


class RoleManagementError(RuntimeError):
    """Stable coordinator refusal or partial two-store failure."""

    def __init__(self, message, code="role_management_error", status=422,
                 partial=False, result=None, **details):
        self.code = code
        self.status = int(status)
        self.partial = bool(partial)
        self.details = dict(details)
        self.result = dict(result or {})
        self.result.setdefault("ok", False)
        self.result.setdefault("error", code)
        self.result.setdefault("partial", self.partial)
        self.result.update(self.details)
        super().__init__(message)


def _role_value(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise RoleManagementError("role must be a string or null",
                                  code="bad_role", status=400)
    if value == "":
        return None
    if value != value.strip():
        raise RoleManagementError(
            "role must not contain surrounding whitespace",
            code="bad_role", status=400)
    try:
        return peer_policy.validate_role_name(value)
    except peer_policy.PolicyError as exc:
        raise RoleManagementError(str(exc), code=exc.code, status=422,
                                  **exc.details) from None


def _policy_roles(result):
    compiled = getattr(result, "roles", None)
    return compiled if compiled is not None \
        else peer_policy.compile_roles(result.document)


def drift_report(fleet, policy_result, limit=DRIFT_ID_LIMIT, rows=None):
    """Return a bounded, address-free declaration/enforcement drift summary."""
    if rows is None:
        _revision, rows = fleet.snapshot()
    fleet_rows = {row.get("device_id"): row for row in rows
                  if isinstance(row, dict) and row.get("device_id")}
    compiled = _policy_roles(policy_result)
    role_of = compiled.role_of
    divergent = set()
    for device_id in set(fleet_rows) | set(role_of):
        declared = (fleet_rows.get(device_id) or {}).get("role") or None
        enforced = role_of.get(device_id) or None
        if declared != enforced:
            divergent.add(device_id)
        assignment = peer_policy.ordinary_assignment(
            policy_result.document, device_id)
        if declared and assignment is not None:
            divergent.add(device_id)
    ordered = sorted(divergent)
    return {"count": len(ordered), "device_ids": ordered[:limit],
            "truncated": len(ordered) > limit}


def _access_signature(document, role, role_of=None, device_ids=None):
    """Address-free effective origin and mutual peer access for one role.

    With a role map and device universe, peer tokens identify the actual live
    candidate principals. The label-only form remains useful for definition
    lifecycle comparisons where no fleet population is available.
    """
    defs = document.get("roles", {}).get("defs", {})
    definition = defs.get(role, {}) if role is not None else {}
    if not isinstance(definition, dict) or not definition.get("restricted", False):
        origin = True
    else:
        origin = definition.get("origin", True)
    peers = set()
    name = role if role is not None else "default"
    if role_of is None:
        # Keep potential role populations distinct. An isolated role A can
        # reach A's members while isolated B can reach B's members; mutually
        # connected A/B correctly produce the same {A, B} signature.
        for other in set(defs) | {"default"}:
            if peer_policy._role_pair_permitted(document, name, other):
                peers.add("role:" + other)
    else:
        for device_id in device_ids or ():
            other = role_of.get(device_id) or "default"
            if peer_policy._role_pair_permitted(document, name, other):
                peers.add("device:" + device_id)
    if origin:
        peers.add("service:origin")
    return frozenset(peers)


def _change_direction(document, old_role, new_role, quarantined=False,
                      old_signature=None, new_signature=None):
    if old_role == new_role:
        return "neutral"
    # Quarantine remains the effective ACL before and after membership changes.
    # Fleet-first therefore exposes intent before the inert policy tidy-up.
    if quarantined:
        return "neutral"
    old = (_access_signature(document, old_role)
           if old_signature is None else old_signature)
    new = (_access_signature(document, new_role)
           if new_signature is None else new_signature)
    defs = document.get("roles", {}).get("defs", {})
    old_definition = defs.get(old_role, {}) if old_role is not None else {}
    new_definition = defs.get(new_role, {}) if new_role is not None else {}
    old_restricted = bool(isinstance(old_definition, dict)
                          and old_definition.get("restricted", False))
    new_restricted = bool(isinstance(new_definition, dict)
                          and new_definition.get("restricted", False))
    if new == old:
        # With no independently reachable peer difference, the canonical
        # restricted boundary still determines safe residue ordering.
        if old_restricted != new_restricted:
            return "tighten" if new_restricted else "relax"
        return "neutral"
    if new < old:
        return "tighten"
    if new > old:
        return "relax"
    return "incomparable"


def _mutate_role_map(candidate, role_by_device):
    roles = candidate.setdefault("roles", {})
    roles.setdefault("defs", {})
    role_of = roles.setdefault("role_of", {})
    roles.setdefault("qos_default", {})
    roles.setdefault("qos_device", {})
    candidate["roles_present"] = True
    for device_id, role in role_by_device.items():
        if role is None:
            role_of.pop(device_id, None)
        else:
            role_of[device_id] = role


def _remove_matching_assignments(candidate, device_ids, acl_name):
    assignments = candidate.setdefault("assignments", {})
    for device_id in device_ids:
        if assignments.get(device_id) == acl_name:
            assignments.pop(device_id)


class RoleCoordinator:
    """One outer transaction coordinator for API, CSV and CLI role writes."""

    def __init__(self, fleet, auth_path, lkg_path, now_fn=time.time,
                 acked_revision_fn=None, schedule_store=None):
        self.fleet = fleet
        self.auth_path = auth_path
        self.lkg_path = lkg_path
        self.now_fn = now_fn
        self.acked_revision_fn = acked_revision_fn or (lambda: 0)
        self.schedule_store = schedule_store
        self.lock_path = os.path.join(
            os.path.dirname(os.path.abspath(auth_path)), "role-management")

    def _load(self):
        result = peer_policy.load_policy(self.auth_path, self.lkg_path)
        if result.fail_closed:
            raise RoleManagementError("peer policy is fail closed",
                                      code="policy_fail_closed", status=503)
        if result.degraded:
            raise RoleManagementError("peer policy is degraded",
                                      code="policy_error", status=503)
        return result

    def _acked(self):
        try:
            value = self.acked_revision_fn()
        except Exception:
            return 0
        if isinstance(value, dict):
            return dict(value)
        return value if type(value) is int and value >= 0 else 0

    def role_drift(self):
        return drift_report(self.fleet, self._load())

    @staticmethod
    def _known_roles(document):
        roles = document.get("roles", {})
        defs = roles.get("defs", {}) if isinstance(roles, dict) else {}
        return defs if isinstance(defs, dict) else {}

    @staticmethod
    def _scheduled_role(definition):
        if not isinstance(definition, dict):
            return None
        target = definition.get("target")
        filters = target.get("filters") if isinstance(target, dict) else None
        role = filters.get("role") if isinstance(filters, dict) else None
        return role if isinstance(role, str) and role not in ("", "__none") \
            else None

    def _require_scheduled_role(self, definition, policy):
        role = self._scheduled_role(definition)
        if role is not None and role not in self._known_roles(policy.document):
            raise RoleManagementError(
                "unknown schedule target role", code="role_not_found",
                status=422, role=role)
        return role

    @contextlib.contextmanager
    def schedule_role_guard(self, definition):
        """Hold role and fleet authority across resolution and schedule claim.

        The yielded policy is the exact snapshot validated. A runner claims the
        schedule inside this context and invokes executors only after leaving.
        """
        with secrets_store.store_lock(self.lock_path):
            with assignment_service.membership_guard(self.fleet):
                policy = self._load()
                self._require_scheduled_role(definition, policy)
                yield policy

    @staticmethod
    def _schedule_preview(resolved):
        return {key: resolved[key]
                for key in ("revision", "now", "device_ids")}

    def create_schedule(self, schedule_id, definition, *, actor, now,
                        resolve_target):
        if self.schedule_store is None:
            raise RoleManagementError(
                "schedule authority unavailable",
                code="schedule_state_unavailable", status=503)
        with self.schedule_role_guard(definition) as policy:
            resolved = resolve_target(definition["target"],
                                      role_policy=policy)
            row = self.schedule_store.create(
                schedule_id, definition, actor=actor, now=now,
                preview=self._schedule_preview(resolved))
            return row, resolved

    def put_schedule(self, schedule_id, definition, *, expected_rev,
                     resolve_target):
        if self.schedule_store is None:
            raise RoleManagementError(
                "schedule authority unavailable",
                code="schedule_state_unavailable", status=503)
        with self.schedule_role_guard(definition) as policy:
            resolved = resolve_target(definition["target"],
                                      role_policy=policy)
            row = self.schedule_store.put(
                schedule_id, definition, expected_rev=expected_rev,
                preview=self._schedule_preview(resolved))
            return row, resolved

    def patch_schedule(self, schedule_id, patch, *, expected_rev,
                       resolve_target):
        if self.schedule_store is None:
            raise RoleManagementError(
                "schedule authority unavailable",
                code="schedule_state_unavailable", status=503)
        # All definition writers take the same outer lock. Only a retarget
        # needs a policy/fleet read and a new preview.
        with secrets_store.store_lock(self.lock_path):
            with assignment_service.membership_guard(self.fleet):
                resolved = None
                preview = None
                if "target" in patch:
                    policy = self._load()
                    self._require_scheduled_role({"target": patch["target"]},
                                                 policy)
                    resolved = resolve_target(patch["target"],
                                              role_policy=policy)
                    preview = self._schedule_preview(resolved)
                row = self.schedule_store.patch(
                    schedule_id, patch, expected_rev=expected_rev,
                    preview=preview)
            return row, resolved

    def delete_schedule(self, schedule_id, *, expected_rev):
        """Delete under the role boundary without requiring a live role.

        A missing/degraded role may prevent execution, but must never prevent
        an operator from removing the schedule that refers to it.
        """
        if self.schedule_store is None:
            raise RoleManagementError(
                "schedule authority unavailable",
                code="schedule_state_unavailable", status=503)
        with secrets_store.store_lock(self.lock_path):
            return self.schedule_store.delete(
                schedule_id, expected_rev=expected_rev)

    def _validate_mapping(self, mapping, result, allow_missing=False,
                          allow_shadow=False):
        if not isinstance(mapping, dict) or not mapping:
            raise RoleManagementError("role mapping must not be empty",
                                      code="bad_role_mapping", status=400)
        definitions = self._known_roles(result.document)
        normalized = {}
        failed = {}
        for raw_device_id, raw_role in mapping.items():
            device_id = str(raw_device_id or "").strip()
            if not device_id:
                raise RoleManagementError("device id must not be empty",
                                          code="bad_device_id", status=400)
            role = _role_value(raw_role)
            if role is not None and role not in definitions:
                raise RoleManagementError(
                    "unknown role", code="role_not_found", status=422,
                    role=role)
            if not allow_missing and self.fleet.get_device(device_id) is None:
                failed[device_id] = "no such device"
                continue
            assignment = peer_policy.ordinary_assignment(
                result.document, device_id)
            if not allow_shadow and assignment is not None:
                raise RoleManagementError(
                    "role is shadowed by an explicit assignment",
                    code="role_shadowed_by_assignment", status=409,
                    device_id=device_id, assignment=assignment, role=role)
            normalized[device_id] = role
        return normalized, failed

    def _direction(self, document, mapping):
        compiled = peer_policy.compile_roles(document)
        _fleet_revision, fleet_rows = self.fleet.snapshot()
        device_ids = {row.get("device_id") for row in fleet_rows
                      if isinstance(row, dict) and row.get("device_id")}
        old_role_of = dict(compiled.role_of)
        candidate_role_of = dict(old_role_of)
        for device_id, role in mapping.items():
            device_ids.add(device_id)
            if role is None:
                candidate_role_of.pop(device_id, None)
            else:
                candidate_role_of[device_id] = role
        device_ids.update(old_role_of)
        device_ids.update(candidate_role_of)
        directions = set()
        # Bulk role changes commonly contain thousands of copies of the same
        # transition.  A transition depends only on these three values while
        # *document* is fixed, so compute its role-graph signature once.
        transitions = {}
        old_signatures = {}
        new_signatures = {}
        for device_id, new_role in mapping.items():
            transition = (
                compiled.role_of.get(device_id), new_role,
                peer_policy.is_quarantined(document, device_id))
            if transition not in transitions:
                old_role = transition[0]
                if old_role not in old_signatures:
                    old_signatures[old_role] = _access_signature(
                        document, old_role, old_role_of, device_ids)
                if new_role not in new_signatures:
                    new_signatures[new_role] = _access_signature(
                        document, new_role, candidate_role_of, device_ids)
                moving = {"device:" + device_id}
                transitions[transition] = _change_direction(
                    document, *transition,
                    old_signature=old_signatures[old_role] - moving,
                    new_signature=new_signatures[new_role] - moving)
            direction = transitions[transition]
            if direction == "incomparable":
                raise RoleManagementError(
                    "incomparable role change; split into a relax/clear action "
                    "followed by an add/tighten action",
                    code="incomparable_role_change", status=422,
                    device_id=device_id)
            directions.add(direction)
        active = directions - {"neutral"}
        if active == {"tighten", "relax"}:
            raise RoleManagementError(
                "bulk contains tightening and relaxing changes; split it",
                code="mixed_role_direction", status=422)
        return next(iter(active), "neutral")

    def _commit_mapping(self, mapping, actor, expected_revision=None,
                        dry_run=False, action="set_roles_bulk", target=None,
                        precommit=None):
        if target is None:
            values = set(mapping.values())
            target = ("role:" + (next(iter(values)) or "")) \
                if len(values) == 1 else "roles:mixed"
        return peer_policy.commit_mutation(
            self.auth_path, self.lkg_path, action=action, target=target,
            actor=actor, now=self.now_fn(),
            mutate=lambda candidate: _mutate_role_map(candidate, mapping),
            acked_revision=self._acked(), expected_revision=expected_revision,
            dry_run=dry_run, precommit=precommit)

    @staticmethod
    def _blast_details(blast):
        return {
            "member_delta": blast.member_delta,
            "origin_access_lost": blast.origin_access_lost,
            "empty_permitted_sets": blast.empty_permitted_sets,
            "role_pairs_stopped": blast.role_pairs_stopped,
            "qos_changed": blast.qos_changed,
            "requires_confirmation": blast.requires_confirmation,
            "confirm_token": blast.confirm_token,
        }

    @staticmethod
    def _confirmation_guard(token):
        def check(prior, candidate):
            if not peer_policy.confirm_blast_radius(
                    prior, candidate,
                    peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD, token):
                current = peer_policy.blast_radius(
                    prior, candidate,
                    peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD)
                raise peer_policy.PolicyError(
                    "confirmation required", code="confirmation_required",
                    **RoleCoordinator._blast_details(current))
        return check

    def _translate_policy_error(self, exc, partial=False, fallback_ids=(),
                                applied_ids=(), failed=None):
        if isinstance(exc, peer_policy.RevisionConflict):
            code, status = "revision_conflict", 409
            details = {"revision": exc.revision}
        elif isinstance(exc, peer_policy.OperationBacklogFull):
            code, status, details = "operation_backlog_full", 503, {}
        elif isinstance(exc, peer_policy.PolicyDegradedError):
            code, status, details = "policy_error", 503, {}
        elif isinstance(exc, peer_policy.PolicyError):
            code = exc.code
            status = 428 if code == "confirmation_required" else 422
            details = dict(exc.details)
        else:
            code, status, details = "policy_write_failed", 503, {}
        result = {}
        if partial:
            result["applied"] = len(set(applied_ids))
            result["failed"] = dict(failed or {})
            try:
                result["role_drift"] = self.role_drift()
            except Exception:
                ids = sorted(set(fallback_ids))
                result["role_drift"] = {
                    "count": len(ids), "device_ids": ids[:DRIFT_ID_LIMIT],
                    "truncated": len(ids) > DRIFT_ID_LIMIT}
        raise RoleManagementError(
            str(exc) or code, code=code, status=status, partial=partial,
            result=result, **details) from None

    @staticmethod
    def _fleet_outcomes(results):
        failed = {device_id: outcome.get("error", "fleet write failed")
                  for device_id, outcome in results.items()
                  if not outcome.get("ok")}
        applied = {device_id for device_id, outcome in results.items()
                   if outcome.get("ok")}
        return applied, failed

    def _live_role_outcomes(self, mapping, message="fleet write failed"):
        """Describe the requested role state from durable rows after an error."""
        results = {}
        for device_id, role in mapping.items():
            try:
                row = self.fleet.get_device(device_id)
                actual = (row or {}).get("role") or None
                if row is not None and actual == role:
                    results[device_id] = {"ok": True, "device": row}
                else:
                    results[device_id] = {"ok": False, "error": message}
            except Exception:
                results[device_id] = {"ok": False, "error": message}
        return results

    def _write_fleet_roles(self, mapping):
        values = set(mapping.values())
        if len(values) == 1:
            return self.fleet.bulk_upsert(
                list(mapping), {"role": next(iter(values))})
        return self.fleet.bulk_set_roles(mapping)

    def set_role(self, device_id, role, actor, **kwargs):
        result = self.set_roles({device_id: role}, actor=actor, **kwargs)
        if result.get("failed", {}).get(device_id) == "no such device":
            raise RoleManagementError("no such device", code="device_not_found",
                                      status=404, result=result)
        return result

    def set_roles(self, role_by_device, actor, expected_revision=None,
                  dry_run=False, allow_shadow=False, confirm_token=None,
                  require_confirmation=False):
        """Set several possibly different roles as one policy event."""
        with secrets_store.store_lock(self.lock_path):
            policy = self._load()
            classified_revision = policy.document["revision"]
            if expected_revision is not None \
                    and policy.document.get("revision") != expected_revision:
                raise RoleManagementError(
                    "policy revision conflict", code="revision_conflict",
                    status=409, revision=policy.document.get("revision"))
            mapping, failed = self._validate_mapping(
                role_by_device, policy, allow_shadow=allow_shadow)
            if not mapping:
                return {"ok": False, "applied": 0, "failed": failed,
                        "partial": False, "revision": policy.document["revision"],
                        "direction": "neutral", "dry_run": bool(dry_run),
                        "role_drift": drift_report(self.fleet, policy)}
            compiled = _policy_roles(policy)
            policy_mapping = {
                device_id: role for device_id, role in mapping.items()
                if compiled.role_of.get(device_id) != role}
            direction = self._direction(policy.document, policy_mapping) \
                if policy_mapping else "neutral"
            guard = None
            blast = None
            if dry_run or require_confirmation:
                candidate = policy.document
                if policy_mapping:
                    captured = []
                    def capture(prior, proposed):
                        captured.append(peer_policy.blast_radius(
                            prior, proposed, peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD))
                    candidate = self._commit_mapping(
                        policy_mapping, actor, expected_revision=classified_revision,
                        dry_run=True, precommit=capture)
                    blast = captured[0]
                else:
                    blast = peer_policy.blast_radius(
                        policy.document, candidate,
                        peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD)
            if dry_run:
                return {"ok": True, "applied": len(mapping), "failed": failed,
                        "partial": False, "revision": policy.document["revision"],
                        "candidate_revision": candidate["revision"],
                        "direction": direction, "dry_run": True,
                        **self._blast_details(blast),
                        "role_drift": drift_report(self.fleet, policy)}
            if require_confirmation and blast.requires_confirmation:
                if not peer_policy.confirm_blast_radius(
                        policy.document, candidate,
                        peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD,
                        confirm_token):
                    raise RoleManagementError(
                        "confirmation required", code="confirmation_required",
                        status=428, **self._blast_details(blast))
            if require_confirmation:
                guard = self._confirmation_guard(confirm_token)

            policy_first = bool(policy_mapping) and direction == "relax"
            committed = None
            if policy_first:
                try:
                    committed = self._commit_mapping(
                        policy_mapping, actor,
                        expected_revision=classified_revision, precommit=guard)
                except Exception as exc:
                    self._translate_policy_error(exc, fallback_ids=mapping)
                try:
                    outcomes = self._write_fleet_roles(mapping)
                except Exception as exc:
                    outcomes = (exc.results if isinstance(
                        exc, gui_fleet.FleetPartialWriteError)
                        else self._live_role_outcomes(mapping))
                    applied_ids, fleet_failed = self._fleet_outcomes(outcomes)
                    failed.update(fleet_failed)
                    try:
                        drift = self.role_drift()
                    except Exception:
                        drift = {"count": len(mapping),
                                 "device_ids": sorted(mapping)[:DRIFT_ID_LIMIT],
                                 "truncated": len(mapping) > DRIFT_ID_LIMIT}
                    raise RoleManagementError(
                        str(exc), code="fleet_write_failed", status=503,
                        partial=True,
                        result={"revision": committed["revision"],
                                             "applied": len(applied_ids),
                                             "failed": failed,
                                             "role_drift": drift}) from None
            else:
                # Refuse capacity/CAS/candidate errors before Fleet-first writes.
                # The real commit still rechecks under its policy lock: a direct
                # writer racing after this preview retains partial classification.
                if policy_mapping:
                    try:
                        self._commit_mapping(policy_mapping, actor,
                            expected_revision=classified_revision,
                            dry_run=True, precommit=guard)
                    except Exception as exc:
                        self._translate_policy_error(exc, fallback_ids=mapping)
                try:
                    outcomes = self._write_fleet_roles(mapping)
                except Exception as exc:
                    outcomes = (exc.results if isinstance(
                        exc, gui_fleet.FleetPartialWriteError)
                        else self._live_role_outcomes(mapping))
                    applied_ids, fleet_failed = self._fleet_outcomes(outcomes)
                    failed.update(fleet_failed)
                    try:
                        drift = self.role_drift()
                    except Exception:
                        ids = sorted(set(mapping) - set(applied_ids))
                        drift = {"count": len(ids),
                                 "device_ids": ids[:DRIFT_ID_LIMIT],
                                 "truncated": len(ids) > DRIFT_ID_LIMIT}
                    raise RoleManagementError(
                        str(exc), code="fleet_write_failed", status=503,
                        partial=bool(applied_ids),
                        result={"applied": len(applied_ids),
                                "failed": failed,
                                "revision": policy.document["revision"],
                                "role_drift": drift}) from None
                applied_ids, fleet_failed = self._fleet_outcomes(outcomes)
                failed.update(fleet_failed)
                applied_mapping = {
                    device_id: policy_mapping[device_id]
                    for device_id in applied_ids if device_id in policy_mapping}
                if applied_mapping:
                    try:
                        committed = self._commit_mapping(
                            applied_mapping, actor,
                            expected_revision=classified_revision,
                            precommit=guard)
                    except Exception as exc:
                        self._translate_policy_error(
                            exc, partial=True, fallback_ids=applied_mapping,
                            applied_ids=applied_ids, failed=failed)

            applied_ids, fleet_failed = self._fleet_outcomes(outcomes)
            failed.update(fleet_failed)
            live = self._load()
            drift = drift_report(self.fleet, live)
            partial = bool(failed) or drift["count"] > 0
            return {"ok": not partial, "applied": len(applied_ids),
                    "failed": failed, "partial": partial,
                    "revision": (committed or live.document)["revision"],
                    "direction": direction, "dry_run": False,
                    "role_drift": drift}

    def upsert_device(self, record, actor, expected_revision=None,
                      dry_run=False, allow_shadow=False):
        """Coordinate generic device creation/update when ``role`` is explicit."""
        # Validate the complete logical fleet row before a relaxing role
        # change can commit policy first. The eventual upsert repeats these
        # checks while holding the device shard lock.
        self.fleet.validate_operator_upsert(record)
        if "role" not in record:
            saved = self.fleet.upsert(record)
            return {"ok": True, "device": saved, "applied": 1,
                    "failed": {}, "partial": False}
        device_id = str(record.get("device_id") or "").strip()
        with secrets_store.store_lock(self.lock_path):
            policy = self._load()
            classified_revision = policy.document["revision"]
            if expected_revision is not None \
                    and policy.document.get("revision") != expected_revision:
                raise RoleManagementError(
                    "policy revision conflict", code="revision_conflict",
                    status=409, revision=policy.document.get("revision"))
            mapping, _failed = self._validate_mapping(
                {device_id: record.get("role")}, policy, allow_missing=True,
                allow_shadow=allow_shadow)
            compiled = _policy_roles(policy)
            policy_mapping = {
                key: value for key, value in mapping.items()
                if compiled.role_of.get(key) != value}
            direction = self._direction(policy.document, policy_mapping) \
                if policy_mapping else "neutral"
            if dry_run:
                if policy_mapping:
                    self._commit_mapping(
                        policy_mapping, actor, classified_revision, dry_run=True)
                return {"ok": True, "dry_run": True, "direction": direction,
                        "revision": policy.document["revision"]}
            policy_first = bool(policy_mapping) and direction == "relax"
            committed = None
            if policy_first:
                try:
                    committed = self._commit_mapping(
                        policy_mapping, actor, classified_revision)
                except Exception as exc:
                    self._translate_policy_error(exc, fallback_ids=mapping)
            try:
                saved = self.fleet.upsert(record)
            except Exception as exc:
                if policy_first:
                    raise RoleManagementError(
                        str(exc), code="fleet_write_failed", status=503,
                        partial=True,
                        result={"revision": committed["revision"],
                                "role_drift": self.role_drift()}) from None
                raise
            if policy_mapping and not policy_first:
                try:
                    committed = self._commit_mapping(
                        policy_mapping, actor, classified_revision)
                except Exception as exc:
                    self._translate_policy_error(exc, partial=True,
                                                 fallback_ids=mapping,
                                                 applied_ids=mapping)
            return {"ok": True, "device": saved, "applied": 1,
                    "failed": {}, "partial": False,
                    "revision": (committed or policy.document)["revision"],
                    "direction": direction,
                    "role_drift": self.role_drift()}

    def import_csv(self, text, actor, expected_revision=None, dry_run=False,
                   allow_shadow=False):
        """Apply inventory CSV and its nonblank/carry-forward roles together."""
        parsed = self.fleet.parse_csv(text)
        with secrets_store.store_lock(self.lock_path):
            policy = self._load()
            classified_revision = policy.document["revision"]
            if expected_revision is not None \
                    and policy.document.get("revision") != expected_revision:
                raise RoleManagementError(
                    "policy revision conflict", code="revision_conflict",
                    status=409, revision=policy.document.get("revision"))
            try:
                # Validate retained server/local fields and every prospective
                # replacement before a relaxing role change can commit first.
                # Fleet persistence repeats this under its shard locks.
                self.fleet.validate_parsed_csv(parsed)
            except Exception as exc:
                raise RoleManagementError(
                    str(exc), code="fleet_write_failed", status=503,
                    partial=False,
                    result={"revision": policy.document["revision"],
                            "applied": 0, "failed": {},
                            "stats": {"imported": 0, "new": 0,
                                      "updated": 0,
                                      "skipped": parsed["skipped"],
                                      "roles_cleared": 0},
                            "role_drift": drift_report(self.fleet, policy)}) \
                    from None
            desired = {}
            for record in parsed["records"]:
                previous = self.fleet.get_device(record["device_id"])
                role = record.get("role") or \
                    ((previous or {}).get("role") if previous else None)
                # A blank row with no existing declaration has no membership
                # opinion.  In particular, ordinary inventory import must not
                # erase a policy-only membership while repairing existing
                # drift; only the explicit role API/CLI clears membership.
                if role is not None:
                    desired[record["device_id"]] = role
            if desired:
                mapping, _failed = self._validate_mapping(
                    desired, policy, allow_missing=True,
                    allow_shadow=allow_shadow)
            else:
                mapping = {}
            compiled = _policy_roles(policy)
            changed = {device_id: role for device_id, role in mapping.items()
                       if compiled.role_of.get(device_id) != role}
            direction = self._direction(policy.document, changed) \
                if changed else "neutral"
            if dry_run:
                if changed:
                    self._commit_mapping(
                        changed, actor, expected_revision=classified_revision,
                        dry_run=True, action="import_roles", target="csv")
                return {"ok": True, "dry_run": True, "direction": direction,
                        "stats": {"imported": len(parsed["records"]),
                                  "new": 0, "updated": 0,
                                  "skipped": parsed["skipped"],
                                  "roles_cleared": 0},
                        "revision": policy.document["revision"],
                        "role_drift": drift_report(self.fleet, policy)}
            policy_first = changed and direction == "relax"
            committed = None
            if policy_first:
                try:
                    committed = self._commit_mapping(
                        changed, actor, expected_revision=classified_revision,
                        action="import_roles", target="csv")
                except Exception as exc:
                    self._translate_policy_error(exc, fallback_ids=changed)
            try:
                stats = self.fleet.import_parsed_csv(parsed)
            except Exception as exc:
                partial_result = (exc.result if isinstance(
                    exc, gui_fleet.FleetPartialWriteError) else {})
                applied = int(partial_result.get("applied", 0))
                failures = dict(partial_result.get("failed", {}))
                try:
                    drift = self.role_drift()
                except Exception:
                    ids = sorted(set(changed))
                    drift = {"count": len(ids),
                             "device_ids": ids[:DRIFT_ID_LIMIT],
                             "truncated": len(ids) > DRIFT_ID_LIMIT}
                raise RoleManagementError(
                    str(exc), code="fleet_write_failed", status=503,
                    partial=bool(applied or policy_first),
                    result={"revision": (committed or policy.document)["revision"],
                            "applied": applied, "failed": failures,
                            "stats": partial_result.get("stats", {
                                "imported": applied, "new": 0, "updated": 0,
                                "skipped": parsed["skipped"],
                                "roles_cleared": 0}),
                            "role_drift": drift}) from None
            if changed and not policy_first:
                try:
                    committed = self._commit_mapping(
                        changed, actor, expected_revision=classified_revision,
                        action="import_roles", target="csv")
                except Exception as exc:
                    self._translate_policy_error(exc, partial=True,
                                                 fallback_ids=changed,
                                                 applied_ids=changed)
            live = self._load()
            return {"ok": True, "dry_run": False, "direction": direction,
                    "stats": stats,
                    "revision": (committed or live.document)["revision"],
                    "role_drift": drift_report(self.fleet, live)}

    def set_quarantine(self, device_id, quarantined, actor,
                       expected_revision):
        """Change device quarantine membership under the role outer lock."""
        if type(quarantined) is not bool:
            raise RoleManagementError("quarantined must be boolean",
                                      code="bad_quarantine", status=400)
        with secrets_store.store_lock(self.lock_path):
            if self.fleet.get_device(device_id) is None:
                raise RoleManagementError("unknown device",
                                          code="unknown_device", status=422)
            policy = peer_policy.load_policy(self.auth_path, self.lkg_path)
            if policy.fail_closed:
                raise RoleManagementError("peer policy is fail closed",
                                          code="policy_fail_closed", status=503)
            if policy.degraded:
                raise RoleManagementError("peer policy is degraded",
                                          code="policy_error", status=422)
            revision = policy.document["revision"]
            if revision != expected_revision:
                raise RoleManagementError(
                    "policy revision conflict", code="revision_conflict",
                    status=409, revision=revision)

            def mutate(candidate):
                peer_policy._set_quarantine_membership(
                    candidate, device_id, quarantined)

            try:
                return peer_policy.commit_mutation(
                    self.auth_path, self.lkg_path,
                    action="assign" if quarantined else "unassign",
                    target=device_id, actor=actor, now=self.now_fn(),
                    mutate=mutate, acked_revision=self._acked(),
                    expected_revision=revision)
            except Exception as exc:
                self._translate_policy_error(exc)

    def clear_assignment_for_revoke(self, device_id, actor):
        """Remove only an explicit ACL shadow after durable credential revoke.

        Pure revoke keeps the fleet declaration, compiled role membership and
        per-device QoS and quarantine membership so a later remint cannot
        silently shed policy intent. Retirement uses :meth:`retire_device` for
        the wider four-slot cleanup.
        """
        with secrets_store.store_lock(self.lock_path):
            policy = self._load()
            if peer_policy.ordinary_assignment(
                    policy.document, device_id) is None:
                return policy.document

            def mutate(candidate):
                candidate.setdefault("assignments", {}).pop(device_id, None)

            try:
                return peer_policy.commit_mutation(
                    self.auth_path, self.lkg_path, action="unassign",
                    target=device_id, actor=actor, now=self.now_fn(),
                    mutate=mutate, acked_revision=self._acked(),
                    expected_revision=policy.document["revision"])
            except Exception as exc:
                self._translate_policy_error(exc)

    def retire_device(self, device_id, actor, catalog=None, *, cleanup=None):
        """Clean policy, fleet, and optional catalog state for one device.

        The caller owns durable credential revocation and performs it before
        entering here.  Policy cleanup failure therefore degrades but does not
        block fleet retirement; a fleet failure after policy cleanup is a
        reported partial result and the first phase is never rolled back. The
        membership guard spans fleet deletion, catalog purge, and optional
        caller cleanup. Replacement registration cannot race record retirement
        or job cancellation. The caller contains degraded cleanup failures.
        """
        if cleanup is not None and not callable(cleanup):
            raise ValueError("invalid retirement cleanup")
        with secrets_store.store_lock(self.lock_path):
            with assignment_service.membership_guard(self.fleet):
                policy_error = None
                committed = None
                try:
                    committed = peer_policy.unassign_device(
                        self.auth_path, self.lkg_path, device_id, actor=actor,
                        now=self.now_fn(), acked_revision=self._acked())
                except Exception as exc:
                    policy_error = exc
                try:
                    deleted = self.fleet.delete(device_id)
                except Exception as exc:
                    result = {}
                    if committed is not None:
                        result["revision"] = committed["revision"]
                        try:
                            result["role_drift"] = self.role_drift()
                        except Exception:
                            result["role_drift"] = {
                                "count": 1, "device_ids": [device_id],
                                "truncated": False}
                    raise RoleManagementError(
                        str(exc), code="fleet_write_failed", status=503,
                        partial=committed is not None, result=result) from None
                purged = False
                catalog_degraded = False
                if catalog is not None:
                    try:
                        purged = catalog.purge_device(device_id)
                    except Exception:
                        catalog_degraded = True
                if cleanup is not None:
                    cleanup()
                try:
                    drift = self.role_drift()
                except Exception:
                    drift = {"count": 1 if policy_error is not None else 0,
                             "device_ids": [device_id]
                             if policy_error is not None else [],
                             "truncated": False}
                return {"deleted": deleted,
                        "policy_degraded": policy_error is not None,
                        "catalog_purged": purged,
                        "catalog_degraded": catalog_degraded,
                        "revision": committed.get("revision")
                        if committed is not None else None,
                        "role_drift": drift}

    def define_role(self, name, definition, actor, **kwargs):
        with secrets_store.store_lock(self.lock_path):
            try:
                return peer_policy.define_role(
                    self.auth_path, self.lkg_path, name, definition,
                    actor=actor, now=self.now_fn(), acked_revision=self._acked(),
                    **kwargs)
            except Exception as exc:
                self._translate_policy_error(exc)

    def set_qos(self, qos, actor, **kwargs):
        """Serialize role-scoped QoS with all fleet/role writers."""
        with secrets_store.store_lock(self.lock_path):
            try:
                return peer_policy.set_qos(
                    self.auth_path, self.lkg_path, qos, actor=actor,
                    now=self.now_fn(), acked_revision=self._acked(), **kwargs)
            except Exception as exc:
                self._translate_policy_error(exc)

    def delete_role(self, name, actor, **kwargs):
        with secrets_store.store_lock(self.lock_path):
            referring_schedules = (self.schedule_store.referring_schedules(name)
                                   if self.schedule_store is not None else [])
            _revision, rows = self.fleet.snapshot()
            declared = sorted(
                row["device_id"] for row in rows
                if isinstance(row, dict) and row.get("role") == name)
            if declared:
                raise RoleManagementError(
                    "role is in use", code="role_in_use", status=422,
                    role=name, member_count=len(declared),
                    referring_roles=sorted(other for other, definition in
                        self._load().document.get("roles", {}).get("defs", {}).items()
                        if other != name and name in definition.get("peers", [other])),
                    referring_schedules=referring_schedules,
                    device_ids=declared[:DRIFT_ID_LIMIT],
                    truncated=len(declared) > DRIFT_ID_LIMIT)
            try:
                kwargs = dict(kwargs)
                kwargs["referring_schedules"] = referring_schedules
                return peer_policy.delete_role(
                    self.auth_path, self.lkg_path, name, actor=actor,
                    now=self.now_fn(), acked_revision=self._acked(), **kwargs)
            except Exception as exc:
                self._translate_policy_error(exc)

    def replace_definitions(self, definitions, actor, expected_revision=None,
                            dry_run=False, precommit=None):
        """Replace all role definitions as one revision/outbox event."""
        with secrets_store.store_lock(self.lock_path):
            _revision, rows = self.fleet.snapshot()
            declared = sorted({row.get("role") for row in rows
                               if isinstance(row, dict) and row.get("role")})
            schedule_references = {}
            if self.schedule_store is not None:
                for row in self.schedule_store.list():
                    role = self._scheduled_role(row)
                    if role is not None and role not in definitions:
                        schedule_references.setdefault(role, []).append(row["id"])
            missing = sorted(set(name for name in declared
                                 if name not in definitions) |
                             set(schedule_references))
            if missing:
                raise RoleManagementError(
                    "role definitions omit declared fleet roles",
                    code="role_in_use", status=422, roles=missing[:DRIFT_ID_LIMIT],
                    referring_schedules=sorted(
                        schedule_id for ids in schedule_references.values()
                        for schedule_id in ids)[:DRIFT_ID_LIMIT],
                    truncated=len(missing) > DRIFT_ID_LIMIT)
            def mutate(candidate):
                roles = candidate.setdefault("roles", {})
                roles.setdefault("role_of", {})
                roles.setdefault("qos_default", {})
                roles.setdefault("qos_device", {})
                roles["defs"] = json.loads(json.dumps(definitions))
                candidate["roles_present"] = True
            try:
                return peer_policy.commit_mutation(
                    self.auth_path, self.lkg_path, action="import_roles",
                    target="roles", actor=actor, now=self.now_fn(),
                    mutate=mutate, acked_revision=self._acked(),
                    expected_revision=expected_revision, dry_run=dry_run,
                    precommit=precommit)
            except Exception as exc:
                self._translate_policy_error(exc)

    def migrate_assignment(self, acl_name, role, actor, dry_run=True,
                           confirm_token=None):
        """Stage members behind an explicit ACL, then remove that ACL shadow.

        Quarantine is never eligible.  A real migration performs exactly two
        policy commits under the same outer role lock: membership staging and
        explicit-assignment removal.  Failure never rolls either commit back.
        """
        if not isinstance(acl_name, str) or not acl_name \
                or acl_name == peer_policy.RESERVED_QUARANTINE:
            raise RoleManagementError("bad migration ACL", code="bad_acl",
                                      status=400)
        role = _role_value(role)
        if role is None:
            raise RoleManagementError("migration role is required",
                                      code="bad_role", status=400)
        with secrets_store.store_lock(self.lock_path):
            policy = self._load()
            if acl_name not in policy.document.get("acls", {}):
                raise RoleManagementError("no such ACL", code="acl_not_found",
                                          status=404, acl=acl_name)
            assignments = policy.document.get("assignments", {})
            devices = sorted(device_id for device_id, assigned in
                             assignments.items() if assigned == acl_name)
            if role not in self._known_roles(policy.document):
                raise RoleManagementError("unknown role",
                                          code="role_not_found", status=422,
                                          role=role)
            if not devices:
                return {"ok": True, "dry_run": bool(dry_run), "devices": [],
                        "shadowed_inert": [], "newly_restricted": [],
                        "failed": {}, "revision": policy.document["revision"]}
            mapping, failed = self._validate_mapping(
                {device_id: role for device_id in devices}, policy,
                allow_shadow=True)
            preview = {"ok": not failed, "dry_run": bool(dry_run),
                       "devices": sorted(mapping),
                       "shadowed_inert": sorted(mapping),
                       "newly_restricted": [], "failed": failed,
                       "revision": policy.document["revision"]}
            staged_candidate = None
            released_candidate = None
            blast = None
            if mapping:
                staged_candidate = self._commit_mapping(
                    mapping, actor, dry_run=True, action="migrate_roles",
                    target="acl:%s" % acl_name)
                released_candidate = json.loads(json.dumps(staged_candidate))
                _remove_matching_assignments(
                    released_candidate, mapping, acl_name)
                # This represents the semantic outcome of both commits.  The
                # blast token ignores revision/outbox metadata, while the +2
                # revision tells a dry-run caller where a completed migration
                # will land.
                released_candidate["revision"] = \
                    policy.document["revision"] + 2
                peer_policy.validate_document(released_candidate)
                blast = peer_policy.blast_radius(
                    policy.document, released_candidate,
                    peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD)
                preview.update(self._blast_details(blast))
                preview["candidate_revision"] = released_candidate["revision"]
                if role in peer_policy.compile_roles(
                        released_candidate).restricted:
                    preview["newly_restricted"] = sorted(mapping)
            if dry_run or not mapping:
                return preview
            if blast.requires_confirmation and not \
                    peer_policy.confirm_blast_radius(
                        policy.document, released_candidate,
                        peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD,
                        confirm_token):
                raise RoleManagementError(
                    "confirmation required", code="confirmation_required",
                    status=428, **self._blast_details(blast))

            def confirm_staged_release(live_prior, live_staged):
                live_released = json.loads(json.dumps(live_staged))
                _remove_matching_assignments(live_released, mapping, acl_name)
                if not peer_policy.confirm_blast_radius(
                        live_prior, live_released,
                        peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD,
                        confirm_token):
                    current = peer_policy.blast_radius(
                        live_prior, live_released,
                        peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD)
                    raise peer_policy.PolicyError(
                        "confirmation required", code="confirmation_required",
                        confirm_token=current.confirm_token)

            def confirm_release(_live_staged, live_released):
                # Bind the operator's token to the actual removal candidate,
                # under the umbrella policy lock.  This catches a stale token
                # and any interleaved/tampered candidate before commit 2.
                if not peer_policy.confirm_blast_radius(
                        policy.document, live_released,
                        peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD,
                        confirm_token):
                    current = peer_policy.blast_radius(
                        policy.document, live_released,
                        peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD)
                    raise peer_policy.PolicyError(
                        "confirmation required", code="confirmation_required",
                        confirm_token=current.confirm_token)

            stage_guard = confirm_staged_release \
                if blast.requires_confirmation else None
            release_guard = confirm_release \
                if blast.requires_confirmation else None
            try:
                outcomes = self._write_fleet_roles(mapping)
            except Exception as exc:
                outcomes = (exc.results if isinstance(
                    exc, gui_fleet.FleetPartialWriteError)
                    else self._live_role_outcomes(mapping))
                applied, fleet_failed = self._fleet_outcomes(outcomes)
                failed.update(fleet_failed)
                try:
                    drift = self.role_drift()
                except Exception:
                    ids = sorted(set(mapping) - set(applied))
                    drift = {"count": len(ids),
                             "device_ids": ids[:DRIFT_ID_LIMIT],
                             "truncated": len(ids) > DRIFT_ID_LIMIT}
                raise RoleManagementError(
                    str(exc), code="fleet_write_failed", status=503,
                    partial=bool(applied),
                    result={"applied": len(applied), "failed": failed,
                            "revision": policy.document["revision"],
                            "role_drift": drift}) from None
            applied, fleet_failed = self._fleet_outcomes(outcomes)
            failed.update(fleet_failed)
            applied_mapping = {device_id: mapping[device_id]
                               for device_id in applied}
            if applied_mapping:
                try:
                    staged = self._commit_mapping(
                        applied_mapping, actor, action="migrate_roles",
                        target="acl:%s" % acl_name,
                        expected_revision=policy.document["revision"],
                        precommit=stage_guard)
                except Exception as exc:
                    self._translate_policy_error(
                        exc, partial=True, fallback_ids=applied_mapping,
                        applied_ids=applied, failed=failed)

                try:
                    released = peer_policy.commit_mutation(
                        self.auth_path, self.lkg_path,
                        action="migrate_release", target="acl:%s" % acl_name,
                        actor=actor, now=self.now_fn(),
                        mutate=lambda candidate: _remove_matching_assignments(
                            candidate, applied, acl_name),
                        acked_revision=self._acked(),
                        expected_revision=staged["revision"],
                        precommit=release_guard)
                except Exception as exc:
                    self._translate_policy_error(
                        exc, partial=True, fallback_ids=applied_mapping,
                        applied_ids=applied, failed=failed)
            else:
                released = policy.document
            drift = drift_report(self.fleet, self._load())
            return {"ok": not failed and not drift["count"], "dry_run": False,
                    "devices": sorted(applied),
                    "shadowed_inert": sorted(applied),
                    "newly_restricted": [device_id for device_id in
                                         sorted(applied) if device_id in
                                         preview["newly_restricted"]],
                    "failed": failed,
                    "revision": released["revision"], "role_drift": drift}
