# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durable, non-secret deployment receipt lifecycle state."""
import copy
import json
import os
import secrets
import tempfile
import time

import secrets_store


_STATES = frozenset(("planned", "applying", "active", "unknown", "drifted",
                     "needs-reconcile", "removed", "superseded"))
_NONTERMINAL = frozenset(("planned", "applying"))
# States that are not active but still describe a deployment IRIS applied, so a
# teardown may be authorized from them (see recoverable_for_device).
_RECOVERABLE = frozenset(("unknown", "drifted", "needs-reconcile"))
_TRANSITIONS = {
    "planned": frozenset(("applying", "unknown", "needs-reconcile", "removed")),
    "applying": frozenset(("active", "unknown", "needs-reconcile", "removed")),
    "active": frozenset(("drifted", "needs-reconcile", "applying", "removed",
                         "superseded")),
    # unknown/drifted/needs-reconcile must all still reach "applying", because
    # reconciling a deployment IS tearing it down. Without that edge a receipt
    # interrupted by a controller restart became a permanent dead end: the
    # device is already configured, so a re-onboard fails preflight, a router
    # cannot be adopted, and undeploy had no receipt to authorize it — leaving
    # no Console path to the device at all.
    "unknown": frozenset(("applying", "drifted", "needs-reconcile")),
    "drifted": frozenset(("applying", "needs-reconcile")),
    "needs-reconcile": frozenset(("applying",)),
    "removed": frozenset(),
    "superseded": frozenset(),
}
_REQUIRED = ("controller_id", "device_id", "inventory_revision", "plan_hash",
             "resolved", "preflight", "resources")
_SECRET_KEYS = frozenset(("password", "pass", "token", "secret", "private_key",
                          "credential", "authorization"))


def _atomic_write_json(path, obj):
    directory = os.path.dirname(path) or "."
    mode = None
    try:
        mode = os.stat(path).st_mode
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".receipts-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(obj, stream, indent=2, sort_keys=True)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _contains_secret(value):
    if isinstance(value, dict):
        return any(any(secret_key in str(key).lower() for secret_key in _SECRET_KEYS)
                   or _contains_secret(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    return False


class ReceiptStore:
    """Lock-protected receipt store persisted beneath ``IRIS_STATE``."""
    def __init__(self, state_dir, now_fn=time.time):
        os.makedirs(state_dir, exist_ok=True)
        self.path = os.path.join(state_dir, "deployment_receipts.json")
        self._now = now_fn

    def _read(self):
        try:
            with open(self.path) as stream:
                data = json.load(stream)
            receipts = data.get("receipts", {}) if isinstance(data, dict) else {}
            return {"receipts": receipts} if isinstance(receipts, dict) else {"receipts": {}}
        except (OSError, ValueError):
            return {"receipts": {}}

    @staticmethod
    def _validate(receipt):
        if not isinstance(receipt, dict):
            raise ValueError("receipt must be an object")
        missing = [key for key in _REQUIRED if key not in receipt]
        if missing:
            raise ValueError("receipt missing %s" % ", ".join(missing))
        if receipt.get("state", "planned") != "planned":
            raise ValueError("new receipts must start planned")
        if not isinstance(receipt["inventory_revision"], int):
            raise ValueError("inventory_revision must be an integer")
        if not isinstance(receipt["resolved"], dict):
            raise ValueError("resolved must be an object")
        if not isinstance(receipt["preflight"], dict):
            raise ValueError("preflight must be an object")
        if not isinstance(receipt["resources"], list):
            raise ValueError("resources must be a list")
        if _contains_secret(receipt):
            raise ValueError("receipts must not contain secrets")

    def _supersede_other_actives(self, data, device_id, keep_receipt_id):
        """Retire every OTHER active receipt of ``device_id`` (caller holds the
        store lock). A device has ONE live deployment: when a new receipt goes
        active — a re-onboard's idempotent teardown+redeploy, or an explicit
        adopt — the previous active record no longer describes what is on the
        box. Without this, actives accumulate and active_for_device() refuses
        undeploy for the device."""
        timestamp = int(self._now())
        for receipt in data["receipts"].values():
            if (receipt.get("device_id") == device_id
                    and receipt.get("state") == "active"
                    and receipt.get("receipt_id") != keep_receipt_id):
                receipt["state"] = "superseded"
                receipt.setdefault("timestamps", {})["finished_at"] = timestamp

    def create(self, receipt):
        """Persist a new planned receipt and return its immutable initial record."""
        self._validate(receipt)
        record = copy.deepcopy(receipt)
        record["receipt_id"] = record.get("receipt_id") or secrets.token_hex(16)
        if not isinstance(record["receipt_id"], str) or not record["receipt_id"]:
            raise ValueError("receipt_id must be a non-empty string")
        timestamp = int(self._now())
        record["state"] = "planned"
        record["timestamps"] = {"planned_at": timestamp, "finished_at": None}
        with secrets_store.store_lock(self.path):
            data = self._read()
            if record["receipt_id"] in data["receipts"]:
                raise ValueError("receipt already exists: %s" % record["receipt_id"])
            data["receipts"][record["receipt_id"]] = record
            _atomic_write_json(self.path, data)
        return copy.deepcopy(record)

    def adopt(self, receipt):
        """Create a receipt directly in ``active`` for an already-deployed device
        that predates receipts. This is the ONLY path that bypasses the planned
        start; callers must gate it behind an explicit, audited operator action."""
        self._validate(receipt)
        record = copy.deepcopy(receipt)
        record["receipt_id"] = record.get("receipt_id") or secrets.token_hex(16)
        if not isinstance(record["receipt_id"], str) or not record["receipt_id"]:
            raise ValueError("receipt_id must be a non-empty string")
        timestamp = int(self._now())
        record["state"] = "active"
        record["adopted"] = True
        record["timestamps"] = {"planned_at": timestamp, "finished_at": timestamp}
        with secrets_store.store_lock(self.path):
            data = self._read()
            if record["receipt_id"] in data["receipts"]:
                raise ValueError("receipt already exists: %s" % record["receipt_id"])
            self._supersede_other_actives(data, record["device_id"],
                                          record["receipt_id"])
            data["receipts"][record["receipt_id"]] = record
            _atomic_write_json(self.path, data)
        return copy.deepcopy(record)

    def get(self, receipt_id):
        receipt = self._read()["receipts"].get(receipt_id)
        return copy.deepcopy(receipt) if receipt else None

    def update_planned(self, receipt_id, *, plan_hash, resolved, preflight,
                       resources):
        """Atomically refresh execution-time evidence on a planned receipt.

        Router jobs can wait in the onboarding queue, so ownership-sensitive
        preflight is repeated immediately before apply. Only a still-planned
        receipt may be refreshed; once applying starts its renderer inputs are
        immutable.
        """
        with secrets_store.store_lock(self.path):
            data = self._read()
            receipt = data["receipts"].get(receipt_id)
            if receipt is None:
                raise ValueError("unknown receipt: %s" % receipt_id)
            if receipt.get("state") != "planned":
                raise ValueError("only planned receipts may refresh preflight")
            candidate = copy.deepcopy(receipt)
            candidate.update({"plan_hash": plan_hash,
                              "resolved": copy.deepcopy(resolved),
                              "preflight": copy.deepcopy(preflight),
                              "resources": copy.deepcopy(resources)})
            self._validate(candidate)
            data["receipts"][receipt_id] = candidate
            _atomic_write_json(self.path, data)
            return copy.deepcopy(candidate)

    def list(self, device_id=None):
        receipts = self._read()["receipts"].values()
        if device_id is not None:
            receipts = (receipt for receipt in receipts
                        if receipt.get("device_id") == device_id)
        return [copy.deepcopy(receipt) for receipt in receipts]

    def transition(self, receipt_id, state, evidence=None):
        """Advance a receipt through its fail-closed lifecycle state machine."""
        if state not in _STATES:
            raise ValueError("unknown receipt state: %s" % state)
        if evidence is not None and _contains_secret(evidence):
            raise ValueError("receipt evidence must not contain secrets")
        with secrets_store.store_lock(self.path):
            data = self._read()
            receipt = data["receipts"].get(receipt_id)
            if receipt is None:
                raise ValueError("unknown receipt: %s" % receipt_id)
            current = receipt.get("state")
            if state not in _TRANSITIONS.get(current, frozenset()):
                raise ValueError("invalid receipt transition: %s -> %s" % (current, state))
            receipt["state"] = state
            if evidence is not None:
                receipt["evidence"] = copy.deepcopy(evidence)
            if state in ("active", "unknown", "drifted", "needs-reconcile", "removed"):
                receipt.setdefault("timestamps", {})["finished_at"] = int(self._now())
            if state == "active":
                self._supersede_other_actives(data, receipt.get("device_id"),
                                              receipt_id)
            _atomic_write_json(self.path, data)
            return copy.deepcopy(receipt)

    def recover_interrupted(self):
        """Mark planned/applying work unknown after a controller restart, and
        collapse legacy duplicate actives (written before activation superseded
        siblings): keep each device's NEWEST active — by activation time, then
        plan time, then receipt id, so the choice is deterministic — and retire
        the rest, restoring the one-active-per-device invariant undeploy needs."""
        changed = []
        with secrets_store.store_lock(self.path):
            data = self._read()
            for receipt in data["receipts"].values():
                if receipt.get("state") in _NONTERMINAL:
                    receipt["state"] = "unknown"
                    receipt.setdefault("timestamps", {})["finished_at"] = int(self._now())
                    changed.append(receipt["receipt_id"])
            actives = {}
            for receipt in data["receipts"].values():
                if receipt.get("state") == "active":
                    actives.setdefault(receipt.get("device_id"), []).append(receipt)
            for duplicates in actives.values():
                if len(duplicates) < 2:
                    continue
                def _age(receipt):
                    timestamps = receipt.get("timestamps") or {}
                    return (timestamps.get("finished_at") or 0,
                            timestamps.get("planned_at") or 0,
                            receipt.get("receipt_id") or "")
                for receipt in sorted(duplicates, key=_age)[:-1]:
                    receipt["state"] = "superseded"
                    receipt.setdefault("timestamps", {})["finished_at"] = int(self._now())
                    changed.append(receipt["receipt_id"])
            if changed:
                _atomic_write_json(self.path, data)
        return changed

    def active_for_device(self, device_id):
        active = [receipt for receipt in self.list(device_id)
                  if receipt.get("state") == "active"]
        if len(active) > 1:
            raise ValueError("multiple active receipts for device: %s" % device_id)
        return active[0] if active else None

    def recoverable_for_device(self, device_id):
        """The receipt that may authorize a TEARDOWN of *device_id*: the active
        one, or — when there is none — a single receipt left in a recoverable
        state (unknown after a controller restart, or drifted/needs-reconcile).
        Those states still record the resolved plan and the owned resources,
        which is exactly the ownership proof teardown validates, and without
        this the device would be unmanageable.

        Returns None when nothing is left to reconcile. Raises when more than
        one candidate exists: two receipts mean we cannot prove which one
        describes the box, and tearing down the wrong one could remove
        resources the other still owns."""
        active = self.active_for_device(device_id)
        if active is not None:
            return active
        candidates = [receipt for receipt in self.list(device_id)
                      if receipt.get("state") in _RECOVERABLE]
        if len(candidates) > 1:
            raise ValueError(
                "multiple recoverable receipts for device: %s — resolve them "
                "before undeploying" % device_id)
        return candidates[0] if candidates else None
