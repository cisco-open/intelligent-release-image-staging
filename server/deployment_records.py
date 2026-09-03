# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durable, non-secret deployment record lifecycle state."""
import copy
import json
import os
import secrets
import tempfile
import time

import secrets_store


_STATES = frozenset(("planned", "applying", "active", "unknown", "drifted",
                     "needs-reconcile", "removed", "superseded", "abandoned"))
_NONTERMINAL = frozenset(("planned", "applying"))
# States that are not active but still describe a deployment IRIS applied, so a
# teardown may be authorized from them (see recoverable_for_device).
#
# "applying" is here because it is the durable marker written BEFORE the device
# is touched: an onboard that dies mid-run leaves it, and it already carries the
# resolved plan and owned resources teardown validates. Without it the marker
# was readable only after recover_interrupted() ran at process start, so with no
# restart a device stayed stranded forever -- not undeployable (no readable
# record), not adoptable (routers never are), not re-onboardable (preflight
# refuses the live Guest Shell). A genuinely in-flight onboard is NOT at risk:
# its job is still non-terminal, so the busy guard in gui_onboard refuses the
# undeploy before teardown is ever rendered.
_RECOVERABLE = frozenset(("unknown", "drifted", "needs-reconcile", "applying"))
# Recoverable states that describe a deployment nobody is working on. When a
# NEWER record of the same device goes active, these no longer describe the
# box and are abandoned (see _supersede_other_actives).
_STALE_ON_ACTIVATION = frozenset(("unknown", "drifted", "needs-reconcile"))
# States from which nothing further can happen: the record is history.
_TERMINAL = frozenset(("removed", "superseded", "abandoned"))
# Every non-terminal state can also be ABANDONED. That edge is reached when the
# device leaves the fleet (console delete) or when a forced teardown strips only
# the agent footprint: the record then stops describing anything IRIS manages,
# so it must stop being teardown authority and must stop blocking a re-onboard.
# It is deliberately NOT "removed" (which asserts IRIS tore the deployment down)
# and NOT "superseded" (which asserts a newer record replaced it) -- the record
# is kept because it is the only list of resources IRIS created on that box.
_TRANSITIONS = {
    "planned": frozenset(("applying", "unknown", "needs-reconcile", "removed",
                          "abandoned")),
    "applying": frozenset(("active", "unknown", "needs-reconcile", "removed",
                           "abandoned")),
    "active": frozenset(("drifted", "needs-reconcile", "applying", "removed",
                         "superseded", "abandoned")),
    # unknown/drifted/needs-reconcile must all still reach "applying", because
    # reconciling a deployment IS tearing it down. Without that edge a record
    # interrupted by a controller restart became a permanent dead end: the
    # device is already configured, so a re-onboard fails preflight, a router
    # cannot be adopted, and undeploy had no record to authorize it — leaving
    # no Console path to the device at all.
    "unknown": frozenset(("applying", "drifted", "needs-reconcile", "abandoned")),
    "drifted": frozenset(("applying", "needs-reconcile", "abandoned")),
    "needs-reconcile": frozenset(("applying", "abandoned")),
    "removed": frozenset(),
    "superseded": frozenset(),
    "abandoned": frozenset(),
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
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".records-", suffix=".tmp")
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


class RecordStoreUnreadable(ValueError):
    """The record file is present but cannot be parsed.

    A ``ValueError`` subclass so every existing ``except ValueError`` around a
    write path keeps behaving exactly as before, but distinguishable by callers
    that must not confuse "this device has no deployment record" with "we
    cannot read the records at all". Telling an operator to adopt a device IRIS
    may well already own is worse than saying nothing: adoption writes a record
    asserting an unverified deployment, and the real fault is a file on the
    server."""


class DeploymentRecordStore:
    """Lock-protected record store persisted beneath ``IRIS_STATE``."""
    def __init__(self, state_dir, now_fn=time.time):
        os.makedirs(state_dir, exist_ok=True)
        self.path = os.path.join(state_dir, "deployment_records.json")
        self._now = now_fn

    def _read(self, strict=False):
        """Load the store. A MISSING file is an empty store. A file that is
        present but unreadable is different: with strict=True (every write
        path) it raises, so the next create/transition cannot rewrite a
        corrupt but repairable file as a store holding one record -- these
        records are the only proof of what IRIS created on each box and the
        gate for undeploy/re-onboard. Without strict (reads) it degrades to
        an empty view.

        The strict failure is a RecordStoreUnreadable, so a reader that cannot
        safely treat "unreadable" as "empty" -- the console's undeploy gate --
        can ask for strict and report the real fault instead of "no record"."""
        try:
            with open(self.path) as stream:
                data = json.load(stream)
        except FileNotFoundError:
            return {"records": {}}
        except (OSError, ValueError) as exc:
            if strict:
                raise RecordStoreUnreadable(
                    "deployment record store %s is unreadable (%s); refusing "
                    "to overwrite it -- repair or remove the file"
                    % (self.path, exc))
            return {"records": {}}
        records = data.get("records", {}) if isinstance(data, dict) else None
        if not isinstance(records, dict):
            if strict:
                raise RecordStoreUnreadable(
                    "deployment record store %s is malformed; refusing to "
                    "overwrite it -- repair or remove the file" % self.path)
            return {"records": {}}
        return {"records": records}

    @staticmethod
    def _validate(record):
        if not isinstance(record, dict):
            raise ValueError("record must be an object")
        missing = [key for key in _REQUIRED if key not in record]
        if missing:
            raise ValueError("record missing %s" % ", ".join(missing))
        if record.get("state", "planned") != "planned":
            raise ValueError("new records must start planned")
        if not isinstance(record["inventory_revision"], int):
            raise ValueError("inventory_revision must be an integer")
        if not isinstance(record["resolved"], dict):
            raise ValueError("resolved must be an object")
        if not isinstance(record["preflight"], dict):
            raise ValueError("preflight must be an object")
        if not isinstance(record["resources"], list):
            raise ValueError("resources must be a list")
        if _contains_secret(record):
            raise ValueError("records must not contain secrets")

    def _supersede_other_actives(self, data, device_id, keep_record_id):
        """Retire every OTHER live record of ``device_id`` (caller holds the
        store lock). A device has ONE live deployment: when a new record goes
        active — a re-onboard's idempotent teardown+redeploy, or an explicit
        adopt — the previous active record no longer describes what is on the
        box, and neither does a sibling left in a recoverable but inactive
        state (unknown/drifted/needs-reconcile). Without this, actives
        accumulate and active_for_device() refuses undeploy; and a recoverable
        leftover survived the re-onboard only to resurface as teardown
        authority once the new record was removed -- offering a full recorded
        teardown, rendered from its stale VLAN/SVI numbers, against a box
        that no longer carries any of it. Actives become ``superseded``;
        the stale leftovers are ``abandoned`` with the reason recorded.
        ``planned``/``applying`` siblings are left alone: they belong to a
        job that is still in flight (adopt has no busy guard) and fail closed
        on their own if this activation made them stale."""
        timestamp = int(self._now())
        for record in data["records"].values():
            if (record.get("device_id") != device_id
                    or record.get("record_id") == keep_record_id):
                continue
            if record.get("state") == "active":
                record["state"] = "superseded"
                record.setdefault("timestamps", {})["finished_at"] = timestamp
            elif record.get("state") in _STALE_ON_ACTIVATION:
                record["state"] = "abandoned"
                record["evidence"] = {
                    "status": "abandoned",
                    "reason": "superseded by the activation of record %s"
                              % keep_record_id}
                record.setdefault("timestamps", {})["finished_at"] = timestamp

    def create(self, record_in):
        """Persist a new planned record and return its immutable initial record."""
        self._validate(record_in)
        record = copy.deepcopy(record_in)
        record["record_id"] = record.get("record_id") or secrets.token_hex(16)
        if not isinstance(record["record_id"], str) or not record["record_id"]:
            raise ValueError("record_id must be a non-empty string")
        timestamp = int(self._now())
        record["state"] = "planned"
        record["timestamps"] = {"planned_at": timestamp, "finished_at": None}
        with secrets_store.store_lock(self.path):
            data = self._read(strict=True)
            if record["record_id"] in data["records"]:
                raise ValueError("record already exists: %s" % record["record_id"])
            data["records"][record["record_id"]] = record
            _atomic_write_json(self.path, data)
        return copy.deepcopy(record)

    def adopt(self, record_in):
        """Create a record directly in ``active`` for an already-deployed device
        that predates records. This is the ONLY path that bypasses the planned
        start; callers must gate it behind an explicit, audited operator action."""
        self._validate(record_in)
        record = copy.deepcopy(record_in)
        record["record_id"] = record.get("record_id") or secrets.token_hex(16)
        if not isinstance(record["record_id"], str) or not record["record_id"]:
            raise ValueError("record_id must be a non-empty string")
        timestamp = int(self._now())
        record["state"] = "active"
        record["adopted"] = True
        record["timestamps"] = {"planned_at": timestamp, "finished_at": timestamp}
        with secrets_store.store_lock(self.path):
            data = self._read(strict=True)
            if record["record_id"] in data["records"]:
                raise ValueError("record already exists: %s" % record["record_id"])
            self._supersede_other_actives(data, record["device_id"],
                                          record["record_id"])
            data["records"][record["record_id"]] = record
            _atomic_write_json(self.path, data)
        return copy.deepcopy(record)

    def get(self, record_id):
        record = self._read()["records"].get(record_id)
        return copy.deepcopy(record) if record else None

    def update_planned(self, record_id, *, plan_hash, resolved, preflight,
                       resources):
        """Atomically refresh execution-time evidence on a planned record.

        Router jobs can wait in the onboarding queue, so ownership-sensitive
        preflight is repeated immediately before apply. Only a still-planned
        record may be refreshed; once applying starts its renderer inputs are
        immutable.
        """
        with secrets_store.store_lock(self.path):
            data = self._read(strict=True)
            record = data["records"].get(record_id)
            if record is None:
                raise ValueError("unknown record: %s" % record_id)
            if record.get("state") != "planned":
                raise ValueError("only planned records may refresh preflight")
            candidate = copy.deepcopy(record)
            candidate.update({"plan_hash": plan_hash,
                              "resolved": copy.deepcopy(resolved),
                              "preflight": copy.deepcopy(preflight),
                              "resources": copy.deepcopy(resources)})
            self._validate(candidate)
            data["records"][record_id] = candidate
            _atomic_write_json(self.path, data)
            return copy.deepcopy(candidate)

    def list(self, device_id=None, strict=False):
        """Records, optionally for one device. *strict* makes an unreadable
        store raise RecordStoreUnreadable instead of reading as empty; use it
        wherever an empty result would be reported to an operator as a fact
        about the device rather than about the file."""
        records = self._read(strict=strict)["records"].values()
        if device_id is not None:
            records = (record for record in records
                        if record.get("device_id") == device_id)
        return [copy.deepcopy(record) for record in records]

    def transition(self, record_id, state, evidence=None):
        """Advance a record through its fail-closed lifecycle state machine."""
        if state not in _STATES:
            raise ValueError("unknown record state: %s" % state)
        if evidence is not None and _contains_secret(evidence):
            raise ValueError("record evidence must not contain secrets")
        with secrets_store.store_lock(self.path):
            data = self._read(strict=True)
            record = data["records"].get(record_id)
            if record is None:
                raise ValueError("unknown record: %s" % record_id)
            current = record.get("state")
            if state not in _TRANSITIONS.get(current, frozenset()):
                raise ValueError("invalid record transition: %s -> %s" % (current, state))
            record["state"] = state
            if evidence is not None:
                record["evidence"] = copy.deepcopy(evidence)
            if state in ("active", "unknown", "drifted", "needs-reconcile", "removed"):
                record.setdefault("timestamps", {})["finished_at"] = int(self._now())
            if state == "active":
                self._supersede_other_actives(data, record.get("device_id"),
                                              record_id)
            _atomic_write_json(self.path, data)
            return copy.deepcopy(record)

    def recover_interrupted(self):
        """Mark planned/applying work unknown after a controller restart, and
        collapse legacy duplicate actives (written before activation superseded
        siblings): keep each device's NEWEST active — by activation time, then
        plan time, then record id, so the choice is deterministic — and retire
        the rest, restoring the one-active-per-device invariant undeploy needs."""
        changed = []
        with secrets_store.store_lock(self.path):
            data = self._read(strict=True)
            for record in data["records"].values():
                if record.get("state") in _NONTERMINAL:
                    record["state"] = "unknown"
                    record.setdefault("timestamps", {})["finished_at"] = int(self._now())
                    changed.append(record["record_id"])
            actives = {}
            for record in data["records"].values():
                if record.get("state") == "active":
                    actives.setdefault(record.get("device_id"), []).append(record)
            for duplicates in actives.values():
                if len(duplicates) < 2:
                    continue
                def _age(record):
                    timestamps = record.get("timestamps") or {}
                    return (timestamps.get("finished_at") or 0,
                            timestamps.get("planned_at") or 0,
                            record.get("record_id") or "")
                for record in sorted(duplicates, key=_age)[:-1]:
                    record["state"] = "superseded"
                    record.setdefault("timestamps", {})["finished_at"] = int(self._now())
                    changed.append(record["record_id"])
            if changed:
                _atomic_write_json(self.path, data)
        return changed

    def retire_device(self, device_id, reason):
        """Abandon every record of *device_id* that is not already terminal.

        Called when the device leaves the fleet (console delete) and after a
        forced agent-only teardown. Both leave a record that no longer
        describes a device IRIS manages, and a record in a recoverable state
        is what onboard refuses on and what undeploy renders teardown from --
        so leaving one behind hands the NEXT device registered under this id a
        dead predecessor's deployment. That is not hypothetical: it strands the
        device outright, because onboard says "undeploy it first" while the
        teardown it names refuses the box on an identity mismatch.

        The rows are kept, not dropped: a record is the only account of the
        resources IRIS created on that box (the VirtualPortGroup, the NAT
        stanza, the app address), and an operator who deletes a device that is
        still configured needs that list. *reason* is recorded as non-secret
        evidence so the trail says which of the two paths retired it.

        Returns the ids of the records retired, newest first."""
        retired = []
        with secrets_store.store_lock(self.path):
            data = self._read(strict=True)
            timestamp = int(self._now())
            for record in data["records"].values():
                if (record.get("device_id") != device_id
                        or record.get("state") in _TERMINAL):
                    continue
                record["state"] = "abandoned"
                record["evidence"] = {"status": "abandoned", "reason": reason}
                record.setdefault("timestamps", {})["finished_at"] = timestamp
                retired.append(record["record_id"])
            if retired:
                _atomic_write_json(self.path, data)
        return sorted(retired, reverse=True)

    def active_for_device(self, device_id, strict=False):
        active = [record for record in self.list(device_id, strict=strict)
                  if record.get("state") == "active"]
        if len(active) > 1:
            raise ValueError("multiple active records for device: %s" % device_id)
        return active[0] if active else None

    def recoverable_for_device(self, device_id, strict=False):
        """The record that may authorize a TEARDOWN of *device_id*: the active
        one, or — when there is none — a single record left in a recoverable
        state (unknown after a controller restart, or drifted/needs-reconcile).
        Those states still record the resolved plan and the owned resources,
        which is exactly the ownership proof teardown validates, and without
        this the device would be unmanageable.

        Returns None when nothing is left to reconcile. Raises when more than
        one candidate exists: two records mean we cannot prove which one
        describes the box, and tearing down the wrong one could remove
        resources the other still owns.

        *strict* raises RecordStoreUnreadable rather than returning None when
        the store file itself cannot be read -- "no record" and "no readable
        records" call for opposite advice to the operator."""
        active = self.active_for_device(device_id, strict=strict)
        if active is not None:
            return active
        candidates = [record for record in self.list(device_id, strict=strict)
                      if record.get("state") in _RECOVERABLE]
        if len(candidates) > 1:
            raise ValueError(
                "multiple recoverable records for device: %s — resolve them "
                "before undeploying" % device_id)
        return candidates[0] if candidates else None
