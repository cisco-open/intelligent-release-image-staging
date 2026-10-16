# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Reviewed, bounded origin-blocking approvals; no activation by upgrade.

The management API writes the private approval. Only the tracker applies rules
and writes the private application journal. Public projections contain counts,
never address lists or Aria2 session identifiers.
"""
import contextlib
import copy
import fcntl
import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import stat
import tempfile

import blocklist_reconciler as reconciler
import peer_endpoints
import peer_policy

SCHEMA = 1
DEFAULT_BUDGET = 10
MAX_BUDGET = 1000
MAX_IPS = peer_endpoints.MAX_PRINCIPALS * peer_endpoints.ENDPOINT_CAP
MAX_DEVICES = peer_endpoints.SUPPORTED_DEVICES
MAX_BINDINGS = MAX_IPS
MAX_APPLIED_IPS = MAX_IPS * 2 + peer_endpoints.MAX_PRINCIPALS
MAX_BYTES = 8 * 1024 * 1024
MAX_APPLICATION_BYTES = 16 * 1024 * 1024
STATES = frozenset(("preflight", "pending", "enforced", "review_required",
                    "degraded", "unavailable"))
REASONS = frozenset((
    "origin_unknown", "origin_unobserved", "origin_mismatch",
    "policy_unavailable", "endpoint_state_unavailable", "control_state_unavailable",
    "application_state_unavailable", "policy_changed", "endpoint_set_changed",
    "shared_address", "protected_address", "ip_budget_exceeded",
    "device_budget_exceeded", "retention_capacity_exceeded", "application_pending",
    "aria_unavailable", "apply_failed", "session_changed"))
_ID = re.compile(r"device:[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_COUNTS = ("new_ip_count", "new_device_count", "retained_ip_count",
           "proposed_ip_count", "proposed_device_count", "shared_conflict_count",
           "protected_conflict_count")


class OriginError(ValueError):
    def __init__(self, code, status=409):
        super().__init__(code)
        self.code, self.status = code, status


def _integer(value, maximum=None):
    return type(value) is int and value >= 0 and (maximum is None or value <= maximum)


def _time(value):
    try:
        return type(value) in (int, float) and math.isfinite(value) and value >= 0
    except OverflowError:
        return False


def valid_origin(value):
    if not reconciler.valid_protected_seeder_ipv4(value):
        return False
    address = ipaddress.IPv4Address(value)
    return not address.is_unspecified and not address.is_multicast and value != "255.255.255.255"


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()


def policy_hash(policy):
    # Includes the history epoch, not merely a potentially replayed revision.
    return _hash(policy.document)


def default_control():
    return {"schema": SCHEMA, "revision": 0, "mode": "preflight",
            "max_new_ips": DEFAULT_BUDGET, "max_new_devices": DEFAULT_BUDGET,
            "approval": None}


def bindings_devices(bindings):
    return {principal for row in bindings for principal in row["principals"]}


def validate_bindings(value):
    if not isinstance(value, list) or len(value) > MAX_IPS:
        raise OriginError("origin_enforcement_unavailable", 503)
    addresses, devices, result, binding_count = [], set(), [], 0
    for row in value:
        if not isinstance(row, dict) or set(row) != {"ipv4", "principals"}:
            raise OriginError("origin_enforcement_unavailable", 503)
        address, principals = row["ipv4"], row["principals"]
        if not isinstance(address, str):
            raise OriginError("origin_enforcement_unavailable", 503)
        try:
            if str(ipaddress.IPv4Address(address)) != address:
                raise ValueError()
        except ValueError as exc:
            raise OriginError("origin_enforcement_unavailable", 503) from exc
        if (not isinstance(principals, list) or not principals
                or len(principals) > MAX_DEVICES
                or any(not isinstance(key, str) or not _ID.fullmatch(key) for key in principals)
                or principals != sorted(set(principals))):
            raise OriginError("origin_enforcement_unavailable", 503)
        addresses.append(address)
        devices.update(principals)
        binding_count += len(principals)
        result.append({"ipv4": address, "principals": list(principals)})
    if (addresses != sorted(set(addresses)) or len(devices) > MAX_DEVICES
            or binding_count > MAX_BINDINGS):
        raise OriginError("origin_enforcement_unavailable", 503)
    return result


def validate_control(value):
    fields = {"schema", "revision", "mode", "max_new_ips", "max_new_devices", "approval"}
    if (not isinstance(value, dict) or set(value) != fields
            or type(value["schema"]) is not int or value["schema"] != SCHEMA
            or not _integer(value["revision"])
            or value["mode"] not in ("preflight", "enforce")
            or not _integer(value["max_new_ips"], MAX_BUDGET)
            or not _integer(value["max_new_devices"], MAX_BUDGET)):
        raise OriginError("origin_enforcement_unavailable", 503)
    approval = value["approval"]
    if value["mode"] == "preflight":
        if approval is not None:
            raise OriginError("origin_enforcement_unavailable", 503)
    else:
        if (not isinstance(approval, dict)
                or set(approval) != {"policy_hash", "policy_revision", "origin_ipv4",
                                     "bindings", "reviewed_at"}
                or not isinstance(approval["policy_hash"], str)
                or not _HASH.fullmatch(approval["policy_hash"])
                or not _integer(approval["policy_revision"])
                or not valid_origin(approval["origin_ipv4"])
                or not _time(approval["reviewed_at"])):
            raise OriginError("origin_enforcement_unavailable", 503)
        validate_bindings(approval["bindings"])
    return copy.deepcopy(value)


def read_json(path, *, max_bytes=MAX_BYTES):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise OriginError("origin_enforcement_unavailable", 503) from exc
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_size > max_bytes:
            raise OriginError("origin_enforcement_unavailable", 503)
        with os.fdopen(descriptor, "r") as stream:
            descriptor = None
            value = json.load(stream)
            # None is reserved for a genuinely absent file. A JSON null on
            # disk is corrupt state, never evidence of a fresh installation.
            if value is None:
                raise OriginError("origin_enforcement_unavailable", 503)
            return value
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise OriginError("origin_enforcement_unavailable", 503) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def write_json(path, value):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".origin-enforcement-", dir=directory)
    try:
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def locked(path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    descriptor = os.open(path + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def load_control(path):
    value = read_json(path)
    if value is None and any(os.path.lexists(os.path.join(os.path.dirname(path), name))
            for name in ("origin-enforcement.application.json", "origin-enforcement.status.json")):
        raise OriginError("origin_enforcement_unavailable", 503)
    return default_control() if value is None else validate_control(value)


def approved_bindings(control):
    return (control.get("approval") or {}).get("bindings", [])


def merge_approved(durable, control):
    """Retain only exact bounded approvals, not arbitrary expired endpoints."""
    merged = copy.deepcopy(durable)
    for row in approved_bindings(control):
        for key in row["principals"]:
            entry = merged.setdefault(key, {"principal_type": "device",
                "principal_id": key.split(":", 1)[1], "endpoints": []})
            if not any(endpoint["ipv4"] == row["ipv4"] for endpoint in entry["endpoints"]):
                entry["endpoints"].append({"ipv4": row["ipv4"]})
    return merged


def observe(policy, durable, pending, revoked, origin, control):
    """Private exact snapshot, including approved evidence after endpoint TTL."""
    merged = merge_approved(durable, control)
    protected = {origin} if valid_origin(origin) else set()
    observed_origin = set()
    for snapshot in (durable, pending):
        for key, entry in snapshot.items():
            if key == "service:seeder":
                observed_origin.update(endpoint["ipv4"] for endpoint in entry.get("endpoints", []))
    protected.update(observed_origin)
    blockers = []
    if policy.fail_closed or policy.degraded:
        blockers.append("policy_unavailable")
    if not valid_origin(origin):
        blockers.append("origin_unknown")
    elif not observed_origin:
        blockers.append("origin_unobserved")
    elif origin not in observed_origin:
        blockers.append("origin_mismatch")
    derived = reconciler.derive_denied_set(policy, merged, pending, [], revoked, origin)
    # A missing seeder observation prevents activation, but does not erase
    # positive evidence that an already-approved IP now serves an allowed
    # principal too. Apply this safety exclusion even on the frozen-list path.
    shared = {conflict["ipv4"] for conflict in derived.prospective_conflicts or []}
    if (not policy.fail_closed and not policy.degraded
            and not valid_origin(origin) and control.get("approval")):
        # The last reviewed origin is sufficient to detect unsafe attribution,
        # but not to authorize new blocks or claim the current origin is known.
        safety = reconciler.derive_denied_set(policy, merged, pending, [], revoked,
                                              control["approval"]["origin_ipv4"])
        shared.update(conflict["ipv4"] for conflict in safety.prospective_conflicts or [])
    result = {"policy_revision": policy.document["revision"], "policy_hash": policy_hash(policy),
              "origin_ipv4": origin, "bindings": [], "derived": derived,
              "shared_ips": shared, "protected_ips": protected, "blockers": blockers,
              **{name: None for name in _COUNTS}}
    if blockers:
        return result
    denied_devices = {}
    protected_denied = set()
    compiled = policy.roles or peer_policy.compile_roles(policy.document)
    seeder = reconciler._Struct("service", "seeder")
    for snapshot in (merged, pending):
        for key, entry in snapshot.items():
            if entry["principal_type"] != "device":
                continue
            principal = reconciler._Struct("device", entry["principal_id"])
            for endpoint in entry["endpoints"]:
                address = endpoint["ipv4"]
                denied = key in revoked or not peer_policy.mutual_permit(
                    policy.document, seeder, origin, principal, address, compiled=compiled)
                if denied:
                    denied_devices.setdefault(address, set()).add(key)
                    if address in protected:
                        protected_denied.add(address)
    extra = (set(derived.prospective_denied_ips or []) - set(derived.denied_ips)
             - protected - shared)
    bindings = [{"ipv4": address, "principals": sorted(denied_devices[address])}
                for address in sorted(extra) if address in denied_devices]
    prior = approved_bindings(control)
    old_ips = {row["ipv4"] for row in prior}
    proposed_ips = {row["ipv4"] for row in bindings}
    devices = bindings_devices(bindings)
    if shared:
        blockers.append("shared_address")
    if protected_denied:
        blockers.append("protected_address")
    if (len(bindings) > MAX_IPS or len(devices) > MAX_DEVICES
            or sum(len(row["principals"]) for row in bindings) > MAX_BINDINGS):
        blockers.append("retention_capacity_exceeded")
    result.update(bindings=bindings, shared_ips=shared,
        new_ip_count=len(proposed_ips - old_ips),
        new_device_count=len(devices - bindings_devices(prior)),
        retained_ip_count=len(proposed_ips & old_ips), proposed_ip_count=len(bindings),
        proposed_device_count=len(devices), shared_conflict_count=len(shared),
        protected_conflict_count=len(protected_denied))
    return result


def preview(control, observation, mode, max_new_ips, max_new_devices):
    if (mode not in ("preflight", "enforce")
            or not _integer(max_new_ips, MAX_BUDGET)
            or not _integer(max_new_devices, MAX_BUDGET)):
        raise OriginError("invalid_origin_enforcement", 422)
    blockers = list(observation["blockers"])
    if mode == "enforce":
        if observation["new_ip_count"] is not None and observation["new_ip_count"] > max_new_ips:
            blockers.append("ip_budget_exceeded")
        if observation["new_device_count"] is not None and observation["new_device_count"] > max_new_devices:
            blockers.append("device_budget_exceeded")
    else:
        # Disabling releases origin-only blocks but still requires usable policy
        # and endpoint state, so it cannot accidentally clear baseline controls.
        blockers = [code for code in blockers if code not in
                    ("origin_unobserved", "origin_mismatch", "shared_address", "protected_address")]
    counts = {name: observation[name] for name in _COUNTS}
    if mode == "preflight" and not blockers:
        # The proposed retained origin set is empty on a reviewed release.
        # These exact counts remain available even without a fresh seeder
        # announce; ordinary quarantine/revocation still follows the baseline.
        counts.update(new_ip_count=0, new_device_count=0, retained_ip_count=0,
                      proposed_ip_count=0, proposed_device_count=0,
                      shared_conflict_count=len(observation["shared_ips"]),
                      protected_conflict_count=observation["protected_conflict_count"] or 0)
    request = {"mode": mode, "max_new_ips": max_new_ips, "max_new_devices": max_new_devices}
    token = None if blockers else _hash({
        "control": control, "policy_hash": observation["policy_hash"],
        "origin_ipv4": observation["origin_ipv4"], "bindings": observation["bindings"],
        "baseline": observation["derived"].denied_ips,
        "request": request})
    return {"revision": control["revision"], "policy_revision": observation["policy_revision"],
            **request, **counts,
            "approved_ip_count": len(approved_bindings(control)),
            "approved_device_count": len(bindings_devices(approved_bindings(control))),
            "dry_run": True, "requires_confirmation": True, "confirm_token": token,
            "blockers": blockers}


def approved_control(control, observation, proposed, token, now):
    if proposed["blockers"]:
        raise OriginError("origin_enforcement_blocked")
    if (not isinstance(token, str) or not _HASH.fullmatch(token)
            or not secrets.compare_digest(token, proposed["confirm_token"] or "")):
        raise OriginError("origin_review_stale")
    result = {"schema": SCHEMA, "revision": control["revision"] + 1,
        "mode": proposed["mode"], "max_new_ips": proposed["max_new_ips"],
        "max_new_devices": proposed["max_new_devices"], "approval": None}
    if result["mode"] == "enforce":
        result["approval"] = {"policy_hash": observation["policy_hash"],
            "policy_revision": observation["policy_revision"],
            "origin_ipv4": observation["origin_ipv4"],
            "bindings": observation["bindings"], "reviewed_at": now}
    return validate_control(result)


def etag(revision):
    return '"origin-enforcement-%d"' % revision


def paths(state_dir):
    return tuple(os.path.join(state_dir, name) for name in (
        "origin-enforcement.json", "origin-enforcement.application.json",
        "origin-enforcement.status.json"))


def validate_application(value):
    if value is None:
        return {"schema": SCHEMA, "last_applied": None, "intent": None,
                "shared_revision": 0, "shared_ips": []}
    if (not isinstance(value, dict) or set(value) != {
            "schema", "last_applied", "intent", "shared_revision", "shared_ips"}
            or type(value["schema"]) is not int or value["schema"] != SCHEMA
            or not _integer(value["shared_revision"])
            or not isinstance(value["shared_ips"], list) or len(value["shared_ips"]) > MAX_IPS
            or any(not isinstance(ip, str) or not reconciler.valid_protected_seeder_ipv4(ip)
                   for ip in value["shared_ips"])
            or value["shared_ips"] != sorted(set(value["shared_ips"]))):
        raise OriginError("origin_enforcement_unavailable", 503)
    for name in ("last_applied", "intent"):
        row = value[name]
        if row is None:
            continue
        if (not isinstance(row, dict) or set(row) != {
                "revision", "control_hash", "policy_hash", "ips", "bindings", "session", "verified_at"}
                or not _integer(row["revision"])
                or not isinstance(row["control_hash"], str)
                or not _HASH.fullmatch(row["control_hash"])
                or not isinstance(row["policy_hash"], str)
                or not _HASH.fullmatch(row["policy_hash"])
                or not isinstance(row["ips"], list) or len(row["ips"]) > MAX_APPLIED_IPS
                or any(not isinstance(ip, str) for ip in row["ips"])
                or row["ips"] != sorted(set(row["ips"]))
                or (row["session"] is not None and (
                    not isinstance(row["session"], str) or not row["session"]
                    or len(row["session"]) > 128))
                or (row["verified_at"] is not None and not _time(row["verified_at"]))):
            raise OriginError("origin_enforcement_unavailable", 503)
        try:
            for ip in row["ips"]:
                if str(ipaddress.IPv4Address(ip)) != ip:
                    raise ValueError()
        except ValueError as exc:
            raise OriginError("origin_enforcement_unavailable", 503) from exc
        validate_bindings(row["bindings"])
        if name == "last_applied" and (not row["session"] or row["verified_at"] is None):
            raise OriginError("origin_enforcement_unavailable", 503)
    if (value["intent"] is not None and value["last_applied"] is not None
            and value["intent"]["revision"] < value["last_applied"]["revision"]):
        raise OriginError("origin_enforcement_unavailable", 503)
    return copy.deepcopy(value)


def load_application(path, *, required=False):
    # A journal temporarily holds both an acknowledged and an attempted set.
    # Its bound must accommodate two legal maximum-sized binding snapshots.
    value = read_json(path, max_bytes=MAX_APPLICATION_BYTES)
    if value is None and required:
        raise OriginError("origin_enforcement_unavailable", 503)
    return validate_application(value)


def load_application_for(control, path):
    """Reject mixed/restored generations before even the preflight shortcut."""
    application = load_application(path, required=control["revision"] > 0)
    revision = control["revision"]
    if application["shared_revision"] > revision:
        raise OriginError("origin_enforcement_unavailable", 503)
    for name in ("last_applied", "intent"):
        row = application[name]
        if row is not None and (row["revision"] > revision or
                row["revision"] == revision and row["control_hash"] != _hash(control)):
            raise OriginError("origin_enforcement_unavailable", 503)
    if (application["shared_revision"] == revision
            and not set(application["shared_ips"]) <=
            {row["ipv4"] for row in approved_bindings(control)}):
        raise OriginError("origin_enforcement_unavailable", 503)
    return application


def public_view(control, observation, proof=None, now=0):
    """Never turn desired mode, stale acknowledgements or counts into proof."""
    proposed = preview(control, observation, control["mode"],
                       control["max_new_ips"], control["max_new_devices"])
    # Reads keep the diagnostic observation; a PUT preview separately reports
    # its proposed target counts (zero when releasing origin restrictions).
    proposed.update({name: observation[name] for name in _COUNTS})
    for name in ("dry_run", "requires_confirmation", "confirm_token"):
        proposed.pop(name)
    proposed.update(state="preflight" if control["mode"] == "preflight" else "pending",
                    reason=None if control["mode"] == "preflight" else "application_pending",
                    applied_ip_count=None, applied_device_count=None, last_verified_at=None)
    if control["revision"] and control["mode"] == "preflight":
        proposed.update(state="pending", reason="application_pending")
    approval = control["approval"]
    if approval:
        if (valid_origin(observation["origin_ipv4"])
                and approval["origin_ipv4"] != observation["origin_ipv4"]
                and "origin_mismatch" not in proposed["blockers"]):
            proposed["blockers"].append("origin_mismatch")
        if approval["policy_hash"] != observation["policy_hash"]:
            proposed["blockers"].append("policy_changed")
        elif approval["bindings"] != observation["bindings"] and not observation["blockers"]:
            proposed["blockers"].append("endpoint_set_changed")
    if proposed["blockers"]:
        reason = proposed["blockers"][0]
        proposed.update(state="review_required" if reason in
                        ("policy_changed", "endpoint_set_changed") else "degraded",
                        reason=reason)
        return proposed
    # Status is produced only after a current-session acknowledgement. Validate
    # the entire closed proof before consuming any of its fields.
    required = {"revision", "policy_hash", "state", "reason", "applied_ip_count",
                "applied_device_count", "last_verified_at", "updated_at"}
    if (isinstance(proof, dict) and set(proof) == required
            and type(proof["revision"]) is int and proof["revision"] == control["revision"]
            and proof["policy_hash"] == observation["policy_hash"]
            and isinstance(proof["state"], str) and proof["state"] in STATES
            and (proof["reason"] is None or isinstance(proof["reason"], str)
                 and proof["reason"] in REASONS)
            and _time(proof["updated_at"]) and 0 <= now - proof["updated_at"] <= 120
            and all(proof[name] is None or _integer(proof[name]) for name in
                    ("applied_ip_count", "applied_device_count"))
            and (proof["last_verified_at"] is None or _time(proof["last_verified_at"]))):
        healthy = proof["state"] in ("enforced", "preflight")
        healthy = healthy and proof["reason"] is None and (
            proof["last_verified_at"] is not None and proof["last_verified_at"] > 0
            and proof["last_verified_at"] <= proof["updated_at"]
            and proof["applied_ip_count"] == len(approved_bindings(control))
            and proof["applied_device_count"] == len(bindings_devices(approved_bindings(control))))
        healthy = healthy and (proof["state"] == "enforced") == (control["mode"] == "enforce")
        if healthy or proof["state"] not in ("enforced", "preflight"):
            for name in required - {"revision", "policy_hash", "updated_at"}:
                proposed[name] = proof[name]
            if not healthy:
                proposed.update(applied_ip_count=None, applied_device_count=None,
                                last_verified_at=None)
    elif control["revision"]:
        proposed.update(state="unavailable", reason="application_state_unavailable")
    return proposed


class Store:
    """Management-side CAS; the tracker remains the sole RPC writer."""
    def __init__(self, state_dir, origin, revoked=None, now=None):
        import time
        self.state_dir, self.origin = state_dir, origin
        self.control_path, self.application_path, self.status_path = paths(state_dir)
        self.policy_paths = tuple(os.path.join(state_dir, name) for name in
                                  ("peer-policy.json", "peer-policy.lkg.json"))
        self.endpoints_path = os.path.join(state_dir, "peer-endpoints.json")
        self.revoked, self.now = revoked or (lambda: set()), now or time.time

    def snapshot(self, control, *, initialize_missing=True):
        policy = peer_policy.load_policy(*self.policy_paths,
                                        initialize_missing=initialize_missing)
        revoked = self.revoked()
        if revoked is None:
            raise OriginError("origin_enforcement_unavailable", 503)
        durable = peer_endpoints.fresh_endpoints(self.endpoints_path, self.now(),
            keep=reconciler.denied_retention(policy, revoked))
        observation = observe(policy, durable, {}, revoked, self.origin, control)
        return observation

    def read(self):
        control = load_control(self.control_path)
        load_application_for(control, self.application_path)
        observation = self.snapshot(control)
        try:
            proof = read_json(self.status_path)
        except OriginError:
            proof = None
        return public_view(control, observation, proof, self.now())

    def change(self, body, matches):
        required = {"mode", "max_new_ips", "max_new_devices", "if_policy_revision", "dry_run"}
        if (not isinstance(body, dict) or set(body) - (required | {"confirm_token"})
                or not required <= set(body) or type(body["dry_run"]) is not bool
                or not _integer(body["if_policy_revision"])
                or ("confirm_token" in body and not isinstance(body["confirm_token"], str))):
            raise OriginError("invalid_origin_enforcement", 422)
        # Consistent lock ordering: policy first, control second. Endpoint
        # observations are re-read after both locks; no cached count authorizes
        # an apply. Runtime rechecks the exact bindings independently.
        peer_policy.load_policy(*self.policy_paths)  # Fresh-install initialization before locks.
        with peer_policy._umbrella_lock(self.policy_paths[0]), locked(self.control_path):
            control = load_control(self.control_path)
            if not matches:
                raise OriginError("precondition_required", 428)
            if matches != [etag(control["revision"])]:
                raise OriginError("precondition_failed", 412)
            load_application_for(control, self.application_path)
            observation = self.snapshot(control, initialize_missing=False)
            if body["if_policy_revision"] != observation["policy_revision"]:
                raise OriginError("policy_revision_conflict")
            proposed = preview(control, observation, body["mode"],
                               body["max_new_ips"], body["max_new_devices"])
            current = public_view(control, observation, read_json(self.status_path), self.now())
            if body["dry_run"]:
                return {**current, **proposed}
            prior_control = control
            control = approved_control(control, observation, proposed,
                                       body.get("confirm_token"), self.now())
            if prior_control["revision"] == 0:
                # The journal exists before an approval becomes visible. Once
                # opted in, a missing journal is state loss, not a fresh start.
                # Materialize inert control first: a crash between the next
                # two writes must remain a retryable preflight installation,
                # not look like a lost established control file.
                write_json(self.control_path, prior_control)
                write_json(self.application_path, validate_application(None))
            write_json(self.control_path, control)
            # Never reuse previous proof after a reviewed change, even a
            # same-mode reapproval with no changed counts.
            result = public_view(control, observation, now=self.now())
            result.update(state="pending", reason="application_pending", blockers=[],
                          applied_ip_count=None, applied_device_count=None,
                          last_verified_at=None, dry_run=False,
                          requires_confirmation=False, confirm_token=None)
            return result


class Runtime:
    """One tracker's bounded reviewed plan and durable apply acknowledgement."""
    def __init__(self, state_dir):
        self.control_path, self.application_path, self.status_path = paths(state_dir)
        self.control = default_control()
        self.application = None
        self.observation = None
        self.reason = None
        self.enabled = False
        self.desired = None
        self.bindings = []

    def prepare(self, policy, durable, pending, revoked, origin, baseline):
        self.reason, self.desired, self.bindings = None, None, []
        try:
            self.control = load_control(self.control_path)
        except (OriginError, OSError):
            self.enabled, self.reason = True, "control_state_unavailable"
            return None
        self.enabled = self.control["revision"] > 0 or self.control["mode"] == "enforce"
        self.observation = observe(policy, durable, pending, revoked, origin, self.control)
        try:
            self.application = load_application_for(self.control, self.application_path)
        except (OriginError, OSError):
            self.enabled = True
            self.reason = "application_state_unavailable"
            return None
        if not self.enabled:
            return baseline
        current = public_view(self.control, self.observation)
        self.reason = current["blockers"][0] if current["blockers"] else None
        approval = self.control["approval"]
        if approval and valid_origin(origin) and approval["origin_ipv4"] != origin:
            self.reason = "origin_mismatch"
        if self.reason in ("origin_unknown", "origin_unobserved", "origin_mismatch",
                           "policy_unavailable", "policy_changed"):
            if self.application["intent"] is not None:
                # A timed-out/crashed apply may have reached aria2. Replacing
                # it with last_applied would silently assume that it did not.
                # Leave the live list untouched until current evidence allows
                # an exact reviewed apply again.
                self.reason = "application_state_unavailable"
                return None
            # Freeze the last exact acknowledged list. Do not reconstruct a
            # new origin list from incomplete evidence or from today's counts.
            previous = self.application["last_applied"]
            if previous is None:
                return None
            desired = set(previous["ips"])
            bindings = previous["bindings"]
            if self.reason == "policy_changed":
                # A healthy newer policy still controls ordinary quarantine
                # and revocation. Retain only prior origin-specific bindings,
                # not yesterday's unrelated baseline decisions.
                desired = set(self.observation["derived"].denied_ips)
                desired.update(row["ipv4"] for row in bindings)
        else:
            desired = set(self.observation["derived"].denied_ips)
            bindings = approved_bindings(self.control)
            desired.update(row["ipv4"] for row in bindings)
        # Known shared addresses always take precedence over an old approval.
        # IP blocking cannot distinguish principals behind the same NAT.
        approved_ips = {row["ipv4"] for row in approved_bindings(self.control)}
        old_shared = (set(self.application["shared_ips"])
                      if self.application["shared_revision"] == self.control["revision"] else set())
        # Only approved origin addresses can be reintroduced by this approval
        # after an endpoint expires. Retain their exclusions, not an unbounded
        # history of unrelated NAT addresses. All current shared addresses
        # still exclude blocks from the complete baseline+origin set below.
        retained_shared = (old_shared | self.observation["shared_ips"]) & approved_ips
        if len(retained_shared) > MAX_IPS:
            self.reason = "retention_capacity_exceeded"
            return None
        shared = retained_shared | self.observation["shared_ips"]
        self.application.update(shared_revision=self.control["revision"],
                                shared_ips=sorted(retained_shared))
        if shared and self.reason is None and self.control["mode"] == "enforce":
            self.reason = "shared_address"
        unsafe = shared | self.observation["protected_ips"]
        desired -= unsafe
        if len(desired) > MAX_APPLIED_IPS:
            self.reason = "retention_capacity_exceeded"
            return None
        self.bindings = [row for row in bindings if row["ipv4"] in desired]
        self.desired = sorted(desired)
        conflicts = list(baseline.conflicts)
        for conflict in self.observation["derived"].prospective_conflicts or []:
            if conflict not in conflicts:
                conflicts.append(conflict)
        return baseline._replace(denied_ips=self.desired, conflicts=conflicts,
                                 apply_empty=True)

    def before_apply(self, session):
        if not self.enabled:
            return True
        if self.desired is None or not session:
            return False
        row = {"revision": self.control["revision"],
               "control_hash": _hash(self.control),
               "policy_hash": self.observation["policy_hash"], "ips": self.desired,
               "bindings": self.bindings, "session": session, "verified_at": None}
        self.application["intent"] = row
        try:
            write_json(self.application_path, self.application)
        except OSError:
            self.reason = "application_state_unavailable"
            return False
        return True

    def finish(self, *, success, session, now, applied=False):
        if not self.enabled:
            return
        state = "degraded"
        reason = self.reason
        if not session:
            reason = "aria_unavailable"
        elif not success and reason is None:
            reason = "apply_failed"
        proof = {"revision": self.control["revision"],
            "policy_hash": self.observation["policy_hash"] if self.observation else "0" * 64,
            "state": state, "reason": reason, "applied_ip_count": None,
            "applied_device_count": None, "last_verified_at": None, "updated_at": now}
        if success and self.desired is not None:
            row = {"revision": self.control["revision"],
                   "control_hash": _hash(self.control),
                   "policy_hash": self.observation["policy_hash"], "ips": self.desired,
                   "bindings": self.bindings, "session": session, "verified_at": now}
            if applied or self.application["last_applied"] != row:
                self.application.update(last_applied=row, intent=None)
                try:
                    write_json(self.application_path, self.application)
                except OSError:
                    proof["reason"] = "application_state_unavailable"
                    success = False
            if success and reason is None:
                proof.update(state="enforced" if self.control["mode"] == "enforce" else "preflight",
                    applied_ip_count=len(self.bindings),
                    applied_device_count=len(bindings_devices(self.bindings)), last_verified_at=now)
        if reason in ("policy_changed", "endpoint_set_changed"):
            proof["state"] = "review_required"
        try:
            write_json(self.status_path, proof)
        except OSError:
            pass  # A missing/stale status is unavailable, never healthy.
