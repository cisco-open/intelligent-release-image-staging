# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durable producer for signed, per-device IRIS staging instructions."""

import base64
import contextlib
import copy
import datetime
import errno
import fcntl
import hashlib
import ipaddress
import json
import math
import os
import re
import struct
import tempfile
import threading
import time
from dataclasses import dataclass

import auth
import catalog
import gui_fleet
import gui_onboard
import instruction_keys
import instructions
import keyed_state
import live_samples
import peer_endpoints
import peer_handouts
import peer_policy
import secrets_store


MAX_TTL = 7 * 86400
PASS_INTERVAL = 60
MAX_DEVICES = 20000
MAX_GENERATIONS = 8192
SIGN_RETRIES = 3
LIVE_SNAPSHOT_MAX = 256 * 1024
LIVE_DEVICE_MAX = 10000
STATUS_ERROR_MAX = 32
ADMISSIONS_MAX_BYTES = 8 * 1024 * 1024
ROLE_STATE_MAX_BYTES = 8 * 1024 * 1024
ACTIVATION_SCHEMA = "iris-instruction-producer/v1"
ADMISSIONS_SCHEMA = "iris-instruction-admissions/v1"
ROLE_STATE_SCHEMA = "iris-role-state/v1"
STATUS_SCHEMA = "iris-instruction-stamper-status/v1"
ERROR_CODES = frozenset((
    "uninitialized", "activation_invalid", "admissions_invalid",
    "admission_refused", "history_invalid", "fleet_unavailable",
    "platform_unresolved", "key_unavailable", "policy_fail_closed",
    "policy_unavailable", "endpoint_unavailable", "live_unavailable",
    "handout_unavailable", "role_unavailable", "role_cap",
    "stamp_invalid", "stamp_commit", "key_superseded", "status_write",
))
_DAY = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


class StamperError(RuntimeError):
    """Fixed-code producer failure safe for status publication."""

    def __init__(self, code):
        self.code = code if code in ERROR_CODES else "stamp_commit"
        super().__init__(self.code)


class RoleArtifactMissing(StamperError):
    """Active metadata names an immutable artifact that cannot be found."""

    def __init__(self):
        super().__init__("role_unavailable")


@dataclass(frozen=True)
class StamperPaths:
    state_dir: str
    config_dir: str
    run_dir: str
    secrets: str

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        return cls(
            env.get("IRIS_STATE", "/var/lib/iris"),
            env.get("IRIS_CONFIG", "/etc/iris"),
            env.get("IRIS_RUN", "/run/iris"),
            env.get("IRIS_SECRETS", "/run/iris/secrets.json"))

    @property
    def directory(self):
        return os.path.join(self.state_dir, "instructions")

    @property
    def roles(self):
        return os.path.join(self.directory, "roles.d")

    @property
    def role_state(self):
        return os.path.join(self.directory, "role-state.json")

    @property
    def activation(self):
        return os.path.join(self.directory, "activation.json")

    @property
    def activation_lock(self):
        return os.path.join(self.directory, "producer.lock")

    @property
    def admissions(self):
        return os.path.join(self.directory, "admitted-devices.json")

    @property
    def serial_history(self):
        return os.path.join(self.directory, "serial-history.json")

    @property
    def role_lock(self):
        return os.path.join(self.directory, "roles.lock")

    @property
    def handouts(self):
        return os.path.join(self.state_dir, "peer-handouts.json")

    @property
    def endpoints(self):
        return os.path.join(self.state_dir, "peer-endpoints.json")

    @property
    def live_samples(self):
        return os.path.join(self.state_dir, "live-samples.json")

    @property
    def policy_authoritative(self):
        return os.path.join(self.state_dir, "peer-policy.json")

    @property
    def policy_lkg(self):
        return os.path.join(self.state_dir, "peer-policy.lkg.json")

    @property
    def status(self):
        return os.path.join(self.state_dir, "instruction-stamper-status.json")


def _i63(value, code="stamp_invalid"):
    if isinstance(value, bool) or not isinstance(value, int) \
            or not 0 <= value <= instructions.MAX_I63:
        raise StamperError(code)
    return value


def _time(value, code="stamp_invalid"):
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value) or value < 0 \
            or value > instructions.MAX_I63:
        raise StamperError(code)
    return int(value)


def _fsync_directory(directory):
    fd = os.open(directory or ".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    except OSError as exc:
        unsupported = {errno.EINVAL}
        if hasattr(errno, "ENOTSUP"):
            unsupported.add(errno.ENOTSUP)
        if exc.errno not in unsupported:
            raise
    finally:
        os.close(fd)


def _atomic_bytes(path, value, mode=0o600):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=directory, prefix=".instruction-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _atomic_json(path, value):
    _atomic_bytes(path, instructions.canonical_json(value) + b"\n")


def _read_json(path, missing=None, max_bytes=256 * 1024, code="stamp_invalid"):
    try:
        stat_result = os.stat(path)
        if stat_result.st_size > max_bytes:
            raise StamperError(code)
        with open(path, "rb") as stream:
            data = stream.read(max_bytes + 1)
    except FileNotFoundError:
        return missing
    except OSError as exc:
        raise StamperError(code) from exc
    if len(data) > max_bytes:
        raise StamperError(code)
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda _v: (_ for _ in ()).throw(
                              ValueError("constant")))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise StamperError(code) from exc


def _pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


@contextlib.contextmanager
def _flock(path, exclusive=True):
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def producer_lock(paths, exclusive=False):
    return _flock(paths.activation_lock, exclusive=exclusive)


def device_lock(paths, device_id):
    digest = hashlib.sha256(device_id.encode("utf-8")).hexdigest()
    return _flock(os.path.join(paths.directory, "device-%s.lock" % digest),
                  exclusive=True)


def role_lock(paths):
    return _flock(paths.role_lock, exclusive=True)


def _validate_activation(value):
    if not isinstance(value, dict) or set(value) != {
            "schema", "epoch", "activated_at", "mode"} \
            or value.get("schema") != ACTIVATION_SCHEMA \
            or value.get("mode") not in ("initialize", "recover"):
        raise StamperError("activation_invalid")
    _i63(value.get("epoch"), "activation_invalid")
    _i63(value.get("activated_at"), "activation_invalid")
    return value


def read_activation(paths, required=True):
    value = _read_json(paths.activation, missing=None,
                       code="activation_invalid")
    if value is None:
        if required:
            raise StamperError("uninitialized")
        return None
    return _validate_activation(value)


def _validate_admissions(value):
    if not isinstance(value, dict) or set(value) != {"schema", "epoch", "devices"} \
            or value.get("schema") != ADMISSIONS_SCHEMA:
        raise StamperError("admissions_invalid")
    _i63(value.get("epoch"), "admissions_invalid")
    devices = value.get("devices")
    if not isinstance(devices, dict) or len(devices) > MAX_DEVICES:
        raise StamperError("admissions_invalid")
    for device_id, row in devices.items():
        if not isinstance(device_id, str) \
                or instructions.DEVICE_ID.fullmatch(device_id) is None:
            raise StamperError("admissions_invalid")
        try:
            secrets_store.validate_device_id(device_id)
        except (TypeError, ValueError) as exc:
            raise StamperError("admissions_invalid") from exc
        if not isinstance(row, dict) or set(row) != {
                "state", "registered_at", "created_at"} \
                or row.get("state") not in ("pending", "active"):
            raise StamperError("admissions_invalid")
        for name in ("registered_at", "created_at"):
            if row[name] is not None:
                _i63(row[name], "admissions_invalid")
    return value


def _read_admissions(paths):
    value = _read_json(paths.admissions, missing=None,
                       max_bytes=ADMISSIONS_MAX_BYTES,
                       code="admissions_invalid")
    if value is None:
        raise StamperError("admissions_invalid")
    return _validate_admissions(value)


def _validate_history(device_id, value):
    if not isinstance(device_id, str) \
            or instructions.DEVICE_ID.fullmatch(device_id) is None:
        raise ValueError("invalid serial-history device")
    try:
        secrets_store.validate_device_id(device_id)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid serial-history device") from exc
    if not isinstance(value, dict) or set(value) != {
            "v", "epoch", "high_water", "reservation"} \
            or isinstance(value.get("v"), bool) \
            or not isinstance(value.get("v"), int) or value.get("v") != 1:
        raise ValueError("invalid serial history")
    for name in ("epoch", "high_water"):
        if isinstance(value.get(name), bool) or not isinstance(value.get(name), int) \
                or not 0 <= value[name] <= instructions.MAX_I63:
            raise ValueError("invalid serial history")
    reservation = value.get("reservation")
    if reservation is not None:
        if not isinstance(reservation, dict) or set(reservation) != {
                "instr_serial", "desired_sha256"}:
            raise ValueError("invalid serial reservation")
        serial = reservation.get("instr_serial")
        digest = reservation.get("desired_sha256")
        if isinstance(serial, bool) or not isinstance(serial, int) \
                or serial < 1 or serial != value["high_water"] \
                or not isinstance(digest, str) \
                or instructions.HEX64.fullmatch(digest) is None:
            raise ValueError("invalid serial reservation")


def _history(paths):
    def history_error(_message):
        return StamperError("history_invalid")

    return keyed_state.KeyedState(
        paths.serial_history, error=history_error,
        validate=_validate_history, durable=True, indent=None)


def _zero_history(epoch):
    return {"v": 1, "epoch": epoch, "high_water": 0, "reservation": None}


def _reset_history(paths, epoch, device_ids):
    """Discard old-epoch authority without trusting corrupt old rows."""
    history = _history(paths)
    changed_parent = False
    for legacy in (history.legacy_path, history.legacy_path + ".migrated"):
        try:
            os.unlink(legacy)
            changed_parent = True
        except FileNotFoundError:
            pass
    changed_shards = False
    try:
        entries = list(os.scandir(history.dir))
    except FileNotFoundError:
        entries = []
    for entry in entries:
        if entry.is_file(follow_symlinks=False) \
                and re.fullmatch(r"[0-9a-f]{2}\.json", entry.name):
            os.unlink(entry.path)
            changed_shards = True
    if changed_shards:
        _fsync_directory(history.dir)
    if changed_parent:
        _fsync_directory(os.path.dirname(history.legacy_path) or ".")
    for device_id in sorted(device_ids):
        history.put(device_id, _zero_history(epoch))


def _instruction_key(paths, device_id):
    try:
        with secrets_store.store_lock(paths.secrets):
            store = secrets_store.load(paths.secrets)
            records = store.get("devices", {}).get(device_id)
            if not isinstance(records, dict) or "instr_key" not in records:
                raise StamperError("key_unavailable")
            record = secrets_store.validate_instruction_key_record(
                records["instr_key"])
            if record["revoked"]:
                raise StamperError("key_unavailable")
            return dict(record)
    except StamperError:
        raise
    except (OSError, ValueError, secrets_store.StoreCorruptError) as exc:
        raise StamperError("key_unavailable") from exc


def _same_key(paths, device_id, key_id):
    try:
        return secrets_store.validate_instruction_key_record(
            _instruction_key(paths, device_id))["key_id"] == key_id
    except (StamperError, ValueError):
        return False


def _registered_at(row):
    value = row.get("registered_at") if isinstance(row, dict) else None
    return None if value is None else _time(value, "fleet_unavailable")


def _admit(paths, activation, device_id, fleet_row, key_record):
    facts = {"state": "pending", "registered_at": _registered_at(fleet_row),
             "created_at": key_record["created_at"]}
    history = _history(paths)
    document = _read_admissions(paths)
    if document["epoch"] != activation["epoch"]:
        raise StamperError("admissions_invalid")
    established = document["devices"].get(device_id)
    if established is not None and established["state"] == "active":
        with keyed_state.file_lock(paths.admissions):
            refreshed = _read_admissions(paths)
            active = refreshed["devices"].get(device_id)
            if active is None or active["state"] != "active" \
                    or active["registered_at"] != established["registered_at"]:
                raise StamperError("admission_refused")
            if active["created_at"] is None:
                active["created_at"] = key_record["created_at"]
                _atomic_json(paths.admissions, refreshed)
            else:
                _fsync_directory(os.path.dirname(paths.admissions) or ".")
        row = history.get(device_id)
        if row is None or row["epoch"] != activation["epoch"]:
            raise StamperError("history_invalid")
        _confirm_history(paths, device_id, row)
        return
    with keyed_state.file_lock(paths.admissions):
        document = _read_admissions(paths)
        if document["epoch"] != activation["epoch"]:
            raise StamperError("admissions_invalid")
        established = document["devices"].get(device_id)
        if established is not None and established["state"] == "active":
            _fsync_directory(os.path.dirname(paths.admissions) or ".")
            return
        if established is None:
            if len(document["devices"]) >= MAX_DEVICES:
                raise StamperError("admission_refused")
            if facts["registered_at"] is None \
                    or facts["registered_at"] < activation["activated_at"] \
                    or facts["created_at"] < activation["activated_at"]:
                raise StamperError("admission_refused")
            document["devices"][device_id] = facts
            _atomic_json(paths.admissions, document)
            established = facts
        else:
            _fsync_directory(os.path.dirname(paths.admissions) or ".")
        if established["state"] != "pending" \
                or established["registered_at"] != facts["registered_at"]:
            raise StamperError("admission_refused")
        # created_at is the frozen initial-admission fact.  A later key
        # rotation changes the current key record and must not rewrite or
        # invalidate that established fact.  Only seeded null history is
        # completed once.
        if established["created_at"] is None:
            established["created_at"] = facts["created_at"]
            document["devices"][device_id] = established
            _atomic_json(paths.admissions, document)

    row = history.get(device_id)
    if row is None:
        history.put(device_id, _zero_history(activation["epoch"]))
    elif row != _zero_history(activation["epoch"]):
        raise StamperError("history_invalid")
    else:
        _confirm_history(paths, device_id, row)

    with keyed_state.file_lock(paths.admissions):
        document = _read_admissions(paths)
        pending = document["devices"].get(device_id)
        if pending is None or pending["state"] != "pending" \
                or pending["registered_at"] != facts["registered_at"] \
                or pending["created_at"] != facts["created_at"]:
            raise StamperError("admission_refused")
        document["devices"][device_id] = dict(pending, state="active")
        _atomic_json(paths.admissions, document)
    _confirm_history(paths, device_id, _zero_history(activation["epoch"]))


def _reserve(paths, device_id, epoch, desired_sha256):
    history = _history(paths)
    result = {}

    def update(row):
        if row is None or row.get("epoch") != epoch:
            raise StamperError("history_invalid")
        reservation = row["reservation"]
        if reservation is not None \
                and reservation["desired_sha256"] == desired_sha256:
            result["serial"] = reservation["instr_serial"]
            keyed_state._fsync_directory(history.dir)
            return None
        if row["high_water"] >= instructions.MAX_I63:
            raise StamperError("history_invalid")
        serial = row["high_water"] + 1
        result["serial"] = serial
        return {"v": 1, "epoch": epoch, "high_water": serial,
                "reservation": {"instr_serial": serial,
                                "desired_sha256": desired_sha256}}

    history.update(device_id, update)
    return result["serial"]


def _finalize(paths, device_id, epoch, serial, desired_sha256):
    history = _history(paths)

    def update(row):
        if row is None or row.get("epoch") != epoch:
            raise StamperError("history_invalid")
        if row.get("reservation") is None and row.get("high_water") == serial:
            # A prior finalize rename may be visible without a confirmed
            # directory barrier. Validate the exact finalized high-water
            # authority under its shard lock and finish that barrier without
            # rewriting an unchanged row.
            keyed_state._fsync_directory(history.dir)
            return None
        if row.get("reservation") != {
                "instr_serial": serial, "desired_sha256": desired_sha256}:
            raise StamperError("history_invalid")
        return dict(row, reservation=None)
    history.update(device_id, update)


def _validate_role_state(value):
    if not isinstance(value, dict) or set(value) != {"schema", "generations"} \
            or value.get("schema") != ROLE_STATE_SCHEMA \
            or not isinstance(value.get("generations"), dict) \
            or len(value["generations"]) > MAX_GENERATIONS:
        raise StamperError("role_unavailable")
    expected = {"state", "epoch", "role", "day", "semantic_body_sha256",
                "cert_sha256", "issued_at", "expires_at", "artifact_sha256",
                "temp_name", "unreferenced_at"}
    tuples = set()
    for generation, row in value["generations"].items():
        if instructions.HEX64.fullmatch(generation or "") is None \
                or not isinstance(row, dict) or set(row) != expected \
                or row.get("state") not in ("pending", "active") \
                or not isinstance(row.get("role"), str) \
                or instructions.ROLE.fullmatch(row["role"]) is None \
                or not isinstance(row.get("day"), str) \
                or not _valid_day(row["day"]):
            raise StamperError("role_unavailable")
        for key in ("semantic_body_sha256", "cert_sha256", "artifact_sha256"):
            if instructions.HEX64.fullmatch(row.get(key, "")) is None:
                raise StamperError("role_unavailable")
        for key in ("epoch", "issued_at", "expires_at"):
            _i63(row.get(key), "role_unavailable")
        if row["issued_at"] < row["epoch"] \
                or row["expires_at"] <= row["issued_at"] \
                or row["expires_at"] - row["issued_at"] > MAX_TTL:
            raise StamperError("role_unavailable")
        if row["state"] == "pending":
            if row["temp_name"] != ".pending-" + generation \
                    or row["unreferenced_at"] is not None:
                raise StamperError("role_unavailable")
        elif row["temp_name"] is not None:
            raise StamperError("role_unavailable")
        if row["unreferenced_at"] is not None:
            _i63(row["unreferenced_at"], "role_unavailable")
        identity = (row["epoch"], row["day"], row["role"],
                    row["semantic_body_sha256"], row["cert_sha256"])
        if identity in tuples:
            raise StamperError("role_unavailable")
        tuples.add(identity)
    return value


def _valid_day(value):
    if _DAY.fullmatch(value) is None:
        return False
    try:
        return datetime.date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _read_role_state(paths):
    value = _read_json(paths.role_state, missing={
        "schema": ROLE_STATE_SCHEMA, "generations": {}},
        max_bytes=ROLE_STATE_MAX_BYTES,
        code="role_unavailable")
    return _validate_role_state(value)


def _ssh_string(data, offset):
    if offset + 4 > len(data):
        raise StamperError("role_unavailable")
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    if offset + length > len(data):
        raise StamperError("role_unavailable")
    return data[offset:offset + length], offset + length


def certificate_blob(certificate):
    if not isinstance(certificate, bytes) or len(certificate) > 64 * 1024 \
            or b"\r" in certificate:
        raise StamperError("role_unavailable")
    lines = certificate.splitlines()
    if len(lines) != 1:
        raise StamperError("role_unavailable")
    fields = lines[0].split()
    if len(fields) < 2:
        raise StamperError("role_unavailable")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (ValueError, TypeError) as exc:
        raise StamperError("role_unavailable") from exc
    if base64.b64encode(blob) != fields[1]:
        raise StamperError("role_unavailable")
    return blob


def signature_certificate_blob(signature):
    if not isinstance(signature, bytes) or len(signature) > 256 * 1024 \
            or b"\r" in signature:
        raise StamperError("role_unavailable")
    lines = signature.splitlines()
    if len(lines) < 3 or lines[0] != b"-----BEGIN SSH SIGNATURE-----" \
            or lines[-1] != b"-----END SSH SIGNATURE-----":
        raise StamperError("role_unavailable")
    try:
        binary = base64.b64decode(b"".join(lines[1:-1]), validate=True)
    except (ValueError, TypeError) as exc:
        raise StamperError("role_unavailable") from exc
    if not binary.startswith(b"SSHSIG") or len(binary) < 10 \
            or struct.unpack(">I", binary[6:10])[0] != 1:
        raise StamperError("role_unavailable")
    blob, _offset = _ssh_string(binary, 10)
    return blob


def _read_certificate(path):
    try:
        stat_result = os.stat(path)
        if stat_result.st_size > instruction_keys.MAX_CERTIFICATE_BYTES:
            raise StamperError("role_unavailable")
        with open(path, "rb") as stream:
            data = stream.read(instruction_keys.MAX_CERTIFICATE_BYTES + 1)
    except OSError as exc:
        raise StamperError("role_unavailable") from exc
    certificate_blob(data)
    return data


def _validate_certificate_snapshot(key_paths, certificate, roots, now,
                                   certificate_info=None):
    """Validate the selected immutable bytes, never the mutable config path."""
    if certificate_info is not None:
        info = certificate_info(certificate, now)
    else:
        directory = os.path.dirname(key_paths.runtime_certificate)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd, snapshot = tempfile.mkstemp(
            dir=directory, prefix=".certificate-snapshot-")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(certificate)
                stream.flush()
                os.fsync(stream.fileno())
            info = instruction_keys.validate_online_certificate(
                key_paths, snapshot, roots, now=now)
        finally:
            try:
                os.unlink(snapshot)
            except FileNotFoundError:
                pass
    if not isinstance(info, dict):
        raise StamperError("role_unavailable")
    valid_after = _i63(info.get("valid_after"), "role_unavailable")
    valid_before = _i63(info.get("valid_before"), "role_unavailable")
    if valid_before <= valid_after:
        raise StamperError("role_unavailable")
    return dict(info, valid_after=valid_after, valid_before=valid_before)


def _artifact_name(role, generation):
    if role == "default":
        return "default@" + generation
    try:
        peer_policy.validate_role_name(role)
    except peer_policy.PolicyError as exc:
        raise StamperError("role_unavailable") from exc
    return role + "@" + generation


def _artifact_path(paths, role, generation):
    return os.path.join(paths.roles, _artifact_name(role, generation))


def _validate_artifact(data, generation, metadata=None):
    try:
        body_bytes, signature = instructions.parse_role(data)
        body = instructions.parse_json(body_bytes)
    except instructions.InstructionError as exc:
        raise StamperError("role_unavailable") from exc
    if body["role_gen"] != generation:
        raise StamperError("role_unavailable")
    if metadata is not None:
        if hashlib.sha256(data).hexdigest() != metadata["artifact_sha256"] \
                or body["role"] != metadata["role"] \
                or body["issued_at"] != metadata["issued_at"] \
                or body["expires_at"] != metadata["expires_at"]:
            raise StamperError("role_unavailable")
        semantic = {key: value for key, value in body.items()
                    if key not in {"role_gen", "issued_at", "expires_at",
                                   "server_time"}}
        if hashlib.sha256(instructions.canonical_json(semantic)).hexdigest() \
                != metadata["semantic_body_sha256"]:
            raise StamperError("role_unavailable")
        body0 = {key: value for key, value in body.items()
                 if key != "role_gen"}
        expected_generation = hashlib.sha256(instructions.pae(
            b"iris-role-generation-v1", instructions.canonical_json(body0),
            metadata["cert_sha256"].encode("ascii"))).hexdigest()
        if expected_generation != generation:
            raise StamperError("role_unavailable")
    signature_certificate_blob(signature)
    return body_bytes, signature, body


def read_role_artifact_snapshot(paths, stamp):
    """Copy one complete validated role artifact without producer mutation.

    The role lock covers metadata and artifact reads, including all identity
    checks. It is released before catalog callers select a key under the
    secrets lock. No reconciliation, signing or durability repair runs on GET.
    """
    try:
        stamp = copy.deepcopy(stamp)
        instructions.validate_stamp(stamp)
        with role_lock(paths):
            generation = stamp["role_gen"]
            metadata = _read_role_state(paths)["generations"].get(generation)
            if metadata is None or metadata["state"] != "active" \
                    or any(metadata[name] != stamp[name] for name in (
                        "role", "epoch", "issued_at", "expires_at")):
                raise StamperError("role_unavailable")
            try:
                stream = open(_artifact_path(paths, stamp["role"], generation),
                              "rb")
            except FileNotFoundError as exc:
                raise RoleArtifactMissing() from exc
            with stream:
                artifact = stream.read(instructions.INSTR_RESPONSE_MAX + 1)
            body_bytes, signature, body = _validate_artifact(
                artifact, generation, metadata)
            if hashlib.sha256(body_bytes).hexdigest() != \
                    stamp["role_body_sha256"]:
                raise StamperError("role_unavailable")
            return {
                "body_bytes": bytes(body_bytes),
                "signature_bytes": bytes(signature),
                "role": copy.deepcopy(body),
                "artifact_sha256": metadata["artifact_sha256"],
            }
    except StamperError:
        raise
    except (OSError, ValueError, TypeError, KeyError, OverflowError) as exc:
        raise StamperError("role_unavailable") from exc


def _validated_active_artifact(paths, generation, metadata):
    """Validate and durability-confirm one active artifact under role_lock."""
    if metadata is None or metadata.get("state") != "active":
        raise StamperError("role_unavailable")
    value = _validate_artifact(
        _role_bytes(_artifact_path(paths, metadata["role"], generation)),
        generation, metadata)
    _fsync_directory(paths.roles)
    return value


def _role_bytes(path):
    try:
        with open(path, "rb") as stream:
            return stream.read(instructions.INSTR_RESPONSE_MAX + 1)
    except OSError as exc:
        raise StamperError("role_unavailable") from exc


def _policy_references(catalog_store):
    try:
        rows = catalog_store._policies.snapshot()
    except Exception as exc:
        raise StamperError("stamp_invalid") from exc
    references = set()
    for row in rows.values():
        if not isinstance(row, dict) or "instr" not in row:
            continue
        try:
            instructions.validate_stamp(row["instr"])
        except instructions.InstructionError as exc:
            raise StamperError("stamp_invalid") from exc
        references.add(row["instr"]["role_gen"])
    return references


def reconcile_roles(paths, catalog_store):
    state = _read_role_state(paths)
    # A visible role-state rename is not durable authority until its parent
    # directory barrier succeeds. The role lock is held by every caller.
    _fsync_directory(os.path.dirname(paths.role_state) or ".")
    references = _policy_references(catalog_store)
    if references - set(state["generations"]):
        # A policy stamp can only be committed after its generation became
        # active.  References absent from the global index therefore prove
        # authority loss rather than a first-publication state.
        raise StamperError("role_unavailable")
    os.makedirs(paths.roles, mode=0o700, exist_ok=True)
    changed = False
    for generation, metadata in state["generations"].items():
        if metadata["state"] != "pending":
            continue
        pending = os.path.join(paths.roles, metadata["temp_name"])
        final = _artifact_path(paths, metadata["role"], generation)
        pending_exists = os.path.exists(pending)
        final_exists = os.path.exists(final)
        if not pending_exists and not final_exists:
            raise StamperError("role_unavailable")
        final_data = _role_bytes(final) if final_exists else None
        pending_data = _role_bytes(pending) if pending_exists else None
        if final_data is not None:
            _validate_artifact(final_data, generation, metadata)
        if pending_data is not None:
            _validate_artifact(pending_data, generation, metadata)
        if final_data is not None and pending_data is not None \
                and final_data != pending_data:
            raise StamperError("role_unavailable")
        if final_data is None:
            os.replace(pending, final)
            _fsync_directory(paths.roles)
        elif pending_exists:
            os.unlink(pending)
            _fsync_directory(paths.roles)
        else:
            # The final rename may have become visible before its directory
            # fsync failed. Confirm the validated exact artifact before the
            # pending index can be activated.
            _fsync_directory(paths.roles)
        metadata["state"] = "active"
        metadata["temp_name"] = None
        metadata["unreferenced_at"] = None
        changed = True
    indexed_pending = {
        row["temp_name"] for row in state["generations"].values()
        if row["state"] == "pending"}
    try:
        names = [entry.name for entry in os.scandir(paths.roles)
                 if entry.is_file() and entry.name.startswith(".pending-")]
    except OSError as exc:
        raise StamperError("role_unavailable") from exc
    for name in names:
        if name in indexed_pending:
            continue
        generation = name[len(".pending-"):]
        if instructions.HEX64.fullmatch(generation) is None \
                or generation in references:
            raise StamperError("role_unavailable")
        orphan = os.path.join(paths.roles, name)
        try:
            _validate_artifact(_role_bytes(orphan), generation)
        except StamperError:
            os.unlink(orphan)
            _fsync_directory(paths.roles)
        # A valid deterministic pending artifact can be the visible result of
        # a failed post-rename directory fsync. Preserve it for the matching
        # publisher, which must compare its exact bytes and re-establish the
        # barrier before indexing it. Malformed or referenced orphans remain
        # fail-closed/cleaned as above.
    if changed:
        _atomic_json(paths.role_state, state)
    return state


def _day(now):
    return datetime.datetime.fromtimestamp(
        now, datetime.timezone.utc).strftime("%Y-%m-%d")


def semantic_role(document, compiled, device_id):
    roles = document.get("roles", {})
    definitions = roles.get("defs", {}) if isinstance(roles, dict) else {}
    role = compiled.role_of.get(device_id) or "default"
    definition = definitions.get(role, {}) if role != "default" else {}
    restricted = bool(definition.get("restricted", False))
    shared_doc = copy.deepcopy(document)
    shared_roles = shared_doc.setdefault("roles", {})
    shared_roles["qos_device"] = {}
    base = peer_policy.compile_qos(shared_doc, device_id)
    qos = {key: base[key] for key in instructions.QOS_FIELDS}
    control = {key: base[key] for key in instructions.CONTROL_FIELDS}
    result = {"v": 1, "role": role, "restricted": restricted,
              "qos": qos, "control": control,
              "on_stale": base["on_stale"]}
    if "nets" in definition:
        nets = sorted({str(ipaddress.IPv4Network(value, strict=False))
                       for value in definition["nets"]})
        if len(nets) <= instructions.MAX_ALLOWED:
            result["allowed_nets"] = nets
    instructions.validate_qos(qos)
    instructions.validate_control(control)
    return result, base, peer_policy.compile_qos(document, device_id)


def _endpoint_attribution(paths, now):
    try:
        rows = peer_endpoints.fresh_endpoints(paths.endpoints, now)
    except Exception as exc:
        raise StamperError("endpoint_unavailable") from exc
    ttl = peer_endpoints.endpoint_ttl()
    by_ip = {}
    expiries = {}
    for row in rows.values():
        principal = auth.Principal(row["principal_type"], row["principal_id"])
        for endpoint in row["endpoints"]:
            observed = endpoint.get("observed_at")
            if isinstance(observed, bool) or not isinstance(observed, (int, float)) \
                    or not math.isfinite(observed) or observed > now \
                    or not now < observed + ttl:
                continue
            address = str(ipaddress.IPv4Address(endpoint["ipv4"]))
            by_ip.setdefault(address, set()).add(principal)
            expiries[address] = min(expiries.get(address, instructions.MAX_I63),
                                    int(observed + ttl))
    return by_ip, expiries


_V1_FIELDS = frozenset((
    "v", "schema", "image_id", "phase", "tier", "done_bytes", "down_bps",
    "up_bps", "peers", "received_at", "retention_seconds", "valid",
    "observed_received_at",
))
_V2_STATE_FIELDS = frozenset((
    "v", "schema", "obs_state", "observed_at", "received_at",
    "retention_seconds", "valid",
))
_V2_OBSERVED_FIELDS = _V2_STATE_FIELDS | frozenset((
    "sample_seq", "sampling_class", "aria", "peer_connections",
    "last_sample_seq", "observed_received_at", "last_observed_seq",
))
_V2_OPTIONAL_FIELDS = frozenset((
    "transfer_id", "image_id", "aria_session_id",
))
_V2_WITHDRAWN_OPTIONAL = _V2_OPTIONAL_FIELDS | frozenset((
    "sample_seq", "last_sample_seq", "observed_received_at",
    "last_observed_seq", "sampling_class",
))


def _live_number(value, now=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value) or value < 0 \
            or value > instructions.MAX_I63 \
            or (now is not None and value > now):
        raise StamperError("live_unavailable")
    return value


def _live_integer(value, maximum=None):
    if isinstance(value, bool) or not isinstance(value, int) \
            or value < 0 or (maximum is not None and value > maximum):
        raise StamperError("live_unavailable")
    return value


def _live_identifier(value, pattern):
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise StamperError("live_unavailable")


def _live_enum(value, choices):
    if not isinstance(value, str) or value not in choices:
        raise StamperError("live_unavailable")
    return value


def _validate_live_common(sample, now):
    _live_number(sample["received_at"], now=now)
    _live_integer(sample["retention_seconds"], live_samples.RETENTION_CAP)
    if sample["retention_seconds"] < 3 * live_samples.TICK_SECONDS \
            or sample["retention_seconds"] % (3 * live_samples.TICK_SECONDS):
        raise StamperError("live_unavailable")
    if not isinstance(sample["valid"], bool):
        raise StamperError("live_unavailable")
    if "observed_received_at" in sample:
        _live_number(sample["observed_received_at"], now=now)


def _validate_live_peer(row):
    allowed = {"ip", "port", "send_bps", "receive_bps",
               "peer_client_name", "progress"}
    if not isinstance(row, dict) or "ip" not in row or set(row) - allowed:
        raise StamperError("live_unavailable")
    try:
        address = str(ipaddress.IPv4Address(row["ip"]))
    except (ipaddress.AddressValueError, TypeError, ValueError) as exc:
        raise StamperError("live_unavailable") from exc
    if row["ip"] != address:
        raise StamperError("live_unavailable")
    if "port" in row:
        _live_integer(row["port"], 65535)
    for key in ("send_bps", "receive_bps"):
        if key in row:
            _live_integer(row[key], live_samples._PEER_ROW_BPS_CAP)
    if "peer_client_name" in row and (
            not isinstance(row["peer_client_name"], str)
            or len(row["peer_client_name"]) > 64):
        raise StamperError("live_unavailable")
    if "progress" in row:
        value = row["progress"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) \
                or not math.isfinite(value) or not 0 <= value <= 100:
            raise StamperError("live_unavailable")
    return address


def _validate_live_sample(device_id, sample, now):
    try:
        secrets_store.validate_device_id(device_id)
    except (TypeError, ValueError) as exc:
        raise StamperError("live_unavailable") from exc
    if not isinstance(sample, dict):
        raise StamperError("live_unavailable")
    version = sample.get("v")
    if isinstance(version, bool) or not isinstance(version, int):
        raise StamperError("live_unavailable")
    if version == 1:
        optional = {"obs_state"}
        if not _V1_FIELDS <= set(sample) or set(sample) - _V1_FIELDS - optional \
                or sample.get("schema") != "v1":
            raise StamperError("live_unavailable")
        _live_identifier(sample["image_id"], live_samples._IMAGE_RE)
        _live_enum(sample["phase"], live_samples._PHASES)
        _live_enum(sample["tier"], live_samples.TIER_TICKS)
        for key, cap in live_samples._INT_BOUNDS.items():
            _live_integer(sample[key], cap)
        _validate_live_common(sample, now)
        if sample["observed_received_at"] != sample["received_at"]:
            raise StamperError("live_unavailable")
        if "obs_state" in sample:
            _live_enum(sample["obs_state"],
                       live_samples.LiveTable._WITHDRAW_STATES)
            if sample["valid"] is not False:
                raise StamperError("live_unavailable")
        return sample
    if version != 2 or sample.get("schema") != "v2":
        raise StamperError("live_unavailable")
    _live_enum(sample.get("obs_state"), live_samples.OBS_STATES)
    observed = sample["obs_state"] == "observed"
    required = _V2_OBSERVED_FIELDS if observed else _V2_STATE_FIELDS
    optional = _V2_OPTIONAL_FIELDS if observed else _V2_WITHDRAWN_OPTIONAL
    if not required <= set(sample) or set(sample) - required - optional:
        raise StamperError("live_unavailable")
    _live_number(sample["observed_at"])
    _validate_live_common(sample, now)
    if "transfer_id" in sample:
        _live_identifier(sample["transfer_id"], live_samples._HEX32)
    if "image_id" in sample:
        _live_identifier(sample["image_id"], live_samples._IMAGE_RE)
    if "aria_session_id" in sample and (
            not isinstance(sample["aria_session_id"], str)
            or re.fullmatch(r"[a-f0-9]{1,64}", sample["aria_session_id"])
            is None):
        raise StamperError("live_unavailable")
    for key in ("sample_seq", "last_sample_seq", "last_observed_seq"):
        if key in sample:
            _live_integer(sample[key])
    if "last_sample_seq" in sample and "sample_seq" in sample \
            and sample["last_sample_seq"] != sample["sample_seq"]:
        raise StamperError("live_unavailable")
    if "sampling_class" in sample:
        _live_enum(sample["sampling_class"], live_samples.SAMPLING_CLASSES)
    if not observed:
        if sample["valid"] is not False:
            raise StamperError("live_unavailable")
        if "observed_received_at" in sample \
                and sample["observed_received_at"] > sample["received_at"]:
            raise StamperError("live_unavailable")
        return sample
    if sample["observed_received_at"] != sample["received_at"] \
            or sample["last_observed_seq"] != sample["sample_seq"]:
        raise StamperError("live_unavailable")
    aria = sample["aria"]
    required_aria = set(live_samples._ARIA_INT_BOUNDS)
    if not isinstance(aria, dict) or not required_aria <= set(aria) \
            or set(aria) - required_aria - {"status"}:
        raise StamperError("live_unavailable")
    if "status" in aria:
        _live_enum(aria["status"], live_samples.ARIA_STATUSES)
    for key, cap in live_samples._ARIA_INT_BOUNDS.items():
        _live_integer(aria[key], cap)
    peers = sample["peer_connections"]
    if not isinstance(peers, list) \
            or len(peers) > live_samples.LIVE_PEER_ROWS_HARD_CAP:
        raise StamperError("live_unavailable")
    for row in peers:
        _validate_live_peer(row)
    return sample


def _live_connections(paths, device_id, now):
    try:
        stat_result = os.stat(paths.live_samples)
        if stat_result.st_size > LIVE_SNAPSHOT_MAX:
            raise StamperError("live_unavailable")
        document = _read_json(paths.live_samples, missing=None,
                              max_bytes=LIVE_SNAPSHOT_MAX,
                              code="live_unavailable")
    except FileNotFoundError as exc:
        raise StamperError("live_unavailable") from exc
    if not isinstance(document, dict) or set(document) != {
            "written_at", "counters", "samples"} \
            or not isinstance(document["samples"], dict) \
            or len(document["samples"]) > LIVE_DEVICE_MAX:
        raise StamperError("live_unavailable")
    _live_number(document["written_at"], now=now)
    counters = document["counters"]
    if not isinstance(counters, dict) or set(counters) != {
            "samples_rejected_total"}:
        raise StamperError("live_unavailable")
    _live_integer(counters["samples_rejected_total"])
    for sample_device, candidate in document["samples"].items():
        _validate_live_sample(sample_device, candidate, now)
    sample = document["samples"].get(device_id)
    if not isinstance(sample, dict) or sample.get("v") != 2 \
            or sample.get("obs_state") != "observed" \
            or "peer_connections_truncated" in sample:
        raise StamperError("live_unavailable")
    received = sample.get("observed_received_at")
    if isinstance(received, bool) or not isinstance(received, (int, float)) \
            or not math.isfinite(received) or received > now \
            or not now < received + live_samples.LIVE_VALUE_VALIDITY:
        raise StamperError("live_unavailable")
    peers = sample["peer_connections"]
    addresses = set()
    for row in peers:
        addresses.add(_validate_live_peer(row))
    return addresses, int(received + live_samples.LIVE_VALUE_VALIDITY)


def compile_peers(paths, policy, device_id, role, restricted, definition,
                  now, stamp_expires):
    doc, compiled = policy.document, policy.roles
    include_origin = peer_policy.role_origin_enabled(doc, role)
    explicit = device_id in doc.get("assignments", {})
    owner = auth.Principal("device", device_id)
    if restricted and not explicit and \
            not peer_policy.is_quarantined(doc, device_id):
        if "nets" in definition:
            allowed = sorted({str(ipaddress.IPv4Network(value, strict=False))
                              for value in definition["nets"]})
            if len(allowed) > instructions.MAX_ALLOWED:
                return {"mode": "tracker-only", "include_origin": include_origin,
                        "allowed_expires_at": stamp_expires}
            return {"mode": "allow", "allowed": allowed,
                    "include_origin": include_origin,
                    "allowed_expires_at": stamp_expires}
        by_ip, endpoint_expiries = _endpoint_attribution(paths, now)
        owner_addresses = [address for address, principals in by_ip.items()
                           if owner in principals]
        allowed, expiries = set(), []
        peer_roles = definition.get("peers", [role])
        eligible = set().union(*(
            compiled.members_by_role.get(name, frozenset())
            for name in peer_roles))
        for address, principals in by_ip.items():
            permitted = False
            qualifying_owner_expiries = []
            for candidate in principals:
                if candidate.type != "device" \
                        or candidate == owner \
                        or candidate.id not in eligible:
                    continue
                for owner_address in owner_addresses:
                    if peer_policy.mutual_permit(
                            doc, owner, owner_address, candidate, address,
                            compiled=compiled):
                        permitted = True
                        qualifying_owner_expiries.append(
                            endpoint_expiries[owner_address])
            if permitted:
                allowed.add(address)
                # Any qualifying pair is sufficient until the later of the
                # owner proofs expires; the candidate endpoint bounds them all.
                expiries.append(min(endpoint_expiries[address],
                                    max(qualifying_owner_expiries)))
        if len(allowed) > instructions.MAX_ALLOWED:
            return {"mode": "tracker-only", "include_origin": include_origin,
                    "allowed_expires_at": stamp_expires}
        expiry = min(expiries + [int(now + peer_endpoints.endpoint_ttl()),
                                 stamp_expires])
        return {"mode": "allow", "allowed": sorted(allowed),
                "include_origin": include_origin,
                "allowed_expires_at": expiry}

    acl_name = peer_policy.effective_acl_name(doc, owner, compiled=compiled)
    if acl_name is None:
        return {"mode": "deny", "rules": [], "include_origin": include_origin,
                "allowed_expires_at": stamp_expires}
    if acl_name.startswith("role:"):
        rules = compiled.sorted_rules.get(acl_name, ())
    else:
        rules = doc.get("acls", {}).get(acl_name, {}).get("rules", ())
    if not any(isinstance(rule, dict) and rule.get("action") == "deny"
               for rule in rules):
        return {"mode": "deny", "rules": [], "include_origin": include_origin,
                "allowed_expires_at": stamp_expires}
    by_ip, endpoint_expiries = _endpoint_attribution(paths, now)
    try:
        live_addresses, live_expiry = _live_connections(
            paths, device_id, now)
    except StamperError as exc:
        if exc.code != "live_unavailable":
            raise
        return {"mode": "tracker-only", "include_origin": include_origin,
                "allowed_expires_at": stamp_expires}
    try:
        handouts = peer_handouts.current_handouts(paths.handouts, device_id, now)
    except peer_handouts.HandoutStoreError as exc:
        raise StamperError("handout_unavailable") from exc
    addresses = set(live_addresses)
    addresses.update(item["address"] for item in handouts)
    handout_expiry = {item["address"]: item["expires_at"] for item in handouts}
    denied, expiries = set(), []
    for address in addresses:
        principals = by_ip.get(address, ())
        if not principals:
            continue
        decisions = [peer_policy.evaluate_for(
            doc, owner, candidate, address, compiled=compiled)[0]
                     for candidate in principals]
        if "deny" in decisions:
            evidence = []
            if address in live_addresses:
                evidence.append(live_expiry)
            if address in handout_expiry:
                evidence.append(handout_expiry[address])
            expiries.append(min([endpoint_expiries[address]] + evidence))
            if "permit" not in decisions:
                denied.add(address)
    if len(denied) > instructions.MAX_RULES:
        return {"mode": "tracker-only", "include_origin": include_origin,
                "allowed_expires_at": stamp_expires}
    expiry = min(expiries + [int(now + peer_endpoints.endpoint_ttl()),
                             stamp_expires]) if expiries else min(
                                 live_expiry,
                                 int(now + peer_endpoints.endpoint_ttl()),
                                 stamp_expires)
    return {"mode": "deny", "rules": sorted(denied),
            "include_origin": include_origin, "allowed_expires_at": expiry}


def _role_tuple(epoch, day, role, semantic_sha, cert_sha):
    return epoch, day, role, semantic_sha, cert_sha


def _publish_role_locked(paths, catalog_store, semantic, epoch, now,
                         signer=None, certificate_info=None):
    state = reconcile_roles(paths, catalog_store)
    semantic_bytes = instructions.canonical_json(semantic)
    semantic_sha = hashlib.sha256(semantic_bytes).hexdigest()
    key_paths = instruction_keys.InstructionPaths(
        paths.state_dir, paths.config_dir, paths.run_dir)
    day = _day(now)
    for attempt in range(SIGN_RETRIES):
        certificate = _read_certificate(key_paths.certificate)
        cert_sha = hashlib.sha256(certificate).hexdigest()
        try:
            roots = instruction_keys.discover_roots(key_paths)
            info = _validate_certificate_snapshot(
                key_paths, certificate, roots, now,
                certificate_info=certificate_info)
        except Exception as exc:
            raise StamperError("role_unavailable") from exc
        if _read_certificate(key_paths.certificate) != certificate:
            if attempt + 1 == SIGN_RETRIES:
                raise StamperError("role_unavailable")
            continue
        identity = _role_tuple(
            epoch, day, semantic["role"], semantic_sha, cert_sha)
        matches = [(generation, row) for generation, row
                   in state["generations"].items()
                   if row["state"] == "active" and _role_tuple(
                       row["epoch"], row["day"], row["role"],
                       row["semantic_body_sha256"],
                       row["cert_sha256"]) == identity]
        if len(matches) > 1:
            raise StamperError("role_unavailable")
        if matches:
            generation, metadata = matches[0]
            body_bytes, signature, body = _validated_active_artifact(
                paths, generation, metadata)
            return (generation, body_bytes, signature, body, metadata,
                    semantic_sha)
        if len(state["generations"]) >= MAX_GENERATIONS:
            raise StamperError("role_cap")
        issued = max(int(now), epoch, int(info["valid_after"]))
        expires = min(issued + MAX_TTL, int(info["valid_before"]))
        if expires <= issued:
            raise StamperError("role_unavailable")
        body0 = dict(semantic, issued_at=issued, expires_at=expires,
                     server_time=issued)
        generation = hashlib.sha256(instructions.pae(
            b"iris-role-generation-v1", instructions.canonical_json(body0),
            cert_sha.encode("ascii"))).hexdigest()
        body = dict(body0, role_gen=generation)
        body_bytes = instructions.canonical_json(body)
        instructions.validate_role_body(body)
        before = _read_certificate(key_paths.certificate)
        try:
            signature = ((lambda: instruction_keys.sign_instruction(
                key_paths, body_bytes, roots, now=now))()
                         if signer is None else signer(body_bytes, now))
        except Exception as exc:
            raise StamperError("role_unavailable") from exc
        after = _read_certificate(key_paths.certificate)
        if before == certificate and after == certificate \
                and signature_certificate_blob(signature) == \
                certificate_blob(certificate):
            break
        if attempt + 1 == SIGN_RETRIES:
            raise StamperError("role_unavailable")
    artifact = instructions.frame_role(body_bytes, signature)
    artifact_sha = hashlib.sha256(artifact).hexdigest()
    final = _artifact_path(paths, semantic["role"], generation)
    pending_name = ".pending-" + generation
    pending = os.path.join(paths.roles, pending_name)
    os.makedirs(paths.roles, mode=0o700, exist_ok=True)
    if os.path.exists(final):
        if _role_bytes(final) != artifact:
            raise StamperError("role_unavailable")
        _fsync_directory(paths.roles)
    elif os.path.exists(pending):
        if _role_bytes(pending) != artifact:
            raise StamperError("role_unavailable")
        _fsync_directory(paths.roles)
    else:
        _atomic_bytes(pending, artifact, mode=0o644)
    metadata = {
        "state": "pending", "epoch": epoch, "role": semantic["role"],
        "day": day, "semantic_body_sha256": semantic_sha,
        "cert_sha256": cert_sha, "issued_at": issued, "expires_at": expires,
        "artifact_sha256": artifact_sha, "temp_name": pending_name,
        "unreferenced_at": None,
    }
    state["generations"][generation] = metadata
    _atomic_json(paths.role_state, state)
    if not os.path.exists(final):
        os.replace(pending, final)
        _fsync_directory(paths.roles)
    elif os.path.exists(pending):
        if _role_bytes(pending) != artifact:
            raise StamperError("role_unavailable")
        os.unlink(pending)
        _fsync_directory(paths.roles)
    metadata["state"] = "active"
    metadata["temp_name"] = None
    _atomic_json(paths.role_state, state)
    return generation, body_bytes, signature, body, metadata, semantic_sha


def _effective_part(paths, policy, device_id, role, restricted, definition,
                    base, effective, now, expires):
    peers = compile_peers(paths, policy, device_id, role, restricted,
                          definition, now, expires)
    qos_override = {key: effective[key] for key in instructions.QOS_FIELDS
                    if effective[key] != base[key]}
    control_override = {key: effective[key] for key in instructions.CONTROL_FIELDS
                        if effective[key] != base[key]}
    return {"peers": peers, "qos_override": qos_override,
            "control_override": control_override, "server_time": expires}


def _generation_metadata(paths, generation):
    return _read_role_state(paths)["generations"].get(generation)


def _confirm_policy_stamp(catalog_store, device_id, expected):
    """Confirm an exact visible policy stamp under its shard's owning lock."""
    state = catalog_store._policies
    state._ensure_migrated()
    bucket = keyed_state.bucket_of(device_id, state.shards)
    with keyed_state.file_lock(state._shard_path(bucket)):
        rows = state._read_shard(bucket)
        row = rows.get(device_id)
        if not isinstance(row, dict) or row.get("instr") != expected:
            raise StamperError("stamp_commit")
        try:
            instructions.validate_stamp(row["instr"])
        except instructions.InstructionError as exc:
            raise StamperError("stamp_invalid") from exc
        keyed_state._fsync_directory(state.dir)


def _confirm_history(paths, device_id, expected):
    history = _history(paths)

    def confirm(row):
        if row != expected:
            raise StamperError("history_invalid")
        keyed_state._fsync_directory(history.dir)
        return None

    history.update(device_id, confirm)


def _daily_due(device_id, now):
    seconds = int(now) % 86400
    return seconds >= instructions.daily_offset(device_id)


def _load_instruction_policy(paths):
    """Return policy with ``degraded`` reserved for actual LKG provenance.

    ``peer_policy`` also uses its degraded bit to report a valid authoritative
    base that is missing previously configured roles.  That condition is a
    state-loss refusal for instruction production, not permission to label an
    authoritative stamp as an LKG stamp.
    """
    try:
        result = peer_policy.load_policy(
            paths.policy_authoritative, paths.policy_lkg)
    except Exception as exc:
        raise StamperError("policy_unavailable") from exc
    if result.degraded and not result.fail_closed:
        try:
            authoritative = peer_policy._read_valid(  # provenance only
                paths.policy_authoritative)
        except Exception as exc:
            raise StamperError("policy_unavailable") from exc
        if authoritative is not None:
            raise StamperError("policy_unavailable")
    return result


class InstructionStamper:
    def __init__(self, paths=None, fleet=None, catalog_store=None, now=None,
                 signer=None, certificate_info=None):
        self.paths = paths or StamperPaths.from_env()
        self.fleet = fleet or gui_fleet.FleetStore(self.paths.state_dir)
        self.catalog = catalog_store or catalog.CatalogStore(self.paths.state_dir)
        self.now = time.time if now is None else now
        self.signer = signer
        self.certificate_info = certificate_info

    def _fleet_row(self, device_id):
        try:
            row = self.fleet.get_device(device_id)
        except Exception as exc:
            raise StamperError("fleet_unavailable") from exc
        if not isinstance(row, dict) or row.get("device_id") != device_id:
            raise StamperError("fleet_unavailable")
        return row

    def stamp_device(self, device_id, expected_key_id=None):
        with producer_lock(self.paths, exclusive=False):
            activation = _validated_activation_epoch(self.paths)
            with device_lock(self.paths, device_id):
                return self._stamp_locked(
                    device_id, activation, expected_key_id=expected_key_id)

    def _stamp_locked(self, device_id, activation, expected_key_id=None):
        now = _time(self.now())
        fleet_row = self._fleet_row(device_id)
        try:
            platform = gui_onboard.resolve_platform(fleet_row, probe=None)
        except Exception as exc:
            raise StamperError("platform_unresolved") from exc
        key_record = _instruction_key(self.paths, device_id)
        superseded = (expected_key_id is not None
                      and expected_key_id != key_record["key_id"])
        _admit(self.paths, activation, device_id, fleet_row, key_record)
        policy = _load_instruction_policy(self.paths)
        if policy.fail_closed:
            raise StamperError("policy_fail_closed")
        semantic, base, effective = semantic_role(
            policy.document, policy.roles, device_id)
        role = semantic["role"]
        definition = policy.document.get("roles", {}).get("defs", {}).get(
            role, {}) if role != "default" else {}
        old_row = self.catalog._policies.get(device_id)
        old_stamp = None
        if isinstance(old_row, dict) and "instr" in old_row:
            try:
                old_stamp = instructions.validate_stamp(old_row["instr"])
            except instructions.InstructionError as exc:
                raise StamperError("stamp_invalid") from exc
        history = _history(self.paths).get(device_id)
        if history is None or history["epoch"] != activation["epoch"] \
                or (old_stamp is not None
                    and old_stamp["epoch"] == activation["epoch"]
                    and history["high_water"] < old_stamp["instr_serial"]):
            raise StamperError("history_invalid")

        with role_lock(self.paths):
            role_state = reconcile_roles(self.paths, self.catalog)
            semantic_sha = hashlib.sha256(
                instructions.canonical_json(semantic)).hexdigest()
            key_paths = instruction_keys.InstructionPaths(
                self.paths.state_dir, self.paths.config_dir,
                self.paths.run_dir)
            current_certificate = _read_certificate(key_paths.certificate)
            current_cert_sha = hashlib.sha256(current_certificate).hexdigest()
            if old_stamp is not None:
                try:
                    roots = instruction_keys.discover_roots(key_paths)
                    _validate_certificate_snapshot(
                        key_paths, current_certificate, roots, now,
                        certificate_info=self.certificate_info)
                except Exception as exc:
                    raise StamperError("role_unavailable") from exc
                if _read_certificate(key_paths.certificate) != \
                        current_certificate:
                    raise StamperError("role_unavailable")
                old_meta = role_state["generations"].get(old_stamp["role_gen"])
                if old_meta is None or old_meta["state"] != "active":
                    raise StamperError("role_unavailable")
                old_body, _old_signature, _old_role = \
                    _validated_active_artifact(
                        self.paths, old_stamp["role_gen"], old_meta)
                if old_meta["epoch"] != old_stamp["epoch"] \
                        or old_meta["role"] != old_stamp["role"] \
                        or old_meta["issued_at"] != old_stamp["issued_at"] \
                        or old_meta["expires_at"] != old_stamp["expires_at"] \
                        or hashlib.sha256(old_body).hexdigest() != \
                        old_stamp["role_body_sha256"]:
                    raise StamperError("stamp_invalid")
                preliminary = _effective_part(
                    self.paths, policy, device_id, role,
                    semantic["restricted"], definition, base, effective, now,
                    old_stamp["expires_at"])
                preliminary["server_time"] = old_stamp["issued_at"]
                old_peers = old_stamp["part"]["peers"]
                new_peers = preliminary["peers"]
                membership_old = {key: value for key, value in old_peers.items()
                                  if key != "allowed_expires_at"}
                membership_new = {key: value for key, value in new_peers.items()
                                  if key != "allowed_expires_at"}
                renewal = max(
                    1, min(120, peer_endpoints.endpoint_ttl() // 3))
                if membership_old == membership_new \
                        and old_peers["allowed_expires_at"] - now > renewal:
                    preliminary["peers"] = copy.deepcopy(old_peers)
                same_content = (
                    old_stamp["epoch"] == activation["epoch"]
                    and old_stamp["key_id"] == key_record["key_id"]
                    and old_stamp["platform"] == platform
                    and old_stamp["role"] == role
                    and old_stamp["degraded"] == policy.degraded
                    and old_meta["semantic_body_sha256"] == semantic_sha
                    and old_meta["cert_sha256"] == current_cert_sha
                    and old_stamp["part"] == preliminary)
                if same_content and (old_meta["day"] == _day(now)
                                     or not _daily_due(device_id, now)):
                    _confirm_policy_stamp(self.catalog, device_id, old_stamp)
                    unfinished = history.get("reservation")
                    old_desired = dict(old_stamp)
                    old_serial = old_desired.pop("instr_serial")
                    old_digest = instructions.desired_digest(old_desired)
                    if unfinished == {"instr_serial": old_serial,
                                      "desired_sha256": old_digest}:
                        _finalize(self.paths, device_id, activation["epoch"],
                                  old_serial, old_digest)
                    else:
                        _confirm_history(self.paths, device_id, history)
                    return "superseded" if superseded else "unchanged"
            generation, body_bytes, signature, body, metadata, semantic_sha = \
                _publish_role_locked(
                    self.paths, self.catalog, semantic, activation["epoch"],
                    now, signer=self.signer,
                    certificate_info=self.certificate_info)
            part = _effective_part(
                self.paths, policy, device_id, role, semantic["restricted"],
                definition, base, effective, now, body["expires_at"])
            # Role issuance is the immutable server time for both layers.
            part["server_time"] = body["issued_at"]
            if old_stamp is not None:
                old_peers = old_stamp["part"]["peers"]
                new_peers = part["peers"]
                membership_old = {k: v for k, v in old_peers.items()
                                  if k != "allowed_expires_at"}
                membership_new = {k: v for k, v in new_peers.items()
                                  if k != "allowed_expires_at"}
                renewal = max(1, min(120, peer_endpoints.endpoint_ttl() // 3))
                if membership_old == membership_new \
                        and old_peers["allowed_expires_at"] - now > renewal:
                    part["peers"] = copy.deepcopy(old_peers)

            desired = {
                "epoch": activation["epoch"],
                "policy_revision": policy.document["revision"],
                "platform": platform, "role": role, "role_gen": generation,
                "role_body_sha256": hashlib.sha256(body_bytes).hexdigest(),
                "key_id": key_record["key_id"], "verify_level": "sig",
                "issued_at": body["issued_at"], "expires_at": body["expires_at"],
                "degraded": bool(policy.degraded), "part": part,
            }
            desired_sha = instructions.desired_digest(desired)
            serial = _reserve(self.paths, device_id, activation["epoch"],
                              desired_sha)
            stamp = dict(desired, instr_serial=serial)
            instructions.validate_stamp(stamp)
            if not _same_key(self.paths, device_id, key_record["key_id"]):
                raise StamperError("key_superseded")

            def merge(row):
                current = dict(row) if isinstance(row, dict) else {
                    "approved_image_id": None, "approved_image_ids": [],
                    "plans": {}}
                if "instr" in current:
                    instructions.validate_stamp(current["instr"])
                current["instr"] = stamp
                return current

            try:
                self.catalog._policies.update(device_id, merge)
            except Exception as exc:
                raise StamperError("stamp_commit") from exc
        if not _same_key(self.paths, device_id, key_record["key_id"]):
            def cleanup(row):
                if not isinstance(row, dict) or row.get("instr") != stamp:
                    return None
                clean = dict(row)
                clean.pop("instr", None)
                return clean
            self.catalog._policies.update(device_id, cleanup)
            raise StamperError("key_superseded")
        _finalize(self.paths, device_id, activation["epoch"], serial,
                  desired_sha)
        return "superseded" if superseded else "updated"

    def run_once(self):
        counts = {"seen": 0, "updated": 0, "unchanged": 0, "failed": 0}
        errors = {}
        try:
            _validated_activation_epoch(self.paths)
        except StamperError as exc:
            errors[exc.code] = 1
            return counts, errors, ("uninitialized" if exc.code == "uninitialized"
                                    else "degraded")
        try:
            rows = self.fleet.list_devices()
        except Exception:
            rows = []
            errors["fleet_unavailable"] = 1
        for row in rows:
            counts["seen"] += 1
            try:
                outcome = self.stamp_device(row.get("device_id"))
                counts["unchanged" if outcome == "unchanged" else "updated"] += 1
            except StamperError as exc:
                counts["failed"] += 1
                errors[exc.code] = errors.get(exc.code, 0) + 1
            except Exception:
                counts["failed"] += 1
                errors["stamp_commit"] = errors.get("stamp_commit", 0) + 1
        try:
            gc_roles(self.paths, self.catalog, now=_time(self.now()))
        except StamperError as exc:
            errors[exc.code] = errors.get(exc.code, 0) + 1
        except Exception:
            errors["role_unavailable"] = errors.get(
                "role_unavailable", 0) + 1
        state = "ok" if not errors else "degraded"
        if errors.get("uninitialized"):
            state = "uninitialized"
        return counts, errors, state


def _validated_activation_epoch(paths):
    activation = read_activation(paths)
    try:
        key_epoch = instruction_keys.read_epoch(
            instruction_keys.InstructionPaths(
                paths.state_dir, paths.config_dir, paths.run_dir))
    except Exception as exc:
        raise StamperError("activation_invalid") from exc
    if key_epoch is None or key_epoch["epoch"] != activation["epoch"]:
        raise StamperError("activation_invalid")
    return activation


def initialize_producer(mode, paths=None, fleet=None, now=None):
    if mode not in ("initialize", "recover"):
        raise StamperError("activation_invalid")
    paths = paths or StamperPaths.from_env()
    fleet = fleet or gui_fleet.FleetStore(paths.state_dir)
    clock = time.time if now is None else now
    activated_at = _time(clock(), "activation_invalid")
    os.makedirs(paths.directory, mode=0o700, exist_ok=True)
    with producer_lock(paths, exclusive=True):
        prior = read_activation(paths, required=False)
        if mode == "initialize" and prior is not None:
            raise StamperError("activation_invalid")
        if mode == "recover" and prior is None:
            raise StamperError("activation_invalid")
        if mode == "recover":
            # Validate the established disclosure authority before rotating
            # the epoch or replacing any producer authority.  Recovery from
            # its loss is an operator repair, not a new empty deployment.
            try:
                peer_handouts.initialize(paths.handouts, create=False)
            except peer_handouts.HandoutStoreError as exc:
                raise StamperError("handout_unavailable") from exc
        key_paths = instruction_keys.InstructionPaths(
            paths.state_dir, paths.config_dir, paths.run_dir)
        epoch_doc = instruction_keys.new_epoch(key_paths, now=activated_at)
        epoch = epoch_doc["epoch"]
        try:
            fleet_rows = fleet.list_devices()
            secret_store = secrets_store.load(paths.secrets)
        except Exception as exc:
            raise StamperError("fleet_unavailable") from exc
        if len(fleet_rows) > MAX_DEVICES:
            raise StamperError("admission_refused")
        devices = {}
        for row in fleet_rows:
            device_id = row.get("device_id")
            try:
                secrets_store.validate_device_id(device_id)
            except (TypeError, ValueError) as exc:
                raise StamperError("fleet_unavailable") from exc
            created = None
            records = secret_store.get("devices", {}).get(device_id)
            if isinstance(records, dict) and "instr_key" in records:
                created = secrets_store.validate_instruction_key_record(
                    records["instr_key"])["created_at"]
            devices[device_id] = {"state": "active",
                                  "registered_at": _registered_at(row),
                                  "created_at": created}
        admissions = {"schema": ADMISSIONS_SCHEMA, "epoch": epoch,
                      "devices": devices}
        _validate_admissions(admissions)
        _atomic_json(paths.admissions, admissions)
        _reset_history(paths, epoch, devices)
        if mode == "initialize":
            try:
                peer_handouts.initialize(paths.handouts, create=True)
            except peer_handouts.HandoutStoreError as exc:
                raise StamperError("handout_unavailable") from exc
        marker = {"schema": ACTIVATION_SCHEMA, "epoch": epoch,
                  "activated_at": activated_at, "mode": mode}
        _atomic_json(paths.activation, marker)
        return marker


_ROTATION_LOCAL = threading.local()


@contextlib.contextmanager
def rotation_context(device_id, paths=None):
    """Hold the producer locks across Task 12 mutation and Task 13 handoff."""
    paths = paths or StamperPaths.from_env()
    with producer_lock(paths, exclusive=False):
        activation = _validated_activation_epoch(paths)
        with device_lock(paths, device_id):
            prior = getattr(_ROTATION_LOCAL, "held", None)
            _ROTATION_LOCAL.held = (paths, device_id, activation)
            try:
                yield
            finally:
                _ROTATION_LOCAL.held = prior


def restamp_instruction_key(device_id, expected_key_id=None):
    held = getattr(_ROTATION_LOCAL, "held", None)
    if held is not None and held[1] == device_id:
        return InstructionStamper(paths=held[0])._stamp_locked(
            device_id, held[2], expected_key_id=expected_key_id)
    return InstructionStamper().stamp_device(
        device_id, expected_key_id=expected_key_id)


restamp_instruction_key._iris_rotation_context = rotation_context


def gc_roles(paths=None, catalog_store=None, now=None):
    paths = paths or StamperPaths.from_env()
    catalog_store = catalog_store or catalog.CatalogStore(paths.state_dir)
    now = _time(time.time() if now is None else now)
    with producer_lock(paths, exclusive=False), role_lock(paths):
        state = reconcile_roles(paths, catalog_store)
        references = _policy_references(catalog_store)
        changed = False
        for generation in list(state["generations"]):
            row = state["generations"][generation]
            if row["state"] != "active":
                continue
            if generation in references:
                if row["unreferenced_at"] is not None:
                    row["unreferenced_at"] = None
                    changed = True
                continue
            if row["unreferenced_at"] is None:
                row["unreferenced_at"] = now
                changed = True
                continue
            if now < row["expires_at"] \
                    or now < row["unreferenced_at"] + MAX_TTL:
                continue
            artifact = _artifact_path(paths, row["role"], generation)
            _validated_active_artifact(paths, generation, row)
            os.unlink(artifact)
            _fsync_directory(paths.roles)
            del state["generations"][generation]
            changed = True
        if changed:
            _atomic_json(paths.role_state, state)
        return changed


def _status_document(now, last_success_at, state, counts, errors):
    now = _time(now)
    if last_success_at is not None:
        _i63(last_success_at, "status_write")
    if state not in ("ok", "degraded", "uninitialized") \
            or set(counts) != {"seen", "updated", "unchanged", "failed"} \
            or not isinstance(errors, dict) or len(errors) > STATUS_ERROR_MAX:
        raise StamperError("status_write")
    for value in counts.values():
        _i63(value, "status_write")
    for key, value in errors.items():
        if key not in ERROR_CODES:
            raise StamperError("status_write")
        _i63(value, "status_write")
    return {"schema": STATUS_SCHEMA, "updated_at": now,
            "last_success_at": last_success_at, "state": state,
            "counts": counts, "errors": errors}


def status_loop(stop_event, stamper=None, interval=PASS_INTERVAL):
    stamper = stamper or InstructionStamper()
    last_success = None
    while True:
        now = None
        try:
            now = _time(stamper.now(), "status_write")
            counts, errors, state = stamper.run_once()
            if state == "ok":
                last_success = now
        except Exception:
            if now is None:
                try:
                    now = _time(time.time(), "status_write")
                except Exception:
                    now = 0
            counts = {"seen": 0, "updated": 0, "unchanged": 0, "failed": 1}
            errors = {"stamp_commit": 1}
            state = "degraded"
        try:
            _atomic_json(stamper.paths.status, _status_document(
                now, last_success, state, counts, errors))
        except Exception:
            pass
        if stop_event.wait(interval):
            return
