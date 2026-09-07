# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durable, privacy-scoped evidence of tracker peer disclosures."""

import errno
import ipaddress
import json
import math
import os
import re
import tempfile
import threading

import keyed_state
import peer_endpoints
import secrets_store


MAX_RECIPIENTS = 10256
MAX_ADDRESSES = 4096
ADMISSIONS_MAX_BYTES = 4 * 1024 * 1024
ADMISSIONS_SCHEMA = "iris-peer-handout-admissions/v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
DEVICE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_I63 = (1 << 63) - 1


class HandoutStoreError(ValueError):
    """Disclosure evidence is unavailable or corrupt."""


def admissions_path(path):
    directory = os.path.dirname(path)
    return os.path.join(directory, "peer-handouts-admissions.json")


def _integer_time(value, name="time"):
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or not math.isfinite(value) or value < 0 or value > MAX_I63:
        raise HandoutStoreError("invalid %s" % name)
    return int(value)


def _stored_time(value, name):
    if isinstance(value, bool) or not isinstance(value, int) \
            or not 0 <= value <= MAX_I63:
        raise HandoutStoreError("invalid %s" % name)
    return value


def _device_id(value):
    if not isinstance(value, str) or DEVICE_ID.fullmatch(value) is None:
        raise HandoutStoreError("invalid principal")
    try:
        secrets_store.validate_device_id(value)
    except (TypeError, ValueError) as exc:
        raise HandoutStoreError("invalid principal") from exc
    return value


def _address(value):
    try:
        parsed = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError, ValueError) as exc:
        raise HandoutStoreError("invalid address") from exc
    if str(parsed) != value:
        raise HandoutStoreError("noncanonical address")
    return value


def _validate_row(key, row):
    if not isinstance(row, dict) or set(row) != {
            "v", "principal_type", "principal_id", "updated_at", "handouts"}:
        raise ValueError("invalid handout row")
    if isinstance(row["v"], bool) or not isinstance(row["v"], int) \
            or row["v"] != 1 \
            or row["principal_type"] != "device" or row["principal_id"] != key:
        raise ValueError("invalid handout identity")
    _device_id(key)
    _stored_time(row["updated_at"], "updated_at")
    values = row["handouts"]
    if not isinstance(values, list) or len(values) > MAX_ADDRESSES:
        raise ValueError("invalid handout list")
    prior = None
    for item in values:
        if not isinstance(item, dict) or set(item) != {
                "address", "info_hash", "expires_at"}:
            raise ValueError("invalid handout")
        address = _address(item["address"])
        if prior is not None and address <= prior:
            raise ValueError("unsorted handouts")
        prior = address
        if not isinstance(item["info_hash"], str) \
                or HEX40.fullmatch(item["info_hash"]) is None:
            raise ValueError("invalid info hash")
        _stored_time(item["expires_at"], "expires_at")


def _validate_admissions(document):
    if not isinstance(document, dict) or set(document) != {"schema", "devices"} \
            or document.get("schema") != ADMISSIONS_SCHEMA:
        raise HandoutStoreError("handout admissions are corrupt")
    devices = document.get("devices")
    if not isinstance(devices, dict) or len(devices) > MAX_RECIPIENTS:
        raise HandoutStoreError("handout admissions are corrupt")
    for device_id, state in devices.items():
        _device_id(device_id)
        if state not in ("pending", "active"):
            raise HandoutStoreError("handout admissions are corrupt")
    return document


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


def _write_document(path, document):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        dir=directory, prefix=".peer-handout-admissions-")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(document, stream, sort_keys=True, separators=(",", ":"),
                      allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(directory)
    finally:
        try:
            os.remove(temporary)
        except FileNotFoundError:
            pass


def _read_admissions(path, missing_ok=False):
    try:
        stat_result = os.stat(path)
        if stat_result.st_size > ADMISSIONS_MAX_BYTES:
            raise HandoutStoreError("handout admissions are unavailable")
        with open(path, "rb") as stream:
            data = stream.read(ADMISSIONS_MAX_BYTES + 1)
    except FileNotFoundError:
        if missing_ok:
            return None
        raise HandoutStoreError("handout admissions are unavailable")
    except OSError as exc:
        raise HandoutStoreError("handout admissions are unavailable") from exc
    if len(data) > ADMISSIONS_MAX_BYTES:
        raise HandoutStoreError("handout admissions are unavailable")
    try:
        document = json.loads(
            data.decode("utf-8"), object_pairs_hook=_pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite")))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise HandoutStoreError("handout admissions are unavailable") from exc
    return _validate_admissions(document)


def _pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def initialize(path, create=True):
    """Validate authority, creating it only for explicit first initialization."""
    admission_file = admissions_path(path)
    rows = keyed_state.KeyedState(
        path, error=HandoutStoreError, validate=_validate_row,
        durable=True, indent=None)
    with keyed_state.file_lock(admission_file):
        existing = _read_admissions(admission_file, missing_ok=True)
    if existing is not None:
        snapshot = rows.snapshot()
        with keyed_state.file_lock(admission_file):
            if _read_admissions(admission_file) != existing:
                raise HandoutStoreError("handout admissions changed")
        admitted = set(existing["devices"])
        if set(snapshot) - admitted:
            raise HandoutStoreError(
                "established handout admission is missing")
        if any(state == "active" and device_id not in snapshot
               for device_id, state in existing["devices"].items()):
            raise HandoutStoreError("established handout row is missing")
        return False

    snapshot = rows.snapshot()
    if not create:
        raise HandoutStoreError("handout admissions are unavailable")
    if snapshot:
        raise HandoutStoreError("established handout admissions are missing")
    with keyed_state.file_lock(admission_file):
        existing = _read_admissions(admission_file, missing_ok=True)
        if existing is None:
            _write_document(admission_file, {
                "schema": ADMISSIONS_SCHEMA, "devices": {}})
            return True
    # A concurrent initializer won. Validate it after releasing the
    # non-reentrant admissions lock.
    return initialize(path, create=create)


class HandoutLedger:
    def __init__(self, path, admission_file=None, ttl=None):
        self.path = path
        self.admission_file = admission_file or admissions_path(path)
        self.ttl = peer_endpoints.endpoint_ttl() if ttl is None else int(ttl)
        if self.ttl < 1:
            raise HandoutStoreError("invalid handout TTL")
        self.rows = keyed_state.KeyedState(
            path, error=HandoutStoreError, validate=_validate_row,
            durable=True, indent=None)

    @staticmethod
    def _empty(device_id, now):
        return {"v": 1, "principal_type": "device",
                "principal_id": device_id, "updated_at": int(now),
                "handouts": []}

    def _admit(self, device_id, now):
        """Resume the pending -> row -> active protocol without nested locks."""
        observed_row = self.rows.get(device_id)
        with keyed_state.file_lock(self.admission_file):
            document = _read_admissions(self.admission_file)
            state = document["devices"].get(device_id)
            if state is None:
                if observed_row is not None:
                    raise HandoutStoreError(
                        "established handout admission is missing")
                if len(document["devices"]) >= MAX_RECIPIENTS:
                    raise HandoutStoreError("handout recipient cap reached")
                document["devices"][device_id] = "pending"
                _write_document(self.admission_file, document)
                state = "pending"
            if state == "active":
                _fsync_directory(os.path.dirname(self.admission_file) or ".")
            elif state == "pending":
                # A prior rename may have made this exact pending admission
                # visible before its directory fsync failed. Confirm it while
                # its owning lock is held before allowing it to authorize a
                # row or an active transition.
                _fsync_directory(os.path.dirname(self.admission_file) or ".")
            else:
                raise HandoutStoreError("handout admission changed")

        def ensure(row):
            if row is None:
                if state == "active":
                    raise HandoutStoreError(
                        "established handout row is missing")
                return self._empty(device_id, now)
            _validate_row(device_id, row)
            # No rewrite is needed, but visibility after a failed prior
            # directory fsync is not durability. The shard lock held by
            # KeyedState.update makes this confirmation authoritative.
            keyed_state._fsync_directory(self.rows.dir)
            return None

        self.rows.update(device_id, ensure)

        with keyed_state.file_lock(self.admission_file):
            document = _read_admissions(self.admission_file)
            state = document["devices"].get(device_id)
            if state == "pending":
                document["devices"][device_id] = "active"
                _write_document(self.admission_file, document)
            elif state == "active":
                # Another caller completed the same pending admission. Its
                # exact established value is success after durability is
                # confirmed; it must not turn a concurrent retry into error.
                _fsync_directory(os.path.dirname(self.admission_file) or ".")
            else:
                raise HandoutStoreError("handout admission changed")

        def confirm_row(row):
            if row is None:
                raise HandoutStoreError("pending handout row is missing")
            _validate_row(device_id, row)
            keyed_state._fsync_directory(self.rows.dir)
            return None

        self.rows.update(device_id, confirm_row)

    def record(self, principal, peers, info_hash, now):
        if getattr(principal, "type", None) != "device":
            return True
        device_id = _device_id(getattr(principal, "id", None))
        if not isinstance(info_hash, str) or HEX40.fullmatch(info_hash) is None:
            raise HandoutStoreError("invalid info hash")
        disclosed = _integer_time(now, "disclosure time")
        addresses = []
        for peer in peers:
            if not isinstance(peer, dict):
                raise HandoutStoreError("invalid selected peer")
            addresses.append(_address(peer.get("ip")))
        addresses = sorted(set(addresses))
        if not addresses:
            return True
        renewal = max(1, min(120, self.ttl // 3))
        if disclosed > MAX_I63 - self.ttl:
            raise HandoutStoreError("invalid disclosure time")
        new_expiry = disclosed + self.ttl
        self._admit(device_id, disclosed)

        def update(row):
            if row is None:
                raise HandoutStoreError("established handout row is missing")
            _validate_row(device_id, row)
            current = {
                item["address"]: dict(item) for item in row["handouts"]
                if disclosed < item["expires_at"]
            }
            changed = len(current) != len(row["handouts"])
            for address in addresses:
                old = current.get(address)
                if old is None:
                    current[address] = {"address": address,
                                        "info_hash": info_hash,
                                        "expires_at": new_expiry}
                    changed = True
                else:
                    if old["info_hash"] != info_hash:
                        old["info_hash"] = info_hash
                        changed = True
                    if old["expires_at"] - disclosed <= renewal:
                        old["expires_at"] = new_expiry
                        changed = True
            if len(current) > MAX_ADDRESSES:
                raise HandoutStoreError("handout address cap reached")
            if not changed:
                keyed_state._fsync_directory(self.rows.dir)
                return None
            return {"v": 1, "principal_type": "device",
                    "principal_id": device_id, "updated_at": disclosed,
                    "handouts": [current[key] for key in sorted(current)]}

        self.rows.update(device_id, update)
        return True

    def current(self, device_id, now):
        device_id = _device_id(device_id)
        current_time = _integer_time(now)
        with keyed_state.file_lock(self.admission_file):
            document = _read_admissions(self.admission_file)
            state = document["devices"].get(device_id)
            if state == "active":
                _fsync_directory(os.path.dirname(self.admission_file) or ".")
        if state is None:
            observed = {"present": False}

            def inspect_orphan(row):
                if row is not None:
                    _validate_row(device_id, row)
                    observed["present"] = True
                return None

            # Admissions and recipient rows deliberately have separate,
            # non-reentrant locks.  Inspect exactly this recipient's shard
            # only after releasing the admissions lock, then recheck the
            # admission before accepting the never-admitted empty result.
            self.rows.update(device_id, inspect_orphan)
            with keyed_state.file_lock(self.admission_file):
                document = _read_admissions(self.admission_file)
                if document["devices"].get(device_id) is not None:
                    raise HandoutStoreError("handout admission changed")
            if observed["present"]:
                raise HandoutStoreError(
                    "established handout admission is missing")
            return []
        if state != "active":
            raise HandoutStoreError("handout admission is pending")
        held = {}

        def confirm(row):
            if row is None:
                raise HandoutStoreError("established handout row is missing")
            _validate_row(device_id, row)
            held["row"] = row
            keyed_state._fsync_directory(self.rows.dir)
            return None

        self.rows.update(device_id, confirm)
        row = held["row"]
        return [dict(item) for item in row["handouts"]
                if current_time < item["expires_at"]]


_LEDGERS = {}
_LEDGERS_LOCK = threading.Lock()


def _ledger(path):
    with _LEDGERS_LOCK:
        ledger = _LEDGERS.get(path)
        if ledger is None:
            ledger = HandoutLedger(path)
            _LEDGERS[path] = ledger
        return ledger


def record_handout(path, principal, peers, info_hash, now):
    return _ledger(path).record(principal, peers, info_hash, now)


def current_handouts(path, device_id, now):
    return _ledger(path).current(device_id, now)
