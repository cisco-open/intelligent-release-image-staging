# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Durable peer-certificate identity revocations, shared by all issuers.

An identity is the opaque SHA256 value in the certificate's IRIS URI SAN.
Revoked identities are never removed. Inventory deletion, credential renewal,
and restarting the service must not restore trust in an old certificate.
"""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

import peer_tls_settings

MAX_IDENTITIES = 10000
MAX_REVISION = 9007199254740991
MAX_STATE_BYTES = 8 * 1024 * 1024
SNAPSHOT_LIFETIME = 300
HEX = re.compile(r"[0-9a-f]{64}\Z")
NONCE = re.compile(r"[0-9a-f]{32}\Z")
REQUEST_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
ORIGIN = "__iris_origin__"


class RevocationError(Exception):
    """The authoritative revocation state cannot be safely used."""


class RevokedIdentity(RevocationError):
    """This device's current certificate identity is permanently withdrawn."""


class RevisionConflict(RevocationError):
    """The operator reviewed an older state, or reused a request identifier."""


def device_identity(device_id):
    """The identity carried by certificates issued before identity replacement."""
    _device_id(device_id, origin=True)
    return hashlib.sha256(device_id.encode("utf-8")).hexdigest()


def _device_id(value, *, origin=False):
    if (not isinstance(value, str) or not value or len(value.encode("utf-8")) > 128
            or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)
            or value == "seeder" or (value == ORIGIN and not origin)):
        raise ValueError("Invalid device identity")
    return value


def _integer(value, maximum=MAX_REVISION):
    return type(value) is int and 0 <= value <= maximum


def observation(value):
    """Validate a bounded, self-reported native enforcement observation."""
    fields = {"supported", "mode", "state", "authority", "revision", "issued_at",
              "expires_at", "own_revoked", "observed_at"}
    if (not isinstance(value, dict) or set(value) != fields
            or value["supported"] is not True
            or value["mode"] not in ("required", "disabled")
            or value["state"] not in ("valid", "unavailable", "expired")
            or type(value["own_revoked"]) is not bool
            or not _integer(value["observed_at"])):
        return None
    authority = value["authority"]
    stamps = (value["revision"], value["issued_at"], value["expires_at"])
    absent = authority is None and all(stamp is None for stamp in stamps)
    complete = (isinstance(authority, str) and HEX.fullmatch(authority) is not None
                and all(_integer(stamp) for stamp in stamps)
                and 0 < value["expires_at"] - value["issued_at"] <= SNAPSHOT_LIFETIME)
    if not absent and not complete:
        return None
    if value["state"] in ("valid", "expired") and (not complete or value["mode"] != "required"):
        return None
    return dict(value)


def _unique_object(items):
    result = {}
    for key, value in items:
        if key in result:
            raise RevocationError("Duplicate revocation state field")
        result[key] = value
    return result


def _read(path):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_mode & 0o077 or info.st_size > MAX_STATE_BYTES):
                raise RevocationError("Unsafe revocation state file")
            data = stream.read(MAX_STATE_BYTES + 1)
            if len(data) > MAX_STATE_BYTES:
                raise RevocationError("Revocation state exceeds supported size")
            return json.loads(data, object_pairs_hook=_unique_object)
    except (OSError, ValueError, TypeError):
        raise RevocationError("Revocation state is unavailable") from None


def _durable(path):
    """A read reconciles even a write whose final directory fsync failed."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Ledger:
    def __init__(self, config=None):
        self.directory = Path(config or os.environ.get("IRIS_CONFIG", "/etc/iris")) / "peer-tls"
        self.path = self.directory / "revocations.json"
        self.marker = self.directory / "revocations.initialized.json"

    @contextlib.contextmanager
    def locked(self):
        """Cross-process serialization of issuance, withdrawal and snapshots."""
        if self.directory.is_symlink():
            raise RevocationError("Unsafe revocation directory")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.stat().st_mode & 0o077:
            raise RevocationError("Unsafe revocation directory permissions")
        try:
            descriptor = os.open(self.directory / "revocations.lock",
                                 os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            with os.fdopen(descriptor, "a+") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077:
                    raise RevocationError("Unsafe revocation lock")
                fcntl.flock(stream, fcntl.LOCK_EX)
                yield self._load()
        except OSError:
            raise RevocationError("Revocation state is unavailable") from None

    @staticmethod
    def _validate(data):
        if (not isinstance(data, dict)
                or set(data) != {"schema", "authority", "revision", "devices", "revoked", "recoveries"}
                or type(data["schema"]) is not int or data["schema"] != 1
                or not isinstance(data["authority"], str) or NONCE.fullmatch(data["authority"]) is None
                or not _integer(data["revision"])
                or not isinstance(data["devices"], dict) or len(data["devices"]) > MAX_IDENTITIES
                or not isinstance(data["revoked"], dict) or len(data["revoked"]) > MAX_IDENTITIES
                or not isinstance(data["recoveries"], dict) or len(data["recoveries"]) > MAX_IDENTITIES
                or data["revision"] < len(data["revoked"])):
            raise RevocationError("Invalid revocation state")
        try:
            for device_id, identity in data["devices"].items():
                _device_id(device_id)
                if (not isinstance(identity, str) or HEX.fullmatch(identity) is None
                        or identity == device_identity(ORIGIN)):
                    raise ValueError("Invalid certificate identity")
            if len(set(data["devices"].values())) != len(data["devices"]):
                raise ValueError("Certificate identity has multiple owners")
            seen_requests = set()
            for identity, record in data["revoked"].items():
                if (not isinstance(identity, str) or HEX.fullmatch(identity) is None
                        or identity == device_identity(ORIGIN)
                        or not isinstance(record, dict)
                        or set(record) != {"device_id", "revoked_at", "request_id", "actor", "expected_revision"}
                        or not _integer(record["revoked_at"])
                        or not _integer(record["expected_revision"])
                        or record["expected_revision"] >= data["revision"]
                        or not isinstance(record["request_id"], str)
                        or REQUEST_ID.fullmatch(record["request_id"]) is None
                        or record["request_id"] in seen_requests
                        or not isinstance(record["actor"], str) or len(record["actor"]) > 256):
                    raise ValueError("Invalid revoked identity")
                _device_id(record["device_id"])
                if record["device_id"] not in data["devices"]:
                    raise ValueError("Revoked certificate owner is missing")
                seen_requests.add(record["request_id"])
            replacements = set()
            for identity, record in data["recoveries"].items():
                if (identity not in data["revoked"] or not isinstance(record, dict)
                        or set(record) != {"device_id", "request_id", "expected_revision", "next_identity_sha256",
                                           "approved_at", "activated_at", "actor"}
                        or record["device_id"] != data["revoked"][identity]["device_id"]
                        or not isinstance(record["request_id"], str)
                        or REQUEST_ID.fullmatch(record["request_id"]) is None
                        or record["request_id"] in seen_requests
                        or not _integer(record["expected_revision"])
                        or record["expected_revision"] >= data["revision"]
                        or not isinstance(record["next_identity_sha256"], str)
                        or HEX.fullmatch(record["next_identity_sha256"]) is None
                        or record["next_identity_sha256"] == device_identity(ORIGIN)
                        or record["next_identity_sha256"] == identity
                        or record["next_identity_sha256"] in replacements
                        or not _integer(record["approved_at"])
                        or record["activated_at"] is not None and (
                            not _integer(record["activated_at"]) or record["activated_at"] < record["approved_at"])
                        or not isinstance(record["actor"], str) or len(record["actor"]) > 256):
                    raise ValueError("Invalid certificate recovery approval")
                if record["activated_at"] is None and data["devices"][record["device_id"]] != identity:
                    raise ValueError("Pending recovery lost its withdrawn identity")
                replacements.add(record["next_identity_sha256"])
                seen_requests.add(record["request_id"])
        except (ValueError, UnicodeError):
            raise RevocationError("Invalid revocation state") from None
        return data

    def _load(self):
        # The separate marker distinguishes the first feature migration from
        # loss of an established ledger. Publish the ledger before the marker;
        # an interruption may finish migration but can never replace the file.
        if not self.path.exists() and not self.path.is_symlink():
            if self.marker.exists() or self.marker.is_symlink():
                raise RevocationError("Established revocation state is missing")
            data = {"schema": 1, "authority": secrets.token_hex(16),
                    "revision": 0, "devices": {}, "revoked": {}, "recoveries": {}}
            peer_tls_settings.atomic_json(self.path, data)
        else:
            data = self._validate(_read(self.path))
        marker = {"schema": 1, "authority": data["authority"]}
        if not self.marker.exists() and not self.marker.is_symlink():
            peer_tls_settings.atomic_json(self.marker, marker)
        elif _read(self.marker) != marker:
            raise RevocationError("Revocation authority does not match")
        _durable(self.path)
        _durable(self.marker)
        return data

    def initialize(self):
        with self.locked():
            pass

    @staticmethod
    def identity(data, device_id):
        return data["devices"].get(device_id, device_identity(device_id))

    @classmethod
    def allowed_identity(cls, data, device_id):
        identity = cls.identity(data, device_id)
        if identity in data["revoked"]:
            raise RevokedIdentity("This device certificate has been revoked")
        return identity

    @classmethod
    def projection(cls, data, device_id):
        identity = cls.identity(data, device_id)
        revoked = data["revoked"].get(identity)
        recovery = data["recoveries"].get(identity)
        if recovery is None and revoked is None:
            recovery = next((record for record in data["recoveries"].values()
                             if record["device_id"] == device_id
                             and record["next_identity_sha256"] == identity), None)
        pending = recovery is not None and recovery["activated_at"] is None
        return {"device_id": device_id, "identity_sha256": identity,
                "revision": data["revision"],
                "state": "reenrollment-required" if pending else "revoked" if revoked else "active",
                "revoked_at": revoked["revoked_at"] if revoked else None,
                "request_id": revoked["request_id"] if revoked else None,
                "recovery_request_id": recovery["request_id"] if recovery else None}

    def status(self, device_id):
        _device_id(device_id)
        with self.locked() as data:
            return self.projection(data, device_id)

    @staticmethod
    def _request(device_id, expected_revision, expected_identity_sha256, request_id, actor, now):
        _device_id(device_id)
        if (not _integer(expected_revision) or not isinstance(request_id, str)
                or REQUEST_ID.fullmatch(request_id) is None
                or not isinstance(expected_identity_sha256, str)
                or HEX.fullmatch(expected_identity_sha256) is None
                or not isinstance(actor, str) or len(actor) > 256):
            raise ValueError("Provide the reviewed revision and a unique request ID")
        now = int(time.time()) if now is None else now
        if not _integer(now):
            raise ValueError("Invalid revocation time")
        return now

    def _save(self, data):
        self._validate(data)
        if len(json.dumps(data).encode("utf-8")) > MAX_STATE_BYTES:
            raise RevocationError("Revocation state has reached its supported limit")
        peer_tls_settings.atomic_json(self.path, data)

    def revoke(self, device_id, *, expected_revision, expected_identity_sha256,
               request_id, actor, now=None):
        now = self._request(device_id, expected_revision, expected_identity_sha256, request_id, actor, now)
        with self.locked() as data:
            if any(record["request_id"] == request_id for record in data["recoveries"].values()):
                raise RevisionConflict("This request ID belongs to another certificate operation")
            identity = self.identity(data, device_id)
            if identity != expected_identity_sha256:
                raise RevisionConflict("Device certificate identity changed; refresh before retrying")
            for revoked_identity, record in data["revoked"].items():
                if record["request_id"] == request_id and (
                        revoked_identity != identity or record["device_id"] != device_id
                        or record["expected_revision"] != expected_revision):
                    raise RevisionConflict("This request ID belongs to another withdrawal")
            if identity in data["revoked"]:
                if data["revoked"][identity]["request_id"] != request_id:
                    raise RevisionConflict("This certificate identity is already revoked; refresh its status")
                return dict(self.projection(data, device_id), applied=False)
            if data["revision"] != expected_revision:
                raise RevisionConflict("Certificate status changed; refresh before retrying")
            if (len(data["revoked"]) >= MAX_IDENTITIES
                    or device_id not in data["devices"] and len(data["devices"]) >= MAX_IDENTITIES
                    or data["revision"] == MAX_REVISION):
                raise RevocationError("Revocation state has reached its supported limit")
            data["devices"][device_id] = identity
            data["revoked"][identity] = {"device_id": device_id, "revoked_at": now,
                                         "request_id": request_id, "actor": actor,
                                         "expected_revision": expected_revision}
            data["revision"] += 1
            self._save(data)
            return dict(self.projection(data, device_id), applied=True)

    def prepare_reenrollment(self, device_id, *, expected_revision, expected_identity_sha256,
                             request_id, actor, now=None, admission_check=None):
        now = self._request(device_id, expected_revision, expected_identity_sha256, request_id, actor, now)
        with self.locked() as data:
            for old_identity, record in data["recoveries"].items():
                if record["request_id"] == request_id:
                    if (record["device_id"] != device_id or old_identity != expected_identity_sha256
                            or record["expected_revision"] != expected_revision):
                        raise RevisionConflict("This request ID belongs to another certificate operation")
                    return dict(self.projection(data, device_id), applied=False)
            if any(record["request_id"] == request_id for record in data["revoked"].values()):
                raise RevisionConflict("This request ID belongs to another certificate operation")
            identity = self.identity(data, device_id)
            if identity != expected_identity_sha256 or data["revision"] != expected_revision:
                raise RevisionConflict("Certificate status changed; refresh before retrying")
            if identity not in data["revoked"]:
                raise RevisionConflict("Only a revoked certificate needs fresh onboarding approval")
            if identity in data["recoveries"]:
                raise RevisionConflict("Fresh onboarding is already approved; refresh certificate status")
            if data["revision"] == MAX_REVISION:
                raise RevocationError("Revocation state has reached its supported limit")
            if admission_check is not None:
                admission_check()
            unavailable = set(data["revoked"]) | set(data["devices"].values()) | {
                record["next_identity_sha256"] for record in data["recoveries"].values()}
            unavailable.add(device_identity(ORIGIN))
            for _ in range(128):
                replacement = secrets.token_hex(32)
                if HEX.fullmatch(replacement) is not None and replacement not in unavailable:
                    break
            else:
                raise RevocationError("Fresh certificate identity could not be generated")
            data["recoveries"][identity] = {"device_id": device_id, "request_id": request_id,
                "expected_revision": expected_revision, "next_identity_sha256": replacement,
                "approved_at": now, "activated_at": None, "actor": actor}
            data["revision"] += 1
            self._save(data)
            return dict(self.projection(data, device_id), applied=True)

    def _activate_enrollment(self, data, device_id, now=None):
        """Caller holds secrets-store and ledger locks after durable fresh mint."""
        identity = self.identity(data, device_id)
        recovery = data["recoveries"].get(identity)
        if recovery is None or recovery["activated_at"] is not None:
            return False
        now = int(time.time()) if now is None else now
        if not _integer(now) or now < recovery["approved_at"] or data["revision"] == MAX_REVISION:
            raise RevocationError("Fresh certificate enrollment cannot be activated")
        data["devices"][device_id] = recovery["next_identity_sha256"]
        recovery["activated_at"] = now
        data["revision"] += 1
        self._save(data)
        return True

    def snapshot(self, ca_sha256, nonce, *, now=None):
        if not isinstance(ca_sha256, str) or HEX.fullmatch(ca_sha256) is None:
            raise ValueError("Invalid peer certificate authority")
        if not isinstance(nonce, str) or NONCE.fullmatch(nonce) is None:
            raise ValueError("Provide a 32-character lowercase hexadecimal nonce")
        now = int(time.time()) if now is None else now
        if not _integer(now, MAX_REVISION - SNAPSHOT_LIFETIME):
            raise ValueError("Invalid snapshot time")
        with self.locked() as data:
            lines = ["IRIS-PEER-REVOCATIONS-1", ca_sha256, str(data["revision"]),
                     str(now), str(now + SNAPSHOT_LIFETIME), *sorted(data["revoked"])]
            return {"schema": 1, "nonce": nonce, "snapshot": "\n".join(lines) + "\n"}


@contextlib.contextmanager
def fresh_enrollment(device_id):
    """Serialize explicit onboarding; never let token refresh approve recovery.

    A legacy plaintext deployment with no ledger remains usable offline. Once
    either authority file exists, unreadable or missing state fails closed.
    Call the yielded function only AFTER the new catalog token is durable and
    the old current/previous token lineage has been removed.
    """
    ledger = Ledger()
    established = False
    for path in (ledger.path, ledger.marker):
        try:
            path.lstat()
            established = True
        except FileNotFoundError:
            pass
        except OSError:
            raise RevocationError("Revocation state is unavailable") from None
    if not established:
        yield lambda: False
        return
    with ledger.locked() as data:
        yield lambda: ledger._activate_enrollment(data, device_id)
