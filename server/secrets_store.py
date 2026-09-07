# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Per-device secret store: load/save (atomic), type registry, reverse index,
mint, rotate_catalog, revoke, record_for, valid.

Store schema:
  {
    "devices": {
      "<device_id>": {
        "<secret_name>": {"value", "created_at", "expires_at"(0=never),
                          "revoked", ["refresh_expires_at"]}
      }
    },
    "seeder": {"<secret_name>": {...}}
  }

The seeder is a pseudo-device that holds shared announce secrets for the
seeding server (not bound to any individual device).
"""
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import tempfile

# ---------------------------------------------------------------------------
# Secret-type registry
# ---------------------------------------------------------------------------
# Read IRIS_TOKEN_TTL from env at module load; tests can patch the module attr.
_DEFAULT_TTL = int(os.environ.get("IRIS_TOKEN_TTL", "604800"))

SECRET_TYPES = {
    "catalog_token": {
        "scope": "catalog",
        "ttl":   _DEFAULT_TTL,   # 7 days by default
        "auth":  "bearer",
    },
    "announce_token": {
        "scope": "announce",
        "ttl":   0,              # never expires
        "auth":  "announce_key",
    },
    "rpc_secret": {
        "scope": "local",
        "ttl":   0,              # never expires
        "auth":  None,
    },
    "instr_key": {
        "scope": "instructions",
        "ttl": 2592000,
        "auth": None,
        "bits": 256,
    },
}

INSTR_KEY_TTL = 2592000
INSTR_KEY_PREV_TTL = 604800
_SUPPORTED_SECRET_BITS = frozenset((128, 256))
_INSTRUCTION_RECORD_FIELDS = frozenset((
    "value", "key_id", "created_at", "expires_at", "revoked", "_scope",
))
_INSTRUCTION_KEY_ABSENT = object()

# Maximum number of rotated-out seeder announce records kept valid at once
# (spec §6). rotate_announce refuses any rotation that would evict a still-valid
# previous beyond this cap, so a credential a device still relies on is never
# silently dropped.
SEEDER_PREV_CAP = 2

# How long a rotated-out seeder announce token stays usable, measured from the
# rotation that retired it (env IRIS_SEEDER_PREV_TTL; 30 days by default).
#
# A previous record used to be kept non-expiring "until explicit revoke", but no
# shipped command revokes one, so the previous credential of every rotation
# stayed valid forever -- and every device that ever received a torrent carrying
# it still holds it. The overlap exists to recover a device that did not receive
# the new token; it is not a permanent second key. Thirty days is far longer
# than any real rollout window and longer than the catalog-token lifetime a
# device must refresh anyway, and both credentials are valid throughout it, so
# nothing can be locked out inside the window: a device that missed the rotation
# keeps announcing on the old token, and its migration path -- re-fetching a
# personalized torrent from the catalog -- is authorized by its catalog token,
# never by the announce credential being retired.
SEEDER_PREV_TTL = int(os.environ.get("IRIS_SEEDER_PREV_TTL") or 2592000)

# ---------------------------------------------------------------------------
# Load / save
# ---------------------------------------------------------------------------

class StoreCorruptError(ValueError):
    """The store file at *path* exists but could not be read or parsed.

    Raised by load() instead of returning the empty skeleton. An empty store
    and an unreadable one must never look alike: every writer does
    load -> mutate -> persist_store, and persist_store encrypts durable-first,
    so a skeleton returned for a truncated/unreadable tmpfs copy would be
    re-encrypted over the only durable copy of every device and seeder
    credential. The message names the path and the failure class only --
    never file content."""


def load(path):
    """Load the store from *path*.

    A MISSING file is the empty store (first run) and returns the skeleton.
    A present-but-unreadable or unparsable file raises StoreCorruptError so
    that no caller can mistake it for a fresh install: readers fail closed
    and writers never persist the emptiness over the durable ciphertext."""
    try:
        with open(path) as f:
            data = json.load(f)
        # Minimal shape guard
        if not isinstance(data, dict):
            raise ValueError("not a dict")
    except FileNotFoundError:
        return {"devices": {}, "seeder": {}}
    except (OSError, ValueError) as exc:
        raise StoreCorruptError(
            "secrets store %s is unreadable (%s)"
            % (path, exc.__class__.__name__)) from exc
    data.setdefault("devices", {})
    data.setdefault("seeder", {})
    _prune_previous_on_load(data)
    return data


def _prune_previous_on_load(store):
    """Drop revoked seeder announce previous records, and make sure every
    retained one carries an explicit expiry.

    Stamping on load, from a value already in the record, is what makes the
    bound real: an older store's non-expiring previous becomes enforceable at
    the first read, without waiting for a writer, and every reader computes the
    SAME deadline (it is anchored to the record's own rotation stamp, never to
    "now") — so the window cannot roll forward one load at a time. Expired
    records are left in place here and dropped by the next rotation pass, so an
    operator can still see what was retired and when.
    """
    seeder = store.get("seeder", {})
    prev = seeder.get("announce_token_previous")
    if isinstance(prev, list):
        for rec in prev:
            if isinstance(rec, dict):
                _stamp_previous_expiry(rec)
        seeder["announce_token_previous"] = [
            r for r in prev if not r.get("revoked")]


def _stamp_previous_expiry(record):
    """Give a seeder announce previous record an explicit ``expires_at``.

    Anchored to the rotation that retired it (``rotated_at``, falling back to
    ``created_at``), so the deadline is stable across processes and reloads. A
    record carrying neither stamp cannot have a window computed and is therefore
    already expired (anchor 0) rather than honoured indefinitely.
    """
    if record.get("expires_at"):
        return
    anchor = record.get("rotated_at") or record.get("created_at")
    try:
        # Never 0: that is `valid`'s "never expires" sentinel, so a zero anchor
        # with a zero TTL would resurrect exactly what this bound removes.
        record["expires_at"] = max(1, int(anchor) + SEEDER_PREV_TTL)
    except (TypeError, ValueError):
        record["expires_at"] = 1   # no anchor: an epoch long past, never valid


def retire_expired_previous(store, now):
    """Drop seeder announce previous records that are revoked or past expiry.

    Returns the number dropped. Called at the top of every rotation pass: the
    retirement is what bounds the credential, and doing it here keeps
    SEEDER_PREV_CAP counting live credentials rather than dead ones.
    """
    seeder = store.get("seeder", {})
    prev = seeder.get("announce_token_previous")
    if not isinstance(prev, list):
        return 0
    for rec in prev:
        if isinstance(rec, dict):
            _stamp_previous_expiry(rec)
    kept = [r for r in prev if isinstance(r, dict) and valid(r, now, 0)]
    seeder["announce_token_previous"] = kept
    return len(prev) - len(kept)


def save(store, path):
    """Atomically write *store* to *path*.

    Uses a UNIQUE temp file in the same directory (tempfile.mkstemp) + an
    os.replace, so two writers that target the same path never share — and
    truncate/interleave — one fixed `path + '.tmp'`.  The replace is atomic;
    a present *path* is therefore always a complete store.  The target file
    mode is preserved across writes (mkstemp creates 0600 by default).
    """
    d = os.path.dirname(path) or "."
    mode = None
    try:
        mode = os.stat(path).st_mode
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".secrets-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(store, f, indent=2, sort_keys=True)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# ---------------------------------------------------------------------------
# Advisory file lock (serialize read-modify-write of a shared JSON store)
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def store_lock(path):
    """Process-wide advisory lock for the shared JSON store at *path*.

    Holds an exclusive fcntl.flock on a per-store sidecar lockfile
    (`<path>.lock`) for the duration of the `with` block, so every writer that
    wraps its full load->mutate->save cycle in this lock serializes against the
    others — the catalog's threaded token-refresh handlers and the out-of-band
    iris-revoke / iris-mint-enrollment CLIs all coordinate on the same file.

    flock is advisory and per-open-file: it works across threads of one
    process AND across separate processes (the CLIs run via `docker exec` in
    the same container, sharing one filesystem), which a threading.Lock alone
    would not cover.  Stdlib only.
    """
    lock_path = path + ".lock"
    d = os.path.dirname(lock_path) or "."
    os.makedirs(d, exist_ok=True)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


# ---------------------------------------------------------------------------
# Reverse index
# ---------------------------------------------------------------------------

def build_index(store):
    """Return {value: (device_id, secret_name)} for every record in the store.

    The seeder pseudo-device is included with device_id == "seeder".
    """
    index = {}
    devices = store.get("devices", {})
    if not isinstance(devices, dict):
        devices = {}
    for device_id, secrets_dict in devices.items():
        if not isinstance(secrets_dict, dict):
            continue
        for secret_name, record in secrets_dict.items():
            if not isinstance(record, dict) or "value" not in record:
                continue
            value = record["value"]
            try:
                index[value] = (device_id, secret_name)
            except TypeError:
                # This broad inventory is used for mint collision avoidance,
                # never authorization. A malformed unhashable value must not
                # prevent an unrelated credential from being minted.
                continue
    seeder = store.get("seeder", {})
    if not isinstance(seeder, dict):
        seeder = {}
    for secret_name, record in seeder.items():
        if not isinstance(record, dict) or "value" not in record:
            continue
        try:
            index[record["value"]] = ("seeder", secret_name)
        except TypeError:
            continue
    return index


# ---------------------------------------------------------------------------
# Strict collision-detecting authorization indexes (spec §6)
# ---------------------------------------------------------------------------
# These indexes back every AUTHORIZATION decision. Unlike the broad build_index
# (retained for non-authorization callers only), they raise a token-free error
# on duplicate value ownership rather than silently overwriting a dict key — a
# silent overwrite could mis-attribute a principal. No error message ever
# contains a secret value.

class DuplicateCredentialError(Exception):
    """Two records share a credential value (spec §6 hard config error).

    The message is deliberately token-free; the offending value is never
    included so it cannot leak into logs or audit trails.
    """


class CredentialMintError(Exception):
    """A unique credential could not be generated."""


class InstructionKeyError(ValueError):
    """Instruction-key state is unavailable, invalid, or unsafe to mutate."""


def validate_device_id(device_id):
    if device_id == "seeder":
        raise ValueError("device_id 'seeder' is reserved for the seeder service")
    return device_id


def _principal():
    # Local import avoids a module-load cycle: auth imports secrets_store.
    import auth
    return auth.Principal


def _credential_bytes(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        return value.encode("utf-8")
    except UnicodeError:
        return None


def _credential_digest(value_bytes):
    return hashlib.sha256(value_bytes).digest()


def credential_for(index, value):
    """Look up a credential in a strict digest index without scanning records.

    Digest keys have a fixed size and reveal no raw credential prefixes through
    dictionary comparisons. Verify the selected live record's value before
    returning it: even a digest collision or an in-place token replacement must
    not authenticate a different credential. Expiry and revocation remain the
    caller's responsibility, including catalog refresh's bounded recovery rule.
    """
    candidate = _credential_bytes(value)
    if candidate is None:
        return None
    entry = index.get(_credential_digest(candidate))
    if entry is None:
        return None
    expected = _credential_bytes(entry[2].get("value"))
    if expected is None or not hmac.compare_digest(candidate, expected):
        return None
    return entry


def _strict_set(index, value, entry, principal_type, principal_id):
    candidate = _credential_bytes(value)
    if candidate is None:
        return
    digest = _credential_digest(candidate)
    if digest in index:
        raise DuplicateCredentialError(
            "duplicate credential digest owned by %s:%s and %s:%s" % (
                index[digest][0].type, index[digest][0].id,
                principal_type, principal_id))
    index[digest] = entry


def build_announce_index(store):
    """Return {SHA-256 digest: (Principal, secret_name, record, legacy_bool)}.

    Covers device ``announce_token`` (legacy=False), the seeder **current**
    ``announce_token`` (service principal, legacy=False), and every seeder
    **previous** record (service principal, secret_name
    ``announce_token_previous``, legacy=True). Returns the live record object so
    validity/revocation are checked at resolution time. Raises
    DuplicateCredentialError (token-free) on duplicate value or digest ownership.
    Malformed or empty credential values are not indexed.
    """
    Principal = _principal()
    index = {}
    for device_id, secrets_dict in store.get("devices", {}).items():
        rec = secrets_dict.get("announce_token")
        if rec and "value" in rec:
            p = Principal("device", device_id)
            _strict_set(index, rec["value"], (p, "announce_token", rec, False),
                        "device", device_id)
    seeder = store.get("seeder", {})
    cur = seeder.get("announce_token")
    if cur and "value" in cur:
        p = Principal("service", "seeder")
        _strict_set(index, cur["value"],
                    (p, "announce_token", cur, False), "service", "seeder")
    for rec in seeder.get("announce_token_previous", []) or []:
        if "value" in rec:
            p = Principal("service", "seeder")
            _strict_set(index, rec["value"],
                        (p, "announce_token_previous", rec, True),
                        "service", "seeder")
    return index


def build_catalog_auth_index(store):
    """Return {SHA-256 digest: (Principal, secret_name, record)} for catalog auth.

    Covers ``catalog_token`` and ``catalog_token_prev`` across every device.
    A previous record may also carry ``refresh_expires_at``: its original
    pre-rotation expiry, used only by catalog.py's token-refresh recovery.
    Raises DuplicateCredentialError (token-free) on duplicate value or digest
    ownership. Malformed or empty credential values are not indexed.
    """
    Principal = _principal()
    index = {}
    for device_id, secrets_dict in store.get("devices", {}).items():
        for secret_name in ("catalog_token", "catalog_token_prev"):
            rec = secrets_dict.get(secret_name)
            if rec and "value" in rec:
                p = Principal("device", device_id)
                _strict_set(index, rec["value"], (p, secret_name, rec),
                            "device", device_id)
    return index


def device_announce_value(store, device_id, now, grace):
    """Return *device_id*'s current, valid ``announce_token`` value, or None.

    Used by the catalog to personalize a device's torrent with its OWN announce
    credential (spec §6). A device with no minted announce credential, or one
    that is expired/revoked, returns None so the caller can fail CLOSED — a
    device is never silently fallen back to the shared seeder token. Validity
    is checked against the live record via ``valid``.
    """
    rec = store.get("devices", {}).get(device_id, {}).get("announce_token")
    if not isinstance(rec, dict):
        return None
    if not valid(rec, now, grace):
        return None
    return rec.get("value")


def _canonical_hex(value, length):
    return (isinstance(value, str) and len(value) == length
            and value == value.lower()
            and all(char in "0123456789abcdef" for char in value))


def validate_instruction_key_record(record, previous=False):
    """Return a valid closed instruction record or raise a fixed error.

    Current records retain the exact 30-day mint lifetime. Archived previous
    records keep their original creation time but receive a seven-day deadline
    from rotation, so they require only strictly ordered timestamps.
    """
    error = InstructionKeyError("invalid instruction key record")
    if not isinstance(record, dict) or set(record) != _INSTRUCTION_RECORD_FIELDS:
        raise error
    value = record.get("value")
    key_id = record.get("key_id")
    created_at = record.get("created_at")
    expires_at = record.get("expires_at")
    if not _canonical_hex(value, 64) or not _canonical_hex(key_id, 64):
        raise error
    try:
        expected_id = hashlib.sha256(bytes.fromhex(value)).hexdigest()
    except ValueError:
        raise error
    if not hmac.compare_digest(key_id, expected_id):
        raise error
    if type(created_at) is not int or created_at < 0:
        raise error
    if type(expires_at) is not int or expires_at <= created_at:
        raise error
    if not previous and expires_at != created_at + INSTR_KEY_TTL:
        raise error
    if type(record.get("revoked")) is not bool:
        raise error
    if record.get("_scope") != "instructions":
        raise error
    return record


def validate_instruction_key_pair(current, previous=_INSTRUCTION_KEY_ABSENT):
    """Return one valid current and its distinct, optional previous record."""
    current = validate_instruction_key_record(current)
    if previous is _INSTRUCTION_KEY_ABSENT:
        return current, None
    previous = validate_instruction_key_record(previous, previous=True)
    if (hmac.compare_digest(current["key_id"], previous["key_id"])
            or hmac.compare_digest(current["value"], previous["value"])):
        raise InstructionKeyError("invalid instruction key relationship")
    return current, previous


def instruction_key_projection(record, now=None, previous=False):
    """Return the closed wire object for an eligible instruction record.

    Current expiry is deliberately ignored: it schedules rotation but never
    makes the current decryption key disappear. Previous expiry is a strict
    server-side overlap bound and equality is expired.
    """
    record = validate_instruction_key_record(record, previous=previous)
    if record["revoked"]:
        return None
    if previous and (type(now) not in (int, float)
                     or now >= record["expires_at"]):
        return None
    return {"value": record["value"], "key_id": record["key_id"]}


# ---------------------------------------------------------------------------
# Mint
# ---------------------------------------------------------------------------

def mint(store, device_id, secret_name, now):
    """Mint a new secret for *device_id*/*secret_name* and write it into
    *store* in-place. Returns its hexadecimal value.

    device_id == "seeder" writes under store["seeder"].
    """
    stype = SECRET_TYPES[secret_name]
    bits = stype.get("bits", 128)
    if type(bits) is not int or bits not in _SUPPORTED_SECRET_BITS \
            or bits % 8:
        raise CredentialMintError("unsupported secret bit count")
    ttl = stype["ttl"]
    existing = set(build_index(store))
    existing_ids = set()
    devices = store.get("devices", {})
    if isinstance(devices, dict):
        for records in devices.values():
            if not isinstance(records, dict):
                continue
            for record in records.values():
                if isinstance(record, dict) \
                        and isinstance(record.get("key_id"), str):
                    existing_ids.add(record["key_id"])
    for rec in store.get("seeder", {}).get(
            "announce_token_previous", []) or []:
        if isinstance(rec, dict) and rec.get("value"):
            try:
                existing.add(rec["value"])
            except TypeError:
                pass
    for _attempt in range(128):
        value = secrets.token_hex(bits // 8)
        try:
            unique_value = value not in existing
        except TypeError:
            unique_value = False
        if not unique_value:
            continue
        key_id = None
        if secret_name == "instr_key":
            if not _canonical_hex(value, 64):
                raise CredentialMintError("credential generator returned invalid data")
            key_id = hashlib.sha256(bytes.fromhex(value)).hexdigest()
            if key_id in existing_ids:
                continue
        break
    else:
        raise CredentialMintError("unable to mint unique credential")
    inow = int(now)  # coerce: callers may pass time.time() (float); store only holds int epochs
    record = {
        "value":      value,
        "created_at": inow,
        "expires_at": (inow + ttl) if ttl else 0,
        "revoked":    False,
    }
    if secret_name == "instr_key":
        record["key_id"] = key_id
        record["_scope"] = "instructions"
    if device_id == "seeder":
        store["seeder"][secret_name] = record
    else:
        store["devices"].setdefault(device_id, {})[secret_name] = record
    return value


# ---------------------------------------------------------------------------
# record_for / valid
# ---------------------------------------------------------------------------

def record_for(index, store, value):
    """Look up *value* in the reverse *index*.

    Returns (device_id, secret_name, record) or None if not found.
    The record dict is the live object inside *store*.
    """
    entry = index.get(value)
    if entry is None:
        return None
    device_id, secret_name = entry
    if device_id == "seeder":
        record = store["seeder"].get(secret_name)
    else:
        record = store["devices"].get(device_id, {}).get(secret_name)
    if record is None:
        return None
    return (device_id, secret_name, record)


def valid(record, now, grace):
    """Return True iff the record is not revoked AND (never expires OR
    now < expires_at + grace).  Strict less-than: at-boundary is invalid.
    """
    if record.get("revoked"):
        return False
    expires_at = record.get("expires_at", 0)
    if expires_at == 0:
        return True
    return now < expires_at + grace


# ---------------------------------------------------------------------------
# Instruction-key rotation
# ---------------------------------------------------------------------------

def rotate_instruction_key(store, device_id, now, no_overlap=False):
    """Rotate one existing device instruction key in-place.

    The caller owns persistence and must hold ``store_lock`` around a fresh
    load, this mutation, and ``secretfs.persist_store``. The returned key ID is
    nonsecret and is the only material passed to the later stamper handoff.
    """
    devices = store.get("devices")
    if not isinstance(device_id, str) or not device_id or device_id == "seeder":
        raise InstructionKeyError("invalid instruction key device")
    if not isinstance(devices, dict) or device_id not in devices:
        raise InstructionKeyError("instruction key device not found")
    records = devices[device_id]
    if not isinstance(records, dict):
        raise InstructionKeyError("invalid instruction key state")
    if any(isinstance(record, dict) and record.get("revoked")
           for record in records.values()):
        raise InstructionKeyError("instruction key rotation refused: device revoked")
    if "instr_key" not in records:
        raise InstructionKeyError("instruction key is missing")
    if "instr_key_prev" in records:
        current, previous = validate_instruction_key_pair(
            records["instr_key"], records["instr_key_prev"])
        if previous["revoked"]:
            raise InstructionKeyError(
                "instruction key rotation refused: device revoked")
    else:
        current, previous = validate_instruction_key_pair(
            records["instr_key"])

    try:
        inow = int(now)
    except (TypeError, ValueError, OverflowError):
        raise InstructionKeyError("invalid instruction key rotation time")
    if inow < 0:
        raise InstructionKeyError("invalid instruction key rotation time")
    if not no_overlap and previous is not None \
            and inow < previous["expires_at"]:
        raise InstructionKeyError("previous instruction key overlap is active")
    if not no_overlap and inow + INSTR_KEY_PREV_TTL <= current["created_at"]:
        raise InstructionKeyError("invalid instruction key rotation time")

    archived = dict(current)
    archived["expires_at"] = inow + INSTR_KEY_PREV_TTL
    records.pop("instr_key_prev", None)
    mint(store, device_id, "instr_key", inow)
    if not no_overlap:
        records["instr_key_prev"] = archived
    return records["instr_key"]["key_id"]


# ---------------------------------------------------------------------------
# rotate_catalog
# ---------------------------------------------------------------------------

def rotate_catalog(store, device_id, now, overlap):
    """Rotate the catalog token for *device_id*.

    Sets the OLD catalog_token's expires_at = now + overlap, then mints a
    fresh catalog_token (overwrites the live record).  Returns the new value.

    The old record is mutated in-place BEFORE mint overwrites the store slot,
    so any reference the caller holds before calling this function will see
    the updated expires_at.
    """
    device_secrets = store["devices"].get(device_id, {})
    old_record = device_secrets.get("catalog_token")
    if old_record is not None:
        old_record["expires_at"] = int(now) + overlap  # coerce: now may be float
    new_value = mint(store, device_id, "catalog_token", now)
    return new_value


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------

def revoke(store, device_id):
    """Set revoked=True on every record belonging to *device_id*.

    No-op for unknown devices; never touches the seeder or other devices.
    """
    device_secrets = store["devices"].get(device_id)
    if device_secrets is None:
        return
    for record in device_secrets.values():
        if isinstance(record, dict):
            record["revoked"] = True


# ---------------------------------------------------------------------------
# Retirement / revocation view (spec §7 retirement)
# ---------------------------------------------------------------------------

def revoked_device_principals(store):
    """Return the set of ``"device:<id>"`` keys whose credentials are all
    revoked (spec §7 retirement).

    A device is treated as **retired/revoked** only when it owns at least one
    secret record AND **every** owned record is durably ``revoked`` (the state
    ``revoke`` sets). This is deliberately based on the durable revoke flag, not
    on transient catalog-token expiry: a device with an expired-but-not-revoked
    ``catalog_token`` whose ``announce_token`` is still valid is **not** retired
    (not all records are revoked), so ordinary token expiry never derives a
    deny. Only the seeder pseudo-device is skipped — it is a service principal,
    never a retirable device. The returned keys feed the tracker reconciler's
    ``revoked_principals`` view, where a matching principal is derived-denied
    regardless of policy assignment.
    """
    keys = set()
    devices = store.get("devices", {})
    if not isinstance(devices, dict):
        return keys
    for device_id, records in devices.items():
        if not isinstance(records, dict) or not records:
            continue
        if all(isinstance(rec, dict) and rec.get("revoked")
               for rec in records.values()):
            keys.add("device:%s" % device_id)
    return keys


# ---------------------------------------------------------------------------
# Seeder announce-token overlap (spec §6)
# ---------------------------------------------------------------------------

def rotate_announce(store, now):
    """Rotate the seeder announce token, keeping the old value valid.

    Prepends the current ``seeder.announce_token`` record into
    ``seeder.announce_token_previous`` (newest-first), stamped with
    ``rotated_at``, a fresh nonsecret ``record_id`` (token_hex(8), 16 hex
    chars) and an ``expires_at`` of ``now + SEEDER_PREV_TTL``, then mints a
    fresh current announce token. Returns the new value.

    Every pass first RETIRES previous records that are revoked or past their
    expiry, so the overlap is a bounded recovery window rather than a permanent
    second key: nothing here needs an operator to remember a manual revoke.

    Refuses (raises) any rotation that would evict a still-valid previous
    beyond ``SEEDER_PREV_CAP`` — the operator must revoke an old previous first
    (or wait for it to expire), so a credential a device still relies on is
    never silently dropped.
    """
    seeder = store.setdefault("seeder", {})
    seeder.setdefault("announce_token_previous", [])
    retire_expired_previous(store, now)
    prev_list = seeder["announce_token_previous"]
    valid_prev = [r for r in prev_list if valid(r, now, 0)]
    if len(valid_prev) >= SEEDER_PREV_CAP:
        raise ValueError(
            "rotate_announce refused: %d valid previous records already at "
            "SEEDER_PREV_CAP=%d; revoke one first" % (
                len(valid_prev), SEEDER_PREV_CAP))
    current = seeder.get("announce_token")
    if current is not None and "value" in current:
        archived = dict(current)
        archived["rotated_at"] = int(now)
        archived["record_id"] = secrets.token_hex(8)
        archived.setdefault("revoked", False)
        # The recovery overlap is bounded from HERE, not open-ended: the
        # current token is minted non-expiring, its retired predecessor is not.
        archived["expires_at"] = max(1, int(now) + SEEDER_PREV_TTL)
        prev_list.insert(0, archived)
    return mint(store, "seeder", "announce_token", now)


def revoke_announce_value(store, value):
    """Set revoked=True on the seeder announce record matching *value*.

    Matches the current record or any previous record by value; leaves all
    others intact. Library support only — no Day-1 operation calls this.
    """
    seeder = store.get("seeder", {})
    current = seeder.get("announce_token")
    if current is not None and current.get("value") == value:
        current["revoked"] = True
        return
    for rec in seeder.get("announce_token_previous", []) or []:
        if rec.get("value") == value:
            rec["revoked"] = True
            return


def revoke_announce_record(store, record_id):
    """Set revoked=True on the seeder previous record whose ``record_id`` matches.

    Targets a specific previous without ever handling its secret value (P1 uses
    this form). Library support only — no Day-1 operation calls this.
    """
    seeder = store.get("seeder", {})
    for rec in seeder.get("announce_token_previous", []) or []:
        if rec.get("record_id") == record_id:
            rec["revoked"] = True
            return
