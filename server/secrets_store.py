# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Per-device secret store: load/save (atomic), type registry, reverse index,
mint, rotate_catalog, revoke, record_for, valid.

Store schema:
  {
    "devices": {
      "<device_id>": {
        "<secret_name>": {"value", "created_at", "expires_at"(0=never), "revoked"}
      }
    },
    "seeder": {"<secret_name>": {...}}
  }

The seeder is a pseudo-device that holds shared announce secrets for the
seeding server (not bound to any individual device).
"""
import contextlib
import fcntl
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
}

# Maximum number of rotated-out seeder announce records kept valid at once
# (spec §6). rotate_announce refuses any rotation that would evict a still-valid
# previous beyond this cap, so a credential a device still relies on is never
# silently dropped.
SEEDER_PREV_CAP = 2

# ---------------------------------------------------------------------------
# Load / save
# ---------------------------------------------------------------------------

def load(path):
    """Load the store from *path*; return skeleton on missing/corrupt file."""
    try:
        with open(path) as f:
            data = json.load(f)
        # Minimal shape guard
        if not isinstance(data, dict):
            raise ValueError("not a dict")
        data.setdefault("devices", {})
        data.setdefault("seeder", {})
        _prune_previous_on_load(data)
        return data
    except (OSError, ValueError):
        return {"devices": {}, "seeder": {}}


def _prune_previous_on_load(store):
    """Drop revoked seeder announce previous records so the list stays clean.

    Non-revoked previous records are retained regardless of age (they never
    auto-expire; a time-expiring previous could strand an un-migrated device
    mid-overlap — spec §6).
    """
    seeder = store.get("seeder", {})
    prev = seeder.get("announce_token_previous")
    if isinstance(prev, list):
        seeder["announce_token_previous"] = [
            r for r in prev if not r.get("revoked")]


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
    for device_id, secrets_dict in store.get("devices", {}).items():
        for secret_name, record in secrets_dict.items():
            if "value" in record:
                index[record["value"]] = (device_id, secret_name)
    for secret_name, record in store.get("seeder", {}).items():
        if "value" in record:
            index[record["value"]] = ("seeder", secret_name)
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


def _principal():
    # Local import avoids a module-load cycle: auth imports secrets_store.
    import auth
    return auth.Principal


def _strict_set(index, value, entry, principal_type, principal_id):
    if value in index:
        raise DuplicateCredentialError(
            "duplicate credential value owned by %s:%s and %s:%s" % (
                index[value][0].type, index[value][0].id,
                principal_type, principal_id))
    index[value] = entry


def build_announce_index(store):
    """Return {value: (Principal, secret_name, record, legacy_bool)}.

    Covers device ``announce_token`` (legacy=False), the seeder **current**
    ``announce_token`` (service principal, legacy=False), and every seeder
    **previous** record (service principal, secret_name
    ``announce_token_previous``, legacy=True). Returns the live record object so
    validity/revocation are checked at resolution time. Raises
    DuplicateCredentialError (token-free) on any duplicate value ownership.
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
    """Return {value: (Principal, secret_name, record)} for catalog auth.

    Covers ``catalog_token`` and ``catalog_token_prev`` across every device.
    Raises DuplicateCredentialError (token-free) on duplicate value ownership.
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


# ---------------------------------------------------------------------------
# Mint
# ---------------------------------------------------------------------------

def mint(store, device_id, secret_name, now):
    """Mint a new secret for *device_id*/*secret_name* and write it into
    *store* in-place.  Returns the new token value (32 hex chars).

    device_id == "seeder" writes under store["seeder"].
    """
    stype = SECRET_TYPES[secret_name]
    ttl = stype["ttl"]
    value = secrets.token_hex(16)
    inow = int(now)  # coerce: callers may pass time.time() (float); store only holds int epochs
    record = {
        "value":      value,
        "created_at": inow,
        "expires_at": (inow + ttl) if ttl else 0,
        "revoked":    False,
    }
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
        record["revoked"] = True


# ---------------------------------------------------------------------------
# Seeder announce-token overlap (spec §6)
# ---------------------------------------------------------------------------

def rotate_announce(store, now):
    """Rotate the seeder announce token, keeping the old value valid.

    Prepends the current ``seeder.announce_token`` record into
    ``seeder.announce_token_previous`` (newest-first), stamped with
    ``rotated_at`` and a fresh nonsecret ``record_id`` (token_hex(8), 16 hex
    chars), then mints a fresh current announce token. Returns the new value.

    Refuses (raises) any rotation that would evict a still-valid previous
    beyond ``SEEDER_PREV_CAP`` — the operator must revoke an old previous first,
    so a credential a device still relies on is never silently dropped.
    """
    seeder = store.setdefault("seeder", {})
    prev_list = seeder.setdefault("announce_token_previous", [])
    valid_prev = [r for r in prev_list if not r.get("revoked")]
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
        archived["expires_at"] = 0   # non-expiring until explicit revoke
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
