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
        return data
    except (OSError, ValueError):
        return {"devices": {}, "seeder": {}}


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
