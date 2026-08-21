#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Seeder-announce rotation core (durable-first, recovery-manifested, byte-safe).

This is the ONLY supported way to rotate the seeder announce credential
(spec §6). The orchestration is:

1. Write a nonsecret recovery manifest FIRST (paths, digests, GIDs, phase — no
   URLs, no tokens).
2. ``rotate_announce`` under the store lock: keep the current record as a valid
   non-expiring *previous* and mint a fresh current. Durable persist happens
   BEFORE any canonical torrent mutation (via the injected ``persist``).
3. For each seeder torrent, prepare a raw-span-verified canonical replacement
   whose outer announce carries ``announce_token=<current>`` and whose ``info``
   byte span is SHA-1 identical to the old canonical (via torrent_personalize).
4. Serially force-remove then re-add each torrent to the live seeder, updating
   the manifest phase per torrent.

Failure handling (spec §6):
- New-add failure -> restore the EXACT old canonical bytes and attempt the old
  add (rollback).
- If the old re-add ALSO fails -> a hard no-go: restore the EXACT old canonical
  bytes for EVERY previously applied torrent too and attempt to re-add each of
  them, abort all remaining torrents, leave maintenance frozen, preserve old
  bytes + manifest, return a hard no-go, and NEVER claim the image remains
  served. Every disturbed torrent is reported explicitly in
  ``RotationResult.affected`` (with ``restore_readd_ok`` per torrent); any
  ``restore_readd_ok=False`` means serving repair is still required there.

The helper never accepts or prints token values (argv/output are nonsecret) and
does NOT revoke any previous credential (revoke is P1). It never accesses the
tracker's in-process registry — the loopback ``/swarm`` verification is an
INJECTABLE probe (``deps.swarm_probe``); its final typed predicate integration
is deferred to a later task and the deployment path leaves it uncalled until
then.

Compatibility note: ``rotate_announce`` and the additive
``announce_token_previous`` store shape live here for the torrent lane; the
identity lane may relocate ``rotate_announce`` into ``secrets_store``. This
module reuses ``secrets_store.valid`` and record shapes and does not duplicate
token validation.

Stdlib only; the orchestration takes injectable deps so it is fully unit
testable off any live aria2 / tracker."""
import argparse
import collections
import hashlib
import json
import os
import secrets
import sys
import tempfile

import secretfs
import secrets_store
import torrent_personalize

SEEDER_PREV_CAP = 2


class RotationError(Exception):
    """Rotation refused (e.g. would evict a still-valid previous credential)."""


TorrentTarget = collections.namedtuple(
    "TorrentTarget", ["image_id", "path", "image_dir", "gid"])

RotationDeps = collections.namedtuple(
    "RotationDeps",
    ["persist", "seeder_remove", "seeder_add", "swarm_probe",
     "manifest_write", "now"])

RotationResult = collections.namedtuple(
    "RotationResult",
    ["rolled_back", "hard_no_go", "maintenance_frozen", "served_claimed",
     "new_current", "affected"])
# ``affected`` is a (possibly empty) list of per-torrent dicts surfaced on a
# hard no-go so the operator sees EVERY torrent whose live state was disturbed
# and whether its old-bytes restore re-add succeeded, e.g.
#   {"image_id": ..., "gid": ..., "restore_readd_ok": bool}
# A ``restore_readd_ok=False`` entry means serving repair is still required for
# that torrent; the result never claims the image remains served.
RotationResult.__new__.__defaults__ = ((),)


def _atomic_write_json(path, obj):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".manifest-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# ---------------------------------------------------------------------------
# rotate_announce (additive store shape; current + bounded previous list)
# ---------------------------------------------------------------------------

def rotate_announce(store, now):
    """Prepend the current seeder announce record into ``announce_token_previous``
    (stamped ``rotated_at`` + fresh nonsecret ``record_id``), then mint a fresh
    current ``announce_token``. Returns the new current value.

    Refuses (RotationError) any rotation that would leave more than
    ``SEEDER_PREV_CAP`` still-valid previous records — the operator must revoke
    an old previous (P1) first, so a credential a device still relies on is
    never silently dropped."""
    seeder = store.setdefault("seeder", {})
    prev = seeder.get("announce_token_previous")
    if not isinstance(prev, list):
        prev = []
    # Count still-valid (non-revoked) previous records.
    valid_prev = [r for r in prev if not r.get("revoked")]
    if len(valid_prev) >= SEEDER_PREV_CAP:
        raise RotationError(
            "cannot rotate: %d valid previous credentials already exist "
            "(revoke one first)" % len(valid_prev))

    current = seeder.get("announce_token")
    if isinstance(current, dict):
        record = dict(current)
        record["rotated_at"] = int(now)
        record["record_id"] = secrets.token_hex(8)
        prev.insert(0, record)
    seeder["announce_token_previous"] = prev

    new_value = secrets.token_hex(16)
    seeder["announce_token"] = {
        "value": new_value,
        "created_at": int(now),
        "expires_at": 0,   # seeder announce never expires
        "revoked": False,
    }
    return new_value


# ---------------------------------------------------------------------------
# Replacement preparation (raw-span verified)
# ---------------------------------------------------------------------------

def prepare_replacement(canonical_bytes, announce_url):
    """Return raw-span-verified personalized canonical bytes.

    Rewrites only the outer announce to *announce_url* and copies the ``info``
    byte span verbatim; torrent_personalize asserts the raw ``info`` SHA-1 is
    identical (spec §6). Raises ValueError on malformed/ambiguous input."""
    return torrent_personalize.personalize(canonical_bytes, announce_url)


def _announce_url(base, token):
    sep = "&" if "?" in base else "?"
    return "%s%sannounce_token=%s" % (base, sep, token)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def rotate_seeder_announce(secrets_path, manifest_path, torrents,
                           tracker_announce_base, deps):
    """Perform the full durable-first, byte-safe seeder announce rotation.

    Returns a ``RotationResult``. On a double failure it returns
    ``hard_no_go=True, maintenance_frozen=True, served_claimed=False`` and
    leaves the old canonical bytes + recovery manifest in place."""
    now = deps.now()

    # 1. Recovery manifest FIRST — nonsecret only (no URLs, no tokens).
    manifest = {
        "phase": "started",
        "created_at": int(now),
        "torrents": [
            {"image_id": t.image_id,
             "path": t.path,
             "gid": t.gid,
             "old_sha256": _sha256_file(t.path),
             "status": "pending"}
            for t in torrents
        ],
    }
    deps.manifest_write(manifest_path, manifest)

    # 2. rotate_announce under the store lock, then DURABLE persist BEFORE any
    #    canonical mutation.
    with secrets_store.store_lock(secrets_path):
        store = secrets_store.load(secrets_path)
        new_current = rotate_announce(store, now)
        deps.persist(store, secrets_path)
    manifest["phase"] = "secret_rotated"
    deps.manifest_write(manifest_path, manifest)

    new_url = _announce_url(tracker_announce_base, new_current)

    # Track torrents whose NEW bytes were successfully applied to the live
    # seeder, so that on a later hard no-go we can restore the EXACT old
    # canonical bytes for ALL of them (spec §6: an already-applied earlier
    # torrent must not be left rotated while a later torrent hard-fails).
    applied = []  # list of (idx, target, old_bytes)

    # 3+4. Serial per-torrent: prepare verified replacement, force-remove, add.
    for idx, target in enumerate(torrents):
        with open(target.path, "rb") as f:
            old_bytes = f.read()
        try:
            new_bytes = prepare_replacement(old_bytes, new_url)
        except Exception:
            # Preparation failure is treated like a byte-safe abort for this
            # torrent: nothing was removed/added yet, old bytes intact. Any
            # earlier applied torrents must still be restored to old bytes.
            _mark(manifest, idx, "prepare_failed")
            return _hard_no_go(
                manifest, manifest_path, applied, new_current, deps)

        # Write the new canonical to disk atomically (durable) before add.
        _atomic_write_bytes(target.path, new_bytes)
        deps.seeder_remove(target.gid)
        try:
            deps.seeder_add(new_bytes, target.image_dir)
        except Exception:
            # New-add failure: restore EXACT old bytes and attempt old add.
            _atomic_write_bytes(target.path, old_bytes)
            _mark(manifest, idx, "rolled_back")
            manifest["phase"] = "rolling_back"
            deps.manifest_write(manifest_path, manifest)
            try:
                deps.seeder_add(old_bytes, target.image_dir)
            except Exception:
                # Double failure: hard no-go. Restore old bytes for ALL
                # previously applied torrents too, attempt to re-add them, abort
                # remaining, freeze maintenance, never claim served.
                _mark(manifest, idx, "double_failure")
                # This torrent's old re-add failed -> record it as affected with
                # repair still required.
                this_failed = [(idx, target, old_bytes)]
                return _hard_no_go(
                    manifest, manifest_path, applied, new_current, deps,
                    also=this_failed, this_readd_failed=True)
            # Rollback succeeded for this torrent -> stop (rotation not applied).
            manifest["phase"] = "rolled_back"
            deps.manifest_write(manifest_path, manifest)
            return RotationResult(True, False, False, False, new_current)

        _mark(manifest, idx, "applied")
        applied.append((idx, target, old_bytes))
        deps.manifest_write(manifest_path, manifest)

    manifest["phase"] = "complete"
    deps.manifest_write(manifest_path, manifest)
    return RotationResult(False, False, False, True, new_current)


def _hard_no_go(manifest, manifest_path, applied, new_current, deps,
                also=None, this_readd_failed=False):
    """Enter the hard no-go state: restore EXACT old canonical bytes for every
    previously applied torrent, attempt to re-add each restored torrent, abort
    remaining torrents, freeze maintenance, preserve the manifest, and never
    claim served.

    ``also`` carries the torrent whose own old re-add just failed (already
    restored on disk); it is reported as affected with ``restore_readd_ok`` set
    from ``this_readd_failed`` and its re-add is NOT retried here.

    Returns a hard-no-go ``RotationResult`` whose ``affected`` lists every
    disturbed torrent and whether its restore re-add succeeded — any ``False``
    means serving repair is still required for that torrent."""
    affected = []
    # Restore + re-add each previously applied torrent, newest first is fine;
    # order does not matter for correctness, only that ALL are restored.
    for idx, target, old_bytes in applied:
        _atomic_write_bytes(target.path, old_bytes)
        _mark(manifest, idx, "restored")
        readd_ok = True
        try:
            deps.seeder_remove(target.gid)
            deps.seeder_add(old_bytes, target.image_dir)
        except Exception:
            readd_ok = False
            _mark(manifest, idx, "restore_readd_failed")
        affected.append({"image_id": target.image_id, "gid": target.gid,
                         "restore_readd_ok": readd_ok})

    for idx, target, _old in (also or []):
        affected.append({"image_id": target.image_id, "gid": target.gid,
                         "restore_readd_ok": not this_readd_failed})

    manifest["phase"] = "double_failure"
    manifest["maintenance_frozen"] = True
    manifest["served_claimed"] = False
    manifest["affected"] = affected
    deps.manifest_write(manifest_path, manifest)
    return RotationResult(True, True, True, False, new_current, affected)


def _mark(manifest, idx, status):
    manifest["torrents"][idx]["status"] = status


def _sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
    except OSError:
        return ""
    return h.hexdigest()


def _atomic_write_bytes(path, data):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".torrent-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# ---------------------------------------------------------------------------
# Durable-first persist adapter + production deps (F3)
#
# The rotation core persists the rotated secret via the INJECTED ``deps.persist``
# BEFORE any canonical torrent mutation. The operational path MUST route that
# persist through ``secretfs.persist_store`` (durable-encrypted-FIRST): the
# at-rest ``.age`` ciphertext is the only copy that survives a restart, so it is
# written and confirmed before the live tmpfs plaintext is swapped. If the
# durable write fails, ``persist_store`` leaves the live plaintext untouched and
# re-raises, so rotation aborts before touching a single canonical torrent and
# the caller never reports a phantom rotation.
#
# ``durable_persist`` REQUIRES both recipients and an enc path so the production
# wiring cannot silently degrade to a plaintext-only ``secrets_store.save`` — the
# unsafe path is unreachable by construction. Tests may still inject their own
# persist seam via ``RotationDeps`` directly.
# ---------------------------------------------------------------------------

def durable_persist(recipients_csv, enc_path, age_bin=None):
    """Build a durable-first persist callable ``persist(store, plain_path)``.

    Requires non-empty ``recipients_csv`` and ``enc_path`` (raises ValueError
    otherwise) so the operational path can never accidentally build a
    plaintext-only persist. The returned callable delegates to
    ``secretfs.persist_store`` (durable-encrypted-first, with rollback on a live
    swap failure) and is marked ``_durable`` for introspection."""
    if not (recipients_csv and recipients_csv.strip()):
        raise ValueError("durable_persist requires recipients_csv")
    if not (enc_path and enc_path.strip()):
        raise ValueError("durable_persist requires enc_path")
    age_bin = age_bin or secretfs.AGE_BIN

    def persist(store, plain_path):
        secretfs.persist_store(
            store, plain_path, recipients_csv=recipients_csv,
            enc_path=enc_path, age_bin=age_bin)

    persist._durable = True
    return persist


def production_deps(seeder_remove, seeder_add, recipients_csv, enc_path,
                    swarm_probe=None, manifest_write=None, now=None,
                    age_bin=None):
    """Assemble ``RotationDeps`` for the operational path with a durable-first
    persist. The seeder RPC and (deferred) loopback ``/swarm`` probe are still
    injected so the core stays testable; only ``persist`` is fixed to the safe
    durable adapter."""
    import time
    return RotationDeps(
        persist=durable_persist(recipients_csv, enc_path, age_bin=age_bin),
        seeder_remove=seeder_remove,
        seeder_add=seeder_add,
        swarm_probe=swarm_probe if swarm_probe is not None else (lambda: True),
        manifest_write=manifest_write or _atomic_write_json,
        now=now or (lambda: int(time.time())))


# ---------------------------------------------------------------------------
# CLI (nonsecret only — no token/value argv or output, no revoke option)
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="rotate-seeder-announce",
        description="Rotate the seeder announce credential (durable-first, "
                    "recovery-manifested). Operates on the secrets store and "
                    "nonsecret record ids only; never prints or accepts a "
                    "token value, and never revokes a previous credential.")
    ap.add_argument("--state", default=os.environ.get(
        "IRIS_STATE", "/var/lib/iris"),
        help="IRIS state dir (torrents live under <state>/torrents)")
    ap.add_argument("--secrets", default=os.environ.get(
        "IRIS_SECRETS", "/run/iris/secrets.json"))
    ap.add_argument("--manifest", default=None,
                    help="recovery manifest path (default <state>/"
                         "seeder-rotation-recovery.json)")
    ap.parse_args(argv)
    # Live wiring (real aria2 RPC, real loopback /swarm probe, live tracker
    # resolver) is assembled by the deployment path in a later task; the pure
    # core above is the unit under test. When that wiring lands it MUST build
    # its persist via ``production_deps`` / ``durable_persist`` (secretfs
    # durable-first) — the plaintext-only ``secrets_store.save`` path is not a
    # valid operational persist. This CLI intentionally does not perform a live
    # rotation without that wiring, and new ``announce_token=`` canonical
    # torrents are not deployable until the tracker-side resolver integration
    # (deferred) consumes the credential.
    print("rotate-seeder-announce: core helper; live wiring pending deployment "
          "integration", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
