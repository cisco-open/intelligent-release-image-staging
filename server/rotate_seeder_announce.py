#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Seeder-announce rotation core (durable-first, recovery-manifested, byte-safe).

This is the ONLY supported way to rotate the seeder announce credential
(spec §6). The orchestration is:

1. Write a nonsecret recovery manifest FIRST (paths, digests, GIDs, phase — no
   URLs, no tokens).
2. ``rotate_announce`` under the store lock: retire previous records that are
   revoked or past ``secrets_store.SEEDER_PREV_TTL``, keep the current record as
   a *previous* valid for that bounded window, and mint a fresh current. Durable
   persist happens BEFORE any canonical torrent mutation (via ``persist``).
3. Refresh aria2's process-wide Authorization header to the durably persisted
   current credential (the shipped client gives that option precedence over a
   per-download header). For each seeder torrent, prepare a raw-span-verified
   canonical replacement whose outer announce is token-free and whose ``info``
   byte span is SHA-1 identical to the old canonical (via
   torrent_personalize). Every re-add also receives the current credential as a
   per-download header.
4. Serially force-remove then re-add each torrent to the live seeder, updating
   the manifest phase per torrent.

Failure handling (spec §6):
- Remove failure/uncertain result -> restore the EXACT old canonical bytes,
  enter hard no-go, and do not re-add because aria2 may still hold the old
  torrent; explicit repair is required.
- New-add failure -> restore the EXACT old canonical bytes for that torrent and
  every earlier applied torrent, then re-add all old bytes with the current
  credential (rollback).
- If the old-byte re-add ALSO fails -> a hard no-go: restore the EXACT canonical
  bytes for EVERY previously applied torrent too and attempt to re-add each of
  them, abort all remaining torrents, leave maintenance frozen, preserve old
  bytes + manifest, return a hard no-go, and NEVER claim the image remains
  served. Every disturbed torrent is reported explicitly in
  ``RotationResult.affected`` (with ``restore_readd_ok`` per torrent); any
  ``restore_readd_ok=False`` means serving repair is still required there.

The helper never accepts or prints token values (argv/output are nonsecret) and
does NOT revoke any previous credential (revoke is P1). It never accesses the
tracker's in-process registry — the loopback ``/swarm`` verification is an
injectable probe (``deps.swarm_probe(expected_info_hashes, not_before)``) that
must prove a post-rotation typed current service seeder and exact control-state
torrent set.

Compatibility note: ``rotate_announce`` and the additive
``announce_token_previous`` store shape live here for the torrent lane; the
identity lane may relocate ``rotate_announce`` into ``secrets_store``. This
module reuses ``secrets_store.valid`` and record shapes and does not duplicate
token validation.

Stdlib only; the orchestration takes injectable deps so it is fully unit
testable off any live aria2 / tracker."""
import argparse
import base64
import collections
import hashlib
import json
import math
import os
import secrets
import sys
import tempfile
import time

import secretfs
import seeder_auth
import secrets_store
import telemetry
import tracker_announce
import torrent_personalize

SEEDER_PREV_CAP = 2

DEFAULT_SWARM_URL = "https://127.0.0.1:9101/swarm"


def _default_swarm_url():
    """Resolve and validate the same-container authenticated swarm target."""
    return telemetry.validate_local_swarm_url(
        os.environ.get("IRIS_SWARM_URL") or DEFAULT_SWARM_URL)


class RotationError(Exception):
    """Rotation refused (e.g. would evict a still-valid previous credential)."""


TorrentTarget = collections.namedtuple(
    "TorrentTarget", ["image_id", "path", "image_dir", "gid"])

RotationDeps = collections.namedtuple(
    "RotationDeps",
    ["persist", "seeder_remove", "seeder_add", "seeder_set_credential",
     "swarm_probe", "manifest_write", "now"])

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
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_dir(d)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# ---------------------------------------------------------------------------
# rotate_announce (additive store shape; current + bounded previous list)
# ---------------------------------------------------------------------------

def rotate_announce(store, now):
    """Prepend the current seeder announce record into ``announce_token_previous``
    (stamped ``rotated_at``, a fresh nonsecret ``record_id`` and an
    ``expires_at`` of ``now + secrets_store.SEEDER_PREV_TTL``), then mint a
    fresh current ``announce_token``. Returns the new current value.

    Every pass first RETIRES previous records that are revoked or past their
    expiry: the overlap is a bounded recovery window for a device that did not
    receive the new token, not a second permanent credential, and no shipped
    command retires one by hand.

    Refuses (RotationError) any rotation that would leave more than
    ``SEEDER_PREV_CAP`` still-valid previous records — the operator must revoke
    an old previous (P1) first, or wait for it to expire, so a credential a
    device still relies on is never silently dropped."""
    seeder = store.setdefault("seeder", {})
    if not isinstance(seeder, dict):
        raise RotationError("invalid seeder credential state")
    prev = seeder.get("announce_token_previous")
    if "announce_token_previous" not in seeder:
        prev = []
    elif not isinstance(prev, list) or any(
            not isinstance(record, dict) for record in prev):
        # Never turn corrupt overlap state into an empty list and durably
        # persist over credentials an operator may still need for recovery.
        raise RotationError("invalid previous seeder credential state")
    seeder["announce_token_previous"] = prev
    # Retire first, then count: the cap bounds LIVE credentials, so an expired
    # previous never blocks a rotation it has no business blocking.
    secrets_store.retire_expired_previous(store, now)
    prev = seeder["announce_token_previous"]
    valid_prev = [r for r in prev if secrets_store.valid(r, now, 0)]
    if len(valid_prev) >= SEEDER_PREV_CAP:
        raise RotationError(
            "cannot rotate: %d valid previous credentials already exist "
            "(revoke one first)" % len(valid_prev))

    current = seeder.get("announce_token")
    if current is not None and not isinstance(current, dict):
        raise RotationError("invalid current seeder credential state")
    if isinstance(current, dict):
        record = dict(current)
        record["rotated_at"] = int(now)
        record["record_id"] = secrets.token_hex(8)
        record.setdefault("revoked", False)
        # Bounded from here: the retired credential is not a permanent key.
        record["expires_at"] = max(
            1, int(now) + secrets_store.SEEDER_PREV_TTL)
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
    # Kept as a seam for the byte-safe rotation tests; credentials no longer
    # enter torrent metadata or any URL.
    return base


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
    recovery_dir = os.path.join(os.path.dirname(manifest_path) or ".",
                                "seeder-rotation-recovery")
    os.makedirs(recovery_dir, mode=0o700, exist_ok=True)
    torrent_rows = []
    for idx, target in enumerate(torrents):
        with open(target.path, "rb") as f:
            old_bytes = f.read()
        backup_path = os.path.join(recovery_dir, "%04d.torrent" % idx)
        _atomic_write_bytes(backup_path, old_bytes, mode=0o600)
        torrent_rows.append({
            "image_id": target.image_id, "path": os.path.realpath(target.path),
            "image_dir": os.path.realpath(target.image_dir), "gid": target.gid,
            "info_hash": _info_hash(old_bytes),
            "backup_path": backup_path,
            "old_sha256": hashlib.sha256(old_bytes).hexdigest(),
            "status": "pending"})
    manifest = {
        "version": 2,
        "phase": "started",
        "created_at": int(now),
        "maintenance_frozen": True,
        "served_claimed": False,
        "torrents": torrent_rows,
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

    # aria2 gives a process-wide `header` precedence over an addTorrent-local
    # header. seed-launch installs the then-current bearer globally, so merely
    # passing the freshly rotated value to addTorrent would still announce with
    # the retired startup value. Replace the global option after durable secret
    # persistence and before any live/canonical torrent mutation. The JSON-RPC
    # caller is bounded by its transport timeout in production.
    deps.seeder_set_credential(new_current)
    manifest["phase"] = "seeder_credential_updated"
    deps.manifest_write(manifest_path, manifest)

    new_url = _announce_url(tracker_announce_base, new_current)

    # Track torrents whose NEW bytes were successfully applied to the live
    # seeder, so that on a later hard no-go we can restore the EXACT old
    # canonical bytes for ALL of them (spec §6: an already-applied earlier
    # torrent must not be left rotated while a later torrent hard-fails).
    expected_info_hashes = set()
    # (idx, target, old_bytes, live_gid). aria2.addTorrent returns a NEW GID;
    # rollback must remove that live GID, never the pre-rotation target.gid.
    applied = []

    # 3+4. Serial per-torrent: prepare verified replacement, force-remove, add.
    for idx, target in enumerate(torrents):
        with open(target.path, "rb") as f:
            old_bytes = f.read()
        try:
            new_bytes = prepare_replacement(old_bytes, new_url)
            expected_info_hashes.add(_info_hash(old_bytes))
            manifest["torrents"][idx]["new_sha256"] = hashlib.sha256(
                new_bytes).hexdigest()
            deps.manifest_write(manifest_path, manifest)
        except Exception:
            # Preparation failure is treated like a byte-safe abort for this
            # torrent: nothing was removed/added yet, old bytes intact. Any
            # earlier applied torrents must still be restored to old bytes.
            _mark(manifest, idx, "prepare_failed")
            return _hard_no_go(
                manifest, manifest_path, applied, new_current, deps)

        # Write the new canonical to disk atomically (durable) before add.
        _atomic_write_bytes(target.path, new_bytes)
        _mark(manifest, idx, "new_canonical_written")
        deps.manifest_write(manifest_path, manifest)
        try:
            _mark(manifest, idx, "removing_old")
            deps.manifest_write(manifest_path, manifest)
            deps.seeder_remove(target.gid)
            _mark(manifest, idx, "old_removed")
            deps.manifest_write(manifest_path, manifest)
        except Exception:
            # forceRemove may have reached aria2 before its caller observed an
            # error.  The live state is therefore unknown: restore the exact
            # old file, but never add it again and risk a duplicate torrent.
            _atomic_write_bytes(target.path, old_bytes)
            _mark(manifest, idx, "remove_failed")
            manifest["phase"] = "rolling_back"
            deps.manifest_write(manifest_path, manifest)
            return _hard_no_go(
                manifest, manifest_path, applied, new_current, deps,
                also=[(idx, target, old_bytes)], this_readd_failed=True,
                failure_class="remove_failed")
        try:
            _mark(manifest, idx, "adding_new")
            deps.manifest_write(manifest_path, manifest)
            live_gid = deps.seeder_add(new_bytes, target.image_dir,
                                       new_current)
            if not live_gid:
                raise RuntimeError("aria2 add returned no gid")
        except Exception:
            # New-add failure: restore EXACT old bytes and attempt an old-byte
            # add with the current bearer.
            _atomic_write_bytes(target.path, old_bytes)
            _mark(manifest, idx, "rolled_back")
            manifest["phase"] = "rolling_back"
            deps.manifest_write(manifest_path, manifest)
            try:
                # The secret-store rotation is durable and is deliberately not
                # rolled back. Old torrent bytes therefore still need the NEW
                # current bearer when they are restored to aria2.
                restored_gid = deps.seeder_add(old_bytes, target.image_dir,
                                               new_current)
                if not restored_gid:
                    raise RuntimeError("aria2 rollback add returned no gid")
                manifest["torrents"][idx]["restored_gid"] = str(restored_gid)
                deps.manifest_write(manifest_path, manifest)
            except Exception:
                # Double failure: hard no-go. Restore old bytes for ALL
                # previously applied torrents too, attempt to re-add them, abort
                # remaining, freeze maintenance, never claim served.
                _mark(manifest, idx, "double_failure")
                # This torrent's old-byte re-add failed -> record it as
                # affected with repair still required.
                this_failed = [(idx, target, old_bytes)]
                return _hard_no_go(
                    manifest, manifest_path, applied, new_current, deps,
                    also=this_failed, this_readd_failed=True)
            # Rollback succeeded for this torrent, but an earlier torrent may
            # already have new canonical bytes and a new live GID. Restore all
            # of those too before claiming the rotation rolled back cleanly.
            return _hard_no_go(
                manifest, manifest_path, applied, new_current, deps,
                also=[(idx, target, old_bytes)],
                failure_class="new_add_failed",
                permit_clean_rollback=True)

        _mark(manifest, idx, "applied")
        applied.append((idx, target, old_bytes, live_gid))
        manifest["torrents"][idx]["live_gid"] = str(live_gid)
        deps.manifest_write(manifest_path, manifest)

    # Capture the boundary only after every canonical add succeeded: an announce
    # must occur strictly later than this point for every expected info hash.
    probe_not_before = deps.now()

    # Claim serving only after the canonical adds are independently observed.
    # Probe errors and timeouts fail closed exactly like a failed predicate; no
    # credential is revoked and the recovery manifest remains terminal.
    try:
        serving = (callable(deps.swarm_probe)
                    and deps.swarm_probe(expected_info_hashes, probe_not_before))
    except Exception:
        serving = False
    if not serving:
        manifest["phase"] = "swarm_probe_failed"
        manifest["error"] = "swarm_probe_failed"
        manifest["maintenance_frozen"] = True
        manifest["served_claimed"] = False
        deps.manifest_write(manifest_path, manifest)
        return RotationResult(False, True, True, False, new_current)
    manifest["phase"] = "complete"
    manifest["served_claimed"] = True
    deps.manifest_write(manifest_path, manifest)
    return RotationResult(False, False, False, True, new_current)


def _hard_no_go(manifest, manifest_path, applied, new_current, deps,
                also=None, this_readd_failed=False,
                failure_class="double_failure", permit_clean_rollback=False):
    """Enter the hard no-go state: restore EXACT old canonical bytes for every
    previously applied torrent, attempt to re-add each restored torrent, abort
    remaining torrents, freeze maintenance, preserve the manifest, and never
    claim served.

    ``also`` carries the torrent whose own old re-add just failed (already
    restored on disk); it is reported as affected with ``restore_readd_ok`` set
    from ``this_readd_failed`` and its re-add is NOT retried here.

    With ``permit_clean_rollback``, a complete restoration returns an ordinary
    rolled-back result. Otherwise returns a hard-no-go ``RotationResult`` whose
    ``affected`` lists every disturbed torrent and whether its restore re-add
    succeeded — any ``False`` means serving repair is still required."""
    affected = []
    # Restore + re-add each previously applied torrent, newest first is fine;
    # order does not matter for correctness, only that ALL are restored.
    for idx, target, old_bytes, live_gid in applied:
        _atomic_write_bytes(target.path, old_bytes)
        _mark(manifest, idx, "restored")
        readd_ok = True
        try:
            deps.seeder_remove(live_gid)
            # Canonical bytes roll back; the durably persisted credential does
            # not. Re-add with the current bearer, never the retired one.
            restored_gid = deps.seeder_add(old_bytes, target.image_dir,
                                           new_current)
            if not restored_gid:
                raise RuntimeError("aria2 restore add returned no gid")
            manifest["torrents"][idx]["restored_gid"] = str(restored_gid)
            deps.manifest_write(manifest_path, manifest)
        except Exception:
            readd_ok = False
            _mark(manifest, idx, "restore_readd_failed")
        affected.append({"image_id": target.image_id, "gid": target.gid,
                         "restore_readd_ok": readd_ok})

    for idx, target, _old in (also or []):
        affected.append({"image_id": target.image_id, "gid": target.gid,
                         "restore_readd_ok": not this_readd_failed})

    if permit_clean_rollback and affected and all(
            item["restore_readd_ok"] for item in affected):
        manifest["phase"] = "rolled_back"
        manifest["maintenance_frozen"] = False
        manifest["served_claimed"] = False
        manifest["affected"] = affected
        deps.manifest_write(manifest_path, manifest)
        return RotationResult(True, False, False, False, new_current,
                              affected)

    manifest["phase"] = ("hard_no_go" if failure_class == "remove_failed"
                         else "double_failure")
    manifest["error"] = failure_class
    manifest["maintenance_frozen"] = True
    manifest["served_claimed"] = False
    manifest["affected"] = affected
    deps.manifest_write(manifest_path, manifest)
    return RotationResult(True, True, True, False, new_current, affected)


def _mark(manifest, idx, status):
    manifest["torrents"][idx]["status"] = status


def _info_hash(torrent_bytes):
    """Return the canonical SHA-1 info hash from raw torrent bytes."""
    spans = torrent_personalize.scan_top_level(torrent_bytes)
    start, end = spans["info"]
    return hashlib.sha1(torrent_bytes[start:end]).hexdigest()


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _atomic_write_bytes(path, data, mode=None):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".torrent-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
        _fsync_dir(d)
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


# The post-add proof requires every expected info_hash to re-announce AFTER the
# boundary. Clients re-announce on the tracker's interval (peer_registry.
# INTERVAL, 30s), and the earlier torrents announced during their own add --
# before the boundary -- so a short window fails them deterministically even
# though the rotation itself succeeded.
#
# Sized from measurement, not theory: in the lab the three re-announces landed
# 54-63s after the boundary (aria2 does not re-announce immediately on re-add;
# it waits out its own schedule), and server_observation is only rebuilt on the
# sampler tick. 50s was still short. 120s covers two announce intervals plus a
# sampler tick with margin; it only costs wall-clock on a maintenance operation
# that is already under freeze.
_SWARM_RETRIES = 120         # x 1s cadence ~= 120s


def production_deps(seeder_remove, seeder_add, recipients_csv, enc_path,
                    manifest_write=None, now=None, age_bin=None,
                    swarm_sender=None, swarm_sleep=None, swarm_timeout=2.0,
                    swarm_retries=_SWARM_RETRIES,
                    seeder_set_credential=None):
    """Assemble ``RotationDeps`` for the operational path with a durable-first
    persist and the canonical loopback ``/swarm`` probe. Its proof is bound to
    exact info hashes and the post-rotation observation boundary.
    ``swarm_sender`` is an injectable transport seam for tests; it cannot
    bypass the typed predicate enforced by :func:`make_swarm_probe`."""
    import time
    if not callable(seeder_set_credential):
        raise TypeError("seeder credential updater is required")
    def swarm_probe(expected_info_hashes, not_before):
        return make_swarm_probe(
            expected_info_hashes, not_before=not_before, sender=swarm_sender,
            sleep=swarm_sleep, timeout=swarm_timeout,
            retries=swarm_retries)()

    return RotationDeps(
        persist=durable_persist(recipients_csv, enc_path, age_bin=age_bin),
        seeder_remove=seeder_remove,
        seeder_add=seeder_add,
        seeder_set_credential=seeder_set_credential,
        swarm_probe=swarm_probe,
        manifest_write=manifest_write or _atomic_write_json,
        # Keep sub-second precision: rotation verification requires each
        # service-seeder announce to occur strictly after the post-add boundary.
        # Truncating to int would let an earlier announce in the same second pass.
        now=now or time.time)


# ---------------------------------------------------------------------------
# Loopback /swarm live verification (spec §6 step 5)
#
# The helper is a SEPARATE process; it NEVER touches the tracker's in-process
# peer registry. It verifies a current, non-legacy service-seeder observation
# using ONLY the tracker's loopback ``/swarm`` contract (spec §10.3): the
# current, non-legacy seeder is deduped out of the peer rings and represented
# under the canonical ``server`` source. Success requires the ``server`` source
# to prove the relevant canonical torrents are serving (``rpc_up`` true and each
# expected info_hash present in ``server_observation.torrent`` with a
# ``control-state`` lifetime). A seeder that announced on a WRONG/legacy or
# unattributed credential is NOT deduped — it appears as a ``legacy`` (or an
# un-deduped ``service:seeder``) peer row instead, which this predicate rejects.
# A typed DEVICE principal that has completed its download (left == 0, role ==
# seeder) is a legitimate downloader and does NOT disprove the origin seeder, so
# device ring rows are ignored. Token/URL never appear in output.
# ---------------------------------------------------------------------------

def is_seeder_serving(swarm_doc, expected_info_hashes, not_before):
    """True iff the loopback ``/swarm`` document proves the current, non-legacy
    service-seeder is serving EVERY expected canonical torrent after
    ``not_before`` (spec §6/§10.3).

    Proof lives under the canonical ``server`` source (the deduped current
    non-legacy ``service:seeder``): ``server_observation.rpc_up`` must be true
    and each expected info_hash must appear in ``server_observation.torrent``
    with ``lifetime == "control-state"`` and the factual
    ``last_seen_by_info_hash`` must show every expected hash strictly after the
    boundary. A seeder announcing on a wrong/legacy
    or unattributed credential is NOT deduped and instead shows up as a
    ``legacy`` / un-deduped ``service:seeder`` peer row — its presence as a
    seeder for an expected torrent fails the predicate (the current seeder
    identity is not proven). A completed typed DEVICE seeder row (left == 0) is
    a legitimate downloader, not a rival origin claim, and is ignored."""
    if not isinstance(swarm_doc, dict) or not _finite_number(not_before):
        return False
    expected = {h for h in (expected_info_hashes or []) if h}
    if not expected:
        return False
    server = swarm_doc.get("server")
    if not isinstance(server, dict):
        return False
    obs = server.get("server_observation")
    if not isinstance(obs, dict) or obs.get("rpc_up") is not True:
        return False
    serving = set()
    for t in obs.get("torrent") or []:
        if isinstance(t, dict) and t.get("lifetime") == "control-state" \
                and t.get("info_hash"):
            serving.add(t["info_hash"])
    marker = obs.get("tracker_observation")
    if not isinstance(marker, dict) \
            or marker.get("principal_type") != "service" \
            or marker.get("principal_id") != "seeder" \
            or set(marker.get("observed_info_hashes") or []) != expected:
        return False
    last_seen_by_info_hash = marker.get("last_seen_by_info_hash")
    if not isinstance(last_seen_by_info_hash, dict) \
            or set(last_seen_by_info_hash) != expected \
            or any(not _finite_number(last_seen_by_info_hash.get(info_hash))
                    or last_seen_by_info_hash[info_hash] <= not_before
                   for info_hash in expected):
        return False
    if serving != expected:
        return False
    # Reject only a ring seeder row that genuinely conflicts with the canonical
    # dedup of the current non-legacy service seeder: a legacy/unattributed or
    # an un-deduped service:seeder row for an expected torrent means the current
    # seeder identity is not cleanly proven. A typed DEVICE principal that has
    # finished (left == 0, role == seeder) is a legitimate completed downloader
    # — it does NOT disprove the origin service seeder (already proven by the
    # canonical `server` source above), so device ring rows are ignored.
    for image in swarm_doc.get("images") or []:
        if not isinstance(image, dict) or image.get("info_hash") not in expected:
            continue
        for peer in image.get("peers") or []:
            if not isinstance(peer, dict):
                continue
            tracker = peer.get("tracker")
            if not isinstance(tracker, dict):
                continue
            if tracker.get("role") == "seeder" \
                    and tracker.get("principal_type") != "device":
                return False
    return True


def _finite_number(value):
    """Accept JSON numbers used as observation timestamps, never bool/NaN/inf."""
    return (not isinstance(value, bool)
            and isinstance(value, (int, float))
            and math.isfinite(value))


def make_swarm_probe(expected_info_hashes, not_before, url=None,
                     timeout=2.0, retries=3, sender=None, sleep=None):
    """Build a zero-arg ``swarm_probe()`` -> bool for the rotation deps.

    Polls the tracker's loopback ``/swarm`` with a per-attempt ``timeout`` and up
    to ``retries`` attempts, returning True only when :func:`is_seeder_serving`
    confirms the current non-legacy service seeder serves every expected torrent
    with a tracker observation strictly after ``not_before``.
    When ``url`` is None the target is resolved once at construction from
    :func:`_default_swarm_url` (operator ``IRIS_SWARM_URL`` override, else the
    token-free :data:`DEFAULT_SWARM_URL`). Injectable ``sender(url, timeout)
    -> doc`` and ``sleep(seconds)`` seams keep it fully unit-testable off any live
    tracker.

    Fail-closed: any transport error, malformed body, or unproven observation
    returns False. The token/URL is NEVER included in any raised message or
    output (the helper prints nothing here; the caller logs only pass/fail)."""
    url = url if url is not None else _default_swarm_url()
    expected = list(expected_info_hashes or [])
    sender = sender if sender is not None else _http_swarm_sender
    if sleep is None:
        import time as _time
        sleep = _time.sleep
    attempts = max(1, int(retries))

    def probe():
        for attempt in range(attempts):
            try:
                doc = sender(url, timeout)
            except Exception:
                doc = None
            if doc is not None and is_seeder_serving(doc, expected, not_before):
                return True
            if attempt + 1 < attempts:
                sleep(min(timeout, 1.0))
        return False

    return probe


def _http_swarm_sender(url, timeout):
    """Loopback ``/swarm`` GET returning the parsed JSON document. Errors
    propagate to the probe (which fails closed); the URL is never echoed."""
    import tier_auth
    token, _ = tier_auth.load_pair(
        os.environ.get("IRIS_MANAGEMENT_API_TOKEN_FILE", ""))
    return json.loads(telemetry.local_swarm_get(
        url, token.decode("utf-8"), timeout=timeout).decode())


# ---------------------------------------------------------------------------
# CLI (nonsecret only — no token/value argv or output, no revoke option)
# ---------------------------------------------------------------------------

def _tracker_announce_base(env):
    """Return the strict token-free HTTPS announce base without echoing it."""
    return tracker_announce.resolve(env)


def _image_dir(entry, env):
    """Resolve an image directory without guessing a basename collision."""
    filename = entry.get("filename")
    if not isinstance(filename, str) or not filename:
        return None
    if "source_dir" in entry:
        source_dir = entry.get("source_dir")
        # A recorded source_dir is authoritative even when it has gone stale.
        # Falling back by basename could seed unrelated same-named bytes under
        # the canonical torrent's piece hashes (bt-seed-unverified is enabled).
        if not isinstance(source_dir, str) or not os.path.isdir(source_dir):
            return None
        return source_dir if os.path.isfile(os.path.join(source_dir, filename)) else None
    roots = []
    for value in (env.get("IRIS_IMAGES_DIR"), env.get("IMAGES_ROOT"),
                  "/opt/images"):
        roots.extend(p for p in (value or "").split(":") if p)
    for root in roots:
        if not os.path.isdir(root):
            continue
        for parent, _dirs, files in os.walk(root):
            if filename in files:
                return parent
    return None


def discover_targets(state, env, rpc, skipped=None):
    """Discover published canonical torrents and bind each to one active aria GID.

    All reads and RPC preflight occur before the core writes its recovery
    manifest or changes credentials/canonical torrent bytes.

    A quarantined image is not a target: its quarantine force-removed the
    torrent from the seeder on purpose, so it can never be "uniquely active",
    and refusing the whole rotation for it would make two security controls
    mutually exclusive. Its canonical file keeps the rotated-out announce;
    the release path (catalog.release_quarantine -> publish.resume_torrent_rpc)
    re-syncs it to the then-current credential before re-adding it. When
    *skipped* is a list, each skipped image id is appended to it.
    """
    try:
        with open(os.path.join(state, "catalog.json")) as f:
            catalog = json.load(f)
    except Exception:
        raise ValueError("catalog unavailable")
    images = catalog.get("images") if isinstance(catalog, dict) else None
    if not isinstance(images, dict):
        raise ValueError("catalog unavailable")
    if not images:
        raise ValueError("no published torrent targets")
    candidates = []
    for image_id in sorted(images):
        entry = images[image_id]
        if isinstance(entry, dict) and entry.get("quarantined"):
            if skipped is not None:
                skipped.append(str(image_id))
            continue
        torrent = os.path.join(state, "torrents", "%s.torrent" % image_id)
        if not isinstance(entry, dict) or not os.path.isfile(torrent):
            raise ValueError("canonical torrent unavailable")
        image_dir = _image_dir(entry, env)
        if image_dir is None:
            raise ValueError("image directory unavailable")
        try:
            with open(torrent, "rb") as f:
                info_hash = _info_hash(f.read()).lower()
        except Exception:
            raise ValueError("canonical torrent unavailable")
        candidates.append((str(image_id), torrent, image_dir, info_hash))
    if not candidates:
        raise ValueError("no published torrent targets: every published image "
                         "is quarantined")

    try:
        active = rpc("aria2.tellActive", [["gid", "infoHash"]]) or []
    except Exception:
        raise ValueError("aria RPC preflight failed")
    gids = {}
    for item in active:
        if isinstance(item, dict) and item.get("gid") and item.get("infoHash"):
            gids.setdefault(str(item["infoHash"]).lower(), []).append(item["gid"])
    missing = [h for _, _, _, h in candidates if len(gids.get(h, [])) != 1]
    if missing:
        # Inspect non-active states only to make an operator-visible distinction
        # in RPC audit trails; these states are never acceptable for rotation.
        try:
            rpc("aria2.tellWaiting", [0, 1000, ["gid", "infoHash"]])
            rpc("aria2.tellStopped", [0, 1000, ["gid", "infoHash"]])
        except Exception:
            pass
        raise ValueError("canonical torrent is not uniquely active")
    return [TorrentTarget(image_id, path, image_dir, gids[info_hash][0])
            for image_id, path, image_dir, info_hash in candidates]


def _seeder_rpc_ops(rpc):
    def remove(gid):
        rpc("aria2.forceRemove", [gid])
        try:
            rpc("aria2.removeDownloadResult", [gid])
        except Exception:
            pass

    def add(torrent_bytes, image_dir, announce_token):
        header = _announce_authorization_header(announce_token)
        return rpc("aria2.addTorrent", [base64.b64encode(torrent_bytes).decode(),
                                         [], {"dir": image_dir,
                                              "seed-ratio": "0",
                                              "bt-seed-unverified": "true",
                                              "header": [header]}])

    def set_credential(announce_token):
        header = _announce_authorization_header(announce_token)
        result = rpc("aria2.changeGlobalOption", [{"header": [header]}])
        if result != "OK":
            raise RuntimeError("aria2 global credential update failed")
        return result

    return remove, add, set_credential


def _announce_authorization_header(announce_token):
    """Build the same validated header used by seeder startup and publish."""
    return seeder_auth.announce_authorization_header(announce_token)


def _current_announce_token(secrets_path, now=None):
    """Load the current valid seeder bearer for an explicit recovery re-add."""
    try:
        with secrets_store.store_lock(secrets_path):
            store = secrets_store.load(secrets_path)
            record = store.get("seeder", {}).get("announce_token")
            if (not isinstance(record, dict)
                    or not secrets_store.valid(
                        record, time.time() if now is None else now, 0)):
                raise ValueError
            value = record.get("value")
            _announce_authorization_header(value)
            return value
    except Exception:
        # A corrupt store may carry arbitrary content; never include the
        # underlying exception or record value in operator-visible output.
        raise ValueError(
            "current seeder announce credential unavailable") from None


def _contained_path(path, parent):
    path = os.path.realpath(path)
    parent = os.path.realpath(parent)
    try:
        return os.path.commonpath((path, parent)) == parent
    except ValueError:
        return False


def _recovery_image_dirs(rows, state, env):
    """Validate manifest image directories against the current catalog."""
    try:
        with open(os.path.join(state, "catalog.json")) as f:
            catalog = json.load(f)
        images = catalog.get("images") if isinstance(catalog, dict) else None
        if not isinstance(images, dict):
            raise ValueError
    except Exception:
        raise ValueError("invalid recovery manifest image directory")

    image_dirs = []
    for row in rows:
        image_id = row.get("image_id") if isinstance(row, dict) else None
        image_dir = row.get("image_dir") if isinstance(row, dict) else None
        entry = images.get(image_id) if isinstance(image_id, str) and image_id else None
        expected = _image_dir(entry, env) if isinstance(entry, dict) else None
        if (not isinstance(image_dir, str) or not image_dir or expected is None
                or not os.path.isdir(image_dir)
                or os.path.realpath(image_dir) != os.path.realpath(expected)):
            raise ValueError("invalid recovery manifest image directory")
        image_dirs.append(os.path.realpath(expected))
    return image_dirs


def recover_rotation(manifest_path, state, rpc, announce_token):
    """Restore exact pre-rotation torrent bytes and reconcile aria2.

    Evidence is retained and maintenance remains frozen. Invalid/tampered
    manifests are rejected before any filesystem or RPC mutation.
    """
    # Validate the in-memory credential before any filesystem or RPC mutation.
    # Recovery restores canonical bytes, not the pre-rotation secret record, so
    # every re-add must authenticate with the current persisted bearer.
    _announce_authorization_header(announce_token)
    _remove, add, set_credential = _seeder_rpc_ops(rpc)

    with open(manifest_path) as f:
        manifest = json.load(f)
    rows = manifest.get("torrents") if isinstance(manifest, dict) else None
    recovery_dir = os.path.join(os.path.dirname(manifest_path) or ".",
                                "seeder-rotation-recovery")
    torrents_dir = os.path.join(state, "torrents")
    if manifest.get("version") != 2 or not isinstance(rows, list) or not rows:
        raise ValueError("unsupported recovery manifest")
    if manifest.get("phase") in ("complete", "recovered"):
        raise ValueError("recovery manifest is already terminal")

    # Validate every attacker-controlled image_dir against current authoritative
    # catalog data before any canonical write or aria2 call.
    image_dirs = _recovery_image_dirs(rows, state, os.environ)
    validated = []
    for row, image_dir in zip(rows, image_dirs):
        if not isinstance(row, dict):
            raise ValueError("invalid recovery manifest")
        backup = row.get("backup_path")
        canonical = row.get("path")
        digest = row.get("old_sha256")
        info_hash = row.get("info_hash")
        if (not isinstance(backup, str) or not os.path.isabs(backup)
                or not _contained_path(backup, recovery_dir)
                or not isinstance(canonical, str) or not os.path.isabs(canonical)
                or not _contained_path(canonical, torrents_dir)
                or not isinstance(digest, str) or len(digest) != 64
                or not isinstance(info_hash, str) or len(info_hash) != 40):
            raise ValueError("invalid recovery manifest path or digest")
        with open(backup, "rb") as f:
            old_bytes = f.read()
        if (hashlib.sha256(old_bytes).hexdigest() != digest
                or _info_hash(old_bytes).lower() != info_hash.lower()):
            raise ValueError("recovery backup verification failed")
        validated.append((row, canonical, old_bytes, info_hash.lower(), image_dir))

    try:
        # Shipped aria2 prefers the process-wide header over addTorrent's local
        # option. Refresh it before touching a live download; the secret store
        # remains authoritative and recovery never reinstates the retired one.
        set_credential(announce_token)
        checkpoint = os.path.join(state, "identity-compatible-ready")
        if os.path.exists(checkpoint):
            os.remove(checkpoint)
        active = rpc("aria2.tellActive", [["gid", "infoHash"]]) or []
        by_hash = collections.defaultdict(list)
        for item in active:
            if isinstance(item, dict) and item.get("gid") and item.get("infoHash"):
                by_hash[str(item["infoHash"]).lower()].append(str(item["gid"]))
        for row, canonical, old_bytes, info_hash, image_dir in validated:
            _atomic_write_bytes(canonical, old_bytes)
            for gid in by_hash.get(info_hash, []):
                rpc("aria2.forceRemove", [gid])
                try:
                    rpc("aria2.removeDownloadResult", [gid])
                except Exception:
                    pass
            gid = add(old_bytes, image_dir, announce_token)
            if not gid:
                raise RuntimeError("aria2 restore returned no gid")
            status = rpc("aria2.tellStatus", [gid, ["gid", "infoHash"]])
            if (not isinstance(status, dict) or str(status.get("gid")) != str(gid)
                    or str(status.get("infoHash", "")).lower() != info_hash):
                raise RuntimeError("aria2 restore verification failed")
            row["restored_gid"] = str(gid)
            row["status"] = "restored"
            _atomic_write_json(manifest_path, manifest)
    except Exception:
        manifest["phase"] = "repair_needed"
        manifest["maintenance_frozen"] = True
        manifest["served_claimed"] = False
        for row, _canonical, _old_bytes, _info_hash_value, _image_dir_value in validated:
            if row.get("status") != "restored":
                row["status"] = "restore_failed"
        _atomic_write_json(manifest_path, manifest)
        return False

    manifest["phase"] = "recovered"
    manifest["maintenance_frozen"] = True
    manifest["served_claimed"] = False
    _atomic_write_json(manifest_path, manifest)
    return True


def _refusal_reason(exc):
    """Nonsecret text for a preflight refusal: the message of a ValueError or
    RotationError when it is a plain literal, else the exception class name."""
    if isinstance(exc, (ValueError, RotationError)):
        text = str(exc)
        if (text and "://" not in text and "=" not in text
                and "token" not in text.lower()
                and "\n" not in text and len(text) <= 200):
            return "%s: %s" % (exc.__class__.__name__, text)
    return exc.__class__.__name__


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="rotate-seeder-announce",
        description="Rotate the seeder announce credential (durable-first, "
                    "recovery-manifested). The external maintenance freeze and "
                    "loopback tracker /swarm service must already be active. "
                    "Never prints or accepts credential values.")
    ap.add_argument("--state", default=os.environ.get(
        "IRIS_STATE", "/var/lib/iris"),
        help="IRIS state dir (torrents live under <state>/torrents)")
    ap.add_argument("--secrets", default=os.environ.get(
        "IRIS_SECRETS", "/run/iris/secrets.json"))
    ap.add_argument("--manifest", default=None,
                    help="recovery manifest path (default <state>/"
                          "seeder-rotation-recovery.json)")
    ap.add_argument("--maintenance-frozen", action="store_true", required=True,
                    help="acknowledge maintenance is externally frozen; required")
    ap.add_argument("--recover", action="store_true",
                    help="restore exact pre-rotation bytes from the manifest")
    args = ap.parse_args(argv)
    args.state = os.path.abspath(args.state)
    manifest = args.manifest or os.path.join(args.state,
                                              "seeder-rotation-recovery.json")
    manifest = os.path.abspath(manifest)
    # Every condition below is preflight-only. In particular, no manifest is
    # created until the live seeder has been proved to host every target.
    try:
        if args.recover and not os.path.isfile(manifest):
            raise ValueError("recovery manifest unavailable")
        if not args.recover and os.path.exists(manifest):
            raise ValueError("recovery manifest already exists; archive or remove it safely")
        rpc_secret = telemetry._read_rpc_secret(os.environ)
        if not rpc_secret:
            raise ValueError("aria RPC secret unavailable")
        rpc = telemetry.make_jsonrpc_caller(
            os.environ.get("IRIS_RPC", telemetry.DEFAULT_RPC_URL), rpc_secret)
        if args.recover:
            current_token = _current_announce_token(args.secrets)
            recovered = recover_rotation(manifest, args.state, rpc,
                                         current_token)
            if recovered:
                print("rotate-seeder-announce: recovered; maintenance remains frozen; "
                      "manifest preserved", file=sys.stderr)
                return 0
            print("rotate-seeder-announce: repair needed; maintenance remains frozen; "
                  "manifest preserved", file=sys.stderr)
            return 1
        recipients = os.environ.get("IRIS_AGE_RECIPIENTS", "")
        enc_path = os.environ.get("IRIS_SECRETS_ENC", "")
        if not recipients.strip() or not enc_path.strip():
            raise ValueError("durable encrypted secrets configuration unavailable")
        skipped = []
        targets = discover_targets(args.state, os.environ, rpc, skipped=skipped)
        if skipped:
            print("rotate-seeder-announce: skipping %d quarantined image(s) "
                  "(not seeded; re-synced to the current credential on "
                  "release): %s" % (len(skipped), ", ".join(skipped)),
                  file=sys.stderr)
        tracker_base = _tracker_announce_base(os.environ)
        remove, add, set_credential = _seeder_rpc_ops(rpc)
        deps = production_deps(
            remove, add, recipients, enc_path,
            seeder_set_credential=set_credential)
        result = rotate_seeder_announce(args.secrets, manifest, targets,
                                        tracker_base, deps)
    except Exception as exc:
        # RPC and URL exceptions can include request/token material: never
        # echo those. This module's own preflight refusals are fixed literals
        # (ValueError / RotationError with nothing interpolated), and an
        # operator diagnosing a refused maintenance-window operation needs
        # them -- so they are printed, gated by a shape check that falls back
        # to the class name if any URL- or credential-like text slipped in.
        print("rotate-seeder-announce: refused (%s); maintenance remains frozen"
              % _refusal_reason(exc), file=sys.stderr)
        return 2
    if result.served_claimed and not result.hard_no_go:
        _atomic_write_bytes(os.path.join(args.state,
                                         "identity-compatible-ready"),
                            b"ready\n", mode=0o644)
        print("rotate-seeder-announce: complete; maintenance may remain frozen",
              file=sys.stderr)
        return 0
    print("rotate-seeder-announce: not proven; maintenance remains frozen; "
          "recovery manifest preserved at %s" % manifest, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
