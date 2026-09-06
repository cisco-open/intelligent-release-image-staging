# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Swarm state with peer lifecycle. Each peer carries (ip, port, last_seen,
left). `left=0` means a seeder. Peers are pruned when silent for >2*INTERVAL or
on event=stopped. `downloaded` (completed count) is tracked per swarm for scrape.

Identity (spec §0a/§6). Each peer is keyed by its typed principal AND peer_id:
the registry identity key is ``(principal.type, principal.id, peer_id)``. A
device literally named ``seeder`` (``device:seeder``) is therefore distinct from
the service seeder (``service:seeder``), and two principals that happen to share
a peer_id are isolated. Callers that pass no principal (the current tracker path,
pending typed integration) default to a single ``legacy:''`` principal, so their
behaviour is unchanged (same peer_id still collides/replaces as before).
"""
import secrets
import threading
import time

import auth

INTERVAL = 30          # client re-announce interval (seconds)
NUMWANT_CAP = 200      # never hand back more than this many peers
# Completion counts are operational telemetry, not durable accounting. Keeping
# them for one day after the swarm disappears preserves useful scrape history
# while bounding attacker-created inactive keys.
DOWNLOADED_TTL = 24 * 60 * 60
# Even inside the TTL, cap inactive/active completion records. Ten thousand is
# far above a realistic IRIS catalog while keeping memory deterministic.
MAX_DOWNLOADED_SWARMS = 10000

# Default principal for principal-less (bare) announce callers. Using a single
# constant legacy principal preserves the pre-typed behaviour where two
# announces sharing a peer_id map to one registry slot.
_DEFAULT_PRINCIPAL = auth.Principal("legacy", "")

# Map principal type -> participant class surfaced in snapshots/events.
_PARTICIPANT_CLASS = {
    "device": "device",
    "service": "seeder",
    "legacy": "legacy_unattributed",
}


def _participant_class(principal):
    return _PARTICIPANT_CLASS.get(principal.type, "legacy_unattributed")


def _public_principal_id(principal):
    """The public principal_id. The legacy id is only an internal dedupe key and
    MAY be omitted from public output (spec §0a); we omit an empty legacy id and
    surface a nonsecret endpoint-derived one when present."""
    if principal.type == "legacy" and not principal.id:
        return None
    return principal.id


class PeerRegistry:
    def __init__(self, interval=INTERVAL, on_event=None,
                 read_prune_interval=INTERVAL, randbelow=None):
        self._interval = interval
        self._read_prune_interval = max(0, read_prune_interval)
        self._randbelow = randbelow or secrets.randbelow
        # info_hash -> {peer_id: {"ip","port","last_seen","left"}}
        self._swarms = {}
        # Selection indexes are updated with the swarm under the same lock.
        # The insertion-order vector permits an O(1) random start; removals
        # leave tombstones which are compacted amortized rather than shifting a
        # fleet-sized list on every stop or expiry.
        self._orders = {}
        self._positions = {}
        self._principal_keys = {}
        self._ip_keys = {}
        self._type_orders = {}
        self._type_positions = {}
        self._type_tombstones = {}
        self._tombstones = {}
        # Per-swarm role vectors are bound to one immutable CompiledRoles
        # generation. A policy change rebuilds once; ordinary reannounces keep
        # the current vectors hot and additions/removals update them in place.
        self._role_indexes = {}
        self._role_index_builds = 0
        # info_hash -> {count, last_seen}; expired once no swarm remains.
        self._downloaded = {}
        # Session-cumulative transfer baselines are per torrent and typed
        # principal, independent of the peer_id used by a particular session.
        self._transfer_counters = {}
        self._last_read_prune = None
        # optional telemetry hook: on_event({event, info_hash, peer_id, ip,
        # port, left, ts}) for join/complete/stop/stale. Best-effort — it is
        # called on the announce path, so it must never break the registry.
        self._on_event = on_event
        # Serialises all reads and writes of _swarms and _downloaded.
        # Telemetry callbacks (_emit) are invoked OUTSIDE the lock so that
        # slow or failing I/O in the hook never holds up other threads.
        self._lock = threading.Lock()

    def _emit(self, event, info_hash, peer_id, ip, port, left, now,
              principal=_DEFAULT_PRINCIPAL):
        if self._on_event is None:
            return
        try:
            self._on_event({"event": event, "info_hash": info_hash,
                            "peer_id": peer_id, "ip": ip, "port": port,
                            "left": left, "ts": now,
                            "principal_type": principal.type,
                            "principal_id": _public_principal_id(principal),
                            "participant_class": _participant_class(principal),
                            # Random in-process lifecycle id (spec §5/§10.8):
                            # kept only in this queue — NOT a durable audit id.
                            "event_id": secrets.token_hex(16)})
        except Exception:
            pass  # telemetry is observational, never on the critical path

    def _index_add(self, info_hash, key, row):
        order = self._orders.setdefault(info_hash, [])
        positions = self._positions.setdefault(info_hash, {})
        positions[key] = len(order)
        order.append(key)
        principal_key = (row["principal"].type, row["principal"].id)
        self._principal_keys.setdefault(info_hash, {}).setdefault(
            principal_key, {})[key] = None
        self._ip_keys.setdefault(info_hash, {}).setdefault(
            row["ip"], {})[key] = None
        principal_type = row["principal"].type
        type_order = self._type_orders.setdefault(info_hash, {}).setdefault(
            principal_type, [])
        self._type_positions.setdefault(info_hash, {}).setdefault(
            principal_type, {})[key] = len(type_order)
        type_order.append(key)
        self._role_index_add(info_hash, key, row)

    def _index_remove(self, info_hash, key, row):
        position = self._positions.get(info_hash, {}).pop(key, None)
        if position is not None:
            self._orders[info_hash][position] = None
            self._tombstones[info_hash] = self._tombstones.get(info_hash, 0) + 1
        principal_key = (row["principal"].type, row["principal"].id)
        for index, value in ((self._principal_keys, principal_key),
                             (self._ip_keys, row["ip"])):
            members = index.get(info_hash, {}).get(value)
            if members is not None:
                members.pop(key, None)
                if not members:
                    index[info_hash].pop(value, None)
        principal_type = row["principal"].type
        type_positions = self._type_positions.get(info_hash, {}).get(
            principal_type, {})
        type_offset = type_positions.pop(key, None)
        if type_offset is not None:
            self._type_orders[info_hash][principal_type][type_offset] = None
            tombstones = self._type_tombstones.setdefault(
                info_hash, {})
            tombstones[principal_type] = tombstones.get(principal_type, 0) + 1
        self._role_index_remove(info_hash, key)

    def _compact_order(self, info_hash, force=False):
        order = self._orders.get(info_hash, [])
        tombstones = self._tombstones.get(info_hash, 0)
        if not tombstones or (not force and
                              tombstones < max(32, len(order) // 2)):
            return
        compact = [key for key in order if key is not None]
        self._orders[info_hash] = compact
        self._positions[info_hash] = {
            key: index for index, key in enumerate(compact)}
        self._tombstones[info_hash] = 0

    def _role_index_add(self, info_hash, key, row):
        role_index = self._role_indexes.get(info_hash)
        principal = row["principal"]
        if role_index is None or principal.type != "device":
            return
        role = role_index["compiled"].role_of.get(principal.id)
        if role is None:
            return
        order = role_index["orders"].setdefault(role, [])
        role_index["positions"][key] = (role, len(order))
        order.append(key)

    def _role_index_remove(self, info_hash, key):
        role_index = self._role_indexes.get(info_hash)
        if role_index is None:
            return
        position = role_index["positions"].pop(key, None)
        if position is None:
            return
        role, offset = position
        role_index["orders"][role][offset] = None
        role_index["tombstones"][role] = \
            role_index["tombstones"].get(role, 0) + 1

    def _role_index(self, info_hash, compiled):
        cached = self._role_indexes.get(info_hash)
        if cached is not None and cached["compiled"] is compiled:
            return cached
        cached = {"compiled": compiled, "orders": {}, "positions": {},
                  "tombstones": {}}
        swarm = self._swarms.get(info_hash, {})
        for key in self._orders.get(info_hash, ()):
            if key is None:
                continue
            row = swarm.get(key)
            if row is None or row["principal"].type != "device":
                continue
            role = compiled.role_of.get(row["principal"].id)
            if role is None:
                continue
            order = cached["orders"].setdefault(role, [])
            cached["positions"][key] = (role, len(order))
            order.append(key)
        self._role_indexes[info_hash] = cached
        self._role_index_builds += 1
        return cached

    @staticmethod
    def _compact_role(role_index, role):
        order = role_index["orders"].get(role, [])
        tombstones = role_index["tombstones"].get(role, 0)
        if not tombstones or tombstones < max(32, len(order) // 2):
            return order
        compact = [key for key in order if key is not None]
        role_index["orders"][role] = compact
        for offset, key in enumerate(compact):
            role_index["positions"][key] = (role, offset)
        role_index["tombstones"][role] = 0
        return compact

    def _compact_type(self, info_hash, principal_type):
        order = self._type_orders.get(info_hash, {}).get(principal_type, [])
        tombstones = self._type_tombstones.get(info_hash, {}).get(
            principal_type, 0)
        if not tombstones or tombstones < max(32, len(order) // 2):
            return order
        compact = [key for key in order if key is not None]
        self._type_orders[info_hash][principal_type] = compact
        self._type_positions[info_hash][principal_type] = {
            key: offset for offset, key in enumerate(compact)}
        self._type_tombstones[info_hash][principal_type] = 0
        return compact

    def _remove_record(self, info_hash, swarm, key):
        row = swarm.pop(key, None)
        if row is None:
            return None
        self._index_remove(info_hash, key, row)
        counter_key = (info_hash, row["principal"].type,
                       row["principal"].id)
        baseline = self._transfer_counters.get(counter_key)
        if baseline is not None and baseline["peer_id"] == row["peer_id"]:
            self._transfer_counters.pop(counter_key, None)
        return row

    def _counter_delta(self, info_hash, principal, peer_id, event,
                       uploaded, downloaded, now):
        counter_key = (info_hash, principal.type, principal.id)
        previous = self._transfer_counters.get(counter_key)
        supplied = uploaded is not None or downloaded is not None
        reset = bool(previous is not None and (
            event == "started" or previous["peer_id"] != peer_id or
            (uploaded is not None and previous["uploaded"] is not None and
             uploaded < previous["uploaded"]) or
            (downloaded is not None and previous["downloaded"] is not None and
             downloaded < previous["downloaded"])))
        if previous is None or reset:
            uploaded_delta = 0
            downloaded_delta = 0
            current_uploaded = uploaded
            current_downloaded = downloaded
        else:
            uploaded_delta = (uploaded - previous["uploaded"]
                              if uploaded is not None and
                              previous["uploaded"] is not None else 0)
            downloaded_delta = (downloaded - previous["downloaded"]
                                if downloaded is not None and
                                previous["downloaded"] is not None else 0)
            current_uploaded = (previous["uploaded"] if uploaded is None
                                else uploaded)
            current_downloaded = (previous["downloaded"] if downloaded is None
                                  else downloaded)
        if supplied or previous is not None:
            self._transfer_counters[counter_key] = {
                "peer_id": peer_id,
                "uploaded": current_uploaded,
                "downloaded": current_downloaded,
                "last_seen": now,
            }
        return uploaded_delta, downloaded_delta, reset

    def announce(self, info_hash, peer_id, ip, port, event=None,
                 left=None, now=None, principal=None, interval=None,
                 uploaded=None, downloaded=None, legacy_restricted=False):
        now = time.time() if now is None else now
        principal = _DEFAULT_PRINCIPAL if principal is None else principal
        key = (principal.type, principal.id, peer_id)
        # Collect telemetry events to fire AFTER releasing the lock so that
        # slow callbacks never hold up other announcing threads.
        pending = []
        with self._lock:
            swarm = self._swarms.setdefault(info_hash, {})
            if event == "stopped":
                if self._remove_record(info_hash, swarm, key) is not None:
                    pending.append(("stop", info_hash, peer_id, ip, port, left,
                                    now, principal))
                if not swarm:
                    self._cleanup_empty(info_hash, swarm, now)
            else:
                prev = swarm.get(key)
                if prev is None:
                    pending.append(("join", info_hash, peer_id, ip, port, left,
                                    now, principal))
                # joined_at / completed_at track this peer's CURRENT download cycle:
                #   * joined_at = when this cycle started (first announce, or the
                #     moment `left` transitions from 0 back up to >0 — a re-download).
                #   * completed_at = when `left` first hits 0 in this cycle. Locked
                #     until the cycle resets so the displayed time stays stable while
                #     the peer keeps seeding.
                # (completed_at - joined_at) is the wall-clock torrent download time,
                # excluding any post-download copy/verify on the device.
                joined_at = prev["joined_at"] if prev is not None else now
                completed_at = prev.get("completed_at") if prev is not None else None
                # cycle reset: the peer had FINISHED a cycle (completed_at is stamped)
                # and now reports more bytes to download — a fresh cycle (user deleted
                # the file, agent self-healed and started re-downloading). Key off
                # completed_at, NOT the last `left`: a finished peer that re-announces
                # while OMITTING `left` is stored as left=None, and `None == 0` is
                # False, so a `prev["left"] == 0` guard would miss the reset and report
                # the prior cycle's stale time for the new download. Stamp a new
                # joined_at, clear completed_at so the next zero-transition locks this
                # cycle's time.
                if prev is not None and completed_at is not None \
                        and left is not None and left > 0:
                    joined_at = now
                    completed_at = None
                if completed_at is None and left == 0:
                    completed_at = now
                uploaded_delta, downloaded_delta, counter_reset = \
                    self._counter_delta(info_hash, principal, peer_id, event,
                                        uploaded, downloaded, now)
                if event == "completed":
                    completed = self._downloaded.get(
                        info_hash, {"count": 0, "last_seen": now})
                    self._downloaded[info_hash] = {
                        "count": completed["count"] + 1, "last_seen": now}
                    if len(self._downloaded) > MAX_DOWNLOADED_SWARMS:
                        oldest = min(self._downloaded,
                                     key=lambda k: self._downloaded[k]["last_seen"])
                        if oldest != info_hash or len(self._downloaded) > 1:
                            self._downloaded.pop(oldest, None)
                    pending.append(
                        ("complete", info_hash, peer_id, ip, port, left, now,
                         principal))
                    if completed_at is None:
                        completed_at = now
                row = {
                    "ip": ip,
                    "port": int(port),
                    "last_seen": now,
                    "left": None if left is None else int(left),
                    "joined_at": joined_at,
                    "completed_at": completed_at,
                    "peer_id": peer_id,
                    "principal": principal,
                    "interval": self._interval if interval is None else interval,
                    "uploaded_delta": uploaded_delta,
                    "downloaded_delta": downloaded_delta,
                    "counter_reset": counter_reset,
                    "legacy_restricted": bool(legacy_restricted),
                }
                if prev is not None and (prev["ip"] != ip or
                                         prev["principal"] != principal):
                    self._index_remove(info_hash, key, prev)
                    self._index_add(info_hash, key, row)
                elif prev is None:
                    self._index_add(info_hash, key, row)
                swarm[key] = row
        for args in pending:
            self._emit(*args)

    def _prune(self, info_hash, swarm, now):
        """Remove stale peers from *swarm* (caller must hold self._lock).
        Returns a list of telemetry event arg-tuples to fire after releasing."""
        stale_keys = [
            key for key, row in swarm.items()
            if row["last_seen"] < now - 2 * row.get("interval", self._interval)]
        pending = []
        for k in stale_keys:
            r = self._remove_record(info_hash, swarm, k)
            pending.append(
                ("stale", info_hash, r["peer_id"], r["ip"], r["port"],
                 r["left"], now, r["principal"]))
        return pending

    def _cleanup_empty(self, info_hash, swarm, now):
        """Drop empty swarm state and completion history after its grace TTL."""
        if swarm:
            return
        self._swarms.pop(info_hash, None)
        self._orders.pop(info_hash, None)
        self._positions.pop(info_hash, None)
        self._principal_keys.pop(info_hash, None)
        self._ip_keys.pop(info_hash, None)
        self._type_orders.pop(info_hash, None)
        self._type_positions.pop(info_hash, None)
        self._type_tombstones.pop(info_hash, None)
        self._tombstones.pop(info_hash, None)
        self._role_indexes.pop(info_hash, None)
        completed = self._downloaded.get(info_hash)
        if completed and completed["last_seen"] < now - DOWNLOADED_TTL:
            self._downloaded.pop(info_hash, None)

    def _read_prune_locked(self, now, force=False):
        last = self._last_read_prune
        due = (force or last is None or now < last or
               self._read_prune_interval == 0 or
               now - last >= self._read_prune_interval)
        if not due:
            return []
        self._last_read_prune = now
        pending = []
        for info_hash, swarm in list(self._swarms.items()):
            pending.extend(self._prune(info_hash, swarm, now))
            self._cleanup_empty(info_hash, swarm, now)
        for info_hash in list(self._downloaded):
            if info_hash not in self._swarms:
                self._cleanup_empty(info_hash, {}, now)
        return pending

    @staticmethod
    def _peer_result(row):
        return {"ip": row["ip"], "port": row["port"]}

    def _candidate_sources(self, info_hash, candidate_principals=None,
                           candidate_ips=None, candidate_roles=None,
                           candidate_types=None, compiled_roles=None):
        if candidate_principals is None and candidate_ips is None \
                and candidate_roles is None and candidate_types is None:
            self._compact_order(info_hash)
            order = self._orders.get(info_hash, [])
            return [order] if order else []
        sources = []
        if candidate_roles is not None:
            role_index = self._role_index(info_hash, compiled_roles)
            for role in sorted(candidate_roles):
                order = self._compact_role(role_index, role)
                if order:
                    sources.append(order)
        principal_index = self._principal_keys.get(info_hash, {})
        for principal_key in candidate_principals or ():
            keys = principal_index.get(principal_key)
            if keys:
                sources.append(keys)
        ip_index = self._ip_keys.get(info_hash, {})
        for ip in candidate_ips or ():
            keys = ip_index.get(ip)
            if keys:
                sources.append(keys)
        for principal_type in candidate_types or ():
            order = self._compact_type(info_hash, principal_type)
            if order:
                sources.append(order)
        return sources

    def _select_locked(self, info_hash, peer_id, requester_principal,
                       requester_ip, predicate, numwant,
                       candidate_principals=None, candidate_ips=None,
                       candidate_roles=None, candidate_types=None,
                       compiled_roles=None,
                       bare_peer_id=False):
        limit = min(max(0, numwant), NUMWANT_CAP)
        if limit == 0:
            return []
        swarm = self._swarms.get(info_hash, {})
        sources = self._candidate_sources(
            info_hash, candidate_principals, candidate_ips,
            candidate_roles, candidate_types, compiled_roles)
        if not sources:
            return []
        req = (_DEFAULT_PRINCIPAL if requester_principal is None
               else requester_principal)
        self_key = (req.type, req.id, peer_id)
        source_lengths = [len(source) for source in sources]
        total_slots = sum(source_lengths)
        start = self._randbelow(total_slots)
        inspect_limit = min(4 * limit, len(swarm))
        inspected = 0
        out = []
        seen = set()
        first_source = start % len(sources)
        for source_offset in range(len(sources)):
            source = sources[(first_source + source_offset) % len(sources)]
            keys = tuple(source) if isinstance(source, dict) else source
            source_start = start % len(keys)
            for offset in range(len(keys)):
                if inspected >= inspect_limit or len(out) >= limit:
                    break
                key = keys[(source_start + offset) % len(keys)]
                if key is None or key in seen:
                    continue
                seen.add(key)
                row = swarm.get(key)
                if row is None:
                    continue
                if (bare_peer_id and row["peer_id"] == peer_id) or \
                        (not bare_peer_id and key == self_key):
                    continue
                inspected += 1
                if predicate is not None and not predicate(
                        requester_principal, requester_ip,
                        row["principal"], row["ip"]):
                    continue
                out.append(self._peer_result(row))
            if inspected >= inspect_limit or len(out) >= limit:
                break
        return out

    def peers(self, info_hash, peer_id, numwant=50, now=None):
        now = time.time() if now is None else now
        with self._lock:
            pending = self._read_prune_locked(now)
            out = self._select_locked(
                info_hash, peer_id, None, None, None, numwant,
                bare_peer_id=True)
        for args in pending:
            self._emit(*args)
        return out

    def select_peers(self, info_hash, peer_id, requester_principal,
                     requester_ip, predicate=None, numwant=50, now=None,
                     candidate_principals=None, candidate_ips=None,
                     candidate_roles=None, candidate_types=None,
                     compiled_roles=None):
        """Return candidate peers for a requester, filtered by *predicate*.

        The predicate — when given — receives BOTH complete identities on each
        side: ``predicate(requester_principal, requester_ip, candidate_principal,
        candidate_ip)`` and returns True to permit the candidate. This is the
        mutual-ACL seam (spec §7); the tracker HTTP integration and the concrete
        policy live in a later task. With no predicate, every other peer is
        returned (implicit permit-all discovery).
        """
        now = time.time() if now is None else now
        # Exclude the requester's OWN record by its FULL identity key
        # (principal.type, principal.id, peer_id), not by bare peer_id: a
        # different typed principal that happens to reuse this peer_id is a
        # distinct peer and must stay discoverable (spec §0a/§6).
        with self._lock:
            pending = self._read_prune_locked(now)
            out = self._select_locked(
                info_hash, peer_id, requester_principal, requester_ip,
                predicate, numwant, candidate_principals, candidate_ips,
                candidate_roles, candidate_types, compiled_roles)
        for args in pending:
            self._emit(*args)
        return out

    def has_principal_type(self, info_hash, principal_type):
        """O(1) hint used to avoid durable legacy scans for typed-only swarms."""
        with self._lock:
            return bool(self._type_positions.get(info_hash, {}).get(
                principal_type))

    def scrape(self, info_hash, now=None):
        now = time.time() if now is None else now
        with self._lock:
            pending = self._read_prune_locked(now)
            swarm = self._swarms.get(info_hash, {})
            records = list(swarm.values())
            downloaded = self._downloaded.get(info_hash, {}).get("count", 0)
        for args in pending:
            self._emit(*args)
        complete = sum(1 for r in records if r["left"] == 0)
        return {
            "complete": complete,
            "incomplete": len(records) - complete,
            "downloaded": downloaded,
        }

    def stats(self, now=None):
        """Per-info_hash aggregate snapshot for the /metrics endpoint:
        {info_hash: {seeders, leechers, peers, bytes_remaining, completed}}.
        All reads are taken under the lock; telemetry callbacks fire after."""
        now = time.time() if now is None else now
        all_pending = []
        snapshots = {}
        with self._lock:
            all_pending.extend(self._read_prune_locked(now))
            for info_hash in set(self._swarms) | set(self._downloaded):
                swarm = self._swarms.get(info_hash, {})
                if info_hash not in self._swarms and info_hash not in self._downloaded:
                    continue
                snapshots[info_hash] = (
                    list(swarm.values()),
                    self._downloaded.get(info_hash, {}).get("count", 0),
                )
        for args in all_pending:
            self._emit(*args)
        out = {}
        for info_hash, (records, downloaded) in snapshots.items():
            peers = len(records)
            seeders = sum(1 for r in records if r["left"] == 0)
            remaining = sum(r["left"] for r in records
                            if r["left"] and r["left"] > 0)
            out[info_hash] = {
                "seeders": seeders,
                "leechers": peers - seeders,
                "peers": peers,
                "bytes_remaining": remaining,
                "completed": downloaded,
            }
        return out

    def snapshot(self, now=None):
        """Per-peer detail per info_hash for the live swarm map:
        {info_hash: [{ip, port, left, last_seen, is_seeder}, ...]}.
        Empty (or fully pruned) swarms are omitted. All reads taken under
        the lock; telemetry callbacks fire after."""
        now = time.time() if now is None else now
        all_pending = []
        raw = {}
        with self._lock:
            all_pending.extend(self._read_prune_locked(now))
            for info_hash in list(self._swarms):
                swarm = self._swarms.get(info_hash, {})
                raw[info_hash] = list(swarm.values())
        for args in all_pending:
            self._emit(*args)
        out = {}
        for info_hash, records in raw.items():
            peers = [{"ip": r["ip"], "port": r["port"], "left": r["left"],
                      "last_seen": r["last_seen"], "is_seeder": r["left"] == 0,
                      "joined_at": r["joined_at"],
                      "completed_at": r.get("completed_at"),
                      "principal_type": r["principal"].type,
                      "principal_id": _public_principal_id(r["principal"]),
                      "participant_class": _participant_class(r["principal"]),
                      "peer_id": r["peer_id"],
                      "interval": r.get("interval", self._interval),
                      "uploaded_delta": r.get("uploaded_delta", 0),
                      "downloaded_delta": r.get("downloaded_delta", 0),
                      "counter_reset": r.get("counter_reset", False),
                      "legacy_restricted": r.get("legacy_restricted", False),
                      "download_seconds": (
                          (r["completed_at"] - r["joined_at"])
                          if r.get("completed_at") is not None else None)}
                     for r in records]
            if peers:
                out[info_hash] = peers
        return out

    def prune_all(self, now=None):
        now = time.time() if now is None else now
        all_pending = []
        with self._lock:
            all_pending.extend(self._read_prune_locked(now, force=True))
        for args in all_pending:
            self._emit(*args)
