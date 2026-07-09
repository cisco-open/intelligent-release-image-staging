# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Swarm state with peer lifecycle. Each peer carries (ip, port, last_seen,
left). `left=0` means a seeder. Peers are pruned when silent for >2*INTERVAL or
on event=stopped. `downloaded` (completed count) is tracked per swarm for scrape."""
import threading
import time

INTERVAL = 30          # client re-announce interval (seconds)
NUMWANT_CAP = 200      # never hand back more than this many peers


class PeerRegistry:
    def __init__(self, interval=INTERVAL, on_event=None):
        self._interval = interval
        # info_hash -> {peer_id: {"ip","port","last_seen","left"}}
        self._swarms = {}
        # info_hash -> int completed-announce count (scrape "downloaded")
        self._downloaded = {}
        # optional telemetry hook: on_event({event, info_hash, peer_id, ip,
        # port, left, ts}) for join/complete/stop/stale. Best-effort — it is
        # called on the announce path, so it must never break the registry.
        self._on_event = on_event
        # Serialises all reads and writes of _swarms and _downloaded.
        # Telemetry callbacks (_emit) are invoked OUTSIDE the lock so that
        # slow or failing I/O in the hook never holds up other threads.
        self._lock = threading.Lock()

    def _emit(self, event, info_hash, peer_id, ip, port, left, now):
        if self._on_event is None:
            return
        try:
            self._on_event({"event": event, "info_hash": info_hash,
                            "peer_id": peer_id, "ip": ip, "port": port,
                            "left": left, "ts": now})
        except Exception:
            pass  # telemetry is observational, never on the critical path

    def announce(self, info_hash, peer_id, ip, port, event=None,
                 left=None, now=None):
        now = time.time() if now is None else now
        # Collect telemetry events to fire AFTER releasing the lock so that
        # slow callbacks never hold up other announcing threads.
        pending = []
        with self._lock:
            swarm = self._swarms.setdefault(info_hash, {})
            if event == "stopped":
                if swarm.pop(peer_id, None) is not None:
                    pending.append(("stop", info_hash, peer_id, ip, port, left, now))
            else:
                prev = swarm.get(peer_id)
                if prev is None:
                    pending.append(("join", info_hash, peer_id, ip, port, left, now))
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
                if event == "completed":
                    self._downloaded[info_hash] = (
                        self._downloaded.get(info_hash, 0) + 1)
                    pending.append(
                        ("complete", info_hash, peer_id, ip, port, left, now))
                    if completed_at is None:
                        completed_at = now
                swarm[peer_id] = {
                    "ip": ip,
                    "port": int(port),
                    "last_seen": now,
                    "left": None if left is None else int(left),
                    "joined_at": joined_at,
                    "completed_at": completed_at,
                }
        for args in pending:
            self._emit(*args)

    def _prune(self, info_hash, swarm, now):
        """Remove stale peers from *swarm* (caller must hold self._lock).
        Returns a list of telemetry event arg-tuples to fire after releasing."""
        cutoff = now - 2 * self._interval
        stale_pids = [p for p, r in swarm.items() if r["last_seen"] < cutoff]
        pending = []
        for pid in stale_pids:
            r = swarm.pop(pid)
            pending.append(
                ("stale", info_hash, pid, r["ip"], r["port"], r["left"], now))
        return pending

    def peers(self, info_hash, peer_id, numwant=50, now=None):
        now = time.time() if now is None else now
        with self._lock:
            swarm = self._swarms.get(info_hash, {})
            pending = self._prune(info_hash, swarm, now)
            limit = min(max(0, numwant), NUMWANT_CAP)
            out = []
            for pid, r in swarm.items():
                if pid == peer_id:
                    continue
                out.append({"ip": r["ip"], "port": r["port"]})
                if len(out) >= limit:
                    break
        for args in pending:
            self._emit(*args)
        return out

    def scrape(self, info_hash, now=None):
        now = time.time() if now is None else now
        with self._lock:
            swarm = self._swarms.get(info_hash, {})
            pending = self._prune(info_hash, swarm, now)
            records = list(swarm.values())
            downloaded = self._downloaded.get(info_hash, 0)
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
            for info_hash in set(self._swarms) | set(self._downloaded):
                swarm = self._swarms.get(info_hash, {})
                pending = self._prune(info_hash, swarm, now)
                all_pending.extend(pending)
                snapshots[info_hash] = (
                    list(swarm.values()),
                    self._downloaded.get(info_hash, 0),
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
            for info_hash in list(self._swarms):
                swarm = self._swarms.get(info_hash, {})
                pending = self._prune(info_hash, swarm, now)
                all_pending.extend(pending)
                raw[info_hash] = list(swarm.values())
        for args in all_pending:
            self._emit(*args)
        out = {}
        for info_hash, records in raw.items():
            peers = [{"ip": r["ip"], "port": r["port"], "left": r["left"],
                      "last_seen": r["last_seen"], "is_seeder": r["left"] == 0,
                      "joined_at": r["joined_at"],
                      "completed_at": r.get("completed_at"),
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
            for info_hash, swarm in list(self._swarms.items()):
                all_pending.extend(self._prune(info_hash, swarm, now))
        for args in all_pending:
            self._emit(*args)
