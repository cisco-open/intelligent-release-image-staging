# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Durable per-edge accumulation of origin->peer bytes.

aria2-next 2.5.6 exposes a per-peer CUMULATIVE session counter
(``getPeers`` -> ``uploaded``/``downloaded``), which aria2 1.37 did not have.
It is per CONNECTION and it is ephemeral: ``getPeers`` returns only LIVE
connections, so when a peer disconnects its counter is gone forever. Measured
against the origin's own torrent-wide ``uploadLength`` on a 7-router pull, a
3s sample attributed 73.3% of the bytes actually sent and a 2s sample 88.1%;
the residue is bytes sent to connections that opened and closed between two
samples.

Two consequences shape this module:

  * attribution must be ACCUMULATED as it is observed and persisted here,
    never read at scrape time -- a counter nobody read before the peer hung
    up is a counter that no longer exists;
  * the residue -- the origin's monotonic upload total minus the sum of the
    edges -- is kept and surfaced as its own quantity (:meth:`unattributed`),
    never spread across the peers. Splitting it evenly would be division, not
    measurement, and this codebase does not present arithmetic as observation.

The store lives at ``$IRIS_STATE/peer-ledger.json`` and is written with the
same atomic-replace + ``secrets_store.store_lock`` idiom as
``deployment_receipts``: the telemetry hub, the GUI process and any CLI that
reads it all serialize on one lockfile.
"""
import copy
import json
import os
import tempfile
import time

import secrets_store


# Distinct peers retained per torrent. 512 matches the fleet-scale peer bound
# already used for report peer sets (catalog._STATE_PEER_SET_CAP); a swarm
# wider than that is far past anything IRIS stages. At the cap NEW peers are
# refused rather than evicting an existing one (evicting would silently lower
# an already-published cumulative total), the torrent is flagged
# ``peers_saturated``, and the refused bytes stay visible as unattributed
# residue -- saturation shows up on the dashboards, it is never a quiet drop.
_PEER_CAP = 512
# Connection baselines kept per peer. A peer normally holds one connection;
# the slack absorbs reconnect churn. Eviction is least-recently-seen, which by
# construction is a connection that is no longer live (a live one refreshes
# its baseline on every sample).
_CONN_CAP = 16
# Torrents retained. prune() is the intended bound (see its docstring); this
# cap is the backstop for a caller that never prunes. The least-recently
# observed torrent is evicted and the eviction is counted in stats().
_TORRENT_CAP = 256
# JSON-safe integer ceiling, as in catalog._CONTENT_CAP.
_BYTES_CAP = 2 ** 53
_IP_MAX = 64


def _atomic_write_json(path, obj):
    directory = os.path.dirname(path) or "."
    mode = None
    try:
        mode = os.stat(path).st_mode
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".peer-ledger-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(obj, stream, indent=2, sort_keys=True)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _bytes(value):
    """A byte count from RPC, or None when the value is not one. Booleans are
    rejected explicitly (bool is an int subclass) and negatives are dropped:
    a negative counter is a broken reading, not a correction to apply."""
    if isinstance(value, bool):
        return None
    if isinstance(value, str):
        try:
            value = int(value)
        except ValueError:
            return None
    if not isinstance(value, int):
        if isinstance(value, float) and value == int(value):
            value = int(value)
        else:
            return None
    if value < 0:
        return None
    return min(value, _BYTES_CAP)


class PeerLedger:
    """Lock-protected origin->peer byte ledger persisted beneath ``IRIS_STATE``."""

    def __init__(self, state_dir, now_fn=time.time):
        os.makedirs(state_dir, exist_ok=True)
        self.path = os.path.join(state_dir, "peer-ledger.json")
        self._now = now_fn

    # --- storage -----------------------------------------------------------

    def _read(self):
        try:
            with open(self.path) as stream:
                data = json.load(stream)
        except (OSError, ValueError):
            data = None
        if not isinstance(data, dict):
            return {"torrents": {}, "torrents_evicted": 0}
        torrents = data.get("torrents")
        evicted = data.get("torrents_evicted")
        return {"torrents": torrents if isinstance(torrents, dict) else {},
                "torrents_evicted": evicted if isinstance(evicted, int) else 0}

    @staticmethod
    def _torrent(data, info_hash, image_id):
        rec = data["torrents"].get(info_hash)
        if not isinstance(rec, dict):
            rec = {}
            data["torrents"][info_hash] = rec
        rec.setdefault("image_id", "")
        rec.setdefault("session_id", None)
        rec.setdefault("peers", {})
        rec.setdefault("peers_saturated", False)
        rec.setdefault("peers_saturated_at", None)
        rec.setdefault("first_observed", None)
        rec.setdefault("updated_at", 0)
        origin = rec.get("origin")
        if not isinstance(origin, dict):
            origin = {}
            rec["origin"] = origin
        origin.setdefault("total", 0)
        origin.setdefault("last", None)
        if image_id:
            rec["image_id"] = str(image_id)
        return rec

    def _write(self, data):
        """Persist, evicting the least-recently observed torrents past the cap."""
        torrents = data["torrents"]
        if len(torrents) > _TORRENT_CAP:
            ordered = sorted(torrents.items(),
                             key=lambda item: (item[1].get("updated_at") or 0, item[0]))
            for info_hash, _ in ordered[:len(torrents) - _TORRENT_CAP]:
                del torrents[info_hash]
                data["torrents_evicted"] = int(data.get("torrents_evicted") or 0) + 1
        _atomic_write_json(self.path, data)

    # --- accumulation ------------------------------------------------------

    def observe(self, info_hash, image_id, samples, session_id, now=None,
                upload_length=None):
        """Fold one aria2 sample into the durable per-(info_hash, ip) total.

        *samples* is ``{(ip, port): uploaded_bytes}`` -- the ephemeral
        PER-CONNECTION cumulative counter for every connection alive at this
        instant. Only the DELTA since the previous sample of that connection
        is banked, which makes the durable total correct across reconnects:

          * a connection seen for the first time contributes its whole
            current value (whatever it accumulated before we first saw it);
          * a value that grew contributes the growth;
          * a value that DROPPED means the (ip, port) was reused by a new
            connection whose counter restarted at zero. The previous peak is
            already banked -- every sample of it was added as it happened --
            so the new value is banked in full and accumulation continues
            from there. Neither double-counting the old peak nor losing the
            new connection.

        A *session_id* different from the one this torrent was last observed
        under means aria2 restarted: every connection baseline (and the origin
        gauge baseline) is banked and a new counter epoch starts, so the first
        sample of the new epoch is counted in full rather than diffed against
        a counter that no longer exists.

        When supplied, *upload_length* is folded into the origin total in the
        same locked write, after applying that session transition. This keeps
        the torrent-wide and per-connection baselines in one counter epoch.

        A connection that simply vanishes needs no banking: everything ever
        observed of it is already in the total, and the bytes it carried after
        the last sample are exactly the residue :meth:`unattributed` reports.

        Returns one row per peer that gained bytes, ready for
        ``otlp.build_peer_bytes_record``::

            {"info_hash", "image_id", "ip",
             "peer_sent_bytes", "peer_sent_delta_bytes"}

        Peers whose delta is zero are omitted: the cumulative value on the
        wire has not changed, so re-emitting it would only inflate the log
        stream.
        """
        now = self._now() if now is None else now
        info_hash = str(info_hash)
        rows = []
        with secrets_store.store_lock(self.path):
            data = self._read()
            rec = self._torrent(data, info_hash, image_id)
            if rec["first_observed"] is None:
                rec["first_observed"] = now
            # An UNKNOWN session is not a CHANGED session. poll_seeder_peers
            # passes None when the getSessionInfo probe itself failed; treating
            # that as a restart would bank every baseline and make the next
            # sample re-count each connection in full, inflating totals from a
            # single transient RPC error. Keep the last known epoch instead.
            if session_id is not None:
                if (rec["session_id"] is not None
                        and session_id != rec["session_id"]):
                    self._start_epoch(rec)
                rec["session_id"] = session_id
            self._observe_origin(rec, upload_length)
            peers = rec["peers"]
            for ip, port, value in self._clean(samples):
                peer = peers.get(ip)
                if not isinstance(peer, dict):
                    if len(peers) >= _PEER_CAP:
                        # Refused, not truncated silently: the flag says the
                        # swarm outgrew the store and the bytes remain in the
                        # unattributed residue.
                        if not rec["peers_saturated"]:
                            rec["peers_saturated"] = True
                            rec["peers_saturated_at"] = now
                        continue
                    peer = {"total": 0, "conns": {}, "first_seen": now,
                            "last_seen": now}
                    peers[ip] = peer
                conns = peer.setdefault("conns", {})
                previous = conns.get(port)
                previous = previous.get("last") if isinstance(previous, dict) else None
                if previous is None or value < previous:
                    delta = value             # new connection, or a reused (ip, port)
                else:
                    delta = value - previous
                conns[port] = {"last": value, "seen": now}
                self._cap_conns(conns)
                peer["last_seen"] = now
                peer.setdefault("first_seen", now)
                if delta:
                    peer["total"] = min(int(peer.get("total") or 0) + delta, _BYTES_CAP)
                    rows.append({"info_hash": info_hash,
                                 "image_id": rec["image_id"],
                                 "ip": ip,
                                 "peer_sent_bytes": peer["total"],
                                 "peer_sent_delta_bytes": delta})
            rec["updated_at"] = now
            self._write(data)
        rows.sort(key=lambda row: row["ip"])
        return rows

    @staticmethod
    def _start_epoch(rec):
        """Bank every live counter and drop its baseline: the counters the new
        aria2 session reports share nothing with the old session's."""
        for peer in rec["peers"].values():
            if isinstance(peer, dict):
                peer["conns"] = {}
        rec["origin"]["last"] = None

    @staticmethod
    def _clean(samples):
        """(ip, port-key, bytes) triples from an RPC sample, junk dropped."""
        out = []
        for key, value in (samples or {}).items():
            try:
                ip, port = key
            except (TypeError, ValueError):
                continue
            if not isinstance(ip, str) or not ip or len(ip) > _IP_MAX:
                continue
            total = _bytes(value)
            if total is None:
                continue
            out.append((ip, str(port), total))
        out.sort()
        return out

    @staticmethod
    def _cap_conns(conns):
        if len(conns) <= _CONN_CAP:
            return
        ordered = sorted(conns.items(),
                         key=lambda item: (item[1].get("seen") or 0, item[0]))
        for port, _ in ordered[:len(conns) - _CONN_CAP]:
            del conns[port]

    @staticmethod
    def _observe_origin(rec, upload_length):
        value = _bytes(upload_length)
        origin = rec["origin"]
        if value is not None:
            previous = origin.get("last")
            if previous is None or value < previous:
                delta = value
            else:
                delta = value - previous
            origin["last"] = value
            origin["total"] = min(
                int(origin.get("total") or 0) + delta, _BYTES_CAP)
        return int(origin.get("total") or 0)

    # --- readers -----------------------------------------------------------

    def totals(self, info_hash=None):
        """``{info_hash: {ip: cumulative_bytes}}``, optionally one torrent."""
        out = {}
        for key, rec in self._read()["torrents"].items():
            if info_hash is not None and key != str(info_hash):
                continue
            peers = rec.get("peers") if isinstance(rec, dict) else {}
            out[key] = {ip: int(peer.get("total") or 0)
                        for ip, peer in (peers or {}).items()
                        if isinstance(peer, dict)}
        return copy.deepcopy(out)

    def torrent_totals(self):
        """Per-torrent aggregate, the shape the Prometheus renderer needs.

        ``attributed`` is the sum of the edges, ``origin_total`` the monotonic
        ground truth, ``unattributed`` the honest residue between them, and
        ``peers_attributed`` the count of peers with a nonzero total (peers
        seen but never credited a byte are not swarm participants worth
        charting). ``saturated`` says the peer cap was hit, i.e. some of the
        residue is refused peers rather than missed connections."""
        out = {}
        for info_hash, rec in self._read()["torrents"].items():
            if not isinstance(rec, dict):
                continue
            edges = [int(peer.get("total") or 0)
                     for peer in (rec.get("peers") or {}).values()
                     if isinstance(peer, dict)]
            attributed = sum(edges)
            origin = rec.get("origin") if isinstance(rec.get("origin"), dict) else {}
            origin_total = int(origin.get("total") or 0)
            out[info_hash] = {
                "image_id": rec.get("image_id") or "",
                "attributed": attributed,
                "origin_total": origin_total,
                "unattributed": max(0, origin_total - attributed),
                "peers": len(edges),
                "peers_attributed": sum(1 for total in edges if total > 0),
                "saturated": bool(rec.get("peers_saturated")),
                "updated_at": rec.get("updated_at") or 0,
            }
        return copy.deepcopy(out)

    def unattributed(self, info_hash):
        """Origin total minus the sum of the edges, floored at zero.

        The floor is not cosmetic: the per-edge counters and the torrent-wide
        gauge are separate readings taken at different instants, so a sample
        that catches an edge ahead of the gauge would otherwise print a
        negative residue -- a number that cannot describe bytes."""
        rec = self._read()["torrents"].get(str(info_hash))
        if not isinstance(rec, dict):
            return 0
        origin = rec.get("origin") if isinstance(rec.get("origin"), dict) else {}
        attributed = sum(int(peer.get("total") or 0)
                         for peer in (rec.get("peers") or {}).values()
                         if isinstance(peer, dict))
        return max(0, int(origin.get("total") or 0) - attributed)

    def stats(self):
        """Store occupancy, so the backstop eviction is observable."""
        data = self._read()
        return {"torrents": len(data["torrents"]),
                "torrent_cap": _TORRENT_CAP,
                "peer_cap": _PEER_CAP,
                "torrents_evicted": int(data.get("torrents_evicted") or 0)}

    # --- retention ---------------------------------------------------------

    def prune(self, before_ts):
        """Drop torrents not observed since *before_ts*; return their hashes.

        Retention is whole-torrent, never per-peer: dropping some peers of a
        torrent that is still accumulating would move their bytes into the
        unattributed residue and make the ledger lie about where the load
        went. A torrent is the atomic unit of that arithmetic, so a pruned
        torrent takes its origin total, its edges and its residue with it.

        Callers should prune well behind the retention window their dashboards
        chart: these are cumulative counters, and a pruned torrent that is
        later observed again restarts from zero -- correct for ``rate()``,
        but its earlier history is gone from the store.
        """
        dropped = []
        with secrets_store.store_lock(self.path):
            data = self._read()
            for info_hash, rec in list(data["torrents"].items()):
                updated = rec.get("updated_at") if isinstance(rec, dict) else 0
                if (updated or 0) < before_ts:
                    del data["torrents"][info_hash]
                    dropped.append(info_hash)
            if dropped:
                self._write(data)
        return sorted(dropped)
