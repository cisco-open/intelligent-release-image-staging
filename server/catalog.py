#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""IRIS catalog: HTTPS JSON API + torrent serving. State is JSON files
under the state dir, written atomically and re-read per request. Bearer-token
auth on every endpoint. The server publishes images and each device's
staging approval (the ordered set of images it may STAGE) but NEVER triggers
install (spec §6). main() refuses to start over plain HTTP unless
IRIS_CATALOG_ALLOW_PLAINTEXT=1 opts in explicitly -- every route answers
device bearer tokens. Stdlib only."""
import gzip
import hashlib
import io
import json
import math
import ipaddress
import os
import re
import secrets
import ssl
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlsplit

import audit
import auth
import bounded_pool
import bulkhash
import credential_cache
import keyed_state
import live_samples
import secretfs
import secrets_store
import tracker_announce
import torrent_personalize
import transfer_lifecycle
import api_problem
import api_routes

# A device may hold an ordered set of approved images at once (issue: multi-
# image assignment); this bounds the set so policy.json rows and the console
# stay a fixed, glanceable size rather than an unbounded list.
MAX_ASSIGNED_IMAGES = 10

# Cisco Bulk Hash reconciliation (KGV reconciler): the only three
# provenances apply_hash_verification() accepts, matching the pipeline call
# sites later tasks wire in -- a periodic scheduler, an operator-triggered
# manual recheck, and an offline/air-gapped import. An unrecognised source
# is refused rather than silently accepted, so a typo in a caller can never
# masquerade as a real provenance in the audit trail.
HASH_VERIFICATION_SOURCES = ("scheduled", "manual", "offline")


def _audit_id(value):
    """Derive a short, non-secret correlation id from a token value.

    The audit log lives on the unencrypted /etc/iris volume, so it must never
    carry any portion of a live token: value[:8] would leak 32 bits of the
    secret.  A truncated sha256 is correlatable across events but reveals
    nothing about the underlying token."""
    if not value:
        return ""
    return hashlib.sha256(value.encode()).hexdigest()[:8]


def _resolve_refresh_auth(store, index, token, now, grace):
    """Resolve a token for the same-device refresh route.

    Current credentials use ordinary catalog auth. A previous credential may
    recover after its shared-route overlap only until its original expiry, and
    only while the current successor remains valid. Keeping this exception out
    of the canonical resolver makes it impossible for another route to enable
    recovery accidentally.
    """
    ctx = auth.resolve_catalog_auth(store, index, token, now, grace)
    if token is None:
        return None
    if ctx is not None and ctx.secret_name != "catalog_token_prev":
        return ctx
    entry = index.get(token)
    if entry is None:
        return None
    principal, secret_name, record = entry
    if secret_name != "catalog_token_prev" or record.get("revoked"):
        return None
    deadline = record.get("refresh_expires_at")
    try:
        # Old persisted records lack a recovery deadline. They remain usable
        # here only during their ordinary overlap (ctx is non-None), which is
        # enough for a rolling deployment without granting an indefinite retry.
        if deadline is None and ctx is None:
            return None
        if deadline is not None and deadline != 0 \
                and not now < deadline + grace:
            return None
    except TypeError:
        return None
    current = store.get("devices", {}).get(
        principal.id, {}).get("catalog_token")
    if not isinstance(current, dict) or not secrets_store.valid(
            current, now, grace):
        return None
    return auth.AuthContext(principal, secret_name, "catalog")


def _atomic_write_json(path, obj):
    """Atomically write *obj* as JSON to *path* via a UNIQUE temp file in the
    same directory + os.replace, so concurrent writers never share — and
    truncate/interleave — one fixed `path + '.tmp'`.  The target file mode is
    preserved across rewrites."""
    d = os.path.dirname(path) or "."
    mode = None
    try:
        mode = os.stat(path).st_mode
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".state-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            # allow_nan=False: a NaN/Infinity that slipped past ingest would
            # otherwise be written as a bare token no browser JSON parser
            # accepts, poisoning every reader of the file. Fail loudly here.
            json.dump(obj, f, indent=2, sort_keys=True, allow_nan=False)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# Global POST body cap (also applied to gzip-DECOMPRESSED bodies — bomb guard).
MAX_BODY_BYTES = 65536

# Per-connection socket inactivity timeout for the HTTP handler (seconds). A
# client that stalls mid-request -- a partial request line, or a declared
# Content-Length it never finishes sending -- would otherwise pin its handler
# thread, file descriptor and stack for the life of the server, before any
# authentication. Overridable with IRIS_HTTP_TIMEOUT; non-positive/garbage
# falls back to the default rather than disabling the guard.
HANDLER_TIMEOUT = 30.0


def handler_timeout(env=None):
    raw = (os.environ if env is None else env).get("IRIS_HTTP_TIMEOUT")
    try:
        value = float(raw) if raw else HANDLER_TIMEOUT
    except (TypeError, ValueError):
        return HANDLER_TIMEOUT
    return value if value > 0 else HANDLER_TIMEOUT


# Bound on how long a TLS handshake may occupy its worker thread.
_HANDSHAKE_TIMEOUT = 30

# Opt-in to serve the catalog over plain HTTP when no certificate is
# available. Same name pattern as gui_server's IRIS_GUI_ALLOW_PLAINTEXT, so
# an operator learns one convention for every listener. Only main() consults
# this -- make_server() itself still accepts certfile=None unconditionally,
# which the test suite relies on to run a plain-HTTP server without opting
# in globally.
_PLAINTEXT_OPT_IN_ENV = "IRIS_CATALOG_ALLOW_PLAINTEXT"


def _plaintext_allowed():
    return os.environ.get(_PLAINTEXT_OPT_IN_ENV, "") == "1"


class _CatalogServer(bounded_pool.BoundedThreadingMixin, ThreadingHTTPServer):
    """ThreadingHTTPServer with a fleet-sized accept backlog that completes
    the TLS handshake in the WORKER thread, and a bounded pool of
    concurrently running handler threads.

    Three stdlib defaults are wrong for a device-facing listener:

    * ``request_queue_size`` is 5. Every device in the fleet contacts this
      server on the same heartbeat cadence, so a rollout burst overflows the
      accept queue and the kernel answers with RSTs; agents see a connection
      reset rather than a slow answer.
    * Wrapping the LISTENING socket makes socketserver run the whole
      handshake inside accept() on the single serve_forever thread, so one
      client that connects and never sends a ClientHello stalls every other
      device. Here accept() hands back the plain socket and the wrap happens
      per connection, bounded by _HANDSHAKE_TIMEOUT.
    * ``ThreadingMixIn.process_request`` spawns one thread per connection
      with no cap -- see bounded_pool.py for why that is unsafe and how the
      mixin below bounds it without risking a deadlock on a long-lived
      connection.

    Same mechanism as gui_server._ConsoleServer and artifact_server._Server.
    """

    request_queue_size = 128
    tls_context = None
    # The catalog has no long-lived connections of its own (no SSE, no
    # device-held streams) -- every request is a bounded JSON exchange or a
    # small .torrent fetch. Sized to the fleet-sized accept backlog above so
    # a burst that fills the kernel queue can still be drained rather than
    # rejected outright.
    max_concurrent_requests = 256

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.tls_context is not None:
            sock.settimeout(_HANDSHAKE_TIMEOUT)
        return sock, addr

    def process_request_thread(self, request, client_address):
        if self.tls_context is not None:
            try:
                request = self.tls_context.wrap_socket(request,
                                                       server_side=True)
            except (ssl.SSLError, OSError, ValueError):
                # A failed or timed-out handshake is this connection's
                # problem and nobody else's.
                self.shutdown_request(request)
                return
            try:
                request.settimeout(None)   # Handler.timeout re-arms it
            except OSError:
                pass
        super().process_request_thread(request, client_address)


def _reject_constant(name):
    # json.loads' default parse_constant ACCEPTS the non-standard NaN /
    # Infinity / -Infinity literals; nothing downstream can serialise them
    # for a browser, so they are a 400 at the door.
    raise ValueError("non-finite number literal: %s" % name)


def parse_json_body(body):
    """json.loads for a device POST body. Refuses the NaN/Infinity literals
    (ValueError) and maps a pathologically nested body's RecursionError to a
    ValueError so every malformed body is a 400 rather than a dropped
    connection. An empty body reads as {}."""
    try:
        return json.loads(body or b"{}", parse_constant=_reject_constant)
    except RecursionError:
        raise ValueError("body too deeply nested")


class StateFileError(RuntimeError):
    """A state file under the state dir EXISTS but cannot be read or parsed
    (or its top level is not a JSON object). Distinct from a missing file,
    which is the empty store. Routes map it to 503; writers never replace
    the file's content while it is in this state."""

_REPORT_KEYS = ("ts", "image_id", "event", "transfer", "link", "peers",
                "peers_total", "agent")
_REPORT_EVENTS = ("staging-complete", "seeding-only", "pull")
_REPORT_PEER_ROWS = 64
_REPORT_STR_MAX = 128

# v2 terminal report (spec §10.2). Exact strict schema, distinct from the
# legacy v1 shape above. Ingest re-validates every type/enum/id/bound.
_HEX32 = re.compile(r"^[a-f0-9]{32}$")
_IMAGE_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_CONTENT_SHA256_STATES = ("verified", "mismatch", "not_checked")
_IOS_COPY_VERIFY_STATES = ("ok", "failed", "not_run", "unsupported")
_SAMPLING_CLASSES = ("good", "constrained")
_V2_STAGE_STATES = ("ready", "staging", "flash_full_seeding_only")
_REPORT_STORE_MAX = 16384       # bytes STORED per report (transport stays 64K)
_V2_PEER_CAP = 64
_STATE_PEER_SET_CAP = 512
_CONTENT_CAP = 2 ** 53
# Exact per-peer received bytes (``peer_transfer_records``, hook contract section 1).
# The device hook reads aria2-next's own cumulative per-peer session counters
# ONCE, at --on-bt-download-complete: the instant the last piece lands, before
# enableSeedOnly(), while the peers that fed us are still connected. These are
# NOT the 2026.08.20 rx_bytes/tx_bytes/avg_bps numbers, which were integrated
# from instantaneous rates and were removed for being estimates; nothing here
# is integrated, estimated or split evenly.
_V2_PEER_TRANSFER_ROWS = 32      # named transfer-record rows STORED per report
_PEER_TRANSFER_SOURCES = ("aria2_session_counters",)
_PEER_TRANSFER_ROWS_CAP = 512         # bound on the declared transfer-record row counts
_PORT_CAP = 65535


def _bounded_report_int(value, cap):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("report field not an int")
    if not 0 <= value <= cap:
        raise ValueError("report field out of bounds")
    return value


def _strict_bool(value, field):
    """A bool must arrive as a real bool: 1/"true"/None are a device bug, not
    a truthy value to be guessed at.  Same discipline as ``peers_truncated``."""
    if not isinstance(value, bool):
        raise ValueError("bad %s" % field)
    return value


def _sanitize_peer_transfer_records(block, win_start, created):
    """Strict re-validation of the optional v2 ``peer_transfer_records`` block: exact
    per-peer bytes RECEIVED by the reporting device, measured on the device.

    Provenance, stated so no reader has to guess which kind of number this is:
    each ``session_bytes_from_peer`` is aria2-next 2.5.6's own cumulative
    counter (``peer->getSessionDownloadLength()``), read once by the
    ``--on-bt-download-complete`` hook at the one instant the receiving client
    has complete knowledge.  It is not a rate integrated over samples and not
    an even split, which is why it does not reuse the retired ``rx_bytes``
    name.  Sampling from the origin instead loses real bytes to connections
    that open and close between samples (measured: 26.7% lost at 3s, 11.9% at
    2s); this block is the receiving side's exact answer.

    Absence is a first-class answer.  The whole block absent means NOT
    MEASURED (old agent, no hook, hook failure, stale sidecar discarded) and
    must never be rendered as zero.  A row present with
    ``session_bytes_from_peer: 0`` is a MEASURED zero: connected, fed us
    nothing.  ``complete: false`` means the hook could not read the whole peer
    list, so ``bytes_from_all_senders_total`` is a floor, not a total.

    A malformed block raises (a device bug, not a truncation): it is never
    quietly dropped, because a silently missing block reads as "not measured"
    and would hide the bug behind the honest answer.

    Truncation here is lossless in the aggregate.  Rows are ordered by bytes
    descending (deliberately the OPPOSITE policy from the observation-ordered
    participation rows: here what survives is what matters), and rows the
    server itself drops are MOVED into ``rows_omitted`` /
    ``bytes_from_all_senders_omitted`` and counted in ``rows_dropped_by_server`` --
    a cap the server applies is a cap the server reports.  The identity
    ``sum(rows) + bytes_from_all_senders_omitted == bytes_from_all_senders_total`` there-
    fore survives the server's own trim.

    WHAT THE TOTAL COUNTS, AND WHAT IT DOES NOT.  The origin seeder is an
    ordinary BitTorrent peer of every device: it appears in the device's own
    aria2.getPeers list and its bytes land in a row like any other peer's.
    ``bytes_from_all_senders_total`` therefore INCLUDES the origin, and the
    name says so -- a "bytes from peers" total would have read as
    peer-delivered and reported ~100% peer-to-peer for a wave that was 28.9%.
    Splitting origin from device is a SERVER-side question (only the server
    knows which address is the authenticated ``service:seeder`` principal) and
    is answered by ``telemetry.classify_peer_transfer_records``, not here: this
    function stores the device's measurement verbatim.

    No cross-check against ``content.completed_content_bytes``: aria2 counts
    wire bytes, so hashfailed and duplicate pieces can legitimately push the
    peer sum above the content length, and rejecting the report over that
    would discard the entire measurement.
    """
    if not isinstance(block, dict):
        raise ValueError("bad peer_transfer_records")
    if block.get("source") not in _PEER_TRANSFER_SOURCES:
        raise ValueError("bad peer_transfer_records.source")
    captured = block.get("captured_at")
    if isinstance(captured, bool) or not isinstance(captured, (int, float)):
        raise ValueError("bad peer_transfer_records.captured_at")
    if not math.isfinite(captured) or captured < 0:
        raise ValueError("bad peer_transfer_records.captured_at")
    # The capture instant is the hook's, minutes before the one-shot agent tick
    # that assembles the report -- but it can never precede the transfer window
    # or postdate the report that carries it.
    if not win_start <= captured <= created:
        raise ValueError("bad peer_transfer_records.captured_at range")
    complete = _strict_bool(block.get("complete"), "peer_transfer_records.complete")

    rows_in = block.get("rows")
    if not isinstance(rows_in, list):
        raise ValueError("bad peer_transfer_records.rows")
    rows = []
    seen = set()
    for row in rows_in:
        if not isinstance(row, dict):
            raise ValueError("bad peer_transfer_records row")
        ip = row.get("ip")
        if not isinstance(ip, str) or not ip or len(ip) > 64:
            raise ValueError("bad peer_transfer_records ip")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("bad peer_transfer_records ip")
        if ip in seen:
            # Two transfer records for one peer have no defined meaning: summing them
            # would invent bytes, picking one would discard measured ones.
            raise ValueError("duplicate peer_transfer_records ip")
        seen.add(ip)
        clean = {"ip": ip,
                 "session_bytes_from_peer": _bounded_report_int(
                     row.get("session_bytes_from_peer"), _CONTENT_CAP),
                 "session_bytes_to_peer": _bounded_report_int(
                     row.get("session_bytes_to_peer"), _CONTENT_CAP)}
        # port/has_complete_file are optional: absent stays absent, it does not
        # materialize as 0/false.
        if "port" in row:
            clean["port"] = _bounded_report_int(row.get("port"), _PORT_CAP)
        if "has_complete_file" in row:
            # aria2's peer->isSeeder(): this peer holds the whole file. That is
            # NOT "this peer is the origin" -- in a multi-device wave every
            # device that finishes early raises it. Origin identification is
            # telemetry.classify_peer_transfer_records's job, off the authenticated
            # service:seeder principal.
            clean["has_complete_file"] = _strict_bool(
                row.get("has_complete_file"), "peer_transfer_records has_complete_file")
        rows.append(clean)

    rows_total = _bounded_report_int(block.get("rows_total"),
                                     _PEER_TRANSFER_ROWS_CAP)
    rows_omitted = _bounded_report_int(block.get("rows_omitted"),
                                       _PEER_TRANSFER_ROWS_CAP)
    if rows_total != len(rows) + rows_omitted:
        raise ValueError("peer_transfer_records rows do not sum to rows_total")
    total = _bounded_report_int(block.get("bytes_from_all_senders_total"),
                                _CONTENT_CAP)
    omitted = _bounded_report_int(block.get("bytes_from_all_senders_omitted"),
                                  _CONTENT_CAP)
    if sum(r["session_bytes_from_peer"] for r in rows) + omitted != total:
        raise ValueError("peer_transfer_records bytes do not sum to total")

    # Canonical stored order, and the order the server's own cap trims from:
    # bytes descending, ip as the tiebreak so the result is deterministic.
    rows.sort(key=lambda r: (-r["session_bytes_from_peer"], r["ip"]))
    extra = rows[_V2_PEER_TRANSFER_ROWS:]
    rows = rows[:_V2_PEER_TRANSFER_ROWS]
    rows_omitted += len(extra)
    omitted += sum(r["session_bytes_from_peer"] for r in extra)
    # rows_omitted counts transport loss; ``complete`` describes the capture.
    # Two different failures, two different fields -- dropping the tail here
    # does not make the measurement incomplete.
    return {"source": block["source"], "captured_at": float(captured),
            "complete": complete, "rows": rows,
            "rows_total": rows_total, "rows_omitted": rows_omitted,
            "rows_dropped_by_server": len(extra),
            "bytes_from_all_senders_total": total,
            "bytes_from_all_senders_omitted": omitted}


def _sanitize_report_v2(data):
    """Strict server-side re-validation of a v2 terminal report (spec §10.2).

    Exact types/enums/ids/timestamps; content/verification/sampling/stage/peer
    caps; stored body bounded at _REPORT_STORE_MAX. Tags ``schema:"v2"``.
    The optional ``peer_transfer_records`` block (exact device-measured per-peer
    received bytes) is validated by _sanitize_peer_transfer_records and stored only
    when it was sent -- absent means not measured, never zero.
    ``report_id`` is the ring dedupe key. No token/secret ever appears in a
    raised message (a report carries none, but the discipline is explicit)."""
    report_id = data.get("report_id")
    if not isinstance(report_id, str) or not _HEX32.fullmatch(report_id):
        raise ValueError("bad report_id")
    transfer_id = data.get("transfer_id")
    if not isinstance(transfer_id, str) or not _HEX32.fullmatch(transfer_id):
        raise ValueError("bad transfer_id")
    event = data.get("event")
    if event not in _REPORT_EVENTS:
        raise ValueError("bad event")
    rrid = data.get("report_request_id")
    if event == "pull":
        if rrid is not None and (not isinstance(rrid, str)
                                 or not _HEX32.fullmatch(rrid)):
            raise ValueError("bad report_request_id")
    else:
        if rrid is not None:
            raise ValueError("report_request_id only for pull")
    created = data.get("report_created_at")
    if isinstance(created, bool) or not isinstance(created, (int, float)):
        raise ValueError("bad report_created_at")
    if not math.isfinite(created) or created < 0:
        raise ValueError("bad report_created_at")
    image_id = data.get("image_id")
    if not isinstance(image_id, str) or not _IMAGE_RE.fullmatch(image_id):
        raise ValueError("bad image_id")

    # ``window`` and ``content`` are optional: an agent that measured nothing
    # (no transfer window opened, no aria2 stats in hand) may omit them or
    # send null, and the stored report then omits the key -- not measured is
    # never rendered as a zero-length window or zero bytes. When present the
    # block is validated strictly, exactly as before.
    win = data.get("window")
    win_out = None
    if win is not None:
        if not isinstance(win, dict):
            raise ValueError("bad window")
        # ``end`` is always observed (the agent writes the report at that
        # instant). ``start`` is per-key optional for the same reason the
        # whole block is: an image adopted in place, or one whose started_ts
        # was lost with a state file, has no observed opening edge, and the
        # agent omits the key rather than collapsing it onto the end. A
        # window with no start is stored open-ended, never as zero-length.
        end = win.get("end")
        if isinstance(end, bool) or not isinstance(end, (int, float)):
            raise ValueError("bad window.end")
        if not math.isfinite(end) or end < 0:
            raise ValueError("bad window.end")
        start = win.get("start")
        if start is not None:
            if isinstance(start, bool) or not isinstance(start, (int, float)):
                raise ValueError("bad window.start")
            if not math.isfinite(start) or start < 0:
                raise ValueError("bad window.start")
            if start > end:
                raise ValueError("bad window order")
        if not isinstance(win.get("complete"), bool):
            raise ValueError("bad window.complete")
        win_out = {"end": float(end), "complete": bool(win["complete"])}
        if start is not None:
            win_out["start"] = float(start)

    content = data.get("content")
    content_out = None
    # An EMPTY content block means the same thing as an absent one: the
    # completion tick took no aria2 reading. The agent sends {} on that path
    # (adopted image, RPC hiccup at completion), and a measured zero must
    # stay distinguishable from an unmeasured field.
    if content is not None and content != {}:
        if not isinstance(content, dict):
            raise ValueError("bad content")
        content_out = {
            "completed_content_bytes": _bounded_report_int(
                content.get("completed_content_bytes"), _CONTENT_CAP),
            "total_content_bytes": _bounded_report_int(
                content.get("total_content_bytes"), _CONTENT_CAP)}
        if content_out["completed_content_bytes"] \
                > content_out["total_content_bytes"]:
            raise ValueError("completed content exceeds total")

    csha = data.get("content_sha256")
    if not isinstance(csha, dict) or csha.get("state") not in \
            _CONTENT_SHA256_STATES:
        raise ValueError("bad content_sha256")
    content_sha256 = {"state": csha["state"]}
    checked = csha["state"] != "not_checked"
    if checked and csha.get("algo") != "sha256":
        raise ValueError("checked content requires sha256")
    if not checked and "algo" in csha:
        raise ValueError("unchecked content forbids algo")
    if checked:
        content_sha256["algo"] = "sha256"

    iocv = data.get("ios_copy_verify")
    if not isinstance(iocv, dict) or iocv.get("state") not in \
            _IOS_COPY_VERIFY_STATES:
        raise ValueError("bad ios_copy_verify")

    sampling = data.get("sampling")
    if not isinstance(sampling, dict) or sampling.get("sampling_class") not in \
            _SAMPLING_CLASSES:
        raise ValueError("bad sampling")
    sampling_out = {"sampling_class": sampling["sampling_class"]}
    for key in ("catalog_rtt_ms_median", "catalog_rtt_samples",
                "heartbeat_fail_streak", "report_fail_streak"):
        if key in sampling:
            sampling_out[key] = _peer_int(sampling.get(key))

    stage_state = data.get("stage_state")
    if stage_state not in _V2_STAGE_STATES:
        raise ValueError("bad stage_state")

    peers_in = data.get("peers")
    if not isinstance(peers_in, list):
        raise ValueError("bad peers")
    # A cap the server applies is a cap the server must report: the rows past
    # _V2_PEER_CAP are dropped here, so the count of them is stored and
    # peers_truncated is raised even when the device believed it sent everything.
    peers_dropped = max(len(peers_in) - _V2_PEER_CAP, 0)
    rows = []
    for row in peers_in[:_V2_PEER_CAP]:
        if not isinstance(row, dict):
            raise ValueError("bad peer row")
        ip = row.get("ip")
        if not isinstance(ip, str) or not ip or len(ip) > 64:
            raise ValueError("bad peer ip")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("bad peer ip")
        clean = {"ip": ip}
        for key in ("first_observed", "last_observed"):
            v = row.get(key)
            if (isinstance(v, bool) or not isinstance(v, (int, float))
                    or not math.isfinite(v) or v < 0):
                raise ValueError("bad peer timestamp")
            clean[key] = float(v)
        if clean.get("first_observed", 0) > clean.get("last_observed", 0):
            raise ValueError("bad peer timestamp order")
        clean["observations"] = _bounded_report_int(
            row.get("observations"), _CONTENT_CAP)
        rows.append(clean)
    peers_total = _bounded_report_int(data.get("peers_total"),
                                      _STATE_PEER_SET_CAP)
    # Compared against the PRE-truncation row count, so over-sending rows can
    # never shrink the declared distinct-peer total below what was sent.
    if peers_total < len(peers_in):
        raise ValueError("peers_total below rows")
    for key in ("peers_truncated", "peers_saturated"):
        if not isinstance(data.get(key), bool):
            raise ValueError("bad %s" % key)

    report = {"v": 2, "schema": "v2", "report_id": report_id,
              "transfer_id": transfer_id, "report_request_id": rrid,
              "report_created_at": float(created), "image_id": image_id,
              "event": event, "content_sha256": content_sha256,
              "ios_copy_verify": {"state": iocv["state"]},
              "sampling": sampling_out, "stage_state": stage_state,
              "peers": rows, "peers_total": peers_total,
              "peers_rows_dropped": peers_dropped,
              "peers_truncated": data["peers_truncated"] or peers_dropped > 0,
              "peers_saturated": data["peers_saturated"]}
    if win_out is not None:
        report["window"] = win_out
    if content_out is not None:
        report["content"] = content_out
    transfer_records = data.get("peer_transfer_records")
    if transfer_records is not None:
        # Optional and stored only when sent: an absent block means NOT
        # MEASURED and must stay absent all the way to the reader. Without a
        # window the capture instant is bounded only by the report itself.
        report["peer_transfer_records"] = _sanitize_peer_transfer_records(
            transfer_records,
            # No window, or a window with no observed start, leaves the
            # capture instant bounded only by the report itself.
            (win_out or {}).get("start", 0.0),
            float(created))
    agent = data.get("agent")
    if isinstance(agent, dict):
        report["agent"] = _cap_strings(agent)
    if len(json.dumps(report)) > _REPORT_STORE_MAX:
        raise ValueError("report too large")
    return report


def _cap_strings(value):
    """Recursively cap every string in *value* (keys included) at
    _REPORT_STR_MAX chars.  Non-container, non-string values pass through,
    except a non-finite float (``1e999`` parses as inf), which raises: it
    cannot be stored or served as JSON."""
    if isinstance(value, str):
        return value[:_REPORT_STR_MAX]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite number in report")
    if isinstance(value, dict):
        return {str(k)[:_REPORT_STR_MAX]: _cap_strings(v)
                for k, v in value.items()}
    if isinstance(value, list):
        return [_cap_strings(v) for v in value]
    return value


def _peer_int(value):
    # OverflowError: json.loads accepts Infinity, and int(float('inf')) raises.
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return 0


def _sanitize_report(data):
    """Server-side re-validation of a device telemetry report.

    Dispatches by version: a ``v == 2`` body is the strict v2 terminal report
    (spec §10.2, _sanitize_report_v2); anything else is the legacy v1 report
    (issue #13), tagged ``schema:"v1"`` with its existing ambiguous fields
    preserved verbatim and NEVER mapped into v2 fields. Raises ValueError on a
    non-dict body or an unknown event (routes map that to a 400)."""
    if not isinstance(data, dict):
        raise ValueError("report must be a JSON object")
    if data.get("v") == 2:
        return _sanitize_report_v2(data)
    if data.get("event") not in _REPORT_EVENTS:
        raise ValueError("bad event")
    report = {}
    for key in _REPORT_KEYS:
        if key in data:
            report[key] = _cap_strings(data[key])
    # The numeric link fields must be STORED as numbers: the swarm-map drawer
    # interpolates rtt_ms_median into its HTML unescaped (it reads as a
    # number), so a device-supplied string here would be stored XSS in the
    # console session.  Same int-coercion discipline as the peer rows below;
    # absent keys stay absent (the map shows a placeholder for those).
    link = report.get("link")
    if isinstance(link, dict):
        for key in ("rtt_ms_median", "rtt_samples", "hb_failures"):
            if key in link:
                link[key] = _peer_int(link[key])
    rows = []
    rows_sent = 0
    peers = data.get("peers")
    if isinstance(peers, list):
        for row in peers:
            if not isinstance(row, dict):
                continue
            rows_sent += 1
            if len(rows) < _REPORT_PEER_ROWS:
                rows.append({"ip": str(row.get("ip") or "")[:64]})
    report["peers"] = rows
    # A cap the server applies is a cap the server must report.
    report["peers_rows_dropped"] = rows_sent - len(rows)
    # Exact distinct-participation count, stored as an int (the drawer
    # interpolates it unescaped as a number — same stored-XSS discipline as
    # the link fields above), floored at the rows the device actually SENT —
    # not at the rows that survived our own trim, which used to make the
    # stored record assert a smaller swarm than the device reported — so "and
    # N more" arithmetic can never go negative, and clamped at int32 max so a
    # hostile device can't push a value outside OTLP intValue encoding.
    report["peers_total"] = min(
        max(_peer_int(data.get("peers_total")), rows_sent), 2**31 - 1)
    # Hard per-report bound (spec §6: ring of 5 × ≤16 KB per device). The
    # 64 KiB transport cap bounds the wire body; this bounds what we STORE —
    # key-count in nested sections is otherwise uncapped.
    if len(json.dumps(report)) > 16384:
        raise ValueError("report too large")
    report["schema"] = "v1"
    return report


def _normalize_policy(rec):
    """One raw policy row, normalised to ``{approved_image_id: first-or-None,
    approved_image_ids: [..]}``. Shared by ``get_policy``,
    ``device_policy_view`` and ``set_policy``'s compare-and-set so all three
    read a row the same way from ONE keyed lookup."""
    if not isinstance(rec, dict):
        return {"approved_image_id": None, "approved_image_ids": []}
    ids = rec.get("approved_image_ids")
    if not isinstance(ids, list):
        one = rec.get("approved_image_id")
        ids = [one] if one else []
    ids = [str(i) for i in ids if i]
    return {"approved_image_id": ids[0] if ids else None,
            "approved_image_ids": ids}


class PolicyConflict(Exception):
    """A conditional set_policy() whose expectation no longer held.

    Deliberately NOT a ValueError: callers map ValueError to "the request was
    malformed" (400), and a lost race is neither malformed nor the caller's
    mistake -- it is a concurrent edit the caller must be shown before it
    decides again. ``current_ids`` carries what is actually stored, so the
    answer can say so without a second read racing the first."""

    def __init__(self, current_ids):
        super().__init__("assignment changed since it was read")
        self.current_ids = list(current_ids)


class QuarantinedImage(Exception):
    """Raised by set_policy() when the requested assignment set names an
    image currently quarantined by the Cisco Bulk Hash reconciler -- a NEW
    apply_hash_verification() mismatch, or one release_quarantine() has not
    (yet, or successfully) lifted. Carries the image's current
    ``hash_verification`` so an HTTP caller can surface WHY the assign was
    refused (state/checked_at/feed_published_at/source/deferral) rather
    than a bare 400."""

    def __init__(self, image_id, hash_verification):
        super().__init__("image %s is quarantined" % image_id)
        self.image_id = image_id
        self.hash_verification = hash_verification


class QuarantineStillMismatched(Exception):
    """Raised by release_quarantine() when the image's CURRENT sha512 still
    disagrees with the feed sha512 recorded by the last
    apply_hash_verification() call and the caller did not pass
    override=True. Carries the same ``hash_verification`` shape as
    QuarantinedImage so a caller can show the operator what still fails
    before deciding to force it."""

    def __init__(self, image_id, hash_verification):
        super().__init__(
            "image %s still fails hash verification; override required"
            % image_id)
        self.image_id = image_id
        self.hash_verification = hash_verification


class CatalogStore:
    TELEMETRY_RING = 5      # newest reports kept per device (hard disk bound)
    SEEN_REPORT_IDS = 256   # durable per-device seen v2 report_id ledger bound
    # Durable per-device transfer attestations kept, one slot per TRANSFER.
    # Sized well clear of the real working set: a device may hold
    # MAX_ASSIGNED_IMAGES (10) plans at once, so this is six full
    # re-assignment generations, and the tracker consumes an attestation
    # within one sample pass (15 s) of it being written. It is deliberately
    # far larger than TELEMETRY_RING because the ring is shared by every image
    # and every report KIND on the device while this ledger holds one row per
    # transfer -- see _remember_attestation.
    ATTESTATIONS = 64
    PULL_TTL = 600          # seconds a console pull directive stays pending

    def __init__(self, state_dir, audit_path=None, seeder_remove_fn=None,
                 seeder_add_fn=None):
        self.state_dir = state_dir
        self.torrents_dir = os.path.join(state_dir, "torrents")
        os.makedirs(self.torrents_dir, exist_ok=True)
        self.catalog_path = os.path.join(state_dir, "catalog.json")
        self.devices_path = os.path.join(state_dir, "devices.json")
        self.policy_path = os.path.join(state_dir, "policy.json")
        self.telemetry_path = os.path.join(state_dir, "telemetry.json")
        self.pull_path = os.path.join(state_dir, "pull_requests.json")
        # Durable bounded per-device seen v2 report_id ledger. The ring
        # (TELEMETRY_RING) only remembers the newest few reports, so a v2 retry
        # of an id already evicted from the ring would otherwise re-append and
        # break the final spec's stable report event ids / idempotence. This
        # ledger persists SEEN_REPORT_IDS ids/device (deterministic bound,
        # oldest purged FIFO) and is purged with the device.
        self.report_ledger_path = os.path.join(state_dir,
                                                "report_ledger.json")
        # Durable per-device transfer attestations: the fact that a terminal
        # report bearing a given transfer_id arrived with a VERIFIED content
        # sha256, and when the server took it in. Written at ingest and read
        # by the tracker's transfer-lifecycle pass. It exists because the
        # report ring above cannot be that pass's only source -- see
        # _remember_attestation.
        self.attestations_path = os.path.join(state_dir,
                                              "transfer-attestations.json")
        # Cisco Bulk Hash reconciliation (KGV reconciler): the FULL last
        # verdict reconcile() produced for each image, keyed by image_id --
        # {state, feed_sha512, publish_date, deferral, checked_at, source}.
        # This is deliberately a separate store from the narrower wire-compat
        # `hash_verification` projection written onto the catalog entry
        # itself (state/checked_at/feed_published_at/source/deferral):
        # release_quarantine() needs feed_sha512 to re-run the sha512
        # comparison later without re-fetching the feed, and keeping that
        # internal-bookkeeping-only field off the wire-facing entry means
        # nothing downstream ever has to know it exists.
        self.hash_verdicts_path = os.path.join(state_dir, "hash_verdicts.json")
        # Both None by default: a CatalogStore constructed for anything
        # OTHER than the Bulk Hash quarantine path (most existing callers
        # and tests) must never attempt a real audit write or seeder call it
        # was never asked to make. gui_server.py's main() injects both
        # explicitly, mirroring exactly how gui_images.ImageService is
        # already wired for the identical seeder-teardown + audit concern
        # (this module cannot default seeder_remove_fn to publish.py itself
        # -- publish.py imports this module, so importing it back here would
        # be a cycle; the caller that wants the side effect injects it).
        self.audit_path = audit_path
        self._seeder_remove = seeder_remove_fn
        # The inverse of seeder_remove_fn, for release_quarantine(): called
        # as seeder_add_fn(torrent_path, image_dir, info_hash) to put the
        # canonical torrent back into the seeder (publish.resume_torrent_rpc
        # in main()). None (unwired) is a no-op, like seeder_remove_fn.
        self._seeder_add = seeder_add_fn
        # --- keyed incremental durable state (see keyed_state) -------------
        # Every per-device store above is one ROW per device in a bucketed
        # shard directory (devices.d/ and friends), not one whole-fleet JSON
        # document. A heartbeat, a policy read, a terminal report or a
        # pull-directive check locks, parses and rewrites only the shard its
        # own device lands in; each used to hold one global lock on the whole
        # document while it re-parsed and re-serialised the entire fleet, so
        # the per-device cost -- and the serialisation between unrelated
        # devices -- grew with fleet size. A legacy whole-fleet document is
        # migrated into shards on first use. The durability contract is
        # unchanged: atomic temp+os.replace, allow_nan=False, and an existing
        # but unreadable shard raises StateFileError rather than reading as
        # empty or being overwritten by the next writer.
        self._devices = self._keyed(self.devices_path)
        self._policies = self._keyed(self.policy_path)
        self._pulls = self._keyed(self.pull_path)
        self._reports = self._keyed(self.telemetry_path)
        self._report_ids = self._keyed(self.report_ledger_path)
        self._attestations = self._keyed(self.attestations_path)

    @staticmethod
    def _keyed(path):
        """A keyed store for the per-device state at *path*, carrying this
        class's own fail-closed error type."""
        return keyed_state.KeyedState(path, error=StateFileError)

    def _read(self, path):
        """One state file as a dict. A MISSING file is the empty store (first
        boot, legacy bootstrap). An EXISTING file that cannot be opened or
        parsed, or whose top level is not an object, raises StateFileError
        instead of reading as {}: served as empty, a corrupt policy.json is a
        fleet-wide unassign every agent acts on, and the next set_policy
        would replace the recoverable content with a single row."""
        try:
            with open(path) as f:
                data = json.load(f)
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            raise StateFileError("state file unreadable: %s (%s)"
                                 % (path, type(exc).__name__))
        if not isinstance(data, dict):
            raise StateFileError("state file is not a JSON object: %s" % path)
        return data

    # --- images ---
    def save_image(self, entry):
        with secrets_store.store_lock(self.catalog_path):
            cat = self._read(self.catalog_path)
            cat.setdefault("images", {})[entry["id"]] = entry
            _atomic_write_json(self.catalog_path, cat)

    def delete_image(self, image_id):
        """Remove an image from the catalog. Returns True iff it existed."""
        with secrets_store.store_lock(self.catalog_path):
            cat = self._read(self.catalog_path)
            existed = cat.get("images", {}).pop(image_id, None) is not None
            if existed:
                _atomic_write_json(self.catalog_path, cat)
        return existed

    def get_image(self, image_id):
        return self._read(self.catalog_path).get("images", {}).get(image_id)

    def list_images(self):
        return list(self._read(self.catalog_path).get("images", {}).values())

    def torrent_path(self, image_id):
        return os.path.join(self.torrents_dir, "%s.torrent" % image_id)

    # --- devices ---
    def record_heartbeat(self, device_id, data, now=None):
        now = time.time() if now is None else now
        rec = {"device_id": device_id, "last_seen": now}
        rec.update(data)
        # One shard, one lock: a heartbeat no longer rewrites the fleet.
        self._devices.put(device_id, rec)

    def get_device(self, device_id):
        return self._devices.get(device_id)

    def forget_device(self, device_id):
        """Drop a device's stored heartbeat/staging record.
        Called on a successful undeploy so the console stops reporting a wiped
        device as 'deployed' from its last live heartbeat. Returns True iff a
        record existed. The image ASSIGNMENT (policy) and telemetry history
        are intentionally left untouched — a re-onboard restages the same
        image, and the reports are historical."""
        return self._devices.delete(device_id)

    def list_devices(self, now=None):
        """Every heartbeat record. O(fleet) by nature — the console's fleet
        table, never a per-device request. This read is side-effect free:
        expired report directives are ignored/reaped only on the POST
        heartbeat path or a later write for that device."""
        return list(self._devices.snapshot().values())

    def purge_device(self, device_id):
        """Remove ALL per-device catalog state: the heartbeat record, the
        image assignment (policy), the telemetry history, the seen-report-id
        ledger, the durable transfer attestations, and any pending pull
        directive. Called when the console deletes a device from the fleet — a device that is deleted and added back must
        come back unassigned, or a stale assignment would silently restage the
        old image. Contrast forget_device(), which drops only the heartbeat
        record on undeploy and deliberately keeps the assignment. Returns
        True iff any state existed."""
        existed = self.forget_device(device_id)
        for state in (self._policies, self._reports, self._pulls,
                      self._report_ids, self._attestations):
            if state.delete(device_id):
                existed = True
        return existed

    # --- policy (per-device staging approval) ---
    def image_policy_lock(self):
        """Cross-process serializer for image-existence/assignment decisions.

        Image assignment and deletion span two JSON stores, so their
        check-then-act sequences need one shared lock — and `docker exec ...
        iris-assign` runs as a SEPARATE process from the console, so a
        threading lock cannot cover it. This is a store_lock (fcntl.flock)
        on its own sidecar, distinct from the per-store file locks so the
        holder can still take those underneath (flock does not nest on the
        same path within one process). ImageService.delete_image shares it
        with set_policy."""
        return secrets_store.store_lock(self.catalog_path + ".assign")

    def set_policy(self, device_id, approved_image_id=None,
                   approved_image_ids=None, expect_image_ids=None):
        """Approve an ordered set of images (max MAX_ASSIGNED_IMAGES) for a
        device. Approval is the whole policy: IRIS stages and verifies, and
        never installs, activates or reloads, so there is nothing further to
        authorise.

        The singular kwarg remains for callers/rows from the single-image
        era and means a one-element set; passing both is a programming
        error.

        There used to be an ``install_allowed`` flag here. It gated nothing --
        no code in server/ or device/ ever read it -- and it was always written
        False, because the scope decision had already been made. Displayed to an
        operator as a False beside an approved image it read as a second gate
        still to be opened, which is worse than absent: it invited people to go
        looking for the switch that would let staging proceed.

        ``expect_image_ids`` makes the write CONDITIONAL: the stored set must
        still equal it, or PolicyConflict is raised and nothing is written.
        Two operators with the image picker open on the same device used to
        overwrite each other in silence, the later Apply simply winning. The
        comparison is by sequence, since applying rewrites order as well as
        membership, and an empty list is a real expectation ("I saw nothing
        assigned"), distinct from None ("I am not checking"). Passing None
        keeps the unconditional write every existing caller relies on.

        Raises QuarantinedImage if *ids* names an image the Cisco Bulk Hash
        reconciler currently has quarantined (see apply_hash_verification()/
        release_quarantine()) -- unassigning (an *ids* that DROPS a
        quarantined id, or an empty *ids*) is always allowed; only naming
        one in the set being written is refused.

        Every write also maintains the row's ``plans`` map -- one transfer
        plan (plan_id, transfer_id, planned_at, info_hash) per image id in
        the set, minted here and carried forward verbatim for any id that
        was already assigned. This is the sole mint site for both ids; see
        the comment at the write below for why the merge is load-bearing.
        A refused write -- PolicyConflict or QuarantinedImage -- mints
        nothing, because both checks run before any plan is computed."""
        if approved_image_id is not None and approved_image_ids is not None:
            raise ValueError(
                "pass approved_image_id or approved_image_ids, not both")
        if approved_image_ids is None:
            ids = [approved_image_id] if approved_image_id else []
        else:
            ids = [str(i) for i in approved_image_ids]
        if len(ids) > MAX_ASSIGNED_IMAGES:
            raise ValueError("at most %d images per device" % MAX_ASSIGNED_IMAGES)
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate image id in assignment")
        with self.image_policy_lock():
            # Re-check at persistence time. Missing catalog.json remains valid
            # for legacy bootstrap callers; an existing catalog fails closed.
            # This is also the single enforcement point for "a quarantined
            # image may never be assigned" (KGV reconciler): every caller --
            # the console's /assign route, the iris-assign CLI, and this
            # class's own quarantine auto-unassign below -- goes through
            # set_policy, so the rule can only be gotten wrong in one place.
            if ids and os.path.exists(self.catalog_path):
                for iid in ids:
                    entry = self.get_image(iid)
                    if entry is None:
                        raise ValueError("no such image")
                    if entry.get("quarantined"):
                        raise QuarantinedImage(iid, entry.get("hash_verification"))
            # The compare-and-set, the plan merge and the write all happen
            # inside ONE call under the device row's own shard lock: a check
            # outside it would be a compare-and-set with a gap wide enough for
            # the very race it exists to catch. Cross-device serialisation is
            # image_policy_lock's job (held above), so narrowing this lock from
            # the whole fleet's policy document to one device's shard loses
            # nothing.
            def write_row(prev):
                if expect_image_ids is not None:
                    current = _normalize_policy(prev)["approved_image_ids"]
                    if [str(i) for i in expect_image_ids] != current:
                        raise PolicyConflict(current)
                # --- transfer plans: minted here, and ONLY here ---
                # A plan is the server's durable name for one intended
                # transfer of one image to one device: a plan_id, the
                # transfer_id the device will adopt and stamp on every
                # observation and terminal report, the instant the decision
                # was made, and the info_hash the tracker will see announced.
                # Minting at assignment time (rather than on the device, at
                # download time) is what makes two consecutive assignments of
                # the SAME image distinguishable -- an unassign+reassign
                # inside one agent tick window is invisible to the device, so
                # a device-minted id would silently merge the two into one.
                #
                # The write below replaces the WHOLE row, so the plans map has
                # to be merged forward explicitly: an image id that was
                # already in the set keeps its existing plan row verbatim.
                # Without this merge every Apply -- including one that only
                # adds or removes some OTHER image, and including the
                # quarantine auto-unassign path, which rewrites the row for
                # devices it is not otherwise touching -- would re-mint a new
                # transfer_id for every image the device is already pulling,
                # restarting each in-flight transfer's identity and orphaning
                # every report already in flight under the old id.
                #
                # An id that LEAVES the set simply has no entry in the new
                # map, so a later re-assignment mints a genuinely new plan --
                # which is exactly the distinction the replan case needs.
                #
                # Both ids are 32 lowercase hex (secrets.token_hex(16)):
                # transfer_id is re-validated against _HEX32 on ingest (see
                # _sanitize_report_v2 above and live_samples), and a value
                # that fails it would fail the device's WHOLE report, so the
                # shape is a hard requirement rather than a convention.
                # A carried-forward row is re-validated for the same reason:
                # policy.json is an operator-editable file on disk, and a
                # hand-edited or truncated plan row must be re-minted here
                # rather than travel to the device and poison its reports.
                prev_row = prev if isinstance(prev, dict) else {}
                prev_plans = prev_row.get("plans")
                prev_plans = prev_plans if isinstance(prev_plans, dict) else {}
                planned_at = time.time()
                plans = {}
                for iid in ids:
                    row = prev_plans.get(iid)
                    if isinstance(row, dict) \
                            and _HEX32.fullmatch(str(row.get("plan_id", ""))) \
                            and _HEX32.fullmatch(
                                str(row.get("transfer_id", ""))):
                        plans[iid] = row        # carry forward -- NEVER re-mint
                        continue
                    # info_hash is captured from the catalog entry set_policy
                    # already has in hand, so the tracker can join an announce
                    # back to this plan without re-reading catalog.json at a
                    # later, possibly changed, moment. None on the legacy
                    # bootstrap path where catalog.json does not exist yet.
                    entry = self.get_image(iid) or {}
                    plans[iid] = {"plan_id": secrets.token_hex(16),
                                  "transfer_id": secrets.token_hex(16),
                                  "planned_at": planned_at,
                                  "info_hash": entry.get("info_hash_hex")}
                # Keep writing approved_image_id (first-or-None) alongside
                # approved_image_ids: raw policy.json readers that predate the
                # ordered set (gui_server's device-view merge and Overview
                # aggregation both read list_policies() directly, not through
                # get_policy()'s normalisation) must keep seeing an assignment
                # without themselves knowing about the plural key.
                return {"approved_image_id": ids[0] if ids else None,
                        "approved_image_ids": ids,
                        "plans": plans}

            self._policies.update(device_id, write_row)

    def get_policy(self, device_id):
        """The device's approvals, normalised: every historical row shape
        reads as ``{approved_image_id: first-or-None, approved_image_ids:
        [..]}``. A record written before ``install_allowed`` was removed
        still carries the key on disk; it is dropped on the way out so
        callers never see a field that means nothing. A row written by the
        single-image release carries only ``approved_image_id`` and reads
        back as its one-element list, with no migration step -- the row
        rewrites itself in the new shape at the next set_policy. When a row
        carries BOTH keys (the shape set_policy now writes), the plural is
        authoritative: ``approved_image_id`` is recomputed here as its first
        element and never trusted from disk, so a raw edit or a stale write
        that leaves the two keys disagreeing can't desync what callers see."""
        return _normalize_policy(self._policies.get(device_id))

    def device_policy_view(self, device_id):
        """The WIRE projection of a device's policy: what GET
        /v1/devices/<id>/policy serves to the agent.

        get_policy() is the INTERNAL contract and is deliberately left at its
        two keys -- set_policy's own compare-and-set, the heartbeat
        live-sample admission gate and the v2 ingest gate all read it, and
        several tests pin its exact shape as the guard that it never widens.
        This wrapper adds the one thing the device needs and nothing else.

        Only ``plan_id`` and ``transfer_id`` are projected. ``planned_at`` and
        ``info_hash`` stay server-side: the agent has no use for either (it
        gets its info_hash from the personalised torrent), and shipping a
        field is a promise to keep shipping it.

        A plan row is projected only when BOTH ids are 32 lowercase hex and
        the image is in the normalised approved set. Anything else -- a
        hand-edited policy.json, a row for an image that has since been
        unassigned -- is omitted rather than sent through: the agent's
        adoption path rejects a malformed id anyway, and a transfer_id that
        fails _HEX32 would fail the device's whole report on the way back."""
        # ONE keyed read for both the normalised view and the plans map (it
        # used to be two whole-fleet parses of policy.json per device poll).
        rec = self._policies.get(device_id)
        view = _normalize_policy(rec)
        rows = rec.get("plans") if isinstance(rec, dict) else None
        rows = rows if isinstance(rows, dict) else {}
        plans = {}
        for image_id in view["approved_image_ids"]:
            row = rows.get(image_id)
            if not isinstance(row, dict):
                continue
            plan_id = str(row.get("plan_id", ""))
            transfer_id = str(row.get("transfer_id", ""))
            if not _HEX32.fullmatch(plan_id) \
                    or not _HEX32.fullmatch(transfer_id):
                continue
            plans[image_id] = {"plan_id": plan_id,
                               "transfer_id": transfer_id}
        view["plans"] = plans
        return view

    def list_policies(self):
        """Every device's raw policy row. O(fleet) by nature — console tables
        and the quarantine auto-unassign sweep, never a per-device request."""
        return self._policies.snapshot()

    # --- Cisco Bulk Hash reconciliation: verdict storage + quarantine ---
    # (KGV reconciler). apply_hash_verification() is the only writer of
    # hash_verification/cisco_signature_verified and the only place a NEW
    # mismatch can START a quarantine; release_quarantine() is the only
    # place one can END. set_policy() (above) is the single enforcement
    # point for "a quarantined image may never be assigned".
    #
    # cisco_signature_verified is this subsystem's OWN verdict field --
    # neither method here may ever read or write publish.py's
    # operator_attested_signature (the operator's own `iris-publish
    # --signature-verified` attestation). IRIS-03-009/#88: the two used to
    # share one field, so an operator's mark was silently overwritten by the
    # very next reconciler run. They are now separate and both durable; keep
    # them that way.

    def _audit_event(self, **kwargs):
        """Best-effort audit emit for the quarantine path. self.audit_path
        is None for any CatalogStore not explicitly wired for it (most
        existing callers/tests) -- silently skip rather than fall back to a
        real on-disk path nothing asked for. A logging failure must never
        undo or block an action that has already taken effect on disk."""
        if self.audit_path is None:
            return
        try:
            audit.append_event(self.audit_path, **kwargs)
        except Exception:
            pass

    def _stop_seeding(self, entry):
        """Best-effort seeder teardown for *entry* -- the same call
        gui_images.ImageService.delete_image() makes, reused here so a
        quarantined image stops being served WITHOUT touching the catalog
        entry itself. self._seeder_remove is None for any CatalogStore not
        wired with one (most existing callers/tests): a no-op then, not a
        forced import of publish.py (see __init__).

        Returns True on success (including the not-wired no-op -- that is
        an intentional configuration, not a failure to keep retrying
        forever) and False when a WIRED seeder call raised. The caller
        (_fire_quarantine) uses this to decide whether the quarantine's
        actions have all converged, so a transiently unreachable seeder
        gets retried on the next apply run instead of being forgotten."""
        if self._seeder_remove is None:
            return True
        try:
            self._seeder_remove(entry.get("info_hash_hex"))
            return True
        except Exception:   # seeder unreachable is non-fatal, but retried
            return False

    def _resume_seeding(self, image_id, entry):
        """Inverse of _stop_seeding, for release_quarantine(): hand the
        canonical torrent back to the seeder from the directory the image
        was published from. The quarantine force-removed it from aria2 and
        nothing else ever re-adds a torrent (the startup re-seed skips
        quarantined and unknown torrents on purpose), so without this a
        released-then-assigned image has no origin seeder and every device
        assigned it stalls at 0% with no error anywhere.

        Returns (ok, reason): ok is True on success and for the not-wired
        no-op; reason is a short, credential-free string (an exception class
        name, never its text -- RPC/URL exceptions may carry request
        material) when ok is False."""
        if self._seeder_add is None:
            return True, ""
        image_dir = entry.get("source_dir")
        if not isinstance(image_dir, str) or not os.path.isdir(image_dir):
            # Never guess by basename: bt-seed-unverified would serve
            # same-named bytes under this torrent's piece hashes.
            return False, "image source_dir unavailable"
        try:
            self._seeder_add(self.torrent_path(image_id), image_dir,
                             entry.get("info_hash_hex"))
            return True, ""
        except Exception as exc:
            return False, exc.__class__.__name__

    def apply_hash_verification(self, verdicts, source, now=None):
        """Apply Cisco Bulk Hash reconciliation *verdicts* -- Task 1's
        bulkhash.reconcile() output, ``{image_id: {state, feed_sha512,
        publish_date, deferral}}`` -- from *source* (one of
        HASH_VERIFICATION_SOURCES) onto the catalog.

        For every image_id present in BOTH *verdicts* and the catalog,
        writes the wire-compat ``hash_verification`` field onto its entry --
        ``{state, checked_at, feed_published_at, source, deferral}`` -- and
        keeps ``cisco_signature_verified = (state == "verified")`` in sync.
        An image_id in *verdicts* with no catalog entry is skipped (nothing
        to update, not an error); an image with no verdict entry in this
        call is left completely untouched -- this is a partial update, never
        a full resync.

        Quarantine -- stop seeding (the delete-image path's teardown,
        WITHOUT deleting the entry), block future assignment (enforced in
        set_policy(), above), and auto-unassign from every device currently
        holding it (one audit entry per affected device) -- fires iff, for a
        given image, its new state is "mismatch", it is NOT deferred, it is
        not ALREADY quarantined, AND the reported feed_sha512 is not one an
        operator has already overridden (see release_quarantine()). Not raw
        prior-state-changed, which is what makes this idempotent AND handles
        deferral correctly:

        - re-applying the same (or a different, still-mismatching) verdict
          never re-fires: the image is already quarantined.
        - not_in_feed and a deferred mismatch never quarantine at all.
        - a mismatch that WAS suppressed by deferral=True still fires the
          moment a LATER verdict reports the same mismatch with
          deferral=False -- it was never actually acted on, so "deferral
          flapping" cannot be used to dodge quarantine forever.
        - a mismatch an operator has override-released is NOT re-fired by
          re-applying the byte-identical verdict (the SAME feed_sha512) --
          an override would otherwise survive only until the next scheduled
          check. A DIFFERENT feed_sha512 is a new problem and still fires.
          The acknowledgement is cleared the moment a verdict reports the
          image verified, so a later regression back to that same value (a
          genuinely new occurrence, not a repeat of the acknowledged one)
          is not wrongly suppressed by a stale ack.

        Once quarantined, only release_quarantine() clears the block: a
        LATER verdict reporting "verified" here still updates
        hash_verification/cisco_signature_verified (the informational feed
        comparison is always kept truthful) but never silently lifts an
        active quarantine -- that would let the feed's own churn undo an
        operator-visible gate without anyone deciding to.

        Convergence: on EVERY call (regardless of what *verdicts* names),
        also retries the quarantine actions for any image that is
        quarantined but whose actions never fully completed -- a crash
        between the durable quarantined=True write and _fire_quarantine
        ever running, or a per-device set_policy failure a previous call
        could not finish, must not leave an image blocked-from-new-
        assignment while still actively assigned and seeding forever.
        _fire_quarantine() is itself safe to re-run: it only acts on
        devices/seeding that still need it.

        Raises ValueError, before writing anything, if *source* is not one
        of HASH_VERIFICATION_SOURCES or if any verdict's state is not one of
        bulkhash.STATE_VERIFIED/STATE_MISMATCH/STATE_NOT_IN_FEED -- an
        all-or-nothing validation pass, so a malformed call can never
        quarantine (or fail to record) only SOME of the images it names.

        Returns ``{"quarantined": [image_id, ...]}`` -- every image whose
        quarantine actions were (re-)fired in THIS call, whether newly
        transitioned or a retried leftover; ``{"newly_quarantined": [...]}``
        -- the subset that transitioned into quarantine JUST NOW."""
        if source not in HASH_VERIFICATION_SOURCES:
            raise ValueError(
                "source must be one of %s" % (HASH_VERIFICATION_SOURCES,))
        valid_states = (bulkhash.STATE_VERIFIED, bulkhash.STATE_MISMATCH,
                        bulkhash.STATE_NOT_IN_FEED)
        for image_id, v in verdicts.items():
            if v.get("state") not in valid_states:
                raise ValueError("verdict for %r has an unknown state: %r"
                                 % (image_id, v.get("state")))
        now = time.time() if now is None else now
        newly_quarantined = []
        # catalog.json is shared with save_image()/delete_image() (and the
        # separate-process iris-publish CLI), none of which take
        # image_policy_lock() -- only secrets_store.store_lock(catalog_path)
        # -- so the read-modify-write below must take BOTH, nested exactly
        # as image_policy_lock()'s own docstring documents (a distinct
        # sidecar file so the holder can still take the per-store lock
        # underneath) and as gui_images.ImageService.delete_image already
        # does. Without the inner lock, a concurrent publish landing between
        # this method's read and write is silently clobbered (or clobbers
        # this method's own write).
        with self.image_policy_lock():
            with secrets_store.store_lock(self.catalog_path):
                cat = self._read(self.catalog_path)
                images = cat.get("images", {})
                verdict_store = self._read(self.hash_verdicts_path)
                touched = False
                for image_id, v in verdicts.items():
                    entry = images.get(image_id)
                    if entry is None:
                        continue
                    state = v["state"]
                    deferral = bool(v.get("deferral"))
                    feed_sha512_norm = (v.get("feed_sha512") or "").strip().lower()
                    entry["hash_verification"] = {
                        "state": state,
                        "checked_at": int(now),
                        "feed_published_at": v.get("publish_date"),
                        "source": source,
                        "deferral": deferral,
                    }
                    entry["cisco_signature_verified"] = (
                        state == bulkhash.STATE_VERIFIED)
                    if state == bulkhash.STATE_VERIFIED:
                        # a resolved verdict retires any prior override ack --
                        # a LATER regression to that same value is a fresh
                        # occurrence, not a repeat of the one acknowledged.
                        entry.pop("quarantine_override_sha512", None)
                    already_acked = (
                        state == bulkhash.STATE_MISMATCH and feed_sha512_norm
                        and entry.get("quarantine_override_sha512")
                        == feed_sha512_norm)
                    if (state == bulkhash.STATE_MISMATCH and not deferral
                            and not entry.get("quarantined")
                            and not already_acked):
                        entry["quarantined"] = True
                        entry["quarantine_actions_complete"] = False
                        newly_quarantined.append(image_id)
                    images[image_id] = entry
                    verdict_store[image_id] = {
                        "state": state, "feed_sha512": v.get("feed_sha512"),
                        "publish_date": v.get("publish_date"),
                        "deferral": deferral, "checked_at": int(now),
                        "source": source,
                    }
                    touched = True
                if touched:
                    cat["images"] = images
                    _atomic_write_json(self.catalog_path, cat)
                    _atomic_write_json(self.hash_verdicts_path, verdict_store)
                # Convergence scan: every quarantined-but-incomplete image in
                # the WHOLE catalog, not just ones named by *verdicts* this
                # call -- see docstring.
                to_retry = sorted(
                    iid for iid, e in images.items()
                    if e.get("quarantined")
                    and not e.get("quarantine_actions_complete"))
        # Everything below runs OUTSIDE image_policy_lock (acting on state
        # the write above has ALREADY made durable -- the block-assignment
        # rule in set_policy() is live from that write onward) because
        # _fire_quarantine() calls set_policy() itself, which takes the same
        # lock; flock is not reentrant within one process, so nesting it
        # here would deadlock.
        for image_id in newly_quarantined:
            self._audit_event(
                event="image_quarantine", category="image",
                action="quarantine", target=image_id, actor="system",
                result="ok",
                detail="quarantined: sha512 mismatch against Cisco Bulk "
                       "Hash feed")
        for image_id in to_retry:
            if self._fire_quarantine(image_id):
                self._mark_quarantine_actions_complete(image_id)
        return {"quarantined": to_retry, "newly_quarantined": newly_quarantined}

    def _fire_quarantine(self, image_id):
        """Quarantine side effects for image_id, which
        apply_hash_verification() has ALREADY marked quarantined=True on
        disk (durably, before this ever runs). Stop seeding, then
        auto-unassign the image from every device that currently has it
        approved (set_policy minus the id, minus any OTHER already-
        quarantined id also sitting in that device's set -- set_policy
        refuses to write a set containing any quarantined id at all, so
        leaving a second one in would make this very cleanup call refuse
        itself), one audit entry per affected device -- ok on success,
        FAIL (never silently skipped) on a set_policy error, so a
        transient failure is on the record rather than vanishing.

        Idempotent/re-runnable by construction, which is what makes
        convergence (apply_hash_verification's docstring) safe: `affected`
        is recomputed fresh every call, so a device already cleaned up by a
        PRIOR call simply will not be in it, and re-attempting seeder
        teardown on an already-stopped torrent is a harmless no-op.

        Returns True iff EVERY action -- stop-seeding and every currently-
        affected device's auto-unassign -- succeeded this call. The caller
        only marks the quarantine's actions complete (so it stops being
        retried on future apply runs) when this is True."""
        entry = self.get_image(image_id)
        if entry is None:
            return True   # deleted since -- nothing left to converge toward
        ok = self._stop_seeding(entry)
        pol = self.list_policies()
        affected = sorted(
            did for did, p in pol.items()
            if image_id in (p.get("approved_image_ids") or
                            ([p["approved_image_id"]]
                             if p.get("approved_image_id") else [])))
        for did in affected:
            current = self.get_policy(did)["approved_image_ids"]
            remaining = [i for i in current
                        if not (self.get_image(i) or {}).get("quarantined")]
            try:
                self.set_policy(did, approved_image_ids=remaining)
            except Exception as exc:
                ok = False
                self._audit_event(
                    event="image_quarantine_auto_unassign", category="device",
                    action="unassign", target=did, actor="system",
                    result="fail",
                    detail="failed to auto-unassign %s: %s -- will retry "
                           "on the next apply run"
                           % (image_id, exc.__class__.__name__))
                continue   # keep trying the OTHER affected devices regardless
            self._audit_event(
                event="image_quarantine_auto_unassign", category="device",
                action="unassign", target=did, actor="system", result="ok",
                detail="auto-unassigned %s: failed Cisco Bulk Hash "
                       "verification" % image_id)
        return ok

    def _mark_quarantine_actions_complete(self, image_id):
        """Durably record that _fire_quarantine()'s actions for image_id
        have ALL converged -- called only when it returns True. Nested
        locking matches every other catalog.json read-modify-write (see
        apply_hash_verification); a no-op if the image was released or
        deleted in the meantime (nothing to mark)."""
        with self.image_policy_lock():
            with secrets_store.store_lock(self.catalog_path):
                cat = self._read(self.catalog_path)
                images = cat.get("images", {})
                entry = images.get(image_id)
                if entry is None or not entry.get("quarantined"):
                    return
                entry["quarantine_actions_complete"] = True
                images[image_id] = entry
                cat["images"] = images
                _atomic_write_json(self.catalog_path, cat)

    def release_quarantine(self, image_id, actor, override=False):
        """Lift an active quarantine on image_id -- the ONLY way one is
        lifted (apply_hash_verification() never auto-clears one; see its
        docstring).

        Re-runs the sha512 comparison against the STORED last feed verdict
        (from the most recent apply_hash_verification() call -- this never
        re-fetches or re-parses the feed itself, which is the pipeline's job
        and out of this module's reach) rather than trusting whatever
        hash_verification.state currently says, so an operator who has since
        corrected the catalog's own sha512 (replaced the bad file, fixed a
        publish-time error) sees that reflected immediately:

        - still mismatching -- including when no feed sha512 was ever
          recorded, e.g. a durably corrupted verdict record; that fails
          CLOSED, never treated as an implicit match -- requires
          override=True; without it, raises QuarantineStillMismatched and
          changes nothing. WITH it, the quarantine is lifted but
          hash_verification.state is left exactly as apply_hash_verification
          last wrote it ("mismatch" stays "mismatch"): overriding is a
          deliberate operator decision to permit assignment despite that,
          never a claim that it now verifies. The acknowledged feed_sha512
          is recorded on the entry so apply_hash_verification() does not
          silently re-quarantine on the next scheduled run's byte-identical
          verdict -- only a DIFFERENT feed_sha512 (a new problem) fires
          again; see its docstring.
        - now matching: a clean release. hash_verification.state and
          cisco_signature_verified are updated to "verified" (untouched
          since the quarantining apply_hash_verification() call), and the
          stored verdict is updated too, so a later call reads a consistent
          record rather than re-deriving "still mismatching" from a state
          that is no longer true.

        Either path is audited, with the override flag STRUCTURAL
        (action="release_override" vs "release"), not just prose in the
        detail, so it can be queried/alerted on.

        Raises KeyError if image_id is not in the catalog; ValueError if it
        is not currently quarantined (release is only ever a response to an
        active quarantine)."""
        # Nested locking: see apply_hash_verification's docstring/comment --
        # catalog.json is shared with save_image()/delete_image()/
        # iris-publish, none of which take image_policy_lock().
        with self.image_policy_lock():
            with secrets_store.store_lock(self.catalog_path):
                cat = self._read(self.catalog_path)
                images = cat.get("images", {})
                entry = images.get(image_id)
                if entry is None:
                    raise KeyError(image_id)
                if not entry.get("quarantined"):
                    raise ValueError("image %r is not quarantined" % image_id)
                verdict_store = self._read(self.hash_verdicts_path)
                stored = verdict_store.get(image_id) or {}
                feed_sha512 = (stored.get("feed_sha512") or "").strip().lower()
                current_sha512 = (entry.get("sha512") or "").strip().lower()
                still_mismatching = (
                    (not feed_sha512) or feed_sha512 != current_sha512)
                if still_mismatching and not override:
                    raise QuarantineStillMismatched(
                        image_id, entry.get("hash_verification"))
                entry["quarantined"] = False
                # No pending quarantine actions once released -- otherwise
                # apply_hash_verification's convergence scan (which keys
                # only on quarantined=True) simply never looks at this entry
                # again anyway, but leaving a stale False here would read as
                # "still incomplete" to anyone inspecting the entry directly.
                entry["quarantine_actions_complete"] = True
                if still_mismatching:
                    entry["quarantine_override_sha512"] = feed_sha512
                else:
                    entry.pop("quarantine_override_sha512", None)
                    hv = dict(entry.get("hash_verification") or {})
                    hv["state"] = bulkhash.STATE_VERIFIED
                    entry["hash_verification"] = hv
                    entry["cisco_signature_verified"] = True
                    if stored:
                        verdict_store[image_id] = dict(
                            stored, state=bulkhash.STATE_VERIFIED)
                images[image_id] = entry
                cat["images"] = images
                _atomic_write_json(self.catalog_path, cat)
                _atomic_write_json(self.hash_verdicts_path, verdict_store)
        self._audit_event(
            event="image_quarantine_release", category="image",
            action="release_override" if still_mismatching else "release",
            target=image_id, actor=actor, result="ok",
            detail=("override: sha512 still does not match the Cisco Bulk "
                    "Hash feed" if still_mismatching else
                    "released: sha512 now matches the Cisco Bulk Hash feed"))
        # The quarantine took the torrent out of the seeder; the release
        # puts it back (see _resume_seeding). The release itself is already
        # durable above -- a failed re-add is flagged in the result and
        # audited, not hidden, so the operator knows the image has no origin
        # seeder until it is resolved (a container restart re-seeds every
        # catalogued, non-quarantined torrent).
        resumed, reason = self._resume_seeding(image_id, entry)
        if self._seeder_add is not None:
            self._audit_event(
                event="image_quarantine_release_seeding", category="image",
                action="seed", target=image_id, actor=actor,
                result="ok" if resumed else "fail",
                detail="origin seeding resumed" if resumed else
                       "origin seeding NOT resumed (%s): no seeder until "
                       "fixed or the container restarts" % reason)
        return {"released": True, "override": still_mismatching,
                "state": entry["hash_verification"]["state"],
                "seeding_resumed": resumed}

    # --- device telemetry reports (bounded ring, issue #13) ---
    def record_telemetry(self, device_id, report):
        """Append *report* to the device's ring in telemetry.json
        ({device_id: [oldest..newest, <=TELEMETRY_RING]}), stamping
        received_at (the authoritative ingest clock, spec §2/§4).

        Version-aware durability (spec §4/§8):
        - **v2** reports are DEDUPED by ``report_id``: appending a report whose
          id already exists in the ring OR in the durable bounded per-device
          seen-report-id ledger (SEEN_REPORT_IDS) is a no-op. The ledger keeps
          dedupe idempotent even after the report has aged out of the small
          ring, so a crash-retry after ring eviction stays a no-op (stable
          report event ids, spec §4/§8) without unbounded state.
        - **v1** reports get a random stable ``_event_id`` stamped HERE, before
          the ring write, so OTLP can key a durable event id (there is no
          telemetry-process writeback API). It persists across restart.

        After the write, clears the pending pull directive — MATCH-GATED for v2
        pulls (only a report whose ``report_request_id`` equals the currently
        stored request id clears it; a stale/mismatched id cannot clear a newer
        request). The match-gated clear runs even when the v2 write was a dedupe
        no-op, so a crash-retry whose original clear was interrupted still
        clears the same still-pending pull. A v1 report (no id to echo)
        preserves the legacy bridge: it clears the device's pending request
        unconditionally, but only on a genuine (non-duplicate) append."""
        report = dict(report)
        report["received_at"] = time.time()
        is_v2 = report.get("schema") == "v2" or report.get("v") == 2
        if is_v2:
            rid = report.get("report_id")
        else:
            report.setdefault("_event_id", secrets.token_hex(16))
            rid = None
        outcome = {}

        def append(ring):
            ring = ring if isinstance(ring, list) else []
            duplicate = rid is not None and (
                any(isinstance(r, dict) and r.get("report_id") == rid
                    for r in ring)
                or self._report_id_seen(device_id, rid))
            outcome["duplicate"] = duplicate
            if duplicate:
                return None             # dedupe no-op: the shard is untouched
            return (ring + [report])[-self.TELEMETRY_RING:]

        # One device's ring in one shard, under that shard's lock: a report no
        # longer parses and rewrites every device's ring to append to one.
        self._reports.update(device_id, append)
        duplicate = outcome["duplicate"]
        if not duplicate and rid is not None:
            # Record the id in the durable bounded ledger AFTER the ring
            # write. A crash between the two only means the ring still
            # remembers this id (it is the newest), so a retry before
            # the ledger catches up still dedupes on the ring — no
            # double count, and the ledger makes it durable past
            # eviction.
            self._remember_report_id(device_id, rid)
        # AFTER the ring write, and deliberately NOT gated on `duplicate`.
        # The write is idempotent (first-write-wins per transfer_id), and a
        # crash between the ring write and this one leaves a retry -- itself a
        # ring dedupe no-op -- as the only thing that can still record the
        # attestation. Recording it there costs at worst a slightly later
        # ingest instant; skipping it costs the plan its promotion forever.
        self._remember_attestation(device_id, report)
        if is_v2:
            # Match-gated (spec §10.2b): only a pull report whose
            # report_request_id equals the stored request clears it. A v2
            # completion/seeding report (report_request_id=None) or a mismatched
            # pull id leaves the pending request intact. The clear runs even on
            # a DEDUPE no-op (duplicate report_id): if the original delivery
            # stored the report but its match-gated clear was interrupted (a
            # crash between the ring write and the clear), the crash-retry must
            # still clear the same still-pending pull — the clear is idempotent
            # and match-gated, so a superseded request is never wrongly cleared.
            rrid = report.get("report_request_id")
            if rrid is not None:
                self.clear_report_request(device_id, request_id=rrid)
        elif not duplicate:
            self.clear_report_request(device_id)

    def get_telemetry(self, device_id):
        reports = self._reports.get(device_id)
        return reports if isinstance(reports, list) else []

    def _report_id_seen(self, device_id, rid):
        """True iff *rid* is in the device's durable seen-report-id ledger.
        Read fresh (small bounded file); tolerant of a missing/garbage file."""
        led = self._report_ids.get(device_id)
        return isinstance(led, list) and rid in led

    def _remember_report_id(self, device_id, rid):
        """Append *rid* to the device's durable seen-report-id ledger, bounded
        FIFO at SEEN_REPORT_IDS (oldest purged). Idempotent: an id already
        present is not re-appended, so the ledger never grows on retries."""
        def remember(seen):
            seen = seen if isinstance(seen, list) else []
            if rid in seen:
                return None             # already durable; no write
            return (seen + [rid])[-self.SEEN_REPORT_IDS:]

        self._report_ids.update(device_id, remember)

    def get_transfer_attestations(self):
        """The whole durable attestation ledger, ``{device_id: [row, ...]}``.

        The tracker reads the FILE directly on its sample pass (it runs in a
        different process); this accessor is for callers that already hold a
        store, and for the tests that pin the ledger's shape."""
        return self._attestations.snapshot()

    def _remember_attestation(self, device_id, report):
        """Record that *report* attested completed, VERIFIED content.

        WHY A SECOND STORE AND NOT JUST THE RING. The tracker's
        transfer-lifecycle pass promotes a plan only on a terminal report
        bearing that plan's own transfer_id, and it re-derives that fact by
        reading telemetry.json at most once per sample pass. That ring keeps
        TELEMETRY_RING (5) reports PER DEVICE, shared by every image assigned
        to it and by every report kind. A device finishing several images
        inside one 60 s agent tick -- ten are assignable, and a flash-tight
        device posts a `seeding-only` report and then a `staging-complete`
        upgrade for each -- pushes the earliest terminal report out of the ring
        before any pass sees it. That fact is then NOT DERIVABLE FROM ANYWHERE:
        the plan latches its seeder observation, never its checksum, and sits
        at `planned` with no seeding_started ever emitted, for good. The same
        loss hits any report that lands while the tracker is restarting.

        So the fact is recorded HERE, at ingest, where it is known for certain,
        keyed by transfer so that one row per plan holds one slot however much
        other traffic the device posts. Bounded FIFO at ATTESTATIONS per
        device and purged with the device, like the report-id ledger beside it.

        FIRST-WRITE-WINS per transfer_id: the tracker latches the EARLIEST
        attesting instant, so a retry or a `staging-complete` upgrade of an
        already-attested `seeding-only` transfer must not move the value.

        Not every report attests -- transfer_lifecycle.attestation_from_report
        owns that rule, and owning it in ONE place is what keeps this write and
        the tracker's read of the ring from drifting apart about what counts.
        """
        fact = transfer_lifecycle.attestation_from_report(report)
        if fact is None:
            return
        def remember(rows):
            rows = [r for r in rows if isinstance(r, dict)] \
                if isinstance(rows, list) else []
            if any(r.get("transfer_id") == fact["transfer_id"] for r in rows):
                return None             # first-write-wins; no write
            return (rows + [fact])[-self.ATTESTATIONS:]

        self._attestations.update(device_id, remember)

    # --- pull directives (console-requested fresh reports) ---
    def request_report(self, device_id, now):
        """Flag *device_id* for a fresh report with a random 32-hex
        ``request_id`` (spec §10.2b). Returns False when a non-expired directive
        is already pending (one per device)."""
        refused = []

        def arm(ent):
            if isinstance(ent, dict) and now < ent.get("expires_at", 0):
                refused.append(True)
                return None             # already pending; no write
            return {"request_id": secrets.token_hex(16),
                    "requested_at": now,
                    "expires_at": now + self.PULL_TTL}

        self._pulls.update(device_id, arm)
        return not refused

    def pending_request(self, device_id, now):
        """The full non-expired pull directive dict for *device_id* (carrying
        ``request_id``), or None.

        Reaps THIS DEVICE's expired directive lazily. It used to reap the
        whole fleet's, which meant every heartbeat parsed — and, whenever any
        directive anywhere had lapsed, rewrote — the entire pull document.
        Another device's lapsed directive is reclaimed on that device's own
        next heartbeat or pull, or when it is purged from the fleet; it is a
        bounded, single, expired row that no reader ever honours, because
        every read applies the same expiry test."""
        found = []

        def reap(ent):
            if not isinstance(ent, dict):
                return keyed_state.DELETE if ent is not None else None
            if now >= ent.get("expires_at", 0):
                return keyed_state.DELETE
            found.append(dict(ent))
            return None                 # still pending: no write

        self._pulls.update(device_id, reap)
        return found[0] if found else None

    def pending_report(self, device_id, now):
        """Heartbeat directive for *device_id*: a dict
        ``{report_requested: True, report_request_id: <id>}`` when a non-expired
        pull is pending, else None (spec §10.2b)."""
        ent = self.pending_request(device_id, now)
        if ent is None:
            return None
        return {"report_requested": True,
                "report_request_id": ent.get("request_id")}

    def clear_report_request(self, device_id, request_id="__unset__"):
        """Clear the pending pull directive for *device_id*.

        MATCH-GATED (spec §10.2b): when *request_id* is supplied (v2 pull path)
        the clear happens ONLY if it equals the currently stored request id — a
        stale/mismatched id (e.g. echoing a superseded request) cannot clear a
        newer request. A ``None`` request id (v2 completion/seeding) or the
        default sentinel (v1 legacy bridge / explicit clear) clears
        unconditionally."""
        def clear(ent):
            if not isinstance(ent, dict):
                return None
            if request_id not in ("__unset__", None) \
                    and ent.get("request_id") != request_id:
                return None     # mismatched id: do not clear a newer request
            return keyed_state.DELETE

        self._pulls.update(device_id, clear)


def _id_list(value, cap=16):
    """A device-supplied list of image ids, sanitised: None when absent or
    malformed (absence is meaningful — a legacy agent — so never invent []),
    else up to *cap* non-empty strings. cap > MAX_ASSIGNED_IMAGES so a
    misbehaving agent cannot bloat the heartbeat store unbounded.

    A non-list, or a list holding anything other than image-id-shaped
    strings (_IMAGE_RE: at most 128 chars of [A-Za-z0-9._-]), is rejected
    wholesale as None rather than silently filtered down to [] — a filtered
    [] would be indistinguishable from a real agent's "nothing staged yet",
    turning malformed input into meaningful data instead of failing closed."""
    if not isinstance(value, list) or not all(
            isinstance(i, str) and (not i or _IMAGE_RE.fullmatch(i))
            for i in value):
        return None
    return [i for i in value[:cap] if i]


# Heartbeat field whitelist (spec §6 bounds). The heartbeat is the device's
# WHOLE stored record and is rewritten into devices.json on every tick, then
# copied verbatim into the console's /api/devices JSON -- so every field is
# typed and capped here. A value of the wrong type stores as None (the same
# "absent" the console already handles for a legacy agent) rather than
# failing the heartbeat, which would cost the device its policy poll.
_HEARTBEAT_STR_CAPS = {"current_image_id": 128, "version": 128,
                       "stage_state": 64, "stage_error": 1024,
                       "target_fs": 64, "model": 128}
_HEARTBEAT_BYTES_CAP = 2 ** 63 - 1


def _hb_str(value, cap):
    return value[:cap] if isinstance(value, str) else None


def _hb_bytes(value):
    """A non-negative, finite byte count as int, else None (bool is not a
    count; NaN/inf never arrive -- parse_json_body refuses the literals, but
    1e999 parses as inf and is refused here)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        value = int(value)
    if not isinstance(value, int) or not 0 <= value <= _HEARTBEAT_BYTES_CAP:
        return None
    return value


def _hb_bool(value):
    return value if isinstance(value, bool) else None


def sanitize_heartbeat(data, src_ip):
    """The stored heartbeat record for one device POST body (a dict)."""
    return {
        "current_image_id": _hb_str(data.get("current_image_id"),
                                    _HEARTBEAT_STR_CAPS["current_image_id"]),
        "free_flash_bytes": _hb_bytes(data.get("free_flash_bytes")),
        "version": _hb_str(data.get("version"), _HEARTBEAT_STR_CAPS["version"]),
        "stage_state": _hb_str(data.get("stage_state"),
                               _HEARTBEAT_STR_CAPS["stage_state"]),
        "stage_error": _hb_str(data.get("stage_error"),
                               _HEARTBEAT_STR_CAPS["stage_error"]),
        "target_fs": _hb_str(data.get("target_fs"),
                             _HEARTBEAT_STR_CAPS["target_fs"]),
        "model": _hb_str(data.get("model"), _HEARTBEAT_STR_CAPS["model"]),
        "telemetry_enabled": _hb_bool(data.get("telemetry_enabled")),
        "telemetry_stream_enabled": _hb_bool(
            data.get("telemetry_stream_enabled")),
        # Multi-image staging state (issue: multi-image assignment).
        # Sanitised via _id_list: absence/malformed input stores None
        # (a legacy or misbehaving agent), never an invented [] --
        # the console's fallback logic keys off staged_image_ids
        # being None to fall back to the singular stage_state/
        # current_image_id pair.
        "staged_image_ids": _id_list(data.get("staged_image_ids")),
        "errored_image_ids": _id_list(data.get("errored_image_ids")),
        # The heartbeat's source IP is the agent's Guest Shell IP — the
        # SAME IP it announces to the tracker with — so the swarm map can
        # join this device's model onto its swarm peer by IP.
        "swarm_ip": src_ip,
    }


def _device_image_view(entry):
    """Wire projection of one catalog image entry served to devices by
    Catalog.route_get (KGV / Cisco Bulk Hash reconciler review wave):
    every field the entry carries MINUS the two that exist purely for
    catalog.py's own internal bookkeeping (quarantine_actions_complete --
    convergence-retry state; quarantine_override_sha512 -- the
    re-quarantine-suppression ack) and were never meant to be wire-visible
    -- mirrors gui_server._image_view's console-side projection rationale.
    hash_verification and quarantined stay: an agent benefits from knowing
    its own assigned image's verification state same as a console operator
    does."""
    return {k: v for k, v in entry.items()
           if k not in ("quarantine_actions_complete",
                        "quarantine_override_sha512")}


class Catalog:
    def __init__(self, store, secrets_path,
                 audit_path=None, live_table=None, stream_settings=None,
                 deployment_open=True, deployment_checkpoint=None):
        self.store = store
        self.secrets_path = secrets_path
        # One stat-validated snapshot of the secret store and its strict
        # authorization index, shared by every request. Each request used to
        # re-parse the whole store and rebuild a fleet-wide reverse index to
        # resolve ONE credential; the snapshot rebuilds only when the store
        # file's stat identity changes, which every mint/rotate/revoke causes
        # (they all os.replace the file), in this process or in a CLI beside
        # it. See credential_cache.
        self.credentials = credential_cache.CredentialResolver(secrets_path)
        self.live_table = live_table
        self.stream_settings = stream_settings
        self.audit_path = (audit_path
                           or os.environ.get("IRIS_AUDIT",
                                             "/etc/iris/audit.jsonl"))
        # Deployment gate (spec §6): during the first identity-compatible
        # deployment the catalog refuses to serve any PERSONALIZED (device)
        # torrent until an explicit checkpoint is reached — the canonical
        # choice is binding the catalog to loopback so devices cannot reach
        # :8443, but this in-process flag additionally guarantees no
        # personalized GET is served before the checkpoint even if the bind is
        # misconfigured. ``personalized_served_count`` proves zero personalized
        # GETs before open.
        self.deployment_open = deployment_open
        self.deployment_checkpoint = deployment_checkpoint
        self.personalized_served_count = 0

    def open_deployment(self):
        """Reach the deployment checkpoint: personalized torrents may now be
        served (spec §6 — call only after rotate/reload/verify)."""
        self.deployment_open = True

    def _deployment_is_open(self):
        return (self.deployment_open
                and (self.deployment_checkpoint is None
                     or os.path.isfile(self.deployment_checkpoint)))

    def _load_store(self):
        """The secret store and the STRICT catalog authorization index, from
        one cached snapshot (spec §6: only the strict index authorizes).

        The returned store dict and index are SHARED and read-only. Every
        mutation path re-reads the store under ``secrets_store.store_lock``
        with its own ``secrets_store.load`` — see ``_handle_token_refresh``."""
        return self.credentials.view(
            "catalog", secrets_store.build_catalog_auth_index)

    def _announce_base_url(self):
        """Return the validated HTTPS tracker announce base URL (no query).

        Credentials are supplied to aria2 out-of-band as an Authorization
        header; they never appear in the torrent's announce URL. The base is
        taken from IRIS_TRACKER_ANNOUNCE if set, else derived from
        IRIS_HOST_IP + the tracker announce port. Missing or unsafe config
        raises rather than falling back to plaintext."""
        return tracker_announce.resolve(os.environ)

    def _personalized_torrent(self, image_id, announce_value,
                              tracker_auth="legacy-query"):
        """Return device torrent bytes for the requested tracker auth mode.

        Unified IOx/XR agents opt in to ``bearer`` and receive a token-free
        announce URL.  An absent selector retains the query credential needed
        by already-deployed Guest Shell aria2 bundles, which cannot attach a
        per-download HTTP header.  The canonical file is never mutated and its
        raw ``info`` byte span is preserved verbatim in both modes.  Neither
        the credential nor the resulting URL is logged or placed in errors.
        """
        base = self._announce_base_url()
        if not base:
            raise ValueError("tracker announce base unavailable")
        if tracker_auth == "legacy-query":
            sep = "&" if "?" in base else "?"
            base = "%s%sannounce_token=%s" % (
                base, sep, quote(announce_value, safe=""))
        elif tracker_auth != "bearer":
            raise ValueError("unsupported tracker authentication mode")
        with open(self.store.torrent_path(image_id), "rb") as f:
            canonical = f.read()
        return torrent_personalize.personalize(canonical, base)

    _STATE_UNAVAILABLE = (503, {"error": "state unavailable"})

    def route_get(self, path, auth_ctx=None, store_dict=None,
                  tracker_auth="legacy-query"):
        try:
            return self._route_get(path, auth_ctx=auth_ctx,
                                   store_dict=store_dict,
                                   tracker_auth=tracker_auth)
        except StateFileError:
            # An existing state file that cannot be read: refuse the request
            # rather than serve an empty (fleet-wide unassign) answer.
            return self._json(*self._STATE_UNAVAILABLE)

    def route_post(self, path, body, src_ip=None, store=None, index=None,
                   token=None):
        try:
            return self._route_post(path, body, src_ip=src_ip, store=store,
                                    index=index, token=token)
        except StateFileError:
            return self._json(*self._STATE_UNAVAILABLE)

    def _route_get(self, path, auth_ctx=None, store_dict=None,
                   tracker_auth="legacy-query"):
        parts = urlsplit(path).path.strip("/").split("/")
        principal = getattr(auth_ctx, "principal", None)
        device_id = (principal.id if getattr(principal, "type", None) == "device"
                     else None)
        service_principal = getattr(principal, "type", None) == "service"
        # Device-facing catalog resources are a projection of that device's
        # assignment, not a shared inventory.  Authentication has already
        # succeeded in Handler._guard; an unassigned id is deliberately the
        # same 404 as an unknown id so one device cannot enumerate another
        # device's approved images.
        assigned = set(self.store.get_policy(device_id)["approved_image_ids"]) \
            if device_id is not None else set()
        if parts == ["v1", "images"]:
            return self._json(200, {"images": [
                _device_image_view(i) for i in self.store.list_images()
                if service_principal or i.get("id") in assigned]})
        if len(parts) == 3 and parts[:2] == ["v1", "images"]:
            if not service_principal and parts[2] not in assigned:
                return self._json(404, {"error": "no such image"})
            img = self.store.get_image(parts[2])
            return self._json(200, _device_image_view(img)) if img else \
                self._json(404, {"error": "no such image"})
        if len(parts) == 3 and parts[:2] == ["v1", "torrents"]:
            image_id = parts[2][:-len(".torrent")] \
                if parts[2].endswith(".torrent") else parts[2]
            if not service_principal and image_id not in assigned:
                return self._json(404, {"error": "no such torrent"})
            return self._route_torrent(image_id, auth_ctx, store_dict,
                                       tracker_auth=tracker_auth)
        if len(parts) == 4 and parts[:2] == ["v1", "devices"] \
                and parts[3] == "policy":
            # device_policy_view, not get_policy: the agent adopts the
            # server-minted transfer_id from the ``plans`` map, and this poll
            # is the earliest point of the agent's tick -- ahead of the
            # download and of every telemetry touch -- so the id is in hand
            # before anything can mint one of its own.
            return self._json(200, self.store.device_policy_view(parts[2]))
        return self._json(404, {"error": "not found"})

    # Extra response headers the handler must emit for a personalized torrent
    # so proxies/browsers never cache a device-specific body (spec §6).
    _PERSONALIZED_HEADERS = (
        ("Cache-Control", "private, no-store"),
        ("Vary", "Authorization, X-IRIS-Tracker-Auth"),
    )

    def _route_torrent(self, image_id, auth_ctx, store_dict,
                       tracker_auth="legacy-query"):
        """Serve a torrent per the resolved principal (spec §6).

        - device principal: in-memory personalized torrent carrying ONLY that
          device's valid announce token; missing announce credential fails
          CLOSED (never a seeder fallback).
        - service / other internal principal: canonical bytes, unmodified.

        No announce token, announce URL, or query string is ever placed in an
        error body, log, or audit entry — only the image id, principal, and a
        boolean outcome are non-secret."""
        if not os.path.exists(self.store.torrent_path(image_id)):
            return self._json(404, {"error": "no such torrent"})

        principal = getattr(auth_ctx, "principal", None)
        ptype = getattr(principal, "type", None)

        if ptype == "device":
            # Deployment gate: refuse to serve any personalized torrent before
            # the checkpoint (spec §6 — proves zero personalized GET pre-open).
            if not self._deployment_is_open():
                return self._json(
                    503, {"error": "catalog not open for device personalization"})
            now = time.time()
            grace = int(os.environ.get("IRIS_TOKEN_SKEW_GRACE", "300"))
            announce_value = secrets_store.device_announce_value(
                store_dict or {}, principal.id, now, grace)
            if not announce_value:
                # Fail closed: never fall a device back to the seeder token.
                return self._json(
                    500, {"error": "no announce credential for device"})
            try:
                body = self._personalized_torrent(
                    image_id, announce_value, tracker_auth=tracker_auth)
            except Exception:
                # Any personalization/invariant failure -> 500, no token/URL
                # in the message (spec §6 no-leak).
                return self._json(
                    500, {"error": "torrent personalization failed"})
            self.personalized_served_count += 1
            return (200, "application/x-bittorrent", body,
                    self._PERSONALIZED_HEADERS)

        # Service / internal (or, defensively, unresolved) principal: canonical.
        try:
            with open(self.store.torrent_path(image_id), "rb") as f:
                return (200, "application/x-bittorrent", f.read())
        except OSError:
            return self._json(404, {"error": "no such torrent"})

    def _route_post(self, path, body, src_ip=None, store=None, index=None,
                    token=None):
        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[:2] == ["v1", "devices"] \
                and parts[3] == "heartbeat":
            try:
                data = parse_json_body(body)
            except ValueError:
                return self._json(400, {"error": "bad json"})
            if not isinstance(data, dict):
                return self._json(400, {"error": "bad json"})
            self.store.record_heartbeat(
                parts[2], sanitize_heartbeat(data, src_ip))
            # Live telemetry (spec §3/§10.1): a v2 `telemetry_observation`
            # envelope supersedes the legacy v1 `sample` on v2 agents; a bad
            # envelope/sample NEVER fails the heartbeat — reject-and-count.
            # The server cross-checks the device's telemetry flags and the
            # global stream pause and the policy assignment: telemetry off /
            # paused / unassigned / errored -> WITHDRAW the live value even if
            # an `observed` envelope arrived, without inventing transfer fields.
            if self.live_table is not None:
                # Membership against the WHOLE assigned set, not just the
                # first (singular) member -- a live sample for a device's
                # 2nd+ assigned image must sanitize clean, matching the v2
                # telemetry-report ingest check above.
                approved = self.store.get_policy(parts[2]).get(
                    "approved_image_ids") or []
                every, paused = 1, False
                if self.stream_settings is not None:
                    every, paused = self.stream_settings.read()
                tele_off = (data.get("telemetry_enabled") is False
                            or data.get("telemetry_stream_enabled") is False
                            or paused or not approved)
                # Withdraw under the SERVER's own reason rather than flattening
                # every cause to not_active (spec 3A obs_state fidelity). The
                # value is derived from the heartbeat flags + stream settings
                # this server already trusts, never from the device's claimed
                # obs_state, and the ladder mirrors the agent's: the master
                # toggle outranks the stream toggle, which outranks assignment.
                if data.get("telemetry_enabled") is False:
                    off_state = "disabled"
                elif data.get("telemetry_stream_enabled") is False or paused:
                    off_state = "paused"
                else:
                    off_state = "not_active"
                obs = data.get("telemetry_observation")
                sample = data.get("sample")
                if tele_off:
                    # Policy-driven withdrawal (telemetry flags off / global
                    # stream pause / device unassigned) takes precedence over
                    # and is INDEPENDENT of the approved-image sanitizer: the
                    # live rate/state is withdrawn as not_active NOW, and an
                    # image mismatch on the (now-superseded) envelope must not
                    # bypass that withdrawal by short-circuiting to reject.
                    # This is not a malformed-sample reject, so the reject
                    # counter is left untouched — only a genuinely malformed
                    # envelope WHILE still assigned rejects/leaves prior good.
                    if obs is not None or sample is not None:
                        self.live_table.withdraw(parts[2], off_state)
                elif obs is not None:
                    try:
                        clean, _trunc = live_samples.sanitize_observation(
                            obs, approved, every)
                        self.live_table.observe(
                            parts[2], clean, time.time(), every)
                    except ValueError:
                        self.live_table.reject()
                elif sample is not None:
                    try:
                        clean = live_samples.sanitize_sample(sample, approved)
                        self.live_table.observe(
                            parts[2], clean, time.time(), every)
                    except ValueError:
                        self.live_table.reject()
            resp = {"ok": True}
            if self.stream_settings is not None:
                every, pause = self.stream_settings.read()
                resp["stream_every"] = every
                resp["stream_pause"] = pause
            directive = self.store.pending_report(parts[2], time.time())
            if directive is not None:
                resp["report_requested"] = True
                rrid = directive.get("report_request_id")
                if rrid is not None:
                    resp["report_request_id"] = rrid
            return self._json(200, resp)
        if len(parts) == 4 and parts[:2] == ["v1", "devices"] \
                and parts[3] == "telemetry":
            try:
                data = parse_json_body(body)
            except ValueError:
                return self._json(400, {"error": "bad json"})
            try:
                report = _sanitize_report(data)
            except ValueError:
                return self._json(400, {"error": "bad report"})
            if report.get("schema") == "v2":
                assigned = self.store.get_policy(parts[2]).get(
                    "approved_image_ids") or []
                if report.get("image_id") not in assigned:
                    return self._json(400, {"error": "bad report"})
            self.store.record_telemetry(parts[2], report)
            return self._json(200, {"ok": True})
        if len(parts) == 4 and parts[:2] == ["v1", "devices"] \
                and parts[3] == "token-refresh":
            return self._handle_token_refresh(
                parts[2], src_ip=src_ip, store=store, index=index,
                token=token)
        return self._json(404, {"error": "not found"})

    def _handle_token_refresh(self, device_id, src_ip=None, store=None,
                               index=None, token=None):
        """Rotate or recover the catalog token and return the secret bag.

        The *store* passed in was loaded (pre-lock) by _guard for auth.  The
        mutation here must NOT operate on that snapshot: under the threaded
        server two overlapping refreshes would each rotate their own stale
        snapshot and the second save() would clobber the first (lost rotation,
        which can strand a device).  We take the per-store advisory lock and
        RE-READ the store fresh under it, so the load->mutate->save->encrypt
        cycle is serialized and never loses a concurrent rotation/revoke.
        """
        overlap = int(os.environ.get("IRIS_TOKEN_OVERLAP", "120"))
        grace = int(os.environ.get("IRIS_TOKEN_SKEW_GRACE", "300"))
        secrets_path = self.secrets_path

        with secrets_store.store_lock(secrets_path):
            # Re-read under the lock; discard the pre-lock auth snapshot.
            store = secrets_store.load(secrets_path)
            now = time.time()

            device_secrets = store.get("devices", {}).get(device_id, {})
            current_record = device_secrets.get("catalog_token")
            current_val = current_record.get("value", "") \
                if isinstance(current_record, dict) else ""

            # Re-check revoke status under the lock.  _guard authorized against
            # a PRE-LOCK snapshot; if iris-revoke won the lock first and marked
            # this device revoked in the meantime, the snapshot is stale.
            # rotate_catalog/mint always write revoked=False, so rotating now
            # would silently un-revoke the device (hand it a fresh live token).
            # Abort instead — this closes the TOCTOU the lock made deterministic.
            if current_record is not None and current_record.get("revoked"):
                try:
                    audit.append_event(
                        self.audit_path, "refresh_fail", device_id,
                        secret_name="catalog_token",
                        old_id=_audit_id(current_val),
                        src_ip=src_ip,
                        detail="device is revoked",
                        result="fail",
                    )
                except Exception:
                    pass
                return self._json(409, {"error": "device revoked"})

            # Re-resolve against the fresh, under-lock store. Two requests can
            # both pass _guard with the same current token; after the first
            # rotates, the second must recover that successor rather than mint
            # another one. Revoke and a newer rotation also win here.
            try:
                strict = secrets_store.build_catalog_auth_index(store)
            except secrets_store.DuplicateCredentialError:
                strict = {}
            ctx = _resolve_refresh_auth(store, strict, token, now, grace)
            if (ctx is None or ctx.principal.type != "device"
                    or ctx.principal.id != device_id
                    or ctx.secret_name not in (
                        "catalog_token", "catalog_token_prev")):
                return self._json(401, {"error": "unauthorized"})

            recovering = ctx.secret_name == "catalog_token_prev"
            if recovering:
                # The server already committed this successor. Reissue the
                # current bag unchanged so a lost 200 or failed device conf
                # rewrite can converge on the next tick.
                new_val = current_val
            else:
                old_record = current_record
                old_val = current_val
                # Shared routes retain the old token for only the short overlap.
                # token-refresh additionally remembers the token's ORIGINAL
                # expiry: recovery cannot outlive the credential the device
                # presented, but a 120-second delivery failure cannot strand a
                # token that otherwise had days left.
                if old_record:
                    recovery_expires_at = int(float(
                        old_record.get("expires_at", 0) or 0))
                    store["devices"][device_id]["catalog_token_prev"] = {
                        "value": old_val,
                        "created_at": int(float(
                            old_record.get("created_at", now))),
                        "expires_at": int(now) + overlap,
                        "refresh_expires_at": recovery_expires_at,
                        "revoked": False,
                        "_scope": "catalog",
                    }

                new_val = secrets_store.rotate_catalog(
                    store, device_id, now, overlap)

                # Persist durable-FIRST: the at-rest .age ciphertext is the only
                # copy that survives a restart, so it must be written (and confirmed)
                # before the live tmpfs plaintext is swapped in.  If the durable
                # write fails, persist_store leaves the tmpfs store untouched and
                # raises; we then report failure rather than a phantom rotation that
                # a restart would silently roll back.
                recipients = os.environ.get("IRIS_AGE_RECIPIENTS", "")
                enc_path = os.environ.get(
                    "IRIS_SECRETS_ENC", "/etc/iris/secrets.json.age")
                try:
                    secretfs.persist_store(
                        store, secrets_path,
                        recipients_csv=recipients, enc_path=enc_path)
                except Exception as exc:
                    # Durable write failed: nothing was committed to the live store,
                    # so there is no rotation to roll back and no divergence.  Audit
                    # the failed persist and refuse to report success.
                    try:
                        audit.append_event(
                            self.audit_path, "refresh_fail", device_id,
                            secret_name="catalog_token",
                            old_id=_audit_id(old_val),
                            src_ip=src_ip,
                            detail="durable persist failed",
                            result="fail",
                        )
                    except Exception:
                        pass
                    return self._json(
                        500, {"error": "durable persist failed: %s" % exc})

                # Audit the refresh (only after the rotation is durably committed)
                audit.append_event(
                    self.audit_path, "refresh", device_id,
                    secret_name="catalog_token",
                    old_id=_audit_id(old_val),
                    new_id=_audit_id(new_val),
                    src_ip=src_ip,
                )

        # Build the response bag: catalog_token + expires_at, plus
        # announce_token / rpc_secret ONLY when the device actually has them.
        # The agent persists a returned secret when `bag.get(name) is not None`
        # (iris_agent._refresh_impl), so it can keep its current working value
        # for a field the server omits.  Sending "" for an absent record would
        # be `not None` and make the agent overwrite its live announce_token /
        # rpc_secret with "", stranding it off the swarm and the aria2 RPC.
        device_secrets = store.get("devices", {}).get(device_id, {})
        # After rotate, the NEW record is in the store under catalog_token
        new_cat_rec = device_secrets.get("catalog_token", {})
        bag = {
            "catalog_token": new_val,
            "expires_at": new_cat_rec.get("expires_at", 0),
        }
        ann_val = device_secrets.get("announce_token", {}).get("value")
        if ann_val:
            bag["announce_token"] = ann_val
        rpc_val = device_secrets.get("rpc_secret", {}).get("value")
        if rpc_val:
            bag["rpc_secret"] = rpc_val
        return self._json(200, bag)

    @staticmethod
    def _json(status, obj):
        return (status, "application/json",
                json.dumps(obj, allow_nan=False).encode())


def make_server(host, port, store, secrets_path, certfile=None,
                audit_path=None, live_table=None, stream_settings=None,
                deployment_open=True, deployment_checkpoint=None,
                management_token_file=None,
                management_previous_token_file=None):
    cat = Catalog(store, secrets_path, audit_path=audit_path,
                   live_table=live_table, stream_settings=stream_settings,
                   deployment_open=deployment_open,
                   deployment_checkpoint=deployment_checkpoint)

    grace = int(os.environ.get("IRIS_TOKEN_SKEW_GRACE", "300"))

    class Handler(BaseHTTPRequestHandler):
        # Socket inactivity timeout: StreamRequestHandler.setup applies it
        # with settimeout, so a stalled readline/read raises TimeoutError and
        # handle_one_request closes the connection instead of pinning the
        # thread forever (IRIS-02-003).
        timeout = handler_timeout()

        def _guard(self, parts, token):
            """Route-aware guard.

            Device-bound routes (heartbeat, telemetry, policy): require the
            current device catalog_token resolving to that device's
            principal. token-refresh additionally accepts that same device's
            one previous token for idempotent delivery recovery; it grants no
            other route.

            Image and torrent routes resolve a device principal here and are
            projected onto that principal's assignment in ``_route_get``.
            Policy is device-bound rather than shared
            because device_policy_view() carries per-transfer ids
            (plan_id/transfer_id, spec §9) minted for THIS device's
            assignment -- a shared route would let any enrolled device walk
            /v1/devices then /v1/devices/<id>/policy for every id and read
            every other device's plan/transfer ids.

            Returns ``(store_dict, index, auth_ctx)`` on success (auth_ctx is a
            typed ``auth.AuthContext`` for the resolved principal) or
            ``(None, None, None)`` on auth failure. Every authorization decision
            is made through the STRICT catalog auth index (spec §6): the broad
            ``secrets_store.build_index`` never authorizes, and is no longer
            built at all — it was rebuilt across the whole fleet on every
            request and its only consumer, token-refresh, discards it and
            re-reads the store under the store lock.
            """
            store_dict, strict = cat._load_store()
            # route_post compatibility slot only: the broad reverse index is
            # never an authorization surface, and token-refresh (its only
            # consumer's only route) re-reads the store under the store lock.
            index = None
            now = time.time()

            # Determine if this is a device-bound route
            is_device_bound = (
                len(parts) == 4
                and parts[:2] == ["v1", "devices"]
                and parts[3] in ("heartbeat", "token-refresh", "telemetry",
                                 "policy")
            )

            if is_device_bound:
                device_id = parts[2]
                is_refresh = parts[3] == "token-refresh"
                ctx = _resolve_refresh_auth(
                    store_dict, strict, token, now, grace) if is_refresh \
                    else auth.resolve_catalog_auth(
                        store_dict, strict, token, now, grace)
                ok = (ctx is not None
                      and ctx.principal.type == "device"
                      and ctx.principal.id == device_id
                      and (ctx.secret_name == "catalog_token"
                           or (is_refresh and ctx.secret_name
                               == "catalog_token_prev")))
                if not ok:
                    # Audit auth failure for token-refresh routes
                    if parts[3] == "token-refresh":
                        try:
                            audit.append_event(
                                # Authentication failed, so the path segment
                                # is attacker-controlled rather than a device
                                # identity. Never amplify it into the durable
                                # audit log (or expose its shape via validation).
                                cat.audit_path, "auth_fail", "unresolved",
                                src_ip=self.client_address[0],
                                result="fail",
                            )
                        except Exception:
                            pass
                    return None, None, None
                return store_dict, index, ctx

            # Collection/item/torrent routes still resolve a typed device
            # principal.  The route implementation intersects the requested
            # resource with that principal's policy. A rolled-old token works
            # during its short overlap, then only token-refresh may recover it.
            ctx = auth.resolve_catalog_auth(
                store_dict, strict, token, now, grace)
            if ctx is None:
                return None, None, None
            return store_dict, index, ctx

        def _extract_token(self):
            value = self.headers.get("Authorization", "")
            prefix = "Bearer "
            if not value.startswith(prefix) or value.count(" ") != 1:
                return None
            return value[len(prefix):]

        def _problem(self, status, code, title, headers=()):
            api_problem.send(self, status, code, title, headers=headers)

        def _send(self, triple):
            # triple is (status, ctype, body) or
            # (status, ctype, body, extra_headers) where extra_headers is an
            # iterable of (name, value) pairs (e.g. personalized-torrent
            # Cache-Control/Vary, spec §6).
            extra_headers = ()
            if len(triple) == 4:
                status, ctype, body, extra_headers = triple
            else:
                status, ctype, body = triple
            if status >= 400 and ctype.startswith("application/json"):
                try:
                    doc = json.loads(body)
                except (TypeError, ValueError):
                    doc = {"error": "request failed"}
                api_problem.legacy(self, status, doc, headers=extra_headers)
                return
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            if urlsplit(self.path).path.endswith("/token-refresh"):
                # The response can carry three live credentials.  Never let a
                # browser, proxy, or intermediary retain it beyond delivery.
                self.send_header("Cache-Control", "private, no-store")
            for name, value in extra_headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            token = self._extract_token()
            if not token:
                self._problem(401, "catalog-authentication-required",
                              "Catalog authentication required",
                              (("WWW-Authenticate", "Bearer"),))
                return
            parts = urlsplit(self.path).path.strip("/").split("/")
            try:
                store_dict, index, auth_ctx = self._guard(parts, token)
            except (secrets_store.StoreCorruptError,
                    secrets_store.DuplicateCredentialError, OSError):
                self._problem(503, "credential-store-unavailable",
                              "Credential store unavailable")
                return
            if store_dict is None:
                self._problem(401, "catalog-authentication-required",
                              "Catalog authentication required",
                              (("WWW-Authenticate", "Bearer"),))
                return
            if api_routes.match("catalog", "GET", self.path) is None:
                self._problem(404, "route-not-found", "Route not found")
                return
            tracker_auth = "legacy-query"
            if len(parts) == 3 and parts[:2] == ["v1", "torrents"]:
                selector = self.headers.get("X-IRIS-Tracker-Auth")
                if selector is not None:
                    if selector != "bearer":
                        self._problem(400, "invalid-tracker-auth-selector",
                                      "Invalid tracker authentication selector")
                        return
                    tracker_auth = selector
            self._send(cat.route_get(
                self.path, auth_ctx=auth_ctx, store_dict=store_dict,
                tracker_auth=tracker_auth))

        def do_POST(self):
            token = self._extract_token()
            if not token:
                self._problem(401, "catalog-authentication-required",
                              "Catalog authentication required",
                              (("WWW-Authenticate", "Bearer"),))
                return
            parts = urlsplit(self.path).path.strip("/").split("/")
            try:
                store_dict, index, auth_ctx = self._guard(parts, token)
            except (secrets_store.StoreCorruptError,
                    secrets_store.DuplicateCredentialError, OSError):
                self._problem(503, "credential-store-unavailable",
                              "Credential store unavailable")
                return
            if store_dict is None:
                self._problem(401, "catalog-authentication-required",
                              "Catalog authentication required",
                              (("WWW-Authenticate", "Bearer"),))
                return
            if api_routes.match("catalog", "POST", self.path) is None:
                self._problem(404, "route-not-found", "Route not found")
                return
            # A chunked (or otherwise length-less) POST is refused rather than
            # read as an empty body: on the heartbeat route an empty body IS
            # the device's whole stored record, so silently accepting one
            # would blank every field the console relies on.
            if self.headers.get("Transfer-Encoding") \
                    or self.headers.get("Content-Length") is None:
                self._problem(411, "content-length-required",
                              "Content-Length required")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._problem(400, "invalid-content-length",
                              "Invalid Content-Length")
                return
            if length < 0:
                self._problem(400, "invalid-content-length",
                              "Invalid Content-Length")
                return
            if length > MAX_BODY_BYTES:
                # Refuse before reading: the declared length is untrusted and
                # could be arbitrarily large.
                self._problem(413, "payload-too-large", "Payload too large")
                return
            body = self.rfile.read(length) if length else b""
            enc = self.headers.get("Content-Encoding", "")
            if enc.strip().lower() == "gzip":
                try:
                    # A bounded streaming read avoids allocating an attacker's
                    # complete decompressed payload before enforcing the cap.
                    with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
                        body = gz.read(MAX_BODY_BYTES + 1)
                except Exception:
                    self._problem(400, "invalid-request-body",
                                  "Invalid request body")
                    return
                if len(body) > MAX_BODY_BYTES:
                    # Bomb guard: re-check the DECOMPRESSED size.
                    self._problem(413, "payload-too-large", "Payload too large")
                    return
            self._send(cat.route_post(
                self.path, body, self.client_address[0],
                store=store_dict, index=index, token=token))

        def _unsupported(self):
            """Authenticate before disclosing unsupported method handling."""
            token = self._extract_token()
            if not token:
                self._problem(401, "catalog-authentication-required",
                              "Catalog authentication required",
                              (("WWW-Authenticate", "Bearer"),))
                return
            parts = urlsplit(self.path).path.strip("/").split("/")
            try:
                store_dict, _index, _ctx = self._guard(parts, token)
            except (secrets_store.StoreCorruptError,
                    secrets_store.DuplicateCredentialError, OSError):
                self._problem(503, "credential-store-unavailable",
                              "Credential store unavailable")
                return
            if store_dict is None:
                self._problem(401, "catalog-authentication-required",
                              "Catalog authentication required",
                              (("WWW-Authenticate", "Bearer"),))
                return
            self._problem(405, "method-not-allowed", "Method not allowed",
                          (("Allow", "GET, POST"),))

        do_PUT = _unsupported
        do_DELETE = _unsupported
        do_PATCH = _unsupported
        do_HEAD = _unsupported
        do_OPTIONS = _unsupported

        def __getattr__(self, name):
            if name.startswith("do_"):
                return self._unsupported
            raise AttributeError(name)

        def log_message(self, *args):
            pass

    srv = _CatalogServer((host, port), Handler)
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile)
        # Handshake per connection in the worker thread, NOT by wrapping the
        # listening socket: see _CatalogServer.
        srv.tls_context = ctx
    return srv


def main():
    host = os.environ.get("IRIS_CATALOG_HOST", "0.0.0.0")
    port = int(os.environ.get("IRIS_CATALOG_PORT", "8443"))
    state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
    store = CatalogStore(state_dir)
    secrets_path = os.environ.get("IRIS_SECRETS", "/run/iris/secrets.json")
    cert = os.environ.get("IRIS_CERT", "/etc/iris/tls/cert.pem")
    certfile = cert if os.path.exists(cert) else None
    if certfile is None and not _plaintext_allowed():
        # The catalog answers device bearer tokens on every route; a
        # plaintext listener puts every one of them on the wire in clear
        # text. Same fail-closed contract as the console
        # (gui_server.main / IRIS_GUI_ALLOW_PLAINTEXT): refuse to start
        # rather than silently downgrade. The shipped docker-entrypoint.sh
        # always provisions IRIS_CERT, so this is only reachable running
        # catalog.py directly outside the supported deployment.
        print("iris-catalog: no certificate found (IRIS_CERT=%s); refusing "
              "to serve the catalog over plain HTTP -- it answers device "
              "bearer tokens on every route. Set %s=1 to opt in "
              "deliberately (loopback or an isolated lab network only)."
              % (cert, _PLAINTEXT_OPT_IN_ENV), file=sys.stderr, flush=True)
        sys.exit(2)
    live_table = live_samples.LiveTable()
    stream_settings = live_samples.StreamSettings(
        os.path.join(state_dir, "telemetry-settings.json"))
    require_identity_gate = os.environ.get("IRIS_REQUIRE_IDENTITY_GATE") == "1"
    deployment_checkpoint = (os.path.join(
        state_dir, "identity-compatible-ready") if require_identity_gate else None)
    stop = threading.Event()
    threading.Thread(
        target=live_samples.writer_loop,
        args=(live_table, os.path.join(state_dir, "live-samples.json"),
              live_samples.SNAPSHOT_WRITE_INTERVAL, stop),
        daemon=True).start()
    srv = make_server(host, port, store, secrets_path, certfile=certfile,
                      live_table=live_table, stream_settings=stream_settings,
                      deployment_checkpoint=deployment_checkpoint,
                      management_token_file=os.environ.get(
                          "IRIS_MANAGEMENT_API_TOKEN_FILE") or None,
                      management_previous_token_file=os.environ.get(
                          "IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE") or None)
    scheme = "https" if certfile else "http"
    print("catalog on %s://%s:%d/v1/images" % (scheme, host, port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
