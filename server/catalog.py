#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""IRIS catalog: HTTPS JSON API + torrent serving. State is JSON files
under the state dir, written atomically and re-read per request. Bearer-token
auth on every endpoint. The server publishes images and a per-device
install-approval flag but NEVER triggers install (spec §6). Stdlib only."""
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
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import audit
import auth
import live_samples
import secretfs
import secrets_store
import torrent_personalize


def _audit_id(value):
    """Derive a short, non-secret correlation id from a token value.

    The audit log lives on the unencrypted /etc/iris volume, so it must never
    carry any portion of a live token: value[:8] would leak 32 bits of the
    secret.  A truncated sha256 is correlatable across events but reveals
    nothing about the underlying token."""
    if not value:
        return ""
    return hashlib.sha256(value.encode()).hexdigest()[:8]


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
            json.dump(obj, f, indent=2, sort_keys=True)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# Global POST body cap (also applied to gzip-DECOMPRESSED bodies — bomb guard).
MAX_BODY_BYTES = 65536

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


def _bounded_report_int(value, cap):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("report field not an int")
    if not 0 <= value <= cap:
        raise ValueError("report field out of bounds")
    return value


def _sanitize_report_v2(data):
    """Strict server-side re-validation of a v2 terminal report (spec §10.2).

    Exact types/enums/ids/timestamps; content/verification/sampling/stage/peer
    caps; stored body bounded at _REPORT_STORE_MAX. Tags ``schema:"v2"``.
    ``report_id`` is the ring dedupe key. No token/secret ever appears in a
    raised message (a report carries none, but the discipline is explicit)."""
    report_id = data.get("report_id")
    if not isinstance(report_id, str) or not _HEX32.match(report_id):
        raise ValueError("bad report_id")
    transfer_id = data.get("transfer_id")
    if not isinstance(transfer_id, str) or not _HEX32.match(transfer_id):
        raise ValueError("bad transfer_id")
    event = data.get("event")
    if event not in _REPORT_EVENTS:
        raise ValueError("bad event")
    rrid = data.get("report_request_id")
    if event == "pull":
        if rrid is not None and (not isinstance(rrid, str)
                                 or not _HEX32.match(rrid)):
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
    if not isinstance(image_id, str) or not _IMAGE_RE.match(image_id):
        raise ValueError("bad image_id")

    win = data.get("window")
    if not isinstance(win, dict):
        raise ValueError("bad window")
    for key in ("start", "end"):
        v = win.get(key)
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise ValueError("bad window.%s" % key)
        if not math.isfinite(v) or v < 0:
            raise ValueError("bad window.%s" % key)
    if win["start"] > win["end"]:
        raise ValueError("bad window order")
    if not isinstance(win.get("complete"), bool):
        raise ValueError("bad window.complete")

    content = data.get("content")
    if not isinstance(content, dict):
        raise ValueError("bad content")
    content_out = {
        "completed_content_bytes": _bounded_report_int(
            content.get("completed_content_bytes"), _CONTENT_CAP),
        "total_content_bytes": _bounded_report_int(
            content.get("total_content_bytes"), _CONTENT_CAP)}
    if content_out["completed_content_bytes"] > content_out["total_content_bytes"]:
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
    if peers_total < len(rows):
        raise ValueError("peers_total below rows")
    for key in ("peers_truncated", "peers_saturated"):
        if not isinstance(data.get(key), bool):
            raise ValueError("bad %s" % key)

    report = {"v": 2, "schema": "v2", "report_id": report_id,
              "transfer_id": transfer_id, "report_request_id": rrid,
              "report_created_at": float(created), "image_id": image_id,
              "event": event,
              "window": {"start": float(win["start"]),
                         "end": float(win["end"]),
                         "complete": bool(win["complete"])},
              "content": content_out, "content_sha256": content_sha256,
              "ios_copy_verify": {"state": iocv["state"]},
              "sampling": sampling_out, "stage_state": stage_state,
              "peers": rows, "peers_total": peers_total,
              "peers_truncated": data["peers_truncated"],
              "peers_saturated": data["peers_saturated"]}
    agent = data.get("agent")
    if isinstance(agent, dict):
        report["agent"] = _cap_strings(agent)
    if len(json.dumps(report)) > _REPORT_STORE_MAX:
        raise ValueError("report too large")
    return report


def _cap_strings(value):
    """Recursively cap every string in *value* (keys included) at
    _REPORT_STR_MAX chars.  Non-container, non-string values pass through."""
    if isinstance(value, str):
        return value[:_REPORT_STR_MAX]
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
    peers = data.get("peers")
    if isinstance(peers, list):
        for row in peers:
            if not isinstance(row, dict):
                continue
            rows.append({"ip": str(row.get("ip") or "")[:64]})
            if len(rows) >= _REPORT_PEER_ROWS:
                break
    report["peers"] = rows
    # Exact distinct-participation count, stored as an int (the drawer
    # interpolates it unescaped as a number — same stored-XSS discipline as
    # the link fields above), floored at the named rows so "and N more"
    # arithmetic can never go negative, and clamped at int32 max so a
    # hostile device can't push a value outside OTLP intValue encoding.
    report["peers_total"] = min(
        max(_peer_int(data.get("peers_total")), len(rows)), 2**31 - 1)
    # Hard per-report bound (spec §6: ring of 5 × ≤16 KB per device). The
    # 64 KiB transport cap bounds the wire body; this bounds what we STORE —
    # key-count in nested sections is otherwise uncapped.
    if len(json.dumps(report)) > 16384:
        raise ValueError("report too large")
    report["schema"] = "v1"
    return report


class CatalogStore:
    TELEMETRY_RING = 5      # newest reports kept per device (hard disk bound)
    SEEN_REPORT_IDS = 256   # durable per-device seen v2 report_id ledger bound
    PULL_TTL = 600          # seconds a console pull directive stays pending

    def __init__(self, state_dir):
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

    def _read(self, path):
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

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
        with secrets_store.store_lock(self.devices_path):
            sw = self._read(self.devices_path)
            rec = {"device_id": device_id, "last_seen": now}
            rec.update(data)
            sw[device_id] = rec
            _atomic_write_json(self.devices_path, sw)

    def get_device(self, device_id):
        return self._read(self.devices_path).get(device_id)

    def forget_device(self, device_id):
        """Drop a device's stored heartbeat/staging record (devices.json).
        Called on a successful undeploy so the console stops reporting a wiped
        device as 'deployed' from its last live heartbeat. Returns True iff a
        record existed. The image ASSIGNMENT (policy) and telemetry history
        are intentionally left untouched — a re-onboard restages the same
        image, and the reports are historical."""
        with secrets_store.store_lock(self.devices_path):
            sw = self._read(self.devices_path)
            existed = sw.pop(device_id, None) is not None
            if existed:
                _atomic_write_json(self.devices_path, sw)
        return existed

    def list_devices(self):
        return list(self._read(self.devices_path).values())

    def purge_device(self, device_id):
        """Remove ALL per-device catalog state: the heartbeat record, the
        image assignment (policy), the telemetry history, the seen-report-id
        ledger, and any pending pull directive. Called when the console deletes
        a device from the fleet — a device that is deleted and added back must
        come back unassigned, or a stale assignment would silently restage the
        old image. Contrast forget_device(), which drops only the heartbeat
        record on undeploy and deliberately keeps the assignment. Returns
        True iff any state existed."""
        existed = self.forget_device(device_id)
        for path in (self.policy_path, self.telemetry_path, self.pull_path,
                     self.report_ledger_path):
            with secrets_store.store_lock(path):
                data = self._read(path)
                if data.pop(device_id, None) is not None:
                    existed = True
                    _atomic_write_json(path, data)
        return existed

    # --- policy (install-approval gate) ---
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

    def set_policy(self, device_id, approved_image_id=None, install_allowed=False):
        with self.image_policy_lock():
            # Re-check at persistence time. Missing catalog.json remains valid
            # for legacy bootstrap callers; an existing catalog fails closed.
            if approved_image_id and os.path.exists(self.catalog_path) \
                    and self.get_image(approved_image_id) is None:
                raise ValueError("no such image")
            with secrets_store.store_lock(self.policy_path):
                pol = self._read(self.policy_path)
                pol[device_id] = {"approved_image_id": approved_image_id,
                                  "install_allowed": bool(install_allowed)}
                _atomic_write_json(self.policy_path, pol)

    def get_policy(self, device_id):
        return self._read(self.policy_path).get(
            device_id, {"approved_image_id": None, "install_allowed": False})

    def list_policies(self):
        return self._read(self.policy_path)

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
        with secrets_store.store_lock(self.telemetry_path):
            tel = self._read(self.telemetry_path)
            ring = tel.get(device_id)
            ring = ring if isinstance(ring, list) else []
            duplicate = rid is not None and (
                any(isinstance(r, dict) and r.get("report_id") == rid
                    for r in ring)
                or self._report_id_seen(device_id, rid))
            if not duplicate:
                ring.append(report)
                tel[device_id] = ring[-self.TELEMETRY_RING:]
                _atomic_write_json(self.telemetry_path, tel)
                if rid is not None:
                    # Record the id in the durable bounded ledger AFTER the ring
                    # write. A crash between the two only means the ring still
                    # remembers this id (it is the newest), so a retry before
                    # the ledger catches up still dedupes on the ring — no
                    # double count, and the ledger makes it durable past
                    # eviction.
                    self._remember_report_id(device_id, rid)
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
        reports = self._read(self.telemetry_path).get(device_id, [])
        return reports if isinstance(reports, list) else []

    def _report_id_seen(self, device_id, rid):
        """True iff *rid* is in the device's durable seen-report-id ledger.
        Read fresh (small bounded file); tolerant of a missing/garbage file."""
        led = self._read(self.report_ledger_path).get(device_id)
        return isinstance(led, list) and rid in led

    def _remember_report_id(self, device_id, rid):
        """Append *rid* to the device's durable seen-report-id ledger, bounded
        FIFO at SEEN_REPORT_IDS (oldest purged). Idempotent: an id already
        present is not re-appended, so the ledger never grows on retries."""
        with secrets_store.store_lock(self.report_ledger_path):
            led = self._read(self.report_ledger_path)
            seen = led.get(device_id)
            seen = seen if isinstance(seen, list) else []
            if rid in seen:
                return
            seen.append(rid)
            led[device_id] = seen[-self.SEEN_REPORT_IDS:]
            _atomic_write_json(self.report_ledger_path, led)

    # --- pull directives (console-requested fresh reports) ---
    def request_report(self, device_id, now):
        """Flag *device_id* for a fresh report with a random 32-hex
        ``request_id`` (spec §10.2b). Returns False when a non-expired directive
        is already pending (one per device)."""
        with secrets_store.store_lock(self.pull_path):
            pr = self._read(self.pull_path)
            ent = pr.get(device_id)
            if isinstance(ent, dict) and now < ent.get("expires_at", 0):
                return False
            pr[device_id] = {"request_id": secrets.token_hex(16),
                             "requested_at": now,
                             "expires_at": now + self.PULL_TTL}
            _atomic_write_json(self.pull_path, pr)
            return True

    def pending_request(self, device_id, now):
        """The full non-expired pull directive dict for *device_id* (carrying
        ``request_id``), or None. Reaps expired entries lazily."""
        with secrets_store.store_lock(self.pull_path):
            pr = self._read(self.pull_path)
            expired = [d for d, ent in pr.items()
                       if not isinstance(ent, dict)
                       or now >= ent.get("expires_at", 0)]
            for d in expired:
                del pr[d]
            if expired:
                _atomic_write_json(self.pull_path, pr)
            ent = pr.get(device_id)
            return dict(ent) if isinstance(ent, dict) else None

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
        with secrets_store.store_lock(self.pull_path):
            pr = self._read(self.pull_path)
            ent = pr.get(device_id)
            if not isinstance(ent, dict):
                return
            if request_id not in ("__unset__", None) \
                    and ent.get("request_id") != request_id:
                return          # mismatched id: do not clear a newer request
            del pr[device_id]
            _atomic_write_json(self.pull_path, pr)


class Catalog:
    def __init__(self, store, secrets_path,
                 audit_path=None, live_table=None, stream_settings=None,
                 deployment_open=True, deployment_checkpoint=None):
        self.store = store
        self.secrets_path = secrets_path
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
        """Load the secrets store fresh from disk; return (store_dict, index)."""
        store_dict = secrets_store.load(self.secrets_path)
        index = secrets_store.build_index(store_dict)
        return store_dict, index

    def _announce_base_url(self):
        """Return the tracker announce base URL (no query), or None.

        Personalized/canonical announce URLs carry the IRIS credential in a
        dedicated ``announce_token=`` query parameter (spec §6), distinct from
        aria2's own ``key=``. The base is taken from IRIS_TRACKER_ANNOUNCE if
        set, else derived from IRIS_HOST_IP + the tracker announce port."""
        base = os.environ.get("IRIS_TRACKER_ANNOUNCE")
        if base:
            return base
        host_ip = os.environ.get("IRIS_HOST_IP")
        if not host_ip:
            return None
        port = os.environ.get("IRIS_TRACKER_PORT", "6969")
        return "http://%s:%s/announce" % (host_ip, port)

    def _personalized_torrent(self, image_id, announce_value):
        """Return personalized torrent bytes for *announce_value*, or raise.

        Reads the canonical torrent from disk (never mutating it) and rewrites
        only the outer announce to carry ``announce_token=<announce_value>``.
        The raw ``info`` byte span is preserved verbatim (info hash provably
        identical). The announce token, the announce URL, and the query string
        are NEVER logged, echoed, or embedded in any error (spec §6)."""
        base = self._announce_base_url()
        if not base:
            raise ValueError("tracker announce base unavailable")
        sep = "&" if "?" in base else "?"
        announce_url = "%s%sannounce_token=%s" % (base, sep, announce_value)
        with open(self.store.torrent_path(image_id), "rb") as f:
            canonical = f.read()
        return torrent_personalize.personalize(canonical, announce_url)

    def route_get(self, path, auth_ctx=None, store_dict=None):
        parts = path.strip("/").split("/")
        if parts == ["v1", "images"]:
            return self._json(200, {"images": self.store.list_images()})
        if len(parts) == 3 and parts[:2] == ["v1", "images"]:
            img = self.store.get_image(parts[2])
            return self._json(200, img) if img else \
                self._json(404, {"error": "no such image"})
        if len(parts) == 3 and parts[:2] == ["v1", "torrents"]:
            image_id = parts[2][:-len(".torrent")] \
                if parts[2].endswith(".torrent") else parts[2]
            return self._route_torrent(image_id, auth_ctx, store_dict)
        if parts == ["v1", "devices"]:
            return self._json(200, {"devices": self.store.list_devices()})
        if len(parts) == 4 and parts[:2] == ["v1", "devices"] \
                and parts[3] == "policy":
            return self._json(200, self.store.get_policy(parts[2]))
        return self._json(404, {"error": "not found"})

    # Extra response headers the handler must emit for a personalized torrent
    # so proxies/browsers never cache a device-specific body (spec §6).
    _PERSONALIZED_HEADERS = (
        ("Cache-Control", "private, no-store"),
        ("Vary", "Authorization"),
    )

    def _route_torrent(self, image_id, auth_ctx, store_dict):
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
                body = self._personalized_torrent(image_id, announce_value)
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

    def route_post(self, path, body, src_ip=None, store=None, index=None,
                   token=None):
        parts = path.strip("/").split("/")
        if len(parts) == 4 and parts[:2] == ["v1", "devices"] \
                and parts[3] == "heartbeat":
            try:
                data = json.loads(body or b"{}")
            except ValueError:
                return self._json(400, {"error": "bad json"})
            self.store.record_heartbeat(parts[2], {
                "current_image_id": data.get("current_image_id"),
                "free_flash_bytes": data.get("free_flash_bytes"),
                "version": data.get("version"),
                "stage_state": data.get("stage_state"),
                "stage_error": data.get("stage_error"),
                "target_fs": data.get("target_fs"),
                "model": data.get("model"),
                "telemetry_enabled": data.get("telemetry_enabled"),
                "telemetry_stream_enabled": data.get("telemetry_stream_enabled"),
                # The heartbeat's source IP is the agent's Guest Shell IP — the
                # SAME IP it announces to the tracker with — so the swarm map can
                # join this device's model onto its swarm peer by IP.
                "swarm_ip": src_ip,
            })
            # Live telemetry (spec §3/§10.1): a v2 `telemetry_observation`
            # envelope supersedes the legacy v1 `sample` on v2 agents; a bad
            # envelope/sample NEVER fails the heartbeat — reject-and-count.
            # The server cross-checks the device's telemetry flags and the
            # global stream pause and the policy assignment: telemetry off /
            # paused / unassigned / errored -> WITHDRAW the live value even if
            # an `observed` envelope arrived, without inventing transfer fields.
            if self.live_table is not None:
                approved = self.store.get_policy(parts[2]).get(
                    "approved_image_id")
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
                data = json.loads(body or b"{}")
            except ValueError:
                return self._json(400, {"error": "bad json"})
            try:
                report = _sanitize_report(data)
            except ValueError:
                return self._json(400, {"error": "bad report"})
            if report.get("schema") == "v2":
                assigned = self.store.get_policy(parts[2]).get(
                    "approved_image_id")
                if not assigned or report.get("image_id") != assigned:
                    return self._json(400, {"error": "bad report"})
            self.store.record_telemetry(parts[2], report)
            return self._json(200, {"ok": True})
        if len(parts) == 4 and parts[:2] == ["v1", "devices"] \
                and parts[3] == "token-refresh":
            return self._handle_token_refresh(
                parts[2], src_ip=src_ip, store=store, index=index)
        return self._json(404, {"error": "not found"})

    def _handle_token_refresh(self, device_id, src_ip=None, store=None,
                               index=None):
        """Rotate the catalog token for device_id and return the secret bag.

        The *store* passed in was loaded (pre-lock) by _guard for auth.  The
        mutation here must NOT operate on that snapshot: under the threaded
        server two overlapping refreshes would each rotate their own stale
        snapshot and the second save() would clobber the first (lost rotation,
        which can strand a device).  We take the per-store advisory lock and
        RE-READ the store fresh under it, so the load->mutate->save->encrypt
        cycle is serialized and never loses a concurrent rotation/revoke.
        """
        now = time.time()
        overlap = int(os.environ.get("IRIS_TOKEN_OVERLAP", "120"))
        secrets_path = self.secrets_path

        with secrets_store.store_lock(secrets_path):
            # Re-read under the lock; discard the pre-lock auth snapshot.
            store = secrets_store.load(secrets_path)

            # Capture the old token value for audit (before rotate overwrites it)
            device_secrets = store.get("devices", {}).get(device_id, {})
            old_record = device_secrets.get("catalog_token")
            old_val = old_record["value"] if old_record else ""

            # Re-check revoke status under the lock.  _guard authorized against
            # a PRE-LOCK snapshot; if iris-revoke won the lock first and marked
            # this device revoked in the meantime, the snapshot is stale.
            # rotate_catalog/mint always write revoked=False, so rotating now
            # would silently un-revoke the device (hand it a fresh live token).
            # Abort instead — this closes the TOCTOU the lock made deterministic.
            if old_record is not None and old_record.get("revoked"):
                try:
                    audit.append_event(
                        self.audit_path, "refresh_fail", device_id,
                        secret_name="catalog_token",
                        old_id=_audit_id(old_val),
                        src_ip=src_ip,
                        detail="device is revoked",
                        result="fail",
                    )
                except Exception:
                    pass
                return self._json(409, {"error": "device revoked"})

            # Stash the old token under catalog_token_prev with overlap expiry
            # so the reverse index still finds it for the duration of the
            # overlap window.  rotate_catalog mutates old_record.expires_at then
            # REPLACES the store slot with the new record, so without this stash
            # the old token would be lost on the next per-request load.
            if old_record:
                # Coerce to int: now is time.time() (float); the store schema
                # holds int epoch seconds.  A float expires_at would trip
                # int('...9') ValueError in the agent on the next tick.
                store["devices"][device_id]["catalog_token_prev"] = {
                    "value": old_val,
                    "created_at": int(old_record.get("created_at", now)),
                    "expires_at": int(now) + overlap,
                    "revoked": False,
                    "_scope": "catalog",   # so the guard can accept it
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
        return (status, "application/json", json.dumps(obj).encode())


def make_server(host, port, store, secrets_path, certfile=None,
                audit_path=None, live_table=None, stream_settings=None,
                deployment_open=True, deployment_checkpoint=None):
    cat = Catalog(store, secrets_path, audit_path=audit_path,
                   live_table=live_table, stream_settings=stream_settings,
                   deployment_open=deployment_open,
                   deployment_checkpoint=deployment_checkpoint)

    grace = int(os.environ.get("IRIS_TOKEN_SKEW_GRACE", "300"))

    class Handler(BaseHTTPRequestHandler):
        def _guard(self, parts, token):
            """Route-aware guard.

            Device-bound routes (heartbeat, token-refresh, telemetry): require
            a device catalog_token resolving to that device's principal.

            Shared routes (images, torrents, devices-list, policy): require
            any valid catalog-scoped record.

            Returns ``(store_dict, index, auth_ctx)`` on success (auth_ctx is a
            typed ``auth.AuthContext`` for the resolved principal) or
            ``(None, None, None)`` on auth failure. Every authorization decision
            is made through the STRICT catalog auth index (spec §6): the broad
            ``secrets_store.build_index`` never authorizes (it is loaded here
            only as route_post compatibility data).
            """
            store_dict, index = cat._load_store()
            now = time.time()
            try:
                strict = secrets_store.build_catalog_auth_index(store_dict)
            except secrets_store.DuplicateCredentialError:
                # Hard config error: duplicate catalog credential ownership.
                # Fail closed for every request; never a silent overwrite.
                return None, None, None

            # Determine if this is a device-bound route
            is_device_bound = (
                len(parts) == 4
                and parts[:2] == ["v1", "devices"]
                and parts[3] in ("heartbeat", "token-refresh", "telemetry")
            )

            if is_device_bound:
                device_id = parts[2]
                ctx = auth.resolve_catalog_auth(
                    store_dict, strict, token, now, grace)
                ok = (ctx is not None
                      and ctx.principal.type == "device"
                      and ctx.principal.id == device_id
                      and ctx.secret_name == "catalog_token")
                if not ok:
                    # Audit auth failure for token-refresh routes
                    if parts[3] == "token-refresh":
                        try:
                            audit.append_event(
                                cat.audit_path, "auth_fail", device_id,
                                src_ip=self.client_address[0],
                                result="fail",
                            )
                        except Exception:
                            pass
                    return None, None, None
                return store_dict, index, ctx

            # Shared route: accept any valid catalog credential resolved through
            # the strict index (device catalog_token OR catalog_token_prev). A
            # rolled-old token (catalog_token_prev) works here because the strict
            # index covers it; it is rejected on device-bound routes above
            # because those require secret_name == "catalog_token".
            ctx = auth.resolve_catalog_auth(
                store_dict, strict, token, now, grace)
            if ctx is None:
                return None, None, None
            return store_dict, index, ctx

        def _extract_token(self):
            value = self.headers.get("Authorization", "")
            prefix = "Bearer "
            if not value.startswith(prefix):
                return None
            return value[len(prefix):]

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
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for name, value in extra_headers:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            token = self._extract_token()
            if not token:
                self._send((401, "application/json",
                            json.dumps({"error": "unauthorized"}).encode()))
                return
            parts = self.path.strip("/").split("/")
            store_dict, index, auth_ctx = self._guard(parts, token)
            if store_dict is None:
                self._send((401, "application/json",
                            json.dumps({"error": "unauthorized"}).encode()))
                return
            self._send(cat.route_get(
                self.path, auth_ctx=auth_ctx, store_dict=store_dict))

        def do_POST(self):
            token = self._extract_token()
            if not token:
                self._send((401, "application/json",
                            json.dumps({"error": "unauthorized"}).encode()))
                return
            parts = self.path.strip("/").split("/")
            store_dict, index, auth_ctx = self._guard(parts, token)
            if store_dict is None:
                self._send((401, "application/json",
                            json.dumps({"error": "unauthorized"}).encode()))
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send((400, "application/json",
                            json.dumps({"error": "bad content-length"}).encode()))
                return
            if length < 0:
                self._send((400, "application/json",
                            json.dumps({"error": "bad content-length"}).encode()))
                return
            if length > MAX_BODY_BYTES:
                # Refuse before reading: the declared length is untrusted and
                # could be arbitrarily large.
                self._send((413, "application/json",
                            json.dumps({"error": "body too large"}).encode()))
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
                    self._send((400, "application/json",
                                json.dumps(
                                    {"error": "bad request body"}).encode()))
                    return
                if len(body) > MAX_BODY_BYTES:
                    # Bomb guard: re-check the DECOMPRESSED size.
                    self._send((413, "application/json",
                                json.dumps(
                                    {"error": "body too large"}).encode()))
                    return
            self._send(cat.route_post(
                self.path, body, self.client_address[0],
                store=store_dict, index=index, token=token))

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer((host, port), Handler)
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


def main():
    host = os.environ.get("IRIS_CATALOG_HOST", "0.0.0.0")
    port = int(os.environ.get("IRIS_CATALOG_PORT", "8443"))
    state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
    store = CatalogStore(state_dir)
    secrets_path = os.environ.get("IRIS_SECRETS", "/run/iris/secrets.json")
    cert = os.environ.get("IRIS_CERT", "/etc/iris/tls/cert.pem")
    certfile = cert if os.path.exists(cert) else None
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
                      deployment_checkpoint=deployment_checkpoint)
    scheme = "https" if certfile else "http"
    print("catalog on %s://%s:%d/v1/images" % (scheme, host, port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
