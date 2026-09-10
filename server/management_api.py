# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Stateful management API for the IRIS web console.

Browser traffic reaches this internal HTTPS interface only through the
state-free console BFF.  The established session, CSRF, polling, and
fail-closed semantics are exposed on the versioned ``/internal/v1`` wire
interface.  The implementation mirrors catalog.py's ThreadingHTTPServer,
BaseHTTPRequestHandler, and TLS pattern and remains stdlib-only.
"""
import contextlib
import email.utils
import http.cookies
import copy
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import signal
import ssl
import sys
import tempfile
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, parse_qs, urlsplit

import audit
import auth
import audit_export
import assignment_service
import bounded_pool
import bulkhash_refresh
# aliased: `catalog` is the injected STORE everywhere below
import catalog as catalog_mod
import deployment_records
import gui_app
import gui_auth
import gui_fleet
import gui_onboard
import gui_tls
import instruction_keys
import instruction_stamper
import instructions
import iox_transport
import iox_verification
import live_samples
import origin_qos
import otlp
import peer_endpoints
import peer_policy
import peer_enforcement
import role_management
import schedule_runner
import schedule_validation
import secretfs
import secrets_store
import schedules
import setup_status
import telemetry
import telemetry_destination
import trust
import api_problem
import api_routes
import tier_auth

WEBROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webroot")
COOKIE = "iris_sid"
SWARMMAP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "swarmmap.html")
_IRIS_CERT_DEFAULT = "/run/iris/tls/cert.pem"
# heartbeat freshness horizon (s): a device whose last_seen is older than
# this is what the UI badges "offline" (app.js uses the same 600), so the
# overview must not count it as actively staging
_HEARTBEAT_FRESH = 600
# stage_states that are a failure the agent RETRIES rather than a terminal
# one: it is alive, out of room, and will place the image as soon as space
# appears, so the device is still staging. The agent reports these images in
# errored_image_ids alongside genuinely dead ones, which is why the precise
# tier below cannot read that list alone.
_RETRYABLE_STAGE_STATES = ("flash_full", "flash_full_seeding_only")
# GET /swarmmap swaps this exact placeholder line in the single-source
# server/swarmmap.html for the console config line (the file on disk keeps
# working standalone; only the served copy is rewritten):
_MAP_PLACEHOLDER = "window.IRIS_MAP_CFG = null;"
# eventsUrlTemplate: operator-configured deep link ({ip}/{device_id}
# placeholders) rendered by the swarm-map drawer; unset -> no button (the map
# assumes no particular events backend). Read at request time via a callable
# so tests can monkeypatch the env.
def _map_cfg_line():
    payload = json.dumps(os.environ.get("IRIS_EVENTS_URL_TEMPLATE", ""))
    # Belt-and-suspenders: this line lands inside an inline <script> block, so
    # the value must never contain a literal '</script>'. \uXXXX-escaping
    # < > & keeps the JSON valid and the parsed value byte-identical.
    payload = (payload.replace("<", "\\u003c").replace(">", "\\u003e")
                      .replace("&", "\\u0026"))
    return ('window.IRIS_MAP_CFG = {"swarmUrl":"/api/v1/swarm","pull":true,'
            '"eventsUrlTemplate":%s};' % payload)


def _revision_etag(resource, revision):
    """Strong validator for a JSON representation stamped by an integer."""
    return '"iris-%s-%d"' % (resource, int(revision))
def _telemetry_status_args():
    """(override_endpoint, override_enabled, env_endpoint, env_enabled) for
    setup_status.build_status's telemetry card -- the exact same resolution
    _settings_info uses for telemetry_destination (console override file,
    else IRIS_OTLP_ENDPOINT / IRIS_OBSERVABILITY), read fresh at request time
    so the setup checklist never disagrees with the Telemetry settings pane."""
    state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
    dest = telemetry_destination.read(
        telemetry_destination.settings_path(state_dir))
    return (dest["endpoint"], dest["enabled"],
            os.environ.get("IRIS_OTLP_ENDPOINT", "").strip(),
            telemetry.observability_enabled())
def _image_verification_last_run():
    """last_run for setup_status.build_status's Image verification card
    (KGV / Cisco Bulk Hash reconciler, console Task 5) -- read fresh at
    request time from the same settings file the /api/settings/
    image-verification GET route reads, so the setup checklist never
    disagrees with the Settings pane."""
    state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
    return bulkhash_refresh.read_settings(
        bulkhash_refresh.settings_path(state_dir))["last_run"]
_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript",
    ".css": "text/css",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
}
_MAX_BODY = 64 * 1024  # cap request bodies (esp. the pre-auth /api/login POST) — DoS guard
_SSE_IDLE = 600   # close an onboard log stream after this long with NO progress
                  # (queue-wait and new output both reset it — a deep-queued job
                  # behind the onboard pool legitimately waits >10 min)
_SSE_KEEPALIVE = 15  # comment-frame interval so proxies don't reap a quiet stream
_MAX_CSV = 8 * 1024 * 1024  # 8 MiB — bulk devices.csv import (all-or-nothing, held in memory)
# A device_ids array at the supported fleet size (peer_endpoints.
# SUPPORTED_DEVICES, 10,000 ids up to 64 chars each -- see gui_fleet._ID_RE)
# plus a small field patch comfortably fits well under 64 KiB * 10; generous
# headroom over the ~700 KB worst case without approaching _MAX_CSV's size
# (this body is an id LIST, not per-device CSV rows).
_MAX_BULK_DEVICE_IDS = 2 * 1024 * 1024  # 2 MiB — fleet-id bulk JSON bodies
_CAS_COMPATIBILITY_HEADERS = (
    ("Deprecation", "true"),
    ("Sunset", "Sat, 04 Sep 2027 00:00:00 GMT"),
)
# How long a client gets to complete the TLS handshake once its connection
# has been handed to a worker thread (see _ConsoleServer). Generous for a
# browser on an operator network; bounded so a connection that never sends
# a ClientHello gives its thread back.
_HANDSHAKE_TIMEOUT = 30
# How long peer-policy enforcement can go without a recorded reconcile pass
# before the console calls it stale (IRIS-99). The tracker's own bounded
# maintenance deadline (tracker.MAINTENANCE_INTERVAL_CAP, 60s) forces a pass
# -- and a fresh peer-enforcement.json write, updating last_reconciled_at --
# even when nothing changed, and a FAILED pass still writes a "degraded"
# status with a fresh timestamp (tracker.TrackerReconciler._note_pass_failure).
# So under any live reconciler, healthy or degraded, last_reconciled_at
# should never lag more than ~60s. This is several multiples of that to
# absorb scheduling jitter and a slow aria2 RPC without false-flagging, while
# still catching a genuinely frozen reconciler (the tracker process down, or
# even the degraded write itself failing) well before an operator would
# otherwise notice a stale "enforced" claim reading as healthy.
_PEER_POLICY_STALE_AFTER = 300.0
# Explicit opt-in for serving the console over plain HTTP. Without it the
# console refuses to start when no usable certificate exists: the session
# cookie is Secure-only under TLS, and a plaintext console would otherwise
# accept the admin password in cleartext and then fail to keep a session.
_PLAINTEXT_OPT_IN_ENV = "IRIS_GUI_ALLOW_PLAINTEXT"
_MAX_UPLOAD = 4 * 1024 * 1024 * 1024  # 4 GiB — streamed image uploads (not the JSON cap)
# 256 MiB — streamed offline Cisco Bulk Hash tar upload (KGV reconciler
# Task 4). The real feed tar was ~46 MB on 2026-08-29 (bulkhash_refresh.py's
# FEED_URL provenance note); this stays a comfortable multiple of that while
# matching bulkhash._MAX_CSV_BYTES's own 256 MiB per-member structural cap —
# a bigger HTTP body could never produce a tar verify_tar/parse would accept.
_MAX_OFFLINE_TAR = 256 * 1024 * 1024
_SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy",
     "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"),
]

_INSTRUCTION_I63_MAX = (1 << 63) - 1
_INSTRUCTION_DEVICE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_INSTRUCTION_REJECTED_STATES = frozenset((
    "rollback_rejected", "audience_mismatch", "key_rejected",
    "tamper_rejected", "lkg_rejected", "oversize",
))
_INSTRUCTION_STALE_STATES = frozenset((
    "stale_expired", "allowlist_expired",
))
_INSTRUCTION_UNAVAILABLE_LABELS = {
    "verifier_missing": "verifier unavailable",
    "lkg_unreadable": "LKG unavailable",
    "instr_unavailable": "unavailable",
}


def _instruction_i63(value):
    """Return one exact bounded wire integer, otherwise None."""
    return value if type(value) is int and 0 <= value <= _INSTRUCTION_I63_MAX \
        else None


def _instruction_timestamp(value):
    """Return one finite, nonnegative timestamp in the bounded wire range."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value < 0 or value > _INSTRUCTION_I63_MAX:
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _instruction_report_age(heartbeat, observed_at):
    last_seen = heartbeat.get("last_seen") if isinstance(heartbeat, dict) else None
    last_seen = _instruction_timestamp(last_seen)
    observed_at = _instruction_timestamp(observed_at)
    if last_seen is None or observed_at is None:
        return None
    if last_seen > observed_at:
        return None
    age = int(observed_at - last_seen)
    return age if age <= _INSTRUCTION_I63_MAX else None


def _instruction_raw_state(heartbeat):
    """Validate the closed state/reason unit again at the management edge."""
    if not isinstance(heartbeat, dict):
        return None, None
    state = heartbeat.get("instr_state")
    if not isinstance(state, str) or state not in instructions.INSTR_STATES:
        return None, None
    if state == "key_rejected":
        reason = heartbeat.get("instr_reason")
        return (state, reason) if isinstance(reason, str) \
            and reason in instructions.INSTR_REASONS \
            else (None, None)
    if "instr_reason" in heartbeat:
        return None, None
    return state, None


def _instruction_qos_drift_count(heartbeat, supported):
    if not supported or not isinstance(heartbeat, dict):
        return None
    if "qos_drift" not in heartbeat:
        return 0
    clean = instructions.sanitize_instruction_attestation({
        "qos_drift": heartbeat.get("qos_drift")})
    drift = clean.get("qos_drift")
    if drift is None:
        return None
    return (len(drift.get("options", ()))
            + int("blocklist_revision" in drift)
            + int("blocklist_rules" in drift))


def _instruction_device_projection(heartbeat, revoked, observed_at,
                                   heartbeat_available=True):
    """Return the bounded instruction status used by rows and roll-ups.

    ``revoked`` is deliberately tri-state.  None means the durable revocation
    snapshot was unavailable, so the primary classification is unknown while
    the bounded underlying agent report remains visible.
    """
    heartbeat = heartbeat if isinstance(heartbeat, dict) else {}
    marker_present = "instr_protocol" in heartbeat
    marker = heartbeat.get("instr_protocol")
    supported = type(marker) is int and marker == 1
    state, reason = _instruction_raw_state(heartbeat)
    serial = _instruction_i63(heartbeat.get("instr_serial"))
    identity_values = (
        _instruction_i63(heartbeat.get("instr_epoch")), serial,
        _instruction_i63(heartbeat.get("instr_policy_revision")),
    )
    identity = None
    if supported and all(value is not None for value in identity_values):
        identity = {
            "epoch": identity_values[0], "instr_serial": identity_values[1],
            "policy_revision": identity_values[2],
        }

    if state in ("applied", "reasserted"):
        underlying_display = "applied" if identity is not None else "unknown"
        underlying_label = ("applied r%d" % identity["instr_serial"]
                            if identity is not None else "unknown")
    elif state == "lkg":
        underlying_display = "lkg" if identity is not None else "unknown"
        underlying_label = "lkg" if identity is not None else "unknown"
    elif state in _INSTRUCTION_STALE_STATES:
        underlying_display, underlying_label = "stale", "stale"
    elif state in _INSTRUCTION_REJECTED_STATES:
        underlying_display, underlying_label = "rejected", "rejected"
    elif state in _INSTRUCTION_UNAVAILABLE_LABELS:
        underlying_display = "unavailable"
        underlying_label = _INSTRUCTION_UNAVAILABLE_LABELS[state]
    elif state == "tracker-only":
        underlying_display, underlying_label = "tracker-only", "tracker-only"
    elif state == "instr_pending":
        underlying_display, underlying_label = "pending", "pending"
    elif state == "instr_forbidden":
        underlying_display, underlying_label = "forbidden", "forbidden"
    elif state == "floor_reset":
        underlying_display, underlying_label = "floor_reset", "floor reset"
    elif state == "none":
        underlying_display, underlying_label = "none", "no accepted instruction"
    else:
        underlying_display, underlying_label = "unknown", "unknown"

    age = _instruction_report_age(heartbeat, observed_at)
    report_stale = age >= _HEARTBEAT_FRESH if age is not None else None
    if revoked is True:
        display, label, evidence = "revoked", "revoked", "server-observed"
    elif revoked is None:
        display, label, evidence = "unknown", "unknown", "server-observed"
    elif not heartbeat_available:
        display, label, evidence = "unknown", "unknown", "server-observed"
    elif not marker_present:
        display, label, evidence = (
            "pre-instructions", "pre-instructions", "agent-asserted")
    elif not supported:
        display, label, evidence = "unknown", "unknown", "agent-asserted"
    elif underlying_display == "stale":
        display, label, evidence = (
            underlying_display, underlying_label, "agent-asserted")
    elif age is None:
        display, label, evidence = "unknown", "unknown", "server-observed"
    elif report_stale:
        display = "stale"
        label = "stale · last reported %s" % underlying_label
        evidence = "server-observed"
    else:
        display, label, evidence = (
            underlying_display, underlying_label, "agent-asserted")

    pointer_skew = heartbeat.get("pointer_skew")
    if not supported or not isinstance(pointer_skew, bool):
        pointer_skew = None
    verify_level = heartbeat.get("verify_level")
    if verify_level not in ("sig", "none"):
        verify_level = None
    return {
        "display_state": display, "label": label, "evidence": evidence,
        "underlying_state": state, "underlying_label": underlying_label,
        "underlying_evidence": "agent-asserted",
        "reason": reason, "reported_instr_serial": serial,
        "accepted_identity": identity, "verify_level": verify_level,
        "pointer_skew": pointer_skew,
        "qos_drift_count": _instruction_qos_drift_count(
            heartbeat, supported),
        "report_age_seconds": age, "report_stale": report_stale,
        "revoked": revoked, "revocation_evidence": "server-observed",
    }


def _instruction_fleet_projection(inventory_rows, heartbeat_rows,
                                  raw_policies, revoked_principals,
                                  observed_at):
    """Build one O(n), count-only fleet projection from bulk snapshots."""
    heartbeat_available = isinstance(heartbeat_rows, list)
    heartbeat_by_id = {}
    if heartbeat_available:
        for row in heartbeat_rows:
            if isinstance(row, dict) and isinstance(row.get("device_id"), str):
                heartbeat_by_id[row["device_id"]] = row
    revocation_available = isinstance(revoked_principals, (set, frozenset))

    states, applied = {}, {}
    pointer_skew = 0 if heartbeat_available else None
    inventory_ids = []
    for inventory_row in inventory_rows if isinstance(inventory_rows, list) else ():
        device_id = (inventory_row.get("device_id")
                     if isinstance(inventory_row, dict) else None)
        if (not isinstance(device_id, str)
                or _INSTRUCTION_DEVICE_ID.fullmatch(device_id) is None):
            continue
        inventory_ids.append(device_id)
        heartbeat = heartbeat_by_id.get(device_id, {})
        revoked = ("device:%s" % device_id in revoked_principals
                   if revocation_available and isinstance(device_id, str)
                   else None)
        projected = _instruction_device_projection(
            heartbeat, revoked, observed_at,
            heartbeat_available=heartbeat_available)
        key = projected["display_state"]
        states[key] = states.get(key, 0) + 1
        identity = projected["accepted_identity"]
        if identity is not None:
            revision = str(identity["policy_revision"])
            applied[revision] = applied.get(revision, 0) + 1
        if pointer_skew is not None and projected["pointer_skew"] is True:
            pointer_skew += 1

    issued_revision = None
    instr_stamp_missing = None
    if isinstance(raw_policies, dict):
        missing = 0
        valid = True
        for device_id in inventory_ids:
            row = raw_policies.get(device_id)
            if row is None:
                missing += 1
                continue
            if not isinstance(row, dict):
                valid = False
                break
            if "instr" not in row:
                missing += 1
                continue
            try:
                stamp = instructions.validate_stamp(row["instr"])
            except (instructions.InstructionError, TypeError, ValueError,
                    RecursionError, OverflowError):
                valid = False
                break
            revision = stamp["policy_revision"]
            issued_revision = revision if issued_revision is None \
                else max(issued_revision, revision)
        if valid:
            instr_stamp_missing = missing
        else:
            issued_revision = None

    return {
        "fleet_rollup": {
            "issued_revision": issued_revision,
            "applied": applied,
            "states": {key: states[key] for key in sorted(states)},
        },
        "instruction_status": {
            "observed_at": observed_at,
            "instr_stamp_missing": instr_stamp_missing,
            "pointer_skew": pointer_skew,
            "issued_revision_label": ("r%d" % issued_revision
                                      if issued_revision is not None else None),
        },
    }


def _instruction_revoked_principals(store):
    """Validate the durable snapshot before the canonical revocation rule."""
    if not isinstance(store, dict):
        return None
    devices = store.get("devices")
    if not isinstance(devices, dict) or len(devices) > 20000:
        return None
    for device_id, records in devices.items():
        if (not isinstance(device_id, str)
                or _INSTRUCTION_DEVICE_ID.fullmatch(device_id) is None
                or not isinstance(records, dict) or len(records) > 16):
            return None
        for secret_name, record in records.items():
            if (not isinstance(secret_name, str) or len(secret_name) > 64
                    or not isinstance(record, dict)
                    or ("revoked" in record
                        and not isinstance(record["revoked"], bool))):
                return None
    return secrets_store.revoked_device_principals(store)


def instruction_custody_view(state_dir):
    """Return the durable count/state/age custody status, if available."""
    return instruction_keys.read_status_file(os.path.join(
        state_dir, "instruction-key-status.json"))
# Public, non-configurable default first-run credential, retained for
# compatibility. A fresh Console must stay on a trusted network until claimed.
# The pair is accepted only while no administrator exists and mints a
# short-lived, one-use setup grant; it never creates a session or persistent
# account. Once setup completes, the pair is handled as an ordinary
# administrator login and normally fails unless the operator chose these exact
# permanent credentials.
DEFAULT_SETUP_USER = "iris"
DEFAULT_SETUP_PASS = "irisisgreat!"
_SETUP_GRANT_TTL = 600  # seconds (10 minutes)


def _is_default_credential(username, password):
    """Constant-time comparison of both fields against the first-run pair."""
    try:
        supplied_user = username.encode("utf-8")
        supplied_password = password.encode("utf-8")
    except UnicodeError:
        supplied_user = b""
        supplied_password = b""
    user_ok = hmac.compare_digest(
        supplied_user, DEFAULT_SETUP_USER.encode("utf-8"))
    password_ok = hmac.compare_digest(
        supplied_password, DEFAULT_SETUP_PASS.encode("utf-8"))
    return user_ok and password_ok


def _mint_setup_grant(app):
    """Issue a fresh one-time setup grant on *app* (36-byte urlsafe, 10-minute
    expiry), replacing any previous one -- the latest grant always wins, and
    the value lives only in process memory: never written to disk or logs."""
    grant = secrets.token_urlsafe(36)
    app._setup_grant = (grant, time.time() + _SETUP_GRANT_TTL)
    return grant


def _grant_valid(app, supplied):
    """Constant-time check of *supplied* against the live setup grant on
    *app*. False for no grant, an expired grant, or a mismatch. Does not
    consume the grant -- callers that accept it must clear app._setup_grant
    themselves so a claim is atomic with the admin-account write."""
    current = getattr(app, "_setup_grant", None)
    if current is None or not supplied:
        return False
    grant, expires_at = current
    if time.time() >= expires_at:
        return False
    return hmac.compare_digest(supplied.encode("utf-8"), grant.encode("utf-8"))


def _claim_admin(app, supplied_grant, username, password):
    """Atomically consume the one-time setup grant and create the admin."""
    with secrets_store.store_lock(app.secrets_path):
        store = secrets_store.load(app.secrets_path)
        if gui_auth.get_admin(store) is not None:
            return "configured"
        if not _grant_valid(app, supplied_grant):
            return "grant"
        gui_auth.set_admin(store, username, password, app._now())
        secretfs.persist_store(store, app.secrets_path,
                               recipients_csv=app.recipients_csv,
                               enc_path=app.secrets_enc)
        # Single-use: the account now permanently disables setup, so the
        # grant has nothing left to authorize.
        app._setup_grant = None
        return "ok"


def _idempotency_make_room(cache, limit):
    """Evict one completed replay entry without invalidating live work."""
    if len(cache) < limit:
        return True
    completed = [key for key, entry in cache.items()
                 if entry.get("response") is not None]
    if not completed:
        return False
    oldest = min(completed, key=lambda key: cache[key]["created"])
    cache.pop(oldest, None)
    return True


def _revoke_device_secrets(app, device_id):
    """Durably revoke every secret for *device_id*, durable-copy-FIRST, under the
    secrets-store flock (spec §7 retirement step 1).

    Returns ``"ok"`` on a persisted revoke, ``"absent"`` if the device owns no
    secret records (nothing to revoke — the caller may still clean fleet/catalog
    state), or raises on a persist failure so the caller ABORTS the delete with
    no fleet/catalog/policy change. Uses the same lock + durable-first discipline
    as iris-revoke, so a concurrent rotation cannot re-arm the device and a
    durable-write failure never leaves a phantom (unpersisted) revoke.
    """
    with secrets_store.store_lock(app.secrets_path):
        store = secrets_store.load(app.secrets_path)
        if device_id not in store.get("devices", {}):
            return "absent"
        secrets_store.revoke(store, device_id)
        secretfs.persist_store(store, app.secrets_path,
                               recipients_csv=app.recipients_csv,
                               enc_path=app.secrets_enc)
    return "ok"


def _fmt_bytes(n):
    """Human-readable byte count for audit details: '1.2 GiB' / '340 MiB' /
    '12 KiB' (1024-based, 1 decimal, trailing .0 dropped). Non-numeric or
    absent -> '?' — an audit detail must never raise."""
    try:
        n = float(n)
    except (TypeError, ValueError):
        return "?"
    if n < 1024:
        return "%d B" % int(n)
    for unit in ("KiB", "MiB", "GiB", "TiB"):
        n /= 1024.0
        if n < 1024 or unit == "TiB":
            return "%s %s" % (("%.1f" % n).rstrip("0").rstrip("."), unit)


def _refresh_http_status(result):
    """HTTP status for a bulkhash_refresh.run_refresh() result dict (KGV
    reconciler Task 4), returned to the caller verbatim as the body: "ok" is
    200, the single-flight guard's "already_running" is 409 (a real,
    resolvable conflict -- another run is genuinely in flight right now,
    matching the peer-policy revision-conflict precedent's use of 409), and
    "fail" (fetch/verify/parse/reconcile/apply all fail closed the same way,
    per run_refresh's own contract) is 502 -- the reconciler acting as a
    client of an upstream feed/artifact that this run could not use, the
    Bad Gateway reading fits better than a 500 this server did not itself
    cause."""
    outcome = result.get("outcome")
    if outcome == "ok":
        return 200
    if outcome == "already_running":
        return 409
    return 502


def _image_view(entry):
    """Console/API-safe projection of one catalog image entry (KGV
    reconciler Task 4): every field the entry already carries, PLUS
    guaranteed-present top-level `quarantined`, `cisco_signature_verified`,
    and `operator_attested_signature` bools and a `hash_verification`
    verdict (all default to falsy/None for an image the reconciler -- or,
    for operator_attested_signature, the publishing operator -- has never
    touched; apply_hash_verification()/release_quarantine() only ever set
    the first three, never pre-seed them), MINUS the two fields that exist
    purely for catalog.py's own internal bookkeeping
    (quarantine_actions_complete -- convergence-retry state;
    quarantine_override_sha512 -- the re-quarantine-suppression ack) and
    were never meant to be wire-visible.

    cisco_signature_verified (the Cisco Bulk Hash reconciler's own verdict)
    and operator_attested_signature (the operator's `iris-publish
    --signature-verified` attestation, from publish.py) are DISTINCT fields
    that must never be conflated here or anywhere downstream -- IRIS-03-009/
    #88: they used to share one field, so the reconciler's first run
    silently overwrote the operator's mark."""
    view = {k: v for k, v in entry.items()
           if k not in ("quarantine_actions_complete",
                        "quarantine_override_sha512")}
    view["quarantined"] = bool(entry.get("quarantined"))
    view["hash_verification"] = entry.get("hash_verification")
    view["cisco_signature_verified"] = bool(entry.get("cisco_signature_verified"))
    view["operator_attested_signature"] = bool(entry.get("operator_attested_signature"))
    return view


def _csrf_ok(provided, expected):
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def _default_swarm_fetch():
    url = telemetry.validate_local_swarm_url(os.environ.get(
        "IRIS_SWARM_URL", "https://127.0.0.1:9101/swarm"))
    token_file = os.environ.get("IRIS_MANAGEMENT_API_TOKEN_FILE", "")
    token, _ = tier_auth.load_pair(token_file)
    return telemetry.local_swarm_get(
        url, token.decode("utf-8"), timeout=3)


# ---- paginated read projections (fleet + swarm) ---------------------------
# The console polls these while a view is visible, and at fleet scale the
# whole-snapshot response is most of what the poll costs: 10,000 merged
# device rows are ~6 MiB of JSON to encode, ship and re-render every 10 s.
# Paging is OPT-IN -- no limit/offset means the caller gets the complete
# projection it has always got, because a console that quietly rendered the
# first page of a fleet as if it were the fleet is a worse failure than a
# slow page.  Every response carries the totals a caller needs to know which
# of the two it is holding.
MAX_PAGE_LIMIT = 1000


def _page_params(qs):
    """(limit, offset) from a parsed query string; raises ValueError with an
    operator-readable message on anything that is not a usable page.

    Absent limit means "no page, the whole projection"; a limit above
    MAX_PAGE_LIMIT is clamped (and echoed back, so the caller can see the
    page it actually got).  A malformed or non-positive value is REJECTED
    rather than defaulted: quietly serving a different page than the one
    asked for is how a client ends up believing it has walked a fleet it
    has not."""
    def _one(name):
        raw = qs.get(name)
        return raw[0] if raw else None

    limit = _one("limit")
    if limit is not None:
        try:
            limit = int(limit)
        except ValueError:
            raise ValueError("limit must be an integer")
        if limit < 1:
            raise ValueError("limit must be at least 1")
        limit = min(limit, MAX_PAGE_LIMIT)

    offset = _one("offset")
    if offset is None:
        offset = 0
    else:
        try:
            offset = int(offset)
        except ValueError:
            raise ValueError("offset must be an integer")
        if offset < 0:
            raise ValueError("offset must not be negative")
    return limit, offset


def _swarm_page(body, limit, offset):
    """A page of the hub's swarm snapshot, flattening peers across images in
    image order.  The image entries themselves are all preserved (the map's
    image selector is built from them); only their peer lists are sliced.

    A payload that is not the documented {"images": [{"peers": [...]}]}
    shape cannot be paged, and is reported as such rather than passed
    through whole -- a caller that asked for 100 peers must never be handed
    all of them believing it got a page."""
    try:
        data = json.loads(body)
    except (TypeError, ValueError):
        return {"peers": [], "error": "swarm data unavailable"}
    if not isinstance(data, dict) or not isinstance(data.get("images"), list):
        return {"peers": [], "error": "swarm data not paginatable"}

    end = None if limit is None else offset + limit
    images, seen = [], 0
    for image in data["images"]:
        if not isinstance(image, dict):
            continue
        peers = image.get("peers")
        peers = peers if isinstance(peers, list) else []
        lo = max(0, offset - seen)
        hi = len(peers) if end is None else max(0, min(len(peers), end - seen))
        images.append(dict(image, peers=peers[lo:hi] if lo < hi else []))
        seen += len(peers)

    return dict(data, images=images, peers_total=seen,
                peers_offset=offset, peers_limit=limit)


# ---- server-side filter parity for the Devices table (issue #112) --------
# The console's filter bar offers ten controls: free-text q (already
# server-side, above) plus nine column filters -- management type, agent
# install (platform), credential, telemetry, peer-quarantine, role, model
# family, OS family and status --
# and app.js filters every one of them client-side over the whole fleet
# (deviceMatchesFilters, webroot/app.js). A paged table can only offer a
# filter the server can also apply -- otherwise a page would silently
# disagree with what the filter bar promises. _device_filter_params reads
# the nine off the query string; Handler._row_matches_extra_filters (below,
# next to _row_matches_q) applies them, deliberately mirroring
# deviceMatchesFilters condition-for-condition so the two can never decide
# a row differently.
_DEVICE_FILTER_PARAM_NAMES = ("management_type", "platform", "cred",
                              "telemetry", "peer", "role", "model_family",
                              "os_family", "status")


def _device_filter_params(qs):
    """{name: value} for every column filter present and non-blank in *qs*.
    Absent/blank means "no opinion", same as the dropdown's own "<field>:
    any" option -- there is nothing to validate here; a value naming no real
    option (a stale bookmark, a hand-edited URL) simply matches zero rows,
    exactly like an empty-fleet q."""
    out = {}
    for name in _DEVICE_FILTER_PARAM_NAMES:
        raw = (qs.get(name) or [None])[0]
        if raw:
            out[name] = raw
    return out


def trusted_target_projection(fleet_row, deployment_type=None):
    """Derive scheduling facts from server-owned inventory/record inputs.

    The intentionally narrow signature has no heartbeat argument. A caller
    may pass a row that happens to contain display-only heartbeat fields, but
    they are ignored and cannot influence any returned targeting fact.
    """
    deployment_type = deployment_type or {}
    return {
        "model_family": gui_onboard.family(fleet_row.get("model")),
        "os_family": (fleet_row.get("os_family") or
                      deployment_type.get("os_family") or ""),
        "platform_resolved": (deployment_type.get("platform") or
                              fleet_row.get("platform") or ""),
    }


def deployment_target_snapshot(records):
    """Project one newest live deployment type per device from a bulk read."""
    live_states = frozenset((
        "planned", "applying", "active", "unknown", "drifted",
        "needs-reconcile",
    ))
    newest = {}
    for position, record in enumerate(records):
        if not isinstance(record, dict) or record.get("state") not in live_states:
            continue
        device_id = record.get("device_id")
        resolved = record.get("resolved")
        if not isinstance(device_id, str) or not isinstance(resolved, dict):
            continue
        timestamps = record.get("timestamps")
        timestamps = timestamps if isinstance(timestamps, dict) else {}
        planned_at = timestamps.get("planned_at")
        planned_at = planned_at if type(planned_at) is int else -1
        rank = (planned_at, position)
        if device_id not in newest or rank > newest[device_id][0]:
            newest[device_id] = (rank, {
                "platform": resolved.get("platform"),
                "os_family": resolved.get("os_family"),
            })
    return {device_id: value
            for device_id, (_rank, value) in newest.items()}


_TARGET_CONTEXT_OMITTED = object()


def target_row_matches(row, filters, *, now,
                       quarantined_ids=_TARGET_CONTEXT_OMITTED,
                       status_key_fn=None, status_level_fn=None,
                       offline_fn=None):
    """Pure target-expression predicate shared by HTTP and schedulers.

    Fleet/record projections supply role, model_family, os_family and
    platform_resolved. Peer and status evaluation need explicit context so a
    caller cannot accidentally substitute device-authored or client-local
    state for the server-owned targeting facts.
    """
    mtype = filters.get("management_type")
    if mtype:
        raw = row.get("management_type")
        actual = "legacy" if (raw == "legacy_routed" or not raw) else raw
        if actual != mtype:
            return False
    platform = filters.get("platform")
    if platform:
        actual = row.get("platform_resolved") or row.get("platform") or ""
        if platform == "__none":
            if actual:
                return False
        elif actual != platform:
            return False
    cred = filters.get("cred")
    if cred:
        actual = row.get("credential_profile_id") or ""
        if cred == "__none":
            if actual:
                return False
        elif actual != cred:
            return False
    telemetry = filters.get("telemetry")
    if telemetry:
        if row.get("telemetry_enabled") is False:
            actual = "off"
        elif (row.get("telemetry_enabled") is True
              or isinstance(row.get("telemetry_stream_enabled"), bool)):
            actual = "on"
        else:
            actual = "unknown"
        if actual != telemetry:
            return False
    peer = filters.get("peer")
    if peer:
        if (quarantined_ids is _TARGET_CONTEXT_OMITTED
                or quarantined_ids is None):
            raise ValueError("peer targeting requires quarantine assignments")
        actual = ("quarantined"
                  if row.get("device_id") in quarantined_ids
                  else "not-quarantined")
        if actual != peer:
            return False
    role = filters.get("role")
    if role:
        declared = row.get("role") or ""
        if role == "__none":
            if declared:
                return False
        elif declared != role:
            return False
    model_family = filters.get("model_family")
    if model_family and row.get("model_family") != model_family:
        return False
    os_family = filters.get("os_family")
    if os_family and (row.get("os_family") or "") != os_family:
        return False
    status = filters.get("status")
    if status:
        if not all((status_key_fn, status_level_fn, offline_fn)):
            raise ValueError("status targeting requires server status evaluators")
        if status == "offline":
            if not offline_fn(row, now):
                return False
        elif status == "__attention":
            key = status_key_fn(row)
            if status_level_fn(row, key) not in (
                    "negative", "severe", "warning"):
                return False
        elif status_key_fn(row) != status:
            return False
    return True


# Mirrors app.js's STATUS_LEVELS (the 12-level Magnetic mapping) just far
# enough to answer "is this row's status one of negative/severe/warning" for
# the __attention rollup filter -- the console still owns the full label/
# icon rendering.
_STATUS_LEVELS = {
    "onboarding": "progress", "undeploying": "progress",
    "copying": "progress", "staging": "progress",
    "waiting-heartbeat": "info", "waiting-staging": "info",
    "onboard-failed": "negative", "undeploy-failed": "negative",
    "placement-failed": "negative",
    "deployed": "positive", "enrolled": "positive",
    "image-failed": "warning",
    "unassigned": "inactive", "not-enrolled": "inactive",
    "offline": "inactive",
}


class ScheduleTargetError(RuntimeError):
    """Stable public failure for an unavailable targeting authority."""

    def __init__(self, message, *, code="schedule_target_unavailable",
                 status=503):
        self.code = code
        self.status = status
        super().__init__(message)


@contextlib.contextmanager
def _runner_schedule_role_guard(guard, schedule):
    """Translate expected role-authority refusals into runner-safe reasons."""
    if guard is None:
        raise schedule_runner.ExecutionRefused("role_authority_unavailable")
    try:
        with guard(schedule) as policy:
            yield policy
    except role_management.RoleManagementError as exc:
        reason = exc.code if isinstance(exc.code, str) and re.fullmatch(
            r"[a-z][a-z0-9_]{0,63}", exc.code) else "role_authority_unavailable"
        raise schedule_runner.ExecutionRefused(reason) from None


def _target_row_assigned_ids(row):
    ids = row.get("assigned_image_ids")
    if ids:
        return ids
    single = row.get("assigned_image_id")
    return [single] if single else []


def _target_row_has_staged(row, image_id):
    if image_id in (row.get("errored_image_ids") or ()):
        return False
    staged = row.get("staged_image_ids")
    if staged is not None:
        return image_id in staged
    return (row.get("stage_state") == "ready"
            and row.get("current_image_id") == image_id)


def wave_swarm_contradictions(document, info_hashes):
    """Map device ids seen in *info_hashes* to whether the tracker agrees
    their download finished.

    False means the tracker still sees bytes outstanding for one of those
    torrents; True means it saw the device complete every torrent it appears
    in. A device the tracker has not seen at all is simply absent from the
    map: the registry is in-memory and empty for one prune horizon after a
    restart, so its silence is not a claim about that device.
    """
    out = {}
    images = document.get("images") if isinstance(document, dict) else None
    for image in images if isinstance(images, list) else ():
        if not isinstance(image, dict) or image.get("info_hash") not in info_hashes:
            continue
        peers = image.get("peers")
        for peer in peers if isinstance(peers, list) else ():
            if not isinstance(peer, dict):
                continue
            device_id = peer.get("device_id")
            state = peer.get("tracker")
            if not isinstance(device_id, str) or not isinstance(state, dict):
                continue
            left = state.get("left")
            if type(left) is int and left > 0:
                out[device_id] = False
            else:
                out.setdefault(device_id, True)
    return out


def wave_device_state(kind, heartbeat, image_ids, outcome, corroborated, *,
                      now):
    """Classify one preceding-wave target from the evidence that exists.

    Returns "staged", "errored", "missing" or "in_flight". Missing is
    deliberately not errored: a powered-off or slow-cadence device produces
    no evidence at all, and counting that as a failure would either raise an
    alarm nobody can act on or let one dark device hold a wave chain open
    forever. Corroboration may contradict a staged claim but can never
    create one, and its absence is never read as "not staged".
    """
    if outcome == "error":
        return "errored"
    if heartbeat is None:
        return "missing"
    if kind == "onboard":
        # An onboarding wave stages nothing itself; its own outcome is the
        # only honest completion evidence for the device.
        if outcome == "ok":
            return "staged"
    else:
        if any(image_id in (heartbeat.get("errored_image_ids") or ())
               for image_id in image_ids):
            return "errored"
        if image_ids and corroborated is not False and all(
                _target_row_has_staged(heartbeat, image_id)
                for image_id in image_ids):
            return "staged"
    if outcome == "skipped" or not heartbeat.get("last_seen") \
            or _target_is_offline(heartbeat, now):
        return "missing"
    return "in_flight"


def _target_status_key(row):
    onboard_finished_at = row.get("onboard_finished_at")
    last_seen = row.get("last_seen")
    job_fresh = bool(onboard_finished_at) and (
        not last_seen or last_seen < onboard_finished_at)
    onboard_state = row.get("onboard_state")
    onboard_action = row.get("onboard_action")
    if onboard_state in ("queued", "running"):
        return "undeploying" if onboard_action == "undeploy" else "onboarding"
    if onboard_state == "done" and onboard_action == "onboard" and job_fresh:
        return "waiting-heartbeat"
    if onboard_state == "error" and job_fresh:
        return "undeploy-failed" if onboard_action == "undeploy" else "onboard-failed"
    assigned_ids = _target_row_assigned_ids(row)
    errored_ids = [item for item in (row.get("errored_image_ids") or [])
                   if item in assigned_ids]
    if (assigned_ids and not errored_ids and
            all(_target_row_has_staged(row, item) for item in assigned_ids)):
        return "deployed"
    if errored_ids:
        return "image-failed"
    if row.get("stage_error") or row.get("stage_state") in ("error", "copy_failed"):
        return "placement-failed"
    if row.get("stage_state") == "transferring_to_ios":
        return "copying"
    if row.get("stage_state") in ("unassigned", "ready"):
        return "waiting-staging" if assigned_ids else "unassigned"
    if row.get("stage_state"):
        return "staging"
    if last_seen and not assigned_ids:
        return "unassigned"
    if last_seen:
        return "enrolled"
    return "not-enrolled"


def _target_status_level(row, key):
    if key == "image-failed":
        assigned = _target_row_assigned_ids(row)
        errored = [item for item in (row.get("errored_image_ids") or [])
                   if item in assigned]
        ratio = (len(errored) / len(assigned)) if assigned else 0
        return "severe" if ratio >= 0.5 else "warning"
    return _STATUS_LEVELS.get(key, "inactive")


def _target_is_offline(row, now):
    return bool(row.get("last_seen")) and (now - row["last_seen"]) >= 600


def _merge_target_row(device, policies, heartbeat_by_id, jobs, observed_at,
                      heartbeat_available, revoked_principals,
                      deployment_type=None):
    """Join one trusted targeting row from bounded authority snapshots."""
    device_id = device.get("device_id")
    policy = policies.get(device_id, {})
    heartbeat = heartbeat_by_id.get(device_id, {})
    row = dict(device)
    row.update(trusted_target_projection(device, deployment_type))
    row["assigned_image_id"] = policy.get("approved_image_id")
    row["assigned_image_ids"] = policy.get("approved_image_ids")
    for name in ("last_seen", "stage_state", "stage_error", "current_image_id",
                 "staged_image_ids", "errored_image_ids", "target_fs",
                 "telemetry_enabled", "telemetry_stream_enabled"):
        row[name] = heartbeat.get(name)
    row["heartbeat_model"] = heartbeat.get("model")
    revocation_available = isinstance(revoked_principals, (set, frozenset))
    revoked = ("device:%s" % device_id in revoked_principals
               if revocation_available and isinstance(device_id, str) else None)
    row["instruction"] = _instruction_device_projection(
        heartbeat, revoked, observed_at,
        heartbeat_available=heartbeat_available)
    job = jobs.get(device_id)
    if job:
        row["onboard_action"] = job["action"]
        row["onboard_state"] = job["state"]
        row["onboard_finished_at"] = job["finished_at"]
    return row


def resolve_schedule_target(target, *, fleet, catalog, record_store,
                            role_policy, now, jobs=None,
                            heartbeat_rows=None, revoked_principals=None):
    """Resolve a normalized target from one snapshot of each authority.

    The returned diagnostic fields are transient. Callers persist only
    revision, now, and device_ids in a schedule preview/target snapshot.
    These independent stores do not provide a cross-store transaction.
    """
    if not isinstance(target, dict):
        raise schedules.ScheduleValidationError("invalid target fields")
    filters = target.get("filters")
    explicit = target.get("device_ids")
    if not isinstance(filters, dict) or not isinstance(explicit, list):
        raise schedules.ScheduleValidationError("invalid target fields")
    heartbeat_dependent = bool(set(filters).intersection(
        ("q", "telemetry", "status")))
    if "status" in filters and jobs is None:
        raise ScheduleTargetError(
            "status targeting requires the management job authority",
            code="schedule_target_status_unavailable")
    if heartbeat_dependent and catalog is None:
        raise ScheduleTargetError(
            "targeting requires the heartbeat authority",
            code="schedule_target_heartbeat_unavailable")
    if role_policy.fail_closed or role_policy.degraded:
        raise ScheduleTargetError("peer policy is unavailable",
                                  code="schedule_target_policy_unavailable")

    revision, devices = fleet.snapshot()
    devices = sorted(devices, key=lambda row: str(row.get("device_id") or ""))
    records = record_store.list(strict=True) if record_store is not None else []
    deployment_types = deployment_target_snapshot(records)
    policies = catalog.list_policies() if catalog is not None else {}
    if heartbeat_rows is None:
        heartbeat_rows = catalog.list_devices() if catalog is not None else []
    heartbeat_available = isinstance(heartbeat_rows, list)
    if heartbeat_dependent and not heartbeat_available:
        raise ScheduleTargetError(
            "targeting requires the heartbeat authority",
            code="schedule_target_heartbeat_unavailable")
    heartbeat_by_id = {
        row.get("device_id"): row for row in (heartbeat_rows or [])
        if isinstance(row, dict) and isinstance(row.get("device_id"), str)}
    jobs = jobs or {}
    quarantined = frozenset(peer_policy.quarantine_device_ids(
        role_policy.document))
    drift = role_management.drift_report(
        fleet, role_policy,
        limit=len(devices) + len(role_policy.roles.role_of), rows=devices)
    drift_ids = frozenset(drift["device_ids"])
    q = filters.get("q")
    q = q.lower() if isinstance(q, str) and q else None
    column_filters = {key: value for key, value in filters.items() if key != "q"}
    explicit_ids = frozenset(explicit)

    def matches(row, chosen_filters):
        if explicit_ids and row.get("device_id") not in explicit_ids:
            return False
        if q:
            haystack = " ".join(str(row.get(key) or "") for key in
                                ("device_id", "device_ip", "model",
                                 "heartbeat_model")).lower()
            if q not in haystack:
                return False
        return target_row_matches(
            row, chosen_filters, now=now, quarantined_ids=quarantined,
            status_key_fn=_target_status_key,
            status_level_fn=_target_status_level,
            offline_fn=_target_is_offline)

    matched = []
    missing_os_family = 0
    role_drift = 0
    without_os = {key: value for key, value in column_filters.items()
                  if key != "os_family"}
    for device in devices:
        row = _merge_target_row(
            device, policies, heartbeat_by_id, jobs, now,
            heartbeat_available, revoked_principals,
            deployment_types.get(device.get("device_id"), {}))
        if not row.get("os_family") and matches(row, without_os):
            missing_os_family += 1
        if not matches(row, column_filters):
            continue
        device_id = row["device_id"]
        matched.append(device_id)
        if device_id in drift_ids:
            role_drift += 1
    return {"revision": revision, "now": int(now), "device_ids": matched,
            "missing_os_family": missing_os_family,
            "role_drift": role_drift,
            "quarantined_ids": sorted(quarantined.intersection(matched))}


# ---- persisted deploy logs (written by OnboardService._persist_log) -------
# Filename: <finished_at>-<sanitized device>-<action>-<jobid>.log; first line
# is a "# job=... device=<raw id> ..." header. The header is authoritative
# (it carries the RAW device id); the filename is only a fallback.
_DEPLOY_LOG_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+\.log$")
_DEPLOY_LOG_HEADER_RE = re.compile(
    r"^# job=(?P<job>\S+) device=(?P<device>.*?) action=(?P<action>\S+) "
    r"state=(?P<state>\S+) rc=(?P<rc>\S+) queued_at=\S+ started_at=\S+ "
    r"finished_at=(?P<finished>\S+) platform=\S+$")


def _int_or_none(raw):
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _deploy_log_histogram(log_dir, since_ts, until_ts, buckets, device_id=None):
    """Bin deploy logs into evenly-spaced buckets over [since_ts, until_ts),
    oldest-first, including empty buckets -- the deploy-log counterpart of
    audit.histogram, so the two timelines behave identically. Never raises; an
    unreadable directory yields all-zero buckets."""
    n = max(1, min(int(buckets), 200))
    span = until_ts - since_ts
    width = span / n if span > 0 else 0
    starts = [since_ts + i * width for i in range(n)]
    counts = [0] * n
    for entry in _list_deploy_logs(log_dir, device_id=device_id):
        ts = entry.get("finished_at")
        if not isinstance(ts, int) or ts < since_ts or ts >= until_ts:
            continue
        idx = int((ts - since_ts) / width) if width else 0
        counts[min(max(idx, 0), n - 1)] += 1
    return [{"start": int(starts[i]), "count": counts[i]} for i in range(n)]


def _list_deploy_logs(log_dir, device_id=None, after_ts=None, before_ts=None,
                      registered_at=None):
    """Metadata for every parseable *.log under log_dir, newest first:
    {"file","device_id","action","state","rc","finished_at","size"}. The
    header line wins; a file with a missing/garbled header falls back to the
    filename fields (state/rc unknown); anything unparseable either way is
    skipped. The device_id filter compares the RAW id from the header.

    *registered_at* is when the device currently holding this id was registered.
    Logs are keyed on the bare id and deliberately outlive a delete (they are
    the forensic record of what ran), so after a device is deleted and added
    back — a rebuilt or replaced box — its predecessor's runs would otherwise be
    read as this device's own history. Entries finishing before that stamp are
    flagged ``previous_registration`` rather than hidden: the run happened, it
    just happened to a different machine. Omit the stamp and nothing is
    flagged, which is what pre-existing devices (no stamp) get."""
    if not log_dir or not os.path.isdir(log_dir):
        return []
    out = []
    for name in os.listdir(log_dir):
        if not _DEPLOY_LOG_NAME_RE.match(name):
            continue
        full = os.path.join(log_dir, name)
        try:
            size = os.path.getsize(full)
            with open(full, encoding="utf-8", errors="replace") as f:
                first = f.readline().rstrip("\n")
        except OSError:
            continue
        m = _DEPLOY_LOG_HEADER_RE.match(first)
        if m:
            entry = {"file": name, "device_id": m.group("device"),
                     "action": m.group("action"), "state": m.group("state"),
                     "rc": _int_or_none(m.group("rc")),
                     "finished_at": _int_or_none(m.group("finished")),
                     "size": size}
        else:
            parts = name[:-len(".log")].split("-")
            if len(parts) < 4 or not parts[0].isdigit():
                continue
            entry = {"file": name, "device_id": "-".join(parts[1:-2]),
                     "action": parts[-2], "state": None, "rc": None,
                     "finished_at": int(parts[0]), "size": size}
        if device_id is not None and entry["device_id"] != device_id:
            continue
        if registered_at is not None:
            entry["previous_registration"] = (
                entry.get("finished_at") or 0) < registered_at
        # Inclusive at both ends: a brush selection must contain the entries
        # sitting exactly on the edges the operator dragged to.
        ts = entry.get("finished_at")
        if after_ts is not None and (ts is None or ts < after_ts):
            continue
        if before_ts is not None and (ts is None or ts > before_ts):
            continue
        out.append(entry)
    out.sort(key=lambda e: (e["finished_at"] or 0, e["file"]), reverse=True)
    return out


def _read_deploy_log(log_dir, name):
    """Bytes of one persisted deploy log, or None. The name must look like a
    log filename AND realpath-resolve to a direct child of log_dir — rejects
    traversal and symlinks pointing out of the directory."""
    if not log_dir or not _DEPLOY_LOG_NAME_RE.match(name or ""):
        return None
    root = os.path.realpath(log_dir)
    full = os.path.realpath(os.path.join(root, name))
    if os.path.dirname(full) != root:
        return None
    try:
        with open(full, "rb") as f:
            return f.read()
    except OSError:
        return None


def _read_version():
    """Best-effort IRIS version: IRIS_VERSION env, else a VERSION file near this
    module (present in a source checkout and the self-contained image), else
    'unknown'. A non-empty IRIS_VERSION build arg / env takes precedence."""
    v = os.environ.get("IRIS_VERSION", "").strip()
    if v:            # empty/blank env (compose's "${IRIS_VERSION:-}") = unset
        return v
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, "..", "VERSION"), os.path.join(here, "VERSION")):
        try:
            with open(cand) as f:
                return f.read().strip() or "unknown"
        except OSError:
            continue
    return "unknown"


# Official documentation site (GitHub Pages build of docs/ + docs/zensical/,
# published by .github/workflows/docs.yml). Surfaced by GET /api/help so the
# console's "?" popover can deep-link it.
_DOCS_URL = "https://cisco-open.github.io/intelligent-release-image-staging/"
_INSTANCE_ID_BASENAME = "instance-id"


def read_instance_id(state_dir):
    """Stable per-deployment id: $IRIS_STATE/instance-id holds a uuid4 hex,
    minted exactly once (mode 0600) and immutable afterwards. Created at
    main() startup and lazily by this reader, so tests can call it directly.
    Never raises: an unreadable/unwritable state dir degrades to a fresh
    per-call id rather than breaking /api/help."""
    path = os.path.join(state_dir, _INSTANCE_ID_BASENAME)
    try:
        with open(path) as f:
            existing = f.read().strip()
        if existing:
            return existing
    except OSError:
        pass
    fresh = uuid.uuid4().hex
    try:
        os.makedirs(state_dir, exist_ok=True)
        # O_EXCL: first writer wins; a concurrent creator loses the race and
        # re-reads the winner's id so every caller agrees on one value.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(fresh + "\n")
    except FileExistsError:
        try:
            with open(path) as f:
                return f.read().strip() or fresh
        except OSError:
            return fresh
    except OSError:
        return fresh
    return fresh


def _resolve_certfile():
    """Serve-time TLS cert resolution for the console listener.

    The console-specific override (IRIS_GUI_CERT, combined cert+key built by
    the cert-upload flow and the entrypoint) wins WHEN ITS FILE EXISTS; else
    the shared combined IRIS_CERT file all three TLS services load; else
    None -> main() refuses to start unless IRIS_GUI_ALLOW_PLAINTEXT=1 opts
    into a plain-HTTP console. Catalog and artifact server keep loading
    IRIS_CERT directly, so device pinning is untouched."""
    gui = os.environ.get("IRIS_GUI_CERT", "/run/iris/tls/gui-cert.pem")
    if os.path.exists(gui):
        return gui
    cert = os.environ.get("IRIS_CERT", _IRIS_CERT_DEFAULT)
    if os.path.exists(cert):
        return cert
    return None


# ---- CA-trust settings + refresh jobs (spec A3) ---------------------------
# $IRIS_STATE/ca-trust-settings.json {"url": str|null, "auto": bool}. The
# console is both writer AND consumer (the daily thread below runs in this
# process), so the helpers live here rather than in a shared module the way
# telemetry-settings.json does.
_CA_TRUST_BASENAME = "ca-trust-settings.json"
# Built-in default CA-bundle source (Cisco's published trust store). A
# missing/null/blank configured url falls back to this so a fresh install
# can hit "Download now" (or enable auto) with zero configuration.
_CA_TRUST_DEFAULT_URL = "https://www.cisco.com/security/pki/trs/ios.p7b"
_CA_REFRESH_PERIOD = 24 * 60 * 60   # daily auto-download cadence (s)
_CA_REFRESH_FIRST_DELAY = 60        # "shortly after start" first pass (s)


def ca_trust_settings_path(state_dir):
    return os.path.join(state_dir, _CA_TRUST_BASENAME)


def _read_ca_trust_raw(path):
    """Tolerant raw reader: missing/corrupt file or wrong types -> None.
    Returns {"url": str|None, "auto": bool} WITHOUT applying the default-URL
    fallback. Used by audit logging to distinguish never-configured from
    explicitly-set. A settings reader never raises."""
    url, auto = None, False
    try:
        with open(path) as f:
            data = json.load(f)
        raw = data.get("url")
        if isinstance(raw, str) and raw.strip():
            url = raw.strip()
        auto = data.get("auto") is True
    except (OSError, ValueError, AttributeError):
        pass
    return {"url": url, "auto": auto}


def read_ca_trust_settings(path):
    """Tolerant reader: missing/corrupt file or wrong types -> defaults. A
    missing/null/blank configured url falls back to the built-in default CA
    bundle source (_CA_TRUST_DEFAULT_URL); auto stays off unless the file
    explicitly says otherwise. A settings reader never raises."""
    raw = _read_ca_trust_raw(path)
    return {"url": raw["url"] or _CA_TRUST_DEFAULT_URL, "auto": raw["auto"]}


def write_ca_trust_settings(path, url, auto):
    """Atomic write: mkstemp in the same dir + os.replace (house idiom).
    url may be None -- that is stored literally (first-class "unset"); the
    default-URL fallback lives in the reader, not here, so an operator can
    tell "never configured" apart from "explicitly cleared" if it ever
    matters, and both read back through read_ca_trust_settings() as the
    built-in default."""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".ca-trust-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"url": url, "auto": bool(auto)}, f, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _validate_otlp_endpoint(raw, authenticated=False):
    """Telemetry-destination endpoint validation (design doc, feature B):
    http or https, host required, no query/fragment; the trailing slash is
    stripped so the exporters derive <endpoint>/v1/logs cleanly (they
    rstrip('/') too — otlp.py:252). Returns (endpoint, None) on success or
    (None, error-message)."""
    url = raw.strip()
    try:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            return None, "endpoint must be an http:// or https:// URL with a host"
        if parts.username is not None or parts.password is not None:
            return None, "endpoint must not contain credentials"
        if parts.hostname is None:
            return None, "endpoint must be an http:// or https:// URL with a host"
        if parts.query or parts.fragment:
            return None, "endpoint must not have a query or fragment"
        if authenticated and parts.scheme != "https":
            return None, "authenticated telemetry endpoint must use https://"
        return url.rstrip("/"), None
    except ValueError:
        return None, "endpoint must be an http:// or https:// URL with a host"


_CA_JOB_TTL = 3600                  # evict terminal refresh jobs after (s)
# In-memory refresh jobs (the gui_images.start_publish idiom): id -> dict,
# a daemon thread runs the download, GET /api/settings/ca-trust/refresh/<id>
# polls. Per-process: a restart abandons in-flight jobs.
_CA_JOBS = {}
_CA_JOBS_LOCK = threading.Lock()


def _validate_ca_url(raw):
    """Return a normalized HTTPS CA endpoint, or ``None``.

    Userinfo and query/fragment data commonly carry credentials (Basic or
    signed URLs). They are neither persisted nor handed to audit/error paths.
    """
    if not isinstance(raw, str):
        return None
    url = raw.strip()
    try:
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.netloc or not parts.hostname \
                or parts.username is not None or parts.password is not None \
                or parts.query or parts.fragment:
            return None
        # Force malformed bracket/port spellings through validation.
        _ = parts.port
    except ValueError:
        return None
    return url.rstrip("/")


def _ca_endpoint_label(url):
    """Nonsecret audit label: scheme/host/port only, never URL path data."""
    normalized = _validate_ca_url(url)
    if normalized is None:
        return "(invalid)"
    parts = urlsplit(normalized)
    host = parts.hostname or ""
    if ":" in host:
        host = "[" + host + "]"
    return "%s://%s%s" % (
        parts.scheme, host, ":%d" % parts.port if parts.port else "")


def ca_refresh_due(settings):
    """Pure decision for the daily loop: the URL to download this cycle, or
    None to skip (auto off / no URL). No clock, no I/O. settings is whatever
    the caller passes -- typically read_ca_trust_settings()'s output, whose
    url is never empty (default-URL fallback), so in practice this reduces
    to the auto flag; the url checks stay so the function is correct against
    a raw/partial dict too."""
    if not isinstance(settings, dict) or settings.get("auto") is not True:
        return None
    return _validate_ca_url(settings.get("url"))


def _run_ca_download(url, download_fn=None):
    """One CA-bundle download attempt -> (ok, detail, certs). Never raises;
    detail is audit/UI-safe (URL + error text only, never cert material --
    and download_bundle never puts key/cert bytes in its error strings)."""
    normalized = _validate_ca_url(url)
    if normalized is None:
        return False, "configured CA endpoint is invalid", None
    try:
        result = (download_fn or trust.download_bundle)(normalized)
    except Exception as exc:    # download_bundle reports; belt and suspenders
        result = {"ok": False, "certs": 0, "error": str(exc)}
    if result.get("ok") is True:
        certs = int(result.get("certs") or 0)
        return (True, "downloaded %d certificate(s) from configured endpoint"
                % certs,
                certs)
    # Downloader exception text may contain its request URL. Keep the job and
    # audit result useful without reflecting endpoint path/credential data.
    return False, "CA bundle download failed", None


def start_ca_refresh(url, audit_fn=None, download_fn=None):
    """Run one CA-bundle download on a daemon thread; returns a job id for
    the poll route immediately. audit_fn(result=..., detail=...) is called
    BEFORE the job turns terminal so a poller that sees done/failed can rely
    on the audit line already existing."""
    job_id = secrets.token_hex(8)
    job = {"state": "running", "detail": "", "certs": None,
           "finished_at": None}
    now = time.time()
    with _CA_JOBS_LOCK:
        stale = [jid for jid, j in _CA_JOBS.items()
                 if j["finished_at"] is not None
                 and j["finished_at"] <= now - _CA_JOB_TTL]
        for jid in stale:
            del _CA_JOBS[jid]
        _CA_JOBS[job_id] = job

    def run():
        ok, detail, certs = _run_ca_download(url, download_fn=download_fn)
        if audit_fn is not None:
            try:
                audit_fn(result="ok" if ok else "fail", detail=detail)
            except Exception:
                pass                # audit must never break the job
        with _CA_JOBS_LOCK:
            job["state"] = "done" if ok else "failed"
            job["detail"] = detail
            job["certs"] = certs
            job["finished_at"] = time.time()

    threading.Thread(target=run, daemon=True).start()
    return job_id


def get_ca_job(job_id):
    """Poll view {"state","detail","certs"}, or None for an unknown id."""
    with _CA_JOBS_LOCK:
        job = _CA_JOBS.get(job_id)
        if job is None:
            return None
        return {"state": job["state"], "detail": job["detail"],
                "certs": job["certs"]}


def ca_trust_refresh_loop(stop_event, state_dir, audit_fn=None,
                          period=_CA_REFRESH_PERIOD,
                          first_delay=_CA_REFRESH_FIRST_DELAY,
                          download_fn=None):
    """Daily public-CA auto-refresh (spec A3): stop-event wait loop like
    telemetry.run_forever, with a short first delay so an enabled config is
    honored shortly after start. Re-reads the settings file every cycle,
    skips quietly unless auto && url (ca_refresh_due), audits completions as
    ca-trust-refresh with actor system, and never lets a failure kill the
    thread -- a failed download just retries next cycle."""
    delay = first_delay
    while not stop_event.wait(delay):
        delay = period
        try:
            url = ca_refresh_due(
                read_ca_trust_settings(ca_trust_settings_path(state_dir)))
            if url is None:
                continue
            ok, detail, _certs = _run_ca_download(url,
                                                  download_fn=download_fn)
            if audit_fn is not None:
                audit_fn(event="ca-trust-refresh", category="settings",
                         action="refresh", target="ca-trust", actor="system",
                         result="ok" if ok else "fail", detail=detail)
        except Exception:
            pass                    # the daily thread must never die


def _plaintext_allowed():
    return os.environ.get(_PLAINTEXT_OPT_IN_ENV, "") == "1"


class ConsoleTLSError(RuntimeError):
    """A certificate was configured for the console but none of the
    candidate files is usable, and plaintext was not opted into."""


class _ConsoleServer(bounded_pool.BoundedThreadingMixin, ThreadingHTTPServer):
    """ThreadingHTTPServer that completes the TLS handshake in the WORKER
    thread and bounds the pool of concurrently running handler threads.
    Same mechanism (and reason) as artifact_server._Server: wrapping
    the LISTENING socket makes socketserver perform the whole handshake
    inside accept() on the single serve_forever thread, so one client that
    connects and never sends a ClientHello (nc, a port scan, a TCP health
    check, a stalled NAT'd client) freezes the console for every operator
    until it goes away. Here accept() hands back the plain socket and the
    wrap happens per connection. ``tls_context`` is retained, so
    reload_tls() hot-swapping the chain keeps working unchanged."""

    request_queue_size = 128
    tls_context = None
    # The console holds long-lived SSE streams open for onboard-log tailing
    # (Handler's text/event-stream route, below) -- up to
    # IRIS_ONBOARD_CONCURRENCY (default 25) of them at once. Sized well above
    # that plus ordinary multi-operator browsing/polling traffic, so
    # bounded_pool's admission timeout is only ever reached under genuine
    # overload, never by the SSE streams this console itself holds open.
    max_concurrent_requests = 256

    def get_request(self):
        sock, addr = self.socket.accept()
        if self.tls_context is not None:
            sock.settimeout(_HANDSHAKE_TIMEOUT)
        return sock, addr

    def process_request_thread(self, request, client_address):
        if self.tls_context is not None:
            try:
                request = self.tls_context.wrap_socket(request, server_side=True)
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


class _OnboardSubmissionAdapter(object):
    """One admission path for browser and authenticated local submissions."""

    _HEX16 = re.compile(r"^[0-9a-f]{16}$")
    _HEX32 = re.compile(r"^[0-9a-f]{32}$")
    _RECORD_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
    _TERMINAL = frozenset(("done", "error", "cancelled"))

    def __init__(self, fleet, creds, record_store, onboard, iox_controller,
                 plan_fn, apply_preflight_fn, owned_resources_fn,
                 teardown_resolved_fn, audit_path, now_fn, teardown_plan_fn=None):
        self.fleet = fleet
        self.creds = creds
        self.record_store = record_store
        self.onboard = onboard
        self.iox_controller = iox_controller
        self._plan = plan_fn
        self._teardown_plan = teardown_plan_fn or plan_fn
        self._apply_preflight = apply_preflight_fn
        self._owned_resources = owned_resources_fn
        self._teardown_resolved = teardown_resolved_fn
        self.audit_path = audit_path
        self._now = now_fn

    @staticmethod
    def _bounded_identifier(value, limit):
        if not isinstance(value, str) or not value:
            return False
        try:
            raw = value.encode("utf-8")
        except UnicodeError:
            return False
        return (len(raw) <= limit and
                not any(ord(character) < 32 or 127 <= ord(character) <= 159
                        for character in value))

    def _audit(self, event, category, action=None, target=None, detail=None,
               actor=None, result="ok"):
        if self.audit_path is None:
            return
        try:
            audit.append_event(
                self.audit_path, event, actor=actor, category=category,
                action=action, target=target, detail=detail, result=result)
        except Exception:
            pass

    def prevalidate_device(self, device_id, action, actor=None, audit_fn=None):
        audit_emit = audit_fn or self._audit

        def reject(status, error):
            audit_emit(
                "%s_start" % action, "onboard", action="start",
                target=device_id, actor=actor, result="fail", detail=error)
            return status, {"error": error}

        if self.onboard is None:
            return 404, {"error": "not found"}
        if action not in ("onboard", "undeploy"):
            return reject(400, "invalid action")
        if not self._bounded_identifier(device_id, 128):
            return reject(400, "bad device id")
        if self.fleet is None or self.fleet.get_device(device_id) is None:
            return reject(404, "no such device")
        return None

    def submit_device(self, device_id, action, body, actor=None, audit_fn=None,
                      require_iox=False):
        """Validate authority, prepare callbacks, and enqueue exactly once.

        The returned pair is the existing HTTP status and JSON body. Local
        control uses the same pair and only changes its wire projection.
        """
        audit_emit = audit_fn or self._audit

        def reject(status, error):
            audit_emit(
                "%s_start" % action, "onboard", action="start",
                target=device_id, actor=actor, result="fail", detail=error)
            return status, {"error": error}

        invalid = self.prevalidate_device(
            device_id, action, actor=actor, audit_fn=audit_emit)
        if invalid is not None:
            return invalid
        device = self.fleet.get_device(device_id)
        if not isinstance(body, dict):
            return reject(400, "request body must be an object")

        if "force" in body and type(body["force"]) is not bool:
            return reject(400, "force must be a bool")
        force = body.get("force", False) is True
        if action == "onboard" and force:
            return reject(400, "force is valid only for undeploy")
        telemetry = body.get("telemetry", True) is not False
        stream = body.get("telemetry_stream", False) is True
        env_extra = {
            "TELEMETRY": "on" if telemetry else "off",
            "TELEMETRY_STREAM": "on" if stream else "off",
        }
        env_extra["IRIS_TELEMETRY"] = env_extra["TELEMETRY"]
        env_extra["IRIS_TELEMETRY_STREAM"] = env_extra["TELEMETRY_STREAM"]
        undeploy_env = None
        resolved = None
        record_ref = {}
        selected_record_id = None
        prepare = None
        pre_apply = None
        on_success = None

        if action == "onboard":
            if self.record_store is not None:
                try:
                    plan = self._plan(device_id, device)
                except ValueError as exc:
                    return reject(409, str(exc))
                if require_iox and plan["resolved"].get("platform") != "iox":
                    return reject(409, "device is not an IOx target")
                if plan["resolved"].get("platform") == "router":
                    try:
                        existing = self.record_store.recoverable_for_device(
                            device_id, strict=True)
                    except deployment_records.RecordStoreUnreadable as exc:
                        return reject(
                            503, "%s; the console cannot safely inspect "
                            "deployment authority" % exc)
                    except ValueError as exc:
                        return reject(409, str(exc))
                    if existing is not None:
                        return reject(
                            409, "router already has a %s deployment record; "
                            "undeploy it before onboarding again — if this "
                            "device was replaced, undeploy with force, or "
                            "delete and re-add it" %
                            existing.get("state", "recorded"))
                resolved = plan["resolved"]

                def prepare():
                    record_id = self.record_store.create({
                        "controller_id": "iris", "device_id": device_id,
                        "inventory_revision": self.fleet.revision(),
                        "plan_hash": plan["plan_hash"],
                        "resolved": plan["resolved"],
                        "preflight": {"status": "pending"},
                        "resources": self._owned_resources(
                            plan["resolved"]),
                    })["record_id"]
                    record_ref["id"] = record_id
                    return record_id

                def pre_apply(evidence):
                    final_plan = self._apply_preflight(plan, evidence)
                    record_id = record_ref.get("id")
                    if not record_id:
                        raise ValueError("planned record is unavailable")
                    self.record_store.update_planned(
                        record_id, plan_hash=final_plan["plan_hash"],
                        resolved=final_plan["resolved"], preflight=evidence,
                        resources=self._owned_resources(
                            final_plan["resolved"]))
                    return final_plan["resolved"]
            else:
                try:
                    degraded_plan = self._plan(device_id, device)
                except ValueError as exc:
                    return reject(409, str(exc))
                if require_iox and degraded_plan["resolved"].get(
                        "platform") != "iox":
                    return reject(409, "device is not an IOx target")
                if degraded_plan["resolved"].get("platform") == "router":
                    return reject(
                        503, "router onboarding requires the deployment "
                        "record store")
        elif self.record_store is not None:
            if force:
                try:
                    degraded_plan = self._teardown_plan(device_id, device)
                except ValueError as exc:
                    return reject(409, str(exc))
                resolved = degraded_plan["resolved"]
                if require_iox and resolved.get("platform") != "iox":
                    return reject(409, "device is not an IOx target")
                undeploy_env = {"IRIS_FORCE_AGENT_ONLY": "1"}
                if resolved.get("platform") != "iox":
                    def on_success():
                        self.record_store.retire_device(
                            device_id,
                            "forced agent-only teardown; the record no longer "
                            "describes this device")
                audit_emit(
                    "undeploy_forced", "onboard", action="start",
                    target=device_id, actor=actor, result="ok",
                    detail="forced agent-footprint teardown; VPG/NAT left "
                           "untouched, any deployment record abandoned once "
                           "the teardown succeeds")
            else:
                try:
                    record = self.record_store.recoverable_for_device(
                        device_id, strict=True)
                except deployment_records.RecordStoreUnreadable as exc:
                    return reject(
                        503, "%s; the console cannot tell whether this device "
                        "has a deployment until the file is repaired" % exc)
                except ValueError as exc:
                    return reject(
                        409, "%s; retry with force to remove the agent "
                        "footprint only" % exc)
                if record is None:
                    return reject(
                        409, "no deployment record for this device; adopt it "
                        "first, then undeploy, or retry with force to remove "
                        "the agent footprint only")
                selected_record_id = record["record_id"]
                try:
                    resolved = self._teardown_resolved(record)
                except ValueError as exc:
                    try:
                        self.record_store.transition(
                            record["record_id"], "needs-reconcile")
                    except ValueError:
                        pass
                    return reject(409, str(exc))
                if require_iox and resolved.get("platform") != "iox":
                    return reject(409, "device is not an IOx target")

                def prepare():
                    record_ref["id"] = record["record_id"]
                    return record["record_id"]
        else:
            try:
                degraded_plan = self._teardown_plan(device_id, device)
            except ValueError as exc:
                return reject(409, str(exc))
            if require_iox and degraded_plan["resolved"].get(
                    "platform") != "iox":
                return reject(409, "device is not an IOx target")
            if degraded_plan["resolved"].get("platform") == "router":
                return reject(
                    503, "router undeploy requires an active deployment "
                    "record")

        try:
            job_id = self.onboard.start(
                device_id, action=action, resolved=resolved, prepare=prepare,
                pre_apply=pre_apply, on_success=on_success,
                record_id=selected_record_id,
                teardown_mode=(
                    "none" if action == "onboard" else
                    "force_agent_only" if force else "recorded"),
                env_extra=(env_extra if action == "onboard" else undeploy_env))
        except ValueError as exc:
            if record_ref.get("id") and action == "onboard":
                try:
                    self.record_store.transition(
                        record_ref["id"], "needs-reconcile")
                except ValueError:
                    pass
            return reject(409, str(exc))
        audit_emit(
            "%s_start" % action, "onboard", action="start",
            target=device_id, actor=actor, detail="job %s" % job_id)
        return 200, {"job_id": job_id}

    def _credential_ref(self, device_id):
        device = self.fleet.get_device(device_id) if self.fleet else None
        if device is None:
            raise ValueError("no such device")
        reference = device.get("credential_profile_id") or ""
        profiles = self.creds.list_profiles() if self.creds is not None else []
        if (not self._bounded_identifier(reference, 256) or
                not any(isinstance(profile, dict) and
                        profile.get("id") == reference for profile in profiles)):
            raise ValueError("device has no credential profile")
        return reference

    @staticmethod
    def _job_response(job, accepted=False, timed_out=False):
        if job["state"] in _OnboardSubmissionAdapter._TERMINAL:
            result_code = job.get("result_code")
            allowed = frozenset((0, 2, 3, 4, 5, 130))
            recovery_code = job.get("recovery_code")
            returncode = job.get("returncode")
            if (type(result_code) is not int or result_code not in allowed or
                    (job["state"] == "done") != (result_code == 0) or
                    (job["state"] == "cancelled") != (result_code == 130) or
                    (returncode is not None and type(returncode) is not int) or
                    (recovery_code is not None and
                     (type(recovery_code) is not int or
                      recovery_code not in allowed))):
                raise ValueError("invalid terminal job result")
            return {
                "terminal": True, "state": job["state"],
                "job_id": job["id"], "record_id": job.get("record_id"),
                "result_code": result_code,
                "returncode": returncode,
                "recovery_code": recovery_code,
            }
        response = {
            "job_id": job["id"], "state": job["state"],
            "terminal": False, "record_id": job.get("record_id"),
            "result_code": None,
        }
        if accepted:
            response = {"accepted": True, **response}
        if timed_out:
            response["wait_timed_out"] = True
        return response

    def _observe_job(self, job_id, wait, timeout, accepted=False):
        deadline = time.monotonic() + timeout
        while True:
            job = self.onboard.get_job(job_id) if self.onboard else None
            if job is None:
                return {"error": "job not found", "job_id": job_id}
            if job["state"] in self._TERMINAL:
                return self._job_response(job)
            if not wait:
                return self._job_response(job, accepted=accepted)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return self._job_response(job, timed_out=True)
            time.sleep(min(0.05, remaining))

    def _validate_control_request(self, request):
        if not isinstance(request, dict):
            raise ValueError("invalid request")
        operation = request.get("operation")
        required = {"operation", "wait"}
        optional = set()
        if operation in ("submit-install", "submit-uninstall", "recover"):
            required.add("device_id")
            if operation == "submit-uninstall":
                optional.add("force_agent_only")
        elif operation == "job":
            required.add("job_id")
        elif operation == "reconcile-enabled":
            required.update(("record_id", "transaction_id", "revision",
                             "acknowledge_external_resolution"))
        else:
            raise ValueError("unknown operation")
        if request.get("wait") is True:
            optional.add("wait_timeout")
        if set(request) - required - optional or required - set(request):
            raise ValueError("invalid request shape")
        if type(request["wait"]) is not bool:
            raise ValueError("invalid wait flag")
        if "wait_timeout" in request:
            value = request["wait_timeout"]
            if type(value) is not int or not 1 <= value <= 7200:
                raise ValueError("invalid wait timeout")
        if "device_id" in request and not self._bounded_identifier(
                request["device_id"], 128):
            raise ValueError("invalid device id")
        if "job_id" in request and (not isinstance(request["job_id"], str)
                or not self._HEX16.fullmatch(request["job_id"])):
            raise ValueError("invalid job id")
        if "record_id" in request and (not isinstance(request["record_id"], str)
                or not self._RECORD_ID.fullmatch(request["record_id"])):
            raise ValueError("invalid record id")
        if "transaction_id" in request and (
                not isinstance(request["transaction_id"], str) or
                not self._HEX32.fullmatch(request["transaction_id"])):
            raise ValueError("invalid transaction id")
        if "revision" in request and (
                type(request["revision"]) is not int or
                request["revision"] < 0):
            raise ValueError("invalid revision")
        if "force_agent_only" in request and request["force_agent_only"] is not True:
            raise ValueError("invalid force flag")
        if operation == "reconcile-enabled" and request[
                "acknowledge_external_resolution"] is not True:
            raise ValueError("reconciliation acknowledgement is required")
        return operation

    def dispatch(self, request):
        """Validate one closed local request and return its exact projection."""
        try:
            operation = self._validate_control_request(request)
            wait = request["wait"]
            timeout = request.get("wait_timeout", 7200)
            if operation == "job":
                return self._observe_job(
                    request["job_id"], wait, timeout, accepted=False)
            if operation in ("submit-install", "submit-uninstall"):
                action = ("onboard" if operation == "submit-install" else
                          "undeploy")
                status, response = self.submit_device(
                    request["device_id"], action,
                    {"force": request.get("force_agent_only", False)},
                    actor="local-control", require_iox=True)
                if status != 200:
                    return {"error": response.get("error", "request rejected")}
                return self._observe_job(
                    response["job_id"], wait, timeout, accepted=not wait)
            if operation == "recover":
                device_id = request["device_id"]
                credential_ref = self._credential_ref(device_id)
                authority = self.iox_controller.summary_for_device(device_id)
                sources = (authority.get("iox_verification_obligations", []) +
                           authority.get("iox_sessions", []))
                boards = {
                    item.get("board_identity") for item in sources
                    if isinstance(item, dict) and item.get("board_identity")}
                if len(boards) != 1:
                    raise ValueError("recovery target board is ambiguous")
                board = next(iter(boards))
                historical_records = set()
                for item in sources:
                    if (not isinstance(item, dict) or
                            item.get("board_identity") != board):
                        continue
                    value = item.get("record_id")
                    if value is None:
                        continue
                    if (not isinstance(value, str) or
                            self._RECORD_ID.fullmatch(value) is None):
                        raise ValueError("invalid recovery record")
                    historical_records.add(value)
                if len(historical_records) > 1:
                    raise ValueError("recovery target record is ambiguous")
                historical_record = (next(iter(historical_records))
                                     if historical_records else None)
                job_id = self.onboard.start_iox_recovery(
                    device_id, credential_ref, board,
                    record_id=historical_record)
            else:
                record = self.record_store.get(request["record_id"], strict=True)
                if record is None:
                    raise ValueError("unknown record")
                journal = record.get("iox_verification")
                if (not isinstance(journal, dict) or
                        journal.get("record_id") != request["record_id"] or
                        journal.get("controller_id") != getattr(
                            self.iox_controller, "controller_id", None) or
                        journal.get("transaction_id") != request["transaction_id"] or
                        journal.get("revision") != request["revision"] or
                        journal.get("phase") != "indeterminate"):
                    raise ValueError("stale reconciliation binding")
                device_id = record.get("device_id")
                credential_ref = self._credential_ref(device_id)
                board = journal.get("board_identity")
                if not self._bounded_identifier(board, 128):
                    raise ValueError("invalid reconciliation board")
                job_id = self.onboard.start_iox_reconciliation(
                    device_id, credential_ref, board, request["record_id"],
                    request["transaction_id"], request["revision"], True)
            return self._observe_job(job_id, wait, timeout, accepted=not wait)
        except (KeyError, TypeError, ValueError,
                deployment_records.RecordStoreUnreadable):
            return {"error": "request rejected"}
        except Exception:
            return {"error": "authority unavailable"}


class _ScheduledExecutor(object):
    """Execute the two stage-only schedule verbs against live authorities."""

    _ACTIVE_OCCURRENCES = frozenset(("pending", "running", "interrupted"))
    _ACTIVE_JOBS = frozenset(("queued", "running"))
    _TERMINAL_RECORDS = frozenset(("removed", "superseded", "abandoned"))
    _UNBOUND = object()

    def __init__(self, *, schedule_store, occurrence_store, receipt_store,
                 role_guard, role_policy_snapshot, fleet, secrets_path,
                 assignment_writer, submission, onboard, record_store,
                 now_fn=time.time, catalog=None, heartbeat_fn=None,
                 swarm_fn=None):
        self.schedule_store = schedule_store
        self.occurrences = occurrence_store
        self.receipts = receipt_store
        self.role_guard = role_guard
        self.role_policy_snapshot = role_policy_snapshot
        self.fleet = fleet
        self.secrets_path = secrets_path
        self.assignment_writer = assignment_writer
        self.submission = submission
        self.onboard = onboard
        self.record_store = record_store
        self._now = now_fn
        # Wave-gate evidence only. The heartbeat authority is required to
        # count staging at all; the swarm view is optional corroboration.
        self.catalog = catalog
        self.heartbeat_fn = heartbeat_fn
        self.swarm_fn = swarm_fn
        self.local_validator = schedule_validation.LocalScheduleValidator(
            fleet=fleet,
            plan_fn=(submission._plan if submission is not None
                     else lambda _device_id, _device: {}),
            artifacts_dir=(getattr(onboard, "artifacts_dir", "")
                           if onboard is not None else ""),
            max_concurrent=(getattr(onboard, "max_concurrent", 0)
                            if onboard is not None else 0),
            service_available=(onboard is not None and submission is not None))

    def _iox_artifact_reason(self, device_id, plan):
        return self.local_validator._iox_artifact_reason(device_id, plan)

    def _annotate_quarantine(self, schedule, snapshot, device_ids):
        occurrence_id = snapshot.get("occurrence_id")
        if not occurrence_id or not device_ids:
            return
        quarantined = set(snapshot.get("quarantined_ids") or ())
        # Early-bound targets may no longer match the fire-time filter. Read
        # the complete quarantine authority so their occurrence fact remains
        # accurate too; per-device admission still rechecks under the role lock.
        try:
            policy = self.role_policy_snapshot()
            quarantined = set(peer_policy.quarantine_device_ids(
                policy.document))
        except Exception:
            pass
        if set(device_ids) <= quarantined:
            self.occurrences.annotate_all_targets_quarantined(
                occurrence_id, len(device_ids), now=int(self._now()))

    def _preceding_occurrence(self, schedule_id, not_after):
        """The preceding schedule's newest occurrence at or before this slot.

        Missed slots never bound a target and never ran, so they carry no
        evidence and are skipped rather than counted as an empty success.
        """
        rows = [row for row in self.occurrences.list(schedule_id)
                if row["state"] != "missed" and row["scheduled_at"] <= not_after]
        return rows[-1] if rows else None

    def _wave_heartbeats(self):
        rows = self.heartbeat_fn() if callable(self.heartbeat_fn) else None
        if not isinstance(rows, list):
            raise schedule_runner.ExecutionRefused(
                "staging_evidence_unavailable")
        return {row.get("device_id"): row for row in rows
                if isinstance(row, dict) and isinstance(row.get("device_id"), str)}

    def _wave_corroboration(self, image_ids):
        """The tracker's own view of the wave's torrents, when it has one.

        Every failure here is silence, not a verdict: an unreadable catalog
        entry, an unreachable tracker or an unparsable document all mean the
        gate simply has nothing to corroborate with.
        """
        if not image_ids or not callable(self.swarm_fn) or self.catalog is None:
            return {}
        wanted = set()
        try:
            for image_id in image_ids:
                entry = self.catalog.get_image(image_id)
                info_hash = (entry or {}).get("info_hash_hex")
                if info_hash:
                    wanted.add(info_hash)
            if not wanted:
                return {}
            document = self.swarm_fn()
            if isinstance(document, (bytes, bytearray, str)):
                document = json.loads(document)
        except (OSError, TypeError, ValueError, RecursionError, OverflowError):
            return {}
        return wave_swarm_contradictions(document, wanted)

    def wave_counts(self, schedule, occurrence):
        """Count how much of a gate's preceding occurrence actually landed.

        This is an operational signal, not a security boundary. It reads the
        heartbeat authority the Devices table already reads and, where the
        tracker can corroborate it, the swarm's own view of the same
        torrents. Without the heartbeat authority it refuses instead of
        guessing; without the tracker it still counts, because absent
        corroboration is not evidence against staging.
        """
        after = schedule["after"]
        counts = {"schedule_id": after["schedule_id"], "occurrence_id": None,
                  "total": 0, "staged": 0, "errored": 0, "missing": 0}
        preceding = self._preceding_occurrence(
            after["schedule_id"], occurrence["scheduled_at"])
        if preceding is None:
            return counts
        targets = preceding["target_snapshot"]["device_ids"]
        counts["occurrence_id"] = preceding["id"]
        counts["total"] = len(targets)
        kind = preceding["schedule"]["kind"]
        image_ids = list(preceding["schedule"]["payload"].get("image_ids") or ())
        heartbeats = self._wave_heartbeats()
        corroborated = self._wave_corroboration(image_ids)
        now = int(self._now())
        for device_id in targets:
            outcome = self.receipts.get(preceding["id"], device_id)
            state = wave_device_state(
                kind, heartbeats.get(device_id), image_ids,
                (outcome or {}).get("status"), corroborated.get(device_id),
                now=now)
            if state in schedules.WAVE_COUNTS:
                counts[state] += 1
        return counts

    def validate(self, schedule, snapshot, phase):
        """Validate local blast radius and artifacts without device I/O."""
        device_ids = self.local_validator._ids(snapshot)
        self._annotate_quarantine(schedule, snapshot, device_ids)
        return self.local_validator.validate(schedule, snapshot, phase)

    @staticmethod
    def _provenance(schedule, occurrence, device_id):
        return deployment_records.validate_schedule_provenance({
            "schema_version": 1,
            "schedule_id": schedule["id"],
            "schedule_rev": occurrence["schedule_rev"],
            "occurrence_id": occurrence["id"],
            "device_id": device_id,
        }, device_id)

    def _strict_revocation(self):
        try:
            state = secrets_store.load(
                self.secrets_path, require_existing=True)
            revoked = _instruction_revoked_principals(state)
        except (OSError, TypeError, ValueError, RecursionError,
                OverflowError) as exc:
            raise schedule_runner.ExecutionRefused(
                "revocation_unavailable") from exc
        if not isinstance(revoked, (set, frozenset)):
            raise schedule_runner.ExecutionRefused(
                "revocation_unavailable")
        return frozenset(revoked)

    @staticmethod
    def _plan_authority_projection(plan):
        return {key: copy.deepcopy(value) for key, value in plan.items()
                if key not in ("inventory_revision", "plan_hash")}

    @classmethod
    def _same_authoritative_plan(cls, current, expected):
        """Allow stored preflight evidence while binding every base input."""
        current = cls._plan_authority_projection(current)
        expected = cls._plan_authority_projection(expected)
        for key, value in current.items():
            if key == "resolved":
                resolved = expected.get("resolved")
                if not isinstance(value, dict) or not isinstance(resolved, dict):
                    return False
                if any(resolved.get(name) != item
                       for name, item in value.items()):
                    return False
            elif expected.get(key) != value:
                return False
        return True

    def _check_live(self, schedule, occurrence, device_id, attempt,
                    policy, revoked, expected_plan=None,
                    expected_registered_at=_UNBOUND,
                    expected_registration_id=_UNBOUND):
        now = int(self._now())
        if now < occurrence["scheduled_at"]:
            raise schedule_runner.ExecutionRefused("window_not_open")
        if now >= occurrence["window_end"]:
            raise schedule_runner.ExecutionRefused("window_closed")
        live = self.schedule_store.get(schedule["id"])
        if (live is None
                or live["generation"] != occurrence["schedule_generation"]
                or any(live.get(key) != schedule.get(key)
                       for key in schedules.DEFINITION_KEYS)):
            raise schedule_runner.ExecutionRefused("schedule_changed")
        current = self.occurrences.get(occurrence["id"])
        if (current is None or current["state"] not in self._ACTIVE_OCCURRENCES
                or current["schedule_generation"] !=
                    occurrence["schedule_generation"]
                or device_id not in current["target_snapshot"]["device_ids"]):
            raise schedule_runner.ExecutionRefused("schedule_changed")
        receipt = self.receipts.get(occurrence["id"], device_id)
        if (receipt is None or receipt["attempt"] != attempt
                or receipt["status"] in schedules.TERMINAL_RECEIPT_STATES):
            raise schedule_runner.ExecutionRefused("conflict")
        device = self.fleet.get_device(device_id) if self.fleet else None
        if device is None:
            raise schedule_runner.ExecutionRefused("vanished")
        if "device:" + device_id in revoked:
            raise schedule_runner.ExecutionRefused("device_revoked")
        if (expected_registration_id is not self._UNBOUND
                and device.get("registration_id") != expected_registration_id):
            raise schedule_runner.ExecutionRefused("conflict")
        if (expected_registration_id is self._UNBOUND
                and expected_registered_at is not self._UNBOUND
                and device.get("registered_at") != expected_registered_at):
            raise schedule_runner.ExecutionRefused("conflict")
        if expected_plan is not None:
            try:
                current_plan = self.submission._plan(device_id, device)
            except ValueError:
                raise schedule_runner.ExecutionRefused("conflict") from None
            if not self._same_authoritative_plan(current_plan, expected_plan):
                raise schedule_runner.ExecutionRefused("conflict")
            artifact_reason = self._iox_artifact_reason(
                device_id, current_plan)
            if artifact_reason is not None:
                raise schedule_runner.ExecutionRefused(artifact_reason)
        return device

    @contextlib.contextmanager
    def _authority(self, schedule, occurrence, device_id, attempt):
        if self.role_guard is None or self.fleet is None or not self.secrets_path:
            raise schedule_runner.ExecutionRefused(
                "schedule_authority_unavailable")
        with self.role_guard(schedule) as policy:
            with assignment_service.membership_guard(self.fleet):
                with secrets_store.store_lock(self.secrets_path):
                    revoked = self._strict_revocation()
                    yield policy, revoked

    @staticmethod
    def _map_exception(exc):
        if isinstance(exc, schedule_runner.ExecutionRefused):
            return exc.reason
        if isinstance(exc, assignment_service.MissingFleetDevice):
            return "vanished"
        if isinstance(exc, assignment_service.AssignmentAuthorityUnavailable):
            return "assignment_authority_unavailable"
        if isinstance(exc, deployment_records.RecordStoreUnreadable):
            return "deployment_authority_unavailable"
        return "execution_failed"

    @staticmethod
    def _terminal(reason, *, error=False, **metadata):
        return {"status": "error" if error else "skipped",
                "reason": reason, **metadata}

    @staticmethod
    def _assignment_outcome(result, prior, *, peer_quarantined=False):
        if isinstance(result, assignment_service.ScheduledAssignmentRefusal):
            before = prior.get("before_image_ids", [])
            return _ScheduledExecutor._terminal(
                result.reason, error=result.reason == "execution_failed",
                after_image_ids=result.after_ids,
                removed_image_ids=[image_id for image_id in before
                                   if image_id not in result.after_ids])
        return {
            "status": "ok",
            "reason": ("unchanged" if result.before_ids == result.after_ids
                       else "assigned"),
            "after_image_ids": result.after_ids,
            "removed_image_ids": [
                image_id for image_id in prior.get("before_image_ids", ())
                if image_id not in result.after_ids],
            **({"notes": ["peer_quarantined"]}
               if peer_quarantined else {}),
        }

    def _dispatch_assignment(self, schedule, occurrence, device_id, prior):
        actor = "schedule:" + schedule["id"]
        if "manual_generation" not in prior:
            try:
                with self.role_guard(schedule) as policy:
                    captured = self.assignment_writer.capture_schedule_state(
                        device_id)
                    peer_quarantined = device_id in set(
                        peer_policy.quarantine_device_ids(policy.document))
            except Exception as exc:
                reason = self._map_exception(exc)
                return self._terminal(
                    reason, error=reason.endswith("unavailable"))
            return {"status": "prepared", "reason": "assignment_prepared",
                    "manual_generation": captured["manual_generation"],
                    "fleet_registered_at": captured["fleet_registered_at"],
                    "fleet_registration_id": captured[
                        "fleet_registration_id"],
                    "before_image_ids": captured["before_image_ids"],
                    **({"notes": ["peer_quarantined"]}
                       if peer_quarantined else {})}

        policy_holder = {}

        @contextlib.contextmanager
        def commit_guard():
            try:
                with secrets_store.store_lock(self.secrets_path):
                    revoked = self._strict_revocation()
                    self._check_live(
                        schedule, occurrence, device_id, prior["attempt"],
                        policy_holder.get("policy"), revoked,
                        expected_registered_at=prior.get(
                            "fleet_registered_at"),
                        expected_registration_id=prior.get(
                            "fleet_registration_id", self._UNBOUND))
                    yield
            except schedule_runner.ExecutionRefused:
                raise

        context = assignment_service.ScheduledAssignmentContext(
            schedule_id=schedule["id"], schedule_rev=occurrence["schedule_rev"],
            occurrence_id=occurrence["id"],
            expected_manual_generation=prior["manual_generation"],
            fleet_registered_at=prior.get("fleet_registered_at"),
            fleet_registration_id=prior.get("fleet_registration_id"),
            commit_guard=commit_guard,
            require_existing_authority=True)
        try:
            with self.role_guard(schedule) as policy:
                policy_holder["policy"] = policy
                result = self.assignment_writer.apply(
                    device_id, schedule["payload"]["image_ids"], actor=actor,
                    mode=schedule["payload"]["mode"],
                    expect_image_ids=prior.get("before_image_ids"),
                    retry_conflict=True, plural=True,
                    scheduled_context=context)
        except Exception as exc:
            reason = self._map_exception(exc)
            return self._terminal(
                reason, error=reason.endswith("unavailable")
                or reason == "execution_failed")
        return self._assignment_outcome(
            result, prior, peer_quarantined=(
                "peer_quarantined" in prior.get("notes", ())))

    def _job_result(self, job, *, closed_reason=None):
        if job is None:
            return None
        metadata = {"job_id": job["id"]}
        if job.get("record_id"):
            metadata["record_id"] = job["record_id"]
        state = job.get("state")
        if state == "queued":
            return {"status": "submitted", "reason": "queued", **metadata}
        if state == "running":
            return {"status": "running", "reason": "running", **metadata}
        if state == "done":
            return {"status": "ok", "reason": "onboarded", **metadata}
        reason = job.get("admission_reason")
        if not isinstance(reason, str) or not re.fullmatch(
                r"[a-z][a-z0-9_]{0,63}", reason):
            reason = closed_reason if state == "cancelled" and closed_reason \
                else "cancelled" if state == "cancelled" \
                else "onboarding_failed"
        return {"status": "skipped" if state == "cancelled" else "error",
                "reason": reason, **metadata}

    def _records_for_provenance(self, provenance):
        if self.record_store is None:
            raise deployment_records.RecordStoreUnreadable(
                "deployment record authority unavailable")
        rows = self.record_store.list(provenance["device_id"], strict=True)
        return [row for row in rows
                if row.get("schedule_provenance") == provenance]

    @staticmethod
    def _current_owned_record(rows):
        current = [row for row in rows if row.get("state") not in
                   _ScheduledExecutor._TERMINAL_RECORDS]
        if len(current) > 1:
            raise ValueError("multiple occurrence-owned deployment records")
        return current[0] if current else None

    def _onboard_callbacks(self, schedule, occurrence, device_id, prior,
                           provenance, plan, resume_record_id,
                           fleet_registered_at,
                           fleet_registration_id=_UNBOUND):
        local = threading.local()
        record_ref = {}

        @contextlib.contextmanager
        def authority_guard(phase):
            try:
                with self._authority(
                        schedule, occurrence, device_id,
                        prior["attempt"]) as authority:
                    local.phase = phase
                    local.authority = authority
                    local.checked = False
                    yield
            except schedule_runner.ExecutionRefused as exc:
                raise gui_onboard.ScheduledAdmissionError(exc.reason) from None
            except gui_onboard.ScheduledAdmissionError:
                raise
            except Exception as exc:
                raise gui_onboard.ScheduledAdmissionError(
                    self._map_exception(exc)) from None
            finally:
                for name in ("phase", "authority", "checked"):
                    if hasattr(local, name):
                        delattr(local, name)

        def authority_check(phase):
            if getattr(local, "phase", None) != phase:
                raise gui_onboard.ScheduledAdmissionError(
                    "schedule_authority_unavailable")
            policy, revoked = local.authority
            try:
                self._check_live(
                        schedule, occurrence, device_id, prior["attempt"],
                        policy, revoked, expected_plan=plan,
                        expected_registered_at=fleet_registered_at,
                        expected_registration_id=fleet_registration_id)
            except schedule_runner.ExecutionRefused as exc:
                raise gui_onboard.ScheduledAdmissionError(exc.reason) from None
            local.checked = True

        def authorize(tag, attempt, existing):
            if (not getattr(local, "checked", False)
                    or tag != provenance or attempt != prior["attempt"]):
                return "conflict"
            if int(self._now()) >= occurrence["window_end"]:
                return "window_closed"
            if (resume_record_id is not None and
                    (existing or {}).get("record_id") != resume_record_id):
                return "conflict"
            return None

        candidate = {
            "controller_id": "iris", "device_id": device_id,
            "fleet_registered_at": fleet_registered_at,
            "inventory_revision": plan["inventory_revision"],
            "plan_hash": plan["plan_hash"],
            "resolved": plan["resolved"],
            "preflight": {"status": "pending"},
            "resources": self.submission._owned_resources(plan["resolved"]),
        }
        if fleet_registration_id is not self._UNBOUND \
                and fleet_registration_id is not None:
            candidate["fleet_registration_id"] = fleet_registration_id

        def prepare():
            admitted = self.record_store.admit_scheduled(
                candidate, provenance=provenance, attempt=prior["attempt"],
                authorize=authorize, resume_record_id=resume_record_id,
                router=plan["resolved"].get("platform") == "router")
            if admitted["status"] not in ("created", "resumed"):
                raise gui_onboard.ScheduledAdmissionError(
                    admitted.get("reason") or "record_recovery_required")
            record = admitted["record"]
            record_ref["id"] = record["record_id"]
            record_ref["recovered_applying"] = (
                record.get("state") == "unknown" and
                (record.get("recovery") or {}).get("interrupted_from") ==
                "applying")
            if admitted.get("predecessor_record_id"):
                record_ref["predecessor"] = admitted[
                    "predecessor_record_id"]
            return record["record_id"]

        def pre_apply(evidence):
            final_plan = self.submission._apply_preflight(plan, evidence)
            record_id = record_ref.get("id")
            if not record_id:
                raise ValueError("planned record is unavailable")
            update = (self.record_store.update_scheduled_recovery
                      if record_ref.get("recovered_applying") else
                      self.record_store.update_planned)
            kwargs = {
                "plan_hash": final_plan["plan_hash"],
                "resolved": final_plan["resolved"],
                "preflight": evidence,
                "resources": self.submission._owned_resources(
                    final_plan["resolved"]),
            }
            if record_ref.get("recovered_applying"):
                kwargs["provenance"] = provenance
            update(record_id, **kwargs)
            return final_plan["resolved"]

        return authority_guard, authority_check, prepare, pre_apply, record_ref

    def _onboard_precondition(self, device_id, occurrence_id):
        device = self.fleet.get_device(device_id) if self.fleet else None
        if device is None:
            return None, None, "vanished"
        ensure_registration_id = getattr(
            self.fleet, "ensure_registration_id", None)
        if callable(ensure_registration_id):
            device = ensure_registration_id(device_id)
        if device.get("management_type", "legacy_routed") == "legacy_routed":
            return device, None, "unclassified_management_type"
        own_jobs = (self.onboard.jobs_for_occurrence(
            occurrence_id, device_id) if self.onboard else [])
        if own_jobs:
            return device, None, self._job_result(own_jobs[-1])
        latest = (self.onboard.latest_jobs_by_device().get(device_id)
                  if self.onboard else None)
        if latest and latest.get("state") in self._ACTIVE_JOBS:
            return device, None, "device_busy"
        try:
            plan = self.submission._plan(device_id, device)
            self.submission._credential_ref(device_id)
        except ValueError as exc:
            reason = ("unclassified_management_type"
                      if str(exc) == "unclassified_management_type"
                      else "credential_unavailable"
                      if "credential profile" in str(exc)
                      else "invalid_onboard_target")
            return device, None, reason
        if not self.onboard.host_ip:
            return device, None, "server_address_unconfigured"
        reason = self._iox_artifact_reason(device_id, plan)
        return device, plan, reason

    def _dispatch_onboard(self, schedule, occurrence, device_id, prior):
        provenance = self._provenance(schedule, occurrence, device_id)
        try:
            rows = self._records_for_provenance(provenance)
            owned = self._current_owned_record(rows)
        except Exception as exc:
            reason = self._map_exception(exc)
            return self._terminal(reason, error=True)
        if owned is not None and owned.get("state") == "active":
            result = {"status": "ok", "reason": "onboarded",
                      "record_id": owned["record_id"]}
            for field in ("fleet_registered_at", "fleet_registration_id"):
                if field in owned:
                    result[field] = owned[field]
            return result
        if self.onboard is None or self.submission is None \
                or self.record_store is None:
            return self._terminal("onboarding_service_unavailable", error=True)
        device, plan, problem = self._onboard_precondition(
            device_id, occurrence["id"])
        if isinstance(problem, dict):
            return problem
        if problem is not None:
            return self._terminal(problem)
        resume_record_id = (owned["record_id"] if owned is not None and
                            owned.get("state") in ("planned", "unknown")
                            else None)
        fleet_registered_at = device.get("registered_at")
        fleet_registration_id = device.get("registration_id")
        receipt_registration_id = prior.get(
            "fleet_registration_id", self._UNBOUND)
        record_registration_id = (owned or {}).get(
            "fleet_registration_id", self._UNBOUND)
        for bound_registration_id in (
                receipt_registration_id, record_registration_id):
            if (bound_registration_id is not self._UNBOUND and
                    bound_registration_id != fleet_registration_id):
                return self._terminal("conflict")
        receipt_registered_at = prior.get(
            "fleet_registered_at", self._UNBOUND)
        record_registered_at = (owned or {}).get(
            "fleet_registered_at", self._UNBOUND)
        if (receipt_registration_id is self._UNBOUND and
                receipt_registered_at is not self._UNBOUND and
                receipt_registered_at != fleet_registered_at):
            return self._terminal("conflict")
        if (owned is not None and
                record_registration_id is self._UNBOUND and
                record_registered_at != fleet_registered_at):
            return self._terminal("conflict")
        if (owned is None and
                receipt_registration_id is self._UNBOUND and
                receipt_registered_at is self._UNBOUND):
            result = {
                "status": "prepared", "reason": "onboard_prepared",
                "fleet_registered_at": fleet_registered_at,
            }
            if fleet_registration_id is not None:
                result["fleet_registration_id"] = fleet_registration_id
            return result
        expected_registration_id = (
            receipt_registration_id
            if receipt_registration_id is not self._UNBOUND else
            record_registration_id
            if record_registration_id is not self._UNBOUND else self._UNBOUND)
        if resume_record_id is not None:
            interrupted_from = (owned.get("recovery") or {}).get(
                "interrupted_from")
            if interrupted_from == "applying":
                admitted_plan = copy.deepcopy(plan)
                admitted_plan["inventory_revision"] = owned[
                    "inventory_revision"]
                admitted_plan["plan_hash"] = owned["plan_hash"]
                admitted_plan["resolved"] = copy.deepcopy(owned["resolved"])
                if not self._same_authoritative_plan(plan, admitted_plan):
                    return self._terminal("conflict")
                plan = admitted_plan
        callbacks = self._onboard_callbacks(
            schedule, occurrence, device_id, prior, provenance, plan,
            resume_record_id, fleet_registered_at,
            expected_registration_id)
        authority_guard, authority_check, prepare, pre_apply, record_ref = callbacks
        try:
            job_id = self.onboard.start(
                device_id, action="onboard", resolved=plan["resolved"],
                prepare=prepare, pre_apply=pre_apply,
                env_extra={
                    "TELEMETRY": ("on" if schedule["payload"]["telemetry"]
                                  else "off"),
                    "TELEMETRY_STREAM": (
                        "on" if schedule["payload"]["telemetry_stream"]
                        else "off"),
                    "IRIS_TELEMETRY": (
                        "on" if schedule["payload"]["telemetry"] else "off"),
                    "IRIS_TELEMETRY_STREAM": (
                        "on" if schedule["payload"]["telemetry_stream"]
                        else "off"),
                }, teardown_mode="none", schedule_context=provenance,
                authority_guard=authority_guard,
                authority_check=authority_check)
        except gui_onboard.ScheduledAdmissionError as exc:
            if exc.reason == "queue_full":
                return {"status": "deferred", "reason": exc.reason,
                        "retry_at": int(self._now()) + 1}
            return self._terminal(
                exc.reason, error=exc.reason.endswith("unavailable")
                or exc.reason == "execution_failed")
        except Exception as exc:
            reason = self._map_exception(exc)
            return self._terminal(reason, error=True)
        context = self.onboard.get_schedule_context(job_id)
        if context != provenance:
            return self._terminal("device_busy")
        result = self._job_result(self.onboard.get_job(job_id))
        if result is None:
            return {"status": "deferred", "reason": "job_state_unavailable",
                    "retry_at": int(self._now()) + 1}
        if record_ref.get("predecessor"):
            result["predecessor_record_id"] = record_ref["predecessor"]
        result["fleet_registered_at"] = fleet_registered_at
        if fleet_registration_id is not None:
            result["fleet_registration_id"] = fleet_registration_id
        return result

    def dispatch(self, schedule, occurrence, device_id, prior_receipt):
        if schedule.get("kind") == "assign":
            return self._dispatch_assignment(
                schedule, occurrence, device_id, prior_receipt)
        if schedule.get("kind") == "onboard":
            return self._dispatch_onboard(
                schedule, occurrence, device_id, prior_receipt)
        raise schedule_runner.ExecutionRefused("invalid_schedule_kind")

    def _closed_reason(self, occurrence):
        now = int(self._now())
        if now >= occurrence["window_end"]:
            return "window_closed"
        live = self.schedule_store.get(occurrence["schedule_id"])
        if (live is None or
                live["generation"] != occurrence["schedule_generation"] or
                any(live.get(key) != occurrence["schedule"].get(key)
                    for key in schedules.DEFINITION_KEYS)):
            return "schedule_changed"
        return None

    def _reconcile_onboard(self, receipt, occurrence):
        provenance = self._provenance(
            occurrence["schedule"], occurrence, receipt["device_id"])
        try:
            rows = self._records_for_provenance(provenance)
            owned = self._current_owned_record(rows)
        except Exception as exc:
            reason = self._map_exception(exc)
            return self._terminal(reason, error=True)
        if owned is not None:
            state = owned.get("state")
            if state == "active":
                result = {"status": "ok", "reason": "onboarded",
                          "record_id": owned["record_id"]}
                for field in (
                        "fleet_registered_at", "fleet_registration_id"):
                    if field in owned:
                        result[field] = owned[field]
                return result
            if state in ("planned", "unknown"):
                if (state == "unknown" and
                        owned.get("resolved", {}).get("platform") == "router"):
                    return self._terminal("router_requires_undeploy")
                return {"status": "retry", "reason": "resume_required",
                        "manual_generation": 0,
                        "predecessor_record_id": owned["record_id"]}
            if state == "applying":
                return {"status": "deferred", "reason": "record_in_progress",
                        "retry_at": int(self._now()) + 1}
            return self._terminal("existing_deployment")
        foreign = [row for row in self.record_store.list(
            receipt["device_id"], strict=True)
            if row.get("state") not in self._TERMINAL_RECORDS]
        if any(row.get("state") == "unknown" for row in foreign):
            return self._terminal("foreign_interrupted_record")
        if foreign:
            return self._terminal("existing_deployment")
        return {"status": "retry", "reason": "no_admitted_work",
                "manual_generation": 0}

    def poll(self, receipt):
        occurrence = self.occurrences.get(receipt["occurrence_id"])
        if occurrence is None:
            return self._terminal("schedule_state_unavailable", error=True)
        if occurrence["schedule"]["kind"] == "assign":
            if ("manual_generation" not in receipt
                    or "before_image_ids" not in receipt):
                return self._terminal("conflict", error=True)
            schedule = occurrence["schedule"]
            context = assignment_service.ScheduledAssignmentContext(
                schedule_id=schedule["id"],
                schedule_rev=occurrence["schedule_rev"],
                occurrence_id=occurrence["id"],
                expected_manual_generation=receipt["manual_generation"],
                fleet_registered_at=receipt.get("fleet_registered_at"),
                fleet_registration_id=receipt.get("fleet_registration_id"),
                require_existing_authority=True)
            try:
                result = self.assignment_writer.reconcile_schedule_result(
                    receipt["device_id"], schedule["payload"]["image_ids"],
                    mode=schedule["payload"]["mode"],
                    expect_image_ids=receipt["before_image_ids"],
                    retry_conflict=True, scheduled_context=context)
            except Exception as exc:
                reason = self._map_exception(exc)
                return self._terminal(
                    reason, error=reason.endswith("unavailable")
                    or reason == "execution_failed")
            if result is None:
                # The runner supplies its exact closure/refusal reason when it
                # handles this retry. No claim means no assignment was admitted.
                return {"status": "retry", "reason": "no_admitted_work",
                        "manual_generation": receipt["manual_generation"],
                        "before_image_ids": receipt["before_image_ids"]}
            return self._assignment_outcome(
                result, receipt,
                peer_quarantined=(
                    "peer_quarantined" in receipt.get("notes", ())))
        if occurrence["schedule"]["kind"] != "onboard":
            return self._terminal("conflict", error=True)
        job = self.onboard.get_job(receipt.get("job_id")) \
            if self.onboard is not None and receipt.get("job_id") else None
        if job is None and self.onboard is not None:
            matches = self.onboard.jobs_for_occurrence(
                receipt["occurrence_id"], receipt["device_id"])
            job = matches[-1] if matches else None
        if job is not None:
            return self._job_result(
                job, closed_reason=self._closed_reason(occurrence))
        return self._reconcile_onboard(receipt, occurrence)

    def cancel_queued(self, occurrence_id, job_ids):
        if self.onboard is not None:
            self.onboard.cancel_queued(
                set(job_ids), occurrence_id=occurrence_id)

    def acknowledge(self, receipt):
        occurrence = self.occurrences.get(receipt["occurrence_id"])
        if (occurrence is None or occurrence["schedule"]["kind"] != "assign"
                or "manual_generation" not in receipt):
            return
        self.assignment_writer.acknowledge_schedule_result(
            receipt["occurrence_id"], receipt["device_id"],
            terminal_status=receipt["status"])


def make_server(host, port, app, images=None, fleet=None, creds=None, catalog=None,
                 onboard=None, swarm_fetch=None, certfile=None, audit_path=None,
                 record_store=None, now_fn=time.time, keyfile=None,
                 management_token_file=None,
                 management_previous_token_file=None, iox_controller=None,
                 schedule_wake=None):
    login_limiter = gui_auth.LoginRateLimiter()
    # A bounded, process-local replay ledger for legacy POST operations that
    # create an asynchronous job or an auditable resource mutation. Durable
    # jobs remain authoritative after restart; the ledger prevents the common
    # lost-response retry from creating a second job while this API process is
    # alive. Other POSTs deliberately reject Idempotency-Key rather than imply
    # a guarantee they cannot provide.
    idempotency_lock = threading.Lock()
    idempotency_cache = {}
    idempotency_ttl = 24 * 60 * 60
    idempotency_limit = 512

    def idempotency_supported(path):
        if path in ("/api/devices", "/api/images/import",
                    "/api/image-verification/refresh",
                    "/api/settings/audit-export/run",
                    "/api/settings/ca-trust/refresh"):
            return True
        return bool(re.fullmatch(
            r"/api/devices/[^/]+/(?:request-report|adopt|onboard|undeploy)",
            path))

    def policy_state_dir():
        return (catalog.state_dir if catalog is not None
                else os.environ.get("IRIS_STATE", "/var/lib/iris"))

    def policy_paths():
        state_dir = policy_state_dir()
        return (os.path.join(state_dir, "peer-policy.json"),
                os.path.join(state_dir, "peer-policy.lkg.json"),
                os.path.join(state_dir, "peer-enforcement.json"))

    schedule_store = schedules.ScheduleStore(policy_state_dir())
    schedule_occurrence_store = schedules.OccurrenceStore(policy_state_dir())
    schedule_receipt_store = schedules.ReceiptStore(policy_state_dir())
    scheduled_executor = None

    def wake_schedule_runner():
        if schedule_wake is not None:
            try:
                schedule_wake()
            except Exception:
                # The durable mutation already committed. The runner's bounded
                # idle recheck remains authoritative if an in-process wake
                # notification fails.
                pass

    def role_coordinator():
        """Build the shared direct-store coordinator for this state owner."""
        if fleet is None:
            return None
        auth_path, lkg_path, enforcement_path = policy_paths()

        def acked_revision():
            status = peer_enforcement.read_status(enforcement_path) or {}
            return status

        return role_management.RoleCoordinator(
            fleet, auth_path, lkg_path, now_fn=now_fn,
            acked_revision_fn=acked_revision, schedule_store=schedule_store)

    def instruction_heartbeat_snapshot(unavailable_ok=True):
        if catalog is None:
            return None
        if not unavailable_ok:
            return catalog.list_devices()
        try:
            return catalog.list_devices()
        except (catalog_mod.StateFileError, OSError, TypeError, ValueError,
                RecursionError, OverflowError):
            return None

    def instruction_heartbeat_for_device(device_id):
        """Read one heartbeat shard without turning evidence loss into 5xx."""
        if catalog is None:
            return {}, False
        reader = getattr(catalog, "get_device", None)
        if not callable(reader):
            return {}, False
        try:
            heartbeat = reader(device_id)
        except (catalog_mod.StateFileError, OSError, TypeError, ValueError,
                RecursionError, OverflowError):
            return {}, False
        if heartbeat is None:
            return {}, True
        if not isinstance(heartbeat, dict):
            return {}, False
        return heartbeat, True

    def instruction_raw_policy_snapshot(unavailable_ok=True):
        if catalog is None:
            return None
        reader = getattr(catalog, "list_raw_policies", None)
        if not unavailable_ok:
            return reader() if callable(reader) else catalog.list_policies()
        try:
            # list_raw_policies is the Task 19 public bulk seam.  The fallback
            # keeps this isolated commit usable before the producer commit is
            # integrated; the final tree always takes the raw branch.
            return reader() if callable(reader) else catalog.list_policies()
        except (catalog_mod.StateFileError, OSError, TypeError, ValueError,
                RecursionError, OverflowError):
            return None

    def instruction_revocation_snapshot():
        try:
            return _instruction_revoked_principals(
                secrets_store.load(app.secrets_path))
        except (secrets_store.StoreCorruptError, OSError, TypeError,
                ValueError, RecursionError, OverflowError):
            return None

    def policy_view():
        """Return the GUI-safe, count-only policy and tracker-status view."""
        auth_path, lkg_path, enforcement_path = policy_paths()
        result = peer_policy.load_policy(auth_path, lkg_path)
        doc = result.document
        status = peer_enforcement.read_status(enforcement_path) or {}
        preflight = peer_enforcement.mutual_origin_from_status(status)
        origin_status = origin_qos.read_status(os.path.join(
            policy_state_dir(), "origin-qos.json")) or {}
        conflicts = status.get("conflicts")
        if not isinstance(conflicts, list):
            conflicts = []
        types = sorted({c["reason"] for c in conflicts
                        if isinstance(c, dict) and isinstance(c.get("reason"), str) and c.get("reason") in
                        {"shared_permit_deny"}})
        effect = status.get("last_effect")
        # Reconciler effects are aggregate counters. Do not pass through an
        # arbitrary tracker document (which could accidentally grow an address).
        safe_effect = ({k: v for k, v in effect.items()
                        if k in ("disconnected_peers", "removed_peers")
                        and isinstance(v, int) and not isinstance(v, bool)}
                       if isinstance(effect, dict) else None)
        last_reconciled_at = (status.get("last_reconciled_at")
            if isinstance(status.get("last_reconciled_at"), (int, float))
            and not isinstance(status.get("last_reconciled_at"), bool) else None)
        # IRIS-99: a frozen reconciler leaves last_reconciled_at (and
        # whatever state/applied_revision it last wrote, possibly
        # "enforced") sitting unchanged forever -- the console must say so
        # explicitly rather than let an old "enforced" claim keep reading as
        # current. No timestamp at all (missing/corrupt/never-run) is
        # exactly as unproven as a stale one, so it is stale too.
        stale = (last_reconciled_at is None
                or (now_fn() - last_reconciled_at) > _PEER_POLICY_STALE_AFTER)
        enforcement = {
            "state": status.get("state") if status.get("state") in peer_enforcement.STATES else None,
            "desired_ip_count": status.get("desired_ip_count")
                if isinstance(status.get("desired_ip_count"), int)
                and not isinstance(status.get("desired_ip_count"), bool) else 0,
            "applied_revision": status.get("applied_revision")
                if isinstance(status.get("applied_revision"), int)
                and not isinstance(status.get("applied_revision"), bool) else None,
            "last_reconciled_at": last_reconciled_at,
            "stale": stale,
            "stale_after_seconds": _PEER_POLICY_STALE_AFTER,
            "conflict_count": len(conflicts), "conflict_types": types,
            "last_effect": safe_effect,
            "last_error": status.get("last_error")
                if isinstance(status.get("last_error"), str) and re.fullmatch(
                    r"[A-Za-z][A-Za-z0-9_]{0,63}", status["last_error"]) else None,
            "last_operation_exported_revision": peer_policy.effective_acked(doc, status),
            "mutual_origin": {
                "mode": preflight["mode"],
                "newly_denied_device_count": preflight[
                    "newly_denied_device_count"],
            },
        }

        def origin_count(name):
            value = origin_status.get(name)
            return value if isinstance(value, int) \
                and not isinstance(value, bool) and value >= 0 else 0

        origin_last_reconciled = origin_status.get("last_reconciled_at")
        if not isinstance(origin_last_reconciled, (int, float)) \
                or isinstance(origin_last_reconciled, bool):
            origin_last_reconciled = None
        try:
            origin_last_error = origin_qos.validate_error_code(
                origin_status.get("last_error"))
        except origin_qos.OriginQosError:
            origin_last_error = None
        origin_view = {
            "state": origin_status.get("state")
                if origin_status.get("state") in origin_qos.STATES else None,
            "global_option_count": origin_count("global_option_count"),
            "target_download_count": origin_count("target_download_count"),
            "applied_download_count": origin_count("applied_download_count"),
            "last_reconciled_at": origin_last_reconciled,
            "last_error": origin_last_error,
        }
        compiled_roles = result.roles
        role_members = {name: len(compiled_roles.members_by_role[name])
                        for name in sorted(compiled_roles.members_by_role)}
        rows = fleet.snapshot()[1] if fleet is not None else []
        drift = (role_management.drift_report(fleet, result, rows=rows)
                 if fleet is not None
                 else {"count": 0, "device_ids": [], "truncated": False})
        acked = peer_policy.effective_acked(doc, status)
        pending = sum(event["revision"] > acked
                      for event in doc.get("operation_outbox", []))
        heartbeat_rows = instruction_heartbeat_snapshot()
        raw_policies = instruction_raw_policy_snapshot()
        revoked_principals = instruction_revocation_snapshot()
        custody = instruction_custody_view(policy_state_dir())
        observed_at = now_fn()
        instruction = _instruction_fleet_projection(
            rows, heartbeat_rows, raw_policies, revoked_principals, observed_at)
        return {"schema": doc.get("schema"), "revision": doc.get("revision"),
                "degraded": result.degraded, "fail_closed": result.fail_closed,
                "quarantine": {"reserved": True,
                               "description": "reserved: fully isolate an assigned device"},
                "quarantine_assignments": sorted(
                    peer_policy.quarantine_device_ids(doc)),
                "roles_supported": True,
                "roles_present": doc.get("roles_present", False),
                "roles": {"defined": len(role_members),
                          "restricted": len(compiled_roles.restricted),
                          "members": role_members},
                "role_drift": drift,
                "outbox": {"unacknowledged": pending,
                           "capacity": peer_policy.OUTBOX_CAP},
                "fleet_rollup": instruction["fleet_rollup"],
                "instruction_status": instruction["instruction_status"],
                "enforcement": enforcement, "origin_qos": origin_view,
                "instruction_keys": custody}

    def role_policy_snapshot():
        """The authoritative policy result used by preview drift checks."""
        auth_path, lkg_path, _ = policy_paths()
        return peer_policy.load_policy(auth_path, lkg_path)

    def deployment_type_snapshot():
        """One bulk read of live deployment facts, keyed by device id.

        The newest applicable record wins. Terminal removed, superseded and
        abandoned records describe history and cannot classify a current
        targeting row. Only the small trusted type projection crosses into
        the Devices response.
        """
        if record_store is None:
            return {}
        records = record_store.list(strict=True)
        return deployment_target_snapshot(records)

    def schedule_target_resolver(target, role_policy=None):
        """Resolve through the same authorities as the Devices filter bar."""
        if fleet is None:
            raise ScheduleTargetError("fleet state is unavailable")
        return resolve_schedule_target(
            target, fleet=fleet, catalog=catalog, record_store=record_store,
            role_policy=role_policy or role_policy_snapshot(),
            now=int(now_fn()),
            jobs=(onboard.latest_jobs_by_device()
                  if onboard is not None else None),
            heartbeat_rows=instruction_heartbeat_snapshot(unavailable_ok=False),
            revoked_principals=instruction_revocation_snapshot())

    def runner_schedule_target_resolver(schedule):
        """Runner seam: accept a complete stored schedule, return rich facts."""
        if not isinstance(schedule, dict) or not isinstance(
                schedule.get("target"), dict):
            raise schedules.ScheduleValidationError("invalid schedule target")
        return schedule_target_resolver(copy.deepcopy(schedule["target"]))

    class Handler(BaseHTTPRequestHandler):
        timeout = 60  # socket inactivity timeout (s): a stalled upload frees its thread

        def parse_request(self):
            ok = super().parse_request()
            # Set before any session lookup below so unauthenticated unknown
            # poll paths do not refresh a valid session merely by probing.
            gui_app.set_request_session_touch(
                not (ok and self.command == "GET"
                     and self.headers.get("X-IRIS-Poll", "").strip() == "1"))
            if ok and management_token_file is not None:
                # Authenticate the tier before route matching, request-body
                # reads, browser-session lookup, or resource existence checks.
                # Credential-file failures are indistinguishable from a bad
                # token on the wire and contain no secret in the server log.
                try:
                    authenticated = tier_auth.authorized(
                        self.headers, management_token_file,
                        management_previous_token_file)
                except tier_auth.CredentialUnavailable as exc:
                    print("iris-management: %s" % exc,
                          file=sys.stderr, flush=True)
                    authenticated = False
                if not authenticated:
                    api_problem.send(
                        self, 401, "management-authentication-required",
                        "Management authentication required",
                        headers=(("WWW-Authenticate", "Bearer"),))
                    self.close_connection = True
                    return False
                requested_path = urlsplit(self.path).path
                self._iris_management_wire = requested_path.startswith(
                    "/internal/v1/")
                management_only = (self.command, requested_path) in (
                    ("GET", "/internal/v1/console-certificate"),
                    ("POST", "/internal/v1/authorizations"))
                body_authenticated = (
                    (self.command, requested_path) in (
                        ("POST", "/internal/v1/login"),
                        ("POST", "/internal/v1/setup")))
                if not management_only and not body_authenticated:
                    # Browser authentication precedes registry lookup, so an
                    # unknown and a known resource have identical 401/403
                    # behavior. The mature route repeats this check before
                    # state work; this early gate also protects GET existence.
                    info = app.session_info(self._sid())
                    if info is None:
                        api_problem.send(self, 401,
                                         "console-session-required",
                                         "Console session required")
                        self.close_connection = True
                        return False
                    if self.command in ("POST", "PUT", "PATCH", "DELETE") \
                            and not _csrf_ok(
                                self.headers.get("X-CSRF-Token", ""),
                                info["csrf"]):
                        api_problem.send(self, 403,
                                         "csrf-validation-failed",
                                         "CSRF validation failed")
                        self.close_connection = True
                        return False
                mapped = api_routes.management_to_legacy(
                    self.command, self.path)
                if mapped is None:
                    api_problem.send(self, 404, "route-not-found",
                                     "Route not found")
                    self.close_connection = True
                    return False
                route = api_routes.match("management", self.command, self.path)
                self._task7_session_contract = (self.command, route.path) in {
                    ("GET", "/internal/v1/peer-policy"),
                    ("GET", "/internal/v1/peer-policy/roles"),
                    ("GET", "/internal/v1/peer-policy/explain"),
                    ("GET", "/internal/v1/devices/{device_id}/effective-qos"),
                    ("PUT", "/internal/v1/peer-policy/roles/{name}"),
                    ("DELETE", "/internal/v1/peer-policy/roles/{name}"),
                    ("PUT", "/internal/v1/peer-policy/qos"),
                    ("POST", "/internal/v1/devices/{device_id}/role"),
                    ("POST", "/internal/v1/devices/bulk-role"),
                }
                self.path = mapped
            # A background view poll (GET + "X-IRIS-Poll: 1", sent by app.js's
            # periodic refreshers) validates the session WITHOUT refreshing its
            # idle clock, so an unattended console on a polled view still
            # reaches the advertised idle timeout. GET-only: a mutation can
            # never opt out of counting as activity. gui_app.session_info
            # consults this per-thread flag for every lookup in the request.
            return ok

        def handle_one_request(self):
            try:
                super().handle_one_request()
            except secrets_store.StoreCorruptError as exc:
                # The live secrets store is present but unreadable. Every
                # route that needs it fails closed here with a diagnosable
                # answer (nothing has been written) instead of a dropped
                # connection and a traceback; the message carries the path
                # and failure class only.
                print("iris-gui: %s" % exc, file=sys.stderr, flush=True)
                try:
                    self._json(503, {"error": "secrets store unreadable; "
                                              "see the server log"})
                except OSError:
                    pass
                self.close_connection = True
            except catalog_mod.StateFileError as exc:
                # A catalog state file (policy.json, devices.json, ...) is
                # present but unreadable. Same fail-closed contract as the
                # secrets store above: the console must not render a corrupt
                # file as empty state, and the operator gets a diagnosable
                # answer rather than a traceback with no response.
                print("iris-gui: %s" % exc, file=sys.stderr, flush=True)
                try:
                    self._json(503, {"error": "state unavailable; "
                                              "see the server log"})
                except OSError:
                    pass
                self.close_connection = True
            except gui_fleet.FleetStateError as exc:
                # The fleet inventory (fleet.json / fleet.d/ shards /
                # fleet-revision.json) is present but unreadable. Identical
                # fail-closed contract to the catalog case just above --
                # gui_fleet.FleetStore's own read paths (get_device,
                # list_devices, snapshot) now fail closed the same way its
                # write paths always have, so this is the one place that
                # failure surfaces as a clean answer instead of a dropped
                # connection.
                print("iris-gui: %s" % exc, file=sys.stderr, flush=True)
                try:
                    self._json(503, {"error": "state unavailable; "
                                              "see the server log"})
                except OSError:
                    pass
                self.close_connection = True

        def _cookie_attrs(self):
            """Session-cookie attributes. Secure only when this listener
            actually serves TLS: a Secure cookie set over plain HTTP is
            discarded by every browser except on localhost, which turned the
            plaintext opt-in into a login loop with no diagnostic."""
            secure = srv.tls_active
            if management_token_file is not None:
                # The browser-facing scheme is asserted only by the BFF on an
                # already tier-authenticated hop. The BFF strips any inbound
                # spelling, so a browser cannot downgrade its own cookie.
                forwarded = self.headers.get("X-IRIS-Client-Scheme", "")
                if forwarded == "http":
                    secure = False
                elif forwarded == "https":
                    secure = True
            return ("; HttpOnly; Secure; SameSite=Strict; Path=/"
                    if secure else "; HttpOnly; SameSite=Strict; Path=/")

        def _drain_body(self, length):
            """Consume and discard up to min(length, _MAX_BODY) bytes of a
            request body that the route will not read (rejected before the
            read). Bounded, so an unauthenticated client can never make
            this process hold more than the small-body cap; enough that a
            well-behaved client's small body is drained and the error
            response reaches it instead of a connection reset."""
            left = min(int(length), _MAX_BODY)
            while left > 0:
                chunk = self.rfile.read(min(65536, left))
                if not chunk:
                    return
                left -= len(chunk)

        def _audit(self, event, category, action=None, target=None, detail=None,
                  actor=None, result="ok", src_ip=None):
            """Best-effort audit emit: NEVER let a logging failure break the
            calling route. Writes to the same audit.jsonl the catalog process
            writes (audit_path, default env IRIS_AUDIT)."""
            if audit_path is None:
                return
            try:
                audit.append_event(audit_path, event, actor=actor, category=category,
                                   action=action, target=target, detail=detail,
                                   src_ip=src_ip, result=result)
            except Exception:
                pass

        def _plan(self, device_id, device, onboarding=True):
            """Resolve immutable, non-secret installer input before token minting."""
            if onboarding:
                device = gui_onboard.validate_legacy_onboard_target(device, device_id)
            management_type = device.get("management_type", "legacy_routed")
            if management_type == "legacy_routed":
                management_type = "routed"
            if management_type not in ("routed", "inband", "router-routed", "router-nat",
                                       "xr-host"):
                raise ValueError("unknown management type")
            platform = gui_onboard.resolve_platform(device)
            router_management_type = management_type in ("router-routed", "router-nat")
            if device.get("model") and re.match(
                    r"^C8[0-9]{3}", device["model"], re.IGNORECASE) \
                    and not router_management_type:
                raise ValueError("Catalyst 8000 models require management_type "
                                 "router-routed or router-nat")
            if (platform == "router") != router_management_type:
                raise ValueError("platform router requires management_type "
                                 "router-routed or router-nat")
            if platform == "router" and device.get("model") and not re.match(
                    r"^C8[0-9]{3}", device["model"], re.IGNORECASE):
                raise ValueError("router modes support the Catalyst 8000 family only; "
                                 "%s is not yet supported" % device["model"])
            # xr-host <-> xr-appmgr is mutually required (gui_fleet.validate_record
            # enforces this on any FULLY-CLASSIFIED record), but a record reaching
            # this platform-only, e.g. the /platform route or legacy CSV import
            # (fleet.upsert with just {"platform": ...}) stays management_type
            # legacy_routed, which never runs that check. Left ungated here, such
            # a row planned straight through as 'routed': XE addressing keys, a
            # VLAN/SVI ownership narrative, and vlan/svi/guestshell owned
            # resources on an IOS-XR box. Gate on the RESOLVED platform, the same
            # way the 'router' coupling above already does.
            if (platform == "xr-appmgr") != (management_type == "xr-host"):
                raise ValueError("platform xr-appmgr requires management_type "
                                 "xr-host (the two are mutually required)")
            if management_type == "xr-host":
                # The appmgr container runs on the router's own network stack
                # (--net=host): no VLAN, SVI, app IP/mask/gateway, VPG, or NAT
                # interface is ever configured, so this dict must not carry
                # any of those keys -- not even with an empty-string value.
                # validate_record already rejects a non-empty one on the
                # stored record (gui_fleet.py); this is the same honesty
                # requirement applied to the plan a caller actually reads.
                network = {
                    "management_type": management_type,
                    "device_ip": device.get("device_ip", ""),
                    "swarm_port": "6881",
                    "model": device.get("model", ""),
                    "platform": platform,
                    "renderer": "v1",
                }
            else:
                network = {
                    "management_type": management_type,
                    "device_ip": device.get("device_ip", ""),
                    "iris_vlan": device.get("iris_vlan", device.get("vlan", "")),
                    "svi_ip": device.get("svi_ip", ""),
                    "svi_mask": device.get("svi_mask", ""),
                    # Per-device override of the SVI_IGP env var (issue #85).
                    # Only meaningful for management_type routed (the only
                    # type that creates an SVI); gui_fleet.validate_record
                    # already refuses a non-blank value on every other type,
                    # so device.get here is always "" for those.
                    "svi_igp": device.get("svi_igp", ""),
                    "app_ip": device.get("app_ip", device.get("guest_ip", "")),
                    "app_mask": device.get("app_mask", device.get("svi_mask", "")),
                    "app_gateway": device.get("app_gateway", device.get("svi_ip", "")),
                    "inband_vlan": device.get("inband_vlan", ""),
                    "vpg_number": device.get("vpg_number", ""),
                    "nat_interface": device.get("nat_interface", ""),
                    "swarm_port": "6881",
                    # The inband IOx app reaches IOS at the switch's management IP
                    # (which is on the same existing management VLAN); ios_ssh_host is
                    # an optional advanced override for asymmetric topologies.
                    "ios_ssh_host": (device.get("ios_ssh_host")
                                     or (device.get("device_ip", "") if management_type == "inband" else "")),
                    "model": device.get("model", ""),
                    "platform": platform,
                    "renderer": "v1",
                }
            if management_type == "inband":
                ownership = "preserves existing VLAN, SVI, gateway, routes, and VRF"
            elif management_type == "routed":
                ownership = "creates only a clean IRIS-owned VLAN and SVI"
            elif management_type == "router-nat":
                ownership = ("creates an IRIS-owned VPG and NAT rules; preserves the "
                             "outside interface except for a record-owned NAT marking")
            elif management_type == "xr-host":
                ownership = ("XR host networking — the agent shares the router's "
                             "own network stack; no app-network fields")
            else:
                ownership = "creates only a clean IRIS-owned VirtualPortGroup"
            plan = {"device_id": device_id, "inventory_revision": fleet.revision(),
                    "resolved": network, "ownership": ownership}
            plan["plan_hash"] = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
            return plan

        @staticmethod
        def _apply_preflight(plan, evidence):
            """Bind a platform's live execution-time evidence (board ID,
            model, router ownership facts) into a plan and re-hash it. Used
            to exist for routers only; every platform's preflight now feeds
            the record the same way."""
            resolved = gui_onboard.bind_preflight(plan["resolved"], evidence)
            updated = dict(plan)
            updated["resolved"] = resolved
            payload = {key: value for key, value in updated.items()
                       if key != "plan_hash"}
            updated["plan_hash"] = hashlib.sha256(
                json.dumps(payload, sort_keys=True).encode()).hexdigest()
            return updated

        @staticmethod
        def _owned_resources(resolved):
            """Resources IRIS may later remove, per management type. Inband owns
            only the app; it never claims the operator's VLAN/SVI. XR host owns
            exactly what device/xr-uninstall.sh removes: the appmgr
            application, its registered package source, the RPM staged at
            harddisk: root, and the agent's iris-work/ control-file
            directory. Every other management type here is IOS-XE and runs its
            agent inside a guestshell resource; IOS-XR has no such feature,
            so xr-host must NOT claim one."""
            if resolved.get("platform") == "iox":
                return [{"kind": "iox-app", "ownership": "iris-created"}]
            management_type = resolved["management_type"]
            if management_type == "xr-host":
                # Sidecar files (*.torrent/*.aria2/*.peers.json at harddisk:
                # root) are also part of xr-uninstall.sh's sweep, but are
                # deliberately NOT claimed as an owned resource here: they
                # are swept as IRIS-derived artifacts, not record-claimed
                # ones. Image files are a different story entirely -- a
                # staged image file is never removed by IRIS teardown
                # (recorded or forced), and the agent deletes an adopted
                # file only when the catalog republishes new content under
                # that same image id -- never otherwise -- so there is no
                # image-file resource kind to claim here either.
                return [
                    {"kind": "appmgr-application", "ownership": "iris-created",
                     "name": gui_onboard._XR_APPID},
                    {"kind": "appmgr-source", "ownership": "iris-created",
                     "name": gui_onboard._XR_SOURCE_NAME},
                    {"kind": "agent-rpm", "ownership": "iris-created",
                     "path": "harddisk:iris-xr.rpm"},
                    {"kind": "agent-work-dir", "ownership": "iris-created",
                     "path": "harddisk:iris-work"},
                ]
            resources = [{"kind": "guestshell", "ownership": "iris-created"}]
            if management_type == "routed":
                resources = [
                    {"kind": "vlan", "ownership": "iris-created",
                     "id": resolved.get("iris_vlan", "")},
                    {"kind": "svi", "ownership": "iris-created",
                     "ip": resolved.get("svi_ip", "")},
                ] + resources
            elif management_type in ("router-routed", "router-nat"):
                vpg = resolved.get("vpg_number", "")
                resources = [
                    {"kind": "virtualportgroup", "ownership": "iris-created",
                     "id": vpg},
                    {"kind": "eem-applets", "ownership": "iris-created"},
                    {"kind": "agent-files", "ownership": "iris-created",
                     "path": "bootflash:guest-share"},
                    {"kind": "logging-discriminator", "ownership": "iris-created",
                     "name": "IRISQ"},
                    {"kind": "pki-trustpoint", "ownership": "iris-created",
                     "name": "IRIS"},
                    {"kind": "http-client-trustpoint", "ownership": "iris-created",
                     "name": "IRIS"},
                    {"kind": "iox-global",
                     "ownership": ("pre-existing" if resolved.get("iox_preexisting") == "1"
                                   else "iris-added-preserved")},
                    {"kind": "file-prompt-quiet",
                     "ownership": ("pre-existing"
                                   if resolved.get("file_prompt_quiet_preexisting") == "1"
                                   else "iris-added-preserved")},
                ] + resources
                if management_type == "router-nat":
                    outside_ownership = ("iris-created"
                                         if resolved.get("nat_outside_owned") in (True, 1, "1")
                                         else "pre-existing")
                    resources.extend([
                        {"kind": "nat-acl", "ownership": "iris-created",
                         "name": "IRIS-NAT-%s" % vpg},
                        {"kind": "nat-overload", "ownership": "iris-created"},
                        {"kind": "nat-static", "ownership": "iris-created",
                         "port": resolved.get("swarm_port", "6881")},
                        {"kind": "nat-outside-marking", "ownership": outside_ownership,
                         "interface": resolved.get("nat_interface", "")},
                    ])
            return resources

        @staticmethod
        def _router_teardown_resolved(record):
            """Authorize router teardown strictly from record-owned resources."""
            resolved = dict(record.get("resolved") or {})
            if resolved.get("platform") != "router":
                if resolved.get("platform") == "iox":
                    # The controller's final recorded-uninstall authorization
                    # compares this immutable ownership binding after live
                    # board discovery and predecessor recovery.
                    resolved["resources"] = copy.deepcopy(
                        record.get("resources") or [])
                return resolved
            # A raw KeyError here would escape do_POST as an unhandled 500
            # instead of the clean 409 + needs-reconcile transition the
            # caller's except ValueError expects (gui_server.py:3084-3098) --
            # so every management_type read below this point is guaranteed
            # safe by this one explicit, idiomatic raise.
            if "management_type" not in resolved:
                raise ValueError("plan is missing management_type")
            required = {"virtualportgroup", "eem-applets", "agent-files",
                        "logging-discriminator", "pki-trustpoint",
                        "http-client-trustpoint", "iox-global",
                        "file-prompt-quiet", "guestshell"}
            if resolved["management_type"] == "router-nat":
                required.update(("nat-acl", "nat-overload", "nat-static",
                                 "nat-outside-marking"))
            resources = record.get("resources") or []
            by_kind = {resource.get("kind"): resource for resource in resources}
            missing = sorted(required - set(by_kind))
            if missing:
                raise ValueError("router record does not prove ownership of: %s"
                                 % ", ".join(missing))
            preserved = {"nat-outside-marking", "iox-global", "file-prompt-quiet"}
            for kind in required - preserved:
                if by_kind[kind].get("ownership") != "iris-created":
                    raise ValueError("router record does not prove IRIS ownership of %s"
                                     % kind)
            for kind in ("iox-global", "file-prompt-quiet"):
                if by_kind[kind].get("ownership") not in (
                        "pre-existing", "iris-added-preserved"):
                    raise ValueError("router record has ambiguous ownership of %s"
                                     % kind)
            expected = {
                "virtualportgroup": ("id", str(resolved.get("vpg_number", ""))),
                "agent-files": ("path", "bootflash:guest-share"),
                "logging-discriminator": ("name", "IRISQ"),
                "pki-trustpoint": ("name", "IRIS"),
                "http-client-trustpoint": ("name", "IRIS"),
            }
            if resolved["management_type"] == "router-nat":
                expected.update({
                    "nat-acl": ("name", "IRIS-NAT-%s" % resolved.get("vpg_number", "")),
                    "nat-static": ("port", str(resolved.get("swarm_port", "6881"))),
                    "nat-outside-marking": ("interface", resolved.get("nat_interface", "")),
                })
            for kind, (field, value) in expected.items():
                if str(by_kind[kind].get(field, "")) != str(value):
                    raise ValueError("router record %s does not match resolved plan"
                                     % kind)
            if not resolved.get("device_ip") or not resolved.get("device_identity"):
                raise ValueError("router record is missing deployed device identity")
            resolved["router_resources_owned"] = "1"
            if resolved["management_type"] == "router-nat":
                marking = by_kind["nat-outside-marking"]
                if marking.get("ownership") not in ("iris-created", "pre-existing"):
                    raise ValueError("router record has ambiguous NAT outside ownership")
                resolved["nat_outside_owned"] = (
                    "1" if marking.get("ownership") == "iris-created" else "0")
                resolved["nat_interface"] = marking.get("interface") or ""
            return resolved

        def _send(self, status, ctype, body, extra_headers=None):
            if isinstance(body, str):
                body = body.encode("utf-8")
            extra_headers = (list(getattr(self, "_response_headers", ())) +
                             list(extra_headers or ()))
            self._finish_idempotency(
                (status, ctype, body, tuple(extra_headers))
                if 200 <= status < 300 else None)
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in _SECURITY_HEADERS:
                self.send_header(k, v)
            extra = list(extra_headers)
            if self.path.split("?", 1)[0].startswith("/api/") and not any(
                    k.lower() == "cache-control" for k, _ in extra):
                # Session-gated JSON/CSV must never land in a disk cache or
                # bfcache that outlives the session.
                self.send_header("Cache-Control", "private, no-store")
            for k, v in extra:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status, obj, extra_headers=None):
            if status >= 400:
                self._finish_idempotency(None)
                headers = (list(getattr(self, "_response_headers", ())) +
                           list(extra_headers or ()))
                api_problem.legacy(self, status, obj, headers=headers)
                return
            self._send(status, "application/json",
                       json.dumps(obj).encode("utf-8"), extra_headers)

        def _finish_idempotency(self, response):
            context = getattr(self, "_idempotency_context", None)
            if context is None:
                return
            self._idempotency_context = None
            cache_key, digest = context
            with idempotency_lock:
                entry = idempotency_cache.get(cache_key)
                if entry is None or entry["digest"] != digest:
                    return
                if response is None:
                    idempotency_cache.pop(cache_key, None)
                else:
                    entry["response"] = response
                    entry["created"] = time.time()
                entry["event"].set()

        def _prepare_idempotency(self, path, raw, info):
            """Reserve or replay an Idempotency-Key after browser auth.

            Returns True when normal dispatch should continue and False after
            sending a replay/error. The body is hashed but never retained in
            the ledger, and the key is never logged or included in an error.
            """
            value = self.headers.get("Idempotency-Key")
            if value is None:
                return True
            if not idempotency_supported(path):
                self._json(400, {"error": "idempotency key is not supported "
                                          "for this operation"})
                return False
            if not re.fullmatch(r"[A-Za-z0-9._~:-]{8,128}", value):
                self._json(400, {"error": "invalid idempotency key"})
                return False
            digest = hashlib.sha256(raw).hexdigest()
            cache_key = (str(info.get("username", "")), path, value)
            wait_event = None
            now = time.time()
            with idempotency_lock:
                for key, entry in list(idempotency_cache.items()):
                    if now - entry["created"] > idempotency_ttl:
                        idempotency_cache.pop(key, None)
                entry = idempotency_cache.get(cache_key)
                if entry is not None:
                    if not hmac.compare_digest(entry["digest"], digest):
                        self._json(409, {"error": "idempotency key conflict"})
                        return False
                    if entry["response"] is not None:
                        response = entry["response"]
                    else:
                        response = None
                        wait_event = entry["event"]
                else:
                    if not _idempotency_make_room(
                            idempotency_cache, idempotency_limit):
                        self._json(
                            503,
                            {"error": "idempotency ledger is busy"},
                            extra_headers=[("Retry-After", "1")])
                        return False
                    idempotency_cache[cache_key] = {
                        "digest": digest, "created": now,
                        "response": None, "event": threading.Event()}
                    self._idempotency_context = (cache_key, digest)
                    return True
            if wait_event is not None:
                wait_event.wait(30)
                with idempotency_lock:
                    entry = idempotency_cache.get(cache_key)
                    response = entry.get("response") if entry else None
            if response is None:
                self._json(503, {"error": "idempotent request still in progress"},
                           extra_headers=[("Retry-After", "1")])
                return False
            status, ctype, body, headers = response
            self._send(status, ctype, body,
                       list(headers) + [("Idempotency-Replayed", "true")])
            return False

        def _sid(self):
            jar = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            m = jar.get(COOKIE)
            return m.value if m else ""

        def _client_ip(self):
            """Original BFF peer, trusted only on the tier-authenticated hop."""
            if management_token_file is not None:
                forwarded = self.headers.get("X-IRIS-Client-IP", "").strip()
                try:
                    return str(ipaddress.ip_address(forwarded))
                except ValueError:
                    pass
            return self.client_address[0]

        def _session_refusal(self):
            if getattr(self, "_task7_session_contract", False):
                api_problem.send(self, 401, "console-session-required", "Console session required")
            else:
                self._json(401, {"error": "unauthorized"})

        def _require_session_csrf(self, unread_body=0):
            """Return the session info for a valid session+CSRF request, else send
            the error response and return None. *unread_body* is the declared
            body length the caller has deliberately NOT read yet (auth before
            buffering); on rejection a bounded amount is drained so the error
            answer is delivered rather than reset."""
            info = app.session_info(self._sid())
            if info is None:
                self._drain_body(unread_body)
                self._session_refusal()
                return None
            if not _csrf_ok(self.headers.get("X-CSRF-Token", ""), info["csrf"]):
                self._drain_body(unread_body)
                self._json(403, {"error": "bad csrf"})
                return None
            return info

        def _json_body(self, raw):
            """Parse a JSON request body that must be an object. Returns the dict,
            or sends a 400 and returns None (the caller must then return). Guards
            against valid-JSON-but-non-object bodies (e.g. [], 123, "x", true),
            which would otherwise raise AttributeError on data.get(...) and drop
            the connection instead of returning a clean error."""
            try:
                data = json.loads(raw or b"{}")
            except ValueError:
                self._json(400, {"error": "bad json"})
                return None
            if not isinstance(data, dict):
                self._json(400, {"error": "bad json"})
                return None
            return data

        def _schedule_problem(self, status, code, title, *, headers=None,
                              **extensions):
            api_problem.send(self, status, code, title, headers=headers,
                             **extensions)

        def _schedule_session(self, *, mutation=False, unread_body=0):
            try:
                info = app.session_info(self._sid())
            except (secrets_store.StoreCorruptError, OSError, ValueError,
                    TypeError, RecursionError, OverflowError):
                self._drain_body(unread_body)
                self._schedule_problem(503, "credential-store-unavailable",
                                       "Credential store unavailable")
                return None
            if info is None:
                self._drain_body(unread_body)
                self._schedule_problem(401, "console-session-required",
                                       "Console session required")
                return None
            if mutation and not _csrf_ok(
                    self.headers.get("X-CSRF-Token", ""), info["csrf"]):
                self._drain_body(unread_body)
                self._schedule_problem(403, "csrf-validation-failed",
                                       "CSRF validation failed")
                return None
            return info

        def _schedule_json_body(self, raw):
            try:
                data = json.loads(raw or b"{}")
            except (ValueError, UnicodeDecodeError):
                self._schedule_problem(400, "invalid-request",
                                       "Invalid request")
                return None
            if not isinstance(data, dict):
                self._schedule_problem(400, "invalid-request",
                                       "Invalid request")
                return None
            return data

        @staticmethod
        def _schedule_target_facts(resolved):
            if resolved is None:
                return None
            return {key: resolved[key] for key in
                    ("missing_os_family", "role_drift", "quarantined_ids")}

        @staticmethod
        def _schedule_actor_exists(actor, admin):
            if actor == "cli:iris-schedule":
                return True
            if actor.startswith("console:") and admin is not None:
                return actor[len("console:"):] == admin.get("username")
            return False

        def _schedule_views(self, rows):
            admin = gui_auth.get_admin(app._load())
            now = int(now_fn())
            views = []
            for row in rows:
                view = dict(row)
                view["etag"] = schedules.schedule_etag(row)
                view["creator_exists"] = self._schedule_actor_exists(
                    row["created_by"], admin)
                # The current or next slot, computed by the same authority the
                # runner fires from. A console that recomputed weekly local
                # time itself would be a second, quietly divergent answer to
                # the one question an operator plans a window from.
                view["next_fire"] = schedules.occurrence_slot(row, now)
                views.append(view)
            return views

        def _schedule_error(self, exc, *, raced=False):
            if raced and isinstance(exc, schedules.ScheduleNotFound):
                self._schedule_problem(412, "precondition_failed",
                                       "Precondition failed")
                return
            if isinstance(exc, schedules.ScheduleRevisionConflict):
                try:
                    row = schedule_store.get(exc.schedule_id)
                except Exception:
                    self._schedule_problem(503, "schedule_state_unavailable",
                                           "Schedule state unavailable")
                    return
                headers = ([('ETag', schedules.schedule_etag(row))]
                           if row is not None else None)
                self._schedule_problem(412, "precondition_failed",
                                       "Precondition failed", headers=headers)
                return
            if isinstance(exc, role_management.RoleManagementError):
                safe = {key: value for key, value in exc.result.items()
                        if key not in ("ok", "error", "partial")}
                self._schedule_problem(exc.status, exc.code,
                                       exc.code.replace("_", " ").title(),
                                       **safe)
                return
            if isinstance(exc, (schedules.ScheduleValidationError,
                                schedules.ScheduleConflict,
                                schedules.ScheduleNotFound,
                                schedules.ScheduleStateError,
                                ScheduleTargetError)):
                code = exc.code
                self._schedule_problem(
                    exc.status, code, code.replace("_", " ").title())
                return
            self._schedule_problem(503, "schedule_state_unavailable",
                                   "Schedule state unavailable")

        def _schedule_existing(self, schedule_id):
            try:
                row = schedule_store.get(schedule_id)
            except Exception as exc:
                self._schedule_error(exc)
                return None
            if row is None:
                self._schedule_problem(404, "schedule_not_found",
                                       "Schedule not found")
                return None
            return row

        def _schedule_precondition(self, row):
            current = schedules.schedule_etag(row)
            values = self.headers.get_all("If-Match") or []
            if not values:
                self._schedule_problem(
                    428, "precondition_required", "Precondition required",
                    headers=(("ETag", current),))
                return None
            if len(values) != 1 or values[0] not in ("*", current):
                self._schedule_problem(
                    412, "precondition_failed", "Precondition failed",
                    headers=(("ETag", current),))
                return None
            return "*" if values[0] == "*" else row["rev"]

        def _schedule_get(self, path):
            info = self._schedule_session()
            if info is None:
                return
            try:
                if path == "/api/schedules":
                    if urlsplit(self.path).query:
                        raise schedules.ScheduleValidationError(
                            "schedule list has no query parameters")
                    rows = schedule_store.list()
                    views = self._schedule_views(rows)
                    self._json(200, {"schedules": views, "total": len(views)})
                    return
                history_match = re.fullmatch(
                    r"/api/schedules/([^/]+)/(occurrences|receipts)", path)
                if history_match:
                    schedule_id = unquote(history_match.group(1))
                    resource = history_match.group(2)
                    row = schedule_store.get(schedule_id)
                    # Definitions may be deleted while their occurrence and
                    # receipt evidence is intentionally retained. History
                    # stays readable until both authorities are absent.
                    if (row is None and not
                            schedule_occurrence_store.list(schedule_id)):
                        raise schedules.ScheduleNotFound("no such schedule")
                    query = parse_qs(urlsplit(self.path).query,
                                     keep_blank_values=True)
                    if set(query) - {"limit", "offset"} or any(
                            len(values) != 1 for values in query.values()):
                        raise schedules.ScheduleValidationError(
                            "invalid schedule history pagination")
                    default_limit = (schedules.MAX_OCCURRENCE_PAGE
                                     if resource == "occurrences" else
                                     schedules.MAX_RECEIPT_PAGE)
                    raw_limit = (query.get("limit") or
                                 [str(default_limit)])[0]
                    raw_offset = (query.get("offset") or ["0"])[0]
                    if not raw_limit.isdecimal() or not raw_offset.isdecimal():
                        raise schedules.ScheduleValidationError(
                            "invalid schedule history pagination")
                    history = (schedules.list_schedule_occurrences
                               if resource == "occurrences" else
                               schedules.list_schedule_receipts)
                    self._json(200, history(schedule_store.state_dir,
                                            schedule_id,
                                            limit=int(raw_limit),
                                            offset=int(raw_offset)))
                    return
                item_match = re.fullmatch(r"/api/schedules/([^/]+)", path)
                if item_match:
                    schedule_id = unquote(item_match.group(1))
                    row = schedule_store.get(schedule_id)
                    if row is None:
                        raise schedules.ScheduleNotFound("no such schedule")
                    view = self._schedule_views([row])[0]
                    self._json(200, {"schedule": view},
                               extra_headers=(("ETag", view["etag"]),))
                    return
            except Exception as exc:
                self._schedule_error(exc)
                return
            self._schedule_problem(404, "route-not-found", "Route not found")

        @staticmethod
        def _normalized_schedule_patch(row, patch):
            if not isinstance(patch, dict) or set(patch) - schedules.DEFINITION_KEYS:
                raise schedules.ScheduleValidationError(
                    "invalid schedule patch fields")
            definition = {key: row[key] for key in schedules.DEFINITION_KEYS
                          if key in row}
            definition.update(copy.deepcopy(patch))
            if definition.get("after", False) is None:
                definition.pop("after")
            normalized = schedules.normalize_definition(definition)
            out = {}
            for key in patch:
                if key == "after" and patch[key] is None:
                    out[key] = None
                else:
                    out[key] = normalized[key]
            return out

        def _schedule_mutation(self, method, path, raw, info):
            actor = "console:" + info["username"]
            try:
                if method == "POST" and path == "/api/schedules":
                    body = self._schedule_json_body(raw)
                    if body is None:
                        return
                    schedule_id = body.get("id")
                    definition = {key: value for key, value in body.items()
                                  if key != "id"}
                    definition = schedules.normalize_definition(definition)
                    # Validate the key and detect an existing row before any
                    # fleet/policy authority read. The atomic create still
                    # owns the race with another writer.
                    if schedule_store.get(schedule_id) is not None:
                        raise schedules.ScheduleConflict(
                            "schedule already exists")
                    coordinator = role_coordinator()
                    if coordinator is None:
                        raise ScheduleTargetError("fleet state is unavailable")

                    def validated_resolver(target, role_policy=None):
                        resolved = schedule_target_resolver(
                            target, role_policy=role_policy)
                        if scheduled_executor is None:
                            raise ScheduleTargetError(
                                "schedule executor is unavailable")
                        scheduled_executor.validate(
                            definition, resolved, "creation")
                        return resolved

                    row, resolved = coordinator.create_schedule(
                        schedule_id, definition, actor=actor, now=int(now_fn()),
                        resolve_target=validated_resolver)
                    wake_schedule_runner()
                    view = self._schedule_views([row])[0]
                    self._json(201, {
                        "schedule": view,
                        "target_facts": self._schedule_target_facts(resolved),
                    }, extra_headers=((
                        "Location",
                        ("/internal/v1/schedules/" if getattr(
                            self, "_iris_management_wire", False)
                         else "/api/schedules/") + row["id"]),
                                      ("ETag", view["etag"])))
                    return

                reaffirm_match = re.fullmatch(
                    r"/api/schedules/([^/]+)/reaffirm", path)
                item_match = re.fullmatch(r"/api/schedules/([^/]+)", path)
                match = reaffirm_match or item_match
                if match is None:
                    self._schedule_problem(404, "route-not-found",
                                           "Route not found")
                    return
                schedule_id = unquote(match.group(1))
                before = self._schedule_existing(schedule_id)
                if before is None:
                    return
                expected = self._schedule_precondition(before)
                if expected is None:
                    return

                if method == "DELETE" and item_match:
                    coordinator = role_coordinator()
                    if coordinator is None:
                        raise ScheduleTargetError("fleet state is unavailable")
                    coordinator.delete_schedule(
                        schedule_id, expected_rev=expected)
                    wake_schedule_runner()
                    self._send(204, "application/json", b"",
                               (("ETag", schedules.schedule_etag(before)),))
                    return
                body = self._schedule_json_body(raw)
                if body is None:
                    return
                if method == "POST" and reaffirm_match:
                    if body:
                        raise schedules.ScheduleValidationError(
                            "reaffirm body must be empty")
                    row = schedule_store.reaffirm(
                        schedule_id, actor, expected_rev=expected)
                    wake_schedule_runner()
                    view = self._schedule_views([row])[0]
                    self._json(200, {"schedule": view},
                               extra_headers=(("ETag", view["etag"]),))
                    return
                coordinator = role_coordinator()
                if coordinator is None:
                    raise ScheduleTargetError("fleet state is unavailable")
                if method == "PUT" and item_match:
                    definition = schedules.normalize_definition(body)

                    def validated_resolver(target, role_policy=None):
                        resolved = schedule_target_resolver(
                            target, role_policy=role_policy)
                        if scheduled_executor is None:
                            raise ScheduleTargetError(
                                "schedule executor is unavailable")
                        scheduled_executor.validate(
                            definition, resolved, "creation")
                        return resolved

                    row, resolved = coordinator.put_schedule(
                        schedule_id, definition, expected_rev=expected,
                        resolve_target=validated_resolver)
                elif method == "PATCH" and item_match:
                    patch = self._normalized_schedule_patch(before, body)
                    definition = {
                        key: copy.deepcopy(before[key])
                        for key in schedules.DEFINITION_KEYS if key in before}
                    definition.update(copy.deepcopy(patch))
                    if definition.get("after", False) is None:
                        definition.pop("after")
                    definition = schedules.normalize_definition(definition)

                    def validated_resolver(target, role_policy=None):
                        resolved = schedule_target_resolver(
                            target, role_policy=role_policy)
                        if scheduled_executor is None:
                            raise ScheduleTargetError(
                                "schedule executor is unavailable")
                        scheduled_executor.validate(
                            definition, resolved, "creation")
                        return resolved

                    # Force the coordinator's existing target-resolution path
                    # for payload-only patches too; the identical target does
                    # not reset the durable creation preview.
                    patch.setdefault("target", copy.deepcopy(before["target"]))
                    row, resolved = coordinator.patch_schedule(
                        schedule_id, patch, expected_rev=expected,
                        resolve_target=validated_resolver)
                else:
                    self._schedule_problem(404, "route-not-found",
                                           "Route not found")
                    return
                wake_schedule_runner()
                view = self._schedule_views([row])[0]
                self._json(200, {
                    "schedule": view,
                    "target_facts": self._schedule_target_facts(resolved),
                }, extra_headers=(("ETag", view["etag"]),))
            except schedules.ScheduleNotFound as exc:
                self._schedule_error(exc, raced=True)
            except Exception as exc:
                self._schedule_error(exc)

        def _body_reader(self, remaining):
            """Return a zero-arg reader() streaming up to *remaining* bytes from
            the request body in 1 MiB chunks (b'' at EOF)."""
            state = {"left": remaining}

            def read():
                if state["left"] <= 0:
                    return b""
                n = min(1 << 20, state["left"])
                chunk = self.rfile.read(n)
                state["left"] -= len(chunk)
                return chunk
            return read

        def _serve_static(self, path):
            rel = "index.html" if path in ("", "/") else path.lstrip("/")
            full = os.path.normpath(os.path.join(WEBROOT, rel))
            if not full.startswith(WEBROOT + os.sep) or not os.path.isfile(full):
                self._send(404, "text/plain", b"not found")
                return
            ext = os.path.splitext(full)[1]
            # The SPA assets (index.html/app.js/styles.css) are not
            # content-hashed, so without this a browser keeps serving a stale
            # bundle after a deploy — new features (e.g. the Monitoring tab)
            # stay invisible until the user manually clears their cache.
            # no-cache = the browser may store it but MUST revalidate with the
            # server before use, so a redeploy is picked up on the next load.
            # Last-Modified + If-Modified-Since -> 304 is what makes that
            # revalidation cheap instead of a full ~780 KB re-download per load.
            try:
                mtime = int(os.stat(full).st_mtime)
            except OSError:
                mtime = None
            cache_headers = [("Cache-Control", "no-cache")]
            if mtime is not None:
                cache_headers.append(
                    ("Last-Modified", email.utils.formatdate(mtime, usegmt=True)))
                ims = self.headers.get("If-Modified-Since")
                if ims:
                    try:
                        ims_ts = email.utils.parsedate_to_datetime(ims).timestamp()
                    except (TypeError, ValueError, OverflowError):
                        ims_ts = None
                    if ims_ts is not None and mtime <= int(ims_ts):
                        self.send_response(304)
                        for k, v in _SECURITY_HEADERS:
                            self.send_header(k, v)
                        for k, v in cache_headers:
                            self.send_header(k, v)
                        self.end_headers()
                        return
            with open(full, "rb") as f:
                body = f.read()
            self._send(200, _CONTENT_TYPES.get(ext, "application/octet-stream"),
                       body, extra_headers=cache_headers)

        def _serve_swarmmap(self):
            """Serve the swarm-map page (session gate happens in do_GET) from
            server/swarmmap.html, read fresh per request. Sends its own headers
            instead of _send(): the global _SECURITY_HEADERS CSP has no
            script-src, so its default-src 'self' would block the page's
            nonce'd inline <script>, and X-Frame-Options: DENY would break the
            console shell's same-origin <iframe src="/swarmmap"> embed."""
            try:
                with open(SWARMMAP_PATH, encoding="utf-8") as f:
                    html = f.read()
            except OSError:
                self._send(404, "text/plain", b"not found")
                return
            nonce = secrets.token_urlsafe(16)
            html = html.replace(_MAP_PLACEHOLDER, _map_cfg_line())
            html = html.replace("<script>", '<script nonce="%s">' % nonce)
            html = html.replace("<style>", '<style nonce="%s">' % nonce)
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "private, no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'nonce-%s'; "
                "style-src 'nonce-%s'; connect-src 'self'; img-src 'self'"
                % (nonce, nonce))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/api/schedules" or path.startswith("/api/schedules/"):
                self._schedule_get(path)
                return
            if path == "/__management/console-certificate" and \
                    management_token_file is not None:
                # The state-free console keeps no durable TLS key.  Its only
                # private-key transfer is this management-authenticated,
                # CA-verified hop; the BFF stores the result in its tmpfs.
                override = gui_tls.override_active()
                if not override and self.headers.get(
                        "X-IRIS-Default-Certificate", "").strip() == "available":
                    # Kubernetes supplies an independent console identity with
                    # the operator-facing SAN. Do not send the catalog/server
                    # private key merely for the BFF to discard it.
                    self.send_response(204)
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-IRIS-Certificate-Source", "default")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                active = (_resolve_certfile() if override else
                          os.environ.get("IRIS_GUI_FALLBACK_CERT", "").strip())
                if not active:
                    api_problem.send(self, 503,
                                     "console-certificate-unavailable",
                                     "Console certificate unavailable")
                    return
                try:
                    with open(active, "rb") as stream:
                        body = stream.read(1024 * 1024 + 1)
                except OSError:
                    api_problem.send(self, 503, "console-certificate-unavailable",
                                     "Console certificate unavailable")
                    return
                if len(body) > 1024 * 1024 or b"PRIVATE KEY" not in body:
                    api_problem.send(self, 503, "console-certificate-unavailable",
                                     "Console certificate unavailable")
                    return
                self._send(200, "application/x-pem-file", body,
                           (("Cache-Control", "no-store"),
                            ("X-IRIS-Certificate-Source",
                             "custom" if override else "built-in")))
                return
            if path in ("/api/peer-policy/roles", "/api/peer-policy/explain") or (
                    path.startswith("/api/devices/") and path.endswith("/effective-qos")):
                self._policy_read(path)
                return
            if path == "/api/peer-policy":
                if app.session_info(self._sid()) is None:
                    self._session_refusal(); return
                view = policy_view()
                self._json(200, view, extra_headers=[
                    ("ETag", _revision_etag("peer-policy", view["revision"]))])
                return
            if path == "/api/audit":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                qs = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                category = (qs.get("category") or [None])[0]
                if category is not None and category not in audit.AUDIT_CATEGORIES:
                    self._json(400, {"error": "bad category"}); return
                try:
                    limit = int((qs.get("limit") or [200])[0])
                except ValueError:
                    limit = 200
                limit = min(limit, 500)
                before_ts = None
                if qs.get("before_ts"):
                    try:
                        before_ts = float(qs["before_ts"][0])
                    except ValueError:
                        before_ts = None
                after_ts = None
                if qs.get("after_ts"):
                    try:
                        after_ts = float(qs["after_ts"][0])
                    except ValueError:
                        after_ts = None
                events = (audit.read_events(audit_path, limit=limit,
                                            before_ts=before_ts, after_ts=after_ts,
                                            category=category)
                         if audit_path else [])
                self._json(200, {"events": events}); return
            if path == "/api/audit/histogram":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                qs = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                category = (qs.get("category") or [None])[0]
                if category is not None and category not in audit.AUDIT_CATEGORIES:
                    self._json(400, {"error": "bad category"}); return
                try:
                    buckets = int((qs.get("buckets") or [30])[0])
                except ValueError:
                    buckets = 30
                buckets = max(1, min(buckets, 200))
                now = time.time()
                # Explicit [since_ts, until_ts) window (the timeline brush) when
                # BOTH are given; otherwise the window=<secs>-ending-now default.
                since = until = None
                for name in ("since_ts", "until_ts"):
                    if qs.get(name):
                        try:
                            val = float(qs[name][0])
                        except ValueError:
                            val = None
                        if name == "since_ts":
                            since = val
                        else:
                            until = val
                if since is not None and until is not None:
                    if until <= since:
                        self._json(400, {"error": "until_ts must be greater "
                                                  "than since_ts"}); return
                else:
                    try:
                        window = float((qs.get("window") or [604800])[0])
                    except ValueError:
                        window = 604800
                    since, until = now - window, now
                bucket_seconds = (until - since) / buckets
                data = (audit.histogram(audit_path, since_ts=since,
                                        until_ts=until, buckets=buckets,
                                        category=category)
                       if audit_path else
                       [{"start": int(since + i * bucket_seconds), "count": 0}
                        for i in range(buckets)])
                self._json(200, {"buckets": data, "now": int(now),
                                 "bucket_seconds": bucket_seconds}); return
            if path == "/api/session":
                info = app.session_info(self._sid())
                if info is None:
                    self._json(401, {"error": "unauthorized"})
                else:
                    self._json(200, info)
                return
            if path == "/api/images":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"})
                elif images is None:
                    self._json(200, {"images": []})
                else:
                    self._json(200, {"images": [_image_view(e)
                                                for e in images.list_images()]})
                return
            if path == "/api/images/importable":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"})
                elif images is None:
                    self._json(200, {"importable": [], "skipped": []})
                else:
                    self._json(200, {"importable": images.list_importable(),
                                     "skipped": images.list_skipped()})
                return
            if path.startswith("/api/images/jobs/"):
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"})
                    return
                job = images.get_job(path[len("/api/images/jobs/"):]) if images else None
                self._json(200, job) if job else self._json(404, {"error": "no such job"})
                return
            if path == "/api/devices":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                qs = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                try:
                    limit, offset = _page_params(qs)
                except ValueError as exc:
                    self._json(400, {"error": str(exc)}); return
                q = (qs.get("q") or [None])[0]
                if q is not None:
                    q = q.strip().lower() or None
                filters = _device_filter_params(qs)
                try:
                    rows, total, revision, target_facts = self._device_page(
                        limit, offset, q, filters)
                except deployment_records.RecordStoreUnreadable:
                    self._json(503, {
                        "error": "deployment targeting facts unavailable"})
                    return
                # "now" rides along so last_seen freshness is computed
                # server-clock-to-server-clock in the UI (skewed lab VMs).
                # total/revision ride along on EVERY response, paged or not:
                # a client that never pages still needs to be able to tell
                # that what it holds is the whole fleet.
                target_warnings = []
                if target_facts["missing_os_family"]:
                    target_warnings.append(
                        "%d devices have no os_family yet" %
                        target_facts["missing_os_family"])
                if target_facts["role_drift"]:
                    target_warnings.append(
                        "%d devices have declared role drift" %
                        target_facts["role_drift"])
                self._json(200, {"devices": rows, "now": int(now_fn()),
                                 "total": total, "offset": offset,
                                 "limit": limit, "revision": revision,
                                 "target_facts": target_facts,
                                 "target_warnings": target_warnings},
                           extra_headers=[
                               ("ETag", _revision_etag("fleet", revision))])
                return
            if path == "/api/install-options":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                qs = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                model = (qs.get("model") or [""])[0]
                self._json(200, {"options": gui_onboard.install_options_for(model)}); return
            if path.startswith("/api/devices/") and path.endswith("/plan"):
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                did = unquote(path[len("/api/devices/"):-len("/plan")])
                device = fleet.get_device(did) if fleet else None
                if device is None:
                    self._json(404, {"error": "no such device"}); return
                try:
                    plan = self._plan(did, device)
                except ValueError as exc:
                    self._json(409, {"error": str(exc)}); return
                self._json(200, {"plan": plan}); return
            if path == "/api/devices/export-csv":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                body = (fleet.export_csv() if fleet else "").encode("utf-8")
                self._send(200, "text/csv; charset=utf-8", body,
                           extra_headers=[("Content-Disposition",
                                           "attachment; filename=devices.csv")])
                return
            if path == "/api/devices/example-csv":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                body = (fleet.example_csv() if fleet else "").encode("utf-8")
                self._send(200, "text/csv; charset=utf-8", body,
                           extra_headers=[("Content-Disposition",
                                           "attachment; filename=devices-example.csv")])
                return
            if path.startswith("/api/devices/") and path.endswith("/reports"):
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                did = unquote(path[len("/api/devices/"):-len("/reports")])
                if not did.strip():
                    self._json(400, {"error": "bad device id"}); return
                if fleet is None or fleet.get_device(did) is None:
                    self._json(422, {"error": "device is not in fleet"}); return
                reports = catalog.get_telemetry(did) if catalog else []
                self._json(200, {"reports": reports}); return
            if path.startswith("/api/devices/") and path.endswith("/deployment"):
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                if record_store is None:
                    self._json(404, {"error": "records unavailable"}); return
                did = unquote(path[len("/api/devices/"):-len("/deployment")])
                if iox_controller is None:
                    self._json(503, {
                        "error": "IOx authority is unavailable"}); return
                try:
                    authority = iox_controller.summary_for_device(did)
                    if (not isinstance(authority, dict) or
                            set(authority) != {
                                "iox_verification_obligations",
                                "iox_sessions"} or
                            not isinstance(
                                authority["iox_verification_obligations"],
                                list) or
                            not isinstance(authority["iox_sessions"], list)):
                        raise ValueError("invalid IOx authority projection")
                    records = record_store.list(did, strict=True)
                    # The record that best describes the device: the active
                    # one, else the recoverable teardown-authorizing one.
                    # Duplicate valid candidates retain the established
                    # read-only fallback to the newest record; unreadable
                    # authority is handled by the outer 503 path.
                    try:
                        record = record_store.recoverable_for_device(
                            did, strict=True)
                    except ValueError:
                        record = None
                except Exception:
                    # Authority errors can contain private paths or transport
                    # detail. The browser receives only this bounded fault;
                    # operators can use the server log for diagnosis.
                    self._json(503, {
                        "error": "IOx authority is unreadable"}); return
                if record is None and records:
                    record = max(records,
                                 key=lambda r: (r.get("timestamps") or {})
                                 .get("planned_at") or 0)
                try:
                    public_record = copy.deepcopy(record)
                    if (public_record is not None and
                            public_record.get("iox_verification") is not None):
                        public_record["iox_verification"] = (
                            deployment_records.DeploymentRecordStore
                            ._iox_safe_summary(
                                public_record["iox_verification"]))
                except Exception:
                    self._json(503, {
                        "error": "IOx authority is unreadable"}); return
                self._json(200, {
                    "record": public_record,
                    "total": len(records),
                    "iox_verification_obligations": copy.deepcopy(
                        authority["iox_verification_obligations"]),
                    "iox_sessions": copy.deepcopy(
                        authority["iox_sessions"]),
                })
                return
            if path == "/api/credentials":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                self._json(200, {"profiles": creds.list_profiles() if creds else []})
                return
            if path == "/api/onboard/jobs":     # exact match before the /<id> prefix routes
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                self._json(200, {
                    "jobs": onboard.list_jobs() if onboard else [],
                    "max_concurrent": onboard.max_concurrent if onboard else 0,
                    # server clock: the UI derives running durations from
                    # started_at against THIS, never the browser clock
                    "now": int(time.time())})
                return
            if path.startswith("/api/onboard/jobs/") and path.endswith("/stream"):
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                jid = path[len("/api/onboard/jobs/"):-len("/stream")]
                self._sse_onboard(onboard, jid); return
            if path.startswith("/api/onboard/jobs/"):
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                job = onboard.get_job(path[len("/api/onboard/jobs/"):]) if onboard else None
                self._json(200, job) if job else self._json(404, {"error": "no such job"})
                return
            if path == "/api/deploy-logs":  # exact match before the /<file> prefix route
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                qs = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                device_id = (qs.get("device_id") or [None])[0]
                def _ts(name):
                    if not qs.get(name):
                        return None
                    try:
                        return int(float(qs[name][0]))
                    except ValueError:
                        return None
                log_dir = getattr(onboard, "log_dir", None) if onboard else None
                # Only meaningful for a single device's history; the unfiltered
                # list spans the whole fleet, where one device's stamp says
                # nothing about another's rows.
                registered_at = None
                if device_id and fleet is not None:
                    try:
                        registered_at = int(
                            (fleet.get_device(device_id) or {}).get(
                                "registered_at") or 0) or None
                    except (TypeError, ValueError):
                        registered_at = None
                self._json(200, {"logs": _list_deploy_logs(
                    log_dir, device_id=device_id,
                    after_ts=_ts("after_ts"), before_ts=_ts("before_ts"),
                    registered_at=registered_at)})
                return
            if path == "/api/deploy-logs/histogram":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                qs = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                device_id = (qs.get("device_id") or [None])[0]
                try:
                    buckets = int((qs.get("buckets") or [30])[0])
                except ValueError:
                    buckets = 30
                buckets = max(1, min(buckets, 200))
                now = time.time()
                since = until = None
                for name in ("since_ts", "until_ts"):
                    if qs.get(name):
                        try:
                            val = float(qs[name][0])
                        except ValueError:
                            val = None
                        if name == "since_ts":
                            since = val
                        else:
                            until = val
                if since is not None and until is not None:
                    if until <= since:
                        self._json(400, {"error": "until_ts must be greater "
                                                  "than since_ts"}); return
                else:
                    try:
                        window = float((qs.get("window") or [604800])[0])
                    except ValueError:
                        window = 604800.0
                    window = max(60.0, window)
                    since, until = now - window, now
                log_dir = getattr(onboard, "log_dir", None) if onboard else None
                self._json(200, {"buckets": _deploy_log_histogram(
                    log_dir, since, until, buckets, device_id=device_id),
                    "now": int(now)})
                return
            if path.startswith("/api/deploy-logs/"):
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                log_dir = getattr(onboard, "log_dir", None) if onboard else None
                data = _read_deploy_log(
                    log_dir, unquote(path[len("/api/deploy-logs/"):]))
                if data is None:
                    self._json(404, {"error": "not found"}); return
                self._send(200, "text/plain; charset=utf-8", data); return
            if path == "/api/overview":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                self._json(200, self._overview()); return
            if path == "/api/swarm":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                qs = parse_qs(self.path.split("?", 1)[1] if "?" in self.path else "")
                try:
                    limit, offset = _page_params(qs)
                except ValueError as exc:
                    self._json(400, {"error": str(exc)}); return
                try:
                    body = (swarm_fetch or _default_swarm_fetch)()
                    if limit is None and not offset:
                        # Unpaged: byte-for-byte passthrough of the hub's own
                        # JSON, exactly as before — the swarm map filters and
                        # sorts the whole participant set client-side.
                        self._send(200, "application/json", body)
                    else:
                        self._json(200, _swarm_page(body, limit, offset))
                except Exception:
                    self._json(200, {"peers": [], "error": "swarm data unavailable"})
                return
            if path == "/api/telemetry/health":
                # Fetch detailed status through the management-authenticated
                # telemetry route. Anonymous /healthz stays deliberately
                # minimal and cannot reveal exporter state or topology.
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                try:
                    token, _ = tier_auth.load_pair(
                        os.environ.get("IRIS_MANAGEMENT_API_TOKEN_FILE", ""))
                    body = telemetry.local_swarm_get(
                        "https://127.0.0.1:%s/status"
                        % os.environ.get("IRIS_METRICS_PORT", "9101"),
                        token.decode("utf-8"), timeout=3,
                        expected_path="/status")
                    self._send(200, "application/json", body)
                except Exception:
                    self._json(200, {"ok": False, "error": "unavailable"})
                return
            if path == "/swarmmap":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                self._serve_swarmmap(); return
            if path.startswith("/api/settings/ca-trust/refresh/"):
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                job = get_ca_job(
                    path[len("/api/settings/ca-trust/refresh/"):])
                self._json(200, job) if job else self._json(
                    404, {"error": "no such job"})
                return
            if path.startswith("/api/settings/audit-export/run/"):
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                job = audit_export.get_job(
                    path[len("/api/settings/audit-export/run/"):])
                self._json(200, job) if job else self._json(
                    404, {"error": "no such job"})
                return
            if path == "/api/settings/setup-status":
                info = app.session_info(self._sid())
                if info is None:
                    self._json(401, {"error": "unauthorized"}); return
                artifacts_dir = os.environ.get(
                    "IRIS_ARTIFACTS_DIR", "/srv/artifacts")
                self._json(200, setup_status.build_status(
                    artifacts_dir,
                    os.environ.get("IRIS_CERT", _IRIS_CERT_DEFAULT),
                    os.path.join(artifacts_dir, "iris-catalog.pem"),
                    info["username"],
                    *_telemetry_status_args(),
                    image_verification_last_run=_image_verification_last_run(),
                    provision_status_path=os.path.join(
                        os.environ.get("IRIS_RUN", "/run/iris"), "served-bundle.json"),
                    provision_startup_state=os.environ.get(
                        "_IRIS_SERVED_BUNDLE_STARTUP")))
                return
            if path == "/api/settings/image-verification":
                # KGV reconciler Task 4: schedule config + last_run, its own
                # dedicated GET (unlike audit-export/ca-trust, which are read
                # only via the big /api/settings blob above) -- the brief
                # calls for GET+POST at this exact path.
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
                self._json(200, bulkhash_refresh.read_settings(
                    bulkhash_refresh.settings_path(state_dir)))
                return
            if path == "/api/settings":
                info = app.session_info(self._sid())
                if info is None:
                    self._json(401, {"error": "unauthorized"}); return
                self._json(200, self._settings_info(info["username"])); return
            if path == "/api/help":
                # "?" popover data: version + stable deployment id + doc links.
                # state_dir is read per-request (the /api/settings idiom) so
                # tests can point IRIS_STATE at a tmp dir.
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
                self._json(200, {
                    "version": _read_version(),
                    "deployment_id": read_instance_id(state_dir),
                    "docs_url": _DOCS_URL,
                    "guides": {"device": "/help-device.html",
                               "server": "/help-server.html"},
                })
                return
            if path in ("/", "/index.html") and app.needs_setup():
                # First-run: land on the login page, where the built-in pair
                # mints the one-use grant. setup.html
                # itself stays a plain static page; visiting it grantless just
                # bounces back to login client-side.
                self._serve_static("/login.html"); return
            self._serve_static(path)

        def _device_view(self):
            """The WHOLE merged fleet, in store order — what /api/overview's
            aggregates and the unpaginated /api/devices are defined by."""
            return self._device_page()[0]

        def _device_page(self, limit=None, offset=0, q=None, filters=None):
            """(rows, total, revision, target_facts) for the device projection.

            *limit*/*offset* page it; *q* and *filters* (see _row_matches_q
            and _row_matches_extra_filters -- the nine column filters the
            issue #112 prerequisite requires parity for) narrow it. With
            everything at its default this is the full fleet in store order,
            exactly what the console has always received.

            The page and the revision stamping it come from ONE fleet read
            (FleetStore.snapshot), so a client walking pages can tell a
            coherent walk from one that raced a fleet edit by comparing the
            revision it gets back — the pages themselves carry no cursor,
            and the actions built on them are keyed by device_id, never by
            row position.

            Paging sorts by device_id first: store order is insertion order,
            which is stable to read but says nothing an operator could use to
            reason about "the next 200". Sorting is deliberately NOT applied
            to the unpaginated call, whose order is long-established.
            """
            filters = filters or {}
            revision, devs = fleet.snapshot() if fleet else (0, [])
            active_filter = q is not None or bool(filters)
            paging = limit is not None or offset or active_filter
            if paging:
                devs.sort(key=lambda d: str(d.get("device_id") or ""))
            heartbeat_rows = instruction_heartbeat_snapshot(unavailable_ok=False)
            heartbeat_available = isinstance(heartbeat_rows, list)
            hb = {d.get("device_id"): d for d in (heartbeat_rows or [])
                  if isinstance(d, dict) and isinstance(d.get("device_id"), str)}
            # each device's latest onboard/undeploy job, so the UI can show
            # "onboarding…" / "waiting for heartbeat" instead of a misleading
            # "not enrolled" before the fresh agent's first heartbeat lands
            jobs = onboard.latest_jobs_by_device() if onboard else {}
            # one policy.json read for the whole table — get_policy() re-parses
            # the file per call, which multiplies badly on the polled endpoints
            # Keep the established strict policy projection for assignments.
            # Raw policy rows exist only for policy_view's stamp aggregate.
            policies = catalog.list_policies() if catalog else {}
            revoked_principals = instruction_revocation_snapshot()
            observed_at = now_fn()
            deployment_types = deployment_type_snapshot()
            role_policy = role_policy_snapshot()
            role_report = role_management.drift_report(
                fleet, role_policy,
                limit=len(devs) + len(role_policy.roles.role_of), rows=devs)
            role_drift_ids = frozenset(role_report["device_ids"])

            def merge(device):
                return self._merge_device_row(
                    device, policies, hb, jobs, observed_at,
                    heartbeat_available, revoked_principals,
                    deployment_types.get(device.get("device_id"), {}))

            def role_drift(row):
                return row.get("device_id") in role_drift_ids

            def matches_without_os(row):
                if q is not None and not self._row_matches_q(row, q):
                    return False
                other_filters = {key: value for key, value in filters.items()
                                 if key != "os_family"}
                return (not other_filters or self._row_matches_extra_filters(
                    row, other_filters, observed_at, quarantined_ids))

            if not active_filter:
                # Nothing to count that the inventory does not already know,
                # so merge ONLY the rows this page returns: at fleet scale
                # the merge and the JSON encoding of the rows nobody asked
                # for are most of what the response costs.
                total = len(devs)
                window = devs[offset:] if limit is None else \
                    devs[offset:offset + limit]
                rows = [merge(d) for d in window]
                # These facts describe the whole match set, never just the
                # requested page. They need only trusted fleet/record fields,
                # so the fast path still avoids merging heartbeat and catalog
                # state for rows it will not render.
                fact_rows = []
                for device in devs:
                    resolved = deployment_types.get(device.get("device_id"), {})
                    fact_row = dict(device)
                    fact_row.update(trusted_target_projection(device, resolved))
                    fact_rows.append(fact_row)
                facts = {
                    "missing_os_family": sum(
                        not row.get("os_family") for row in fact_rows),
                    "role_drift": sum(role_drift(row) for row in fact_rows),
                }
                return rows, total, revision, facts

            # A filter reaches merged fields (heartbeat_model, status), so
            # every row is merged to be counted; only the window is
            # retained. Peer and role-drift facts come from the same policy
            # snapshot, so one preview cannot mix policy revisions.
            quarantined_ids = (peer_policy.quarantine_device_ids(
                                   role_policy.document)
                               if "peer" in filters else None)
            now = observed_at
            rows, total = [], 0
            missing_os_family = 0
            drift = 0
            for d in devs:
                row = merge(d)
                if not row.get("os_family") and matches_without_os(row):
                    missing_os_family += 1
                if q is not None and not self._row_matches_q(row, q):
                    continue
                if filters and not self._row_matches_extra_filters(
                        row, filters, now, quarantined_ids):
                    continue
                if role_drift(row):
                    drift += 1
                total += 1
                if total > offset and (limit is None or len(rows) < limit):
                    rows.append(row)
            return rows, total, revision, {
                "missing_os_family": missing_os_family,
                "role_drift": drift,
            }

        @staticmethod
        def _row_matches_q(row, q):
            """Case-insensitive substring over the same four fields the
            console's own search box covers (app.js deviceMatchesFilters), so
            a server-side filter and the client-side one cannot disagree
            about what "matches" means."""
            hay = " ".join(str(row.get(k) or "") for k in
                           ("device_id", "device_ip", "model",
                            "heartbeat_model")).lower()
            return q in hay

        def _row_matches_extra_filters(self, row, filters, now, quarantined_ids):
            """Server-side mirror of app.js deviceMatchesFilters (everything
            besides q, which _row_matches_q already covers) -- kept
            condition-for-condition in step with it so a paged, filtered
            table can never disagree with what the filter bar promises
            (issue #112 prerequisite 1). quarantined_ids is the peer-policy
            quarantine-assignment set, or None when the peer filter is not
            in play (it is never consulted in that case)."""
            return target_row_matches(
                row, filters, now=now, quarantined_ids=quarantined_ids,
                status_key_fn=self._device_status_key,
                status_level_fn=self._device_status_level,
                offline_fn=self._device_is_offline)

        def _device_status_key(self, row):
            """Server-side mirror of app.js deviceStatus()'s KEY derivation,
            order and conditions copied verbatim -- the human label/detail/
            css class stay a pure rendering concern the console still owns
            alone; only the KEY, which the status filter and the
            __attention rollup need to test against, is duplicated here."""
            onboard_finished_at = row.get("onboard_finished_at")
            last_seen = row.get("last_seen")
            job_fresh = bool(onboard_finished_at) and (
                not last_seen or last_seen < onboard_finished_at)
            onboard_state = row.get("onboard_state")
            onboard_action = row.get("onboard_action")
            if onboard_state in ("queued", "running"):
                return "undeploying" if onboard_action == "undeploy" else "onboarding"
            if onboard_state == "done" and onboard_action == "onboard" and job_fresh:
                return "waiting-heartbeat"
            if onboard_state == "error" and job_fresh:
                return ("undeploy-failed" if onboard_action == "undeploy"
                        else "onboard-failed")
            assigned_ids = self._row_assigned_ids(row)
            errored_ids = [iid for iid in (row.get("errored_image_ids") or [])
                          if iid in assigned_ids]
            if (assigned_ids and not errored_ids and
                    all(self._row_has_staged(row, iid) for iid in assigned_ids)):
                return "deployed"
            if errored_ids:
                return "image-failed"
            if (row.get("stage_error")
                    or row.get("stage_state") in ("error", "copy_failed")):
                return "placement-failed"
            if row.get("stage_state") == "transferring_to_ios":
                return "copying"
            if row.get("stage_state") in ("unassigned", "ready"):
                return "waiting-staging" if assigned_ids else "unassigned"
            if row.get("stage_state"):
                return "staging"
            if last_seen and not assigned_ids:
                return "unassigned"
            if last_seen:
                return "enrolled"
            return "not-enrolled"

        @staticmethod
        def _device_status_level(row, key):
            """The Magnetic status LEVEL for a status key -- mirrors app.js
            statusDisplay()'s severity override for image-failed (ratio of
            errored to assigned images, >=0.5 is 'severe' else 'warning')
            and falls back to _STATUS_LEVELS otherwise."""
            if key == "image-failed":
                assigned = Handler._row_assigned_ids(row)
                errored = [iid for iid in (row.get("errored_image_ids") or [])
                          if iid in assigned]
                ratio = (len(errored) / len(assigned)) if assigned else 0
                return "severe" if ratio >= 0.5 else "warning"
            return _STATUS_LEVELS.get(key, "inactive")

        @staticmethod
        def _device_is_offline(row, now):
            """Mirrors app.js deviceIsOffline: a device with a heartbeat that
            is 10+ minutes stale by the SAME server clock every response
            already carries (row's own last_seen against *now*)."""
            return bool(row.get("last_seen")) and (now - row["last_seen"]) >= 600

        @staticmethod
        def _merge_device_row(d, policies, hb, jobs, observed_at,
                              heartbeat_available, revoked_principals,
                              deployment_type=None):
            """One inventory record joined with policy, heartbeat and job."""
            did = d.get("device_id")
            pol = policies.get(did, {})
            h = hb.get(did, {})
            row = dict(d)
            row.update(trusted_target_projection(d, deployment_type))
            # The installs this row can take, from the same rules the fleet
            # store enforces, so the Console offers only those instead of a
            # choice the server refuses and the table then snaps back from.
            row["install_options"] = gui_fleet.install_options_for_record(d)
            row["assigned_image_id"] = pol.get("approved_image_id")
            row["assigned_image_ids"] = pol.get("approved_image_ids")
            row["last_seen"] = h.get("last_seen")
            row["stage_state"] = h.get("stage_state")
            row["stage_error"] = h.get("stage_error")
            row["current_image_id"] = h.get("current_image_id")
            # the ordered set of images the agent reports as staged
            # (Task 3); absent from an agent that predates the field, in
            # which case rollout falls back to current_image_id/stage_state
            row["staged_image_ids"] = h.get("staged_image_ids")
            # which assigned images hit a terminal per-image failure on
            # the agent's last tick; absent from an agent that predates
            # the field, in which case staging falls back to guessing
            # from the single aggregate stage_state (_row_is_staging)
            row["errored_image_ids"] = h.get("errored_image_ids")
            row["heartbeat_model"] = h.get("model")
            # the "copying to <fs>" badge needs the heartbeat's target FS
            row["target_fs"] = h.get("target_fs")
            # telemetry posture as the DEVICE reports it, not as the last
            # onboard requested: True/False from the agent, None when the
            # agent predates the flag (tri-state — unknown is not "off").
            row["telemetry_enabled"] = h.get("telemetry_enabled")
            row["telemetry_stream_enabled"] = h.get(
                "telemetry_stream_enabled")
            revocation_available = isinstance(
                revoked_principals, (set, frozenset))
            revoked = ("device:%s" % did in revoked_principals
                       if revocation_available and isinstance(did, str)
                       else None)
            row["instruction"] = _instruction_device_projection(
                h, revoked, observed_at,
                heartbeat_available=heartbeat_available)
            j = jobs.get(did)
            if j:
                row["onboard_action"] = j["action"]
                row["onboard_state"] = j["state"]
                row["onboard_finished_at"] = j["finished_at"]
            return row

        @staticmethod
        def _audit_image_names(cat, ids):
            """Audit-facing names for a list of image ids: the catalog
            filename when the catalog still has the image, else the bare id.
            A policy row can outlive its images, and an audit entry that
            silently drops the ids it could not resolve would understate what
            was removed -- the one thing this text exists to record."""
            out = []
            for iid in ids:
                entry = cat.get_image(iid) if cat else None
                out.append((entry or {}).get("filename") or iid)
            return ", ".join(out)

        @staticmethod
        def _awaiting_heartbeat(row):
            """True when the device finished an ONBOARD but no heartbeat has
            arrived since — the agent is still bootstrapping on-box."""
            return (row.get("onboard_action") == "onboard"
                    and row.get("onboard_state") == "done"
                    and (row.get("last_seen") is None
                         or row["last_seen"] < (row.get("onboard_finished_at") or 0)))

        @staticmethod
        def _row_assigned_ids(row):
            """The device's approved image ids. assigned_image_ids is None
            for a policy row that predates the ordered set, so fall back to
            the singular field it still carries."""
            ids = row.get("assigned_image_ids")
            if ids:
                return ids
            single = row.get("assigned_image_id")
            return [single] if single else []

        @staticmethod
        def _row_has_staged(row, iid):
            """Whether *row*'s device has staged image *iid*: the heartbeat's
            staged_image_ids set when the agent reports it directly (Task 3),
            else the legacy current_image_id/stage_state pair."""
            if iid in (row.get("errored_image_ids") or ()):
                return False
            sids = row.get("staged_image_ids")
            if sids is not None:
                return iid in sids
            return (row.get("stage_state") == "ready"
                    and row.get("current_image_id") == iid)

        def _row_is_staging(self, row):
            """Whether *row* is actively staging, given its last (fresh)
            heartbeat.

            Task 3's set heartbeat (_send_set_heartbeat) reports the single
            MOST ACTIONABLE stage_state across every image in the tick, so a
            bare stage_state can no longer tell "one image failed, another is
            still downloading" from "every assigned image is stuck" -- both
            collapse to the same "error". Which tier below applies depends on
            what the agent's last heartbeat was actually able to report:

            1. staged_image_ids ABSENT: a legacy single-image agent, which
               only ever stages the first (and only) approved image --
               singular semantics are correct here regardless of how many
               images the POLICY assigns, since a legacy agent ignores the
               rest. This is the pre-multi-image check, verbatim -- and, as a
               side effect, it fixes a legacy-agent overcount: a
               permanently-errored single-image device whose POLICY still
               named several images used to read as staging forever, because
               the multi-image math below ran on the policy's id count
               instead of stopping at what this agent can even attempt.

            2. staged_image_ids present, errored_image_ids ABSENT: this
               branch's multi-image agent BEFORE errored_image_ids existed.
               No fleet has ever run it, so this tier only covers the brief
               in-branch window before every agent picks up the field --
               kept exactly as it was: a set pinned to a collapsed "error" is
               called wholly failed only once at most one assigned image is
               still unstaged (with more than one outstanding, one of them
               could be the one actually still in flight -- an honest guess,
               not a derivation).

            3. Both present: no guessing needed. staged_image_ids marks what
               finished; errored_image_ids marks what is stuck THIS tick; an
               assigned image in neither is genuinely still in flight, so the
               set is staging iff at least one such image exists."""
            state = row.get("stage_state")
            # A policy update can add images before the next heartbeat. The
            # difference between assignment and the last staged set is only
            # outstanding work; a ready/idle heartbeat is not active staging.
            if state in (None, "", "unassigned", "ready"):
                return False
            sids = row.get("staged_image_ids")
            if sids is None:
                # Tier 1: legacy single-image agent.
                return state not in ("error", "copy_failed")
            eids = row.get("errored_image_ids")
            if eids is None:
                # Tier 2: multi-image agent that predates errored_image_ids.
                if state not in ("error", "copy_failed"):
                    return True
                ids = self._row_assigned_ids(row)
                if len(ids) <= 1:
                    return False
                staged = [iid for iid in ids if self._row_has_staged(row, iid)]
                return (len(ids) - len(staged)) > 1
            # Tier 3: precise -- derived from this tick's own verdicts.
            ids = self._row_assigned_ids(row)
            if not ids:
                return False
            # errored_image_ids carries the retryable failures too, so a set
            # entirely blocked on space is fully "accounted for" while the
            # agent is in fact still working it -- the one failure both tiers
            # above deliberately count. Reading the list alone dropped exactly
            # those devices out of staging_now the moment their agent grew the
            # field, so an operator freeing room saw nothing happening.
            if row.get("stage_state") in _RETRYABLE_STAGE_STATES:
                return True
            staged, errored = set(sids), set(eids)
            return any(iid not in staged and iid not in errored for iid in ids)

        def _overview(self):
            imgs = catalog.list_images() if catalog else []
            # the merged device rows already carry policy + heartbeat, so one
            # _device_view() pass feeds rollout, totals, and the awaiting count
            # without re-reading the fleet/policy/heartbeat stores here
            rows = self._device_view()
            rollout = []
            for img in imgs:
                iid = img.get("id")
                # a device counts under EVERY image in its approved set, not
                # just a single "the" assignment
                assigned = [r for r in rows if iid in self._row_assigned_ids(r)]
                staged = [r for r in assigned if self._row_has_staged(r, iid)]
                rollout.append({"image_id": iid, "filename": img.get("filename"),
                                "assigned": len(assigned), "staged": len(staged)})
            # The aggregate cards are about DEVICES, not (image, device)
            # pairs -- app.js renders "Staged" as a device count. Summing the
            # per-image rollout rows double-counts a device across every
            # image it's assigned, so tally devices directly here instead: a
            # device counts once in assigned_total if its set is non-empty,
            # and once in staged_total only if EVERY image in that set is
            # staged (the per-image rollout rows above stay per-pair, which
            # is what the rollout table is specced to show).
            assigned_total = 0
            staged_total = 0
            for r in rows:
                ids = self._row_assigned_ids(r)
                if not ids:
                    continue
                assigned_total += 1
                if all(self._row_has_staged(r, iid) for iid in ids):
                    staged_total += 1
            # "Staging" must mean devices ACTUALLY staging: enrolled (their
            # agent heartbeats), FRESH (last_seen inside the same 600s the
            # UI uses for its "offline" badge — a device that died mid-stage
            # is offline, not staging), and reporting a non-terminal
            # stage_state. The old assigned-minus-staged arithmetic counted
            # inventory rows that never heartbeated, so an idle install with
            # 6 fleet rows read "6 staging". ready (seeding) and unassigned
            # agents are not staging either — ready feeds the staged count
            # above — and error is terminal (flash_full etc. still count:
            # the agent is alive and retrying).
            now = now_fn()
            staging_now = sum(
                1 for row in rows
                if row.get("last_seen") is not None
                and (now - row["last_seen"]) < _HEARTBEAT_FRESH
                and self._row_is_staging(row))
            # devices freshly onboarded whose agent hasn't heartbeated yet —
            # surfaced so an operator doesn't read the gap as "undeployed"
            awaiting = sum(1 for row in rows
                           if self._awaiting_heartbeat(row))
            return {
                "images": len(imgs), "devices": len(rows),
                "assigned": assigned_total, "staged": staged_total,
                "staging_now": staging_now,
                "awaiting_heartbeat": awaiting,
                "rollout": rollout,
                # console-relative: the map lives on this server now (session-
                # gated /swarmmap), not on the unauthenticated :9101 tracker
                "swarm_map_url": "/swarmmap",
            }

        def _settings_info(self, admin_username):
            host_ip = os.environ.get("IRIS_HOST_IP", "")
            obs = bool(os.environ.get("IRIS_OBSERVABILITY"))
            # The Console can have its own host and browser-facing port.
            raw = os.environ.get("IRIS_GUI_PUBLISH", "").strip()
            console_port = int(raw) if raw.isdigit() else 8080
            console_url = "https://%s:%d" % (host_ip, console_port) if host_ip else ""
            configured_url = os.environ.get("IRIS_CONSOLE_URL", "").strip()
            if configured_url:
                try:
                    parsed = urlsplit(configured_url)
                    if (parsed.scheme == "https" and parsed.hostname and
                            not parsed.username and not parsed.password and
                            not parsed.query and not parsed.fragment and
                            parsed.path in ("", "/")):
                        console_port = parsed.port or 443
                        console_url = configured_url.rstrip("/")
                except ValueError:
                    pass
            state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
            dest = telemetry_destination.read(
                telemetry_destination.settings_path(state_dir))
            env_endpoint = os.environ.get("IRIS_OTLP_ENDPOINT", "").strip()
            env_enabled = telemetry.observability_enabled()
            override = (dest["endpoint"] is not None
                        or dest["enabled"] is not None)
            return {
                "admin_username": admin_username,
                "version": _read_version(),
                "host_ip": host_ip,
                "console_url": console_url,
                "ports": {"tracker": 6969, "catalog": 8443, "artifacts": 8000,
                          "swarm": 9101, "console": console_port},
                "observability": {
                    "enabled": obs,
                    "metrics_url": ("https://%s:9101/metrics" % host_ip
                                    if obs and host_ip else ""),
                },
                "sessions": {"active": app.active_sessions(),
                             "idle_ttl_minutes": app.idle_ttl_minutes()},
                # settings file verbatim (it holds no secret) + password_set —
                # the SCP password itself never leaves the encrypted store
                "audit_export": dict(
                    audit_export.read_settings(
                        audit_export.settings_path(state_dir)),
                    password_set=(creds.audit_export_secrets() is not None
                                  if creds is not None else False)),
                # console cert metadata only — key material is never echoed
                "gui_cert": gui_tls.active_info(),
                # installed root CAs: name/subject/expiry/fingerprint/source
                "trust": trust.list_entries(),
                "ca_trust": read_ca_trust_settings(ca_trust_settings_path(
                    state_dir)),
                "telemetry_destination": {
                    "endpoint": dest["endpoint"],
                    "enabled": dest["enabled"],
                    "source": "override" if override else "env",
                    # effective = file-if-not-null else env, PER FIELD —
                    # exactly the hub's rule, so this view never lies
                    "effective_endpoint": (dest["endpoint"]
                                           if dest["endpoint"] is not None
                                           else env_endpoint),
                    "effective_enabled": (dest["enabled"]
                                          if dest["enabled"] is not None
                                          else env_enabled),
                },
            }

        def _sse_onboard(self, onboard, job_id):
            """Stream an onboard job's lines as Server-Sent Events until it is
            terminal. The _SSE_IDLE cap is an IDLE timeout, not a lifetime cap:
            it resets on new output and while the job is still queued for a
            pool slot, so watching a deep-queued job works — only a truly
            stalled running install closes the stream. Keepalive comment
            frames stop proxies reaping the quiet wait. GET-only
            (session-gated, no CSRF)."""
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "private, no-store")
            for k, v in _SECURITY_HEADERS:
                self.send_header(k, v)
            self.end_headers()
            cursor = 0
            last_state = None
            idle_deadline = time.time() + _SSE_IDLE
            next_beat = time.time() + _SSE_KEEPALIVE
            try:
                while time.time() < idle_deadline:
                    job = onboard.get_job(job_id) if onboard else None
                    if job is None:
                        self.wfile.write(b"event: end\ndata: unknown\n\n")
                        self.wfile.flush(); return
                    lines = job["lines"]
                    progressed = cursor < len(lines)
                    while cursor < len(lines):
                        # Collapse any embedded CR/LF so a line can never forge an
                        # extra SSE event (defense-in-depth vs an injected run_fn).
                        safe = lines[cursor].replace("\r", " ").replace("\n", " ")
                        self.wfile.write(("data: %s\n\n" % safe).encode("utf-8"))
                        cursor += 1
                    # A state change (queued -> running) is progress too:
                    # without this the poll that sees the transition, before
                    # the first line lands, spends idle budget on it.
                    state = job["state"]
                    if progressed or state == "queued" or state != last_state:
                        idle_deadline = time.time() + _SSE_IDLE
                    last_state = state
                    if time.time() >= next_beat:
                        self.wfile.write(b": keepalive\n\n")
                        next_beat = time.time() + _SSE_KEEPALIVE
                    self.wfile.flush()
                    if job["state"] in ("done", "error", "cancelled"):
                        self.wfile.write(
                            ("event: end\ndata: %s\n\n" % job["state"]).encode("utf-8"))
                        self.wfile.flush(); return
                    time.sleep(0.5)
                # Idle expiry gets a terminal frame too, so the client can
                # tell a stalled job from a dead server.
                self.wfile.write(b"event: end\ndata: idle\n\n")
                self.wfile.flush()
            except OSError:      # BrokenPipe/ConnectionReset and ssl-layer errors alike
                return

        def _handle_offline_refresh(self, length):
            """POST /api/image-verification/offline (KGV reconciler Task 4):
            a size-capped tar upload, streamed straight to a private temp
            file in bounded chunks (the image-upload PUT route's
            _body_reader idiom -- never held whole in memory, even though
            _MAX_OFFLINE_TAR allows tens of MB), then run through the exact
            same fetch-less pipeline a scheduled/manual run uses
            (bulkhash_refresh.run_refresh with tar_path=..., source=
            "offline"). Session+CSRF gated like every other state-changing
            route, and the session/size checks happen before this ever
            touches the socket body, so an unauthenticated or oversized
            request never makes this server buffer or write anything.
            run_refresh calls its audit_fn with the event fully formed as
            keywords (including actor="system", the source-agnostic
            default) -- relayed verbatim below but with actor overridden to
            the console session that uploaded THIS tar, the same pattern
            /api/settings/audit-export/run and /api/settings/ca-trust/
            refresh use for their own completion audit."""
            info = self._require_session_csrf()
            if info is None:
                return
            actor = "console:" + info["username"]
            if catalog is None:
                self._json(404, {"error": "not found"}); return
            if length <= 0 or length > _MAX_OFFLINE_TAR:
                # rejected before ever touching the socket body -- audited
                # the same way the PUT image-upload route audits its own
                # oversize rejection, so a hostile/mistaken huge upload
                # attempt still leaves a trail even though it never reaches
                # run_refresh's own audit_fn call.
                self._audit("bulkhash-offline-upload", "settings",
                           action="upload", target="bulkhash", actor=actor,
                           result="fail",
                           detail="rejected: %s" % (
                               "empty body" if length <= 0
                               else "oversized (cap 256 MiB)"))
                self._json(413, {"error": "missing or oversized body"}); return
            state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
            reader = self._body_reader(length)
            tmp_dir = tempfile.mkdtemp(prefix="bulkhash-offline-")
            try:
                tmp_path = os.path.join(tmp_dir, "offline-feed.tar")
                total = 0
                try:
                    with open(tmp_path, "wb") as f:
                        while True:
                            chunk = reader()
                            if not chunk:
                                break
                            total += len(chunk)
                            f.write(chunk)
                except (TimeoutError, ConnectionError):
                    self._json(408, {"error":
                               "upload timed out or connection dropped"})
                    return
                if total != length:
                    self._json(408, {"error":
                               "upload timed out or connection dropped"})
                    return
                result = bulkhash_refresh.run_refresh(
                    "offline", state_dir, catalog, tar_path=tmp_path,
                    audit_fn=lambda **kw: self._audit(
                        **dict(kw, actor=actor)))
                status = _refresh_http_status(result)
                # Remove the temp dir BEFORE responding, not after: a test
                # (or any other caller) that reads this response and
                # immediately asserts the temp dir is gone must never race
                # the client's own read against this cleanup -- the finally
                # below is a best-effort backstop for the early-return paths
                # above, not the primary cleanup for the success path.
                shutil.rmtree(tmp_dir, ignore_errors=True)
                self._json(status, result)
            finally:
                shutil.rmtree(tmp_dir, ignore_errors=True)

        def _policy_problem(self, status, code, revision=None, **details):
            self._finish_idempotency(None)
            for key in ("code", "type", "title", "status", "error"):
                details.pop(key, None)
            headers = list(getattr(self, "_response_headers", ()))
            if revision is not None:
                headers.append(("ETag", _revision_etag("peer-policy", revision)))
                details["revision"] = revision
            api_problem.send(self, status, code, code.replace("_", " ").capitalize(),
                             headers=headers, error=code, **details)

        def _policy_failure(self, exc, actor=None, dry_run=False):
            auth_path, lkg_path, _ = policy_paths()
            current = peer_policy.load_policy(auth_path, lkg_path)
            revision = current.document["revision"]
            details = {}
            if isinstance(exc, role_management.RoleManagementError):
                code, status, details = exc.code, exc.status, dict(exc.result)
                revision = details.pop("revision", revision)
            elif isinstance(exc, peer_policy.RevisionConflict):
                code, status, revision = "revision_conflict", 409, exc.revision
            elif isinstance(exc, peer_policy.OperationBacklogFull):
                code, status = "operation_backlog_full", 409
            elif isinstance(exc, peer_policy.PolicyError):
                code, status, details = exc.code, 422, dict(exc.details)
            else:
                code, status = "policy_unavailable", 503
            if code in ("role_in_use", "role_isolated", "role_reserved_name",
                        "role_shadowed_by_assignment", "operation_backlog_full"):
                status = 409
            elif code in ("role_not_found", "unknown_role", "device_not_found"):
                status = 404
            elif code == "confirmation_required":
                status = 428
            elif code in ("policy_fail_closed", "policy_write_failed", "policy_error") or \
                    isinstance(exc, peer_policy.PolicyDegradedError) or \
                    current.degraded or current.fail_closed:
                code, status = "policy_unavailable", 503
            elif status == 400:
                status = 422
            if code == "operation_backlog_full":
                details.update(policy_view()["outbox"])
            if actor is not None and not dry_run:
                path = urlsplit(self.path).path
                if path == "/api/devices/bulk-role":
                    event, target = "device_role_bulk_change", "roles"
                elif path.startswith("/api/devices/") and path.endswith("/role"):
                    event = "device_role_change"
                    target = unquote(path[len("/api/devices/"):-len("/role")])
                else:
                    event, target = "peer_policy_change", path.rsplit("/", 1)[-1]
                self._audit(event, "device", action="role", target=target,
                            actor=actor, result="fail", detail=code)
            self._policy_problem(status, code, revision, **details)

        def _policy_mutation(self, path, actor, raw=None):
            """All new policy writes share strong CAS and bounded JSON parsing."""
            auth_path, lkg_path, _ = policy_paths()
            loaded = peer_policy.load_policy(auth_path, lkg_path)
            revision = loaded.document["revision"]
            match = self.headers.get_all("If-Match", [])
            if not match:
                self._policy_problem(428, "precondition_required", revision)
                return
            if match != [_revision_etag("peer-policy", revision)]:
                self._policy_problem(412, "precondition_failed", revision)
                return
            if loaded.degraded or loaded.fail_closed:
                self._policy_problem(503, "policy_unavailable", revision)
                return
            dry_run = False
            try:
                qs = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
                if set(qs) - {"dry_run"} or qs.get("dry_run", ["0"]) not in (["0"], ["1"]):
                    raise peer_policy.PolicyError("bad query", code="invalid_policy_request")
                dry_run = qs.get("dry_run") == ["1"]
                if raw is None:
                    length = int(self.headers.get("Content-Length", "0") or 0)
                    if length < 0 or length > _MAX_BODY:
                        self._policy_problem(413, "payload-too-large", revision)
                        return
                    raw = self.rfile.read(length) if length else b""
                body = json.loads(raw) if raw else {}
                if not isinstance(body, dict):
                    raise ValueError("object required")
                token = body.get("confirm_token")
                if token is not None and not isinstance(token, str):
                    raise ValueError("bad token")
                preview = {}
                def precommit(prior, candidate):
                    blast = peer_policy.blast_radius(
                        prior, candidate, peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD)
                    preview.update(role_management.RoleCoordinator._blast_details(blast))
                    if not dry_run and not peer_policy.confirm_blast_radius(
                            prior, candidate, peer_policy.BLAST_RADIUS_CONFIRM_THRESHOLD, token):
                        raise peer_policy.PolicyError("confirmation required",
                            code="confirmation_required", **preview)
                options = dict(expected_revision=revision, dry_run=dry_run,
                               precommit=precommit)
                coordinator = role_coordinator()
                if path.startswith("/api/peer-policy/roles/"):
                    name = unquote(path[len("/api/peer-policy/roles/"):])
                    if self.command == "DELETE":
                        if set(body) - {"confirm_token"}:
                            raise ValueError("bad delete fields")
                        committed = coordinator.delete_role(name, actor, **options)
                    else:
                        definition = {key: value for key, value in body.items()
                                      if key != "confirm_token"}
                        committed = coordinator.define_role(name, definition, actor, **options)
                elif path == "/api/peer-policy/qos":
                    if set(body) - {"qos", "qos_state", "role", "confirm_token"} or \
                            not ({"qos", "qos_state"} & set(body)):
                        raise ValueError("bad qos fields")
                    role = body.get("role")
                    if role is not None:
                        peer_policy.validate_role_name(role)
                    qos = body.get("qos")
                    if "qos" in body and not isinstance(qos, dict):
                        raise peer_policy.PolicyError("bad qos")
                    qos_options = dict(options, role=role)
                    if "qos_state" in body:
                        if not isinstance(body["qos_state"], dict):
                            raise peer_policy.PolicyError("bad qos state")
                        qos_options["qos_state"] = body["qos_state"]
                    committed = coordinator.set_qos(qos, actor, **qos_options)
                else:
                    bulk = path == "/api/devices/bulk-role"
                    if set(body) - ({"device_ids", "role", "confirm_token"} if bulk
                                   else {"role", "confirm_token"}) or "role" not in body:
                        raise ValueError("bad role fields")
                    ids = body.get("device_ids") if bulk else [unquote(
                        path[len("/api/devices/"):-len("/role")])]
                    if not isinstance(ids, list) or not ids or \
                            len(ids) > peer_endpoints.SUPPORTED_DEVICES or not all(
                                isinstance(did, str) and did and did == did.strip()
                                and "/" not in did for did in ids):
                        raise ValueError("bad device ids")
                    role_options = dict(expected_revision=revision, dry_run=dry_run,
                                        require_confirmation=True, confirm_token=token)
                    if bulk:
                        result = coordinator.set_roles(
                            {did: body["role"] for did in sorted(set(ids))},
                            actor=actor, **role_options)
                    else:
                        result = coordinator.set_role(ids[0], body["role"], actor=actor,
                                                      **role_options)
                    result_revision = result.get("candidate_revision", result["revision"]) \
                        if dry_run else result["revision"]
                    result["revision"] = result_revision
                    if not dry_run:
                        self._audit("device_role_bulk_change" if bulk else "device_role_change",
                            "device", action="role", actor=actor,
                            target="role:" + (body["role"] or "") if bulk else ids[0],
                            result="ok" if result.get("ok") else "fail",
                            detail="applied %d; failed %d" %
                                (result["applied"], len(result.get("failed", {}))))
                    self._json(200, result, extra_headers=[
                        ("ETag", _revision_etag("peer-policy", result_revision))])
                    return
                result = {"ok": True, "revision": committed["revision"],
                          "candidate_revision": committed["revision"],
                          "dry_run": dry_run, **preview}
                headers = [("ETag", _revision_etag("peer-policy", committed["revision"]))]
                if not dry_run:
                    self._audit("peer_policy_change", "device", actor=actor,
                        action=self.command.lower(), target=path.rsplit("/", 1)[-1],
                        detail="policy revision %d" % committed["revision"])
                if self.command == "DELETE" and not dry_run:
                    self._send(204, "application/json", b"", headers)
                else:
                    self._json(200, result, extra_headers=headers)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                if isinstance(exc, peer_policy.PolicyError):
                    self._policy_failure(exc, actor=actor, dry_run=dry_run)
                else:
                    self._policy_problem(422, "invalid_policy_request", revision)
            except Exception as exc:
                self._policy_failure(exc, actor=actor, dry_run=dry_run)

        def _policy_read(self, path):
            if app.session_info(self._sid()) is None:
                self._session_refusal()
                return
            auth_path, lkg_path, _ = policy_paths()
            policy = peer_policy.load_policy(auth_path, lkg_path)
            doc, compiled = policy.document, policy.roles
            revision = doc["revision"]
            result = {"revision": revision, "degraded": policy.degraded,
                      "fail_closed": policy.fail_closed}
            try:
                if path == "/api/peer-policy/roles":
                    roles = doc.get("roles", {})
                    definitions = roles.get("defs", {})
                    if "qos_state_default" in roles:
                        result["qos_state_default"] = roles["qos_state_default"]
                    result["roles"] = {name: definitions[name] for name in sorted(definitions)}
                elif path.endswith("/effective-qos"):
                    did = unquote(path[len("/api/devices/"):-len("/effective-qos")])
                    if fleet is None or fleet.get_device(did) is None:
                        self._policy_problem(404, "device_not_found", revision)
                        return
                    query = parse_qs(urlsplit(self.path).query,
                                     keep_blank_values=True)
                    if query and (set(query) != {"tracker_state"} or
                                  query["tracker_state"] not in
                                  (["seeder"], ["leecher"])):
                        self._policy_problem(
                            422, "invalid_policy_request", revision)
                        return
                    qos = peer_policy.explain_qos(doc, did)
                    # These are pinned aria2 client constraints, not tracker caps:
                    # DefaultBtAnnounce.cc emits 50 or 0; the peerless leecher
                    # overrides min interval with BtAnnounce's 2 minute default.
                    qos["numwant"].update(effective_ceiling=min(qos["numwant"]["value"], 50),
                        runtime_request_zero="disabled", constraint_source="pinned-aria2-client")
                    qos["announce_min_interval_s"].update(peerless_leecher_floor_s=120,
                        constraint_source="pinned-aria2-client")
                    qos["catalog_tick_s"].update(offline_horizon_s=_HEARTBEAT_FRESH,
                                                heartbeat_always=True)
                    heartbeat, heartbeat_available = \
                        instruction_heartbeat_for_device(did)
                    revoked_principals = instruction_revocation_snapshot()
                    revocation_available = isinstance(
                        revoked_principals, (set, frozenset))
                    revoked = ("device:%s" % did in revoked_principals
                               if revocation_available else None)
                    instruction = _instruction_device_projection(
                        heartbeat, revoked, now_fn(),
                        heartbeat_available=heartbeat_available)
                    result.update(
                        device_id=did, qos=qos,
                        delivery_state="pre-instructions",
                        instruction=instruction)
                    if query:
                        tracker_state = query["tracker_state"][0]
                        tracker_qos = peer_policy.explain_tracker_qos(
                            doc, did, tracker_state)
                        tracker_qos["numwant"].update(
                            effective_ceiling=min(
                                tracker_qos["numwant"]["value"], 50),
                            runtime_request_zero="disabled",
                            constraint_source="pinned-aria2-client")
                        if tracker_state == "leecher":
                            tracker_qos["announce_min_interval_s"].update(
                                peerless_leecher_floor_s=120,
                                constraint_source="pinned-aria2-client")
                        result.update(tracker_state=tracker_state,
                                      tracker_qos=tracker_qos)
                else:
                    qs = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
                    if set(qs) != {"a", "b"} or any(len(qs[k]) != 1 for k in qs):
                        raise ValueError("bad principals")
                    endpoints = peer_endpoints.fresh_endpoints(os.path.join(
                        policy_state_dir(), "peer-endpoints.json"), now_fn())
                    owners = {}
                    for key, row in endpoints.items():
                        for endpoint in row["endpoints"]:
                            owners.setdefault(endpoint["ipv4"], set()).add(key)
                    def resolve(value):
                        if value == "service:seeder":
                            principal = auth.Principal("service", "seeder")
                        else:
                            did = value[len("device:"):] if value.startswith("device:") else value
                            if ":" in did or not did or fleet is None or fleet.get_device(did) is None:
                                raise ValueError("unresolved principal")
                            principal = auth.Principal("device", did)
                        key = peer_endpoints.principal_key(principal)
                        addresses = {ep["ipv4"] for ep in endpoints.get(key, {}).get("endpoints", [])}
                        if len(addresses) != 1:
                            raise ValueError("ambiguous endpoint")
                        address = next(iter(addresses))
                        if owners[address] != {key}:
                            raise ValueError("ambiguous attribution")
                        return principal, address
                    left, left_ip = resolve(qs["a"][0])
                    right, right_ip = resolve(qs["b"][0])
                    def side(owner, subject, subject_ip):
                        decision, seq = peer_policy.evaluate_for(
                            doc, owner, subject, subject_ip, compiled=compiled)
                        role = compiled.role_of.get(owner.id) if owner.type == "device" else None
                        assignment = peer_policy.ordinary_assignment(doc, owner.id) \
                            if owner.type == "device" else None
                        return {"principal": {"type": owner.type, "id": owner.id},
                            "role": role,
                            "acl_source": peer_policy.acl_source(doc, owner, compiled=compiled),
                            "acl_name": peer_policy.effective_acl_name(doc, owner, compiled=compiled),
                            "decision": "deny" if policy.fail_closed else decision,
                            "matched_seq": None if policy.fail_closed else seq,
                            "role_unknown": bool(compiled.acl_by_role.get(role, {}).get("role_unknown")),
                            "role_shadowed_by": role if role and assignment is not None else None}
                    result.update(a=side(left, right, right_ip), b=side(right, left, left_ip))
                    result["mutual"] = all(result[key]["decision"] == "permit" for key in ("a", "b"))
                self._json(200, result, extra_headers=[("ETag", _revision_etag("peer-policy", revision))])
            except (ValueError, peer_endpoints.EndpointStoreError):
                if path == "/api/peer-policy/explain":
                    self._policy_problem(422, "principal_unresolvable", revision)
                else:
                    self._policy_problem(503, "policy_unavailable", revision)
            except Exception:
                self._policy_problem(503, "policy_unavailable", revision)

        def do_PUT(self):
            path = self.path.split("?", 1)[0]
            if re.fullmatch(r"/api/schedules/[^/]+", path):
                try:
                    length = int(self.headers.get("Content-Length", "0") or 0)
                except ValueError:
                    self._schedule_problem(400, "invalid-request",
                                           "Invalid request")
                    return
                if length < 0 or length > _MAX_BODY:
                    self._schedule_problem(413, "payload-too-large",
                                           "Payload too large")
                    return
                info = self._schedule_session(mutation=True,
                                              unread_body=length)
                if info is None:
                    return
                raw = self.rfile.read(length) if length else b""
                self._schedule_mutation("PUT", path, raw, info)
                return
            if path.startswith("/api/peer-policy/roles/") or path == "/api/peer-policy/qos":
                info = self._require_session_csrf()
                if info is not None:
                    self._policy_mutation(path, "console:" + info["username"])
                return
            quarantine_prefix = "/api/peer-policy/quarantine/"
            if path.startswith(quarantine_prefix):
                info = self._require_session_csrf()
                if info is None:
                    return
                encoded_id = path[len(quarantine_prefix):]
                device_id = unquote(encoded_id)
                # This is one URL segment, not a generic policy target. Reject
                # encoded path separators and let FleetStore remain authoritative.
                if not device_id or "/" in device_id or fleet is None or \
                        fleet.get_device(device_id) is None:
                    self._json(422, {"error": "unknown device"}); return
                try:
                    length = int(self.headers.get("Content-Length", "0") or 0)
                except ValueError:
                    self._json(400, {"error": "bad content-length"}); return
                if length < 0 or length > _MAX_BODY:
                    self._json(413, {"error": "payload too large"}); return
                raw = self.rfile.read(length) if length else b""
                body = self._json_body(raw)
                if body is None:
                    return
                if set(body) != {"quarantined", "if_revision"} or \
                        type(body.get("quarantined")) is not bool or \
                        type(body.get("if_revision")) is not int or \
                        body["if_revision"] < 1:
                    self._json(400, {"error": "bad peer-policy request"}); return
                view = policy_view()
                current_etag = _revision_etag("peer-policy", view["revision"])
                if_match = self.headers.get("If-Match")
                if if_match is None:
                    # v1 retained the body-carried revision for the shipped
                    # console. New clients use If-Match; advertise a bounded
                    # migration window instead of silently maintaining two
                    # concurrency contracts forever.
                    self._response_headers = list(_CAS_COMPATIBILITY_HEADERS)
                elif if_match.strip() not in ("*", current_etag):
                    self._json(412, {"error": "precondition failed"},
                               extra_headers=[("ETag", current_etag)])
                    return
                if view["fail_closed"]:
                    self._json(503, {"error": "policy_fail_closed"}); return
                if view["degraded"]:
                    self._json(422, {"error": "policy_error"}); return
                quarantined = body["quarantined"]
                try:
                    committed = role_coordinator().set_quarantine(
                        device_id, quarantined,
                        actor="console:" + info["username"],
                        expected_revision=body["if_revision"])
                except role_management.RoleManagementError as exc:
                    payload = dict(exc.result)
                    revision = payload.get("revision")
                    headers = ([('ETag', _revision_etag(
                        'peer-policy', revision))]
                        if type(revision) is int else None)
                    self._json(exc.status, payload, extra_headers=headers)
                    return
                self._json(200, {"ok": True, "revision": committed["revision"],
                                 "quarantined": quarantined},
                           extra_headers=[("ETag", _revision_etag(
                               "peer-policy", committed["revision"]))])
                return
            prefix = "/api/images/upload/"
            if not path.startswith(prefix) or images is None:
                self._json(404, {"error": "not found"})
                return
            info = self._require_session_csrf()
            if info is None:
                return
            filename = unquote(path[len(prefix):])
            if not images.valid_filename(filename):
                self._json(400, {"error": "bad filename"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                self._json(400, {"error": "bad content-length"})
                return
            actor = "console:" + info["username"]
            if length <= 0 or length > _MAX_UPLOAD:
                self._audit("image_upload", "image", action="upload",
                           target=filename, actor=actor, result="fail",
                           detail="rejected: oversized (cap 4 GiB)")
                self._json(413, {"error": "missing or oversized body"})
                return
            try:
                image_path = images.save_stream(filename, self._body_reader(length),
                                                max_bytes=_MAX_UPLOAD, expected=length)
            except ValueError as exc:
                self._audit("image_upload", "image", action="upload",
                           target=filename, actor=actor, result="fail",
                           detail="rejected: %s" % exc)
                self._json(400, {"error": str(exc)})
                return
            except (TimeoutError, ConnectionError) as exc:
                self._json(408, {"error": "upload timed out or connection dropped"})
                return
            job_id = images.start_publish(image_path)
            self._audit("image_upload", "image", action="upload", target=filename,
                       actor=actor,
                       detail="%s uploaded, publish job %s started"
                              % (_fmt_bytes(length), job_id))
            self._json(200, {"job_id": job_id})

        def do_PATCH(self):
            path = self.path.split("?", 1)[0]
            if not re.fullmatch(r"/api/schedules/[^/]+", path):
                self._schedule_problem(404, "route-not-found", "Route not found")
                return
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                self._schedule_problem(400, "invalid-request", "Invalid request")
                return
            if length < 0 or length > _MAX_BODY:
                self._schedule_problem(413, "payload-too-large",
                                       "Payload too large")
                return
            info = self._schedule_session(mutation=True, unread_body=length)
            if info is None:
                return
            raw = self.rfile.read(length) if length else b""
            self._schedule_mutation("PATCH", path, raw, info)

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                self._json(400, {"error": "bad content-length"})
                return
            if length < 0:
                # int() accepts a sign, and rfile.read(-1) reads until the
                # client half-closes with no cap at all -- pre-auth. Fail
                # closed before any read (do_PUT already does).
                self._json(400, {"error": "bad content-length"})
                return
            if path == "/__management/authorizations" and \
                    management_token_file is not None:
                if length > _MAX_BODY:
                    api_problem.send(self, 413, "payload-too-large",
                                     "Payload too large")
                    return
                data = self._json_body(self.rfile.read(length) if length else b"")
                if data is None:
                    return
                intended_method = data.get("method")
                intended_path = data.get("path")
                if not isinstance(intended_method, str) or \
                        intended_method not in ("GET", "HEAD", "OPTIONS",
                                                "POST", "PUT", "PATCH",
                                                "DELETE") \
                        or not isinstance(intended_path, str):
                    api_problem.send(self, 400, "invalid-authorization-request",
                                     "Invalid authorization request")
                    return
                # Login and first-run setup are the only browser mutations
                # that intentionally precede a session. The real request will
                # independently repeat all checks before parsing its body.
                intended_clean = urlsplit(intended_path).path
                if (intended_method, intended_clean) not in (
                        ("POST", "/internal/v1/login"),
                        ("POST", "/internal/v1/setup")):
                    info = app.session_info(self._sid())
                    if info is None:
                        api_problem.send(self, 401, "console-session-required",
                                         "Console session required")
                        return
                    if intended_method in ("POST", "PUT", "PATCH", "DELETE") \
                            and not _csrf_ok(
                                self.headers.get("X-CSRF-Token", ""),
                                info["csrf"]):
                        api_problem.send(self, 403, "csrf-validation-failed",
                                         "CSRF validation failed")
                        return
                if api_routes.match("management", intended_method,
                                    intended_path) is None:
                    api_problem.send(self, 404, "route-not-found",
                                     "Route not found")
                    return
                self.send_response(204)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path == "/api/schedules" or re.fullmatch(
                    r"/api/schedules/[^/]+/reaffirm", path):
                if length > _MAX_BODY:
                    self._schedule_problem(413, "payload-too-large",
                                           "Payload too large")
                    return
                info = self._schedule_session(mutation=True,
                                              unread_body=length)
                if info is None:
                    return
                raw = self.rfile.read(length) if length else b""
                self._schedule_mutation("POST", path, raw, info)
                return
            if path == "/api/image-verification/offline":
                # KGV reconciler Task 4: a large (tens-of-MB) tar upload --
                # diverted before the generic cap/eager-read below (sized and
                # built for small JSON bodies) so it is streamed to a private
                # temp file in bounded chunks (the image-upload PUT idiom)
                # rather than held whole in memory.
                self._handle_offline_refresh(length)
                return
            if path == "/api/devices/import-csv":
                cap = _MAX_CSV
            elif path in ("/api/devices/bulk-credential",
                           "/api/devices/bulk-role"):
                cap = _MAX_BULK_DEVICE_IDS
            else:
                cap = _MAX_BODY
            if length > cap:
                self._json(413, {"error": "payload too large"})
                return
            info = None
            if path not in ("/api/login", "/api/setup"):
                # Session + CSRF are checked BEFORE the body is buffered, so
                # an unauthenticated connection can never make this process
                # hold a body (up to the 8 MiB CSV cap) in memory; only the
                # two pre-auth routes read a body first, under _MAX_BODY.
                info = self._require_session_csrf(unread_body=length)
                if info is None:
                    return
            raw = self.rfile.read(length) if length else b""

            if info is not None and not self._prepare_idempotency(path, raw, info):
                return

            if path == "/api/login":
                data = self._json_body(raw)
                if data is None:
                    return
                username = str(data.get("username", ""))
                password = str(data.get("password", ""))
                src_ip = self._client_ip()
                retry = login_limiter.retry_after(src_ip)
                if retry:
                    self._json(429, {"error": "too many login attempts"},
                               extra_headers=[("Retry-After", str(retry))])
                    return
                if app.needs_setup() and _is_default_credential(
                        username, password):
                    # The first-run pair does not create a session. It hands
                    # back a short-lived one-time grant for /api/setup.
                    login_limiter.success(src_ip)
                    grant = _mint_setup_grant(app)
                    self._audit("login", "auth", action="login",
                               actor="console:" + username, result="ok",
                               detail="default credential -> setup grant issued",
                               src_ip=src_ip)
                    self._json(200, {"setup": True, "setup_grant": grant})
                    return
                try:
                    res = app.login(username, password)
                except gui_auth.VerifyBusy:
                    # Nothing was verified: neither a limiter penalty nor a
                    # login_fail audit event -- just ask for a retry.
                    self._json(503, {"error": "server busy, retry shortly"},
                               extra_headers=[("Retry-After", "1")])
                    return
                if res is None:
                    login_limiter.failure(src_ip)
                    self._audit("login_fail", "auth", action="login",
                               actor="console:" + username, result="fail",
                               detail="invalid credentials", src_ip=src_ip)
                    self._json(401, {"error": "invalid credentials"})
                    return
                login_limiter.success(src_ip)
                sid, csrf = res
                self._audit("login", "auth", action="login",
                           actor="console:" + username, result="ok", src_ip=src_ip)
                cookie = "%s=%s%s" % (COOKIE, sid, self._cookie_attrs())
                self._json(200, {"username": username, "csrf": csrf},
                           extra_headers=[("Set-Cookie", cookie)])
                return

            if path == "/api/setup":
                content_type = self.headers.get("Content-Type", "")
                if content_type.split(";", 1)[0].strip().lower() != "application/json":
                    self._json(415, {"error": "application/json required"}); return
                fetch_site = self.headers.get("Sec-Fetch-Site", "")
                if fetch_site and fetch_site != "same-origin":
                    self._json(403, {"error": "cross-origin setup denied"}); return
                origin = self.headers.get("Origin")
                if origin:
                    try:
                        parsed_origin = urlsplit(origin)
                        origin_ok = (parsed_origin.scheme in ("http", "https")
                                     and parsed_origin.netloc.lower()
                                     == self.headers.get("Host", "").lower()
                                     and not parsed_origin.path
                                     and not parsed_origin.query
                                     and not parsed_origin.fragment)
                    except ValueError:
                        origin_ok = False
                    if not origin_ok:
                        self._json(403, {"error": "cross-origin setup denied"}); return
                data = self._json_body(raw)
                if data is None:
                    return
                user = str(data.get("username", "")).strip()
                pw = str(data.get("password", ""))
                # strip: the grant rides in from sessionStorage via setup.js,
                # but keep the same defensive strip the old token had in case
                # of stray whitespace from any manual replay
                grant = str(data.get("setup_grant", "")).strip()
                if not user or not pw:
                    self._json(400, {"error": "username and password required"})
                    return
                if len(pw) < 8:
                    self._json(400, {"error": "password must be at least 8 characters"})
                    return
                if not app.needs_setup():
                    self._json(409, {"error": "already set up"}); return
                result = _claim_admin(app, grant, user, pw)
                if result == "configured":
                    self._json(409, {"error": "already set up"}); return
                if result == "grant":
                    self._audit("setup_fail", "auth", action="setup",
                               actor="console:" + user, target=user, result="fail",
                               detail="invalid or expired setup grant",
                               src_ip=self._client_ip())
                    self._json(403, {"error": "invalid setup grant"}); return
                self._audit("setup", "auth", action="setup", actor="console:" + user,
                           target=user, detail="initial admin account created",
                           src_ip=self._client_ip())
                self._json(200, {"ok": True}); return

            # every other POST: session + CSRF were verified above, before
            # the body was read
            if info is None:
                return
            sid = self._sid()
            actor = "console:" + info["username"]
            if path == "/api/logout":
                app.logout(sid)
                self._audit("logout", "auth", action="logout", actor=actor,
                           src_ip=self._client_ip())
                expired = "%s=%s; Max-Age=0" % (COOKIE, self._cookie_attrs())
                self._json(200, {"ok": True}, extra_headers=[("Set-Cookie", expired)])
                return
            if path == "/api/images/import":
                if images is None:
                    self._json(404, {"error": "not found"}); return
                data = self._json_body(raw)
                if data is None:
                    return
                src = str(data.get("path", ""))

                def _reject(status, error, detail):
                    self._audit("image_import", "image", action="import",
                               actor=actor, result="fail",
                               target=os.path.basename(src) if src else "",
                               detail=detail, src_ip=self._client_ip())
                    self._json(status, {"error": error})

                # Authorize by candidate IDENTITY, not by prefix: a path that
                # merely starts inside a root ("<root>/../outside/secret.bin")
                # is not importable.
                if not src or not images.is_importable_path(src):
                    _reject(400, "not an importable image",
                            "rejected non-candidate path %s" % (src or "(empty)"))
                    return
                if not os.path.isfile(src):
                    _reject(404, "image no longer on disk",
                            "candidate vanished before import: %s" % src)
                    return
                if images.publish_in_flight(images.derived_id(src)):
                    _reject(409, "already being published",
                            "concurrent import of %s" % src)
                    return
                self._audit("image_import", "image", action="import",
                           actor=actor, target=os.path.basename(src),
                           detail="publishing in place from %s" % src,
                           src_ip=self._client_ip())
                self._json(200, {"job_id": images.start_publish(src)}); return
            if path == "/api/settings/password":
                data = self._json_body(raw)
                if data is None:
                    return
                new = str(data.get("new", "")); confirm = str(data.get("confirm", ""))
                if len(new) < 8:
                    self._json(400, {"error": "password must be at least 8 characters"}); return
                if new != confirm:
                    self._json(400, {"error": "passwords do not match"}); return
                try:
                    changed = app.change_password(str(data.get("current", "")), new)
                except gui_auth.VerifyBusy:
                    self._json(503, {"error": "server busy, retry shortly"},
                               extra_headers=[("Retry-After", "1")])
                    return
                if not changed:
                    self._audit("password_change_fail", "auth", action="password_change",
                               actor=actor, result="fail",
                               detail="current password incorrect",
                               src_ip=self._client_ip())
                    self._json(400, {"error": "current password is incorrect"}); return
                revoked = app.revoke_other_sessions(sid)
                self._audit("password_change", "auth", action="password_change",
                           actor=actor, result="ok",
                           detail="password changed; %d other session(s) revoked"
                                  % revoked,
                           src_ip=self._client_ip())
                self._json(200, {"ok": True}); return
            if path == "/api/settings/sessions/revoke-others":
                revoked = app.revoke_other_sessions(sid)
                self._audit("revoke_other_sessions", "auth", action="revoke_sessions",
                           actor=actor,
                           detail="revoked %d other session(s)" % revoked,
                           src_ip=self._client_ip())
                self._json(200, {"revoked": revoked}); return
            if path == "/api/settings/audit-export/run":
                # exact match before the bare config route below
                if creds is None:
                    self._json(404, {"error": "not found"}); return
                state = os.environ.get("IRIS_STATE", "/var/lib/iris")
                cfg = audit_export.read_settings(
                    audit_export.settings_path(state))
                secret = creds.audit_export_secrets()
                if audit_export.validate_settings(cfg) is not None \
                        or secret is None:
                    self._json(409, {"error": "audit export not configured"})
                    return

                def _export_audit(result, detail):
                    # safe from the worker thread: _audit only closes over
                    # audit_path, never per-request state
                    self._audit("audit_export", "settings", action="export",
                               target="audit-export", actor=actor,
                               result=result, detail=detail)

                self._json(200, {"job_id": audit_export.start_export(
                    audit_path, cfg, secret.get("password", ""), state,
                    audit_fn=_export_audit)})
                return
            if path == "/api/settings/audit-export":
                if creds is None:
                    self._json(404, {"error": "not found"}); return
                data = self._json_body(raw)
                if data is None:
                    return
                fields = {}
                for key in ("host", "user", "path", "age_recipient"):
                    val = data.get(key)
                    if not isinstance(val, str) or not val.strip():
                        self._json(400, {"error": "%s is required" % key})
                        return
                    fields[key] = val.strip()
                port = data.get("port", 22)
                if not isinstance(port, int) or isinstance(port, bool) \
                        or not 0 < port < 65536:
                    self._json(400, {"error": "port must be an integer 1-65535"})
                    return
                auto = data.get("auto", False)
                if not isinstance(auto, bool):
                    self._json(400, {"error": "auto must be a bool"}); return
                password = data.get("password")
                if password is not None and not isinstance(password, str):
                    self._json(400, {"error": "password must be a string"})
                    return
                candidate = dict(fields, port=port, auto=auto)
                err = audit_export.validate_settings(candidate)
                if err:
                    self._json(400, {"error": err}); return
                spath = audit_export.settings_path(
                    os.environ.get("IRIS_STATE", "/var/lib/iris"))
                try:
                    # the settings lock covers the whole read-modify-write:
                    # an export finishing mid-save (_record_result) must not
                    # clobber this edit, nor this edit its result
                    with audit_export.SETTINGS_LOCK:
                        prev = audit_export.read_settings(spath)
                        # the destination changed, not the run history: keep it
                        candidate["last_run_ts"] = prev["last_run_ts"]
                        candidate["last_result"] = prev["last_result"]
                        audit_export.write_settings(spath, candidate)
                    if password:    # absent/empty keeps the stored password
                        creds.set_audit_export_secret(password)
                except Exception as exc:
                    self._audit("audit_export_config", "settings", action="set",
                               target="audit-export", actor=actor, result="fail",
                               detail="persist failed: %s" % exc.__class__.__name__)
                    self._json(500, {"error": "settings save failed"}); return
                # destination coordinates are non-secret; the password only
                # ever audits as a flag
                self._audit("audit_export_config", "settings", action="set",
                           target="audit-export", actor=actor,
                           detail="dest %s -> %s@%s:%s port %d, auto %s, "
                                  "password %s"
                                  % (("%s@%s" % (prev["user"], prev["host"]))
                                     if prev["host"] else "(none)",
                                     fields["user"], fields["host"],
                                     fields["path"], port, auto,
                                     "updated" if password else "unchanged"))
                self._json(200, {"ok": True}); return
            if path == "/api/settings/ca-trust/refresh":
                spath = ca_trust_settings_path(
                    os.environ.get("IRIS_STATE", "/var/lib/iris"))
                cfg = read_ca_trust_settings(spath)
                if not cfg["url"]:
                    # read_ca_trust_settings() always falls back to the
                    # built-in default url, so this is defense-in-depth only
                    # (e.g. a future empty _CA_TRUST_DEFAULT_URL) -- normal
                    # operation always has a url, so "Download now" works
                    # with zero configuration.
                    self._json(400, {"error": "no CA bundle URL configured"})
                    return

                def _refresh_audit(result, detail):
                    # safe from the worker thread: _audit only closes over
                    # audit_path, never per-request state
                    self._audit("ca-trust-refresh", "settings",
                               action="refresh", target="ca-trust",
                               actor=actor, result=result, detail=detail)

                self._json(200, {"job": start_ca_refresh(
                    cfg["url"], audit_fn=_refresh_audit)})
                return
            if path == "/api/settings/ca-trust":
                data = self._json_body(raw)
                if data is None:
                    return
                url = data.get("url")
                auto = data.get("auto", False)
                if not isinstance(auto, bool):
                    self._json(400, {"error": "auto must be a bool"}); return
                if url is not None and not isinstance(url, str):
                    self._json(400, {"error": "url must be a string or null"})
                    return
                if url is not None:
                    url = url.strip() or None   # blank == unset (falls back to the default)
                if url is not None:
                    normalized = _validate_ca_url(url)
                    if normalized is None:
                        self._json(400, {"error":
                                   "url must be an https URL without credentials, query, or fragment"})
                        return
                    url = normalized
                spath = ca_trust_settings_path(
                    os.environ.get("IRIS_STATE", "/var/lib/iris"))
                # Read raw (stored) value for audit before-side, not the
                # resolved value with fallback: allows distinguishing
                # never-configured from explicitly-set.
                prev_raw = _read_ca_trust_raw(spath)
                prev_url_audit = (_ca_endpoint_label(prev_raw["url"])
                                  if prev_raw["url"] else "(none)")
                url_after_audit = (_ca_endpoint_label(url)
                                   if url is not None else "(none)")
                try:
                    write_ca_trust_settings(spath, url, auto)
                except Exception as exc:
                    self._audit("ca-trust-config", "settings", action="set",
                               target="ca-trust", actor=actor, result="fail",
                               detail="persist failed: %s" % exc.__class__.__name__)
                    self._json(500, {"error": "settings save failed"}); return
                saved = read_ca_trust_settings(spath)
                self._audit("ca-trust-config", "settings", action="set",
                           target="ca-trust", actor=actor,
                           detail="url %s -> %s, auto %s -> %s"
                                  % (prev_url_audit, url_after_audit,
                                     prev_raw["auto"], auto))
                self._json(200, {"ok": True, "ca_trust": saved})
                return
            if path == "/api/settings/telemetry-destination":
                data = self._json_body(raw)
                if data is None:
                    return
                endpoint = data.get("endpoint")
                enabled = data.get("enabled")
                # null = inherit the deployment env, per field (feature B)
                if enabled is not None and not isinstance(enabled, bool):
                    self._json(400, {"error": "enabled must be a bool or null"})
                    return
                if endpoint is not None:
                    if not isinstance(endpoint, str):
                        self._json(400, {"error":
                                         "endpoint must be a string or null"})
                        return
                    endpoint, err = _validate_otlp_endpoint(
                        endpoint,
                        authenticated=bool(otlp.read_headers_env(os.environ)))
                    if err:
                        self._json(400, {"error": err}); return
                dpath = telemetry_destination.settings_path(
                    os.environ.get("IRIS_STATE", "/var/lib/iris"))
                prev = telemetry_destination.read(dpath)
                try:
                    telemetry_destination.write(dpath, endpoint, enabled)
                except Exception as exc:
                    self._audit("telemetry-destination-set", "telemetry",
                               action="set", target="otlp-endpoint",
                               actor=actor, result="fail",
                               detail="persist failed: %s" % exc.__class__.__name__)
                    self._json(500, {"error": "settings save failed"}); return
                # endpoint URLs are non-secret (headers stay env-only), so a
                # before -> after detail is safe.
                self._audit("telemetry-destination-set", "telemetry",
                           action="set", target="otlp-endpoint", actor=actor,
                           detail="endpoint %s -> %s, enabled %s -> %s"
                                  % (prev["endpoint"] or "(inherit)",
                                     endpoint or "(inherit)",
                                     "(inherit)" if prev["enabled"] is None
                                     else prev["enabled"],
                                     "(inherit)" if enabled is None
                                     else enabled))
                self._json(200, {"ok": True, "endpoint": endpoint,
                                 "enabled": enabled})
                return
            if path == "/api/settings/gui-cert":
                data = self._json_body(raw)
                if data is None:
                    return
                cert_pem = data.get("cert_pem"); key_pem = data.get("key_pem")
                if not isinstance(cert_pem, str) or not cert_pem.strip():
                    self._json(400, {"error": "cert_pem must be a non-empty string"})
                    return
                if not isinstance(key_pem, str) or not key_pem.strip():
                    self._json(400, {"error": "key_pem must be a non-empty string"})
                    return
                # Optional passphrase for an encrypted key: decrypted here at
                # import, then stored age-encrypted like any other key. Fed to
                # openssl over stdin; never audited, logged, or echoed.
                passphrase = data.get("key_passphrase")
                if passphrase is not None and (
                        not isinstance(passphrase, str) or len(passphrase) > 4096):
                    self._json(400, {"error": "key_passphrase must be a short string"})
                    return
                if passphrase and gui_tls.key_is_encrypted(key_pem):
                    key_pem, dec_err = gui_tls.decrypt_key_pem(key_pem, passphrase)
                    if dec_err:
                        self._json(400, {"error": dec_err})
                        return
                err = gui_tls.validate_pair(cert_pem, key_pem)
                if err:
                    # validate_pair messages describe the failure only —
                    # they never contain key material
                    self._audit("gui-cert-replace", "settings", action="replace",
                               target="gui-cert", actor=actor, result="fail",
                               detail="rejected: %s" % err,
                               src_ip=self._client_ip())
                    self._json(400, {"error": err}); return
                try:
                    gui_tls.persist_override(cert_pem, key_pem)
                    # new handshakes serve the new chain immediately -- when
                    # this listener serves TLS at all; the answer says which
                    applied = reload_tls()
                    cert_info = gui_tls.active_info()
                    self._audit("gui-cert-replace", "settings", action="replace",
                               target="gui-cert", actor=actor,
                               detail="subject %s, fingerprint %s"
                                      % (cert_info.get("subject"),
                                         cert_info.get("fingerprint_sha256")),
                               src_ip=self._client_ip())
                    self._json(200, {"gui_cert": cert_info, "applied": applied,
                                     "note": None if applied else
                                     "saved; this console is not serving TLS, "
                                     "so it takes effect at the next restart"})
                    return
                except Exception as exc:
                    self._audit("gui-cert-replace", "settings", action="replace",
                               target="gui-cert", actor=actor, result="fail",
                               detail="persist failed: %s" % exc.__class__.__name__,
                               src_ip=self._client_ip())
                    self._json(500, {"error": "certificate install failed"}); return
            if path == "/api/settings/trust":
                data = self._json_body(raw)
                if data is None:
                    return
                pem = data.get("pem")
                if not isinstance(pem, str) or not pem.strip():
                    self._json(400, {"error": "pem must be a non-empty string"})
                    return
                try:
                    entry = trust.add_pem(pem)
                except ValueError as exc:
                    self._audit("trust-add", "settings", action="add",
                               target="trust-store", actor=actor, result="fail",
                               detail="rejected: %s" % exc,
                               src_ip=self._client_ip())
                    self._json(400, {"error": str(exc)}); return
                except Exception as exc:
                    self._audit("trust-add", "settings", action="add",
                               target="trust-store", actor=actor, result="fail",
                               detail="persist failed: %s" % exc.__class__.__name__,
                               src_ip=self._client_ip())
                    self._json(500, {"error": "trust install failed"}); return
                self._audit("trust-add", "settings", action="add",
                           target=entry["name"], actor=actor,
                           detail="installed %s (%s cert(s), subject %s, fingerprint %s)"
                                  % (entry["name"], entry["cert_count"],
                                     entry["subject"], entry["fingerprint_sha256"]),
                           src_ip=self._client_ip())
                self._json(200, {"entry": entry}); return
            if path == "/api/settings/image-verification":
                # KGV reconciler Task 4: schedule config (mode/hour_utc). A
                # full replace like every other settings-write route above
                # (ca-trust, telemetry-destination) -- last_run is system-
                # managed (only run_refresh ever writes it) and is preserved
                # here, never accepted from the request body.
                data = self._json_body(raw)
                if data is None:
                    return
                mode = data.get("mode")
                if mode not in bulkhash_refresh.MODES:
                    self._json(400, {"error": "mode must be one of %s"
                                     % (", ".join(bulkhash_refresh.MODES))})
                    return
                hour_utc = data.get("hour_utc", 0)
                if not isinstance(hour_utc, int) or isinstance(hour_utc, bool) \
                        or not 0 <= hour_utc <= 23:
                    self._json(400, {"error": "hour_utc must be an integer 0-23"})
                    return
                state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
                spath = bulkhash_refresh.settings_path(state_dir)
                with bulkhash_refresh.SETTINGS_LOCK:
                    prev = bulkhash_refresh.read_settings(spath)
                    bulkhash_refresh.write_settings(
                        spath, mode, hour_utc, prev["last_run"])
                self._audit("bulkhash-schedule-config", "settings",
                           action="set", target="bulkhash", actor=actor,
                           detail="mode %s -> %s, hour_utc %s -> %s"
                                  % (prev["mode"], mode, prev["hour_utc"],
                                     hour_utc))
                self._json(200, bulkhash_refresh.read_settings(spath)); return
            if path == "/api/image-verification/refresh":
                # KGV reconciler Task 4: run the reconciler synchronously on
                # this request's own thread (ThreadingHTTPServer -- a slow
                # run blocks only this one connection) and hand back
                # run_refresh's result dict verbatim; run_refresh's own
                # single-flight lock covers concurrency, so this handler
                # stays a thin pass-through. run_refresh calls its audit_fn
                # with the event fully formed as keywords (including
                # actor="system", the source-agnostic default every caller
                # gets) -- relay every field verbatim but override actor to
                # the console session that asked for THIS run, the same
                # pattern /api/settings/audit-export/run and
                # /api/settings/ca-trust/refresh use for their own
                # completion audit (scheduled runs, wired straight to
                # _bg_audit in main(), are untouched and still record
                # "system").
                if catalog is None:
                    self._json(404, {"error": "not found"}); return
                state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
                result = bulkhash_refresh.run_refresh(
                    "manual", state_dir, catalog,
                    audit_fn=lambda **kw: self._audit(
                        **dict(kw, actor=actor)))
                self._json(_refresh_http_status(result), result); return
            if path.startswith("/api/images/") \
                    and path.endswith("/release-quarantine"):
                # KGV reconciler Task 4: lift an active Cisco Bulk Hash
                # quarantine. override=False re-runs the sha512 comparison
                # (catalog.release_quarantine's job) and 409s with the
                # stored verdict if it still disagrees; override=True
                # requires a typed confirmation (confirm_text == the
                # image's own filename) BEFORE catalog is ever touched --
                # catalog.release_quarantine() already audits with the real
                # actor, so this handler does not audit a second time.
                if catalog is None:
                    self._json(404, {"error": "not found"}); return
                image_id = unquote(path[len("/api/images/"):
                                        -len("/release-quarantine")])
                if not image_id or "/" in image_id:
                    self._json(400, {"error": "bad image id"}); return
                body = self._json_body(raw)
                if body is None:
                    return
                override = body.get("override", False)
                if not isinstance(override, bool):
                    self._json(400, {"error": "override must be a bool"})
                    return
                confirm_text = body.get("confirm_text", "")
                if not isinstance(confirm_text, str):
                    self._json(400, {"error": "confirm_text must be a string"})
                    return
                entry = catalog.get_image(image_id)
                if entry is None:
                    self._json(404, {"error": "no such image"}); return
                if override and confirm_text != (entry.get("filename") or ""):
                    self._json(400, {"error": "confirm_text must exactly "
                                              "match the image filename to "
                                              "confirm the override"})
                    return
                try:
                    result = catalog.release_quarantine(
                        image_id, actor, override=override)
                except KeyError:
                    # TOCTOU: deleted between the get_image() pre-check
                    # above and this call -- answer the same 404 the
                    # pre-check itself would have given, not a dropped
                    # connection.
                    self._json(404, {"error": "no such image"}); return
                except ValueError as exc:
                    self._json(400, {"error": str(exc)}); return
                except catalog_mod.QuarantineStillMismatched as exc:
                    self._json(409, {"error": "quarantine_still_mismatched",
                                     "image_id": exc.image_id,
                                     "verdict": exc.hash_verification})
                    return
                self._json(200, result); return
            if path == "/api/devices":
                if fleet is None:
                    self._json(404, {"error": "not found"}); return
                rec = self._json_body(raw)
                if rec is None:
                    return
                rec_id = str(rec.get("device_id") or "").strip()
                prev = fleet.get_device(rec_id) if rec_id else None
                try:
                    # Reject closed, server-owned and malformed fields before
                    # role coordination can apply a policy-first relaxation.
                    # FleetStore.upsert repeats this under its shard lock.
                    fleet.validate_operator_upsert(rec)
                    if "role" in rec:
                        saved = role_coordinator().upsert_device(
                            rec, actor=actor)["device"]
                    else:
                        saved = fleet.upsert(rec)
                except role_management.RoleManagementError as exc:
                    self._audit(
                        "device_upsert", "device", action="update" if prev
                        else "create", target=rec_id, actor=actor,
                        result="fail", detail="role coordination refused: %s"
                        % exc.code)
                    self._json(exc.status, exc.result); return
                except gui_fleet.FleetFieldError as exc:
                    self._json(422, {"error": str(exc)}); return
                except (ValueError, KeyError) as exc:
                    self._json(400, {"error": str(exc)}); return
                if prev is None:
                    action = "create"
                    detail = "ip %s, vlan %s, model %s" % (
                        saved.get("device_ip"),
                        saved.get("iris_vlan") or saved.get("inband_vlan")
                        or saved.get("vlan") or "-",
                        saved.get("model") or "-")
                else:
                    action = "update"
                    # Fleet rows carry network info only — before->after is safe.
                    changed = sorted(k for k in saved if k != "device_id"
                                     and prev.get(k) != saved.get(k))
                    if changed:
                        detail = "changed " + ", ".join(
                            "%s: %s -> %s" % (k, prev.get(k) or "(none)",
                                              saved.get(k))
                            for k in changed[:3])
                        if len(changed) > 3:
                            detail += " (+%d more)" % (len(changed) - 3)
                    else:
                        detail = "no fields changed"
                self._audit("device_upsert", "device", action=action,
                           target=saved.get("device_id"), detail=detail,
                           actor=actor)
                self._json(200, {"device": saved}); return
            if path == "/api/devices/import-csv":
                if fleet is None:
                    self._json(404, {"error": "not found"}); return
                try:
                    result = role_coordinator().import_csv(
                        raw.decode("utf-8"), actor=actor)
                    stats = result["stats"]
                except role_management.RoleManagementError as exc:
                    self._audit(
                        "device_csv_import", "device", action="import_csv",
                        actor=actor, result="fail",
                        detail="role coordination refused: %s" % exc.code)
                    self._json(exc.status, exc.result); return
                except (ValueError, UnicodeDecodeError) as exc:
                    self._json(400, {"error": str(exc)}); return
                self._audit("device_csv_import", "device", action="import_csv",
                           actor=actor,
                           detail="imported %d devices (%d new, %d updated; "
                                  "%d rows skipped)"
                                  % (stats["imported"], stats["new"],
                                     stats["updated"], stats["skipped"]))
                self._json(200, stats); return
            if path == "/api/devices/bulk-role":
                self._policy_mutation(path, actor, raw)
                return
            if path == "/api/devices/bulk-credential":
                # issue #125: the console's "Select all N matching devices"
                # bulk action used to fire one /api/devices/<id>/credential
                # request per selected device (still true for platform,
                # which has no bulk UI action yet) -- each one locking and
                # rewriting the WHOLE fleet document. FleetStore is sharded
                # now (see gui_fleet.py / keyed_state.py), which already
                # makes each of those O(1); this collapses the N *requests*
                # too, and lets FleetStore.bulk_upsert group the underlying
                # writes by shard instead of touching the same ~256 shards
                # once per device landing in them. Keeps every property the
                # single-device route has: session+CSRF (do_POST, above),
                # the credential-profile-exists check, compare-and-set per
                # device (bulk_upsert reads each device's CURRENT row from
                # within its own shard lock, exactly like upsert()), a
                # named audit record, and -- the one property N separate
                # requests gave for free and a single request has to
                # provide explicitly -- partial-failure reporting naming
                # exactly which ids did not apply and why.
                if fleet is None:
                    self._json(404, {"error": "not found"}); return
                body = self._json_body(raw)
                if body is None:
                    return
                ids = body.get("device_ids")
                if not isinstance(ids, list) or not ids or \
                        not all(isinstance(i, str) and i for i in ids):
                    self._json(400, {"error": "device_ids must be a "
                                              "non-empty array of strings"})
                    return
                if len(ids) > peer_endpoints.SUPPORTED_DEVICES:
                    self._json(400, {"error": "device_ids exceeds the "
                                              "supported fleet size (%d)"
                                              % peer_endpoints.SUPPORTED_DEVICES})
                    return
                pid = str(body.get("credential_profile_id", ""))
                if pid and (creds is None or creds.get_secrets(pid) is None):
                    self._json(400, {"error": "no such credential profile"}); return
                try:
                    results = fleet.bulk_upsert(
                        ids, {"credential_profile_id": pid})
                except (ValueError, KeyError) as exc:
                    self._json(400, {"error": str(exc)}); return
                failed = {did: outcome["error"] for did, outcome in results.items()
                         if not outcome["ok"]}
                applied = len(results) - len(failed)
                detail = "credential profile -> %s across %d/%d device(s)" % (
                    pid or "(cleared)", applied, len(ids))
                if failed:
                    named = sorted(failed.items())
                    detail += "; refused: " + ", ".join(
                        "%s (%s)" % (k, v) for k, v in named[:10])
                    if len(named) > 10:
                        detail += " (+%d more)" % (len(named) - 10)
                self._audit("device_credential_bulk_change", "device",
                           action="credential", actor=actor, detail=detail,
                           result="ok" if applied else "fail")
                self._json(200, {"ok": True, "applied": applied,
                                 "failed": failed}); return
            if path.startswith("/api/devices/") and path.endswith("/role"):
                self._policy_mutation(path, actor, raw)
                return
            if path.startswith("/api/devices/") and path.endswith("/assign"):
                did = unquote(path[len("/api/devices/"):-len("/assign")])
                if not did.strip():
                    self._json(400, {"error": "bad device id"}); return
                body = self._json_body(raw)
                if body is None:
                    return
                if catalog is None:
                    self._json(404, {"error": "not found"}); return
                # `image_ids` (plural, the ordered-set body) takes priority
                # when present; `image_id` (singular) is the pre-multi-image
                # compat shape and always means a one-element set. Either an
                # explicit `image_id: null` or an empty `image_ids` means
                # unassign.
                # Optional compare-and-set. The console's picker sends the
                # set it was opened on, so an assignment another operator (or
                # another tab) wrote in between is refused rather than
                # overwritten in silence -- the same guard the peer-policy PUT
                # carries as if_revision. Absent = the unconditional write
                # older clients and API callers already depend on.
                expect = None
                if "expect_image_ids" in body:
                    expect = body.get("expect_image_ids")
                    if not isinstance(expect, list) or not all(
                            isinstance(i, str) and i for i in expect):
                        self._json(400, {"error": "expect_image_ids must be "
                                                  "a list of image ids"})
                        return
                plural = "image_ids" in body
                if plural:
                    # validate the SHAPE before iterating anything: a bare
                    # int isn't iterable (TypeError -> the connection used to
                    # die instead of answering 400), a bare string iterates
                    # into one-character "ids", and a falsy/non-string
                    # element used to be silently filtered out rather than
                    # rejected. image_ids must be a JSON array whose every
                    # element is a non-empty string; anything else is 400.
                    raw_ids = body.get("image_ids")
                    if not isinstance(raw_ids, list) or not all(
                            isinstance(i, str) and i for i in raw_ids):
                        self._json(400, {"error":
                                   "image_ids must be a list of image ids"})
                        return
                    ids = raw_ids
                else:
                    image_id = str(body.get("image_id") or "")
                    ids = [image_id] if image_id else []
                service = assignment_service.AssignmentService(
                    catalog, fleet, audit_path,
                    authority_path=os.path.join(
                        schedule_store.state_dir,
                        "assignment-authority.sqlite3"))
                try:
                    # API compatibility remains replacement semantics. The
                    # shared service holds fleet membership through the
                    # catalog CAS and writes exactly one success/failure audit.
                    result = service.apply(
                        did, ids, actor=actor, mode="replace",
                        expect_image_ids=expect, retry_conflict=False,
                        plural=plural)
                except assignment_service.MissingFleetDevice:
                    self._json(422, {"error": "no such fleet device"})
                    return
                except assignment_service.AssignmentAuthorityUnavailable:
                    self._json(503, {
                        "error": "assignment authority unavailable"})
                    return
                except catalog_mod.PolicyConflict as exc:
                    self._json(409, {"error": "assignment_conflict",
                                     "assigned_image_ids": exc.current_ids})
                    return
                except catalog_mod.QuarantinedImage as exc:
                    self._json(400, {"error": "image_quarantined",
                                     "image_id": exc.image_id,
                                     "verdict": exc.hash_verification})
                    return
                except ValueError as exc:
                    self._json(400, {"error": str(exc)}); return
                self._json(200, {
                    "ok": True,
                    "assigned_image_ids": result.after_ids,
                    "removed_image_ids": result.removed_ids,
                }); return
            if path.startswith("/api/devices/") and path.endswith("/credential"):
                if fleet is None:
                    self._json(404, {"error": "not found"}); return
                did = unquote(path[len("/api/devices/"):-len("/credential")])
                dev = fleet.get_device(did)
                if dev is None:
                    self._json(404, {"error": "no such device"}); return
                body = self._json_body(raw)
                if body is None:
                    return
                pid = str(body.get("credential_profile_id", ""))
                if pid and (creds is None or creds.get_secrets(pid) is None):
                    self._json(400, {"error": "no such credential profile"}); return
                old = dev.get("credential_profile_id") or ""
                try:
                    fleet.upsert({"device_id": did, "credential_profile_id": pid})
                except (ValueError, KeyError) as exc:
                    self._json(400, {"error": str(exc)}); return
                self._audit("device_credential_change", "device", action="credential",
                           target=did,
                           detail="profile %s -> %s" % (old or "(none)",
                                                        pid or "(cleared)"),
                           actor=actor)
                self._json(200, {"ok": True}); return
            if path.startswith("/api/devices/") and path.endswith("/platform"):
                if fleet is None:
                    self._json(404, {"error": "not found"}); return
                did = unquote(path[len("/api/devices/"):-len("/platform")])
                dev = fleet.get_device(did)
                if dev is None:
                    self._json(404, {"error": "no such device"}); return
                body = self._json_body(raw)
                if body is None:
                    return
                plat = str(body.get("platform", "")).strip()
                if plat and plat not in gui_onboard._PLATFORM_RECIPES:
                    self._json(400, {"error": "platform must be empty or one "
                                     "of: %s" % ", ".join(sorted(
                                         gui_onboard._PLATFORM_RECIPES))}); return
                old = dev.get("platform") or ""
                # Empty value CLEARS the override (falls back to Auto/model)
                # -- except on a classified xr-host row, where platform
                # xr-appmgr is mutually required and clearing it is refused
                # below with that mutual-requirement message instead.
                try:
                    fleet.upsert({"device_id": did, "platform": plat})
                except (ValueError, KeyError) as exc:
                    # e.g. platform=iox on an inband device (unsupported)
                    self._json(400, {"error": str(exc)}); return
                self._audit("device_platform_change", "device", action="platform",
                           target=did,
                           detail="platform %s -> %s" % (old or "(auto)",
                                                         plat or "(auto)"),
                           actor=actor)
                self._json(200, {"ok": True}); return
            if path.startswith("/api/devices/") and path.endswith("/forget-host-key"):
                # A device that was re-imaged or replaced presents a NEW SSH
                # host key; lab/iris-ssh-policy.sh's accept-new mode (correct
                # trust-on-first-use) then refuses every session with a
                # changed-key error, and the persistent known_hosts recording
                # the stale entry lives inside the IRIS state volume -- not
                # somewhere an operator always has shell access to. This is
                # a trust decision, so it is deliberate (one device, on
                # request from the console) and always audited -- never a
                # silent removal.
                if fleet is None or onboard is None:
                    self._json(404, {"error": "not found"}); return
                did = unquote(path[len("/api/devices/"):-len("/forget-host-key")])
                dev = fleet.get_device(did)
                if dev is None:
                    self._json(404, {"error": "no such device"}); return
                ok, detail = onboard.forget_host_key(did)
                if not ok:
                    self._audit("device_forget_host_key", "device",
                               action="forget-host-key", target=did,
                               actor=actor, result="fail", detail=detail)
                    self._json(400, {"error": detail}); return
                # detail is the peer address on success -- name it in the
                # audit trail alongside the device id and the actor, and the
                # console's own confirmation.
                self._audit("device_forget_host_key", "device",
                           action="forget-host-key", target=did, actor=actor,
                           detail="host key forgotten for %s; the next "
                                  "session re-pins on first contact" % detail)
                self._json(200, {"ok": True, "peer": detail}); return
            if path.startswith("/api/devices/") and path.endswith("/request-report"):
                did = unquote(path[len("/api/devices/"):-len("/request-report")])
                if not did.strip():
                    self._json(400, {"error": "bad device id"}); return
                if fleet is None or fleet.get_device(did) is None:
                    self._json(422, {"error": "device is not in fleet"}); return
                if catalog is None:
                    self._json(404, {"error": "not found"}); return
                now = time.time()
                if not catalog.request_report(did, now):
                    self._json(429, {"error": "request already pending"}); return
                self._audit("request_report", "telemetry", action="request",
                           target=did, actor=actor,
                           detail="fresh telemetry report requested (valid %dm)"
                                  % (catalog.PULL_TTL // 60))
                self._json(200, {"ok": True,
                                 "expires_at": int(now) + catalog.PULL_TTL})
                return
            if path == "/api/telemetry/stream":
                # Fleet-wide stream tuning (spec 8.2): writes the settings
                # file the catalog echoes on every heartbeat response.
                data = self._json_body(raw)
                if data is None:
                    return
                every = data.get("every", 1)
                pause = data.get("pause", False)
                if isinstance(every, bool) or not isinstance(every, int) \
                        or not 1 <= every <= 60 or not isinstance(pause, bool):
                    self._json(400, {"error":
                                     "every must be an int 1..60, pause a bool"})
                    return
                live_samples.write_settings(
                    os.path.join(os.environ.get("IRIS_STATE",
                                                "/var/lib/iris"),
                                 "telemetry-settings.json"), every, pause)
                self._audit("telemetry_stream_tune", "telemetry",
                            action="tune",
                            detail="stream_every=%d pause=%s" % (every, pause),
                            actor=actor)
                self._json(200, {"ok": True, "stream_every": every,
                                 "stream_pause": pause})
                return
            if path.startswith("/api/devices/") and path.endswith("/adopt"):
                # Adopt an already-deployed device that predates records, so it
                # can be undeployed. Creates an ACTIVE record from the current
                # validated inventory; it is an explicit, acknowledged operator
                # action (audited), never an implicit fallback.
                did = unquote(path[len("/api/devices/"):-len("/adopt")])
                if not did.strip():
                    self._json(400, {"error": "bad device id"}); return
                if record_store is None:
                    self._json(503, {"error": "record store unavailable"}); return
                device = fleet.get_device(did) if fleet else None
                if device is None:
                    self._json(404, {"error": "no such device"}); return
                body = self._json_body(raw)
                if body is None:
                    return
                if body.get("acknowledge_adopt") is not True:
                    self._json(400, {"error": "adoption acknowledgement is required"}); return
                try:
                    if record_store.active_for_device(
                            did, strict=True) is not None:
                        self._json(409, {"error": "device already has an active deployment record"}); return
                except deployment_records.RecordStoreUnreadable:
                    self._json(503, {
                        "error": "deployment authority is unreadable"}); return
                except ValueError as exc:
                    # duplicate actives (legacy store not yet healed) — surface
                    # the reason like the undeploy branch, not a dropped request
                    self._json(409, {"error": str(exc)}); return
                try:
                    plan = self._plan(did, device)
                except ValueError as exc:
                    self._json(409, {"error": str(exc)}); return
                if plan["resolved"].get("platform") == "router":
                    self._json(409, {"error": "router deployments cannot be adopted; "
                                     "re-onboard to record live ownership evidence"}); return
                record = record_store.adopt({"controller_id": "iris", "device_id": did,
                    "inventory_revision": fleet.revision(), "plan_hash": plan["plan_hash"],
                    "resolved": plan["resolved"],
                    "preflight": {"status": "adopted"},
                    "resources": self._owned_resources(plan["resolved"])})
                self._audit("device_adopt", "onboard", action="adopt", target=did,
                           actor=actor, detail="record %s (%s)"
                           % (record["record_id"], plan["resolved"]["management_type"]))
                self._json(200, {"record_id": record["record_id"]}); return
            if path.startswith("/api/devices/") and (
                    path.endswith("/onboard") or path.endswith("/undeploy")):
                if onboard is None:
                    self._json(404, {"error": "not found"}); return
                act = "undeploy" if path.endswith("/undeploy") else "onboard"
                did = unquote(path[len("/api/devices/"):-len("/" + act)])
                invalid = submission_adapter.prevalidate_device(
                    did, act, actor=actor, audit_fn=self._audit)
                if invalid is not None:
                    self._json(invalid[0], invalid[1]); return
                body_flags = self._json_body(raw)
                if body_flags is None:
                    return
                status, response = submission_adapter.submit_device(
                    did, act, body_flags, actor=actor, audit_fn=self._audit)
                self._json(status, response)
                return
            if path.startswith("/api/onboard/jobs/") and path.endswith("/abort"):
                if onboard is None:
                    self._json(404, {"error": "not found"}); return
                jid = unquote(path[len("/api/onboard/jobs/"):-len("/abort")])
                ok = onboard.abort(jid)
                self._audit("onboard_abort", "onboard", action="abort", target=jid,
                           actor=actor, result="ok" if ok else "fail",
                           detail="operator aborted a running onboard job"
                                  if ok else "no running job to abort")
                if not ok:
                    self._json(409, {"error": "job is not running / cannot be aborted"}); return
                self._json(200, {"aborted": True}); return
            if path == "/api/onboard/cancel-queued":
                if onboard is None:
                    self._json(404, {"error": "not found"}); return
                body = self._json_body(raw)
                if body is None:
                    return
                # job_ids scopes the cancel to the caller's own batch; without
                # it EVERY queued job dies, including other sessions' batches
                # and parked single-device onboards (the console always scopes).
                job_ids = body.get("job_ids")
                if job_ids is not None and (
                        not isinstance(job_ids, list)
                        or not all(isinstance(x, str) for x in job_ids)):
                    self._json(400, {"error": "job_ids must be a list of ids"})
                    return
                n = onboard.cancel_queued(job_ids=job_ids)
                self._audit("onboard_cancel", "onboard", action="cancel",
                           actor=actor,
                           detail="cancelled %d queued onboard job(s)%s" % (
                               n, "" if job_ids is None else
                               " (scoped to %d)" % len(job_ids)))
                self._json(200, {"cancelled": n}); return
            if path == "/api/credentials":
                if creds is None:
                    self._json(404, {"error": "not found"}); return
                body = self._json_body(raw)
                if body is None:
                    return
                existed = creds.get_secrets(
                    str(body.get("id", "")).strip()) is not None
                try:
                    saved = creds.set_profile(str(body.get("id", "")), body)
                except (ValueError, KeyError) as exc:
                    self._json(400, {"error": str(exc)}); return
                self._audit("credential_profile_set", "settings",
                           action="update" if existed else "create",
                           target=saved.get("id"), actor=actor,
                           detail="name '%s', device user %s"
                                  % (saved.get("name"), saved.get("device_user")))
                self._json(200, {"profile": saved}); return
            self._json(404, {"error": "not found"})

        def do_DELETE(self):
            path = self.path.split("?", 1)[0]
            if re.fullmatch(r"/api/schedules/[^/]+", path):
                try:
                    length = int(self.headers.get("Content-Length", "0") or 0)
                except ValueError:
                    self._schedule_problem(400, "invalid-request",
                                           "Invalid request")
                    return
                if length < 0:
                    self._schedule_problem(400, "invalid-request",
                                           "Invalid request")
                    return
                if length > _MAX_BODY:
                    self._schedule_problem(413, "payload-too-large",
                                           "Payload too large")
                    return
                info = self._schedule_session(mutation=True,
                                              unread_body=length)
                if info is None:
                    return
                if length:
                    self.rfile.read(length)
                    self._schedule_problem(400, "invalid-request",
                                           "Invalid request")
                    return
                self._schedule_mutation("DELETE", path, b"", info)
                return
            info = self._require_session_csrf()
            if info is None:
                return
            actor = "console:" + info["username"]
            if path.startswith("/api/peer-policy/roles/"):
                self._policy_mutation(path, actor)
                return
            if path == "/api/settings/audit-export" and creds is not None:
                spath = audit_export.settings_path(
                    os.environ.get("IRIS_STATE", "/var/lib/iris"))
                # under the settings lock so an export finishing mid-delete
                # (_record_result) cannot resurrect the file we just removed
                with audit_export.SETTINGS_LOCK:
                    prev = audit_export.read_settings(spath)
                    existed = os.path.exists(spath)
                    audit_export.clear_settings(spath)
                deleted = creds.clear_audit_export_secret() or existed
                self._audit("audit_export_config", "settings", action="clear",
                           target="audit-export", actor=actor,
                           detail=(("cleared (was %s@%s:%s)"
                                    % (prev["user"], prev["host"], prev["path"]))
                                   if prev["host"] else "cleared")
                                  if deleted else "nothing was configured")
                self._json(200, {"deleted": deleted}); return
            if path == "/api/settings/telemetry-destination":
                dpath = telemetry_destination.settings_path(
                    os.environ.get("IRIS_STATE", "/var/lib/iris"))
                prev = telemetry_destination.read(dpath)
                existed = os.path.exists(dpath)
                telemetry_destination.clear(dpath)
                self._audit("telemetry-destination-clear", "telemetry",
                           action="clear", target="otlp-endpoint", actor=actor,
                           detail=("cleared (was endpoint %s, enabled %s)"
                                   % (prev["endpoint"] or "(inherit)",
                                      "(inherit)" if prev["enabled"] is None
                                      else prev["enabled"]))
                                  if existed else "nothing was overridden")
                self._json(200, {"deleted": existed}); return
            if path == "/api/settings/gui-cert":
                was_active = gui_tls.override_active()
                gui_tls.remove_override()
                reload_tls()  # fall back to the built-in IRIS_CERT chain
                self._audit("gui-cert-revert", "settings", action="revert",
                           target="gui-cert", actor=actor,
                           detail="reverted to built-in certificate"
                                  if was_active else "no override was active",
                           src_ip=self._client_ip())
                self._json(200, {"deleted": was_active,
                                 "gui_cert": gui_tls.active_info()}); return
            if path.startswith("/api/settings/trust/"):
                name = unquote(path[len("/api/settings/trust/"):])
                # basename-only: no separators, no dot-dirs — a traversal
                # attempt is a client bug (400), never a store lookup
                if (not name or name in (".", "..") or "/" in name
                        or "\\" in name or name != os.path.basename(name)
                        or "\x00" in name or not name.endswith(".pem")):
                    self._json(400, {"error": "bad name"}); return
                removed = trust.remove(name)
                self._audit("trust-remove", "settings", action="remove",
                           target=name, actor=actor,
                           result="ok" if removed else "fail",
                           detail=("removed %s" % name) if removed
                                  else "no such certificate",
                           src_ip=self._client_ip())
                self._json(200, {"deleted": removed}); return
            if path.startswith("/api/devices/") and fleet is not None:
                did = unquote(path[len("/api/devices/"):])
                prev = fleet.get_device(did)
                # Spec §7 retirement: durably REVOKE the device's secrets FIRST.
                # If that persist fails, ABORT — no fleet/catalog/policy change,
                # HTTP reports failure, audit stays non-secret. Endpoint rows are
                # deliberately RETAINED (never removed here); the now-revoked
                # principal is derived-denied via its still-fresh endpoint
                # regardless of policy, so cleanup order can never re-permit it.
                try:
                    revoke_state = _revoke_device_secrets(app, did)
                except Exception:
                    # Token-free: the exception (which could embed a path or
                    # secret) is dropped, only a generic failure is audited.
                    self._audit("device_delete", "device", action="delete",
                               target=did, actor=actor, result="fail",
                               detail="secret revoke failed; delete aborted, "
                                      "no state changed")
                    self._json(500, {"deleted": False,
                                     "error": "secret revoke failed"})
                    return
                # Revoke succeeded (or the device had no secrets). Now tidy
                # policy + fleet + catalog state. Any failure here is
                # partial/degraded but CANNOT permit the device.
                degraded = []
                try:
                    role_cleanup = role_coordinator().retire_device(
                        did, actor, catalog=catalog)
                except role_management.RoleManagementError as exc:
                    self._audit(
                        "device_delete", "device", action="delete", target=did,
                        actor=actor, result="fail",
                        detail="secret revoke applied; role cleanup failed: %s"
                        % exc.code)
                    self._json(exc.status, exc.result)
                    return
                if role_cleanup["policy_degraded"]:
                    degraded.append("policy")
                deleted = role_cleanup["deleted"]
                # The coordinator keeps its membership guard across fleet
                # deletion and this catalog purge. A concurrent CLI/API assign
                # therefore resumes only after deletion, observes no fleet row,
                # and cannot recreate stale policy for a replacement device.
                purged = role_cleanup["catalog_purged"]
                if role_cleanup["catalog_degraded"]:
                    degraded.append("catalog")
                # Retire the deployment records for the same reason the catalog
                # state goes: a record outlives the fleet row, and the NEXT
                # device registered under this id inherits it. That strands the
                # device rather than merely confusing it — onboard refuses while
                # a recoverable record exists and names undeploy as the fix,
                # while that teardown refuses the (replaced) box on an identity
                # mismatch. Abandoned, not dropped: the record stays the account
                # of what IRIS built there, which an operator who deleted a
                # still-configured device is the one person who needs.
                retired = []
                try:
                    if record_store is not None:
                        retired = record_store.retire_device(
                            did, "device deleted from the fleet")
                except Exception:
                    degraded.append("records")
                # Work in flight outlives the device for the same reason: a job
                # record is keyed on the device id alone, so one left behind
                # keeps the busy guard armed against the NEXT device registered
                # under this name -- refusing the opposite action outright and
                # silently joining the dead job for the same one.
                stopped = 0
                try:
                    if onboard is not None:
                        halted = onboard.cancel_device(did)
                        stopped = halted["cancelled"] + halted["aborted"]
                except Exception:
                    degraded.append("jobs")
                result = "ok" if deleted and not degraded else (
                    "fail" if not deleted else "degraded")
                if deleted:
                    suffix = (", secrets revoked" if revoke_state == "ok"
                              else "")
                    suffix += ", endpoints retained"
                    suffix += (", %d deployment record%s abandoned"
                               % (len(retired), "" if len(retired) == 1 else "s")
                               if retired else ", no deployment record")
                    if stopped:
                        suffix += (", %d in-flight job%s stopped"
                                   % (stopped, "" if stopped == 1 else "s"))
                    if degraded:
                        suffix += ", partial cleanup: %s" % ",".join(degraded)
                    detail = ("removed (ip %s, model %s)%s"
                              % ((prev or {}).get("device_ip"),
                                 (prev or {}).get("model") or "-", suffix))
                elif revoke_state == "ok" or purged or retired:
                    # No fleet row, but the device had durable secrets/state we
                    # revoked/purged — a real retirement, not a no-op.
                    detail = "no fleet row; secrets revoked, state purged"
                else:
                    detail = "no such device"
                self._audit("device_delete", "device", action="delete",
                           target=did, actor=actor, result=result,
                           detail=detail)
                self._json(200 if not degraded else 207,
                           {"deleted": deleted, "degraded": degraded})
                return
            if path.startswith("/api/credentials/") and creds is not None:
                cid = unquote(path[len("/api/credentials/"):])
                prof = creds.get_secrets(cid)  # only .name is logged — non-secret
                deleted = creds.delete(cid)
                self._audit("credential_profile_delete", "settings", action="delete",
                           target=cid, actor=actor,
                           result="ok" if deleted else "fail",
                           detail=("removed profile '%s'"
                                   % (prof or {}).get("name", "?"))
                                  if deleted else "no such profile")
                self._json(200, {"deleted": deleted})
                return
            if path.startswith("/api/images/") and images is not None:
                iid = unquote(path[len("/api/images/"):])
                live = None
                if fleet is not None:
                    live = {d.get("device_id") for d in fleet.list_devices()}
                entry = images.get_image(iid)
                warnings = []
                try:
                    assigned = images.delete_image(iid, live_device_ids=live,
                                                   warnings=warnings)
                except KeyError:
                    self._json(404, {"error": "no such image"}); return
                if assigned:
                    self._audit("image_delete", "image", action="delete",
                               target=iid, actor=actor, result="fail",
                               detail="blocked: assigned to %d device(s): %s"
                                      % (len(assigned),
                                         ", ".join(assigned[:3])
                                         + ("..." if len(assigned) > 3 else "")))
                    self._json(409, {"error": "image is assigned to devices",
                                     "assigned": assigned}); return
                # A failed seeder stop is not a failed delete (the catalog row,
                # file and .torrent are gone), but the audit row must say so:
                # the origin keeps serving that torrent until it restarts.
                self._audit("image_delete", "image", action="delete", target=iid,
                           actor=actor,
                           detail="deleted %s (%s)%s"
                                  % ((entry or {}).get("filename"),
                                     _fmt_bytes((entry or {}).get("size")),
                                     "; " + "; ".join(warnings) if warnings
                                     else ""))
                self._json(200, {"deleted": True, "warnings": warnings}); return
            self._json(404, {"error": "not found"})

        def log_message(self, *args):
            pass

    submission_adapter = _OnboardSubmissionAdapter(
        fleet, creds, record_store, onboard, iox_controller,
        plan_fn=lambda device_id, device: Handler._plan(
            None, device_id, device),
        apply_preflight_fn=Handler._apply_preflight,
        owned_resources_fn=Handler._owned_resources,
        teardown_resolved_fn=Handler._router_teardown_resolved,
        audit_path=audit_path, now_fn=now_fn,
        # Removing an existing agent footprint does not require a complete
        # network plan for creating a new one. Recorded teardown keeps using
        # its immutable record; only the established fallback needs this path.
        teardown_plan_fn=lambda device_id, device: Handler._plan(
            None, device_id, device, onboarding=False))
    schedule_coordinator = role_coordinator()
    schedule_role_guard = (schedule_coordinator.schedule_role_guard
                           if schedule_coordinator is not None else None)
    assignment_writer = assignment_service.AssignmentService(
        catalog, fleet, audit_path,
        authority_path=os.path.join(
            schedule_store.state_dir, "assignment-authority.sqlite3"))
    scheduled_executor = _ScheduledExecutor(
        schedule_store=schedule_store,
        occurrence_store=schedule_occurrence_store,
        receipt_store=schedule_receipt_store,
        role_guard=lambda schedule: _runner_schedule_role_guard(
            schedule_role_guard, schedule),
        role_policy_snapshot=role_policy_snapshot,
        fleet=fleet, secrets_path=getattr(app, "secrets_path", None),
        assignment_writer=assignment_writer,
        submission=submission_adapter, onboard=onboard,
        record_store=record_store, now_fn=now_fn, catalog=catalog,
        heartbeat_fn=instruction_heartbeat_snapshot,
        swarm_fn=lambda: (swarm_fetch or _default_swarm_fetch)())
    srv = _ConsoleServer((host, port), Handler)
    srv.onboard_submission = submission_adapter
    # Inert runner construction seams. They are the exact instances used by
    # HTTP handlers and do not start background work.
    srv.schedule_store = schedule_store
    srv.schedule_occurrence_store = schedule_occurrence_store
    srv.schedule_receipt_store = schedule_receipt_store
    srv.schedule_target_resolver = runner_schedule_target_resolver
    srv.schedule_role_guard = schedule_role_guard
    srv.schedule_executor = scheduled_executor
    tls_ctx = None
    if certfile:
        # Startup crash-window guard: the preferred cert file (normally the
        # gui-cert override, since _resolve_certfile() picks it on existence
        # alone) can be a corrupt or mismatched cert/key pair -- e.g. a crash
        # between writing the cert and the key. Probe with a throwaway
        # context first; on failure, fall back to the next candidate
        # (IRIS_CERT) rather than crashing the process. If that also fails,
        # fail CLOSED (ConsoleTLSError) unless plaintext was opted into with
        # IRIS_GUI_ALLOW_PLAINTEXT=1: a silently plaintext console accepts
        # the admin password in cleartext, and its Secure cookie could not
        # even keep a session in a remote browser.
        candidates = [(certfile, keyfile)]
        iris_cert = os.environ.get("IRIS_CERT", _IRIS_CERT_DEFAULT)
        if management_token_file is None and iris_cert != certfile:
            candidates.append((iris_cert, None))
        for cand, cand_key in candidates:
            if not os.path.exists(cand):
                continue
            try:
                probe = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                probe.load_cert_chain(cand, keyfile=cand_key)
            except (ssl.SSLError, OSError):
                continue                          # corrupt/mismatched pair
            tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_ctx.load_cert_chain(cand, keyfile=cand_key)
            break
        if tls_ctx is None and (management_token_file is not None
                                or not _plaintext_allowed()):
            srv.server_close()
            raise ConsoleTLSError(
                "no usable console certificate (tried: %s); refusing to serve "
                "plain HTTP. Set %s=1 to opt in deliberately."
                % (", ".join(path for path, _ in candidates),
                   _PLAINTEXT_OPT_IN_ENV))

    # Set AFTER construction: _ConsoleServer.get_request consults it, and
    # nothing is accepted before serve_forever(). The handshake happens per
    # connection in the worker thread; the listening socket stays plain.
    srv.tls_context = tls_ctx
    srv.tls_active = tls_ctx is not None

    def reload_tls():
        """Hot-swap the serving certificate: re-resolve the active combined
        file (gui-cert override if present, else IRIS_CERT) and re-run
        load_cert_chain on the retained listening SSLContext. New handshakes
        serve the new chain; established sessions continue; no rebind.

        Returns True on success. Returns False as a safe no-op when the
        server is not serving TLS (certfile was None -- persisted config
        then takes effect at the next restart), when resolution finds no
        file, or when the file fails to load. Atomicity: a throwaway
        context validates the file FIRST, so a bad file can never leave the
        live context half-swapped or kill serving.

        Closure on purpose: Handler methods (defined above, also closures
        of make_server) call this bare as reload_tls()."""
        if tls_ctx is None:
            return False
        if management_token_file is not None:
            # Console-certificate settings are preserved for the console tier,
            # but must never hot-swap the independent management identity.
            return True
        path = _resolve_certfile()
        if path is None:
            return False
        try:
            probe = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            probe.load_cert_chain(path)      # validate on a throwaway first
            tls_ctx.load_cert_chain(path)    # only then touch the live one
        except (ssl.SSLError, OSError):
            return False
        return True

    srv.reload_tls = reload_tls
    return srv


def _log_peer_policy_startup(state_dir):
    """State-owner signal; the Console process has no policy state mount.

    A capable binary can detect missing role state via the durable watermark.
    This cannot add downgrade detection to a binary predating role support.
    """
    auth_path = os.path.join(state_dir, "peer-policy.json")
    try:
        policy = peer_policy.load_policy(
            auth_path, os.path.join(state_dir, "peer-policy.lkg.json"))
        roles_lost = (peer_policy.roles_ever_configured(auth_path) or
                      policy.document.get("roles_present") is True) and \
            "roles" not in policy.document
        if roles_lost:
            signal = ("WARNING: role state lost; roles were previously configured "
                      "but the loaded policy has no roles. Restore the policy. "
                      "Independent quarantine is ignored by older servers. "
                      "Use a separately reviewed containment and compatibility "
                      "procedure before a downgrade.")
        elif policy.fail_closed:
            signal = "WARNING: peer policy is fail_closed; restore a valid policy."
        elif policy.degraded:
            signal = "WARNING: peer policy is degraded; restore authoritative policy state."
        else:
            signal = "peer policy is healthy."
    except (OSError, peer_policy.PolicyError):
        signal = "WARNING: peer policy is unavailable; check policy state storage."
    print("iris-management: roles supported; " + signal,
          file=sys.stderr, flush=True)


class _TerminationRequested(BaseException):
    """Internal unwind used to route container SIGTERM through cleanup."""


class _SigtermLatch(object):
    """Install TERM protection before local admission can begin."""

    def __init__(self):
        self.pending = False
        self.armed = False
        self.previous = None
        self.installed = False

    def _handle(self, _signum, _frame):
        self.pending = True
        if self.armed:
            # Disarm before raising so a second TERM in the tiny unwind window
            # is latched instead of interrupting the cleanup finally block.
            self.armed = False
            raise _TerminationRequested()

    def install(self):
        if not self.installed:
            self.previous = signal.signal(signal.SIGTERM, self._handle)
            self.installed = True

    def restore(self):
        if self.installed:
            signal.signal(signal.SIGTERM, self.previous)
            self.installed = False


def _serve_with_shutdown(server, cleanup, latch=None, start_admission=None):
    """Serve until return, interruption, or SIGTERM, then drain exactly once.

    ``BaseServer.shutdown()`` cannot be called from the serve_forever thread.
    Raising a private base exception from Python's main-thread signal handler
    unwinds that loop directly and guarantees the ordered cleanup callback.
    A second TERM is ignored while cleanup restores device/controller custody;
    the container runtime's eventual KILL remains its external hard ceiling.
    """
    latch = latch or _SigtermLatch()
    latch.install()
    try:
        if latch.pending:
            raise _TerminationRequested()
        if start_admission is not None:
            start_admission()
        latch.armed = True
        if latch.pending:
            latch.armed = False
            raise _TerminationRequested()
        server.serve_forever()
    except _TerminationRequested:
        pass
    finally:
        latch.armed = False
        latch.pending = True
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            cleanup()
        finally:
            latch.restore()


def main():
    import gui_images
    import gui_fleet
    import gui_creds
    import catalog as catalog_mod
    import publish as publish_mod
    host = os.environ.get("IRIS_MANAGEMENT_API_HOST", "0.0.0.0")
    port = int(os.environ.get("IRIS_MANAGEMENT_API_PORT", "9443"))
    secrets_path = os.environ.get("IRIS_SECRETS", "/run/iris/secrets.json")
    recipients = os.environ.get("IRIS_AGE_RECIPIENTS") or None
    secrets_enc = os.environ.get("IRIS_SECRETS_ENC", "/etc/iris/secrets.json.age")
    state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
    images_dir = os.environ.get("IRIS_IMAGES_DIR", "/var/lib/iris-images")
    certfile = os.environ.get("IRIS_MANAGEMENT_API_CERT", "").strip()
    keyfile = os.environ.get("IRIS_MANAGEMENT_API_KEY", "").strip() or None
    token_file = os.environ.get("IRIS_MANAGEMENT_API_TOKEN_FILE", "").strip()
    previous_token_file = os.environ.get(
        "IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE", "").strip() or None
    if (not isinstance(state_dir, str) or not state_dir or
            not os.path.isabs(state_dir) or
            len(state_dir.encode("utf-8", "surrogatepass")) > 4096 or
            any(ord(character) < 32 or 127 <= ord(character) <= 159
                for character in state_dir)):
        print("iris-management: invalid state root; refusing to start",
              file=sys.stderr, flush=True)
        sys.exit(2)
    if not certfile or not os.path.isfile(certfile):
        print("iris-management: management TLS certificate unavailable; "
              "refusing to start", file=sys.stderr, flush=True)
        sys.exit(2)
    if not token_file:
        print("iris-management: current management credential file is not "
              "configured; refusing to start", file=sys.stderr, flush=True)
        sys.exit(2)
    try:
        tier_auth.load_pair(token_file, previous_token_file)
    except tier_auth.CredentialUnavailable as exc:
        print("iris-management: %s; refusing to start" % exc,
              file=sys.stderr, flush=True)
        sys.exit(2)
    audit_path = os.environ.get("IRIS_AUDIT", "/etc/iris/audit.jsonl")
    # Mint the per-deployment instance id up front so the very first
    # /api/help call already sees the durable value.
    read_instance_id(state_dir)
    _log_peer_policy_startup(state_dir)
    app = gui_app.GuiApp(secrets_path, recipients_csv=recipients, secrets_enc=secrets_enc)
    def _bg_audit(**kw):
        # audit sink for background jobs (onboard runs, async image publishes)
        event = kw.pop("event")
        audit.append_event(audit_path, event, **kw)

    fleet = gui_fleet.FleetStore(state_dir)
    creds = gui_creds.CredentialStore(secrets_path, recipients_csv=recipients,
                                      secrets_enc=secrets_enc)
    # audit_path + seeder_remove_fn: the Cisco Bulk Hash quarantine path
    # (KGV reconciler) stops seeding and writes audit entries through THIS
    # instance -- mirrors exactly how `images` (gui_images.ImageService,
    # above) is wired for the identical seeder-teardown + audit concern.
    # seeder_add_fn is the inverse, for release_quarantine(): the release
    # puts the canonical torrent back into the seeder (re-synced to the
    # current announce credential) instead of leaving the image with no
    # origin until the next container restart.
    catalog = catalog_mod.CatalogStore(
        state_dir, audit_path=audit_path,
        seeder_remove_fn=publish_mod.remove_torrent_rpc,
        seeder_add_fn=publish_mod.resume_torrent_rpc)
    instruction_catalog = catalog_mod.Catalog(
        catalog, secrets_path, audit_path=audit_path)
    # A Console publish does not become terminal until Cisco Bulk Hash
    # reconciliation has covered the newly catalogued image. Use the fully
    # wired CatalogStore above (not ImageService's lightweight write store),
    # so a mismatch also unassigns/quarantines and stops the origin seeder.
    # wait=True guarantees a publish that lands during another refresh gets a
    # fresh pass after that run instead of being omitted from its old snapshot.
    images = gui_images.ImageService(
        state_dir, images_dir, audit_fn=_bg_audit,
        verification_fn=lambda _entry: bulkhash_refresh.run_refresh(
            "manual", state_dir, catalog, audit_fn=_bg_audit, wait=True))
    term_latch = _SigtermLatch()
    term_latch.install()
    iox_controller = None
    control_server = None
    srv = None
    onboard = None
    schedule_wake_event = threading.Event()
    schedule_service = None
    try:
        record_store = deployment_records.DeploymentRecordStore(state_dir)
        record_store.recover_interrupted()
        server_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(server_dir)
        controller_id = iox_verification._load_or_create_controller_id(
            record_store, state_dir)
        catalog_certificate = (
            os.environ.get("IRIS_CRT_PUBLIC") or
            os.path.join(os.environ.get("IRIS_CONFIG") or "/etc/iris",
                         "tls", "crt.pem"))
        catalog_host = os.environ.get("IRIS_HOST_IP", "")
        catalog_url = os.environ.get("IRIS_CATALOG_URL") or (
            "https://%s:8443" % catalog_host if catalog_host else "")
        iox_controller = iox_verification.IoxController(
            record_store,
            {
                "state_dir": state_dir,
                "controller_id": controller_id,
                "record_store": os.path.realpath(record_store.path),
                "session_seconds": 7200,
                "restoration_reserve_seconds": 180,
                "application_id": "iris",
                "credential_resolver": creds.get_secrets,
                "enrollment_token_minter": lambda device_id:
                    gui_onboard._default_mint(device_id, server_dir),
                "instruction_bootstrap_materializer":
                    instruction_catalog.materialize_bootstrap_instruction,
                "catalog_url": catalog_url,
                "catalog_certificate_path": catalog_certificate,
                "recipe_argv_by_action": {
                    "install": [
                        "/bin/bash",
                        os.path.join(repo_root, "device", "iox", "install.sh")],
                    "uninstall": [
                        "/bin/bash",
                        os.path.join(repo_root, "device", "iox", "uninstall.sh")],
                },
            },
            iox_transport.IoxTransport, time.time, time.monotonic)
        onboard = gui_onboard.OnboardService(
            fleet, creds, audit_fn=_bg_audit,
            clear_state_fn=catalog.forget_device, record_store=record_store,
            log_dir=os.path.join(state_dir, "deploy-logs"),
            iox_controller=iox_controller, crt_public=catalog_certificate,
            host_ip=catalog_host, catalog_url=catalog_url,
            instruction_bootstrap_fn=(
                instruction_catalog.materialize_bootstrap_instruction))
        srv = make_server(
            host, port, app, images, fleet, creds, catalog, onboard, None,
            certfile=certfile, keyfile=keyfile, audit_path=audit_path,
            record_store=record_store, management_token_file=token_file,
            management_previous_token_file=previous_token_file,
            iox_controller=iox_controller,
            schedule_wake=schedule_wake_event.set)
        schedule_service = schedule_runner.ScheduleRunner(
            srv.schedule_store, srv.schedule_target_resolver,
            executor=srv.schedule_executor,
            role_guard=lambda schedule: _runner_schedule_role_guard(
                srv.schedule_role_guard, schedule),
            wake_event=schedule_wake_event,
            error_fn=lambda reason: print(
                "iris-management: schedule runner pass failed: %s" % reason,
                file=sys.stderr, flush=True))
        def control_dispatch(request):
            if term_latch.pending:
                return {"error": "service shutting down"}
            return srv.onboard_submission.dispatch(request)

        control_server = iox_verification.IoxControlServer(
            state_dir, controller_id, control_dispatch)
    except Exception:
        if control_server is not None:
            try:
                control_server.close()
            except Exception:
                pass
        if srv is not None:
            try:
                srv.server_close()
            except Exception:
                pass
        if onboard is not None:
            try:
                onboard.shutdown()
            except Exception:
                pass
        if iox_controller is not None:
            try:
                iox_controller.close()
            except Exception:
                pass
        term_latch.restore()
        print("iris-management: controller initialization failed; refusing "
              "to start", file=sys.stderr, flush=True)
        sys.exit(2)
    # Schedule recovery starts only after deployment records were recovered and
    # all state-owner adapters were constructed. Importing or calling
    # make_server() remains inert.
    schedule_stop = threading.Event()
    schedule_thread = threading.Thread(
        target=schedule_service.run, args=(schedule_stop,), daemon=True)
    schedule_thread.start()
    # Hourly instruction-key custody refresh. This is an in-process daemon
    # thread like the maintenance loops below, never another entrypoint process.
    custody_stop = threading.Event()  # never set; loop dies with this process
    threading.Thread(
        target=instruction_keys.status_loop,
        args=(custody_stop, instruction_keys.InstructionPaths.from_env()),
        daemon=True).start()
    # Instruction production shares the management process's trusted fleet
    # and catalog stores; importing this module never starts background work.
    instruction_stop = threading.Event()
    threading.Thread(
        target=instruction_stamper.status_loop,
        args=(instruction_stop, instruction_stamper.InstructionStamper(
            fleet=fleet, catalog_store=catalog)),
        daemon=True).start()
    # Daily public-CA bundle auto-refresh (spec A3): in-process daemon
    # thread, the repo's periodic-work idiom -- no cron/timer/extra process.
    ca_stop = threading.Event()     # never set in production; loop dies with us
    threading.Thread(target=ca_trust_refresh_loop,
                     args=(ca_stop, state_dir, _bg_audit),
                     daemon=True).start()
    # Cisco Bulk Hash reconciliation schedule (KGV reconciler Task 3): same
    # daemon-thread idiom as ca_trust_refresh_loop, immediately above.
    bulkhash_stop = threading.Event()  # never set in production either
    threading.Thread(target=bulkhash_refresh.bulkhash_refresh_loop,
                     args=(bulkhash_stop, state_dir, catalog, _bg_audit),
                     daemon=True).start()
    # Daily audit-trail export (F5): same daemon-thread idiom. The password
    # accessor is passed as a callable so each run reads the current secret.
    export_stop = threading.Event()  # never set in production either
    threading.Thread(target=audit_export.export_loop,
                     args=(export_stop, audit_path, state_dir,
                           creds.audit_export_secrets, _bg_audit),
                     daemon=True).start()
    scheme = "https" if srv.tls_active else "http"
    if not srv.tls_active:
        print("iris-gui: WARNING: serving the console over PLAIN HTTP (%s=1): "
              "the admin password and session cookie cross the network in "
              "cleartext and the cookie is not marked Secure."
              % _PLAINTEXT_OPT_IN_ENV, file=sys.stderr, flush=True)
    print("iris-management on %s://%s:%d/internal/v1" %
          (scheme, host, port), flush=True)
    def shutdown_management():
        for stop in (schedule_stop, custody_stop, instruction_stop, ca_stop,
                     bulkhash_stop, export_stop):
            stop.set()
        schedule_service.stop()
        schedule_thread.join(timeout=10)
        if schedule_thread.is_alive():
            print("iris-management: schedule runner did not stop within 10s",
                  file=sys.stderr, flush=True)
        try:
            control_server.close()
        finally:
            try:
                srv.server_close()
            finally:
                try:
                    onboard.shutdown()
                finally:
                    iox_controller.close()

    _serve_with_shutdown(
        srv, shutdown_management, latch=term_latch,
        start_admission=control_server.start)


if __name__ == "__main__":
    main()
