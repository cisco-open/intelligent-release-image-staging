# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""HTTP adapter for the IRIS web console. Serves static SPA assets from
webroot/ and a small JSON API (/api/login, /api/session, /api/logout,
/api/images -- plus a streaming PUT /api/images/upload/<name> and a
GET /api/images/jobs/<id> publish-status poll) with HttpOnly session cookies
and double-submit CSRF on state-changing requests.
Mirrors catalog.py's ThreadingHTTPServer + BaseHTTPRequestHandler + TLS pattern.
Stdlib only."""
import http.cookies
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import ssl
import tempfile
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, parse_qs, urlsplit

import audit
import audit_export
import bulkhash_refresh
# aliased: `catalog` is the injected STORE everywhere below
import catalog as catalog_mod
import gui_app
import gui_auth
import gui_onboard
import gui_tls
import live_samples
import peer_policy
import peer_enforcement
import secretfs
import secrets_store
import setup_status
import telemetry
import telemetry_destination
import trust

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
    return ('window.IRIS_MAP_CFG = {"swarmUrl":"/api/swarm","pull":true,'
            '"eventsUrlTemplate":%s};' % payload)
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
}
_MAX_BODY = 64 * 1024  # cap request bodies (esp. the pre-auth /api/login POST) — DoS guard
_SSE_IDLE = 600   # close an onboard log stream after this long with NO progress
                  # (queue-wait and new output both reset it — a deep-queued job
                  # behind the onboard pool legitimately waits >10 min)
_SSE_KEEPALIVE = 15  # comment-frame interval so proxies don't reap a quiet stream
_MAX_CSV = 8 * 1024 * 1024  # 8 MiB — bulk devices.csv import (all-or-nothing, held in memory)
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
# Default first-run credential (spec: default-cred-setup-and-tls-ux, Feature 1).
# Hardcoded and non-configurable by design -- this deliberately re-accepts the
# first-comer-wins race the old bootstrap token closed, bounded by the
# deployment's own network perimeter. It never creates a persistent account:
# signing in with this pair only ever mints a one-time setup grant (below),
# and becomes an ordinary failed login the moment a real admin exists.
DEFAULT_SETUP_USER = "iris"
DEFAULT_SETUP_PASS = "irisisgreat!"
_SETUP_GRANT_TTL = 600  # seconds (10 minutes)


def _is_default_credential(username, password):
    """Constant-time compare of both fields against the hardcoded default
    setup pair. Both must match -- there is no partial/near-miss case."""
    return (hmac.compare_digest(username.encode("utf-8"),
                                DEFAULT_SETUP_USER.encode("utf-8"))
            and hmac.compare_digest(password.encode("utf-8"),
                                    DEFAULT_SETUP_PASS.encode("utf-8")))


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
    reconciler Task 4): every field the entry already carries, PLUS a
    guaranteed-present top-level `quarantined` bool and `hash_verification`
    verdict (both default to falsy/None for an image the reconciler has
    never touched -- apply_hash_verification()/release_quarantine() only
    ever set them, never pre-seed them), MINUS the two fields that exist
    purely for catalog.py's own internal bookkeeping
    (quarantine_actions_complete -- convergence-retry state;
    quarantine_override_sha512 -- the re-quarantine-suppression ack) and
    were never meant to be wire-visible."""
    view = {k: v for k, v in entry.items()
           if k not in ("quarantine_actions_complete",
                        "quarantine_override_sha512")}
    view["quarantined"] = bool(entry.get("quarantined"))
    view["hash_verification"] = entry.get("hash_verification")
    return view


def _csrf_ok(provided, expected):
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def _default_swarm_fetch():
    url = os.environ.get("IRIS_SWARM_URL", "http://127.0.0.1:9101/swarm")
    with urllib.request.urlopen(url, timeout=3) as r:
        return r.read()


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
    None -> plain-HTTP fallback (unchanged, tested behavior). Catalog and
    artifact server keep loading IRIS_CERT directly, so device pinning is
    untouched."""
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


def _validate_otlp_endpoint(raw):
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
        return url.rstrip("/"), None
    except ValueError:
        return None, "endpoint must be an http:// or https:// URL with a host"


_CA_JOB_TTL = 3600                  # evict terminal refresh jobs after (s)
# In-memory refresh jobs (the gui_images.start_publish idiom): id -> dict,
# a daemon thread runs the download, GET /api/settings/ca-trust/refresh/<id>
# polls. Per-process: a restart abandons in-flight jobs.
_CA_JOBS = {}
_CA_JOBS_LOCK = threading.Lock()


def ca_refresh_due(settings):
    """Pure decision for the daily loop: the URL to download this cycle, or
    None to skip (auto off / no URL). No clock, no I/O. settings is whatever
    the caller passes -- typically read_ca_trust_settings()'s output, whose
    url is never empty (default-URL fallback), so in practice this reduces
    to the auto flag; the url checks stay so the function is correct against
    a raw/partial dict too."""
    if not isinstance(settings, dict) or settings.get("auto") is not True:
        return None
    url = settings.get("url")
    if not isinstance(url, str) or not url.strip():
        return None
    return url.strip()


def _run_ca_download(url, download_fn=None):
    """One CA-bundle download attempt -> (ok, detail, certs). Never raises;
    detail is audit/UI-safe (URL + error text only, never cert material --
    and download_bundle never puts key/cert bytes in its error strings)."""
    try:
        result = (download_fn or trust.download_bundle)(url)
    except Exception as exc:    # download_bundle reports; belt and suspenders
        result = {"ok": False, "certs": 0, "error": str(exc)}
    if result.get("ok") is True:
        certs = int(result.get("certs") or 0)
        return (True, "downloaded %d certificate(s) from %s" % (certs, url),
                certs)
    return False, str(result.get("error") or "download failed"), None


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


def make_server(host, port, app, images=None, fleet=None, creds=None, catalog=None,
                 onboard=None, swarm_fetch=None, certfile=None, audit_path=None,
                 receipts=None, now_fn=time.time):
    login_limiter = gui_auth.LoginRateLimiter()

    def policy_state_dir():
        return (catalog.state_dir if catalog is not None
                else os.environ.get("IRIS_STATE", "/var/lib/iris"))

    def policy_paths():
        state_dir = policy_state_dir()
        return (os.path.join(state_dir, "peer-policy.json"),
                os.path.join(state_dir, "peer-policy.lkg.json"),
                os.path.join(state_dir, "peer-enforcement.json"))

    def policy_view():
        """Return the GUI-safe, count-only policy and tracker-status view."""
        auth_path, lkg_path, enforcement_path = policy_paths()
        result = peer_policy.load_policy(auth_path, lkg_path)
        doc = result.document
        status = peer_enforcement.read_status(enforcement_path) or {}
        conflicts = status.get("conflicts")
        if not isinstance(conflicts, list):
            conflicts = []
        types = sorted({str(c.get("reason")) for c in conflicts
                        if isinstance(c, dict) and isinstance(c.get("reason"), str)})
        effect = status.get("last_effect")
        # Reconciler effects are aggregate counters. Do not pass through an
        # arbitrary tracker document (which could accidentally grow an address).
        safe_effect = ({k: v for k, v in effect.items()
                        if k in ("disconnected_peers", "removed_peers")
                        and isinstance(v, int) and not isinstance(v, bool)}
                       if isinstance(effect, dict) else None)
        enforcement = {
            "state": status.get("state") if status.get("state") in peer_enforcement.STATES else None,
            "desired_ip_count": status.get("desired_ip_count")
                if isinstance(status.get("desired_ip_count"), int)
                and not isinstance(status.get("desired_ip_count"), bool) else 0,
            "applied_revision": status.get("applied_revision")
                if isinstance(status.get("applied_revision"), int)
                and not isinstance(status.get("applied_revision"), bool) else None,
            "last_reconciled_at": status.get("last_reconciled_at")
                if isinstance(status.get("last_reconciled_at"), (int, float)) else None,
            "conflict_count": len(conflicts), "conflict_types": types,
            "last_effect": safe_effect,
            "last_error": status.get("last_error")
                if isinstance(status.get("last_error"), str) else None,
            "last_operation_exported_revision": status.get("last_operation_exported_revision")
                if isinstance(status.get("last_operation_exported_revision"), int)
                and not isinstance(status.get("last_operation_exported_revision"), bool) else 0,
        }
        return {"schema": doc.get("schema"), "revision": doc.get("revision"),
                "degraded": result.degraded, "fail_closed": result.fail_closed,
                "quarantine": {"reserved": True,
                               "description": "reserved: fully isolate an assigned device"},
                "quarantine_assignments": sorted(
                    device_id for device_id, acl in doc.get("assignments", {}).items()
                    if acl == peer_policy.RESERVED_QUARANTINE),
                "enforcement": enforcement}

    class Handler(BaseHTTPRequestHandler):
        timeout = 60  # socket inactivity timeout (s): a stalled upload frees its thread

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

        def _plan(self, device_id, device):
            """Resolve immutable, non-secret installer input before token minting."""
            attachment = device.get("management_type",
                                    device.get("network_attachment", "legacy_routed"))
            if attachment == "legacy_routed":
                attachment = "routed"
            if attachment not in ("routed", "inband", "router-routed", "router-nat"):
                raise ValueError("unknown network attachment")
            platform = gui_onboard.resolve_platform(device)
            router_attachment = attachment in ("router-routed", "router-nat")
            if device.get("model") and re.match(
                    r"^C8[0-9]{3}", device["model"], re.IGNORECASE) \
                    and not router_attachment:
                raise ValueError("Catalyst 8000 models require management_type "
                                 "router-routed or router-nat")
            if (platform == "router") != router_attachment:
                raise ValueError("platform router requires management_type "
                                 "router-routed or router-nat")
            if platform == "router" and device.get("model") and not re.match(
                    r"^C8[0-9]{3}", device["model"], re.IGNORECASE):
                raise ValueError("router modes support the Catalyst 8000 family only; "
                                 "%s is not yet supported" % device["model"])
            network = {
                "attachment": attachment,
                "device_ip": device.get("device_ip", ""),
                "iris_vlan": device.get("iris_vlan", device.get("vlan", "")),
                "svi_ip": device.get("svi_ip", ""),
                "svi_mask": device.get("svi_mask", ""),
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
                                 or (device.get("device_ip", "") if attachment == "inband" else "")),
                "model": device.get("model", ""),
                "platform": platform,
                "renderer": "v1",
            }
            if attachment == "inband":
                ownership = "preserves existing VLAN, SVI, gateway, routes, and VRF"
            elif attachment == "routed":
                ownership = "creates only a clean IRIS-owned VLAN and SVI"
            elif attachment == "router-nat":
                ownership = ("creates an IRIS-owned VPG and NAT rules; preserves the "
                             "outside interface except for a receipt-owned NAT marking")
            else:
                ownership = "creates only a clean IRIS-owned VirtualPortGroup"
            plan = {"device_id": device_id, "inventory_revision": fleet.revision(),
                    "resolved": network, "ownership": ownership}
            plan["plan_hash"] = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
            return plan

        @staticmethod
        def _apply_router_preflight(plan, evidence):
            """Bind live, ownership-sensitive router evidence into a plan."""
            resolved = gui_onboard.apply_router_preflight(
                plan["resolved"], evidence)
            updated = dict(plan)
            updated["resolved"] = resolved
            payload = {key: value for key, value in updated.items()
                       if key != "plan_hash"}
            updated["plan_hash"] = hashlib.sha256(
                json.dumps(payload, sort_keys=True).encode()).hexdigest()
            return updated

        @staticmethod
        def _owned_resources(resolved):
            """Resources IRIS may later remove, per attachment. Inband owns only
            the app; it never claims the operator's VLAN/SVI."""
            attachment = resolved.get("attachment")
            resources = [{"kind": "guestshell", "ownership": "iris-created"}]
            if attachment == "routed":
                resources = [
                    {"kind": "vlan", "ownership": "iris-created",
                     "id": resolved.get("iris_vlan", "")},
                    {"kind": "svi", "ownership": "iris-created",
                     "ip": resolved.get("svi_ip", "")},
                ] + resources
            elif attachment in ("router-routed", "router-nat"):
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
                if attachment == "router-nat":
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
        def _router_teardown_resolved(receipt):
            """Authorize router teardown strictly from receipt-owned resources."""
            resolved = dict(receipt.get("resolved") or {})
            if resolved.get("platform") != "router":
                return resolved
            required = {"virtualportgroup", "eem-applets", "agent-files",
                        "logging-discriminator", "pki-trustpoint",
                        "http-client-trustpoint", "iox-global",
                        "file-prompt-quiet", "guestshell"}
            if resolved.get("attachment") == "router-nat":
                required.update(("nat-acl", "nat-overload", "nat-static",
                                 "nat-outside-marking"))
            resources = receipt.get("resources") or []
            by_kind = {resource.get("kind"): resource for resource in resources}
            missing = sorted(required - set(by_kind))
            if missing:
                raise ValueError("router receipt does not prove ownership of: %s"
                                 % ", ".join(missing))
            preserved = {"nat-outside-marking", "iox-global", "file-prompt-quiet"}
            for kind in required - preserved:
                if by_kind[kind].get("ownership") != "iris-created":
                    raise ValueError("router receipt does not prove IRIS ownership of %s"
                                     % kind)
            for kind in ("iox-global", "file-prompt-quiet"):
                if by_kind[kind].get("ownership") not in (
                        "pre-existing", "iris-added-preserved"):
                    raise ValueError("router receipt has ambiguous ownership of %s"
                                     % kind)
            expected = {
                "virtualportgroup": ("id", str(resolved.get("vpg_number", ""))),
                "agent-files": ("path", "bootflash:guest-share"),
                "logging-discriminator": ("name", "IRISQ"),
                "pki-trustpoint": ("name", "IRIS"),
                "http-client-trustpoint": ("name", "IRIS"),
            }
            if resolved.get("attachment") == "router-nat":
                expected.update({
                    "nat-acl": ("name", "IRIS-NAT-%s" % resolved.get("vpg_number", "")),
                    "nat-static": ("port", str(resolved.get("swarm_port", "6881"))),
                    "nat-outside-marking": ("interface", resolved.get("nat_interface", "")),
                })
            for kind, (field, value) in expected.items():
                if str(by_kind[kind].get(field, "")) != str(value):
                    raise ValueError("router receipt %s does not match resolved plan"
                                     % kind)
            if not resolved.get("device_ip") or not resolved.get("device_identity"):
                raise ValueError("router receipt is missing deployed device identity")
            resolved["router_resources_owned"] = "1"
            if resolved.get("attachment") == "router-nat":
                marking = by_kind["nat-outside-marking"]
                if marking.get("ownership") not in ("iris-created", "pre-existing"):
                    raise ValueError("router receipt has ambiguous NAT outside ownership")
                resolved["nat_outside_owned"] = (
                    "1" if marking.get("ownership") == "iris-created" else "0")
                resolved["nat_interface"] = marking.get("interface") or ""
            return resolved

        def _send(self, status, ctype, body, extra_headers=None):
            if isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in _SECURITY_HEADERS:
                self.send_header(k, v)
            for k, v in (extra_headers or []):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status, obj, extra_headers=None):
            self._send(status, "application/json",
                       json.dumps(obj).encode("utf-8"), extra_headers)

        def _sid(self):
            jar = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            m = jar.get(COOKIE)
            return m.value if m else ""

        def _require_session_csrf(self):
            """Return the session info for a valid session+CSRF request, else send
            the error response and return None."""
            info = app.session_info(self._sid())
            if info is None:
                self._json(401, {"error": "unauthorized"})
                return None
            if not _csrf_ok(self.headers.get("X-CSRF-Token", ""), info["csrf"]):
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
            with open(full, "rb") as f:
                body = f.read()
            ext = os.path.splitext(full)[1]
            # The SPA assets (index.html/app.js/styles.css) are not
            # content-hashed, so without this a browser keeps serving a stale
            # bundle after a deploy — new features (e.g. the Monitoring tab)
            # stay invisible until the user manually clears their cache.
            # no-cache = the browser may store it but MUST revalidate with the
            # server before use, so a redeploy is picked up on the next load.
            self._send(200, _CONTENT_TYPES.get(ext, "application/octet-stream"),
                       body, extra_headers=[("Cache-Control", "no-cache")])

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
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'nonce-%s'; "
                "style-src 'nonce-%s'; connect-src 'self'; img-src 'self'"
                % (nonce, nonce))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path == "/api/peer-policy":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                self._json(200, policy_view()); return
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
                # "now" rides along so last_seen freshness is computed
                # server-clock-to-server-clock in the UI (skewed lab VMs)
                self._json(200, {"devices": self._device_view(),
                                  "now": int(time.time())}); return
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
                if receipts is None:
                    self._json(404, {"error": "receipts unavailable"}); return
                did = unquote(path[len("/api/devices/"):-len("/deployment")])
                records = receipts.list(did)
                # The record that best describes the device: the active one,
                # else the recoverable teardown-authorizing one — both can
                # raise on ambiguity (duplicate receipts), and this is a
                # read-only visibility panel, so fall back to the newest
                # record rather than erroring it.
                try:
                    record = receipts.recoverable_for_device(did)
                except ValueError:
                    record = None
                if record is None and records:
                    record = max(records,
                                 key=lambda r: (r.get("timestamps") or {})
                                 .get("planned_at") or 0)
                self._json(200, {"receipt": record, "total": len(records)})
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
                try:
                    body = (swarm_fetch or _default_swarm_fetch)()
                    self._send(200, "application/json", body)
                except Exception:
                    self._json(200, {"peers": [], "error": "swarm data unavailable"})
                return
            if path == "/api/telemetry/health":
                # Proxy the hub's /healthz JSON (spec 8.3) behind the console
                # session so the badge never needs the unauthenticated :9101.
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                try:
                    with urllib.request.urlopen(
                            "http://127.0.0.1:%s/healthz"
                            % os.environ.get("IRIS_METRICS_PORT", "9101"),
                            timeout=3) as r:
                        self._send(200, "application/json", r.read())
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
                    creds.get_stage_host() if creds is not None else None,
                    *_telemetry_status_args(),
                    image_verification_last_run=_image_verification_last_run()))
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
                # First-run: land on the LOGIN page — the default iris
                # credential there is what mints the setup grant. setup.html
                # itself stays a plain static page; visiting it grantless just
                # bounces back to login client-side.
                self._serve_static("/login.html"); return
            self._serve_static(path)

        def _device_view(self):
            devs = fleet.list_devices() if fleet else []
            hb = {d.get("device_id"): d for d in (catalog.list_devices()
                                                  if catalog else [])}
            # each device's latest onboard/undeploy job, so the UI can show
            # "onboarding…" / "waiting for heartbeat" instead of a misleading
            # "not enrolled" before the fresh agent's first heartbeat lands
            jobs = onboard.latest_jobs_by_device() if onboard else {}
            # one policy.json read for the whole table — get_policy() re-parses
            # the file per call, which multiplies badly on the polled endpoints
            policies = catalog.list_policies() if catalog else {}
            out = []
            for d in devs:
                did = d.get("device_id")
                pol = policies.get(did, {})
                h = hb.get(did, {})
                row = dict(d)
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
                j = jobs.get(did)
                if j:
                    row["onboard_action"] = j["action"]
                    row["onboard_state"] = j["state"]
                    row["onboard_finished_at"] = j["finished_at"]
                out.append(row)
            return out

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
            sids = row.get("staged_image_ids")
            if sids is None:
                # Tier 1: legacy single-image agent.
                state = row.get("stage_state")
                return state not in (None, "", "unassigned", "ready", "error")
            eids = row.get("errored_image_ids")
            if eids is None:
                # Tier 2: multi-image agent that predates errored_image_ids.
                state = row.get("stage_state")
                if state in (None, "", "unassigned", "ready"):
                    return False
                if state != "error":
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
            # The console's published host port is overridable (IRIS_GUI_PUBLISH);
            # the container always listens on 8080 internally. Prefer that env,
            # else derive it from the operator-set IRIS_CONSOLE_URL, else 8080.
            raw = os.environ.get("IRIS_GUI_PUBLISH", "").strip()
            if not raw:
                tail = os.environ.get("IRIS_CONSOLE_URL", "").rstrip("/").rsplit(":", 1)[-1]
                raw = tail if tail.isdigit() else ""
            console_port = int(raw) if raw.isdigit() else 8080
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
                "ports": {"tracker": 6969, "catalog": 8443, "artifacts": 8000,
                          "swarm": 9101, "console": console_port},
                "observability": {
                    "enabled": obs,
                    "metrics_url": ("http://%s:9101/metrics" % host_ip
                                    if obs and host_ip else ""),
                },
                "sessions": {"active": app.active_sessions(),
                             "idle_ttl_minutes": app.idle_ttl_minutes()},
                # redacted (configured + username only) — the password stays
                # server-side in the age-encrypted store
                "stage_host": (creds.get_stage_host() if creds is not None
                               else {"configured": False, "username": ""}),
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
            self.send_header("Cache-Control", "no-cache")
            for k, v in _SECURITY_HEADERS:
                self.send_header(k, v)
            self.end_headers()
            cursor = 0
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
                    if progressed or job["state"] == "queued":
                        idle_deadline = time.time() + _SSE_IDLE
                    if time.time() >= next_beat:
                        self.wfile.write(b": keepalive\n\n")
                        next_beat = time.time() + _SSE_KEEPALIVE
                    self.wfile.flush()
                    if job["state"] in ("done", "error", "cancelled"):
                        self.wfile.write(
                            ("event: end\ndata: %s\n\n" % job["state"]).encode("utf-8"))
                        self.wfile.flush(); return
                    time.sleep(0.5)
            except (BrokenPipeError, ConnectionError):
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

        def do_PUT(self):
            path = self.path.split("?", 1)[0]
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
                if view["fail_closed"]:
                    self._json(503, {"error": "policy_fail_closed"}); return
                if view["degraded"]:
                    self._json(422, {"error": "policy_error"}); return
                auth_path, lkg_path, enforcement_path = policy_paths()
                status = peer_enforcement.read_status(enforcement_path) or {}
                acked = status.get("last_operation_exported_revision", 0)
                if type(acked) is not int or acked < 0:
                    acked = 0
                quarantined = body["quarantined"]
                def mutate(candidate):
                    if quarantined:
                        candidate["assignments"][device_id] = peer_policy.RESERVED_QUARANTINE
                    else:
                        candidate["assignments"].pop(device_id, None)
                try:
                    committed = peer_policy.commit_mutation(
                        auth_path, lkg_path,
                        action="assign" if quarantined else "unassign",
                        target=device_id, actor="console:" + info["username"],
                        now=now_fn(), mutate=mutate, acked_revision=acked,
                        expected_revision=body["if_revision"])
                except peer_policy.RevisionConflict as exc:
                    self._json(409, {"error": "revision_conflict",
                                     "revision": exc.revision}); return
                except peer_policy.OperationBacklogFull:
                    self._json(503, {"error": "operation_backlog_full"}); return
                except peer_policy.PolicyError:
                    self._json(422, {"error": "policy_error"}); return
                self._json(200, {"ok": True, "revision": committed["revision"],
                                 "quarantined": quarantined}); return
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

        def do_POST(self):
            path = self.path.split("?", 1)[0]
            try:
                length = int(self.headers.get("Content-Length", "0") or 0)
            except ValueError:
                self._json(400, {"error": "bad content-length"})
                return
            if path == "/api/image-verification/offline":
                # KGV reconciler Task 4: a large (tens-of-MB) tar upload --
                # diverted before the generic cap/eager-read below (sized and
                # built for small JSON bodies) so it is streamed to a private
                # temp file in bounded chunks (the image-upload PUT idiom)
                # rather than held whole in memory.
                self._handle_offline_refresh(length)
                return
            cap = _MAX_CSV if path == "/api/devices/import-csv" else _MAX_BODY
            if length > cap:
                self._json(413, {"error": "payload too large"})
                return
            raw = self.rfile.read(length) if length else b""

            if path == "/api/login":
                data = self._json_body(raw)
                if data is None:
                    return
                username = str(data.get("username", ""))
                password = str(data.get("password", ""))
                src_ip = self.client_address[0]
                retry = login_limiter.retry_after(src_ip)
                if retry:
                    self._json(429, {"error": "too many login attempts"},
                               extra_headers=[("Retry-After", str(retry))])
                    return
                if app.needs_setup() and _is_default_credential(username, password):
                    # No admin exists yet: the default pair does not create a
                    # session, it hands back a one-time grant so the client can
                    # complete /api/setup. A wrong/partial attempt at the
                    # default pair falls through to the ordinary login below,
                    # which fails closed (no admin -> no match) and is audited
                    # the same as any other failed login.
                    login_limiter.success(src_ip)
                    grant = _mint_setup_grant(app)
                    self._audit("login", "auth", action="login",
                               actor="console:" + username, result="ok",
                               detail="default credential -> setup grant issued",
                               src_ip=src_ip)
                    self._json(200, {"setup": True, "setup_grant": grant})
                    return
                res = app.login(username, password)
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
                cookie = "%s=%s; HttpOnly; Secure; SameSite=Strict; Path=/" % (COOKIE, sid)
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
                               src_ip=self.client_address[0])
                    self._json(403, {"error": "invalid setup grant"}); return
                self._audit("setup", "auth", action="setup", actor="console:" + user,
                           target=user, detail="initial admin account created",
                           src_ip=self.client_address[0])
                self._json(200, {"ok": True}); return

            # every other POST requires a live session + CSRF
            info = self._require_session_csrf()
            if info is None:
                return
            sid = self._sid()
            actor = "console:" + info["username"]
            if path == "/api/logout":
                app.logout(sid)
                self._audit("logout", "auth", action="logout", actor=actor,
                           src_ip=self.client_address[0])
                expired = ("%s=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
                           % COOKIE)
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
                               detail=detail, src_ip=self.client_address[0])
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
                           src_ip=self.client_address[0])
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
                if not app.change_password(str(data.get("current", "")), new):
                    self._audit("password_change_fail", "auth", action="password_change",
                               actor=actor, result="fail",
                               detail="current password incorrect",
                               src_ip=self.client_address[0])
                    self._json(400, {"error": "current password is incorrect"}); return
                revoked = app.revoke_other_sessions(sid)
                self._audit("password_change", "auth", action="password_change",
                           actor=actor, result="ok",
                           detail="password changed; %d other session(s) revoked"
                                  % revoked,
                           src_ip=self.client_address[0])
                self._json(200, {"ok": True}); return
            if path == "/api/settings/sessions/revoke-others":
                revoked = app.revoke_other_sessions(sid)
                self._audit("revoke_other_sessions", "auth", action="revoke_sessions",
                           actor=actor,
                           detail="revoked %d other session(s)" % revoked,
                           src_ip=self.client_address[0])
                self._json(200, {"revoked": revoked}); return
            if path == "/api/settings/stage-host":
                if creds is None:
                    self._json(404, {"error": "not found"}); return
                data = self._json_body(raw)
                if data is None:
                    return
                user = data.get("username", ""); pw = data.get("password", "")
                if not isinstance(user, str) or not isinstance(pw, str):
                    self._json(400, {"error": "username and password must be strings"}); return
                prev = creds.get_stage_host()  # redacted: configured + username only
                try:
                    saved = creds.set_stage_host(user, pw)
                except ValueError as exc:
                    self._json(400, {"error": str(exc)}); return
                self._audit("stage_host_set", "settings", action="set",
                           target="stage-host", actor=actor,
                           detail="user %s -> %s"
                                  % (prev["username"] or "(none)", user))
                self._json(200, {"stage_host": saved}); return
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
                # destination coordinates are non-secret (stage-host
                # precedent); the password only ever audits as a flag
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
                    try:
                        parts = urlsplit(url)
                        if parts.scheme != "https" or not parts.netloc:
                            self._json(400, {"error": "url must be an https:// URL"})
                            return
                    except ValueError:
                        self._json(400, {"error": "url must be an https:// URL"})
                        return
                spath = ca_trust_settings_path(
                    os.environ.get("IRIS_STATE", "/var/lib/iris"))
                # Read raw (stored) value for audit before-side, not the
                # resolved value with fallback: allows distinguishing
                # never-configured from explicitly-set.
                prev_raw = _read_ca_trust_raw(spath)
                prev_url_audit = prev_raw["url"] or "(none)"
                url_after_audit = url if url is not None else "(none)"
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
                    endpoint, err = _validate_otlp_endpoint(endpoint)
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
                # before -> after detail is safe — stage-host precedent.
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
                               src_ip=self.client_address[0])
                    self._json(400, {"error": err}); return
                try:
                    gui_tls.persist_override(cert_pem, key_pem)
                    reload_tls()  # new handshakes serve the new chain immediately
                    cert_info = gui_tls.active_info()
                    self._audit("gui-cert-replace", "settings", action="replace",
                               target="gui-cert", actor=actor,
                               detail="subject %s, fingerprint %s"
                                      % (cert_info.get("subject"),
                                         cert_info.get("fingerprint_sha256")),
                               src_ip=self.client_address[0])
                    self._json(200, {"gui_cert": cert_info}); return
                except Exception as exc:
                    self._audit("gui-cert-replace", "settings", action="replace",
                               target="gui-cert", actor=actor, result="fail",
                               detail="persist failed: %s" % exc.__class__.__name__,
                               src_ip=self.client_address[0])
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
                               src_ip=self.client_address[0])
                    self._json(400, {"error": str(exc)}); return
                except Exception as exc:
                    self._audit("trust-add", "settings", action="add",
                               target="trust-store", actor=actor, result="fail",
                               detail="persist failed: %s" % exc.__class__.__name__,
                               src_ip=self.client_address[0])
                    self._json(500, {"error": "trust install failed"}); return
                self._audit("trust-add", "settings", action="add",
                           target=entry["name"], actor=actor,
                           detail="installed %s (%s cert(s), subject %s, fingerprint %s)"
                                  % (entry["name"], entry["cert_count"],
                                     entry["subject"], entry["fingerprint_sha256"]),
                           src_ip=self.client_address[0])
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
                    saved = fleet.upsert(rec)
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
                    stats = fleet.import_csv(raw.decode("utf-8"))
                except (ValueError, UnicodeDecodeError) as exc:
                    self._json(400, {"error": str(exc)}); return
                self._audit("device_csv_import", "device", action="import_csv",
                           actor=actor,
                           detail="imported %d devices (%d new, %d updated; "
                                  "%d rows skipped)"
                                  % (stats["imported"], stats["new"],
                                     stats["updated"], stats["skipped"]))
                self._json(200, stats); return
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
                if not ids:
                    # explicit unassign: clear the approval so the agent stops
                    # staging without deleting the device
                    old_ids = catalog.get_policy(did).get("approved_image_ids") or []
                    try:
                        catalog.set_policy(did, approved_image_ids=[],
                                           expect_image_ids=expect)
                    except catalog_mod.PolicyConflict as exc:
                        self._json(409, {"error": "assignment_conflict",
                                         "assigned_image_ids": exc.current_ids})
                        return
                    # EVERY image this cleared, not just the set's first: the
                    # audit trail is the record of what was done to the
                    # device, and naming one of three removed images made it
                    # read as a far smaller change than it was.
                    self._audit("device_assign", "device", action="unassign",
                               target=did, actor=actor,
                               detail="unassigned (was %s)"
                                      % (self._audit_image_names(catalog, old_ids)
                                         or "none"))
                    self._json(200, {"ok": True}); return
                entries = {}
                for iid in ids:
                    entry = catalog.get_image(iid)
                    if entry is None:
                        self._json(400, {"error": "no such image"}); return
                    entries[iid] = entry
                old_pol = catalog.get_policy(did)
                old = old_pol.get("approved_image_id")
                old_ids = old_pol.get("approved_image_ids") or []
                try:
                    # approval is the whole policy: IRIS stages, never installs
                    catalog.set_policy(did, approved_image_ids=ids,
                                       expect_image_ids=expect)
                except catalog_mod.PolicyConflict as exc:
                    # a lost race, not a bad request: answer with what is
                    # really stored so the client can show it and decide again
                    self._json(409, {"error": "assignment_conflict",
                                     "assigned_image_ids": exc.current_ids})
                    return
                except catalog_mod.QuarantinedImage as exc:
                    # a Cisco Bulk Hash sha512 mismatch blocked this id --
                    # surface the verdict so the operator sees WHY, not just
                    # a bare 400 (KGV reconciler).
                    self._json(400, {"error": "image_quarantined",
                                     "image_id": exc.image_id,
                                     "verdict": exc.hash_verification})
                    return
                except ValueError as exc:
                    self._json(400, {"error": str(exc)}); return
                if plural:
                    detail = "assigned %d image(s): %s" % (
                        len(ids), ", ".join(entries[i].get("filename") for i in ids))
                    # Narrowing a set is an assign, and what it REMOVED is the
                    # consequential half of that edit: an operator reading
                    # "assigned 1 image(s): A" had no way to tell it from a
                    # fresh assignment that dropped nothing.
                    removed = [i for i in old_ids if i not in ids]
                    if removed:
                        detail += "; removed: %s" % self._audit_image_names(
                            catalog, removed)
                else:
                    # singular compat: keep the pre-multi-image detail shape
                    # (existing audit tests assert this text verbatim)
                    entry = entries[ids[0]]
                    detail = "assigned %s (%s) id=%s" % (
                        entry.get("filename"), _fmt_bytes(entry.get("size")), ids[0])
                    if old and old != ids[0]:
                        old_entry = catalog.get_image(old)
                        detail += ", was %s" % ((old_entry or {}).get("filename") or old)
                self._audit("device_assign", "device", action="assign", target=did,
                           detail=detail, actor=actor)
                self._json(200, {"ok": True}); return
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
                # Empty value CLEARS the override (falls back to Auto/model).
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
                # Adopt an already-deployed device that predates receipts, so it
                # can be undeployed. Creates an ACTIVE receipt from the current
                # validated inventory; it is an explicit, acknowledged operator
                # action (audited), never an implicit fallback.
                did = unquote(path[len("/api/devices/"):-len("/adopt")])
                if not did.strip():
                    self._json(400, {"error": "bad device id"}); return
                if receipts is None:
                    self._json(503, {"error": "receipt store unavailable"}); return
                device = fleet.get_device(did) if fleet else None
                if device is None:
                    self._json(404, {"error": "no such device"}); return
                body = self._json_body(raw)
                if body is None:
                    return
                if body.get("acknowledge_adopt") is not True:
                    self._json(400, {"error": "adoption acknowledgement is required"}); return
                try:
                    if receipts.active_for_device(did) is not None:
                        self._json(409, {"error": "device already has an active receipt"}); return
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
                receipt = receipts.adopt({"controller_id": "iris", "device_id": did,
                    "inventory_revision": fleet.revision(), "plan_hash": plan["plan_hash"],
                    "resolved": plan["resolved"],
                    "preflight": {"status": "adopted"},
                    "resources": self._owned_resources(plan["resolved"])})
                self._audit("device_adopt", "onboard", action="adopt", target=did,
                           actor=actor, detail="receipt %s (%s)"
                           % (receipt["receipt_id"], plan["resolved"]["attachment"]))
                self._json(200, {"receipt_id": receipt["receipt_id"]}); return
            if path.startswith("/api/devices/") and (
                    path.endswith("/onboard") or path.endswith("/undeploy")):
                if onboard is None:
                    self._json(404, {"error": "not found"}); return
                act = "undeploy" if path.endswith("/undeploy") else "onboard"
                did = unquote(path[len("/api/devices/"):-len("/" + act)])
                if not did.strip():
                    self._json(400, {"error": "bad device id"}); return

                def _reject(status, error):
                    # Every submission refusal from here on is audited under
                    # the SAME event a successful start uses below (varying
                    # only result), so the trail never goes quiet after an
                    # operator hits onboard/undeploy: a rejected router
                    # preflight, a busy-device conflict, an unreachable
                    # device, etc. all leave a result=fail onboard_start /
                    # undeploy_start record naming this device -- never a
                    # "create" (or a click) followed by nothing.
                    self._audit("%s_start" % act, "onboard", action="start",
                               target=did, actor=actor, result="fail",
                               detail=error)
                    self._json(status, {"error": error})

                # Reject unknown devices HERE, before start() creates a job +
                # parked worker thread — junk ids must not accumulate either.
                if fleet is not None and fleet.get_device(did) is None:
                    _reject(404, "no such device"); return
                resolved = None
                receipt_ref = {}
                prepare = None
                pre_apply = None
                on_success = None
                # Telemetry flags from the onboard form (spec 8.1): reports
                # default on, streaming default off — both installer-style and
                # IOx-style env names so every platform recipe picks them up.
                body_flags = self._json_body(raw)
                if body_flags is None:
                    return
                # Force teardown: an onboard that died after enabling the
                # agent but before its receipt was written leaves a router that
                # cannot be undeployed (no receipt), cannot be adopted (routers
                # never can) and cannot be re-onboarded (preflight refuses the
                # existing Guest Shell). Force removes ONLY the agent footprint.
                force = body_flags.get("force", False) is True
                t_on = body_flags.get("telemetry", True) is not False
                s_on = body_flags.get("telemetry_stream", False) is True
                env_extra = {"TELEMETRY": "on" if t_on else "off",
                             "TELEMETRY_STREAM": "on" if s_on else "off"}
                env_extra["IRIS_TELEMETRY"] = env_extra["TELEMETRY"]
                env_extra["IRIS_TELEMETRY_STREAM"] = env_extra["TELEMETRY_STREAM"]
                # Undeploy carries its own env: the telemetry flags above are
                # onboard-only, but the force flag below MUST reach the
                # teardown recipe. env_extra is the only channel into it.
                undeploy_env = None
                if act == "onboard":
                    # With a receipt store (always in production via main()), an
                    # onboard resolves an immutable plan and records a receipt.
                    # Without one (embedded/degraded), it stays one-click legacy.
                    if receipts is not None:
                        device = fleet.get_device(did)
                        try:
                            plan = self._plan(did, device)
                        except ValueError as exc:
                            _reject(409, str(exc)); return
                        if plan["resolved"].get("platform") == "router":
                            try:
                                # Any receipt IRIS already applied blocks a
                                # re-onboard, not just an active one: the box is
                                # configured either way, so preflight would fail
                                # with a confusing "guestshell is already
                                # enabled" instead of naming the real fix.
                                existing = receipts.recoverable_for_device(did)
                            except ValueError as exc:
                                _reject(409, str(exc)); return
                            if existing is not None:
                                _reject(409, "router already has a %s "
                                        "deployment receipt; undeploy it before "
                                        "onboarding again — if this device was "
                                        "replaced, undeploy with force, or "
                                        "delete and re-add it"
                                        % existing.get("state", "recorded")); return
                        resolved = plan["resolved"]

                        def prepare():
                            # Runs under the onboard job lock only when a genuinely
                            # new job is registered, so a concurrent double-onboard
                            # cannot leave an orphan planned receipt.
                            rid = receipts.create({"controller_id": "iris",
                                "device_id": did, "inventory_revision": fleet.revision(),
                                "plan_hash": plan["plan_hash"], "resolved": plan["resolved"],
                                # Router preflight runs in the bounded worker pool,
                                # not synchronously in this HTTP request. This lets a
                                # large selected batch show queued progress immediately.
                                "preflight": ({"status": "pending"}
                                              if resolved.get("platform") == "router"
                                              else {"status": "not-required"}),
                                "resources": self._owned_resources(plan["resolved"])})["receipt_id"]
                            receipt_ref["id"] = rid
                            return rid

                        if resolved.get("platform") == "router":
                            def pre_apply(evidence):
                                # The job may have waited in the queue. Refresh
                                # live ownership immediately before apply, then
                                # atomically replace the planned receipt inputs.
                                final_plan = self._apply_router_preflight(plan, evidence)
                                rid = receipt_ref.get("id")
                                if not rid:
                                    raise ValueError("planned receipt is unavailable")
                                receipts.update_planned(
                                    rid, plan_hash=final_plan["plan_hash"],
                                    resolved=final_plan["resolved"],
                                    preflight=evidence,
                                    resources=self._owned_resources(
                                        final_plan["resolved"]))
                                return final_plan["resolved"]
                    else:
                        try:
                            degraded_plan = self._plan(did, fleet.get_device(did))
                        except ValueError as exc:
                            _reject(409, str(exc)); return
                        if degraded_plan["resolved"].get("platform") == "router":
                            _reject(503, "router onboarding requires the "
                                    "deployment receipt store"); return
                else:
                    # Undeploy renders exclusively from an active receipt so a
                    # post-deploy inventory edit cannot retarget cleanup. Without
                    # a receipt store, fall back to legacy fleet-driven teardown.
                    if receipts is not None:
                        # FORCE is decided BEFORE the receipt is read, because a
                        # forced teardown never uses a receipt as authority: it
                        # strips only what is identifiably IRIS's by name and
                        # leaves the operator's network exactly as it is. Force
                        # used to be consulted only on the no-receipt branch,
                        # which defeated the one case it exists for — a receipt
                        # that describes a device no longer there. A rebuilt VM
                        # keeps its id and address but gets a new board ID, so
                        # the teardown recipe's identity guard refused it every
                        # time, while onboard kept naming that same teardown as
                        # the fix. Force could not be reached from either end.
                        if force:
                            try:
                                degraded_plan = self._plan(
                                    did, fleet.get_device(did))
                            except ValueError as exc:
                                _reject(409, str(exc)); return
                            resolved = degraded_plan["resolved"]
                            undeploy_env = {"IRIS_FORCE_AGENT_ONLY": "1"}

                            # Retired only once the box is actually clean (see
                            # OnboardService.start's on_success). EVERY
                            # non-terminal receipt goes, which is also the only
                            # exit from "multiple recoverable receipts" — that
                            # state refuses onboard, undeploy and adopt alike,
                            # and nothing else in the product resolves it.
                            def on_success(_did=did):
                                receipts.retire_device(
                                    _did, "forced agent-only teardown; the "
                                    "receipt no longer describes this device")

                            self._audit("undeploy_forced", "onboard",
                                        action="start", target=did,
                                        actor=actor, result="ok",
                                        detail="forced agent-footprint teardown;"
                                               " VPG/NAT left untouched, any "
                                               "deployment receipt abandoned "
                                               "once the teardown succeeds")
                        else:
                            try:
                                # Not just the ACTIVE receipt: a controller
                                # restart during an onboard leaves the receipt
                                # "unknown" while the device is already
                                # configured, and that receipt still records
                                # what IRIS created. Teardown must accept it, or
                                # the device is stranded — a router cannot be
                                # adopted and its preflight refuses a re-onboard.
                                receipt = receipts.recoverable_for_device(did)
                            except ValueError as exc:
                                # duplicate actives should be impossible
                                # (activation supersedes siblings; startup
                                # collapses legacy dupes) — but surface the
                                # reason instead of a 500 if not, and name the
                                # way out rather than leaving the operator with
                                # a state the console cannot resolve.
                                _reject(409, "%s; retry with force to remove "
                                        "the agent footprint only" % exc); return
                            if receipt is None:
                                _reject(409, "no deployment receipt for this "
                                        "device; adopt it first, then undeploy, "
                                        "or retry with force to remove the "
                                        "agent footprint only"); return
                            try:
                                resolved = self._router_teardown_resolved(receipt)
                            except ValueError as exc:
                                # Best effort: the receipt may already BE
                                # needs-reconcile, from an earlier attempt at
                                # this same broken teardown, and that self-edge
                                # is not a legal transition. Letting it raise
                                # turned every retry after the first into an
                                # unhandled 500 with no JSON body to explain it.
                                try:
                                    receipts.transition(receipt["receipt_id"],
                                                        "needs-reconcile")
                                except ValueError:
                                    pass
                                _reject(409, str(exc)); return

                            def prepare():
                                receipt_ref["id"] = receipt["receipt_id"]
                                return receipt["receipt_id"]
                    else:
                        try:
                            degraded_plan = self._plan(did, fleet.get_device(did))
                        except ValueError as exc:
                            _reject(409, str(exc)); return
                        if degraded_plan["resolved"].get("platform") == "router":
                            _reject(503, "router undeploy requires an "
                                    "active deployment receipt"); return
                try:
                    jid = onboard.start(
                        did, action=act, resolved=resolved, prepare=prepare,
                        pre_apply=pre_apply, on_success=on_success,
                        env_extra=(env_extra if act == "onboard"
                                   else undeploy_env))
                except ValueError as exc:
                    if receipt_ref.get("id") and act == "onboard":
                        # Best effort, for the same reason as the teardown-
                        # resolve handler above: start() retires the receipt
                        # itself when the work queue is full, so this would be
                        # removed -> needs-reconcile, which is not a legal edge.
                        # An illegal transition raised from inside an except
                        # handler escapes do_POST entirely — the operator gets a
                        # dropped request instead of the 409 that explains why.
                        try:
                            receipts.transition(receipt_ref["id"],
                                                "needs-reconcile")
                        except ValueError:
                            pass
                    # the device is busy with the OPPOSITE action
                    _reject(409, str(exc)); return
                # Emitted AFTER start() so the job id correlates this start with
                # its *_finished event when jobs run concurrently.
                self._audit("%s_start" % act, "onboard", action="start",
                           target=did, actor=actor, detail="job %s" % jid)
                self._json(200, {"job_id": jid}); return
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
            info = self._require_session_csrf()
            if info is None:
                return
            actor = "console:" + info["username"]
            if path == "/api/settings/stage-host" and creds is not None:
                prev = creds.get_stage_host()  # redacted: username only
                deleted = creds.clear_stage_host()
                self._audit("stage_host_clear", "settings", action="clear",
                           target="stage-host", actor=actor,
                           detail=("cleared (was user %s)" % prev["username"])
                                  if deleted else "nothing was configured")
                self._json(200, {"deleted": deleted}); return
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
                           src_ip=self.client_address[0])
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
                           src_ip=self.client_address[0])
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
                # Peer-policy lives in the shared IRIS state dir. Prefer the
                # catalog's own state_dir (single source of truth, and what the
                # tracker reconciler reads) so console + tracker agree; fall back
                # to IRIS_STATE only when no catalog is wired.
                state_dir = (catalog.state_dir if catalog is not None
                             else os.environ.get("IRIS_STATE", "/var/lib/iris"))
                try:
                    peer_policy.unassign_device(
                        os.path.join(state_dir, "peer-policy.json"),
                        os.path.join(state_dir, "peer-policy.lkg.json"),
                        did, actor=actor, now=time.time())
                except Exception:
                    degraded.append("policy")
                deleted = fleet.delete(did)
                # Purge catalog-side state (assignment, heartbeat record,
                # telemetry history, seen-report ledger, pending pull) even when
                # the fleet row was already gone — a deleted-and-re-added device
                # must come back unassigned. Endpoints are NOT purged (retained
                # to TTL); re-onboard clears them before new credentials mint.
                try:
                    purged = (catalog.purge_device(did)
                              if catalog is not None else False)
                except Exception:
                    purged = False
                    degraded.append("catalog")
                # Retire the deployment receipts for the same reason the catalog
                # state goes: a receipt outlives the fleet row, and the NEXT
                # device registered under this id inherits it. That strands the
                # device rather than merely confusing it — onboard refuses while
                # a recoverable receipt exists and names undeploy as the fix,
                # while that teardown refuses the (replaced) box on an identity
                # mismatch. Abandoned, not dropped: the receipt stays the record
                # of what IRIS built there, which an operator who deleted a
                # still-configured device is the one person who needs.
                retired = []
                try:
                    if receipts is not None:
                        retired = receipts.retire_device(
                            did, "device deleted from the fleet")
                except Exception:
                    degraded.append("receipts")
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
                    suffix += (", %d deployment receipt%s abandoned"
                               % (len(retired), "" if len(retired) == 1 else "s")
                               if retired else ", no deployment receipt")
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
                try:
                    assigned = images.delete_image(iid, live_device_ids=live)
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
                self._audit("image_delete", "image", action="delete", target=iid,
                           actor=actor,
                           detail="deleted %s (%s)"
                                  % ((entry or {}).get("filename"),
                                     _fmt_bytes((entry or {}).get("size"))))
                self._json(200, {"deleted": True}); return
            self._json(404, {"error": "not found"})

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer((host, port), Handler)
    tls_ctx = None
    if certfile:
        # Startup crash-window guard: the preferred cert file (normally the
        # gui-cert override, since _resolve_certfile() picks it on existence
        # alone) can be a corrupt or mismatched cert/key pair -- e.g. a crash
        # between writing the cert and the key. Probe with a throwaway
        # context BEFORE wrapping the listening socket; on failure, fall
        # back to the next candidate (IRIS_CERT) rather than crashing the
        # process. If that also fails, serve plain HTTP -- never take the
        # console down over a bad cert file.
        candidates = [certfile]
        iris_cert = os.environ.get("IRIS_CERT", _IRIS_CERT_DEFAULT)
        if iris_cert != certfile:
            candidates.append(iris_cert)
        for cand in candidates:
            if not os.path.exists(cand):
                continue
            try:
                probe = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                probe.load_cert_chain(cand)      # validate before wrapping
            except (ssl.SSLError, OSError):
                continue                          # corrupt/mismatched pair
            tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_ctx.load_cert_chain(cand)
            srv.socket = tls_ctx.wrap_socket(srv.socket, server_side=True)
            break

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


def main():
    import gui_images
    import gui_fleet
    import gui_creds
    import deployment_receipts
    import catalog as catalog_mod
    import publish as publish_mod
    host = os.environ.get("IRIS_GUI_HOST", "0.0.0.0")
    port = int(os.environ.get("IRIS_GUI_PORT", "8080"))
    secrets_path = os.environ.get("IRIS_SECRETS", "/run/iris/secrets.json")
    recipients = os.environ.get("IRIS_AGE_RECIPIENTS") or None
    secrets_enc = os.environ.get("IRIS_SECRETS_ENC", "/etc/iris/secrets.json.age")
    state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
    images_dir = os.environ.get("IRIS_IMAGES_DIR", "/var/lib/iris-images")
    certfile = _resolve_certfile()
    audit_path = os.environ.get("IRIS_AUDIT", "/etc/iris/audit.jsonl")
    # Mint the per-deployment instance id up front so the very first
    # /api/help call already sees the durable value.
    read_instance_id(state_dir)
    app = gui_app.GuiApp(secrets_path, recipients_csv=recipients, secrets_enc=secrets_enc)

    def _bg_audit(**kw):
        # audit sink for background jobs (onboard runs, async image publishes)
        event = kw.pop("event")
        audit.append_event(audit_path, event, **kw)

    images = gui_images.ImageService(state_dir, images_dir, audit_fn=_bg_audit)
    fleet = gui_fleet.FleetStore(state_dir)
    creds = gui_creds.CredentialStore(secrets_path, recipients_csv=recipients,
                                      secrets_enc=secrets_enc)
    # audit_path + seeder_remove_fn: the Cisco Bulk Hash quarantine path
    # (KGV reconciler) stops seeding and writes audit entries through THIS
    # instance -- mirrors exactly how `images` (gui_images.ImageService,
    # above) is wired for the identical seeder-teardown + audit concern.
    catalog = catalog_mod.CatalogStore(
        state_dir, audit_path=audit_path,
        seeder_remove_fn=publish_mod.remove_torrent_rpc)
    receipts = deployment_receipts.ReceiptStore(state_dir)
    receipts.recover_interrupted()
    onboard = gui_onboard.OnboardService(
        fleet, creds, audit_fn=_bg_audit,
        clear_state_fn=catalog.forget_device, receipts=receipts,
        log_dir=os.path.join(state_dir, "deploy-logs"))
    srv = make_server(host, port, app, images, fleet, creds, catalog, onboard,
                       None, certfile=certfile, audit_path=audit_path, receipts=receipts)
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
    print("iris-gui on %s://%s:%d/" % (scheme, host, port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
