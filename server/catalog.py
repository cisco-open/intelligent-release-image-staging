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
import json
import os
import ssl
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import audit
import auth
import secretfs
import secrets_store


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
                "agent")
_REPORT_EVENTS = ("staging-complete", "seeding-only", "pull")
_REPORT_PEER_ROWS = 20
_REPORT_STR_MAX = 128


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
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _sanitize_report(data):
    """Server-side re-validation of a device telemetry report (spec issue #13).

    Whitelists top-level keys, requires a known event, re-trims peers to
    _REPORT_PEER_ROWS rows of exactly
    {ip[:64], rx_bytes:int, tx_bytes:int, avg_bps:int}, and caps every other
    string at _REPORT_STR_MAX chars.  The device already trims client-side, but
    ingest never trusts that.  Raises ValueError on a non-dict body or an
    unknown event (routes map that to a 400)."""
    if not isinstance(data, dict):
        raise ValueError("report must be a JSON object")
    if data.get("event") not in _REPORT_EVENTS:
        raise ValueError("bad event")
    report = {}
    for key in _REPORT_KEYS:
        if key in data:
            report[key] = _cap_strings(data[key])
    rows = []
    peers = data.get("peers")
    if isinstance(peers, list):
        for row in peers:
            if not isinstance(row, dict):
                continue
            rows.append({"ip": str(row.get("ip", ""))[:64],
                         "rx_bytes": _peer_int(row.get("rx_bytes")),
                         "tx_bytes": _peer_int(row.get("tx_bytes")),
                         "avg_bps": _peer_int(row.get("avg_bps"))})
            if len(rows) >= _REPORT_PEER_ROWS:
                break
    report["peers"] = rows
    # Hard per-report bound (spec §6: ring of 5 × ≤16 KB per device). The
    # 64 KiB transport cap bounds the wire body; this bounds what we STORE —
    # key-count in nested sections is otherwise uncapped.
    if len(json.dumps(report)) > 16384:
        raise ValueError("report too large")
    return report


class CatalogStore:
    TELEMETRY_RING = 5      # newest reports kept per device (hard disk bound)
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

    # --- policy (install-approval gate) ---
    def set_policy(self, device_id, approved_image_id=None, install_allowed=False):
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
        received_at.  Evicts the oldest beyond the ring bound, then clears
        any pending pull directive — the report IS the directive's answer
        (or supersedes it)."""
        report = dict(report)
        report["received_at"] = time.time()
        with secrets_store.store_lock(self.telemetry_path):
            tel = self._read(self.telemetry_path)
            ring = tel.get(device_id)
            ring = ring if isinstance(ring, list) else []
            ring.append(report)
            tel[device_id] = ring[-self.TELEMETRY_RING:]
            _atomic_write_json(self.telemetry_path, tel)
        self.clear_report_request(device_id)

    def get_telemetry(self, device_id):
        reports = self._read(self.telemetry_path).get(device_id, [])
        return reports if isinstance(reports, list) else []

    # --- pull directives (console-requested fresh reports) ---
    def request_report(self, device_id, now):
        """Flag *device_id* for a fresh report.  Returns False when a
        non-expired directive is already pending (one per device)."""
        with secrets_store.store_lock(self.pull_path):
            pr = self._read(self.pull_path)
            ent = pr.get(device_id)
            if isinstance(ent, dict) and now < ent.get("expires_at", 0):
                return False
            pr[device_id] = {"requested_at": now,
                             "expires_at": now + self.PULL_TTL}
            _atomic_write_json(self.pull_path, pr)
            return True

    def pending_report(self, device_id, now):
        """True when a non-expired pull directive exists for *device_id*.
        Expired entries (any device) are reaped lazily here — no threads."""
        with secrets_store.store_lock(self.pull_path):
            pr = self._read(self.pull_path)
            expired = [d for d, ent in pr.items()
                       if not isinstance(ent, dict)
                       or now >= ent.get("expires_at", 0)]
            for d in expired:
                del pr[d]
            if expired:
                _atomic_write_json(self.pull_path, pr)
            return device_id in pr

    def clear_report_request(self, device_id):
        with secrets_store.store_lock(self.pull_path):
            pr = self._read(self.pull_path)
            if pr.pop(device_id, None) is not None:
                _atomic_write_json(self.pull_path, pr)


class Catalog:
    def __init__(self, store, secrets_path,
                 audit_path=None):
        self.store = store
        self.secrets_path = secrets_path
        self.audit_path = (audit_path
                           or os.environ.get("IRIS_AUDIT",
                                             "/etc/iris/audit.jsonl"))

    def _load_store(self):
        """Load the secrets store fresh from disk; return (store_dict, index)."""
        store_dict = secrets_store.load(self.secrets_path)
        index = secrets_store.build_index(store_dict)
        return store_dict, index

    def route_get(self, path):
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
            try:
                with open(self.store.torrent_path(image_id), "rb") as f:
                    return (200, "application/x-bittorrent", f.read())
            except OSError:
                return self._json(404, {"error": "no such torrent"})
        if parts == ["v1", "devices"]:
            return self._json(200, {"devices": self.store.list_devices()})
        if len(parts) == 4 and parts[:2] == ["v1", "devices"] \
                and parts[3] == "policy":
            return self._json(200, self.store.get_policy(parts[2]))
        return self._json(404, {"error": "not found"})

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
                # The heartbeat's source IP is the agent's Guest Shell IP — the
                # SAME IP it announces to the tracker with — so the swarm map can
                # join this device's model onto its swarm peer by IP.
                "swarm_ip": src_ip,
            })
            resp = {"ok": True}
            if self.store.pending_report(parts[2], time.time()):
                resp["report_requested"] = True
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
                audit_path=None):
    cat = Catalog(store, secrets_path, audit_path=audit_path)

    grace = int(os.environ.get("IRIS_TOKEN_SKEW_GRACE", "300"))

    class Handler(BaseHTTPRequestHandler):
        def _guard(self, parts, token):
            """Route-aware guard.

            Device-bound routes (heartbeat, token-refresh, telemetry): require
            auth.authorize(..., parts[2], "catalog", ...).

            Shared routes (images, torrents, devices-list, policy): require
            any valid catalog-scoped record.
            """
            store_dict, index = cat._load_store()
            now = time.time()

            # Determine if this is a device-bound route
            is_device_bound = (
                len(parts) == 4
                and parts[:2] == ["v1", "devices"]
                and parts[3] in ("heartbeat", "token-refresh", "telemetry")
            )

            if is_device_bound:
                device_id = parts[2]
                ok = auth.authorize(
                    index, store_dict, token, device_id, "catalog", now, grace)
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
                    return None, None

                return store_dict, index

            # Shared route: accept any valid catalog token.
            # NOTE: a rolled-old token (catalog_token_prev) works here because
            # record_for finds it in the index and its _scope=="catalog".  It is
            # rejected on device-bound routes above because auth.authorize only
            # matches SECRET_TYPES entries, and catalog_token_prev has no entry
            # there — that asymmetry is intentional (overlap window applies to
            # non-device-bound reads only).
            result = secrets_store.record_for(index, store_dict, token)
            if result is None:
                return None, None
            _, secret_name, record = result
            # Accept catalog_token (via SECRET_TYPES) or catalog_token_prev
            # (stashed by _handle_token_refresh for the overlap window).
            stype = secrets_store.SECRET_TYPES.get(secret_name, {})
            scope = stype.get("scope") or record.get("_scope", "")
            if scope != "catalog":
                return None, None
            if not secrets_store.valid(record, now, grace):
                return None, None
            return store_dict, index

        def _extract_token(self):
            value = self.headers.get("Authorization", "")
            prefix = "Bearer "
            if not value.startswith(prefix):
                return None
            return value[len(prefix):]

        def _send(self, triple):
            status, ctype, body = triple
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            token = self._extract_token()
            if not token:
                self._send((401, "application/json",
                            json.dumps({"error": "unauthorized"}).encode()))
                return
            parts = self.path.strip("/").split("/")
            store_dict, index = self._guard(parts, token)
            if store_dict is None:
                self._send((401, "application/json",
                            json.dumps({"error": "unauthorized"}).encode()))
                return
            self._send(cat.route_get(self.path))

        def do_POST(self):
            token = self._extract_token()
            if not token:
                self._send((401, "application/json",
                            json.dumps({"error": "unauthorized"}).encode()))
                return
            parts = self.path.strip("/").split("/")
            store_dict, index = self._guard(parts, token)
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
                    body = gzip.decompress(body)
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
    store = CatalogStore(os.environ.get("IRIS_STATE", "/var/lib/iris"))
    secrets_path = os.environ.get("IRIS_SECRETS", "/run/iris/secrets.json")
    cert = os.environ.get("IRIS_CERT", "/etc/iris/tls/cert.pem")
    certfile = cert if os.path.exists(cert) else None
    srv = make_server(host, port, store, secrets_path, certfile=certfile)
    scheme = "https" if certfile else "http"
    print("catalog on %s://%s:%d/v1/images" % (scheme, host, port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
