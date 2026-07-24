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
import secrets
import ssl
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, parse_qs

import audit
import gui_app
import gui_onboard

WEBROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "webroot")
COOKIE = "iris_sid"
SWARMMAP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "swarmmap.html")
# GET /swarmmap swaps this exact placeholder line in the single-source
# server/swarmmap.html for the console config line (the file on disk keeps
# working standalone; only the served copy is rewritten):
_MAP_PLACEHOLDER = "window.IRIS_MAP_CFG = null;"
_MAP_CFG_LINE = 'window.IRIS_MAP_CFG = {"swarmUrl":"/api/swarm","pull":true};'
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
_SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy",
     "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"),
]


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


def _csrf_ok(provided, expected):
    if not provided or not expected:
        return False
    return hmac.compare_digest(provided.encode("utf-8"), expected.encode("utf-8"))


def _default_swarm_fetch():
    url = os.environ.get("IRIS_SWARM_URL", "http://127.0.0.1:9101/swarm")
    with urllib.request.urlopen(url, timeout=3) as r:
        return r.read()


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


def make_server(host, port, app, images=None, fleet=None, creds=None, catalog=None,
                 onboard=None, swarm_fetch=None, certfile=None, audit_path=None,
                 receipts=None):
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
            if attachment not in ("routed", "inband"):
                raise ValueError("unknown network attachment")
            platform = gui_onboard.resolve_platform(device)
            network = {
                "attachment": attachment,
                "iris_vlan": device.get("iris_vlan", device.get("vlan", "")),
                "svi_ip": device.get("svi_ip", ""),
                "svi_mask": device.get("svi_mask", ""),
                "app_ip": device.get("app_ip", device.get("guest_ip", "")),
                "app_mask": device.get("app_mask", device.get("svi_mask", "")),
                "app_gateway": device.get("app_gateway", device.get("svi_ip", "")),
                "inband_vlan": device.get("inband_vlan", ""),
                # The inband IOx app reaches IOS at the switch's management IP
                # (which is on the same existing management VLAN); ios_ssh_host is
                # an optional advanced override for asymmetric topologies.
                "ios_ssh_host": (device.get("ios_ssh_host")
                                 or (device.get("device_ip", "") if attachment == "inband" else "")),
                "model": device.get("model", ""),
                "platform": platform,
                "renderer": "v1",
            }
            plan = {"device_id": device_id, "inventory_revision": fleet.revision(),
                    "resolved": network,
                    "ownership": ("preserves existing VLAN, SVI, gateway, routes, and VRF"
                                  if attachment == "inband" else
                                  "creates only a clean IRIS-owned VLAN and SVI")}
            plan["plan_hash"] = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
            return plan

        @staticmethod
        def _owned_resources(resolved):
            """Resources IRIS may later remove, per attachment. Inband owns only
            the app; it never claims the operator's VLAN/SVI."""
            resources = [{"kind": "guestshell", "ownership": "iris-created"}]
            if resolved.get("attachment") == "routed":
                resources = [
                    {"kind": "vlan", "ownership": "iris-created",
                     "id": resolved.get("iris_vlan", "")},
                    {"kind": "svi", "ownership": "iris-created",
                     "ip": resolved.get("svi_ip", "")},
                ] + resources
            return resources

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
            html = html.replace(_MAP_PLACEHOLDER, _MAP_CFG_LINE)
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
                    self._json(200, {"images": images.list_images()})
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
                reports = catalog.get_telemetry(did) if catalog else []
                self._json(200, {"reports": reports}); return
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
            if path == "/swarmmap":
                if app.session_info(self._sid()) is None:
                    self._json(401, {"error": "unauthorized"}); return
                self._serve_swarmmap(); return
            if path == "/api/settings":
                info = app.session_info(self._sid())
                if info is None:
                    self._json(401, {"error": "unauthorized"}); return
                self._json(200, self._settings_info(info["username"])); return
            if path in ("/", "/index.html", "/login.html") and app.needs_setup():
                self._serve_static("/setup.html"); return
            self._serve_static(path)

        def _device_view(self):
            devs = fleet.list_devices() if fleet else []
            hb = {d.get("device_id"): d for d in (catalog.list_devices()
                                                  if catalog else [])}
            # each device's latest onboard/undeploy job, so the UI can show
            # "onboarding…" / "waiting for heartbeat" instead of a misleading
            # "not enrolled" before the fresh agent's first heartbeat lands
            jobs = onboard.latest_jobs_by_device() if onboard else {}
            out = []
            for d in devs:
                did = d.get("device_id")
                pol = catalog.get_policy(did) if catalog else {}
                h = hb.get(did, {})
                row = dict(d)
                row["assigned_image_id"] = pol.get("approved_image_id")
                row["last_seen"] = h.get("last_seen")
                row["stage_state"] = h.get("stage_state")
                row["stage_error"] = h.get("stage_error")
                row["current_image_id"] = h.get("current_image_id")
                row["heartbeat_model"] = h.get("model")
                j = jobs.get(did)
                if j:
                    row["onboard_action"] = j["action"]
                    row["onboard_state"] = j["state"]
                    row["onboard_finished_at"] = j["finished_at"]
                out.append(row)
            return out

        @staticmethod
        def _awaiting_heartbeat(row):
            """True when the device finished an ONBOARD but no heartbeat has
            arrived since — the agent is still bootstrapping on-box."""
            return (row.get("onboard_action") == "onboard"
                    and row.get("onboard_state") == "done"
                    and (row.get("last_seen") is None
                         or row["last_seen"] < (row.get("onboard_finished_at") or 0)))

        def _overview(self):
            imgs = catalog.list_images() if catalog else []
            devs = fleet.list_devices() if fleet else []
            hb = {d.get("device_id"): d for d in (catalog.list_devices()
                                                  if catalog else [])}
            pol = catalog.list_policies() if catalog else {}
            rollout = []
            for img in imgs:
                iid = img.get("id")
                assigned = [d for d in devs
                            if pol.get(d.get("device_id"), {}).get(
                                "approved_image_id") == iid]
                staged = [d for d in assigned
                          if hb.get(d.get("device_id"), {}).get(
                              "stage_state") == "ready"
                          and hb.get(d.get("device_id"), {}).get(
                              "current_image_id") == iid]
                rollout.append({"image_id": iid, "filename": img.get("filename"),
                                "assigned": len(assigned), "staged": len(staged)})
            assigned_total = sum(r["assigned"] for r in rollout)
            staged_total = sum(r["staged"] for r in rollout)
            # devices freshly onboarded whose agent hasn't heartbeated yet —
            # surfaced so an operator doesn't read the gap as "undeployed"
            awaiting = sum(1 for row in self._device_view()
                           if self._awaiting_heartbeat(row))
            return {
                "images": len(imgs), "devices": len(devs),
                "assigned": assigned_total, "staged": staged_total,
                "staging_now": assigned_total - staged_total,
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

        def do_PUT(self):
            path = self.path.split("?", 1)[0]
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
                src_ip = self.client_address[0]
                res = app.login(username, str(data.get("password", "")))
                if res is None:
                    self._audit("login_fail", "auth", action="login",
                               actor="console:" + username, result="fail",
                               detail="invalid credentials", src_ip=src_ip)
                    self._json(401, {"error": "invalid credentials"})
                    return
                sid, csrf = res
                self._audit("login", "auth", action="login",
                           actor="console:" + username, result="ok", src_ip=src_ip)
                cookie = "%s=%s; HttpOnly; Secure; SameSite=Strict; Path=/" % (COOKIE, sid)
                self._json(200, {"username": username, "csrf": csrf},
                           extra_headers=[("Set-Cookie", cookie)])
                return

            if path == "/api/setup":
                if not app.needs_setup():
                    self._json(409, {"error": "already set up"}); return
                data = self._json_body(raw)
                if data is None:
                    return
                user = str(data.get("username", "")).strip()
                pw = str(data.get("password", ""))
                if not user or not pw:
                    self._json(400, {"error": "username and password required"})
                    return
                app.set_admin(user, pw)
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
                        saved.get("device_ip"), saved.get("vlan") or "-",
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
                image_id = str(body.get("image_id", ""))
                entry = catalog.get_image(image_id) if catalog is not None else None
                if entry is None:
                    self._json(400, {"error": "no such image"}); return
                old = catalog.get_policy(did).get("approved_image_id")
                catalog.set_policy(did, approved_image_id=image_id)  # install_allowed stays False (stage-only)
                detail = "assigned %s (%s) id=%s" % (
                    entry.get("filename"), _fmt_bytes(entry.get("size")), image_id)
                if old and old != image_id:
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
                if plat and plat not in ("guestshell", "iox"):
                    self._json(400, {"error": "platform must be empty, "
                                     "guestshell, or iox"}); return
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
                # Reject unknown devices HERE, before start() creates a job +
                # parked worker thread — junk ids must not accumulate either.
                if fleet is not None and fleet.get_device(did) is None:
                    self._json(404, {"error": "no such device"}); return
                resolved = None
                receipt_ref = {}
                prepare = None
                if act == "onboard":
                    # With a receipt store (always in production via main()), an
                    # onboard resolves an immutable plan and records a receipt.
                    # Without one (embedded/degraded), it stays one-click legacy.
                    if receipts is not None:
                        device = fleet.get_device(did)
                        try:
                            plan = self._plan(did, device)
                        except ValueError as exc:
                            self._json(409, {"error": str(exc)}); return
                        resolved = plan["resolved"]

                        def prepare():
                            # Runs under the onboard job lock only when a genuinely
                            # new job is registered, so a concurrent double-onboard
                            # cannot leave an orphan planned receipt.
                            rid = receipts.create({"controller_id": "iris",
                                "device_id": did, "inventory_revision": fleet.revision(),
                                "plan_hash": plan["plan_hash"], "resolved": plan["resolved"],
                                "preflight": {"status": "pending"},
                                "resources": self._owned_resources(plan["resolved"])})["receipt_id"]
                            receipt_ref["id"] = rid
                            return rid
                else:
                    # Undeploy renders exclusively from an active receipt so a
                    # post-deploy inventory edit cannot retarget cleanup. Without
                    # a receipt store, fall back to legacy fleet-driven teardown.
                    if receipts is not None:
                        try:
                            receipt = receipts.active_for_device(did)
                        except ValueError as exc:
                            # duplicate actives should be impossible (activation
                            # supersedes siblings; startup collapses legacy dupes)
                            # — but surface the reason instead of a 500 if not.
                            self._json(409, {"error": str(exc)}); return
                        if receipt is None:
                            self._json(409, {"error": "no active receipt; adopt the device "
                                             "first, then undeploy"}); return
                        resolved = receipt["resolved"]

                        def prepare():
                            receipt_ref["id"] = receipt["receipt_id"]
                            return receipt["receipt_id"]
                try:
                    jid = onboard.start(did, action=act, resolved=resolved, prepare=prepare)
                except ValueError as exc:
                    if receipt_ref.get("id") and act == "onboard":
                        receipts.transition(receipt_ref["id"], "needs-reconcile")
                    # the device is busy with the OPPOSITE action
                    self._json(409, {"error": str(exc)}); return
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
            if path.startswith("/api/devices/") and fleet is not None:
                did = unquote(path[len("/api/devices/"):])
                prev = fleet.get_device(did)
                deleted = fleet.delete(did)
                self._audit("device_delete", "device", action="delete", target=did,
                           actor=actor, result="ok" if deleted else "fail",
                           detail=("removed (ip %s, model %s)"
                                   % ((prev or {}).get("device_ip"),
                                      (prev or {}).get("model") or "-"))
                                  if deleted else "no such device")
                self._json(200, {"deleted": deleted})
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
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


def main():
    import gui_images
    import gui_fleet
    import gui_creds
    import deployment_receipts
    import catalog as catalog_mod
    host = os.environ.get("IRIS_GUI_HOST", "0.0.0.0")
    port = int(os.environ.get("IRIS_GUI_PORT", "8080"))
    secrets_path = os.environ.get("IRIS_SECRETS", "/run/iris/secrets.json")
    recipients = os.environ.get("IRIS_AGE_RECIPIENTS") or None
    secrets_enc = os.environ.get("IRIS_SECRETS_ENC", "/etc/iris/secrets.json.age")
    state_dir = os.environ.get("IRIS_STATE", "/var/lib/iris")
    images_dir = os.environ.get("IRIS_IMAGES_DIR", "/var/lib/iris-images")
    cert = os.environ.get("IRIS_CERT", "/run/iris/tls/cert.pem")
    certfile = cert if os.path.exists(cert) else None
    audit_path = os.environ.get("IRIS_AUDIT", "/etc/iris/audit.jsonl")
    app = gui_app.GuiApp(secrets_path, recipients_csv=recipients, secrets_enc=secrets_enc)

    def _bg_audit(**kw):
        # audit sink for background jobs (onboard runs, async image publishes)
        event = kw.pop("event")
        audit.append_event(audit_path, event, **kw)

    images = gui_images.ImageService(state_dir, images_dir, audit_fn=_bg_audit)
    fleet = gui_fleet.FleetStore(state_dir)
    creds = gui_creds.CredentialStore(secrets_path, recipients_csv=recipients,
                                      secrets_enc=secrets_enc)
    catalog = catalog_mod.CatalogStore(state_dir)
    receipts = deployment_receipts.ReceiptStore(state_dir)
    receipts.recover_interrupted()
    onboard = gui_onboard.OnboardService(
        fleet, creds, audit_fn=_bg_audit,
        clear_state_fn=catalog.forget_device, receipts=receipts)
    srv = make_server(host, port, app, images, fleet, creds, catalog, onboard,
                       None, certfile=certfile, audit_path=audit_path, receipts=receipts)
    scheme = "https" if certfile else "http"
    print("iris-gui on %s://%s:%d/" % (scheme, host, port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
