# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""HTTPS client for the IRIS catalog (Phase 1 server). Bearer auth.
The `context` the agent passes is the VERIFYING ssl.SSLContext built by
iris_agent.make_catalog_context from the pinned catalog_ca (chain + hostname
/ IP-SAN checks); that builder fails closed and never falls back to an
unverified context. `context=None` exists for plain-http unit tests only.
Stdlib only."""
import calendar
import email.utils
import gzip
import json
import os
import time
import urllib.error
import urllib.request

# gzip telemetry bodies strictly larger than this many bytes; mirrors
# telemetry_report.GZIP_MIN (kept local -- this module never imports the
# agent-side telemetry module).
GZIP_MIN = 1024
# keep only the newest N request RTT samples (drained once per agent tick)
RTT_LOG_MAX = 16

# Catalog JSON is deliberately small; torrent metainfo is larger but still tiny
# compared with the image it describes.  Endpoint-specific caps keep a broken
# proxy/captive portal from exhausting the 512 MB device before we parse/write.
JSON_RESPONSE_MAX = 64 * 1024
TORRENT_RESPONSE_MAX = 4 * 1024 * 1024
ERROR_RESPONSE_MAX = 64 * 1024
INSTRUCTION_RESPONSE_MAX = 256 * 1024
INSTRUCTION_KEYLIST_RESPONSE_MAX = 128 * 1024
TRACKER_BEARER_NEGOTIATION_HEADER = "X-IRIS-Tracker-Auth"


class CatalogError(Exception):
    pass


class CatalogClient:
    def __init__(self, base_url, token, context=None, tracker_bearer=False):
        self.base = base_url.rstrip("/")
        self.token = token
        self.context = context     # ssl.SSLContext for https; None for http/tests
        # Unified IOx/XR containers opt into token-free torrent metainfo. The
        # default is deliberately false so existing Guest Shell bundles keep
        # their byte-identical request and receive legacy query-auth metainfo.
        self.tracker_bearer = tracker_bearer
        # RTT samples (ms) from successful catalog calls. Neither variant can
        # ICMP-probe (no ping binary in the IOx container; IOS ping over
        # SSH-to-self costs seconds), so timed HTTPS calls are the agent's
        # only link probe. Drained once per tick via drain_rtts().
        self.rtt_ms_log = []
        # The most recent strict IMF-fixdate on a successful authenticated
        # response.  Consumers apply their own persisted monotonic/regression
        # rules; this value deliberately records the response Date as received.
        self.last_authenticated_date = None
        # Per-call signal used when a response's payload (such as a policy
        # hint) must be authenticated by that same response Date.  Unlike the
        # cumulative value above, this resets before every request.
        self.response_authenticated_date = None

    @staticmethod
    def _read_limited(response, limit):
        length = response.headers.get("Content-Length")
        if length is not None:
            try:
                if int(length) > limit:
                    raise CatalogError("catalog response exceeds %d bytes" % limit)
            except ValueError:
                pass
        chunks = []
        total = 0
        while True:
            chunk = response.read(min(64 * 1024, limit - total + 1))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise CatalogError("catalog response exceeds %d bytes" % limit)

    @staticmethod
    def _authenticated_date(headers):
        if headers is None:
            return None
        get_all = getattr(headers, "get_all", None)
        if get_all is not None:
            values = get_all("Date") or []
        else:
            value = headers.get("Date")
            values = [] if value is None else [value]
        if len(values) != 1 or not isinstance(values[0], str):
            return None
        value = values[0]
        try:
            parsed = email.utils.parsedate_to_datetime(value)
            if parsed is None or parsed.utcoffset() is None:
                return None
            timestamp = calendar.timegm(parsed.utctimetuple())
            if email.utils.formatdate(timestamp, usegmt=True) != value:
                return None
        except (OSError, TypeError, ValueError, OverflowError):
            return None
        return value, timestamp

    @classmethod
    def _headers_dict(cls, headers):
        if headers is None:
            return {}
        result = {name: value for name, value in headers.items()
                  if name.lower() != "date"}
        observed = cls._authenticated_date(headers)
        if observed is not None:
            result["Date"] = observed[0]
        return result

    def _observe_authenticated_date(self, headers):
        observed = self._authenticated_date(headers)
        if observed is not None:
            self.response_authenticated_date = observed[1]
            self.last_authenticated_date = observed[1]

    def _req(self, method, path, body=None, data=None, extra_headers=None,
             max_response_bytes=JSON_RESPONSE_MAX, return_headers=False):
        # body: dict to JSON-encode. data: pre-encoded bytes sent as-is
        # (e.g. a gzipped telemetry report) -- callers pass one or the
        # other, never both. extra_headers: merged over the defaults.
        self.response_authenticated_date = None
        url = self.base + path
        if data is None:
            data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": "Bearer " + self.token}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        started = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=15, context=self.context) as r:
                status = r.status
                payload = self._read_limited(r, max_response_bytes)
                response_headers = self._headers_dict(r.headers)
                if 200 <= status <= 299:
                    self._observe_authenticated_date(r.headers)
            # Successful round trip: record the RTT for link classification.
            # HTTPError/URLError paths record nothing -- failures feed the
            # heartbeat fail_streak instead, never the RTT median.
            self.rtt_ms_log.append((time.monotonic() - started) * 1000.0)
            del self.rtt_ms_log[:-RTT_LOG_MAX]        # keep the newest 16
            result = (status, payload, response_headers)
            return result if return_headers else result[:2]
        except urllib.error.HTTPError as e:
            limit = max_response_bytes if e.code == 304 else ERROR_RESPONSE_MAX
            payload = self._read_limited(e, limit)
            if e.code == 304:
                if payload:
                    raise CatalogError("catalog HTTP 304 response has a body")
                self._observe_authenticated_date(e.headers)
            result = (e.code, payload, self._headers_dict(e.headers))
            return result if return_headers else result[:2]
        except urllib.error.URLError as e:
            raise CatalogError("catalog unreachable: %s" % e)

    def drain_rtts(self):
        # Return the RTT samples (ms) collected since the last drain and
        # clear the log; the agent moves them into state['link']['rtt_ms']
        # once per tick. Returns a copy -- the caller may mutate it.
        out = list(self.rtt_ms_log)
        del self.rtt_ms_log[:]
        return out

    def get_policy(self, device_id):
        status, body = self._req("GET", "/v1/devices/%s/policy" % device_id)
        if status == 200:
            return json.loads(body)
        raise CatalogError("policy %s -> HTTP %d" % (device_id, status))

    def get_image(self, image_id):
        status, body = self._req("GET", "/v1/images/%s" % image_id)
        if status == 404:
            return None
        if status == 200:
            return json.loads(body)
        raise CatalogError("image %s -> HTTP %d" % (image_id, status))

    def _get_binary(self, path, etag, limit):
        headers = None
        if etag is not None:
            if not isinstance(etag, str) or not etag or any(
                    character in etag for character in ("\x00", "\r", "\n")):
                raise CatalogError("invalid catalog ETag")
            headers = {"If-None-Match": etag}
        return self._req(
            "GET", path, extra_headers=headers, max_response_bytes=limit,
            return_headers=True)

    def get_instructions(self, device_id, etag=None):
        return self._get_binary(
            "/v1/devices/%s/instructions" % device_id, etag,
            INSTRUCTION_RESPONSE_MAX)

    def get_instruction_keylist(self, device_id, etag=None):
        return self._get_binary(
            "/v1/devices/%s/instruction-keylist" % device_id, etag,
            INSTRUCTION_KEYLIST_RESPONSE_MAX)

    def download_torrent(self, image_id, dest_path):
        extra_headers = None
        if self.tracker_bearer:
            extra_headers = {TRACKER_BEARER_NEGOTIATION_HEADER: "bearer"}
        status, body = self._req(
            "GET", "/v1/torrents/%s.torrent" % image_id,
            extra_headers=extra_headers,
            max_response_bytes=TORRENT_RESPONSE_MAX)
        if status != 200:
            raise CatalogError("torrent %s -> HTTP %d" % (image_id, status))
        # Write to a sibling tmp then os.replace() over dest_path, so a crash
        # mid-write never leaves a truncated/0-byte .torrent. The agent only
        # re-downloads when file_size(torrent) is None or the catalog's
        # torrent identity moved (iris_agent._stage_image), so a partial file
        # would be treated as already-present and fed to
        # aria2 (which rejects it) -> a silent permanent stall. The rename is
        # atomic, so a present .torrent is always complete. Matches
        # agent_config.write_conf's atomic-write pattern. Stdlib only.
        tmp = dest_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.replace(tmp, dest_path)
        except OSError:
            try:
                os.remove(tmp)            # don't leak the tmp on a failed rename
            except OSError:
                pass
            raise
        return dest_path

    def heartbeat(self, device_id, data):
        status, body = self._req(
            "POST", "/v1/devices/%s/heartbeat" % device_id, body=data)
        if status != 200:
            raise CatalogError("heartbeat %s -> HTTP %d" % (device_id, status))
        return json.loads(body)

    def post_telemetry(self, device_id, report):
        # POST a device telemetry report (issue #13). ASCII JSON body; when
        # it exceeds GZIP_MIN bytes it is gzip-compressed and flagged with
        # Content-Encoding: gzip so a constrained WAN link never carries a
        # fat per-peer table verbatim (the catalog decodes + re-checks size).
        # Bearer auth + pinned-TLS context via _req, exactly like heartbeat.
        # Raises CatalogError on non-200; the agent's never-raise guard wraps
        # this at the call site (same invariant as _send_heartbeat).
        data = json.dumps(report).encode("ascii")
        extra_headers = None
        if len(data) > GZIP_MIN:
            data = gzip.compress(data)
            extra_headers = {"Content-Encoding": "gzip"}
        status, body = self._req(
            "POST", "/v1/devices/%s/telemetry" % device_id,
            data=data, extra_headers=extra_headers)
        if status != 200:
            raise CatalogError("telemetry %s -> HTTP %d" % (device_id, status))
        return json.loads(body)

    def refresh_token(self, device_id):
        # POST the device's current Bearer to mint a fresh catalog token; the
        # response is the device's full current secret bag (new catalog_token +
        # expires_at, plus the unrotated announce_token / rpc_secret). Reuses
        # _req, so it goes over the SAME pinned-TLS context the client was built
        # with (verify-if-present, set in make_catalog_context).
        status, body = self._req(
            "POST", "/v1/devices/%s/token-refresh" % device_id, body={})
        if status == 200:
            return json.loads(body)
        raise CatalogError("token-refresh %s -> HTTP %d" % (device_id, status))
