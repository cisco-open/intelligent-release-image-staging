# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""HTTPS client for the IRIS catalog (Phase 1 server). Bearer auth.
Lab uses a self-signed cert, so the agent passes an unverified SSL context;
PRODUCTION should pin the server cert instead. Stdlib only."""
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


class CatalogError(Exception):
    pass


class CatalogClient:
    def __init__(self, base_url, token, context=None):
        self.base = base_url.rstrip("/")
        self.token = token
        self.context = context     # ssl.SSLContext for https; None for http/tests
        # RTT samples (ms) from successful catalog calls. Neither variant can
        # ICMP-probe (no ping binary in the IOx container; IOS ping over
        # SSH-to-self costs seconds), so timed HTTPS calls are the agent's
        # only link probe. Drained once per tick via drain_rtts().
        self.rtt_ms_log = []

    def _req(self, method, path, body=None, data=None, extra_headers=None):
        # body: dict to JSON-encode. data: pre-encoded bytes sent as-is
        # (e.g. a gzipped telemetry report) -- callers pass one or the
        # other, never both. extra_headers: merged over the defaults.
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
                status, payload = r.status, r.read()
            # Successful round trip: record the RTT for link classification.
            # HTTPError/URLError paths record nothing -- failures feed the
            # heartbeat fail_streak instead, never the RTT median.
            self.rtt_ms_log.append((time.monotonic() - started) * 1000.0)
            del self.rtt_ms_log[:-RTT_LOG_MAX]        # keep the newest 16
            return status, payload
        except urllib.error.HTTPError as e:
            return e.code, e.read()
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

    def download_torrent(self, image_id, dest_path):
        status, body = self._req("GET", "/v1/torrents/%s.torrent" % image_id)
        if status != 200:
            raise CatalogError("torrent %s -> HTTP %d" % (image_id, status))
        # Write to a sibling tmp then os.replace() over dest_path, so a crash
        # mid-write never leaves a truncated/0-byte .torrent. The agent only
        # re-downloads when file_size(torrent) is None (iris_agent.run_once),
        # so a partial file would be treated as already-present and fed to
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
