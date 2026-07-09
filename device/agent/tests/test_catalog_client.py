# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import gzip
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import catalog_client


class _Stub(BaseHTTPRequestHandler):
    def _auth(self):
        return self.headers.get("Authorization") == "Bearer tok"

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._auth():
            return self._send(401, b'{"error":"unauthorized"}')
        if self.path == "/v1/devices/sw1/policy":
            self._send(200, b'{"approved_image_id":"img1","install_allowed":false}')
        elif self.path == "/v1/images/img1":
            self._send(200, b'{"id":"img1","filename":"img1.bin","size":5,'
                            b'"sha256":"abc","info_hash_hex":"dd"}')
        elif self.path == "/v1/images/none":
            self._send(404, b'{"error":"no such image"}')
        elif self.path == "/v1/torrents/img1.torrent":
            self._send(200, b"TORRENTBYTES", "application/x-bittorrent")
        else:
            self._send(404, b'{}')

    def do_POST(self):
        if not self._auth():
            return self._send(401, b'{}')
        n = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(n)
        if self.path == "/v1/devices/sw1/token-refresh":
            return self._send(200, b'{"catalog_token":"newtok",'
                                   b'"expires_at":1750000000,'
                                   b'"announce_token":"anntok",'
                                   b'"rpc_secret":"rpcsecret"}')
        self._send(200, b'{"ok":true}')

    def log_message(self, *a):
        pass


class _TeleStub(_Stub):
    """Stub that records the raw wire bytes + headers of the last telemetry
    POST, so tests can assert exactly what left the client (plain vs gzip).
    `captured` is a class attribute because the HTTP server builds a fresh
    handler instance per request; the fixture resets it between tests."""
    captured = None

    def do_POST(self):
        if not self._auth():
            return self._send(401, b'{}')
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n)
        if self.path.startswith("/v1/devices/") and \
                self.path.endswith("/telemetry"):
            _TeleStub.captured = {
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "content_type": self.headers.get("Content-Type"),
                "content_encoding": self.headers.get("Content-Encoding"),
                "body": raw,
            }
            return self._send(200, b'{"ok":true,"stored":1}')
        self._send(200, b'{"ok":true}')


@pytest.fixture
def client():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    yield catalog_client.CatalogClient(base, "tok")
    srv.shutdown()


@pytest.fixture
def tele_client():
    _TeleStub.captured = None
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _TeleStub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    yield catalog_client.CatalogClient(base, "tok")
    srv.shutdown()


def test_get_policy(client):
    assert client.get_policy("sw1") == {"approved_image_id": "img1",
                                        "install_allowed": False}


def test_get_image_and_404(client):
    assert client.get_image("img1")["sha256"] == "abc"
    assert client.get_image("none") is None


def test_download_torrent(client, tmp_path):
    dest = tmp_path / "img1.torrent"
    client.download_torrent("img1", str(dest))
    assert dest.read_bytes() == b"TORRENTBYTES"


def test_heartbeat(client):
    assert client.heartbeat("sw1", {"version": "17.18"}) == {"ok": True}


def test_unauthorized_raises():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    c = catalog_client.CatalogClient(base, "WRONG")
    with pytest.raises(catalog_client.CatalogError):
        c.get_policy("sw1")
    srv.shutdown()


def test_refresh_token_posts_and_returns_secret_bag(client):
    bag = client.refresh_token("sw1")
    assert bag == {"catalog_token": "newtok", "expires_at": 1750000000,
                   "announce_token": "anntok", "rpc_secret": "rpcsecret"}


def test_download_torrent_is_atomic_no_truncated_file_on_interrupt(
        client, tmp_path, monkeypatch):
    """MINOR 29: an interrupted .torrent download must NOT leave a truncated
    file at dest_path. The agent only re-downloads when file_size(torrent) is
    None, so a 0-byte/partial .torrent left behind would be treated as
    already-present and fed to aria2 (which rejects it) -> permanent stall.

    Simulate a crash mid-write by making the final rename/replace raise after
    the body is fetched; dest_path must be absent (or unchanged), never a
    half-written file."""
    dest = tmp_path / "img1.torrent"

    # Force the atomic-finalize step to blow up, mimicking a crash after the
    # body was fetched but before dest_path was put in place.
    def boom(src, dst):
        raise OSError("simulated crash before rename")

    monkeypatch.setattr(catalog_client.os, "replace", boom)
    try:
        client.download_torrent("img1", str(dest))
    except OSError:
        pass
    # the destination path must NOT hold a truncated/partial file
    assert not dest.exists(), \
        "interrupted download left a file at dest_path (should be atomic)"
    # and the .tmp sibling must be cleaned up so it doesn't accumulate on the
    # switch's constrained flash across repeated rename failures.
    assert not (tmp_path / "img1.torrent.tmp").exists(), \
        "failed rename left an orphan .tmp sibling on flash"


def test_download_torrent_cleans_tmp_on_failed_rename(client, tmp_path,
                                                      monkeypatch):
    """Directly target the cleanup guard: when os.replace raises, the .tmp
    sibling must be removed (no orphan .tmp leak on constrained switch flash),
    and the original OSError must still propagate to the caller. This fails if
    the `except OSError: os.remove(tmp)` block in download_torrent is removed."""
    dest = tmp_path / "img1.torrent"
    tmp = tmp_path / "img1.torrent.tmp"

    def boom(src, dst):
        raise OSError("simulated rename failure (e.g. ENOSPC)")

    monkeypatch.setattr(catalog_client.os, "replace", boom)
    with pytest.raises(OSError):
        client.download_torrent("img1", str(dest))
    assert not tmp.exists(), "orphan .tmp sibling left after failed rename"
    assert not dest.exists()


def test_download_torrent_overwrites_atomically(client, tmp_path):
    """A pre-existing (stale/truncated) .torrent at dest_path is fully replaced
    by a complete download — the dest never passes through a 0-byte state that
    the presence check would mistake for 'already there'."""
    dest = tmp_path / "img1.torrent"
    dest.write_bytes(b"")                      # stale 0-byte leftover
    client.download_torrent("img1", str(dest))
    assert dest.read_bytes() == b"TORRENTBYTES"


def test_refresh_token_non_200_raises():
    class _Deny(_Stub):
        def do_POST(self):
            self._send(500, b'{"error":"boom"}')

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Deny)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    c = catalog_client.CatalogClient(base, "tok")
    with pytest.raises(catalog_client.CatalogError):
        c.refresh_token("sw1")
    srv.shutdown()


def test_rtt_log_starts_empty_and_records_successful_requests(client):
    """Every successful catalog HTTPS call appends its round-trip time (ms)
    to rtt_ms_log -- the agent's only link probe (no ICMP on either
    variant)."""
    assert client.rtt_ms_log == []
    client.heartbeat("sw1", {"version": "17.18"})
    assert len(client.rtt_ms_log) == 1
    client.get_policy("sw1")
    assert len(client.rtt_ms_log) == 2
    assert all(isinstance(v, float) and v >= 0.0 for v in client.rtt_ms_log)


def test_rtt_log_skips_non_2xx_responses(client):
    """Only *successful* round trips are sampled: a 404 goes down the
    HTTPError path in _req and must not append an RTT sample."""
    assert client.get_image("none") is None      # 404 handled, no raise
    assert client.rtt_ms_log == []


def test_rtt_log_capped_at_16(client):
    for _ in range(20):
        client.heartbeat("sw1", {"v": 1})
    assert len(client.rtt_ms_log) == 16          # newest 16 kept, oldest dropped


def test_drain_rtts_returns_copy_and_clears(client):
    for _ in range(3):
        client.heartbeat("sw1", {"v": 1})
    got = client.drain_rtts()
    assert len(got) == 3
    assert all(isinstance(v, float) for v in got)
    assert client.rtt_ms_log == []               # cleared by the drain
    got.append(999.0)                            # caller owns the copy...
    assert client.rtt_ms_log == []               # ...client state untouched
    assert client.drain_rtts() == []             # nothing left to drain


def test_post_telemetry_small_body_plain_json(tele_client):
    """A report under GZIP_MIN goes over the wire as plain ASCII JSON with
    Bearer auth -- byte-exact, no Content-Encoding header."""
    report = {"ts": 1783000000, "image_id": "img1",
              "event": "staging-complete",
              "transfer": {"total_bytes": 5, "elapsed_s": 1, "avg_bps": 5,
                           "sha_ok": True, "stage_state": "ready"},
              "link": {"tier": "good", "rtt_ms_median": 12, "rtt_samples": 8,
                       "hb_failures": 0, "trimmed": False},
              "peers": [],
              "agent": {"version": "x", "runtime_mode": "guestshell"}}
    resp = tele_client.post_telemetry("sw1", report)
    assert resp == {"ok": True, "stored": 1}
    cap = _TeleStub.captured
    assert cap["path"] == "/v1/devices/sw1/telemetry"
    assert cap["authorization"] == "Bearer tok"
    assert cap["content_type"] == "application/json"
    assert cap["content_encoding"] is None       # small body: never gzipped
    assert cap["body"] == json.dumps(report).encode("ascii")
    assert json.loads(cap["body"]) == report


def test_post_telemetry_large_body_arrives_gzipped(tele_client):
    """A report over GZIP_MIN bytes is gzip-compressed on the wire with a
    Content-Encoding: gzip header, and decompresses to the exact JSON."""
    peers = [{"ip": "10.0.%d.%d" % (i // 250, i % 250),
              "rx_bytes": 123456789 + i, "tx_bytes": 987654 + i}
             for i in range(20)]
    report = {"ts": 1783000000, "image_id": "img1", "event": "pull",
              "peers": peers, "pad": "x" * 1200}
    raw = json.dumps(report).encode("ascii")
    assert len(raw) > 1024                       # precondition: over GZIP_MIN
    resp = tele_client.post_telemetry("sw1", report)
    assert resp == {"ok": True, "stored": 1}
    cap = _TeleStub.captured
    assert cap["content_encoding"] == "gzip"
    assert cap["authorization"] == "Bearer tok"
    assert len(cap["body"]) < len(raw)           # actually smaller on the wire
    assert gzip.decompress(cap["body"]) == raw   # exact JSON after decode
    assert json.loads(gzip.decompress(cap["body"])) == report


def test_post_telemetry_exactly_1024_bytes_stays_plain(tele_client):
    """The gzip trigger is strictly greater-than: a body of exactly GZIP_MIN
    bytes is sent plain. json.dumps({"pad": "x"*N}) is N + 11 bytes."""
    assert catalog_client.GZIP_MIN == 1024
    report = {"pad": "x" * 1013}
    raw = json.dumps(report).encode("ascii")
    assert len(raw) == 1024                      # precondition: exactly at cap
    tele_client.post_telemetry("sw1", report)
    cap = _TeleStub.captured
    assert cap["content_encoding"] is None
    assert cap["body"] == raw


def test_post_telemetry_non_200_raises_and_records_no_rtt():
    """Non-200 raises CatalogError (the agent-side never-raise wrapper lives
    in iris_agent, not here), and the failed call takes no RTT sample."""
    class _Deny(_Stub):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(n)
            self._send(500, b'{"error":"boom"}')

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Deny)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    c = catalog_client.CatalogClient(base, "tok")
    with pytest.raises(catalog_client.CatalogError):
        c.post_telemetry("sw1", {"ts": 1})
    assert c.rtt_ms_log == []                    # HTTPError path: no sample
    srv.shutdown()
