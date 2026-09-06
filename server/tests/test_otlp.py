# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import http.server
import json
import os
import ssl
import subprocess
import threading

import pytest

import otlp
import trust


def _attrs(record):
    return {attr["key"]: attr["value"] for attr in record["attributes"]}


def test_build_log_record_maps_core_fields():
    # design §10.8: lifecycle events map to iris.tracker.peer with typed attrs.
    rec = otlp.build_log_record({
        "event": "join", "info_hash": "abc", "peer_id": "p1",
        "ip": "10.0.0.1", "port": 6881, "left": 9, "ts": 1.5,
        "principal_type": "device", "principal_id": "iris8kv-1",
        "event_id": "beef1234"})
    assert rec["timeUnixNano"] == "1500000000"
    assert rec["eventName"] == "iris.tracker.peer"
    assert "event.id" not in rec
    assert _attrs(rec)["event.id"]["stringValue"] == "beef1234"
    attrs = {a["key"]: a["value"] for a in rec["attributes"]}
    assert attrs["iris.telemetry.schema.version"] == {"intValue": "2"}
    assert attrs["iris.principal"] == {"stringValue": "device:iris8kv-1"}
    assert attrs["iris.torrent.info_hash"] == {"stringValue": "abc"}
    assert attrs["network.peer.address"] == {"stringValue": "10.0.0.1"}
    assert attrs["iris.peer.role"] == {"stringValue": "leecher"}  # left>0
    assert "event" not in attrs


def test_build_log_record_seeder_role_when_left_zero():
    rec = otlp.build_log_record({
        "event": "complete", "info_hash": "abc", "ip": "10.0.0.1",
        "left": 0, "ts": 2, "principal_type": "device",
        "principal_id": "d1", "event_id": "x"})
    attrs = {a["key"]: a["value"] for a in rec["attributes"]}
    assert attrs["iris.peer.role"] == {"stringValue": "seeder"}


def test_payload_has_resource_service_name():
    payload = otlp.build_logs_payload([], {"service.name": "iris-tracker"})
    res = payload["resourceLogs"][0]["resource"]["attributes"]
    pairs = {a["key"]: a["value"]["stringValue"] for a in res}
    assert pairs["service.name"] == "iris-tracker"


def test_emit_then_flush_sends_all_events_in_one_request():
    sent = []
    exp = otlp.OTLPLogExporter(
        "http://collector:4318",
        sender=lambda url, body: sent.append((url, body)))
    exp.emit({"event": "join", "ip": "10.0.0.1", "ts": 0})
    exp.emit({"event": "join", "ip": "10.0.0.2", "ts": 0})
    n = exp.flush()
    assert n == 2
    assert len(sent) == 1
    url, body = sent[0]
    assert url == "http://collector:4318/v1/logs"
    text = body.decode()
    assert "10.0.0.1" in text and "10.0.0.2" in text


def test_flush_clears_queue():
    sent = []
    exp = otlp.OTLPLogExporter("http://c:4318",
                               sender=lambda u, b: sent.append(b))
    exp.emit({"event": "join", "ts": 0})
    exp.flush()
    assert exp.flush() is None   # nothing left to send (None = no attempt)
    assert len(sent) == 1


def test_queue_is_bounded_drop_oldest():
    sent = []
    exp = otlp.OTLPLogExporter("http://c:4318", max_queue=2,
                               sender=lambda u, b: sent.append(b))
    for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        exp.emit({"event": "join", "ip": ip, "ts": 0})
    exp.flush()
    text = sent[0].decode()
    assert "10.0.0.3" in text and "10.0.0.2" in text \
        and "10.0.0.1" not in text


def test_flush_empty_does_not_call_sender():
    sent = []
    exp = otlp.OTLPLogExporter("http://c:4318",
                               sender=lambda u, b: sent.append(b))
    assert exp.flush() is None   # empty queue: no attempt, nothing to report
    assert sent == []


def test_sender_failure_is_swallowed():
    def boom(url, body):
        raise OSError("collector down")
    exp = otlp.OTLPLogExporter("http://c:4318", sender=boom)
    exp.emit({"event": "join", "ts": 0})
    assert exp.flush() == 0       # swallowed; reported as 0 delivered


# --- build_report_record (device telemetry reports, design §10.8) ---

def _v2_report():
    return {
        "v": 2, "schema": "v2",
        "report_id": "7c1f0b9a2d3e4f5061728394a5b6c7d8",
        "transfer_id": "3f0a9c1d8e2b4a6f9017c3d5e7b1a2c4",
        "report_created_at": 1755743200.5,
        "image_id": "cat9k_iosxe.17.15.01.SPA.bin",
        "event": "staging-complete",
        "content": {"completed_content_bytes": 1288490188,
                    "total_content_bytes": 1288490188},
        "content_sha256": {"state": "verified", "algo": "sha256"},
        "ios_copy_verify": {"state": "ok"},
        "peers": [{"ip": "198.51.100.14"}], "peers_total": 3,
        "observed_at": 1755743190.0,
        "window": {"start": 1755743180.0, "end": 1755743195.0},
        "received_at": 1755743200.0,
    }


def _v1_report():
    return {
        "v": 1, "schema": "v1",
        "_event_id": "aa11bb22cc33dd44ee55ff6677889900",
        "ts": 1783000000,
        "image_id": "cat9k_iosxe.17.15.01.SPA.bin",
        "event": "staging-complete",
        "transfer": {"total_bytes": 1215751680, "elapsed_s": 300,
                     "avg_bps": 4052505, "sha_ok": True},
        "peers": [{"ip": "10.0.0.7"}], "peers_total": 1,
        "received_at": 1783000042.5,
    }


def test_v2_report_uses_transfer_report_name_and_received_at_event_time():
    rec = otlp.build_report_record(_v2_report(), "iris8kv-1")
    # OTLP event time = server received_at (design §8/§10.8), NOT device time.
    assert rec["timeUnixNano"] == str(int(1755743200.0 * 1e9))
    assert rec["eventName"] == "iris.device.transfer.report"
    attrs = {a["key"]: a["value"] for a in rec["attributes"]}
    assert attrs["otel.log.name"] == {
        "stringValue": "iris.device.transfer.report"}
    assert attrs["iris.telemetry.schema.version"] == {"intValue": "2"}
    assert attrs["device.id"] == {"stringValue": "iris8kv-1"}
    assert attrs["iris.image.id"] == {
        "stringValue": "cat9k_iosxe.17.15.01.SPA.bin"}
    assert attrs["iris.transfer.id"] == {
        "stringValue": "3f0a9c1d8e2b4a6f9017c3d5e7b1a2c4"}
    assert attrs["iris.report.event"] == {"stringValue": "staging-complete"}
    assert attrs["iris.transfer.content_sha256.state"] == {
        "stringValue": "verified"}
    assert attrs["iris.transfer.ios_copy_verify.state"] == {"stringValue": "ok"}
    assert attrs["iris.transfer.completed_content_bytes"] == {
        "intValue": "1288490188"}
    assert attrs["iris.device.observed_at"]["doubleValue"] == 1755743195.0
    assert attrs["iris.transfer.peers_total"] == {"intValue": "3"}
    # network.peer.address is the participation list
    row = attrs["network.peer.address"]
    assert row["arrayValue"]["values"][0] == {"stringValue": "198.51.100.14"}
    # retired ambiguous v1 attrs never appear on a v2 record
    assert "iris.transfer.throughput_avg" not in attrs
    assert "iris.link.tier" not in attrs


def test_v2_event_id_is_report_id():
    rec = otlp.build_report_record(_v2_report(), "iris8kv-1")
    assert _attrs(rec)["event.id"]["stringValue"] == "7c1f0b9a2d3e4f5061728394a5b6c7d8"


def test_v1_report_uses_distinct_name_and_safe_subset():
    rec = otlp.build_report_record(_v1_report(), "d1")
    assert rec["eventName"] == "iris.device.report"
    assert rec["timeUnixNano"] == str(int(1783000042.5 * 1e9))   # received_at
    assert _attrs(rec)["event.id"]["stringValue"] == "aa11bb22cc33dd44ee55ff6677889900"
    attrs = {a["key"]: a["value"] for a in rec["attributes"]}
    assert attrs["iris.telemetry.schema.version"] == {"intValue": "1"}
    assert attrs["device.id"] == {"stringValue": "d1"}
    assert attrs["iris.image.id"] == {
        "stringValue": "cat9k_iosxe.17.15.01.SPA.bin"}
    assert attrs["iris.report.event"] == {"stringValue": "staging-complete"}
    assert attrs["iris.transfer.peers_total"] == {"intValue": "1"}
    # ambiguous v1 fields are NOT projected as v2-named attributes (§10.8)
    for gone in ("iris.transfer.throughput_avg",
                 "iris.transfer.completed_content_bytes",
                 "iris.transfer.content_sha256.state", "iris.link.tier"):
        assert gone not in attrs, gone


def test_build_report_record_non_dict_report():
    rec = otlp.build_report_record("total garbage", "d1")
    attrs = {a["key"]: a["value"] for a in rec["attributes"]}
    assert attrs["device.id"] == {"stringValue": "d1"}
    assert rec["eventName"] == "iris.device.report"


# ---- device transfer telemetry: headers, redirect refusal, semconv wire ----

class TestHeaders:
    def test_parse(self):
        assert otlp.parse_headers("Authorization=Bearer x, X-A=1") == {
            "Authorization": "Bearer x", "X-A": "1"}
        assert otlp.parse_headers("") == {}
        assert otlp.parse_headers("garbage-no-equals") == {}

    def test_env_file_variant(self, tmp_path):
        p = tmp_path / "h"
        p.write_text("Authorization=Splunk tok\n")
        assert otlp.read_headers_env(
            {"IRIS_OTLP_HEADERS_FILE": str(p)}) == {
                "Authorization": "Splunk tok"}
        assert otlp.read_headers_env({"IRIS_OTLP_HEADERS": "A=b"}) == {"A": "b"}
        assert otlp.read_headers_env({}) == {}


class TestNoRedirect:
    def test_redirect_handler_refuses(self):
        h = otlp._NoRedirect()
        assert h.redirect_request(None, None, 302, "Found", {}, "http://x/") \
            is None

    def test_secret_never_in_error_text(self):
        exp = otlp.OTLPLogExporter("http://c:4318",
                                   headers={"Authorization": "Splunk SECRET"},
                                   sender=lambda u, b: (_ for _ in ()).throw(
                                       RuntimeError("plain")))
        exp.emit({"ts": 1, "event": "start"})
        assert exp.flush() == 0            # swallowed, never raised

    def test_authenticated_plaintext_transport_is_refused_before_open(self):
        with pytest.raises(RuntimeError, match="requires HTTPS"):
            otlp._http_post(
                "http://collector.example:4318/v1/logs", b"{}",
                headers={"Authorization": "Bearer secret"})


class TestSemconvLogRecords:
    def test_swarm_event_record(self):
        rec = otlp.build_log_record(
            {"ts": 2, "event": "start", "info_hash": "aa11",
             "peer_id": "p1", "ip": "10.0.0.2", "port": 6881, "left": 500,
             "principal_type": "device", "principal_id": "d1",
             "event_id": "e1"})
        assert rec["eventName"] == "iris.tracker.peer"
        attrs = {a["key"]: a["value"] for a in rec["attributes"]}
        assert attrs["network.peer.address"] == {"stringValue": "10.0.0.2"}
        assert attrs["iris.torrent.info_hash"] == {"stringValue": "aa11"}
        assert attrs["iris.peer.role"] == {"stringValue": "leecher"}
        assert attrs["iris.principal"] == {"stringValue": "device:d1"}
        assert "event" not in attrs        # legacy key gone

    def test_report_record_v1_safe_subset_and_peers(self):
        # design §10.8: a v1 report exports the SAFE SUBSET only; ambiguous
        # avg_bps/tier are never projected. network.peer.address is the
        # participation list.
        report = {"v": 1, "schema": "v1", "ts": 3, "image_id": "img-1",
                  "event": "seeding-only",
                  "link": {"tier": "good"}, "transfer": {"avg_bps": 42},
                  "agent": {"version": "9", "runtime_mode": "container"},
                  "peers": [{"ip": "10.0.0.3", "rx_bytes": 7, "tx_bytes": 1,
                            "avg_bps": 3}], "peers_total": 5,
                  "received_at": 33.0}
        rec = otlp.build_report_record(report, "d1")
        assert rec["eventName"] == "iris.device.report"
        attrs = {a["key"]: a["value"] for a in rec["attributes"]}
        assert attrs["device.id"] == {"stringValue": "d1"}
        assert attrs["iris.image.id"] == {"stringValue": "img-1"}
        assert attrs["iris.report.event"] == {"stringValue": "seeding-only"}
        assert attrs["iris.telemetry.schema.version"] == {"intValue": "1"}
        assert attrs["iris.transfer.peers_total"] == {"intValue": "5"}
        row = attrs["network.peer.address"]["arrayValue"]["values"][0]
        assert row == {"stringValue": "10.0.0.3"}
        # ambiguous / high-cardinality fields are dropped
        for gone in ("iris.transfer.throughput_avg", "iris.link.tier",
                     "device.model.identifier", "iris.stage.state",
                     "iris.agent.runtime"):
            assert gone not in attrs, gone


class TestPolicyAndTrackerEvents:
    def test_policy_event_typed_attrs_and_event_id(self):
        # design §10.8: iris.peer.policy, event.id = operation_outbox event_id,
        # no rule text / IP list / device-id list beyond the acted target.
        entry = {"event_id": "a71c33e90b5d4f28", "revision": 7,
                 "action": "assign", "target": "iris8kv-1",
                 "actor": "console:admin", "created_at": 1755743180.0}
        status = {"state": "enforced", "applied_revision": 7,
                  "desired_ip_count": 3}
        rec = otlp.build_policy_record(entry, status)
        assert rec["eventName"] == "iris.peer.policy"
        assert _attrs(rec)["event.id"]["stringValue"] == "a71c33e90b5d4f28"
        attrs = {a["key"]: a["value"] for a in rec["attributes"]}
        assert attrs["iris.telemetry.schema.version"] == {"intValue": "2"}
        assert attrs["iris.policy.revision"] == {"intValue": "7"}
        assert attrs["iris.policy.action"] == {"stringValue": "assign"}
        assert attrs["iris.enforcement.state"] == {"stringValue": "enforced"}
        assert attrs["iris.enforcement.applied_revision"] == {"intValue": "7"}
        assert attrs["iris.enforcement.desired_ip_count"] == {"intValue": "3"}
        # forbidden: no rule text, no IP list, no multi-device list
        text = json.dumps(rec)
        assert "10.0.0" not in text and "deny" not in text
        assert "iris8kv-2" not in text

    def test_tracker_lifecycle_event_named_and_typed(self):
        # design §10.8: iris.tracker.peer with a random in-process event.id.
        ev = {"event": "join", "event_id": "beef1234",
              "principal": "device:iris8kv-1", "info_hash": "aa11",
              "role": "leecher", "ip": "198.51.100.14",
              "received_at": 1755743190.0}
        rec = otlp.build_tracker_record(ev)
        assert rec["eventName"] == "iris.tracker.peer"
        assert _attrs(rec)["event.id"]["stringValue"] == "beef1234"
        # event time = server received_at
        assert rec["timeUnixNano"] == str(int(1755743190.0 * 1e9))
        attrs = {a["key"]: a["value"] for a in rec["attributes"]}
        assert attrs["iris.telemetry.schema.version"] == {"intValue": "2"}
        assert attrs["iris.principal"] == {"stringValue": "device:iris8kv-1"}
        assert attrs["iris.peer.role"] == {"stringValue": "leecher"}
        assert attrs["network.peer.address"] == {"stringValue": "198.51.100.14"}
        assert attrs["iris.torrent.info_hash"] == {"stringValue": "aa11"}


class TestMetricsPayload:
    POINTS = [
        {"name": "iris.transfer.throughput", "unit": "By/s", "kind": "gauge",
         "value": 100,
         "attrs": {"iris.image.id": "img-1",
                   "iris.torrent.info_hash": "aa11",
                   "network.io.direction": "receive"}},
        {"name": "iris.telemetry.samples.rejected", "unit": "{sample}",
         "kind": "sum", "value": 7, "attrs": {}},
    ]

    def test_payload_shape(self):
        body = otlp.build_metrics_payload(
            self.POINTS, {"service.name": "iris-tracker",
                          "service.namespace": "iris",
                          "service.version": "2026.07.08"})
        rm = body["resourceMetrics"][0]
        res = {a["key"]: a["value"] for a in rm["resource"]["attributes"]}
        assert res["service.namespace"] == {"stringValue": "iris"}
        metrics_by_name = {m["name"]: m
                           for m in rm["scopeMetrics"][0]["metrics"]}
        g = metrics_by_name["iris.transfer.throughput"]
        assert g["unit"] == "By/s"
        dp = g["gauge"]["dataPoints"][0]
        assert dp["asInt"] == "100"
        dattrs = {a["key"]: a["value"] for a in dp["attributes"]}
        assert dattrs["network.io.direction"] == {"stringValue": "receive"}
        s = metrics_by_name["iris.telemetry.samples.rejected"]
        assert s["sum"]["isMonotonic"] is True
        assert s["sum"]["aggregationTemporality"] == 2
        assert "_total" not in s["name"]

    def test_exporter_posts_and_reports_result(self):
        sent = {}
        def sender(url, body, headers=None):
            sent["url"], sent["headers"] = url, headers
        exp = otlp.OTLPMetricsExporter("http://c:4318/",
                                       headers={"A": "b"}, sender=sender)
        assert exp.export(self.POINTS) is True
        assert sent["url"] == "http://c:4318/v1/metrics"
        assert sent["headers"] == {"A": "b"}
        exp_fail = otlp.OTLPMetricsExporter(
            "http://c:4318", sender=lambda u, b, headers=None:
            (_ for _ in ()).throw(RuntimeError("down")))
        assert exp_fail.export(self.POINTS) is False
        assert exp_fail.export([]) is True             # nothing to send = ok


class TestDefaultResource:
    def test_service_identity(self):
        res = otlp.default_resource()
        assert res["service.name"] == "iris-tracker"
        assert res["service.namespace"] == "iris"
        assert res["service.version"] and res["service.version"] != ""


# ---- trust-store wiring: _http_post verifies via trust.ssl_context() ------

def _throwaway_cert(dirpath):
    """Self-signed cert with SAN=IP:127.0.0.1 (the test_artifact_server
    idiom). Returns (crt, combined)."""
    crt = os.path.join(str(dirpath), "crt.pem")
    key = os.path.join(str(dirpath), "key.pem")
    combined = os.path.join(str(dirpath), "cert.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "2", "-keyout", key, "-out", crt, "-subj", "/CN=collector",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True)
    with open(combined, "w") as f:
        with open(crt) as c:
            f.write(c.read())
        with open(key) as k:
            f.write(k.read())
    return crt, combined


def _tls_collector(combined, redirect=False):
    """Local https 'collector': 200 on POST (or a 302 when redirect=True)."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if redirect:
                self.send_response(302)
                self.send_header("Location", "https://127.0.0.1:9/elsewhere")
            else:
                self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(combined)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestTrustStoreWiring:
    """_http_post must verify against trust.ssl_context() (system roots PLUS
    the IRIS bundle): a private-CA collector works once its root is
    installed, stays refused when it is not, and the redirect refusal
    survives the change (spec feature A2)."""

    @pytest.fixture(autouse=True)
    def _trust_env(self, tmp_path, monkeypatch):
        monkeypatch.setenv("IRIS_TRUST_DIR", str(tmp_path / "trust"))
        monkeypatch.setenv("IRIS_CA_BUNDLE",
                           str(tmp_path / "run" / "ca-bundle.pem"))

    def test_accepts_private_ca_once_root_installed(self, tmp_path):
        crt, combined = _throwaway_cert(tmp_path)
        srv = _tls_collector(combined)
        try:
            with open(crt) as f:
                trust.add_pem(f.read())
            url = "https://127.0.0.1:%d/v1/logs" % srv.server_address[1]
            otlp._http_post(url, b"{}")          # must not raise
        finally:
            srv.shutdown()

    def test_refused_while_root_not_installed(self, tmp_path):
        _, combined = _throwaway_cert(tmp_path)
        srv = _tls_collector(combined)
        try:
            url = "https://127.0.0.1:%d/v1/logs" % srv.server_address[1]
            with pytest.raises(RuntimeError):
                otlp._http_post(url, b"{}")
        finally:
            srv.shutdown()

    def test_redirect_refusal_survives_trust_wiring(self, tmp_path):
        crt, combined = _throwaway_cert(tmp_path)
        srv = _tls_collector(combined, redirect=True)
        try:
            with open(crt) as f:
                trust.add_pem(f.read())
            url = "https://127.0.0.1:%d/v1/logs" % srv.server_address[1]
            with pytest.raises(RuntimeError):
                otlp._http_post(url, b"{}")      # 3xx is an export failure
        finally:
            srv.shutdown()

    def test_trust_context_failure_is_caught_and_wrapped(self, monkeypatch):
        """If trust.ssl_context() raises (unreadable bundle, ssl error),
        the exception must be caught and wrapped in the generic RuntimeError,
        not escape as a raw exception."""
        monkeypatch.setattr(trust, "ssl_context",
                           lambda: (_ for _ in ()).throw(
                               ssl.SSLError("boom")))
        with pytest.raises(RuntimeError, match="OTLP POST to"):
            otlp._http_post("https://collector.local/v1/logs", b"{}")


def test_peer_bytes_record_carries_the_attributed_edge():
    """Per-peer CUMULATIVE bytes reach the backend as a LOG record, for the
    same reason the rate does: peer- and device-labelled history must not
    multiply metric cardinality. The record has to name the edge, the image,
    the running total AND the delta that produced it, so a backend can chart
    either without re-deriving one from the other."""
    rec = otlp.build_peer_bytes_record({
        "info_hash": "abc", "image_id": "cat9k_iosxe.26.01.01",
        "ip": "198.51.100.2", "device_id": "rtr-04", "role": "seeder",
        "peer_sent_bytes": 429_496_729, "peer_sent_delta_bytes": 1_048_576,
        "ts": 1787000000.0, "event_id": "e7"})
    attrs = {k: list(v.values())[0] for k, v in _attrs(rec).items()}
    assert rec["eventName"] == "iris.swarm.peer_bytes"
    assert rec["timeUnixNano"] == "1787000000000000000"
    assert attrs["otel.log.name"] == "iris.swarm.peer_bytes"
    assert attrs["iris.torrent.info_hash"] == "abc"
    assert attrs["iris.image.id"] == "cat9k_iosxe.26.01.01"
    # a single address, as on peer_rate -- never an array like the report
    # records use, so a backend groups by one string.
    assert attrs["network.peer.address"] == "198.51.100.2"
    assert attrs["iris.device.id"] == "rtr-04"
    assert attrs["iris.peer.role"] == "seeder"
    assert attrs["event.id"] == "e7"
    # int64 rides the OTLP/JSON wire as a STRING; a query that sums these has
    # to coerce first.
    assert _attrs(rec)["iris.transfer.peer_sent_bytes"] == \
        {"intValue": "429496729"}
    assert _attrs(rec)["iris.transfer.peer_sent_delta_bytes"] == \
        {"intValue": "1048576"}


def test_peer_bytes_record_omits_what_it_does_not_know():
    """A peer IP with no heartbeat cannot be joined to a device. Omit the
    attribute rather than emit a placeholder that a dashboard would happily
    group by."""
    rec = otlp.build_peer_bytes_record({
        "info_hash": "abc", "ip": "10.0.0.9",
        "peer_sent_bytes": 10, "peer_sent_delta_bytes": 10, "ts": 1.0})
    keys = set(_attrs(rec))
    assert "iris.device.id" not in keys
    assert "iris.peer.role" not in keys
    assert "iris.image.id" not in keys
    assert keys >= {"iris.torrent.info_hash", "network.peer.address",
                    "iris.transfer.peer_sent_bytes"}


def test_peer_bytes_record_tolerates_garbage():
    """Telemetry is never on the critical path: a non-dict row must produce a
    well-formed (if empty) record rather than raise into the sampler."""
    rec = otlp.build_peer_bytes_record(None)
    assert rec["eventName"] == "iris.swarm.peer_bytes"
    assert rec["timeUnixNano"] == "0"


# ---------------------------------------------------------------------------
# iris.device.peer_transfer_record -- the EXACT device-side measurement
#
# The sampled origin-side estimate has always been exported; the exact
# device-side one was stored in the catalog and went no further, so the worse
# number was the only one an operator could see. These tests hold the exact one
# reachable, and hold it apart from the estimate.
# ---------------------------------------------------------------------------


def _transfer_record_report(rows, **block):
    b = {"source": "aria2_session_counters", "captured_at": 1787000000.0,
         "complete": True, "rows": rows, "rows_total": len(rows),
         "rows_omitted": 0, "bytes_from_all_senders_total":
         sum(r.get("session_bytes_from_peer", 0) for r in rows),
         "bytes_from_all_senders_omitted": 0}
    b.update(block)
    return {"schema": "v2", "report_id": "r1", "image_id": "cat9k.26.01.01",
            "transfer_id": "t1", "received_at": 1787000100.0,
            "peer_transfer_records": b}


def test_peer_transfer_record_is_a_separate_name_from_the_sampled_estimate():
    """iris.swarm.peer_bytes carries the origin-side SAMPLED estimate, which
    loses 26.7% at 3s. These are the same bytes counted exactly. If both landed
    under one log name a backend sum() would silently mix an exact number with
    a lossy one and double-count the transfer, so the names are disjoint by
    construction."""
    rec = otlp.build_peer_transfer_record({
        "ip": "198.51.100.2", "session_bytes_from_peer": 429_496_729,
        "captured_at": 1787000000.0})
    assert rec["eventName"] == "iris.device.peer_transfer_record"
    assert rec["eventName"] != "iris.swarm.peer_bytes"
    assert _attrs(rec)["otel.log.name"] == \
        {"stringValue": "iris.device.peer_transfer_record"}
    # event time is the hook's capture instant, not server ingest time.
    assert rec["timeUnixNano"] == "1787000000000000000"


def test_peer_transfer_record_carries_the_measured_edge():
    rec = otlp.build_peer_transfer_record({
        "device_id": "rtr-04", "image_id": "cat9k.26.01.01",
        "transfer_id": "t1", "ip": "198.51.100.7", "port": 6881,
        "peer_device_id": "rtr-07", "peer_attribution": "device",
        "has_complete_file": True, "session_bytes_from_peer": 281_474_976,
        "session_bytes_to_peer": 1_048_576, "captured_at": 1787000000.0,
        "source": "aria2_session_counters", "capture_complete": True,
        "event_id": "r1:198.51.100.7"})
    attrs = _attrs(rec)
    flat = {k: list(v.values())[0] for k, v in attrs.items()}
    assert flat["device.id"] == "rtr-04"          # the RECEIVING device
    assert flat["iris.peer.device.id"] == "rtr-07"
    assert flat["iris.peer.attribution"] == "device"
    assert flat["network.peer.address"] == "198.51.100.7"
    assert flat["iris.transfer_record.source"] == "aria2_session_counters"
    assert flat["event.id"] == "r1:198.51.100.7"
    assert attrs["network.peer.port"] == {"intValue": "6881"}
    assert attrs["iris.transfer_record.capture_complete"] == {"boolValue": True}
    # int64 rides the OTLP/JSON wire as a STRING, as on peer_bytes.
    assert attrs["iris.transfer.session_bytes_from_peer"] == \
        {"intValue": "281474976"}
    assert attrs["iris.transfer.session_bytes_to_peer"] == \
        {"intValue": "1048576"}


def test_peer_transfer_record_never_calls_an_unclassified_peer_a_device():
    """The origin seeder is an ordinary BitTorrent peer of every device, so it
    sits in the device's own peer list like any other. Only the server can tell
    the two apart; a row it did not classify is 'unknown', never folded into
    'device' -- that fold is what would report a wave as ~100% peer-delivered
    when the origin fed most of it."""
    rec = otlp.build_peer_transfer_record({
        "ip": "192.0.2.10", "session_bytes_from_peer": 9})
    assert _attrs(rec)["iris.peer.attribution"] == {"stringValue": "unknown"}
    # no resolution, no name -- but the bytes are still exported.
    assert "iris.peer.device.id" not in _attrs(rec)
    assert _attrs(rec)["iris.transfer.session_bytes_from_peer"] == \
        {"intValue": "9"}
    for bogus in ("peer", "", None, "DEVICE", "origin_maybe", 1):
        rec = otlp.build_peer_transfer_record({"ip": "10.0.0.1",
                                              "peer_attribution": bogus})
        assert _attrs(rec)["iris.peer.attribution"] == \
            {"stringValue": "unknown"}


def test_peer_transfer_record_marks_the_origin_as_origin():
    """The origin's bytes are exported, and exported as the origin's -- they
    are the figure the peer share is measured AGAINST, so they must be
    separable at query time rather than absent."""
    rec = otlp.build_peer_transfer_record({
        "ip": "192.0.2.10", "peer_attribution": "origin",
        "session_bytes_from_peer": 691_167_232})
    assert _attrs(rec)["iris.peer.attribution"] == {"stringValue": "origin"}
    assert _attrs(rec)["iris.transfer.session_bytes_from_peer"] == \
        {"intValue": "691167232"}


def test_peer_transfer_record_seeder_flag_is_not_an_origin_flag():
    """aria2's isSeeder() is true for ANY peer holding the complete file --
    every device that finished early in a wave. The attribute is named for what
    it measures so no dashboard mistakes it for the origin."""
    rec = otlp.build_peer_transfer_record({
        "ip": "10.0.0.2", "has_complete_file": True,
        "peer_attribution": "device"})
    attrs = _attrs(rec)
    assert attrs["iris.peer.has_complete_file"] == {"boolValue": True}
    assert "iris.peer.seeder" not in attrs
    assert "iris.peer.origin" not in attrs
    # false is a measurement, not an absence: it must survive the None-skip.
    rec = otlp.build_peer_transfer_record({"ip": "10.0.0.2",
                                          "has_complete_file": False})
    assert _attrs(rec)["iris.peer.has_complete_file"] == {"boolValue": False}


def test_peer_transfer_record_keeps_a_measured_zero():
    """A peer that connected and delivered nothing is a measurement. Absence of
    a record is what means 'not measured'."""
    rec = otlp.build_peer_transfer_record({
        "ip": "10.0.0.3", "session_bytes_from_peer": 0,
        "session_bytes_to_peer": 0})
    assert _attrs(rec)["iris.transfer.session_bytes_from_peer"] == \
        {"intValue": "0"}
    assert _attrs(rec)["iris.transfer.session_bytes_to_peer"] == \
        {"intValue": "0"}


def test_peer_transfer_record_omits_what_it_does_not_know():
    rec = otlp.build_peer_transfer_record({"ip": "10.0.0.4"})
    keys = set(_attrs(rec))
    assert "network.peer.port" not in keys          # absent, not 0
    assert "iris.peer.has_complete_file" not in keys  # absent, not false
    assert "iris.transfer_record.capture_complete" not in keys
    assert "iris.transfer.session_bytes_from_peer" not in keys


def test_peer_transfer_record_tolerates_garbage():
    """Telemetry is never on the critical path."""
    rec = otlp.build_peer_transfer_record(None)
    assert rec["eventName"] == "iris.device.peer_transfer_record"
    assert rec["timeUnixNano"] == "0"
    assert _attrs(rec)["iris.peer.attribution"] == {"stringValue": "unknown"}


def test_peer_transfer_records_fan_out_one_record_per_row():
    report = _transfer_record_report([
        {"ip": "198.51.100.7", "session_bytes_from_peer": 200,
         "session_bytes_to_peer": 0, "peer_attribution": "device",
         "peer_device_id": "rtr-07"},
        {"ip": "192.0.2.10", "session_bytes_from_peer": 800,
         "session_bytes_to_peer": 0, "peer_attribution": "origin"},
    ])
    recs = otlp.build_peer_transfer_records(report, "rtr-04")
    assert len(recs) == 2
    for rec in recs:
        attrs = {k: list(v.values())[0] for k, v in _attrs(rec).items()}
        # per-row context is filled from the report and the block, so a single
        # record stands on its own in the logs pipeline.
        assert attrs["device.id"] == "rtr-04"
        assert attrs["iris.image.id"] == "cat9k.26.01.01"
        assert attrs["iris.transfer.id"] == "t1"
        assert attrs["iris.transfer_record.source"] == "aria2_session_counters"
        assert rec["timeUnixNano"] == "1787000000000000000"
    # ids are stable per row and unique within the report, so a retry of the
    # same report does not look like new bytes.
    ids = [{k: list(v.values())[0] for k, v in _attrs(r).items()}["event.id"]
           for r in recs]
    assert ids == ["r1:198.51.100.7", "r1:192.0.2.10"]
    assert otlp.build_peer_transfer_records(report, "rtr-04")[0][
        "attributes"] == recs[0]["attributes"]
    # the origin/device split survives the fan-out
    attribution = sorted(
        {k: list(v.values())[0] for k, v in _attrs(r).items()}[
            "iris.peer.attribution"] for r in recs)
    assert attribution == ["device", "origin"]


def test_peer_transfer_records_take_the_sender_class_from_the_server():
    """The classification is telemetry.transfer_record_source_class's answer, injected.
    otlp does not re-implement the origin/device join: a second copy of an
    identity rule drifts, and the copy that drifts is the one a peer share gets
    read off."""
    report = _transfer_record_report([
        {"ip": "192.0.2.10", "session_bytes_from_peer": 700,
         "session_bytes_to_peer": 0},
        {"ip": "198.51.100.7", "session_bytes_from_peer": 289,
         "session_bytes_to_peer": 0},
        {"ip": "192.0.2.9", "session_bytes_from_peer": 11,
         "session_bytes_to_peer": 0},
    ])
    classes = {"192.0.2.10": "origin", "198.51.100.7": "device"}
    enrich = {"peer_devices": {"198.51.100.7": "rtr-07",
                               "192.0.2.10": "rtr-20"}}
    recs = otlp.build_peer_transfer_records(
        report, "rtr-04", enrich=enrich,
        classify=lambda ip: classes.get(ip, "unknown"))
    got = [{k: list(v.values())[0] for k, v in _attrs(r).items()}
           for r in recs]
    assert [g["iris.peer.attribution"] for g in got] == \
        ["origin", "device", "unknown"]
    assert [g["iris.transfer.session_bytes_from_peer"] for g in got] == \
        ["700", "289", "11"]
    # only the row the server called a device gets a device name; a stale
    # heartbeat map must not name the origin, and an unknown stays unnamed.
    assert [g.get("iris.peer.device.id") for g in got] == \
        [None, "rtr-07", None]


def test_peer_transfer_records_treat_a_failed_classification_as_unknown():
    """A join that raised has told us nothing, which is exactly 'unknown'. It
    must not take the export down with it -- telemetry is never on the critical
    path -- and it must not silently become 'device'."""
    def boom(ip):
        raise KeyError(ip)
    report = _transfer_record_report([{"ip": "10.0.0.8", "session_bytes_from_peer": 5,
                               "session_bytes_to_peer": 0}])
    recs = otlp.build_peer_transfer_records(
        report, "rtr-04", enrich={"peer_devices": {"10.0.0.8": "rtr-08"}},
        classify=boom)
    attrs = _attrs(recs[0])
    assert attrs["iris.peer.attribution"] == {"stringValue": "unknown"}
    assert "iris.peer.device.id" not in attrs
    assert attrs["iris.transfer.session_bytes_from_peer"] == {"intValue": "5"}


def test_peer_transfer_records_emit_nothing_when_nothing_was_measured():
    """Absent block means NOT MEASURED. An empty list is how that stays
    distinguishable from a measured zero (which is a row)."""
    assert otlp.build_peer_transfer_records({"report_id": "r1"}, "d1") == []
    assert otlp.build_peer_transfer_records(None, "d1") == []
    assert otlp.build_peer_transfer_records({"peer_transfer_records": 7}, "d1") == []
    assert otlp.build_peer_transfer_records(
        {"peer_transfer_records": {"rows": "nope"}}, "d1") == []
    assert otlp.build_peer_transfer_records(
        {"peer_transfer_records": {"rows": [None, 3]}}, "d1") == []


def test_report_record_summarises_transfer_records_without_claiming_a_peer_share():
    """The device's total includes the ORIGIN's bytes -- the origin is an
    ordinary BitTorrent peer of every device -- so the attribute keeps the
    device's honest name, all_senders. Nothing on this record may read as
    "bytes the peers delivered, server excluded"; that split is a server
    classification and appears only once the server has made it."""
    report = _transfer_record_report(
        [{"ip": "10.0.0.5", "session_bytes_from_peer": 1000,
          "session_bytes_to_peer": 0}],
        rows_total=3, rows_omitted=2, bytes_from_all_senders_total=1500,
        bytes_from_all_senders_omitted=500, rows_dropped_by_server=1,
        complete=False)
    report["peers_rows_dropped"] = 6
    attrs = _attrs(otlp.build_report_record(report, "rtr-04"))
    assert attrs["iris.transfer.bytes_from_all_senders_total"] == \
        {"intValue": "1500"}
    assert attrs["iris.transfer.bytes_from_all_senders_omitted"] == \
        {"intValue": "500"}
    assert attrs["iris.transfer.peer_records.rows_total"] == {"intValue": "3"}
    assert attrs["iris.transfer.peer_records.rows_omitted"] == \
        {"intValue": "2"}
    assert attrs["iris.transfer.peer_records.rows_dropped_by_server"] == \
        {"intValue": "1"}
    assert attrs["iris.transfer.peer_records.capture_complete"] == \
        {"boolValue": False}
    assert attrs["iris.transfer.peers_rows_dropped"] == {"intValue": "6"}
    assert not [k for k in attrs if "bytes_from_peers" in k]
    # unclassified: no origin/device figures invented, not even zeroed ones
    assert "iris.transfer.bytes_from_origin_total" not in attrs
    assert "iris.transfer.bytes_from_devices_total" not in attrs
    assert "iris.transfer.bytes_from_unknown_total" not in attrs


def test_report_record_exports_the_four_way_split_when_the_server_made_it():
    """telemetry.classify_peer_transfer_records rides in on `enrich`. Its four figures
    go out as four: only bytes_from_devices_total is peer-to-peer delivery, and
    the bytes a row cap dropped are reported rather than spread across the
    named buckets (that even-split fabrication was removed in 2026.08.20)."""
    report = _transfer_record_report(
        [{"ip": "10.0.0.5", "session_bytes_from_peer": 1000,
          "session_bytes_to_peer": 0}],
        bytes_from_all_senders_total=1500, bytes_from_all_senders_omitted=500,
        rows_total=2, rows_omitted=1)
    enrich = {"model": "C9300-48P", "free_flash_bytes": 1,
              "peer_transfer_record_attribution": {
                  "origin_bytes": 700, "origin_rows": 1,
                  "device_bytes": 289, "device_rows": 2,
                  "unknown_bytes": 11, "unknown_rows": 1,
                  "unattributed_omitted_bytes": 500,
                  "unattributed_omitted_rows": 1,
                  "bytes_from_all_senders_total": 1500,
                  "capture_complete": True}}
    attrs = _attrs(otlp.build_report_record(report, "rtr-04", enrich=enrich))
    assert attrs["iris.transfer.bytes_from_origin_total"] == \
        {"intValue": "700"}
    assert attrs["iris.transfer.bytes_from_devices_total"] == \
        {"intValue": "289"}
    assert attrs["iris.transfer.bytes_from_unknown_total"] == \
        {"intValue": "11"}
    assert attrs["iris.transfer.bytes_unattributed_omitted"] == \
        {"intValue": "500"}
    assert attrs["iris.transfer.peer_records.origin_rows"] == \
        {"intValue": "1"}
    assert attrs["iris.transfer.peer_records.device_rows"] == \
        {"intValue": "2"}
    assert attrs["iris.transfer.peer_records.unknown_rows"] == \
        {"intValue": "1"}
    # the four sum to the device's own total, so the split can be checked
    # rather than trusted
    assert 700 + 289 + 11 + 500 == 1500
    # the rest of enrich stays out of the canonical report event
    assert "model" not in attrs and "iris.device.model" not in attrs


def test_report_record_ignores_a_split_that_is_not_a_split():
    for enrich in (None, {}, {"peer_transfer_record_attribution": None},
                   {"peer_transfer_record_attribution": "origin"}, "nope"):
        attrs = _attrs(otlp.build_report_record(
            _transfer_record_report([]), "rtr-04", enrich=enrich))
        assert not [k for k in attrs if "bytes_from_origin" in k
                    or "bytes_from_devices" in k]


def test_report_record_without_transfer_records_adds_no_transfer_record_attributes():
    attrs = _attrs(otlp.build_report_record(
        {"schema": "v2", "report_id": "r3", "received_at": 1.0}, "rtr-04"))
    assert not [k for k in attrs if "peer_records" in k
                or "all_senders" in k]


def test_peer_transfer_records_ride_the_logs_payload_unchanged():
    """Pre-built records are passed through build_logs_payload untouched (they
    are recognised by timeUnixNano); a second trip through build_log_record
    would silently empty them."""
    report = _transfer_record_report([{"ip": "10.0.0.6",
                               "session_bytes_from_peer": 5,
                               "session_bytes_to_peer": 0}])
    recs = otlp.build_peer_transfer_records(report, "rtr-04")
    payload = otlp.build_logs_payload(recs, {"service.name": "iris-tracker"})
    sent = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    assert sent == recs
    assert json.loads(json.dumps(payload))  # serialises as-is


# --- transfer lifecycle (iris.transfer.lifecycle, server-side plan events) ---

def _plan_row(**over):
    """A promoted (state ``seeding``) transfer_lifecycle store row.

    Both instants are server-clock epochs minted inside the tracker container,
    which is what makes ``seeding_started_at - planned_at`` a single-clock
    subtraction; ``observed_at`` is the DEVICE's clock off the attesting
    report's ``window.end`` and is deliberately a different number."""
    row = {
        "plan_id": "9b0c1d2e3f405162738495a6b7c8d9e0",
        "transfer_id": "3f0a9c1d8e2b4a6f9017c3d5e7b1a2c4",
        "device_id": "iris8kv-1",
        "image_id": "cat9k_iosxe.17.15.01.SPA.bin",
        "info_hash": "a" * 40,
        "planned_at": 1755743200.482,
        "state": "seeding",
        "checksum_verified_at": 1755743450.0,
        "tracker_seeder_at": 1755743380.25,
        "seeding_started_at": 1755743500.75,
        "observed_at": 1755743495.0,
        "report_created_at": 1755743448.5,
    }
    row.update(over)
    return row


def test_planned_record_carries_the_lifecycle_name_and_the_four_correlation_ids():
    rec = otlp.build_transfer_lifecycle_record(_plan_row(), "planned")
    assert rec["eventName"] == "iris.transfer.lifecycle"
    attrs = _attrs(rec)
    assert attrs["otel.log.name"] == {
        "stringValue": "iris.transfer.lifecycle"}
    assert attrs["iris.telemetry.schema.version"] == {"intValue": "2"}
    assert attrs["event"] == {"stringValue": "planned"}
    # The four correlation ids. iris.plan.id is the join key an operator groups
    # on; the transfer id is what the device's own reports carry.
    assert attrs["iris.plan.id"] == {
        "stringValue": "9b0c1d2e3f405162738495a6b7c8d9e0"}
    assert attrs["iris.transfer.id"] == {
        "stringValue": "3f0a9c1d8e2b4a6f9017c3d5e7b1a2c4"}
    assert attrs["iris.image.id"] == {
        "stringValue": "cat9k_iosxe.17.15.01.SPA.bin"}
    assert attrs["iris.torrent.info_hash"] == {"stringValue": "a" * 40}
    # BOTH device-id spellings ride, so a join against
    # iris.device.transfer.report (device.id) or against iris.swarm.peer_bytes
    # (iris.device.id) can be written without a coalesce.
    assert attrs["device.id"] == {"stringValue": "iris8kv-1"}
    assert attrs["iris.device.id"] == {"stringValue": "iris8kv-1"}
    assert attrs["iris.transfer.planned_at"] == {
        "stringValue": "2025-08-21T02:26:40.482Z"}


def test_planned_record_omits_the_seeding_instants_it_cannot_yet_know():
    """A plan is ``planned`` before any precondition has latched, and the store
    may hand the builder a row that already carries latches (the pair is
    emitted in order, so ``planned`` can be built after promotion). The planned
    record must still describe only the planning decision -- shipping a seeding
    timestamp on it would date the transfer's completion to its assignment."""
    attrs = _attrs(otlp.build_transfer_lifecycle_record(_plan_row(), "planned"))
    for gone in ("iris.transfer.seeding_started_at",
                 "iris.transfer.checksum_verified_at",
                 "iris.transfer.report_received_at",
                 "iris.transfer.tracker_seeder_at",
                 "iris.device.observed_at",
                 "iris.device.report_created_at"):
        assert gone not in attrs, gone


def test_seeding_started_record_carries_the_four_correlation_ids_and_both_timestamps():
    rec = otlp.build_transfer_lifecycle_record(_plan_row(), "seeding_started")
    assert rec["eventName"] == "iris.transfer.lifecycle"
    attrs = _attrs(rec)
    assert attrs["otel.log.name"] == {
        "stringValue": "iris.transfer.lifecycle"}
    assert attrs["iris.telemetry.schema.version"] == {"intValue": "2"}
    assert attrs["event"] == {"stringValue": "seeding_started"}
    assert attrs["iris.plan.id"] == {
        "stringValue": "9b0c1d2e3f405162738495a6b7c8d9e0"}
    assert attrs["iris.transfer.id"] == {
        "stringValue": "3f0a9c1d8e2b4a6f9017c3d5e7b1a2c4"}
    assert attrs["device.id"] == {"stringValue": "iris8kv-1"}
    assert attrs["iris.device.id"] == {"stringValue": "iris8kv-1"}
    assert attrs["iris.image.id"] == {
        "stringValue": "cat9k_iosxe.17.15.01.SPA.bin"}
    # planned_at is repeated here on purpose: the duration is then computable
    # from this record alone, without joining back to a planned record a
    # bounded queue may have dropped.
    assert attrs["iris.transfer.planned_at"] == {
        "stringValue": "2025-08-21T02:26:40.482Z"}
    assert attrs["iris.transfer.seeding_started_at"] == {
        "stringValue": "2025-08-21T02:31:40.750Z"}
    # The two preconditions ride separately so an operator can see WHICH one
    # was the laggard -- the device's sha256 or the swarm.
    assert attrs["iris.transfer.checksum_verified_at"] == {
        "stringValue": "2025-08-21T02:30:50.000Z"}
    assert attrs["iris.transfer.tracker_seeder_at"] == {
        "stringValue": "2025-08-21T02:29:40.250Z"}
    # The device's own clock, a float epoch named exactly as the v2 report
    # names it, and never subtracted from the server instants above.
    assert attrs["iris.device.observed_at"]["doubleValue"] == 1755743495.0


def test_the_ingest_instant_also_ships_under_the_name_that_says_ingest():
    """iris.transfer.checksum_verified_at is the server's received_at for the
    attesting report -- the first moment the SERVER knew the checksum had
    verified, not the moment the DEVICE verified it. The device reports no
    verification instant, so none is invented; the same value ships again as
    iris.transfer.report_received_at, which is the name that says what it is.
    The old name keeps shipping because an exported attribute cannot be
    withdrawn."""
    attrs = _attrs(
        otlp.build_transfer_lifecycle_record(_plan_row(), "seeding_started"))
    assert attrs["iris.transfer.report_received_at"] == {
        "stringValue": "2025-08-21T02:30:50.000Z"}
    assert attrs["iris.transfer.report_received_at"] \
        == attrs["iris.transfer.checksum_verified_at"]
    # Absent, not defaulted, when the row never latched one.
    row = _plan_row(checksum_verified_at=None)
    gone = _attrs(otlp.build_transfer_lifecycle_record(row, "seeding_started"))
    assert "iris.transfer.report_received_at" not in gone
    assert "iris.transfer.checksum_verified_at" not in gone


def test_the_devices_own_report_instant_makes_the_delivery_lag_visible():
    """The correction to a plan-to-seed duration inflated by report-delivery
    backoff. The agent arms a terminal report at completion and then defers
    the whole send on a bad link, backing off to ~16 minutes, so the ingest
    instant can sit that far behind the physical one. Shipping the device's
    own report_created_at beside its observed_at makes that gap visible
    instead of leaving it read as transfer time. Both are DEVICE-clock float
    epochs, named as iris.device.transfer.report names them, and neither is
    ever subtracted from a server instant as though it were exact."""
    attrs = _attrs(
        otlp.build_transfer_lifecycle_record(_plan_row(), "seeding_started"))
    assert attrs["iris.device.observed_at"]["doubleValue"] == 1755743495.0
    assert attrs["iris.device.report_created_at"]["doubleValue"] == \
        1755743448.5
    # Absent, never a stand-in, when the report carried no such instant.
    row = _plan_row()
    del row["report_created_at"]
    assert "iris.device.report_created_at" not in _attrs(
        otlp.build_transfer_lifecycle_record(row, "seeding_started"))


def test_a_recovered_promotion_says_so_on_the_wire():
    """A row rebuilt from a LOST store takes its seeding_started_at from the
    durable pair alone -- the peer registry is in memory, so no rebuild can
    reproduce an original instant that came from tracker_seeder_at. The replay
    therefore carries a possibly EARLIER value under an IDENTICAL event.id,
    and the tracker_seeder_at riding with it is a post-loss re-announce, so
    recomputing max() over these attributes does not reproduce the promotion
    instant. The flag is what lets a backend attribute that difference to a
    recovery instead of silently holding two disagreeing values; a
    process-wide counter cannot, because it is not on the record."""
    attrs = _attrs(otlp.build_transfer_lifecycle_record(
        _plan_row(recovered_promotion=True), "seeding_started"))
    assert attrs["iris.transfer.recovered_promotion"] == {"boolValue": True}
    # ABSENT, never false, on an ordinary promotion -- and never on `planned`,
    # whose instant comes from policy.json and replays identically regardless.
    assert "iris.transfer.recovered_promotion" not in _attrs(
        otlp.build_transfer_lifecycle_record(_plan_row(), "seeding_started"))
    assert "iris.transfer.recovered_promotion" not in _attrs(
        otlp.build_transfer_lifecycle_record(
            _plan_row(recovered_promotion=True), "planned"))
    # A truthy non-True value is not the flag: the store writes True or
    # nothing, and anything else came from a hand-edited row.
    assert "iris.transfer.recovered_promotion" not in _attrs(
        otlp.build_transfer_lifecycle_record(
            _plan_row(recovered_promotion="yes"), "seeding_started"))


def test_lifecycle_event_time_is_the_source_instant_not_the_emit_instant():
    """timeUnixNano is the instant the SERVER minted or observed -- planned_at
    for planned, seeding_started_at for seeding_started -- never the moment the
    record was queued or ingested. Timing off the emit would report a queue
    delay as a transfer fact, and a crash-replay would then move an instant a
    backend already holds under an identical event.id. This is the deliberate
    departure from iris.device.transfer.report, which times off the server's
    received_at because arrival is the only thing it knows for certain."""
    row = _plan_row()
    planned = otlp.build_transfer_lifecycle_record(row, "planned")
    seeding = otlp.build_transfer_lifecycle_record(row, "seeding_started")
    assert planned["timeUnixNano"] == str(int(1755743200.482 * 1e9))
    assert seeding["timeUnixNano"] == str(int(1755743500.75 * 1e9))


def test_rfc3339_is_utc_milliseconds_with_a_literal_z():
    """Stands in for the operator-facing Splunk extraction
    ``%Y-%m-%dT%H:%M:%S.%N%Z``: %N needs a fractional field that is always
    present and always three digits, and %Z matches a zone NAME, so it will not
    consume a numeric +00:00 offset. The strptime round-trip below is the
    machine-checkable proxy for that pattern."""
    import datetime
    value = otlp._rfc3339_millis(1755743200.482)
    assert value == "2025-08-21T02:26:40.482Z"
    assert datetime.datetime.strptime(
        value, "%Y-%m-%dT%H:%M:%S.%fZ") == datetime.datetime(
            2025, 8, 21, 2, 26, 40, 482000)
    # A whole-second instant still renders three fractional digits: a bare
    # "...:50Z" would fail the pattern outright.
    assert otlp._rfc3339_millis(1755743450) == "2025-08-21T02:30:50.000Z"
    assert otlp._rfc3339_millis(0) == "1970-01-01T00:00:00.000Z"
    # UTC via time.gmtime, never the container's local zone.
    assert value.endswith("Z") and "+" not in value


def test_rfc3339_rounding_carry_rolls_the_second():
    # 1.9996s rounds to 2000 millis: it must become ...:02.000Z, never
    # ...:01.1000Z, which is four fractional digits and breaks the pattern.
    assert otlp._rfc3339_millis(1.9996) == "1970-01-01T00:00:02.000Z"
    assert otlp._rfc3339_millis(0.9999) == "1970-01-01T00:00:01.000Z"


def test_rfc3339_returns_none_for_anything_it_cannot_honestly_render():
    # None means the caller DROPS the attribute pair; an absent instant is
    # honest where a fabricated one is not. bool is rejected explicitly
    # because it is an int subclass and would render True as ...:01.000Z.
    for bad in (None, True, False, "nope", {}, [], float("nan"),
                float("inf"), -float("inf"), -1.0):
        assert otlp._rfc3339_millis(bad) is None, repr(bad)


def test_event_id_is_stable_across_a_repeat_build():
    """The id is DERIVED from the plan, never minted per emission, so a replay
    after a crash between the queue accepting a record and its durable marker
    landing carries a byte-identical record."""
    row = _plan_row()
    rec = otlp.build_transfer_lifecycle_record(row, "seeding_started")
    again = otlp.build_transfer_lifecycle_record(dict(row), "seeding_started")
    assert rec["attributes"] == again["attributes"]
    assert rec == again
    assert _attrs(rec)["event.id"] == {
        "stringValue": "9b0c1d2e3f405162738495a6b7c8d9e0.seeding_started"}


def test_planned_and_seeding_started_carry_different_event_ids():
    """They MUST differ: LogQueue.emit refuses a key already in
    _keys/_inflight_keys, so a shared event.id would make the second record of
    a plan vanish silently rather than fail loudly."""
    row = _plan_row()
    planned = _attrs(otlp.build_transfer_lifecycle_record(row, "planned"))
    seeding = _attrs(
        otlp.build_transfer_lifecycle_record(row, "seeding_started"))
    assert planned["event.id"] == {
        "stringValue": "9b0c1d2e3f405162738495a6b7c8d9e0.planned"}
    assert seeding["event.id"] == {
        "stringValue": "9b0c1d2e3f405162738495a6b7c8d9e0.seeding_started"}
    assert planned["event.id"] != seeding["event.id"]


def test_event_id_is_an_attribute_not_a_top_level_key():
    rec = otlp.build_transfer_lifecycle_record(_plan_row(), "planned")
    assert "event.id" not in rec
    assert _attrs(rec)["event.id"]["stringValue"].endswith(".planned")


def test_lifecycle_record_omits_what_it_does_not_know():
    """An absent attribute means NOT KNOWN. Nothing is defaulted: an empty
    string info_hash or a fabricated instant is worse than a missing one."""
    row = _plan_row()
    del row["info_hash"]
    del row["observed_at"]
    row["tracker_seeder_at"] = None
    attrs = _attrs(otlp.build_transfer_lifecycle_record(row, "seeding_started"))
    for gone in ("iris.torrent.info_hash", "iris.device.observed_at",
                 "iris.transfer.tracker_seeder_at"):
        assert gone not in attrs, gone
    # ...and the ones it does know are unaffected by the omissions.
    assert attrs["iris.transfer.seeding_started_at"] == {
        "stringValue": "2025-08-21T02:31:40.750Z"}
    assert attrs["iris.transfer.checksum_verified_at"] == {
        "stringValue": "2025-08-21T02:30:50.000Z"}


def test_lifecycle_record_never_labels_a_transfer_id_as_device_reported():
    """There is exactly ONE promotion path: a plan promotes only on a terminal
    report bearing that plan's own transfer_id. No divergent / mixed-fleet
    fallback exists, so no attribute may claim one -- even if a row somehow
    carries such keys, they never reach the wire. An attribute cannot be
    withdrawn additively, so shipping one would be permanent."""
    row = _plan_row(id_source="device_divergent",
                    device_reported_id="ffffffffffffffffffffffffffffffff")
    for event in ("planned", "seeding_started"):
        attrs = _attrs(otlp.build_transfer_lifecycle_record(row, event))
        assert "iris.transfer.id_source" not in attrs
        assert "iris.transfer.device_reported_id" not in attrs
        # the plan's own transfer id is the only one exported
        assert attrs["iris.transfer.id"] == {
            "stringValue": "3f0a9c1d8e2b4a6f9017c3d5e7b1a2c4"}


def test_lifecycle_record_tolerates_garbage():
    # A builder never raises on bad input (the house rule); _ts_nano yields
    # "0" rather than blowing up, and every uncoercible value drops its pair.
    for row in (None, "total garbage", 7, [], {}):
        rec = otlp.build_transfer_lifecycle_record(row, "planned")
        assert rec["timeUnixNano"] == "0"
        assert rec["eventName"] == "iris.transfer.lifecycle"
        attrs = _attrs(rec)
        assert attrs["otel.log.name"] == {
            "stringValue": "iris.transfer.lifecycle"}
        assert "iris.plan.id" not in attrs
        assert "iris.transfer.planned_at" not in attrs
    junk = _plan_row(planned_at="soon", seeding_started_at=float("nan"),
                     observed_at="later")
    rec = otlp.build_transfer_lifecycle_record(junk, "seeding_started")
    assert rec["timeUnixNano"] == "0"
    attrs = _attrs(rec)
    assert "iris.transfer.planned_at" not in attrs
    assert "iris.transfer.seeding_started_at" not in attrs
    assert "iris.device.observed_at" not in attrs
    assert attrs["iris.plan.id"] == {
        "stringValue": "9b0c1d2e3f405162738495a6b7c8d9e0"}


def test_lifecycle_records_ride_the_logs_payload_unchanged():
    """build_logs_payload discriminates solely on the presence of
    timeUnixNano, so a pre-built lifecycle record passes through untouched --
    which is why the builder needs no registration anywhere."""
    recs = [otlp.build_transfer_lifecycle_record(_plan_row(), "planned"),
            otlp.build_transfer_lifecycle_record(_plan_row(),
                                                 "seeding_started")]
    payload = otlp.build_logs_payload(recs, {"service.name": "iris-tracker"})
    sent = payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    assert sent == recs
    assert json.loads(json.dumps(payload))  # serialises as-is


def test_existing_report_record_attributes_are_unchanged_by_the_lifecycle_addition():
    """The lifecycle event is PURELY ADDITIVE: no existing builder gained an
    attribute, and in particular the device report is NOT given a plan id.
    plan_id never travels device -> server at all, so a report cannot honestly
    carry one; the server owns the transfer_id -> plan_id mapping."""
    for rec in (otlp.build_report_record(_v2_report(), "iris8kv-1"),
                otlp.build_report_record(_v1_report(), "d1")):
        attrs = _attrs(rec)
        for gone in ("iris.plan.id", "iris.transfer.planned_at",
                     "iris.transfer.seeding_started_at",
                     "iris.transfer.checksum_verified_at",
                     "iris.transfer.tracker_seeder_at", "event"):
            assert gone not in attrs, gone
        assert rec["eventName"] != "iris.transfer.lifecycle"
    # the report event time and schema version are untouched by this change
    v2 = otlp.build_report_record(_v2_report(), "iris8kv-1")
    assert v2["timeUnixNano"] == str(int(1755743200.0 * 1e9))   # received_at
    assert _attrs(v2)["iris.telemetry.schema.version"] == {"intValue": "2"}


# ---------------------------------------------------------------------------
# IRIS-05-002: sampled (evictable) records never evict durable-intent ones
# ---------------------------------------------------------------------------

def test_evictable_records_are_dropped_before_durable_ones():
    q = otlp.LogQueue(max_queue=3)
    assert q.emit({"n": "lifecycle-1"}) is True
    assert q.emit({"n": "sample-1"}, evictable=True) is True
    assert q.emit({"n": "sample-2"}, evictable=True) is True
    # Full. A durable record evicts the OLDEST SAMPLED one, not lifecycle-1.
    assert q.emit({"n": "lifecycle-2"}) is True
    assert [e["n"] for e in q.snapshot()] == ["lifecycle-1", "sample-2",
                                              "lifecycle-2"]
    # A sampled record likewise evicts a sampled one first.
    assert q.emit({"n": "sample-3"}, evictable=True) is True
    assert [e["n"] for e in q.snapshot()] == ["lifecycle-1", "lifecycle-2",
                                              "sample-3"]
    # Nothing evictable left after this: only then does the oldest go.
    assert q.emit({"n": "lifecycle-3"}) is True
    assert q.emit({"n": "lifecycle-4"}) is True
    assert [e["n"] for e in q.snapshot()] == ["lifecycle-2", "lifecycle-3",
                                              "lifecycle-4"]
    assert q.dropped_total == 4


def test_flush_after_mid_batch_eviction_removes_all_sent_events():
    """An in-flight batch can lose an evictable record from its MIDDLE (not
    only its head). After a successful send every retained sent event must
    leave the queue and later emits stay queued in order."""
    q = otlp.LogQueue(max_queue=4)
    q.emit({"n": "a"})
    q.emit({"n": "s"}, evictable=True)
    q.emit({"n": "b"})
    seen = []

    def send(batch):
        seen.append([e["n"] for e in batch])
        q.emit({"n": "c"})                 # concurrent emits during send
        q.emit({"n": "d"})                 # -> queue full, evicts "s"
        q.emit({"n": "e"})                 # -> nothing evictable: drops "a"
    assert q.flush(send) == 3
    assert seen == [["a", "s", "b"]]
    assert [e["n"] for e in q.snapshot()] == ["c", "d", "e"]
    # "s" and "a" were delivered, not lost: their provisional drops undone.
    assert q.dropped_total == 0
