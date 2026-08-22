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
        "peers": [{"ip": "100.92.100.14"}], "peers_total": 3,
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
    assert row["arrayValue"]["values"][0] == {"stringValue": "100.92.100.14"}
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
              "role": "leecher", "ip": "100.92.100.14",
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
        assert attrs["network.peer.address"] == {"stringValue": "100.92.100.14"}
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
