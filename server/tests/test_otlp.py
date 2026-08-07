# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import otlp


def test_build_log_record_maps_core_fields():
    # semconv wire contract (spec 7.6/7.9): eventName is top-level, network
    # peer attrs use the registry names, iris.* namespaces the torrent detail.
    rec = otlp.build_log_record({
        "event": "join", "info_hash": "abc", "peer_id": "p1",
        "ip": "10.0.0.1", "port": 6881, "left": 9, "ts": 1.5})
    assert rec["timeUnixNano"] == "1500000000"
    assert rec["eventName"] == "iris.swarm.join"
    assert rec["body"]["stringValue"] == "swarm join"
    attrs = {a["key"]: a["value"] for a in rec["attributes"]}
    assert attrs["iris.torrent.peer_id"] == {"stringValue": "p1"}
    assert attrs["iris.torrent.info_hash"] == {"stringValue": "abc"}
    assert attrs["network.peer.address"] == {"stringValue": "10.0.0.1"}
    assert attrs["network.peer.port"] == {"intValue": "6881"}
    assert attrs["network.transport"] == {"stringValue": "tcp"}
    assert attrs["iris.torrent.left"] == {"intValue": "9"}
    assert "event" not in attrs


def test_build_log_record_omits_none_left():
    rec = otlp.build_log_record({
        "event": "stale", "info_hash": "abc", "peer_id": "p1",
        "ip": "10.0.0.1", "port": 6881, "left": None, "ts": 2})
    keys = {a["key"] for a in rec["attributes"]}
    assert "iris.torrent.left" not in keys


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
    exp.emit({"event": "join", "peer_id": "p1", "ts": 0})
    exp.emit({"event": "join", "peer_id": "p2", "ts": 0})
    n = exp.flush()
    assert n == 2
    assert len(sent) == 1
    url, body = sent[0]
    assert url == "http://collector:4318/v1/logs"
    text = body.decode()
    assert "p1" in text and "p2" in text


def test_flush_clears_queue():
    sent = []
    exp = otlp.OTLPLogExporter("http://c:4318",
                               sender=lambda u, b: sent.append(b))
    exp.emit({"event": "join", "ts": 0})
    exp.flush()
    assert exp.flush() == 0      # nothing left to send
    assert len(sent) == 1


def test_queue_is_bounded_drop_oldest():
    sent = []
    exp = otlp.OTLPLogExporter("http://c:4318", max_queue=2,
                               sender=lambda u, b: sent.append(b))
    for pid in ("p1", "p2", "p3"):
        exp.emit({"event": "join", "peer_id": pid, "ts": 0})
    exp.flush()
    text = sent[0].decode()
    assert "p3" in text and "p2" in text and "p1" not in text


def test_flush_empty_does_not_call_sender():
    sent = []
    exp = otlp.OTLPLogExporter("http://c:4318",
                               sender=lambda u, b: sent.append(b))
    assert exp.flush() == 0
    assert sent == []


def test_sender_failure_is_swallowed():
    def boom(url, body):
        raise OSError("collector down")
    exp = otlp.OTLPLogExporter("http://c:4318", sender=boom)
    exp.emit({"event": "join", "ts": 0})
    assert exp.flush() == 0       # swallowed; reported as 0 delivered


# --- build_report_record (device telemetry reports, issue #13) ---

def _device_report():
    return {
        "ts": 1783000000,
        "image_id": "cat9k_iosxe.17.15.01.SPA.bin",
        "event": "staging-complete",
        "transfer": {"total_bytes": 1215751680, "elapsed_s": 300,
                     "avg_bps": 4052505, "sha_ok": True,
                     "stage_state": "ready"},
        "link": {"tier": "good", "rtt_ms_median": 12, "rtt_samples": 8,
                 "hb_failures": 0, "trimmed": False},
        "peers": [{"ip": "10.0.0.7", "rx_bytes": 123456789, "tx_bytes": 0}],
        "agent": {"version": "x", "runtime_mode": "guestshell"},
        "received_at": 1783000042.5,
    }


def test_build_report_record_maps_core_fields():
    rec = otlp.build_report_record(_device_report(), "100.92.9.3")
    assert rec["timeUnixNano"] == str(int(float(1783000000) * 1e9))
    assert rec["severityText"] == "INFO"
    assert rec["eventName"] == "iris.device.report"
    attrs = {a["key"]: a["value"] for a in rec["attributes"]}
    assert attrs["device.id"] == {"stringValue": "100.92.9.3"}
    assert attrs["iris.image.id"] == {
        "stringValue": "cat9k_iosxe.17.15.01.SPA.bin"}
    assert attrs["iris.link.tier"] == {"stringValue": "good"}
    assert attrs["iris.transfer.throughput_avg"] == {
        "intValue": "4052505"}               # int64-as-string rule
    assert "event" not in attrs and "device_id" not in attrs


def test_build_report_record_missing_fields_are_omitted_not_raised():
    rec = otlp.build_report_record({}, "d1")
    assert rec["timeUnixNano"] == "0"
    assert rec["eventName"] == "iris.device.report"
    keys = {a["key"] for a in rec["attributes"]}
    assert keys == {"device.id"}             # only the constant survives


def test_build_report_record_tolerates_garbage_sections():
    rec = otlp.build_report_record(
        {"ts": "not-a-number", "link": "garbage", "transfer": None,
         "image_id": "img.bin"}, "d1")
    assert rec["timeUnixNano"] == "0"
    attrs = {a["key"]: a["value"] for a in rec["attributes"]}
    assert attrs["iris.image.id"] == {"stringValue": "img.bin"}
    assert "iris.link.tier" not in attrs
    assert "iris.transfer.throughput_avg" not in attrs


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
             "peer_id": "p1", "ip": "10.0.0.2", "port": 6881, "left": 500})
        assert rec["eventName"] == "iris.swarm.start"
        attrs = {a["key"]: a["value"] for a in rec["attributes"]}
        assert attrs["network.peer.address"] == {"stringValue": "10.0.0.2"}
        assert attrs["network.peer.port"] == {"intValue": "6881"}
        assert attrs["network.transport"] == {"stringValue": "tcp"}
        assert attrs["iris.torrent.info_hash"] == {"stringValue": "aa11"}
        assert attrs["iris.torrent.left"] == {"intValue": "500"}
        assert "event" not in attrs        # legacy key gone

    def test_report_record_semconv_and_peers(self):
        report = {"ts": 3, "image_id": "img-1",
                  "link": {"tier": "good"},
                  "transfer": {"avg_bps": 42},
                  "agent": {"version": "9", "runtime_mode": "container"},
                  "peers": [{"ip": "10.0.0.3", "rx_bytes": 7, "tx_bytes": 1,
                             "avg_bps": 3}]}
        enrich = {"model": "C9300", "free_flash_bytes": 5,
                  "stage_state": "ready",
                  "peer_devices": {"10.0.0.3": "d3"}}
        rec = otlp.build_report_record(report, "d1", enrich=enrich)
        assert rec["eventName"] == "iris.device.report"
        attrs = {a["key"]: a["value"] for a in rec["attributes"]}
        assert attrs["device.id"] == {"stringValue": "d1"}
        assert attrs["iris.image.id"] == {"stringValue": "img-1"}
        assert attrs["iris.link.tier"] == {"stringValue": "good"}
        assert attrs["iris.transfer.throughput_avg"] == {"intValue": "42"}
        assert attrs["device.model.identifier"] == {"stringValue": "C9300"}
        assert attrs["iris.device.flash.free"] == {"intValue": "5"}
        assert attrs["iris.stage.state"] == {"stringValue": "ready"}
        assert attrs["iris.agent.runtime"] == {"stringValue": "container"}
        assert attrs["iris.agent.version"] == {"stringValue": "9"}
        row = attrs["iris.transfer.peers"]["arrayValue"]["values"][0]
        kv = {p["key"]: p["value"] for p in row["kvlistValue"]["values"]}
        assert kv["network.peer.address"] == {"stringValue": "10.0.0.3"}
        assert kv["device.id"] == {"stringValue": "d3"}
        assert kv["iris.transfer.received"] == {"intValue": "7"}
        assert kv["iris.transfer.sent"] == {"intValue": "1"}

    def test_enrichment_sanitized(self):
        rec = otlp.build_report_record(
            {"ts": 1, "image_id": "i"}, "d1",
            enrich={"model": "x" * 500, "free_flash_bytes": "junk",
                    "stage_state": None, "peer_devices": {}})
        attrs = {a["key"]: a["value"] for a in rec["attributes"]}
        assert len(attrs["device.model.identifier"]["stringValue"]) == 128
        assert "iris.device.flash.free" not in attrs   # non-int dropped
        assert "iris.stage.state" not in attrs


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
