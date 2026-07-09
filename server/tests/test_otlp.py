# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import otlp


def test_build_log_record_maps_core_fields():
    rec = otlp.build_log_record({
        "event": "join", "info_hash": "abc", "peer_id": "p1",
        "ip": "10.0.0.1", "port": 6881, "left": 9, "ts": 1.5})
    assert rec["timeUnixNano"] == "1500000000"
    assert rec["body"]["stringValue"] == "join"
    attrs = {a["key"]: a["value"] for a in rec["attributes"]}
    assert attrs["peer_id"] == {"stringValue": "p1"}
    assert attrs["info_hash"] == {"stringValue": "abc"}
    assert attrs["ip"] == {"stringValue": "10.0.0.1"}
    assert attrs["port"] == {"intValue": "6881"}
    assert attrs["left"] == {"intValue": "9"}
    assert attrs["event"] == {"stringValue": "join"}


def test_build_log_record_omits_none_left():
    rec = otlp.build_log_record({
        "event": "stale", "info_hash": "abc", "peer_id": "p1",
        "ip": "10.0.0.1", "port": 6881, "left": None, "ts": 2})
    keys = {a["key"] for a in rec["attributes"]}
    assert "left" not in keys


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
    assert rec["body"]["stringValue"] == "device-report"
    attrs = {a["key"]: a["value"] for a in rec["attributes"]}
    assert attrs["event"] == {"stringValue": "device-report"}
    assert attrs["device_id"] == {"stringValue": "100.92.9.3"}
    assert attrs["image_id"] == {
        "stringValue": "cat9k_iosxe.17.15.01.SPA.bin"}
    assert attrs["tier"] == {"stringValue": "good"}
    assert attrs["avg_bps"] == {"intValue": "4052505"}   # int64-as-string rule


def test_build_report_record_missing_fields_are_omitted_not_raised():
    rec = otlp.build_report_record({}, "d1")
    assert rec["timeUnixNano"] == "0"
    keys = {a["key"] for a in rec["attributes"]}
    assert keys == {"event", "device_id"}    # only the constants survive


def test_build_report_record_tolerates_garbage_sections():
    rec = otlp.build_report_record(
        {"ts": "not-a-number", "link": "garbage", "transfer": None,
         "image_id": "img.bin"}, "d1")
    assert rec["timeUnixNano"] == "0"
    attrs = {a["key"]: a["value"] for a in rec["attributes"]}
    assert attrs["image_id"] == {"stringValue": "img.bin"}
    assert "tier" not in attrs
    assert "avg_bps" not in attrs


def test_build_report_record_non_dict_report():
    rec = otlp.build_report_record("total garbage", "d1")
    attrs = {a["key"]: a["value"] for a in rec["attributes"]}
    assert attrs["device_id"] == {"stringValue": "d1"}
    assert attrs["event"] == {"stringValue": "device-report"}
