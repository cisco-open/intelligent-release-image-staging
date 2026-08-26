# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Task 22: the OTLP log queue is a stable, bounded object separate from the
mutable destination transport. A telemetry-destination change / disable /
re-enable swaps the transport but retains the one queue, so already-queued
events are never dropped and never re-ordered, and a failed flush restores the
exact original batch (order + identity) without losing concurrent emits."""

import json
import threading

import otlp
import telemetry
import telemetry_destination


# --- LogQueue: stable bounded FIFO with drop accounting -------------------

def test_log_queue_is_fifo_and_bounded_counts_drops():
    q = otlp.LogQueue(max_queue=2)
    for pid in ("p1", "p2", "p3", "p4"):
        q.emit({"event": "join", "peer_id": pid, "ts": 0})
    # newest two retained, in order; the two oldest counted as drops
    assert q.queued == 2
    assert q.dropped_total == 2
    assert [e["peer_id"] for e in q.snapshot()] == ["p3", "p4"]


def test_log_queue_flush_removes_only_on_confirmed_success():
    q = otlp.LogQueue(max_queue=10)
    q.emit({"event": "join", "peer_id": "p1", "ts": 0})
    q.emit({"event": "join", "peer_id": "p2", "ts": 0})

    # A failing transport must leave the batch intact, in order, with IDs.
    def fail(batch):
        raise OSError("collector down")

    delivered = q.flush(fail)
    assert delivered == 0
    assert [e["peer_id"] for e in q.snapshot()] == ["p1", "p2"]
    assert q.queued == 2

    # A succeeding transport removes exactly what it confirmed.
    sent = []
    delivered = q.flush(lambda batch: sent.append(list(batch)) or len(batch))
    assert delivered == 2
    assert q.queued == 0
    assert [e["peer_id"] for e in sent[0]] == ["p1", "p2"]


def test_log_queue_empty_flush_is_no_attempt():
    q = otlp.LogQueue()
    called = []
    assert q.flush(lambda b: called.append(b) or len(b)) is None
    assert called == []


def test_failed_flush_preserves_concurrent_emits_without_loss_or_reorder():
    q = otlp.LogQueue(max_queue=1000)
    for i in range(5):
        q.emit({"event": "join", "peer_id": "orig%d" % i, "ts": 0})

    started = threading.Event()

    def slow_fail(batch):
        started.set()
        # let a concurrent emit land during the in-flight (failing) send
        for _ in range(1000):
            if q.queued > 5:
                break
        raise OSError("down")

    t = threading.Thread(target=lambda: q.flush(slow_fail))
    t.start()
    started.wait(1.0)
    q.emit({"event": "join", "peer_id": "concurrent", "ts": 0})
    t.join(2.0)

    ids = [e["peer_id"] for e in q.snapshot()]
    # original batch restored in order, concurrent emit appended after, nothing lost
    assert ids == ["orig0", "orig1", "orig2", "orig3", "orig4", "concurrent"]


def test_failed_inflight_flush_stays_bounded_when_concurrent_emits_overflow():
    q = otlp.LogQueue(max_queue=2)
    q.emit({"peer_id": "p1"})
    q.emit({"peer_id": "p2"})
    sending = threading.Event()
    release = threading.Event()

    def fail(batch):
        assert [event["peer_id"] for event in batch] == ["p1", "p2"]
        sending.set()
        assert release.wait(1.0)
        raise OSError("down")

    thread = threading.Thread(target=lambda: q.flush(fail))
    thread.start()
    assert sending.wait(1.0)
    q.emit({"peer_id": "p3"})
    q.emit({"peer_id": "p4"})
    release.set()
    thread.join(1.0)

    # In-flight events are part of the bounded FIFO: overflow drops p1, then p2.
    assert q.queued == 2
    assert q.dropped_total == 2
    assert [event["peer_id"] for event in q.snapshot()] == ["p3", "p4"]


def test_concurrent_flushes_deliver_fifo_without_duplicates():
    q = otlp.LogQueue(max_queue=10)
    q.emit({"peer_id": "p1"})
    q.emit({"peer_id": "p2"})
    first_started = threading.Event()
    release_first = threading.Event()
    delivered = []

    def first_send(batch):
        first_started.set()
        assert release_first.wait(1.0)
        delivered.extend(event["peer_id"] for event in batch)

    def second_send(batch):
        delivered.extend(event["peer_id"] for event in batch)

    first = threading.Thread(target=lambda: q.flush(first_send))
    first.start()
    assert first_started.wait(1.0)
    second = threading.Thread(target=lambda: q.flush(second_send))
    second.start()
    q.emit({"peer_id": "p3"})
    release_first.set()
    first.join(1.0)
    second.join(1.0)

    assert delivered == ["p1", "p2", "p3"]
    assert q.queued == 0


def test_successful_inflight_flush_removes_only_sent_prefix():
    q = otlp.LogQueue(max_queue=10)
    q.emit({"peer_id": "p1"})
    sending = threading.Event()
    release = threading.Event()

    def send(batch):
        assert [event["peer_id"] for event in batch] == ["p1"]
        sending.set()
        assert release.wait(1.0)

    thread = threading.Thread(target=lambda: q.flush(send))
    thread.start()
    assert sending.wait(1.0)
    q.emit({"peer_id": "p2"})
    release.set()
    thread.join(1.0)

    assert [event["peer_id"] for event in q.snapshot()] == ["p2"]


def test_successful_inflight_eviction_is_delivery_not_drop():
    q = otlp.LogQueue(max_queue=1)
    q.emit({"peer_id": "p1"})
    sending = threading.Event()
    release = threading.Event()

    def send(batch):
        sending.set()
        assert release.wait(1.0)

    thread = threading.Thread(target=lambda: q.flush(send))
    thread.start()
    assert sending.wait(1.0)
    q.emit({"peer_id": "p2"})
    release.set()
    thread.join(1.0)
    assert q.dropped_total == 0
    assert [event["peer_id"] for event in q.snapshot()] == ["p2"]


# --- OTLPLogTransport: mutable destination, no queue ----------------------

def test_transport_send_posts_batch_and_reports_delivered():
    sent = []
    tx = otlp.OTLPLogTransport(
        "http://collector:4318",
        sender=lambda url, body, headers=None: sent.append((url, body)))
    n = tx.send([{"event": "join", "ip": "10.9.9.9", "ts": 0}])
    assert n == 1
    url, body = sent[0]
    assert url == "http://collector:4318/v1/logs"
    assert "10.9.9.9" in body.decode()


def test_transport_send_failure_raises_so_queue_can_retain():
    def boom(url, body, headers=None):
        raise OSError("down")
    tx = otlp.OTLPLogTransport("http://c:4318", sender=boom)
    try:
        tx.send([{"event": "join", "ts": 0}])
        assert False, "expected send to raise"
    except Exception:
        pass


# --- Hub retains one queue across destination changes ---------------------

def _dest(tmp_path):
    return telemetry_destination.DestinationSettings(
        telemetry_destination.settings_path(str(tmp_path)))


def test_hub_retains_queue_across_endpoint_change(tmp_path):
    path = telemetry_destination.settings_path(str(tmp_path))
    telemetry_destination.write(path, "http://a:4318", True)
    sent = []
    hub = telemetry.Telemetry(
        dest_settings=_dest(tmp_path), env_endpoint="", env_enabled=False)
    hub._log_sender = lambda url, body, headers=None: sent.append(url)
    hub._refresh_exporters()
    # queue an event, then change endpoint BEFORE any flush
    hub.on_swarm_event({"event": "join", "ip": "10.9.9.9", "ts": 0})
    telemetry_destination.write(path, "http://b:4318", True)
    hub._refresh_exporters()
    # the previously queued event survives the transport swap and flushes to B
    hub._flush_logs(now=1.0)
    assert sent and all(u == "http://b:4318/v1/logs" for u in sent)


def test_hub_disable_then_reenable_retains_queue(tmp_path):
    path = telemetry_destination.settings_path(str(tmp_path))
    telemetry_destination.write(path, "http://a:4318", True)
    sent = []
    hub = telemetry.Telemetry(
        dest_settings=_dest(tmp_path), env_endpoint="", env_enabled=False)
    hub._log_sender = lambda url, body, headers=None: sent.append(url)
    hub._refresh_exporters()
    hub.on_swarm_event({"event": "join", "ip": "10.9.9.9", "ts": 0})
    # disable: transport dropped, queue retained (no fake success)
    telemetry_destination.write(path, "http://a:4318", False)
    hub._refresh_exporters()
    hub._flush_logs(now=1.0)
    assert sent == []           # disabled: no transport, nothing sent
    assert hub.log_queue.queued == 1     # event retained, not a fake success
    # re-enable: same queue flushes now
    telemetry_destination.write(path, "http://a:4318", True)
    hub._refresh_exporters()
    hub._flush_logs(now=2.0)
    assert sent == ["http://a:4318/v1/logs"]
    assert hub.log_queue.queued == 0
