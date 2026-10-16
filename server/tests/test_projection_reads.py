# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Fresh FIFO read admission, with writers and other API routes independent."""
from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time

import pytest

import management_api
from projection_reads import ProjectionBusy, ReadProjectionGate
from test_gui_server import _auth, _req, _serve_full


def queued(gate, count):
    """Wait for actual queue entry, never assume thread scheduling order."""
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        with gate._condition:
            if len(gate._queue) == count:
                return
        threading.Event().wait(.001)
    pytest.fail("projection callers did not reach the expected queue depth")


def test_fifo_arrival_order_even_when_a_reader_fails():
    gate, order = ReadProjectionGate(), []

    @gate.ordered
    def read(value):
        order.append(value)
        if value == 2:
            raise ValueError("fixture read error")
        return value

    with ThreadPoolExecutor(max_workers=8) as pool:
        with gate.enter():
            futures = []
            for index in range(8):
                futures.append(pool.submit(read, index))
                queued(gate, index + 2)
            assert order == []
        for index, future in enumerate(futures):
            if index == 2:
                with pytest.raises(ValueError, match="fixture read error"):
                    future.result(timeout=3)
            else:
                assert future.result(timeout=3) == index
    assert order == list(range(8))
    assert not gate._queue and gate._owner is None
    assert read(9) == 9


def test_wait_timeout_removes_only_waiter_and_does_not_execute_read():
    gate = ReadProjectionGate(wait_timeout=.05)
    calls = []

    @gate.ordered
    def read():
        calls.append(True)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with gate.enter():
            future = pool.submit(read)
            with pytest.raises(ProjectionBusy):
                future.result(timeout=3)
            assert len(gate._queue) == 1
            assert gate._owner == threading.get_ident()
            assert calls == []
        read()
    assert calls == [True] and not gate._queue


def test_interrupted_wait_keeps_owner_and_releases_next_reader(monkeypatch):
    gate = ReadProjectionGate()
    original = gate._condition.wait_for

    class Interrupted(BaseException):
        pass

    def interrupt_wait(predicate, timeout=None):
        if not predicate():
            raise Interrupted()
        return original(predicate, timeout=timeout)

    with ThreadPoolExecutor(max_workers=1) as pool:
        with gate.enter():
            monkeypatch.setattr(gate._condition, "wait_for", interrupt_wait)
            future = pool.submit(gate.ordered(lambda: pytest.fail("ran waiter")))
            with pytest.raises(Interrupted):
                future.result(timeout=3)
            assert len(gate._queue) == 1
            assert gate._owner == threading.get_ident()
        monkeypatch.setattr(gate._condition, "wait_for", original)
        assert pool.submit(gate.ordered(lambda: 42)).result(timeout=3) == 42


def test_nested_gate_fails_immediately_and_base_exception_releases_it():
    gate = ReadProjectionGate()
    with gate.enter():
        with pytest.raises(RuntimeError, match="cannot be nested"):
            with gate.enter():
                pytest.fail("nested read")
        assert len(gate._queue) == 1
    with pytest.raises(KeyboardInterrupt):
        with gate.enter():
            raise KeyboardInterrupt()
    with gate.enter():
        assert len(gate._queue) == 1
    assert not gate._queue


def test_decorator_preserves_call_signature_and_never_reuses_result():
    gate, current = ReadProjectionGate(), {"version": 1}

    @gate.ordered
    def read(label, *, size=1):
        """Fixture projection."""
        return {"label": label, "size": size, **current}

    assert read.__name__ == "read" and read.__doc__ == "Fixture projection."
    first = read("a", size=2)
    current["version"] = 2
    assert read("a", size=2) == {"label": "a", "size": 2, "version": 2}
    assert first["version"] == 1


@pytest.fixture
def api(tmp_path, monkeypatch):
    gates = []

    def create_gate():
        gate = ReadProjectionGate()
        gates.append(gate)
        return gate

    monkeypatch.setattr(management_api.projection_reads, "ReadProjectionGate", create_gate)
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    host, port, stores, stop = _serve_full(tmp_path, now_fn=lambda: 1000)
    try:
        cookie, csrf = _auth(host, port)
        assert len(gates) == 1
        yield host, port, stores, {"Cookie": cookie, "X-CSRF-Token": csrf}, gates[0], stop.__self__
    finally:
        stop()
        stop.__self__.server_close()


ROUTES = ("/api/devices?limit=100", "/api/overview", "/api/peer-policy")


def test_all_three_http_reads_share_queue_but_writes_and_session_do_not(api):
    host, port, (_app, fleet, _creds, cat), headers, gate, _server = api
    order = []

    def get(route):
        result = _req(host, port, "GET", route, headers=headers)
        order.append(route)
        return result

    with ThreadPoolExecutor(max_workers=3) as pool:
        with gate.enter():
            reads = []
            for route in ROUTES:
                reads.append(pool.submit(get, route))
                queued(gate, len(reads) + 1)
            assert not order
            assert _req(host, port, "GET", "/api/session", headers=headers)[0] == 200
            # Authenticated writes commit while every projection is queued.
            assert _req(host, port, "POST", "/api/devices", {
                "device_id": "fresh", "device_ip": "192.0.2.1", "model": "C9300"
            }, headers=headers)[0] == 200
            cat.set_policy("fresh", approved_image_ids=["img1"])
            cat.record_heartbeat("fresh", {
                "stage_state": "ready", "staged_image_ids": ["img1"],
                "errored_image_ids": []}, now=999)
            # This write has its own policy projection before mutation. It must
            # not acquire the GET queue, even with queued fleet reads.
            status, _, _ = _req(host, port, "PUT", "/api/peer-policy/quarantine/fresh", {
                "quarantined": True, "if_revision": 1
            }, headers=headers)
            assert status == 200
        responses = [future.result(timeout=3) for future in reads]
    assert all(status == 200 for status, _, _ in responses)
    inventory, overview, policy = [json.loads(raw) for _, _, raw in responses]
    assert inventory["revision"] == fleet.snapshot()[0]
    assert inventory["total"] == 1 and inventory["devices"][0]["device_id"] == "fresh"
    assert inventory["devices"][0]["staged_image_ids"] == ["img1"]
    assert overview["devices"] == overview["assigned"] == overview["staged"] == 1
    assert policy["quarantine_assignments"] == ["fresh"]
    # Response sends are deliberately OUTSIDE the gate, so response arrival
    # order is not asserted; the deterministic unit test checks entry ordering.
    assert set(order) == set(ROUTES)


@pytest.mark.parametrize("route", ROUTES)
def test_http_wait_timeout_is_bounded_503_and_recovers_without_dirty_shutdown(api, route):
    host, port, _stores, headers, gate, server = api
    gate._wait_timeout = .05
    with ThreadPoolExecutor(max_workers=1) as pool:
        with gate.enter():
            status, response_headers, raw = pool.submit(
                _req, host, port, "GET", route, headers=headers).result(timeout=3)
            assert status == 503
            assert response_headers["Retry-After"] == "1"
            assert json.loads(raw)["code"] == "projection-busy"
            assert len(gate._queue) == 1
        assert _req(host, port, "GET", route, headers=headers)[0] == 200
    assert not gate._queue and not server._request_lifecycle_state()["failed"]


@pytest.mark.parametrize("route", ROUTES)
def test_read_failure_remains_503_and_does_not_poison_next_request(api, monkeypatch, route):
    host, port, (_app, fleet, _creds, _cat), headers, gate, _server = api
    original = fleet.snapshot

    def fail():
        raise management_api.gui_fleet.FleetStateError("fixture unavailable")

    monkeypatch.setattr(fleet, "snapshot", fail)
    status, _, raw = _req(host, port, "GET", route, headers=headers)
    assert status == 503 and "unavailable" in json.loads(raw)["error"]
    assert not gate._queue
    monkeypatch.setattr(fleet, "snapshot", original)
    fleet.upsert({"device_id": "recovered", "device_ip": "192.0.2.2"})
    assert _req(host, port, "GET", route, headers=headers)[0] == 200


def test_gates_are_per_server_and_unauthed_requests_never_join_queue(api, tmp_path):
    host, port, stores, headers, gate, _server = api
    app, fleet, creds, cat = stores
    other = management_api.make_server(host, 0, app, fleet=fleet, creds=creds,
                                       catalog=cat, now_fn=lambda: 1000)
    handler = object.__new__(other.RequestHandlerClass)
    try:
        with gate.enter():
            # A second server instance does not share a process-global lock.
            assert handler._overview()["devices"] == 0
            for route in ROUTES:
                assert _req(host, port, "GET", route)[0] == 401
                assert len(gate._queue) == 1
    finally:
        other.server_close()


def test_slow_response_send_does_not_hold_read_queue(api, monkeypatch):
    host, port, _stores, headers, gate, server = api
    entered, release = threading.Event(), threading.Event()
    original = server.RequestHandlerClass._json

    def hold_response(handler, status, body, **kwargs):
        if handler.path == "/api/overview":
            entered.set()
            assert release.wait(3), "fixture response was never released"
        return original(handler, status, body, **kwargs)

    monkeypatch.setattr(server.RequestHandlerClass, "_json", hold_response)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_req, host, port, "GET", "/api/overview", headers=headers)
        try:
            assert entered.wait(3)
            assert not gate._queue
            for route in ("/api/devices?limit=100", "/api/peer-policy"):
                assert _req(host, port, "GET", route, headers=headers)[0] == 200
        finally:
            release.set()
        assert future.result(timeout=3)[0] == 200
