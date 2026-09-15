# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("api_exercise", Path(__file__).with_name("api-exercise.py"))
exercise = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exercise)


def test_summary_distinguishes_successful_capacity_from_errors():
    records = [{"status": status, "seconds": seconds} for status, seconds in
               [(200, .01), (200, .02), (429, .03), (503, .04), (0, .05)]]
    result = exercise.summary(records, 2)
    assert result["requests_per_second"] == 2.5
    assert result["successful_per_second"] == 1
    assert result["statuses"] == {"200": 2, "429": 1, "503": 1, "0": 1}
    assert result["p95_ms"] == 50


def test_empty_summary_does_not_invent_latency():
    assert exercise.summary([], 0)["p50_ms"] is None


def test_multistatus_is_not_a_clean_success():
    result = exercise.summary([{"status": 207, "seconds": .1}], .1)
    assert result["successful"] == 0
    assert result["partial_responses"] == 1


def test_client_refuses_plaintext_and_path_base():
    import pytest
    for base in ("http://localhost", "https://localhost/api"):
        with pytest.raises(ValueError):
            exercise.Client(base, None)


def test_pacer_spaces_starts_without_catch_up(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(exercise.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(exercise.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    pacer = exercise.Pacer(20)
    pacer.wait()
    pacer.wait()
    assert clock[0] == .05
    clock[0] = 100
    pacer.wait()
    pacer.wait()
    assert clock[0] == 100.05
