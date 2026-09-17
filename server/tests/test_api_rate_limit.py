# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import pytest
from concurrent.futures import ThreadPoolExecutor

import api_rate_limit


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def test_disabled_by_default_and_rejects_invalid_configuration():
    limiter = api_rate_limit.AggregateRateLimiter.from_env({})
    assert limiter.admit("GET") == (True, 0)
    assert limiter.admit("POST") == (True, 0)
    for env in (
            {"IRIS_API_RATE_READ": "-1"},
            {"IRIS_API_RATE_TOTAL": "nan"},
            {"IRIS_API_BURST_WRITE": "0"},
            {"IRIS_API_BURST_TOTAL": "1001"}):
        with pytest.raises(ValueError):
            api_rate_limit.AggregateRateLimiter.from_env(env)


def test_read_write_and_total_buckets_are_separate_and_shared():
    clock = Clock()
    limiter = api_rate_limit.AggregateRateLimiter(
        read_rate=1, write_rate=2, total_rate=0, write_burst=2,
        clock=clock)
    assert limiter.admit("GET") == (True, 0)
    assert limiter.admit("GET") == (False, 1)
    # A separate write budget remains available while read is depleted.
    assert limiter.admit("POST") == (True, 0)
    assert limiter.admit("DELETE") == (True, 0)
    assert limiter.admit("PATCH") == (False, 1)
    clock.advance(1)
    assert limiter.admit("GET") == (True, 0)
    assert limiter.admit("POST") == (True, 0)


def test_total_budget_is_shared_and_failed_admission_is_atomic():
    clock = Clock()
    limiter = api_rate_limit.AggregateRateLimiter(
        read_rate=0, write_rate=0.1, total_rate=1, clock=clock)
    assert limiter.admit("GET") == (True, 0)
    # Total budget rejects this write. It must not debit its still-full write
    # bucket while only one of the two buckets is available.
    assert limiter.admit("POST") == (False, 1)
    clock.advance(1)
    assert limiter.admit("POST") == (True, 0)
    # The shared total bucket, rather than per-category state, is exhausted.
    assert limiter.admit("GET") == (False, 1)


def test_burst_is_bounded_and_retry_uses_the_slowest_required_bucket():
    clock = Clock()
    limiter = api_rate_limit.AggregateRateLimiter(
        read_rate=0.5, total_rate=0.25, read_burst=2, total_burst=1,
        clock=clock)
    assert limiter.admit("GET") == (True, 0)
    assert limiter.admit("GET") == (False, 4)
    clock.advance(3.2)
    assert limiter.admit("GET") == (False, 1)
    clock.advance(0.8)
    assert limiter.admit("GET") == (True, 0)


def test_concurrent_calls_cannot_overspend_a_bucket():
    clock = Clock()
    limiter = api_rate_limit.AggregateRateLimiter(
        read_rate=100, read_burst=1, clock=clock)
    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(lambda _: limiter.admit("GET"), range(128)))
    assert sum(allowed for allowed, _ in results) == 1
