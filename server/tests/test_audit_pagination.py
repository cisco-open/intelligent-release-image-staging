# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import json

import pytest

import audit


@pytest.fixture(params=[False, True], ids=["indexed", "fallback"])
def log(tmp_path, monkeypatch, request):
    if request.param:
        monkeypatch.setattr(audit, "_indexed", lambda _path: None)
    return tmp_path / "audit.jsonl"


def rows(path, records):
    with path.open("ab") as stream:
        for record in records:
            stream.write(json.dumps(record).encode() + b"\n")


def test_pages_include_all_ties_and_identical_records_despite_appends(log):
    records = [{"ts": 100, "event": str(i)} for i in range(6)]
    records[2] = records[1].copy()
    rows(log, records)
    first = audit.read_page(log, limit=2)
    rows(log, [{"ts": 100, "event": "newer"}])
    second = audit.read_page(log, limit=2, cursor=first["next_cursor"])
    third = audit.read_page(log, limit=2, cursor=second["next_cursor"])
    assert first["events"] + second["events"] + third["events"] == records[::-1]
    assert third["next_cursor"] is None


def test_filters_and_complete_line_rules_hold_on_every_page(log):
    records = [{"ts": i // 2, "event": str(i), "category": "auth" if i % 3 else "device"}
               for i in range(14)]
    rows(log, records)
    with log.open("ab") as stream:
        stream.write(b'junk\n[]\n\n{"ts":4,"event":"torn"}')
    filters = dict(before_ts=6, after_ts=2, category="auth")
    actual, cursor = [], None
    while True:
        page = audit.read_page(log, limit=1, cursor=cursor, **filters)
        actual.extend(page["events"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    expected = [r for r in reversed(records) if 2 <= r["ts"] < 6 and r["category"] == "auth"]
    assert actual == expected


@pytest.mark.parametrize("change", ["replace", "truncate", "modify", "remove"])
def test_expired_position_never_silently_returns_another_page(log, change):
    rows(log, [{"ts": 100, "event": str(i)} for i in range(4)])
    cursor = audit.read_page(log, limit=1)["next_cursor"]
    if change == "replace":
        replacement = log.with_suffix(".new")
        replacement.write_bytes(log.read_bytes())
        replacement.replace(log)
    elif change == "truncate":
        log.write_bytes(b"")
    elif change == "modify":
        log.write_bytes(log.read_bytes().replace(b'"3"', b'"X"'))
    else:
        log.unlink()
    with pytest.raises(audit.CursorExpired):
        audit.read_page(log, limit=1, cursor=cursor)


@pytest.mark.parametrize("cursor", ["", "../file", "1.0.0.0.1.bad", "a" * 10000, 123])
def test_malformed_cursor_is_rejected_before_open(log, cursor):
    with pytest.raises(ValueError, match="invalid audit cursor"):
        audit.read_page(log, cursor=cursor)


def test_forged_length_does_not_control_read_size(log):
    rows(log, [{"ts": 1}, {"ts": 2}])
    cursor = audit.read_page(log, limit=1)["next_cursor"].split(".")
    cursor[4] = "f" * 16
    with pytest.raises(audit.CursorExpired):
        audit.read_page(log, cursor=".".join(cursor))


def test_missing_empty_zero_and_unlimited_pages(log):
    assert audit.read_page(log) == {"events": [], "next_cursor": None}
    rows(log, [{"ts": 1}, {"ts": 1}])
    assert audit.read_page(log, limit=0) == {"events": [], "next_cursor": None}
    assert audit.read_page(log, limit=None) == {"events": [{"ts": 1}, {"ts": 1}], "next_cursor": None}
