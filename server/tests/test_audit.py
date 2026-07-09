# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import glob
import hashlib
import json
import os
import stat
import threading
import time

import audit


def _read_lines(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def test_creates_file_and_dirs(tmp_path):
    p = tmp_path / "sub" / "audit.jsonl"
    audit.append_event(str(p), "mint", "dev-1")
    assert p.exists()


def test_required_fields_present(tmp_path):
    p = tmp_path / "audit.jsonl"
    audit.append_event(str(p), "mint", "dev-1")
    lines = _read_lines(str(p))
    assert len(lines) == 1
    ev = lines[0]
    assert "ts" in ev
    assert ev["event"] == "mint"
    assert ev["device_id"] == "dev-1"
    assert isinstance(ev["ts"], int)


def test_optional_fields_present_when_given(tmp_path):
    p = tmp_path / "audit.jsonl"
    audit.append_event(
        str(p), "refresh", "dev-1",
        secret_name="catalog_token",
        old_id="aabbcc",
        new_id="ddeeff",
        src_ip="10.0.0.1",
        result="ok",
    )
    ev = _read_lines(str(p))[0]
    assert ev["secret_name"] == "catalog_token"
    assert ev["old_id"] == "aabbcc"
    assert ev["new_id"] == "ddeeff"
    assert ev["src_ip"] == "10.0.0.1"
    assert ev["result"] == "ok"


def test_optional_fields_absent_when_none(tmp_path):
    p = tmp_path / "audit.jsonl"
    audit.append_event(str(p), "mint", "dev-1")
    ev = _read_lines(str(p))[0]
    assert "secret_name" not in ev
    assert "old_id" not in ev
    assert "new_id" not in ev
    assert "src_ip" not in ev


def test_result_defaults_to_ok(tmp_path):
    p = tmp_path / "audit.jsonl"
    audit.append_event(str(p), "mint", "dev-1")
    ev = _read_lines(str(p))[0]
    assert ev["result"] == "ok"


def test_multiple_independent_json_lines(tmp_path):
    p = tmp_path / "audit.jsonl"
    audit.append_event(str(p), "mint", "dev-1")
    audit.append_event(str(p), "revoke", "dev-2")
    lines = _read_lines(str(p))
    assert len(lines) == 2
    assert lines[0]["event"] == "mint"
    assert lines[1]["event"] == "revoke"


def test_full_token_never_in_file(tmp_path):
    p = tmp_path / "audit.jsonl"
    full_token = "a" * 32  # a full 32-char hex token (token_hex(16))
    # Callers pass a truncated sha256 of the token as old_id / new_id (never a
    # value prefix). Even so, the full token value must never appear in the log.
    audit_id = hashlib.sha256(full_token.encode()).hexdigest()[:8]
    audit.append_event(str(p), "refresh", "dev-1",
                       old_id=audit_id, new_id=audit_id)
    raw = p.read_text()
    assert full_token not in raw


def test_result_fail_recorded(tmp_path):
    p = tmp_path / "audit.jsonl"
    audit.append_event(str(p), "auth_fail", "dev-1", result="fail")
    ev = _read_lines(str(p))[0]
    assert ev["result"] == "fail"


# ---------------------------------------------------------------------------
# Old-caller compatibility: replicate catalog.py's exact call shapes
# ---------------------------------------------------------------------------

def test_catalog_refresh_call_shape_still_works(tmp_path):
    """Exact shape of catalog.py's post-rotation audit call (path, event and
    device_id positional; the rest kwargs)."""
    p = tmp_path / "audit.jsonl"
    audit.append_event(
        str(p), "refresh", "dev-1",
        secret_name="catalog_token",
        old_id="aabbcc11",
        new_id="ddeeff22",
        src_ip="10.0.0.9",
    )
    ev = _read_lines(str(p))[0]
    assert ev["event"] == "refresh"
    assert ev["device_id"] == "dev-1"
    assert ev["secret_name"] == "catalog_token"
    assert ev["old_id"] == "aabbcc11"
    assert ev["new_id"] == "ddeeff22"
    assert ev["src_ip"] == "10.0.0.9"
    assert ev["result"] == "ok"


def test_catalog_auth_fail_call_shape_still_works(tmp_path):
    """Exact shape of catalog.py's token-refresh auth-failure audit call."""
    p = tmp_path / "audit.jsonl"
    audit.append_event(
        str(p), "auth_fail", "dev-1",
        src_ip="10.0.0.9",
        result="fail",
    )
    ev = _read_lines(str(p))[0]
    assert ev["event"] == "auth_fail"
    assert ev["result"] == "fail"


def test_legacy_events_auto_mapped_to_category(tmp_path):
    """Existing broker events map cleanly onto the structured vocabulary
    without their call sites changing."""
    p = tmp_path / "audit.jsonl"
    audit.append_event(str(p), "mint", "dev-1")
    audit.append_event(str(p), "refresh", "dev-1")
    audit.append_event(str(p), "refresh_fail", "dev-1", result="fail")
    audit.append_event(str(p), "revoke", "dev-1")
    audit.append_event(str(p), "auth_fail", "dev-1", result="fail")
    cats = [ev["category"] for ev in _read_lines(str(p))]
    assert cats == ["token", "token", "token", "token", "auth"]


# ---------------------------------------------------------------------------
# Structured fields (console actions)
# ---------------------------------------------------------------------------

def test_structured_fields_recorded(tmp_path):
    p = tmp_path / "audit.jsonl"
    audit.append_event(
        str(p), "settings_update",
        actor="console:admin",
        category="settings",
        action="update",
        target="stage_host",
        detail="host changed",
    )
    ev = _read_lines(str(p))[0]
    assert ev["actor"] == "console:admin"
    assert ev["category"] == "settings"
    assert ev["action"] == "update"
    assert ev["target"] == "stage_host"
    assert ev["detail"] == "host changed"
    # device_id was not given -> omitted (console actions have no device)
    assert "device_id" not in ev


def test_structured_fields_absent_when_none(tmp_path):
    p = tmp_path / "audit.jsonl"
    audit.append_event(str(p), "custom_event", "dev-1")
    ev = _read_lines(str(p))[0]
    assert "actor" not in ev
    assert "action" not in ev
    assert "target" not in ev
    assert "detail" not in ev
    assert "category" not in ev  # unknown event, no explicit category


def test_explicit_ts_used(tmp_path):
    p = tmp_path / "audit.jsonl"
    audit.append_event(str(p), "mint", "dev-1", ts=12345)
    ev = _read_lines(str(p))[0]
    assert ev["ts"] == 12345


def test_explicit_category_wins_over_auto_map(tmp_path):
    p = tmp_path / "audit.jsonl"
    audit.append_event(str(p), "mint", "dev-1", category="onboard")
    ev = _read_lines(str(p))[0]
    assert ev["category"] == "onboard"


# ---------------------------------------------------------------------------
# Retention prune (90-day window)
# ---------------------------------------------------------------------------

def test_retention_prune_drops_expired_keeps_fresh(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    now = 20_000_000_000  # injected 'now' (far future so defaults are exact)
    audit.append_event(p, "mint", "dev-old", ts=now - 91 * 86400)
    audit.append_event(p, "mint", "dev-edge", ts=now - 89 * 86400)
    audit.append_event(p, "mint", "dev-new", ts=now - 60)
    audit.prune(p, now=now)
    devs = [ev["device_id"] for ev in _read_lines(p)]
    assert devs == ["dev-edge", "dev-new"]


def test_retention_days_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_AUDIT_RETENTION_DAYS", "1")
    p = str(tmp_path / "audit.jsonl")
    now = 20_000_000_000
    audit.append_event(p, "mint", "dev-old", ts=now - 2 * 86400)
    audit.append_event(p, "mint", "dev-new", ts=now - 3600)
    audit.prune(p, now=now)
    devs = [ev["device_id"] for ev in _read_lines(p)]
    assert devs == ["dev-new"]


# ---------------------------------------------------------------------------
# Entry-cap eviction
# ---------------------------------------------------------------------------

def test_entry_cap_evicts_oldest(tmp_path, monkeypatch):
    monkeypatch.setenv("IRIS_AUDIT_MAX_EVENTS", "5")
    p = str(tmp_path / "audit.jsonl")
    for i in range(8):
        audit.append_event(p, "mint", "dev-%d" % i)
    audit.prune(p)
    devs = [ev["device_id"] for ev in _read_lines(p)]
    assert devs == ["dev-%d" % i for i in range(3, 8)]


def test_entry_cap_evicts_by_position_despite_clock_games(tmp_path,
                                                          monkeypatch):
    """A forged far-future ts must not shield an old entry from the cap:
    eviction is by file position (append order), not by claimed timestamp."""
    monkeypatch.setenv("IRIS_AUDIT_MAX_EVENTS", "3")
    p = str(tmp_path / "audit.jsonl")
    future = int(time.time()) + 10 * 86400
    audit.append_event(p, "mint", "dev-future", ts=future)  # oldest by position
    for i in range(3):
        audit.append_event(p, "mint", "dev-%d" % i)
    audit.prune(p)
    devs = [ev["device_id"] for ev in _read_lines(p)]
    assert devs == ["dev-0", "dev-1", "dev-2"]


# ---------------------------------------------------------------------------
# Amortized pruning
# ---------------------------------------------------------------------------

def test_prune_amortized_not_on_every_append(tmp_path, monkeypatch):
    """append_event only prunes every PRUNE_EVERY-th append; an expired entry
    lingers until the amortized prune fires, then disappears."""
    monkeypatch.setattr(audit, "PRUNE_EVERY", 5)
    p = str(tmp_path / "audit.jsonl")
    audit.append_event(p, "mint", "dev-old", ts=1000)  # long expired
    for i in range(3):  # appends 2..4: below the threshold, no prune
        audit.append_event(p, "mint", "dev-%d" % i)
        assert any(ev["device_id"] == "dev-old" for ev in _read_lines(p))
    audit.append_event(p, "mint", "dev-final")  # 5th append: prune fires
    devs = [ev["device_id"] for ev in _read_lines(p)]
    assert "dev-old" not in devs
    assert "dev-final" in devs


def test_prune_skips_rewrite_when_nothing_to_drop(tmp_path):
    """prune() with nothing expired and under the cap must not rewrite the
    file (same inode: no needless atomic-replace churn)."""
    p = str(tmp_path / "audit.jsonl")
    audit.append_event(p, "mint", "dev-1")
    ino = os.stat(p).st_ino
    audit.prune(p)
    assert os.stat(p).st_ino == ino


def test_prune_atomic_and_preserves_mode(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    audit.append_event(p, "mint", "dev-old", ts=1000)
    audit.append_event(p, "mint", "dev-new")
    os.chmod(p, 0o640)
    audit.prune(p)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o640
    devs = [ev["device_id"] for ev in _read_lines(p)]
    assert devs == ["dev-new"]
    # no temp-file droppings from the atomic rewrite
    assert not glob.glob(str(tmp_path / "*.tmp"))
    assert not glob.glob(str(tmp_path / ".*.tmp"))


# ---------------------------------------------------------------------------
# read_events
# ---------------------------------------------------------------------------

def test_read_events_newest_first_with_limit(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    for i in range(10):
        audit.append_event(p, "mint", "dev-%d" % i, ts=1000 + i)
    evs = audit.read_events(p, limit=3)
    assert [e["device_id"] for e in evs] == ["dev-9", "dev-8", "dev-7"]


def test_read_events_default_limit_200(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    for i in range(210):
        with open(p, "a") as f:  # raw write: fast, avoids amortized prune
            f.write(json.dumps({"ts": 1000 + i, "event": "mint",
                                "device_id": "dev-%d" % i}) + "\n")
    evs = audit.read_events(p)
    assert len(evs) == 200
    assert evs[0]["device_id"] == "dev-209"


def test_read_events_before_ts_pagination(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    for i in range(10):
        audit.append_event(p, "mint", "dev-%d" % i, ts=1000 + i)
    evs = audit.read_events(p, before_ts=1005)
    assert [e["ts"] for e in evs] == [1004, 1003, 1002, 1001, 1000]


def test_read_events_category_filter(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    audit.append_event(p, "refresh", "dev-1")               # auto: token
    audit.append_event(p, "auth_fail", "dev-1", result="fail")  # auto: auth
    audit.append_event(p, "settings_update", category="settings",
                       actor="console:admin")
    evs = audit.read_events(p, category="token")
    assert len(evs) == 1
    assert evs[0]["event"] == "refresh"


def test_read_events_garbage_tolerant(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    audit.append_event(p, "mint", "dev-1", ts=1000)
    with open(p, "a") as f:
        f.write("{not json at all\n")
        f.write("42\n")            # valid JSON but not an object
        f.write("\n")              # blank
    audit.append_event(p, "mint", "dev-2", ts=1002)
    with open(p, "a") as f:
        f.write('{"ts": 1003, ')   # torn tail (writer mid-append at EOF)
    evs = audit.read_events(p)
    assert [e["device_id"] for e in evs] == ["dev-2", "dev-1"]


def test_append_after_torn_tail_keeps_new_event_intact(tmp_path):
    """A crashed writer's partial line (no trailing newline) must not merge
    with — and corrupt — the next appended event."""
    p = str(tmp_path / "audit.jsonl")
    audit.append_event(p, "mint", "dev-1", ts=1000)
    with open(p, "a") as f:
        f.write('{"ts": 1001, ')   # crashed mid-write, no newline
    audit.append_event(p, "mint", "dev-2", ts=1002)
    evs = audit.read_events(p)
    assert [e["device_id"] for e in evs] == ["dev-2", "dev-1"]


def test_read_events_missing_file_returns_empty(tmp_path):
    assert audit.read_events(str(tmp_path / "nope.jsonl")) == []


def test_read_events_never_raises_on_unreadable(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    audit.append_event(p, "mint", "dev-1")
    os.chmod(p, 0o000)
    try:
        assert audit.read_events(p) == []
    finally:
        os.chmod(p, 0o600)


def test_read_events_limit_zero(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    audit.append_event(p, "mint", "dev-1")
    assert audit.read_events(p, limit=0) == []


def test_read_events_after_ts_window(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    for i in range(10):
        audit.append_event(p, "mint", "dev-%d" % i, ts=1000 + i)
    evs = audit.read_events(p, after_ts=1004)
    assert [e["ts"] for e in evs] == [1009, 1008, 1007, 1006, 1005, 1004]


def test_read_events_after_ts_and_before_ts_window(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    for i in range(10):
        audit.append_event(p, "mint", "dev-%d" % i, ts=1000 + i)
    evs = audit.read_events(p, after_ts=1002, before_ts=1007)
    assert [e["ts"] for e in evs] == [1006, 1005, 1004, 1003, 1002]


def test_read_events_after_ts_ignores_non_numeric_ts(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    audit.append_event(p, "mint", "dev-1", ts=1000)
    with open(p, "a") as f:
        f.write(json.dumps({"event": "mint", "device_id": "dev-bad",
                            "ts": "not-a-number"}) + "\n")
    evs = audit.read_events(p, after_ts=999)
    assert [e["device_id"] for e in evs] == ["dev-1"]


# ---------------------------------------------------------------------------
# histogram()
# ---------------------------------------------------------------------------

def test_histogram_bins_events_evenly(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    # window [0, 100), 5 buckets -> width 20: bucket starts 0,20,40,60,80
    audit.append_event(p, "mint", "dev-1", ts=5)     # bucket 0
    audit.append_event(p, "mint", "dev-2", ts=25)     # bucket 1
    audit.append_event(p, "mint", "dev-3", ts=25)     # bucket 1
    audit.append_event(p, "mint", "dev-4", ts=99)     # bucket 4
    buckets = audit.histogram(p, since_ts=0, until_ts=100, buckets=5)
    assert [b["start"] for b in buckets] == [0, 20, 40, 60, 80]
    assert [b["count"] for b in buckets] == [1, 2, 0, 0, 1]


def test_histogram_includes_zero_count_buckets(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    buckets = audit.histogram(p, since_ts=0, until_ts=10, buckets=2)
    assert [b["count"] for b in buckets] == [0, 0]


def test_histogram_respects_category_filter(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    audit.append_event(p, "settings_update", category="settings", ts=5)
    audit.append_event(p, "refresh", ts=5)  # auto-mapped to "token"
    buckets = audit.histogram(p, since_ts=0, until_ts=10, buckets=1,
                              category="settings")
    assert buckets[0]["count"] == 1


def test_histogram_excludes_events_outside_window(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    audit.append_event(p, "mint", "dev-1", ts=-5)
    audit.append_event(p, "mint", "dev-2", ts=500)
    audit.append_event(p, "mint", "dev-3", ts=50)
    buckets = audit.histogram(p, since_ts=0, until_ts=100, buckets=1)
    assert buckets[0]["count"] == 1


def test_histogram_garbage_tolerant(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    audit.append_event(p, "mint", "dev-1", ts=5)
    with open(p, "a") as f:
        f.write("{not json\n")
        f.write(json.dumps({"event": "mint", "ts": "nan"}) + "\n")
    buckets = audit.histogram(p, since_ts=0, until_ts=10, buckets=1)
    assert buckets[0]["count"] == 1


def test_histogram_never_raises_on_missing_file(tmp_path):
    p = str(tmp_path / "nope.jsonl")
    buckets = audit.histogram(p, since_ts=0, until_ts=10, buckets=3)
    assert [b["count"] for b in buckets] == [0, 0, 0]


def test_histogram_caps_buckets_at_200(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    buckets = audit.histogram(p, since_ts=0, until_ts=1000, buckets=500)
    assert len(buckets) == 200


def test_histogram_at_least_one_bucket(tmp_path):
    p = str(tmp_path / "audit.jsonl")
    buckets = audit.histogram(p, since_ts=0, until_ts=1000, buckets=0)
    assert len(buckets) == 1


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------

def test_concurrent_appends_lose_nothing(tmp_path):
    """N threads appending concurrently must leave one intact JSON line per
    append — no interleaved/torn lines, no lost events (store_lock + O_APPEND
    discipline shared with the catalog/gui processes)."""
    p = str(tmp_path / "audit.jsonl")
    n = 40
    barrier = threading.Barrier(n)
    errors = []

    def worker(i):
        try:
            barrier.wait()
            audit.append_event(p, "mint", "dev-%d" % i)
        except Exception as exc:  # pragma: no cover - surfaced via assert
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    lines = _read_lines(p)  # raises if any line is torn/invalid JSON
    assert len(lines) == n
    assert {ev["device_id"] for ev in lines} == {"dev-%d" % i
                                                 for i in range(n)}
