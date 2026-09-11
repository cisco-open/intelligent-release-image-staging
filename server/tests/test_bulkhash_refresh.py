# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for server/bulkhash_refresh.py (KGV reconciler Task 3): the
schedule settings store, the pure next_run_at() schedule math, run_refresh
(the single scheduled/manual/offline entry point, lock-guarded, fail-closed,
never-partial), and the bulkhash_refresh_loop scheduler daemon thread.

Task 1 (server/bulkhash.py, merged) owns fetch/verify_tar/parse/reconcile;
Task 2 (server/catalog.py, merged) owns CatalogStore.apply_hash_verification.
Neither is mocked away here where a real, hermetic exercise is practical:
run_refresh's success/failure-path tests drive the REAL bulkhash functions
against a local plain-HTTP server and a throwaway-signed fixture tar (the
test_bulkhash.py idiom, replicated here since test files in this repo do not
import helpers from one another), and a REAL CatalogStore/tmp_path so
"catalog untouched on failure" is a real assertion, not a mock call count."""
import calendar
import hashlib
import http.server
import io
import json
import os
import re
import subprocess
import tarfile
import threading
import time

import pytest

import bulkhash
import bulkhash_refresh
import catalog


# ---------------------------------------------------------------------------
# Throwaway signing cert + fixture-tar builders (never the real Cisco cert)
# -- mirrors server/tests/test_bulkhash.py's own helpers.
# ---------------------------------------------------------------------------

CSV_HEADER = "FILE_NAME,MD5_CHECKSUM,SHA512_CHECKSUM,PUBLISH_DATE,DEFERRAL_STATUS,IMAGE_SIZE"

REAL_ROW = (
    "image1.bin,D949B99A104B23B2129718220C78F28E,"
    + ("aa" * 64).upper() +
    ",August 03 2016 00:00:00 PDT-0700,,5\r\n")


# ---------------------------------------------------------------------------
# The pinned cert itself -- server/certs/cisco_bulkhash_verify.pem, NEVER a
# throwaway one -- must match its own provenance header.
# ---------------------------------------------------------------------------

_CERT_HEADER_FINGERPRINT_RE = re.compile(
    r"SHA-256 fingerprint \(of the DER bytes\): ([0-9a-f]{64})")


def test_pinned_cert_matches_its_own_provenance_fingerprint():
    """server/certs/cisco_bulkhash_verify.pem's provenance header (the
    comment block above the certificate) documents the SHA-256 fingerprint
    of the DER bytes of the certificate it pins for verify_tar. Parse that
    documented value out of the header, hash the certificate body actually
    on disk, and compare -- a silent swap of the certificate bytes (without
    also editing the header to match) must fail this test, not just be a
    comment someone forgot to update."""
    with open(bulkhash_refresh._CERT_PATH) as f:
        header_text = f.read()
    match = _CERT_HEADER_FINGERPRINT_RE.search(header_text)
    assert match, "provenance header fingerprint line not found"
    documented_fingerprint = match.group(1)

    der = subprocess.run(
        ["openssl", "x509", "-in", bulkhash_refresh._CERT_PATH,
         "-outform", "der"],
        capture_output=True, check=True).stdout
    actual_fingerprint = hashlib.sha256(der).hexdigest()
    assert actual_fingerprint == documented_fingerprint


def _throwaway_keypair(dirpath, cn):
    key = os.path.join(str(dirpath), cn + "-key.pem")
    crt = os.path.join(str(dirpath), cn + "-crt.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "2", "-keyout", key, "-out", crt, "-subj", "/CN=" + cn],
        check=True, capture_output=True)
    return crt, key


def _sign(key_path, data):
    proc = subprocess.run(
        ["openssl", "dgst", "-sha512", "-sign", key_path],
        input=data, capture_output=True, check=True)
    return proc.stdout


def _build_tar(tar_path, members):
    with tarfile.open(tar_path, mode="w:gz") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def _csv_bytes(rows_text):
    return (CSV_HEADER + "\r\n" + rows_text).encode("utf-8")


def _signed_fixture(tmp_path, csv_text, key_path, name="signed",
                    csv_name="Cisco_BulkHash_CSV.csv",
                    dirprefix="Cisco_BulkHash_CSV.csv_2026.08.29.08.29.48"):
    tar_path = os.path.join(str(tmp_path), name + ".tar")
    csv_bytes = _csv_bytes(csv_text)
    sig_bytes = _sign(key_path, csv_bytes)
    _build_tar(tar_path, [
        (dirprefix + "/", b""),
        ("%s/%s" % (dirprefix, csv_name), csv_bytes),
        ("%s/%s.signature" % (dirprefix, csv_name), sig_bytes),
    ])
    return tar_path


def _unsigned_fixture(tmp_path, csv_text, name="unsigned",
                      csv_name="Cisco_BulkHash_CSV.csv",
                      dirprefix="Cisco_BulkHash_CSV.csv_2026.08.29.08.29.48"):
    """A tar with NO .signature member at all -- verify_tar must reject it
    before parse ever sees it."""
    tar_path = os.path.join(str(tmp_path), name + ".tar")
    csv_bytes = _csv_bytes(csv_text)
    _build_tar(tar_path, [
        (dirprefix + "/", b""),
        ("%s/%s" % (dirprefix, csv_name), csv_bytes),
    ])
    return tar_path


@pytest.fixture
def signing_key(tmp_path):
    return _throwaway_keypair(tmp_path, "bulkhash-refresh-test-signer")


def _http_server(payload):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _url_for(srv, path="/feed.tar"):
    return "http://127.0.0.1:%d%s" % (srv.server_address[1], path)


# ---------------------------------------------------------------------------
# CatalogStore helpers (mirrors test_catalog_hash_verification.py)
# ---------------------------------------------------------------------------

def _store(tmp_path):
    return catalog.CatalogStore(str(tmp_path))


def _entry(image_id, filename, size=5, sha512=("aa" * 64), **over):
    e = {"id": image_id, "filename": filename, "size": size,
        "sha256": "ab" * 32, "sha512": sha512,
        "cisco_signature_verified": False, "info_hash_hex": "cc" * 20,
        "published_at": 111}
    e.update(over)
    return e


# ---------------------------------------------------------------------------
# Settings store
# ---------------------------------------------------------------------------

def test_settings_path_joins_basename():
    assert bulkhash_refresh.settings_path("/var/lib/iris") == \
        "/var/lib/iris/bulkhash-schedule.json"


def test_read_missing_file_defaults_off(tmp_path):
    out = bulkhash_refresh.read_settings(str(tmp_path / "nope.json"))
    assert out == {"mode": "off", "hour_utc": 0,
                   "last_run": {"at": None, "source": None, "outcome": None,
                                "matched": None, "mismatched": None,
                                "not_in_feed": None}}


def test_read_corrupt_json_defaults_off(tmp_path):
    p = tmp_path / "bulkhash-schedule.json"
    p.write_text("{not json")
    out = bulkhash_refresh.read_settings(str(p))
    assert out["mode"] == "off"


def test_read_non_dict_document_defaults_off(tmp_path):
    p = tmp_path / "bulkhash-schedule.json"
    p.write_text("[1, 2, 3]")
    out = bulkhash_refresh.read_settings(str(p))
    assert out["mode"] == "off"


def test_read_unknown_mode_falls_back_to_off(tmp_path):
    p = tmp_path / "bulkhash-schedule.json"
    p.write_text(json.dumps({"mode": "hourly", "hour_utc": 5}))
    out = bulkhash_refresh.read_settings(str(p))
    assert out["mode"] == "off"


def test_read_out_of_range_hour_falls_back_to_zero(tmp_path):
    p = tmp_path / "bulkhash-schedule.json"
    p.write_text(json.dumps({"mode": "daily", "hour_utc": 99}))
    out = bulkhash_refresh.read_settings(str(p))
    assert out["hour_utc"] == 0


def test_read_wrong_typed_last_run_fields_collapse_to_none(tmp_path):
    p = tmp_path / "bulkhash-schedule.json"
    p.write_text(json.dumps({"mode": "daily", "hour_utc": 6,
                            "last_run": {"at": "not-a-number",
                                         "matched": "nope"}}))
    out = bulkhash_refresh.read_settings(str(p))
    assert out["last_run"]["at"] is None
    assert out["last_run"]["matched"] is None


def test_write_read_roundtrip(tmp_path):
    p = str(tmp_path / "bulkhash-schedule.json")
    last_run = {"at": 1000, "source": "manual", "outcome": "ok",
               "matched": 1, "mismatched": 2, "not_in_feed": 3}
    bulkhash_refresh.write_settings(p, "weekly", 14, last_run)
    out = bulkhash_refresh.read_settings(p)
    assert out == {"mode": "weekly", "hour_utc": 14, "last_run": last_run}


def test_write_is_atomic_no_temp_left_behind(tmp_path):
    p = str(tmp_path / "bulkhash-schedule.json")
    bulkhash_refresh.write_settings(
        p, "daily", 3, dict(bulkhash_refresh._DEFAULT_LAST_RUN))
    leftovers = [f for f in os.listdir(str(tmp_path))
                if f.startswith(".bulkhash-schedule-")]
    assert leftovers == []


# ---------------------------------------------------------------------------
# next_run_at: pure schedule math
# ---------------------------------------------------------------------------

def _epoch(y, mo, d, h, mi=0, s=0):
    return calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))


def test_next_run_at_off_is_none():
    now = _epoch(2026, 8, 29, 12, 0)
    assert bulkhash_refresh.next_run_at("off", 6, now) is None


def test_next_run_at_unknown_mode_is_none():
    now = _epoch(2026, 8, 29, 12, 0)
    assert bulkhash_refresh.next_run_at("bogus", 6, now) is None


def test_next_run_at_daily_later_today():
    now = _epoch(2026, 8, 29, 10, 0)     # Saturday 10:00 UTC
    got = bulkhash_refresh.next_run_at("daily", 18, now)
    assert got == _epoch(2026, 8, 29, 18, 0)


def test_next_run_at_daily_already_passed_rolls_to_tomorrow():
    now = _epoch(2026, 8, 29, 20, 0)
    got = bulkhash_refresh.next_run_at("daily", 6, now)
    assert got == _epoch(2026, 8, 30, 6, 0)


def test_next_run_at_daily_exact_slot_instant_rolls_to_tomorrow():
    """Equality (now == the slot) must not fire again this instant."""
    now = _epoch(2026, 8, 29, 6, 0)
    got = bulkhash_refresh.next_run_at("daily", 6, now)
    assert got == _epoch(2026, 8, 30, 6, 0)


def test_next_run_at_daily_crosses_midnight_utc_boundary():
    now = _epoch(2026, 8, 29, 23, 59, 30)
    got = bulkhash_refresh.next_run_at("daily", 0, now)
    assert got == _epoch(2026, 8, 30, 0, 0)


def test_next_run_at_daily_crosses_month_boundary():
    now = _epoch(2026, 8, 31, 20, 0)
    got = bulkhash_refresh.next_run_at("daily", 6, now)
    assert got == _epoch(2026, 9, 1, 6, 0)


def test_next_run_at_weekly_from_anchor_day_before_slot():
    # 2026-08-24 is a Monday (the fixed weekly anchor).
    now = _epoch(2026, 8, 24, 3, 0)
    got = bulkhash_refresh.next_run_at("weekly", 6, now)
    assert got == _epoch(2026, 8, 24, 6, 0)


def test_next_run_at_weekly_from_anchor_day_after_slot_rolls_a_full_week():
    now = _epoch(2026, 8, 24, 20, 0)     # Monday, past hour_utc=6 already
    got = bulkhash_refresh.next_run_at("weekly", 6, now)
    assert got == _epoch(2026, 8, 31, 6, 0)    # next Monday


def test_next_run_at_weekly_from_a_non_anchor_day():
    now = _epoch(2026, 8, 29, 12, 0)     # Saturday
    got = bulkhash_refresh.next_run_at("weekly", 6, now)
    assert got == _epoch(2026, 8, 31, 6, 0)    # following Monday


def test_next_run_at_weekly_crosses_month_boundary():
    now = _epoch(2026, 8, 31, 20, 0)     # Monday 2026-08-31, past hour_utc
    got = bulkhash_refresh.next_run_at("weekly", 6, now)
    assert got == _epoch(2026, 9, 7, 6, 0)


def test_next_run_at_non_int_hour_defaults_to_zero():
    now = _epoch(2026, 8, 29, 12, 0)
    got = bulkhash_refresh.next_run_at("daily", "garbage", now)
    assert got == _epoch(2026, 8, 30, 0, 0)


# ---------------------------------------------------------------------------
# _reconcile_input: unhashed/malformed catalog entries never reach reconcile
# ---------------------------------------------------------------------------

def test_reconcile_input_filters_missing_and_blank_sha512():
    images = [
        {"id": "a", "filename": "a.bin", "size": 5, "sha512": "aa" * 64},
        {"id": "b", "filename": "b.bin", "size": 5, "sha512": None},
        {"id": "c", "filename": "c.bin", "size": 5, "sha512": "  "},
        {"id": "d", "filename": "d.bin", "size": 5},
    ]
    out = bulkhash_refresh._reconcile_input(images)
    assert [t[0] for t in out] == ["a"]


def test_reconcile_input_filters_non_int_size():
    images = [
        {"id": "a", "filename": "a.bin", "size": "not-a-number",
         "sha512": "aa" * 64},
        {"id": "b", "filename": "b.bin", "size": None, "sha512": "aa" * 64},
        {"id": "c", "filename": "c.bin", "size": 5, "sha512": "aa" * 64},
    ]
    out = bulkhash_refresh._reconcile_input(images)
    assert [t[0] for t in out] == ["c"]


# ---------------------------------------------------------------------------
# run_refresh: success path, real fetch -> verify -> parse -> reconcile ->
# apply, against a local HTTP server and a throwaway-signed fixture tar.
# ---------------------------------------------------------------------------

def test_run_refresh_success_records_counts_and_applies_to_catalog(
        tmp_path, signing_key):
    cert, key = signing_key
    csv_text = REAL_ROW
    fixture = _signed_fixture(tmp_path, csv_text, key)
    with open(fixture, "rb") as f:
        payload = f.read()
    srv = _http_server(payload)
    try:
        store = _store(tmp_path / "state")
        store.save_image(_entry("image1", "image1.bin", size=5,
                                sha512="aa" * 64))       # verified
        store.save_image(_entry("image2", "unrelated.bin", size=99,
                                sha512="bb" * 64))        # not_in_feed

        result = bulkhash_refresh.run_refresh(
            "manual", str(tmp_path / "state"), store,
            feed_url=_url_for(srv), cert_path=cert, timeout=5)

        assert result == {"outcome": "ok", "matched": 1, "mismatched": 0,
                          "not_in_feed": 1}
        assert store.get_image("image1")["hash_verification"]["state"] == \
            "verified"
        assert store.get_image("image2")["hash_verification"]["state"] == \
            "not_in_feed"

        settings = bulkhash_refresh.read_settings(
            bulkhash_refresh.settings_path(str(tmp_path / "state")))
        assert settings["last_run"]["source"] == "manual"
        assert settings["last_run"]["outcome"] == "ok"
        assert settings["last_run"]["matched"] == 1
        assert settings["last_run"]["mismatched"] == 0
        assert settings["last_run"]["not_in_feed"] == 1
        assert settings["last_run"]["at"] is not None
    finally:
        srv.shutdown()


def test_run_refresh_calls_audit_fn_on_success(tmp_path, signing_key):
    cert, key = signing_key
    fixture = _signed_fixture(tmp_path, REAL_ROW, key)
    with open(fixture, "rb") as f:
        payload = f.read()
    srv = _http_server(payload)
    events = []
    try:
        store = _store(tmp_path / "state")
        bulkhash_refresh.run_refresh(
            "scheduled", str(tmp_path / "state"), store,
            feed_url=_url_for(srv), cert_path=cert, timeout=5,
            audit_fn=lambda **kw: events.append(kw))
        assert len(events) == 1
        assert events[0]["result"] == "ok"
        assert events[0]["event"] == "bulkhash-refresh"
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# run_refresh: fetch failure -- catalog untouched, failure recorded+logged
# ---------------------------------------------------------------------------

def test_run_refresh_fetch_failure_leaves_catalog_untouched_and_records_fail(
        tmp_path):
    store = _store(tmp_path / "state")
    store.save_image(_entry("image1", "image1.bin"))
    events = []

    result = bulkhash_refresh.run_refresh(
        "scheduled", str(tmp_path / "state"), store,
        feed_url="http://127.0.0.1:1/definitely-not-listening", timeout=2,
        audit_fn=lambda **kw: events.append(kw))

    assert result["outcome"] == "fail"
    assert result["matched"] is None
    assert "hash_verification" not in store.get_image("image1")

    settings = bulkhash_refresh.read_settings(
        bulkhash_refresh.settings_path(str(tmp_path / "state")))
    assert settings["last_run"]["source"] == "scheduled"
    assert settings["last_run"]["outcome"].startswith("fail:")
    assert settings["last_run"]["matched"] is None

    assert len(events) == 1
    assert events[0]["result"] == "fail"


# ---------------------------------------------------------------------------
# run_refresh: verify-before-parse ordering -- an unsigned tar must never
# reach parse (or reconcile/apply); catalog stays untouched.
# ---------------------------------------------------------------------------

def test_run_refresh_unsigned_tar_never_reaches_parse_or_catalog(
        tmp_path, signing_key):
    """No .signature member at all: verify_tar fails on the missing member
    before it ever even reads cert_path -- any throwaway cert here proves
    the point just as well as a real one."""
    cert, _key = signing_key
    fixture = _unsigned_fixture(tmp_path, REAL_ROW)
    with open(fixture, "rb") as f:
        payload = f.read()
    srv = _http_server(payload)
    parse_calls = []

    def spy_parse(tar_path):
        parse_calls.append(tar_path)
        return bulkhash.parse(tar_path)

    try:
        store = _store(tmp_path / "state")
        store.save_image(_entry("image1", "image1.bin"))

        result = bulkhash_refresh.run_refresh(
            "scheduled", str(tmp_path / "state"), store,
            feed_url=_url_for(srv), cert_path=cert,
            timeout=5, _parse_fn=spy_parse)
        assert result["outcome"] == "fail"
        assert parse_calls == []
        assert "hash_verification" not in store.get_image("image1")
    finally:
        srv.shutdown()


def test_run_refresh_verify_failure_with_wrong_signer_never_reaches_parse(
        tmp_path, signing_key, tmp_path_factory):
    """A tar signed by a DIFFERENT throwaway key than the one passed as
    cert_path: verify_tar's signature check fails (as opposed to the
    unsigned-tar case, where the .signature member is simply absent), and
    parse must still never run."""
    cert, _key = signing_key
    other_dir = tmp_path_factory.mktemp("other-signer")
    _other_cert, other_key = _throwaway_keypair(other_dir, "other-signer")
    fixture = _signed_fixture(tmp_path, REAL_ROW, other_key)
    with open(fixture, "rb") as f:
        payload = f.read()
    srv = _http_server(payload)
    parse_calls = []

    def spy_parse(tar_path):
        parse_calls.append(tar_path)
        return bulkhash.parse(tar_path)

    try:
        store = _store(tmp_path / "state")
        result = bulkhash_refresh.run_refresh(
            "scheduled", str(tmp_path / "state"), store,
            feed_url=_url_for(srv), cert_path=cert, timeout=5,
            _parse_fn=spy_parse)
        assert result["outcome"] == "fail"
        assert parse_calls == []
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# run_refresh: parse failure (verify_tar succeeds -- the signature over the
# bytes checks out -- but the CSV inside is structurally unparseable) --
# apply must never run, catalog stays untouched.
# ---------------------------------------------------------------------------

def test_run_refresh_parse_failure_leaves_catalog_untouched(
        tmp_path, signing_key):
    cert, key = signing_key
    bad_csv = "NOT,THE,RIGHT,HEADER\r\n"     # signed, but wrong header
    # Built directly (bypassing _signed_fixture's CSV_HEADER prefix) so the
    # signed bytes really do have a bad header.
    tar_path = os.path.join(str(tmp_path), "badheader.tar")
    csv_bytes = bad_csv.encode("utf-8")
    sig_bytes = _sign(key, csv_bytes)
    _build_tar(tar_path, [
        ("d/", b""),
        ("d/Cisco_BulkHash_CSV.csv", csv_bytes),
        ("d/Cisco_BulkHash_CSV.csv.signature", sig_bytes),
    ])
    with open(tar_path, "rb") as f:
        payload = f.read()
    srv = _http_server(payload)
    apply_calls = []
    try:
        store = _store(tmp_path / "state")
        store.save_image(_entry("image1", "image1.bin"))
        real_apply = store.apply_hash_verification

        def spy_apply(*a, **kw):
            apply_calls.append((a, kw))
            return real_apply(*a, **kw)

        store.apply_hash_verification = spy_apply

        result = bulkhash_refresh.run_refresh(
            "scheduled", str(tmp_path / "state"), store,
            feed_url=_url_for(srv), cert_path=cert, timeout=5)

        assert result["outcome"] == "fail"
        assert apply_calls == []
        assert "hash_verification" not in store.get_image("image1")
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# run_refresh: reconcile failure -- apply must never run, catalog untouched.
# ---------------------------------------------------------------------------

def test_run_refresh_reconcile_failure_leaves_catalog_untouched(
        tmp_path, signing_key):
    cert, key = signing_key
    fixture = _signed_fixture(tmp_path, REAL_ROW, key)
    with open(fixture, "rb") as f:
        payload = f.read()
    srv = _http_server(payload)
    events = []

    def blowing_up_reconcile(rows, images):
        raise bulkhash.BulkHashError("simulated reconcile failure")

    try:
        store = _store(tmp_path / "state")
        store.save_image(_entry("image1", "image1.bin"))

        result = bulkhash_refresh.run_refresh(
            "scheduled", str(tmp_path / "state"), store,
            feed_url=_url_for(srv), cert_path=cert, timeout=5,
            _reconcile_fn=blowing_up_reconcile,
            audit_fn=lambda **kw: events.append(kw))

        assert result["outcome"] == "fail"
        assert "hash_verification" not in store.get_image("image1")
        settings = bulkhash_refresh.read_settings(
            bulkhash_refresh.settings_path(str(tmp_path / "state")))
        assert settings["last_run"]["outcome"].startswith("fail:")
        assert len(events) == 1
        assert events[0]["result"] == "fail"
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# run_refresh: apply_hash_verification failure (an invalid `source`, its
# own ValueError guard) -- caught by the SAME broad except as every other
# pipeline stage; must not raise out of run_refresh, must still be
# recorded and logged, and the catalog stays untouched (apply_hash_
# verification raises before writing anything for a bad source).
# ---------------------------------------------------------------------------

def test_run_refresh_apply_failure_records_fail_without_raising(
        tmp_path, signing_key):
    cert, key = signing_key
    fixture = _signed_fixture(tmp_path, REAL_ROW, key)
    with open(fixture, "rb") as f:
        payload = f.read()
    srv = _http_server(payload)
    events = []
    try:
        store = _store(tmp_path / "state")
        store.save_image(_entry("image1", "image1.bin", size=5,
                                sha512="aa" * 64))

        result = bulkhash_refresh.run_refresh(
            "not-a-real-source", str(tmp_path / "state"), store,
            feed_url=_url_for(srv), cert_path=cert, timeout=5,
            audit_fn=lambda **kw: events.append(kw))

        assert result["outcome"] == "fail"
        assert "hash_verification" not in store.get_image("image1")
        assert len(events) == 1
        assert events[0]["result"] == "fail"
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# run_refresh: persisting last_run must never itself make run_refresh
# raise, on EITHER the failure or the success path (Important 1 fix) --
# and the true outcome (the original pipeline failure's detail, or the
# real counts on success) must still come back and still reach audit_fn
# even though the on-disk write is broken.
# ---------------------------------------------------------------------------

def test_run_refresh_failure_survives_a_broken_settings_write(
        tmp_path, monkeypatch):
    """A fetch failure whose OWN last_run write then also fails (e.g.
    ENOSPC/read-only state dir): the ORIGINAL fetch failure's detail must
    still be what's returned and audited -- not swallowed/replaced by the
    write's own OSError, and above all run_refresh must not raise it."""
    def broken_write(*a, **kw):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(bulkhash_refresh, "write_settings", broken_write)
    events = []
    store = _store(tmp_path / "state")

    result = bulkhash_refresh.run_refresh(
        "scheduled", str(tmp_path / "state"), store,
        feed_url="http://127.0.0.1:1/definitely-not-listening", timeout=2,
        audit_fn=lambda **kw: events.append(kw))

    assert result["outcome"] == "fail"
    assert "simulated disk failure" not in result["detail"]
    assert len(events) == 1
    assert events[0]["result"] == "fail"
    assert "simulated disk failure" not in events[0]["detail"]


def test_run_refresh_success_survives_a_broken_settings_write(
        tmp_path, signing_key, monkeypatch):
    """Same guard on the success path: apply_hash_verification has ALREADY
    mutated the catalog by the time last_run is recorded, so a broken
    settings write here must not turn a genuinely successful run into a
    raised exception -- the caller (a future console route) still gets a
    clean "ok" result even though last_run itself didn't stick this time."""
    cert, key = signing_key
    fixture = _signed_fixture(tmp_path, REAL_ROW, key)
    with open(fixture, "rb") as f:
        payload = f.read()
    srv = _http_server(payload)

    def broken_write(*a, **kw):
        raise OSError("simulated disk failure")

    monkeypatch.setattr(bulkhash_refresh, "write_settings", broken_write)
    events = []
    try:
        store = _store(tmp_path / "state")
        store.save_image(_entry("image1", "image1.bin", size=5,
                                sha512="aa" * 64))

        result = bulkhash_refresh.run_refresh(
            "scheduled", str(tmp_path / "state"), store,
            feed_url=_url_for(srv), cert_path=cert, timeout=5,
            audit_fn=lambda **kw: events.append(kw))

        assert result == {"outcome": "ok", "matched": 1, "mismatched": 0,
                          "not_in_feed": 0}
        # the catalog write itself (apply_hash_verification) is unrelated
        # to the settings-file write and must have gone through normally
        assert store.get_image("image1")["hash_verification"]["state"] == \
            "verified"
        assert len(events) == 1
        assert events[0]["result"] == "ok"
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# run_refresh: offline source with a pre-downloaded tar_path -- _fetch_fn
# is never called at all.
# ---------------------------------------------------------------------------

def test_run_refresh_offline_tar_path_skips_fetch(tmp_path, signing_key):
    cert, key = signing_key
    fixture = _signed_fixture(tmp_path, REAL_ROW, key)
    fetch_calls = []

    def spy_fetch(*a, **kw):
        fetch_calls.append((a, kw))
        raise AssertionError("fetch_fn must not be called for an offline run")

    store = _store(tmp_path / "state")
    store.save_image(_entry("image1", "image1.bin", size=5, sha512="aa" * 64))

    result = bulkhash_refresh.run_refresh(
        "offline", str(tmp_path / "state"), store, tar_path=fixture,
        cert_path=cert, _fetch_fn=spy_fetch)

    assert fetch_calls == []
    assert result == {"outcome": "ok", "matched": 1, "mismatched": 0,
                      "not_in_feed": 0}


# ---------------------------------------------------------------------------
# run_refresh: unhashed catalog image is filtered, never blocks other
# verdicts, and the run still succeeds.
# ---------------------------------------------------------------------------

def test_run_refresh_filters_unhashed_image_without_failing_the_run(
        tmp_path, signing_key):
    cert, key = signing_key
    fixture = _signed_fixture(tmp_path, REAL_ROW, key)
    with open(fixture, "rb") as f:
        payload = f.read()
    srv = _http_server(payload)
    try:
        store = _store(tmp_path / "state")
        store.save_image(_entry("image1", "image1.bin", size=5,
                                sha512="aa" * 64))
        legacy = _entry("image2", "legacy.bin", size=5, sha512="aa" * 64)
        del legacy["sha512"]           # unhashed legacy row
        store.save_image(legacy)

        result = bulkhash_refresh.run_refresh(
            "scheduled", str(tmp_path / "state"), store,
            feed_url=_url_for(srv), cert_path=cert, timeout=5)

        assert result["outcome"] == "ok"
        assert result["matched"] == 1
        assert store.get_image("image1")["hash_verification"]["state"] == \
            "verified"
        assert "hash_verification" not in store.get_image("image2")
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# run_refresh: lock exclusion -- a manual run during a scheduled (or any)
# run in flight returns "already_running", touching nothing.
# ---------------------------------------------------------------------------

def test_run_refresh_concurrent_call_returns_already_running(tmp_path):
    store = _store(tmp_path / "state")
    enter = threading.Event()
    release = threading.Event()

    def blocking_fetch(url, timeout, out_path):
        enter.set()
        release.wait(timeout=5)
        raise bulkhash.BulkHashError("stopped for the test")

    results = []

    def run_first():
        r = bulkhash_refresh.run_refresh(
            "scheduled", str(tmp_path / "state"), store,
            _fetch_fn=blocking_fetch)
        results.append(r)

    t = threading.Thread(target=run_first)
    t.start()
    assert enter.wait(timeout=5)      # first run is in flight, holding the lock

    second = bulkhash_refresh.run_refresh(
        "manual", str(tmp_path / "state"), store)
    assert second == {"outcome": "already_running"}

    release.set()
    t.join(timeout=5)
    assert results and results[0]["outcome"] == "fail"

    # the manual call touched neither last_run nor the catalog
    settings = bulkhash_refresh.read_settings(
        bulkhash_refresh.settings_path(str(tmp_path / "state")))
    assert settings["last_run"]["source"] == "scheduled"


def test_run_refresh_waits_for_turn_then_takes_fresh_snapshot(tmp_path):
    store = _store(tmp_path / "state")
    first_entered = threading.Event()
    release_first = threading.Event()
    second_entered = threading.Event()

    def first_fetch(url, timeout, out_path):
        first_entered.set()
        assert release_first.wait(timeout=5)
        raise bulkhash.BulkHashError("first finished")

    def second_fetch(url, timeout, out_path):
        second_entered.set()
        raise bulkhash.BulkHashError("second took its turn")

    first_result = []
    second_result = []
    first = threading.Thread(target=lambda: first_result.append(
        bulkhash_refresh.run_refresh(
            "scheduled", str(tmp_path / "state"), store,
            _fetch_fn=first_fetch)))
    first.start()
    assert first_entered.wait(timeout=5)

    second = threading.Thread(target=lambda: second_result.append(
        bulkhash_refresh.run_refresh(
            "manual", str(tmp_path / "state"), store,
            _fetch_fn=second_fetch, wait=True)))
    second.start()
    assert not second_entered.wait(timeout=0.1)

    release_first.set()
    first.join(timeout=5)
    second.join(timeout=5)
    assert not first.is_alive() and not second.is_alive()
    assert first_result[0]["outcome"] == "fail"
    assert second_result[0] == {
        "outcome": "fail", "detail": "second took its turn",
        "matched": None, "mismatched": None, "not_in_feed": None}
    assert second_entered.is_set()
    settings = bulkhash_refresh.read_settings(
        bulkhash_refresh.settings_path(str(tmp_path / "state")))
    assert settings["last_run"]["source"] == "manual"


def _wait_for_wait_generation(after):
    """Wait until another wait=True caller has registered with the runner."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with bulkhash_refresh._RUN_CONDITION:
            if bulkhash_refresh._WAIT_GENERATION > after:
                return
        time.sleep(0.001)
    raise AssertionError("wait=True caller did not register")


def _not_in_feed(images):
    return {
        image_id: {
            "state": bulkhash.STATE_NOT_IN_FEED,
            "feed_sha512": None,
            "publish_date": None,
            "deferral": False,
        }
        for image_id, _filename, _size, _sha512 in images
    }


def test_waiting_imports_covered_by_one_snapshot_coalesce(tmp_path):
    """Two published rows present before one snapshot need one feed run."""
    store = _store(tmp_path / "state")
    store.save_image(_entry("image1", "image1.bin"))
    fetch_entered = threading.Event()
    release_fetch = threading.Event()
    fetch_calls = []
    snapshots = []

    def fetch(_url, _timeout, _out_path):
        fetch_calls.append(True)
        fetch_entered.set()
        assert release_fetch.wait(timeout=5)

    def reconcile(_rows, images):
        snapshots.append(tuple(row[0] for row in images))
        return _not_in_feed(images)

    common = {
        "_fetch_fn": fetch,
        "_verify_fn": lambda _path, _cert: None,
        "_parse_fn": lambda _path: {},
        "_reconcile_fn": reconcile,
        "wait": True,
    }
    results = {}
    first = threading.Thread(target=lambda: results.__setitem__(
        "first", bulkhash_refresh.run_refresh(
            "manual", str(tmp_path / "state"), store, **common)))
    first.start()
    assert fetch_entered.wait(timeout=5)

    # This mirrors the second publish job: the row is durable before its
    # wait=True verification call registers, while the first feed fetch is
    # still ahead of the catalog snapshot.
    store.save_image(_entry("image2", "image2.bin"))
    with bulkhash_refresh._RUN_CONDITION:
        before = bulkhash_refresh._WAIT_GENERATION
    second = threading.Thread(target=lambda: results.__setitem__(
        "second", bulkhash_refresh.run_refresh(
            "manual", str(tmp_path / "state"), store, **common)))
    second.start()
    _wait_for_wait_generation(before)

    release_fetch.set()
    first.join(timeout=5)
    second.join(timeout=5)
    assert not first.is_alive() and not second.is_alive()
    assert len(fetch_calls) == 1
    assert snapshots == [("image1", "image2")]
    expected = {"outcome": "ok", "matched": 0, "mismatched": 0,
                "not_in_feed": 2}
    assert results == {"first": expected, "second": expected}
    assert store.get_image("image1")["hash_verification"]["state"] == \
        "not_in_feed"
    assert store.get_image("image2")["hash_verification"]["state"] == \
        "not_in_feed"


def test_image_registered_after_snapshot_forces_new_refresh(tmp_path):
    """An older success must not claim a row absent from its snapshot."""
    store = _store(tmp_path / "state")
    store.save_image(_entry("image1", "image1.bin"))
    first_snapshot = threading.Event()
    release_first = threading.Event()
    fetch_calls = []
    snapshots = []

    def fetch(_url, _timeout, _out_path):
        fetch_calls.append(True)

    def reconcile(_rows, images):
        snapshot = tuple(row[0] for row in images)
        snapshots.append(snapshot)
        if len(snapshots) == 1:
            first_snapshot.set()
            assert release_first.wait(timeout=5)
        return _not_in_feed(images)

    common = {
        "_fetch_fn": fetch,
        "_verify_fn": lambda _path, _cert: None,
        "_parse_fn": lambda _path: {},
        "_reconcile_fn": reconcile,
        "wait": True,
    }
    results = {}
    first = threading.Thread(target=lambda: results.__setitem__(
        "first", bulkhash_refresh.run_refresh(
            "manual", str(tmp_path / "state"), store, **common)))
    first.start()
    assert first_snapshot.wait(timeout=5)

    store.save_image(_entry("image2", "image2.bin"))
    with bulkhash_refresh._RUN_CONDITION:
        before = bulkhash_refresh._WAIT_GENERATION
    second = threading.Thread(target=lambda: results.__setitem__(
        "second", bulkhash_refresh.run_refresh(
            "manual", str(tmp_path / "state"), store, **common)))
    second.start()
    _wait_for_wait_generation(before)

    release_first.set()
    first.join(timeout=5)
    second.join(timeout=5)
    assert not first.is_alive() and not second.is_alive()
    assert len(fetch_calls) == 2
    assert snapshots == [("image1",), ("image1", "image2")]
    assert results["first"]["not_in_feed"] == 1
    assert results["second"]["not_in_feed"] == 2
    assert store.get_image("image2")["hash_verification"]["state"] == \
        "not_in_feed"


def test_failed_snapshot_is_not_reused_by_waiting_import(tmp_path):
    """Even a failure whose snapshot covered a waiter must be retried."""
    store = _store(tmp_path / "state")
    store.save_image(_entry("image1", "image1.bin"))
    fetch_entered = threading.Event()
    release_fetch = threading.Event()
    fetch_calls = []
    snapshots = []

    def fetch(_url, _timeout, _out_path):
        fetch_calls.append(True)
        if len(fetch_calls) == 1:
            fetch_entered.set()
            assert release_fetch.wait(timeout=5)

    def reconcile(_rows, images):
        snapshots.append(tuple(row[0] for row in images))
        if len(snapshots) == 1:
            raise bulkhash.BulkHashError("first covered snapshot failed")
        return _not_in_feed(images)

    common = {
        "_fetch_fn": fetch,
        "_verify_fn": lambda _path, _cert: None,
        "_parse_fn": lambda _path: {},
        "_reconcile_fn": reconcile,
        "wait": True,
    }
    results = {}
    first = threading.Thread(target=lambda: results.__setitem__(
        "first", bulkhash_refresh.run_refresh(
            "manual", str(tmp_path / "state"), store, **common)))
    first.start()
    assert fetch_entered.wait(timeout=5)

    store.save_image(_entry("image2", "image2.bin"))
    with bulkhash_refresh._RUN_CONDITION:
        before = bulkhash_refresh._WAIT_GENERATION
    second = threading.Thread(target=lambda: results.__setitem__(
        "second", bulkhash_refresh.run_refresh(
            "manual", str(tmp_path / "state"), store, **common)))
    second.start()
    _wait_for_wait_generation(before)

    release_fetch.set()
    first.join(timeout=5)
    second.join(timeout=5)
    assert not first.is_alive() and not second.is_alive()
    assert len(fetch_calls) == 2
    assert snapshots == [
        ("image1", "image2"), ("image1", "image2")]
    assert results["first"]["outcome"] == "fail"
    assert results["first"]["detail"] == "first covered snapshot failed"
    assert results["second"] == {
        "outcome": "ok", "matched": 0, "mismatched": 0,
        "not_in_feed": 2}


def test_run_refresh_lock_is_released_after_completion(tmp_path):
    store = _store(tmp_path / "state")
    r1 = bulkhash_refresh.run_refresh(
        "manual", str(tmp_path / "state"), store,
        feed_url="http://127.0.0.1:1/nope", timeout=1)
    assert r1["outcome"] == "fail"
    r2 = bulkhash_refresh.run_refresh(
        "manual", str(tmp_path / "state"), store,
        feed_url="http://127.0.0.1:1/nope", timeout=1)
    assert r2["outcome"] == "fail"      # not "already_running"


# ---------------------------------------------------------------------------
# bulkhash_refresh_loop
# ---------------------------------------------------------------------------

def _run_loop(tmp_path, stop, run_refresh_fn, idle_recheck=0.03,
             next_run_at_fn=None):
    store = _store(tmp_path / "state")
    kwargs = {}
    if next_run_at_fn is not None:
        kwargs["next_run_at_fn"] = next_run_at_fn
    t = threading.Thread(
        target=bulkhash_refresh.bulkhash_refresh_loop,
        args=(stop, str(tmp_path / "state"), store),
        kwargs=dict(idle_recheck=idle_recheck, run_refresh_fn=run_refresh_fn,
                   **kwargs),
        daemon=True)
    t.start()
    return t


def test_loop_mode_off_never_runs(tmp_path):
    calls = []
    bulkhash_refresh.write_settings(
        bulkhash_refresh.settings_path(str(tmp_path / "state")), "off", 0,
        dict(bulkhash_refresh._DEFAULT_LAST_RUN))
    stop = threading.Event()
    t = _run_loop(tmp_path, stop, lambda *a, **kw: calls.append((a, kw)),
                 idle_recheck=0.02)
    time.sleep(0.15)      # several idle-recheck cycles
    stop.set()
    t.join(timeout=5)
    assert not t.is_alive()
    assert calls == []


def test_loop_fires_when_next_run_at_reports_due(tmp_path):
    """A fake next_run_at_fn ("always due 0.03s from now") decouples this
    test from the real calendar math (already covered directly, without
    threads, above) -- it only exercises the loop's own wait-then-fire
    wiring."""
    calls = []
    bulkhash_refresh.write_settings(
        bulkhash_refresh.settings_path(str(tmp_path / "state")), "daily", 6,
        dict(bulkhash_refresh._DEFAULT_LAST_RUN))
    stop = threading.Event()

    def fake_next_run_at(mode, hour_utc, now):
        return None if mode == "off" else now + 0.03

    t = _run_loop(tmp_path, stop, lambda *a, **kw: calls.append((a, kw)),
                 idle_recheck=0.5, next_run_at_fn=fake_next_run_at)
    for _ in range(50):
        if calls:
            break
        time.sleep(0.05)
    stop.set()
    t.join(timeout=5)
    assert len(calls) >= 1
    args, kwargs = calls[0]
    assert args[0] == "scheduled"


def test_loop_mode_change_takes_effect_without_restart(tmp_path):
    """Starts "off", flips to "daily" on disk mid-run -- the SAME running
    thread must pick it up (no restart) within idle_recheck."""
    calls = []
    spath = bulkhash_refresh.settings_path(str(tmp_path / "state"))
    bulkhash_refresh.write_settings(
        spath, "off", 0, dict(bulkhash_refresh._DEFAULT_LAST_RUN))
    stop = threading.Event()

    def fake_next_run_at(mode, hour_utc, now):
        return None if mode == "off" else now + 0.03

    t = _run_loop(tmp_path, stop, lambda *a, **kw: calls.append((a, kw)),
                 idle_recheck=0.03, next_run_at_fn=fake_next_run_at)
    time.sleep(0.1)
    assert calls == []          # still off, nothing fired yet
    bulkhash_refresh.write_settings(
        spath, "daily", 6, dict(bulkhash_refresh._DEFAULT_LAST_RUN))
    for _ in range(50):
        if calls:
            break
        time.sleep(0.05)
    stop.set()
    t.join(timeout=5)
    assert len(calls) >= 1


def test_loop_mode_flipped_off_during_countdown_skips_the_stale_target(
        tmp_path):
    """The mirror image of the test above: mode flips OFF while a run is
    already counting down to a target computed under the OLD (daily)
    settings. Before the stale-target fix, the loop fired anyway once the
    wait elapsed -- it only ever checked `now >= target` against the
    settings read BEFORE the wait, never noticing the flip. A quarantine-
    capable scheduled run must not fire from a schedule the operator has
    since turned off.

    Deterministic by construction, not by sleep-racing the thread: the
    injected next_run_at_fn signals `computed_target` on its FIRST call,
    then waits for `settings_updated`.  The write below therefore lands
    after the loop read the original "daily" settings but before it can
    start counting down.  `reentered` fires on the SECOND call, which only
    happens once the loop has re-read settings post-wait and either fired or
    correctly skipped -- so by then, `calls` is settled and safe to assert
    on."""
    calls = []
    spath = bulkhash_refresh.settings_path(str(tmp_path / "state"))
    bulkhash_refresh.write_settings(
        spath, "daily", 6, dict(bulkhash_refresh._DEFAULT_LAST_RUN))
    stop = threading.Event()
    computed_target = threading.Event()
    settings_updated = threading.Event()
    reentered = threading.Event()

    def fake_next_run_at(mode, hour_utc, now):
        if not computed_target.is_set():
            computed_target.set()
            assert settings_updated.wait(timeout=5)
        elif not reentered.is_set():
            reentered.set()
        return None if mode == "off" else now + 0.15

    t = _run_loop(tmp_path, stop, lambda *a, **kw: calls.append((a, kw)),
                 idle_recheck=0.5, next_run_at_fn=fake_next_run_at)
    try:
        assert computed_target.wait(timeout=5)
        bulkhash_refresh.write_settings(
            spath, "off", 0, dict(bulkhash_refresh._DEFAULT_LAST_RUN))
        settings_updated.set()
        assert reentered.wait(timeout=5)
    finally:
        settings_updated.set()
        stop.set()
        t.join(timeout=5)
    assert not t.is_alive()
    assert calls == []


def test_loop_hour_utc_pushed_later_during_countdown_skips_the_stale_target(
        tmp_path):
    """Same guard, triggered by an hour_utc edit instead of a mode flip --
    the schedule stayed "daily" but no longer means the same target. The
    fake schedule fn treats hour_utc=6 as "due very soon" and any OTHER
    hour_utc as "genuinely far off" -- modeling the edit as an operator
    truly pushing the run later, not just re-arriving at a new near-term
    target moments afterward (which would be legitimate, and is exercised
    separately by test_loop_fires_when_next_run_at_reports_due).

    Same three-event handshake as the mode-flip test above, in place of
    sleep-racing the thread."""
    calls = []
    spath = bulkhash_refresh.settings_path(str(tmp_path / "state"))
    bulkhash_refresh.write_settings(
        spath, "daily", 6, dict(bulkhash_refresh._DEFAULT_LAST_RUN))
    stop = threading.Event()
    computed_target = threading.Event()
    settings_updated = threading.Event()
    reentered = threading.Event()

    def fake_next_run_at(mode, hour_utc, now):
        if not computed_target.is_set():
            computed_target.set()
            assert settings_updated.wait(timeout=5)
        elif not reentered.is_set():
            reentered.set()
        if mode == "off":
            return None
        return now + 0.15 if hour_utc == 6 else now + 100

    t = _run_loop(tmp_path, stop, lambda *a, **kw: calls.append((a, kw)),
                 idle_recheck=0.5, next_run_at_fn=fake_next_run_at)
    try:
        assert computed_target.wait(timeout=5)
        bulkhash_refresh.write_settings(
            spath, "daily", 20, dict(bulkhash_refresh._DEFAULT_LAST_RUN))
        settings_updated.set()
        assert reentered.wait(timeout=5)
    finally:
        settings_updated.set()
        stop.set()
        t.join(timeout=5)
    assert not t.is_alive()
    assert calls == []


def test_loop_run_refresh_exception_does_not_kill_the_thread(tmp_path):
    spath = bulkhash_refresh.settings_path(str(tmp_path / "state"))
    bulkhash_refresh.write_settings(
        spath, "daily", 6, dict(bulkhash_refresh._DEFAULT_LAST_RUN))
    stop = threading.Event()
    calls = []

    def blowing_up(*a, **kw):
        calls.append(1)
        raise RuntimeError("boom")

    def fake_next_run_at(mode, hour_utc, now):
        return None if mode == "off" else now + 0.03

    t = _run_loop(tmp_path, stop, blowing_up, idle_recheck=0.5,
                 next_run_at_fn=fake_next_run_at)
    for _ in range(50):
        if calls:
            break
        time.sleep(0.05)
    assert t.is_alive()          # the exception did not kill the thread
    stop.set()
    t.join(timeout=5)
    assert not t.is_alive()


def test_loop_stop_event_exits_promptly_with_long_idle(tmp_path):
    bulkhash_refresh.write_settings(
        bulkhash_refresh.settings_path(str(tmp_path / "state")), "off", 0,
        dict(bulkhash_refresh._DEFAULT_LAST_RUN))
    stop = threading.Event()
    t = _run_loop(tmp_path, stop, lambda *a, **kw: None, idle_recheck=30)
    time.sleep(0.05)
    started = time.time()
    stop.set()
    t.join(timeout=5)
    assert not t.is_alive()
    assert time.time() - started < 4       # stopped promptly, not after 30s
