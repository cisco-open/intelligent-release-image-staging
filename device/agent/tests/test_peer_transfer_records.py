# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exact per-peer received bytes: the --on-bt-download-complete hook and the
agent-side plumbing that carries its snapshot into the v2 terminal report.

The number under test is aria2-next's own cumulative per-peer session counter
(peer->getSessionDownloadLength()), READ ONCE at the instant the last piece
landed. It is not the integrated-from-rates estimate removed in release
2026.08.20, and these tests pin the distinction in three places: the field is
`session_bytes_from_peer` and the retired names appear nowhere; an unreadable
or absent measurement is reported as ABSENT, never as a measured zero; and a
spurious all-zero fire can never overwrite a real snapshot.
"""
import json
import os
import shutil
import subprocess
import threading
import time
import types
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import iris_agent
import telemetry_report as tr

HOOK = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "peer-transfer-hook.sh")


def _peer(ip, got, sent, port=None, seeder=None):
    """One aria2 getPeers row. aria2 serialises every value as a STRING
    (util::itos / VLB_TRUE), which is exactly what the parser must survive."""
    row = {"ip": ip, "downloaded": str(got), "uploaded": str(sent)}
    if port is not None:
        row["port"] = str(port)
    if seeder is not None:
        row["seeder"] = "true" if seeder else "false"
    return row


def _doc(peers, captured_at=1000.0, **over):
    """A sidecar document shaped exactly as peer-transfer-hook.sh writes one:
    the JSON-RPC BATCH body embedded verbatim, unparsed by the shell."""
    doc = {"schema": 1, "source": "aria2_session_counters",
           "captured_at": captured_at, "gid": "2089b05ecca3d829",
           "rpc": [{"jsonrpc": "2.0", "id": "peers", "result": list(peers)},
                   {"jsonrpc": "2.0", "id": "session",
                    "result": {"sessionId": "cd6f6d0"}}]}
    doc.update(over)
    return json.dumps(doc)


# ---- parse_peer_transfer_snapshot(): the measurement ---------------------------

class TestParseSnapshot:
    def test_exact_shape_and_totals(self):
        b = tr.parse_peer_transfer_snapshot(_doc([
            _peer("10.0.0.7", 41943040, 1048576, port=6881, seeder=True),
            _peer("10.0.0.8", 4194304, 0, port=51413, seeder=False)]))
        assert b == {
            "source": "aria2_session_counters",
            "captured_at": 1000.0,
            "complete": True,
            "rows": [{"ip": "10.0.0.7", "session_bytes_from_peer": 41943040,
                      "session_bytes_to_peer": 1048576, "port": 6881,
                      "has_complete_file": True},
                     {"ip": "10.0.0.8", "session_bytes_from_peer": 4194304,
                      "session_bytes_to_peer": 0, "port": 51413,
                      "has_complete_file": False}],
            "rows_total": 2,
            "rows_omitted": 0,
            "bytes_from_all_senders_total": 46137344,
            "bytes_from_all_senders_omitted": 0}

    def test_retired_field_names_appear_nowhere(self):
        """The 2026.08.20 names stay dead: a dashboard querying rx_bytes must
        stay empty rather than silently repopulate with a different kind of
        number, and a reader must never wonder which kind they are holding."""
        blob = json.dumps(tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 10, 1)])))
        for retired in ("rx_bytes", "tx_bytes", "avg_bps", "bytes_received"):
            assert retired not in blob

    def test_zero_from_a_connected_peer_is_a_measured_zero(self):
        """A row that exists carrying 0 is a fact (connected, fed us nothing).
        Only an ABSENT row/block means 'not measured'."""
        b = tr.parse_peer_transfer_snapshot(_doc([
            _peer("10.0.0.7", 500, 0), _peer("10.0.0.9", 0, 900)]))
        zero = [r for r in b["rows"] if r["ip"] == "10.0.0.9"][0]
        assert zero["session_bytes_from_peer"] == 0
        assert zero["session_bytes_to_peer"] == 900
        assert b["complete"] is True

    def test_accepts_int_values_too(self):
        b = tr.parse_peer_transfer_snapshot(_doc([
            {"ip": "10.0.0.7", "downloaded": 7, "uploaded": 0,
             "seeder": True, "port": 6881}]))
        assert b["rows"][0]["session_bytes_from_peer"] == 7
        assert b["rows"][0]["has_complete_file"] is True

    @pytest.mark.parametrize("over", [
        {"schema": 2}, {"schema": None}, {"source": "estimated"},
        {"source": None}, {"captured_at": 0}, {"captured_at": -1.0},
        {"captured_at": "1000"}, {"captured_at": True},
        {"captured_at": float("inf")}, {"rpc": {"error": {"code": -32600}}},
        {"rpc": None}, {"rpc": "[]"}])
    def test_unusable_documents_yield_nothing(self, over):
        assert tr.parse_peer_transfer_snapshot(_doc([_peer("10.0.0.7", 9, 0)],
                                              **over)) is None

    @pytest.mark.parametrize("raw", ["", "not json", "[]", '{"a":1}',
                                     b'{"schema":1}', '{"schema":1,'])
    def test_garbage_yields_nothing(self, raw):
        assert tr.parse_peer_transfer_snapshot(raw) is None

    def test_rpc_error_response_yields_no_block(self):
        """An RPC error is 'not measured', which is an absent block — never an
        empty one that a reader could mistake for a measured zero."""
        doc = json.dumps({"schema": 1, "source": "aria2_session_counters",
                          "captured_at": 1000.0,
                          "rpc": [{"id": "peers",
                                   "error": {"code": 1, "message": "no gid"}}]})
        assert tr.parse_peer_transfer_snapshot(doc) is None

    def test_reads_bytes_payload(self):
        b = tr.parse_peer_transfer_snapshot(_doc([_peer("10.0.0.7", 5, 0)]).encode())
        assert b["bytes_from_all_senders_total"] == 5

    def test_ignores_the_session_entry_and_entry_order(self):
        doc = json.loads(_doc([_peer("10.0.0.7", 5, 0)]))
        doc["rpc"].reverse()
        b = tr.parse_peer_transfer_snapshot(json.dumps(doc))
        assert b["rows_total"] == 1 and b["bytes_from_all_senders_total"] == 5

    def test_accepts_a_lone_response_object(self):
        b = tr.parse_peer_transfer_snapshot(_doc(
            [], rpc={"jsonrpc": "2.0", "id": "peers",
                     "result": [_peer("10.0.0.7", 8, 0)]}))
        assert b["bytes_from_all_senders_total"] == 8

    def test_accepts_a_bare_peer_list(self):
        b = tr.parse_peer_transfer_snapshot(_doc([], rpc=[_peer("10.0.0.7", 8, 0)]))
        assert b["bytes_from_all_senders_total"] == 8


class TestParseIncompleteCapture:
    """`complete: false` says bytes_from_all_senders_total is a FLOOR. A row whose
    counters cannot be read is DROPPED, never carried as a zero — the total
    then understates, and the flag says so."""

    def test_unreadable_counters_drop_the_row_and_clear_complete(self):
        b = tr.parse_peer_transfer_snapshot(_doc([
            _peer("10.0.0.7", 1000, 0),
            {"ip": "10.0.0.8", "downloaded": "not-a-number", "uploaded": "0"},
            {"ip": "10.0.0.9", "uploaded": "0"}]))
        assert [r["ip"] for r in b["rows"]] == ["10.0.0.7"]
        assert b["complete"] is False
        assert b["bytes_from_all_senders_total"] == 1000     # a floor, and flagged

    @pytest.mark.parametrize("bad", [
        {"downloaded": "-5", "uploaded": "0", "ip": "10.0.0.8"},
        {"downloaded": "1.5", "uploaded": "0", "ip": "10.0.0.8"},
        {"downloaded": True, "uploaded": "0", "ip": "10.0.0.8"},
        {"downloaded": None, "uploaded": "0", "ip": "10.0.0.8"}])
    def test_nonsense_counters_are_not_zeroes(self, bad):
        b = tr.parse_peer_transfer_snapshot(_doc([_peer("10.0.0.7", 5, 0), bad]))
        assert len(b["rows"]) == 1 and b["complete"] is False

    @pytest.mark.parametrize("entry", [
        "not a dict", 17, None, {"downloaded": "5", "uploaded": "0"},
        {"ip": "", "downloaded": "5", "uploaded": "0"},
        {"ip": "x" * 65, "downloaded": "5", "uploaded": "0"}])
    def test_malformed_entries_clear_complete(self, entry):
        b = tr.parse_peer_transfer_snapshot(_doc([_peer("10.0.0.7", 5, 0), entry]))
        assert [r["ip"] for r in b["rows"]] == ["10.0.0.7"]
        assert b["complete"] is False

    @pytest.mark.parametrize("ip", ["not-an-ip", "10.0.0.256", "10.0.0.7 ",
                                    "::ffff:1.2.3.4.5", "10.0.0.7:6881"])
    def test_unparseable_addresses_are_dropped_not_shipped(self, ip):
        """The server rejects an unparseable address, and rejects the WHOLE
        report over one. A row we cannot vouch for costs its own bytes, never
        the entire terminal report."""
        b = tr.parse_peer_transfer_snapshot(_doc([
            _peer("10.0.0.7", 1000, 0), _peer(ip, 7, 0)]))
        assert [r["ip"] for r in b["rows"]] == ["10.0.0.7"]
        assert b["complete"] is False
        assert b["bytes_from_all_senders_total"] == 1000

    def test_ipv6_peers_are_kept(self):
        b = tr.parse_peer_transfer_snapshot(_doc([_peer("2001:db8::7", 42, 0)]))
        assert b["rows"][0]["ip"] == "2001:db8::7"
        assert b["complete"] is True

    def test_unreadable_bytes_past_the_hard_cap_make_the_total_a_floor(self):
        """An overflow entry is still counted as a dropped row, but bytes we
        cannot read are bytes we cannot report: the total goes back to being a
        floor and complete says so, exactly as below the cap."""
        peers = [_peer("10.1.%d.%d" % (i // 256, i % 256), 1, 0)
                 for i in range(tr.HOOK_PEER_ROWS_HARD_CAP)]
        peers.append({"ip": "10.9.0.1", "downloaded": "nope", "uploaded": "0"})
        b = tr.parse_peer_transfer_snapshot(_doc(peers))
        assert b["rows_total"] == tr.HOOK_PEER_ROWS_HARD_CAP + 1
        assert b["complete"] is False
        assert b["bytes_from_all_senders_total"] == tr.HOOK_PEER_ROWS_HARD_CAP

    def test_port_is_optional_and_never_guessed(self):
        b = tr.parse_peer_transfer_snapshot(_doc([
            _peer("10.0.0.7", 5, 0),
            _peer("10.0.0.8", 4, 0, port=0),
            _peer("10.0.0.9", 3, 0, port="70000")]))
        assert all("port" not in r for r in b["rows"])
        assert b["complete"] is True        # a port is not the measurement

    def test_complete_file_flag_omitted_when_unrecognised(self):
        b = tr.parse_peer_transfer_snapshot(_doc([
            {"ip": "10.0.0.7", "downloaded": "5", "uploaded": "0",
             "seeder": "yes"}]))
        assert "has_complete_file" not in b["rows"][0]


class TestParseDuplicateAddresses:
    """Two connections from one address (NAT, or a reconnect on a new port).
    The server's row key is the ip and duplicate rows are rejected outright, so
    the device collapses them here — summing keeps the total exact."""

    def test_collapsed_and_summed(self):
        b = tr.parse_peer_transfer_snapshot(_doc([
            _peer("10.0.0.7", 100, 5, port=6881, seeder=False),
            _peer("10.0.0.7", 400, 1, port=6881, seeder=False)]))
        assert len(b["rows"]) == 1 and b["rows_total"] == 1
        assert b["rows"][0]["session_bytes_from_peer"] == 500
        assert b["rows"][0]["session_bytes_to_peer"] == 6
        assert b["bytes_from_all_senders_total"] == 500

    def test_disagreeing_port_is_dropped_not_picked(self):
        b = tr.parse_peer_transfer_snapshot(_doc([
            _peer("10.0.0.7", 100, 0, port=6881),
            _peer("10.0.0.7", 100, 0, port=51413)]))
        assert "port" not in b["rows"][0]

    def test_complete_file_flag_survives_the_collapse(self):
        b = tr.parse_peer_transfer_snapshot(_doc([
            _peer("10.0.0.7", 1, 0, seeder=False),
            _peer("10.0.0.7", 1, 0, seeder=True)]))
        assert b["rows"][0]["has_complete_file"] is True


class TestParseTruncation:
    """Overflow is a COUNT, never a silence: the biggest contributors are
    named, and the mass of everything dropped is stated."""

    def _many(self, n):
        return [_peer("10.2.0.%d" % i, (i + 1) * 1000, 0) for i in range(n)]

    def test_named_rows_are_the_largest_contributors(self):
        b = tr.parse_peer_transfer_snapshot(_doc(self._many(40)))
        assert len(b["rows"]) == tr.PEER_TRANSFER_ROWS_CAP
        assert b["rows"][0]["session_bytes_from_peer"] == 40000
        assert b["rows"] == sorted(
            b["rows"], key=lambda r: -r["session_bytes_from_peer"])

    def test_totals_are_summed_before_truncation_and_stay_exact(self):
        rows = self._many(40)
        b = tr.parse_peer_transfer_snapshot(_doc(rows))
        assert b["bytes_from_all_senders_total"] == sum(
            int(r["downloaded"]) for r in rows)
        assert b["rows_total"] == 40
        assert b["rows_omitted"] == 40 - tr.PEER_TRANSFER_ROWS_CAP
        assert (sum(r["session_bytes_from_peer"] for r in b["rows"])
                + b["bytes_from_all_senders_omitted"]
                == b["bytes_from_all_senders_total"])

    def test_ties_break_on_ip_for_determinism(self):
        peers = [_peer("10.3.0.%d" % i, 7, 0) for i in range(5)]
        first = tr.parse_peer_transfer_snapshot(_doc(peers))["rows"]
        peers.reverse()
        assert tr.parse_peer_transfer_snapshot(_doc(peers))["rows"] == first

    def test_entries_past_the_hard_cap_are_weighed_not_silently_dropped(self):
        """HOOK_PEER_ROWS_HARD_CAP bounds how many entries become ROWS, not how
        much of the answer we are willing to know. Their bytes were really
        received, so they are counted AND summed into rows_omitted /
        bytes_from_all_senders_omitted like every other cap here. Slicing them
        away unweighed left them out of the total too — an understated total
        with nothing but complete=False hinting at it."""
        kept = [_peer("10.1.%d.%d" % (i // 256, i % 256), 1, 0)
                for i in range(tr.HOOK_PEER_ROWS_HARD_CAP)]
        over = [_peer("10.9.0.%d" % i, 1000, 0) for i in range(5)]
        b = tr.parse_peer_transfer_snapshot(_doc(kept + over))
        assert b["rows_total"] == tr.HOOK_PEER_ROWS_HARD_CAP + 5
        assert b["rows_omitted"] == (
            tr.HOOK_PEER_ROWS_HARD_CAP - tr.PEER_TRANSFER_ROWS_CAP + 5)
        assert b["bytes_from_all_senders_total"] == \
            tr.HOOK_PEER_ROWS_HARD_CAP + 5000
        assert (sum(r["session_bytes_from_peer"] for r in b["rows"])
                + b["bytes_from_all_senders_omitted"]
                == b["bytes_from_all_senders_total"])
        # The cap is the reader's, not the capture's: nothing was missed on the
        # wire, so complete stays true — the same rule PEER_TRANSFER_ROWS_CAP follows.
        assert b["complete"] is True

    def test_truncation_does_not_make_the_capture_incomplete(self):
        """complete is about the CAPTURE; rows_omitted is about the TRANSPORT.
        Two different failures, two different fields."""
        b = tr.parse_peer_transfer_snapshot(_doc(self._many(40)))
        assert b["complete"] is True and b["rows_omitted"] > 0


# ---- fold_peer_transfer_records(): the guards ------------------------------------

class TestFold:
    def test_accepts_and_stores(self):
        tele = {"started_ts": 900.0}
        b = tr.parse_peer_transfer_snapshot(_doc([_peer("10.0.0.7", 500, 0)]))
        assert tr.fold_peer_transfer_records(tele, b, now=1010.0) is True
        assert tele["peer_transfer_records"]["bytes_from_all_senders_total"] == 500

    def test_all_zero_snapshot_is_discarded(self):
        """aria2 re-fires this hook on a --bt-seed-unverified re-add of an
        already-complete file, with no peers connected. A torrent that really
        received nothing from anyone did not happen: absent, not zero."""
        tele = {"started_ts": 900.0}
        b = tr.parse_peer_transfer_snapshot(_doc([_peer("10.0.0.7", 0, 900)]))
        assert tr.fold_peer_transfer_records(tele, b, now=1010.0) is False
        assert "peer_transfer_records" not in tele

    def test_empty_snapshot_is_discarded(self):
        tele = {"started_ts": 900.0}
        b = tr.parse_peer_transfer_snapshot(_doc([]))
        assert b["rows"] == [] and b["bytes_from_all_senders_total"] == 0
        assert tr.fold_peer_transfer_records(tele, b, now=1010.0) is False
        assert "peer_transfer_records" not in tele

    def test_all_zero_snapshot_never_overwrites_a_real_one(self):
        tele = {"started_ts": 900.0}
        real = tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 500, 0)], captured_at=1000.0))
        tr.fold_peer_transfer_records(tele, real, now=1010.0)
        spurious = tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 0, 0)], captured_at=1500.0))
        assert tr.fold_peer_transfer_records(tele, spurious, now=1600.0) is False
        assert tele["peer_transfer_records"]["bytes_from_all_senders_total"] == 500

    def test_snapshot_from_before_this_transfer_is_refused(self):
        """The sidecar is keyed by staged FILENAME, so a re-download of the
        same image could find its predecessor's snapshot. Attributing those
        bytes here is the exact class of false data this work ends."""
        tele = {"started_ts": 5000.0}
        stale = tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 500, 0)], captured_at=4000.0))
        assert tr.fold_peer_transfer_records(tele, stale, now=5100.0) is False
        assert "peer_transfer_records" not in tele

    def test_snapshot_after_this_transfer_started_is_kept(self):
        tele = {"started_ts": 5000.0}
        b = tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 500, 0)], captured_at=5000.0))
        assert tr.fold_peer_transfer_records(tele, b, now=5100.0) is True

    def test_age_bounds_a_snapshot_with_no_started_ts(self):
        old = tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 5, 0)], captured_at=1000.0))
        assert tr.fold_peer_transfer_records(
            {}, old, now=1000.0 + tr.PEER_TRANSFER_MAX_AGE_S + 1) is False
        assert tr.fold_peer_transfer_records({}, old, now=1000.0 + 30.0) is True

    def test_a_capture_from_the_future_is_refused(self):
        b = tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 5, 0)], captured_at=9000.0))
        assert tr.fold_peer_transfer_records(
            {"started_ts": 100.0}, b,
            now=9000.0 - tr.PEER_TRANSFER_FUTURE_SKEW_S - 1) is False

    def test_newer_replaces_older_but_not_the_reverse(self):
        tele = {"started_ts": 100.0}
        newer = tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 900, 0)], captured_at=2000.0))
        older = tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 100, 0)], captured_at=1000.0))
        assert tr.fold_peer_transfer_records(tele, newer, now=2100.0) is True
        assert tr.fold_peer_transfer_records(tele, older, now=2100.0) is False
        assert tele["peer_transfer_records"]["bytes_from_all_senders_total"] == 900

    @pytest.mark.parametrize("block", [None, {}, "x", 5, {"captured_at": 1}])
    def test_junk_is_refused_without_raising(self, block):
        tele = {}
        assert tr.fold_peer_transfer_records(tele, block, now=1.0) is False
        assert tele == {}


# ---- the v2 report ------------------------------------------------------

_CFG = {"device_id": "sw1", "agent_version": "2026.08.25"}


def _state(**tele_over):
    tele = {"transfer_id": "a" * 32, "started_ts": 1000.0, "done_ts": 1100.0,
            "completed_content_bytes": 973078528,
            "total_content_bytes": 973078528,
            "content_sha256_state": "verified",
            "ios_copy_verify_state": "ok",
            "peers_v2": {"10.0.0.9": {"first_observed": 1010.0,
                                      "last_observed": 1090.0,
                                      "observations": 71}}}
    tele.update(tele_over)
    return {"img1": {"copied": True, "tele": tele}}


def _report(state):
    return tr.build_report_v2(_CFG, state, "img1", "staging-complete",
                              1200.5, "a" * 32, "b" * 32)


class TestReportBlock:
    def test_absent_when_nothing_was_measured(self):
        """Absent means 'not measured'. There is no zeroed placeholder for a
        device with no hook wired, and a reader must render it as such."""
        assert "peer_transfer_records" not in _report(_state())

    def test_present_and_exact_when_folded(self):
        tele = _state()["img1"]["tele"]
        tr.fold_peer_transfer_records(tele, tr.parse_peer_transfer_snapshot(_doc(
            [_peer("10.0.0.7", 41943040, 1048576, port=6881, seeder=True),
             _peer("10.0.0.9", 4194304, 0, port=51413, seeder=False)],
            captured_at=1099.5)), now=1100.0)
        rep = _report({"img1": {"copied": True, "tele": tele}})
        block = rep["peer_transfer_records"]
        assert block["source"] == "aria2_session_counters"
        assert block["captured_at"] == 1099.5
        assert block["complete"] is True
        assert block["bytes_from_all_senders_total"] == 46137344
        assert block["rows"][0]["session_bytes_from_peer"] == 41943040

    def test_capture_instant_is_not_the_report_instant(self):
        """The hook fires at the last piece; the report is assembled minutes
        later by the next one-shot EEM tick. captured_at is the former."""
        tele = _state()["img1"]["tele"]
        tr.fold_peer_transfer_records(tele, tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 500, 0)], captured_at=1099.5)), now=1100.0)
        rep = _report({"img1": {"copied": True, "tele": tele}})
        assert rep["peer_transfer_records"]["captured_at"] == 1099.5
        assert rep["report_created_at"] == 1200.5
        assert rep["window"]["start"] <= 1099.5 <= rep["report_created_at"]

    def test_participation_rows_never_gain_bytes(self):
        """peers[] and peer_transfer_records.rows[] sit APART, joined by ip at read
        time: one is what a 60 s sampler caught, the other is what the client
        knew when knowledge was complete. Merging them would produce rows that
        are part sampled and part exact."""
        tele = _state()["img1"]["tele"]
        tr.fold_peer_transfer_records(tele, tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 500, 0)], captured_at=1050.0)), now=1100.0)
        rep = _report({"img1": {"copied": True, "tele": tele}})
        assert rep["peers"] == [{"ip": "10.0.0.9", "first_observed": 1010.0,
                                 "last_observed": 1090.0, "observations": 71}]
        assert all(set(r) == {"ip", "first_observed", "last_observed",
                              "observations"} for r in rep["peers"])
        # the two sets legitimately disagree, and that disagreement is the
        # finding: 10.0.0.7 fed us and was never sampled.
        assert rep["peer_transfer_records"]["rows"][0]["ip"] == "10.0.0.7"

    def test_report_rows_are_copies_of_state(self):
        tele = _state()["img1"]["tele"]
        tr.fold_peer_transfer_records(tele, tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 500, 0)], captured_at=1050.0)), now=1100.0)
        rep = _report({"img1": {"copied": True, "tele": tele}})
        rep["peer_transfer_records"]["rows"][0]["session_bytes_from_peer"] = 1
        assert tele["peer_transfer_records"]["rows"][0][
            "session_bytes_from_peer"] == 500

    def test_capture_outside_the_window_costs_only_itself(self):
        """A transfer whose started_ts was never recorded (agent state lost
        while the staged file survived) has no window start to place the
        hook's instant in: the report leaves window.start ABSENT and the
        window incomplete, and the records are bounded at done_ts — which is
        strictly after the hook fired — so the block is dropped instead of
        costing the whole report an impossible instant. Stretching the window
        back to captured_at, which would keep it, would misstate the transfer
        window to save a byte count.
        (Rewritten: it used to pin window.start COLLAPSED onto done_ts, the
        invented zero-length window IRIS-10-002 removed.)"""
        tele = _state()["img1"]["tele"]
        del tele["started_ts"]                    # the state that was lost
        assert tr.fold_peer_transfer_records(tele, tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 500, 0)], captured_at=1099.0)),
            now=1100.0) is True                   # measured, and kept in state
        rep = _report({"img1": {"copied": True, "tele": tele}})
        assert "start" not in rep["window"]       # unknown, not invented
        assert rep["window"]["end"] == 1100.0
        assert rep["window"]["complete"] is False
        assert "peer_transfer_records" not in rep         # but not shipped
        assert rep["content"]["completed_content_bytes"] == 973078528

    def test_capture_after_the_report_instant_is_not_shipped(self):
        tele = _state()["img1"]["tele"]
        tele["peer_transfer_records"] = tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 500, 0)], captured_at=9999.0))
        assert "peer_transfer_records" not in _report({"img1": {"copied": True,
                                                        "tele": tele}})

    def test_worst_case_report_fits_the_server_store_bound(self):
        """The server stores a bounded body (16384 B) and REJECTS anything
        larger, so the two peer tables together must fit with room to spare."""
        tele = _state()["img1"]["tele"]
        tele["peers_v2"] = {
            "%d.%d.255.255" % (100 + i // 256, i % 256): {
                "first_observed": 1234567890.123,
                "last_observed": 1234567999.987, "observations": 9999}
            for i in range(tr.STATE_PEER_SET_CAP)}
        tele["peer_transfer_records"] = {
            "source": tr.PEER_TRANSFER_SOURCE, "captured_at": 1050.0,
            "complete": True,
            "rows": [{"ip": "%d.%d.255.255" % (200 + i // 256, i % 256),
                      "session_bytes_from_peer": 9007199254740992,
                      "session_bytes_to_peer": 9007199254740992,
                      "port": 65535, "has_complete_file": True}
                     for i in range(tr.PEER_TRANSFER_ROWS_CAP)],
            "rows_total": 512, "rows_omitted": 512 - tr.PEER_TRANSFER_ROWS_CAP,
            "bytes_from_all_senders_total": 9007199254740992,
            "bytes_from_all_senders_omitted": 9007199254740992}
        rep = _report({"img1": {"copied": True, "tele": tele}})
        assert len(rep["peers"]) == tr.PEER_CAP
        assert len(rep["peer_transfer_records"]["rows"]) == tr.PEER_TRANSFER_ROWS_CAP
        assert len(json.dumps(rep)) < 16384

    def test_report_is_json_serialisable(self):
        tele = _state()["img1"]["tele"]
        tr.fold_peer_transfer_records(tele, tr.parse_peer_transfer_snapshot(
            _doc([_peer("10.0.0.7", 500, 0)], captured_at=1050.0)), now=1100.0)
        json.dumps(_report({"img1": {"copied": True, "tele": tele}}))

    def test_corrupt_stored_block_is_simply_absent(self):
        for junk in ({"source": "guessed"}, {"source": "aria2_session_counters"},
                     "x", 5, []):
            assert "peer_transfer_records" not in _report(_state(peer_transfer_records=junk))


# ---- agent-side sidecar I/O ---------------------------------------------

class TestSidecarIO:
    def test_read_and_remove(self, tmp_path):
        p = tmp_path / "img.bin.peers.json"
        p.write_text("hello")
        assert iris_agent._take_peer_transfer_sidecar(str(p)) == b"hello"
        assert not p.exists()

    def test_missing_is_the_ordinary_case(self, tmp_path):
        assert iris_agent._take_peer_transfer_sidecar(
            str(tmp_path / "nope.json")) is None

    def test_oversized_is_removed_unread(self, tmp_path):
        p = tmp_path / "img.bin.peers.json"
        p.write_bytes(b"x" * (tr.PEER_TRANSFER_MAX_BYTES + 1))
        assert iris_agent._take_peer_transfer_sidecar(str(p)) is None
        assert not p.exists()

    def test_unusable_document_is_still_removed(self, tmp_path):
        """One-shot agent: a snapshot that cannot be used now never becomes
        usable, and leaving it behind makes it a candidate for the NEXT
        transfer of the same image."""
        stage = tmp_path / "img.bin"
        side = tmp_path / ("img.bin" + tr.PEER_TRANSFER_SIDECAR_SUFFIX)
        side.write_text("{not json")
        deps = types.SimpleNamespace(emit=lambda *a: None)
        assert iris_agent._ingest_peer_transfer_records(deps, {}, str(stage), 1.0) \
            is False
        assert not side.exists()

    def test_discard_before_a_new_download(self, tmp_path):
        side = tmp_path / ("img.bin" + tr.PEER_TRANSFER_SIDECAR_SUFFIX)
        side.write_text("{}")
        iris_agent._discard_peer_transfer_records(str(tmp_path / "img.bin"))
        assert not side.exists()
        iris_agent._discard_peer_transfer_records(str(tmp_path / "img.bin"))   # no-op

    def test_sidecar_path_is_derived_from_the_staged_file(self):
        assert tr.peer_transfer_sidecar_path("/flash/guest-share/iris/img.bin") == \
            "/flash/guest-share/iris/img.bin.peers.json"

    def test_ingest_folds_and_removes(self, tmp_path):
        stage = tmp_path / "img.bin"
        side = tmp_path / ("img.bin" + tr.PEER_TRANSFER_SIDECAR_SUFFIX)
        side.write_text(_doc([_peer("10.0.0.7", 500, 0)], captured_at=1000.0))
        emitted = []
        deps = types.SimpleNamespace(
            emit=lambda tag, msg: emitted.append((tag, msg)))
        tele = {"started_ts": 900.0}
        assert iris_agent._ingest_peer_transfer_records(
            deps, tele, str(stage), 1010.0) is True
        assert tele["peer_transfer_records"]["bytes_from_all_senders_total"] == 500
        assert not side.exists()
        assert emitted and "measured" in emitted[0][1]

    def test_ingest_never_raises(self, tmp_path):
        side = tmp_path / ("img.bin" + tr.PEER_TRANSFER_SIDECAR_SUFFIX)
        side.write_text(_doc([_peer("10.0.0.7", 500, 0)]))
        boom = types.SimpleNamespace(
            emit=lambda *a: (_ for _ in ()).throw(RuntimeError("syslog down")))
        assert iris_agent._ingest_peer_transfer_records(
            boom, {"started_ts": 1.0}, str(tmp_path / "img.bin"), 2000.0) \
            is False


class TestTerminalTickIngest:
    """The tick is where the one-shot process meets a file written minutes ago
    by a process it never saw."""

    CFG = {"telemetry": "on", "device_id": "d1", "agent_version": "t"}

    def _deps(self):
        return types.SimpleNamespace(
            aria_stats=lambda s: {"completedLength": "973078528",
                                  "totalLength": "973078528"},
            aria_peers=lambda s: [{"ip": "10.0.0.9"}],
            emit=lambda *a: None,
            catalog=types.SimpleNamespace())

    def test_folded_before_done_ts_freezes_the_report(self, tmp_path):
        stage = tmp_path / "img.bin"
        (tmp_path / ("img.bin" + tr.PEER_TRANSFER_SIDECAR_SUFFIX)).write_text(
            _doc([_peer("10.0.0.7", 41943040, 0, seeder=True)],
                 captured_at=1099.0))
        state = {"img1": {"copied": True, "tele": {"started_ts": 1000.0}}}
        iris_agent._telemetry_tick(self.CFG, self._deps(), state, "img1",
                                   str(stage), "copied", {}, 1100.0)
        tele = state["img1"]["tele"]
        assert tele["done_ts"] == 1100.0
        assert tele["peer_transfer_records"]["captured_at"] == 1099.0
        assert tele["peer_transfer_records"]["rows"][0]["has_complete_file"] is True
        assert not (tmp_path / ("img.bin" + tr.PEER_TRANSFER_SIDECAR_SUFFIX)).exists()

    def test_absent_sidecar_leaves_the_tick_untouched(self, tmp_path):
        state = {"img1": {"copied": True, "tele": {"started_ts": 1000.0}}}
        iris_agent._telemetry_tick(self.CFG, self._deps(), state, "img1",
                                   str(tmp_path / "img.bin"), "copied",
                                   {}, 1100.0)
        assert state["img1"]["tele"]["done_ts"] == 1100.0
        assert "peer_transfer_records" not in state["img1"]["tele"]

    def test_seeding_only_completion_also_ingests(self, tmp_path):
        stage = tmp_path / "img.bin"
        (tmp_path / ("img.bin" + tr.PEER_TRANSFER_SIDECAR_SUFFIX)).write_text(
            _doc([_peer("10.0.0.7", 77, 0)], captured_at=1099.0))
        state = {"img1": {"blocked_no_space": True,
                          "tele": {"started_ts": 1000.0}}}
        iris_agent._telemetry_tick(self.CFG, self._deps(), state, "img1",
                                   str(stage), "seeding-only", {}, 1100.0)
        assert state["img1"]["tele"][
            "peer_transfer_records"]["bytes_from_all_senders_total"] == 77

    def test_not_ingested_twice(self, tmp_path):
        stage = tmp_path / "img.bin"
        side = tmp_path / ("img.bin" + tr.PEER_TRANSFER_SIDECAR_SUFFIX)
        side.write_text(_doc([_peer("10.0.0.7", 77, 0)], captured_at=1099.0))
        state = {"img1": {"copied": True, "tele": {"started_ts": 1000.0}}}
        iris_agent._telemetry_tick(self.CFG, self._deps(), state, "img1",
                                   str(stage), "copied", {}, 1100.0)
        side.write_text(_doc([_peer("10.0.0.7", 999, 0)], captured_at=1199.0))
        iris_agent._telemetry_tick(self.CFG, self._deps(), state, "img1",
                                   str(stage), "copied", {}, 1200.0)
        assert state["img1"]["tele"][
            "peer_transfer_records"]["bytes_from_all_senders_total"] == 77


# ---- the hook script itself ---------------------------------------------

class _RpcHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.requests.append(json.loads(body.decode()))
        out = json.dumps(self.server.reply).encode()
        self.send_response(self.server.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


class _Rpc:
    """A stand-in for aria2's JSON-RPC endpoint, on the loopback address the
    hook always talks to (same netns as aria2c in every runtime)."""

    def __init__(self, reply, status=200):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _RpcHandler)
        self.srv.requests = []
        self.srv.reply = reply
        self.srv.status = status
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()

    @property
    def requests(self):
        return self.srv.requests


def _run_hook(stage, port=None, secret="s3cret", gid="2089b05ecca3d829"):
    """Invoke the hook exactly as aria2 does: execlp(prog, gid, numFiles,
    firstFilename) — no shell, no quoting anywhere on that path."""
    env = dict(os.environ, IRIS_RPC_SECRET=secret)
    env["IRIS_RPC_PORT"] = str(port if port is not None else 1)
    return subprocess.run([HOOK, gid, "1", str(stage)], env=env,
                          capture_output=True, timeout=30)


needs_curl = pytest.mark.skipif(shutil.which("curl") is None,
                                reason="curl not available")


class TestHookScript:
    def test_is_executable_and_posix_sh(self):
        assert os.access(HOOK, os.X_OK)      # execlp needs the exec bit
        assert subprocess.run(["sh", "-n", HOOK]).returncode == 0
        with open(HOOK) as f:
            assert f.readline().strip() == "#!/bin/sh"

    @needs_curl
    def test_writes_a_snapshot_the_agent_can_parse(self, tmp_path):
        stage = tmp_path / "img.bin"
        reply = [{"jsonrpc": "2.0", "id": "peers", "result": [
                    _peer("10.0.0.7", 41943040, 1048576, port=6881,
                          seeder=True),
                    _peer("10.0.0.8", 4194304, 0, port=51413, seeder=False)]},
                 {"jsonrpc": "2.0", "id": "session",
                  "result": {"sessionId": "cd6f6d0"}}]
        with _Rpc(reply) as rpc:
            assert _run_hook(stage, rpc.port).returncode == 0
            req = rpc.requests[0]
        # one HTTP round trip, batched
        assert [c["method"] for c in req] == ["aria2.getPeers",
                                              "aria2.getSessionInfo"]
        # the gid arrives on argv and goes straight into getPeers
        assert req[0]["params"][:2] == ["token:s3cret", "2089b05ecca3d829"]
        # getPeers keys are opt-in in our build: the byte counters must be
        # asked for by name or they are simply not in the reply
        assert set(req[0]["params"][2]) >= {"downloaded", "uploaded", "seeder"}

        side = tmp_path / ("img.bin" + tr.PEER_TRANSFER_SIDECAR_SUFFIX)
        block = tr.parse_peer_transfer_snapshot(side.read_text())
        assert block["bytes_from_all_senders_total"] == 46137344
        assert block["complete"] is True
        assert block["rows"][0] == {"ip": "10.0.0.7",
                                    "session_bytes_from_peer": 41943040,
                                    "session_bytes_to_peer": 1048576,
                                    "port": 6881, "has_complete_file": True}
        assert block["captured_at"] > 0
        assert not list(tmp_path.glob("*.tmp.*"))   # published atomically

    @needs_curl
    def test_no_daemon_writes_nothing_and_still_exits_zero(self, tmp_path):
        """A broken hook is SILENT by design (daemon-mode stderr is
        /dev/null), so its only contract is: never break the transfer, never
        leave a half-written file behind."""
        stage = tmp_path / "img.bin"
        assert _run_hook(stage).returncode == 0          # nothing listening
        assert list(tmp_path.iterdir()) == []

    @needs_curl
    def test_rpc_error_writes_nothing(self, tmp_path):
        stage = tmp_path / "img.bin"
        reply = [{"jsonrpc": "2.0", "id": "peers",
                  "error": {"code": 1, "message": "No such download"}}]
        with _Rpc(reply) as rpc:
            assert _run_hook(stage, rpc.port).returncode == 0
        assert list(tmp_path.iterdir()) == []

    @needs_curl
    def test_http_failure_writes_nothing(self, tmp_path):
        stage = tmp_path / "img.bin"
        with _Rpc({"unauthorized": True}, status=401) as rpc:
            assert _run_hook(stage, rpc.port).returncode == 0
        assert list(tmp_path.iterdir()) == []

    @needs_curl
    def test_missing_argv_is_a_silent_noop(self, tmp_path):
        for argv in ([HOOK], [HOOK, "gid", "1", ""]):
            assert subprocess.run(argv, capture_output=True, cwd=str(tmp_path),
                                  timeout=30).returncode == 0
        assert list(tmp_path.iterdir()) == []

    @needs_curl
    def test_a_stalled_rpc_is_bounded_and_writes_nothing(self, tmp_path):
        """It cannot block aria2 — aria2 forks and never waits (SIGCHLD is
        SIG_IGN) — but the worst case must still be bounded, because the
        statement after the hook fires is enableSeedOnly(). aria2 is local and
        already holds this answer in memory, so a stall means something is
        wrong and waiting longer buys nothing."""
        stage = tmp_path / "img.bin"

        class _Slow(_RpcHandler):
            def do_POST(self):
                time.sleep(30)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Slow)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            began = time.time()
            assert _run_hook(stage, srv.server_address[1]).returncode == 0
            assert time.time() - began < 10.0
        finally:
            srv.shutdown()
            srv.server_close()
        assert list(tmp_path.iterdir()) == []

    @needs_curl
    def test_unwritable_stage_dir_is_a_silent_noop(self, tmp_path):
        reply = [{"jsonrpc": "2.0", "id": "peers",
                  "result": [_peer("10.0.0.7", 5, 0)]}]
        with _Rpc(reply) as rpc:
            r = _run_hook("/proc/nonexistent-dir/img.bin", rpc.port)
        assert r.returncode == 0

    @needs_curl
    def test_republished_atomically_over_an_existing_snapshot(self, tmp_path):
        stage = tmp_path / "img.bin"
        side = tmp_path / ("img.bin" + tr.PEER_TRANSFER_SIDECAR_SUFFIX)
        side.write_text("stale")
        reply = [{"jsonrpc": "2.0", "id": "peers",
                  "result": [_peer("10.0.0.7", 12345, 0)]}]
        with _Rpc(reply) as rpc:
            assert _run_hook(stage, rpc.port).returncode == 0
        assert tr.parse_peer_transfer_snapshot(
            side.read_text())["bytes_from_all_senders_total"] == 12345
        assert not list(tmp_path.glob("*.tmp.*"))
