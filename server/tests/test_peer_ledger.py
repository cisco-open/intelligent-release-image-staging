# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import json

import peer_ledger


IH = "a" * 40
IMAGE = "cat9k_iosxe.17.15.01.SPA.bin"


class Clock:
    def __init__(self, start=1000.0):
        self.now = start

    def __call__(self):
        return self.now

    def tick(self, seconds=2.0):
        self.now += seconds
        return self.now


def _ledger(tmp_path, clock=None):
    return peer_ledger.PeerLedger(str(tmp_path), now_fn=clock or Clock())


def _totals(ledger, info_hash=IH):
    return ledger.totals(info_hash).get(info_hash, {})


def test_first_sample_of_a_connection_counts_in_full(tmp_path):
    ledger = _ledger(tmp_path)
    rows = ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 100}, "s1")
    assert rows == [{"info_hash": IH, "image_id": IMAGE, "ip": "10.0.0.1",
                     "peer_sent_bytes": 100, "peer_sent_delta_bytes": 100}]
    assert _totals(ledger) == {"10.0.0.1": 100}


def test_growth_accumulates_only_the_delta(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 100}, "s1")
    rows = ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 450}, "s1")
    assert rows[0]["peer_sent_delta_bytes"] == 350
    assert rows[0]["peer_sent_bytes"] == 450
    assert _totals(ledger) == {"10.0.0.1": 450}


def test_unchanged_counter_emits_no_row(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 100}, "s1")
    assert ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 100}, "s1") == []
    assert _totals(ledger) == {"10.0.0.1": 100}


def test_replaced_connection_banks_the_peak_and_continues(tmp_path):
    """A DROP on a known (ip, port) is a new connection on a reused port: the
    old peak is already banked sample by sample, so the new value counts in
    full and accumulation continues from it — no double count, no lost
    connection."""
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 100}, "s1")
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 500}, "s1")
    rows = ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 40}, "s1")
    assert rows[0]["peer_sent_delta_bytes"] == 40
    assert _totals(ledger) == {"10.0.0.1": 540}
    rows = ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 90}, "s1")
    assert rows[0]["peer_sent_delta_bytes"] == 50
    assert _totals(ledger) == {"10.0.0.1": 590}


def test_absent_then_returning_connection_is_not_double_counted(tmp_path):
    """A peer missing from one sample must not restart its baseline: re-reading
    the same cumulative value would bank the whole connection twice."""
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 500}, "s1")
    assert ledger.observe(IH, IMAGE, {}, "s1") == []
    assert ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 500}, "s1") == []
    assert _totals(ledger) == {"10.0.0.1": 500}


def test_multiple_connections_from_one_peer_sum_into_one_edge(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 100,
                               ("10.0.0.1", 6882): 250}, "s1")
    assert _totals(ledger) == {"10.0.0.1": 350}
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 130,
                               ("10.0.0.1", 6882): 250}, "s1")
    assert _totals(ledger) == {"10.0.0.1": 380}


def test_session_change_banks_everything_and_starts_an_epoch(tmp_path):
    """aria2 restarted: the new session's counters share nothing with the old
    ones, so the first sample of the epoch counts in full and the durable
    totals are kept."""
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 900}, "s1")
    rows = ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 120}, "s2")
    assert rows[0]["peer_sent_delta_bytes"] == 120
    assert _totals(ledger) == {"10.0.0.1": 1020}
    # ...and the new epoch diffs normally from there.
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 200}, "s2")
    assert _totals(ledger) == {"10.0.0.1": 1100}


def test_session_change_moves_origin_and_peers_to_one_epoch(tmp_path):
    """The origin reading must not be banked before the session transition and
    then counted again after that transition clears its baseline."""
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 500}, "s1",
                   upload_length=500)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 120}, "s2",
                   upload_length=120)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 200}, "s2",
                   upload_length=200)
    totals = ledger.torrent_totals()[IH]
    assert totals["origin_total"] == 700
    assert totals["attributed"] == 700


def test_session_change_with_a_higher_counter_still_counts_in_full(tmp_path):
    """Without the epoch reset this reading would be diffed against a dead
    session's counter and silently lose 300 bytes."""
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 300}, "s1")
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 700}, "s2")
    assert _totals(ledger) == {"10.0.0.1": 1000}


def test_origin_gauge_becomes_a_monotonic_counter(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {}, "s1", upload_length=1000)
    assert ledger.torrent_totals()[IH]["origin_total"] == 1000
    ledger.observe(IH, IMAGE, {}, "s1", upload_length=4618)
    assert ledger.torrent_totals()[IH]["origin_total"] == 4618
    # control-state loss: the gauge restarts, the durable counter must not
    ledger.observe(IH, IMAGE, {}, "s1", upload_length=200)
    assert ledger.torrent_totals()[IH]["origin_total"] == 4818
    ledger.observe(IH, IMAGE, {}, "s1", upload_length=500)
    assert ledger.torrent_totals()[IH]["origin_total"] == 5118


def test_origin_gauge_baseline_resets_on_a_session_change(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 10}, "s1",
                   upload_length=4000)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 10}, "s2",
                   upload_length=4000)
    assert ledger.torrent_totals()[IH]["origin_total"] == 8000


def test_origin_gauge_ignores_junk_readings(tmp_path):
    ledger = _ledger(tmp_path)
    for value in (500, -1, None, "nope"):
        ledger.observe(IH, IMAGE, {}, "s1", upload_length=value)
    assert ledger.torrent_totals()[IH]["origin_total"] == 500
    ledger.observe(IH, IMAGE, {}, "s1", upload_length=600)
    assert ledger.torrent_totals()[IH]["origin_total"] == 600


def test_unattributed_is_the_residue_between_ground_truth_and_edges(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 700,
                               ("10.0.0.2", 6881): 300}, "s1",
                   upload_length=1400)
    assert ledger.unattributed(IH) == 400


def test_unattributed_never_goes_negative(tmp_path):
    """Edges and the torrent gauge are separate readings; an edge ahead of the
    gauge must not print a negative byte count."""
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 5000}, "s1",
                   upload_length=100)
    assert ledger.unattributed(IH) == 0
    assert ledger.torrent_totals()[IH]["unattributed"] == 0


def test_unattributed_of_an_unknown_torrent_is_zero(tmp_path):
    assert _ledger(tmp_path).unattributed("b" * 40) == 0


def test_torrent_totals_reports_the_aggregate_the_dashboards_chart(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 700,
                               ("10.0.0.2", 6881): 0}, "s1",
                   upload_length=1000)
    totals = ledger.torrent_totals()[IH]
    assert totals["image_id"] == IMAGE
    assert totals["attributed"] == 700
    assert totals["origin_total"] == 1000
    assert totals["unattributed"] == 300
    assert totals["peers"] == 2
    assert totals["peers_attributed"] == 1
    assert totals["saturated"] is False


def test_peer_cap_saturates_visibly_and_leaves_the_bytes_in_the_residue(tmp_path):
    ledger = _ledger(tmp_path)
    samples = {("10.1.%d.%d" % (i // 256, i % 256), 6881): 10
               for i in range(peer_ledger._PEER_CAP)}
    ledger.observe(IH, IMAGE, samples, "s1")
    assert ledger.torrent_totals()[IH]["saturated"] is False
    ledger.observe(IH, IMAGE, {("192.0.2.99", 6881): 999}, "s1")
    totals = ledger.torrent_totals()[IH]
    assert totals["saturated"] is True
    assert totals["peers"] == peer_ledger._PEER_CAP
    assert "192.0.2.99" not in _totals(ledger)
    ledger.observe(IH, IMAGE, {}, "s1",
                   upload_length=peer_ledger._PEER_CAP * 10 + 999)
    assert ledger.unattributed(IH) == 999


def test_known_peers_keep_accumulating_after_saturation(tmp_path):
    ledger = _ledger(tmp_path)
    samples = {("10.1.%d.%d" % (i // 256, i % 256), 6881): 10
               for i in range(peer_ledger._PEER_CAP)}
    ledger.observe(IH, IMAGE, samples, "s1")
    ledger.observe(IH, IMAGE, {("192.0.2.99", 6881): 999,
                               ("10.1.0.0", 6881): 40}, "s1")
    assert _totals(ledger)["10.1.0.0"] == 40


def test_connection_baselines_are_bounded_per_peer(tmp_path):
    clock = Clock()
    ledger = _ledger(tmp_path, clock)
    for port in range(peer_ledger._CONN_CAP * 3):
        clock.tick()
        ledger.observe(IH, IMAGE, {("10.0.0.1", 7000 + port): 5}, "s1")
    with open(ledger.path) as stream:
        stored = json.load(stream)
    conns = stored["torrents"][IH]["peers"]["10.0.0.1"]["conns"]
    assert len(conns) == peer_ledger._CONN_CAP
    # eviction is least-recently-seen, i.e. never a live connection
    assert "7000" not in conns
    assert str(7000 + peer_ledger._CONN_CAP * 3 - 1) in conns
    assert _totals(ledger) == {"10.0.0.1": 5 * peer_ledger._CONN_CAP * 3}


def test_totals_survive_a_reload_from_disk(tmp_path):
    clock = Clock()
    ledger = _ledger(tmp_path, clock)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 400}, "s1",
                   upload_length=1000)
    reopened = peer_ledger.PeerLedger(str(tmp_path), now_fn=clock)
    assert _totals(reopened) == {"10.0.0.1": 400}
    assert reopened.unattributed(IH) == 600
    # and a reloaded ledger still diffs against the stored connection baseline
    assert reopened.observe(IH, IMAGE, {("10.0.0.1", 6881): 450}, "s1") == [
        {"info_hash": IH, "image_id": IMAGE, "ip": "10.0.0.1",
         "peer_sent_bytes": 450, "peer_sent_delta_bytes": 50}]


def test_a_corrupt_store_does_not_break_accumulation(tmp_path):
    ledger = _ledger(tmp_path)
    with open(ledger.path, "w") as stream:
        stream.write("{ not json")
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 7}, "s1")
    assert _totals(ledger) == {"10.0.0.1": 7}


def test_junk_samples_are_dropped(tmp_path):
    ledger = _ledger(tmp_path)
    rows = ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): -5,
                                      ("10.0.0.2", 6881): True,
                                      ("10.0.0.3", 6881): None,
                                      ("", 6881): 10,
                                      ("x" * 65, 6881): 10,
                                      "10.0.0.4": 10,
                                      ("10.0.0.5", 6881): "42"}, "s1")
    assert [row["ip"] for row in rows] == ["10.0.0.5"]
    assert _totals(ledger) == {"10.0.0.5": 42}


def test_totals_are_copies_of_the_store(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 100}, "s1")
    out = ledger.totals()
    out[IH]["10.0.0.1"] = 10 ** 9
    assert _totals(ledger) == {"10.0.0.1": 100}


def test_torrents_are_tracked_independently(tmp_path):
    other = "b" * 40
    ledger = _ledger(tmp_path)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 100}, "s1")
    ledger.observe(other, "other.bin", {("10.0.0.1", 6881): 70}, "s1")
    assert ledger.totals() == {IH: {"10.0.0.1": 100}, other: {"10.0.0.1": 70}}
    assert ledger.torrent_totals()[other]["image_id"] == "other.bin"


def test_prune_drops_only_torrents_older_than_the_cutoff(tmp_path):
    clock = Clock()
    ledger = _ledger(tmp_path, clock)
    ledger.observe(IH, IMAGE, {("10.0.0.1", 6881): 100}, "s1")
    clock.tick(3600)
    other = "b" * 40
    ledger.observe(other, "other.bin", {("10.0.0.2", 6881): 100}, "s1")
    assert ledger.prune(clock.now - 60) == [IH]
    assert list(ledger.totals()) == [other]


def test_torrent_cap_evicts_the_stalest_and_counts_it(tmp_path):
    clock = Clock()
    ledger = _ledger(tmp_path, clock)
    for i in range(peer_ledger._TORRENT_CAP + 3):
        clock.tick()
        ledger.observe("%040d" % i, IMAGE, {("10.0.0.1", 6881): 10}, "s1")
    stats = ledger.stats()
    assert stats["torrents"] == peer_ledger._TORRENT_CAP
    assert stats["torrents_evicted"] == 3
    assert "%040d" % 0 not in ledger.totals()
