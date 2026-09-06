# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Mixed-workload capacity harness (issue #55; extended for issue #125).

#51/#52/#53/#56/#58 (see ``test_keyed_state_scaling.py``) and the console
paging work each measured ONE operation, by hand, with a throwaway script,
against a single fleet size. Nothing repeatable was left behind, so nothing
catches a future change that quietly gives the win back. This module is that
repeatable harness: it seeds a synthetic fleet of N devices in a fresh
temporary directory, drives the same operations a real fleet drives
concurrently -- a tracker announce, a catalog heartbeat, a device policy
read, a terminal report, a credential resolution, a fleet-wide bulk
credential reassignment, and the console's own fleet projection -- and
reports, per operation, how the cost moves as N goes from 100 to 1,000 to
10,000. A single number at one size proves nothing about growth; the growth
factor across a hundredfold fleet is the thing that would catch a
regression.

This module itself is what found issue #125: ``gui_fleet.FleetStore`` was
the one per-device store the #51-#58 shard migration missed, still doing a
whole-fleet read-modify-write under one lock -- reachable at fleet scale
through the console's own "Select all N matching devices" bulk credential
action, one HTTP request per selected device against a route that called
it. ``_measure_bulk_reassignment`` below is that fix's own regression
coverage: FleetStore is sharded now (this harness's ``_seed_fleet`` seeds
its shards directly, like every other store here), and
``FleetStore.bulk_upsert`` collapses the console's N per-device requests
into one call that groups the underlying writes by shard.

**What this measures, and how.** Every write/read below calls the exact
production function the real hot path calls (``peer_endpoints
.record_endpoint``, ``catalog.CatalogStore.record_heartbeat`` /
``device_policy_view`` / ``record_telemetry``, ``credential_cache
.CredentialResolver.view`` followed by the catalog and tracker auth resolvers,
``gui_fleet.FleetStore.upsert`` /
``bulk_upsert``) against synthetic state shaped like the real thing. The
console projection goes one step further and drives the real ``gui_server``
HTTP handler end to end (bind, login, ``GET /api/devices`` paged and
unpaged) rather than re-deriving the merge logic here, so a change to that
handler's shape shows up the same way it would in production.

**What this does NOT measure.** No concurrency (operations run one at a
time, sequentially, from a single thread/process -- a real fleet hammers the
tracker and catalog from thousands of devices at once, and this harness says
nothing about lock contention or thread-pool saturation under that load). No
process/FD/thread growth over time. No real network path (the console check
binds a real loopback socket on an OS-assigned port -- port 0, never a
documented product port -- but the per-device store operations are called as
library functions, not through HTTP). No disk-hardware latency: state lives
under ``tempfile.TemporaryDirectory()``, whatever filesystem backs the
process's temp dir on the machine running this.

**Wall-clock numbers here are informational, not a gate.** This machine also
runs the live IRIS lab server and real device traffic; a shared, loaded build
host is a noisy clock. Only the DETERMINISTIC counters -- which shard files
changed, how many rows a touched shard holds, how many credential-index
builds and index lookups a run of requests costs, how many bytes a console
response carries --
are asserted on, following the style ``test_keyed_state_scaling.py``
established: bytes and files touched and index builds counted, never elapsed
time. A comparison between two SEPARATE runs (different day, different
machine load, different host) is not valid; only the growth factor WITHIN
one run, across its sizes, is.

**Running it.**

A small, fast check (two sizes ten-fold apart, ~seconds) runs by default with
every test suite:

    python3 -m pytest server/tests/test_capacity_harness.py -q

The full 100/1,000/10,000 progression is slow by design -- it rebuilds a
10,000-device synthetic fleet -- so it is opt-in, following the project's
``IRIS_TEST_HOST_INTEGRATION=1`` convention for tests that should not run on
every commit:

    IRIS_TEST_CAPACITY_LARGE=1 python3 -m pytest \\
        server/tests/test_capacity_harness.py -q -s -k ten_thousand

It can also be run standalone, outside pytest, for an ad hoc report at any
sizes:

    python3 server/tests/test_capacity_harness.py --sizes 100 1000 10000

See ``TESTING.md`` and ``docs/zensical/validation.md`` for the numbers this
produced on record and what would invalidate a comparison against them.
"""
import collections
import http.client
import json
import os
import statistics
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import auth
import catalog
import credential_cache
import gui_app
import gui_fleet
import management_api as gui_server
import keyed_state
import peer_endpoints
import secrets_store

Principal = collections.namedtuple("Principal", ["type", "id"])

# Two sizes, ten-fold apart: fast enough to run on every commit, still wide
# enough to show a growth factor rather than a single point.
FAST_SIZES = (50, 500)
FAST_SAMPLE = 12
FAST_PAGE_LIMIT = 8

# The progression the project's own scale claims are stated at (see
# CHANGELOG.md "Unreleased" and the commit this issue follows up on):
# a hundredfold fleet, 100 -> 1,000 -> 10,000 devices. 10,000 is also
# peer_endpoints.SUPPORTED_DEVICES -- the top of the supported range, not an
# arbitrary large number.
# Below the SMALLEST size on purpose: a page limit that is not smaller than
# the fleet being measured is not actually paging at that size (it returns
# every row, same as the unpaged call), which would make the "flat" claim
# below vacuous at the small end of the range. Pass --page-limit 200 on the
# CLI to reproduce the console's own real-world page size against a single
# large fleet (e.g. --sizes 10000 --page-limit 200).
LARGE_SIZES = (100, 1000, 10000)
LARGE_SAMPLE = 50
LARGE_PAGE_LIMIT = 50

_HTTP_TIMEOUT = 15


# ---------------------------------------------------------------------------
# Synthetic fleet construction. Every seeder below writes shard files (or,
# for the un-sharded fleet.json, the one file) DIRECTLY, the same way
# test_keyed_state_scaling.py's own ``_seed`` does -- paying the real
# per-device hot path 10,000 times just to build a fixture would make the
# harness itself the slow, flaky thing, and it is not what is under test
# here.
# ---------------------------------------------------------------------------

def _device_id(i):
    return "d%05d" % i


def _seed_shards(path, rows):
    """Put *rows* ({key: row}) into the keyed store at *path* without going
    through KeyedState -- see the module docstring."""
    d = keyed_state.shard_dir(path)
    os.makedirs(d, exist_ok=True)
    buckets = {}
    for key, row in rows.items():
        buckets.setdefault(keyed_state.bucket_of(key), {})[key] = row
    for bucket, rs in buckets.items():
        with open(os.path.join(d, "%02x.json" % bucket), "w") as f:
            json.dump(rs, f)


def _shard_bytes(path):
    """{shard file name: content} for the keyed store at *path*."""
    d = keyed_state.shard_dir(path)
    out = {}
    if not os.path.isdir(d):
        return out
    for name in sorted(os.listdir(d)):
        if name.endswith(".json"):
            with open(os.path.join(d, name)) as f:
                out[name] = f.read()
    return out


def _changed_shards(before, after):
    return sorted(n for n in set(before) | set(after) if before.get(n) != after.get(n))


def _v2(rid, tid):
    return {"schema": "v2", "report_id": rid, "transfer_id": tid,
            "event": "staging-complete", "image_id": "img-a"}


def _seed_catalog_store(store, n):
    _seed_shards(store.devices_path, {
        _device_id(i): {"device_id": _device_id(i), "last_seen": 1000.0,
                        "stage_state": "ready"} for i in range(n)})
    _seed_shards(store.policy_path, {
        _device_id(i): {"approved_image_id": "img-a",
                        "approved_image_ids": ["img-a"],
                        "plans": {"img-a": {"plan_id": "a" * 32,
                                            "transfer_id": "b" * 32,
                                            "planned_at": 1000.0,
                                            "info_hash": "c" * 40}}}
        for i in range(n)})
    _seed_shards(store.telemetry_path, {
        _device_id(i): [_v2("%032x" % (i * 7), "%032x" % (i * 7 + 1))]
        for i in range(n)})
    _seed_shards(store.report_ledger_path, {
        _device_id(i): ["%032x" % (i * 7)] for i in range(n)})


def _seed_peer_endpoints(path, n):
    rows = {"device:%s" % _device_id(i): {
        "principal_type": "device", "principal_id": _device_id(i),
        "updated_at": 1000.0,
        "endpoints": [{"ipv4": "10.%d.%d.%d" % (0, (i // 256) % 256, i % 256),
                       "port": 6881, "observed_at": 1000.0,
                       "source": "announce"}]} for i in range(n)}
    _seed_shards(path, rows)


def _seed_secrets(path, n):
    store = {"devices": {}, "seeder": {}}
    for i in range(n):
        store["devices"][_device_id(i)] = {
            "catalog_token": {"value": "%032x" % (i * 3), "created_at": 0,
                              "expires_at": 0, "revoked": False},
            "announce_token": {"value": "%032x" % (i * 3 + 1), "created_at": 0,
                               "expires_at": 0, "revoked": False}}
    secrets_store.save(store, path)


def _seed_fleet(path, n):
    """FleetStore's fleet.d/ shards directly, exactly like every other
    keyed store here is seeded (issue #125 sharded it the same way
    devices.json/policy.json/etc. already were, see gui_fleet.py) --
    ``upsert()`` per device would still be O(1) now, but paying it 10,000
    times just to build a fixture would make SEEDING dominate the harness's
    own runtime, which is not what is under test here. This intentionally
    bypasses the legacy fleet.json document/migration path entirely, the
    same way _seed_shards below bypasses KeyedState for every other store:
    seeding measures steady state, not the one-shot migration."""
    _seed_shards(path, {
        _device_id(i): {
            "device_id": _device_id(i),
            "device_ip": "10.%d.%d.%d" % (1, (i // 256) % 256, i % 256),
            "model": "C9300", "platform": "guestshell",
            "management_type": "legacy_routed", "registered_at": 1000,
        } for i in range(n)})


def _sample_indices(n, sample):
    """`sample` device indices spread evenly across [0, n)."""
    sample = max(1, min(sample, n))
    step = max(1, n // sample)
    return list(range(0, n, step))[:sample]


def _time_call(fn):
    t0 = time.perf_counter()
    fn()
    return time.perf_counter() - t0


# ---------------------------------------------------------------------------
# Per-operation measurement. Each returns a dict with "times" (one
# perf_counter duration per sampled call -- informational) plus deterministic
# counters specific to the operation.
# ---------------------------------------------------------------------------

def _measure_announce(path, indices, seed):
    first = indices[0]
    key0 = "device:%s" % _device_id(first)
    before = _shard_bytes(path)
    t0 = time.perf_counter()
    peer_endpoints.record_endpoint(path, Principal("device", _device_id(first)),
                                   "10.77.0.1", 6881, float(seed))
    times = [time.perf_counter() - t0]
    after = _shard_bytes(path)
    changed = _changed_shards(before, after)
    mine = "%02x.json" % keyed_state.bucket_of(key0)
    rows = len(json.loads(after[mine])) if changed == [mine] else None
    for j, i in enumerate(indices[1:], start=1):
        did = _device_id(i)
        ip = "10.77.%d.%d" % ((i // 256) % 256, i % 256)
        now = float(seed + j)
        times.append(_time_call(
            lambda did=did, ip=ip, now=now: peer_endpoints.record_endpoint(
                path, Principal("device", did), ip, 6881, now)))
    return {"times": times, "single_shard": changed == [mine], "shard_rows": rows}


def _measure_heartbeat(store, indices, seed):
    first = indices[0]
    before = _shard_bytes(store.devices_path)
    t0 = time.perf_counter()
    store.record_heartbeat(_device_id(first), {"stage_state": "staging"},
                           now=float(seed))
    times = [time.perf_counter() - t0]
    after = _shard_bytes(store.devices_path)
    changed = _changed_shards(before, after)
    mine = "%02x.json" % keyed_state.bucket_of(_device_id(first))
    rows = len(json.loads(after[mine])) if changed == [mine] else None
    for j, i in enumerate(indices[1:], start=1):
        did = _device_id(i)
        now = float(seed + j)
        times.append(_time_call(
            lambda did=did, now=now: store.record_heartbeat(
                did, {"stage_state": "staging"}, now=now)))
    return {"times": times, "single_shard": changed == [mine], "shard_rows": rows}


def _measure_policy_read(store, indices):
    """Deterministic: exactly one shard is READ (opened/parsed) per policy
    lookup, holding only its bucket's share of the fleet -- the #52 property
    (see test_keyed_state_scaling.test_policy_read_does_not_parse_the_fleet),
    now checked at this harness's own sizes."""
    opened = []
    real_read = keyed_state.KeyedState._read_shard

    def counting(self, bucket):
        rows = real_read(self, bucket)
        opened.append(len(rows))
        return rows

    first = indices[0]
    keyed_state.KeyedState._read_shard = counting
    try:
        view = store.device_policy_view(_device_id(first))
    finally:
        keyed_state.KeyedState._read_shard = real_read
    assert view["approved_image_ids"] == ["img-a"]

    times = [_time_call(lambda: store.device_policy_view(_device_id(first)))]
    for i in indices[1:]:
        did = _device_id(i)
        times.append(_time_call(lambda did=did: store.device_policy_view(did)))
    return {"times": times, "shard_reads": len(opened),
            "rows_in_shard": opened[0] if opened else None}


def _measure_report_persist(store, indices, seed):
    first = indices[0]
    tel_before = _shard_bytes(store.telemetry_path)
    led_before = _shard_bytes(store.report_ledger_path)

    def report_for(i, j):
        base = (seed * 1000003 + i * 97 + j) % (1 << 127)
        return _v2("%032x" % base, "%032x" % (base + 1))

    t0 = time.perf_counter()
    store.record_telemetry(_device_id(first), report_for(first, 0))
    times = [time.perf_counter() - t0]
    tel_after = _shard_bytes(store.telemetry_path)
    led_after = _shard_bytes(store.report_ledger_path)
    tel_changed = _changed_shards(tel_before, tel_after)
    led_changed = _changed_shards(led_before, led_after)
    mine = "%02x.json" % keyed_state.bucket_of(_device_id(first))
    tel_rows = len(json.loads(tel_after[mine])) if tel_changed == [mine] else None
    for j, i in enumerate(indices[1:], start=1):
        did = _device_id(i)
        report = report_for(i, j)
        times.append(_time_call(
            lambda did=did, report=report: store.record_telemetry(did, report)))
    return {"times": times,
            "single_shard": tel_changed == [mine] and led_changed == [mine],
            "shard_rows": tel_rows}


class _CountedCredentialIndex(dict):
    """Count direct lookups and reject fleet traversal during authentication."""

    def __init__(self, entries):
        super().__init__(entries)
        self.lookups = 0

    def get(self, key, default=None):
        assert isinstance(key, bytes) and len(key) == 32
        self.lookups += 1
        return super().get(key, default)

    def __getitem__(self, key):
        self.lookups += 1
        return super().__getitem__(key)

    def __iter__(self):
        raise AssertionError("credential resolution must not scan the fleet")

    items = values = keys = __iter__


def _measure_credential_resolve(secrets_path, indices):
    """Measure real accepted/rejected auth requests, including cached views.

    Building an index once is insufficient: a resolver can still scan it on
    every request. Count lookups and forbid traversal after construction so
    fleet-wide scans fail deterministically, regardless of timing noise.
    """
    resolver = credential_cache.CredentialResolver(secrets_path)
    builds = collections.Counter()
    builders = {
        "catalog": secrets_store.build_catalog_auth_index,
        "announce": secrets_store.build_announce_index,
    }

    def counting(scope):
        def build(store):
            builds[scope] += 1
            return _CountedCredentialIndex(builders[scope](store))
        return build

    cached_builders = {scope: counting(scope) for scope in builders}
    paths = {}
    for name in ("catalog", "announce_query", "announce_legacy", "announce_bearer"):
        scope = "catalog" if name == "catalog" else "announce"
        times, lookups = [], []
        for i in indices:
            valid_token = "%032x" % (i * 3 + (scope == "announce"))
            for token, accepted in ((valid_token, True), ("unknown-token", False)):
                t0 = time.perf_counter()
                store, index = resolver.view(scope, cached_builders[scope])
                before = index.lookups
                try:
                    if name == "catalog":
                        context = auth.resolve_catalog_auth(store, index, token, 1000, 0)
                    elif name == "announce_bearer":
                        context = auth.resolve_announce_bearer(token, index, store, 1000, 0)
                    else:
                        param = "announce_token" if name == "announce_query" else "key"
                        context = auth.resolve_announce_principal(
                            param + "=" + token, index, store, 1000, 0)
                except auth.AnnounceAuthError as exc:
                    assert not accepted
                    assert not exc.expired
                    context = None
                times.append(time.perf_counter() - t0)
                lookups.append(index.lookups - before)
                if accepted:
                    assert context is not None
                    assert context.principal == auth.Principal("device", _device_id(i))
                    assert context.scope == scope
                else:
                    assert context is None
        paths[name] = {"times": times, "lookups": lookups}
    return {"paths": paths, "index_builds": dict(builds)}


def _measure_bulk_reassignment(fleet, indices, all_ids):
    """Issue #125: a fleet-wide credential/platform reassignment through the
    console's "Select all N matching devices" bulk action, before and after.

    'Before' is what the OLD single-device route still does per selected
    device -- one fleet.upsert() call, one shard lock/read/write cycle. Its
    O(1)-per-call property is already proven elsewhere in this file (the
    same pattern _measure_heartbeat/_measure_announce use); what matters
    here is that N of THOSE calls cost N shard writes, counted directly
    over a SAMPLE (running the real thing 10,000 times just to re-prove a
    per-call constant already established would make this measurement
    dominate the harness, not what is under test).

    'After' is ONE FleetStore.bulk_upsert() call across the WHOLE selected
    set (*all_ids* -- the "select all" case, not a sample): grouped by
    shard, so the shard WRITE COUNT is bounded by min(len(all_ids),
    keyed_state.SHARD_COUNT) -- not by len(all_ids) -- however large the
    selection. That bound, not a wall-clock number, is the proof: doing
    the same reassignment as N single-device calls would cost N shard
    writes (most of the store's ~256 shards rewritten many times over at
    fleet scale); bulk_upsert costs at most SHARD_COUNT, each exactly
    once."""
    real_write = keyed_state.KeyedState._write_shard

    def counting(writes):
        def wrapped(self, bucket, rows):
            writes.append(bucket)
            return real_write(self, bucket, rows)
        return wrapped

    before_writes = []
    keyed_state.KeyedState._write_shard = counting(before_writes)
    t0 = time.perf_counter()
    try:
        for i in indices:
            fleet.upsert({"device_id": _device_id(i),
                          "credential_profile_id": "lab-before"})
    finally:
        keyed_state.KeyedState._write_shard = real_write
    before_seconds = time.perf_counter() - t0

    after_writes = []
    keyed_state.KeyedState._write_shard = counting(after_writes)
    t0 = time.perf_counter()
    try:
        results = fleet.bulk_upsert(all_ids, {"credential_profile_id": "lab-after"})
    finally:
        keyed_state.KeyedState._write_shard = real_write
    after_seconds = time.perf_counter() - t0

    assert all(outcome["ok"] for outcome in results.values()), \
        [k for k, v in results.items() if not v["ok"]][:5]
    assert len(results) == len(all_ids)
    distinct_buckets = {keyed_state.bucket_of(did) for did in all_ids}
    return {
        "before_calls": len(indices),
        "before_write_calls": len(before_writes),   # == before_calls, one each
        "before_seconds": before_seconds,
        "after_devices": len(all_ids),
        "after_write_calls": len(after_writes),      # == distinct shard buckets
        "after_distinct_buckets": len(distinct_buckets),
        "after_seconds": after_seconds,
    }


def _console_login(host, port):
    c = http.client.HTTPConnection(host, port, timeout=_HTTP_TIMEOUT)
    body = json.dumps({"username": "admin", "password": "pw"}).encode()
    c.request("POST", "/api/login", body=body,
             headers={"Content-Type": "application/json"})
    r = c.getresponse()
    data = r.read()
    headers = dict(r.getheaders())
    c.close()
    assert r.status == 200, data
    return headers["Set-Cookie"].split(";")[0]


def _console_get(host, port, path, cookie):
    c = http.client.HTTPConnection(host, port, timeout=_HTTP_TIMEOUT)
    c.request("GET", path, headers={"Cookie": cookie})
    r = c.getresponse()
    body = r.read()
    c.close()
    return r.status, body


def _measure_console_projection(state_dir, fleet, cat, page_limit):
    """Drives the REAL gui_server HTTP handler (bind, login, GET) rather than
    re-deriving the merge/paging logic here -- see the module docstring.
    Binds to an OS-assigned port (0), never a fixed/documented one."""
    secrets_path = os.path.join(state_dir, "gui-secrets.json")
    app = gui_app.GuiApp(secrets_path)
    app.set_admin("admin", "pw")
    srv = gui_server.make_server("127.0.0.1", 0, app, fleet=fleet, catalog=cat,
                                 certfile=None)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        cookie = _console_login("127.0.0.1", port)
        t0 = time.perf_counter()
        status, body = _console_get("127.0.0.1", port, "/api/devices", cookie)
        unpaged_seconds = time.perf_counter() - t0
        assert status == 200, body
        unpaged = json.loads(body)
        unpaged_bytes = len(body)

        t0 = time.perf_counter()
        status, body = _console_get(
            "127.0.0.1", port, "/api/devices?limit=%d&offset=0" % page_limit,
            cookie)
        paged_seconds = time.perf_counter() - t0
        assert status == 200, body
        paged = json.loads(body)
        paged_bytes = len(body)
    finally:
        srv.shutdown()
        srv.server_close()
    assert unpaged["total"] == len(unpaged["devices"])
    assert len(paged["devices"]) == min(page_limit, paged["total"])
    assert paged["total"] == unpaged["total"]
    return {"unpaged_bytes": unpaged_bytes, "paged_bytes": paged_bytes,
            "unpaged_seconds": unpaged_seconds, "paged_seconds": paged_seconds}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def _run_one_size(n, sample, page_limit, seed=0):
    indices = _sample_indices(n, sample)
    with tempfile.TemporaryDirectory(prefix="iris-capacity-") as tmp:
        state_dir = tmp
        cat = catalog.CatalogStore(state_dir)
        _seed_catalog_store(cat, n)
        endpoints_path = os.path.join(state_dir, "peer-endpoints.json")
        _seed_peer_endpoints(endpoints_path, n)
        secrets_path = os.path.join(state_dir, "secrets.json")
        _seed_secrets(secrets_path, n)
        _seed_fleet(os.path.join(state_dir, "fleet.json"), n)
        fleet = gui_fleet.FleetStore(state_dir)

        return {
            "n": n, "sample": len(indices),
            "announce": _measure_announce(endpoints_path, indices, seed),
            "heartbeat": _measure_heartbeat(cat, indices, seed),
            "policy_read": _measure_policy_read(cat, indices),
            "report_persist": _measure_report_persist(cat, indices, seed),
            "credential_resolve": _measure_credential_resolve(secrets_path, indices),
            # issue #125: measured LAST -- it is the only measurement that
            # touches every device in the fleet (the "select all" bulk
            # case), so it runs after every other store's own measurement
            # rather than before it.
            "bulk_reassignment": _measure_bulk_reassignment(
                fleet, indices, [_device_id(i) for i in range(n)]),
            "console": _measure_console_projection(state_dir, fleet, cat, page_limit),
        }


def run_capacity_report(sizes, sample, page_limit):
    """{size: metrics} for every size in *sizes*. Each size gets its own
    fresh temporary directory, seeded and torn down before the next size
    starts -- at most one synthetic fleet is ever on disk at once."""
    return {n: _run_one_size(n, sample, page_limit, seed=n) for n in sizes}


def _median_ms(times):
    return statistics.median(times) * 1000.0


def format_report(report, sizes):
    lines = [
        "Capacity harness report (issue #55) -- wall-clock is informational "
        "only; see the module docstring for what invalidates a comparison.",
        "sizes: %s   sample calls/op: %s"
        % (", ".join(str(n) for n in sizes),
           ", ".join(str(report[n]["sample"]) for n in sizes)),
        "",
    ]
    header = "%-22s" % "operation (median)"
    for n in sizes:
        header += "%16s" % ("%d devices" % n)
    header += "%12s" % "growth"
    lines.append(header)
    ops = [("announce", "announce"), ("heartbeat", "heartbeat"),
          ("policy_read", "policy_read"), ("report_persist", "report_persist")]
    for key, label in ops:
        vals = [_median_ms(report[n][key]["times"]) for n in sizes]
        row = "%-22s" % label
        for v in vals:
            row += "%13.4f ms" % v
        growth = vals[-1] / vals[0] if vals[0] else float("inf")
        row += "%11.2fx" % growth
        lines.append(row)

    for name in ("catalog", "announce_query", "announce_legacy", "announce_bearer"):
        vals = [_median_ms(report[n]["credential_resolve"]["paths"][name]["times"])
                for n in sizes]
        row = "%-22s" % ("auth " + name)
        for value in vals:
            row += "%13.4f ms" % value
        growth = vals[-1] / vals[0] if vals[0] else float("inf")
        lines.append(row + "%11.2fx" % growth)

    unpaged_vals = [report[n]["console"]["unpaged_bytes"] for n in sizes]
    row = "%-22s" % "console unpaged"
    for v in unpaged_vals:
        row += "%14d B" % v
    growth = unpaged_vals[-1] / unpaged_vals[0] if unpaged_vals[0] else float("inf")
    row += "%11.2fx" % growth
    lines.append(row)

    paged_vals = [report[n]["console"]["paged_bytes"] for n in sizes]
    row = "%-22s" % "console paged"
    for v in paged_vals:
        row += "%14d B" % v
    growth = paged_vals[-1] / paged_vals[0] if paged_vals[0] else float("inf")
    row += "%11.2fx" % growth
    lines.append(row)

    fleet_growth = sizes[-1] / float(sizes[0])
    lines.append("")
    lines.append("fleet size grew %.0fx (%d -> %d); an O(1)-per-device "
                 "operation should stay near 1x, not track the fleet."
                 % (fleet_growth, sizes[0], sizes[-1]))

    for n in sizes:
        credentials = report[n]["credential_resolve"]
        maximum = max(max(path["lookups"]) for path in credentials["paths"].values())
        lines.append("auth at %d devices: %d index builds, at most %d lookups/request"
                     % (n, sum(credentials["index_builds"].values()), maximum))

    lines.append("")
    lines.append("issue #125: reassigning ALL selected devices' credential "
                 "-- old way (N single-device calls, each proven ONE shard "
                 "write/call below by sampling -- so N calls is N writes, "
                 "extrapolated here to the full selection) vs. bulk_upsert "
                 "(one call, grouped by shard)")
    header = "%-22s" % "devices selected"
    for n in sizes:
        header += "%16s" % ("%d devices" % n)
    lines.append(header)
    row = "%-22s" % "old: shard writes*"
    for n in sizes:
        row += "%16d" % report[n]["n"]      # one write per device, always
    lines.append(row)
    row = "%-22s" % "bulk: shard writes"
    for n in sizes:
        row += "%16d" % report[n]["bulk_reassignment"]["after_write_calls"]
    lines.append(row)
    row = "%-22s" % "reduction"
    for n in sizes:
        after = report[n]["bulk_reassignment"]["after_write_calls"]
        row += "%15.1fx" % (report[n]["n"] / float(after) if after else float("inf"))
    lines.append(row)
    lines.append("(median wall-clock, informational only: old %s -> bulk %s)"
                 % (", ".join("%.2fms/call" % (
                        1000.0 * report[n]["bulk_reassignment"]["before_seconds"]
                        / max(1, report[n]["bulk_reassignment"]["before_calls"]))
                        for n in sizes),
                    ", ".join("%.2fms total" % (
                        1000.0 * report[n]["bulk_reassignment"]["after_seconds"])
                        for n in sizes)))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _assert_credential_work(size_report):
    result = size_report["credential_resolve"]
    assert result["index_builds"] == {"catalog": 1, "announce": 1}
    assert set(result["paths"]) == {
        "catalog", "announce_query", "announce_legacy", "announce_bearer"}
    for path in result["paths"].values():
        assert len(path["lookups"]) == 2 * size_report["sample"]
        assert all(0 < count <= 2 for count in path["lookups"])


def test_capacity_harness_per_device_cost_is_flat_across_a_tenfold_fleet():
    """Always-run half of the harness: the SAME per-device write/read
    invariants #51-#58 established (one shard touched, one shard read, one
    credential-index build, a flat page) checked at TWO fleet sizes ten-fold
    apart, so a regression that only shows up as growth -- not as a single
    wrong number -- has something to catch it. Every assertion is
    deterministic (shard identity, row counts, response byte counts); none
    is wall-clock, so this cannot flake on a busy host."""
    report = run_capacity_report(FAST_SIZES, FAST_SAMPLE, FAST_PAGE_LIMIT)
    small, large = report[FAST_SIZES[0]], report[FAST_SIZES[1]]

    for op in ("announce", "heartbeat", "report_persist"):
        assert small[op]["single_shard"], op
        assert large[op]["single_shard"], op
        # A whole-fleet rewrite would show up here as shard_rows == n; a
        # sharded one stays a small fraction of the fleet at every size.
        assert small[op]["shard_rows"] < FAST_SIZES[0] // 4, op
        assert large[op]["shard_rows"] < FAST_SIZES[1] // 4, op

    assert small["policy_read"]["shard_reads"] == 1
    assert large["policy_read"]["shard_reads"] == 1
    assert small["policy_read"]["rows_in_shard"] < FAST_SIZES[0] // 4
    assert large["policy_read"]["rows_in_shard"] < FAST_SIZES[1] // 4

    for size_report in (small, large):
        _assert_credential_work(size_report)

    # issue #125: bulk_upsert's shard-write count is bounded by SHARD_COUNT
    # regardless of how many devices are selected, where N single-device
    # upsert() calls (still O(1) each post-#125, proven below) cost exactly
    # N shard writes -- doing a "select all" reassignment the OLD, one-
    # request-per-device way costs N writes; the bulk call costs at most
    # SHARD_COUNT, however large N is.
    for size_report in (small, large):
        br = size_report["bulk_reassignment"]
        assert br["before_write_calls"] == br["before_calls"], br
        assert br["after_write_calls"] == br["after_distinct_buckets"], br
        assert br["after_write_calls"] <= keyed_state.SHARD_COUNT, br
        assert br["after_devices"] == size_report["n"], br
    assert large["bulk_reassignment"]["after_write_calls"] < large["n"]

    # Console projection: a page stays the same shape regardless of fleet
    # size; the unpaged projection IS the whole fleet and must grow with it.
    paged_growth = (large["console"]["paged_bytes"]
                    / small["console"]["paged_bytes"])
    assert paged_growth < 1.3, paged_growth
    unpaged_growth = (large["console"]["unpaged_bytes"]
                      / small["console"]["unpaged_bytes"])
    fleet_growth = FAST_SIZES[1] / FAST_SIZES[0]
    assert unpaged_growth > fleet_growth * 0.8, unpaged_growth


@pytest.mark.skipif(
    os.environ.get("IRIS_TEST_CAPACITY_LARGE") != "1",
    reason="10,000-device capacity report: rebuilds a synthetic fleet at "
          "100/1,000/10,000 devices and is slow by design. Set "
          "IRIS_TEST_CAPACITY_LARGE=1 (add -s to see the printed table).")
def test_capacity_harness_ten_thousand_device_report(capsys):
    report = run_capacity_report(LARGE_SIZES, LARGE_SAMPLE, LARGE_PAGE_LIMIT)
    with capsys.disabled():
        print()
        print(format_report(report, LARGE_SIZES))

    small, large = report[LARGE_SIZES[0]], report[LARGE_SIZES[-1]]
    for op in ("announce", "heartbeat", "report_persist"):
        assert small[op]["single_shard"], op
        assert large[op]["single_shard"], op
        assert large[op]["shard_rows"] < LARGE_SIZES[-1] // 4, op
    assert large["policy_read"]["shard_reads"] == 1
    for size_report in report.values():
        _assert_credential_work(size_report)
    paged_growth = (large["console"]["paged_bytes"]
                    / small["console"]["paged_bytes"])
    assert paged_growth < 1.3, paged_growth

    # issue #125's headline number, at full scale: reassigning ALL 10,000
    # selected devices costs at most SHARD_COUNT (256) shard writes via
    # bulk_upsert -- not the 10,000 a caller doing it as one upsert() per
    # device (the console's pre-#125 bulk action) would cost.
    br = large["bulk_reassignment"]
    assert br["before_write_calls"] == br["before_calls"], br
    assert br["after_write_calls"] == br["after_distinct_buckets"], br
    assert br["after_write_calls"] <= keyed_state.SHARD_COUNT, br
    assert br["after_devices"] == LARGE_SIZES[-1], br
    assert br["after_write_calls"] < br["after_devices"] / 10, br


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="IRIS mixed-workload capacity harness (issue #55). "
                    "Self-contained: all state lives under a temporary "
                    "directory and is removed before the next size runs.")
    parser.add_argument("--sizes", type=int, nargs="+",
                        default=list(LARGE_SIZES),
                        help="fleet sizes to measure, e.g. --sizes 100 1000 "
                             "10000 (default: %s)" % (LARGE_SIZES,))
    parser.add_argument("--sample", type=int, default=LARGE_SAMPLE,
                        help="sampled calls per operation per size "
                             "(default: %d)" % LARGE_SAMPLE)
    parser.add_argument("--page-limit", type=int, default=LARGE_PAGE_LIMIT,
                        help="console page size to request (default: %d)"
                             % LARGE_PAGE_LIMIT)
    args = parser.parse_args()
    rpt = run_capacity_report(tuple(args.sizes), args.sample, args.page_limit)
    print(format_report(rpt, tuple(args.sizes)))
