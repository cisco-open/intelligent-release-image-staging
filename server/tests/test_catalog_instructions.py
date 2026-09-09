# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Task 14 catalog instruction and keylist HTTP contracts."""

import base64
import datetime as dt
import email.utils
import hashlib
import http.client
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import struct
import threading
import time

import pytest

import catalog
import instruction_keys
import instruction_stamper
import instructions
import keyed_state
import live_samples
import secrets_store


NOW = int(dt.datetime(2026, 9, 7, 12, tzinfo=dt.timezone.utc).timestamp())
PROBLEM_TITLES = {
    (503, "credential-store-unavailable"): "Credential store unavailable",
    (401, "catalog-authentication-required"): "Catalog authentication required",
    (403, "instruction-device-forbidden"): "Instruction access forbidden",
    (404, "instruction-stamp-missing"): "Instruction stamp missing",
    (404, "instruction-keylist-missing"): "Instruction keylist missing",
    (409, "stale_pointer"): "Stale instruction pointer",
    (429, "instruction-rate-limit-exceeded"):
        "Instruction request rate limit exceeded",
    (503, "instruction-state-unavailable"): "Instruction state unavailable",
    (503, "instruction-keylist-unavailable"):
        "Instruction keylist unavailable",
}


def _credential(value, expires=0, revoked=False):
    return {"value": value, "created_at": NOW - 60,
            "expires_at": expires, "revoked": revoked}


def _instruction_key(value="01" * 32, *, created=NOW - 60,
                     expires=None, revoked=False):
    expires = created + secrets_store.INSTR_KEY_TTL if expires is None else expires
    return {"value": value,
            "key_id": hashlib.sha256(bytes.fromhex(value)).hexdigest(),
            "created_at": created, "expires_at": expires,
            "revoked": revoked, "_scope": "instructions"}


def _sshsig(blob, marker=b"signature"):
    binary = (b"SSHSIG" + struct.pack(">I", 1)
              + struct.pack(">I", len(blob)) + blob + marker)
    return (b"-----BEGIN SSH SIGNATURE-----\n"
            + base64.b64encode(binary)
            + b"\n-----END SSH SIGNATURE-----\n")


def _role_material(state_dir, *, issued=NOW, expires=NOW + 3600,
                   control=None, signature_marker=b"signature"):
    control = control or {"catalog_tick_s": 300,
                          "telemetry_every_ticks": 3,
                          "telemetry_pause": False}
    qos = {"max_peers": 50, "seed_up_bps": 0, "seed_down_bps": 0,
           "leech_up_bps": 0, "leech_down_bps": 0,
           "overall_up_bps": 0, "overall_down_bps": 0,
           "max_concurrent": 2, "request_peer_speed_limit_bps": 0}
    semantic = {"v": 1, "role": "default", "restricted": False,
                "qos": qos, "control": control, "on_stale": "keep"}
    semantic_sha = hashlib.sha256(
        instructions.canonical_json(semantic)).hexdigest()
    certificate = b"ssh-ed25519-cert-v01@openssh.com AAAA test\n"
    cert_sha = hashlib.sha256(certificate).hexdigest()
    body0 = dict(semantic, issued_at=issued, expires_at=expires,
                 server_time=issued)
    generation = hashlib.sha256(instructions.pae(
        b"iris-role-generation-v1", instructions.canonical_json(body0),
        cert_sha.encode("ascii"))).hexdigest()
    body = dict(body0, role_gen=generation)
    body_bytes = instructions.canonical_json(body)
    cert_blob = (struct.pack(">I", len(b"ssh-ed25519-cert-v01@openssh.com"))
                 + b"ssh-ed25519-cert-v01@openssh.com" + b"certificate")
    signature = _sshsig(cert_blob, signature_marker)
    artifact = instructions.frame_role(body_bytes, signature)
    artifact_sha = hashlib.sha256(artifact).hexdigest()
    roles = Path(state_dir) / "instructions" / "roles.d"
    roles.mkdir(parents=True, exist_ok=True)
    (roles / ("default@" + generation)).write_bytes(artifact)
    role_state = {
        "schema": instruction_stamper.ROLE_STATE_SCHEMA,
        "generations": {generation: {
            "state": "active", "epoch": issued, "role": "default",
            "day": "2026-09-07", "semantic_body_sha256": semantic_sha,
            "cert_sha256": cert_sha, "issued_at": issued,
            "expires_at": expires, "artifact_sha256": artifact_sha,
            "temp_name": None, "unreferenced_at": None}}}
    (Path(state_dir) / "instructions" / "role-state.json").write_text(
        json.dumps(role_state, sort_keys=True, separators=(",", ":")) + "\n")
    return body, body_bytes, signature, artifact, generation


def _stamp(key, body, body_bytes, generation, *, serial=1, device="device-a",
           part=None):
    del device
    issued, expires = body["issued_at"], body["expires_at"]
    default_part = {
        "peers": {"mode": "tracker-only", "include_origin": False,
                  "allowed_expires_at": expires},
        "qos_override": {}, "control_override": {}, "server_time": issued,
    }
    stamp = {"epoch": issued, "instr_serial": serial, "policy_revision": 1,
             "platform": "guestshell", "role": "default",
             "role_gen": generation,
             "role_body_sha256": hashlib.sha256(body_bytes).hexdigest(),
             "key_id": key["key_id"], "verify_level": "sig",
             "issued_at": issued, "expires_at": expires,
             "degraded": False, "part": part or default_part}
    instructions.validate_stamp(stamp)
    return stamp


def _keylist(state_dir, seq=7, with_state=False):
    signature = (b"-----BEGIN SSH SIGNATURE-----\n"
                 b"test-only\n-----END SSH SIGNATURE-----\n")
    payload = instruction_keys.build_keylist_payload(
        b"", keylist_seq=seq, issued_at=NOW, signer_root_id="root-a")
    artifact = instruction_keys.assemble_keylist_artifact(payload, signature)
    directory = Path(state_dir) / "instructions"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "keylist.current").write_bytes(artifact)
    if with_state:
        parsed = instruction_keys.parse_keylist_artifact(artifact)
        state = {"schema": instruction_keys.KEYLIST_STATE_SCHEMA,
                 "keylist_seq": seq,
                 "artifact_sha256": parsed["artifact_sha256"],
                 "krl_sha256": parsed["metadata"]["krl_sha256"],
                 "issued_at": NOW, "verified_root_id": "root-a",
                 "root_attestations": {}, "updated_at": NOW}
        (directory / "keylist-state.json").write_text(
            json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n")
    return artifact


class _StreamSettings:
    def __init__(self, value=(9, False), failure=None):
        self.value, self.failure, self.reads = value, failure, 0

    def read(self):
        self.reads += 1
        if self.failure:
            raise self.failure
        return self.value


class _Fixture:
    def __init__(self, tmp_path, monkeypatch, *, devices=("device-a",),
                 keylist=True, stream_settings=None, live_table=None):
        self.state = tmp_path / "state"
        self.config = tmp_path / "config"
        self.run = tmp_path / "run"
        self.secrets_path = tmp_path / "secrets.json"
        for name, value in (("IRIS_STATE", self.state),
                            ("IRIS_CONFIG", self.config),
                            ("IRIS_RUN", self.run),
                            ("IRIS_SECRETS", self.secrets_path)):
            monkeypatch.setenv(name, str(value))
        self.store = catalog.CatalogStore(str(self.state))
        self.tokens = {}
        secret_doc = {"devices": {}, "seeder": {}}
        self.body, self.body_bytes, self.signature, self.artifact, generation = \
            _role_material(self.state)
        for index, device_id in enumerate(devices, 1):
            token = ("%02x" % (32 + index)) * 16
            key = _instruction_key(("%02x" % index) * 32)
            self.tokens[device_id] = token
            secret_doc["devices"][device_id] = {
                "catalog_token": _credential(token), "instr_key": key}
            stamp = _stamp(key, self.body, self.body_bytes, generation,
                           device=device_id)
            self.store._policies.put(device_id, {
                "approved_image_id": None, "approved_image_ids": [],
                "plans": {}, "instr": stamp})
        secrets_store.save(secret_doc, str(self.secrets_path))
        self.keylist = _keylist(self.state) if keylist else None
        captured = []
        real_init = catalog.Catalog.__init__

        def capture(instance, *args, **kwargs):
            real_init(instance, *args, **kwargs)
            captured.append(instance)

        monkeypatch.setattr(catalog.Catalog, "__init__", capture)
        self.srv = catalog.make_server(
            "127.0.0.1", 0, self.store, str(self.secrets_path),
            stream_settings=stream_settings, live_table=live_table)
        self.catalog = captured[0]
        self.thread = threading.Thread(target=self.srv.serve_forever,
                                       daemon=True)
        self.thread.start()

    @property
    def port(self):
        return self.srv.server_address[1]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=5)


def _request(fixture, path, *, device="device-a", method="GET", body=None,
             headers=(), token=None):
    conn = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=5)
    conn.putrequest(method, path)
    supplied = list(headers)
    authorization = token if token is not None else fixture.tokens.get(device)
    if authorization is not False:
        conn.putheader("Authorization", "Bearer " + authorization)
    if body is not None:
        body = json.dumps(body).encode()
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(body)))
    for name, value in supplied:
        conn.putheader(name, value)
    conn.endheaders(body)
    response = conn.getresponse()
    result = response.status, response.getheaders(), response.read()
    conn.close()
    return result


def _header(headers, name):
    values = [value for key, value in headers if key.lower() == name.lower()]
    return values[-1] if values else None


def _assert_problem(result, status, code, *, retry=None, authenticate=False):
    actual, headers, body = result
    assert actual == status
    assert _header(headers, "Content-Type") == "application/problem+json"
    assert _header(headers, "Cache-Control") == "no-store"
    assert _header(headers, "Vary") == "Authorization"
    assert _header(headers, "X-Content-Type-Options") == "nosniff"
    transport_date = email.utils.parsedate_to_datetime(
        _header(headers, "Date")).timestamp()
    assert abs(transport_date - time.time()) <= 2
    assert _header(headers, "Retry-After") == retry
    assert (_header(headers, "WWW-Authenticate") == "Bearer") is authenticate
    doc = json.loads(body)
    assert set(doc) == {"type", "title", "status", "code"}
    assert doc["status"] == status and doc["code"] == code
    assert doc["title"] == PROBLEM_TITLES[(status, code)]
    assert doc["type"].endswith("#" + code)


def _instruction_path(device="device-a"):
    return "/v1/devices/%s/instructions" % device


def _keylist_path(device="device-a"):
    return "/v1/devices/%s/instruction-keylist" % device


def test_instruction_pointer_uses_one_row_read_and_only_stored_stamp(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch)
    reads = []
    real = keyed_state.KeyedState._read_shard

    def counted(state, bucket):
        if state.legacy_path == fixture.store.policy_path:
            reads.append(bucket)
        return real(state, bucket)

    monkeypatch.setattr(keyed_state.KeyedState, "_read_shard", counted)
    monkeypatch.setattr(instruction_keys, "read_epoch",
                        lambda *_a, **_k: pytest.fail("pointer read epoch"))
    try:
        status, _, body = _request(
            fixture, "/v1/devices/device-a/policy")
        assert status == 200
        assert json.loads(body)["instr_rev"] == {
            "epoch": NOW, "instr_serial": 1}
        assert len(reads) == 1
    finally:
        fixture.close()


def test_heartbeat_carries_instruction_and_keylist_hints_without_costing_heartbeat(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch, devices=("device-a", "device-b"))
    try:
        status, _, body = _request(
            fixture, "/v1/devices/device-a/heartbeat", method="POST",
            body={"version": "task14"})
        assert status == 200
        assert json.loads(body) == {
            "ok": True, "instr_rev": {"epoch": NOW, "instr_serial": 1},
            "keylist_seq": 7, "stream_every": 3, "stream_pause": False}
        assert fixture.catalog.instruction_counters() == {
            "instr_stamp_missing": 0, "instr_hint_failures": 0,
            "keylist_hint_failures": 0, "instr_cadence_failures": 0}
        copied = fixture.catalog.instruction_counters()
        copied["instr_hint_failures"] = 99
        assert fixture.catalog.instruction_counters()["instr_hint_failures"] == 0
        shard = (Path(keyed_state.shard_dir(fixture.store.policy_path)) /
                 ("%02x.json" % keyed_state.bucket_of("device-b")))
        rows = json.loads(shard.read_text())
        rows["device-b"]["instr"] = {"epoch": 1}
        shard.write_text(json.dumps(rows))
        barrier = threading.Barrier(5)
        results = []

        def malformed_heartbeat(index):
            barrier.wait()
            results.append(_request(
                fixture, "/v1/devices/device-b/heartbeat", device="device-b",
                method="POST", body={"version": "malformed-%d" % index}))

        workers = [threading.Thread(target=malformed_heartbeat, args=(index,))
                   for index in range(4)]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(timeout=5)
        assert all(not worker.is_alive() for worker in workers)
        assert len(results) == 4
        assert all(status == 200 and "instr_rev" not in json.loads(body)
                   for status, _headers, body in results)
        assert fixture.catalog.instruction_counters()["instr_hint_failures"] == 4

        rows = json.loads(shard.read_text())
        rows["device-b"]["instr"] = None
        shard.write_text(json.dumps(rows))
        status, _, body = _request(
            fixture, "/v1/devices/device-b/heartbeat", device="device-b",
            method="POST", body={"version": "null-malformed-hint"})
        assert status == 200 and "instr_rev" not in json.loads(body)
        assert fixture.catalog.instruction_counters()["instr_hint_failures"] == 5

        monkeypatch.setattr(instructions, "MAX_I63", 6)
        status, _, body = _request(
            fixture, "/v1/devices/device-b/heartbeat", device="device-b",
            method="POST", body={"version": "saturating-malformed-hint"})
        assert status == 200 and "instr_rev" not in json.loads(body)
        assert fixture.catalog.instruction_counters()["instr_hint_failures"] == 6
        status, _, body = _request(
            fixture, "/v1/devices/device-b/heartbeat", device="device-b",
            method="POST", body={"version": "saturated-malformed-hint"})
        assert status == 200 and "instr_rev" not in json.loads(body)
        assert fixture.catalog.instruction_counters()["instr_hint_failures"] == \
            instructions.MAX_I63
    finally:
        fixture.close()


def test_instruction_routes_require_current_same_device_bearer(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch, devices=("device-a", "device-b"))
    previous = "55" * 16
    announce = "66" * 16
    rpc = "77" * 16
    service = "88" * 16
    doc = secrets_store.load(str(fixture.secrets_path))
    doc["devices"]["device-a"]["catalog_token_prev"] = _credential(previous)
    doc["devices"]["device-a"]["announce_token"] = _credential(announce)
    doc["devices"]["device-a"]["rpc_secret"] = _credential(rpc)
    doc["seeder"]["announce_token"] = _credential(service)
    secrets_store.save(doc, str(fixture.secrets_path))
    try:
        for path in (_instruction_path(), _keylist_path()):
            _assert_problem(_request(fixture, path, token=False), 401,
                            "catalog-authentication-required", authenticate=True)
            _assert_problem(_request(fixture, path, token="not-current"), 401,
                            "catalog-authentication-required", authenticate=True)
            _assert_problem(_request(fixture, path, token=previous), 401,
                            "catalog-authentication-required", authenticate=True)
            for invalid in (announce, rpc, service,
                            doc["devices"]["device-a"]["instr_key"]["value"]):
                _assert_problem(_request(fixture, path, token=invalid), 401,
                                "catalog-authentication-required",
                                authenticate=True)
            _assert_problem(_request(fixture, path + "?token=" +
                                     fixture.tokens["device-a"], token=False),
                            401, "catalog-authentication-required",
                            authenticate=True)
            _assert_problem(_request(
                fixture, path, token=False,
                headers=(("Authorization", "Basic ZGV2aWNlLWE6dG9r"),)),
                401, "catalog-authentication-required", authenticate=True)
            existing = _request(fixture, path,
                                token=fixture.tokens["device-b"])
            absent_path = path.replace("/device-a/", "/absent/")
            absent = _request(fixture, absent_path,
                              token=fixture.tokens["device-b"])
            _assert_problem(existing, 403, "instruction-device-forbidden")
            _assert_problem(absent, 403, "instruction-device-forbidden")
            assert existing[2] == absent[2]

        # None of the authentication/authorization failures consumed either
        # token; the two successful resources still fit in the shared burst.
        assert _request(fixture, _instruction_path())[0] == 200
        assert _request(fixture, _keylist_path())[0] == 200
        _assert_problem(_request(fixture, _instruction_path()), 429,
                        "instruction-rate-limit-exceeded", retry="10")
        assert _request(fixture, _instruction_path("device-b"),
                        device="device-b")[0] == 200
        assert _request(fixture, _keylist_path("device-b"),
                        device="device-b")[0] == 200
        _assert_problem(_request(fixture, _instruction_path("device-b"),
                                 device="device-b"), 429,
                        "instruction-rate-limit-exceeded", retry="10")
    finally:
        fixture.close()


def test_instruction_route_reconstructs_exact_stable_envelope_and_current_date(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch)
    try:
        before = time.time()
        first = _request(fixture, _instruction_path())
        second = _request(fixture, _instruction_path())
        after = time.time()
        for status, headers, body in (first, second):
            assert status == 200 and len(body) <= instructions.INSTR_RESPONSE_MAX
            assert _header(headers, "Content-Type") == "application/octet-stream"
            assert _header(headers, "Cache-Control") == "private, no-store"
            assert _header(headers, "Vary") == "Authorization"
            assert _header(headers, "X-Content-Type-Options") == "nosniff"
            assert _header(headers, "ETag") == \
                '"sha256-%s"' % hashlib.sha256(body).hexdigest()
            transport_date = email.utils.parsedate_to_datetime(
                _header(headers, "Date")).timestamp()
            assert before - 1 <= transport_date <= after + 1
        assert first[2] == second[2]
        opened = instructions.open_parts(first[2], bytes.fromhex("01" * 32))
        assert opened[0]["server_time"] == NOW
        assert opened[3] == fixture.store._policies.get("device-a")["instr"]["part"]
    finally:
        fixture.close()


def test_instruction_route_same_epoch_serial_isolated_by_device_and_key(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch, devices=("device-a", "device-b"))
    try:
        a = _request(fixture, _instruction_path("device-a"), device="device-a")
        b = _request(fixture, _instruction_path("device-b"), device="device-b")
        assert a[0] == b[0] == 200 and a[2] != b[2]
        assert _header(a[1], "ETag") != _header(b[1], "ETag")
        assert instructions.open_parts(a[2], bytes.fromhex("01" * 32))[0][
            "device_id"] == "device-a"
        assert instructions.open_parts(b[2], bytes.fromhex("02" * 32))[0][
            "device_id"] == "device-b"
    finally:
        fixture.close()


def test_instruction_cache_validates_role_and_complete_stamp_before_hit(
        tmp_path, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(catalog.time, "monotonic", lambda: clock[0])
    fixture = _Fixture(tmp_path, monkeypatch)
    try:
        first = _request(fixture, _instruction_path())
        assert first[0] == 200
        clock[0] += 10
        fixture.store._policies.update("device-a", lambda row: dict(
            row, instr=dict(
                row["instr"], policy_revision=2,
                part=dict(row["instr"]["part"],
                          control_override={"telemetry_every_ticks": 5}))))
        changed = _request(fixture, _instruction_path())
        assert changed[0] == 200 and changed[2] != first[2]
        changed_header, _, _, changed_part = instructions.open_parts(
            changed[2], bytes.fromhex("01" * 32))
        assert changed_header["policy_revision"] == 2
        assert changed_part["control_override"] == {
            "telemetry_every_ticks": 5}
        clock[0] += 10
        fixture.store._policies.update("device-a", lambda row: dict(
            row, instr=dict(row["instr"], role_body_sha256="f" * 64)))
        _assert_problem(_request(fixture, _instruction_path()), 503,
                        "instruction-state-unavailable", retry="10")
    finally:
        fixture.close()


def test_instruction_cache_rejects_signature_only_mutation_cold_and_warm(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch)
    role = next((fixture.state / "instructions" / "roles.d").iterdir())
    try:
        assert _request(fixture, _instruction_path())[0] == 200
        body, _ = instructions.parse_role(role.read_bytes())
        role.write_bytes(instructions.frame_role(
            body, _sshsig(b"mutated-certificate", b"mutated")))
        _assert_problem(_request(fixture, _instruction_path()), 503,
                        "instruction-state-unavailable", retry="10")
        restarted = _Fixture(tmp_path, monkeypatch)
        try:
            restarted_role = next(
                (restarted.state / "instructions" / "roles.d").iterdir())
            restarted_body, _ = instructions.parse_role(
                restarted_role.read_bytes())
            restarted_role.write_bytes(instructions.frame_role(
                restarted_body,
                _sshsig(b"mutated-certificate", b"mutated")))
            _assert_problem(_request(restarted, _instruction_path()), 503,
                            "instruction-state-unavailable", retry="10")
        finally:
            restarted.close()
    finally:
        fixture.close()


def test_instruction_cache_entry_and_byte_bounds_evict_lru(
        tmp_path, monkeypatch):
    assert catalog.INSTR_CACHE_MAX_ENTRIES == 256
    assert catalog.INSTR_CACHE_MAX_BYTES == 16 * 1024 * 1024
    real_seal = instructions.seal_parts
    seals = []

    def counted_seal(*args, **kwargs):
        result = real_seal(*args, **kwargs)
        seals.append(hashlib.sha256(result).hexdigest())
        return result

    monkeypatch.setattr(instructions, "seal_parts", counted_seal)
    monkeypatch.setattr(catalog, "INSTR_CACHE_MAX_ENTRIES", 2)
    monkeypatch.setattr(catalog, "INSTR_CACHE_MAX_BYTES", 16 * 1024 * 1024)
    fixture = _Fixture(tmp_path / "entries", monkeypatch,
                       devices=("device-a", "device-b", "device-c"))
    try:
        assert _request(fixture, _instruction_path("device-a"),
                        device="device-a")[0] == 200
        assert _request(fixture, _instruction_path("device-b"),
                        device="device-b")[0] == 200
        assert _request(fixture, _instruction_path("device-a"),
                        device="device-a")[0] == 200  # refresh A's LRU age
        assert len(seals) == 2
        assert _request(fixture, _instruction_path("device-c"),
                        device="device-c")[0] == 200
        assert _request(fixture, _instruction_path("device-b"),
                        device="device-b")[0] == 200
        assert len(seals) == 4  # C evicted B, the least-recently-used entry.
    finally:
        fixture.close()

    monkeypatch.setattr(catalog, "INSTR_CACHE_MAX_ENTRIES", 256)
    monkeypatch.setattr(catalog, "INSTR_CACHE_MAX_BYTES", 1)
    fixture = _Fixture(tmp_path / "bytes", monkeypatch)
    before = len(seals)
    try:
        assert _request(fixture, _instruction_path())[0] == 200
        assert _request(fixture, _instruction_path())[0] == 200
        assert len(seals) == before + 2  # neither oversize entry was retained.
    finally:
        fixture.close()


def test_instruction_route_current_and_live_previous_key_eligibility(
        tmp_path, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(catalog.time, "monotonic", lambda: clock[0])
    fixture = _Fixture(tmp_path, monkeypatch)
    previous = _instruction_key("09" * 32, created=NOW - 1000,
                                expires=NOW + 30)
    doc = secrets_store.load(str(fixture.secrets_path))
    current = _instruction_key(
        "01" * 32, created=NOW - secrets_store.INSTR_KEY_TTL - 1)
    doc["devices"]["device-a"]["instr_key"] = current
    doc["devices"]["device-a"]["instr_key_prev"] = previous
    secrets_store.save(doc, str(fixture.secrets_path))
    try:
        monkeypatch.setattr(catalog.time, "time", lambda: NOW)
        # Current expiry is a rotation trigger and does not invalidate sealing.
        assert _request(fixture, _instruction_path())[0] == 200
        clock[0] += 10
        fixture.store._policies.update("device-a", lambda row: dict(
            row, instr=dict(row["instr"], key_id=previous["key_id"])))
        status, _, body = _request(fixture, _instruction_path())
        assert status == 200
        assert instructions.open_parts(body, bytes.fromhex(previous["value"]))
        doc = secrets_store.load(str(fixture.secrets_path))
        doc["devices"]["device-a"]["instr_key_prev"]["expires_at"] = NOW
        secrets_store.save(doc, str(fixture.secrets_path))
        clock[0] += 10
        _assert_problem(_request(fixture, _instruction_path()), 409,
                        "stale_pointer", retry="10")
    finally:
        fixture.close()


def test_instruction_route_revocation_wins_locked_seal_race(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path / "revocation-first", monkeypatch)
    result = []
    try:
        with secrets_store.store_lock(str(fixture.secrets_path)):
            doc = secrets_store.load(str(fixture.secrets_path))
            doc["devices"]["device-a"]["instr_key"]["revoked"] = True
            secrets_store.save(doc, str(fixture.secrets_path))
            worker = threading.Thread(
                target=lambda: result.append(_request(
                    fixture, _instruction_path())))
            worker.start()
            time.sleep(0.1)
            assert worker.is_alive()
        worker.join(timeout=5)
        assert not worker.is_alive()
        _assert_problem(result[0], 409, "stale_pointer", retry="10")
    finally:
        fixture.close()

    # The opposite ordering is equally explicit: once the real request has
    # entered deterministic sealing, the competing revoker cannot acquire the
    # same store lock until the complete envelope has its linearization point.
    fixture = _Fixture(tmp_path / "seal-first", monkeypatch)
    real_seal = instructions.seal_parts
    entered, release, revoked = (threading.Event(), threading.Event(),
                                 threading.Event())
    result = []

    def gated_seal(*args, **kwargs):
        entered.set()
        assert release.wait(timeout=5)
        return real_seal(*args, **kwargs)

    def revoke():
        with secrets_store.store_lock(str(fixture.secrets_path)):
            doc = secrets_store.load(str(fixture.secrets_path))
            doc["devices"]["device-a"]["instr_key"]["revoked"] = True
            secrets_store.save(doc, str(fixture.secrets_path))
        revoked.set()

    monkeypatch.setattr(instructions, "seal_parts", gated_seal)
    request = threading.Thread(target=lambda: result.append(
        _request(fixture, _instruction_path())))
    revoker = threading.Thread(target=revoke)
    try:
        request.start()
        assert entered.wait(timeout=5)
        revoker.start()
        assert not revoked.wait(timeout=0.1)
        release.set()
        request.join(timeout=5)
        revoker.join(timeout=5)
        assert not request.is_alive() and not revoker.is_alive()
        assert result[0][0] == 200 and revoked.is_set()
        assert instructions.open_parts(
            result[0][2], bytes.fromhex("01" * 32))[0]["device_id"] == \
            "device-a"
    finally:
        release.set()
        if request.ident is not None:
            request.join(timeout=5)
        if revoker.ident is not None:
            revoker.join(timeout=5)
        fixture.close()


def test_instruction_route_missing_stamp_or_named_body_is_counted_404(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch, devices=("device-a", "device-b"))
    fixture.store._policies.update("device-a", lambda row: {
        key: value for key, value in row.items() if key != "instr"})
    role = next((fixture.state / "instructions" / "roles.d").iterdir())
    role.unlink()
    try:
        for _ in range(2):
            _assert_problem(_request(
                fixture, _instruction_path("device-a")), 404,
                "instruction-stamp-missing")
        _assert_problem(_request(fixture, _instruction_path("device-a")), 429,
                        "instruction-rate-limit-exceeded", retry="10")
        for _ in range(2):
            _assert_problem(_request(
                fixture, _instruction_path("device-b"), device="device-b"),
                404, "instruction-stamp-missing")
        _assert_problem(_request(fixture, _instruction_path("device-b"),
                                 device="device-b"), 429,
                        "instruction-rate-limit-exceeded", retry="10")
        assert fixture.catalog.instruction_counters()["instr_stamp_missing"] == 4
    finally:
        fixture.close()


def test_instruction_route_stale_pointer_and_unavailable_problem_contracts(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch, devices=("device-a", "device-b"))
    fixture.store._policies.update("device-a", lambda row: dict(
        row, instr=dict(row["instr"], key_id="f" * 64)))
    state = fixture.state / "instructions" / "role-state.json"
    try:
        for _ in range(2):
            _assert_problem(_request(fixture, _instruction_path()), 409,
                            "stale_pointer", retry="10")
        _assert_problem(_request(fixture, _instruction_path()), 429,
                        "instruction-rate-limit-exceeded", retry="10")
        state.write_text("{}")
        for _ in range(2):
            _assert_problem(_request(fixture, _instruction_path("device-b"),
                                     device="device-b"), 503,
                            "instruction-state-unavailable", retry="10")
        _assert_problem(_request(fixture, _instruction_path("device-b"),
                                 device="device-b"), 429,
                        "instruction-rate-limit-exceeded", retry="10")
    finally:
        fixture.close()


def test_instruction_route_final_response_cap_before_headers(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(instructions, "seal_parts",
                        lambda *_a, **_k: b"x" *
                        (instructions.INSTR_RESPONSE_MAX + 1))
    try:
        _assert_problem(_request(fixture, _instruction_path()), 503,
                        "instruction-state-unavailable", retry="10")
    finally:
        fixture.close()


def test_instruction_routes_shared_limiter_concurrency_and_device_isolation(
        tmp_path, monkeypatch):
    assert catalog.INSTR_REQUEST_BURST == 2
    assert catalog.INSTR_REQUEST_REFILL_SECONDS == 10
    assert catalog.INSTR_LIMITER_MAX_DEVICES == 20_000
    assert catalog.INSTR_LIMITER_IDLE_SECONDS == 20
    fixture = _Fixture(tmp_path / "concurrency", monkeypatch,
                       devices=("device-a", "device-b"))
    barrier = threading.Barrier(4)
    results = []

    def request(path, device):
        barrier.wait()
        results.append((device, _request(fixture, path, device=device)))

    workers = [threading.Thread(target=request, args=(
        _instruction_path(), "device-a")),
        threading.Thread(target=request, args=(_keylist_path(), "device-a")),
        threading.Thread(target=request, args=(_instruction_path(), "device-a"))]
    try:
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(timeout=5)
        a_statuses = sorted(result[1][0] for result in results)
        assert a_statuses == [200, 200, 429]
        assert _request(fixture, _instruction_path("device-b"),
                        device="device-b")[0] == 200
    finally:
        fixture.close()

    # Fractional refill is retained, and Retry-After is computed by ceiling
    # from the live balance rather than returning a fixed interval.
    clock = [100.0]
    monkeypatch.setattr(catalog.time, "monotonic", lambda: clock[0])
    fixture = _Fixture(tmp_path / "fractional", monkeypatch)
    try:
        assert _request(fixture, _instruction_path())[0] == 200
        assert _request(fixture, _keylist_path())[0] == 200
        clock[0] = 102.5
        _assert_problem(_request(fixture, _instruction_path()), 429,
                        "instruction-rate-limit-exceeded", retry="8")
        clock[0] = 110.0
        assert _request(fixture, _instruction_path())[0] == 200
    finally:
        fixture.close()

    # A caller that entered first must sample the clock only after it owns the
    # bucket lock.  Otherwise its stale timestamp can overwrite a newer
    # caller's last-seen value and grant an early refill.
    clock_entered = threading.Event()
    newer_sampled = threading.Event()
    second_request_completed = threading.Event()
    release_clock = threading.Event()
    race_results = []
    calls = [0]
    calls_lock = threading.Lock()

    def racing_clock():
        with calls_lock:
            calls[0] += 1
            call = calls[0]
        if call == 1:
            clock_entered.set()
            assert release_clock.wait(5)
            return 100.0
        newer_sampled.set()
        return 105.0

    # Fill and exhaust the public shared bucket before installing the gated
    # clock used by the two racing requests.
    monkeypatch.setattr(catalog.time, "monotonic", lambda: 100.0)
    fixture = _Fixture(tmp_path / "clock-lock", monkeypatch)
    try:
        assert _request(fixture, _instruction_path())[0] == 200
        assert _request(fixture, _keylist_path())[0] == 200
        monkeypatch.setattr(catalog.time, "monotonic", racing_clock)

        first = threading.Thread(target=lambda: race_results.append(
            _request(fixture, _instruction_path())))
        def second_request():
            try:
                race_results.append(_request(fixture, _keylist_path()))
            finally:
                second_request_completed.set()

        second = threading.Thread(target=second_request)
        first.start()
        assert clock_entered.wait(5)
        second.start()
        # On the faulty implementation the second request runs around the
        # first while its clock call is parked.  The release is unconditional
        # so the fixed implementation, where the first holds the lock, cannot
        # deadlock this test.
        if newer_sampled.wait(1):
            assert second_request_completed.wait(5)
        release_clock.set()
        first.join(timeout=5)
        second.join(timeout=5)
        assert not first.is_alive() and not second.is_alive()
        assert len(race_results) == 2
        assert all(result[0] == 429 for result in race_results)
        _assert_problem(_request(fixture, _instruction_path()), 429,
                        "instruction-rate-limit-exceeded", retry="5")
    finally:
        release_clock.set()
        fixture.close()

    monkeypatch.setattr(catalog.time, "monotonic", lambda: clock[0])
    # Tight test-only limits make pruning and bounded LRU behavior visible at
    # the HTTP surface; each value is frozen before Catalog construction.
    monkeypatch.setattr(catalog, "INSTR_LIMITER_IDLE_SECONDS", 2)
    clock[0] = 200.0
    fixture = _Fixture(tmp_path / "idle", monkeypatch)
    try:
        assert _request(fixture, _instruction_path())[0] == 200
        assert _request(fixture, _keylist_path())[0] == 200
        clock[0] = 203.0
        assert _request(fixture, _instruction_path())[0] == 200
        assert _request(fixture, _keylist_path())[0] == 200
    finally:
        fixture.close()

    monkeypatch.setattr(catalog, "INSTR_LIMITER_IDLE_SECONDS", 1_000)
    monkeypatch.setattr(catalog, "INSTR_LIMITER_MAX_DEVICES", 2)
    clock[0] = 300.0
    fixture = _Fixture(tmp_path / "bounded", monkeypatch,
                       devices=("device-a", "device-b", "device-c"))
    try:
        assert _request(fixture, _instruction_path("device-a"),
                        device="device-a")[0] == 200
        assert _request(fixture, _instruction_path("device-b"),
                        device="device-b")[0] == 200
        assert _request(fixture, _keylist_path("device-a"),
                        device="device-a")[0] == 200  # A is newest.
        assert _request(fixture, _instruction_path("device-c"),
                        device="device-c")[0] == 200  # evicts B.
        assert _request(fixture, _instruction_path("device-b"),
                        device="device-b")[0] == 200
        assert _request(fixture, _keylist_path("device-b"),
                        device="device-b")[0] == 200
    finally:
        fixture.close()


def test_instruction_routes_charge_304_and_reset_limiter_on_restart(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch)
    try:
        first = _request(fixture, _instruction_path())
        assert first[0] == 200
        etag = _header(first[1], "ETag")
        assert _request(fixture, _keylist_path(), headers=(
            ("If-None-Match", '*'),))[0] == 304
        limited = _request(fixture, _instruction_path(), headers=(
            ("If-None-Match", etag),))
        _assert_problem(limited, 429, "instruction-rate-limit-exceeded",
                        retry="10")
    finally:
        fixture.close()
    restarted = _Fixture(tmp_path, monkeypatch)
    try:
        repeated = _request(restarted, _instruction_path())
        assert repeated[0] == 200 and repeated[2] == first[2]
        assert _header(repeated[1], "ETag") == _header(first[1], "ETag")
    finally:
        restarted.close()


def test_instruction_routes_if_none_match_semantics_date_and_no_body_contract(
        tmp_path, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(catalog.time, "monotonic", lambda: clock[0])
    fixture = _Fixture(tmp_path, monkeypatch)
    try:
        first = _request(fixture, _instruction_path())
        assert first[0] == 200
        etag = _header(first[1], "ETag")
        assert etag is not None
        cases = [(("If-None-Match", "W/" + etag), 304),
                 (("If-None-Match", '"other", ' + etag), 304),
                 (("If-None-Match", '"opaque,tag", ' + etag), 304),
                 (("If-None-Match", '"other",, ' + etag), 304),
                 (("If-None-Match", ',, "other", ' + etag + ',,'), 304),
                 (("If-None-Match", ",".join(
                     ['"other-%d"' % index for index in range(65)]
                     + [etag])), 304),
                 (("If-None-Match", "*"), 304),
                 (("If-None-Match", etag[:-1]), 200),
                 (("If-None-Match", "bogus, " + etag), 200),
                 (("If-None-Match", "*, " + etag), 200),
                 (("If-None-Match", "," * 65 + etag), 200),
                 (("If-None-Match", '"bad tag", ' + etag), 200),
                 (("If-None-Match", '"bad\x7f", ' + etag), 200)]
        for (name, value), expected in cases:
            clock[0] += 10
            before = time.time()
            status, headers, body = _request(
                fixture, _instruction_path(), headers=((name, value),))
            after = time.time()
            assert status == expected
            if expected == 304:
                assert body == b""
                assert _header(headers, "ETag") == etag
                assert _header(headers, "Cache-Control") == \
                    "private, no-store"
                assert _header(headers, "Vary") == "Authorization"
                assert _header(headers, "X-Content-Type-Options") == "nosniff"
                assert _header(headers, "Content-Type") is None
                assert _header(headers, "Content-Length") is None
                transport_date = email.utils.parsedate_to_datetime(
                    _header(headers, "Date")).timestamp()
                assert before - 1 <= transport_date <= after + 1
        clock[0] += 10
        status, _, _ = _request(fixture, _instruction_path(), headers=(
            ("If-None-Match", ""), ("If-None-Match", '"other"'),
            ("If-None-Match", "W/" + etag)))
        assert status == 304
    finally:
        fixture.close()


def test_instruction_keylist_serves_exact_installed_artifact_and_304(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch)
    try:
        first_before = time.time()
        first = _request(fixture, _keylist_path())
        first_after = time.time()
        assert first[0] == 200 and first[2] == fixture.keylist
        assert _header(first[1], "Content-Type") == "application/octet-stream"
        assert _header(first[1], "Cache-Control") == "private, no-store"
        assert _header(first[1], "Vary") == "Authorization"
        assert _header(first[1], "X-Content-Type-Options") == "nosniff"
        assert _header(first[1], "ETag") == \
            '"sha256-%s"' % hashlib.sha256(fixture.keylist).hexdigest()
        first_date = email.utils.parsedate_to_datetime(
            _header(first[1], "Date")).timestamp()
        assert first_before - 1 <= first_date <= first_after + 1
        conditional_before = time.time()
        status, headers, body = _request(fixture, _keylist_path(), headers=(
            ("If-None-Match", _header(first[1], "ETag")),))
        conditional_after = time.time()
        assert status == 304 and body == b""
        assert _header(headers, "ETag") == _header(first[1], "ETag")
        assert _header(headers, "Cache-Control") == "private, no-store"
        assert _header(headers, "Vary") == "Authorization"
        assert _header(headers, "X-Content-Type-Options") == "nosniff"
        assert _header(headers, "Content-Type") is None
        assert _header(headers, "Content-Length") is None
        conditional_date = email.utils.parsedate_to_datetime(
            _header(headers, "Date")).timestamp()
        assert conditional_before - 1 <= conditional_date <= \
            conditional_after + 1
    finally:
        fixture.close()


def test_instruction_keylist_uninitialized_lost_corrupt_and_oversize_contracts(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch, devices=(
        "device-a", "device-b", "device-c", "device-d"), keylist=False)
    directory = fixture.state / "instructions"
    state_path, artifact_path = (directory / "keylist-state.json",
                                 directory / "keylist.current")
    try:
        for _ in range(2):
            _assert_problem(_request(
                fixture, _keylist_path("device-a")), 404,
                "instruction-keylist-missing")
        _assert_problem(_request(fixture, _keylist_path("device-a")), 429,
                        "instruction-rate-limit-exceeded", retry="10")
        state_path.write_text("{}")
        for _ in range(2):
            _assert_problem(_request(fixture, _keylist_path("device-b"),
                                     device="device-b"), 503,
                            "instruction-keylist-unavailable", retry="10")
        _assert_problem(_request(fixture, _keylist_path("device-b"),
                                 device="device-b"), 429,
                        "instruction-rate-limit-exceeded", retry="10")
        state_path.unlink()
        artifact_path.write_bytes(b"not-a-keylist")
        for _ in range(2):
            _assert_problem(_request(fixture, _keylist_path("device-c"),
                                     device="device-c"), 503,
                            "instruction-keylist-unavailable", retry="10")
        _assert_problem(_request(fixture, _keylist_path("device-c"),
                                 device="device-c"), 429,
                        "instruction-rate-limit-exceeded", retry="10")
        artifact_path.write_bytes(b"x" * (instruction_keys.MAX_KEYLIST_BYTES + 1))
        for _ in range(2):
            _assert_problem(_request(fixture, _keylist_path("device-d"),
                                     device="device-d"), 503,
                            "instruction-keylist-unavailable", retry="10")
        _assert_problem(_request(fixture, _keylist_path("device-d"),
                                 device="device-d"), 429,
                        "instruction-rate-limit-exceeded", retry="10")
    finally:
        fixture.close()


def test_keylist_hint_is_monotonic_artifact_sequence_and_failure_isolated(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch, devices=(
        "device-a", "device-b", "device-c"))
    try:
        first = _request(fixture, "/v1/devices/device-a/policy")
        assert json.loads(first[2])["keylist_seq"] == 7
        _keylist(fixture.state, seq=8)
        second = _request(fixture, "/v1/devices/device-b/policy",
                          device="device-b")
        assert json.loads(second[2])["keylist_seq"] == 8
        (fixture.state / "instructions" / "keylist.current").write_bytes(b"bad")
        status, _, body = _request(
            fixture, "/v1/devices/device-c/heartbeat", device="device-c",
            method="POST", body={"version": "still-accepted"})
        assert status == 200 and "keylist_seq" not in json.loads(body)
        assert fixture.catalog.instruction_counters()["keylist_hint_failures"] == 1
    finally:
        fixture.close()


def test_instruction_routes_dispatch_before_assignment_and_preserve_auth_grace(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch, devices=("device-a", "device-b"))
    shard = (Path(keyed_state.shard_dir(fixture.store.policy_path)) /
             ("%02x.json" % keyed_state.bucket_of("device-a")))
    Path(shard).write_text("not json")
    try:
        assert _request(fixture, _keylist_path())[0] == 200
        doc = secrets_store.load(str(fixture.secrets_path))
        doc["devices"]["device-b"]["catalog_token"]["expires_at"] = NOW
        secrets_store.save(doc, str(fixture.secrets_path))
        monkeypatch.setattr(catalog.time, "time", lambda: NOW + 299.999)
        assert _request(fixture, _keylist_path("device-b"),
                        device="device-b")[0] == 200
        monkeypatch.setattr(catalog.time, "time", lambda: NOW + 300)
        _assert_problem(_request(fixture, _instruction_path("device-b"),
                                 device="device-b"), 401,
                        "catalog-authentication-required", authenticate=True)
    finally:
        fixture.close()


def test_instruction_routes_credential_store_failure_contract(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch, devices=("device-a", "device-b"))
    fixture.secrets_path.write_text("not json")
    try:
        for path, device in ((_instruction_path(), "device-a"),
                             (_keylist_path("device-b"), "device-b")):
            _assert_problem(_request(fixture, path, device=device), 503,
                            "credential-store-unavailable", retry="10")
    finally:
        fixture.close()


def test_instruction_routes_malformed_bearer_precedes_corrupt_store(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch)
    fixture.secrets_path.write_text("not json")
    try:
        for path in (_instruction_path(), _keylist_path()):
            for headers in ((), (("Authorization", "Basic nope"),),
                            (("Authorization", "Bearer too many words"),)):
                result = _request(fixture, path, token=False, headers=headers)
                _assert_problem(result, 401, "catalog-authentication-required",
                                authenticate=True)
    finally:
        fixture.close()


def test_heartbeat_instruction_attestation_closed_schema_and_dependencies(
        tmp_path, monkeypatch):
    fixture = _Fixture(tmp_path, monkeypatch, devices=("device-a", "device-b"))
    applied = {name: index for index, name in enumerate(
        instructions.APPLIED_FIELDS, 1)}
    try:
        valid = {"instr_state": "key_rejected", "instr_reason": "bad_mac",
                 "instr_serial": 1, "verify_level": "sig", "applied": applied,
                 "blocklist_rules": 2, "blocklist_revision": 3}
        assert _request(fixture, "/v1/devices/device-a/heartbeat",
                        method="POST", body=valid)[0] == 200
        stored = fixture.store.get_device("device-a")
        for key, value in valid.items():
            assert stored[key] == value
        invalid = dict(valid, instr_state="applied", instr_reason="bad_mac",
                       applied=dict(applied, unexpected=1),
                       blocklist_revision=None, role="secret-role", gid="gid")
        assert _request(fixture, "/v1/devices/device-b/heartbeat",
                        device="device-b", method="POST", body=invalid)[0] == 200
        stored = fixture.store.get_device("device-b")
        assert not ({"instr_state", "instr_reason", "applied",
                     "blocklist_rules", "blocklist_revision", "role", "gid"}
                    & set(stored))
    finally:
        fixture.close()


def test_heartbeat_resolves_one_cadence_for_storage_retention_and_response(
        tmp_path, monkeypatch):
    settings, live = _StreamSettings(), live_samples.LiveTable()
    fixture = _Fixture(tmp_path, monkeypatch, devices=("device-a", "device-b"),
                       stream_settings=settings, live_table=live)
    sample = {"v": 2, "obs_state": "observed", "observed_at": NOW,
              "sample_seq": 1, "sampling_class": "good", "image_id": "img1",
              "aria": {"status": "active", "completed_content_bytes": 1,
                       "total_content_bytes": 2, "receive_bps": 3,
                       "send_bps": 4, "connections": 0},
              "peer_connections": []}
    for device_id in ("device-a", "device-b"):
        fixture.store._policies.update(device_id, lambda row: dict(
            row, approved_image_id="img1", approved_image_ids=["img1"]))
    fixture.store._policies.update("device-a", lambda row: dict(
        row, instr=dict(row["instr"], part=dict(
            row["instr"]["part"],
            control_override={"telemetry_every_ticks": 2}))))
    try:
        status, _, body = _request(
            fixture, "/v1/devices/device-a/heartbeat", method="POST",
            body={"telemetry_enabled": True,
                  "telemetry_stream_enabled": True,
                  "telemetry_observation": sample})
        assert status == 200
        response = json.loads(body)
        assert response["stream_every"] == 2
        assert response["stream_pause"] is False and settings.reads == 0
        stored = live.snapshot(time.time())["samples"]["device-a"]
        assert stored["retention_seconds"] == 360 and stored["valid"] is True

        withdrawn = dict(sample, sample_seq=2)
        status, _, body = _request(
            fixture, "/v1/devices/device-a/heartbeat", method="POST",
            body={"telemetry_enabled": True,
                  "telemetry_stream_enabled": False,
                  "telemetry_observation": withdrawn})
        response = json.loads(body)
        assert status == 200 and response["stream_every"] == 2
        assert response["stream_pause"] is False and settings.reads == 0
        stored = live.snapshot(time.time())["samples"]["device-a"]
        assert stored["retention_seconds"] == 360
        assert stored["valid"] is False and stored["obs_state"] == "paused"

        next((fixture.state / "instructions" / "roles.d").iterdir()).unlink()
        settings.failure = RuntimeError("test-only cadence read failure")
        status, _, body = _request(
            fixture, "/v1/devices/device-b/heartbeat", device="device-b",
            method="POST", body={"telemetry_enabled": True,
                                 "telemetry_stream_enabled": True,
                                 "telemetry_observation": sample})
        response = json.loads(body)
        assert status == 200 and response["stream_every"] == 1
        assert response["stream_pause"] is False
        assert response["instr_rev"] == {"epoch": NOW, "instr_serial": 1}
        assert settings.reads == 1
        stored = live.snapshot(time.time())["samples"]["device-b"]
        assert stored["retention_seconds"] == 180 and stored["valid"] is True
        assert fixture.catalog.instruction_counters()["instr_cadence_failures"] == 1
    finally:
        fixture.close()


class _BootstrapStamperError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _bootstrap_catalog(outcomes, timeline):
    """Build the narrow Catalog seam used by the fire-time producer tests."""
    instance = object.__new__(catalog.Catalog)
    instance.store = object()

    class FakeStamper:
        def __init__(self, *, paths, catalog_store):
            assert paths == "paths"
            assert catalog_store is instance.store

        def stamp_device(self, device_id):
            timeline.append(("stamp", device_id))
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

    module = type("FakeStamperModule", (), {
        "InstructionStamper": FakeStamper,
        "StamperError": _BootstrapStamperError,
    })
    instance._stamper_paths = lambda: (module, "paths")
    return instance


def test_bootstrap_materializer_stamps_then_reuses_catalog_envelope():
    timeline = []
    instance = _bootstrap_catalog(["updated"], timeline)

    def resource(device_id, kind):
        timeline.append(("resource", device_id, kind))
        return catalog._InstructionResult(200, body=b"sealed-ciphertext")

    instance._instruction_resource = resource

    assert instance.materialize_bootstrap_instruction("device-a") == \
        b"sealed-ciphertext"
    assert timeline == [
        ("stamp", "device-a"),
        ("resource", "device-a", "instructions"),
    ]


@pytest.mark.parametrize("retry_at", ("stamp", "resource"))
def test_bootstrap_materializer_retries_one_key_supersession(retry_at):
    timeline = []
    outcomes = ([_BootstrapStamperError("key_superseded"), "updated"]
                if retry_at == "stamp" else ["updated", "unchanged"])
    instance = _bootstrap_catalog(outcomes, timeline)
    resources = [
        catalog._InstructionResult(409, body=b"must-not-escape"),
        catalog._InstructionResult(200, body=b"fresh-envelope"),
    ] if retry_at == "resource" else [
        catalog._InstructionResult(200, body=b"fresh-envelope")]

    def resource(device_id, kind):
        timeline.append(("resource", device_id, kind))
        return resources.pop(0)

    instance._instruction_resource = resource

    assert instance.materialize_bootstrap_instruction("device-a") == \
        b"fresh-envelope"
    assert [event[0] for event in timeline].count("stamp") == 2


@pytest.mark.parametrize("result", (
    catalog._InstructionResult(503, body=b"private-response"),
    catalog._InstructionResult(200, body=None),
    catalog._InstructionResult(200, body=b""),
    catalog._InstructionResult(
        200, body=b"x" * (instructions.INSTR_RESPONSE_MAX + 1)),
))
def test_bootstrap_materializer_fails_with_one_fixed_public_error(result):
    instance = _bootstrap_catalog(["updated"], [])
    instance._instruction_resource = lambda *_args: result

    with pytest.raises(
            catalog.InstructionBootstrapUnavailable,
            match=r"^instruction bootstrap unavailable$") as raised:
        instance.materialize_bootstrap_instruction("device-a")
    assert "private-response" not in str(raised.value)


def test_direct_bootstrap_cli_writes_only_private_ciphertext(
        tmp_path, monkeypatch, capsys):
    cli_path = Path(__file__).resolve().parents[1] / \
        "iris-instruction-bootstrap"
    assert cli_path.is_file()
    loader = importlib.machinery.SourceFileLoader(
        "iris_instruction_bootstrap_test", str(cli_path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)

    store = object()
    monkeypatch.setattr(module.catalog, "CatalogStore", lambda _state: store)

    class Producer:
        def __init__(self, actual_store, secrets_path):
            assert actual_store is store
            assert secrets_path == "/private/secrets.json"

        def materialize_bootstrap_instruction(self, device_id):
            assert device_id == "device-a"
            return b"sealed-bootstrap"

    monkeypatch.setattr(module.catalog, "Catalog", Producer)
    monkeypatch.setenv("IRIS_STATE", str(tmp_path / "state"))
    monkeypatch.setenv("IRIS_SECRETS", "/private/secrets.json")
    output = tmp_path / "bootstrap.envelope"
    output.write_bytes(b"old")
    output.chmod(0o644)

    assert module.main(["device-a", "--output", str(output)]) == 0
    assert output.read_bytes() == b"sealed-bootstrap"
    assert output.stat().st_mode & 0o777 == 0o600
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
