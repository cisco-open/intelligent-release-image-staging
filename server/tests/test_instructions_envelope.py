# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Frozen byte and closed-schema contracts for Task 13 instructions."""

import base64
import copy
import hashlib
import hmac
import json
import os
import struct
import subprocess
import sys

import pytest

import instructions


KEY = bytes(range(32))
KEY_ID = hashlib.sha256(KEY).hexdigest()
QOS = {
    "max_peers": 10, "seed_up_bps": 0, "seed_down_bps": 0,
    "leech_up_bps": 0, "leech_down_bps": 0, "overall_up_bps": 0,
    "overall_down_bps": 0, "max_concurrent": 100,
    "request_peer_speed_limit_bps": 51200,
}
CONTROL = {"catalog_tick_s": 60, "telemetry_every_ticks": 1,
           "telemetry_pause": False}


def _role():
    body = {"v": 1, "role": "default", "restricted": False,
            "role_gen": "a" * 64, "issued_at": 100, "expires_at": 700,
            "server_time": 100, "qos": dict(QOS), "control": dict(CONTROL),
            "on_stale": "defaults"}
    return instructions.canonical_json(body)


def _part(payload=None):
    value = {"peers": {"mode": "tracker-only", "include_origin": False,
                       "allowed_expires_at": 700},
             "qos_override": {}, "control_override": {}, "server_time": 100}
    if payload is not None:
        value["qos_override"]["overall_down_bps"] = payload
    return value


def _header(part=None):
    part = _part() if part is None else part
    return {"v": 1, "device_id": "device-1", "platform": "guestshell",
            "epoch": 99, "instr_serial": 7, "policy_revision": 3,
            "issued_at": 100, "expires_at": 700, "server_time": 100,
            "verify_level": "sig", "key_id": KEY_ID, "role": "default",
            "role_gen": "a" * 64,
            "role_body_sha256": hashlib.sha256(_role()).hexdigest(),
            "ct_len": len(instructions.canonical_json(part)),
            "allowed_expires_at": part["peers"]["allowed_expires_at"],
            "degraded": False}


def _reference_pae(parts):
    return (struct.pack("<Q", len(parts)) + b"".join(
        struct.pack("<Q", len(part)) + part for part in parts))


def _reference_kdf(key, label, context, length):
    blocks = []
    for counter in range(1, (length + 31) // 32 + 1):
        fixed = (struct.pack(">I", counter) + label + b"\0" + context
                 + struct.pack(">I", length * 8))
        blocks.append(hmac.new(key, fixed, hashlib.sha256).digest())
    return b"".join(blocks)[:length]


def _reference_crypt(key, nonce, plaintext):
    stream = b"".join(hmac.new(
        key, nonce + struct.pack(">I", counter), hashlib.sha256).digest()
        for counter in range(1, (len(plaintext) + 31) // 32 + 1))
    return bytes(left ^ right for left, right in zip(plaintext, stream))


def test_pae_vector_and_ambiguous_text_contexts_are_distinct():
    expected = "0300000000000000010000000000000061020000000000000062630000000000000000"
    assert _reference_pae((b"a", b"bc", b"" )).hex() == expected
    assert instructions.pae(b"a", b"bc", b"").hex() == expected
    assert instructions.pae(b"a", b"bc") != instructions.pae(b"ab", b"c")
    with pytest.raises(instructions.InstructionError):
        instructions.pae("not-bytes")


def test_sp800_108_vector_domain_separation_and_bounds():
    context = _reference_pae((b"device-1", KEY_ID.encode("ascii")))
    reference = _reference_kdf(KEY, b"iris-instr-v1", context, 96)
    assert reference.hex() == (
        "f6465d3fcf8512a65f6fa9d66add6f55e1b1cc26d5a35a89507546551970e075"
        "b46f089a15073c4bff5879d84c0679ca36eabf7c8df56dd4f359668a6df17362"
        "6e8ce852b9b63c7b31b41f7d4599fa53533eb70ac3c24b23555515cea382d839")
    assert instructions.sp800_108(
        KEY, b"iris-instr-v1", context, 96) == reference
    assert instructions.sp800_108(
        KEY, b"iris-lkg-v1", context, 32) != reference[:32]
    for length in (0, -1, True, 1.0, 97):
        with pytest.raises(instructions.InstructionError):
            instructions.sp800_108(KEY, b"x", b"", length)


@pytest.mark.parametrize("plaintext", [b"", b"partial", bytes(range(97))],
                         ids=["empty", "partial-block", "multi-block"])
def test_stream_encryption_independent_vectors(plaintext):
    context = _reference_pae((b"device-1", KEY_ID.encode("ascii")))
    material = _reference_kdf(KEY, b"iris-instr-v1", context, 96)
    nonce_context = _reference_pae((
        b"device-1", KEY_ID.encode("ascii"), struct.pack(">Q", 99),
        struct.pack(">Q", 7)))
    nonce = _reference_kdf(
        material[64:], b"iris-instr-nonce-v1", nonce_context, 16)
    assert instructions.derive_keys(KEY, "device-1", KEY_ID) == (
        material[:32], material[32:64], material[64:])
    assert instructions.derive_nonce(
        material[64:], "device-1", KEY_ID, 99, 7) == nonce
    assert instructions.crypt(material[:32], nonce, plaintext) == \
        _reference_crypt(material[:32], nonce, plaintext)
    assert instructions.crypt(
        material[:32], nonce,
        instructions.crypt(material[:32], nonce, plaintext)) == plaintext


def test_epoch_and_serial_integer_boundaries():
    nonce_key = instructions.derive_keys(KEY, "device-1", KEY_ID)[2]
    for value in (0, instructions.MAX_I63):
        assert len(instructions.derive_nonce(
            nonce_key, "device-1", KEY_ID, value, value)) == 16
    for value in (-1, instructions.MAX_I63 + 1, True, 1.0):
        with pytest.raises(instructions.InstructionError):
            instructions.derive_nonce(
                nonce_key, "device-1", KEY_ID, value, 1)


def test_exact_envelope_round_trip_and_all_components_authenticate():
    part = _part()
    role = _role()
    signature = b"synthetic-public-signature"
    envelope = instructions.seal_parts(_header(part), part, role, signature, KEY)
    assert envelope.count(b"\n") == 7
    assert b"\r" not in envelope and envelope.endswith(b"\n")
    opened = instructions.open_parts(envelope, KEY)
    assert opened[0] == _header(part)
    assert opened[1:] == (role, signature, part)

    components = list(instructions.parse_envelope(envelope))
    mutations = []
    changed_header = dict(_header(part), policy_revision=4)
    mutations.append((0, instructions.canonical_json(changed_header)))
    changed_role = json.loads(role)
    changed_role["on_stale"] = "keep"
    mutations.append((1, instructions.canonical_json(changed_role)))
    for index in range(2, 6):
        value = bytearray(components[index])
        value[0] ^= 1
        mutations.append((index, bytes(value)))
    for index, changed in mutations:
        candidate = list(components)
        candidate[index] = changed
        tampered = instructions.frame_envelope(*candidate)
        decrypt_calls = []
        with pytest.raises(instructions.InstructionError):
            instructions.open_parts(
                tampered, KEY, before_decrypt=lambda: decrypt_calls.append(1))
        assert decrypt_calls == []


@pytest.mark.parametrize("damage", [b'{"a":1,"a":1}', b'{"a":NaN}'])
def test_duplicate_unknown_and_nonfinite_json_are_rejected(damage):
    with pytest.raises(instructions.InstructionError):
        instructions.parse_json(damage)
    with pytest.raises(instructions.InstructionError):
        instructions.validate_header(dict(_header(), unknown=1))


def test_closed_header_role_part_and_stamp_schemas():
    part = _part()
    header = _header(part)
    role = instructions.parse_json(_role())
    stamp = {key: header[key] for key in (
        "epoch", "instr_serial", "policy_revision", "platform", "role",
        "role_gen", "role_body_sha256", "key_id", "verify_level",
        "issued_at", "expires_at", "degraded")}
    stamp["part"] = part
    assert instructions.validate_header(header) is header
    assert instructions.validate_role_body(role) is role
    assert instructions.validate_part(part, issued_at=100, expires_at=700) is part
    assert instructions.validate_stamp(stamp) is stamp
    for validator, value in ((instructions.validate_header, header),
                             (instructions.validate_role_body, role),
                             (instructions.validate_part, part),
                             (instructions.validate_stamp, stamp)):
        bad = dict(value, unknown=True)
        with pytest.raises(instructions.InstructionError):
            validator(bad)
    for field, value in (("max_peers", 0), ("max_concurrent", 1001),
                         ("overall_up_bps", 1),
                         ("overall_up_bps", 10_000_000_001)):
        with pytest.raises(instructions.InstructionError):
            instructions.validate_qos(dict(QOS, **{field: value}))
    for field, value in (("catalog_tick_s", 59),
                         ("catalog_tick_s", 61),
                         ("telemetry_every_ticks", 61)):
        with pytest.raises(instructions.InstructionError):
            instructions.validate_control(dict(CONTROL, **{field: value}))
    for damage in (
        dict(header, platform="unknown"),
        dict(header, device_id="seeder"),
        dict(header, allowed_expires_at=99),
    ):
        with pytest.raises(instructions.InstructionError):
            instructions.validate_header(damage)
    for name in ("quarantine", "Uppercase", "r" * 33):
        with pytest.raises(instructions.InstructionError):
            instructions.validate_role_body(dict(role, role=name))
    with pytest.raises(instructions.InstructionError):
        instructions.validate_stamp(dict(stamp, part=None))


@pytest.mark.parametrize("value", [1.0, True, False])
@pytest.mark.parametrize("target", ["header-version", "role-version"])
def test_versions_are_exact_nonboolean_integers_on_direct_and_parsed_paths(
        target, value):
    candidate = _header() if target == "header-version" else json.loads(_role())
    candidate["v"] = value
    validator = (instructions.validate_header if target == "header-version"
                 else instructions.validate_role_body)
    with pytest.raises(instructions.InstructionError):
        validator(candidate)
    parsed = instructions.parse_json(instructions.canonical_json(candidate))
    with pytest.raises(instructions.InstructionError):
        validator(parsed)


@pytest.mark.parametrize("value", [100.0, True, False])
@pytest.mark.parametrize("target", ["header-time", "role-time"])
def test_server_times_are_exact_nonboolean_integers_before_equality(
        target, value):
    candidate = _header() if target == "header-time" else json.loads(_role())
    candidate["server_time"] = value
    validator = (instructions.validate_header if target == "header-time"
                 else instructions.validate_role_body)
    with pytest.raises(instructions.InstructionError):
        validator(candidate)
    parsed = instructions.parse_json(instructions.canonical_json(candidate))
    with pytest.raises(instructions.InstructionError):
        validator(parsed)


def test_peer_modes_canonical_addresses_caps_and_expiry():
    for peers in (
        {"mode": "allow", "allowed": ["10.0.0.1", "10.0.1.0/24"],
         "include_origin": True, "allowed_expires_at": 700},
        {"mode": "deny", "rules": ["10.0.0.2"], "include_origin": False,
         "allowed_expires_at": 700},
        {"mode": "tracker-only", "include_origin": False,
         "allowed_expires_at": 700},
    ):
        instructions.validate_peers(peers, expires_at=700)
    bad = {"mode": "allow", "allowed": ["10.0.0.01"],
           "include_origin": False, "allowed_expires_at": 700}
    with pytest.raises(instructions.InstructionError):
        instructions.validate_peers(bad)
    too_many = {"mode": "allow",
                "allowed": ["10.%d.%d.%d" %
                            ((i >> 16) & 255, (i >> 8) & 255, i & 255)
                            for i in range(1001)],
                "include_origin": False, "allowed_expires_at": 700}
    with pytest.raises(instructions.InstructionError):
        instructions.validate_peers(too_many)


def test_canonical_framed_size_boundaries_and_raw_malformed_buffers():
    part = _part()
    role = _role()
    header = _header(part)
    probe_signature = b"s"
    probe = instructions.seal_parts(
        header, part, role, probe_signature, KEY)
    fixed_size = len(probe) - len(base64.b64encode(probe_signature))
    encoded_signature_size = 262143 - fixed_size
    assert encoded_signature_size > 0
    assert encoded_signature_size % 4 == 0
    signature = b"s" * (3 * (encoded_signature_size // 4))

    valid = instructions.seal_parts(header, part, role, signature, KEY)
    assert len(valid) == 262143
    components = instructions.parse_envelope(valid)
    assert all(components)
    opened_header, opened_role, opened_signature, opened_part = \
        instructions.open_parts(valid, KEY)
    assert opened_header == header
    assert opened_role == role
    assert opened_signature == signature
    assert opened_part == part

    header_bytes, role_bytes, _signature, nonce, ciphertext, _tag = components
    oversized_signature = signature + b"xyz"
    mac_key = instructions.derive_keys(
        KEY, header["device_id"], header["key_id"])[1]
    oversized_tag = instructions.compute_tag(
        mac_key, header_bytes, role_bytes, oversized_signature,
        nonce, ciphertext)
    oversized_components = (
        header_bytes, role_bytes, oversized_signature, nonce,
        ciphertext, oversized_tag)
    independently_framed = b"\n".join(
        (instructions.INSTR_MAGIC,) + tuple(
            base64.b64encode(value) for value in oversized_components)) + b"\n"
    assert len(independently_framed) == 262147
    with pytest.raises(instructions.InstructionError):
        instructions.frame_envelope(*oversized_components)
    for size in (262144, 262145):
        with pytest.raises(instructions.InstructionError):
            instructions.parse_envelope(b"x" * size)


def test_seal_is_restart_deterministic_across_python_hash_seeds(tmp_path):
    script = r'''
import hashlib, instructions
key = bytes(range(32)); kid = hashlib.sha256(key).hexdigest()
q = {"max_peers":10,"seed_up_bps":0,"seed_down_bps":0,"leech_up_bps":0,"leech_down_bps":0,"overall_up_bps":0,"overall_down_bps":0,"max_concurrent":100,"request_peer_speed_limit_bps":51200}
c = {"catalog_tick_s":60,"telemetry_every_ticks":1,"telemetry_pause":False}
r = {"v":1,"role":"default","restricted":False,"role_gen":"a"*64,"issued_at":100,"expires_at":700,"server_time":100,"qos":q,"control":c,"on_stale":"defaults"}
rb = instructions.canonical_json(r)
p = {"peers":{"mode":"tracker-only","include_origin":False,"allowed_expires_at":700},"qos_override":{},"control_override":{},"server_time":100}
h = {"v":1,"device_id":"device-1","platform":"guestshell","epoch":99,"instr_serial":7,"policy_revision":3,"issued_at":100,"expires_at":700,"server_time":100,"verify_level":"sig","key_id":kid,"role":"default","role_gen":"a"*64,"role_body_sha256":hashlib.sha256(rb).hexdigest(),"ct_len":len(instructions.canonical_json(p)),"allowed_expires_at":700,"degraded":False}
print(hashlib.sha256(instructions.seal_parts(h,p,rb,b"sig",key)).hexdigest())
'''
    values = []
    for seed in ("1", "8675309"):
        env = dict(os.environ, PYTHONHASHSEED=seed,
                   PYTHONPATH=os.path.dirname(instructions.__file__))
        result = subprocess.run([sys.executable, "-c", script], env=env,
                                check=True, capture_output=True, text=True)
        values.append(result.stdout.strip())
    assert values[0] == values[1]


_TASK14_APPLIED = (
    "bt_max_peers", "max_upload_limit", "max_download_limit", "overall_up",
    "overall_down", "request_peer_speed_limit", "max_concurrent",
)
_TASK14_STATES = {
    "none", "applied", "lkg", "stale_expired", "allowlist_expired",
    "rollback_rejected", "floor_reset", "audience_mismatch", "key_rejected",
    "tamper_rejected", "verifier_missing", "lkg_rejected", "lkg_unreadable",
    "oversize", "reasserted", "instr_unavailable", "instr_pending",
    "instr_forbidden", "tracker-only",
}
_TASK14_MAX = (1 << 63) - 1


def _task14_attestation():
    return {
        "applied": {name: index for index, name in enumerate(_TASK14_APPLIED)},
        "instr_state": "applied", "instr_serial": 7, "verify_level": "sig",
        "blocklist_rules": 12, "blocklist_revision": 3,
        "qos_drift": {
            "options": [{"option": "max_upload_limit", "expected": 1, "observed": 2}],
            "blocklist_revision": {"expected": 3, "observed": 4},
            "blocklist_rules": {"expected": 12, "observed": 13},
        },
    }


def test_task14_instruction_attestation_authoritative_constants():
    assert set(instructions.APPLIED_FIELDS) == set(_TASK14_APPLIED)
    assert len(instructions.APPLIED_FIELDS) == 7
    assert set(instructions.INSTR_STATES) == _TASK14_STATES
    assert set(instructions.INSTR_REASONS) == {"unknown_key", "bad_mac"}
    assert instructions.QOS_DRIFT_MAX_ROWS == 47
    assert instructions.MAX_I63 == _TASK14_MAX


def test_task14_instruction_attestation_complete_projection_is_copied_and_private():
    sanitize = instructions.sanitize_instruction_attestation
    expected = _task14_attestation()
    supplied = copy.deepcopy(expected)
    supplied.update({"role": "untrusted-role", "platform": "xr-appmgr",
                     "gid": "untrusted-id", "key_id": "0" * 64,
                     "key": "never stored", "signature": "never stored",
                     "envelope": "never stored", "peers": ["192.0.2.1"],
                     "aria2_options": {"arbitrary": "never stored"}})
    before = copy.deepcopy(supplied)
    result = sanitize(supplied)
    assert result == expected
    assert supplied == before
    result["applied"]["max_concurrent"] = 99
    result["qos_drift"]["options"][0]["observed"] = 77
    assert supplied == before
    assert sanitize({}) == {}


@pytest.mark.parametrize("state", sorted(_TASK14_STATES))
def test_task14_instruction_attestation_exact_states_and_reason_dependency(state):
    sanitize = instructions.sanitize_instruction_attestation
    candidate = {"instr_state": state}
    if state == "key_rejected":
        assert sanitize(candidate) == {}
        for reason in ("unknown_key", "bad_mac"):
            complete = dict(candidate, instr_reason=reason)
            assert sanitize(complete) == complete
    else:
        assert sanitize(candidate) == candidate
        assert sanitize(dict(candidate, instr_reason="unknown_key")) == {}


@pytest.mark.parametrize("candidate", [
    {"instr_state": "pre-instructions"}, {"instr_state": "pointer_skew"},
    {"instr_state": "qos_drift"}, {"instr_state": "future-state"},
    {"instr_state": []}, {"instr_state": True},
    {"instr_reason": "unknown_key"},
    {"instr_state": "key_rejected", "instr_reason": "future-reason"},
    {"instr_state": "key_rejected", "instr_reason": []},
])
def test_task14_instruction_attestation_bad_state_reason_omits_only_that_unit(candidate):
    sanitize = instructions.sanitize_instruction_attestation
    candidate = dict(candidate, instr_serial=8, verify_level="none")
    assert sanitize(candidate) == {"instr_serial": 8, "verify_level": "none"}


@pytest.mark.parametrize("field", _TASK14_APPLIED)
def test_task14_instruction_attestation_applied_is_seven_closed_bounded_integers(field):
    sanitize = instructions.sanitize_instruction_attestation
    complete = {name: 0 for name in _TASK14_APPLIED}
    for valid in (0, _TASK14_MAX):
        candidate = dict(complete, **{field: valid})
        assert sanitize({"applied": candidate}) == {"applied": candidate}
    for invalid in (-1, _TASK14_MAX + 1, True, 1.0, "1", None):
        candidate = dict(complete, **{field: invalid})
        assert sanitize({"applied": candidate, "instr_state": "lkg"}) == {
            "instr_state": "lkg"}
    partial = dict(complete)
    del partial[field]
    assert sanitize({"applied": partial}) == {}
    assert sanitize({"applied": dict(complete, arbitrary_option=1)}) == {}


def test_task14_instruction_attestation_serial_verify_and_blocklist_units():
    sanitize = instructions.sanitize_instruction_attestation
    for boundary in (0, _TASK14_MAX):
        candidate = {"instr_serial": boundary, "blocklist_rules": boundary,
                     "blocklist_revision": boundary}
        assert sanitize(candidate) == candidate
    for level in ("sig", "none"):
        assert sanitize({"verify_level": level}) == {"verify_level": level}
    for invalid in (-1, _TASK14_MAX + 1, True, 1.0, "1", None):
        assert sanitize({"instr_serial": invalid}) == {}
        for field in ("blocklist_rules", "blocklist_revision"):
            pair = {"blocklist_rules": 1, "blocklist_revision": 2, field: invalid}
            assert sanitize(dict(pair, instr_state="applied")) == {"instr_state": "applied"}
    for partial in ({"blocklist_rules": 1}, {"blocklist_revision": 2}):
        assert sanitize(partial) == {}
    for invalid in ("SIG", "unverified", True, None, []):
        assert sanitize({"verify_level": invalid}) == {}


def test_task14_instruction_attestation_drift_preserves_47_rows_order_and_duplicates():
    sanitize = instructions.sanitize_instruction_attestation
    rows = [{"option": name, "expected": 0, "observed": _TASK14_MAX}
            for name in _TASK14_APPLIED]
    repeated = {"option": "bt_max_peers", "expected": 1, "observed": 2}
    rows += [dict(repeated) for _ in range(40)]
    fact = {"options": rows}
    assert len(rows) == 47
    assert sanitize({"qos_drift": fact}) == {"qos_drift": fact}
    assert sanitize({"qos_drift": {"options": rows + [dict(repeated)]}}) == {}
    for field in ("blocklist_rules", "blocklist_revision"):
        blocklist_only = {"options": [], field: {"expected": 0, "observed": _TASK14_MAX}}
        assert sanitize({"qos_drift": blocklist_only}) == {"qos_drift": blocklist_only}


@pytest.mark.parametrize("damage", [
    "missing-options", "empty", "options-not-list", "row-not-object",
    "unknown-option", "gid", "scope", "ip", "index", "token", "row-extra",
    "row-missing", "equal", "negative", "overflow", "boolean", "float", "text",
    "fact-extra", "pair-extra", "pair-missing", "pair-equal", "pair-negative",
    "pair-overflow", "pair-boolean", "pair-float", "pair-text",
])
def test_task14_instruction_attestation_invalid_drift_omits_whole_fact(damage):
    sanitize = instructions.sanitize_instruction_attestation
    fact = copy.deepcopy(_task14_attestation()["qos_drift"])
    row = fact["options"][0]
    pair = fact["blocklist_revision"]
    invalid_numbers = {"negative": -1, "overflow": _TASK14_MAX + 1,
                       "boolean": True, "float": 1.0, "text": "1"}
    if damage == "missing-options":
        del fact["options"]
    elif damage == "empty":
        fact = {"options": []}
    elif damage == "options-not-list":
        fact["options"] = {}
    elif damage == "row-not-object":
        fact["options"] = [1]
    elif damage == "unknown-option":
        row["option"] = "arbitrary-aria2-option"
    elif damage in {"gid", "scope", "ip", "index", "token", "row-extra"}:
        row[damage] = "untrusted"
    elif damage == "row-missing":
        del row["observed"]
    elif damage == "equal":
        row["observed"] = row["expected"]
    elif damage in invalid_numbers:
        row["observed"] = invalid_numbers[damage]
    elif damage == "fact-extra":
        fact["role"] = "untrusted"
    elif damage == "pair-extra":
        pair["gid"] = "untrusted"
    elif damage == "pair-missing":
        del pair["expected"]
    elif damage == "pair-equal":
        pair["observed"] = pair["expected"]
    else:
        pair["observed"] = invalid_numbers[damage.removeprefix("pair-")]
    assert sanitize({"qos_drift": fact, "instr_serial": 7}) == {"instr_serial": 7}


@pytest.mark.parametrize("marker", [None, False, True, 0, 2, -1, 2 ** 63,
                                     1.0, "1", "private-token", [], {}])
def test_task19_attestation_protocol_invalid_present_is_bounded_unknown(marker):
    assert instructions.sanitize_instruction_attestation(
        {"instr_protocol": marker}) == {"instr_protocol": None}
    assert instructions.sanitize_instruction_attestation({}) == {}
    assert instructions.sanitize_instruction_attestation(
        {"instr_protocol": 1}) == {"instr_protocol": 1}


@pytest.mark.parametrize("field", ["instr_epoch", "instr_serial", "instr_policy_revision"])
def test_task19_attestation_accepted_identity_is_complete_bounded_unit(field):
    identity = {"instr_epoch": 11, "instr_serial": 7, "instr_policy_revision": 3}
    for boundary in (0, 2 ** 63 - 1):
        valid = dict(identity, **{field: boundary})
        assert instructions.sanitize_instruction_attestation(valid) == valid
    for invalid in (None, False, True, -1, 2 ** 63, 1.0, "1", {}, []):
        candidate = dict(identity, **{field: invalid})
        assert instructions.sanitize_instruction_attestation(
            dict(candidate, instr_state="lkg")) == {"instr_state": "lkg"}
    partial = dict(identity)
    del partial[field]
    assert instructions.sanitize_instruction_attestation(partial) == {}
    # Old persisted reports keep the bounded serial without invented members.
    assert instructions.sanitize_instruction_attestation(
        {"instr_serial": 7}) == {"instr_serial": 7}


@pytest.mark.parametrize("value", [True, False, None, 0, 1, 3, "true", [], {}])
def test_task19_attestation_pointer_skew_boolean_only(value):
    supplied = {"pointer_skew": value, "pointer_skew_count": 3,
                "fetched_pointer": {"epoch": 11, "instr_serial": 100},
                "token": "private-token"}
    expected = {"pointer_skew": value} if type(value) is bool else {}
    assert instructions.sanitize_instruction_attestation(supplied) == expected
