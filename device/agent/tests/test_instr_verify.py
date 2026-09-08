# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Device verification contracts, using independently framed synthetic data.

The future module is imported at fixture execution, never at collection. Test
keys are disposable; no production signing helper constructs these vectors.
"""

import base64
import copy
import hashlib
import hmac
import importlib
import json
import os
import shutil
import socketserver
import stat
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import agent_config
import catalog_client
import iris_agent


NOW = 1788782400
KEY = bytes(range(32))
KEY_ID = hashlib.sha256(KEY).hexdigest()
NEXT_KEY = b"d" * 32
NEXT_KEY_ID = hashlib.sha256(NEXT_KEY).hexdigest()
SIGNATURE = b"-----BEGIN SSH SIGNATURE-----\ntest-only\n-----END SSH SIGNATURE-----\n"
BOOT = "test-boot-a"
QOS = {"max_peers": 10, "seed_up_bps": 0, "seed_down_bps": 0,
       "leech_up_bps": 0, "leech_down_bps": 0, "overall_up_bps": 0,
       "overall_down_bps": 0, "max_concurrent": 100,
       "request_peer_speed_limit_bps": 51200}
CONTROL = {"catalog_tick_s": 60, "telemetry_every_ticks": 1,
           "telemetry_pause": False}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def pae(*parts):
    return struct.pack("<Q", len(parts)) + b"".join(
        struct.pack("<Q", len(part)) + part for part in parts)


def kdf(key, label, context, length):
    return b"".join(hmac.new(
        key, struct.pack(">I", counter) + label + b"\0" + context
        + struct.pack(">I", length * 8), hashlib.sha256).digest()
        for counter in range(1, (length + 31) // 32 + 1))[:length]


def role_value():
    return {"v": 1, "role": "default", "restricted": False,
            "role_gen": "a" * 64, "issued_at": NOW, "expires_at": NOW + 600,
            "server_time": NOW, "qos": dict(QOS), "control": dict(CONTROL),
            "on_stale": "defaults"}


def part_value():
    return {"peers": {"mode": "tracker-only", "include_origin": False,
                      "allowed_expires_at": NOW + 600},
            "qos_override": {}, "control_override": {}, "server_time": NOW}


def make_envelope(header=None, role=None, part=None, key=KEY,
                  signature=SIGNATURE, plaintext=None):
    role = role_value() if role is None else copy.deepcopy(role)
    part = part_value() if part is None else copy.deepcopy(part)
    role_bytes = role if isinstance(role, bytes) else canonical(role)
    plain = canonical(part) if plaintext is None else plaintext
    kid = hashlib.sha256(key).hexdigest()
    hdr = {"v": 1, "device_id": "sw1", "platform": "guestshell",
           "epoch": NOW - 1, "instr_serial": 7, "policy_revision": 3,
           "issued_at": NOW, "expires_at": NOW + 600, "server_time": NOW,
           "verify_level": "sig", "key_id": kid, "role": "default",
           "role_gen": "a" * 64,
           "role_body_sha256": hashlib.sha256(role_bytes).hexdigest(),
           "ct_len": len(plain), "allowed_expires_at": NOW + 600,
           "degraded": False}
    hdr.update(header or {})
    header_bytes = canonical(hdr)
    context = pae(hdr["device_id"].encode("ascii"), kid.encode("ascii"))
    material = kdf(key, b"iris-instr-v1", context, 96)
    nonce = kdf(material[64:], b"iris-instr-nonce-v1", pae(
        hdr["device_id"].encode("ascii"), kid.encode("ascii"),
        struct.pack(">Q", max(0, int(hdr["epoch"]))),
        struct.pack(">Q", max(0, int(hdr["instr_serial"])))), 16)
    stream = b"".join(hmac.new(
        material[:32], nonce + struct.pack(">I", i), hashlib.sha256).digest()
        for i in range(1, (len(plain) + 31) // 32 + 1))
    ciphertext = bytes(a ^ b for a, b in zip(plain, stream))
    tag = hmac.new(material[32:64], pae(header_bytes, role_bytes, signature,
                                      nonce, ciphertext), hashlib.sha256).digest()
    return frame((header_bytes, role_bytes, signature, nonce, ciphertext, tag))


def frame(parts):
    return b"IRIS-INSTR/1\n" + b"\n".join(
        base64.b64encode(item) for item in parts) + b"\n"


def unframe(raw):
    return [base64.b64decode(line) for line in raw.splitlines()[1:]]


def config():
    return {"device_id": "sw1", "platform": "guestshell", "stage_dir": "/stage",
            "catalog_url": "https://192.0.2.10:8443", "catalog_token": "old-token",
            "token_expires_at": str(NOW + 604800),
            "instr_key": canonical({"key_id": KEY_ID, "value": KEY.hex()}).decode(),
            "lkg_key": "bb" * 32}


class AcceptVerifier:
    def __init__(self):
        self.calls = []

    def verify(self, body, signature, namespace, identity, verify_time, **kwargs):
        self.calls.append((body, signature, namespace, identity, verify_time, kwargs))
        return True


@pytest.fixture
def instr():
    return importlib.import_module("instr")


def verify(module, raw=None, cfg=None, state=None, date=NOW, mono=10,
           boot=BOOT, verifier=None):
    return module.verify_envelope(
        make_envelope() if raw is None else raw,
        config() if cfg is None else cfg, {} if state is None else state,
        date, mono, boot, AcceptVerifier() if verifier is None else verifier)


def reject(module, raw, expected=None, **kwargs):
    with pytest.raises(module.InstructionError) as caught:
        verify(module, raw, **kwargs)
    if expected is not None:
        assert caught.value.state == expected
    return caught.value


def test_independent_envelope_round_trip_preserves_exact_signed_bytes(instr):
    raw = make_envelope()
    verifier = AcceptVerifier()
    state = {}
    result = verify(instr, raw, state=state, verifier=verifier)
    parts = unframe(raw)
    assert result["header_bytes"] == parts[0]
    assert result["role_body"] == parts[1]
    assert result["signature"] == parts[2]
    assert result["envelope"] == raw
    assert result["header"]["instr_serial"] == 7
    assert result["role"] == role_value()
    assert result["device"] == part_value()
    assert state == {}                    # verification is not durable application
    assert verifier.calls[0][:5] == (parts[1], parts[2], "iris-instructions-v1",
                                     "iris-server", NOW)
    artifact = b"IRIS-ROLE/1\n" + base64.b64encode(parts[1]) + b"\n" + \
        base64.b64encode(parts[2]) + b"\n"
    assert verifier.calls[0][5]["artifact_digest"] == hashlib.sha256(artifact).hexdigest()


def test_verification_order_short_circuits_before_mac_and_decryption(instr, monkeypatch):
    raw = make_envelope(plaintext=b"not-json")
    parts = unframe(raw)
    parts[-1] = b"x" * 32
    verifier = AcceptVerifier()
    # Foreign audience wins even when both authentication and plaintext are bad.
    cfg = config()
    cfg["device_id"] = "other-device"
    reject(instr, frame(parts), "audience_mismatch", cfg=cfg, verifier=verifier)
    assert verifier.calls == []
    calls = []
    original = hmac.compare_digest
    original_new = hmac.new
    decrypted_blocks = []

    def record_hmac(key, msg=None, digestmod=None):
        # The specified XOR stream uses nonce(16) || counter(4). These are
        # distinct from both SP800-108 derivation and the length-framed MAC.
        if isinstance(msg, bytes) and len(msg) == 20:
            decrypted_blocks.append(msg)
        return original_new(key, msg, digestmod)

    monkeypatch.setattr(hmac, "new", record_hmac)

    def record_compare(left, right):
        calls.append("mac")
        return original(left, right)

    monkeypatch.setattr(hmac, "compare_digest", record_compare)

    class Refuse(AcceptVerifier):
        def verify(self, *args, **kwargs):
            calls.append("signature")
            return False

    reject(instr, frame(parts), verifier=Refuse())
    assert calls == ["signature"]
    assert decrypted_blocks == []
    calls[:] = []
    error = reject(instr, frame(parts), "key_rejected", verifier=verifier)
    assert error.reason == "bad_mac"
    assert verifier.calls and calls
    assert decrypted_blocks == []
    # Valid MAC exposes the later parse error, never a successful partial apply.
    reject(instr, raw)
    assert decrypted_blocks


@pytest.mark.parametrize("where,field,value", [
    ("header", "extra", 1), ("header", "v", True), ("header", "v", 2),
    ("header", "instr_serial", True), ("header", "instr_serial", -1),
    ("header", "instr_serial", (1 << 63)), ("header", "epoch", NOW + 1),
    ("header", "policy_revision", 1.0), ("header", "server_time", NOW + 1),
    ("header", "verify_level", "none"), ("header", "ct_len", 0),
    ("header", "role_body_sha256", "0" * 64),
    ("header", "info_hash", "A" * 40), ("header", "degraded", 0),
    ("role", "extra", 1), ("role", "server_time", NOW + 1),
    ("role", "on_stale", "install"), ("role", "restricted", 1),
    ("part", "extra", 1), ("part", "server_time", NOW + 1),
], ids=["header-unknown", "version-bool", "version-future", "serial-bool",
        "serial-negative", "serial-overflow", "epoch-after-issuance",
        "revision-float", "header-time", "verification-level", "ciphertext-length",
        "role-digest", "infohash-case", "degraded-type", "role-unknown",
        "role-time", "stale-posture", "restricted-type", "part-unknown", "part-time"])
def test_closed_envelope_schema_rejects_whole_instruction(instr, where, field, value):
    values = {"header": {}, "role": role_value(), "part": part_value()}
    values[where][field] = value
    reject(instr, make_envelope(**values))


@pytest.mark.parametrize("field,value", [
    ("max_peers", 0), ("max_peers", 1001), ("max_concurrent", True),
    ("overall_down_bps", 8191), ("overall_up_bps", 10000000001),
    ("request_peer_speed_limit_bps", 1000000001), ("unknown", 0),
])
def test_qos_bounds_reject_whole_instruction(instr, field, value):
    part = part_value()
    part["qos_override"][field] = value
    reject(instr, make_envelope(part=part))


@pytest.mark.parametrize("field,value", [("catalog_tick_s", 61),
    ("catalog_tick_s", 960), ("telemetry_every_ticks", 0),
    ("telemetry_every_ticks", 61), ("telemetry_pause", 1), ("extra", False)])
def test_control_bounds_reject_whole_instruction(instr, field, value):
    part = part_value()
    part["control_override"][field] = value
    reject(instr, make_envelope(part=part))


@pytest.mark.parametrize("peers", [
    {"mode": "allow", "allowed": ["10.0.0.1", "10.0.0.1"]},
    {"mode": "allow", "allowed": ["10.0.0.1/24"]},
    {"mode": "allow", "allowed": ["::1"]},
    {"mode": "allow", "allowed": ["10.0.0.2", "10.0.0.1"]},
    {"mode": "allow", "allowed": ["10.0.0.1"] * 1001},
    {"mode": "deny", "rules": ["10.0.0.1"] * 4097},
    {"mode": "tracker-only", "allowed": []}, {"mode": "anything"},
])
def test_peer_schema_and_list_caps(instr, peers):
    part = part_value()
    part["peers"].update(peers)
    reject(instr, make_envelope(part=part))


@pytest.mark.parametrize("plaintext", [b'{"x":1,"x":2}', b'{"x":NaN}',
                                       b'{ "x":1}', b'\xff', b'[]'],
                         ids=["duplicate", "nonfinite", "whitespace", "utf8", "array"])
def test_noncanonical_or_nonobject_plaintext_is_rejected(instr, plaintext):
    reject(instr, make_envelope(plaintext=plaintext))


def test_known_reserved_infohash_and_exact_valid_bounds(instr):
    part = part_value()
    part["qos_override"] = {"max_peers": 1000, "overall_up_bps": 8192,
                            "overall_down_bps": 0, "max_concurrent": 1}
    part["control_override"] = {"catalog_tick_s": 900,
                                "telemetry_every_ticks": 60}
    result = verify(instr, make_envelope(header={"info_hash": "b" * 40}, part=part))
    assert result["device"] == part
    assert result["header"]["info_hash"] == "b" * 40


@pytest.mark.parametrize("raw", [b"x" * (256 * 1024 + 1),
    make_envelope().replace(b"\n", b"\r\n"), make_envelope()[:-1],
    make_envelope() + b"\n", b"IRIS-INSTR/2\n"],
                         ids=["oversize", "crlf", "missing-lf", "extra-line", "magic"])
def test_size_and_framing_precede_verifier(instr, raw):
    verifier = AcceptVerifier()
    reject(instr, raw, verifier=verifier)
    assert verifier.calls == []


def test_current_previous_exact_ids_and_unknown_vs_bad_mac(instr):
    previous = bytes(reversed(range(32)))
    cfg = config()
    cfg["instr_key_prev"] = canonical({"key_id": hashlib.sha256(previous).hexdigest(),
                                        "value": previous.hex()}).decode()
    assert verify(instr, make_envelope(key=previous), cfg=cfg)["device"] == part_value()
    unknown = b"z" * 32
    error = reject(instr, make_envelope(key=unknown), "key_rejected", cfg=cfg)
    assert error.reason == "unknown_key"
    parts = unframe(make_envelope())
    parts[-1] = b"z" * 32
    error = reject(instr, frame(parts), "key_rejected", cfg=cfg)
    assert error.reason == "bad_mac"
    cfg["instr_key"] = canonical({"key_id": KEY_ID, "value": previous.hex()}).decode()
    reject(instr, make_envelope(), "key_rejected", cfg=cfg)


def test_separate_clocks_retain_anchor_and_reject_regression(instr, monkeypatch):
    state = {}
    instr.observe_clock(state, "catalog", NOW, 10, BOOT)
    instr.observe_clock(state, "instruction", NOW - 1000, 10, BOOT)
    assert instr.project_clock(state, "catalog", 70, BOOT) == NOW + 60
    assert instr.project_clock(state, "instruction", 70, BOOT) == NOW - 940
    instr.observe_clock(state, "catalog", NOW - 200, 70, BOOT)
    assert instr.project_clock(state, "catalog", 80, BOOT) == NOW + 70
    with pytest.raises(instr.InstructionError):
        instr.observe_clock(state, "catalog", NOW - 301, 10, BOOT)
    monkeypatch.setattr(time, "time", lambda: 4070908800)
    assert instr.project_clock(state, "catalog", 80, BOOT) == NOW + 70
    assert instr.project_clock(state, "catalog", 9, BOOT) is None
    assert instr.project_clock(state, "catalog", 80, "different-boot") is None
    # JSON persistence must retain the effective-time/monotonic pair.
    restored = json.loads(json.dumps(state))
    assert instr.project_clock(restored, "instruction", 80, BOOT) == NOW - 930


def test_future_skew_expiry_and_immutable_issuance(instr):
    assert verify(instr, date=NOW - 60)["header"]["issued_at"] == NOW
    reject(instr, make_envelope(), date=NOW - 61)
    verifier = AcceptVerifier()
    assert verify(instr, date=NOW + 599, verifier=verifier)["header"]["server_time"] == NOW
    # Certificate validity is checked at signed issuance, with the current
    # KRL; transport Date governs freshness but never rewrites verify-time.
    assert verifier.calls[0][4] == NOW
    reject(instr, make_envelope(), date=NOW + 600)
    role = role_value()
    role["expires_at"] = NOW + 604801
    reject(instr, make_envelope(role=role, header={"expires_at": NOW + 604801}))


def test_verification_failure_never_advances_clock_or_replay_floor(instr):
    state = {}
    instr.observe_clock(state, "instruction", NOW, 10, BOOT)
    before = copy.deepcopy(state)
    parts = unframe(make_envelope())
    parts[-1] = b"x" * 32
    reject(instr, frame(parts), state=state, date=NOW + 100, mono=110)
    assert state == before
    result = verify(instr, state=state, date=NOW + 100, mono=110)
    assert state == before
    instr.apply_verified(result, state, NOW + 100, 110, BOOT)
    assert instr.project_clock(state, "instruction", 120, BOOT) == NOW + 110


def test_equal_replay_requires_identical_bytes_and_pending_reset_is_transactional(instr):
    state = {}
    high = make_envelope(header={"instr_serial": 20})
    result = verify(instr, high, state=state)
    instr.apply_verified(result, state, NOW, 10, BOOT)
    accepted = copy.deepcopy(state)
    assert verify(instr, high, state=state)["envelope"] == high
    reject(instr, make_envelope(header={"instr_serial": 20, "policy_revision": 4}),
           state=state)
    low = make_envelope(header={"instr_serial": 10})
    hint = {"epoch": NOW - 1, "instr_serial": 10}
    for _ in range(9):
        instr.note_hint(state, hint, authenticated=True)
        reject(instr, low, state=state)
    instr.note_hint(state, hint, authenticated=True)
    parts = unframe(low)
    parts[-1] = b"x" * 32
    reject(instr, frame(parts), state=state)
    assert verify(instr, high, state=state)["envelope"] == high
    candidate = verify(instr, low, state=state)
    # The accepted old identity remains valid until the durable apply boundary.
    assert verify(instr, high, state=state)["envelope"] == high
    instr.apply_verified(candidate, state, NOW, 10, BOOT)
    assert state != accepted
    assert verify(instr, low, state=state)["envelope"] == low
    reject(instr, make_envelope(header={"instr_serial": 9}), state=state)


@pytest.mark.parametrize("interruption", [None, "different", "equal", "higher", "unauthenticated"])
def test_lower_hint_streak_is_consecutive_and_exact(instr, interruption):
    state = {}
    high = verify(instr, make_envelope(header={"instr_serial": 20}))
    instr.apply_verified(high, state, NOW, 10, BOOT)
    hint = {"epoch": NOW - 1, "instr_serial": 10}
    for _ in range(9):
        instr.note_hint(state, hint, authenticated=True)
    if interruption == "unauthenticated":
        instr.note_hint(state, hint, authenticated=False)
    else:
        serial = {"different": 11, "equal": 20, "higher": 21}.get(interruption)
        instr.note_hint(state, None if serial is None else
                        {"epoch": NOW - 1, "instr_serial": serial}, authenticated=True)
    instr.note_hint(state, hint, authenticated=True)
    reject(instr, make_envelope(header={"instr_serial": 10}), state=state)


def ssh(args, data=None):
    executable = shutil.which("ssh-keygen")
    assert executable and os.path.isabs(executable), "real OpenSSH is a required gate"
    return subprocess.run([executable] + [str(item) for item in args], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=10, check=True).stdout


@pytest.fixture
def signing(tmp_path):
    root = tmp_path / "root-a"
    root_b = tmp_path / "root-b"
    leaf = tmp_path / "leaf"
    other = tmp_path / "unrelated"
    for path in (root, root_b, leaf, other):
        ssh(["-q", "-t", "ed25519", "-N", "", "-C", "test-only", "-f", path])
    validity = "%s:%s" % (
        time.strftime("%Y%m%d%H%M%SZ", time.gmtime(NOW - 3600)),
        time.strftime("%Y%m%d%H%M%SZ", time.gmtime(NOW + 86400)))
    ssh(["-q", "-s", root, "-I", "iris-online", "-n", "iris-server",
         "-V", validity, str(leaf) + ".pub"])
    allowed = tmp_path / "iris-signers.allowed_signers"
    roots = tmp_path / "iris-root.allowed_signers"
    allowed.write_text("".join('iris-server cert-authority,namespaces="iris-instructions-v1" '
                               + path.with_suffix(".pub").read_text()
                               for path in (root, root_b)))
    roots.write_text("".join('iris-root:%s namespaces="iris-keylist-v1" ' % root_id
                             + " ".join(path.with_suffix(".pub").read_text().split()[:2]) + "\n"
                             for root_id, path in (("root-a", root), ("root-b", root_b))))
    krl = tmp_path / "unrelated.krl"
    ssh(["-q", "-k", "-f", krl, str(other) + ".pub"])
    revoked = tmp_path / "revoked-leaf.krl"
    ssh(["-q", "-k", "-f", revoked, str(leaf) + ".pub"])
    return {"root": root, "root_b": root_b, "leaf": leaf,
            "allowed": allowed, "roots": roots, "krl": krl.read_bytes(),
            "revoked": revoked.read_bytes(), "work": tmp_path / "work"}


def ssh_verifier(module, signing, runner=None):
    signing["work"].mkdir(exist_ok=True)
    kwargs = {} if runner is None else {"runner": runner}
    return module.SSHVerifier(shutil.which("ssh-keygen"), str(signing["allowed"]),
                              str(signing["roots"]), str(signing["work"]), **kwargs)


def test_real_sshsig_exact_body_namespace_time_krl_and_cleanup(instr, signing):
    body = canonical(role_value())
    signature = ssh(["-Y", "sign", "-f", str(signing["leaf"]) + "-cert.pub",
                     "-n", "iris-instructions-v1"], body)
    calls = []

    def runner(argv, **kwargs):
        calls.append((list(argv), dict(kwargs)))
        assert os.path.isabs(argv[0])
        assert kwargs["stdout"] == subprocess.DEVNULL
        assert kwargs["stderr"] == subprocess.DEVNULL
        assert 4 <= kwargs["timeout"] <= 6
        signature_path = argv[argv.index("-s") + 1]
        assert open(signature_path, "rb").read() == signature
        assert stat.S_IMODE(os.stat(signature_path).st_mode) == 0o600
        if "-r" in argv:
            krl_path = argv[argv.index("-r") + 1]
            assert os.path.dirname(krl_path).startswith(str(signing["work"]))
            assert stat.S_IMODE(os.stat(krl_path).st_mode) == 0o600
        return subprocess.run(argv, **kwargs)

    verifier = ssh_verifier(instr, signing, runner)
    assert verifier.verify(body, signature, "iris-instructions-v1", "iris-server", NOW)
    assert "-r" not in calls[-1][0]
    assert verifier.verify(body, signature, "iris-instructions-v1", "iris-server", NOW,
                           krl=signing["krl"])
    argv, kwargs = calls[-1]
    assert kwargs["input"] == body
    assert argv[argv.index("-f") + 1] == str(signing["allowed"])
    assert argv[argv.index("-I") + 1] == "iris-server"
    assert argv[argv.index("-n") + 1] == "iris-instructions-v1"
    assert argv[argv.index("-O") + 1] == "verify-time=" + time.strftime(
        "%Y%m%d%H%M%SZ", time.gmtime(NOW))
    assert not verifier.verify(body + b" ", signature, "iris-instructions-v1",
                               "iris-server", NOW, krl=signing["krl"])
    assert not verifier.verify(body, signature, "iris-instructions-v1",
                               "iris-server", NOW, krl=signing["revoked"])
    for argv, _ in calls:
        assert not os.path.exists(argv[argv.index("-s") + 1])
        if "-r" in argv:
            assert not os.path.exists(argv[argv.index("-r") + 1])


def test_real_envelope_verification_and_signed_body_tamper(instr, signing):
    body = canonical(role_value())
    signature = ssh(["-Y", "sign", "-f", str(signing["leaf"]) + "-cert.pub",
                     "-n", "iris-instructions-v1"], body)
    verifier = ssh_verifier(instr, signing)
    raw = make_envelope(signature=signature)
    assert verify(instr, raw, verifier=verifier)["role_body"] == body
    changed = role_value()
    changed["qos"]["max_peers"] += 1
    # Correct MAC and header hash cannot replace the independent role signature.
    reject(instr, make_envelope(role=changed, signature=signature), verifier=verifier)


def test_verifier_timeout_digest_latch_boot_reset_and_nonzero_exit(instr, signing):
    calls = []

    def timeout(argv, **kwargs):
        if "verify" not in argv:
            return subprocess.run(argv, **kwargs)
        calls.append(argv)
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    # The subprocess wrapper is stateless. Persistence belongs to the tick
    # coordinator, so reusing a wrapper cannot silently hide verification calls.
    verifier = ssh_verifier(instr, signing, timeout)
    for _ in range(5):
        with pytest.raises(instr.InstructionError) as caught:
            verifier.verify(b"body", SIGNATURE, "iris-instructions-v1", "iris-server",
                            NOW, artifact_digest="a" * 64, boot_id=BOOT)
        assert caught.value.state == "verifier_missing"
        assert caught.value.reason == "verifier_timeout"
    assert len(calls) == 5
    calls[:] = []

    catalog = RouteCatalog()
    state = {}

    def tick(raw, boot=BOOT, runner=timeout):
        catalog.response = (200, raw, {"Date": "Mon, 07 Sep 2026 12:00:00 GMT"})
        return instr.run_instruction_step(
            cfg=config(), state=state, catalog=catalog,
            hints={"instr_rev": {"epoch": NOW - 1, "instr_serial": 7}},
            catalog_date=NOW, platform="guestshell", work_dir=str(signing["work"]),
            boot_id=boot, monotonic_now=10,
            verifier=ssh_verifier(instr, signing, runner),
            persist_config=lambda updated: None, emit=lambda *args: None)["attestation"]

    raw = make_envelope()
    parts = unframe(raw)
    role_artifact = b"IRIS-ROLE/1\n" + base64.b64encode(parts[1]) + b"\n" + \
        base64.b64encode(parts[2]) + b"\n"
    digest = hashlib.sha256(role_artifact).hexdigest()
    for attempt in range(5):
        assert tick(raw)["instr_state"] == "verifier_missing"
        bag = state["instructions"]
        assert bag["verifier_timeout_digest"] == digest
        assert bag["verifier_timeout_count"] == min(attempt + 1, 3)
        assert bag["verifier_timeout_boot_id"] == BOOT
        # Model the next launcher process: new wrapper and reloaded durable JSON.
        state = json.loads(json.dumps(state))
    assert len(calls) == 3
    assert not (signing["work"] / "iris-instructions.lkg").exists()

    # A changed per-device envelope does not change the signed role artifact.
    assert tick(make_envelope(header={"policy_revision": 4}))["instr_state"] == "verifier_missing"
    assert len(calls) == 3
    changed_role = role_value()
    changed_role["qos"]["max_peers"] = 11
    changed = make_envelope(role=changed_role)
    assert tick(changed)["instr_state"] == "verifier_missing"
    assert len(calls) == 4
    assert state["instructions"]["verifier_timeout_digest"] != digest
    assert state["instructions"]["verifier_timeout_count"] == 1
    state = json.loads(json.dumps(state))
    assert tick(changed, boot="next-boot")["instr_state"] == "verifier_missing"
    assert len(calls) == 5
    assert state["instructions"]["verifier_timeout_boot_id"] == "next-boot"
    assert state["instructions"]["verifier_timeout_count"] == 1
    assert list(signing["work"].iterdir()) == []

    def rejected(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 1)

    before = len(calls)
    for _ in range(4):
        assert tick(changed, boot="next-boot", runner=rejected)["instr_state"] != "verifier_missing"
        state = json.loads(json.dumps(state))
    assert len(calls) == before + 4
    assert state["instructions"].get("verifier_timeout_count", 0) == 0


def test_missing_verifier_is_immediate_and_cleans_temporary_files(instr, signing):
    def missing(argv, **kwargs):
        raise FileNotFoundError("synthetic missing executable")

    verifier = ssh_verifier(instr, signing, missing)
    with pytest.raises(instr.InstructionError) as caught:
        verifier.verify(b"body", SIGNATURE, "iris-instructions-v1", "iris-server", NOW)
    assert caught.value.state == "verifier_missing"
    assert list(signing["work"].iterdir()) == []


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


@pytest.fixture
def http_catalog():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.server.requests.append((self.path, dict(self.headers)))
            assert self.headers["Authorization"] == "Bearer test-token"
            status, body, headers = self.server.reply
            self.send_response_only(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadedHTTPServer(("127.0.0.1", 0), Handler)
    server.requests = []
    server.reply = (200, b"binary\x00", {"Date": "Mon, 07 Sep 2026 12:00:00 GMT",
                                       "ETag": '"opaque-strong"'})
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server, catalog_client.CatalogClient(
            "http://127.0.0.1:%d" % server.server_port, "test-token")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("method,route,limit", [
    ("get_instructions", "instructions", 256 * 1024),
    ("get_instruction_keylist", "instruction-keylist", 128 * 1024),
])
def test_binary_transport_date_etag_caps_and_bodyless_304(http_catalog, method, route, limit):
    server, client = http_catalog
    fetch = getattr(client, method)
    status, body, headers = fetch("sw1", etag='"previous"')
    assert (status, body) == (200, b"binary\x00")
    assert headers["Date"] == "Mon, 07 Sep 2026 12:00:00 GMT"
    assert headers["ETag"] == '"opaque-strong"'
    assert server.requests[-1][0] == "/v1/devices/sw1/" + route
    assert server.requests[-1][1]["If-None-Match"] == '"previous"'
    server.reply = (304, b"", {"Date": headers["Date"], "ETag": headers["ETag"]})
    assert fetch("sw1", etag=headers["ETag"]) == (304, b"", server.reply[2])
    server.reply = (200, b"x" * limit, {})
    assert len(fetch("sw1")[1]) == limit
    # Both advertised and unadvertised oversize must fail before returning bytes.
    for response_headers in ({}, {"Content-Length": str(limit + 1)}):
        server.reply = (200, b"x" * (limit + 1), response_headers)
        with pytest.raises(catalog_client.CatalogError):
            fetch("sw1")


@pytest.mark.parametrize("status", [401, 403, 404, 409, 429, 500, 503])
def test_binary_transport_preserves_failure_status_and_retry_metadata(http_catalog, status):
    server, client = http_catalog
    headers = {"Date": "Mon, 07 Sep 2026 12:00:00 GMT", "Retry-After": "10"}
    server.reply = (status, b'{"status":%d}' % status, headers)
    assert client.get_instructions("sw1") == (status, server.reply[1], headers)


@pytest.mark.parametrize("bag_change,expected", [
    ({}, "retain"), ({"instr_key_prev": {"bad": "ignored"}}, "retain"),
    ({"instr_key": {"key_id": NEXT_KEY_ID, "value": NEXT_KEY.hex()}}, "clear"),
    ({"instr_key": {"key_id": NEXT_KEY_ID, "value": NEXT_KEY.hex()},
      "instr_key_prev": {"key_id": KEY_ID, "value": KEY.hex()}}, "replace"),
    ({"instr_key": {"key_id": "C" * 64, "value": "d" * 64}}, "retain"),
    ({"instr_key": {"key_id": NEXT_KEY_ID, "value": NEXT_KEY.hex()},
      "instr_key_prev": {"key_id": "e" * 64}}, "retain"),
    ({"instr_key": {"key_id": NEXT_KEY_ID, "value": NEXT_KEY.hex(), "extra": 1}}, "retain"),
])
def test_refresh_key_subtransaction_preserves_other_valid_bag_fields(tmp_path, bag_change, expected):
    cfg = config()
    previous = bytes(reversed(range(32)))
    cfg["instr_key_prev"] = canonical({
        "key_id": hashlib.sha256(previous).hexdigest(), "value": previous.hex()}).decode()
    path = tmp_path / "agent.conf"
    agent_config.write_conf(str(path), cfg)
    bag = {"catalog_token": "new-token", "expires_at": NOW + 604800,
           "announce_token": "new-announce", "rpc_secret": "new-rpc"}
    bag.update(copy.deepcopy(bag_change))

    class Client:
        token = "old-token"

        def refresh_token(self, device_id):
            return bag

    client = Client()
    emitted = []
    updated = iris_agent._refresh_impl(cfg, str(path), client,
                                        lambda *args: emitted.append(args))
    assert client.token == "new-token"
    assert updated["catalog_token"] == "new-token"
    assert updated["announce_token"] == "new-announce"
    assert updated["rpc_secret"] == "new-rpc"
    if expected == "retain":
        assert updated["instr_key"] == cfg["instr_key"]
        assert updated["instr_key_prev"] == cfg["instr_key_prev"]
    else:
        assert updated["instr_key"] == canonical(bag["instr_key"]).decode()
        if expected == "clear":
            assert "instr_key_prev" not in updated
        else:
            assert updated["instr_key_prev"] == canonical(bag["instr_key_prev"]).decode()
    loaded = agent_config.load(str(path))
    for key in ("instr_key", "instr_key_prev", "lkg_key"):
        assert loaded.get(key) == updated.get(key)
    assert all("new-token" not in repr(item) and KEY.hex() not in repr(item)
               for item in emitted)


def test_bad_instruction_key_and_conf_failure_keep_current_bearer(tmp_path, monkeypatch):
    class Client:
        token = "old-token"

        def refresh_token(self, device_id):
            return {"catalog_token": "new-token", "expires_at": NOW + 600,
                    "instr_key": {"value": "malformed"}}

    client = Client()

    def fail_write(path, cfg):
        assert client.token == "new-token"
        assert cfg["catalog_token"] == "new-token"
        raise OSError("synthetic durability failure")

    monkeypatch.setattr(agent_config, "write_conf", fail_write)
    assert iris_agent._refresh_impl(config(), str(tmp_path / "agent.conf"),
                                    client, lambda *args: None) is None
    assert client.token == "new-token"


def make_keylist(signing, seq=1, krl=None, root_id="root-a", signer=None,
                 metadata_change=None):
    krl = signing["krl"] if krl is None else krl
    metadata = {"v": 1, "keylist_seq": seq, "issued_at": NOW,
                "signer_root_id": root_id, "krl_sha256": hashlib.sha256(krl).hexdigest()}
    metadata.update(metadata_change or {})
    payload = b"IRIS-KEYLIST/1\n" + base64.b64encode(canonical(metadata)) + b"\n" + \
        base64.b64encode(krl) + b"\n"
    signature = ssh(["-Y", "sign", "-f", signing["root"] if signer is None else signer,
                     "-n", "iris-keylist-v1"], payload)
    return payload + base64.b64encode(signature) + b"\n"


def keylist_paths(signing):
    return (signing["work"] / "iris-instruction-keylist.current",
            signing["work"] / "iris-instruction-keylist-state.json")


def keylist_store(module, signing, runner=None):
    return module.KeylistStore(str(signing["work"]), ssh_verifier(module, signing, runner))


def test_keylist_first_install_exact_state_permissions_and_fresh_snapshot(instr, signing):
    store = keylist_store(instr, signing)
    assert store.snapshot() is None
    assert store.recover() is None
    raw = make_keylist(signing)
    store.install(raw, NOW)
    artifact, state_path = keylist_paths(signing)
    expected = {"schema": "iris-device-instruction-keylist-state/v1",
                "keylist_seq": 1, "artifact_sha256": hashlib.sha256(raw).hexdigest(),
                "krl_sha256": hashlib.sha256(signing["krl"]).hexdigest(),
                "krl_b64": base64.b64encode(signing["krl"]).decode(),
                "issued_at": NOW, "verified_root_id": "root-a"}
    assert artifact.read_bytes() == raw
    assert json.loads(state_path.read_text()) == expected
    assert store.snapshot() == expected
    assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(artifact.stat().st_mode) == 0o600
    snapshot = store.snapshot()
    snapshot["keylist_seq"] = 999
    assert store.snapshot() == expected
    assert keylist_store(instr, signing).snapshot() == expected
    assert sorted(path.name for path in signing["work"].iterdir()) == sorted(
        [artifact.name, state_path.name])


def test_keylist_verifies_both_roots_independently_and_installed_krl_is_never_omitted(instr, signing):
    calls = []

    def runner(argv, **kwargs):
        if "verify" in argv:
            allowed = open(argv[argv.index("-f") + 1]).read()
            assert len(allowed.splitlines()) == 1
            principal = argv[argv.index("-I") + 1]
            assert principal in ("iris-root:root-a", "iris-root:root-b")
            assert allowed.split()[0] == principal
            calls.append((principal, None if "-r" not in argv else
                          open(argv[argv.index("-r") + 1], "rb").read()))
        return subprocess.run(argv, **kwargs)

    store = keylist_store(instr, signing, runner)
    store.install(make_keylist(signing), NOW)
    assert set(principal for principal, _ in calls) == {"iris-root:root-a", "iris-root:root-b"}
    assert all(krl is None for _, krl in calls)
    calls[:] = []
    second = make_keylist(signing, seq=2, root_id="root-b", signer=signing["root_b"])
    store.install(second, NOW)
    assert set(principal for principal, _ in calls) == {"iris-root:root-a", "iris-root:root-b"}
    assert all(krl == signing["krl"] for _, krl in calls)
    assert store.snapshot()["verified_root_id"] == "root-b"
    # Exactly the same bytes remain acceptable on a fresh process-equivalent store.
    restored = keylist_store(instr, signing, runner)
    restored.install(second, NOW)
    assert restored.snapshot()["keylist_seq"] == 2


@pytest.mark.parametrize("change", ["reverse", "duplicate-id", "duplicate-key",
    "trailing-field", "wrong-principal", "namespace", "third-line", "one-line",
    "unsafe-id", "wrong-algorithm", "noncanonical-base64"])
def test_keylist_root_mapping_is_closed_and_order_independent(instr, signing, change):
    lines = signing["roots"].read_text().splitlines()
    if change == "reverse":
        lines.reverse()
    elif change == "duplicate-id":
        lines[1] = lines[1].replace("root-b", "root-a")
    elif change == "duplicate-key":
        lines[1] = lines[0].replace("root-a", "root-b")
    elif change == "trailing-field":
        lines[0] += " comment"
    elif change == "wrong-principal":
        lines[0] = lines[0].replace("iris-root:root-a", "iris-root")
    elif change == "namespace":
        lines[0] = lines[0].replace("iris-keylist-v1", "iris-instructions-v1")
    elif change == "third-line":
        lines.append(lines[0])
    elif change == "unsafe-id":
        lines[0] = lines[0].replace("root-a", "../root")
    elif change == "wrong-algorithm":
        lines[0] = lines[0].replace("ssh-ed25519", "ssh-rsa")
    elif change == "noncanonical-base64":
        lines[0] += "="
    else:
        lines.pop()
    signing["roots"].write_text("\n".join(lines) + "\n")
    raw = make_keylist(signing)
    if change == "reverse":
        store = keylist_store(instr, signing)
        store.install(raw, NOW)
        assert store.snapshot()["verified_root_id"] == "root-a"
    else:
        with pytest.raises(instr.InstructionError):
            keylist_store(instr, signing).install(raw, NOW)
        assert not any(path.exists() for path in keylist_paths(signing))


def test_keylist_claim_cannot_select_root_and_multiple_matches_fail_closed(instr, signing):
    raw = make_keylist(signing, root_id="root-b", signer=signing["root"])
    with pytest.raises(instr.InstructionError):
        keylist_store(instr, signing).install(raw, NOW)
    assert not any(path.exists() for path in keylist_paths(signing))

    def both_match(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 0)

    with pytest.raises(instr.InstructionError):
        keylist_store(instr, signing, both_match).install(make_keylist(signing), NOW)
    assert not any(path.exists() for path in keylist_paths(signing))


@pytest.mark.parametrize("bad", ["rollback", "equal-different", "oversize", "metadata-extra",
    "boolean-sequence", "zero-sequence", "overflow-sequence", "bad-digest", "krl-cap",
    "bad-root", "bad-signature", "bad-krl", "issued-bool", "issued-negative",
    "issued-future"])
def test_keylist_rejections_retain_established_bytes_and_state(instr, signing, bad):
    store = keylist_store(instr, signing)
    good = make_keylist(signing, seq=2)
    store.install(good, NOW)
    paths = keylist_paths(signing)
    before = tuple(path.read_bytes() for path in paths)
    if bad == "rollback":
        candidate = make_keylist(signing, seq=1)
    elif bad == "equal-different":
        candidate = make_keylist(signing, seq=2, krl=b"")
    elif bad == "oversize":
        candidate = b"x" * (128 * 1024 + 1)
    elif bad == "krl-cap":
        candidate = make_keylist(signing, seq=3, krl=b"x" * (80 * 1024 + 1))
    elif bad == "bad-root":
        candidate = make_keylist(signing, seq=3, signer=signing["leaf"])
    elif bad == "bad-signature":
        candidate = make_keylist(signing, seq=3).rsplit(b"\n", 2)[0] + b"\neA==\n"
    elif bad == "bad-krl":
        candidate = make_keylist(signing, seq=3, krl=b"not an OpenSSH KRL")
    else:
        mutation = {"metadata-extra": {"extra": 1}, "boolean-sequence": {"keylist_seq": True},
                    "zero-sequence": {"keylist_seq": 0},
                    "overflow-sequence": {"keylist_seq": 1 << 63},
                    "bad-digest": {"krl_sha256": "0" * 64},
                    "issued-bool": {"issued_at": True},
                    "issued-negative": {"issued_at": -1},
                    "issued-future": {"issued_at": NOW + 61}}[bad]
        candidate = make_keylist(signing, seq=3, metadata_change=mutation)
    with pytest.raises(instr.InstructionError):
        store.install(candidate, NOW)
    assert tuple(path.read_bytes() for path in paths) == before
    assert store.snapshot()["keylist_seq"] == 2


def test_keylist_revoked_chain_cannot_replace_last_usable_installation(instr, signing):
    # The first KRL revokes root-b; the next root-b-signed candidate cannot
    # clear that revocation by presenting its own empty replacement KRL.
    revoked = signing["work"].parent / "root-b-revoked.krl"
    ssh(["-q", "-k", "-f", revoked, str(signing["root_b"]) + ".pub"])
    store = keylist_store(instr, signing)
    store.install(make_keylist(signing, krl=revoked.read_bytes()), NOW)
    before = tuple(path.read_bytes() for path in keylist_paths(signing))
    candidate = make_keylist(signing, seq=2, krl=b"", root_id="root-b", signer=signing["root_b"])
    with pytest.raises(instr.InstructionError):
        store.install(candidate, NOW)
    assert tuple(path.read_bytes() for path in keylist_paths(signing)) == before


@pytest.mark.parametrize("case", ["artifact-ahead", "metadata-ahead", "equal-different",
    "missing-artifact", "missing-state", "malformed-state", "malformed-state-alone"])
def test_keylist_restart_classifies_every_authority_pair(instr, signing, case):
    store = keylist_store(instr, signing)
    first = make_keylist(signing)
    second = make_keylist(signing, seq=2)
    store.install(first, NOW)
    artifact, state_path = keylist_paths(signing)
    old_state = state_path.read_bytes()
    if case == "artifact-ahead":
        artifact.write_bytes(second)
        restarted = keylist_store(instr, signing)
        restarted.recover()
        assert restarted.snapshot()["keylist_seq"] == 2
        assert artifact.read_bytes() == second
    elif case == "missing-artifact":
        artifact.unlink()
        restarted = keylist_store(instr, signing)
        restarted.recover()
        assert state_path.read_bytes() == old_state
        # Loss never makes an equal/older sequence a new initial installation.
        with pytest.raises(instr.InstructionError):
            restarted.install(first, NOW)
        restarted.install(second, NOW)
        assert restarted.snapshot()["keylist_seq"] == 2
    else:
        if case == "metadata-ahead":
            store.install(second, NOW)
            artifact.write_bytes(first)
        elif case == "equal-different":
            artifact.write_bytes(make_keylist(signing, krl=b""))
        elif case == "missing-state":
            state_path.unlink()
        else:
            state_path.write_bytes(b"{broken")
            if case == "malformed-state-alone":
                artifact.unlink()
        before = tuple(path.read_bytes() if path.exists() else None
                       for path in (artifact, state_path))
        with pytest.raises(instr.InstructionError):
            keylist_store(instr, signing).recover()
        assert tuple(path.read_bytes() if path.exists() else None
                     for path in (artifact, state_path)) == before
        with pytest.raises(instr.InstructionError):
            keylist_store(instr, signing).install(make_keylist(signing, seq=3), NOW)


@pytest.mark.parametrize("field,value", [("extra", 1), ("keylist_seq", True),
    ("artifact_sha256", "A" * 64), ("krl_sha256", "0" * 64),
    ("krl_b64", "!invalid!"), ("issued_at", -1), ("verified_root_id", "../root")])
def test_keylist_malformed_state_never_bootstraps(instr, signing, field, value):
    store = keylist_store(instr, signing)
    store.install(make_keylist(signing), NOW)
    artifact, state_path = keylist_paths(signing)
    value_map = json.loads(state_path.read_text())
    value_map[field] = value
    state_path.write_bytes(canonical(value_map))
    artifact.unlink()
    before = state_path.read_bytes()
    with pytest.raises(instr.InstructionError):
        keylist_store(instr, signing).install(make_keylist(signing, seq=2), NOW)
    assert state_path.read_bytes() == before
    assert not artifact.exists()


@pytest.mark.parametrize("boundary", ["artifact-file-fsync", "artifact-replace",
    "artifact-dir-fsync", "state-file-fsync", "state-replace", "state-dir-fsync"])
def test_keylist_durability_failures_preserve_recoverable_authority(instr, signing, monkeypatch, boundary):
    store = keylist_store(instr, signing)
    first = make_keylist(signing)
    second = make_keylist(signing, seq=2)
    store.install(first, NOW)
    artifact, state_path = keylist_paths(signing)
    old_metadata = state_path.read_bytes()
    real_replace, real_fsync = os.replace, os.fsync
    phase = [None]
    observed = []

    def replace(source, destination):
        name = os.path.basename(str(destination))
        if name in (artifact.name, state_path.name):
            label = "artifact" if name == artifact.name else "state"
            observed.append(label + "-replace")
            if boundary == label + "-replace":
                raise OSError("injected replace failure")
            real_replace(source, destination)
            phase[0] = label
        else:
            real_replace(source, destination)

    def fsync(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            with open("/proc/self/fd/%d" % fd, "rb") as stream:
                value = stream.read()
            label = None
            if value == second:
                label = "artifact"
            else:
                try:
                    parsed = json.loads(value.decode())
                except (ValueError, UnicodeError):
                    parsed = None
                if isinstance(parsed, dict) and parsed.get("schema") == \
                        "iris-device-instruction-keylist-state/v1":
                    label = "state"
            if label is not None:
                observed.append(label + "-file-fsync")
                if boundary == label + "-file-fsync":
                    raise OSError("injected file fsync failure")
        if stat.S_ISDIR(os.fstat(fd).st_mode) and phase[0] is not None:
            observed.append(phase[0] + "-dir-fsync")
            if boundary == phase[0] + "-dir-fsync":
                raise OSError("injected directory fsync failure")
        return real_fsync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(os, "replace", replace)
        patch.setattr(os, "fsync", fsync)
        with pytest.raises((OSError, instr.InstructionError)):
            store.install(second, NOW)
    assert boundary in observed
    if boundary in ("artifact-file-fsync", "artifact-replace"):
        assert artifact.read_bytes() == first
        assert state_path.read_bytes() == old_metadata
    elif boundary in ("artifact-dir-fsync", "state-file-fsync", "state-replace"):
        assert artifact.read_bytes() == second
        assert state_path.read_bytes() == old_metadata
    else:
        assert artifact.read_bytes() == second
        assert json.loads(state_path.read_text())["keylist_seq"] == 2
        assert observed.index("artifact-dir-fsync") < observed.index("state-replace")
    restarted = keylist_store(instr, signing)
    restarted.recover()
    restarted.install(second, NOW)
    assert restarted.snapshot()["keylist_seq"] == 2
    assert artifact.read_bytes() == second


def test_catalog_date_observation_is_success_only_strict_and_additive(http_catalog):
    server, client = http_catalog
    assert client.last_authenticated_date is None
    server.reply = (200, b'{"approved_image_id":null}',
                    {"Date": "Mon, 07 Sep 2026 12:00:00 GMT"})
    assert client.get_policy("sw1") == {"approved_image_id": None}
    assert client.last_authenticated_date == NOW
    for invalid in (None, "not-a-date", "Mon, 07 Sep 2026 12:00:00 PST",
                    "Mon, 07 Sep 2026 12:00:00 GMT, Mon, 07 Sep 2026 12:00:00 GMT"):
        server.reply = (200, b"{}", {} if invalid is None else {"Date": invalid})
        client.get_policy("sw1")
        assert client.last_authenticated_date == NOW
    server.reply = (401, b"{}", {"Date": "Mon, 07 Sep 2026 13:00:00 GMT"})
    with pytest.raises(catalog_client.CatalogError):
        client.get_policy("sw1")
    assert client.last_authenticated_date == NOW
    server.reply = (304, b"", {"Date": "Mon, 07 Sep 2026 12:01:00 GMT"})
    assert client.get_instructions("sw1")[0] == 304
    assert client.last_authenticated_date == NOW + 60


def test_run_once_without_trustworthy_clock_refreshes_despite_future_wallclock(instr, monkeypatch):
    from test_iris_agent import FakeCatalog, make_deps
    catalog = FakeCatalog({"approved_image_id": None}, None)
    deps = make_deps(catalog, {})[0]
    refreshed = []
    deps = deps._replace(refresh=lambda: refreshed.append(True))
    monkeypatch.setattr(time, "time", lambda: 4070908800)
    cfg = config()
    cfg["token_expires_at"] = "9999999999"
    state = {}
    assert iris_agent.run_once(cfg, deps, state) == "no-assignment"
    assert refreshed == [True]
    assert catalog.heartbeats


class RouteCatalog:
    def __init__(self, response=None):
        self.response = (200, make_envelope(), {"Date": "Mon, 07 Sep 2026 12:00:00 GMT",
                                               "ETag": '"envelope-a"'}) if response is None else response
        self.requests = []
        self.refreshes = []

    def get_instructions(self, device_id, etag=None):
        self.requests.append(("instructions", device_id, etag))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def get_instruction_keylist(self, device_id, etag=None):
        self.requests.append(("keylist", device_id, etag))
        return 503, b"", {}

    def refresh_token(self, device_id):
        self.refreshes.append(device_id)
        return {"catalog_token": "refreshed-token", "expires_at": NOW + 604800}


def run_step(module, tmp_path, catalog, state, hints=None, cfg=None, mono=10):
    return module.run_instruction_step(
        config() if cfg is None else cfg, state, catalog,
        {"instr_rev": {"epoch": NOW - 1, "instr_serial": 7}}
        if hints is None else hints,
        NOW, "guestshell", str(tmp_path), BOOT, mono,
        AcceptVerifier(), lambda updated: None, lambda *args: None)["attestation"]


@pytest.mark.parametrize("response,expected,refresh", [
    ((404, b"", {}), "instr_unavailable", 0),
    ((409, b"", {}), "instr_pending", 0),
    ((429, b"", {"Retry-After": "10"}), "instr_unavailable", 0),
    ((500, b"", {}), "instr_unavailable", 0),
    ((503, b"", {}), "instr_unavailable", 0),
    ((401, b"", {}), "instr_forbidden", 1),
    ((403, b"", {}), "instr_forbidden", 1),
    (catalog_client.CatalogError("unreachable"), "instr_unavailable", 0),
    ((200, b"x" * (256 * 1024 + 1), {}), "oversize", 0),
], ids=["404", "409", "429", "500", "503", "401", "403", "transport", "oversize"])
def test_instruction_route_failures_have_exact_facts_and_bounded_refresh(instr, tmp_path, response, expected, refresh):
    catalog = RouteCatalog(response)
    state = {}
    result = run_step(instr, tmp_path, catalog, state)
    assert result["instr_state"] == expected
    assert len(catalog.refreshes) == refresh
    assert not (tmp_path / "iris-instructions.lkg").exists()


def test_pointer_absence_skips_fetch_and_failed_pointer_remains_retryable(instr, tmp_path):
    catalog = RouteCatalog((409, b"", {}))
    state = {}
    result = run_step(instr, tmp_path, catalog, state, hints={})
    assert result["instr_state"] == "none"
    assert catalog.requests == []
    for _ in range(2):
        assert run_step(instr, tmp_path, catalog, state)["instr_state"] == "instr_pending"
    assert len(catalog.requests) == 2


def test_verified_unchanged_pointer_skips_fetch_moved_pointer_304_preserves_authority(instr, tmp_path):
    catalog = RouteCatalog()
    state = {}
    result = run_step(instr, tmp_path, catalog, state)
    assert result["instr_state"] in ("applied", "lkg")
    lkg = tmp_path / "iris-instructions.lkg"
    before_lkg = lkg.read_bytes()
    run_step(instr, tmp_path, catalog, state, mono=20)
    assert len(catalog.requests) == 1
    catalog.response = (304, b"", {"Date": "Mon, 07 Sep 2026 12:00:30 GMT",
                                   "ETag": '"envelope-a"'})
    moved = {"instr_rev": {"epoch": NOW - 1, "instr_serial": 8}}
    run_step(instr, tmp_path, catalog, state, hints=moved, mono=30)
    assert catalog.requests[-1] == ("instructions", "sw1", '"envelope-a"')
    assert lkg.read_bytes() == before_lkg
    # A 304 cannot fabricate acceptance of the moved pointer; it stays retryable.
    run_step(instr, tmp_path, catalog, state, hints=moved, mono=40)
    assert len(catalog.requests) == 3
    assert lkg.read_bytes() == before_lkg


def test_higher_keylist_hint_is_fetched_before_envelope(instr, tmp_path):
    catalog = RouteCatalog((409, b"", {}))
    hints = {"instr_rev": {"epoch": NOW - 1, "instr_serial": 7}, "keylist_seq": 1}
    run_step(instr, tmp_path, catalog, {}, hints=hints)
    assert catalog.requests
    assert catalog.requests[0][:2] == ("keylist", "sw1")


def test_unknown_key_refresh_is_latched_but_known_bad_mac_never_refreshes(instr, tmp_path):
    catalog = RouteCatalog((200, make_envelope(key=b"z" * 32),
                            {"Date": "Mon, 07 Sep 2026 12:00:00 GMT"}))
    state = {}
    for _ in range(2):
        result = run_step(instr, tmp_path, catalog, state)
        assert (result["instr_state"], result["instr_reason"]) == ("key_rejected", "unknown_key")
    assert len(catalog.refreshes) == 1
    parts = unframe(make_envelope())
    parts[-1] = b"x" * 32
    catalog.response = (200, frame(parts), {"Date": "Mon, 07 Sep 2026 12:00:00 GMT"})
    result = run_step(instr, tmp_path, catalog, state)
    assert (result["instr_state"], result["instr_reason"]) == ("key_rejected", "bad_mac")
    assert len(catalog.refreshes) == 1


def test_higher_body_is_accepted_and_lower_body_refetch_is_bounded(instr, tmp_path):
    catalog = RouteCatalog((200, make_envelope(header={"instr_serial": 6}),
                            {"Date": "Mon, 07 Sep 2026 12:00:00 GMT"}))
    state = {}
    assert run_step(instr, tmp_path, catalog, state,
                    hints={"instr_rev": {"epoch": NOW - 1, "instr_serial": 5}})["instr_state"] in ("applied", "lkg")
    catalog.requests[:] = []
    catalog.response = (200, make_envelope(), {"Date": "Mon, 07 Sep 2026 12:00:00 GMT"})
    hints = {"instr_rev": {"epoch": NOW - 1, "instr_serial": 8}}
    for tick in range(5):
        run_step(instr, tmp_path, catalog, state, hints=hints, mono=20 + tick)
    assert len(catalog.requests) == 3


def test_effective_instruction_expiry_cannot_be_extended_by_tolerated_date_rollback(instr):
    state = {}
    instr.observe_clock(state, "instruction", NOW, 10, BOOT)
    # The received Date is inside the signed lifetime and within skew tolerance,
    # but monotonic projection has reached expiry. No restored lifetime is allowed.
    reject(instr, make_envelope(), state=state, date=NOW + 300, mono=610)


@pytest.mark.parametrize("interruption", [None, "different", "equal", "higher", "unauthenticated"])
def test_pending_reset_authorization_is_cleared_when_exact_hint_stops(instr, interruption):
    state = {}
    high = verify(instr, make_envelope(header={"instr_serial": 20}))
    instr.apply_verified(high, state, NOW, 10, BOOT)
    hint = {"epoch": NOW - 1, "instr_serial": 10}
    low = make_envelope(header={"instr_serial": 10})
    for _ in range(10):
        instr.note_hint(state, hint, authenticated=True)
    assert verify(instr, low, state=state)["envelope"] == low
    if interruption == "unauthenticated":
        instr.note_hint(state, hint, authenticated=False)
    else:
        serial = {"different": 11, "equal": 20, "higher": 21}.get(interruption)
        instr.note_hint(state, None if serial is None else
                        {"epoch": NOW - 1, "instr_serial": serial}, authenticated=True)
    reject(instr, low, state=state)


def test_version_floor_is_advanced_only_after_apply_and_never_reset(instr):
    state = {}
    value = verify(instr)
    instr.apply_verified(value, state, NOW, 10, BOOT)
    reject(instr, make_envelope(header={"v": 0}), state=state)
    hint = {"epoch": NOW - 1, "instr_serial": 1}
    for _ in range(10):
        instr.note_hint(state, hint, authenticated=True)
    reject(instr, make_envelope(header={"v": 0, "instr_serial": 1}), state=state)


def test_keylist_artifact_loss_preserves_revocation_context(instr, signing):
    revoked = signing["work"].parent / "root-b-revoked.krl"
    ssh(["-q", "-k", "-f", revoked, str(signing["root_b"]) + ".pub"])
    store = keylist_store(instr, signing)
    store.install(make_keylist(signing, krl=revoked.read_bytes()), NOW)
    artifact, state_path = keylist_paths(signing)
    artifact.unlink()
    before = state_path.read_bytes()
    with pytest.raises(instr.InstructionError):
        keylist_store(instr, signing).install(make_keylist(
            signing, seq=2, root_id="root-b", signer=signing["root_b"], krl=b""), NOW)
    assert state_path.read_bytes() == before
    assert not artifact.exists()


def test_keylist_304_keeps_installed_bytes_and_metadata(instr, signing):
    store = keylist_store(instr, signing)
    store.install(make_keylist(signing), NOW)
    paths = keylist_paths(signing)
    before = tuple(path.read_bytes() for path in paths)

    class NotModified(RouteCatalog):
        def get_instruction_keylist(self, device_id, etag=None):
            self.requests.append(("keylist", device_id, etag))
            return 304, b"", {"Date": "Mon, 07 Sep 2026 12:00:00 GMT"}

    catalog = NotModified()
    run_step(instr, signing["work"], catalog, {}, hints={"keylist_seq": 2})
    assert catalog.requests and catalog.requests[0][0] == "keylist"
    assert not any(request[0] == "instructions" for request in catalog.requests)
    assert tuple(path.read_bytes() for path in paths) == before


def test_established_empty_krl_still_passes_revocation_option(instr, signing):
    store = keylist_store(instr, signing)
    store.install(make_keylist(signing, krl=b""), NOW)
    calls = []

    def runner(argv, **kwargs):
        if "verify" in argv:
            assert "-r" in argv
            assert open(argv[argv.index("-r") + 1], "rb").read() == b""
            calls.append(argv)
        return subprocess.run(argv, **kwargs)

    keylist_store(instr, signing, runner).install(make_keylist(signing, seq=2), NOW)
    assert len(calls) >= 2


def edited_config(tmp_path, changes, absent=()):
    cfg = config()
    for name in absent:
        cfg.pop(name, None)
    cfg.update(changes)
    path = tmp_path / "edited-agent.conf"
    # Model a local edit, bypassing any writer normalization. The normal loader
    # must keep staging usable and retain the raw evidence for contained parsing.
    path.write_text("\n".join("%s = %s" % pair for pair in sorted(cfg.items())) + "\n")
    return path, agent_config.load(str(path))


@pytest.mark.parametrize("record", [
    json.dumps({"key_id": KEY_ID, "value": KEY.hex()}, sort_keys=True),
    '{"value":"%s","key_id":"%s"}' % (KEY.hex(), KEY_ID),
    '{"key_id":"%s","key_id":"%s","value":"%s"}' % (KEY_ID, KEY_ID, KEY.hex()),
    canonical({"key_id": KEY_ID, "value": KEY.hex(), "extra": 1}).decode(),
    canonical({"key_id": KEY_ID.upper(), "value": KEY.hex()}).decode(),
    canonical({"key_id": KEY_ID, "value": KEY.hex().upper()}).decode(),
    canonical({"key_id": KEY_ID[:-1], "value": KEY.hex()}).decode(),
    canonical({"key_id": KEY_ID, "value": KEY.hex()[:-1]}).decode(),
    canonical({"key_id": KEY_ID, "value": NEXT_KEY.hex()}).decode(),
    canonical({"key_id": True, "value": KEY.hex()}).decode(),
    canonical({"key_id": KEY_ID, "value": [1, 2]}).decode(),
    "null", "[]", '"string"', "{broken",
], ids=["spacing", "key-order", "duplicate", "unknown", "uppercase-id",
        "uppercase-value", "short-id", "short-value", "digest-mismatch",
        "id-type", "value-type", "null", "array", "string", "invalid-json"])
def test_edited_instruction_key_encoding_loads_but_rejects_at_use(instr, tmp_path, record):
    path, cfg = edited_config(tmp_path, {"instr_key": record})
    assert cfg["catalog_token"] == "old-token"
    assert cfg["instr_key"] == record
    reject(instr, make_envelope(), "key_rejected", cfg=cfg)
    # A normal unrelated conf rewrite must not silently normalize malformed
    # JSON into usable instruction material or erase the rejected field.
    agent_config.write_conf(str(path), cfg)
    assert agent_config.load(str(path))["instr_key"] == record


def test_malformed_previous_and_lone_previous_never_form_usable_key_selection(instr, tmp_path):
    valid = canonical({"key_id": KEY_ID, "value": KEY.hex()}).decode()
    _, bad_pair = edited_config(tmp_path, {"instr_key_prev": "{broken"})
    assert bad_pair["instr_key_prev"] == "{broken"
    assert bad_pair["catalog_token"] == "old-token"
    reject(instr, make_envelope(), "key_rejected", cfg=bad_pair)
    _, lone = edited_config(tmp_path, {"instr_key_prev": valid}, absent=("instr_key",))
    assert "instr_key" not in lone
    assert lone["instr_key_prev"] == valid
    reject(instr, make_envelope(), "key_rejected", cfg=lone)


@pytest.mark.parametrize("shape", ["absent", "current", "pair", "pair-local-key"])
def test_canonical_instruction_config_and_absence_round_trip_unchanged(instr, tmp_path, shape):
    current = canonical({"key_id": KEY_ID, "value": KEY.hex()}).decode()
    previous = canonical({"key_id": NEXT_KEY_ID, "value": NEXT_KEY.hex()}).decode()
    changes = {}
    if shape != "absent":
        changes["instr_key"] = current
    if shape in ("pair", "pair-local-key"):
        changes["instr_key_prev"] = previous
    if shape == "pair-local-key":
        changes["lkg_key"] = "bb" * 32
    path, cfg = edited_config(tmp_path, changes,
                              absent=("instr_key", "instr_key_prev", "lkg_key"))
    assert cfg["catalog_token"] == "old-token"
    agent_config.write_conf(str(path), cfg)
    loaded = agent_config.load(str(path))
    for name in ("instr_key", "instr_key_prev", "lkg_key"):
        assert loaded.get(name) == changes.get(name)
    if shape != "absent":
        assert verify(instr, cfg=loaded)["device"] == part_value()


def test_keylist_timeout_latch_survives_coordinator_restart(instr, signing):
    calls = []

    def timeout(argv, **kwargs):
        if "verify" not in argv:
            return subprocess.run(argv, **kwargs)
        calls.append(argv)
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    raw = make_keylist(signing)

    class KeylistCatalog(RouteCatalog):
        def get_instruction_keylist(self, device_id, etag=None):
            self.requests.append(("keylist", device_id, etag))
            return 200, raw, {"Date": "Mon, 07 Sep 2026 12:00:00 GMT"}

    state = {}
    for attempt in range(5):
        instr.run_instruction_step(
            cfg=config(), state=state, catalog=KeylistCatalog(), hints={"keylist_seq": 1},
            catalog_date=NOW, platform="guestshell", work_dir=str(signing["work"]),
            boot_id=BOOT, monotonic_now=10,
            verifier=ssh_verifier(instr, signing, timeout),
            persist_config=lambda updated: None, emit=lambda *args: None)
        bag = state["instructions"]
        assert bag["verifier_timeout_digest"] == hashlib.sha256(raw).hexdigest()
        assert bag["verifier_timeout_count"] == min(attempt + 1, 3)
        assert bag["verifier_timeout_boot_id"] == BOOT
        state = json.loads(json.dumps(state))
    assert len(calls) == 3
    assert not any(path.exists() for path in keylist_paths(signing))


@pytest.mark.parametrize("malformed", ["", "AB" * 32, "b" * 63, "b" * 65,
                                       "g" * 64, "null", "12", '"' + "bb" * 32 + '"'],
                         ids=["empty", "uppercase", "short", "long", "nonhex",
                              "null", "number", "json-string"])
def test_malformed_local_lkg_key_loads_but_is_never_regenerated(instr, tmp_path, malformed):
    verified = verify(instr)
    instr.LKGStore(str(tmp_path), config(), lambda updated: None,
                    AcceptVerifier()).store(verified, verified["device"], {})
    path, cfg = edited_config(tmp_path, {"lkg_key": malformed})
    assert cfg["catalog_token"] == "old-token"
    assert cfg["lkg_key"] == malformed
    before = (tmp_path / "iris-instructions.lkg").read_bytes()
    persisted = []
    store = instr.LKGStore(str(tmp_path), cfg,
                           lambda updated: persisted.append(copy.deepcopy(updated)),
                           AcceptVerifier())
    with pytest.raises(instr.InstructionError) as caught:
        store.load(device_id="sw1", platform="guestshell", authenticated_date=NOW,
                   monotonic_now=10, boot_id=BOOT, state={})
    assert caught.value.state == "lkg_unreadable"
    assert persisted == []
    assert cfg["lkg_key"] == malformed
    assert agent_config.load(str(path))["lkg_key"] == malformed
    assert (tmp_path / "iris-instructions.lkg").read_bytes() == before
