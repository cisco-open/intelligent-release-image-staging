# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Pure IRIS instruction framing, cryptography, and closed-schema checks."""

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import struct


INSTR_MAGIC = b"IRIS-INSTR/1"
ROLE_MAGIC = b"IRIS-ROLE/1"
INSTR_RESPONSE_MAX = 256 * 1024
MAX_PLAINTEXT = INSTR_RESPONSE_MAX
MAX_KDF_BYTES = 96
MAX_ALLOWED = 1000
MAX_RULES = 4096
MAX_I63 = (1 << 63) - 1
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
DEVICE_ID = re.compile(r"^(?!seeder$)[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
ROLE = re.compile(
    r"^(?:default|(?!(?:quarantine|origin|seeder|legacy)$)"
    r"[a-z0-9][a-z0-9._-]{0,31})$")
PLATFORM = re.compile(r"^(?:guestshell|iox|router|xr-appmgr)$")

QOS_FIELDS = (
    "max_peers", "seed_up_bps", "seed_down_bps", "leech_up_bps",
    "leech_down_bps", "overall_up_bps", "overall_down_bps",
    "max_concurrent", "request_peer_speed_limit_bps",
)
CONTROL_FIELDS = ("catalog_tick_s", "telemetry_every_ticks",
                  "telemetry_pause")
QOS_RANGES = {
    "max_peers": (1, 1000),
    "seed_up_bps": (0, 10_000_000_000),
    "seed_down_bps": (0, 10_000_000_000),
    "leech_up_bps": (0, 10_000_000_000),
    "leech_down_bps": (0, 10_000_000_000),
    "overall_up_bps": (0, 10_000_000_000),
    "overall_down_bps": (0, 10_000_000_000),
    "max_concurrent": (1, 1000),
    "request_peer_speed_limit_bps": (0, 1_000_000_000),
}
RATE_FIELDS = frozenset((
    "seed_up_bps", "seed_down_bps", "leech_up_bps", "leech_down_bps",
    "overall_up_bps", "overall_down_bps",
    "request_peer_speed_limit_bps",
))
MIN_RATE_BPS = 8192
CONTROL_RANGES = {
    "catalog_tick_s": (60, 900),
    "telemetry_every_ticks": (1, 60),
}

# Device assertions are distinct from the server's desired QoS values above.
# These are the seven global/default aria2 observations; individual active
# downloads contribute only anonymous, bounded drift facts.
APPLIED_FIELDS = (
    "bt_max_peers", "max_upload_limit", "max_download_limit", "overall_up",
    "overall_down", "request_peer_speed_limit", "max_concurrent",
)
INSTR_STATES = frozenset((
    "none", "applied", "lkg", "stale_expired", "allowlist_expired",
    "rollback_rejected", "floor_reset", "audience_mismatch", "key_rejected",
    "tamper_rejected", "verifier_missing", "lkg_rejected", "lkg_unreadable",
    "oversize", "reasserted", "instr_unavailable", "instr_pending",
    "instr_forbidden", "tracker-only",
))
INSTR_REASONS = frozenset(("unknown_key", "bad_mac"))
QOS_DRIFT_MAX_ROWS = 47


class InstructionError(ValueError):
    """An instruction value is malformed or cannot be authenticated."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InstructionError("duplicate JSON key")
        result[key] = value
    return result


def canonical_json(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise InstructionError("invalid JSON value") from exc


def parse_json(data):
    if not isinstance(data, bytes):
        raise InstructionError("JSON input must be bytes")
    try:
        text = data.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_constant=lambda _v: (_ for _ in ()).throw(
                               InstructionError("non-finite JSON number")))
    except InstructionError:
        raise
    except (UnicodeError, ValueError, TypeError) as exc:
        raise InstructionError("invalid JSON") from exc
    if canonical_json(value) != data:
        raise InstructionError("JSON is not canonical")
    return value


def pae(*parts):
    if any(not isinstance(part, bytes) for part in parts):
        raise InstructionError("PAE parts must be bytes")
    if len(parts) > (1 << 64) - 1:
        raise InstructionError("too many PAE parts")
    out = bytearray(struct.pack("<Q", len(parts)))
    for part in parts:
        if len(part) > (1 << 64) - 1:
            raise InstructionError("PAE part is too long")
        out.extend(struct.pack("<Q", len(part)))
        out.extend(part)
    return bytes(out)


def sp800_108(key, label, context, length):
    if not all(isinstance(value, bytes) for value in (key, label, context)):
        raise InstructionError("KDF inputs must be bytes")
    if (isinstance(length, bool) or not isinstance(length, int)
            or length <= 0 or length > MAX_KDF_BYTES):
        raise InstructionError("invalid KDF output length")
    if len(label) > 255 or len(context) > 4096:
        raise InstructionError("KDF input is too long")
    bits = length * 8
    blocks = (length + hashlib.sha256().digest_size - 1) // 32
    if blocks > 0xffffffff or bits > 0xffffffff:
        raise InstructionError("invalid KDF output length")
    output = bytearray()
    for counter in range(1, blocks + 1):
        fixed = (struct.pack(">I", counter) + label + b"\x00" + context
                 + struct.pack(">I", bits))
        output.extend(hmac.new(key, fixed, hashlib.sha256).digest())
    return bytes(output[:length])


def instruction_key_id(key):
    if not isinstance(key, bytes) or len(key) != 32:
        raise InstructionError("instruction key must be 32 bytes")
    return hashlib.sha256(key).hexdigest()


def derive_keys(key, device_id, key_id):
    _device_id(device_id)
    _digest64(key_id, "key_id")
    if instruction_key_id(key) != key_id:
        raise InstructionError("instruction key identity mismatch")
    context = pae(device_id.encode("utf-8"), key_id.encode("ascii"))
    material = sp800_108(key, b"iris-instr-v1", context, 96)
    return material[:32], material[32:64], material[64:]


def derive_nonce(k_nonce, device_id, key_id, epoch, instr_serial):
    if not isinstance(k_nonce, bytes) or len(k_nonce) != 32:
        raise InstructionError("nonce key must be 32 bytes")
    _device_id(device_id)
    _digest64(key_id, "key_id")
    _i63(epoch, "epoch")
    _i63(instr_serial, "instr_serial")
    context = pae(device_id.encode("utf-8"), key_id.encode("ascii"),
                  struct.pack(">Q", epoch), struct.pack(">Q", instr_serial))
    return sp800_108(k_nonce, b"iris-instr-nonce-v1", context, 16)


def crypt(k_enc, nonce, data):
    if not isinstance(k_enc, bytes) or len(k_enc) != 32:
        raise InstructionError("encryption key must be 32 bytes")
    if not isinstance(nonce, bytes) or len(nonce) != 16:
        raise InstructionError("nonce must be 16 bytes")
    if not isinstance(data, bytes) or len(data) > MAX_PLAINTEXT:
        raise InstructionError("plaintext is too large")
    out = bytearray(len(data))
    for offset in range(0, len(data), 32):
        counter = offset // 32 + 1
        block = hmac.new(k_enc, nonce + struct.pack(">I", counter),
                         hashlib.sha256).digest()
        chunk = data[offset:offset + 32]
        for index, value in enumerate(chunk):
            out[offset + index] = value ^ block[index]
    return bytes(out)


def compute_tag(k_mac, header, role_body, signature, nonce, ciphertext):
    if not isinstance(k_mac, bytes) or len(k_mac) != 32:
        raise InstructionError("MAC key must be 32 bytes")
    return hmac.new(k_mac, pae(header, role_body, signature, nonce,
                               ciphertext), hashlib.sha256).digest()


def _b64(value):
    return base64.b64encode(value)


def _unb64(line):
    try:
        decoded = base64.b64decode(line, validate=True)
    except (ValueError, TypeError) as exc:
        raise InstructionError("invalid base64") from exc
    if _b64(decoded) != line:
        raise InstructionError("noncanonical base64")
    return decoded


def frame_envelope(header, role_body, signature, nonce, ciphertext, tag):
    values = (header, role_body, signature, nonce, ciphertext, tag)
    if any(not isinstance(item, bytes) for item in values):
        raise InstructionError("envelope components must be bytes")
    framed = b"\n".join((INSTR_MAGIC,) + tuple(_b64(item) for item in values)) \
        + b"\n"
    if len(framed) > INSTR_RESPONSE_MAX:
        raise InstructionError("instruction envelope is too large")
    return framed


def parse_envelope(framed):
    if not isinstance(framed, bytes):
        raise InstructionError("instruction envelope must be bytes")
    if len(framed) > INSTR_RESPONSE_MAX:
        raise InstructionError("instruction envelope is too large")
    if b"\r" in framed or not framed.endswith(b"\n"):
        raise InstructionError("invalid instruction framing")
    lines = framed[:-1].split(b"\n")
    if len(lines) != 7 or lines[0] != INSTR_MAGIC or any(not line for line in lines):
        raise InstructionError("invalid instruction framing")
    components = tuple(_unb64(line) for line in lines[1:])
    header, role_body, signature, nonce, ciphertext, tag = components
    validate_header(parse_json(header))
    validate_role_body(parse_json(role_body))
    if not signature or len(nonce) != 16 or len(tag) != 32:
        raise InstructionError("invalid instruction component")
    return components


def seal(header_obj, role_body, signature, key):
    if not isinstance(header_obj, dict) or "_part" not in header_obj:
        raise InstructionError("seal requires internal _part")
    visible = dict(header_obj)
    part = visible.pop("_part")
    return seal_parts(visible, part, role_body, signature, key)


def seal_parts(header_obj, part_obj, role_body, signature, key):
    header_obj = dict(header_obj)
    plaintext = canonical_json(part_obj)
    header_obj["ct_len"] = len(plaintext)
    validate_part(part_obj, issued_at=header_obj.get("issued_at"),
                  expires_at=header_obj.get("expires_at"))
    header_obj = validate_header(header_obj)
    role = validate_role_body(parse_json(role_body))
    if hashlib.sha256(role_body).hexdigest() != \
            header_obj["role_body_sha256"] \
            or role["role_gen"] != header_obj["role_gen"] \
            or role["role"] != header_obj["role"] \
            or role["issued_at"] != header_obj["issued_at"] \
            or role["expires_at"] != header_obj["expires_at"]:
        raise InstructionError("role body identity mismatch")
    header = canonical_json(header_obj)
    k_enc, k_mac, k_nonce = derive_keys(
        key, header_obj["device_id"], header_obj["key_id"])
    nonce = derive_nonce(k_nonce, header_obj["device_id"], header_obj["key_id"],
                         header_obj["epoch"], header_obj["instr_serial"])
    ciphertext = crypt(k_enc, nonce, plaintext)
    tag = compute_tag(k_mac, header, role_body, signature, nonce, ciphertext)
    return frame_envelope(header, role_body, signature, nonce, ciphertext, tag)


def open_parts(framed, key, before_decrypt=None):
    header_b, role_b, signature, nonce, ciphertext, tag = parse_envelope(framed)
    header = validate_header(parse_json(header_b))
    role = validate_role_body(parse_json(role_b))
    if hashlib.sha256(role_b).hexdigest() != header["role_body_sha256"]:
        raise InstructionError("role body digest mismatch")
    if role["role_gen"] != header["role_gen"] \
            or role["role"] != header["role"] \
            or role["issued_at"] != header["issued_at"] \
            or role["expires_at"] != header["expires_at"]:
        raise InstructionError("role body identity mismatch")
    k_enc, k_mac, k_nonce = derive_keys(key, header["device_id"],
                                        header["key_id"])
    expected_nonce = derive_nonce(k_nonce, header["device_id"],
                                  header["key_id"], header["epoch"],
                                  header["instr_serial"])
    if not hmac.compare_digest(nonce, expected_nonce):
        raise InstructionError("instruction nonce mismatch")
    expected_tag = compute_tag(k_mac, header_b, role_b, signature, nonce,
                               ciphertext)
    if not hmac.compare_digest(tag, expected_tag):
        raise InstructionError("instruction authentication failed")
    if len(ciphertext) != header["ct_len"]:
        raise InstructionError("ciphertext length mismatch")
    if before_decrypt is not None:
        before_decrypt()
    part = validate_part(parse_json(crypt(k_enc, nonce, ciphertext)),
                         issued_at=header["issued_at"],
                         expires_at=header["expires_at"])
    if part["peers"]["allowed_expires_at"] != header["allowed_expires_at"]:
        raise InstructionError("peer expiry mismatch")
    return header, role_b, signature, part


def frame_role(role_body, signature):
    if not isinstance(role_body, bytes) or not isinstance(signature, bytes) \
            or not signature:
        raise InstructionError("invalid role artifact component")
    validate_role_body(parse_json(role_body))
    framed = b"\n".join((ROLE_MAGIC, _b64(role_body), _b64(signature))) + b"\n"
    if len(framed) > INSTR_RESPONSE_MAX:
        raise InstructionError("role artifact is too large")
    return framed


def parse_role(framed):
    if not isinstance(framed, bytes) or len(framed) > INSTR_RESPONSE_MAX \
            or b"\r" in framed \
            or not framed.endswith(b"\n"):
        raise InstructionError("invalid role artifact framing")
    lines = framed[:-1].split(b"\n")
    if len(lines) != 3 or lines[0] != ROLE_MAGIC or any(not line for line in lines):
        raise InstructionError("invalid role artifact framing")
    body, signature = _unb64(lines[1]), _unb64(lines[2])
    validate_role_body(parse_json(body))
    if not signature:
        raise InstructionError("invalid role signature")
    return body, signature


def _closed(value, required, optional=()):
    if not isinstance(value, dict):
        raise InstructionError("object required")
    keys = set(value)
    required = set(required)
    optional = set(optional)
    if not required <= keys or keys - required - optional:
        raise InstructionError("invalid object schema")
    return value


def _i63(value, name):
    if isinstance(value, bool) or not isinstance(value, int) \
            or value < 0 or value > MAX_I63:
        raise InstructionError("invalid %s" % name)
    return value


def _attestation_integers(value, fields):
    _closed(value, fields)
    return {name: _i63(value[name], name) for name in fields}


def _attestation_drift_pair(value):
    pair = _attestation_integers(value, ("expected", "observed"))
    if pair["expected"] == pair["observed"]:
        raise InstructionError("drift values must differ")
    return pair


def _attestation_drift(value):
    _closed(value, ("options",), ("blocklist_revision", "blocklist_rules"))
    rows = value["options"]
    if not isinstance(rows, list) or len(rows) > QOS_DRIFT_MAX_ROWS:
        raise InstructionError("invalid drift observations")
    clean = {"options": []}
    for row in rows:
        _closed(row, ("option", "expected", "observed"))
        if not isinstance(row["option"], str) \
                or row["option"] not in APPLIED_FIELDS:
            raise InstructionError("invalid drift option")
        pair = _attestation_drift_pair({
            "expected": row["expected"], "observed": row["observed"]})
        clean["options"].append(dict(pair, option=row["option"]))
    for name in ("blocklist_revision", "blocklist_rules"):
        if name in value:
            clean[name] = _attestation_drift_pair(value[name])
    if not rows and len(clean) == 1:
        raise InstructionError("empty drift observations")
    return clean


def sanitize_instruction_attestation(data):
    """Project copied, bounded device assertions, omitting invalid units.

    This is not compliance verification. Unknown top-level fields are ignored;
    unknown nested fields reject their complete applied/drift observation. No
    identifier, peer address, arbitrary aria2 option or free text is retained.
    """
    if not isinstance(data, dict):
        return {}
    clean = {}
    if "instr_protocol" in data:
        # Null is the bounded unknown marker. Preserve present-invalid versus
        # absent so malformed or future agents are never presented as legacy.
        marker = data["instr_protocol"]
        clean["instr_protocol"] = 1 if type(marker) is int and marker == 1 else None
    if "applied" in data:
        try:
            clean["applied"] = _attestation_integers(data["applied"], APPLIED_FIELDS)
        except InstructionError:
            pass
    state = data.get("instr_state")
    if isinstance(state, str) and state in INSTR_STATES:
        if state == "key_rejected":
            reason = data.get("instr_reason")
            if isinstance(reason, str) and reason in INSTR_REASONS:
                clean.update(instr_state=state, instr_reason=reason)
        elif "instr_reason" not in data:
            clean["instr_state"] = state
    identity_fields = ("instr_epoch", "instr_serial", "instr_policy_revision")
    if "instr_epoch" in data or "instr_policy_revision" in data:
        identity = {name: data[name] for name in identity_fields if name in data}
        try:
            clean.update(_attestation_integers(identity, identity_fields))
        except InstructionError:
            pass
    elif "instr_serial" in data:
        # Preserve old stored reports without inventing an accepted identity.
        try:
            clean["instr_serial"] = _i63(data["instr_serial"], "instr_serial")
        except InstructionError:
            pass
    if type(data.get("pointer_skew")) is bool:
        clean["pointer_skew"] = data["pointer_skew"]
    level = data.get("verify_level")
    if isinstance(level, str) and level in ("sig", "none"):
        clean["verify_level"] = level
    if "blocklist_rules" in data or "blocklist_revision" in data:
        pair = {name: data[name] for name in (
            "blocklist_rules", "blocklist_revision") if name in data}
        try:
            clean.update(_attestation_integers(
                pair, ("blocklist_rules", "blocklist_revision")))
        except InstructionError:
            pass
    if "qos_drift" in data:
        try:
            clean["qos_drift"] = _attestation_drift(data["qos_drift"])
        except InstructionError:
            pass
    return clean


def _digest64(value, name):
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise InstructionError("invalid %s" % name)
    return value


def _device_id(value):
    if not isinstance(value, str) or DEVICE_ID.fullmatch(value) is None:
        raise InstructionError("invalid device_id")
    return value


def _role(value):
    if not isinstance(value, str) or ROLE.fullmatch(value) is None:
        raise InstructionError("invalid role")
    return value


def validate_qos(value, partial=False):
    _closed(value, () if partial else QOS_FIELDS,
            QOS_FIELDS if partial else ())
    for key, item in value.items():
        _i63(item, key)
        low, high = QOS_RANGES[key]
        if not low <= item <= high:
            raise InstructionError("invalid %s" % key)
        if key in RATE_FIELDS and item != 0 and item < MIN_RATE_BPS:
            raise InstructionError("invalid %s" % key)
    return value


def validate_control(value, partial=False):
    _closed(value, () if partial else CONTROL_FIELDS,
            CONTROL_FIELDS if partial else ())
    for key, item in value.items():
        if key == "telemetry_pause":
            if not isinstance(item, bool):
                raise InstructionError("invalid telemetry_pause")
        else:
            _i63(item, key)
            low, high = CONTROL_RANGES[key]
            if not low <= item <= high:
                raise InstructionError("invalid %s" % key)
            if key == "catalog_tick_s" and item % 60:
                raise InstructionError("invalid catalog_tick_s")
    return value


def _canonical_networks(values, cap):
    if not isinstance(values, list) or len(values) > cap:
        raise InstructionError("network list exceeds cap")
    result = []
    for value in values:
        if not isinstance(value, str):
            raise InstructionError("invalid IPv4 network")
        try:
            parsed = (ipaddress.IPv4Network(value, strict=True)
                      if "/" in value else ipaddress.IPv4Address(value))
        except ipaddress.AddressValueError as exc:
            raise InstructionError("invalid IPv4 network") from exc
        except ipaddress.NetmaskValueError as exc:
            raise InstructionError("invalid IPv4 network") from exc
        text = str(parsed)
        if value != text:
            raise InstructionError("noncanonical IPv4 network")
        result.append(text)
    if result != sorted(set(result)):
        raise InstructionError("network list is not sorted and unique")
    return values


def validate_peers(value, expires_at=None):
    if not isinstance(value, dict):
        raise InstructionError("invalid peers")
    mode = value.get("mode")
    if mode == "allow":
        _closed(value, ("mode", "allowed", "include_origin",
                        "allowed_expires_at"))
        _canonical_networks(value["allowed"], MAX_ALLOWED)
    elif mode == "deny":
        _closed(value, ("mode", "rules", "include_origin",
                        "allowed_expires_at"))
        _canonical_networks(value["rules"], MAX_RULES)
    elif mode == "tracker-only":
        _closed(value, ("mode", "include_origin", "allowed_expires_at"))
    else:
        raise InstructionError("invalid peer mode")
    if not isinstance(value["include_origin"], bool):
        raise InstructionError("invalid include_origin")
    _i63(value["allowed_expires_at"], "allowed_expires_at")
    if expires_at is not None and value["allowed_expires_at"] > expires_at:
        raise InstructionError("peer expiry exceeds stamp expiry")
    return value


def validate_part(value, issued_at=None, expires_at=None):
    _closed(value, ("peers", "qos_override", "control_override", "server_time"))
    validate_peers(value["peers"], expires_at=expires_at)
    validate_qos(value["qos_override"], partial=True)
    validate_control(value["control_override"], partial=True)
    _i63(value["server_time"], "server_time")
    if issued_at is not None and value["server_time"] != issued_at:
        raise InstructionError("part server_time mismatch")
    if issued_at is not None \
            and value["peers"]["allowed_expires_at"] < issued_at:
        raise InstructionError("peer expiry precedes stamp issuance")
    return value


def validate_role_body(value):
    _closed(value,
            ("v", "role", "restricted", "role_gen", "issued_at",
             "expires_at", "server_time", "qos", "control", "on_stale"),
            ("allowed_nets",))
    if isinstance(value["v"], bool) or not isinstance(value["v"], int) \
            or value["v"] != 1:
        raise InstructionError("invalid role version")
    _role(value["role"])
    if not isinstance(value["restricted"], bool):
        raise InstructionError("invalid restricted")
    _digest64(value["role_gen"], "role_gen")
    issued = _i63(value["issued_at"], "issued_at")
    expires = _i63(value["expires_at"], "expires_at")
    if expires <= issued or expires - issued > 604800:
        raise InstructionError("invalid role lifetime")
    if _i63(value["server_time"], "server_time") != issued:
        raise InstructionError("role server_time mismatch")
    validate_qos(value["qos"])
    validate_control(value["control"])
    if value["on_stale"] not in ("keep", "defaults"):
        raise InstructionError("invalid on_stale")
    if "allowed_nets" in value:
        _canonical_networks(value["allowed_nets"], MAX_ALLOWED)
    return value


def validate_header(value):
    required = (
        "v", "device_id", "platform", "epoch", "instr_serial",
        "policy_revision", "issued_at", "expires_at", "server_time",
        "verify_level", "key_id", "role", "role_gen",
        "role_body_sha256", "ct_len", "allowed_expires_at", "degraded",
    )
    _closed(value, required, ("info_hash",))
    if isinstance(value["v"], bool) or not isinstance(value["v"], int) \
            or value["v"] != 1:
        raise InstructionError("invalid instruction version")
    _device_id(value["device_id"])
    if not isinstance(value["platform"], str) \
            or PLATFORM.fullmatch(value["platform"]) is None:
        raise InstructionError("invalid platform")
    _i63(value["epoch"], "epoch")
    _i63(value["instr_serial"], "instr_serial")
    _i63(value["policy_revision"], "policy_revision")
    issued = _i63(value["issued_at"], "issued_at")
    expires = _i63(value["expires_at"], "expires_at")
    if issued < value["epoch"] \
            or expires <= issued or expires - issued > 604800:
        raise InstructionError("invalid instruction lifetime")
    if _i63(value["server_time"], "server_time") != issued:
        raise InstructionError("instruction server_time mismatch")
    if value["verify_level"] != "sig":
        raise InstructionError("invalid verify_level")
    _digest64(value["key_id"], "key_id")
    _role(value["role"])
    _digest64(value["role_gen"], "role_gen")
    _digest64(value["role_body_sha256"], "role_body_sha256")
    _i63(value["ct_len"], "ct_len")
    allowed_expiry = _i63(value["allowed_expires_at"], "allowed_expires_at")
    if allowed_expiry < issued or allowed_expiry > expires:
        raise InstructionError("peer expiry exceeds stamp expiry")
    if not isinstance(value["degraded"], bool):
        raise InstructionError("invalid degraded")
    if "info_hash" in value and (not isinstance(value["info_hash"], str)
                                 or HEX40.fullmatch(value["info_hash"]) is None):
        raise InstructionError("invalid info_hash")
    return value


def validate_stamp(value):
    _closed(value, (
        "epoch", "instr_serial", "policy_revision", "platform", "role",
        "role_gen", "role_body_sha256", "key_id", "verify_level",
        "issued_at", "expires_at", "degraded", "part",
    ))
    part = value["part"]
    validate_part(part, issued_at=value["issued_at"],
                  expires_at=value["expires_at"])
    synthetic = {key: value[key] for key in (
        "epoch", "instr_serial", "policy_revision", "platform", "role",
        "role_gen", "role_body_sha256", "key_id", "verify_level",
        "issued_at", "expires_at", "degraded")}
    synthetic.update({
        "v": 1, "device_id": "validation", "server_time": value.get("issued_at"),
        "ct_len": len(canonical_json(part)),
        "allowed_expires_at": part["peers"]["allowed_expires_at"],
    })
    validate_header(synthetic)
    return value


def stamp_header(device_id, stamp):
    validate_stamp(stamp)
    header = {key: stamp[key] for key in (
        "epoch", "instr_serial", "policy_revision", "platform", "role",
        "role_gen", "role_body_sha256", "key_id", "verify_level",
        "issued_at", "expires_at", "degraded")}
    header.update({
        "v": 1,
        "device_id": device_id,
        "server_time": stamp["issued_at"],
        "ct_len": len(canonical_json(stamp["part"])),
        "allowed_expires_at": stamp["part"]["peers"]["allowed_expires_at"],
    })
    return validate_header(header)


def desired_digest(stamp_without_serial):
    if not isinstance(stamp_without_serial, dict) or "instr_serial" in stamp_without_serial:
        raise InstructionError("invalid desired stamp")
    candidate = dict(stamp_without_serial, instr_serial=0)
    validate_stamp(candidate)
    return hashlib.sha256(canonical_json(stamp_without_serial)).hexdigest()


def daily_offset(device_id):
    _device_id(device_id)
    digest = hashlib.sha256(
        b"iris-instr-daily-v1\0" + device_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % 86400
