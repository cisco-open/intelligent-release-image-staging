# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bounded device instruction verification and durable last-known-good custody.

Network envelopes and local LKG records have separate cryptographic domains.
No method installs software or applies aria2 options. The tick coordinator
contains instruction failures and exposes only bounded attestation facts.
"""

import base64
import copy
import email.utils
import errno
import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
import secrets
import stat
import struct
import subprocess
import tempfile
import threading
import time


class InstructionError(ValueError):
    def __init__(self, state, reason=None):
        self.state = state
        self.reason = reason
        ValueError.__init__(self, state)


class _Invalid(ValueError):
    pass


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

_TORRENT_OPTION_CONTEXT = threading.local()
_KRL_UNSET = object()


def torrent_option_context():
    """Return the process-wide context shared by every agent module load."""
    return _TORRENT_OPTION_CONTEXT

def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _Invalid("duplicate JSON key")
        result[key] = value
    return result

def canonical_json(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise _Invalid("invalid JSON value") from exc

def parse_json(data):
    if not isinstance(data, bytes):
        raise _Invalid("JSON input must be bytes")
    try:
        text = data.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_pairs,
                           parse_constant=lambda _v: (_ for _ in ()).throw(
                               _Invalid("non-finite JSON number")))
    except _Invalid:
        raise
    except (UnicodeError, ValueError, TypeError) as exc:
        raise _Invalid("invalid JSON") from exc
    if canonical_json(value) != data:
        raise _Invalid("JSON is not canonical")
    return value

def pae(*parts):
    if any(not isinstance(part, bytes) for part in parts):
        raise _Invalid("PAE parts must be bytes")
    if len(parts) > (1 << 64) - 1:
        raise _Invalid("too many PAE parts")
    out = bytearray(struct.pack("<Q", len(parts)))
    for part in parts:
        if len(part) > (1 << 64) - 1:
            raise _Invalid("PAE part is too long")
        out.extend(struct.pack("<Q", len(part)))
        out.extend(part)
    return bytes(out)

def sp800_108(key, label, context, length):
    if not all(isinstance(value, bytes) for value in (key, label, context)):
        raise _Invalid("KDF inputs must be bytes")
    if (isinstance(length, bool) or not isinstance(length, int)
            or length <= 0 or length > MAX_KDF_BYTES):
        raise _Invalid("invalid KDF output length")
    if len(label) > 255 or len(context) > 4096:
        raise _Invalid("KDF input is too long")
    bits = length * 8
    blocks = (length + hashlib.sha256().digest_size - 1) // 32
    if blocks > 0xffffffff or bits > 0xffffffff:
        raise _Invalid("invalid KDF output length")
    output = bytearray()
    for counter in range(1, blocks + 1):
        fixed = (struct.pack(">I", counter) + label + b"\x00" + context
                 + struct.pack(">I", bits))
        output.extend(hmac.new(key, fixed, hashlib.sha256).digest())
    return bytes(output[:length])

def instruction_key_id(key):
    if not isinstance(key, bytes) or len(key) != 32:
        raise _Invalid("instruction key must be 32 bytes")
    return hashlib.sha256(key).hexdigest()

def derive_nonce(k_nonce, device_id, key_id, epoch, instr_serial):
    if not isinstance(k_nonce, bytes) or len(k_nonce) != 32:
        raise _Invalid("nonce key must be 32 bytes")
    _device_id(device_id)
    _digest64(key_id, "key_id")
    _i63(epoch, "epoch")
    _i63(instr_serial, "instr_serial")
    context = pae(device_id.encode("utf-8"), key_id.encode("ascii"),
                  struct.pack(">Q", epoch), struct.pack(">Q", instr_serial))
    return sp800_108(k_nonce, b"iris-instr-nonce-v1", context, 16)

def crypt(k_enc, nonce, data):
    if not isinstance(k_enc, bytes) or len(k_enc) != 32:
        raise _Invalid("encryption key must be 32 bytes")
    if not isinstance(nonce, bytes) or len(nonce) != 16:
        raise _Invalid("nonce must be 16 bytes")
    if not isinstance(data, bytes) or len(data) > MAX_PLAINTEXT:
        raise _Invalid("plaintext is too large")
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
        raise _Invalid("MAC key must be 32 bytes")
    return hmac.new(k_mac, pae(header, role_body, signature, nonce,
                               ciphertext), hashlib.sha256).digest()

def _b64(value):
    return base64.b64encode(value)

def _unb64(line):
    try:
        decoded = base64.b64decode(line, validate=True)
    except (ValueError, TypeError) as exc:
        raise _Invalid("invalid base64") from exc
    if _b64(decoded) != line:
        raise _Invalid("noncanonical base64")
    return decoded

def _closed(value, required, optional=()):
    if not isinstance(value, dict):
        raise _Invalid("object required")
    keys = set(value)
    required = set(required)
    optional = set(optional)
    if not required <= keys or keys - required - optional:
        raise _Invalid("invalid object schema")
    return value

def _i63(value, name):
    if isinstance(value, bool) or not isinstance(value, int) \
            or value < 0 or value > MAX_I63:
        raise _Invalid("invalid %s" % name)
    return value

def _digest64(value, name):
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        raise _Invalid("invalid %s" % name)
    return value

def _device_id(value):
    if not isinstance(value, str) or DEVICE_ID.fullmatch(value) is None:
        raise _Invalid("invalid device_id")
    return value

def _role(value):
    if not isinstance(value, str) or ROLE.fullmatch(value) is None:
        raise _Invalid("invalid role")
    return value

def validate_qos(value, partial=False):
    _closed(value, () if partial else QOS_FIELDS,
            QOS_FIELDS if partial else ())
    for key, item in value.items():
        _i63(item, key)
        low, high = QOS_RANGES[key]
        if not low <= item <= high:
            raise _Invalid("invalid %s" % key)
        if key in RATE_FIELDS and item != 0 and item < MIN_RATE_BPS:
            raise _Invalid("invalid %s" % key)
    return value

def validate_control(value, partial=False):
    _closed(value, () if partial else CONTROL_FIELDS,
            CONTROL_FIELDS if partial else ())
    for key, item in value.items():
        if key == "telemetry_pause":
            if not isinstance(item, bool):
                raise _Invalid("invalid telemetry_pause")
        else:
            _i63(item, key)
            low, high = CONTROL_RANGES[key]
            if not low <= item <= high:
                raise _Invalid("invalid %s" % key)
            if key == "catalog_tick_s" and item % 60:
                raise _Invalid("invalid catalog_tick_s")
    return value

def _canonical_networks(values, cap):
    if not isinstance(values, list) or len(values) > cap:
        raise _Invalid("network list exceeds cap")
    result = []
    for value in values:
        if not isinstance(value, str):
            raise _Invalid("invalid IPv4 network")
        try:
            parsed = (ipaddress.IPv4Network(value, strict=True)
                      if "/" in value else ipaddress.IPv4Address(value))
        except ipaddress.AddressValueError as exc:
            raise _Invalid("invalid IPv4 network") from exc
        except ipaddress.NetmaskValueError as exc:
            raise _Invalid("invalid IPv4 network") from exc
        text = str(parsed)
        if value != text:
            raise _Invalid("noncanonical IPv4 network")
        result.append(text)
    if result != sorted(set(result)):
        raise _Invalid("network list is not sorted and unique")
    return values

def validate_peers(value, expires_at=None):
    if not isinstance(value, dict):
        raise _Invalid("invalid peers")
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
        raise _Invalid("invalid peer mode")
    if not isinstance(value["include_origin"], bool):
        raise _Invalid("invalid include_origin")
    _i63(value["allowed_expires_at"], "allowed_expires_at")
    if expires_at is not None and value["allowed_expires_at"] > expires_at:
        raise _Invalid("peer expiry exceeds stamp expiry")
    return value

def validate_part(value, issued_at=None, expires_at=None):
    _closed(value, ("peers", "qos_override", "control_override", "server_time"))
    validate_peers(value["peers"], expires_at=expires_at)
    validate_qos(value["qos_override"], partial=True)
    validate_control(value["control_override"], partial=True)
    _i63(value["server_time"], "server_time")
    if issued_at is not None and value["server_time"] != issued_at:
        raise _Invalid("part server_time mismatch")
    if issued_at is not None \
            and value["peers"]["allowed_expires_at"] < issued_at:
        raise _Invalid("peer expiry precedes stamp issuance")
    return value

def validate_role_body(value):
    _closed(value,
            ("v", "role", "restricted", "role_gen", "issued_at",
             "expires_at", "server_time", "qos", "control", "on_stale"),
            ("allowed_nets",))
    if isinstance(value["v"], bool) or not isinstance(value["v"], int) \
            or value["v"] != 1:
        raise _Invalid("invalid role version")
    _role(value["role"])
    if not isinstance(value["restricted"], bool):
        raise _Invalid("invalid restricted")
    _digest64(value["role_gen"], "role_gen")
    issued = _i63(value["issued_at"], "issued_at")
    expires = _i63(value["expires_at"], "expires_at")
    if expires <= issued or expires - issued > 604800:
        raise _Invalid("invalid role lifetime")
    if _i63(value["server_time"], "server_time") != issued:
        raise _Invalid("role server_time mismatch")
    validate_qos(value["qos"])
    validate_control(value["control"])
    if value["on_stale"] not in ("keep", "defaults"):
        raise _Invalid("invalid on_stale")
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
        raise _Invalid("invalid instruction version")
    _device_id(value["device_id"])
    if not isinstance(value["platform"], str) \
            or PLATFORM.fullmatch(value["platform"]) is None:
        raise _Invalid("invalid platform")
    _i63(value["epoch"], "epoch")
    _i63(value["instr_serial"], "instr_serial")
    _i63(value["policy_revision"], "policy_revision")
    issued = _i63(value["issued_at"], "issued_at")
    expires = _i63(value["expires_at"], "expires_at")
    if issued < value["epoch"] \
            or expires <= issued or expires - issued > 604800:
        raise _Invalid("invalid instruction lifetime")
    if _i63(value["server_time"], "server_time") != issued:
        raise _Invalid("instruction server_time mismatch")
    if value["verify_level"] != "sig":
        raise _Invalid("invalid verify_level")
    _digest64(value["key_id"], "key_id")
    _role(value["role"])
    _digest64(value["role_gen"], "role_gen")
    _digest64(value["role_body_sha256"], "role_body_sha256")
    _i63(value["ct_len"], "ct_len")
    allowed_expiry = _i63(value["allowed_expires_at"], "allowed_expires_at")
    if allowed_expiry < issued or allowed_expiry > expires:
        raise _Invalid("peer expiry exceeds stamp expiry")
    if not isinstance(value["degraded"], bool):
        raise _Invalid("invalid degraded")
    if "info_hash" in value and (not isinstance(value["info_hash"], str)
                                 or HEX40.fullmatch(value["info_hash"]) is None):
        raise _Invalid("invalid info_hash")
    return value


LKG_LABEL = b"iris-lkg-v1"
KEYLIST_MAX = 128 * 1024
KRL_MAX = 80 * 1024
KEYLIST_STATE_SCHEMA = "iris-device-instruction-keylist-state/v1"
ROOT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
KEYLIST_NAME = "iris-instruction-keylist.current"
KEYLIST_STATE_NAME = "iris-instruction-keylist-state.json"
LKG_NAME = "iris-instructions.lkg"
BOOTSTRAP_NAME = "iris-instructions.bootstrap"


def boot_id():
    try:
        with open("/proc/sys/kernel/random/boot_id") as stream:
            value = stream.read(128).strip()
        if value:
            return value
    except OSError:
        pass
    # Unavailable boot identity must not make a saved anchor trustworthy.
    return None


def paths_for(platform, cfg):
    stage = cfg.get("stage_dir", "/flash/guest-share/iris")
    work = os.path.join(stage, "iris-work") if platform == "xr-appmgr" else stage
    trust = "/opt/iris/agent" if platform in ("iox", "xr-appmgr") else stage
    return {"work_dir": work, "lkg": os.path.join(work, LKG_NAME),
            "bootstrap": os.path.join(work, BOOTSTRAP_NAME),
            "keylist": os.path.join(work, KEYLIST_NAME),
            "keylist_state": os.path.join(work, KEYLIST_STATE_NAME),
            "signers": os.path.join(trust, "iris-signers.allowed_signers"),
            "root_signers": os.path.join(trust, "iris-root.allowed_signers")}


def _bag(state):
    value = state.get("instructions")
    if not isinstance(value, dict):
        value = {}
        state["instructions"] = value
    return value


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        return False
    try:
        return math.isfinite(value) and value >= 0
    except (OverflowError, TypeError, ValueError):
        return False


def project_clock(state, domain, monotonic_now, boot_id):
    if domain not in ("catalog", "instruction"):
        raise InstructionError("tamper_rejected")
    bag = state.get("instructions", {})
    if not isinstance(bag, dict):
        return None
    name = domain + "_clock"
    anchor = bag.get(name)
    if (not isinstance(anchor, dict) or not boot_id
            or anchor.get("boot_id") != boot_id
            or not _number(monotonic_now)
            or not _number(anchor.get("monotonic"))
            or not _number(anchor.get("effective"))
            or monotonic_now < anchor["monotonic"]):
        bag.pop(name, None)
        return None
    return anchor["effective"] + monotonic_now - anchor["monotonic"]


def observe_clock(state, domain, date, monotonic_now, boot_id):
    if (not _number(date) or not _number(monotonic_now)
            or not isinstance(boot_id, str) or not 1 <= len(boot_id) <= 128):
        raise InstructionError("instr_unavailable")
    projected = project_clock(state, domain, monotonic_now, boot_id)
    if projected is not None and date < projected - 300:
        raise InstructionError("tamper_rejected")
    if projected is None or date > projected:
        _bag(state)[domain + "_clock"] = {
            "effective": date, "monotonic": monotonic_now, "boot_id": boot_id}
    return max(date, projected) if projected is not None else date


def _pair(value):
    if not isinstance(value, dict):
        return None
    try:
        return (_i63(value["epoch"], "epoch"),
                _i63(value["instr_serial"], "instr_serial"))
    except (KeyError, _Invalid):
        return None


def _accepted(bag):
    epoch, serial = bag.get("accepted_epoch"), bag.get("accepted_serial")
    return _pair({"epoch": epoch, "instr_serial": serial})


def note_hint(state, hint, authenticated=True):
    bag = _bag(state)
    pair = _pair(hint) if authenticated else None
    floor = _accepted(bag)
    if pair is None or floor is None or pair >= floor:
        for name in ("lower_hint", "lower_hint_count", "pending_reset"):
            bag.pop(name, None)
        return
    previous = _pair(bag.get("lower_hint"))
    if pair != previous:
        bag.pop("pending_reset", None)
        bag["lower_hint_count"] = 0
    count = bag.get("lower_hint_count", 0)
    if type(count) is not int or not 0 <= count <= 10:
        count = 0
        bag.pop("pending_reset", None)
    bag["lower_hint"] = {"epoch": pair[0], "instr_serial": pair[1]}
    bag["lower_hint_count"] = min(10, count + 1)
    if bag["lower_hint_count"] == 10:
        bag["pending_reset"] = dict(bag["lower_hint"])


def _record_key(raw):
    if not isinstance(raw, str):
        raise _Invalid("invalid key record")
    value = parse_json(raw.encode("ascii"))
    _closed(value, ("key_id", "value"))
    _digest64(value["key_id"], "key_id")
    _digest64(value["value"], "value")
    key = bytes.fromhex(value["value"])
    if instruction_key_id(key) != value["key_id"]:
        raise _Invalid("key identity mismatch")
    return value["key_id"], key


def _select_key(cfg, key_id):
    try:
        current = _record_key(cfg.get("instr_key"))
        previous = _record_key(cfg["instr_key_prev"]) if "instr_key_prev" in cfg else None
        if previous is not None and previous[0] == current[0]:
            raise _Invalid("duplicate key identity")
    except (ValueError, TypeError, UnicodeError):
        raise InstructionError("key_rejected", "unknown_key")
    for candidate in (current, previous):
        if candidate and candidate[0] == key_id:
            return candidate[1]
    raise InstructionError("key_rejected", "unknown_key")


def _material(key, header, label=b"iris-instr-v1"):
    context = pae(header["device_id"].encode("utf-8"), header["key_id"].encode("ascii"))
    return sp800_108(key, label, context, 96)


def _components(raw, magic=INSTR_MAGIC):
    if not isinstance(raw, bytes) or len(raw) > INSTR_RESPONSE_MAX:
        raise InstructionError("oversize")
    if b"\r" in raw or not raw.endswith(b"\n"):
        raise _Invalid("invalid framing")
    lines = raw[:-1].split(b"\n")
    if len(lines) != 7 or lines[0] != magic or any(not line for line in lines):
        raise _Invalid("invalid framing")
    parts = tuple(_unb64(line) for line in lines[1:])
    if not parts[2] or len(parts[3]) != 16 or len(parts[5]) != 32:
        raise _Invalid("invalid component")
    return parts


def _role_digest(body, signature):
    raw = b"IRIS-ROLE/1\n" + _b64(body) + b"\n" + _b64(signature) + b"\n"
    return hashlib.sha256(raw).hexdigest()


def _platform(cfg):
    value = cfg.get("device_platform") or cfg.get("platform")
    if value:
        return "xr-appmgr" if value == "xr" else value
    if cfg.get("mode") == "xr":
        return "xr-appmgr"
    if (cfg.get("stage_dir") == "/bootflash/guest-share/iris"
            and cfg.get("target_fs") == "bootflash:"):
        return "router"
    return "guestshell"


def _identity(header, role, body):
    if (hashlib.sha256(body).hexdigest() != header["role_body_sha256"]
            or any(role[name] != header[name] for name in (
                "role", "role_gen", "issued_at", "expires_at", "server_time"))):
        raise _Invalid("role identity mismatch")


def _authenticate(parts, header, key, label):
    hb, rb, signature, nonce, ciphertext, tag = parts
    material = _material(key, header, label)
    expected_nonce = derive_nonce(material[64:], header["device_id"],
                                  header["key_id"], header["epoch"], header["instr_serial"])
    expected_tag = compute_tag(material[32:64], hb, rb, signature, nonce, ciphertext)
    if not hmac.compare_digest(nonce, expected_nonce) or not hmac.compare_digest(tag, expected_tag):
        raise InstructionError("key_rejected", "bad_mac")
    if len(ciphertext) != header["ct_len"]:
        raise _Invalid("ciphertext length mismatch")
    part = validate_part(parse_json(crypt(material[:32], nonce, ciphertext)),
                         issued_at=header["issued_at"], expires_at=header["expires_at"])
    if part["peers"]["allowed_expires_at"] != header["allowed_expires_at"]:
        raise _Invalid("peer expiry mismatch")
    return part


def _replay(header, digest, state):
    bag = state.get("instructions", {})
    floor = _accepted(bag)
    pair = (header["epoch"], header["instr_serial"])
    if header["v"] < bag.get("v_floor", 1):
        raise InstructionError("rollback_rejected")
    if floor is not None:
        if pair < floor and pair != _pair(bag.get("pending_reset")):
            raise InstructionError("rollback_rejected")
        if pair == floor and digest != bag.get("envelope_digest"):
            raise InstructionError("tamper_rejected")


def verify_envelope(raw, cfg, state, authenticated_date, monotonic_now, boot_id, verifier):
    try:
        parts = _components(raw)
        hb, rb, signature = parts[:3]
        header = validate_header(parse_json(hb))
        if header["device_id"] != cfg.get("device_id") or header["platform"] != _platform(cfg):
            raise InstructionError("audience_mismatch")
        if not verifier.verify(rb, signature, "iris-instructions-v1", "iris-server",
                               header["issued_at"], artifact_digest=_role_digest(rb, signature),
                               boot_id=boot_id):
            raise InstructionError("tamper_rejected")
        key = _select_key(cfg, header["key_id"])
        part = _authenticate(parts, header, key, b"iris-instr-v1")
        role = validate_role_body(parse_json(rb))
        _identity(header, role, rb)
        provisional = copy.deepcopy(state)
        effective = observe_clock(provisional, "instruction", authenticated_date,
                                  monotonic_now, boot_id)
        if header["issued_at"] > authenticated_date + 60 or effective >= header["expires_at"]:
            raise InstructionError("stale_expired" if effective >= header["expires_at"] else "tamper_rejected")
        _replay(header, hashlib.sha256(raw).hexdigest(), state)
        return {"header": header, "role": role, "device": part, "header_bytes": hb,
                "role_body": rb, "signature": signature, "envelope": raw}
    except InstructionError:
        raise
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError, UnicodeError):
        raise InstructionError("tamper_rejected") from None


def apply_verified(verified, state, authenticated_date, monotonic_now, boot_id):
    updated = copy.deepcopy(state)
    bag = _bag(updated)
    header = verified["header"]
    former = _accepted(bag)
    pair = (header["epoch"], header["instr_serial"])
    if former is not None and pair < former:
        bag["floor_reset"] = {"from": list(former), "to": list(pair)}
    bag.update(accepted_epoch=pair[0], accepted_serial=pair[1],
               v_floor=max(bag.get("v_floor", 1), header["v"]),
               envelope_digest=hashlib.sha256(verified["envelope"]).hexdigest())
    for name in ("pending_reset", "lower_hint", "lower_hint_count"):
        bag.pop(name, None)
    observe_clock(updated, "instruction", authenticated_date, monotonic_now, boot_id)
    state.clear()
    state.update(updated)


def _read_bytes(path, cap):
    try:
        with open(path, "rb") as stream:
            data = stream.read(cap + 1)
    except FileNotFoundError:
        return None
    if len(data) > cap:
        raise InstructionError("oversize")
    return data


def _read_bootstrap(path):
    """Read one fixed-name candidate without following or reopening its inode."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise InstructionError("instr_unavailable")
    try:
        observed = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(observed.st_mode):
        raise InstructionError("instr_unavailable")
    # O_NONBLOCK prevents a raced-in FIFO/device from waiting before fstat.
    flags = (os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_NONBLOCK", 0))
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(fd)
        identity = (before.st_dev, before.st_ino, before.st_size,
                    getattr(before, "st_mtime_ns", before.st_mtime),
                    getattr(before, "st_ctime_ns", before.st_ctime))
        if not stat.S_ISREG(before.st_mode):
            raise InstructionError("instr_unavailable")
        if before.st_size > INSTR_RESPONSE_MAX:
            return {"raw": None, "identity": identity,
                    "error": InstructionError("oversize")}
        chunks = []
        remaining = INSTR_RESPONSE_MAX
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        after_identity = (after.st_dev, after.st_ino, after.st_size,
                          getattr(after, "st_mtime_ns", after.st_mtime),
                          getattr(after, "st_ctime_ns", after.st_ctime))
        if after_identity != identity:
            raise InstructionError("instr_unavailable")
        if after.st_size > INSTR_RESPONSE_MAX:
            return {"raw": None, "identity": identity,
                    "error": InstructionError("oversize")}
        raw = b"".join(chunks)
        if len(raw) != after.st_size:
            raise InstructionError("instr_unavailable")
        return {"raw": raw, "identity": identity,
                "error": None}
    finally:
        os.close(fd)


def _unlink_bootstrap(path, identity):
    """Remove only the pathname that still identifies the opened candidate."""
    try:
        current = os.lstat(path)
        current_identity = (
            current.st_dev, current.st_ino, current.st_size,
            getattr(current, "st_mtime_ns", current.st_mtime),
            getattr(current, "st_ctime_ns", current.st_ctime))
        if (not stat.S_ISREG(current.st_mode)
                or current_identity != identity):
            return False
        os.unlink(path)
        _directory_sync(os.path.dirname(path))
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _directory_sync(directory):
    fd = None
    try:
        fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        os.fsync(fd)
    except OSError as exc:
        if exc.errno not in (errno.EINVAL, errno.ENOTSUP):
            raise
    finally:
        if fd is not None:
            os.close(fd)


def _atomic(path, data):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + os.path.basename(path) + ".", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _directory_sync(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _private(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


class SSHVerifier:
    """Stateless OpenSSH adapter; durable retry policy belongs to the caller."""

    def __init__(self, executable, allowed_signers, root_signers, work_dir, runner=None):
        self.executable = executable
        self.allowed_signers = allowed_signers
        self.root_signers = root_signers
        self.work_dir = work_dir
        self.runner = subprocess.run if runner is None else runner

    def root_lines(self):
        try:
            raw = _read_bytes(self.root_signers, 8192)
            if raw is None or not raw.endswith(b"\n") or b"\r" in raw:
                raise _Invalid("invalid roots")
            lines = raw[:-1].split(b"\n")
            if len(lines) != 2:
                raise _Invalid("invalid roots")
            result = {}
            keys = set()
            pattern = re.compile(
                rb'iris-root:([A-Za-z0-9][A-Za-z0-9_.-]{0,63}) namespaces="iris-keylist-v1" ssh-ed25519 ([A-Za-z0-9+/]+={0,2})')
            for line in lines:
                match = pattern.fullmatch(line)
                if match is None:
                    raise _Invalid("invalid roots")
                root_id = match.group(1).decode("ascii")
                key = _unb64(match.group(2))
                if (len(key) != 51 or key[:19] != b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
                        or root_id in result or key in keys):
                    raise _Invalid("invalid roots")
                result[root_id] = line + b"\n"
                keys.add(key)
            return result
        except (OSError, ValueError, UnicodeError, TypeError):
            raise InstructionError("tamper_rejected") from None

    def _run(self, argv, data=None):
        if not isinstance(self.executable, str) or not os.path.isabs(self.executable):
            raise InstructionError("verifier_missing")
        try:
            result = self.runner([self.executable] + argv, input=data,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 timeout=5)
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            raise InstructionError("verifier_missing", "verifier_timeout") from None
        except OSError:
            raise InstructionError("verifier_missing") from None

    def verify(self, body, signature, namespace, identity, verify_time,
               krl=None, artifact_digest=None, boot_id=None):
        del artifact_digest, boot_id  # The wrapper deliberately owns no retry state.
        if namespace not in ("iris-instructions-v1", "iris-keylist-v1"):
            raise InstructionError("tamper_rejected")
        os.makedirs(self.work_dir, mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".iris-verify-", dir=self.work_dir) as directory:
            signature_path = os.path.join(directory, "signature")
            _private(signature_path, signature)
            signers = self.allowed_signers
            if namespace == "iris-keylist-v1":
                roots = self.root_lines()
                if not identity.startswith("iris-root:") or identity[10:] not in roots:
                    raise InstructionError("tamper_rejected")
                signers = os.path.join(directory, "allowed_signers")
                _private(signers, roots[identity[10:]])
            try:
                formatted_time = time.strftime("%Y%m%d%H%M%SZ", time.gmtime(verify_time))
            except (OSError, OverflowError, ValueError, TypeError):
                raise InstructionError("tamper_rejected") from None
            argv = ["-Y", "verify", "-f", signers, "-I", identity,
                    "-n", namespace, "-s", signature_path, "-O",
                    "verify-time=" + formatted_time]
            if krl is not None:
                krl_path = os.path.join(directory, "revoked.krl")
                _private(krl_path, krl)
                argv.extend(["-r", krl_path])
            return self._run(argv, body)

    def validate_krl(self, data):
        if not data:
            return
        if not data.startswith(b"SSHKRL\n\x00"):
            raise InstructionError("tamper_rejected")
        os.makedirs(self.work_dir, mode=0o700, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".iris-krl-", dir=self.work_dir) as directory:
            path = os.path.join(directory, "candidate.krl")
            _private(path, data)
            if not self._run(["-Q", "-f", path]):
                raise InstructionError("tamper_rejected")


class _GuardedVerifier:
    """Track complete candidate attempts, independently for role and keylist.

    Root nonmatches are part of one keylist attempt. Routine verification of
    an older LKG cannot overwrite the pending candidate's timeout record.
    The per-tick cache also prevents counting the same timeout twice when a
    cached role and an envelope refer to the same signed artifact.
    """

    def __init__(self, verifier, state, boot, krl=None, fallback=False, attempts=None):
        self.verifier, self.state, self.krl = verifier, state, krl
        self.boot = boot if isinstance(boot, str) and 1 <= len(boot) <= 128 else None
        self.is_fallback = fallback
        self.attempts = {} if attempts is None else attempts

    def __getattr__(self, name):
        return getattr(self.verifier, name)

    def fallback(self):
        return _GuardedVerifier(self.verifier, self.state, self.boot, self.krl,
                                fallback=True, attempts=self.attempts)

    def _attempt(self, kind, digest, function, krl=_KRL_UNSET):
        bag = _bag(self.state)
        records = bag.get("verifier_timeouts")
        if not isinstance(records, dict):
            records = {}
        actual_krl = self.krl if krl is _KRL_UNSET else krl
        krl_identity = ("absent" if actual_krl is None else
                        "sha256:" + hashlib.sha256(actual_krl).hexdigest())
        # Three fixed custody slots; never grow a remote-controlled digest map.
        bounded = {}
        for name in ("role", "lkg", "keylist"):
            record = records.get(name)
            if (isinstance(record, dict)
                    and isinstance(record.get("digest"), str)
                    and HEX64.fullmatch(record["digest"]) is not None
                    and type(record.get("count")) is int and 0 <= record["count"] <= 3
                    and "boot_id" in record
                    and (record.get("boot_id") is None or isinstance(record.get("boot_id"), str)
                         and len(record["boot_id"]) <= 128)
                    and isinstance(record.get("krl_identity"), str)
                    and (record["krl_identity"] == "absent"
                         or (record["krl_identity"].startswith("sha256:")
                             and HEX64.fullmatch(record["krl_identity"][7:])
                             is not None))):
                bounded[name] = {field: record[field] for field in (
                    "digest", "count", "boot_id", "krl_identity")}
        records = bounded
        bag["verifier_timeouts"] = records
        shared_kind = "role" if kind == "lkg" else kind
        key = (shared_kind, digest, krl_identity)
        attempted_count = self.attempts.get(key)
        if type(attempted_count) is not int or not 0 <= attempted_count <= 3:
            attempted_count = 0
        previous = records.get(kind)
        if (self.boot is None or not isinstance(previous, dict)
                or previous.get("digest") != digest
                or previous.get("boot_id") != self.boot
                or previous.get("krl_identity") != krl_identity):
            previous = {"digest": digest, "count": attempted_count,
                        "boot_id": self.boot,
                        "krl_identity": krl_identity}
            records[kind] = previous
        if self.boot is not None and kind in ("role", "lkg"):
            other = records.get("lkg" if kind == "role" else "role", {})
            if (other.get("digest") == digest
                    and other.get("boot_id") == self.boot
                    and other.get("krl_identity") == krl_identity):
                previous["count"] = max(previous["count"], other["count"])
        count = previous.get("count", 0)
        if type(count) is not int or not 0 <= count <= 3:
            count = 0
        count = max(count, attempted_count)
        previous["count"] = count

        def publish():
            if kind in ("role", "lkg"):
                other = records.get("lkg" if kind == "role" else "role", {})
                if (other.get("digest") == digest
                        and other.get("boot_id") == self.boot
                        and other.get("krl_identity") == krl_identity):
                    other["count"] = previous["count"]
            visible = previous
            if not previous["count"]:
                for record in records.values():
                    if (isinstance(record, dict) and record.get("boot_id") == self.boot
                            and type(record.get("count")) is int and record["count"] > 0):
                        visible = record
                        break
            bag.update(verifier_timeout_digest=visible["digest"],
                       verifier_timeout_count=visible["count"],
                       verifier_timeout_boot_id=self.boot)

        if count >= 3 or key in self.attempts:
            publish()
            raise InstructionError("verifier_missing", "verifier_timeout")
        try:
            value = function()
        except InstructionError as exc:
            if exc.reason == "verifier_timeout":
                previous["count"] = min(3, count + 1)
                self.attempts[key] = previous["count"]
            else:
                previous["count"] = 0
            publish()
            raise
        previous["count"] = 0
        publish()
        return value

    def keylist_attempt(self, digest, function, krl=_KRL_UNSET):
        return self._attempt("keylist", digest, function, krl=krl)

    def verify(self, body, signature, namespace, identity, verify_time, **kwargs):
        kwargs.setdefault("krl", self.krl)
        kwargs["boot_id"] = self.boot

        def invoke():
            return self.verifier.verify(body, signature, namespace, identity, verify_time, **kwargs)

        if namespace == "iris-keylist-v1":
            return invoke()
        digest = kwargs.get("artifact_digest") or _role_digest(body, signature)
        return self._attempt("lkg" if self.is_fallback else "role", digest, invoke)


def _parse_keylist(raw):
    if not isinstance(raw, bytes) or len(raw) > KEYLIST_MAX:
        raise InstructionError("oversize")
    try:
        lines = raw.split(b"\n")
        if len(lines) != 5 or lines[0] != b"IRIS-KEYLIST/1" or lines[-1] != b"":
            raise _Invalid("keylist framing")
        meta_bytes, krl, signature = (_unb64(line) for line in lines[1:4])
        if len(meta_bytes) > 4096 or len(krl) > KRL_MAX or len(signature) > 8192:
            raise InstructionError("oversize")
        metadata = parse_json(meta_bytes)
        _closed(metadata, ("v", "keylist_seq", "issued_at", "signer_root_id", "krl_sha256"))
        if type(metadata["v"]) is not int or metadata["v"] != 1:
            raise _Invalid("keylist version")
        if _i63(metadata["keylist_seq"], "sequence") == 0:
            raise _Invalid("keylist sequence")
        _i63(metadata["issued_at"], "issuance")
        if not isinstance(metadata["signer_root_id"], str) or ROOT_ID.fullmatch(metadata["signer_root_id"]) is None:
            raise _Invalid("root identity")
        _digest64(metadata["krl_sha256"], "KRL digest")
        if hashlib.sha256(krl).hexdigest() != metadata["krl_sha256"]:
            raise _Invalid("KRL digest mismatch")
        if krl and not krl.startswith(b"SSHKRL\n\x00"):
            raise _Invalid("KRL format")
        if not signature.startswith(b"-----BEGIN SSH SIGNATURE-----\n"):
            raise _Invalid("signature framing")
        return {"metadata": metadata, "krl": krl, "signature": signature,
                "payload": b"\n".join(lines[:3]) + b"\n",
                "digest": hashlib.sha256(raw).hexdigest()}
    except InstructionError:
        raise
    except (ValueError, TypeError, UnicodeError, KeyError, RecursionError):
        raise InstructionError("tamper_rejected") from None


class KeylistStore:
    def __init__(self, work_dir, verifier):
        self.work_dir, self.verifier = work_dir, verifier
        self.artifact_path = os.path.join(work_dir, KEYLIST_NAME)
        self.state_path = os.path.join(work_dir, KEYLIST_STATE_NAME)
        self.recovery_error = None

    def _state(self):
        raw = _read_bytes(self.state_path, KEYLIST_MAX)
        if raw is None:
            return None
        try:
            # This is local custody metadata rather than a signed canonical
            # artifact.  Accept semantically identical JSON written by an
            # older/runtime helper while retaining duplicate-key, finite-value
            # and closed-shape checks below.
            value = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_pairs,
                parse_constant=lambda _v: (_ for _ in ()).throw(
                    _Invalid("non-finite JSON number")))
            _closed(value, ("schema", "keylist_seq", "artifact_sha256", "krl_sha256",
                            "krl_b64", "issued_at", "verified_root_id"))
            if value["schema"] != KEYLIST_STATE_SCHEMA or _i63(value["keylist_seq"], "sequence") == 0:
                raise _Invalid("state schema")
            _i63(value["issued_at"], "issuance")
            _digest64(value["artifact_sha256"], "artifact digest")
            _digest64(value["krl_sha256"], "KRL digest")
            if not isinstance(value["verified_root_id"], str) or ROOT_ID.fullmatch(value["verified_root_id"]) is None:
                raise _Invalid("root identity")
            krl = _unb64(value["krl_b64"].encode("ascii"))
            if len(krl) > KRL_MAX or hashlib.sha256(krl).hexdigest() != value["krl_sha256"]:
                raise _Invalid("retained KRL mismatch")
            if krl and not krl.startswith(b"SSHKRL\n\x00"):
                raise _Invalid("retained KRL format")
            return value
        except (ValueError, TypeError, UnicodeError, KeyError, AttributeError, RecursionError):
            raise InstructionError("tamper_rejected") from None

    def snapshot(self):
        return copy.deepcopy(self._state())

    def _verified_state(self, parsed, previous, date):
        krl = (None if previous is None else
               _unb64(previous["krl_b64"].encode("ascii")))
        if isinstance(self.verifier, _GuardedVerifier):
            return self.verifier.keylist_attempt(
                parsed["digest"],
                lambda: self._verify_roots(parsed, previous, date, krl),
                krl=krl)
        return self._verify_roots(parsed, previous, date, krl)

    def _verify_roots(self, parsed, previous, date, krl):
        metadata = parsed["metadata"]
        if not _number(date) or metadata["issued_at"] > date + 60:
            raise InstructionError("tamper_rejected")
        self.verifier.validate_krl(parsed["krl"])
        matches = []
        for root_id in self.verifier.root_lines():
            if self.verifier.verify(parsed["payload"], parsed["signature"],
                                    "iris-keylist-v1", "iris-root:" + root_id,
                                    metadata["issued_at"], krl=krl,
                                    artifact_digest=parsed["digest"]):
                matches.append(root_id)
        if len(matches) != 1 or matches[0] != metadata["signer_root_id"]:
            raise InstructionError("tamper_rejected")
        return {"schema": KEYLIST_STATE_SCHEMA, "keylist_seq": metadata["keylist_seq"],
                "artifact_sha256": parsed["digest"], "krl_sha256": metadata["krl_sha256"],
                "krl_b64": _b64(parsed["krl"]).decode("ascii"),
                "issued_at": metadata["issued_at"], "verified_root_id": matches[0]}

    def recover(self):
        self.recovery_error = None
        previous = self._state()
        raw = _read_bytes(self.artifact_path, KEYLIST_MAX)
        if raw is None:
            return previous
        if previous is None:
            raise InstructionError("tamper_rejected")
        parsed = _parse_keylist(raw)
        seq = parsed["metadata"]["keylist_seq"]
        if seq < previous["keylist_seq"]:
            raise InstructionError("tamper_rejected")
        if seq == previous["keylist_seq"]:
            if (parsed["digest"] != previous["artifact_sha256"]
                    or parsed["metadata"]["krl_sha256"] != previous["krl_sha256"]
                    or parsed["metadata"]["issued_at"] != previous["issued_at"]
                    or parsed["metadata"]["signer_root_id"] != previous["verified_root_id"]):
                raise InstructionError("tamper_rejected")
            # Finish a previously failed state directory fsync before exposing it.
            _directory_sync(self.work_dir)
            return previous
        try:
            value = self._verified_state(parsed, previous, parsed["metadata"]["issued_at"])
        except InstructionError as exc:
            # Preserve custody while exposing the rejected candidate fact.
            self.recovery_error = exc
            return previous
        _atomic(self.state_path, canonical_json(value))
        return value

    def install(self, raw, authenticated_date):
        previous = self.recover()
        parsed = _parse_keylist(raw)
        if previous is not None:
            seq = parsed["metadata"]["keylist_seq"]
            if seq < previous["keylist_seq"]:
                raise InstructionError("rollback_rejected")
            if seq == previous["keylist_seq"]:
                if (parsed["digest"] != previous["artifact_sha256"]
                        or not os.path.exists(self.artifact_path)):
                    raise InstructionError("tamper_rejected")
                return copy.deepcopy(previous)
        value = self._verified_state(parsed, previous, authenticated_date)
        _atomic(self.artifact_path, raw)
        _atomic(self.state_path, canonical_json(value))
        return copy.deepcopy(value)


def _local_key(cfg):
    try:
        value = cfg.get("lkg_key")
        _digest64(value, "local key")
        return bytes.fromhex(value)
    except (ValueError, TypeError):
        raise InstructionError("lkg_unreadable") from None


class LKGStore:
    def __init__(self, work_dir, cfg, persist_config, verifier):
        self.work_dir, self.cfg = work_dir, cfg
        self.persist_config, self.verifier = persist_config, verifier
        self.path = os.path.join(work_dir, LKG_NAME)
        self.previous_path = self.path + ".previous"
        # Transient only: stale=defaults deliberately removes the public
        # role/device values, but Task 16 must retain a signature-verified
        # deny posture in memory.  This value is never persisted or attested.
        self.verified_peers = None

    def recover(self, state):
        previous = _read_bytes(self.previous_path, INSTR_RESPONSE_MAX)
        if previous is None:
            return
        current = _read_bytes(self.path, INSTR_RESPONSE_MAX)
        digest = _bag(state).get("lkg_digest")
        if current is not None and hashlib.sha256(current).hexdigest() == digest:
            self.finish()
            return
        if previous == b"IRIS-LKG-ABSENT/1\n" and digest is None:
            if current is not None:
                os.unlink(self.path)
                _directory_sync(self.work_dir)
            self.finish()
            return
        if digest is None or hashlib.sha256(previous).hexdigest() == digest:
            _atomic(self.path, previous)
            self.finish()
            return
        raise InstructionError("lkg_rejected")

    def begin(self, state):
        self.recover(state)
        previous = _read_bytes(self.path, INSTR_RESPONSE_MAX)
        _atomic(self.previous_path, previous if previous is not None else b"IRIS-LKG-ABSENT/1\n")

    def finish(self):
        if os.path.exists(self.previous_path):
            os.unlink(self.previous_path)
            _directory_sync(self.work_dir)

    def store(self, verified, device_part, state):
        try:
            header = validate_header(parse_json(verified["header_bytes"]))
            role = validate_role_body(parse_json(verified["role_body"]))
            _identity(header, role, verified["role_body"])
            validate_part(device_part, header["issued_at"], header["expires_at"])
            if device_part != verified["device"]:
                raise _Invalid("unverified device part")
            plaintext = canonical_json(device_part)
            if len(plaintext) != header["ct_len"]:
                raise _Invalid("device part length")
            if "lkg_key" not in self.cfg:
                mint = getattr(secrets, "token_bytes", None)
                key = mint(32) if callable(mint) else os.urandom(32)
                updated = dict(self.cfg, lkg_key=key.hex())
                self.persist_config(updated)
                self.cfg.update(updated)
            key = _local_key(self.cfg)
            material = _material(key, header, LKG_LABEL)
            nonce = derive_nonce(material[64:], header["device_id"], header["key_id"],
                                 header["epoch"], header["instr_serial"])
            ciphertext = crypt(material[:32], nonce, plaintext)
            components = (verified["header_bytes"], verified["role_body"],
                          verified["signature"], nonce, ciphertext)
            tag = compute_tag(material[32:64], *components)
            raw = b"IRIS-LKG/1\n" + b"\n".join(_b64(item) for item in components + (tag,)) + b"\n"
            if len(raw) > INSTR_RESPONSE_MAX:
                raise InstructionError("oversize")
            _atomic(self.path, raw)
            _bag(state)["lkg_digest"] = hashlib.sha256(raw).hexdigest()
        except InstructionError:
            raise
        except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
            raise InstructionError("lkg_rejected") from None

    def load(self, device_id, platform, authenticated_date, monotonic_now, boot_id, state):
        try:
            self.verified_peers = None
            self.recover(state)
            raw = _read_bytes(self.path, INSTR_RESPONSE_MAX)
            if raw is None:
                raise InstructionError("lkg_unreadable")
            parts = _components(raw, b"IRIS-LKG/1")
            hb, rb, signature = parts[:3]
            header = validate_header(parse_json(hb))
            if header["device_id"] != device_id or header["platform"] != platform:
                raise InstructionError("audience_mismatch")
            key = _local_key(self.cfg)
            if not self.verifier.verify(rb, signature, "iris-instructions-v1", "iris-server",
                                        header["issued_at"], artifact_digest=_role_digest(rb, signature),
                                        boot_id=boot_id):
                raise InstructionError("lkg_rejected")
            try:
                part = _authenticate(parts, header, key, LKG_LABEL)
            except InstructionError:
                raise InstructionError("lkg_unreadable") from None
            role = validate_role_body(parse_json(rb))
            _identity(header, role, rb)
            self.verified_peers = copy.deepcopy(part["peers"])
            bag = state.get("instructions", {})
            if bag.get("lkg_digest") not in (None, hashlib.sha256(raw).hexdigest()):
                raise InstructionError("lkg_rejected")
            pair = (header["epoch"], header["instr_serial"])
            floor = _accepted(bag)
            if header["v"] < bag.get("v_floor", 1) or floor is not None and pair < floor:
                raise InstructionError("rollback_rejected")
            provisional = copy.deepcopy(state)
            effective = project_clock(provisional, "instruction", monotonic_now, boot_id)
            if authenticated_date is not None:
                effective = observe_clock(provisional, "instruction", authenticated_date, monotonic_now, boot_id)
            result = {"header": header, "header_bytes": hb, "role": role,
                      "role_body": rb, "signature": signature, "device": part,
                      "instr_state": "lkg", "on_stale": role["on_stale"]}
            if effective is None or effective >= header["expires_at"]:
                result["instr_state"] = "stale_expired"
                if role["on_stale"] == "defaults":
                    result["device"], result["role"] = None, None
            return result
        except InstructionError:
            raise
        except (OSError, ValueError, TypeError, KeyError, RecursionError, OverflowError):
            raise InstructionError("lkg_rejected") from None


def _date(headers):
    raw = headers.get("Date") if headers is not None else None
    if not isinstance(raw, str):
        raise InstructionError("instr_unavailable")
    try:
        parsed = email.utils.parsedate_to_datetime(raw)
        stamp = parsed.timestamp()
        if parsed.tzinfo is None or email.utils.formatdate(stamp, usegmt=True) != raw:
            raise ValueError
        return stamp
    except (OSError, TypeError, ValueError, OverflowError):
        raise InstructionError("instr_unavailable") from None


def _refresh_instruction_keys(cfg, catalog, persist_config):
    try:
        bag = catalog.refresh_token(cfg["device_id"])
        if not isinstance(bag, dict) or not isinstance(bag.get("catalog_token"), str) or not bag["catalog_token"]:
            return
        expiry = bag["expires_at"]
        if isinstance(expiry, bool) or not math.isfinite(float(expiry)):
            return
        catalog.token = bag["catalog_token"]
        updated = dict(cfg, catalog_token=bag["catalog_token"], token_expires_at=str(expiry))
        for name in ("announce_token", "rpc_secret"):
            if bag.get(name) is not None:
                updated[name] = bag[name]
        if "instr_key" in bag:
            import agent_config
            updated = agent_config.merge_instruction_key_refresh(updated, bag)
        # Live bearer repoint must survive a failed persistence callback.
        cfg.update(updated)
        persist_config(updated)
    except Exception:
        return


def _fact(state, header=None, reason=None):
    result = {"instr_state": state}
    if header is not None:
        result.update(instr_epoch=header["epoch"],
                      instr_serial=header["instr_serial"],
                      instr_policy_revision=header["policy_revision"],
                      verify_level=header["verify_level"])
    if state == "key_rejected" and reason in ("unknown_key", "bad_mac"):
        result["instr_reason"] = reason
    return result


def pointer_skew_fact(state):
    """Project the existing observation latch without changing its state.

    A missing or damaged latch is unknown; it is not evidence of no skew.
    Only the detector establishes/reset its bounded observation count.
    """
    bag = state.get("instructions") if isinstance(state, dict) else None
    count = bag.get("pointer_skew_count") if isinstance(bag, dict) else None
    if type(count) is int and 0 <= count <= 3:
        return {"pointer_skew": count == 3}
    return {}


def _effective(verified):
    if verified is None or verified.get("device") is None:
        return None
    return copy.deepcopy(verified["device"])


def _tracker_only():
    return {"mode": "tracker-only", "include_origin": False}


def _effective_peers(peers, effective_time):
    """Return the private in-memory peer posture from verified plaintext."""
    if not isinstance(peers, dict):
        return _tracker_only(), None
    mode = peers.get("mode")
    if mode == "deny":
        return copy.deepcopy(peers), None
    if mode == "tracker-only":
        return copy.deepcopy(peers), None
    if mode == "allow":
        expires = peers.get("allowed_expires_at")
        if (effective_time is None or isinstance(expires, bool)
                or not isinstance(expires, int) or effective_time >= expires):
            return _tracker_only(), "allowlist_expired"
        return copy.deepcopy(peers), None
    return _tracker_only(), None


def _promote_verified(store, verified, state, authenticated_date,
                      monotonic_now, boot_id, checkpoint):
    """Store, apply, and checkpoint one already verified envelope."""
    header = verified["header"]
    former_pair = _accepted(_bag(state))
    reset_applied = (former_pair is not None
                     and (header["epoch"], header["instr_serial"]) < former_pair)
    prior_state = copy.deepcopy(state)
    store.begin(state)
    try:
        store.store(verified, verified["device"], state)
        apply_verified(
            verified, state, authenticated_date, monotonic_now, boot_id)
        if checkpoint is not None:
            checkpoint(state)
    except Exception:
        # A failed checkpoint may already have replaced the state file.  Keep
        # both local artifacts so restart can classify either outcome.
        state.clear()
        state.update(prior_state)
        raise
    if checkpoint is not None:
        store.finish()
    return reset_applied


def _definitive_bootstrap_error(exc):
    if exc.state in ("oversize", "audience_mismatch", "tamper_rejected",
                     "stale_expired", "rollback_rejected"):
        return True
    return exc.state == "key_rejected" and exc.reason == "bad_mac"


def run_instruction_step(cfg, state, catalog, hints, catalog_date, platform,
                         work_dir, boot_id, monotonic_now, verifier,
                         persist_config, emit, checkpoint=None,
                         cache_only=False, verification_attempts=None):
    """Contain instruction processing; return data for later RPC application."""
    result = {"instruction": None, "effective": None, "attestation": {"instr_state": "none"}}
    if cache_only:
        result["effective_peers"] = _tracker_only()
    header = None
    bag = _bag(state)
    guarded = _GuardedVerifier(
        verifier, state, boot_id, attempts=verification_attempts)
    store = LKGStore(work_dir, cfg, persist_config, guarded)
    hint = hints.get("instr_rev") if isinstance(hints, dict) else None
    pointer = _pair(hint)
    loaded = None
    refresh_attempted = False
    authenticated_hint = False
    bootstrap_applied = False
    bootstrap_seen = False

    def refresh_once():
        nonlocal refresh_attempted
        if not refresh_attempted:
            refresh_attempted = True
            _refresh_instruction_keys(cfg, catalog, persist_config)

    try:
        # Persist invalidation on reboot/regression even if no envelope arrives.
        instruction_time = project_clock(state, "instruction", monotonic_now, boot_id)
        if not cache_only:
            try:
                if _number(catalog_date) and boot_id:
                    observe_clock(
                        state, "catalog", catalog_date, monotonic_now, boot_id)
                    authenticated_hint = True
            except InstructionError:
                note_hint(state, hint, authenticated=False)
                raise
            note_hint(state, hint, authenticated=authenticated_hint)
        keylists = KeylistStore(work_dir, guarded)
        installed = keylists.recover()
        keylist_failure = keylists.recovery_error
        if installed is not None:
            guarded.krl = _unb64(installed["krl_b64"].encode("ascii"))
            bag["keylist_seq"] = installed["keylist_seq"]
            bag["keylist_digest"] = installed["artifact_sha256"]
        desired_keylist = hints.get("keylist_seq") if isinstance(hints, dict) else None
        if (not cache_only
                and type(desired_keylist) is int
                and 1 <= desired_keylist <= MAX_I63
                and (installed is None or desired_keylist > installed["keylist_seq"])):
            try:
                status, raw, headers = catalog.get_instruction_keylist(
                    cfg["device_id"], etag=bag.get("keylist_etag")
                    if os.path.exists(keylists.artifact_path) else None)
                if status == 200:
                    installed = keylists.install(raw, _date(headers))
                    keylist_failure = None
                    guarded.krl = _unb64(installed["krl_b64"].encode("ascii"))
                    bag.update(keylist_seq=installed["keylist_seq"], keylist_digest=installed["artifact_sha256"])
                    bag["keylist_etag"] = headers.get("ETag")
                elif status in (401, 403):
                    refresh_once()
            except InstructionError as exc:
                keylist_failure = exc
            except Exception:
                # The old keylist remains usable; retain its KRL for the role.
                pass
        store.recover(state)
        if os.path.exists(store.path):
            try:
                store.verifier = guarded.fallback()
                loaded = store.load(cfg["device_id"], platform, None,
                                    monotonic_now, boot_id, state)
                header = loaded["header"]
                peers, peer_state = _effective_peers(
                    store.verified_peers, instruction_time)
                result.update(instruction=loaded, effective=_effective(loaded),
                              effective_peers=peers,
                              attestation=_fact(
                                  peer_state or loaded["instr_state"], header))
            except InstructionError as exc:
                result["attestation"] = _fact(exc.state, reason=exc.reason)
                if exc.state == "verifier_missing":
                    result["effective"] = {"peers": {"mode": "tracker-only", "include_origin": False}}
                    result["effective_peers"] = _tracker_only()
                    result["attestation"]["verify_level"] = "sig"
        if keylist_failure is not None:
            result["attestation"] = _fact(keylist_failure.state, header, keylist_failure.reason)
            if keylist_failure.state == "verifier_missing":
                if result["effective"] is None:
                    result["effective"] = {"peers": {"mode": "tracker-only", "include_origin": False}}
                result["effective_peers"] = _tracker_only()
                result["attestation"]["verify_level"] = "sig"
        if cache_only:
            return result
        if pointer is None:
            return result
        candidate_path = os.path.join(work_dir, BOOTSTRAP_NAME)
        if authenticated_hint and checkpoint is not None:
            candidate = None
            try:
                candidate = _read_bootstrap(candidate_path)
                if candidate is not None:
                    bootstrap_seen = True
                    candidate_error = candidate["error"]
                    raw = candidate["raw"]
                    identity = candidate["identity"]
                    if candidate_error is not None:
                        if _definitive_bootstrap_error(candidate_error):
                            _unlink_bootstrap(candidate_path, identity)
                        result["attestation"] = _fact(
                            candidate_error.state, header,
                            candidate_error.reason)
                    else:
                        digest = hashlib.sha256(raw).hexdigest()
                        accepted = _accepted(_bag(state))
                        loaded_pair = ((loaded["header"]["epoch"],
                                        loaded["header"]["instr_serial"])
                                       if loaded is not None else None)
                        if (loaded_pair is not None and loaded_pair == accepted
                                and digest == _bag(state).get("envelope_digest")):
                            _unlink_bootstrap(candidate_path, identity)
                        else:
                            effective_cfg = dict(cfg, platform=platform)
                            verified = verify_envelope(
                                raw, effective_cfg, state, catalog_date,
                                monotonic_now, boot_id, guarded)
                            try:
                                reset_applied = _promote_verified(
                                    store, verified, state, catalog_date,
                                    monotonic_now, boot_id, checkpoint)
                            except Exception:
                                # A verified candidate is still retryable when
                                # any local transaction operation is not durable.
                                result["attestation"] = _fact(
                                    "instr_unavailable", header)
                            else:
                                # Deletion failure deliberately leaves the
                                # durable digest/LKG pair for the next tick.
                                _unlink_bootstrap(candidate_path, identity)
                                header = verified["header"]
                                bag = _bag(state)
                                result.update(
                                    instruction=verified,
                                    effective=_effective(verified),
                                    attestation=_fact(
                                        "floor_reset" if reset_applied
                                        else "applied", header))
                                peers, peer_state = _effective_peers(
                                    verified["device"]["peers"],
                                    project_clock(state, "instruction",
                                                  monotonic_now, boot_id))
                                result["effective_peers"] = peers
                                if peer_state is not None:
                                    result["attestation"] = _fact(
                                        peer_state, header)
                                bootstrap_applied = True
            except InstructionError as exc:
                if candidate is not None and _definitive_bootstrap_error(exc):
                    _unlink_bootstrap(candidate_path, candidate["identity"])
                result["attestation"] = _fact(exc.state, header, exc.reason)
                if exc.state == "key_rejected" and exc.reason == "unknown_key":
                    refresh_once()
                if exc.state == "verifier_missing":
                    if result["effective"] is None:
                        result["effective"] = {
                            "peers": {"mode": "tracker-only",
                                      "include_origin": False}}
                    result["effective_peers"] = _tracker_only()
                    result["attestation"]["verify_level"] = "sig"
            except Exception:
                # Candidate I/O and durability failures retain the fixed file.
                result["attestation"] = _fact("instr_unavailable", header)
        bag = _bag(state)
        cached_pointer = _pair(bag.get("fetched_pointer"))
        unconditional = loaded is None or instruction_time is None
        needs_fetch = (bootstrap_seen or pointer != cached_pointer
                       or unconditional or bag.get("fetch_pending")
                       or bag.get("pending_reset"))
        skew = bag.get("pointer_skew_count", 0)
        if pointer != cached_pointer or type(skew) is not int or not 0 <= skew <= 3:
            skew = 0
            bag["pointer_skew_count"] = 0
        if cached_pointer == pointer and 0 < skew < 3:
            needs_fetch = True
        if not needs_fetch:
            return result
        bag["fetch_pending"] = True
        status, raw, headers = catalog.get_instructions(
            cfg["device_id"], etag=None if unconditional else bag.get("envelope_etag"))
        if status == 304:
            if not unconditional and cached_pointer == pointer and 0 < skew < 3:
                bag["pointer_skew_count"] = skew + 1
                bag["fetch_pending"] = False
                if skew + 1 == 3:
                    emit("INSTRUCTION-POINTER-SKEW", "instruction pointer differs from verified body")
            return result
        if status in (401, 403):
            refresh_once()
            raise InstructionError("instr_forbidden")
        if status == 409:
            raise InstructionError("instr_pending")
        if status != 200:
            raise InstructionError("instr_unavailable")
        if not isinstance(raw, bytes) or len(raw) > INSTR_RESPONSE_MAX:
            raise InstructionError("oversize")
        date = _date(headers)
        effective_cfg = dict(cfg, platform=platform)
        verified = verify_envelope(raw, effective_cfg, state, date, monotonic_now, boot_id, guarded)
        candidate_header = verified["header"]
        reset_applied = _promote_verified(
            store, verified, state, date, monotonic_now, boot_id, checkpoint)
        header = candidate_header
        bag = _bag(state)
        bag["fetch_pending"] = False
        bag["fetched_pointer"] = {"epoch": pointer[0], "instr_serial": pointer[1]}
        bag["envelope_etag"] = headers.get("ETag")
        actual = (header["epoch"], header["instr_serial"])
        if actual < pointer:
            bag["pointer_skew_count"] = min(3, skew + 1)
            if bag["pointer_skew_count"] == 3:
                emit("INSTRUCTION-POINTER-SKEW", "instruction pointer differs from verified body")
        else:
            bag["pointer_skew_count"] = 0
        result.update(instruction=verified, effective=_effective(verified),
                      attestation=_fact("floor_reset" if reset_applied else "applied", header))
        peers, peer_state = _effective_peers(
            verified["device"]["peers"],
            project_clock(state, "instruction", monotonic_now, boot_id))
        result["effective_peers"] = peers
        if peer_state is not None:
            result["attestation"] = _fact(peer_state, header)
        return result
    except InstructionError as exc:
        if exc.state == "key_rejected" and exc.reason == "unknown_key":
            try:
                key_id = parse_json(_components(raw)[0])["key_id"]
                if bag.get("unknown_key_refresh") != key_id:
                    bag["unknown_key_refresh"] = key_id
                    refresh_once()
            except Exception:
                pass
        if bootstrap_applied:
            return result
        result["attestation"] = _fact(exc.state, header, exc.reason)
        if exc.state == "verifier_missing":
            if result["effective"] is None:
                result["effective"] = {"peers": {"mode": "tracker-only", "include_origin": False}}
            result["effective_peers"] = _tracker_only()
            result["attestation"]["verify_level"] = "sig"
        return result
    except Exception as exc:
        # Neither arbitrary remote text nor credentials enter the public fact.
        if bootstrap_applied:
            return result
        message = str(exc).lower()
        result["attestation"] = _fact(
            "oversize" if "exceeds" in message and "bytes" in message
            else "instr_unavailable", header)
        return result
    finally:
        # Include the current latch after all detector updates, including
        # cached, pending, rejected, and transport-failure early returns.
        result["attestation"].update(pointer_skew_fact(state))
