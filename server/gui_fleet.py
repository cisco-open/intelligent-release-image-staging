# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Validated operator inventory, separate from applied deployment records."""
import csv
import io
import ipaddress
import json
import os
import re
import tempfile
import time

import gui_onboard
import keyed_state
import secrets_store


class FleetStateError(RuntimeError):
    """A fleet state file (the legacy ``fleet.json``, a ``fleet.d/`` shard,
    or the ``fleet-revision.json`` counter) is present but unreadable or
    malformed. Deliberately NOT a ``ValueError``: every FleetStore write
    path already raises plain ``ValueError`` for BAD INPUT (an invalid
    device_id, an unsupported management_type, ...), which every existing
    caller catches locally and turns into a 400. Corrupt STORAGE is a
    different failure a client did nothing to cause, and reusing the same
    exception type would let it fall into one of those local catches and
    come back as a misleading 400 instead of the clean 503 gui_server.py's
    connection-level handler gives catalog.StateFileError -- mirrored here,
    on purpose, for the identical reason."""


class FleetPartialWriteError(FleetStateError):
    """A grouped write failed after zero or more shards reached durable state."""

    def __init__(self, message, results, stats=None):
        self.results = dict(results)
        failed = {device_id: outcome.get("error", "fleet write failed")
                  for device_id, outcome in self.results.items()
                  if not outcome.get("ok")}
        applied = sum(1 for outcome in self.results.values()
                      if outcome.get("ok"))
        self.result = {"applied": applied, "failed": failed}
        if stats is not None:
            self.result["stats"] = dict(stats)
        super().__init__(message)


class FleetFieldError(ValueError):
    """An operator supplied a field name or JSON value the fleet schema rejects.

    Management HTTP maps this narrow input-integrity class to 422. Existing
    semantic validation errors remain ordinary :class:`ValueError` and retain
    their established 400 response.
    """

_CSV_V2_OLD_COLS = ["device_id", "device_ip", "management_type", "iris_vlan",
                    "svi_ip", "svi_mask", "app_ip", "app_mask", "app_gateway",
                    "inband_vlan", "ios_ssh_host", "model", "platform"]
# The pre-svi_igp v2 header (issue #85): router fields (vpg_number,
# nat_interface) but no svi_igp column. Kept as its own name, like
# _CSV_V2_OLD_COLS, so an export/CSV from before this field existed still
# imports unchanged -- see import_csv's v2_headers.
_CSV_V2_PRE_SVI_IGP_COLS = _CSV_V2_OLD_COLS[:-1] + ["vpg_number", "nat_interface", "platform"]
_CSV_V2_PRE_ROLE_COLS = _CSV_V2_PRE_SVI_IGP_COLS[:-1] + ["svi_igp", "platform"]
CSV_V2_COLS = _CSV_V2_PRE_ROLE_COLS[:-1] + ["role", "platform"]
_LEGACY_COLS = ["device_id", "device_ip", "vlan", "svi_ip", "svi_mask",
                "guest_ip", "model", "platform"]
OPERATOR_WRITABLE_FIELDS = frozenset((
    "device_id", "device_ip", "management_type", "iris_vlan", "svi_ip",
    "svi_mask", "app_ip", "app_mask", "app_gateway", "inband_vlan",
    "ios_ssh_host", "model", "vpg_number", "nat_interface", "svi_igp",
    "role", "platform", "credential_profile_id",
))
SERVER_OWNED_FIELDS = frozenset(("schema_version", "registered_at", "os_family"))
INTERNAL_OBSERVATION_FIELDS = frozenset(("model", "os_family"))
_LEGACY_CSV_ALIASES = frozenset(("vlan", "guest_ip"))
STORED_FIELDS = OPERATOR_WRITABLE_FIELDS | SERVER_OWNED_FIELDS | _LEGACY_CSV_ALIASES
_FIELD_MAX_LENGTH = {
    "device_id": 64,
    "device_ip": 64,
    "management_type": 32,
    "iris_vlan": 16,
    "svi_ip": 64,
    "svi_mask": 64,
    "app_ip": 64,
    "app_mask": 64,
    "app_gateway": 64,
    "inband_vlan": 16,
    "ios_ssh_host": 64,
    "model": 64,
    "vpg_number": 16,
    "nat_interface": 64,
    "svi_igp": 16,
    "role": 32,
    "platform": 32,
    "credential_profile_id": 128,
    "vlan": 16,
    "guest_ip": 64,
    "os_family": 16,
}
_MAX_STORED_ROW_BYTES = 4096
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$")
_INTERFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9./_-]{0,63}$")
_ROLE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
_C8K_RE = re.compile(r"^C8[0-9]{3}", re.IGNORECASE)
_ROUTER_TYPES = frozenset(("router-routed", "router-nat"))


def _atomic_write_json(path, obj):
    """Only remaining caller: _bump_revision's {"revision": N} counter (every
    device row now goes through keyed_state's own _write_shard, which
    already sets allow_nan=False). Matches that same guard: a NaN/Infinity
    that slipped in would otherwise be written as a bare token no JSON
    parser accepts, poisoning the next reader."""
    directory = os.path.dirname(path) or "."
    mode = None
    try:
        mode = os.stat(path).st_mode
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".fleet-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(obj, stream, indent=2, sort_keys=True, allow_nan=False)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _text(value):
    return str(value or "").strip()


def _validate_scalar_fields(record, fields, error=FleetFieldError):
    """Reject JSON containers/bools and bound every textual fleet value."""
    for field in fields:
        if field not in record or record[field] is None:
            continue
        value = record[field]
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise error("%s must be a scalar string or integer" % field)
        limit = _FIELD_MAX_LENGTH[field]
        if len(str(value)) > limit:
            raise error("%s must be at most %d characters" % (field, limit))


def _validate_operator_fields(record):
    if not isinstance(record, dict):
        raise ValueError("device record must be an object")
    server_fields = sorted(set(record) & SERVER_OWNED_FIELDS)
    if server_fields:
        raise FleetFieldError("server-owned fleet field is not writable: %s"
                              % ", ".join(server_fields))
    unknown = sorted(set(record) - OPERATOR_WRITABLE_FIELDS)
    if unknown:
        raise FleetFieldError("unknown fleet field: %s" % ", ".join(unknown))
    _validate_scalar_fields(record, set(record) & OPERATOR_WRITABLE_FIELDS)


def _validate_stored_fields(record):
    if not isinstance(record, dict):
        raise ValueError("device record must be an object")
    unknown = sorted(set(record) - STORED_FIELDS)
    if unknown:
        raise ValueError("unknown stored fleet field: %s" % ", ".join(unknown))
    aliases = sorted(set(record) & _LEGACY_CSV_ALIASES)
    if aliases and record.get("management_type") not in (None, "", "legacy_routed"):
        raise ValueError("legacy fleet field is invalid on a classified row: %s"
                         % ", ".join(aliases))
    _validate_scalar_fields(
        record, set(record) & (STORED_FIELDS - {"schema_version", "registered_at"}),
        error=ValueError)
    if "schema_version" in record and record["schema_version"] != 2:
        raise ValueError("schema_version must be 2")
    if "schema_version" in record and type(record["schema_version"]) is not int:
        raise ValueError("schema_version must be the integer 2")
    registered = record.get("registered_at")
    if registered is not None and type(registered) is not int:
        raise ValueError("registered_at must be an integer or null")
    family = record.get("os_family")
    if family not in (None, "", "xe", "xr"):
        raise ValueError("os_family must be xe or xr")


def _check_stored_row_size(record):
    try:
        encoded = json.dumps(record, allow_nan=False, separators=(",", ":"))
    except (TypeError, ValueError):
        raise ValueError("fleet record must contain JSON scalar values")
    if len(encoded.encode("utf-8")) > _MAX_STORED_ROW_BYTES:
        raise ValueError("fleet record exceeds %d bytes" % _MAX_STORED_ROW_BYTES)


def _ipv4(value, field):
    try:
        return str(ipaddress.IPv4Address(_text(value)))
    except ipaddress.AddressValueError:
        raise ValueError("%s must be an IPv4 address" % field)


def _mask(value, field):
    try:
        return str(ipaddress.IPv4Network("0.0.0.0/%s" % _text(value)).netmask)
    except (ipaddress.NetmaskValueError, ipaddress.AddressValueError):
        raise ValueError("%s must be a contiguous IPv4 mask" % field)


def _vlan(value, field):
    try:
        number = int(_text(value))
    except ValueError:
        raise ValueError("%s must be a VLAN ID" % field)
    if not 1 <= number <= 4094:
        raise ValueError("%s must be between 1 and 4094" % field)
    return number


def _vpg(value):
    try:
        number = int(_text(value))
    except ValueError:
        raise ValueError("vpg_number must be an integer")
    if not 0 <= number <= 31:
        raise ValueError("vpg_number must be between 0 and 31")
    return number


# Per-device override of device/device-install.sh's SVI_IGP env var (issue
# #85): routed onboarding used to have exactly one way to opt a fabric's IRIS
# SVI into IS-IS -- the process-wide SVI_IGP env var on the server -- which is
# wrong the moment one server onboards devices into different fabrics. This is
# interpolated into a live IOS config block (device-install.sh emits a literal
# " ip router isis" line whenever it equals "isis"), so it is validated the
# same way every other value bound for that path is: a closed enum, not a
# pattern that merely excludes shell metacharacters. Blank means "no
# per-device override" -- device-install.sh then falls back to its own
# SVI_IGP env var / "none" default, so a record that says nothing behaves
# exactly as before this field existed.
_SVI_IGP_VALUES = ("", "none", "isis")


def _svi_igp(value):
    value = _text(value)
    if value not in _SVI_IGP_VALUES:
        raise ValueError("svi_igp must be 'none' or 'isis'")
    return value


def _role(value):
    """Normalize the declared policy role; blank is canonical unassigned."""
    if value is None or value == "":
        return ""
    if not isinstance(value, str):
        raise ValueError("role must be a string or null")
    if value != value.strip():
        raise ValueError("role must not contain surrounding whitespace")
    if value and not _ROLE_RE.fullmatch(value):
        raise ValueError(
            "role must be 1-32 lowercase letters, numbers, dot, underscore, or hyphen")
    return value


def _static_network(ip, mask, gateway, prefix):
    ip = _ipv4(ip, prefix + "_ip")
    mask = _mask(mask, prefix + "_mask")
    gateway = _ipv4(gateway, prefix + "_gateway")
    network = ipaddress.IPv4Network("%s/%s" % (ip, mask), strict=False)
    if ipaddress.IPv4Address(ip) not in network or ipaddress.IPv4Address(gateway) not in network:
        raise ValueError("%s IP and gateway must share a subnet" % prefix)
    if ip == gateway:
        raise ValueError("%s IP and gateway must differ" % prefix)
    return ip, mask, gateway


def validate_record(record, allow_legacy=False):
    """Normalize a safe v2 record. Legacy data is only accepted when explicit."""
    _validate_stored_fields(record)
    raw_role = record.get("role")
    result = {key: _text(value) for key, value in record.items() if value is not None}
    did = result.get("device_id", "")
    if not _ID_RE.fullmatch(did):
        raise ValueError("device_id must contain only letters, numbers, dot, underscore, or hyphen")
    secrets_store.validate_device_id(did)
    result["device_ip"] = _ipv4(result.get("device_ip"), "device_ip")
    role = _role(raw_role)
    if role:
        result["role"] = role
    else:
        result.pop("role", None)
    management_type = result.get("management_type", "")
    if management_type == "legacy_routed" and allow_legacy:
        return _legacy_like(record)
    if management_type not in ("routed", "inband", "router-routed", "router-nat", "xr-host"):
        raise ValueError("management_type must be routed, inband, router-routed, "
                         "router-nat, or xr-host")
    platform = result.get("platform", "")
    if platform not in ("", "guestshell", "iox", "router", "xr-appmgr"):
        raise ValueError(
            "platform must be guestshell, iox, router, or xr-appmgr")
    model = result.get("model", "")
    if model:
        # '8201-SYS' and '8201' must read identically wherever a model is
        # stored, whether it arrived here via console/CSV entry or (in
        # gui_onboard) a live probe.
        model = gui_onboard.normalize_model(model)
        result["model"] = model
    if model and not _MODEL_RE.fullmatch(model):
        raise ValueError("model contains unsupported characters")
    model_is_c8k = bool(_C8K_RE.match(model))
    effective_platform = platform or ("router" if model_is_c8k else "")
    if management_type in _ROUTER_TYPES:
        if model and not model_is_c8k:
            raise ValueError("router modes support the Catalyst 8000 family only; "
                             "%s is not yet supported" % model)
        if effective_platform != "router":
            raise ValueError("router management types require platform router or a C8xxx model")
    elif model_is_c8k:
        raise ValueError("Catalyst 8000 models require management_type router-routed or router-nat")
    elif effective_platform == "router":
        raise ValueError("platform router requires management_type router-routed or router-nat")
    if platform:
        # Model-aware guardrail: an operator (or a CSV import) must not be
        # able to force an install method the hardware cannot run -- e.g.
        # 'guestshell' on an IOS-XR 8201, which has no Guest Shell at all.
        # None means the model is blank or not a recognized family, so there
        # is nothing to check against; the c8k-specific rules above already
        # cover Catalyst 8000.
        allowed = gui_onboard.install_options_for(model, result.get("os_family", ""))
        if platform == "xr-appmgr" and allowed != ["xr-appmgr"]:
            # The inverse of that guardrail, and it must fail closed where the
            # generic one abstains: 'None' (blank or unrecognized model) is
            # exactly the case where nobody has established this is IOS-XR,
            # and device/xr-install.sh speaks appmgr and IOS-XR config mode.
            raise ValueError(
                "platform xr-appmgr is the IOS-XR agent; %s needs an IOS-XR "
                "model (e.g. 8201) or a device already classified os_family=xr"
                % (("model %s" % model) if model else "a device with no model"))
        if allowed is not None and platform not in allowed:
            raise ValueError("model %s cannot run %s; allowed: %s"
                             % (model, platform, ", ".join(allowed) or "none"))
    # xr-host <-> xr-appmgr is a mutual requirement on any fully-validated
    # record: the appmgr container is the only agent that runs against
    # xr-host's bare network stack, and xr-appmgr is the only platform that
    # ever means that. Before this, no such pairing existed anywhere, which
    # is how an XR router ended up recorded as 'inband' with a made-up
    # VLAN. The legacy short-circuit above (allow_legacy) is untouched, so
    # an inventory-only device may still carry platform xr-appmgr before a
    # management type is chosen.
    if management_type == "xr-host":
        if platform != "xr-appmgr":
            raise ValueError("management_type xr-host requires platform xr-appmgr")
    elif platform == "xr-appmgr":
        raise ValueError("platform xr-appmgr requires management_type xr-host")
    result["schema_version"] = 2
    result["management_type"] = management_type
    if management_type == "routed":
        result["iris_vlan"] = str(_vlan(result.get("iris_vlan"), "iris_vlan"))
        result["svi_ip"] = _ipv4(result.get("svi_ip"), "svi_ip")
        result["svi_mask"] = _mask(result.get("svi_mask"), "svi_mask")
        # Per-device SVI_IGP override (issue #85): blank keeps the
        # process-wide SVI_IGP env var (default 'none') as the fallback --
        # see _svi_igp's docstring-equivalent comment above.
        result["svi_igp"] = _svi_igp(result.get("svi_igp"))
        app_ip, app_mask, app_gateway = _static_network(
            result.get("app_ip"), result.get("app_mask"), result.get("app_gateway"), "app")
        result.update(app_ip=app_ip, app_mask=app_mask, app_gateway=app_gateway)
        if any(result.get(key) for key in ("inband_vlan", "ios_ssh_host",
                                           "vpg_number", "nat_interface")):
            raise ValueError("routed inventory cannot contain inband or router fields")
    elif management_type == "inband":
        result["inband_vlan"] = str(_vlan(result.get("inband_vlan"), "inband_vlan"))
        app_ip, app_mask, app_gateway = _static_network(
            result.get("app_ip"), result.get("app_mask"), result.get("app_gateway"), "app")
        result.update(app_ip=app_ip, app_mask=app_mask, app_gateway=app_gateway)
        if any(result.get(key) for key in ("iris_vlan", "svi_ip", "svi_mask",
                                           "svi_igp", "vpg_number", "nat_interface")):
            raise ValueError("inband inventory cannot contain routed or router fields")
        # ios_ssh_host is the IOS endpoint the inband IOx app SSHes to for its
        # plain-copy placement. It defaults to the device's management IP
        # (device_ip), which is on the same existing management VLAN; it is
        # only set here as an advanced override for asymmetric topologies.
        # Guest Shell never uses it.
        if result.get("ios_ssh_host"):
            result["ios_ssh_host"] = _ipv4(result.get("ios_ssh_host"), "ios_ssh_host")
    elif management_type == "xr-host":
        # The appmgr container runs on the router's own network stack -- no
        # VLAN, SVI, app IP/mask/gateway, VPG, or NAT interface exists to
        # configure, so a non-empty one is a caller mistake, not silently
        # tolerated garbage.
        for key in ("iris_vlan", "svi_ip", "svi_mask", "svi_igp", "app_ip",
                    "app_mask", "app_gateway", "inband_vlan", "ios_ssh_host",
                    "vpg_number", "nat_interface"):
            if result.get(key):
                raise ValueError(
                    "xr-host needs no app-network fields; remove %s" % key)
    else:
        result["vpg_number"] = str(_vpg(result.get("vpg_number")))
        app_ip, app_mask, app_gateway = _static_network(
            result.get("app_ip"), result.get("app_mask"), result.get("app_gateway"), "app")
        result.update(app_ip=app_ip, app_mask=app_mask, app_gateway=app_gateway)
        if any(result.get(key) for key in ("iris_vlan", "svi_ip", "svi_mask",
                                           "svi_igp", "inband_vlan", "ios_ssh_host")):
            raise ValueError("router inventory cannot contain switch management fields")
        nat_interface = result.get("nat_interface", "")
        if management_type == "router-nat":
            if not _INTERFACE_RE.fullmatch(nat_interface):
                raise ValueError("nat_interface must be a valid IOS interface name")
        elif nat_interface:
            raise ValueError("nat_interface is only valid for router-nat")
    _check_stored_row_size(result)
    return result


def _legacy_record(row):
    result = dict(zip(_LEGACY_COLS, row))
    result["management_type"] = "legacy_routed"
    return _legacy_like(result)


def _legacy_like(record):
    """Normalize a bounded unclassified or historical legacy record."""
    _validate_stored_fields(record)
    result = {key: _text(value) for key, value in record.items()
              if value is not None}
    if not _ID_RE.fullmatch(result.get("device_id", "")):
        raise ValueError("device_id must contain only letters, numbers, dot, "
                         "underscore, or hyphen")
    secrets_store.validate_device_id(result["device_id"])
    result["device_ip"] = _ipv4(result.get("device_ip"), "device_ip")
    for field in ("svi_ip", "app_ip", "app_gateway", "ios_ssh_host", "guest_ip"):
        if result.get(field):
            result[field] = _ipv4(result[field], field)
    for field in ("svi_mask", "app_mask"):
        if result.get(field):
            result[field] = _mask(result[field], field)
    for field in ("iris_vlan", "inband_vlan", "vlan"):
        if result.get(field):
            result[field] = str(_vlan(result[field], field))
    if result.get("vpg_number"):
        result["vpg_number"] = str(_vpg(result["vpg_number"]))
    if result.get("nat_interface") and not _INTERFACE_RE.fullmatch(
            result["nat_interface"]):
        raise ValueError("nat_interface must be a valid IOS interface name")
    if result.get("svi_igp"):
        result["svi_igp"] = _svi_igp(result["svi_igp"])
    model = result.get("model", "")
    if model:
        model = gui_onboard.normalize_model(model)
        if not _MODEL_RE.fullmatch(model):
            raise ValueError("model contains unsupported characters")
        result["model"] = model
    platform = result.get("platform", "")
    if platform not in ("", "guestshell", "iox", "router", "xr-appmgr"):
        raise ValueError("platform must be guestshell, iox, router, or xr-appmgr")
    role = _role(record.get("role"))
    if role:
        result["role"] = role
    else:
        result.pop("role", None)
    result["management_type"] = "legacy_routed"
    if "schema_version" in record:
        result["schema_version"] = 2
    if "registered_at" in record:
        result["registered_at"] = record["registered_at"]
    _check_stored_row_size(result)
    return result


def _fleet_legacy_rows(doc):
    """Extract ``{device_id: row}`` from a legacy whole-fleet ``fleet.json``
    document for :class:`keyed_state.KeyedState`'s one-shot migration.

    The document has taken two shapes over this store's life: the current
    ``{"revision": N, "devices": {...}}`` wrapper, and — before the
    ``revision`` field existed — a bare ``{device_id: row}`` mapping with no
    wrapper at all. ``FleetStore`` has tolerated reading either shape since
    before this migration (see the old ``_read``'s "upgrade the old bare
    mapping in memory" branch); this mirrors that same two-shape check
    exactly, so a legacy document that read one way before migration reads
    the identical rows after it."""
    if isinstance(doc.get("devices"), dict):
        return doc["devices"]
    return doc


class FleetStore:
    # snapshot()'s revision+rows pairing is two separate reads (a small
    # revision-counter file, and a KeyedState.snapshot() that is itself up to
    # SHARD_COUNT separate shard reads) standing in for what used to be ONE
    # json.load of one document. A write racing the scan can make the two
    # reads disagree about which edit of the fleet they describe; this many
    # settle attempts (read revision, scan rows, read revision again, retry
    # if they moved) resolves that in the overwhelmingly common case of an
    # operator edit landing between two of many device reads, cheaply (two
    # small-file reads per extra attempt). See snapshot()'s docstring for the
    # safe fallback once attempts run out.
    _SNAPSHOT_SETTLE_ATTEMPTS = 4

    def __init__(self, state_dir, now_fn=time.time):
        os.makedirs(state_dir, exist_ok=True)
        self.path = os.path.join(state_dir, "fleet.json")
        # The fleet-wide revision counter (see revision()/snapshot()) is
        # deliberately NOT part of the keyed store: it describes the STORE,
        # not any one device, so it has no device_id to shard on. It is one
        # small file bumped under its own lock -- still O(1) regardless of
        # fleet size (a fixed few bytes), which is the property this whole
        # migration exists to give every per-device write; it is just the
        # one remaining thing every fleet mutation still serializes on,
        # because "did the fleet change" is inherently a whole-store
        # question. A store migrated from a pre-shard fleet.json restarts
        # this counter at 0 -- see _bump_revision.
        self._revision_path = os.path.join(state_dir, "fleet-revision.json")
        # One keyed store, sharded by device_id (see keyed_state.py). The
        # legacy whole-fleet document at self.path is migrated into shards
        # on first use; error=FleetStateError keeps every fail-closed raise
        # here out of the plain-ValueError input-validation catches every
        # write route already has (see FleetStateError's docstring).
        self._devices = keyed_state.KeyedState(
            self.path, error=FleetStateError, legacy_extract=_fleet_legacy_rows)
        self._now = now_fn

    def _read_revision(self):
        """The fleet-wide revision counter. A MISSING file is a fresh store
        (revision 0, matching a fresh KeyedState store with no legacy
        document — see __init__). An EXISTING file that cannot be parsed, or
        whose value is not an int, fails closed exactly like every other
        state file here — never silently reset to 0, which would let the
        next write quietly resume counting from the wrong place."""
        try:
            with open(self._revision_path) as stream:
                data = json.load(stream)
        except FileNotFoundError:
            return 0
        except (OSError, ValueError) as exc:
            raise FleetStateError(
                "fleet revision counter %s is unreadable (%s); refusing to "
                "overwrite it -- repair or remove the file"
                % (self._revision_path, type(exc).__name__))
        value = data.get("revision") if isinstance(data, dict) else None
        if not isinstance(value, int) or isinstance(value, bool):
            raise FleetStateError("fleet revision counter %s is malformed"
                                  % self._revision_path)
        return value

    def _ensure_revision_readable(self):
        """Fail closed on a corrupt revision counter BEFORE a write path
        mutates any device row, not only when it goes to bump the counter
        afterward: _bump_revision runs after the row write commits (see its
        own docstring for why), so without this check first, a counter that
        was ALREADY corrupt would let the row write go through and only
        raise on the bump that follows it -- a caller seeing the exception
        would have no way to know the device was, in fact, just written. A
        pre-existing corruption is by far the common case this catches; the
        remaining window (the counter is corrupted by something else between
        this check and the bump) is the same narrow, already-accepted class
        of race as the rest of this store's fail-closed design."""
        self._read_revision()

    def _bump_revision(self):
        """Increment the revision counter by exactly one, under its own
        lock. Called AFTER the device row write it accounts for has already
        committed (never before): if the shard write itself fails, nothing
        here has counted a change that never happened; if it succeeds, the
        counter can only be READ as stale relative to it, never as ahead of
        it — the safe direction snapshot()'s settle loop relies on, since a
        reader that samples the counter after the row content has already
        landed can only under- or exactly-count, never over-count, a
        concurrent write it raced."""
        with secrets_store.store_lock(self._revision_path):
            current = self._read_revision()
            _atomic_write_json(self._revision_path, {"revision": current + 1})

    def _merge_record(self, previous, record, trusted_observation=False):
        """The full per-row merge/validate/stamp pipeline every write path
        (upsert, bulk_upsert, import_csv) shares — factored out so there is
        exactly ONE place this logic lives, whether one device is being
        written or a thousand. Raises ValueError on an invalid record;
        otherwise returns the normalized new row. *previous* is that
        device's CURRENT row (or None), read from within the same shard
        lock that will hold the write — never a separately-fetched, possibly
        stale copy."""
        if trusted_observation:
            allowed = INTERNAL_OBSERVATION_FIELDS | {"device_id"}
            unknown = sorted(set(record) - allowed)
            if unknown:
                raise FleetFieldError("unknown internal observation field: %s"
                                      % ", ".join(unknown))
            _validate_scalar_fields(record, set(record) & allowed)
            family = record.get("os_family")
            if family is not None and family not in ("xe", "xr"):
                raise ValueError("os_family must be xe or xr")
        else:
            _validate_operator_fields(record)
        if previous is not None:
            _validate_stored_fields(previous)
        previous_record = previous if isinstance(previous, dict) else {}
        merged = dict(previous_record)
        incoming_management_type = record.get("management_type")
        if incoming_management_type is not None:
            incoming_management_type = _text(incoming_management_type)
        if incoming_management_type and incoming_management_type != previous_record.get(
                "management_type"):
            # Management-type-specific fields are mutually exclusive. A
            # partial upsert changing type must not retain stale values
            # from the old family and then fail validation (or, worse,
            # retarget a plan).
            old_router = previous_record.get("management_type") in _ROUTER_TYPES
            new_router = incoming_management_type in _ROUTER_TYPES
            old_xr = previous_record.get("management_type") == "xr-host"
            new_xr = incoming_management_type == "xr-host"
            if old_xr or new_xr:
                # xr-host carries none of the XE addressing fields, and no
                # XE management type carries xr-host's (none); either
                # direction of this swap must not let a stale one survive.
                for key in ("iris_vlan", "svi_ip", "svi_mask", "app_ip",
                            "app_mask", "app_gateway", "inband_vlan",
                            "ios_ssh_host", "vpg_number", "nat_interface"):
                    merged.pop(key, None)
            elif old_router and new_router:
                # VPG and app addressing are shared by both router modes;
                # only the NAT outside field is mode-specific.
                if incoming_management_type == "router-routed":
                    merged.pop("nat_interface", None)
            else:
                for key in ("iris_vlan", "svi_ip", "svi_mask", "inband_vlan",
                            "ios_ssh_host", "vpg_number", "nat_interface"):
                    merged.pop(key, None)
            if (old_router != new_router or old_xr != new_xr) and \
                    "platform" not in record:
                merged.pop("platform", None)
        # ``None`` means "leave unchanged" for ordinary partial fields, but an
        # explicitly present blank/null role is the role API's clear operation.
        # Remove the prior key before the usual non-None overlay and let both
        # validators retain their canonical blank-is-unassigned normalization.
        if "role" in record and record.get("role") in (None, ""):
            merged.pop("role", None)
        merged.update({key: value for key, value in record.items() if value is not None})
        # Full v2 validation applies only when the record actually carries a
        # classified management type (Console form, CSV v2, adoption). Bare
        # creation and partial edits (model/platform/credential/legacy CSV)
        # are stored as legacy_routed and must pick a management type before
        # deployment -- OnboardService/plan enforce that at onboard time.
        if merged.get("management_type") in (
                "routed", "inband", "router-routed", "router-nat", "xr-host"):
            normalized = validate_record(merged)
        elif merged.get("management_type", "") in ("", "legacy_routed"):
            normalized = _legacy_like(merged)
        else:
            raise ValueError("management_type must be routed, inband, router-routed, "
                             "router-nat, xr-host, or legacy_routed")
        normalized["registered_at"] = self._registration_stamp(previous)
        _check_stored_row_size(normalized)
        return normalized

    def _registration_stamp(self, previous):
        """When this device id was registered, or ``None`` when unknown.

        A device that is deleted and added back is a DIFFERENT device wearing a
        familiar name -- routinely a rebuilt or replaced box. Everything else
        keyed on the bare id was made to stop outliving the device it described;
        persisted deployment logs cannot be, because they are the forensic
        record. So they stay, and this stamp is what lets a reader tell which
        registration each one belongs to: a log that finished before this device
        was registered was written about its predecessor."""
        if previous is None:
            return int(self._now())
        if not isinstance(previous, dict) or not previous:
            raise ValueError("existing fleet record must be a non-empty object")
        prior = previous.get("registered_at")
        try:
            return int(prior) if prior is not None else None
        except (TypeError, ValueError):
            raise ValueError("registered_at must be an integer or null")

    def list_devices(self):
        return list(self._devices.snapshot().values())

    def snapshot(self):
        """(revision, [record, ...]).

        The paginated console projection needs both halves to describe the
        SAME edit of the fleet: stamping a page with a revision fetched by an
        unrelated read could label rows from state A with the version of
        state B, which is exactly what a caller walking pages compares to
        decide its walk is still coherent. That used to come for free (one
        json.load of one document); now the rows are up to SHARD_COUNT
        separate shard reads with no single lock spanning all of them, so a
        write racing the scan could otherwise pair fresh rows with a stale
        revision (or vice versa). This retries a settled (revision, rows)
        pairing a few times — cheap, since nothing here holds a lock, only
        re-reads a small file and rescans — and if it still hasn't settled,
        falls back to the LAST revision read next to the last scan: always
        >= what those rows reflect (see _bump_revision), so the fallback can
        only look newer than the rows actually are, never staler."""
        for _ in range(self._SNAPSHOT_SETTLE_ATTEMPTS - 1):
            before = self._read_revision()
            rows = list(self._devices.snapshot().values())
            after = self._read_revision()
            if before == after:
                return before, rows
        rows = list(self._devices.snapshot().values())
        return self._read_revision(), rows

    def get_device(self, device_id):
        return self._devices.get(device_id)

    def revision(self):
        return self._read_revision()

    def upsert(self, record):
        _validate_operator_fields(record)
        did = _text(record.get("device_id"))
        self._ensure_revision_readable()
        normalized = self._devices.update(
            did, lambda old: self._merge_record(old, record))
        self._bump_revision()
        return normalized

    def validate_operator_upsert(self, record):
        """Return the normalized upsert result without mutating fleet state.

        Role coordination calls this before a policy-first relaxation. The
        real upsert repeats the same checks under the device shard lock.
        """
        _validate_operator_fields(record)
        did = _text(record.get("device_id"))
        return self._merge_record(self.get_device(did), record)

    def update_observation(self, device_id, *, model=None, os_family=None):
        """Persist model/OS values learned from a trusted device observation."""
        record = {"device_id": device_id}
        if model is not None:
            record["model"] = model
        if os_family is not None:
            record["os_family"] = os_family
        # A caller with no new evidence gets a read-only result and does not
        # advance the fleet revision.
        if len(record) == 1:
            existing = self.get_device(_text(device_id))
            if existing is None:
                raise ValueError("no such device")
            return existing
        _validate_scalar_fields(record, set(record))
        if record.get("os_family") not in (None, "xe", "xr"):
            raise ValueError("os_family must be xe or xr")
        did = _text(device_id)
        self._ensure_revision_readable()

        def merge(previous):
            if previous is None:
                raise ValueError("no such device")
            return self._merge_record(
                previous, record, trusted_observation=True)

        normalized = self._devices.update(did, merge)
        self._bump_revision()
        return normalized

    def bulk_upsert(self, device_ids, fields):
        """Apply the SAME partial-record patch *fields* (e.g. a credential or
        platform reassignment) to every id in *device_ids* — the fix for
        issue #125: the console's "Select all N matching devices" bulk
        action used to fire one HTTP request per selected device against the
        single-device routes, each locking and rewriting the WHOLE fleet
        document; with FleetStore sharded, each of those N requests would
        still be O(1), but N still means N HTTP round trips and, worse, N
        separate lock/read/write cycles against the same ~256 shards (every
        selected device's shard rewritten once per device landing in it,
        instead of once total). This groups by shard the same way
        keyed_state.KeyedState.update_many does (because it IS update_many)
        so a shard holding a hundred of the selected ids is read and
        rewritten exactly once.

        Unlike import_csv, this is NOT all-or-nothing: a device id that does
        not exist, or whose merged record fails validation, is reported and
        skipped — every OTHER id in the batch still applies. A ten-thousand-
        device selection needs to know exactly which ones did not take, not
        have one bad id abort the other 9,999. It also deliberately does
        NOT create a device that does not already exist (unlike upsert()) —
        the two callers this exists for (bulk credential/platform
        reassignment) both refuse a non-existent device on the single-device
        route today, and a stale "Select all" snapshot racing a delete must
        fail the same way there, not quietly conjure a bare inventory row.

        Returns ``{device_id: {"ok": True, "device": normalized}
                              | {"ok": False, "error": message}}``, one entry
        per id in *device_ids* (a repeated id is processed once per
        occurrence; only the last outcome for it survives in the result,
        the same as calling upsert() that many times in a row would leave)."""
        fields = {key: value for key, value in dict(fields or {}).items()
                 if key != "device_id"}
        _validate_operator_fields(dict(fields, device_id="bulk-validation"))
        self._ensure_revision_readable()
        results = {}

        def merge(did, previous):
            if previous is None:
                results[did] = {"ok": False, "error": "no such device"}
                return None
            try:
                normalized = self._merge_record(
                    previous, dict(fields, device_id=did))
            except ValueError as exc:
                results[did] = {"ok": False, "error": str(exc)}
                return None
            results[did] = {"ok": True, "device": normalized}
            return normalized

        ids = [_text(did) for did in device_ids]
        try:
            self._devices.update_many(ids, merge)
        except Exception as exc:
            self._complete_grouped_intentions(ids, results, merge)
            live = self._live_grouped_results(ids, results)
            if any(outcome["ok"] for outcome in live.values()):
                self._bump_revision()
            raise FleetPartialWriteError(str(exc), live) from exc
        # One bump per CALL, not per device: the counter is a "did the fleet
        # change" signal, not a per-row tally (import_csv has always bumped
        # once per call the same way), and bumping it once keeps this call's
        # cost O(1) regardless of how many of the ten thousand ids actually
        # applied -- N separate bumps would reintroduce, on the one file
        # every mutation still shares, exactly the kind of per-device
        # serialization this whole batch call exists to avoid.
        if any(outcome["ok"] for outcome in results.values()):
            self._bump_revision()
        return results

    def bulk_set_roles(self, role_by_device):
        """Apply per-device role declarations in one grouped fleet mutation.

        Unlike :meth:`bulk_upsert`, each device can receive a different role;
        this is the CSV/coordinator seam.  Missing devices are reported and
        skipped, explicit blank/``None`` clears the declaration, and the fleet
        revision advances once when at least one row changes successfully.
        """
        requested = dict(role_by_device or {})
        for device_id, role in requested.items():
            _validate_operator_fields({"device_id": device_id, "role": role})
        self._ensure_revision_readable()
        ids = [_text(device_id) for device_id in requested]
        results = {}

        def merge(device_id, previous):
            if previous is None:
                results[device_id] = {"ok": False, "error": "no such device"}
                return None
            try:
                normalized = self._merge_record(
                    previous, {"device_id": device_id,
                               "role": requested[device_id]})
            except ValueError as exc:
                results[device_id] = {"ok": False, "error": str(exc)}
                return None
            results[device_id] = {"ok": True, "device": normalized}
            return normalized

        try:
            self._devices.update_many(ids, merge)
        except Exception as exc:
            self._complete_grouped_intentions(ids, results, merge)
            live = self._live_grouped_results(ids, results)
            if any(outcome["ok"] for outcome in live.values()):
                self._bump_revision()
            raise FleetPartialWriteError(str(exc), live) from exc
        if any(outcome["ok"] for outcome in results.values()):
            self._bump_revision()
        return results

    def _complete_grouped_intentions(self, device_ids, intended, merge):
        """Build expected records for shards update_many never visited."""
        for device_id in dict.fromkeys(device_ids):
            if device_id in intended:
                continue
            try:
                merge(device_id, self.get_device(device_id))
            except Exception:
                intended[device_id] = {"ok": False,
                                       "error": "fleet write failed"}

    def _live_grouped_results(self, device_ids, intended):
        """Re-read grouped-write outcomes so a late shard error is exact."""
        live = {}
        for device_id in dict.fromkeys(device_ids):
            expected = intended.get(device_id, {}).get("device")
            if expected is None:
                live[device_id] = {
                    "ok": False,
                    "error": intended.get(device_id, {}).get(
                        "error", "fleet write failed")}
                continue
            try:
                actual = self.get_device(device_id)
            except Exception:
                actual = None
            if actual == expected:
                live[device_id] = {"ok": True, "device": actual}
            else:
                live[device_id] = {"ok": False,
                                   "error": "fleet write failed"}
        return live

    def delete(self, device_id):
        self._ensure_revision_readable()
        existed = self._devices.delete(device_id)
        if existed:
            self._bump_revision()
        return existed

    def parse_csv(self, text):
        """Parse and validate an inventory CSV without reading or writing state.

        The role coordinator uses this pure preview to validate every declared
        role and select the safe fleet/policy write order before phase one.
        """
        skipped = 0
        header = None
        data_rows = []
        for row in csv.reader(io.StringIO(text)):
            if not row or not any(cell.strip() for cell in row) \
                    or row[0].strip().startswith("#"):
                skipped += 1
                continue
            if header is None:
                header = [cell.strip() for cell in row]
                skipped += 1
                continue
            data_rows.append(row)
        if header is None:
            return {"records": [], "skipped": skipped, "header": None,
                    "legacy": False}
        # The pre-router v2 header (_CSV_V2_OLD_COLS, no vpg_number/nat_interface
        # columns) and the pre-svi_igp v2 header (_CSV_V2_PRE_SVI_IGP_COLS, no
        # svi_igp column) both still import unchanged; the retired
        # network_attachment alias header is gone -- an old exported CSV
        # using it is rejected below like any other unknown header.
        v2_headers = (CSV_V2_COLS, _CSV_V2_PRE_ROLE_COLS,
                      _CSV_V2_PRE_SVI_IGP_COLS, _CSV_V2_OLD_COLS)
        legacy = header in (_LEGACY_COLS, _LEGACY_COLS[:-1], _LEGACY_COLS[:-2])
        if header not in v2_headers and not legacy:
            raise ValueError("CSV must use the v2 named header: %s" % ",".join(CSV_V2_COLS))
        cols = header if header in v2_headers else CSV_V2_COLS
        records = []
        first_row_of = {}
        for index, row in enumerate(data_rows, 1):
            if len(row) != len(header):
                raise ValueError("data row %d has %d columns, need %d"
                                 % (index, len(row), len(header)))
            try:
                record = (_legacy_record(row) if legacy else
                          validate_record(dict(zip(cols, row)),
                                          allow_legacy=True))
            except ValueError as exc:
                raise ValueError("data row %d: %s" % (index, exc))
            # Two rows for one device used to collapse silently (last row
            # wins, stats counting it as new AND updated). The import is
            # all-or-nothing for bad rows; a conflicting duplicate is bad
            # input too, and naming both rows is what lets the operator fix
            # the sheet.
            seen_at = first_row_of.setdefault(record["device_id"], index)
            if seen_at != index:
                raise ValueError("data row %d repeats device_id %s from data "
                                 "row %d" % (index, record["device_id"],
                                             seen_at))
            records.append(record)
        return {"records": records, "skipped": skipped, "header": header,
                "legacy": legacy}

    @staticmethod
    def _revalidate_parsed_csv(parsed):
        """Validate a parse preview as untrusted input before grouped writes."""
        if not isinstance(parsed, dict):
            raise ValueError("parsed CSV must be an object")
        raw_records = parsed.get("records", [])
        if not isinstance(raw_records, list):
            raise ValueError("parsed CSV records must be a list")
        skipped = parsed.get("skipped", 0)
        if type(skipped) is not int or skipped < 0:
            raise ValueError("parsed CSV skipped count must be a non-negative integer")
        header = parsed.get("header")
        legacy = parsed.get("legacy", False)
        if type(legacy) is not bool:
            raise ValueError("parsed CSV legacy marker must be boolean")
        v2_headers = (CSV_V2_COLS, _CSV_V2_PRE_ROLE_COLS,
                      _CSV_V2_PRE_SVI_IGP_COLS, _CSV_V2_OLD_COLS)
        legacy_headers = (_LEGACY_COLS, _LEGACY_COLS[:-1], _LEGACY_COLS[:-2])
        if header is None:
            if raw_records or legacy:
                raise ValueError("parsed CSV without a header cannot contain records")
            return [], skipped
        if not isinstance(header, list):
            raise ValueError("parsed CSV header must be a list")
        if legacy != (header in legacy_headers):
            raise ValueError("parsed CSV header and legacy marker disagree")
        if header not in v2_headers and header not in legacy_headers:
            raise ValueError("parsed CSV has an unsupported header")

        records = []
        seen = set()
        for index, raw in enumerate(raw_records, 1):
            if not isinstance(raw, dict):
                raise ValueError("parsed CSV data row %d must be an object" % index)
            record = dict(raw)
            allowed = ((set(_LEGACY_COLS) | {"management_type"}) if legacy else
                       (set(CSV_V2_COLS) | {"schema_version"}))
            unknown = sorted(set(record) - allowed)
            if unknown:
                raise FleetFieldError(
                    "parsed CSV data row %d has unknown fleet field: %s"
                    % (index, ", ".join(unknown)))
            try:
                normalized = (_legacy_like(record) if legacy else
                              validate_record(record, allow_legacy=True))
            except ValueError as exc:
                raise type(exc)("parsed CSV data row %d: %s" % (index, exc))
            device_id = normalized["device_id"]
            if device_id in seen:
                raise ValueError("parsed CSV data row %d repeats device_id %s"
                                 % (index, device_id))
            seen.add(device_id)
            records.append(normalized)
        return records, skipped

    def import_parsed_csv(self, parsed):
        """Apply a :meth:`parse_csv` result, preserving non-CSV state.

        CSV is add/change-only for roles.  Both a pre-role header and a blank
        role in the current header retain the existing declaration; explicit
        role removal belongs to the role API/CLI.
        """
        records, skipped = self._revalidate_parsed_csv(parsed)
        # Every row above is fully parsed and validated (schema, IP/mask,
        # management-type field isolation, duplicate device_id) BEFORE any
        # storage is touched -- the "all-or-nothing" the docstring promises
        # is about BAD INPUT, and is enforced entirely above this point, so
        # nothing below can fail on account of what the CSV said. What CAN
        # still fail below is storage itself (a shard that is independently
        # corrupt): grouped by shard the same way bulk_upsert is, one shard's
        # failure aborts that shard's write (leaving it untouched, as every
        # fail-closed shard read here always has) without rolling back
        # shards that already committed earlier in this same call -- the
        # same narrower blast radius every other store's migration to
        # keyed_state already accepted (a corrupt shard used to mean a
        # corrupt WHOLE fleet.json blocking every device; now it means the
        # devices in that one shard).
        new = updated = roles_cleared = 0
        by_id = {record["device_id"]: record for record in records}
        intended = {}
        existed = {}

        # A historical row carrying an unknown field is recoverable state,
        # not permission for CSV replacement to erase it. Refuse before the
        # first grouped write so every original field remains available for
        # an explicit repair or migration.
        for did in by_id:
            previous = self.get_device(did)
            if previous is not None:
                _validate_stored_fields(previous)

        def merge(did, previous):
            nonlocal new, updated, roles_cleared
            record = dict(by_id[did])
            if previous is not None:
                updated += 1
            else:
                new += 1
            # A re-import REPLACES the row wholesale, so carry the
            # registration stamp across explicitly or every CSV import
            # would look like a fresh registration of the whole fleet.
            registered_at = self._registration_stamp(previous)
            # Same reason, different field: os_family is determined from
            # the device's own 'show version' banner and is deliberately
            # NOT a CSV column -- an operator typing it would be a new way
            # to lie to the system. Dropping it on the documented
            # export -> edit -> re-import round trip would silently reopen
            # the IOS-XR misroute on the next onboard.
            family = previous.get("os_family") if isinstance(previous, dict) else None
            if family:
                record["os_family"] = family
            # And the credential profile: the CSV deliberately carries no
            # credential column (fleet-workflows.md), so the assignment
            # made in the Console after the first import must survive the
            # export -> edit -> re-import cycle, or one bulk edit silently
            # disarms every device's onboard/undeploy until re-assigned.
            profile = (previous.get("credential_profile_id")
                       if isinstance(previous, dict) else None)
            if profile and not record.get("credential_profile_id"):
                record["credential_profile_id"] = profile
            prior_role = (previous.get("role")
                          if isinstance(previous, dict) else None)
            incoming_role = record.get("role")
            if prior_role and not incoming_role:
                record["role"] = prior_role
            # This should remain zero under the carry-forward above.  Count
            # the actual stored outcome so a future replacement-merge change
            # cannot silently weaken the guarantee while still reporting 0.
            if prior_role and not record.get("role"):
                roles_cleared += 1
            # Revalidate the final durable row after carrying server-owned
            # and non-CSV fields forward. Parsed previews are untrusted, and
            # direct callers must not bypass the storage schema by editing one.
            record = validate_record(record, allow_legacy=True)
            record["registered_at"] = registered_at
            _check_stored_row_size(record)
            intended[did] = {"ok": True, "device": record}
            existed[did] = previous is not None
            return record

        if records:
            self._ensure_revision_readable()
            ids = list(by_id)
            try:
                self._devices.update_many(ids, merge)
            except Exception as exc:
                # update_many intentionally retains earlier shard commits.
                # Reconstruct expectations for an unvisited shard from its
                # still-live row, then compare every requested full record.
                for did in ids:
                    if did in intended:
                        continue
                    try:
                        previous = self.get_device(did)
                        intended[did] = {
                            "ok": True, "device": merge(did, previous)}
                    except Exception:
                        intended[did] = {"ok": False,
                                         "error": "fleet write failed"}
                live = self._live_grouped_results(ids, intended)
                applied = {did for did, outcome in live.items()
                           if outcome["ok"]}
                if applied:
                    self._bump_revision()
                partial_stats = {
                    "imported": len(applied),
                    "new": sum(1 for did in applied if not existed.get(did)),
                    "updated": sum(1 for did in applied if existed.get(did)),
                    "skipped": skipped,
                    "roles_cleared": 0}
                raise FleetPartialWriteError(
                    str(exc), live, stats=partial_stats) from exc
            self._bump_revision()
        return {"imported": len(records), "new": new, "updated": updated,
                "skipped": skipped, "roles_cleared": roles_cleared}

    def import_csv(self, text):
        """Parse then apply an inventory CSV; invalid input writes nothing."""
        return self.import_parsed_csv(self.parse_csv(text))

    @staticmethod
    def _export_row(record):
        """Map any stored record onto the v2 columns. Legacy routed rows keep a
        ``legacy_routed`` marker and map vlan->iris_vlan, guest_ip->app_ip so an
        export never silently drops a device."""
        if record.get("management_type") == "legacy_routed":
            row = dict(record)
            row.setdefault("iris_vlan", record.get("vlan", ""))
            row.setdefault("app_ip", record.get("guest_ip", ""))
            return [row.get(column, "") for column in CSV_V2_COLS]
        return [record.get(column, "") for column in CSV_V2_COLS]

    def export_csv(self):
        output = io.StringIO()
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(CSV_V2_COLS)
        devices = self._devices.snapshot()
        for device_id in sorted(devices):
            writer.writerow(self._export_row(devices[device_id]))
        return output.getvalue()

    @staticmethod
    def example_csv():
        # Data rows are commented so importing the template as-is adds zero
        # devices; operators uncomment and edit their own rows.
        return "\n".join([
            "# IRIS inventory CSV v2. Legacy routed CSV files require explicit migration.",
            "# Inband preserves an existing operator-owned VLAN, SVI, gateway, routes, and VRF.",
            "# Inband supports static IPv4 Guest Shell and IOx (IE-3x00, C9300); DHCP is not",
            "# supported. Inband IOx SSHes to the switch mgmt IP by default (ios_ssh_host overrides).",
            "# Router modes use a VirtualPortGroup; router-nat also needs an outside interface.",
            "# XR host (xr-host, platform xr-appmgr) runs on the router's own network stack --",
            "# no VLAN, SVI, app IP/mask/gateway, VPG, or NAT interface; leave those columns empty.",
            "# svi_igp is routed-only: 'isis' adds 'ip router isis' to the IRIS SVI for a fabric",
            "# that must learn it (e.g. an SD-Access underlay). Blank keeps the SVI_IGP env var's",
            "# default (none) for that device; every other management type must leave it blank.",
            "# Uncomment and edit the example rows below to import your devices.",
            ",".join(CSV_V2_COLS),
            "# edge-routed,192.0.2.10,routed,666,192.0.2.9,255.255.255.252,192.0.2.10,255.255.255.252,192.0.2.9,,,C9300-48UXM,,,,,guestshell",
            "# edge-inband,192.0.2.20,inband,,,,192.0.2.21,255.255.255.0,192.0.2.1,120,,C9300-48UXM,,,,,guestshell",
            "# ie-inband-iox,192.0.2.30,inband,,,,192.0.2.31,255.255.255.0,192.0.2.1,120,192.0.2.1,IE-3400,,,,,iox",
            "# edge-c8kv,192.0.2.40,router-nat,,,,10.8.0.2,255.255.255.252,10.8.0.1,,,C8000V,10,GigabitEthernet1,,,router",
            "# edge-xr,192.0.2.50,xr-host,,,,,,,,,8201,,,,,xr-appmgr",
        ]) + "\n"
