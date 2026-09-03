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
import secrets_store


_CSV_V2_OLD_COLS = ["device_id", "device_ip", "management_type", "iris_vlan",
                    "svi_ip", "svi_mask", "app_ip", "app_mask", "app_gateway",
                    "inband_vlan", "ios_ssh_host", "model", "platform"]
CSV_V2_COLS = _CSV_V2_OLD_COLS[:-1] + ["vpg_number", "nat_interface", "platform"]
_LEGACY_COLS = ["device_id", "device_ip", "vlan", "svi_ip", "svi_mask",
                "guest_ip", "model", "platform"]
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$")
_INTERFACE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9./_-]{0,63}$")
_C8K_RE = re.compile(r"^C8[0-9]{3}", re.IGNORECASE)
_ROUTER_TYPES = frozenset(("router-routed", "router-nat"))


def _atomic_write_json(path, obj):
    directory = os.path.dirname(path) or "."
    mode = None
    try:
        mode = os.stat(path).st_mode
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".fleet-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(obj, stream, indent=2, sort_keys=True)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _text(value):
    return str(value or "").strip()


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
    if not isinstance(record, dict):
        raise ValueError("device record must be an object")
    result = {key: _text(value) for key, value in record.items() if value is not None}
    did = result.get("device_id", "")
    if not _ID_RE.fullmatch(did):
        raise ValueError("device_id must contain only letters, numbers, dot, underscore, or hyphen")
    secrets_store.validate_device_id(did)
    result["device_ip"] = _ipv4(result.get("device_ip"), "device_ip")
    management_type = result.get("management_type", "")
    if management_type == "legacy_routed" and allow_legacy:
        return result
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
                                           "vpg_number", "nat_interface")):
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
        for key in ("iris_vlan", "svi_ip", "svi_mask", "app_ip", "app_mask",
                    "app_gateway", "inband_vlan", "ios_ssh_host", "vpg_number",
                    "nat_interface"):
            if result.get(key):
                raise ValueError(
                    "xr-host needs no app-network fields; remove %s" % key)
    else:
        result["vpg_number"] = str(_vpg(result.get("vpg_number")))
        app_ip, app_mask, app_gateway = _static_network(
            result.get("app_ip"), result.get("app_mask"), result.get("app_gateway"), "app")
        result.update(app_ip=app_ip, app_mask=app_mask, app_gateway=app_gateway)
        if any(result.get(key) for key in ("iris_vlan", "svi_ip", "svi_mask",
                                           "inband_vlan", "ios_ssh_host")):
            raise ValueError("router inventory cannot contain switch management fields")
        nat_interface = result.get("nat_interface", "")
        if management_type == "router-nat":
            if not _INTERFACE_RE.fullmatch(nat_interface):
                raise ValueError("nat_interface must be a valid IOS interface name")
        elif nat_interface:
            raise ValueError("nat_interface is only valid for router-nat")
    return result


def _legacy_record(row):
    result = dict(zip(_LEGACY_COLS, row))
    result = {key: _text(value) for key, value in result.items() if value is not None}
    if not _ID_RE.fullmatch(result.get("device_id", "")):
        raise ValueError("legacy row has invalid device_id")
    secrets_store.validate_device_id(result["device_id"])
    result["device_ip"] = _ipv4(result.get("device_ip"), "device_ip")
    result["management_type"] = "legacy_routed"
    return result


def _legacy_like(record):
    """Minimal normalization for an unclassified or legacy record. It enforces a
    safe device_id and IPv4 device_ip, preserves the remaining fields as-is, and
    marks the row ``legacy_routed`` so it cannot deploy until a management type
    is chosen. This keeps bare device creation and partial edits (model, platform,
    credential) working without demanding full routed/inband fields."""
    result = {key: (_text(value) if isinstance(value, str) else value)
              for key, value in record.items() if value is not None}
    if not _ID_RE.fullmatch(result.get("device_id", "")):
        raise ValueError("device_id must contain only letters, numbers, dot, "
                         "underscore, or hyphen")
    secrets_store.validate_device_id(result["device_id"])
    result["device_ip"] = _ipv4(result.get("device_ip"), "device_ip")
    result["management_type"] = "legacy_routed"
    return result


class FleetStore:
    def __init__(self, state_dir, now_fn=time.time):
        os.makedirs(state_dir, exist_ok=True)
        self.path = os.path.join(state_dir, "fleet.json")
        self._now = now_fn

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

    def _read(self, strict=False):
        """Load the store. A MISSING file is an empty fleet. A file that is
        present but unreadable is different: with strict=True (every write
        path) it raises, so the next upsert cannot rewrite a corrupt but
        repairable inventory as a fresh one-device fleet at revision 1;
        without it (reads) it degrades to an empty view."""
        try:
            with open(self.path) as stream:
                data = json.load(stream)
        except FileNotFoundError:
            return {"revision": 0, "devices": {}}
        except (OSError, ValueError) as exc:
            if strict:
                raise ValueError("fleet store %s is unreadable (%s); refusing "
                                 "to overwrite it -- repair or remove the file"
                                 % (self.path, exc))
            return {"revision": 0, "devices": {}}
        try:
            if not isinstance(data, dict):
                raise ValueError("top level is not an object")
            if "devices" in data and isinstance(data["devices"], dict):
                return {"revision": int(data.get("revision", 0)),
                        "devices": data["devices"]}
            # Upgrade the old bare mapping in memory on the next write.
            return {"revision": 0, "devices": data}
        except (TypeError, ValueError) as exc:
            if strict:
                raise ValueError("fleet store %s is malformed (%s); refusing "
                                 "to overwrite it -- repair or remove the file"
                                 % (self.path, exc))
            return {"revision": 0, "devices": {}}

    def list_devices(self):
        return list(self._read()["devices"].values())

    def get_device(self, device_id):
        return self._read()["devices"].get(device_id)

    def revision(self):
        return self._read()["revision"]

    def upsert(self, record):
        did = _text(record.get("device_id"))
        with secrets_store.store_lock(self.path):
            data = self._read(strict=True)
            previous = data["devices"].get(did)
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
            data["devices"][did] = normalized
            data["revision"] += 1
            _atomic_write_json(self.path, data)
        return normalized

    def delete(self, device_id):
        with secrets_store.store_lock(self.path):
            data = self._read(strict=True)
            existed = data["devices"].pop(device_id, None) is not None
            if existed:
                data["revision"] += 1
                _atomic_write_json(self.path, data)
        return existed

    def import_csv(self, text):
        """Import v2 (named-header) or a legacy routed CSV. Legacy rows are
        classified ``legacy_routed`` and never inferred as inband. Returns
        {imported, new, updated, skipped} where skipped counts comment, blank,
        and header lines. All-or-nothing: any bad row raises before writing."""
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
            return {"imported": 0, "new": 0, "updated": 0, "skipped": skipped}
        # The pre-router v2 header (_CSV_V2_OLD_COLS, no vpg_number/nat_interface
        # columns) still imports unchanged; the retired network_attachment
        # alias header is gone -- an old exported CSV using it is rejected
        # below like any other unknown header.
        v2_headers = (CSV_V2_COLS, _CSV_V2_OLD_COLS)
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
        new = updated = 0
        with secrets_store.store_lock(self.path):
            data = self._read(strict=True)
            for record in records:
                previous = data["devices"].get(record["device_id"])
                if previous is not None:
                    updated += 1
                else:
                    new += 1
                # A re-import REPLACES the row wholesale, so carry the
                # registration stamp across explicitly or every CSV import
                # would look like a fresh registration of the whole fleet.
                record["registered_at"] = self._registration_stamp(previous)
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
                data["devices"][record["device_id"]] = record
            if records:
                data["revision"] += 1
                _atomic_write_json(self.path, data)
        return {"imported": len(records), "new": new, "updated": updated,
                "skipped": skipped}

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
        devices = self._read()["devices"]
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
            "# Uncomment and edit the example rows below to import your devices.",
            ",".join(CSV_V2_COLS),
            "# edge-routed,192.0.2.10,routed,666,192.0.2.9,255.255.255.252,192.0.2.10,255.255.255.252,192.0.2.9,,,C9300-48UXM,,,guestshell",
            "# edge-inband,192.0.2.20,inband,,,,192.0.2.21,255.255.255.0,192.0.2.1,120,,C9300-48UXM,,,guestshell",
            "# ie-inband-iox,192.0.2.30,inband,,,,192.0.2.31,255.255.255.0,192.0.2.1,120,192.0.2.1,IE-3400,,,iox",
            "# edge-c8kv,192.0.2.40,router-nat,,,,10.8.0.2,255.255.255.252,10.8.0.1,,,C8000V,10,GigabitEthernet1,router",
            "# edge-xr,192.0.2.50,xr-host,,,,,,,,,8201,,,xr-appmgr",
        ]) + "\n"
