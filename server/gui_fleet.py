# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Validated operator inventory, separate from applied deployment receipts."""
import csv
import io
import ipaddress
import json
import os
import re
import tempfile

import secrets_store


CSV_V2_COLS = ["device_id", "device_ip", "network_attachment", "iris_vlan",
               "svi_ip", "svi_mask", "app_ip", "app_mask", "app_gateway",
               "inband_vlan", "ios_ssh_host", "model", "platform"]
# Retained for callers that render/export the current schema.
CSV_COLS = CSV_V2_COLS
_LEGACY_COLS = ["device_id", "device_ip", "vlan", "svi_ip", "svi_mask",
                "guest_ip", "model", "platform"]
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,63}$")


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
    result["device_ip"] = _ipv4(result.get("device_ip"), "device_ip")
    attachment = result.get("network_attachment", "")
    if attachment == "legacy_routed" and allow_legacy:
        return result
    if attachment not in ("routed", "inband"):
        raise ValueError("network_attachment must be routed or inband")
    platform = result.get("platform", "")
    if platform not in ("", "guestshell", "iox"):
        raise ValueError("platform must be guestshell or iox")
    model = result.get("model", "")
    if model and not _MODEL_RE.fullmatch(model):
        raise ValueError("model contains unsupported characters")
    result["schema_version"] = 2
    result["network_attachment"] = attachment
    if attachment == "routed":
        result["iris_vlan"] = str(_vlan(result.get("iris_vlan"), "iris_vlan"))
        result["svi_ip"] = _ipv4(result.get("svi_ip"), "svi_ip")
        result["svi_mask"] = _mask(result.get("svi_mask"), "svi_mask")
        app_ip, app_mask, app_gateway = _static_network(
            result.get("app_ip"), result.get("app_mask"), result.get("app_gateway"), "app")
        result.update(app_ip=app_ip, app_mask=app_mask, app_gateway=app_gateway)
        if any(result.get(key) for key in ("inband_vlan", "ios_ssh_host")):
            raise ValueError("routed inventory cannot contain inband fields")
    else:
        if platform == "iox":
            raise ValueError("inband IOx is not supported")
        result["inband_vlan"] = str(_vlan(result.get("inband_vlan"), "inband_vlan"))
        app_ip, app_mask, app_gateway = _static_network(
            result.get("app_ip"), result.get("app_mask"), result.get("app_gateway"), "app")
        result.update(app_ip=app_ip, app_mask=app_mask, app_gateway=app_gateway)
        if any(result.get(key) for key in ("iris_vlan", "svi_ip", "svi_mask", "ios_ssh_host")):
            raise ValueError("inband inventory cannot contain routed or IOx fields")
    return result


def _legacy_record(row):
    result = dict(zip(_LEGACY_COLS, row))
    result = {key: _text(value) for key, value in result.items() if value is not None}
    if not _ID_RE.fullmatch(result.get("device_id", "")):
        raise ValueError("legacy row has invalid device_id")
    result["device_ip"] = _ipv4(result.get("device_ip"), "device_ip")
    result["network_attachment"] = "legacy_routed"
    return result


def _legacy_like(record):
    """Minimal normalization for an unclassified or legacy record. It enforces a
    safe device_id and IPv4 device_ip, preserves the remaining fields as-is, and
    marks the row ``legacy_routed`` so it cannot deploy until an attachment is
    chosen. This keeps bare device creation and partial edits (model, platform,
    credential) working without demanding full routed/inband fields."""
    result = {key: (_text(value) if isinstance(value, str) else value)
              for key, value in record.items() if value is not None}
    if not _ID_RE.fullmatch(result.get("device_id", "")):
        raise ValueError("device_id must contain only letters, numbers, dot, "
                         "underscore, or hyphen")
    result["device_ip"] = _ipv4(result.get("device_ip"), "device_ip")
    result["network_attachment"] = "legacy_routed"
    return result


class FleetStore:
    def __init__(self, state_dir):
        os.makedirs(state_dir, exist_ok=True)
        self.path = os.path.join(state_dir, "fleet.json")

    def _read(self):
        try:
            with open(self.path) as stream:
                data = json.load(stream)
            if not isinstance(data, dict):
                return {"revision": 0, "devices": {}}
            if "devices" in data and isinstance(data["devices"], dict):
                return {"revision": int(data.get("revision", 0)), "devices": data["devices"]}
            # Upgrade the old bare mapping in memory on the next write.
            return {"revision": 0, "devices": data}
        except (OSError, ValueError):
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
            data = self._read()
            previous = data["devices"].get(did, {})
            merged = dict(previous)
            merged.update({key: value for key, value in record.items() if value is not None})
            # Full v2 validation applies only when the record actually carries a
            # routed/inband attachment (Console form, CSV v2, adoption). Bare
            # creation and partial edits (model/platform/credential/legacy CSV)
            # are stored as legacy_routed and must pick an attachment before
            # deployment -- OnboardService/plan enforce that at onboard time.
            if merged.get("network_attachment") in ("routed", "inband"):
                normalized = validate_record(merged)
            elif merged.get("network_attachment", "") in ("", "legacy_routed"):
                normalized = _legacy_like(merged)
            else:
                raise ValueError("network_attachment must be routed, inband, "
                                 "or legacy_routed")
            data["devices"][did] = normalized
            data["revision"] += 1
            _atomic_write_json(self.path, data)
        return normalized

    def delete(self, device_id):
        with secrets_store.store_lock(self.path):
            data = self._read()
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
        legacy = header in (_LEGACY_COLS, _LEGACY_COLS[:-1], _LEGACY_COLS[:-2])
        if header != CSV_V2_COLS and not legacy:
            raise ValueError("CSV must use the v2 named header: %s" % ",".join(CSV_V2_COLS))
        records = []
        for index, row in enumerate(data_rows, 1):
            if len(row) != len(header):
                raise ValueError("data row %d has %d columns, need %d"
                                 % (index, len(row), len(header)))
            try:
                records.append(_legacy_record(row) if legacy else
                               validate_record(dict(zip(CSV_V2_COLS, row)),
                                               allow_legacy=True))
            except ValueError as exc:
                raise ValueError("data row %d: %s" % (index, exc))
        new = updated = 0
        with secrets_store.store_lock(self.path):
            data = self._read()
            for record in records:
                if record["device_id"] in data["devices"]:
                    updated += 1
                else:
                    new += 1
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
        if record.get("network_attachment") == "legacy_routed":
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
            "# Supported inband cell: static IPv4 Guest Shell only. IOx and DHCP are rejected.",
            "# Uncomment and edit the example rows below to import your devices.",
            ",".join(CSV_V2_COLS),
            "# edge-routed,192.0.2.10,routed,666,192.0.2.9,255.255.255.252,192.0.2.10,255.255.255.252,192.0.2.9,,,C9300-48UXM,guestshell",
            "# edge-inband,192.0.2.20,inband,,,,192.0.2.21,255.255.255.0,192.0.2.1,120,,C9300-48UXM,guestshell",
        ]) + "\n"
