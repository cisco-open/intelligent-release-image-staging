# server/gui_fleet.py
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""FleetStore: the operator-entered device inventory (fleet.json under IRIS_STATE),
keyed by device_id, with CSV import/export matching the canonical devices.csv
columns. Uses the same atomic-write + advisory-lock idiom as catalog.py so the
GUI's writers (manual edit + CSV import) don't race. Stdlib only. This is config
inventory, kept separate from CatalogStore's devices.json (runtime heartbeats)."""
import csv
import io
import json
import os
import tempfile

import secrets_store

# Canonical devices.csv columns (network info only — no secrets). "model" is
# LAST and optional (used to auto-select the onboarding platform; see
# gui_onboard.resolve_platform) so older 6-column CSVs/exports keep importing.
CSV_COLS = ["device_id", "device_ip", "vlan", "svi_ip", "svi_mask", "guest_ip", "model"]
_REQUIRED = ("device_id", "device_ip")
_REQUIRED_CSV_COLS = CSV_COLS[:-1]  # model is optional; short (6-col) rows are OK


def _atomic_write_json(path, obj):
    d = os.path.dirname(path) or "."
    mode = None
    try:
        mode = os.stat(path).st_mode          # preserve target mode across writes
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".fleet-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=2, sort_keys=True)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


class FleetStore:
    def __init__(self, state_dir):
        os.makedirs(state_dir, exist_ok=True)
        self.path = os.path.join(state_dir, "fleet.json")

    def _read(self):
        try:
            with open(self.path) as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def list_devices(self):
        return list(self._read().values())

    def get_device(self, device_id):
        return self._read().get(device_id)

    def upsert(self, record):
        """Insert or MERGE a device record (keyed by device_id). A first insert
        must carry device_id + device_ip; a later partial upsert merges fields."""
        did = str(record.get("device_id") or "").strip()
        if not did:
            raise ValueError("device_id is required")
        with secrets_store.store_lock(self.path):
            fleet = self._read()
            merged = dict(fleet.get(did, {}))
            merged.update({k: v for k, v in record.items() if v is not None})
            merged["device_id"] = did
            for req in _REQUIRED:
                if not str(merged.get(req) or "").strip():
                    raise ValueError("%s is required" % req)
            fleet[did] = merged
            _atomic_write_json(self.path, fleet)
        return merged

    def delete(self, device_id):
        with secrets_store.store_lock(self.path):
            fleet = self._read()
            existed = fleet.pop(device_id, None) is not None
            if existed:
                _atomic_write_json(self.path, fleet)
        return existed

    def import_csv(self, text):
        """Parse the canonical devices.csv (comment lines starting with # ignored),
        validate ALL rows, then upsert them additively. Raises ValueError on any
        bad row WITHOUT applying anything (all-or-nothing).

        Returns a stats dict: {"imported": <rows applied>, "new": <ids not
        already in the fleet>, "updated": <ids already present>, "skipped":
        <comment/blank/header lines ignored>} — the audit trail renders these
        so an operator sees more than a bare count."""
        rows = []
        skipped = 0
        reader = csv.reader(io.StringIO(text))
        for idx, raw in enumerate(reader, 1):
            if not raw or (raw[0].strip().startswith("#")):
                skipped += 1
                continue
            cells = [c.strip() for c in raw]
            if cells == CSV_COLS or cells == _REQUIRED_CSV_COLS:  # header row (new or pre-model)
                skipped += 1
                continue
            if len(cells) < len(_REQUIRED_CSV_COLS):
                raise ValueError("row %d has %d columns, need at least %d"
                                 % (idx, len(cells), len(_REQUIRED_CSV_COLS)))
            rec = dict(zip(CSV_COLS, cells[:len(CSV_COLS)]))
            for req in _REQUIRED:
                if not rec.get(req):
                    raise ValueError("row %d missing %s" % (idx, req))
            rows.append(rec)
        new = updated = 0
        with secrets_store.store_lock(self.path):
            fleet = self._read()
            for rec in rows:
                if rec["device_id"] in fleet:
                    updated += 1
                else:
                    new += 1
                merged = dict(fleet.get(rec["device_id"], {}))
                merged.update(rec)
                fleet[rec["device_id"]] = merged
            _atomic_write_json(self.path, fleet)
        return {"imported": len(rows), "new": new, "updated": updated,
                "skipped": skipped}

    def export_csv(self):
        """Serialize the fleet to the canonical devices.csv columns (sorted by id)."""
        buf = io.StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(CSV_COLS)
        fleet = self._read()
        for did in sorted(fleet):
            rec = fleet[did]
            writer.writerow([rec.get(c, "") for c in CSV_COLS])
        return buf.getvalue()

    @staticmethod
    def example_csv():
        """A ready-to-edit devices.csv template: the canonical header (derived from
        CSV_COLS, so it can't drift from import_csv) plus commented guidance and
        example rows. Because import_csv() ignores '#' lines and the header, this
        template imports zero devices as-is -- the user uncomments/edits the rows."""
        return "\n".join([
            "# Device inventory - import via Devices > Import CSV",
            "# Columns: " + ", ".join(CSV_COLS),
            "# Required: " + ", ".join(_REQUIRED)
            + ".  Lines starting with # are ignored.",
            "# 'model' is optional -- if left blank, console onboarding will",
            "# auto-detect the platform (guestshell/IOx) from a live 'show version'",
            "# probe the first time you onboard the device.",
            "# Replace the examples below with your devices (delete the leading #).",
            ",".join(CSV_COLS),
            "# 100.92.9.11,100.92.9.11,666,100.92.9.10,255.255.255.252,100.92.9.9,C9300-48UXM",
            "# 100.92.9.12,100.92.9.12,666,100.92.9.13,255.255.255.252,100.92.9.14,",
            "# 100.90.168.99,100.90.168.99,666,100.90.168.98,255.255.255.252,100.90.168.97,IE-3400",
        ]) + "\n"
