# server/tests/test_gui_fleet.py
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import gui_fleet


def _fs(tmp_path):
    return gui_fleet.FleetStore(str(tmp_path))


def test_upsert_get_list_delete(tmp_path):
    fs = _fs(tmp_path)
    assert fs.list_devices() == []
    fs.upsert({"device_id": "d1", "device_ip": "10.0.0.1", "vlan": "666",
               "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
               "guest_ip": "10.0.0.3", "model": "C9300",
               "credential_profile_id": "lab"})
    assert fs.get_device("d1")["device_ip"] == "10.0.0.1"
    assert [d["device_id"] for d in fs.list_devices()] == ["d1"]
    # upsert merges (partial update keeps prior fields)
    fs.upsert({"device_id": "d1", "model": "IE-3400"})
    d = fs.get_device("d1")
    assert d["model"] == "IE-3400" and d["device_ip"] == "10.0.0.1"
    assert fs.delete("d1") is True
    assert fs.get_device("d1") is None
    assert fs.delete("d1") is False


def test_upsert_requires_ids(tmp_path):
    fs = _fs(tmp_path)
    for bad in ({}, {"device_id": "d1"}, {"device_ip": "1.2.3.4"}):
        try:
            fs.upsert(bad)
            assert False, "expected ValueError for %r" % bad
        except ValueError:
            pass


def test_import_export_csv_roundtrip(tmp_path):
    fs = _fs(tmp_path)
    csv_in = ("device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip\n"
              "# a comment line\n"
              "d1,10.0.0.1,666,10.0.0.2,255.255.255.252,10.0.0.3\n"
              "d2,10.0.0.5,777,10.0.0.6,255.255.255.252,10.0.0.7\n")
    stats = fs.import_csv(csv_in)
    assert stats["imported"] == 2
    assert stats["new"] == 2 and stats["updated"] == 0
    assert stats["skipped"] == 2                       # header + comment line
    assert {d["device_id"] for d in fs.list_devices()} == {"d1", "d2"}
    out = fs.export_csv()
    assert out.splitlines()[0] == "device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip,model"
    assert "d1,10.0.0.1,666,10.0.0.2,255.255.255.252,10.0.0.3," in out
    # re-importing the export reproduces the same fleet
    fs2 = gui_fleet.FleetStore(str(tmp_path / "b"))
    assert fs2.import_csv(out)["imported"] == 2


def test_import_csv_rejects_bad_rows(tmp_path):
    fs = _fs(tmp_path)
    try:
        fs.import_csv("device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip\n,,,,,\n")
        assert False, "expected ValueError"
    except ValueError:
        pass
    assert fs.list_devices() == []   # atomic: nothing imported on a bad row


def test_example_csv_is_a_safe_importable_template(tmp_path):
    tpl = gui_fleet.FleetStore.example_csv()
    assert ",".join(gui_fleet.CSV_COLS) in tpl        # canonical header present
    fs = _fs(tmp_path)
    assert fs.import_csv(tpl)["imported"] == 0         # comments + header only
    assert fs.list_devices() == []                     # safe to import as-is
    assert "IE-3400" in tpl                             # IOx example present
    assert "platform" in tpl.lower()                    # auto-detection mentioned


def test_model_is_last_csv_column():
    assert gui_fleet.CSV_COLS[-1] == "model"


def test_import_csv_stats_new_updated_skipped(tmp_path):
    """import_csv reports new vs updated ids and skipped comment/blank/header
    lines — the audit trail renders these so 'imported=5' becomes
    'imported 5 devices (4 new, 1 updated; 3 rows skipped)'."""
    fs = _fs(tmp_path)
    fs.upsert({"device_id": "d1", "device_ip": "10.0.0.9"})   # pre-existing
    csv_in = ("device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip\n"
              "# comment\n"
              "\n"
              "d1,10.0.0.1,666,10.0.0.2,255.255.255.252,10.0.0.3\n"
              "d2,10.0.0.5,777,10.0.0.6,255.255.255.252,10.0.0.7\n")
    stats = fs.import_csv(csv_in)
    assert stats == {"imported": 2, "new": 1, "updated": 1, "skipped": 3}
    assert fs.get_device("d1")["device_ip"] == "10.0.0.1"     # overwrite applied


def test_import_export_csv_roundtrip_with_model(tmp_path):
    fs = _fs(tmp_path)
    csv_in = ("device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip,model\n"
              "d1,10.0.0.1,666,10.0.0.2,255.255.255.252,10.0.0.3,C9300-48UXM\n"
              "d2,10.0.0.5,777,10.0.0.6,255.255.255.252,10.0.0.7,IE-3400\n")
    assert fs.import_csv(csv_in)["imported"] == 2
    assert fs.get_device("d1")["model"] == "C9300-48UXM"
    assert fs.get_device("d2")["model"] == "IE-3400"
    out = fs.export_csv()
    assert out.splitlines()[0] == "device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip,model"
    assert "d1,10.0.0.1,666,10.0.0.2,255.255.255.252,10.0.0.3,C9300-48UXM" in out


def test_import_old_six_column_csv_still_works(tmp_path):
    """Old exports/templates predating the model column must still import --
    model is optional and simply absent on those rows."""
    fs = _fs(tmp_path)
    csv_in = ("device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip\n"
              "d1,10.0.0.1,666,10.0.0.2,255.255.255.252,10.0.0.3\n")
    assert fs.import_csv(csv_in)["imported"] == 1
    dev = fs.get_device("d1")
    assert dev["device_ip"] == "10.0.0.1"
    assert dev.get("model", "") == ""
