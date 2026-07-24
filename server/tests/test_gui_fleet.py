# server/tests/test_gui_fleet.py
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import gui_fleet


def _fs(tmp_path):
    return gui_fleet.FleetStore(str(tmp_path))


_ROUTED = {"device_id": "d1", "device_ip": "10.0.0.1", "management_type": "routed",
           "iris_vlan": "666", "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
           "app_ip": "10.0.0.1", "app_mask": "255.255.255.252", "app_gateway": "10.0.0.2",
           "model": "C9300", "platform": "guestshell"}


def test_upsert_get_list_delete(tmp_path):
    fs = _fs(tmp_path)
    assert fs.list_devices() == []
    fs.upsert(dict(_ROUTED, credential_profile_id="lab"))
    assert fs.get_device("d1")["device_ip"] == "10.0.0.1"
    assert [d["device_id"] for d in fs.list_devices()] == ["d1"]
    # a partial model/platform upsert merges without re-validating the whole row
    fs.upsert({"device_id": "d1", "model": "C9300-48UXM"})
    d = fs.get_device("d1")
    assert d["model"] == "C9300-48UXM" and d["device_ip"] == "10.0.0.1"
    assert d["management_type"] == "routed"     # preserved
    assert fs.delete("d1") is True
    assert fs.get_device("d1") is None
    assert fs.delete("d1") is False


def test_upsert_rejects_invalid_records(tmp_path):
    fs = _fs(tmp_path)
    bad = [
        {"device_id": "d1", "device_ip": "nope", "management_type": "routed"},
        {"device_id": "bad id", "device_ip": "10.0.0.1", "management_type": "routed"},
        {"device_id": "d1", "device_ip": "10.0.0.1", "management_type": "sideways"},
        # inband IOx is rejected
        dict(_ROUTED, device_id="d2", management_type="inband", inband_vlan="120",
             iris_vlan="", svi_ip="", svi_mask="", platform="iox"),
    ]
    for rec in bad:
        try:
            fs.upsert(rec)
            assert False, "expected ValueError for %r" % rec
        except ValueError:
            pass


def test_inband_upsert_and_field_isolation(tmp_path):
    fs = _fs(tmp_path)
    saved = fs.upsert({"device_id": "edge-1", "device_ip": "192.0.2.10",
                       "management_type": "inband", "inband_vlan": "120",
                       "app_ip": "192.0.2.11", "app_mask": "255.255.255.0",
                       "app_gateway": "192.0.2.1", "platform": "guestshell"})
    assert saved["management_type"] == "inband" and saved["inband_vlan"] == "120"
    # inband records must not carry routed SVI/VLAN fields
    try:
        fs.upsert({"device_id": "edge-2", "device_ip": "192.0.2.20",
                   "management_type": "inband", "inband_vlan": "120",
                   "app_ip": "192.0.2.21", "app_mask": "255.255.255.0",
                   "app_gateway": "192.0.2.1", "iris_vlan": "999"})
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_inband_iox_requires_ios_ssh_host(tmp_path):
    fs = _fs(tmp_path)
    # inband IOx without ios_ssh_host is rejected
    try:
        fs.upsert({"device_id": "ie1", "device_ip": "192.0.2.30",
                   "management_type": "inband", "inband_vlan": "120",
                   "app_ip": "192.0.2.31", "app_mask": "255.255.255.0",
                   "app_gateway": "192.0.2.1", "platform": "iox"})
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "ios_ssh_host" in str(exc)
    # with ios_ssh_host it is accepted and the field is preserved
    saved = fs.upsert({"device_id": "ie1", "device_ip": "192.0.2.30",
                       "management_type": "inband", "inband_vlan": "120",
                       "app_ip": "192.0.2.31", "app_mask": "255.255.255.0",
                       "app_gateway": "192.0.2.1", "platform": "iox",
                       "ios_ssh_host": "192.0.2.1"})
    assert saved["platform"] == "iox" and saved["ios_ssh_host"] == "192.0.2.1"
    # a bad ios_ssh_host is rejected
    try:
        fs.upsert({"device_id": "ie2", "device_ip": "192.0.2.40",
                   "management_type": "inband", "inband_vlan": "120",
                   "app_ip": "192.0.2.41", "app_mask": "255.255.255.0",
                   "app_gateway": "192.0.2.1", "platform": "iox",
                   "ios_ssh_host": "not-an-ip"})
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_import_export_csv_roundtrip(tmp_path):
    fs = _fs(tmp_path)
    header = ",".join(gui_fleet.CSV_COLS)
    csv_in = (header + "\n"
              "# a comment line\n"
              "d1,10.0.0.1,routed,666,10.0.0.2,255.255.255.252,10.0.0.1,255.255.255.252,10.0.0.2,,,C9300,guestshell\n"
              "edge,10.0.0.5,inband,,,,10.0.0.6,255.255.255.0,10.0.0.1,120,,C9300,guestshell\n")
    stats = fs.import_csv(csv_in)
    assert stats["imported"] == 2 and stats["new"] == 2 and stats["updated"] == 0
    assert stats["skipped"] == 2                       # header + comment line
    assert {d["device_id"] for d in fs.list_devices()} == {"d1", "edge"}
    out = fs.export_csv()
    assert out.splitlines()[0] == header
    assert "d1,10.0.0.1,routed,666" in out
    assert "edge,10.0.0.5,inband" in out
    # re-importing the export reproduces the same fleet
    fs2 = gui_fleet.FleetStore(str(tmp_path / "b"))
    assert fs2.import_csv(out)["imported"] == 2
    assert fs2.get_device("edge")["management_type"] == "inband"


def test_import_csv_stats_new_updated_skipped(tmp_path):
    fs = _fs(tmp_path)
    fs.upsert(dict(_ROUTED, device_id="d1", device_ip="10.0.0.9"))   # pre-existing
    header = ",".join(gui_fleet.CSV_COLS)
    csv_in = (header + "\n"
              "# comment\n"
              "\n"
              "d1,10.0.0.1,routed,666,10.0.0.2,255.255.255.252,10.0.0.1,255.255.255.252,10.0.0.2,,,C9300,guestshell\n"
              "d2,10.0.0.5,routed,777,10.0.0.6,255.255.255.252,10.0.0.5,255.255.255.252,10.0.0.6,,,C9300,guestshell\n")
    stats = fs.import_csv(csv_in)
    assert stats == {"imported": 2, "new": 1, "updated": 1, "skipped": 3}
    assert fs.get_device("d1")["device_ip"] == "10.0.0.1"     # overwrite applied


def test_import_csv_rejects_bad_rows_atomically(tmp_path):
    fs = _fs(tmp_path)
    header = ",".join(gui_fleet.CSV_COLS)
    # a populated but invalid row (bad IP) must abort the whole import
    bad = "d1,not-an-ip,routed,666,10.0.0.2,255.255.255.252,10.0.0.1,255.255.255.252,10.0.0.2,,,C9300,guestshell"
    try:
        fs.import_csv(header + "\n" + bad + "\n")
        assert False, "expected ValueError"
    except ValueError:
        pass
    assert fs.list_devices() == []   # atomic: nothing imported on a bad row


def test_unknown_or_short_header_rejected(tmp_path):
    fs = _fs(tmp_path)
    try:
        fs.import_csv("device_id,device_ip,color\nd1,10.0.0.1,red\n")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_legacy_csv_imports_as_legacy_routed_and_exports_without_loss(tmp_path):
    """Old 6/7/8-column routed CSVs still import, are classified legacy_routed
    (never inband), and survive an export/re-import round-trip."""
    fs = _fs(tmp_path)
    legacy = ("device_id,device_ip,vlan,svi_ip,svi_mask,guest_ip,model\n"
              "old,192.0.2.20,666,192.0.2.21,255.255.255.252,192.0.2.22,C9300-48UXM\n")
    assert fs.import_csv(legacy)["imported"] == 1
    dev = fs.get_device("old")
    assert dev["management_type"] == "legacy_routed"
    assert dev["model"] == "C9300-48UXM"
    # export maps it onto v2 columns without dropping the device
    out = fs.export_csv()
    assert "old,192.0.2.20,legacy_routed" in out
    fs2 = gui_fleet.FleetStore(str(tmp_path / "b"))
    assert fs2.import_csv(out)["imported"] == 1
    assert fs2.get_device("old")["management_type"] == "legacy_routed"


def test_example_csv_is_a_safe_importable_template(tmp_path):
    tpl = gui_fleet.FleetStore.example_csv()
    assert ",".join(gui_fleet.CSV_COLS) in tpl          # canonical header present
    fs = _fs(tmp_path)
    assert fs.import_csv(tpl)["imported"] == 0           # comments + header only
    assert fs.list_devices() == []                       # safe to import as-is
    assert "inband" in tpl.lower()                       # both attachment modes documented
    assert "routed" in tpl.lower()


def test_revision_increments_on_write(tmp_path):
    fs = _fs(tmp_path)
    assert fs.revision() == 0
    fs.upsert(dict(_ROUTED))
    assert fs.revision() == 1
    fs.delete("d1")
    assert fs.revision() == 2


def test_platform_is_last_csv_column():
    assert gui_fleet.CSV_COLS[-1] == "platform"
    assert gui_fleet.CSV_COLS[0] == "device_id"
    assert "management_type" in gui_fleet.CSV_COLS
