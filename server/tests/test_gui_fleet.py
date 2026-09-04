# server/tests/test_gui_fleet.py
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import json
import os

import gui_fleet
import keyed_state
import pytest


def _fs(tmp_path):
    return gui_fleet.FleetStore(str(tmp_path))


def _shard_path(fs, device_id):
    """Where FleetStore actually persists *device_id*'s row now that it is
    sharded (see keyed_state.py) -- fs.path (fleet.json) is only the LEGACY
    document, migrated away on first use, so a test that pokes stored state
    directly must poke the shard, not that retired path."""
    return os.path.join(keyed_state.shard_dir(fs.path),
                        "%02x.json" % keyed_state.bucket_of(device_id))


_ROUTED = {"device_id": "d1", "device_ip": "10.0.0.1", "management_type": "routed",
           "iris_vlan": "666", "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
           "app_ip": "10.0.0.1", "app_mask": "255.255.255.252", "app_gateway": "10.0.0.2",
           "model": "C9300", "platform": "guestshell"}
_ROUTER = {"device_id": "r1", "device_ip": "192.0.2.10",
           "management_type": "router-routed", "vpg_number": "10",
           "app_ip": "10.8.0.2", "app_mask": "255.255.255.252",
           "app_gateway": "10.8.0.1", "model": "C8000V", "platform": "router"}
_XRHOST = {"device_id": "xr1", "device_ip": "10.0.0.9",
           "management_type": "xr-host", "model": "8201", "platform": "xr-appmgr"}
_XR_FORBIDDEN_FIELDS = {
    "iris_vlan": "100", "svi_ip": "10.0.0.2", "svi_mask": "255.255.255.252",
    "app_ip": "10.0.0.3", "app_mask": "255.255.255.252", "app_gateway": "10.0.0.4",
    "inband_vlan": "100", "ios_ssh_host": "10.0.0.5", "vpg_number": "5",
    "nat_interface": "GigabitEthernet1", "svi_igp": "isis",
}


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


def test_reserved_seeder_device_id_rejected(tmp_path):
    with pytest.raises(ValueError, match="reserved"):
        _fs(tmp_path).upsert(dict(_ROUTED, device_id="seeder"))


def test_upsert_rejects_invalid_records(tmp_path):
    fs = _fs(tmp_path)
    bad = [
        {"device_id": "d1", "device_ip": "nope", "management_type": "routed"},
        {"device_id": "bad id", "device_ip": "10.0.0.1", "management_type": "routed"},
        {"device_id": "d1", "device_ip": "10.0.0.1", "management_type": "sideways"},
        # inband with a routed VLAN field is rejected
        dict(_ROUTED, device_id="d2", management_type="inband", inband_vlan="120",
             svi_ip="", svi_mask="", platform="guestshell"),
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


def test_inband_iox_ssh_host_optional_and_validated(tmp_path):
    fs = _fs(tmp_path)
    # inband IOx is accepted WITHOUT ios_ssh_host (it defaults to the device's
    # management IP at plan time), and platform=iox persists.
    saved = fs.upsert({"device_id": "ie1", "device_ip": "192.0.2.30",
                       "management_type": "inband", "inband_vlan": "120",
                       "app_ip": "192.0.2.31", "app_mask": "255.255.255.0",
                       "app_gateway": "192.0.2.1", "platform": "iox"})
    assert saved["platform"] == "iox" and not saved.get("ios_ssh_host")
    # an explicit override is kept and IPv4-validated
    saved2 = fs.upsert({"device_id": "ie2", "device_ip": "192.0.2.40",
                        "management_type": "inband", "inband_vlan": "120",
                        "app_ip": "192.0.2.41", "app_mask": "255.255.255.0",
                        "app_gateway": "192.0.2.1", "platform": "iox",
                        "ios_ssh_host": "192.0.2.1"})
    assert saved2["ios_ssh_host"] == "192.0.2.1"
    try:
        fs.upsert({"device_id": "ie3", "device_ip": "192.0.2.50",
                   "management_type": "inband", "inband_vlan": "120",
                   "app_ip": "192.0.2.51", "app_mask": "255.255.255.0",
                   "app_gateway": "192.0.2.1", "platform": "iox",
                   "ios_ssh_host": "not-an-ip"})
        assert False, "expected ValueError"
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# svi_igp (issue #85): per-device override of device/device-install.sh's
# SVI_IGP env var, so one server can onboard devices into different fabrics
# (only some of which run IS-IS) without a process-wide setting. It is
# interpolated into a live IOS config block on the device
# (device-install.sh: `[ "$SVI_IGP" = "isis" ] && echo " ip router isis"`),
# so it is validated as a closed enum here -- the same command-injection
# defense every other value bound for that path gets, not a blocklist of
# shell metacharacters that a new one could slip past.
# ---------------------------------------------------------------------------

def test_svi_igp_accepted_on_routed_and_blank_by_default(tmp_path):
    fs = _fs(tmp_path)
    # blank/unset -> "" (device-install.sh then falls back to its own
    # SVI_IGP env var / 'none' default -- no per-device override at all)
    default = fs.upsert(dict(_ROUTED))
    assert default.get("svi_igp", "") == ""
    # an explicit per-device override is stored verbatim
    isis = fs.upsert(dict(_ROUTED, device_id="d2", svi_igp="isis"))
    assert isis["svi_igp"] == "isis"
    none = fs.upsert(dict(_ROUTED, device_id="d3", svi_igp="none"))
    assert none["svi_igp"] == "none"


def test_svi_igp_rejects_anything_outside_the_closed_enum(tmp_path):
    """Not a blocklist: only the literal strings 'none' and 'isis' (or
    blank) are accepted. This also covers the command-injection surface --
    device-install.sh interpolates SVI_IGP into a live IOS config block, so
    whitespace, quotes, and shell/IOS metacharacters must be rejected here,
    not merely tolerated because they happen not to equal 'isis'."""
    # Leading/trailing whitespace is stripped by every field (_text), same as
    # every other column here, so it is deliberately NOT in this bad list --
    # what must be rejected is anything that is not exactly 'none' or 'isis'
    # once that ordinary normalization has run.
    fs = _fs(tmp_path)
    for bad in ("isis; reload", "eigrp", "ISIS", '"isis"', "isis' ; end",
                "isis\x00", "no ip router isis", "isis,none"):
        with pytest.raises(ValueError, match="svi_igp"):
            fs.upsert(dict(_ROUTED, device_id="bad", svi_igp=bad))


def test_svi_igp_rejected_outside_routed_management_type(tmp_path):
    """svi_igp only means anything where IRIS creates the SVI; inband and
    xr-host never create one, so a non-blank value there is a caller mistake
    refused by name, matching every other routed-only field."""
    fs = _fs(tmp_path)
    with pytest.raises(ValueError):
        fs.upsert({"device_id": "edge-1", "device_ip": "192.0.2.10",
                   "management_type": "inband", "inband_vlan": "120",
                   "app_ip": "192.0.2.11", "app_mask": "255.255.255.0",
                   "app_gateway": "192.0.2.1", "platform": "guestshell",
                   "svi_igp": "isis"})
    with pytest.raises(ValueError, match="svi_igp"):
        fs.upsert(dict(_XRHOST, svi_igp="isis"))


def test_svi_igp_csv_roundtrip(tmp_path):
    """The new column sits between nat_interface and platform; an isis row
    imports, exports with the value intact, and re-imports identically."""
    fs = _fs(tmp_path)
    header = ",".join(gui_fleet.CSV_V2_COLS)
    row = ("isis-edge,10.0.0.1,routed,666,10.0.0.2,255.255.255.252,10.0.0.1,"
           "255.255.255.252,10.0.0.2,,,C9300,,,isis,guestshell")
    assert fs.import_csv(header + "\n" + row + "\n")["imported"] == 1
    assert fs.get_device("isis-edge")["svi_igp"] == "isis"
    out = fs.export_csv()
    exported = next(line for line in out.splitlines()
                    if line.startswith("isis-edge,"))
    assert exported.split(",")[gui_fleet.CSV_V2_COLS.index("svi_igp")] == "isis"
    fs2 = gui_fleet.FleetStore(str(tmp_path / "b"))
    assert fs2.import_csv(out)["imported"] == 1
    assert fs2.get_device("isis-edge")["svi_igp"] == "isis"


def test_pre_svi_igp_v2_header_still_imports(tmp_path):
    """A CSV exported before this field existed (current column set minus
    svi_igp) still imports unchanged, and the record reads back with no
    per-device override -- device-install.sh's SVI_IGP env var default
    keeps deciding for that device, exactly as before this field existed."""
    fs = _fs(tmp_path)
    old_header = ("device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,"
                  "app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,"
                  "vpg_number,nat_interface,platform")
    row = ("old-v2,10.0.0.1,routed,666,10.0.0.2,255.255.255.252,10.0.0.1,"
           "255.255.255.252,10.0.0.2,,,C9300,,,guestshell")
    assert fs.import_csv(old_header + "\n" + row + "\n")["imported"] == 1
    dev = fs.get_device("old-v2")
    assert dev["management_type"] == "routed"
    assert dev.get("svi_igp", "") == ""
    assert fs.export_csv().splitlines()[0] == ",".join(gui_fleet.CSV_V2_COLS)


def test_router_modes_validate_and_isolate_fields(tmp_path):
    fs = _fs(tmp_path)
    routed = fs.upsert(dict(_ROUTER))
    assert routed["vpg_number"] == "10"
    assert routed["platform"] == "router"

    nat = fs.upsert(dict(_ROUTER, device_id="r2", management_type="router-nat",
                         nat_interface="GigabitEthernet1"))
    assert nat["nat_interface"] == "GigabitEthernet1"

    invalid = [
        dict(_ROUTER, device_id="bad-vpg", vpg_number="32"),
        dict(_ROUTER, device_id="bad-model", model="ISR4451"),
        dict(_ROUTER, device_id="bad-platform", platform="guestshell"),
        dict(_ROUTER, device_id="switch-field", iris_vlan="666"),
        dict(_ROUTER, device_id="svi-igp-on-router", svi_igp="isis"),
        dict(_ROUTER, device_id="nat-missing", management_type="router-nat"),
        dict(_ROUTER, device_id="nat-on-routed", nat_interface="GigabitEthernet1"),
        dict(_ROUTER, device_id="bad-interface", management_type="router-nat",
             nat_interface="GigabitEthernet1; reload"),
        dict(_ROUTER, device_id="bad-subnet", app_gateway="10.9.0.1"),
    ]
    for record in invalid:
        with pytest.raises(ValueError):
            fs.upsert(record)


def test_router_platform_and_management_type_are_bidirectional(tmp_path):
    fs = _fs(tmp_path)
    with pytest.raises(ValueError, match="platform router requires"):
        fs.upsert(dict(_ROUTED, platform="router"))
    # A blank platform with a C8xxx model auto-resolves at onboard time.
    saved = fs.upsert(dict(_ROUTER, platform=""))
    assert saved["platform"] == "" and saved["model"] == "C8000V"
    with pytest.raises(ValueError, match="Catalyst 8000 models require"):
        fs.upsert(dict(_ROUTED, model="C8000V", platform="guestshell"))


def test_validate_record_model_guardrail_matrix(tmp_path):
    """A device's explicit platform must be one install_options_for allows for
    its model -- gui_onboard.install_options_for and validate_record share
    one table, so these two views of "what can this model run" cannot drift
    apart. Every family gets one accepted platform and (where the earlier
    router/model coupling checks don't already intercept it) one refused
    platform."""
    fs = _fs(tmp_path)
    ok = [
        dict(_ROUTED, device_id="c9-gs", model="C9300-48UXM", platform="guestshell"),
        dict(_ROUTED, device_id="c9-iox", model="C9300-48UXM", platform="iox"),
        dict(_ROUTED, device_id="ie3-iox", model="IE-3400", platform="iox"),
        dict(_ROUTED, device_id="ir11-iox", model="IR1101", platform="iox"),
        dict(_ROUTED, device_id="ir18-iox", model="IR1800", platform="iox"),
        dict(_ROUTED, device_id="isr-gs", model="ISR4451", platform="guestshell"),
        dict(_ROUTED, device_id="asr-gs", model="ASR1001", platform="guestshell"),
        dict(_ROUTED, device_id="csr-gs", model="CSR1000v", platform="guestshell"),
        dict(_ROUTER, device_id="c8-router", model="C8000V", platform="router"),
        dict(_XRHOST, device_id="xr-8201"),
    ]
    for record in ok:
        saved = fs.upsert(record)
        assert saved["platform"] == record["platform"], record["device_id"]

    bad = [
        # the motivating incident: an IOS-XR 8201 offered guestshell/iox
        dict(_ROUTED, device_id="xr-8201-gs", model="8201", platform="guestshell"),
        dict(_ROUTED, device_id="xr-8201-iox", model="8201", platform="iox"),
        # an IOx-only family offered guestshell
        dict(_ROUTED, device_id="ie3-gs", model="IE-3400", platform="guestshell"),
        # a Guest-Shell-only family offered iox
        dict(_ROUTED, device_id="isr-iox", model="ISR4451", platform="iox"),
    ]
    for record in bad:
        with pytest.raises(ValueError, match="cannot run"):
            fs.upsert(record)


def test_validate_record_refuses_8201_guestshell_explicitly():
    # The exact scenario from the brief: model 8201 (Cisco 8000-series,
    # IOS-XR) must never accept platform=guestshell, whether typed at the
    # console or smuggled through a CSV import.
    with pytest.raises(ValueError) as exc:
        gui_fleet.validate_record(dict(_ROUTED, device_id="d1", model="8201",
                                       platform="guestshell"))
    assert "8201" in str(exc.value) and "guestshell" in str(exc.value)


def test_validate_record_accepts_the_xr_platform_on_xr_hardware(tmp_path):
    """IRIS stages to IOS-XR through the appmgr container agent, so an XR
    device may carry a platform now -- the one that is IOS-XR. v1 is
    validated on the Cisco 8000 series only, so this is the one model shape
    that qualifies (see the refusal test below for a family-ambiguous model
    that does NOT, even once os_family classifies it as XR). xr-appmgr is
    mutually bound to management_type xr-host (see the bidirectional tests
    below), so acceptance is exercised through that pairing rather than the
    fabricated 'routed' management type this used to (incorrectly) accept."""
    fs = _fs(tmp_path)
    saved = fs.upsert(dict(_XRHOST, device_id="xr-8201", model="8201",
                           platform="xr-appmgr"))
    assert saved["platform"] == "xr-appmgr"
    # and with no model recorded yet, where only the classified family knows
    saved = fs.upsert(dict(_XRHOST, device_id="xr-nomodel", model="",
                           platform="xr-appmgr", os_family="xr"))
    assert saved["platform"] == "xr-appmgr"


def test_validate_record_refuses_the_xr_platform_on_non_xr_hardware(tmp_path):
    """The inverse guardrail. It fails closed on a blank/unrecognized model
    too: 'nobody has established this is IOS-XR' is not permission to run an
    appmgr recipe against it."""
    fs = _fs(tmp_path)
    for model in ("C9300-48UXM", "IE-3400", "WS-C2960", ""):
        with pytest.raises(ValueError, match="IOS-XR"):
            fs.upsert(dict(_ROUTED, device_id="d-xr", model=model,
                           platform="xr-appmgr"))


def test_validate_record_refuses_the_xr_platform_on_a_non_8000_xr_family_device(tmp_path):
    """F5: v1 is validated on the Cisco 8000 series only. os_family=="xr"
    being classified is not by itself enough -- an ASR-9906 (family-ambiguous
    model prefix, but confirmed IOS-XR by os_family) still may not run the
    appmgr recipe until the model shape is one this v1 agent actually
    supports."""
    fs = _fs(tmp_path)
    with pytest.raises(ValueError, match="IOS-XR"):
        fs.upsert(dict(_ROUTED, device_id="asr9k", model="ASR-9906",
                       platform="xr-appmgr", os_family="xr"))


def test_validate_record_xr_os_family_refuses_explicit_platform():
    # os_family=="xr" forbids every explicit platform even for a model this
    # table has never seen before -- the ASR9k-shaped case: a model that
    # superficially matches the ISR/ASR/CSR guestshell family but is actually
    # IOS-XR hardware.
    with pytest.raises(ValueError, match="cannot run"):
        gui_fleet.validate_record(dict(_ROUTED, device_id="d1", model="ASR-9906",
                                       platform="guestshell", os_family="xr"))


def test_validate_record_unknown_model_does_not_restrict_platform(tmp_path):
    # None (unknown/blank model) means "no guardrail opinion" -- an
    # unrecognized model must still accept any structurally-valid platform,
    # exactly as before this guardrail existed.
    fs = _fs(tmp_path)
    saved = fs.upsert(dict(_ROUTED, device_id="d1", model="WS-C2960", platform="guestshell"))
    assert saved["platform"] == "guestshell"


def test_validate_record_normalizes_sys_suffix_on_import(tmp_path):
    # '8201-SYS' and '8201' must be stored identically -- and, since the
    # normalized form fails the SAME guardrail as the bare number, a
    # platform=guestshell row for '8201-SYS' is refused exactly like '8201'
    # is: no suffix-shaped loophole for a CSV import to smuggle through.
    normalized = gui_fleet.validate_record(dict(_ROUTED, device_id="d1",
                                                model="8201-SYS", platform=""))
    assert normalized["model"] == "8201"
    fs = _fs(tmp_path)
    with pytest.raises(ValueError, match="cannot run"):
        fs.upsert(dict(_ROUTED, device_id="d2", model="8201-SYS", platform="guestshell"))


def test_xr_host_accepted_and_prunes_old_addressing_fields_on_upsert(tmp_path):
    """The matrix's core positive case: xr-host + xr-appmgr + 8201 is
    accepted, and switching an existing XE-attached device to xr-host prunes
    every stale app-network field rather than carrying it forward silently
    -- the exact fabrication risk this task closes (a live run had to
    fabricate an 'inband' row for an XR router because nothing honest
    existed)."""
    fs = _fs(tmp_path)
    fs.upsert(dict(_ROUTED, device_id="was-routed"))
    saved = fs.upsert({"device_id": "was-routed", "management_type": "xr-host",
                       "model": "8201", "platform": "xr-appmgr"})
    assert saved["management_type"] == "xr-host" and saved["platform"] == "xr-appmgr"
    for field in _XR_FORBIDDEN_FIELDS:
        assert not saved.get(field), field

    # and a fresh xr-host row, with no prior state to prune
    fresh = fs.upsert(dict(_XRHOST, device_id="fresh-xr"))
    assert fresh["management_type"] == "xr-host" and fresh["platform"] == "xr-appmgr"
    for field in _XR_FORBIDDEN_FIELDS:
        assert not fresh.get(field), field


def test_xr_host_upsert_prunes_a_fabricated_inband_rows_addressing_in_one_shot(tmp_path):
    """The exact .20 healing shape: a router fabricated as an inband row
    (full XE addressing, no platform override) is corrected to
    xr-host/xr-appmgr in a single upsert. All ten addressing fields -- the
    ones this fabricated shape actually carried -- are pruned, not
    partially retained; pinning the OUT-of-fabrication direction the
    pruning branch's own comment claims ('either direction')."""
    fs = _fs(tmp_path)
    fs.upsert({"device_id": "r1", "device_ip": "10.0.0.9",
               "management_type": "inband", "inband_vlan": "120",
               "ios_ssh_host": "10.0.0.8", "app_ip": "192.0.2.11",
               "app_mask": "255.255.255.0", "app_gateway": "192.0.2.1",
               "model": "8201"})
    saved = fs.upsert({"device_id": "r1", "management_type": "xr-host",
                       "platform": "xr-appmgr"})
    assert saved["management_type"] == "xr-host" and saved["platform"] == "xr-appmgr"
    for field in _XR_FORBIDDEN_FIELDS:
        assert not saved.get(field), field


def test_xr_host_to_inband_transition_drops_stale_platform(tmp_path):
    """The platform-clear guard (originally keyed on old_router != new_router
    alone) must also fire when only one side of the swap is xr-host: routed
    and inband are both non-router, so that XOR alone is False, and without
    tracking the xr side too a stale platform=xr-appmgr would survive the
    swap and surface 'platform xr-appmgr requires management_type xr-host'
    about a field the operator never sent. Moving an established xr-host
    device to inband with fresh addressing and no explicit platform must
    drop the stale platform and validate cleanly -- the same clean drop the
    router family already gets."""
    fs = _fs(tmp_path)
    fs.upsert(dict(_XRHOST, device_id="d1"))
    saved = fs.upsert({"device_id": "d1", "management_type": "inband",
                       "inband_vlan": "120", "app_ip": "192.0.2.11",
                       "app_mask": "255.255.255.0", "app_gateway": "192.0.2.1"})
    assert saved["management_type"] == "inband"
    assert saved.get("platform", "") == ""
    assert saved["inband_vlan"] == "120" and saved["app_ip"] == "192.0.2.11"


def test_inband_to_xr_host_transition_without_platform_fails_honestly(tmp_path):
    """The inverse direction: an established inband/XE device moved to
    xr-host without an explicit platform=xr-appmgr fails with the
    mutual-requirement message -- the honest outcome, since the swap also
    drops the stale XE platform rather than silently keeping it (which
    would let an xr-host row sit with a non-xr-appmgr platform)."""
    fs = _fs(tmp_path)
    fs.upsert({"device_id": "d1", "device_ip": "192.0.2.10",
               "management_type": "inband", "inband_vlan": "120",
               "app_ip": "192.0.2.11", "app_mask": "255.255.255.0",
               "app_gateway": "192.0.2.1", "platform": "guestshell"})
    with pytest.raises(ValueError,
                       match="management_type xr-host requires platform xr-appmgr"):
        fs.upsert({"device_id": "d1", "management_type": "xr-host", "model": "8201"})


def test_xr_host_rejects_every_app_network_field(tmp_path):
    """XR host networking shares the router's own network stack -- no VLAN,
    SVI, app IP/mask/gateway, VPG, or NAT interface exists to configure, so
    a non-empty one is refused by name, not silently dropped."""
    fs = _fs(tmp_path)
    for field, value in _XR_FORBIDDEN_FIELDS.items():
        with pytest.raises(ValueError, match=field):
            fs.upsert(dict(_XRHOST, device_id="xr-forbidden-" + field, **{field: value}))


def test_xr_host_requires_xr_appmgr_platform(tmp_path):
    """One direction of the mutual coupling: management_type xr-host demands
    platform xr-appmgr -- no other platform value (including blank) may
    pair with it. Model is blanked here so the pre-existing model<->platform
    ladder (which would otherwise catch guestshell/iox on an 8201 first, via
    a different, equally valid message) abstains and this check is the one
    that fires."""
    fs = _fs(tmp_path)
    for platform in ("", "guestshell", "iox"):
        with pytest.raises(ValueError,
                           match="management_type xr-host requires platform xr-appmgr"):
            fs.upsert(dict(_XRHOST, device_id="xr-bad-platform", model="",
                           platform=platform))
    # platform=router hits the pre-existing router<->platform coupling
    # first, but xr-host is refused all the same.
    with pytest.raises(ValueError, match="platform router requires"):
        fs.upsert(dict(_XRHOST, device_id="xr-bad-router-platform", platform="router"))


def test_xr_appmgr_platform_requires_xr_host_management_type(tmp_path):
    """The other direction: a fully-validated record naming platform
    xr-appmgr with any XE management_type is refused -- this closes the gap
    that let an XR router get recorded as 'inband' with a made-up VLAN.
    router-routed/router-nat additionally trip the pre-existing
    router<->platform coupling (an XR model is never platform router), so
    only routed/inband exercise the new message text; all four are
    refused."""
    fs = _fs(tmp_path)
    with pytest.raises(ValueError,
                       match="platform xr-appmgr requires management_type xr-host"):
        fs.upsert(dict(_XRHOST, device_id="xr-bad-routed", management_type="routed"))
    with pytest.raises(ValueError,
                       match="platform xr-appmgr requires management_type xr-host"):
        fs.upsert(dict(_XRHOST, device_id="xr-bad-inband", management_type="inband"))
    for mgmt_type in ("router-routed", "router-nat"):
        with pytest.raises(ValueError):
            fs.upsert(dict(_XRHOST, device_id="xr-bad-" + mgmt_type,
                           management_type=mgmt_type))


def test_xr_host_still_refused_by_model_platform_ladder(tmp_path):
    """xr-host + xr-appmgr composes with the pre-existing model<->platform
    guardrail rather than bypassing it -- a switch model must still be
    refused even once it carries an otherwise-valid xr-host/xr-appmgr
    pairing."""
    fs = _fs(tmp_path)
    with pytest.raises(ValueError, match="IOS-XR"):
        fs.upsert(dict(_XRHOST, device_id="xr-on-a-switch", model="C9300-48UXM"))


def test_legacy_upsert_accepts_xr_appmgr_platform_without_management_type(tmp_path):
    """The legacy short-circuit stays untouched: an inventory-only device may
    carry platform xr-appmgr before a management type is chosen (the console
    records the live probe's platform before the operator picks xr-host)."""
    fs = _fs(tmp_path)
    saved = fs.upsert({"device_id": "xr-inventory", "device_ip": "10.0.0.9",
                       "model": "8201", "platform": "xr-appmgr"})
    assert saved["platform"] == "xr-appmgr"
    assert saved["management_type"] == "legacy_routed"


def test_management_type_enum_error_mentions_xr_host():
    with pytest.raises(ValueError, match="xr-host"):
        gui_fleet.validate_record({"device_id": "d1", "device_ip": "10.0.0.1",
                                   "management_type": "bogus"})


def test_upsert_management_type_enum_error_mentions_xr_host(tmp_path):
    fs = _fs(tmp_path)
    with pytest.raises(ValueError, match="xr-host"):
        fs.upsert({"device_id": "d1", "device_ip": "10.0.0.1",
                  "management_type": "bogus"})


def test_management_type_transitions_clear_only_incompatible_fields(tmp_path):
    fs = _fs(tmp_path)
    fs.upsert(dict(_ROUTED))
    router = fs.upsert({
        "device_id": "d1", "management_type": "router-routed",
        "model": "C8000V", "vpg_number": "10",
        "app_ip": "10.8.0.2", "app_mask": "255.255.255.252",
        "app_gateway": "10.8.0.1"})
    assert router["vpg_number"] == "10" and router.get("platform", "") == ""
    assert not any(router.get(key) for key in ("iris_vlan", "svi_ip", "svi_mask"))

    nat = fs.upsert({"device_id": "d1", "management_type": "router-nat",
                     "nat_interface": "GigabitEthernet1"})
    assert nat["vpg_number"] == "10" and nat["nat_interface"] == "GigabitEthernet1"
    routed_again = fs.upsert({"device_id": "d1", "management_type": "router-routed"})
    assert routed_again["vpg_number"] == "10" and not routed_again.get("nat_interface")

    switch = fs.upsert({
        "device_id": "d1", "management_type": "inband", "model": "C9300",
        "inband_vlan": "120", "app_ip": "192.0.2.11",
        "app_mask": "255.255.255.0", "app_gateway": "192.0.2.1"})
    assert switch["inband_vlan"] == "120" and not switch.get("vpg_number")


def test_import_export_csv_roundtrip(tmp_path):
    fs = _fs(tmp_path)
    header = ",".join(gui_fleet.CSV_V2_COLS)
    csv_in = (header + "\n"
              "# a comment line\n"
              "d1,10.0.0.1,routed,666,10.0.0.2,255.255.255.252,10.0.0.1,255.255.255.252,10.0.0.2,,,C9300,,,,guestshell\n"
              "edge,10.0.0.5,inband,,,,10.0.0.6,255.255.255.0,10.0.0.1,120,,C9300,,,,guestshell\n"
              "r1,192.0.2.10,router-nat,,,,10.8.0.2,255.255.255.252,10.8.0.1,,,C8000V,10,GigabitEthernet1,,router\n")
    stats = fs.import_csv(csv_in)
    assert stats["imported"] == 3 and stats["new"] == 3 and stats["updated"] == 0
    assert stats["skipped"] == 2                       # header + comment line
    assert {d["device_id"] for d in fs.list_devices()} == {"d1", "edge", "r1"}
    out = fs.export_csv()
    assert out.splitlines()[0] == header
    assert "d1,10.0.0.1,routed,666" in out
    assert "edge,10.0.0.5,inband" in out
    assert "r1,192.0.2.10,router-nat" in out
    # re-importing the export reproduces the same fleet
    fs2 = gui_fleet.FleetStore(str(tmp_path / "b"))
    assert fs2.import_csv(out)["imported"] == 3
    assert fs2.get_device("edge")["management_type"] == "inband"
    assert fs2.get_device("r1")["nat_interface"] == "GigabitEthernet1"


def test_import_csv_stats_new_updated_skipped(tmp_path):
    fs = _fs(tmp_path)
    fs.upsert(dict(_ROUTED, device_id="d1", device_ip="10.0.0.9"))   # pre-existing
    header = ",".join(gui_fleet.CSV_V2_COLS)
    csv_in = (header + "\n"
              "# comment\n"
              "\n"
              "d1,10.0.0.1,routed,666,10.0.0.2,255.255.255.252,10.0.0.1,255.255.255.252,10.0.0.2,,,C9300,,,,guestshell\n"
              "d2,10.0.0.5,routed,777,10.0.0.6,255.255.255.252,10.0.0.5,255.255.255.252,10.0.0.6,,,C9300,,,,guestshell\n")
    stats = fs.import_csv(csv_in)
    assert stats == {"imported": 2, "new": 1, "updated": 1, "skipped": 3}
    assert fs.get_device("d1")["device_ip"] == "10.0.0.1"     # overwrite applied


def test_import_csv_rejects_bad_rows_atomically(tmp_path):
    fs = _fs(tmp_path)
    header = ",".join(gui_fleet.CSV_V2_COLS)
    # a populated but invalid row (bad IP) must abort the whole import
    bad = "d1,not-an-ip,routed,666,10.0.0.2,255.255.255.252,10.0.0.1,255.255.255.252,10.0.0.2,,,C9300,,,,guestshell"
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


def test_pre_router_v2_header_still_imports(tmp_path):
    fs = _fs(tmp_path)
    old_header = ("device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,"
                  "app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,platform")
    row = ("old-v2,10.0.0.1,routed,666,10.0.0.2,255.255.255.252,10.0.0.1,"
           "255.255.255.252,10.0.0.2,,,C9300,guestshell")
    assert fs.import_csv(old_header + "\n" + row + "\n")["imported"] == 1
    assert fs.get_device("old-v2")["management_type"] == "routed"
    assert fs.export_csv().splitlines()[0] == ",".join(gui_fleet.CSV_V2_COLS)


def test_example_csv_is_a_safe_importable_template(tmp_path):
    tpl = gui_fleet.FleetStore.example_csv()
    assert ",".join(gui_fleet.CSV_V2_COLS) in tpl          # canonical header present
    fs = _fs(tmp_path)
    assert fs.import_csv(tpl)["imported"] == 0           # comments + header only
    assert fs.list_devices() == []                       # safe to import as-is
    assert "inband" in tpl.lower()                       # both management types documented
    assert "routed" in tpl.lower()
    assert "router-nat" in tpl.lower()
    assert "xr-host" in tpl.lower()


def test_revision_increments_on_write(tmp_path):
    fs = _fs(tmp_path)
    assert fs.revision() == 0
    fs.upsert(dict(_ROUTED))
    assert fs.revision() == 1
    fs.delete("d1")
    assert fs.revision() == 2


def test_bulk_upsert_bumps_revision_once_per_call_not_per_device(tmp_path):
    fs = _fs(tmp_path)
    fs.upsert(dict(_ROUTED))
    fs.upsert(dict(_ROUTER, device_id="other"))
    assert fs.revision() == 2
    result = fs.bulk_upsert(["d1", "other"], {"credential_profile_id": "lab"})
    assert all(v["ok"] for v in result.values())
    assert fs.revision() == 3           # one bump, not two
    # a call where NOTHING applies bumps nothing
    result = fs.bulk_upsert(["ghost"], {"credential_profile_id": "lab"})
    assert result == {"ghost": {"ok": False, "error": "no such device"}}
    assert fs.revision() == 3


def test_snapshot_returns_the_revision_that_matches_its_rows(tmp_path):
    fs = _fs(tmp_path)
    fs.upsert(dict(_ROUTED))
    revision, rows = fs.snapshot()
    assert revision == fs.revision() == 1
    assert [r["device_id"] for r in rows] == ["d1"]
    fs.upsert(dict(_ROUTER, device_id="other"))
    revision, rows = fs.snapshot()
    assert revision == fs.revision() == 2
    assert {r["device_id"] for r in rows} == {"d1", "other"}


def test_snapshot_settles_a_write_racing_its_own_multi_shard_scan(tmp_path,
                                                                  monkeypatch):
    """snapshot() is not one atomic read any more (see its docstring): the
    rows come from up to SHARD_COUNT separate shard reads, so a write
    landing in the middle of that scan could pair FRESH rows with a STALE
    revision number -- exactly the "rows from state A labeled with the
    revision of state B" bug the whole-document read this replaces could
    never produce. This simulates that race directly: the FIRST call to the
    underlying multi-shard scan performs an extra write before returning,
    as if another request's upsert() landed mid-scan. Without the settle
    loop (read revision, scan, read revision again, retry until they
    agree), the naive "read revision once, then scan" order returns
    revision=1 paired with a scan that already reflects 2 devices -- this
    proves the settled read never does that: it retries until revision and
    rows agree, and reports the SAME revision fs.revision() reports once
    everything has settled."""
    fs = _fs(tmp_path)
    fs.upsert(dict(_ROUTED))                      # revision 1, d1 only
    real_snapshot = fs._devices.snapshot
    calls = {"n": 0}

    def racing_snapshot():
        calls["n"] += 1
        if calls["n"] == 1:
            # A write races the FIRST attempt's scan, landing between it and
            # its paired revision read.
            fs.upsert(dict(_ROUTER, device_id="other"))
        return real_snapshot()

    monkeypatch.setattr(fs._devices, "snapshot", racing_snapshot)
    revision, rows = fs.snapshot()
    assert calls["n"] >= 2, "the race was not retried -- settle loop skipped"
    assert revision == fs.revision() == 2
    assert {r["device_id"] for r in rows} == {"d1", "other"}


def test_snapshot_settle_fallback_is_never_staler_than_the_rows(tmp_path,
                                                                 monkeypatch):
    """When every settle attempt keeps losing the race (pathological, but
    the code has to do SOMETHING deterministic), the fallback must still
    never pair a LOWER revision than what _bump_revision guarantees is
    already reflected by the time a write's row content is visible -- see
    _bump_revision's docstring. This forces every attempt to see a fresh
    write (never settling) and checks the final answer is still >= the
    true revision, never the stale value from before this call started."""
    fs = _fs(tmp_path)
    fs.upsert(dict(_ROUTED))
    real_snapshot = fs._devices.snapshot
    calls = {"n": 0}

    def always_racing_snapshot():
        calls["n"] += 1
        fs.upsert({"device_id": "d1", "model": "C9300-%d" % calls["n"]})
        return real_snapshot()

    monkeypatch.setattr(fs._devices, "snapshot", always_racing_snapshot)
    starting_revision = fs.revision()
    revision, rows = fs.snapshot()
    assert revision >= starting_revision + fs._SNAPSHOT_SETTLE_ATTEMPTS
    assert revision == fs.revision()   # the fallback used the freshest read


def test_platform_is_last_csv_column():
    assert gui_fleet.CSV_V2_COLS[-1] == "platform"
    assert gui_fleet.CSV_V2_COLS[0] == "device_id"
    assert "management_type" in gui_fleet.CSV_V2_COLS


# ---------------------------------------------------------------------------
# xr-host CSV v2 round trip
# ---------------------------------------------------------------------------

def test_xr_host_csv_roundtrip_addressing_columns_stay_empty(tmp_path):
    """An xr-host record exports with management_type xr-host, platform
    xr-appmgr in the last column, and every addressing column empty (not the
    string 'None') -- and reimporting that export reproduces the same
    record, the round trip this management type has to survive."""
    fs = _fs(tmp_path)
    fs.upsert(dict(_XRHOST))
    out = fs.export_csv()
    row = next(line for line in out.splitlines() if line.startswith("xr1,"))
    fields = row.split(",")
    assert fields[2] == "xr-host"
    assert fields[-1] == "xr-appmgr"          # platform is the last CSV column
    for field in _XR_FORBIDDEN_FIELDS:
        assert fields[gui_fleet.CSV_V2_COLS.index(field)] == ""
    fs2 = gui_fleet.FleetStore(str(tmp_path / "b"))
    assert fs2.import_csv(out)["imported"] == 1
    reimported = fs2.get_device("xr1")
    assert reimported["management_type"] == "xr-host"
    assert reimported["platform"] == "xr-appmgr"
    assert reimported["model"] == "8201"
    for field in _XR_FORBIDDEN_FIELDS:
        assert not reimported.get(field)


def test_import_csv_rejects_xr_host_row_with_app_ip_atomically(tmp_path):
    """XR host networking has no app_ip to carry; a CSV row that fills it in
    anyway is rejected, and -- matching the existing bad-IP atomic reject --
    the whole import aborts, including an otherwise-good row ahead of it."""
    fs = _fs(tmp_path)
    header = ",".join(gui_fleet.CSV_V2_COLS)
    good = ("d1,10.0.0.1,routed,666,10.0.0.2,255.255.255.252,10.0.0.1,"
            "255.255.255.252,10.0.0.2,,,C9300,,,,guestshell")
    bad = "xr1,10.0.0.9,xr-host,,,,192.0.2.99,,,,,8201,,,,xr-appmgr"
    with pytest.raises(ValueError, match="app_ip"):
        fs.import_csv(header + "\n" + good + "\n" + bad + "\n")
    assert fs.list_devices() == []   # atomic: the good row is rejected too


def test_network_attachment_csv_header_is_rejected(tmp_path):
    """The retired network_attachment v2 header alias is gone: a CSV using it
    (an old export from before the rename) fails exactly like any other
    unrecognized header -- not a silent partial import, not a field-alias
    substitution, just the same unknown-header ValueError every other bad
    header produces."""
    fs = _fs(tmp_path)
    alias_header = ",".join(
        col if col != "management_type" else "network_attachment"
        for col in gui_fleet.CSV_V2_COLS)
    row = "xr1,10.0.0.9,xr-host,,,,,,,,,8201,,,,xr-appmgr"
    with pytest.raises(ValueError, match="v2 named header"):
        fs.import_csv(alias_header + "\n" + row + "\n")
    assert fs.list_devices() == []


def test_legacy_network_attachment_only_row_reads_as_unclassified(tmp_path):
    """Decision 1: the network_attachment read-alias is REMOVED from
    FleetStore._read -- a fleet.json row still carrying only the retired
    alias key (never re-saved since before the rename) is not migrated in
    memory. It reads back exactly as stored: no management_type key at all,
    so it is unclassified/legacy from every reader's point of view (the
    console table, the filter, an operator script) until an upsert
    normalizes it."""
    fs = _fs(tmp_path)
    with open(fs.path, "w") as stream:
        json.dump({"revision": 1, "devices": {"d1": {
            "device_id": "d1", "device_ip": "10.0.0.1",
            "network_attachment": "routed", "registered_at": 1000,
        }}}, stream)
    dev = fs.get_device("d1")
    assert dev.get("management_type") is None
    assert dev["network_attachment"] == "routed"          # untouched, not migrated
    assert [d.get("management_type") for d in fs.list_devices()] == [None]


def test_pre_router_v2_header_still_imports_xr_host_row(tmp_path):
    """The pre-router-fields v2 header (no vpg_number/nat_interface columns)
    still imports an xr-host row -- it never carried those columns either."""
    fs = _fs(tmp_path)
    old_header = ("device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,"
                  "app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,platform")
    row = "old-v2-xr,10.0.0.9,xr-host,,,,,,,,,8201,xr-appmgr"
    assert fs.import_csv(old_header + "\n" + row + "\n")["imported"] == 1
    dev = fs.get_device("old-v2-xr")
    assert dev["management_type"] == "xr-host" and dev["platform"] == "xr-appmgr"
    assert fs.export_csv().splitlines()[0] == ",".join(gui_fleet.CSV_V2_COLS)


def test_example_csv_xr_host_row_is_importable_and_validates(tmp_path):
    """example_csv documents the xr-host shape: model 8201, platform
    xr-appmgr, every addressing column empty -- uncommenting that one row
    imports a clean, fully-validated xr-host device."""
    tpl = gui_fleet.FleetStore.example_csv()
    assert "xr-host" in tpl
    assert "xr-appmgr" in tpl
    xr_line = next(line for line in tpl.splitlines() if ",xr-host," in line)
    uncommented = xr_line.lstrip("#").strip()
    header = ",".join(gui_fleet.CSV_V2_COLS)
    fs = _fs(tmp_path)
    assert fs.import_csv(header + "\n" + uncommented + "\n")["imported"] == 1
    devices = fs.list_devices()
    assert len(devices) == 1
    dev = devices[0]
    assert dev["management_type"] == "xr-host" and dev["platform"] == "xr-appmgr"
    assert dev["model"] == "8201"
    for field in _XR_FORBIDDEN_FIELDS:
        assert not dev.get(field)


# ---------------------------------------------------------------------------
# registered_at: which device currently holds this id
# ---------------------------------------------------------------------------

def test_registered_at_is_stamped_once_at_creation(tmp_path):
    """Deployment logs are keyed on the bare device id and deliberately outlive
    a delete, so something has to say which device each one belongs to. This
    stamp does, which only works if an ordinary edit does not move it."""
    clock = [1000]
    fs = gui_fleet.FleetStore(str(tmp_path), now_fn=lambda: clock[0])
    created = fs.upsert(dict(_ROUTED))
    assert created["registered_at"] == 1000

    clock[0] = 2000
    edited = fs.upsert({"device_id": "d1", "model": "C9300-48UXM"})
    assert edited["registered_at"] == 1000, "an edit re-registered the device"
    assert fs.get_device("d1")["registered_at"] == 1000


def test_readding_a_deleted_device_registers_it_afresh(tmp_path):
    """A device deleted and added back is a different machine wearing a
    familiar name -- routinely a rebuilt box. Its predecessor's runs must stop
    counting as its own history, and the new stamp is what draws that line."""
    clock = [1000]
    fs = gui_fleet.FleetStore(str(tmp_path), now_fn=lambda: clock[0])
    fs.upsert(dict(_ROUTED))
    assert fs.delete("d1") is True

    clock[0] = 5000
    readded = fs.upsert(dict(_ROUTED))
    assert readded["registered_at"] == 5000


def test_csv_reimport_keeps_the_registration_stamp(tmp_path):
    """import_csv REPLACES a row wholesale. Without carrying the stamp across,
    a routine re-import would look like a fresh registration of every device
    and orphan the whole fleet's log history."""
    clock = [1000]
    fs = gui_fleet.FleetStore(str(tmp_path), now_fn=lambda: clock[0])
    fs.upsert(dict(_ROUTED))
    header = ",".join(gui_fleet.CSV_V2_COLS)
    row = ",".join(str(_ROUTED.get(c, "")) for c in gui_fleet.CSV_V2_COLS)

    clock[0] = 9000
    fs.import_csv(header + "\n" + row + "\n")

    assert fs.get_device("d1")["registered_at"] == 1000


def test_csv_reimport_keeps_a_cached_os_family(tmp_path):
    """os_family is machine-determined, so it is deliberately NOT a CSV column
    -- an operator typing it would be a new way to lie to the system. But
    import_csv REPLACES a row wholesale, so without carrying it across, the
    documented export -> edit -> re-import bulk workflow silently drops the
    classification and reopens the IOS-XR misroute on the next onboard.

    Platform is blanked here: os_family="xr" now forbids every explicit
    platform (the model-aware install guardrail), and a device actually
    classified "xr" would never carry one -- this test is purely about the
    os_family field surviving the round trip, not about resolving
    guestshell/iox/router."""
    fs = _fs(tmp_path)
    seed = dict(_ROUTED, os_family="xr", platform="")
    fs.upsert(seed)
    header = ",".join(gui_fleet.CSV_V2_COLS)
    row = ",".join(str(seed.get(c, "")) for c in gui_fleet.CSV_V2_COLS)

    fs.import_csv(header + "\n" + row + "\n")

    assert fs.get_device("d1")["os_family"] == "xr"


def test_os_family_is_not_an_operator_editable_csv_column():
    # It must stay machine-determined: exported for nobody to edit, imported
    # from nowhere.
    assert "os_family" not in gui_fleet.CSV_V2_COLS


def test_csv_import_stamps_a_device_it_creates(tmp_path):
    clock = [7000]
    fs = gui_fleet.FleetStore(str(tmp_path), now_fn=lambda: clock[0])
    header = ",".join(gui_fleet.CSV_V2_COLS)
    row = ",".join(str(_ROUTED.get(c, "")) for c in gui_fleet.CSV_V2_COLS)
    fs.import_csv(header + "\n" + row + "\n")
    assert fs.get_device("d1")["registered_at"] == 7000


def test_legacy_unstamped_device_stays_unstamped_on_update(tmp_path):
    """Pokes d1's own SHARD directly, not a single fleet.json -- FleetStore
    is sharded per device now (see _shard_path)."""
    clock = [1000]
    fs = gui_fleet.FleetStore(str(tmp_path), now_fn=lambda: clock[0])
    fs.upsert(dict(_ROUTED))
    shard = _shard_path(fs, "d1")
    with open(shard) as stream:
        data = json.load(stream)
    data["d1"].pop("registered_at")
    with open(shard, "w") as stream:
        json.dump(data, stream)

    clock[0] = 9000
    assert fs.upsert({"device_id": "d1", "model": "C9300-48UXM"})[
        "registered_at"] is None

    header = ",".join(gui_fleet.CSV_V2_COLS)
    row = ",".join(str(_ROUTED.get(c, "")) for c in gui_fleet.CSV_V2_COLS)
    fs.import_csv(header + "\n" + row + "\n")
    assert fs.get_device("d1")["registered_at"] is None


def test_invalid_registration_stamp_is_rejected(tmp_path):
    """Pokes d1's own shard directly -- see
    test_legacy_unstamped_device_stays_unstamped_on_update."""
    fs = gui_fleet.FleetStore(str(tmp_path))
    fs.upsert(dict(_ROUTED))
    shard = _shard_path(fs, "d1")
    with open(shard) as stream:
        data = json.load(stream)
    data["d1"]["registered_at"] = "not-a-timestamp"
    with open(shard, "w") as stream:
        json.dump(data, stream)

    with pytest.raises(ValueError, match="registered_at"):
        fs.upsert({"device_id": "d1", "model": "C9300-48UXM"})


def test_empty_existing_fleet_record_is_rejected(tmp_path):
    fs = gui_fleet.FleetStore(str(tmp_path))
    with open(fs.path, "w") as stream:
        json.dump({"revision": 1, "devices": {"d1": {}}}, stream)

    with pytest.raises(ValueError, match="non-empty object"):
        fs.upsert(dict(_ROUTED))


def test_csv_reimport_keeps_the_credential_profile(tmp_path):
    """The CSV deliberately has no credential column, so the profile assigned
    in the Console after the first import must survive the documented
    export -> edit -> re-import cycle. It used to be the ONE key lost on the
    round trip, and the loss surfaced only later, per device, as an
    onboard/undeploy job failing with 'device has no credential profile'."""
    fs = _fs(tmp_path)
    fs.upsert(dict(_ROUTED, credential_profile_id="lab"))
    before = fs.get_device("d1")
    stats = fs.import_csv(fs.export_csv())
    assert stats["updated"] == 1
    after = fs.get_device("d1")
    assert after["credential_profile_id"] == "lab"
    assert set(before) - set(after) == set(), "keys lost on the round trip"


def test_csv_import_does_not_invent_a_credential_profile(tmp_path):
    fs = _fs(tmp_path)
    header = ",".join(gui_fleet.CSV_V2_COLS)
    row = ",".join(str(_ROUTED.get(c, "")) for c in gui_fleet.CSV_V2_COLS)
    fs.import_csv(header + "\n" + row + "\n")
    assert not fs.get_device("d1").get("credential_profile_id")


def test_import_csv_rejects_duplicate_device_rows_atomically(tmp_path):
    """Two rows for one device used to collapse silently -- last row wins,
    stats claiming one new AND one updated device -- so a conflicting
    duplicate in the sheet was never surfaced."""
    fs = _fs(tmp_path)
    header = ",".join(gui_fleet.CSV_V2_COLS)
    row_a = "d1,10.0.0.1,routed,666,10.0.0.2,255.255.255.252,10.0.0.1,255.255.255.252,10.0.0.2,,,C9300,,,,guestshell"
    row_b = "d1,10.0.0.9,routed,667,10.0.0.6,255.255.255.252,10.0.0.5,255.255.255.252,10.0.0.6,,,C9300,,,,guestshell"
    with pytest.raises(ValueError, match=r"data row 2 repeats device_id d1 from data row 1"):
        fs.import_csv("\n".join([header, row_a, row_b]) + "\n")
    assert fs.list_devices() == []                 # all-or-nothing


def test_corrupt_device_shard_fails_closed_and_is_left_intact(tmp_path):
    """Was test_unparseable_fleet_file_refuses_writes_and_is_left_intact,
    written when a present-but-corrupt fleet.json meant a corrupt WHOLE
    fleet: read as an empty fleet, with the next upsert rewriting it as a
    fresh one-device fleet at revision 1 -- turning repairable corruption
    into silent, permanent loss of the whole inventory. FleetStore is
    sharded per device now (see keyed_state.py): the corruption goes into
    the shard that actually holds d1, and the blast radius narrows on
    purpose -- a device in ANOTHER shard keeps working, while every read or
    write touching the damaged shard fails closed and never overwrites it
    (the same narrowing catalog.py's own migration already accepted --
    see test_catalog.py's
    test_corrupt_policy_state_is_not_read_as_empty_and_is_never_rewritten).
    Reads (get_device/list_devices/snapshot) now fail closed here too,
    where the old whole-document FleetStore let them degrade to an empty
    view -- matching every other keyed store, which never had that
    lenient-read exception in the first place."""
    fs = _fs(tmp_path)
    fs.upsert(dict(_ROUTED))                       # d1
    fs.upsert(dict(_ROUTER, device_id="other"))     # a different shard (bucket_of differs)
    shard = _shard_path(fs, "d1")
    good = open(shard).read()
    with open(shard, "w") as stream:
        stream.write("{not json")
    for write in (lambda: fs.upsert({"device_id": "d1", "device_ip": "10.0.0.5"}),
                  lambda: fs.delete("d1"),
                  lambda: fs.import_csv(",".join(gui_fleet.CSV_V2_COLS) + "\n"
                                        + "d1,10.0.0.7,routed,666,10.0.0.2,255.255.255.252,10.0.0.1,255.255.255.252,10.0.0.2,,,C9300,,,,guestshell\n"),
                  lambda: fs.get_device("d1"),
                  lambda: fs.list_devices(),
                  lambda: fs.snapshot()):
        with pytest.raises(gui_fleet.FleetStateError, match="unreadable"):
            write()
    with open(shard) as stream:
        assert stream.read() == "{not json"        # the evidence survives
    # a device in a DIFFERENT shard is untouched by d1's corruption
    assert fs.get_device("other")["device_id"] == "other"
    # repairing the shard restores it
    with open(shard, "w") as stream:
        stream.write(good)
    assert fs.get_device("d1")["device_id"] == "d1"
    # a MISSING shard is still an empty position writes can create
    os.remove(shard)
    assert fs.upsert({"device_id": "d1", "device_ip": "10.0.0.5"})["device_id"] == "d1"


def test_malformed_fleet_revision_counter_fails_closed_before_mutating(tmp_path):
    """Was test_malformed_fleet_file_refuses_writes: "revision" lived inside
    the single fleet.json document then, so a bad value there blocked every
    write outright. The counter is its own small file now
    (fleet-revision.json, see FleetStore._read_revision) -- a bad value
    there still fails closed, and a write path checks the counter is
    READABLE before it ever touches a device shard (_ensure_revision_readable),
    so a pre-existing corrupt counter refuses the write instead of silently
    creating the device and only raising on the bump that would have
    followed it (which would have left a caller unable to tell, from the
    exception alone, that the device was in fact just written)."""
    fs = _fs(tmp_path)
    fs.upsert(dict(_ROUTED))                    # d1; creates fleet-revision.json at 1
    with open(fs._revision_path, "w") as stream:
        stream.write('{"revision": "not-a-number"}')
    with pytest.raises(gui_fleet.FleetStateError, match="malformed"):
        fs.upsert({"device_id": "new1", "device_ip": "10.0.0.5"})
    with pytest.raises(gui_fleet.FleetStateError, match="malformed"):
        fs.revision()
    with pytest.raises(gui_fleet.FleetStateError, match="malformed"):
        fs.snapshot()
    # the mutation never touched storage, and an unrelated device is unaffected
    assert fs.get_device("new1") is None
    assert fs.get_device("d1")["device_id"] == "d1"
