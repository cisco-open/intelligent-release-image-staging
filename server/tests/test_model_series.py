# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Series aliases preserve exact-model classification and installer guards."""
import pytest

import gui_fleet
import gui_onboard
import management_api


@pytest.mark.parametrize("series,model,options", [
    ("IE3x00", "IE-3400-8T2S", ["iox"]),
    ("IR1x00", "IR1101", ["iox"]),
    ("C9xxx", "C9300", ["guestshell", "iox"]),
    ("C8xxx", "C8000V", ["router", "iox"]),
    ("NCS", "NCS-540", ["xr-appmgr"]),
    ("XR8000", "8201-SYS", ["xr-appmgr"]),
])
def test_series_has_same_family_options_and_architecture(series, model, options):
    for spelling in (series, series.lower()):
        assert gui_onboard.family(spelling) == gui_onboard.family(model)
        assert gui_onboard.install_options_for(spelling) == options
        projection = management_api.trusted_target_projection({"model": spelling})
        assert projection["model_family"] == series
        for platform in options:
            assert gui_onboard.resolve_platform({"device_id": "test", "model": spelling,
                                                 "platform": platform}) == platform
        if "iox" in options:
            assert gui_onboard._iox_arch_env("test", spelling) == gui_onboard._iox_arch_env("test", model)
        else:
            with pytest.raises(ValueError):
                gui_onboard._iox_arch_env("test", spelling)


@pytest.mark.parametrize("series,management,platform", [
    ("IE3x00", "inband", "iox"),
    ("IR1x00", "inband", "iox"),
    ("C9xxx", "inband", "guestshell"),
    ("C8xxx", "router-routed", "router"),
    ("C8xxx", "router-routed", "iox"),
    ("NCS", "xr-host", "xr-appmgr"),
    ("XR8000", "xr-host", "xr-appmgr"),
])
def test_series_can_be_saved_with_compatible_management(series, management, platform):
    record = {"device_id": "test-series", "device_ip": "192.0.2.10",
              "model": series, "management_type": management, "platform": platform}
    if management != "xr-host":
        record.update(app_ip="192.0.2.2", app_mask="255.255.255.0", app_gateway="192.0.2.1")
        record.update({"inband_vlan": "10"} if management == "inband" else {"vpg_number": "10"})
    saved = gui_fleet.validate_record(record)
    assert saved["model"] == series
    assert platform in gui_fleet.install_options_for_record(saved)
    record["platform"] = "guestshell" if platform == "xr-appmgr" else "xr-appmgr"
    with pytest.raises(ValueError):
        gui_fleet.validate_record(record)


def test_series_does_not_bypass_xr_or_catalyst_router_guards():
    assert gui_onboard.install_options_for("C9xxx", "xr") == []
    assert gui_onboard.install_options_for("C8xxx", "xr") == []
    with pytest.raises(ValueError):
        gui_onboard.resolve_platform({"device_id": "test", "model": "C8xxx", "platform": "guestshell"})
    with pytest.raises(ValueError):
        gui_onboard.resolve_platform({"device_id": "test", "model": "XR8000", "platform": "xr-appmgr", "os_family": "xe"})
