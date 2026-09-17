# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import pathlib
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from time_preflight import require_device_time
import gui_onboard

SYNC = "Clock is synchronized, stratum 5, reference is 192.0.2.123\n"


@pytest.mark.parametrize("text", [SYNC, SYNC.encode(), "r1#show ntp status\r\n" + SYNC])
def test_accept_synchronized_time(text):
    assert require_device_time(text)["time_synchronized"] is True


@pytest.mark.parametrize("text", [
    "", "NTP is not enabled.", "ntp server 192.0.2.123", "Time source is NTP",
    "Clock is unsynchronized, stratum 16, no reference clock", SYNC + SYNC,
    SYNC.replace("stratum 5", "stratum 16"), SYNC.replace("stratum 5", "stratum 0"),
    SYNC.replace("192.0.2.123", "127.127.1.1"), SYNC.replace("192.0.2.123", "0.0.0.0"),
    SYNC.replace("192.0.2.123", ".LOCL."), "% Invalid input detected",
])
def test_time_check_fails_closed(text):
    with pytest.raises(ValueError, match="time preflight failed"):
        require_device_time(text)


@pytest.mark.parametrize("label", ["guestshell", "iox", "xr"])
@pytest.mark.parametrize("status", [SYNC, "Clock is unsynchronized, stratum 16, no reference clock"])
def test_probe_adds_read_only_time_requirement(monkeypatch, label, status):
    def run(argv, input, **kwargs):
        assert "show ntp status" in input
        assert "configure" not in input
        return SimpleNamespace(returncode=0, stdout="__IRIS_PREFLIGHT_VERSION__\nversion\n"
                               "__IRIS_PREFLIGHT_NTP__\n" + status)
    monkeypatch.setattr(gui_onboard.subprocess, "run", run)
    if status == SYNC:
        assert gui_onboard._probe_sections("runner", {"DEVICE_IP": "192.0.2.1"},
                                           (("version", "show version"),), label)["ntp"] == SYNC
    else:
        with pytest.raises(ValueError, match="time preflight failed"):
            gui_onboard._probe_sections("runner", {"DEVICE_IP": "192.0.2.1"},
                                        (("version", "show version"),), label)
