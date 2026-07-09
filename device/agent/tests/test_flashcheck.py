# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import pytest

import flashcheck

SAMPLE = (
    "Directory of flash:/\n"
    "   1  -rw-  1260618344  Jun 10 2026  cat9k_iosxe.26.01.01.SPA.bin\n"
    "11353194496 bytes total (7935512576 bytes free)\n"
)


def test_parse_free_bytes():
    assert flashcheck.parse_free_bytes(SAMPLE) == 7935512576


def test_parse_free_bytes_missing_raises():
    with pytest.raises(ValueError):
        flashcheck.parse_free_bytes("no free line here")


def test_has_room():
    assert flashcheck.has_room(free_bytes=2_000_000_000,
                               image_size=1_260_618_344)        # +headroom fits
    assert not flashcheck.has_room(free_bytes=1_300_000_000,
                                   image_size=1_260_618_344)


def test_reclaim_plan_is_install_remove_inactive_only():
    # short on space -> ONLY `install remove inactive`; never a delete of any bin
    plan = flashcheck.reclaim_plan(free_bytes=500_000_000, image_size=1_260_618_344)
    assert plan == ["install remove inactive"]
    assert all("delete" not in action for action in plan)


def test_reclaim_plan_empty_when_room():
    assert flashcheck.reclaim_plan(
        free_bytes=9_000_000_000, image_size=1_260_618_344) == []
