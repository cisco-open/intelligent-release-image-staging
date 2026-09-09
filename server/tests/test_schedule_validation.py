# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Pure Task 23 schedule validation shared by API and direct writers."""

import pytest

import schedule_validation
import schedules


class _Fleet:
    def __init__(self, rows=()):
        self.rows = {row["device_id"]: row for row in rows}

    def get_device(self, device_id):
        return self.rows.get(device_id)


def _definition(max_devices=10):
    return schedules.normalize_definition({
        "kind": "onboard",
        "target": {"filters": {}, "device_ids": []},
        "payload": {"max_devices": max_devices},
        "when": {"kind": "once", "at": 1_788_883_260,
                 "window_seconds": 3600},
    })


def _validator(tmp_path, rows=(), *, max_concurrent=25,
               service_available=True):
    fleet = _Fleet(rows)
    return schedule_validation.LocalScheduleValidator(
        fleet=fleet,
        plan_fn=lambda _device_id, device: {"resolved": {
            "platform": device["platform"], "model": device.get("model", "")}},
        artifacts_dir=str(tmp_path), max_concurrent=max_concurrent,
        service_available=service_available)


@pytest.mark.parametrize(("kwargs", "reason"), (
    ({"service_available": False}, "onboarding_service_unavailable"),
    ({"max_concurrent": 1}, "scheduled_capacity_unavailable"),
))
def test_creation_refuses_unavailable_service_or_scheduled_capacity(
        tmp_path, kwargs, reason):
    validator = _validator(tmp_path, **kwargs)
    with pytest.raises(schedules.ScheduleValidationError, match=reason):
        validator.validate(_definition(), {"device_ids": []}, "creation")


def test_max_devices_and_growth_boundaries_are_shared(tmp_path):
    validator = _validator(tmp_path)
    with pytest.raises(schedules.ScheduleValidationError,
                       match="max_devices_exceeded"):
        validator.validate(
            _definition(max_devices=1), {"device_ids": ["edge-1", "edge-2"]},
            "creation")

    schedule = dict(_definition(max_devices=10),
                    preview={"device_ids": ["edge-1"]})
    assert validator.validate(
        schedule, {"device_ids": ["edge-1"]}, "window_start") is None
    assert validator.validate(
        schedule, {"device_ids": ["edge-1", "edge-2"]},
        "window_start") == {
            "status": "skipped", "reason": "target_growth_exceeded"}
    zero = dict(_definition(max_devices=10), preview={"device_ids": []})
    assert validator.validate(
        zero, {"device_ids": ["edge-1"]}, "window_start") == {
            "status": "skipped", "reason": "target_growth_exceeded"}


@pytest.mark.parametrize(("model", "filename", "reason"), (
    ("C9300", "iris-amd64.tar", "iox_package_missing"),
    ("IE-3400", "iris-arm64.tar", "iox_package_missing"),
    ("unknown", None, "iox_model_unclassified"),
))
def test_iox_architecture_and_artifact_are_checked_locally(
        tmp_path, model, filename, reason):
    row = {"device_id": "edge-1", "management_type": "inband",
           "platform": "iox", "model": model}
    validator = _validator(tmp_path, (row,))
    with pytest.raises(schedules.ScheduleValidationError, match=reason):
        validator.validate(
            _definition(), {"device_ids": ["edge-1"]}, "creation")
    if filename is not None:
        (tmp_path / filename).write_bytes(b"package")
        assert validator.validate(
            _definition(), {"device_ids": ["edge-1"]}, "creation") is None


def test_assignment_and_legacy_targets_do_not_require_onboarding_artifacts(
        tmp_path):
    validator = _validator(
        tmp_path,
        ({"device_id": "legacy-1", "management_type": "legacy_routed",
          "platform": "iox", "model": "unknown"},),
        max_concurrent=1, service_available=False)
    assignment = schedules.normalize_definition({
        "kind": "assign", "target": {"filters": {}, "device_ids": []},
        "payload": {"image_ids": ["image-a"]},
        "when": {"kind": "once", "at": 1_788_883_260,
                 "window_seconds": 3600},
    })
    assert validator.validate(
        assignment, {"device_ids": ["legacy-1"]}, "creation") is None

    validator = _validator(
        tmp_path,
        ({"device_id": "legacy-1", "management_type": "legacy_routed",
          "platform": "iox", "model": "unknown"},))
    assert validator.validate(
        _definition(), {"device_ids": ["legacy-1"]}, "creation") is None
