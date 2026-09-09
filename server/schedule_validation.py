# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Pure local validation for scheduled onboarding blast radius and artifacts.

Callers provide durable fleet lookup, a plan callback, and local service
configuration.  This module deliberately performs no device I/O and mutates no
schedule, fleet, occurrence, or deployment authority.
"""
import os

import gui_onboard
import schedules


ONBOARD_TARGET_GROWTH_RATIO = 1.25


class LocalScheduleValidator(object):
    """Apply the local checks shared by API and direct schedule writers."""

    def __init__(self, *, fleet, plan_fn, artifacts_dir, max_concurrent,
                 service_available=True):
        self.fleet = fleet
        self.plan_fn = plan_fn
        self.artifacts_dir = artifacts_dir
        self.max_concurrent = max_concurrent
        self.service_available = service_available

    @staticmethod
    def _definition(schedule):
        return schedules.normalize_definition({
            key: schedule[key] for key in schedules.DEFINITION_KEYS
            if key in schedule})

    @staticmethod
    def _ids(snapshot):
        if (not isinstance(snapshot, dict)
                or not isinstance(snapshot.get("device_ids"), list)
                or not all(isinstance(value, str)
                           for value in snapshot["device_ids"])):
            raise schedules.ScheduleValidationError(
                "invalid schedule validation snapshot")
        return list(snapshot["device_ids"])

    @staticmethod
    def _creation_refusal(reason):
        raise schedules.ScheduleValidationError(reason)

    def _iox_artifact_reason(self, device_id, plan):
        resolved = plan.get("resolved") if isinstance(plan, dict) else None
        if not isinstance(resolved, dict) or resolved.get("platform") != "iox":
            return None
        try:
            package = gui_onboard._iox_arch_env(
                device_id, resolved.get("model")).get(
                    "PKG", "iris-arm64.tar")
        except ValueError:
            return "iox_model_unclassified"
        if not os.path.isfile(os.path.join(self.artifacts_dir, package)):
            return "iox_package_missing"
        return None

    def validate(self, schedule, snapshot, phase):
        """Return a window refusal or raise a creation validation error."""
        if phase not in ("creation", "window_start"):
            raise ValueError("invalid schedule validation phase")
        definition = self._definition(schedule)
        device_ids = self._ids(snapshot)
        if definition["kind"] != "onboard":
            return None

        def refuse(reason):
            if phase == "creation":
                self._creation_refusal(reason)
            return {"status": "skipped", "reason": reason}

        if not self.service_available:
            return refuse("onboarding_service_unavailable")
        if type(self.max_concurrent) is not int or self.max_concurrent < 2:
            return refuse("scheduled_capacity_unavailable")
        maximum = definition["payload"]["max_devices"]
        if len(device_ids) > maximum:
            return refuse("max_devices_exceeded")
        if phase == "window_start":
            baseline = len((schedule.get("preview") or {}).get(
                "device_ids", ()))
            if ((baseline == 0 and device_ids)
                    or (baseline and len(device_ids) >
                        baseline * ONBOARD_TARGET_GROWTH_RATIO)):
                return refuse("target_growth_exceeded")

        for device_id in device_ids:
            device = self.fleet.get_device(device_id) if self.fleet else None
            if device is None or device.get(
                    "management_type", "legacy_routed") == "legacy_routed":
                continue
            try:
                plan = self.plan_fn(device_id, device)
            except ValueError:
                continue  # preserved as a per-device terminal refusal
            reason = self._iox_artifact_reason(device_id, plan)
            if reason is not None:
                return refuse(reason)
        return None
