# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Operator-facing progress only; never changes installer execution/results."""
import re

SERIES_LABELS = {
    "IE3x00": "IE Switches", "IR1x00": "IR Routers",
    "C9xxx": "Catalyst Switches", "C8xxx": "Catalyst Routers",
    "NCS": "NCS", "XR8000": "Cisco 8000 Series",
    "ISR/ASR/CSR": "Cisco Routers",
}
PLATFORM_LABELS = {"guestshell": "Guest Shell", "router": "Guest Shell",
                   "iox": "IOx", "xr-appmgr": "IOS-XR appmgr"}
ACTION_LABELS = {"onboard": "Onboard", "undeploy": "Undeploy",
                 "iox-recover": "Recover", "iox-reconcile-enabled": "Reconcile"}
_STEP = re.compile(r"^\[(\d+)/(\d+)\]\s+(.+)$")
_OP_OK = re.compile(r"^\s+[a-z][a-z0-9_]* ok \([0-9.]+s\)$")
_POLL_OK = re.compile(r"^(?:IOx services ready|app is [A-Z]+) \(poll \d+/\d+\)$")
_COMPLETE = re.compile(r"^(?:onboard|undeploy) complete:", re.I)
_DIAGNOSTIC = re.compile(r"\b(?:error|failed|failure|warning|refused|timeout)\b", re.I)


def action_label(action):
    return ACTION_LABELS.get(action, "Device action")


def heading(action, series, platform):
    return "%s | %s | %s" % (
        action_label(action), SERIES_LABELS.get(series, "Series not identified"),
        PLATFORM_LABELS.get(platform, "Agent installer"))


def phase(job, number):
    """Emit a broad phase once, without fabricating skipped work on failure."""
    if number <= job.get("_message_phase", 0):
        return []
    job["_message_phase"] = number
    removal = job.get("action") == "undeploy"
    labels = (("Prepare undeployment", "Remove IRIS agent", "Finalize undeployment")
              if removal else
              ("Prepare onboarding", "Deploy IRIS agent", "Finalize onboarding"))
    return ["[%s/3] %s" % (number, labels[number - 1])]


def progress(job, line):
    """Keep failures/notices intact; collapse known routine recipe chatter.

    Detailed mode retains every original installer line in addition to the
    common phases. Unknown output is never discarded: it may be a diagnostic
    or recovery instruction from an older/newer recipe.
    """
    detailed = (job.get("env_extra") or {}).get("IRIS_LOG") == "on"
    if _DIAGNOSTIC.search(line):
        return [line]
    match = _STEP.match(line)
    if match and job.get("action") in ("onboard", "undeploy"):
        step = int(match[1])
        platform = job.get("platform")
        if job["action"] == "undeploy":
            final = (platform == "iox" and step == 4 or
                     platform == "xr-appmgr" and step == 5)
            number = 3 if final else 2
        else:
            final = {"iox": 8, "xr-appmgr": 5,
                     "guestshell": 6, "router": 6}.get(platform)
            number = 3 if final is not None and step >= final else 2 if step >= 3 else 1
        return phase(job, number) + ([line] if detailed else [])
    if _COMPLETE.match(line):
        # The service's final result is authoritative (cleanup can still fail).
        return [line] if detailed else []
    if not detailed and (_OP_OK.match(line) or _POLL_OK.match(line)):
        return []
    return [line]


def result(action, state):
    outcome = {"done": "completed", "error": "failed",
               "cancelled": "cancelled"}.get(state, state)
    return "%s %s." % (action_label(action), outcome)
