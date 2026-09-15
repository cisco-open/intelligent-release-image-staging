# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Read-only IOS-XE / IOS-XR time-source admission check. No configuration."""
import ipaddress
import re
import sys


def require_device_time(text):
    """Require a synchronized, non-local NTP reference, not just an NTP config."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    matches = re.findall(
        r"(?im)^\s*Clock is synchronized,\s*stratum\s+(\d+),\s*"
        r"reference is\s+(\S+)", text.replace("\r", ""))
    valid = len(matches) == 1 and not re.search(r"(?i)Clock is unsynchronized", text)
    if valid:
        stratum, reference = matches[0]
        valid = 1 <= int(stratum) <= 15
        try:
            address = ipaddress.ip_address(reference)
            valid = valid and not (address.is_loopback or address.is_unspecified
                                   or address.is_multicast)
        except ValueError:
            # Refuse local-master and unknown status formats; do not guess.
            valid = False
    if not valid:
        raise ValueError(
            "time preflight failed: no synchronized external NTP source. "
            "Configure an approved time source and wait for 'show ntp status' "
            "to report synchronized before retrying. IRIS does not configure NTP.")
    return {"time_synchronized": True, "time_source": reference}


if __name__ == "__main__":
    try:
        require_device_time(sys.stdin.read())
    except ValueError as exc:
        print("PREREQ: " + str(exc), file=sys.stderr)
        sys.exit(1)
