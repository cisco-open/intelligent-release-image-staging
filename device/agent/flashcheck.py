# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Flash space pre-check + reclaim planning for the device agent.
Parses IOS `dir flash:` output and decides whether an image fits. Automated
reclaim is either `install remove inactive` or deletion of strictly allowlisted,
unused bundle artifacts. Bundle deletion is skipped unless the running image is
confirmed and protected; replaced root images are deleted only when state records
that IRIS placed them. If space remains insufficient, staging stops. Pure
functions — the agent runs the resulting IOS commands on-box."""
import re

HEADROOM = 200 * 1024 * 1024     # 200 MB slack on top of the image size


def parse_free_bytes(dir_output):
    m = re.search(r"\(([0-9]+) bytes free\)", dir_output)
    if not m:
        raise ValueError("no '(N bytes free)' line in dir output")
    return int(m.group(1))


def has_room(free_bytes, image_size, headroom=HEADROOM):
    return free_bytes >= image_size + headroom
