# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Flash space pre-check + reclaim planning for the device agent.
Parses IOS `dir flash:` output and decides whether an image fits. SAFETY: the only
automated reclaim is `install remove inactive` — the agent NEVER deletes image
files. If space is still insufficient after that, the agent just syslogs and stops
(the operator decides what to remove). Pure functions — the agent runs the
resulting IOS commands on-box."""
import re

HEADROOM = 200 * 1024 * 1024     # 200 MB slack on top of the image size


def parse_free_bytes(dir_output):
    m = re.search(r"\(([0-9]+) bytes free\)", dir_output)
    if not m:
        raise ValueError("no '(N bytes free)' line in dir output")
    return int(m.group(1))


def has_room(free_bytes, image_size, headroom=HEADROOM):
    return free_bytes >= image_size + headroom


def reclaim_plan(free_bytes, image_size, headroom=HEADROOM):
    """Reclaim steps to try when short on space. Returns [] if there is already
    room. The ONLY automated reclaim is `install remove inactive` — the agent
    never deletes image files; if still short after this, it just syslogs."""
    if has_room(free_bytes, image_size, headroom):
        return []
    return ["install remove inactive"]
