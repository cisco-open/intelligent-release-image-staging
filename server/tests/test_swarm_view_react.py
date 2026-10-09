# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exercise the shipped Console summary against the native swarm producer."""
import json
from pathlib import Path
import subprocess

import auth
import management_api
from peer_registry import PeerRegistry
import telemetry


def test_swarm_summary_counts_native_tracker_entries_and_rejects_partial_pages():
    registry = PeerRegistry()
    for image in ("a" * 40, "b" * 40):
        for kind in ("device", "legacy", "service"):
            registry.announce(image, kind, "192.0.2.1", 6881, left=10, now=100,
                              principal=auth.Principal(kind, "router-a" if kind == "device" else "seeder"))
    hub = telemetry.Telemetry(registry)
    snapshot = hub.swarm_snapshot(now=100.5)
    partial = management_api._swarm_page(json.dumps(snapshot), 1, 0)
    model = Path(__file__).parents[1] / "console-ui/src/swarm-view-model.mjs"
    program = """
import assert from 'node:assert/strict';
import {swarmSummary} from MODULE;
const [native, partial] = INPUT;
// The origin seeder is a hub, not a ring entry. One device under two images
// contributes two entries; sharing an IP with a legacy participant is not ID.
const result = swarmSummary(native);
assert.equal(result.entries, 4);
assert.equal(result.legacy, 2);
assert.equal(result.seederUnavailable, true);
assert.equal(swarmSummary(partial), null);
console.log('native swarm projection PASS');
""".replace("MODULE", json.dumps(model.as_uri())).replace("INPUT", json.dumps([snapshot, partial]))
    result = subprocess.run(["node", "--input-type=module", "-e", program],
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stdout + result.stderr
