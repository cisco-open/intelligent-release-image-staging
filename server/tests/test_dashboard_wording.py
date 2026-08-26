# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import os
import re


REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DASHBOARDS = os.path.join(REPO, "docs", "zensical", "dashboards")
LEGACY_OPERATOR_WORDING = re.compile(
    r"(?<![A-Za-z_])(?:un)?attributed(?![A-Za-z_])", re.IGNORECASE)
COMPATIBILITY_METRICS = (
    "iris_peer_attributed_bytes_total",
    "iris_peer_unattributed_bytes_total",
    "iris_swarm_peers_attributed",
)


def test_dashboards_use_traced_wording_for_operators():
    """Metric identifiers stay compatible; prose uses traced/untraced."""
    for name in ("grafana-iris-swarm.json", "splunk-iris-swarm.xml"):
        with open(os.path.join(DASHBOARDS, name)) as stream:
            text = stream.read()
        assert LEGACY_OPERATOR_WORDING.search(text) is None, name
        assert all(metric in text for metric in COMPATIBILITY_METRICS), name
