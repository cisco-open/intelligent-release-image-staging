<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Where the dashboard metrics come from in code

This page is for a contributor who is changing what a dashboard panel shows,
adding a metric, or debugging why a panel reads oddly. It traces each metric
family back to the server code that emits it. It explains one metric-naming
exception you need to know before you write a query against it. It also
gives the runbook for updating the shipped Splunk rollout view without
breaking it.

Read [Telemetry signals](../zensical/reference/telemetry-signals.md) for
what each metric means to an operator, and
[Import the Splunk and Grafana dashboards](../zensical/user-guide/dashboards.md)
for the day-to-day import and read procedure. This page only covers where
the numbers come from.

## Where each metric family comes from

`server/metrics.py` renders the whole Prometheus exposition from one
function. It takes the swarm state, the peer ledger's per-torrent totals,
and the catalog's image sizes, among other inputs, and turns them into text;
it never talks to aria2 or the catalog itself. Each caller assembles its own
input first.

`iris_image_size_bytes` comes from the catalog's own size field, recorded at
publish time from the published file itself. The family is emitted only for
an image whose size and info hash are both known, because a partial row
would be a guess.

`iris_origin_sent_bytes_total`, `iris_peer_attributed_bytes_total`,
`iris_peer_unattributed_bytes_total`, `iris_swarm_peers_attributed`, and
`iris_swarm_peers_saturated` all come from one source: the peer ledger's
per-torrent totals, one row per torrent with an origin total, an attributed
total, a count of attributed peers, and a saturated flag. `server/metrics.py`
only formats those rows; the peer ledger does the counting.

## Why one gauge keeps a counter's name

`iris_peer_unattributed_bytes_total` is declared a gauge, not a counter,
even though its name ends in `_total`. The name is kept for dashboard
compatibility, and the value really is a subtraction: origin bytes sent,
minus the bytes traced to a device. That subtraction can step down whenever
a device is traced late, and a counter can never step down. Declare it a
counter instead and Prometheus reads every step down as a reset, then
invents a burst of untraced bytes at the exact moment tracing improved. When
you write a query against this family, graph the value. Never wrap it in
`rate()` or `increase()`.

## Why a device's own transfer record is a floor

The device-side hook that captures per-peer bytes for the dashboards reads
aria2's live peer list the instant a download finishes. A peer that sent the
device bytes and disconnected before that instant leaves no row in the
read, so the device's own transfer count can only undercount peer-to-peer
activity, never overcount it.
[aria2 peer sampling, report ring and promotion design](telemetry-internals.md)
covers why aria2 behaves this way and what the server does about the gap.

## Update, roll back, and verify the rollout view

`splunk-iris-rollout.xml` ships as a file in the repository, but the view a
Splunk instance runs is a saved object you update in place, not a file you
re-import. Follow this order when you change it on a live instance.

1. Save the view's current `eai:data` and ACL to private rollback files
   before you change anything.
2. Compare the panels and filters you are about to push against what is
   already saved, and carry over any local additions an operator made.
3. Re-read the view definition immediately before you write, so a
   concurrent edit does not get silently overwritten.
4. POST only `eai:data`, URL-encoded, to the view's own edit endpoint. Use
   the edit endpoint, not the endpoint
   [Import the Splunk and Grafana dashboards](../zensical/user-guide/dashboards.md)
   uses to create a new view, and keep the existing name, app, owner and
   sharing. See Splunk's [view endpoint reference](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/knowledge-endpoints/knowledge-endpoint-descriptions).
5. Read back the XML and ACL, then open the saved view. Run its searches
   under five conditions: all devices, a single receiving device, a
   receiving device with no captures, a short window, and an absolute
   historical window. Compare the table's exact bytes and completeness
   against what those searches return directly.
6. Treat a missing capture as unavailable, not as zero. A captured
   origin-only transfer produces a real, measured zero peer share.
7. If the updated view breaks, restore the saved XML to the same endpoint
   and verify the restored view the same way you verified the update.

## Related

- [Import the Splunk and Grafana dashboards](../zensical/user-guide/dashboards.md)
- [Monitor transfers and reports](../zensical/user-guide/monitoring.md)
- [Telemetry signals](../zensical/reference/telemetry-signals.md)
- [aria2 peer sampling, report ring and promotion design](telemetry-internals.md)
