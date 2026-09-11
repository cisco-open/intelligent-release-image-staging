<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Troubleshooting

Start with the [recovery checklist](operations.md#recovery-checklist). Confirm
service health, network direction, the recorded artifact, and durable job or
schedule evidence before retrying. Do not repair state by editing databases,
deployment JSON, occurrences, or receipts by hand.

| Symptom | Action |
| --- | --- |
| Console or device service is unavailable | Follow the [recovery checklist](operations.md#recovery-checklist), then verify the exact direction and listener in [Network ports and flows](network-ports.md). |
| A scheduled receipt says `conflict` | Compare occurrence `target_snapshot.registration_ids`, receipt `fleet_registration_id`, and the current fleet registration. Manual changes and replacement registrations win; verify the intended current device and schedule new work. |
| A scheduled receipt says `identity_unavailable` | Fresh work could not prove the claimed target's durable identity. Recover prepared work only when its receipt records `fleet_registration_id`; otherwise verify the current registration and schedule new work. |
| A device name was deleted and added again | Treat the new row as a replacement identity. Do not redirect or replay an old occurrence against it. |
| IOS-XR leaves a root image after undeploy or parking | Undeploy intentionally leaves root images. Parking deletes only when every historical record naming the same file proves downloaded ownership; any adopted or unknown claim protects it. See [Unassigned image park](device-agents.md#unassigned-image-park). |
| Imported Splunk panels are empty but pasted SPL returns rows | Inspect the resolved browser job. `search search index=...` identifies an extra generating `search` prefix in standalone Simple XML. Re-import the corrected shipped view. |
| **Received data by source** is below captured bytes | Keep `iris.transfer.bytes_unattributed_omitted` in a separate **Untraced capped rows** bucket. Do not redistribute capped bytes among origin, peer-device, or unknown rows. |
| Peer share says **No data** | No capture exists in the selected bounds, so the ratio is unavailable. |
| Peer share says **0%** | Captures exist but contain no measured peer bytes; origin-only and unknown-only captures are measured zero. If `capture_complete=false`, totals are a floor and the partial ratio has unknown bias. |
| A cumulative ledger tile changes with the time picker | It shows the latest sample inside the selected window, not a delta. A window with no sample is unavailable; **Seeder RPC** uses a fixed 15-minute window. |
| An API request returns Problem Details | Match `type` or `code` in the [Problem type registry](problems.md). Schedule receipt reasons are durable outcomes, not HTTP problem types. |
| Swagger's model view warns about `jsonSchemaDialect` | IRIS explicitly declares generic JSON Schema draft 2020-12. Use the page's canonical explorer or [raw OpenAPI 3.2 contract](openapi.yaml) for exact schemas, including conditional constraints. |

## Preserve evidence before retrying

Record the affected device id, registration identity, image id, occurrence id,
receipt revision, job id, and selected dashboard time bounds as applicable. Keep
the original outcome and job log. A retry cannot explain what the first attempt
observed if those identifiers or bounds are lost.

For a scheduled device, distinguish the inventory name from its durable
registration identity. Deleting and re-adding the same name does not restore the
old identity. See [Scheduled outcomes](operations.md#scheduled-outcomes).

For telemetry, keep capture time and completeness with byte totals. Exact bytes
in retained rows do not make a capped capture complete, and absence of captures
is not a measured zero. See [Telemetry export known limits](telemetry-export.md#known-limits)
and [Splunk troubleshooting](splunk.md#troubleshooting).

## Escalate with the canonical record

Use the [browsable API reference](swagger/index.html) to find an operation and the raw
contract link for canonical request, response, SSE, and binary definitions.
Swagger is documentation only and does not accept credentials or send requests.
The running Console and management server do not expose a Swagger route.
