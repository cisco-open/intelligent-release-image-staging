<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Console API

The Console's `/api/v1` HTTP API: authentication, request and error formats, the routes by area, rate limits, and the Swagger reference.

The Console serves this API on its own HTTPS listener, normally port 8080, at `<IRIS_CONSOLE_URL>`, and proxies each call to `/internal/v1` on the server's management listener at port 9443. Use `/api/v1` for your own integrations. For a worked example, see [Automate with the API](../user-guide/automation.md).

## Authentication and requests

| Rule | Detail |
| --- | --- |
| Sessions | Every route needs one, except `POST /api/v1/login` and `POST /api/v1/setup`. |
| CSRF | A write needs `X-CSRF-Token` from the session, or the server returns 403. |
| Body size | 64 KiB JSON; 2 MiB bulk credential assignment; 8 MiB CSV import; 4 GiB streamed image upload; 256 MiB offline Bulk Hash feed (the checksum Cisco publishes for an image). |
| Errors | RFC 9457 Problem Details with a `type` and `code`; match against [API error codes (problem types)](../problems.md). `detail` is redacted. The tracker returns bencoded BEP failures instead. |
| Versions | `/api/v1` (Console), `/internal/v1` (server), `/v1` (device-facing services). A major version stays published for two releases, warned first with `Deprecation`, `Sunset`, `Link` headers. |
| Retries | Send `Idempotency-Key` to retry safely; the server replays the same response for 24 hours. A restart clears this — check the catalog or deployment record first. |
| Schedule writes | Use `ETag` and `If-Match` instead — see Schedules, below. |
| Polling | The Console marks its own background `GET` requests `X-IRIS-Poll: 1`; the server does not count these as session activity. |

## Session and settings

| Route | What it does |
| --- | --- |
| `POST /api/v1/login` | `{username, password}` signs you in and returns `{username, csrf}` plus the session cookie; 401 on bad credentials, 429 while throttled. Before an administrator exists, returns a one-time setup grant for `POST /api/v1/setup`. |
| `POST /api/v1/setup` | Creates the permanent admin account from the setup grant. 409 once an admin exists. |
| `POST /api/v1/logout` | Ends the current session. |
| `GET /api/v1/session` | The current session's info, or 401. |
| `GET /api/v1/settings` | Server address, Console URL, running version, the current certificate, and telemetry and audit-export destinations. |
| `GET /api/v1/settings/setup-status` | Status behind the setup wizard and the Device packages view: `admin`, `telemetry`, `packages`, `image_verification`. |
| `POST /api/v1/settings/password` | Changes the admin password and signs out every other session. |
| `POST /api/v1/settings/sessions/revoke-others` | Signs out every session except yours. |
| `GET`, `POST /api/v1/settings/peer-tls` | Reads or sets whether peer transfers require TLS. |
| `POST`, `DELETE /api/v1/settings/gui-cert` | Sets or removes the Console's certificate override. |
| `POST`, `DELETE /api/v1/settings/trust/<name>` | Adds or removes one trusted CA certificate. |
| `POST /api/v1/settings/ca-trust`, `.../ca-trust/refresh` | Configures, and runs, the public CA bundle download. |
| `POST`, `DELETE /api/v1/settings/telemetry-destination` | Overrides, or clears, where telemetry is sent. |
| `POST`, `DELETE /api/v1/settings/audit-export` | Configures, or clears, the audit-export destination and password. |
| `POST /api/v1/settings/audit-export/run` | Starts one export job; read its state at `GET .../run/<id>`. |

Every response carries `Cache-Control: private, no-store`. If the encrypted secrets store cannot be read, every route backed by it returns 503. See [Routine maintenance tasks](../admin-guide/maintenance.md) for the procedures.

## Images

| Route | What it does |
| --- | --- |
| `GET /api/v1/images` | `{images: [...]}`: the catalog entries. |
| `GET /api/v1/images/importable` | Image files on disk not yet in the catalog. |
| `PUT /api/v1/images/upload/<filename>` | Streams an upload and starts a publish job; returns `{job_id}`. |
| `POST /api/v1/images/import` | Publishes a file already on disk; body `{"path": "<candidate path>"}`. |
| `GET /api/v1/images/jobs/<job_id>` | Publish job state: `publishing`, `verifying`, then `done` or `error`. Check `verification.outcome` and `verification.image_state`, not the top-level state alone. |
| `DELETE /api/v1/images/<image_id>` | `{deleted: true}`, or 409 while a device still has the image approved. |

Each catalog entry also carries `quarantined` and a `hash_verification` result. See [Publish and verify images](../user-guide/images.md).

## Image verification

| Route | What it does |
| --- | --- |
| `GET /api/v1/settings/image-verification` | `{mode, hour_utc, last_run}`: the Bulk Hash schedule. |
| `POST /api/v1/settings/image-verification` | Replaces the schedule; `mode` is `off`, `daily`, or `weekly` (weekly runs Monday UTC). |
| `POST /api/v1/image-verification/refresh` | Runs the check now; `{outcome, matched, mismatched, not_in_feed}`. |
| `POST /api/v1/image-verification/offline` | The same check against an uploaded `.tar` feed, for a server with no internet access. |
| `POST /api/v1/images/<id>/release-quarantine` | Lifts a quarantine, after a recheck or an explicit override. |

See [Security model and trust boundaries](../architecture/security-model.md) for how the Bulk Hash check works.

## Devices

| Route | What it does |
| --- | --- |
| `GET /api/v1/devices` | `{devices: [...], now, total, offset, limit, revision}`: a paged, filtered view of the inventory. See the filters below. |
| `POST /api/v1/devices` | Creates or updates one inventory row; returns `{device: ...}`. Unknown or server-owned fields return 422. |
| `DELETE /api/v1/devices/<id>` | Retires the device: revokes its credentials, then clears its policy and row. Returns 207 with a `degraded` list on partial failure. |
| `GET /api/v1/devices/export-csv`, `.../example-csv` | The inventory as `devices.csv`, and a blank example. |
| `POST /api/v1/devices/import-csv` | Bulk inventory import (8 MiB cap, all or nothing). |
| `GET /api/v1/install-options?model=<model>` | The onboarding options a model supports. |
| `GET /api/v1/devices/<id>/plan` | The resolved deployment plan for one device. |
| `GET /api/v1/devices/<id>/reports` | The device's stored telemetry history. |
| `GET /api/v1/devices/<id>/deployment` | The deployment record for the device. |
| `POST /api/v1/devices/<id>/assign` | Sets the device's approved image set, up to ten images. |
| `POST /api/v1/devices/<id>/credential`, `.../platform` | Sets the credential profile, or the agent platform and storage target. |
| `POST /api/v1/devices/bulk-credential` | Sets one credential profile on many devices in one call. |
| `POST /api/v1/devices/<id>/forget-host-key` | Clears a device's saved SSH host key after a re-image or replacement. |
| `POST /api/v1/devices/<id>/request-report` | Asks the device for a fresh telemetry report. |
| `POST /api/v1/devices/<id>/adopt` | Adopts a pre-existing deployment; routers cannot be adopted. |
| `POST /api/v1/devices/<id>/onboard`, `.../undeploy` | Starts the onboarding or undeploy job. See Onboarding jobs, below. Both accept an optional `log` flag. Undeploy with no deployment record returns 409 unless you send `force`, which removes only the IRIS-installed agent. |

Filters on `GET /api/v1/devices` combine:

| Filter | Values |
| --- | --- |
| `q` | A case-insensitive match on device id, IP, or model. |
| `management_type` | `routed`, `inband`, `router-routed`, `router-nat`, `xr-host`, or `legacy`. |
| `platform`, `cred`, `role` | The agent platform, credential profile, or declared role; `__none` selects an unset value. |
| `telemetry`, `peer` | `on`/`off`/`unknown`, or `quarantined`/`not-quarantined`. |
| `status` | A deployment status such as `deployed`, `staging`, or `onboard-failed`; `__attention` selects anything that needs notice. |

See [Work with many devices at once](../user-guide/devices.md) for the procedures.

## Onboarding jobs

| Route | What it does |
| --- | --- |
| `GET /api/v1/onboard/jobs` | `{jobs: [...], max_concurrent, now}`. |
| `GET /api/v1/onboard/jobs/<id>` | One job, or 404. |
| `GET /api/v1/onboard/jobs/<id>/stream` | Server-sent log lines, ending with a named `end` event. |
| `POST /api/v1/onboard/jobs/<id>/abort` | Stops the job. |
| `POST /api/v1/onboard/cancel-queued` | Drops jobs still queued. |

A job's state is `queued`, `running`, `done`, `error`, or `cancelled`. `done` means the installer or undeployer finished — check the device's own heartbeat status for the image download and check. The `end` stream event carries `done`, `error`, `cancelled`, `idle` (timed out), or `unknown` (job no longer available); read the job's own state before treating a closed stream as a failure.

For a router, preflight runs once, before the job mints its enrollment token, so submitting many routers returns one job id per device right away. See [Security model and trust boundaries](../architecture/security-model.md) for what preflight checks, and [Helper commands](tools.md) for recovery operations with no route of their own.

## Credentials

| Route | What it does |
| --- | --- |
| `GET /api/v1/credentials` | `{profiles: [...]}`: id, name, and device username, never the password. |
| `POST /api/v1/credentials` | Creates or updates a profile; returns `{profile}`, redacted the same way. |
| `DELETE /api/v1/credentials/<id>` | `{deleted: <bool>}`. |

See [Rotate credentials and certificates](../admin-guide/rotations.md).

## Schedules

Every schedule write sends the schedule's strong `ETag` in `If-Match`, or the server refuses it. Occurrence and outcome history stays readable after a definition is deleted.

| Route | Body / result |
| --- | --- |
| `GET /api/v1/schedules` | `{schedules: [...], total}`. Each entry adds `etag`, `creator_exists`, `next_fire`. |
| `POST /api/v1/schedules` | Creates one schedule from `{id, kind, target, payload, when, after?, state?}`; 201 with `Location` and `ETag`. `kind` is `assign` or `onboard`. |
| `GET /api/v1/schedules/{id}` | `{schedule}` with its `ETag`. |
| `PUT /api/v1/schedules/{id}` | Replaces the whole definition. Requires `If-Match`. |
| `PATCH /api/v1/schedules/{id}` | Changes named fields only; `{"after": null}` removes a wave gate. Requires `If-Match`. |
| `DELETE /api/v1/schedules/{id}` | 204. Requires `If-Match`. Occurrences and outcomes are kept. |
| `POST /api/v1/schedules/{id}/reaffirm` | Empty body. Rewrites `created_by` to you, for a schedule whose creator no longer exists. Requires `If-Match`. |
| `GET /api/v1/schedules/{id}/occurrences` | `{occurrences: [...], total, offset, truncated}`, oldest first, `limit` at most 100. |
| `GET /api/v1/schedules/{id}/receipts` | `{receipts: [...], total, offset, truncated}` — the durable per-device outcome for every occurrence, `limit` ≤ 1000. `fleet_registration_id` identifies the bound registration when present. |

A receipt reason of `conflict` can mean the current same-name fleet row has a different registration than the occurrence binding. `identity_unavailable` means fresh work could not prove a durable target identity. Follow [Schedule maintenance windows](../user-guide/scheduling.md#scheduled-outcomes).

`next_fire` is the schedule's current or next slot, computed by the server: `{scheduled_at, window_end, status, resolution, tz, local_time, next_at}`. It is `null` for a paused, completed, or one-time-with-no-further-slot schedule. `resolution` is `normal`, `gap`, or `fold`; see [Schedule maintenance windows](../user-guide/scheduling.md#scheduling).

## Monitoring

| Route | What it does |
| --- | --- |
| `GET /api/v1/overview` | The dashboard rollup: image, device, and rollout state. |
| `GET /api/v1/swarm` | The live swarm view. Optional `limit`/`offset` page the peers. |
| `GET /api/v1/audit` | `{events: [...]}`; filter with `category`, `limit` (max 500), `before_ts`, `after_ts`. |
| `GET /api/v1/audit/histogram` | Per-bucket audit event counts, for the activity strip. |
| `GET /api/v1/deploy-logs` | Metadata for persisted per-job deployment logs, newest first; filter by `device_id`, `after_ts`, `before_ts`. |
| `GET /api/v1/deploy-logs/histogram` | Evenly spaced counts of finished jobs, for the time-range histogram. |
| `GET /api/v1/deploy-logs/<file>` | One persisted log as plain text. |
| `GET /api/v1/help` | Version, deployment id, and documentation links for the Console's help popover. |
| `POST /api/v1/telemetry/stream` | `{"every": <1-60>, "pause": <bool>}`: sets telemetry cadence fleet-wide. |
| `GET /api/v1/telemetry/health` | The telemetry hub's own health. |
| `GET /swarmmap` | The swarm map page, behind the same session as the API. |

See [Monitor transfers and device reports](../user-guide/monitoring.md) for the procedures.

## API admission limits

Set a shared request budget with `IRIS_API_RATE_TOTAL`, and optionally narrower `IRIS_API_RATE_READ` and `IRIS_API_RATE_WRITE` budgets, plus the `IRIS_API_BURST_*` settings; see [Server configuration](server-configuration.md) for the full variable table. Login, setup, and the Console's own internal calls are outside this budget.

A rejected request returns 429 with `Retry-After`; wait at least that long, with jitter, before retrying. A 207 means part of a bulk request succeeded — it is not the same as a 429. See [Automate with the API](../user-guide/automation.md) for both cases worked through. The budget is per server process; see [Limitations](../architecture/limitations.md).

## Browse the API reference

Open **Help → Local API reference (Swagger)** in the Console to browse the same routes, generated from the running server's contract. The documentation site publishes the same read-only view. There is no **Try it out** button or authorization field — send real requests through the Console or your own client. A header switch shows Console routes alone or every service, including the device-facing catalog and tracker APIs.

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| `/swagger/` or `/openapi.yaml` returns 404 | Wrong listener, or the Console image is out of date. | Use the browser-facing Console port, normally 8080, not the management port. Rebuild or pull the current Console image. |
| Swagger loads without styles or scripts | A reverse proxy dropped part of the `/swagger/` path. | Preserve the full `/swagger/` prefix through any proxy. |
| Swagger shows no **Try it out** or authorization control | Expected. | Use the Console or an authenticated API client to send requests. |
| The browser reports a certificate error for Swagger | Swagger uses the Console's own certificate. | Fix the Console certificate's trust or hostname. |
