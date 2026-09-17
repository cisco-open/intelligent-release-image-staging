<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Live API coverage and capacity checks

`tools/api-exercise.py` exercises the public Console API on an isolated lab
deployment. It discovers registered routes, checks authentication/CSRF guards,
and reports successful operations separately. A 401/403/404 is **not** proof
that an operation's happy path works; fixture-dependent routes may remain
untested positively.

Start with the read-only run. Mutation mode is for an isolated lab only: it
requires an empty inventory and available policy outbox, creates synthetic
devices using benchmark-only addresses, exercises selected fixtures, and
retires only run-owned devices. No onboarding or image installation is run.
The harness attempts to remove its schedule, role, and credential fixtures;
device-retirement/audit history remains, so mutation mode is not zero-footprint.

Read-only example (keep password files private; do not put a password in command arguments):

```sh
python3 tools/api-exercise.py \
  --base https://iris-lab.example:8082 \
  --cafile /path/to/lab/console-ca.pem \
  --password-file /path/to/lab/admin-password \
  --concurrency 1,4,8,16 \
  --request-rate 16 \
  --seconds 2 --max-requests 400 \
  --output /path/to/lab/api-read-check.json
```

For a separate disposable-lab fixture run, add `--mutate --devices 500` and
use a distinct output path. The normal cleanup removes the run's paused
schedule, role, and credential fixtures and retires its devices; audit history
remains. If interrupted, inspect and reconcile all run-owned fixtures manually.

Replace the example hostname and paths with your isolated lab's values. The
example paces below the historical lab budget below. Use `--request-rate 0` only
when deliberately probing admission or benchmarking an isolated uncapped lab.

Omit `--mutate` for guard/GET coverage and read-load testing without creating
devices. TLS/hostname verification is mandatory. The harness uses one
authenticated session, persistent HTTPS connections per worker, an 8 MiB
response bound, and a five-second socket timeout. It does not measure login
capacity. Concurrency is capped at 32, device count at 2,000, and each
`--seconds` interval applies per endpoint/concurrency phase. There is no
unbounded stress mode.

The generated single-host default browser identity persists encrypted in
`tls/console-fallback.pem.age` and is reused on restart. Upgrading from the
older ephemeral default changes it once: verify its public certificate through
a trusted provisioning channel before updating the client's CA file. Use a
matching operator certificate when changing the browser address. Never disable
TLS verification. Split Docker and Kubernetes use mounted default browser
identities that persist independently of server restarts.

Use `--request-rate N` to pace aggregate request starts across all workers at
at most N requests/second. This applies to coverage and cleanup too. It does
not retry failures or hide HTTP 429 responses. Reported latency excludes time
waiting for the client-side pacer; throughput includes that time.

The report contains per-phase request rates, status counts, and p50/p95/p99
latency. HTTP 207 is counted separately as a partial/degraded result, not a
fully successful response. Per-minute figures are arithmetic equivalents, not
sustained measurements. Create phases operate on a growing fleet and delete
phases on a shrinking one; read phases report fixed fleet size.

Short localhost lab bursts do not establish a production rate limit. Measure
representative fleet sizes, real client network latency, mixed endpoint costs,
concurrent sessions, and sustained resource usage before choosing limits.
Do not generalize a fast session GET rate to inventory projections, policy
writes, uploads, or device jobs. A concurrency cap is not a request-rate limit.
Local projection profiles can identify copying or locking costs, but exclude
HTTP, authentication and representative live state; they cannot set API limits.

If a run is interrupted, its JSON `owned_device_ids` manifest is written before
creation starts. Reconcile those exact IDs against inventory and retire only
those records; never delete a whole prefix or reset the server to clean up.
Also inspect any run-named paused schedule, role, and credential fixtures.
No response bodies or authentication secrets are written to the report.

## Repeat the smoke test across layouts

Test the browser-facing Console URL in each layout: single-host Docker,
separate-host Docker, and Kubernetes. Healthy containers or pods do not prove
that authenticated requests reach the state-owning server.

For a small write check on an existing **lab** inventory, use:

```sh
python3 tools/api-exercise.py \
  --base https://iris-lab.example:8080 \
  --cafile /path/to/console-ca.pem \
  --password-file /path/to/admin-password \
  --mutate --allow-existing-inventory --devices 3 --concurrency 1 \
  --request-rate 8 --seconds 0.5 --max-requests 4 \
  --output /path/to/single-docker-api.json
```

Repeat with each layout's URL, trusted browser CA and a separate report.
Existing-inventory mode permits at most ten synthetic devices and one worker.
It checks that existing device IDs remain present; it does not lock the fleet
against concurrent operator changes. Use a quiet lab window. The same policy,
credential, assignment and paused-schedule fixtures exercise GET, POST, PUT,
PATCH and DELETE without contacting devices. No active schedules or device
jobs are created. Audit and retirement history remains after cleanup.

Require an empty `errors` list, no `remaining_owned_devices`, and successful
fixture checks. Inspect `coverage`: authentication/CSRF checks and missing
fixtures are not successful end-to-end tests. Trust changes, real-device jobs,
image uploads and external exports still need separate controlled scenarios.
These brief checks do not establish production capacity or justify rate-limit changes.

## API admission limits

The state-owning management server can enforce one shared request budget across
all Console users, sessions, and Console hosts. Configure requests/second with
`IRIS_API_RATE_TOTAL`, and optionally narrower `IRIS_API_RATE_READ` and
`IRIS_API_RATE_WRITE` budgets. Zero disables that budget. The corresponding
`IRIS_API_BURST_TOTAL`, `IRIS_API_BURST_READ`, and `IRIS_API_BURST_WRITE` settings
control token capacity (default one). Restart the server after changes.

Admission follows authentication, CSRF validation, and route matching, but
precedes request-body processing and mutation. Rejected requests return HTTP
429 with `Retry-After`; wait at least that long and add jitter before retrying.
Do not automatically retry a partially completed HTTP 207 mutation as though
it were a rejected 429. Login/setup and private tier preauthorization/certificate
requests are outside these budgets; existing authentication controls remain.
Stream starts count once, not once per event. Device-facing tracker, artifact,
and catalog traffic is outside this Console API limit.

These are per-management-process limits, not distributed quotas or a substitute
for upload-size bounds, connection limits, or network-layer protection. A shared
budget protects server capacity but does not guarantee fairness between users.

### Historical lab calibration

On 2026-09-15, the unthrottled 500-device repeat completed all creates,
readbacks, and removals without HTTP 207 responses. Its slowest clean measured
phase was serial DELETE at **21.27 requests/second**. That lab deployment used
80%, rounded down: **17 requests/second shared across reads and writes**
(1,020/minute arithmetic equivalent), with capacity for a four-request burst:

```ini
IRIS_API_RATE_TOTAL=17
IRIS_API_BURST_TOTAL=4
IRIS_API_RATE_READ=0
IRIS_API_RATE_WRITE=0
```

That deployment has since been retired; this is a calibration example, not a
statement about the configuration of another running server. Put chosen limits
in the deployment's existing Compose environment file. This is a
conservative lab setting, not a certified maximum: the short test covered fleet
CRUD and selected policy fixtures, not sustained mixed uploads or device jobs.
Other deployments default to disabled limits until configured. Retest before
raising the budget or applying the measured rate to a different host/fleet.
