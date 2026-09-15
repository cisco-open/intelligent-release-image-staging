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
  --base https://100.90.168.20:8082 \
  --cafile /opt/iris/deployment-20/console-ca.pem \
  --password-file /opt/iris/deployment-20/admin-password \
  --concurrency 1,4,8,16 \
  --request-rate 16 \
  --seconds 2 --max-requests 400 \
  --output /opt/iris/deployment-20/api-read-check.json
```

For a separate disposable-lab fixture run, add `--mutate --devices 500` and
use a distinct output path. The normal cleanup removes the run's paused
schedule, role, and credential fixtures and retires its devices; audit history
remains. If interrupted, inspect and reconcile all run-owned fixtures manually.

The example paces below .20's configured limit. Use `--request-rate 0` only
when deliberately probing admission or benchmarking an isolated uncapped lab.

Omit `--mutate` for guard/GET coverage and read-load testing without creating
devices. TLS/hostname verification is mandatory. The harness uses one
authenticated session, persistent HTTPS connections per worker, an 8 MiB
response bound, and a five-second socket timeout. It does not measure login
capacity. Concurrency is capped at 32, device count at 2,000, and each
`--seconds` interval applies per endpoint/concurrency phase. There is no
unbounded stress mode.

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

If a run is interrupted, its JSON `owned_device_ids` manifest is written before
creation starts. Reconcile those exact IDs against inventory and retire only
those records; never delete a whole prefix or reset the server to clean up.
Also inspect any run-named paused schedule, role, and credential fixtures.
No response bodies or authentication secrets are written to the report.

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

### Current .20 lab setting

On 2026-09-15, the unthrottled 500-device repeat completed all creates,
readbacks, and removals without HTTP 207 responses. Its slowest clean measured
phase was serial DELETE at **21.27 requests/second**. The .20 deployment uses
80%, rounded down: **17 requests/second shared across reads and writes**
(1,020/minute arithmetic equivalent), with capacity for a four-request burst:

```ini
IRIS_API_RATE_TOTAL=17
IRIS_API_BURST_TOTAL=4
IRIS_API_RATE_READ=0
IRIS_API_RATE_WRITE=0
```

Put these in the deployment's existing Compose environment file. This is a
conservative lab setting, not a certified maximum: the short test covered fleet
CRUD and selected policy fixtures, not sustained mixed uploads or device jobs.
Other deployments default to disabled limits until configured. Retest before
raising the budget or applying the measured rate to a different host/fleet.
