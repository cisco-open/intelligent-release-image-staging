<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# tools/api-exercise.py

`tools/api-exercise.py` exercises the public Console API against a test
deployment of IRIS. It discovers the routes the server registers, checks
their authentication and CSRF guards, and reports each operation's outcome
separately from those guard checks. A 401, 403, or 404 response proves only
that a guard is in place. It is not proof that an operation's normal path
works, and some fixture-dependent routes stay untested beyond the guard
check.

Run it only against a test deployment, never one you rely on. Read-only mode
discovers routes and checks guards without creating anything, so start
there. Mutation mode requires an empty inventory and no backlog of pending
role or policy changes. It creates synthetic devices using addresses
reserved for benchmarking. It exercises fixtures such as a role (a named
group of devices that share with each other), a credential, and a paused
schedule, and retires only the devices it created. It never onboards a
device or installs a software image.

When a run finishes, the harness tries to remove the schedule, role, and
credential fixtures it made. Device-retirement and audit history remain, so
mutation mode does not leave a clean state behind.

## Run a read-only check

The `--cafile` argument must point at the certificate authority your test
deployment's Console actually presents. A single-host deployment with no
browser certificate configured reuses its default browser identity across
restarts; see
[Set up certificates and tokens](../install/certificates-and-tokens.md)
for how that identity works. Never disable TLS verification to work around
a certificate mismatch; point `--cafile` at the correct certificate
instead.

Keep password files private and never put a password in a command
argument:

```bash
python3 tools/api-exercise.py \
  --base https://iris-lab.example:8082 \
  --cafile /path/to/lab/console-ca.pem \
  --password-file /path/to/lab/admin-password \
  --concurrency 1,4,8,16 \
  --request-rate 16 \
  --seconds 2 --max-requests 400 \
  --output /path/to/lab/api-read-check.json
```

Replace the example host and paths with your test deployment's own values.

## Run a mutation check

For a separate, disposable fixture run, add `--mutate --devices 500` and use
a distinct `--output` path. Cleanup removes the run's paused schedule,
role, and credential fixtures and retires its devices; audit history
remains. If a run is interrupted, see
[Reconcile an interrupted run](#reconcile-an-interrupted-run) before you
retry it.

## Harness bounds

TLS and hostname verification are mandatory; there is no flag to turn them
off. The harness uses one authenticated session, a persistent HTTPS
connection per worker, an 8 MiB response bound, and a five-second socket
timeout. It does not measure how many logins the server can accept.
Concurrency is capped at 32 and device count at 2,000. Each `--seconds`
interval applies per endpoint and concurrency phase, and there is no
unbounded stress mode.

## Pace requests with --request-rate

Use `--request-rate N` to pace aggregate request starts across all workers
at, at most, N requests per second. This applies during coverage checks and
during cleanup too. It does not retry failed requests and does not hide
HTTP 429 responses. Reported latency excludes time a request spent waiting
for this pacer; reported throughput includes that time. Use
`--request-rate 0` only when you deliberately want to probe admission
behavior or benchmark an uncapped test deployment.

## Read the report

The report holds per-phase request rates, status counts, and p50/p95/p99
latency. It counts HTTP 207 separately, as a partial result, not as a fully
successful response. Its per-minute figures are arithmetic equivalents, not
measurements of a sustained run. A create phase runs against a growing
fleet and a delete phase against a shrinking one; a read phase reports a
fixed fleet size. The report never contains response bodies or
authentication secrets.

## What the numbers do not prove

Short bursts run from one host do not establish a production rate limit.
Before you choose limits, measure representative fleet sizes, real client
network latency, mixed endpoint costs, concurrent sessions, and sustained
resource use. Do not generalize a fast read rate to inventory projections,
policy writes, uploads, or device jobs. A concurrency cap is not a
request-rate limit. A local projection that only times copying or locking
costs, with no HTTP, authentication, or live server state, cannot set an
API limit either.

If you calibrate a request budget from your own clean run, see
[Routine maintenance tasks](../admin-guide/maintenance.md) for the
method and [Dated lab evidence](validation-records.md) for a worked
example.

## Reconcile an interrupted run

If a run is interrupted, or its cleanup step reports leftover fixtures,
keep the JSON report. Before it creates anything, the harness writes an
`owned_device_ids` manifest into that report. Reconcile exactly those
device IDs against your inventory and retire only those records; never
delete a whole prefix of devices or reset the server to clean up. Also
check for any run-named paused schedule, role, and credential fixtures the
run may have left behind, and remove only those. A partial result (HTTP
207) is not a successful cleanup; resolve the specific failed component
before you retry.

## Repeat the smoke test across every layout

Test the browser-facing Console URL in each layout you use: a single
Docker host, separate Docker hosts, and Kubernetes. Healthy containers or
pods do not prove that authenticated requests reach the server that owns
the state.

For a small write check against an existing inventory, run:

```bash
python3 tools/api-exercise.py \
  --base https://iris-lab.example:8080 \
  --cafile /path/to/console-ca.pem \
  --password-file /path/to/admin-password \
  --mutate --allow-existing-inventory --devices 3 --concurrency 1 \
  --request-rate 8 --seconds 0.5 --max-requests 4 \
  --output /path/to/single-docker-api.json
```

Repeat this with each layout's own URL, its trusted browser CA, and a
separate output path. Existing-inventory mode permits at most ten
synthetic devices and one worker. It checks that existing device IDs
remain present; it does not lock your fleet against another operator's
changes, so run it during a quiet window. The same policy, credential,
assignment, and paused-schedule fixtures exercise GET, POST, PUT, PATCH,
and DELETE without contacting devices. No active schedule or device job is
created, and audit and retirement history remain after cleanup.

Require an empty `errors` list, no `remaining_owned_devices`, and
successful fixture checks in the report. Check `coverage` separately:
authentication and CSRF checks, and a missing fixture, are not the same as
a successful end-to-end test. Trust changes, real-device jobs, image
uploads, and external exports still need their own controlled scenarios.
These checks confirm the API path works; they do not establish production
capacity or justify a rate-limit change.

## Related

- [Verify the installation](../install/verify.md)
- [Set up certificates and tokens](../install/certificates-and-tokens.md)
- [Routine maintenance tasks](../admin-guide/maintenance.md)
- [Limitations](../architecture/limitations.md)
- [Dated lab evidence](validation-records.md)
