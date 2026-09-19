<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Process and thread topology, preflight and internal rationale

This page collects the engineering reasoning behind the server that does not
belong in the user-facing guides. It covers why a timing bound sits where it
does, why a store is shaped the way it is, and what a preflight check does
today versus what it will do later. Read
[Server configuration](../zensical/reference/server-configuration.md) and
[Data formats and states](../zensical/reference/state-and-data.md)
first for what each setting and store does; this page explains why.

## Artifact-server thread model

The artifact server logs one line per GET, with the method, path, response
status, duration, and the number of requests currently in flight. During a
slow onboarding run, compare that count against the persisted deployment-log
offsets to tell a slow device apart from a busy server; see
[Troubleshoot: symptoms and first steps](../zensical/user-guide/troubleshooting.md).

Its thread model exists to stop one slow client from starving the rest. A TLS
handshake runs inside the connection's own worker rather than inside the
accept loop, so a client that stalls partway through a handshake cannot block
a new connection from being accepted. The handshake itself is bounded to 30
seconds, and the listen backlog holds 128 pending connections. Expired
staging credentials are swept on their own five-minute timer instead of on a
request path. One device's fetch never pays for another device's cleanup,
and a burst of fetches never triggers a burst of deletion work.

## The mutual-origin preflight gate

Two devices that both hold a full copy of the same image are a mutual
origin. A future rule could stop such devices from becoming peers, but that
rule is not active yet. The reconciler that shares a pass with origin quality
of service only measures the effect for now. It counts how many devices a
mutual-origin rule would newly deny if it ran, using the same self-evaluation
blocklist the tracker already applies, and it changes nothing else. The
management surface reports that count, never the device IDs or addresses
behind it. The count is unavailable, reported as null, when the protected
seeder's IPv4 address is unknown, and a count of zero means the check ran and
found no device it would newly deny.

This preflight stays open, tracked internally, until one full tagged-release dwell of observation has completed with no surprises. Only a later, separately authorized activation can turn the count into an enforced rule. That activation would apply the union of the current self-evaluation blocklist and the mutual-origin evaluation, across every ACL, including one written by hand. Nothing in the reconciler pass itself starts that dwell or grants that authorization; turning the gate on is a distinct, reviewed release. See
[Roles and peer sharing](../zensical/architecture/security-model.md#roles-and-peer-sharing)
for the rule as an operator sees it today.

## Tracker announce cadence

This is the contributor-level detail behind the bounded jitter and the QoS
ranges that
[Peer policy API](../zensical/reference/peer-policy-api.md) documents for
operators. That page covers the operator-visible half: the bounded jitter,
the 10-300 s and 4-200 s ranges, and the `qos_state` precedence chain. This
section covers how the tracker actually resolves a cadence value on each
announce.

On every authenticated announce, the tracker loads the current compiled
policy and resolves the parsed state before applying exactly one bounded
±10% jitter within 10–300 seconds. Exact `left == 0` selects seeder;
positive, omitted, malformed, and negative values select leecher. The
issued value is returned as both `interval` and `min interval`, and a peer
row expires after twice its own issued interval.

The service origin seeder selects its own parsed state using global scalar
and global state cadence, and it sits outside the handout ledger: it is not
one of the devices the ledger accounts for. An unattributed legacy
announce, one the tracker cannot tie to a specific device, uses the
selected `global-state:<state>` cadence instead. An attributed legacy
announce is resolved differently: the tracker resolves the selected state
separately for every possible owner before aggregating the results. A
shared or legacy NAT address can have several possible owners, so the
tracker considers all of them and aggregates their states to the maximum
interval and the minimum `numwant`, the slowest cadence and the smallest
peer list among the possible owners.

If attribution is unreadable, the global cadence fallback applies; the
tracker remains fail-closed and withholds candidates.

Candidate return is capped by the smaller of the request and the effective
selected-state `numwant`; `numwant=0` returns no peers. A valid,
port-bearing announce registers its issued interval; an invalid port
receives cadence without registration. Selection starts at a randomized
registry position and inspects at most the smaller of four times that
ceiling or the whole swarm, so a policy denial can make a response shorter
than its ceiling. Restricted-role selection uses role indexes but still
evaluates mutual policy for every candidate, so a role edit affects the
next requester's announce without waiting for every candidate to
reannounce.

## Why one timeout bounds IOS-XR teardown and install

`IRIS_XR_SESSION_TIMEOUT` bounds a single command session to a router, not
the whole job. The default value is comfortably above a normal, healthy
session; see [Dated lab evidence](validation-records.md) for the recorded
numbers. The same bound covers both install and teardown by design. The
install step that waits for the application to come up already runs as a
sequence of short, client-looped sessions rather than one long one. It fits
inside the shared bound without needing a separate knob of its own.

Undeploy composes at most two bounded sessions in one run: a read-only probe
and deactivate session, then a destructive session that uninstalls, removes,
sweeps, and verifies. A router that stops answering mid-session can therefore
hold a teardown job for up to twice `IRIS_XR_SESSION_TIMEOUT`, never longer,
because each session fails the job outright instead of hanging it. A
deployment with a tighter job-queue deadline can export a lower value.
Setting it to `0` disables the bound entirely, which trades a hard exit code
for an unbounded wait on a router that stops responding. See
[Recover from an interrupted job or damaged state](../zensical/admin-guide/recovery.md)
for the operator procedure this bound protects.

## Catalog-token rotation recovery

A catalog-token rotation is safe to recover from without turning a
superseded token into a general device credential. If the server commits a
rotation but the response, or the device's own atomic write of its new
token, is lost in transit, the device still holds its one previous token.
That token can ask only the token-refresh route to reissue the secret bag
that is already current. It cannot send a heartbeat or submit a report, and
its normal, assignment-bound catalog reads stop once the short overlap
window ends. Recovery still ends at the previous token's original expiry,
under the same clock-skew allowance every request gets. The retry itself is
checked under the server's own lock on the secrets store, so a revocation or
a newer, already-completed rotation always wins over a late retry.

## Why per-device state is sharded

Splitting per-device state into 256 shard files, rather than one
whole-fleet document, keeps an ordinary write cheap. A heartbeat, a policy
read, a terminal report, a tracker announce, and a credential or platform
change each lock, parse, and rewrite only the one shard their own device
lands in. None of them touches the rest of the fleet.

The inventory store carries one exception on purpose: a small counter file,
bumped once per fleet-editing call and read back alongside a fleet listing.
That lets a Console client paging through devices tell whether the fleet
changed between two reads. Whether the fleet changed at all is a
whole-store question that no single shard can answer by itself, so it gets
its own tiny file instead of a field repeated in every shard. The file stays
a few bytes regardless of fleet size, so the one thing every inventory write
still has to agree on stays cheap to check.

A Console bulk action that reassigns a credential or platform across many
selected devices at once goes through its own dedicated route rather than
one request per device, for the same reason. It groups the underlying shard
writes so a shard holding several of the selected devices is rewritten
once, not once per device in it.

## Why the lifecycle store only records two latches

The lifecycle store keeps one row per transfer plan, and it is deliberately
derived state. Plan identity lives in the policy store. This file keeps only the two
latched observations behind the decision that a device is seeding, plus the
markers that say which records already reached the export queue. Losing the file costs nothing but a little delay: the tracker
rebuilds every row from the policy store on its next pass, under the same
plan IDs. The records that follow carry the same event ID as before, so a
telemetry backend sees a duplicate of a record it already has rather than a
new one.

Both latches are first-write-wins and never reset. The checksum latch is set
once, by the earliest terminal report proving the staged file's hash
verified. The seeding latch is set once, by the tracker's own record of the
device announcing it holds the whole image. The promotion instant is the
later of the two, floored at the plan's own creation so a planned-to-seeding
duration can never come out negative. It is computed once, at promotion,
and never recomputed, which is what makes a replay after a crash produce a
byte-identical record instead of a slightly different one each time.

A row rebuilt after the store was lost promotes on only two of the three
inputs: the checksum latch and the plan's creation time. The tracker's own
prior seeding observation did not survive the loss, so a fresh announcement
after the rebuild is a new fact, not the same one recomputed. Applying the
usual formula to the rebuilt row would not reproduce the instant it actually
promoted on. See
[Telemetry signals](../zensical/reference/telemetry-signals.md) for the
records this store feeds.

## Environment variable parsing and test-only knobs

A handful of numeric settings choose different failure behavior on purpose.
`IRIS_HTTP_TIMEOUT`, `IRIS_ENDPOINT_TTL`, `IRIS_XR_SESSION_TIMEOUT`, and the
two audit variables fall back to their default on a value they cannot parse.
Every one of them except `IRIS_XR_SESSION_TIMEOUT` also falls back on zero
or a negative number, so `0` is not a way to turn off a cap on those. Only
the XR session bound treats `0` as a real, deliberate off switch.

Most of the rest are parsed as a plain integer, and a value that is not one
raises an error at startup instead of quietly falling back. For
`IRIS_ONBOARD_CONCURRENCY` and `IRIS_ENROLL_TTL` specifically, an empty
string raises the same way, which is why `server/docker-compose.yml`
restates their defaults explicitly, instead of leaving Compose to
interpolate an unset variable into an empty string and hand that empty
string to the process. Set a real value or leave the variable out, never
the empty string.

The telemetry listener's own port setting goes the other way. The process
itself treats an empty `IRIS_METRICS_PORT` as disabled. Compose separately
substitutes `9101` for an empty value before the process ever sees it, so
the two empty-string behaviors only look the same by coincidence of the
shipped Compose files.

`IRIS_CONTAINER_TESTING` and `IRIS_TEST_SKIP_MOUNT_CHECK` exist only for the
test harness and must never be set on a real device. The common entrypoint
accepts a temporary path override only once the first of the two is set, and
the IOS-XR mount check is skipped only once both are set. That mount check
exists to stop a container from staging an image into its own disposable
root filesystem. A production IOS-XR appmgr container refuses to start
unless `/hostmount` is a real bind mount, so an image staged there survives
a container restart instead of vanishing with it.

## Generated outputs

These directories are build output, not checked-in source, and none of them
belong in a commit.

| Output | Source |
| --- | --- |
| `site/` | Zensical build output. Not committed. |
| `deploy/` | GitHub Pages assembly directory. Not committed. |
| `fleet/dist/` | Generated device installers. Not committed. |
| `artifacts/` | Served runtime artifacts. Not committed except `.gitkeep`. |
| `release/` | Release packaging output. Not committed. |

## Related

- [Developer documentation index](README.md)
- [Writing and building the docs](documentation.md)
- [Dated lab evidence](validation-records.md)
- [Roles and peer sharing](../zensical/architecture/security-model.md#roles-and-peer-sharing)
- [Peer policy API](../zensical/reference/peer-policy-api.md): the
  operator-visible QoS keys, ranges and precedence chain.
- [Data formats and states](../zensical/reference/state-and-data.md)
