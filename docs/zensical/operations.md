<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Operations

This page collects the actions operators perform after the first deployment.

## Daily commands

| Task | Command |
| --- | --- |
| Start server and Console | `docker compose -f server/docker-compose.yml up -d --build` |
| View server logs | `docker logs iris` |
| View Console logs | `docker logs iris-console` |
| Publish image | `docker compose -f server/docker-compose.yml exec iris iris-publish /opt/images/<path>/<image>.bin` |
| Show images and assignments | `docker compose -f server/docker-compose.yml exec iris iris-assign` |
| Apply assignments | `tools/apply-assignments.sh fleet/assignments.csv` |
| Create or reset admin | `docker compose -f server/docker-compose.yml exec iris iris-gui-admin admin` — a reset also ends every live console session ([Console sessions](security.md#console-sessions)) |

`apply-assignments.sh` and `gen-device-installers.sh`
([Prepare devices](getting-started.md#prepare-devices)) require the running
`iris` container by that name; set `IRIS_CONTAINER=<name>` if yours differs.

The Console is a separate service. It reaches the server through the internal
HTTPS management API on TCP 9443; it does not mount the server's state or image
storage. For [separate Docker hosts](docker-hosts.md), use
`server/docker-compose.server.yml` on the server and
`server/docker-compose.console.yml` on the Console host, with that host's
`--env-file`. For Kubernetes, use the corresponding deployments:

```bash
kubectl -n iris exec deployment/iris-seed-server -c iris -- iris-assign
kubectl -n iris logs deployment/iris-seed-server -c iris
kubectl -n iris logs deployment/iris-console -c console
```

## Recognizing an ownership problem

Every service runs at uid 10001, so a path the server cannot reach at that uid
produces a recognizable symptom rather than a crash: the Images screen lists a
file as `not readable by the server`, a secret store that worked before fails to
decrypt, or onboarding fails while downloading the agent bundle. These are
ownership problems, not corrupt state.

The host age key and artifacts directory must be owned by uid `10001`; see
[Host paths to chown on every deploy](server.md#host-paths-to-chown-on-every-deploy).
State, configuration, and uploads volumes need the same ownership. Check
restored or manually copied files against [Volume permissions](server.md#volume-permissions).

## Unreachable devices at onboard

A Guest Shell onboard job probes the device before running the installer. An
unreachable device — wrong IP, wrong credentials, no network path — fails the
job immediately with `cannot reach device <ip> — ping/SSH probe failed; check
the device IP and credentials` instead of silently doing nothing. Router and
IOx onboarding also run a live preflight.
Submit-time rejections render in the console and are audited like any other
onboarding failure.

IRIS does not send `enable` and its secret unless the device's own prompt has
shown that the login lands at user EXEC (`>`). Sending that pair to a login
already at privileged EXEC (`#`) executes the secret as a command, which IOS may
try to resolve as a hostname and can delay every session by tens of seconds. A
device that genuinely needs enable fails its first unprivileged session loudly,
is learned from the prompt, and succeeds on retry. Set
`IRIS_DEVICE_ENABLE_ALWAYS=1` only for a known environment that must start
escalated; even then the pair is dropped for the rest of that process as soon
as a session shows a privileged prompt.

## Bulk device actions

Network-wide changes come from the Devices toolbar, which acts on every checked
row instead of one row at a time. Bulk operations report per-device refusals
rather than failing the batch, so a partial result is normal: the status line
counts the successes and names the devices that refused. The controls and their
individual effects are documented in
[Bulk device actions](console.md#bulk-device-actions).

## Onboarding at scale

`POST /api/v1/devices/<id>/onboard` resolves the plan, checks for a conflicting
deployment record, and returns a job id. Router preflight — the read-only
collision, identity, and NAT checks in
[Router preflight and ownership](management-type.md#router-preflight-and-ownership)
— runs in the onboarding worker before it mints an enrollment token or applies
any device configuration. A preflight failure fails that job and appears in
its log; other queued jobs can continue.

`IRIS_ONBOARD_CONCURRENCY` limits the number of running jobs (default 25).
`GET /api/v1/onboard/jobs` reports the limit as `max_concurrent`.

The installers group read-only pre-checks and final verification into one
device session each. State-polling loops make a fresh observation on every
iteration. Guest Shell readiness waits 2, 4, 6, and then up to 15 seconds
between observations.

## Role-policy operations and rollback

Treat a role change like a network-policy change. Read the current policy and
ETag, call the same mutation with `dry_run=1`, review
`member_delta`, `origin_access_lost`, `empty_permitted_sets`,
`role_pairs_stopped`, and `qos_changed`, then apply the unchanged request with
its `confirm_token` and the same strong `If-Match`. The zero blast-radius
threshold means every effective access, membership, or QoS change requires
confirmation. A concurrent commit invalidates both the ETag and token; read and
preview again rather than replaying either.

Create definitions before assigning members. Clear or move every member and
remove every referring peer-role before deleting a definition. A direct role
assignment is refused when a non-quarantine explicit ACL already shadows that
device. For a deliberate conversion, use `iris-role migrate ACL ROLE --dry-run`
to preview without persisting anything. A confirmed `--apply` migration first
records the role membership while the old ACL still shadows it, then a second
policy commit removes the matching ACL assignments.
If the second commit fails, the shadow remains and enforcement stays on the old
ACL; inspect `role_drift`, correct the failure, and rerun the preview.

Fleet declaration and compiled policy membership are separate durable stores.
IRIS serializes their writers and chooses an order that leaves a more permissive
residue on failure: a restriction writes the fleet declaration before policy;
a relaxation writes policy before the declaration. Bulk results report exact
`applied` and `failed` rows plus a bounded drift summary. Do not interpret a
partial response as rollback. Repair the failed store and repeat the same
idempotent membership intent.

Neither order is a distributed rollback. A policy restore changes policy
content only and does not roll back a completed Fleet write. Before repairing
or restoring policy, preserve `peer-policy.json`, Fleet state,
`peer-enforcement.json`, `origin-qos.json`, the LKG/ring, and the roles-ever
watermark. Then compare declared and compiled membership and repair the reported
drift.

For an intentional policy rollback, the internal restore primitive copies
reviewed historical content into a monotonic new revision, preserves the live
outbox, appends a restore event, and rotates its acknowledgement epoch. There is
no public restore route or CLI. Do not overwrite a healthy authoritative file
with a ring snapshot; arrange a reviewed maintenance procedure around the
primitive. Copying verified LKG bytes is reserved for repair of an already
corrupt authoritative store.

Peer quarantine is independent of a device's ordinary ACL assignment. Applying
peer quarantine preserves the current ordinary ACL; an ACL changed while
quarantine is active stays suppressed until release, when the then-current
ordinary ACL, role, or established unassigned fallback becomes effective.
Reads enforce both independent membership and legacy
`assignments[device-id] == "quarantine"` rows. The next successful policy
mutation migrates legacy rows to the independent container without adding a
second revision or outbox event. A legacy quarantine row has no surviving
ordinary ACL, so IRIS cannot recover the assignment that older behavior already
overwrote. Repeating quarantine or release at the current revision still
creates one revision and one outbox event. Pure credential revoke clears only
the ordinary ACL assignment and retains peer quarantine, Fleet and policy role
membership, and device QoS. Device retirement clears peer quarantine along with
the ordinary ACL, role membership, and device QoS. Peer quarantine controls
device peer discovery and is separate from catalog image quarantine.

Tracker policy changes discovery on the next announce and does not sever a
live connection or erase aria2's retained peer list. If isolation cannot wait
for connections to age naturally, unassign every image from the affected
device; its current agent removes the torrents on the next tick. This remains a
staging operation and never installs, activates, reloads, or changes boot state.

Before rolling the server back to an older binary, treat peer-policy containment
and compatibility as a separately reviewed change. Any restricted-role downgrade
requires this separately reviewed containment and compatibility procedure. Older
servers that predate independent quarantine ignore that membership, so
independent quarantine is not sufficient containment for a downgrade even after
the current tracker has
exported the operation. Do not convert the membership for compatibility by
overwriting the preserved ordinary ACL.

For a binary that also predates roles or state-aware QoS, use the newer binary
to remove every global and role state container, then make one additional
scalar-only policy commit. Verify that both `peer-policy.json` and
`peer-policy.lkg.json` contain state-free schema-1 documents before starting the
older binary; do not supply it a retained state-bearing ring snapshot. These
schema preparations do not make an older server enforce independent quarantine.
Code predating roles ignores `roles_present` and cannot enforce or warn about
role definitions. After restoring a role-capable, independent-quarantine-aware
version, verify the retained quarantine intent, repair any `role_drift`, verify
the policy and origin-QoS status, and deliberately release each quarantine. Do
not delete `peer-policy.json` or its LKG to silence a warning: doing so loses
role, ACL, and quarantine intent.

## Instruction-root ceremony and recovery

These procedures describe operator actions; they are not a record of a
production ceremony or release. Use the selected deployment's server shell
(`docker compose -f server/docker-compose.yml exec iris sh`, the split-host
server equivalent, or `kubectl -n iris exec -it deployment/iris-seed-server -c
iris -- sh`). Its existing `IRIS_CONFIG`, `IRIS_STATE`, `IRIS_RUN` and age
identity must stay with that deployment. Offline-root private material never
enters this shell, the server, installer arguments or device platform config.

Exactly two distinct public roots belong in `$IRIS_CONFIG/instr/roots.d/`, with
private material held by separate custodians at separate sites. The optional
encrypted online key is `$IRIS_CONFIG/instr/signing-key.age`; runtime plaintext
is `$IRIS_RUN/instr/signing-key`. Keep the [durable state inventory](server.md#instruction-state-and-processes)
with its deployment: epochs, serial history, admission/activation records,
role artifacts and keylist authority must not be restored backwards.

### Quarterly two-root ceremony

1. Have both custodians verify separate custody/sites and compare public
   fingerprints with the approved inventory (`ssh-keygen -lf root-a.pub` and
   `ssh-keygen -lf root-b.pub`, on public copies). Record identities,
   fingerprints, times and outcomes; never record private keys or bearer values.
2. In the server shell, inspect `iris-instructions --status` and export only
   the online public half to a controlled exchange directory. Create that
   directory before these commands:

   ```bash
   install -d -m 0700 "$IRIS_RUN/ceremony"
   iris-instructions --export-public "$IRIS_RUN/ceremony/signing-key.pub"
   iris-instructions --status
   ```

   On the first setup only, generate the server's online key with
   `iris-instructions --generate-online-key` before exporting it. This uses the
   configured age recipients and keeps the plaintext in the runtime directory.
3. Take the public key to one offline custodian. Issue a 30-day certificate
   for exactly the `iris-server` principal. The private-key path below exists
   only on that offline station; use its normal passphrase prompt:

   ```bash
   ssh-keygen -s /offline/root-a -I iris-online -n iris-server \
     -V +0s:+30d signing-key.pub
   ```

   Return only `signing-key-cert.pub` to the server exchange directory and
   validate/import it:

   ```bash
   iris-instructions --import-certificate "$IRIS_RUN/ceremony/signing-key-cert.pub"
   ```

   Renew at half of the 30-day lifetime; signing refuses with seven days or
   less remaining. An instruction stamp lasts at most seven days. Renewal is
   therefore a scheduled action, not something to defer to certificate expiry.
4. Re-sign the current approved KRL with a strictly increasing keylist sequence.
   Retain all intended revocations. Set `IRIS_CEREMONY_SEQ` to the next reviewed
   sequence and `IRIS_CEREMONY_ROOT_ID` to the configured public-root ID (for
   example `root-a`); neither is a secret. In the server shell:

   ```bash
   iris-instructions --keylist-request "$IRIS_RUN/ceremony/revocations.krl" \
     --keylist-seq "$IRIS_CEREMONY_SEQ" --root-id "$IRIS_CEREMONY_ROOT_ID" \
     --output "$IRIS_RUN/ceremony/keylist.payload"
   ```

   Move only that public payload offline. Sign its exact bytes there:

   ```bash
   ssh-keygen -Y sign -f /offline/root-a -n iris-keylist-v1 keylist.payload
   ```

   Return only `keylist.payload.sig`; in the server shell assemble and install
   it against the unchanged request:

   ```bash
   iris-instructions --assemble-keylist "$IRIS_RUN/ceremony/keylist.payload.sig" \
     --payload "$IRIS_RUN/ceremony/keylist.payload" \
     --output "$IRIS_RUN/ceremony/keylist.envelope"
   iris-instructions --install-keylist "$IRIS_RUN/ceremony/keylist.envelope"
   iris-instructions --status
   ```

   Repeat with the other custodian/root and the next sequence so both roots
   are independently attested. The CLI accepts no root private-key input and
   independently verifies the claimed root. An identical artifact retry can
   repair interrupted metadata publication; do not change bytes at the same
   sequence. Re-signing is due at 90 days, warning at 100, critical at 135;
   both roots must have attestations within 180 days for healthy quorum.
5. Check the Console custody panel and `iris_instruction_*` metrics against
   the recorded certificate/keylist windows. `enabled: false` is not enabled,
   null/unknown is unavailable, and degraded quorum needs custody investigation.
   Verify a current stamp and authorized device receipt separately; never
   call command success live-device validation. Preserve public ceremony
   evidence and dispose of exchange copies according to local custody policy.

### One-root loss

1. Preserve the two public-root files and existing device trust bytes. Identify
   the surviving offline custodian; do not delete the lost root's public key
   from provisioned trust merely because its private copy is unavailable.
2. Use the quarterly export/issue/import procedure with the surviving root for
   the next online certificate and keylist. No device trust change is required
   for this failover, so loss of one private root is invisible to provisioned
   devices until custody evidence ages.
3. Record quorum as degraded operationally until the replacement-root plan and
   next signed device release are complete. The automated 180-day attestation
   metric can remain healthy temporarily; it cannot detect physical key loss.
   A replacement changes trust bytes and must propagate through every package
   and affected device. Never substitute disposable proof roots.

### Both-roots-lost break glass

1. Preserve public/state evidence, declare the custody outage and retain server
   tracker/origin enforcement. Devices use usable LKG, then the documented
   stale behavior. Do not weaken signature, audience or replay verification.
2. At two separate offline sites, create two new independent roots with normal
   passphrase protection (`ssh-keygen -t ed25519 -f /offline/root-a`, and the
   corresponding root-b command at its site). Record their public fingerprints.
   Complete recovery requires a reviewed maintenance procedure that reconciles
   root configuration, existing keylist/revocation state and sequence before
   provisioning the new online certificate/keylist. The current CLI cannot
   migrate an installed keylist to two wholly new roots: certificate import
   and keylist install first verify the old keylist under the configured roots.
   Simply replacing `roots.d/` and rerunning those commands will fail. This is
   an intentional break-glass boundary: no code path claims recovery. Preserve
   existing revocations and evidence; do not delete state to bypass it. The
   remaining steps require the reviewed maintenance recovery first.
3. Build fresh Guest Shell bundles, unified OCI, both IOx tars and XR RPM with
   the new public roots and the current pinned aria2c binaries. Typical build
   entry points are `tools/make-agent-bundle.sh --instruction-roots-dir DIR`,
   `IRIS_INSTRUCTION_ROOTS_DIR=DIR tools/provision-iox-packages.sh`, and
   `tools/build-xr-package.sh --instruction-roots-dir DIR --out artifacts/`.
   Build the ARM Guest Shell variant with `--arch arm64 --aria2 PATH` too.
   Supply the canonical binaries for both architectures, inspect trust/source
   byte identity and wrapper provenance, and obtain native signatures before
   claiming signed-image trust. No staged IOS image is installed or activated.
4. Re-onboard every device with the new trust material. A disconnected device
   uses [F3 bootstrap-envelope redelivery](#f3-offline-bootstrap-envelope-redelivery)
   after the fresh agent/trust package arrives. Verify the accepted identity
   and custody state on each device; publishing packages alone is not fleet
   recovery. An intentional server authority recovery uses
   `iris-instr-key recover`, which advances the epoch; fresh activation uses
   `iris-instr-key initialize`. Do not delete local replay floors to force
   acceptance or report the fleet recovered while devices remain on old roots.

### Instruction failure and key response

Instruction-body fetch/verification failures affect the instruction step only; heartbeat/staging
continue when usable LKG or defaults can be applied. If aria2 RPC policy apply
fails, the heartbeat is still sent but staging is skipped for that tick. Repair
the RPC failure before claiming staging progress. An unreadable assignment
policy also skips staging reconciliation; heartbeat and existing aria2
transfers continue. The [failure table](device-agents.md#instruction-failures-and-recovery)
covers expiry, allow-list/deny-list asymmetry, bad audience/signature/MAC,
rollback/floor reset, missing verifier, rejected LKG, 256 KiB oversize,
pointer/body races, one-shot refresh and later-tick retries.

For a leaked instruction key on an otherwise honest device:

```bash
iris-instr-key rotate --no-overlap <device_id>
```

A committed rotation can report incomplete restamping. After fixing producer
state, run `iris-instr-key restamp <device_id>`; do not repeatedly rotate.
For retirement or compromise, use `iris-revoke <device_id>` instead. Durable
revocation wins over an agent-reported LKG and must not be avoided by rotation.

## F3 offline bootstrap-envelope redelivery

F3 transports a ciphertext bootstrap envelope for one device; it is not a
secret key, an OS image, or a bypass of signature/audience/replay checks. In the
server shell, materialize it to a controlled private destination:

```bash
iris-instruction-bootstrap <device_id> --output "$IRIS_RUN/ceremony/bootstrap.envelope"
```

The output is mode 0600 and bounded; the CLI prints no envelope or key bytes.
Transfer it through the authorized platform installer/controller. Guest Shell
installer generation (`tools/gen-device-installers.sh`) stages a short-lived
capability-bound envelope and the installer places
`iris-instructions.bootstrap`; IOx uses its owned application-data delivery;
XR snapshots `IRIS_INSTRUCTION_BOOTSTRAP_FILE` and copies the ciphertext to
`harddisk:iris-instructions.bootstrap`. Preserve exact bytes and device identity,
never place a key in activation configuration. Disconnected here means the
normal instruction body needs redelivery: fresh authenticated refresh/time and
usable verification trust are still required before the agent can accept it.
A new-root recovery first needs the new agent/trust package.

On the next ordinary tick, authenticated refresh self-heals current/prior key
availability and the agent consumes the verified envelope transactionally.
Retryable delivery/durability failures retain it; rejected evidence never
replaces working LKG. Observe accepted identity/state after the tick and follow
the failure table if the device remains pending or unavailable.

## Guest Shell fleet bundle drop

Treat a Phase 1 Guest Shell agent update as a fleet operation. Build each
required architecture with `tools/make-agent-bundle.sh --arch amd64|arm64
--aria2 PATH --instruction-roots-dir DIR --out OUTPUT`, using the canonical
binary and exactly two approved public roots. Record archive/sidecar hashes
and source provenance. The adjacent 64-hex SHA-256 sidecar is digest evidence,
not a detached signature.

Publish the bundle and sidecar together on the existing artifact server, with
coordinated installer/bootstrap evidence for both public-root files. Deliver
sidecar before archive and observe bootstrap's outcome: missing, malformed or
mismatched evidence, unsafe members or incomplete writes must refuse the new
bundle and preserve the prior runnable bundle. Never remove the prior runnable
agent to force a refused update through. Check the next tick's
`instr_protocol`, accepted identity and instruction state, including
tracker-only fallback where Guest Shell lacks `ssh-keygen -Y verify`.
Roll back by restoring the reviewed prior bundle/evidence as one set; do not
rewind replay state or substitute trust roots. This changes the agent only;
it never installs or activates the staged IOS image.

IOx recovery differs: its device-global verification controller records and
restores only an owned initial enabled state, with read-back before
activation/start; initial disabled stays disabled, unknown refuses, and a
signed wrapper causes no state change. Interruption/resume and uninstall
recovery never blindly enables operator-changed or unowned state. See
[IOx verification](iox.md#device-global-package-verification).

## Peer-policy operations and their backlog

Every policy mutation — role definitions, memberships, QoS, migration,
quarantine, and release — is committed under a single policy lock and appends a
stable entry to an **outbox** that the tracker drains. One bulk membership
change creates one revision and one outbox entry. Each commit also creates a new
acknowledgement epoch. The tracker may advance
`last_operation_exported_revision` only when the status epoch matches the
current policy history and after it appends the local audit record and accepts
the event into its queue. Each outbox row has a stable event ID, so a failed
export or history mismatch replays the same event at least once. Only entries at
or below a valid revision-and-epoch watermark are pruned on the next commit.
The tracker persists both the accepted revision and its epoch in enforcement
status.

The outbox is capped at **256** unacknowledged entries. A mutation that observes
a full backlog in preflight is refused before its normal Fleet/policy write with
`operation_backlog_full`, so a stalled consumer blocks new operations instead
of silently discarding them. New role/QoS routes use 409; the legacy quarantine
route retains its 503 compatibility response. Either means the tracker is not
draining — check that it is running and reconciling before retrying. A direct
writer racing after a Fleet-first preflight can still fail partially; inspect
`partial`, `applied`, `failed`, revision, and `role_drift` on every error before
retrying.

Do not manually advance or clear the acknowledgement fields to suppress a
backlog. A number from another acknowledgement epoch is treated as zero and all
stable event IDs replay; changing it by hand can only obscure the state that
the tracker still needs to export. Reads, refusals, and dry runs commit no new
revision or acknowledgement epoch.

The same route separates its other refusals, and they mean different things:

| Response | Meaning |
| --- | --- |
| `409 revision_conflict` | Policy changed elsewhere; the current revision is returned so the caller can retry against it. |
| `422 policy_error` | Policy is degraded — running on the last-known-good copy. Repair the authoritative file. |
| `503 policy_fail_closed` | Policy is fail-closed; mutations are refused entirely. |
| `503 operation_backlog_full` | 256 operations are unacknowledged. The tracker is not draining. |

New role and QoS routes instead use exact strong ETags (`428
precondition_required`, `412 precondition_failed`) and return `409
operation_backlog_full`. See [Peer policy](reference.md#peer-policy).

### Tracker cadence, selection, and origin QoS

On every authenticated announce, the tracker
loads the current compiled policy and resolves the parsed state before applying
exactly one bounded ±10% jitter within 10–300 seconds. Exact `left == 0`
selects seeder; positive, omitted, malformed, and negative values select
leecher. The service origin seeder selects its parsed state with
global scalar and global state cadence and remains outside the handout ledger. An unattributed
legacy principal uses the selected `global-state:<state>` cadence. An
attributed legacy principal resolves the selected state separately for
every possible owner before aggregation. A shared legacy/NAT address therefore
considers all possible owners; each owner's selected state is aggregated with
the maximum interval and minimum `numwant`. If
attribution is unreadable, the global cadence fallback applies; the tracker
remains fail-closed and withholds candidates. The issued value is returned as both
`interval` and `min interval`; the peer row expires after twice its own issued
interval. Candidate return is capped by the smaller of the request and the
effective selected-state `numwant`; `numwant=0` returns no peers. A valid
port-bearing announce registers its issued interval; an invalid port receives
cadence without registration. Selection starts at a randomized registry
position and inspects at most the smaller of four times that ceiling or the
whole swarm, so policy denials can make a response shorter than its ceiling.
Restricted-role selection uses role indexes but still evaluates mutual policy
for every candidate. A role edit therefore affects the next requester announce
without waiting for every candidate to reannounce.

The same serialized reconciler applies origin QoS. It forces a complete apply
on first run, aria2 session change, desired-option or active-GID-set change, and
recovery after a failed pass. A global-option failure stops that pass. A
per-download failure does not skip later downloads, but the entire pass remains
degraded and is retried. `origin-qos.json` and the management view expose only
state, option/download counts, timestamp, and a closed error code. They contain
no GIDs, addresses, option values, or hashes.

The mutual-origin result beside that status is still #153 preflight evidence.
It does not change the applied blocklist. A `shared_permit_deny` NAT conflict is
counted and the shared address stays unblocked, because a global IP block would
also cut off the permitted principal.

Keep #153 open until one full release of preflight observation has completed.
Only a later reviewed activation may union the current self-evaluation set with
mutual-origin evaluation for every ACL, including hand-written ACLs. This
runbook neither starts the tagged-release dwell nor authorizes an activation
release or lab/live validation of the union.

## Endpoint writes that fail

An authenticated announce from an attributable principal records the peer's
address in the durable endpoint map under `IRIS_STATE`, aged out by
`IRIS_ENDPOINT_TTL` (seconds; a non-positive or non-numeric value falls back
to the 900 s default rather than disabling enforcement). The address recorded
for a **device** is always the announce's socket source; the BEP3 `ip=`
override is honoured only for the service seeder, whose container source is
loopback. If that durable write fails, the entry is queued in memory and
retried on the following reconcile passes rather than being dropped — the
device keeps participating in the swarm meanwhile, but the reported enforcement
status degrades until the write lands, because the derived deny set is computed
from durable state.

Rows belonging to a quarantined or revoked device are **not** aged out by the
TTL: the seeder block for a device that has stopped announcing stays in place
until the device is un-quarantined or re-onboarded (which clears its rows), not
merely until the TTL lapses.

### How the map is stored

The endpoint map stores one row per principal in `peer-endpoints.d/`, spread
over 256 shard files. An announce locks, parses, and rewrites only its own
principal's shard. Each write is atomic: a temporary file followed by a rename.

The capacity of the map is the supported fleet size **plus** headroom for
service principals, so a full fleet of devices and the `service:seeder`
principal all fit without evicting anything. The capacity bound is applied by
the reconciler's maintenance pass, not by each announce.

A corrupt or unreadable shard — unparseable JSON, a wrong schema, or a
malformed endpoint row — is treated as fail-closed rather than empty: the reconcile pass stops before deriving or applying anything, existing
blocks stay in place, and the recorded state is forced to `fail_closed`. Peer
discovery for device and service principals continues (the announce still
returns its peer list; the endpoint it could not write waits in the retry
queue), while a legacy-token announce gets no peers until the store is readable
again, because the tracker cannot tell whether its address belongs to a
quarantined device.

If a reconcile pass fails for any other reason (for example the state volume is
full when the status file is written), the loop records `degraded` with the
exception type in `last_error` where it can and retries on the next poll; it
never stops.

If even that degraded write fails — or the tracker process itself is
down — `peer-enforcement.json` simply stops changing, and its last recorded
state (possibly `enforced`) would otherwise sit there looking current
indefinitely. The console's peer-policy badge (device inventory, Peer
policy column) does not take a frozen state at face value: `GET
/api/v1/peer-policy` derives `enforcement.stale` from how long it has been
since `last_reconciled_at` (never, or more than five minutes — several
multiples of the reconciler's own 60-second maintenance deadline, to absorb
scheduling jitter without false-flagging a healthy but quiet fleet) and the
badge shows `<state> (stale)` regardless of what that state is, with the
last-reconciled time and `last_error` in its tooltip. A stale badge means
"go check the tracker process," not "policy is misconfigured."

## Retiring a device

Deleting a device revokes its credentials first. The revoke is written durably
under the secrets-store lock before anything else is touched; if that write
fails, the delete is aborted and no fleet, catalog, or policy state changes. Once
the revoke is durable, the remaining cleanup is best-effort and a partial cleanup
is reported rather than hidden.

Endpoint rows are deliberately **retained** until they age out. A revoked device
is denied through its still-fresh retained endpoint regardless of policy, so the
order of cleanup cannot accidentally re-permit it. Re-onboarding clears the
device's old endpoint rows before the fresh credential becomes usable, and aborts
without minting if that clear fails.

## Forgetting a device's SSH host key

Every SSH/scp session IRIS opens itself — device transports, the installers'
stage-host push, the XR RPM scp — verifies the peer per
[Security → Device SSH host keys](security.md#device-ssh-host-keys).
By default that is trust-on-first-use: the first session records the peer's
host key into a persistent `known_hosts` under the IRIS state volume, and
every later session must present the same one.

A device that is re-imaged or replaced presents a **new** host key, and every
session against it then fails with a changed-key error — correct behavior
(the alternative would be silently trusting a possibly-different box), but
with nothing recorded to distinguish "legitimately re-imaged" from "someone
else answering at that address" beyond the operator's own judgment, and the
persistent `known_hosts` file lives inside the state volume, which the
operator does not always have shell access to reach directly.

**Console:** open the device's deployment details drawer and use **Forget
host key**. This is a trust decision, so it asks for confirmation, and it is
audited (`device_forget_host_key`, naming the device and the console user)
either way. See [Reference → Devices](reference.md#devices) for the
underlying route.

**From a shell with access to the state volume:** the hint
`iris_ssh_explain` already prints on a changed-key failure works directly —
`ssh-keygen -R '<device_ip>' -f '<state>/ssh/known_hosts'`.

Either path only clears the stale entry; it does not disable verification.
The very next session re-verifies and pins whatever key the device now
presents, the same trust-on-first-use flow a brand-new device gets. Neither
path touches `IRIS_SSH_HOST_KEY` (a per-device pin) or an operator-supplied
`IRIS_SSH_KNOWN_HOSTS` file — clearing either of those, if set, is the
operator's own decision.

## Backups

Back up the server's `iris-state`, `iris-config`, and `iris-images` volumes,
the host age identity named by `IRIS_AGE_KEY_FILE_HOST`, and image files under
the read-only import root. Keep the matching state, configuration, and age
identity together: a certificate alone cannot restore device credentials,
assignments, or deployment records.

For one-host Compose, preserve the `iris-tier-auth` and `iris-management-ca`
volumes when restoring the Console-to-server identity. With separate Docker
hosts, back up each host's local credential and TLS directories instead; keep
the management private key on the server host and the default browser private
key on the Console host. Treat the tier credential backup as a secret.
Generated device packages and their adjacent
manifests live in the host artifacts directory; retain them if you need to
redeploy the same build.

For Kubernetes, snapshot the `iris-data` PVC and back up the separately managed
age identity, tier-auth Secret, and management TLS Secrets. The Console has no
state PVC; its persistent application state is on the server.

## Audit export

The console can ship the audit trail (`audit.jsonl`) off the box: *Settings →
Audit export* takes an SCP destination (host, port, user, remote path), an
age recipient, and the SCP password. Every export encrypts the trail to that
recipient before it leaves the server — encryption is mandatory, there is no
plaintext export path, and a missing recipient refuses the run rather than
degrading. The password lives in the age-encrypted secrets store, never in
the settings file, and reaches `scp` through the environment, never argv or a
log line.

Exports run on demand (**Export now**) or on the daily schedule (**Export
daily**): the scheduler makes its first pass shortly after server start and
then at most one attempt per day — failed attempts count, so a broken
destination retries daily rather than hourly. Each upload is a fresh
timestamped file (`audit-<utc>-<suffix>.jsonl.age`), so two exports never
overwrite each other at the destination. The sub-page's status line shows the
destination, the schedule mode, and the last run — timestamp plus `ok` with
the uploaded filename or `fail` with the reason — and every run is also
recorded in the audit trail itself as `audit_export`.

The destination's SSH host key is pinned trust-on-first-use: the first export
records it in a known-hosts file under the server state directory
(`audit-export-known-hosts`), and later exports fail if the destination's key
changes. Verify the fingerprint out of band where the destination warrants
it, and remove that file after an intentional host rebuild.

Audit events are append-only. Use the structured action and device fields for
saved searches rather than matching detail text.

## Image verification

*Settings → Image verification* checks the catalog's images against Cisco's
published Bulk Hash feed and quarantines a sha512 mismatch — see [Cisco Bulk
Hash verification](security.md#cisco-bulk-hash-verification) for what the
check does and what a quarantine changes. A locally-rebuilt image that
reuses a Cisco filename mismatches and quarantines on its next verification
run; the check has no way to distinguish that from tampering, which is the
point.

Every Console upload or **Import from disk** publish starts a reconciliation
immediately, independent of the schedule. Its job progresses from `publishing`
to `verifying`, then reports the new image's verdict. Concurrent imports share
a successful refresh when its catalog snapshot covers their images. An image
registered after that snapshot takes a fresh pass, and a failed refresh is
never reused as success. A feed failure is
reported as verification incomplete without falsely claiming the durable
publish failed.

The schedule has three modes: **off** (the default), **daily**, and
**weekly** — both timed modes fire at a configured `hour_utc` (0-23), and
weekly always anchors to Monday UTC; there is no day-of-week setting. A slot
the server was down for is skipped, not made up: the next scheduled slot
runs normally, and nothing catches up for the one that was missed. **Refresh
now** in the same pane runs the check immediately; if a run is already in
progress, the button and the API both answer "already in progress" rather
than starting a second one.

Air-gapped servers can upload the feed tar directly instead of the server
fetching it: the same pane's offline upload takes a raw `.tar` (256 MiB cap)
and runs it through the identical signature-verification-then-parse
pipeline, recorded as `source=offline`. A scheduled run is
`source=scheduled`; **Refresh now** is `source=manual`.

The pane's status line shows the last run's time, source, outcome, and
matched/mismatched/not_in_feed counts. Every run is audited as
`bulkhash-refresh` — scheduled runs record `actor=system`, a manual refresh
or offline upload records the console operator who triggered it; a schedule
change is audited separately as `bulkhash-schedule-config`, and an offline
upload additionally as `bulkhash-offline-upload`.

### Releasing a quarantine

An image quarantined by a sha512 mismatch cannot be newly assigned to a
device — an assignment attempt is refused with the verdict that blocked it.
From the image's detail view, **Release** re-runs the sha512 comparison
against the stored feed verdict: if the catalog's own sha512 now agrees
(the file was replaced with a corrected copy), the quarantine lifts and the
verdict updates to verified. If it still disagrees, the release is refused
unless the operator types the image's own filename to confirm an override,
recorded as a distinct `release_override` audit action rather than a plain
release. An override does not change the recorded verdict back to verified —
it only permits assignment despite the mismatch — and re-running the check
later and getting that same mismatch again does not re-quarantine an
overridden image; a genuinely different mismatch does.

Either kind of release also puts the image back into the origin seeder: the
quarantine had force-removed its torrent from aria2, and a released image with
no origin would otherwise leave every device assigned it waiting at 0% until the
next container restart. The re-add happens from the image's recorded
`source_dir`, after re-syncing the canonical torrent's announce to the current
seeder credential (a quarantine can outlive an announce rotation, which skips
quarantined images); the `info` byte span, and so the info hash, is unchanged.
The response carries `seeding_resumed`, and a re-add that fails — aria2
unreachable, or a `source_dir` that no longer exists (IRIS never guesses a
directory by basename) — is audited as
`image_quarantine_release_seeding` with `result=fail` while the release itself
stays in force. A container restart re-seeds every catalogued, non-quarantined
torrent, so it repairs that case too.

## Scaling notes

Private BitTorrent reduces server load by letting devices exchange pieces after the seeder introduces the content. The server remains important for tracker announces, catalog policy, initial seeding, and telemetry. Watch the seeder data port, tracker health, and device storage pressure during large network waves.

On Catalyst 9300 IOx devices the final agent-to-IOS transfer uses the bind-mounted SSD share and runs at disk speed; Catalyst 9300 Guest Shell writes through the guest-share; Catalyst 8000 routers stage over Guest Shell to `bootflash:`. On IE-3400 (or a Catalyst 9300 that fell back to the scp push) that transfer is capped by the platform's default control-plane policing at roughly 1.4 MB/s; IRIS never modifies CoPP.

### How many torrents are served at once

A seeding torrent holds an aria2 concurrency slot indefinitely. The origin's
`SEED_MAX_CONCURRENT` defaults to 1000; device verified/default
`max_concurrent` defaults to 100. Configure device concurrency through signed
QoS intent, not launcher variables. Legacy `IRIS_MAX_CONCURRENT` and
`IRIS_MAX_PEERS` are provisional until the first successful tick, with restored
downloads held until verified/default options are written. Parsed legacy
`max_peers` is ignored and produces the value-free `MAX-PEERS-IGNORED` notice
once. `IRIS_TICK_SECONDS` controls the mechanical interval/floor; signed
`catalog_tick_s` controls logical catalog/staging cadence. Every mechanical
tick reasserts QoS and sends a heartbeat; all future `addTorrent` calls use
verified/default policy. A low concurrency cap can leave assigned images
waiting even when bandwidth remains available.

`iris_seeder_queued_torrents` is the signal to watch. Any non-zero value means the origin is holding back a published image; alert on it.

## Cleanup

Use `device/device-uninstall.sh` (Guest Shell devices),
`device/router-uninstall.sh` (Catalyst 8000 IOS-XE routers),
`device/iox/uninstall.sh` (IOx), or `device/xr-uninstall.sh` (IOS-XR appmgr).
Cleanup removes only the platform's IRIS-owned agent footprint and staged agent
artifacts. It still does not reload the device or remove a staged software image.

Undeploy is driven by the device's applied **deployment record**, not its editable
inventory row, so a later inventory edit cannot retarget cleanup. An
**inband** device's teardown removes the app footprint and every other
IRIS-named artifact — the EEM applets, the IRISQ discriminator and its logging
bindings, and the IRIS PKI trustpoint and HTTP-client binding — and preserves
the operator-owned VLAN/SVI/routes/VRF. An agent without an active deployment
record must be **adopted** (an explicit, audited, no-change
recording of ownership) before it can be undeployed, or undeployed with
**Force** to strip only the agent footprint when there is no deployment record at all —
see [Bulk device actions](console.md#bulk-device-actions). A Catalyst 8000
router cannot be adopted, and preflight refuses an onboard over a live agent, so
a router with no deployment record has only Force as its path. Force behaves identically on every
platform: it removes every artifact identifiable by name as IRIS — the IRIS EEM
applets, the IRISQ logging discriminator and its buffered/console/monitor
bindings, `crypto pki trustpoint IRIS` and `ip http client secure-trustpoint
IRIS`, the app-hosting stanza, and the staged IRIS files — and leaves only the
operator's network exactly as it is: the VLAN/SVI, the VirtualPortGroup, and the
NAT rules, which no deployment record proves IRIS created. Undeploy therefore clears
exactly what preflight refuses, so a forced teardown leaves the device able to be
onboarded again. A missing, drifted, or uncertain deployment record otherwise stops cleanup
in `needs-reconcile` rather than guessing. See
[Management Type and VLAN Ownership](management-type.md).

### Recovering an interrupted IOS-XR teardown

An IOS-XR undeploy that was interrupted partway through needs no special
recovery: re-run undeploy (record-backed or Force) and it converges, because
each step re-probes the router's own state — including the appmgr
application's — before acting rather than assuming an earlier attempt
succeeded. A step that cannot even trust its own probe — a transport error,
or a truncated read — refuses to continue rather than guess, and a failed
teardown leaves the device's deployment record in `needs-reconcile` (a red badge in
the console); undeploy or Force is legal to run again directly from that
state, and the re-run converges the same way. Every command session to the
router is bounded by `IRIS_XR_SESSION_TIMEOUT` (tracked default 150 seconds
in `lab/xr-run.sh`; a value exported in the server's environment always
takes precedence over that default, `0` disables the bound entirely, and an
invalid value falls back to the default with a logged warning), so a
wedged router fails the job with a real exit code instead of hanging it. The
150-second default sits at the top of a measured 120-150-second band:
every healthy session in the lab runs ~15-20 seconds, so 150s carries
6-10x headroom over that ceiling for both install and teardown alike — the
install Up-poll is 30 short, client-looped sessions rather than one long
one, so it shares the same bound safely without a separate knob. Undeploy
composes at most two bounded sessions per run — a read-only probe and
deactivate session, then a destructive uninstall/remove/sweep/verify
session — so a completely unresponsive router
holds a teardown job for at most 300 seconds (two stalled sessions) at
the default bound. A deployment
with a tighter job-queue deadline can still export a lower
`IRIS_XR_SESSION_TIMEOUT` (e.g. `60`) in the server's environment. XR's CLI
has no prompt-free way to remove a directory, so a completed teardown may
honestly leave an empty `iris-work/` directory behind on harddisk: rather
than failing over it — a later onboarding simply reuses that same directory
(it only ever ensures the directory exists, never requires it be absent).

An `IRIS_XR_SESSION_TIMEOUT` override changes each session's bound, not the
whole job's deadline. For example, 300 seconds allows up to 600 seconds across
the two teardown sessions.

Successful cleanup ends with `undeploy complete: <device-ip>` on every
platform. XR undeploy removes the app, package, agent files, and torrent
sidecars. It leaves image files at `harddisk:` root in place and does not
change assignments. This differs from clearing assignments while the XR
agent is running: the agent can remove files it recorded as downloaded by
IRIS, while retaining adopted files and files of unknown origin. See
[Unassigned image park](device-agents.md#unassigned-image-park).

Deleting an inventory row is not an undeploy — undeploy before deleting anything
still deployed. See [Bulk device actions](console.md#bulk-device-actions).

## Rebuilding the catalog from images already on disk

A catalog reset does not delete image files, and operators often stage images on
the host outside IRIS, so the recovery path after wiping `iris-state` is to
republish from disk rather than re-upload gigabytes. The Images screen's **Import
from disk** panel lists image files that exist under either root — the uploads
volume (`IRIS_IMAGES_DIR`) or the read-only import root (`IMAGES_ROOT`) — and
are not in the catalog.

Publishing from the panel happens **in place**. The seeder seeds from the file's
own directory, so nothing is copied and the read-only root stays read-only; the
`.torrent` is written to the state directory, never next to the image. Import
each file back instead of copying it into the uploads volume first.

Files the panel greys out carry a reason, and the three reasons and their fixes
are listed in [Import skip reasons](reference.md#import-skip-reasons) — an
`ambiguous name in more than one location` needs the duplicate removed or
renamed, and `not readable by the server` is the ownership problem above. Each
import is audited as `image_import`, rejections included, recorded with
`result=fail`.

A later delete of an entry published in place leaves the file on disk: the unlink
decision comes from the entry's recorded directory, not from its filename. See
[Catalog entry fields](reference.md#catalog-entry-fields) for the exact rule,
including how entries with no recorded source directory are handled.

## Artifact-server diagnostics

The artifact server logs one line per GET with the method, path, response
status, duration, and in-flight request count. TLS handshakes happen in the
per-connection worker rather than the accept loop, have a 30-second handshake
bound, and use a listen backlog of 128. During a slow fleet onboard, compare the
persisted deployment-log offsets with lines such as `artifacts GET ... in
0.123s (inflight 20)` to distinguish device-side delay from server-side
concurrency. Expired staging credentials are swept on a five-minute timer, not
on a request path, so one fetch cannot trigger deletion work for another.

## Rotating the Console-to-server credential

The Console reaches server state only through the internal management API on
9443. Both services read the credential from mounted files; never place it in
`server/.env`, a Compose `environment:` value, a URL, or a command argument.
Compose atomically provisions a scoped random value in its `iris-tier-auth`
named volume on first start. Kubernetes operators create the corresponding
Secret before deployment, as documented in [Kubernetes](kubernetes.md).
Separate Docker hosts keep local credential directories; use the
[remote rotation procedure](docker-hosts.md#rotate-the-management-credential)
to transfer the new value before removing the old one.

Rotation uses the current/previous overlap and is intentionally two phase:

1. Preserve the current scoped JSON record as `previous.json`, then atomically
   replace `current.json` with a random value of at least 32 bytes. Compose's
   `iris-management-token rotate` makes the overlap durable before replacement
   and rejects paths that refer to the same file. Kubernetes uses the two
   projected Secret keys.
2. Confirm both tiers have received the new `current` file and make an
   authenticated browser request through `/api/v1/session`. The processes
   reread their files for requests. Kubernetes should roll Console and server
   while the overlap exists and check the mounted values; see its
   [rotation procedure](kubernetes.md#secrets-and-storage).
3. Remove `previous.json` for Docker or empty the Kubernetes `previous` key,
   verify again, and securely retire any out-of-band copy of the old value.
   Keep the Kubernetes key present because both pods project it.

The Console tries the current token first and can use the previous token only
after a management-authentication rejection. It retains the token accepted by
authorization preflight when forwarding a mutation. It never retries a streamed
request body. Readiness or successful API access alone does not prove the new
token has reached both tiers, because the previous token may still work.

The server rereads the pair and compares both in constant time. A missing,
unreadable, too-short, wrongly scoped, or unmatched value returns a redacted
401 before a route is matched or a request body is read. The Console pins the
management CA independently; a token does not enable plaintext fallback.

## TLS rotation and device packages

The canonical device image, both IOx wrappers (`iris-arm64.tar` and
`iris-amd64.tar`), and the IOS-XR wrapper (`iris-xr.rpm`) are
**deployment-neutral**. None contains a server certificate, and none needs
`CATALOG_PEM` at build time. Console and API onboarding invoke the same
platform installers available from the CLI, and every path delivers the
current public certificate beside the package instead:

- IOx copies it into app-hosting application data after activation and before
  app start. The container reads that runtime file from CAF's app data directory.
- IOS-XR copies it to `harddisk:/iris-catalog.pem`, which the appmgr container
  reads through its `/hostmount` harddisk bind mount.
- Guest Shell receives the same current public certificate with its other
  short-lived onboarding artifacts.

Rotating or regenerating the server certificate therefore does **not** make an
IOx tar or XR RPM stale and does not require a package rebuild. It does leave
already-onboarded agents trusting the previous certificate. Re-onboard every
affected device so its runtime trust file is replaced; the same unchanged IOx
or XR package may be reused. Console onboarding requires the normal undeploy,
then onboard sequence because preflight refuses an already-running IRIS agent.

Console **Settings → Device packages** (also linked from the setup flow) keeps
the readiness checks separate:

- Each IOx/XR package row checks that the wrapper is readable and non-empty, that its
  adjacent `.manifest` has the expected wrapper kind, filename, platform, and
  canonical OCI digests, and that the manifest's wrapper SHA-256 matches the
  served bytes. `ok` proves that byte-to-provenance binding only; it does not
  inspect package contents or validate a native signature. `stale` means the
  wrapper digest disagrees with its manifest. Missing, unreadable, or malformed
  evidence reports `absent` or `unknown`, never success.
- The `iris-agent.tgz` row checks the latest server startup provisioning
  result and the resulting bundle and `bootstrap.sh` digests. Startup verifies
  the image-baked aria2c against the x86_64 checksum pin and ELF architecture
  before replacing the bundle. A verification, packing, or publication failure
  reports `stale`; absent or invalid evidence reports `unknown`. The server
  continues running, but an older bundle left on disk cannot appear ready.
  Inspect startup logs and correct the image input or artifact-directory
  permissions before restarting. The provisioning record lives at
  `$IRIS_RUN/served-bundle.json` (default `/run/iris/served-bundle.json`),
  independently of the artifacts mount so a read-only mount is visible.
  Readiness also requires this server startup to have confirmed provisioning;
  a previous successful record cannot hide a failure to write the new record.
- The card separately compares the certificate the live services present with
  the public `iris-catalog.pem` copy onboarding distributes. A missing copy or
  mismatch means new onboarding is not ready. Reconcile that served artifact;
  rebuilding deployment-neutral packages cannot repair certificate drift.

`tools/check-package-freshness.sh` checks the IOx/XR wrapper and certificate
conditions above; the Guest Shell provisioning record is reported by the
Console setup-status endpoint. Its default
mode is read-only; `--rebuild` rebuilds wrapper families whose package or
provenance evidence is missing or invalid, then rechecks. It will not rebuild
packages to paper over a served-versus-distributed certificate failure.

Package rebuilds remain mandatory after a shared agent or device-image source
change. Before rebuilding, set `IRIS_INSTRUCTION_ROOTS_DIR` to the approved
two-public-root directory and `ARIA2C_BIN_AMD64` / `ARIA2C_BIN_ARM64` to the
current checksum-pinned binaries if fallback artifacts are older. Root private
keys never enter build inputs. Rebuild the server to refresh its Guest Shell
bundle, then build both IOx wrappers and the XR wrapper with their adjacent
provenance manifests:

```bash
docker compose -f server/docker-compose.yml up -d --build
IRIS_FORCE_DEVICE_IMAGE_BUILD=1 tools/provision-iox-packages.sh
tools/build-xr-package.sh --out artifacts/
tools/check-package-freshness.sh
```

The force flag allows the local canonical archive to be replaced when source
changed without a `VERSION` change. To retain that archive, set
`IRIS_DEVICE_IMAGE_OCI` to a new path for both wrapper commands instead. Both
families must package the same canonical build.

For a manual Guest Shell bundle build with the approved public-root directory
configured, the no-argument command still verifies
`bin/aria2c` against the x86_64 pin and writes `artifacts/iris-agent.tgz`.
Produce the ARM bundle from an explicitly selected aarch64 binary:

```bash
tools/make-agent-bundle.sh
tools/make-agent-bundle.sh --arch arm64 \
  --aria2 tools/aria2c-build/out/aarch64/aria2c
```

The ARM command verifies both the static ELF architecture and the aarch64
entry in `tools/aria2c.sha256`, then writes `artifacts/iris-agent-arm.tgz`.
It leaves the x86_64 bundle and `bin/aria2c` unchanged. `--out /path/bundle.tgz`
selects another output path. These commands pack existing binaries; they do
not rebuild aria2c or contact a device. Refresh the ARM bundle before any
wrapper build that uses it as an input, or pass the verified binary directly
with `ARIA2C_BIN_ARM64`.

The pinned amd64 and arm64 aria2 binaries are now built from the documented
source pin plus all six patches in `tools/aria2c-patches/`. Patches 0005 and
0006 make the configured peer admission cap cover stalled/pending connections
and preserve protocol messages coalesced with the BitTorrent handshake. These
binaries are the source inputs for the **next** signed IOx wrappers and XR RPM,
and for refreshed Guest Shell bundles. Their presence in the source tree does
not mean a release was cut, a package was signed, or any deployed device was
updated. Build, sign where your platform process requires it, verify the
adjacent provenance, and redeploy as separate operator actions.

Then redeploy affected devices so they actually run the new agent bytes. A
green package row verifies the served wrapper against its manifest; it does
not compare the package with the current checkout or confirm that an already
deployed device runs those bytes.

## Redeploying agents after an artifact rebuild

Rebuild and publish the Guest Shell bundles, both IOx packages, and the XR
package after changing shared agent source. Redeploy affected devices to run
those bytes. A package rebuild does not change an already-running agent.

The server accepts only report fields and peer identities it can validate.
Unrecognized peer data is omitted from transfer attribution. Check the device's
running agent and its package when a report lacks expected peer details.

## Rotating the seeder announce credential

`rotate-seeder-announce` is the one supported way to rotate the seeder's announce
credential. It requires `--maintenance-frozen`, which acknowledges a freeze the
operator has already put in place — the command never creates one. Preflight
binds every published image's canonical torrent to exactly one active aria2 GID
and refuses before touching anything if an image has no canonical torrent, is not
uniquely active, the announce base is not a usable HTTPS IPv4 endpoint (loopback,
link-local, unspecified and multicast addresses are refused; any routable
address is accepted), durable encrypted secrets are missing, or a recovery
manifest from an earlier run is still on disk. A refusal names its reason on
stderr (`refused (ValueError: canonical torrent is not uniquely active)`); the
reasons are fixed phrases that never carry a URL or credential.

A quarantined image is skipped, not a refusal: its quarantine removed the
torrent from the seeder on purpose, so it cannot be "uniquely active" and must
not block rotating the credential for the rest of the fleet. The command lists
the skipped ids. Their canonical torrents keep the rotated-out announce until
the quarantine is released, which re-syncs the announce to the then-current
credential before re-adding the torrent (see
[Releasing a quarantine](#releasing-a-quarantine)). If every published image is
quarantined there is nothing active to rotate and the command refuses.

Each replacement rewrites only the outer announce and keeps the `info` byte span
identical, so info hashes do not move. Credential values are never accepted on
the command line and never printed.

The rotated-out credential stays valid for a bounded overlap — 30 days from the
rotation, `IRIS_SEEDER_PREV_TTL` — so a device that has not yet received a
re-personalised torrent keeps announcing meanwhile. Nothing has to be retired by
hand: the old token expires on its own, and the next rotation drops the record.
Two still-valid previous records are the cap, and a rotation that would exceed
it is refused, so run no more than two rotations inside one window unless you
have already personalised the fleet's torrents. Expiry cannot lock a device out:
the way it picks up the current credential is a fresh personalised torrent from
the catalog, and that request is authorised by the device's catalog token.

**The rotation is only reported complete when the tracker independently proves
the new identity is serving.** After every canonical torrent is re-added, the
command polls the telemetry listener's authenticated, pinned-TLS `/swarm` and requires the current typed
`service:seeder` principal to be observed for every expected info hash, each with
an announce later than the post-add boundary. A completed device peer does not
stand in for that proof, and there is no registry shortcut or IP-based guess.
Anything else — transport error, timeout, or a document that does not prove it —
fails closed: serving is not claimed, the freeze stands, the recovery manifest is
preserved, and the command exits non-zero.

Every run writes a non-secret recovery manifest with the exact pre-rotation
torrent bytes and their digests before it starts. If an add fails, the old bytes
are restored and the old torrent re-added. If that re-add also fails, or a remove
fails and live state is therefore unknown, the run becomes a **hard no-go**: old
bytes are restored for every torrent already rotated, the remaining torrents are
abandoned, and maintenance stays frozen.

!!! warning "A hard no-go can leave an image not being served"
    The run does not claim the image is still being served, and it may not be.
    The result lists every disturbed torrent — a `false` restore result means
    serving repair is still required for that image before the freeze is lifted.

`--recover` restores the exact pre-rotation state from the manifest. It validates
the manifest — version, terminal state, path containment, digest and info-hash
agreement, and that the named image directory matches the current catalog —
before any file or aria2 call. Recovery leaves maintenance frozen and keeps the
manifest as evidence in either outcome.

## Recovery checklist

1. Confirm both `iris` and `iris-console` are running. In Kubernetes, check
   both deployments.
2. Check server logs for catalog, tracker, seeder, storage, and secret errors.
   Check Console logs for management API connectivity or authentication errors.
3. Confirm the Console can reach the internal server API on HTTPS TCP 9443.
   Do not publish that port for devices or browsers.
4. From the device's agent network, check the catalog on HTTPS TCP 8443 and
   tracker on HTTPS TCP 6969. Check BitTorrent TCP 6881 to the server seeder
   and TCP 6881–6999 between device peers. Guest Shell onboarding also needs
   the artifact server on HTTPS TCP
   8000; server-to-device onboarding uses SSH/SCP on TCP 22. IOx additionally
   needs SSH/SCP from the app to IOS. See [Network ports](network-ports.md).
5. Confirm the published image still exists in its recorded source directory
   under the import root or uploads volume, and uid 10001 can read it.
6. Confirm the server can read its age key, state, and artifacts. Check the
   device clock and runtime certificate if catalog or tracker TLS fails.
7. Read the device's job log, heartbeat, and per-image report. Confirm its
   management type, installer, and addresses before retrying. A running agent
   normally requires undeploy before Console onboarding again.
