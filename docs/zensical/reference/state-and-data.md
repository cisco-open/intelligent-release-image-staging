<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Data formats and states

Field names, file formats, and state values used by the Console, the API, and the device agent.

## Catalog entry fields

| Field | Meaning |
| --- | --- |
| `id` | The catalog id: the filename with `.SPA.bin` or `.bin` removed. |
| `filename` | The basename of the image file, as it reaches the device. |
| `source_dir` | The directory the image is seeded from. |
| `size` | The image size in bytes. |
| `sha256` | Checked by the agent against the staged file. |
| `sha512` | Compared with the Bulk Hash Cisco publishes. Guest Shell and IOx also use it to check a file already on the device; see [How the agent replaces an image without deleting it first](../architecture/data-path.md#crash-safe-same-name-replacement). |
| `cisco_signature_verified` | True once the Bulk Hash check has verified the image. |
| `operator_attested_signature` | True when the publisher ran `iris-publish --signature-verified`. Advisory only. |
| `hash_verification` | The latest verdict: state, when it was checked, source, and any deferral. |
| `quarantined` | True once a `mismatch` verdict holds the image back. Only `POST /api/v1/images/<id>/release-quarantine` clears it. See [Publish and verify images](../user-guide/images.md). |
| `info_hash_hex` | The image's torrent info hash. |
| `published_at` | The Unix timestamp of the publish. |

!!! warning
    A delete removes the image file only when `source_dir` points at IRIS's own images directory.

Catalog state is written as small JSON documents, atomically, under an
advisory lock, so a Console write and a CLI write at the same time cannot
corrupt it.

## Policy and heartbeat fields

`POST /api/v1/devices/<id>/assign` writes the policy; the agent reads it from `GET /v1/devices/<device_id>/policy`.

| Field | Meaning |
| --- | --- |
| `approved_image_ids` | Up to ten catalog image ids the device stages and verifies in parallel. |
| `approved_image_id` | The first id in `approved_image_ids`, or null. |
| `plans` | One transfer identity per approved image (`plan_id`, `transfer_id`, `planned_at`, `info_hash`). |

The heartbeat reports staging progress:

| Field | Meaning |
| --- | --- |
| `current_image_id` | The image that supplied this heartbeat's identity and observation. |
| `stage_state` | One state for the tick: `staging`, `downloading`, `transferring_to_ios`, `ready`, or `error`. |
| `stage_error` | The reason for `stage_state`. |
| `staged_image_ids` | Assigned images staged and verified as of the last heartbeat. |
| `errored_image_ids` | Assigned images that failed on the last tick. |

An image in both lists shows its current error, not the older staged flag. See [Assign images and check staging status](../user-guide/assignments.md#unassigned-image-park).

## Inventory CSV columns

`fleet/devices.csv` is a named-header CSV:

```text
device_id,device_ip,management_type,iris_vlan,svi_ip,svi_mask,app_ip,app_mask,app_gateway,inband_vlan,ios_ssh_host,model,vpg_number,nat_interface,svi_igp,role,platform
```

| Column | Meaning |
| --- | --- |
| `device_id`, `device_ip` | The device's id and management address. |
| `management_type` | `routed`, `inband`, `router-routed`, `router-nat`, or `xr-host`. |
| `iris_vlan`, `svi_ip`, `svi_mask` | The VLAN and SVI address IRIS creates. Routed only. |
| `app_ip`, `app_mask`, `app_gateway` | The address IRIS gives the agent. Routed, inband, router-routed, and router-nat. |
| `inband_vlan` | The existing management VLAN the agent attaches to. Inband only. |
| `ios_ssh_host` | The IOS endpoint an inband IOx app connects to. Defaults to `device_ip`. |
| `model` | The device's hardware model. May be blank. |
| `vpg_number` | The VirtualPortGroup number IRIS creates. Router-routed and router-nat only. |
| `nat_interface` | The interface router-nat uses for port address translation. |
| `svi_igp` | `isis` to add IS-IS to the IRIS SVI, or blank. Routed only. |
| `role` | Optional. The device's named group of devices that share with each other. |
| `platform` | `router` for router-routed and router-nat, `xr-appmgr` for xr-host. |

The Console and the API accept only these fields plus `credential_profile_id`. A write with any other field name is rejected, not silently stored. `schema_version`, `registered_at`, `registration_id`, and `os_family` are set by the server. `registration_id` distinguishes a device deleted and re-added under the same `device_id` within the same second. Two older CSV headers, `vlan` and `guest_ip`, are still accepted on import.

Import and export this CSV from [Add and onboard devices](../user-guide/onboarding.md). Roles and schedules have their own templates: `fleet/roles.csv.example` and `fleet/schedules.csv.example`; see [Control which devices share with each other](../user-guide/roles.md) and [Schedule maintenance windows](../user-guide/scheduling.md).

## Instruction state vocabulary

An instruction is the signed message the server sends a device saying which images to stage and how. Each tick, the agent reports one raw state; the server derives a display state from that, report age, and revocation.

Raw agent states: `none`, `applied`, `lkg`, `stale_expired`, `allowlist_expired`, `rollback_rejected`, `floor_reset`, `audience_mismatch`, `key_rejected`, `tamper_rejected`, `verifier_missing`, `lkg_rejected`, `lkg_unreadable`, `oversize`, `reasserted`, `instr_unavailable`, `instr_pending`, `instr_forbidden`, `tracker-only`.

Server display states: `applied`, `lkg`, `stale`, `rejected`, `tracker-only`, `pre-instructions`, `unknown`, `unavailable`, `pending`, `forbidden`, `floor_reset`, `none`, `revoked`.

`lkg` means the device fell back to its last accepted policy (LKG, last known good; see [Glossary](glossary.md)). The Guest Shell agent package bundles its own signature verifier, so every device checks instruction signatures. `verifier_missing` means the device's agent package is outdated or damaged; redeploy the package to fix it. A device whose `instr_protocol: 1` marker is absent displays as `pre-instructions`; an `instr_protocol` value that is invalid displays as `unknown`. A durable `revoked` display overrides the agent's own state, and the underlying agent evidence stays visible beneath it. Missing/corrupt evidence reads as null/unknown and must never become healthy zero. The server measures report age itself: an old report is marked stale while the underlying agent state and its evidence stay visible.

| Revision term | Meaning |
| --- | --- |
| `policy_revision` | The server-issued role and QoS intent. |
| `instr_serial` with `instr_epoch` | The per-device freshness identity. A device never accepts a candidate below its own accepted floor. |
| `enforcement.applied_revision`, `iris_peer_enforcement_applied_revision` | Counters for aria2 blocklist changes, unrelated to `policy_revision` or `instr_serial`. |

Each device row, and the per-device QoS response, carries one `instruction` object:

| Field | Meaning |
| --- | --- |
| `display_state`, `label` | The display state above, and its human-readable label. |
| `evidence` | What the display state is based on. |
| `underlying_state`, `underlying_label`, `underlying_evidence` | The raw agent state, kept visible even under a revoked display state. |
| `reason` | Why the agent reported the state. |
| `reported_instr_serial`, `accepted_identity` | The serial the agent reported, and the accepted `{epoch, instr_serial, policy_revision}`, or null. |
| `verify_level` | How the agent verified the instruction. |
| `pointer_skew` | The bounded count of fresh-but-behind-pointer observations. |
| `qos_drift_count` | The bounded count of QoS corrections the agent reported applying. |
| `report_age_seconds`, `report_stale` | How old the last report is, and whether that makes it stale. |
| `revoked`, `revocation_evidence` | Whether a durable revocation is in force, and the evidence for it. |

!!! warning
    A `violation` count of zero means no violation is in the evidence, not that the device is compliant.

`/api/v1/peer-policy` adds `fleet_rollup`, an `instruction_status` summary, and `instruction_keys`. See [Roles and sharing-policy API](peer-policy-api.md) and [How instructions are signed and trusted](../architecture/security-model.md).

## Instruction failures and recovery

| State | Retained QoS/peer state | Action |
| --- | --- | --- |
| First tick/no file: `none` | Defaults, tracker-only peers | Wait for a stamp and authenticated refresh. |
| Valid fresh envelope: `applied` | Verified QoS and peer state, recorded as the accepted identity | Normal cadence. |
| Cached instructions during catalog loss: `lkg` | The locally re-encrypted verified LKG is retained | Retry on a later tick. |
| Instruction expires: `stale_expired` | Role `on_stale: keep` retains QoS; `defaults` restores defaults | Restore authenticated catalog time and fresh instructions. |
| Attribution expires: `allowlist_expired` | An expired allow-list falls back to tracker-only, and an expired deny-list remains effective; both independently of `on_stale` | Refresh endpoint attribution and instructions. |
| Older identity: `rollback_rejected`; authenticated reset: `floor_reset` | Reject older candidate; a validated reset adopts its new floor | Repair the server epoch/stamp. |
| Wrong device/platform: `audience_mismatch` | Retain usable LKG/defaults | Redeliver for the exact device/platform. |
| Unknown key: `key_rejected` (`unknown_key`) | Retain usable LKG/defaults | One unscheduled refresh per unknown key ID, then retry later. |
| Bad MAC: `key_rejected` (`bad_mac`) | Retain usable LKG/defaults | Record a violation and inspect integrity. There is no refresh. |
| Bad signer or tampered bytes: `tamper_rejected` | Retain only independently usable LKG/defaults | Repair signer/keylist or envelope provenance. |
| Outdated or damaged agent package: `verifier_missing` | Tracker-only peers, verified/default QoS | Redeploy the agent package. |
| Bad local cache: `lkg_rejected`, `lkg_unreadable` | Defaults, tracker-only peers | Obtain a fresh envelope. |
| Oversize response: `oversize` | Retain usable LKG/defaults | Fix the producer or transport, and retry on a later tick. |
| aria2 session restart: `reasserted` | Reapply verified/default QoS | Check `qos_drift_count`. |
| Instructions 404/429/5xx/transport: `instr_unavailable` | Retain usable LKG/defaults | Retry on a later tick; never sleep in-tick. |
| Instructions 409 `stale_pointer`: `instr_pending` | Retain usable LKG/defaults | Retry on a later tick; never sleep in-tick. |
| Instructions 401/403: `instr_forbidden` | Retain usable LKG/defaults | One token refresh, then retry on a later tick; no in-tick retry loop. |
| Durable revoked principal: `revoked` | Underlying agent state stays visible | Resolve retirement/compromise on the server. |
| Pointer/body race | A higher body serial applies; a lower-but-fresh one above the floor applies with `pointer_skew`; below its accepted floor it reports `rollback_rejected`. At an equal identity, identical bytes are accepted idempotently, and different bytes report `tamper_rejected` | After three skews, check producer convergence. |
| Explicit `tracker-only` | Tracker supplies peers under server policy | No device peer-list enforcement. |

A fetch or verification failure affects only that step: heartbeat and staging continue on usable LKG or defaults. An aria2 RPC apply failure still sends a heartbeat but skips staging that tick. A rejection can coexist with a complete older accepted identity.

The instruction and keylist endpoints share a per-device rate limit: a burst of 2 requests, refilling at one every 10 seconds. A `429` response carries a bounded `Retry-After` hint.

## Deployment records

IRIS records three parts of each device deployment:

| Part | What it is |
| --- | --- |
| Desired inventory | Editable operator intent, `fleet.d/`. |
| Deployment plan | An immutable, resolved plan for one action, including the resolved platform and a `plan_hash`. Computed before any device contact. |
| Deployment record | A durable, non-secret account of what IRIS actually applied: resource ownership, lifecycle state, management IP, and processor-board identity. |

A deployment record's lifecycle is fail-closed:

```text
planned → applying → active → (applying) → removed
                 ↘ unknown / needs-reconcile / drifted / superseded
```

A controller restart converts any non-terminal record (`planned` or
`applying`) to `unknown`; in-flight device work is never silently resumed. A
device has exactly one live deployment, so when a new deployment record
becomes `active`, any previous `active` record for that device is retired to
the terminal `superseded` state.

## Setup-status states

`GET /api/v1/settings/setup-status` reports one state each for `admin`, `telemetry`, `packages`, and `image_verification`.

| State | Meaning |
| --- | --- |
| `ok` | Configured and current. |
| `unset` | Nothing configured yet. |
| `stale` | Configured, but due for a refresh or renewal. |
| `absent` | An expected file or certificate is missing. |
| `unknown` | The server could not determine the state. |

## Where server state lives

The management process writes these, on the server host:

| Base | Files | What it holds |
| --- | --- | --- |
| `$IRIS_CONFIG/instr/` | `signing-key.age`, `signing-key.pub`, `signing-key-cert.pub`, `roots.d/` | The encrypted online private key, its public half and its certificate; `roots.d/` carries public roots only. |
| `$IRIS_RUN/instr/` | `signing-key`, `signing-key-cert.pub` | Runtime plaintext only, beside the runtime certificate cache. Written on start, gone when the server stops. |
| `$IRIS_STATE/` | `instructions-epoch.json`, `instructions-epoch.json.lock`, `instruction-key-status.json`, `instruction-stamper-status.json` | Durable instruction state: the epoch, its lock, and the key and stamper status. |
| `$IRIS_STATE/instructions/` | `keylist.current`, `keylist-state.json`, `keylist.lock`, `roles.d/`, `role-state.json`, `activation.json`, `producer.lock`, `admitted-devices.json`, `serial-history.json`, `roles.lock` | Durable instruction state: the keylist, the role artifacts, the admitted devices and the serial history. |

Every per-device store under `IRIS_STATE` is keyed state, split over 256 shard files.

| Store | Directory |
| --- | --- |
| Heartbeats | `<state>/devices.d/` |
| Staging approval | `<state>/policy.d/` |
| Telemetry report rings | `<state>/telemetry.d/` |
| Seen-report-id ledger | `<state>/report_ledger.d/` |
| Transfer attestations | `<state>/transfer-attestations.d/` |
| Pending pull directives | `<state>/pull_requests.d/` |
| Durable peer endpoints | `<state>/peer-endpoints.d/` |
| Operator inventory (fleet) | `<state>/fleet.d/` |

The peer endpoint map holds one row per principal, in `peer-endpoints.d/`, split over 256 shard files. An announce locks, parses, and rewrites only its own principal's shard, recording the announce's socket source as the address.

### `report-attribution.json`

`<state>/report-attribution.json` pins, per exported device report, the
peer-attribution classification (origin, device, or unknown) of that
report's rows. The server classifies a report once, at first export, and
reuses the same classification if the same report is re-exported under the
same `event.id` after a server restart, so a downstream system that
deduplicates by `event.id` never sees two different records with one id. If
the pin is lost, a later replay can classify the same rows differently,
using whatever peer-identity view is current at replay time.

If that durable write fails, the entry is queued in memory and retried on the following reconcile passes rather than dropped. The device keeps participating in the swarm meanwhile, but the reported enforcement status degrades until the write lands, because the derived deny set is computed from durable state.
