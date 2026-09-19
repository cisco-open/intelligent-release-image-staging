<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Roles and sharing-policy API

Routes, fields and refusal codes for roles and QoS. See [Security model and trust boundaries](../architecture/security-model.md) for how roles and policy work, and [Control which devices share with each other](../user-guide/roles.md) for the task.

## Routes

| Route | What it does |
| --- | --- |
| `GET /api/v1/peer-policy` | Returns a count-only status: role and member counts, outbox size, the applied policy revision, and other summary fields. See [Response fields](#response-fields). |
| `GET /api/v1/peer-policy/roles` | Returns every role definition, sorted, with the current revision and ETag. |
| `PUT /api/v1/peer-policy/roles/<name>` | Creates or replaces one role definition. Preview with `?dry_run=1` before you commit. See [Role fields and validation](#role-fields-and-validation). |
| `GET /api/v1/peer-policy/roles/export-csv` | Returns every role definition as CSV, in the format `iris-role export` writes. Returns `503 policy_unavailable` instead of an export when the policy is degraded. |
| `POST /api/v1/peer-policy/roles/import-csv` | Replaces every role definition in one revision from an uploaded CSV file, up to 8 MiB. A role a device or a schedule still uses cannot be dropped; refuses with `role_in_use`. A CSV grammar problem refuses with `invalid_roles_csv`, naming the row or field. |
| `DELETE /api/v1/peer-policy/roles/<name>` | Deletes an unused role after preview. The preview returns 200 JSON with the candidate revision and ETag; the committed DELETE returns 204 with an empty body and the committed ETag. A role with members, or another role that still permits it, refuses with `role_in_use`. |
| `PUT /api/v1/peer-policy/qos` | Replaces global QoS, or one role's QoS, or the `qos_state` tracker overlay, or both together. See [QoS keys](#qos-keys). |
| `POST /api/v1/devices/<id>/role` | Sets or clears one device's role. |
| `POST /api/v1/devices/bulk-role` | Applies one role change to a batch of devices as one policy revision, with a request body up to 2 MiB. |
| `GET /api/v1/devices/<id>/effective-qos` | Returns the QoS values that apply to one device, with their source. Add `tracker_state=seeder` or `tracker_state=leecher` to also get paired `tracker_state`/`tracker_qos` values for that state. Invalid or unknown query input refuses with `422 invalid_policy_request`; an unknown device refuses with `404 device_not_found`. `delivery_state: pre-instructions` is a deprecated legacy value. |
| `GET /api/v1/peer-policy/explain?a=&b=` | Resolves two devices, or a device and the server's own seeder, and returns whether each side permits the other, the matched rule, and the current revision. Each argument is a device id, `device:<id>`, or `service:seeder`. Refuses with `422` when a side cannot be resolved to exactly one match. |
| `PUT /api/v1/peer-policy/quarantine/<device_id>` | Quarantines or releases one device. The body must be exactly `{"quarantined": <bool>, "if_revision": <int ≥ 1>}`, with no other keys. `if_revision` is the revision from `GET /api/v1/peer-policy`. Success returns `200 {ok: true, revision, quarantined}`. |

Role and QoS writes share one policy revision:

1. Read the current ETag from `GET /api/v1/peer-policy`.
2. Send your write with `If-Match: <ETag>` and `?dry_run=1`. Result: a `confirm_token`.
3. Send the same body again with `confirm_token` set, using the original ETag. Result: the write commits.

A token is bound to the revision and body it previewed. If another commit lands first, reread the ETag and preview again. See [Automate with the API](../user-guide/automation.md) for a full worked session.

On `/api/v1`, a missing or expired browser session returns 401 `console-session-required`; sign in and preview again. On the private management listener, a missing or invalid management credential returns 401 `management-authentication-required`. A browser request also needs its current CSRF token.

## Role fields and validation

Role names match `^[a-z0-9][a-z0-9._-]{0,31}$`, and at most 256 roles may exist. `default`, `quarantine`, `origin`, `seeder` and `legacy` are reserved names.

| Field | Default / bound | Meaning |
| --- | --- | --- |
| `restricted` | `false` | When true, the server compiles a virtual access list for this role; false keeps open, implicit permit. |
| `peers` | the role itself; at most 64 | Permitted role names. The list must contain the role itself. A link between two restricted roles must be symmetric; the server normalizes the reciprocal side for you. |
| `origin` | `true` | Whether the tracker may introduce the server's own seeder to this restricted role. |
| `nets` | empty | Optional IPv4 subnet hints for role management. |
| `on_stale` | `keep` for restricted roles, `defaults` otherwise | What happens to QoS when the policy goes stale: keep the last verified values, or fall back to defaults. |
| `qos` | empty | Overrides the global QoS values for this role, for the keys that allow a role scope. |
| `qos_state` | omitted | The seeder and leecher tracker cadence overlay for this role. Tracker-only, and set only through the API. |

Allow-list membership always falls back to tracker-only, independent of `on_stale`. `peers` must be a non-null array of unique role names. The role schema sets no per-role member cap, but the devices in one role still cannot exceed the devices in your inventory. A restricted role with `origin: false` is valid. `origin_unreachable` is an advisory the server returns when neither this role nor a permitted role can reach the origin. Every role and QoS object is closed and typed: an unknown key is refused.

`nets` accepts a bare IPv4 address or an IPv4 prefix with a decimal length, a netmask, or a hostmask; leading zeroes and IPv6 are refused. `iris-role` CSV import compares networks for you and keeps the first valid spelling.

A role's `qos` object cannot set `defs.<role>.qos.on_stale`: that fallback is a separate field on the role definition, not a QoS key. Stored ACLs, the older explicit per-device peer lists, hold at most 64 names with 256 rules each; a role's rules compile in memory and use none of those slots. One explicit stored-ACL assignment shadows a role rather than combining with it. `iris-role migrate ACL ROLE --dry-run` previews moving a device between them; `iris-role migrate ACL ROLE --apply` commits the move in two policy revisions. A quarantined device cannot be migrated.

## QoS keys

Values are integers. Rate keys are bytes per second, and `0` means unlimited; a nonzero rate must be at least 8,192 B/s. Numeric QoS values reject booleans. A key with a state overlay resolves in this order, most general to most specific: builtin → `roles.qos_default` → `roles.qos_state_default.<state>` → `roles.defs.<role>.qos` → `roles.defs.<role>.qos_state.<state>`. A partial state map overrides only the key it supplies; every other key keeps resolving through the rest of the chain.

| Key | Default | Range | Scope | Current behavior |
| --- | ---: | ---: | --- | --- |
| `max_peers` | 10 | 1–1,000 | global, role, device | Hard per-torrent peer cap, including pending outbound peers. |
| `per_peer_bps` | 12,500,000 | 0 or 8,192–10,000,000,000 | global, role, device | A modelling input, not a cap by itself: when set, it derives any per-torrent rate you did not set as `per_peer_bps × fanout`. |
| `fanout` | 1 | 1–1,000, and no greater than `max_peers` | global, role, device | Modeling input for derived per-torrent rates. |
| `seed_up_bps`, `seed_down_bps` | 0 | 0 or 8,192–10,000,000,000 | global, role, device | Device rate while seeding; unlimited by default. |
| `leech_up_bps`, `leech_down_bps` | 0 | 0 or 8,192–10,000,000,000 | global, role, device | Device rate while leeching; unlimited by default. |
| `overall_up_bps`, `overall_down_bps` | 0 | 0 or 8,192–10,000,000,000 | global, role, device | Device-wide rate across all transfers; unlimited by default. |
| `max_concurrent` | 100 | 1–1,000 | global, role, device | Concurrent torrents a device runs. |
| `request_peer_speed_limit_bps` | 51,200 | 0 or 8,192–1,000,000,000 | global, role | Per-peer request rate a device applies. |
| `announce_min_interval_s` | 30 s | 10–300 s | global, role, state overlay | The tracker applies one bounded jitter of plus or minus 10% to the interval it issues; a peerless leecher still gets a 120 s floor. |
| `numwant` | 50 | 4–200 | global, role, state overlay | Ceiling on peers returned per announce; a client that asks for `numwant=0` gets none. |
| `handout_budget` | 0 (off) | 0–1,000 | global, role | Per-window handout limit accepted by the API. |
| `catalog_tick_s` | 60 s | 60–900 s, multiple of 60 | global, role, device | Catalog and staging cadence. For a restricted device, the effective value may not exceed effective `endpoint_ttl()/3`; the endpoint TTL defaults to 900 s but is configurable. |
| `telemetry_every_ticks` | 1 | 1–60 | global, role, device | Ticks between telemetry sends. |
| `telemetry_pause` | `false` | boolean | global, role, device | Suspends telemetry sends without changing anything else. |
| `on_stale` | `defaults` | `keep` or `defaults` | global or role definition | What happens to QoS when the policy goes stale. |
| `origin_up_bps` | 0 | 0 or 8,192–10,000,000,000 | global only | Origin-wide upload limit; unlimited by default. |
| `origin_per_torrent_up_bps` | 0 | 0 or 8,192–10,000,000,000 | global only | Per-image origin upload limit; unlimited by default. |
| `origin_max_peers` | 55 | 1–1,000 | global only | Origin per-torrent peer cap. |

`max_peers`, `max_concurrent` and the peer caps count connections; `fanout` is a multiplier; `numwant` counts peers per announce; `handout_budget` counts handouts per window; `telemetry_every_ticks` counts ticks; interval and cadence fields are seconds. Convert a decimal rate to the `*_bps` value with `Mbit/s × 1,000,000 ÷ 8`.

A `PUT /api/v1/peer-policy/qos` write replaces the whole selected QoS object; `{}` clears that layer. Omitting `qos_state` preserves the stored state object. An explicit `qos_state: {}` removes only the selected state layer and preserves the rest of the scalar QoS unchanged. A full role-definition replacement, a `PUT .../roles/<name>` write, must include `qos_state` to retain it: that write is a complete replacement, not a merge.

Use role membership and access rules to keep a role off a swarm. The Console edits role fields as typed fields; global or role QoS, including the `qos_state` overlay, is set only through `PUT /api/v1/peer-policy/qos`. There is no per-device QoS write route. Pair explanations come only from `GET /api/v1/peer-policy/explain`.

## Response fields

`GET /api/v1/peer-policy` is count-only: it never returns the raw deny list, peer addresses, aria2 option dictionaries, session IDs, or the device IDs behind the mutual-origin preflight. Role drift (the gap between a device's declared role and its compiled membership) is the one exception: up to ten device IDs return, flagged if the list was truncated.

| Field | Meaning |
| --- | --- |
| `roles_supported`, `roles_present` | Whether this server build understands roles, and whether role state has ever existed in this policy. Presence is not proof of enforcement. |
| `enforcement.state`, `applied_revision`, `stale` | The tracker's last reconciliation result and how fresh it is. A result older than five minutes is marked stale. |
| `enforcement.mutual_origin.mode = preflight` | Mutual-origin blocking (two devices that both hold a full copy of the same image) is observation-only. `newly_denied_device_count` is `null` when unavailable, and `0` when a completed check found no newly denied device; neither adds a device to the active deny list. |
| `origin_qos.state`, `target_download_count`, `applied_download_count` | Whether the origin's rate limits reached every active download. These are counts, not per-role throughput. |
| `fleet_rollup.issued_revision`, `fleet_rollup.applied` | The current issued policy revision, and accepted-device counts grouped by that revision. |
| `fleet_rollup.states.pre-instructions` | Devices whose last heartbeat did not claim the instruction protocol. |
| `GET /api/v1/devices/<id>/effective-qos` `delivery_state = pre-instructions` | A deprecated legacy sentinel; read the response's `instruction` object for current evidence instead. |

!!! warning
    Never log or export an aria2 option dictionary. Tracker authorization
    data can be present among those options.

## Refusals

Every policy write queues in an outbox the tracker must acknowledge; see [Security model and trust boundaries](../architecture/security-model.md) for the mechanism. A write that finds a full backlog of 256 unacknowledged entries is refused before it changes anything.

New role and QoS routes use exact strong ETags and return `409 operation_backlog_full` for a full outbox. The legacy quarantine route keeps its own refusals, which mean different things:

| Response | Meaning |
| --- | --- |
| `409 revision_conflict` | Policy changed elsewhere; retry against the revision the response returns. |
| `422 policy_error` | Policy is degraded and running on the last known good copy. Repair the file it read from. |
| `503 policy_fail_closed` | Policy is fail-closed; every mutation is refused. |
| `503 operation_backlog_full` | 256 operations are unacknowledged; check the tracker and reduce write pressure. |

Full descriptions of every code, including `precondition_required`, `precondition_failed`, `confirmation_required` and `role_in_use`, are in [API error codes (problem types)](../problems.md).
