<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# API error codes (problem types)

IRIS API errors follow [RFC 9457 Problem Details](https://www.rfc-editor.org/rfc/rfc9457.html). Match on the `type` or `code` field, not on `title` or `detail`, which can change.

!!! warning
    The BitTorrent tracker is the exception: its errors stay bencoded BEP failure dictionaries, not Problem Details.

Codes appear in alphabetical order below, grouped here by the part of IRIS that returns them.

| Group | Codes |
| --- | --- |
| HTTP | [`authentication-required`](#authentication-required) · [`content-length-required`](#content-length-required) · [`credential-store-unavailable`](#credential-store-unavailable) · [`csrf-validation-failed`](#csrf-validation-failed) · [`forbidden`](#forbidden) · [`internal-error`](#internal-error) · [`invalid-content-length`](#invalid-content-length) · [`invalid-request`](#invalid-request) · [`invalid-request-body`](#invalid-request-body) · [`method-not-allowed`](#method-not-allowed) · [`payload-too-large`](#payload-too-large) · [`precondition-failed`](#precondition-failed) · [`rate-limit-exceeded`](#rate-limit-exceeded) · [`request-body-not-supported`](#request-body-not-supported) · [`request-timeout`](#request-timeout) · [`resource-conflict`](#resource-conflict) · [`resource-not-found`](#resource-not-found) · [`route-not-found`](#route-not-found) · [`service-unavailable`](#service-unavailable) · [`unprocessable-content`](#unprocessable-content) · [`unsupported-media-type`](#unsupported-media-type) · [`upstream-operation-failed`](#upstream-operation-failed) |
| Console and management | [`console-certificate-unavailable`](#console-certificate-unavailable) · [`console-session-required`](#console-session-required) · [`invalid-authorization-request`](#invalid-authorization-request) · [`management-api-unavailable`](#management-api-unavailable) · [`management-authentication-required`](#management-authentication-required) · [`reconciliation_required`](#reconciliation_required) |
| Artifact server | [`artifact-authentication-required`](#artifact-authentication-required) · [`artifact-forbidden`](#artifact-forbidden) · [`artifact-not-found`](#artifact-not-found) · [`artifact-request-failed`](#artifact-request-failed) · [`artifact-resource-forbidden`](#artifact-resource-forbidden) · [`range-not-satisfiable`](#range-not-satisfiable) |
| Catalog and device instructions | [`catalog-authentication-required`](#catalog-authentication-required) · [`instruction-device-forbidden`](#instruction-device-forbidden) · [`instruction-keylist-missing`](#instruction-keylist-missing) · [`instruction-keylist-unavailable`](#instruction-keylist-unavailable) · [`instruction-rate-limit-exceeded`](#instruction-rate-limit-exceeded) · [`instruction-state-unavailable`](#instruction-state-unavailable) · [`instruction-stamp-missing`](#instruction-stamp-missing) · [`invalid-tracker-auth-selector`](#invalid-tracker-auth-selector) · [`stale_pointer`](#stale_pointer) |
| Roles and sharing policy | [`acl_not_found`](#acl_not_found) · [`asymmetric_peers`](#asymmetric_peers) · [`bad_acl`](#bad_acl) · [`bad_device_id`](#bad_device_id) · [`bad_quarantine`](#bad_quarantine) · [`bad_role`](#bad_role) · [`bad_role_mapping`](#bad_role_mapping) · [`confirmation_required`](#confirmation_required) · [`device_not_found`](#device_not_found) · [`fleet_write_failed`](#fleet_write_failed) · [`incomparable_role_change`](#incomparable_role_change) · [`invalid_policy`](#invalid_policy) · [`invalid_policy_request`](#invalid_policy_request) · [`invalid_roles_csv`](#invalid_roles_csv) · [`mixed_role_direction`](#mixed_role_direction) · [`operation_backlog_full`](#operation_backlog_full) · [`policy_error`](#policy_error) · [`policy_fail_closed`](#policy_fail_closed) · [`policy_unavailable`](#policy_unavailable) · [`precondition_failed`](#precondition_failed) · [`precondition_required`](#precondition_required) · [`principal_unresolvable`](#principal_unresolvable) · [`revision_conflict`](#revision_conflict) · [`role_in_use`](#role_in_use) · [`role_isolated`](#role_isolated) · [`role_management_error`](#role_management_error) · [`role_not_found`](#role_not_found) · [`role_reserved_name`](#role_reserved_name) · [`role_shadowed_by_assignment`](#role_shadowed_by_assignment) · [`unknown_device`](#unknown_device) |
| Schedules | [`invalid_schedule`](#invalid_schedule) · [`schedule_conflict`](#schedule_conflict) · [`schedule_not_found`](#schedule_not_found) · [`schedule_state_unavailable`](#schedule_state_unavailable) · [`schedule_target_heartbeat_unavailable`](#schedule_target_heartbeat_unavailable) · [`schedule_target_policy_unavailable`](#schedule_target_policy_unavailable) · [`schedule_target_status_unavailable`](#schedule_target_status_unavailable) · [`schedule_target_unavailable`](#schedule_target_unavailable) |
| Observability | [`observability-authentication-required`](#observability-authentication-required) · [`telemetry-status-unavailable`](#telemetry-status-unavailable) |

## acl_not_found

404: the ACL named for migration does not exist in current policy.
## artifact-authentication-required

The artifact server operation needs valid HTTP Basic device credentials.
## artifact-forbidden

Access to the requested staging artifact is not allowed.
## artifact-not-found

The requested staging artifact does not exist.
## artifact-request-failed

The artifact server could not complete an otherwise valid request.
## artifact-resource-forbidden

The device credential does not grant access to the requested artifact.
## asymmetric_peers

A role is a named group of devices that share with each other. This code means raw policy input, or an `iris-role import` file, gives two restricted roles an asymmetric relationship: one permits the other but not back. Fix the whole role graph and validate or import it again.
## authentication-required

The request needs a credential, and none was given, or the one given is invalid.
## bad_acl

400: the ACL name given for migration is missing, invalid, or reserved.
## bad_device_id

400: a role membership mapping contains an empty device ID.
## bad_quarantine

Quarantine, applied to a device, tells it to stop sharing with every peer. 400: the quarantine value in the request must be a JSON boolean (`true` or `false`).
## bad_role

A device role change did not give a valid role name or an explicit `null` to clear the role. Use a known, non-reserved role name, or `null` to clear membership, then preview the change again.
## bad_role_mapping

400: the role membership input must be a nonempty mapping from device to role.
## catalog-authentication-required

The catalog operation needs a valid device bearer credential. See [Troubleshoot: symptoms and first steps](user-guide/troubleshooting.md) for how to read the refusal line the server logs for this error.
## confirmation_required

The candidate role or QoS change affects a large number of devices, or changes a QoS value. Preview that exact candidate with `dry_run=1`, then send its `confirm_token` with the same current ETag.
## console-certificate-unavailable

No usable Console certificate is available for the browser to check.
## console-session-required

The browser request needs a valid Console session cookie.
## content-length-required

The request must include a valid `Content-Length` header. This operation does not accept chunked transfer encoding.
## credential-store-unavailable

The credential store could not be read or checked, so the request is refused rather than allowed by default.
## csrf-validation-failed

The browser request changes state but does not carry the session's valid CSRF token.
## device_not_found

The device-role or effective-QoS route names a device that is not in current inventory. Refresh the inventory and use its exact device ID.
## fleet_write_failed

A coordinated role-membership change could not finish writing to inventory. Policy may have already committed a relaxation. Check the `partial`, `applied`, `failed`, revision, and `role_drift` fields, and refresh both stores before you decide whether to retry.
## forbidden

A principal is who a request comes from: a device, the server's seeder, or a legacy device. This code means the authenticated principal is not allowed to do this operation.
## incomparable_role_change

The server cannot safely tell whether the requested role change is a tightening or a relaxation of access. Split the change into separate, individually previewed steps. See [Control which devices share with each other](user-guide/roles.md) for how role changes are classified.
## instruction-device-forbidden

An instruction is the signed message the server sends a device saying which images to stage and how. 403: a valid, current catalog token belongs to a different device than the one in the request path. An invalid, revoked, out-of-date, or unsupported credential instead returns 401 [`catalog-authentication-required`](#catalog-authentication-required). On a 401 or 403 for an instruction, the device agent tries one refresh and reports `instr_forbidden`. If the server has revoked the device, rotating its key does not fix this.
## instruction-keylist-missing

404: no published instruction key list exists yet. Complete the root-signed key list setup; the device agent keeps its last usable evidence and retries at the next check.
## instruction-keylist-unavailable

503: the root-signed key list needed to trust an instruction cannot be read or checked. Fix the problem with who holds the private keys, or with server state, and retry at the next check; the retry hint is 10 seconds. The device keeps using its last usable cached key list until then.
## instruction-rate-limit-exceeded

429: the shared per-device bucket for instruction and key-list requests is empty. It allows a burst of 2 requests and refills one every 10 seconds. Wait for the `Retry-After` hint before the next check; do not add your own retry loop.

For how the device agent behaves after an instruction failure, see [Data formats and states](reference/state-and-data.md). To replace or recover the signing keys, see [Replace or recover signing keys](admin-guide/instruction-keys.md#instruction-root-ceremony-and-recovery).
## instruction-stamp-missing

404: the device has no instruction stamp, or its fixed role file is missing. Check the state of whatever produces the stamp, fix the source, then run `iris-instr-key restamp <device_id>`.
## instruction-state-unavailable

503: the policy stamp, role file, key, or the record of who holds the private keys cannot be safely read or checked. Look at the status of whichever part produced it and repair the source; do not send an empty stamp instead. The retry hint is 10 seconds.
## internal-error

The server hit an internal failure. The response never includes exception text or file paths.
## invalid-authorization-request

The Console container's header-only authorization check found the request malformed.
## invalid-content-length

The `Content-Length` header is not a valid non-negative integer.
## invalid-request

The request syntax or parameters are invalid.
## invalid-request-body

The request body does not match the schema the operation requires.
## invalid-tracker-auth-selector

The catalog torrent request asked for a tracker authentication mode IRIS does not support.
## invalid_policy

A role definition, role graph, network value, or QoS value breaks the fixed policy schema. Fix the named field and validate the whole candidate again.
## invalid_policy_request

A role or QoS route received an unknown query parameter, an unknown body field, a malformed JSON shape, or a value of the wrong type. Send only the fields the route documents.
## invalid_roles_csv

A roles CSV file sent to `POST /api/v1/peer-policy/roles/import-csv` does not follow the required format. The file might have a missing `role` header, an unknown column, a row with no role, a duplicate role, a non-integer QoS cell, or a malformed network value. The `detail` field names the row or field. Nothing is written; fix the file and preview again. A well-formed file can still fail for a policy reason, such as an unknown peer, a reserved name, or an isolated role; those keep their own codes.
## invalid_schedule

A schedule definition, patch, or CSV row failed validation. The schema is fixed and rejects these before anything is written: an unknown field, an unknown verb, a payload that does not match the verb, an out-of-range window, or an unrecognized time zone. Nothing changed.
## management-api-unavailable

The Console container cannot open its authenticated, CA-verified connection to the management API.
## management-authentication-required

The internal operation needs the current management bearer credential, or one still inside its short overlap window after a rotation.
## method-not-allowed

The resource exists but does not support this HTTP method. Check the response's `Allow` header for the methods it does support.
## mixed_role_direction

One bulk role request mixes devices whose change tightens access with devices whose change relaxes it. Split it into two requests, one for each direction, so the writes stay safe.
## observability-authentication-required

The observability operation needs its own, separately scoped bearer credential.
## operation_backlog_full

Peer policy, also called sharing policy, is the rules that say which devices may share pieces with which. The tracker has not confirmed 256 peer-policy operations yet. When the normal preflight check sees this backlog, it refuses the request before writing anything. A write already in flight can still finish with a partial outcome. Check the partial and drift fields, then let the tracker catch up before you retry.
## payload-too-large

The request body, declared or received, is larger than this operation's documented limit.
## policy_error

503: role, QoS, or schedule coordination cannot safely use policy that is out of date. The legacy quarantine check keeps its own 422 response for the same condition. Repair the current policy before you retry; an old cached copy does not authorize new changes.
## policy_fail_closed

503: no trustworthy peer policy is available, so the change is refused. Restore the current policy and check that it is healthy before you retry.
## policy_unavailable

The role or QoS interface cannot use the current policy, or a policy store it needs is unavailable. This can be a refusal before any write happens, or it can follow a successful inventory write whose policy write then failed. Check the partial outcome, revision, and drift fields, then refresh both stores before you retry.
## precondition-failed

An HTTP precondition such as `If-Match` did not match current state.
## precondition_failed

The role or QoS route's compare-and-swap check did not receive exactly the current, strong peer-policy ETag in `If-Match`. A weak, wildcard, duplicate, missing-current, or stale value fails. Read the current policy again and preview your change again.
## precondition_required

The role or QoS change left out the required `If-Match` header carrying the current, strong peer-policy ETag.
## principal_unresolvable

The pair-explanation lookup could not resolve one requested principal to exactly one fresh, unambiguous address. Wait for a fresh announce, or fix shared attribution; this route never guesses an address from inventory.
## range-not-satisfiable

The requested byte range cannot be served.
## rate-limit-exceeded

The caller exceeded an operation's rate limit. Retry only after the duration in `Retry-After`.
## reconciliation_required

This is not an HTTP problem type. It is the `error_category` an IOx onboard, undeploy, or forced undeploy job ends with when an earlier attempt was cut off partway through changing device-global app signature verification. IRIS cannot safely guess the device's state, and no retry clears it, including a forced one.

A verification journal stuck in phase `indeterminate`, and two unresolved journals claiming the same device, are different conditions with different fixes. See [Recover from an interrupted job or damaged state](admin-guide/recovery.md) for both.
## request-body-not-supported

This operation does not accept a request body.
## request-timeout

The client did not finish sending the request within the server's deadline.
## resource-conflict

The request conflicts with the resource's current state, or reuses an idempotency key for a different operation.
## resource-not-found

The authenticated resource does not exist.
## revision_conflict

Another policy writer committed a change after this request passed its first ETag check but before the final, locked revision check. Use the revision and ETag the response returns to reread and preview again; do not resend the old candidate token.
## role_in_use

The requested role still has members, or another role refers to it. The response gives the member count and the referring role names; remove those uses before you delete it.
## role_isolated

A role's peer list left out the role itself. Every role must permit its own members, even when it permits no other role.
## role_management_error

422: the role coordinator rejected the request without a more specific code. Check the response's partial-result fields before you refresh and retry.
## role_not_found

The requested definition, QoS target, or membership role does not exist. Refresh the role list, create the role first if you meant to, and preview again.
## role_reserved_name

The requested role name is reserved by the policy model: `default`, `quarantine`, `origin`, `seeder`, or `legacy`.
## role_shadowed_by_assignment

The device has an explicit stored-ACL assignment that would override its role silently. Use the audited ACL-to-role migration instead of creating a role membership that would have no effect.
## route-not-found

No registered API route matches the request. The server checks authentication before it discloses this.
## schedule_conflict

The schedule could not be changed as asked because it moved under you. The id already exists, the definition changed while the request was in flight, or an occurrence and its evidence no longer match the definition you are writing. Read the schedule again and reapply the same change.
## schedule_not_found

No schedule with that id exists. Occurrence and outcome history stay readable after a definition is deleted, so a history read can still succeed where this does not.
## schedule_state_unavailable

The durable schedule store could not be read, or a write could not be confirmed. A failed write may already be visible elsewhere; this response does not promise a rollback. Fix the storage problem, then reread the definition, ETag, and occurrence evidence before you retry. An unreadable store never authorizes new scheduled work.
## schedule_target_heartbeat_unavailable

The schedule's target filter (`q`, `telemetry`, or `status`) can only be resolved from device heartbeat data, and that data could not be read. IRIS refuses the target rather than resolve it against a partial inventory.
## schedule_target_policy_unavailable

Peer policy is unavailable or out of date, so a role-aware schedule target cannot be resolved. Roles are enforced from that policy, so resolving the target without it would silently ignore role membership.
## schedule_target_status_unavailable

A `status` filter needs live management-job data that is not available here. Use a filter that does not depend on live job state.
## schedule_target_unavailable

503: the service that resolves a schedule's target devices is unavailable. Restore inventory and policy access, then retry the preview. Do not substitute an empty target set.
## service-unavailable

A required service or state store is temporarily unavailable. Retry only after the duration in `Retry-After`.
## stale_pointer

409: the key named in the stamp is no longer current or still valid. Finish or redo the committed key rotation and retry later; the retry hint is 10 seconds. The device agent reports `instr_pending` while it keeps using its last usable policy.
## telemetry-status-unavailable

The authenticated telemetry status view could not be produced.
## unknown_device

422: the legacy quarantine request names a device that is not in inventory.
## unprocessable-content

The body is syntactically valid but violates the operation's semantic rules.
## unsupported-media-type

The operation does not support the request's media type.
## upstream-operation-failed

An authenticated operation could not be completed by its upstream dependency.
