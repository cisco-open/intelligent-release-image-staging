<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Problem type registry

IRIS JSON API errors use [RFC 9457 Problem Details](https://www.rfc-editor.org/rfc/rfc9457.html).
The `type` URI ends with one of the fragments below, and the same stable value
appears in the `code` extension. Clients should branch on `type` or `code`, not
on the human-readable `title` or `detail`. A response can omit `detail`; when it
is present, it is deliberately redacted.

The BitTorrent tracker is the one protocol-format exception: its errors remain
BEP-compatible bencoded failure dictionaries. Anonymous `/healthz` and
`/readyz` probes disclose only an `ok` boolean.

## asymmetric_peers

Raw policy or `iris-role import` input contains an asymmetric relationship
between two restricted roles. Correct the whole graph and validate/import
again. The public role PUT owns lifecycle normalization and updates reciprocal
edges atomically, so this code is not part of that route's live refusal set.

## bad_role

A device role mutation did not supply a valid role string or explicit `null`
clear. Use a known non-reserved role name, or `null` to clear membership, and
preview again.

## authentication-required

The operation requires a credential that was absent or invalid.

## artifact-authentication-required

The artifact operation requires valid HTTP Basic device credentials.

## artifact-forbidden

Access to the requested staging artifact is forbidden.

## artifact-not-found

The requested staging artifact does not exist.

## artifact-request-failed

The artifact server could not complete an otherwise valid request.

## artifact-resource-forbidden

The device credential is not bound to the requested artifact resource.

## catalog-authentication-required

The catalog operation requires a valid device bearer credential.

## console-certificate-unavailable

No usable browser-facing Console certificate is available.

## console-session-required

The browser operation requires a valid Console session cookie.

## confirmation_required

The role or QoS candidate changes at least one blast-radius count or QoS value.
Preview that exact candidate with `dry_run=1`, then send its `confirm_token`
with the same current ETag.

## content-length-required

The request must provide a valid `Content-Length` and cannot use chunked
transfer encoding for this operation.

## credential-store-unavailable

The credential store could not be read or validated, so access failed closed.

## csrf-validation-failed

The state-changing browser request lacks the session's valid CSRF value.

## device_not_found

The device-role or effective-QoS route names no current Fleet device. Refresh
the inventory and use its exact device ID.

## forbidden

The authenticated principal is not allowed to perform the operation.

## instruction-keylist-unavailable

503: the root-signed keylist cannot be read or validated. Repair server custody
or state and retry on a later tick; the bounded retry hint is 10 seconds.
Usable cached keylist/LKG evidence is retained.

## instruction-keylist-missing

404: no published instruction keylist exists. Complete the root-signed keylist
procedure; the agent retains usable prior evidence and retries on a later tick.

## instruction-state-unavailable

503: policy stamp, role artifact, key or custody state cannot be safely read or
validated. Inspect producer/custody status; repair the source rather than
fabricating an empty stamp. The bounded retry hint is 10 seconds.

## instruction-stamp-missing

404: the device has no instruction stamp or its immutable role artifact is
missing. Check admission/producer state and use `iris-instr-key restamp
<device_id>` after fixing the source. Current `instr_stamp_missing` inventory
counts are separate from cumulative route failures.

## stale_pointer

409: the stamped key no longer resolves to a current or still-valid prior
instruction key. Finish/restamp the committed rotation and retry later; the
bounded retry hint is 10 seconds. The agent reports `instr_pending` while
retaining usable LKG/defaults.

## instruction-device-forbidden

403: a valid current catalog token belongs to a different device than the path.
Invalid/revoked, non-current or unsupported credentials instead return 401
`catalog-authentication-required`. For instruction 401/403 the agent attempts
one-shot refresh and reports `instr_forbidden`; durable revocation is
server-observed and cannot be healed by key rotation.

## instruction-rate-limit-exceeded

429: the shared per-device instruction/keylist request bucket is exhausted.
It permits a burst of 2 and refills one request every 10 seconds. Honor the
bounded `Retry-After` hint on a later tick; never add an in-tick sleep/retry loop.

These fetch failures affect the instruction step only; heartbeat/staging
continue with verified fallback/defaults when policy apply succeeds. An aria2
RPC apply failure still sends heartbeat but skips staging for that tick. Shared `catalog-authentication-required`
and `credential-store-unavailable` failures still apply. Bad MAC, audience,
rollback, signer and size failures are local agent states, listed with actions
in the [failure table](device-agents.md#instruction-failures-and-recovery).
Missing/invalid evidence stays unknown: **violation = 0 does not mean compliant**.
For custody renewal, refusal and degraded-root alarms, use the
[root runbook](operations.md#instruction-root-ceremony-and-recovery).

## fleet_write_failed

A coordinated membership change could not finish its Fleet write. Policy may
already have committed on a relaxation. Inspect `partial`, `applied`, `failed`,
revision, and `role_drift`; refresh both stores before reviewing a retry.

## internal-error

The server encountered an internal failure. Details never expose exception or
filesystem text.

## incomparable_role_change

The server cannot classify the requested membership move safely as one
tightening or relaxation. Split the change into separately previewed steps.

## invalid-authorization-request

The Console tier's header-only authorization preflight was malformed.

## invalid-content-length

The supplied `Content-Length` is not a valid non-negative integer.

## invalid_policy

A role definition, role graph, network, or QoS value violates the closed policy
schema. Correct the named field and validate the complete candidate again.

## invalid_policy_request

A role/QoS route received an unknown query key, unknown body field, malformed
JSON shape, or a value of the wrong request type. Send only the documented
route fields.

## invalid-request

The request syntax or parameters are invalid.

## invalid-request-body

The request body cannot be decoded as the schema required by the operation.

## invalid-tracker-auth-selector

The catalog torrent request selected an unsupported tracker authentication
mode.

## management-api-unavailable

The Console tier cannot establish its authenticated, CA-verified management
API hop.

## management-authentication-required

The internal operation requires the current or bounded-overlap management
bearer credential.

## method-not-allowed

The resource exists but does not support the requested HTTP method. Consult
the response's `Allow` header.

## mixed_role_direction

One bulk role request combines devices whose changes tighten policy with
devices whose changes relax it. Split them into directionally consistent bulk
requests so the two-store write order remains safe.

## observability-authentication-required

The observability operation requires its independently scoped bearer
credential.

## operation_backlog_full

The tracker has not acknowledged 256 peer-policy operations. A backlog observed
during normal preflight refuses before durable mutation; a Fleet-first writer
racing after that check can still report a partial outcome. Inspect partial and
drift fields, then repair tracker reconciliation before retrying.

## payload-too-large

The declared or received request body exceeds that operation's documented
limit.

## policy_unavailable

The role/QoS interface cannot use authoritative policy or a required policy
store. This can be a pre-write degraded/fail-closed refusal, or it can wrap a
Fleet-first `policy_write_failed` after Fleet changed. Inspect partial outcome,
revision, and drift fields, then refresh both stores before retrying.

## precondition-failed

An HTTP precondition such as `If-Match` did not match current state.

## precondition_failed

The role/QoS route's header-time CAS check did not receive exactly the current
strong peer-policy ETag. Weak, wildcard, duplicate, missing-current, and stale
values fail. Reread and preview again.

## precondition_required

The role or QoS mutation omitted the current strong peer-policy `If-Match`.

## principal_unresolvable

Pair explanation could not resolve one requested typed principal to exactly one
fresh, unambiguous endpoint address. Wait for a fresh announce or repair shared
attribution; the route never guesses from the inventory address.

## range-not-satisfiable

The requested byte range cannot be served.

## rate-limit-exceeded

The caller exceeded an operation's rate limit. Retry only after the duration
in `Retry-After`.

## request-body-not-supported

This operation does not accept a request body.

## request-timeout

The client did not complete the request within the server's bounded deadline.

## resource-conflict

The request conflicts with current resource state or reuses an idempotency key
for a different operation.

## resource-not-found

The authenticated resource does not exist.

## revision_conflict

Another policy writer committed after the request passed its initial ETag check
but before the under-lock revision check. Use the returned revision/ETag to
reread and preview; do not replay the old candidate token.

## role_in_use

The requested role still has members or is referenced by another role. The
response gives the member count and referring role names; remove those uses
before deleting it.

## role_isolated

A role's peer list omitted the role itself. Every role must permit its own
members, even when it permits no other role.

## role_not_found

The requested definition, QoS target, or membership role does not exist.
Refresh the role list, create the definition first if intended, and preview
again.

## role_reserved_name

The requested role name is reserved by the policy model: `default`,
`quarantine`, `origin`, `seeder`, or `legacy`.

## role_shadowed_by_assignment

The device has an explicit stored-ACL assignment that would shadow its role.
Use the audited ACL-to-role migration workflow instead of creating inert
membership accidentally.

## route-not-found

No registered API route matches the request. Authentication is checked before
this distinction is disclosed.

## service-unavailable

A required service or state store is temporarily unavailable. Retry only after
the duration in `Retry-After`.

## telemetry-status-unavailable

The authenticated telemetry status projection could not be produced.

## unprocessable-content

The body is syntactically valid but violates the operation's semantic rules.

## unsupported-media-type

The operation does not support the request's media type.

## upstream-operation-failed

An authenticated operation could not be completed by its upstream dependency.
