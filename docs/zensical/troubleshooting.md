<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Troubleshooting

## Time synchronization

**Onboarding says “time preflight failed”:** run `show ntp status` and
`show ntp associations` on the switch or router. Require a synchronized external
reference (stratum 1–15), not merely an `ntp server` line. Configure your approved
time source outside IRIS and wait for synchronization before retrying. Check
the selected VRF, source interface, return route and UDP/123 access when the
association has reach 0. On IOS-XR, the NTP server association can specify its
source interface and VRF; do not change unrelated routing to make the check pass.

A selected peer with replies is not yet a synchronized clock. If status still
says `unsynchronized` while measuring drift (`FREQ`), let it settle and recheck;
do not reset NTP repeatedly or bypass preflight.

If devices cannot reach the approved upstream server, an operator-approved
host NTP relay is an option—not an IRIS feature. Synchronize that host to the
upstream, allow UDP/123 only from the intended clients, and verify both hops.
Do not configure a local/orphan clock to make an unsynchronized relay appear
healthy. Keep relay addresses and service configuration outside IRIS templates.

**Docker/Kubernetes clock or TLS errors:** containers inherit the host/node clock.
Run `bash tools/check-host-time.sh` on each relevant host, plus
`timedatectl timesync-status` (systemd-timesyncd) or `chronyc tracking` and
`chronyc sources -v` (chrony). `NTP=yes`, a running daemon, and equal container/
host timestamps alone do not prove synchronization. Fix the host, not the pod;
no privileged container or `SYS_TIME` capability is needed. Repeat on every
eligible node and alert on loss of synchronization.

Reference: Linux [time namespaces](https://www.man7.org/linux/man-pages/man7/time_namespaces.7.html)
do not virtualize the wall clock. Cisco's
[IOS-XR NTP commands](https://www.cisco.com/c/en/us/td/docs/iosxr/cisco8000/system-management/b-timing-and-synchronization/m-ntp-commands.html)
describe per-server source/VRF selection.

For certificate import or “not yet valid” errors, also compare `show clock`
with the public certificate's `openssl x509 -noout -dates` output. Synchronized
time does not repair an expired or wrongly issued certificate. Never disable
TLS verification to work around a clock problem.

Start with the [recovery checklist](operations.md#recovery-checklist). Confirm
service health, network direction, the recorded artifact, and durable job or
schedule evidence before retrying. Do not repair state by editing databases,
deployment JSON, occurrences, or receipts by hand.

| Symptom | Action |
| --- | --- |
| Console or device service is unavailable | Follow the [recovery checklist](operations.md#recovery-checklist), then verify the exact direction and listener in [Network ports and flows](network-ports.md). |
| Console loads but authenticated API calls return 503 | Wait for server readiness, then check Console-to-server DNS/routing, management certificate hostname/CA and matching scoped tokens. In Kubernetes, check port 9443 NetworkPolicy and Service endpoints. Do not disable TLS verification. Run the [API smoke check](api-testing.md#repeat-the-smoke-test-across-layouts) after recovery. |
| API calls return 401 after a server restart | Sign in again. Browser sessions are held in server memory and do not survive its restart; this does not mean inventory or encrypted configuration was lost. |
| A Settings save reports that the response is unavailable | The server may have committed the change before the connection failed. Reload and read the current setting (or `GET /api/v1/settings`) before retrying; do not assume rollback. If the write changed Console TLS, verify the new certificate through a trusted channel. |
| Cisco CA downloads appear as Custom, or daily refresh rejects the Cisco preset | Update the Console image. The Cisco preset uses the server's default bundle URL and supports daily refresh; only Custom requires an explicit HTTPS URL. |
| A strict API client rejects the single-host default certificate | The default browser identity is persisted as encrypted `tls/console-fallback.pem.age` and reused on restart. Upgrading from an older, ephemeral default creates a new identity once; verify and provision its public certificate through a trusted channel. Address changes need a matching operator certificate in Settings. Never disable TLS verification. |
| API test reports partial cleanup or leftover fixtures | Preserve the JSON report. Reconcile only its exact `owned_device_ids` and run-named role, credential and paused schedule; do not clear the fleet. HTTP 207 is a partial result, not success. Resolve the reported failed component before retrying cleanup. |
| A scheduled receipt says `conflict` | Compare occurrence `target_snapshot.registration_ids`, receipt `fleet_registration_id`, and the current fleet registration. Manual changes and replacement registrations win; verify the intended current device and schedule new work. |
| A scheduled receipt says `identity_unavailable` | Fresh work could not prove the claimed target's durable identity. Recover prepared work only when its receipt records `fleet_registration_id`; otherwise verify the current registration and schedule new work. |
| A device name was deleted and added again | Treat the new row as a replacement identity. Do not redirect or replay an old occurrence against it. |
| IOS-XR leaves a root image after undeploy or parking | Undeploy intentionally leaves root images. Parking deletes only when every historical record naming the same file proves downloaded ownership; any adopted or unknown claim protects it. See [Unassigned image park](device-agents.md#unassigned-image-park). |
| Imported Splunk panels are empty but pasted SPL returns rows | Inspect the resolved browser job. `search search index=...` identifies an extra generating `search` prefix in standalone Simple XML. Re-import the corrected shipped view. |
| **Received data by source** is below captured bytes | Keep `iris.transfer.bytes_unattributed_omitted` in a separate **Untraced capped rows** bucket. Do not redistribute capped bytes among origin, peer-device, or unknown rows. |
| Peer share says **No data** | No capture exists in the selected bounds, so the ratio is unavailable. |
| Peer share says **0%** | Captures exist but contain no measured peer bytes; origin-only and unknown-only captures are measured zero. If `capture_complete=false`, totals are a floor and the partial ratio has unknown bias. |
| A cumulative ledger tile changes with the time picker | It shows the latest sample inside the selected window, not a delta. A window with no sample is unavailable; **Seeder RPC** uses a fixed 15-minute window. |
| An API request returns Problem Details | Match `type` or `code` in the [Problem type registry](problems.md). Schedule receipt reasons are durable outcomes, not HTTP problem types. |
| Set role, bulk role, or devices CSV import is refused with `incomparable_role_change` or `mixed_role_direction` | Moves between two roles whose permitted sets do not nest must be previewed and applied as separate steps, and one bulk must be all tightening or all relaxing. A device policy places in no role can always enter a restricted role and be cleared back. |
| Devices CSV import reports `role_not_found` | Define the named role in Policies first, or omit role assignments and apply them separately. The import result remains visible across inventory polls; selecting the same file again retries explicitly. After a network or unreadable-response error, refresh inventory before retrying because the import may already have completed. |
| Guest Shell reports `bundle rejected (trust-unreadable)` | The guest user could not read a trust file after bundle promotion. IRIS rolls back before starting the new agent; the prior bundle remains in use if rollback succeeds. Check guest-share ownership and mount permissions, then retry onboarding. Do not make trust files world-writable. This guard does not repair an already-broken installation or add SSH signature-verifier support. |
| Guest Shell stages files but instructions report `verifier_missing` | Its installed `ssh-keygen` may lack SSHSIG verification. File staging and signed-policy application are separate checks. Use a supported IOx deployment when available, or retain the documented tracker-only limitation; retrying onboarding does not add a verifier. See [Device agents](device-agents.md). |
| Onboarding reports `instruction bootstrap unavailable` on an otherwise healthy server | Run `iris-instructions --status` on that deployment's server and check its configured signing identity and producer. Public roots alone are insufficient, and a retained Kubernetes PVC may have different custody from Docker. Follow [Initialise instruction custody](aiagent.md#initialise-instruction-custody); never create replacement roots to bypass this check. |
| Publishing a package fails with `chown: Operation not permitted` | The hardened container drops capabilities even for uid 0. Build readable package files on the host, then use the [package publishing procedure](aiagent.md#publish-to-either-docker-layout). Do not grant the running server extra capabilities or widen secret permissions. |
| IOx reports its clock is outside the artifact certificate's validity period, or IOS reports `Error in saving certificate` | Compare `show clock detail` with the catalog certificate's validity dates. An unsynchronized clock can reject a newly issued certificate even with the correct year. The IOx controller checks recognized UTC/GMT clocks before replacing the IRIS trustpoint. Synchronize using an approved time source; for a certificate not yet valid, retry once the device clock enters its validity period. Renew an expired certificate. Never disable certificate validation. |
| IOx reports `identity discovery failed (connection/timeout/ssh_authentication/host_key)` | Check device SSH reachability, timeout, assigned credentials, or the recorded host key according to the category. The category is a sanitized failure class, not raw device output. Do not disable host-key checking or force undeploy to bypass an authentication/transport failure. |
| IOS-XR onboarding fails at `XR HTTPS staging failed` | Check XR-host bash/curl availability, the route to the artifact HTTPS origin (normally TCP 8000), the certificate's validity and hostname, enrollment authentication, and `harddisk:` space. The installer refuses incomplete or hash-mismatched downloads and never falls back to SCP. Raw session output is withheld because it may contain credentials. An older `upload failed` message indicates the previous SCP installer. Force undeploy does not fix transport or trust failures. |
| `/swagger/` or `/openapi.yaml` returns 404 | Use the browser-facing Console HTTPS port, normally 8080, not management port 9443 or a device-facing listener. Keep the leading slash and use exact `/swagger/` or `/openapi.yaml`, not a path below `/api/v1`. If the path is still absent, the Console container is running an older image; rebuild or pull the current release and recreate that container. |
| Swagger loads without styles or scripts | Preserve the `/swagger/` prefix through any reverse proxy and check the browser network log for local `/swagger/...` asset 404s. The shipped page makes no CDN or other Internet request. |
| Swagger shows no **Try it out** or authorization control | This is expected. The bundled reference is public, static, and read-only; use the Console or an authenticated API client to send requests. |
| The browser reports a certificate error for Swagger | The reference uses the same HTTPS listener and certificate as the Console. Fix the Console certificate trust or hostname; Swagger has no separate TLS configuration. |
| The Help popover shows an older version than `VERSION` | `IRIS_VERSION` is a build argument that overrides the image's `VERSION` file. Remove it from `server/.env` and the build shell, then rebuild both images; compare `docker exec iris sh -c 'echo $IRIS_VERSION'` with `docker exec iris cat /opt/iris/VERSION`. |

## Preserve evidence before retrying

For XR SSH resets, also check `show logging` for
`Incoming SSH session rate limit exceeded`. Free VTY lines do not rule out
connection rate limiting. The installer spaces connections with
`XR_SSH_CONNECT_DELAY` (default 2 seconds, configurable from 0 to 60), and
retries registration transport failures using `XR_SCP_ATTEMPTS` and
`XR_SCP_RETRY_SECONDS`. It checks the source table before repeating an
interrupted registration and includes the SSH error in the job log. Package
registration and its confirming query share a session. A package rejection
with a successful transport is reported for diagnosis rather than retried
as a connection failure.

Record the affected device id, registration identity, image id, occurrence id,
receipt revision, job id, and selected dashboard time bounds as applicable. Keep
the original outcome and job log. A retry cannot explain what the first attempt
observed if those identifiers or bounds are lost.

For a scheduled device, distinguish the inventory name from its durable
registration identity. Deleting and re-adding the same name does not restore the
old identity. See [Scheduled outcomes](operations.md#scheduled-outcomes).

For telemetry, keep capture time and completeness with byte totals. Exact bytes
in retained rows do not make a capped capture complete, and absence of captures
is not a measured zero. See [Telemetry export known limits](telemetry-export.md#known-limits)
and [Splunk troubleshooting](splunk.md#troubleshooting).

## Escalate with the canonical record

Open **Help → Local API reference (Swagger)** in the Console, or use the
[published API reference](swagger/index.html), to find an operation and its raw
contract definition. The local canonical document is `/openapi.yaml`. Swagger
does not accept credentials or execute documented operations; use the Console or an
authenticated API client for execution.
