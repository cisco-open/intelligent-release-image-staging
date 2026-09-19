<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Troubleshoot: symptoms and first steps

Start here when something looks wrong. Work the checklist, then find your
symptom in the table for that area.

## Start with the recovery checklist

1. Check that the server and the Console are both running. On Kubernetes, check
   both deployments.
2. Read the server log for catalog, tracker, seeder, storage and secret errors,
   and the Console log for management API errors.
3. Check that the Console reaches the server's management API on HTTPS TCP 9443.
4. From the device network, check the catalog on TCP 8443, the tracker on TCP
   6969, the seeder on TCP 6881, peer traffic on TCP 6881 to 6999, the artifact
   server on TCP 8000, and SSH from the server on TCP 22. See
   [Network ports and flows](../architecture/network-ports.md).
5. Check that the published image is still in its recorded source directory, and
   that the server can read its age key, its state and its artifacts.
6. Read the device's job log, heartbeat and per-image report, then check its
   management type, which is how the agent reaches the network.

!!! warning
    Do not repair state by editing databases, deployment JSON, occurrences or
    receipts by hand. Undeploy a running agent before you onboard it again.

## Time synchronization

A wrong clock reads as a certificate problem.

- A device that fails onboarding with `time preflight failed` needs a
  synchronized external reference. See
  [What a device needs before onboarding](../install/device-requirements.md).
- A container or node inherits its host's clock. Fix the host. See
  [Check the host before you install](../install/check-the-host.md).
- For a certificate error, compare `show clock` on the device with the dates
  from `openssl x509 -noout -dates`.

!!! warning
    Never disable TLS verification to work around a clock problem.

## Server and Console symptoms

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| The Console or a device-facing service does not answer | A container is down, or traffic reaches the wrong listener | Work the checklist above, then confirm the listener in [Network ports and flows](../architecture/network-ports.md). |
| A new server exits again and again, saying its encrypted configuration is missing | The stack started before bootstrap | Finish [Install on one Docker host](../install/one-docker-host.md). Keep the same project name, volumes, age identity and environment files. On a deployment that already ran, see [Recover from an interrupted job or damaged state](../admin-guide/recovery.md). |
| A file shows as `not readable by the server`, a secret fails to decrypt, or the agent bundle download fails | A path is not owned by uid 10001 | Every service runs as uid 10001. Give the age key, the artifacts directory and the state, configuration and uploads volumes that ownership. See [Install on one Docker host](../install/one-docker-host.md). |
| The Console loads but API calls return 503 | The Console cannot reach the server's management endpoint | Check DNS and routing from inside the Console container, the management certificate hostname and CA, and the token files. On Kubernetes, check the NetworkPolicy and the port 9443 endpoints. Then repeat [Verify the installation](../install/verify.md). |
| An audit-export save says exports are disabled | The save did not carry a complete destination and password | Reload **Settings → Audit export**. Re-enter the complete destination and password, then save again; do not leave the password blank. Exports stay disabled until a complete save succeeds. An export already using the previous complete configuration may finish. |
| The browser warns about the Console certificate | The stack still serves its own default browser identity | That identity is stored encrypted as `tls/console-fallback.pem.age` and is reused on restart. Import a certificate that matches the address you browse to. |
| The server starts with an empty inventory | The stack came up with a different project name or different volumes | Check `COMPOSE_PROJECT_NAME` and the mounted state and configuration volumes. |
| Publishing a package fails with `chown: Operation not permitted` | The container drops capabilities | Build readable package files on the host, then publish them with [Build and publish the device packages](../install/device-packages.md). |
| Devices are refused with `catalog-authentication-required` | A device credential is missing, unknown, expired, revoked, from another device, or from before a rotation | Read the server log line `iris-catalog: refused bearer method=… route=… device=… src=… reason=…`. The reason names the case. |

## Onboarding

An instruction is the signed message the server sends a device saying which
images to stage and how. These rows apply to every platform.

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| The device never appears after onboarding | The installer failed, or the device cannot reach the server | Read the job log, then check the artifact server, the catalog trust anchor on the device, and the enrollment token. |
| Onboarding says `time preflight failed` | The device clock is not synchronized | Set your time source outside IRIS. See [What a device needs before onboarding](../install/device-requirements.md). |
| The device SSH host key differs from the saved key | The device was replaced or reimaged, or the session is intercepted | Confirm the device identity, then use **Forget SSH host key** in its Console drawer. |
| A new device reports `ARIA2-AUTH` right after first boot | The transfer client still holds the startup secret | Wait one tick, one pass of the agent's check-in loop. A refused or unreachable transfer client endpoint is a real error. |
| Onboarding reports `instruction bootstrap unavailable` | That server has no signing identity or producer | Run `iris-instructions --status` on that server, then follow [Turn on instruction signing](../install/activate-signing.md#initialise-instruction-custody). |

### Guest Shell

The agent runs in Guest Shell on Catalyst 9000 series switches and Catalyst 8000
series routers. On switches with app-hosting storage, use the IOx app instead.

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| Guest Shell reports `bundle rejected (trust-unreadable)` | The guest user could not read a trust file | IRIS rolls back to the previous bundle. Check guest share ownership and mount permissions, then retry onboarding. |
| Guest Shell stages files but instructions report `verifier_missing` | The device would check the signature but the tool to do so is not installed | Check that the latest bootstrap and an architecture-matched bundle are deployed and that the bundled verifier passed its runtime probe. See [Upgrade to a new release](../admin-guide/upgrade.md). |

### IOx

The IOx app runs on Industrial Ethernet 3000 series switches, Catalyst 8000
series routers, and Catalyst 9000 series switches with app-hosting storage.

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| IOx reports `identity discovery failed` with `connection`, `timeout`, `ssh_authentication` or `host_key` | The app could not open a session to IOS | Check device SSH reachability, the timeout, the assigned credentials or the recorded host key, by category. |
| Placement fails with `ROOTCOPY-FAIL` on a device that has a share | The share is not mounted, is unreadable from IOS, or the copy failed | Read what the share probe found in the message and repair the share. The agent retries placement on a later tick. |
| Onboarding stops with a `PREREQ:` line about `sdflash:` | The SD card was never formatted for IOx | Format the card for IOx, then onboard again. |

### IOS-XR

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| Onboarding fails at `XR HTTPS staging failed` | The router could not fetch or verify the package | Check the router's bash and curl support, the route to the artifact server, the certificate validity and hostname, the enrollment authentication, and free space on `harddisk:`. |
| Onboarding fails while opening repeated SSH sessions | The router is rate limiting SSH sessions | Check `show logging` for `Incoming SSH session rate limit exceeded`. The timing variables are in [Device agent configuration](../reference/device-configuration.md). |
| A root image stays on the router after undeploy or after an image is parked | This is intended | Parking keeps an unassigned image on the device in case it is assigned again. See [Assign images and check staging status](assignments.md#unassigned-image-park). |

!!! warning
    Do not delete a device's instruction state or key files to make it accept
    an older envelope, the encrypted file that carries an instruction. See
    [Device agent configuration](../reference/device-configuration.md).

## Staging and transfers

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| A download never starts | The device cannot announce or reach the seeder | Check the tracker port and its authentication, then the seeder port and the device's route to the server. |
| A download stalls | No peer has the pieces, or the device has no room | Check the swarm view for peer count and seeder availability, then free space on the target disk. |
| Verification fails after the bytes arrive | The staged copy does not match the catalog | Compare the catalog hash, the file name, the staged size and the source image. |
| A transfer stays planned and never reaches seeding | The device reported after you unassigned the image, or the peer announced with a credential that carries no device identity | The plan is cancelled on the next pass. The bytes may have landed; the server never received the proof. Onboard the device again so that it announces with its own credential. |
| An image stops being served and cannot be assigned | It is quarantined: it failed the Cisco hash check and is held back from devices | A mismatch against Bulk Hash, the checksum Cisco publishes for an image, stops seeding and unassigns the image everywhere. Release the quarantine to resume seeding. See [Publish and verify images](images.md). |

## Roles and sharing

A peer policy says which devices may share pieces with which. A role is a named
group of devices that share with each other.

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| No device is offered any peer | A policy file is present and none is valid, so the tracker fails closed | Repair the policy store first. Preserve the current files, the fleet state and the tracker and seeder status. See [The security model](../architecture/security-model.md). |
| Every device can share with every other after a state loss | Both policy files are missing, which is the open case | Rebuild your roles, assignments and overrides. See [Control which devices share with each other](roles.md). |
| The server's own seeder is denied while the tracker fails closed | `IRIS_HOST_IP` is not the address the seeder announces from | Set `IRIS_HOST_IP` to that address. |
| A devices CSV import reports `role_not_found` | The named role does not exist yet | Define the role in Policies first, or import without role assignments. After a network error, refresh inventory first, because the import may already have completed. |

## Scheduled work

A scheduled outcome is the record of what a scheduled run did on one device.

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| A scheduled receipt says `conflict` or `identity_unavailable` | The device that was scheduled is not the device that is registered now | Compare the occurrence `target_snapshot.registration_ids`, the recorded `fleet_registration_id` and the current fleet registration, then schedule new work. |

## Telemetry and dashboards

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| Every panel is empty | Nothing is exporting | Check that the server's telemetry listener answers, then read the Console's telemetry export badge. See [Export telemetry](telemetry-export.md). |
| No data reaches the collector | `IRIS_OTLP_ENDPOINT` includes a `/v1/...` path, or OTLP export is off | The endpoint is a host and port, so drop that suffix. Turn on OTLP in **Settings → Telemetry**, or set `IRIS_OBSERVABILITY=1` and recreate the server container. |
| The collector returns 401, or a scrape returns 404 | The token does not match, or telemetry is off | The bearer token must match the collector token file, with no duplicated `Bearer` prefix. A scrape has its own token. Set `IRIS_OBSERVABILITY` and recreate the server container. |

More symptoms are in [Send telemetry to Splunk](splunk.md#troubleshooting).

## Preserve evidence before retrying

Record the device id, registration identity, image id, occurrence id, receipt
revision, job id and dashboard time bounds that apply, and keep the original
outcome and the job log. For a scheduled device, keep the inventory name and the
durable registration identity apart. See
[Schedule maintenance windows](scheduling.md#scheduled-outcomes).

## Report a problem

Collect this before you file:

- the platform, the device software version and the boot mode
- the server host operating system and the Docker version
- the image id, the device's agent report and the relevant Console audit lines
- whether the Guest Shell, IOx or IOS-XR appmgr path is in use, and the
  identifiers under [Preserve evidence before retrying](#preserve-evidence-before-retrying)

File the report at
<https://github.com/cisco-open/intelligent-release-image-staging/issues>.
**Report a vulnerability** through
<https://github.com/cisco-open/intelligent-release-image-staging/blob/main/SECURITY.md>,
not in a public issue.

## Related

- [Recover from an interrupted job or damaged state](../admin-guide/recovery.md)
- [API error codes (problem types)](../problems.md)
