<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Recover from an interrupted job or damaged state

## What this is for

A job that stops partway through, or storage that comes back with the wrong
file permissions, leaves IRIS stuck. Each procedure here clears one state.

## What you see

| Symptom | Likely cause | What to do |
| --- | --- | --- |
| Every job on one IOx device ends in `error` with the category `reconciliation_required` | An attempt was cut off while device-wide app signature verification was turned off | Recovering an IOx attempt cut off mid-run |
| An IOS-XR undeploy stopped partway and the device shows a red `needs-reconcile` badge | The job ended before teardown finished | Recovering an interrupted IOS-XR teardown |
| A Guest Shell job reports `copy_failed`, and a later job says the hash launch was never confirmed | The native hash job's result was lost | Recover an interrupted Guest Shell root-hash job |
| The server refuses to start and reports an unsafe deployment-authority or transcript mode | A volume mount rewrote private file modes | Repair a volume whose file permissions were changed |
| A read of a device store fails, and the file at its old path is not valid JSON | Older code is reading the path the store moved away from | Roll back the per-device state split |

## Recovering an IOx attempt cut off mid-run

This covers Industrial Ethernet 3000 series switches, Catalyst 8000 series
routers, and Catalyst 9000 series switches with app-hosting storage, where the
IOx app replaces the Guest Shell agent. A cut-off onboard or undeploy leaves
the device's IOx verification journal in phase `indeterminate`. Every later job
on that device, Force included, then ends in `error` with result code 3 and the
category `reconciliation_required`. Its job log starts with
`IOx controller: predecessor recovery failed` and names the values to
reconcile.

1. **Read the binding.** Take the record id, transaction id and revision from
   that job-log line, or from `record.iox_verification` in
   `GET /api/v1/devices/<id>/deployment`. Use the journal's current revision;
   an older number is refused as stale.

2. **Restore verification on the device.** In privileged EXEC:

   ```
   show app-hosting infra | include App signature verification
   app-hosting verification enable
   show app-hosting infra | include App signature verification
   ```

   The second read must report `App signature verification: enabled`.
   Verification is device-wide, so check the other IOx applications on the
   device first. See
   [Prepare IE-3x00, Catalyst 9000 and 8000 devices for the IOx app](../install/iox.md#device-global-package-verification).

3. **Reconcile the journal** from inside the server container, as the service
   user:

   ```bash
   docker compose -f server/docker-compose.yml exec -w /opt/iris/server iris \
     python3 iox_verification.py reconcile-enabled \
       --record-id <record-id> --transaction-id <transaction-id> \
       --revision <revision> --acknowledge-external-resolution \
       --wait --wait-timeout 600
   ```

   It reads the device once over SSH and closes the journal when the device
   reports `enabled`. See [Helper commands](../reference/tools.md).

4. **Clear what the attempt left behind.** Run **Undeploy** with **Force** in
   the Console, or `POST /api/v1/devices/<id>/undeploy` with
   `{"force": true}`. Then onboard the device again.

### What the exit status means

| Exit status | Meaning | What to do |
| --- | --- | --- |
| `0` | Resolved. | Go on to step 4. |
| `3` | The job log says `fresh read did not establish enabled`. | Go back to step 2. |
| `2` with `{"error": "request rejected"}` | The binding is stale or mistyped. | Read the binding again. |
| `4` | A wait timeout or a transport failure. | Read the job with `job --job-id <id> --wait` before retrying. |
| `5` | A journal or authority fault. | Read the server log. |

### Job error categories

A job ends with the category `reconciliation_required` when the journal is
`indeterminate`, or when two unresolved journals claim one device. For HTTP
errors, see [API error codes (problem types)](../problems.md).

## Recovering an interrupted IOS-XR teardown

This covers Cisco 8000 series and NCS routers. An interrupted undeploy leaves
the deployment record in `needs-reconcile`, a red badge in the Console. Run
undeploy again from that state, record-backed or with **Force**: each step
re-probes the router, including the appmgr application, before acting.

`IRIS_XR_SESSION_TIMEOUT` bounds every command session to the router, so a
wedged router fails the job with a real exit code; `0` turns the bound off. See
[Server configuration](../reference/server-configuration.md) for the default.

A finished teardown may leave an empty `iris-work/` directory on `harddisk:`,
which a later onboarding reuses.
[Undeploy, retire and clean up devices](../user-guide/undeploy.md) lists what it removes.

## Recover an interrupted Guest Shell root-hash job

This covers Catalyst 9000 series switches, where the agent runs in Guest Shell;
the IOx app is the alternative on switches with app-hosting storage. When an
image of the same name already sits in the IOS root file system, the agent
hashes it in place with a native Embedded Event Manager (EEM) policy,
`IRIS-ROOT-HASH`. A lost result reports `copy_failed` and asks you to look at
the device.

1. Remove the `IRIS-ROOT-HASH` applet from the running configuration.
2. Wait at least 625 seconds for any job already started to finish.
3. Inspect the EEM job history.
4. Remove only `<stage_dir>/.iris-root-hash.json`. The next check-in retries.

!!! warning
    While the agent is running, leave `<stage_dir>/.iris-root-hash.lock`, the
    staged image, the IOS root image and any `BOOT` target in place.

## Repair a volume whose file permissions were changed { #recover-a-volume-whose-private-modes-were-changed }

A storage driver that rewrites permissions on mount widens the private files
holding the deployment authority and the IOx transcripts, and the server
refuses to start. [Install on Kubernetes](../install/kubernetes.md) has the
mount settings that prevent this. Keep the failure evidence, then repair the
storage:

1. Stop new job admission, wait for all onboard, undeploy and scheduled work to
   finish, then stop the server pod and any maintenance pods on the volume.
2. Inspect ownership, modes, inode and link metadata against trusted backup
   evidence, without printing file contents. A change to content or identity
   needs investigation instead.
3. Restore only the verified, explicitly identified paths, each owned by
   `10001:10001`:

   | Path | Mode |
   | --- | --- |
   | `/data/state/deployment_records.json`, its `.lock`, IOx transcript files | `0600` |
   | `/data/state`, `/data/state/iox`, its authority subdirectories | `0700`, setgid cleared |
   | `/data/config/tls/crt.pem`, the public catalog certificate | `0644` |

   Startup rejects group-writable modes such as `0660` or `0664`. Check other
   authority files and instruction roots against their own rules.
4. Verify the volume root is `10001:10001` with mode `2770`, apply the
   `OnRootMismatch` policy to the Deployment, then start the server.
5. Recheck the private modes, then verify management API health and
   deployment-record access before you admit jobs.

!!! warning
    Never use recursive `chmod` or `chown`, never delete authority evidence,
    never weaken the validators, and never change permissions while a job runs.

## Roll back the per-device state split { #rollback-after-the-shard-migration }

The server now keeps one file per device instead of one whole-fleet JSON
document per store. See
[Data formats and states](../reference/state-and-data.md). The original
document keeps a `.migrated` suffix, and an invalid placeholder at its old path
names the original and backup paths.

1. Stop every reader and writer of the selected store.
2. Back up the whole state volume: per-device files, revision metadata,
   placeholders, and `.migrated` files.
3. Restore the retained document at the original path. Code from before the
   split can then read it, but it **does not restore writes made after the
   migration**. If those writes matter, export them with the newer release, or
   restore a consistent backup first.
4. Verify inventory and policy together. An empty store is not a successful
   recovery.

!!! warning
    Do not delete the per-device files, and do not overwrite the only backup.

## Replace the two root keys { #instruction-root-ceremony-and-recovery }

Replacing the two offline keys that sign every instruction key, and recovering
a lost one, are on
[Replace or recover signing keys](instruction-keys.md#instruction-root-ceremony-and-recovery).

A server restart also marks any deployment record for a job that was still
running as `unknown`, not `active` or failed. Do not retry the device
operation blindly: read the record first and reconcile from it, the same way
as for a cut-off IOx attempt above.

## With the API

`GET /api/v1/devices/<id>/deployment` returns the deployment record, with
`record.iox_verification` and the `iox_verification_obligations` summary.
`POST /api/v1/devices/<id>/undeploy` runs a teardown; send `{"force": true}`
for Force. Both are described in [Console API](../reference/console-api.md).

## Related

- [Troubleshoot: symptoms and first steps](../user-guide/troubleshooting.md)
- [Undeploy, retire and clean up devices](../user-guide/undeploy.md)
- [Back up and restore](backups.md)
- [API error codes (problem types)](../problems.md)
