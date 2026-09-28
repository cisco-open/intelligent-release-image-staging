<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Rotate browser and telemetry credentials in the Console

Open **Settings > Certificates & keys** as the owner. These controls replace
the browser certificate, metrics scraping token and outbound collector
authentication. Private material stays in encrypted server configuration and
its private runtime copy. Deployment-mounted credential files remain unchanged.

## Replace the browser certificate

1. In **Browser certificate**, enter every exact DNS name and IP address used
   to reach the Console. Separate names with commas; do not enter URLs or
   wildcards.
2. Choose **Request approval from my CA** and select **Create replacement
   request**. Download the public request and submit it to your certificate
   authority. The private key never leaves IRIS through this workflow.
3. Import the approved public PEM chain, leaf certificate first. Select
   **Validate approval**. The certificate must match the generated key and
   exact requested names, allow TLS server authentication, and be valid now
   with more than seven days remaining.
4. Review the replacement fingerprint and ensure browser clients trust its
   issuing authority. Select **Apply approved certificate** and confirm.
5. Open a new trusted browser connection. Verify the served certificate and
   application access, not just the published state.

For an explicitly self-signed replacement, select **Create a self-signed
certificate (90 days)** in step 2. Download and approve trust in the public
certificate before applying it. IRIS does not change browser trust for you.

This changes the browser override only, not management TLS, device-pinned TLS,
or peer trust. The authenticated Console reloads its own listener. With several
Console instances, visit each one and select **Retry Console certificate
reload**, then verify a new connection to each instance.

### Recover or cancel

**Cancel replacement** discards a request before publication starts; it does
not change the active certificate. If another administrator changed the active
files, cancel the uncommitted request and prepare a new one.

After interrupted publication, select **Recover approved publication**. IRIS
repairs only files that still match the original or approved replacement; it
refuses unrelated file changes. Recovery completes the previously approved
bytes, even if time has since expired that certificate. Renew an expired
certificate afterward: recovery does not extend validity.

A server restart during publication can temporarily fall back to the deployment
browser certificate if the override pair is incomplete. Preserve trust in that
deployment identity until the replacement is verified. Do not delete the
rotation journal to bypass a conflict.

If publication succeeded but Console reload was not confirmed, use **Retry
Console certificate reload**. This retries delivery without generating another
key. **Settings > TLS & trust** still supports importing an existing key/pair
or returning to the deployment default; these actions are blocked while an
admitted publication needs recovery.

## Replace the metrics scraping token

1. Under **Service credentials**, choose **Metrics scraping token**.
2. Select **Generate token in this browser**, or enter a replacement token.
   Select **Download private token file** and protect it as a credential.
   Status responses do not return the token later.
3. Select **Apply replacement credential**. IRIS accepts the replacement and
   retains the previous token during migration.
4. Update every scraper's credentials using its own administration interface.
   After a successful scrape with the replacement, select **Refresh evidence**.
5. Confirm all scrapers have migrated, then select **Finish verified rotation**.
   IRIS stops accepting the previous token. Verify scrapes continue.

Evidence proves at least one successful authenticated scrape, not that every
scraper has migrated. Retirement therefore also requires your confirmation.
Before finishing, **Restore previous setting** rolls back a pending transition.
The first rollback returns control to the unchanged deployment-mounted files;
later rollbacks restore the preceding Console-managed value.

An existing distinct deployment-managed previous token must be retired before
adopting Console management. See the [mounted-file procedure](rotations.md#rotate-the-metrics-scrape-token).

## Replace outbound collector authentication

1. Create the replacement credential in your collector's administration
   interface, keeping the previous credential valid during migration.
2. Under **Service credentials**, choose **Outbound collector authentication**.
3. Enter the exact HTTPS collector base URL already configured for telemetry.
   Add its authentication header names and values, then select **Apply
   replacement credential**. This does not change the export destination.
4. After a successful authenticated delivery, select **Refresh evidence**.
   If delivery fails, inspect collector access and trust; **Restore previous
   setting** is available while the transition is pending.
5. Verify all senders using the old credential have migrated. Revoke the old
   credential in the collector's administration interface, then select
   **Finish verified rotation** and confirm.

IRIS cannot revoke credentials at an external collector. Finishing removes its
saved previous Console value; it does not attest to remote revocation. Deployment
files remain untouched and should not be mistaken for an active override.

Credentials are bound to the exact HTTPS base URL. Changing the telemetry
destination while an override targets another URL stops export rather than
forwarding those credentials elsewhere. Finish or revert the pending transition
before preparing replacement credentials for a different destination.

## Scheduling and deployment boundaries

Schedules for these families still create review reminders. Approval, consumer
updates and retirement use the controls above; they are not unattended rotations.
See [Schedule key maintenance](key-maintenance.md).

These workflows use server-owned encrypted configuration and the authenticated
Console connection. They do not modify host bind mounts or Kubernetes Secrets.
For management and device TLS, peer issuing CA, offline signing roots, service
encryption identity and seeder credentials, use
[deployment maintenance](deployment-rotation.md). That host-worker workflow has
a narrower deployment boundary and requires verified recovery access.
Do not treat a review acknowledgment as evidence that credentials changed.
