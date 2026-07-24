<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Operations

This page collects the actions operators perform after the first deployment.

## Daily commands

| Task | Command |
| --- | --- |
| Start server | `docker compose -f server/docker-compose.yml up -d --build` |
| View logs | `docker logs iris` |
| Publish image | `docker compose -f server/docker-compose.yml exec iris iris-publish /opt/images/<path>/<image>.bin` |
| Show images and assignments | `docker compose -f server/docker-compose.yml exec iris iris-assign` |
| Apply assignments | `tools/apply-assignments.sh fleet/assignments.csv` |
| Create or reset admin | `docker compose -f server/docker-compose.yml exec iris iris-gui-admin admin` |

For Kubernetes, the equivalent process and logs are available through the
single deployment:

```bash
kubectl -n iris exec deployment/iris-seed-server -- iris-assign
kubectl -n iris logs deployment/iris-seed-server -c iris
```

## Backups

Back up the Docker volumes that hold `/var/lib/iris` and `/etc/iris`, plus the offline age recipient material required to decrypt secrets. Keep image binaries and generated artifacts in their normal external storage path.

For Kubernetes, snapshot the `iris-data` PVC and back up the age identity stored
outside that PVC. Both are required for recovery.

## Scaling notes

Private BitTorrent reduces server load by letting devices exchange pieces after the seeder introduces the content. The server remains important for tracker announces, catalog policy, initial seeding, and telemetry. Watch the seeder data port, tracker health, and device storage pressure during large fleet waves.

## Cleanup

Use `device/device-uninstall.sh` or the IOx uninstall path for device cleanup. Cleanup removes IRIS-owned EEM applets, Guest Shell or IOx agent wiring, trustpoint binding, and staged agent artifacts. It still does not reload the device.

Undeploy is driven by the device's applied **receipt**, not its editable
inventory row, so a later inventory edit cannot retarget cleanup. An
**inband** device's teardown removes only the app footprint and preserves the
operator-owned VLAN/SVI/routes/VRF. A device deployed before receipts existed
has no active receipt and must be **adopted** (an explicit, audited, no-change
recording of ownership) before it can be undeployed; a missing, drifted, or
uncertain receipt stops cleanup in `needs-reconcile` rather than guessing. See
[Network Attachment and VLAN Ownership](network-attachment.md).

## Recovery checklist

1. Confirm `docker ps` shows the `iris` container.
2. Check `docker logs iris` for catalog, tracker, seeder, or secretfs errors.
3. Confirm the device can reach ports 8443, 8000, 6969, and 6881.
4. Confirm the published image exists under `/opt/images` on the server host.
5. Check the console audit and latest device report.
6. Re-run the generated installer only after confirming the device inventory row is still correct.
