<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Verify the installation

Check that your server works before the first device reaches it.

## Before you start

- Finish the deployment page for your layout:
  [Install on one Docker host](one-docker-host.md),
  [Install on separate Docker hosts](separate-docker-hosts.md), or
  [Install on Kubernetes](kubernetes.md).
- Create the Console administrator and sign in once:
  [Sign in for the first time](first-sign-in.md).
- Publish the device packages if you onboard IOx or IOS-XR devices:
  [Build and publish the device packages](device-packages.md).

!!! warning

    One server owns one set of state files. Two servers on the same state, or
    more than one server replica on Kubernetes, corrupt it.

## Check the deployment for your layout

Read the column for the layout you deployed and confirm every row. The
"Devices and signing" row checks the state
[Turn on instruction signing](activate-signing.md) sets up.

| Check | Docker on one host | Docker on separate hosts | Kubernetes |
| --- | --- | --- | --- |
| Services | Both services are healthy in the same Compose project. | Server and Console are healthy in their own projects. | Both Deployments finish their rollout and their readiness probes pass. |
| Management route | The Console reaches `https://iris:9443` on the Docker network. No host port publishes 9443. | The Console reaches the private HTTPS endpoint, with hostname and CA verification and matching token files. | The Console reaches management HTTPS 9443 on the internal Service, and the NetworkPolicy allows that only from Console pods. |
| Browser and API | Login, inventory, Settings, image import and upload, and job logs work through the published Console URL. | The same operations work through the Console host's URL. | The same operations work through the Console load balancer address. |
| Addresses and certificate | Settings shows the intended server IP, Console URL, and the certificate served to the browser. | Settings separates the device-facing server address from the Console URL, and reports the Console's own browser certificate. | Settings reports the server IP and the Console URL, which can differ. The Console certificate is separate from the server's management certificate. |
| Server restart | The running Console stays ready and API requests recover when the server returns. | The Console starts on its local identity while the server is stopped, then recovers API access. | The Console starts while the server pod is down, requests get a 503 with `Retry-After`, and API access recovers after the rollout. |
| Storage | Only the server mounts state, images, artifacts, and encrypted configuration. | The Console host holds only its scoped credential, public management trust, and default browser identity. | Only the server pod mounts the data volume. |
| Devices and signing | Device HTTPS 8443 serves instructions and the list of trusted signing keys, and 9443 carries management traffic only. The signing status shows a current stamp. One device applies a policy, keeps the last policy it accepted while the catalog is unreachable, and reasserts its traffic rules after drift. | The same checks. | The same checks. |
| Layout specifics | Every device package matches its recorded artifact provenance. | The instruction state, the age identity, and the encrypted signing key exist only on the server host. | `replicas: 1`, the existing persistent volume claim (PVC) `iris-data` at `/data`, the runtime directory in memory, and no new Secret, port, Service or NetworkPolicy rule. |

## Run one read-only API check

`tools/api-exercise.py` signs in to the Console API and sends read-only
requests. Run it once per layout, against that layout's Console address.

```bash
python3 tools/api-exercise.py \
  --base "https://<console-url>" \
  --cafile "<path to the Console CA file>" \
  --password-file "<path to the admin password file>" \
  --output "<path to the report file>"
```

The run writes the report file. The check passes when the report's `errors`
list is empty. Keep the password in a file. Never disable TLS verification. For
every flag and the mutation-mode example, see
[api-exercise.md](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/docs/dev/api-exercise.md).

## Verify

| Check | Expected result |
| --- | --- |
| The runtime user owns the host paths | The age identity, the host `artifacts/` directory, and the named volumes give uid `10001` access. The Console Images screen lists no file as `not readable by the server`. For a wrong owner after a restore, see [Back up and restore](../admin-guide/backups.md). |
| Admin exists | Console login succeeds. |
| Image publishes | The catalog lists the image id, hashes, and info hash. |
| Import publishes in place | A file already under the read-only image root imports from the Console, and that root keeps no copy of the image and no `.torrent` beside it. |
| Shared package provenance | IOx and IOS-XR wrappers match their adjacent manifests and the one Open Container Initiative (OCI) build they come from. Guest Shell and both container architectures carry the current shared agent source. |

## Next steps

- [Stage your first image](../user-guide/first-image.md)
- [What a device needs before onboarding](device-requirements.md)
- [Add and onboard devices](../user-guide/onboarding.md)
- [Troubleshoot: symptoms and first steps](../user-guide/troubleshooting.md)
