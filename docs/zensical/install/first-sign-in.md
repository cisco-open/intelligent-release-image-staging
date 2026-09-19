<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Sign in for the first time

Claim the administrator account on your new Console, then finish setup.

## Before you start

- The server and the Console are running: see
  [Install on one Docker host](one-docker-host.md),
  [Install on separate Docker hosts](separate-docker-hosts.md) or
  [Install on Kubernetes](kubernetes.md).
- You know the Console address and port, and you are on the management network
  that reaches it.

!!! warning "The first caller to reach a new Console can claim it"
    Restrict the Console port to trusted operator sources and create the
    administrator right after deployment. On Kubernetes, restrict the load
    balancer too.

## Open the Console

Open your Console address and port in a browser:

```text
https://<console-address>:8080/
```

The sign-in page appears. In the one-host stack the address is `IRIS_HOST_IP`.

### What the browser shows

The browser warns that it does not trust the certificate, because the default
identity is generated during installation. Check the address in the bar, then
continue past the warning. Replace that identity before you run IRIS for real:
see [Set up certificates and tokens](certificates-and-tokens.md).

## Claim the administrator account

1. Sign in with the first-run credential `iris` / `irisisgreat!`.
   You get a one-use setup grant, good for ten minutes, and the
   account-creation page.
2. Create the administrator account, with a name and password of your own.
   You are signed in as that administrator.

Creating the administrator retires the first-run credential. The API claims the
account the same way: see [Console API](../reference/console-api.md). If you
lose the password, recover the account from the host: see
[Routine maintenance tasks](../admin-guide/maintenance.md).

## Finish the first three setup steps

The next sign-in opens the setup flow. You can skip any step, and the flow
resumes at the first one outstanding.

1. **Telemetry destination.** Where swarm progress, device reports and export
   health are published. Already done when the deployment sets
   `IRIS_OTLP_ENDPOINT`.
2. **Device packages.** Whether each IOx package and the IOS-XR agent package
   `iris-xr.rpm` still match the record of how they were built, and whether the
   served and distributed runtime certificates agree. Run the build commands it
   gives you on the Docker host, then select **Re-check**.
3. **Image verification.** The check of published images against Bulk Hash, the
   checksum Cisco publishes for an image. Refresh now, schedule a daily run, or
   import a feed file.

## Verify

- The Console shows the operator areas, not the account-creation page.
- Sign out, then try `iris` / `irisisgreat!` again. It fails.
- The Setup page in Settings reports all four items.

## Next steps

- [Turn on instruction signing](activate-signing.md): an instruction is the
  signed message the server sends a device saying which images to stage and how.
- [Set up certificates and tokens](certificates-and-tokens.md).
- [Build and publish the device packages](device-packages.md).
- [Verify the installation](verify.md), then
  [find your way around the Console](../user-guide/console.md).
