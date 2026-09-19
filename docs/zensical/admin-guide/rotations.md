<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Rotate credentials and certificates

Replace any credential or certificate in a running deployment. Each section is one
procedure: install the new value, confirm both sides use it, retire the old one.
Run one rotation at a time.

## In the Console

| Settings page | What it does |
| --- | --- |
| **TLS & trust** | Installs the browser certificate this Console serves and the certificate authorities it trusts. |
| **Device packages** | Compares the certificate the live services present with the public `iris-catalog.pem` copy that onboarding hands to devices. |

## Rotate the management credential

The Console reaches server state over the management API on internal HTTPS port
9443. Both sides read the credential from mounted files.

!!! warning "Keep the credential in files"
    Never put it in `server/.env`, a Compose `environment:` entry, a URL, or a
    command argument.

### On one Docker host

1. Rotate it. The old value moves to `previous.json`, the new one to `current.json`:

```bash
docker compose -f server/docker-compose.yml exec iris \
  iris-management-token rotate
```

2. Open **Devices** in the Console. The page loads.
3. Retire the old value:

```bash
docker compose -f server/docker-compose.yml exec iris \
  iris-management-token retire-previous
```

### On separate Docker hosts

1. On the server host, run `iris_server exec iris iris-management-token rotate`.
   The new value lands in `current.json` in `IRIS_TIER_AUTH_DIR`, whose path is
   set in [Install on separate Docker hosts](../install/separate-docker-hosts.md).
2. Copy that file to the Console host over verified SSH, under a temporary name
   in its `IRIS_TIER_AUTH_DIR`. Set owner `10001:10001` and mode 600, then
   rename it to `current.json` there.
3. Open **Devices** in the Console. The page loads.
4. On the server host, run
   `iris_server exec iris iris-management-token retire-previous` and remove the
   temporary copies.

### On Kubernetes

1. Put the new token in `current` and the old one in `previous`, then recreate
   the `iris-tier-auth` Secret from both files.
2. Restart both Deployments. Each pod's mounted `current` file holds the new
   token.
3. Open **Devices** in the Console. The page loads.
4. Empty `previous`, apply the Secret again, restart both Deployments.

Use `kubectl create secret generic ... --dry-run=client -o yaml | kubectl apply -f -`
for each update. Secret names: [Install on Kubernetes](../install/kubernetes.md).

## Rotate the certificate that devices trust

Every onboarding path delivers the current public certificate beside the package:

| Platform | Where the certificate lands |
| --- | --- |
| Guest Shell, where the agent runs on Catalyst 9000 series switches and Catalyst 8000 series routers | With the other short-lived onboarding artifacts. |
| IOx, the alternative on Catalyst 9000 series switches with app-hosting storage and the path on Industrial Ethernet 3000 series switches and IR 1100 and 1800 series routers | In app-hosting application data, after activation and before the app starts. |
| IOS-XR appmgr on Cisco 8000 series and NCS routers | In `harddisk:/iris-catalog.pem`, read through the container's `/hostmount` bind mount. |

1. Publish the new certificate.
2. Re-onboard every device: undeploy, then onboard. See
   [Add and onboard devices](../user-guide/onboarding.md).
3. Check the certificate row on **Settings → Device packages**. No mismatch.

!!! warning "Onboarded agents keep the old certificate"
    A device you do not re-onboard still trusts the previous certificate.

## Rotate the management certificate

The certificate must cover the exact DNS name or IP address the Console calls.
Keep each certificate and key pair matched.

### On separate Docker hosts

Same authority: replace the server's certificate and key together, then restart
the server. New authority or new self-signed certificate:

1. Add the replacement certificate or authority to the Console's `ca.pem`
   beside the current one.
2. Restart the Console. It still reaches the server.
3. Replace the server pair and restart the server.
4. Open **Devices** in the Console. The page loads.
5. Remove the old trust entry and restart the Console again.

### On Kubernetes

1. Recreate the `iris-management-tls` Secret with the new pair. It needs DNS
   subject names for `iris-server-api`, `iris-server-api.iris`, and
   `iris-server-api.iris.svc`.
2. Recreate the `iris-management-ca` ConfigMap with the new issuing authority,
   keeping the old one until the swap is confirmed.

!!! warning "The management private key goes only to the server"
    The Console receives the issuing authority alone.

## Rotate the Console browser certificate

A certificate installed through **Settings → TLS & trust** takes precedence
over the deployment default, and the card shows the identity the Console is
serving. **Use deployment default certificate** returns to the default one. An
encrypted private key asks for its passphrase and is stored encrypted at rest.
Drop authority files to trust them, or pick a bundle source to trust a whole
public bundle, which appears as one row you can remove again.

To replace the deployment default, replace the Console host's `tls.crt` and
`tls.key` together and restart the Console, or on Kubernetes recreate the
`iris-console-tls` Secret. See [Find your way around the Console](../user-guide/console.md).

!!! warning "Keep the browser key on the Console"
    That key never belongs in the server pod, the server volume, a ConfigMap,
    or an image.

## Rotate the seeder announce credential

The seeder, the server's own copy of each published image and the first source
in the swarm, announces itself to the tracker with its own credential.

1. Freeze maintenance for your layout.
2. Run `rotate-seeder-announce --maintenance-frozen`. It exits zero only after
   the tracker proves the new identity is serving.
3. Lift the freeze.

Preflight refuses, naming the reason on standard error, when an image has no
torrent or its torrent is not uniquely active, when the announce base is not a
usable HTTPS IPv4 endpoint, when durable encrypted secrets are missing, or when
an earlier recovery manifest is still on disk. For proof, the command polls the
tracker's authenticated, pinned-TLS `/swarm` and requires the current typed
`service:seeder` principal for every torrent, announced after the adds; any
other result fails closed. Every run first writes a non-secret recovery
manifest of the pre-rotation torrent bytes, and `--recover` restores it.

!!! warning "A hard no-go can leave an image not being served"
    If a restore also fails, or a remove fails and live state is therefore
    unknown, the run becomes a hard no-go. The result lists every disturbed
    torrent; a `false` restore result means serving repair is still required
    for that image before you lift the freeze.

The rotated-out credential stays valid for 30 days, set by
`IRIS_SEEDER_PREV_TTL`. Two retired credentials can be valid at once, so run at
most two rotations per window unless every device has a fresh torrent.

## Rotate the metrics scrape token

The token is a raw value in a private file that the server rereads on each
request.

1. Write the new raw value to a new private file. On Docker, give Compose its
   path; on Kubernetes, put it in `current` in the `iris-observability-auth`
   Secret.
2. Keep the old value available while you update the scraper: on Docker through
   `IRIS_OBSERVABILITY_PREVIOUS_TOKEN_FILE_HOST`, on Kubernetes as `previous`.
3. Update the collector or Prometheus credentials file. A scrape succeeds.
4. Remove the old value. Scrapes keep working.

Keep both files as raw token values so Prometheus reads `current` as its
credentials file. See [Set up certificates and tokens](../install/certificates-and-tokens.md).

## Rotate the collector headers

The headers that authenticate the server's outbound telemetry push live in
their own private file. Write the new value to that file. On Kubernetes,
re-apply the `iris-otlp-headers` Secret and restart the server Deployment. See
[Export telemetry](../user-guide/telemetry-export.md).

## Rotate the age recipients

This changes who can decrypt the stored configuration.

1. Back up the encrypted configuration and the age identity. See [Back up and restore](backups.md).
2. Stop configuration writers with the maintenance procedure for your layout.
3. Set `IRIS_AGE_RECIPIENTS` to the full public recipient list, including the
   current service identity's public key, and persist it in the environment.
4. Run `iris-bootstrap --rekey` in a server container with the same
   configuration volume and the current age identity mounted.
5. Verify decryption with the intended identities, then retire the old
   recovery material.

!!! warning "Do not add `--force`"
    `iris-bootstrap --rekey --force` can discard state this procedure needs.

## Rotate one device's instruction key

For a leaked instruction key on an otherwise honest device, run
`iris-instr-key rotate --no-overlap <device_id>`. The device keeps the last
policy it accepted, which the agent re-encrypts locally.

For device retirement or a compromise, run `iris-revoke <device_id>` instead.
See [Undeploy, retire and clean up devices](../user-guide/undeploy.md).

!!! warning "Never rotate a key to spare a revoked device"
    A rotation never restores a revoked device. The server refuses its catalog
    access even when its last report says it runs an accepted policy.

## Change the server's public address

The address appears in the certificate devices trust, the tracker announce URL,
and the seeder endpoint. Reissue the certificate, publish it, re-onboard devices.

## What you see

| After you rotate | How you know it worked |
| --- | --- |
| Management credential | An authenticated Console request succeeds with the old value removed. |
| Device certificate | The certificate row on **Settings → Device packages** stops reporting a mismatch, and re-onboarded devices report in. |
| Seeder announce credential | The command exits zero, which happens only after the tracker proves the new identity is serving. |

## Edge cases

- A quarantined image, an image that failed the Cisco hash check and is held
  back from devices, is skipped during a seeder rotation and its id is listed.
  Its torrent keeps the retired announce until you release the quarantine. If
  every image is quarantined, the command refuses. See
  [Publish and verify images](../user-guide/images.md).
- A rotation you started but did not finish leaves both values working. Finish it
  before you start another.

## Related

- [Back up and restore](backups.md)
- [Replace or recover signing keys](instruction-keys.md)
- [Add and onboard devices](../user-guide/onboarding.md)
- [Security model and trust boundaries](../architecture/security-model.md)
- [Helper commands](../reference/tools.md)
