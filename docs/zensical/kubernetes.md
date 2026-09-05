<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Kubernetes

The server and Console images run as separate Kubernetes Deployments and
Services. The alpha manifests live under `kubernetes/` and use Kustomize; the
server owns persistent state; the Console reaches it through authenticated
HTTPS on the internal management Service.

## Topology

| Resource | Purpose |
| --- | --- |
| `iris-seed-server` Deployment | One amd64 pod running tracker, catalog, seeder, artifacts, telemetry, and the internal management API. |
| `iris-console` Deployment | One state-free Console pod serving browser HTTPS and its same-origin API gateway. |
| Server init container | Runs idempotent `iris-bootstrap` against the data PVC. |
| PVC | Stores catalog state, encrypted configuration, images, and served artifacts; mounted by server only. |
| Secrets | Supply the age identity, management and observability current/previous tokens, and two distinct TLS identities outside the PVC. |
| Memory `emptyDir` | Holds decrypted server runtime secrets under `/run/iris`. |
| Two LoadBalancer Services | Publish device/server ports separately from the operator Console. |
| ClusterIP Service | Publishes management HTTPS on 9443 inside the cluster; NetworkPolicy restricts its ingress to Console pods. |
| NetworkPolicies | Permit the declared ingress paths and deny incidental cross-tier access. |

```mermaid
flowchart LR
    Device["Devices"] -->|"6969, 8443, 8000, 6881"| Server["Server Deployment"]
    Operator["Operator browser"] -->|"8080"| Console["Console Deployment"]
    Console -->|"authenticated HTTPS 9443"| Api["Internal management Service"]
    Api --> Server
    Server --> PVC["RWO data PVC"]
```

The server Deployment uses `replicas: 1` with `Recreate`. The tracker peer
registry is in memory, catalog state is file-backed, and seeder RPC is local to
the server pod. More replicas would split coordination state rather than add
capacity. Console can restart independently without interrupting devices. Pods receive
private cluster addresses and use Service DNS; devices and browsers use the
LoadBalancer addresses. Neither pod needs its own external IP.

Deployment records live under `IRIS_STATE` (`/data/state`) on the PVC, and
server-side onboarding stages artifacts under `/data/artifacts`. Console
reaches both through the management API and never mounts the PVC. A server pod
restart marks in-flight deployment records `unknown` and requires
reconciliation rather than blindly retrying a device operation. See
[Management Type and VLAN Ownership](management-type.md).

IOx onboarding needs `iris-arm64.tar` and/or `iris-amd64.tar` under
`/data/artifacts`; IOS-XR onboarding needs `iris-xr.rpm`. Copy each package's
adjacent `.manifest` as well, because readiness binds the served wrapper bytes
to their canonical OCI provenance. Kubernetes does not run host-side package
builders. Build the deployment-neutral packages elsewhere and copy them to the
server pod with `kubectl cp --no-preserve`. Rebuild and re-copy every package
after a shared-agent or common image-definition change, and rebuild/redeploy
the server image to refresh its Guest Shell bundle. A certificate rotation
does not require rebuilding them: server startup refreshes the distributed
`/data/artifacts/iris-catalog.pem`; re-onboard devices so IOx app data or the
IOS-XR harddisk bind mount receives the new runtime trust anchor. Package
readiness checks bytes against manifests, not whether the source has changed;
use the [rebuild procedure](development.md#embedded-agent-packages).

## External address

Reserve stable device/server and operator-Console addresses before bootstrap.
Put the device-reachable address in `kubernetes/iris-seed-server.env` as
`IRIS_HOST_IP`, and configure the server LoadBalancer to use it. IRIS uses it
in the catalog certificate, tracker announce URL, and seeder endpoint.

The server Service sets `externalTrafficPolicy: Local`. The tracker uses the
connection source address when a device does not send an explicit peer IP, so
source NAT could advertise an unreachable node address. See Kubernetes
[source-IP behavior](https://kubernetes.io/docs/tutorials/services/source-ip/).
Port 6969 is an HTTPS listener using the same server certificate devices pin
for the catalog; the Service remains a layer-4 TCP mapping and terminates no
TLS itself.

The management Service is ClusterIP-only and port 9443 is absent from both
LoadBalancers. Its ingress NetworkPolicy selects only Console pods. The API also requires a scoped service credential and pinned TLS. These
NetworkPolicies require a CNI that enforces them. The base policies allow any
source on the published server ports and on Console 8080; restrict operator,
device, and monitoring source ranges at the LoadBalancer or firewall. Egress
is unrestricted because SSH, DNS, and optional feed/telemetry destinations
depend on the deployment.

## Unprivileged runtime

Both pods run as uid/gid `10001`, drop all capabilities, disallow privilege
escalation, and inherit `RuntimeDefault` seccomp. The namespace enforces the
restricted Pod Security profile. All listeners bind above 1024.

The server uses `fsGroup: 10001` so its PVC and age-key projection are usable
by the non-root process. The Console has no PVC. Whether a PVC honors `fsGroup`
depends on the storage driver's `fsGroupPolicy`; verify it before first deploy:

```bash
kubectl get csidriver \
  -o custom-columns=NAME:.metadata.name,FSGROUPPOLICY:.spec.fsGroupPolicy
kubectl -n iris exec deployment/iris-seed-server -- id
kubectl -n iris exec deployment/iris-seed-server -- \
  ls -ld /data /data/state /data/images /data/artifacts /run/secrets/iris_age_key
```

If the driver does not apply the group, pre-create volume ownership out of band
or use a storage class that supports it. Do not make either container root to
work around storage ownership.

## Secrets and storage

Before applying the Kustomization, replace the address/recipient sentinels in
`iris-seed-server.env`, configure `iris-console.env`, and set both image names
and immutable digests in `kustomization.yaml`. Build the images from
`server/Dockerfile` and `server/Dockerfile.console` and publish them to a
registry reachable by every node. Configure the LoadBalancers and source
restrictions for the reserved addresses.

Create the namespace, age identity, both token pairs, and both TLS identities.
Use a protected directory outside the repository in place of `/secure/path`
below. The management certificate must have DNS SANs for `iris-server-api`, `iris-server-api.iris`, and
`iris-server-api.iris.svc`; its private key goes only to the server, while
Console receives only the issuing CA. The separate Console certificate must
cover the exact DNS name or IP address operators use in their browser:

```bash
umask 077
age-keygen -o /secure/path/iris-age.txt
age-keygen -y /secure/path/iris-age.txt
openssl rand -hex 32 > /secure/path/management-current
openssl rand -hex 32 > /secure/path/observability-current
: > /secure/path/management-previous
: > /secure/path/observability-previous

kubectl apply -f kubernetes/namespace.yaml
kubectl -n iris create secret generic iris-age \
  --from-file=identity=/secure/path/iris-age.txt
kubectl -n iris create secret generic iris-tier-auth \
  --from-file=current=/secure/path/management-current \
  --from-file=previous=/secure/path/management-previous
kubectl -n iris create secret generic iris-observability-auth \
  --from-file=current=/secure/path/observability-current \
  --from-file=previous=/secure/path/observability-previous
# Optional: outbound OTLP collector authentication.
kubectl -n iris create secret generic iris-otlp-headers \
  --from-file=headers=/secure/path/otlp-headers
kubectl -n iris create secret tls iris-management-tls \
  --cert=/secure/path/server-api.crt --key=/secure/path/server-api.key
kubectl -n iris create configmap iris-management-ca \
  --from-file=ca.crt=/secure/path/server-api-ca.crt
kubectl -n iris create secret tls iris-console-tls \
  --cert=/secure/path/console.crt --key=/secure/path/console.key
```

Set `IRIS_AGE_RECIPIENTS` to the public recipient printed above plus a separately
held break-glass recipient, then apply:

```bash
kubectl apply -k kubernetes
```

After both Deployments are ready, open the Console from the trusted management
network and sign in with the default first-run credential `iris` /
`irisisgreat!`. The login creates no session; it returns a one-use setup grant
that expires after ten minutes and leads to administrator creation. Creating
the administrator permanently ends this special behavior.

!!! warning "The first reachable caller can claim a fresh Console"
    Restrict the Console LoadBalancer to trusted operators and complete setup
    immediately after deployment. Do not make a brand-new Console reachable
    from an untrusted network while no administrator exists.

The base manifests require both `current` files even when external monitoring
is disabled. The initially empty `previous` files satisfy the projections
until the first rotation. A scoped JSON `management` record makes a management-token
mis-mount auditable. Keep observability files as raw token values so Prometheus
can consume `current` directly with `authorization.credentials_file`; the
server assigns those files the `observability` scope when it validates them,
so their values are not accepted by the management API.

Management-token rotation is two phase: put the new token in `current` and the
former token in `previous`, recreate/apply `iris-tier-auth` from both files,
and restart both Deployments. Verify an authenticated Console request, then
empty `previous`, recreate/apply the Secret, and restart both again. Use
`kubectl create secret generic ... --dry-run=client -o yaml | kubectl apply -f -`
for each update so the command works for an existing Secret. Observability
rotation follows the same current/previous overlap, but
only the server Deployment and external scraper need to move. The server
rereads both observability files on each request. Missing, unreadable,
wrongly-scoped, or weak credentials fail closed; rotation never opens an
anonymous fallback.

The optional `iris-otlp-headers` Secret is different from the observability
pair: it authenticates outbound OTLP pushes, not inbound Prometheus scrapes.
Its `headers` key contains the comma-separated `Name=Value` header spec and is
mounted only by the server. Do not put it in a ConfigMap, URL, or command
argument. With the Secret absent IRIS sends no collector header; with it
present, the configured OTLP endpoint must use HTTPS. Re-apply that Secret and
restart only `iris-seed-server` to rotate it.

`iris-console-tls` is mounted read-only only by the Console. Its key never
enters the server pod, PVC, ConfigMap, or image. On a normal start the Console
checks the authenticated management API for an operator-installed override.
If the server is unavailable during cold start, or explicitly reports that
the default is active, the Console validates this Secret and copies it into
its memory-backed runtime directory. A malformed or authentication-failed API
response is not treated as a reason to fall back.

Each env file is a hashed `configMapGenerator` input, so an edit and re-apply
rolls the affected Deployment. Keep deployment images pinned to immutable
registry digests. The default server PVC request is `50Gi`; size it for
retained images.

## Health and operation

Server startup/readiness probes call `https://<server-pod>:9101/readyz`, which
checks tracker, catalog, artifact, and management listeners. Server liveness
calls `/healthz`, proving the telemetry process is alive without restarting the
pod for a dependency-readiness failure. Console probes call its local
`/readyz` and `/healthz` on 8080. Console readiness checks local serving files,
a valid credential file, and the presence of its management CA file, not
server availability; the independent
`iris-console-tls` identity lets it start while the server is cold. API
requests arriving while server is down get a redacted 503 with `Retry-After`.

The server LoadBalancer publishes 6969, 8443, 8000, 6881, and 9101; the Console
LoadBalancer publishes 8080. Metrics export is optional, but the base Service
publishes 9101 for probes regardless. Ports 6800 and 9443 remain internal.
Metrics require monitoring authentication. `/healthz` and `/readyz` disclose
no state; login/setup have their own credential/grant checks. The existing
Guest Shell bootstrap, CA, and agent-bundle HTTPS downloads are separate static
endpoints and are anonymous; per-install staging-artifact
paths still carry their resource capability in the filename.

```bash
kubectl -n iris rollout status deployment/iris-seed-server
kubectl -n iris rollout status deployment/iris-console
kubectl -n iris logs deployment/iris-seed-server -c iris
kubectl -n iris logs deployment/iris-console
POD="$(kubectl -n iris get pod -l app.kubernetes.io/name=iris-seed-server \
  -o jsonpath='{.items[0].metadata.name}')"
kubectl -n iris cp --no-preserve <image>.bin \
  "$POD:/data/images/<image>.bin"
kubectl -n iris exec deployment/iris-seed-server -- \
  iris-publish /data/images/<image>.bin
```

Back up the server PVC and keep the age identity in separate protected storage.
Include the independently supplied Secrets in your recovery plan. Treat a
public IP change as certificate and device-trust rotation, not a transparent Service
update.
