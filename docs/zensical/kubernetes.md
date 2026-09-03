<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Kubernetes

The seed-server image can run on Kubernetes without changing the IRIS protocol
or splitting the services into separate pods. The alpha manifests live under
`kubernetes/` and use Kustomize.

## Topology

| Resource | Purpose |
| --- | --- |
| Deployment | One amd64 pod running tracker, catalog, seeder, artifacts, console, and telemetry. |
| Init container | Runs idempotent `iris-bootstrap` against the data PVC. |
| PVC | Stores catalog state, encrypted configuration, images, and served artifacts. |
| Secret | Supplies the age identity outside the PVC. |
| Memory `emptyDir` | Holds decrypted runtime secrets under `/run/iris`. |
| LoadBalancer Service | Preserves the public IRIS ports and device source addresses. |

The deployment uses `replicas: 1` with a `Recreate` strategy. The tracker peer
registry is in memory, catalog state is file-backed, and the seeder RPC is local
to the container. More replicas would split coordination state rather than add
capacity.

Deployment records (the applied-lifecycle state that drives undeploy) are
file-backed under `IRIS_STATE` (`/data/state`) on the PVC, and Console artifact
staging uses `/data/artifacts` on the same PVC. Because there is a single
replica, a pod restart marks any in-flight (`planned`/`applying`) deployment record
`unknown` and requires reconciliation instead of blindly retrying a device
operation. See
[Management Type and VLAN Ownership](management-type.md).

IOx onboarding (routed or inband, on IE-3400 or Catalyst 9300) needs
`iris-arm64.tar` and/or `iris-amd64.tar` staged under `/data/artifacts` on the
PVC. IOS-XR onboarding likewise needs `iris-xr.rpm` there. Kubernetes does not
run the host-side package builders, so build the required packages elsewhere
(`tools/provision-iox-packages.sh` and `tools/build-xr-package.sh --out
artifacts/`) and copy them in with `kubectl cp`. Guest Shell onboarding,
including Catalyst 8000 router VPG deployments, needs no prebuilt package.

Rebuild and re-copy those packages after any certificate rotation or shared
agent change. Each package bakes both at build time; see
[TLS rotation and device packages](operations.md#tls-rotation-and-device-packages).

The published console port shown on the Settings page follows `IRIS_CONSOLE_URL`
when set (otherwise it defaults to the Service's `8080`); set it if you front
the console on a different external port.

## External address

Reserve a stable, device-reachable IPv4 address before bootstrapping. Put that
exact value in `kubernetes/iris-seed-server.env` as `IRIS_HOST_IP`, and configure the
LoadBalancer to use the same address with the mechanism provided by the cluster.
IRIS uses it in the certificate SAN, torrent tracker URLs, and seeder announces.

The Service sets `externalTrafficPolicy: Local`. The tracker uses a connection's
source address when a device does not send an explicit peer IP, so source NAT
would cause it to advertise an unreachable cluster or node address. See the
Kubernetes documentation on
[source IP behavior](https://kubernetes.io/docs/tutorials/services/source-ip/).

## Unprivileged runtime

The pod runs as the unprivileged identity baked into the server image. The pod
`securityContext` sets `runAsNonRoot: true` together with `runAsUser`,
`runAsGroup`, and `fsGroup` of `10001`. The container and the init container each
drop `ALL` capabilities with `allowPrivilegeEscalation: false`, and both inherit
the `RuntimeDefault` seccomp profile from the pod. `namespace.yaml` labels the
namespace `pod-security.kubernetes.io/enforce: restricted`, so a manifest edit
that reintroduces root or a privileged setting is refused at admission instead of
being applied quietly.

Keep `runAsUser` and `runAsGroup` equal to the image's uid and gid — `10001`, the
`iris` user baked into the server image
([Runtime identity](server.md#runtime-identity)). When both sides agree, ownership
is deterministic across the PVC, the Secret mount, and anything copied in with
`kubectl cp`; change one without the other and the process cannot read its own
files. Every listener binds above 1024 (6969, 8443, 8000, 6881, 8080, 9101), so
nothing in the pod needs a privileged port.

`fsGroup` is what makes the mounted volumes usable. The kubelet group-owns the
PVC-backed `/data` tree for gid 10001, and it also changes how the age-key Secret
is projected: the files arrive as mode `0440` owned `root:10001` rather than the
`0400` `root:root` declared in `deployment.yaml`. That group read is precisely
what lets the non-root process read the identity and decrypt configuration. A
Secret readable only by root fails at startup.

!!! warning "Verify `fsGroup` support before the first deploy"
    Applying `fsGroup` to a PVC is the storage driver's decision, not the
    kubelet's. A CSI driver whose `fsGroupPolicy` is `None` ignores it: `/data`
    stays root-owned and the pod cannot write catalog state, images, or
    artifacts at uid 10001. Check the driver behind your storage class, then
    confirm ownership from inside the running pod. If the driver does not apply
    `fsGroup`, pre-create the volume's ownership out of band or choose a storage
    class whose driver honors it.

```bash
kubectl get csidriver \
  -o custom-columns=NAME:.metadata.name,FSGROUPPOLICY:.spec.fsGroupPolicy
kubectl -n iris exec deployment/iris-seed-server -- id
kubectl -n iris exec deployment/iris-seed-server -- \
  ls -ld /data /data/state /data/images /data/artifacts /run/secrets/iris_age_key
```

## Secrets and storage

Create the namespace and age identity Secret before applying the full
Kustomization:

```bash
age-keygen -o iris-age.txt
age-keygen -y iris-age.txt

kubectl apply -f kubernetes/namespace.yaml
kubectl -n iris create secret generic iris-age \
  --from-file=identity=iris-age.txt
kubectl apply -k kubernetes
```

Replace the recipient and external-address sentinels in `iris-seed-server.env`,
and change the image mapping in `kustomization.yaml` to a registry image
reachable by every cluster node. The env file is turned into the ConfigMap by
kustomize's `configMapGenerator`, so editing it and re-applying rolls the pod
onto the new values. The image tag is a mutable placeholder pulled with
`imagePullPolicy: Always`; after rebuilding under the same tag run
`kubectl -n iris rollout restart deployment/iris-seed-server` to re-pull. The default PVC request is `50Gi`; size it for the images
that must remain available for seeding.

## Health and operation

Startup, readiness, and liveness probes use `http://<pod>:9101/readyz`, which
TCP-probes the tracker, catalog, artifact server and console listeners and
answers 503 naming any that are down (`/healthz` answers 200 unconditionally
and proves only that the telemetry server is alive — curl `/readyz`, not
`/healthz`, when diagnosing a `Readiness probe failed` event). Set
`IRIS_HEALTH_LISTENERS` in `iris-seed-server.env` to `name:port,name:port` to
narrow that probe set, or to the literal `off` to check nothing, for a
deployment that runs a subset of the services. The
same port serves the swarm and peer-distribution counters at `/metrics` when
`IRIS_OBSERVABILITY=1` is set in `iris-seed-server.env` ([Telemetry
export](telemetry-export.md)); the peer ledger they are read from lives under
`IRIS_STATE` on the PVC, so the totals survive a pod restart. The
external Service publishes ports 6969, 8443, 8000, 6881, 8080, and 9101. Port
6800 remains pod-local. Remote `/swarm` through the Service answers `403` by
default — swarm data is console-gated; set `IRIS_SWARM_PUBLIC=1` in the pod
environment or use the console (probes and `/healthz` are unaffected).

```bash
kubectl -n iris rollout status deployment/iris-seed-server
kubectl -n iris logs deployment/iris-seed-server -c iris
POD="$(kubectl -n iris get pod -l app.kubernetes.io/name=iris-seed-server \
  -o jsonpath='{.items[0].metadata.name}')"
kubectl -n iris cp --no-preserve <image>.bin \
  "$POD:/data/images/<image>.bin"
kubectl -n iris exec deployment/iris-seed-server -- \
  iris-publish /data/images/<image>.bin
```

Keep `--no-preserve` on the copy so the file lands with the pod's own uid and a
default mode instead of carrying the host file's ownership and mode. The same
applies to the IOx app packages copied into `/data/artifacts`.

The configmap points both `IRIS_IMAGES_DIR` and `IMAGES_ROOT` at `/data/images`.
The import scan walks each distinct tree once, so a file copied there is offered
for import exactly once rather than colliding with itself.

Back up the PVC and offline age identity together. Treat a public IP change as
a certificate and device-trust rotation, not as a transparent Service update.
