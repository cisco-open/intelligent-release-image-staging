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

## External address

Reserve a stable, device-reachable IPv4 address before bootstrapping. Put that
exact value in `kubernetes/configmap.yaml` as `IRIS_HOST_IP`, and configure the
LoadBalancer to use the same address with the mechanism provided by the cluster.
IRIS uses it in the certificate SAN, torrent tracker URLs, and seeder announces.

The Service sets `externalTrafficPolicy: Local`. The tracker uses a connection's
source address when a device does not send an explicit peer IP, so source NAT
would cause it to advertise an unreachable cluster or node address. See the
Kubernetes documentation on
[source IP behavior](https://kubernetes.io/docs/tutorials/services/source-ip/).

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

Replace the recipient and external-address sentinels in `configmap.yaml`, and
change the image mapping in `kustomization.yaml` to a registry image reachable
by every cluster node. The default PVC request is `50Gi`; size it for the images
that must remain available for seeding.

## Health and operation

Startup, readiness, and liveness probes use `http://<pod>:9101/healthz`. The
external Service publishes ports 6969, 8443, 8000, 6881, 8080, and 9101. Port
6800 remains pod-local.

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

Back up the PVC and offline age identity together. Treat a public IP change as
a certificate and device-trust rotation, not as a transparent Service update.
