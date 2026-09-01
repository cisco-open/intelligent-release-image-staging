<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Kubernetes seed server alpha

This directory runs the same self-contained IRIS seed-server image used by
Docker Compose. It is an optional deployment target, not a second server
implementation.

## Deployment contract

- Run exactly one replica. The tracker peer registry is in memory, the catalog
  uses local files, and the seeder RPC is local to the pod.
- Use an amd64 node. The server image carries an x86_64 static `aria2c` that is
  also packed into Catalyst Guest Shell agent bundles.
- Reserve one stable, device-reachable IPv4 address for the LoadBalancer. The
  tracker, catalog, artifact server, BitTorrent seeder, console, and health port
  must all retain their declared external port numbers.
- Preserve client source addresses. `externalTrafficPolicy: Local` is set
  because the tracker returns peer addresses to other devices; a masqueraded
  node address would break peer-to-peer transfers.
- Keep the age identity outside the PVC. Kubernetes mounts it from the
  `iris-age` Secret, while decrypted runtime material lives in a memory-backed
  `emptyDir` at `/run/iris`.

## Build and publish

From the repository root, build an amd64 image and publish it to a registry the
cluster can pull from:

```bash
docker build --platform linux/amd64 \
  -f server/Dockerfile \
  -t registry.example.com/iris/seed-server:docker-alpha .
docker push registry.example.com/iris/seed-server:docker-alpha
```

Set that image in `kustomization.yaml`:

```yaml
images:
  - name: iris
    newName: registry.example.com/iris/seed-server
    newTag: docker-alpha
```

## Configure and deploy

1. Reserve the external LoadBalancer IPv4 address using the mechanism for your
   cluster, such as a cloud load-balancer annotation or a MetalLB address pool.
2. Replace `REPLACE_WITH_STATIC_EXTERNAL_IP` in `configmap.yaml` with that exact
   address. It becomes the TLS certificate IP SAN, tracker URL, and seeder
   advertised address, so it must not change behind the running deployment.
3. Create and protect an age identity, then put only that identity into the
   Kubernetes Secret:

```bash
age-keygen -o iris-age.txt
age-keygen -y iris-age.txt

kubectl apply -f kubernetes/namespace.yaml
kubectl -n iris create secret generic iris-age \
  --from-file=identity=iris-age.txt
```

4. Replace `REPLACE_WITH_AGE_RECIPIENTS` in `configmap.yaml` with the printed
   public recipient, ideally followed by an offline break-glass recipient.
5. Review the `50Gi` PVC request and LoadBalancer configuration, then deploy:

```bash
kubectl apply -k kubernetes
kubectl -n iris rollout status deployment/iris-seed-server
```

The init container runs `iris-bootstrap` idempotently against the PVC. The main
container then decrypts secrets into memory and starts the tracker, catalog,
seeder, artifact server, console, and telemetry health endpoint.

## Operate

The console is available at `https://<external-ip>:8080/`. Check pod health and
logs with:

```bash
kubectl -n iris get pods,svc,pvc
kubectl -n iris logs deployment/iris-seed-server -c iris
curl -fsS http://<external-ip>:9101/healthz
curl -fsS http://<external-ip>:9101/readyz
```

`/healthz` answers 200 unconditionally and proves only that the telemetry
server on `:9101` is alive. `/readyz` is the one with a meaningful status code:
it TCP-probes the tracker, catalog, artifact server and console — separate
listeners inside the container, any of which can die while the process stays
up — and answers 503 naming the offenders. All three pod probes point at
`/readyz` for exactly that reason. `IRIS_HEALTH_LISTENERS`
(`"name:port,..."`, or `off`) narrows the set for a deployment that runs a
subset of the services.

Images uploaded through the console are stored under `/data/images` on the PVC.
For an operator-managed image, copy it into the pod and publish it through the
local seeder RPC:

```bash
POD="$(kubectl -n iris get pod -l app.kubernetes.io/name=iris-seed-server \
  -o jsonpath='{.items[0].metadata.name}')"
kubectl -n iris cp --no-preserve image.bin "$POD:/data/images/image.bin"
kubectl -n iris exec deployment/iris-seed-server -- \
  iris-publish /data/images/image.bin
```

### Operator-supplied device artifacts

The container regenerates the *derivable* served files at startup
(`iris-agent.tgz`, `bootstrap.sh`, `iris-catalog.pem`), so a fresh pod can
onboard Guest Shell and router devices with no manual step. The IOx packages
and the XR appmgr RPM are **not** derivable — they are built out of tree
(`tools/provision-iox-packages.sh`, `tools/build-xr-package.sh`) and have to be
placed in the artifacts directory by hand.

`tools/stage-iox-package.sh` stages them with `docker cp` into a container
literally named `iris`, which does not exist here. On Kubernetes copy them into
`$IRIS_ARTIFACTS_DIR` (`/data/artifacts`, on the PVC, so they survive a
restart):

```bash
POD="$(kubectl -n iris get pod -l app.kubernetes.io/name=iris-seed-server \
  -o jsonpath='{.items[0].metadata.name}')"
for f in iris-arm64.tar iris-amd64.tar iris-xr.rpm; do
  [ -f "artifacts/$f" ] || continue
  kubectl -n iris cp --no-preserve "artifacts/$f" "$POD:/data/artifacts/$f"
done
kubectl -n iris exec "$POD" -- ls -la /data/artifacts
```

Without this, onboarding an IE-3x00 (IOx) or an IOS-XR device fails at the
artifact fetch while every other platform works — the failure looks like a
device problem, not a missing file. Re-copy after any rebuild of those
packages: nothing on the cluster side notices that they went stale.

Back up the PVC and the age identity together. If the external IP changes, plan
a controlled certificate rotation and device trust update; changing only the
Service address leaves the existing certificate and torrent announce URLs stale.
