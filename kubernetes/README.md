<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Kubernetes deployment

This optional kustomize base runs IRIS as two independently deployable tiers:
the device-facing seed server and the browser-facing console. The server is the
only owner of persistent state. The console calls a narrow, authenticated HTTPS
management API and never mounts the server PVC.

## Topology and invariants

| Service | Type | TCP ports |
| --- | --- | --- |
| `iris-seed-server` | `LoadBalancer` | `6969, 8443, 8000, 6881, 9101` |
| `iris-console` | `LoadBalancer` | `8080` |
| `iris-server-api` | `ClusterIP` | `9443` |

- Both Deployments deliberately run one replica with a `Recreate` strategy.
  The tracker registry and console TLS serving context are process-local, and
  the server's `ReadWriteOnce` PVC cannot safely be shared by multiple server
  pods.
- Only `iris-seed-server` mounts `iris-data`. Images, generated artifacts,
  encrypted configuration, and state remain under `/data` there.
- Port 9443 is cluster-internal. A default-deny ingress policy admits it only
  from pods carrying the console labels; it is absent from both LoadBalancers.
- Server source addresses are preserved with `externalTrafficPolicy: Local`
  because the tracker returns peer addresses to devices.
- The base leaves egress open. Device SSH targets, DNS, registries, and an
  optional OTLP collector are site-specific; add a deployment-specific egress
  policy if those destinations are known.
- The manifests require an amd64 node and Kubernetes restricted pod-security
  semantics. Verify that your CNI enforces `NetworkPolicy` before relying on
  the management API isolation.

The public server and console LoadBalancers may use different stable IPv4
addresses. Put the server address in `IRIS_HOST_IP`; it becomes the device TLS
certificate IP SAN, tracker URL, and seeder advertised address. Set
`IRIS_CONSOLE_URL` to the full browser-facing HTTPS Console URL, including
its published port. Settings reports that URL separately from the server IP.

## Build and pin both images

Build from the repository root and push each tier to a registry the cluster can
pull from:

```bash
tools/get-aria2c.sh amd64
docker build --pull --platform linux/amd64 \
  -f server/Dockerfile \
  -t registry.example.com/iris/server:candidate .
docker build --pull --platform linux/amd64 \
  -f server/Dockerfile.console \
  -t registry.example.com/iris/console:candidate .
docker push registry.example.com/iris/server:candidate
docker push registry.example.com/iris/console:candidate
```

Resolve the registry digest for each pushed image, then replace both
`registry.example.invalid` names and both all-zero digests in
`kustomization.yaml`. Keep `digest: sha256:...`; do not replace it with a
mutable `newTag`. The checked-in values are intentionally unusable so an
operator cannot accidentally deploy an unpinned development image.

## Provision trust and authentication

Create the namespace before its Secrets and ConfigMap:

```bash
kubectl apply -f kubernetes/namespace.yaml
```

### Persistent-state encryption

Generate an age identity offline, keep a protected backup, and create the
server-only Secret from the file:

```bash
age-keygen -o iris-age.txt
age-keygen -y iris-age.txt
kubectl -n iris create secret generic iris-age \
  --from-file=identity=iris-age.txt \
  --dry-run=client -o yaml | kubectl apply -f -
```

Put the printed public recipient (and preferably an offline break-glass
recipient) in `IRIS_AGE_RECIPIENTS` in `iris-seed-server.env`.

### First-run Console administrator

After both Deployments are ready, open the Console from the trusted management
network and sign in with the default first-run credential `iris` / `irisisgreat!`.
This login creates no session; it returns a one-use setup grant that expires
after ten minutes and leads to administrator creation. Creating the
administrator permanently ends that special behavior, after which the pair is
checked only against the stored administrator credentials and normally fails.

Whoever reaches a brand-new Console first can claim the administrator account.
Restrict the Console LoadBalancer to trusted operators and complete setup
immediately after deployment; do not expose an unconfigured Console to an
untrusted network.

### Management-tier bearer token

The console and management API authenticate with one operator-provisioned
Secret. Generate the values into protected local files; do not put token values
on a command line or in either ConfigMap:

```bash
umask 077
mkdir -p iris-tier-auth
openssl rand -hex 32 > iris-tier-auth/current
: > iris-tier-auth/previous
kubectl -n iris create secret generic iris-tier-auth \
  --from-file=current=iris-tier-auth/current \
  --from-file=previous=iris-tier-auth/previous \
  --dry-run=client -o yaml | kubectl apply -f -
```

`current` is required. `previous` is initially an empty file, but the key must
exist because both pods project it as a separate file. The manifests do not use
`subPath`, allowing kubelet to refresh projected Secret data.

Rotate without a flag day:

1. Generate a new token file. Copy the old `current` file to `previous`, put
   the new value in `current`, and re-apply `iris-tier-auth` from both files.
2. Restart and wait for both Deployments. The Console tries `current` first
   and can use `previous` if the server rejects the new management token.
   The server accepts both during the overlap.
3. Check that both pods have the replacement in their mounted `current` file,
   then make an authenticated Console request. Readiness alone is insufficient:
   a request can still succeed using the previous token.
4. After those checks and any in-flight calls finish, empty `previous`,
   re-apply the Secret, and restart both Deployments again. Do not begin
   another rotation until this one is complete.

[Secret projection updates are eventually consistent](https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod).
The Console's fallback covers either pod receiving the new pair first.

```bash
cp iris-tier-auth/current iris-tier-auth/previous
openssl rand -hex 32 > iris-tier-auth/current
kubectl -n iris create secret generic iris-tier-auth \
  --from-file=current=iris-tier-auth/current \
  --from-file=previous=iris-tier-auth/previous \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n iris rollout restart \
  deployment/iris-seed-server deployment/iris-console
kubectl -n iris rollout status deployment/iris-seed-server
kubectl -n iris rollout status deployment/iris-console

# Check the shipped single-replica Deployments without printing credentials.
expected_digest="$(sha256sum iris-tier-auth/current)" || exit 1
expected_digest="${expected_digest%% *}"
for deployment in iris-seed-server iris-console; do
  mounted_digest="$(kubectl -n iris exec deployment/"$deployment" -- \
    sha256sum /run/secrets/iris-tier-auth/current)" || exit 1
  if [ "${mounted_digest%% *}" != "$expected_digest" ]; then
    echo "$deployment has not received the replacement; keep the overlap" >&2
    exit 1
  fi
done
```

Open Devices in the Console and confirm it loads. Then retire the overlap:

```bash
: > iris-tier-auth/previous
kubectl -n iris create secret generic iris-tier-auth \
  --from-file=current=iris-tier-auth/current \
  --from-file=previous=iris-tier-auth/previous \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n iris rollout restart \
  deployment/iris-seed-server deployment/iris-console
kubectl -n iris rollout status deployment/iris-seed-server
kubectl -n iris rollout status deployment/iris-console
```

Confirm authenticated Console access again. The Console does not retry browser
session or CSRF failures, and it never replays a streamed mutation or upload.

### Management API TLS

Issue a server certificate from an operator-controlled internal CA. Its DNS
SANs must include at least `iris-server-api`, `iris-server-api.iris`, and
`iris-server-api.iris.svc`. Create the server Secret from its certificate chain
and private key, and expose only the public CA certificate to the console:

```bash
kubectl -n iris create secret tls iris-management-tls \
  --cert=management-server.crt --key=management-server.key \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n iris create configmap iris-management-ca \
  --from-file=ca.crt=management-ca.crt \
  --dry-run=client -o yaml | kubectl apply -f -
```

The private key is mounted only in the server pod. The console receives only
`ca.crt` and verifies `https://iris-server-api:9443`; do not disable hostname
or certificate verification to make a mismatched certificate work.

### Browser-facing console TLS

Create a distinct `iris-console-tls` Secret for the browser listener. The
certificate SAN must contain the exact DNS name or IP address operators use in
the Console URL; the management Service names belong only in the separate
management certificate above. For example, this creates a development
self-signed identity for a reserved Console DNS name:

```bash
CONSOLE_DNS=iris-console.example.com
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
  -subj "/CN=${CONSOLE_DNS}" \
  -addext "subjectAltName=DNS:${CONSOLE_DNS}" \
  -keyout console-server.key -out console-server.crt
kubectl -n iris create secret tls iris-console-tls \
  --cert=console-server.crt --key=console-server.key \
  --dry-run=client -o yaml | kubectl apply -f -
```

For an IP URL, issue a certificate with
`subjectAltName=IP:<reserved-console-ip>` instead. Use a certificate signed by
a CA trusted by operator browsers in production; a self-signed example must be
explicitly trusted before browsers will accept it.

The Secret is mounted read-only only in the Console pod. On startup the
Console normally asks the authenticated, CA-verified management API whether a
custom browser identity is active. A custom identity is atomically written to
`/run/iris/console-cert.pem` on the Console's memory-backed `emptyDir`. If the
server tier is unavailable during a cold start, or reports that the default is
active, Console validates and copies `iris-console-tls` into that runtime file
and can still serve local health and static content. Invalid authenticated API
responses do not trigger this fallback. The default private key never enters
the image, PVC, ConfigMap, management API, or server pod.

### Observability bearer token

Prometheus `/metrics` has its own scoped principal. Provision current and
previous files even when `IRIS_OBSERVABILITY` is initially disabled, so
enabling it later cannot accidentally create an anonymous scrape endpoint:

```bash
umask 077
mkdir -p iris-observability-auth
openssl rand -hex 32 > iris-observability-auth/current
: > iris-observability-auth/previous
kubectl -n iris create secret generic iris-observability-auth \
  --from-file=current=iris-observability-auth/current \
  --from-file=previous=iris-observability-auth/previous \
  --dry-run=client -o yaml | kubectl apply -f -
```

The Secret is mounted read-only only in the server pod. Its scope is
fixed by the server-side consumer as `observability`, so neither raw value is
accepted by the management API. Raw token files also work directly with
standard Prometheus file-based authorization:

```yaml
scrape_configs:
  - job_name: iris
    scheme: https
    authorization:
      type: Bearer
      credentials_file: /run/secrets/iris-observability-auth/current
    tls_config:
      ca_file: /run/secrets/iris-catalog-ca/ca.crt
      server_name: <certificate DNS name or IP SAN>
    static_configs:
      - targets: ['<server-external-ip>:9101']
```

Mount the token and catalog CA at the paths used by your Prometheus deployment;
the paths above are examples. To rotate without interrupting scrapes, copy the
old raw `current` value to `previous`, write a newly generated raw value to
`current`, and re-apply the Secret. Wait for the projected files to update (or restart only
`iris-seed-server`), move every scraper to the new token, verify a scrape, then
empty `previous` and re-apply. The server rereads both files on each request;
missing, malformed, or weak credentials fail closed.

### Optional OTLP collector headers

Prometheus pull authentication above is separate from authentication that IRIS
may send with outbound OTLP pushes. Put the latter in the optional, server-only
`iris-otlp-headers` Secret. Its `headers` key uses the same comma-separated
`Name=Value` syntax as `IRIS_OTLP_HEADERS`; do not put the value in a ConfigMap,
URL, or command argument:

```bash
umask 077
mkdir -p iris-otlp-headers
read -rsp 'OTLP Authorization header value: ' IRIS_OTLP_AUTH_VALUE; echo
printf 'Authorization=%s\n' "$IRIS_OTLP_AUTH_VALUE" > iris-otlp-headers/headers
unset IRIS_OTLP_AUTH_VALUE
kubectl -n iris create secret generic iris-otlp-headers \
  --from-file=headers=iris-otlp-headers/headers \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n iris rollout restart deployment/iris-seed-server
```

When this Secret is absent, the optional projection is empty and IRIS sends no
collector-authentication header. When it is present, the OTLP endpoint must be
HTTPS. Remove or replace the Secret and restart only the server Deployment to
revoke or rotate it.

Protect and back up the age identity, both bearer-token pairs, optional OTLP
header file, and TLS private keys; none are generated by kustomize or stored in
this repository.

## Configure and deploy

1. Reserve stable external IPv4 addresses using the mechanism for your cluster,
   such as cloud LoadBalancer annotations or a MetalLB address pool.
2. Replace `REPLACE_WITH_STATIC_EXTERNAL_IP` and
   `REPLACE_WITH_AGE_RECIPIENTS` in `iris-seed-server.env`, and set its full
   `IRIS_CONSOLE_URL` to the browser-facing Console Service URL.
3. Review the PVC size, resource budgets, NetworkPolicies, and both generated
   ConfigMap inputs. The checked-in CPU and memory values are initial guardrails,
   not measured fleet-capacity claims.
4. Replace the two fail-closed image digest mappings, then render and apply:

```bash
kubectl kustomize kubernetes > /tmp/iris-rendered.yaml
kubectl apply -k kubernetes
kubectl -n iris rollout status deployment/iris-seed-server
kubectl -n iris rollout status deployment/iris-console
```

`iris-seed-server.env` and `iris-console.env` become content-hashed ConfigMaps.
Changing one and re-applying rolls only the Deployment that consumes it. Secret
values are separate projected files and never belong in these env files.

The server init container runs `iris-bootstrap` idempotently against its PVC.
The server startup and readiness probes call `/readyz`, which checks only the
tracker, catalog, artifact, and management-API listeners owned by that pod. Its
liveness probe calls `/healthz`. The console has independent HTTPS probes on
its own `/readyz` and `/healthz`; a cold or restarting server may make an API
request return 503, but cannot prevent the console pod from becoming ready.

## Operate

Inspect both tiers independently:

```bash
kubectl -n iris get pods,svc,pvc,networkpolicy
kubectl -n iris logs deployment/iris-seed-server -c iris
kubectl -n iris logs deployment/iris-console -c console
curl -fsS --cacert /secure/path/catalog-ca.crt \
  https://<server-external-ip>:9101/readyz
curl -fsS --cacert /secure/path/catalog-ca.crt \
  https://<server-external-ip>:9101/healthz
curl -fsS --cacert /secure/path/console-ca.crt \
  https://<console-address>:8080/readyz
```

`/readyz` is a non-disclosing dependency/readiness result and may answer 503
with only `{"ok":false}`; inspect the server log for the failing listener.
`/healthz` is the local liveness signal. Do not use management API health as an
external monitor: port 9443 is intentionally internal.

Images uploaded through the console are written by the server under
`/data/images`. To stage an operator-managed image directly, copy it to the
server pod without attempting a disallowed ownership change, then publish it:

```bash
POD="$(kubectl -n iris get pod -l app.kubernetes.io/name=iris-seed-server \
  -o jsonpath='{.items[0].metadata.name}')"
kubectl -n iris cp --no-preserve image.bin "$POD:/data/images/image.bin"
kubectl -n iris exec deployment/iris-seed-server -- \
  iris-publish /data/images/image.bin
```

### Operator-supplied device artifacts

The server regenerates derivable Guest Shell assets at startup. The two IOx
packages and XR appmgr RPM are built out of tree and must be copied with their
adjacent provenance manifests to the server PVC after each package rebuild.
Use temporary filenames and publish each manifest last:

```bash
POD="$(kubectl -n iris get pod -l app.kubernetes.io/name=iris-seed-server \
  -o jsonpath='{.items[0].metadata.name}')"
for f in iris-arm64.tar iris-amd64.tar iris-xr.rpm; do
  [ -f "artifacts/$f" ] || continue
  test -f "artifacts/$f.manifest" || exit 1
  kubectl -n iris cp --no-preserve "artifacts/$f" "$POD:/data/artifacts/.$f.next" || exit 1
  kubectl -n iris cp --no-preserve "artifacts/$f.manifest" "$POD:/data/artifacts/.$f.manifest.next" || exit 1
  kubectl -n iris exec "$POD" -- rm -f "/data/artifacts/$f.manifest" || exit 1
  kubectl -n iris exec "$POD" -- mv "/data/artifacts/.$f.next" "/data/artifacts/$f" || exit 1
  kubectl -n iris exec "$POD" -- mv "/data/artifacts/.$f.manifest.next" "/data/artifacts/$f.manifest" || exit 1
done
kubectl -n iris exec "$POD" -- ls -la /data/artifacts
```

Back up the PVC and the age identity together, plus both operator-managed token
pairs and both TLS identities. Changing the server external IP requires
coordinated device trust and torrent announce updates; changing only the
Service address leaves the existing certificate and announce URLs stale.
The tracker listener on TCP 6969 is HTTPS and terminates TLS in the server pod
with that same device-pinned certificate; the LoadBalancer is layer 4 and must
not terminate or replace it.
