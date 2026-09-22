<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Build the server and Console images

IRIS ships as two container images: the server and the Console. Build both from
a fresh checkout, for the layout you chose.

## Before you start

- Check out the same IRIS source on every host that builds an image.
- Install Docker Engine and Docker Compose. See [Check the host before you install](check-the-host.md).
- The tested `aria2c` clients are included in the checkout; the build scripts
  verify them against `tools/aria2c.sha256`.
- Run every command from the root of the checkout.

## Build the images

### On one Docker host

Skip this. [Install on one Docker host](one-docker-host.md) runs
`tools/start-compose-server.sh`, which builds both images for you and verifies
the included amd64 `aria2c` client against `tools/aria2c.sha256`.

### On separate Docker hosts

First create and configure `server/server.env` on the server host and
`server/console.env` on the Console host, following
[Install on separate Docker hosts](separate-docker-hosts.md). Compose reads
these files even for a build. That procedure includes the build commands below.

On the server host, which also builds every device package:

```bash
iris_server() {
  docker compose --env-file server/server.env \
    -f server/docker-compose.server.yml "$@"
}

iris_server build --pull
```

On the Console host, which needs no `aria2c` client:

```bash
iris_console() {
  docker compose --env-file server/console.env \
    -f server/docker-compose.console.yml "$@"
}

iris_console build --pull
```

### On Kubernetes

Build on a machine that can push to the registry your cluster pulls from:

```bash
docker build --pull --platform linux/amd64 \
  -f server/Dockerfile \
  -t registry.example.com/iris/server:candidate .
docker build --pull --platform linux/amd64 \
  -f server/Dockerfile.console \
  -t registry.example.com/iris/console:candidate .
docker push registry.example.com/iris/server:candidate
docker push registry.example.com/iris/console:candidate
```

`--pull` re-resolves the server image's base tag instead of reusing whatever
the build host already cached, which can be weeks of security updates behind
that tag.

In `kubernetes/kustomization.yaml`, replace both `registry.example.invalid`
names with your registry and both all-zero digests with the digests the pushes
printed.

!!! warning

    Keep the `digest:` field. A tag can be pointed at different content later.

## Rebuild both images when the client checksum changes

If the `aria2c` checksum changes, rebuild both images and every device package.
See [When to rebuild the packages](device-packages.md#embedded-agent-packages).

## Verify

On one Docker host, check both image tags:

```bash
docker image inspect --format '{{ index .RepoTags 0 }}' iris:latest iris-console:latest
```

For separate hosts, inspect only `iris:latest` on the server host and only
`iris-console:latest` on the Console host. Each host needs its own image.

On Kubernetes, this prints nothing when both registry names are replaced:

```bash
grep -n "registry.example.invalid" kubernetes/kustomization.yaml
```

## Next steps

- [Create the two offline signing keys](signing-roots.md)
- [Install on one Docker host](one-docker-host.md), [on separate Docker hosts](separate-docker-hosts.md), or [on Kubernetes](kubernetes.md)
- [Build and publish the device packages](device-packages.md)
