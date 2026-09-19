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
- Put the `aria2c` client in the checkout. See [Download the tools that build device packages](build-tools.md).
- Run every command from the root of the checkout.

## Build the images

### On one Docker host

Fetch the client, then build both images:

```bash
tools/get-aria2c.sh amd64
docker compose -f server/docker-compose.yml build --pull
```

Compose builds `iris:latest` and `iris-console:latest`. Without Compose, use
those same two tags:

```bash
tools/get-aria2c.sh amd64
docker build --pull --platform linux/amd64 \
  -f server/Dockerfile \
  -t iris:latest .
docker build --pull --platform linux/amd64 \
  -f server/Dockerfile.console \
  -t iris-console:latest .
```

### On separate Docker hosts

On the server host, which also builds every device package:

```bash
iris_server() {
  docker compose --env-file server/server.env \
    -f server/docker-compose.server.yml "$@"
}

tools/get-aria2c.sh amd64
iris_server build --pull
```

On the Console host:

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

In `kubernetes/kustomization.yaml`, replace both `registry.example.invalid`
names with your registry and both all-zero digests with the digests the pushes
printed.

!!! warning

    Keep the `digest:` field. A tag can be pointed at different content later.

## Rebuild both images when the client checksum changes

If the `aria2c` checksum changes, rebuild both images and every device package.
See [When to rebuild the packages](device-packages.md#embedded-agent-packages).

## Verify

On a Docker host, check the tags it built:

```bash
docker image inspect --format '{{ index .RepoTags 0 }}' iris:latest iris-console:latest
```

On Kubernetes, this prints nothing when both registry names are replaced:

```bash
grep -n "registry.example.invalid" kubernetes/kustomization.yaml
```

## Next steps

- [Create the two offline signing keys](signing-roots.md)
- [Install on one Docker host](one-docker-host.md), [on separate Docker hosts](separate-docker-hosts.md), or [on Kubernetes](kubernetes.md)
- [Build and publish the device packages](device-packages.md)
