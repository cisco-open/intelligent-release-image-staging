<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Install on one Docker host

At the end of this page, the server and the Console run under Docker Compose on
one host, the two public signing roots are installed, and you have an
administrator account. Run every command from the repository root on the server
host.

Skip this page if the Console runs on its own host, covered by
[Install on separate Docker hosts](separate-docker-hosts.md), or if you deploy
to a cluster, covered by [Install on Kubernetes](kubernetes.md).

## Before you start

- [Check the host before you install](check-the-host.md).
- [Build the server and Console images](build-images.md).
- [Download the tools that build device packages](build-tools.md), including the
  amd64 `aria2c` client.
- [Create the two offline signing keys](signing-roots.md), then copy their public
  halves to a reviewed directory on this host, such as `$HOME/iris-roots`.

## Configure the server

1. Create the age identity that encrypts server state and export the settings
   Compose reads:

```bash
umask 077
mkdir -p ~/.config/iris
age-keygen -o ~/.config/iris/age.txt
age-keygen -y ~/.config/iris/age.txt

export IRIS_HOST_IP="<server-ip>"
export IRIS_AGE_KEY_FILE_HOST=$HOME/.config/iris/age.txt
export IRIS_AGE_RECIPIENTS="<primary-age-public-key>"
```

`IRIS_HOST_IP` is the address devices use to reach the server, and
`IRIS_AGE_RECIPIENTS` has to contain the public half of the key in
`IRIS_AGE_KEY_FILE_HOST`. Keep the private key outside the checkout. A production
deployment lists a second age key too, held by someone else:

```bash
export IRIS_AGE_RECIPIENTS="<primary-age-public-key>,<second-age-public-key>"
```

You can add a recovery recipient later with `iris-bootstrap --rekey`.

2. Put the same settings in the git-ignored `server/.env`, one plain
   `NAME=value` line each, without `export` and without the private key. Load
   that file before you run host helpers:

```bash
set -a
. server/.env
set +a
```

Use an absolute path for `IRIS_AGE_KEY_FILE_HOST`. Shell exports override
`server/.env`, so keep the two consistent.

Compose publishes the Console only on `IRIS_HOST_IP`. Restrict its TCP 8080
firewall rule to trusted operator sources. The Compose project name is `server`,
so the named volumes keep the `server_` prefix. See
[Server configuration](../reference/server-configuration.md).

## Give the runtime user the host paths

The server and the Console run as the fixed uid and gid `10001`. Give that uid
the age identity file and a writable artifacts directory before the first start,
and again whenever either one is recreated:

```bash
mkdir -p artifacts
chmod 600 "$IRIS_AGE_KEY_FILE_HOST"
sudo chown 10001 "$IRIS_AGE_KEY_FILE_HOST"
sudo chown -R 10001:"$(id -g)" artifacts && sudo chmod -R g+w artifacts   # or "$IRIS_ARTIFACTS_HOST_DIR"
```

Keep the age identity at mode `600` or `400`. `IRIS_ARTIFACTS_HOST_DIR` defaults
to the repository's `artifacts/` directory; point it elsewhere and you create and
chown that directory instead. For a restored volume, see
[Back up and restore](../admin-guide/backups.md). For Prometheus scraping, create
the scrape token as described in
[Set up certificates and tokens](certificates-and-tokens.md).

## Start the server

1. Run the helper, pointing it at the directory that holds the two reviewed
   public roots:

```bash
IRIS_INSTRUCTION_ROOTS_DIR=/path/to/reviewed/roots tools/start-compose-server.sh
```

The helper bootstraps encrypted configuration, installs the two public roots,
starts both containers, and builds the device packages, including the IOS-XR
appmgr package unless `IRIS_SKIP_XR` is set.

2. Check its exit code. A nonzero exit with the stack still running means a
   package build failed. Fix the reported problem, then rebuild as described in
   [Build and publish the device packages](device-packages.md).

!!! warning "Do not start a fresh configuration volume with docker compose up alone"
    Missing encrypted state makes the entrypoint fail closed and restart-loop.
    Use `tools/start-compose-server.sh`. Never force-reset a deployment to
    resolve a missing file or package: keep its volumes, identity, and
    certificates, and follow [Back up and restore](../admin-guide/backups.md).
    For the symptom and the repair, see
    [Troubleshoot: symptoms and first steps](../user-guide/troubleshooting.md).

## Install the two public roots by hand

Do this only when you started the stack some other way.

1. Install the roots into the config volume:

```bash
docker compose -f server/docker-compose.yml run --rm \
  -v "$HOME/iris-roots:/pub:ro" --entrypoint sh iris -c \
  'install -d -m 0755 "$IRIS_CONFIG/instr" "$IRIS_CONFIG/instr/roots.d" && \
   install -m 0644 /pub/*.pub "$IRIS_CONFIG/instr/roots.d/"'
```

2. Confirm the result:

```bash
docker compose -f server/docker-compose.yml exec iris \
  sh -c 'ls -l "$IRIS_CONFIG/instr/roots.d"'
```

Two `.pub` files are listed, one per signing root.

## Create the console admin

Open `https://<server-ip>:8080/` and claim the administrator account with the
first-run credential. Whoever reaches a brand-new Console first can claim that
account, so do this straight after deployment and keep port 8080 on a trusted
management network. The full step is in [Sign in for the first time](first-sign-in.md).

## Verify

```bash
docker compose -f server/docker-compose.yml ps
```

- The server and the Console are both up.
- `https://<server-ip>:8080/`, or the host port set by `IRIS_GUI_PUBLISH`, loads
  the Console sign-in page. Its default browser certificate is covered by
  [Set up certificates and tokens](certificates-and-tokens.md).
- `$IRIS_CONFIG/instr/roots.d` holds the two public roots, and
  **Settings -> Device packages** reports the packages you meant to build as
  built.

For an authenticated request through the Console address, see
[Verify the installation](verify.md).

## Server-only preview

These three commands give you the server and the Console without signing roots
or device packages. They still need the amd64 `aria2c` client:

```bash
docker compose -f server/docker-compose.yml build --pull
docker compose -f server/docker-compose.yml run --rm iris iris-bootstrap
docker compose -f server/docker-compose.yml up -d
```

## Running a second stack on the same host

A second checkout on the same Docker host needs all of the following:

- A distinct `COMPOSE_PROJECT_NAME` for its network and named volumes.
- Distinct `IRIS_CONTAINER` and `IRIS_CONSOLE_CONTAINER` names.
- A separate `IRIS_ARTIFACTS_HOST_DIR`, age identity, and configuration.
- Nonconflicting host bindings for every published port. Setting
  `IRIS_GUI_PUBLISH` changes only the Console port; server mappings still use
  6969, 8443, 8000, 6881, and 9101. Use a reviewed Compose override or a separate
  host, and make the advertised catalog, tracker, and seeder endpoints match.

`IRIS_CONTAINER` also selects the server for helpers such as
`tools/apply-assignments.sh` and `tools/check-package-freshness.sh`. Use the same
project and override configuration for every later Compose command.

## Next steps

- [Sign in for the first time](first-sign-in.md)
- [Turn on instruction signing](activate-signing.md)
- [Set up certificates and tokens](certificates-and-tokens.md)
- [Build and publish the device packages](device-packages.md)
- [Verify the installation](verify.md)
