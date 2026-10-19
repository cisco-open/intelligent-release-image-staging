<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Install IRIS with the Ubuntu .deb package

The Ubuntu 24.04 amd64 `.deb` installer builds the server, Console, both IOx
architectures, IOS-XR RPM and Guest Shell bundles. It installs the tools it needs,
creates the server's keys, and completes local signing approval by default.
Run it over SSH or in a local terminal. You create your Console account yourself.

Use `irisctl setup` for Docker on one host, separate Docker hosts, or Kubernetes.
It creates and approves the signing keys, starts instruction signing, and
prepares the device packages automatically.

!!! note "Choose the IRIS installer release"
    Select a release containing `iris-installer_*_amd64.deb`, `release-auth.py`,
    and `attestations.jsonl`. The separate `aria2c-*` releases provide the
    transfer clients.

## Download and authenticate

The release workflow supplies GitHub artifact attestations. Verify the package
before installation; a checksum alone does not authenticate its publisher.
Use GitHub CLI with `gh attestation verify` support. Select the release tag and
its full source commit from the
[public releases](https://github.com/cisco-open/intelligent-release-image-staging/releases).
Replace both placeholders before running:

```bash
tag=vYYYY.MM.DD
commit=<full-40-character-source-commit>
repo=cisco-open/intelligent-release-image-staging
mkdir iris-download
gh release download "$tag" --repo "$repo" --dir iris-download
gh attestation verify iris-download/release-auth.py --repo "$repo" \
  --bundle iris-download/attestations.jsonl \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --cert-identity "https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag" \
  --source-ref "refs/tags/$tag" --source-digest "$commit" \
  --signer-digest "$commit" --deny-self-hosted-runners
```

Continue only after verification succeeds. Then authenticate the complete
inventory and every asset, including the `.deb` itself:

```bash
python3 iris-download/release-auth.py verify --directory iris-download \
  --tag "$tag" --commit "$commit"
```

Stop if verification fails. The attestation binds the downloaded bytes to the
GitHub-hosted release workflow and the selected source commit. The release also
includes the matching aria2 source archive, licenses, both client binaries,
and source inventories. See GitHub's
[verification reference](https://cli.github.com/manual/gh_attestation_verify).

## Install the package

Use an Ubuntu host with a synchronized clock and network access for builds and
dependencies. Install the authenticated package:

```bash
sudo apt install ./iris-download/iris-installer_*_amd64.deb
```

## Guided local setup

Run this as your normal user, without `sudo`:

```bash
irisctl setup
```

Automatic key setup is the default (`--key-mode automatic`). Setup has four steps:

1. Review the server and Console addresses, then confirm **Start setup?**
2. Setup creates protected local signing and recovery keys, then builds the server.
3. It approves that server's signing request and finishes the device packages.
4. Open the displayed Console address and create your administrator account.

You do not choose or type signing-key passphrases. Setup generates a separate
strong random passphrase for each signing key and stores them in mode `0600` files.
The owner-only key folder is mode `0700`, outside deployment storage and backups.
Its default is `~/.local/share/iris-setup-keys/<instance>`; setup prints the path.
Use `--key-directory` to choose another protected location. Your operating-system
password for `sudo` and the Console administrator password remain separate.

Keeping keys and their passphrases on this host means a host compromise can expose
both. Keep a secure independent copy of the entire key folder, including passphrase
files and `recovery.age`. The deployment backup does not include these private setup keys.

Rerun the same command with the same `--instance` or `--state-dir` to continue.
Automatic setup checks and reuses its recorded keys. Existing manual keys are
never replaced or unlocked automatically: use `--key-mode manual` and their
original `--key-directory`, then enter their passphrases when OpenSSH asks.
Manual mode also lets you choose key passphrases for a new installation.
Add the layout options below for split Docker or Kubernetes; setup supports all three layouts.

Choose a new instance name and an empty state directory. Existing deployments
are refused, not adopted. Restrict access to the Console before exposing its
first-account claim. The installer does not select your NTP source or configure
your organization's firewall.

## Choose the layout

For a named installation, start with the command below. Append the options for
your layout to the same command. Replace the placeholders first. Setup supplies
the signing keys and recovery recipient.

```bash
irisctl setup --instance my-iris \
  --state-dir /var/lib/iris-installer/my-iris \
  --host <device-facing-ipv4>
```

Add `--observability` to a new `irisctl setup` command to
enable authenticated `/metrics` on port 9101 in any layout. It is off by default.
The choice is saved for resume. Set the scraper token through
[Rotate telemetry credentials](../admin-guide/console-credentials.md#replace-the-metrics-scraping-token).

### Docker on one host

The default is `--target docker`. The Console listens on `127.0.0.1:8080` over
HTTPS. Set `--console-bind <management-ipv4> --console-port <port>` when exposing
it on an approved management network. Existing Docker engines are preserved.

### Use an existing image folder

For Docker, add `--image-root /opt/images` when installing to use that host
folder. Otherwise, the installer uses `images` inside its state directory.
Uploads from the Console stay in a separate Docker volume.

To connect a folder to an existing one-host Docker install:

```bash
sudo irisctl image-root --state-dir /var/lib/iris-installer/my-iris \
  --path /opt/images --allow-downtime
```

The command checks access, records the folder and briefly restarts IRIS. The
current import folder must be empty. It leaves permissions and files unchanged.
If interrupted, rerun the same command.

Use a dedicated folder: backups include it, and a restore can replace its
contents. The server reads it through a read-only mount. For a separate disk,
choose a folder inside that disk, not the mount point itself.

### Docker on separate hosts

Add:

```text
--target docker-split
--console-ssh-host <console-host-ipv4>
--console-ssh-user root
--console-ssh-key /root/iris-console-access
--console-known-hosts /root/iris-console-known-hosts
--console-state-dir /etc/iris/my-iris-console
--console-bind <console-management-ipv4>
--console-port 8080
```

The remote host must run Ubuntu 24.04 amd64, with Python 3, SSH access and
noninteractive root access through `sudo`. The installer adds missing Docker,
Compose and OpenSSL dependencies without replacing an existing engine.
Provision a dedicated SSH key and verify its host key independently.
Local transport files must be root-owned;
the private key must be mode `0600`. The remote state parent must already exist
and be root-owned; the instance directory must be new. The installer pins the
SSH settings and exact Console image for later maintenance.

Allow the Console to reach the server's device-facing address on authenticated
HTTPS 9443. Only the Console's credentials, public management CA and browser
identity go to that host, not server data, the age identity or management private
key. Keep the controller's SSH access available for backup and rotation.

### Kubernetes

Use an existing cluster with a suitable StorageClass, NetworkPolicy enforcement
and a LoadBalancer implementation that can assign the selected external IPs.
The installer does not create a cluster or replace its networking/storage setup.
It preserves an existing `kubectl` or k3s client and installs a pinned `kubectl`
when neither exists. The client must be within one minor version of the API
server; an incompatible existing client is refused, not replaced.
Add:

```text
--target kubernetes
--kubeconfig-path /root/iris-kubeconfig
--kube-context <explicit-context>
--kube-namespace my-iris
--kube-storage-class <existing-storage-class>
--kube-storage-size 20Gi
--kube-registry <registry.example.com/iris>
--kube-console-replicas 2
--console-bind <console-loadbalancer-ipv4>
--console-port 8080
--lifecycle-url https://<controller-management-ipv4>:28443
```

`--host` is the server LoadBalancer address. The kubeconfig must be root-owned,
mode `0600`, and use verified HTTPS. Use a fresh dedicated namespace. Registry
authentication, when needed, comes from `--kube-registry-auth` pointing to a
root-owned, mode `0600` Docker `config.json`. It must contain only static `auths`;
credential helpers are not supported. Only credentials for the selected registry
enter the deployment. Do not put credentials in the registry argument.

The server has exactly one replica and owns the persistent data. The Console
supports one to eight replicas; adding Console pods does not make the stateful
server highly available. Each Console must pass authenticated management checks.
The lifecycle worker runs outside the cluster and uses a deployment-specific
mutual-TLS connection, so it can remain available while pods are stopped.
Allow the server pod to reach the recorded controller address and port.
The server pod receives the public CA and client certificate/key; the CA private
key and worker private key remain on the controller, never in Console pods.
Use `irisctl maintenance` on the controller to check connection certificates.
The `renew-transport` action renews them without replacing their private keys.
See [Rotate deployment trust and keys](../admin-guide/deployment-rotation.md).

For a local single-node k3s lab, replace `--kube-registry` with
`--kube-image-import k3s --kube-node <exact-local-node-name>`. This imports the
built images without changing registry trust. Static storage still requires an
administrator-provisioned PV bound to this namespace's `iris-data` claim.

## Finish setup { #approve-and-resume }

Setup approves its own server signing request, builds and verifies the device
packages, and starts the Console. Open the displayed address and create your
administrator account. Complete the Console setup checks, root attestations,
backup access and renewal arrangements using the
[certificate workflows](../admin-guide/rotations.md).

If setup stops, rerun `irisctl setup` with the same instance, key mode and paths.
Keep the original installer version until setup finishes. It reuses recorded
identities and checks source, topology and resource ownership.
For failed builds, see [Installer command failures](../user-guide/troubleshooting.md#installer-command-failures).

The installer starts a maintenance service after signing approval
and package verification. It starts automatically at boot and creates private,
separate data-backup and encrypted identity-set directories. Local directories
do not protect against loss of the host. Use `--backup-root` and `--recovery-root`
to select existing protected storage, or copy both encrypted sets to independent
storage. Initial storage choices are retained across signing approval.

Use `sudo irisctl maintenance --state-dir /var/lib/iris-installer/my-iris`
to check the worker and its recorded jobs. Its terminal commands also set
recovery-key access and the trusted public backup signer. See
[Back up and restore](../admin-guide/backups.md#console-backup-controls).
`irisctl worker-status` reports service and storage health.

Use [Backup & restore](../admin-guide/backups.md) and
[deployment rotation](../admin-guide/deployment-rotation.md) for managed
maintenance. Keep encrypted copies and a separate recovery key off the controller.
**Restore selected backup** replaces saved data in this same deployment after
checking its current keys and security records. It preserves instruction counters
and stops if the keys have changed. **Extract for isolated recovery** copies
the saved files to a separate folder for inspection.

### Separate key holders

Organizations that keep signing keys on separate offline machines can use the
[separate key holder installation procedure](../reference/manual-installation/offline-approval.md#install-with-separate-key-holders).
That advanced workflow uses `irisctl install` and explicit public approvals.

## If maintenance stops

| Message or symptom | What to do |
| --- | --- |
| A resource differs from recorded installation intent | Check the exact instance, cluster and namespace. Preserve the journal and investigate changes outside the installer; do not delete ownership records to adopt a resource. |
| Writers did not stop cleanly | Keep the failed operation and backup evidence. Inspect the stopped service and outstanding work; forced termination is not a consistent backup. |
| Management credential synchronization needs intervention | Keep the previous credential active. Restore worker/Console connectivity and use the schedule's reconciliation control before retirement. |
| The Kubernetes worker connection certificate expired | Use `irisctl maintenance` on the controller to renew the connection or recover the recorded operation. Preserve its private keys and operation records. |

For interrupted credential replacement, use the
[host recovery procedure](../admin-guide/recovery.md#recover-a-deployment-rotation-while-the-console-is-stopped).
