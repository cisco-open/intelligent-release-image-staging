<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Install with the managed package

The Ubuntu 24.04 amd64 installer candidate builds the server, Console, both IOx
architectures, IOS-XR RPM and Guest Shell bundles. It provisions build dependencies,
creates deployment identities, and pauses for offline instruction-signing approval.
It never creates or signs in to your Console account.

This is a development candidate, not an authenticated public production release.
Obtain a reviewed `.deb` and its source inventory through your approved delivery
process. A checksum alone does not authenticate its publisher. Build instructions
and remaining release gates are in the
[development guide](https://github.com/cisco-open/intelligent-release-image-staging/blob/main/docs/dev/installer.md).

## Prepare once

Use a synchronized Ubuntu controller with network access for source builds and
dependencies. Keep the two offline private roots on the custodian's machine;
provide only their public files and an independently held age recovery recipient.
`irisctl custody-ui` provides the offline signing window.

```bash
sudo apt install ./iris-installer_<version>_amd64.deb
```

Choose a new instance name and an empty state directory. Existing deployments
are refused, not adopted. Restrict access to the Console before exposing its
first-account claim. The installer does not select your NTP source or configure
your organization's firewall.

## Choose the layout

All layouts use these common options; append the layout options below to the
same command. Replace the example addresses and public recipient first.

```bash
sudo irisctl install --instance my-iris \
  --state-dir /var/lib/iris-installer/my-iris \
  --host <device-facing-ipv4> \
  --roots-dir /path/to/two-reviewed-public-roots \
  --recovery-recipient <independent-age-public-recipient> \
  --accept-changes
```

### Docker on one host

The default is `--target docker`. The Console listens on `127.0.0.1:8080` over
HTTPS. Set `--console-bind <management-ipv4> --console-port <port>` when exposing
it on an approved management network. Existing Docker engines are preserved.

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

The remote host needs Docker Compose and Python 3. Provision a dedicated SSH key
and verify its host key independently. Local transport files must be root-owned;
the private key must be mode `0600`. The remote state parent must already exist
and be root-owned; the instance directory must be new. The installer pins the
SSH custody and immutable Console image for later maintenance.

Allow the Console to reach the server's device-facing address on authenticated
HTTPS 9443. Only the Console's credentials, public management CA and browser
identity go to that host—not server data, the age identity or management private
key. Keep the controller's SSH access available for backup and rotation.

### Kubernetes

Use an existing cluster with a suitable StorageClass, NetworkPolicy enforcement
and a LoadBalancer implementation that can assign the selected external IPs.
The installer does not create a cluster or replace its networking/storage setup.
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
protected Docker `config.json`; do not put credentials in the registry argument.

The server has exactly one replica and owns the persistent data. The Console
supports one to eight replicas; adding Console pods does not make the stateful
server highly available. Each Console must pass authenticated management checks.
The lifecycle worker runs outside the cluster and uses a deployment-specific
mutual-TLS connection, so it remains available while pods are stopped.

For a local single-node k3s lab, replace `--kube-registry` with
`--kube-image-import k3s --kube-node <exact-local-node-name>`. This imports the
built images without changing registry trust. Static storage still requires an
administrator-provisioned PV bound to this namespace's `iris-data` claim.

## Approve and resume

Exit `20` means the installer is waiting for offline approval. Take only
`requests/online.pub` from the state directory to the custodian. Approve it in
the custody window or run there:

```bash
irisctl approve-signing --public-key online.pub --root-key /offline/root-a
```

Return only the public certificate to the controller:

```bash
sudo irisctl resume --state-dir /var/lib/iris-installer/my-iris \
  --certificate /path/to/online-cert.pub
```

Resume reuses recorded identities and checks source, topology and resource
ownership. It builds and verifies the device packages before starting the
Console. Exit `21` means you must claim your administrator account yourself.
Exit `22` means the running deployment still needs production review—not that
it is production-ready. Complete root attestations, backup access and renewal
arrangements using the [certificate workflows](../admin-guide/rotations.md).

Use [Backup & restore](../admin-guide/backups.md) and
[deployment rotation](../admin-guide/deployment-rotation.md) for managed
maintenance. Keep encrypted copies and recovery custody off the controller.
Isolated recovery extraction is not an automated restore or service cutover.
