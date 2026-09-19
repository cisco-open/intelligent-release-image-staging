<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Installer files, staging retention, bootstrap and supervisor internals

This page is for a contributor working on the device installers or the
shared agent runtime under `device/`. It covers detail that does not belong
on an operator-facing page. That detail includes exactly what each installer
writes to a device, how a Guest Shell bundle earns the right to run, and
what the container entrypoint and its supervisor loop do. It also covers the
design notes behind a few rules that platform pages only state. Read
[How the device agent works](../zensical/architecture/device-agent.md)
first; it covers the agent's ordinary check-in loop, one pass of which is a
tick.

!!! note
    IRIS stages images. It never installs, activates, reloads, or changes
    boot variables. See [IRIS documentation](../zensical/index.md).

## What the Guest Shell and router installers push

`device/device-install.sh` (Catalyst 9300 Guest Shell) and
`device/router-install.sh` (Catalyst 8000 router) push the same set of files
to the guest-share root, over an HTTPS copy that a PKI trustpoint, pasted
over SSH first, lets IOS verify.

| File served from the artifact server | Device-side name | Purpose |
| --- | --- | --- |
| staged as `iris-agent-<DEVICE_ID>-<CAP>.conf` | `iris-agent.conf` | the catalog URL, the device id, and an empty `rpc_secret`; the agent fetches the real secret on its first token refresh |
| staged as `rpc-secret-<CAP>` | `rpc-secret` | seeds aria2c's RPC secret; `bootstrap.sh` reconciles it against the config file on every tick |
| `iris-agent.tgz` | `bundle.tgz` | the agent's Python code, `bootstrap.sh`, `guestshell-start.sh`, `rotate-logs.sh`, the peer-transfer hook aria2 calls on each completed download, and an architecture-matched `aria2c`, packed by `tools/make-agent-bundle.sh` |
| the bare server certificate | `iris-catalog.pem` | the pinned TLS trust anchor for the agent's catalog calls |
| (not staged) | `bootstrap.sh` | the EEM entry point itself |

`CAP` is a random 128-bit capability minted for each install run. The staged
copies live under the artifact server's `staging/` prefix and stay
reachable for 3600 seconds, enough headroom for queued fleet work and the
installer's own retries. This capability-bearing surface serves only the
Guest Shell installer; the authenticated device artifact API other clients
use is separate.

The installer also adds one EEM applet:

```text
event manager applet IRIS-AGENT authorization bypass
 event timer watchdog time 60 maxrun 900
 action 100 cli command "enable"
 action 200 cli command "guestshell run bash <fs>guest-share/bootstrap.sh"
```

Every 60 seconds this applet runs `bootstrap.sh` inside Guest Shell.

## What it takes for bootstrap to adopt a new bundle

Before it replaces the running `bundle.tgz`, bootstrap collects the SHA-256
sidecar for the new archive and checks bounded archive and member contents.
It also checks evidence that the bootstrap script and the root of trust
agree with each other. Missing, malformed, or mismatched evidence stops the adoption
and keeps the prior bundle running; dropping an archive by itself is never
enough. Once the evidence checks out, bootstrap makes sure `aria2c` is up
and serving, then runs `iris_agent.py --once`.

A validated bundle plus its SHA-256 sidecar and matching bootstrap and root
evidence is the whole agent upgrade for Guest Shell and router; there is no
separate upgrade command. Re-running the installer script delivers a fresh,
matched set, because it mints a new capability and re-copies everything
together. Re-onboarding from the Console is not the same path: its checks
refuse a device that still carries a live agent, so undeploy a device first,
then onboard it again. See
[Upgrade to a new release](../zensical/admin-guide/upgrade.md) for the
operator procedure.

## Entrypoint and PID 1 on IOx and IOS-XR

Unlike Guest Shell, the IOx and IOS-XR agents run inside a container.
`device/container/entrypoint.sh` is PID 1 (the container's first process) in
the IOx container. IOS-XR uses the same supervisor from the same shared
image, so the same is likely true there too, though only the IOx case is
confirmed directly.

`IRIS_DEVICE_PLATFORM` selects which profile the entrypoint runs: `iox` or
`xr-appmgr`. On first boot, if no configuration already exists on the
persistent mount, the entrypoint writes the deployment values it was given
into `iris-agent.conf`. On every later boot it leaves an existing
`iris-agent.conf` alone.

There is no EEM timer on IOx or IOS-XR. The entrypoint is its own
supervisor: once setup finishes, it becomes a loop that runs the agent once
every `IRIS_TICK_SECONDS` (default 60 seconds).

By default, `IRIS_STARTUP_JITTER` spreads a container's first tick across
the whole tick window, so a fleet of containers that all started in the same
second do not all contact the catalog together. Set it to `0` for a
single-device debug session watching for the first tick.

The IOS-XR profile adds checks the IOx profile does not need. It verifies
the `harddisk:` bind mount before its first write, rejects every IOx SSH and
share variable, and never opens the SSH transport. The shared image still
ships the same client binaries IOx uses for its own device SSH-to-self
connection; IOS-XR never calls them.

## How the supervisor restarts aria2c

A running process does not prove aria2 is answering requests. Guest Shell
bootstrap and the common IOx and IOS-XR supervisor both probe
`aria2.getVersion` on the local RPC port before deciding whether to relaunch
the daemon.

Guest Shell stops a non-serving daemon before it replaces the binary;
otherwise the copy can fail because the old binary is still running. Copy
and launch failures show up in the bootstrap output instead of being
silently dropped.

The container supervisor tracks aria2 by its child process id. To restart
it, the supervisor sends TERM, waits up to five seconds, then sends KILL if
the process has not exited, and reaps it. The container uses the same
shutdown path when it stops. TERM gives aria2 time to save its `.aria2`
checkpoint file, so every launcher enables `--check-integrity`: a resumed
transfer checks its saved pieces and downloads any that are damaged again.
A completed file that is re-added for seeding uses `--bt-seed-unverified`
instead, because its content check already happened and is recorded in the
agent's own state; this avoids a full re-read at startup.

Every aria2 launcher loads the device's pinned `iris-catalog.pem` as its
certificate authority and keeps certificate checking on for tracker
announces on TCP 6969. IOx and IOS-XR attach their bearer credential as a
per-torrent header; Guest Shell sends its credential inside the same
verified TLS transport.

Guest Shell goes one step further: it copies the validated certificate to a
content-addressed path on its executable filesystem and starts aria2
against that fixed copy. Aria2 only reads its certificate authority when it
starts, so overwriting `iris-catalog.pem` at the same path during
re-onboarding would leave an already-running daemon trusting the old
certificate. A changed certificate forces one restart; a certificate that
fails validation is never launched against.

## A busy aria2c can look dead

A daemon built without asynchronous DNS can pause its whole event loop
while it resolves a tracker hostname. During that pause it can accept a
connection without answering the RPC request in time.

The supervisor uses two separate timeouts: one for making the connection,
one for getting a response. A refused loopback connection triggers a
restart right away; a slow reply has to fail a second probe before the
supervisor stops the daemon. This gives a temporary DNS stall room to clear
without losing the transfer. Using the server's address directly in the
tracker URL, described in
[Network ports and flows](../zensical/architecture/network-ports.md), avoids
the hostname lookup that could cause this in the first place.

## Legacy launcher inputs

The old `max_peers` setting is still parsed, for compatibility with earlier
agent versions, but ignored as policy: the agent logs the value-free
`MAX-PEERS-IGNORED` notice once. Guest Shell no longer exports the setting
at all.

Two container variables, `IRIS_MAX_PEERS` and `IRIS_MAX_CONCURRENT`, are
absent from the image's own defaults but still work as provisional launcher
inputs. The agent uses them only until its first successful tick, and no
restored download starts before then. At that first successful tick, the
agent unconditionally writes the verified, signed defaults for the global
options and for every active group, and every `addTorrent` call after that
uses those values. Neither variable has any lasting say over swarm policy.

## Design notes for the routed management type

[Choose a management type](../zensical/install/management-types.md) covers
the routed management type for an operator. Two implementation details sit
underneath it.

The per-device `svi_igp` setting controls whether the SVI joins an interior
gateway protocol. Before it is ever written into a device's configuration,
the installer checks it against a closed set of two values, `none` or
`isis`. This is the same defense against command injection that every
other value interpolated into device configuration on this path gets. A
device record that leaves `svi_igp` blank falls back to the fleet-wide
`SVI_IGP` server environment variable (default `none`); an explicit
`svi_igp=none` on the device overrides a server default of `isis`.

Checking whether IP routing is enabled is not a search for a positive
`ip routing` line, because that line is absent whenever routing is the
platform default, as it is on the IE-3x00. Instead the installer treats an
explicit `no ip routing` line, or a route table that answers in host mode,
as proof that routing is off. A session that never echoes the command back
at all is a transport failure, and the installer reports it as "could not
verify ip routing" rather than misreporting it as a routing problem.

## Test-harness overrides

Production containers reject five variables outright: `IRIS_STAGE_DIR`,
`IRIS_WORK_DIR`, `IRIS_AGENT_CONF`, `IRIS_AGENT_STATE`, and
`IRIS_CATALOG_CA`. Those, together with `IRIS_CONTAINER_TESTING=1` and
`IRIS_TEST_SKIP_MOUNT_CHECK=1`, exist only for the source-level test
harness. Rejecting them in production stops a deployment from redirecting a
multi-gigabyte stage away from the storage policy its platform selected.
See [Device agent configuration](../zensical/reference/device-configuration.md)
for the variables a real deployment uses.

## Related

- [How the device agent works](../zensical/architecture/device-agent.md)
- [Device agent configuration](../zensical/reference/device-configuration.md)
- [Building the device image, IOx wrappers, IOS-XR rpm and aria2c](device-packages.md)
- [Prepare Catalyst 9000 and 8000 devices for Guest Shell](../zensical/install/guest-shell.md)
- [Prepare IE-3x00, Catalyst 9000 and 8000 devices for the IOx app](../zensical/install/iox.md)
