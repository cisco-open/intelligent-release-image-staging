<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# IRIS Documentation

IRIS — Intelligent Release and Image Staging — distributes Cisco images and
patches through a private peer-to-peer swarm. Devices verify and stage assigned
images; operators remain responsible for software installation and reloads.

!!! warning "Stage only"
    IRIS never installs or activates a staged software image, changes boot
    variables, or reloads a device. Onboarding deploys the IRIS agent, not the
    software image being staged.

Use the [Console](console.md) for everyday operations and the
[API reference](swagger/index.html) for automation. Server deployment and
offline trust provisioning are separate administrative tasks.

## What IRIS provides

- Image upload/import, device inventory, assignments, and agent lifecycle management.
- Peer-assisted delivery governed by device assignments and peer policy.
- Staging status, transfer measurements, audit events, and optional telemetry export.
- Guest Shell, IOx, and IOS-XR appmgr deployment paths for eligible Catalyst,
  Industrial Ethernet, Cisco 8000, and NCS devices.

Platform family names describe deployment paths, not compatibility with every
model or software release. Check [device requirements](device-agents.md) before
onboarding. Peer delivery depends on connectivity, policy, and available pieces;
it is not a fixed performance guarantee.

## Where to start

| Task | Guide |
| --- | --- |
| Set up IRIS and stage an image | [Getting started](getting-started.md) |
| Manage images and devices | [Console](console.md) |
| Automate operations | [API reference](swagger/index.html), [API testing and limits](api-testing.md) |
| Plan a fleet rollout | [Network workflows](fleet-workflows.md) |
| Choose device connectivity | [Management types](management-type.md) |
| Understand trust and network access | [Architecture](architecture.md), [Security](security.md), [Network ports](network-ports.md) |
| Deploy on separate hosts or Kubernetes | [Docker hosts](docker-hosts.md), [Kubernetes](kubernetes.md) |
| Investigate a problem | [Troubleshooting](troubleshooting.md) |

## Further reference

Use [Operations](operations.md) for recovery and maintenance,
[Reference](reference.md) for configuration and API behavior, and
[Observability](observability.md) for dashboards. [Telemetry export](telemetry-export.md)
explains what transfer measurements do and do not establish.

Implementation and verification details live in [Development](development.md)
and [Validation](validation.md), separately from the operator workflow.
