<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Web Console

The console is the preferred operator surface once the server is running. It does not replace the CLI; it wraps common workflows and makes fleet state visible.

## First run

Open:

```text
https://<server-ip>:8080/
```

The server uses a self-signed certificate by default. Create the initial admin in the browser or with:

```bash
docker compose -f server/docker-compose.yml exec iris iris-gui-admin admin
```

## Console areas

| Area | What it does |
| --- | --- |
| Images | Shows published image metadata and staged fleet status. |
| Devices | Lists known devices, platform details, current assignment, and recent reports. |
| Assignments | Maps each device to the image it should stage. |
| Onboarding | Starts and tracks install or undeploy jobs when stage-host credentials are configured. |
| Swarm | Shows peer progress and seeder/device participation. |
| Monitoring | Links to health, swarm, metrics, and recent telemetry. |
| Settings | Shows server configuration, version, and operational settings. |
| Audit | Records administrative and workflow actions. |

## Onboarding from the console

GUI-driven onboarding uses stage-host credentials to run the same install logic that the CLI generates. The sensitive values belong in the console or the server secret store, not in Git. Generated per-device staging files are temporary and swept after their configured age.

## When to use the CLI

Use the CLI when you want a reproducible batch operation from reviewed CSV files. Use the console when you need visibility, one-off onboarding, or fast assignment changes during a lab.

