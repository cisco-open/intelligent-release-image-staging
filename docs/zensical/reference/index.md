<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Look up a setting, route or term

The values you look up: environment variables, API routes, file formats, state
names, helper commands and the words IRIS uses.

!!! note
    IRIS stages images. It never installs, activates, reloads, or changes boot
    variables.

    See [IRIS documentation](../index.md) for the full rule.

## Find the route for a task

Use the Console by hand, and the authenticated `/api/v1` API for automation.
For a sequence you can run, see [Automate with the API](../user-guide/automation.md).

| Task | API |
| --- | --- |
| List images | `GET /api/v1/images` |
| Upload or import an image | `PUT /api/v1/images/upload/{filename}`, `POST /api/v1/images/import` |
| List or add devices | `GET /api/v1/devices`, `POST /api/v1/devices` |
| Set a device's image assignment | `POST /api/v1/devices/{device_id}/assign` |
| Onboard or undeploy the agent | `POST /api/v1/devices/{device_id}/onboard`, `POST /api/v1/devices/{device_id}/undeploy` |
| Read device reports | `GET /api/v1/devices/{device_id}/reports` |
| Read policy or audit history | `GET /api/v1/peer-policy`, `GET /api/v1/audit` |

An assignment update replaces the whole ordered image list. Jobs run in the
background, so follow one until it finishes. For every route with its schemas
and errors, see [Console API](console-api.md). The catalog on port 8443, the
tracker on 6969 and the artifact server on 8000 have their own credentials and
serve the device agent, not your integrations: see
[APIs the device agent uses](device-apis.md).

## Pages in this section

| Page | What it holds |
| --- | --- |
| [Server configuration](server-configuration.md) | Server and Console variables, container paths, credential file formats. |
| [Device agent configuration](device-configuration.md) | Agent variables and keys, installer variables, the files on each platform. |
| [Console API](console-api.md) | Sign-in, tokens, routes by area, request limits, versioning, error bodies. |
| [Roles and sharing-policy API](peer-policy-api.md) | Routes and fields for roles, the named groups of devices that share with each other. |
| [APIs the device agent uses](device-apis.md) | The catalog, tracker, telemetry and artifact listeners, and what each answers. |
| [Data formats and states](state-and-data.md) | Catalog fields, policy fields, CSV columns, device state names. |
| [Telemetry signals](telemetry-signals.md) | Metric families, one attribute table per log event, example records. |
| [Helper commands](tools.md) | Each helper script: what it does, where it runs, which task uses it. |
| [Glossary](glossary.md) | The words IRIS uses, each with its plain meaning. |
| [Cisco references and third-party components](external-references.md) | The Cisco documentation the guides cite, and the third-party parts IRIS ships. |
| [API error codes (problem types)](../problems.md) | Every error code the API returns, what it means, what to do. |
