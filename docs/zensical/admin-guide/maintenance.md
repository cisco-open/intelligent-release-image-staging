<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Routine maintenance tasks

Three jobs that come up now and then: send the audit trail off the server, size
a request budget for the API, and get back into the Console when locked out.

## Export the audit trail off the server

`audit.jsonl` records administrative and workflow actions. Export a copy off
the server.

### In the Console

1. Open **Settings → Audit export**.
2. Enter the SCP destination: host, port, user and remote path.
3. Enter the age recipient, the public key each exported file is encrypted to.
4. Enter the SCP password, then save the sub-page.
5. Choose **Export now** for a single run, or turn on **Export daily**.

### What you see

The status line shows the destination, the schedule and the last run: `ok`
with the filename, or `fail` with the reason. Each run is written to the audit
trail as `audit_export`, in a file named `audit-<utc>-<suffix>.jsonl.age`.
Search the action and device fields.

!!! warning "The destination host key is pinned on the first export"
    Later exports fail if that key changes. Delete
    `audit-export-known-hosts`, in the server state directory, after a
    planned host rebuild.

## Size the API request budget

One request budget covers the Console API, for every user, session and host.
It is off by default. Set the rate and burst in
[Server configuration](../reference/server-configuration.md).

### Measure, then choose

1. Wait for a quiet window, with no other work running against the server.
2. Run the API coverage harness from [Helper commands](../reference/tools.md)
   against a fleet the size you expect.
3. Read the slowest phase that finished cleanly. That rate, in requests per
   second, is your ceiling.
4. Set the budget to a fraction of that ceiling, plus a burst of a few requests.
5. Put the values in the deployment's environment file, then restart the server.

A rejected request gets an HTTP 429 with a `Retry-After` header; see
[Automate with the API](../user-guide/automation.md).

## Reset the admin account when you are locked out

Use this when nobody can sign in to the Console. It runs on the server host,
not in the browser. Type the new password when it asks:

```bash
docker compose -f server/docker-compose.yml run --rm iris iris-gui-admin "<username>"
```

On separate Docker hosts, run the same command on the server host, with that
layout's compose file and environment file.

!!! warning "Keep the password off long-lived containers"
    To set the password without a prompt, pass `IRIS_GUI_ADMIN_PASSWORD` on
    this one-shot command only. Never add it to the Compose `environment:`
    block, or a long-running container holds the password for as long as it
    runs.

The reset drops every open session. A password change made inside the Console
keeps that session.

## Related

- [Find your way around the Console](../user-guide/console.md)
- [Server configuration](../reference/server-configuration.md)
- [Automate with the API](../user-guide/automation.md)
- [Back up and restore](backups.md)
- [Security model and trust boundaries](../architecture/security-model.md)
