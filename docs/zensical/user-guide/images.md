<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Publish and verify images

Publishing turns an image file on the server into a catalog entry that devices
can receive. The server hashes the file, builds a private torrent, starts
seeding it, and saves the entry. Publish an image before you assign it.
`.bin`, `.iso`, `.tar`, and `.rpm` images all travel the same path.

## Where the server keeps images

| Image root | Variable | What it holds |
| --- | --- | --- |
| Uploads volume | `IRIS_IMAGES_DIR`, default `/var/lib/iris-images` | Files you uploaded in the Console. A catalog delete unlinks a file here. |
| Import root | `IMAGES_ROOT`, default `/opt/images` | The host tree `IRIS_IMAGE_ROOT`, mounted read-only. Files you placed on the host yourself. |

Both roots are scanned recursively. A publish happens in place: the seeder
reads the image where it sits, and the `.torrent` goes under the state
directory. See [Data formats and states](../reference/state-and-data.md).

!!! warning "Reseeding on restart trusts the recorded directory"

    On restart, the server reseeds each image from its catalog entry's
    recorded `source_dir`. If that field is missing or its directory is
    unavailable, the server searches both image roots for a file with the
    entry's filename instead. The seeder runs with `bt-seed-unverified`, so a
    wrong directory would serve the wrong bytes under a piece hash that still
    matches. Keep `source_dir` accurate, and do not leave two files with the
    same name under different roots.

!!! warning

    The host tree behind `IRIS_IMAGE_ROOT` must be readable and traversable
    by uid `10001`. A `755` tree is fine; a `700` tree owned by root fails to
    publish and seed. See
    [Check the host before you install](../install/check-the-host.md).

## In the Console

### Upload a file

1. Open the Images screen and pick or drop one or more files.
   Each file gets its own row with a progress bar, the publish state, and then
   the Bulk Hash result, the checksum Cisco publishes for an image.
2. Watch the rows.
   Finished rows fade out. A failed row stays, naming its error, until you
   dismiss it.

The cap is 4 GiB per file, and the browser refuses a larger one.

### Import a file already on disk

The **Import from disk** panel lists image files present on the server but
missing from the catalog.

1. Choose a file.
   IRIS publishes it where it sits and records the attempt in Audit as
   `image_import`, with `result=fail` and a reason for a rejection.
2. Read the Bulk Hash result.
   An import runs the check at once, whatever the schedule says.

A grayed-out file carries its reason. See
[Why a file is not offered](#why-a-file-is-not-offered).

## From the command line

`iris-publish` is the command behind every publish, run inside the server
container. See [Helper commands](../reference/tools.md).

### On one Docker host

```bash
docker compose -f server/docker-compose.yml exec iris \
  iris-publish /opt/images/iosxe/c9300/<image>.bin
```

### On separate Docker hosts

On the server host:

```bash
docker compose --env-file server/server.env \
  -f server/docker-compose.server.yml exec iris \
  iris-publish /opt/images/iosxe/c9300/<image>.bin
```

### On Kubernetes

Copy the file into the server pod, then publish it there.

```bash
POD="$(kubectl -n iris get pod -l app.kubernetes.io/name=iris-seed-server \
  -o jsonpath='{.items[0].metadata.name}')"
kubectl -n iris cp --no-preserve <image>.bin \
  "$POD:/data/images/<image>.bin"
kubectl -n iris exec deployment/iris-seed-server -- \
  iris-publish /data/images/<image>.bin
```

## With the API

| Route | What it does |
| --- | --- |
| `PUT /api/v1/images/upload/<filename>` | Streams the body into the uploads volume and starts a publish job. Answers 413 for a missing body or one over 4 GiB. |
| `POST /api/v1/images/import` | Publishes a file already on disk in place. |

Both routes need an authenticated session, and `POST` also needs the
cross-site request forgery (CSRF) header. The import route checks the identity
of the candidate file: a path that merely starts inside a root is refused with
400. See [Console API](../reference/console-api.md).

## What you see

A publish job moves through `publishing`, then `verifying` while the Bulk Hash
check runs, then `done`. `error` means the publish itself failed. A `done` job
can still report a failed check, so read its verification outcome, image state,
and message. Jobs are held in memory and disappear on a server restart.

| Verdict | Meaning |
| --- | --- |
| `verified` | The image's `sha512` matches the feed row. |
| `mismatch` | The feed row disagrees. The image is quarantined. |
| `not in feed` | No feed row matches the image by file name and size, or by file name alone against a row that publishes no size. Expect this for an image you built yourself. |

Each verdict records when it was checked, Cisco's publish date for the matched
row, and the run that produced it: `scheduled`, `manual`, or `offline`.

## Check images against the Cisco Bulk Hash feed

*Settings → Image verification* compares each catalog image's `sha512` against
the feed Cisco publishes. IRIS verifies the feed's detached signature with the
public key from a Cisco certificate pinned in the repository before it parses a
row. A fetch, signature, or parse failure leaves every stored verdict as it is.

The schedule has three modes: **off**, the default, **daily**, and **weekly**.
Both timed modes fire at an hour you choose in UTC, and weekly anchors to
Monday. A slot the server was down for is skipped.

**Refresh now** in the same pane runs the check at once. When a run is already
in progress, the button and the API both say so instead of starting a second.

A server with no internet access uploads the feed archive instead. The same
pane takes a raw `.tar` of up to 256 MiB and runs the identical signature check
and parse.

The status line shows the last run's time, source, outcome, and its matched,
mismatched and not-in-feed counts. Every run is audited as `bulkhash-refresh`,
with the operator as the actor for a manual refresh or an offline upload.

## Release a quarantine

A quarantined image is an image that failed the Cisco hash check and is held
back from devices. A `sha512` mismatch stops seeding, blocks new assignments,
and unassigns the image from every device that already had it approved. Seeding
stays stopped across container restarts.

From the image's detail view, **Release** runs the `sha512` comparison again:

- It now agrees, because you replaced the file with a corrected copy: the
  quarantine lifts and the verdict becomes `verified`.
- It still disagrees: type the image's own filename to confirm an override. The
  override is audited as a distinct action, permits assignment, and leaves the
  verdict at `mismatch`. A later run with that same mismatch leaves the release
  in place; a different mismatch re-quarantines the image.

Either release also puts the image back into the origin seeder, the server's
own copy of the image and the first source in the swarm, from the directory the
entry recorded. The response says whether seeding resumed. A re-add fails when
the seeder is unreachable or that directory is gone; the failure is audited,
the release stays in force, and the next container restart re-seeds the image.

## Why a file is not offered

A file reaches the **Import from disk** panel only when it ends in `.bin`,
`.iso`, `.tar`, or `.rpm`, its filename uses only the characters
`A-Za-z0-9._-`, it is not a dotfile, a sidecar `.torrent` or an upload
temporary, and its resolved path is still inside the root it was found under.
Discovery resolves each candidate to its real path and keeps it only when that
real path still lands inside the root it was found under, so a symlink cannot
pull a file from outside the set. Other files are hidden. Three more reasons are listed grayed out and named.

| Reason | What it means | What to do |
| --- | --- | --- |
| `already published` | The derived catalog id is already in the catalog, or a publish for that id is in flight. IRIS strips `.SPA.bin` or `.bin` when it derives the id, so `foo.bin` and `foo.SPA.bin` are one catalog id. | Nothing. The image is in the catalog under its derived id. |
| `ambiguous name in more than one location` | The same basename, or the same derived id, exists under more than one root. IRIS refuses rather than guess which file the entry means. | Remove or rename the duplicate so one file claims the id, then check the panel again. |
| `not readable by the server` | The file exists but uid `10001` cannot open it. | Fix ownership so uid `10001` can read the file and traverse its directory, then check the panel again. |

## Rebuild the catalog from images on disk

A catalog reset leaves the image files on disk. The **Import from disk** panel
then lists every image under either root that is missing from the catalog.
Import each file where it sits, so nothing is copied.

## Related

- [Stage your first image](first-image.md)
- [Assign images and check staging status](assignments.md)
- [Find your way around the Console](console.md)
- [Console API](../reference/console-api.md)
- [Back up and restore](../admin-guide/backups.md)
