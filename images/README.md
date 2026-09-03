# `images/`

Local storage for the firmware images intelligent-release-image-staging (IRIS)
distributes. Nothing in IRIS requires this directory — it is a convenient place
to drop images on a developer machine or a small lab server.

IRIS publishes four Cisco software formats, and any of them may live here:

| Format | Typical platform |
| --- | --- |
| `.bin` | IOS-XE (Catalyst 9300, Catalyst 8000, WLC) |
| `.iso` | IOS-XR |
| `.tar` | IOS-XE / IOS-XR bundles |
| `.rpm` | IOS-XR packages |

Organise them however you like; a common layout is one subdirectory per family
(`ios-xe/`, `ios-xr/`).

**The image binaries are intentionally NOT committed** — they are large and
Cisco-proprietary. `.gitignore` ignores **everything under `images/` except
this README**, so any format you drop here stays out of git.

On a server host the canonical location is the tree bind-mounted read-only into
the container at `/opt/images` (`IRIS_IMAGE_ROOT` on the host, `IMAGES_ROOT`
inside). It is scanned recursively by the console's *Import from disk* panel,
and publishing from it seeds in place — nothing is copied and the tree stays
read-only. See
[Image path variables](../docs/zensical/reference.md#image-path-variables) and
[Importing images already on disk](../docs/zensical/console.md#importing-images-already-on-disk).

The host tree must be readable and traversable by uid `10001`; a `700`
root-owned tree fails to publish and seed.
