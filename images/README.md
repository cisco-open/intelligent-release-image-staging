# images/

Local storage for the firmware images intelligent-release-image-staging (IRIS) distributes.

- `ios-xe/` — IOS-XE `.bin` images for Catalyst 9300 (and WLC) platforms.

**The image binaries are intentionally NOT committed** (they are large and
Cisco-proprietary); `*.bin` and `images/ios-xe/` are gitignored. On the server
host the canonical location is `/opt/images/iosxe/c9300/`, mounted read-only
into the container.
