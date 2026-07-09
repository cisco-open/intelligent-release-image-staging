# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Build the aria2 --input-file for the seeder's startup re-seed: pair each
published torrent in the state dir with the directory that actually holds its
image, by walking the image roots (colon-separated, earlier roots win a basename
collision — callers pass the writable upload dir first). Split out of
seed-launch.sh so this mapping is unit-testable. Stdlib only."""
import glob
import json
import os
import sys


def build(state, images_roots, default_dir):
    """Return a list of aria2 input-file lines (torrent path, then ' dir=<dir>')
    for every state/torrents/*.torrent, resolving each to the directory holding
    its image (via the catalog id->filename map + a walk of images_roots), or
    default_dir if not found."""
    try:
        with open(os.path.join(state, "catalog.json")) as f:
            cat = json.load(f)
        imgs = cat.get("images", {}) if isinstance(cat, dict) else {}
    except Exception:
        imgs = {}
    loc = {}
    for images_root in images_roots.split(":"):
        if images_root and os.path.isdir(images_root):
            for root, _dirs, files in os.walk(images_root):
                for f in files:
                    loc.setdefault(f, root)
    lines = []
    for t in sorted(glob.glob(os.path.join(state, "torrents", "*.torrent"))):
        iid = os.path.basename(t)[:-len(".torrent")]
        fn = (imgs.get(iid) or {}).get("filename")
        d = loc.get(fn) if fn else None
        if d is None:
            d = default_dir
        lines.append(t)
        lines.append(" dir=" + d)
    return lines


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    state, images_roots, default_dir = argv[0], argv[1], argv[2]
    for line in build(state, images_roots, default_dir):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
