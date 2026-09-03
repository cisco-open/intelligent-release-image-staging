# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Build the aria2 --input-file for the seeder's startup re-seed: pair each
published torrent in the state dir with the directory that actually holds its
image. The catalog is the authority on WHAT is re-seeded: a torrent file with
no catalog row (left behind by a publish that failed after mktorrent ran) and a
torrent whose image is quarantined (its quarantine force-removed it from the
seeder on purpose) are skipped, so a restart can never serve what the API says
is absent or withheld. A catalog entry's recorded source_dir is authoritative
for WHERE; otherwise fall back to walking the image roots (colon-separated,
earlier roots win a basename collision — callers pass the writable upload dir
first). Split out of seed-launch.sh so this mapping is unit-testable. Stdlib
only."""
import glob
import json
import os
import sys


def build(state, images_roots, default_dir, skipped=None):
    """Return a list of aria2 input-file lines (torrent path, then ' dir=<dir>')
    for every state/torrents/*.torrent that the catalog authorizes (has a row
    for, and has not quarantined), resolving each to the directory holding its
    image (via the catalog id->filename map + a walk of images_roots), or
    default_dir if not found. When *skipped* is a list, one (image_id, reason)
    pair is appended per torrent left out."""
    try:
        with open(os.path.join(state, "catalog.json")) as f:
            cat = json.load(f)
        imgs = cat.get("images", {}) if isinstance(cat, dict) else {}
    except Exception:
        # No readable catalog means nothing is authorized: with no catalog
        # row an image cannot be assigned or even answered for by the API,
        # so seeding it would only ever serve bytes nobody was directed to.
        imgs = {}
    if not isinstance(imgs, dict):
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
        entry = imgs.get(iid)
        if not isinstance(entry, dict):
            if skipped is not None:
                skipped.append((iid, "no catalog entry"))
            continue
        if entry.get("quarantined"):
            if skipped is not None:
                skipped.append((iid, "quarantined"))
            continue
        fn = entry.get("filename")
        # Prefer the directory the image was actually published from. The
        # basename walk cannot tell two same-named files in different roots
        # apart, and the seeder runs with bt-seed-unverified — so guessing wrong
        # serves the wrong bytes under the right piece hashes. Entries predating
        # source_dir, or whose recorded directory has since gone away, still fall
        # back to the walk.
        src = entry.get("source_dir")
        d = src if src and os.path.isdir(src) else None
        if d is None:
            d = loc.get(fn) if fn else None
        if d is None:
            d = default_dir
        lines.append(t)
        lines.append(" dir=" + d)
    return lines


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    state, images_roots, default_dir = argv[0], argv[1], argv[2]
    skipped = []
    for line in build(state, images_roots, default_dir, skipped=skipped):
        print(line)
    for iid, reason in skipped:
        print("reseed: skipping %s.torrent: %s" % (iid, reason), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
