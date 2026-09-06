#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Upgrade persisted canonical torrents to the configured HTTPS tracker.

Only the top-level announce value changes.  ``torrent_personalize`` copies the
raw ``info`` value span byte-for-byte and proves its SHA-1 is unchanged, so an
upgrade never changes the swarm identity or invalidates device assignments.
The command is intentionally run before the origin seeder starts.
"""
import glob
import os
import stat
import sys
import tempfile

import torrent_personalize
import tracker_announce


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path, data, mode):
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory,
                               prefix=".tracker-announce-", suffix=".tmp")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        _fsync_dir(directory)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def migrate(state_dir, announce_url, image_ids=None):
    """Rewrite selected canonical torrents below *state_dir* atomically.

    Returns the number changed.  Malformed torrents fail closed before the
    seeder can start; already-migrated files are untouched.  ``image_ids=None``
    selects every file. The operation is idempotent, so retrying after any
    interruption is safe.
    """
    announce_url = tracker_announce.validate(announce_url)
    changed = 0
    pattern = os.path.join(state_dir, "torrents", "*.torrent")
    allowed = None if image_ids is None else set(image_ids)
    for path in sorted(glob.glob(pattern)):
        image_id = os.path.basename(path)[:-len(".torrent")]
        if allowed is not None and image_id not in allowed:
            continue
        with open(path, "rb") as stream:
            original = stream.read()
        upgraded = torrent_personalize.personalize(original, announce_url)
        if upgraded == original:
            continue
        mode = stat.S_IMODE(os.stat(path).st_mode)
        _atomic_write(path, upgraded, mode)
        changed += 1
    return changed


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: migrate_tracker_announces.py <state-dir>",
              file=sys.stderr)
        return 2
    try:
        announce_url = tracker_announce.resolve(os.environ)
        # Rewrite every persisted torrent, including quarantined and orphaned
        # files. They may become active later, and retaining a dormant HTTP
        # announce would silently reintroduce plaintext transport on release or
        # repair. A malformed file therefore blocks startup until repaired.
        changed = migrate(argv[0], announce_url)
    except Exception as exc:
        # The configured URL is deliberately not echoed: this utility's output
        # stays nonsecret even if a future caller accidentally supplies one.
        print("tracker announce migration failed (%s)" %
              exc.__class__.__name__, file=sys.stderr)
        return 1
    print("tracker announce migration: %d canonical torrent(s) updated" %
          changed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
