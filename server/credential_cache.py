# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""O(1) credential resolution: one stat-validated snapshot of the secret store
and its strict authorization indexes, shared by every request.

The catalog and the tracker authenticate every single request — a policy GET,
a heartbeat, a telemetry POST, a tracker announce — and each one used to
``secrets_store.load()`` the whole store off disk and rebuild a strict reverse
index across every identity in it. At 10,000 devices that is a full JSON parse
plus a full index build per request, on the rollout critical path, for a
single dictionary lookup.

This wraps that work in a snapshot cache whose validity key is the store
file's own ``os.stat`` identity — ``(st_dev, st_ino, st_mtime_ns,
st_ctime_ns, st_size)``. Every writer in the system replaces the store with
``os.replace`` from a fresh temp file (``secrets_store.save``), so any mint,
rotate or revoke — in this process or in an ``iris-revoke`` / ``iris-mint-
enrollment`` CLI running beside it — lands a NEW inode and the very next
request rebuilds. The check costs one ``stat``; nothing is served from a
snapshot that the file no longer matches, and there is no TTL to tune and no
window during which a revoked credential still authorizes.

Fail-closed behaviour is preserved exactly:

* ``secrets_store.StoreCorruptError`` from ``load`` propagates to the caller
  as it always did, and is never cached as an empty store.
* ``DuplicateCredentialError`` — two records sharing one credential value — is
  raised by the index build. The snapshot REMEMBERS that the build failed and
  re-raises for every subsequent request against the same file, so a hard
  configuration error keeps failing closed instead of being silently rebuilt.

The snapshot's store dict and index are shared, so callers must treat them as
READ-ONLY. Every mutation path (``catalog._handle_token_refresh``, the CLIs,
the console) already re-reads the store under ``secrets_store.store_lock``
with a plain ``secrets_store.load`` and mutates that private copy — which is
what makes sharing the read-only snapshot safe.
"""
import os
import threading

import secrets_store

_MISSING = object()


def _stat_key(path):
    """The store file's identity, or None when it does not exist (the empty
    store: cheap to rebuild, and never cached as a positive answer)."""
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_ctime_ns, st.st_size)


class _Snapshot:
    """One parsed store plus its lazily built indexes."""

    __slots__ = ("key", "store", "_indexes", "_lock")

    def __init__(self, key, store):
        self.key = key
        self.store = store
        self._indexes = {}
        self._lock = threading.Lock()

    def index(self, name, build):
        """The index *name*, built at most once per snapshot. A build that
        raises (duplicate credential ownership) is remembered and re-raised,
        so the hard configuration error never quietly disappears between two
        requests against an unchanged file."""
        with self._lock:
            cached = self._indexes.get(name, _MISSING)
            if cached is _MISSING:
                try:
                    cached = build(self.store)
                except Exception as exc:        # remembered, then re-raised
                    cached = exc
                self._indexes[name] = cached
            if isinstance(cached, Exception):
                raise cached
            return cached


class CredentialResolver:
    """Cached read-only view of the secret store at *path*."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()
        self._snapshot = None

    def snapshot(self):
        """The current :class:`_Snapshot`, rebuilt only when the store file's
        stat identity has changed."""
        key = _stat_key(self.path)
        snap = self._snapshot
        if snap is not None and snap.key == key and key is not None:
            return snap
        with self._lock:
            snap = self._snapshot
            if snap is not None and snap.key == key and key is not None:
                return snap
            # load() raises StoreCorruptError for an existing-but-unreadable
            # store; let it out and cache nothing.
            store = secrets_store.load(self.path)
            snap = _Snapshot(key, store)
            self._snapshot = snap
            return snap

    def store(self):
        """The parsed store. READ-ONLY — see the module docstring."""
        return self.snapshot().store

    def view(self, name, build):
        """``(store, index)`` from ONE snapshot.

        The CALLER names the index builder (``secrets_store
        .build_catalog_auth_index`` / ``build_announce_index``), so the
        authorization surface a route depends on stays visible at that route,
        and this module never gets to decide which index authorizes. *name*
        is the cache slot. Raises ``secrets_store.DuplicateCredentialError``
        when the store has duplicate credential ownership.
        """
        snap = self.snapshot()
        return snap.store, snap.index(name, build)

    def invalidate(self):
        """Drop the snapshot. The stat check already catches every durable
        change; this exists for a caller that has just written the store and
        wants the next read to be unambiguous rather than relying on
        timestamp resolution."""
        with self._lock:
            self._snapshot = None
