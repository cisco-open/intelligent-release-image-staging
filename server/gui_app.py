# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""GuiApp: the web console's application object. Wires the age-encrypted
secrets store (admin credential) and an in-memory SessionStore. All socket/HTTP
I/O lives in gui_server; all crypto lives in gui_auth. Persistence always goes
through secretfs.persist_store (durable-encrypted-first when recipients are
configured; a plain atomic write otherwise, e.g. in unit tests)."""
import os
import threading
import time

import secrets_store
import secretfs
import gui_auth

# Per-request session-touch policy, set by the HTTP layer (gui_server's
# Handler.parse_request) for the thread serving one request and consulted by
# GuiApp.session_info when the caller passes touch=None. A background view
# poll (GET with ``X-IRIS-Poll: 1``) validates the session WITHOUT refreshing
# its idle clock, so a console left open on a polled view still reaches the
# advertised idle timeout. Default (no HTTP layer, or no header): touch.
_REQUEST = threading.local()


def set_request_session_touch(flag):
    _REQUEST.touch = bool(flag)


def request_session_touch():
    return getattr(_REQUEST, "touch", True)


class GuiApp:
    def __init__(self, secrets_path, recipients_csv=None, secrets_enc=None,
                 sessions=None, now_fn=time.time):
        self.secrets_path = secrets_path
        self.recipients_csv = recipients_csv
        self.secrets_enc = secrets_enc
        self.sessions = sessions if sessions is not None else gui_auth.SessionStore()
        self._now = now_fn
        self._floor_lock = threading.Lock()
        self._floor_key = None
        self._floor = 0

    def _load(self):
        return secrets_store.load(self.secrets_path)

    def needs_setup(self):
        """True when no admin account is configured yet (first-run state)."""
        return gui_auth.get_admin(self._load()) is None

    def set_admin(self, username, password, invalidate_sessions=False):
        """Set/replace the admin credential and persist it. persist_store
        encrypts at rest when recipients are configured and degrades to a plain
        atomic write when they aren't, so one call covers both paths. Serialized
        against other store writers via the shared advisory lock.
        ``invalidate_sessions`` is the break-glass contract: see
        gui_auth.set_admin. A corrupt live store raises
        secrets_store.StoreCorruptError before anything is persisted."""
        with secrets_store.store_lock(self.secrets_path):
            store = secrets_store.load(self.secrets_path)
            gui_auth.set_admin(store, username, password, self._now(),
                               invalidate_sessions=invalidate_sessions)
            secretfs.persist_store(store, self.secrets_path,
                                   recipients_csv=self.recipients_csv,
                                   enc_path=self.secrets_enc)

    def login(self, username, password):
        """Return (session_id, csrf) on success, else None."""
        store = self._load()
        if not gui_auth.verify_admin(store, username, password):
            return None
        return self.sessions.create(username, self._now())

    def _sessions_not_before(self):
        """The break-glass floor from the store (gui_auth.sessions_not_before),
        cached on the store file's stat so a request costs one os.stat and
        the JSON is re-read only when the file changed. A corrupt store
        raises (StoreCorruptError) -- fail closed, never "no floor"."""
        try:
            st = os.stat(self.secrets_path)
        except FileNotFoundError:
            return 0
        key = (st.st_mtime_ns, st.st_ino, st.st_size)
        with self._floor_lock:
            if key == self._floor_key:
                return self._floor
        floor = gui_auth.sessions_not_before(self._load())
        with self._floor_lock:
            self._floor_key, self._floor = key, floor
        return floor

    def session_info(self, sid, touch=None):
        """Return {'username', 'csrf'} for a live session, else None.

        ``touch`` controls whether the lookup refreshes the idle clock;
        None defers to the per-request policy (request_session_touch).
        A session created at or before the admin record's break-glass
        floor is destroyed here rather than honoured."""
        if touch is None:
            touch = request_session_touch()
        sess = self.sessions.get(sid, self._now(), touch=touch)
        if sess is None:
            return None
        floor = self._sessions_not_before()
        if floor and sess["created_at"] <= floor:
            self.sessions.destroy(sid)
            return None
        return {"username": sess["username"], "csrf": sess["csrf"]}

    def logout(self, sid):
        self.sessions.destroy(sid)

    def change_password(self, current, new):
        """Verify *current* against the stored admin and, on success, set *new*.
        Returns True on success, False if current is wrong or no admin exists.
        Verify-and-set happen under one store lock (atomic, like set_admin)."""
        with secrets_store.store_lock(self.secrets_path):
            store = secrets_store.load(self.secrets_path)
            admin = gui_auth.get_admin(store)
            if admin is None or not gui_auth.verify_admin(
                    store, admin.get("username", ""), current):
                return False
            gui_auth.set_admin(store, admin["username"], new, self._now())
            secretfs.persist_store(store, self.secrets_path,
                                   recipients_csv=self.recipients_csv,
                                   enc_path=self.secrets_enc)
        return True

    def active_sessions(self):
        return self.sessions.count(self._now())

    def idle_ttl_minutes(self):
        return self.sessions.idle_ttl // 60

    def revoke_other_sessions(self, keep_sid):
        return self.sessions.destroy_others(keep_sid)
