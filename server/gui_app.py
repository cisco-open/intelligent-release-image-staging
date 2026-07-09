# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""GuiApp: the web console's application object. Wires the age-encrypted
secrets store (admin credential) and an in-memory SessionStore. All socket/HTTP
I/O lives in gui_server; all crypto lives in gui_auth. Persistence always goes
through secretfs.persist_store (durable-encrypted-first when recipients are
configured; a plain atomic write otherwise, e.g. in unit tests)."""
import time

import secrets_store
import secretfs
import gui_auth


class GuiApp:
    def __init__(self, secrets_path, recipients_csv=None, secrets_enc=None,
                 sessions=None, now_fn=time.time):
        self.secrets_path = secrets_path
        self.recipients_csv = recipients_csv
        self.secrets_enc = secrets_enc
        self.sessions = sessions if sessions is not None else gui_auth.SessionStore()
        self._now = now_fn

    def _load(self):
        return secrets_store.load(self.secrets_path)

    def needs_setup(self):
        """True when no admin account is configured yet (first-run state)."""
        return gui_auth.get_admin(self._load()) is None

    def set_admin(self, username, password):
        """Set/replace the admin credential and persist it. persist_store
        encrypts at rest when recipients are configured and degrades to a plain
        atomic write when they aren't, so one call covers both paths. Serialized
        against other store writers via the shared advisory lock."""
        with secrets_store.store_lock(self.secrets_path):
            store = secrets_store.load(self.secrets_path)
            gui_auth.set_admin(store, username, password, self._now())
            secretfs.persist_store(store, self.secrets_path,
                                   recipients_csv=self.recipients_csv,
                                   enc_path=self.secrets_enc)

    def login(self, username, password):
        """Return (session_id, csrf) on success, else None."""
        store = self._load()
        if not gui_auth.verify_admin(store, username, password):
            return None
        return self.sessions.create(username, self._now())

    def session_info(self, sid):
        """Return {'username', 'csrf'} for a live session, else None."""
        sess = self.sessions.get(sid, self._now())
        if sess is None:
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
