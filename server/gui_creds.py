# server/gui_creds.py
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""CredentialStore: shared device credential profiles, kept in the age-encrypted
secrets store under the top-level 'credential_profiles' key, plus the singleton
audit-export SCP password under the top-level 'audit_export' key (used by
audit_export.py's sshpass upload). The whole store file is encrypted at rest, so
fields are stored plaintext inside (consistent with token storage). list_profiles()
NEVER returns passwords — the audit-export HTTP surface only ever sees
password_set; get_secrets()/audit_export_secrets() are server-side accessors.
Persists via secretfs.persist_store (durable-first), mirroring GuiApp.set_admin.
Stdlib + repo modules only."""
import time

import secrets_store
import secretfs

_REQUIRED = ("name", "device_user", "device_pass")


class CredentialStore:
    def __init__(self, secrets_path, recipients_csv=None, secrets_enc=None,
                 now_fn=time.time):
        self.secrets_path = secrets_path
        self.recipients_csv = recipients_csv
        self.secrets_enc = secrets_enc
        self._now = now_fn

    def _load(self):
        return secrets_store.load(self.secrets_path)

    def set_profile(self, profile_id, fields):
        """Create/replace a credential profile. Required: name, device_user,
        device_pass. Optional: enable_secret (defaults to device_pass at use)."""
        pid = str(profile_id or "").strip()
        if not pid:
            raise ValueError("profile id required")
        for req in _REQUIRED:
            if not isinstance(fields.get(req), str) or not fields[req].strip():
                raise ValueError("%s is required" % req)
        # Values end up in an onboarding subprocess environment, which only
        # takes strings: reject other JSON types at save time rather than
        # failing the onboard later with a TypeError.
        if fields.get("enable_secret") is not None and \
                not isinstance(fields.get("enable_secret"), str):
            raise ValueError("enable_secret must be a string")
        rec = {
            "name": fields["name"],
            "device_user": fields["device_user"],
            "device_pass": fields["device_pass"],
            "enable_secret": fields.get("enable_secret") or "",
            "created_at": int(self._now()),
        }
        with secrets_store.store_lock(self.secrets_path):
            store = secrets_store.load(self.secrets_path)
            store.setdefault("credential_profiles", {})[pid] = rec
            secretfs.persist_store(store, self.secrets_path,
                                   recipients_csv=self.recipients_csv,
                                   enc_path=self.secrets_enc)
        return {"id": pid, "name": rec["name"], "device_user": rec["device_user"]}

    def list_profiles(self):
        """Return [{id, name, device_user}] — NEVER passwords."""
        profs = self._load().get("credential_profiles", {})
        return [{"id": pid, "name": r.get("name", ""),
                 "device_user": r.get("device_user", "")}
                for pid, r in sorted(profs.items())]

    def get_secrets(self, profile_id):
        """Full record incl. passwords — SERVER-SIDE ONLY (onboarding). None if absent."""
        return self._load().get("credential_profiles", {}).get(profile_id)

    def delete(self, profile_id):
        with secrets_store.store_lock(self.secrets_path):
            store = secrets_store.load(self.secrets_path)
            profs = store.get("credential_profiles", {})
            existed = profs.pop(profile_id, None) is not None
            if existed:
                secretfs.persist_store(store, self.secrets_path,
                                       recipients_csv=self.recipients_csv,
                                       enc_path=self.secrets_enc)
        return existed

    def set_audit_export_secret(self, password):
        """Set the audit-export SCP password (singleton). Required."""
        if not str(password or ""):
            raise ValueError("password is required")
        rec = {"password": password, "updated_at": int(self._now())}
        with secrets_store.store_lock(self.secrets_path):
            store = secrets_store.load(self.secrets_path)
            store["audit_export"] = rec
            secretfs.persist_store(store, self.secrets_path,
                                   recipients_csv=self.recipients_csv,
                                   enc_path=self.secrets_enc)
        return {"password_set": True}

    def audit_export_secrets(self):
        """Full record incl. password — SERVER-SIDE ONLY (the export job).
        None if unset. The HTTP surface only ever exposes password_set."""
        rec = self._load().get("audit_export")
        return rec if rec and rec.get("password") else None

    def clear_audit_export_secret(self):
        with secrets_store.store_lock(self.secrets_path):
            store = secrets_store.load(self.secrets_path)
            existed = store.pop("audit_export", None) is not None
            if existed:
                secretfs.persist_store(store, self.secrets_path,
                                       recipients_csv=self.recipients_csv,
                                       enc_path=self.secrets_enc)
        return existed
