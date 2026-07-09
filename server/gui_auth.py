# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Pure auth primitives for the IRIS web console: scrypt password hashing,
admin-account helpers over a secrets-store dict, and an in-memory SessionStore.
Stdlib only; no I/O here (persistence lives in gui_app).

Clock contract: every ``now`` argument is epoch seconds (e.g. ``time.time()``),
used for ``created_at`` and idle-expiry math -- not ``time.monotonic()``, and
not safe against backward wall-clock jumps."""
import hashlib
import hmac
import secrets
import threading

_SCRYPT_N = 65536      # 2**16 — this admin credential gates full fleet control; aligns with current OWASP guidance for interactive logins
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 128 * 1024 * 1024  # headroom for n*r*128 (~64 MB)


def hash_password(password):
    """Return an encoded scrypt hash: 'scrypt$N$r$p$salthex$hashhex'."""
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_SCRYPT_N,
                        r=_SCRYPT_R, p=_SCRYPT_P, dklen=_SCRYPT_DKLEN,
                        maxmem=_SCRYPT_MAXMEM)
    return "scrypt$%d$%d$%d$%s$%s" % (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
                                      salt.hex(), dk.hex())


def verify_password(encoded, password):
    """Constant-time verify *password* against an encoded scrypt hash.
    Returns False for any malformed/empty encoded value (fail closed)."""
    try:
        scheme, n, r, p, salt_hex, hash_hex = encoded.split("$")
        if scheme != "scrypt":
            return False
        n, r, p = int(n), int(r), int(p)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                        dklen=len(expected), maxmem=_SCRYPT_MAXMEM)
    return hmac.compare_digest(dk, expected)


# ---------------------------------------------------------------------------
# Admin account (stored under store["admin"] in the secrets store)
# ---------------------------------------------------------------------------

def set_admin(store, username, password, now):
    """Set the single admin account in *store* (in-place). Password is hashed."""
    store["admin"] = {
        "username": username,
        "pw_hash": hash_password(password),
        "created_at": int(now),
    }


def get_admin(store):
    """Return the admin record dict, or None if no admin is configured."""
    return store.get("admin")


def verify_admin(store, username, password):
    """Return True iff *username*/*password* match the configured admin.
    Fail closed when no admin exists. Avoids early-out on username mismatch."""
    admin = store.get("admin")
    if not admin:
        return False
    user_ok = hmac.compare_digest(
        str(admin.get("username", "")).encode("utf-8"),
        str(username).encode("utf-8"))
    pass_ok = verify_password(admin.get("pw_hash", ""), password)
    return user_ok and pass_ok


# ---------------------------------------------------------------------------
# In-memory session store (single-process service; restart logs everyone out)
# ---------------------------------------------------------------------------

class SessionStore:
    """Thread-safe in-memory sessions with idle expiry.

    A session is {username, csrf, created_at, last_seen}. get() refreshes
    last_seen on access; a session idle for >= idle_ttl seconds is dropped.
    """

    def __init__(self, idle_ttl=1800):
        self._idle_ttl = idle_ttl
        self._sessions = {}
        self._lock = threading.Lock()

    def create(self, username, now):
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[sid] = {
                "username": username,
                "csrf": csrf,
                "created_at": int(now),
                "last_seen": int(now),
            }
        return sid, csrf

    def get(self, sid, now):
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is None:
                return None
            if int(now) - sess["last_seen"] >= self._idle_ttl:
                del self._sessions[sid]
                return None
            sess["last_seen"] = int(now)
            return dict(sess)

    def destroy(self, sid):
        with self._lock:
            self._sessions.pop(sid, None)

    @property
    def idle_ttl(self):
        return self._idle_ttl

    def count(self, now):
        """Number of live (non-expired) sessions; prunes expired as a side effect."""
        with self._lock:
            expired = [sid for sid, s in self._sessions.items()
                       if int(now) - s["last_seen"] >= self._idle_ttl]
            for sid in expired:
                del self._sessions[sid]
            return len(self._sessions)

    def destroy_others(self, keep_sid):
        """Destroy every session except *keep_sid*. Returns the number destroyed."""
        with self._lock:
            others = [sid for sid in self._sessions if sid != keep_sid]
            for sid in others:
                del self._sessions[sid]
            return len(others)
