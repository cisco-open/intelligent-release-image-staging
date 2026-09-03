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
import time

_SCRYPT_N = 65536      # 2**16 — this admin credential gates full fleet control; aligns with current OWASP guidance for interactive logins
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 128 * 1024 * 1024  # headroom for n*r*128 (~64 MB)
# Two simultaneous scrypts consume roughly 128 MiB.  Reject excess work rather
# than queueing it on the unbounded ThreadingHTTPServer and exhausting RAM.
_PASSWORD_VERIFY_SLOTS = threading.BoundedSemaphore(2)


class VerifyBusy(Exception):
    """Both password-verification slots are taken. Raised instead of
    returning False so a caller never records or penalises a credential
    failure that was never checked -- the right answer is "try again in a
    moment" (503 + Retry-After), not "wrong password"."""


class LoginRateLimiter:
    """Per-IP and fleet-wide exponential login backoff (in-memory)."""

    def __init__(self, per_ip_free=3, global_free=20, max_delay=60,
                 window=300, now_fn=time.monotonic):
        # A short per-source allowance avoids penalising typos; the larger
        # global allowance still stops distributed scrypt floods.
        self.per_ip_free = per_ip_free
        self.global_free = global_free
        self.max_delay = max_delay
        self.window = window
        self._now = now_fn
        self._lock = threading.Lock()
        self._sources = {}
        self._global = [0, 0.0, self._now()]

    def retry_after(self, source):
        now = self._now()
        with self._lock:
            self._expire(now)
            source_until = self._sources.get(source, (0, 0.0, now))[1]
            return max(0, int(max(source_until, self._global[1]) - now + 0.999))

    def failure(self, source):
        now = self._now()
        with self._lock:
            self._expire(now)
            count, _until, _started = self._sources.get(source, (0, 0.0, now))
            count += 1
            delay = self._delay(count, self.per_ip_free)
            self._sources[source] = (count, now + delay, now)
            self._global[0] += 1
            global_delay = self._delay(self._global[0], self.global_free)
            self._global[1] = now + global_delay

    def success(self, source):
        with self._lock:
            self._sources.pop(source, None)

    def _delay(self, count, free):
        if count <= free:
            return 0
        return min(self.max_delay, 2 ** (count - free - 1))

    def _expire(self, now):
        self._sources = {
            source: state for source, state in self._sources.items()
            if now - state[2] < self.window
        }
        if now - self._global[2] >= self.window:
            self._global = [0, 0.0, now]


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
    Returns False for any malformed/empty encoded value (fail closed).
    Raises VerifyBusy when no verification slot is free (see the class)."""
    try:
        scheme, n, r, p, salt_hex, hash_hex = encoded.split("$")
        if scheme != "scrypt":
            return False
        n, r, p = int(n), int(r), int(p)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except (ValueError, AttributeError):
        return False
    if not _PASSWORD_VERIFY_SLOTS.acquire(blocking=False):
        raise VerifyBusy("password verification slots busy")
    try:
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                            dklen=len(expected), maxmem=_SCRYPT_MAXMEM)
        return hmac.compare_digest(dk, expected)
    finally:
        _PASSWORD_VERIFY_SLOTS.release()


# ---------------------------------------------------------------------------
# Admin account (stored under store["admin"] in the secrets store)
# ---------------------------------------------------------------------------

def set_admin(store, username, password, now, invalidate_sessions=False):
    """Set the single admin account in *store* (in-place). Password is hashed.

    ``invalidate_sessions=True`` (the break-glass reset from the
    iris-gui-admin CLI) stamps ``sessions_not_before`` = now: the console
    process reads it through GuiApp.session_info and drops every session
    created at or before that instant, so a suspected-compromised session
    dies with the credential it was minted from. Sessions only live in the
    console process, so the store is the one channel a separate process has
    to reach them. Without the flag an existing floor is carried forward
    unchanged (the in-console password change revokes the OTHER sessions
    itself and keeps the caller's)."""
    previous = store.get("admin") if isinstance(store.get("admin"), dict) else {}
    record = {
        "username": username,
        "pw_hash": hash_password(password),
        "created_at": int(now),
    }
    floor = int(now) if invalidate_sessions else previous.get("sessions_not_before")
    if isinstance(floor, int) and not isinstance(floor, bool) and floor > 0:
        record["sessions_not_before"] = floor
    store["admin"] = record


def sessions_not_before(store):
    """Epoch-second floor below which no console session is valid (0 when
    no break-glass reset has ever been recorded)."""
    admin = store.get("admin") if isinstance(store.get("admin"), dict) else {}
    floor = admin.get("sessions_not_before", 0)
    if isinstance(floor, bool) or not isinstance(floor, int) or floor < 0:
        return 0
    return floor


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
    last_seen on access unless told not to (``touch=False``: a background
    poll that must not count as operator activity); a session idle for
    >= idle_ttl seconds is dropped.
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

    def get(self, sid, now, touch=True):
        with self._lock:
            sess = self._sessions.get(sid)
            if sess is None:
                return None
            if int(now) - sess["last_seen"] >= self._idle_ttl:
                del self._sessions[sid]
                return None
            if touch:
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
