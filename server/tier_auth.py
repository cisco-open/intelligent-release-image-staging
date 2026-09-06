# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Authentication for the console-to-management HTTPS hop.

The credential is deliberately file-mounted rather than placed in an
environment variable or command line.  A current and an optional previous
credential provide a bounded, two-phase rotation window: mount the replacement
as current while retaining the old value as previous, restart both tiers, then
remove the previous file after all console replicas have moved.

Files may contain either a raw token or a JSON scoped record of the form
``{"scope":"management","token":"..."}``.  The file path is itself scoped to
the management API; accepting an explicit record makes that scope auditable in
secret-management systems that support structured values.
"""

import hmac
import json
import os
import stat


SCOPE = "management"
MIN_TOKEN_BYTES = 32
MAX_TOKEN_BYTES = 4096


class CredentialUnavailable(RuntimeError):
    """A required credential file cannot be used; message contains no secret."""


def _read(path, *, required, scope=SCOPE):
    if not path:
        if required:
            raise CredentialUnavailable("required management credential is not configured")
        return None
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            raise CredentialUnavailable("management credential is not a regular file")
        # Group-readable projected Kubernetes Secrets (0440) are supported;
        # world access is never appropriate for an inter-tier bearer token.
        if st.st_mode & 0o007:
            raise CredentialUnavailable("management credential permissions are too broad")
        with open(path, "rb") as stream:
            raw = stream.read(MAX_TOKEN_BYTES + 1)
    except CredentialUnavailable:
        raise
    except OSError as exc:
        if not required and isinstance(exc, FileNotFoundError):
            return None
        raise CredentialUnavailable("management credential is unreadable") from None
    if len(raw) > MAX_TOKEN_BYTES:
        raise CredentialUnavailable("management credential is oversized")
    raw = raw.strip()
    if not raw and not required:
        return None
    if raw.startswith(b"{"):
        try:
            record = json.loads(raw.decode("utf-8"))
        except (UnicodeError, ValueError):
            raise CredentialUnavailable("management credential record is invalid") from None
        if not isinstance(record, dict) or record.get("scope") != scope:
            raise CredentialUnavailable("management credential scope is invalid")
        token = record.get("token", record.get("value"))
        if not isinstance(token, str):
            raise CredentialUnavailable("management credential record is invalid")
        raw = token.encode("utf-8")
    if len(raw) < MIN_TOKEN_BYTES:
        raise CredentialUnavailable("management credential is too short")
    return raw


def load_pair(current_path, previous_path=None, scope=SCOPE):
    """Read current+previous credentials afresh so rotation needs no reload."""
    current = _read(current_path, required=True, scope=scope)
    previous = _read(previous_path, required=False, scope=scope)
    if previous is not None and hmac.compare_digest(previous, current):
        previous = None
    return current, previous


def bearer(headers):
    """Return the strict Bearer token bytes, or ``None`` for malformed input."""
    value = headers.get("Authorization", "")
    if not value.startswith("Bearer ") or value.count(" ") != 1:
        return None
    try:
        token = value[7:].encode("utf-8")
    except UnicodeError:
        return None
    return token if token else None


def authorized(headers, current_path, previous_path=None, scope=SCOPE):
    """Fail closed and compare against both rotation credentials in constant time."""
    presented = bearer(headers)
    current, previous = load_pair(current_path, previous_path, scope=scope)
    candidate = presented if presented is not None else b""
    current_ok = hmac.compare_digest(candidate, current)
    # Always execute a second compare so current-vs-previous success does not
    # disclose which side of the rotation window matched.
    previous_value = previous if previous is not None else current
    previous_ok = hmac.compare_digest(candidate, previous_value)
    return presented is not None and (current_ok or (previous is not None and previous_ok))
