# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Post-install setup status for the console (spec 2026-08-24).

Why this module exists: the IOx device packages bake ``iris-catalog.pem`` in at
BUILD time, so any change to the catalog certificate silently invalidates every
previously built package. The device still installs and the app still reports
RUNNING -- it simply can never authenticate, and the only evidence is a
TOKEN-REFRESH-FAIL line in the DEVICE's syslog. Nothing server-side otherwise
distinguishes "never onboarded" from "onboarded but rejecting our certificate".

Guest Shell platforms are immune because provision-served.sh regenerates their
artifacts (including the pem) at every container start; the IOx packages are
precisely the artifacts it cannot produce.

Stdlib only. Every function is pure and independently testable: nothing here
touches HTTP, and the caller supplies all paths.

GOVERNING RULE: never report ``ok`` on missing evidence. Unreadable, absent and
unparseable all degrade to a non-ok state, because a false green here is the
failure this module exists to prevent.
"""
import hashlib
import os
import ssl
import tarfile

# Packages the console reports on. These are the artifacts the container CANNOT
# rebuild itself (see provision-served.sh), which is exactly why they drift.
IOX_PACKAGES = ("iris-amd64.tar", "iris-arm64.tar")
_CERT_MEMBER = "iris-catalog.pem"


def fingerprint_pem(pem_text):
    """Colon-separated uppercase SHA-256 of a PEM certificate, or None.

    Matches ``openssl x509 -noout -fingerprint -sha256`` byte for byte: both
    hash the DER encoding.
    """
    try:
        der = ssl.PEM_cert_to_DER_cert(pem_text)
    except (ValueError, TypeError):
        return None
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def read_pem_fingerprint(path):
    """Fingerprint of the PEM at *path*, or None if missing/unreadable/bad."""
    try:
        with open(path) as handle:
            return fingerprint_pem(handle.read())
    except OSError:
        return None


def package_fingerprint(tar_path):
    """The catalog certificate an IOx package PINS, as (fingerprint, reason).

    reason is "" on success, else one of: absent, unreadable, no-artifacts,
    no-cert, bad-cert. Only the single pem member is read -- the ~60 MB package
    is never unpacked to disk.
    """
    if not os.path.exists(tar_path):
        return None, "absent"
    try:
        with tarfile.open(tar_path, mode="r:*") as outer:
            try:
                inner_file = outer.extractfile("artifacts.tar.gz")
            except KeyError:
                inner_file = None
            if inner_file is None:
                return None, "no-artifacts"
            with tarfile.open(fileobj=inner_file, mode="r:gz") as inner:
                member = next(
                    (m for m in inner.getmembers()
                     if os.path.basename(m.name) == _CERT_MEMBER), None)
                if member is None:
                    return None, "no-cert"
                pem_file = inner.extractfile(member)
                if pem_file is None:
                    return None, "no-cert"
                fingerprint = fingerprint_pem(
                    pem_file.read().decode("utf-8", "replace"))
    except (tarfile.TarError, OSError, EOFError):
        return None, "unreadable"
    if fingerprint is None:
        return None, "bad-cert"
    return fingerprint, ""


# Worst-of ordering. Higher wins, so a stale package is never masked by an
# unreadable sibling and "cannot determine" never resolves to done.
_RANK = {"ok": 0, "absent": 1, "unknown": 2, "unset": 3, "stale": 4}

REMEDY = "tools/provision-iox-packages.sh"

_REASON_STATE = {
    "absent": "absent",
    "unreadable": "unknown",
    "no-artifacts": "unknown",
    "no-cert": "unknown",
    "bad-cert": "unknown",
}


def _worst(states):
    """The most severe state in *states*; 'ok' only when everything is ok."""
    if not states:
        return "unknown"
    return max(states, key=lambda s: _RANK.get(s, 2))


def build_status(artifacts_dir, served_cert_path, distributed_cert_path,
                 admin_username, stage_host):
    """Assemble the three-card setup status. Pure: all inputs are supplied."""
    reference = read_pem_fingerprint(served_cert_path)
    distributed = read_pem_fingerprint(distributed_cert_path)
    # A disagreement here is worse than a stale package: every NEW onboard is
    # broken too, and rebuilding packages would not fix it.
    mismatch = (reference is not None and distributed is not None
                and reference != distributed)

    items = []
    for name in IOX_PACKAGES:
        fingerprint, reason = package_fingerprint(
            os.path.join(artifacts_dir, name))
        entry = {"name": name, "fingerprint": fingerprint, "built_at": None}
        path = os.path.join(artifacts_dir, name)
        try:
            entry["built_at"] = int(os.path.getmtime(path))
        except OSError:
            pass
        if reason:
            entry["state"] = _REASON_STATE.get(reason, "unknown")
            entry["reason"] = reason
        elif reference is None:
            # We cannot say whether this pins the right certificate, so we do
            # not say it is fine.
            entry["state"] = "unknown"
            entry["reason"] = "no-reference"
        elif fingerprint == reference:
            entry["state"] = "ok"
        else:
            entry["state"] = "stale"
        items.append(entry)

    packages = {
        "state": _worst([i["state"] for i in items]),
        "reference_fingerprint": reference,
        "items": items,
        "remedy": REMEDY,
    }
    if distributed is None and reference is not None:
        # Not knowing what devices are told to trust is missing evidence, so
        # this can never leave us at ok -- but it must not DEMOTE a worse
        # finding either: a stale package is the more urgent fact.
        packages["state"] = _worst([packages["state"], "unknown"])
        packages["reason"] = "distributed-cert-unavailable"
    elif mismatch:
        packages["state"] = "unknown"
        packages["reason"] = "served-vs-distributed-mismatch"

    stage_host = stage_host or {"configured": False, "username": ""}
    return {
        "admin": {
            "state": "ok" if admin_username else "unknown",
            "username": admin_username or "",
        },
        "stage_host": {
            "state": "ok" if stage_host.get("configured") else "unset",
            "username": stage_host.get("username", ""),
        },
        "packages": packages,
    }
