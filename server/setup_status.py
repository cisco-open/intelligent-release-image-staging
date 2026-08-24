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
