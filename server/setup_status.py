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


_CERT_BEGIN = "-----BEGIN CERTIFICATE-----"
_CERT_END = "-----END CERTIFICATE-----"


def _first_certificate_block(pem_text):
    """The FIRST certificate block in *pem_text*, or None.

    ``IRIS_CERT`` is the SHARED combined file all three TLS services load: a
    certificate followed by its private key. ``ssl.PEM_cert_to_DER_cert``
    demands the text END with the certificate footer, so the whole file cannot
    be handed to it. Slicing the leading block also keeps the private key out
    of the parser entirely -- this module has no business touching key material.
    """
    if not isinstance(pem_text, str):
        return None
    start = pem_text.find(_CERT_BEGIN)
    if start < 0:
        return None
    end = pem_text.find(_CERT_END, start)
    if end < 0:
        return None
    return pem_text[start:end + len(_CERT_END)] + "\n"


def fingerprint_pem(pem_text):
    """Colon-separated uppercase SHA-256 of a PEM certificate, or None.

    Matches ``openssl x509 -noout -fingerprint -sha256`` byte for byte: both
    hash the DER encoding. Accepts a combined certificate+key file by reading
    only its leading certificate.
    """
    block = _first_certificate_block(pem_text)
    if block is None:
        return None
    try:
        der = ssl.PEM_cert_to_DER_cert(block)
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
                # Stream member-by-member and stop at the first match instead
                # of getmembers(), which walks the ENTIRE inner archive
                # (packages run ~60 MB) before we ever look at a name.
                member = None
                for m in inner:
                    if os.path.basename(m.name) == _CERT_MEMBER:
                        member = m
                        break
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


def _telemetry_status(override_endpoint, override_enabled,
                      env_endpoint, env_enabled):
    """Resolve the effective telemetry destination card.

    Mirrors the /api/settings resolution exactly (per-field: an explicit
    console override wins, else the deployment environment -- IRIS_OTLP_ENDPOINT
    / IRIS_OBSERVABILITY) so this card can never disagree with the Telemetry
    settings pane. ``ok`` requires BOTH export enabled and an endpoint that
    actually resolves -- an enabled export with nowhere to send is still
    nothing reaching the dashboards, so it is not ok (governing rule: never
    green on missing evidence).
    """
    is_override = override_endpoint is not None or override_enabled is not None
    endpoint = (override_endpoint if override_endpoint is not None
                else (env_endpoint or ""))
    enabled = bool(override_enabled if override_enabled is not None
                   else env_enabled)
    return {
        "state": "ok" if (enabled and endpoint) else "unset",
        # "override" = an operator explicitly set this from the console;
        # "env" = whatever the deployment's compose/env file happens to say.
        # Meaningfully different to an operator, per the spec.
        "source": "override" if is_override else "env",
        "endpoint": endpoint,
        "enabled": enabled,
    }


def _image_verification_status(last_run):
    """Resolve the Image verification setup card (KGV / Cisco Bulk Hash
    reconciler, console Task 5). ``ok`` only once a run has actually
    SUCCEEDED (``last_run.at`` set and ``outcome`` exactly ``"ok"``) -- a
    scheduled-but-never-run config, or a run that failed, both stay
    ``unset``: the operator cannot yet trust that staged images have been
    checked against Cisco's feed (same governing rule as every other card
    here: never report ok on missing evidence)."""
    last_run = last_run or {}
    ok = bool(last_run.get("at")) and last_run.get("outcome") == "ok"
    return {"state": "ok" if ok else "unset"}


def build_status(artifacts_dir, served_cert_path, distributed_cert_path,
                 admin_username, stage_host,
                 telemetry_override_endpoint=None, telemetry_override_enabled=None,
                 telemetry_env_endpoint="", telemetry_env_enabled=False,
                 image_verification_last_run=None):
    """Assemble the five-card setup status. Pure: all inputs are supplied."""
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
        "telemetry": _telemetry_status(
            telemetry_override_endpoint, telemetry_override_enabled,
            telemetry_env_endpoint, telemetry_env_enabled),
        "stage_host": {
            "state": "ok" if stage_host.get("configured") else "unset",
            "username": stage_host.get("username", ""),
        },
        "packages": packages,
        "image_verification": _image_verification_status(image_verification_last_run),
    }
