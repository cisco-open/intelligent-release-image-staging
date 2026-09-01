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
import calendar
import hashlib
import os
import ssl
import tarfile
import time

# Packages the console reports on. These are the artifacts the container CANNOT
# rebuild itself (see provision-served.sh), which is exactly why they drift.
IOX_PACKAGES = ("iris-amd64.tar", "iris-arm64.tar")
_CERT_MEMBER = "iris-catalog.pem"

# The IOS-XR agent package (device/xr-install.sh, tools/build-xr-package.sh).
# Unlike the two IOx tars, it is not a plain tar of a tar.gz -- it is an RPM
# produced by the ios-xr/xr-appmgr-build tool, whose internal layout this
# stdlib-only module has no way to parse (no rpm/cpio reader here, and this
# module does not shell out). So its baked certificate can never be PINNED
# the way package_fingerprint() pins the IOx tars -- see _xr_package_item's
# docstring for what is checked instead, and its "detail" text for exactly
# what is not.
XR_PACKAGE = "iris-xr.rpm"


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


def _der_tlv(data, offset):
    """The DER element at *offset* as (tag, value_offset, length, next_offset).

    Raises IndexError/ValueError on malformed input; every caller here treats
    that as "unparseable", which the governing rule turns into a non-ok state.
    """
    tag = data[offset]
    index = offset + 1
    first = data[index]
    index += 1
    if first & 0x80:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[index:index + count], "big")
        index += count
    else:
        length = first
    if index + length > len(data):
        raise ValueError("DER length overruns the buffer")
    return tag, index, length, index + length


def certificate_not_before(pem_text):
    """The certificate's own notBefore as epoch seconds, or None.

    Why this is worth a hand-rolled DER walk in a stdlib-only module: the XR
    RPM's freshness can only be judged by comparing its build time against the
    certificate, and the obvious baseline -- the mtime of the pem file on disk
    -- is wrong. The served pem is a STAGED COPY, re-written on every bring-up,
    so its mtime records the last staging operation and says nothing about when
    the certificate came into existence. Baselining on it reported "Needs
    rebuild" for an RPM built ELEVEN MINUTES AFTER the very certificate it was
    accused of predating (operator report 2026-08-31), purely because a later
    bring-up re-copied the pem. notBefore is the certificate's real birthday and
    no copy can move it.

    Walks Certificate -> tbsCertificate -> validity -> notBefore: skip the
    optional [0] EXPLICIT version, then serialNumber, signature and issuer, and
    the next element is validity, whose first member is notBefore.
    """
    block = _first_certificate_block(pem_text)
    if block is None:
        return None
    try:
        der = ssl.PEM_cert_to_DER_cert(block)
        _tag, cert_value, _len, _next = _der_tlv(der, 0)
        _tag, tbs_value, _len, _next = _der_tlv(der, cert_value)
        tag, _value, _len, after = _der_tlv(der, tbs_value)
        if tag == 0xA0:                       # [0] EXPLICIT version
            _tag, _value, _len, after = _der_tlv(der, after)
        _tag, _value, _len, after = _der_tlv(der, after)   # signature alg
        _tag, _value, _len, after = _der_tlv(der, after)   # issuer
        _tag, validity, _len, _next = _der_tlv(der, after)
        tag, value, length, _next = _der_tlv(der, validity)
        raw = der[value:value + length].decode("ascii")
    except (ValueError, TypeError, IndexError, UnicodeDecodeError):
        return None
    try:
        if tag == 0x17:                       # UTCTime: YYMMDDHHMMSSZ
            two = int(raw[:2])
            # RFC 5280: 00-49 is 20xx, 50-99 is 19xx.
            year = 2000 + two if two < 50 else 1900 + two
            parsed = time.strptime("%04d%s" % (year, raw[2:12]), "%Y%m%d%H%M%S")
        elif tag == 0x18:                     # GeneralizedTime: YYYYMMDDHHMMSSZ
            parsed = time.strptime(raw[:14], "%Y%m%d%H%M%S")
        else:
            return None
    except (ValueError, IndexError):
        return None
    return calendar.timegm(parsed)


def read_pem_not_before(path):
    """notBefore epoch of the PEM at *path*, or None if missing/unreadable/bad."""
    try:
        with open(path, "r") as handle:
            return certificate_not_before(handle.read())
    except OSError:
        return None


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
# CATALOG_PEM must point at the CURRENT live certificate (certificate block
# only) when this runs -- see docs/zensical/aiagent.md step 6 and its reset-
# flow note for the full discipline.
REMEDY_XR = "tools/build-xr-package.sh --out artifacts/"

_REASON_STATE = {
    "absent": "absent",
    "unreadable": "unknown",
    "no-artifacts": "unknown",
    "no-cert": "unknown",
    "bad-cert": "unknown",
}

_XR_DETAIL_FRESH = "Built after the current certificate; contents not inspected."
_XR_DETAIL_STALE = "Built before the current certificate; contents not inspected."
_XR_DETAIL_NO_REFERENCE = (
    "Current certificate could not be read, so build time cannot be "
    "compared against it; contents are not inspected for this package "
    "type regardless.")
_XR_DETAIL_UNREADABLE = (
    "Build time could not be read; contents are not inspected for this "
    "package type regardless.")


def _worst(states):
    """The most severe state in *states*; 'ok' only when everything is ok."""
    if not states:
        return "unknown"
    return max(states, key=lambda s: _RANK.get(s, 2))


def _xr_package_item(artifacts_dir, served_cert_path, reference):
    """The device-packages row for the IOS-XR agent RPM.

    HONESTY CONSTRAINT: package_fingerprint()'s cert-pinning check reads a
    named member out of the IOx tars' inner artifacts.tar.gz -- a shape the
    XR RPM (built by ios-xr/xr-appmgr-build, see tools/build-xr-package.sh)
    does not share, and this stdlib-only module has no RPM/cpio reader to
    give it one. So this can never say "this RPM pins certificate X" the
    way the two tar rows do. What it CAN honestly check is the RPM's build
    time against the certificate currently served: built at/after the
    certificate's own mtime is the best available evidence the RPM was
    produced with the live cert (REMEDY_XR's CATALOG_PEM argument is how a
    real build ties the two together); built before it is evidence the RPM
    predates a rotation and may still pin the old one. Either way, "detail"
    says plainly that only build time was compared, never contents -- the
    governing rule (never report ok on missing evidence) applies to what
    "ok" is allowed to imply, not just to whether it fires at all.
    """
    path = os.path.join(artifacts_dir, XR_PACKAGE)
    entry = {"name": XR_PACKAGE, "fingerprint": None, "built_at": None,
             "remedy": REMEDY_XR}
    if not os.path.exists(path):
        entry["state"] = "absent"
        entry["reason"] = "absent"
        return entry
    try:
        built_at = os.path.getmtime(path)
    except OSError:
        entry["state"] = "unknown"
        entry["reason"] = "unreadable"
        entry["detail"] = _XR_DETAIL_UNREADABLE
        return entry
    entry["built_at"] = int(built_at)
    if reference is None:
        # Same condition IOX_PACKAGES rows use for "no-reference": the
        # served certificate itself could not be read, so there is nothing
        # to compare against -- not specific to this package.
        entry["state"] = "unknown"
        entry["reason"] = "no-reference"
        entry["detail"] = _XR_DETAIL_NO_REFERENCE
        return entry
    # The certificate's own notBefore, never the pem file's mtime: that file is
    # a staged copy re-written on every bring-up, so its mtime tracks the last
    # staging rather than the certificate's life, and a re-copy alone would
    # brand a perfectly good RPM stale (operator report 2026-08-31).
    cert_born = read_pem_not_before(served_cert_path)
    if cert_born is None:
        entry["state"] = "unknown"
        entry["reason"] = "no-reference"
        entry["detail"] = _XR_DETAIL_NO_REFERENCE
        return entry
    if built_at >= cert_born:
        entry["state"] = "ok"
        entry["detail"] = _XR_DETAIL_FRESH
    else:
        entry["state"] = "stale"
        entry["detail"] = _XR_DETAIL_STALE
    return entry


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
        entry = {"name": name, "fingerprint": fingerprint, "built_at": None,
                 "remedy": REMEDY}
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
    # The XR agent RPM (device/xr-install.sh) ships from this same directory
    # and is exactly as vulnerable to a stale-cert build as the two tars --
    # see _xr_package_item's docstring for why it is checked differently.
    items.append(_xr_package_item(artifacts_dir, served_cert_path, reference))

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
