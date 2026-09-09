# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Post-install setup status for the console (spec 2026-08-24).

IOx and IOS-XR packages are deployment-neutral: their catalog trust anchor is
supplied during onboarding, never baked into a package. Package readiness is
therefore based on readable wrapper bytes and the adjacent build-provenance
manifest that binds those bytes to the canonical OCI image. Certificate
rotation does not make a package stale.

The TLS certificate check has a separate, narrower purpose. It compares the
certificate served by the live services with the public copy distributed at
runtime, because a disagreement still breaks every new onboard.

Stdlib only. Every function is pure and independently testable: nothing here
touches HTTP, and the caller supplies all paths.

GOVERNING RULE: never report ``ok`` on missing evidence. Unreadable, absent and
unparseable inputs all degrade to a non-ok state.
"""
import hashlib
import json
import os
import re
import ssl
import stat
import tarfile

IOX_PACKAGES = ("iris-amd64.tar", "iris-arm64.tar")
XR_PACKAGE = "iris-xr.rpm"
REMEDY = "tools/provision-iox-packages.sh"
REMEDY_XR = "tools/build-xr-package.sh --out artifacts/"

_PACKAGE_SPECS = (
    ("iris-amd64.tar", "iox", "linux/amd64", REMEDY),
    ("iris-arm64.tar", "iox", "linux/arm64", REMEDY),
    (XR_PACKAGE, "xr-appmgr", "linux/amd64", REMEDY_XR),
)
_PROVENANCE_FORMAT = "iris-device-wrapper-v1"
_PROVENANCE_MAX_BYTES = 64 * 1024
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OCI_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_REQUIRED_PROVENANCE = {
    "format", "wrapper_kind", "wrapper_file", "wrapper_sha256", "platform",
    "canonical_index_digest", "canonical_archive_sha256",
    "canonical_source_sha256",
}
_READY_DETAIL = (
    "Readable package bytes match the adjacent build-provenance manifest; "
    "package contents and native signatures are not inspected, and the "
    "sidecar is not authenticated here."
)
_REASON_DETAIL = {
    "empty": "The package file is empty.",
    "unreadable": "The package bytes could not be read.",
    "provenance-absent": "The adjacent provenance manifest is missing.",
    "provenance-unreadable": "The adjacent provenance manifest could not be read.",
    "provenance-invalid": "The adjacent provenance manifest is malformed or for another wrapper.",
    "wrapper-digest-mismatch": "The package bytes do not match the adjacent provenance manifest.",
}


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
    except (OSError, UnicodeError):
        return None


def _parse_provenance(path):
    """Return one bounded, duplicate-free wrapper manifest or a reason."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(_PROVENANCE_MAX_BYTES + 1)
    except FileNotFoundError:
        return None, "provenance-absent"
    except OSError:
        return None, "provenance-unreadable"
    if len(raw) > _PROVENANCE_MAX_BYTES:
        return None, "provenance-invalid"
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return None, "provenance-invalid"
    values = {}
    for line in lines:
        if not line or "=" not in line:
            return None, "provenance-invalid"
        key, value = line.split("=", 1)
        if not key or not value or key in values:
            return None, "provenance-invalid"
        values[key] = value
    if not _REQUIRED_PROVENANCE.issubset(values):
        return None, "provenance-invalid"
    return values, ""


def package_readiness(path, name, kind, platform, remedy):
    """Read and bind one native wrapper to its adjacent provenance sidecar.

    The sidecar is intentionally outside the native envelope so a signing
    service can treat the package as immutable. This verifies byte identity
    and canonical-image provenance metadata; it does not parse package contents
    or claim that a native signature is valid.
    """
    entry = {"name": name, "fingerprint": None, "built_at": None,
             "remedy": remedy, "provenance": None}
    try:
        with open(path, "rb") as handle:
            stat_result = os.fstat(handle.fileno())
            # Keep the existing wire field; this is the served artifact's
            # mtime, not an attested build timestamp.
            entry["built_at"] = int(stat_result.st_mtime)
            if stat_result.st_size == 0:
                entry.update(state="unknown", reason="empty",
                             detail=_REASON_DETAIL["empty"])
                return entry
            digest = hashlib.sha256()
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except FileNotFoundError:
        entry.update(state="absent", reason="absent")
        return entry
    except OSError:
        entry.update(state="unknown", reason="unreadable",
                     detail=_REASON_DETAIL["unreadable"])
        return entry

    values, reason = _parse_provenance(path + ".manifest")
    if reason:
        entry.update(state="unknown", reason=reason,
                     detail=_REASON_DETAIL[reason])
        return entry
    if (values["format"] != _PROVENANCE_FORMAT
            or values["wrapper_kind"] != kind
            or values["wrapper_file"] != name
            or values["platform"] != platform
            or not _HEX_SHA256.fullmatch(values["wrapper_sha256"])
            or not _OCI_SHA256.fullmatch(values["canonical_index_digest"])
            or not _HEX_SHA256.fullmatch(values["canonical_archive_sha256"])
            or not _HEX_SHA256.fullmatch(values["canonical_source_sha256"])):
        entry.update(state="unknown", reason="provenance-invalid",
                     detail=_REASON_DETAIL["provenance-invalid"])
        return entry
    if digest.hexdigest() != values["wrapper_sha256"]:
        entry.update(state="stale", reason="wrapper-digest-mismatch",
                     detail=_REASON_DETAIL["wrapper-digest-mismatch"])
        return entry

    entry["state"] = "ok"
    entry["detail"] = _READY_DETAIL
    entry["provenance"] = {
        "canonical_index_digest": values["canonical_index_digest"],
        "canonical_archive_sha256": values["canonical_archive_sha256"],
        "canonical_source_sha256": values["canonical_source_sha256"],
    }
    return entry


def served_bundle_readiness(artifacts_dir, status_path, startup_state=None):
    """Bind provisioning to the bundle, raw digest and both trust views."""
    entry = {"name": "iris-agent.tgz", "fingerprint": None, "built_at": None,
             "provenance": None, "state": "unknown",
             "remedy": "Rebuild the server image and restart after correcting the provisioning error.",
             "reason": "provisioning-unavailable",
             "detail": "Guest Shell bundle provisioning evidence is unavailable or invalid."}
    # A record may survive a failed attempt to replace it. The supervisor's
    # current startup outcome is independent of that filesystem evidence.
    if startup_state != "ok":
        entry.update(state="stale" if startup_state == "failed" else "unknown",
                     reason="startup-provisioning-unconfirmed",
                     detail="This server startup did not confirm Guest Shell bundle provisioning; inspect startup logs.")
        return entry
    try:
        with open(status_path, "rb") as handle:
            raw = handle.read(4097)
        if len(raw) > 4096:
            return entry
        record = json.loads(raw)
        if not isinstance(record, dict) or record.get("format") != "iris-served-bundle-v1":
            return entry
        if record.get("state") != "ok":
            entry.update(state="stale", reason="provisioning-failed",
                         detail="The latest Guest Shell bundle provisioning did not succeed; inspect server startup logs.")
            return entry
        contents = {}
        embedded = {}
        identities = {}
        for name in ("iris-agent.tgz", "iris-agent.tgz.sha256",
                     "bootstrap.sh", "iris-signers.pem"):
            expected = record.get(name)
            if not isinstance(expected, str) or not _HEX_SHA256.fullmatch(expected):
                return entry
            target = os.path.join(artifacts_dir, name)
            before = os.lstat(target)
            if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
                return entry
            with open(target, "rb") as handle:
                info = os.fstat(handle.fileno())
                if not stat.S_ISREG(info.st_mode) \
                        or (before.st_dev, before.st_ino) != \
                        (info.st_dev, info.st_ino) or not info.st_size:
                    return entry
                if name == "iris-agent.tgz.sha256" and info.st_size != 65:
                    entry.update(state="stale", reason="served-bundle-changed",
                                 detail="The served bundle digest sidecar is not canonical.")
                    return entry
                if name == "iris-signers.pem" and info.st_size > 128 * 1024:
                    return entry
                identity = (info.st_dev, info.st_ino, info.st_size,
                            info.st_mtime_ns, info.st_ctime_ns)
                digest = hashlib.sha256()
                data = bytearray()
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
                    if name in ("iris-agent.tgz.sha256", "iris-signers.pem"):
                        limit = 65 if name == "iris-agent.tgz.sha256" \
                            else 128 * 1024
                        if len(data) + len(chunk) > limit:
                            entry.update(
                                state="stale", reason="served-bundle-changed",
                                detail="A bounded served publication input grew while being read.")
                            return entry
                        data.extend(chunk)
                if name == "iris-agent.tgz":
                    entry["built_at"] = int(info.st_mtime)
                if digest.hexdigest() != expected:
                    entry.update(
                        state="stale", reason="served-bundle-changed",
                        detail="A served bundle publication input changed after verified provisioning.")
                    return entry
                if name == "iris-agent.tgz":
                    handle.seek(0)
                    with tarfile.open(fileobj=handle, mode="r:gz") as archive:
                        members = archive.getmembers()
                        if len(members) > 1024:
                            return entry
                        for trust_name in (
                                "iris-signers.allowed_signers",
                                "iris-root.allowed_signers"):
                            matches = [member for member in members
                                       if member.name == trust_name]
                            if len(matches) != 1 or not matches[0].isfile() \
                                    or not 0 < matches[0].size <= 128 * 1024:
                                return entry
                            member_handle = archive.extractfile(matches[0])
                            trust_data = member_handle.read(128 * 1024 + 1) \
                                if member_handle is not None else b""
                            if not trust_data \
                                    or len(trust_data) != matches[0].size:
                                return entry
                            embedded[trust_name] = trust_data
                            trust_expected = record.get(trust_name)
                            if not isinstance(trust_expected, str) \
                                    or not _HEX_SHA256.fullmatch(
                                        trust_expected):
                                return entry
                            if hashlib.sha256(trust_data).hexdigest() != \
                                    trust_expected:
                                entry.update(
                                    state="stale",
                                    reason="served-bundle-changed",
                                    detail="Embedded device instruction trust changed after verified provisioning.")
                                return entry
                after = os.fstat(handle.fileno())
                if (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns) != identity:
                    entry.update(
                        state="stale", reason="served-bundle-changed",
                        detail="A served bundle publication input changed while it was verified.")
                    return entry
            identities[name] = identity
            contents[name] = bytes(data)
        bundle_digest = record["iris-agent.tgz"]
        if contents["iris-agent.tgz.sha256"] != \
                (bundle_digest + "\n").encode("ascii"):
            entry.update(state="stale", reason="served-bundle-changed",
                         detail="The served bundle digest sidecar is not the exact digest of the bundle.")
            return entry
        if embedded["iris-signers.allowed_signers"] != \
                contents["iris-signers.pem"]:
            entry.update(state="stale", reason="served-bundle-changed",
                         detail="Public and bundled instruction signer trust do not match.")
            return entry
        for name, identity in identities.items():
            current = os.lstat(os.path.join(artifacts_dir, name))
            if (current.st_dev, current.st_ino, current.st_size,
                current.st_mtime_ns, current.st_ctime_ns) != identity:
                entry.update(
                    state="stale", reason="served-bundle-changed",
                    detail="A served bundle publication input changed while readiness was checked.")
                return entry
    except (OSError, ValueError, UnicodeError, tarfile.TarError):
        return entry
    entry.update(state="ok", reason="ready",
                 detail="The served bundle, raw digest, bootstrap and device instruction trust match the latest successful provisioning from a checksum- and architecture-verified aria2c.")
    return entry


# Worst-of ordering. Higher wins, so an invalid package is never masked by an
# unreadable sibling and "cannot determine" never resolves to done.
_RANK = {"ok": 0, "absent": 1, "unknown": 2, "unset": 3, "stale": 4}


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
                 admin_username,
                 telemetry_override_endpoint=None, telemetry_override_enabled=None,
                 telemetry_env_endpoint="", telemetry_env_enabled=False,
                 image_verification_last_run=None, provision_status_path=None,
                 provision_startup_state=None):
    """Assemble the four-card setup status. Pure: all inputs are supplied."""
    reference = read_pem_fingerprint(served_cert_path)
    distributed = read_pem_fingerprint(distributed_cert_path)
    # A disagreement here is worse than a stale package: every NEW onboard is
    # broken too, and rebuilding packages would not fix it.
    mismatch = (reference is not None and distributed is not None
                and reference != distributed)

    items = [package_readiness(
        os.path.join(artifacts_dir, name), name, kind, platform, remedy)
        for name, kind, platform, remedy in _PACKAGE_SPECS]
    if provision_status_path is not None:
        items.append(served_bundle_readiness(
            artifacts_dir, provision_status_path, provision_startup_state))

    packages = {
        "state": _worst([i["state"] for i in items]),
        "reference_fingerprint": reference,
        "items": items,
        "remedy": REMEDY,
    }
    if reference is None:
        packages["state"] = _worst([packages["state"], "unknown"])
        packages["reason"] = "served-cert-unavailable"
    elif distributed is None:
        # Not knowing what devices are told to trust is missing evidence, but
        # it does not change any package item's deployment-neutral readiness.
        packages["state"] = _worst([packages["state"], "unknown"])
        packages["reason"] = "distributed-cert-unavailable"
    elif mismatch:
        packages["state"] = "unknown"
        packages["reason"] = "served-vs-distributed-mismatch"

    return {
        "admin": {
            "state": "ok" if admin_username else "unknown",
            "username": admin_username or "",
        },
        "telemetry": _telemetry_status(
            telemetry_override_endpoint, telemetry_override_enabled,
            telemetry_env_endpoint, telemetry_env_enabled),
        "packages": packages,
        "image_verification": _image_verification_status(image_verification_last_run),
    }
