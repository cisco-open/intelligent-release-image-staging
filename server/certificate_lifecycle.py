# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Public certificate inventory and guarded, same-key instruction renewal.

No deployment privileges or root private keys are accepted by this module.
File observations do not attest the identity currently loaded by a TLS listener.
"""

import hashlib
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import time

import instruction_keys as keys
import trust

DAY = 86400


def validity(start, end, now, *, renew_at=None, refuse_at=None):
    if now < start:
        return "not-yet-valid"
    if now >= end:
        return "expired"
    if refuse_at is not None and now >= refuse_at:
        return "signing-refused"
    if now >= (renew_at if renew_at is not None else end - 30 * DAY):
        return "renewal-due"
    return "within-validity"


def _row(name, label, impact):
    return {"id": name, "label": label, "state": "unknown", "source": "server-file",
            "kind": "certificate",
            "fingerprint_sha256": None, "valid_from": None, "expires_at": None,
            "renew_at": None, "refuse_at": None, "impact": impact}


def x509_row(name, label, path, impact, now):
    row = _row(name, label, impact)
    try:
        # Combined PEM may contain a key. Pass ONLY the public leaf to openssl.
        content = keys._read_regular(path, 2 * 1024 * 1024,
                                     unavailable="certificate unavailable",
                                     too_large="certificate too large")
        blocks = trust.split_pem_certs(content.decode("ascii"))
        if not blocks:
            return row
        leaf = blocks[0]
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-startdate", "-enddate"],
            input=leaf.encode("ascii"), capture_output=True, timeout=10, check=True,
            env=dict(os.environ, LC_ALL="C", TZ="UTC"))
        dates = dict(line.split("=", 1) for line in proc.stdout.decode("ascii").splitlines())
        start, end = (int(ssl.cert_time_to_seconds(dates[field]))
                      for field in ("notBefore", "notAfter"))
        row.update(fingerprint_sha256=hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf)).hexdigest(),
                   valid_from=start, expires_at=end, renew_at=end - 30 * DAY,
                   state=validity(start, end, now))
    except (keys.InstructionKeyError, OSError, ValueError, UnicodeError,
            subprocess.SubprocessError):
        pass
    return row


def inventory(*, now=None, paths=None):
    now = int(time.time()) if now is None else now
    paths = paths or keys.InstructionPaths.from_env()
    items = [
        x509_row("device-tls", "Device-facing TLS",
                 os.environ.get("IRIS_CERT", "/run/iris/tls/cert.pem"),
                 "Replacing device-pinned trust requires re-onboarding devices.", now),
        x509_row("management-tls", "Console-to-server TLS",
                 os.environ.get("IRIS_MANAGEMENT_API_CERT", ""),
                 "Coordinate server identity and Console trust before restart.", now),
        x509_row("peer-ca", "Private swarm issuing CA",
                 str(Path(paths.run_dir) / "peer-tls" / "ca.pem"),
                 "Devices renew short-lived peer certificates through the catalog.", now),
    ]
    signer = _row("instruction-signer", "Instruction signing certificate",
                  "Renew the certificate with the existing key and offline root approval.")
    try:
        # Inventory is a public observation, not cryptographic admission.
        # Renewal and instruction signing independently validate custody.
        raw = keys._read_regular(paths.certificate, keys.MAX_CERTIFICATE_BYTES,
                                 unavailable="certificate unavailable", too_large="certificate too large")
        if (not raw.startswith(b'ssh-ed25519-cert-v01@openssh.com ')
                or len(raw.strip().splitlines()) != 1):
            raise keys.InstructionKeyError('expected one public certificate')
        with tempfile.TemporaryDirectory() as directory:
            snapshot = Path(directory) / "certificate.pub"
            snapshot.write_bytes(raw)
            start, end, _principals = keys._certificate_fields(snapshot)
            fingerprint = keys._fingerprint(snapshot)
        signer.update(fingerprint_sha256=fingerprint, valid_from=start, expires_at=end,
                      renew_at=start + (end - start) // 2,
                      refuse_at=end - keys.CERTIFICATE_REFUSE_SECONDS)
        signer["state"] = validity(start, end, now, renew_at=signer["renew_at"],
                                   refuse_at=signer["refuse_at"])
    except (keys.InstructionKeyError, OSError, ValueError):
        pass
    items.append(signer)
    # Public keys do not expire. Their certificates/attestations and rotation
    # policies do; never invent an expiry for a bare root or online public key.
    public_keys = [("online-key", "Online instruction public key", paths.public_key,
                    "Certificate renewal retains this key. Key replacement is a separate custody operation.")]
    try:
        roots = keys.discover_roots(paths)
        public_keys.extend(("root-" + name, "Offline root " + name, path,
                            "Public trust only. Confirm private custody with the holder; changing roots requires device trust rollout.")
                           for name, path in roots.items())
    except keys.InstructionKeyError:
        roots = {}
    for name, label, path, impact in public_keys:
        row = _row(name, label, impact)
        row['kind'] = 'public-key'
        try:
            raw = path if isinstance(path, bytes) else keys._read_regular(
                path, keys.MAX_ROOT_KEY_BYTES, unavailable='public key unavailable',
                too_large='public key too large')
            if not raw.startswith(b'ssh-ed25519 ') or len(raw.strip().splitlines()) != 1:
                raise keys.InstructionKeyError('unexpected public key type')
            with tempfile.TemporaryDirectory() as directory:
                snapshot = Path(directory) / 'public.pub'
                snapshot.write_bytes(raw)
                row['fingerprint_sha256'] = keys._fingerprint(snapshot)
            row['state'] = 'public-key-present'
        except (keys.InstructionKeyError, OSError, ValueError):
            pass
        items.append(row)
    return {"observed_at": now, "scope": "server-certificate-files",
            "items": items,
            "custody": keys.read_status_file(paths.status, now=now),
            "note": "Validity dates do not prove trust, key availability or the certificate loaded by a listener."}


def renew(payload, *, paths=None, now=None):
    """Import a public approval; reject unknown fields, private keys and stale UI."""
    if (not isinstance(payload, dict)
            or set(payload) != {"certificate", "public_key_sha256", "certificate_sha256"}):
        raise keys.InstructionKeyError("expected a certificate and both renewal guards")
    certificate = payload["certificate"]
    if (not isinstance(certificate, str) or len(certificate) > keys.MAX_CERTIFICATE_BYTES
            or not certificate.startswith("ssh-ed25519-cert-v01@openssh.com ")
            or "PRIVATE KEY" in certificate or len(certificate.strip().splitlines()) != 1):
        raise keys.InstructionKeyError("upload one public OpenSSH certificate, not a private key")
    paths = paths or keys.InstructionPaths.from_env()
    roots = keys.discover_roots(paths)
    # Runtime tmpfs in production; only a public certificate is staged here.
    with tempfile.TemporaryDirectory(dir=keys._runtime_directory(paths)) as directory:
        candidate = Path(directory) / "approved-cert.pub"
        candidate.write_text(certificate, encoding="ascii")
        info = keys.import_online_certificate(
            paths, candidate, roots, now=now,
            renewal={name: payload[name] for name in ("public_key_sha256", "certificate_sha256")})
    # Successful import is authoritative even if an unrelated status write fails.
    refreshed = True
    try:
        keys.refresh_custody_status(paths, now=now)
    except (keys.InstructionKeyError, OSError):
        refreshed = False
    return {"applied": True, "expires_at": info["valid_before"],
            "refuse_at": info["valid_before"] - keys.CERTIFICATE_REFUSE_SECONDS,
            "status_refreshed": refreshed}
