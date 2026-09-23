# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Offline custodian companion; private roots never travel to the server."""

import os
from pathlib import Path
import subprocess
import stat
import tempfile
import sys

from .state import InstallError, regular_bytes


def approve(args):
    public = regular_bytes(args.public_key, 16384)
    if not public.startswith(b"ssh-ed25519 ") or b"PRIVATE" in public:
        raise InstallError("Expected the online Ed25519 PUBLIC key")
    root = Path(args.root_key).resolve(strict=True)
    info = root.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077):
        raise InstallError("Root private key must be a caller-owned regular file with private permissions")
    output = Path(args.output).absolute()
    if output.exists() or output.is_symlink():
        raise InstallError("Certificate destination already exists; choose a new path")
    # Prompt belongs to ssh-keygen and its controlling terminal. Neither the
    # passphrase nor private key bytes are read by the installer.
    with tempfile.TemporaryDirectory(prefix="iris-approval-") as directory:
        request = Path(directory) / "online.pub"
        request.write_bytes(public)
        result = subprocess.run(["ssh-keygen", "-s", str(root), "-I", "iris-online",
                                 "-n", "iris-server", "-V", "+0s:+30d", str(request)], check=False)
        if result.returncode:
            raise InstallError("Custodian signing failed; no certificate was published")
        data = regular_bytes(Path(directory) / "online-cert.pub", 65536)
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(data)
    print("Return only this public certificate to the installer: " + str(output))
    return 0


def approve_keylist(args):
    """Use the shipped server framing/limits, never a second KRL protocol."""
    package = Path(__file__).resolve().parents[1] / 'source/server'
    source = package if package.is_dir() else Path(__file__).resolve().parents[2] / 'server'
    sys.path.insert(0, str(source))
    import instruction_keys as keys
    try:
        payload = regular_bytes(args.payload, keys.MAX_KEYLIST_PAYLOAD_BYTES)
        metadata, krl = keys._parse_keylist_payload(payload)
        keys._validate_krl_bytes(krl)
    except keys.InstructionKeyError:
        raise InstallError('Invalid public keylist request') from None
    root = Path(args.root_key).resolve(strict=True)
    info = root.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise InstallError('Root private key must be caller-owned with private permissions')
    output = Path(args.output).absolute()
    if output.exists() or output.is_symlink():
        raise InstallError('Approval output exists; choose a new path')
    print('Approving keylist sequence ' + str(metadata['keylist_seq']) +
          ' for root ' + metadata['signer_root_id'] + '; KRL SHA256 ' + metadata['krl_sha256'])
    print('Confirm the request and revoked keys through your custody procedure before signing.')
    with tempfile.TemporaryDirectory(prefix='iris-keylist-approval-') as directory:
        request = Path(directory) / 'keylist.payload'
        request.write_bytes(payload)
        result = subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(root),
                                 '-n', keys.KEYLIST_NAMESPACE, str(request)], check=False)
        if result.returncode:
            raise InstallError('Custodian signing failed; no approval published')
        artifact = keys.assemble_keylist_artifact(payload, regular_bytes(str(request) + '.sig', keys.MAX_SIGNATURE_BYTES))
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(artifact)
            stream.flush()
            os.fsync(stream.fileno())
    print('Return only the public keylist approval: ' + str(output))
    return 0
