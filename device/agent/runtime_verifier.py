# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Promote the bundled SSHSIG verifier off Guest Shell's noexec flash mount."""
import os
import shutil
import stat
import subprocess
import tempfile

from instr import _directory_sync, _private, _read_bytes

MAX_BINARY = 2 * 1024 * 1024
NAME = "iris-ssh-keygen"
_PUBLIC = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINylURfH+4WYp3aLkFQ+bcyEvOX9WWI9VIO/k9XgMHGS"
_SIGNATURE = b"""-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg3KVRF8f7hZindouQVD5tzIS85f
1ZYj1Ug7+T1eAwcZIAAAAUaXJpcy1pbnN0cnVjdGlvbnMtdjEAAAAAAAAABnNoYTUxMgAA
AFMAAAALc3NoLWVkMjU1MTkAAABAcZZIxmZfNxiYXdqJhYE6BbAqEW6+gCewk5ZX8WmrSk
R4Cy1k/ouENDoxHp9/5qUr5VpyiH4ssRF3RMsTt+ixCA==
-----END SSH SIGNATURE-----
"""


def select(stage, exec_dir="/home/guestshell"):
    """Never fall back to an older verifier when a bundle supplied one."""
    source = os.path.join(stage, "agent", "ssh-keygen")
    if not os.path.lexists(source):
        return shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen"
    runtime = os.path.join(exec_dir, NAME)
    try:
        data = _read_bytes(source, MAX_BINARY)
        if not data or data != _read_bytes(runtime, MAX_BINARY):
            return None
        info = os.lstat(runtime)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            return None
        return runtime
    except (OSError, ValueError):
        return None


def install(stage, exec_dir="/home/guestshell", runner=subprocess.run):
    source = os.path.join(stage, "agent", "ssh-keygen")
    if not os.path.lexists(source):
        return False  # An older bundle still reports system verifier capability.
    data = _read_bytes(source, MAX_BINARY)
    if not data or not data.startswith(b"\x7fELF"):
        raise ValueError("bundled verifier is not an ELF executable")
    destination = os.path.join(exec_dir, NAME)
    if select(stage, exec_dir) == destination:
        return False
    # Probe the actual candidate before atomic promotion. Public test material
    # is not a trust root and is never passed to real instruction verification.
    with tempfile.TemporaryDirectory(prefix=".iris-verifier-", dir=exec_dir) as work:
        candidate = os.path.join(work, "ssh-keygen")
        _private(candidate, data)
        os.chmod(candidate, 0o700)
        signers = os.path.join(work, "signers")
        signature = os.path.join(work, "signature")
        _private(signers, b'iris-probe namespaces="iris-instructions-v1" ' + _PUBLIC + b"\n")
        _private(signature, _SIGNATURE)
        result = runner([candidate, "-Y", "verify", "-f", signers,
                         "-I", "iris-probe", "-n", "iris-instructions-v1",
                         "-s", signature, "-O", "verify-time=20260919000000Z"],
                        input=b"IRIS verifier capability check\n",
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=5)
        if result.returncode != 0:
            raise ValueError("bundled SSHSIG verifier failed capability probe")
        with open(candidate, "rb") as handle:
            os.fsync(handle.fileno())
        os.replace(candidate, destination)
        _directory_sync(exec_dir)
    return True
