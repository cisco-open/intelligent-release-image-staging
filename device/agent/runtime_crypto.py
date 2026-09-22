# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Promote the pinned AEAD adapter off Guest Shell's noexec shared flash."""
import os
import stat
import struct
import subprocess
import tempfile

MAX_BINARY = 8 * 1024 * 1024


def select(agent_dir, exec_dir="/home/guestshell"):
    from instr import _read_bytes
    target = os.path.join(exec_dir, "iris-aead")
    try:
        data = _read_bytes(os.path.join(agent_dir, "iris-aead"), MAX_BINARY)
        if not data or data != _read_bytes(target, MAX_BINARY):
            return None
        info = os.lstat(target)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            return None
        return target
    except (OSError, ValueError):
        return None


def install(stage, exec_dir="/home/guestshell"):
    from instr import _read_bytes, _private, _directory_sync
    agent_dir = os.path.join(stage, "agent")
    data = _read_bytes(os.path.join(agent_dir, "iris-aead"), MAX_BINARY)
    if not data or not data.startswith(b"\x7fELF"):
        raise ValueError("bundled AEAD helper missing or invalid")
    if select(agent_dir, exec_dir) is not None:
        return False
    # Public known-answer vector from an independent RFC5297 implementation.
    aad = b"IRIS-AEAD/2"
    plain = b"IRIS AES-SIV capability check"
    sealed = bytes.fromhex("3f308a628f2e9d1535050f68c74d6191828b2771ef8166ae1dd4a0fe69992418aac84041d91f5797910f5809eb")
    tag, ciphertext = sealed[:16], sealed[16:]
    with tempfile.TemporaryDirectory(prefix=".iris-aead-", dir=exec_dir) as work:
        candidate = os.path.join(work, "iris-aead")
        _private(candidate, data)
        os.chmod(candidate, 0o700)
        for supplied, expected in ((tag, plain), (bytes(16), None)):
            request = struct.pack(">II", len(aad), len(ciphertext)) + bytes(range(64)) + aad + ciphertext + supplied
            result = subprocess.run([candidate, "open"], input=request,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    timeout=5, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
            if ((expected is not None and (result.returncode or result.stdout != expected))
                    or (expected is None and (not result.returncode or result.stdout))):
                raise ValueError("bundled AEAD helper failed capability probe")
        with open(candidate, "rb") as handle:
            os.fsync(handle.fileno())
        os.replace(candidate, os.path.join(exec_dir, "iris-aead"))
        _directory_sync(exec_dir)
    return True
