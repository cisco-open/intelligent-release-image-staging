# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bounded AES-256-SIV pipe adapter; secrets never enter argv or temp files."""
import os
import platform
import struct
import subprocess

LIMIT = 256 * 1024


def helper_path():
    # Fixed installed paths, never PATH or a remote/config-supplied executable.
    here = os.path.dirname(os.path.abspath(__file__))
    bundled = os.path.join(here, "iris-aead")
    if os.path.lexists(bundled):
        from runtime_crypto import select
        result = select(here)
        if result is None:
            raise ValueError("instruction AEAD helper unavailable")
        return result
    installed = "/opt/iris/bin/iris-aead"
    if os.path.isfile(installed):
        return installed
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    root = os.path.dirname(here)
    if os.path.basename(root) == "device":
        root = os.path.dirname(root)
    candidate = os.path.join(root, "bin", "iris-aead-" + str(arch))
    if arch and os.path.isfile(candidate):
        return candidate
    raise ValueError("instruction AEAD helper unavailable")


def transform(operation, key, aad, data, tag=b""):
    if (operation not in ("seal", "open") or not isinstance(key, bytes)
            or len(key) != 64 or not isinstance(aad, bytes)
            or not 0 < len(aad) <= LIMIT or not isinstance(data, bytes)
            or not 0 < len(data) <= LIMIT or not isinstance(tag, bytes)
            or len(tag) != (16 if operation == "open" else 0)):
        raise ValueError("invalid instruction AEAD input")
    payload = struct.pack(">II", len(aad), len(data)) + key + aad + data + tag
    try:
        result = subprocess.run(
            [helper_path(), operation], input=payload, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    except (OSError, subprocess.SubprocessError):
        raise ValueError("instruction AEAD unavailable") from None
    expected = len(data) + (16 if operation == "seal" else 0)
    if result.returncode or len(result.stdout) != expected:
        raise ValueError("instruction authentication failed")
    return result.stdout


def seal(key, aad, plaintext):
    result = transform("seal", key, aad, plaintext)
    return result[:-16], result[-16:]


def open_sealed(key, aad, ciphertext, tag):
    return transform("open", key, aad, ciphertext, tag)
