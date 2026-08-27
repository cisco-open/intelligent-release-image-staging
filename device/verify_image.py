#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Verifier for the IRIS device agent.

sha256_matches hashes the STAGED file (under /flash/guest-share, readable from
guestshell) and gates whether the copy-to-root runs at all. This hash check IS
the image-integrity verification — there is no on-box re-check. The
flash-root copy itself is a plain `copy`; placement is attested by the agent's
own dir-presence + exact catalog byte size check, not by reading the image
back. Authenticity is established server-side at publish time. Pure function
so it unit-tests off-box without the on-device `cli` module."""
import hashlib


def sha256_matches(path, expected_hex, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest().lower() == expected_hex.lower()
