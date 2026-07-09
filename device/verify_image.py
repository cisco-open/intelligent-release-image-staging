#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Verifier for the IRIS device agent.

sha256_matches hashes the STAGED file (under /flash/guest-share, readable from
guestshell) and gates whether the copy-to-root runs at all. It's the only check
the agent computes itself; the flash-root copy's authenticity is enforced
on-box by IOS `copy /verify` (copy + Cisco signature in one step — a bad
signature fails the copy and deletes the destination), so the agent never has
to read the image back. Pure function so it unit-tests off-box without the
on-device `cli` module."""
import hashlib


def sha256_matches(path, expected_hex, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest().lower() == expected_hex.lower()
