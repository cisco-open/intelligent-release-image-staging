# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Validate seeder credentials before writing HTTP headers or aria2 options."""


def credential_text(value):
    """Return printable, whitespace-free ASCII without exposing bad values."""
    if (not isinstance(value, str) or not value
            or any(ord(char) < 0x21 or ord(char) > 0x7e for char in value)):
        raise ValueError("seeder credential unavailable")
    return value


def announce_authorization_header(value):
    """Build a single tracker header from a validated bearer credential."""
    try:
        token = credential_text(value)
    except ValueError:
        raise ValueError("current seeder announce credential unavailable") from None
    return "Authorization: Bearer " + token
