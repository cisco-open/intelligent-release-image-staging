# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Resolve and validate the public HTTPS tracker announce endpoint."""

import ipaddress
import os
from urllib.parse import urlsplit, urlunsplit


DEFAULT_PORT = "6969"
ANNOUNCE_PATH = "/announce"

_INVALID = "invalid tracker announce URL"
_UNAVAILABLE = "tracker announce URL unavailable"


def validate(value):
    """Return a normalized, token-free HTTPS announce URL.

    The endpoint must use a usable IPv4 address.  Private, shared (RFC 6598),
    and public addresses are allowed; addresses that no fleet peer could use
    as a tracker endpoint are refused.  Errors deliberately never echo the
    supplied value because it may have been misconfigured with a credential.
    """
    if not isinstance(value, str) or not value:
        raise ValueError(_INVALID)
    if any(ord(char) <= 0x20 or ord(char) == 0x7f for char in value):
        raise ValueError(_INVALID)
    if "?" in value or "#" in value:
        raise ValueError(_INVALID)

    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
        username = parsed.username
        password = parsed.password
    except (UnicodeError, ValueError):
        raise ValueError(_INVALID) from None

    if (parsed.scheme != "https" or not parsed.netloc or hostname is None
            or username is not None or password is not None
            or parsed.query or parsed.fragment):
        raise ValueError(_INVALID)

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        raise ValueError(_INVALID) from None
    if (address.version != 4 or address.is_loopback or address.is_link_local
            or address.is_unspecified or address.is_multicast
            or address.is_reserved):
        raise ValueError(_INVALID)

    # urlsplit accepts an empty port (``host:``), and int() accepts some
    # non-ASCII digits.  Neither is a valid URI authority for this endpoint.
    authority = parsed.netloc
    if ":" in authority:
        authority_host, port_text = authority.rsplit(":", 1)
        if (authority_host != hostname or not port_text
                or not port_text.isascii() or not port_text.isdigit()):
            raise ValueError(_INVALID)
        if port is None or not 1 <= port <= 65535:
            raise ValueError(_INVALID)
    elif authority != hostname:
        raise ValueError(_INVALID)

    path = parsed.path or ANNOUNCE_PATH
    if path != ANNOUNCE_PATH:
        raise ValueError(_INVALID)

    normalized_authority = str(address)
    if port is not None:
        normalized_authority += ":%d" % port
    return urlunsplit(("https", normalized_authority, path, "", ""))


def resolve(env=None):
    """Resolve the configured public tracker announce URL and validate it.

    ``IRIS_TRACKER_ANNOUNCE`` takes precedence.  Otherwise the URL is derived
    from ``IRIS_HOST_IP`` and ``IRIS_TRACKER_PORT`` (default 6969).
    """
    env = os.environ if env is None else env
    configured = env.get("IRIS_TRACKER_ANNOUNCE")
    if configured:
        return validate(configured)

    host = env.get("IRIS_HOST_IP")
    if not host:
        raise ValueError(_UNAVAILABLE)
    port = env.get("IRIS_TRACKER_PORT") or DEFAULT_PORT
    return validate("https://%s:%s%s" % (host, port, ANNOUNCE_PATH))
