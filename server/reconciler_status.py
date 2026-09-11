# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Source-owned, nonsecret reconciler failure identities."""

import re


def validate_ack_epoch(value):
    """Optional policy-history identity; legacy status has no epoch."""
    if value is not None and (not isinstance(value, str) or
                              re.fullmatch(r"[0-9a-f]{32}", value) is None):
        raise ValueError("bad operation_ack_epoch")
    return value

ARIA_SESSION_CHANGED = "aria_session_changed"
ARIA_SESSION_UNAVAILABLE = "aria_session_unavailable"
ENDPOINT_STORE_UNAVAILABLE = "endpoint_store_unavailable"
PEER_BLOCKLIST_APPLY_FAILED = "peer_blocklist_apply_failed"
PEER_RECONCILE_FAILED = "peer_reconcile_failed"
TARGET_DISCOVERY_UNAVAILABLE = "target_discovery_unavailable"
POLICY_FAIL_CLOSED = "policy_fail_closed"
ORIGIN_DESIRED_STATE_FAILED = "origin_desired_state_failed"
ORIGIN_GLOBAL_APPLY_FAILED = "origin_global_apply_failed"
ORIGIN_DOWNLOAD_APPLY_FAILED = "origin_download_apply_failed"
ORIGIN_RECONCILE_FAILED = "origin_reconcile_failed"

_SHARED = frozenset((ARIA_SESSION_CHANGED, ARIA_SESSION_UNAVAILABLE))
PEER_ERROR_CODES = _SHARED | frozenset((ENDPOINT_STORE_UNAVAILABLE,
    PEER_BLOCKLIST_APPLY_FAILED, PEER_RECONCILE_FAILED))
ORIGIN_ERROR_CODES = _SHARED | frozenset((TARGET_DISCOVERY_UNAVAILABLE,
    POLICY_FAIL_CLOSED, ORIGIN_DESIRED_STATE_FAILED, ORIGIN_GLOBAL_APPLY_FAILED,
    ORIGIN_DOWNLOAD_APPLY_FAILED, ORIGIN_RECONCILE_FAILED))


def validate_error_code(value, allowed):
    """Reject unknown historical/injected strings rather than trusting them."""
    if value is not None and (not isinstance(value, str) or value not in allowed):
        raise ValueError("bad last_error")
    return value
