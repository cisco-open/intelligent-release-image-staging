# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Small, dependency-free RFC 9457 Problem Details helpers.

Problem ``type`` values are stable identifiers under the public documentation
namespace.  Details passed here must already be safe for an untrusted caller;
this module intentionally never serializes exceptions, paths, or credentials.
"""

import json


# The fragment keeps every stable code on one resolvable documentation page
# while remaining a distinct RFC 9457 type URI.
TYPE_BASE = "https://cisco-open.github.io/intelligent-release-image-staging/docs/problems/#"

# Stable status-level examples shared by the runtime adapter and OpenAPI.
# Individual guards may use a more specific code (for example
# ``csrf-validation-failed``), but never a contradictory generic spelling.
STATUS_DEFAULTS = {
    400: ("invalid-request", "Invalid request"),
    401: ("authentication-required", "Authentication required"),
    403: ("forbidden", "Forbidden"),
    404: ("resource-not-found", "Resource not found"),
    405: ("method-not-allowed", "Method not allowed"),
    408: ("request-timeout", "Request timeout"),
    409: ("resource-conflict", "Resource conflict"),
    411: ("content-length-required", "Content-Length required"),
    412: ("precondition-failed", "Precondition failed"),
    413: ("payload-too-large", "Payload too large"),
    415: ("unsupported-media-type", "Unsupported media type"),
    416: ("range-not-satisfiable", "Range not satisfiable"),
    422: ("unprocessable-content", "Unprocessable content"),
    428: ("precondition_required", "Precondition required"),
    429: ("rate-limit-exceeded", "Rate limit exceeded"),
    500: ("internal-error", "Internal server error"),
    502: ("upstream-operation-failed", "Upstream operation failed"),
    503: ("service-unavailable", "Service unavailable"),
}


def document(status, code, title, detail=None, instance=None, **extensions):
    """Return a redacted RFC 9457 problem document."""
    body = {
        "type": TYPE_BASE + code,
        "title": title,
        "status": int(status),
        # A short, stable machine-readable member is an intentional RFC 9457
        # extension.  Clients should not have to parse the documentation URL
        # in ``type`` to branch on a failure.
        "code": code,
    }
    if detail:
        body["detail"] = detail
    if instance:
        body["instance"] = instance
    for key, value in extensions.items():
        if value is not None:
            body[key] = value
    return body


def send(handler, status, code, title, detail=None, headers=None, instance=None,
         **extensions):
    """Write one Problem Details response through a BaseHTTPRequestHandler."""
    headers = list(headers or ())
    if status in (429, 503) and not any(
            str(name).lower() == "retry-after" for name, _ in headers):
        headers.append(("Retry-After", "1"))
    payload = json.dumps(document(status, code, title, detail, instance,
                                  **extensions), separators=(",", ":")).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/problem+json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    for name, value in headers:
        handler.send_header(name, value)
    handler.end_headers()
    if getattr(handler, "command", "") != "HEAD":
        handler.wfile.write(payload)


def legacy(handler, status, obj, headers=None):
    """Normalize a mature ``{"error": ...}`` response without breaking UI JSON.

    The legacy ``error`` member is retained as a deprecated extension for 4xx
    responses while clients migrate to stable ``type``. Server failures get a
    fixed message so exception text and filesystem paths never cross the wire.
    """
    error = obj.get("error") if isinstance(obj, dict) else None
    text = error if isinstance(error, str) else "request failed"
    lower = text.lower()
    if status >= 500:
        code, title = STATUS_DEFAULTS.get(status, STATUS_DEFAULTS[500])
        safe_error = title.lower()
    elif status == 401:
        code, title = STATUS_DEFAULTS[401]
        safe_error = text
    elif status == 403 and "csrf" in lower:
        code, title, safe_error = "csrf-validation-failed", "CSRF validation failed", text
    elif status == 403:
        code, title = STATUS_DEFAULTS[403]
        safe_error = text
    elif status == 404 or lower.startswith("no such") or lower == "not found":
        code, title = STATUS_DEFAULTS[404]
        safe_error = text
    elif status in STATUS_DEFAULTS:
        code, title = STATUS_DEFAULTS[status]
        safe_error = text
    else:
        code, title = STATUS_DEFAULTS[400]
        safe_error = text
    extensions = dict(obj) if isinstance(obj, dict) else {}
    extensions["error"] = safe_error
    extensions.pop("type", None)
    extensions.pop("title", None)
    extensions.pop("status", None)
    send(handler, status, code, title, headers=headers, **extensions)
