# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Canonical HTTP route registry for runtime dispatch and OpenAPI drift tests.

The console and management entries intentionally describe the same resources
at different trust boundaries.  Browser-facing paths use ``/api/v1``; the BFF
maps an authenticated request to ``/internal/v1`` and the management adapter
maps that path to the mature legacy handler internally.  No unregistered
management path is dispatched.
"""

from dataclasses import dataclass
import re
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class Route:
    service: str
    method: str
    path: str
    security: str
    summary: str


# (method, resource suffix, short operation summary).  A leading slash is
# required.  Path variables are exactly one encoded URL segment.
_CONSOLE_RESOURCES = (
    ("GET", "/peer-policy", "Read peer policy"),
    ("GET", "/peer-policy/roles", "List role definitions"),
    ("PUT", "/peer-policy/roles/{name}", "Replace a role definition"),
    ("DELETE", "/peer-policy/roles/{name}", "Delete a role definition"),
    ("PUT", "/peer-policy/qos", "Replace global or role QoS"),
    ("POST", "/devices/{device_id}/role", "Set a device role"),
    ("POST", "/devices/bulk-role", "Set device roles in bulk"),
    ("GET", "/devices/{device_id}/effective-qos", "Explain effective device QoS"),
    ("GET", "/peer-policy/explain", "Explain mutual peer access"),
    ("PUT", "/peer-policy/quarantine/{device_id}", "Set device quarantine"),
    ("GET", "/audit", "List audit events"),
    ("GET", "/audit/histogram", "Read audit histogram"),
    ("GET", "/session", "Read console session"),
    ("POST", "/login", "Create console session"),
    ("POST", "/setup", "Create the first administrator"),
    ("POST", "/logout", "End console session"),
    ("GET", "/images", "List images"),
    ("GET", "/images/importable", "List importable images"),
    ("POST", "/images/import", "Import an image"),
    ("PUT", "/images/upload/{filename}", "Upload an image"),
    ("GET", "/images/jobs/{job_id}", "Read image job"),
    ("DELETE", "/images/{image_id}", "Delete an image"),
    ("POST", "/images/{image_id}/release-quarantine", "Release image quarantine"),
    ("POST", "/image-verification/offline", "Upload offline verification data"),
    ("POST", "/image-verification/refresh", "Start image verification refresh"),
    ("GET", "/devices", "List devices"),
    ("POST", "/devices", "Create a device"),
    ("DELETE", "/devices/{device_id}", "Retire a device"),
    ("GET", "/devices/export-csv", "Export devices"),
    ("GET", "/devices/example-csv", "Download example device CSV"),
    ("POST", "/devices/import-csv", "Import devices"),
    ("POST", "/devices/bulk-credential", "Assign credentials in bulk"),
    ("GET", "/devices/{device_id}/plan", "Read device plan"),
    ("GET", "/devices/{device_id}/reports", "List device reports"),
    ("GET", "/devices/{device_id}/deployment", "Read device deployment"),
    ("POST", "/devices/{device_id}/assign", "Assign an image"),
    ("POST", "/devices/{device_id}/credential", "Assign a credential"),
    ("POST", "/devices/{device_id}/platform", "Set device platform"),
    ("POST", "/devices/{device_id}/forget-host-key", "Forget SSH host key"),
    ("POST", "/devices/{device_id}/request-report", "Request a device report"),
    ("POST", "/devices/{device_id}/adopt", "Adopt a deployment"),
    ("POST", "/devices/{device_id}/onboard", "Start device onboarding"),
    ("POST", "/devices/{device_id}/undeploy", "Start device removal"),
    ("GET", "/install-options", "List install options"),
    ("GET", "/credentials", "List credential profiles"),
    ("POST", "/credentials", "Create a credential profile"),
    ("DELETE", "/credentials/{credential_id}", "Delete a credential profile"),
    ("GET", "/onboard/jobs", "List onboarding jobs"),
    ("GET", "/onboard/jobs/{job_id}", "Read onboarding job"),
    ("GET", "/onboard/jobs/{job_id}/stream", "Stream onboarding job output"),
    ("POST", "/onboard/jobs/{job_id}/abort", "Abort onboarding job"),
    ("POST", "/onboard/cancel-queued", "Cancel queued onboarding jobs"),
    ("GET", "/deploy-logs", "List deployment logs"),
    ("GET", "/deploy-logs/histogram", "Read deployment log histogram"),
    ("GET", "/deploy-logs/{filename}", "Read deployment log"),
    ("GET", "/overview", "Read fleet overview"),
    ("GET", "/swarm", "Read swarm state"),
    ("GET", "/telemetry/health", "Read telemetry health"),
    ("POST", "/telemetry/stream", "Proxy telemetry stream"),
    ("GET", "/settings", "Read settings"),
    ("POST", "/settings/password", "Change administrator password"),
    ("POST", "/settings/sessions/revoke-others", "Revoke other sessions"),
    ("GET", "/settings/setup-status", "Read setup status"),
    ("GET", "/settings/image-verification", "Read verification settings"),
    ("POST", "/settings/image-verification", "Update verification settings"),
    ("POST", "/settings/audit-export", "Update audit export settings"),
    ("DELETE", "/settings/audit-export", "Delete audit export settings"),
    ("POST", "/settings/audit-export/run", "Start audit export"),
    ("GET", "/settings/audit-export/run/{job_id}", "Read audit export job"),
    ("POST", "/settings/ca-trust", "Update CA trust settings"),
    ("POST", "/settings/ca-trust/refresh", "Start CA trust refresh"),
    ("GET", "/settings/ca-trust/refresh/{job_id}", "Read CA trust refresh job"),
    ("POST", "/settings/telemetry-destination", "Update telemetry destination"),
    ("DELETE", "/settings/telemetry-destination", "Delete telemetry destination"),
    ("POST", "/settings/gui-cert", "Install console certificate"),
    ("DELETE", "/settings/gui-cert", "Remove console certificate"),
    ("POST", "/settings/trust", "Install a trust anchor"),
    ("DELETE", "/settings/trust/{name}", "Delete a trust anchor"),
    ("GET", "/help", "Read help metadata"),
)


def _console_security(method, suffix, internal=False):
    if method == "POST" and suffix == "/login":
        return ("managementBearer+consolePassword" if internal
                else "consolePassword")
    if method == "POST" and suffix == "/setup":
        return ("managementBearer+setupGrant" if internal else "setupGrant")
    return "managementBearer+consoleSession" if internal else "consoleSession"


ROUTES = tuple(
    Route("console", method, "/api/v1" + suffix,
          _console_security(method, suffix), summary)
    for method, suffix, summary in _CONSOLE_RESOURCES
) + (
    Route("console", "GET", "/swarmmap", "consoleSession", "Open swarm map"),
    Route("console", "GET", "/healthz", "none", "Read console health"),
    Route("console", "GET", "/readyz", "none", "Read console readiness"),
) + tuple(
    Route("management", method, "/internal/v1" + suffix,
          _console_security(method, suffix, internal=True), summary)
    for method, suffix, summary in _CONSOLE_RESOURCES
) + (Route("management", "GET", "/internal/v1/swarmmap",
           "managementBearer+consoleSession", "Open swarm map"),) + (
    Route("management", "GET", "/internal/v1/console-certificate",
          "managementBearer", "Read active console TLS identity"),
    Route("management", "POST", "/internal/v1/authorizations",
          "managementBearer", "Authorize a browser mutation"),
    Route("catalog", "GET", "/v1/images", "deviceBearer", "List assigned images"),
    Route("catalog", "GET", "/v1/images/{image_id}", "deviceBearer", "Read assigned image"),
    Route("catalog", "GET", "/v1/torrents/{image_id}", "deviceBearer", "Download personalized torrent"),
    Route("catalog", "GET", "/v1/devices/{device_id}/policy", "deviceBearer", "Read device policy"),
    Route("catalog", "POST", "/v1/devices/{device_id}/heartbeat", "deviceBearer", "Record heartbeat"),
    Route("catalog", "POST", "/v1/devices/{device_id}/telemetry", "deviceBearer", "Record telemetry"),
    Route("catalog", "POST", "/v1/devices/{device_id}/token-refresh", "deviceBearer", "Rotate device token"),
    Route("tracker", "GET", "/announce", "announceBearerOrLegacyQuery", "Announce peer"),
    Route("tracker", "GET", "/scrape", "announceBearerOrLegacyQuery", "Scrape torrent"),
    Route("telemetry", "GET", "/metrics", "observabilityBearer", "Read Prometheus metrics"),
    Route("telemetry", "GET", "/healthz", "none", "Read listener health"),
    Route("telemetry", "GET", "/readyz", "none", "Read listener readiness"),
    Route("telemetry", "GET", "/swarm", "managementBearer", "Read swarm state"),
    Route("telemetry", "GET", "/status", "managementBearer",
          "Read detailed telemetry status"),
    Route("artifact", "GET", "/v1/devices/{device_id}/artifacts/{artifact_path}",
          "artifactBasic", "Download device artifact"),
    Route("artifact", "HEAD", "/v1/devices/{device_id}/artifacts/{artifact_path}",
          "artifactBasic", "Inspect device artifact"),
    # Guest Shell uses IOS ``copy https:`` and cannot attach Basic headers.
    # Static entries contain no credentials; staging names carry a 128-bit
    # capability and are swept.  Keep these explicit so the compatibility
    # exception cannot silently grow into arbitrary anonymous file serving.
    Route("artifact", "GET", "/bootstrap.sh", "guestShellAnonymousStatic",
          "Download Guest Shell bootstrap"),
    Route("artifact", "HEAD", "/bootstrap.sh", "guestShellAnonymousStatic",
          "Inspect Guest Shell bootstrap"),
    Route("artifact", "GET", "/iris-agent.tgz", "guestShellAnonymousStatic",
          "Download x86 Guest Shell agent"),
    Route("artifact", "HEAD", "/iris-agent.tgz", "guestShellAnonymousStatic",
          "Inspect x86 Guest Shell agent"),
    Route("artifact", "GET", "/iris-agent-arm.tgz", "guestShellAnonymousStatic",
          "Download ARM Guest Shell agent"),
    Route("artifact", "HEAD", "/iris-agent-arm.tgz", "guestShellAnonymousStatic",
          "Inspect ARM Guest Shell agent"),
    Route("artifact", "GET", "/iris-catalog.pem", "guestShellAnonymousStatic",
          "Download Guest Shell catalog CA"),
    Route("artifact", "HEAD", "/iris-catalog.pem", "guestShellAnonymousStatic",
          "Inspect Guest Shell catalog CA"),
    Route("artifact", "GET", "/staging/{legacy_artifact}",
          "legacyGuestShell", "Download Guest Shell enrollment capability"),
    Route("artifact", "HEAD", "/staging/{legacy_artifact}",
          "legacyGuestShell", "Inspect Guest Shell enrollment capability"),
)


def _pattern(template):
    cursor = 0
    pieces = []
    for match in re.finditer(r"\{([a-z_][a-z0-9_]*)\}", template):
        pieces.append(re.escape(template[cursor:match.start()]))
        # Artifact paths intentionally name a hierarchy below the protected
        # device resource; all other variables are one encoded segment.
        if match.group(1) == "artifact_path":
            atom = ".+"
        elif match.group(1) == "legacy_artifact":
            atom = (r"(?:iris-agent-[A-Za-z0-9._:-]+-[0-9A-Fa-f]{32}\.conf|"
                    r"rpc-secret-[0-9A-Fa-f]{32})")
        else:
            atom = "[^/]+"
        pieces.append("(?P<%s>%s)" % (match.group(1), atom))
        cursor = match.end()
    pieces.append(re.escape(template[cursor:]))
    return re.compile("^" + "".join(pieces) + "$")


_COMPILED = tuple((route, _pattern(route.path)) for route in ROUTES)


def match(service, method, path):
    """Return the registered route matching a URL path, else ``None``."""
    clean = urlsplit(path).path
    for route, pattern in _COMPILED:
        # HTTP method tokens are case-sensitive. Treat a lowercase/custom
        # spelling as unsupported so it cannot be normalized into a privileged
        # registered operation before the handler emits Problem Details.
        if route.service == service and route.method == method \
                and pattern.fullmatch(clean):
            return route
    return None


def _replace_prefix(url, source, target):
    parts = urlsplit(url)
    if not parts.path.startswith(source):
        return None
    mapped = target + parts.path[len(source):]
    return urlunsplit((parts.scheme, parts.netloc, mapped, parts.query,
                       parts.fragment))


def console_to_management(method, url):
    """Map a browser API URL without revealing whether it is registered.

    The management tier authenticates the browser session before consulting
    the registry. Returning ``None`` for an unknown browser path here would
    let an unauthenticated caller distinguish it from a known path by 404 vs
    401 at the BFF boundary.
    """
    path = urlsplit(url).path
    if path == "/swarmmap":
        if match("console", method, url) is not None:
            return _replace_prefix(url, "/swarmmap", "/internal/v1/swarmmap")
        return _replace_prefix(url, path,
                               "/internal/v1/__unregistered-browser-route")
    if path.startswith("/api/"):
        if match("console", method, url) is not None:
            return _replace_prefix(url, "/api/", "/internal/")
        # An unknown browser path still reaches management so its session
        # check precedes 404, but always through one non-colliding sentinel.
        # Mechanical suffix mapping could otherwise make a future internal-
        # only control (private-key export, preauthorization) browser-callable.
        return _replace_prefix(url, path,
                               "/internal/v1/__unregistered-browser-route")
    return None


def management_to_legacy(method, url):
    """Map a registered management URL to the legacy in-process path."""
    route = match("management", method, url)
    if route is None:
        return None
    if urlsplit(url).path == "/internal/v1/swarmmap":
        return _replace_prefix(url, "/internal/v1/swarmmap", "/swarmmap")
    if urlsplit(url).path == "/internal/v1/console-certificate":
        return _replace_prefix(url, "/internal/v1/console-certificate",
                               "/__management/console-certificate")
    if urlsplit(url).path == "/internal/v1/authorizations":
        return _replace_prefix(url, "/internal/v1/authorizations",
                               "/__management/authorizations")
    return _replace_prefix(url, "/internal/v1", "/api")


def keys():
    """Return canonical triples consumed by the bidirectional spec test."""
    return {(route.service, route.method, route.path) for route in ROUTES}
