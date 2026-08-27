# server/gui_onboard.py
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""OnboardService: one-click device onboarding. Resolves a device's FleetStore row
+ CredentialStore profile, mints a short-lived enrollment token, and runs the
existing device/device-install.sh over SSH (shelling out — the installer is 300+
lines of hardware-specific IOS/SSH logic; reimplementing risks divergence),
streaming its output into an in-memory job the UI reads over SSE. The subprocess
runner and the token minter are INJECTED so orchestration is unit-testable without
a device. Stage-only invariant preserved: device-install.sh only sets up the agent
+ enrollment; it never installs/activates/reloads. Stdlib only.

Note: onboarding passes DEVICE_PASS (and, when configured in the store, the
stage-host HOST_USER/HOST_PASS) to the installer via the environment (consumed
by lab/device-run.sh's SSHPASS and the installer's sshpass). The streamed job
lines are the installer's stdout, which echoes neither password (sshpass reads
them from the env)."""
import inspect
import ipaddress
import os
import queue
import re
import secrets
import signal
import subprocess
import threading
import time

_JOB_TTL = 3600  # seconds a terminal onboard job is retained before eviction
# Wall-clock bound on a RUNNING job. Without one, a recipe whose output pipe
# never EOFs hangs forever: the job never becomes terminal, so it is never
# evicted, so the device stays permanently "busy" and every later onboard AND
# undeploy for it is refused. Comfortably above the slowest real recipe (the
# router guestshell wait plus copy retries, ~7-10 min).
_JOB_DEADLINE = int(os.environ.get("IRIS_ONBOARD_JOB_TIMEOUT") or 7200)
_TERMINAL = ("done", "error", "cancelled")
_DEFAULT_CONCURRENCY = 25  # simultaneous installer runs (env IRIS_ONBOARD_CONCURRENCY)
# A fleet action may legitimately be large, but a request storm must not retain
# unlimited closures/jobs. 1,000 pending jobs is ample operational headroom.
_MAX_QUEUED_JOBS = 1000
# Installer output can be very noisy. Bound both object count and encoded bytes;
# the byte cap is the stronger memory guarantee for unusually long lines.
_MAX_JOB_LOG_LINES = 2000
_MAX_JOB_LOG_BYTES = 256 * 1024
_LOG_TRUNCATED = "[additional job output truncated: retention limit reached]"
# In-memory jobs evaporate after _JOB_TTL; when a log_dir is configured every
# finished job's log is also written there so an operator can read yesterday's
# failure. Bounded: the directory is pruned to the newest N files.
_MAX_PERSISTED_LOGS = 200


def _fmt_dur(secs):
    """Human-readable duration for audit details: '52s' / '4m32s' / '1h04m'."""
    secs = int(secs)
    if secs < 60:
        return "%ds" % secs
    m, s = divmod(secs, 60)
    if m < 60:
        return "%dm%02ds" % (m, s)
    h, m = divmod(m, 60)
    return "%dh%02dm" % (h, m)

# Platform onboarding recipes: which installer drives a device family.
# Extending to a new model family = one _MODEL_PLATFORMS row (+ a recipe if
# the deployment mechanism is genuinely new).
_PLATFORM_RECIPES = {
    "guestshell": "device/device-install.sh",
    "iox": "device/iox/install.sh",
    "router": "device/router-install.sh",
}
# Teardown recipe per platform — the inverse of _PLATFORM_RECIPES, so undeploy
# is fleet-wide (Guest Shell C9300/ISR/ASR AND IOx IE-3x00/IR1101/IR18xx).
_UNINSTALL_RECIPES = {
    "guestshell": "device/device-uninstall.sh",
    "iox": "device/iox/uninstall.sh",
    "router": "device/router-uninstall.sh",
}
_MODEL_PLATFORMS = (          # first match wins; case-insensitive prefix regexes
    (r"^IE-?3", "iox"),       # IE-3x00: no Guest Shell on IOS-XE >=17.9
    (r"^IR1[018]", "iox"),    # IR1101/IR18xx are IOx-hosted the same way
    (r"^C9[0-9]{3}", "guestshell"),
    (r"^C8[0-9]{3}", "router"),
    (r"^(ISR|ASR|CSR)", "guestshell"),  # legacy router mapping; not yet supported
)

# Model families that take the arm64 IOx package (installer defaults: iris-arm64.tar,
# AppGigabitEthernet1/1, sdflash:). Used ONLY after platform has resolved to iox.
_ARM_IOX_MODELS = (r"^IE-?3", r"^IR1[018]")
# Catalyst 9000 -> amd64 IOx package; the app-hosting SSD share
# (usbflash1:iox_host_data_share, host-side /vol/usb1) is bind-mounted into
# the app so image transfer is a local disk write + an IOS-internal
# `copy /verify` onto bootflash — same final placement as Guest Shell, and no
# CoPP-policed punt traffic. Stacked-member-overridable APP_INTF.
_C9K_MODEL = r"^C9[0-9]{3}"
_C9K_IOX_ENV = {
    "PKG": "iris-amd64.tar",
    "APP_INTF": "AppGigabitEthernet1/0/1",
    "TARGET_FS": "flash:",
    "SHARE_HOST_PATH": "/vol/usb1/iox_host_data_share",
    "SHARE_IOS_PATH": "usbflash1:iox_host_data_share",
}


def _iox_arch_env(device_id, model):
    """Given a device that has ALREADY resolved to the iox platform, return the
    env overrides for its architecture. C9k -> the amd64 mapping; IE-3k/IR ->
    an EMPTY mapping (installer arm64 defaults apply); blank/unclassifiable ->
    raise ValueError with guidance (NO silent arm fallback). No probe-for-arch."""
    model = (model or "").strip()
    if model and re.match(_C9K_MODEL, model, re.IGNORECASE):
        return dict(_C9K_IOX_ENV)
    if model and any(re.match(p, model, re.IGNORECASE) for p in _ARM_IOX_MODELS):
        return {}
    raise ValueError(
        "IOx onboarding for %s needs a recognized device model to select the "
        "package/architecture (C9k->amd64, IE-3k/IR->arm). Set the device model."
        % device_id)


def resolve_platform(dev, probe=None):
    """Resolve which onboarding platform drives a device.

    Resolution order: (a) explicit dev['platform'] if it names a known recipe;
    (b) dev['model'] matched against _MODEL_PLATFORMS; (c) if a probe callable
    is given, call it with dev -- if it returns a model string, match that
    (the CALLER is responsible for caching the probed model, e.g. into the
    fleet store); (d) ValueError telling the operator how to unblock."""
    device_id = dev.get("device_id", "?")
    explicit = dev.get("platform")
    if explicit:
        if explicit not in _PLATFORM_RECIPES:
            raise ValueError(
                "unknown platform %r for %s: valid platforms are %s"
                % (explicit, device_id, ", ".join(sorted(_PLATFORM_RECIPES))))
        if re.match(r"^C8[0-9]{3}", dev.get("model") or "", re.IGNORECASE) \
                and explicit != "router":
            raise ValueError("Catalyst 8000 models require platform router")
        return explicit

    def _match(model):
        for pattern, platform in _MODEL_PLATFORMS:
            if re.match(pattern, model, re.IGNORECASE):
                return platform
        return None

    model = dev.get("model")
    if model:
        platform = _match(model)
        if platform:
            return platform
        raise ValueError(
            "cannot determine platform for %s: unrecognized model %r -- set "
            "'platform' (guestshell|iox|router) or a recognized 'model' on the device"
            % (device_id, model))

    if probe is not None:
        probed_model = probe(dev)
        if probed_model:
            platform = _match(probed_model)
            if platform:
                return platform

    raise ValueError(
        "cannot determine platform for %s: set 'platform' (guestshell|iox|router) "
        "or 'model' on the device" % device_id)


def _default_mint(device_id, server_dir):
    out = subprocess.run([os.path.join(server_dir, "iris-mint-enrollment"), device_id],
                         capture_output=True, text=True, check=True)
    return out.stdout.strip()


def _default_runner(install_path, env, on_line, on_proc=None):
    """Run device-install.sh, calling on_line(line) for each stdout/stderr line.
    Returns the process exit code. on_proc(proc), when given, receives the live
    Popen so the caller can terminate it (abort)."""
    # start_new_session puts the recipe in its OWN process group. Without it,
    # terminating "bash" leaves the ssh -tt it spawned holding the stdout pipe,
    # so the read loop below never sees EOF and the job hangs forever instead of
    # failing -- which is how a device ends up mutated with no finish, no log
    # and no reapable job record.
    proc = subprocess.Popen(["bash", install_path], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, start_new_session=True)
    if on_proc is not None:
        on_proc(proc)
    try:
        for line in proc.stdout:
            on_line(line.rstrip("\n"))
    finally:
        proc.stdout.close()
    return proc.wait()


_MODEL_RE = re.compile(r"^cisco\s+(\S+)\s+\(", re.MULTILINE)
_DEVICE_IDENTITY_RE = re.compile(r"(?im)^Processor board ID\s+(\S+)\s*$")

# 'IOS XE' and 'IOS XR' differ by a single character, and no model prefix can
# separate the families: ^ASR matches both an ASR 1000 (IOS-XE, Guest Shell
# capable) and an ASR 9000 (IOS-XR, which has no Guest Shell at all). The
# banner is the only authority, so match the whole token and never a prefix.
_OS_XR_RE = re.compile(r"\bIOS[\s-]*XR\b", re.IGNORECASE)
_OS_XE_RE = re.compile(r"\bIOS[\s-]*XE\b", re.IGNORECASE)
_OS_CLASSIC_RE = re.compile(r"\bCisco IOS Software\b", re.IGNORECASE)


def parse_os_family(version_text):
    """Classify 'show version' output as 'xe', 'xr', or '' (unknown).

    Classic IOS (no XE/XR token) reports 'xe': it is driven by the same
    recipes, and the distinction that matters here is XE-family vs XR-family,
    not XE vs classic."""
    text = version_text or ""
    if _OS_XR_RE.search(text):
        return "xr"
    if _OS_XE_RE.search(text) or _OS_CLASSIC_RE.search(text):
        return "xe"
    return ""


def _parse_show_version(version_text):
    """Extract (model, device_identity) from 'show version' output. Either
    element is '' when its line is not present. Shared by the router and
    IOx preflights so both trust the same real-device parsing (a single
    regex pair to keep in sync instead of two)."""
    model_match = _MODEL_RE.search(version_text)
    identity_match = _DEVICE_IDENTITY_RE.search(version_text)
    return (model_match.group(1) if model_match else "",
            identity_match.group(1) if identity_match else "")


def _default_probe(dev, env, repo_root):
    """Best-effort live 'show version' probe over lab/device-run.sh, using the
    DEVICE_USER/DEVICE_PASS already resolved into env. ANY failure -> None
    (never raises) -- an unreachable device just falls through to the
    resolve_platform ValueError telling the operator to set platform/model."""
    device_ip = env.get("DEVICE_IP", "")
    try:
        out = subprocess.run(
            ["bash", os.path.join(repo_root, "lab", "device-run.sh"), device_ip],
            input="show version\n", capture_output=True, text=True, env=env,
            timeout=45)
    except Exception:
        return None
    m = _MODEL_RE.search(out.stdout or "")
    return m.group(1) if m else None


# Collisions that mean the same thing on EVERY platform: each carries IRIS's
# own name, so its presence says a previous deployment is still on the device.
# Preflight used to check these for routers only, so the identical device was
# refused as a router and silently accepted as Guest Shell or IOx.
_IRIS_NAMED_COLLISIONS = (
    (r"(?m)^event manager applet IRIS-(?:AGENT|COPYROOT|RECLAIM|RECLAIM-BUNDLE)(?:\s|$)",
     "an IRIS EEM applet"),
    (r"(?m)^logging discriminator IRISQ(?:\s|$)", "logging discriminator IRISQ"),
    (r"(?m)^logging (?:buffered|console|monitor) discriminator IRISQ\s*$",
     "an IRISQ logging binding"),
    (r"(?m)^crypto pki trustpoint IRIS\s*$", "crypto pki trustpoint IRIS"),
    (r"(?m)^ip http client secure-trustpoint IRIS\s*$",
     "the IRIS HTTP client trustpoint binding"),
)


def _check_iris_named_collisions(running, extra=()):
    """Raise on any IRIS-named artifact still present. ``extra`` carries the
    platform's own app-hosting stanza, which differs per platform."""
    for pattern, description in tuple(extra) + _IRIS_NAMED_COLLISIONS:
        if re.search(pattern, running):
            raise ValueError("%s already exists" % description)


def _probe_sections(runner, env, commands, label):
    """Run every command in ONE ssh login and split the output on echoed
    markers. One login per device is what makes a large fleet submission
    viable -- see the note in the router preflight."""
    marker = "__IRIS_PREFLIGHT_"
    request = "\n".join(
        "echo %s%s__\n%s" % (marker, name.upper(), command)
        for name, command in commands) + "\n"
    out = subprocess.run(["bash", runner, env["DEVICE_IP"]], input=request,
                         capture_output=True, text=True, env=env, timeout=60)
    if out.returncode != 0:
        raise ValueError("%s preflight could not run" % label)
    sections = {}
    for name, _command in commands:
        start = "%s%s__" % (marker, name.upper())
        match = re.search(re.escape(start) + r"\r?\n?(.*?)(?=" +
                          re.escape(marker) + r"[A-Z_]+__|\Z)",
                          out.stdout or "", re.DOTALL)
        if not match:
            raise ValueError("%s preflight did not return %s" % (label, name))
        sections[name] = match.group(1)
    return sections


def _default_guestshell_preflight(dev, env, resolved, repo_root):
    """Read-only collision check for a Guest Shell deployment -- the same
    checks the router flow has always run, minus the VPG/NAT specifics that
    only exist on a router."""
    runner = os.path.join(repo_root, "lab", "device-run.sh")
    sections = _probe_sections(runner, env, (
        ("version", "show version"),
        ("running", "show running-config"),
        ("apps", "show app-hosting list"),
        ("files", "dir bootflash:guest-share"),
    ), "guestshell")
    model, device_identity = _parse_show_version(sections["version"])
    if not device_identity:
        raise ValueError("could not determine the device's processor board ID")
    _check_iris_named_collisions(sections["running"], extra=(
        (r"(?m)^app-hosting appid guestshell\s*$", "guestshell app-hosting config"),))
    if re.search(r"(?im)^\s*(?:app id\s*:\s*)?guestshell(?:\s|$)", sections["apps"]):
        raise ValueError("guestshell is already enabled")
    files = sections["files"]
    if re.search(r"(?im)Directory of\s+bootflash:/?guest-share/?", files) \
            and not re.search(r"(?im)^No files in directory\s*$", files):
        raise ValueError("bootflash:guest-share is not empty")
    evidence = {"status": "passed", "device_identity": device_identity}
    if model:
        evidence["detected_model"] = model
    return evidence


def _default_router_preflight(dev, env, resolved, repo_root):
    """Read-only collision check for a Catalyst 8000 VPG deployment."""
    runner = os.path.join(repo_root, "lab", "device-run.sh")
    commands = [
        ("version", "show version"),
        ("running", "show running-config"),
        ("apps", "show app-hosting list"),
        ("guest_share", "dir bootflash:guest-share"),
    ]
    if resolved.get("attachment") == "router-nat":
        commands.append(("interfaces", "show interfaces %s" % resolved["nat_interface"]))
    # One SSH login per router is essential for large fleet submissions. IOS XE
    # echoes these markers verbatim, letting the same fail-closed checks consume
    # each command's output without paying a connection setup per check.
    marker = "__IRIS_PREFLIGHT_"
    request = "\n".join(
        "echo %s%s__\n%s" % (marker, name.upper(), command)
        for name, command in commands) + "\n"
    out = subprocess.run(["bash", runner, env["DEVICE_IP"]], input=request,
                         capture_output=True, text=True, env=env, timeout=60)
    if out.returncode != 0:
        raise ValueError("router preflight could not run")
    sections = {}
    for name, _command in commands:
        start = "%s%s__" % (marker, name.upper())
        match = re.search(re.escape(start) + r"\r?\n?(.*?)(?=" +
                          re.escape(marker) + r"[A-Z_]+__|\Z)",
                          out.stdout or "", re.DOTALL)
        if not match:
            raise ValueError("router preflight did not return %s" % name)
        sections[name] = match.group(1)

    version = sections["version"]
    model, device_identity = _parse_show_version(version)
    if not re.match(r"^C8[0-9]{3}", model, re.IGNORECASE):
        raise ValueError("router modes support the Catalyst 8000 family only; %s is not yet supported"
                         % (model or "detected model"))
    if not device_identity:
        raise ValueError("could not determine the router's processor board ID")

    running = sections["running"]
    vpg = str(resolved.get("vpg_number", ""))
    if re.search(r"(?m)^interface VirtualPortGroup%s\s*$" % re.escape(vpg), running):
        raise ValueError("VirtualPortGroup%s already exists" % vpg)

    candidate = ipaddress.IPv4Network(
        "%s/%s" % (resolved["app_ip"], resolved["app_mask"]), strict=False)
    for address, mask in re.findall(
            r"(?m)^\s*ip address\s+(\d+(?:\.\d+){3})\s+"
            r"(\d+(?:\.\d+){3})(?:\s+secondary)?\s*$",
            running):
        try:
            configured = ipaddress.IPv4Network("%s/%s" % (address, mask), strict=False)
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            continue
        if candidate.overlaps(configured):
            raise ValueError("router app subnet %s is already configured" % candidate)

    apps = sections["apps"]
    if re.search(r"(?im)^\s*(?:app id\s*:\s*)?guestshell(?:\s|$)", apps):
        raise ValueError("guestshell is already enabled")
    _check_iris_named_collisions(running, extra=(
        (r"(?m)^app-hosting appid guestshell\s*$", "guestshell app-hosting config"),))
    guest_share = sections["guest_share"]
    if re.search(r"(?im)Directory of\s+bootflash:/?guest-share/?", guest_share) \
            and not re.search(r"(?im)^No files in directory\s*$", guest_share):
        raise ValueError("bootflash:guest-share is not empty")

    evidence = {"status": "passed", "detected_model": model,
                "device_identity": device_identity,
                "iox_preexisting": bool(re.search(r"(?m)^iox\s*$", running)),
                "file_prompt_quiet_preexisting": bool(
                    re.search(r"(?m)^file prompt quiet\s*$", running)),
                "nat_outside_preexisting": False}
    if resolved.get("attachment") != "router-nat":
        return evidence

    requested_outside = resolved["nat_interface"]
    interfaces = sections["interfaces"]
    interface_match = re.search(
        r"(?m)^([A-Za-z][A-Za-z0-9./_-]{0,63}) is ", interfaces)
    if not interface_match:
        raise ValueError("nat_interface %s does not exist" % requested_outside)
    outside = interface_match.group(1)
    evidence["nat_interface"] = outside

    block = re.search(
        r"(?ms)^interface %s\s*$\n(.*?)(?=^!\s*$|^interface |^end\s*$|\Z)"
        % re.escape(outside), running)
    evidence["nat_outside_preexisting"] = bool(
        block and re.search(r"(?m)^\s*ip nat outside\s*$", block.group(1)))
    acl = "IRIS-NAT-%s" % vpg
    if re.search(r"(?m)^ip access-list standard %s\s*$" % re.escape(acl), running):
        raise ValueError("NAT ACL %s already exists" % acl)
    if re.search(r"(?m)^ip nat inside source list %s\s" % re.escape(acl), running):
        raise ValueError("NAT overload rule for %s already exists" % acl)
    port = str(resolved.get("swarm_port", "6881"))
    for line in re.findall(r"(?m)^ip nat inside source static tcp\s+.*$", running):
        fields = line.split()
        # ip nat inside source static tcp <inside-ip> <inside-port>
        #   interface <outside-interface> <outside-port>
        if len(fields) < 10:
            continue
        inside_ip, inside_port = fields[6], fields[7]
        if fields[8] == "interface":
            outside_port = fields[10] if len(fields) > 10 else ""
        else:
            outside_port = fields[9]
        if ((inside_ip == resolved["app_ip"] and inside_port == port)
                or outside_port == port):
            raise ValueError("NAT static mapping collides with swarm port %s" % port)
    return evidence


def apply_router_preflight(resolved, evidence):
    """Return renderer input bound to validated live router evidence."""
    if evidence.get("status") != "passed":
        raise ValueError("router preflight did not pass")
    identity = str(evidence.get("device_identity") or "").strip()
    if not identity or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", identity):
        raise ValueError("router preflight did not return a safe device identity")
    result = dict(resolved)
    attachment = result.get(
        "attachment", result.get("management_type",
                                 result.get("network_attachment", "")))
    bound_identity = str(result.get("device_identity") or "").strip()
    if bound_identity and bound_identity != identity:
        raise ValueError("router device identity changed while the job was queued")
    result["device_identity"] = identity
    result["iox_preexisting"] = (
        "1" if evidence.get("iox_preexisting") else "0")
    result["file_prompt_quiet_preexisting"] = (
        "1" if evidence.get("file_prompt_quiet_preexisting") else "0")
    detected_model = str(evidence.get("detected_model") or "").strip()
    if detected_model:
        if not re.match(r"^C8[0-9]{3}", detected_model, re.IGNORECASE):
            raise ValueError("router preflight returned a non-Catalyst-8000 model")
        result["model"] = detected_model
    if attachment == "router-nat":
        outside = str(evidence.get("nat_interface") or "").strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9./_-]{0,63}", outside):
            raise ValueError("router preflight did not resolve nat_interface")
        if bound_identity and result.get("nat_interface") != outside:
            raise ValueError("router NAT interface changed while the job was queued")
        result["nat_interface"] = outside
        result["nat_outside_owned"] = (
            "0" if evidence.get("nat_outside_preexisting") else "1")
    return result


def _default_iox_preflight(dev, env, resolved, repo_root):
    """Read-only preflight for an IOx deployment: the live processor board ID
    (device/iox/install.sh hard-requires EXPECTED_DEVICE_IDENTITY so a typo'd
    DEVICE_IP cannot reconfigure the wrong switch) AND the same IRIS-named
    collision checks every other platform runs.

    It used to resolve identity and nothing else, which is why a device still
    carrying IRIS config was refused as a router and accepted as IOx. Raises
    ValueError (fail-closed) on an unparseable identity; never proceeds with
    an empty value."""
    runner = os.path.join(repo_root, "lab", "device-run.sh")
    appid = str((resolved or {}).get("iox_appid") or "iris")
    sections = _probe_sections(runner, env, (
        ("version", "show version"),
        ("running", "show running-config"),
        ("apps", "show app-hosting list"),
    ), "iox")
    model, device_identity = _parse_show_version(sections["version"])
    if not device_identity:
        raise ValueError("could not determine the device's processor board ID")
    _check_iris_named_collisions(sections["running"], extra=(
        (r"(?m)^app-hosting appid %s\s*$" % re.escape(appid),
         "the %s app-hosting config" % appid),))
    evidence = {"status": "passed", "device_identity": device_identity}
    if model:
        evidence["detected_model"] = model
    return evidence


def apply_iox_preflight(resolved, evidence):
    """Return renderer input bound to validated live IOx device identity --
    the IOx counterpart of apply_router_preflight. Fails closed: a missing
    or unsafe identity, or a mismatch against an identity already bound to
    this job, raises rather than letting an empty/stale value through to
    _build_env's EXPECTED_DEVICE_IDENTITY export."""
    if evidence.get("status") != "passed":
        raise ValueError("iox preflight did not pass")
    identity = str(evidence.get("device_identity") or "").strip()
    if not identity or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", identity):
        raise ValueError("iox preflight did not return a safe device identity")
    result = dict(resolved)
    bound_identity = str(result.get("device_identity") or "").strip()
    if bound_identity and bound_identity != identity:
        raise ValueError("device identity changed while the job was queued")
    result["device_identity"] = identity
    detected_model = str(evidence.get("detected_model") or "").strip()
    if detected_model:
        result["model"] = detected_model
    return result


class OnboardService:
    def __init__(self, fleet, creds, server_dir=None, device_install=None,
                 crt_public=None, host_ip=None, catalog_url=None,
                 mint_fn=None, run_fn=_default_runner, now_fn=time.time,
                 probe_fn=None, artifacts_dir=None, audit_fn=None,
                 max_concurrent=None, clear_state_fn=None, receipts=None,
                 preflight_fn=None, iox_preflight_fn=None, log_dir=None,
                 guestshell_preflight_fn=None):
        self.fleet = fleet
        self.creds = creds
        self.server_dir = server_dir or os.path.dirname(os.path.abspath(__file__))
        self.repo_root = os.path.dirname(self.server_dir)
        # device_install is a GUESTSHELL-ONLY override (explicit arg or
        # IRIS_DEVICE_INSTALL env): it does not affect which script is chosen
        # for iox devices, which always run _PLATFORM_RECIPES["iox"].
        self.device_install = device_install or os.environ.get("IRIS_DEVICE_INSTALL") or os.path.join(
            self.repo_root, "device", "device-install.sh")
        self.crt_public = crt_public or os.environ.get(
            "IRIS_CRT_PUBLIC", "/etc/iris/tls/crt.pem")
        self.host_ip = host_ip if host_ip is not None else os.environ.get(
            "IRIS_HOST_IP", "")
        self.catalog_url = catalog_url or os.environ.get("IRIS_CATALOG_URL") or (
            "https://%s:8443" % self.host_ip if self.host_ip else "")
        self._mint = mint_fn or (lambda did: _default_mint(did, self.server_dir))
        self._run = run_fn
        self._now = now_fn
        self._probe = probe_fn or (lambda dev, env: _default_probe(dev, env, self.repo_root))
        self._router_preflight = preflight_fn or (
            lambda dev, env, resolved: _default_router_preflight(
                dev, env, resolved, self.repo_root))
        self._guestshell_preflight = guestshell_preflight_fn or (
            lambda dev, env, resolved: _default_guestshell_preflight(
                dev, env, resolved, self.repo_root))
        self._iox_preflight = iox_preflight_fn or (
            lambda dev, env, resolved: _default_iox_preflight(
                dev, env, resolved, self.repo_root))
        self.artifacts_dir = artifacts_dir or os.environ.get("IRIS_ARTIFACTS_DIR", "/srv/artifacts")
        self._audit = audit_fn
        # Injected callback(device_id) run after a successful undeploy to drop
        # the device's stale heartbeat/staging record (wired to
        # CatalogStore.forget_device in main()). Injected, like mint/run/audit,
        # so orchestration stays unit-testable without a catalog.
        self._clear_state = clear_state_fn
        self.receipts = receipts
        # Directory for persisted per-job logs (None disables persistence —
        # unit tests and legacy callers keep the purely in-memory behavior).
        self.log_dir = log_dir
        if max_concurrent is None:
            max_concurrent = int(os.environ.get(
                "IRIS_ONBOARD_CONCURRENCY", str(_DEFAULT_CONCURRENCY)))
        self.max_concurrent = max(1, int(max_concurrent))
        # A bounded queue plus at most max_concurrent workers prevents one
        # parked daemon thread per submission. Workers are created lazily so a
        # service that never onboards does not consume 25 idle threads.
        self._work_queue = queue.Queue(maxsize=_MAX_QUEUED_JOBS)
        self._workers = []
        self._jobs = {}
        self._procs = {}   # job_id -> live installer Popen (for abort)
        # Whether the injected runner can report its process for abort support.
        try:
            self._run_supports_proc = len(
                inspect.signature(self._run).parameters) >= 4
        except (TypeError, ValueError):
            self._run_supports_proc = False
        self._lock = threading.Lock()

    def _worker_loop(self):
        while True:
            try:
                work = self._work_queue.get(timeout=60)
            except queue.Empty:
                # TTL cleanup does not depend on another submission; idle pool
                # wakeups provide periodic maintenance without another thread.
                with self._lock:
                    self._evict_old(self._now())
                continue
            try:
                work()
            finally:
                self._work_queue.task_done()

    def _ensure_workers(self):
        """Grow the fixed-size pool lazily, never beyond max_concurrent."""
        wanted = min(self.max_concurrent, len(self._jobs))
        while len(self._workers) < wanted:
            worker = threading.Thread(target=self._worker_loop, daemon=True)
            self._workers.append(worker)
            worker.start()

    def _build_env(self, device_id, mint=True, resolved=None, env_extra=None):
        dev = self.fleet.get_device(device_id)
        if not dev:
            raise ValueError("unknown device: %s" % device_id)
        cred = self.creds.get_secrets(dev.get("credential_profile_id") or "")
        if not cred:
            raise ValueError("device has no credential profile")
        if not self.host_ip:
            raise ValueError("IRIS_HOST_IP not configured on the server")
        # Undeploy never mints: minting persists fresh enrollment state into
        # the secrets store — pure teardown must not touch it.
        token = self._mint(device_id) if mint else ""
        env = dict(os.environ)
        target = resolved or dev
        attachment = target.get("attachment",
                                target.get("management_type",
                                           target.get("network_attachment", "routed")))
        if attachment == "legacy_routed":
            attachment = "routed"
        target_ip = (target.get("device_ip")
                     if attachment in ("router-routed", "router-nat") else None)
        env.update({
            "DEVICE_IP": target_ip or dev["device_ip"],
            "DEVICE_ID": device_id,
            "NETWORK_ATTACHMENT": attachment,
            "VLAN": str(target.get("iris_vlan", target.get("vlan", ""))),
            "SVI_IP": target.get("svi_ip", ""),
            "SVI_MASK": target.get("svi_mask", target.get("app_mask", "")),
            "GUEST_IP": target.get("app_ip", target.get("guest_ip", "")),
            "INBAND_VLAN": str(target.get("inband_vlan", "")),
            "APP_IP": target.get("app_ip", target.get("guest_ip", "")),
            "APP_MASK": target.get("app_mask", target.get("svi_mask", "")),
            "APP_GATEWAY": target.get("app_gateway", target.get("svi_ip", "")),
            "VPG_NUMBER": str(target.get("vpg_number", "")),
            "NAT_INTERFACE": target.get("nat_interface", ""),
            "BT_LISTEN_PORT": str(target.get("swarm_port", "6881"))
                              if attachment == "router-nat" else "",
            "NAT_OUTSIDE_OWNED": str(target.get("nat_outside_owned", "0")),
            "EXPECTED_DEVICE_IDENTITY": target.get("device_identity", ""),
            "ROUTER_RESOURCES_OWNED": str(target.get("router_resources_owned", "0")),
            # inband IOx reaches IOS at the switch's management IP by default
            "IOS_SSH_HOST": (target.get("ios_ssh_host", "")
                             or (dev["device_ip"] if attachment == "inband" else "")),
            "CATALOG_URL": self.catalog_url,
            "STAGE_HOST": self.host_ip,
            "CATALOG_TOKEN": token,
            "DEVICE_USER": cred["device_user"],
            "DEVICE_PASS": cred["device_pass"],
            "DEVICE_ENABLE": cred.get("enable_secret") or cred["device_pass"],
            "IRIS_CRT_FILE": self.crt_public,
            # The console always runs in the SAME container as the artifact
            # server (docker-entrypoint launches both), so device-install.sh's
            # step [2/7] can always stage the per-device config directly --
            # ssh-to-self / HOST_USER is never needed for console onboarding.
            # IRIS_ARTIFACTS_DIR tells the installer where that server actually
            # serves from (default /srv/artifacts, bind-mounted from the host).
            "IRIS_STAGE_LOCAL": "1",
            "IRIS_ARTIFACTS_DIR": os.environ.get("IRIS_ARTIFACTS_DIR", "/srv/artifacts"),
        })
        if target.get("model"):
            env["MODEL"] = target["model"]
        # Stage-host SSH login for the installer's remote-STAGE_HOST branch (in
        # Docker the container's netns never owns STAGE_HOST, so artifact staging
        # goes over ssh). The age-encrypted store beats any inherited process env;
        # unset leaves the plain passthrough (and the on-host local path needs
        # neither). getattr: injected test doubles may predate stage-host support.
        stage_host_fn = getattr(self.creds, "stage_host_secrets", None)
        sh = stage_host_fn() if callable(stage_host_fn) else None
        if sh:
            env["HOST_USER"] = sh["username"]
            env["HOST_PASS"] = sh["password"]
        # Console-driven feature flags (e.g. the telemetry checkboxes) applied
        # last: explicit operator intent beats any inherited process env.
        if env_extra:
            env.update(env_extra)
        resolved_dev = dict(dev)
        resolved_dev.update(target)
        resolved_dev["platform"] = target.get("platform", resolved_dev.get("platform"))
        return resolved_dev, env

    def preflight(self, device_id, resolved):
        """Run a deployment's read-only checks before token minting.

        Every platform runs one. Returning "not-required" for anything that
        was not a router meant the same device was refused as a router and
        silently accepted as Guest Shell or IOx."""
        dev, env = self._build_env(device_id, mint=False, resolved=resolved)
        platform = resolved.get("platform")
        if platform == "router":
            return self._router_preflight(dev, env, resolved)
        if platform == "iox":
            return self._iox_preflight(dev, env, resolved)
        if platform == "guestshell":
            return self._guestshell_preflight(dev, env, resolved)
        return {"status": "not-required"}

    def _resolve(self, device_id, dev, env, action="onboard"):
        """Resolve (platform, script) for a device, using the live probe (if
        needed) with creds already present in env. Caches a probed model onto
        the fleet row so future onboards (and the devices table) skip the
        probe. For iox, additionally sets the SSH creds the IOx-hosted agent
        needs for its SSH-to-self CLI, reusing the device credential profile
        (rotating this via the secrets broker is the known follow-up).

        action="undeploy" runs the platform's teardown script (the inverse of
        the install recipe) — fleet-wide across Guest Shell and IOx."""
        def probe(d):
            model = self._probe(d, env)
            if model:
                self.fleet.upsert({"device_id": device_id, "model": model})
                dev["model"] = model   # so the job line reports what was found
            return model

        platform = resolve_platform(dev, probe=probe)
        # For iox, derive the arch env (C9k->amd64, IE-3k/IR->arm defaults,
        # blank/unclassifiable -> raise). Runs for BOTH onboard and undeploy so
        # teardown deletes the RESOLVED package (iris-arm64.tar vs iris-amd64.tar).
        # setdefault so an explicit operator/env override (e.g. a stacked
        # member's APP_INTF) always wins.
        if platform == "iox":
            for k, v in _iox_arch_env(device_id, dev.get("model")).items():
                env.setdefault(k, v)
        if action == "undeploy":
            return platform, os.path.join(self.repo_root,
                                          _UNINSTALL_RECIPES[platform])
        script = os.path.join(self.repo_root, _PLATFORM_RECIPES[platform])
        if platform == "guestshell":
            script = self.device_install
        elif platform == "iox":
            env["DEVICE_SSH_PASS"] = env["DEVICE_PASS"]
            env["DEVICE_SSH_USER"] = env["DEVICE_USER"]
        return platform, script

    def _transition_or_note(self, job_id, receipt_id, state):
        """Advance the job's receipt, downgrading lifecycle races to a job
        line. A concurrent action can retire the bound receipt between this
        worker's steps — e.g. a re-onboard's activation supersedes it, or an
        operator adopt replaces it. The transition then raises, and an
        uncaught raise here would kill the worker thread BEFORE _finish(),
        wedging the job "running" and the device "busy" until a restart.
        Returns True iff the transition applied."""
        if self.receipts is None or not receipt_id:
            return True
        try:
            self.receipts.transition(receipt_id, state)
            return True
        except Exception as exc:
            self._append(job_id, "receipt %s -> %s not applied: %s"
                         % (receipt_id, state, exc))
            return False

    def start(self, device_id, action="onboard", resolved=None, prepare=None,
              pre_apply=None, env_extra=None, on_success=None):
        """Create a job and run the action's script on a daemon thread.
        Returns the job id immediately. action is "onboard"
        (the platform's install recipe: device-install.sh, device/iox/install.sh
        or device/router-install.sh) or "undeploy" (the platform's teardown
        recipe: device-uninstall.sh, device/iox/uninstall.sh or
        device/router-uninstall.sh). At most max_concurrent
        installers run at once; beyond that a job stays in a bounded work queue
        until a worker is free or cancel_queued() flips it to "cancelled".

        on_success() (optional) is called once the script exits 0, for caller
        bookkeeping that must not happen until the box is actually clean. Its
        exceptions are swallowed: the job already succeeded, and a bookkeeping
        failure must not restate that as a failure. Like prepare(), it is never
        registered when this start joins an already-active same-action job.

        prepare() (optional) is called EXACTLY ONCE, under the job lock, only
        when a genuinely new job is registered — never when this start joins an
        already-active same-action job. It returns the receipt id to bind to the
        job. Creating the receipt there (instead of before start) means a
        concurrent double-onboard cannot leave an orphan planned receipt behind.

        Jobs are in-memory and per-process: a server restart loses all job state
        and abandons any in-flight job (re-running either script is
        idempotent). Terminal (done/error/cancelled) jobs are evicted after
        _JOB_TTL."""
        if action not in ("onboard", "undeploy"):
            raise ValueError("unknown action: %s" % action)
        job_id = secrets.token_hex(8)
        job = {"id": job_id, "device_id": device_id, "action": action,
                 "state": "queued", "lines": [], "returncode": None,
                 "_line_bytes": 0, "_log_truncated": False,
                "queued_at": int(self._now()),
                "started_at": None, "finished_at": None, "receipt_id": None,
                "resolved": resolved, "env_extra": env_extra}
        # Reap BEFORE the busy guard, not after it. The reaper used to run
        # further down, past every path that returns or raises — so it could
        # only ever fire on a start() for some OTHER device, and never for the
        # one actually stuck. A device whose job hung was refused for the whole
        # _JOB_DEADLINE window with no way to clear it, which is exactly the
        # strand the reaper exists to prevent.
        self.reap_overdue_jobs()
        with self._lock:
            # Never run two scripts against the same device at once: the same
            # action again (double-click, overlapping batches) joins the
            # active job; the OPPOSITE action is refused — silently attaching
            # an undeploy click to a running onboard (or vice versa) would do
            # the exact reverse of what the operator asked.
            for j in self._jobs.values():
                if j["device_id"] == device_id and j["state"] not in _TERMINAL:
                    if j.get("action", "onboard") == action:
                        return j["id"]
                    raise ValueError(
                        "device %s is busy with an active %s job (%s)"
                        % (device_id, j.get("action", "onboard"), j["id"]))
            # Only now, holding the lock and past the dedup guard, do we mint the
            # receipt — so exactly one receipt exists per genuinely started job.
            job["receipt_id"] = prepare() if prepare else None
            self._evict_old(self._now())
            self._jobs[job_id] = job

        def run():
            with self._lock:
                j = self._jobs.get(job_id)
                # cancelled (or TTL-evicted) while parked on the semaphore
                if j is None or j["state"] != "queued":
                    return
                j["state"] = "running"
                j["started_at"] = int(self._now())
            try:
                # Build credentials and resolve the recipe without minting. A
                # Router preflight runs only here, in the bounded worker pool,
                # immediately before its receipt becomes applying and before an
                # enrollment token is created. Batch submissions therefore do
                # not block their HTTP requests on individual routers' SSH.
                dev, env = self._build_env(device_id, mint=False,
                                           resolved=j.get("resolved"),
                                           env_extra=j.get("env_extra"))
                platform, script = self._resolve(device_id, dev, env, action)
                if action == "onboard" and platform == "guestshell":
                    # The reachability probe stays AHEAD of the collision
                    # preflight: an unreachable device is far more common than
                    # a collision, and "preflight could not run" tells an
                    # operator nothing about which of the two to go and check.
                    if not self._probe(dev, env):
                        raise ValueError(
                            "cannot reach device %s — ping/SSH probe "
                            "failed; check the device IP and credentials"
                            % env.get("DEVICE_IP", device_id))
                    # Guest Shell used to stop there, so a device still
                    # carrying IRIS config was refused as a router and
                    # silently accepted here.
                    try:
                        self._guestshell_preflight(
                            dev, env, j.get("resolved") or dev)
                    except Exception as exc:
                        raise ValueError("preflight failed: %s" % exc)
                if action == "onboard" and platform == "router":
                    try:
                        evidence = self._router_preflight(
                            dev, env, j.get("resolved") or dev)
                    except Exception as exc:
                        raise ValueError("preflight failed: %s" % exc)
                    final_resolved = (pre_apply(evidence) if pre_apply else
                                      apply_router_preflight(
                                          j.get("resolved") or dev, evidence))
                    if final_resolved is not None:
                        with self._lock:
                            current = self._jobs.get(job_id)
                            if current is not None:
                                current["resolved"] = final_resolved
                        dev, env = self._build_env(
                            device_id, mint=False, resolved=final_resolved,
                            env_extra=j.get("env_extra"))
                        platform, script = self._resolve(
                            device_id, dev, env, action)
                elif action == "onboard" and platform == "iox":
                    # The console never supplies device_identity for IOx
                    # devices (unlike router, there is no separate
                    # collision-check preflight that already probes 'show
                    # version'), so device/iox/install.sh's identity guard
                    # would otherwise always see an empty
                    # EXPECTED_DEVICE_IDENTITY -- a no-op guard against
                    # reconfiguring the wrong switch. Probe live here, at
                    # execution time, the same as the router flow.
                    try:
                        evidence = self._iox_preflight(
                            dev, env, j.get("resolved") or dev)
                    except Exception as exc:
                        raise ValueError("preflight failed: %s" % exc)
                    final_resolved = apply_iox_preflight(
                        j.get("resolved") or dev, evidence)
                    with self._lock:
                        current = self._jobs.get(job_id)
                        if current is not None:
                            current["resolved"] = final_resolved
                    dev, env = self._build_env(
                        device_id, mint=False, resolved=final_resolved,
                        env_extra=j.get("env_extra"))
                    platform, script = self._resolve(
                        device_id, dev, env, action)
            except Exception as exc:
                # Nothing has reached the device yet. A planned onboarding
                # receipt must not become teardown authority: another actor
                # may own the resources that caused this pre-apply failure.
                # An undeploy receipt already describes the live deployment,
                # so leave it unchanged when teardown never started.
                if action == "onboard":
                    self._transition_or_note(job_id, j.get("receipt_id"),
                                             "removed")
                self._append(job_id, "ERROR: " + str(exc))
                self._finish(job_id, "error", None)
                return
            with self._lock:
                j = self._jobs.get(job_id)
                if j is not None:
                    j["platform"] = platform   # for the *_finished audit line
            recipe = (_UNINSTALL_RECIPES if action == "undeploy"
                      else _PLATFORM_RECIPES)[platform]
            self._append(job_id, "platform: %s (model %s) -> %s" % (
                platform, dev.get("model") or "?", recipe))
            if action == "onboard" and platform == "iox":
                pkg = env.get("PKG", "iris-arm64.tar")
                if not os.path.isfile(os.path.join(self.artifacts_dir, pkg)):
                    flag = " --amd64" if pkg == "iris-amd64.tar" else ""
                    self._append(job_id, "ERROR: %s not found in artifacts dir "
                                 "-- build device/iox/build.sh%s and place it in "
                                 "artifacts/ (device untouched)" % (pkg, flag))
                    self._transition_or_note(job_id, j.get("receipt_id"),
                                             "removed")
                    self._finish(job_id, "error", None)
                    return
            # An operator abort can land while the job is "running" but the
            # installer has not been spawned yet (env build, preflight, the
            # artifacts guard). Stop here, before minting a token or touching
            # the device: an onboard's planned receipt is retired outright; an
            # undeploy receipt still describes the live deployment, so leave
            # it, as in the pre-apply error path above.
            with self._lock:
                cur = self._jobs.get(job_id)
                abort_pending = cur is not None and cur.get("_abort_requested",
                                                            False)
            if abort_pending:
                self._append(job_id, "ERROR: aborted by operator before the "
                             "installer started; device untouched")
                if action == "onboard":
                    self._transition_or_note(job_id, j.get("receipt_id"),
                                             "removed")
                self._finish(job_id, "error", None)
                return
            try:
                receipt_id = j.get("receipt_id")
                if not self._transition_or_note(job_id, receipt_id, "applying"):
                    # The bound receipt is no longer usable (a newer action
                    # superseded it). Running a script rendered from a STALE
                    # receipt would act on a box someone else just changed —
                    # abort before touching the device.
                    self._append(job_id, "ERROR: the job's receipt is no "
                                 "longer active; aborting without touching "
                                 "the device")
                    self._finish(job_id, "error", None)
                    return
                if action == "onboard":
                    env["CATALOG_TOKEN"] = self._mint(device_id)
                if self._run_supports_proc:
                    rc = self._run(script, env,
                                   lambda line: self._append(job_id, line),
                                   lambda proc: self._register_proc(job_id, proc))
                else:
                    rc = self._run(script, env, lambda line: self._append(job_id, line))
            except Exception as exc:
                self._transition_or_note(job_id, receipt_id, "needs-reconcile")
                self._append(job_id, "ERROR: " + str(exc))
                self._finish(job_id, "error", None)
                return
            # A successful undeploy wiped the box: forget its stored heartbeat
            # so the console stops calling it 'deployed' from stale state. Only
            # on success — a failed undeploy may have left it partly deployed.
            if action == "undeploy" and rc == 0 and self._clear_state is not None:
                try:
                    self._clear_state(device_id)
                except Exception:
                    pass   # a bookkeeping failure must never fail the job
            # Same contract for the caller's own success bookkeeping. A forced
            # teardown retires its receipts here rather than at submit time:
            # force means "that receipt does not describe this box", but a
            # transient failure to reach the device is not proof of that, and
            # voiding a healthy deployment's receipt on a network blip would
            # strand it exactly the way this whole path exists to prevent.
            if rc == 0 and on_success is not None:
                try:
                    on_success()
                except Exception:
                    pass   # as above: never fail a job that already succeeded
            if rc != 0:
                self._transition_or_note(job_id, receipt_id, "needs-reconcile")
            elif action == "onboard":
                self._transition_or_note(job_id, receipt_id, "active")
            else:
                self._transition_or_note(job_id, receipt_id, "removed")
            self._finish(job_id, "done" if rc == 0 else "error", rc)

        try:
            self._work_queue.put_nowait(run)
        except queue.Full:
            with self._lock:
                self._jobs.pop(job_id, None)
            if job.get("receipt_id"):
                self._transition_or_note(job_id, job["receipt_id"], "removed")
            raise ValueError("onboarding queue is full")
        with self._lock:
            self._ensure_workers()
        return job_id

    def _append(self, job_id, line):
        with self._lock:
            j = self._jobs.get(job_id)
            if j is not None:
                self._append_locked(j, line)

    def _append_locked(self, job, line):
        size = len(line.encode("utf-8", "replace"))
        if len(job["lines"]) < _MAX_JOB_LOG_LINES \
                and job["_line_bytes"] + size <= _MAX_JOB_LOG_BYTES:
            job["lines"].append(line)
            job["_line_bytes"] += size
        elif not job["_log_truncated"]:
            marker_bytes = len(_LOG_TRUNCATED.encode())
            # Keep the marker itself inside both advertised limits.
            while job["lines"] and (len(job["lines"]) >= _MAX_JOB_LOG_LINES
                    or job["_line_bytes"] + marker_bytes > _MAX_JOB_LOG_BYTES):
                removed = job["lines"].pop()
                job["_line_bytes"] -= len(removed.encode("utf-8", "replace"))
            job["lines"].append(_LOG_TRUNCATED)
            job["_line_bytes"] += marker_bytes
            job["_log_truncated"] = True

    def _register_proc(self, job_id, proc):
        with self._lock:
            self._procs[job_id] = proc
            j = self._jobs.get(job_id)
            abort_pending = j is not None and j.get("_abort_requested", False)
        if abort_pending:
            # abort() landed while the job was "running" but before the
            # installer existed; honor it the moment the process appears.
            try:
                proc.terminate()
            except Exception:
                pass

    def abort(self, job_id):
        """Terminate a running installer subprocess. Returns True if a running
        job's process was signalled. The run loop then finishes with a non-zero
        rc, so the job errors and its receipt moves to needs-reconcile.

        A job reports "running" before its installer process exists (env
        build, preflight). An abort in that window is recorded instead of
        dropped: the worker stops before spawning the installer, or
        _register_proc terminates it on registration."""
        with self._lock:
            j = self._jobs.get(job_id)
            proc = self._procs.get(job_id)
            if j is None or j["state"] != "running":
                return False
            if proc is None:
                if not self._run_supports_proc:
                    # Legacy runner that never reports its process: there is
                    # nothing to signal once the installer is in flight, so
                    # keep the old "cannot abort" contract.
                    return False
                j["_abort_requested"] = True
                self._append_locked(j, "[abort requested by operator]")
                return True
            self._append_locked(j, "[abort requested by operator]")
        try:
            # Signal the whole group: the recipe's ssh child is what holds the
            # pipe, so terminating only the shell leaves the job hung.
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (OSError, AttributeError, ProcessLookupError):
                proc.terminate()
        except Exception:
            return False
        return True

    def _finish(self, job_id, state, rc):
        device_id = detail = None
        action = "onboard"
        log_job = None
        with self._lock:
            self._procs.pop(job_id, None)   # drop the (now-dead) installer handle
            j = self._jobs.get(job_id)
            if j is not None:
                j["state"] = state
                j["returncode"] = rc
                j["finished_at"] = int(self._now())
                device_id = j.get("device_id")
                action = j.get("action", "onboard")
                dur = _fmt_dur(j["finished_at"] - j["started_at"])
                platform = j.get("platform")
                if state == "done":
                    detail = "job %s %s platform=%s rc=0" % (job_id, dur, platform)
                else:
                    detail = "job %s %s platform=%s rc=%s" % (
                        job_id, dur, platform or "?",
                        rc if rc is not None else "?")
                    # Job lines never echo passwords (sshpass reads them from
                    # the env — module docstring), so the ERROR line is safe;
                    # still truncated.
                    err = next((ln for ln in reversed(j["lines"])
                                if ln.startswith("ERROR:")), None)
                    if err:
                        detail += " -- " + err[:120]
                if self.log_dir:
                    # snapshot under the lock; the disk write happens outside it
                    log_job = dict(j, lines=list(j["lines"]))
        if log_job is not None:
            # Best-effort: a full or read-only state volume must never fail
            # the job (or block the audit emit below). Log lines are the
            # installer's stdout, which never echoes passwords (see above).
            try:
                self._persist_log(log_job)
            except Exception:
                pass
        if self._audit is not None:
            try:
                self._audit(event="%s_finished" % action, category="onboard",
                           target=device_id, actor="system",
                           result="ok" if state == "done" else "fail",
                           detail=detail)
            except Exception:
                pass

    def _persist_log(self, job):
        """Write one finished job's log into log_dir as
        <finished_at>-<device>-<action>-<jobid>.log: a machine-parseable
        header line, then the captured installer lines. The device id is
        sanitized for the FILENAME only — the header keeps the raw id, and
        readers (gui_server's /api/deploy-logs) parse the header. Afterwards
        the directory is pruned to the newest _MAX_PERSISTED_LOGS files.
        Callers treat the whole thing as best-effort."""
        os.makedirs(self.log_dir, exist_ok=True)
        device = str(job.get("device_id") or "")
        fname = "%s-%s-%s-%s.log" % (
            job.get("finished_at"),
            re.sub(r"[^A-Za-z0-9._-]", "_", device),
            job.get("action"), job.get("id"))
        header = ("# job=%s device=%s action=%s state=%s rc=%s queued_at=%s "
                  "started_at=%s finished_at=%s platform=%s"
                  % (job.get("id"), device, job.get("action"),
                     job.get("state"), job.get("returncode"),
                     job.get("queued_at"), job.get("started_at"),
                     job.get("finished_at"), job.get("platform")))
        with open(os.path.join(self.log_dir, fname), "w",
                  encoding="utf-8") as f:
            f.write(header + "\n")
            for line in job["lines"]:
                f.write(line + "\n")
        logs = sorted(
            (n for n in os.listdir(self.log_dir) if n.endswith(".log")),
            key=lambda n: os.path.getmtime(os.path.join(self.log_dir, n)),
            reverse=True)
        for stale in logs[_MAX_PERSISTED_LOGS:]:
            try:
                os.unlink(os.path.join(self.log_dir, stale))
            except OSError:
                pass    # a concurrent _finish may have pruned it already

    def get_job(self, job_id):
        with self._lock:
            self._evict_old(self._now())
            j = self._jobs.get(job_id)
            return ({k: v for k, v in j.items() if not k.startswith("_")} |
                    {"lines": list(j["lines"])}) if j else None

    def list_jobs(self):
        """Summaries of every retained job (no 'lines' — cheap to poll from
        the console's batch panel; 'last_line' carries the newest line for a
        one-glance status). Oldest-queued first."""
        with self._lock:
            self._evict_old(self._now())
            out = []
            for j in self._jobs.values():
                s = {k: v for k, v in j.items()
                     if k != "lines" and not k.startswith("_")}
                s["last_line"] = j["lines"][-1] if j["lines"] else None
                out.append(s)
        out.sort(key=lambda s: (s["queued_at"], s["id"]))
        return out

    def latest_jobs_by_device(self):
        """{device_id: {"action","state","finished_at"}} for each device's most
        relevant retained job: an ACTIVE (queued/running) job wins outright,
        else the most recently queued one. Lets the devices view show
        'onboarding…' / 'waiting for heartbeat' instead of a misleading
        'not enrolled' in the minutes between onboard-done and the agent's
        first heartbeat."""
        best = {}
        with self._lock:
            self._evict_old(self._now())
            for j in self._jobs.values():
                did = j["device_id"]
                cur = best.get(did)
                j_active = j["state"] not in _TERMINAL
                if cur is None:
                    best[did] = j
                    continue
                cur_active = cur["state"] not in _TERMINAL
                if (j_active and not cur_active) or (
                        j_active == cur_active
                        and j["queued_at"] > cur["queued_at"]):
                    best[did] = j
            return {did: {"action": j.get("action", "onboard"),
                          "state": j["state"],
                          "finished_at": j.get("finished_at")}
                    for did, j in best.items()}

    def cancel_queued(self, job_ids=None):
        """Flip still-queued jobs to 'cancelled' — only those in job_ids when
        given (the console scopes a cancel to its own batch; other sessions'
        queued jobs must survive), every queued job when None. Running
        installers are NOT killed (an interrupted device-install.sh
        mid-IOS-config is worse than letting it finish). A cancelled job's
        parked thread exits without running when it eventually wins a slot.
        Returns the count cancelled."""
        n = 0
        receipt_ids = []
        with self._lock:
            now = int(self._now())
            for jid, j in self._jobs.items():
                if job_ids is not None and jid not in job_ids:
                    continue
                if j["state"] == "queued":
                    j["state"] = "cancelled"
                    j["finished_at"] = now
                    self._append_locked(j, "cancelled before start")
                    if j.get("receipt_id"):
                        receipt_ids.append((jid, j["receipt_id"]))
                    n += 1
        for jid, receipt_id in receipt_ids:
            if not self._transition_or_note(jid, receipt_id, "removed"):
                self._append(jid, "cancelled job receipt could not be retired")
        return n

    def reap_overdue_jobs(self):
        """Fail every job past its deadline, with the SAME bookkeeping an
        ordinary finish gets.

        The old inline version wrote a ``rc`` key that no reader looks at (they
        all read ``returncode``), never went through _finish, and so left the
        installer handle in self._procs, wrote no persisted log, and emitted no
        ``*_finished`` audit event — a job could fail with nothing anywhere
        saying so. Going through _finish fixes all four.

        Takes the lock itself and does the log/audit I/O outside it, so start()
        can call this before its busy guard.

        A genuinely hung worker may still return later and finish the job a
        second time. That is deliberate and predates this: the second finish
        records the real outcome, and recording it twice beats a job that stays
        non-terminal forever."""
        with self._lock:
            overdue = self._reap_overdue(self._now())
            for jid in overdue:
                # Claim it while still holding the lock: _reap_overdue only
                # considers jobs with no finished_at, so stamping one here stops
                # a concurrent reap from failing the same job twice. _finish
                # overwrites this with the real stamp a moment later.
                self._jobs[jid]["finished_at"] = int(self._now())
                self._append_locked(
                    self._jobs[jid],
                    "[job exceeded %ds deadline; marked failed so the device is "
                    "not left permanently busy]" % _JOB_DEADLINE)
        for jid in overdue:
            self._finish(jid, "error", -1)
        return overdue

    def cancel_device(self, device_id):
        """Stop everything in flight for *device_id*: queued jobs are
        cancelled, a running installer is signalled. Returns
        {"cancelled": n, "aborted": n}.

        Called when the device leaves the fleet. A job record outlives the
        device — it is keyed on the id alone — so without this a job left
        behind by a deleted device keeps the busy guard armed against the NEXT
        device registered under that id: the opposite action is refused 409 and
        the same action silently joins the dead job, which reads as a click
        that did nothing. It self-healed only after _JOB_DEADLINE.

        Queued jobs are cancelled through the same path the console's cancel
        uses, so their receipts are retired too."""
        with self._lock:
            queued = [jid for jid, j in self._jobs.items()
                      if j.get("device_id") == device_id
                      and j["state"] == "queued"]
            running = [jid for jid, j in self._jobs.items()
                       if j.get("device_id") == device_id
                       and j["state"] == "running"]
        cancelled = self.cancel_queued(job_ids=set(queued)) if queued else 0
        aborted = 0
        for jid in running:
            # Best effort: a legacy runner that never reports its process
            # cannot be signalled, and the job then ages out on the deadline.
            try:
                if self.abort(jid):
                    aborted += 1
            except Exception:
                pass
        return {"cancelled": cancelled, "aborted": aborted}

    def _reap_overdue(self, now):
        """Fail any job that has been running past the deadline.

        A hung recipe is indistinguishable from a slow one from here, so the
        bound is deliberately generous. What matters is that the job becomes
        TERMINAL: that releases the busy guard, lets the record be evicted, and
        leaves the receipt in a state teardown can read -- turning a permanent
        strand into an ordinary failure. Caller must hold self._lock."""
        overdue = []
        for jid, j in self._jobs.items():
            if j.get("state") not in _TERMINAL and j.get("finished_at") is None:
                started = j.get("started_at") or j.get("queued_at")
                if started is not None and now - started > _JOB_DEADLINE:
                    overdue.append(jid)
        return overdue

    def _evict_old(self, now):
        """Drop terminal (done/error/cancelled) jobs finished more than
        _JOB_TTL ago. Active jobs do not prevent unrelated terminal records
        from being reclaimed. Caller must hold self._lock."""
        cutoff = int(now) - _JOB_TTL
        stale = [jid for jid, v in self._jobs.items()
                 if v.get("finished_at") is not None
                 and v["finished_at"] <= cutoff]
        for jid in stale:
            del self._jobs[jid]
