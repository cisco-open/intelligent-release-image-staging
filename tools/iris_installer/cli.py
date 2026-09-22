# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""First installer building block: scoped, read-only runtime diagnostics."""

import argparse
import json
from pathlib import Path
import re
import subprocess

from .probe import PACKAGES, SCOPE


def target_name(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,252}", value):
        raise argparse.ArgumentTypeError("expected an explicit runtime name, not an option")
    return value


def positive_timeout(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be an integer") from exc
    if not 1 <= number <= 3600:
        raise argparse.ArgumentTypeError("timeout must be between 1 and 3600 seconds")
    return number


def parser():
    result = argparse.ArgumentParser(
        description="IRIS installer foundation. Deployment/lifecycle commands are not implemented yet.")
    commands = result.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser(
        "doctor", help="read-only native package checks; not whole-installation readiness")
    doctor.add_argument("--target", choices=("docker", "kubernetes"), required=True)
    doctor.add_argument("--container", type=target_name, default="iris")
    doctor.add_argument("--context", type=target_name,
                        help="Docker context; required Kubernetes context (never inferred)")
    doctor.add_argument("--namespace", type=target_name)
    doctor.add_argument("--pod", type=target_name,
                        help="exact server pod name, not a selector or Deployment")
    doctor.add_argument("--timeout", type=positive_timeout, default=120)
    doctor.add_argument("--format", choices=("text", "json"), default="text")
    doctor.add_argument("--optional-xr", action="store_true",
                        help="allow an absent XR RPM for IOx-only deployments; never ignore an invalid RPM")
    return result


def runtime_command(args):
    if args.target == "docker":
        command = ["docker"]
        if args.context:
            command += ["--context", args.context]
        # Use the container's configured identity, then verify it in the probe.
        # Forcing --user would hide an incorrectly root-configured deployment.
        command += ["exec", "-i", args.container]
    else:
        command = ["kubectl", "--context", args.context, "--namespace", args.namespace,
                   "exec", "-i", args.pod, "-c", args.container, "--"]
    command += ["python3", "-I", "-B", "-"]
    if args.optional_xr:
        command += ["--optional-xr"]
    return command


def validate_report(report, *, optional_xr):
    """Reject malformed/truncated evidence instead of trusting a success label."""
    if (not isinstance(report, dict) or report.get("schema_version") != 1
            or report.get("scope") != SCOPE
            or report.get("state") not in ("checks-passed", "checks-failed")):
        raise ValueError("invalid probe report")
    if "reason" in report:
        if (report["state"] != "checks-failed" or report["reason"] not in
                ("unexpected-runtime-identity", "runtime-probe-failed")):
            raise ValueError("invalid failure evidence")
        if report.get("packages", []) != []:
            raise ValueError("unexpected package evidence")
        return
    packages = report.get("packages")
    if (report.get("runtime_uid") != 10001 or report.get("runtime_gid") != 10001
            or not isinstance(packages, list) or len(packages) != len(PACKAGES)):
        raise ValueError("missing runtime evidence")
    for item, (name, *_rest) in zip(packages, PACKAGES):
        required = not (optional_xr and name == "iris-xr.rpm")
        if (not isinstance(item, dict) or item.get("name") != name
                or item.get("required") is not required
                or item.get("state") not in ("ok", "absent", "unknown", "stale")
                or not isinstance(item.get("reason", ""), str)):
            raise ValueError("missing package evidence")
    cert = report.get("catalog_certificate", {})
    if not isinstance(cert, dict) or cert.get("state") not in ("ok", "unknown"):
        raise ValueError("missing certificate evidence")
    if cert["state"] == "ok" and (
        not isinstance(cert.get("fingerprint"), str)
        or not re.fullmatch(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}", cert["fingerprint"])
    ):
        raise ValueError("invalid certificate evidence")
    passed = cert["state"] == "ok" and all(
        item["state"] == "ok" or (not item["required"] and item["state"] == "absent")
        for item in packages)
    if (report["state"] == "checks-passed") != passed:
        raise ValueError("inconsistent check result")


def diagnose(args):
    failure = {"schema_version": 1, "scope": SCOPE, "state": "checks-failed"}
    try:
        source = Path(__file__).with_name("probe.py").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return dict(failure, reason="local-probe-unavailable")
    try:
        result = subprocess.run(runtime_command(args), input=source, text=True,
                                encoding="utf-8", errors="replace",
                                capture_output=True, timeout=args.timeout, check=False)
    except subprocess.TimeoutExpired:
        return dict(failure, reason="runtime-probe-timeout")
    except OSError:
        return dict(failure, reason="runtime-command-unavailable")
    # kubectl/plugin stderr can contain credentials; never echo it unfiltered.
    if result.returncode:
        return dict(failure, reason="runtime-exec-failed")
    try:
        report = json.loads(result.stdout)
        validate_report(report, optional_xr=args.optional_xr)
    except (ValueError, TypeError):
        return dict(failure, reason="invalid-runtime-evidence")
    return report


def main(argv=None):
    command_parser = parser()
    args = command_parser.parse_args(argv)
    if args.target == "kubernetes" and not all((args.context, args.namespace, args.pod)):
        command_parser.error("Kubernetes requires --context, --namespace and an exact --pod")
    if args.target == "docker" and (args.namespace or args.pod):
        command_parser.error("--namespace and --pod apply only to Kubernetes")
    report = diagnose(args)
    if args.format == "json":
        print(json.dumps(report, sort_keys=True))
    else:
        print("Native package runtime checks: " + report["state"])
        if report.get("reason"):
            print("  " + report["reason"])
        for item in report.get("packages", []):
            print("  {}: {}{}".format(item["name"], item["state"],
                                       " (" + item["reason"] + ")" if item.get("reason") else ""))
        if report.get("catalog_certificate"):
            print("  Distributed catalog certificate: " + report["catalog_certificate"]["state"])
        print("Scope only: package bytes/provenance and distributed certificate readability.")
        print("Not an installation READY result: signing, TLS endpoints, Guest Shell,")
        print("owner claim, package contents and native signatures are not qualified here.")
    return 0 if report["state"] == "checks-passed" else 1
