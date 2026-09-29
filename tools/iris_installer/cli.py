# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Installer deployment, managed maintenance and scoped runtime diagnostics."""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

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
        description="Install and manage IRIS on Ubuntu with Docker or Kubernetes.")
    commands = result.add_subparsers(dest="command", required=True)
    maintenance = commands.add_parser("maintenance", help="check or repair this deployment from the terminal")
    from .maintenance import add_arguments as maintenance_arguments
    maintenance_arguments(maintenance)
    install = commands.add_parser("install", help="install a new owned deployment from Ubuntu 24.04")
    install.add_argument("--target", choices=("docker", "docker-split", "kubernetes"), default="docker")
    install.add_argument("--source", type=Path,
                         default=Path(__file__).resolve().parent.parent / "source")
    install.add_argument("--state-dir", type=Path)
    install.add_argument("--instance", default="iris")
    install.add_argument("--host", help="device-facing IPv4 address on this host")
    install.add_argument("--roots-dir", type=Path, help="exactly two approved PUBLIC roots")
    install.add_argument("--recovery-recipient", help="separately held age PUBLIC recovery recipient")
    install.add_argument("--console-bind", default="127.0.0.1", help="loopback by default; restrict remote access before exposing first claim")
    install.add_argument("--console-port", type=int, default=8080)
    install.add_argument("--peer-tls", choices=("required", "disabled"), default="required")
    split = install.add_argument_group('Split Docker: explicit remote Console custody')
    split.add_argument('--console-ssh-host')
    split.add_argument('--console-ssh-user')
    split.add_argument('--console-ssh-port', type=int, default=22)
    split.add_argument('--console-ssh-key', type=Path)
    split.add_argument('--console-known-hosts', type=Path)
    split.add_argument('--console-state-dir')
    split.add_argument('--management-bind', help='server management interface; defaults to --host')
    kube = install.add_argument_group('Kubernetes: explicit cluster and a new dedicated namespace')
    kube.add_argument('--kubeconfig-path', type=Path)
    kube.add_argument('--kube-context')
    kube.add_argument('--kube-namespace')
    kube.add_argument('--kube-storage-class')
    kube.add_argument('--kube-storage-size', default='20Gi')
    kube.add_argument('--kube-registry', default='')
    kube.add_argument('--kube-registry-auth', default='', help='optional protected Docker config.json for the selected registry')
    kube.add_argument('--kube-console-replicas', type=int, default=1)
    kube.add_argument('--kube-image-import', choices=('registry', 'k3s'), default='registry')
    kube.add_argument('--kube-node', default='', help='exact local single-node k3s node for explicit image import')
    kube.add_argument('--lifecycle-url', help='verified HTTPS endpoint of this deployment host worker')
    install.add_argument("--accept-changes", action="store_true", help="approve Ubuntu dependency installation, source builds and new services")
    resume = commands.add_parser("resume", help="resume without regenerating identity or resetting state")
    resume.add_argument("--state-dir", type=Path, required=True)
    resume.add_argument("--certificate", type=Path)
    setup = commands.add_parser("worker-setup", help="provision this deployment's persistent maintenance service")
    setup.add_argument("--state-dir", type=Path, required=True)
    setup.add_argument("--refresh-runtime", action="store_true", help="explicitly approve this installer's maintenance runtime update")
    for operation in (install, resume, setup):
        operation.add_argument("--backup-root", type=Path, help="private backup storage root; local storage by default")
        operation.add_argument("--recovery-root", type=Path, help="separate encrypted identity-set storage root")
        operation.add_argument("--recovery-identity", type=Path, help="optional independently held recovery identity made available on this host")
        operation.add_argument("--listen-address", help="explicit bind address for the recorded Kubernetes worker endpoint")
    worker_status = commands.add_parser("worker-status", help="inspect the pinned maintenance service and storage")
    worker_status.add_argument("--state-dir", type=Path, required=True)
    worker_service = commands.add_parser("worker-service", help="control only this deployment's maintenance service")
    worker_service.add_argument("--state-dir", type=Path, required=True)
    worker_service.add_argument("--action", choices=("start", "stop", "restart"), required=True)
    managed = commands.add_parser("managed-worker", help=argparse.SUPPRESS)
    managed.add_argument("--state-dir", type=Path, required=True)
    approve = commands.add_parser("approve-signing", help="run ONLY on the offline custodian machine")
    approve.add_argument("--public-key", type=Path, required=True)
    approve.add_argument("--root-key", type=Path, required=True)
    approve.add_argument("--output", type=Path, default=Path("online-cert.pub"))
    retire = commands.add_parser("approve-keylist", help="approve a public retirement payload ONLY on the offline custodian machine")
    retire.add_argument("--payload", type=Path, required=True)
    retire.add_argument("--root-key", type=Path, required=True)
    retire.add_argument("--output", type=Path, default=Path("keylist.envelope"))
    backup = commands.add_parser("backup", help="cold encrypted backup of an installer-owned deployment")
    backup.add_argument("--state-dir", type=Path, required=True)
    backup.add_argument("--output", type=Path, required=True, help="new backup set under a private 0700 parent")
    backup.add_argument("--recovery-output", type=Path, required=True, help="separate new identity set under a different private 0700 parent")
    backup.add_argument("--allow-downtime", action="store_true")
    worker = commands.add_parser("lifecycle-worker", help="serve scoped Console backup requests outside the containers")
    worker.add_argument("--state-dir", type=Path, required=True)
    worker.add_argument("--backup-dir", type=Path, required=True)
    worker.add_argument("--recovery-dir", type=Path, required=True)
    worker.add_argument("--recovery-identity", type=Path, help="optional temporary operator-provisioned age identity for verification")
    worker.add_argument("--extract-dir", type=Path, help="optional private isolated recovery workspace")
    worker.add_argument('--listen-address', help='optional explicit bind address for the recorded Kubernetes mutual-TLS endpoint')
    for command, help_text in (
        ("verify-backup", "authenticate and decrypt all backup files without restoring services"),
        ("extract-backup", "extract verified files into a NEW isolated directory; no service startup or cutover"),
    ):
        check = commands.add_parser(command, help=help_text)
        check.add_argument("--backup", type=Path, required=True)
        check.add_argument("--identity", type=Path, required=True, help="independently held age recovery identity")
        check.add_argument("--trusted-signer", type=Path, required=True, help="independently pinned backup PUBLIC key, not archive-supplied trust")
        check.add_argument("--max-bytes", type=int, default=1024 ** 4)
        if command == "extract-backup":
            check.add_argument("--destination", type=Path, required=True)
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


def install_questions(args, command_parser):
    """Prompt only for public deployment inputs; never request a private root."""
    missing = not all((args.host, args.roots_dir, args.recovery_recipient))
    if missing and not sys.stdin.isatty():
        command_parser.error("interactive installation needs a terminal; otherwise supply --host, --roots-dir and --recovery-recipient")
    if missing:
        print("This will install the required tools, build IRIS and set up a new deployment.")
        print("Keep private signing keys off this server. Check the package's release signature first.")
        args.host = args.host or input("Server IPv4 address that devices can reach: ").strip()
        args.roots_dir = args.roots_dir or Path(input("Folder with the two public signing keys (root-a.pub and root-b.pub): ").strip())
        args.recovery_recipient = args.recovery_recipient or input("Public backup recovery key (starts with age1): ").strip()
        console = input("Console listen address [" + args.console_bind + "; allow access only from your management network]: ").strip()
        if console:
            args.console_bind = console
        port = input("Console port [" + str(args.console_port) + "]: ").strip()
        if port:
            try:
                args.console_port = int(port)
            except ValueError:
                command_parser.error("Console port must be an integer")
    args.state_dir = args.state_dir or Path("/var/lib/iris-installer") / args.instance
    if not args.accept_changes and sys.stdin.isatty():
        print("Deployment: " + args.instance + "; settings folder: " + str(args.state_dir))
        print("Peer TLS: " + args.peer_tls + "; Console: " + args.console_bind + ":" + str(args.console_port))
        args.accept_changes = input("Install the required tools, build IRIS and start its services? Type INSTALL: ") == "INSTALL"
    return args


def runtime_command(args):
    if args.target == "docker":
        command = ["docker"]
        if args.context:
            command += ["--context", args.context]
        # Use the container's configured identity, then verify it in the probe.
        # Forcing --user would hide an incorrectly root-configured deployment.
        command += ["exec", "-i", args.container]
    else:
        client = ['k3s', 'kubectl'] if not shutil.which('kubectl') and shutil.which('k3s') else ['kubectl']
        command = [*client, "--context", args.context, "--namespace", args.namespace,
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


def diagnose(args, *, env=None):
    failure = {"schema_version": 1, "scope": SCOPE, "state": "checks-failed"}
    try:
        source = Path(__file__).with_name("probe.py").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return dict(failure, reason="local-probe-unavailable")
    try:
        result = subprocess.run(runtime_command(args), input=source, text=True,
                                encoding="utf-8", errors="replace",
                                env=env,
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
    if args.command != "doctor":
        if args.command == "install":
            args = install_questions(args, command_parser)
        from .state import InstallError
        try:
            if args.command == "maintenance":
                from .maintenance import main as maintenance_command
                return maintenance_command(args)
            if args.command == "lifecycle-worker":
                from .lifecycle_worker import serve
                return serve(args)
            if args.command in ("worker-setup", "worker-status", "worker-service", "managed-worker"):
                from . import managed_worker
                handler = {"worker-setup": managed_worker.setup, "worker-status": managed_worker.status,
                           "worker-service": managed_worker.action, "managed-worker": managed_worker.serve_managed}
                return handler[args.command](args)
            if args.command in ("backup", "verify-backup", "extract-backup"):
                from .backup import create, verify
                return create(args) if args.command == "backup" else verify(args)
            if args.command == "approve-signing":
                from .custody import approve
                return approve(args)
            if args.command == "approve-keylist":
                from .custody import approve_keylist
                return approve_keylist(args)
            from .deploy import start, resume, OWNER_CLAIM, PRODUCTION_REVIEW
            result = start(args) if args.command == "install" else resume(args)
            from .managed_worker import remember_options
            remember_options(args)
            if result in (OWNER_CLAIM, PRODUCTION_REVIEW):
                # Deployment locks have been released. Provision before returning
                # success so maintenance does not depend on an open terminal.
                from .managed_worker import setup
                setup(args)
            return result
        except (InstallError, OSError, ValueError) as exc:
            # Known validation errors do not contain private key contents.
            print("Installation stopped: " + (str(exc) if isinstance(exc, InstallError)
                                             else "input or filesystem error; state retained"))
            return 1
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
