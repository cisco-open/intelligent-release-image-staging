# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Terminal maintenance that remains usable when the Console is stopped."""

import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import sys
import uuid

from .backup_archive import private_directory
from .state import InstallError, Journal, atomic_write, regular_bytes


FAMILIES = ("management-tls", "device-tls", "peer-ca", "instruction-roots",
            "age-identity", "age-recovery", "seeder-announce")


def _identity_source_uids():
    owners = {os.geteuid()}
    value = os.environ.get("SUDO_UID", "")
    if os.geteuid() == 0 and re.fullmatch(r"[0-9]{1,10}", value):
        owners.add(int(value))
    return owners


def recovery_identity(path, *, allow_invoking_user=False):
    """Read only its public recipient; no private bytes enter terminal output or RPC."""
    identity = Path(path).absolute()
    if identity.resolve() != identity:
        raise InstallError("Recovery identity must not traverse symbolic links")
    info = identity.lstat()
    owners = _identity_source_uids() if allow_invoking_user else {os.geteuid()}
    if (not stat.S_ISREG(info.st_mode) or info.st_uid not in owners or
            stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise InstallError("Select a caller-owned regular age identity with mode 0600")
    if info.st_size > 8192:
        raise InstallError("Recovery identity exceeds its size limit")
    try:
        result = subprocess.run(["age-keygen", "-y", str(identity)],
            env={"PATH": "/usr/local/bin:/usr/bin:/bin"}, stdin=subprocess.DEVNULL,
            capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise InstallError("Age identity validation is unavailable on this host") from None
    recipient = result.stdout.decode("ascii", errors="replace").strip()
    if result.returncode or not re.fullmatch(r"age1[0-9a-z]{58}", recipient):
        raise InstallError("Select a valid native age recovery identity")
    return identity, recipient


def prepare_recovery_candidate(client, path, approved_recipient, *, independent_copy):
    if independent_copy is not True:
        raise InstallError("Confirm independent storage and retention of old backup keys")
    identity, recipient = recovery_identity(path, allow_invoking_user=True)
    if recipient != approved_recipient:
        raise InstallError("Recovery identity changed after review; review it again")
    status = client.call({"action": "rotation-status"})
    if (status.get("can_rotate") is not True or "age-recovery" not in status.get("families", [])):
        raise InstallError("This host worker does not support recovery-recipient rotation")
    jobs = client.snapshot()
    if any(job.get("state") in ("running", "recovery-required") for job in jobs):
        raise InstallError("Finish or recover the existing operation first")
    with Journal(client.state_dir).locked() as journal:
        if journal.document is None:
            raise InstallError("Installer deployment state is unavailable")
        if journal.document["config"].get("recovery_recipient") == recipient:
            raise InstallError("Choose a different recovery recipient")
        target = client.state_dir / "recovery-candidate.json"
        if target.exists() or target.is_symlink():
            previous = json.loads(regular_bytes(target, 16384))
            if (not isinstance(previous, dict) or set(previous) != {"operation_id", "identity_path", "recipient"}
                    or not isinstance(previous["operation_id"], str)
                    or not re.fullmatch(r"[0-9a-f-]{36}", previous["operation_id"])):
                raise InstallError("Preserve the invalid recovery candidate for investigation")
            finished = any(job.get("id") == previous["operation_id"] and job.get("state") == "rotated" for job in jobs)
            intent = client.state_dir / "credential-operations" / previous["operation_id"] / "record.json"
            failed = any(job.get("id") == previous["operation_id"] and
                job.get("action") == "rotate" and job.get("family") == "age-recovery" and
                job.get("state") == "failed" for job in jobs)
            safely_refused = failed and not intent.exists() and not intent.is_symlink()
            if failed and intent.exists() and intent.resolve() == intent:
                info = intent.lstat()
                if (stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                        stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1):
                    try:
                        record = json.loads(regular_bytes(intent, 1024 * 1024))
                    except (OSError, ValueError, InstallError):
                        record = None
                    safely_refused = isinstance(record, dict) and (
                        record.get("schema") == 1 and record.get("operation_id") == previous["operation_id"] and
                        record.get("kind") == "age-recovery" and record.get("phase") == "refused" and
                        record.get("mutations_admitted") is False and record.get("initial_clean_stop") is True and
                        isinstance(journal.document.get("id"), str) and
                        record.get("instance_id") == journal.document["id"])
            if not finished and not safely_refused:
                if previous["recipient"] != recipient:
                    raise InstallError("A different recovery candidate is pending; retain it until its operation completes")
                if recovery_identity(previous["identity_path"])[1] != recipient:
                    raise InstallError("The pending protected recovery identity changed; preserve its state")
                return {"action": "rotate", "family": "age-recovery", "request_id": previous["operation_id"], "allow_downtime": True}
        operation_id = str(uuid.uuid4())
        storage = client.state_dir / "host-recovery-identities"
        storage.mkdir(mode=0o700, exist_ok=True)
        private_directory(storage)
        destination = storage / (operation_id + ".age")
        # Validate the opened source, not just a pathname inspected earlier.
        source_fd = os.open(identity, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(source_fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in _identity_source_uids() or
                    stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 8192):
                raise InstallError("Recovery source is not a protected bounded identity")
            private = source.read(8193)
        if len(private) > 8192:
            raise InstallError("Recovery identity exceeds its size limit")
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(private)
            output.flush()
            os.fsync(output.fileno())
        directory_fd = os.open(storage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        if recovery_identity(destination)[1] != recipient:
            raise InstallError("Imported identity changed after review; retain the protected copy for investigation")
        value = {"operation_id": operation_id, "identity_path": str(destination), "recipient": recipient}
        atomic_write(target, (json.dumps(value, sort_keys=True) + "\n").encode())
    return {"action": "rotate", "family": "age-recovery", "request_id": value["operation_id"], "allow_downtime": True}


def recovery_request(job):
    if isinstance(job, dict) and job.get("action") == "restore":
        if job.get("state") != "recovery-required":
            raise InstallError("Select an interrupted deployment restore")
        return restore_request(job, recover=True)
    if isinstance(job, dict) and job.get("action") == "renew-transport":
        if (job.get("state") != "recovery-required" or not isinstance(job.get("id"), str)
                or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", job["id"])):
            raise InstallError("Select an interrupted connection certificate renewal")
        return {"action": "recover-transport", "request_id": job["id"], "allow_downtime": True}
    if (not isinstance(job, dict) or job.get("action") != "rotate" or
            job.get("state") != "recovery-required" or job.get("family") not in FAMILIES or
            not isinstance(job.get("id"), str) or not re.fullmatch(r"[0-9a-f-]{36}", job["id"])):
        raise InstallError("Select an interrupted rotation from this deployment")
    return {"action": "recover-rotation", "request_id": job["id"],
            "family": job["family"], "allow_downtime": True}


def restore_request(job, *, recover=False):
    """Select recorded backup/job identifiers, never paths or archive authority."""
    pattern = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    expected = ("restore", "recovery-required") if recover else ("backup", "captured")
    if (not isinstance(job, dict) or (job.get("action"), job.get("state")) != expected
            or not isinstance(job.get("backup_id"), str) or not re.fullmatch(pattern, job["backup_id"])
            or recover and (not isinstance(job.get("id"), str) or not re.fullmatch(pattern, job["id"]))):
        raise InstallError("Select a captured backup or its interrupted restore")
    return {"action": "recover-restore" if recover else "restore",
            "request_id": job["id"] if recover else str(uuid.uuid4()),
            "backup_id": job["backup_id"], "allow_downtime": True, "confirm_restore": True}


class MaintenanceClient:
    def __init__(self, state_dir):
        self.state_dir = private_directory(state_dir)
        installation = self.state_dir / "installation.json"
        self.transport_supported = (installation.exists()
            and json.loads(regular_bytes(installation)).get("config", {}).get("target") == "kubernetes")
        self.transport_state = None
        self.backup_state = None

    def call(self, request):
        if isinstance(request, dict) and request.get("action") in ("renew-transport", "recover-transport"):
            if (set(request) != {"action", "request_id", "allow_downtime"} or request["allow_downtime"] is not True
                    or not isinstance(request["request_id"], str)
                    or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", request["request_id"])):
                raise InstallError("Unsupported connection certificate maintenance request")
        elif isinstance(request, dict) and request.get("action") in ("restore", "recover-restore"):
            if (set(request) != {"action", "request_id", "backup_id", "allow_downtime", "confirm_restore"}
                    or request["allow_downtime"] is not True or request["confirm_restore"] is not True
                    or any(not isinstance(request[name], str) or not re.fullmatch(
                        r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", request[name])
                        for name in ("request_id", "backup_id"))):
                raise InstallError("Unsupported deployment restore request")
        elif request not in ({"action": "status"}, {"action": "rotation-status"}, {"action": "transport-status"}):
            if not isinstance(request, dict) or set(request) != {"action", "request_id", "family", "allow_downtime"}:
                raise InstallError("Unsupported maintenance request")
            expected = recovery_request({"action": "rotate", "state": "recovery-required",
                                         "id": request["request_id"], "family": request["family"]})
            if request["action"] == "rotate" and request["family"] == "age-recovery":
                expected["action"] = "rotate"
            if request != expected or request["allow_downtime"] is not True:
                raise InstallError("Unsupported maintenance request")
        # No environment override or browser-controlled path. Revalidate before
        # each connection; connect via a pinned directory descriptor for long
        # installation paths and reject a replaced endpoint or non-root worker.
        private_directory(self.state_dir)
        directory = os.open(self.state_dir / "control", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise InstallError("Unsafe lifecycle socket directory")
            endpoint = os.stat("control.sock", dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != os.geteuid():
                raise InstallError("Unsafe lifecycle endpoint")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(5)
                connection.connect("/proc/self/fd/" + str(directory) + "/control.sock")
                _pid, uid, _gid = struct.unpack("3i", connection.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
                if uid != os.geteuid():
                    raise InstallError("Lifecycle worker belongs to another account")
                connection.sendall(json.dumps(request).encode() + b"\n")
                with connection.makefile("rb") as stream:
                    raw = stream.readline(128 * 1024 + 1)
                if len(raw) > 128 * 1024 or not raw.endswith(b"\n"):
                    raise InstallError("Invalid lifecycle worker response")
                response = json.loads(raw)
                if not isinstance(response, dict) or type(response.get("ok")) is not bool:
                    raise InstallError("Invalid lifecycle worker response")
                if not response["ok"]:
                    # Do not render arbitrary socket diagnostics as operator
                    # instructions. Details remain in the protected host journal.
                    raise InstallError("Worker refused recovery. Refresh the operation state and preserve its journal and backup")
                result = response.get("result")
                if not isinstance(result, dict):
                    raise InstallError("Invalid lifecycle worker response")
                return result
        except (OSError, ValueError):
            raise InstallError("Lifecycle worker unavailable. Start the deployment's configured worker and refresh") from None
        finally:
            os.close(directory)

    def snapshot(self):
        ordinary = self.call({"action": "status"})
        self.backup_state = ordinary
        rotations = self.call({"action": "rotation-status"})
        jobs = []
        responses = [ordinary, rotations]
        if self.transport_supported:
            self.transport_state = self.call({"action": "transport-status"})
            responses.append(self.transport_state)
        for response in responses:
            items = response.get("jobs")
            if not isinstance(items, list) or len(items) > 100 or any(not isinstance(job, dict) for job in items):
                raise InstallError("Invalid lifecycle job history")
            jobs.extend(items)
        return jobs


ACTIONS = ("status", "recover", "restore", "renew-transport", "replace-recovery",
           "configure-recovery", "disable-recovery", "trust-signer")


def add_arguments(parser):
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("action", nargs="?", choices=ACTIONS, default="status")
    parser.add_argument("--job-id", help="operation ID shown by maintenance status")
    parser.add_argument("--identity", type=Path, help="private age recovery key file")
    parser.add_argument("--signer", type=Path, help="independently trusted public backup signing key")
    parser.add_argument("--allow-downtime", action="store_true",
                        help="allow this operation to stop and restart IRIS")
    parser.add_argument("--independent-copy", action="store_true",
                        help="confirm you keep a separate copy and retain keys for older backups")
    parser.add_argument("--yes", action="store_true", help="confirm the selected change without a prompt")


def _validate_arguments(args):
    needed = {
        "recover": {"job_id", "allow_downtime"},
        "restore": {"job_id", "allow_downtime"},
        "renew-transport": {"allow_downtime"},
        "replace-recovery": {"identity", "allow_downtime", "independent_copy"},
        "configure-recovery": {"identity", "independent_copy"},
        "trust-signer": {"signer"},
        "disable-recovery": set(),
        "status": set(),
    }
    if args.action not in needed:
        raise InstallError("Choose a supported maintenance action")
    for name in ("job_id", "identity", "signer", "allow_downtime", "independent_copy"):
        value = getattr(args, name, None)
        flag = "--" + name.replace("_", "-")
        if name in needed[args.action] and not value:
            raise InstallError(args.action + " requires " + flag)
        if name not in needed[args.action] and value:
            raise InstallError(flag + " does not apply to " + args.action)
    if args.action == "status" and args.yes:
        raise InstallError("--yes does not apply to status")
    if args.job_id and not re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", args.job_id):
        raise InstallError("Use an operation ID from maintenance status")


def _confirm(args):
    descriptions = {
        "recover": "Continue interrupted operation " + str(args.job_id) + ". IRIS may stop and restart.",
        "restore": "Restore the backup recorded by operation " + str(args.job_id) +
                   ". This replaces deployment data and stops and restarts IRIS.",
        "renew-transport": "Renew the Kubernetes worker connection certificates. IRIS will restart.",
        "replace-recovery": "Replace the backup recovery key. IRIS will stop and restart. Keep keys for older backups.",
        "configure-recovery": "Let the worker use this private recovery key. A protected copy may be kept on this host. Keep your separate copy.",
        "disable-recovery": "Disable recovery key access for new operations. Existing keys and backup history are kept.",
        "trust-signer": "Trust this public key for backup restore. Check it with the key owner, not just the backup.",
    }
    print(descriptions[args.action])
    if not args.yes:
        if not sys.stdin.isatty():
            raise InstallError("No changes made. Run from a terminal to confirm, or add --yes")
        try:
            answer = input("Type YES to continue: ")
        except (EOFError, KeyboardInterrupt):
            raise InstallError("No changes made") from None
        if answer != "YES":
            raise InstallError("No changes made")


def _selected_job(client, identifier):
    matches = [job for job in client.snapshot() if job.get("id") == identifier]
    if len(matches) != 1:
        raise InstallError("Operation not found or not unique. Check maintenance status")
    return matches[0]


def main(args):
    if os.geteuid() != 0:
        raise InstallError("Run maintenance as root on the installer host")
    _validate_arguments(args)
    reviewed_identity = None
    if args.action in ("configure-recovery", "replace-recovery"):
        # Review the public address before approval, without importing the key.
        reviewed_identity = recovery_identity(args.identity, allow_invoking_user=True)
        print("Public recovery address: " + reviewed_identity[1])
    if args.action != "status":
        # Refusal must not open a socket, import a key or write state.
        _confirm(args)
    if args.action in ("configure-recovery", "disable-recovery", "trust-signer"):
        from . import managed_worker
        if args.action == "trust-signer":
            managed_worker.configure_restore_signer(args.state_dir, args.signer)
        else:
            if reviewed_identity is not None and recovery_identity(
                    args.identity, allow_invoking_user=True)[1] != reviewed_identity[1]:
                raise InstallError("Recovery key changed after review. Check the file and try again")
            managed_worker.configure_recovery(args.state_dir,
                args.identity if args.action == "configure-recovery" else None)
        print(json.dumps(managed_worker.inspect(args.state_dir), indent=2, sort_keys=True))
        return 0
    client = MaintenanceClient(args.state_dir)
    if args.action == "status":
        jobs = client.snapshot()
        print("Current maintenance operations and backup readiness:")
        print(json.dumps({"jobs": jobs, "backup": client.backup_state,
                          "connection": client.transport_state}, indent=2, sort_keys=True))
        return 0
    if args.action == "recover":
        request = recovery_request(_selected_job(client, args.job_id))
    elif args.action == "restore":
        request = restore_request(_selected_job(client, args.job_id))
        if not (client.backup_state or {}).get("can_restore"):
            raise InstallError("The worker is not ready to restore. Check maintenance status")
    elif args.action == "renew-transport":
        if not client.transport_supported:
            raise InstallError("Connection renewal is only available for Kubernetes")
        status = client.call({"action": "transport-status"})
        if status.get("can_renew") is not True:
            raise InstallError("The worker is not ready to renew. Check maintenance status")
        request = {"action": "renew-transport", "request_id": str(uuid.uuid4()), "allow_downtime": True}
    else:
        identity, recipient = reviewed_identity
        request = prepare_recovery_candidate(client, identity, recipient, independent_copy=True)
    result = client.call(request)
    print("Request sent. Check maintenance status for the result.")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0
