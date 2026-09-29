# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Host-side recovery UI that remains usable when the Console is stopped."""

import json
import os
from pathlib import Path
import queue
import re
import socket
import stat
import struct
import subprocess
import threading
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


def recovery_identity(path, *, allow_desktop_owner=False):
    """Read only its public recipient; no private bytes enter the UI or RPC."""
    identity = Path(path).absolute()
    if identity.resolve() != identity:
        raise InstallError("Recovery identity must not traverse symbolic links")
    info = identity.lstat()
    owners = _identity_source_uids() if allow_desktop_owner else {os.geteuid()}
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
    identity, recipient = recovery_identity(path, allow_desktop_owner=True)
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


class MaintenanceWindow:
    def __init__(self, window, client):
        import tkinter as tk
        from tkinter import ttk
        self.window, self.client = window, client
        self.events = queue.Queue()
        self.busy = False
        self.jobs = {}
        window.title("IRIS · Deployment recovery")
        window.geometry("980x850")
        window.minsize(760, 760)
        style = ttk.Style(window)
        style.theme_use("clam")
        style.configure("TFrame", background="#ffffff")
        style.configure("TLabel", background="#ffffff", foreground="#59616b")
        style.configure("TLabelframe", background="#ffffff")
        style.configure("TLabelframe.Label", background="#ffffff", foreground="#102942")
        style.configure("TCheckbutton", background="#ffffff", foreground="#102942")
        style.configure("Heading.TLabel", foreground="#102942", font=("DejaVu Sans", 20, "bold"))
        style.configure("Expiry.TLabel", foreground="#102942", font=("DejaVu Sans Mono", 9))
        style.configure("ExpiryWarning.TLabel", foreground="#9e3624", font=("DejaVu Sans Mono", 9))
        outer = ttk.Frame(window, padding=24)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Deployment recovery", style="Heading.TLabel").pack(anchor="w")
        ttk.Label(outer, text=str(client.state_dir), wraplength=830).pack(anchor="w", pady=(8, 16))
        ttk.Label(outer, text="Manage the host worker and recover this deployment while the Console is stopped.").pack(anchor="w", pady=(0, 12))
        service_box = ttk.LabelFrame(outer, text="Host maintenance service", padding=8)
        service_box.pack(fill="x", pady=(0, 12))
        self.service_buttons = []
        for label, action in (("Set up service", "setup"), ("Restart service", "restart"),
                              ("Service status", "status"), ("Recovery key access", "identity"),
                              ("Trust backup signer", "signer")):
            button = ttk.Button(service_box, text=label, command=lambda action=action: self.manage_service(action))
            button.pack(side="left", padx=(0, 6))
            self.service_buttons.append(button)
        self.tree = ttk.Treeview(outer, columns=("operation", "family", "state"), show="headings", height=4 if getattr(client, "transport_supported", False) else 6, selectmode="browse")
        for name, width in (("operation", 150), ("family", 190), ("state", 180)):
            self.tree.heading(name, text=name.capitalize())
            self.tree.column(name, width=width, minwidth=100)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.select)
        self.details = tk.Text(outer, height=4, wrap="word", state="disabled", font=("DejaVu Sans Mono", 10),
                               background="#ffffff", foreground="#102942")
        self.details.pack(fill="both", expand=True, pady=12)
        controls = ttk.Frame(outer)
        controls.pack(fill="x")
        self.refresh_button = ttk.Button(controls, text="Refresh operations", command=self.refresh)
        self.refresh_button.pack(side="left")
        self.recover_button = ttk.Button(controls, text="Recover approved operation", command=self.recover, state="disabled")
        self.recover_button.pack(side="right")
        self.restore_button = ttk.Button(controls, text="Restore selected backup", command=self.restore, state="disabled")
        self.restore_button.pack(side="right", padx=8)
        recipient_box = ttk.LabelFrame(outer, text="Replace the independent recovery recipient", padding=8)
        recipient_box.pack(fill="x", pady=(12, 0))
        self.new_identity = tk.StringVar()
        ttk.Entry(recipient_box, textvariable=self.new_identity).pack(side="left", fill="x", expand=True)
        def choose_identity():
            from tkinter import filedialog
            path = filedialog.askopenfilename(parent=window, title="Protected replacement age identity on this host")
            if path:
                self.new_identity.set(path)
        ttk.Button(recipient_box, text="Browse…", command=choose_identity).pack(side="left", padx=8)
        self.recipient_button = ttk.Button(recipient_box, text="Review replacement", command=self.replace_recipient)
        self.recipient_button.pack(side="right")
        self.independent_copy = tk.BooleanVar(value=False)
        ttk.Checkbutton(outer, text="I hold an independent off-host copy and will retain keys for older backups.",
                        variable=self.independent_copy).pack(anchor="w", pady=(6, 0))
        self.transport_button = None
        if getattr(client, "transport_supported", False):
            connection_box = ttk.LabelFrame(outer, text="Kubernetes lifecycle connection", padding=8)
            connection_box.pack(fill="x", pady=(12, 0))
            self.transport_expiry = ttk.Label(connection_box, text="Reading certificate expiry…", style="Expiry.TLabel")
            self.transport_expiry.pack(side="left", fill="x", expand=True)
            self.transport_button = ttk.Button(connection_box, text="Renew connection certificates", command=self.renew_transport, state="disabled")
            self.transport_button.pack(side="right", padx=(12, 0))
        self.status = tk.StringVar(value="Reading the host worker…")
        status = ttk.Label(outer, textvariable=self.status, wraplength=830)
        status.pack(anchor="w", pady=(12, 0))
        outer.bind("<Configure>", lambda event: status.configure(wraplength=max(300, event.width - 48)))
        window.after(100, self.poll)
        window.after(10000, self.refresh_periodically)
        window.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh()

    def selected(self):
        selected = self.tree.selection()
        return self.jobs.get(selected[0]) if selected else None

    def select(self, _event=None):
        job = self.selected()
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        if job:
            self.details.insert("1.0", json.dumps(job, indent=2, sort_keys=True))
        self.details.configure(state="disabled")
        self.recover_button.state(["disabled"])
        self.restore_button.state(["disabled"])
        if (not self.busy and (getattr(self.client, "backup_state", None) or {}).get("can_restore")
                and not any(item.get("state") in ("running", "recovery-required") for item in self.jobs.values())):
            try:
                restore_request(job)
                self.restore_button.state(["!disabled"])
            except InstallError:
                pass
        self.recipient_button.state(["disabled"] if self.busy or any(
            item.get("state") in ("running", "recovery-required") for item in self.jobs.values()) else ["!disabled"])
        if self.transport_button is not None:
            status = self.client.transport_state or {}
            self.transport_button.state(["!disabled"] if not self.busy and status.get("can_renew") is True else ["disabled"])
        try:
            recovery_request(job)
        except InstallError:
            return
        if not self.busy:
            self.recover_button.state(["!disabled"])

    def start(self, operation):
        if self.busy:
            return
        self.busy = True
        self.refresh_button.state(["disabled"])
        self.recover_button.state(["disabled"])
        self.restore_button.state(["disabled"])
        for button in self.service_buttons:
            button.state(["disabled"])
        self.recipient_button.state(["disabled"])
        if self.transport_button is not None:
            self.transport_button.state(["disabled"])

        def run():
            try:
                self.events.put((True, operation()))
            except Exception as exc:
                self.events.put((False, exc))

        threading.Thread(target=run, daemon=True).start()

    def refresh(self):
        self.start(lambda: (self.client.snapshot(), "Operation state refreshed. Select a job to inspect its recorded evidence."))

    def recover(self):
        from tkinter import messagebox
        if self.busy:
            return
        try:
            request = recovery_request(self.selected())
        except InstallError as exc:
            self.status.set(str(exc))
            return
        description = "deployment restore" if request["action"] == "recover-restore" else request.get("family", "connection certificate renewal")
        if not messagebox.askokcancel("Recover approved operation", "Recover " + description +
                " for operation " + request["request_id"] + "?\n\nThis can stop and restart this deployment. "
                "The worker reuses its approved journal and refuses changed authority. Preserve the backup."
                + (" Expired pending connection certificates will be renewed again using the same private keys; previous certificates are retained."
                   if request["action"] == "recover-transport" else ""), parent=self.window):
            return

        def recover():
            self.client.call(request)
            return self.client.snapshot(), "Recovery requested. Completion requires the worker's recorded evidence."

        self.start(recover)

    def restore(self):
        from tkinter import messagebox
        if self.busy:
            return
        try:
            request = restore_request(self.selected())
        except InstallError as exc:
            self.status.set(str(exc))
            return
        if not messagebox.askokcancel("Restore selected backup", "Restore backup " + request["backup_id"] +
                "?\n\nIRIS and the Console will stop. The worker checks current security authority, replaces saved content, "
                "preserves current instruction counters and verifies the restarted services. Previous files are retained for recovery.", parent=self.window):
            return
        def submit():
            self.client.call(request)
            return self.client.snapshot(), "Restore requested. Check the recorded result before resuming normal work."
        self.start(submit)

    def manage_service(self, action):
        from tkinter import filedialog, messagebox
        from types import SimpleNamespace
        from . import managed_worker
        if self.busy:
            return
        path = None
        if action in ("identity", "signer"):
            title = "Independent recovery identity (private; retained on this host)" if action == "identity" else "Independently trusted backup signer (PUBLIC key)"
            path = filedialog.askopenfilename(parent=self.window, title=title)
            if not path:
                return
        if action != "status" and not messagebox.askokcancel("Host maintenance service",
                {"setup": "Provision the managed worker and private local backup directories? Local copies do not protect against host loss.",
                 "restart": "Restart only this deployment's maintenance worker? An active operation must finish first.",
                 "identity": "Allow the worker to use this independent recovery identity for verification and restore? The key is not uploaded to the Console.",
                 "signer": "Pin this independently trusted public signer for deployment restore? Do not select a key supplied only by an untrusted backup."}[action], parent=self.window):
            return
        def operate():
            if action == "setup":
                managed_worker.configure(self.client.state_dir)
            elif action == "restart":
                managed_worker.action(SimpleNamespace(state_dir=self.client.state_dir, action="restart"))
            elif action == "identity":
                managed_worker.configure_recovery(self.client.state_dir, path)
            elif action == "signer":
                managed_worker.configure_restore_signer(self.client.state_dir, path)
            status = managed_worker.inspect(self.client.state_dir)
            try:
                jobs = self.client.snapshot()
            except (InstallError, OSError, ValueError):
                jobs = list(self.jobs.values())
            return jobs, json.dumps(status, sort_keys=True)
        self.start(operate)

    def replace_recipient(self):
        from tkinter import messagebox
        if self.busy:
            return
        try:
            if not self.independent_copy.get():
                raise InstallError("Confirm independent storage and retention of old backup keys")
            identity, recipient = recovery_identity(self.new_identity.get(), allow_desktop_owner=True)
            if not messagebox.askokcancel("Replace recovery recipient", "New public recovery recipient:\n" + recipient +
                    "\n\nThe private identity stays on this host; no private path or key is sent to the Console. "
                    "This operation stops and restarts this deployment. Retain older recovery keys for older backups. Proceed?",
                    parent=self.window):
                return
        except (InstallError, OSError) as exc:
            self.status.set(str(exc) if isinstance(exc, InstallError) else "Select a readable protected age identity")
            return

        def rotate():
            request = prepare_recovery_candidate(self.client, identity, recipient, independent_copy=True)
            self.client.call(request)
            return self.client.snapshot(), "Recovery-recipient rotation requested. Review worker evidence before removing any old key."

        self.start(rotate)

    def renew_transport(self):
        from tkinter import messagebox
        if self.busy or not (self.client.transport_state or {}).get("can_renew"):
            return
        if not messagebox.askokcancel("Renew connection certificates",
                "Renew the lifecycle CA, worker and server-client certificates using their existing private keys?\n\n"
                "This restarts the Kubernetes server. The worker retains the previous client certificate until the new connection is verified. "
                "Use this host window to recover an interrupted renewal.", parent=self.window):
            return
        request = {"action": "renew-transport", "request_id": str(uuid.uuid4()), "allow_downtime": True}
        def renew():
            self.client.call(request)
            return self.client.snapshot(), "Connection renewal requested. Completion requires a verified new client connection."
        self.start(renew)

    def poll(self):
        try:
            success, result = self.events.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            self.refresh_button.state(["!disabled"])
            self.recipient_button.state(["!disabled"])
            for button in self.service_buttons:
                button.state(["!disabled"])
            if success:
                jobs, message = result
                selected = self.tree.selection()
                self.tree.delete(*self.tree.get_children())
                self.jobs = {}
                for index, job in enumerate(jobs):
                    key = str(index)
                    self.jobs[key] = job
                    self.tree.insert("", "end", iid=key, values=(job.get("action", "unknown"),
                        job.get("family", "backup"), job.get("state", "unknown")))
                if selected and selected[0] in self.jobs:
                    self.tree.selection_set(selected[0])
                self.status.set(message)
                if self.transport_button is not None:
                    import datetime
                    status = self.client.transport_state or {}
                    lines = []
                    for certificate in status.get("certificates", []):
                        date = datetime.datetime.fromtimestamp(certificate["expires_at"], datetime.timezone.utc).strftime("%Y-%m-%d")
                        lines.append(certificate["name"].capitalize().ljust(7) + date + "  (" + str(certificate["days_remaining"]) + " days)")
                    self.transport_expiry.configure(text="\n".join(lines) or "Connection certificate status unavailable",
                        style="ExpiryWarning.TLabel" if status.get("renewal_due") else "Expiry.TLabel")
            else:
                self.status.set(str(result) if isinstance(result, InstallError) else
                                "Recovery request failed. Refresh before retrying; keep the operation journal and backup.")
            self.select()
        self.window.after(100, self.poll)

    def refresh_periodically(self):
        self.refresh()
        self.window.after(10000, self.refresh_periodically)

    def close(self):
        if self.busy:
            self.status.set("Wait for the worker response before closing. A submitted operation continues on the host.")
        else:
            self.window.destroy()


def main(args):
    if os.geteuid() != 0:
        raise InstallError("Open deployment recovery as root on its installer host")
    client = MaintenanceClient(args.state_dir)
    try:
        import tkinter as tk
        window = tk.Tk()
    except ImportError:
        raise InstallError("Install python3-tk to open deployment recovery") from None
    except tk.TclError:
        raise InstallError("Deployment recovery needs an authorized desktop display on the installer host") from None
    MaintenanceWindow(window, client)
    window.mainloop()
    return 0
