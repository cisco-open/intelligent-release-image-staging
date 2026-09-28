# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Local desktop approval companion. No HTTP listener or private-key transfer."""

import hashlib
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import threading

from .state import InstallError, regular_bytes


def instruction_module():
    package = Path(__file__).resolve().parents[1] / "source/server"
    source = package if package.is_dir() else Path(__file__).resolve().parents[2] / "server"
    sys.path.insert(0, str(source))
    import instruction_keys
    return instruction_keys


def inspect_request(kind, path):
    """Return the exact reviewed public bytes and a bounded, non-secret summary."""
    keys = instruction_module()
    if kind == "signing":
        data = regular_bytes(path, 16384)
        try:
            keys._public_key_bytes(data)
        except keys.InstructionKeyError:
            raise InstallError("Select a valid Ed25519 public key, not a private key or certificate") from None
        details = "Online signing key; certificate valid for 30 days."
    elif kind == "keylist":
        data = regular_bytes(path, keys.MAX_KEYLIST_PAYLOAD_BYTES)
        try:
            metadata, krl = keys._parse_keylist_payload(data)
            keys._validate_krl_bytes(krl)
        except keys.InstructionKeyError:
            raise InstallError("Select a valid public retirement request") from None
        details = ("Retirement sequence: " + str(metadata["keylist_seq"]) +
                   "\nApproving root: " + metadata["signer_root_id"] +
                   "\nRevocation list SHA256: " + metadata["krl_sha256"])
    else:
        raise InstallError("Unknown approval type")
    return data, details + "\nPublic file SHA256: " + hashlib.sha256(data).hexdigest()


def signing_environment():
    helper = Path(__file__).resolve().parents[1] / "iris-custody-askpass"
    if not helper.is_file() or not os.access(helper, os.X_OK):
        raise InstallError("Passphrase window is unavailable; reinstall the installer package")
    # Forward display/session routing, never a caller-provided askpass executable
    # or an environment variable containing a passphrase.
    env = {key: os.environ[key] for key in
           ("HOME", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR",
            "DBUS_SESSION_BUS_ADDRESS", "LANG", "LC_ALL") if key in os.environ}
    env.update(PATH="/usr/bin:/bin", SSH_ASKPASS=str(helper), SSH_ASKPASS_REQUIRE="force")
    return env


def run_local(command, *, env):
    process = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=600)
    except subprocess.TimeoutExpired:
        # Kill the whole local signing session, including a pending askpass
        # dialog, so a timed-out operation cannot publish an approval later.
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise InstallError("Approval timed out; check the output location before retrying") from None
    if process.returncode:
        # OpenSSH diagnostics may contain file contents or sensitive local paths.
        raise InstallError("Operation stopped. Check the selected files and passphrase, then choose a new output path")
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def approve_public(kind, data, root, output):
    """Sign reviewed bytes, not a file that could change after confirmation."""
    env = signing_environment()
    entry = Path(__file__).resolve().parents[1] / "irisctl"
    with tempfile.TemporaryDirectory(prefix="iris-public-approval-") as temporary:
        request = Path(temporary) / "request"
        request.write_bytes(data)
        # Revalidate immediately before dispatch; the shared CLI owns private-key
        # permissions, framing, exclusive publication and OpenSSH invocation.
        inspect_request(kind, request)
        command = [sys.executable, str(entry), "approve-" + kind,
                   "--public-key" if kind == "signing" else "--payload", str(request),
                   "--root-key", str(Path(root).absolute()), "--output", str(Path(output).absolute())]
        run_local(command, env=env)
    return "Public approval saved: " + str(Path(output).absolute())


def generate_root(parent, name):
    """An exclusive directory prevents overwriting any existing private root."""
    if name not in ("root-a", "root-b"):
        raise InstallError("Choose root-a or root-b")
    env = signing_environment()
    directory = Path(parent).resolve(strict=True) / ("iris-" + name)
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        raise InstallError("The root directory already exists; select another parent directory") from None
    if directory.stat().st_mode & 0o077:
        raise InstallError("Selected storage does not enforce private directory permissions")
    root = directory / name
    run_local(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-C", "iris-" + name,
               "-f", str(root)], env=env)
    # An empty passphrase is refused by the askpass window. Independently check
    # that a plaintext key was not generated before announcing success.
    check = subprocess.run(["/usr/bin/ssh-keygen", "-y", "-P", "", "-f", str(root)],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=15, check=False)
    if check.returncode == 0:
        raise InstallError("Generated key lacks passphrase protection; retain it locally and investigate before use")
    public = regular_bytes(str(root) + ".pub", 16384)
    keys = instruction_module()
    try:
        keys._public_key_bytes(public)
    except keys.InstructionKeyError:
        raise InstallError("Root generation did not produce a valid public key") from None
    fingerprint = subprocess.run(["/usr/bin/ssh-keygen", "-l", "-f", str(root) + ".pub"],
                                 capture_output=True, timeout=15, check=True).stdout.decode().split()[1]
    return "Root created. Keep the private file here.\nTransfer only: " + str(root) + ".pub\n" + fingerprint


def generate_recovery_identity(parent):
    """Write the native age identity directly to protected, exclusive storage."""
    directory = Path(parent).resolve(strict=True) / "iris-recovery"
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        raise InstallError("The recovery directory already exists; choose another parent location") from None
    if directory.stat().st_mode & 0o077:
        raise InstallError("Selected storage does not enforce private directory permissions")
    identity = directory / "recovery.age"
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin"}
    run_local(["age-keygen", "-o", str(identity)], env=env)
    result = run_local(["age-keygen", "-y", str(identity)], env=env)
    recipient = result.stdout.decode("ascii").strip()
    import re
    if not re.fullmatch(r"age1[0-9a-z]{58}", recipient) or identity.stat().st_mode & 0o077:
        raise InstallError("Recovery generation did not produce a protected native age identity")
    public = directory / "recovery-recipient.pub"
    fd = os.open(public, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w") as stream:
        stream.write(recipient + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return "Recovery identity created: " + str(identity) + "\nKeep an independent off-host copy. " \
        "This private file has no passphrase.\nPublic recipient: " + str(public) + "\n" + recipient


class CustodyWindow:
    """One review surface; work runs off the Tk thread with explicit completion."""

    def __init__(self, window):
        import tkinter as tk
        from tkinter import ttk
        self.window = window
        self.events = queue.Queue()
        self.busy = False
        window.title("IRIS · Offline signing")
        window.geometry("800x550")
        window.minsize(620, 500)
        window.configure(background="#ffffff")
        style = ttk.Style(window)
        style.theme_use("clam")
        style.configure("TFrame", background="#ffffff")
        style.configure("TLabel", background="#ffffff", foreground="#59616b", font=("DejaVu Sans", 10))
        style.configure("TNotebook", background="#ffffff", borderwidth=0)
        style.configure("TNotebook.Tab", background="#eef3f8", foreground="#102942", padding=(12, 8))
        style.map("TNotebook.Tab", background=[("selected", "#ffffff")])
        style.configure("TRadiobutton", background="#ffffff", foreground="#102942")
        style.map("TRadiobutton", background=[("active", "#ffffff")])
        style.configure("TButton", background="#eef3f8", foreground="#102942", padding=(10, 5))
        style.map("TButton", background=[("active", "#2998fa")], foreground=[("disabled", "#59616b")])
        style.configure("Heading.TLabel", font=("DejaVu Sans", 20, "bold"), foreground="#102942")
        style.configure("Status.TLabel", font=("DejaVu Sans Mono", 10), foreground="#102942")
        outer = ttk.Frame(window, padding=24)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Offline signing", style="Heading.TLabel").pack(anchor="w")
        ttk.Label(outer, text="Private keys stay on this machine. Return only public approvals.",
                  wraplength=700).pack(anchor="w", pady=(8, 18))
        tabs = ttk.Notebook(outer)
        tabs.pack(fill="x")
        approval = ttk.Frame(tabs, padding=16)
        creation = ttk.Frame(tabs, padding=16)
        recovery = ttk.Frame(tabs, padding=16)
        tabs.add(approval, text="Approve a request")
        tabs.add(creation, text="Create my root")
        tabs.add(recovery, text="Create recovery identity")
        self.kind = tk.StringVar(value="signing")
        ttk.Radiobutton(approval, text="Online signing certificate", variable=self.kind,
                        value="signing").grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Radiobutton(approval, text="Retirement list", variable=self.kind,
                        value="keylist").grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 12))
        self.request = self.file_row(approval, 2, "Public request")
        self.root = self.file_row(approval, 3, "My private root")
        self.output = self.file_row(approval, 4, "Save public approval", save=True)
        self.approve_button = ttk.Button(approval, text="Review and approve", command=self.review)
        self.approve_button.grid(row=5, column=1, sticky="e", pady=(16, 0))
        creation_hint = ttk.Label(creation, text="Create only your own root. The other holder uses a separate offline machine.",
                                  wraplength=610)
        creation_hint.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))
        creation.bind("<Configure>", lambda event: creation_hint.configure(wraplength=max(300, event.width - 32)))
        self.root_name = tk.StringVar(value="root-a")
        ttk.Label(creation, text="My root").grid(row=1, column=0, sticky="w")
        ttk.Combobox(creation, textvariable=self.root_name, values=("root-a", "root-b"),
                     state="readonly").grid(row=1, column=1, sticky="ew", pady=6)
        self.parent = self.file_row(creation, 2, "Private storage location", directory=True)
        self.create_button = ttk.Button(creation, text="Create protected root", command=self.create)
        self.create_button.grid(row=3, column=1, sticky="e", pady=(16, 0))
        ttk.Label(recovery, text="Create an independent age identity for deployment recovery. "
                  "Keep an off-host copy. The private file has no passphrase.",
                  wraplength=490).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))
        self.recovery_parent = self.file_row(recovery, 1, "Private storage location", directory=True)
        self.recovery_button = ttk.Button(recovery, text="Create recovery identity", command=self.create_recovery)
        self.recovery_button.grid(row=2, column=1, sticky="e", pady=(16, 0))
        self.status = tk.StringVar(value="Choose a public request and your private root, then review their details.")
        ttk.Separator(outer).pack(fill="x", pady=20)
        self.status_label = ttk.Label(outer, textvariable=self.status, style="Status.TLabel", wraplength=710,
                                     justify="left")
        self.status_label.pack(anchor="w")
        outer.bind("<Configure>", lambda event: self.status_label.configure(wraplength=max(300, event.width - 48)))
        window.protocol("WM_DELETE_WINDOW", self.close)
        window.after(100, self.poll)

    def file_row(self, frame, row, label, *, save=False, directory=False):
        import tkinter as tk
        from tkinter import filedialog, ttk
        value = tk.StringVar()
        ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=6)
        field = ttk.Frame(frame)
        field.grid(row=row, column=1, sticky="ew")
        ttk.Entry(field, textvariable=value).pack(side="left", fill="x", expand=True)

        def choose():
            picker = filedialog.askdirectory if directory else (filedialog.asksaveasfilename if save else filedialog.askopenfilename)
            selected = picker(parent=self.window, title=label)
            if selected:
                value.set(selected)

        ttk.Button(field, text="Browse…", command=choose).pack(side="right", padx=(8, 0))
        frame.columnconfigure(1, weight=1)
        return value

    def review(self):
        from tkinter import messagebox
        if self.busy:
            return
        try:
            kind, root, output = self.kind.get(), self.root.get(), self.output.get()
            if not all((self.request.get(), root, output)):
                raise InstallError("Choose the request, private root and a new approval output file")
            data, details = inspect_request(kind, self.request.get())
            if messagebox.askokcancel("Confirm public request", details +
                    "\n\nPrivate root: " + root +
                    "\n\nCompare these details with your independently trusted request. Approve this exact request?",
                    parent=self.window):
                self.start(lambda: approve_public(kind, data, root, output))
        except (InstallError, OSError, ValueError) as exc:
            self.failure(exc)

    def create(self):
        from tkinter import messagebox
        if self.busy:
            return
        parent, name = self.parent.get(), self.root_name.get()
        if not parent:
            self.status.set("Choose the private storage location for your root.")
            return
        if messagebox.askokcancel("Create your offline root", "Create " + name +
                " in a new private folder? Choose a nonempty passphrase in the next window. "
                "The other root holder must use their own machine.", parent=self.window):
            self.start(lambda: generate_root(parent, name))

    def start(self, operation):
        self.busy = True
        self.approve_button.state(["disabled"])
        self.create_button.state(["disabled"])
        self.recovery_button.state(["disabled"])
        self.status.set("Working. Complete any passphrase window. Keep this window open.")

        def work():
            try:
                self.events.put((True, operation()))
            except Exception as exc:
                self.events.put((False, exc))

        threading.Thread(target=work, daemon=True).start()

    def poll(self):
        try:
            success, result = self.events.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            self.approve_button.state(["!disabled"])
            self.create_button.state(["!disabled"])
            self.recovery_button.state(["!disabled"])
            self.status.set(result) if success else self.failure(result)
        self.window.after(100, self.poll)

    def failure(self, exc):
        self.status.set(str(exc) if isinstance(exc, InstallError) else
                        "Operation stopped. Check the selected files and output location; existing files are retained.")

    def create_recovery(self):
        from tkinter import messagebox
        if self.busy:
            return
        parent = self.recovery_parent.get()
        if not parent:
            self.status.set("Choose a protected storage location for the independent recovery identity.")
            return
        if messagebox.askokcancel("Create recovery identity", "Create a new private age identity? "
                "Keep an independent copy off the deployment host. The private file is not passphrase encrypted.", parent=self.window):
            self.start(lambda: generate_recovery_identity(parent))

    def close(self):
        if self.busy:
            self.status.set("Complete or cancel the passphrase window first; an operation is still running.")
        else:
            self.window.destroy()


def main():
    if os.geteuid() == 0:
        raise InstallError("Open Offline signing as the key holder, without sudo")
    try:
        import tkinter as tk
        window = tk.Tk()
    except ImportError:
        raise InstallError("Install python3-tk on the offline desktop to open Offline signing") from None
    except tk.TclError:
        raise InstallError("Offline signing needs a local desktop session; open it on the key holder's machine") from None
    CustodyWindow(window)
    window.mainloop()
    return 0


def askpass():
    """OpenSSH reads stdout over its pipe; secrets never enter argv or env."""
    import tkinter as tk
    from tkinter import simpledialog, messagebox
    try:
        window = tk.Tk()
        window.withdraw()
        # The OpenSSH-provided prompt contains a local filename, not key bytes.
        prompt = sys.argv[1][:1024] if len(sys.argv) > 1 else "Private root passphrase"
        while True:
            value = simpledialog.askstring("IRIS · Private root passphrase", prompt,
                                           show="•", parent=window)
            if value is None:
                return 1
            if value and "\n" not in value and "\r" not in value and len(value) <= 4096:
                print(value, flush=True)
                return 0
            messagebox.showerror("Passphrase required", "Use a nonempty passphrase on one line.", parent=window)
    except tk.TclError:
        return 1
    finally:
        if "window" in locals():
            window.destroy()
