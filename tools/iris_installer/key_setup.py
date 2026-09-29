# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Small, offline terminal workflow; only public files leave this machine."""

import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import shutil
import shlex
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace

from . import custody
from .state import InstallError, regular_bytes


def instruction_module():
    package = Path(__file__).resolve().parents[1] / "source/server"
    source = package if package.is_dir() else Path(__file__).resolve().parents[2] / "server"
    sys.path.insert(0, str(source))
    import instruction_keys
    return instruction_keys


def private_directory(path):
    path = Path(path).expanduser().absolute()
    if path.resolve() != path:
        raise InstallError("Use a storage folder without symbolic links")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise InstallError("Private storage must belong to you and have permissions 0700")
    return path


def check_private(path):
    info = Path(path).lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600):
        raise InstallError("Private key must belong to you and have permissions 0600")


def publish(path, data, mode=0o644):
    """Allow an identical public result on retry, never replace another file."""
    path = Path(path)
    if path.exists() or path.is_symlink():
        if regular_bytes(path, 1024 * 1024) != data:
            raise InstallError("A different file already exists: " + str(path))
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def public_key(data):
    """Accept exactly one ordinary Ed25519 public key, without secret comments."""
    parts = data.strip().split()
    if len(parts) < 2 or parts[0] != b"ssh-ed25519" or len(data.splitlines()) != 1:
        raise InstallError("Choose an Ed25519 public .pub file")
    try:
        wire = base64.b64decode(parts[1], validate=True)
    except ValueError:
        raise InstallError("Public key is not valid") from None
    expected = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)
    if len(wire) != 51 or not wire.startswith(expected):
        raise InstallError("Public key is not a valid Ed25519 key")
    return b"ssh-ed25519 " + parts[1] + b"\n"


def protected_root(path):
    """Inspect the OpenSSH envelope without exposing or decrypting its key."""
    path = Path(path).absolute()
    if path.resolve() != path:
        raise InstallError("Private key path must not use symbolic links")
    check_private(path)
    data = regular_bytes(path, 32768)
    try:
        lines = data.splitlines()
        if lines[0] != b"-----BEGIN OPENSSH PRIVATE KEY-----" or lines[-1] != b"-----END OPENSSH PRIVATE KEY-----":
            raise ValueError
        wire = base64.b64decode(b"".join(lines[1:-1]), validate=True)
        if not wire.startswith(b"openssh-key-v1\x00"):
            raise ValueError
        length = struct.unpack(">I", wire[15:19])[0]
        cipher = wire[19:19 + length]
        offset = 19 + length
        kdf_length = struct.unpack(">I", wire[offset:offset + 4])[0]
        kdf = wire[offset + 4:offset + 4 + kdf_length]
        if cipher == b"none" or kdf != b"bcrypt" or not cipher:
            raise InstallError("This key has no passphrase protection. Run ssh-keygen -p -f " + str(path) + " to add one, then retry")
    except (ValueError, IndexError, struct.error):
        raise InstallError("This is not a supported OpenSSH private key") from None


def run(command, *, capture=False):
    # OpenSSH owns the terminal prompt. No passphrase enters Python or argv.
    env = dict(os.environ)
    for name in ("SSH_ASKPASS", "SSH_ASKPASS_REQUIRE"):
        env.pop(name, None)
    env["SSH_ASKPASS_REQUIRE"] = "never"
    result = subprocess.run(command, env=env, check=False,
                            stdout=subprocess.PIPE if capture else None,
                            stderr=subprocess.PIPE if capture else None)
    if result.returncode:
        raise InstallError("Key operation stopped; check the files and passphrase, then retry")
    return result.stdout


def holder_machine():
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        raise InstallError("Run this on your key-holder machine, not inside a container")
    if Path("/etc/iris").exists() or list(Path("/var/lib/iris-installer").glob("*/installation.json")):
        raise InstallError("This looks like an IRIS server. Use a separate key-holder machine")
    print("Use your separate key-holder machine, not the IRIS server.")
    print("Keep this machine offline while creating or using private keys.")
    if input("Type KEY HOLDER to confirm where you are running this: ").strip() != "KEY HOLDER":
        raise InstallError("Stopped; no private keys were created or used")


def create_root(name, directory):
    if name not in ("root-a", "root-b"):
        raise InstallError("Choose root-a or root-b")
    directory = private_directory(directory)
    other = "root-b" if name == "root-a" else "root-a"
    if (directory / other).exists() or (directory / (other + ".pub")).exists():
        raise InstallError("The other signing key is here. Each holder must use a separate machine")
    root = directory / name
    if root.is_symlink():
        raise InstallError("Private key must not be a symbolic link")
    if not root.exists():
        if (directory / (name + ".pub")).exists():
            raise InstallError("A public key is already here without its private key; use the original key location")
        print("Choose a non-empty passphrase when ssh-keygen asks. Keep it safe.")
        run(["ssh-keygen", "-q", "-t", "ed25519", "-C", "iris-" + name, "-f", str(root)])
    protected_root(root)
    # Derive from the private key on every run, detecting mismatched public files.
    data = public_key(run(["ssh-keygen", "-y", "-f", str(root)], capture=True))
    public = directory / (name + ".pub")
    if public.exists():
        if public_key(regular_bytes(public, 16384)) != data:
            raise InstallError("Public and private keys do not match; keep both files and investigate")
    else:
        publish(public, data)
    run(["ssh-keygen", "-l", "-f", str(public)])
    print("Your signing key is ready. Keep the private file on this machine.")
    print("Share only: " + str(public))
    return public


def create_recovery(directory):
    directory = private_directory(directory)
    identity = directory / "recovery.age"
    if identity.is_symlink():
        raise InstallError("Recovery key must not be a symbolic link")
    if not identity.exists():
        if (directory / "recovery-recipient.pub").exists():
            raise InstallError("A public recovery file is already here; find its original private key")
        run(["age-keygen", "-o", str(identity)], capture=True)
    check_private(identity)
    recipient = run(["age-keygen", "-y", str(identity)], capture=True).strip()
    if not re.fullmatch(rb"age1[0-9a-z]{58}", recipient):
        raise InstallError("Recovery key did not produce a valid public age recipient")
    output = directory / "recovery-recipient.pub"
    publish(output, recipient + b"\n")
    print("Recovery key is ready. Keep recovery.age safe and keep an independent offline copy.")
    print("It has no passphrase. Use encrypted storage for the private file.")
    print("Share only: " + str(output))
    return output


def approve(kind, request, root, output):
    protected_root(root)
    data = regular_bytes(request, 1024 * 1024)
    if kind == "signing":
        public_key(data)
        print("This approves the server signing key for 30 days.")
    else:
        keys = instruction_module()
        try:
            metadata, krl = keys._parse_keylist_payload(data)
            keys._validate_krl_bytes(krl)
        except keys.InstructionKeyError:
            raise InstallError("Choose a valid public retirement request") from None
        print("This approves a signing-key retirement request. Review the revoked keys first.")
        print("Sequence: " + str(metadata["keylist_seq"]) + "; signing root: " + metadata["signer_root_id"])
        print("Revocation list SHA256: " + metadata["krl_sha256"])
    digest = hashlib.sha256(data).hexdigest()
    print("Request SHA256: " + digest)
    expected = input("Enter the SHA256 from the server's trusted operator record: ").strip().lower()
    if expected != digest:
        raise InstallError("Hashes do not match; nothing was signed")
    with tempfile.TemporaryDirectory(prefix="iris-public-request-") as temporary:
        snapshot = Path(temporary) / "request"
        snapshot.write_bytes(data)
        args = SimpleNamespace(root_key=Path(root), output=Path(output), public_key=snapshot, payload=snapshot)
        if kind == "signing":
            custody.approve(args)
        else:
            custody.approve_keylist(args)
    return Path(output)


def public_data(source):
    data = regular_bytes(source, 1024 * 1024)
    if b"PRIVATE" in data or b"AGE-SECRET-" in data:
        raise InstallError("Private key material must stay here; choose a public file")
    if data.startswith(b"ssh-ed25519 "):
        data = public_key(data)  # Strip comments rather than copying arbitrary text.
    elif re.fullmatch(rb"age1[0-9a-z]{58}\n?", data):
        data = data.strip() + b"\n"
    elif data.startswith(b"ssh-ed25519-cert-v01@openssh.com "):
        # Let OpenSSH parse the complete public certificate before exporting it.
        with tempfile.TemporaryDirectory(prefix="iris-public-check-") as temporary:
            check = Path(temporary) / "certificate.pub"
            # Comments are not needed and may contain unexpected private text.
            parts = data.strip().split()
            if len(parts) < 2 or len(data.splitlines()) != 1:
                raise InstallError("Choose a public certificate file")
            data = b" ".join(parts[:2]) + b"\n"
            check.write_bytes(data)
            run(["ssh-keygen", "-L", "-f", str(check)], capture=True)
    elif data.startswith(b"IRIS-KEYLIST"):
        keys = instruction_module()
        try:
            keys.parse_keylist_artifact(data)
        except keys.InstructionKeyError:
            raise InstallError("Choose a valid public retirement approval") from None
    else:
        raise InstallError("Choose a public key, public approval or public recovery recipient")
    return data


def export_public(source, directory):
    source = Path(source)
    data = public_data(source)
    directory = Path(directory).expanduser().absolute()
    if directory.resolve() != directory or not directory.is_dir():
        raise InstallError("Choose an existing transfer folder without symbolic links")
    destination = directory / source.name
    publish(destination, data)
    print("Public file copied: " + str(destination))
    return destination


def ssh_command(host, script):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*@[A-Za-z0-9][A-Za-z0-9.-]*", host):
        raise InstallError("Use a plain SSH address such as user@server.example")
    return ["ssh", "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no",
            "-o", "ClearAllForwardings=yes", host, "python3 -c " + shlex.quote(script)]


def remote_path(path):
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", path) or ".." in Path(path).parts:
        raise InstallError("Use a full remote file path without spaces or '..'")
    return path


def send_public(source, host, destination):
    data = public_data(source)
    destination = remote_path(destination)
    script = ("import os,pathlib,sys; p=pathlib.Path(" + repr(destination) + "); "
              "assert p.parent.resolve()==p.parent and p.parent.is_dir(), 'Use an existing folder without links'; "
              "d=sys.stdin.buffer.read(1048577); assert len(d)<=1048576; "
              "fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644); "
              "os.fchmod(fd,0o644); f=os.fdopen(fd,'wb'); f.write(d); f.flush(); os.fsync(f.fileno()); f.close()")
    print("Sending only the checked public file. SSH host must already be trusted.")
    result = subprocess.run(ssh_command(host, script), input=data, check=False)
    if result.returncode:
        raise InstallError("Public upload stopped. Check SSH trust, folder access, and whether that file already exists")
    print("Public file sent to " + host + ":" + destination)


def fetch_request(host, source, output):
    source = remote_path(source)
    # Validate on the remote host before transmitting: never fetch a private file.
    script = ("import os,stat,sys,base64,re; "
              "fd=os.open(" + repr(source) + ",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK); "
              "assert stat.S_ISREG(os.fstat(fd).st_mode); d=os.read(fd,16385); os.close(fd); "
              "assert len(d)<=16384 and len(d.splitlines())==1; "
              "assert re.fullmatch(rb'ssh-ed25519 [A-Za-z0-9+/=]+(?: [A-Za-z0-9@._/-]{1,128})?\\n?',d); "
              "w=base64.b64decode(d.split()[1],validate=True); "
              "assert len(w)==51 and w.startswith(b'\\x00\\x00\\x00\\x0bssh-ed25519\\x00\\x00\\x00 '); "
              "assert b'PRIVATE' not in d and b'AGE-SECRET-' not in d; sys.stdout.buffer.write(d)")
    print("Reading a public signing request over trusted SSH. The remote file must be readable by this user.")
    data = run(ssh_command(host, script), capture=True)
    public_key(data)
    publish(output, data)
    print("Public request saved: " + str(output))
    print("SHA256: " + hashlib.sha256(data).hexdigest())


def parser():
    result = argparse.ArgumentParser(description="Create and use IRIS keys from a terminal on a separate key-holder machine.")
    modes = result.add_subparsers(dest="command")
    root = modes.add_parser("create-root", help="create or check your protected signing key")
    root.add_argument("--name", choices=("root-a", "root-b"))
    root.add_argument("--directory", type=Path)
    recovery = modes.add_parser("create-recovery", help="create or check an independent recovery key")
    recovery.add_argument("--directory", type=Path)
    approval = modes.add_parser("approve", help="sign a public request from the server")
    approval.add_argument("--kind", choices=("signing", "keylist"), default="signing")
    approval.add_argument("--request", type=Path)
    approval.add_argument("--root-key", type=Path)
    approval.add_argument("--output", type=Path)
    export = modes.add_parser("export", help="copy only a public file to a transfer folder")
    export.add_argument("--file", type=Path)
    export.add_argument("--directory", type=Path)
    send = modes.add_parser("send", help="send a public file over trusted SSH")
    send.add_argument("--file", type=Path)
    send.add_argument("--host")
    send.add_argument("--remote-path")
    fetch = modes.add_parser("fetch", help="read an exported public signing request over trusted SSH")
    fetch.add_argument("--host")
    fetch.add_argument("--remote-path")
    fetch.add_argument("--output", type=Path)
    return result


def ask(value, prompt):
    answer = value or input(prompt).strip()
    if not answer:
        raise InstallError("A value is required; stopped without continuing")
    return Path(answer).expanduser()


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command is None:
            print("1. Create my signing key\n2. Create recovery key\n3. Approve server request\n4. Copy public file\n5. Send public file over SSH\n6. Read public request over SSH")
            choice = input("Choose 1 to 6: ").strip()
            commands = {"1": "create-root", "2": "create-recovery", "3": "approve", "4": "export", "5": "send", "6": "fetch"}
            if choice not in commands:
                raise InstallError("Choose a number from 1 to 6")
            args = parser().parse_args([commands[choice]])
            if args.command == "approve":
                kind = input("Request type: 1. Server signing key  2. Key retirement list: ").strip()
                if kind not in ("1", "2"):
                    raise InstallError("Choose request type 1 or 2")
                args.kind = "signing" if kind == "1" else "keylist"
        if args.command in ("create-root", "create-recovery", "approve"):
            holder_machine()
        for binary in (("age-keygen",) if args.command == "create-recovery" else ("ssh-keygen",)):
            if shutil.which(binary) is None:
                raise InstallError("Install " + binary + " on this key-holder machine first")
        if args.command == "create-root":
            name = args.name or input("Your key name (root-a or root-b): ").strip()
            if name not in ("root-a", "root-b"):
                raise InstallError("Choose root-a or root-b")
            result = create_root(name, ask(args.directory, "Private storage folder: "))
        elif args.command == "create-recovery":
            result = create_recovery(ask(args.directory, "Private recovery storage folder: "))
        elif args.command == "approve":
            result = approve(args.kind, ask(args.request, "Public request file from server: "),
                             ask(args.root_key, "Your private signing key: "),
                             ask(args.output, "Save public approval as: "))
        elif args.command == "export":
            export_public(ask(args.file, "Public file to copy: "), ask(args.directory, "Transfer folder: "))
            return 0
        elif args.command == "send":
            send_public(ask(args.file, "Public file to send: "),
                        args.host or input("SSH address (user@host): ").strip(),
                        args.remote_path or input("Full public destination path on server: ").strip())
            return 0
        else:
            fetch_request(args.host or input("SSH address (user@host): ").strip(),
                          args.remote_path or input("Full readable public request path on server: ").strip(),
                          ask(args.output, "Save public request as: "))
            return 0
        transfer = input("Copy the public file to a transfer folder? Enter folder, or press Enter to skip: ").strip()
        if transfer:
            export_public(result, transfer)
        return 0
    except (InstallError, OSError, EOFError, KeyboardInterrupt) as error:
        print("Stopped: " + (str(error) or "cancelled"))
        return 1
