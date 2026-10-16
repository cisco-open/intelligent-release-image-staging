# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Guided local setup; privileged deployment receives public files only."""

import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import uuid

from . import custody, key_setup
from .state import InstallError, Journal, regular_bytes


def confirm(question):
    return input(question + " [y/N]: ").strip().lower() in ("y", "yes")


def public_status(directory):
    """Return only allowlisted public data, never the complete private journal."""
    if os.geteuid() != 0:
        raise InstallError("Run setup-status with sudo")
    journal = Journal(directory)
    if not journal.directory.exists():
        return {"present": False}
    with journal.locked():
        if journal.document is None:
            return {"present": False}
        doc = journal.document
        config = doc["config"]
        from .deploy import validate_config
        from .prebuilt_install import public_selection
        validate_config(config)
        result = {"present": True, "id": doc["id"], "state": doc["state"],
                  "config": {key: config[key] for key in
                             ("target", "instance", "host", "console_bind", "console_port")},
                  **public_selection(doc)}
        if config.get("image_root"):
            result["config"]["image_root"] = config["image_root"]
        if doc["state"] == "WAITING_FOR_SIGNING_APPROVAL":
            from .deploy import read_roots
            roots = read_roots(journal.directory / "roots")
            hashes = {name: hashlib.sha256(data).hexdigest() for name, data in roots.items()}
            if hashes != doc["root_digests"]:
                raise InstallError("Deployment public roots changed; keep the files and investigate")
            result["roots"] = {name: key_setup.public_key(data).decode("ascii")
                               for name, data in roots.items()}
            data = regular_bytes(journal.directory / "requests/online.pub", 16384)
            result["request"] = key_setup.public_key(data).decode("ascii")
        return result


def controller(arguments, *, capture=False):
    # Use the matching installed command, never an unrelated irisctl from PATH.
    executable = Path(__file__).resolve().parents[1] / "irisctl"
    result = subprocess.run(["sudo", str(executable), *arguments], check=False,
                            stdout=subprocess.PIPE if capture else None)
    if capture:
        if result.returncode:
            raise InstallError("Could not read installation state. Nothing was reset")
        try:
            status = json.loads(result.stdout)
            if not isinstance(status, dict) or type(status.get("present")) is not bool:
                raise ValueError
            if status["present"] and not (
                    isinstance(status.get("id"), str) and isinstance(status.get("state"), str)
                    and isinstance(status.get("config"), dict)
                    and all(name in status["config"] for name in
                            ("instance", "host", "console_bind", "console_port", "target"))):
                raise ValueError
            return status
        except (ValueError, UnicodeError):
            raise InstallError("Invalid setup status; keep your files and check the installer") from None
    return result.returncode


def choose_key_folder(args):
    default = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".local/share/iris-setup-keys" / args.instance
    value = args.key_directory
    if value is None:
        if args.key_mode == "automatic":
            value = default
        else:
            answer = input("Private key folder [" + str(default) + "]: ").strip()
            value = Path(answer).expanduser() if answer else default
    folder = Path(value).expanduser()
    if not folder.is_absolute():
        raise InstallError("Enter a full folder path, or press Enter for the default. This is not a passphrase prompt")
    # Private keys must stay out of build inputs, image mounts and backups.
    excluded = [args.state_dir, args.source, Path("/opt/images"), Path("/opt/iris"),
                Path("/etc/iris"), Path("/var/lib/iris-installer")]
    excluded += [getattr(args, name) for name in ("image_root", "backup_root", "recovery_root")
                 if getattr(args, name, None) is not None]
    for path in excluded:
        path = Path(path).absolute()
        if folder == path or path in folder.parents or folder in path.parents:
            raise InstallError("Choose a dedicated private key folder outside deployment, source, image and backup folders")
    return key_setup.private_directory(folder)


def prepare_keys(folder, *, mode="manual"):
    public = key_setup.private_directory(folder / "public")
    roots = key_setup.private_directory(public / "roots")
    if set(path.name for path in roots.iterdir()) - {"root-a.pub", "root-b.pub"}:
        raise InstallError("The public roots folder contains other files; keep them and investigate")
    for name in ("root-a", "root-b"):
        private = folder / name / name
        if (roots / (name + ".pub")).exists() and not private.exists():
            raise InstallError("A signing key was moved or is missing. Use its original folder; nothing was replaced")
    for name in ("root-a", "root-b"):
        if mode == "automatic":
            from . import automatic_keys
            result = automatic_keys.create_root(name, folder / name)
        else:
            print("\nSet up " + name + ". Existing keys are checked and reused.")
            result = key_setup.create_root(name, folder / name)
        key_setup.publish(roots / (name + ".pub"), key_setup.public_data(result))
    recovery = folder / "recovery"
    recipient = public / "recovery-recipient.pub"
    if recipient.exists() and not (recovery / "recovery.age").exists():
        raise InstallError("The recovery key was moved or is missing. Find the original before continuing")
    result = key_setup.create_recovery(recovery)
    key_setup.publish(recipient, key_setup.public_data(result))
    print("Private keys: " + str(folder))
    print("Keep a separate secure copy of this complete folder for recovery.")
    return roots, key_setup.public_data(recipient).decode("ascii").strip()


def install_arguments(args):
    """Forward only options understood by install, including all three layouts."""
    from .cli import parser
    defaults = vars(parser().parse_args(["install"]))
    result = ["install"]
    for name in defaults:
        if name == "command":
            continue
        value = getattr(args, name)
        if name == "origin_egress_ip":
            for address in value:
                result.extend(["--origin-egress-ip", address])
            continue
        if value is None or value is False:
            continue
        result.append("--" + name.replace("_", "-"))
        if value is not True:
            result.append(str(value))
    return result


def sign_request(status, folder, *, mode="manual"):
    data = status["request"].encode("ascii")
    key_setup.public_key(data)
    root = folder / "root-a/root-a"
    key_setup.protected_root(root)
    if mode == "automatic":
        from . import automatic_keys
        selected = automatic_keys.root_public(root)
    else:
        selected = key_setup.public_key(key_setup.run(["ssh-keygen", "-y", "-f", str(root)], capture=True))
    if selected.decode("ascii") != status["roots"].get("root-a.pub"):
        raise InstallError("This root-a does not match the installation. No certificate was signed")
    print("Server " + status["config"]["host"] + ", installation " + status["id"] + ".")
    print("Public request SHA256: " + hashlib.sha256(data).hexdigest())
    if mode == "manual":
        print("This signs the local server request for 30 days.")
        if not confirm("Sign this request with root-a and continue?"):
            raise InstallError("Setup is paused. Your keys and installation state are kept")
    else:
        print("Signing the checked local server request automatically (valid for 30 days).")
    approvals = key_setup.private_directory(folder / "approvals")
    output = approvals / ("online-cert-" + uuid.uuid4().hex + ".pub")
    with tempfile.TemporaryDirectory(prefix="iris-public-request-") as temporary:
        request = Path(temporary) / "online.pub"
        request.write_bytes(data)
        if mode == "automatic":
            automatic_keys.sign_online(root, request, output)
        else:
            custody.approve(SimpleNamespace(root_key=root, public_key=request, output=output))
    return output


def run_setup(args):
    try:
        if os.geteuid() == 0:
            raise InstallError("Run irisctl setup without sudo. It asks for sudo when needed")
        if not sys.stdin.isatty():
            raise InstallError("Run irisctl setup from an interactive terminal")
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", args.instance):
            raise InstallError("Choose an instance name with lowercase letters, digits and hyphens")
        if args.roots_dir is not None or args.recovery_recipient is not None:
            raise InstallError("For existing public keys, use irisctl install. Setup creates or reuses local keys")
        args.state_dir = (args.state_dir or Path("/var/lib/iris-installer") / args.instance).absolute()
        print("\n[1/4] Review this installation")
        print("IRIS will prepare the server, device packages and Console.")
        print("Your system may ask for your sudo password; this is not a certificate password.")
        status = controller(["setup-status", "--state-dir", str(args.state_dir)], capture=True)
        folder = None
        if status["present"]:
            from .prebuilt_install import assert_setup_selection
            assert_setup_selection(args, status)
            print("Resuming " + status["id"] + "; recorded deployment settings are kept.")
            # Default key location follows the recorded instance, not a CLI guess.
            args.instance = status["config"]["instance"]
            if "image_root" in status["config"]:
                args.image_root = Path(status["config"]["image_root"])
        else:
            args.host = args.host or input("Server IPv4 address that devices can reach: ").strip()
            if args.console_bind == "127.0.0.1":
                args.console_bind = input("Console listen IPv4 address [127.0.0.1; management access only]: ").strip() or "127.0.0.1"
            folder = choose_key_folder(args)
            print("Server: " + args.host)
            print("Console address after setup: https://" + args.console_bind + ":" + str(args.console_port) + "/")
        if args.key_mode == "automatic":
            print("Keys: automatic. Strong random passphrases are saved privately on this host.")
        else:
            print("Keys: manual. OpenSSH will ask for your signing-key passphrase.")
        print("A host compromise can expose keys and passwords kept here. Keep a separate secure copy.")
        if not confirm("Start setup?"):
            print("Setup paused. No deployment was started or changed.")
            return 0
        print("\n[2/4] Prepare keys and build the server")
        print("This can take several minutes. Wait for the next numbered step.")
        if status["present"]:
            result = controller(["resume", "--state-dir", str(args.state_dir)])
        else:
            args.roots_dir, args.recovery_recipient = prepare_keys(folder, mode=args.key_mode)
            args.accept_changes = True
            result = controller(install_arguments(args))
        if result == 20:
            print("\n[3/4] Finish trusted setup and build device packages")
            status = controller(["setup-status", "--state-dir", str(args.state_dir)], capture=True)
            if status.get("state") != "WAITING_FOR_SIGNING_APPROVAL" or "request" not in status:
                raise InstallError("The installation changed. Rerun setup to review its current state")
            folder = folder or choose_key_folder(args)
            certificate = sign_request(status, folder, mode=args.key_mode)
            print("Preparing device packages and starting the Console. No action is needed while this runs.")
            result = controller(["resume", "--state-dir", str(args.state_dir), "--certificate", str(certificate)])
        elif result in (0, 21, 22):
            print("\n[3/4] Existing signing and device package checks completed")
        if result not in (0, 21, 22):
            raise InstallError("Installer stopped with code " + str(result) + ". Keep your files, fix the reported error and rerun setup")
        status = controller(["setup-status", "--state-dir", str(args.state_dir)], capture=True)
        config = status["config"]
        print("\n[4/4] Open the Console")
        print("Open https://" + config["console_bind"] + ":" + str(config["console_port"]) + "/ and check its certificate.")
        print("Create your own administrator account if asked. No account was created or signed in for you.")
        print("Finish the Console setup checks and arrange key renewal and independent backups.")
        return 0
    except (EOFError, KeyboardInterrupt):
        raise InstallError("Setup cancelled. Existing keys and installation state were kept") from None
