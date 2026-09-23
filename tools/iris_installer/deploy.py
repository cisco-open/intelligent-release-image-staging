# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Resumable source-build installation on one Ubuntu Docker host.

Production roots are always supplied as public keys. This module never creates
offline private roots or an administrator, and never contacts inventory devices.
"""

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess

from . import ubuntu
from .state import InstallError, Journal, atomic_write, regular_bytes


WAITING_APPROVAL = 20
OWNER_CLAIM = 21
PRODUCTION_REVIEW = 22


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def clean_env():
    # Do not inherit stale Compose overrides, builder overrides, proxy auth or
    # an operator's SSH agent into privileged deployment/build commands.
    return {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8", "DEBIAN_FRONTEND": "noninteractive",
            "DOCKER_HOST": "unix:///var/run/docker.sock"}


def run(command, *, env=None, input=None, timeout=7200, capture=False):
    print(">> " + command[0] + " " + command[1] if len(command) > 1 else ">> " + command[0], flush=True)
    try:
        result = subprocess.run(command, input=input, env=env or clean_env(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise InstallError("Command timed out; installation state was retained for resume") from exc
    except OSError as exc:
        raise InstallError("Required command is unavailable: " + command[0]) from exc
    if result.returncode:
        # Bootstrap/build tools can print tokens and private paths. Do not copy
        # their unrestricted output into a journal or terminal support log.
        raise InstallError("Command failed: " + command[0] + "; state retained, no reset performed")
    return result.stdout if capture else b""


def validate_config(config):
    if config["target"] != "docker":
        raise InstallError("Kubernetes deployment is not implemented in this candidate; no changes made")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", config["instance"]):
        raise InstallError("Instance name must start with a letter and contain lowercase letters/digits/hyphens")
    for key in ("host", "console_bind"):
        try:
            address = ipaddress.IPv4Address(config[key])
        except ipaddress.AddressValueError as exc:
            raise InstallError(key + " must be a concrete IPv4 address") from exc
        if address.is_unspecified or address.is_multicast:
            raise InstallError(key + " must be a concrete unicast address")
    if not 1024 <= config["console_port"] <= 65535:
        raise InstallError("Console port must be between 1024 and 65535")
    if config["console_port"] in (6969, 8443, 8000, 6881, 9101):
        raise InstallError("Console port conflicts with a server port")
    if not re.fullmatch(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", config["recovery_recipient"]):
        raise InstallError("Supply an approved age recovery PUBLIC recipient held separately")
    if config["peer_tls"] not in ("required", "disabled"):
        raise InstallError("Peer TLS must be required or explicitly disabled")


def read_roots(directory):
    directory = Path(directory)
    names = sorted(p.name for p in directory.iterdir())
    if len(names) != 2 or any(not re.fullmatch(r"[A-Za-z0-9_-]+\.pub", name) for name in names):
        raise InstallError("Roots directory must contain exactly two public .pub files and nothing else")
    roots = {}
    blobs = set()
    for name in names:
        data = regular_bytes(directory / name, 16384)
        fields = data.decode("ascii").strip().split()
        if len(fields) < 2 or fields[0] != "ssh-ed25519" or fields[1] in blobs:
            raise InstallError("Supply two distinct Ed25519 public roots, never private keys")
        blobs.add(fields[1])
        roots[name] = data
    return roots


def port_preflight(config):
    endpoints = [(config["host"], port) for port in (6969, 8443, 8000, 6881, 9101)]
    endpoints.append((config["console_bind"], config["console_port"]))
    for host, port in endpoints:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((host, port))
            except OSError as exc:
                raise InstallError(f"Address unavailable or port occupied: {host}:{port}; nothing will be replaced") from exc


class DockerInstall:
    def __init__(self, journal, runner=run):
        self.journal = journal
        self.base = journal.directory
        self.config = journal.document["config"]
        validate_config(self.config)
        self.runner = runner
        self.source = self.base / "source"
        self.compose_file = self.base / "compose.json"
        self.env = dict(clean_env(), HOME=str(self.base / "build-home"),
                        DOCKER_CONFIG=str(self.base / "build-home/.docker"),
                        XDG_CACHE_HOME=str(self.base / "cache"),
                        IRIS_INSTRUCTION_ROOTS_DIR=str(self.base / "roots"),
                        IRIS_ARTIFACTS_HOST_DIR=str(self.base / "artifacts"),
                        IRIS_DEVICE_IMAGE_OCI=str(self.base / "artifacts/device.oci.tar"),
                        IRIS_DEVICE_PLATFORMS="linux/amd64,linux/arm64",
                        IOXCLIENT=str(self.base / "bin/ioxclient"))

    def command(self, command, **kwargs):
        return self.runner([str(arg) for arg in command], env=self.env, **kwargs)

    def compose(self, *args, **kwargs):
        return self.command(["docker", "compose", "-p", self.config["instance"],
                             "-f", self.compose_file, *args], **kwargs)

    def execute(self, *args, **kwargs):
        return self.compose("exec", "-T", "iris", *args, **kwargs)

    def python(self, code, *args):
        code = "import sys; sys.path.insert(0,'/opt/iris/server'); " + code
        return self.execute("python3", "-I", "-B", "-c", code, *args, capture=True)

    def verify_inputs(self):
        manifest = self.journal.document["source_manifest"]
        actual = {}
        for path in sorted(self.source.rglob("*")):
            if path.is_symlink():
                raise InstallError("Source snapshot contains a symlink")
            if path.is_file():
                actual[str(path.relative_to(self.source))] = digest(path)
        if actual != manifest:
            raise InstallError("Installer source snapshot changed; refusing to resume")
        expected = self.journal.document["root_digests"]
        actual = {name: hashlib.sha256(data).hexdigest()
                  for name, data in read_roots(self.base / "roots").items()}
        if actual != expected:
            raise InstallError("Deployment root fingerprints changed; refusing to resume")

    def prepare(self):
        completed = self.journal.document["completed"]
        if "prepared" in completed:
            if digest(self.compose_file) != completed["prepared"]:
                raise InstallError("Generated Compose configuration changed")
            return
        for directory in ("build-home", "build-home/.docker", "cache", "bin", "requests", "images", "artifacts"):
            (self.base / directory).mkdir(mode=0o755, exist_ok=True)
        os.chown(self.base / "artifacts", 10001, 10001)
        identity = self.base / "age.txt"
        if not identity.exists():
            # age-keygen refuses an existing destination. Never regenerate a
            # partially-created identity or replace another deployment's key.
            self.command(["age-keygen", "-o", identity])
        public = self.command(["age-keygen", "-y", identity], capture=True).decode().strip()
        if not public.startswith("age1"):
            raise InstallError("Unable to validate the generated age identity")
        identity.chmod(0o600)
        os.chown(identity, 10001, 10001)
        settings = {
            "IRIS_HOST_IP": self.config["host"],
            "IRIS_AGE_KEY_FILE_HOST": str(identity),
            "IRIS_AGE_RECIPIENTS": public + "," + self.config["recovery_recipient"],
            "IRIS_GUI_PUBLISH": str(self.config["console_port"]),
            "IRIS_CONSOLE_URL": f'https://{self.config["console_bind"]}:{self.config["console_port"]}/',
            "IRIS_PEER_TLS_MODE": self.config["peer_tls"],
            "IRIS_IMAGE_ROOT": str(self.base / "images"),
            "IRIS_ARTIFACTS_HOST_DIR": str(self.base / "artifacts"),
        }
        # Empty explicit env file prevents automatic discovery of server/.env.
        atomic_write(self.base / "compose.env", b"# managed by irisctl\n")
        data = self.runner(["docker", "compose", "--env-file", str(self.base / "compose.env"),
                            "-p", self.config["instance"], "-f", str(self.source / "server/docker-compose.yml"),
                            "config", "--format", "json"], env=dict(self.env, **settings), capture=True)
        compose = json.loads(data)
        compose["name"] = self.config["instance"]
        for service, suffix in (("iris", "server"), ("console", "console")):
            spec = compose["services"][service]
            spec["container_name"] = self.config["instance"] + "-" + suffix
            spec["image"] = "iris-installer/" + self.config["instance"] + "-" + suffix + ":" + self.journal.document["id"]
            spec.setdefault("labels", {})["com.cisco.iris.installer"] = self.journal.document["id"]
            for port in spec.get("ports", []):
                port["host_ip"] = self.config["host"] if service == "iris" else self.config["console_bind"]
        for category in ("volumes", "networks"):
            for spec in compose.get(category, {}).values():
                spec.setdefault("labels", {})["com.cisco.iris.installer"] = self.journal.document["id"]
        atomic_write(self.compose_file, json.dumps(compose, sort_keys=True, indent=2).encode())
        self.journal.checkpoint("prepared", digest(self.compose_file))

    def verify_resource_ownership(self):
        for kind in ("container", "volume", "network"):
            command = ["docker", kind, "ls", "-q"]
            if kind == "container":
                command.append("-a")
            identifiers = self.command([*command, "--filter", "label=com.docker.compose.project=" + self.config["instance"]], capture=True).decode().split()
            for identifier in identifiers:
                records = json.loads(self.command(["docker", kind, "inspect", identifier], capture=True))
                for record in records:
                    labels = record.get("Config", {}).get("Labels", {}) if kind == "container" else record.get("Labels", {})
                    if not labels or labels.get("com.cisco.iris.installer") != self.journal.document["id"]:
                        raise InstallError("Existing resource is not owned by this installation; refusing adoption")

    def build(self):
        saved = self.journal.document["completed"].get("images")
        if saved:
            for image, expected in saved.items():
                actual = self.command(["docker", "image", "inspect", image, "--format", "{{.Id}}"], capture=True).decode().strip()
                if actual != expected:
                    raise InstallError("Previously built image is missing or changed; do not replace deployment state")
            return
        self.compose("build", "--pull")
        images = {}
        for spec in json.loads(regular_bytes(self.compose_file))["services"].values():
            image = spec["image"]
            images[image] = self.command(["docker", "image", "inspect", image, "--format", "{{.Id}}"], capture=True).decode().strip()
        self.journal.checkpoint("images", images)

    def bootstrap(self):
        self.compose("run", "--rm", "--no-deps", "iris", "iris-bootstrap")
        self.compose("run", "--rm", "--no-deps", "-v", str(self.base / "roots") + ":/pub:ro",
                     "--entrypoint", "sh", "iris", "-c",
                     'install -d -m 0755 "$IRIS_CONFIG/instr/roots.d" && '
                     'install -m 0644 /pub/*.pub "$IRIS_CONFIG/instr/roots.d/"')
        self.compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "180", "iris")
        self.journal.checkpoint("server", True)

    def signing(self, certificate=None):
        existing = self.python("import instruction_keys as k, os; print(os.path.exists(k.InstructionPaths.from_env().encrypted_key))").strip()
        if existing == b"False":
            self.execute("iris-instructions", "--generate-online-key")
        elif existing != b"True":
            raise InstallError("Cannot determine online signing key state")
        # Public export validates custody through the established server API.
        public = self.python("import instruction_keys as k; p=k.export_online_public(k.InstructionPaths.from_env()); sys.stdout.buffer.write(open(p,'rb').read())")
        atomic_write(self.base / "requests/online.pub", public, 0o644)
        if certificate:
            data = regular_bytes(certificate, 65536)
            # Import via stdin into a private temporary runtime file. No docker
            # cp ownership/mode dependence and no private root on the server.
            code = (
                "import sys,tempfile,os; sys.path.insert(0,'/opt/iris/server'); "
                "import instruction_keys as k; p=k.InstructionPaths.from_env(); "
                "f=tempfile.NamedTemporaryFile(dir=p.run_dir); "
                "f.write(sys.stdin.buffer.read(65537)); f.flush(); "
                "k.import_online_certificate(p,f.name,k.discover_roots(p)); f.close()")
            self.execute("python3", "-I", "-B", "-c", code, input=data)
        status = json.loads(self.execute("iris-instructions", "--status", capture=True))
        if not status.get("enabled") or status.get("signing_refused") or status.get("state") in ("error", "invalid"):
            self.journal.pause("WAITING_FOR_SIGNING_APPROVAL")
            print("Awaiting offline custodian approval. Public request: " + str(self.base / "requests/online.pub"))
            print("On the custody machine: irisctl approve-signing --public-key online.pub --root-key /offline/root-a")
            print("Then: irisctl resume --state-dir " + str(self.base) + " --certificate /path/online-cert.pub")
            return False
        # Never reinitialize an existing producer on resume; validate it instead.
        self.python("import instruction_stamper as s; p=s.StamperPaths.from_env(); "
                    "a=s.read_activation(p,required=False); "
                    "s.initialize_producer('initialize',paths=p) if a is None else s._validated_activation_epoch(p)")
        self.journal.checkpoint("signing", True)
        return True

    def packages(self):
        if "packages" not in self.journal.document["completed"]:
            self.command(["bash", self.source / "tools/get-ioxclient.sh", self.base / "bin"])
            for arch in ("arm64", "amd64"):
                self.command(["bash", self.source / "tools/stage-iox-package.sh", "--arch", arch,
                              "--artifacts-dir", self.base / "artifacts"])
            self.command(["bash", self.source / "tools/build-xr-package.sh", "--out", self.base / "artifacts"])
            self.journal.checkpoint("packages", {
                path.name: digest(path) for name in ("iris-amd64.tar", "iris-arm64.tar", "iris-xr.rpm")
                for path in (self.base / "artifacts" / name, self.base / "artifacts" / (name + ".manifest"))})
        for name, expected in self.journal.document["completed"]["packages"].items():
            if digest(self.base / "artifacts" / name) != expected:
                raise InstallError("Published package changed; refusing to report installation complete")
        from .cli import parser, diagnose
        args = parser().parse_args(["doctor", "--target", "docker", "--container", self.config["instance"] + "-server"])
        report = diagnose(args)
        if report["state"] != "checks-passed":
            raise InstallError("Runtime package verification failed; inspect irisctl doctor output")

    def finish(self):
        self.compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "180", "console")
        claimed = self.python("import gui_auth,secrets_store,os; print(bool(gui_auth.get_admin(secrets_store.load(os.environ['IRIS_SECRETS']))))").strip()
        if claimed not in (b"True", b"False"):
            raise InstallError("Cannot determine Console ownership; no account was changed")
        state = "OWNER_CLAIM_REQUIRED" if claimed == b"False" else "PRODUCTION_REVIEW_REQUIRED"
        self.journal.pause(state)
        print(state + ": https://" + self.config["console_bind"] + ":" + str(self.config["console_port"]) + "/")
        print("No administrator was created or logged in. Configure root attestations/keylist, certificate renewal and backups before production use.")
        return OWNER_CLAIM if claimed == b"False" else PRODUCTION_REVIEW

    def resume(self, certificate=None):
        self.verify_inputs()
        ubuntu.provision(self.command)
        self.verify_resource_ownership()
        self.command(["bash", self.source / "tools/check-host-time.sh"], timeout=30)
        self.prepare()
        self.build()
        self.bootstrap()
        if not self.signing(certificate):
            return WAITING_APPROVAL
        self.packages()
        return self.finish()


def snapshot(source, destination):
    """Copy only declared distribution inputs, never an operator's dirty tree."""
    source = Path(source).resolve()
    manifest_path = source / "INSTALLER-SOURCE.json"
    if not manifest_path.is_file():
        raise InstallError("Use the source payload shipped in the installer package (missing INSTALLER-SOURCE.json)")
    manifest = json.loads(regular_bytes(manifest_path, 8 * 1024 * 1024))
    if not isinstance(manifest, dict) or not manifest:
        raise InstallError("Invalid source inventory")
    destination.mkdir(mode=0o755)
    for name, expected in manifest.items():
        relative = Path(name)
        if (relative.is_absolute() or ".." in relative.parts or str(relative) != name
                or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise InstallError("Unsafe source inventory entry")
        path = source / relative
        if path.resolve() != path or not path.is_file() or digest(path) != expected:
            raise InstallError("Source inventory mismatch: " + name)
        output = destination / relative
        output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        shutil.copyfile(path, output)
        output.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
        if digest(output) != expected:
            raise InstallError("Source changed during snapshot")
    return manifest


def start(args):
    if os.geteuid() != 0:
        raise InstallError("Run the installer with sudo; dependency and service setup require root")
    ubuntu.check_platform()
    config = {name: getattr(args, name) for name in (
        "target", "instance", "host", "console_bind", "console_port", "recovery_recipient", "peer_tls")}
    validate_config(config)
    roots = read_roots(args.roots_dir)
    if not args.accept_changes:
        raise InstallError("Review the install options, then pass --accept-changes to permit dependencies, builds and new services")
    journal = Journal(args.state_dir)
    with journal.locked(create=True):
        if journal.document is not None:
            raise InstallError("An installation journal exists; use irisctl resume, not install")
        if any(p.name != "lock" for p in journal.directory.iterdir()):
            raise InstallError("State directory is not empty; refusing to adopt or overwrite it")
        ubuntu.provision(run)
        port_preflight(config)
        # Refuse adoption, even if an old project's containers are stopped.
        for kind in ("container", "volume", "network"):
            command = ["docker", kind, "ls", "-q"]
            if kind == "container":
                command.append("-a")
            matches = run([*command, "--filter", "label=com.docker.compose.project=" + config["instance"]], capture=True)
            if matches.strip():
                raise InstallError("Compose instance already has resources; adoption is not implemented")
        manifest = snapshot(args.source, journal.directory / "source")
        (journal.directory / "roots").mkdir(mode=0o755)
        for name, data in roots.items():
            atomic_write(journal.directory / "roots" / name, data, 0o644)
            run(["ssh-keygen", "-lf", str(journal.directory / "roots" / name)], capture=True)
        import uuid
        journal.document = {"schema": 1, "id": str(uuid.uuid4()), "config": config,
                            "source_manifest": manifest,
                            "root_digests": {name: hashlib.sha256(data).hexdigest() for name, data in roots.items()},
                            "completed": {}, "state": "INITIALIZED"}
        journal.save()
        return DockerInstall(journal).resume()


def resume(args):
    if os.geteuid() != 0:
        raise InstallError("Run resume with sudo")
    with Journal(args.state_dir).locked() as journal:
        if journal.document is None:
            raise InstallError("No installation journal exists")
        return DockerInstall(journal).resume(args.certificate)
