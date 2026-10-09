# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Resumable source-build installation on one Ubuntu Docker host.

Production roots are always supplied as public keys. This module never creates
offline private roots or an administrator, and never contacts inventory devices.
"""

from contextlib import ExitStack
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import stat
import subprocess
import tempfile

from . import ubuntu
from .state import InstallError, Journal, atomic_write, regular_bytes


WAITING_APPROVAL = 20
OWNER_CLAIM = 21
PRODUCTION_REVIEW = 22
BASE_CONFIG_KEYS = {"target", "instance", "host", "console_bind", "console_port", "recovery_recipient", "peer_tls"}
NATIVE_PACKAGES = ("iris-amd64.tar", "iris-arm64.tar", "iris-xr.rpm")
NATIVE_FILES = frozenset(name + suffix for name in NATIVE_PACKAGES for suffix in ("", ".manifest"))


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _native_hash(path):
    """Hash bounded immutable regular output without following links."""
    from . import device_finalize as f
    path = f._path(path)
    maximum = 65536 if path.name.endswith(".manifest") else f.MAX_ARCHIVE
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise InstallError("Native package must be a bounded nonempty regular file")
        actual, size = f._copy(stream, None, maximum)
        if size != before.st_size or f._fingerprint(before) != f._fingerprint(os.fstat(stream.fileno())):
            raise InstallError("Native package changed during verification")
    f._unchanged(path, before)
    return actual


def _finalized_package_hashes(directory, receipt, finalization_sha256):
    """Bind all six wrapper files to the selected finalized runtime."""
    hashes = {name: _native_hash(directory / name) for name in NATIVE_FILES}
    for name in NATIVE_PACKAGES:
        raw = regular_bytes(directory / (name + ".manifest"), 65536)
        if hashlib.sha256(raw).hexdigest() != hashes[name + ".manifest"]:
            raise InstallError("Native package provenance changed during verification")
        try:
            lines = raw.decode("ascii").splitlines()
            rows = [line.split("=", 1) for line in lines]
            values = dict(rows)
        except (UnicodeError, ValueError):
            raise InstallError("Native package provenance is invalid") from None
        expected = {"format": "iris-device-wrapper-v2", "wrapper_kind": "xr-appmgr" if name.endswith(".rpm") else "iox",
                    "wrapper_file": name, "wrapper_sha256": hashes[name],
                    "platform": "linux/arm64" if name == "iris-arm64.tar" else "linux/amd64",
                    "canonical_index_digest": receipt["index_digest"],
                    "canonical_archive_sha256": receipt["archive_sha256"],
                    "canonical_neutral_source_sha256": receipt["neutral_source_sha256"],
                    "canonical_finalization_sha256": finalization_sha256}
        if len(rows) != len(expected) or values != expected:
            raise InstallError("Native package provenance differs from the selected finalized runtime")
    return hashes


def _publish_prebuilt_packages(source, destination, hashes):
    """Finish an interrupted publication without replacing existing artifacts."""
    from . import device_finalize as f
    destination = f._path(destination)
    parent = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        held = os.fstat(parent)
        for name in sorted(NATIVE_FILES):
            path = destination / name
            if path.exists() or path.is_symlink():
                if _native_hash(path) != hashes[name]:
                    raise InstallError("An existing native artifact differs; preserve it before resuming")
                continue
            with tempfile.TemporaryDirectory(prefix=".iris-native-", dir=Path('/proc/self/fd') / str(parent)) as temporary:
                snapshot = Path(temporary) / name
                actual, _, _ = f._snapshot(source / name, snapshot, f.MAX_ARCHIVE)
                if actual != hashes[name]:
                    raise InstallError("Native package changed before publication")
                snapshot.chmod(0o444)
                with snapshot.open("rb") as stream:
                    os.fsync(stream.fileno())
                current = destination.lstat()
                if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                    raise InstallError("Native artifacts directory changed during publication")
                f._publish(parent, Path(temporary).name + "/" + name, name)
    finally:
        os.close(parent)


def clean_env():
    # Do not inherit stale Compose overrides, builder overrides, proxy auth or
    # an operator's SSH agent into privileged deployment/build commands.
    return {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8", "DEBIAN_FRONTEND": "noninteractive",
            "PYTHONDONTWRITEBYTECODE": "1",
            "DOCKER_HOST": "unix:///var/run/docker.sock"}


def run(command, *, env=None, input=None, timeout=7200, capture=False):
    label = Path(command[0]).name
    if label == "docker":
        actions = ("compose", "container", "volume", "network", "image", "build", "run", "up", "exec", "inspect", "ls", "config")
        label += " " + " ".join(part for part in command[1:] if part in actions)
    elif label == "bash" and len(command) > 1:
        label += " " + Path(command[1]).name
    print(">> " + label, flush=True)
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
        raise InstallError("Command failed: " + label + " (exit " + str(result.returncode) + "); state retained, no reset performed")
    return result.stdout if capture else b""


def validate_config(config):
    if isinstance(config, dict) and 'image_root' in config:
        from .image_storage import validate_name
        validate_name(config['image_root'])
        if config.get('target') not in ('docker', 'docker-split'):
            raise InstallError('Host image folders are supported by Docker; Kubernetes uses its persistent volume')
        config = {key: value for key, value in config.items() if key != 'image_root'}
    if isinstance(config, dict) and config.get('target') in ('docker-split', 'kubernetes'):
        if not BASE_CONFIG_KEYS.issubset(config):
            raise InstallError('Installation configuration is incomplete or invalid')
        validate_config(dict({name: config[name] for name in BASE_CONFIG_KEYS}, target='docker'))
        if config['target'] == 'docker-split':
            from .split_deploy import validate_split_config
            validate_split_config(config)
        else:
            from .kube_deploy import validate_kube_config
            validate_kube_config(config)
        return
    required = BASE_CONFIG_KEYS
    if (not isinstance(config, dict) or set(config) != required
            or type(config.get("console_port")) is not int
            or any(not isinstance(config.get(key), str) for key in required - {"console_port"})):
        raise InstallError("Installation configuration is incomplete or invalid")
    if config["target"] != "docker":
        raise InstallError("Unsupported deployment target; no changes made")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", config["instance"]):
        raise InstallError("Instance name must start with a letter and contain lowercase letters/digits/hyphens")
    for key in ("host", "console_bind"):
        try:
            address = ipaddress.IPv4Address(config[key])
        except ipaddress.AddressValueError as exc:
            raise InstallError(key + " must be a concrete IPv4 address") from exc
        if address.is_unspecified or address.is_multicast:
            raise InstallError(key + " must be a concrete unicast address")
        if key == "host" and (address.is_loopback or address.is_link_local or address.is_reserved):
            raise InstallError("Device-facing host must be a routable address, not loopback/link-local/reserved")
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


def check_tcp_endpoint(host, port):
    """Permit a service restart through TIME_WAIT, but never replace a listener."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            # Bind alone can succeed beside another reusable bound socket.
            # Probe the operation the new service actually needs as well.
            sock.listen(1)
        except OSError as exc:
            raise InstallError(f"Address unavailable or port occupied: {host}:{port}; nothing will be replaced") from exc


def port_preflight(config):
    endpoints = [(config["host"], port) for port in (6969, 8443, 8000, 6881, 9101)]
    endpoints.append((config["console_bind"], config["console_port"]))
    for host, port in endpoints:
        check_tcp_endpoint(host, port)


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

    def prebuilt(self):
        from .prebuilt_install import selected
        return selected(self.journal.document)

    def provision_host(self):
        if self.prebuilt():
            ubuntu.preflight_prebuilt(self.config['target'])
        else:
            ubuntu.provision(self.command)

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
        from .prebuilt_install import bind_source, validate_packaging_tool, verify_selected
        self._verified_kit = verify_selected(self.journal)
        if self._verified_kit is not None:
            bind_source(self._verified_kit, manifest, self.base)
            if 'prebuilt-package-generated' not in self.journal.document['completed']:
                validate_packaging_tool(self._verified_kit,
                                        self.journal.document.get('prebuilt_ioxclient'), self.base)

    def prepare(self):
        from .image_storage import image_root
        import_root = image_root(self)
        completed = self.journal.document["completed"]
        if "prepared" in completed:
            if digest(self.compose_file) != completed["prepared"]:
                raise InstallError("Generated Compose configuration changed")
            return
        for directory in ("build-home", "build-home/.docker", "cache", "bin", "requests", "images", "artifacts"):
            if (self.base / directory).resolve() != self.base / directory:
                raise InstallError("Public installer directories must not traverse symlinks")
            (self.base / directory).mkdir(mode=0o755, exist_ok=True)
            # Mounted public inputs must remain readable by the fixed
            # unprivileged container uid even with a private invoking umask.
            # Host-only build caches, state and secrets keep their private modes.
            if directory in ("images", "artifacts"):
                (self.base / directory).chmod(0o755)
        (self.base / 'control').mkdir(mode=0o750, exist_ok=True)
        if (self.base / 'control').is_symlink():
            raise InstallError("Lifecycle control directory must not be a symlink")
        (self.base / 'control').chmod(0o750)
        os.chown(self.base / 'control', 0, 10001)
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
            "IRIS_IMAGE_ROOT": str(import_root),
            "IRIS_ARTIFACTS_HOST_DIR": str(self.base / "artifacts"),
        }
        # Empty explicit env file prevents automatic discovery of server/.env.
        atomic_write(self.base / "compose.env", b"# managed by irisctl\n")
        data = self.runner(["docker", "compose", "--env-file", str(self.base / "compose.env"),
                            "-p", self.config["instance"], "-f", str(self.source / "server/docker-compose.yml"),
                            "config", "--format", "json"], env=dict(self.env, **settings), capture=True)
        compose = json.loads(data)
        compose["name"] = self.config["instance"]
        # A narrowly scoped Unix socket, NOT the Docker socket. The worker runs
        # on the host and continues while these two containers are stopped.
        compose['services']['iris']['volumes'].append({
            'type': 'bind', 'source': str(self.base / 'control'),
            'target': '/run/iris-lifecycle', 'read_only': True})
        for service, suffix in (("iris", "server"), ("console", "console")):
            spec = compose["services"][service]
            spec["container_name"] = self.config["instance"] + "-" + suffix
            spec.setdefault("environment", {}).update(
                IRIS_RUNTIME_LAYOUT=self.config["target"],
                IRIS_RUNTIME_NAME=spec["container_name"], IRIS_RUNTIME_HOST=self.config["host"])
            spec["image"] = "iris-installer/" + self.config["instance"] + "-" + suffix + ":" + self.journal.document["id"]
            if self.prebuilt():
                from .prebuilt_install import image_tag
                spec['image'] = image_tag(self, service)
                spec.pop('build', None)
                spec['pull_policy'] = 'never'
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
        if self.prebuilt():
            from .prebuilt_install import acquire_images
            acquire_images(self, json.loads(regular_bytes(self.compose_file))['services'])
            return
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
                     'set -eu; destination="$IRIS_CONFIG/instr/roots.d"; '
                     '[ ! -L "$destination" ]; '
                     'for existing in "$destination"/*.pub; do '
                     '[ -e "$existing" ] || continue; [ ! -L "$existing" ]; '
                     'cmp "$existing" "/pub/$(basename "$existing")" >/dev/null; done; '
                     'install -d -m 0755 "$destination" && '
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
            print("Setup is paused until a signing key holder approves the server's public key.")
            print("Public request file: " + str(self.base / "requests/online.pub"))
            print("On the key holder's machine, run iris-key-setup and choose Approve server request.")
            print("Then: irisctl resume --state-dir " + str(self.base) + " --certificate /path/online-cert.pub")
            return False
        # Never reinitialize an existing producer on resume; validate it instead.
        self.python("import instruction_stamper as s; p=s.StamperPaths.from_env(); "
                    "a=s.read_activation(p,required=False); "
                    "s.initialize_producer('initialize',paths=p) if a is None else s._validated_activation_epoch(p)")
        self.journal.checkpoint("signing", True)
        return True

    def acquire_packages(self):
        """Acquire local native wrappers; each topology retains runtime checks."""
        if self.prebuilt():
            return self._acquire_prebuilt_packages()
        if "packages" not in self.journal.document["completed"]:
            self.command(["bash", self.source / "tools/get-ioxclient.sh", self.base / "bin"])
            for arch in ("arm64", "amd64"):
                self.command(["bash", self.source / "tools/stage-iox-package.sh", "--arch", arch,
                              "--artifacts-dir", self.base / "artifacts"])
            self.command(["bash", self.source / "tools/build-xr-package.sh", "--out", self.base / "artifacts"])
            self.journal.checkpoint("packages", {
                path.name: digest(path) for name in ("iris-amd64.tar", "iris-arm64.tar", "iris-xr.rpm")
                for path in (self.base / "artifacts" / name, self.base / "artifacts" / (name + ".manifest"))})

    def _acquire_prebuilt_packages(self):
        from . import device_context as context, device_finalize as f
        from .prebuilt_device import prepare_runtime
        from .prebuilt_install import _kit
        tool = self.journal.document.get("prebuilt_ioxclient")
        if (not isinstance(tool, str) or not Path(tool).is_absolute()
                or any(ord(char) < 32 for char in tool)):
            raise InstallError("Prebuilt packaging requires the explicitly supplied local ioxclient path")
        from .packaging_inputs import prepare_packaging_inputs
        kit = _kit(self)
        completed = self.journal.document["completed"]
        artifacts = self.base / "artifacts"
        with ExitStack() as scope:
            inputs_fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            scope.callback(os.close, inputs_fd)
            temporary = scope.enter_context(tempfile.TemporaryDirectory(prefix="prebuilt-package-inputs-",
                dir=Path("/proc/self/fd") / str(inputs_fd)))
            scratch = Path(temporary).resolve()
            inputs = prepare_packaging_inputs(kit, scratch / "tools")
            if inputs.kit_receipt != kit.receipt():
                raise InstallError("Packaging inputs differ from the selected authenticated kit")
            runtime, finalization_sha256 = prepare_runtime(self)
            raw = regular_bytes(runtime / context.RECEIPT, f.MAX_JSON)
            if hashlib.sha256(raw).hexdigest() != finalization_sha256:
                raise InstallError("Finalized runtime receipt changed before packaging")
            receipt = context.validate_receipt(f._load(raw))
            intent = {"schema": 1, "kit": kit.receipt(), "finalization_sha256": finalization_sha256,
                      "appmgr_sha256": inputs.appmgr_sha256, "appmgr_revision": inputs.appmgr_revision,
                      "ioxclient_sha256": inputs.ioxclient_sha256}
            previous = completed.get("prebuilt-package-intent")
            if previous is not None and previous != intent:
                raise InstallError("Recorded native packaging inputs changed; preserve the journal")
            if previous is None:
                if ("packages" in completed or "prebuilt-package-generated" in completed
                        or any((artifacts / name).exists() or (artifacts / name).is_symlink() for name in NATIVE_FILES)):
                    raise InstallError("Unrecorded native artifacts exist; refusing to replace or adopt them")
                # Verify the licensed local program before recording build intent.
                local_tool = context.prepare_ioxclient(tool, scratch / "ioxclient", expected_sha256=inputs.ioxclient_sha256)
                self.journal.checkpoint("prebuilt-package-intent", intent)
            else:
                local_tool = None
            generated = completed.get("prebuilt-package-generated")
            if generated is None:
                if "packages" in completed:
                    raise InstallError("Recorded native package generation is missing; refusing to rebuild")
                if local_tool is None:
                    local_tool = context.prepare_ioxclient(tool, scratch / "ioxclient", expected_sha256=inputs.ioxclient_sha256)
                environment = dict(self.env, IOXCLIENT=str(local_tool))
                for key in ("IRIS_INSTRUCTION_ROOTS_DIR", "IOXCLIENT_HOME", "APPMGR_BUILD_CMD"):
                    environment.pop(key, None)
                def command(arguments):
                    return self.runner([str(item) for item in arguments], env=environment)
                # Pin generated bytes before serving them. An unrecorded
                # interrupted directory is never adopted: a later attempt
                # generates fresh bytes in a different private directory.
                base_fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                anchored_output, retain = None, False
                try:
                    held = os.fstat(base_fd)
                    anchored_output = Path(tempfile.mkdtemp(prefix="prebuilt-native-packages-",
                        dir=Path("/proc/self/fd") / str(base_fd)))
                    output = anchored_output.resolve()
                    finalized = ["--finalized-dir", runtime, "--finalization-sha256", finalization_sha256]
                    for arch in ("arm64", "amd64"):
                        command(["bash", self.source / "tools/stage-iox-package.sh", "--arch", arch,
                                 "--artifacts-dir", output, *finalized, "--ioxclient-sha256", inputs.ioxclient_sha256])
                    command(["bash", self.source / "tools/build-xr-package.sh", "--out", output, *finalized,
                             "--appmgr-archive", inputs.appmgr_archive, "--appmgr-sha256", inputs.appmgr_sha256,
                             "--appmgr-revision", inputs.appmgr_revision])
                    if set(path.name for path in output.iterdir()) != NATIVE_FILES:
                        raise InstallError("Generated native package directory contains unexpected files")
                    hashes = _finalized_package_hashes(output, receipt, finalization_sha256)
                    for path in output.iterdir():
                        path.chmod(0o444)
                        with path.open("rb") as stream:
                            os.fsync(stream.fileno())
                    _sync_directory(output)
                    os.fsync(base_fd)
                    current = self.base.lstat()
                    if (self.base.resolve() != self.base
                            or (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino)):
                        raise InstallError("Installation directory changed during native packaging")
                    generated = {"schema": 1, "directory": output.name, "hashes": hashes}
                    # A checkpoint can persist and then raise. Preserve its
                    # input directory in either case; only its journal record
                    # can authorize reuse on resume.
                    retain = True
                    self.journal.checkpoint("prebuilt-package-generated", generated)
                finally:
                    if anchored_output is not None and not retain:
                        shutil.rmtree(anchored_output)
                    os.close(base_fd)
            if (not isinstance(generated, dict) or set(generated) != {"schema", "directory", "hashes"}
                    or type(generated["schema"]) is not int or generated["schema"] != 1
                    or not isinstance(generated["directory"], str)
                    or not re.fullmatch(r"prebuilt-native-packages-[a-z0-9_]{8}", generated["directory"])
                    or not isinstance(generated["hashes"], dict) or set(generated["hashes"]) != NATIVE_FILES
                    or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                           for value in generated["hashes"].values())):
                raise InstallError("Recorded native package generation is invalid")
            cache = self.base / generated["directory"]
            if not cache.exists() and not cache.is_symlink():
                raise InstallError("Recorded native package cache is missing; refusing to rebuild")
            info = cache.lstat()
            if (cache.resolve() != cache or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700 or set(path.name for path in cache.iterdir()) != NATIVE_FILES):
                raise InstallError("Native package cache contains unexpected files or permissions")
            hashes = _finalized_package_hashes(cache, receipt, finalization_sha256)
            if generated["hashes"] != hashes:
                raise InstallError("Recorded native package cache changed; refusing to reuse it")
            if "packages" in completed:
                if completed["packages"] != hashes or _finalized_package_hashes(artifacts, receipt, finalization_sha256) != hashes:
                    raise InstallError("Published native package checkpoint changed")
                return
            _publish_prebuilt_packages(cache, artifacts, hashes)
            if _finalized_package_hashes(artifacts, receipt, finalization_sha256) != hashes:
                raise InstallError("Published native packages changed during verification")
            self.journal.checkpoint("packages", hashes)

    def packages(self):
        self.acquire_packages()
        for name, expected in self.journal.document["completed"]["packages"].items():
            if digest(self.base / "artifacts" / name) != expected:
                raise InstallError("Published package changed; refusing to report installation complete")
        from .cli import parser, diagnose
        args = parser().parse_args(["doctor", "--target", "docker", "--container", self.config["instance"] + "-server"])
        report = diagnose(args, env=self.env)
        if report["state"] != "checks-passed":
            raise InstallError("Runtime package verification failed; inspect irisctl doctor output")
        # Provision and verify Guest Shell under the same uid that serves it.
        # docker exec does not inherit startup-only supervisor environment, so
        # establish this attempt's success directly before checking its record.
        self.execute("/opt/iris/server/provision-served.sh")
        guest = json.loads(self.python(
            "import setup_status,os,json; "
            "print(json.dumps(setup_status.served_bundle_readiness("
            "os.environ.get('IRIS_ARTIFACTS_DIR','/srv/artifacts'),"
            "os.path.join(os.environ.get('IRIS_RUN','/run/iris'),'served-bundle.json'),"
            "startup_state='ok')))"))
        if guest.get("state") != "ok":
            raise InstallError("Guest Shell bundle verification failed; installation remains incomplete")
        self.journal.checkpoint("guestshell", guest)

    def finish(self):
        self.compose("up", "-d", "--no-build", "--wait", "--wait-timeout", "180", "console")
        public_certificate = self.execute("openssl", "x509", "-in", "/run/iris/tls/console-fallback.pem",
                                          "-outform", "PEM", capture=True)
        if not public_certificate.startswith(b"-----BEGIN CERTIFICATE-----"):
            raise InstallError("Console public certificate export failed")
        atomic_write(self.base / "requests/console-cert.pem", public_certificate, 0o644)
        print("Verify and trust the Console public certificate before sign-in: " + str(self.base / "requests/console-cert.pem"))
        claimed = self.python("import gui_auth,secrets_store,os; print(bool(gui_auth.get_admin(secrets_store.load(os.environ['IRIS_SECRETS']))))").strip()
        if claimed not in (b"True", b"False"):
            raise InstallError("Cannot determine Console ownership; no account was changed")
        state = "OWNER_CLAIM_REQUIRED" if claimed == b"False" else "PRODUCTION_REVIEW_REQUIRED"
        self.journal.pause(state)
        print(state + ": https://" + self.config["console_bind"] + ":" + str(self.config["console_port"]) + "/")
        print("No administrator was created or logged in. Configure root attestations/keylist, certificate renewal and backups before production use.")
        return OWNER_CLAIM if claimed == b"False" else PRODUCTION_REVIEW

    def resume(self, certificate=None):
        from .restore import assert_no_pending_restore
        assert_no_pending_restore(self.journal)
        operation = self.base / 'credential-operation.json'
        if operation.exists() or operation.is_symlink():
            command = 'sudo irisctl maintenance --state-dir ' + shlex.quote(str(self.base))
            recovery_hint = (
                f' Run `{command} status`, then select the recorded operation with '
                f'`{command} recover --job-id <operation-id> --allow-downtime`.')
            try:
                authority = json.loads(regular_bytes(operation))
            except (OSError, ValueError, InstallError):
                raise InstallError('Credential maintenance authority is unreadable; preserve the journal.' + recovery_hint) from None
            terminal = isinstance(authority, dict) and (
                authority.get('phase') == 'rotated' or (
                    authority.get('phase') == 'refused' and authority.get('mutations_admitted') is False))
            if (not terminal
                    or authority.get('instance_id') != self.journal.document['id']):
                raise InstallError('Recover the approved credential operation before resuming installation.' + recovery_hint)
        self.verify_inputs()
        self.provision_host()
        self.verify_resource_ownership()
        self.command(["bash", self.source / "tools/check-host-time.sh"], timeout=30)
        self.prepare()
        self.build()
        self.bootstrap()
        if not self.signing(certificate):
            return WAITING_APPROVAL
        self.packages()
        return self.finish()


def source_inventory(source):
    """Validate the declared distribution inventory before reserving inputs."""
    source = Path(source).resolve()
    manifest_path = source / "INSTALLER-SOURCE.json"
    if not manifest_path.is_file():
        raise InstallError("Use the source payload shipped in the installer package (missing INSTALLER-SOURCE.json)")
    manifest = json.loads(regular_bytes(manifest_path, 8 * 1024 * 1024))
    if not isinstance(manifest, dict) or not manifest:
        raise InstallError("Invalid source inventory")
    for name, expected in manifest.items():
        if not isinstance(name, str) or not isinstance(expected, str):
            raise InstallError("Unsafe source inventory entry")
        relative = Path(name)
        if (relative.is_absolute() or not relative.parts or ".." in relative.parts or str(relative) != name
                or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise InstallError("Unsafe source inventory entry")
    return manifest


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _public_directory(path):
    path = Path(path)
    if path.resolve() != path:
        raise InstallError("Installation inputs must not traverse symlinks")
    path.mkdir(mode=0o755, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
        raise InstallError("Installation input directory has changed ownership")
    path.chmod(0o755)
    _sync_directory(path)
    _sync_directory(path.parent)


def _input_buffer(path):
    """Open only the caller-owned scratch file reserved by initialization."""
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        os.close(fd)
        raise InstallError("Unsafe initialization buffer; preserve it for inspection")
    return os.fdopen(fd, 'r+b')


def _publish_input(source, output, expected, mode, buffer):
    """Verify before rename so an interrupted copy never leaves a partial input."""
    if output.exists() or output.is_symlink():
        if (output.resolve() != output or not output.is_file()
                or output.stat().st_uid != os.geteuid()
                or output.stat().st_nlink != 1 or digest(output) != expected):
            raise InstallError("Completed installation input changed; preserve it: " + str(output))
    else:
        with _input_buffer(buffer) as temporary:
            temporary.seek(0)
            temporary.truncate()
            shutil.copyfileobj(source, temporary)
            temporary.flush()
            if digest(buffer) != expected:
                raise InstallError("Source changed during snapshot")
            os.fsync(temporary.fileno())
        os.replace(buffer, output)
    output.chmod(mode)
    with output.open('rb') as published:
        os.fsync(published.fileno())
    for directory in {output.parent, Path(buffer).parent}:
        _sync_directory(directory)


def snapshot(source, destination, *, expected_manifest=None, buffer=None):
    """Copy verified inputs; a pinned initialization may resume complete files."""
    source = Path(source).resolve()
    destination = Path(destination).absolute()
    manifest = source_inventory(source)
    if expected_manifest is not None and manifest != expected_manifest:
        raise InstallError("Installer source inventory changed; use the original source package")
    if expected_manifest is None:
        destination.mkdir(mode=0o755)
    _public_directory(destination)
    expected_dirs = {str(parent) for name in manifest for parent in Path(name).parents}
    for path in destination.rglob('*'):
        name = str(path.relative_to(destination))
        if path.is_symlink() or (name not in manifest and not (path.is_dir() and name in expected_dirs)):
            raise InstallError("Unexpected snapshot input; preserve it: " + name)
    owned_buffer = buffer is None
    if owned_buffer:
        fd, buffer = tempfile.mkstemp(prefix='.snapshot-', dir=destination.parent)
        os.close(fd)
    try:
        for name, expected in manifest.items():
            relative = Path(name)
            path = source / relative
            if path.resolve() != path or not path.is_file() or digest(path) != expected:
                raise InstallError("Source inventory mismatch: " + name)
            output = destination / relative
            for parent in reversed(relative.parents):
                if str(parent) != '.':
                    _public_directory(destination / parent)
            mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            with path.open('rb') as data:
                _publish_input(data, output, expected, mode, buffer)
    finally:
        if owned_buffer and Path(buffer).exists():
            Path(buffer).unlink()
    return manifest


def complete_initialization(journal):
    """Resume only inputs explicitly reserved before the first snapshot write."""
    import io
    record = journal.document.get('initialization')
    if record is None:
        if journal.document.get('state') == 'INITIALIZING':
            raise InstallError('Initialization intent is missing; preserve the journal')
        return
    if (journal.document.get('state') != 'INITIALIZING' or journal.document['completed']
            or not isinstance(record, dict) or set(record) != {'source', 'public_roots'}
            or not isinstance(record['source'], str) or not Path(record['source']).is_absolute()
            or not isinstance(record['public_roots'], dict) or len(record['public_roots']) != 2
            or not isinstance(journal.document.get('source_manifest'), dict)
            or not journal.document['source_manifest']):
        raise InstallError('Invalid initialization intent; preserve the journal')
    roots = record['public_roots']
    if any(not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]+\.pub', name)
           or not isinstance(data, str) or not data.startswith('ssh-ed25519 ')
           for name, data in roots.items()):
        raise InstallError('Invalid public roots in initialization intent')
    try:
        root_bytes = {name: data.encode('ascii') for name, data in roots.items()}
    except UnicodeEncodeError:
        raise InstallError('Invalid public roots in initialization intent') from None
    expected_roots = {name: hashlib.sha256(data).hexdigest() for name, data in root_bytes.items()}
    if expected_roots != journal.document.get('root_digests'):
        raise InstallError('Initialization root fingerprints changed; preserve the journal')
    buffer = journal.directory / '.initial-input-buffer'
    snapshot(record['source'], journal.directory / 'source',
             expected_manifest=journal.document['source_manifest'], buffer=buffer)
    directory = journal.directory / 'roots'
    _public_directory(directory)
    if any(path.name not in roots for path in directory.iterdir()):
        raise InstallError('Unexpected roots input; preserve it for inspection')
    for name, data in root_bytes.items():
        _publish_input(io.BytesIO(data), directory / name, expected_roots[name], 0o644, buffer)
        run(['ssh-keygen', '-lf', str(directory / name)], capture=True)
    read_roots(directory)
    if buffer.exists() or buffer.is_symlink():
        with _input_buffer(buffer):
            pass
        buffer.unlink()
    journal.document.pop('initialization')
    journal.document['state'] = 'INITIALIZED'
    journal.save()


def installation(journal, runner=None):
    """Select only a recorded, validated deployment adapter; never infer context."""
    validate_config(journal.document['config'])
    target = journal.document['config']['target']
    if target == 'docker-split':
        from .split_deploy import SplitDockerInstall
        return SplitDockerInstall(journal, runner=runner or run)
    if target == 'kubernetes':
        from .kube_deploy import KubeInstall
        return KubeInstall(journal, runner=runner or run)
    return DockerInstall(journal) if runner is None else DockerInstall(journal, runner=runner)


def start(args):
    if os.geteuid() != 0:
        raise InstallError("Run the installer with sudo; dependency and service setup require root")
    ubuntu.check_platform()
    config = {name: getattr(args, name) for name in (
        "target", "instance", "host", "console_bind", "console_port", "recovery_recipient", "peer_tls")}
    if getattr(args, 'image_root', None) is not None:
        config['image_root'] = str(args.image_root)
    if args.target == 'docker-split':
        from .split_deploy import SPLIT_FIELDS
        config.update({name: getattr(args, name) for name in SPLIT_FIELDS})
        config['management_bind'] = config['management_bind'] or config['host']
        for name in ('console_ssh_key', 'console_known_hosts'):
            config[name] = str(config[name]) if config[name] is not None else ''
    elif args.target == 'kubernetes':
        from .kube_deploy import FIELDS
        config.update({name: getattr(args, name) for name in FIELDS})
        config['kubeconfig_path'] = str(config['kubeconfig_path']) if config['kubeconfig_path'] is not None else ''
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
        from .prebuilt_install import prepare_selection, selected
        manifest = source_inventory(args.source)
        inputs = prepare_selection(args, manifest, journal.directory)
        prebuilt = selected(inputs)
        if prebuilt:
            ubuntu.preflight_prebuilt(config['target'])
        else:
            ubuntu.provision(run)
        if config['target'] == 'docker-split':
            from .split_deploy import preflight
            preflight(config, runner=run)
        elif config['target'] == 'kubernetes':
            from .kube_deploy import preflight
            if not prebuilt:
                ubuntu.provision_kubernetes_client(run)
            preflight(config, runner=run)
        else:
            port_preflight(config)
        # Refuse adoption, even if an old project's containers are stopped.
        for kind in ("container", "volume", "network"):
            command = ["docker", kind, "ls", "-q"]
            if kind == "container":
                command.append("-a")
            matches = run([*command, "--filter", "label=com.docker.compose.project=" + config["instance"]], capture=True)
            if matches.strip():
                raise InstallError("Compose instance already has resources; adoption is not implemented")
        # Validate the captured public bytes, not a path that could change
        # between validation and recording the immutable initialization intent.
        for data in roots.values():
            run(['ssh-keygen', '-lf', '-'], input=data, capture=True)
        import uuid
        journal.document = {"schema": 1, "id": str(uuid.uuid4()), "config": config,
                            **inputs,
                            "source_manifest": manifest,
                            "root_digests": {name: hashlib.sha256(data).hexdigest() for name, data in roots.items()},
                            "completed": {}, "state": "INITIALIZING",
                            "initialization": {"source": str(Path(args.source).resolve()),
                                               "public_roots": {name: data.decode('ascii') for name, data in roots.items()}}}
        journal.save()
        complete_initialization(journal)
        return installation(journal).resume()


def resume(args):
    if os.geteuid() != 0:
        raise InstallError("Run resume with sudo")
    with Journal(args.state_dir).locked() as journal:
        if journal.document is None:
            raise InstallError("No installation journal exists")
        from .restore import assert_no_pending_restore
        assert_no_pending_restore(journal)
        validate_config(journal.document['config'])
        if journal.document.get('state') == 'INITIALIZING':
            from .prebuilt_install import bind_source, verify_selected
            kit = verify_selected(journal)
            if kit is not None:
                bind_source(kit, journal.document['source_manifest'], journal.directory)
        complete_initialization(journal)
        return installation(journal).resume(args.certificate)
