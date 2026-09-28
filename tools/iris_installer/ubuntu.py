# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Ubuntu dependency provisioning, with no replacement of existing Docker."""

from pathlib import Path
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile

from .state import InstallError


TOOLS = {"age-keygen": "age", "git": "git", "curl": "curl", "openssl": "openssl",
         "ssh-keygen": "openssh-client", "file": "file", "skopeo": "skopeo",
         "rpmbuild": "rpm", "xz": "xz-utils"}

# Official immutable release and digest, checked against:
# https://dl.k8s.io/release/v1.36.4/bin/linux/amd64/kubectl.sha256
# Installation and supported client/server skew:
# https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/
# https://kubernetes.io/releases/version-skew-policy/
KUBECTL_VERSION = 'v1.36.4'
KUBECTL_SHA256 = '8b8f088da2dab964f853b38464033b1be15ede2839eca751482357c45abdd05a'
KUBECTL_DESTINATION = Path('/usr/local/bin/kubectl')
SYSTEM_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


def provision_kubernetes_client(run):
    """Preserve an installed client; add a verified client only when absent.

    This provisions no Kubernetes daemon, modifies no cluster, and never
    replaces a system-managed or operator-provided executable.
    """
    if shutil.which('kubectl', path=SYSTEM_PATH):
        return ('kubectl',)
    if shutil.which('k3s', path=SYSTEM_PATH):
        return ('k3s', 'kubectl')
    if os.geteuid() != 0:
        raise InstallError('Run Kubernetes client provisioning with sudo')
    check_platform()
    destination = KUBECTL_DESTINATION
    if destination.exists() or destination.is_symlink():
        raise InstallError('An existing kubectl path is not executable; inspect it without replacing it')
    for parent in (destination.parent, *destination.parent.parents):
        try:
            info = parent.lstat()
        except OSError:
            raise InstallError('Kubernetes client destination is unavailable; no executable was replaced') from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise InstallError('Kubernetes client destination requires root-owned, non-writable ancestors')
    # The private directory is on the destination filesystem so link() can
    # publish atomically with no-overwrite semantics even under a race.
    with tempfile.TemporaryDirectory(prefix='.iris-kubectl-', dir=destination.parent) as temporary:
        candidate = Path(temporary) / 'kubectl'
        url = 'https://dl.k8s.io/release/' + KUBECTL_VERSION + '/bin/linux/amd64/kubectl'
        run(['curl', '--fail', '--silent', '--show-error', '--location',
             '--proto', '=https', '--proto-redir', '=https', '--tlsv1.2',
             '--retry', '3', '--connect-timeout', '15', '--max-time', '300',
             '--max-filesize', str(128 * 1024 * 1024), '--output', str(candidate), url], timeout=1000)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            fd = os.open(candidate, flags)
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= 128 * 1024 * 1024:
                    raise InstallError('Downloaded Kubernetes client is not a bounded regular file')
                checksum = hashlib.sha256()
                for block in iter(lambda: stream.read(1024 * 1024), b''):
                    checksum.update(block)
                if checksum.hexdigest() != KUBECTL_SHA256:
                    raise InstallError('Official Kubernetes client checksum differs from the installer pin')
                os.fchmod(stream.fileno(), 0o755)
                os.fsync(stream.fileno())
            report = json.loads(run([str(candidate), 'version', '--client', '-o', 'json'], capture=True, timeout=30))
            if report.get('clientVersion', {}).get('gitVersion') != KUBECTL_VERSION:
                raise InstallError('Verified Kubernetes client reports an unexpected version')
            os.link(candidate, destination, follow_symlinks=False)
            descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except FileExistsError:
            raise InstallError('kubectl appeared during provisioning; no executable was replaced') from None
        except (OSError, ValueError, TypeError):
            raise InstallError('Kubernetes client provisioning did not complete; no existing executable was replaced') from None
    return ('kubectl',)


def validate_kubernetes_versions(report):
    """Fail before resource mutation outside Kubernetes' one-minor skew rule."""
    versions = []
    for side in ('clientVersion', 'serverVersion'):
        description = report.get(side) if isinstance(report, dict) else None
        value = description.get('gitVersion') if isinstance(description, dict) else None
        match = re.fullmatch(r'v([0-9]+)\.([0-9]+)\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?', value if isinstance(value, str) else '')
        if not match:
            raise InstallError('Cannot establish Kubernetes client and server versions')
        versions.append(tuple(map(int, match.groups())))
    if versions[0][0] != versions[1][0] or abs(versions[0][1] - versions[1][1]) > 1:
        raise InstallError('Kubernetes client must be within one minor version of the API server; preserve the existing client and select a supported installer/controller')


def check_platform():
    fields = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        key, separator, value = line.partition("=")
        if separator:
            fields[key] = value.strip('"')
    if fields.get("ID") != "ubuntu" or fields.get("VERSION_ID") != "24.04":
        raise InstallError("This installer candidate targets Ubuntu 24.04 only")
    if platform.machine() not in ("x86_64", "amd64"):
        raise InstallError("Server host must be amd64; ARM64 device packages are still included")


def command_ok(command):
    try:
        return subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                                   "DOCKER_HOST": "unix:///var/run/docker.sock"},
                              timeout=20, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def missing_packages():
    packages = {package for tool, package in TOOLS.items() if not shutil.which(tool)}
    if not shutil.which("docker"):
        packages.update(("docker.io", "docker-compose-v2", "docker-buildx"))
    else:
        for plugin, distro_package, ce_package in (
            ("compose", "docker-compose-v2", "docker-compose-plugin"),
            ("buildx", "docker-buildx", "docker-buildx-plugin"),
        ):
            if command_ok(["docker", plugin, "version"]):
                continue
            # Follow the installed engine's provider, never replace it as a
            # side effect of dependency resolution. apt --no-remove adds a
            # second guard against a solver-driven engine migration.
            if command_ok(["dpkg-query", "--status", "docker.io"]):
                packages.add(distro_package)
            elif command_ok(["dpkg-query", "--status", "docker-ce"]):
                packages.add(ce_package)
            else:
                raise InstallError("Cannot safely provision " + plugin + " for an unrecognized Docker installation")
    registration = Path("/proc/sys/fs/binfmt_misc/qemu-aarch64")
    if not registration.exists() or not registration.read_text().startswith("enabled\n"):
        packages.update(("qemu-user-static", "binfmt-support"))
    return sorted(packages)


def provision(run):
    check_platform()
    packages = missing_packages()
    if packages:
        print("Installing Ubuntu dependencies: " + ", ".join(packages), flush=True)
        run(["apt-get", "update"], timeout=900)
        # --no-remove prevents the solver from removing an existing runtime.
        run(["apt-get", "install", "--no-remove", "-y", *packages], timeout=1800)
    if not command_ok(["docker", "info"]):
        raise InstallError("Docker is unavailable; check its service before resuming")
    if not command_ok(["docker", "compose", "version"]) or not command_ok(["docker", "buildx", "version"]):
        raise InstallError("Docker Compose and Buildx must be available before deployment")
    registration = Path("/proc/sys/fs/binfmt_misc/qemu-aarch64")
    if not registration.exists() or not registration.read_text().startswith("enabled\n"):
        run(["update-binfmts", "--enable", "qemu-aarch64"], timeout=30)
        if not registration.exists() or not registration.read_text().startswith("enabled\n"):
            raise InstallError("Ubuntu ARM64 emulation registration failed; deployment was not started")
