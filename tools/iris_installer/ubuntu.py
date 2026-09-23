# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Ubuntu dependency provisioning, with no replacement of existing Docker."""

from pathlib import Path
import platform
import shutil
import subprocess

from .state import InstallError


TOOLS = {"age-keygen": "age", "git": "git", "curl": "curl", "openssl": "openssl",
         "ssh-keygen": "openssh-client", "file": "file", "skopeo": "skopeo",
         "rpmbuild": "rpm", "xz": "xz-utils"}


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
