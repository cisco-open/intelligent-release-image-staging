#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Build the Ubuntu installer candidate from committed, allowlisted inputs.

No root/deployment keys are generated. No maintainer hooks start a deployment.
Artifacts are not official authenticated releases until signed by the approved
release authority. Outputs carry a committed source inventory for drift checks.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


ROOT_FILES = {"VERSION", "LICENSE", "NOTICE", ".dockerignore", ".gitignore",
              "README.md", "CHANGELOG.md", "requirements-dev.txt", "requirements-docs.txt",
              "zensical.toml", "CONTRIBUTING.md", "DEVELOPMENT.md", "TESTING.md",
              "SECURITY.md", "CODE_OF_CONDUCT.md"}
TREES = {"server", "device", "tools", "docs", "kubernetes", "bin", "deliverables"}
LAB_FILES = {"lab/device-run.sh", "lab/xr-run.sh", "lab/xr-dialogue.pl", "lab/iris-ssh-policy.sh"}


def selected(name):
    path = Path(name)
    return (name in ROOT_FILES or path.parts[0] in TREES or name in LAB_FILES
            or (path.parts[0] == "fleet" and (name.endswith(".example") or name == "fleet/README.md")))


def build(repo, output):
    repo = repo.resolve()
    commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    epoch = int(subprocess.check_output(["git", "-C", str(repo), "show", "-s", "--format=%ct", commit], text=True).strip())
    output.mkdir(parents=True, exist_ok=True)
    archive_bytes = subprocess.check_output(["git", "-C", str(repo), "archive", "--format=tar", commit])
    with tempfile.TemporaryDirectory(prefix=".iris-installer-build-", dir=output) as temporary:
        root = Path(temporary) / "package"
        lib = root / "usr/lib/iris-installer"
        source = lib / "source"
        source.mkdir(parents=True)
        inventory = {}
        with tarfile.open(fileobj=io.BytesIO(archive_bytes)) as archive:
            for member in archive:
                if member.isdir() or not selected(member.name):
                    continue
                path = Path(member.name)
                if not member.isfile() or path.is_absolute() or ".." in path.parts:
                    raise ValueError("Only regular, relative committed files may ship: " + member.name)
                data = archive.extractfile(member).read()
                target = source / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
                inventory[member.name] = hashlib.sha256(data).hexdigest()
        (source / "INSTALLER-SOURCE.json").write_text(json.dumps(inventory, sort_keys=True, indent=2) + "\n")
        shutil.copytree(source / "tools/iris_installer", lib / "iris_installer")
        shutil.copy2(source / "tools/irisctl", lib / "irisctl")
        binary = root / "usr/bin"
        binary.mkdir(parents=True)
        (binary / "irisctl").symlink_to("../lib/iris-installer/irisctl")
        version = (source / "VERSION").read_text().strip() + "+installer.0.g" + commit[:12]
        control = root / "DEBIAN"
        control.mkdir()
        (control / "control").write_text(
            "Package: iris-installer\nVersion: " + version + "\nArchitecture: amd64\n"
            "Maintainer: IRIS contributors\nSection: admin\nPriority: optional\n"
            "Depends: python3 (>= 3.12), ca-certificates, openssh-client\n"
            "Description: IRIS Ubuntu installer candidate\n"
            " Source-build deployment with managed Ubuntu dependencies and offline signing approval.\n"
            " Candidate: not yet a qualified all-topology production release.\n")
        doc = root / "usr/share/doc/iris-installer"
        doc.mkdir(parents=True)
        shutil.copy2(source / "LICENSE", doc / "copyright")
        shutil.copy2(source / "docs/dev/installer.md", doc / "README.md")
        artifact = output / ("iris-installer_" + version + "_amd64.deb")
        if artifact.exists():
            raise FileExistsError("Refusing to replace existing installer package")
        # Package permissions must not depend on the release builder's umask.
        for path in [root, *root.rglob("*")]:
            if not path.is_symlink():
                path.chmod(0o755 if path.is_dir() or path.stat().st_mode & 0o111 else 0o644)
                os.utime(path, (epoch, epoch))
        staged = Path(temporary) / "installer.deb"
        subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(root), str(staged)],
                       env=dict(os.environ, SOURCE_DATE_EPOCH=str(epoch)), check=True)
        os.link(staged, artifact)  # atomic exclusive publication; no overwrite race
        artifact.chmod(0o644)
        # A local integrity checksum is not a release signature or trust root.
        checksum = hashlib.sha256(artifact.read_bytes()).hexdigest()
        artifact.with_suffix(".deb.sha256").write_text(checksum + "  " + artifact.name + "\n")
        print("Built candidate from commit " + commit + ": " + str(artifact))
        print("Not an authenticated public release; release-authority signing remains required.")
        return artifact


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--out", type=Path, required=True)
    arguments = parser.parse_args()
    build(arguments.repo, arguments.out)
