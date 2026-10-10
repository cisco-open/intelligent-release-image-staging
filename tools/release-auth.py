#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Assemble release inventories and verify the public GitHub release identity."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile


REPOSITORY = "cisco-open/intelligent-release-image-staging"
WORKFLOW = REPOSITORY + "/.github/workflows/release.yml"
SOURCE_ASSET = "aria2c-2.5.6-p11-source.tar.gz"
# These new binary products are local candidates until their complete source
# coverage and deployment qualification gates are connected to publication.
# A release attestation establishes provenance, not those missing checks.
PREBUILT_CANDIDATE_ASSETS = frozenset((
    "release-kit.json", "local-candidate.json", "iris-server-amd64.docker.tar",
    "iris-console-amd64.docker.tar", "iris-device-neutral.oci.tar",
    "iris-ubuntu-dependencies.tar.gz",
))


def validate_tag(tag):
    if not re.fullmatch(r"v20\d{2}\.\d{2}\.\d{2}(?:\.\d+)?", tag):
        raise ValueError("Release tag must be vYYYY.MM.DD with an optional numeric micro version")
    return tag


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _source_identity(path):
    """Inspect the held regular file; never follow an existing output symlink."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ValueError("Release source must be an available regular file") from None
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= 16 * 1024**3:
            raise ValueError("Release source must be a bounded regular file without aliases")
        checksum, size = hashlib.sha256(), 0
        while block := stream.read(1024 * 1024):
            size += len(block)
            if size > before.st_size:
                raise ValueError("Release source grew during inspection")
            checksum.update(block)
        after = os.fstat(stream.fileno())
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("Release source changed during inspection")
        return before.st_size, checksum.hexdigest()


def _copy_or_match_source(source, destination):
    """Preserve a kit producer's exact source asset; never silently replace it."""
    expected = _source_identity(source)
    if destination.exists() or destination.is_symlink():
        if _source_identity(destination) != expected:
            raise ValueError("Existing release source differs from the selected source archive")
        return
    with tempfile.TemporaryDirectory(prefix=".iris-source-", dir=destination.parent) as temporary:
        candidate = Path(temporary) / "iris.tgz"
        shutil.copyfile(source, candidate, follow_symlinks=False)
        if _source_identity(candidate) != expected:
            raise ValueError("Release source changed while being copied")
        with candidate.open("rb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.link(candidate, destination, follow_symlinks=False)


def verify_command(artifact, tag, commit, bundle=None, *, trusted_root=None):
    validate_tag(tag)
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Expected a full source commit SHA")
    command = ["gh", "attestation", "verify", str(artifact), "--repo", REPOSITORY,
               "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
               "--cert-identity", "https://github.com/" + WORKFLOW + "@refs/tags/" + tag,
               "--signer-workflow", WORKFLOW, "--source-ref", "refs/tags/" + tag,
               "--source-digest", commit, "--signer-digest", commit,
               "--deny-self-hosted-runners"]
    if bundle is not None:
        command.extend(["--bundle", str(bundle)])
    if trusted_root is not None:
        command.extend(["--custom-trusted-root", str(trusted_root)])
    return command


def prepare(repo, output, tag):
    """Require a committed tag and a verified corresponding-source asset."""
    validate_tag(tag)
    repo, output = repo.resolve(), output.resolve()
    if (repo / "VERSION").read_text().strip() != tag[1:]:
        raise ValueError("Release tag does not match VERSION")
    def git(*arguments):
        return subprocess.check_output(["git", "-C", str(repo), *arguments], text=True).strip()
    commit = git("rev-parse", "HEAD")
    if git("rev-parse", tag + "^{commit}") != commit:
        raise ValueError("Release tag does not identify the checked-out commit")
    if git("status", "--porcelain", "--untracked-files=no"):
        raise ValueError("Release inputs must have no tracked changes")
    if PREBUILT_CANDIDATE_ASSETS.intersection(path.name for path in output.iterdir()):
        raise ValueError("Prebuilt kit publication is not enabled: complete corresponding-source "
                         "coverage checks and deployment qualification before authenticating these candidates")
    source = output / SOURCE_ASSET
    expected = [line.split()[0] for line in (repo / "tools/aria2c-source/source.sha256").read_text().splitlines()
                if line and not line.startswith("#")]
    if len(expected) != 1 or digest(source) != expected[0]:
        raise ValueError("Corresponding aria2 source archive does not match the committed checksum")
    source.with_name(source.name + ".sha256").write_text(expected[0] + "  " + source.name + "\n")
    binary_pins = dict(line.split()[::-1] for line in (repo / "tools/aria2c.sha256").read_text().splitlines()
                       if line and not line.startswith("#"))
    binary_checksums = []
    for arch in ("x86_64", "aarch64"):
        name = "aria2c-" + arch
        binary = repo / "deliverables" / name
        if digest(binary) != binary_pins[arch]:
            raise ValueError("aria2 binary does not match the committed checksum: " + arch)
        shutil.copy2(binary, output / name)
        binary_checksums.append(binary_pins[arch] + "  " + name + "\n")
    (output / "aria2c.sha256").write_text("".join(binary_checksums))
    for name in ("iris.tgz", "iris.tgz.sha256", "MANIFEST.txt"):
        if name == "iris.tgz":
            _copy_or_match_source(repo / "release" / name, output / name)
        else:
            shutil.copy2(repo / "release" / name, output / name)
    packages = list(output.glob("iris-installer_*.deb"))
    if len(packages) != 1:
        raise ValueError("Expected exactly one Ubuntu installer package")
    inventory = packages[0].with_suffix(".deb.source.json")
    if not inventory.is_file():
        raise ValueError("Installer source inventory is missing")
    shutil.copy2(repo / "tools/release-auth.py", output / "release-auth.py")
    manifest = {"schema": 1, "repository": REPOSITORY, "workflow": WORKFLOW,
                "tag": tag, "commit": commit, "assets": {}}
    for path in sorted(output.iterdir()):
        if not path.is_file() or path.is_symlink():
            raise ValueError("Release output must contain regular files only")
        if path.name in ("SHA256SUMS", "release.json", "attestations.jsonl"):
            raise ValueError("Refusing to replace an existing release inventory")
        manifest["assets"][path.name] = {"sha256": digest(path), "size": path.stat().st_size}
    (output / "release.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    paths = sorted(output.iterdir())
    (output / "SHA256SUMS").write_text("".join(digest(path) + "  " + path.name + "\n" for path in paths))


def verify(directory, tag, commit):
    """Authenticate the inventory before using it, then authenticate every asset."""
    bundle = directory / "attestations.jsonl"
    manifest_path = directory / "release.json"
    subprocess.run(verify_command(manifest_path, tag, commit, bundle), check=True)
    manifest = json.loads(manifest_path.read_text())
    if (manifest.get("schema") != 1 or manifest.get("repository") != REPOSITORY
            or manifest.get("workflow") != WORKFLOW or manifest.get("tag") != tag
            or manifest.get("commit") != commit):
        raise ValueError("Authenticated inventory does not match the selected release")
    assets = manifest["assets"]
    if not isinstance(assets, dict) or not assets:
        raise ValueError("Authenticated inventory has no assets")
    for name, record in assets.items():
        if not isinstance(name, str) or Path(name).name != name or name in (".", ".."):
            raise ValueError("Unsafe release asset name")
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Missing or nonregular release asset: " + name)
        if path.stat().st_size != record["size"] or digest(path) != record["sha256"]:
            raise ValueError("Release asset checksum mismatch: " + name)
        subprocess.run(verify_command(path, tag, commit, bundle), check=True)
    subprocess.run(verify_command(directory / "SHA256SUMS", tag, commit, bundle), check=True)
    print("Authenticated release " + tag + " from " + commit)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    assembly = commands.add_parser("prepare")
    assembly.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    assembly.add_argument("--out", type=Path, required=True)
    assembly.add_argument("--tag", required=True)
    check = commands.add_parser("verify")
    check.add_argument("--directory", type=Path, required=True)
    check.add_argument("--tag", required=True)
    check.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args.repo, args.out, args.tag)
        else:
            verify(args.directory, args.tag, args.commit)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        print("Release verification/assembly failed: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
