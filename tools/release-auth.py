#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Assemble release inventories and verify the public GitHub release identity."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


REPOSITORY = "cisco-open/intelligent-release-image-staging"
WORKFLOW = REPOSITORY + "/.github/workflows/release.yml"
SOURCE_ASSET = "aria2c-2.5.6-p10-source.tar.gz"


def validate_tag(tag):
    if not re.fullmatch(r"v20\d{2}\.\d{2}\.\d{2}(?:\.\d+)?", tag):
        raise ValueError("Release tag must be vYYYY.MM.DD with an optional numeric micro version")
    return tag


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_command(artifact, tag, commit, bundle=None):
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
