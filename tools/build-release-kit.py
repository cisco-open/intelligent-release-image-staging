#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Inventory explicit prebuilt inputs; this neither builds nor signs a release.

Inputs are already-produced local archives. The prepared-host profile can add
an explicit Ubuntu dependency closure as the ubuntu-dependencies profile.
The release workflow must build them from its selected commit and
then authenticate every output using its normal release inventory/attestation.
"""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import tarfile
import tempfile

from iris_installer import release_kit as kit
from iris_installer.device_finalize import inspect_neutral
from iris_installer.offline_inputs import inspect_dependency_archive
from iris_installer.state import InstallError


NAMES = {
    "server-image": "iris-server-amd64.docker.tar",
    "console-image": "iris-console-amd64.docker.tar",
    "device-runtime": "iris-device-neutral.oci.tar",
    "guest-inputs": "iris-guest-inputs.tar.gz",
    "packaging-tools": "iris-packaging-tools.tar.gz",
    "source": "iris.tgz",
}
DEPENDENCY_NAME = "iris-ubuntu-dependencies.tar.gz"


def docker_config(path, commit):
    """Inspect one Docker-save image; bind raw or gzip layers to config diffIDs."""
    with tarfile.open(path, "r:", tarinfo=kit._BoundedTarInfo) as archive:
        members = {member.name.rstrip("/") if member.isdir() else member.name: member
                   for member in archive}

        def member(name, maximum=kit.MAX_METADATA):
            if not isinstance(name, str):
                raise InstallError("Docker archive member identity is invalid")
            item = members.get(name)
            if item is None or not item.isfile() or not 0 < item.size <= maximum:
                raise InstallError("Docker archive is missing a bounded regular member")
            return item

        def raw(name):
            return archive.extractfile(member(name)).read(kit.MAX_METADATA + 1)

        manifests = kit._json(raw("manifest.json"))
        if not isinstance(manifests, list) or len(manifests) != 1:
            raise InstallError("Each Docker archive must contain exactly one image")
        manifest = manifests[0]
        kit._keys(manifest, ("Config", "Layers", "RepoTags"))
        tags = manifest["RepoTags"]
        if tags is not None and (not isinstance(tags, list) or len(tags) > 128
                or any(not isinstance(tag, str) or len(tag) > 512
                       or any(ord(char) < 32 for char in tag) for tag in tags)):
            raise InstallError("Docker archive tags are invalid")
        config_bytes = raw(manifest["Config"])
        config = kit._json(config_bytes)
        if not isinstance(config, dict) or config.get("os") != "linux" or config.get("architecture") != "amd64":
            raise InstallError("Core image archives must contain linux/amd64 images")
        rootfs = config.get("rootfs")
        layers = manifest["Layers"]
        if (not isinstance(layers, list) or not 1 <= len(layers) <= 256
                or any(not isinstance(name, str) for name in layers)
                or manifest["Config"] in layers
                or not isinstance(rootfs, dict) or set(rootfs) != {"type", "diff_ids"}
                or rootfs["type"] != "layers" or not isinstance(rootfs["diff_ids"], list)
                or len(rootfs["diff_ids"]) != len(layers)):
            raise InstallError("Docker archive layers do not match its configuration")
        labels = config.get("config", {}).get("Labels", {}) if isinstance(config.get("config", {}), dict) else None
        if labels is not None and not isinstance(labels, dict):
            raise InstallError("Docker archive image labels are invalid")
        revision = (labels or {}).get("org.opencontainers.image.revision")
        if revision is not None and revision != commit:
            raise InstallError("Docker archive revision label identifies another source commit")
        inspected, expanded = {}, 0
        for name, expected in zip(layers, rootfs["diff_ids"]):
            kit._sha(expected, "sha256:")
            if name not in inspected:
                item = member(name, kit.MAX_ASSET)
                raw_digest = hashlib.sha256()
                stream = archive.extractfile(item)
                while data := stream.read(kit.CHUNK):
                    raw_digest.update(data)
                if re.fullmatch(r"blobs/sha256/[a-f0-9]{64}", name) and name.rsplit("/", 1)[1] != raw_digest.hexdigest():
                    raise InstallError("Docker archive blob differs from its content identity")
                stream = archive.extractfile(item)
                compressed = stream.read(2) == b"\x1f\x8b"
                stream.seek(0)
                content = gzip.GzipFile(fileobj=stream) if compressed else stream
                digest, size = hashlib.sha256(), 0
                try:
                    while data := content.read(kit.CHUNK):
                        size += len(data)
                        if size > kit.MAX_ASSET:
                            raise InstallError("Docker layer exceeds its expansion limit")
                        digest.update(data)
                except (OSError, EOFError):
                    raise InstallError("Docker layer compression is invalid") from None
                finally:
                    content.close()
                    stream.close()
                inspected[name] = ("sha256:" + digest.hexdigest(), size)
            actual, size = inspected[name]
            expanded += size
            if expanded > kit.MAX_ASSET:
                raise InstallError("Docker image exceeds its expansion limit")
            if actual != expected:
                raise InstallError("Docker archive layer differs from its configuration")
        return "sha256:" + hashlib.sha256(config_bytes).hexdigest()


def _parent_current(output, descriptor):
    current = output.lstat()
    held = os.fstat(descriptor)
    if (kit._path(output) != output or
            (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino)):
        raise InstallError("Release output directory changed; no further assets were published")


def neutral_provenance(path, archive_sha256, inspection):
    """Bind the builder's neutral source identity to the inspected exact bytes."""
    try:
        lines = path.read_bytes().decode("ascii").splitlines()
    except UnicodeError:
        raise InstallError("Neutral builder receipt must be ASCII metadata") from None
    records = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or key in records:
            raise InstallError("Neutral builder receipt has invalid or duplicate fields")
        records[key] = value
    kit._keys(records, ("format", "trust_mode", "source_sha256", "index_digest", "archive_sha256", "platforms"))
    if (records["format"] != "iris-device-neutral-oci-v1" or records["trust_mode"] != "neutral"
            or records["archive_sha256"] != archive_sha256
            or records["index_digest"] != inspection["index_digest"]
            or records["platforms"] != "linux/amd64,linux/arm64"):
        raise InstallError("Neutral builder receipt differs from the inspected runtime")
    return kit._sha(records["source_sha256"])


def assemble(inputs, output, *, tag, commit, neutral_receipt, ubuntu_dependencies=None):
    """Validate all payloads before exclusive publication; no payload is run."""
    auth = kit._auth()
    auth.validate_tag(tag)
    if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise InstallError("An exact source commit is required")
    if not isinstance(inputs, dict) or set(inputs) != kit.ROLES:
        raise InstallError("Supply exactly the six prepared-host release payloads")
    inputs = dict(inputs)
    names = dict(NAMES)
    profile = "prepared-host"
    if ubuntu_dependencies is not None:
        inputs["ubuntu-dependencies"] = ubuntu_dependencies
        names["ubuntu-dependencies"] = DEPENDENCY_NAME
        profile = "ubuntu-dependencies"
    output = kit._path(output)
    directory = kit._protected_directory(output)
    published = []
    try:
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise InstallError("Release output must be caller-owned and protected from other writers")
        for name in (*names.values(), "release-kit.json"):
            try:
                os.stat(name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise InstallError("Release producer never replaces an existing output")
        with tempfile.TemporaryDirectory(prefix="iris-kit-producer-", dir="/tmp") as temporary:
            work = Path(temporary)
            receipt = work / "neutral-builder.manifest"
            kit._snapshot(kit._path(neutral_receipt), receipt, 4096)
            records, inventory, total = {}, {}, 0
            for role in sorted(inputs):
                name = names[role]
                target = work / name
                checksum = kit._snapshot(kit._path(inputs[role]), target, kit.MAX_ASSET)
                size = target.stat().st_size
                total += size
                if total > kit.MAX_TOTAL:
                    raise InstallError("Release kit exceeds its total size limit")
                image = role in kit.IMAGES
                format = "oci-archive" if role == "device-runtime" else "docker-archive" if image else "tar.gz"
                fd, _ = kit._open(target, kit.MAX_ASSET)
                try:
                    kit._archive(fd, format)
                finally:
                    os.close(fd)
                record = {"name": name, "size": size, "sha256": checksum, "format": format}
                if role == "device-runtime":
                    inspected = inspect_neutral(target, expected_archive_sha256=checksum)
                    if (inspected.get("format") != "iris-device-neutral-inspection-v1"
                            or inspected.get("archive_sha256") != checksum
                            or set(inspected.get("platforms", {})) != {"amd64", "arm64"}):
                        raise InstallError("Neutral runtime inspection did not identify both supported platforms")
                    record.update(platforms=["linux/amd64", "linux/arm64"],
                                  image_digest=inspected["index_digest"],
                                  neutral_source_sha256=neutral_provenance(receipt, checksum, inspected))
                elif image:
                    record.update(platforms=["linux/amd64"], image_digest=docker_config(target, commit))
                elif role == "ubuntu-dependencies":
                    inspected = inspect_dependency_archive(target)
                    record["dependency_manifest_sha256"] = inspected["manifest_sha256"]
                records[role] = record
                inventory[name] = {"size": size, "sha256": checksum}
            manifest = {"schema": kit.SCHEMA, "repository": auth.REPOSITORY,
                        "workflow": auth.WORKFLOW, "tag": tag, "commit": commit,
                        "host": dict(kit.HOST), "profile": profile, "assets": records}
            # The consumer schema is the final authority; no producer-only role
            # or metadata alias can silently diverge from installation checks.
            kit._kit_manifest(manifest, auth, tag, commit, inventory)
            manifest_path = work / "release-kit.json"
            manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
            # Stage on the output filesystem through its held descriptor.
            # This also works when /tmp and the output live on different disks.
            with tempfile.TemporaryDirectory(prefix=".kit-publish-", dir=Path("/proc/self/fd") / str(directory)) as stage:
                staged = Path(stage)
                staging_fd = os.open(staged, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    for name in (*names.values(), "release-kit.json"):
                        checksum = kit._snapshot(work / name, staged / name, kit.MAX_ASSET)
                        if name in inventory and checksum != inventory[name]["sha256"]:
                            raise InstallError("Release input changed before publication")
                        with (staged / name).open("rb") as stream:
                            os.fchmod(stream.fileno(), 0o644)
                            os.fsync(stream.fileno())
                    # Manifest last: a partial directory has no complete kit.
                    # Failure cleanup removes only our exact owned inodes.
                    for name in (*names.values(), "release-kit.json"):
                        _parent_current(output, directory)
                        os.link(name, name, src_dir_fd=staging_fd, dst_dir_fd=directory,
                                follow_symlinks=False)
                        published.append((name, os.stat(name, dir_fd=staging_fd)))
                    os.fsync(directory)
                    _parent_current(output, directory)
                finally:
                    os.close(staging_fd)
            return manifest
    except BaseException:
        for name, expected in reversed(published):
            try:
                actual = os.stat(name, dir_fd=directory, follow_symlinks=False)
                if (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino):
                    os.unlink(name, dir_fd=directory)
            except FileNotFoundError:
                pass
        if published:
            os.fsync(directory)
        raise
    finally:
        os.close(directory)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--out", type=Path, required=True, help="Existing owned release-assets directory")
    parser.add_argument("--device-runtime-receipt", type=Path, required=True,
                        help="Exact neutral builder .manifest sidecar, not a rooted package receipt")
    parser.add_argument("--ubuntu-dependencies", type=Path,
                        help="Already-produced complete Ubuntu dependency archive; selects its authenticated profile")
    for role in sorted(kit.ROLES):
        parser.add_argument("--" + role, type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        assemble({role: getattr(args, role.replace("-", "_")) for role in kit.ROLES},
                 args.out, tag=args.tag, commit=args.commit, neutral_receipt=args.device_runtime_receipt,
                 ubuntu_dependencies=args.ubuntu_dependencies)
    except (InstallError, OSError, ValueError, tarfile.TarError, EOFError):
        parser.exit(1, "Release-kit preparation failed; existing assets were not replaced.\n")
    print("Prepared local, unauthenticated release-kit inputs. Authenticate all assets before distribution.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
