# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Snapshot authenticated finalized runtimes and local packaging tools.

Expected hashes come from the installer's protected journal or authenticated
tool inventory, never from an adjacent untrusted file. This helper neither
authenticates publishers nor executes payloads or downloads dependencies.
"""

import argparse
from contextlib import contextmanager
import gzip
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile

from . import device_finalize as f
from .state import InstallError

MAX_TOOL = 128 * 1024**2
MAX_APPMGR = 64 * 1024**2
RECEIPT = "iris-device.oci.tar.finalization.json"
APPMGR_SOURCE = "iris-appmgr-source.json"
APPMGR_REPOSITORY = "https://github.com/ios-xr/xr-appmgr-build.git"


def fail(message):
    raise InstallError("Device packaging input: " + message)


def _hash(value):
    return isinstance(value, str) and bool(f.HEX.fullmatch(value))


def _digest(value):
    return isinstance(value, str) and bool(f.DIGEST.fullmatch(value))


def validate_receipt(value):
    """Validate the exact v1 finalizer receipt; caller authenticates its bytes."""
    fields = {"format", "base_archive_sha256", "neutral_source_sha256",
              "base_index_digest", "finalizer_source_commit", "finalizer_module_sha256",
              "trust_renderer_sha256", "root_files_sha256", "trust_files_sha256",
              "archive_sha256", "archive_size", "index_digest", "platforms"}
    if (not isinstance(value, dict) or set(value) != fields
            or value["format"] != "iris-device-finalized-v1"
            or any(not _hash(value[key]) for key in ("base_archive_sha256", "neutral_source_sha256",
                   "finalizer_module_sha256", "trust_renderer_sha256", "archive_sha256"))
            or not _digest(value["base_index_digest"]) or not _digest(value["index_digest"])
            or not isinstance(value["finalizer_source_commit"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", value["finalizer_source_commit"])
            or type(value["archive_size"]) is not int
            or not 0 < value["archive_size"] <= f.MAX_ARCHIVE):
        fail("invalid finalization receipt")
    roots, trust = value["root_files_sha256"], value["trust_files_sha256"]
    if (not isinstance(roots, dict) or len(roots) != 2
            or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\.pub", name)
                   or not _hash(digest) for name, digest in roots.items())
            or not isinstance(trust, dict) or set(trust) != set(f.TRUST)
            or any(not _hash(digest) for digest in trust.values())):
        fail("invalid public-trust identities in finalization receipt")
    platforms = value["platforms"]
    if not isinstance(platforms, dict) or set(platforms) != {"amd64", "arm64"}:
        fail("both finalized architectures are required")
    platform_fields = {"base_manifest_digest", "manifest_digest", "config_digest", "layer_digest",
                       "diff_id", "runtime_inventory_sha256", "runtime_members"}
    for row in platforms.values():
        if (not isinstance(row, dict) or set(row) != platform_fields
                or any(not _digest(row[key]) for key in platform_fields - {"runtime_inventory_sha256", "runtime_members"})
                or not _hash(row["runtime_inventory_sha256"])
                or type(row["runtime_members"]) is not int
                or not 0 < row["runtime_members"] <= f.MAX_MEMBERS):
            fail("invalid finalized architecture inventory")
    return value


@contextmanager
def _publication(destination):
    """Use the same FD-anchored exclusive publication as the finalizer."""
    output = f._path(destination)
    if any(ord(char) < 32 for char in str(output)):
        fail("output path contains control characters")
    parent = f._path(output.parent)
    before = parent.lstat()
    if (not stat.S_ISDIR(before.st_mode) or before.st_uid != os.geteuid()
            or before.st_mode & 0o022):
        fail("output parent must be caller-owned and not group/world writable")
    if output.exists() or output.is_symlink():
        fail("output already exists")
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    stage, published = None, False
    try:
        held = os.fstat(fd)
        if (held.st_dev, held.st_ino) != (before.st_dev, before.st_ino):
            fail("output parent changed before staging")
        stage = Path(tempfile.mkdtemp(prefix=".iris-package-input-", dir=Path("/proc/self/fd") / str(fd)))
        yield stage, output
        for path in stage.rglob("*"):
            if path.is_file():
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
        for path in [*sorted((p for p in stage.rglob("*") if p.is_dir()), reverse=True), stage]:
            directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        current = parent.lstat()
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            fail("output parent changed during preparation")
        f._publish(fd, stage.name, output.name)
        published = True
    finally:
        if stage is not None and not published:
            shutil.rmtree(stage)
        os.close(fd)


def prepare(finalized_dir, output_dir, *, expected_finalization_sha256):
    if not _hash(expected_finalization_sha256):
        fail("authenticated finalization SHA256 is required")
    source = f._path(finalized_dir)
    before = source.lstat()
    if not stat.S_ISDIR(before.st_mode):
        fail("finalized input must be a directory")
    with _publication(output_dir) as (stage, output):
        digest, _, receipt_identity = f._snapshot(source / RECEIPT, stage / RECEIPT, f.MAX_JSON)
        if digest != expected_finalization_sha256:
            fail("receipt differs from authenticated finalization SHA256")
        receipt = validate_receipt(f._load_file(stage / RECEIPT))
        actual, size, archive_identity = f._snapshot(source / "iris-device.oci.tar", stage / "iris-device.oci.tar", f.MAX_ARCHIVE)
        if actual != receipt["archive_sha256"] or size != receipt["archive_size"]:
            fail("archive differs from authenticated finalization receipt")
        values = {"format": "iris-device-finalized-context-v1",
                  "index_digest": receipt["index_digest"], "archive_sha256": actual,
                  "neutral_source_sha256": receipt["neutral_source_sha256"],
                  "finalization_sha256": digest, "platforms": "linux/amd64,linux/arm64"}
        (stage / "iris-device-oci.manifest").write_text("".join(key + "=" + value + "\n" for key, value in values.items()))
        (stage / "iris-device-oci-path").write_text(str(output / "iris-device.oci.tar") + "\n")
        for path in stage.iterdir():
            path.chmod(0o444)
        for identity in (receipt_identity, archive_identity, (source, before)):
            f._unchanged(*identity)
    return receipt


def prepare_ioxclient(binary, output_dir, *, expected_sha256):
    if not _hash(expected_sha256):
        fail("authenticated ioxclient SHA256 is required")
    with _publication(output_dir) as (stage, output):
        digest, size, identity = f._snapshot(binary, stage / "ioxclient", MAX_TOOL)
        if digest != expected_sha256 or not size or not identity[1].st_mode & 0o111:
            fail("ioxclient differs from authenticated executable")
        (stage / "ioxclient").chmod(0o500)
        f._unchanged(*identity)
    return output / "ioxclient"


def prepare_appmgr(archive, output_dir, *, expected_sha256, expected_revision):
    if not _hash(expected_sha256):
        fail("authenticated appmgr archive SHA256 is required")
    if not isinstance(expected_revision, str) or not re.fullmatch(r"[0-9a-f]{40}", expected_revision):
        fail("authenticated full appmgr source revision is required")
    with tempfile.TemporaryDirectory(prefix="iris-appmgr-input-") as temporary:
        scratch = Path(temporary)
        packed, raw = scratch / "tool.tar.gz", scratch / "tool.tar"
        digest, _, identity = f._snapshot(archive, packed, MAX_APPMGR)
        if digest != expected_sha256:
            fail("appmgr archive differs from authenticated SHA256")
        with gzip.open(packed, "rb") as incoming, raw.open("xb") as outgoing:
            f._copy(incoming, outgoing, MAX_APPMGR)
        with tarfile.open(raw, "r:", tarinfo=f._TarInfo) as incoming:
            members = f._members(incoming)
            if len(members) > 4096:
                fail("appmgr member limit exceeded")
            source = members.get(APPMGR_SOURCE)
            if source is None or not source.isfile() or source.size > f.MAX_JSON:
                fail("appmgr archive lacks authenticated source metadata")
            metadata = f._load(incoming.extractfile(source).read(f.MAX_JSON + 1))
            if metadata != {"format": "iris-appmgr-source-v1",
                            "source_repository": APPMGR_REPOSITORY,
                            "source_revision": expected_revision}:
                fail("appmgr source metadata differs from authenticated revision")
            for required in ("appmgr_build", "build_rpm.sh"):
                member = members.get(required)
                if member is None or not member.isfile() or not member.mode & 0o111:
                    fail("appmgr archive lacks supported executable inputs")
            release = members.get("release_configs")
            if release is None or not release.isdir() or not any(name.startswith("release_configs/") and row.isfile() for name, row in members.items()):
                fail("appmgr archive lacks release configuration")
            if any(".git" in PurePosixPath(name).parts for name in members):
                fail("appmgr archive must omit repository metadata")
            with _publication(output_dir) as (stage, output):
                # _members permits no links/special files in this envelope.
                # Paths were validated before any directory or file is created.
                for name, member in sorted(members.items()):
                    target = stage / name
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    if member.isdir():
                        target.mkdir(exist_ok=True, mode=0o700)
                    else:
                        with target.open("xb") as outgoing:
                            f._copy(incoming.extractfile(member), outgoing, MAX_APPMGR)
                        target.chmod(0o500 if member.mode & 0o111 else 0o400)
                f._unchanged(*identity)
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--finalized-dir", type=Path)
    mode.add_argument("--ioxclient", type=Path)
    mode.add_argument("--appmgr-archive", type=Path)
    parser.add_argument("--finalization-sha256")
    parser.add_argument("--ioxclient-sha256")
    parser.add_argument("--appmgr-sha256")
    parser.add_argument("--appmgr-revision")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.finalized_dir is not None:
            if any(value is not None for value in (args.ioxclient_sha256, args.appmgr_sha256, args.appmgr_revision)):
                fail("unrelated tool hashes are not accepted in runtime mode")
            prepare(args.finalized_dir, args.output_dir, expected_finalization_sha256=args.finalization_sha256)
        elif args.ioxclient is not None:
            if any(value is not None for value in (args.finalization_sha256, args.appmgr_sha256, args.appmgr_revision)):
                fail("unrelated hashes are not accepted in ioxclient mode")
            prepare_ioxclient(args.ioxclient, args.output_dir, expected_sha256=args.ioxclient_sha256)
        else:
            if args.finalization_sha256 is not None or args.ioxclient_sha256 is not None:
                fail("unrelated hashes are not accepted in appmgr mode")
            prepare_appmgr(args.appmgr_archive, args.output_dir, expected_sha256=args.appmgr_sha256,
                           expected_revision=args.appmgr_revision)
    except InstallError as exc:
        parser.exit(1, str(exc) + "\n")
    except (OSError, tarfile.TarError, EOFError):
        parser.exit(1, "Device packaging input: archive or filesystem operation failed\n")
    return 0
