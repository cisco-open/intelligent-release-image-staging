# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Finalize an authenticated neutral, two-platform OCI without executing it.

The caller authenticates the supplied archive/source digests before this API.
Only the two instruction trust files are added. This is not native IOx signing.
Existing finalized images are never accepted as neutral inputs, even for the
same roots. Installer resume must verify its prior output rather than rekey it.
"""

import argparse
import copy
import ctypes
import errno
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile

from .key_setup import instruction_module
from .state import InstallError

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
LAYER = "application/vnd.oci.image.layer.v1.tar"
TRUST = ("opt/iris/agent/iris-signers.allowed_signers",
         "opt/iris/agent/iris-root.allowed_signers")
MAX_ARCHIVE = 2 * 1024**3
MAX_LAYER = 1024**3
MAX_JSON = 4 * 1024**2
MAX_MEMBERS = 100000
CHUNK = 1024**2
HEX = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:([0-9a-f]{64})\Z")


def fail(message):
    raise InstallError("Device trust finalization: " + message)


def _json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode()


def _load(raw):
    if len(raw) > MAX_JSON:
        fail("JSON size limit exceeded")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail("duplicate JSON field")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: fail("non-finite JSON value"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InstallError("Device trust finalization: invalid JSON") from exc
    if not isinstance(value, dict):
        fail("expected a JSON object")
    return value


def _load_file(path):
    with path.open("rb") as stream:
        return _load(stream.read(MAX_JSON + 1))


def _fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _path(path):
    path = Path(path).absolute()
    if path.resolve() != path:
        fail("input and output paths must not traverse symbolic links")
    return path


def _copy(stream, output, limit):
    digest, size = hashlib.sha256(), 0
    while data := stream.read(CHUNK):
        size += len(data)
        if size > limit:
            fail("file size limit exceeded")
        digest.update(data)
        if output is not None:
            output.write(data)
    return digest.hexdigest(), size


def _snapshot(path, destination, limit):
    path = _path(path)
    before = path.lstat()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_size > limit
                or _fingerprint(info) != _fingerprint(before)):
            fail("expected a bounded unchanged regular input")
        with destination.open("xb") as output:
            digest, size = _copy(source, output, limit)
        if _fingerprint(os.fstat(source.fileno())) != _fingerprint(info):
            fail("input changed while being read")
    _unchanged(path, info)
    return digest, size, (path, info)


def _unchanged(path, info):
    if _path(path) != path or _fingerprint(path.lstat()) != _fingerprint(info):
        fail("input changed during finalization")


class _TarInfo(tarfile.TarInfo):
    """Bound extension headers before tarfile allocates their contents."""
    def _proc_member(self, archive):
        if self.type in (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME,
                         tarfile.GNUTYPE_LONGLINK):
            if not 0 <= self.size <= 16384 or getattr(archive, "_extension", False):
                fail("excessive or chained archive extension")
            archive._extension = True
            try:
                return super()._proc_member(archive)
            finally:
                archive._extension = False
        if self.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE,
                             tarfile.SYMTYPE, tarfile.LNKTYPE):
            fail("unsupported archive header type")
        return super()._proc_member(archive)

    def _proc_gnusparse_00(self, *args):
        fail("sparse archive entries are not supported")

    _proc_gnusparse_01 = _proc_gnusparse_00
    _proc_gnusparse_10 = _proc_gnusparse_00


def _name(value, *, directory=False):
    try:
        encoded = value.encode("utf-8") if isinstance(value, str) else b""
    except UnicodeError:
        fail("unsafe archive path encoding")
    if not encoded or len(encoded) > 4096:
        fail("unsafe archive path")
    value = value[:-1] if directory and value.endswith("/") else value
    name = PurePosixPath(value)
    if (name.is_absolute() or ".." in name.parts or str(name) != value
            or value == "." or "\\" in value or any(ord(c) < 32 for c in value)):
        fail("unsafe archive path")
    if name.name in ("package.sign", "package.cert"):
        fail("signed input is not supported")
    if any(part.startswith(".wh.") for part in name.parts):
        fail("whiteouts are not supported in a flattened runtime")
    return value


def _members(archive, *, layer=False):
    entries, expanded = {}, 0
    for member in archive:
        name = _name(member.name, directory=member.isdir())
        if name in entries or len(entries) >= MAX_MEMBERS:
            fail("duplicate path or archive member limit exceeded")
        if member.size < 0 or member.size > (MAX_LAYER if layer else MAX_ARCHIVE):
            fail("archive member size limit exceeded")
        if (not math.isfinite(member.mtime) or member.mode < 0 or member.mode > 0o7777
                or min(member.uid, member.gid) < 0
                or max(member.uid, member.gid) > 2**32 - 1):
            fail("invalid archive ownership or timestamp")
        expanded += member.size
        if expanded > (MAX_LAYER if layer else MAX_ARCHIVE):
            fail("expanded archive size limit exceeded")
        if any(key.startswith("GNU.sparse") for key in member.pax_headers):
            fail("sparse archive entries are not supported")
        if not layer and not (member.isfile() or member.isdir()):
            fail("OCI envelope must contain regular files and directories")
        if not member.isfile() and member.size:
            fail("non-file archive member has payload")
        entries[name] = member
    # Reject a hidden second archive or arbitrary trailing payload.
    archive.fileobj.seek(archive.offset)
    while tail := archive.fileobj.read(CHUNK):
        if tail.strip(b"\0"):
            fail("unexpected data after archive end")
    for name, member in entries.items():
        for parent in PurePosixPath(name).parents:
            prior = entries.get(str(parent))
            if prior is not None and not prior.isdir():
                fail("archive path traverses a non-directory")
        if member.issym():
            target = member.linkname
            if (not target or "\\" in target or len(target.encode()) > 4096
                    or any(ord(c) < 32 for c in target)):
                fail("unsafe runtime symbolic link")
            parts = [] if target.startswith("/") else list(PurePosixPath(name).parent.parts)
            for part in target.split("/"):
                if part in ("", "."):
                    continue
                if part == "..":
                    if not parts:
                        fail("runtime symbolic link escapes container root")
                    parts.pop()
                else:
                    parts.append(part)
        if member.islnk():
            target = _name(member.linkname)
            if target not in entries or not entries[target].isfile():
                fail("hard link must identify a regular runtime member")
    return entries


def _annotations(value):
    annotations = value.get("annotations", {})
    if (not isinstance(annotations, dict)
            or any(not isinstance(key, str) or not isinstance(item, str)
                   for key, item in annotations.items())):
        fail("invalid OCI annotations")
    if any(re.search(r"signat|cosign|attestation", key, re.I) for key in annotations):
        fail("signed or attested input references are not supported")


def _descriptor(value, media):
    if (not isinstance(value, dict)
            or set(value) - {"mediaType", "digest", "size", "platform", "annotations"}
            or value.get("mediaType") not in media
            or not isinstance(value.get("digest"), str)
            or not DIGEST.fullmatch(value["digest"])
            or type(value.get("size")) is not int or not 0 < value["size"] <= MAX_ARCHIVE):
        fail("unsupported OCI descriptor")
    _annotations(value)
    return value["digest"].split(":")[1]


def _object(value, kind, fields):
    if (type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 2
            or value.get("mediaType", kind) != kind
            or set(value) - fields - {"schemaVersion", "mediaType", "annotations"}):
        fail("unsupported OCI object or signed artifact")
    _annotations(value)


def _record(member, content_hash=None):
    return {"path": member.name, "type": member.type.decode("ascii"),
            "mode": member.mode, "uid": member.uid, "gid": member.gid,
            "uname": member.uname, "gname": member.gname, "mtime": member.mtime,
            "size": member.size, "link": member.linkname,
            "pax": member.pax_headers, "sha256": content_hash}


def _layer(source, destination, compressed, rendered, scratch):
    raw = scratch / (destination.name + ".raw")
    with source.open("rb") as incoming, raw.open("xb") as output:
        if compressed:
            with gzip.GzipFile(fileobj=incoming, mode="rb") as expanded:
                original_diff, _ = _copy(expanded, output, MAX_LAYER)
        else:
            original_diff, _ = _copy(incoming, output, MAX_LAYER)
    rewritten = scratch / (destination.name + ".new")
    inventory = []
    with tarfile.open(raw, "r:", tarinfo=_TarInfo) as archive:
        members = _members(archive, layer=True)
        if any(name in members for name in TRUST):
            fail("neutral runtime already contains active trust files")
        for name in TRUST:
            for parent in PurePosixPath(name).parents:
                if str(parent) == ".":
                    continue
                entry = members.get(str(parent))
                if entry is None or not entry.isdir():
                    fail("trust-file ancestors must be explicit real directories")
        with tarfile.open(rewritten, "w", format=tarfile.PAX_FORMAT) as outgoing:
            # Keep native tar ordering: a hard link may require its regular
            # target to have been extracted already. Sorting can break a valid
            # flattened runtime even when every file's bytes stay unchanged.
            for name in members:
                member = members[name]
                content_hash = None
                if member.isfile():
                    content_hash, _ = _copy(archive.extractfile(member), None, MAX_LAYER)
                inventory.append(_record(member, content_hash))
                outgoing.addfile(copy.copy(member), archive.extractfile(member) if member.isfile() else None)
            for name in TRUST:
                member = tarfile.TarInfo(name)
                member.mode, member.uid, member.gid, member.mtime = 0o444, 0, 0, 0
                member.size = len(rendered[name])
                outgoing.addfile(member, io.BytesIO(rendered[name]))
    with rewritten.open("rb") as stream:
        diff, _ = _copy(stream, None, MAX_LAYER)
    with rewritten.open("rb") as stream, destination.open("xb") as output:
        if compressed:
            with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0, compresslevel=9) as packed:
                _copy(stream, packed, MAX_LAYER)
        else:
            _copy(stream, output, MAX_LAYER)
    inventory.sort(key=lambda row: row["path"])
    return original_diff, diff, hashlib.sha256(_json(inventory)).hexdigest(), len(inventory)


def _blob(path):
    with path.open("rb") as stream:
        digest, size = _copy(stream, None, MAX_ARCHIVE)
    return digest, size


def _roots(directory, scratch):
    directory = _path(directory)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode):
        fail("public roots must be a directory")
    names = sorted(entry.name for entry in directory.iterdir())
    if len(names) != 2 or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\.pub", name) for name in names):
        fail("exactly two named public root files are required")
    snapshots, original = [], {}
    staging = scratch / "public-roots"
    staging.mkdir(mode=0o700)
    for name in names:
        digest, _, identity = _snapshot(directory / name, staging / name, 4096)
        snapshots.append(identity)
        original[name] = digest
    module = instruction_module()
    rendered_dir = scratch / "rendered"
    rendered_dir.mkdir(mode=0o700)
    try:
        module.render_device_trust(staging, rendered_dir)
    except module.InstructionKeyError as exc:
        raise InstallError("Device trust finalization: invalid public instruction roots") from exc
    rendered = {name: (rendered_dir / PurePosixPath(name).name).read_bytes() for name in TRUST}
    return rendered, original, snapshots + [(directory, info)], module


def _rewrite(archive_path, destination, scratch, rendered):
    output_blobs, used, platforms = {}, set(), {}
    with tarfile.open(archive_path, "r:", tarinfo=_TarInfo) as archive:
        members = _members(archive)
        allowed_dirs = {"blobs", "blobs/sha256"}
        for name, member in members.items():
            if member.isdir():
                if name not in allowed_dirs:
                    fail("unknown OCI directory")
            elif name not in ("oci-layout", "index.json") and not re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name):
                fail("unknown OCI member or signed input")
        def raw(name, limit=MAX_JSON):
            member = members.get(name)
            if member is None or not member.isfile() or member.size > limit:
                fail("missing or oversized OCI member")
            return archive.extractfile(member).read(limit + 1)
        if _load(raw("oci-layout")) != {"imageLayoutVersion": "1.0.0"}:
            fail("unsupported OCI layout version")
        def read_blob(descriptor, media):
            digest = _descriptor(descriptor, media)
            name = "blobs/sha256/" + digest
            member = members.get(name)
            if member is None or not member.isfile() or member.size != descriptor["size"]:
                fail("OCI blob size mismatch")
            path = scratch / digest
            if name not in used:
                with path.open("xb") as target:
                    actual, _ = _copy(archive.extractfile(member), target, MAX_ARCHIVE)
                if actual != digest:
                    fail("OCI blob digest mismatch")
                used.add(name)
            return path
        def add_blob(data, media, old=None):
            if isinstance(data, bytes):
                digest, size = hashlib.sha256(data).hexdigest(), len(data)
            else:
                digest, size = _blob(data)
            output_blobs["blobs/sha256/" + digest] = data
            result = copy.deepcopy(old) if old else {"mediaType": media}
            result.update(digest="sha256:" + digest, size=size)
            return result
        root = _load(raw("index.json"))
        _object(root, INDEX, {"manifests"})
        descriptors = root.get("manifests")
        nested = isinstance(descriptors, list) and len(descriptors) == 1 and isinstance(descriptors[0], dict) and descriptors[0].get("mediaType") == INDEX
        index = _load_file(read_blob(descriptors[0], {INDEX})) if nested else root
        _object(index, INDEX, {"manifests"})
        descriptors = index.get("manifests")
        if not isinstance(descriptors, list) or len(descriptors) != 2:
            fail("exactly amd64 and arm64 image manifests are required")
        old_index_digest = "sha256:" + hashlib.sha256(_json(index)).hexdigest()
        if nested:
            old_index_digest = root["manifests"][0]["digest"]
        else:
            old_index_digest = "sha256:" + hashlib.sha256(raw("index.json")).hexdigest()
        final_descriptors = []
        for descriptor in descriptors:
            manifest_path = read_blob(descriptor, {MANIFEST})
            platform = descriptor.get("platform")
            if (not isinstance(platform, dict) or platform.get("os") != "linux"
                    or platform.get("architecture") not in ("amd64", "arm64")
                    or set(platform) - {"os", "architecture", "variant"}
                    or ("variant" in platform and (platform["architecture"] != "arm64" or platform["variant"] != "v8"))):
                fail("unsupported OCI platform")
            arch = platform["architecture"]
            if arch in platforms:
                fail("duplicate OCI platform")
            manifest = _load_file(manifest_path)
            _object(manifest, MANIFEST, {"config", "layers"})
            config_path = read_blob(manifest.get("config"), {CONFIG})
            config = _load_file(config_path)
            layers = manifest.get("layers")
            rootfs = config.get("rootfs")
            if (not isinstance(layers, list) or len(layers) != 1
                    or config.get("os") != "linux" or config.get("architecture") != arch
                    or not isinstance(rootfs, dict) or set(rootfs) != {"type", "diff_ids"}
                    or rootfs.get("type") != "layers" or not isinstance(rootfs.get("diff_ids"), list)
                    or len(rootfs["diff_ids"]) != 1):
                fail("runtime must contain exactly one matching CAF layer")
            layer_path = read_blob(layers[0], {LAYER, LAYER + "+gzip"})
            updated_layer = scratch / (arch + ".layer")
            before, after, inventory, count = _layer(layer_path, updated_layer,
                layers[0]["mediaType"].endswith("+gzip"), rendered, scratch)
            if rootfs["diff_ids"] != ["sha256:" + before]:
                fail("uncompressed layer digest mismatch")
            config["rootfs"]["diff_ids"] = ["sha256:" + after]
            manifest["config"] = add_blob(_json(config), CONFIG, manifest["config"])
            manifest["layers"] = [add_blob(updated_layer, layers[0]["mediaType"], layers[0])]
            final_descriptor = add_blob(_json(manifest), MANIFEST, descriptor)
            final_descriptors.append(final_descriptor)
            platforms[arch] = {"base_manifest_digest": descriptor["digest"],
                "manifest_digest": final_descriptor["digest"],
                "config_digest": manifest["config"]["digest"],
                "layer_digest": manifest["layers"][0]["digest"],
                "diff_id": "sha256:" + after,
                "runtime_inventory_sha256": inventory, "runtime_members": count}
        if set(platforms) != {"amd64", "arm64"}:
            fail("both supported architectures are required")
        if used != {name for name, member in members.items() if member.isfile() and name.startswith("blobs/")}:
            fail("unreferenced OCI blobs or signature artifacts are not supported")
        index["manifests"] = sorted(final_descriptors, key=lambda item: item["platform"]["architecture"])
        index_bytes = _json(index)
        final_index = "sha256:" + hashlib.sha256(index_bytes).hexdigest()
        if nested:
            root["manifests"] = [add_blob(index_bytes, INDEX, root["manifests"][0])]
            root_bytes = _json(root)
        else:
            root_bytes = index_bytes
        content = dict(output_blobs, **{"oci-layout": _json({"imageLayoutVersion": "1.0.0"}), "index.json": root_bytes})
        with tarfile.open(destination, "w", format=tarfile.PAX_FORMAT) as result:
            for name in sorted(content):
                value = content[name]
                member = tarfile.TarInfo(name)
                member.mode, member.uid, member.gid, member.mtime = 0o444, 0, 0, 0
                member.size = len(value) if isinstance(value, bytes) else value.stat().st_size
                if isinstance(value, bytes):
                    result.addfile(member, io.BytesIO(value))
                else:
                    with value.open("rb") as stream:
                        result.addfile(member, stream)
    return old_index_digest, final_index, platforms


def _publish(parent_fd, stage_name, output_name):
    # Linux is the supported installer host. Never fall back to rename(), which
    # can replace a concurrently created empty directory belonging to the caller.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        fail("host lacks exclusive directory publication")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(stage_name), parent_fd, os.fsencode(output_name), 1):
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            fail("output already exists; verify or choose a new destination")
        raise OSError(code, os.strerror(code))
    os.fsync(parent_fd)


def finalize(input_oci, roots_dir, output_dir, *, expected_archive_sha256,
             neutral_source_sha256, finalizer_source_commit):
    """Return provenance after exclusive all-or-nothing directory publication.

    Expected archive/source identity and finalizer commit come from the caller's
    authenticated kit. This function verifies bytes, not publisher authority.
    """
    if (not isinstance(expected_archive_sha256, str) or not HEX.fullmatch(expected_archive_sha256)
            or not isinstance(neutral_source_sha256, str) or not HEX.fullmatch(neutral_source_sha256)
            or not isinstance(finalizer_source_commit, str)
            or not re.fullmatch(r"[0-9a-f]{40}", finalizer_source_commit)):
        fail("authenticated archive/source/finalizer identities are required")
    output = _path(output_dir)
    parent = _path(output.parent)
    if output.exists() or output.is_symlink():
        fail("output already exists; verify or choose a new destination")
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        fail("output parent must be caller-owned and not group/world writable")
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    held_parent = os.fstat(parent_fd)
    if (held_parent.st_dev, held_parent.st_ino) != (info.st_dev, info.st_ino):
        os.close(parent_fd)
        fail("output parent changed before staging")
    # Anchor our temporary objects and cleanup to the opened directory rather
    # than a path which another operation could rename or replace mid-work.
    anchored = Path("/proc/self/fd") / str(parent_fd)
    scratch = staging = None
    published = False
    try:
        scratch = Path(tempfile.mkdtemp(prefix=".iris-finalize-", dir=anchored))
        staging = Path(tempfile.mkdtemp(prefix=".iris-finalized-", dir=anchored))
        snapshot = scratch / "input.oci.tar"
        digest, _, identity = _snapshot(input_oci, snapshot, MAX_ARCHIVE)
        if digest != expected_archive_sha256:
            fail("archive differs from authenticated digest")
        rendered, roots, snapshots, module = _roots(roots_dir, scratch)
        archive = staging / "iris-device.oci.tar"
        old_index, index, platforms = _rewrite(snapshot, archive, scratch, rendered)
        archive_digest, archive_size = _blob(archive)
        receipt = {"format": "iris-device-finalized-v1", "base_archive_sha256": digest,
            "neutral_source_sha256": neutral_source_sha256, "base_index_digest": old_index,
            "finalizer_source_commit": finalizer_source_commit,
            "finalizer_module_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "trust_renderer_sha256": hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest(),
            "root_files_sha256": roots,
            "trust_files_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in rendered.items()},
            "archive_sha256": archive_digest, "archive_size": archive_size,
            "index_digest": index, "platforms": platforms}
        (staging / "iris-device.oci.tar.finalization.json").write_bytes(_json(receipt))
        for path in staging.iterdir():
            path.chmod(0o444)
            with path.open("rb") as stream:
                os.fsync(stream.fileno())
        directory_fd = os.open(staging, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        for path, before in [identity, *snapshots]:
            _unchanged(path, before)
        current_parent = parent.lstat()
        if ((current_parent.st_dev, current_parent.st_ino) != (info.st_dev, info.st_ino)
                or (os.fstat(parent_fd).st_dev, os.fstat(parent_fd).st_ino) != (info.st_dev, info.st_ino)):
            fail("output parent changed during finalization")
        _publish(parent_fd, staging.name, output.name)
        published = True
        return receipt
    except (tarfile.TarError, EOFError, gzip.BadGzipFile, OSError) as exc:
        raise InstallError("Device trust finalization: archive or filesystem operation failed") from exc
    finally:
        try:
            if scratch is not None and scratch.exists():
                shutil.rmtree(scratch)
            if not published and staging is not None and staging.exists():
                shutil.rmtree(staging)
        finally:
            os.close(parent_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--instruction-roots-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--expected-archive-sha256", required=True)
    parser.add_argument("--neutral-source-sha256", required=True)
    parser.add_argument("--finalizer-source-commit", required=True)
    args = parser.parse_args(argv)
    try:
        result = finalize(args.input, args.instruction_roots_dir, args.output_dir,
            expected_archive_sha256=args.expected_archive_sha256,
            neutral_source_sha256=args.neutral_source_sha256,
            finalizer_source_commit=args.finalizer_source_commit)
    except InstallError as exc:
        parser.exit(1, str(exc) + "\n")
    except OSError:
        parser.exit(1, "Device trust finalization: input or output path is unavailable\n")
    print(json.dumps({key: result[key] for key in ("format", "archive_sha256", "index_digest")}, sort_keys=True))
    return 0
