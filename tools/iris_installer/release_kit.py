# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Authenticate prebuilt inputs; never install, extract, execute or grant custody.

The initial prepared-host profile does not include a host dependency closure.
The caller supplies its independently trusted verifier and optional trust root;
neither may be selected by the kit. Consumers must use copy_asset(), not a path
from the download directory, and independently check imported image identities.
"""

from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile
import time

from .state import InstallError

SCHEMA = "iris-release-kit-v1"
SELECTION_SCHEMA = "iris-install-input-v1"
MAX_METADATA = 8 * 1024 * 1024
MAX_BUNDLE = 32 * 1024 * 1024
MAX_ASSETS = 128
MAX_ASSET = 16 * 1024 ** 3
MAX_TOTAL = 64 * 1024 ** 3
CHUNK = 1024 * 1024
ROLES = frozenset(("server-image", "console-image", "device-runtime", "guest-inputs", "packaging-tools", "source"))
IMAGES = frozenset(("server-image", "console-image", "device-runtime"))
HOST = {"os": "ubuntu", "version": "24.04", "architecture": "amd64"}


def _auth():
    # Import the installer's own helper, never release-auth.py from the kit.
    base = Path(__file__).resolve().parents[1]
    path = base / "source/tools/release-auth.py"
    if not path.is_file():
        path = base / "release-auth.py"
    spec = importlib.util.spec_from_file_location("iris_trusted_release_auth", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _keys(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise InstallError("Release kit has unsupported or missing fields")


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InstallError("Release kit JSON contains duplicate fields")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, RecursionError, UnicodeError):
        raise InstallError("Release kit JSON is invalid") from None


def _name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,159}", value):
        raise InstallError("Release kit asset name is unsafe")
    return value


def _sha(value, prefix=""):
    if not isinstance(value, str) or not re.fullmatch(re.escape(prefix) + r"[a-f0-9]{64}", value):
        raise InstallError("Release kit digest is invalid")
    return value


def _path(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise InstallError("Release kit paths must be absolute and must not traverse symlinks")
    return path


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open(path, maximum):
    _path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or not 0 < info.st_size <= maximum):
        os.close(fd)
        raise InstallError("Release kit input must be a bounded regular file without aliases")
    return fd, info


def _hash(fd, maximum, output=None):
    os.lseek(fd, 0, os.SEEK_SET)
    digest, size = hashlib.sha256(), 0
    while data := os.read(fd, CHUNK):
        size += len(data)
        if size > maximum:
            raise InstallError("Release kit input exceeded its size limit")
        digest.update(data)
        if output is not None:
            output.write(data)
    return digest.hexdigest(), size


def _snapshot(source, destination, maximum):
    fd, info = _open(source, maximum)
    try:
        return _snapshot_fd(fd, info, destination, maximum)
    finally:
        os.close(fd)


def _snapshot_fd(fd, info, destination, maximum):
    with destination.open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        digest, size = _hash(fd, maximum, output)
    if _identity(info) != _identity(os.fstat(fd)) or size != info.st_size:
        raise InstallError("Release kit input changed during verification")
    return digest


def _protected_directory(path):
    """Open through pinned protected ancestry, returning the owned descriptor.

    A root-owned sticky directory such as /tmp may contain an owned private
    child. The next component must still pass the same ownership checks;
    other writable ancestors cannot select or replace trusted inputs/outputs.
    """
    path = _path(path)
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in (*path.parts[1:], None):
            info = os.fstat(directory)
            sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
            if (info.st_uid not in (0, os.geteuid())
                    or (info.st_mode & 0o022 and not sticky)):
                raise InstallError("Release kit requires protected parent directories")
            if component is not None:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
                os.close(directory)
                directory = child
        return directory
    except BaseException:
        os.close(directory)
        raise


def _trusted_snapshot(source, destination):
    """Inspect actual trust FD ownership/mode, never a previous path lookup."""
    source = _path(source)
    directory = _protected_directory(source.parent)
    try:
        fd = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or not 0 < info.st_size <= MAX_METADATA
                    or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022):
                raise InstallError("Trusted root material must have protected ownership and permissions")
            digest = _snapshot_fd(fd, info, destination, MAX_METADATA)
            if _identity(info) != _identity(os.stat(source.name, dir_fd=directory, follow_symlinks=False)):
                raise InstallError("Trusted root material changed during verification")
            return digest
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def _verifier(path, directory):
    path = _path(path)
    if path.is_relative_to(directory):
        raise InstallError("Use an independently installed verifier outside the release kit")
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or info.st_mode & 0o022 or not info.st_mode & 0o111):
        raise InstallError("The release verifier must be root-owned and protected from other writers")
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise InstallError("The verifier requires root-owned, protected parent directories")
    fd, info = _open(path, MAX_ASSET)
    try:
        digest, _ = _hash(fd, MAX_ASSET)
        if _identity(info) != _identity(os.fstat(fd)):
            raise InstallError("The release verifier changed during inspection")
        version = subprocess.run([str(path), "--version"], check=True, timeout=10,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "GH_PROMPT_DISABLED": "1"}).stdout
        if not isinstance(version, bytes) or len(version) > 4096 or not re.match(rb"gh version [0-9]+\.[0-9]+\.[0-9]+\b", version):
            raise InstallError("The selected verifier is not GitHub CLI")
        return path, digest
    finally:
        os.close(fd)


class _BoundedTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        extensions = (tarfile.XHDTYPE, tarfile.GNUTYPE_LONGNAME)
        if self.type in extensions:
            if not 0 < self.size <= 16384 or getattr(archive, "_kit_extension", False):
                raise InstallError("Release kit archive metadata is too large or chained")
            archive._kit_extension = True
            try:
                return super()._proc_member(archive)
            finally:
                archive._kit_extension = False
        if self.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
            raise InstallError("Release kit archive contains unsupported entry types")
        return super()._proc_member(archive)

    def _proc_gnusparse_00(self, *args):
        raise InstallError("Release kit archives cannot contain sparse entries")

    _proc_gnusparse_01 = _proc_gnusparse_00
    _proc_gnusparse_10 = _proc_gnusparse_00


def _archive(fd, format):
    """Inspect only the outer archive; nested OCI layers are not extracted."""
    if (os.pread(fd, 2, 0) == b"\x1f\x8b") != (format == "tar.gz"):
        raise InstallError("Release kit archive encoding does not match its declared format")
    os.lseek(fd, 0, os.SEEK_SET)
    names, expanded = set(), 0
    with os.fdopen(os.dup(fd), "rb") as stream:
        try:
            with tarfile.open(fileobj=stream, mode="r|*", tarinfo=_BoundedTarInfo) as archive:
                for member in archive:
                    name = member.name.rstrip("/") if member.isdir() else member.name
                    path = PurePosixPath(name)
                    if (not name or name == "." or path.is_absolute() or ".." in path.parts
                            or str(path) != name or len(name.encode()) > 4096
                            or any(ord(c) < 32 for c in name) or name in names):
                        raise InstallError("Release kit archive has unsafe or duplicate entries")
                    names.add(name)
                    expanded += member.size
                    if len(names) > 100000 or member.size < 0 or expanded > MAX_ASSET:
                        raise InstallError("Release kit archive exceeds its expansion limit")
        except (tarfile.TarError, EOFError, UnicodeError, ValueError):
            raise InstallError("Release kit archive is invalid") from None
    if not names:
        raise InstallError("Release kit archive is empty")


@dataclass(frozen=True)
class Asset:
    role: str
    name: str
    size: int
    sha256: str
    format: str
    platforms: tuple = ()
    image_digest: str = ""
    neutral_source_sha256: str = ""

    @property
    def config_digest(self):
        """Docker archive config bytes, not a daemon-specific image identity."""
        if self.format != "docker-archive":
            raise InstallError("This asset does not declare a Docker config digest")
        return self.image_digest


@dataclass(frozen=True)
class VerifiedKit:
    directory: Path
    tag: str
    commit: str
    manifest_sha256: str
    inventory_sha256: str
    verifier_sha256: str
    trusted_root_sha256: str | None
    offline: bool
    assets: tuple

    def asset(self, role):
        for asset in self.assets:
            if asset.role == role:
                return asset
        raise InstallError("Release kit has no supported asset for this role")

    def receipt(self):
        return {"schema": SCHEMA, "profile": "prepared-host", "tag": self.tag,
                "commit": self.commit, "manifest_sha256": self.manifest_sha256,
                "inventory_sha256": self.inventory_sha256,
                "verifier_sha256": self.verifier_sha256,
                "trusted_root_sha256": self.trusted_root_sha256, "offline": self.offline}

    def copy_asset(self, role, destination):
        """Publish exact authenticated bytes, never a caller-supplied executable."""
        asset = self.asset(role)
        destination = _path(destination)
        parent = destination.parent
        directory = _protected_directory(parent)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise InstallError("Release kit staging needs a caller-owned private directory")
            try:
                os.stat(destination.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise InstallError("Release kit staging never replaces an existing file")
            # /proc/self/fd anchors tempfile creation, reads and cleanup to the
            # checked directory even if its pathname is moved or substituted.
            with tempfile.TemporaryDirectory(prefix=".kit-copy-", dir=Path("/proc/self/fd") / str(directory)) as temporary:
                snapshot = Path(temporary) / "asset"
                actual = _snapshot(self.directory / asset.name, snapshot, asset.size)
                if actual != asset.sha256 or snapshot.stat().st_size != asset.size:
                    raise InstallError("Release kit asset changed; nothing was published")
                with snapshot.open("rb") as stream:
                    os.fsync(stream.fileno())
                named = parent.lstat()
                if (_path(parent) != parent or (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)):
                    raise InstallError("Release kit staging directory changed; nothing was published")
                relative = str(Path(Path(temporary).name) / "asset")
                os.link(relative, destination.name, src_dir_fd=directory,
                        dst_dir_fd=directory, follow_symlinks=False)
                os.fsync(directory)
        finally:
            os.close(directory)
        return destination


def _kit_manifest(value, auth, tag, commit, inventory):
    _keys(value, ("schema", "repository", "workflow", "tag", "commit", "host", "profile", "assets"))
    if (value["schema"] != SCHEMA or value["repository"] != auth.REPOSITORY
            or value["workflow"] != auth.WORKFLOW or value["tag"] != tag
            or value["commit"] != commit or value["host"] != HOST
            or value["profile"] != "prepared-host"):
        raise InstallError("Release kit identity or host profile is unsupported")
    entries = value["assets"]
    if isinstance(entries, dict) and "ubuntu-dependencies" in entries:
        raise InstallError("Offline Ubuntu dependency closure is not supported by this kit profile")
    _keys(entries, ROLES)
    result, names = [], set()
    for role in sorted(entries):
        entry = entries[role]
        fields = {"name", "size", "sha256", "format"}
        if role in IMAGES:
            fields.update(("platforms", "image_digest"))
        if role == "device-runtime":
            fields.add("neutral_source_sha256")
        _keys(entry, fields)
        name = _name(entry["name"])
        if name in names or name not in inventory or inventory[name] != {key: entry[key] for key in ("size", "sha256")}:
            raise InstallError("Release kit role does not match a unique authenticated asset")
        names.add(name)
        platforms = ("linux/amd64", "linux/arm64") if role == "device-runtime" else ("linux/amd64",)
        expected_format = "oci-archive" if role == "device-runtime" else "docker-archive" if role in IMAGES else "tar.gz"
        if entry["format"] != expected_format:
            raise InstallError("Release kit asset format is unsupported")
        if role in IMAGES and entry["platforms"] != list(platforms):
            raise InstallError("Release kit image architectures are incomplete or unsupported")
        result.append(Asset(role, name, entry["size"], entry["sha256"], entry["format"],
                            platforms if role in IMAGES else (),
                            _sha(entry["image_digest"], "sha256:") if role in IMAGES else "",
                            _sha(entry["neutral_source_sha256"]) if role == "device-runtime" else ""))
    return tuple(result)


def verify_kit(directory, *, tag, commit, verifier, trusted_root=None, offline=False):
    """Authenticate all assets before returning; failures expose no raw tool text."""
    auth = _auth()
    try:
        auth.validate_tag(tag)
        if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit) or type(offline) is not bool:
            raise InstallError("Select an exact release commit and network policy")
        directory = _path(directory)
        if not directory.is_dir():
            raise InstallError("Select a release kit directory")
        verifier, verifier_hash = _verifier(verifier, directory)
        if offline and trusted_root is None:
            raise InstallError("Offline verification requires independently trusted root material")
        if trusted_root is not None:
            trusted_root = _path(trusted_root)
            if trusted_root.is_relative_to(directory):
                raise InstallError("The kit cannot authorize its own trusted root")
        with tempfile.TemporaryDirectory(prefix="iris-kit-verification-") as temporary:
            work = Path(temporary)
            work.chmod(0o700)
            inventory_hash = _snapshot(directory / "release.json", work / "release.json", MAX_METADATA)
            _snapshot(directory / "attestations.jsonl", work / "attestations.jsonl", MAX_BUNDLE)
            root_hash = _trusted_snapshot(trusted_root, work / "trusted-root.json") if trusted_root else None
            deadline = time.monotonic() + 600

            def authenticate(path, *, pass_fds=()):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise InstallError("Release kit authentication exceeded its time limit")
                command = auth.verify_command(path, tag, commit, work / "attestations.jsonl",
                    trusted_root=work / "trusted-root.json" if trusted_root else None)
                command[0] = str(verifier)
                subprocess.run(command, check=True, timeout=min(60, remaining), pass_fds=pass_fds,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env={"PATH": "/usr/bin:/bin", "HOME": str(work), "GH_CONFIG_DIR": str(work),
                         "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1"})

            authenticate(work / "release.json")
            inventory = _json((work / "release.json").read_bytes())
            _keys(inventory, ("schema", "repository", "workflow", "tag", "commit", "assets"))
            if (type(inventory["schema"]) is not int or inventory["schema"] != 1
                    or inventory["repository"] != auth.REPOSITORY or inventory["workflow"] != auth.WORKFLOW
                    or inventory["tag"] != tag or inventory["commit"] != commit):
                raise InstallError("Authenticated inventory identifies another release")
            records = inventory["assets"]
            if not isinstance(records, dict) or not 1 <= len(records) <= MAX_ASSETS:
                raise InstallError("Release asset inventory exceeds supported bounds")
            total = 0
            for name, record in records.items():
                _name(name)
                if name in {"release.json", "attestations.jsonl", "SHA256SUMS"}:
                    raise InstallError("Release inventory repeats a reserved metadata name")
                _keys(record, ("size", "sha256"))
                _sha(record["sha256"])
                if type(record["size"]) is not int or not 0 < record["size"] <= MAX_ASSET:
                    raise InstallError("Release asset size is invalid")
                total += record["size"]
            if total > MAX_TOTAL or "release-kit.json" not in records:
                raise InstallError("Release kit inventory is missing or too large")
            expected_names = set(records) | {"release.json", "attestations.jsonl", "SHA256SUMS"}
            actual_names = set()
            for path in directory.iterdir():
                actual_names.add(path.name)
                if path.name not in expected_names or len(actual_names) > len(expected_names):
                    raise InstallError("Release kit contains missing or unlisted inputs")
            if actual_names != expected_names:
                raise InstallError("Release kit contains missing or unlisted inputs")
            kit_hash = _snapshot(directory / "release-kit.json", work / "release-kit.json", MAX_METADATA)
            if records["release-kit.json"] != {"size": (work / "release-kit.json").stat().st_size, "sha256": kit_hash}:
                raise InstallError("Release kit metadata differs from authenticated inventory")
            authenticate(work / "release-kit.json")
            assets = _kit_manifest(_json((work / "release-kit.json").read_bytes()), auth, tag, commit, records)
            archive_formats = {asset.name: asset.format for asset in assets}
            for name in sorted(set(records) | {"SHA256SUMS"}):
                if name == "release-kit.json":
                    continue
                maximum = records[name]["size"] if name in records else MAX_METADATA
                fd, info = _open(directory / name, maximum)
                try:
                    checksum, size = _hash(fd, maximum)
                    if name in records and records[name] != {"size": size, "sha256": checksum}:
                        raise InstallError("Release asset differs from authenticated inventory")
                    authenticate(Path("/proc/self/fd") / str(fd), pass_fds=(fd,))
                    if name in archive_formats:
                        _archive(fd, archive_formats[name])
                    if _identity(info) != _identity(os.fstat(fd)) or _hash(fd, maximum) != (checksum, size):
                        raise InstallError("Release asset changed during authentication")
                finally:
                    os.close(fd)
            if _verifier(verifier, directory)[1] != verifier_hash:
                raise InstallError("Release verifier changed during authentication")
            return VerifiedKit(directory, tag, commit, kit_hash, inventory_hash,
                               verifier_hash, root_hash, offline, assets)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise InstallError("Release kit verification failed; no payload was installed") from None


def selection(mode="source", *, kit=None, offline=False):
    """Pure CLI/journal contract; callers persist it before any host mutation."""
    if type(offline) is not bool or mode not in ("source", "prebuilt"):
        raise InstallError("Unsupported installer input mode")
    result = {"schema": SELECTION_SCHEMA, "mode": mode}
    if mode == "source":
        if kit is not None or offline:
            raise InstallError("Source-build installation does not support an offline kit")
    else:
        if not isinstance(kit, VerifiedKit) or kit.offline != offline:
            raise InstallError("Prebuilt installation requires a verified matching kit")
        result["kit"] = kit.receipt()
    return result


def assert_resume_selection(recorded, current):
    for value in (recorded, current):
        if not isinstance(value, dict) or value.get("schema") != SELECTION_SCHEMA:
            raise InstallError("Installer input selection is invalid")
        if value.get("mode") == "source":
            _keys(value, ("schema", "mode"))
        elif value.get("mode") == "prebuilt":
            _keys(value, ("schema", "mode", "kit"))
            receipt = value["kit"]
            _keys(receipt, ("schema", "profile", "tag", "commit", "manifest_sha256", "inventory_sha256",
                            "verifier_sha256", "trusted_root_sha256", "offline"))
            if (receipt["schema"] != SCHEMA or receipt["profile"] != "prepared-host"
                    or not isinstance(receipt["tag"], str) or not re.fullmatch(r"v20\d{2}\.\d{2}\.\d{2}(?:\.\d+)?", receipt["tag"])
                    or not isinstance(receipt["commit"], str) or not re.fullmatch(r"[a-f0-9]{40}", receipt["commit"])
                    or type(receipt["offline"]) is not bool
                    or (receipt["offline"] and receipt["trusted_root_sha256"] is None)):
                raise InstallError("Installer kit selection is invalid")
            for name in ("manifest_sha256", "inventory_sha256", "verifier_sha256"):
                _sha(receipt[name])
            if receipt["trusted_root_sha256"] is not None:
                _sha(receipt["trusted_root_sha256"])
        else:
            raise InstallError("Installer input mode is invalid")
    if recorded != current:
        raise InstallError("Installer input mode or authenticated kit changed; preserve the journal")
