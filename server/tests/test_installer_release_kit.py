# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Kit boundary tests use synthetic attestations, never publication claims."""

import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from iris_installer import release_kit as kit
from iris_installer.state import InstallError

TAG, COMMIT = "v2026.10.09", "a" * 40
VERIFIER = Path(shutil.which("true")).resolve()


def archive_bytes(*, compressed=False, name="payload", kind=tarfile.REGTYPE, size=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz" if compressed else "w", format=tarfile.USTAR_FORMAT) as archive:
        member = tarfile.TarInfo(name)
        member.type = kind
        data = b"synthetic fixture payload"
        member.size = len(data) if size is None else size
        if kind != tarfile.REGTYPE:
            member.size = 0 if size is None else size
        archive.addfile(member, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return output.getvalue()


def write_json(path, value):
    path.write_text(json.dumps(value))


@pytest.fixture
def release(tmp_path, monkeypatch):
    directory = tmp_path / "kit"
    directory.mkdir()
    root = tmp_path / "independent-root.json"
    root.write_bytes(b"synthetic independently selected trusted root")
    root.chmod(0o600)
    auth = kit._auth()
    manifest = {"schema": kit.SCHEMA, "repository": auth.REPOSITORY, "workflow": auth.WORKFLOW,
                "tag": TAG, "commit": COMMIT, "host": dict(kit.HOST),
                "profile": "prepared-host", "assets": {}}
    for role in sorted(kit.ROLES):
        image = role in kit.IMAGES
        name = role + (".tar" if image else ".tar.gz")
        data = archive_bytes(compressed=not image)
        (directory / name).write_bytes(data)
        entry = {"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                 "format": "oci-archive" if role == "device-runtime" else "docker-archive" if image else "tar.gz"}
        if image:
            entry.update(platforms=["linux/amd64", "linux/arm64"] if role == "device-runtime" else ["linux/amd64"],
                         image_digest="sha256:" + "1" * 64)
        manifest["assets"][role] = entry
    (directory / "attestations.jsonl").write_bytes(b"synthetic, not a valid attestation")
    (directory / "SHA256SUMS").write_bytes(b"synthetic checksum inventory")
    (directory / "release-auth.py").write_bytes(b"raise RuntimeError('untrusted kit code must never execute')")
    calls = []

    def run(command, **kwargs):
        calls.append((list(command), kwargs))
        if command[1:] == ["--version"]:
            return SimpleNamespace(stdout=b"gh version 2.100.0\n", returncode=0)
        assert command[:3] == [str(VERIFIER), "attestation", "verify"]
        assert kwargs["stdout"] == subprocess.DEVNULL and kwargs["stderr"] == subprocess.DEVNULL
        assert kwargs["timeout"] <= 60
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(kit.subprocess, "run", run)
    fixture = SimpleNamespace(directory=directory, root=root, manifest=manifest, calls=calls, runner=run)
    seal(fixture)
    return fixture


def seal(fixture):
    write_json(fixture.directory / "release-kit.json", fixture.manifest)
    auth = kit._auth()
    inventory = {"schema": 1, "repository": auth.REPOSITORY, "workflow": auth.WORKFLOW,
                 "tag": TAG, "commit": COMMIT, "assets": {}}
    for path in fixture.directory.iterdir():
        if path.name not in ("release.json", "SHA256SUMS", "attestations.jsonl"):
            data = path.read_bytes()
            inventory["assets"][path.name] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    write_json(fixture.directory / "release.json", inventory)


def verify(release, **changes):
    arguments = dict(tag=TAG, commit=COMMIT, verifier=VERIFIER, trusted_root=release.root, offline=True)
    arguments.update(changes)
    return kit.verify_kit(release.directory, **arguments)


def test_complete_prepared_host_kit_and_protected_copy(release, tmp_path, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "must-not-be-inherited")
    result = verify(release)
    assert result.asset("server-image").config_digest == "sha256:" + "1" * 64
    assert result.asset("device-runtime").platforms == ("linux/amd64", "linux/arm64")
    with pytest.raises(InstallError, match="Docker config"):
        _ = result.asset("device-runtime").config_digest
    receipt = result.receipt()
    assert receipt["profile"] == "prepared-host" and receipt["offline"] is True
    assert receipt["trusted_root_sha256"] == hashlib.sha256(release.root.read_bytes()).hexdigest()
    calls = [call for call in release.calls if call[0][1] == "attestation"]
    assert calls[0][0][3].endswith("/release.json")
    assert calls[1][0][3].endswith("/release-kit.json")
    assert len(calls) == 10  # Both metadata files, six archives, helper and SHA256SUMS.
    for command, options in calls:
        for flag in ("--bundle", "--custom-trusted-root", "--source-digest", "--signer-digest",
                     "--cert-identity", "--source-ref", "--deny-self-hosted-runners"):
            assert flag in command
        assert command[command.index("--source-digest") + 1] == COMMIT
        assert "GH_TOKEN" not in options["env"]
        assert str(release.root) not in command and str(release.directory / "attestations.jsonl") not in command
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    output = result.copy_asset("server-image", private / "verified.tar")
    assert output.read_bytes() == (release.directory / "server-image.tar").read_bytes()
    assert output.stat().st_mode & 0o777 == 0o600 and output.stat().st_nlink == 1
    with pytest.raises(InstallError, match="never replaces"):
        result.copy_asset("server-image", output)
    with pytest.raises(InstallError, match="supported asset"):
        result.asset("not-a-role")


@pytest.mark.parametrize("change", ["tag", "commit", "host", "unknown-field", "unknown-role", "missing-role",
    "platform", "format", "image-digest", "profile", "closure", "duplicate-name", "boolean-size"])
def test_strict_manifest_rejects_unimplemented_or_malformed_contracts(release, change):
    manifest = release.manifest
    if change in ("tag", "commit"):
        manifest[change] = "wrong"
    elif change == "host":
        manifest["host"]["unexpected"] = True
    elif change == "unknown-field":
        manifest["verifier"] = "own-verifier"
    elif change == "unknown-role":
        manifest["assets"]["unexpected"] = dict(manifest["assets"]["source"])
    elif change == "missing-role":
        del manifest["assets"]["source"]
    elif change == "profile":
        manifest["profile"] = "bare-host-offline"
    elif change == "closure":
        manifest["assets"]["ubuntu-dependencies"] = dict(manifest["assets"]["source"])
    elif change == "duplicate-name":
        manifest["assets"]["guest-inputs"] = dict(manifest["assets"]["source"])
    else:
        entry = manifest["assets"]["server-image"]
        entry[{"platform": "platforms", "format": "format", "image-digest": "image_digest", "boolean-size": "size"}[change]] = {
            "platform": ["linux/arm64"], "format": "shell", "image-digest": "mutable:tag", "boolean-size": True}[change]
    seal(release)
    with pytest.raises(InstallError):
        verify(release)


@pytest.mark.parametrize("filename", ["release.json", "release-kit.json"])
def test_duplicate_json_keys_are_refused_even_if_attested(release, filename):
    target = release.directory / filename
    data = target.read_bytes().replace(b'{', b'{"schema":"duplicate",', 1)
    target.write_bytes(data)
    if filename != "release.json":
        inventory = json.loads((release.directory / "release.json").read_bytes())
        inventory["assets"][filename] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        write_json(release.directory / "release.json", inventory)
    with pytest.raises(InstallError, match="duplicate"):
        verify(release)


@pytest.mark.parametrize("change", ["extra-file", "missing-file", "tampered-file", "symlink-file", "hardlink-file",
                                      "oversized-metadata", "unsafe-name", "reserved-name", "boolean-size"])
def test_inventory_and_files_fail_closed(release, tmp_path, monkeypatch, change):
    path = release.directory / "source.tar.gz"
    if change == "extra-file":
        (release.directory / "not-listed").write_bytes(b"extra")
    elif change == "missing-file":
        path.unlink()
    elif change == "tampered-file":
        path.write_bytes(b"different")
    elif change in ("symlink-file", "hardlink-file"):
        outside = tmp_path / "outside"
        path.rename(outside)
        if change == "symlink-file":
            path.symlink_to(outside)
        else:
            os.link(outside, path)
    elif change == "oversized-metadata":
        monkeypatch.setattr(kit, "MAX_METADATA", 20)
    else:
        inventory_path = release.directory / "release.json"
        inventory = json.loads(inventory_path.read_bytes())
        if change == "boolean-size":
            inventory["assets"][path.name]["size"] = True
        else:
            name = "../outside" if change == "unsafe-name" else "release.json"
            inventory["assets"][name] = inventory["assets"].pop(path.name)
        write_json(inventory_path, inventory)
    with pytest.raises(InstallError):
        verify(release)


def test_signature_rejection_precedes_untrusted_json_and_redacts_tool_output(release, monkeypatch):
    (release.directory / "release.json").write_bytes(b"not json")
    def reject(command, **kwargs):
        if command[1:] == ["--version"]:
            return release.runner(command, **kwargs)
        raise subprocess.CalledProcessError(1, command, output=b"private token not printable")
    monkeypatch.setattr(kit.subprocess, "run", reject)
    with pytest.raises(InstallError, match="verification failed") as failure:
        verify(release)
    assert "private" not in str(failure.value) and "JSON" not in str(failure.value)


@pytest.mark.parametrize("change", ["kit-root", "no-root", "writable-root", "linked-root", "kit-verifier", "unprotected-verifier", "symlink-directory"])
def test_independent_trust_boundaries(release, tmp_path, change):
    arguments = {}
    if change == "kit-root":
        arguments["trusted_root"] = release.directory / "release.json"
    elif change == "no-root":
        arguments["trusted_root"] = None
    elif change == "writable-root":
        release.root.chmod(0o666)
    elif change == "linked-root":
        link = tmp_path / "root-link"
        link.symlink_to(release.root)
        arguments["trusted_root"] = link
    elif change == "kit-verifier":
        arguments["verifier"] = release.directory / "release-auth.py"
    elif change == "unprotected-verifier":
        executable = tmp_path / "unprotected-tool"
        executable.write_text("not executed")
        executable.chmod(0o755)
        arguments["verifier"] = executable
    else:
        link = tmp_path / "alias"
        link.symlink_to(release.directory, target_is_directory=True)
        release.directory = link
    with pytest.raises(InstallError):
        verify(release, **arguments)


@pytest.mark.parametrize("change", ["writable-parent", "unowned-parent", "writable-opened-file", "symlink-opened-file", "replaced-after-open"])
def test_trusted_root_custody_is_checked_on_pinned_ancestry_and_open_fd(release, monkeypatch, change):
    parent = release.root.parent / "trust-custody"
    parent.mkdir(mode=0o700)
    release.root = release.root.rename(parent / "trusted-root.json")
    original_open, original_fstat = os.open, os.fstat
    replaced = False

    if change == "writable-parent":
        parent.chmod(0o777)
    elif change == "unowned-parent":
        parent_identity = parent.stat()
        def fstat(fd):
            info = original_fstat(fd)
            if (info.st_dev, info.st_ino) == (parent_identity.st_dev, parent_identity.st_ino):
                return SimpleNamespace(st_uid=65534, st_mode=info.st_mode)
            return info
        monkeypatch.setattr(kit.os, "fstat", fstat)
    elif change in ("writable-opened-file", "symlink-opened-file"):
        def open_file(path, flags, *args, **kwargs):
            nonlocal replaced
            if path == release.root.name and "dir_fd" in kwargs and not replaced:
                replaced = True
                replacement = parent / "substitute"
                replacement.write_bytes(b"untrusted substituted root")
                if change == "writable-opened-file":
                    replacement.chmod(0o666)
                    replacement.replace(release.root)
                else:
                    release.root.unlink()
                    release.root.symlink_to(replacement)
            return original_open(path, flags, *args, **kwargs)
        monkeypatch.setattr(kit.os, "open", open_file)
    else:
        original_snapshot = kit._snapshot_fd
        def snapshot(fd, info, destination, maximum):
            result = original_snapshot(fd, info, destination, maximum)
            if destination.name == "trusted-root.json":
                replacement = parent / "substitute"
                replacement.write_bytes(b"different root after opening")
                replacement.chmod(0o600)
                replacement.replace(release.root)
            return result
        monkeypatch.setattr(kit, "_snapshot_fd", snapshot)
    with pytest.raises(InstallError):
        verify(release)
    assert not any(command[1] == "attestation" for command, _ in release.calls)


@pytest.mark.parametrize("change", ["unsafe-name", "symlink", "fifo", "duplicate", "oversized-pax", "sparse"])
def test_bounded_archive_envelopes(release, change):
    name = "source.tar.gz"
    if change == "unsafe-name":
        data = archive_bytes(name="../escape")
    elif change in ("symlink", "fifo"):
        data = archive_bytes(kind=tarfile.SYMTYPE if change == "symlink" else tarfile.FIFOTYPE)
    elif change == "duplicate":
        raw = archive_bytes()
        data = raw[:1024] + raw
    else:
        member = tarfile.TarInfo("metadata")
        member.type = tarfile.XHDTYPE if change == "oversized-pax" else tarfile.GNUTYPE_SPARSE
        member.size = 16385 if change == "oversized-pax" else 0
        data = member.tobuf() + b"\0" * 32768
    data = gzip.compress(data)
    (release.directory / name).write_bytes(data)
    release.manifest["assets"]["source"].update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
    seal(release)
    with pytest.raises(InstallError, match="archive"):
        verify(release)


def test_archive_encoding_must_match_declared_format(release):
    data = archive_bytes(compressed=False)
    (release.directory / "source.tar.gz").write_bytes(data)
    release.manifest["assets"]["source"].update(size=len(data), sha256=hashlib.sha256(data).hexdigest())
    seal(release)
    with pytest.raises(InstallError, match="encoding"):
        verify(release)


def test_changed_asset_during_attestation_is_not_accepted(release, monkeypatch):
    path = release.directory / "server-image.tar"
    def mutate(command, **kwargs):
        result = release.runner(command, **kwargs)
        if len(command) > 3 and command[3].startswith("/proc/self/fd/"):
            fd = int(command[3].rsplit("/", 1)[1])
            if Path(os.readlink(command[3])) == path:
                assert fd in kwargs["pass_fds"]
                path.write_bytes(archive_bytes(name="different"))
        return result
    monkeypatch.setattr(kit.subprocess, "run", mutate)
    with pytest.raises(InstallError, match="changed during"):
        verify(release)


def test_changed_asset_at_consumption_never_publishes(release, tmp_path):
    verified = verify(release)
    (release.directory / "server-image.tar").write_bytes(archive_bytes(name="different"))
    parent = tmp_path / "stage"
    parent.mkdir(mode=0o700)
    with pytest.raises(InstallError, match="changed"):
        verified.copy_asset("server-image", parent / "image")
    assert list(parent.iterdir()) == []


def test_replaced_copy_parent_cannot_publish_substituted_snapshot(release, tmp_path, monkeypatch):
    verified = verify(release)
    parent = tmp_path / "stage"
    parent.mkdir(mode=0o700)
    moved = tmp_path / "original-stage"
    original_snapshot = kit._snapshot
    replacement = b"x" * verified.asset("server-image").size

    def substitute(source, destination, maximum):
        digest = original_snapshot(source, destination, maximum)
        parent.rename(moved)
        parent.mkdir(mode=0o700)
        counterfeit = parent / destination.parent.name
        counterfeit.mkdir(mode=0o700)
        (counterfeit / "asset").write_bytes(replacement)
        return digest

    monkeypatch.setattr(kit, "_snapshot", substitute)
    with pytest.raises(InstallError, match="staging directory changed"):
        verified.copy_asset("server-image", parent / "image.tar")
    assert not (parent / "image.tar").exists()
    assert not (moved / "image.tar").exists()
    assert list(moved.iterdir()) == []  # Only the owned anchored temporary was removed.
    assert next(parent.glob(".kit-copy-*/asset")).read_bytes() == replacement


def test_copy_refuses_unprotected_ancestor_before_creating_anything(release, tmp_path):
    verified = verify(release)
    ancestor = tmp_path / "shared"
    ancestor.mkdir(mode=0o700)
    ancestor.chmod(0o777)
    parent = ancestor / "private"
    parent.mkdir(mode=0o700)
    with pytest.raises(InstallError, match="protected parent"):
        verified.copy_asset("server-image", parent / "image.tar")
    assert list(parent.iterdir()) == []


def test_mode_and_resume_contract_rejects_drift(release):
    verified = verify(release)
    source = kit.selection()
    current = kit.selection("prebuilt", kit=verified, offline=True)
    kit.assert_resume_selection(source, copy.deepcopy(source))
    kit.assert_resume_selection(current, copy.deepcopy(current))
    for changed in (source, {}, {**current, "unexpected": True},
                    {**current, "kit": {**current["kit"], "commit": "b" * 40}}):
        with pytest.raises(InstallError):
            kit.assert_resume_selection(current, changed)
    with pytest.raises(InstallError):
        kit.assert_resume_selection({}, {})
    for arguments in ({"kit": verified}, {"offline": True}, {"mode": "other"},
                      {"mode": "prebuilt"}, {"mode": "prebuilt", "kit": verified}):
        with pytest.raises(InstallError):
            kit.selection(**arguments)
