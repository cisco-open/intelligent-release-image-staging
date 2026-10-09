# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Authenticated wrapper inputs are private snapshots, never executable imports."""

import gzip
import json
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest

from test_device_finalize import digest, encoded, entry, roots, run, tar_bytes
from iris_installer import device_context as c
from iris_installer.state import InstallError


@pytest.fixture
def finalized(tmp_path, roots):
    receipt = run(tmp_path, roots)
    directory = tmp_path / "result"
    return directory, receipt, digest((directory / c.RECEIPT).read_bytes())


def prepare(finalized, tmp_path, **kwargs):
    source, _, receipt_sha = finalized
    return c.prepare(source, tmp_path / "context",
                     expected_finalization_sha256=kwargs.get("expected", receipt_sha))


def test_finalized_context_is_private_readonly_and_preserves_distinct_identity(finalized, tmp_path):
    source, receipt, receipt_sha = finalized
    assert prepare(finalized, tmp_path) == receipt
    output = tmp_path / "context"
    assert output.stat().st_mode & 0o777 == 0o700
    assert {path.name for path in output.iterdir()} == {
        c.RECEIPT, "iris-device.oci.tar", "iris-device-oci-path", "iris-device-oci.manifest"}
    for path in output.iterdir():
        assert path.stat().st_mode & 0o777 == 0o444
    assert (output / "iris-device.oci.tar").read_bytes() == (source / "iris-device.oci.tar").read_bytes()
    assert (output / "iris-device-oci-path").read_text() == str(output / "iris-device.oci.tar") + "\n"
    values = dict(line.split("=", 1) for line in (output / "iris-device-oci.manifest").read_text().splitlines())
    assert values == {"format": "iris-device-finalized-context-v1",
                      "index_digest": receipt["index_digest"], "archive_sha256": receipt["archive_sha256"],
                      "neutral_source_sha256": receipt["neutral_source_sha256"],
                      "finalization_sha256": receipt_sha, "platforms": "linux/amd64,linux/arm64"}
    assert not list(tmp_path.glob(".iris-package-input-*"))


@pytest.mark.parametrize("expected", [None, "", "a" * 63, "A" * 64, "a" * 64 + "\n", "0" * 64])
def test_context_requires_authenticated_exact_receipt_hash(finalized, tmp_path, expected):
    with pytest.raises(InstallError):
        prepare(finalized, tmp_path, expected=expected)
    assert not (tmp_path / "context").exists()


@pytest.mark.parametrize("kind", ["extra", "missing", "version", "archive-size-bool", "archive-size-large",
                                  "architecture", "platform-extra", "platform-digest", "root-name", "trust-name"])
def test_strict_receipt_contract_even_when_receipt_bytes_are_authenticated(finalized, tmp_path, kind):
    source, value, _ = finalized
    if kind == "extra": value["source_sha256"] = "a" * 64
    elif kind == "missing": del value["neutral_source_sha256"]
    elif kind == "version": value["format"] = "iris-device-finalized-v2"
    elif kind == "archive-size-bool": value["archive_size"] = True
    elif kind == "archive-size-large": value["archive_size"] = c.f.MAX_ARCHIVE + 1
    elif kind == "architecture": del value["platforms"]["arm64"]
    elif kind == "platform-extra": value["platforms"]["amd64"]["extra"] = True
    elif kind == "platform-digest": value["platforms"]["amd64"]["config_digest"] = "bad"
    elif kind == "root-name": value["root_files_sha256"] = {"../root.pub": "a" * 64, "root.pub": "b" * 64}
    elif kind == "trust-name": value["trust_files_sha256"]["extra"] = "a" * 64
    (source / c.RECEIPT).chmod(0o600)
    (source / c.RECEIPT).write_bytes(encoded(value))
    with pytest.raises(InstallError):
        c.prepare(source, tmp_path / "context", expected_finalization_sha256=digest(encoded(value)))
    assert not (tmp_path / "context").exists()


@pytest.mark.parametrize("kind", ["archive-bytes", "receipt-link", "archive-link", "directory-link", "unsafe-parent", "existing"])
def test_context_input_custody_and_exclusive_output(finalized, tmp_path, kind):
    source, receipt, receipt_sha = finalized
    if kind == "archive-bytes":
        (source / "iris-device.oci.tar").chmod(0o600)
        (source / "iris-device.oci.tar").write_bytes(b"replaced")
    elif kind in ("receipt-link", "archive-link"):
        path = source / (c.RECEIPT if kind == "receipt-link" else "iris-device.oci.tar")
        path.rename(tmp_path / "actual")
        path.symlink_to(tmp_path / "actual")
    elif kind == "directory-link":
        source.rename(tmp_path / "actual")
        source.symlink_to(tmp_path / "actual", target_is_directory=True)
    elif kind == "unsafe-parent": tmp_path.chmod(0o777)
    else:
        (tmp_path / "context").mkdir()
        (tmp_path / "context/keep").write_text("owner data")
    with pytest.raises(InstallError):
        prepare(finalized, tmp_path)
    if kind == "existing": assert (tmp_path / "context/keep").read_text() == "owner data"
    else: assert not (tmp_path / "context").exists()


def test_parent_rename_cannot_redirect_publication_or_cleanup(finalized, tmp_path, monkeypatch):
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    snapshot = c.f._snapshot
    def changed(*args, **kwargs):
        result = snapshot(*args, **kwargs)
        if Path(args[0]).name == "iris-device.oci.tar":
            parent.rename(tmp_path / "held-parent")
            parent.mkdir(mode=0o700)
            (parent / "keep").write_text("owner data")
        return result
    monkeypatch.setattr(c.f, "_snapshot", changed)
    with pytest.raises(InstallError, match="parent changed"):
        c.prepare(finalized[0], parent / "context", expected_finalization_sha256=finalized[2])
    assert list((tmp_path / "held-parent").iterdir()) == []
    assert [path.name for path in parent.iterdir()] == ["keep"]


def test_receipt_change_after_snapshot_prevents_publication(finalized, tmp_path, monkeypatch):
    snapshot = c.f._snapshot
    def changed(*args, **kwargs):
        result = snapshot(*args, **kwargs)
        if Path(args[0]).name == "iris-device.oci.tar":
            receipt = finalized[0] / c.RECEIPT
            receipt.chmod(0o600)
            receipt.write_bytes(b"changed")
        return result
    monkeypatch.setattr(c.f, "_snapshot", changed)
    with pytest.raises(InstallError, match="changed"):
        prepare(finalized, tmp_path)
    assert not (tmp_path / "context").exists()


def appmgr_entries():
    metadata = {"format": "iris-appmgr-source-v1", "source_repository": c.APPMGR_REPOSITORY,
                "source_revision": "a" * 40}
    return [entry("appmgr_build", b"#!/usr/bin/env python3\n", mode=0o755),
            entry("build_rpm.sh", b"#!/bin/sh\n", mode=0o755),
            entry("release_configs", kind=tarfile.DIRTYPE),
            entry("release_configs/ThinXR_7.3.15.yaml", b"release: test\n"),
            entry(c.APPMGR_SOURCE, encoded(metadata))]


def appmgr(tmp_path, entries=None, **kwargs):
    source = tmp_path / "appmgr.tar.gz"
    source.write_bytes(gzip.compress(tar_bytes(appmgr_entries() if entries is None else entries), mtime=0))
    return c.prepare_appmgr(source, tmp_path / "appmgr",
                            expected_sha256=kwargs.get("expected", digest(source.read_bytes())),
                            expected_revision=kwargs.get("revision", "a" * 40))


def test_appmgr_snapshot_is_pinned_private_and_nonexecuting(tmp_path):
    output = appmgr(tmp_path)
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "appmgr_build").stat().st_mode & 0o777 == 0o500
    assert (output / c.APPMGR_SOURCE).stat().st_mode & 0o777 == 0o400
    assert json.loads((output / c.APPMGR_SOURCE).read_text())["source_revision"] == "a" * 40


@pytest.mark.parametrize("kind", ["path", "link", "fifo", "duplicate", "git", "missing-builder", "nonexecutable",
                                  "missing-config", "missing-source", "bad-source", "extra-source", "source-link"])
def test_unsafe_or_unbound_appmgr_is_never_extracted(tmp_path, kind):
    rows = appmgr_entries()
    if kind == "path": rows.append(entry("../escape", b"no"))
    elif kind == "link": rows.append(entry("alias", kind=tarfile.SYMTYPE, target="build_rpm.sh"))
    elif kind == "fifo": rows.append(entry("fifo", kind=tarfile.FIFOTYPE))
    elif kind == "duplicate": rows.append(entry("appmgr_build", b"replace", mode=0o755))
    elif kind == "git": rows.append(entry(".git/config", b"extra"))
    elif kind == "missing-builder": rows = rows[1:]
    elif kind == "nonexecutable": rows[0][0].mode = 0o644
    elif kind == "missing-config": rows = [row for row in rows if not row[0].name.startswith("release_configs")]
    elif kind == "missing-source": rows = rows[:-1]
    elif kind == "bad-source": rows[-1] = entry(c.APPMGR_SOURCE, b'{}')
    elif kind == "extra-source":
        value = json.loads(rows[-1][1]); value["extra"] = True
        rows[-1] = entry(c.APPMGR_SOURCE, encoded(value))
    else: rows[-1] = entry(c.APPMGR_SOURCE, kind=tarfile.SYMTYPE, target="appmgr_build")
    with pytest.raises(InstallError):
        appmgr(tmp_path, rows)
    assert not (tmp_path / "appmgr").exists()
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize("options", [{"expected": "0" * 64}, {"revision": "b" * 40}, {"revision": "a" * 8}])
def test_appmgr_requires_both_authenticated_archive_and_matching_full_revision(tmp_path, options):
    with pytest.raises(InstallError):
        appmgr(tmp_path, **options)
    assert not (tmp_path / "appmgr").exists()


@pytest.mark.parametrize("kind", ["valid", "hash", "nonexecutable", "symlink"])
def test_ioxclient_exact_bytes_are_snapshotted_without_execution(tmp_path, kind):
    tool = tmp_path / "tool"
    tool.write_bytes(b"#!/bin/sh\nexit 91\n")
    tool.chmod(0o700 if kind != "nonexecutable" else 0o600)
    expected = digest(tool.read_bytes()) if kind != "hash" else "0" * 64
    if kind == "symlink":
        tool.rename(tmp_path / "real-tool")
        tool.symlink_to(tmp_path / "real-tool")
    if kind != "valid":
        with pytest.raises(InstallError):
            c.prepare_ioxclient(tool, tmp_path / "private-tool", expected_sha256=expected)
        assert not (tmp_path / "private-tool").exists()
    else:
        result = c.prepare_ioxclient(tool, tmp_path / "private-tool", expected_sha256=expected)
        assert result.read_bytes() == tool.read_bytes()
        assert result.stat().st_mode & 0o777 == 0o500
        assert result.parent.stat().st_mode & 0o777 == 0o700


def test_cli_rejects_unrelated_hashes_and_sanitizes_filesystem_failures(tmp_path):
    command = [sys.executable, str(Path(c.__file__).parents[1] / "prepare-device-context.py"),
               "--finalized-dir", str(tmp_path / "absent"), "--finalization-sha256", "a" * 64,
               "--output-dir", str(tmp_path / "context")]
    for extra, message in [(["--ioxclient-sha256", "b" * 64], "unrelated"), ([], "filesystem operation failed")]:
        result = subprocess.run(command + extra, capture_output=True, text=True)
        assert result.returncode == 1 and message in result.stderr
        assert "Traceback" not in result.stderr
