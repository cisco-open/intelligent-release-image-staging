# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Release authentication fails closed and binds artifacts to the public identity."""

import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("release_auth", ROOT / "tools/release-auth.py")
AUTH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUTH)
TAG = "v2026.09.29"
COMMIT = "a" * 40


@pytest.fixture
def release(tmp_path):
    artifact = tmp_path / "iris-installer_example_amd64.deb"
    artifact.write_bytes(b"test package bytes")
    manifest = {"schema": 1, "repository": AUTH.REPOSITORY, "workflow": AUTH.WORKFLOW,
                "tag": TAG, "commit": COMMIT, "assets": {
                    artifact.name: {"size": artifact.stat().st_size, "sha256": AUTH.digest(artifact)}}}
    (tmp_path / "release.json").write_text(json.dumps(manifest))
    (tmp_path / "attestations.jsonl").write_text("test bundle, never trusted without gh verification")
    (tmp_path / "SHA256SUMS").write_text("test inventory")
    return tmp_path, artifact, manifest


def test_verification_binds_every_security_identity():
    command = AUTH.verify_command(Path("installer.deb"), TAG, COMMIT, Path("bundle.jsonl"))
    for flag, value in {
        "--repo": AUTH.REPOSITORY,
        "--cert-oidc-issuer": "https://token.actions.githubusercontent.com",
        "--cert-identity": "https://github.com/" + AUTH.WORKFLOW + "@refs/tags/" + TAG,
        "--source-ref": "refs/tags/" + TAG,
        "--source-digest": COMMIT, "--signer-digest": COMMIT,
        "--bundle": "bundle.jsonl",
    }.items():
        assert command[command.index(flag) + 1] == value
    assert "--deny-self-hosted-runners" in command
    # GitHub CLI rejects multiple signer selectors. The exact certificate SAN
    # already binds both the workflow path and release tag.
    selectors = ("--cert-identity", "--cert-identity-regex", "--signer-repo", "--signer-workflow")
    assert sum(flag in command for flag in selectors) == 1


@pytest.mark.parametrize("tag", ["main", "v2026.09.29;echo injected", "../v2026.09.29", "v1.2.3"])
def test_rejects_nonrelease_refs(tag):
    with pytest.raises(ValueError):
        AUTH.verify_command(Path("installer.deb"), tag, COMMIT)


def test_verifies_manifest_before_reading_and_each_deb_directly(release, monkeypatch):
    directory, artifact, _ = release
    calls = []
    monkeypatch.setattr(AUTH.subprocess, "run", lambda command, **kwargs: calls.append(command))
    AUTH.verify(directory, TAG, COMMIT)
    assert [Path(call[3]).name for call in calls] == ["release.json", artifact.name, "SHA256SUMS"]


def test_bad_signature_stops_before_reading_untrusted_inventory(release, monkeypatch):
    directory, _, _ = release
    (directory / "release.json").write_text("invalid JSON must never be read")
    def reject(command, **kwargs):
        raise subprocess.CalledProcessError(1, command)
    monkeypatch.setattr(AUTH.subprocess, "run", reject)
    with pytest.raises(subprocess.CalledProcessError):
        AUTH.verify(directory, TAG, COMMIT)


@pytest.mark.parametrize("change", ["bytes", "missing", "symlink", "tag", "commit", "repository", "workflow", "path"])
def test_rejects_tampered_or_mismatched_downloads(release, monkeypatch, change):
    directory, artifact, manifest = release
    monkeypatch.setattr(AUTH.subprocess, "run", lambda *args, **kwargs: None)
    if change == "bytes":
        artifact.write_bytes(b"tampered")
    elif change == "missing":
        artifact.unlink()
    elif change == "symlink":
        artifact.unlink()
        artifact.symlink_to(directory / "SHA256SUMS")
    elif change == "path":
        manifest["assets"]["../outside"] = manifest["assets"].pop(artifact.name)
    else:
        manifest[change] = "wrong"
    (directory / "release.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        AUTH.verify(directory, TAG, COMMIT)


def test_release_workflow_fetches_the_exact_current_source_asset():
    lines = [line.split() for line in (ROOT / "tools/aria2c-source/source.sha256").read_text().splitlines()
             if line and not line.startswith("#")]
    assert len(lines) == 1
    source_asset = lines[0][1]
    assert AUTH.SOURCE_ASSET == source_asset
    release_tag = source_asset.removesuffix("-source.tar.gz")
    text = (ROOT / ".github/workflows/release.yml").read_text()
    assert "gh release download " + release_tag + " \\\n" in text
    assert "--pattern " + source_asset + " --dir release-assets" in text


def test_workflows_separate_authentication_from_manual_publication_and_pin_actions():
    text = (ROOT / ".github/workflows/release.yml").read_text()
    publish = (ROOT / ".github/workflows/publish-release.yml").read_text()
    assert text.index("tools/release-auth.py verify") < text.index("actions/upload-artifact@")
    assert "gh release create" not in text and "contents: write" not in text
    assert "id-token: write" in text and "attestations: write" in text
    assert "subject-path: release-assets/*" in text
    assert "workflow_dispatch:" in publish and "push:" not in publish and "workflow_run:" not in publish
    assert "github.ref == 'refs/heads/main'" in publish
    assert publish.index("tools/release-stage.py prepare-publication") < publish.index("gh release create")
    assert '"$snapshot"/assets/*' in publish and "--verify-tag" in publish
    assert "id-token:" not in publish and "attestations:" not in publish
    assert "build-installer" not in publish and "make-release" not in publish
    assert "environment:" not in publish
    assert "--clobber" not in text + publish
    import re
    for action in re.findall(r"uses: (\S+)", text + publish):
        assert re.fullmatch(r"actions/[\w-]+@[a-f0-9]{40}", action)


@pytest.fixture
def prepared_inputs(tmp_path):
    repo = tmp_path / "repo"
    output = tmp_path / "assets"
    repo.mkdir()
    output.mkdir()
    (repo / "tools/aria2c-source").mkdir(parents=True)
    (repo / "deliverables").mkdir()
    (repo / "release").mkdir()
    (repo / "VERSION").write_text(TAG[1:] + "\n")
    (repo / "tools/release-auth.py").write_text("# fixture helper\n")
    source = output / AUTH.SOURCE_ASSET
    source.write_bytes(b"fixture corresponding source")
    (repo / "tools/aria2c-source/source.sha256").write_text(AUTH.digest(source) + "  " + source.name + "\n")
    pins = []
    for arch in ("x86_64", "aarch64"):
        binary = repo / "deliverables" / ("aria2c-" + arch)
        binary.write_bytes(arch.encode())
        pins.append(AUTH.digest(binary) + "  " + arch + "\n")
    (repo / "tools/aria2c.sha256").write_text("".join(pins))
    for name in ("iris.tgz", "iris.tgz.sha256", "MANIFEST.txt"):
        (repo / "release" / name).write_text("fixture " + name)
    (output / "iris-installer_fixture.deb").write_bytes(b"fixture package")
    (output / "iris-installer_fixture.deb.source.json").write_text("{}")
    for args in (["init", "-q"], ["add", "."],
                 ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Fixture"],
                 ["tag", TAG]):
        subprocess.run(["git", "-C", str(repo), *args], check=True)
    return repo, output


def test_prepares_complete_publishable_inventory(prepared_inputs):
    repo, output = prepared_inputs
    AUTH.prepare(repo, output, TAG)
    manifest = json.loads((output / "release.json").read_text())
    assert {"iris.tgz", "MANIFEST.txt", "iris-installer_fixture.deb",
            "iris-installer_fixture.deb.source.json", AUTH.SOURCE_ASSET,
            "aria2c-x86_64", "aria2c-aarch64", "release-auth.py"} <= manifest["assets"].keys()
    for record_name, record in manifest["assets"].items():
        assert AUTH.digest(output / record_name) == record["sha256"]
    subprocess.run(["sha256sum", "--check", "SHA256SUMS"], cwd=output, check=True)
    subprocess.run(["sha256sum", "--check", "aria2c.sha256"], cwd=output, check=True)


@pytest.mark.parametrize('name', sorted(AUTH.PREBUILT_CANDIDATE_ASSETS))
@pytest.mark.parametrize('kind', ['file', 'dangling-symlink'])
def test_unqualified_prebuilt_candidates_refused_before_publication_writes(prepared_inputs, name, kind):
    repo, output = prepared_inputs
    candidate = output / name
    if kind == 'file':
        candidate.write_bytes(b'local unqualified candidate')
    else:
        candidate.symlink_to(output / 'missing')
    before = {path.name: path.lstat() for path in output.iterdir()}
    with pytest.raises(ValueError, match='corresponding-source coverage checks'):
        AUTH.prepare(repo, output, TAG)
    after = {path.name: path.lstat() for path in output.iterdir()}
    assert before == after
    assert not (output / 'release.json').exists()


def test_prepare_preserves_exact_prebuilt_source_asset(prepared_inputs):
    repo, output = prepared_inputs
    target = output / "iris.tgz"
    target.write_bytes((repo / "release/iris.tgz").read_bytes())
    original = target.stat()
    AUTH.prepare(repo, output, TAG)
    current = target.stat()
    assert (current.st_ino, current.st_mtime_ns) == (original.st_ino, original.st_mtime_ns)
    assert json.loads((output / "release.json").read_text())["assets"]["iris.tgz"]["sha256"] == AUTH.digest(target)


@pytest.mark.parametrize("change", ["different", "symlink", "hardlink"])
def test_prepare_refuses_replacing_existing_prebuilt_source(prepared_inputs, change):
    import os
    repo, output = prepared_inputs
    target = output / "iris.tgz"
    original = repo / "release/iris.tgz"
    if change == "different":
        target.write_bytes(b"other source archive")
    elif change == "symlink":
        target.symlink_to(original)
    else:
        os.link(original, target)
    before = target.lstat()
    with pytest.raises(ValueError):
        AUTH.prepare(repo, output, TAG)
    after = target.lstat()
    assert (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) == (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    assert not (output / "release.json").exists()
    assert original.read_bytes() == b"fixture iris.tgz"


def test_source_copy_does_not_replace_a_concurrently_created_output(tmp_path, monkeypatch):
    source, target = tmp_path / "source", tmp_path / "destination"
    source.write_bytes(b"selected source")
    original = AUTH.os.link
    def race(candidate, destination, **kwargs):
        target.write_bytes(b"concurrent owner file")
        return original(candidate, destination, **kwargs)
    monkeypatch.setattr(AUTH.os, "link", race)
    with pytest.raises(FileExistsError):
        AUTH._copy_or_match_source(source, target)
    assert target.read_bytes() == b"concurrent owner file"
    assert set(path.name for path in tmp_path.iterdir()) == {"source", "destination"}


@pytest.mark.parametrize("change", ["tag", "dirty", "source", "inventory"])
def test_preparation_refuses_unpublishable_inputs(prepared_inputs, change):
    repo, output = prepared_inputs
    if change == "tag":
        with pytest.raises(ValueError, match="VERSION"):
            AUTH.prepare(repo, output, "v2026.09.28")
        return
    if change == "dirty":
        (repo / "tools/release-auth.py").write_text("uncommitted changes")
    elif change == "source":
        (output / AUTH.SOURCE_ASSET).write_bytes(b"wrong source")
    else:
        (output / "iris-installer_fixture.deb.source.json").unlink()
    with pytest.raises(ValueError):
        AUTH.prepare(repo, output, TAG)
