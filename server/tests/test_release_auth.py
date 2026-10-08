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
        "--signer-workflow": AUTH.WORKFLOW,
        "--cert-identity": "https://github.com/" + AUTH.WORKFLOW + "@refs/tags/" + TAG,
        "--source-ref": "refs/tags/" + TAG,
        "--source-digest": COMMIT, "--signer-digest": COMMIT,
        "--bundle": "bundle.jsonl",
    }.items():
        assert command[command.index(flag) + 1] == value
    assert "--deny-self-hosted-runners" in command


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


def test_workflow_attests_before_publishing_and_pins_actions():
    text = (ROOT / ".github/workflows/release.yml").read_text()
    assert text.index("tools/release-auth.py verify") < text.index("gh release create")
    assert "id-token: write" in text and "attestations: write" in text
    assert "subject-path: release-assets/*" in text
    assert "--clobber" not in text
    import re
    for action in re.findall(r"uses: (\S+)", text):
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
