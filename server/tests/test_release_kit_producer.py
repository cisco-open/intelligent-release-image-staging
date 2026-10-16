# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Local producer tests inspect synthetic images, never attest or execute them."""

import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from iris_installer.state import InstallError
from test_device_finalize import image_bytes, tar_bytes, entry

SPEC = importlib.util.spec_from_file_location("iris_release_kit_producer", ROOT / "tools/build-release-kit.py")
producer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(producer)
TAG, COMMIT = "v2026.10.09", "a" * 40


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


def docker_bytes(change=None, *, compressed=False):
    layer = tar_bytes([entry("runtime", b"synthetic runtime")])
    config = {"os": "linux", "architecture": "amd64",
              "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(layer).hexdigest()]},
              "config": {"Labels": {"org.opencontainers.image.revision": COMMIT}}}
    manifests = [{"Config": "config.json", "Layers": ["layer.tar"], "RepoTags": ["ignored:tag"]}]
    if change in ("architecture", "os"):
        config[change] = "wrong"
    elif change == "revision":
        config["config"]["Labels"]["org.opencontainers.image.revision"] = "b" * 40
    elif change == "layer-digest":
        config["rootfs"]["diff_ids"] = ["sha256:" + "0" * 64]
    elif change == "duplicate-layer":
        manifests[0]["Layers"] *= 2
        config["rootfs"]["diff_ids"] *= 2
    elif change == "missing-layer":
        manifests[0]["Layers"] = ["absent.tar"]
    elif change == "multiple-images":
        manifests *= 2
    elif change == "unsafe-config":
        manifests[0]["Config"] = "../outside"
    elif change == "extra-manifest-field":
        manifests[0]["execute"] = "nothing"
    elif change == "invalid-tags":
        manifests[0]["RepoTags"] = [False]
    config_bytes = encoded(config)
    if change == "duplicate-json":
        config_bytes = config_bytes.replace(b"{", b'{"architecture":"amd64",', 1)
    entries = [entry("manifest.json", encoded(manifests)), entry("config.json", config_bytes),
               entry("layer.tar", gzip.compress(layer, mtime=0) if compressed else layer)]
    if change == "duplicate-member":
        entries.append(entries[1])
    return tar_bytes(entries), "sha256:" + hashlib.sha256(config_bytes).hexdigest()


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    source = tmp_path / "inputs"
    source.mkdir()
    result = {}
    for role in producer.kit.ROLES:
        path = source / producer.NAMES[role]
        data = (docker_bytes()[0] if role in ("server-image", "console-image") else
                image_bytes()[0] if role == "device-runtime" else
                gzip.compress(tar_bytes([entry("payload", b"synthetic source or tools")]), mtime=0))
        path.write_bytes(data)
        result[role] = path
    output = tmp_path / "release-assets"
    output.mkdir(mode=0o700)
    checksum = hashlib.sha256(result["device-runtime"].read_bytes()).hexdigest()
    index = producer.inspect_neutral(result["device-runtime"], expected_archive_sha256=checksum)["index_digest"]
    (source / "neutral.manifest").write_text("format=iris-device-neutral-oci-v1\ntrust_mode=neutral\n"
        + "source_sha256=" + "c" * 64 + "\nindex_digest=" + index
        + "\narchive_sha256=" + checksum + "\nplatforms=linux/amd64,linux/arm64\n")
    monkeypatch.setattr(producer.kit.subprocess, "run", lambda *_a, **_k: pytest.fail("No subprocess or payload execution"))
    return result, output


def assemble(inputs):
    paths, output = inputs
    return producer.assemble(paths, output, tag=TAG, commit=COMMIT,
        neutral_receipt=paths["device-runtime"].parent / "neutral.manifest")


def test_producer_binds_actual_configs_and_both_neutral_platforms(inputs):
    paths, output = inputs
    manifest = assemble(inputs)
    assert manifest == json.loads((output / "release-kit.json").read_bytes())
    assert manifest["profile"] == "prepared-host" and manifest["commit"] == COMMIT
    assert set(path.name for path in output.iterdir()) == set(producer.NAMES.values()) | {"release-kit.json"}
    for role, record in manifest["assets"].items():
        payload = output / record["name"]
        assert payload.read_bytes() == paths[role].read_bytes()
        assert record["sha256"] == hashlib.sha256(payload.read_bytes()).hexdigest()
        assert record["size"] == payload.stat().st_size
        assert payload.stat().st_mode & 0o777 == 0o644 and payload.stat().st_nlink == 1
    assert manifest["assets"]["server-image"]["image_digest"] == docker_bytes()[1]
    assert manifest["assets"]["device-runtime"]["platforms"] == ["linux/amd64", "linux/arm64"]
    assert manifest["assets"]["device-runtime"]["neutral_source_sha256"] == "c" * 64
    inspection = producer.inspect_neutral(paths["device-runtime"],
        expected_archive_sha256=manifest["assets"]["device-runtime"]["sha256"])
    assert manifest["assets"]["device-runtime"]["image_digest"] == inspection["index_digest"]
    assert not any(name.startswith("attestation") for name in os.listdir(output))


@pytest.mark.parametrize("change", ["architecture", "os", "revision", "layer-digest",
    "missing-layer", "multiple-images", "unsafe-config", "extra-manifest-field", "invalid-tags", "duplicate-json", "duplicate-member"])
def test_invalid_docker_archives_publish_nothing(inputs, change):
    paths, output = inputs
    paths["server-image"].write_bytes(docker_bytes(change)[0])
    with pytest.raises(InstallError):
        assemble(inputs)
    assert list(output.iterdir()) == []


@pytest.mark.parametrize("compressed", [False, True])
def test_repeated_layer_references_keep_each_verified_diff_id(inputs, compressed):
    paths, _ = inputs
    payload, config_digest = docker_bytes("duplicate-layer", compressed=compressed)
    paths["server-image"].write_bytes(payload)
    assert assemble(inputs)["assets"]["server-image"]["image_digest"] == config_digest


def test_gzip_layer_expansion_is_bounded(inputs, monkeypatch):
    paths, output = inputs
    data, _ = docker_bytes(compressed=True)
    paths["server-image"].write_bytes(data)
    # Direct image inspection avoids changing unrelated archive-size limits.
    monkeypatch.setattr(producer.kit, "MAX_ASSET", 1024)
    with pytest.raises(InstallError, match="expansion limit"):
        producer.docker_config(paths["server-image"], COMMIT)
    assert list(output.iterdir()) == []


def test_named_compressed_blob_hash_must_match_stored_bytes(inputs):
    paths, output = inputs
    payload, _ = docker_bytes(compressed=True)
    import io
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
        members = {member.name: archive.extractfile(member).read() for member in archive}
    manifest = json.loads(members["manifest.json"])
    name = "blobs/sha256/" + "0" * 64
    manifest[0]["Layers"] = [name]
    paths["server-image"].write_bytes(tar_bytes([entry("manifest.json", encoded(manifest)),
        entry("config.json", members["config.json"]), entry(name, members["layer.tar"])]))
    with pytest.raises(InstallError, match="content identity"):
        assemble(inputs)
    assert list(output.iterdir()) == []


@pytest.mark.parametrize("change", ["missing-arm", "already-trusted", "wrong-format", "symlink", "changed-during-snapshot"])
def test_invalid_neutral_or_input_files_publish_nothing(inputs, monkeypatch, change):
    paths, output = inputs
    if change == "missing-arm":
        paths["device-runtime"].write_bytes(image_bytes(mutate_index=lambda index: index["manifests"].pop())[0])
    elif change == "already-trusted":
        paths["device-runtime"].write_bytes(image_bytes(mutate_layer=lambda entries, _arch:
            entries.append(entry("opt/iris/agent/iris-root.allowed_signers", b"preexisting trust")))[0])
    elif change == "wrong-format":
        paths["source"].write_bytes(tar_bytes([entry("payload", b"uncompressed")]))
    elif change == "symlink":
        other = paths["source"].with_name("other")
        paths["source"].rename(other)
        paths["source"].symlink_to(other)
    else:
        original = producer.kit._hash
        def changed(fd, maximum, output=None):
            result = original(fd, maximum, output)
            original_path = Path(os.readlink("/proc/self/fd/" + str(fd)))
            if original_path == paths["source"]:
                original_path.write_bytes(b"different")
            return result
        monkeypatch.setattr(producer.kit, "_hash", changed)
    with pytest.raises(InstallError):
        assemble(inputs)
    assert list(output.iterdir()) == []


def test_existing_asset_is_not_replaced(inputs):
    _, output = inputs
    existing = output / "iris.tgz"
    existing.write_bytes(b"owner artifact")
    with pytest.raises(InstallError, match="never replaces"):
        assemble(inputs)
    assert existing.read_bytes() == b"owner artifact" and len(list(output.iterdir())) == 1


@pytest.mark.parametrize("change", ["missing", "duplicate", "rooted", "source-commit", "index", "archive", "platforms", "unknown"])
def test_neutral_builder_receipt_is_required_exact_and_not_self_authorizing(inputs, change):
    paths, output = inputs
    path = paths["device-runtime"].parent / "neutral.manifest"
    data = path.read_text()
    if change == "missing":
        data = "\n".join(line for line in data.splitlines() if not line.startswith("source_sha256="))
    elif change == "duplicate":
        data += "source_sha256=" + "c" * 64 + "\n"
    elif change == "rooted":
        data = data.replace("trust_mode=neutral", "trust_mode=rooted")
    elif change == "source-commit":
        data = data.replace("c" * 64, COMMIT)
    elif change == "unknown":
        data += "verifier=own-code\n"
    else:
        prefix = {"index": "index_digest", "archive": "archive_sha256", "platforms": "platforms"}[change]
        data = "\n".join(prefix + "=wrong" if line.startswith(prefix + "=") else line for line in data.splitlines())
    path.write_text(data)
    with pytest.raises(InstallError):
        assemble(inputs)
    assert list(output.iterdir()) == []


def test_publication_failure_rolls_back_only_our_exact_outputs(inputs, monkeypatch):
    _, output = inputs
    original, links = os.link, []
    def raced(source, target, **kwargs):
        assert kwargs["src_dir_fd"] != kwargs["dst_dir_fd"]
        links.append(target)
        if len(links) == 2:
            (output / target).write_bytes(b"unrelated concurrent artifact")
        return original(source, target, **kwargs)
    monkeypatch.setattr(producer.os, "link", raced)
    with pytest.raises(FileExistsError):
        assemble(inputs)
    assert [path.name for path in output.iterdir()] == [links[1]]
    assert (output / links[1]).read_bytes() == b"unrelated concurrent artifact"


def test_replaced_output_parent_refuses_publication_and_preserves_substitute(inputs, monkeypatch):
    _, output = inputs
    moved = output.with_name("original-release-assets")
    original, replaced = producer._parent_current, False
    def moved_parent(path, descriptor):
        nonlocal replaced
        if not replaced:
            replaced = True
            output.rename(moved)
            output.mkdir(mode=0o700)
            (output / "owner-file").write_bytes(b"preserve")
        return original(path, descriptor)
    monkeypatch.setattr(producer, "_parent_current", moved_parent)
    with pytest.raises(InstallError, match="directory changed"):
        assemble(inputs)
    assert list(moved.iterdir()) == []
    assert (output / "owner-file").read_bytes() == b"preserve"


def test_producer_help_is_explicit_about_scope(capsys):
    with pytest.raises(SystemExit) as result:
        producer.main(["--help"])
    assert result.value.code == 0
    text = capsys.readouterr().out
    assert "prepared-host" in text and "neither builds nor signs" in text
