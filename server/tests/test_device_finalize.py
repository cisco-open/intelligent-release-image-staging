# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Neutral multi-architecture finalization without Docker or device execution."""

import base64
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))
from iris_installer import device_finalize as f
from iris_installer.state import InstallError


def digest(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def tar_bytes(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for member, value in entries:
            archive.addfile(member, io.BytesIO(value) if member.isfile() else None)
    return buffer.getvalue()


def entry(name, value=b"", kind=tarfile.REGTYPE, target="", **fields):
    member = tarfile.TarInfo(name)
    member.type, member.size = kind, len(value) if kind in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
    member.uid, member.gid, member.mtime = 0, 0, 123456789
    member.mode = 0o755 if kind == tarfile.DIRTYPE else 0o644
    member.linkname = target
    for key, item in fields.items():
        setattr(member, key, item)
    return member, value


def layer_entries(arch):
    return [entry(name, kind=tarfile.DIRTYPE) for name in
            ("opt", "opt/iris", "opt/iris/agent", "usr", "usr/bin", "var", "run")] + [
        entry("entrypoint.sh", b"#!/bin/sh\nexec /usr/bin/python3\n", mode=0o755),
        entry("usr/bin/python3.12", b"synthetic ELF " + arch.encode(), mode=0o755, uid=3, gid=4),
        entry("usr/bin/python3", kind=tarfile.SYMTYPE, target="python3.12"),
        entry("usr/bin/python", kind=tarfile.LNKTYPE, target="usr/bin/python3.12"),
        entry("var/run", kind=tarfile.SYMTYPE, target="/run"),
        entry("opt/iris/agent/iris_agent.py", b"# runtime\n", pax_headers={"mtime": "123456789.5"})]


def image_bytes(*, compressed=True, nested=True, mutate_layer=None, mutate_config=None,
                mutate_manifest=None, mutate_index=None, outer_extra=()):
    blobs, descriptors, originals = {}, [], {}
    def blob(value, media, **extra):
        data = value if isinstance(value, bytes) else encoded(value)
        key = digest(data)
        blobs["blobs/sha256/" + key] = data
        return dict(mediaType=media, digest="sha256:" + key, size=len(data), **extra)
    for arch in ("amd64", "arm64"):
        entries = layer_entries(arch)
        if mutate_layer:
            mutate_layer(entries, arch)
        raw = tar_bytes(entries)
        packed = gzip.compress(raw, mtime=17) if compressed else raw
        config = {"os": "linux", "architecture": arch,
                  "rootfs": {"type": "layers", "diff_ids": ["sha256:" + digest(raw)]},
                  "config": {"Entrypoint": ["/entrypoint.sh"], "Env": ["IRIS_LOG=off"], "WorkingDir": "/opt/iris"},
                  "history": [{"created_by": "authenticated neutral build"}]}
        if mutate_config:
            mutate_config(config, arch)
        manifest = {"schemaVersion": 2, "mediaType": f.MANIFEST,
                    "config": blob(config, f.CONFIG),
                    "layers": [blob(packed, f.LAYER + ("+gzip" if compressed else ""))]}
        if mutate_manifest:
            mutate_manifest(manifest, arch)
        descriptors.append(blob(manifest, f.MANIFEST,
            platform={"os": "linux", "architecture": arch}, annotations={"org.opencontainers.image.title": arch}))
        originals[arch] = {"layer": raw, "config": config}
    index = {"schemaVersion": 2, "mediaType": f.INDEX, "manifests": descriptors}
    if mutate_index:
        mutate_index(index)
    root = {"schemaVersion": 2, "manifests": [blob(index, f.INDEX,
        annotations={"org.opencontainers.image.ref.name": "iris-neutral:test"})]} if nested else index
    entries = [entry("oci-layout", encoded({"imageLayoutVersion": "1.0.0"})), entry("index.json", encoded(root))]
    entries += [entry(name, value) for name, value in sorted(blobs.items())] + list(outer_extra)
    return tar_bytes(entries), originals


@pytest.fixture
def roots(tmp_path):
    directory = tmp_path / "roots"
    directory.mkdir()
    for index, name in enumerate(("root-a", "root-b"), 1):
        algorithm = b"ssh-ed25519"
        wire = len(algorithm).to_bytes(4, "big") + algorithm + (32).to_bytes(4, "big") + bytes([index]) * 32
        (directory / (name + ".pub")).write_bytes(b"ssh-ed25519 " + base64.b64encode(wire) + b" fixture public root\n")
    return directory


def run(tmp_path, roots, *, payload=None, output="result", **options):
    source = tmp_path / "source.oci.tar"
    if payload is not None:
        source.write_bytes(payload)
    elif not source.exists():
        source.write_bytes(image_bytes()[0])
    args = dict(expected_archive_sha256=digest(source.read_bytes()), neutral_source_sha256="a" * 64,
                finalizer_source_commit="b" * 40)
    args.update(options)
    return f.finalize(source, roots, tmp_path / output, **args)


def read_image(path):
    with tarfile.open(path) as archive:
        members = {member.name: archive.extractfile(member).read() for member in archive if member.isfile()}
    def blob(descriptor):
        data = members["blobs/sha256/" + descriptor["digest"].split(":")[1]]
        assert len(data) == descriptor["size"]
        assert "sha256:" + digest(data) == descriptor["digest"]
        return data
    root = json.loads(members["index.json"])
    index = json.loads(blob(root["manifests"][0])) if len(root["manifests"]) == 1 else root
    images = {}
    for descriptor in index["manifests"]:
        manifest = json.loads(blob(descriptor))
        assert len(manifest["layers"]) == 1
        config = json.loads(blob(manifest["config"]))
        layer = manifest["layers"][0]
        raw = gzip.decompress(blob(layer)) if layer["mediaType"].endswith("+gzip") else blob(layer)
        assert config["rootfs"]["diff_ids"] == ["sha256:" + digest(raw)]
        images[descriptor["platform"]["architecture"]] = {"config": config, "layer": raw}
    return images


def records(raw):
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        return {member.name: (f._record(member), archive.extractfile(member).read() if member.isfile() else None)
                for member in archive}


@pytest.mark.parametrize("compressed", [True, False])
@pytest.mark.parametrize("nested", [True, False])
def test_two_architectures_preserve_all_runtime_and_config_bytes(tmp_path, roots, compressed, nested):
    payload, originals = image_bytes(compressed=compressed, nested=nested)
    receipt = run(tmp_path, roots, payload=payload)
    output = tmp_path / "result" / "iris-device.oci.tar"
    images = read_image(output)
    assert set(images) == {"amd64", "arm64"}
    expected = tmp_path / "expected"
    expected.mkdir()
    f.instruction_module().render_device_trust(roots, expected)
    for arch, image in images.items():
        before, after = records(originals[arch]["layer"]), records(image["layer"])
        assert list(after)[:len(before)] == list(before)
        assert set(after) - set(before) == set(f.TRUST)
        for name in before:
            assert after[name] == before[name]
        for name in f.TRUST:
            metadata, value = after[name]
            assert value == (expected / Path(name).name).read_bytes()
            assert (metadata["mode"], metadata["uid"], metadata["gid"]) == (0o444, 0, 0)
        new_config, old_config = copy.deepcopy(image["config"]), copy.deepcopy(originals[arch]["config"])
        new_config.pop("rootfs")
        old_config.pop("rootfs")
        assert new_config == old_config
    assert receipt["format"] == "iris-device-finalized-v1"
    assert receipt["neutral_source_sha256"] == "a" * 64 and "source_sha256" not in receipt
    assert receipt["archive_sha256"] == digest(output.read_bytes())
    assert json.loads((output.parent / "iris-device.oci.tar.finalization.json").read_bytes()) == receipt
    assert output.stat().st_mode & 0o777 == 0o444
    assert not list(tmp_path.glob(".iris-*"))


def test_same_neutral_inputs_produce_identical_archives_and_receipts(tmp_path, roots):
    assert run(tmp_path, roots, output="one") == run(tmp_path, roots, output="two")
    for name in ("iris-device.oci.tar", "iris-device.oci.tar.finalization.json"):
        assert (tmp_path / "one" / name).read_bytes() == (tmp_path / "two" / name).read_bytes()


def test_finalized_input_is_refused_even_for_identical_roots(tmp_path, roots):
    run(tmp_path, roots)
    payload = (tmp_path / "result/iris-device.oci.tar").read_bytes()
    with pytest.raises(InstallError, match="already contains active trust"):
        run(tmp_path, roots, payload=payload, output="again")
    assert not (tmp_path / "again").exists()


@pytest.mark.parametrize("kind", ["absolute", "parent", "duplicate", "whiteout", "fifo", "device", "link-parent", "link-escape", "hardlink-missing", "trust-active", "signature"])
def test_unsafe_runtime_refused_without_published_output(tmp_path, roots, kind):
    def mutate(entries, arch):
        if kind == "absolute": entries.append(entry("/escape", b"x"))
        elif kind == "parent": entries.append(entry("../escape", b"x"))
        elif kind == "duplicate": entries.append(entry("entrypoint.sh", b"changed"))
        elif kind == "whiteout": entries.append(entry("opt/.wh.iris", b""))
        elif kind == "fifo": entries.append(entry("fifo", kind=tarfile.FIFOTYPE))
        elif kind == "device": entries.append(entry("devnode", kind=tarfile.CHRTYPE))
        elif kind == "link-parent":
            entries[:] = [(member, value) for member, value in entries if member.name != "opt/iris/agent"]
            entries.append(entry("opt/iris/agent", kind=tarfile.SYMTYPE, target="/tmp/other"))
        elif kind == "link-escape": entries.append(entry("alias", kind=tarfile.SYMTYPE, target="../outside"))
        elif kind == "hardlink-missing": entries.append(entry("alias", kind=tarfile.LNKTYPE, target="absent"))
        elif kind == "trust-active": entries.append(entry(f.TRUST[0], b"old active root"))
        elif kind == "signature": entries.append(entry("package.sign", b"signature"))
    with pytest.raises(InstallError):
        run(tmp_path, roots, payload=image_bytes(mutate_layer=mutate)[0])
    assert not (tmp_path / "result").exists()
    assert not list(tmp_path.glob(".iris-*"))


@pytest.mark.parametrize("kind", ["platform", "duplicate-platform", "third-platform", "multi-layer", "diff-id", "external", "subject", "signed-annotation", "extra-blob", "outer-symlink", "outer-signature"])
def test_unrecognized_oci_or_incomplete_integrity_refused(tmp_path, roots, kind):
    options = {}
    if kind == "platform": options["mutate_index"] = lambda index: index["manifests"][0]["platform"].update(os="windows")
    elif kind == "duplicate-platform": options["mutate_index"] = lambda index: index["manifests"][1].update(platform=index["manifests"][0]["platform"])
    elif kind == "third-platform": options["mutate_index"] = lambda index: index["manifests"].append(index["manifests"][0])
    elif kind == "multi-layer": options["mutate_manifest"] = lambda manifest, arch: manifest["layers"].append(manifest["layers"][0])
    elif kind == "diff-id": options["mutate_config"] = lambda config, arch: config["rootfs"].update(diff_ids=["sha256:" + "0" * 64])
    elif kind == "external": options["mutate_manifest"] = lambda manifest, arch: manifest["layers"][0].update(urls=["https://invalid.example/layer"])
    elif kind == "subject": options["mutate_manifest"] = lambda manifest, arch: manifest.update(subject={})
    elif kind == "signed-annotation": options["mutate_index"] = lambda index: index.update(annotations={"dev.cosignproject.cosign/signature": "signed"})
    elif kind == "extra-blob": options["outer_extra"] = [entry("blobs/sha256/" + "0" * 64, b"unreferenced")]
    elif kind == "outer-symlink": options["outer_extra"] = [entry("alias", kind=tarfile.SYMTYPE, target="index.json")]
    elif kind == "outer-signature": options["outer_extra"] = [entry("package.cert", b"signature")]
    with pytest.raises(InstallError):
        run(tmp_path, roots, payload=image_bytes(**options)[0])
    assert not (tmp_path / "result").exists()


@pytest.mark.parametrize("kind", ["wrong-archive", "symlink-source", "symlink-root", "duplicate-root", "private-root", "extra-root", "missing-root", "bad-identity", "existing-output", "unsafe-parent"])
def test_input_custody_and_publication_guards(tmp_path, roots, kind):
    source = tmp_path / "source.oci.tar"
    source.write_bytes(image_bytes()[0])
    options = {}
    if kind == "wrong-archive": options["expected_archive_sha256"] = "0" * 64
    elif kind == "symlink-source":
        source.rename(tmp_path / "real")
        source.symlink_to(tmp_path / "real")
    elif kind == "symlink-root":
        (roots / "root-a.pub").rename(tmp_path / "real.pub")
        (roots / "root-a.pub").symlink_to(tmp_path / "real.pub")
    elif kind == "duplicate-root": (roots / "root-b.pub").write_bytes((roots / "root-a.pub").read_bytes())
    elif kind == "private-root": (roots / "root-a.pub").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    elif kind == "extra-root": (roots / "extra").write_text("extra")
    elif kind == "missing-root": (roots / "root-a.pub").unlink()
    elif kind == "bad-identity": options["neutral_source_sha256"] = "not-authenticated"
    elif kind == "existing-output": (tmp_path / "result").mkdir()
    elif kind == "unsafe-parent": tmp_path.chmod(0o777)
    with pytest.raises(InstallError):
        run(tmp_path, roots, **options)
    if kind != "existing-output": assert not (tmp_path / "result").exists()


@pytest.mark.parametrize("target", ["source", "root", "directory"])
def test_input_changes_during_rewrite_abort_before_publication(tmp_path, roots, monkeypatch, target):
    rewrite = f._rewrite
    def changing(*args, **kwargs):
        result = rewrite(*args, **kwargs)
        if target == "source": (tmp_path / "source.oci.tar").write_bytes(b"changed")
        elif target == "root": (roots / "root-a.pub").write_bytes((roots / "root-b.pub").read_bytes())
        else: (roots / "extra.pub").write_text("new input")
        return result
    monkeypatch.setattr(f, "_rewrite", changing)
    with pytest.raises(InstallError, match="changed"):
        run(tmp_path, roots)
    assert not (tmp_path / "result").exists()


def test_exclusive_directory_commit_preserves_concurrent_output(tmp_path, roots, monkeypatch):
    publish = f._publish
    def collision(parent, staging, output):
        (tmp_path / output).mkdir()
        (tmp_path / output / "owner-marker").write_text("keep")
        return publish(parent, staging, output)
    monkeypatch.setattr(f, "_publish", collision)
    with pytest.raises(InstallError, match="output already exists"):
        run(tmp_path, roots)
    assert (tmp_path / "result/owner-marker").read_text() == "keep"
    assert sorted(path.name for path in (tmp_path / "result").iterdir()) == ["owner-marker"]


def test_cli_uses_same_bounded_finalizer(tmp_path, roots):
    source = tmp_path / "neutral.oci.tar"
    source.write_bytes(image_bytes()[0])
    result = subprocess.run([sys.executable, str(REPO / "tools/finalize-device-image.py"),
        "--input", str(source), "--instruction-roots-dir", str(roots), "--output-dir", str(tmp_path / "cli"),
        "--expected-archive-sha256", digest(source.read_bytes()), "--neutral-source-sha256", "a" * 64,
        "--finalizer-source-commit", "b" * 40], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["format"] == "iris-device-finalized-v1"
    assert "ssh-ed25519" not in result.stdout


def test_parent_rename_cannot_redirect_publication_or_cleanup(tmp_path, roots, monkeypatch):
    parent = tmp_path / "output-parent"
    parent.mkdir(mode=0o700)
    source = tmp_path / "neutral.oci.tar"
    source.write_bytes(image_bytes()[0])
    rewrite = f._rewrite
    def moved(*args, **kwargs):
        result = rewrite(*args, **kwargs)
        parent.rename(tmp_path / "original-parent")
        parent.mkdir(mode=0o700)
        (parent / "keep").write_text("foreign")
        return result
    monkeypatch.setattr(f, "_rewrite", moved)
    with pytest.raises(InstallError, match="parent changed"):
        f.finalize(source, roots, parent / "output", expected_archive_sha256=digest(source.read_bytes()),
                   neutral_source_sha256="a" * 64, finalizer_source_commit="b" * 40)
    assert sorted(path.name for path in parent.iterdir()) == ["keep"]
    assert list((tmp_path / "original-parent").iterdir()) == []


@pytest.mark.parametrize("kind", ["json-duplicate", "json-size", "layer-size", "trailing", "blob-digest", "blob-size", "metadata-size"])
def test_bounded_reader_and_digest_failures(tmp_path, roots, monkeypatch, kind):
    payload = image_bytes()[0]
    if kind == "layer-size": monkeypatch.setattr(f, "MAX_LAYER", 100)
    elif kind == "json-size": monkeypatch.setattr(f, "MAX_JSON", 50)
    elif kind == "trailing": payload += b"hidden second payload"
    else:
        with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
            entries = [(copy.copy(member), archive.extractfile(member).read()) for member in archive]
        if kind == "json-duplicate":
            entries = [entry(member.name, b'{"schemaVersion":2,"schemaVersion":2}' if member.name == "index.json" else data)
                       for member, data in entries]
        elif kind == "blob-digest":
            member, data = next((member, data) for member, data in entries if member.name.startswith("blobs/"))
            entries = [entry(item.name, b"X" + content[1:] if item.name == member.name else content)
                       for item, content in entries]
        elif kind == "blob-size":
            root = json.loads(next(data for member, data in entries if member.name == "index.json"))
            root["manifests"][0]["size"] += 1
            entries = [entry(member.name, encoded(root) if member.name == "index.json" else data) for member, data in entries]
        elif kind == "metadata-size":
            entries.append(entry("unused", b"x", pax_headers={"comment": "x" * 20000}))
        payload = tar_bytes(entries)
    with pytest.raises(InstallError):
        run(tmp_path, roots, payload=payload)
    assert not (tmp_path / "result").exists()


def test_root_parser_failure_is_sanitized_at_cli(tmp_path, roots):
    source = tmp_path / "neutral.oci.tar"
    source.write_bytes(image_bytes()[0])
    (roots / "root-a.pub").write_text("PRIVATE SENTINEL MUST NOT LEAK")
    result = subprocess.run([sys.executable, str(REPO / "tools/finalize-device-image.py"),
        "--input", str(source), "--instruction-roots-dir", str(roots), "--output-dir", str(tmp_path / "cli"),
        "--expected-archive-sha256", digest(source.read_bytes()), "--neutral-source-sha256", "a" * 64,
        "--finalizer-source-commit", "b" * 40], capture_output=True, text=True)
    assert result.returncode == 1
    assert "invalid public instruction roots" in result.stderr
    assert "SENTINEL" not in result.stderr and "Traceback" not in result.stderr


@pytest.mark.parametrize("compressed,nested", [(True, True), (True, False), (False, True), (False, False)])
def test_read_only_inspector_shares_exact_neutral_contract(tmp_path, roots, monkeypatch, compressed, nested):
    payload, originals = image_bytes(compressed=compressed, nested=nested)
    source = tmp_path / "neutral.oci.tar"
    source.write_bytes(payload)
    def forbidden():
        pytest.fail("read-only inspection must not access trust rendering")
    monkeypatch.setattr(f, "instruction_module", forbidden)
    result = f.inspect_neutral(source, expected_archive_sha256=digest(payload))
    assert result["format"] == "iris-device-neutral-inspection-v1"
    assert set(result["platforms"]) == {"amd64", "arm64"}
    for arch, platform in result["platforms"].items():
        assert set(platform) == {"manifest_digest", "config_digest", "layer_digest", "diff_id", "runtime_inventory_sha256", "runtime_members"}
        assert platform["diff_id"] == "sha256:" + digest(originals[arch]["layer"])
        assert platform["runtime_members"] == len(layer_entries(arch))
    assert source.read_bytes() == payload
    assert sorted(path.name for path in tmp_path.iterdir()) == ["neutral.oci.tar", "roots"]


@pytest.mark.parametrize("kind", ["active-trust", "digest", "extra-blob", "runtime-path", "changed-input"])
def test_inspector_refuses_same_unsafe_inputs_as_finalizer(tmp_path, monkeypatch, kind):
    options = {}
    if kind == "active-trust": options["mutate_layer"] = lambda entries, arch: entries.append(entry(f.TRUST[0], b"active"))
    elif kind == "extra-blob": options["outer_extra"] = [entry("blobs/sha256/" + "0" * 64, b"extra")]
    elif kind == "runtime-path": options["mutate_layer"] = lambda entries, arch: entries.append(entry("../escape", b"unsafe"))
    source = tmp_path / "neutral.oci.tar"
    source.write_bytes(image_bytes(**options)[0])
    if kind == "changed-input":
        original = f._rewrite
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            source.write_bytes(b"changed")
            return result
        monkeypatch.setattr(f, "_rewrite", changed)
    expected = "0" * 64 if kind == "digest" else digest(source.read_bytes())
    with pytest.raises(InstallError):
        f.inspect_neutral(source, expected_archive_sha256=expected)
