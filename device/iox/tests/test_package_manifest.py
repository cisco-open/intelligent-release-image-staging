# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Exercise signing-input manifests against complete miniature IOx archives."""

import gzip
import hashlib
import io
from pathlib import Path
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import package_manifest as pm


def _tar(members):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        for name, data in members:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o444
            archive.addfile(member, io.BytesIO(data))
    return result.getvalue()


def _wrapper(arch="amd64", algorithm="SHA256", envelope=None):
    artifacts = gzip.compress(_tar([("rootfs.tar", b"unchanged image bytes")]))
    members = [("package.yaml", f"app:\n  cpuarch: {arch}\n".encode()),
               ("artifacts.tar.gz", artifacts),
               (".package.metadata", b'{"packageInfo":{}}')]
    if envelope is not None:
        members.append(("envelope_package.tar.gz", gzip.compress(envelope)))
    manifest = "".join(
        f"{algorithm}({name})= {hashlib.new(algorithm.lower(), data).hexdigest()}\n"
        for name, data in members).encode()
    return members + [("package.mf", manifest)]


def _read(path):
    with tarfile.open(path, mode="r:*") as archive:
        return {m.name: archive.extractfile(m).read() for m in archive}


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
@pytest.mark.parametrize("algorithm", ["SHA256", "SHA512"])
def test_prepare_verifies_sha512_and_preserves_payloads(tmp_path, arch, algorithm):
    source, output = tmp_path / "in.tar", tmp_path / "out.tar"
    original = _tar(_wrapper(arch, algorithm))
    source.write_bytes(original)
    pm.prepare(source, output)
    pm.verify(output)
    assert source.read_bytes() == original
    before, after = _read(source), _read(output)
    assert after.pop("package.mf") == b"".join(
        f"SHA512({name})= {hashlib.sha512(data).hexdigest()}\n".encode()
        for name, data in before.items() if name != "package.mf")
    before.pop("package.mf")
    assert after == before
    with tarfile.open(output) as archive:
        assert all(member.mode == 0o444 for member in archive)


def test_verify_rejects_sha256(tmp_path):
    source = tmp_path / "input.tar"
    source.write_bytes(_tar(_wrapper()))
    with pytest.raises(pm.ManifestError, match="must use SHA512"):
        pm.verify(source)


@pytest.mark.parametrize("name", ["package.sign", "package.cert", "nested/package.sign"])
@pytest.mark.parametrize("nested", [False, True])
def test_signed_wrappers_are_never_rewritten(tmp_path, name, nested):
    signed = _tar(_wrapper() + [(name, b"existing signature")])
    original = _tar(_wrapper(envelope=signed)) if nested else signed
    source, output = tmp_path / "input.tar", tmp_path / "output.tar"
    source.write_bytes(original)
    with pytest.raises(pm.ManifestError, match="refusing signed"):
        pm.prepare(source, output)
    assert source.read_bytes() == original
    assert not output.exists()


def test_prepare_normalizes_inner_envelope_before_outer_manifest(tmp_path):
    source, output = tmp_path / "input.tar", tmp_path / "output.tar"
    source.write_bytes(_tar(_wrapper(envelope=_tar(_wrapper()))))
    pm.prepare(source, output)
    pm.verify(output)
    with tarfile.open(fileobj=io.BytesIO(_read(output)["envelope_package.tar.gz"])) as inner:
        pm._verify(inner, pm._members(inner), sha512_only=True)


def test_verify_does_not_hide_a_sha256_inner_manifest(tmp_path):
    source = tmp_path / "input.tar"
    source.write_bytes(_tar(_wrapper(algorithm="SHA512", envelope=_tar(_wrapper()))))
    with pytest.raises(pm.ManifestError, match="must use SHA512"):
        pm.verify(source)


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE])
def test_nonregular_package_members_are_rejected(tmp_path, kind):
    source, output = tmp_path / "input.tar", tmp_path / "output.tar"
    source.write_bytes(_tar(_wrapper()))
    with tarfile.open(source, "a") as archive:
        member = tarfile.TarInfo("alias")
        member.type = kind
        member.linkname = "package.yaml"
        archive.addfile(member)
    with pytest.raises(pm.ManifestError, match="flat, regular"):
        pm.prepare(source, output)
    assert not output.exists()


@pytest.mark.parametrize("change,reason", [
    ("hash", "hash mismatch"), ("missing", "cover every payload"),
    ("duplicate", "duplicate package"), ("self", "cannot hash"),
    ("signature", "cannot hash"), ("traversal", "flat, regular"),
    ("malformed", "invalid package.mf"), ("manifest-size", "size limit"),
])
def test_invalid_inputs_do_not_produce_a_package(tmp_path, monkeypatch, change, reason):
    members = _wrapper()
    manifest = members[-1][1]
    if change == "hash":
        members[0] = ("package.yaml", b"tampered")
    elif change == "missing":
        members.append(("extra", b"not covered"))
    elif change == "duplicate":
        members.append(members[0])
    elif change == "self":
        members[-1] = ("package.mf", manifest + b"SHA512(package.mf)= 00\n")
    elif change == "signature":
        members[-1] = ("package.mf", manifest + b"SHA512(package.sign)= 00\n")
    elif change == "traversal":
        members.append(("../escape", b"unsafe"))
    elif change == "malformed":
        members[-1] = ("package.mf", b"not a manifest\n")
    elif change == "manifest-size":
        monkeypatch.setattr(pm, "MAX_MANIFEST_BYTES", 1)
    source, output = tmp_path / "input.tar", tmp_path / "output.tar"
    source.write_bytes(_tar(members))
    with pytest.raises(pm.ManifestError, match=reason):
        pm.prepare(source, output)
    assert not output.exists()
    assert not (tmp_path.parent / "escape").exists()


def test_existing_output_is_preserved(tmp_path):
    source, output = tmp_path / "input.tar", tmp_path / "output.tar"
    source.write_bytes(_tar(_wrapper()))
    output.write_bytes(b"keep existing package")
    with pytest.raises(FileExistsError):
        pm.prepare(source, output)
    assert output.read_bytes() == b"keep existing package"


def test_same_input_output_is_refused(tmp_path):
    source = tmp_path / "input.tar"
    original = _tar(_wrapper())
    source.write_bytes(original)
    with pytest.raises(FileExistsError):
        pm.prepare(source, source)
    assert source.read_bytes() == original
