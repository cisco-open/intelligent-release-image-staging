# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Tests for device/iox/rebake_iris_tar.py — the offline IOx-package file
replacer (swaps files like the pinned catalog cert or the agent code inside an
already-built IOx package and recomputes the full OCI + package hash chain, so a
server re-key doesn't require ioxclient/aarch64 to fix the fleet package).

The fixture synthesizes a miniature but structurally-faithful arm64 package:
OCI rootfs (index.json -> manifest blob -> config blob + plain-tar layers,
plus docker-compat manifest.json/repositories), wrapped in artifacts.tar.gz +
SHA256 manifests + envelope, in the exact member order ioxclient produces.
"""
import gzip
import hashlib
import io
import json
import os
import sys
import tarfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import rebake_iris_tar as rb  # noqa: E402


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _tar_bytes(members, gz=False):
    """members: list of (name, bytes). Returns (plain or gzipped) tar bytes."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in members:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mtime = 1700000000
            t.addfile(ti, io.BytesIO(data))
    raw = buf.getvalue()
    return gzip.compress(raw, mtime=0) if gz else raw


def _mini_package(tmp_path, layer_gz=False):
    """Build a structurally-faithful miniature IOx package. Returns its path."""
    cert = b"OLD-CERT\n"
    agent = b"OLD_AGENT_CODE = 1\n"
    layer1 = _tar_bytes([("opt/iris/iris-catalog.pem", cert),
                         ("opt/iris/agent/iris_agent.py", agent)], gz=layer_gz)
    layer2 = _tar_bytes([("etc/other.conf", b"untouched\n")])
    mt = ("application/vnd.oci.image.layer.v1.tar+gzip" if layer_gz
          else "application/vnd.oci.image.layer.v1.tar")
    d1, d2 = _sha(layer1), _sha(layer2)
    diff1 = _sha(gzip.decompress(layer1)) if layer_gz else d1
    config = json.dumps({"architecture": "arm64",
                         "rootfs": {"type": "layers",
                                    "diff_ids": ["sha256:" + diff1,
                                                 "sha256:" + d2]}}).encode()
    dc = _sha(config)
    manifest = json.dumps({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                   "digest": "sha256:" + dc, "size": len(config)},
        "layers": [
            {"mediaType": mt, "digest": "sha256:" + d1, "size": len(layer1)},
            {"mediaType": "application/vnd.oci.image.layer.v1.tar",
             "digest": "sha256:" + d2, "size": len(layer2)}]}).encode()
    dm = _sha(manifest)
    index = json.dumps({"schemaVersion": 2,
                        "manifests": [{"mediaType": "application/vnd.oci.image.manifest.v1+json",
                                       "digest": "sha256:" + dm,
                                       "size": len(manifest)}]}).encode()
    mjson = json.dumps([{"Config": "blobs/sha256/" + dc,
                         "RepoTags": ["iris-iox:arm64"],
                         "Layers": ["blobs/sha256/" + d1, "blobs/sha256/" + d2],
                         "LayerSources": {
                             "sha256:" + d1: {"mediaType": mt, "size": len(layer1),
                                              "digest": "sha256:" + d1},
                             "sha256:" + d2: {"mediaType": "application/vnd.oci.image.layer.v1.tar",
                                              "size": len(layer2),
                                              "digest": "sha256:" + d2}}}]).encode()
    repos = json.dumps({"iris-iox": {"arm64": d2}}).encode()
    rootfs = _tar_bytes([
        ("oci-layout", b'{"imageLayoutVersion":"1.0.0"}'),
        ("index.json", index),
        ("manifest.json", mjson),
        ("repositories", repos),
        ("blobs/sha256/" + dm, manifest),
        ("blobs/sha256/" + dc, config),
        ("blobs/sha256/" + d1, layer1),
        ("blobs/sha256/" + d2, layer2)])

    art_gz = _tar_bytes([("rootfs.tar", rootfs)], gz=True)
    art_mf = ("SHA256(rootfs.tar)= %s\n" % _sha(rootfs)).encode()
    meta_inner = json.dumps({"packageInfo": {
        "compressedArtifactsSizeInBytes": str(len(art_gz)),
        "uncompressedArtifactsSizeInBytes": str(len(rootfs)),
        "compressedArtifactsSizeInMB": "0.0",
        "uncompressedArtifactsSizeInMB": "0.0",
        "ioxclientVersion": "1.18.0.0"}}).encode()
    pkg_yaml = b"descriptor-schema-version: '2.8'\napp:\n  cpuarch: aarch64\n"

    def mf(pairs):
        return ("".join("SHA256(%s)= %s\n" % (n, _sha(b)) for n, b in pairs)).encode()

    mf_inner = mf([(".package.metadata", meta_inner), ("artifacts.mf", art_mf),
                   ("artifacts.tar.gz", art_gz), ("package.yaml", pkg_yaml)])
    envelope = _tar_bytes([("package.yaml", pkg_yaml), ("package.mf", mf_inner),
                           (".package.metadata", meta_inner),
                           ("artifacts.mf", art_mf),
                           ("artifacts.tar.gz", art_gz)], gz=True)
    meta_outer = meta_inner
    mf_outer = mf([(".package.metadata", meta_outer), ("artifacts.mf", art_mf),
                   ("artifacts.tar.gz", art_gz),
                   ("envelope_package.tar.gz", envelope),
                   ("package.yaml", pkg_yaml)])
    pkg = tmp_path / "iris-arm64.tar"
    with tarfile.open(pkg, "w") as t:
        for name, data in [("package.yaml", pkg_yaml), ("artifacts.mf", art_mf),
                           (".package.metadata", meta_outer),
                           ("package.mf", mf_outer),
                           ("envelope_package.tar.gz", envelope),
                           ("artifacts.tar.gz", art_gz)]:
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return pkg


def _read_member(tar_path, name):
    with tarfile.open(tar_path) as t:
        return t.extractfile(name).read()


def _verify_chain(pkg_path):
    """Full self-consistency check of a package: every SHA256 manifest line
    matches its member, and the OCI chain (index -> manifest -> config +
    layers, manifest.json, diff_ids) is internally consistent. Returns the
    rootfs member map."""
    with tarfile.open(pkg_path) as t:
        outer = {m.name: t.extractfile(m).read() for m in t if m.isfile()}
    for line in outer["package.mf"].decode().strip().splitlines():
        name = line[len("SHA256("):line.index(")")]
        want = line.split("= ")[1]
        assert _sha(outer[name]) == want, "outer mf mismatch for %s" % name
    with tarfile.open(fileobj=io.BytesIO(outer["envelope_package.tar.gz"]), mode="r:gz") as t:
        env = {m.name: t.extractfile(m).read() for m in t if m.isfile()}
    for line in env["package.mf"].decode().strip().splitlines():
        name = line[len("SHA256("):line.index(")")]
        want = line.split("= ")[1]
        assert _sha(env[name]) == want, "inner mf mismatch for %s" % name
    assert env["artifacts.tar.gz"] == outer["artifacts.tar.gz"]
    with tarfile.open(fileobj=io.BytesIO(outer["artifacts.tar.gz"]), mode="r:gz") as t:
        rootfs = t.extractfile("rootfs.tar").read()
    assert ("SHA256(rootfs.tar)= %s" % _sha(rootfs)) in outer["artifacts.mf"].decode()
    with tarfile.open(fileobj=io.BytesIO(rootfs)) as t:
        rf = {m.name: t.extractfile(m).read() for m in t if m.isfile()}
    idx = json.loads(rf["index.json"])
    mdig = idx["manifests"][0]["digest"].split(":")[1]
    manifest = rf["blobs/sha256/" + mdig]
    assert len(manifest) == idx["manifests"][0]["size"]
    mj = json.loads(manifest)
    cdig = mj["config"]["digest"].split(":")[1]
    config = rf["blobs/sha256/" + cdig]
    assert len(config) == mj["config"]["size"]
    diffs = json.loads(config)["rootfs"]["diff_ids"]
    for i, layer in enumerate(mj["layers"]):
        ldig = layer["digest"].split(":")[1]
        blob = rf["blobs/sha256/" + ldig]
        assert _sha(blob) == ldig
        assert len(blob) == layer["size"]
        raw = gzip.decompress(blob) if layer["mediaType"].endswith("+gzip") else blob
        assert diffs[i] == "sha256:" + _sha(raw), "diff_id mismatch layer %d" % i
    dj = json.loads(rf["manifest.json"])[0]
    assert dj["Config"] == "blobs/sha256/" + cdig
    assert dj["Layers"] == ["blobs/sha256/" + l["digest"].split(":")[1] for l in mj["layers"]]
    return rf


def test_fixture_is_self_consistent(tmp_path):
    _verify_chain(_mini_package(tmp_path))


def test_rebake_replaces_files_and_keeps_chain_valid(tmp_path):
    pkg = _mini_package(tmp_path)
    out = tmp_path / "out.tar"
    new_cert = tmp_path / "new.pem"; new_cert.write_bytes(b"NEW-CERT\n")
    new_agent = tmp_path / "iris_agent.py"; new_agent.write_bytes(b"NEW_AGENT = 2\n")
    summary = rb.rebake(str(pkg), str(out),
                        {"opt/iris/iris-catalog.pem": str(new_cert),
                         "opt/iris/agent/iris_agent.py": str(new_agent)})
    rf = _verify_chain(out)
    # the replaced layer now carries the new contents
    idx = json.loads(rf["index.json"])
    mj = json.loads(rf["blobs/sha256/" + idx["manifests"][0]["digest"].split(":")[1]])
    found = {}
    for layer in mj["layers"]:
        blob = rf["blobs/sha256/" + layer["digest"].split(":")[1]]
        raw = gzip.decompress(blob) if layer["mediaType"].endswith("+gzip") else blob
        with tarfile.open(fileobj=io.BytesIO(raw)) as t:
            for m in t:
                if m.name in ("opt/iris/iris-catalog.pem", "opt/iris/agent/iris_agent.py"):
                    found[m.name] = t.extractfile(m).read()
    assert found["opt/iris/iris-catalog.pem"] == b"NEW-CERT\n"
    assert found["opt/iris/agent/iris_agent.py"] == b"NEW_AGENT = 2\n"
    assert set(summary["replaced"]) == {"opt/iris/iris-catalog.pem",
                                        "opt/iris/agent/iris_agent.py"}


def test_rebake_handles_gzip_layers(tmp_path):
    pkg = _mini_package(tmp_path, layer_gz=True)
    out = tmp_path / "out.tar"
    new_cert = tmp_path / "new.pem"; new_cert.write_bytes(b"NEW-CERT\n")
    rb.rebake(str(pkg), str(out), {"opt/iris/iris-catalog.pem": str(new_cert)})
    _verify_chain(out)


def test_untouched_layers_and_member_order_preserved(tmp_path):
    pkg = _mini_package(tmp_path)
    out = tmp_path / "out.tar"
    new_cert = tmp_path / "new.pem"; new_cert.write_bytes(b"NEW-CERT\n")
    rb.rebake(str(pkg), str(out), {"opt/iris/iris-catalog.pem": str(new_cert)})
    with tarfile.open(pkg) as t:
        order_in = [m.name for m in t]
    with tarfile.open(out) as t:
        order_out = [m.name for m in t]
    assert order_in == order_out
    # the layer without matches is byte-identical (same blob name + content)
    rf_in = _verify_chain(pkg)
    rf_out = _verify_chain(out)
    untouched = [n for n, b in rf_in.items()
                 if n.startswith("blobs/") and b"untouched" in b]
    assert untouched and all(rf_out.get(n) == rf_in[n] for n in untouched)


def test_unmatched_replacement_errors(tmp_path):
    pkg = _mini_package(tmp_path)
    ghost = tmp_path / "g.py"; ghost.write_bytes(b"x")
    with pytest.raises(rb.RebakeError, match="not found in any layer"):
        rb.rebake(str(pkg), str(tmp_path / "out.tar"),
                  {"opt/iris/agent/ghost.py": str(ghost)})


def test_identical_content_is_reported_unchanged(tmp_path):
    pkg = _mini_package(tmp_path)
    out = tmp_path / "out.tar"
    same = tmp_path / "same.pem"; same.write_bytes(b"OLD-CERT\n")
    new_agent = tmp_path / "a.py"; new_agent.write_bytes(b"NEW_AGENT = 2\n")
    summary = rb.rebake(str(pkg), str(out),
                        {"opt/iris/iris-catalog.pem": str(same),
                         "opt/iris/agent/iris_agent.py": str(new_agent)})
    assert "opt/iris/iris-catalog.pem" in summary["unchanged"]
    assert "opt/iris/agent/iris_agent.py" in summary["replaced"]
    _verify_chain(out)


def test_metadata_sizes_updated(tmp_path):
    pkg = _mini_package(tmp_path)
    out = tmp_path / "out.tar"
    big = tmp_path / "big.pem"; big.write_bytes(b"N" * 5000)   # size change
    rb.rebake(str(pkg), str(out), {"opt/iris/iris-catalog.pem": str(big)})
    meta = json.loads(_read_member(out, ".package.metadata"))["packageInfo"]
    with tarfile.open(out) as t:
        art = t.extractfile("artifacts.tar.gz").read()
    rootfs = tarfile.open(fileobj=io.BytesIO(art), mode="r:gz").extractfile("rootfs.tar").read()
    assert meta["compressedArtifactsSizeInBytes"] == str(len(art))
    assert meta["uncompressedArtifactsSizeInBytes"] == str(len(rootfs))
