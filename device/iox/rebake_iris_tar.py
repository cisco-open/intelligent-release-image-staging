#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Replace files inside an already-built IOx package offline.

Why this exists: an IOx package bakes the catalog CA (iris-catalog.pem) and the
agent code into the image at BUILD time, and building a fresh package needs an
arm64 Docker build + Cisco's ioxclient. When the server is re-keyed (new TLS
cert) or the agent code gets a fix, an environment WITHOUT that toolchain is
stuck: the deployed IE-3400 agents pin a dead cert and can never talk to the
catalog again. The package format itself carries no signatures — it is tar +
gzip + SHA256 manifests all the way down — so a rebuild-in-place is possible
anywhere Python runs:

    outer IOx package tar
      package.yaml / artifacts.mf / .package.metadata / package.mf
      envelope_package.tar.gz      (copies of the above four)
      artifacts.tar.gz -> rootfs.tar   (an OCI image archive)
        index.json -> manifest blob -> config blob (rootfs.diff_ids)
                                    -> layer blobs (plain tar or tar+gzip)
        manifest.json / repositories    (docker-save compat views)

rebake() swaps the given container paths for new file contents inside every
layer that carries them, then recomputes the ENTIRE hash chain bottom-up
(layer digests + diff_ids -> config -> manifest -> index/manifest.json/
repositories -> rootfs.tar -> artifacts.mf/.tar.gz -> package.mf + metadata
sizes, inner and outer), preserving member order and tar attributes. aria2c
and every other binary stay byte-identical — only the named files change, so
the aarch64 parts never need rebuilding.

Usage:
    rebake_iris_tar.py <in.tar> <out.tar> <container-path>=<local-file> ...
e.g.
    rebake_iris_tar.py iris-arm64.tar iris-arm64-new.tar \
        opt/iris/iris-catalog.pem=/etc/iris/tls/crt.pem \
        opt/iris/agent/iris_agent.py=device/agent/iris_agent.py

Stdlib only. Raises RebakeError when a requested path exists in no layer
(catches typos — a silent no-op here would ship a package that still carries
the old file).
"""
import gzip
import hashlib
import io
import json
import re
import sys
import tarfile


class RebakeError(Exception):
    pass


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _read_tar(data):
    """-> ordered list of (TarInfo, bytes|None) from a plain-tar byte string."""
    out = []
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        for m in t:
            out.append((m, t.extractfile(m).read() if m.isfile() else None))
    return out


def _write_tar(members):
    """members: list of (TarInfo, bytes|None) -> plain-tar bytes, attributes
    preserved (sizes corrected to the payload)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as t:
        for ti, data in members:
            if data is not None:
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
            else:
                t.addfile(ti)
    return buf.getvalue()


def _rewrite_layer(blob, replacements, hit):
    """Replace matching member contents in one layer blob (plain tar or
    tar+gzip). Returns (new_blob, changed) and records matches in hit."""
    is_gz = blob[:2] == b"\x1f\x8b"
    raw = gzip.decompress(blob) if is_gz else blob
    try:
        members = _read_tar(raw)
    except tarfile.TarError:
        return blob, False               # not a layer (e.g. a config/manifest blob)
    changed = False
    out = []
    for ti, data in members:
        key = ti.name.lstrip("./")
        if ti.isfile() and key in replacements:
            new = replacements[key]
            hit.setdefault(key, "unchanged" if data == new else "replaced")
            if data != new:
                hit[key] = "replaced"
                data = new
                changed = True
        out.append((ti, data))
    if not changed:
        return blob, False
    new_raw = _write_tar(out)
    return (gzip.compress(new_raw, mtime=0) if is_gz else new_raw), True


def _rebake_rootfs(rootfs, replacements, hit):
    """Rewrite the OCI archive: patch layers, then recompute digest chain."""
    members = _read_tar(rootfs)
    byname = {ti.name: (ti, data) for ti, data in members}
    idx = json.loads(byname["index.json"][1])
    mdig = idx["manifests"][0]["digest"].split(":", 1)[1]
    manifest = json.loads(byname["blobs/sha256/" + mdig][1])
    cdig = manifest["config"]["digest"].split(":", 1)[1]
    config = json.loads(byname["blobs/sha256/" + cdig][1])

    renames = {}                      # old blob digest -> new blob digest
    diff_renames = {}                 # old diff_id -> new diff_id
    for layer in manifest["layers"]:
        ldig = layer["digest"].split(":", 1)[1]
        blob = byname["blobs/sha256/" + ldig][1]
        new_blob, changed = _rewrite_layer(blob, replacements, hit)
        if not changed:
            continue
        new_dig = _sha(new_blob)
        gz = layer["mediaType"].endswith("+gzip")
        old_diff = _sha(gzip.decompress(blob)) if gz else ldig
        new_diff = _sha(gzip.decompress(new_blob)) if gz else new_dig
        renames[ldig] = new_dig
        diff_renames[old_diff] = new_diff
        layer["digest"] = "sha256:" + new_dig
        layer["size"] = len(new_blob)
        ti = byname["blobs/sha256/" + ldig][0]
        ti.name = "blobs/sha256/" + new_dig
        byname["blobs/sha256/" + ldig] = (ti, new_blob)

    if not renames:
        return rootfs

    config["rootfs"]["diff_ids"] = [
        "sha256:" + diff_renames.get(d.split(":", 1)[1], d.split(":", 1)[1])
        for d in config["rootfs"]["diff_ids"]]
    new_config = json.dumps(config, separators=(",", ":")).encode()
    new_cdig = _sha(new_config)
    renames[cdig] = new_cdig
    cti = byname["blobs/sha256/" + cdig][0]
    cti.name = "blobs/sha256/" + new_cdig
    byname["blobs/sha256/" + cdig] = (cti, new_config)

    manifest["config"]["digest"] = "sha256:" + new_cdig
    manifest["config"]["size"] = len(new_config)
    new_manifest = json.dumps(manifest, separators=(",", ":")).encode()
    new_mdig = _sha(new_manifest)
    renames[mdig] = new_mdig
    mti = byname["blobs/sha256/" + mdig][0]
    mti.name = "blobs/sha256/" + new_mdig
    byname["blobs/sha256/" + mdig] = (mti, new_manifest)

    idx["manifests"][0]["digest"] = "sha256:" + new_mdig
    idx["manifests"][0]["size"] = len(new_manifest)
    byname["index.json"] = (byname["index.json"][0],
                            json.dumps(idx, separators=(",", ":")).encode())

    # docker-save compat views: pure digest-string renames (no sizes except
    # LayerSources, whose entries carry both key and size)
    for name in ("manifest.json", "repositories"):
        if name not in byname:
            continue
        txt = byname[name][1].decode()
        for old, new in renames.items():
            txt = txt.replace(old, new)
        byname[name] = (byname[name][0], txt.encode())
    if "manifest.json" in byname:
        dj = json.loads(byname["manifest.json"][1])
        for entry in dj:
            for src in (entry.get("LayerSources") or {}).values():
                dig = src["digest"].split(":", 1)[1]
                blob = byname.get("blobs/sha256/" + dig)
                if blob is not None:
                    src["size"] = len(blob[1])
        byname["manifest.json"] = (byname["manifest.json"][0],
                                   json.dumps(dj, separators=(",", ":")).encode())

    return _write_tar([byname[ti.name] for ti, _ in members
                       if ti.name in byname] +
                      [v for k, v in byname.items()
                       if k not in {ti.name for ti, _ in members}])


def _mf(entries):
    """entries: ordered (name, bytes) -> ioxclient-style SHA256 manifest."""
    return ("".join("SHA256(%s)= %s\n" % (n, _sha(b)) for n, b in entries)).encode()


def _update_metadata(meta_bytes, compressed, uncompressed):
    meta = json.loads(meta_bytes)
    pi = meta.get("packageInfo", {})
    pi["compressedArtifactsSizeInBytes"] = str(compressed)
    pi["uncompressedArtifactsSizeInBytes"] = str(uncompressed)
    pi["compressedArtifactsSizeInMB"] = "%.2f" % (compressed / 1048576.0)
    pi["uncompressedArtifactsSizeInMB"] = "%.2f" % (uncompressed / 1048576.0)
    return json.dumps(meta, separators=(",", ":")).encode()


def _mf_order(mf_bytes, present):
    """Preserve the original manifest's line order; fall back to sorted."""
    names = re.findall(r"^SHA256\(([^)]+)\)=", mf_bytes.decode(), re.MULTILINE)
    return [n for n in names if n in present] or sorted(present)


def rebake(in_path, out_path, replacements):
    """replacements: {container-path: local-file-path}. Returns a summary dict
    {"replaced": [...], "unchanged": [...]} (unchanged = already identical)."""
    contents = {p: open(f, "rb").read() for p, f in replacements.items()}

    with tarfile.open(in_path) as t:
        outer_order = [m.name for m in t if m.isfile()]
        outer = {}
        t2 = tarfile.open(in_path)
        for m in t2:
            if m.isfile():
                outer[m.name] = (m, t2.extractfile(m).read())

    with tarfile.open(fileobj=io.BytesIO(outer["artifacts.tar.gz"][1]),
                      mode="r:gz") as t:
        rootfs = t.extractfile("rootfs.tar").read()

    hit = {}
    new_rootfs = _rebake_rootfs(rootfs, contents, hit)
    missing = [p for p in contents if p not in hit]
    if missing:
        raise RebakeError("not found in any layer: %s" % ", ".join(sorted(missing)))

    # artifacts.tar.gz + artifacts.mf
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        ti = tarfile.TarInfo("rootfs.tar")
        ti.size = len(new_rootfs)
        t.addfile(ti, io.BytesIO(new_rootfs))
    art_gz = gzip.compress(buf.getvalue(), mtime=0)
    art_mf = ("SHA256(rootfs.tar)= %s\n" % _sha(new_rootfs)).encode()

    # inner envelope: refresh metadata sizes + manifest, keep member order
    with tarfile.open(fileobj=io.BytesIO(outer["envelope_package.tar.gz"][1]),
                      mode="r:gz") as t:
        env_order = [m.name for m in t if m.isfile()]
        env = {m.name: t.extractfile(m).read() for m in t if m.isfile()}
    env["artifacts.tar.gz"] = art_gz
    env["artifacts.mf"] = art_mf
    env[".package.metadata"] = _update_metadata(env[".package.metadata"],
                                                len(art_gz), len(new_rootfs))
    inner_named = [n for n in env if n != "package.mf"]
    env["package.mf"] = _mf([(n, env[n]) for n in
                             _mf_order(env["package.mf"], inner_named)])
    ebuf = io.BytesIO()
    with tarfile.open(fileobj=ebuf, mode="w") as t:
        for n in env_order:
            ti = tarfile.TarInfo(n)
            ti.size = len(env[n])
            t.addfile(ti, io.BytesIO(env[n]))
    envelope = gzip.compress(ebuf.getvalue(), mtime=0)

    # outer members
    new_outer = dict((n, b) for n, (_, b) in outer.items())
    new_outer["artifacts.tar.gz"] = art_gz
    new_outer["artifacts.mf"] = art_mf
    new_outer["envelope_package.tar.gz"] = envelope
    new_outer[".package.metadata"] = _update_metadata(
        new_outer[".package.metadata"], len(art_gz), len(new_rootfs))
    outer_named = [n for n in new_outer if n != "package.mf"]
    new_outer["package.mf"] = _mf([(n, new_outer[n]) for n in
                                   _mf_order(new_outer["package.mf"], outer_named)])

    with tarfile.open(out_path, "w") as t:
        for n in outer_order:
            ti = outer[n][0]
            ti.size = len(new_outer[n])
            t.addfile(ti, io.BytesIO(new_outer[n]))

    return {"replaced": sorted(k for k, v in hit.items() if v == "replaced"),
            "unchanged": sorted(k for k, v in hit.items() if v == "unchanged")}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) < 3 or any("=" not in a for a in argv[2:]):
        print(__doc__.split("Usage:")[1].strip(), file=sys.stderr)
        return 2
    replacements = dict(a.split("=", 1) for a in argv[2:])
    summary = rebake(argv[0], argv[1], replacements)
    for p in summary["replaced"]:
        print("replaced:  %s" % p)
    for p in summary["unchanged"]:
        print("unchanged: %s (already identical)" % p)
    print("wrote %s" % argv[1])
    return 0


if __name__ == "__main__":
    sys.exit(main())
