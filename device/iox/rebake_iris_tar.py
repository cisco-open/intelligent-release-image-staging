#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Replace files inside an already-built IOx package offline.

Why this exists: an IOx package bakes the agent code into its image, and
building a fresh package needs a multi-architecture container builder plus
Cisco's ioxclient.  A deployment-neutral IRIS package receives its catalog CA
through IOx application data at onboard time; older packages also baked that
certificate and remain readable by this compatibility tool.  An environment
without the original toolchain can replace files in an *unsigned* package by
recomputing the tar/gzip/SHA manifest chain. IOx also supports signed packages
carrying package.sign and/or package.cert; this tool refuses those because
changing any covered byte would invalidate the existing signature:

    outer IOx package tar
      package.yaml / artifacts.mf / .package.metadata / package.mf
      envelope_package.tar.gz      (copies of the above four)
      artifacts.tar.gz
        rootfs.tar                 (the image archive, one of two layouts)
        iris-catalog.pem           (legacy package only: the old pinned-cert
                                    probe member matching the image copy)
        package.yaml               (whatever else ioxclient tarred)

rootfs.tar comes in two layouts, both handled:

  CLASSIC docker-archive (what build.sh exports via `skopeo copy
  docker-archive:` since 2026-08-20 -- the only layout IE3x00 CAF's legacy
  dockerd can load):
        manifest.json  [{Config: <cfg>.json, Layers: [<layer>.tar ...]}]
        repositories
        <cfg>.json                 (config: rootfs.diff_ids)
        <digest>.tar               (plain layer tars; skopeo also writes
        <id>/layer.tar              legacy <id>/{VERSION,json,layer.tar}, the
                                    last a symlink to ../<digest>.tar)

  OCI layout (what the old `ioxclient docker package` produced):
        index.json -> manifest blob -> config blob (rootfs.diff_ids)
                                    -> layer blobs (plain tar or tar+gzip)
        manifest.json / repositories    (docker-save compat views)

rebake() swaps the given container paths for new file contents inside every
layer that carries them, then recomputes the ENTIRE hash chain bottom-up
(layer digests + diff_ids -> config -> manifest -> index/manifest.json/
repositories -> rootfs.tar -> artifacts.mf/.tar.gz -> package.mf + metadata
sizes, inner and outer), preserving member order and tar attributes. A
top-level probe member in artifacts.tar.gz whose basename matches a replaced
container path (iris-catalog.pem <-> opt/iris/iris-catalog.pem) is replaced
with the same bytes, so the freshness readers keep telling the truth. aria2c
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


# Top-level artifacts.tar.gz members that duplicate a baked container path in
# legacy packages: replaced alongside the layer copy.
_PROBE_MEMBERS = {"iris-catalog.pem": "opt/iris/iris-catalog.pem"}
_SIGNATURE_MEMBERS = frozenset(("package.sign", "package.cert"))


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _is_signature_member(name):
    """True for IOx signing material at any package-wrapper path."""
    return str(name).rstrip("/").rsplit("/", 1)[-1] in _SIGNATURE_MEMBERS


def _refuse_signature_members(members, scope):
    """Fail closed before rewriting a signed IOx package."""
    found = sorted({m.name for m in members if _is_signature_member(m.name)})
    if found:
        raise RebakeError(
            "refusing signed IOx package: %s contains %s"
            % (scope, ", ".join(found)))


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
    """Rewrite the image archive (either layout): patch layers, then
    recompute the digest chain."""
    members = _read_tar(rootfs)
    byname = {ti.name: (ti, data) for ti, data in members}
    if "index.json" in byname:
        new = _rebake_rootfs_oci(members, byname, replacements, hit)
    elif "manifest.json" in byname:
        new = _rebake_rootfs_classic(members, byname, replacements, hit)
    else:
        raise RebakeError("rootfs.tar is neither a classic docker-archive "
                          "(manifest.json) nor an OCI layout (index.json)")
    # nothing changed: hand back the ORIGINAL bytes, never a re-serialisation
    return rootfs if new is None else new


def _emit_tar(members, byname):
    """Re-emit in the original member order (renamed members keep their
    slot); anything new goes last."""
    return _write_tar([byname[ti.name] for ti, _ in members
                       if ti.name in byname] +
                      [v for k, v in byname.items()
                       if k not in {ti.name for ti, _ in members}])


def _rebake_rootfs_classic(members, byname, replacements, hit):
    """CLASSIC docker-archive: manifest.json[0].Layers name the layer tars
    directly (plain tar; diff_id == sha256 of the member), Config names the
    config json. Rewrite matching layers, recompute rootfs.diff_ids, rename
    the config and every layer member (and legacy symlink) that carried the
    old digest in its name, and refresh manifest.json / repositories."""
    manifest_list = json.loads(byname["manifest.json"][1])
    if not manifest_list:
        raise RebakeError("manifest.json lists no image")
    manifest = manifest_list[0]
    cfg_name = manifest["Config"]
    if cfg_name not in byname:
        raise RebakeError("manifest.json Config %s missing from rootfs.tar" % cfg_name)
    config = json.loads(byname[cfg_name][1])

    renames = {}                      # old digest hex -> new digest hex
    new_layer_paths = []
    for layer_path in manifest["Layers"]:
        if layer_path not in byname:
            raise RebakeError("manifest.json layer %s missing from rootfs.tar" % layer_path)
        ti, blob = byname[layer_path]
        if ti.issym() or ti.islnk():
            # skopeo's legacy <id>/layer.tar entries are symlinks to the real
            # <digest>.tar; manifest.json normally names the real file, but
            # resolve a link just in case.
            target = ti.linkname
            if target.startswith("../"):
                target = target[3:]
            ti, blob = byname[target]
            layer_path = target
        if blob[:2] == b"\x1f\x8b":
            raise RebakeError("classic layer %s is gzip-compressed; CAF cannot "
                              "load that and this tool does not rewrite it" % layer_path)
        old_dig = _sha(blob)
        new_blob, changed = _rewrite_layer(blob, replacements, hit)
        if not changed:
            new_layer_paths.append(layer_path)
            continue
        new_dig = _sha(new_blob)
        renames[old_dig] = new_dig
        new_path = layer_path.replace(old_dig, new_dig)
        ti.name = new_path
        del byname[layer_path]
        byname[new_path] = (ti, new_blob)
        new_layer_paths.append(new_path)

    if not renames:
        return None

    config["rootfs"]["diff_ids"] = [
        "sha256:" + renames.get(d.split(":", 1)[1], d.split(":", 1)[1])
        for d in config["rootfs"]["diff_ids"]]
    new_config = json.dumps(config, separators=(",", ":")).encode()
    old_cdig = cfg_name[:-len(".json")] if cfg_name.endswith(".json") else cfg_name
    new_cdig = _sha(new_config)
    renames[old_cdig] = new_cdig
    new_cfg_name = cfg_name.replace(old_cdig, new_cdig)
    cti = byname[cfg_name][0]
    cti.name = new_cfg_name
    del byname[cfg_name]
    byname[new_cfg_name] = (cti, new_config)

    manifest["Config"] = new_cfg_name
    manifest["Layers"] = new_layer_paths
    for src in (manifest.get("LayerSources") or {}).values():
        dig = src.get("digest", "").split(":", 1)[-1]
        if dig in renames:
            src["digest"] = "sha256:" + renames[dig]
            blob = byname.get(renames[dig] + ".tar")
            if blob is not None:
                src["size"] = len(blob[1])
    byname["manifest.json"] = (byname["manifest.json"][0],
                               json.dumps(manifest_list, separators=(",", ":")).encode())

    # Legacy symlinks (<id>/layer.tar -> ../<digest>.tar) follow the rename;
    # <id>/json and <id>/VERSION are docker-save compat metadata that a
    # manifest.json-driven load never consults, so they stay as they are.
    for name, (ti, data) in list(byname.items()):
        if ti.issym() or ti.islnk():
            for old, new in renames.items():
                if old in ti.linkname:
                    ti.linkname = ti.linkname.replace(old, new)
    # repositories maps repo:tag -> the top legacy layer id (a digest-string
    # rename if it happens to carry a layer digest, else untouched).
    if "repositories" in byname:
        txt = byname["repositories"][1].decode()
        for old, new in renames.items():
            txt = txt.replace(old, new)
        byname["repositories"] = (byname["repositories"][0], txt.encode())

    return _emit_tar(members, byname)


def _rebake_rootfs_oci(members, byname, replacements, hit):
    """OCI layout: index.json -> manifest blob -> config blob + layer blobs."""
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
        return None

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
    # CAF forbids the signature/certificate members from appearing in a
    # package manifest. Signed inputs are rejected before this point, and this
    # second gate keeps the invariant local to every manifest we generate.
    return ("".join("SHA256(%s)= %s\n" % (n, _sha(b)) for n, b in entries
                    if not _is_signature_member(n))).encode()


def _update_metadata(meta_bytes, compressed, uncompressed):
    meta = json.loads(meta_bytes)
    pi = meta.get("packageInfo", {})
    pi["compressedArtifactsSizeInBytes"] = str(compressed)
    pi["uncompressedArtifactsSizeInBytes"] = str(uncompressed)
    pi["compressedArtifactsSizeInMB"] = "%.2f" % (compressed / 1048576.0)
    pi["uncompressedArtifactsSizeInMB"] = "%.2f" % (uncompressed / 1048576.0)
    return json.dumps(meta, separators=(",", ":")).encode()


def _mf_order(mf_bytes, present):
    """Preserve SHA256/SHA512 manifest order; fall back to sorted."""
    safe_present = [n for n in present if not _is_signature_member(n)]
    names = re.findall(r"^SHA(?:256|512)\(([^)]+)\)=",
                       mf_bytes.decode(), re.MULTILINE)
    ordered = [n for n in names
               if n in safe_present and not _is_signature_member(n)]
    return ordered or sorted(safe_present)


def rebake(in_path, out_path, replacements):
    """replacements: {container-path: local-file-path}. Returns a summary dict
    {"replaced": [...], "unchanged": [...]} (unchanged = already identical)."""
    contents = {p: open(f, "rb").read() for p, f in replacements.items()}

    with tarfile.open(in_path) as t:
        outer_members = list(t)
        _refuse_signature_members(outer_members, "outer package")
        outer_order = [m.name for m in outer_members if m.isfile()]
        outer = {}
        for m in outer_members:
            if m.isfile():
                outer[m.name] = (m, t.extractfile(m).read())

    # artifacts.tar.gz holds rootfs.tar plus whatever else ioxclient tarred
    # from build.sh's packaging dir (package.yaml, and the pinned-cert probe
    # member iris-catalog.pem). Keep every member, in order.
    with tarfile.open(fileobj=io.BytesIO(outer["artifacts.tar.gz"][1]),
                      mode="r:gz") as t:
        art_infos = list(t)
        _refuse_signature_members(art_infos, "artifacts.tar.gz")
        art_members = [(m, t.extractfile(m).read() if m.isfile() else None)
                       for m in art_infos]
    # A signed package can repeat its signing material inside the envelope.
    # Inspect that wrapper before doing any in-memory rootfs rebuild as well.
    with tarfile.open(fileobj=io.BytesIO(outer["envelope_package.tar.gz"][1]),
                      mode="r:gz") as t:
        env_infos = list(t)
        _refuse_signature_members(env_infos, "envelope_package.tar.gz")
        env_order = [m.name for m in env_infos if m.isfile()]
        env = {m.name: t.extractfile(m).read()
               for m in env_infos if m.isfile()}
    # Do not assume the envelope's artifacts copy is byte-identical to the
    # outer one before we validate it. A mismatched signed copy would otherwise
    # be silently replaced by the clean outer archive below.
    env_artifacts = env.get("artifacts.tar.gz")
    if env_artifacts is not None and env_artifacts != outer["artifacts.tar.gz"][1]:
        with tarfile.open(fileobj=io.BytesIO(env_artifacts), mode="r:gz") as t:
            _refuse_signature_members(
                list(t), "envelope_package.tar.gz/artifacts.tar.gz")
    art_by_name = {ti.name: data for ti, data in art_members if data is not None}
    if "rootfs.tar" not in art_by_name:
        raise RebakeError("artifacts.tar.gz carries no rootfs.tar")
    rootfs = art_by_name["rootfs.tar"]

    hit = {}
    new_rootfs = _rebake_rootfs(rootfs, contents, hit)
    missing = [p for p in contents if p not in hit]
    if missing:
        raise RebakeError("not found in any layer: %s" % ", ".join(sorted(missing)))

    # The probe member must carry the same bytes as the baked file it stands
    # for, or the freshness readers (server/setup_status.py,
    # tools/check-package-freshness.sh) would keep reporting the OLD cert.
    by_basename = {}
    for path, data in contents.items():
        by_basename.setdefault(path.rsplit("/", 1)[-1], data)
    new_art = []
    for ti, data in art_members:
        if ti.name == "rootfs.tar":
            data = new_rootfs
        elif data is not None and ti.name in _PROBE_MEMBERS \
                and ti.name in by_basename:
            data = by_basename[ti.name]
            hit.setdefault(_PROBE_MEMBERS[ti.name], "replaced")
        new_art.append((ti, data))
    art_files = [(ti.name, data) for ti, data in new_art if data is not None]

    # artifacts.tar.gz + artifacts.mf (the manifest keeps its original scope
    # and line order; a member it never listed is not added to it)
    art_gz = gzip.compress(_write_tar(new_art), mtime=0)
    art_present = [n for n, _ in art_files if not _is_signature_member(n)]
    art_mf = _mf([(n, dict(art_files)[n])
                  for n in _mf_order(outer["artifacts.mf"][1], art_present)])
    uncompressed = sum(len(d) for _, d in art_files)

    # inner envelope: refresh metadata sizes + manifest, keep member order
    env["artifacts.tar.gz"] = art_gz
    env["artifacts.mf"] = art_mf
    env[".package.metadata"] = _update_metadata(env[".package.metadata"],
                                                len(art_gz), uncompressed)
    inner_named = [n for n in env
                   if n != "package.mf" and not _is_signature_member(n)]
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
        new_outer[".package.metadata"], len(art_gz), uncompressed)
    outer_named = [n for n in new_outer
                   if n != "package.mf" and not _is_signature_member(n)]
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
