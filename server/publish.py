#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Publish an IOS-XE image into the IRIS catalog and seeder.
sha256 → private .torrent (token in announce URL) → info_hash → catalog → seed.
Server does NOT check the Cisco signature (no cli module off-box); the device is
the on-box trust gate (spec §6). Stdlib only + the `mktorrent` CLI."""
import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

import bencode
import catalog as catalog_mod
import secrets_store

_SUFFIXES = (".SPA.bin", ".bin")


def derive_id(filename):
    name = os.path.basename(filename)
    for suf in _SUFFIXES:
        if name.endswith(suf):
            return name[:-len(suf)]
    return name


def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def digests_file(path, chunk=1 << 20):
    """Return (sha256_hex, sha512_hex) in one pass.

    The agent checks sha256 against the staged file (hashed in Python) and
    sha512 against the flash-root copy via IOS `verify /sha512` — IOS has
    /sha512 but not /sha256, hence both."""
    h256, h512 = hashlib.sha256(), hashlib.sha512()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h256.update(block)
            h512.update(block)
    return h256.hexdigest(), h512.hexdigest()


def make_torrent(image_path, tracker_url, out_path):
    """Build a PRIVATE torrent (no DHT/PEX) whose announce URL carries the token."""
    if os.path.exists(out_path):
        os.remove(out_path)
    subprocess.run(["mktorrent", "-p", "-a", tracker_url, "-o", out_path,
                    image_path], check=True)


def torrent_info_hash(torrent_path):
    meta = bencode.decode(open(torrent_path, "rb").read())
    return hashlib.sha1(bencode.encode(meta[b"info"])).hexdigest()


def default_rpc_secret():
    """IRIS_RPC_SECRET env, else the decrypted rpc-secret the entrypoint writes to
    the tmpfs (/run/iris/rpc-secret), falling back to the legacy on-volume
    /etc/iris/rpc-secret — so iris-publish needs no env even under `docker exec`
    (where the entrypoint's runtime exports aren't inherited)."""
    s = os.environ.get("IRIS_RPC_SECRET")
    if s is not None:
        return s
    explicit = os.environ.get("IRIS_RPC_SECRET_FILE")
    paths = [explicit] if explicit else ["/run/iris/rpc-secret",
                                         "/etc/iris/rpc-secret"]
    for p in paths:
        try:
            with open(p) as f:
                return f.read().strip()
        except OSError:
            continue
    return ""


def default_tracker_url():
    """Build the tracker URL from what the server already knows: IRIS_HOST_IP (set
    by docker compose) + the seeder's announce token from the broker secrets store
    (decrypted to /run/iris/secrets.json at container start). Falls back to the
    retired tokens.txt for pre-broker installs."""
    host_ip = os.environ.get("IRIS_HOST_IP")
    if not host_ip:
        return None
    # Preferred: the secrets-broker store. The seeder is a pseudo-device whose
    # announce_token is the private-tracker key (secrets_store schema).
    secrets_path = os.environ.get("IRIS_SECRETS", "/run/iris/secrets.json")
    try:
        store = secrets_store.load(secrets_path)
        tok = store.get("seeder", {}).get("announce_token", {}).get("value")
        if tok:
            return "http://%s:6969/announce?key=%s" % (host_ip, tok)
    except Exception:
        pass
    # Legacy fallback: first token in tokens.txt (pre-secrets-broker installs).
    try:
        with open(os.environ.get("IRIS_TOKENS", "/etc/iris/tokens.txt")) as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    return "http://%s:6969/announce?key=%s" % (host_ip, s)
    except OSError:
        pass
    return None


def add_torrent_rpc(torrent_bytes, image_dir, rpc_url=None, rpc_secret=None):
    """Hand the torrent to the running aria2c seeder (aria2.addTorrent)."""
    rpc_url = rpc_url or os.environ.get("IRIS_RPC", "http://127.0.0.1:6800/jsonrpc")
    rpc_secret = rpc_secret if rpc_secret is not None else default_rpc_secret()
    # bt-seed-unverified=true: the torrent was just generated FROM this exact
    # file, so seed it as-is without re-hashing (avoids re-checking ~1.2 GB and
    # the "complete file but no .aria2 control file -> won't seed" trap).
    params = ["token:" + rpc_secret,
              base64.b64encode(torrent_bytes).decode(),
              [],
              {"dir": image_dir, "seed-ratio": "0.0",
               "bt-seed-unverified": "true"}]
    payload = json.dumps({"jsonrpc": "2.0", "id": "pub",
                          "method": "aria2.addTorrent",
                          "params": params}).encode()
    req = urllib.request.Request(rpc_url, data=payload,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        out = json.loads(r.read().decode())
    if "error" in out:
        raise RuntimeError("aria2 RPC error: %s" % out["error"])
    return out.get("result")


def remove_torrent_rpc(info_hash, rpc_url=None, rpc_secret=None):
    """Best-effort: tell the aria2 seeder to stop seeding the active torrent whose
    BT infoHash matches *info_hash* (hex). No-op if not found. Raises on RPC error."""
    if not info_hash:
        return None
    rpc_url = rpc_url or os.environ.get("IRIS_RPC", "http://127.0.0.1:6800/jsonrpc")
    rpc_secret = rpc_secret if rpc_secret is not None else default_rpc_secret()

    def _call(method, params):
        payload = json.dumps({"jsonrpc": "2.0", "id": "del", "method": method,
                              "params": ["token:" + rpc_secret] + params}).encode()
        req = urllib.request.Request(rpc_url, data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            out = json.loads(r.read().decode())
        if "error" in out:
            raise RuntimeError("aria2 RPC error: %s" % out["error"])
        return out.get("result")

    want = info_hash.lower()
    for d in _call("aria2.tellActive", [["gid", "infoHash"]]) or []:
        if (d.get("infoHash") or "").lower() == want:
            gid = d.get("gid")
            _call("aria2.forceRemove", [gid])
            try:
                _call("aria2.removeDownloadResult", [gid])
            except Exception:
                pass
            return gid
    return None


def publish(image_path, store, tracker_url, image_id=None,
            signature_verified=False, seeder=add_torrent_rpc):
    if not os.path.isfile(image_path):
        raise FileNotFoundError(image_path)
    image_id = image_id or derive_id(image_path)
    sha, sha512 = digests_file(image_path)
    size = os.path.getsize(image_path)
    out_path = store.torrent_path(image_id)
    make_torrent(image_path, tracker_url, out_path)
    info_hash = torrent_info_hash(out_path)
    entry = {
        "id": image_id,
        "filename": os.path.basename(image_path),
        "size": size,
        "sha256": sha,
        "sha512": sha512,
        "cisco_signature_verified": bool(signature_verified),
        "info_hash_hex": info_hash,
        "published_at": int(time.time()),
    }
    with open(out_path, "rb") as f:
        seeder(f.read(), os.path.dirname(os.path.abspath(image_path)))
    store.save_image(entry)
    return entry


def main(argv=None):
    ap = argparse.ArgumentParser(prog="iris-publish")
    ap.add_argument("image", help="path to the .bin image")
    ap.add_argument("--id", dest="image_id", default=None)
    ap.add_argument("--signature-verified", action="store_true",
                    help="record that the Cisco signature was verified elsewhere")
    ap.add_argument("--state", default=os.environ.get(
        "IRIS_STATE", "/var/lib/iris"))
    ap.add_argument("--tracker-url", default=os.environ.get(
        "IRIS_TRACKER_URL"))
    args = ap.parse_args(argv)
    if not args.tracker_url:
        args.tracker_url = default_tracker_url()
    if not args.tracker_url:
        print("error: can't determine the tracker URL — set IRIS_HOST_IP (docker "
              "compose does this) or pass --tracker-url", file=sys.stderr)
        return 2
    if shutil.which("mktorrent") is None:
        print("error: mktorrent not installed (apt install mktorrent)",
              file=sys.stderr)
        return 2
    store = catalog_mod.CatalogStore(args.state)
    entry = publish(args.image, store, args.tracker_url,
                    image_id=args.image_id,
                    signature_verified=args.signature_verified)
    print("published %s sha256=%s info_hash=%s"
          % (entry["id"], entry["sha256"], entry["info_hash_hex"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
