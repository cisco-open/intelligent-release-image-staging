#!/usr/bin/env python3

# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Publish an IOS-XE image into the IRIS catalog and seeder.
sha256 → private .torrent (token-free announce URL) → info_hash → catalog → seed.
Server does NOT check the Cisco signature (no cli module off-box): authenticity
is settled before publish, and the device's check is the agent's sha256 of the
staged file against this catalog entry (spec §6). Nothing on the box re-hashes
the placed copy. Stdlib only + the `mktorrent` CLI."""
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import bencode
import catalog as catalog_mod
from seeder_auth import announce_authorization_header
import secrets_store
import tracker_announce
import torrent_personalize

_SUFFIXES = (".SPA.bin", ".bin")
# Credential-bearing query parameters that may appear in an announce URL:
# IRIS's own announce_token=, the legacy key=, and aria2's key=. Anything
# after the "=" is replaced before text reaches a job message, an audit row
# or a terminal.
_CRED_QUERY_RE = re.compile(r"((?:announce_token|token|key)=)[^&\s'\"\]\)]*")
_REDACTED = "<redacted>"


def redact(text, *secrets):
    """Return *text* with every credential-bearing announce query parameter
    and every literal in *secrets* (a tracker URL, a token) replaced. Exception
    text is untrusted on the publish path: mktorrent only takes the announce
    URL on argv, so anything that renders argv -- CalledProcessError, a
    traceback -- carries the seeder's private-tracker token."""
    text = "" if text is None else str(text)
    for secret in secrets:
        if secret:
            text = text.replace(str(secret), _REDACTED)
    return _CRED_QUERY_RE.sub(lambda m: m.group(1) + _REDACTED, text)


def _unlink_quiet(path):
    try:
        os.remove(path)
    except OSError:
        pass


def derive_id(filename):
    name = os.path.basename(filename)
    for suf in _SUFFIXES:
        if name.endswith(suf):
            return name[:-len(suf)]
    return name


def digests_file(path, chunk=1 << 20):
    """Return (sha256_hex, sha512_hex) in one pass.

    The agent checks sha256 against the staged file (hashed in Python) as
    the integrity check. sha512 is not checked on-device — it exists as the
    join key into Cisco's published Bulk Hash data, matching this image to
    Cisco's own authoritative hash record at publish time."""
    h256, h512 = hashlib.sha256(), hashlib.sha512()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h256.update(block)
            h512.update(block)
    return h256.hexdigest(), h512.hexdigest()


def make_torrent(image_path, tracker_url, out_path):
    """Build a PRIVATE torrent whose announce URL contains no credential.

    A partial output file is removed on failure so nothing re-seeds it."""
    tracker_url = tracker_announce.validate(tracker_url)
    if os.path.exists(out_path):
        os.remove(out_path)
    try:
        subprocess.run(["mktorrent", "-p", "-a", tracker_url, "-o", out_path,
                        image_path], check=True)
    except subprocess.CalledProcessError as exc:
        _unlink_quiet(out_path)
        raise RuntimeError("mktorrent exited %d" % exc.returncode) from None
    except Exception:
        _unlink_quiet(out_path)
        raise


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


def tracker_announce_base():
    """The token-free tracker announce base, derived exactly the way the
    catalog's per-device personalization and the rotation CLI derive it:
    IRIS_TRACKER_ANNOUNCE if set, else IRIS_HOST_IP + IRIS_TRACKER_PORT
    (default 6969, the port tracker.py listens on). Missing or unsafe config
    raises rather than falling back to plaintext. Keeping the three in step is
    what makes the canonical (seeder) announce reach the same tracker the
    devices are told to announce to."""
    return tracker_announce.resolve(os.environ)


def _with_query(base, param, value):
    return "%s%s%s=%s" % (base, "&" if "?" in base else "?", param, value)


def default_tracker_url():
    """Return the token-free tracker URL; authentication is an HTTP header."""
    base = tracker_announce_base()
    return base


def default_announce_header():
    """Return the seeder Bearer header, loaded from tmpfs and never logged."""
    secrets_path = os.environ.get("IRIS_SECRETS", "/run/iris/secrets.json")
    try:
        store = secrets_store.load(secrets_path)
        tok = store.get("seeder", {}).get("announce_token", {}).get("value")
        return announce_authorization_header(tok)
    except Exception:
        pass
    return None


def _rpc_endpoint(rpc_url, rpc_secret):
    rpc_url = rpc_url or os.environ.get("IRIS_RPC", "http://127.0.0.1:6800/jsonrpc")
    rpc_secret = rpc_secret if rpc_secret is not None else default_rpc_secret()
    return rpc_url, rpc_secret


def _rpc_call(rpc_url, rpc_secret, method, params, call_id="pub"):
    payload = json.dumps({"jsonrpc": "2.0", "id": call_id, "method": method,
                          "params": ["token:" + rpc_secret] + params}).encode()
    req = urllib.request.Request(rpc_url, data=payload,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        out = json.loads(r.read().decode())
    if "error" in out:
        raise RuntimeError("aria2 RPC error: %s" % out["error"])
    return out.get("result")


def _active_gid(rpc_url, rpc_secret, info_hash):
    """GID of the active aria2 download whose BT infoHash is *info_hash*, or
    None. Raises on RPC error."""
    want = (info_hash or "").lower()
    if not want:
        return None
    for d in _rpc_call(rpc_url, rpc_secret, "aria2.tellActive",
                       [["gid", "infoHash"]]) or []:
        if (d.get("infoHash") or "").lower() == want:
            return d.get("gid")
    return None


def add_torrent_rpc(torrent_bytes, image_dir, rpc_url=None, rpc_secret=None):
    """Hand the torrent to the running aria2c seeder (aria2.addTorrent)."""
    rpc_url, rpc_secret = _rpc_endpoint(rpc_url, rpc_secret)
    # bt-seed-unverified=true: the torrent was just generated FROM this exact
    # file, so seed it as-is without re-hashing (avoids re-checking ~1.2 GB and
    # the "complete file but no .aria2 control file -> won't seed" trap).
    announce_header = default_announce_header()
    if not announce_header:
        raise RuntimeError("seeder announce credential unavailable")
    params = [base64.b64encode(torrent_bytes).decode(),
              [],
              {"dir": image_dir, "seed-ratio": "0.0",
               "bt-seed-unverified": "true",
               "header": [announce_header]}]
    return _rpc_call(rpc_url, rpc_secret, "aria2.addTorrent", params)


def remove_torrent_rpc(info_hash, rpc_url=None, rpc_secret=None):
    """Best-effort: tell the aria2 seeder to stop seeding the active torrent whose
    BT infoHash matches *info_hash* (hex). No-op if not found. Raises on RPC error."""
    if not info_hash:
        return None
    rpc_url, rpc_secret = _rpc_endpoint(rpc_url, rpc_secret)
    gid = _active_gid(rpc_url, rpc_secret, info_hash)
    if gid is None:
        return None
    _rpc_call(rpc_url, rpc_secret, "aria2.forceRemove", [gid], call_id="del")
    try:
        _rpc_call(rpc_url, rpc_secret, "aria2.removeDownloadResult", [gid],
                  call_id="del")
    except Exception:
        pass
    return gid


def resume_torrent_rpc(torrent_path, image_dir, info_hash=None,
                       tracker_url=None, rpc_url=None, rpc_secret=None):
    """Put a canonical torrent that was force-removed from the seeder (a
    quarantine) back into aria2, from the directory its image was published
    from. Used by catalog.CatalogStore.release_quarantine.

    Before the add, the canonical file's outer announce is re-synced to the
    token-free tracker base (*tracker_url*, default default_tracker_url()).
    The seeder's current credential is supplied separately as an HTTP header
    by :func:`add_torrent_rpc`. Only the outer announce moves; the raw ``info``
    span, and therefore the info hash every device policy references, remains
    byte-identical (torrent_personalize asserts it). An already-active torrent
    is left alone rather than handed to aria2 as a duplicate info hash. Returns
    the new GID, or None when it was already active. Raises on RPC error; no
    URL or token is ever placed in an exception."""
    with open(torrent_path, "rb") as f:
        data = f.read()
    tracker_url = tracker_announce.validate(
        tracker_url or default_tracker_url())
    synced = torrent_personalize.personalize(data, tracker_url)
    if synced != data:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(torrent_path) or ".",
                                   prefix=".resync-", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(synced)
            os.replace(tmp, torrent_path)
        except Exception:
            _unlink_quiet(tmp)
            raise
        data = synced
    info_hash = info_hash or torrent_info_hash(torrent_path)
    rpc_url, rpc_secret = _rpc_endpoint(rpc_url, rpc_secret)
    if _active_gid(rpc_url, rpc_secret, info_hash) is not None:
        return None
    return add_torrent_rpc(data, image_dir, rpc_url=rpc_url,
                           rpc_secret=rpc_secret)


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
        # Where the image is seeded FROM. An image published in place (from the
        # read-only IRIS_IMAGE_ROOT, or by iris-publish) is not in the uploads
        # volume, and the two directories can hold the same basename -- so a
        # delete must not infer the file's location from its name alone.
        "source_dir": os.path.dirname(os.path.abspath(image_path)),
        "size": size,
        "sha256": sha,
        "sha512": sha512,
        # The OPERATOR's own attestation (--signature-verified), durable and
        # distinct from cisco_signature_verified -- the Cisco Bulk Hash
        # reconciler's OWN verdict field (catalog.py's apply_hash_verification/
        # release_quarantine; never written here). IRIS-03-009/#88: the two
        # used to share one field, so the reconciler's first run silently
        # clobbered the operator's mark. Never write cisco_signature_verified
        # from this module again -- see catalog.py's apply_hash_verification
        # docstring for why it is the reconciler's exclusively.
        "operator_attested_signature": bool(signature_verified),
        "info_hash_hex": info_hash,
        "published_at": int(time.time()),
    }
    # Torrent file -> seeder -> catalog, in that order (a catalog entry must
    # never advertise an unseeded image). If either later step fails, the
    # torrent file is rolled back too: an on-disk .torrent with no catalog row
    # is exactly what a restart's re-seed must never find, and the same image
    # is offered for import again anyway.
    try:
        with open(out_path, "rb") as f:
            seeder(f.read(), os.path.dirname(os.path.abspath(image_path)))
        store.save_image(entry)
    except Exception:
        _unlink_quiet(out_path)
        raise
    return entry


def main(argv=None):
    ap = argparse.ArgumentParser(prog="iris-publish")
    ap.add_argument("image", help="path to the .bin image")
    ap.add_argument("--id", dest="image_id", default=None)
    ap.add_argument("--signature-verified", action="store_true",
                    help="record the operator's own attestation that the Cisco "
                         "signature was verified elsewhere, as "
                         "operator_attested_signature -- stored separately from "
                         "cisco_signature_verified, the Cisco Bulk Hash "
                         "reconciler's own verdict field, so a later "
                         "reconciliation run never overwrites this mark")
    ap.add_argument("--state", default=os.environ.get(
        "IRIS_STATE", "/var/lib/iris"))
    ap.add_argument("--tracker-url", default=os.environ.get(
        "IRIS_TRACKER_URL"))
    args = ap.parse_args(argv)
    try:
        args.tracker_url = tracker_announce.validate(args.tracker_url) \
            if args.tracker_url else default_tracker_url()
    except ValueError:
        print("error: can't determine the tracker URL — set IRIS_HOST_IP (docker "
              "compose does this) or pass a token-free HTTPS --tracker-url",
              file=sys.stderr)
        return 2
    if shutil.which("mktorrent") is None:
        print("error: mktorrent not installed (apt install mktorrent)",
              file=sys.stderr)
        return 2
    store = catalog_mod.CatalogStore(args.state)
    try:
        entry = publish(args.image, store, args.tracker_url,
                        image_id=args.image_id,
                        signature_verified=args.signature_verified)
    except Exception as exc:
        # Never a traceback: one could render mktorrent's argv, and with it
        # the announce URL. The message is redacted as a second line of
        # defence even though make_torrent already strips it at the source.
        print("error: publish failed (%s): %s"
              % (exc.__class__.__name__, redact(exc, args.tracker_url)),
              file=sys.stderr)
        return 1
    print("published %s sha256=%s info_hash=%s"
          % (entry["id"], entry["sha256"], entry["info_hash_hex"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
