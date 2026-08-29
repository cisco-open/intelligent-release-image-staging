# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Cisco Bulk Hash feed: fetch, verify, parse, reconcile (pure core).

No HTTP-server coupling -- this module knows nothing about gui_server,
catalog.py, or the console; a later task wires the pipeline below into all
three. The pipeline, in order, each stage fail-closed (ANY failure raises
``BulkHashError``; a caller that catches it MUST leave prior verdicts
untouched -- a broken feed can never quarantine anything):

    fetch(url, timeout, out_path)      -- stream the tar to disk
    verify_tar(tar_path, cert_path)    -- check Cisco's signature (raises)
    parse(tar_path)                    -- extract+parse the CSV (raises)
    reconcile(rows, images)            -- pure join -> per-image verdicts

A live run against the real feed (2026-08-29) found Cisco publishes a
blank IMAGE_SIZE on a measured ~17% of rows -- including exact duplicates
of otherwise-sized rows for the same image (observed live: a C9800
image). ``parse()`` keeps such rows (``Row.image_size = None``, a size
wildcard) instead of dropping them, and ``reconcile()`` joins each image
against every same-filename row whose size matches OR is that wildcard,
verifying on ANY candidate's sha512 match -- see ``reconcile()``'s own
docstring for the exact semantics and the metadata tie-break on mismatch.

The feed (confirmed by a live download, 2026-08-29): a gzip tar containing
one timestamped directory holding ``<name>.csv`` (comma-separated, CRLF
line endings, header ``FILE_NAME,MD5_CHECKSUM,SHA512_CHECKSUM,PUBLISH_DATE,
DEFERRAL_STATUS,IMAGE_SIZE``) and its detached signature
``<name>.csv.signature``, plus Cisco's own end-entity cert, README, and
verify scripts (all ignored here -- see below). ``verify_tar`` never trusts
a certificate found inside the downloaded tar; it checks the signature
against ONLY the certificate pinned in-repo at
``server/certs/cisco_bulkhash_verify.pem`` (provenance + fingerprint
documented in that file's header), matching the recipe Cisco's own
``cisco_x509_verify_release.py`` documents (`-v dgst -sha512`): extract the
public key from the certificate, then ``openssl dgst -sha512 -verify``.

The tar is external input even once its signature checks out, so every
member touched by ``verify_tar`` or ``parse`` -- not just the ones each
function ultimately needs -- is hardened first: regular files and
directories only (no symlinks/devices), no absolute paths, no ``..``
traversal segments, and a per-member size cap. Structural/tarfile/gzip
parsing errors are caught broadly and re-raised as ``BulkHashError``: for
untrusted external archives, failing closed matters more than preserving
the original exception's exact type.
"""
import collections
import csv
import io
import os
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.request

_DOWNLOAD_CHUNK = 1024 * 1024
_OPENSSL_TIMEOUT = 60

# The real feed's CSV was ~88.5 MB uncompressed on 2026-08-29 and grows
# (append-only) over time; this leaves decades of headroom while still
# bounding a hostile/corrupt member's memory footprint. Tests monkeypatch
# this down to exercise the oversized-member fail-closed path cheaply.
_MAX_CSV_BYTES = 256 * 1024 * 1024
# An RSA (even 4096-bit) detached signature is at most a few KB.
_MAX_SIGNATURE_BYTES = 16 * 1024

_EXPECTED_CSV_HEADER = [
    "FILE_NAME", "MD5_CHECKSUM", "SHA512_CHECKSUM", "PUBLISH_DATE",
    "DEFERRAL_STATUS", "IMAGE_SIZE"]

STATE_VERIFIED = "verified"
STATE_MISMATCH = "mismatch"
STATE_NOT_IN_FEED = "not_in_feed"


class BulkHashError(Exception):
    """Any failure in fetch/verify/parse -- the pipeline's fail-closed
    signal. Callers must keep prior state on this (or any) exception."""


Row = collections.namedtuple(
    "Row", ["file_name", "md5", "sha512", "publish_date", "deferral_status",
             "image_size"])


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------

def fetch(url, timeout, out_path):
    """Stream-download `url` to `out_path`, atomically: a temp file in the
    same directory is renamed into place only once every byte has arrived,
    so a failed or partial download never clobbers a prior good file at
    `out_path`. Raises `BulkHashError` on ANY failure (HTTP error,
    network/timeout error, short read); returns `out_path` on success."""
    dest_dir = os.path.dirname(os.path.abspath(out_path)) or "."
    os.makedirs(dest_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=dest_dir, prefix=".bulkhash-",
                                    suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            try:
                with urllib.request.urlopen(url, timeout=timeout) as resp:
                    while True:
                        chunk = resp.read(_DOWNLOAD_CHUNK)
                        if not chunk:
                            break
                        f.write(chunk)
            except urllib.error.HTTPError as exc:
                raise BulkHashError(
                    "download failed: HTTP %d" % exc.code) from exc
            except Exception as exc:
                # class name only: urllib error text can embed request
                # details (host, path) that need not end up in logs/UI.
                raise BulkHashError(
                    "download failed: %s" % exc.__class__.__name__) from exc
        os.replace(tmp_path, out_path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    return out_path


# ---------------------------------------------------------------------------
# Shared tar-member hardening (verify_tar and parse both use this)
# ---------------------------------------------------------------------------

_ALLOWED_TYPES = (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)


def _validated_members(tf, max_file_bytes):
    """All members of open `TarFile` `tf`, after hardening every one of
    them (not just the ones a caller will end up using): regular files and
    plain directories only, no absolute paths, no `..`/empty path segments,
    and per-file member size capped at `max_file_bytes`. Directory members
    are validated but not returned (nothing ever reads their "content").
    Raises `BulkHashError` on the FIRST violation -- one hostile member
    fails the whole archive closed."""
    members = []
    for member in tf.getmembers():
        name = member.name
        if member.type not in _ALLOWED_TYPES:
            raise BulkHashError("unexpected member type: %s" % name)
        norm = name.replace("\\", "/").rstrip("/")
        if not norm or os.path.isabs(norm) or norm.startswith("/"):
            raise BulkHashError("unsafe path member: %s" % name)
        parts = norm.split("/")
        if any(p in ("", ".", "..") for p in parts):
            raise BulkHashError("unsafe path member: %s" % name)
        if member.isfile():
            if member.size > max_file_bytes:
                raise BulkHashError("oversized member: %s" % name)
            members.append(member)
    return members


def _member_by_basename(tf, members, name, max_bytes):
    """Bytes of the single validated member in `members` whose basename is
    exactly `name` (tolerating an arbitrary leading directory prefix -- the
    real feed wraps everything in a timestamped directory). Raises on zero
    or more than one match, on an unreadable member, or when the actual
    bytes exceed `max_bytes` (defense in depth on top of the size already
    checked by `_validated_members`)."""
    matches = [m for m in members if os.path.basename(m.name) == name]
    if not matches:
        raise BulkHashError("missing expected member: %s" % name)
    if len(matches) > 1:
        raise BulkHashError("ambiguous duplicate member: %s" % name)
    member = matches[0]
    f = tf.extractfile(member)
    if f is None:
        raise BulkHashError("member is not a regular file: %s" % name)
    data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise BulkHashError("oversized member: %s" % name)
    return data


def _find_csv_member_name(members):
    """The single member (by basename) ending in `.csv` among `members`.
    Raises when there is not exactly one -- an archive with zero or several
    candidate CSVs is treated as tampered/unparseable, not guessed at."""
    candidates = [os.path.basename(m.name) for m in members
                  if os.path.basename(m.name).lower().endswith(".csv")]
    if not candidates:
        raise BulkHashError("no .csv member found in archive")
    if len(candidates) > 1:
        raise BulkHashError(
            "ambiguous archive: multiple .csv members found")
    return candidates[0]


def _open_and_scan(tar_path):
    """Open `tar_path` (auto-detecting gzip) and return `(tf, members)` --
    `tf` left OPEN, the caller owns closing it (`with tf:`) -- or raise
    `BulkHashError`, in which case `tf` is closed here first (nothing is
    ever leaked, and nothing is ever handed back closed either -- unlike a
    `with tarfile.open(...) as tf: return tf, ...`, which would close `tf`
    during the `return`, before the caller ever gets it). Broad `except
    Exception` is deliberate: `tar_path` is untrusted external input (a
    truncated download, a corrupted/hostile archive), and gzip/tarfile can
    surface a wide variety of exception types (`tarfile.TarError`,
    `EOFError`, `zlib.error`, `OSError`, ...) for malformed input --
    fail-closed here matters more than preserving the original exception's
    exact type.

    The scan pass caps every member at `_MAX_CSV_BYTES` -- the largest
    member the real archive legitimately contains (the CSV itself); a
    tighter, member-specific cap is applied again when a member's bytes
    are actually read (see `_member_by_basename`)."""
    try:
        tf = tarfile.open(tar_path, mode="r:*")
    except Exception as exc:
        raise BulkHashError(
            "unreadable tar: %s" % exc.__class__.__name__) from exc
    try:
        members = _validated_members(tf, _MAX_CSV_BYTES)
    except BulkHashError:
        tf.close()
        raise
    except Exception as exc:
        tf.close()
        raise BulkHashError(
            "unreadable tar: %s" % exc.__class__.__name__) from exc
    return tf, members


# ---------------------------------------------------------------------------
# verify_tar
# ---------------------------------------------------------------------------

def _run_openssl(argv, data=None):
    """Run one openssl subprocess call. Raises `BulkHashError` on ANY
    failure to even invoke it (missing binary, timeout); a non-zero exit
    from a successfully-invoked openssl is left for the caller to
    interpret (that is itself a normal "verification failed" outcome, not
    an invocation failure)."""
    try:
        return subprocess.run(argv, input=data, capture_output=True,
                              timeout=_OPENSSL_TIMEOUT)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BulkHashError(
            "openssl invocation failed: %s" % exc.__class__.__name__) from exc


def verify_tar(tar_path, cert_path):
    """Verify `tar_path`'s Cisco X.509 signature: RSA/SHA-512 `openssl dgst
    -verify`, the exact recipe Cisco's own `cisco_x509_verify_release.py`
    documents (`-v dgst -sha512`), checked against the PINNED verification
    certificate at `cert_path` -- never a certificate found inside
    `tar_path` itself, so a tampered archive can never supply its own trust
    anchor. Raises `BulkHashError` on ANY failure: an unreadable/truncated
    tar, unsafe members, a missing/oversized CSV or signature member, a
    missing openssl binary, or a signature that does not verify (including
    an absent ".signature" member -- an "unsigned" bundle). Returns `None`
    on success."""
    tf, members = _open_and_scan(tar_path)
    with tf:
        csv_name = _find_csv_member_name(members)
        csv_bytes = _member_by_basename(tf, members, csv_name,
                                        _MAX_CSV_BYTES)
        signature = _member_by_basename(
            tf, members, csv_name + ".signature", _MAX_SIGNATURE_BYTES)

    pubkey_proc = _run_openssl(
        ["openssl", "x509", "-pubkey", "-noout", "-in", cert_path])
    if pubkey_proc.returncode != 0 or not pubkey_proc.stdout.strip():
        raise BulkHashError("could not read the pinned verification cert")

    with tempfile.TemporaryDirectory(prefix="bulkhash-verify-") as tmp:
        pubkey_path = os.path.join(tmp, "pubkey.pem")
        sig_path = os.path.join(tmp, "signature.bin")
        with open(pubkey_path, "wb") as f:
            f.write(pubkey_proc.stdout)
        with open(sig_path, "wb") as f:
            f.write(signature)
        verify_proc = _run_openssl(
            ["openssl", "dgst", "-sha512", "-verify", pubkey_path,
             "-signature", sig_path], data=csv_bytes)

    if verify_proc.returncode != 0 or b"Verified OK" not in verify_proc.stdout:
        raise BulkHashError("Cisco Bulk Hash signature verification failed")
    return None


# ---------------------------------------------------------------------------
# parse
# ---------------------------------------------------------------------------

def _parse_csv_rows(text):
    reader = csv.reader(io.StringIO(text, newline=""))
    try:
        header = next(reader)
    except StopIteration:
        raise BulkHashError("empty CSV: no header row")
    if [h.strip() for h in header] != _EXPECTED_CSV_HEADER:
        raise BulkHashError("unexpected CSV header: %r" % (header,))
    for fields in reader:
        if not fields:
            continue
        name = fields[0].strip()
        if not name or name.startswith("##"):
            continue  # blank row, or a ##START_DATE##/##END_DATE## sentinel
        if len(fields) < 6:
            continue  # malformed data row -- skip rather than fail the feed
        file_name, md5, sha512, publish_date, deferral, size_s = fields[:6]
        size_s = size_s.strip()
        if size_s:
            try:
                size = int(size_s)
            except ValueError:
                continue  # genuinely non-numeric IMAGE_SIZE -- malformed
        else:
            # A blank IMAGE_SIZE is real on the live feed (~17% of rows,
            # 2026-08-29 measurement, including exact duplicates of
            # otherwise-sized rows) -- kept as a size WILDCARD (None) so
            # reconcile() can still join it by filename alone, rather than
            # silently losing every image whose only feed row happens to
            # be blank-size.
            size = None
        sha512 = sha512.strip().lower()
        if not sha512:
            # A blank SHA512_CHECKSUM (real, observed on the live feed) is
            # nothing to compare a catalog image's sha512 against -- skip
            # the row so it can never be joined against by reconcile(),
            # rather than risk a false "verified" if a broken catalog
            # entry also carries a blank sha512.
            continue
        yield Row(file_name=name, md5=md5.strip().lower(), sha512=sha512,
                  publish_date=publish_date.strip(),
                  deferral_status=deferral.strip(), image_size=size)


def parse(tar_path):
    """Parse the Cisco Bulk Hash CSV inside `tar_path` (the same tar
    `verify_tar` checks the signature of) into an iterator of `Row`
    namedtuples. All structural validation (tar hardening, member lookup,
    CSV header shape) happens eagerly, before anything is returned, so a
    caller either gets a complete result or an exception -- never a partial
    iteration that dies partway through. Blank lines and
    `##START_DATE##`/`##END_DATE##`-style sentinel/batch-marker rows are
    skipped. A blank IMAGE_SIZE is real on the live feed (~17% of rows,
    2026-08-29 measurement, including exact duplicates of otherwise-sized
    rows) and is KEPT, with `Row.image_size` set to `None` -- a size
    wildcard `reconcile()` joins on filename alone, so an image whose
    only feed row happens to be blank-size can still be reconciled. A
    genuinely non-numeric (not blank) IMAGE_SIZE, or a blank
    SHA512_CHECKSUM, is skipped instead of failing the whole feed -- a
    row with no usable sha512 to compare against a catalog image's own
    must never be joinable by `reconcile()` at all."""
    tf, members = _open_and_scan(tar_path)
    with tf:
        csv_name = _find_csv_member_name(members)
        csv_bytes = _member_by_basename(tf, members, csv_name,
                                        _MAX_CSV_BYTES)
    text = csv_bytes.decode("utf-8", "replace")
    return iter(list(_parse_csv_rows(text)))


# ---------------------------------------------------------------------------
# reconcile
# ---------------------------------------------------------------------------

def _image_fields(image):
    """(image_id, filename, size, sha512) from one `images` entry -- a dict
    with those keys, or a plain 4-tuple in that order. `size` is coerced
    to `int` (Task 2's catalog entries may come from JSON, where an int
    can round-trip as a numeric string) so it joins correctly against
    `Row.image_size`, which is always a real int -- a `size` that cannot
    be coerced (None, "not-a-number", ...) raises `BulkHashError` rather
    than silently failing every join and reporting the whole catalog as
    not_in_feed."""
    if isinstance(image, dict):
        image_id, filename, size, sha512 = (
            image["image_id"], image["filename"], image["size"],
            image.get("sha512"))
    else:
        image_id, filename, size, sha512 = image
    try:
        size = int(size)
    except (TypeError, ValueError) as exc:
        raise BulkHashError(
            "image %r has a non-integer size: %r" % (image_id, size)
        ) from exc
    return image_id, filename, size, sha512


def reconcile(rows, images):
    """Per-image verdict dict `{image_id: {state, feed_sha512,
    publish_date, deferral}}` -- PURE, no side effects, no I/O. `rows` is
    an iterable of `Row` (e.g. from `parse()`); `images` is an iterable of
    IRIS catalog entries, each either a dict with `image_id`, `filename`,
    `size`, `sha512` keys or a `(image_id, filename, size, sha512)` tuple.

    A feed row is a CANDIDATE for an image when `FILE_NAME == filename`
    AND (`IMAGE_SIZE == size` OR `IMAGE_SIZE` is the wildcard `None` --
    see `parse()`/`_parse_csv_rows`: a blank IMAGE_SIZE, real on the live
    feed, is kept as `None` rather than dropped, specifically so a
    blank-size row can still join). `SHA512_CHECKSUM` is then compared
    (case-insensitively) against every candidate, ANY-MATCH-WINS:

    - "verified": at least one candidate's sha512 agrees. This was a
      real live-feed gap (2026-08-29): three of six catalog images
      verified against Cisco's real, hash-identical published row only
      after this fix, because that row happened to carry a blank
      IMAGE_SIZE and the old strict (name, size) join could never match
      it at all.
    - "mismatch": candidates exist, but NONE of their sha512s agree.
    - "not_in_feed": no candidates at all (no feed row shares the
      filename, or none of the same-name rows has a matching/wildcard
      size) -- the expected, non-alarming state for a customer-built
      image Cisco never published.

    The verdict's `feed_sha512`/`publish_date`/`deferral` come from ONE
    representative row: on "verified", whichever candidate matched (the
    first, in `rows` iteration order, if more than one does -- any real
    match is equally authoritative). On "mismatch", the exact-size
    candidate is preferred when one exists (a more specific match than a
    wildcard row), else the first blank-size candidate.

    Duplicate feed rows for the same (FILE_NAME, IMAGE_SIZE) -- observed
    live, e.g. Cisco publishing both a sized row and a blank-size
    duplicate for the same image -- are NOT deduplicated or overwritten:
    every one is a candidate, and any-match-wins reads all of them. This
    replaces an earlier last-row-wins dict-overwrite design, which could
    fabricate a false mismatch whenever the real matching row was not the
    last duplicate seen.

    Every `Row` in `rows` is guaranteed a non-blank `sha512` (`parse()`
    skips any feed row with a blank SHA512_CHECKSUM before it ever gets
    here) -- but `rows` need not have come from `parse()`, so that is not
    relied on. An `images` entry with a falsy/missing `sha512` (an
    unhashed catalog entry -- a data-integrity bug elsewhere, since every
    published image is hashed at publish time) raises `BulkHashError`
    immediately: it must never silently produce "verified" by comparing
    two blank strings, nor any other verdict."""
    rows_by_name = {}
    for row in rows:
        rows_by_name.setdefault(row.file_name, []).append(row)

    verdicts = {}
    for image in images:
        image_id, filename, size, sha512 = _image_fields(image)
        image_sha512 = (sha512 or "").strip().lower()
        if not image_sha512:
            raise BulkHashError(
                "image %r has no sha512 to reconcile against" % (image_id,))

        candidates = [r for r in rows_by_name.get(filename, ())
                     if r.image_size == size or r.image_size is None]
        if not candidates:
            verdicts[image_id] = {
                "state": STATE_NOT_IN_FEED, "feed_sha512": None,
                "publish_date": None, "deferral": False}
            continue

        matched = next(
            (r for r in candidates if r.sha512 == image_sha512), None)
        if matched is not None:
            state, row = STATE_VERIFIED, matched
        else:
            exact = [r for r in candidates if r.image_size == size]
            state, row = STATE_MISMATCH, (exact[0] if exact else
                                          candidates[0])

        deferral = bool(row.deferral_status) and \
            row.deferral_status.lower() != "active"
        verdicts[image_id] = {
            "state": state,
            "feed_sha512": row.sha512,
            "publish_date": row.publish_date,
            "deferral": deferral,
        }
    return verdicts
