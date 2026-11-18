#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Prepare an unsigned IOx wrapper's SHA512 manifest before native signing.

Only wrapper manifests change. Image blobs, their OCI digests and artifacts.mf
keep their original bytes. Verify the input hashes before replacing a manifest;
never rewrite a wrapper that already carries native signing material.
"""

import argparse
import copy
import gzip
import hashlib
import io
from pathlib import Path
import re
import tarfile
import tempfile


class ManifestError(ValueError):
    """An input package cannot safely be prepared for signing."""


MAX_MANIFEST_BYTES = 1024 * 1024
MAX_MEMBERS = 128
MAX_PACKAGE_BYTES = 2 * 1024 * 1024 * 1024
SIGNING_MEMBERS = frozenset(("package.sign", "package.cert"))
_ENTRY = re.compile(r"(SHA256|SHA512)\(([^\r\n()]+)\)= ([0-9a-f]+)")


def _members(archive):
    members = {}
    total = 0
    for member in archive:
        name = member.name
        if name.rstrip("/").rsplit("/", 1)[-1] in SIGNING_MEMBERS:
            raise ManifestError("refusing signed IOx package")
        if (not member.isfile() or not name or name in (".", "..")
                or "/" in name or "\\" in name or "\n" in name
                or "\r" in name or "(" in name or ")" in name):
            raise ManifestError("expected flat, regular IOx package members")
        if name in members:
            raise ManifestError("duplicate package member: " + name)
        total += member.size
        if len(members) >= MAX_MEMBERS or total > MAX_PACKAGE_BYTES:
            raise ManifestError("IOx package exceeds manifest preparation limits")
        members[name] = member
    required = {"package.yaml", "package.mf", "artifacts.tar.gz"}
    if not required <= members.keys():
        raise ManifestError("IOx package is missing required members")
    return members


def _digest(stream, algorithm):
    digest = hashlib.new(algorithm.lower())
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _verify(archive, members, *, sha512_only=False, required_algorithm=None):
    member = members["package.mf"]
    if member.size > MAX_MANIFEST_BYTES:
        raise ManifestError("package.mf exceeds size limit")
    try:
        text = archive.extractfile(member).read().decode("ascii")
    except UnicodeDecodeError as exc:
        raise ManifestError("package.mf must be ASCII") from exc
    covered = set()
    for line in text.splitlines():
        match = _ENTRY.fullmatch(line)
        if not match:
            raise ManifestError("invalid package.mf entry")
        algorithm, name, expected = match.groups()
        if name in SIGNING_MEMBERS or name == "package.mf":
            raise ManifestError("manifest cannot hash signing material or itself")
        if name in covered or name not in members:
            raise ManifestError("duplicate or missing manifest member: " + name)
        if sha512_only and algorithm != "SHA512":
            raise ManifestError("package.mf must use SHA512")
        if required_algorithm is not None and algorithm != required_algorithm:
            raise ManifestError("package.mf must use " + required_algorithm)
        with archive.extractfile(members[name]) as payload:
            actual = _digest(payload, algorithm)
        if actual != expected:
            raise ManifestError("package.mf hash mismatch: " + name)
        covered.add(name)
    if covered != members.keys() - {"package.mf"}:
        raise ManifestError("package.mf does not cover every payload member")


def _rewrite(source, destination, depth=0, algorithm="SHA512"):
    if depth > 1:
        raise ManifestError("unexpected nested IOx envelope")
    with tarfile.open(fileobj=source, mode="r:*") as archive:
        members = _members(archive)
        _verify(archive, members)
        # Some ioxclient versions include a duplicate inner package envelope.
        # Normalize that manifest first, then hash the resulting envelope bytes.
        with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as envelope:
            if "envelope_package.tar.gz" in members:
                with archive.extractfile(members["envelope_package.tar.gz"]) as nested:
                    with gzip.GzipFile(fileobj=envelope, mode="wb", mtime=0) as gz:
                        _rewrite(nested, gz, depth + 1, algorithm)
                envelope.seek(0)
            lines = []
            for name, member in members.items():
                if name == "package.mf":
                    continue
                if name == "envelope_package.tar.gz":
                    digest = _digest(envelope, algorithm)
                    envelope.seek(0)
                else:
                    with archive.extractfile(member) as payload:
                        digest = _digest(payload, algorithm)
                lines.append(f"{algorithm}({name})= {digest}\n")
            manifest = "".join(lines).encode("ascii")
            with tarfile.open(fileobj=destination, mode="w|") as output:
                for name, member in members.items():
                    info = copy.copy(member)
                    if name == "package.mf":
                        info.size = len(manifest)
                        output.addfile(info, io.BytesIO(manifest))
                    elif name == "envelope_package.tar.gz":
                        info.size = envelope.seek(0, 2)
                        envelope.seek(0)
                        output.addfile(info, envelope)
                    else:
                        with archive.extractfile(member) as payload:
                            output.addfile(info, payload)


def _verify_archive(archive, depth=0, algorithm="SHA512"):
    if depth > 1:
        raise ManifestError("unexpected nested IOx envelope")
    members = _members(archive)
    _verify(archive, members, required_algorithm=algorithm)
    if "envelope_package.tar.gz" in members:
        with archive.extractfile(members["envelope_package.tar.gz"]) as nested:
            with tarfile.open(fileobj=nested, mode="r:gz") as inner:
                _verify_archive(inner, depth + 1, algorithm)


def verify(path, algorithm="SHA512"):
    """Verify manifest coverage and bytes without extracting or changing files."""
    if algorithm not in ("SHA256", "SHA512"):
        raise ManifestError("unsupported manifest algorithm")
    with tarfile.open(path, mode="r:*") as archive:
        _verify_archive(archive, algorithm=algorithm)


def prepare(source, destination, algorithm="SHA512"):
    """Write a new unsigned wrapper; leave the input and existing outputs alone."""
    destination = Path(destination)
    if algorithm not in ("SHA256", "SHA512"):
        raise ManifestError("unsupported manifest algorithm")
    # Exclusive creation also rejects aliases/symlinks to the source package.
    with open(source, "rb") as original:
        with destination.open("xb") as output:
            try:
                _rewrite(original, output, algorithm=algorithm)
                output.flush()
                verify(destination, algorithm)
            except BaseException:
                destination.unlink()
                raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path, nargs="?")
    parser.add_argument("--algorithm", choices=("SHA256", "SHA512"),
                        default="SHA512",
                        help="SHA256 for unsigned legacy CAF packages; SHA512 for signing inputs")
    args = parser.parse_args()
    try:
        if args.destination is None:
            verify(args.source, args.algorithm)
        else:
            prepare(args.source, args.destination, args.algorithm)
    except (ManifestError, OSError, tarfile.TarError) as exc:
        parser.exit(1, f"IOx manifest: {exc}\n")


if __name__ == "__main__":
    main()
