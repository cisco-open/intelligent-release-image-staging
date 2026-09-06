#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Create separate server/Console TLS and management-token bundles.

Run once on a trusted operator machine, then deliver only each host's bundle
over an authenticated channel. Existing output is never replaced. The server
age identity is provisioned separately and is never part of these bundles.
"""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess


def certificate_name(value):
    """Accept one concrete DNS name or IP address, not OpenSSL SAN syntax."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if len(value) > 253 or not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in value.split(".")
        ):
            raise argparse.ArgumentTypeError("expected a DNS name or IP address")
        # A malformed address must not silently become a DNS SAN.
        if all(part.isdecimal() for part in value.split(".")):
            raise argparse.ArgumentTypeError("invalid IP address")
        return "DNS:" + value.lower()
    if address.is_unspecified or address.is_multicast:
        raise argparse.ArgumentTypeError("expected a concrete unicast IP address")
    return "IP:" + str(address)


def _write(path, content):
    with path.open("xb") as stream:
        stream.write(content)
    path.chmod(0o600)


def _identity(directory, names):
    command = [
        "openssl", "req", "-x509", "-newkey", "rsa:3072", "-sha256", "-nodes",
        "-days", "365", "-subj", "/CN=" + names[0].partition(":")[2],
        "-addext", "subjectAltName=" + ",".join(dict.fromkeys(names)),
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
        "-addext", "extendedKeyUsage=serverAuth",
        "-keyout", str(directory / "tls.key"),
        "-out", str(directory / "tls.crt"),
    ]
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE)
    (directory / "tls.key").chmod(0o600)
    (directory / "tls.crt").chmod(0o600)


def prepare(output, management_names, console_names):
    output = Path(output).absolute()
    # mkdir is the exclusive reservation: no existing files, directories, or
    # symlinks can be overwritten, including after a failed earlier run.
    output.mkdir(mode=0o700)
    try:
        _write(output / ".gitignore", b"*\n")
        for relative in ("server", "console", "server/tier-auth",
                         "server/management-tls", "console/tier-auth",
                         "console/management-ca", "console/console-tls"):
            (output / relative).mkdir(mode=0o700)
        token = (json.dumps({"scope": "management", "token": secrets.token_urlsafe(48)},
                            separators=(",", ":")) + "\n").encode("utf-8")
        _write(output / "server/tier-auth/current.json", token)
        _write(output / "console/tier-auth/current.json", token)
        _identity(output / "server/management-tls", management_names)
        _identity(output / "console/console-tls", console_names)
        _write(output / "console/management-ca/ca.pem",
               (output / "server/management-tls/tls.crt").read_bytes())
    except Exception:
        shutil.rmtree(output)
        raise
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True,
                        help="new output directory (parent must already exist)")
    parser.add_argument("--management-host", required=True, action="append",
                        type=certificate_name,
                        help="management URL hostname or IP; repeat for aliases")
    parser.add_argument("--console-host", required=True, action="append",
                        type=certificate_name,
                        help="browser hostname or IP; repeat for aliases")
    args = parser.parse_args(argv)
    previous_umask = os.umask(0o077)
    try:
        output = prepare(args.out, args.management_host, args.console_host)
    except FileExistsError:
        parser.exit(1, "Output already exists; choose a new directory.\n")
    except subprocess.CalledProcessError:
        parser.exit(1, "TLS identity generation failed; no bundle was retained.\n")
    except OSError as exc:
        parser.exit(1, "Could not prepare bundles: %s\n" % exc)
    finally:
        os.umask(previous_umask)
    print("Created separate server and Console bundles in %s" % output)
    print("Deliver only each host's directory and set its owner to UID/GID 10001.")


if __name__ == "__main__":
    main()
