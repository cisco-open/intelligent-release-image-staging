#!/usr/bin/python3 -I
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Private OpenSSH pipe helper. Never invoke as a user-facing command."""

import hashlib
import json
import os
import re
import stat
import sys


def main():
    path = os.environ.get('IRIS_AUTOMATIC_PASSPHRASE', '')
    match = re.fullmatch(r'(/proc/[1-9][0-9]*/fd/[0-9]+)/(root-[ab])\.passphrase', path)
    if match is None:
        return 1
    directory = os.open(match[1], os.O_RDONLY | os.O_DIRECTORY)
    try:
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            return 1

        def read(name, limit):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                st = os.fstat(fd)
                if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                        or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1
                        or st.st_size > limit):
                    raise ValueError
                data = os.read(fd, limit + 1)
                after = os.fstat(fd)
                if (len(data) != st.st_size or (st.st_size, st.st_mtime_ns, st.st_ctime_ns) !=
                        (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                    raise ValueError
                return data
            finally:
                os.close(fd)

        secret = read(match[2] + '.passphrase', 65)
        record = json.loads(read('automatic-root.json', 4096))
        if (not re.fullmatch(rb'[A-Za-z0-9_-]{64}\n', secret) or not isinstance(record, dict)
                or record.get('name') != match[2]
                or record.get('passphrase_sha256') != hashlib.sha256(secret).hexdigest()):
            return 1
        sys.stdout.buffer.write(secret)
        return 0
    finally:
        os.close(directory)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, UnicodeError):
        raise SystemExit(1) from None
