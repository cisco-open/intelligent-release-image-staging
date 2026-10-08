# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Private, locked installation journal; never contains private key bytes."""

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile


class InstallError(Exception):
    """An actionable, non-secret installer failure."""


def regular_bytes(path, limit=1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise InstallError("Expected a regular file: " + str(path))
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise InstallError("Input exceeds its size limit: " + str(path))
    return value


def atomic_write(path, data, mode=0o600):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".iris-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Journal:
    def __init__(self, directory):
        self.directory = Path(directory).absolute()
        if self.directory == Path("/"):
            raise InstallError("Choose a dedicated installation state directory")
        if self.directory.resolve() != self.directory:
            raise InstallError("Installation state must not traverse symlinks")
        self.path = self.directory / "installation.json"
        self.document = None

    @contextmanager
    def locked(self, *, create=False):
        if create:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise InstallError("Installation state must be owned by the caller with mode 0700")
        fd = os.open(self.directory / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise InstallError("Unsafe installation lock")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise InstallError("Another installer is operating on this instance") from exc
            if self.path.exists() or self.path.is_symlink():
                try:
                    self.document = json.loads(regular_bytes(self.path))
                except (OSError, ValueError) as exc:
                    raise InstallError("Installation journal is unreadable or invalid; do not reset it") from exc
                if (not isinstance(self.document, dict)
                        or self.document.get("schema") != 1
                        or not isinstance(self.document.get("config"), dict)
                        or not isinstance(self.document.get("completed"), dict)):
                    raise InstallError("Unsupported or incomplete installation journal")
            yield self
        finally:
            os.close(fd)

    def save(self):
        atomic_write(self.path, (json.dumps(self.document, indent=2, sort_keys=True) + "\n").encode())

    def checkpoint(self, stage, evidence):
        self.document["completed"][stage] = evidence
        self.document["state"] = stage
        self.save()

    def pause(self, state):
        self.document["state"] = state
        self.save()
