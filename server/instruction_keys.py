# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""OpenSSH-backed custody for IRIS instruction signing.

The server owns one short-lived online key.  Offline root *public* keys are
provisioned under ``$IRIS_CONFIG/instr/roots.d``; this module has no operation
that generates, imports, or accepts a path to a root private key.  A keylist is
a monotonic, root-signed KRL delivery object.  It does not carry replacement
trust roots: later consumers pin the two bare root public keys independently.
"""

from dataclasses import dataclass
import base64
import binascii
from contextlib import contextmanager
import datetime as dt
import errno
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

INSTRUCTION_NAMESPACE = "iris-instructions-v1"
KEYLIST_NAMESPACE = "iris-keylist-v1"
ONLINE_PRINCIPAL = "iris-server"
ROOT_PRINCIPAL = "iris-root"
EPOCH_SCHEMA = "iris-instructions-epoch/v1"
KEYLIST_STATE_SCHEMA = "iris-instruction-keylist-state/v1"
STATUS_SCHEMA = "iris-instruction-key-status/v1"
KEYLIST_HEADER = b"IRIS-KEYLIST/1\n"

CERTIFICATE_LIFETIME_SECONDS = 30 * 86400
# Absolute OpenSSH validity stamps have one-second precision.  This one-minute
# allowance is deliberately narrow enough that a 31-day certificate is never
# accepted while tolerating ceremony tooling that rounds a boundary to a minute.
CERTIFICATE_TIME_TOLERANCE = 60
CERTIFICATE_REFUSE_SECONDS = 7 * 86400
KEYLIST_RESIGN_SECONDS = 90 * 86400
ROOT_ATTEST_SECONDS = 180 * 86400
ROOT_CEREMONY_WARN_DAYS = 100
ROOT_CEREMONY_CRITICAL_DAYS = 135
SSH_TIMEOUT = 10
MAX_KEYLIST_BYTES = 128 * 1024
MAX_KEYLIST_PAYLOAD_BYTES = 116 * 1024
MAX_KRL_BYTES = 80 * 1024
MAX_SIGNATURE_BYTES = 8 * 1024
MAX_METADATA_BYTES = 4 * 1024
MAX_ROOT_KEY_BYTES = 4 * 1024
MAX_CERTIFICATE_BYTES = 64 * 1024
MAX_PRIVATE_KEY_BYTES = 64 * 1024
MAX_SERIALIZED_INTEGER = (1 << 63) - 1
STATUS_MAX_AGE_SECONDS = 2 * 3600
STATUS_FUTURE_TOLERANCE_SECONDS = 60
_ROOT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class InstructionKeyError(RuntimeError):
    """A custody input or OpenSSH operation was invalid."""


class SigningUnavailable(InstructionKeyError):
    """The online certificate is not in its permitted signing window."""


@dataclass(frozen=True)
class InstructionPaths:
    state_dir: str
    config_dir: str
    run_dir: str

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        return cls(
            state_dir=env.get("IRIS_STATE", "/var/lib/iris"),
            config_dir=env.get("IRIS_CONFIG", "/etc/iris"),
            run_dir=env.get("IRIS_RUN", "/run/iris"))

    @property
    def encrypted_key(self):
        return os.path.join(self.config_dir, "instr", "signing-key.age")

    @property
    def runtime_key(self):
        return os.path.join(self.run_dir, "instr", "signing-key")

    @property
    def public_key(self):
        return os.path.join(self.config_dir, "instr", "signing-key.pub")

    @property
    def certificate(self):
        return os.path.join(
            self.config_dir, "instr", "signing-key-cert.pub")

    @property
    def runtime_certificate(self):
        return os.path.join(
            self.run_dir, "instr", "signing-key-cert.pub")

    @property
    def roots_dir(self):
        return os.path.join(self.config_dir, "instr", "roots.d")

    @property
    def epoch(self):
        return os.path.join(self.state_dir, "instructions-epoch.json")

    @property
    def epoch_lock(self):
        return self.epoch + ".lock"

    @property
    def instructions_dir(self):
        return os.path.join(self.state_dir, "instructions")

    @property
    def keylist_current(self):
        return os.path.join(self.instructions_dir, "keylist.current")

    @property
    def keylist_state(self):
        return os.path.join(self.instructions_dir, "keylist-state.json")

    @property
    def keylist_lock(self):
        return os.path.join(self.instructions_dir, "keylist.lock")

    @property
    def status(self):
        return os.path.join(self.state_dir, "instruction-key-status.json")


def _is_int(value, *, minimum=0, maximum=MAX_SERIALIZED_INTEGER):
    return (isinstance(value, int) and not isinstance(value, bool)
            and minimum <= value <= maximum)


def _fsync_directory(directory):
    fd = os.open(directory or ".", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    except OSError as exc:
        unsupported = {errno.EINVAL}
        if hasattr(errno, "ENOTSUP"):
            unsupported.add(errno.ENOTSUP)
        if exc.errno not in unsupported:
            raise
    finally:
        os.close(fd)


def _fsync_file(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _atomic_write(path, data, mode=0o600):
    path = os.fspath(path)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        dir=directory, prefix="." + os.path.basename(path) + ".")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _atomic_write_json(path, document, mode=0o600):
    data = (json.dumps(document, sort_keys=True, separators=(",", ":"))
            + "\n").encode("utf-8")
    _atomic_write(path, data, mode=mode)


@contextmanager
def _custody_lock(paths):
    os.makedirs(paths.instructions_dir, mode=0o700, exist_ok=True)
    lock_fd = os.open(
        paths.keylist_lock, os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
        0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


def _ssh_env():
    env = dict(os.environ)
    env.pop("HOME", None)
    env.pop("SSH_AUTH_SOCK", None)
    env.update({"LC_ALL": "C", "TZ": "UTC"})
    return env


def _run_ssh(args, *, data=None, timeout=SSH_TIMEOUT,
             ssh_keygen="ssh-keygen", check=False):
    try:
        result = subprocess.run(
            [ssh_keygen, *map(os.fspath, args)], input=data,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout, env=_ssh_env())
    except subprocess.TimeoutExpired:
        raise InstructionKeyError("OpenSSH operation timed out") from None
    except OSError:
        raise InstructionKeyError("OpenSSH tooling is unavailable") from None
    if check and result.returncode != 0:
        # OpenSSH diagnostics may include untrusted comments or paths.  The
        # stable error is enough and cannot disclose key material.
        raise InstructionKeyError("OpenSSH operation failed")
    return result


def _strict_json_loads(data, error):
    def reject_duplicates(pairs):
        document = {}
        for key, value in pairs:
            if key in document:
                raise InstructionKeyError("%s contains duplicate keys" % error)
            document[key] = value
        return document

    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        return json.loads(data, object_pairs_hook=reject_duplicates)
    except InstructionKeyError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise InstructionKeyError("%s is invalid" % error) from exc


def _path_exists(path, error):
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise InstructionKeyError(error) from exc


def _read_regular(path, limit, *, unavailable, too_large,
                  expected_mode=None):
    path = os.fspath(path)
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            raise InstructionKeyError(unavailable)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        try:
            after = os.fstat(fd)
            if not stat.S_ISREG(after.st_mode) or \
                    (before.st_dev, before.st_ino) != (after.st_dev,
                                                        after.st_ino):
                raise InstructionKeyError(unavailable)
            if expected_mode is not None and \
                    stat.S_IMODE(after.st_mode) != expected_mode:
                raise InstructionKeyError(unavailable)
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(limit + 1)
        finally:
            os.close(fd)
    except InstructionKeyError:
        raise
    except OSError as exc:
        raise InstructionKeyError(unavailable) from exc
    if len(data) > limit:
        raise InstructionKeyError(too_large)
    return data


def _public_key_bytes(source, *, message="configured root public key"):
    if isinstance(source, bytes):
        data = source
        if len(data) > MAX_ROOT_KEY_BYTES:
            raise InstructionKeyError(message + " is too large")
    else:
        data = _read_regular(
            source, MAX_ROOT_KEY_BYTES,
            unavailable=message + " is unreadable",
            too_large=message + " is too large")
    try:
        text = data.decode("ascii")
    except UnicodeError as exc:
        raise InstructionKeyError(message + " is invalid") from exc
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0].strip():
        raise InstructionKeyError(message + " must contain one key")
    fields = lines[0].split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519" \
            or "-cert-" in fields[0]:
        raise InstructionKeyError("configured root must be a supported bare public key")
    try:
        decoded = base64.b64decode(fields[1].encode("ascii"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise InstructionKeyError(message + " is invalid") from exc
    # The wire blob starts with a length-prefixed algorithm name.  Checking it
    # here prevents a syntactically valid base64 field from being credited as
    # an Ed25519 root before OpenSSH later consumes it.
    algorithm = b"ssh-ed25519"
    if decoded[:4] != len(algorithm).to_bytes(4, "big") \
            or decoded[4:4 + len(algorithm)] != algorithm \
            or decoded[4 + len(algorithm):8 + len(algorithm)] != \
            (32).to_bytes(4, "big") \
            or len(decoded) != 8 + len(algorithm) + 32:
        raise InstructionKeyError(message + " is invalid")
    # Base64 decoders can accept surplus padding.  Re-encode the validated
    # wire identity so distinctness, allowed-signers files and attestations all
    # use one representation for the same Ed25519 key.
    canonical_blob = base64.b64encode(decoded).decode("ascii")
    return (fields[0] + " " + canonical_blob + "\n").encode("ascii")


def _read_public_key(source):
    canonical = _public_key_bytes(source)
    fields = canonical.decode("ascii").split()
    return fields[0], fields[1]


def _snapshot_roots(roots):
    if not isinstance(roots, dict):
        raise InstructionKeyError("configured roots are invalid")
    snapshots = {}
    seen = set()
    for root_id in sorted(roots):
        if not isinstance(root_id, str) or not _ROOT_ID.fullmatch(root_id):
            raise InstructionKeyError("configured root id is invalid")
        key = _public_key_bytes(roots[root_id])
        if key in seen:
            raise InstructionKeyError(
                "a configured key cannot match more than exactly one root")
        seen.add(key)
        snapshots[root_id] = key
    if len(snapshots) > 2:
        raise InstructionKeyError("at most two configured roots are supported")
    return snapshots


def _root_digest(key):
    return hashlib.sha256(_public_key_bytes(key)).hexdigest()


def discover_roots(paths):
    directory = paths.roots_dir
    try:
        try:
            info = os.lstat(directory)
        except FileNotFoundError:
            return {}
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise InstructionKeyError("configured roots directory is invalid")
        with os.scandir(directory) as scan:
            entries = sorted(
                (entry for entry in scan if entry.name.endswith(".pub")),
                key=lambda entry: entry.name)
    except InstructionKeyError:
        raise
    except OSError as exc:
        raise InstructionKeyError("configured roots are unreadable") from exc
    if not entries:
        return {}
    if len(entries) != 2:
        raise InstructionKeyError("configured custody requires exactly two roots")
    roots = {}
    for entry in entries:
        root_id = entry.name[:-4]
        if not _ROOT_ID.fullmatch(root_id):
            raise InstructionKeyError("configured root id is invalid")
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise InstructionKeyError("configured root public key is unreadable") from exc
        if entry.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise InstructionKeyError("configured root public key must be a regular file")
        roots[root_id] = _public_key_bytes(entry.path)
    return _snapshot_roots(roots)


def write_allowed_signers(path, identity, public_keys, *, namespace,
                          certificate_authority):
    if not isinstance(identity, str) or not identity or any(
            char.isspace() for char in identity):
        raise InstructionKeyError("allowed-signers identity is invalid")
    if not isinstance(namespace, str) or not namespace or any(
            char in namespace for char in '\n\r"'):
        raise InstructionKeyError("allowed-signers namespace is invalid")
    lines = []
    for public_key in public_keys:
        key_type, blob = _read_public_key(public_key)
        options = ('cert-authority,namespaces="%s"' % namespace
                   if certificate_authority
                   else 'namespaces="%s"' % namespace)
        lines.append("%s %s %s %s\n" % (
            identity, options, key_type, blob))
    if not lines:
        raise InstructionKeyError("at least one public key is required")
    _atomic_write(path, "".join(lines).encode("ascii"), mode=0o644)


def openssh_time(epoch):
    if not _is_int(epoch):
        raise InstructionKeyError("verification time must be an epoch integer")
    try:
        return dt.datetime.fromtimestamp(
            epoch, dt.timezone.utc).strftime("%Y%m%d%H%M%SZ")
    except (OverflowError, OSError, ValueError) as exc:
        raise InstructionKeyError("verification time is out of range") from exc


def verify_signature(data, signature, allowed_signers, identity, namespace,
                     *, krl=None, verify_time=None, timeout=SSH_TIMEOUT,
                     ssh_keygen="ssh-keygen"):
    if not isinstance(data, bytes) or not isinstance(signature, bytes):
        raise TypeError("data and signature must be bytes")
    with tempfile.TemporaryDirectory(prefix="iris-sshsig-") as directory:
        signature_path = os.path.join(directory, "signature")
        _atomic_write(signature_path, signature, mode=0o600)
        args = ["-Y", "verify", "-f", os.fspath(allowed_signers),
                "-I", identity, "-n", namespace, "-s", signature_path]
        if verify_time is not None:
            args.extend(["-O", "verify-time=" + openssh_time(verify_time)])
        if krl is not None:
            args.extend(["-r", os.fspath(krl)])
        result = _run_ssh(
            args, data=data, timeout=timeout, ssh_keygen=ssh_keygen)
        return result.returncode == 0


def _fingerprint(path, *, timeout=SSH_TIMEOUT, ssh_keygen="ssh-keygen"):
    result = _run_ssh(
        ["-l", "-f", os.fspath(path)], timeout=timeout,
        ssh_keygen=ssh_keygen, check=True)
    fields = result.stdout.decode("ascii", "strict").split()
    if len(fields) < 2 or not fields[1].startswith("SHA256:"):
        raise InstructionKeyError("OpenSSH returned an invalid fingerprint")
    return fields[1]


def _certificate_fields(path, *, timeout=SSH_TIMEOUT,
                        ssh_keygen="ssh-keygen"):
    result = _run_ssh(
        ["-L", "-f", os.fspath(path)], timeout=timeout,
        ssh_keygen=ssh_keygen, check=True)
    try:
        text = result.stdout.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise InstructionKeyError("online certificate details are invalid") from exc
    lines = text.splitlines()
    type_headers = [line for line in lines
                    if re.match(r"^[ \t]*Type:", line)]
    if len(type_headers) != 1:
        raise InstructionKeyError("online certificate type is invalid")
    certificate_type = re.fullmatch(
        r"[ \t]*Type:[ \t]+(ssh-ed25519-cert-v01@openssh\.com)"
        r"[ \t]+(user|host) certificate[ \t]*", type_headers[0])
    if certificate_type is None:
        raise InstructionKeyError("online certificate type is invalid")
    if certificate_type.group(2) != "user":
        raise InstructionKeyError("online certificate must be a user certificate")
    critical_headers = [(index, line) for index, line in enumerate(lines)
                        if re.match(r"^[ \t]*Critical Options:", line)]
    if len(critical_headers) != 1:
        raise InstructionKeyError("online certificate details are invalid")
    critical_index, critical_line = critical_headers[0]
    critical_options = re.fullmatch(
        r"([ \t]*)Critical Options:[ \t]+\(none\)[ \t]*",
        critical_line)
    if critical_options is None:
        raise InstructionKeyError(
            "online certificate has unsupported critical options")
    following = next((line for line in lines[critical_index + 1:]
                      if line.strip()), None)
    extension_header = re.escape(critical_options.group(1)) + \
        r"Extensions:(?:[ \t]+\(none\))?[ \t]*"
    if following is None or re.fullmatch(
            extension_header, following) is None:
        raise InstructionKeyError(
            "online certificate has unsupported critical options")
    if re.search(r"^\s*Valid:\s+forever\s*$", text, re.MULTILINE):
        raise InstructionKeyError("online certificate requires a finite 30-day validity")
    valid = re.search(
        r"^\s*Valid:\s+from\s+(\S+)\s+to\s+(\S+)\s*$",
        text, re.MULTILINE)
    principals = re.search(
        r"^\s*Principals:\s*\n((?:\s{12,}\S[^\n]*\n)+)",
        text, re.MULTILINE)
    if valid is None or principals is None:
        raise InstructionKeyError("online certificate validity or principal is invalid")
    try:
        start = int(dt.datetime.strptime(
            valid.group(1), "%Y-%m-%dT%H:%M:%S").replace(
                tzinfo=dt.timezone.utc).timestamp())
        end = int(dt.datetime.strptime(
            valid.group(2), "%Y-%m-%dT%H:%M:%S").replace(
                tzinfo=dt.timezone.utc).timestamp())
    except (ValueError, OverflowError) as exc:
        raise InstructionKeyError("online certificate validity is invalid") from exc
    names = [line.strip() for line in principals.group(1).splitlines()
             if line.strip()]
    return start, end, names


def _matching_roots(data, signature, roots, *, identity, namespace,
                    krl=None, verify_time=None, timeout=SSH_TIMEOUT,
                    ssh_keygen="ssh-keygen", certificate_authority=False):
    if not isinstance(roots, dict) or not roots:
        return []
    matches = []
    with tempfile.TemporaryDirectory(prefix="iris-root-check-") as directory:
        krl_path = None
        if krl is not None:
            krl_path = os.path.join(directory, "previous.krl")
            _atomic_write(krl_path, krl, mode=0o600)
        for root_id in sorted(roots):
            if not _ROOT_ID.fullmatch(root_id):
                raise InstructionKeyError("configured root id is invalid")
            allowed = os.path.join(directory, "allowed-" + root_id)
            write_allowed_signers(
                allowed, identity, [roots[root_id]], namespace=namespace,
                certificate_authority=certificate_authority)
            if verify_signature(
                    data, signature, allowed, identity, namespace,
                    krl=krl_path, verify_time=verify_time, timeout=timeout,
                    ssh_keygen=ssh_keygen):
                matches.append(root_id)
    return matches


def _owned_inode(path):
    info = os.lstat(path)
    return info.st_dev, info.st_ino


def _unlink_owned(path, identity):
    try:
        if _owned_inode(path) != identity:
            return False
        os.unlink(path)
    except OSError:
        # Cleanup is best effort: an unlink failure must not prevent attempts
        # on the remaining operation-owned paths or replace the stable error.
        return False
    try:
        _fsync_directory(os.path.dirname(os.fspath(path)) or ".")
    except OSError:
        # The unlink already happened.  Preserve the primary custody error if
        # the cleanup durability sync itself fails.
        pass
    return True


def _unlink_temporary(path):
    try:
        os.unlink(path)
    except OSError:
        return False
    try:
        _fsync_directory(os.path.dirname(os.fspath(path)) or ".")
    except OSError:
        pass
    return True


def _publish_owned(path, data, mode, owned):
    path = os.fspath(path)
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        dir=directory, prefix="." + os.path.basename(path) + ".generation-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        owned[path] = _owned_inode(path)
        _fsync_directory(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _move_owned(source, destination, mode, owned):
    destination = os.fspath(destination)
    os.chmod(source, mode)
    os.replace(source, destination)
    owned[destination] = _owned_inode(destination)
    _fsync_directory(os.path.dirname(destination) or ".")


def _runtime_directory(paths):
    directory = os.path.dirname(paths.runtime_key)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    return directory


def _derive_public_bytes(paths, private_bytes, *, timeout, ssh_keygen):
    with tempfile.TemporaryDirectory(
            prefix=".key-check-", dir=_runtime_directory(paths)) as directory:
        private = os.path.join(directory, "signing-key")
        _atomic_write(private, private_bytes, mode=0o600)
        result = _run_ssh(
            ["-y", "-f", private], timeout=timeout,
            ssh_keygen=ssh_keygen, check=True)
    return _public_key_bytes(result.stdout.strip() + b"\n",
                             message="online public key")


def _runtime_private_locked(paths, *, timeout, ssh_keygen):
    private = _read_regular(
        paths.runtime_key, MAX_PRIVATE_KEY_BYTES,
        unavailable="online runtime key or mode is invalid",
        too_large="online runtime key is too large", expected_mode=0o600)
    durable_public = _public_key_bytes(
        paths.public_key, message="online public key")
    if _derive_public_bytes(
            paths, private, timeout=timeout,
            ssh_keygen=ssh_keygen) != durable_public:
        raise InstructionKeyError("online runtime key does not match its public key")
    return private, durable_public


def _run_age(args):
    try:
        result = subprocess.run(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=30, env=_ssh_env())
    except (OSError, subprocess.TimeoutExpired):
        raise InstructionKeyError("age operation failed") from None
    if result.returncode != 0:
        raise InstructionKeyError("age operation failed")


def _default_decrypt(ciphertext, destination, identity_file):
    _run_age([
        os.environ.get("IRIS_AGE_BIN", "age"), "-d", "-i",
        os.fspath(identity_file), "-o", os.fspath(destination),
        os.fspath(ciphertext)])
    os.chmod(destination, 0o600)


def _default_encrypt(plain, destination, recipients_csv):
    recipients = [item.strip() for item in recipients_csv.split(",")
                  if item.strip()]
    if not recipients:
        raise InstructionKeyError("age recipients are required")
    command = [os.environ.get("IRIS_AGE_BIN", "age")]
    for recipient in recipients:
        command.extend(["-r", recipient])
    command.extend(["-o", os.fspath(destination), os.fspath(plain)])
    _run_age(command)
    os.chmod(destination, 0o600)


def _ensure_runtime_key_locked(paths, *, required, identity_file=None,
                               decrypt_fn=None, timeout=SSH_TIMEOUT,
                               ssh_keygen="ssh-keygen"):
    if _path_exists(paths.runtime_key, "online runtime key is unreadable"):
        if not _path_exists(
                paths.encrypted_key,
                "online signing key ciphertext is unreadable"):
            raise InstructionKeyError(
                "online signing key ciphertext is unavailable")
        _read_regular(
            paths.encrypted_key, MAX_KEYLIST_BYTES,
            unavailable="online signing key ciphertext is invalid",
            too_large="online signing key ciphertext is too large")
        private, public = _runtime_private_locked(
            paths, timeout=timeout, ssh_keygen=ssh_keygen)
        _atomic_write(paths.runtime_key + ".pub", public, mode=0o644)
        return private, public
    if not _path_exists(
            paths.encrypted_key,
            "online signing key ciphertext is unreadable"):
        if required:
            raise InstructionKeyError("online signing key ciphertext is unavailable")
        return None

    ciphertext = _read_regular(
        paths.encrypted_key, MAX_KEYLIST_BYTES,
        unavailable="online signing key ciphertext is invalid",
        too_large="online signing key ciphertext is too large")
    public = _public_key_bytes(paths.public_key, message="online public key")
    identity_file = (os.environ.get(
        "IRIS_AGE_KEY_FILE", "/run/secrets/iris_age_key")
                     if identity_file is None else os.fspath(identity_file))
    decrypt = _default_decrypt if decrypt_fn is None else decrypt_fn
    runtime_dir = _runtime_directory(paths)
    owned = {}
    try:
        with tempfile.TemporaryDirectory(
                prefix=".key-recovery-", dir=runtime_dir) as directory:
            staged = os.path.join(directory, "signing-key.age")
            recovered = os.path.join(directory, "signing-key")
            _atomic_write(staged, ciphertext, mode=0o600)
            decrypt(staged, recovered, identity_file)
            recovered_bytes = _read_regular(
                recovered, MAX_PRIVATE_KEY_BYTES,
                unavailable="online signing key recovery failed",
                too_large="online signing key recovery failed")
            if _derive_public_bytes(
                    paths, recovered_bytes, timeout=timeout,
                    ssh_keygen=ssh_keygen) != public:
                raise InstructionKeyError(
                    "recovered online key does not match its public key")
            _publish_owned(paths.runtime_key + ".pub", public, 0o644, owned)
            _move_owned(recovered, paths.runtime_key, 0o600, owned)
        return recovered_bytes, public
    except Exception:
        for target, identity in reversed(tuple(owned.items())):
            _unlink_owned(target, identity)
        raise InstructionKeyError("online signing key recovery failed") from None


def _generate_online_key_locked(paths, recipients_csv, *, identity_file,
                                encrypt_fn, decrypt_fn, timeout, ssh_keygen):
    if not isinstance(recipients_csv, str) or not recipients_csv.strip():
        raise InstructionKeyError("age recipients are required")
    targets = (paths.runtime_key, paths.runtime_key + ".pub",
               paths.encrypted_key, paths.public_key, paths.certificate,
               paths.runtime_certificate)
    if any(_path_exists(
            target, "instruction signing key material is unreadable")
           for target in targets):
        raise InstructionKeyError("instruction signing key material already exists")
    runtime_dir = _runtime_directory(paths)
    config_dir = os.path.dirname(paths.encrypted_key)
    os.makedirs(config_dir, mode=0o700, exist_ok=True)
    identity_file = (os.environ.get(
        "IRIS_AGE_KEY_FILE", "/run/secrets/iris_age_key")
                     if identity_file is None else os.fspath(identity_file))
    encrypt = _default_encrypt if encrypt_fn is None else encrypt_fn
    decrypt = _default_decrypt if decrypt_fn is None else decrypt_fn
    owned = {}
    stage_ciphertext = None
    try:
        with tempfile.TemporaryDirectory(
                prefix=".key-generation-", dir=runtime_dir) as directory:
            private = os.path.join(directory, "signing-key")
            result = _run_ssh(
                ["-q", "-t", "ed25519", "-N", "", "-C",
                 "iris-online-instructions", "-f", private],
                timeout=timeout, ssh_keygen=ssh_keygen)
            if result.returncode != 0:
                raise InstructionKeyError("online signing key generation failed")
            os.chmod(private, 0o600)
            private_bytes = _read_regular(
                private, MAX_PRIVATE_KEY_BYTES,
                unavailable="online signing key generation failed",
                too_large="online signing key generation failed")
            public_bytes = _public_key_bytes(
                Path(private + ".pub").read_bytes(),
                message="online public key")

            fd, stage_ciphertext = tempfile.mkstemp(
                dir=config_dir, prefix=".signing-key.age.generation-")
            os.close(fd)
            os.unlink(stage_ciphertext)
            encrypt(private, stage_ciphertext, recipients_csv)
            _read_regular(
                stage_ciphertext, MAX_KEYLIST_BYTES,
                unavailable="online signing key encryption failed",
                too_large="online signing key ciphertext is too large")
            _fsync_file(stage_ciphertext)
            _fsync_directory(config_dir)
            recovered = os.path.join(directory, "recovered-signing-key")
            try:
                decrypt(stage_ciphertext, recovered, identity_file)
            except Exception:
                raise InstructionKeyError(
                    "online signing key ciphertext cannot be recovered") from None
            recovered_bytes = _read_regular(
                recovered, MAX_PRIVATE_KEY_BYTES,
                unavailable="online signing key recovery failed",
                too_large="online signing key recovery failed")
            if recovered_bytes != private_bytes:
                raise InstructionKeyError(
                    "online signing key ciphertext cannot be recovered")
            if _derive_public_bytes(
                    paths, recovered_bytes, timeout=timeout,
                    ssh_keygen=ssh_keygen) != public_bytes:
                raise InstructionKeyError(
                    "online signing key ciphertext cannot be recovered")

            _move_owned(stage_ciphertext, paths.encrypted_key, 0o600, owned)
            stage_ciphertext = None
            _publish_owned(paths.public_key, public_bytes, 0o644, owned)
            _publish_owned(paths.runtime_key + ".pub", public_bytes, 0o644,
                           owned)
            _move_owned(private, paths.runtime_key, 0o600, owned)
    except Exception as exc:
        if stage_ciphertext is not None:
            _unlink_temporary(stage_ciphertext)
        for target, identity in reversed(tuple(owned.items())):
            _unlink_owned(target, identity)
        if isinstance(exc, InstructionKeyError):
            raise
        raise InstructionKeyError("online signing key setup failed") from None
    return {"state": "generated", "public_key_path": paths.public_key,
            "encrypted_key_path": paths.encrypted_key}


def generate_online_key(paths, recipients_csv, *, identity_file=None,
                        encrypt_fn=None, decrypt_fn=None,
                        timeout=SSH_TIMEOUT, ssh_keygen="ssh-keygen"):
    with _custody_lock(paths):
        return _generate_online_key_locked(
            paths, recipients_csv, identity_file=identity_file,
            encrypt_fn=encrypt_fn, decrypt_fn=decrypt_fn, timeout=timeout,
            ssh_keygen=ssh_keygen)


def _certificate_operation_locked(paths, private, public, certificate_bytes,
                                  roots, *, now, krl, body, timeout,
                                  ssh_keygen):
    roots = _snapshot_roots(roots)
    with tempfile.TemporaryDirectory(
            prefix=".certificate-check-",
            dir=_runtime_directory(paths)) as directory:
        private_path = os.path.join(directory, "signing-key")
        certificate_path = private_path + "-cert.pub"
        public_path = os.path.join(directory, "signing-key.pub")
        _atomic_write(private_path, private, mode=0o600)
        _atomic_write(certificate_path, certificate_bytes, mode=0o600)
        _atomic_write(public_path, public, mode=0o644)
        if _fingerprint(
                certificate_path, timeout=timeout,
                ssh_keygen=ssh_keygen) != _fingerprint(
                    public_path, timeout=timeout, ssh_keygen=ssh_keygen):
            raise InstructionKeyError("certificate does not match the online key")
        start, end, principals = _certificate_fields(
            certificate_path, timeout=timeout, ssh_keygen=ssh_keygen)
        if principals != [ONLINE_PRINCIPAL]:
            raise InstructionKeyError("certificate principal is invalid")
        lifetime = end - start
        if abs(lifetime - CERTIFICATE_LIFETIME_SECONDS) > \
                CERTIFICATE_TIME_TOLERANCE:
            raise InstructionKeyError(
                "certificate does not have a 30-day validity")
        if not start <= now < end:
            raise InstructionKeyError(
                "certificate is outside its validity interval")
        challenge = b"IRIS online certificate validation v1\n"
        proof = _run_ssh(
            ["-Y", "sign", "-f", certificate_path,
             "-n", INSTRUCTION_NAMESPACE], data=challenge,
            timeout=timeout, ssh_keygen=ssh_keygen, check=True).stdout
        matches = _matching_roots(
            challenge, proof, roots, identity=ONLINE_PRINCIPAL,
            namespace=INSTRUCTION_NAMESPACE, krl=krl, verify_time=now,
            timeout=timeout, ssh_keygen=ssh_keygen,
            certificate_authority=True)
        if not matches:
            raise InstructionKeyError(
                "certificate is not chained to a configured root")
        if len(matches) != 1:
            raise InstructionKeyError(
                "certificate must chain to exactly one configured root")
        signature = None
        if body is not None:
            if end - now <= CERTIFICATE_REFUSE_SECONDS:
                raise SigningUnavailable(
                    "online certificate is in its last seven days")
            signature = _run_ssh(
                ["-Y", "sign", "-f", certificate_path,
                 "-n", INSTRUCTION_NAMESPACE], data=body,
                timeout=timeout, ssh_keygen=ssh_keygen, check=True).stdout
            if not signature.startswith(b"-----BEGIN SSH SIGNATURE-----\n"):
                raise InstructionKeyError(
                    "OpenSSH returned an invalid signature")
    return ({"valid_after": start, "valid_before": end,
             "lifetime_seconds": lifetime, "principal": ONLINE_PRINCIPAL,
             "root_id": matches[0]}, signature)


def _installed_krl_locked(paths, roots, *, timeout, ssh_keygen):
    snapshot = _load_keylist_snapshot_locked(
        paths, roots, timeout=timeout, ssh_keygen=ssh_keygen)
    if snapshot is None:
        return None
    if not snapshot["metadata_consistent"]:
        raise InstructionKeyError(
            "keylist metadata requires an identical retry")
    return snapshot["parsed"]["krl"]


def validate_online_certificate(paths, candidate, roots, *, now=None,
                                timeout=SSH_TIMEOUT,
                                ssh_keygen="ssh-keygen"):
    now = int(time.time()) if now is None else now
    if not _is_int(now):
        raise InstructionKeyError("certificate validation time is invalid")
    with _custody_lock(paths):
        private, public = _ensure_runtime_key_locked(
            paths, required=True, timeout=timeout, ssh_keygen=ssh_keygen)
        roots = _snapshot_roots(roots)
        krl = _installed_krl_locked(
            paths, roots, timeout=timeout, ssh_keygen=ssh_keygen)
        candidate_bytes = _read_regular(
            candidate, MAX_CERTIFICATE_BYTES,
            unavailable="online certificate is unavailable",
            too_large="online certificate is too large")
        info, _ = _certificate_operation_locked(
            paths, private, public, candidate_bytes, roots, now=now,
            krl=krl, body=None,
            timeout=timeout, ssh_keygen=ssh_keygen)
        return info


def export_online_public(paths, destination=None, *, timeout=SSH_TIMEOUT,
                         ssh_keygen="ssh-keygen"):
    with _custody_lock(paths):
        _private, public = _ensure_runtime_key_locked(
            paths, required=True, timeout=timeout, ssh_keygen=ssh_keygen)
        target = paths.public_key if destination is None else os.fspath(destination)
        _atomic_write(target, public, mode=0o644)
        return target


def import_online_certificate(paths, candidate, roots, *, now=None,
                              timeout=SSH_TIMEOUT,
                              ssh_keygen="ssh-keygen"):
    now = int(time.time()) if now is None else now
    if not _is_int(now):
        raise InstructionKeyError("certificate validation time is invalid")
    with _custody_lock(paths):
        private, public = _ensure_runtime_key_locked(
            paths, required=True, timeout=timeout, ssh_keygen=ssh_keygen)
        roots = _snapshot_roots(roots)
        krl = _installed_krl_locked(
            paths, roots, timeout=timeout, ssh_keygen=ssh_keygen)
        candidate_bytes = _read_regular(
            candidate, MAX_CERTIFICATE_BYTES,
            unavailable="online certificate is unavailable",
            too_large="online certificate is too large")
        info, _ = _certificate_operation_locked(
            paths, private, public, candidate_bytes, roots, now=now,
            krl=krl, body=None,
            timeout=timeout, ssh_keygen=ssh_keygen)
        try:
            # The runtime copy is a disposable cache.  Finish its fallible
            # publication before committing the durable authority.  The
            # durable atomic replace is the commit boundary; an error from its
            # following directory fsync may therefore report failure after the
            # new authority is already visible.
            _atomic_write(paths.runtime_certificate, candidate_bytes, mode=0o644)
            _atomic_write(paths.certificate, candidate_bytes, mode=0o644)
        except OSError:
            raise InstructionKeyError(
                "online certificate publication failed") from None
        return info


def sign_instruction(paths, data, roots, *, now=None, timeout=SSH_TIMEOUT,
                     ssh_keygen="ssh-keygen"):
    if not isinstance(data, bytes):
        raise TypeError("instruction body must be bytes")
    now = int(time.time()) if now is None else now
    if not _is_int(now):
        raise InstructionKeyError("certificate validation time is invalid")
    with _custody_lock(paths):
        private, public = _ensure_runtime_key_locked(
            paths, required=True, timeout=timeout, ssh_keygen=ssh_keygen)
        roots = _snapshot_roots(roots)
        krl = _installed_krl_locked(
            paths, roots, timeout=timeout, ssh_keygen=ssh_keygen)
        certificate = _read_regular(
            paths.certificate, MAX_CERTIFICATE_BYTES,
            unavailable="online certificate is unavailable",
            too_large="online certificate is too large")
        _info, signature = _certificate_operation_locked(
            paths, private, public, certificate, roots, now=now, krl=krl,
            body=data,
            timeout=timeout, ssh_keygen=ssh_keygen)
        _atomic_write(paths.runtime_certificate, certificate, mode=0o644)
        return signature


def _validate_keylist_metadata(metadata):
    expected = {"v", "keylist_seq", "issued_at", "signer_root_id",
                "krl_sha256"}
    if not isinstance(metadata, dict) or set(metadata) != expected:
        raise InstructionKeyError("keylist metadata schema is invalid")
    if type(metadata["v"]) is not int or metadata["v"] != 1:
        raise InstructionKeyError("keylist version is invalid")
    if not _is_int(metadata["keylist_seq"], minimum=1):
        raise InstructionKeyError("keylist sequence is invalid")
    if not _is_int(metadata["issued_at"]):
        raise InstructionKeyError("keylist issue time is invalid")
    if not isinstance(metadata["signer_root_id"], str) or not \
            _ROOT_ID.fullmatch(metadata["signer_root_id"]):
        raise InstructionKeyError("keylist claimed root id is invalid")
    if not isinstance(metadata["krl_sha256"], str) or not \
            _SHA256.fullmatch(metadata["krl_sha256"]):
        raise InstructionKeyError("keylist KRL digest is invalid")
    return metadata


def _validate_krl_bytes(krl, *, timeout=SSH_TIMEOUT,
                        ssh_keygen="ssh-keygen"):
    if not isinstance(krl, bytes):
        raise TypeError("KRL must be bytes")
    if len(krl) > MAX_KRL_BYTES:
        raise InstructionKeyError("KRL is too large")
    if not krl:
        return
    if not krl.startswith(b"SSHKRL\n\x00"):
        raise InstructionKeyError("keylist data is not an OpenSSH KRL")
    with tempfile.TemporaryDirectory(prefix="iris-krl-check-") as directory:
        candidate = os.path.join(directory, "candidate.krl")
        _atomic_write(candidate, krl, mode=0o600)
        # With no query keys OpenSSH still parses the complete KRL and returns
        # zero only for its binary KRL format.  This rejects the alternate
        # revoked-key text format without manufacturing a probe key.
        result = _run_ssh(
            ["-Q", "-f", candidate], timeout=timeout,
            ssh_keygen=ssh_keygen)
        if result.returncode != 0:
            raise InstructionKeyError("keylist data is not an OpenSSH KRL")


def build_keylist_payload(krl, *, keylist_seq, issued_at, signer_root_id,
                          timeout=SSH_TIMEOUT, ssh_keygen="ssh-keygen"):
    _validate_krl_bytes(krl, timeout=timeout, ssh_keygen=ssh_keygen)
    metadata = _validate_keylist_metadata({
        "v": 1, "keylist_seq": keylist_seq, "issued_at": issued_at,
        # This signed field is an operator hint.  Install independently derives
        # the actual root by exit-status verification and rejects disagreement.
        "signer_root_id": signer_root_id,
        "krl_sha256": hashlib.sha256(krl).hexdigest(),
    })
    encoded = json.dumps(
        metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_METADATA_BYTES:
        raise InstructionKeyError("keylist metadata is too large")
    payload = (KEYLIST_HEADER + base64.b64encode(encoded) + b"\n"
               + base64.b64encode(krl) + b"\n")
    if len(payload) > MAX_KEYLIST_PAYLOAD_BYTES:
        raise InstructionKeyError("keylist payload is too large")
    return payload


def _encoded_exceeds_limit(encoded, decoded_limit):
    return len(encoded) > 4 * ((decoded_limit + 2) // 3)


def _parse_keylist_payload(payload):
    if not isinstance(payload, bytes):
        raise InstructionKeyError("keylist payload is invalid")
    if len(payload) > MAX_KEYLIST_PAYLOAD_BYTES:
        raise InstructionKeyError("keylist payload is too large")
    lines = payload.split(b"\n")
    if len(lines) != 4 or lines[0] != KEYLIST_HEADER.rstrip(b"\n") \
            or lines[3] != b"":
        raise InstructionKeyError("keylist payload framing is invalid")
    if _encoded_exceeds_limit(lines[1], MAX_METADATA_BYTES):
        raise InstructionKeyError("keylist metadata is too large")
    if _encoded_exceeds_limit(lines[2], MAX_KRL_BYTES):
        raise InstructionKeyError("KRL is too large")
    try:
        metadata_bytes = base64.b64decode(lines[1], validate=True)
        krl = base64.b64decode(lines[2], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InstructionKeyError("keylist payload encoding is invalid") from exc
    if len(metadata_bytes) > MAX_METADATA_BYTES:
        raise InstructionKeyError("keylist metadata is too large")
    if len(krl) > MAX_KRL_BYTES:
        raise InstructionKeyError("KRL is too large")
    metadata = _strict_json_loads(metadata_bytes, "keylist metadata")
    metadata = _validate_keylist_metadata(metadata)
    canonical = json.dumps(
        metadata, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if base64.b64encode(canonical) != lines[1] \
            or base64.b64encode(krl) != lines[2]:
        raise InstructionKeyError("keylist payload is not canonical")
    if hashlib.sha256(krl).hexdigest() != metadata["krl_sha256"]:
        raise InstructionKeyError("keylist KRL digest is invalid")
    _validate_krl_bytes(krl)
    return metadata, krl


def assemble_keylist_artifact(payload, signature):
    if not isinstance(signature, bytes):
        raise InstructionKeyError("keylist root signature is invalid")
    if len(signature) > MAX_SIGNATURE_BYTES:
        raise InstructionKeyError("keylist signature is too large")
    if not isinstance(payload, bytes):
        raise InstructionKeyError("keylist payload is invalid")
    if len(payload) > MAX_KEYLIST_PAYLOAD_BYTES:
        raise InstructionKeyError("keylist payload is too large")
    if len(payload) + 4 * ((len(signature) + 2) // 3) + 1 > \
            MAX_KEYLIST_BYTES:
        raise InstructionKeyError("keylist artifact is too large")
    _parse_keylist_payload(payload)
    if not signature.startswith(b"-----BEGIN SSH SIGNATURE-----\n"):
        raise InstructionKeyError("keylist root signature is invalid")
    artifact = payload + base64.b64encode(signature) + b"\n"
    if len(artifact) > MAX_KEYLIST_BYTES:
        raise InstructionKeyError("keylist artifact is too large")
    return artifact


def parse_keylist_artifact(artifact):
    if not isinstance(artifact, bytes):
        raise InstructionKeyError("keylist artifact is invalid")
    if len(artifact) > MAX_KEYLIST_BYTES:
        raise InstructionKeyError("keylist artifact is too large")
    lines = artifact.split(b"\n")
    if len(lines) != 5 or lines[-1] != b"":
        raise InstructionKeyError("keylist artifact framing is invalid")
    if _encoded_exceeds_limit(lines[3], MAX_SIGNATURE_BYTES):
        raise InstructionKeyError("keylist signature is too large")
    payload = b"\n".join(lines[:3]) + b"\n"
    metadata, krl = _parse_keylist_payload(payload)
    try:
        signature = base64.b64decode(lines[3], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InstructionKeyError("keylist signature encoding is invalid") from exc
    if len(signature) > MAX_SIGNATURE_BYTES:
        raise InstructionKeyError("keylist signature is too large")
    if base64.b64encode(signature) != lines[3] \
            or not signature.startswith(b"-----BEGIN SSH SIGNATURE-----\n"):
        raise InstructionKeyError("keylist root signature is invalid")
    return {"metadata": metadata, "krl": krl, "signature": signature,
            "payload": payload,
            "artifact_sha256": hashlib.sha256(artifact).hexdigest()}


def _read_keylist_state(path):
    if not _path_exists(path, "keylist state is unreadable"):
        return None
    try:
        document = _strict_json_loads(
            _read_regular(
                path, MAX_METADATA_BYTES,
                unavailable="keylist state is invalid",
                too_large="keylist state is too large"),
            "keylist state")
    except InstructionKeyError:
        raise
    expected = {"schema", "keylist_seq", "artifact_sha256", "krl_sha256",
                "issued_at", "verified_root_id", "root_attestations",
                "updated_at"}
    if not isinstance(document, dict) or set(document) != expected \
            or document.get("schema") != KEYLIST_STATE_SCHEMA \
            or not _is_int(document.get("keylist_seq"), minimum=1) \
            or not isinstance(document.get("artifact_sha256"), str) \
            or not _SHA256.fullmatch(document["artifact_sha256"]) \
            or not isinstance(document.get("krl_sha256"), str) \
            or not _SHA256.fullmatch(document["krl_sha256"]) \
            or not _is_int(document.get("issued_at")) \
            or not isinstance(document.get("verified_root_id"), str) \
            or not _ROOT_ID.fullmatch(document["verified_root_id"]) \
            or not _is_int(document.get("updated_at")):
        raise InstructionKeyError("keylist state is invalid")
    attestations = document.get("root_attestations")
    if not isinstance(attestations, dict) or any(
            not isinstance(root_id, str) or not _ROOT_ID.fullmatch(root_id)
            or not isinstance(attestation, dict)
            or set(attestation) != {"key_sha256", "attested_at"}
            or not isinstance(attestation.get("key_sha256"), str)
            or not _SHA256.fullmatch(attestation["key_sha256"])
            or not _is_int(attestation.get("attested_at"))
            for root_id, attestation in attestations.items()):
        raise InstructionKeyError("keylist state is invalid")
    if len(attestations) > 2:
        raise InstructionKeyError("keylist state is invalid")
    verified = document["verified_root_id"]
    if verified not in attestations \
            or attestations[verified]["attested_at"] < document["issued_at"] \
            or document["updated_at"] + CERTIFICATE_TIME_TOLERANCE < \
            document["issued_at"]:
        raise InstructionKeyError("keylist state is invalid")
    return document


def _keylist_state(parsed, root_id, roots, previous_state, *, now):
    attestations = {}
    if previous_state is not None:
        attestations.update({
            candidate_id: attestation
            for candidate_id, attestation in previous_state[
                "root_attestations"].items()
            if candidate_id in roots and attestation["key_sha256"] ==
            _root_digest(roots[candidate_id])
        })
    metadata = parsed["metadata"]
    # A retry re-verifies the same bytes but is not a new root ceremony.  The
    # root-signed issue time records when the root actually attested; replaying
    # an old artifact must never refresh the 180-day custody signal.
    attested_at = metadata["issued_at"]
    root_key_digest = _root_digest(roots[root_id])
    previous = attestations.get(root_id)
    if isinstance(previous, dict) \
            and previous.get("key_sha256") == root_key_digest \
            and _is_int(previous.get("attested_at")):
        attested_at = max(previous["attested_at"], attested_at)
    attestations[root_id] = {
        "key_sha256": root_key_digest, "attested_at": attested_at}
    return {
        "schema": KEYLIST_STATE_SCHEMA,
        "keylist_seq": metadata["keylist_seq"],
        "artifact_sha256": parsed["artifact_sha256"],
        "krl_sha256": metadata["krl_sha256"],
        "issued_at": metadata["issued_at"],
        "verified_root_id": root_id,
        "root_attestations": attestations,
        "updated_at": now,
    }


def _verify_keylist(parsed, roots, *, previous_krl, timeout, ssh_keygen):
    matches = _matching_roots(
        parsed["payload"], parsed["signature"], roots,
        identity=ROOT_PRINCIPAL, namespace=KEYLIST_NAMESPACE,
        krl=previous_krl, timeout=timeout, ssh_keygen=ssh_keygen,
        certificate_authority=False)
    if not matches:
        raise InstructionKeyError(
            "keylist signature did not match a configured root")
    if len(matches) != 1:
        raise InstructionKeyError(
            "keylist signature must match exactly one configured root")
    root_id = matches[0]
    if parsed["metadata"]["signer_root_id"] != root_id:
        raise InstructionKeyError(
            "keylist claimed root does not match the verified root")
    return root_id


def _load_keylist_snapshot_locked(paths, roots=None, *, timeout=SSH_TIMEOUT,
                                  ssh_keygen="ssh-keygen"):
    current_exists = _path_exists(
        paths.keylist_current, "installed keylist is unreadable")
    state_exists = _path_exists(
        paths.keylist_state, "keylist state is unreadable")
    if not current_exists and not state_exists:
        return None
    if not current_exists:
        raise InstructionKeyError("established keylist is missing")
    current_bytes = _read_regular(
        paths.keylist_current, MAX_KEYLIST_BYTES,
        unavailable="installed keylist is invalid",
        too_large="installed keylist is too large")
    parsed = parse_keylist_artifact(current_bytes)
    state = _read_keylist_state(paths.keylist_state)
    consistent = False
    if state is not None:
        sequence = parsed["metadata"]["keylist_seq"]
        if state["keylist_seq"] > sequence:
            raise InstructionKeyError("keylist state is ahead of the artifact")
        if state["keylist_seq"] == sequence:
            if state["artifact_sha256"] != parsed["artifact_sha256"] \
                    or state["krl_sha256"] != parsed["metadata"]["krl_sha256"] \
                    or state["issued_at"] != parsed["metadata"]["issued_at"] \
                    or state["verified_root_id"] != \
                    parsed["metadata"]["signer_root_id"]:
                raise InstructionKeyError("keylist state does not match the artifact")
            consistent = True
    return {"bytes": current_bytes, "parsed": parsed, "state": state,
            "metadata_consistent": consistent}


def read_keylist_snapshot(paths):
    """Read exact installed delivery bytes and identity under custody lock.

    The installed artifact is authoritative during metadata crash recovery.
    This reader uses the same bounded parse and consistency rules as custody,
    but does not reverify roots, repair metadata, or install anything.
    """
    try:
        with _custody_lock(paths):
            snapshot = _load_keylist_snapshot_locked(paths)
            if snapshot is None:
                return None
            parsed = snapshot["parsed"]
            return {
                "bytes": bytes(snapshot["bytes"]),
                "keylist_seq": parsed["metadata"]["keylist_seq"],
                "artifact_sha256": parsed["artifact_sha256"],
            }
    except OSError as exc:
        raise InstructionKeyError("installed keylist is unreadable") from exc


def install_keylist(paths, artifact, roots, *, now=None, timeout=SSH_TIMEOUT,
                    ssh_keygen="ssh-keygen"):
    now = int(time.time()) if now is None else now
    if not _is_int(now):
        raise InstructionKeyError("keylist installation time is invalid")
    if not isinstance(artifact, bytes):
        raise InstructionKeyError("keylist artifact is invalid")
    if len(artifact) > MAX_KEYLIST_BYTES:
        raise InstructionKeyError("keylist artifact is too large")
    parsed = parse_keylist_artifact(artifact)
    if parsed["metadata"]["issued_at"] > now + CERTIFICATE_TIME_TOLERANCE:
        raise InstructionKeyError("keylist issue time is in the future")
    roots = _snapshot_roots(roots)
    with _custody_lock(paths):
        snapshot = _load_keylist_snapshot_locked(
            paths, roots, timeout=timeout, ssh_keygen=ssh_keygen)
        current = None if snapshot is None else snapshot["parsed"]
        current_bytes = None if snapshot is None else snapshot["bytes"]
        if snapshot is not None:
            old_seq = current["metadata"]["keylist_seq"]
            new_seq = parsed["metadata"]["keylist_seq"]
            if new_seq < old_seq or (new_seq == old_seq
                                     and artifact != current_bytes):
                raise InstructionKeyError(
                    "keylist sequence must strictly increase")
            if new_seq == old_seq:
                # The artifact is the authority.  This path repairs metadata
                # after a crash between its replace and the state replace.
                root_id = _verify_keylist(
                    current, roots, previous_krl=None, timeout=timeout,
                    ssh_keygen=ssh_keygen)
                previous_state = snapshot["state"]
                state = _keylist_state(
                    current, root_id, roots, previous_state, now=now)
                _atomic_write_json(paths.keylist_state, state)
                return {"keylist_seq": new_seq,
                        "verified_root_id": root_id, "retry": True}
            if not snapshot["metadata_consistent"]:
                raise InstructionKeyError(
                    "keylist metadata requires an identical retry")
            if parsed["metadata"]["issued_at"] < \
                    current["metadata"]["issued_at"]:
                raise InstructionKeyError("keylist issue time moved backwards")
        root_id = _verify_keylist(
            parsed, roots,
            previous_krl=current["krl"] if current is not None else None,
            timeout=timeout, ssh_keygen=ssh_keygen)
        previous_state = None if snapshot is None else snapshot["state"]
        # Commit the complete verified artifact first.  If metadata fails, a
        # retry derives sequence/digest from these authoritative bytes.
        _atomic_write(paths.keylist_current, artifact, mode=0o644)
        state = _keylist_state(
            parsed, root_id, roots, previous_state, now=now)
        _atomic_write_json(paths.keylist_state, state)
        return {"keylist_seq": parsed["metadata"]["keylist_seq"],
                "verified_root_id": root_id, "retry": False}


def _keylist_info_locked(paths):
    snapshot = _load_keylist_snapshot_locked(paths)
    if snapshot is None:
        return None
    parsed = snapshot["parsed"]
    state = snapshot["state"]
    attestations = {}
    if state is not None and snapshot["metadata_consistent"]:
        attestations = dict(state["root_attestations"])
    metadata = parsed["metadata"]
    return {"keylist_seq": metadata["keylist_seq"],
            "issued_at": metadata["issued_at"],
            "krl_sha256": metadata["krl_sha256"],
            "artifact_sha256": parsed["artifact_sha256"],
            "root_attestations": attestations,
            "metadata_consistent": snapshot["metadata_consistent"]}


def keylist_info(paths):
    with _custody_lock(paths):
        return _keylist_info_locked(paths)


def keylist_resign_due(paths, *, now=None):
    now = int(time.time()) if now is None else now
    if not _is_int(now):
        raise InstructionKeyError("keylist status time is invalid")
    info = keylist_info(paths)
    return (info is None
            or not info["metadata_consistent"]
            or now - info["issued_at"] >= KEYLIST_RESIGN_SECONDS)


def _validate_epoch(document):
    expected = {"schema", "epoch", "updated_at"}
    if not isinstance(document, dict) or set(document) != expected \
            or document.get("schema") != EPOCH_SCHEMA \
            or not _is_int(document.get("epoch")) \
            or not _is_int(document.get("updated_at")):
        raise InstructionKeyError("instruction epoch document is invalid")
    return document


def read_epoch(paths):
    """Read without creating either the state file or its lock sidecar."""
    try:
        data = _read_regular(
            paths.epoch, MAX_METADATA_BYTES,
            unavailable="instruction epoch document is unavailable",
            too_large="instruction epoch document is too large")
    except InstructionKeyError as exc:
        if not _path_exists(
                paths.epoch, "instruction epoch document is unreadable"):
            return None
        raise exc
    return _validate_epoch(_strict_json_loads(data, "instruction epoch document"))


def new_epoch(paths, *, now=None):
    value = time.time() if now is None else now
    if isinstance(value, bool) or not isinstance(value, (int, float)) \
            or value < 0 or value > MAX_SERIALIZED_INTEGER - 1 \
            or not math.isfinite(value):
        raise InstructionKeyError("instruction epoch clock is invalid")
    unix_floor = int(value)
    os.makedirs(os.path.dirname(paths.epoch) or ".", mode=0o700,
                exist_ok=True)
    lock_fd = os.open(paths.epoch_lock, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        current = read_epoch(paths)
        old = current["epoch"] if current is not None else -1
        if old >= MAX_SERIALIZED_INTEGER:
            raise InstructionKeyError("instruction epoch cannot advance")
        document = {"schema": EPOCH_SCHEMA,
                    "epoch": max(old, unix_floor) + 1,
                    "updated_at": unix_floor}
        _atomic_write_json(paths.epoch, document)
        return document
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


_STATUS_KEYS = {
    "schema", "enabled", "state", "certificate_days_to_expiry",
    "certificate_renewal_due", "signing_refused", "keylist_seq",
    "keylist_age_days", "keylist_resign_due", "roots_configured",
    "roots_attested_180d", "root_ceremony_overdue",
    "root_quorum_degraded", "updated_at",
}
_STATUS_STATES = {"phase0", "ready", "renewal_due", "signing_refused",
                  "keylist_missing", "invalid", "error"}


def build_custody_status(*, now, enabled, certificate_info, keylist_info,
                         roots_configured, force_invalid=False):
    if not _is_int(now) or not isinstance(enabled, bool) \
            or not _is_int(roots_configured, maximum=2) \
            or not isinstance(force_invalid, bool):
        raise InstructionKeyError("custody status input is invalid")
    cert_days = None
    renewal_due = False
    signing_refused = False
    if certificate_info is not None:
        start = certificate_info.get("valid_after")
        end = certificate_info.get("valid_before")
        if not _is_int(start) or not _is_int(end) or end <= start:
            raise InstructionKeyError("custody certificate status is invalid")
        cert_days = (end - now) // 86400
        renewal_due = now >= start + (end - start) // 2
        signing_refused = end - now <= CERTIFICATE_REFUSE_SECONDS

    keylist_seq = None
    keylist_age = None
    resign_due = False
    attestations = {}
    if keylist_info is not None:
        keylist_seq = keylist_info.get("keylist_seq")
        issued_at = keylist_info.get("issued_at")
        attestations = keylist_info.get("root_attestations", {})
        if not _is_int(keylist_seq, minimum=1) or not _is_int(issued_at) \
                or not isinstance(attestations, dict):
            raise InstructionKeyError("custody keylist status is invalid")
        keylist_age = max(0, (now - issued_at) // 86400)
        resign_due = now - issued_at >= KEYLIST_RESIGN_SECONDS

    attested = len({
        root_id for root_id, attestation in attestations.items()
        if isinstance(root_id, str) and _ROOT_ID.fullmatch(root_id)
        and isinstance(attestation, dict)
        and set(attestation) == {"key_sha256", "attested_at"}
        and isinstance(attestation.get("key_sha256"), str)
        and _SHA256.fullmatch(attestation["key_sha256"])
        and _is_int(attestation.get("attested_at"))
        and now - ROOT_ATTEST_SECONDS <= attestation["attested_at"]
        <= now + CERTIFICATE_TIME_TOLERANCE})
    if attested > roots_configured:
        raise InstructionKeyError("custody root attestation status is invalid")
    if keylist_age is None:
        ceremony = "critical" if enabled else "unknown"
    elif keylist_age >= ROOT_CEREMONY_CRITICAL_DAYS:
        ceremony = "critical"
    elif keylist_age >= ROOT_CEREMONY_WARN_DAYS:
        ceremony = "warn"
    else:
        ceremony = "ok"
    if force_invalid:
        state = "invalid"
    elif not enabled:
        state = "phase0"
    elif certificate_info is None:
        state = "invalid"
    elif signing_refused:
        state = "signing_refused"
    elif keylist_info is None:
        state = "keylist_missing"
    elif renewal_due:
        state = "renewal_due"
    else:
        state = "ready"
    return {
        "schema": STATUS_SCHEMA, "enabled": enabled, "state": state,
        "certificate_days_to_expiry": cert_days,
        "certificate_renewal_due": renewal_due,
        "signing_refused": signing_refused,
        "keylist_seq": keylist_seq, "keylist_age_days": keylist_age,
        "keylist_resign_due": resign_due,
        "roots_configured": roots_configured,
        "roots_attested_180d": attested,
        "root_ceremony_overdue": ceremony,
        "root_quorum_degraded": enabled and attested < 2,
        "updated_at": now,
    }


def _validate_status(document):
    if not isinstance(document, dict) or set(document) != _STATUS_KEYS \
            or document.get("schema") != STATUS_SCHEMA \
            or not isinstance(document.get("enabled"), bool) \
            or not isinstance(document.get("state"), str) \
            or document["state"] not in _STATUS_STATES \
            or not isinstance(document.get("certificate_renewal_due"), bool) \
            or not isinstance(document.get("signing_refused"), bool) \
            or not isinstance(document.get("keylist_resign_due"), bool) \
            or not isinstance(document.get("root_quorum_degraded"), bool) \
            or not isinstance(document.get("root_ceremony_overdue"), str) \
            or document["root_ceremony_overdue"] not in {
                "unknown", "ok", "warn", "critical"} \
            or not _is_int(document.get("roots_configured"), maximum=2) \
            or not _is_int(document.get("roots_attested_180d"), maximum=2) \
            or not _is_int(document.get("updated_at")):
        raise InstructionKeyError("instruction custody status is invalid")
    for field in ("certificate_days_to_expiry", "keylist_seq",
                  "keylist_age_days"):
        value = document.get(field)
        if value is not None and (type(value) is not int
                                  or abs(value) > MAX_SERIALIZED_INTEGER):
            raise InstructionKeyError("instruction custody status is invalid")
    if document["keylist_seq"] is not None and document["keylist_seq"] < 1:
        raise InstructionKeyError("instruction custody status is invalid")
    if document["keylist_age_days"] is not None \
            and document["keylist_age_days"] < 0:
        raise InstructionKeyError("instruction custody status is invalid")
    configured = document["roots_configured"]
    attested = document["roots_attested_180d"]
    has_certificate = document["certificate_days_to_expiry"] is not None
    has_keylist = document["keylist_seq"] is not None
    if (has_certificate and document["certificate_days_to_expiry"] < 0) \
            or (not has_certificate and (
                document["certificate_renewal_due"]
                or document["signing_refused"])) \
            or (document["signing_refused"]
                and not document["certificate_renewal_due"]) \
            or has_keylist != (document["keylist_age_days"] is not None):
        raise InstructionKeyError("instruction custody status is invalid")
    expected_ceremony = (
        "critical" if document["enabled"] else "unknown")
    if has_keylist:
        age = document["keylist_age_days"]
        expected_ceremony = (
            "critical" if age >= ROOT_CEREMONY_CRITICAL_DAYS else
            "warn" if age >= ROOT_CEREMONY_WARN_DAYS else "ok")
        if document["keylist_resign_due"] != (
                age >= KEYLIST_RESIGN_SECONDS // 86400):
            raise InstructionKeyError("instruction custody status is invalid")
    elif document["keylist_resign_due"]:
        raise InstructionKeyError("instruction custody status is invalid")
    state = document["state"]
    if document["root_ceremony_overdue"] != expected_ceremony \
            or (state == "phase0" and (
                document["enabled"] or has_certificate or has_keylist
                or attested != 0)) \
            or (state == "ready" and (
                not document["enabled"] or not has_certificate
                or not has_keylist or document["certificate_renewal_due"]
                or document["signing_refused"])) \
            or (state == "renewal_due" and (
                not document["enabled"] or not has_certificate
                or not has_keylist or not document["certificate_renewal_due"]
                or document["signing_refused"])) \
            or (state == "signing_refused" and (
                not document["enabled"] or not has_certificate
                or not document["signing_refused"])) \
            or (state == "keylist_missing" and (
                not document["enabled"] or not has_certificate
                or has_keylist or document["signing_refused"])):
        raise InstructionKeyError("instruction custody status is invalid")
    if attested > configured \
            or document["root_quorum_degraded"] != (
                document["enabled"] and attested < 2) \
            or (not document["enabled"] and document["state"] != "phase0"):
        raise InstructionKeyError("instruction custody status is invalid")
    return document


def write_status(paths, status):
    _atomic_write_json(paths.status, _validate_status(status))


def read_status_file(path, *, now=None):
    now = int(time.time()) if now is None else now
    if not _is_int(now):
        return None
    try:
        document = _strict_json_loads(
            _read_regular(
                path, MAX_METADATA_BYTES,
                unavailable="instruction custody status is unavailable",
                too_large="instruction custody status is too large"),
            "instruction custody status")
        document = _validate_status(document)
        age = now - document["updated_at"]
        if age > STATUS_MAX_AGE_SECONDS \
                or age < -STATUS_FUTURE_TOLERANCE_SECONDS:
            return None
        return document
    except (InstructionKeyError, TypeError, ValueError, RecursionError):
        return None


def refresh_custody_status(paths, roots=None, *, now=None,
                           timeout=SSH_TIMEOUT, ssh_keygen="ssh-keygen"):
    now = int(time.time()) if now is None else now
    if not _is_int(now):
        raise InstructionKeyError("custody status time is invalid")
    with _custody_lock(paths):
        invalid = False
        try:
            roots = (discover_roots(paths) if roots is None
                     else _snapshot_roots(roots))
        except InstructionKeyError:
            roots = {}
            invalid = True
        try:
            custody_present = any(_path_exists(
                path, "instruction custody material is unreadable")
                for path in (paths.encrypted_key, paths.runtime_key,
                             paths.public_key, paths.certificate,
                             paths.keylist_current, paths.keylist_state))
        except InstructionKeyError:
            custody_present = True
            invalid = True
        enabled = invalid or custody_present
        private_ready = False
        private = public = None
        try:
            has_online_key = (
                _path_exists(paths.encrypted_key,
                             "online signing key ciphertext is unreadable")
                or _path_exists(paths.runtime_key,
                                "online runtime key is unreadable"))
        except InstructionKeyError:
            has_online_key = False
            invalid = True
        if has_online_key:
            try:
                private, public = _ensure_runtime_key_locked(
                    paths, required=True, timeout=timeout,
                    ssh_keygen=ssh_keygen)
                private_ready = True
            except InstructionKeyError:
                invalid = True
        certificate_info = None
        snapshot = None
        keylist_valid = True
        try:
            snapshot = _load_keylist_snapshot_locked(
                paths, roots, timeout=timeout, ssh_keygen=ssh_keygen)
            if snapshot is not None and not snapshot["metadata_consistent"]:
                invalid = True
        except InstructionKeyError:
            invalid = True
            keylist_valid = False
        current_keylist = None
        krl = None
        if snapshot is not None:
            parsed = snapshot["parsed"]
            krl = parsed["krl"]
            attestations = {}
            if snapshot["state"] is not None \
                    and snapshot["metadata_consistent"]:
                for root_id, attestation in snapshot[
                        "state"]["root_attestations"].items():
                    if root_id in roots and attestation["key_sha256"] == \
                            _root_digest(roots[root_id]):
                        attestations[root_id] = attestation
            current_keylist = {
                "keylist_seq": parsed["metadata"]["keylist_seq"],
                "issued_at": parsed["metadata"]["issued_at"],
                "root_attestations": attestations,
            }
        try:
            has_certificate = _path_exists(
                paths.certificate, "online certificate is unreadable")
        except InstructionKeyError:
            has_certificate = False
            invalid = True
        if private_ready and has_certificate and roots and keylist_valid:
            try:
                certificate = _read_regular(
                    paths.certificate, MAX_CERTIFICATE_BYTES,
                    unavailable="online certificate is unavailable",
                    too_large="online certificate is too large")
                certificate_info, _ = _certificate_operation_locked(
                    paths, private, public, certificate, roots, now=now,
                    krl=krl, body=None,
                    timeout=timeout, ssh_keygen=ssh_keygen)
            except InstructionKeyError:
                invalid = True
                certificate_info = None
        elif enabled:
            invalid = True
        status = build_custody_status(
            now=now, enabled=enabled, certificate_info=certificate_info,
            keylist_info=current_keylist, roots_configured=len(roots),
            force_invalid=invalid)
        write_status(paths, status)
        return status


def status_loop(stop_event, paths=None, interval=3600):
    paths = InstructionPaths.from_env() if paths is None else paths
    while not stop_event.is_set():
        try:
            refresh_custody_status(paths)
        except Exception:
            try:
                write_status(paths, build_custody_status(
                    now=int(time.time()), enabled=True,
                    certificate_info=None, keylist_info=None,
                    roots_configured=0))
            except Exception:
                pass
        if stop_event.wait(interval):
            break
