# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""At-rest encryption helpers for the IRIS server secret files.

Whole-file `age` (the store is machine-rewritten, so structured partial
encryption buys little). The server MAY use third-party tooling — the
stdlib-only rule is agent-only. The `age` binary is installed in the
server Dockerfile; these helpers shell out to it via subprocess.

Plaintext only ever lives in tmpfs (/run/iris); the persistent copies on
the iris-config volume are always ciphertext (`*.age`).
"""
import json
import os
import subprocess
import tempfile

AGE_BIN = os.environ.get("IRIS_AGE_BIN", "age")


def decrypt_to(enc_path, out_path, key_file, age_bin=AGE_BIN):
    """Decrypt `enc_path` (ciphertext on the volume) to `out_path` (tmpfs)
    using the age identity in `key_file`. Raises CalledProcessError if age
    fails (missing/invalid key, bad ciphertext) — callers fail closed.
    """
    d = os.path.dirname(out_path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    os.close(fd)
    try:
        subprocess.run(
            [age_bin, "-d", "-i", key_file, "-o", tmp, enc_path],
            check=True,
        )
        os.chmod(tmp, 0o600)
        os.replace(tmp, out_path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def encrypt_from(plain_path, enc_path, recipients_csv, age_bin=AGE_BIN):
    """Encrypt the tmpfs plaintext `plain_path` to the persistent ciphertext
    `enc_path`, to every recipient in `recipients_csv` (primary + offline
    break-glass). Written atomically (a UNIQUE tmp in the same dir + os.replace)
    so a crash mid-write never truncates the only encrypted copy, and the
    existing `enc_path` file mode is preserved across rewrites.
    """
    recipients = [r.strip() for r in recipients_csv.split(",") if r.strip()]
    if not recipients:
        raise ValueError("encrypt_from: no recipients")
    cmd = [age_bin]
    for r in recipients:
        cmd += ["-r", r]
    d = os.path.dirname(enc_path) or "."
    mode = None
    try:
        mode = os.stat(enc_path).st_mode
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    os.close(fd)
    try:
        cmd += ["-o", tmp, plain_path]
        subprocess.run(cmd, check=True)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, enc_path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def persist_store(store, plain_path, recipients_csv=None, enc_path=None,
                  age_bin=AGE_BIN):
    """Persist a secrets *store* dict durably, durable-copy-FIRST.

    The live serving copy is the tmpfs plaintext at *plain_path*; the only copy
    that survives a restart is the at-rest ciphertext at *enc_path* (decrypted
    back to tmpfs on every container start).  To avoid the two ever diverging,
    we write the durable ciphertext BEFORE swapping the new plaintext into the
    live path:

      1. Serialize *store* to a UNIQUE temp plaintext beside *plain_path*.
      2. If recipients are configured, encrypt that temp to *enc_path* FIRST
         (atomic, mode-preserving).  If this raises, the live *plain_path* is
         left untouched (still the previous, consistent value) and we re-raise
         — the caller must NOT report success.
      3. Only after the durable write succeeds, os.replace the temp plaintext
         over *plain_path*.

    Crash-safety / no divergence: the durable copy must never be ahead of the
    live copy.  If step 2 succeeded (enc_path now holds the NEW store) but the
    step-3 os.replace then raises (e.g. ENOSPC on tmpfs), enc_path and
    plain_path would diverge — and on the next container start decrypt_to would
    load the NEW enc_path into plain_path, silently materialising a rotation the
    caller already reported as failed (the device's old token would vanish and
    it would 401).  To prevent that, on a step-3 failure we re-encrypt the
    (still-old, untouched) live plain_path back over enc_path, restoring the
    durable==live invariant, then re-raise.  If even that rollback fails, we
    raise the rollback error (durable is known-diverged and the operator must
    intervene) rather than masking it.

    With no recipients (at-rest encryption disabled, e.g. tests), there is no
    durable copy, so step 2 is skipped and the plaintext is written atomically.
    The serialization matches secrets_store.save (indent=2, sort_keys=True) and
    the target *plain_path* file mode is preserved.
    """
    d = os.path.dirname(plain_path) or "."
    mode = None
    try:
        mode = os.stat(plain_path).st_mode
    except OSError:
        pass
    recipients = [r.strip() for r in (recipients_csv or "").split(",")
                  if r.strip()]
    fd, tmp_plain = tempfile.mkstemp(dir=d, prefix=".secrets-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(store, f, indent=2, sort_keys=True)
        if mode is not None:
            os.chmod(tmp_plain, mode)
        durable_written = False
        if recipients:
            # Durable FIRST: if this raises, plain_path is never touched.
            encrypt_from(tmp_plain, enc_path, recipients_csv, age_bin=age_bin)
            durable_written = True
        # Commit the live plaintext only after the durable write succeeded.
        try:
            os.replace(tmp_plain, plain_path)
        except OSError:
            # The durable copy is now ahead of the live copy.  Roll the durable
            # copy back to match the (untouched) old live plaintext so a restart
            # does not silently apply the rotation we are about to fail.
            if durable_written and os.path.exists(plain_path):
                encrypt_from(plain_path, enc_path, recipients_csv,
                             age_bin=age_bin)
            raise
    finally:
        if os.path.exists(tmp_plain):
            os.remove(tmp_plain)
