# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Console (web UI) TLS certificate override (stdlib + repo modules only).

The console may serve a custom operator-supplied certificate instead of the
shared, device-pinned bootstrap identity (spec feature A1). Durable copies
live on the config volume: $IRIS_CONFIG/tls/gui-crt.pem (plaintext —
certificates are public material, like crt.pem) plus gui-key.pem.age
(age-encrypted to the same IRIS_AGE_RECIPIENTS the secrets store uses;
plaintext keys never touch the volume). The serving copy is the combined
cert(+chain)+key file at IRIS_GUI_CERT (default /run/iris/tls/gui-cert.pem,
tmpfs, 0600) — the same shape docker-entrypoint.sh / iris-secretfs rebuild
from the durable pair at boot. Persistence is durable-FIRST with rollback,
mirroring secretfs.persist_store: a failed runtime commit rolls the durable
pair back, so a restart can never materialise an upload that was reported
as failed. With no recipients configured (at-rest encryption disabled, e.g.
tests) there is no durable copy at all — only the runtime file is written,
exactly persist_store's no-recipient degradation. Every path derives from
the environment at call time. Never logs or returns key material."""
import os
import shutil
import ssl
import tempfile

import secretfs
import trust


def combined_path():
    """Runtime combined cert(+chain)+key file the console serves when it
    exists (gui_server falls back to IRIS_CERT, then plain HTTP)."""
    return os.environ.get("IRIS_GUI_CERT", "/run/iris/tls/gui-cert.pem")


def _builtin_path():
    """The shared combined cert every service serves by default."""
    return os.environ.get("IRIS_CERT", "/run/iris/tls/cert.pem")


def _tls_config_dir():
    return os.path.join(os.environ.get("IRIS_CONFIG", "/etc/iris"), "tls")


def _durable_crt_path():
    return os.path.join(_tls_config_dir(), "gui-crt.pem")


def _durable_key_path():
    return os.path.join(_tls_config_dir(), "gui-key.pem.age")


def validate_pair(cert_pem, key_pem):
    """None when cert_pem+key_pem load as a servable pair, else a safe
    per-upload error message (never echoes PEM or key material back).

    Validation is the real consumer: a throwaway
    ssl.SSLContext.load_cert_chain over temp files rejects garbage PEM,
    truncated keys and cert/key mismatch in one place (spec A1 step 2).
    Temp files prefer the IRIS_GUI_CERT directory (tmpfs in production) and
    fall back to the system temp dir when it does not exist (dev/test
    hosts); either way they are 0600 inside a private 0700 mkdtemp dir and
    removed before returning."""
    if not isinstance(cert_pem, str) or not cert_pem.strip():
        return "certificate PEM is required"
    if not isinstance(key_pem, str) or not key_pem.strip():
        return "private key PEM is required"
    run_dir = os.path.dirname(combined_path()) or "."
    base = run_dir if os.path.isdir(run_dir) else None
    tmpdir = tempfile.mkdtemp(dir=base, prefix=".gui-tls-check-")
    try:
        cert_tmp = os.path.join(tmpdir, "crt.pem")
        key_tmp = os.path.join(tmpdir, "key.pem")
        for path, text in ((cert_tmp, cert_pem), (key_tmp, key_pem)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(text)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            ctx.load_cert_chain(cert_tmp, key_tmp)
        except ssl.SSLError as exc:
            # exc.reason is an OpenSSL constant (e.g. KEY_VALUES_MISMATCH,
            # NO_START_LINE) — safe to echo; str(exc) is deliberately NOT
            # used (it can quote library internals, never user input, but
            # stay conservative).
            return ("certificate/key pair rejected (%s)"
                    % (getattr(exc, "reason", None) or "SSL error"))
        except (OSError, ValueError) as exc:
            return ("certificate/key pair rejected (%s)"
                    % exc.__class__.__name__)
        return None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _atomic_write(path, data, mode=0o600):
    """mkstemp in the destination dir + os.replace (the secretfs idiom):
    readers only ever see a complete file; mode is set before the swap.
    Accepts str or bytes."""
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".gui-tls-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data.encode() if isinstance(data, str) else data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _read_bytes(path):
    """File bytes, or None when absent — the rollback snapshot."""
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def _put_back(path, data):
    """Rollback helper: restore prior bytes, or prior absence (data=None).
    Deliberately does NOT swallow write errors — like persist_store, a
    failed rollback is raised (durable state is known-diverged and the
    operator must intervene) rather than masked."""
    if data is None:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
    else:
        _atomic_write(path, data)


def persist_override(cert_pem, key_pem):
    """Persist a VALIDATED cert/key upload, durable-FIRST with rollback
    (mirrors secretfs.persist_store's durable-ciphertext-first idiom):

      1. The plaintext key goes to a unique 0600 temp beside the runtime
         combined file (tmpfs in production — plaintext keys never touch
         the config volume).
      2. Durable copies first: gui-key.pem.age (age-encrypted to
         IRIS_AGE_RECIPIENTS via secretfs.encrypt_from) then gui-crt.pem.
         A failure here leaves the previous override fully intact.
      3. Only then the runtime combined cert(+chain)+key file (0600,
         atomic) the console actually serves. If THIS commit fails, the
         durable pair is rolled back to its previous content so the boot
         rebuild can never materialise an upload that was reported as
         failed (durable must never be ahead of runtime).

    With no recipients configured there is no durable copy at all (step 2
    skipped — persist_store's no-recipient degradation) and only the
    runtime file is written. Callers run validate_pair first; a cert with
    no parseable certificate block raises ValueError as a backstop."""
    blocks = trust.split_pem_certs(cert_pem)
    if not blocks:
        raise ValueError("no certificate found in PEM input")
    cert_text = "\n".join(blocks) + "\n"
    key_text = (key_pem or "").strip() + "\n"
    combined = combined_path()
    recipients = (os.environ.get("IRIS_AGE_RECIPIENTS") or "").strip()
    if not recipients:
        _atomic_write(combined, cert_text + key_text)
        return
    crt_path = _durable_crt_path()
    enc_path = _durable_key_path()
    old_crt = _read_bytes(crt_path)
    old_enc = _read_bytes(enc_path)
    run_dir = os.path.dirname(combined) or "."
    os.makedirs(run_dir, exist_ok=True)
    os.makedirs(os.path.dirname(enc_path), exist_ok=True)
    fd, key_tmp = tempfile.mkstemp(dir=run_dir, prefix=".gui-key-",
                                   suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(key_text)
        os.chmod(key_tmp, 0o600)
        # Durable FIRST: if the encrypt raises, nothing has changed.
        # age_bin comes from env at call time — secretfs.AGE_BIN is frozen
        # at import and would ignore a monkeypatched IRIS_AGE_BIN.
        secretfs.encrypt_from(key_tmp, enc_path, recipients,
                              age_bin=os.environ.get("IRIS_AGE_BIN", "age"))
    finally:
        if os.path.exists(key_tmp):
            os.remove(key_tmp)
    try:
        _atomic_write(crt_path, cert_text)
    except OSError:
        _put_back(enc_path, old_enc)
        raise
    try:
        _atomic_write(combined, cert_text + key_text)
    except OSError:
        # The durable pair is ahead of the runtime file: roll it back so a
        # restart reproduces the PREVIOUS override, not the failed upload.
        _put_back(crt_path, old_crt)
        _put_back(enc_path, old_enc)
        raise


def override_active():
    """True when the custom override is in place — i.e. the runtime
    combined file exists (gui_server prefers it whenever it exists)."""
    return os.path.exists(combined_path())


def remove_override():
    """Remove ALL THREE gui-* files (durable crt, durable key.age, runtime
    combined) — the "Use built-in certificate" revert. Idempotent; missing
    files are fine, and a half pair left by an env change is cleaned too."""
    for path in (_durable_crt_path(), _durable_key_path(), combined_path()):
        try:
            os.remove(path)
        except OSError:
            pass


_UNKNOWN_INFO = {"subject": "unknown", "issuer": "unknown",
                 "not_after": "unknown", "fingerprint_sha256": "unknown"}


def active_info():
    """Console-cert metadata for GET /api/settings: which source is serving
    ("custom" when the IRIS_GUI_CERT override file exists, "built-in" when
    only the IRIS_CERT combined file does, "none" when neither — the
    plain-HTTP fallback) plus subject/issuer/expiry/fingerprint of the
    FIRST certificate block in that file (fullchain: the leaf wins).

    Never raises, and never spawns the openssl subprocess unless a cert
    file actually exists and yields a parseable block — this runs on every
    settings GET, including cert-less test servers. Metadata and
    fingerprint come from trust.cert_info, so normalization is
    byte-identical to the trust-store table; unparseable files degrade
    every field to "unknown" (spec A1 display)."""
    info = dict(_UNKNOWN_INFO)
    info["source"] = "none"
    path = combined_path()
    if os.path.isfile(path):
        info["source"] = "custom"
    else:
        path = _builtin_path()
        if os.path.isfile(path):
            info["source"] = "built-in"
        else:
            return info
    try:
        with open(path) as f:
            blocks = trust.split_pem_certs(f.read())
    except (OSError, UnicodeDecodeError):
        return info
    if not blocks:
        return info
    info.update(trust.cert_info(blocks[0]))
    return info
