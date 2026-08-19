# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""IRIS-owned root-CA trust store (stdlib only).

Durable installed-CA PEMs live one file per install under IRIS_TRUST_DIR
(default /etc/iris/tls/trust), named by the sha256 fingerprint of the first
certificate in the upload; the daily public-CA download is the distinguished
file downloaded-bundle.pem. Every change rebuilds the runtime concat bundle
IRIS_CA_BUNDLE (default /run/iris/tls/ca-bundle.pem) atomically. Outbound-TLS
consumers (OTLP export, the CA-bundle downloader) call ssl_context(): system
roots PLUS the IRIS bundle, mtime-cached so a console trust edit is honored
without a restart. Certificates are public material — no secrets live here."""
import base64
import binascii
import hashlib
import os
import re
import ssl
import subprocess
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request

DOWNLOADED_BUNDLE = "downloaded-bundle.pem"

_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL)
_OPENSSL_TIMEOUT = 10
_MAX_BUNDLE_BYTES = 2 * 1024 * 1024
_DOWNLOAD_TIMEOUT = 30


def trust_dir():
    return os.environ.get("IRIS_TRUST_DIR", "/etc/iris/tls/trust")


def bundle_path():
    return os.environ.get("IRIS_CA_BUNDLE", "/run/iris/tls/ca-bundle.pem")


def split_pem_certs(text):
    """All BEGIN/END CERTIFICATE blocks in `text`, whitespace-normalized
    (stripped lines rejoined with \\n, surrounding junk dropped). Returns []
    when nothing parseable is present. Never raises."""
    if not isinstance(text, str):
        return []
    blocks = []
    for match in _PEM_CERT_RE.findall(text):
        lines = [ln.strip() for ln in match.splitlines()]
        blocks.append("\n".join(ln for ln in lines if ln))
    return blocks


def _fingerprint(pem_block):
    """sha256 fingerprint (lowercase hex) of one PEM certificate block: the
    hash of the DER bytes, i.e. exactly what `openssl x509 -fingerprint
    -sha256` prints. Pure stdlib so file naming never depends on the openssl
    CLI. "unknown" when the base64 body does not decode."""
    if not isinstance(pem_block, str):
        return "unknown"
    body = "".join(ln.strip() for ln in pem_block.splitlines()
                   if ln.strip() and not ln.startswith("-----"))
    try:
        der = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError):
        return "unknown"
    if not der:
        return "unknown"
    return hashlib.sha256(der).hexdigest()


def cert_info(pem_block):
    """{"subject","issuer","not_after","fingerprint_sha256"} for one PEM
    certificate block. Subject/issuer/expiry come from the `openssl x509` CLI
    (guaranteed in the image — iris-bootstrap already shells out to it); every
    field degrades to "unknown" rather than raising."""
    info = {"subject": "unknown", "issuer": "unknown",
            "not_after": "unknown",
            "fingerprint_sha256": _fingerprint(pem_block)}
    if not isinstance(pem_block, str):
        return info
    try:
        proc = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate"],
            input=pem_block.encode(), capture_output=True,
            timeout=_OPENSSL_TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return info
    if proc.returncode != 0:
        return info
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip().lower(), value.strip()
        if key == "subject" and value:
            info["subject"] = value
        elif key == "issuer" and value:
            info["issuer"] = value
        elif key == "notafter" and value:
            info["not_after"] = value
    return info


def _atomic_write(path, text):
    """mkstemp in the destination dir + os.replace (the live_samples
    _atomic_write_json idiom): readers only ever see a complete file."""
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".trust-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _entry(name):
    """One list_entries() row for the store file `name` (metadata from the
    FIRST certificate in the file; cert_count covers the whole file)."""
    try:
        with open(os.path.join(trust_dir(), name)) as f:
            blocks = split_pem_certs(f.read())
    except OSError:
        blocks = []
    info = cert_info(blocks[0]) if blocks else {
        "subject": "unknown", "issuer": "unknown", "not_after": "unknown",
        "fingerprint_sha256": "unknown"}
    return {"name": name,
            "subject": info["subject"],
            "not_after": info["not_after"],
            "fingerprint_sha256": info["fingerprint_sha256"],
            "cert_count": len(blocks),
            "source": ("downloaded" if name == DOWNLOADED_BUNDLE
                       else "manual")}


def list_entries():
    """Installed-CA table for the console: sorted by file name; missing store
    dir means an empty store."""
    try:
        names = sorted(n for n in os.listdir(trust_dir())
                       if n.endswith(".pem"))
    except OSError:
        return []
    return [_entry(n) for n in names]


def add_pem(text):
    """Install one uploaded PEM (>=1 certificate block required; a multi-cert
    upload stays ONE file, named by the first cert's sha256 fingerprint).
    Rebuilds the runtime bundle. Raises ValueError on unusable input — the
    message is safe to echo to the console (no user text interpolated)."""
    blocks = split_pem_certs(text)
    if not blocks:
        raise ValueError("no certificate found in PEM input")
    fp = _fingerprint(blocks[0])
    if fp == "unknown":
        raise ValueError("first certificate block is not decodable")
    d = trust_dir()
    os.makedirs(d, exist_ok=True)
    name = fp + ".pem"
    _atomic_write(os.path.join(d, name), "\n".join(blocks) + "\n")
    rebuild_bundle()
    return _entry(name)


def remove(name):
    """Delete one store file by exact basename. Refuses anything that is not
    a plain `<name>.pem` basename (traversal-proof), returns False when the
    file is absent, rebuilds the bundle on success."""
    if (not isinstance(name, str) or not name
            or name != os.path.basename(name) or name in (".", "..")
            or not name.endswith(".pem") or "\x00" in name):
        return False
    try:
        os.remove(os.path.join(trust_dir(), name))
    except OSError:
        return False
    rebuild_bundle()
    return True


def rebuild_bundle():
    """Concatenate every store PEM (sorted file-name order — deterministic)
    into the runtime bundle via an atomic write; an empty store removes the
    bundle so consumers fall back to system roots alone. Returns the total
    certificate count in the bundle."""
    bundle = bundle_path()
    try:
        names = sorted(n for n in os.listdir(trust_dir())
                       if n.endswith(".pem"))
    except OSError:
        names = []
    blocks = []
    for n in names:
        try:
            with open(os.path.join(trust_dir(), n)) as f:
                blocks.extend(split_pem_certs(f.read()))
        except OSError:
            continue
    if not blocks:
        try:
            os.remove(bundle)
        except OSError:
            pass
        return 0
    os.makedirs(os.path.dirname(bundle) or ".", exist_ok=True)
    _atomic_write(bundle, "\n".join(blocks) + "\n")
    return len(blocks)


_CTX_LOCK = threading.Lock()
_CTX_CACHE = {"key": None, "ctx": None}


def ssl_context():
    """Client-side verification context for outbound TLS consumers (OTLP
    export, the CA-bundle downloader): system default roots PLUS the IRIS
    runtime bundle when it exists. Cached on the bundle's (mtime, inode,
    size) so a console trust edit is picked up on the next call without a
    restart and without rebuilding a context per request. A corrupt bundle
    degrades to system roots alone (never raises — callers are best-effort
    paths)."""
    path = bundle_path()
    try:
        st = os.stat(path)
        key = (path, st.st_mtime_ns, st.st_ino, st.st_size)
    except OSError:
        key = (path, None, None, None)
    with _CTX_LOCK:
        if _CTX_CACHE["key"] == key and _CTX_CACHE["ctx"] is not None:
            return _CTX_CACHE["ctx"]
    ctx = ssl.create_default_context()
    if key[1] is not None:
        try:
            ctx.load_verify_locations(path)
        except (ssl.SSLError, OSError):
            ctx = ssl.create_default_context()
    with _CTX_LOCK:
        _CTX_CACHE["key"], _CTX_CACHE["ctx"] = key, ctx
    return ctx


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse ALL redirects — the same hardening stance as otlp._NoRedirect
    (duplicated here, not imported: otlp imports trust, so trust must never
    import otlp). A bundle URL answering 3xx fails the download instead of
    fetching whatever Location it names."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def download_bundle(url):
    """Fetch the operator-configured public-CA bundle into
    trust_dir()/DOWNLOADED_BUNDLE and rebuild the runtime bundle.

    Hardening (spec feature A3): https-only URL, redirects refused, 2 MiB
    size cap read-enforced (Content-Length is not trusted), response must
    contain >=1 PEM certificate block, atomic write. Never raises; returns
    {"ok": bool, "certs": int, "error": str|None}. On ANY failure the
    previous downloaded file is left untouched (validation happens entirely
    before the write). TLS is verified via ssl_context(), so the bundle host
    may itself sit behind an already-installed private CA."""
    parsed = urllib.parse.urlsplit(url if isinstance(url, str) else "")
    if parsed.scheme != "https" or not parsed.netloc:
        return {"ok": False, "certs": 0, "error": "URL must be https"}
    opener = urllib.request.build_opener(
        _NoRedirect(), urllib.request.HTTPSHandler(context=ssl_context()))
    try:
        with opener.open(url, timeout=_DOWNLOAD_TIMEOUT) as resp:
            data = resp.read(_MAX_BUNDLE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return {"ok": False, "certs": 0, "error": "HTTP %d" % exc.code}
    except Exception as exc:
        # class name only: urllib error text can embed request details
        return {"ok": False, "certs": 0, "error": exc.__class__.__name__}
    if len(data) > _MAX_BUNDLE_BYTES:
        return {"ok": False, "certs": 0,
                "error": "bundle exceeds the 2 MiB cap"}
    blocks = split_pem_certs(data.decode("utf-8", "replace"))
    if not blocks:
        return {"ok": False, "certs": 0,
                "error": "no PEM certificate blocks in response"}
    d = trust_dir()
    os.makedirs(d, exist_ok=True)
    _atomic_write(os.path.join(d, DOWNLOADED_BUNDLE),
                  "\n".join(blocks) + "\n")
    rebuild_bundle()
    return {"ok": True, "certs": len(blocks), "error": None}
