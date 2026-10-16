# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Persist the default browser identity encrypted, independently of catalog TLS."""
import ipaddress
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
from urllib.parse import urlsplit

import secretfs


def _browser_name(console_url):
    """Accept one HTTPS origin, never raw OpenSSL extension text."""
    if console_url == "":
        return None
    try:
        if (not isinstance(console_url, str) or len(console_url) > 2048
                or any(character.isspace() or ord(character) < 32 or ord(character) == 127
                       for character in console_url)):
            raise ValueError()
        parsed = urlsplit(console_url)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or "?" in console_url or "#" in console_url
                or parsed.path not in ("", "/") or parsed.netloc.endswith(":")):
            raise ValueError()
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError()
        name = parsed.hostname
        if "%" in name:
            raise ValueError()
        try:
            address = ipaddress.ip_address(name)
        except ValueError:
            name = name.encode("idna").decode("ascii").lower()
            if (len(name) > 253 or any(not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in name.split("."))):
                raise ValueError()
            return "DNS:" + name
        if address.is_unspecified or address.is_multicast:
            raise ValueError()
        return "IP:" + str(address)
    except (ValueError, UnicodeError):
        raise ValueError("IRIS_CONSOLE_URL must be a valid HTTPS origin without credentials") from None


def ensure_identity(config, runtime, identity, recipients, host, age_bin="age", *, console_url=""):
    """Durable-first publication; corrupt existing ciphertext never rotates trust."""
    host = str(ipaddress.ip_address(host))
    browser = _browser_name(console_url)
    names = ["IP:" + host]
    if browser is not None and browser not in names:
        names.append(browser)
    destination = Path(runtime)
    encrypted = Path(config) / "tls" / "console-fallback.pem.age"
    destination.parent.mkdir(parents=True, exist_ok=True)
    encrypted.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".console-identity-", dir=destination.parent) as tmp:
        combined = Path(tmp) / "combined.pem"
        if encrypted.exists() or encrypted.is_symlink():
            if encrypted.is_symlink() or not encrypted.is_file():
                raise ValueError("default Console ciphertext must be a regular file")
            secretfs.decrypt_to(str(encrypted), str(combined), identity, age_bin=age_bin)
        else:
            if not recipients.strip():
                raise ValueError("age recipients required for default Console identity")
            key, cert = Path(tmp) / "key.pem", Path(tmp) / "cert.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-days", "3650", "-subj", "/CN=" + host,
                "-addext", "subjectAltName=" + ",".join(names),
                "-keyout", str(key), "-out", str(cert),
            ], check=True, capture_output=True, timeout=30)
            combined.write_bytes(cert.read_bytes() + key.read_bytes())
            combined.chmod(0o600)
            secretfs.encrypt_from(str(combined), str(encrypted), recipients, age_bin=age_bin)
            # Verify recipient configuration before publishing a usable runtime identity.
            secretfs.decrypt_to(str(encrypted), str(combined), identity, age_bin=age_bin)
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(str(combined))
        combined.chmod(0o600)
        os.replace(combined, destination)


if __name__ == "__main__":
    ensure_identity(os.environ["IRIS_CONFIG"], os.environ["IRIS_GUI_FALLBACK_CERT"],
                    os.environ["IRIS_AGE_KEY_FILE"], os.environ["IRIS_AGE_RECIPIENTS"],
                    os.environ["IRIS_HOST_IP"], os.environ.get("IRIS_AGE_BIN", "age"),
                    console_url=os.environ.get("IRIS_CONSOLE_URL", ""))
