# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Persist the default browser identity encrypted, independently of catalog TLS."""
import ipaddress
import os
from pathlib import Path
import ssl
import subprocess
import tempfile

import secretfs


def ensure_identity(config, runtime, identity, recipients, host, age_bin="age"):
    """Durable-first publication; corrupt existing ciphertext never rotates trust."""
    host = str(ipaddress.ip_address(host))
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
                "-addext", "subjectAltName=IP:" + host,
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
                    os.environ["IRIS_HOST_IP"], os.environ.get("IRIS_AGE_BIN", "age"))
