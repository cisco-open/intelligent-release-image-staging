# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import hashlib
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import console_identity


@pytest.fixture
def paths(tmp_path):
    if not shutil.which("age") or not shutil.which("age-keygen"):
        pytest.skip("age tools required")
    identity = tmp_path / "identity"
    subprocess.run(["age-keygen", "-o", str(identity)], check=True, capture_output=True)
    recipient = subprocess.check_output(["age-keygen", "-y", str(identity)], text=True).strip()
    return tmp_path / "config", tmp_path / "run" / "console.pem", str(identity), recipient


def test_identity_survives_runtime_loss(paths):
    config, runtime, identity, recipient = paths
    console_identity.ensure_identity(config, runtime, identity, recipient, "192.0.2.1")
    initial = runtime.read_bytes()
    encrypted = config / "tls" / "console-fallback.pem.age"
    assert b"PRIVATE KEY" not in encrypted.read_bytes()
    assert runtime.stat().st_mode & 0o777 == 0o600
    assert encrypted.stat().st_mode & 0o777 == 0o600
    before = hashlib.sha256(encrypted.read_bytes()).hexdigest()
    runtime.unlink()
    console_identity.ensure_identity(config, runtime, identity, recipient, "192.0.2.1")
    assert runtime.read_bytes() == initial
    assert hashlib.sha256(encrypted.read_bytes()).hexdigest() == before
    assert not list(runtime.parent.glob(".console-identity-*"))


def test_corrupt_ciphertext_does_not_rotate_or_publish(paths):
    config, runtime, identity, recipient = paths
    console_identity.ensure_identity(config, runtime, identity, recipient, "192.0.2.1")
    initial = runtime.read_bytes()
    encrypted = config / "tls" / "console-fallback.pem.age"
    encrypted.write_bytes(b"broken")
    with pytest.raises(subprocess.CalledProcessError):
        console_identity.ensure_identity(config, runtime, identity, recipient, "192.0.2.1")
    assert runtime.read_bytes() == initial
    assert encrypted.read_bytes() == b"broken"


def test_failed_persistence_never_publishes(paths, monkeypatch):
    config, runtime, identity, recipient = paths
    def refuse(*args, **kwargs):
        raise OSError("disk full")
    monkeypatch.setattr(console_identity.secretfs, "encrypt_from", refuse)
    with pytest.raises(OSError, match="disk full"):
        console_identity.ensure_identity(config, runtime, identity, recipient, "192.0.2.1")
    assert not runtime.exists()


def _tls_peer(runtime, hostname):
    """Verify actual certificate DER/name over a real bounded loopback socket."""
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(runtime)
    client = ssl.create_default_context(cafile=str(runtime))
    failures = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        def serve():
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(5)
                    with server.wrap_socket(connection, server_side=True) as secured:
                        secured.sendall(b"ok")
            except ssl.SSLError:
                # The deliberate wrong-name client sends a TLS refusal alert.
                pass
            except Exception as exc:
                failures.append(type(exc).__name__)
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            with socket.create_connection(listener.getsockname(), timeout=5) as connection:
                with client.wrap_socket(connection, server_hostname=hostname) as secured:
                    assert secured.recv(2) == b"ok"
                    return secured.getpeercert(), secured.getpeercert(binary_form=True)
        finally:
            worker.join(timeout=6)
            assert not worker.is_alive(), "bounded TLS server did not stop"
            assert not failures


@pytest.mark.parametrize("url, hostname, expected", [
    ("https://127.0.0.1:8080/", "127.0.0.1", ("IP Address", "127.0.0.1")),
    ("https://Console.Example:9443/", "console.example", ("DNS", "console.example")),
    ("https://[::1]:8080/", "::1", ("IP Address", "0:0:0:0:0:0:0:1")),
    ("https://b\u00fccher.example/", "xn--bcher-kva.example", ("DNS", "xn--bcher-kva.example")),
])
def test_new_identity_covers_advertised_console_and_distinct_device_host(paths, url, hostname, expected):
    config, runtime, identity, recipient = paths
    console_identity.ensure_identity(config, runtime, identity, recipient, "192.0.2.1", console_url=url)
    peer, der = _tls_peer(runtime, hostname)
    assert set(peer["subjectAltName"]) == {("IP Address", "192.0.2.1"), expected}
    device_peer, device_der = _tls_peer(runtime, "192.0.2.1")
    assert device_der == der and device_peer == peer
    with pytest.raises(ssl.SSLCertVerificationError):
        _tls_peer(runtime, "wrong-console.example")


def test_same_host_is_not_duplicated_in_certificate(paths):
    config, runtime, identity, recipient = paths
    console_identity.ensure_identity(config, runtime, identity, recipient, "192.0.2.1",
                                     console_url="https://192.0.2.1:8080")
    peer, _ = _tls_peer(runtime, "192.0.2.1")
    assert peer["subjectAltName"] == (("IP Address", "192.0.2.1"),)


@pytest.mark.parametrize("url", [
    "http://console.example", "https://user:secret@console.example", "https://@console.example",
    "https://console.example/path", "https://console.example/?secret=value", "https://console.example/#fragment",
    "https://console.example?", "https://console.example#", "https://console.example:",
    "https://console.example:0", "https://console.example:65536", "https://console.example:bad",
    "https://console.example\n", "https://console. example", "https://console.example,DNS:other.example",
    "https://*.example", "https://bad_name.example", "https://-bad.example", "https://[::1",
    "https://[fe80::1%25eth0]", "https://0.0.0.0", "https://224.0.0.1",
    "https://" + "a" * 64 + ".example", "https://" + "a" * 2048,
    None, 123,
])
def test_invalid_origin_refuses_before_key_generation_or_publication(tmp_path, monkeypatch, url):
    def unexpected(*args, **kwargs):
        pytest.fail("invalid origin reached key generation or encrypted storage")
    monkeypatch.setattr(console_identity.subprocess, "run", unexpected)
    monkeypatch.setattr(console_identity.secretfs, "encrypt_from", unexpected)
    config, runtime = tmp_path / "config", tmp_path / "run" / "console.pem"
    with pytest.raises(ValueError, match="IRIS_CONSOLE_URL must be a valid HTTPS origin without credentials"):
        console_identity.ensure_identity(config, runtime, "unused", "unused", "192.0.2.1", console_url=url)
    assert not config.exists() and not runtime.parent.exists()


def test_existing_identity_is_not_rotated_when_advertised_url_changes(paths):
    config, runtime, identity, recipient = paths
    console_identity.ensure_identity(config, runtime, identity, recipient, "192.0.2.1")
    original = runtime.read_bytes()
    encrypted = config / "tls" / "console-fallback.pem.age"
    original_encrypted = encrypted.read_bytes()
    # The default generator must also leave separately managed override files alone.
    override = config / "tls" / "gui-crt.pem"
    override.write_bytes(original.split(b"-----END CERTIFICATE-----", 1)[0] + b"-----END CERTIFICATE-----\n")
    override_key = config / "tls" / "gui-key.pem.age"
    override_key.write_bytes(original_encrypted)
    runtime.unlink()
    console_identity.ensure_identity(config, runtime, identity, recipient, "192.0.2.1",
                                     console_url="https://127.0.0.1:8080/")
    assert runtime.read_bytes() == original
    assert encrypted.read_bytes() == original_encrypted
    assert override_key.read_bytes() == original_encrypted
    assert override.read_bytes() == original.split(b"-----END CERTIFICATE-----", 1)[0] + b"-----END CERTIFICATE-----\n"
    _tls_peer(runtime, "192.0.2.1")
    # Resume deliberately preserves old trust. This is not an automatic repair
    # of an already-issued certificate; use the normal TLS replacement flow.
    with pytest.raises(ssl.SSLCertVerificationError):
        _tls_peer(runtime, "127.0.0.1")


def test_entrypoint_reads_advertised_url_from_environment(paths):
    config, runtime, identity, recipient = paths
    environment = dict(os.environ, IRIS_CONFIG=str(config), IRIS_GUI_FALLBACK_CERT=str(runtime),
                       IRIS_AGE_KEY_FILE=identity, IRIS_AGE_RECIPIENTS=recipient,
                       IRIS_HOST_IP="192.0.2.1", IRIS_CONSOLE_URL="https://127.0.0.1:8080/",
                       IRIS_AGE_BIN="age")
    subprocess.run([sys.executable, console_identity.__file__], env=environment,
                   check=True, capture_output=True, timeout=30)
    peer, _ = _tls_peer(runtime, "127.0.0.1")
    assert set(peer["subjectAltName"]) == {("IP Address", "192.0.2.1"), ("IP Address", "127.0.0.1")}
