# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Independent AES-SIV oracle, malformed pipe inputs and no plaintext on failure."""
from pathlib import Path
import re
import struct
import subprocess

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESSIV

import instruction_aead as aead

KEY = bytes(range(64))
AAD = b"IRIS-AEAD/2"


@pytest.mark.parametrize("size", [1, 15, 16, 17, 32, 255, 4096, 262144])
def test_real_helper_matches_independent_implementation(size):
    plain = (bytes(range(256)) * (size // 256 + 1))[:size]
    ciphertext, tag = aead.seal(KEY, AAD, plain)
    assert tag + ciphertext == AESSIV(KEY).encrypt(plain, [AAD])
    assert aead.open_sealed(KEY, AAD, ciphertext, tag) == plain


def test_fixed_known_answer_and_deterministic_nonce_misuse_resistance():
    plain = b"IRIS AES-SIV capability check"
    ciphertext, tag = aead.seal(KEY, AAD, plain)
    assert (tag + ciphertext).hex() == (
        "3f308a628f2e9d1535050f68c74d6191828b2771ef8166ae1dd4a0fe69992418aac84041d91f5797910f5809eb")
    assert aead.seal(KEY, AAD, plain) == (ciphertext, tag)
    # Identical context with changed content must not reuse an XOR stream.
    other = bytes(len(plain))
    other_ciphertext, _ = aead.seal(KEY, AAD, other)
    assert bytes(a ^ b for a, b in zip(ciphertext, other_ciphertext)) != plain


@pytest.mark.parametrize("field", ["key", "aad", "data", "tag"])
def test_authentication_failure_emits_no_plaintext(field):
    ciphertext, tag = aead.seal(KEY, AAD, b"private instruction payload")
    parts = dict(key=KEY, aad=AAD, data=ciphertext, tag=tag)
    value = parts[field]
    parts[field] = bytes([value[0] ^ 1]) + value[1:]
    request = struct.pack(">II", len(parts['aad']), len(parts['data'])) + b"".join(parts.values())
    result = subprocess.run([aead.helper_path(), "open"], input=request, capture_output=True)
    assert result.returncode != 0
    assert result.stdout == result.stderr == b""


@pytest.mark.parametrize("damage", ["truncated", "extra", "oversize", "empty", "badop"])
def test_helper_rejects_malformed_pipe_requests(damage):
    request = struct.pack(">II", len(AAD), 4) + KEY + AAD + b"test"
    operation = "seal"
    if damage == "truncated": request = request[:-1]
    if damage == "extra": request += b"x"
    if damage == "oversize": request = struct.pack(">II", aead.LIMIT + 1, 4)
    if damage == "empty": request = struct.pack(">II", 0, 0)
    if damage == "badop": operation = "legacy"
    result = subprocess.run([aead.helper_path(), operation], input=request, capture_output=True)
    assert result.returncode != 0
    assert result.stdout == result.stderr == b""


def test_missing_helper_fails_closed_without_fallback(monkeypatch):
    monkeypatch.setattr(aead, "helper_path", lambda: "/does-not-exist/iris-aead")
    with pytest.raises(ValueError, match="unavailable"):
        aead.seal(KEY, AAD, b"secret")


def test_shared_server_and_agent_adapter_bytes_match():
    root = Path(__file__).resolve().parents[2]
    assert (root/'server/instruction_aead.py').read_bytes() == (root/'device/agent/instruction_aead.py').read_bytes()


def test_build_exports_helper_and_public_notice_with_explicit_modes():
    root = Path(__file__).resolve().parents[2]
    script = (root/'tools/build-instruction-crypto-inner.sh').read_text()
    assert 'chmod 0755 /out/iris-aead' in script
    assert 'chmod 0644 /out/iris-aead.LICENCE' in script
    assert script.index('chmod 0644') > script.index('cat /src/musl-COPYRIGHT')


def test_crypto_build_keeps_exact_matching_openssl_pins():
    root = Path(__file__).resolve().parents[2]
    script = (root / 'tools/build-instruction-crypto-inner.sh').read_text()
    command = next(line for line in script.splitlines() if line.startswith('apk add '))
    assert command.startswith('apk add --no-cache ')
    packages = command.split()[3:]
    assert all(re.fullmatch(r'[a-z0-9-]+=[0-9][0-9A-Za-z._]*-r\d+', value)
               for value in packages)
    pins = dict(value.split('=', 1) for value in packages)
    assert pins['openssl-dev'] == pins['openssl-libs-static']


def test_contributor_guide_matches_the_linked_openssl():
    root = Path(__file__).resolve().parents[2]
    script = (root / 'tools/build-instruction-crypto-inner.sh').read_text()
    version = re.search(r'openssl-dev=([0-9.]+)-r\d+', script).group(1)
    guide = (root / 'docs/dev/instruction-crypto.md').read_text()
    assert re.findall(r'\bOpenSSL ([0-9]+\.[0-9]+\.[0-9]+)\b', guide) == [version]


@pytest.mark.parametrize('dockerfile', [
    'tools/build-instruction-crypto.Dockerfile',
    'server/Dockerfile',
    'device/container/Dockerfile',
])
def test_all_crypto_build_notices_match_the_linked_openssl(dockerfile):
    root = Path(__file__).resolve().parents[2]
    script = (root / 'tools/build-instruction-crypto-inner.sh').read_text()
    version = re.search(r'openssl-dev=([0-9.]+)-r\d+', script).group(1)
    recipe = (root / dockerfile).read_text()
    notices = [line for line in recipe.splitlines() if line.startswith('ADD ') and
               line.endswith(' /src/openssl-LICENSE')]
    assert len(notices) == 1
    assert re.fullmatch(
        r'ADD --checksum=sha256:[0-9a-f]{64} '
        r'https://raw\.githubusercontent\.com/openssl/openssl/openssl-'
        + re.escape(version) + r'/LICENSE\.txt /src/openssl-LICENSE', notices[0])
    assert 'build-instruction-crypto-inner.sh /src/build.sh' in recipe
    notice = (root / 'NOTICE').read_text()
    assert 'with OpenSSL ' + version + ' libcrypto' in notice
    assert 'https://github.com/openssl/openssl/tree/openssl-' + version in notice
