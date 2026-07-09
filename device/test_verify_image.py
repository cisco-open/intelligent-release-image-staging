# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import hashlib, tempfile, os
from verify_image import sha256_matches


# --- sha256_matches: gates whether the copy-to-root runs at all ---

def test_sha256_matches_true_and_false():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"hello iris")
        path = f.name
    expected = hashlib.sha256(b"hello iris").hexdigest()
    try:
        assert sha256_matches(path, expected) is True
        assert sha256_matches(path, "deadbeef") is False
    finally:
        os.unlink(path)


def test_sha256_matches_case_insensitive():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"case-insensitive check")
        path = f.name
    expected_lower = hashlib.sha256(b"case-insensitive check").hexdigest()
    try:
        assert sha256_matches(path, expected_lower.upper()) is True
        assert sha256_matches(path, expected_lower) is True
    finally:
        os.unlink(path)


def test_sha256_matches_large_multichunk_file():
    """~3 MB file spread across multiple 1 MB chunks hashes correctly."""
    data = b"X" * (3 * 1024 * 1024 + 7)   # crosses two chunk boundaries
    expected = hashlib.sha256(data).hexdigest()
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        path = f.name
    try:
        assert sha256_matches(path, expected) is True
        assert sha256_matches(path, "00" * 32) is False
    finally:
        os.unlink(path)
