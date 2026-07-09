# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import hashlib

import bencode


def test_round_trip_all_types():
    value = {"a": 1, "b": b"raw", "c": [1, "two", b"3"], "d": {"x": 0}}
    encoded = bencode.encode(value)
    decoded = bencode.decode(encoded)
    # str values come back as bytes (bencode has no str/bytes distinction)
    assert decoded == {b"a": 1, b"b": b"raw",
                       b"c": [1, b"two", b"3"], b"d": {b"x": 0}}


def test_keys_are_sorted_as_bytes():
    # 'a' < 'b' < 'c'; encoder must emit sorted keys regardless of insertion order
    assert bencode.encode({"c": 3, "a": 1, "b": 2}) == b"d1:ai1e1:bi2e1:ci3ee"


def test_no_whitespace_and_known_vectors():
    assert bencode.encode(42) == b"i42e"
    assert bencode.encode(b"spam") == b"4:spam"
    assert bencode.encode([b"a", b"b"]) == b"l1:a1:be"


def test_info_hash_of_a_minimal_torrent():
    # info_hash = sha1 of the bencoded `info` dict. Build one, encode, hash.
    info = {"name": b"x.bin", "piece length": 16384, "length": 5,
            "pieces": b"\x00" * 20, "private": 1}
    expected = hashlib.sha1(bencode.encode(info)).hexdigest()
    # decode then re-encode must reproduce identical bytes (canonical form)
    reencoded = bencode.encode(bencode.decode(bencode.encode(info)))
    assert hashlib.sha1(reencoded).hexdigest() == expected


def test_decode_rejects_trailing_bytes():
    import pytest
    with pytest.raises(ValueError):
        bencode.decode(b"i1ejunk")
