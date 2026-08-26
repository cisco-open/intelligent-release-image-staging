# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Pure tests for the raw top-level bencode value-span scanner/rewriter.

These never decode-and-re-encode as a correctness proof: they assert on the
RAW byte span of the top-level ``info`` value (spec §6). The rewriter copies
that span verbatim, replaces the outer ``announce``, and removes any
``announce-list`` — so the info hash is provably identical."""
import hashlib

import pytest

import bencode
import torrent_personalize as tp


# ---------------------------------------------------------------------------
# Helpers to build well-formed torrents at the byte level
# ---------------------------------------------------------------------------

def _torrent(announce=b"http://old/announce", info=None, extra=b"",
             announce_list=None, prefix_keys=b""):
    """Assemble a top-level bencode dict from ordered raw member fragments.

    ``announce`` and ``announce_list`` are given as the raw (already-bencoded)
    values would be — but for ergonomics ``announce`` is passed as the URL
    bytes and bencoded here. We concatenate members verbatim (NOT via
    bencode.encode of a dict) so tests can inject non-canonical key order or
    duplicate keys that a canonical encoder would never emit."""
    if info is None:
        info = bencode.encode({"name": "img.bin", "piece length": 16384,
                               "pieces": b"\x00" * 20, "length": 100})
    body = bytearray(b"d")
    body += prefix_keys
    body += bencode.encode("announce") + bencode.encode(announce)
    if announce_list is not None:
        body += bencode.encode("announce-list") + announce_list
    body += bencode.encode("info") + info
    body += extra
    body += b"e"
    return bytes(body)


def _bstr(s):
    return bencode.encode(s)


# ---------------------------------------------------------------------------
# Raw value-span extraction over nested structures
# ---------------------------------------------------------------------------

def test_extract_info_span_is_verbatim_bytes():
    info = bencode.encode({"name": "img.bin", "piece length": 16384,
                           "pieces": b"\xab" * 40, "length": 100})
    data = _torrent(info=info)
    spans = tp.scan_top_level(data)
    start, end = spans["info"]
    assert data[start:end] == info


def test_scan_skips_deeply_nested_values():
    # info holds a nested list/dict/int/bytes to exercise the raw skipper.
    info = bencode.encode({"a": [1, [2, 3], {"x": b"y"}], "z": b"deep"})
    data = _torrent(info=info)
    spans = tp.scan_top_level(data)
    start, end = spans["info"]
    assert data[start:end] == info


def test_noncanonical_info_span_preserved_byte_for_byte():
    # Keys NOT in sorted order: a canonical re-encode would reorder them and
    # change the info hash. The raw span must be preserved as-is.
    noncanon = b"d4:name7:img.bin1:ai1ee"  # 'name' before 'a' (non-sorted)
    data = _torrent(info=noncanon)
    out = tp.personalize(data, b"http://new/announce?announce_token=T")
    spans_in = tp.scan_top_level(data)
    spans_out = tp.scan_top_level(out)
    s_in = data[spans_in["info"][0]:spans_in["info"][1]]
    s_out = out[spans_out["info"][0]:spans_out["info"][1]]
    assert s_in == noncanon
    assert s_out == noncanon
    assert hashlib.sha1(s_in).digest() == hashlib.sha1(s_out).digest()


# ---------------------------------------------------------------------------
# Malformed / trailing-data rejection
# ---------------------------------------------------------------------------

def test_trailing_data_rejected():
    data = _torrent() + b"junk"
    with pytest.raises(ValueError):
        tp.scan_top_level(data)


def test_not_a_dict_rejected():
    with pytest.raises(ValueError):
        tp.scan_top_level(b"l4:spame")


def test_truncated_input_rejected():
    data = _torrent()[:-3]
    with pytest.raises(ValueError):
        tp.scan_top_level(data)


def test_bad_length_prefix_rejected():
    with pytest.raises(ValueError):
        tp.scan_top_level(b"d99:short")


def test_empty_input_rejected():
    with pytest.raises(ValueError):
        tp.scan_top_level(b"")


# ---------------------------------------------------------------------------
# Duplicate top-level key rejection (info / announce / announce-list)
# ---------------------------------------------------------------------------

def test_duplicate_info_rejected():
    info = bencode.encode({"length": 1})
    data = (b"d" + _bstr("announce") + b"3:xxx"
            + _bstr("info") + info + _bstr("info") + info + b"e")
    with pytest.raises(ValueError):
        tp.scan_top_level(data)


def test_duplicate_announce_rejected():
    data = (b"d" + _bstr("announce") + b"3:aaa"
            + _bstr("announce") + b"3:bbb"
            + _bstr("info") + bencode.encode({"length": 1}) + b"e")
    with pytest.raises(ValueError):
        tp.scan_top_level(data)


def test_duplicate_announce_list_rejected():
    al = bencode.encode([[b"http://t/a"]])
    data = (b"d" + _bstr("announce") + b"3:aaa"
            + _bstr("announce-list") + al
            + _bstr("announce-list") + al
            + _bstr("info") + bencode.encode({"length": 1}) + b"e")
    with pytest.raises(ValueError):
        tp.scan_top_level(data)


# ---------------------------------------------------------------------------
# personalize() output invariants
# ---------------------------------------------------------------------------

def test_personalize_rewrites_single_announce():
    data = _torrent(announce=b"http://old/announce")
    out = tp.personalize(data, b"http://new/announce?announce_token=TOKEN")
    meta = bencode.decode(out)
    assert meta[b"announce"] == b"http://new/announce?announce_token=TOKEN"


def test_personalize_removes_announce_list():
    al = bencode.encode([[b"http://old/a"], [b"http://old/b"]])
    data = _torrent(announce_list=al)
    assert b"announce-list" in data
    out = tp.personalize(data, b"http://new/a?announce_token=T")
    meta = bencode.decode(out)
    assert b"announce-list" not in meta


def test_personalize_exactly_one_announce_zero_announce_list_raw():
    al = bencode.encode([[b"http://old/a"]])
    data = _torrent(announce_list=al)
    out = tp.personalize(data, b"http://new/a?announce_token=T")
    spans = tp.scan_top_level(out)
    assert "announce" in spans
    assert "announce-list" not in spans


def test_personalize_info_hash_identical():
    info = bencode.encode({"name": "x", "piece length": 16384,
                           "pieces": b"\x11" * 20, "length": 100})
    data = _torrent(info=info)
    old_hash = hashlib.sha1(info).hexdigest()
    out = tp.personalize(data, b"http://new/a?announce_token=T")
    spans = tp.scan_top_level(out)
    s, e = spans["info"]
    assert hashlib.sha1(out[s:e]).hexdigest() == old_hash


def test_personalize_rejects_duplicate_outer_keys():
    info = bencode.encode({"length": 1})
    data = (b"d" + _bstr("announce") + b"3:aaa"
            + _bstr("info") + info + _bstr("info") + info + b"e")
    with pytest.raises(ValueError):
        tp.personalize(data, b"http://new/a?announce_token=T")


def test_personalize_missing_info_rejected():
    data = b"d" + _bstr("announce") + b"3:aaa" + b"e"
    with pytest.raises(ValueError):
        tp.personalize(data, b"http://new/a?announce_token=T")


def test_personalize_preserves_other_top_level_keys():
    # A 'comment' key before announce must survive.
    data = _torrent(prefix_keys=_bstr("comment") + _bstr("hello"))
    out = tp.personalize(data, b"http://new/a?announce_token=T")
    meta = bencode.decode(out)
    assert meta[b"comment"] == b"hello"
    assert meta[b"announce"] == b"http://new/a?announce_token=T"
