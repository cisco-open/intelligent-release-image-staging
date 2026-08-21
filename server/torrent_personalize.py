# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Raw top-level bencode value-span scanner/rewriter for torrent personalization.

The info-hash invariant is enforced on the RAW byte span of the top-level
``info`` value, never via a decode -> edit -> re-encode -> re-hash comparison
(spec §6): a non-canonical original would re-encode to different bytes, so a
naive comparison could falsely reject valid drift or mask real drift.

``scan_top_level`` locates the exact byte range of each top-level member value
without decoding nested structures into Python objects, rejecting malformed or
ambiguous input (trailing data, truncation, non-dict root, duplicate top-level
``info`` / ``announce`` / ``announce-list`` keys).

``personalize`` rewrites the outer ``announce`` value, removes any
``announce-list``, and copies the ``info`` byte span verbatim, then asserts the
output invariants (exactly one announce, zero announce-list, raw ``info`` span
SHA-1 identical) before returning.

Stdlib only; operates purely on bytes."""
import hashlib

# Top-level keys whose duplication makes a torrent ambiguous/malformed.
_UNIQUE_TOP_KEYS = (b"info", b"announce", b"announce-list")


def _skip_value(data, i):
    """Return the index just past the bencode value that starts at *i*.

    Raises ValueError on any malformed structure. Does not build Python
    objects — it only walks byte offsets so a value's raw span can be sliced
    verbatim by the caller."""
    n = len(data)
    if i >= n:
        raise ValueError("unexpected end of data")
    c = data[i:i + 1]
    if c == b"i":  # integer: i<digits>e
        j = data.find(b"e", i + 1)
        if j < 0:
            raise ValueError("unterminated integer")
        body = data[i + 1:j]
        if not _is_bencode_int(body):
            raise ValueError("malformed integer")
        return j + 1
    if c == b"l" or c == b"d":  # list or dict: recurse over children
        j = i + 1
        while True:
            if j >= n:
                raise ValueError("unterminated list/dict")
            if data[j:j + 1] == b"e":
                return j + 1
            if c == b"d":
                # dict key must be a byte string
                if not data[j:j + 1].isdigit():
                    raise ValueError("dict key must be a byte string")
                j = _skip_value(data, j)
                j = _skip_value(data, j)
            else:
                j = _skip_value(data, j)
    if c.isdigit():  # byte string: <len>:<bytes>
        colon = data.find(b":", i)
        if colon < 0:
            raise ValueError("byte string missing colon")
        length_bytes = data[i:colon]
        if not length_bytes.isdigit():
            raise ValueError("malformed byte string length")
        if len(length_bytes) > 1 and length_bytes[:1] == b"0":
            raise ValueError("byte string length has leading zero")
        length = int(length_bytes)
        start = colon + 1
        end = start + length
        if end > n:
            raise ValueError("byte string overruns input")
        return end
    raise ValueError("unexpected token %r" % c)


def _is_bencode_int(body):
    """True iff *body* is a canonical bencode integer body (no leading zeros,
    optional single leading minus, not '-0')."""
    if not body:
        return False
    s = body
    if s[:1] == b"-":
        s = s[1:]
        if s == b"0" or not s:
            return False
    if not s.isdigit():
        return False
    if len(s) > 1 and s[:1] == b"0":
        return False
    return True


def _read_byte_string(data, i):
    """Read a bencode byte string at *i*; return (value_bytes, end_index)."""
    n = len(data)
    if i >= n or not data[i:i + 1].isdigit():
        raise ValueError("expected byte string")
    colon = data.find(b":", i)
    if colon < 0:
        raise ValueError("byte string missing colon")
    length_bytes = data[i:colon]
    if not length_bytes.isdigit():
        raise ValueError("malformed byte string length")
    if len(length_bytes) > 1 and length_bytes[:1] == b"0":
        raise ValueError("byte string length has leading zero")
    length = int(length_bytes)
    start = colon + 1
    end = start + length
    if end > n:
        raise ValueError("byte string overruns input")
    return data[start:end], end


def scan_top_level(data):
    """Scan the top-level bencode dict of *data* (raw torrent bytes).

    Returns ``{key_str: (value_start, value_end)}`` for every top-level member,
    where the span is the RAW byte range of that member's value (usable as
    ``data[start:end]`` verbatim).

    Rejects (ValueError): non-dict root, truncation, trailing data after the
    dict, malformed bencode, and duplicate top-level ``info`` / ``announce`` /
    ``announce-list`` keys."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("data must be bytes")
    data = bytes(data)
    n = len(data)
    if n == 0 or data[0:1] != b"d":
        raise ValueError("top-level value is not a dict")
    spans = {}
    i = 1
    while True:
        if i >= n:
            raise ValueError("unterminated top-level dict")
        if data[i:i + 1] == b"e":
            i += 1
            break
        key, i = _read_byte_string(data, i)
        value_start = i
        i = _skip_value(data, i)
        value_end = i
        if key in _UNIQUE_TOP_KEYS and key.decode("latin-1") in spans:
            raise ValueError("duplicate top-level key: %r" % key)
        # First occurrence wins for storage; duplicates of the guarded keys are
        # already rejected above. Non-guarded duplicate keys keep first span
        # (a canonical torrent never has them).
        skey = key.decode("latin-1")
        if skey not in spans:
            spans[skey] = (value_start, value_end)
    if i != n:
        raise ValueError("trailing data after top-level dict")
    return spans


def personalize(data, announce_url):
    """Return a personalized copy of the torrent *data*.

    The outer ``announce`` value is replaced with *announce_url* (bytes), any
    ``announce-list`` is removed, and the top-level ``info`` value byte span is
    copied verbatim so the info hash is provably unchanged.

    Asserts the output invariants before returning: exactly one rewritten
    top-level ``announce``, zero ``announce-list``, and a raw ``info`` span
    whose SHA-1 equals the original's. Raises ValueError on malformed/ambiguous
    input or if any invariant fails."""
    if isinstance(announce_url, str):
        announce_url = announce_url.encode("utf-8")
    data = bytes(data)
    spans = scan_top_level(data)
    if "info" not in spans:
        raise ValueError("torrent has no top-level info")
    if "announce" not in spans:
        raise ValueError("torrent has no top-level announce")

    info_start, info_end = spans["info"]
    original_info = data[info_start:info_end]
    original_info_hash = hashlib.sha1(original_info).digest()

    # Rebuild the top-level dict, replacing announce and dropping
    # announce-list. Emit all retained members in sorted key order (canonical
    # top-level layout) and copy each retained value span verbatim so no
    # re-encoding of nested structures ever occurs. Only the announce value is
    # substituted; info's inner bytes are untouched.
    retained = {}
    for skey, (vs, ve) in spans.items():
        if skey == "announce-list":
            continue
        if skey == "announce":
            retained[skey] = announce_url
        else:
            retained[skey] = data[vs:ve]
    out = bytearray(b"d")
    for skey in sorted(retained):
        kb = skey.encode("latin-1")
        out += b"%d:" % len(kb) + kb
        if skey == "announce":
            out += b"%d:" % len(announce_url) + announce_url
        else:
            out += retained[skey]
    out += b"e"
    out = bytes(out)

    # Assert output invariants on the RAW result.
    out_spans = scan_top_level(out)
    if "announce-list" in out_spans:
        raise ValueError("personalized output still has announce-list")
    if "announce" not in out_spans:
        raise ValueError("personalized output lost announce")
    if "info" not in out_spans:
        raise ValueError("personalized output lost info")
    os_, oe = out_spans["info"]
    if hashlib.sha1(out[os_:oe]).digest() != original_info_hash:
        raise ValueError("info span hash drifted during personalization")
    # Exactly one announce: scan_top_level already rejects duplicate announce.
    return out
