# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Minimal bencode (encode + decode), stdlib only. str is encoded as UTF-8 bytes;
decode returns bytes for all byte-strings. Dict keys are emitted in sorted byte
order (canonical form), so re-encoding a decoded `info` dict reproduces the exact
bytes and yields a correct info_hash."""


def encode(obj):
    buf = bytearray()
    _encode(obj, buf)
    return bytes(buf)


def _encode(obj, buf):
    if isinstance(obj, bool):
        raise TypeError("refusing to bencode a bool")
    if isinstance(obj, int):
        buf += b"i%de" % obj
    elif isinstance(obj, bytes):
        buf += b"%d:" % len(obj) + obj
    elif isinstance(obj, str):
        b = obj.encode("utf-8")
        buf += b"%d:" % len(b) + b
    elif isinstance(obj, (list, tuple)):
        buf += b"l"
        for item in obj:
            _encode(item, buf)
        buf += b"e"
    elif isinstance(obj, dict):
        buf += b"d"
        for key in sorted(obj, key=_key_bytes):
            kb = _key_bytes(key)
            buf += b"%d:" % len(kb) + kb
            _encode(obj[key], buf)
        buf += b"e"
    else:
        raise TypeError("cannot bencode %s" % type(obj).__name__)


def _key_bytes(key):
    return key if isinstance(key, bytes) else key.encode("utf-8")


def decode(data):
    value, index = _decode(data, 0)
    if index != len(data):
        raise ValueError("trailing bytes after bencode value")
    return value


def _decode(data, i):
    ch = data[i:i + 1]
    if ch == b"i":
        end = data.index(b"e", i)
        return int(data[i + 1:end]), end + 1
    if ch == b"l":
        i += 1
        out = []
        while data[i:i + 1] != b"e":
            item, i = _decode(data, i)
            out.append(item)
        return out, i + 1
    if ch == b"d":
        i += 1
        out = {}
        while data[i:i + 1] != b"e":
            key, i = _decode(data, i)
            val, i = _decode(data, i)
            out[key] = val
        return out, i + 1
    if ch.isdigit():
        colon = data.index(b":", i)
        length = int(data[i:colon])
        start = colon + 1
        return data[start:start + length], start + length
    raise ValueError("invalid bencode token at byte %d" % i)
