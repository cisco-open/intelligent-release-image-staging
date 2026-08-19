# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import json
import os

import telemetry_destination


def test_settings_path_joins_basename():
    assert telemetry_destination.settings_path("/var/lib/iris") == \
        "/var/lib/iris/telemetry-destination.json"


def test_read_missing_file_inherits_env(tmp_path):
    assert telemetry_destination.read(str(tmp_path / "nope.json")) == \
        {"endpoint": None, "enabled": None}


def test_read_corrupt_json_inherits_env(tmp_path):
    p = tmp_path / telemetry_destination.BASENAME
    p.write_text("{nope")
    assert telemetry_destination.read(str(p)) == \
        {"endpoint": None, "enabled": None}


def test_read_non_dict_document_inherits_env(tmp_path):
    p = tmp_path / telemetry_destination.BASENAME
    p.write_text('["a list, not a dict"]')
    assert telemetry_destination.read(str(p)) == \
        {"endpoint": None, "enabled": None}


def test_read_wrong_types_collapse_per_field(tmp_path):
    p = tmp_path / telemetry_destination.BASENAME
    # enabled=1 is an int, not a bool -> inherit; endpoint int -> inherit
    p.write_text(json.dumps({"endpoint": 42, "enabled": 1}))
    assert telemetry_destination.read(str(p)) == \
        {"endpoint": None, "enabled": None}
    # one good field survives a bad sibling
    p.write_text(json.dumps({"endpoint": "http://c:4318", "enabled": "yes"}))
    assert telemetry_destination.read(str(p)) == \
        {"endpoint": "http://c:4318", "enabled": None}
    # whitespace-only endpoint is "no override", not an empty destination
    p.write_text(json.dumps({"endpoint": "   ", "enabled": False}))
    assert telemetry_destination.read(str(p)) == \
        {"endpoint": None, "enabled": False}


def test_write_roundtrip_and_null_fields(tmp_path):
    p = str(tmp_path / telemetry_destination.BASENAME)
    telemetry_destination.write(p, "http://collector:4318", True)
    assert telemetry_destination.read(p) == \
        {"endpoint": "http://collector:4318", "enabled": True}
    telemetry_destination.write(p, None, False)   # endpoint inherits, off
    assert telemetry_destination.read(p) == \
        {"endpoint": None, "enabled": False}


def test_write_is_atomic_no_temp_left_behind(tmp_path):
    p = str(tmp_path / telemetry_destination.BASENAME)
    telemetry_destination.write(p, "http://c:4318", True)
    assert os.listdir(str(tmp_path)) == [telemetry_destination.BASENAME]
    with open(p) as f:                            # visible file is complete
        assert json.load(f) == {"endpoint": "http://c:4318", "enabled": True}


def test_clear_removes_and_is_idempotent(tmp_path):
    p = str(tmp_path / telemetry_destination.BASENAME)
    telemetry_destination.write(p, "http://c:4318", True)
    telemetry_destination.clear(p)
    assert not os.path.exists(p)
    telemetry_destination.clear(p)                # second clear: no raise


def test_destination_settings_mtime_cache(tmp_path):
    p = str(tmp_path / telemetry_destination.BASENAME)
    s = telemetry_destination.DestinationSettings(p)
    assert s.current() == (None, None)            # missing file: inherit env
    telemetry_destination.write(p, "http://one:4318", True)
    os.utime(p, (1000, 1000))
    assert s.current() == ("http://one:4318", True)
    # same mtime -> the CACHED tuple is returned even if content changed
    with open(p, "w") as f:
        json.dump({"endpoint": "http://two:4318", "enabled": False}, f)
    os.utime(p, (1000, 1000))
    assert s.current() == ("http://one:4318", True)
    # mtime bump -> re-read picks up the new content
    os.utime(p, (2000, 2000))
    assert s.current() == ("http://two:4318", False)


def test_destination_settings_removed_file_reverts_to_inherit(tmp_path):
    p = str(tmp_path / telemetry_destination.BASENAME)
    telemetry_destination.write(p, "http://one:4318", True)
    s = telemetry_destination.DestinationSettings(p)
    assert s.current() == ("http://one:4318", True)
    telemetry_destination.clear(p)                # revert to deployment default
    assert s.current() == (None, None)


def test_destination_settings_corrupt_file_inherits(tmp_path):
    p = str(tmp_path / telemetry_destination.BASENAME)
    with open(p, "w") as f:
        f.write("{nope")
    assert telemetry_destination.DestinationSettings(p).current() == \
        (None, None)
