# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for server/iris-assign (no .py extension, loaded via
SourceFileLoader -- the test_iris_revoke.py idiom): the QuarantinedImage
error path (KGV / Cisco Bulk Hash reconciler review wave) -- assigning an
image the reconciler has quarantined must print the verdict/reason to
stderr in the CLI's existing "error: ..." style and exit 1, never let the
exception escape as a traceback."""
import os
import types
from importlib.machinery import SourceFileLoader

import pytest

import bulkhash
import catalog

_CLI_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                          "iris-assign")


def _load_cli():
    loader = SourceFileLoader("iris_assign", _CLI_PATH)
    mod = types.ModuleType("iris_assign")
    mod.__file__ = _CLI_PATH
    loader.exec_module(mod)
    return mod


def _entry(image_id="img1", sha512="aa" * 64, **over):
    e = {"id": image_id, "filename": image_id + ".bin", "size": 5,
         "sha256": "ab" * 32, "sha512": sha512,
         "cisco_signature_verified": False,
         "info_hash_hex": "cc" * 20, "published_at": 111}
    e.update(over)
    return e


def _verdict(state, feed_sha512="bb" * 64, publish_date="2026-08-01",
            deferral=False):
    return {"state": state, "feed_sha512": feed_sha512,
            "publish_date": publish_date, "deferral": deferral}


def test_assigning_a_quarantined_image_prints_verdict_and_exits_1(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    store = catalog.CatalogStore(str(tmp_path))
    store.save_image(_entry("img1", sha512="aa" * 64))
    store.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_MISMATCH)}, source="scheduled",
        now=1000)
    assert store.get_image("img1")["quarantined"] is True

    rc = _load_cli().main(["sw-1", "img1"])

    assert rc == 1
    err = capsys.readouterr().err
    assert "img1" in err
    assert "quarantined" in err
    assert "mismatch" in err
    # nothing was persisted -- the device keeps no assignment at all
    assert store.get_policy("sw-1").get("approved_image_id") is None


def test_quarantined_and_since_deferred_image_notes_the_deferral(
        tmp_path, monkeypatch, capsys):
    """quarantined=True and hash_verification.deferral=True can co-occur:
    a first mismatch (deferral=False) quarantines the image, then a LATER
    feed refresh reports the same mismatch now deferred by Cisco --
    apply_hash_verification always refreshes hash_verification, but only
    ever ADDS a quarantine, never lifts one, on a later deferral. The CLI's
    printed reason should surface that deferral, not just the bare state."""
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    store = catalog.CatalogStore(str(tmp_path))
    store.save_image(_entry("img1", sha512="aa" * 64))
    store.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_MISMATCH, deferral=False)},
        source="scheduled", now=1000)
    store.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_MISMATCH, deferral=True)},
        source="scheduled", now=2000)
    entry = store.get_image("img1")
    assert entry["quarantined"] is True
    assert entry["hash_verification"]["deferral"] is True

    rc = _load_cli().main(["sw-1", "img1"])

    assert rc == 1
    assert "deferred" in capsys.readouterr().err


def test_assigning_a_verified_image_still_succeeds(tmp_path, monkeypatch,
                                                    capsys):
    """The QuarantinedImage try/except must not disturb the happy path."""
    monkeypatch.setenv("IRIS_STATE", str(tmp_path))
    store = catalog.CatalogStore(str(tmp_path))
    store.save_image(_entry("img1", sha512="aa" * 64))

    rc = _load_cli().main(["sw-1", "img1"])

    assert rc == 0
    assert store.get_policy("sw-1").get("approved_image_id") == "img1"
