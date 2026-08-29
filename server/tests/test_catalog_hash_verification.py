# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Cisco Bulk Hash reconciliation (KGV reconciler Task 2):
CatalogStore.apply_hash_verification() / release_quarantine(), and the
quarantine enforcement set_policy() carries for both the console /assign
route and this module's own auto-unassign.

Task 1 (server/bulkhash.py, merged) owns fetch/verify/parse/reconcile --
none of that runs here. Every test builds verdict dicts by hand, in
exactly the shape bulkhash.reconcile() returns: {image_id: {state,
feed_sha512, publish_date, deferral}}."""
import json

import pytest

import audit
import bulkhash
import catalog


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _store(tmp_path, audited=True, seeder=True):
    """A CatalogStore wired for the quarantine path: an audit_path under
    tmp_path (so tests can read it back) and a fake seeder_remove_fn that
    records every info_hash it was asked to remove -- both toggleable off
    to exercise the "not wired" defaults."""
    removed = []
    kwargs = {}
    if audited:
        kwargs["audit_path"] = str(tmp_path / "audit.jsonl")
    if seeder:
        kwargs["seeder_remove_fn"] = lambda ih: removed.append(ih)
    s = catalog.CatalogStore(str(tmp_path), **kwargs)
    s.removed = removed  # test-only attribute, harmless
    return s


def _entry(image_id="img1", sha512="aa" * 64, **over):
    e = {"id": image_id, "filename": image_id + ".bin", "size": 5,
         "sha256": "ab" * 32, "sha512": sha512,
         "cisco_signature_verified": False,
         "info_hash_hex": "cc" * 20, "published_at": 111}
    e.update(over)
    return e


def _seed(store, image_id="img1", sha512="aa" * 64, **over):
    store.save_image(_entry(image_id, sha512, **over))


def _verdict(state, feed_sha512="aa" * 64, publish_date="2026-08-01",
            deferral=False):
    return {"state": state, "feed_sha512": feed_sha512,
            "publish_date": publish_date, "deferral": deferral}


def _audit_events(store):
    return audit.read_events(store.audit_path, limit=None)


# ---------------------------------------------------------------------------
# apply_hash_verification: wire fields + cisco_signature_verified sync
# ---------------------------------------------------------------------------

def test_apply_hash_verification_writes_wire_fields_on_verified(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_VERIFIED, feed_sha512="aa" * 64,
                          publish_date="2026-08-01")},
        source="scheduled", now=1000)
    entry = s.get_image("img1")
    assert entry["hash_verification"] == {
        "state": "verified", "checked_at": 1000,
        "feed_published_at": "2026-08-01", "source": "scheduled",
        "deferral": False}
    assert entry["cisco_signature_verified"] is True
    assert not entry.get("quarantined")


def test_apply_hash_verification_mismatch_syncs_signature_flag_false(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_MISMATCH, feed_sha512="bb" * 64)},
        source="scheduled", now=1000)
    entry = s.get_image("img1")
    assert entry["hash_verification"]["state"] == "mismatch"
    assert entry["cisco_signature_verified"] is False


def test_apply_hash_verification_not_in_feed_never_quarantines(tmp_path):
    s = _store(tmp_path)
    _seed(s)
    s.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_NOT_IN_FEED, feed_sha512=None,
                          publish_date=None)},
        source="scheduled", now=1000)
    entry = s.get_image("img1")
    assert entry["hash_verification"]["state"] == "not_in_feed"
    assert not entry.get("quarantined")
    assert s.removed == []


def test_apply_hash_verification_skips_verdict_for_unknown_image(tmp_path):
    """An image_id in verdicts with no catalog entry is skipped, not an
    error -- the pipeline reconciles against list_images(), so this should
    not happen in practice, but a stale/racing id must never crash the
    whole batch."""
    s = _store(tmp_path)
    _seed(s, image_id="img1")
    s.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_VERIFIED),
         "ghost": _verdict(bulkhash.STATE_MISMATCH)},
        source="scheduled")
    assert s.get_image("img1")["hash_verification"]["state"] == "verified"
    assert s.get_image("ghost") is None


def test_apply_hash_verification_untouched_images_have_no_verdict_field(tmp_path):
    s = _store(tmp_path)
    _seed(s, image_id="img1")
    _seed(s, image_id="img2")
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_VERIFIED)},
                              source="scheduled")
    assert "hash_verification" not in s.get_image("img2")


# ---------------------------------------------------------------------------
# apply_hash_verification: input validation, all-or-nothing
# ---------------------------------------------------------------------------

def test_apply_hash_verification_rejects_unknown_source(tmp_path):
    s = _store(tmp_path)
    _seed(s)
    with pytest.raises(ValueError):
        s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_VERIFIED)},
                                  source="cron")
    assert "hash_verification" not in s.get_image("img1")


def test_apply_hash_verification_rejects_unknown_state_before_writing_anything(tmp_path):
    """Validation is a full pass BEFORE any write: a bad verdict later in
    the dict must not leave an earlier, valid one partially applied."""
    s = _store(tmp_path)
    _seed(s, image_id="img1")
    _seed(s, image_id="img2")
    verdicts = {"img1": _verdict(bulkhash.STATE_VERIFIED),
               "img2": {"state": "bogus", "feed_sha512": None,
                        "publish_date": None, "deferral": False}}
    with pytest.raises(ValueError):
        s.apply_hash_verification(verdicts, source="scheduled")
    assert "hash_verification" not in s.get_image("img1")
    assert "hash_verification" not in s.get_image("img2")


# ---------------------------------------------------------------------------
# Transition matrix + idempotency + deferral flapping
# ---------------------------------------------------------------------------

def test_verified_to_mismatch_fires_quarantine(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_VERIFIED,
                                                feed_sha512="aa" * 64)},
                              source="scheduled")
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    entry = s.get_image("img1")
    assert entry["quarantined"] is True
    assert s.removed == ["cc" * 20]                 # stopped seeding
    with pytest.raises(catalog.QuarantinedImage):
        s.set_policy("d1", approved_image_ids=["img1"])


def test_mismatch_to_mismatch_does_not_refire(tmp_path):
    """Idempotent re-runs (or a second scheduled check reporting the same
    mismatch) must not re-fire actions: no second seeder-stop call, no
    second quarantine audit entry, no double auto-unassign."""
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.set_policy("d1", approved_image_ids=[])  # no-op, exercises nothing yet
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    assert len(s.removed) == 1
    quarantine_events = [e for e in _audit_events(s)
                         if e.get("event") == "image_quarantine"]
    assert len(quarantine_events) == 1
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="cc" * 64)},
                              source="scheduled")  # even a different feed hash
    assert len(s.removed) == 1                      # no repeat stop-seeding
    quarantine_events = [e for e in _audit_events(s)
                         if e.get("event") == "image_quarantine"]
    assert len(quarantine_events) == 1               # no repeat quarantine audit


def test_mismatch_to_verified_updates_wire_fields_but_stays_quarantined(tmp_path):
    """apply_hash_verification never auto-lifts a quarantine, even when a
    LATER verdict reports the image verified again -- only
    release_quarantine() can do that."""
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    assert s.get_image("img1")["quarantined"] is True
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_VERIFIED,
                                                feed_sha512="aa" * 64)},
                              source="scheduled")
    entry = s.get_image("img1")
    assert entry["hash_verification"]["state"] == "verified"
    assert entry["cisco_signature_verified"] is True
    assert entry["quarantined"] is True              # still blocked
    with pytest.raises(catalog.QuarantinedImage):
        s.set_policy("d1", approved_image_ids=["img1"])


def test_not_in_feed_to_mismatch_fires_quarantine(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_NOT_IN_FEED,
                                                feed_sha512=None,
                                                publish_date=None)},
                              source="scheduled")
    assert not s.get_image("img1").get("quarantined")
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    assert s.get_image("img1")["quarantined"] is True
    assert len(s.removed) == 1


def test_first_ever_verdict_mismatch_fires_quarantine(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    assert s.get_image("img1")["quarantined"] is True
    assert len(s.removed) == 1


def test_deferred_mismatch_never_quarantines(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_MISMATCH, feed_sha512="bb" * 64,
                          deferral=True)},
        source="scheduled")
    entry = s.get_image("img1")
    assert entry["hash_verification"]["state"] == "mismatch"
    assert entry["hash_verification"]["deferral"] is True
    assert not entry.get("quarantined")
    assert s.removed == []
    s.set_policy("d1", approved_image_ids=["img1"])   # must NOT raise


def test_deferral_flapping_fires_once_deferral_clears(tmp_path):
    """A mismatch suppressed by deferral has never been ACTED on. The
    moment a later verdict reports the same mismatch with deferral
    cleared, quarantine must fire then -- the prior stored state was
    already "mismatch", so a naive prior-state-only transition check would
    wrongly treat this as "no change"."""
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_MISMATCH, feed_sha512="bb" * 64,
                          deferral=True)},
        source="scheduled")
    assert not s.get_image("img1").get("quarantined")
    assert s.removed == []
    s.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_MISMATCH, feed_sha512="bb" * 64,
                          deferral=False)},
        source="scheduled")
    entry = s.get_image("img1")
    assert entry["quarantined"] is True
    assert len(s.removed) == 1
    # and flapping deferral back on afterward does not un-quarantine
    s.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_MISMATCH, feed_sha512="bb" * 64,
                          deferral=True)},
        source="scheduled")
    assert s.get_image("img1")["quarantined"] is True
    assert len(s.removed) == 1                        # no repeat fire either


# ---------------------------------------------------------------------------
# Quarantine actions: seeder teardown without deleting, block assign,
# auto-unassign everywhere with one audit entry per affected device
# ---------------------------------------------------------------------------

def test_quarantine_stops_seeding_without_deleting_the_entry(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64, info_hash_hex="deadbeef" * 5)
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    assert s.removed == ["deadbeef" * 5]
    assert s.get_image("img1") is not None           # entry kept
    assert s.list_images() and s.list_images()[0]["id"] == "img1"


def test_quarantine_without_seeder_fn_is_a_safe_noop(tmp_path):
    """seeder_remove_fn defaults to None (unwired): quarantine must still
    take effect (block + auto-unassign) even though there is nothing to
    call for the stop-seeding step."""
    s = _store(tmp_path, seeder=False)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    assert s.get_image("img1")["quarantined"] is True


def test_quarantine_auto_unassigns_every_affected_device_with_one_audit_entry_each(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.save_image(_entry("img2", sha512="ee" * 64))
    s.set_policy("d1", approved_image_ids=["img1"])
    s.set_policy("d2", approved_image_ids=["img1", "img2"])
    s.set_policy("d3", approved_image_ids=["img2"])   # unaffected
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    assert s.get_policy("d1")["approved_image_ids"] == []
    assert s.get_policy("d2")["approved_image_ids"] == ["img2"]
    assert s.get_policy("d3")["approved_image_ids"] == ["img2"]   # untouched

    unassign_events = [e for e in _audit_events(s)
                       if e.get("category") == "device"
                       and e.get("action") == "unassign"]
    assert len(unassign_events) == 2
    assert {e["target"] for e in unassign_events} == {"d1", "d2"}


def test_quarantine_with_no_assignments_audits_only_the_quarantine_event(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    unassign_events = [e for e in _audit_events(s) if e.get("action") == "unassign"]
    assert unassign_events == []
    quarantine_events = [e for e in _audit_events(s)
                         if e.get("event") == "image_quarantine"]
    assert len(quarantine_events) == 1
    assert quarantine_events[0]["target"] == "img1"


def test_set_policy_refuses_quarantined_id_for_a_new_device_too(tmp_path):
    """Blocking is a property of the IMAGE, independent of whether the
    device requesting it ever held it before."""
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    with pytest.raises(catalog.QuarantinedImage) as exc:
        s.set_policy("brand-new-device", approved_image_ids=["img1"])
    assert exc.value.image_id == "img1"
    assert exc.value.hash_verification["state"] == "mismatch"
    assert s.get_policy("brand-new-device")["approved_image_ids"] == []


def test_set_policy_unassign_of_a_quarantined_image_still_works(tmp_path):
    """Refusing quarantined ids must never block removing them."""
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.set_policy("d1", approved_image_ids=["img1"])
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    s.set_policy("d1", approved_image_ids=[])   # must not raise
    assert s.get_policy("d1")["approved_image_ids"] == []


def test_auto_unassign_recovers_when_a_device_carries_two_quarantined_images(tmp_path):
    """A device holding TWO already-quarantined images must not have its
    auto-unassign of the first blocked by set_policy's own "no quarantined
    ids in the stored set" rule tripping over the second one still sitting
    in its policy."""
    s = _store(tmp_path)
    _seed(s, image_id="img1", sha512="aa" * 64)
    _seed(s, image_id="img2", sha512="cc" * 64)
    s.set_policy("d1", approved_image_ids=["img1", "img2"])
    s.apply_hash_verification(
        {"img1": _verdict(bulkhash.STATE_MISMATCH, feed_sha512="bb" * 64),
         "img2": _verdict(bulkhash.STATE_MISMATCH, feed_sha512="dd" * 64)},
        source="scheduled")
    assert s.get_policy("d1")["approved_image_ids"] == []


# ---------------------------------------------------------------------------
# release_quarantine: clean release, override release, guard rails
# ---------------------------------------------------------------------------

def test_release_quarantine_clean_when_feed_now_matches(tmp_path):
    """The stored feed verdict now agrees with the catalog's OWN sha512
    (the operator replaced/corrected the image) -- a clean release, no
    override needed, and hash_verification flips back to verified."""
    s = _store(tmp_path)
    _seed(s, sha512="bb" * 64)          # already the corrected sha512
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    # the operator fixes the catalog's own sha512 to agree with the feed
    entry = s.get_image("img1")
    entry["sha512"] = "bb" * 64
    s.save_image(entry)
    result = s.release_quarantine("img1", actor="console:admin")
    assert result["override"] is False
    entry = s.get_image("img1")
    assert entry["quarantined"] is False
    assert entry["hash_verification"]["state"] == "verified"
    assert entry["cisco_signature_verified"] is True
    s.set_policy("d1", approved_image_ids=["img1"])   # must not raise


def test_release_quarantine_still_mismatching_requires_override(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)          # never corrected
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    with pytest.raises(catalog.QuarantineStillMismatched):
        s.release_quarantine("img1", actor="console:admin")
    entry = s.get_image("img1")
    assert entry["quarantined"] is True                # nothing changed
    assert entry["hash_verification"]["state"] == "mismatch"


def test_release_quarantine_override_lifts_block_but_state_stays_mismatch(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    result = s.release_quarantine("img1", actor="console:admin", override=True)
    assert result["override"] is True
    entry = s.get_image("img1")
    assert entry["quarantined"] is False
    assert entry["hash_verification"]["state"] == "mismatch"   # truthful, unchanged
    assert entry["cisco_signature_verified"] is False
    s.set_policy("d1", approved_image_ids=["img1"])   # must not raise now


def test_release_quarantine_audits_override_flag(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    s.release_quarantine("img1", actor="console:admin", override=True)
    releases = [e for e in _audit_events(s)
               if e.get("event") == "image_quarantine_release"]
    assert len(releases) == 1
    assert releases[0]["action"] == "release_override"
    assert releases[0]["actor"] == "console:admin"
    assert releases[0]["target"] == "img1"


def test_release_quarantine_audits_clean_release_without_override_flag(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="bb" * 64)
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    entry = s.get_image("img1")
    entry["sha512"] = "bb" * 64
    s.save_image(entry)
    s.release_quarantine("img1", actor="console:admin")
    releases = [e for e in _audit_events(s)
               if e.get("event") == "image_quarantine_release"]
    assert len(releases) == 1
    assert releases[0]["action"] == "release"


def test_release_quarantine_unknown_image_raises_keyerror(tmp_path):
    s = _store(tmp_path)
    with pytest.raises(KeyError):
        s.release_quarantine("nope", actor="console:admin")


def test_release_quarantine_not_currently_quarantined_raises_valueerror(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    with pytest.raises(ValueError):
        s.release_quarantine("img1", actor="console:admin")


def test_release_quarantine_with_no_stored_feed_sha512_fails_closed(tmp_path):
    """Defensive: a durably corrupt/missing feed_sha512 in the verdict
    store must never be treated as an implicit match."""
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    catalog._atomic_write_json(s.hash_verdicts_path, {})  # simulate corruption
    with pytest.raises(catalog.QuarantineStillMismatched):
        s.release_quarantine("img1", actor="console:admin")


# ---------------------------------------------------------------------------
# Crash-safe persistence: a fresh CatalogStore reads back the same state
# ---------------------------------------------------------------------------

def test_quarantine_state_survives_a_fresh_store_reload(tmp_path):
    s = _store(tmp_path)
    _seed(s, sha512="aa" * 64)
    s.apply_hash_verification({"img1": _verdict(bulkhash.STATE_MISMATCH,
                                                feed_sha512="bb" * 64)},
                              source="scheduled")
    s2 = catalog.CatalogStore(str(tmp_path))
    entry = s2.get_image("img1")
    assert entry["quarantined"] is True
    assert entry["hash_verification"]["state"] == "mismatch"
    with pytest.raises(catalog.QuarantinedImage):
        s2.set_policy("d1", approved_image_ids=["img1"])
