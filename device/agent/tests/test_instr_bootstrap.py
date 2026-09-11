# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""One-shot custody contract for the staged instruction bootstrap envelope."""

import copy
import email.utils
import hashlib
import importlib
import os

import pytest

from test_instr_verify import (
    AcceptVerifier,
    BOOT,
    NOW,
    config,
    frame,
    make_envelope,
    part_value,
    role_value,
    unframe,
)


BOOTSTRAP_NAME = "iris-instructions.bootstrap"
DATE = email.utils.formatdate(NOW, usegmt=True)


@pytest.fixture
def instr():
    return importlib.import_module("instr")


class Catalog:
    def __init__(self, response=(503, b"", {})):
        self.response = response
        self.requests = []
        self.token = "token"

    def get_instructions(self, device_id, etag=None):
        self.requests.append((device_id, etag))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def get_instruction_keylist(self, device_id, etag=None):
        raise AssertionError("no keylist fetch was requested")

    def refresh_token(self, device_id):
        return {}


def _candidate(tmp_path):
    return tmp_path / BOOTSTRAP_NAME


def _run(module, tmp_path, *, catalog=None, state=None, cfg=None,
         verifier=None, hints=None, catalog_date=NOW, mono=10,
         cache_only=False, checkpoint=None):
    state = {} if state is None else state
    cfg = config() if cfg is None else cfg
    cfg["stage_dir"] = str(tmp_path)
    catalog = Catalog() if catalog is None else catalog
    verifier = AcceptVerifier() if verifier is None else verifier
    checkpoints = []
    if checkpoint is None:
        checkpoint = lambda value: checkpoints.append(copy.deepcopy(value))
    result = module.run_instruction_step(
        cfg, state, catalog,
        {"instr_rev": {"epoch": NOW - 1, "instr_serial": 8}}
        if hints is None else hints,
        catalog_date, "guestshell", str(tmp_path), BOOT, mono, verifier,
        lambda _updated: None, lambda *_args: None,
        checkpoint=checkpoint, cache_only=cache_only)
    return result, state, catalog, verifier, checkpoints


def test_paths_expose_fixed_bootstrap_name_under_each_platform_work_dir(instr):
    for platform in ("guestshell", "router", "iox", "xr-appmgr"):
        paths = instr.paths_for(platform, {"stage_dir": "/stage"})
        assert paths["bootstrap"] == os.path.join(
            paths["work_dir"], BOOTSTRAP_NAME)


@pytest.mark.parametrize("kwargs", [
    {"cache_only": True},
    {"hints": {}},
    {"catalog_date": None},
], ids=["cache-only", "no-pointer", "no-authenticated-date"])
def test_bootstrap_is_retained_outside_eligible_online_step(instr, tmp_path,
                                                            kwargs):
    path = _candidate(tmp_path)
    path.write_bytes(make_envelope())
    verifier = AcceptVerifier()

    _run(instr, tmp_path, verifier=verifier, **kwargs)

    assert path.exists()
    assert verifier.calls == []


def test_bootstrap_is_durably_applied_and_survives_online_fetch_failure(
        instr, tmp_path):
    raw = make_envelope()
    path = _candidate(tmp_path)
    path.write_bytes(raw)

    result, state, catalog, _verifier, checkpoints = _run(instr, tmp_path)

    assert result["instruction"]["header"]["instr_serial"] == 7
    assert result["attestation"]["instr_state"] == "applied"
    assert result["effective"] == part_value()
    assert "fetched_pointer" not in state["instructions"]
    assert "envelope_etag" not in state["instructions"]
    assert state["instructions"]["envelope_digest"] == hashlib.sha256(raw).hexdigest()
    assert checkpoints[-1]["instructions"]["accepted_serial"] == 7
    assert (tmp_path / "iris-instructions.lkg").is_file()
    assert not path.exists()
    assert catalog.requests == [("sw1", None)]


def test_newer_online_envelope_wins_after_bootstrap_in_the_same_tick(
        instr, tmp_path):
    path = _candidate(tmp_path)
    path.write_bytes(make_envelope())
    online = make_envelope(header={"instr_serial": 8})
    catalog = Catalog((200, online, {"Date": DATE, "ETag": '"online-8"'}))

    result, state, _catalog, verifier, checkpoints = _run(
        instr, tmp_path, catalog=catalog)

    assert result["instruction"]["header"]["instr_serial"] == 8
    assert result["attestation"]["instr_state"] == "applied"
    assert state["instructions"]["fetched_pointer"] == {
        "epoch": NOW - 1, "instr_serial": 8}
    assert state["instructions"]["envelope_etag"] == '"online-8"'
    assert len(verifier.calls) == 2
    assert [item["instructions"]["accepted_serial"] for item in checkpoints] == [7, 8]
    assert not path.exists()


def _expired_envelope():
    role = role_value()
    role["expires_at"] = NOW
    part = part_value()
    part["peers"]["allowed_expires_at"] = NOW
    return make_envelope(
        header={"expires_at": NOW, "allowed_expires_at": NOW},
        role=role, part=part)


def _bad_mac_envelope():
    parts = unframe(make_envelope())
    parts[-1] = b"x" * 32
    return frame(parts)


@pytest.mark.parametrize("raw,state,accepted", [
    (b"broken\n", {}, True),
    (b"x" * (256 * 1024 + 1), {}, True),
    (make_envelope(header={"device_id": "other"}), {}, True),
    (make_envelope(), {}, False),
    (_bad_mac_envelope(), {}, True),
    (_expired_envelope(), {}, True),
    (make_envelope(), {"instructions": {
        "accepted_epoch": NOW - 1, "accepted_serial": 8,
        "envelope_digest": "a" * 64, "v_floor": 1}}, True),
], ids=["framing", "size", "audience", "signature", "mac", "expiry",
        "rollback"])
def test_definitive_bootstrap_rejection_deletes_candidate(
        instr, tmp_path, raw, state, accepted):
    path = _candidate(tmp_path)
    path.write_bytes(raw)
    verifier = AcceptVerifier()
    verifier.verify = (lambda *_args, **_kwargs: accepted)

    _run(instr, tmp_path, state=copy.deepcopy(state), verifier=verifier)

    assert not path.exists()


def test_unknown_key_and_verifier_failure_retain_candidate(instr, tmp_path):
    unknown = make_envelope(key=b"z" * 32)
    path = _candidate(tmp_path)
    path.write_bytes(unknown)
    _run(instr, tmp_path)
    assert path.read_bytes() == unknown

    class MissingVerifier:
        def verify(self, *_args, **_kwargs):
            raise instr.InstructionError("verifier_missing", "verifier_timeout")

    known = make_envelope()
    path.write_bytes(known)
    _run(instr, tmp_path, verifier=MissingVerifier())
    assert path.read_bytes() == known


def test_symlink_and_failed_checkpoint_retain_candidate(instr, tmp_path):
    target = tmp_path / "outside.envelope"
    target.write_bytes(make_envelope())
    path = _candidate(tmp_path)
    path.symlink_to(target)
    verifier = AcceptVerifier()

    _run(instr, tmp_path, verifier=verifier)
    assert path.is_symlink()
    assert verifier.calls == []

    path.unlink()
    raw = make_envelope()
    path.write_bytes(raw)

    def fail_checkpoint(_state):
        # A local failure must never inherit the deletion policy of a remote
        # verification state with the same name.
        raise instr.InstructionError("rollback_rejected")

    _result, state, _catalog, _verifier, _checkpoints = _run(
        instr, tmp_path, checkpoint=fail_checkpoint)
    assert path.read_bytes() == raw
    assert state.get("instructions", {}).get("accepted_serial") is None


def test_matching_accepted_digest_retries_unlink_without_candidate_reverify(
        instr, tmp_path):
    raw = make_envelope()
    cfg = config()
    cfg["stage_dir"] = str(tmp_path)
    state = {}
    seed_verifier = AcceptVerifier()
    verified = instr.verify_envelope(
        raw, cfg, state, NOW, 10, BOOT, seed_verifier)
    store = instr.LKGStore(str(tmp_path), cfg, lambda _updated: None,
                           seed_verifier)
    store.store(verified, verified["device"], state)
    instr.apply_verified(verified, state, NOW, 10, BOOT)
    path = _candidate(tmp_path)
    path.write_bytes(raw)
    verifier = AcceptVerifier()

    result, _state, _catalog, _verifier, _checkpoints = _run(
        instr, tmp_path, cfg=cfg, state=state, verifier=verifier, mono=20)

    assert result["instruction"]["header"]["instr_serial"] == 7
    assert len(verifier.calls) == 1  # LKG only; the duplicate candidate is not verified.
    assert not path.exists()


def test_candidate_path_swap_does_not_delete_replacement(instr, tmp_path):
    original = make_envelope()
    replacement = b"replacement must survive\n"
    path = _candidate(tmp_path)
    path.write_bytes(original)

    class SwappingVerifier(AcceptVerifier):
        def verify(self, *args, **kwargs):
            temporary = tmp_path / "replacement.tmp"
            temporary.write_bytes(replacement)
            os.replace(str(temporary), str(path))
            return super().verify(*args, **kwargs)

    result, _state, _catalog, _verifier, _checkpoints = _run(
        instr, tmp_path, verifier=SwappingVerifier())

    assert result["attestation"]["instr_state"] == "applied"
    assert path.read_bytes() == replacement
