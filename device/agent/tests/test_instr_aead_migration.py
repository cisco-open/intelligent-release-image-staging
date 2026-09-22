# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
import copy
import hashlib
import json
from pathlib import Path

import pytest
import instr
from test_instr_verify import make_envelope, verify, reject, config, NOW, BOOT


def test_one_way_format_upgrade_preserves_epoch_serial_floor():
    raw = make_envelope()
    old = {'instructions': {'accepted_epoch': NOW - 1, 'accepted_serial': 7,
                            'v_floor': 1, 'envelope_digest': 'a' * 64}}
    result = verify(instr, raw, state=old)
    # Authentication alone must not mutate durable state.
    assert old['instructions']['v_floor'] == 1
    instr.apply_verified(result, old, NOW, 10, BOOT)
    assert old['instructions']['v_floor'] == 2
    assert old['instructions']['accepted_epoch'] == NOW - 1
    assert old['instructions']['accepted_serial'] == 7
    reject(instr, make_envelope(header={'policy_revision': 4}), 'tamper_rejected', state=old)
    reject(instr, make_envelope(header={'instr_serial': 6}), 'rollback_rejected', state=old)


@pytest.mark.parametrize('floor', [None, 1, 2])
def test_old_wire_version_is_rejected_even_without_persisted_version_floor(floor):
    raw = make_envelope().replace(b'IRIS-INSTR/2', b'IRIS-INSTR/1', 1)
    state = {} if floor is None else {'instructions': {'v_floor': floor}}
    before = copy.deepcopy(state)
    reject(instr, raw, state=state)
    assert state == before


def test_wire_magic_and_header_version_cannot_be_relabelled():
    reject(instr, make_envelope(header={'v': 1}))
    reject(instr, make_envelope().replace(b'IRIS-INSTR/2', b'IRIS-LKG/2', 1))


def test_legacy_lkg_requires_online_refresh_and_is_not_deleted(tmp_path):
    from test_instr_verify import AcceptVerifier, BOOT
    cfg = config()
    store = instr.LKGStore(str(tmp_path), cfg, lambda _: None, AcceptVerifier())
    raw = make_envelope().replace(b'IRIS-INSTR/2', b'IRIS-LKG/1', 1)
    Path(store.path).write_bytes(raw)
    state = {'instructions': {'v_floor': 1, 'lkg_digest': hashlib.sha256(raw).hexdigest()}}
    before = copy.deepcopy(state)
    with pytest.raises(instr.InstructionError):
        store.load('sw1', 'guestshell', NOW, 10, BOOT, state)
    assert state == before
    assert Path(store.path).read_bytes() == raw


@pytest.mark.parametrize('state_committed', [False, True])
def test_upgrade_cache_crash_recovery_tracks_durable_version_floor(tmp_path, state_committed):
    from test_instr_verify import AcceptVerifier
    cfg = config()
    store = instr.LKGStore(str(tmp_path), cfg, lambda _: None, AcceptVerifier())
    legacy = b'IRIS-LKG/1\nretained legacy bytes\n'
    Path(store.path).write_bytes(legacy)
    old = {'instructions': {'accepted_epoch': NOW - 1, 'accepted_serial': 7,
                            'v_floor': 1, 'envelope_digest': 'a' * 64,
                            'lkg_digest': hashlib.sha256(legacy).hexdigest()}}
    verified = verify(instr, state=old)
    candidate = copy.deepcopy(old)
    store.begin(old)
    store.store(verified, verified['device'], candidate)
    instr.apply_verified(verified, candidate, NOW, 10, BOOT)
    durable = candidate if state_committed else old
    # Simulate restart before transaction cleanup, with the actually durable state.
    restarted = instr.LKGStore(str(tmp_path), cfg, lambda _: None, AcceptVerifier())
    restarted.recover(durable)
    assert not Path(store.previous_path).exists()
    if state_committed:
        assert Path(store.path).read_bytes().startswith(b'IRIS-LKG/2\n')
        assert durable['instructions']['v_floor'] == 2
        loaded = restarted.load('sw1', 'guestshell', NOW, 11, BOOT, durable)
        assert loaded['device'] == verified['device']
    else:
        assert Path(store.path).read_bytes() == legacy
        assert durable['instructions']['v_floor'] == 1
        with pytest.raises(instr.InstructionError):
            restarted.load('sw1', 'guestshell', NOW, 11, BOOT, durable)
