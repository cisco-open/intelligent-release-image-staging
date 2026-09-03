# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the tracker-written / GUI-read enforcement status file
(``peer-enforcement.json``, spec 10.5b / 13). Exact schema, count-only
``desired_ip_count`` (never a raw IP list), typed conflicts, effect counters,
nonsecret error, and the no-false-enforced states."""
import glob
import json
import os

import pytest

import peer_enforcement


@pytest.fixture
def path(tmp_path):
    return str(tmp_path / "peer-enforcement.json")


def _read(path):
    with open(path) as f:
        return json.load(f)


class TestConstants:
    def test_states(self):
        assert set(peer_enforcement.STATES) == {
            "enforced", "degraded", "pending", "rpc_unavailable",
            "fail_closed"}


class TestEnforcedWrite:
    def test_full_enforced_status(self, path):
        status = peer_enforcement.build_status(
            state="enforced", aria_session_id="b1d9c0a2f4e6",
            desired_hash="3ab8f0c1d2e34556", applied_revision=12,
            desired_ip_count=3, now=1755743185.0,
            last_operation_exported_revision=7,
            conflicts=[{
                "ipv4": "192.0.2.10", "reason": "shared_permit_deny",
                "permitted_principal_type": "service",
                "permitted_principal_id": "seeder",
                "denied_principal_type": "device",
                "denied_principal_id": "iris8kv-3",
                "global_block_applied": False}],
            last_effect={"disconnected_peers": 1, "removed_peers": 0},
            last_error=None)
        peer_enforcement.write_status(path, status)
        doc = _read(path)
        assert doc["schema"] == 1
        assert doc["state"] == "enforced"
        assert doc["aria_session_id"] == "b1d9c0a2f4e6"
        assert doc["desired_hash"] == "3ab8f0c1d2e34556"
        assert doc["applied_revision"] == 12
        assert doc["desired_ip_count"] == 3
        assert doc["updated_at"] == 1755743185.0
        assert doc["last_reconciled_at"] == 1755743185.0
        assert doc["last_operation_exported_revision"] == 7
        assert doc["last_effect"] == {"disconnected_peers": 1,
                                      "removed_peers": 0}
        assert doc["last_error"] is None
        assert doc["conflicts"][0]["global_block_applied"] is False

    def test_atomic_no_tmp_left(self, path):
        peer_enforcement.write_status(
            path, peer_enforcement.build_status(
                state="enforced", aria_session_id="s", desired_hash="h",
                applied_revision=1, desired_ip_count=0, now=1.0))
        d = os.path.dirname(path)
        assert glob.glob(os.path.join(d, ".peer-enforcement*.tmp")) == []


class TestCountOnly:
    def test_never_stores_raw_ip_list(self, path):
        peer_enforcement.write_status(
            path, peer_enforcement.build_status(
                state="enforced", aria_session_id="s", desired_hash="h",
                applied_revision=1, desired_ip_count=3, now=1.0))
        blob = open(path).read()
        assert "denied_ips" not in blob
        assert "100.92.100" not in blob  # no device address anywhere

    def test_build_rejects_raw_denied_ip_list(self):
        with pytest.raises((TypeError, ValueError)):
            peer_enforcement.build_status(
                state="enforced", aria_session_id="s", desired_hash="h",
                applied_revision=1, desired_ip_count=3, now=1.0,
                denied_ips=["10.0.0.1"])

    def test_desired_ip_count_must_be_int(self):
        with pytest.raises((TypeError, ValueError)):
            peer_enforcement.build_status(
                state="enforced", aria_session_id="s", desired_hash="h",
                applied_revision=1, desired_ip_count="3", now=1.0)


class TestNoFalseEnforced:
    def test_fail_closed_state_written(self, path):
        status = peer_enforcement.build_status(
            state="fail_closed", aria_session_id="s", desired_hash=None,
            applied_revision=None, desired_ip_count=0, now=1.0)
        peer_enforcement.write_status(path, status)
        assert _read(path)["state"] == "fail_closed"

    def test_enforced_requires_session_and_hash(self):
        # enforced with no session or no hash is a false claim -> rejected.
        with pytest.raises(peer_enforcement.EnforcementError):
            peer_enforcement.build_status(
                state="enforced", aria_session_id=None, desired_hash="h",
                applied_revision=1, desired_ip_count=1, now=1.0)
        with pytest.raises(peer_enforcement.EnforcementError):
            peer_enforcement.build_status(
                state="enforced", aria_session_id="s", desired_hash=None,
                applied_revision=1, desired_ip_count=1, now=1.0)

    def test_pending_allows_missing_hash(self, path):
        status = peer_enforcement.build_status(
            state="pending", aria_session_id="s", desired_hash=None,
            applied_revision=None, desired_ip_count=0, now=1.0)
        peer_enforcement.write_status(path, status)
        assert _read(path)["state"] == "pending"

    def test_rpc_unavailable_state(self, path):
        status = peer_enforcement.build_status(
            state="rpc_unavailable", aria_session_id=None, desired_hash=None,
            applied_revision=None, desired_ip_count=0, now=1.0)
        peer_enforcement.write_status(path, status)
        assert _read(path)["state"] == "rpc_unavailable"

    def test_bad_state_rejected(self):
        with pytest.raises(peer_enforcement.EnforcementError):
            peer_enforcement.build_status(
                state="on", aria_session_id="s", desired_hash="h",
                applied_revision=1, desired_ip_count=1, now=1.0)


class TestNonsecretError:
    def test_last_error_is_short_string(self, path):
        status = peer_enforcement.build_status(
            state="degraded", aria_session_id="s", desired_hash="h",
            applied_revision=1, desired_ip_count=1, now=1.0,
            last_error="rpc_timeout")
        peer_enforcement.write_status(path, status)
        assert _read(path)["last_error"] == "rpc_timeout"

    def test_conflicts_default_empty(self):
        status = peer_enforcement.build_status(
            state="enforced", aria_session_id="s", desired_hash="h",
            applied_revision=1, desired_ip_count=0, now=1.0)
        assert status["conflicts"] == []
        assert status["last_effect"] is None


class TestGuiReader:
    def test_read_status_roundtrip(self, path):
        status = peer_enforcement.build_status(
            state="enforced", aria_session_id="s", desired_hash="h",
            applied_revision=1, desired_ip_count=0, now=1.0,
            last_operation_exported_revision=5)
        peer_enforcement.write_status(path, status)
        got = peer_enforcement.read_status(path)
        assert got["state"] == "enforced"
        assert got["last_operation_exported_revision"] == 5

    def test_read_missing_returns_none(self, path):
        assert peer_enforcement.read_status(path) is None

    def test_read_corrupt_returns_none(self, path):
        with open(path, "w") as f:
            f.write("{ not json")
        assert peer_enforcement.read_status(path) is None
