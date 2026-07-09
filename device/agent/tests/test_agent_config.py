# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import agent_config


def test_loads_keys_and_strips(tmp_path):
    p = tmp_path / "cat-agent.conf"
    p.write_text(
        "# iris agent config\n"
        "catalog_url = https://100.90.168.20:8443\n"
        "catalog_token =  deadbeef  \n"
        "device_id = 100.92.9.3\n"
        "\n"
        "stage_dir = /flash/guest-share/iris\n")
    cfg = agent_config.load(str(p))
    assert cfg["catalog_url"] == "https://100.90.168.20:8443"
    assert cfg["catalog_token"] == "deadbeef"
    assert cfg["device_id"] == "100.92.9.3"
    assert cfg["stage_dir"] == "/flash/guest-share/iris"


def test_missing_required_key_raises(tmp_path):
    import pytest
    p = tmp_path / "c.conf"
    p.write_text("catalog_url = https://x\n")   # no token / device_id
    with pytest.raises(KeyError):
        agent_config.load(str(p))


def test_catalog_ca_defaults_empty_when_absent(tmp_path):
    # An old config with no catalog_ca still loads; the key defaults to "" (falsy),
    # which the agent treats as "TLS not pinned" (verify-if-present off). Required
    # keys + concrete IP stay green.
    p = tmp_path / "agent.conf"
    p.write_text(
        "catalog_url = https://100.90.168.20:8443\n"
        "catalog_token = deadbeef\n"
        "device_id = 100.92.9.3\n")
    cfg = agent_config.load(str(p))
    assert cfg["catalog_ca"] == ""
    assert cfg["catalog_url"] == "https://100.90.168.20:8443"
    assert cfg["device_id"] == "100.92.9.3"


def test_catalog_ca_parsed_when_present(tmp_path):
    p = tmp_path / "agent.conf"
    p.write_text(
        "catalog_url = https://100.90.168.20:8443\n"
        "catalog_token = deadbeef\n"
        "device_id = 100.92.9.3\n"
        "catalog_ca = /flash/guest-share/iris/iris-catalog.pem\n")
    cfg = agent_config.load(str(p))
    assert cfg["catalog_ca"] == "/flash/guest-share/iris/iris-catalog.pem"


def test_token_expires_at_defaults_to_zero_when_absent(tmp_path):
    # An enrolled-but-never-refreshed device has no token_expires_at line; the
    # key defaults to "0" (epoch unknown -> agent refreshes on next tick).
    p = tmp_path / "agent.conf"
    p.write_text(
        "catalog_url = https://100.90.168.20:8443\n"
        "catalog_token = deadbeef\n"
        "device_id = 100.92.9.3\n")
    cfg = agent_config.load(str(p))
    assert cfg["token_expires_at"] == "0"


def test_token_expires_at_parsed_when_present(tmp_path):
    p = tmp_path / "agent.conf"
    p.write_text(
        "catalog_url = https://100.90.168.20:8443\n"
        "catalog_token = deadbeef\n"
        "device_id = 100.92.9.3\n"
        "token_expires_at = 1750000000\n")
    cfg = agent_config.load(str(p))
    assert cfg["token_expires_at"] == "1750000000"


def test_write_conf_round_trips_through_load(tmp_path):
    # write_conf emits key = value lines that load() reads back unchanged.
    # Include all DEFAULTS keys to confirm none are silently dropped on round-trip.
    p = tmp_path / "iris-agent.conf"
    cfg = {
        "catalog_url": "https://100.90.168.20:8443",
        "catalog_token": "newtok",
        "device_id": "100.92.9.3",
        "token_expires_at": "1750000000",
        "rpc_secret": "rpcsecret",
        "stage_dir": "/flash/guest-share/iris",
        "catalog_ca": "/flash/guest-share/iris/iris-catalog.pem",
        "max_peers": "20",
    }
    agent_config.write_conf(str(p), cfg)
    back = agent_config.load(str(p))
    assert back["catalog_token"] == "newtok"
    assert back["token_expires_at"] == "1750000000"
    assert back["rpc_secret"] == "rpcsecret"
    assert back["device_id"] == "100.92.9.3"
    assert back["catalog_ca"] == "/flash/guest-share/iris/iris-catalog.pem"
    assert back["max_peers"] == "20"


def test_write_conf_is_atomic_no_tmp_left_behind(tmp_path):
    # write_conf must write via a tmp file + os.replace and leave no .tmp residue.
    p = tmp_path / "iris-agent.conf"
    agent_config.write_conf(str(p), {
        "catalog_url": "https://x", "catalog_token": "t", "device_id": "d"})
    names = [f.name for f in tmp_path.iterdir()]
    assert names == ["iris-agent.conf"]


def test_write_conf_overwrites_existing(tmp_path):
    p = tmp_path / "iris-agent.conf"
    p.write_text(
        "catalog_url = https://x\ncatalog_token = OLD\ndevice_id = d\n")
    agent_config.write_conf(str(p), {
        "catalog_url": "https://x", "catalog_token": "NEW", "device_id": "d"})
    assert agent_config.load(str(p))["catalog_token"] == "NEW"
