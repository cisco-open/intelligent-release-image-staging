# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import stat

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


def test_catalog_ca_absent_from_conf_stays_absent_after_load(tmp_path):
    # SECURITY: catalog_ca is deliberately NOT in DEFAULTS. A conf that omits
    # it must load with the key still absent -- never backfilled to "" -- or
    # make_catalog_context's fail-closed check can't tell "operator genuinely
    # never configured this" apart from "the backfill invented an empty
    # string", and (worse) an invented "" would get re-persisted to disk by
    # the very next write_conf() round-trip (e.g. any reconcile_conf_key call
    # in an entrypoint), permanently baking the omission into the file.
    # Required keys + concrete IP stay green.
    p = tmp_path / "agent.conf"
    p.write_text(
        "catalog_url = https://100.90.168.20:8443\n"
        "catalog_token = deadbeef\n"
        "device_id = 100.92.9.3\n")
    cfg = agent_config.load(str(p))
    assert "catalog_ca" not in cfg
    assert cfg.get("catalog_ca") is None
    assert cfg["catalog_url"] == "https://100.90.168.20:8443"
    assert cfg["device_id"] == "100.92.9.3"


def test_catalog_ca_omission_survives_a_write_conf_round_trip(tmp_path):
    # Reproduces the entrypoint.sh reconcile_conf_key pattern that used to
    # persist the invented "": load() a dropped conf that omits catalog_ca,
    # touch an unrelated key, write_conf() the whole cfg back. catalog_ca
    # must never appear on disk afterward.
    p = tmp_path / "agent.conf"
    p.write_text(
        "catalog_url = https://100.90.168.20:8443\n"
        "catalog_token = deadbeef\n"
        "device_id = 100.92.9.3\n")
    cfg = agent_config.load(str(p))
    cfg["agent_version"] = "2026.08.29"
    agent_config.write_conf(str(p), cfg)
    assert "catalog_ca" not in p.read_text()
    reloaded = agent_config.load(str(p))
    assert "catalog_ca" not in reloaded


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


def test_target_fs_defaults_to_auto_detection(tmp_path):
    p = tmp_path / "agent.conf"
    p.write_text(
        "catalog_url = https://x\ncatalog_token = t\ndevice_id = d\n")
    assert agent_config.load(str(p))["target_fs"] == ""


def test_target_fs_accepts_ios_prefix_and_rejects_paths(tmp_path):
    import pytest

    p = tmp_path / "agent.conf"
    p.write_text(
        "catalog_url = https://x\ncatalog_token = t\ndevice_id = d\n"
        "target_fs = sdflash:\n")
    assert agent_config.load(str(p))["target_fs"] == "sdflash:"
    p.write_text(
        "catalog_url = https://x\ncatalog_token = t\ndevice_id = d\n"
        "target_fs = /data/images\n")
    with pytest.raises(ValueError, match="invalid target_fs"):
        agent_config.load(str(p))


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


def test_write_conf_restricts_secret_bearing_file_to_owner(tmp_path):
    p = tmp_path / "iris-agent.conf"
    agent_config.write_conf(str(p), {
        "catalog_url": "https://x", "catalog_token": "secret", "device_id": "d"})
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_write_conf_does_not_persist_backfilled_defaults(tmp_path):
    # IRIS-10-007: load() backfills DEFAULTS into the dict it returns; writing
    # that dict back froze the agent's defaults into every device conf on its
    # first token refresh, so a later release that changes a default never
    # reached a deployed device. Keys the file never had, still at their
    # default value, stay out of the file.
    p = tmp_path / "iris-agent.conf"
    p.write_text(
        "catalog_url = https://x\ncatalog_token = t\ndevice_id = d\n"
        "token_expires_at = 0\n")
    cfg = agent_config.load(str(p))
    assert cfg["max_peers"] == "10"                 # backfilled in memory...
    cfg["catalog_token"] = "NEW"
    agent_config.write_conf(str(p), cfg)
    keys = sorted(agent_config._file_keys(str(p)))
    assert keys == ["catalog_token", "catalog_url", "device_id",
                    "token_expires_at"]              # ...but not on disk
    assert agent_config.load(str(p))["catalog_token"] == "NEW"


def test_write_conf_keeps_explicit_and_non_default_values(tmp_path):
    p = tmp_path / "iris-agent.conf"
    # max_peers explicitly set to the default value in the file: stays.
    p.write_text(
        "catalog_url = https://x\ncatalog_token = t\ndevice_id = d\n"
        "max_peers = 10\n")
    cfg = agent_config.load(str(p))
    cfg["telemetry_stream"] = "on"                  # differs from the default
    cfg["rpc_secret"] = ""                          # default, not in file
    cfg["catalog_ca"] = "/flash/iris-catalog.pem"   # outside DEFAULTS
    agent_config.write_conf(str(p), cfg)
    keys = agent_config._file_keys(str(p))
    assert "max_peers" in keys and "telemetry_stream" in keys
    assert "catalog_ca" in keys
    assert "rpc_secret" not in keys and "stage_dir" not in keys
    back = agent_config.load(str(p))
    assert back["telemetry_stream"] == "on" and back["max_peers"] == "10"
