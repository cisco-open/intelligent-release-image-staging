# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import pytest

import tracker_announce


def test_resolve_derives_https_url_with_default_or_configured_port():
    assert tracker_announce.resolve({"IRIS_HOST_IP": "100.64.0.1"}) == \
        "https://100.64.0.1:6969/announce"
    assert tracker_announce.resolve({
        "IRIS_HOST_IP": "10.1.2.3",
        "IRIS_TRACKER_PORT": "7443",
    }) == "https://10.1.2.3:7443/announce"


def test_configured_url_takes_precedence_and_normalizes_empty_path():
    env = {
        "IRIS_TRACKER_ANNOUNCE": "https://8.8.8.8:7443",
        "IRIS_HOST_IP": "10.1.2.3",
        "IRIS_TRACKER_PORT": "6969",
    }
    assert tracker_announce.resolve(env) == \
        "https://8.8.8.8:7443/announce"


def test_empty_configured_url_falls_back_to_host_and_default_port():
    assert tracker_announce.resolve({
        "IRIS_TRACKER_ANNOUNCE": "",
        "IRIS_HOST_IP": "192.168.5.4",
        "IRIS_TRACKER_PORT": "",
    }) == "https://192.168.5.4:6969/announce"


def test_resolve_uses_process_environment(monkeypatch):
    monkeypatch.setenv("IRIS_TRACKER_ANNOUNCE", "https://8.8.4.4/announce")
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.1")
    assert tracker_announce.resolve() == "https://8.8.4.4/announce"


@pytest.mark.parametrize("host", [
    "100.64.0.1",       # RFC 6598 shared address space
    "10.1.2.3",         # private address space
    "192.168.5.4",      # private address space
    "203.0.113.9",      # routed documentation prefix
    "8.8.8.8",          # public address space
])
def test_validate_accepts_same_routable_ipv4_classes_as_rotation(host):
    url = "https://%s:6969/announce" % host
    assert tracker_announce.validate(url) == url


@pytest.mark.parametrize("host", [
    "127.0.0.1",
    "169.254.1.1",
    "0.0.0.0",
    "224.0.0.1",
    "240.0.0.1",
    "::1",
    "tracker.example.com",
])
def test_validate_refuses_nonusable_or_nonnumeric_hosts(host):
    if ":" in host:
        host = "[%s]" % host
    with pytest.raises(ValueError, match="^invalid tracker announce URL$"):
        tracker_announce.validate("https://%s:6969/announce" % host)


@pytest.mark.parametrize("url", [
    "http://8.8.8.8:6969/announce",
    "ftp://8.8.8.8:6969/announce",
    "//8.8.8.8:6969/announce",
    "https://user@8.8.8.8:6969/announce",
    "https://user:password@8.8.8.8:6969/announce",
    "https://8.8.8.8:6969/announce?token=value",
    "https://8.8.8.8:6969/announce?",
    "https://8.8.8.8:6969/announce#fragment",
    "https://8.8.8.8:6969/announce#",
    "https://8.8.8.8:6969/other",
    "https://8.8.8.8:6969/announce/",
    " https://8.8.8.8:6969/announce",
    "https://8.8.8.8:6969/announce\n",
])
def test_validate_requires_token_free_https_announce_endpoint(url):
    with pytest.raises(ValueError, match="^invalid tracker announce URL$"):
        tracker_announce.validate(url)


@pytest.mark.parametrize("port", ["", "0", "65536", "abc", "-1", "٦٩٦٩"])
def test_validate_refuses_invalid_explicit_ports(port):
    with pytest.raises(ValueError, match="^invalid tracker announce URL$"):
        tracker_announce.validate(
            "https://8.8.8.8:%s/announce" % port)


def test_validate_normalizes_numeric_port_and_empty_path():
    assert tracker_announce.validate("https://8.8.8.8:06969") == \
        "https://8.8.8.8:6969/announce"


def test_resolve_requires_a_configured_url_or_host():
    with pytest.raises(ValueError, match="^tracker announce URL unavailable$"):
        tracker_announce.resolve({})


def test_validation_errors_never_echo_misconfigured_credentials():
    secret = "do-not-echo-this-value"
    url = "https://operator:%s@8.8.8.8/announce?token=%s" % (
        secret, secret)
    with pytest.raises(ValueError) as error:
        tracker_announce.validate(url)
    assert secret not in str(error.value)
    assert url not in str(error.value)
