# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import shutil
import time

import pytest

import bencode
import bulkhash
import catalog
import publish
import secrets_store


@pytest.mark.skipif(shutil.which("mktorrent") is None,
                    reason="mktorrent not installed")
def test_publish_end_to_end(tmp_path):
    img = tmp_path / "cat9k_iosxe.26.01.01.SPA.bin"
    img.write_bytes(b"fake image payload" * 1000)
    store = catalog.CatalogStore(str(tmp_path / "state"))

    captured = {}

    def fake_seeder(torrent_bytes, image_dir):
        captured["bytes"] = torrent_bytes
        captured["dir"] = image_dir

    entry = publish.publish(
        str(img), store,
        tracker_url="https://10.0.0.5:6969/announce",
        image_id=None, signature_verified=False, seeder=fake_seeder)

    # id derived from filename (strip .SPA.bin)
    assert entry["id"] == "cat9k_iosxe.26.01.01"
    # sha256 correct
    assert entry["sha256"] == hashlib.sha256(img.read_bytes()).hexdigest()
    # info_hash matches sha1 of the torrent's info dict
    torrent_path = store.torrent_path(entry["id"])
    meta = bencode.decode(open(torrent_path, "rb").read())
    assert entry["info_hash_hex"] == \
        hashlib.sha1(bencode.encode(meta[b"info"])).hexdigest()
    # catalog persisted + seeder invoked with the image's dir
    assert store.get_image("cat9k_iosxe.26.01.01") is not None
    assert captured["dir"] == str(tmp_path)


@pytest.mark.skipif(shutil.which("mktorrent") is None,
                    reason="mktorrent not installed")
def test_signature_verified_writes_operator_field_not_the_reconcilers(tmp_path):
    """#88: `iris-publish --signature-verified` used to write
    cisco_signature_verified -- the SAME field the Cisco Bulk Hash
    reconciler owns (catalog.apply_hash_verification) -- so the operator's
    attestation was silently overwritten by the very next reconciler run.
    The operator's mark now lands on its own field, untouched by the
    reconciler, and the reconciler's field is untouched by publish()."""
    img = tmp_path / "cat9k_iosxe.26.01.01.SPA.bin"
    img.write_bytes(b"fake image payload" * 1000)
    store = catalog.CatalogStore(str(tmp_path / "state"))

    entry = publish.publish(
        str(img), store,
        tracker_url="https://10.0.0.5:6969/announce",
        image_id=None, signature_verified=True,
        seeder=lambda torrent_bytes, image_dir: None)

    # the operator's own attestation
    assert entry["operator_attested_signature"] is True
    # publish() never writes the reconciler's field at all
    assert "cisco_signature_verified" not in entry

    # The reconciler's first run (a mismatch, so it would previously have
    # flipped the shared field to False) must not touch the operator's mark.
    store.apply_hash_verification(
        {entry["id"]: {"state": bulkhash.STATE_MISMATCH,
                       "feed_sha512": "bb" * 64,
                       "publish_date": "2026-08-01", "deferral": False}},
        source="scheduled", now=1000)
    after = store.get_image(entry["id"])
    assert after["operator_attested_signature"] is True, \
        "the reconciler must never overwrite the operator's attestation"
    assert after["cisco_signature_verified"] is False
    assert after["hash_verification"]["state"] == "mismatch"


@pytest.mark.skipif(shutil.which("mktorrent") is None,
                    reason="mktorrent not installed")
def test_publish_without_signature_verified_flag_leaves_attestation_false(tmp_path):
    img = tmp_path / "cat9k_iosxe.26.01.01.SPA.bin"
    img.write_bytes(b"fake image payload" * 1000)
    store = catalog.CatalogStore(str(tmp_path / "state"))
    entry = publish.publish(
        str(img), store,
        tracker_url="https://10.0.0.5:6969/announce",
        image_id=None, signature_verified=False,
        seeder=lambda torrent_bytes, image_dir: None)
    assert entry["operator_attested_signature"] is False
    assert "cisco_signature_verified" not in entry


def test_derive_id_strips_known_suffixes():
    assert publish.derive_id("cat9k_iosxe.26.01.01.SPA.bin") == "cat9k_iosxe.26.01.01"
    assert publish.derive_id("C9800-SW-iosxe-wlc.26.01.01.SPA.bin") == \
        "C9800-SW-iosxe-wlc.26.01.01"
    assert publish.derive_id("plain.bin") == "plain"


def test_default_tracker_url_from_secrets_store(tmp_path, monkeypatch):
    # The secrets-broker store supplies the seeder's Authorization header; its
    # credential must never be embedded in the canonical torrent URL.
    store = {"devices": {}, "seeder": {}}
    secrets_store.mint(store, "seeder", "announce_token", int(time.time()))
    tok = store["seeder"]["announce_token"]["value"]
    sec = tmp_path / "secrets.json"
    secrets_store.save(store, str(sec))
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.5")
    monkeypatch.setenv("IRIS_SECRETS", str(sec))
    monkeypatch.setenv("IRIS_TOKENS", str(tmp_path / "no-such-tokens.txt"))
    assert publish.default_tracker_url() == "https://10.0.0.5:6969/announce"
    assert publish.default_announce_header() == "Authorization: Bearer %s" % tok


def test_default_tracker_url_does_not_embed_legacy_tokens(tmp_path, monkeypatch):
    # A legacy tokens.txt must not put a credential back into torrent metadata.
    toks = tmp_path / "tokens.txt"
    toks.write_text("# header comment\nLEGACYSEEDTOK\n")
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.5")
    monkeypatch.setenv("IRIS_SECRETS", str(tmp_path / "absent.json"))
    monkeypatch.setenv("IRIS_TOKENS", str(toks))
    assert publish.default_tracker_url() == "https://10.0.0.5:6969/announce"
    assert publish.default_announce_header() is None


@pytest.mark.parametrize("value", [
    "private-token\nX-Injected: yes", "private-token\rX-Injected: yes",
    "private-token\tmore", "private-token more", "private-token\x00",
    "private-token\x7f", "private-token\u00e9", "private-token\ud800",
    "", None, 12, ["private-token"], {"value": "private-token"},
])
def test_seeder_rpc_rejects_unsafe_persisted_announce_token(
        tmp_path, monkeypatch, capsys, value):
    sec = tmp_path / "secrets.json"
    secrets_store.save({"devices": {}, "seeder": {
        "announce_token": {"value": value}}}, str(sec))
    monkeypatch.setenv("IRIS_SECRETS", str(sec))
    calls = []
    monkeypatch.setattr(publish, "_rpc_call", lambda *a, **kw: calls.append(a))

    assert publish.default_announce_header() is None
    with pytest.raises(RuntimeError) as error:
        publish.add_torrent_rpc(b"torrent", str(tmp_path),
                                rpc_url="http://127.0.0.1:6800/jsonrpc",
                                rpc_secret="test-rpc")
    assert str(error.value) == "seeder announce credential unavailable"
    assert calls == []
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_seeder_rpc_preserves_safe_printable_announce_token(tmp_path, monkeypatch):
    value = "test-Token_0123.~+/=:!"
    sec = tmp_path / "secrets.json"
    secrets_store.save({"devices": {}, "seeder": {
        "announce_token": {"value": value}}}, str(sec))
    monkeypatch.setenv("IRIS_SECRETS", str(sec))
    calls = []
    monkeypatch.setattr(publish, "_rpc_call", lambda *a, **kw: calls.append(a))

    publish.add_torrent_rpc(b"torrent", str(tmp_path),
                            rpc_url="http://127.0.0.1:6800/jsonrpc",
                            rpc_secret="test-rpc")
    assert len(calls) == 1
    assert calls[0][2] == "aria2.addTorrent"
    assert calls[0][3][2]["header"] == ["Authorization: Bearer " + value]


def test_default_tracker_url_fails_closed_without_host_ip(monkeypatch):
    monkeypatch.delenv("IRIS_HOST_IP", raising=False)
    monkeypatch.delenv("IRIS_TRACKER_ANNOUNCE", raising=False)
    with pytest.raises(ValueError, match="unavailable"):
        publish.default_tracker_url()


@pytest.mark.parametrize("url", [
    "http://10.0.0.5:6969/announce",
    "https://10.0.0.5:6969/announce?announce_token=secret",
])
def test_make_torrent_rejects_plaintext_or_credential_bearing_url(
        tmp_path, url):
    image = tmp_path / "image.bin"
    image.write_bytes(b"payload")
    with pytest.raises(ValueError, match="invalid tracker announce URL"):
        publish.make_torrent(str(image), url, str(tmp_path / "image.torrent"))
    assert not (tmp_path / "image.torrent").exists()


@pytest.mark.skipif(shutil.which("mktorrent") is None,
                    reason="mktorrent not installed")
def test_publish_seeder_failure_does_not_commit_catalog(tmp_path):
    """If the seeder add fails, publish must NOT persist the catalog entry."""
    img = tmp_path / "cat9k_iosxe.26.01.01.SPA.bin"
    img.write_bytes(b"fake image" * 1000)
    store = catalog.CatalogStore(str(tmp_path / "state"))

    def failing_seeder(torrent_bytes, image_dir):
        raise RuntimeError("aria2 RPC unreachable")

    with pytest.raises(RuntimeError, match="aria2 RPC unreachable"):
        publish.publish(
            str(img), store,
            tracker_url="https://10.0.0.5:6969/announce",
            image_id=None, signature_verified=False, seeder=failing_seeder)

    # The catalog must NOT contain the entry — no advertised-but-unseeded window.
    assert store.get_image("cat9k_iosxe.26.01.01") is None


@pytest.mark.skipif(shutil.which("mktorrent") is None,
                    reason="mktorrent not installed")
def test_publish_seeder_called_before_catalog_commit(tmp_path):
    """Seeder is invoked (and succeeds) before the catalog entry is persisted."""
    img = tmp_path / "cat9k_iosxe.26.01.01.SPA.bin"
    img.write_bytes(b"fake image" * 1000)
    store = catalog.CatalogStore(str(tmp_path / "state"))

    call_order = []

    original_save = store.save_image

    def tracking_save(entry):
        call_order.append("catalog")
        original_save(entry)

    store.save_image = tracking_save

    def tracking_seeder(torrent_bytes, image_dir):
        call_order.append("seeder")

    publish.publish(
        str(img), store,
        tracker_url="https://10.0.0.5:6969/announce",
        image_id=None, signature_verified=False, seeder=tracking_seeder)

    assert call_order == ["seeder", "catalog"], (
        "seeder must be called before catalog.save_image; got %s" % call_order)


def test_default_rpc_secret_env_wins(monkeypatch):
    monkeypatch.setenv("IRIS_RPC_SECRET", "ENVSECRET")
    assert publish.default_rpc_secret() == "ENVSECRET"


def test_default_rpc_secret_explicit_file(tmp_path, monkeypatch):
    f = tmp_path / "rpc-secret"
    f.write_text("FILESECRET\n")
    monkeypatch.delenv("IRIS_RPC_SECRET", raising=False)
    monkeypatch.setenv("IRIS_RPC_SECRET_FILE", str(f))
    assert publish.default_rpc_secret() == "FILESECRET"


def test_default_rpc_secret_missing_returns_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("IRIS_RPC_SECRET", raising=False)
    monkeypatch.setenv("IRIS_RPC_SECRET_FILE", str(tmp_path / "absent"))
    assert publish.default_rpc_secret() == ""


# ---------------------------------------------------------------------------
# Publisher keeps the CURRENT announce token in an HTTP header only.
# ---------------------------------------------------------------------------

def test_default_tracker_url_uses_current_never_previous(tmp_path, monkeypatch):
    """The canonical URL is token-free and the HTTP header carries only the
    current seeder credential, never a rotated-out previous value."""
    now = int(time.time())
    store = {"devices": {}, "seeder": {}}
    secrets_store.mint(store, "seeder", "announce_token", now)
    current = store["seeder"]["announce_token"]["value"]
    # Inject a rotated-out previous value that must NEVER appear in the URL.
    store["seeder"]["announce_token_previous"] = [{
        "value": "PREVIOUSVALUE", "created_at": now, "expires_at": 0,
        "revoked": False, "rotated_at": now, "record_id": "deadbeef"}]
    sec = tmp_path / "secrets.json"
    secrets_store.save(store, str(sec))
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.9")
    monkeypatch.setenv("IRIS_SECRETS", str(sec))
    monkeypatch.setenv("IRIS_TOKENS", str(tmp_path / "no-such-tokens.txt"))
    url = publish.default_tracker_url()
    assert url == "https://10.0.0.9:6969/announce"
    assert "PREVIOUSVALUE" not in url
    assert "key=" not in url
    header = publish.default_announce_header()
    assert header == "Authorization: Bearer %s" % current
    assert "PREVIOUSVALUE" not in header


# ---------------------------------------------------------------------------
# The announce URL carries the seeder's private-tracker token and mktorrent
# only takes it on argv. A failing mktorrent must never surface that argv --
# not in the exception, not in a traceback, not on the CLI's stderr.
# ---------------------------------------------------------------------------

_TOKEN = "deadbeefcafef00d" * 2
_TRACKER = "https://10.0.0.5:6969/announce"
_LEAKY_TRACKER = _TRACKER + "?announce_token=" + _TOKEN


def _stub_mktorrent(tmp_path, monkeypatch, rc=1):
    """Put a failing `mktorrent` first on PATH."""
    import os
    import stat
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    stub = bindir / "mktorrent"
    stub.write_text("#!/bin/sh\necho 'mktorrent: simulated failure' >&2\nexit %d\n" % rc)
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    return stub


def test_mktorrent_failure_never_exposes_the_announce_token(tmp_path, monkeypatch):
    import os
    import traceback
    _stub_mktorrent(tmp_path, monkeypatch)
    img = tmp_path / "cat9k_iosxe.26.01.01.SPA.bin"
    img.write_bytes(b"fake image" * 100)
    store = catalog.CatalogStore(str(tmp_path / "state"))
    with pytest.raises(RuntimeError) as info:
        publish.publish(str(img), store, _TRACKER, seeder=lambda b, d: None)
    rendered = "".join(traceback.format_exception(info.value))
    assert _TOKEN not in str(info.value)
    assert _TOKEN not in rendered, "chained context would print mktorrent's argv"
    assert "mktorrent exited 1" in str(info.value)
    # nothing half-written is left for the startup re-seed to find
    assert not os.path.exists(store.torrent_path("cat9k_iosxe.26.01.01"))
    assert store.get_image("cat9k_iosxe.26.01.01") is None


def test_cli_publish_failure_prints_no_token_and_no_traceback(tmp_path, monkeypatch,
                                                              capsys):
    _stub_mktorrent(tmp_path, monkeypatch)
    img = tmp_path / "cat9k_iosxe.26.01.01.SPA.bin"
    img.write_bytes(b"fake image" * 100)
    rc = publish.main([str(img), "--state", str(tmp_path / "state"),
                       "--tracker-url", _TRACKER])
    out = capsys.readouterr()
    assert rc == 1
    assert _TOKEN not in out.err + out.out
    assert "Traceback" not in out.err + out.out
    assert "publish failed" in out.err


def test_redact_strips_announce_credentials_and_known_secrets():
    argv_text = ("Command '['mktorrent', '-p', '-a', '%s', '-o', 'x.torrent']' "
                 "returned non-zero exit status 1." % _LEAKY_TRACKER)
    assert _TOKEN not in publish.redact(argv_text)
    assert _TOKEN not in publish.redact(argv_text, _LEAKY_TRACKER)
    assert "announce_token=<redacted>" in publish.redact(argv_text)
    assert publish.redact("legacy ?key=abc&x=1") == "legacy ?key=<redacted>&x=1"
    assert publish.redact("plain error text") == "plain error text"
    assert publish.redact(None) == ""


@pytest.mark.skipif(shutil.which("mktorrent") is None,
                    reason="mktorrent not installed")
def test_publish_failure_after_mktorrent_rolls_back_the_torrent_file(tmp_path):
    """A .torrent with no catalog row is exactly what the startup re-seed must
    never find: roll it back when the seeder add (or the catalog write) fails."""
    import os
    img = tmp_path / "cat9k_iosxe.26.01.01.SPA.bin"
    img.write_bytes(b"fake image" * 1000)
    store = catalog.CatalogStore(str(tmp_path / "state"))

    def failing_seeder(torrent_bytes, image_dir):
        raise RuntimeError("aria2 RPC unreachable")

    with pytest.raises(RuntimeError, match="aria2 RPC unreachable"):
        publish.publish(str(img), store, "https://10.0.0.5:6969/announce",
                        seeder=failing_seeder)
    assert not os.path.exists(store.torrent_path("cat9k_iosxe.26.01.01"))

    def failing_save(entry):
        raise OSError("state volume full")

    store.save_image = failing_save
    with pytest.raises(OSError, match="state volume full"):
        publish.publish(str(img), store, "https://10.0.0.5:6969/announce",
                        seeder=lambda b, d: None)
    assert not os.path.exists(store.torrent_path("cat9k_iosxe.26.01.01"))


# ---------------------------------------------------------------------------
# The canonical announce base must be derived the way the tracker listens and
# the catalog personalizes, or the origin seeder announces to the wrong port.
# ---------------------------------------------------------------------------

def _secrets_with_seeder_token(tmp_path, monkeypatch):
    store = {"devices": {}, "seeder": {}}
    secrets_store.mint(store, "seeder", "announce_token", int(time.time()))
    sec = tmp_path / "secrets.json"
    secrets_store.save(store, str(sec))
    monkeypatch.setenv("IRIS_SECRETS", str(sec))
    monkeypatch.setenv("IRIS_TOKENS", str(tmp_path / "no-such-tokens.txt"))
    return store["seeder"]["announce_token"]["value"]


def test_default_tracker_url_honours_tracker_port(tmp_path, monkeypatch):
    tok = _secrets_with_seeder_token(tmp_path, monkeypatch)
    monkeypatch.setenv("IRIS_HOST_IP", "10.0.0.5")
    monkeypatch.setenv("IRIS_TRACKER_PORT", "7070")
    monkeypatch.delenv("IRIS_TRACKER_ANNOUNCE", raising=False)
    assert publish.default_tracker_url() == "https://10.0.0.5:7070/announce"
    assert publish.default_announce_header() == "Authorization: Bearer %s" % tok


def test_default_tracker_url_honours_tracker_announce_override(tmp_path, monkeypatch):
    tok = _secrets_with_seeder_token(tmp_path, monkeypatch)
    monkeypatch.delenv("IRIS_HOST_IP", raising=False)
    monkeypatch.setenv("IRIS_TRACKER_ANNOUNCE", "https://10.9.8.7:6969/announce")
    assert publish.default_tracker_url() == "https://10.9.8.7:6969/announce"
    assert publish.default_announce_header() == "Authorization: Bearer %s" % tok


# ---------------------------------------------------------------------------
# resume_torrent_rpc: the release path's inverse of the quarantine's
# force-remove -- re-sync the canonical announce to the CURRENT credential,
# never hand aria2 a duplicate info hash.
# ---------------------------------------------------------------------------

def _canonical(tmp_path, announce=b"http://10.0.0.5:6969/announce?announce_token=old"):
    info = bencode.encode({b"name": b"img.bin", b"piece length": 16384,
                           b"pieces": b"\0" * 20, b"length": 1})
    data = (b"d8:announce%d:%s4:info" % (len(announce), announce)) + info + b"e"
    path = tmp_path / "img.torrent"
    path.write_bytes(data)
    return path, hashlib.sha1(info).hexdigest()


def test_resume_torrent_rpc_resyncs_announce_and_adds_when_inactive(tmp_path, monkeypatch):
    path, info_hash = _canonical(tmp_path)
    calls = []

    def fake_rpc(rpc_url, rpc_secret, method, params, call_id="pub"):
        calls.append((method, params))
        if method == "aria2.tellActive":
            return []
        if method == "aria2.addTorrent":
            return "gid-new"
        raise AssertionError(method)

    monkeypatch.setattr(publish, "_rpc_call", fake_rpc)
    monkeypatch.setattr(
        publish, "default_announce_header",
        lambda: "Authorization: Bearer current-seeder-token")
    gid = publish.resume_torrent_rpc(str(path), str(tmp_path), info_hash,
                                     tracker_url="https://10.0.0.5:6969/announce",
                                     rpc_url="http://x",
                                     rpc_secret="s")
    assert gid == "gid-new"
    assert [m for m, _ in calls] == ["aria2.tellActive", "aria2.addTorrent"]
    # The canonical file is token-free and keeps its info hash intact.
    data = path.read_bytes()
    assert bencode.decode(data)[b"announce"] == \
        b"https://10.0.0.5:6969/announce"
    assert publish.torrent_info_hash(str(path)) == info_hash
    # and that is what the seeder was handed, from the image's own directory
    import base64
    add_params = calls[1][1]
    assert base64.b64decode(add_params[0]) == data
    assert add_params[2]["dir"] == str(tmp_path)
    assert add_params[2]["header"] == [
        "Authorization: Bearer current-seeder-token"]


def test_resume_torrent_rpc_leaves_an_active_torrent_alone(tmp_path, monkeypatch):
    path, info_hash = _canonical(tmp_path)
    calls = []

    def fake_rpc(rpc_url, rpc_secret, method, params, call_id="pub"):
        calls.append(method)
        if method == "aria2.tellActive":
            return [{"gid": "g1", "infoHash": info_hash.upper()}]
        raise AssertionError(method)

    monkeypatch.setattr(publish, "_rpc_call", fake_rpc)
    assert publish.resume_torrent_rpc(str(path), str(tmp_path), info_hash,
                                      tracker_url=_TRACKER, rpc_url="http://x",
                                      rpc_secret="s") is None
    assert calls == ["aria2.tellActive"]


def test_resume_torrent_rpc_without_a_known_tracker_fails_closed(tmp_path, monkeypatch):
    path, info_hash = _canonical(tmp_path)
    before = path.read_bytes()
    monkeypatch.delenv("IRIS_HOST_IP", raising=False)
    monkeypatch.delenv("IRIS_TRACKER_ANNOUNCE", raising=False)
    monkeypatch.setattr(publish, "_rpc_call",
                        lambda *a, **k: [] if a[2] == "aria2.tellActive" else "g")
    monkeypatch.setattr(
        publish, "default_announce_header",
        lambda: "Authorization: Bearer current-seeder-token")
    with pytest.raises(ValueError, match="unavailable"):
        publish.resume_torrent_rpc(str(path), str(tmp_path), None,
                                   rpc_url="http://x", rpc_secret="s")
    assert path.read_bytes() == before
