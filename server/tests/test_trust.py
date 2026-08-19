# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Trust-store tests. Hermetic and offline: throwaway self-signed certs via
the openssl CLI (the test_artifact_server idiom) and local 127.0.0.1 TLS
servers only."""
import http.server
import os
import ssl
import subprocess
import threading
import urllib.error
import urllib.request

import pytest

import trust


def _throwaway_cert(dirpath, cn):
    """Self-signed cert with SAN=IP:127.0.0.1 (mirrors
    test_artifact_server._throwaway_cert). Returns (crt, key, combined)."""
    crt = os.path.join(str(dirpath), cn + "-crt.pem")
    key = os.path.join(str(dirpath), cn + "-key.pem")
    combined = os.path.join(str(dirpath), cn + "-cert.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "2", "-keyout", key, "-out", crt, "-subj", "/CN=" + cn,
         "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True)
    with open(combined, "w") as f:
        with open(crt) as c:
            f.write(c.read())
        with open(key) as k:
            f.write(k.read())
    return crt, key, combined


def _read(path):
    with open(path) as f:
        return f.read()


@pytest.fixture
def trust_env(tmp_path, monkeypatch):
    """Point the trust store and runtime bundle at per-test temp paths."""
    tdir = tmp_path / "trust"
    bundle = tmp_path / "run" / "ca-bundle.pem"
    monkeypatch.setenv("IRIS_TRUST_DIR", str(tdir))
    monkeypatch.setenv("IRIS_CA_BUNDLE", str(bundle))
    return str(tdir), str(bundle)


# --- split_pem_certs / cert_info -------------------------------------------

def test_env_paths_have_contract_defaults(monkeypatch):
    monkeypatch.delenv("IRIS_TRUST_DIR", raising=False)
    monkeypatch.delenv("IRIS_CA_BUNDLE", raising=False)
    assert trust.trust_dir() == "/etc/iris/tls/trust"
    assert trust.bundle_path() == "/run/iris/tls/ca-bundle.pem"
    assert trust.DOWNLOADED_BUNDLE == "downloaded-bundle.pem"


def test_split_pem_certs_extracts_normalized_blocks(tmp_path):
    crt_a, _, _ = _throwaway_cert(tmp_path, "splita")
    crt_b, _, _ = _throwaway_cert(tmp_path, "splitb")
    text = ("# junk before\n" + _read(crt_a) + "\nnoise between\r\n"
            + _read(crt_b).replace("\n", "\r\n") + "trailing junk")
    blocks = trust.split_pem_certs(text)
    assert len(blocks) == 2
    for blk in blocks:
        assert blk.startswith("-----BEGIN CERTIFICATE-----")
        assert blk.endswith("-----END CERTIFICATE-----")
        assert "\r" not in blk and "junk" not in blk


def test_split_pem_certs_no_certs():
    assert trust.split_pem_certs("") == []
    assert trust.split_pem_certs("hello world") == []
    # a lone header with no END is not a block
    assert trust.split_pem_certs("-----BEGIN CERTIFICATE-----\nAAAA") == []


def test_cert_info_real_cert_matches_openssl_fingerprint(tmp_path):
    crt, _, _ = _throwaway_cert(tmp_path, "infocase")
    block = trust.split_pem_certs(_read(crt))[0]
    info = trust.cert_info(block)
    assert set(info) == {"subject", "issuer", "not_after",
                         "fingerprint_sha256"}
    assert "infocase" in info["subject"]
    assert "infocase" in info["issuer"]          # self-signed
    assert info["not_after"] != "unknown"
    out = subprocess.run(
        ["openssl", "x509", "-noout", "-fingerprint", "-sha256",
         "-in", crt], check=True, capture_output=True).stdout.decode()
    expected = out.split("=", 1)[1].strip().replace(":", "").lower()
    assert info["fingerprint_sha256"] == expected
    assert len(info["fingerprint_sha256"]) == 64


def test_cert_info_garbage_falls_back_to_unknown():
    info = trust.cert_info("-----BEGIN CERTIFICATE-----\n!!!not-base64!!!\n"
                           "-----END CERTIFICATE-----")
    assert info == {"subject": "unknown", "issuer": "unknown",
                    "not_after": "unknown", "fingerprint_sha256": "unknown"}


# --- store operations + bundle rebuild --------------------------------------

def test_add_pem_writes_fingerprint_named_file_and_bundle(trust_env, tmp_path):
    tdir, bundle = trust_env
    crt, _, _ = _throwaway_cert(tmp_path, "addcase")
    entry = trust.add_pem(_read(crt))
    fp = entry["fingerprint_sha256"]
    assert len(fp) == 64 and entry["name"] == fp + ".pem"
    assert entry["source"] == "manual"
    assert entry["cert_count"] == 1
    assert "addcase" in entry["subject"]
    assert entry["not_after"] != "unknown"
    assert os.path.isfile(os.path.join(tdir, fp + ".pem"))
    assert _read(bundle).count("BEGIN CERTIFICATE") == 1


def test_add_pem_multi_cert_upload_stays_one_file(trust_env, tmp_path):
    tdir, bundle = trust_env
    crt_a, _, _ = _throwaway_cert(tmp_path, "chaina")
    crt_b, _, _ = _throwaway_cert(tmp_path, "chainb")
    entry = trust.add_pem(_read(crt_a) + _read(crt_b))
    assert entry["cert_count"] == 2
    # named by the FIRST cert's fingerprint; one file for the whole upload
    assert entry["name"] == trust.cert_info(
        trust.split_pem_certs(_read(crt_a))[0])["fingerprint_sha256"] + ".pem"
    assert sorted(os.listdir(tdir)) == [entry["name"]]
    assert _read(bundle).count("BEGIN CERTIFICATE") == 2


def test_add_pem_rejects_input_without_certs(trust_env):
    tdir, bundle = trust_env
    with pytest.raises(ValueError):
        trust.add_pem("this is not a pem")
    with pytest.raises(ValueError):
        trust.add_pem("-----BEGIN CERTIFICATE-----\n@@@@\n"
                      "-----END CERTIFICATE-----")   # undecodable body
    assert not os.path.exists(bundle)
    assert trust.list_entries() == []


def test_list_entries_marks_downloaded_source(trust_env, tmp_path):
    tdir, _ = trust_env
    crt_m, _, _ = _throwaway_cert(tmp_path, "manualone")
    trust.add_pem(_read(crt_m))
    crt_d, _, _ = _throwaway_cert(tmp_path, "downloadedone")
    with open(os.path.join(tdir, trust.DOWNLOADED_BUNDLE), "w") as f:
        f.write(_read(crt_d))
    entries = trust.list_entries()
    assert len(entries) == 2
    for e in entries:
        assert set(e) == {"name", "subject", "not_after",
                          "fingerprint_sha256", "cert_count", "source"}
    by_name = {e["name"]: e for e in entries}
    assert by_name[trust.DOWNLOADED_BUNDLE]["source"] == "downloaded"
    manual = [e for e in entries if e["name"] != trust.DOWNLOADED_BUNDLE]
    assert manual[0]["source"] == "manual"
    assert "manualone" in manual[0]["subject"]


def test_list_entries_empty_or_missing_dir(trust_env):
    assert trust.list_entries() == []      # dir does not even exist yet


def test_remove_deletes_file_and_empties_bundle(trust_env, tmp_path):
    tdir, bundle = trust_env
    crt, _, _ = _throwaway_cert(tmp_path, "gonecase")
    entry = trust.add_pem(_read(crt))
    assert os.path.isfile(bundle)
    assert trust.remove(entry["name"]) is True
    assert trust.list_entries() == []
    assert not os.path.exists(bundle)      # empty store removes the bundle


def test_remove_refuses_traversal_and_missing(trust_env, tmp_path):
    tdir, _ = trust_env
    crt, _, _ = _throwaway_cert(tmp_path, "keepcase")
    trust.add_pem(_read(crt))
    outside = os.path.join(str(tmp_path), "victim.pem")
    with open(outside, "w") as f:
        f.write("do not delete")
    assert trust.remove("../victim.pem") is False
    assert trust.remove("/etc/passwd") is False
    assert trust.remove("sub/dir.pem") is False
    assert trust.remove("") is False
    assert trust.remove("absent.pem") is False
    assert trust.remove("not-a-pem.txt") is False
    assert os.path.isfile(outside)
    assert len(trust.list_entries()) == 1  # store untouched


def test_remove_refuses_null_byte_in_name(trust_env):
    assert trust.remove("evil\x00.pem") is False


def test_rebuild_bundle_sorted_and_deterministic(trust_env, tmp_path):
    tdir, bundle = trust_env
    crt_a, _, _ = _throwaway_cert(tmp_path, "detera")
    crt_b, _, _ = _throwaway_cert(tmp_path, "deterb")
    trust.add_pem(_read(crt_a))
    trust.add_pem(_read(crt_b))
    first = _read(bundle)
    assert trust.rebuild_bundle() == 2     # returns total cert count
    assert _read(bundle) == first          # same inputs -> identical bytes


# --- ssl_context: mtime cache + end-to-end verification ---------------------

def _tls_server(combined, handler_cls):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(combined)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class _OkHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def test_ssl_context_is_mtime_cached(trust_env, tmp_path):
    c1 = trust.ssl_context()
    assert isinstance(c1, ssl.SSLContext)
    assert trust.ssl_context() is c1          # no bundle: cached object
    crt, _, _ = _throwaway_cert(tmp_path, "cachecase")
    trust.add_pem(_read(crt))                 # bundle appears -> new context
    c2 = trust.ssl_context()
    assert c2 is not c1
    assert trust.ssl_context() is c2          # cached again until next change
    trust.remove(trust.list_entries()[0]["name"])   # bundle removed
    assert trust.ssl_context() is not c2


def test_ssl_context_trusts_installed_ca_end_to_end(trust_env, tmp_path):
    crt, _, combined = _throwaway_cert(tmp_path, "e2ecase")
    srv = _tls_server(combined, _OkHandler)
    try:
        url = "https://127.0.0.1:%d/" % srv.server_address[1]
        # absent from the trust store: default roots reject the private CA
        with pytest.raises(urllib.error.URLError):
            urllib.request.urlopen(url, context=trust.ssl_context(),
                                   timeout=5)
        trust.add_pem(_read(crt))
        with urllib.request.urlopen(url, context=trust.ssl_context(),
                                    timeout=5) as r:
            assert r.status == 200 and r.read() == b"ok"
    finally:
        srv.shutdown()


def test_ssl_context_survives_corrupt_bundle(trust_env):
    tdir, bundle = trust_env
    os.makedirs(os.path.dirname(bundle), exist_ok=True)
    with open(bundle, "w") as f:
        f.write("-----BEGIN CERTIFICATE-----\ngarbage\n"
                "-----END CERTIFICATE-----\n")
    ctx = trust.ssl_context()                 # must not raise
    assert isinstance(ctx, ssl.SSLContext)
