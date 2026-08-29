# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for the pure Cisco Bulk Hash feed core (server/bulkhash.py):
``fetch`` (streaming download, hermetic via a local plain-HTTP server),
``verify_tar`` (the X.509 `openssl dgst -verify` signature check, against a
throwaway per-test RSA cert -- NEVER the real pinned Cisco certificate),
``parse`` (tar/CSV extraction with tar-hardening), and ``reconcile`` (pure
join + verdict derivation, no I/O). Fixture tars mirror the real feed's
shape confirmed by a live 2026-08-29 download: an outer gzip tar holding one
timestamped directory with ``<name>.csv`` and ``<name>.csv.signature``."""
import http.server
import io
import os
import subprocess
import tarfile
import threading

import pytest

import bulkhash

CSV_HEADER = "FILE_NAME,MD5_CHECKSUM,SHA512_CHECKSUM,PUBLISH_DATE,DEFERRAL_STATUS,IMAGE_SIZE"


# ---------------------------------------------------------------------------
# Throwaway signing cert + fixture-tar builders (never the real Cisco cert)
# ---------------------------------------------------------------------------

def _throwaway_keypair(dirpath, cn):
    """Self-signed RSA cert/key pair used ONLY to sign test fixtures (mirrors
    test_trust.py's _throwaway_cert). Returns (cert_path, key_path)."""
    key = os.path.join(str(dirpath), cn + "-key.pem")
    crt = os.path.join(str(dirpath), cn + "-crt.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-days", "2", "-keyout", key, "-out", crt, "-subj", "/CN=" + cn],
        check=True, capture_output=True)
    return crt, key


def _sign(key_path, data):
    proc = subprocess.run(
        ["openssl", "dgst", "-sha512", "-sign", key_path],
        input=data, capture_output=True, check=True)
    return proc.stdout


def _build_tar(tar_path, members):
    """`members`: list of (arcname, bytes) written into a gzip tar."""
    with tarfile.open(tar_path, mode="w:gz") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def _csv_bytes(rows_text):
    return (CSV_HEADER + "\r\n" + rows_text).encode("utf-8")


def _signed_fixture(tmp_path, csv_text, key_path,
                     csv_name="Cisco_BulkHash_CSV.csv",
                     dirprefix="Cisco_BulkHash_CSV.csv_2026.08.29.08.29.48",
                     tar_name="feed.tar"):
    """A realistic outer tar: <dirprefix>/<csv_name> plus its detached
    `.signature` sibling, signed with `key_path`. Returns the tar path."""
    tar_path = os.path.join(str(tmp_path), tar_name)
    csv_bytes = _csv_bytes(csv_text)
    sig_bytes = _sign(key_path, csv_bytes)
    _build_tar(tar_path, [
        (dirprefix + "/", b""),
        ("%s/%s" % (dirprefix, csv_name), csv_bytes),
        ("%s/%s.signature" % (dirprefix, csv_name), sig_bytes),
    ])
    return tar_path


@pytest.fixture
def signing_key(tmp_path):
    """The throwaway signer used by most verify_tar/parse fixtures. Returns
    (cert_path, key_path)."""
    return _throwaway_keypair(tmp_path, "bulkhash-test-signer")


REAL_ROW = (
    "isr4300-universalk9.16.03.01.SPA.bin,D949B99A104B23B2129718220C78F28E,"
    "2E0D49321F6ABBF416EE2AB021D9720E2B575F5715DA773F1DFD147A5B52EDFE34CFC8"
    "ABD746471756A3B2D6C8655BA1B9BC86B9EB7A04850F49D89EA92BF63B,"
    "August 03 2016 00:00:00 PDT-0700,,12345\r\n")


# ---------------------------------------------------------------------------
# fetch()
# ---------------------------------------------------------------------------

def _http_server(handler_cls):
    srv = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class TestFetch:
    def test_downloads_full_body_to_out_path(self, tmp_path):
        payload = b"hello bulk hash tar" * 1000

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        srv = _http_server(Handler)
        try:
            out_path = os.path.join(str(tmp_path), "out.tar")
            url = "http://127.0.0.1:%d/feed.tar" % srv.server_address[1]
            result = bulkhash.fetch(url, timeout=5, out_path=out_path)
            assert result == out_path
            with open(out_path, "rb") as f:
                assert f.read() == payload
        finally:
            srv.shutdown()

    def test_follows_redirect(self, tmp_path):
        payload = b"redirected payload"

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/first":
                    self.send_response(302)
                    self.send_header("Location", "/second")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        srv = _http_server(Handler)
        try:
            out_path = os.path.join(str(tmp_path), "out.tar")
            url = "http://127.0.0.1:%d/first" % srv.server_address[1]
            bulkhash.fetch(url, timeout=5, out_path=out_path)
            with open(out_path, "rb") as f:
                assert f.read() == payload
        finally:
            srv.shutdown()

    def test_http_error_raises_and_leaves_no_partial_file(self, tmp_path):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = _http_server(Handler)
        try:
            out_path = os.path.join(str(tmp_path), "out.tar")
            url = "http://127.0.0.1:%d/missing" % srv.server_address[1]
            with pytest.raises(bulkhash.BulkHashError):
                bulkhash.fetch(url, timeout=5, out_path=out_path)
            assert not os.path.exists(out_path)
        finally:
            srv.shutdown()

    def test_failure_never_clobbers_a_prior_good_file(self, tmp_path):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = _http_server(Handler)
        try:
            out_path = os.path.join(str(tmp_path), "out.tar")
            with open(out_path, "wb") as f:
                f.write(b"prior good tar")
            url = "http://127.0.0.1:%d/broken" % srv.server_address[1]
            with pytest.raises(bulkhash.BulkHashError):
                bulkhash.fetch(url, timeout=5, out_path=out_path)
            with open(out_path, "rb") as f:
                assert f.read() == b"prior good tar"
        finally:
            srv.shutdown()

    def test_connection_refused_raises(self, tmp_path):
        out_path = os.path.join(str(tmp_path), "out.tar")
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.fetch("http://127.0.0.1:1/nope", timeout=2,
                           out_path=out_path)
        assert not os.path.exists(out_path)


# ---------------------------------------------------------------------------
# verify_tar()
# ---------------------------------------------------------------------------

class TestVerifyTar:
    def test_valid_signature_passes(self, tmp_path, signing_key):
        cert, key = signing_key
        tar_path = _signed_fixture(tmp_path, REAL_ROW, key)
        assert bulkhash.verify_tar(tar_path, cert) is None  # never raises

    def test_unsigned_bundle_raises(self, tmp_path, signing_key):
        cert, key = signing_key
        tar_path = os.path.join(str(tmp_path), "unsigned.tar")
        _build_tar(tar_path, [
            ("feed/Cisco_BulkHash_CSV.csv", _csv_bytes(REAL_ROW)),
            # no .signature member at all
        ])
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.verify_tar(tar_path, cert)

    def test_empty_signature_raises(self, tmp_path, signing_key):
        cert, key = signing_key
        tar_path = os.path.join(str(tmp_path), "emptysig.tar")
        _build_tar(tar_path, [
            ("feed/Cisco_BulkHash_CSV.csv", _csv_bytes(REAL_ROW)),
            ("feed/Cisco_BulkHash_CSV.csv.signature", b""),
        ])
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.verify_tar(tar_path, cert)

    def test_wrong_cert_raises(self, tmp_path, signing_key):
        _cert, key = signing_key
        other_cert, _other_key = _throwaway_keypair(tmp_path, "not-the-signer")
        tar_path = _signed_fixture(tmp_path, REAL_ROW, key)
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.verify_tar(tar_path, other_cert)

    def test_tampered_csv_raises(self, tmp_path, signing_key):
        cert, key = signing_key
        tar_path = _signed_fixture(tmp_path, REAL_ROW, key)
        # Re-open and rewrite just the CSV member's bytes post-signing --
        # simplest way is to rebuild the tar with mismatched content/sig.
        csv_bytes = _csv_bytes(REAL_ROW)
        sig_bytes = _sign(key, csv_bytes)
        tampered = csv_bytes.replace(b"12345", b"99999")
        tar_path2 = os.path.join(str(tmp_path), "tampered.tar")
        _build_tar(tar_path2, [
            ("feed/Cisco_BulkHash_CSV.csv", tampered),
            ("feed/Cisco_BulkHash_CSV.csv.signature", sig_bytes),
        ])
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.verify_tar(tar_path2, cert)

    def test_truncated_tar_raises(self, tmp_path, signing_key):
        cert, key = signing_key
        tar_path = _signed_fixture(tmp_path, REAL_ROW, key)
        with open(tar_path, "rb") as f:
            data = f.read()
        truncated_path = os.path.join(str(tmp_path), "truncated.tar")
        with open(truncated_path, "wb") as f:
            f.write(data[:len(data) // 2])
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.verify_tar(truncated_path, cert)

    def test_missing_tar_file_raises(self, tmp_path, signing_key):
        cert, _key = signing_key
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.verify_tar(
                os.path.join(str(tmp_path), "does-not-exist.tar"), cert)

    def test_path_traversal_member_raises(self, tmp_path, signing_key):
        cert, key = signing_key
        csv_bytes = _csv_bytes(REAL_ROW)
        sig_bytes = _sign(key, csv_bytes)
        tar_path = os.path.join(str(tmp_path), "traversal.tar")
        _build_tar(tar_path, [
            ("../../etc/Cisco_BulkHash_CSV.csv", csv_bytes),
            ("../../etc/Cisco_BulkHash_CSV.csv.signature", sig_bytes),
        ])
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.verify_tar(tar_path, cert)

    def test_absolute_path_member_raises(self, tmp_path, signing_key):
        cert, key = signing_key
        csv_bytes = _csv_bytes(REAL_ROW)
        sig_bytes = _sign(key, csv_bytes)
        tar_path = os.path.join(str(tmp_path), "absolute.tar")
        _build_tar(tar_path, [
            ("/etc/Cisco_BulkHash_CSV.csv", csv_bytes),
            ("/etc/Cisco_BulkHash_CSV.csv.signature", sig_bytes),
        ])
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.verify_tar(tar_path, cert)

    def test_oversized_member_raises(self, tmp_path, signing_key, monkeypatch):
        cert, key = signing_key
        monkeypatch.setattr(bulkhash, "_MAX_CSV_BYTES", 100)
        big_row = REAL_ROW * 20  # comfortably over the 100-byte test cap
        tar_path = _signed_fixture(tmp_path, big_row, key)
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.verify_tar(tar_path, cert)

    def test_oversized_signature_raises(self, tmp_path, signing_key,
                                        monkeypatch):
        cert, key = signing_key
        monkeypatch.setattr(bulkhash, "_MAX_SIGNATURE_BYTES", 10)
        tar_path = _signed_fixture(tmp_path, REAL_ROW, key)
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.verify_tar(tar_path, cert)

    def test_csv_larger_than_a_tiny_cap_is_not_rejected_by_the_scan_pass(
            self, tmp_path, signing_key):
        """Regression guard: the initial member-scan cap must be at least
        `_MAX_CSV_BYTES`, not some smaller generic per-member cap -- the
        real feed's CSV (~88.5 MB, live 2026-08-29) is far bigger than a
        README/script-sized member, and must still pass the scan that
        happens before the CSV-specific size check even runs."""
        cert, key = signing_key
        repeats = 25000
        big_row = REAL_ROW * repeats  # ~6 MB: bigger than any "small
        # member" cap a careless implementation might reuse for the scan
        # pass (e.g. a few MB for README-sized files), but nowhere near the
        # real _MAX_CSV_BYTES default.
        tar_path = _signed_fixture(tmp_path, big_row, key)
        assert bulkhash.verify_tar(tar_path, cert) is None
        assert len(list(bulkhash.parse(tar_path))) == repeats

    def test_symlink_member_rejected(self, tmp_path, signing_key):
        cert, key = signing_key
        csv_bytes = _csv_bytes(REAL_ROW)
        sig_bytes = _sign(key, csv_bytes)
        tar_path = os.path.join(str(tmp_path), "symlink.tar")
        with tarfile.open(tar_path, mode="w:gz") as tf:
            info = tarfile.TarInfo(name="feed/Cisco_BulkHash_CSV.csv")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            tf.addfile(info)
            sig_info = tarfile.TarInfo(
                name="feed/Cisco_BulkHash_CSV.csv.signature")
            sig_info.size = len(sig_bytes)
            tf.addfile(sig_info, io.BytesIO(sig_bytes))
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.verify_tar(tar_path, cert)


# ---------------------------------------------------------------------------
# parse()
# ---------------------------------------------------------------------------

class TestParse:
    def test_parses_expected_rows(self, tmp_path, signing_key):
        _cert, key = signing_key
        rows_text = REAL_ROW + (
            "asa-9-8-2.smp,aaaa,BBBB,January 01 2020 00:00:00 PDT-0700,"
            "Deferred,999\r\n")
        tar_path = _signed_fixture(tmp_path, rows_text, key)
        rows = list(bulkhash.parse(tar_path))
        assert len(rows) == 2
        r0 = rows[0]
        assert r0.file_name == "isr4300-universalk9.16.03.01.SPA.bin"
        assert r0.md5 == "d949b99a104b23b2129718220c78f28e"
        assert r0.sha512.startswith("2e0d49321f6abbf4")
        assert r0.publish_date == "August 03 2016 00:00:00 PDT-0700"
        assert r0.deferral_status == ""
        assert r0.image_size == 12345
        r1 = rows[1]
        assert r1.file_name == "asa-9-8-2.smp"
        assert r1.deferral_status == "Deferred"
        assert r1.image_size == 999

    def test_empty_csv_after_header_yields_no_rows(self, tmp_path,
                                                    signing_key):
        _cert, key = signing_key
        tar_path = _signed_fixture(tmp_path, "", key)
        assert list(bulkhash.parse(tar_path)) == []

    def test_row_with_blank_image_size_is_kept_as_wildcard(self, tmp_path,
                                                            signing_key):
        """Live-feed finding (2026-08-29): ~17% of real rows -- including
        exact duplicates of otherwise-sized rows -- publish a blank
        IMAGE_SIZE. Such a row is real, hashed data (non-blank sha512),
        just missing the size column; it must be KEPT (image_size=None,
        a size wildcard for reconcile()'s join), not dropped, or every
        catalog image whose only feed row happens to be blank-size can
        never be reconciled at all."""
        _cert, key = signing_key
        rows_text = (
            "isr4300-universalk9.16.03.01.SPA.bin,D949B99A104B23B2129718220"
            "C78F28E,2E0D4932,August 03 2016 00:00:00 PDT-0700,,\r\n"
            + REAL_ROW)
        tar_path = _signed_fixture(tmp_path, rows_text, key)
        rows = list(bulkhash.parse(tar_path))
        assert len(rows) == 2
        assert rows[0].image_size is None
        assert rows[0].sha512 == "2e0d4932"
        assert rows[1].image_size == 12345

    def test_row_with_garbage_non_blank_image_size_is_still_skipped(
            self, tmp_path, signing_key):
        """Only a BLANK IMAGE_SIZE becomes a wildcard; a non-numeric,
        non-blank value is still genuinely malformed data and is skipped
        exactly as before."""
        _cert, key = signing_key
        rows_text = (
            "isr4300-universalk9.16.03.01.SPA.bin,D949B99A104B23B2129718220"
            "C78F28E,2E0D4932,August 03 2016 00:00:00 PDT-0700,,not-a-size"
            "\r\n" + REAL_ROW)
        tar_path = _signed_fixture(tmp_path, rows_text, key)
        rows = list(bulkhash.parse(tar_path))
        assert len(rows) == 1
        assert rows[0].image_size == 12345

    def test_row_with_blank_sha512_is_skipped_not_fatal(self, tmp_path,
                                                         signing_key):
        """A feed row with a blank SHA512_CHECKSUM must never reach
        reconcile() -- there is nothing to compare a catalog image's own
        sha512 against, and letting it through risks a false "verified"
        when an unhashed image also has a blank sha512 (both sides empty
        string == empty string)."""
        _cert, key = signing_key
        rows_text = (
            "blank-hash-image.bin,D949B99A104B23B2129718220C78F28E,,"
            "August 03 2016 00:00:00 PDT-0700,,100\r\n"
            + REAL_ROW)
        tar_path = _signed_fixture(tmp_path, rows_text, key)
        rows = list(bulkhash.parse(tar_path))
        assert len(rows) == 1
        assert rows[0].file_name == "isr4300-universalk9.16.03.01.SPA.bin"

    def test_sentinel_marker_rows_are_skipped(self, tmp_path, signing_key):
        _cert, key = signing_key
        rows_text = "##START_DATE##   FEB 14 2000,,,,,\r\n" + REAL_ROW + \
            "##END_DATE##   APR 30 2017,,,,,\r\n"
        tar_path = _signed_fixture(tmp_path, rows_text, key)
        rows = list(bulkhash.parse(tar_path))
        assert len(rows) == 1
        assert rows[0].file_name == "isr4300-universalk9.16.03.01.SPA.bin"

    def test_blank_lines_are_skipped(self, tmp_path, signing_key):
        _cert, key = signing_key
        rows_text = "\r\n" + REAL_ROW + "\r\n"
        tar_path = _signed_fixture(tmp_path, rows_text, key)
        rows = list(bulkhash.parse(tar_path))
        assert len(rows) == 1

    def test_missing_csv_member_raises(self, tmp_path):
        tar_path = os.path.join(str(tmp_path), "nocsv.tar")
        _build_tar(tar_path, [("feed/README", b"nothing to see here")])
        with pytest.raises(bulkhash.BulkHashError):
            list(bulkhash.parse(tar_path))

    def test_bad_header_raises(self, tmp_path, signing_key):
        _cert, key = signing_key
        tar_path = os.path.join(str(tmp_path), "badheader.tar")
        bad_csv = b"NOT,THE,RIGHT,HEADER\r\n"
        sig = _sign(key, bad_csv)
        _build_tar(tar_path, [
            ("feed/Cisco_BulkHash_CSV.csv", bad_csv),
            ("feed/Cisco_BulkHash_CSV.csv.signature", sig),
        ])
        with pytest.raises(bulkhash.BulkHashError):
            list(bulkhash.parse(tar_path))

    def test_truncated_tar_raises(self, tmp_path, signing_key):
        _cert, key = signing_key
        tar_path = _signed_fixture(tmp_path, REAL_ROW, key)
        with open(tar_path, "rb") as f:
            data = f.read()
        truncated_path = os.path.join(str(tmp_path), "truncated.tar")
        with open(truncated_path, "wb") as f:
            f.write(data[:len(data) // 2])
        with pytest.raises(bulkhash.BulkHashError):
            list(bulkhash.parse(truncated_path))

    def test_path_traversal_member_raises(self, tmp_path, signing_key):
        _cert, key = signing_key
        csv_bytes = _csv_bytes(REAL_ROW)
        sig_bytes = _sign(key, csv_bytes)
        tar_path = os.path.join(str(tmp_path), "traversal.tar")
        _build_tar(tar_path, [
            ("../../etc/Cisco_BulkHash_CSV.csv", csv_bytes),
            ("../../etc/Cisco_BulkHash_CSV.csv.signature", sig_bytes),
        ])
        with pytest.raises(bulkhash.BulkHashError):
            list(bulkhash.parse(tar_path))

    def test_oversized_member_raises(self, tmp_path, signing_key,
                                     monkeypatch):
        _cert, key = signing_key
        monkeypatch.setattr(bulkhash, "_MAX_CSV_BYTES", 100)
        big_row = REAL_ROW * 20
        tar_path = _signed_fixture(tmp_path, big_row, key)
        with pytest.raises(bulkhash.BulkHashError):
            list(bulkhash.parse(tar_path))

    def test_ambiguous_multiple_csv_members_raises(self, tmp_path,
                                                    signing_key):
        _cert, key = signing_key
        csv_bytes = _csv_bytes(REAL_ROW)
        sig_bytes = _sign(key, csv_bytes)
        tar_path = os.path.join(str(tmp_path), "ambiguous.tar")
        _build_tar(tar_path, [
            ("feed/Cisco_BulkHash_CSV.csv", csv_bytes),
            ("feed/Cisco_BulkHash_CSV.csv.signature", sig_bytes),
            ("feed/decoy_Extra.csv", csv_bytes),
        ])
        with pytest.raises(bulkhash.BulkHashError):
            list(bulkhash.parse(tar_path))


# ---------------------------------------------------------------------------
# reconcile()
# ---------------------------------------------------------------------------

def _row(file_name, sha512, size, publish_date="Jan 01 2020", deferral=""):
    return bulkhash.Row(file_name=file_name, md5="ignored", sha512=sha512,
                        publish_date=publish_date, deferral_status=deferral,
                        image_size=size)


class TestReconcile:
    def test_verified_when_sha512_matches(self):
        rows = [_row("image.bin", "abc123", 100)]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100, "sha512": "ABC123"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts == {
            "img-1": {"state": "verified", "feed_sha512": "abc123",
                      "publish_date": "Jan 01 2020", "deferral": False}}

    def test_mismatch_when_sha512_differs_same_name_and_size(self):
        rows = [_row("image.bin", "abc123", 100)]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100, "sha512": "deadbeef"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["state"] == "mismatch"
        assert verdicts["img-1"]["feed_sha512"] == "abc123"

    def test_not_in_feed_when_filename_absent(self):
        rows = [_row("other.bin", "abc123", 100)]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100, "sha512": "abc123"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"] == {
            "state": "not_in_feed", "feed_sha512": None,
            "publish_date": None, "deferral": False}

    def test_not_in_feed_when_size_differs_same_name(self):
        rows = [_row("image.bin", "abc123", 100)]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 999, "sha512": "abc123"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["state"] == "not_in_feed"

    def test_deferral_flag_set_when_deferral_status_not_active(self):
        rows = [_row("image.bin", "abc123", 100, deferral="Deferred")]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100, "sha512": "abc123"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["deferral"] is True
        assert verdicts["img-1"]["state"] == "verified"  # deferral != quarantine

    def test_deferral_false_for_active_status(self):
        rows = [_row("image.bin", "abc123", 100, deferral="Active")]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100, "sha512": "abc123"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["deferral"] is False

    def test_duplicate_rows_any_match_wins_not_last_row_wins(self):
        """The old last-wins dict-overwrite could fabricate a false
        mismatch: with two same-name/same-size rows, whichever was built
        into the join dict LAST silently discarded the other, so an image
        whose real sha512 matched the FIRST (discarded) row read as
        mismatch. any-match-wins fixes this: a match anywhere among the
        candidates is verified, regardless of position."""
        rows = [
            _row("image.bin", "first-hash", 100),
            _row("image.bin", "second-hash", 100),
        ]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100, "sha512": "first-hash"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["state"] == "verified"
        assert verdicts["img-1"]["feed_sha512"] == "first-hash"

    # -- live-feed finding (2026-08-29): wildcard (blank/None) IMAGE_SIZE
    # -- rows must still join and reconcile correctly
    def test_blank_size_row_verifies_a_matching_image(self):
        rows = [_row("cat9k_iosxe.17.12.04.SPA.bin", "real-hash", None)]
        images = [{"image_id": "img-1",
                   "filename": "cat9k_iosxe.17.12.04.SPA.bin",
                   "size": 123456, "sha512": "real-hash"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["state"] == "verified"
        assert verdicts["img-1"]["feed_sha512"] == "real-hash"

    def test_blank_size_candidate_with_differing_sha512_is_mismatch(self):
        rows = [_row("image.bin", "feed-hash", None)]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100, "sha512": "catalog-hash"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["state"] == "mismatch"
        assert verdicts["img-1"]["feed_sha512"] == "feed-hash"

    def test_duplicate_sized_and_blank_rows_either_matching_verifies(self):
        """The C9800 shape observed live: Cisco published both a sized
        row and a blank-size duplicate for the same image; either one
        carrying the right sha512 must verify."""
        rows = [
            _row("c8000v-universalk9.17.12.04.SPA.bin", "real-hash", 555),
            _row("c8000v-universalk9.17.12.04.SPA.bin", "real-hash", None),
        ]
        images = [{"image_id": "img-1",
                   "filename": "c8000v-universalk9.17.12.04.SPA.bin",
                   "size": 555, "sha512": "real-hash"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["state"] == "verified"

    def test_no_same_name_rows_is_not_in_feed_even_with_other_names(self):
        rows = [_row("other.bin", "hash", None),
                _row("another.bin", "hash", 100)]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100, "sha512": "hash"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["state"] == "not_in_feed"

    def test_mismatch_metadata_prefers_exact_size_over_blank_size_candidate(
            self):
        """On mismatch, the verdict's feed_sha512/publish_date/deferral
        must come from the exact-size candidate when one exists, not an
        arbitrary/blank-size one -- the exact-size row is the more
        specific, more trustworthy match for reporting."""
        rows = [
            _row("image.bin", "blank-row-hash", None,
                 publish_date="Blank Pub Date", deferral="Deferred"),
            _row("image.bin", "exact-row-hash", 100,
                 publish_date="Exact Pub Date", deferral="Active"),
        ]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100, "sha512": "catalog-hash"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["state"] == "mismatch"
        assert verdicts["img-1"]["feed_sha512"] == "exact-row-hash"
        assert verdicts["img-1"]["publish_date"] == "Exact Pub Date"
        assert verdicts["img-1"]["deferral"] is False

    def test_mismatch_metadata_falls_back_to_blank_size_candidate(self):
        """When NO exact-size candidate exists, mismatch metadata falls
        back to the (first) blank-size candidate."""
        rows = [_row("image.bin", "blank-row-hash", None,
                     publish_date="Blank Pub Date")]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 999, "sha512": "catalog-hash"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["state"] == "mismatch"
        assert verdicts["img-1"]["feed_sha512"] == "blank-row-hash"
        assert verdicts["img-1"]["publish_date"] == "Blank Pub Date"

    def test_multiple_images_independent_verdicts(self):
        rows = [_row("a.bin", "hash-a", 10), _row("b.bin", "hash-b", 20)]
        images = [
            {"image_id": "img-a", "filename": "a.bin", "size": 10,
             "sha512": "hash-a"},
            {"image_id": "img-b", "filename": "b.bin", "size": 20,
             "sha512": "wrong"},
            {"image_id": "img-c", "filename": "c.bin", "size": 30,
             "sha512": "hash-c"},
        ]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-a"]["state"] == "verified"
        assert verdicts["img-b"]["state"] == "mismatch"
        assert verdicts["img-c"]["state"] == "not_in_feed"

    def test_empty_rows_all_images_not_in_feed(self):
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100, "sha512": "abc123"}]
        verdicts = bulkhash.reconcile([], images)
        assert verdicts["img-1"]["state"] == "not_in_feed"

    def test_empty_images_yields_empty_dict(self):
        rows = [_row("image.bin", "abc123", 100)]
        assert bulkhash.reconcile(rows, []) == {}

    def test_accepts_image_tuples(self):
        rows = [_row("image.bin", "abc123", 100)]
        images = [("img-1", "image.bin", 100, "abc123")]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["state"] == "verified"

    def test_case_insensitive_sha512_comparison(self):
        rows = [_row("image.bin", "abcdef", 100)]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100, "sha512": "ABCDEF"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["state"] == "verified"

    def test_reconcile_is_pure_and_repeatable(self):
        rows = [_row("image.bin", "abc123", 100)]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100, "sha512": "abc123"}]
        first = bulkhash.reconcile(rows, images)
        rows2 = [_row("image.bin", "abc123", 100)]
        second = bulkhash.reconcile(rows2, images)
        assert first == second

    # -- fail-open regressions: blank sha512 on either side must never
    # -- produce "verified" (empty string == empty string is not a match)
    def test_raises_when_image_sha512_is_missing(self):
        rows = [_row("image.bin", "abc123", 100)]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100}]  # no "sha512" key at all
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.reconcile(rows, images)

    def test_raises_when_image_sha512_is_blank(self):
        rows = [_row("image.bin", "abc123", 100)]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100, "sha512": ""}]
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.reconcile(rows, images)

    def test_raises_when_both_feed_and_image_sha512_are_blank(self):
        """The exact fail-open scenario: a directly-constructed Row with a
        blank sha512 (parse() itself now refuses to ever produce one, but
        reconcile() must not rely on that -- it is called with `rows` from
        callers other than parse() too) paired with an unhashed catalog
        image must raise, never silently report "verified" via "" == ""."""
        rows = [_row("image.bin", "", 100)]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": 100, "sha512": ""}]
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.reconcile(rows, images)

    def test_raises_when_image_sha512_is_none(self):
        rows = [_row("image.bin", "abc123", 100)]
        images = [("img-1", "image.bin", 100, None)]
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.reconcile(rows, images)

    # -- fail-open regression: a non-int catalog `size` must never
    # -- silently degrade every image to not_in_feed
    def test_accepts_a_numeric_string_size_and_still_matches(self):
        """Task 2's catalog entries may come from JSON, where an integer
        can round-trip as a numeric string; that must still join correctly
        against the feed's int image_size, not silently miss every match."""
        rows = [_row("image.bin", "abc123", 100)]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": "100", "sha512": "abc123"}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["state"] == "verified"

    def test_raises_when_image_size_is_not_coercible_to_int(self):
        rows = [_row("image.bin", "abc123", 100)]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": "not-a-number", "sha512": "abc123"}]
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.reconcile(rows, images)

    def test_raises_when_image_size_is_none(self):
        rows = [_row("image.bin", "abc123", 100)]
        images = [{"image_id": "img-1", "filename": "image.bin",
                   "size": None, "sha512": "abc123"}]
        with pytest.raises(bulkhash.BulkHashError):
            bulkhash.reconcile(rows, images)


# ---------------------------------------------------------------------------
# End-to-end: fetch (from a local server) -> verify_tar -> parse -> reconcile
# ---------------------------------------------------------------------------

def test_full_pipeline_local_server_to_verdict(tmp_path, signing_key):
    cert, key = signing_key
    fixture_tar = _signed_fixture(tmp_path, REAL_ROW, key)
    with open(fixture_tar, "rb") as f:
        payload = f.read()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):
            pass

    srv = _http_server(Handler)
    try:
        out_path = os.path.join(str(tmp_path), "downloaded.tar")
        url = "http://127.0.0.1:%d/feed.tar" % srv.server_address[1]
        bulkhash.fetch(url, timeout=5, out_path=out_path)
        bulkhash.verify_tar(out_path, cert)  # raises on failure
        rows = bulkhash.parse(out_path)
        images = [{"image_id": "img-1",
                   "filename": "isr4300-universalk9.16.03.01.SPA.bin",
                   "size": 12345,
                   "sha512": ("2E0D49321F6ABBF416EE2AB021D9720E2B575F5715DA7"
                              "73F1DFD147A5B52EDFE34CFC8ABD746471756A3B2D6C8"
                              "655BA1B9BC86B9EB7A04850F49D89EA92BF63B")}]
        verdicts = bulkhash.reconcile(rows, images)
        assert verdicts["img-1"]["state"] == "verified"
    finally:
        srv.shutdown()
