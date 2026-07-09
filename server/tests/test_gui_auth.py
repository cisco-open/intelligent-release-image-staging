# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
import threading

import gui_auth


def test_hash_password_roundtrip():
    enc = gui_auth.hash_password("hunter2")
    assert enc.startswith("scrypt$")
    assert gui_auth.verify_password(enc, "hunter2") is True
    assert gui_auth.verify_password(enc, "wrong") is False


def test_hash_password_salts_differ():
    a = gui_auth.hash_password("same")
    b = gui_auth.hash_password("same")
    assert a != b  # random salt per hash


def test_verify_password_rejects_garbage():
    assert gui_auth.verify_password("", "x") is False
    assert gui_auth.verify_password("not-a-hash", "x") is False
    assert gui_auth.verify_password("scrypt$bad", "x") is False


def test_admin_set_get_verify():
    store = {"devices": {}, "seeder": {}}
    assert gui_auth.get_admin(store) is None
    gui_auth.set_admin(store, "admin", "s3cret", now=1000)
    admin = gui_auth.get_admin(store)
    assert admin["username"] == "admin"
    assert admin["created_at"] == 1000
    assert "pw_hash" in admin and "s3cret" not in admin["pw_hash"]
    assert gui_auth.verify_admin(store, "admin", "s3cret") is True
    assert gui_auth.verify_admin(store, "admin", "nope") is False
    assert gui_auth.verify_admin(store, "root", "s3cret") is False


def test_verify_admin_no_admin_configured():
    assert gui_auth.verify_admin({"devices": {}, "seeder": {}}, "admin", "x") is False


def test_verify_admin_non_ascii_username_returns_false_not_raise():
    store = {"devices": {}, "seeder": {}}
    gui_auth.set_admin(store, "admin", "pw", now=0)
    assert gui_auth.verify_admin(store, "admén", "pw") is False


def test_verify_admin_non_ascii_admin_username_roundtrip():
    store = {"devices": {}, "seeder": {}}
    gui_auth.set_admin(store, "müller", "pw", now=0)
    assert gui_auth.verify_admin(store, "müller", "pw") is True
    assert gui_auth.verify_admin(store, "müller", "bad") is False


def test_session_create_get_destroy():
    ss = gui_auth.SessionStore(idle_ttl=100)
    sid, csrf = ss.create("admin", now=1000)
    assert sid and csrf and sid != csrf
    sess = ss.get(sid, now=1050)
    assert sess["username"] == "admin"
    assert sess["csrf"] == csrf
    ss.destroy(sid)
    assert ss.get(sid, now=1051) is None


def test_session_idle_expiry():
    ss = gui_auth.SessionStore(idle_ttl=100)
    sid, _ = ss.create("admin", now=1000)
    assert ss.get(sid, now=1050) is not None    # 50s idle -> ok; refreshes last_seen=1050
    assert ss.get(sid, now=1120) is not None    # 70s since 1050 -> ok; refreshes last_seen=1120
    assert ss.get(sid, now=1300) is None         # 180s since 1120 (>= ttl) -> expired


def test_session_unknown_id():
    ss = gui_auth.SessionStore(idle_ttl=100)
    assert ss.get("nope", now=1000) is None


def test_session_store_concurrent_access_no_race():
    ss = gui_auth.SessionStore(idle_ttl=1000)
    errors = []
    barrier = threading.Barrier(16)

    def worker(i):
        try:
            barrier.wait()
            for _ in range(50):
                sid, csrf = ss.create("admin", now=1000)
                got = ss.get(sid, now=1000)
                assert got is not None and got["csrf"] == csrf
                ss.destroy(sid)
                assert ss.get(sid, now=1000) is None
        except Exception as exc:  # pragma: no cover - only on a real race
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors


def test_session_store_count_and_destroy_others():
    ss = gui_auth.SessionStore(idle_ttl=1800)
    s1, _ = ss.create("admin", now=0)
    ss.create("admin", now=0)
    ss.create("admin", now=0)
    assert ss.count(now=0) == 3
    assert ss.idle_ttl == 1800
    assert ss.destroy_others(s1) == 2          # keeps s1, drops the other two
    assert ss.count(now=0) == 1
    assert ss.get(s1, now=0) is not None


def test_session_store_count_prunes_expired():
    ss = gui_auth.SessionStore(idle_ttl=100)
    ss.create("admin", now=0)
    ss.create("admin", now=0)
    assert ss.count(now=200) == 0              # both idle >= ttl -> pruned
