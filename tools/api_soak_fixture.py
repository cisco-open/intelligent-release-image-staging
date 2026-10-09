#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Private disposable-container fixture helper for api-soak.py, not an installer."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

sys.path.insert(0, "/opt/iris/server")


def main():
    # The orchestrator supplies this exact marker only on fresh labelled resources.
    if os.environ.get("IRIS_SOAK_FIXTURE") != "synthetic-isolated-v1":
        raise SystemExit("disposable fixture marker required")
    if sys.argv[1] == "init":
        import gui_auth
        import gui_fleet
        import secretfs
        import secrets_store
        for directory in ("/etc/iris", "/var/lib/iris", "/opt/images",
                          "/srv/artifacts", "/var/lib/iris-images",
                          "/run/soak-keys", "/run/soak-shared", "/run/iris"):
            os.chown(directory, 10001, 10001)
        os.setgid(10001)
        os.setuid(10001)
        os.umask(0o077)
        if list(Path("/etc/iris").glob("*.age")):
            raise SystemExit("fixture initialization requires fresh encrypted state")
        subprocess.run(["/opt/iris/server/iris-bootstrap"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        recipient = subprocess.check_output(
            ["age-keygen", "-y", "/run/soak-keys/age.key"], text=True).strip()
        Path("/run/soak-shared/recipient.pub").write_text(recipient)
        plain = "/run/iris/secrets.json"
        encrypted = "/etc/iris/secrets.json.age"
        secretfs.decrypt_to(encrypted, plain, "/run/soak-keys/age.key")
        # Native tracker URLs require a routable address, here reachable only
        # on the isolated bridge. The driver reaches the same TLS identity
        # through the exact host-verified address on the owned internal bridge.
        secretfs.decrypt_to("/etc/iris/tls/key.pem.age", "/run/iris/catalog.key",
                            "/run/soak-keys/age.key")
        subprocess.run([
            "openssl", "req", "-x509", "-new", "-days", "2",
            "-key", "/run/iris/catalog.key", "-out", "/etc/iris/tls/crt.pem",
            "-subj", "/CN=isolated-capacity-fixture",
            "-addext", "subjectAltName=IP:127.0.0.1,IP:" + os.environ["IRIS_HOST_IP"]],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        Path("/run/iris/catalog.key").unlink()
        store = secrets_store.load(plain, require_existing=True)
        password = secrets.token_urlsafe(32)
        gui_auth.set_admin(store, "soak", password, int(time.time()))
        tokens = {}
        fleet = gui_fleet.FleetStore("/var/lib/iris")
        for index in range(int(sys.argv[2])):
            device = "soak-%04d" % index
            tokens[device] = secrets_store.mint(
                store, device, "catalog_token", int(time.time()))
            fleet.upsert({"device_id": device, "device_ip": "198.18.%d.%d" %
                          (index // 250, 1 + index % 250), "platform": "router",
                          "model": "synthetic-capacity-fixture"})
        secretfs.persist_store(store, plain, recipient, encrypted)
        Path("/run/soak-keys/driver.json").write_text(json.dumps(
            {"username": "soak", "password": password, "tokens": tokens}))
        Path("/run/soak-shared/tier.token").write_text(secrets.token_hex(32))
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "2", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost,IP:" + os.environ["IRIS_SOAK_CONSOLE_IP"],
            "-keyout", "/run/soak-shared/browser.key",
            "-out", "/run/soak-shared/browser.pem"], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(json.dumps({"initialized_devices": len(tokens)}))
    elif sys.argv[1] == "assign":
        import catalog
        import gui_fleet
        store = catalog.CatalogStore("/var/lib/iris")
        if store.get_image(sys.argv[2]) is None:
            raise SystemExit("real published fixture image required")
        for device in gui_fleet.FleetStore("/var/lib/iris").list_devices():
            did = device["device_id"]
            if not did.startswith("soak-"):
                raise SystemExit("foreign fixture device")
            store.set_policy(did, approved_image_id=sys.argv[2])
        print(json.dumps({"assigned_fixture_image": sys.argv[2]}))
    elif sys.argv[1] == "check-content":
        import catalog
        import hashlib
        count = 0
        for entry in catalog.CatalogStore("/var/lib/iris").list_images():
            if not entry["filename"].startswith("soak-") or entry.get("source_dir") != "/var/lib/iris-images":
                raise SystemExit("foreign image in disposable fixture")
            path = Path("/var/lib/iris-images") / entry["filename"]
            digest = hashlib.sha256()
            with path.open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(block)
            if path.stat().st_size != entry["size"] or digest.hexdigest() != entry["sha256"]:
                raise SystemExit("persisted content differs")
            count += 1
        print(json.dumps({"content_files_rehashed": count}))
    elif sys.argv[1] == "resources":
        # cgroup v2 counters, process/FD/thread totals; no command lines or env.
        result = {}
        for name in ("cpu.stat", "memory.current", "memory.peak", "memory.events", "memory.stat",
                     "pids.current", "cpu.pressure", "memory.pressure", "io.pressure"):
            path = Path("/sys/fs/cgroup") / name
            result[name] = path.read_text() if path.is_file() else None
        processes = [p for p in Path("/proc").iterdir() if p.name.isdigit()]
        result["processes"] = len(processes)
        result["fds"] = result["threads"] = 0
        for process in processes:
            try:
                result["fds"] += len(list((process / "fd").iterdir()))
                result["threads"] += len(list((process / "task").iterdir()))
            except OSError:
                pass
        print(json.dumps(result))
    else:
        raise SystemExit("unsupported fixture action")


if __name__ == "__main__":
    main()
