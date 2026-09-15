#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Bounded live Console API coverage and load exercise; never onboards devices.

Default is read-only. --mutate requires an empty inventory and creates only
run-owned documentation-address devices. Reports never contain response bodies,
cookies, CSRF tokens, or passwords. Successful guards are NOT positive coverage.
"""
import argparse
import collections
import concurrent.futures
import http.client
import json
import math
import pathlib
import secrets
import ssl
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "server"))
from api_routes import ROUTES, match


class Pacer:
    """Bound aggregate request starts across workers, without catch-up bursts."""
    def __init__(self, rate=0):
        self.interval = 1.0 / rate if rate else 0
        self.lock = threading.Lock()
        self.next_start = 0.0

    def wait(self):
        if not self.interval:
            return
        with self.lock:
            delay = self.next_start - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            self.next_start = time.monotonic() + self.interval


class Client:
    def __init__(self, base, cafile, timeout=5, request_rate=0):
        self.url = urllib.parse.urlsplit(base)
        if self.url.scheme != "https" or self.url.path not in ("", "/"):
            raise ValueError("base must be an HTTPS origin")
        self.context = ssl.create_default_context(cafile=cafile)
        self.timeout = timeout
        self.local = threading.local()
        self.cookie = self.csrf = ""
        self.records = []
        self.lock = threading.Lock()
        self.pacer = Pacer(request_rate)

    def request(self, method, path, body=None, auth=True, csrf=True, phase="coverage", headers=None):
        self.pacer.wait()
        conn = getattr(self.local, "conn", None)
        if conn is None:
            conn = http.client.HTTPSConnection(self.url.hostname, self.url.port or 443,
                                              context=self.context, timeout=self.timeout)
            self.local.conn = conn
        headers = {"Accept": "application/json", **(headers or {})}
        if auth and self.cookie:
            headers["Cookie"] = self.cookie
        if auth and csrf and self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            headers["Content-Type"] = "application/json"
        started = time.monotonic()
        status, parsed, error = 0, {}, None
        try:
            conn.request(method, path, body=data, headers=headers)
            response = conn.getresponse()
            self.local.response_headers = dict(response.getheaders())
            status = response.status
            raw = response.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                raise ValueError("response exceeds 8 MiB safety bound")
            if path == "/api/v1/login" and status == 200:
                cookie = response.getheader("Set-Cookie")
                if cookie:
                    self.cookie = cookie.split(";", 1)[0]
            if "json" in response.getheader("Content-Type", ""):
                parsed = json.loads(raw) if raw else {}
        except Exception as exc:
            error = type(exc).__name__  # never log response bodies or credentials
            status = 0
            conn.close()
            self.local.conn = None
        record = {"method": method, "path": path, "status": status,
                  "seconds": time.monotonic() - started, "phase": phase}
        if error:
            record["error"] = error
        if status == 207 and isinstance(parsed, dict):
            record["degraded"] = [v for v in parsed.get("degraded", [])
                                  if v in ("policy", "catalog", "records", "jobs")]
        with self.lock:
            self.records.append(record)
        return status, parsed

    def call(self, method, path, body=None, expected=(200,), headers=None):
        status, parsed = self.request(method, path, body, headers=headers)
        if status not in expected:
            raise RuntimeError("%s %s: HTTP %s, expected %s" %
                               (method, path, status, expected))
        return status, parsed

    def response_header(self, name):
        return next((v for k, v in getattr(self.local, "response_headers", {}).items()
                     if k.lower() == name.lower()), None)


def summary(records, elapsed):
    times = sorted(row["seconds"] for row in records)
    def percentile(p):
        return round(times[max(0, math.ceil(len(times) * p) - 1)] * 1000, 2) if times else None
    success = sum(200 <= r["status"] < 300 and r["status"] != 207 for r in records)
    return {"requests": len(records), "successful": success,
            "partial_responses": sum(r["status"] == 207 for r in records),
            "wall_seconds": round(elapsed, 3),
            "requests_per_second": round(len(records) / elapsed, 2) if elapsed else 0,
            "successful_per_second": round(success / elapsed, 2) if elapsed else 0,
            "successful_per_minute_equivalent": round(success * 60 / elapsed, 2) if elapsed else 0,
            "statuses": dict(collections.Counter(str(r["status"]) for r in records)),
            "p50_ms": percentile(.5), "p95_ms": percentile(.95), "p99_ms": percentile(.99)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base", required=True)
    p.add_argument("--cafile", required=True)
    p.add_argument("--username", default="admin")
    p.add_argument("--password-file", required=True)
    p.add_argument("--mutate", action="store_true")
    p.add_argument("--devices", type=int, default=500)
    p.add_argument("--concurrency", default="1,4,8,16")
    p.add_argument("--seconds", type=float, default=2)
    p.add_argument("--max-requests", type=int, default=160)
    p.add_argument("--output", required=True)
    p.add_argument("--request-rate", type=float, default=0,
                   help="aggregate request starts/second; 0 means unpaced")
    args = p.parse_args()
    if not math.isfinite(args.request_rate) or not 0 <= args.request_rate <= 1000:
        p.error("request-rate must be finite and between 0 and 1000")
    levels = [int(v) for v in args.concurrency.split(",")]
    if not levels or any(v < 1 or v > 32 for v in levels):
        p.error("concurrency must be between 1 and 32")
    if not 1 <= args.devices <= 2000 or not 0 < args.seconds <= 10 or not 1 <= args.max_requests <= 1000:
        p.error("limits: 1..2000 devices, <=10 seconds per read phase, <=1000 requests")
    client = Client(args.base, args.cafile, request_rate=args.request_rate)
    password = pathlib.Path(args.password_file).read_text().strip()
    _, login = client.call("POST", "/api/v1/login",
                           {"username": args.username, "password": password})
    client.csrf = login.get("csrf", "")
    if not client.csrf or not client.cookie:
        raise RuntimeError("configured admin login required; setup is never performed")
    _, initial = client.call("GET", "/api/v1/devices")
    if not isinstance(initial.get("devices"), list):
        raise RuntimeError("unexpected device-list schema")
    if args.mutate and initial["devices"]:
        raise RuntimeError("mutation exercise requires an empty inventory")
    if args.mutate:
        _, policy = client.call("GET", "/api/v1/peer-policy")
        outbox = policy.get("outbox", {})
        if (outbox.get("capacity", 0) > 0 and
                outbox.get("unacknowledged", 0) >= outbox["capacity"]):
            raise RuntimeError("policy outbox is full; resolve the backlog before another mutation run")
    prefix = "api-load-" + secrets.token_hex(6)
    ids = ["%s-%04d" % (prefix, n) for n in range(args.devices)] if args.mutate else []
    report = {"base": args.base, "run_id": prefix, "coverage": [], "phases": [],
              "request_start_rate": args.request_rate,
              "scope": "Console API only; guards are not positive functional coverage",
              "read_phase_seconds": args.seconds, "max_requests_per_read_phase": args.max_requests,
              "limitations": ["short local-loopback load test, not sustained production capacity",
                              "one authenticated session; login throughput not benchmarked",
                              "no positive real-device jobs, trust changes, or external exports"],
              "owned_device_ids": ids, "errors": []}
    output = pathlib.Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    def save():
        report["requests"] = client.records
        output.write_text(json.dumps(report, indent=2) + "\n")
    save()  # recovery manifest exists before the first mutation

    def phase(name, jobs, concurrency):
        before = len(client.records)
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            results = list(pool.map(lambda job: client.request(*job, phase=name), jobs))
        row = summary(client.records[before:], time.monotonic() - started)
        row.update(name=name, concurrency=concurrency)
        report["phases"].append(row)
        save()
        print(json.dumps(row), flush=True)
        return results

    try:
        if ids:
            for index, concurrency in enumerate(levels):
                subset = ids[len(ids)*index//len(levels):len(ids)*(index+1)//len(levels)]
                jobs = [("POST", "/api/v1/devices", {"device_id": did,
                         "device_ip": "198.18.%d.%d" % (n//254, n%254+1)})
                        for n, did in enumerate(subset, len(ids)*index//len(levels))]
                results = phase("create", jobs, concurrency)
                if any(status != 200 for status, _ in results):
                    raise RuntimeError("create failed; stop load and reconcile owned records")
            _, devices = client.call("GET", "/api/v1/devices")
            present = {d["device_id"] for d in devices["devices"]}
            if not set(ids) <= present:
                raise RuntimeError("acknowledged creates missing from inventory")
            report["created_verified"] = len(ids)
            from api_exercise_fixtures import exercise
            report["fixtures"] = exercise(client, ids[0], prefix)
            report["errors"].extend("fixture " + row["name"] + ": " + row.get("error", "failed")
                                    for row in report["fixtures"]["checks"] if not row["ok"])

        fixture = ids[0] if ids else "api-exercise-missing"
        for route in ROUTES:
            if route.service != "console":
                continue
            path = route.path
            for key, value in {"device_id": fixture, "id": "api-exercise-missing",
                               "job_id": "api-exercise-missing", "filename": "api-exercise-missing.log",
                               "name": prefix, "image_id": prefix, "credential_id": prefix}.items():
                path = path.replace("{" + key + "}", urllib.parse.quote(value, safe=""))
            entry = {"method": route.method, "template": route.path}
            report["coverage"].append(entry)
            if route.security != "none":
                status, _ = client.request(route.method, path,
                                           {} if route.method != "GET" else None, auth=False,
                                           phase="unauthorized-guard")
                entry["unauthorized_status"] = status
                if route.path not in ("/api/v1/login", "/api/v1/setup") and status != 401:
                    report["errors"].append("unexpected auth guard: %s %s HTTP %s" %
                                            (route.method, path, status))
                if route.method not in ("GET", "HEAD") and route.path not in ("/api/v1/login", "/api/v1/setup"):
                    status, _ = client.request(route.method, path, {}, csrf=False, phase="csrf-guard")
                    entry["csrf_status"] = status
                    if status != 403:
                        report["errors"].append("unexpected CSRF guard: %s %s HTTP %s" %
                                                (route.method, path, status))
            if route.method == "GET":
                if path.endswith("/peer-policy/explain"):
                    path += "?a=device:" + fixture + "&b=service:seeder"
                status, _ = client.request("GET", path, phase="get-coverage")
                entry["get_status"] = status
                entry["positive"] = 200 <= status < 300
                if "{" in route.path and not entry["positive"]:
                    entry["limitation"] = "fixture unavailable; negative response is not positive coverage"
            else:
                entry["positive"] = any(r["method"] == route.method and
                    r["phase"] == "coverage" and r["status"] in (200, 201, 204) and
                    match("console", r["method"], r["path"]) == route
                    for r in client.records)
        save()

        for endpoint in ("/api/v1/session", "/api/v1/devices?limit=100&offset=0",
                         "/api/v1/peer-policy", "/api/v1/overview"):
            for concurrency in levels:
                before = len(client.records)
                started = time.monotonic()
                counter = [0]
                lock = threading.Lock()
                stop = threading.Event()
                def worker():
                    while not stop.is_set() and time.monotonic()-started < args.seconds:
                        with lock:
                            if counter[0] >= args.max_requests:
                                return
                            counter[0] += 1
                        status, _ = client.request("GET", endpoint, phase="read-load")
                        if status == 0 or status >= 500:
                            stop.set()
                with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                    list(pool.map(lambda _: worker(), range(concurrency)))
                row = summary(client.records[before:], time.monotonic()-started)
                row.update(name="read", endpoint=endpoint, concurrency=concurrency,
                           fleet_size=len(ids) if ids else initial.get("total", len(initial["devices"])),
                           stopped_on_error=stop.is_set(),
                           completion="error" if stop.is_set() else
                           "request-cap" if counter[0] >= args.max_requests else "time-budget")
                report["phases"].append(row)
                save()
                print(json.dumps(row), flush=True)
                if stop.is_set():
                    report["errors"].append("read load stopped on transport/server error: " + endpoint)
                    break
    except Exception as exc:
        report["errors"].append(str(exc))
        print("Exercise stopped: " + str(exc), flush=True)
    finally:
        if ids:
            # Only IDs from this run's manifest can be retired. Never delete
            # records merely because their names happen to share a prefix.
            status, inventory = client.request("GET", "/api/v1/devices", phase="cleanup")
            if status == 200 and isinstance(inventory.get("devices"), list):
                present = {d["device_id"] for d in inventory["devices"]}
                owned = [did for did in ids if did in present]
                for index, concurrency in enumerate(levels):
                    subset = owned[len(owned)*index//len(levels):len(owned)*(index+1)//len(levels)]
                    results = phase("delete", [("DELETE", "/api/v1/devices/"+did) for did in subset], concurrency)
                    for did, (status, _) in zip(subset, results):
                        if not 200 <= status < 300 or status == 207:
                            report["errors"].append("cleanup %s HTTP %s" % (did, status))
                status, inventory = client.request("GET", "/api/v1/devices", phase="cleanup")
                if status != 200 or not isinstance(inventory.get("devices"), list):
                    report["remaining_owned_devices"] = "unknown"
                    report["errors"].append("final cleanup verification unavailable")
                else:
                    report["remaining_owned_devices"] = [d["device_id"] for d in inventory["devices"]
                                                         if d["device_id"] in set(ids)]
            else:
                report["errors"].append("cleanup inventory unavailable; use owned_device_ids manifest")
                report["remaining_owned_devices"] = "unknown"
        for entry in report["coverage"]:
            successes = [r for r in client.records if r["phase"] in
                         ("coverage", "get-coverage", "create", "delete")
                         and 200 <= r["status"] < 300 and r["status"] != 207
                         and r["method"] == entry["method"]
                         and (matched := match("console", r["method"], r["path"]))
                         and matched.path == entry["template"]]
            entry["positive"] = bool(successes)
            if entry["template"].endswith("/stream"):
                entry["positive"] = False
                entry["limitation"] = "missing-job stream probe only, not a successful live stream"
        save()
        print("Report: " + str(output), flush=True)
    return 1 if report["errors"] or report.get("remaining_owned_devices") else 0


if __name__ == "__main__":
    sys.exit(main())
