# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Bounded mixed HTTPS workload used only by the isolated api-soak runner."""
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import json
import math
from pathlib import Path
import ssl
import threading
import time
from urllib.parse import urlsplit
import uuid


class Failure(RuntimeError):
    """Safe fixed diagnostic, never a response body or credential."""


def origin(value, allowed_hosts=("127.0.0.1",)):
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or parsed.hostname not in allowed_hosts
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or parsed.port is None):
        raise ValueError("only an explicitly allowed fixture HTTPS origin is supported")
    return parsed


class Client:
    def __init__(self, base, ca, allowed_hosts=("127.0.0.1",)):
        self.url = origin(base, allowed_hosts)
        self.context = ssl.create_default_context(cafile=ca)
        self.local = threading.local()
        self.cookie = self.csrf = ""

    def request(self, method, path, body=None, token=None):
        # Connections belong to worker threads. No failed write is replayed.
        conn = getattr(self.local, "connection", None)
        if conn is None:
            conn = http.client.HTTPSConnection(self.url.hostname, self.url.port,
                                              timeout=5, context=self.context)
            self.local.connection = conn
        headers = {"Accept": "application/json"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        if token:
            headers["Authorization"] = "Bearer " + token
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        elif isinstance(body, bytes):
            headers["Content-Type"] = "application/octet-stream"
        started = time.monotonic()
        status, data, retry, error = 0, {}, None, None
        try:
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            status = response.status
            retry = response.getheader("Retry-After")
            raw = response.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                raise Failure("response safety bound exceeded")
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise Failure("JSON object required")
            if path == "/api/v1/login" and status == 200:
                self.cookie = (response.getheader("Set-Cookie") or "").split(";", 1)[0]
                self.csrf = data.get("csrf", "")
        except Exception as exc:
            # Class only; URL/headers/payload and exception text are never logged.
            error, status, data = type(exc).__name__, 0, {}
            conn.close()
            self.local.connection = None
        return {"status": status, "seconds": time.monotonic() - started,
                "retry_after": retry, "error": error}, data

    def call(self, method, path, body=None, token=None):
        record, data = self.request(method, path, body, token)
        if record["status"] != 200:
            raise Failure("HTTP %d during %s" % (record["status"], method))
        return data

    def login(self, credentials):
        self.call("POST", "/api/v1/login", {key: credentials[key]
                                            for key in ("username", "password")})
        if not self.cookie or not self.csrf:
            raise Failure("authenticated session missing")


class Metrics:
    """Exact fixed-resolution histograms, not unbounded per-request lists."""
    def __init__(self):
        self.rows = defaultdict(lambda: {"statuses": Counter(), "ms": Counter(),
                                        "retry_after_valid": 0, "max_ms": 0})
        self.lock = threading.Lock()

    def add(self, kind, record):
        with self.lock:
            row = self.rows[kind]
            row["statuses"][str(record["status"])] += 1
            # 1 ms buckets through 60 seconds, bounded even after a stalled host.
            milliseconds = math.ceil(record["seconds"] * 1000)
            row["ms"][min(milliseconds, 60000)] += 1
            row["max_ms"] = max(row["max_ms"], milliseconds)
            if record["status"] == 429 and valid_retry(record["retry_after"]):
                row["retry_after_valid"] += 1

    def report(self, seconds):
        result = {}
        with self.lock:
            for kind, row in self.rows.items():
                count = sum(row["statuses"].values())
                def percentile(p):
                    remaining = math.ceil(count * p)
                    for duration, occurrences in sorted(row["ms"].items()):
                        remaining -= occurrences
                        if remaining <= 0:
                            return duration
                    return None
                result[kind] = {"count": count, "statuses": dict(row["statuses"]),
                                "rps": count / seconds, "p95_ms": percentile(.95),
                                "p99_ms": percentile(.99), "max_ms": row["max_ms"],
                                "valid_retry_after": row["retry_after_valid"]}
        return result


def valid_retry(value):
    return isinstance(value, str) and value.isascii() and value.isdecimal() and 1 <= int(value) <= 60


def objectives(report, overload=False):
    failures = []
    for kind, row in report.items():
        statuses = row["statuses"]
        if set(statuses) - ({"200", "429"} if overload else {"200"}):
            failures.append(kind + ": unexpected response")
        if overload and statuses.get("429", 0) != row["valid_retry_after"]:
            failures.append(kind + ": invalid Retry-After")
        p95, p99 = (500, 2000) if kind == "read" else (1000, 3000)
        if kind == "upload":
            p95 = p99 = 30000
        if row["p95_ms"] > p95 or row["p99_ms"] > p99:
            failures.append(kind + ": latency objective exceeded")
    return failures


def delivery_failures(report, seconds, rate, console_starts, devices, overload=False):
    failures = []
    if not overload and console_starts < seconds * rate * .95:
        failures.append("driver delivered less than 95% of scheduled Console starts")
    if report.get("heartbeat", {}).get("count", 0) < seconds * devices / 60 * .95:
        failures.append("driver delivered less than 95% of scheduled heartbeats")
    if report.get("telemetry", {}).get("count", 0) < seconds * .95:
        failures.append("driver delivered less than 95% of scheduled terminal reports")
    return failures


def terminal_report(image):
    return {"v": 2, "report_id": uuid.uuid4().hex, "transfer_id": uuid.uuid4().hex,
            "event": "pull", "report_created_at": time.time(), "image_id": image,
            "content_sha256": {"state": "not_checked"},
            "ios_copy_verify": {"state": "not_run"},
            "sampling": {"sampling_class": "good"}, "stage_state": "staging",
            "peers": [], "peers_total": 0, "peers_truncated": False,
            "peers_saturated": False}


def validate_read(path, data, devices, username, csrf):
    if path.startswith("/api/v1/devices"):
        if (not isinstance(data.get("devices"), list)
                or any(not isinstance(row, dict) or not str(row.get("device_id", "")).startswith("soak-")
                       for row in data["devices"])):
            raise Failure("inventory projection schema invalid")
    elif path == "/api/v1/overview":
        if data.get("devices") != devices or not isinstance(data.get("rollout"), list):
            raise Failure("Overview projection differs from fixture inventory")
    elif path == "/api/v1/peer-policy":
        if (type(data.get("revision")) is not int or data["revision"] < 0
                or data.get("degraded") is not False or data.get("fail_closed") is not False):
            raise Failure("peer-policy read is malformed or degraded")
    elif path == "/api/v1/session":
        if data.get("username") != username or data.get("csrf") != csrf:
            raise Failure("session identity changed")


class Workload:
    def __init__(self, console, catalog, ca_console, ca_catalog, credentials, allowed_hosts=("127.0.0.1",)):
        self.clients = [Client(console, ca_console, allowed_hosts) for _ in range(4)]
        self.catalog = Client(catalog, ca_catalog, allowed_hosts)
        self.credentials = credentials
        self.devices = sorted(credentials["tokens"])
        self.models, self.reports, self.images = {}, {}, {}
        self.image = None
        self.lock = threading.Lock()
        self.sequence = 0
        # A synthetic image, not Cisco software and never advertised as verified.
        self.payload = (b"IRIS synthetic capacity fixture\n" * 600000)[:16 * 1024 * 1024]
        self.sha256 = hashlib.sha256(self.payload).hexdigest()
        self.login()

    def login(self):
        for client in self.clients:
            client.cookie = client.csrf = ""
            client.login(self.credentials)

    def upload(self, metrics=None):
        filename = "soak-" + uuid.uuid4().hex + ".bin"
        client = self.clients[3]
        started = time.monotonic()
        def call(method, path, body=None):
            record, data = client.request(method, path, body)
            if metrics:
                metrics.add("upload_http", record)
            if record["status"] != 200:
                raise Failure("upload HTTP operation failed: %d" % record["status"])
            return data
        job = call("PUT", "/api/v1/images/upload/" + filename, self.payload)
        if not isinstance(job.get("job_id"), str):
            raise Failure("upload job identity missing")
        while time.monotonic() - started < 30:
            result = call("GET", "/api/v1/images/jobs/" + job["job_id"])
            if result.get("state") == "done":
                image = result.get("image_id")
                rows = call("GET", "/api/v1/images").get("images")
                if not isinstance(rows, list):
                    raise Failure("image-list schema invalid")
                entry = next((row for row in rows if row.get("id") == image), {})
                if entry.get("sha256") != self.sha256 or entry.get("size") != len(self.payload):
                    raise Failure("published content digest or length differs")
                with self.lock:
                    self.images[image] = self.sha256
                if metrics:
                    metrics.add("upload", {"status": 200, "seconds": time.monotonic() - started,
                                           "retry_after": None})
                return image
            if result.get("state") not in ("publishing", "verifying"):
                raise Failure("publish job failed")
            time.sleep(.1)
        raise Failure("publish completion exceeded 30 seconds")

    def phase(self, seconds, rate, monitor, upload_interval=60, overload=False):
        metrics, stop = Metrics(), threading.Event()
        errors = []
        started = time.monotonic()
        deadline = started + seconds
        operations = Counter()
        operation_lock = threading.Lock()

        def invoke(kind, client, method, path, body=None, token=None):
            record, data = client.request(method, path, body, token)
            metrics.add(kind, record)
            if record["status"] == 429 and overload and valid_retry(record["retry_after"]):
                # Do not replay this operation. Respect the server before NEXT work.
                stop.wait(int(record["retry_after"]))
                return None
            if record["status"] != 200:
                raise Failure(kind + ": HTTP %d (%s)" % (record["status"], record["error"] or "response"))
            return data

        def paced_worker(offset, interval, action):
            target = started + offset
            try:
                while target < deadline and not stop.is_set():
                    if stop.wait(max(0, target - time.monotonic())):
                        break
                    if time.monotonic() >= deadline:
                        break
                    action()
                    # Never catch up with a burst after slow responses.
                    target = max(target + interval, time.monotonic())
            except Exception as exc:
                errors.append(str(exc) if isinstance(exc, Failure) else type(exc).__name__)
                stop.set()

        def console_action(worker):
            with operation_lock:
                sequence = self.sequence
                self.sequence += 1
                operations["console"] += 1
            client = self.clients[worker]
            # Exactly 20% operator metadata writes. Different workers own separate
            # fixture devices, so accepted last values have an unambiguous order.
            if sequence % 5 == 0:
                device = self.devices[worker]
                model = "soak-write-%d" % sequence
                data = invoke("write", client, "POST", "/api/v1/devices",
                              {"device_id": device, "model": model})
                if data is not None:
                    if data.get("device", {}).get("model") != model:
                        raise Failure("accepted metadata write did not echo exact value")
                    with self.lock:
                        self.models[device] = model
            else:
                paths = ("/api/v1/devices?limit=100&offset=0", "/api/v1/overview",
                         "/api/v1/peer-policy", "/api/v1/session")
                path = paths[(sequence // 5 + sequence) % len(paths)]
                data = invoke("read", client, "GET", path)
                if data is not None:
                    validate_read(path, data, len(self.devices), self.credentials["username"], client.csrf)

        hb_index = [0]
        def heartbeat():
            index = hb_index[0]
            hb_index[0] += 1
            device = self.devices[index % len(self.devices)]
            invoke("heartbeat", self.catalog, "POST", "/v1/devices/" + device + "/heartbeat",
                   {"current_image_id": self.image, "stage_state": "staging",
                    "version": "synthetic-soak", "free_flash_bytes": 1024 ** 3,
                    "telemetry_enabled": True, "telemetry_stream_enabled": True},
                   self.credentials["tokens"][device])

        telemetry_index = [0]
        def telemetry():
            device = self.devices[telemetry_index[0] % len(self.devices)]
            telemetry_index[0] += 1
            report = terminal_report(self.image)
            invoke("telemetry", self.catalog, "POST", "/v1/devices/" + device + "/telemetry",
                   report, self.credentials["tokens"][device])
            with self.lock:
                self.reports[device] = report["report_id"]

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(paced_worker, worker / rate, 4 / rate,
                                   lambda worker=worker: console_action(worker))
                       for worker in range(4)]
            # One heartbeat per device per minute; one v2 terminal report/second.
            futures.append(pool.submit(paced_worker, 0, 60 / len(self.devices), heartbeat))
            futures.append(pool.submit(paced_worker, .5, 1, telemetry))
            if not overload:
                futures.append(pool.submit(paced_worker, 1, upload_interval, lambda: self.upload(metrics)))
            while not stop.is_set() and time.monotonic() < deadline:
                if stop.wait(min(5, max(0, deadline - time.monotonic()))):
                    break
                try:
                    monitor()
                except Failure as exc:
                    errors.append(str(exc))
                    stop.set()
            for future in futures:
                future.result()
        elapsed = time.monotonic() - started
        report = metrics.report(elapsed)
        errors.extend(objectives(report, overload))
        errors.extend(delivery_failures(report, seconds, rate, operations["console"], len(self.devices), overload))
        return {"seconds": elapsed, "target_console_rps": rate,
                "metrics": report, "failures": errors, "passed": not errors}

    def verify_durability(self):
        client = self.clients[0]
        for device, model in self.models.items():
            rows = client.call("GET", "/api/v1/devices?q=" + device).get("devices", [])
            row = next((r for r in rows if r.get("device_id") == device), {})
            if row.get("model") != model:
                raise Failure("accepted metadata did not survive")
        for device, report_id in self.reports.items():
            rows = client.call("GET", "/api/v1/devices/" + device + "/reports").get("reports", [])
            if not any(row.get("report_id") == report_id for row in rows):
                raise Failure("accepted v2 report did not survive")
        images = client.call("GET", "/api/v1/images").get("images", [])
        by_id = {entry.get("id"): entry for entry in images}
        for image, digest in self.images.items():
            if by_id.get(image, {}).get("sha256") != digest:
                raise Failure("published image digest did not survive")
        return {"metadata_rows": len(self.models), "terminal_reports": len(self.reports),
                "published_images": len(self.images)}
