#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Qualify mixed HTTP capacity on NEW local-only disposable Docker resources.

Never accepts an existing deployment, remote Docker context or target URL.
Run --help and read docs/dev/api-soak.md before reserving a measurement window.
"""
import argparse
import ipaddress
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import traceback
import uuid

from api_soak_workload import Client, Failure, Workload

LABEL = "com.cisco.iris.soak"
ROOT = Path(__file__).resolve().parents[1]
MOUNTS = {"config": "/etc/iris", "state": "/var/lib/iris",
          "imports": "/opt/images", "artifacts": "/srv/artifacts",
          "images": "/var/lib/iris-images", "keys": "/run/soak-keys",
          "shared": "/run/soak-shared"}


def docker(*args, check=True):
    result = subprocess.run(["docker", "--context", "default", *args],
                            capture_output=True, text=True, timeout=120)
    if check and result.returncode:
        # Docker may include command/environment in errors. Never echo stderr.
        raise Failure("Docker %s failed (exit %d)" % (args[0], result.returncode))
    return result


def validate_host():
    if os.environ.get("DOCKER_CONTEXT", "default") != "default" or os.environ.get("DOCKER_HOST"):
        raise Failure("unset remote Docker context/host overrides")
    context = json.loads(docker("context", "inspect", "default").stdout)[0]
    if context["Endpoints"]["docker"]["Host"] != "unix:///var/run/docker.sock":
        raise Failure("only the local default Docker socket is supported")
    if not hasattr(os, "sched_setaffinity"):
        raise Failure("Linux driver CPU affinity required")


def owned(kind, identity, run_id):
    row = json.loads(docker(kind, "inspect", identity).stdout)[0]
    labels = row.get("Labels") if kind != "container" else row.get("Config", {}).get("Labels")
    if not labels or labels.get(LABEL) != run_id:
        raise Failure("resource ownership changed; refusing mutation")
    if kind != "volume" and row.get("Id") != identity:
        raise Failure("resource identity changed; refusing mutation")
    return row


class Fixture:
    def __init__(self, directory, server_image, console_image, devices):
        self.directory = directory
        self.run_id = uuid.uuid4().hex
        self.prefix = "iris-soak-" + self.run_id[:12]
        self.resources = {"container": [], "volume": [], "network": []}
        self.manifest = {"run_id": self.run_id, "devices": devices,
                         "resources": self.resources, "images": {}, "cleaned": False,
                         "started_at": time.time(), "monitor_interval_seconds": 5}
        self.manifest["image_references"] = {"server": server_image, "console": console_image}
        self.manifest["driver_sha256"] = {name: hashlib.sha256((ROOT / "tools" / name).read_bytes()).hexdigest()
                                          for name in ("api-soak.py", "api_soak_workload.py", "api_soak_fixture.py")}
        self.manifest["host_logical_cpus"] = os.cpu_count()
        self.manifest["baseline_container_stats"] = [json.loads(line) for line in docker(
            "stats", "--no-stream", "--format", "{{json .}}").stdout.splitlines()]
        self.server_image, self.console_image = server_image, console_image
        self.devices = devices
        self.volumes = {}
        self.samples = []
        self.previous = {}
        self.resource_log = (directory / "resources.jsonl").open("x")
        self.server = self.console = None
        self.save()

    def save(self):
        path = self.directory / "resources.json"
        path.write_text(json.dumps(self.manifest, indent=2) + "\n")

    def register(self, kind, identity):
        self.resources[kind].append(identity)
        self.save()
        return identity

    def inspect(self, container):
        return owned("container", container, self.run_id)

    def run_args(self, name, image, cpus, memory, boot=False):
        args = ["container", "create", "--label", LABEL + "=" + self.run_id,
                "--name", self.prefix + "-" + name, "--network", self.network,
                "--cpus", str(cpus), "--memory", memory, "--memory-swap", memory,
                "--pids-limit", "256", "--security-opt", "no-new-privileges",
                "--log-opt", "max-size=5m", "--log-opt", "max-file=2",
                "--tmpfs", "/run/iris:rw,noexec,nosuid,size=128m,uid=10001,gid=10001,mode=0700",
                "--tmpfs", "/run/iris-console:rw,noexec,nosuid,size=8m,uid=10001,gid=10001,mode=0700",
                "--mount", "type=bind,src=%s,dst=/soak-fixture.py,readonly" %
                (ROOT / "tools/api_soak_fixture.py")]
        if not boot:
            args += ["--cap-drop", "ALL"]
        return args

    def create(self, args, image, command=()):
        identity = docker(*args, image, *command).stdout.strip()
        self.register("container", identity)
        docker("container", "start", identity)
        return identity

    def copy(self, container, source, destination):
        self.inspect(container)
        docker("cp", container + ":" + source, str(self.directory / destination))
        os.chmod(self.directory / destination, 0o600)

    def fixture_command(self, container, *args):
        self.inspect(container)
        return docker("exec", container, "python3", "/soak-fixture.py", *args).stdout

    def start(self):
        for role, reference in (("server", self.server_image), ("console", self.console_image)):
            row = json.loads(docker("image", "inspect", reference).stdout)[0]
            self.manifest["images"][role] = row["Id"]
        self.network = self.register("network", docker(
            "network", "create", "--internal", "--label", LABEL + "=" + self.run_id,
            self.prefix).stdout.strip())
        network = owned("network", self.network, self.run_id)
        if network.get("Internal") is not True:
            raise Failure("fixture network must be internal")
        subnet = self.subnet = ipaddress.ip_network(network["IPAM"]["Config"][0]["Subnet"])
        if subnet.version != 4 or subnet.num_addresses < 16:
            raise Failure("fixture requires an owned IPv4 subnet with sufficient addresses")
        self.server_ip = str(subnet.network_address + 10)
        self.console_ip = str(subnet.network_address + 11)
        self.allowed_hosts = (self.server_ip, self.console_ip)
        for role in MOUNTS:
            name = docker("volume", "create", "--label", LABEL + "=" + self.run_id,
                          self.prefix + "-" + role).stdout.strip()
            self.volumes[role] = self.register("volume", name)
        self.server_mounts = []
        for role, target in MOUNTS.items():
            self.server_mounts += ["--mount", "type=volume,src=%s,dst=%s" % (self.volumes[role], target)]
        base_env = {"IRIS_SOAK_FIXTURE": "synthetic-isolated-v1", "IRIS_HOST_IP": self.server_ip,
                    "IRIS_SOAK_CONSOLE_IP": self.console_ip,
                    "IRIS_AGE_KEY_FILE": "/run/soak-keys/age.key"}
        def env_args(values):
            return [item for key, value in values.items() for item in ("--env", key + "=" + str(value))]
        boot_args = self.run_args("init", self.server_image, 1, "1g", boot=True)
        boot_args += self.server_mounts + env_args(base_env) + ["--user", "0:0", "--entrypoint", "python3"]
        boot = self.create(boot_args, self.manifest["images"]["server"],
                           ("/soak-fixture.py", "init", str(self.devices)))
        exit_code = docker("container", "wait", boot).stdout.strip()
        if exit_code != "0":
            raise Failure("fresh fixture initialization failed")
        self.copy(boot, "/run/soak-shared/recipient.pub", "recipient.pub")
        self.copy(boot, "/run/soak-keys/driver.json", "driver.json")
        self.copy(boot, "/run/soak-shared/browser.pem", "browser.pem")
        self.copy(boot, "/etc/iris/tls/crt.pem", "catalog.pem")
        self.server_env = dict(base_env, IRIS_AGE_RECIPIENTS=(self.directory / "recipient.pub").read_text(),
                               IRIS_MANAGEMENT_API_GENERATE_CERT="1",
                               IRIS_MANAGEMENT_API_TOKEN_FILE="/run/soak-shared/tier.token",
                               IRIS_MANAGEMENT_API_CA_EXPORT="/run/soak-shared/management.pem")
        self.env_args = env_args
        self.server = self.create_server()
        self.wait_management()
        args = self.run_args("console", self.console_image, 2, "2g")
        args += ["--ip", self.console_ip, "--mount",
                 "type=volume,src=%s,dst=/run/soak-shared,readonly" % self.volumes["shared"]]
        args += env_args({"IRIS_SOAK_FIXTURE": "synthetic-isolated-v1",
                          "IRIS_GUI_CERT": "/run/iris-console/cert.pem",
                          "IRIS_GUI_DEFAULT_CERT": "/run/soak-shared/browser.pem",
                          "IRIS_GUI_DEFAULT_KEY": "/run/soak-shared/browser.key",
                          "IRIS_MANAGEMENT_API_URL": "https://iris-server:9443",
                          "IRIS_MANAGEMENT_API_TOKEN_FILE": "/run/soak-shared/tier.token",
                          "IRIS_MANAGEMENT_API_CA": "/run/soak-shared/management.pem"})
        self.console = self.create(args, self.manifest["images"]["console"])
        self.console_url = self.url(self.console, "8080/tcp")
        self.catalog_url = self.url(self.server, "8443/tcp")
        self.manifest.update(console_url=self.console_url, catalog_url=self.catalog_url,
                             server_cpus=4, server_memory_bytes=4 * 1024**3,
                             console_cpus=2, console_memory_bytes=2 * 1024**3)
        self.save()
        self.wait_console()

    def create_server(self):
        args = self.run_args("server", self.server_image, 4, "4g")
        args += self.server_mounts + ["--network-alias", "iris-server", "--ip", self.server_ip]
        args += self.env_args(self.server_env)
        return self.create(args, self.manifest["images"]["server"])

    def url(self, container, port):
        row = self.inspect(container)
        if any(row["NetworkSettings"]["Ports"].values()):
            raise Failure("fixture must not publish host ports")
        networks = list(row["NetworkSettings"]["Networks"].values())
        if (len(networks) != 1 or networks[0]["NetworkID"] != self.network
                or networks[0]["IPAddress"] not in self.allowed_hosts
                or ipaddress.ip_address(networks[0]["IPAddress"]) not in self.subnet):
            raise Failure("fixture network identity differs")
        return "https://" + networks[0]["IPAddress"] + ":" + port.split("/")[0]

    def wait_management(self):
        # Readiness probes only; never retry a state-changing request.
        for _ in range(60):
            if not self.inspect(self.server)["State"]["Running"]:
                raise Failure("server exited before management became ready")
            result = docker("exec", self.server, "python3", "-c",
                            "import socket; s=socket.create_connection(('127.0.0.1',9443),1); s.close()",
                            check=False)
            if result.returncode == 0:
                return
            time.sleep(.5)
        raise Failure("management startup did not become ready")

    def wait_console(self):
        client = Client(self.console_url, str(self.directory / "browser.pem"), self.allowed_hosts)
        for _ in range(60):
            record, _ = client.request("GET", "/api/v1/session")
            if record["status"] in (200, 401):
                return
            time.sleep(.5)
        raise Failure("Console startup did not become ready")

    def monitor(self, enforce=True):
        now = time.monotonic()
        sample = {"elapsed_monotonic": now, "containers": {}}
        for role, identity, cpus, memory in (("server", self.server, 4, 4 * 1024**3),
                                            ("console", self.console, 2, 2 * 1024**3)):
            if not identity:
                continue
            state = self.inspect(identity)["State"]
            if state.get("OOMKilled") or not state.get("Running"):
                raise Failure(role + " stopped or was OOM-killed")
            counters = json.loads(self.fixture_command(identity, "resources"))
            cpu = dict(line.split() for line in counters["cpu.stat"].splitlines())
            previous = self.previous.get(role)
            fraction = 0 if previous is None else (
                int(cpu["usage_usec"]) - previous[1]) / (now - previous[0]) / 1e6 / cpus
            self.previous[role] = (now, int(cpu["usage_usec"]))
            counters["cpu_fraction"] = fraction
            counters["memory_fraction"] = int(counters["memory.current"]) / memory
            counters["pids_fraction"] = int(counters["pids.current"]) / 256
            sample["containers"][role] = counters
        meminfo = dict((line.split()[0].rstrip(":"), int(line.split()[1]))
                       for line in Path("/proc/meminfo").read_text().splitlines())
        sample["host_available_kib"] = meminfo["MemAvailable"]
        sample["host_total_kib"] = meminfo["MemTotal"]
        sample["disk_free_bytes"] = shutil.disk_usage(self.directory).free
        host_cpu = [int(v) for v in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
        host_previous = self.previous.get("host")
        total, idle = sum(host_cpu[:8]), host_cpu[3] + host_cpu[4]
        sample["host_cpu_fraction"] = (0 if host_previous is None else
                                       1 - (idle - host_previous[1]) / max(1, total - host_previous[0]))
        self.previous["host"] = (total, idle)
        self.samples.append(sample)
        self.resource_log.write(json.dumps(sample) + "\n")
        self.resource_log.flush()
        if sample["host_available_kib"] < 8 * 1024**2 or sample["disk_free_bytes"] < 5 * 1024**3:
            raise Failure("host memory/disk safety floor crossed")
        if sample["host_cpu_fraction"] > .85:
            raise Failure("host CPU safety ceiling crossed")
        if enforce and any(row["cpu_fraction"] > .8 or row["memory_fraction"] > .8 or row["pids_fraction"] > .8
                           for row in sample["containers"].values()):
            raise Failure("container 20% resource headroom exhausted")

    def resource_summary(self):
        result = {"samples": len(self.samples)}
        for role in ("server", "console"):
            rows = [sample["containers"][role] for sample in self.samples if role in sample["containers"]]
            if rows:
                result[role] = {"max_" + field: max(row[field] for row in rows)
                                for field in ("cpu_fraction", "memory_fraction", "pids_fraction", "fds", "threads")}
        if self.samples:
            result["max_host_cpu_fraction"] = max(sample["host_cpu_fraction"] for sample in self.samples)
            result["min_host_available_kib"] = min(sample["host_available_kib"] for sample in self.samples)
        return result

    def restart(self):
        for identity in (self.console, self.server):
            self.inspect(identity)
            docker("container", "stop", "--time", "30", identity)
        # Same volumes, same identities, fresh runtime tmpfs, no writes retried.
        docker("container", "start", self.server)
        self.wait_management()
        docker("container", "start", self.console)
        self.wait_console()
        self.previous.clear()

    def change_budget(self, total):
        # Recreate ONLY this owned server, preserving its own volumes. The
        # workload is stopped, so there are no in-flight writes to replay.
        self.inspect(self.console)
        docker("container", "stop", "--time", "30", self.console)
        self.inspect(self.server)
        docker("container", "stop", "--time", "30", self.server)
        docker("container", "rm", self.server)
        self.manifest.setdefault("retired_containers", []).append(self.server)
        self.resources["container"].remove(self.server)
        self.save()
        self.server_env.update(IRIS_API_RATE_TOTAL=str(total),
                               IRIS_API_RATE_READ=str(total),
                               IRIS_API_RATE_WRITE=str(total),
                               IRIS_API_BURST_TOTAL="2", IRIS_API_BURST_READ="2",
                               IRIS_API_BURST_WRITE="1")
        self.server = self.create_server()
        self.wait_management()
        docker("container", "start", self.console)
        self.wait_console()
        self.catalog_url = self.url(self.server, "8443/tcp")
        self.manifest["catalog_url"] = self.catalog_url
        self.save()
        self.previous.clear()

    def dependency_outage(self, workload):
        self.inspect(self.server)
        docker("container", "stop", "--time", "30", self.server)
        # Console stays live. This one expected read failure must not become a
        # retry policy, and is separate from an unexplained healthy-tier 503.
        record, problem = workload.clients[0].request("GET", "/api/v1/devices?limit=1")
        if (record["status"] != 503 or record["retry_after"] != "1"
                or not str(problem.get("type", "")).endswith("management-api-unavailable")):
            raise Failure("dependency outage did not produce the documented safe 503")
        docker("container", "start", self.server)
        self.wait_management()
        workload.login()
        result = workload.verify_durability()
        self.previous.clear()
        return {"expected_status": 503, "retry_after": 1, "durability": result}

    def cleanup(self):
        problems = []
        for kind in ("container", "volume", "network"):
            for identity in reversed(self.resources[kind]):
                try:
                    row = owned(kind, identity, self.run_id)
                    if kind == "container" and row["State"].get("Running"):
                        docker("container", "stop", "--time", "30", identity)
                    docker(kind, "rm", identity)
                except Failure as exc:
                    problems.append(str(exc))
        self.manifest["cleaned"] = not problems
        self.manifest["cleanup_failures"] = problems
        self.save()
        self.resource_log.close()
        # Credentials existed only for this fixture and are not evidence.
        (self.directory / "driver.json").unlink(missing_ok=True)
        return problems


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-image", required=True)
    parser.add_argument("--console-image", required=True)
    parser.add_argument("--devices", type=int, default=1000)
    parser.add_argument("--steps", default="2,5,10,15")
    parser.add_argument("--step-seconds", type=int, default=120)
    parser.add_argument("--soak-seconds", type=int, default=1800)
    parser.add_argument("--output", required=True, help="new directory under agentinfo")
    parser.add_argument("--accept-isolated-load", action="store_true")
    args = parser.parse_args(argv)
    args.rates = [float(v) for v in args.steps.split(",")]
    if (not args.accept_isolated_load or not 4 <= args.devices <= 1000
            or not 5 <= args.step_seconds <= 120 or not 5 <= args.soak_seconds <= 1800
            or not 1 <= len(args.rates) <= 4
            or any(not 0 < rate <= 15 for rate in args.rates)
            or args.rates != sorted(set(args.rates))):
        parser.error("explicit consent required; bounds: 4..1000 devices, 5..120s steps, 5..1800s soak, 1..4 increasing rates <=15/s")
    directory = Path(args.output).resolve()
    if not directory.is_relative_to(ROOT / "agentinfo") or directory == ROOT / "agentinfo" or directory.exists():
        parser.error("output must be a new child directory under agentinfo")
    args.directory = directory
    return args


def main(argv=None):
    args = arguments(argv)
    validate_host()
    os.umask(0o077)
    args.directory.mkdir(parents=True, mode=0o700)
    # Driver remains on one logical CPU. Docker daemon/service quotas are separate.
    driver_cpu = min(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {driver_cpu})
    fixture = Fixture(args.directory, args.server_image, args.console_image, args.devices)
    report = {"qualification": args.soak_seconds >= 1800 and args.step_seconds >= 120,
              "driver_logical_cpu": driver_cpu, "steps": [], "passed": False,
              "exclusions": ["device onboarding", "Cisco software authenticity", "WAN",
                             "Kubernetes", "multi-host", "large multi-GiB images"]}
    try:
        print("Creating isolated synthetic deployment", flush=True)
        fixture.start()
        credentials = json.loads((args.directory / "driver.json").read_text())
        workload = Workload(fixture.console_url, fixture.catalog_url,
                            str(args.directory / "browser.pem"), str(args.directory / "catalog.pem"),
                            credentials, fixture.allowed_hosts)
        workload.image = workload.upload()
        fixture.fixture_command(fixture.server, "assign", workload.image)
        fixture.monitor()
        selected = None
        for rate in args.rates:
            print("Step: %.2f Console requests/s for %ds" % (rate, args.step_seconds), flush=True)
            result = workload.phase(args.step_seconds, rate, fixture.monitor)
            report["steps"].append(result)
            if not result["passed"]:
                # A lower measured step may be selected only after operational
                # errors are ruled out; stop on every failed step for review.
                raise Failure("step failed; inspect safe result, no automatic downgrade")
            selected = rate
        print("Soak: %.2f Console requests/s for %ds" % (selected, args.soak_seconds), flush=True)
        report["soak"] = workload.phase(args.soak_seconds, selected, fixture.monitor)
        if not report["soak"]["passed"]:
            raise Failure("sustained workload failed")
        report["before_restart"] = workload.verify_durability()
        print("Checking clean restart and accepted-write durability", flush=True)
        fixture.restart()
        workload.login()
        report["after_restart"] = workload.verify_durability()
        report["content_after_restart"] = json.loads(fixture.fixture_command(fixture.server, "check-content"))
        report["recovery"] = workload.phase(min(30, args.soak_seconds), selected, fixture.monitor)
        if not report["recovery"]["passed"]:
            raise Failure("recovery workload failed")
        print("Checking management dependency outage and recovery", flush=True)
        report["dependency_recovery"] = fixture.dependency_outage(workload)
        budget = selected * .8
        print("Checking shared admission budgets and Retry-After", flush=True)
        fixture.change_budget(budget)
        workload.catalog = Client(fixture.catalog_url, str(args.directory / "catalog.pem"), fixture.allowed_hosts)
        # Login is not an admission-budget operation. Each browser session is
        # renewed after process restart, never copied across a server lifetime.
        workload.login()
        report["admission"] = workload.phase(min(30, args.soak_seconds), selected,
                                               fixture.monitor, overload=True)
        admitted = sum(row["statuses"].get("200", 0) for kind, row in
                       report["admission"]["metrics"].items() if kind in ("read", "write"))
        limited = sum(row["statuses"].get("429", 0) for row in report["admission"]["metrics"].values())
        if (not report["admission"]["passed"] or limited == 0
                or admitted > budget * report["admission"]["seconds"] + 2):
            raise Failure("aggregate admission/Retry-After qualification failed")
        fixture.change_budget(0)
        workload.catalog = Client(fixture.catalog_url, str(args.directory / "catalog.pem"), fixture.allowed_hosts)
        workload.login()
        report["after_admission"] = workload.verify_durability()
        report["highest_qualified_console_rps"] = selected
        report["capacity_ceiling_known"] = False
        report["suggested_total_budget_rps"] = .8 * selected
        report["suggested_read_budget_rps"] = .8 * .8 * selected
        report["suggested_write_budget_rps"] = .2 * .8 * selected
        report["passed"] = True
    except Exception as exc:
        report["failure"] = str(exc) if isinstance(exc, Failure) else type(exc).__name__
        report["failure_frames"] = [{"file": Path(frame.filename).name,
                                      "function": frame.name, "line": frame.lineno}
                                     for frame in traceback.extract_tb(exc.__traceback__)]
        print("Stopped: " + report["failure"], flush=True)
    finally:
        report["resource_summary"] = fixture.resource_summary()
        report["cleanup_failures"] = fixture.cleanup()
        if report["cleanup_failures"]:
            report["passed"] = False
        (args.directory / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Result: " + str(args.directory / "result.json"), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
