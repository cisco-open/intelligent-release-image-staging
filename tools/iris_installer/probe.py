# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Read-only native-package probe, executed inside the selected server runtime.

This is intentionally usable on existing images: the launcher streams this
module over stdin, without copying files or installing software in the target.
It reuses the server's provenance implementation, not a second manifest parser.
"""

import json
import os
import sys


SCOPE = "native-package-readability-and-provenance"
PACKAGES = (
    ("iris-amd64.tar", "iox", "linux/amd64", "tools/provision-iox-packages.sh"),
    ("iris-arm64.tar", "iox", "linux/arm64", "tools/provision-iox-packages.sh"),
    ("iris-xr.rpm", "xr-appmgr", "linux/amd64", "tools/build-xr-package.sh"),
)


def collect(artifacts_dir, *, optional_xr=False):
    """Return evidence, never whole-installation READY or private file contents."""
    import setup_status

    report = {
        "schema_version": 1,
        "scope": SCOPE,
        "state": "checks-failed",
        "runtime_uid": os.geteuid(),
        "runtime_gid": os.getegid(),
        "packages": [],
        "catalog_certificate": {"state": "unknown", "fingerprint": None},
    }
    # Both shipped adapters use this service identity. Root-readable evidence
    # cannot establish whether onboarding can open a package.
    if (report["runtime_uid"], report["runtime_gid"]) != (10001, 10001):
        report["reason"] = "unexpected-runtime-identity"
        return report
    for name, kind, platform, remedy in PACKAGES:
        item = setup_status.package_readiness(
            os.path.join(artifacts_dir, name), name, kind, platform, remedy)
        item["required"] = not (optional_xr and name == "iris-xr.rpm")
        report["packages"].append(item)
    fingerprint = setup_status.read_pem_fingerprint(
        os.path.join(artifacts_dir, "iris-catalog.pem"))
    report["catalog_certificate"] = {
        "state": "ok" if fingerprint else "unknown",
        "fingerprint": fingerprint,
    }
    if fingerprint and all(
        item["state"] == "ok" or (not item["required"] and item["state"] == "absent")
        for item in report["packages"]
    ):
        report["state"] = "checks-passed"
    return report


def main():
    sys.path.insert(0, "/opt/iris/server")
    try:
        report = collect(
            os.environ.get("IRIS_ARTIFACTS_DIR", "/srv/artifacts"),
            optional_xr=sys.argv[1:] == ["--optional-xr"],
        )
    except Exception:
        # Do not reflect arbitrary target errors or paths into support output.
        report = {"schema_version": 1, "scope": SCOPE,
                  "state": "checks-failed", "reason": "runtime-probe-failed"}
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
