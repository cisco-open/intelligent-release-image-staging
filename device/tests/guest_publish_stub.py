#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Installer test boundary; validate real requests without contacting a device.

The prompt-aware transport itself has separate tests. This scratch-tree helper
uses its real request validator and marker, not the old device-run.sh path.
"""
import importlib.util
import json
import os
from pathlib import Path
import sys


def main():
    spec = importlib.util.spec_from_file_location(
        "actual_guest_publish_request", os.environ["IRIS_TEST_GUEST_PUBLISH_SOURCE"]
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    args = sys.argv[1:]
    if len(args) != 11:
        raise module.PublicationError("invalid-request")
    _, marker = module.request(args[0], args[1], args[2], args[3:])
    if log := os.environ.get("IRIS_TEST_GUEST_PUBLISH_LOG"):
        with Path(log).open("a") as stream:
            stream.write(json.dumps(args) + "\n")
    outcome = os.environ.get("IRIS_TEST_GUEST_PUBLISH_RESULT", "published")
    if outcome == "failed":
        print("ERROR: Guest Shell publication not proved", file=sys.stderr)
        return 1
    if outcome == "missing":
        return 0
    if outcome not in ("published", "duplicate"):
        raise ValueError("Unknown test publication result")
    print(marker)
    if outcome == "duplicate":
        print(marker)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
