#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Assemble or validate local core CPython/pip source and notice evidence."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from iris_installer.core_python_sources import build_sources, validate_source_archive
from iris_installer.state import InstallError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--inventory-sha256', required=True)
    parser.add_argument('--server-config', type=Path, required=True)
    parser.add_argument('--console-config', type=Path, required=True)
    parser.add_argument('--pip-sdist-sha256', required=True, help='Explicit external caller pin, not companion authority')
    parser.add_argument('--source-pool', type=Path)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--out', type=Path)
    action.add_argument('--verify-bundle', type=Path)
    args = parser.parse_args()
    configs = {'server-image': args.server_config, 'console-image': args.console_config}
    try:
        if args.verify_bundle is not None:
            if args.source_pool is not None:
                parser.error('--verify-bundle uses bundled sources and independent inventory/configuration/pip pins')
            manifest = validate_source_archive(args.verify_bundle, args.inventory, args.inventory_sha256,
                                               configs, pip_sdist_sha256=args.pip_sdist_sha256)
            result = {'inventory_sha256': manifest['inventory_sha256'], 'scope': manifest['scope'],
                      'source_coverage_complete': False}
        else:
            if args.source_pool is None:
                parser.error('--out requires --source-pool')
            result = build_sources(args.inventory, args.inventory_sha256, configs, args.source_pool,
                                   args.out, pip_sdist_sha256=args.pip_sdist_sha256)
        print(json.dumps(result, sort_keys=True))
    except (InstallError, OSError, ValueError) as error:
        parser.exit(1, 'Core Python source producer: ' + str(error) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
