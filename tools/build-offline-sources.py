#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Assemble a deterministic Ubuntu source/notices companion from local inputs.

Index descriptors are locators, not trust authority. The producer authenticates
every index and exact source byte itself. No network fetch, install, recipe
execution or release publication occurs.
"""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from iris_installer.offline_sources import build_sources, load_index_inputs, validate_source_archive
from iris_installer.state import InstallError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary-closure', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--indexes', type=Path,
                        help='iris-ubuntu-source-inputs-v1 local index descriptor JSON')
    parser.add_argument('--source-pool', type=Path,
                        help='Local mirror root containing signed pool/... source file paths')
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--out', type=Path, help='Exclusive output .tar.gz path')
    action.add_argument('--verify-bundle', type=Path, help='Independently validate an existing companion against its binary closure')
    args = parser.parse_args()
    try:
        if args.verify_bundle is not None:
            if args.indexes is not None or args.source_pool is not None:
                parser.error('--verify-bundle uses only the binary closure and bundled source evidence')
            manifest = validate_source_archive(args.verify_bundle, args.binary_closure, args.manifest_sha256)
            result = {'binary_manifest_sha256': manifest['binary_manifest_sha256'],
                      'sources': len(manifest['sources']), 'binaries': len(manifest['binaries']), 'coverage_verified': True}
        else:
            if args.indexes is None or args.source_pool is None:
                parser.error('--out requires --indexes and --source-pool')
            result = build_sources(args.binary_closure, args.manifest_sha256,
                                   load_index_inputs(args.indexes), args.source_pool, args.out)
        print(json.dumps(result, sort_keys=True))
    except (InstallError, OSError, ValueError) as error:
        parser.exit(1, 'Offline source producer: ' + str(error) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
