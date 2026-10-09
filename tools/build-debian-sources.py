#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Assemble or independently validate local Debian image source-only evidence."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from iris_installer.debian_sources import build_sources, load_index_inputs, validate_source_archive
from iris_installer.state import InstallError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--inventory-sha256', required=True, help='Externally reviewed inventory digest')
    parser.add_argument('--keyring', type=Path, required=True, help='Independent trusted Debian archive keyring')
    parser.add_argument('--indexes', type=Path)
    parser.add_argument('--source-pool', type=Path)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--out', type=Path)
    action.add_argument('--verify-bundle', type=Path)
    parser.add_argument('--archived-integrity', action='store_true',
                        help='Verify retained source integrity past repository expiry; requires --verify-bundle')
    args = parser.parse_args()
    if args.archived_integrity and args.verify_bundle is None:
        parser.error('--archived-integrity requires --verify-bundle and cannot produce a new companion')
    try:
        if args.verify_bundle is not None:
            if args.indexes is not None or args.source_pool is not None:
                parser.error('--verify-bundle uses bundled evidence and independently supplied inventory/keyring')
            manifest = validate_source_archive(args.verify_bundle, args.inventory, args.inventory_sha256,
                                               keyring=args.keyring, archived_integrity=args.archived_integrity)
            result = {'inventory_sha256': manifest['inventory_sha256'], 'sources': len(manifest['sources']),
                      'scope': 'debian-source-only', 'source_coverage_complete': False,
                      'verification_mode': 'archived-integrity' if args.archived_integrity else 'current-metadata'}
        else:
            if args.indexes is None or args.source_pool is None:
                parser.error('--out requires --indexes and --source-pool')
            result = build_sources(args.inventory, args.inventory_sha256, load_index_inputs(args.indexes),
                                   args.source_pool, args.out, keyring=args.keyring)
        print(json.dumps(result, sort_keys=True))
    except (InstallError, OSError, ValueError) as error:
        parser.exit(1, 'Debian source producer: ' + str(error) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
