#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

version=5.32.15
archive_sha512=4d214447eac54257f59f393a5af2a431a1d3c403d0dde000c628054e19f141e7524446a77d98126c915ac9956cfd42e749b35dac939bf7dbcb0fac696f74777a
archive_sha1=0bbaa62695104dbf2db06ad9bbbaaa127d830614
source_url="https://registry.npmjs.org/swagger-ui-dist/-/swagger-ui-dist-${version}.tgz"
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destination="${repo_root}/docs/zensical/swagger"
archive=$(mktemp)
trap 'rm -f "$archive"' EXIT

curl --fail --silent --show-error --location --output "$archive" "$source_url"
printf '%s  %s\n' "$archive_sha512" "$archive" | sha512sum --check --status
printf '%s  %s\n' "$archive_sha1" "$archive" | sha1sum --check --status

mkdir -p "$destination"
tar -xzf "$archive" --strip-components=1 --directory "$destination" \
  package/swagger-ui.css \
  package/swagger-ui-bundle.js \
  package/swagger-ui-bundle.js.LICENSE.txt \
  package/LICENSE \
  package/NOTICE \
  package/package.json

printf 'updated Swagger UI %s in %s\n' "$version" "$destination"
