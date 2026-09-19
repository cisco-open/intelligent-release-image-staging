<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

SPDX-License-Identifier: Apache-2.0
-->

# Developer documentation

This folder holds the material addressed to a contributor or a maintainer:
how the documentation is written and built, how packages are produced, what a
test proves, and the records of lab runs. It is for anyone changing this
repository, not for someone running IRIS.

## How this relates to the site

`docs/zensical/` is the user manual. Zensical builds it and CI publishes it at
<https://cisco-open.github.io/intelligent-release-image-staging/docs/>.

`docs/dev/` is not part of that site. It sits outside `docs_dir`, so Zensical
never reads it, the build never copies it into `site/` or `deploy/`, and
nothing here is published. Read these pages in the repository or on GitHub.

The release tarball is the exception: `tools/make-release.sh` ships the whole
tracked `docs/` tree, so a recipient unpacking a release gets this folder too.

## What is here

| Page | What it covers |
| --- | --- |
| [documentation.md](documentation.md) | Writing and building the manual: the writing standard, heading aliases, redirect stubs, pinned tool versions, and what the documentation tests check. |

More pages land here as developer material moves off the site.

## Related material in the repository root

- [DEVELOPMENT.md](../../DEVELOPMENT.md): setting up a checkout, building the
  server and device packages, and the day-to-day development loop.
- [TESTING.md](../../TESTING.md): the test suites, what each one proves, and
  how to run them.
- [CONTRIBUTING.md](../../CONTRIBUTING.md): reporting issues, sending a pull
  request, and the CHANGELOG entry a change is expected to carry.
