# Development

This document covers project-specific development setup, conventions, and the
release process for **intelligent-release-image-staging**. For how to report
issues and send pull requests, see [CONTRIBUTING.md](CONTRIBUTING.md); for
running the test suites, see [TESTING.md](TESTING.md).

## Project scope

The project only **distributes and STAGES** IOS-XE images to `flash:` across a
Catalyst 9300 fleet. It **never installs, activates, or reloads** anything — that
remains an explicit, human-driven operation outside the system. Contributions must
respect this hard invariant: please do not add code, automation, or documentation
that installs, activates, reloads, or otherwise mutates the running/booted
software state of a device.

## Development setup

1. **Clone the repository:**
   ```
   git clone https://github.com/cisco-open/intelligent-release-image-staging.git
   cd intelligent-release-image-staging
   ```
2. **Prerequisites:**
   - **Python 3** with **pytest** (for the Python test suite)
   - **bats** (for the shell test suite)
   - **Docker** and **Docker Compose** (for the server stack)
3. **Run the server stack** (tracker / catalog / seeder) locally with Docker
   Compose:
   ```
   cd server/
   docker compose up
   ```

## Commit message format

Keep commit messages light and consistent with the repo's existing style: a
clear, concise, **imperative** subject line (e.g., "Add flash reclaim guard"),
with an optional body explaining the *why* when it isn't obvious. Conventional
Commits are **not** required.

For changes that ship (a release-worthy change):

- Add a **`CHANGELOG.md`** entry describing the change.
- **Bump the `VERSION` file** using CalVer: `YYYY.0M.0D` with an optional
  `.MICRO` (`1`, `2`, …) for multiple releases on the same day
  (e.g., `2026.06.11`, then `2026.06.11.1`).
- Releases are **tagged** `vYYYY.0M.0D`. Keep `VERSION`, `CHANGELOG.md`, and the
  tag in sync.

## License headers

The project is licensed under the **Apache License, Version 2.0** (see
[LICENSE](LICENSE) and [NOTICE](NOTICE)). Every source file carries a short SPDX
header rather than repeating the full license block.

Each source file must carry, after any shebang line:

```
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
```

Copy that block verbatim into any new source file (adjusting the comment
character to match the file's syntax). Non-source assets and files that can't
carry an inline comment header — for example IOS-XE EEM `.cfg` applets and
systemd `.service` units — are left unannotated; they inherit the repository's
Apache-2.0 license.
