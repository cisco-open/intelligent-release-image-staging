# How to Contribute

Thanks for your interest in contributing to `intelligent-release-image-staging`! Here are a few
general guidelines on contributing and reporting bugs that we ask you to review.
Following these guidelines helps to communicate that you respect the time of the
contributors managing and developing this open source project. In return, they
should reciprocate that respect in addressing your issue, assessing changes, and
helping you finalize your pull requests. In that spirit of mutual respect, we
endeavor to review incoming issues and pull requests within 10 days, and will
close any lingering issues or pull requests after 60 days of inactivity.

Please note that all of your interactions in the project are subject to our
[Code of Conduct](/CODE_OF_CONDUCT.md). This includes creation of issues or pull
requests, commenting on issues or pull requests, and extends to all interactions
in any real-time space e.g., Slack, Discord, etc.

## Reporting Issues

Before reporting a new issue, please ensure that the issue was not already
reported or fixed by searching through our [issues
list](https://github.com/cisco-open/intelligent-release-image-staging/issues).

When creating a new issue, please be sure to include a **title and clear
description**, as much relevant information as possible, and, if possible, a
test case.

**If you discover a security bug, please do not report it through GitHub.
Instead, please see security procedures in [SECURITY.md](/SECURITY.md).**

## Sending Pull Requests

Before sending a new pull request, take a look at existing pull requests and
issues to see if the proposed change or fix has been discussed in the past, or
if the change was already implemented but not yet released.

We expect new pull requests to include tests for affected behavior and an entry
under `CHANGELOG.md` → `Unreleased` for operator-visible changes. The project
uses calendar versioning (`YYYY.0M.0D`, with an optional same-day `.MICRO`
suffix), not semantic versioning; maintainers decide when accumulated changes
are cut into a dated release.

## Other Ways to Contribute

We welcome anyone that wants to contribute to `intelligent-release-image-staging` to triage and
reply to open issues to help troubleshoot and fix existing bugs. Here is what
you can do:

- Help ensure that existing issues follows the recommendations from the
  _[Reporting Issues](#reporting-issues)_ section, providing feedback to the
  issue's author on what might be missing.
- Review and update the reference documentation under `docs/zensical/`; build
  or preview it with the Zensical commands in
  [DEVELOPMENT.md](DEVELOPMENT.md).
- Review existing pull requests, and testing patches against real existing
  applications that use `intelligent-release-image-staging`.
- Write a test, or add a missing test case to an existing test.

Thanks again for your interest on contributing to `intelligent-release-image-staging`!

:heart:

---

For development setup and contribution workflows, see
[DEVELOPMENT.md](DEVELOPMENT.md); for running the test suites, see
[TESTING.md](TESTING.md).
