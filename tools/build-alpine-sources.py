#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Collect exact local Alpine source inputs without running package recipes."""

from iris_installer.alpine_sources import main


if __name__ == '__main__':
    raise SystemExit(main())
