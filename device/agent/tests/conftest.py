# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Put device/agent/ and device/ on sys.path so tests can `import catalog_client`,
`import verify_image`, etc. — the flat-import style used across this repo."""
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_here))                       # device/agent/
sys.path.insert(0, os.path.dirname(os.path.dirname(_here)))      # device/
