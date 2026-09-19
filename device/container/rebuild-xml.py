#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0
"""Rebuild CPython's paired XML extensions against its upstream Expat backport."""
import pathlib
import shlex
import shutil
import subprocess
import sys
import sysconfig

if sys.version_info[:3] != (3, 12, 14):
    raise SystemExit("XML backport requires the pinned CPython 3.12.14 ABI")
source = pathlib.Path('/src/Python-3.12.14')
out = pathlib.Path('/out')
out.mkdir()
include = pathlib.Path(sysconfig.get_path('include'))
# Keep this interpreter's upstream module flags, replacing only build-tree
# include paths with the installed, architecture-matched headers and config.
flags = []
for key in ('CFLAGS', 'PY_CFLAGS_NODIST', 'CCSHARED'):
    flags.extend(arg for arg in shlex.split(sysconfig.get_config_var(key) or '')
                 if not arg.startswith('-I'))
flags += ['-I' + str(include), '-I' + str(include / 'internal'),
          '-I' + str(source / 'Modules/expat'), '-I' + str(source / 'Modules')]
suffix = sysconfig.get_config_var('EXT_SUFFIX')
for name, units in (
    ('pyexpat', ['pyexpat.c', 'expat/xmlparse.c', 'expat/xmlrole.c', 'expat/xmltok.c']),
    ('_elementtree', ['_elementtree.c']),
):
    target = out / (name + suffix)
    subprocess.run(shlex.split(sysconfig.get_config_var('LDSHARED')) + flags +
                   [str(source / 'Modules' / unit) for unit in units] +
                   ['-o', str(target), '-lm'], check=True)
    subprocess.run(['strip', '--strip-unneeded', str(target)], check=True)
    shutil.copy2(target, pathlib.Path(sysconfig.get_config_var('DESTSHARED')) / target.name)
# _elementtree checks the exact Expat micro-version in pyexpat's C capsule:
# rebuilding only pyexpat would silently disable the standard-library accelerator.
subprocess.run([sys.executable, '-c',
    'import pyexpat, _elementtree, xml.etree.ElementTree as E; '
    'assert pyexpat.version_info == (2, 8, 4); '
    'assert E.XMLParser is _elementtree.XMLParser; '
    'assert E.fromstring("<root/>").tag == "root"'], check=True)
shutil.copy2(source / 'LICENSE', out / 'PYTHON-LICENSE')
shutil.copy2(source / 'Modules/expat/COPYING', out / 'EXPAT-COPYING')
