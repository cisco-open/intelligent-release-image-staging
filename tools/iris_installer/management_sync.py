# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Bind host-side token publication to an existing public maintenance intent."""

import json
import re
import uuid

from .state import InstallError


def validate_operation(install, operation_id):
    """Read a committed intent without acquiring the scheduler's held lock.

    Atomic state publication plus the credential fingerprint bind the export;
    no private token is returned by this validation. The caller must check again
    after proving every owned Console consumer.
    """
    try:
        if str(uuid.UUID(operation_id)) != operation_id:
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise InstallError('Choose a canonical management operation ID') from None
    code = '''import hashlib,json,os,sys
import key_maintenance,tier_auth
request=sys.argv[1]
jobs=[j for j in key_maintenance.Maintenance().load()['jobs'] if j['id']==request]
if len(jobs)!=1: raise RuntimeError('unknown operation')
j=jobs[0]
if j['family']!='management-token' or j['state'] not in ('running','verification-required','intervention-required','completed') or not j['before'] or not j['after']: raise RuntimeError('unapproved operation')
c,p=tier_auth.load_pair(os.environ['IRIS_MANAGEMENT_API_TOKEN_FILE'],os.environ.get('IRIS_MANAGEMENT_API_PREVIOUS_TOKEN_FILE'))
fingerprint=hashlib.sha256(c).hexdigest()
if fingerprint!=j['after'] or fingerprint==j['before'] or (p is not None and hashlib.sha256(p).hexdigest()!=j['before']): raise RuntimeError('credential authority changed')
if p is None and j['state'] not in ('verification-required','completed'): raise RuntimeError('overlap missing')
print(json.dumps({'request_id':request,'current_sha256':fingerprint}))
'''
    result = json.loads(install.python(code, operation_id))
    if (not isinstance(result, dict) or set(result) != {'request_id', 'current_sha256'}
            or result['request_id'] != operation_id
            or not isinstance(result['current_sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', result['current_sha256'])):
        raise InstallError('Management operation authority could not be established')
    return result
