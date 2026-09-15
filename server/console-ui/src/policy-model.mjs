// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Role intent only: quarantine and explicit device/server ACLs can further
// restrict a real pair. This is not a device compliance claim.
export function roleAllows(definitions, from, to) {
  if (!Object.hasOwn(definitions, from) || !Object.hasOwn(definitions, to)) return false;
  const role = definitions[from];
  return role.restricted !== true || from === to || (role.peers || []).includes(to);
}

export function roleConnections(definitions, name) {
  return Object.keys(definitions).sort().filter(peer =>
    roleAllows(definitions, name, peer) && roleAllows(definitions, peer, name));
}

export function distributionAllowed(role) {
  // An unrestricted role has no virtual ACL, so origin=false is ignored.
  return role.restricted !== true || role.origin !== false;
}

export function enforcementLabel(policy, ready) {
  if (!ready || !policy.enforcement) return 'Unavailable';
  if (policy.enforcement.stale !== false) return 'Not current';
  return {enforced: 'Enforced', degraded: 'Partly enforced', pending: 'Pending',
    rpc_unavailable: 'Transfer service unavailable', fail_closed: 'Fail closed'}[policy.enforcement.state] || 'Unavailable';
}
