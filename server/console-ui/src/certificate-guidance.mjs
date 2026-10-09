// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

// Display-only guidance. Admission and response validation stay in the native
// lifecycle models; an observed file or a saved request is not live adoption.
const lookup = (map, key) => Object.hasOwn(map, key) ? map[key] : undefined;
const purposes = {
  'device-tls': ['Device connection certificate', 'Lets devices recognize the IRIS server when fetching instructions and images.', 'Plan replacement under Deployment keys below. Remove IRIS deployments, then onboard devices with the new certificate.'],
  'management-tls': ['Console-to-server certificate', 'Protects the private connection between the Console and IRIS server.', 'Use Deployment keys below. The worker updates Console trust and checks the connection during maintenance.'],
  'peer-ca': ['Private swarm certificate authority', 'Approves the short-lived certificates used for encrypted peer transfers.', 'Devices renew their own peer certificates. To replace this authority, use Deployment keys and re-onboard devices.'],
  'instruction-signer': ['Instruction signing certificate', 'Authorizes the server key that signs instructions for devices.', 'Use Renew signing certificate below to keep the current key. A root signing key holder must approve the request.'],
  'online-key': ['Server instruction signing key', 'Signs the instructions that devices verify before acting.', 'Renew its certificate for routine expiry. Use Replace signing key below when the key itself needs replacing.'],
};
export function certificateGuidance(row) {
  const known = lookup(purposes, row.id);
  if (known) return {title: known[0], purpose: known[1], next: known[2]};
  if (row.id.startsWith('root-')) return {title: row.label, purpose: 'Public trust used by devices to check signing approvals.',
    next: 'Ask this root signing key holder for signed confirmation under Deployment keys. Replacing the root requires new packages and re-onboarding.'};
  return {title: row.label, purpose: row.impact, next: 'Review this identity with the person responsible for its keys before making changes.'};
}
export function certificateState(state) {
  return lookup({unknown: 'Status unavailable', 'not-yet-valid': 'Not valid yet', expired: 'Expired',
    'signing-refused': 'Signing stopped', 'renewal-due': 'Renewal due', 'within-validity': 'Within validity dates',
    'public-key-present': 'Public key found'}, state) || 'Status unavailable';
}
export function signingHealth(state) {
  return lookup({ready: 'Current signing certificate and revocation list passed the recorded checks.',
    phase0: 'Instruction signing is not initialized. Complete signing setup before onboarding devices.',
    invalid: 'Signing checks failed. Review instruction signing diagnostics before continuing.',
    signing_refused: 'New instruction signing is stopped. Renew the signing certificate.',
    keylist_missing: 'A signed revocation list is missing. Ask a root signing key holder to approve it.',
    renewal_due: 'The signing certificate is due for renewal. Ask a root signing key holder to approve a new certificate.'}, state)
    || 'Signing status is unavailable. Refresh and check the server connection.';
}
export function signerGuidance(state) {
  return lookup({idle: ['No replacement in progress', 'For routine certificate expiry, use renewal above. To change the key, prepare a replacement.'],
    'awaiting-approval': ['Waiting for a root key holder', 'Download the replacement public key and obtain its signed certificate. The current key remains active.'],
    committing: ['Key switch needs review', 'Publication is incomplete. Refresh the request and check signing diagnostics before continuing.'],
    'retirement-pending': ['New key active; old key retirement needed', 'Download a retirement request. The selected root key holder must approve revoking the old key.'],
    retiring: ['Old key retirement needs review', 'Refresh the request. Re-submit the matching approval only after checking the current revocation list.'],
    completed: ['Replacement published', 'The old key revocation is published. Verify fresh signed instructions and the updated revocation list on your devices.'],
    cancelled: ['Replacement cancelled', 'The active key is unchanged. You can prepare another replacement when needed.']}, state)
    || ['Replacement status unavailable', 'Refresh before changing the signing key.'];
}
export function browserGuidance(state) {
  return lookup({idle: ['No replacement in progress', 'Enter the addresses people use to open this Console. IRIS will create a new key and public approval request.'],
    'awaiting-approval': ['Waiting for your certificate authority', 'Download the public request. Ask your certificate authority to sign it, then import the approved certificate.'],
    approved: ['Approved certificate ready to apply', 'Check the names and browser trust, then apply the certificate. The current browser certificate is still active.'],
    committing: ['Certificate publication needs recovery', 'Recover the approved publication, then verify a new trusted browser connection.'],
    published: ['Certificate saved; verify browser access', 'Check the reload result below. Verify a new trusted connection to every Console; saved files alone do not prove it is serving the new certificate.'],
    cancelled: ['Replacement cancelled', 'The active browser certificate is unchanged. You can create another request.']}, state)
    || ['Replacement status unavailable', 'Refresh the request before changing the browser certificate.'];
}
export const deploymentGuidance = {
  'management-tls': ['Console connection to the server', 'The worker replaces the internal HTTPS key and certificate, updates Console trust and checks each Console connection. Plan downtime.'],
  'device-tls': ['Device connections to the server', 'Remove existing IRIS deployments first. Prepare the certificate, have your certificate authority approve it if selected, then run maintenance and onboard devices again.'],
  'peer-ca': ['Encrypted transfers between peers', 'This authority issues peer certificates. Remove existing IRIS deployments, prepare a replacement authority, then run maintenance and onboard devices again.'],
  'instruction-roots': ['Approval of instruction signing keys', 'Root key holders provide the replacement public keys and signed approvals. Remove IRIS deployments before maintenance; the worker rebuilds packages for re-onboarding.'],
  'age-identity': ['Encrypted server settings and secrets', 'The worker replaces the server encryption key. The separate backup recovery key stays unchanged; older backups still need their original keys. Plan downtime.'],
  'seeder-announce': ['Seeder access to the tracker', 'The worker replaces the credential the server uses to join image swarms, then checks that images are being served. Published active torrents are required. Plan downtime.'],
};
export function trustState(state) {
  return lookup({idle: 'No replacement prepared', 'awaiting-approval': 'Waiting for signed approval', approved: 'Approval checked; ready for maintenance',
    committing: 'Publication needs recovery', published: 'Replacement trust published; verify device adoption', cancelled: 'Replacement cancelled'}, state)
    || 'Replacement status unavailable';
}
