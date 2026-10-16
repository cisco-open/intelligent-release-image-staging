// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export const CISCO_CA = 'https://www.cisco.com/security/pki/trs/ios.p7b';
export const MOZILLA_CA = 'https://curl.se/ca/cacert.pem';
export const SETTINGS_LIMIT = 64 * 1024;
export const object = value => !!value && typeof value === 'object' && !Array.isArray(value);
export const count = value => Number.isSafeInteger(value) && value >= 0;
const text = value => typeof value === 'string';
const bool = value => typeof value === 'boolean';
export const pemCertificate = value => /-----BEGIN CERTIFICATE-----/.test(value);
export const pemKey = value => /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(value);
export const encryptedKey = value => value.includes('ENCRYPTED PRIVATE KEY') || value.includes('Proc-Type: 4,ENCRYPTED');
export function pemFileFields(value) {
  const certificates = value.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  const keys = [...value.matchAll(/-----BEGIN ([A-Z ]*PRIVATE KEY)-----[\s\S]*?-----END \1-----/g)].map(match => match[0]);
  if (keys.length > 1) throw Error('Choose a file with only one private key.');
  return {pem: certificates.length ? certificates.join('\n') + '\n' : '', key: keys[0] || ''};
}
export const trustName = value => text(value) && value.endsWith('.pem') && !/[\/\\\0]/.test(value) && value.length <= 255;
export const trustEntry = value => object(value) && trustName(value.name) && count(value.cert_count) && value.cert_count > 0
  && ['manual', 'downloaded'].includes(value.source);
export const jobId = value => text(value) && /^[a-zA-Z0-9._-]{1,128}$/.test(value);
export const initialForms = () => ({pw: {current: '', next: '', confirm: ''}, cert: {pem: '', key: '', passphrase: ''}, trust: {pem: ''},
  ca: {source: 'cisco', url: '', auto: false}, td: {endpoint: '', enabled: false},
  ae: {host: '', port: '22', user: '', path: '', recipient: '', password: '', auto: false}, peer: {required: false}});
export function settingsValidity(s) {
  if (!object(s)) return {};
  return {
    general: text(s.version) && text(s.admin_username) && object(s.ports) && ['tracker', 'catalog', 'artifacts', 'swarm', 'console'].every(key => Number.isInteger(s.ports[key]) && s.ports[key] > 0 && s.ports[key] <= 65535)
      && object(s.sessions) && count(s.sessions.active) && count(s.sessions.idle_ttl_minutes),
    tls: object(s.gui_cert) && Array.isArray(s.trust) && s.trust.every(trustEntry) && object(s.ca_trust) && text(s.ca_trust.url) && bool(s.ca_trust.auto),
    telemetry: object(s.telemetry_destination) && ['env', 'environment', 'override'].includes(s.telemetry_destination.source)
      && text(s.telemetry_destination.effective_endpoint) && bool(s.telemetry_destination.effective_enabled),
    audit: object(s.audit_export) && ['host', 'user', 'path', 'age_recipient'].every(key => text(s.audit_export[key]))
      && Number.isInteger(s.audit_export.port) && s.audit_export.port > 0 && s.audit_export.port <= 65535
      && bool(s.audit_export.auto) && bool(s.audit_export.password_set),
  };
}
export function formsFromSettings(s) {
  const valid = settingsValidity(s), forms = {};
  if (valid.tls) {const ca = s.ca_trust; forms.ca = {source: !ca.url || ca.url === CISCO_CA ? 'cisco' : ca.url === MOZILLA_CA ? 'mozilla' : 'custom', url: ca.url, auto: ca.auto};}
  if (valid.telemetry) forms.td = {endpoint: s.telemetry_destination.effective_endpoint, enabled: s.telemetry_destination.effective_enabled};
  if (valid.audit) {const ae = s.audit_export; forms.ae = {host: ae.host, port: String(ae.port), user: ae.user, path: ae.path, recipient: ae.age_recipient, auto: ae.auto, password: ''};}
  return forms;
}
export function checkedPeer(data) {
  return object(data) && ['required', 'disabled'].includes(data.mode) && bool(data.can_change) && object(data.origin)
    && text(data.origin.state) && (data.origin.active_mode === null || ['required', 'disabled'].includes(data.origin.active_mode))
    && count(data.active_devices) && count(data.active_jobs);
}
export const actionGroup = action => ({certDefault: 'cert', trustDelete: 'trust', caRun: 'ca', tdDefault: 'td', aeRun: 'ae', aeClear: 'ae'}[action] || action);
export const groupPane = group => ({pw: 'general', revoke: 'general', cert: 'tls', trust: 'tls', ca: 'tls', td: 'telemetry', ae: 'audit', peer: 'tls'}[group]);
export function settingsBody(value) {
  const body = JSON.stringify(value);
  if (new TextEncoder().encode(body).length > SETTINGS_LIMIT) throw Error('This settings request exceeds 64 KiB. Reduce the input before submitting.');
  return body;
}
function endpoint(value, httpsOnly = false) {
  const raw = value.trim().replace(/\/+$/, '');
  if (!raw) return null;
  try {const u = new URL(raw); if (!(httpsOnly ? u.protocol === 'https:' : ['https:', 'http:'].includes(u.protocol)) || !u.hostname || u.username || u.password || u.search || u.hash) throw Error();}
  catch {throw Error('Use an ' + (httpsOnly ? 'HTTPS' : 'HTTP or HTTPS') + ' URL without credentials, query parameters or fragments.');}
  return raw;
}
export function settingsRequest(action, state, name) {
  const f = state.forms, group = actionGroup(action);
  let path, body, method = 'POST', confirmation = '';
  switch (action) {
    case 'pw':
      if (f.pw.next.length < 8) throw Error('New password must be at least 8 characters.');
      if (f.pw.next !== f.pw.confirm) throw Error('Passwords do not match.');
      path = 'password'; body = {current: f.pw.current, new: f.pw.next, confirm: f.pw.confirm}; break;
    case 'revoke': path = 'sessions/revoke-others'; body = {}; break;
    case 'cert':
      if (!pemCertificate(f.cert.pem)) throw Error('Certificate PEM is required.');
      if (pemKey(f.cert.pem)) throw Error('Put private key material only in the Private key PEM field.');
      if (!pemKey(f.cert.key)) throw Error('Private key PEM is required.');
      body = {cert_pem: f.cert.pem.trim(), key_pem: f.cert.key.trim()};
      if (encryptedKey(body.key_pem)) {if (!f.cert.passphrase) throw Error('Enter the passphrase for this encrypted private key.'); body.key_passphrase = f.cert.passphrase;}
      path = 'gui-cert'; break;
    case 'certDefault': path = 'gui-cert'; method = 'DELETE'; confirmation = 'Use the default Console certificate? The uploaded certificate and key will be removed. New connections use the default; open sessions continue.'; break;
    case 'trust': if (!pemCertificate(f.trust.pem) || pemKey(f.trust.pem)) throw Error('Paste public CA certificate blocks only, without a private key.'); path = 'trust'; body = {pem: f.trust.pem.trim()}; break;
    case 'trustDelete':
      if (!trustName(name) || !state.data.trust.some(entry => entry.name === name)) throw Error('This CA is unavailable. Refresh before removing it.');
      path = 'trust/' + encodeURIComponent(name); method = 'DELETE'; confirmation = 'Remove trusted CA ' + name + '? New connections will no longer trust it. Telemetry export and CA downloads may fail.'; break;
    case 'ca':
      if (!['cisco', 'mozilla', 'custom'].includes(f.ca.source)) throw Error('Choose a CA bundle source.');
      body = {url: f.ca.source === 'cisco' ? null : f.ca.source === 'mozilla' ? MOZILLA_CA : endpoint(f.ca.url, true), auto: f.ca.auto};
      if (f.ca.source === 'custom' && !body.url) throw Error('Enter a custom HTTPS bundle URL.');
      path = 'ca-trust'; break;
    case 'caRun': path = 'ca-trust/refresh'; body = {}; break;
    case 'td':
      body = {endpoint: endpoint(f.td.endpoint), enabled: f.td.enabled};
      if (body.enabled && !body.endpoint) throw Error('An endpoint is required when export is enabled.');
      path = 'telemetry-destination'; break;
    case 'tdDefault': path = 'telemetry-destination'; method = 'DELETE'; confirmation = 'Use the default telemetry destination? This removes the Console override. Telemetry uses deployment settings from the next sample.'; break;
    case 'ae': {
      const port = f.ae.port.trim(); body = {host: f.ae.host.trim(), port: port ? Number(port) : 22, user: f.ae.user.trim(), path: f.ae.path.trim(), age_recipient: f.ae.recipient.trim(), auto: f.ae.auto};
      if (!body.host || !body.user || !body.path) throw Error('Host, username and remote path are required.');
      if (!/^age1[0-9a-z]+$/.test(body.age_recipient)) throw Error('A valid age recipient (age1…) is required.');
      if ((port && !/^\d+$/.test(port)) || !Number.isInteger(body.port) || body.port < 1 || body.port > 65535) throw Error('Port must be a number between 1 and 65535.');
      if (f.ae.password) body.password = f.ae.password;
      path = 'audit-export'; break;
    }
    case 'aeRun': path = 'audit-export/run'; body = {}; break;
    case 'aeClear': path = 'audit-export'; method = 'DELETE'; confirmation = 'Stop daily audit exports? This deletes the export settings and saved password. Audit events and files already exported are kept.'; break;
    case 'peer':
      if (!checkedPeer(state.peer) || !state.peer.can_change || !['required', 'disabled'].includes(state.peerBase)) throw Error('Refresh peer transport status before changing the mode.');
      body = {mode: f.peer.required ? 'required' : 'disabled', expected_mode: state.peerBase};
      if (body.mode === body.expected_mode) throw Error('Choose a different peer TLS mode first.');
      path = 'peer-tls'; confirmation = body.mode === 'required' ? 'Require TLS for all torrent traffic? The origin seeder will restart. Onboard devices afterward so they receive the same mode.' : 'Turn off peer TLS? Torrent traffic will no longer require encryption. The origin seeder will restart.'; break;
    default: throw Error('Unknown settings action.');
  }
  return {action, group, path: '/api/v1/settings/' + path, method, payload: body, body: method === 'DELETE' ? undefined : settingsBody(body), confirmation};
}
export function checkedSettingsResult(request, response, body) {
  if (response.status >= 500) return 'unknown';
  if (!response.ok) return 'refused';
  if (!object(body)) return 'unknown';
  let valid = false;
  switch (request.action) {
    case 'pw': case 'ae': valid = body.ok === true; break;
    case 'revoke': valid = count(body.revoked); break;
    case 'cert': case 'certDefault':
      valid = bool(body.applied) && object(body.gui_cert) && (request.action !== 'certDefault' || bool(body.deleted))
        && (!body.applied || (body.gui_cert.source === (request.action === 'cert' ? 'custom' : 'built-in')
          && text(body.gui_cert.subject) && text(body.gui_cert.not_after) && /^[a-f0-9]{64}$/i.test(body.gui_cert.fingerprint_sha256 || '')));
      break;
    case 'trust': valid = trustEntry(body.entry); break;
    case 'trustDelete': case 'tdDefault': case 'aeClear': valid = bool(body.deleted); break;
    case 'ca': valid = body.ok === true && object(body.ca_trust) && body.ca_trust.url === (request.payload.url || CISCO_CA) && body.ca_trust.auto === request.payload.auto; break;
    case 'td': valid = body.ok === true && body.endpoint === request.payload.endpoint && body.enabled === request.payload.enabled; break;
    case 'peer': valid = body.applied === true && checkedPeer(body) && body.mode === request.payload.mode; break;
    case 'caRun': valid = jobId(body.job); break;
    case 'aeRun': valid = jobId(body.job_id); break;
  }
  return valid ? 'saved' : 'unknown';
}
export function successMessage(action, body) {
  return {pw: 'Password changed. Other sessions signed out.', revoke: `Signed out ${body.revoked} other session(s).`,
    cert: body.applied ? 'Certificate replaced. New connections use it now; reload to see it on this one.' : 'Certificate saved; restart the Console to apply it.',
    certDefault: body.applied ? 'Reverted to the deployment default certificate.' : 'Default certificate saved; restart the Console to apply it.',
    trust: 'CA installed.', trustDelete: body.deleted ? 'CA removed.' : 'CA already absent.', ca: 'CA download settings saved.',
    td: 'Telemetry destination saved. The exporter picks it up on the next sample pass.', tdDefault: 'Reverted to the deployment default.',
    ae: 'Audit export settings saved.', aeClear: 'Audit export configuration cleared.', peer: 'Mode saved. Checking the origin seeder…',
    caRun: 'Downloading…', aeRun: 'Exporting…'}[action];
}

export function refusedSettingsMessage(action, status, body) {
  if (status === 401) return 'Your session expired. Sign in again before retrying.';
  if (status === 409) return 'The server refused a conflicting change. Reload and review current settings before retrying.';
  // Match known constant responses, never reflect a submitted credential or PEM.
  if (status === 400) {
    if (action === 'pw' && body?.error === 'current password is incorrect') return 'Current password is incorrect. Re-enter the passwords and try again.';
    if (action === 'ae' && body?.error === 'password is required when audit export is not configured; re-enter the destination and password')
      return 'Enter the destination and password to configure audit export.';
    if (action === 'td' && body?.error === 'authenticated telemetry endpoint must use https://') return 'Use HTTPS when telemetry has authentication configured.';
    if (action === 'cert') return 'Certificate import refused. Check the certificate, matching private key and key passphrase.';
    if (action === 'trust') return 'CA import refused. Check that the file contains valid public CA certificates.';
  }
  return `Request refused (HTTP ${status}). Check the input and current settings.`;
}
