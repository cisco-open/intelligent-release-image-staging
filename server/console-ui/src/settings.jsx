// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {createPortal} from 'react-dom';
import {SettingsController} from './settings-controller.mjs';
import {CISCO_CA, MOZILLA_CA, encryptedKey} from './settings-model.mjs';

function Dropzone({id, label, disabled, onFiles}) {
  const file = useRef(null), zone = useRef(null);
  const choose = () => {if (!disabled) file.current.click();};
  return <div className="dropzone" id={id} ref={zone} tabIndex={0} role="button" aria-label={label} aria-disabled={disabled}
    onClick={choose} onKeyDown={event => {if (event.key === 'Enter' || event.key === ' ') {event.preventDefault(); choose();}}}
    onDragOver={event => {event.preventDefault(); if (!disabled) zone.current.classList.add('drag');}}
    onDragLeave={() => zone.current.classList.remove('drag')} onDrop={event => {event.preventDefault(); zone.current.classList.remove('drag'); if (!disabled) onFiles([...event.dataTransfer.files]);}}>
    <input type="file" id={id + '-input'} ref={file} multiple hidden onChange={event => {const files = [...event.target.files]; event.target.value = ''; if (!disabled) onFiles(files);}} />
    <p>{label}<span className="hint">PEM files, or press Enter to browse</span></p>
  </div>;
}
function Certificate({info = {}}) {
  if (!['custom', 'built-in'].includes(info.source)) return <div id="cert-status" role="status" aria-live="polite">Certificate details are unavailable.</div>;
  const expiry = Date.parse(info.not_after || ''), remaining = expiry - Date.now();
  return <div id="cert-status" className="tls-certificate" role="status" aria-live="polite">
    <div className="tls-certificate-heading"><strong>Certificate this Console serves</strong><span className="badge badge-running">{info.source === 'custom' ? 'Custom' : 'Deployment default'}</span>
      {Number.isFinite(expiry) && <span className={'badge ' + (remaining <= 0 ? 'badge-fail' : remaining < 30 * 86400000 ? 'badge-queued' : 'badge-ok')}>{remaining <= 0 ? 'Expired' : remaining < 30 * 86400000 ? 'Expires soon' : 'In date'}</span>}</div>
    <dl className="tls-certificate-facts">{[['Issued to', info.subject], ['Expires', info.not_after], ['SHA-256 fingerprint', info.fingerprint_sha256]].map(([label, value]) =>
      <div key={label} className={label.startsWith('SHA') ? 'tls-fingerprint' : undefined}><dt>{label}</dt><dd>{value || 'Unavailable'}</dd></div>)}</dl>
  </div>;
}

function Settings({controller: c, roots}) {
  const s = useSyncExternalStore(c.subscribe, c.snapshot), focus = useRef(null), certDetails = useRef(null);
  const {data, forms: f} = s;
  useLayoutEffect(() => {
    const node = focus.current;
    if (node?.disabled && (document.activeElement === node || document.activeElement === document.body)) node.closest('[data-setting]')?.querySelector('.settings-message')?.focus({preventScroll: true});
    if (encryptedKey(f.cert.key)) certDetails.current.open = true;
  }, [s, f.cert.key]);
  const blocked = group => s.busy || s.fileBusy || !!s.unknown[group] || !c.available(group);
  const field = (group, key, id, label, props = {}) => <label className="field" htmlFor={id}><span className="field-label">{label}</span>
    <input id={id} value={f[group][key]} disabled={s.busy} onChange={event => c.field(group, key, event.target.value)} {...props} /></label>;
  const check = (group, key, id, label, props = {}) => <label className="form-check"><input id={id} type="checkbox" checked={f[group][key]} disabled={s.busy} onChange={event => c.field(group, key, event.target.checked)} {...props} /> {label}</label>;
  const area = (group, key, id, label) => <label className="field field-wide" htmlFor={id}><span className="field-label">{label}</span><textarea id={id} rows={4} autoComplete="off" spellCheck={false} value={f[group][key]} disabled={s.busy} onChange={event => c.field(group, key, event.target.value)} /></label>;
  const message = (group, id) => <span className={'settings-message ' + (s.messages[group]?.kind === 'success' ? 'err ok' : s.messages[group]?.kind === 'error' ? 'err' : 'muted')} id={id} role="status" aria-live="polite" tabIndex={-1}>{s.messages[group]?.text}</span>;
  const review = group => <button className="btn ghost" id={'settings-review-' + group} type="button" disabled={s.busy || s.fileBusy || s.loading} onClick={() => c.review(group)}>Reload current settings</button>;
  const form = (id, action, contents) => <form className="inline-form" id={id} onSubmit={event => {event.preventDefault(); c.perform(action);}}>{contents}</form>;
  const unavailable = pane => <p className="err" role="status" hidden={!!s.valid[pane]}>{s.loading ? 'Reading settings…' : 'Current settings unavailable. Reload before making changes.'}</p>;
  const portText = s.valid.general ? Object.entries(data.ports).map(([key, value]) => key + ' ' + value).join(' · ') : 'Unavailable';
  const general = <div data-settings-react><div className="setup-cards">
    <div className="card"><h3>Server &amp; build</h3>{unavailable('general')}<div className="table-scroll"><table className="tbl" id="settings-info"><tbody>
      {[['Version', data.version], ['Admin', data.admin_username], ['Server IP', data.host_ip || '(unset)'], ['Console URL', data.console_url || location.origin], ['Ports', portText]].map(([label, value]) => <tr key={label}><td className="muted">{label}</td><td>{value || 'Unavailable'}</td></tr>)}
    </tbody></table></div></div>
    <div className="card" data-setting="pw"><h3>Change admin password</h3>{form('pw-form', 'pw', <>
      {field('pw', 'current', 'pw-cur', 'Current password', {type: 'password', autoComplete: 'current-password'})}
      {field('pw', 'next', 'pw-new', 'New password', {type: 'password', autoComplete: 'new-password', placeholder: 'Min 8 characters'})}
      {field('pw', 'confirm', 'pw-confirm', 'Confirm new password', {type: 'password', autoComplete: 'new-password'})}
      <div className="form-actions"><button className="btn" type="submit" disabled={blocked('pw')}>Change password</button>{review('pw')}</div>{message('pw', 'pw-msg')}</>)}</div>
    <div className="card" data-setting="revoke"><h3>Sessions</h3><p id="sessions-info" role="status" aria-live="polite">{s.valid.general ? `${data.sessions.active} active session(s); idle timeout ${data.sessions.idle_ttl_minutes} min.` : 'Session status unavailable.'}</p>
      <div className="form-actions"><button className="btn ghost" id="revoke-others" disabled={blocked('revoke')} onClick={() => c.perform('revoke')}>Sign out other sessions</button>{review('revoke')}</div>{message('revoke', 'revoke-msg')}</div>
  </div></div>;
  const bundleLabel = !data.ca_trust?.url || data.ca_trust.url === CISCO_CA ? 'Cisco Trusted Root Store' : data.ca_trust.url === MOZILLA_CA ? 'Mozilla CA bundle (curl.se)' : 'Custom URL';
  const peer = s.peer;
  const tls = <div data-settings-react>{unavailable('tls')}<div className="setup-cards tls-layout">
    <div className="card tls-identity" data-setting="peer"><h3>Peer transfer TLS</h3><p className="muted">Encrypt BitTorrent traffic between the origin seeder and devices. Applies to all torrents; off by default.</p>
      {form('peer-tls-form', 'peer', <>{check('peer', 'required', 'peer-tls-toggle', 'Require TLS for torrent traffic', {role: 'switch', disabled: s.busy || !s.peerOk || !peer?.can_change})}
        <div className="form-actions"><button className="btn" id="peer-tls-save" type="submit" disabled={blocked('peer') || !peer?.can_change || (f.peer.required ? 'required' : 'disabled') === s.peerBase}>Apply</button>{review('peer')}</div>{message('peer', 'peer-tls-msg')}</>)}
      <p className="muted" id="peer-tls-status" role="status" aria-live="polite">{s.peerOk ? `Origin seeder: ${peer.origin.active_mode === 'required' ? 'TLS required' : peer.origin.active_mode === 'disabled' ? 'TLS off' : 'not active'} · ${peer.origin.state}` + (peer.active_devices ? ` · ${peer.active_devices} device(s) must be undeployed before switching.` : '') + (peer.active_jobs ? ` · Wait for ${peer.active_jobs} device job(s) to finish.` : '') : 'Peer transport status unavailable. Reload before changing the mode.'}</p>
      <p className="muted">Undeploy existing agents before switching, then onboard them again. The origin seeder restarts automatically; certificates are provisioned automatically.</p></div>
    <div className="card tls-identity" data-setting="cert"><h3>Console browser certificate</h3><p className="muted">Protects your browser connection. For a guided replacement request, open <a href="#settings/certificates">Certificates &amp; keys</a>. Use the form below if you already have a matching certificate and private key.</p><Certificate info={data.gui_cert} />
      <h4>Replace certificate</h4><p className="muted">Upload a PEM certificate and private key. Private keys are encrypted at rest and never returned by the server.</p>
      <Dropzone id="cert-dropzone" label="Drop a certificate and/or private key PEM file" disabled={s.busy} onFiles={files => c.certificateFiles(files)} />
      {form('cert-form', 'cert', <><details className="tls-pem" ref={certDetails}><summary>Paste certificate and key instead</summary><div className="tls-pem-fields">
        {area('cert', 'pem', 'cert-pem', 'Certificate PEM (leaf or full chain)')}{area('cert', 'key', 'cert-key', 'Private key PEM')}
        <div id="cert-passphrase-row" hidden={!encryptedKey(f.cert.key)}>{field('cert', 'passphrase', 'cert-passphrase', 'Key passphrase', {type: 'password', autoComplete: 'off'})}</div>
      </div></details><div className="form-actions"><button className="btn" type="submit" disabled={blocked('cert')}>Replace certificate</button>
        <button className="linkish danger-link" id="cert-revert" type="button" disabled={blocked('cert')} onClick={() => c.perform('certDefault')}>Use deployment default certificate</button>{review('cert')}</div>{message('cert', 'cert-msg')}</>)}</div>
    <div className="card" data-setting="trust"><h3>Trusted certificate authorities</h3><p className="muted">Additional trust for outbound HTTPS, including image verification and telemetry. System roots remain trusted.</p>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Trusted certificate authorities"><table className="tbl" id="trust-tbl" hidden={!s.valid.tls || !data.trust?.length}><thead><tr>{['Subject', 'Expires', 'SHA-256', 'Source', 'Certs', 'Actions'].map(label => <th key={label} scope="col">{label}</th>)}</tr></thead>
        <tbody id="trust-rows">{(s.valid.tls ? data.trust : []).map(entry => <tr key={entry.name} data-name={entry.name}><td>{entry.source === 'downloaded' ? 'Public CA bundle — ' + bundleLabel : entry.subject || 'Unavailable'}</td><td>{entry.not_after || 'Unavailable'}</td><td className="machine">{entry.fingerprint_sha256 ? entry.fingerprint_sha256.slice(0, 16) + '…' : 'Unavailable'}</td><td>{entry.source}</td><td>{entry.cert_count}</td><td><button className="linkish danger-link trust-del" disabled={blocked('trust')} onClick={() => c.perform('trustDelete', entry.name)}>{entry.source === 'downloaded' ? 'remove bundle' : 'remove'}</button></td></tr>)}</tbody></table></div>
      <p id="trust-empty" className="muted" hidden={!s.valid.tls || !!data.trust?.length}>No additional CAs installed. Outbound HTTPS uses the system trust store.</p>
      <Dropzone id="trust-dropzone" label="Drop public CA certificate PEM files" disabled={blocked('trust')} onFiles={files => c.trustFiles(files)} />
      {form('trust-form', 'trust', <><details className="tls-pem"><summary>Paste CA certificates instead</summary>{area('trust', 'pem', 'trust-pem', 'CA certificate PEM')}</details><div className="form-actions"><button className="btn" type="submit" disabled={blocked('trust')}>Add CA</button>{review('trust')}</div>{message('trust', 'trust-msg')}</>)}</div>
    <div className="card" data-setting="ca"><h3>Public CA bundle</h3><p className="muted">Download a public root bundle over HTTPS and optionally refresh it daily. If a download fails, the previous bundle stays in use.</p>
      {form('ca-form', 'ca', <><label className="field" htmlFor="ca-source"><span className="field-label">CA bundle source</span><select id="ca-source" value={f.ca.source} disabled={s.busy} onChange={event => c.field('ca', 'source', event.target.value)}><option value="cisco">Cisco Trusted Root Store</option><option value="mozilla">Mozilla CA bundle (curl.se)</option><option value="custom">Custom URL</option></select></label>
        {field('ca', 'url', 'ca-url', 'Custom bundle URL', {hidden: f.ca.source !== 'custom', placeholder: 'https://…'})}{check('ca', 'auto', 'ca-auto', 'Refresh daily')}
        <div className="form-actions"><button className="btn ghost" type="submit" disabled={blocked('ca')}>Save</button><button className="btn ghost" type="button" id="ca-refresh" disabled={blocked('ca') || !!s.jobs.ca} onClick={() => c.perform('caRun')}>Download now</button>{review('ca')}</div>{message('ca', 'ca-msg')}</>)}</div>
  </div><p className="muted tls-scope-note">Device-facing HTTPS certificates are managed during onboarding. The Console certificate protects browser HTTPS.</p></div>;
  const td = data.telemetry_destination;
  const telemetry = <div data-settings-react data-setting="td">{unavailable('telemetry')}<p className="muted" id="td-status" role="status" aria-live="polite">{s.valid.telemetry ? (td.source === 'override' ? 'console override' : 'deployment default') + ' · ' + (td.effective_enabled ? 'export on — ' + td.effective_endpoint : 'export off') + (data.observability?.metrics_url ? ' · Prometheus scrape ' + data.observability.metrics_url : '') : 'Telemetry destination unavailable.'}</p>
    {form('td-form', 'td', <>{field('td', 'endpoint', 'td-endpoint', 'OTLP endpoint', {placeholder: 'https://collector:4318'})}{check('td', 'enabled', 'td-enabled', 'Export enabled')}
      <div className="form-actions"><button className="btn" type="submit" disabled={blocked('td')}>Save</button><button className="linkish danger-link" type="button" id="td-revert" hidden={td?.source !== 'override'} disabled={blocked('td')} onClick={() => c.perform('tdDefault')}>Revert to deployment default</button>{review('td')}</div>{message('td', 'td-msg')}</>)}</div>;
  const ae = data.audit_export;
  const audit = <div className="card" data-settings-react data-setting="ae"><h3>Audit export</h3><p className="muted">Uploads the audit trail to a remote host over SCP, age-encrypted to the recipient below. Encryption is mandatory. The SCP password is stored encrypted and never shown again.</p>{unavailable('audit')}
    <p id="ae-status" className="muted" role="status" aria-live="polite">{!s.valid.audit ? 'Audit export settings unavailable.' : !ae.host ? 'Not configured — the audit trail stays on this server.'
      : `${ae.user}@${ae.host}:${ae.path} · ${ae.auto ? 'daily' : 'manual only'} · ` + (ae.last_run_ts ? `last export ${c.services.formatDate(ae.last_run_ts)} · ${ae.last_result || 'outcome unavailable'}` : 'never exported yet')}</p>
    {form('ae-form', 'ae', <>{field('ae', 'host', 'ae-host', 'Host')}{field('ae', 'port', 'ae-port', 'Port', {placeholder: '22', inputMode: 'numeric'})}{field('ae', 'user', 'ae-user', 'Username', {autoComplete: 'username'})}{field('ae', 'path', 'ae-path', 'Remote path')}
      {field('ae', 'recipient', 'ae-recipient', 'age recipient', {placeholder: 'age1…', spellCheck: false})}{field('ae', 'password', 'ae-pass', 'Password', {type: 'password', autoComplete: 'new-password', placeholder: ae?.password_set ? 'unchanged' : 'Password'})}{check('ae', 'auto', 'ae-auto', 'Export daily')}
      <div className="form-actions"><button className="btn" type="submit" disabled={blocked('ae')}>Save</button><button className="btn ghost" id="ae-run" type="button" disabled={blocked('ae') || !!s.jobs.ae} onClick={() => c.perform('aeRun')}>Export now</button><button className="linkish danger-link" id="ae-clear" type="button" disabled={blocked('ae')} onClick={() => c.perform('aeClear')}>Clear</button>{review('ae')}</div>{message('ae', 'ae-msg')}</>)}</div>;
  return <div onFocusCapture={event => {focus.current = event.target;}}>{createPortal(general, roots.general)}{createPortal(tls, roots.tls)}{createPortal(audit, roots.audit)}{createPortal(telemetry, document.getElementById(s.telemetryHost))}</div>;
}
export function mountSettings() {
  const c = new SettingsController(); window.irisSettings = c;
  const root = document.getElementById('iris-settings-root'), roots = Object.fromEntries(['general', 'tls', 'audit'].map(name => [name, document.getElementById('iris-settings-' + name)]));
  if (!root || Object.values(roots).some(value => !value)) throw Error('Settings mount point missing');
  createRoot(root).render(<Settings controller={c} roots={roots} />);
}
