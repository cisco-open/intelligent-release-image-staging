// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {createPortal} from 'react-dom';
import {SecurityLifecycleController} from './security-lifecycle-controller.mjs';
import {browserGuidance} from './certificate-guidance.mjs';

function SecurityLifecycle({controller: c, roots}) {
  const s = useSyncExternalStore(c.subscribe, c.snapshot), focus = useRef(null), outcomes = useRef({}), add = useRef(null);
  useLayoutEffect(() => {
    const {node, group, header} = focus.current || {};
    if (!c.visible() || !node) return;
    if (!node.isConnected && !s.busy) {(header ? add.current : outcomes.current[group])?.focus(); return;}
    if (node.disabled && (document.activeElement === node || document.activeElement === document.body)) outcomes.current[group]?.focus();
  }, [s, c]);
  const message = (key, group, id) => <p id={id} role="status" aria-live="polite" tabIndex={-1} ref={node => {outcomes.current[group] = node;}}>{s.messages[key]?.text || ''}</p>;
  const tlsState = s.valid.tls ? s.tls.state : 'unavailable';
  const tlsGuide = browserGuidance(tlsState);
  const tlsButton = (action, label, ghost = false) => <button type="button" className={'btn' + (ghost ? ' ghost' : '')} id={'browser-tls-' + action} disabled={!c.canTls(action)} onClick={() => c.perform('tls', action)}>{label}</button>;
  const tls = <details className="card certificate-task" id="browser-certificate-controls" data-security-group="tls" onToggle={event => {if (event.target === event.currentTarget && !event.currentTarget.open) c.clearFile();}}><summary><strong>Replace the Console browser certificate</strong><span>{s.unknown.tls ? 'Outcome unknown: refresh request and review before continuing' : s.busy && s.messages.tls?.text ? s.messages.tls.text : s.loading.tls ? 'Checking certificate request…' : tlsGuide[0]}</span></summary><div className="certificate-task-body">
    <p>This certificate protects the HTTPS connection from your browser to the Console. View its current identity and expiry in <a href="#settings/tls">TLS &amp; trust</a>.</p>
    <p>IRIS creates a new key for this replacement. Your certificate authority approves the public request; the private key stays encrypted on the server.</p>
    <div id="browser-tls-workflow"><p id="browser-tls-state" role="status" aria-live="polite">{s.loading.tls ? 'Checking certificate request…' : tlsGuide[0] + '.'}</p>
      <p id="browser-tls-next-step">{tlsGuide[1]}</p>
      <form id="browser-tls-prepare-form" className="maintenance-form" onSubmit={event => {event.preventDefault(); c.perform('tls', 'prepare');}}>
        <label>Console DNS names or IP addresses, comma-separated<input id="browser-tls-names" type="text" required value={s.names} disabled={!c.canTls('prepare')} onChange={event => c.field('names', event.target.value)} placeholder="console.example.com, 192.0.2.10" /></label>
        <label>Who approves the certificate?<select id="browser-tls-mode" value={s.mode} disabled={!c.canTls('prepare')} onChange={event => c.field('mode', event.target.value)}><option value="ca">My certificate authority (CA)</option><option value="self-signed">Create a self-signed certificate (90 days)</option></select></label>
        <button className="btn" id="browser-tls-prepare" type="submit" disabled={!c.canTls('prepare')}>Create replacement request</button>
      </form>
      <p className="muted">Use exact names, without URLs or wildcards. For a self-signed certificate, configure each browser to trust it before applying. Device and internal server certificates stay unchanged.</p>
      {s.valid.tls && s.tls.request_id && <details><summary>Replacement names and public fingerprint</summary><p className="machine">Request: {s.tls.request_id}<br />Requested names: {s.tls.names.join(', ')}</p>
        <p className="machine" id="browser-tls-identity">{s.tls.fingerprint_sha256 ? 'Replacement SHA256: ' + s.tls.fingerprint_sha256 : 'Fingerprint available after approval.'}</p></details>}
      <p className="security-actions"><button className="btn ghost" id="browser-tls-refresh" disabled={s.busy || s.loading.tls} onClick={() => c.refresh('tls', true)}>Refresh request</button>
        <button className="btn ghost" id="browser-tls-csr" disabled={!c.available('tls') || !s.tls?.csr} onClick={() => c.download('csr')}>Download public request</button>
        <button className="btn ghost" id="browser-tls-certificate" disabled={!c.available('tls') || !s.tls?.certificate} onClick={() => c.download('certificate')}>Download approved certificate</button>
        {tlsButton('cancel', 'Cancel replacement', true)}</p>
      <form id="browser-tls-approve-form" className="inline-form" hidden={!s.valid.tls || !['awaiting-approval', 'approved'].includes(tlsState) || s.tls?.mode !== 'ca'} onSubmit={event => {event.preventDefault(); c.perform('tls', 'approve');}}>
        <label htmlFor="browser-tls-approved">Approved public certificate file (PEM, Console certificate first)</label>
        <input key={s.fileEpoch} id="browser-tls-approved" type="file" accept=".pem,.crt,.cer" disabled={!c.canTls('approve')} onChange={event => c.file(event.target.files[0])} />
        <button className="btn" id="browser-tls-approve" type="submit" disabled={!c.canTls('approve')}>Validate approval</button>
      </form>
      <p className="security-actions">{tlsButton('apply', tlsState === 'committing' ? 'Recover approved publication' : tlsState === 'published' ? 'Retry Console certificate reload' : 'Apply approved certificate')}</p>
      {message('tls', 'tls', 'browser-tls-result')}
    </div></div></details>;
  const item = s.valid.credentials ? c.item() : null, replace = c.canCredential('replace'), metrics = s.family === 'metrics-token';
  const credentialButton = (action, label, ghost = false) => <button className={'btn' + (ghost ? ' ghost' : '')} id={'service-credential-' + action} disabled={!c.canCredential(action)} onClick={() => c.perform('credentials', action)}>{label}</button>;
  const credentials = <details className="card certificate-task" id="telemetry-credential-controls" data-security-group="credentials" onToggle={event => {if (event.target === event.currentTarget && !event.currentTarget.open) c.clearSecrets();}}><summary><strong>Rotate telemetry credentials</strong><span>{['metrics-token', 'collector-headers'].some(key => s.unknown[key]) ? 'Outcome unknown: refresh evidence and review before continuing' : s.busy && s.messages[s.family]?.text ? s.messages[s.family].text : !s.valid.credentials ? 'Credential status unavailable' : s.credentials.items.some(row => row.state === 'awaiting-verification') ? 'Replacement awaiting verification' : 'Access for your monitoring systems'}</span></summary><div className="certificate-task-body">
    <p>These credentials give monitoring systems access to metrics or let IRIS send telemetry to your collector. Replacements are stored encrypted on the server.</p>
    <div id="service-credential-workflow"><label className="security-field">Credential<select id="service-credential-family" value={s.family} disabled={s.busy} onChange={event => c.family(event.target.value)}><option value="metrics-token">Metrics scraping token</option><option value="collector-headers">Outbound collector authentication</option></select></label>
      <p id="service-credential-state" role="status" aria-live="polite">{s.loading.credentials ? 'Checking credential state…' : !item ? 'Credential state unavailable. Refresh before changing credentials.'
        : ({'deployment-managed': 'Using deployment credential files', 'awaiting-verification': 'Replacement saved; confirm all consumers have moved', completed: 'Previous credential retired from IRIS', reverted: 'Previous IRIS setting restored'}[item.state] || 'Review the current credential') + (item.observed_at !== null ? '. Successful use observed ' + c.services.formatDate(item.observed_at) + '.' : '. No replacement-use evidence recorded.')}</p>
      {item?.request_id && <p className="machine">Operation: {item.request_id}{item.endpoint && <><br />Bound destination: {item.endpoint}</>}</p>}
      {item?.state === 'awaiting-verification' && <p className="muted">{item.previous_retained ? 'The previous credential remains stored until retirement.' : 'No previous Console-managed credential is stored.'} Confirm every external consumer before finishing.</p>}
      <div id="service-credential-metrics" hidden={!metrics}>
        <label className="security-field">Replacement token<input id="service-credential-token" type="password" autoComplete="new-password" spellCheck={false} value={s.token} disabled={!replace} onChange={event => c.field('token', event.target.value)} /></label>
        <p className="security-actions"><button className="btn ghost" id="service-credential-generate" disabled={!replace} onClick={() => c.generateToken()}>Generate token in this browser</button>
          <button className="btn ghost" id="service-credential-download" disabled={!replace} onClick={() => c.download('token')}>Download private token file</button></p>
        <p className="muted">Download the replacement before applying it, then configure every scraper to use that file. The old token remains accepted until retirement.</p>
      </div>
      <div id="service-credential-collector" hidden={metrics}>
        <label className="security-field">Exact HTTPS collector base URL<input id="service-credential-endpoint" type="url" value={s.endpoint} disabled={!replace} onChange={event => c.field('endpoint', event.target.value)} placeholder="https://collector.example:4318" /></label>
        <div id="service-credential-headers">{s.headers.map(row => <div key={row.id} className="maintenance-form">
          <label>Header name<input data-field="name" value={row.name} disabled={!replace} onChange={event => c.header(row.id, 'name', event.target.value)} /></label>
          <label>Secret value<input data-field="value" type="password" autoComplete="new-password" value={row.value} disabled={!replace} onChange={event => c.header(row.id, 'value', event.target.value)} /></label>
          <button className="btn ghost" disabled={!replace || s.headers.length === 1} onClick={() => c.removeHeader(row.id)} aria-label={'Remove header ' + (row.name || s.headers.indexOf(row) + 1)}>Remove header</button>
        </div>)}</div>
        <p><button ref={add} className="btn ghost" id="service-credential-add-header" disabled={!replace || s.headers.length >= 16} onClick={() => c.addHeader()}>Add authentication header</button></p>
        <p className="muted">Obtain the replacement from your collector's administrator. IRIS binds it to this URL and waits for a successful export. Keep the old credential valid there until all senders have moved.</p>
      </div>
      <p className="security-actions">{credentialButton('replace', 'Apply replacement credential')}
        <button className="btn ghost" id="service-credential-refresh" disabled={s.busy || s.loading.credentials} onClick={() => c.refresh('credentials', true)}>Refresh evidence</button></p>
      <p className="security-actions">{credentialButton('retire', 'Finish verified rotation')}{credentialButton('revert', 'Restore previous setting', true)}</p>
      {message(s.family, 'credentials', 'service-credential-result')}
    </div></div></details>;
  return <div onFocusCapture={event => {focus.current = {node: event.target, group: event.target.closest('[data-security-group]')?.dataset.securityGroup, header: !!event.target.closest('#service-credential-headers')};}}>{createPortal(tls, roots.tls)}{createPortal(credentials, roots.credentials)}</div>;
}
export function mountSecurityLifecycle() {
  const c = new SecurityLifecycleController(); window.irisSecurityLifecycle = c;
  const root = document.getElementById('iris-security-lifecycle-root'), roots = {tls: document.getElementById('iris-browser-tls'), credentials: document.getElementById('iris-service-credentials')};
  if (!root || !roots.tls || !roots.credentials) throw Error('Security lifecycle mount points missing');
  createRoot(root).render(<SecurityLifecycle controller={c} roots={roots} />);
}
