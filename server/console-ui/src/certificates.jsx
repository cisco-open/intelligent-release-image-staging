// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {createPortal} from 'react-dom';
import {CertificatesController} from './certificates-controller.mjs';
import {signerAllows} from './certificates-model.mjs';
import {certificateGuidance, certificateState, signingHealth, signerGuidance} from './certificate-guidance.mjs';

function Certificates({controller: c, roots}) {
  const s = useSyncExternalStore(c.subscribe, c.snapshot), focus = useRef(null), outcomes = useRef({});
  useLayoutEffect(() => {
    const node = focus.current;
    if (node?.disabled && c.visible() && (document.activeElement === node || document.activeElement === document.body)) {
      outcomes.current[node.closest('[data-certificate-group]')?.dataset.certificateGroup]?.focus();
    }
  }, [s, c]);
  const date = value => value == null ? 'Unknown' : c.services?.formatDate(value) || String(value);
  const result = (group, id) => <p id={id} role="status" aria-live="polite" tabIndex={-1} ref={node => {outcomes.current[group] = node;}}>{s.messages[group]?.text || ''}</p>;
  const blocked = action => !c.available('signer') || !signerAllows(s.signer?.state, action);
  const button = (action, label, ghost = false) => <button className={'btn' + (ghost ? ' ghost' : '')} id={'rotation-' + action} disabled={blocked(action)} onClick={() => c.perform(action)}>{label}</button>;
  const file = (action, id, label, disabled, accept) => <><label htmlFor={id}>{label}</label><input key={s.fileEpoch + action} id={id} type="file" accept={accept} disabled={disabled} onChange={event => c.file(action, event.target.files[0])} /></>;
  const inventory = <div className="card" data-certificate-group="inventory"><h3>Certificates at a glance</h3>
    <p>Certificates protect different connections. Renew a signing certificate to extend its validity; replace a key when you need a new signing identity.</p>
    <details><summary>Where to approve instruction signing requests</summary><p>Run <code>iris-key-setup</code> on a separate key holder's machine. If you keep the keys on the deployment host, use <code>iris-key-setup --local</code> there and confirm your choice. Return only the public approval files to the Console.</p></details>
    <p className="muted">These dates come from public files on the server, in your browser's timezone. They do not confirm which certificate a running service presents.</p>
    <div className="table-scroll" role="region" aria-label="Certificate deadlines" tabIndex={0}><table className="tbl"><thead><tr>{['Certificate or key', 'Status', 'Renew from', 'Expires', 'Your next step'].map(label => <th key={label} scope="col">{label}</th>)}</tr></thead>
      <tbody id="certificate-rows">{(s.valid.inventory ? s.inventory.items : []).map(row => {const guide = certificateGuidance(row); return <tr key={row.id}>
        <td><strong>{guide.title}</strong><p>{guide.purpose}</p><details><summary>Public fingerprint</summary><small className="machine">{row.fingerprint_sha256 || 'Fingerprint unavailable'}</small></details></td>
        <td>{certificateState(row.state)}</td><td>{row.kind === 'public-key' ? 'Holder review' : date(row.renew_at)}</td>
        <td>{row.kind === 'public-key' ? 'No expiry date' : date(row.expires_at)}</td><td>{row.state === 'unknown' ? 'Refresh to check this file before making changes. ' : ''}{guide.next}{row.refuse_at == null ? null : <><p>New instruction signing stops: {date(row.refuse_at)}</p></>}</td></tr>;})}</tbody></table></div>
    <p id="certificate-observed" className="muted" role="status" aria-live="polite" tabIndex={-1} ref={node => {outcomes.current.inventory = node;}}>{s.loading.inventory ? 'Checking certificate files…' : s.valid.inventory
      ? 'Checked ' + date(s.inventory.observed_at) + '. ' + signingHealth(s.inventory.custody?.state)
      : s.messages.inventory?.text || 'Certificate inventory unavailable.'}</p>
    <p className="certificate-actions"><button className="btn ghost" id="certificate-refresh" disabled={s.busy || s.loading.inventory} onClick={() => c.refresh('inventory', true)}>Refresh certificates</button>{' '}
      <a className="btn ghost" href="#settings/tls">View active browser certificate</a></p></div>;
  const renewal = <div className="card" data-certificate-group="renew"><h3>Renew signing certificate</h3>
    <p>Use this for routine expiry. The server keeps its signing key; a root signing key holder approves a new 30-day certificate for it.</p>
    <ol><li>Download the current public key below.</li><li>Ask its root key holder to approve it with <code>iris-key-setup</code>.</li><li>Import the returned public certificate and apply the renewal.</li></ol>
    <p className="muted">Start at the renewal date above. New instruction signing stops seven days before expiry. Import public approvals only; never upload a root private key.</p>
    <p><button className="btn" id="certificate-request" disabled={s.busy} onClick={() => c.renewalRequest()}>Download public renewal request</button></p>
    <form id="certificate-renew-form" className="inline-form" onSubmit={event => {event.preventDefault(); c.perform('renew');}}>
      {file('renew', 'certificate-approved', 'Approved signing certificate (.pub)', s.busy || !s.request || s.unknown.renew, '.pub')}
      <button className="btn" id="certificate-renew" type="submit" disabled={s.busy || !s.request || s.unknown.renew}>Validate and apply renewal</button>
    </form>{result('renew', 'certificate-renew-result')}</div>;
  const state = s.valid.signer ? s.signer.state : 'unavailable';
  const signerGuide = signerGuidance(state);
  const signer = <div className="card" id="signer-rotation" data-certificate-group="signer"><h3>Replace signing key</h3>
    <p>Use this when the key itself needs replacing. Prepare a new key, get a root key holder's approval, switch to it, then retire the old key.</p>
    <p id="rotation-state" role="status" aria-live="polite">{s.loading.signer ? 'Checking key replacement…' : signerGuide[0] + '.'}</p>
    <p id="rotation-next-step">{signerGuide[1]}</p>
    <details><summary>Compare public keys and request details</summary>
      {s.valid.signer && s.signer.request_id && <p className="machine">Request: {s.signer.request_id}</p>}
      <div className="rotation-identities" aria-label="Signer comparison"><div><strong>Previous key SHA256</strong><p className="machine" id="rotation-previous">{s.valid.signer && s.signer.previous_sha256 || 'No replacement recorded'}</p></div>
        <div><strong>Replacement key SHA256</strong><p className="machine" id="rotation-replacement">{s.valid.signer && s.signer.replacement_sha256 || 'No replacement recorded'}</p></div></div>
      {state === 'completed' && <p>Published revocation list sequence: {s.signer.retired_keylist_seq}.</p>}
      <p>Device trust roots and instruction counters stay unchanged.</p>
    </details>
    <p className="certificate-actions"><button className="btn ghost" id="rotation-refresh" disabled={s.busy || s.loading.signer} onClick={() => c.refresh('signer', true)}>Refresh rotation</button>{' '}{button('prepare', 'Prepare replacement key')}</p>
    <div id="rotation-approval" hidden={state !== 'awaiting-approval'}>
      <p className="certificate-actions"><button className="btn ghost" id="rotation-download" disabled={!c.available('signer')} onClick={() => c.downloadSigner()}>Download replacement public key</button>{' '}{button('cancel', 'Cancel pending replacement', true)}</p>
      <p>Ask the root key holder to choose <strong>Approve server request</strong> in <code>iris-key-setup</code>. Return only the approved public certificate.</p>
      <div className="inline-form">{file('activate', 'rotation-certificate', 'Approved replacement certificate (.pub)', blocked('activate'), '.pub')}{button('activate', 'Validate and switch signer')}</div>
    </div>
    <div id="rotation-retirement" hidden={!['retirement-pending', 'retiring'].includes(state)}>
      <p>The old key remains trusted until its certificate expires or devices receive its revocation. The retirement request preserves all earlier revocations.</p>
      <div className="inline-form"><label htmlFor="rotation-root">Root key used for approval</label><select id="rotation-root" value={s.root} disabled={blocked('retirement-request')} onChange={event => c.root(event.target.value)}>{(s.signer?.root_ids || []).map(root => <option key={root}>{root}</option>)}</select>
        {button('retirement-request', 'Download retirement request', true)}</div>
      <p>That root's holder approves the retirement request with <code>iris-key-setup</code>. Import the signed public retirement list below.</p>
      <div className="inline-form">{file('retire', 'rotation-keylist', 'Approved retirement list (.envelope)', blocked('retire'), '.envelope')}{button('retire', 'Validate and retire previous key')}</div>
    </div>{result('signer', 'rotation-result')}
    <p className="muted">After replacement, verify fresh signed instructions and the updated revocation list on devices using each deployment type in your fleet.</p>
  </div>;
  return <div onFocusCapture={event => {focus.current = event.target;}}>{createPortal(inventory, roots.inventory)}{createPortal(renewal, roots.renewal)}{createPortal(signer, roots.signer)}</div>;
}
export function mountCertificates() {
  const c = new CertificatesController(); window.irisCertificates = c;
  const root = document.getElementById('iris-certificates-root'), roots = Object.fromEntries(['inventory', 'renewal', 'signer'].map(name => [name, document.getElementById('iris-certificates-' + name)]));
  if (!root || Object.values(roots).some(value => !value)) throw Error('Certificate mount point missing');
  createRoot(root).render(<Certificates controller={c} roots={roots} />);
}
