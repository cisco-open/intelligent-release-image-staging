// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {createPortal} from 'react-dom';
import {CertificatesController} from './certificates-controller.mjs';
import {signerAllows} from './certificates-model.mjs';

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
  const inventory = <div className="card" data-certificate-group="inventory"><h3>Certificate deadlines</h3>
    <p className="muted">Server file observations, with dates in your browser's timezone. A valid date alone does not prove trust or the identity currently served by a listener.</p>
    <div className="table-scroll" role="region" aria-label="Certificate deadlines" tabIndex={0}><table className="tbl"><thead><tr>{['Purpose', 'State', 'Renew from', 'Expires', 'Operational impact'].map(label => <th key={label} scope="col">{label}</th>)}</tr></thead>
      <tbody id="certificate-rows">{(s.valid.inventory ? s.inventory.items : []).map(row => <tr key={row.id}>
        <td>{row.label}<br /><small className="machine">{row.fingerprint_sha256 || 'Fingerprint unavailable'}</small></td>
        <td>{row.state.replaceAll('-', ' ')}</td><td>{row.kind === 'public-key' ? 'Policy / custody review' : date(row.renew_at)}</td>
        <td>{row.kind === 'public-key' ? 'No expiry' : date(row.expires_at)}</td><td>{row.impact}{row.refuse_at == null ? null : <><br />Signing stops: {date(row.refuse_at)}</>}</td></tr>)}</tbody></table></div>
    <p id="certificate-observed" className="muted" role="status" aria-live="polite" tabIndex={-1} ref={node => {outcomes.current.inventory = node;}}>{s.loading.inventory ? 'Checking certificate files…' : s.valid.inventory
      ? 'Observed ' + date(s.inventory.observed_at) + '. Signing custody: ' + (s.inventory.custody?.state || 'unknown; status evidence unavailable') + '.'
      : s.messages.inventory?.text || 'Certificate inventory unavailable.'}</p>
    <p className="certificate-actions"><button className="btn ghost" id="certificate-refresh" disabled={s.busy || s.loading.inventory} onClick={() => c.refresh('inventory', true)}>Refresh certificates</button>{' '}
      <a className="btn ghost" href="#settings/tls">Replace browser certificate</a></p></div>;
  const renewal = <div className="card" data-certificate-group="renew"><h3>Renew instruction signing</h3>
    <p>Keep the existing signing key. Download its public request, have an offline custodian issue the 30-day certificate, then import the approved public certificate here.</p>
    <p className="muted">Signing stops seven days before expiry. Renew from the midpoint of the current certificate's validity. Private root keys stay with their custodians.</p>
    <p><button className="btn" id="certificate-request" disabled={s.busy} onClick={() => c.renewalRequest()}>Download public renewal request</button></p>
    <form id="certificate-renew-form" className="inline-form" onSubmit={event => {event.preventDefault(); c.perform('renew');}}>
      {file('renew', 'certificate-approved', 'Approved OpenSSH certificate (.pub)', s.busy || !s.request || s.unknown.renew, '.pub')}
      <button className="btn" id="certificate-renew" type="submit" disabled={s.busy || !s.request || s.unknown.renew}>Validate and apply renewal</button>
    </form>{result('renew', 'certificate-renew-result')}</div>;
  const state = s.valid.signer ? s.signer.state : 'unavailable';
  const signer = <div className="card" id="signer-rotation" data-certificate-group="signer"><h3>Rotate the instruction signing key</h3>
    <p>Prepare a replacement, obtain its public certificate from an offline custodian, then switch signers. Device roots and instruction counters stay unchanged.</p>
    <p id="rotation-state" role="status" aria-live="polite">{s.loading.signer ? 'Checking rotation state…' : 'Rotation: ' + state.replaceAll('-', ' ') +
      (state === 'completed' ? '. Previous key revoked at keylist sequence ' + s.signer.retired_keylist_seq + '.' : '.')}</p>
    {s.valid.signer && s.signer.request_id && <p className="machine">Request: {s.signer.request_id}</p>}
    {state === 'committing' && <p className="muted">Signer publication is incomplete. Keep the existing request and refresh custody evidence before continuing.</p>}
    <div className="rotation-identities" aria-label="Signer comparison"><div><strong>Previous key SHA256</strong><p className="machine" id="rotation-previous">{s.valid.signer && s.signer.previous_sha256 || 'No rotation evidence'}</p></div>
      <div><strong>Replacement key SHA256</strong><p className="machine" id="rotation-replacement">{s.valid.signer && s.signer.replacement_sha256 || 'No rotation evidence'}</p></div></div>
    <p className="certificate-actions"><button className="btn ghost" id="rotation-refresh" disabled={s.busy || s.loading.signer} onClick={() => c.refresh('signer', true)}>Refresh rotation</button>{' '}{button('prepare', 'Prepare replacement key')}</p>
    <div id="rotation-approval" hidden={state !== 'awaiting-approval'}>
      <p className="certificate-actions"><button className="btn ghost" id="rotation-download" disabled={!c.available('signer')} onClick={() => c.downloadSigner()}>Download replacement public key</button>{' '}{button('cancel', 'Cancel pending replacement', true)}</p>
      <p className="muted">The current signer remains active until you apply approval. On the offline station, run <code>irisctl approve-signing --public-key iris-replacement.pub --root-key /offline/root-a --output replacement-cert.pub</code>.</p>
      <div className="inline-form">{file('activate', 'rotation-certificate', 'Approved replacement certificate (.pub)', blocked('activate'), '.pub')}{button('activate', 'Validate and switch signer')}</div>
    </div>
    <div id="rotation-retirement" hidden={!['retirement-pending', 'retiring'].includes(state)}>
      <p>The replacement is active. The former key can still verify until its certificates expire or its revocation reaches devices. Publish a root-approved retirement list, retaining all existing revocations.</p>
      <div className="inline-form"><label htmlFor="rotation-root">Offline approving root</label><select id="rotation-root" value={s.root} disabled={blocked('retirement-request')} onChange={event => c.root(event.target.value)}>{(s.signer?.root_ids || []).map(root => <option key={root}>{root}</option>)}</select>
        {button('retirement-request', 'Download retirement request', true)}</div>
      <p className="muted">On that root's offline station, run <code>irisctl approve-keylist --payload keylist.payload --root-key /offline/root-a --output keylist.envelope</code>. Use the selected root's private-key path. Return only the public approval.</p>
      <div className="inline-form">{file('retire', 'rotation-keylist', 'Approved retirement list (.envelope)', blocked('retire'), '.envelope')}{button('retire', 'Validate and retire previous key')}</div>
    </div>{result('signer', 'rotation-result')}
    <p className="muted">Server-side completion does not prove device acceptance. Confirm Guest Shell, both IOx architectures and IOS-XR devices fetch the new signer and keylist. Private roots stay offline.</p>
  </div>;
  return <div onFocusCapture={event => {focus.current = event.target;}}>{createPortal(inventory, roots.inventory)}{createPortal(renewal, roots.renewal)}{createPortal(signer, roots.signer)}</div>;
}
export function mountCertificates() {
  const c = new CertificatesController(); window.irisCertificates = c;
  const root = document.getElementById('iris-certificates-root'), roots = Object.fromEntries(['inventory', 'renewal', 'signer'].map(name => [name, document.getElementById('iris-certificates-' + name)]));
  if (!root || Object.values(roots).some(value => !value)) throw Error('Certificate mount point missing');
  createRoot(root).render(<Certificates controller={c} roots={roots} />);
}
