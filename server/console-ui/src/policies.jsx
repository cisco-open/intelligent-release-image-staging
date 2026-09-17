// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import {useEffect, useState} from 'react';
import {createRoot} from 'react-dom/client';
import {distributionAllowed, enforcementLabel, roleConnections} from './policy-model.mjs';

const request = (action, name) => window.dispatchEvent(new CustomEvent('iris:policy-action', {detail: {action, name}}));

function Policies() {
  const [state, setState] = useState({ready: false, definitionsReady: false, policy: {}, definitions: {}, disabled: true});
  useEffect(() => {
    const update = event => setState(event.detail);
    window.addEventListener('iris:policy-state', update);
    return () => window.removeEventListener('iris:policy-state', update);
  }, []);
  const {policy, definitions} = state;
  const names = Object.keys(definitions).sort();
  const current = state.ready && state.definitionsReady && state.revision === policy.revision;
  const previewOnly = state.ready && policy.enforcement?.mutual_origin?.mode === 'preflight';
  return <>
    <div className="policy-simple-heading">
      <div><h3>Who can share images</h3><p className="muted">Role-to-role sharing needs permission from both sides.</p></div>
      <div className="role-def-actions">
        <button className="btn" disabled={state.disabled} onClick={() => request('new')}>New role</button>
        <button className="btn ghost" onClick={() => request('advanced')}>Advanced…</button>
      </div>
    </div>
    <div className="table-scroll policy-sharing-table" tabIndex={0} role="region" aria-label="Role sharing permissions">
      <table className="tbl" aria-label="Who can share images">
        <thead><tr><th scope="col">Role</th><th scope="col">Can share with</th><th scope="col">Distribution server</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
        <tbody>{!current ? <tr><td colSpan={4}>Role permissions unavailable. Refresh or check Advanced.</td></tr>
          : !names.length ? <tr><td colSpan={4}>No roles yet. Create a role, then assign devices in Inventory.</td></tr>
          : names.map(name => <tr key={name}>
            <th scope="row">{name}<span className="policy-member-count">{Number.isInteger(policy.roles?.members?.[name]) ? `${policy.roles.members[name]} ${policy.roles.members[name] === 1 ? 'device' : 'devices'}` : 'Member count unavailable'}</span></th>
            <td><div className="policy-peer-list">{roleConnections(definitions, name).map(peer => <span key={peer} className="policy-peer-name">{peer === name ? `${peer} (same role)` : peer}</span>)}</div></td>
            <td><span className={distributionAllowed(definitions[name]) ? 'policy-access-yes' : 'policy-access-no'}>{distributionAllowed(definitions[name]) ? 'Allowed by role' : 'Not allowed by role'}</span></td>
            <td><button className="linkish" disabled={state.disabled || !current} onClick={() => request('edit', name)} aria-label={`Edit role ${name}`}>Edit</button></td>
          </tr>)}</tbody>
      </table>
    </div>
    <p className="muted">Shows configured role permissions, not a live connectivity test. Quarantine and device or server ACLs can restrict access further.</p>
    <section className="policy-enforcement-summary" aria-labelledby="policy-enforcement-title">
      <h3 id="policy-enforcement-title">Enforcement</h3>
      <dl>
        <div><dt>Role-to-role sharing</dt><dd>Controls which peers the tracker introduces. Existing transfers may continue.</dd></div>
        <div><dt>Distribution server blocklist</dt><dd>{enforcementLabel(policy, state.ready)}<span className="policy-member-count">Status of the existing blocklist, not all role restrictions.</span></dd></div>
        <div><dt>Role restrictions at the server</dt><dd className="policy-access-no">{previewOnly ? 'Preview only — not enforced at the distribution server' : 'Enforcement status unavailable'}</dd></div>
      </dl>
      <p className="muted">Device reports are not independent proof of enforcement. Advanced shows delivery, drift and troubleshooting details.</p>
    </section>
  </>;
}

export function mountPolicies() {
  const root = document.getElementById('iris-policies-root');
  if (root) createRoot(root).render(<Policies />);
}
