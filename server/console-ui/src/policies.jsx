// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import {useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {distributionAllowed, enforcementLabel, roleConnections} from './policy-model.mjs';
import {PoliciesController} from './policies-controller.mjs';
import {PolicyDialogs} from './policy-dialogs.jsx';
import {OriginEnforcement} from './origin-enforcement.jsx';
import './policy-clarity.css';

function Policies({controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const {policy, definitions} = state;
  const names = Object.keys(definitions).sort();
  const current = controller.current(), warning = controller.capability();
  const disabled = !!warning || state.busy || state.externalBusy || !current;
  const lastFocus = useRef(null);
  useLayoutEffect(() => {
    const node = lastFocus.current;
    if (!state.dialog && controller.visible() && node && (!node.isConnected || node.disabled)
      && (document.activeElement === node || document.activeElement === document.body)) document.getElementById('policy-advanced-open')?.focus();
  }, [state, controller]);
  return <div className="policy-workspace" onFocusCapture={event => {lastFocus.current = event.target;}}>
    <div className="page-header"><h2 className="page-title">Policies</h2></div>
    <p className="page-description">Create or edit a role to choose which devices may exchange image pieces and use the distribution server. Preview the effect before saving, then assign devices in <a href="#devices">Inventory</a>.</p>
    <p className="muted" id="policy-refresh-help">This page loads when you open it and after a save. Use Refresh policies to check for changes from elsewhere.</p>
    <p className="policy-warning" id="role-capability-banner" role="status" aria-live="polite" hidden={!warning}>{warning}</p>
    <div className="policy-simple-heading">
      <div><h3>Device-to-device sharing</h3><p className="muted">A role groups devices with the same rules. The table shows sharing allowed by both roles.</p></div>
      <div className="role-def-actions">
        <button className="btn" disabled={disabled} onClick={() => controller.open()}>New role</button>
        <button className="btn ghost" id="policy-refresh" disabled={state.busy || state.loading} onClick={() => controller.refresh(true)}>{state.loading ? 'Refreshing…' : 'Refresh policies'}</button>
        <button className="btn ghost" id="policy-advanced-open" onClick={() => controller.advanced()}>Advanced…</button>
      </div>
    </div>
    <div className="table-scroll policy-sharing-table" tabIndex={0} role="region" aria-label="Role sharing permissions">
      <table className="tbl" aria-label="Who can share images">
        <thead><tr><th scope="col">Role</th><th scope="col">Can share with these roles</th><th scope="col">Distribution permission</th><th scope="col"><span className="sr-only">Actions</span></th></tr></thead>
        <tbody>{!current ? <tr><td colSpan={4}>Role permissions unavailable. Refresh or check Advanced.</td></tr>
          : !names.length ? <tr><td colSpan={4}>No roles yet. Create a role, then assign devices in Inventory.</td></tr>
          : names.map(name => <tr key={name}>
            <th scope="row">{name}<span className="policy-member-count">{Number.isSafeInteger(policy.roles?.members?.[name]) && policy.roles.members[name] >= 0 ? `${policy.roles.members[name]} ${policy.roles.members[name] === 1 ? 'device' : 'devices'}` : 'Member count unavailable'}</span></th>
            <td><div className="policy-peer-list">{roleConnections(definitions, name).map(peer => <span key={peer} className="policy-peer-name">{peer === name ? `${peer} (same role)` : peer}</span>)}</div></td>
            <td><span className={distributionAllowed(definitions[name]) ? 'policy-access-yes' : 'policy-access-no'}>{distributionAllowed(definitions[name]) ? 'Allowed by role' : 'Not allowed by role'}</span></td>
            <td><button className="linkish" disabled={disabled} onClick={() => controller.open(name)} aria-label={`Edit role ${name}`}>Edit</button></td>
          </tr>)}</tbody>
      </table>
    </div>
    <p className="muted">These are saved permissions, not a connectivity test. Quarantine and explicit access lists can restrict them further.</p>
    <p className="err" role="status">{state.readError}</p>
    <p className={state.failed ? 'err' : 'muted'} id="policy-status" role="status" aria-live="polite" hidden={state.dialog === 'advanced'}>{state.message}</p>
    <OriginEnforcement controller={controller.origin} />
    <details className="policy-scope">
      <summary>How sharing rules take effect</summary>
      <dl className="policy-scope-facts">
        <div><dt>Device-to-device sharing</dt><dd>The tracker controls which peers it introduces. Existing device-to-device transfers may continue after a rule changes.</dd></div>
        <div><dt>Distribution blocking</dt><dd>Distribution access can stop the server's transfers to reviewed addresses. Its confirmed status is separate from the role table.</dd></div>
        <div><dt>Existing server blocklist</dt><dd>{enforcementLabel(policy, state.policyOk)}. This is the existing blocklist's status, not proof that every role restriction is applied.</dd></div>
      </dl>
      <p className="muted">Device reports describe what devices report, not independent proof. Advanced includes delivery status, mismatched roles and troubleshooting details.</p>
    </details>
    <PolicyDialogs controller={controller} state={state} disabled={disabled} />
  </div>;
}

export function mountPolicies() {
  const root = document.getElementById('iris-policies-root');
  if (!root) throw new Error('Policies mount point missing');
  const controller = new PoliciesController(); window.irisPolicies = controller;
  createRoot(root).render(<Policies controller={controller} />);
}
