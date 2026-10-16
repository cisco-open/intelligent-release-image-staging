// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {RoleActionsController} from './role-actions-controller.mjs';

function RoleActions({controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const modal = useRef(null), opener = useRef(null), wasOpen = useRef(false), lastFocus = useRef(null);
  const {open, busy, choice, preview} = state;
  const roles = Object.keys(state.policy?.roles?.members || {}).sort();
  useLayoutEffect(() => {
    if (open && !wasOpen.current) {
      opener.current = document.activeElement?.closest('.menu-wrap')?.querySelector('[aria-expanded]') || document.activeElement;
      document.getElementById('role-selected')?.focus();
    } else if (!open && wasOpen.current && controller.visible()) {
      if (opener.current?.isConnected && !opener.current.disabled && opener.current.getClientRects().length) opener.current.focus();
      else document.getElementById('add-dev')?.focus();
    }
    wasOpen.current = open;
  }, [open, controller]);
  useLayoutEffect(() => {
    if (open && preview && !busy && controller.visible() && document.activeElement?.id === 'role-modal-x') {
      document.getElementById('apply-role-selected')?.focus();
    }
  }, [preview, busy, open, controller]);
  useLayoutEffect(() => {
    // Polling can disable the focused action when policy becomes unavailable.
    if (open && controller.visible() && lastFocus.current?.disabled
      && (document.activeElement === document.body || document.activeElement === lastFocus.current)) {
      document.getElementById('role-modal-x')?.focus();
    }
  }, [busy, state.warning, state.externalBusy, open, controller]);
  useLayoutEffect(() => {
    if (!open) return;
    const keys = event => {
      if (event.key === 'Escape') {event.preventDefault(); event.stopPropagation(); controller.close();}
      if (event.key !== 'Tab') return;
      const nodes = [...modal.current.querySelectorAll('button:not(:disabled),select:not(:disabled),summary')].filter(node => node.getClientRects().length);
      const first = nodes[0], last = nodes.at(-1);
      if (!modal.current.contains(document.activeElement)) {event.preventDefault(); (event.shiftKey ? last : first)?.focus();}
      else if (event.shiftKey && document.activeElement === first) {event.preventDefault(); last?.focus();}
      else if (!event.shiftKey && document.activeElement === last) {event.preventDefault(); first?.focus();}
    };
    document.addEventListener('keydown', keys, true); return () => document.removeEventListener('keydown', keys, true);
  }, [open, controller]);
  return <div ref={modal} id="role-modal" className="modal-backdrop" hidden={!open} role="dialog" aria-modal="true" aria-labelledby="role-modal-title" aria-describedby="role-modal-help" onFocusCapture={event => {lastFocus.current = event.target;}}>
    <form className="modal" onSubmit={event => {event.preventDefault(); document.getElementById('role-modal-x')?.focus(); controller.apply();}}>
      <div className="modal-head"><span id="role-modal-title">Set role <span id="role-modal-count" className="muted">{state.ids.length} reviewed</span></span>
        <button className="btn ghost icon-only" type="button" id="role-modal-x" aria-label="Close" onClick={() => controller.close()}>✕</button></div>
      <div className="modal-body">
        <p id="role-modal-help">Apply one role to the reviewed devices, including other pages. Preview before saving. Only peer policy changes.</p>
        <details className="assignment-targets"><summary>Reviewed devices ({state.ids.length})</summary><ul>{state.ids.map(id => <li key={id}>{id}</li>)}</ul></details>
        <label className="field" htmlFor="role-selected"><span className="field-label">Role</span>
          <select id="role-selected" value={choice} disabled={busy} onChange={event => controller.choice(event.target.value)}>
            <option value="" disabled>— choose a role —</option><option value="__none">— no role —</option>
            {roles.map(role => <option key={role} value={role}>{role}</option>)}
            {choice && choice !== '__none' && !roles.includes(choice) && <option value={choice} disabled>{choice} (unavailable)</option>}
          </select></label>
        {!roles.length && <p className="muted">No roles are defined yet. Open Policies and choose New role.</p>}
        {state.warning && <p className="err" role="status">{state.warning}</p>}
        <p className="role-preview" id="role-preview" aria-live="polite" hidden={!preview}>{preview?.text}</p>
        <p className={'role-message' + (state.failed ? ' err' : '')} id="role-modal-msg" role="status" aria-live="polite">{state.message}</p>
        {state.reviewRequired && <button className="btn ghost" type="button" disabled={busy} onClick={() => controller.review()}>Refresh policy before retrying</button>}
      </div><div className="modal-foot">
        <button className="btn ghost" type="button" id="role-modal-cancel" onClick={() => controller.close()}>Cancel</button>
        <button className="btn" type="submit" id="apply-role-selected" disabled={busy || state.externalBusy || !!state.warning || state.reviewRequired}>{busy ? 'Working…' : preview ? 'Set role' : 'Preview change'}</button>
      </div>
    </form>
  </div>;
}
export function mountRoleActions() {
  const root = document.getElementById('iris-role-actions-root');
  if (!root) throw new Error('Role actions mount point missing');
  const controller = new RoleActionsController(); window.irisRoleActions = controller;
  createRoot(root).render(<RoleActions controller={controller} />);
}
