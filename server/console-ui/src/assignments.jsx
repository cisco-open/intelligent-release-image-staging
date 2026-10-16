// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {AssignmentsController} from './assignments-controller.mjs';
import {pickerRows} from './assignments-model.mjs';

function Assignments({controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const overlay = useRef(null), opener = useRef(null), wasOpen = useRef(false);
  useLayoutEffect(() => {
    if (state.open && !wasOpen.current) {
      const active = document.activeElement, menu = active?.closest('.menu');
      opener.current = menu?.closest('.menu-wrap')?.querySelector('[aria-expanded]') || active;
      overlay.current?.querySelector(state.type === 'credentials' ? 'select' : '#img-picker-cancel')?.focus();
    } else if (!state.open && wasOpen.current && controller.visible()) {
      const target = opener.current;
      if (target?.isConnected && target.getClientRects().length) target.focus();
      else document.getElementById('add-dev')?.focus();
      opener.current = null;
    }
    wasOpen.current = state.open;
  }, [state.open, state.type, controller]);
  useLayoutEffect(() => {
    if (state.open && state.busy && (!overlay.current?.contains(document.activeElement) || document.activeElement?.disabled)) {
      overlay.current?.querySelector('#img-picker-cancel, #cred-modal-cancel')?.focus();
    }
  }, [state.open, state.busy]);
  useLayoutEffect(() => {
    if (!state.open) return;
    const listener = event => keys(event);
    document.addEventListener('keydown', listener, true);
    return () => document.removeEventListener('keydown', listener, true);
  }, [state.open, controller]);
  const close = () => controller.close();
  const keys = event => {
    if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(); }
    if (event.key !== 'Tab') return;
    const controls = [...overlay.current.querySelectorAll('button:not(:disabled),select:not(:disabled),input:not(:disabled),summary,[tabindex="0"]')]
      .filter(node => node.getClientRects().length);
    const first = controls[0], last = controls.at(-1);
    if (!overlay.current.contains(document.activeElement)) { event.preventDefault(); (event.shiftKey ? last : first)?.focus(); }
    else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  };
  const images = state.type === 'images', disabled = state.busy || !state.ready || state.externalBusy;
  return <div ref={overlay} id={images ? 'img-picker' : 'cred-modal'} className="modal-backdrop" hidden={!state.open}
    role="dialog" aria-modal="true" aria-label={images ? 'Choose images' : 'Set credential'}>
    <div className="modal">
      <div className="modal-head"><span>{images ? 'Choose images' : 'Set credential'}{' '}
        <span className="muted" id={images ? 'img-picker-count' : 'cred-modal-count'}>{images ? `${state.chosen.length}/10` : `${state.ids.length} reviewed`}</span></span>
        <button className="btn ghost icon-only" id={images ? 'img-picker-x' : 'cred-modal-x'} type="button" aria-label="Close" onClick={close}>✕</button></div>
      <div className="modal-body">
        <details className="assignment-targets"><summary>{state.ids.length} reviewed device{state.ids.length === 1 ? '' : 's'}</summary>
          <ul>{state.ids.map(id => <li key={id}>{id}</li>)}</ul></details>
        {images ? <>
          <p id="img-picker-note" className="muted" hidden={!state.different} role="status" aria-live="polite">
            These devices have different image assignments. Apply gives them all the selected images. Confirm before removing existing assignments.</p>
          {state.loading && <p role="status">Reading current assignments…</p>}
          {!state.imagesOk && <p className="err" role="status">Image catalog unavailable. Review again before applying.</p>}
          <div id="img-picker-rows">{pickerRows(state).map(image => <label className="img-pick-row" key={image.id}>
            <input className="img-pick" type="checkbox" value={image.id} checked={image.checked} disabled={image.disabled}
              data-blocked={image.quarantined ? '1' : undefined} onChange={() => controller.toggleImage(image.id)} />{' '}{image.label}{' '}
            {image.quarantined && <span className="badge badge-fail" title="Hash mismatch reported by Cisco Bulk Hash">quarantined</span>}{' '}
            {image.unknown && <span className="muted">{image.retained ? 'not in the catalog; kept as assigned' : 'no longer in the catalog; remove this choice'}</span>}
          </label>)}{!state.loading && state.ready && !state.order.length && <p className="muted">No images in the catalog yet.</p>}</div>
        </> : <label className="field" htmlFor="cred-selected"><span className="field-label">Credential profile</span>
          <select id="cred-selected" value={state.choice} disabled={state.busy || !state.credentialsOk} onChange={event => controller.chooseCredential(event.target.value)}>
            <option value="" disabled>— choose a credential profile —</option>
            <option value="clear">— no credential (clear the assignment) —</option>
            {state.credentials.map(profile => <option key={profile.id} value={'profile:' + profile.id}>{profile.id}</option>)}
            {state.choice.startsWith('profile:') && !state.credentials.some(profile => 'profile:' + profile.id === state.choice)
              && <option value={state.choice} disabled>{state.choice.slice(8)} (unavailable)</option>}
          </select>{!state.credentialsOk && <span className="err">Credential profiles unavailable. Close and refresh profiles.</span>}
        </label>}
        <p className={state.failed ? 'err' : 'muted'} id={images ? 'img-picker-message' : 'cred-modal-msg'} role="status" aria-live="polite">{state.message}</p>
        {state.busy && images && <p role="status">{state.results.length}/{state.ids.length} responses received</p>}
      </div>
      <div className="modal-foot">
        <button className="btn ghost" type="button" id={images ? 'img-picker-cancel' : 'cred-modal-cancel'} onClick={close}>Cancel</button>
        {images && <button className="btn ghost" type="button" id="img-picker-review" disabled={state.busy || state.loading} onClick={() => controller.review()}>Review current assignments</button>}
        <button className="btn" type="button" id={images ? 'img-picker-apply' : 'apply-cred-selected'}
          disabled={disabled || (images ? !state.imagesOk : !state.credentialsOk)} onClick={() => images ? controller.applyImages() : controller.applyCredential()}>Apply</button>
      </div>
    </div>
  </div>;
}
export function mountAssignments() {
  const root = document.getElementById('iris-assignments-root');
  if (!root) throw new Error('Assignments mount point is missing');
  const controller = new AssignmentsController(); window.irisAssignments = controller;
  createRoot(root).render(<Assignments controller={controller} />);
}
