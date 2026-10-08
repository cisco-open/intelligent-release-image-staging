// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {createPortal} from 'react-dom';
import {SchedulesController} from './schedules-controller.mjs';
import {scheduleTargetSummary, scheduleTargetFromFilters, scheduleNextFireText, scheduleCreatorText, historyText} from './schedules-model.mjs';
import {imageLabel} from './assignments-model.mjs';

function Schedules({controller, dialogRoot}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot), modal = useRef(null), opener = useRef(null), wasOpen = useRef(false), lastFocus = useRef(null);
  const {dialog, form} = state, open = !!dialog, recurring = form.when === 'recurring', assign = form.kind === 'assign';
  useLayoutEffect(() => {
    if (open && !wasOpen.current) {
      opener.current = document.activeElement?.closest('.menu-wrap')?.querySelector('[aria-expanded]') || document.activeElement;
      modal.current.querySelector('input')?.focus();
    } else if (!open && wasOpen.current && controller.visible()) {
      if (opener.current?.isConnected && !opener.current.disabled && opener.current.getClientRects().length) opener.current.focus();
      else document.getElementById('add-dev')?.focus();
    }
    wasOpen.current = open;
  }, [open, controller]);
  useLayoutEffect(() => {
    // Disabling a submitting control can move focus to body. Keep keyboard
    // navigation in this workflow without stealing focus from another control.
    const lost = lastFocus.current && (!lastFocus.current.isConnected || lastFocus.current.disabled || !lastFocus.current.getClientRects().length);
    if (lost && controller.visible() && document.activeElement === document.body) {
      if (open) document.getElementById('sched-modal-x')?.focus();
      else if (state.panelOpen) document.getElementById(state.busy ? 'sched-close' : 'sched-refresh')?.focus();
    }
  }, [state.busy, state.panelOpen, state.rows, open, controller]);
  useLayoutEffect(() => {
    if (!open) return;
    const keys = event => {
      if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); controller.close(); }
      if (event.key !== 'Tab') return;
      const nodes = [...modal.current.querySelectorAll('button:not(:disabled),input:not(:disabled),select:not(:disabled),summary')].filter(node => node.getClientRects().length);
      const first = nodes[0], last = nodes.at(-1);
      if (!modal.current.contains(document.activeElement)) { event.preventDefault(); (event.shiftKey ? last : first)?.focus(); }
      else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    };
    document.addEventListener('keydown', keys, true); return () => document.removeEventListener('keydown', keys, true);
  }, [open, controller]);
  const field = (name, suffix, label, props = {}) => <label className="field" htmlFor={'sched-modal-' + suffix}>
    <span className="field-label">{label}</span><input id={'sched-modal-' + suffix} value={form[name]} disabled={state.busy}
      onChange={event => controller.field(name, event.target.value)} {...props} /></label>;
  const select = (name, suffix, label, options) => <label className="field" htmlFor={'sched-modal-' + suffix}>
    <span className="field-label">{label}</span><select id={'sched-modal-' + suffix} value={form[name]} disabled={state.busy}
      onChange={event => controller.field(name, event.target.value)}>{options.map(([value, label, disabled]) => <option key={value} value={value} disabled={disabled}>{label}</option>)}</select></label>;
  const refresh = () => { if (open) document.getElementById('sched-modal-x')?.focus(); controller.update({panelOpen: true}); return controller.refresh(true); };
  return <>
    <div className="inline-form" id="sched-panel" hidden={!state.panelOpen} aria-label="Schedules" onFocusCapture={event => {lastFocus.current = event.target;}}>
      <div className="table-scroll" role="region" aria-label="Schedules table" tabIndex={0}>
        <table className="tbl"><thead><tr>{['Schedule', 'Action', 'Target', 'Next run', 'State', 'Latest run', 'Created by', 'Actions'].map(title => <th key={title}>{title}</th>)}</tr></thead>
          <tbody id="sched-rows">{state.rows.map(row => <tr key={row.id} data-id={row.id}>
            <td className="machine"><b>{row.id}</b></td><td>{row.kind}</td><td>{scheduleTargetSummary(row)}</td>
            <td>{scheduleNextFireText(row)}</td><td>{row.state}</td><td>{historyText(state.history.get(row.id))}</td>
            <td>{scheduleCreatorText(row)}</td><td>{!row.creator_exists && <button type="button" className="linkish sched-reaffirm"
              disabled={!state.listOk || state.busy || state.externalBusy} onClick={() => {document.getElementById('sched-close')?.focus(); controller.reaffirm(row.id);}}>{state.busyId === row.id ? 'Re-affirming…' : 'Re-affirm'}</button>}</td>
          </tr>)}{!state.rows.length && <tr><td colSpan={8} className="muted">{state.loading ? 'Loading schedules…' : state.listOk
            ? 'No schedules yet. Filter the device table, select devices, and use Schedule… in the bulk bar.' : 'Schedule list unavailable. Refresh to try again.'}</td></tr>}</tbody></table>
      </div>
      {!state.listOk && state.rows.length > 0 && <p className="err" role="status">Schedule list unavailable. Showing the last known schedules; refresh before changing them.</p>}
      <div className="form-actions"><button className="btn ghost" type="button" id="sched-refresh" disabled={state.busy} onClick={refresh}>{state.loading ? 'Refreshing…' : 'Refresh'}</button>
        <button className="btn ghost" type="button" id="sched-close" onClick={() => {controller.closePanel(); document.getElementById('manage-schedules')?.focus();}}>Close</button></div>
      <p className={state.failed ? 'err' : 'muted'} id="sched-status" role="status" aria-live="polite">{state.message}</p>
    </div>
    {createPortal(<div ref={modal} id="sched-modal" className="modal-backdrop" hidden={!open} role="dialog" aria-modal="true" aria-labelledby="sched-modal-title" aria-describedby="sched-modal-help" onFocusCapture={event => {lastFocus.current = event.target;}}>
      <form className="modal" onSubmit={event => {
        event.preventDefault();
        // Move before the submitting control is disabled, not after blur.
        document.getElementById('sched-modal-x')?.focus(); controller.create();
      }}>
        <div className="modal-head"><span id="sched-modal-title">Schedule <span id="sched-modal-count" className="muted">{form.scope === 'filter'
          ? `${dialog?.total || 0} filter matches` : `${dialog?.ids.length || 0} reviewed`}</span></span>
          <button className="btn ghost icon-only" type="button" id="sched-modal-x" aria-label="Close" onClick={() => controller.close()}>✕</button></div>
        <div className="modal-body">
          <p id="sched-modal-help">Choose when to assign images or onboard devices.</p>
          {field('id', 'id', 'Schedule id', {placeholder: 'e.g. core-wave'})}
          {select('scope', 'scope', 'Target', [['filter', 'Reviewed Inventory filter — resolved at each run', !dialog?.filterReady], ['selection', 'Only the reviewed devices']])}
          <p className="muted" id="sched-modal-preview" aria-live="polite">{form.scope === 'selection'
            ? `${dialog?.ids.length || 0} reviewed device(s), named explicitly. Devices matching the filter later are not added.`
            : `The reviewed filter matched ${dialog?.total || 0} device(s) when opened. The schedule resolves it at each run, so that set can differ when it fires.`}</p>
          <details className="assignment-targets"><summary>Reviewed target</summary>{form.scope === 'selection'
            ? <ul>{dialog?.ids.map(id => <li key={id}>{id}</li>)}</ul>
            : <p>{scheduleTargetSummary({target: scheduleTargetFromFilters(dialog?.filters || {}, [], 'filter')})}</p>}</details>
          {select('kind', 'kind', 'Action', [['assign', 'Assign images'], ['onboard', 'Onboard new devices']])}
          {assign ? <>
            <label className="field" htmlFor="sched-modal-images"><span className="field-label">Images to assign</span>
              <select id="sched-modal-images" multiple size={4} value={form.imageIds} disabled={state.busy || !state.imagesOk}
                onChange={event => controller.field('imageIds', [...event.target.selectedOptions].map(option => option.value))}>
                {state.images.map(row => <option key={row.id} value={row.id} disabled={row.quarantined}>{imageLabel(row)}{row.quarantined ? ' (quarantined)' : ''}</option>)}
                {form.imageIds.filter(id => !state.images.some(row => row.id === id)).map(id => <option key={id} value={id} disabled>{id} (unavailable)</option>)}
              </select></label>
            {!state.imagesOk && <p className="err">Image catalog unavailable. Refresh Inventory before creating this schedule.</p>}
            {select('mode', 'mode', 'Assignment mode', [['merge', 'Merge with the existing approved set'], ['replace', 'Replace the approved set']])}
          </> : field('maxDevices', 'max', 'Maximum devices per run', {type: 'number', min: 1, max: 20000})}
          {select('when', 'when', 'When', [['once', 'Once, at a time you pick'], ['recurring', 'Every week']])}
          {recurring ? <>
            {select('weekday', 'weekday', 'Weekday', ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'].map((label, i) => [String(i), label]))}
            {field('time', 'time', 'Local time of day', {type: 'time'})}
          </> : field('at', 'at', "Start (your browser's local time)", {type: 'datetime-local'})}
          {field('tz', 'tz', 'Time zone (IANA)', {placeholder: 'e.g. Europe/Stockholm'})}
          {field('windowMinutes', 'window', 'Window length (minutes)', {type: 'number', min: 1, max: 10080})}
          <p className="role-message" id="sched-modal-msg" role="status" aria-live="polite">{state.formMessage}</p>
          {state.reviewRequired && <button className="btn ghost" type="button" disabled={state.busy || state.loading} onClick={refresh}>Refresh schedules before retrying</button>}
        </div><div className="modal-foot">
          <button className="btn ghost" type="button" id="sched-modal-cancel" onClick={() => controller.close()}>Cancel</button>
          <button className="btn" type="submit" id="create-schedule" disabled={state.busy || state.externalBusy || state.reviewRequired}>{state.busy && !state.busyId ? 'Creating…' : 'Create schedule'}</button>
        </div>
      </form>
    </div>, dialogRoot)}
  </>;
}
export function mountSchedules() {
  const root = document.getElementById('iris-schedules-root'), dialogRoot = document.getElementById('iris-schedule-dialog-root');
  if (!root || !dialogRoot) throw new Error('Schedule mount points missing');
  const controller = new SchedulesController(); window.irisSchedules = controller;
  createRoot(root).render(<Schedules controller={controller} dialogRoot={dialogRoot} />);
}
