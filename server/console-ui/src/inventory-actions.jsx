// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {createPortal} from 'react-dom';
import {InventoryActionsController} from './inventory-actions-controller.mjs';

function InventoryActions({controller, dialogsRoot}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot), file = useRef(null), overlay = useRef(null), opener = useRef(null), wasOpen = useRef(false);
  const dialog = state.dialog, action = dialog?.action || 'onboard', onboard = action === 'onboard', open = !!dialog;
  controller.chooseFile = () => file.current?.click();
  useLayoutEffect(() => {
    if (open && !wasOpen.current) {
      const active = document.activeElement;
      opener.current = active?.closest('.menu-wrap')?.querySelector('[aria-expanded]') || active;
      overlay.current?.querySelector('input')?.focus();
    } else if (!open && wasOpen.current && controller.visible()) {
      if (opener.current?.isConnected && opener.current.getClientRects().length && !opener.current.disabled) opener.current.focus();
      else document.getElementById('add-dev')?.focus();
      opener.current = null;
    }
    wasOpen.current = open;
  }, [open, controller]);
  useLayoutEffect(() => {
    if (!open) return;
    const keys = event => {
      if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); controller.close(); }
      if (event.key !== 'Tab') return;
      const controls = [...overlay.current.querySelectorAll('button:not(:disabled),input:not(:disabled),summary')].filter(node => node.getClientRects().length);
      const first = controls[0], last = controls.at(-1);
      if (!overlay.current.contains(document.activeElement)) { event.preventDefault(); (event.shiftKey ? last : first)?.focus(); }
      else if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    };
    document.addEventListener('keydown', keys, true); return () => document.removeEventListener('keydown', keys, true);
  }, [open, controller]);
  const checkbox = (name, id, label, help) => <label className="check-row"><input type="checkbox" id={id} checked={state.options[name]}
    aria-describedby={help} onChange={event => controller.option(name, event.target.checked)} /> {label}</label>;
  return <>
    <input ref={file} type="file" id="csv-file" accept=".csv" hidden onChange={event => {
      const selected = event.target.files[0]; event.target.value = ''; controller.importFile(selected);
    }} />
    <p id="csv-import-status" role="status" aria-live="polite" hidden={!state.csvMessage} className={state.csvFailed ? 'err' : 'muted'}>{state.csvMessage}</p>
    <p id="csv-download-status" role="status" aria-live="polite" hidden={!state.downloadMessage} className={state.downloadFailed ? 'err' : 'muted'}>{state.downloadMessage}</p>
    {createPortal(<div ref={overlay} id={action + '-modal'} className="modal-backdrop" hidden={!open} role="dialog" aria-modal="true" aria-labelledby={action + '-modal-title'}>
      <div className="modal"><div className="modal-head"><span id={action + '-modal-title'}>{onboard ? 'Onboard' : 'Undeploy'} devices{' '}
        <span id={action + '-modal-count'} className="muted">{dialog?.ids.length || 0} reviewed</span></span>
        <button className="btn ghost icon-only" id={action + '-modal-x'} type="button" aria-label="Close" onClick={() => controller.close()}>✕</button></div>
        <div className="modal-body">
          <details className="assignment-targets"><summary>{dialog?.ids.length || 0} reviewed devices</summary><ul>{dialog?.ids.map(id => <li key={id}>{id}</li>)}</ul></details>
          {onboard ? <>
            <p className="muted">Adds the IRIS agent and starts staging assigned images. Device software is not upgraded.</p>
            {checkbox('telemetry', 'onboard-telemetry', 'Telemetry reports')}
            {checkbox('telemetry_stream', 'onboard-telemetry-stream', 'Live telemetry')}
            {checkbox('onboardLog', 'onboard-log', 'Detailed logs', 'onboard-log-help')}
            <p className="muted" id="onboard-log-help">Show extra troubleshooting details and IOx/IOS-XR download logs.</p>
          </> : <>
            <p className="muted">Removes the IRIS agent and resources listed as IRIS-owned. Keeps staged images in device storage. Does not stop running jobs.</p>
            {checkbox('force', 'undeploy-force', 'Force cleanup', 'undeploy-force-help')}
            <p className="muted" id="undeploy-force-help">For a missing or unusable deployment record. Skips record and device identity checks. Removes only the IRIS agent files and services; keeps VirtualPortGroup and NAT settings. Retires the old record on success.</p>
            {checkbox('undeployLog', 'undeploy-log', 'Detailed logs', 'undeploy-log-help')}
            <p className="muted" id="undeploy-log-help">Show extra troubleshooting details. Errors are always shown.</p>
          </>}
        </div><div className="modal-foot">
          <button className="btn ghost" id={action + '-cancel'} type="button" onClick={() => controller.close()}>Cancel</button>
          <button className={onboard ? 'btn' : 'btn danger'} id={action + '-confirm'} type="button" disabled={state.busy || state.externalBusy} onClick={() => controller.start()}>Start {action}</button>
        </div></div>
    </div>, dialogsRoot)}
  </>;
}
export function saveCsv(text, filename) {
  const url = URL.createObjectURL(new Blob([text], {type: 'text/csv'})), link = document.createElement('a');
  try { link.href = url; link.download = filename; document.body.appendChild(link); link.click(); }
  finally { link.remove(); URL.revokeObjectURL(url); }
}
export function mountInventoryActions() {
  const root = document.getElementById('iris-csv-root'), dialogsRoot = document.getElementById('iris-inventory-actions-root');
  if (!root || !dialogsRoot) throw new Error('Inventory action mount points missing');
  const controller = new InventoryActionsController(); window.irisInventoryActions = controller;
  controller.saveCsv = saveCsv;
  createRoot(root).render(<InventoryActions controller={controller} dialogsRoot={dialogsRoot} />);
}
