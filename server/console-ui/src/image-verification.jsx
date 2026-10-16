// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useEffect, useLayoutEffect, useRef, useState, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {createPortal} from 'react-dom';
import {ImageVerificationController} from './image-verification-controller.mjs';
import {lastRunSummary} from './image-verification-model.mjs';

function Outcome({state, action}) {
  const message = state.messages[action];
  return <p id={`iv-${action}-msg`} tabIndex={-1} className={`err${message?.kind === 'success' ? ' ok' : message?.kind === 'info' ? ' muted' : ''}`}
    role="status" aria-live="polite">{message?.text || ''}</p>;
}

function ImageVerification({controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot), input = useRef(null), bar = useRef(null), focused = useRef(null);
  const [drag, setDrag] = useState(false), canWrite = controller.canWrite();
  const host = document.getElementById(state.host || 'settings-pane-bulkhash');
  useEffect(() => {if (bar.current) bar.current.style.width = `${state.progress}%`;}, [state.progress, state.host]);
  useLayoutEffect(() => {
    const active = focused.current;
    if (active && controller.visible() && (active.node.disabled || active.node.getAttribute('aria-disabled') === 'true')
      && (document.activeElement === active.node || document.activeElement === document.body)) {
      document.getElementById(`iv-${active.action}-msg`)?.focus(); focused.current = null;
    }
  }, [state.busy, state.unknown, state.loading, state.host]);
  const files = values => {
    if (!canWrite) return;
    if (values?.length !== 1) {controller.say('offline', 'Choose one feed archive at a time.'); return;}
    controller.perform('offline', values[0]);
  };
  if (!host) return null;
  return createPortal(<div id="iv-content" className="iris-image-verification" onFocusCapture={event => {
    focused.current = {node: event.target, action: event.target.closest('[data-iv-action]')?.dataset.ivAction || 'review'};
  }}>
    <div className="card" data-iv-action="schedule"><h3>Schedule</h3>
      <p className="muted">IRIS checks catalog image hashes against Cisco's signed Bulk Hash feed. A mismatch quarantines an image and blocks new assignments until it is resolved or explicitly overridden.</p>
      <form className="inline-form" id="iv-schedule-form" onSubmit={event => {event.preventDefault(); controller.perform('schedule');}}>
        <label className="field" htmlFor="iv-mode"><span className="field-label">Frequency</span><select id="iv-mode" disabled={!!state.busy}
          value={state.mode} onChange={event => controller.field('mode', event.target.value)}>
          <option value="off">Off</option><option value="daily">Daily (UTC)</option><option value="weekly">Weekly (Mondays, UTC)</option>
        </select></label>
        <label className="field" htmlFor="iv-hour"><span className="field-label">Hour (UTC)</span><select id="iv-hour" disabled={!!state.busy}
          value={state.hour} onChange={event => controller.field('hour', event.target.value)}>
          {Array.from({length: 24}, (_, hour) => <option key={hour} value={hour}>{String(hour).padStart(2, '0')}:00</option>)}
        </select></label>
        <div className="form-actions"><button type="submit" className="btn" disabled={!canWrite}>Save schedule</button></div>
      </form><Outcome state={state} action="schedule" />
    </div>
    <div className="card" data-iv-action="refresh"><h3>Refresh now</h3>
      <p className="muted">Check Cisco's live feed now, outside the schedule above.</p>
      <div className="iv-actions"><button className="btn ghost" type="button" id="iv-refresh" disabled={!canWrite} onClick={() => controller.perform('refresh')}>Refresh now</button>
        <button className="btn ghost" type="button" id="iv-review" data-iv-action="review" disabled={!!state.busy || state.loading}
          onClick={() => controller.review()}>Review current status</button></div>
      <Outcome state={state} action="refresh" /><Outcome state={state} action="review" />
      <p className="muted" id="iv-last-run" role="status" aria-live="polite">{state.loading ? 'Loading current status…'
        : !state.valid ? 'Could not load current status. Review current status before submitting.'
          : lastRunSummary(state.data.last_run, controller.services.formatDate)}</p>
      {state.unknown && <p className="err" role="status">Review current status to unlock these controls. A latest check does not identify an earlier request whose response was lost.</p>}
    </div>
    <div className="card" data-iv-action="offline"><h3>Offline check</h3>
      <p className="muted">Download <a href="https://tools.cisco.com/cscrdr/security/center/files/trust/Cisco_BulkHash_CSV.tar" target="_blank" rel="noopener">Cisco's Bulk Hash feed</a> on a connected machine, then upload the .tar archive here. IRIS verifies its signature before checking the catalog. Maximum size: 256 MiB.</p>
      <div className={`dropzone${drag ? ' drag' : ''}`} id="iv-offline-dropzone" tabIndex={0} role="button" aria-disabled={!canWrite}
        aria-label="Choose or drop a Cisco Bulk Hash feed tar file" onClick={() => {if (canWrite) input.current.click();}}
        onKeyDown={event => {if (['Enter', ' '].includes(event.key)) {event.preventDefault(); if (canWrite) input.current.click();}}}
        onDragEnter={event => {event.preventDefault(); if (canWrite) setDrag(true);}} onDragOver={event => event.preventDefault()}
        onDragLeave={event => {event.preventDefault(); setDrag(false);}}
        onDrop={event => {event.preventDefault(); setDrag(false); files(event.dataTransfer.files);}}>
        <input ref={input} type="file" id="iv-offline-dropzone-input" accept=".tar" hidden disabled={!canWrite}
          onChange={event => {files(event.target.files); event.target.value = '';}} />
        <p>Drop the feed tar here<span className="hint">or click / press Enter to browse</span></p>
      </div>
      <div className="progress" id="iv-offline-progress" hidden={state.busy !== 'offline'} role="progressbar" aria-valuemin={0} aria-valuemax={100}
        aria-valuenow={state.progress} aria-label="Offline feed upload progress"><div className="bar" id="iv-offline-bar" ref={bar} /></div>
      {state.busy === 'offline' && state.progress === 100 && <p className="muted" role="status">Upload sent. Waiting for signature verification and catalog results.</p>}
      <Outcome state={state} action="offline" />
    </div>
  </div>, host);
}

export function mountImageVerification() {
  const root = document.getElementById('iris-image-verification-root'); if (!root) return null;
  const controller = new ImageVerificationController(); window.irisImageVerification = controller;
  createRoot(root).render(<ImageVerification controller={controller} />); return controller;
}
