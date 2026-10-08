// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {Fragment, useEffect, useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {DeviceDetailsController} from './device-details-controller.mjs';
import {boundarySteps, hardwareRows, imageRows, recordRows} from './device-details-model.mjs';
import {formatDate, formatSize} from './image-model.mjs';
import {deploymentResult} from './monitoring-model.mjs';

const steps = ['Catalogued', 'Source checked', 'Assigned', 'Transferring', 'Verified', 'Staged'];
const icons = {negative: 'i-octagon-x', severe: 'i-diamond-severe', warning: 'i-triangle-warn'};

function BoundaryMarker({entry}) {
  if (entry?.state === 'failed') return <span className="boundary-marker"><span className={`status-pill is-${entry.level}`}>
    <svg aria-hidden="true"><use href={`#${icons[entry.level]}`} /></svg>{entry.label}</span></span>;
  if (entry === 'done') return <span className="boundary-circle is-done"><svg aria-hidden="true"><use href="#i-check" /></svg></span>;
  if (entry === 'current') return <span className="boundary-circle is-current"><span className="boundary-dot" /></span>;
  if (entry === 'na') return <span className="boundary-circle is-na" />;
  return <span className="boundary-circle is-upcoming" />;
}

function StagingBoundary({entries}) {
  return <div className="staging-boundary">{steps.map((label, index) => <Fragment key={label}>
    {index > 0 && <span className="boundary-connector" aria-hidden="true" />}
    <span className={`boundary-step is-${entries[index]?.state || entries[index] || 'upcoming'}`}>
      <BoundaryMarker entry={entries[index]} /><span className="boundary-label">{label}</span>
    </span>
  </Fragment>)}<span className="boundary-connector" aria-hidden="true" />
    <span className="boundary-terminus"><span className="boundary-terminus-label">Operator control</span></span>
  </div>;
}

function DeviceDetails({controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot);
  const close = useRef(null), wasOpen = useRef(false), deviceId = useRef(null);
  const visible = () => !document.getElementById('view-devices')?.hidden;
  useLayoutEffect(() => {
    if (visible()) {
      if (state) { deviceId.current = state.id; close.current?.focus(); }
      else if (wasOpen.current && controller.restoreFocus) {
        if (controller.opener?.isConnected && controller.opener.getClientRects().length) controller.opener.focus();
        else {
          // Inventory polling may have replaced the original button.
          const row = [...document.querySelectorAll('#dev-rows tr[data-id]')]
            .find(node => node.getAttribute('data-id') === deviceId.current);
          (row?.querySelector('.dinfo') || document.getElementById('dev-filter-q'))?.focus();
        }
      }
    }
    wasOpen.current = !!state;
  }, [state?.generation]);
  useEffect(() => {
    const escape = event => {
      if (event.key === 'Escape' && visible() && controller.snapshot()) controller.close();
    };
    document.addEventListener('keydown', escape);
    return () => document.removeEventListener('keydown', escape);
  }, [controller]);
  const hardware = hardwareRows(state?.device, state?.record);
  const records = state?.record ? recordRows(state.record, state.total) : [];
  const images = imageRows(state?.device || {}, state?.filenames);
  return <div id="deploy-info-panel" className="drawer" hidden={!state} role="dialog" aria-label="Deployment details">
    <div className="drawer-head"><span>Deployment details <span id="di-dev" className="machine">{state?.id}</span></span>
      <button ref={close} className="btn ghost" id="di-close" aria-label="Close deployment details" onClick={() => controller.close()}>✕</button></div>
    <div className="drawer-body">
      <p className="muted" id="di-note" role="status" aria-live="polite">{state?.note}</p>
      <div className="card"><div id="di-boundary"><StagingBoundary entries={boundarySteps(state?.device || {}, state?.status,
        state?.failedRatio, state?.quarantined)} /></div></div>
      <div className="card"><h3>SSH host key</h3>
        <p className="muted">If this device was re-imaged or replaced and sessions now fail with a changed host key error,
          verify its identity before forgetting the saved key. The next connection will trust and save the key it presents.</p>
        <button type="button" className="btn ghost" id="di-forget-host-key" disabled={!state || state.forgetBusy}
          onClick={() => controller.forgetHostKey()}>Forget host key</button>
        <p className="muted" id="di-forget-host-key-status" role="status" aria-live="polite">{state?.forgetStatus}</p>
      </div>
      <h3>Images</h3>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Device images"><table className="tbl" id="di-img-tbl">
        <thead><tr><th scope="col">Image</th><th scope="col">State</th></tr></thead><tbody id="di-img-rows">
          {images.length ? images.map((row, index) => <tr key={index}><td className={row.id ? 'machine' : 'muted'}>{row.label}</td><td>{row.state}</td></tr>)
            : <tr><td colSpan={2} className="muted">No images assigned.</td></tr>}
        </tbody></table></div>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Deployment record"><table className="tbl" id="di-tbl"><tbody id="di-rows">
        {[...hardware, ...records].map(row => <tr key={row.label}><td className="muted">{row.label}</td><td>
          <span className={row.badge ? `badge ${row.badge}` : row.machine ? 'machine' : undefined}>{row.value}</span>
          {row.note && <> <span className="muted">({row.note})</span></>}</td></tr>)}
      </tbody></table></div>
      <h3>Deployment logs</h3>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Device deployment logs"><table className="tbl" id="di-log-tbl">
        <thead><tr>{['Finished', 'Action', 'Result', 'Size', 'Log'].map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead>
        <tbody id="di-log-rows">{state?.logs.length ? state.logs.map((log, index) => <tr key={index} data-file={log.file}>
          <td className="machine">{formatDate(log.finished_at) || 'Unknown'}{log.previous_registration && <> <span className="badge badge-off"
            title="This run finished before the current device was registered under this name, so it belongs to a previous device.">previous device</span></>}</td>
          <td>{log.action}</td><td><span className={`badge ${deploymentResult(log).badge}`}>
            {deploymentResult(log).label}</span>{log.rc != null && <> <span className="muted">rc={log.rc}</span></>}</td><td className="machine">{formatSize(log.size)}</td>
          <td><button className="linkish dlog-view" aria-label={`View ${log.file}`} onClick={() => controller.openFile(log.file)}>view</button></td>
        </tr>) : <tr><td colSpan={5} className="muted">{state?.logNote}</td></tr>}</tbody>
      </table></div>
      <pre className="log" id="di-log-text" hidden={!state?.file} tabIndex={0} aria-label={state?.file?.name || 'Device log'}>{state?.file?.text}</pre>
    </div>
  </div>;
}

export function mountDeviceDetails() {
  const root = document.getElementById('iris-device-details-root');
  if (!root) return;
  const controller = new DeviceDetailsController();
  window.addEventListener('iris:device-details-command', event => {
    const {action, services, id, data, restoreFocus, resolve, reject} = event.detail;
    try {
      let result;
      if (action === 'connect') controller.connect(services);
      else if (action === 'open') {
        controller.opener = document.activeElement;
        result = controller.open(id, data);
      } else if (action === 'close') controller.close(restoreFocus);
      else throw new Error('Unknown device details command');
      Promise.resolve(result).then(resolve, reject);
    } catch (error) { reject?.(error); }
  });
  window.addEventListener('pagehide', event => { if (!event.persisted) controller.dispose(); });
  createRoot(root).render(<DeviceDetails controller={controller} />);
}
