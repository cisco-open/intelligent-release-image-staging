// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useEffect, useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {ActivityController} from './activity-controller.mjs';
import {active, actionLabel, activityRows, summary} from './activity-model.mjs';
import {deploymentResult} from './monitoring-model.mjs';

function JobLog({entry, selected, focus, busy, controller}) {
  const panel = useRef(null), log = useRef(null), following = useRef(true);
  useLayoutEffect(() => { if (selected) panel.current?.focus(); }, [selected, focus]);
  useLayoutEffect(() => {
    if (selected && following.current && log.current) log.current.scrollTop = log.current.scrollHeight;
  }, [entry.text, selected]);
  return <div ref={panel} className="job-log-panel" data-job={entry.id} tabIndex={-1} hidden={!selected}>
    <div className="job-log-head"><h3>{entry.job.device_id} — {actionLabel(entry.job.action)}</h3>
      <button type="button" className="btn ghost" hidden={entry.terminal || !active(entry.job)} disabled={busy}
        onClick={() => controller.abort(entry.id)}>Abort</button>
      {entry.paused && <button type="button" className="btn ghost" onClick={() => controller.openLog(entry.id)}>Reconnect log</button>}
    </div>
    <pre ref={log} className="log" tabIndex={0} aria-label={`Output for ${entry.job.device_id}`}
      onScroll={() => { following.current = log.current.scrollTop + log.current.clientHeight >= log.current.scrollHeight - 20; }}>{entry.text}</pre>
    {entry.truncated && <p className="muted" role="status">Showing recent output, up to 500 lines. Earlier output is omitted to keep this view responsive.</p>}
  </div>;
}

function Activity({controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot), close = useRef(null), wasOpen = useRef(false);
  const rows = activityRows(state), queued = rows.filter(job => job.state === 'queued');
  useLayoutEffect(() => {
    if (!document.getElementById('view-devices')?.hidden) {
      if (state.open) close.current?.focus();
      else if (wasOpen.current && controller.restoreFocus) document.getElementById('dev-activity')?.focus();
    }
    wasOpen.current = state.open;
  }, [state.open, state.generation]);
  useEffect(() => {
    const escape = event => { if (event.key === 'Escape' && controller.snapshot().open) controller.close(); };
    document.addEventListener('keydown', escape);
    return () => document.removeEventListener('keydown', escape);
  }, [controller]);
  return <aside id="activity-panel" className="drawer" hidden={!state.open} role="dialog" aria-labelledby="activity-title">
    <div className="drawer-head"><h2 id="activity-title">Device activity</h2>
      <button ref={close} className="btn ghost" type="button" id="batch-close" aria-label="Close device activity"
        onClick={() => controller.close()}>Close</button></div>
    <div className="drawer-body"><div id="batch-panel">
      <p id="batch-summary" className="muted" role="status" aria-live="polite">{state.starting ? 'Starting…'
        : state.loaded ? summary(rows, state.scope !== null) : state.error ? 'Activity unavailable.' : 'Loading activity…'}</p>
      <p className="err" role="status" hidden={!state.error}>{state.error}</p>
      <p className="muted" role="status" aria-live="polite" hidden={!state.message}>{state.message}</p>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Device jobs"><table className="tbl" id="batch-table">
        <thead><tr>{['Device', 'State', 'Duration / queue', 'Last output', 'Log'].map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead>
        <tbody id="batch-rows">{rows.map(job => <tr key={job.id} data-job={job.id} data-dev={job.device_id} data-state={job.state} data-action={job.action}>
          <td className="machine">{job.device_id}<div className="job-action-label">{actionLabel(job.action)}</div></td>
          <td><span className={`badge ${deploymentResult(job).badge}`}>{deploymentResult(job).label}</span></td>
          <td className="muted">{job.duration}</td><td className="out machine" title={job.last_line || undefined}>{job.last_line}</td>
          <td><button className="linkish blog" aria-label={`View ${actionLabel(job.action).toLowerCase()} log for ${job.device_id}`}
            onClick={() => controller.openLog(job.id)}>log</button></td>
        </tr>)}</tbody>
      </table></div>
      <div className="toolbar"><button className="btn ghost" id="batch-cancel" hidden={!queued.length} disabled={state.starting || queued.some(job => state.busyJobs.includes(job.id))}
        onClick={() => controller.cancelQueued()}>Cancel queued</button>
      <button className="btn ghost" id="batch-refresh" disabled={state.busy || state.starting} onClick={() => controller.refresh()}>Refresh activity</button></div>
    </div><div id="onboard-logs">{state.logs.map(entry => <JobLog key={entry.id} entry={entry}
      selected={state.selected === entry.id} focus={state.selection} busy={state.busyJobs.includes(entry.id)} controller={controller} />)}</div></div>
  </aside>;
}

export function mountActivity() {
  const root = document.getElementById('iris-activity-root');
  if (!root) return;
  const controller = new ActivityController();
  window.addEventListener('iris:activity-command', event => {
    const {action, services, visible, restoreFocus, jobAction, ids, options, resolve, reject} = event.detail;
    try {
      let result;
      if (action === 'connect') controller.connect(services);
      else if (action === 'open') result = controller.open();
      else if (action === 'close') controller.close(restoreFocus);
      else if (action === 'visibility') result = controller.setVisible(visible);
      else if (action === 'start') result = controller.start(jobAction, ids, options);
      else throw new Error('Unknown Activity command');
      Promise.resolve(result).then(resolve, reject);
    } catch (error) { reject?.(error); }
  });
  window.addEventListener('pagehide', event => { if (!event.persisted) controller.dispose(); });
  createRoot(root).render(<Activity controller={controller} />);
}
