// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useEffect, useLayoutEffect, useRef, useState, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {MonitoringController} from './monitoring-controller.mjs';
import {auditMessage, bounds, clampSelection, deploymentResult, deploymentRows, formatAgo, handleWidth, height,
  panSelection, ranges, width} from './monitoring-model.mjs';
import {formatDate, formatSize} from './image-model.mjs';

function Timeline({kind, state, active, controller}) {
  const id = kind === 'audit' ? 'audit' : 'dl', svg = useRef(null), drag = useRef(null);
  const [pending, setPending] = useState(null), [cursor, setCursor] = useState('new');
  const domain = drag.current?.domain || state.domain;
  const selection = pending || state.selection;
  const outer = bounds(state.range, controller.now());
  const toX = time => (time - domain.since) / (domain.until - domain.since) * width;
  const toTime = (x, d) => d.domain.since + (x - d.rect.left) / d.rect.width * (d.domain.until - d.domain.since);
  function hit(x, rect) {
    if (state.selection && domain) {
      const left = rect.left + toX(state.selection.start) / width * rect.width;
      const right = rect.left + toX(state.selection.end) / width * rect.width;
      if (Math.abs(x - left) <= 8) return 'left';
      if (Math.abs(x - right) <= 8) return 'right';
      if (x > left && x < right) return 'pan';
    }
    return 'new';
  }
  function abort() {
    if (!drag.current) return;
    const pointer = drag.current.pointer;
    drag.current = null;
    setPending(null); setCursor('new');
    controller.setInteracting(kind, false);
    if (svg.current?.hasPointerCapture(pointer)) svg.current.releasePointerCapture(pointer);
  }
  useEffect(() => { if (!active || !state.interacting) abort(); }, [active, state.interacting]);
  function down(event) {
    if (event.button !== 0 || !event.isPrimary || drag.current || !domain) return;
    const rect = svg.current.getBoundingClientRect();
    if (!rect.width) return;
    drag.current = {mode: hit(event.clientX, rect), rect, domain: {...domain}, outer,
      downX: event.clientX, original: state.selection, moved: false, pointer: event.pointerId};
    drag.current.anchor = toTime(event.clientX, drag.current);
    controller.setInteracting(kind, true);
    svg.current.focus();
    svg.current.setPointerCapture(event.pointerId);
    event.preventDefault();
  }
  function move(event) {
    const d = drag.current;
    if (!d) { setCursor(hit(event.clientX, svg.current.getBoundingClientRect())); return; }
    if (d.pointer !== event.pointerId) return;
    if (Math.abs(event.clientX - d.downX) > 3) d.moved = true;
    if (!d.moved) return;
    const at = toTime(event.clientX, d);
    d.pending = d.mode === 'pan' ? panSelection(d.original, at - d.anchor, d.outer)
      : clampSelection(d.mode === 'left' ? d.original.end : d.mode === 'right' ? d.original.start : d.anchor, at, d.outer);
    setPending(d.pending);
    setCursor(d.mode === 'pan' ? 'dragging' : d.mode);
  }
  function up(event) {
    const d = drag.current;
    if (!d || d.pointer !== event.pointerId) return;
    drag.current = null; setPending(null); setCursor('new');
    controller.setInteracting(kind, false);
    if (svg.current.hasPointerCapture(event.pointerId)) svg.current.releasePointerCapture(event.pointerId);
    if (d.moved && d.pending) controller.setSelection(kind, d.pending);
    else if (!d.moved && kind === 'deploylogs') controller.setSelection(kind, null);
    else if (!d.moved && (d.mode === 'new' || d.mode === 'pan') && state.buckets.length) {
      const index = Math.max(0, Math.min(state.buckets.length - 1,
        Math.floor((event.clientX - d.rect.left) / d.rect.width * state.buckets.length)));
      const start = d.domain.since + index * state.bucketSeconds;
      controller.setSelection(kind, {start, end: start + state.bucketSeconds});
    }
  }
  function key(event) {
    if (!domain || !['ArrowLeft', 'ArrowRight'].includes(event.key)) return;
    event.preventDefault();
    const step = state.bucketSeconds || 60, shift = event.key === 'ArrowLeft' ? -step : step;
    const selected = state.selection || {start: domain.since, end: domain.since + step};
    controller.setSelection(kind, event.shiftKey
      ? clampSelection(selected.start, selected.end + shift, outer)
      : panSelection(selected, state.selection ? shift : 0, outer));
  }
  const maximum = Math.max(1, ...state.buckets.map(bucket => bucket.count)), barWidth = width / (state.buckets.length || 1);
  const left = selection && domain ? toX(selection.start) : 0, right = selection && domain ? toX(selection.end) : 0;
  const label = selection ? `${formatDate(selection.start)} – ${formatDate(selection.end)}`
    : `${formatDate(domain?.since ?? outer.since)} – ${domain ? formatDate(domain.until) : 'now'}`;
  return <div id={`${id}-timeline`}>
    <div className="toolbar" id={`${id}-range-chips`}>
      {Object.keys(ranges).map(range => <button key={range} className={`chip${state.range === range ? ' active' : ''}`}
        data-range={range} aria-pressed={state.range === range} onClick={() => controller.setRange(kind, range)}>{range}</button>)}
    </div>
    <svg ref={svg} id={`${id}-histogram`} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none"
      tabIndex={0} role="group" aria-label={`${kind === 'audit' ? 'Audit' : 'Deployment'} time selection`}
      aria-describedby={`${id}-timeline-help`} data-brush-mode={cursor}
      onPointerDown={down} onPointerMove={move} onPointerUp={up} onPointerCancel={abort} onLostPointerCapture={abort} onKeyDown={key}>
      <g id={`${id}-bars`}><line x1={0} y1={height - 1} x2={width} y2={height - 1} className="axis" />
        {state.buckets.map((bucket, index) => {
          const barHeight = bucket.count > 0 ? Math.max(1, Math.round(bucket.count / maximum * (height - 4))) : 0;
          return <rect key={index} className="bar" x={index * barWidth + 1} y={height - barHeight}
            width={Math.max(1, barWidth - 2)} height={barHeight}>
            <title>{`${formatDate(bucket.start)}–${formatDate(bucket.start + state.bucketSeconds)}: ${bucket.count} ${kind === 'audit' ? 'event' : 'deployment'}${bucket.count === 1 ? '' : 's'}`}</title>
          </rect>;
        })}</g>
      <g id={`${id}-brush`}>{selection && domain && <>
        <rect className="brush-sel" x={left} y={0} width={Math.max(0, right - left)} height={height} />
        {[left, right].map((x, index) => <rect key={index} className="brush-handle"
          x={Math.max(0, Math.min(x - handleWidth / 2, width - handleWidth))} y={0} width={handleWidth} height={height} />)}
      </>}</g>
    </svg>
    <p className="muted"><span id={`${id}-window-label`} role="status" aria-live="polite">{label}</span>{' '}
      <button className="linkish" id={`${id}-clear-selection`} hidden={!state.selection} onClick={() => controller.setSelection(kind, null)}>× clear</button></p>
    <p className="muted monitoring-timeline-help" id={`${id}-timeline-help`}>Drag to select a time range. Arrow keys move the selection; Shift + arrow changes its width.</p>
  </div>;
}

function AuditRow({event, now}) {
  const text = auditMessage(event);
  return <tr><td className="nowrap machine" title={formatAgo(event.ts, now)}>{formatDate(event.ts)}</td>
    <td><span className={text.actorClass} title={text.actorTitle || undefined}>{text.actor}</span></td>
    <td className="msg"><span className={`cat-tag cat-${text.category}`}>{text.categoryLabel}</span>{' '}{text.message}
      {text.detail && <> <span className="detail">— {text.detail}</span></>}
      {text.source && <> <span className="muted">(from {text.source})</span></>}</td>
    <td>{event.result && <span className={`badge ${event.result === 'ok' ? 'badge-ok' : 'badge-fail'}`}>{event.result}</span>}</td></tr>;
}

function Monitoring({controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot), audit = state.audit, logs = state.deploylogs;
  const close = useRef(null), opener = useRef(null), wasOpen = useRef(false), detail = state.detail;
  const page = deploymentRows(logs);
  const visible = () => !document.getElementById('view-monitoring')?.hidden;
  useLayoutEffect(() => {
    if (visible() && state.active === 'deploylogs') {
      if (detail) close.current?.focus();
      else if (wasOpen.current) {
        if (opener.current?.isConnected && opener.current.getClientRects().length) opener.current.focus();
        else document.getElementById('dl-refresh')?.focus();
      }
    }
    wasOpen.current = !!detail;
  }, [detail?.generation, state.active]);
  useEffect(() => {
    const escape = event => {
      if (event.key !== 'Escape' || !visible()) return;
      const current = controller.snapshot();
      if (current.detail) controller.closeDetail();
      else if (current[current.active].selection) controller.setSelection(current.active, null);
    };
    document.addEventListener('keydown', escape);
    return () => document.removeEventListener('keydown', escape);
  }, [controller]);
  const empty = (pane, label) => !pane.loaded ? pane.error ? 'Unavailable.' : 'Loading…' : label;
  return <>
    <div className="page-header"><h2 className="page-title">Monitoring</h2></div>
    <div id="monitoring-pane-audit" hidden={state.active !== 'audit'}>
      <h3>Audit trail <span className="scope-tag" id="audit-scope-tag">{ranges[audit.range].label}</span></h3>
      <p className="muted">Every settings change, sign-in, device and image action recorded on this server, kept for 90 days on a rolling basis.</p>
      <div className="toolbar"><span className="joined">
        <select id="audit-category" aria-label="Filter by category" value={audit.category} onChange={event => controller.setCategory(event.target.value)}>
          <option value="">All categories</option>{['auth', 'device', 'image', 'onboard', 'settings', 'telemetry', 'token'].map(category =>
            <option key={category} value={category}>{category === 'onboard' ? 'deployment' : category}</option>)}</select>
        <button className="btn ghost" id="audit-refresh" onClick={() => controller.refresh('audit')}>Refresh</button>
      </span></div>
      <Timeline kind="audit" state={audit} active={state.active === 'audit'} controller={controller} />
      <p className="err" role="status" hidden={!audit.error}>{audit.error}</p>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Audit events"><table className="tbl" id="audit-tbl">
        <thead><tr>{['Time', 'Actor', 'Message', 'Result'].map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead>
        <tbody id="audit-rows">{audit.rows.length ? audit.rows.map((event, index) => <AuditRow key={`${event.ts}:${index}`} event={event} now={controller.now()} />)
          : <tr><td colSpan={4} className="muted">{empty(audit, 'No events in this range.')}</td></tr>}</tbody>
      </table></div>
      <p><button className="btn ghost" id="audit-load-older" disabled={!audit.loaded || audit.busy || audit.olderBusy || audit.exhausted}
        onClick={() => controller.older()}>{audit.olderBusy ? 'Loading older…' : 'Load older'}</button></p>
    </div>
    <div id="monitoring-pane-deploylogs" hidden={state.active !== 'deploylogs'}>
      <h3>Deployment logs <span className="scope-tag" id="dl-scope-tag">{ranges[logs.range].label}</span></h3>
      <p className="muted">Onboarding and undeployment logs kept on the server. Choose a time range, then search or filter its newest 200 logs.</p>
      <Timeline kind="deploylogs" state={logs} active={state.active === 'deploylogs'} controller={controller} />
      <div className="toolbar"><span className="joined">
        <input id="dl-search" placeholder="Search device, action or result" spellCheck={false} aria-label="Search device, action or result"
          value={logs.query} onChange={event => controller.filter({query: event.target.value})} />
        <select id="dl-action" aria-label="Filter by action" value={logs.action} onChange={event => controller.filter({action: event.target.value})}>
          <option value="">Action: any</option><option value="onboard">deployment</option><option value="undeploy">undeploy</option></select>
        <select id="dl-result" aria-label="Filter by result" value={logs.result} onChange={event => controller.filter({result: event.target.value})}>
          <option value="">Result: any</option>{['done', 'error', 'cancelled', 'unknown'].map(result => <option key={result}>{result}</option>)}</select>
        <button className="btn ghost" id="dl-refresh" onClick={() => controller.refresh('deploylogs')}>Refresh</button>
      </span><span className="muted push" id="dl-count">{logs.loaded
        ? `${page.total} log${page.total === 1 ? '' : 's'}${page.total === logs.rows.length ? '' : ` of ${logs.rows.length}`}` : logs.error ? 'Unavailable' : 'Loading…'}</span></div>
      <p className="err" role="status" hidden={!logs.error}>{logs.error}</p>
      <div className="table-scroll" tabIndex={0} role="region" aria-label="Deployment logs"><table className="tbl" id="dl-tbl">
        <thead><tr>{['Finished', 'Device', 'Action', 'Result', 'Size', ''].map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead>
        <tbody id="dl-rows">{page.rows.length ? page.rows.map(log => <tr key={log.file} data-file={log.file}>
          <td className="machine">{formatDate(log.finished_at)}</td><td className="machine">{log.device_id || ''}</td><td>{log.action || ''}</td>
          <td><span className={`badge ${deploymentResult(log).badge}`}>{deploymentResult(log).label}</span>
            {log.rc != null && <> <span className="muted">rc={log.rc}</span></>}</td><td className="machine">{formatSize(log.size)}</td>
          <td><button className="linkish dlog-view" aria-label={`View log for ${log.device_id || log.file}`}
            onClick={event => { opener.current = event.currentTarget; controller.openDetail(log.file); }}>view</button></td></tr>)
          : <tr><td colSpan={6} className="muted">{empty(logs, logs.rows.length ? 'No deployment logs match.' : 'No deployment logs in this range.')}</td></tr>}</tbody>
      </table></div>
      <div className="toolbar" id="dl-pager"><button className="btn ghost" id="dl-prev" disabled={page.page === 0} onClick={() => controller.page(-1)}>‹ Newer</button>
        <span className="muted" id="dl-page">{logs.loaded ? `page ${page.page + 1} of ${page.pages}` : ''}</span>
        <button className="btn ghost" id="dl-next" disabled={page.page >= page.pages - 1} onClick={() => controller.page(1)}>Older ›</button></div>
    </div>
    <div id="dl-drawer" hidden={!detail || state.active !== 'deploylogs'} role="dialog" aria-label="Deployment log">
      <div className="dl-drawer-head"><span className="machine" id="dl-drawer-title">{detail?.file || ''}</span>
        <button ref={close} className="btn ghost" id="dl-drawer-close" aria-label="Close log" onClick={() => controller.closeDetail()}>✕</button></div>
      <pre className="log" id="dl-text">{detail?.text || ''}</pre>
    </div>
  </>;
}

export function mountMonitoring() {
  const root = document.getElementById('iris-monitoring-root');
  if (!root) return;
  const controller = new MonitoringController();
  window.addEventListener('iris:monitoring-command', event => {
    const {action, services, sub, resolve, reject} = event.detail;
    try {
      let result;
      if (action === 'connect') controller.connect(services);
      else if (action === 'select') controller.select(sub);
      else if (action === 'hide') controller.hide();
      else if (action === 'refresh') result = controller.refresh();
      else if (action === 'poll') result = controller.refresh(controller.snapshot().active, true);
      else throw new Error('Unknown Monitoring command');
      Promise.resolve(result).then(resolve, reject);
    } catch (error) { reject?.(error); }
  });
  window.addEventListener('pagehide', event => { if (!event.persisted) controller.dispose(); });
  createRoot(root).render(<Monitoring controller={controller} />);
}
