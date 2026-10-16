// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {createPortal} from 'react-dom';
import {InventoryController} from './inventory-controller.mjs';
import {PAGE_SIZE, selectionScope, managementLabel, telemetryBadge, tlsBadge, instructionBadge, enforcementBadge} from './inventory-model.mjs';

const filterSpecs = [
  ['modelFamily', 'model-family', 'device series', 'Device series: any', [['IE3x00', 'IE Switches'], ['IR1x00', 'IR Routers'], ['C8xxx', 'Catalyst Routers'], ['C9xxx', 'Catalyst Switches'], ['NCS', 'NCS'], ['XR8000', 'Cisco 8000 Series'], ['ISR/ASR/CSR', 'ISR/ASR/CSR'], ['unknown', 'Unknown series']]],
  ['platform', 'platform', 'agent install', 'Agent install: any', [['guestshell', 'Guest Shell'], ['iox', 'IOx'], ['router', 'Guest Shell (router)'], ['xr-appmgr', 'XR appmgr container'], ['__none', '— unset —']]],
  ['status', 'status', 'status', 'Status: any', []],
  ['managementType', 'management-type', 'management type', 'Management type: any', [['routed', 'routed'], ['inband', 'inband'], ['router-routed', 'router-routed'], ['router-nat', 'router-nat'], ['xr-host', 'XR host'], ['legacy', 'Inventory only — management type not chosen']]],
  ['cred', 'cred', 'credential profile', 'Credential: any', [['__none', '— none —']]],
  ['telemetry', 'telemetry', 'telemetry state', 'Telemetry: any', [['on', 'on'], ['off', 'off'], ['unknown', 'unknown (no heartbeat yet)']]],
  ['peer', 'peer', 'peer policy', 'Peer policy: any', [['quarantined', 'quarantined'], ['not-quarantined', 'not quarantined']]],
  ['role', 'role', 'declared role', 'Role: any', [['__none', '— no role —']]],
  ['osFamily', 'os-family', 'OS family', 'OS family: any', [['xe', 'IOS XE / IOS'], ['xr', 'IOS XR']]],
];
const icons = {positive: 'i-check-circle', progress: 'i-dash-circle', negative: 'i-octagon-x', warning: 'i-triangle-warn',
  severe: 'i-diamond-severe', info: 'i-square-info', inactive: 'i-minus-circle', disabled: 'i-slash-circle'};
function Pill({level = 'inactive', label, title}) {
  return <span className={`status-pill is-${level}`} title={title}><svg aria-hidden="true"><use href={'#' + (icons[level] || icons.inactive)} /></svg>{label}</span>;
}
function Badge({value}) { return <span className={value.cls ? 'badge ' + value.cls : 'muted'} title={value.title}>{value.label}</span>; }
function Caret() { return <svg className="caret" viewBox="0 0 16 16" aria-hidden="true"><path d="M4.5 6.5 8 10l3.5-3.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>; }
function action(controller, id) { return event => controller.action(id, event); }

function Inventory({controller, selectionRoot, tableRoot, capabilityRoot, statusRoot}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot), summary = useRef(null);
  const scope = selectionScope(state), services = controller.services || {};
  const options = spec => {
    const key = spec[0]; let values = spec[4];
    if (key === 'status') values = [...(services.statusOptions || [])].sort((a, b) => a[1].localeCompare(b[1])).concat([['__attention', 'Needs attention (any)']]);
    if (key === 'cred') values = values.concat(state.credentials.map(row => [row.id, row.id]));
    if (key === 'role') values = values.concat(Object.keys(state.policy?.roles?.members || {}).sort().map(id => [id, id]));
    if (state.filters[key] && !values.some(([id]) => id === state.filters[key])) values = values.concat([[state.filters[key], state.filters[key]]]);
    return values;
  };
  const chips = Object.entries(state.filters).filter(([, value]) => value).map(([key, value]) => {
    const spec = filterSpecs.find(row => row[0] === key);
    return {key, label: spec ? options(spec).find(([id]) => id === value)?.[1] || value : value};
  });
  const menu = name => {
    controller.update({menu: state.menu === name ? '' : name});
  };
  useEffect(() => {
    const close = event => {
      if (event.type === 'keydown' && event.key !== 'Escape') return;
      if (event.type === 'click' && event.target.closest('.menu-wrap, #status-legend-btn, #status-legend-pop')) return;
      const active = controller.snapshot().menu;
      if (active && event.type === 'keydown') document.getElementById(active === 'csv' ? 'csv-menu-btn' : active === 'more' ? 'more-menu-btn' : 'status-legend-btn')?.focus();
      controller.update({menu: ''});
    };
    document.addEventListener('click', close); document.addEventListener('keydown', close);
    return () => { document.removeEventListener('click', close); document.removeEventListener('keydown', close); };
  }, [controller]);
  const bulkButton = (id, label, cls = 'menu-item menu-close') => <button key={id} type="button" id={id}
    className={cls} disabled={state.bulkBusy || state.rowBusy.size > 0 || state.actionBusy.has(id)
      || (id === 'set-role-selected' && !state.roleAvailable)} onClick={action(controller, id)}>{label}</button>;
  const selection = <div className="selbar" id="sel-bar" hidden={!state.selected.size}>
    <span className="sel-count" id="sel-count">{state.selected.size} selected</span>
    <span className="muted" id="sel-scope-text" hidden={!scope.text}>{scope.text}</span>
    <button className="btn tertiary" type="button" id="sel-scope-all" hidden={!scope.offerAll}
      disabled={state.selectionBusy || state.bulkBusy} onClick={() => controller.selectAll()}>
      {state.selectionBusy ? '· Selecting…' : `· Select all ${state.total} matching devices`}</button>
    <button className="btn tertiary" type="button" id="sel-clear" onClick={() => controller.clearSelection()}>Cancel</button>
    <div className="selbar-actions">
      {bulkButton('assign-images-selected', 'Assign images…', 'btn ghost')}
      {bulkButton('undeploy-selected', 'Undeploy…', 'btn ghost')}
      {bulkButton('onboard-selected', 'Onboard…', 'btn')}
      <div className="menu-wrap">
        <button className="btn ghost icon-only" type="button" id="more-menu-btn" aria-expanded={state.menu === 'more'}
          aria-haspopup="true" aria-label="More actions" title="More actions" onClick={() => menu('more')}>
          <svg viewBox="0 0 16 16" aria-hidden="true">{[3.5, 8, 12.5].map(cx => <circle key={cx} cx={cx} cy="8" r="1.35" fill="currentColor" />)}</svg></button>
        <div className="menu right" id="more-pop" hidden={state.menu !== 'more'}>
          {bulkButton('adopt-selected', 'Adopt')}{bulkButton('quarantine-selected', 'Quarantine')}{bulkButton('release-selected', 'Release')}
          {bulkButton('set-cred-selected', 'Set credential…')}{bulkButton('set-role-selected', 'Set role…')}{bulkButton('schedule-selected', 'Schedule…')}
          <hr className="menu-divider" />{bulkButton('delete-selected', 'Delete…', 'menu-item danger menu-close')}
        </div>
      </div>
    </div>
  </div>;
  const table = <div className="devices-table-wrap"><div className="table-scroll" tabIndex={0} role="region" aria-label="Device inventory">
    <table className="tbl dense" id="devices"><thead><tr>
      {['Device', 'Role', 'IP', 'Model', 'Management type', 'Agent install', 'Credential', 'Assigned images', 'Telemetry', 'Peer policy', 'Instructions'].map(label => <th key={label}>{label}</th>)}
      <th>Status <button className="linkish" type="button" id="status-legend-btn" aria-expanded={state.menu === 'legend'}
        aria-label="Show status pill legend" onClick={() => menu('legend')}>ⓘ</button></th>
    </tr></thead><tbody id="dev-rows">
      {state.rows.map(device => {
        const id = device.device_id, busy = state.rowBusy.has(id), instruction = instructionBadge(device);
        const assigned = services.assignedIds?.(device) || [], quarantined = state.policy?.quarantine_assignments?.includes(id);
        const presentation = services.status?.(device, state.now) || {pills: []};
        const knownCredential = device.credential_profile_id || '', platform = device.platform || '';
        const creds = state.credentialsOk ? state.credentials.map(row => row.id) : [];
        if (knownCredential && !creds.includes(knownCredential)) creds.push(knownCredential);
        return <tr key={id} data-id={id} tabIndex={0} className={state.selected.has(id) ? 'sel' : ''}
          aria-selected={state.selected.has(id)} aria-label={id} aria-description="Press Space or Enter to select or deselect this device."
          onClick={event => {
            if (event.button !== 0 || event.target.closest('button,a,input,select,textarea,label,summary,[role="button"],[contenteditable="true"]')) return;
            if (window.getSelection().isCollapsed) controller.toggle(id);
          }} onKeyDown={event => {
            if (event.target !== event.currentTarget || ![' ', 'Enter'].includes(event.key)) return;
            event.preventDefault(); if (!event.repeat) controller.toggle(id);
          }}>
          <td className="dev-id"><button type="button" className="linkish dinfo" onClick={() => services.details?.(id)}>{id}</button></td>
          <td className="dev-role">{device.role || '—'}</td><td className="machine">{device.device_ip || '—'}</td>
          <td className="dev-series" title={device.model || device.heartbeat_model || ''}>{services.seriesLabel?.(device.model_family, device.model || device.heartbeat_model)}</td>
          <td>{managementLabel(device)}</td>
          <td><select className="platform" aria-label={`Agent install for ${id}`} value={platform} disabled={busy || state.bulkBusy}
            onChange={event => controller.edit(id, 'platform', event.target.value)}>
            {['', 'guestshell', 'iox', 'router', 'xr-appmgr'].map(value => {
              const refused = value && value !== platform && Array.isArray(device.install_options) && !device.install_options.includes(value);
              return <option key={value} value={value} disabled={!!refused} title={refused ? services.installRefusal?.(device, value) : undefined}>
                {value ? services.installLabel?.(value) : '— auto —'}</option>;
            })}</select></td>
          <td><select className="cred" aria-label={`Credential for ${id}`} value={knownCredential}
            disabled={busy || state.bulkBusy || !state.credentialsOk}
            title={!state.credentialsOk ? 'Credential list unavailable; showing the assignment as recorded in the inventory' : undefined}
            onChange={event => controller.edit(id, 'credential', event.target.value)}>
            <option value="">— no credential —</option>{creds.map(value => <option key={value} value={value}>{value}</option>)}</select></td>
          <td><button type="button" className="linkish assign-btn" disabled={busy || state.bulkBusy}
            onClick={() => services.assign?.(id)}>{assigned.length ? `${assigned.length} image(s)` : '— assign —'}</button></td>
          <td><Badge value={telemetryBadge(device)} /> <Badge value={tlsBadge(device, state.now)} /></td>
          <td><span className={`peer-intent badge ${state.policyOk && quarantined ? 'badge-fail' : 'badge-off'}`}>
            {!state.policyOk ? 'Policy unavailable' : quarantined ? 'Quarantined intent' : 'Not quarantined'}</span>{' '}
            <Badge value={enforcementBadge(state.policy, state.policyOk)} />{' '}
            <button type="button" className="linkish peer-quarantine" disabled={busy || state.bulkBusy || !state.policyOk}
              title={quarantined ? 'Release device from quarantine' : 'Quarantine device'}
              aria-label={(quarantined ? 'Release ' : 'Quarantine ') + id} onClick={() => controller.edit(id, 'quarantine', !quarantined)}>{quarantined ? 'Release' : 'Quarantine'}</button></td>
          <td><Badge value={instruction} />{instruction.detail && <div className="muted">{instruction.detail}</div>}</td>
          <td>{presentation.pills.map((pill, index) => <span key={index}><Pill {...pill} />{' '}</span>)}
            {presentation.detail && <span className="muted" title={presentation.detail}>{presentation.detail}</span>}
            {services.scheduled?.(id) && <span className="sched-chip badge badge-off" title={services.scheduled(id)}>Scheduled</span>}{' '}
            <button type="button" className="linkish dinfo" title="Deployment details" onClick={() => services.details?.(id)}>ⓘ</button></td>
        </tr>;
      })}
      {!state.rows.length && <tr><td colSpan={12} className="muted">{state.error || (state.readOk ? state.total ? 'No devices match the current filters.' : 'No devices yet.' : 'Loading devices…')}</td></tr>}
    </tbody></table></div>
    <div className="menu" id="status-legend-pop" hidden={state.menu !== 'legend'}><div className="legend-title">Status legend</div>
      {(services.statusOptions || []).map(([key, label]) => <div className="legend-row" key={key}><Pill level={services.statusLevel?.(key)} label={label} /></div>)}
    </div>
  </div>;
  return <><div className="table-controls"><div className="filter-bar" id="dev-filters">
    <input id="dev-filter-q" placeholder="Search devices, IP addresses or models" aria-label="Filter by device, IP or model"
      value={state.filters.q} onChange={event => controller.setFilter('q', event.target.value)} />
    <details id="more-filters" open={state.filtersOpen} onToggle={event => {
      if (event.currentTarget.open !== controller.snapshot().filtersOpen) controller.update({filtersOpen: event.currentTarget.open});
    }} onKeyDown={event => { if (event.key === 'Escape') {
      // Native opening can precede its toggle event and the matching React state.
      event.currentTarget.open = false; controller.update({filtersOpen: false}); summary.current?.focus();
    } }}>
      <summary id="more-filters-summary" ref={summary}><svg className="ico" viewBox="0 0 16 16" aria-hidden="true"><path d="M2.5 4h11M4.5 8h7M6.5 12h3" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
        <span id="more-filters-label">Filters{chips.filter(chip => chip.key !== 'q').length ? ` (${chips.filter(chip => chip.key !== 'q').length})` : ''}</span></summary>
      <div className="more-filters-body">{filterSpecs.map(spec => <label className="device-filter-field" key={spec[0]}>
        <span>{spec[2]}</span><select id={'dev-filter-' + spec[1]} aria-label={'Filter by ' + spec[2]}
          value={state.filters[spec[0]]} onChange={event => controller.setFilter(spec[0], event.target.value)}>
          <option value="">{spec[3]}</option>{options(spec).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select></label>)}</div>
    </details>
    <button className="btn tertiary" type="button" id="dev-filter-clear" hidden={!chips.length} onClick={() => controller.resetFilters()}>Reset</button>
    <span className="filter-total" id="dev-count">{state.readOk ? `${state.rows.length === state.total ? state.total : state.rows.length + ' of ' + state.total} result${state.total === 1 ? '' : 's'}` : state.error ? 'Results unavailable' : ''}</span>
    <span className="muted" id="dev-target-warning" role="status">{state.warning}</span>
    <div id="dev-filter-chips" aria-label="Active device filters" hidden={!chips.length}>{chips.map(chip => <button key={chip.key} type="button" className="filter-chip"
      aria-label={'Remove filter: ' + chip.label} onClick={() => { controller.setFilter(chip.key, ''); summary.current?.focus(); }}>{chip.label} ×</button>)}</div>
    <span className="dev-pager" id="dev-pager" hidden={state.total <= PAGE_SIZE}>
      <button className="btn tertiary" type="button" id="dev-page-prev" disabled={state.loading || state.offset <= 0} onClick={() => controller.page(-1)}>Previous</button>
      <span className="muted" id="dev-page-pos">Page {Math.floor(state.offset / PAGE_SIZE) + 1} of {Math.max(1, Math.ceil(state.total / PAGE_SIZE))}</span>
      <button className="btn tertiary" type="button" id="dev-page-next" disabled={state.loading || state.offset + PAGE_SIZE >= state.total} onClick={() => controller.page(1)}>Next</button>
    </span>
  </div><div className="table-actions"><span className="muted" id="dev-selection-hint">Click a row to select or deselect it.</span>
    <button className="btn ghost" type="button" id="mark-all" disabled={!state.rows.length} onClick={() => controller.togglePage()}>{scope.pageLabel}</button>
    <button className="btn ghost" type="button" id="dev-activity" aria-controls="activity-panel" onClick={action(controller, 'dev-activity')}>{state.activityLabel}</button>
    <div className="menu-wrap"><button className="btn ghost dropdown" id="csv-menu-btn" type="button" aria-expanded={state.menu === 'csv'} aria-haspopup="true" onClick={() => menu('csv')}>CSV<Caret /></button>
      <div className="menu right" id="csv-menu" hidden={state.menu !== 'csv'}>{[['import-csv', 'Import CSV…'], ['export-csv', 'Export CSV'], ['example-csv', 'Download example']].map(([id, label]) => <button key={id} type="button" className="menu-item menu-close" id={id}
        disabled={state.actionBusy.has(id) || (id === 'import-csv' && (state.csvBusy || state.bulkBusy || state.rowBusy.size > 0))} onClick={action(controller, id)}>{label}</button>)}</div>
    </div>
    {[['manage-creds', 'Manage credentials'], ['manage-schedules', 'Schedules'], ['add-dev', 'Add device']].map(([id, label]) => <button key={id} className={id === 'add-dev' ? 'btn' : 'btn ghost'} type="button" id={id} onClick={action(controller, id)}>{label}</button>)}
  </div></div>
    {createPortal(<p className="policy-warning" id="inventory-role-capability-banner" role="status" aria-live="polite" hidden={!state.roleCapabilityMessage}>{state.roleCapabilityMessage}</p>, capabilityRoot)}
    {createPortal(<div className={'dev-status-line ' + (state.outcome.failed ? 'err' : 'muted')} id="dev-status" role="status" aria-live="polite">{state.outcome.message}</div>, statusRoot)}
    {createPortal(selection, selectionRoot)}{createPortal(table, tableRoot)}</>;
}

export function mountInventory() {
  const root = document.getElementById('iris-inventory-root'), selectionRoot = document.getElementById('iris-inventory-selection-root'), tableRoot = document.getElementById('iris-inventory-table-root');
  const capabilityRoot = document.getElementById('iris-inventory-capability-root'), statusRoot = document.getElementById('iris-inventory-status-root');
  if (!root || !selectionRoot || !tableRoot || !capabilityRoot || !statusRoot) throw new Error('Inventory mount points are missing');
  const controller = new InventoryController();
  // Synchronous getters keep existing dialogs bound to the same selected-ID
  // model during their migration; the adapter never writes into these roots.
  window.irisInventory = controller;
  window.addEventListener('pagehide', event => { if (!event.persisted) controller.dispose(); });
  createRoot(root).render(<Inventory controller={controller} selectionRoot={selectionRoot} tableRoot={tableRoot} capabilityRoot={capabilityRoot} statusRoot={statusRoot} />);
}
