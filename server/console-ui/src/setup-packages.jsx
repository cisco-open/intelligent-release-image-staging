// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useLayoutEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {createPortal} from 'react-dom';
import {SetupPackagesController} from './setup-packages-controller.mjs';
import {setupChip, setupSteps, packageRemedy, telemetryNote} from './setup-packages-model.mjs';

function Chip({item = '', state = 'unknown', configured = null}) {
  const {label, level} = setupChip(item, state, configured);
  const icon = {positive: 'i-check-circle', warning: 'i-triangle-warn', inactive: 'i-minus-circle', info: 'i-square-info'}[level];
  return <span className={'status-pill is-' + level}><svg aria-hidden="true"><use href={'#' + icon} /></svg>{label}</span>;
}
function PackageTable({pkg, prefix}) {
  return <><div className="table-scroll" tabIndex={0} role="region" aria-label="Package readiness evidence"><table className="tbl" id={prefix + '-table'}>
    <thead><tr>{['Package', 'State', 'Artifact updated', 'Evidence'].map(title => <th key={title} scope="col">{title}</th>)}</tr></thead>
    <tbody>{(pkg?.items || []).map(row => <tr key={row.name}><td className="machine">{row.name}</td><td><Chip state={row.state} /></td><td>{row.built_at === null ? '—' : new Date(row.built_at * 1000).toLocaleString()}</td><td>{row.detail || row.reason}</td></tr>)}</tbody>
  </table></div><p className="machine" id={prefix + '-remedy'}>{packageRemedy(pkg)}</p></>;
}
function PackageDescription() {
  return <><p className="muted">IOx and IOS-XR packages are deployment-neutral. The current server certificate is delivered separately during onboarding.</p>
    <p className="muted">Wrapper readiness checks bytes against the adjacent build-provenance manifest. It does not authenticate that manifest or verify native package signatures. Guest Shell readiness checks the latest startup provisioning evidence. “Artifact updated” is the file modification time.</p></>;
}
function SetupPackages({controller: c, roots}) {
  const s = useSyncExternalStore(c.subscribe, c.snapshot), status = s.status, heading = useRef(null), previousStep = useRef(null), previousMode = useRef(null);
  useLayoutEffect(() => {
    if (s.mode !== 'wizard') {previousMode.current = s.mode; return;}
    const changed = previousStep.current !== s.step || previousMode.current !== 'wizard';
    previousStep.current = s.step; previousMode.current = 'wizard';
    if (changed) {
      c.services.wizardSelect?.(setupSteps[s.step].id);
      if (document.activeElement?.closest('#wz-nav, #wz-steplist')) heading.current?.focus();
    }
  }, [s.mode, s.step, c]);
  const chip = (key, id) => <span id={id}><Chip item={key} state={status?.[key]?.state} configured={s.configured} /></span>;
  const message = id => <p className="muted" id={id} role="status" aria-live="polite">{s.message}</p>;
  const recheck = (id, label) => <button className="btn ghost" id={id} disabled={s.loading} onClick={() => c.refresh()}>{label}</button>;
  const checklist = <div data-setup-packages><p className="muted">Check this server's account, device packages and optional integrations.</p>{message('setup-msg')}<div className="setup-cards">
    <div className="card"><h3>Admin account {chip('admin', 'setup-admin-chip')}</h3><p className="muted">Created during first-run sign-in.</p><p><a href="#settings/general" className="btn ghost">Change password</a></p></div>
    <div className="card"><h3>Telemetry destination {chip('telemetry', 'setup-td-chip')}</h3><p className="muted">Optional export of swarm progress, device reports and export health.</p><p className="muted" id="setup-td-note">{telemetryNote(status?.telemetry)}</p><p><a href="#setup" className="btn ghost">Configure in setup</a></p></div>
    <div className="card"><h3>Device packages {chip('packages', 'setup-pkg-chip')}</h3><PackageDescription /><PackageTable pkg={status?.packages} prefix="setup-pkg" /><p><a href="#settings/packages" className="btn ghost">Review device packages</a></p></div>
    <div className="card"><h3>Image verification {chip('image_verification', 'setup-iv-chip')}</h3><p className="muted">Compare imported image hashes with Cisco's Bulk Hash feed. A configured schedule and a successful check are shown separately.</p><p><a href="#setup" className="btn ghost">Configure in setup</a></p></div>
  </div><p>{recheck('setup-recheck', 'Re-check setup')}</p></div>;
  const packages = <div className="card" data-setup-packages><h3>Device packages {chip('packages', 'device-packages-chip')}</h3><PackageDescription />
    <p className="muted">Build or repair packages on the build host, then re-check them here. Build packages only for the platforms you use.</p><PackageTable pkg={status?.packages} prefix="device-packages" />
    <p>{recheck('device-packages-recheck', 'Re-check packages')}</p>{message('device-packages-msg')}</div>;
  const wizard = <div data-setup-packages><p className="muted" id="wz-progress" role="status" aria-live="polite">Step {s.step + 1} of {setupSteps.length}</p>
    <div className="wz-layout"><div className="wz-panel"><div id="wz-steplist" role="list" aria-label="Setup steps">{setupSteps.map((row, index) => {
      const current = index === s.step, done = !current && status?.[row.key]?.state === 'ok';
      return <div role="listitem" key={row.id}><button type="button" className={'wz-steplist-item' + (current ? ' current' : '')} data-step={index} aria-current={current ? 'step' : undefined} aria-controls={'wz-step-' + row.id} onClick={() => c.chooseStep(index)}>
        <span className={'wz-steplist-n ' + (current ? 'is-current' : done ? 'is-done' : 'is-upcoming')}>{done ? <svg aria-hidden="true"><use href="#i-check" /></svg> : index + 1}</span><span className="wz-steplist-label">{row.label}</span><Chip item={row.key} state={status?.[row.key]?.state} configured={s.configured} /></button></div>;
    })}</div></div><div className="wz-content">
      <div className="wz-done" id="wz-admin"><h3>Admin account {chip('admin', 'wz-admin-chip')}</h3><p className="muted">Created during first-run sign-in. Change the password from Settings › General.</p></div>
      <div className="wz-step" id="wz-step-telemetry" hidden={s.step !== 0}><h3 tabIndex={-1} ref={s.step === 0 ? heading : null}>1. Telemetry destination {chip('telemetry', 'wz-td-chip')}</h3><p className="muted">Choose where to export swarm progress, device reports and export health. This integration is optional.</p><div className="form-mount" id="wz-td-mount" /></div>
      <div className="wz-step" id="wz-step-packages" hidden={s.step !== 1}><h3 tabIndex={-1} ref={s.step === 1 ? heading : null}>2. Device packages {chip('packages', 'wz-pkg-chip')}</h3><PackageDescription /><p className="muted">Build or repair packages on the build host, then re-check. You can skip platforms you do not use.</p><PackageTable pkg={status?.packages} prefix="wz-pkg" /><p>{recheck('wz-pkg-recheck', 'Re-check')}</p></div>
      <div className="wz-step" id="wz-step-imageverification" hidden={s.step !== 2}><h3 tabIndex={-1} ref={s.step === 2 ? heading : null}>3. Image verification {chip('image_verification', 'wz-iv-chip')}</h3><p className="muted">Compare imported image hashes with Cisco's Bulk Hash feed.</p><div className="form-mount" id="wz-iv-mount" /></div>
      <div className="toolbar" id="wz-nav"><button className="btn ghost" id="wz-back" disabled={s.step === 0 || s.navigating} onClick={() => c.chooseStep(s.step - 1)}>‹ Back</button><button className="btn ghost" id="wz-skip" disabled={s.navigating} onClick={() => c.skip()}>Skip for now</button><button className="btn" id="wz-next" disabled={s.navigating} onClick={() => c.next()}>{s.step === setupSteps.length - 1 ? 'Done' : 'Next ›'}</button></div>{message('wz-msg')}
    </div></div></div>;
  const nudge = <div id="setup-nudge" className="nudge" hidden={s.dismissed || !s.attention}><span id="setup-nudge-text">Device packages needed attention at the last check.</span><a className="btn ghost" href="#settings/packages" id="setup-nudge-open">Review packages</a><button className="linkish" id="setup-nudge-dismiss" onClick={() => c.dismiss()}>Dismiss</button></div>;
  return <>{createPortal(checklist, roots.checklist)}{createPortal(packages, roots.packages)}{createPortal(wizard, roots.wizard)}{createPortal(nudge, roots.nudge)}</>;
}
export function mountSetupPackages() {
  const c = new SetupPackagesController(); window.irisSetupPackages = c;
  const root = document.getElementById('iris-setup-packages-root'), roots = {checklist: document.getElementById('iris-setup-checklist'), packages: document.getElementById('iris-device-packages'), wizard: document.getElementById('iris-setup-wizard'), nudge: document.getElementById('iris-setup-nudge')};
  if (!root || Object.values(roots).some(node => !node)) throw Error('Setup and package mount points missing');
  createRoot(root).render(<SetupPackages controller={c} roots={roots} />);
}
