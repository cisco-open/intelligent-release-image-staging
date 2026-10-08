// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import {useEffect, useRef, useSyncExternalStore} from 'react';
import {createRoot} from 'react-dom/client';
import {DeviceFormsController} from './device-forms-controller.mjs';
import {series, managementTypes, installLabels, networkFields} from './device-forms-model.mjs';

function Field({id, label, children, hidden = false}) {
  return <label className="field" htmlFor={id} hidden={hidden}><span className="field-label">{label}</span>{children}</label>;
}
function DeviceForms({controller}) {
  const state = useSyncExternalStore(controller.subscribe, controller.snapshot), form = state.device, cred = state.credential;
  const idInput = useRef(null), profileInput = useRef(null), passwordInput = useRef(null);
  const wasDeviceOpen = useRef(false);
  useEffect(() => {
    if (state.deviceOpen) idInput.current?.focus();
    // Disabling the submitted button can move focus to body before the form
    // closes. Restore that focus too, but leave another active control alone.
    else if (wasDeviceOpen.current && controller.visible()
      && (document.activeElement === document.body || document.getElementById('dev-form')?.contains(document.activeElement))) document.getElementById('add-dev')?.focus();
    wasDeviceOpen.current = state.deviceOpen;
  }, [controller, state.deviceOpen]);
  useEffect(() => { if (state.credentialsOpen) profileInput.current?.focus(); }, [state.credentialsOpen]);
  const closeDevice = () => { controller.closeDevice(); document.getElementById('add-dev')?.focus(); };
  const closeCredentials = () => { controller.closeCredentials(); document.getElementById('manage-creds')?.focus(); };
  const network = networkFields(form.management);
  const input = (key, id, label, placeholder, visible = true) => <Field key={key} id={id} label={label} hidden={!visible}>
    <input id={id} value={form[key]} placeholder={placeholder} disabled={state.deviceBusy} onChange={event => controller.setDevice(key, event.target.value)} />
  </Field>;
  const profileInputField = (key, id, label, placeholder, type = 'text', ref) => <Field id={id} label={label}>
    <input ref={ref} id={id} type={type} value={cred[key]} placeholder={placeholder} autoComplete={type === 'password' ? 'new-password' : undefined}
      readOnly={key === 'id' && state.editing} disabled={state.credentialBusy} onChange={event => controller.setCredential(key, event.target.value)} />
  </Field>;
  return <>
    <form className="inline-form" id="dev-form" hidden={!state.deviceOpen} aria-label="Add device"
      onKeyDown={event => { if (event.key === 'Escape') { event.stopPropagation(); closeDevice(); } }}
      onSubmit={event => { event.preventDefault(); controller.saveDevice(); }}>
      <Field id="df-id" label="Device ID / IP"><input ref={idInput} id="df-id" placeholder="e.g. 10.0.0.5" value={form.id}
        disabled={state.deviceBusy} onChange={event => controller.setDevice('id', event.target.value)} /></Field>
      {input('ip', 'df-ip', 'Management IP', 'e.g. 10.0.0.5')}
      <Field id="df-management-type" label="Management type"><select id="df-management-type" value={form.management} disabled={state.deviceBusy}
        onChange={event => controller.setDevice('management', event.target.value)}><option value="">Choose…</option>
        {managementTypes.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></Field>
      {[
        ['vlan', 'df-vlan', 'VLAN', 'e.g. 100'], ['svi', 'df-svi', 'SVI IP (routed only)', 'e.g. 10.0.1.1'],
        ['vpg', 'df-vpg', 'VirtualPortGroup number (0-31)', 'e.g. 0'], ['nat', 'df-nat-interface', 'NAT outside interface', 'e.g. GigabitEthernet0/0'],
        ['guest', 'df-guest', 'App IP', 'e.g. 10.0.2.5'], ['mask', 'df-mask', 'App mask', 'e.g. 255.255.255.0'],
        ['gateway', 'df-gateway', 'App gateway (VPG IP for routers)', 'e.g. 10.0.2.1'],
      ].map(([key, ...args]) => input(key, ...args, network.includes(key)))}
      <Field id="df-model" label="Model series"><select id="df-model" required value={form.model} disabled={state.deviceBusy}
        onChange={event => controller.setDevice('model', event.target.value)}><option value="">Choose a series…</option>
        {series.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></Field>
      <Field id="df-platform" label="Agent install"><select id="df-platform" aria-describedby="df-platform-hint" value={form.platform}
        disabled={state.deviceBusy || !state.options.length} onChange={event => controller.setDevice('platform', event.target.value)}>
        <option value="" disabled>{!form.management ? 'Choose a management type first' : !state.options.length ? 'No compatible agent install' : 'Choose an agent install'}</option>
        {state.options.map(value => <option key={value} value={value}>{installLabels[value]}</option>)}</select></Field>
      <Field id="df-cred" label="Credential"><select id="df-cred" value={form.credential} disabled={state.deviceBusy}
        onChange={event => controller.setDevice('credential', event.target.value)}>
        <option value="">{state.credentialsOk ? '— no credential —' : '— credential list unavailable; assign later —'}</option>
        {state.profiles.map(row => <option key={row.id} value={row.id} disabled={!state.credentialsOk}>{row.id}</option>)}
        {form.credential && !state.profiles.some(row => row.id === form.credential) && <option value={form.credential} disabled>{form.credential} (unavailable)</option>}
      </select></Field>
      <div className="form-actions"><button className="btn" type="submit" disabled={state.deviceBusy}>Save device</button>
        <button className="btn ghost" type="button" id="df-cancel" onClick={closeDevice}>Cancel</button></div>
      <p className="muted form-help" id="df-platform-hint">{state.optionsLoading ? 'Checking model compatibility…' : state.optionHint}</p>
      <span className={state.deviceFailed ? 'err' : 'form-help muted'} id="df-err" role="alert">{state.deviceMessage}</span>
    </form>
    <section className="inline-form" id="cred-panel" aria-label="Credential profiles" hidden={!state.credentialsOpen}
      onKeyDown={event => { if (event.key === 'Escape') { event.stopPropagation(); closeCredentials(); } }}>
      <div className="table-scroll" role="region" aria-label="Credential profile list" tabIndex={0}>
        <table className="tbl"><thead><tr><th>Profile id</th><th>Name</th><th>Device username</th><th>Actions</th></tr></thead>
          <tbody id="cred-rows">{state.profiles.map(profile => <tr key={profile.id} data-id={profile.id}>
            <td className="machine"><b>{profile.id}</b></td><td>{profile.name}</td><td>{profile.device_user}</td><td>
              <button type="button" className="linkish cred-edit" disabled={state.credentialBusy || !state.credentialsOk} aria-label={`Edit ${profile.id}`}
                onClick={() => { controller.editCredential(profile.id); passwordInput.current?.focus(); }}>Edit</button>{' · '}
              <button type="button" className="linkish cred-del" disabled={state.credentialBusy || !state.credentialsOk} aria-label={`Delete ${profile.id}`}
                onClick={() => controller.deleteCredential(profile.id)}>Delete</button></td></tr>)}
            {!state.profiles.length && <tr><td colSpan={4} className="muted">{state.credentialsLoading ? 'Loading profiles…' : state.credentialsOk ? 'No credential profiles yet.' : 'Credential profiles unavailable.'}</td></tr>}
          </tbody></table></div>
      {!state.credentialsOk && state.profiles.length > 0 && <p className="err" role="status">Credential profiles unavailable. Showing the last successful read.</p>}
      <button className="btn ghost" type="button" id="cf-refresh" disabled={state.credentialBusy || state.credentialsLoading} onClick={() => controller.refreshCredentials()}>Refresh profiles</button>
      <form id="cred-form" aria-label="Credential profile" onSubmit={event => { event.preventDefault(); controller.saveCredential(); }}>
        {profileInputField('id', 'cf-id', 'Profile id', 'e.g. lab-switches', 'text', profileInput)}
        {profileInputField('name', 'cf-name', 'Display name', 'e.g. Lab switches')}
        {profileInputField('user', 'cf-user', 'Device username', 'admin')}
        {profileInputField('password', 'cf-pass', 'Device password', 'Device password', 'password', passwordInput)}
        {profileInputField('confirm', 'cf-pass2', 'Confirm password', 'Confirm password', 'password')}
        {profileInputField('enable', 'cf-en', 'Enable secret', 'Blank = same as password', 'password')}
        <div className="form-actions"><button className="btn" type="submit" disabled={state.credentialBusy}>Save profile</button>
          <button className="btn ghost" type="button" id="cf-reset" disabled={state.credentialBusy} onClick={() => { controller.newCredential(); profileInput.current?.focus(); }}>New</button>
          <button className="btn ghost" type="button" id="cf-close" onClick={closeCredentials}>Close</button></div>
        <span className={state.credentialFailed ? 'err' : state.credentialBusy || state.editing ? 'form-help muted' : 'err ok'} id="cf-err" role="alert">{state.credentialMessage}</span>
      </form>
    </section>
  </>;
}
export function mountDeviceForms() {
  const root = document.getElementById('iris-device-forms-root');
  if (!root) throw new Error('Device forms mount point is missing');
  const controller = new DeviceFormsController(); window.irisDeviceForms = controller;
  createRoot(root).render(<DeviceForms controller={controller} />);
}
