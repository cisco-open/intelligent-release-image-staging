// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

export const series = [['IE3x00', 'IE Switches'], ['IR1x00', 'IR Routers'], ['C8xxx', 'Catalyst Routers'],
  ['C9xxx', 'Catalyst Switches'], ['NCS', 'NCS'], ['XR8000', 'Cisco 8000 Series']];
export const managementTypes = [['routed', 'Routed - IRIS-managed app network'], ['inband', 'Inband - existing management VLAN'],
  ['router-routed', 'Router routed - IRIS-managed VPG subnet'], ['router-nat', 'Router NAT - VPG behind NAT'],
  ['xr-host', "XR host - router's own network stack"]];
export const installLabels = {guestshell: 'Guest Shell', iox: 'IOx', router: 'Guest Shell', 'xr-appmgr': 'XR appmgr container'};
export const emptyDevice = () => ({id: '', ip: '', management: '', model: '', platform: '', credential: '',
  vlan: '', svi: '', vpg: '', nat: '', guest: '', mask: '', gateway: ''});
export const emptyCredential = () => ({id: '', name: '', user: 'admin', password: '', confirm: '', enable: ''});
export function managementInstallOptions(management) {
  if (management === 'xr-host') return ['xr-appmgr'];
  if (['router-routed', 'router-nat'].includes(management)) return ['router', 'iox'];
  if (['routed', 'inband'].includes(management)) return ['guestshell', 'iox'];
  return [];
}
export function networkFields(management) {
  if (management === 'routed') return ['vlan', 'svi', 'guest', 'mask', 'gateway'];
  if (management === 'inband') return ['vlan', 'guest', 'mask', 'gateway'];
  if (management === 'router-routed') return ['vpg', 'guest', 'mask', 'gateway'];
  if (management === 'router-nat') return ['vpg', 'nat', 'guest', 'mask', 'gateway'];
  return [];
}
export function deviceBody(form) {
  const id = form.id.trim(), managementType = form.management;
  if (!id) throw new Error('Device ID is required.');
  if (!form.model) throw new Error('Choose a model series.');
  if (!managementTypes.some(([value]) => value === managementType)) throw new Error('Choose a management type for this device.');
  if (!managementInstallOptions(managementType).includes(form.platform)) throw new Error('Choose an agent install for this device.');
  const body = {device_id: id, device_ip: form.ip.trim() || id, management_type: managementType,
    model: form.model.trim(), platform: form.platform, credential_profile_id: form.credential};
  if (managementType === 'xr-host') return body;
  Object.assign(body, {app_ip: form.guest.trim(), app_mask: form.mask.trim(), app_gateway: form.gateway.trim()});
  if (managementType === 'inband') body.inband_vlan = form.vlan.trim();
  else if (managementType.startsWith('router-')) {
    body.vpg_number = form.vpg.trim();
    if (managementType === 'router-nat') body.nat_interface = form.nat.trim();
  } else Object.assign(body, {iris_vlan: form.vlan.trim(), svi_ip: form.svi.trim(), svi_mask: form.mask.trim()});
  return body;
}
export function credentialBody(form) {
  const id = form.id.trim();
  if (!id) throw new Error('Profile id is required.');
  if (!form.user.trim()) throw new Error('Device username is required.');
  if (!form.password.trim()) throw new Error('Password is required.');
  if (form.password !== form.confirm) throw new Error('Passwords do not match.');
  return {id, name: form.name.trim() || id, device_user: form.user.trim(), device_pass: form.password, enable_secret: form.enable};
}
// Pick only the public projection. Never retain accidental secret fields from a
// malformed server response, or put a returned object directly into form state.
export function credentialProfiles(result) {
  const rows = result?.profiles;
  if (!Array.isArray(rows) || rows.some(row => !row || typeof row.id !== 'string' || !row.id
    || ['name', 'device_user'].some(key => row[key] != null && typeof row[key] !== 'string'))
    || new Set(rows.map(row => row.id)).size !== rows.length) throw new Error('Invalid credential list');
  return rows.map(({id, name, device_user}) => ({id, name: name || '', device_user: device_user || ''}));
}
