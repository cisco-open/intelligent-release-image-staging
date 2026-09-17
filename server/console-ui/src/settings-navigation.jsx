// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';

const sections = [
  ['general', 'General', 'Server details, administrator access, and sessions.'],
  ['tls', 'TLS & trust', 'Manage the Console certificate and trusted certificate authorities.'],
  ['telemetry', 'Telemetry', 'Choose where IRIS sends progress and health reports.'],
  ['bulkhash', 'Image verification', 'Configure image authenticity checks and review their results.'],
  ['packages', 'Device packages', 'Review agent packages before onboarding devices.'],
  ['audit', 'Audit export', 'Configure exports of administrative activity.'],
  ['setup', 'Setup checklist', 'Check which server setup tasks still need attention.'],
];
const selectedSection = () => window.location.hash.split('/')[1] || 'general';

function SettingsNavigation() {
  const [selected, setSelected] = useState(selectedSection);
  useEffect(() => {
    const update = () => setSelected(selectedSection());
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);
  const active = sections.find(([id]) => id === selected) || sections[0];
  return <>
    <nav className="iris-settings-tabs" aria-label="Settings sections">
      {sections.map(([id, name]) => <a key={id} href={`#settings/${id}`}
        aria-current={id === active[0] ? 'page' : undefined}>{name}</a>)}
    </nav>
    <p className="iris-settings-description">{active[2]}</p>
  </>;
}

export function mountSettingsNavigation() {
  const root = document.getElementById('iris-settings-navigation-root');
  if (root) createRoot(root).render(<SettingsNavigation />);
}
