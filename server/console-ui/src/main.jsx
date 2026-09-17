// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

import { useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { flushSync } from 'react-dom';
import { mountSettingsNavigation } from './settings-navigation.jsx';
import { mountPolicies } from './policies.jsx';
import './shell.css';

const primary = [
  ['overview', 'Overview', 'gauge'], ['images', 'Images', 'stack'],
  ['devices', 'Inventory', 'hard-drives'], ['policies', 'Policies', 'list-checks'],
  ['swarm', 'Swarm', 'share-network'],
];
const groups = [
  ['monitoring', 'Monitoring', 'pulse', [['audit', 'Audit trail'], ['deploylogs', 'Deployment logs']]],
];
const mobile = () => window.matchMedia('(max-width: 800px)').matches;
const currentRoute = () => window.location.hash.slice(1).split('?')[0] || 'overview';
const emit = (name, detail) => window.dispatchEvent(new CustomEvent(name, { detail }));

function Icon({ name }) {
  return <svg className="iris-shell-icon" aria-hidden="true"><use href={`#i-nav-${name}`} /></svg>;
}

function closeNavigation(restoreFocus = false) {
  document.body.classList.remove('iris-nav-open');
  emit('iris:navigation-state');
  if (restoreFocus) document.getElementById('iris-menu-toggle')?.focus();
}

function toggleNavigation() {
  document.body.classList.toggle(mobile() ? 'iris-nav-open' : 'iris-nav-collapsed');
  emit('iris:navigation-state');
  if (mobile() && document.body.classList.contains('iris-nav-open')) {
    document.querySelector('.iris-navigation a')?.focus();
  }
}

function safeLink(value, fallback) {
  try {
    const url = new URL(value || fallback, window.location.origin);
    return ['https:', 'http:'].includes(url.protocol) ? url.href : fallback;
  } catch { return fallback; }
}

function Header() {
  const [state, setState] = useState({ username: '', connection: '', help: {} });
  const [open, setOpen] = useState(false);
  const [expanded, setExpanded] = useState(!mobile());
  const [copyStatus, setCopyStatus] = useState('');
  const menu = useRef(null);
  const trigger = useRef(null);
  const firstLink = useRef(null);
  useEffect(() => {
    const update = event => setState(previous => ({ ...previous, ...event.detail }));
    const navState = () => setExpanded(mobile()
      ? document.body.classList.contains('iris-nav-open')
      : !document.body.classList.contains('iris-nav-collapsed'));
    window.addEventListener('iris:shell-state', update);
    window.addEventListener('iris:navigation-state', navState);
    window.addEventListener('resize', navState);
    return () => {
      window.removeEventListener('iris:shell-state', update);
      window.removeEventListener('iris:navigation-state', navState);
      window.removeEventListener('resize', navState);
    };
  }, []);
  useEffect(() => {
    if (!open) return;
    firstLink.current?.focus();
    const click = event => { if (!menu.current?.contains(event.target)) setOpen(false); };
    const key = event => {
      if (event.key === 'Escape') { setOpen(false); trigger.current?.focus(); }
    };
    document.addEventListener('pointerdown', click);
    document.addEventListener('keydown', key);
    return () => {
      document.removeEventListener('pointerdown', click);
      document.removeEventListener('keydown', key);
    };
  }, [open]);
  const help = state.help || {};
  async function copyId() {
    try { await navigator.clipboard.writeText(help.deployment_id); setCopyStatus('Copied'); }
    catch { setCopyStatus('Copy unavailable. Select the deployment ID below.'); }
  }
  return <><header className="iris-header">
    <a className="iris-skip" href="#iris-main-content" onClick={event => {
      event.preventDefault();
      document.getElementById('iris-main-content')?.focus();
    }}>Skip to content</a>
    <button id="iris-menu-toggle" className="iris-header-button iris-menu-toggle" onClick={toggleNavigation}
      aria-label="Toggle navigation" aria-controls="iris-navigation" aria-expanded={expanded}><Icon name="list" /></button>
    <a href="#overview" className="iris-brand" aria-label="IRIS overview">IRIS</a>
    <span className="iris-product-title">Intelligent Release &amp; Image Staging</span>
    <span className="iris-stage-label">Stage only</span>
    <span className="iris-header-spacer" />
    <div className="iris-help-wrap" ref={menu} onBlur={event => {
      if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false);
    }}>
      <button className="iris-header-button" ref={trigger} aria-expanded={open} aria-controls="iris-help-panel"
        onClick={() => setOpen(!open)}>Help <span aria-hidden="true">⌄</span></button>
      {open && <section id="iris-help-panel" className="iris-help-panel" aria-label="Help and account">
        <div className="iris-help-heading">IRIS Console <span>{help.version || 'Version unavailable'}</span></div>
        <a ref={firstLink} href={safeLink(help.docs_url, 'https://cisco-open.github.io/intelligent-release-image-staging/')}
          target="_blank" rel="noopener noreferrer">Documentation ↗</a>
        <a href="/swagger/" target="_blank" rel="noopener noreferrer">API reference ↗</a>
        <a href={safeLink(help.guides?.device, '/help-device.html')} target="_blank" rel="noopener noreferrer">Device troubleshooting ↗</a>
        <a href={safeLink(help.guides?.server, '/help-server.html')} target="_blank" rel="noopener noreferrer">Server troubleshooting ↗</a>
        <div className="iris-deployment-id"><span>Deployment ID</span><code>{help.deployment_id || 'Unavailable'}</code>
          {help.deployment_id && <button onClick={copyId}>Copy ID</button>}<span role="status">{copyStatus}</span></div>
        {state.logoutError && <p className="iris-signout-error" role="alert">{state.logoutError}</p>}
        <button className="iris-signout" aria-disabled={!!state.logoutPending}
          onClick={() => { if (!state.logoutPending) emit('iris:logout'); }}>
          {state.logoutPending ? 'Signing out…' : 'Sign out'}</button>
      </section>}
    </div>
    <span className="iris-account" title={state.username || 'Not signed in'}>{state.username || 'Console'}</span>
  </header>
    {state.connection && <span className="iris-connection" role="status">{state.connection}</span>}
  </>;
}

function Navigation() {
  const [route, setRoute] = useState(currentRoute);
  const [expanded, setExpanded] = useState(() => ({ monitoring: currentRoute().startsWith('monitoring') }));
  const navRef = useRef(null);
  useEffect(() => {
    const change = () => {
      const next = currentRoute();
      setRoute(next);
      const group = next.split('/')[0];
      if (groups.some(([id]) => id === group)) setExpanded(previous => ({ ...previous, [group]: true }));
      closeNavigation();
    };
    const key = event => {
      if (!mobile() || !document.body.classList.contains('iris-nav-open')) return;
      if (event.key === 'Escape') { event.preventDefault(); closeNavigation(true); }
      if (event.key === 'Tab') {
        const focusable = [...navRef.current.querySelectorAll('a, button')].filter(node => node.getClientRects().length);
        const first = focusable[0], last = focusable.at(-1);
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
      }
    };
    window.addEventListener('hashchange', change);
    document.addEventListener('keydown', key);
    return () => { window.removeEventListener('hashchange', change); document.removeEventListener('keydown', key); };
  }, []);
  const link = (id, label, icon, active = route === id) => <a key={id} href={`#${id}`} title={label} aria-label={label}
    className={`iris-navigation-link${active ? ' is-active' : ''}`}
    aria-current={active ? 'page' : undefined} onClick={() => closeNavigation()}>
    {icon && <Icon name={icon} />}<span>{label}</span></a>;
  function toggleGroup(id) {
    if (document.body.classList.contains('iris-nav-collapsed')) {
      document.body.classList.remove('iris-nav-collapsed'); emit('iris:navigation-state');
      setExpanded(previous => ({ ...previous, [id]: true }));
    } else setExpanded(previous => ({ ...previous, [id]: !previous[id] }));
  }
  return <>
    <button className="iris-nav-scrim" onClick={() => closeNavigation(true)} aria-label="Close navigation" tabIndex={-1} />
    <nav id="iris-navigation" className="iris-navigation" aria-label="Primary" ref={navRef}>
      <div className="iris-nav-caption">Workspace</div>
      {primary.map(([id, label, icon]) => link(id, label, icon))}
      <div className="iris-nav-divider" />
      <div className="iris-nav-caption">System</div>
      {link('settings/general', 'Settings', 'gear', route.startsWith('settings'))}
      {groups.map(([id, label, icon, items]) => <div key={id} className="iris-navigation-group">
        <button className={`iris-navigation-link${route.startsWith(id) ? ' is-current-group' : ''}`}
          title={label} aria-label={label} aria-expanded={expanded[id]} aria-controls={`iris-group-${id}`} onClick={() => toggleGroup(id)}>
          <Icon name={icon} /><span>{label}</span><span className="iris-chevron" aria-hidden="true">{expanded[id] ? '⌄' : '›'}</span>
        </button>
        <div id={`iris-group-${id}`} className="iris-navigation-children" hidden={!expanded[id]}>
          {items.map(([child, name]) => link(`${id}/${child}`, name))}
        </div>
      </div>)}
    </nav>
  </>;
}

let mounted = false;
export function mountConsoleShell() {
  if (mounted) return;
  const header = document.getElementById('iris-header-root');
  const navigation = document.getElementById('iris-navigation-root');
  if (!header || !navigation) throw new Error('IRIS Console shell mount points are missing');
  mounted = true;
  document.body.classList.add('iris-react-shell');
  flushSync(() => {
    createRoot(header).render(<Header />);
    createRoot(navigation).render(<Navigation />);
    mountSettingsNavigation();
    mountPolicies();
  });
}

// Mount before the legacy application publishes its initial session/help state.
// Operational views retain their own DOM until they are migrated individually.
if (typeof document !== 'undefined') {
  mountConsoleShell();
  const script = document.createElement('script');
  script.src = '/app.js';
  script.addEventListener('error', () => emit('iris:shell-state', { connection: 'Console failed to load. Reload this page.' }));
  document.body.append(script);
}
