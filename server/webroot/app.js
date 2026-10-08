// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

(async function () {
  try {
  var res = await fetch('/api/v1/session');
  if (res.status === 401) { window.location.href = '/login.html'; return; }
  if (!res.ok) throw new Error('Session check failed (' + res.status + ')');
  var info = await res.json();
  if (!info || typeof info !== 'object' || !info.csrf) throw new Error('Session check returned invalid data');
  window.dispatchEvent(new CustomEvent('iris:shell-state', { detail: { username: info.username } }));
  var logoutPending = false;
  window.addEventListener('iris:logout', async function () {
    if (logoutPending) return;
    logoutPending = true;
    window.dispatchEvent(new CustomEvent('iris:shell-state', { detail: { logoutPending: true, logoutError: '' } }));
    try {
      var response = await fetch('/api/v1/logout', { method: 'POST', headers: { 'X-CSRF-Token': info.csrf } });
      if (!response.ok && response.status !== 401) throw new Error('HTTP ' + response.status);
      window.location.href = '/login.html';
    } catch (e) {
      // A failed request does not revoke the session. Keep a visible retry
      // instead of presenting the login page as proof that sign-out succeeded.
      logoutPending = false;
      window.dispatchEvent(new CustomEvent('iris:shell-state', { detail: {
        logoutPending: false, logoutError: 'Sign out failed. Your session may still be active. Try again.'
      } }));
    }
  });

  // ---- one fetch for the whole console ------------------------------------
  // Shadows window.fetch inside this closure so EVERY request made by this
  // file goes through it (function declarations hoist, so the session check
  // above used it too). Three concerns no individual refresher used to
  // handle:
  //  1. Session loss after the initial check (container restart, "Sign out
  //     other sessions" from another tab, idle expiry): a 401 anywhere stops
  //     the view poll and sends the operator to the login page, instead of
  //     every poll returning silently and a frozen fleet view passing for
  //     live for the rest of the day.
  //  2. A poll that fails (server down, 5xx, network) is announced in the
  //     header as "live data unavailable since <time>" while the last known
  //     state stays on screen; the note clears on the next successful GET.
  //  3. Background polls are marked with "X-IRIS-Poll: 1" (GET only). The
  //     server validates the session for them WITHOUT refreshing its idle
  //     clock, so an unattended console on a polled view reaches the idle
  //     timeout Settings advertises. "Background" = no operator input since
  //     the poll tick began: pointer/keyboard input clears the mark, so a
  //     refresh the operator actually caused still counts as activity.
  // window.fetch is called directly (never cached in a var): the session
  // check above runs before any var here is assigned, and hoisting means
  // it already goes through this wrapper.
  var sessionLost = false;
  var backgroundPoll = false;
  var staleSince = null;
  ['pointerdown', 'keydown'].forEach(function (ev) {
    document.addEventListener(ev, function () { backgroundPoll = false; }, true);
  });
  function markConnection(ok) {
    // == null on purpose: the session check above runs before this
    // closure's vars are assigned, so staleSince can still be undefined.
    if (ok) {
      if (staleSince != null) {
        staleSince = null;
        window.dispatchEvent(new CustomEvent('iris:shell-state', { detail: { connection: '' } }));
      }
      return;
    }
    if (staleSince == null) staleSince = new Date();
    var connection = 'Live data unavailable since ' + staleSince.toLocaleTimeString() +
      ' — showing the last known state, retrying.';
    window.dispatchEvent(new CustomEvent('iris:shell-state', { detail: { connection: connection } }));
  }
  function onSessionLost() {
    if (sessionLost) return;
    sessionLost = true;
    try { stopViewPoll(); } catch (e) { /* not wired yet */ }
    window.location.href = '/login.html';
  }
  function fetch(url, opts) {
    opts = opts || {};
    var isGet = !opts.method || String(opts.method).toUpperCase() === 'GET';
    if (isGet && backgroundPoll) {
      var h = new Headers(opts.headers || {});
      h.set('X-IRIS-Poll', '1');
      opts = Object.assign({}, opts, { headers: h });
    }
    return window.fetch(url, opts).then(function (r) {
      if (r.status === 401) onSessionLost();
      else if (isGet && r.status >= 500) markConnection(false);
      else if (isGet && r.ok) markConnection(true);
      return r;
    }, function (err) {
      if (isGet && !(err && err.name === 'AbortError')) markConnection(false);
      throw err;
    });
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function dash(v) { return v ? esc(v) : '—'; }
  // React owns table state, filters and selected IDs. The remaining dialogs
  // read through this adapter rather than inspecting or rewriting its DOM.
  var inventory = window.irisInventory;
  var deviceForms = window.irisDeviceForms;
  var assignments = window.irisAssignments;
  var inventoryActions = window.irisInventoryActions;
  var schedules = window.irisSchedules;
  var roleActions = window.irisRoleActions;
  var policies = window.irisPolicies;
  var LAST_DEVICES = [], LAST_DEV_NOW = 0, devTotal = 0;
  var LAST_JOBS_BY_DEVICE = Object.create(null);
  function deviceFilterState() {
    var filters = inventory.snapshot().filters;
    return Object.assign({}, filters, {q: filters.q.trim().toLowerCase()});
  }
  function onInventoryAction(id, handler) { inventory.onAction(id, handler); }


  // ONE derivation of the Status cell, read by the row renderer AND by the
  // filter. It used to be written twice, and the filter's copy knew only three
  // of the eleven states the cell can actually show: a device reading
  // "onboarding…", "placement failed" or "copying to bootflash:" could not be
  // picked from the Status filter at all, and asking for "enrolled" silently
  // swept them in. Returning the label and the class from the same place is
  // what makes the two structurally unable to disagree.
  //
  // Order matters and mirrors the cell exactly: job-aware states come FIRST,
  // because right after an onboard the agent needs minutes to bootstrap before
  // its first heartbeat, and without them the row reads "not enrolled" and
  // looks like the onboard did nothing.
  // Labels here are sentence case (Magnetic pill grammar, Task 4) -- they
  // double as statusDisplay()'s default text below, so the dropdown and the
  // rendered pill share one copy of every static label and cannot drift
  // apart. 'deployed' is the one WIRE key that keeps its old spelling while
  // its DISPLAY text becomes "Staged" (spec: derivation in app.js unchanged).
  var DEVICE_STATUS_OPTIONS = [
    ['onboarding', 'Onboarding'],
    ['undeploying', 'Undeploying'],
    ['waiting-heartbeat', 'Waiting for heartbeat'],
    ['waiting-staging', 'Waiting for staging'],
    ['onboard-failed', 'Onboard failed'],
    ['undeploy-failed', 'Undeploy failed'],
    ['deployed', 'Staged'],
    ['placement-failed', 'Staging failed'],
    ['image-failed', 'Image(s) failed'],
    ['copying', 'Copying to IOS storage'],
    ['staging', 'Staging (other)'],
    ['unassigned', 'Unassigned'],
    ['enrolled', 'Enrolled'],
    ['not-enrolled', 'Not enrolled'],
    ['offline', 'Offline (no recent heartbeat)']
  ];
  // The device's approved image ids, ordered. assigned_image_ids is absent
  // for a policy row that predates the ordered set (or simply unassigned),
  // so fall back to the singular field it still carries -- mirrors the
  // server's _row_assigned_ids exactly, so the two can never disagree about
  // what "assigned" means.
  function rowAssignedIds(d) {
    var ids = d.assigned_image_ids;
    if (ids && ids.length) return ids;
    return d.assigned_image_id ? [d.assigned_image_id] : [];
  }
  // `router` is an install recipe/wire value, not an agent runtime. C8000V
  // selected through that recipe runs the same Guest Shell agent as the
  // `guestshell` value; VPG/routed/NAT belongs to Management type instead.
  var AGENT_INSTALL_LABELS = {
    guestshell: 'Guest Shell', iox: 'IOx', router: 'Guest Shell',
    'xr-appmgr': 'XR appmgr container'
  };
  function agentInstallLabel(platform) {
    return AGENT_INSTALL_LABELS[platform] || platform || '—';
  }
  // Why a row cannot take an agent install: the same rules gui_fleet
  // enforces, said in the operator's terms rather than as a 400 after the fact.
  function installRefusal(d, platform) {
    var mt = d.management_type || '';
    if (mt === 'router-routed' || mt === 'router-nat') return 'Router management types run Guest Shell on the router (platform router) or an IOx app, both through the IRIS VirtualPortGroup.';
    if (mt === 'xr-host') return 'XR host runs the XR appmgr container only.';
    if (platform === 'router') return 'Platform router needs management type router-routed or router-nat.';
    if (platform === 'xr-appmgr') return 'The XR appmgr container needs management type xr-host.';
    return 'Model ' + (d.model || d.heartbeat_model || '') + ' cannot run ' + agentInstallLabel(platform) + '.';
  }
  // Whether *d*'s device has staged image *iid*: membership in the
  // heartbeat's staged_image_ids when the agent reports it directly (Task
  // 3), else the legacy current_image_id/stage_state=='ready' pair for an
  // agent that predates the field. Mirrors the server's _row_has_staged.
  function rowHasStaged(d, iid) {
    if ((d.errored_image_ids || []).indexOf(iid) !== -1) return false;
    var sids = d.staged_image_ids;
    if (sids != null) return sids.indexOf(iid) !== -1;
    return d.stage_state === 'ready' && d.current_image_id === iid;
  }
  // The images this device's last tick called a terminal per-image failure.
  // Empty for an agent that predates the field (and for a healthy set), so a
  // one-image agent's row is decided exactly as it always was.
  function rowErroredIds(d) {
    return d.errored_image_ids || [];
  }
  function deviceStatus(d, devNow) {
    // "no heartbeat since the job finished" — the job outcome is the freshest
    // truth we have about this device
    var jobFresh = d.onboard_finished_at &&
      (!d.last_seen || d.last_seen < d.onboard_finished_at);
    if (d.onboard_state === 'queued' || d.onboard_state === 'running') {
      return d.onboard_action === 'undeploy'
        ? { key: 'undeploying', label: 'undeploying…', cls: 'badge badge-running' }
        : { key: 'onboarding', label: 'onboarding…', cls: 'badge badge-running' };
    }
    if (d.onboard_state === 'done' && d.onboard_action === 'onboard' && jobFresh) {
      return { key: 'waiting-heartbeat', label: 'waiting for heartbeat',
               cls: 'badge badge-queued' };
    }
    if (d.onboard_state === 'error' && jobFresh) {
      return d.onboard_action === 'undeploy'
        ? { key: 'undeploy-failed', label: 'undeploy failed', cls: 'badge badge-fail' }
        : { key: 'onboard-failed', label: 'onboard failed', cls: 'badge badge-fail' };
    }
    // "deployed" = every image in the assigned SET is staged and verified on
    // the box -- not just one of them. rowHasStaged() folds in the legacy
    // fallback for an agent that predates staged_image_ids, so a one-image
    // set on an old agent is exactly today's single-field check.
    var assignedIds = rowAssignedIds(d);
    // Images of the set the agent's own last tick gave up on. They are not
    // staged, so the set is not deployed -- this cell used to answer
    // "deployed" before it looked at any error, and read all-green beside a
    // drawer and a swarm map both showing the same image as failed.
    var erroredIds = rowErroredIds(d).filter(function (iid) {
      return assignedIds.indexOf(iid) !== -1;
    });
    if (assignedIds.length && !erroredIds.length &&
        assignedIds.every(function (iid) { return rowHasStaged(d, iid); })) {
      return { key: 'deployed', label: 'deployed', cls: 'badge badge-ok' };
    }
    // Named per-image failures beat the collapsed single stage_state below:
    // that one string is whatever the tick found most actionable, so falling
    // through to it would report a set with three dead images as whatever the
    // fourth is doing. The drawer says WHICH images these are.
    if (erroredIds.length) {
      return { key: 'image-failed',
               label: erroredIds.length + ' of ' + assignedIds.length +
                      ' image(s) failed',
               cls: 'badge badge-fail', detail: d.stage_error };
    }
    if (d.stage_error || d.stage_state === 'error' || d.stage_state === 'copy_failed') {
      return { key: 'placement-failed', label: 'staging failed',
               cls: 'badge badge-fail', detail: d.stage_error || d.stage_state };
    }
    if (d.stage_state === 'transferring_to_ios') {
      return { key: 'copying', label: 'copying to ' + (d.target_fs || 'IOS storage'),
               cls: 'badge badge-running' };
    }
    // Policy changes are visible before the next agent tick. An idle/ready
    // heartbeat for the previous assignment is no evidence that the new one
    // has started, and a cleared assignment must not turn "ready" into work.
    if (d.stage_state === 'unassigned' || d.stage_state === 'ready') {
      return assignedIds.length
        ? { key: 'waiting-staging', label: 'waiting for staging', cls: 'badge badge-queued' }
        : { key: 'unassigned', label: 'unassigned', cls: 'muted' };
    }
    if (d.stage_state) {
      return { key: 'staging', label: d.stage_state, cls: 'badge badge-running' };
    }
    // Enrolled with an empty assigned set. This read "enrolled" before, which
    // is true but hides the one thing an operator can act on -- and nothing
    // else in the row distinguishes them, so there was no way to ask the table
    // "which devices have I not assigned an image to yet". Ordered AFTER every
    // staging/error branch (a device mid-stage is not unassigned) and BEFORE
    // 'enrolled', but never ahead of 'not-enrolled': an agent that has never
    // checked in is not yet an assignment problem.
    if (d.last_seen && !assignedIds.length) {
      return { key: 'unassigned', label: 'unassigned', cls: 'muted' };
    }
    if (d.last_seen) {
      return { key: 'enrolled', label: 'enrolled', cls: 'badge badge-queued' };
    }
    return { key: 'not-enrolled', label: 'not enrolled', cls: 'muted' };
  }

  // ---- Status pill grammar (12-level Magnetic mapping, Task 4) ----------
  // One level (and one icon) per status, built next to deviceStatus() so a
  // key can never be renderable under a level this map doesn't cover --
  // same "one derivation feeds both" reasoning as DEVICE_STATUS_OPTIONS
  // above. Positive is BLUE-family per Magnetic, not green: green stays
  // reserved for Allow/policy grammar elsewhere in the console.
  var STATUS_OPTION_LABELS = {};
  DEVICE_STATUS_OPTIONS.forEach(function (o) { STATUS_OPTION_LABELS[o[0]] = o[1]; });
  // copying/staging/image-failed carry PER-DEVICE text deviceStatus() itself
  // already built (target filesystem, the raw stage_state, an N-of-M count)
  // -- the option label above is only their generic dropdown stand-in, never
  // what a row's own pill should show.
  var STATUS_DYNAMIC_KEYS = { copying: 1, staging: 1, 'image-failed': 1 };
  // offline's dropdown text is a full explanation ("no recent heartbeat"),
  // too long beside the status it modifies -- the pill gets the short form.
  var STATUS_PILL_LABEL_OVERRIDES = { offline: 'Offline' };
  var STATUS_LEVELS = {
    onboarding: 'progress', undeploying: 'progress',
    copying: 'progress', staging: 'progress',
    'waiting-heartbeat': 'info', 'waiting-staging': 'info',
    'onboard-failed': 'negative', 'undeploy-failed': 'negative',
    'placement-failed': 'negative',
    deployed: 'positive', enrolled: 'positive',
    'image-failed': 'warning',   // overridden to 'severe' by ratio below
    // A resting state that wants an operator, not a transfer in flight --
    // same family as not-enrolled, deliberately not 'progress'.
    unassigned: 'inactive',
    'not-enrolled': 'inactive', offline: 'inactive'
  };
  var STATUS_ICONS = {
    positive: 'i-check-circle', progress: 'i-dash-circle', negative: 'i-octagon-x',
    warning: 'i-triangle-warn', severe: 'i-diamond-severe', info: 'i-square-info',
    inactive: 'i-minus-circle', disabled: 'i-slash-circle'
  };
  function statusSentenceCase(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

  // status: the {key, label, ...} object deviceStatus() returns, or a bare
  // key string for the one modifier deviceStatus() never produces itself
  // ('offline', applied by deviceIsOffline() on top of whatever the cell
  // already says). ratio: errored/assigned images, image-failed only --
  // swings the pill between the amber warning and the orange severe diamond
  // (N-of-M by severity, spec status grammar).
  function statusDisplay(status, ratio) {
    var key = typeof status === 'string' ? status : status.key;
    var level = STATUS_LEVELS[key] || 'inactive';
    var label;
    if (key === 'image-failed') {
      level = (ratio || 0) >= 0.5 ? 'severe' : 'warning';
      label = (status && status.label) || STATUS_OPTION_LABELS[key] || key;
    } else if (STATUS_DYNAMIC_KEYS[key]) {
      label = statusSentenceCase((status && status.label) || STATUS_OPTION_LABELS[key] || key);
    } else {
      label = STATUS_PILL_LABEL_OVERRIDES[key] || STATUS_OPTION_LABELS[key] || key;
    }
    return { label: label, level: level };
  }

  // Icon + sentence-case label, tinted background, never color alone. <use>
  // only ever references the sprite vendored in index.html; the label text
  // (not the icon) carries the accessible name, so the sprite stays
  // aria-hidden and the icon itself needs none.
  //
  // levelPillHTML is the raw renderer (level chosen directly by the
  // caller); statusPillHTML derives the level from a deviceStatus() key via
  // statusDisplay() first, then hands off to it. Splitting them out (Task
  // 7) lets non-deviceStatus() domains -- the Cisco Bulk Hash verdict pill,
  // the Overview "Needs attention" rollup cards, a Staging Boundary
  // step's failed-step pill -- share the exact same markup/CSS without
  // borrowing deviceStatus()'s key space, which the spec keeps separate
  // ("device pill vs image verdict pill share only the same 8-level
  // PALETTE, not one key space").
  function levelPillHTML(level, label, opts) {
    opts = opts || {};
    var icon = STATUS_ICONS[level] || STATUS_ICONS.inactive;
    var titleAttr = opts.title ? ' title="' + esc(opts.title) + '"' : '';
    return '<span class="status-pill is-' + level + '"' + titleAttr + '>' +
      '<svg aria-hidden="true"><use href="#' + icon + '"></use></svg>' +
      esc(label) + '</span>';
  }
  function statusPillHTML(status, opts) {
    opts = opts || {};
    var d = statusDisplay(status, opts.ratio);
    return levelPillHTML(d.level, d.label, opts);
  }

  // Shared by deviceStatusHtml and Overview's "Needs attention" tally
  // (overviewDeviceAttention): image-failed's severity (warning vs severe)
  // depends on THIS device's own errored/assigned ratio -- one derivation,
  // so a fleet rollup can never grade a device's severity differently than
  // its own row does.
  function imageFailedRatio(d) {
    var assigned = rowAssignedIds(d);
    var errored = rowErroredIds(d).filter(function (iid) {
      return assigned.indexOf(iid) !== -1;
    });
    return assigned.length ? errored.length / assigned.length : 0;
  }
  // key deviceStatus() can return while an onboard/undeploy job is active ->
  // the job action that must match it, so a stale/superseded job for this
  // device (a different action, or one that already finished) can never be
  // mistaken for the one the cell is describing right now.
  var JOB_ACTION_FOR_STATUS_KEY = { onboarding: 'onboard', undeploying: 'undeploy' };
  function deviceStatusPresentation(d, devNow) {
    var st = deviceStatus(d, devNow);
    var disp = statusDisplay(st, st.key === 'image-failed' ? imageFailedRatio(d) : undefined);
    var job = LAST_JOBS_BY_DEVICE[d.device_id];
    var activeJob = job && (job.state === 'queued' || job.state === 'running') &&
      job.action === JOB_ACTION_FOR_STATUS_KEY[st.key] ? job : null;
    var pills = [{level: disp.level, label: disp.label + (activeJob ? jobPhaseSuffix(activeJob) : ''), title: st.detail}];
    if (deviceIsOffline(d, devNow)) {
      // Only a running teardown can explain a stopped heartbeat. A queued
      // undeploy has not touched the agent yet and keeps the normal warning.
      if (activeJob && activeJob.state === 'running' && st.key === 'undeploying') {
        pills.push({level: 'inactive', label: 'Offline (expected during undeploy)',
          title: 'The agent is deactivated at undeploy step [1/5]; no heartbeat is expected again until it re-enrolls.'});
      } else pills.push(statusDisplay('offline'));
    }
    return {pills: pills, detail: st.detail};
  }
  function deviceIsOffline(d, devNow) {
    return !!(d.last_seen && (devNow - d.last_seen) >= 600);
  }
  // device_id -> job for every RETAINED onboard/undeploy job (from GET
  // /api/v1/onboard/jobs, already fetched by refreshDevices) -> the one job
  // deviceStatusHtml should read for that device: mirrors gui_onboard.py's
  // own latest_jobs_by_device() tie-break exactly (an ACTIVE queued/running
  // job wins outright, else the most recently queued one), just kept on the
  // client so started_at and last_line survive the trip -- the server's own
  // merge into /api/v1/devices deliberately strips both (the raw data already
  // exists in the job listing; it is simply not in the trimmed
  // latest_jobs_by_device() dict). Device ids are operator-chosen, so the
  // map must not inherit anything from Object.prototype.
  function bestJobForDevice(jobs) {
    var best = Object.create(null);
    (jobs || []).forEach(function (j) {
      var did = j.device_id, cur = best[did];
      var active = j.state === 'queued' || j.state === 'running';
      if (!cur) { best[did] = j; return; }
      var curActive = cur.state === 'queued' || cur.state === 'running';
      if ((active && !curActive) ||
          (active === curActive && j.queued_at > cur.queued_at)) {
        best[did] = j;
      }
    });
    return best;
  }
  // A job's freshest log line (last_line) carries a "[n/m]" step marker only
  // on the tick its install/uninstall script actually echoes one
  // (device-install.sh etc. echo "[n/m] ..." per step) -- most ticks in
  // between (e.g. the guestshell-enable step, which can take several
  // minutes on a cold IOx start) show plain progress text with no bracket.
  // Remembering the newest step seen PER JOB keeps the status cell's step
  // count steady between brackets instead of flickering in and out every
  // ~10s poll; pruned back in refreshDevices() as jobs age out.
  var lastJobStep = {};
  function jobPhaseSuffix(job) {
    if (!job || !job.started_at) return '';
    var m = /\[(\d+\/\d+)\]/.exec(job.last_line || '');
    if (m) lastJobStep[job.id] = m[1];
    var step = lastJobStep[job.id];
    // Elapsed is SERVER clock minus SERVER clock (job.started_at is the
    // job's own started_at timestamp; LAST_DEV_NOW is the same server "now"
    // refreshDevices() already reads for offline-freshness math) -- never a
    // client-clock delta, so a page refresh (or a skewed lab VM) never
    // resets or distorts what looks like elapsed progress.
    var now = LAST_DEV_NOW || (Date.now() / 1000);
    var elapsedMin = Math.max(0, Math.round((now - job.started_at) / 60));
    var elapsed = elapsedMin >= 60
      ? Math.floor(elapsedMin / 60) + ' h ' + (elapsedMin % 60) + ' min'
      : elapsedMin + ' min';
    return (step ? ' [' + step + ']' : '') + ' · ' + elapsed;
  }

  // Set once by an Overview "Needs attention" devices card just before
  // routing here; consumed the next time the devices list is (re)fetched.
  var PENDING_DEV_FILTER = null;
  function goToDevicesFiltered(status) {
    PENDING_DEV_FILTER = status;
    location.hash = '#devices';
  }

  function fmtSize(n) {
    if (n == null) return '';
    var u = ['B', 'KB', 'MB', 'GB']; var i = 0; n = Number(n);
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return n.toFixed(i ? 1 : 0) + ' ' + u[i];
  }
  function fmtDate(t) { return t ? new Date(t * 1000).toLocaleString() : ''; }
  function csrfHdr(extra) { var h = { 'X-CSRF-Token': info.csrf }; if (extra) for (var k in extra) h[k] = extra[k]; return h; }
  async function jpost(url, body) {
    return fetch(url, { method: 'POST', headers: csrfHdr({ 'Content-Type': 'application/json' }), body: JSON.stringify(body) });
  }

  // Focus trap for a modal/drawer overlay (Task 6): Tab/Shift+Tab cycle
  // within the container's own focusable elements instead of escaping to
  // the page behind it. Modeled on server/swarmmap.html's #drawer keydown
  // handler, ported to this file's ES5 style. Attaching the listener
  // directly on the container (rather than document) is what makes this
  // safe to call once at setup time for every dialog: while the container
  // carries [hidden] nothing inside it is focusable, so no keydown ever
  // bubbles out of it and the trap is inert until the dialog is actually
  // open.
  function trapDialogFocus(container) {
    container.addEventListener('keydown', function (e) {
      if (e.key !== 'Tab') return;
      var focusable = Array.prototype.filter.call(
        container.querySelectorAll(
          'button:not([disabled]), [href], input:not([disabled]), ' +
          'select:not([disabled]), textarea:not([disabled]), ' +
          '[tabindex]:not([tabindex="-1"])'),
        function (el) { return el.offsetWidth > 0 || el.offsetHeight > 0; });
      if (!focusable.length) return;
      var first = focusable[0], last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault(); last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault(); first.focus();
      }
    });
  }

  // Shared with the remaining legacy image picker.
  function bulkhashVerdictPillHTML(hv, quarantined) {
    var state = hv && hv.state;
    var html;
    if (!state) {
      html = levelPillHTML('inactive', 'Not checked');
    } else if (state === 'verified') {
      html = levelPillHTML('positive', 'Verified');
    } else if (state === 'mismatch') {
      html = quarantined
        ? levelPillHTML('negative', 'Mismatch — quarantined')
        : levelPillHTML('negative', 'Mismatch — released');
    } else if (state === 'not_in_feed') {
      html = levelPillHTML('inactive', 'Not in Cisco\'s feed');
    } else {
      // Defensive: bulkhash.py only ever writes verified/mismatch/
      // not_in_feed, but a catch-all that silently relabeled anything else
      // as "Not in Cisco's feed" would misreport a genuinely unrecognized
      // state as a specific, wrong verdict instead of admitting it doesn't
      // know.
      html = levelPillHTML('inactive', 'Unknown verification state');
    }
    if (hv && hv.deferral) {
      html += ' ' + levelPillHTML('warning', 'Deferred by Cisco', { title: 'Deferred by Cisco' });
    }
    return html;
  }

  // Images owns its state, rendering and jobs in React. Keep session/CSRF and
  // visible-view scheduling shared until the other operational views migrate.
  function imageCommand(action, services) {
    return new Promise(function (resolve, reject) {
      window.dispatchEvent(new CustomEvent('iris:images-command', {
        detail: {action: action, services: services, resolve: resolve, reject: reject}
      }));
    });
  }
  async function refreshImages() { return imageCommand('refresh'); }
  async function refreshImportable() { return imageCommand('importable'); }
  function goToImagesFiltered() {
    imageCommand('attention');
    location.hash = '#images';
  }
  await imageCommand('connect', {
    fetch: fetch, headers: csrfHdr, post: jpost,
    refreshDevices: function () { return refreshDevices(); },
    confirm: function (text) { return window.confirm(text); },
    alert: function (text) { window.alert(text); },
    upload: function (file, progress) {
      return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.open('PUT', '/api/v1/images/upload/' + encodeURIComponent(file.name));
        xhr.setRequestHeader('X-CSRF-Token', info.csrf);
        xhr.upload.onprogress = function (event) {
          if (event.lengthComputable) progress(event.loaded / event.total * 100);
        };
        xhr.onload = function () {
          if (xhr.status === 401) onSessionLost();
          if (xhr.status !== 200) { reject(new Error('upload failed (' + xhr.status + ')')); return; }
          try { resolve(JSON.parse(xhr.responseText)); }
          catch (error) { reject(new Error('Upload response unreadable. Refresh before trying again.')); }
        };
        xhr.onerror = function () { reject(new Error('Upload response unavailable. Refresh before trying again.')); };
        xhr.onabort = function () { reject(new Error('Upload interrupted. Refresh before trying again.')); };
        xhr.send(file);
      });
    }
  });

  // ---- Devices ----
  var devStatus = document.getElementById('dev-status');
  var imageIds = [];
  // Whether imageIds/imageFilenames came from a SUCCESSFUL /api/v1/images read.
  // A failed fetch substitutes an empty list, which is indistinguishable from
  // an empty catalog once it reaches the picker -- and a picker showing no
  // images can only be applied as "unassign everything".
  var imageListOk = false;
  // id -> filename, refreshed alongside imageIds -- so a picker/drawer row
  // can show which file an id actually is, the way the catalog list does.
  var imageFilenames = Object.create(null);
  // id -> quarantined bool, refreshed alongside imageIds (KGV / Cisco Bulk
  // Hash reconciler, Task 5) -- so the picker can visibly block a
  // quarantined image instead of only relying on the server's own
  // set_policy() refusal, which the operator would only discover at Apply.
  var imageQuarantined = Object.create(null);
  var credOpts = [];
  // Whether the LAST /api/v1/credentials read succeeded. Mirrors imageListOk:
  // on failure credOpts keeps its previous value and every credential
  // picker is disabled and says so, instead of rendering the whole fleet
  // as "no credential" (an empty option list matches nothing).
  var credListOk = false;
  var peerPolicy = { revision: null, quarantine_assignments: [], enforcement: {} };
  var peerPolicyReadOk = false;
  // Inventory and Policies share capability/revision state. Only the latest
  // initiated read may replace it when routes or post-write reads overlap.
  var peerPolicyReadGeneration = 0;
  function peerPolicyAssigned(deviceId) {
    return (peerPolicy.quarantine_assignments || []).indexOf(deviceId) !== -1;
  }
  // The router remains the only owner of the visible-view 10-second poll.
  // Keyed React rows preserve focus and open controls through a fresh read.
  function pollDevices() { return refreshDevices(); }
  async function refreshDevices() {
    if (document.hidden || document.getElementById('view-devices').hidden) return;
    if (PENDING_DEV_FILTER !== null) {
      inventory.invalidate();
      inventory.update({filters: Object.assign({}, inventory.snapshot().filters, {status: PENDING_DEV_FILTER}), offset: 0});
      PENDING_DEV_FILTER = null;
    }
    return inventory.refresh();
  }
  inventory.connect({
    fetch: fetch, post: jpost, headers: csrfHdr,
    confirm: function (message) { return confirm(message); },
    isVisible: function () { return !document.hidden && !document.getElementById('view-devices').hidden; },
    beginPolicyRead: function () { return ++peerPolicyReadGeneration; },
    beginCredentialRead: function () { return deviceForms.beginCredentialRead(); },
    acceptCredentials: function (result, ticket) { return deviceForms.acceptCredentials(result, ticket); },
    beginImageRead: function () { return assignments.beginImageRead(); },
    acceptImages: function (result, ticket) { return assignments.acceptImages(result, ticket); },
    beginScheduleRead: function () { return schedules.beginScheduleRead(); },
    acceptSchedules: function (result, ticket) { return schedules.acceptSchedules(result, ticket); },
    publish: function (state, policyTicket) {
      LAST_DEVICES = state.rows; LAST_DEV_NOW = state.now; devTotal = state.total;
      imageListOk = state.imagesOk;
      imageIds = state.images.map(function (image) { return image.id; });
      imageFilenames = Object.create(null); imageQuarantined = Object.create(null);
      state.images.forEach(function (image) {
        imageFilenames[image.id] = image.filename || '';
        imageQuarantined[image.id] = !!image.quarantined;
      });
      credListOk = state.credentialsOk; credOpts = state.credentials;
      LAST_JOBS_BY_DEVICE = bestJobForDevice(state.jobs);
      var liveJobIds = new Set(state.jobs.map(function (job) { return job.id; }));
      Object.keys(lastJobStep).forEach(function (id) { if (!liveJobIds.has(id)) delete lastJobStep[id]; });
      if (policyTicket === peerPolicyReadGeneration) {
        peerPolicyReadOk = state.policyOk;
        if (state.policyOk) peerPolicy = state.policy;
      }
      // Publish shared policy capabilities last, after every adapter value
      // is ready. A newer Policies read always wins over this route's read.
      renderPeerPolicyPanel();
    },
    selectionChanged: updateSelBar,
    report: function (message, failed) {
      devStatus.textContent = message;
      devStatus.classList.toggle('err', failed);
      devStatus.classList.toggle('muted', !failed);
    },
    statusOptions: DEVICE_STATUS_OPTIONS,
    statusLevel: function (key) { return STATUS_LEVELS[key] || 'inactive'; },
    status: deviceStatusPresentation, assignedIds: rowAssignedIds,
    seriesLabel: deviceSeriesLabel, installLabel: agentInstallLabel, installRefusal: installRefusal,
    details: openDeployInfo, assign: openRowAssign,
    scheduled: function (id) { return schedules.scheduled(id); }
  });
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) { inventory.hide(); deviceForms.hide(); assignments.hide(); inventoryActions.hide(); schedules.hide(); roleActions.hide(); policies.hide(); }
    else if (!document.getElementById('view-devices').hidden) { deviceForms.resume(); schedules.resume(); }
  });

  // React owns the details DOM and async lifetimes. Shared Inventory status
  // derivation stays here so table, Overview and drawer cannot disagree.
  function deviceDetailsCommand(action, options) {
    return new Promise(function (resolve, reject) {
      window.dispatchEvent(new CustomEvent('iris:device-details-command', {
        detail: Object.assign({action: action, resolve: resolve, reject: reject}, options || {})
      }));
    });
  }
  function openDeployInfo(id) {
    closeActivity(false);
    var d = LAST_DEVICES.find(function (x) { return x.device_id === id; }) || {};
    return deviceDetailsCommand('open', {id: id, data: {device: d,
      status: deviceStatus(d, LAST_DEV_NOW), failedRatio: imageFailedRatio(d),
      filenames: imageFilenames, quarantined: imageQuarantined}});
  }
  function closeDeployInfo(restoreFocus) { return deviceDetailsCommand('close', {restoreFocus: restoreFocus}); }
  await deviceDetailsCommand('connect', {services: {fetch: fetch, post: jpost,
    confirm: function (message) { return confirm(message); }}});

  // React owns Activity, its timer, streams and batch request lifetimes.
  // The adapter retains shared authentication and the Inventory selection lock.
  function activityCommand(action, options) {
    return new Promise(function (resolve, reject) {
      window.dispatchEvent(new CustomEvent('iris:activity-command', {
        detail: Object.assign({action: action, resolve: resolve, reject: reject}, options || {})
      }));
    });
  }
  function closeActivity(restoreFocus) { return activityCommand('close', {restoreFocus: restoreFocus}); }
  await activityCommand('connect', {services: {
    fetch: function (url, opts, fromPoll) {
      if (fromPoll) backgroundPoll = true;
      return fetch(url, opts);
    },
    post: jpost,
    confirm: function (message) { return confirm(message); },
    eventSource: function (url) { return new EventSource(url); },
    show: function () { closeDeployInfo(false); },
    refreshDevices: function () {
      if (!document.getElementById('view-devices').hidden) return pollDevices();
    },
    reportCount: function (count, error) {
      inventory.update({activityLabel: 'Activity' + (error ? ' (unavailable)' : count ? ' (' + count + ')' : '')});
    },
    outcome: function (message, failed) {
      devStatus.textContent = message;
      devStatus.classList.toggle('err', failed);
      devStatus.classList.toggle('muted', !failed);
    }
  }});
  onInventoryAction('dev-activity', function () { activityCommand('open'); });
  window.addEventListener('hashchange', function () { closeActivity(false); });
  document.addEventListener('visibilitychange', function () {
    activityCommand('visibility', {visible: !document.hidden && !document.getElementById('view-devices').hidden});
  });
  function closeMenus() { inventory.update({menu: ''}); }
  onInventoryAction('onboard-selected', function () { inventoryActions.open('onboard', selectedIds()); });
  onInventoryAction('undeploy-selected', function () { inventoryActions.open('undeploy', selectedIds()); });
  onInventoryAction('set-cred-selected', function () { assignments.openCredentials(selectedIds()); });
  function updateSelBar() {
    if (!selectedIds().length) {
      if (inventory.snapshot().menu === 'more') closeMenus();
    }
  }

  // Dialogs capture explicit IDs from the same model as the table.
  function selectedIds() { return inventory.selectedIds(); }
  function cancelSelectAllMatching() { inventory.cancelSelection(); }
  // Every selected-action shares one lock. Without it a delete could fire while
  // an onboard batch is still starting, removing inventory out from under a
  // running job — onboard/undeploy previously guarded only each other.
  // The controls that actually FIRE a bulk action and claim the lock. Onboard
  // and undeploy now fire from inside their modal, so the ids here are the
  // modal primaries; the bulk bar's own Onboard…/Undeploy… buttons only open
  // those modals and are listed as openers below.
  var BULK_BTNS = ['onboard-confirm', 'undeploy-confirm', 'adopt-selected',
                   'delete-selected', 'apply-cred-selected', 'apply-role-selected',
                   'assign-images-selected',
                   'quarantine-selected', 'release-selected',
                   'create-schedule'];
  // Openers claim no lock of their own -- there is nothing to claim until the
  // modal's primary is pressed -- but they must not hand out a second modal
  // while a batch is still starting.
  var BULK_OPENERS = ['onboard-selected', 'undeploy-selected', 'set-cred-selected', 'set-role-selected',
                      'schedule-selected'];
  var bulkBusy = false;
  function setBulkBusy(busy) {
    bulkBusy = busy;
    inventory.update({bulkBusy: busy});
    BULK_BTNS.concat(BULK_OPENERS).forEach(function (id) {
      var el = document.getElementById(id);
      if (el && !el.closest('[data-inventory-react], [data-assignments-react], [data-inventory-actions-react], [data-schedules-react], [data-role-actions-react]')) el.disabled = busy;
    });
    syncRoleActionAvailability();
  }
  assignments.connect({
    fetch: fetch, post: jpost,
    confirm: function (message) { return confirm(message); },
    isVisible: function () { return !document.hidden && !document.getElementById('view-devices').hidden; },
    refreshInventory: refreshDevices,
    report: function (message, failed) { inventory.report(message, failed); },
    claimRow: function (id) { return inventory.claimRow(id); },
    releaseRow: function (id) { inventory.releaseRow(id); },
    claimBulk: function () {
      if (bulkBusy || inventory.snapshot().rowBusy.size) return false;
      cancelSelectAllMatching(); setBulkBusy(true); return true;
    },
    releaseBulk: function () { setBulkBusy(false); },
    publishImages: function (state) {
      inventory.update(state);
      imageListOk = state.imagesOk; imageIds = state.images.map(function (image) { return image.id; });
      imageFilenames = Object.create(null); imageQuarantined = Object.create(null);
      state.images.forEach(function (image) { imageFilenames[image.id] = image.filename || ''; imageQuarantined[image.id] = !!image.quarantined; });
    }
  });
  inventory.subscribe(function () { assignments.prerequisites(inventory.snapshot()); });
  assignments.prerequisites(inventory.snapshot());
  // "id — filename", both escaped -- the same two facts the catalog list
  // shows for an image, so a picker/drawer row never makes the operator go
  // find the id in the Images tab to see what it actually is. Falls back to
  // the bare id when the filename is not known (a stale id the catalog no
  // longer has, or imageFilenames not loaded yet), and shows the id ONCE when
  // it IS the filename: publish.derive_id strips only .SPA.bin/.bin, so an
  // IOS-XR .iso/.tar image's id is its whole filename and would otherwise
  // read "8000-x64-26.2.1.iso — 8000-x64-26.2.1.iso".
  function imageLabel(id) {
    var fn = imageFilenames[id];
    return fn && fn !== id ? esc(id) + ' — ' + esc(fn) : esc(id);
  }
  // Both entry points use the same React picker and captured-target controller.
  function openRowAssign(id) { return assignments.openImages([id], true); }
  inventoryActions.connect({
    fetch: fetch, post: jpost, headers: csrfHdr,
    confirm: function (message) { return confirm(message); },
    isVisible: function () { return !document.hidden && !document.getElementById('view-devices').hidden; },
    report: function (message, failed) { inventory.report(message, failed); },
    refreshInventory: refreshDevices,
    claimBulk: function () {
      if (bulkBusy || inventory.snapshot().rowBusy.size) return false;
      cancelSelectAllMatching(); setBulkBusy(true); return true;
    },
    releaseBulk: function () { setBulkBusy(false); },
    startJobs: function (action, ids, options) { return activityCommand('start', {jobAction: action, ids: ids, options: options}); },
    csvBusy: function (busy) { inventory.update({csvBusy: busy}); },
    removeSelection: function (ids) { inventory.removeSelection(ids); },
    saveCsv: inventoryActions.saveCsv
  });
  inventory.subscribe(function () { inventoryActions.prerequisites(inventory.snapshot()); });
  inventoryActions.prerequisites(inventory.snapshot());
  onInventoryAction('delete-selected', function () { return inventoryActions.act('delete', selectedIds()); });
  // React owns Policies; this bridge shares authentication and read ordering
  // with Inventory without writing into the Policies root.
  function roleCapabilityMessage() { return policies.capability(peerPolicy, peerPolicyReadOk); }
  function syncRoleActionAvailability() {
    inventory.update({roleAvailable: !roleCapabilityMessage(), policy: peerPolicy, policyOk: peerPolicyReadOk});
  }
  function renderPeerPolicyPanel() {
    syncRoleActionAvailability();
    policies.policy(peerPolicy, peerPolicyReadOk);
    var banner = document.getElementById('inventory-role-capability-banner');
    banner.textContent = roleCapabilityMessage(); banner.hidden = !banner.textContent;
  }
  policies.connect({
    fetch: fetch, headers: csrfHdr, formatDate: fmtDate,
    confirm: function (message) { return confirm(message); },
    saveCsv: inventoryActions.saveCsv,
    isVisible: function () { return !document.hidden && !document.getElementById('view-policies').hidden; },
    beginPolicyRead: function () { return ++peerPolicyReadGeneration; },
    publishPolicy: function (policy, valid, ticket) {
      if (ticket !== peerPolicyReadGeneration) return false;
      peerPolicyReadOk = valid;
      if (valid) peerPolicy = policy;
      renderPeerPolicyPanel(); return true;
    },
    invalidatePolicyReads: function () { peerPolicyReadGeneration++; inventory.invalidate(); },
    claimBulk: function () {
      if (bulkBusy || inventory.snapshot().rowBusy.size) return false;
      cancelSelectAllMatching(); setBulkBusy(true); return true;
    },
    releaseBulk: function () { setBulkBusy(false); }
  });
  inventory.subscribe(function () { policies.prerequisites(inventory.snapshot()); });
  policies.prerequisites(inventory.snapshot());
  policies.policy(peerPolicy, peerPolicyReadOk);

  // React owns captured role targets, preview/commit and serial quarantine.
  roleActions.connect({
    fetch: fetch, headers: csrfHdr,
    warning: roleCapabilityMessage,
    policyWriteBusy: function () { return policies.state.busy; },
    confirm: function (message) { return confirm(message); },
    isVisible: function () { return !document.hidden && !document.getElementById('view-devices').hidden; },
    refreshInventory: async function () {
      // A hidden/superseded read is not evidence for retrying an unknown write.
      var result = await refreshDevices();
      return !!(result && result.policyOk && result.policyTicket === peerPolicyReadGeneration && peerPolicyReadOk);
    },
    invalidatePolicyReads: function () { peerPolicyReadGeneration++; inventory.invalidate(); },
    report: function (message, failed) { inventory.report(message, failed); },
    claimBulk: function () {
      if (bulkBusy || inventory.snapshot().rowBusy.size) return false;
      cancelSelectAllMatching(); setBulkBusy(true); return true;
    },
    releaseBulk: function () { setBulkBusy(false); }
  });
  inventory.subscribe(function () { roleActions.prerequisites(inventory.snapshot()); });
  roleActions.prerequisites(inventory.snapshot());
  onInventoryAction('set-role-selected', function () { roleActions.open(selectedIds()); });
  onInventoryAction('quarantine-selected', function () { return roleActions.quarantine(selectedIds(), true); });
  onInventoryAction('release-selected', function () { return roleActions.quarantine(selectedIds(), false); });

  onInventoryAction('adopt-selected', function () { return inventoryActions.act('adopt', selectedIds()); });
  onInventoryAction('assign-images-selected', function () { assignments.openImages(selectedIds()); });
  function deviceSeriesLabel(series, model) {
    var labels = { IE3x00: 'IE Switches', IR1x00: 'IR Routers',
      C8xxx: 'Catalyst Routers', C9xxx: 'Catalyst Switches',
      NCS: 'NCS', XR8000: 'Cisco 8000 Series' };
    return labels[series] || labels[model] || model || '—';
  }
  // React owns the full device and credential forms. The adapter retains the
  // existing authenticated transport and shared Inventory prerequisites.
  deviceForms.connect({
    fetch: fetch, post: jpost, headers: csrfHdr,
    confirm: function (message) { return confirm(message); },
    isVisible: function () { return !document.hidden && !document.getElementById('view-devices').hidden; },
    refreshInventory: refreshDevices,
    claimDevice: function (id) { return inventory.claimRow(id); },
    releaseDevice: function (id) { inventory.releaseRow(id); },
    report: function (message, failed) { inventory.report(message, failed); },
    publishCredentials: function (state) {
      credOpts = state.credentials; credListOk = state.credentialsOk;
      inventory.update(state);
    }
  });
  // Opening a form is not a mutation. Keep its trigger usable while the
  // controller's cancellable read runs, including close and immediate reopen.
  onInventoryAction('add-dev', function () { deviceForms.toggleDevice(); });
  onInventoryAction('manage-creds', function () { deviceForms.toggleCredentials(); });
  // Inventory CSV state, validation and async lifetimes belong to React.
  onInventoryAction('import-csv', function () { inventoryActions.chooseFile(); });
  function downloadCsv(url, filename) { return inventoryActions.download(url, filename); }
  onInventoryAction('export-csv', function () { return downloadCsv('/api/v1/devices/export-csv', 'devices.csv'); });
  onInventoryAction('example-csv', function () { return downloadCsv('/api/v1/devices/example-csv', 'devices-example.csv'); });
  // Schedules share read ordering with Inventory and use the same write lock.
  schedules.connect({
    fetch: fetch, post: jpost, headers: csrfHdr,
    isVisible: function () { return !document.hidden && !document.getElementById('view-devices').hidden; },
    publishSchedules: function (patch) { inventory.update(patch); },
    refreshInventory: refreshDevices,
    report: function (message, failed) { inventory.report(message, failed); },
    claimBulk: function () {
      if (bulkBusy || inventory.snapshot().rowBusy.size) return false;
      cancelSelectAllMatching(); setBulkBusy(true); return true;
    },
    releaseBulk: function () { setBulkBusy(false); }
  });
  inventory.subscribe(function () { schedules.prerequisites(inventory.snapshot()); });
  schedules.prerequisites(inventory.snapshot());
  onInventoryAction('schedule-selected', function () { schedules.open(inventory.snapshot()); });
  onInventoryAction('manage-schedules', function () { return schedules.togglePanel(); });


  // ---- Overview: "Needs attention" band (worst-of-group rollups) --------
  // Combined worst-of-group, per the Magnetic status-indicator guidance
  // ("COMBINED status = worst-of-group (Overview fleet rollups)"): reuses
  // the SAME deviceStatus()/statusDisplay() derivation the Devices table
  // already renders from, and the SAME quarantine flag the Images catalog
  // and image picker already read -- nothing new is computed here, only
  // tallied. Offline (Inactive, a freshness modifier per spec) is
  // deliberately not counted -- this band is real negative/severe/warning
  // problems, not staleness.
  var ATTENTION_LEVEL_RANK = { negative: 3, severe: 2, warning: 1 };
  function overviewDeviceAttention(devs, devNow) {
    var worst = null, count = 0;
    devs.forEach(function (d) {
      var st = deviceStatus(d, devNow);
      var ratio = st.key === 'image-failed' ? imageFailedRatio(d) : undefined;
      var lvl = statusDisplay(st, ratio).level;
      if (!ATTENTION_LEVEL_RANK[lvl]) return;
      count++;
      if (!worst || ATTENTION_LEVEL_RANK[lvl] > ATTENTION_LEVEL_RANK[worst]) worst = lvl;
    });
    return { count: count, level: worst };
  }
  function overviewImageAttention(imgs) {
    var count = imgs.filter(function (i) { return !!i.quarantined; }).length;
    return { count: count, level: count ? 'negative' : null };
  }
  function publishOverview(detail) {
    window.dispatchEvent(new CustomEvent('iris:overview-state', {detail: detail}));
  }
  function renderOverviewAttention(devs, devNow, imgs, fleetDataUnavailable) {
    publishOverview({attention: {
      devices: overviewDeviceAttention(devs, devNow),
      images: overviewImageAttention(imgs),
      unavailable: fleetDataUnavailable
    }});
  }
  window.addEventListener('iris:overview-action', function (event) {
    if (event.detail.kind === 'devices') goToDevicesFiltered('__attention');
    else if (event.detail.kind === 'images') goToImagesFiltered();
  });

  // ---- Overview ----
  // Same stale-response hazard refreshDevices() already guards against
  // (generation counter + AbortController, above): once the hash router
  // owns ALL visible-view polling (Task 10), an overlapping refreshOverview()
  // call -- a visibilitychange-triggered immediate refresh racing the
  // interval tick, or a rapid nav-away-and-back -- is a real possibility, so
  // a superseded call must not clobber a newer one's render.
  var deploymentRefreshController = null;
  async function refreshDeployment() {
    if (deploymentRefreshController) deploymentRefreshController.abort();
    var controller = new AbortController();
    deploymentRefreshController = controller;
    // Finish before the 10-second view poll, otherwise each new poll could
    // abort its predecessor forever while old inventory still looked current.
    var timer = setTimeout(function () { controller.abort(); }, 8000);
    try {
      var response = await fetch('/api/v1/deployment', {signal: controller.signal});
      if (!response.ok) throw new Error('unavailable');
      var data = await response.json();
      if (!data || !Array.isArray(data.components) || data.components.length > 64 ||
          ['layout', 'instance', 'namespace', 'note'].some(function (key) {
            return data[key] != null && typeof data[key] !== 'string';
          }) || data.components.some(function (item) {
            return !item || typeof item !== 'object' || Array.isArray(item) ||
              ['role', 'kind', 'name', 'host', 'address', 'os', 'architecture', 'image', 'kernel', 'state'].some(function (key) {
                return item[key] != null && typeof item[key] !== 'string';
              });
          })) throw new Error('invalid');
      if (deploymentRefreshController !== controller) return;
      publishOverview({deployment: data});
    } catch (error) {
      if (deploymentRefreshController !== controller) return;
      publishOverview({deployment: {unavailable: true}});
    } finally { clearTimeout(timer); }
  }
  var overviewRefreshGeneration = 0, overviewRefreshController = null;
  async function refreshOverview() {
    var mine = ++overviewRefreshGeneration;
    if (overviewRefreshController) overviewRefreshController.abort();
    overviewRefreshController = new AbortController();
    var signal = overviewRefreshController.signal;
    // Telemetry export health is dashboard state, so it rides the Overview
    // refresh. Deliberately not awaited with the overview fetch: a slow or
    // unreachable collector must not delay the cards.
    refreshTelemetryHealth();
    refreshDeployment();
    // /api/v1/overview is the PRIMARY fetch -- Fleet Totals and Rollout need
    // nothing else, so its own failure is still a hard bail (matches the
    // pre-existing behavior: no data, nothing to render).
    var or_;
    try {
      or_ = await fetch('/api/v1/overview', { signal: signal });
    } catch (e) {
      // Superseding a refresh is expected (a newer refreshOverview() call
      // already owns the render) and must not be treated as a real
      // failure; any other failure keeps the pre-existing hard bail: no
      // data, nothing to render.
      if (e && e.name === 'AbortError') return;
      return;
    }
    if (!or_.ok || mine !== overviewRefreshGeneration) return;
    var ov = await or_.json();
    if (mine !== overviewRefreshGeneration) return;

    // /api/v1/devices and /api/v1/images are SECONDARY -- only the attention band
    // and the aggregate boundary need them (Overview reads the same two
    // existing endpoints Devices/Images already fetch; nothing server-side
    // is new). Each gets its OWN .catch(), so a network-level rejection on
    // either one resolves to an empty fallback instead of rejecting the
    // Promise.all below -- a coupled try/catch around all three fetches
    // would have let one flaky secondary request kill Fleet Totals and
    // Rollout too, which never needed it. Both still fire concurrently.
    // failed:true marks BOTH degraded shapes -- a network-level rejection
    // (.catch) and a resolved-but-non-2xx response (the r.ok ? ... : ...
    // branch) -- so the renderer can tell "no data to report a problem
    // from" apart from "confirmed no problem", which look identical if all
    // you have is an empty array. (A superseded/aborted secondary fetch
    // also resolves to this same failed:true fallback, but that is never
    // rendered either -- the generation check right below discards it.)
    var devsPromise = fetch('/api/v1/devices', { signal: signal }).then(function (r) {
      return r.ok ? r.json() : { devices: [], now: null, failed: true };
    }).catch(function () { return { devices: [], now: null, failed: true }; });
    var imgsPromise = fetch('/api/v1/images', { signal: signal }).then(function (r) {
      return r.ok ? r.json() : { images: [], failed: true };
    }).catch(function () { return { images: [], failed: true }; });
    var results = await Promise.all([devsPromise, imgsPromise]);
    if (mine !== overviewRefreshGeneration) return;
    var dbody = results[0];
    var devs = dbody.devices || [];
    var devNow = dbody.now || Date.now() / 1000;
    var imgsBody = results[1];
    var imgs = imgsBody.images || [];
    var fleetDataUnavailable = !!(dbody.failed || imgsBody.failed);

    renderOverviewAttention(devs, devNow, imgs, fleetDataUnavailable);

    publishOverview({overview: ov});
  }
  async function refreshSwarm() {
    var [or_, sr] = await Promise.all([fetch('/api/v1/overview'), fetch('/api/v1/swarm')]);
    var mapUrl = or_.ok ? (await or_.json()).swarm_map_url : '';
    var link = document.getElementById('swarm-open');
    if (mapUrl) { link.href = mapUrl; link.style.display = ''; } else { link.style.display = 'none'; }
    var frame = document.getElementById('swarm-frame');
    if (frame && !frame.src) frame.src = '/swarmmap';
    var s = document.getElementById('swarm-summary');
    if (!sr.ok) { s.textContent = 'Swarm data unavailable.'; return; }
    var sw = await sr.json();
    if (sw.error) { s.textContent = 'Swarm data unavailable (' + sw.error + ').'; return; }
    var peers = (sw.images || []).reduce(function (n, im) {
      return n + ((im.peers || []).length);
    }, 0);
    var legacyPeers = (sw.images || []).reduce(function (n, im) {
      return n + (im.peers || []).filter(function (p) {
        return p && p.tracker && p.tracker.participant_class === 'legacy_unattributed';
      }).length;
    }, 0);
    var legacyWarning = document.getElementById('legacy-peer-warning');
    legacyWarning.hidden = legacyPeers === 0;
    legacyWarning.textContent = legacyPeers ? legacyPeers + ' legacy participant(s) cannot be attributed or individually quarantined until personalized torrent refresh.' : '';
    s.textContent = peers + ' peer(s) in the swarm. Open the full map for the live view.';
  }

  // ---- Settings ----
  // CA bundle source presets (Feature 3): the select is a client-side view
  // over the same stored URL the free-text input always wrote — "cisco"
  // means "no override" (server default), "mozilla" is this curated URL,
  // anything else is "custom" and shows the raw input.
  var CA_MOZILLA_URL = 'https://curl.se/ca/cacert.pem';
  var CA_CISCO_URL = 'https://www.cisco.com/security/pki/trs/ios.p7b';

  // ---- Settings: post-install setup checklist ----
  // Chips render through the real Magnetic status-pill system (levelPillHTML)
  // rather than the ad-hoc badge-* palette this used before Task 9 --
  // "everything should match Magnetic" applies to the Setup pane's pills too.
  // The level is state-driven by default (SETUP_CHIP_LEVELS); a caller may
  // override it (setupItemChipHTML below) for items that are recommended
  // rather than required, which the state alone cannot express.
  var SETUP_CHIP_LEVELS = {
    ok: 'positive',
    unset: 'warning', stale: 'warning',
    configured_unrun: 'warning',
    // "cannot determine" is an honest unknown, not a claimed problem -- it
    // reads closer to Magnetic's Inactive ("unknown ... indefinite holds")
    // than to a Warning this module has no evidence to justify.
    //
    // 'absent' (fix wave, reviewer Critical): a package for an architecture
    // this deployment does not use -- console.md's own words, "needs no
    // action" -- not a gap the operator failed to fill. The server ranks
    // absent above ok in packages.state's worst-of roll-up
    // (setup_status._RANK), so any single-architecture deployment (the
    // common case: one of iris-amd64.tar/iris-arm64.tar never gets built on
    // purpose) rolled up to 'absent' and painted a PERSISTENT false amber
    // Warning here, in both Settings > Setup and wizard step 3, with
    // nothing an operator could do to clear it. Not-applicable, same as
    // 'unknown'.
    unknown: 'inactive', absent: 'inactive'
  };
  var SETUP_CHIP_LABELS = {
    ok: 'Done', unset: 'Not configured', stale: 'Needs rebuild',
    absent: 'Not built', unknown: 'Cannot determine',
    // M37 fold-in (carried from the KGV close-out): distinct wording for "a
    // schedule exists but has not yet produced a successful run", never
    // conflated with "never configured at all".
    configured_unrun: 'Configured — no successful run yet'
  };
  function setupChip(state, levelOverride) {
    var level = levelOverride || SETUP_CHIP_LEVELS[state] || 'inactive';
    var label = SETUP_CHIP_LABELS[state] || state;
    return levelPillHTML(level, label);
  }

  // packages.reason (present only in some non-ok states) needs its own
  // guidance -- the plain rebuild remedy is actively WRONG for a
  // served-vs-distributed mismatch, since new onboards are broken too and
  // rebuilding packages would not fix it.
  var SETUP_PKG_REASON_TEXT = {
    'served-vs-distributed-mismatch':
      'The certificate this server currently serves does not match the ' +
      'copy handed to devices during onboarding. New onboards are ' +
      'affected as well as existing ones, and rebuilding packages alone ' +
      'will not resolve this.',
    'distributed-cert-unavailable':
      'The copy of the certificate handed to devices could not be read, ' +
      'so onboarding readiness cannot be confirmed.',
    'served-cert-unavailable':
      'The certificate used by this server could not be read, so ' +
      'onboarding readiness cannot be confirmed.'
  };

  function setupPkgRemedyText(pkg) {
    if (pkg.state === 'ok') return '';
    var parts = [];
    var reasonText = SETUP_PKG_REASON_TEXT[pkg.reason];
    if (reasonText) parts.push(reasonText);
    // Each non-ready package names its own build command: IOx and IOS-XR
    // use different wrappers. Certificate rotation does not stale packages;
    // a served/distributed certificate mismatch needs separate repair.
    if (pkg.reason !== 'served-vs-distributed-mismatch') {
      var remedies = [];
      (pkg.items || []).forEach(function (i) {
        // Every non-ready item carries an actionable host-side command.  In
        // particular, a missing/invalid provenance sidecar is reported as
        // "unknown", not "absent" or "stale"; hiding its remedy would leave
        // the operator with a diagnosis but no way to repair it.
        if (i.state !== 'ok' && i.remedy &&
            remedies.indexOf(i.remedy) === -1) {
          remedies.push(i.remedy);
        }
      });
      if (remedies.length) {
        parts.push('Rebuild on the Docker host, then re-onboard affected devices: '
          + remedies.join('; '));
      }
    }
    return parts.join(' ');
  }

  // telemetry.source distinguishes an explicit console override from the
  // deployment default (whatever the compose/env file happens to set) --
  // meaningfully different to an operator, so this note names which one is
  // in effect rather than just showing the chip.
  function setupTelemetryNote(t) {
    var scope = t.source === 'override' ? 'console override' : 'deployment default';
    if (t.state === 'ok') return 'Exporting to ' + t.endpoint + ' (' + scope + ').';
    if (!t.enabled) return 'Export is disabled (' + scope + ').';
    return 'No endpoint is set (' + scope + ').';
  }

  // A failed or thrown fetch must never leave a PREVIOUS render on screen --
  // that would be evidence-free chips still claiming "done" (spec:
  // error handling must show "cannot determine" per card and never silently
  // render a stale/empty checklist as if it were healthy).
  function setupShowUnknown() {
    document.getElementById('setup-admin-chip').innerHTML = setupChip('unknown');
    document.getElementById('setup-td-chip').innerHTML = setupChip('unknown');
    document.getElementById('setup-td-note').textContent = '';
    document.getElementById('setup-pkg-chip').innerHTML = setupChip('unknown');
    document.querySelector('#setup-pkg-table tbody').innerHTML = '';
    document.getElementById('setup-pkg-remedy').textContent = '';
    document.getElementById('setup-iv-chip').innerHTML = setupChip('unknown');
  }

  function renderPackageStatus(pkg, chipId, tableId, remedyId) {
    var chip = document.getElementById(chipId);
    var table = document.querySelector('#' + tableId + ' tbody');
    var remedy = document.getElementById(remedyId);
    if (chip) chip.innerHTML = setupChip(pkg ? pkg.state : 'unknown');
    if (table) {
      table.innerHTML = ((pkg && pkg.items) || []).map(function (i) {
        var when = i.built_at ? new Date(i.built_at * 1000).toLocaleString() : '—';
        var evidence = i.detail || i.reason || '';
        return '<tr><td class="muted machine">' + esc(i.name || '') + '</td><td>' +
          setupChip(i.state) + '</td><td class="muted">' + esc(when) +
          '</td><td class="muted">' + esc(evidence) + '</td></tr>';
      }).join('');
    }
    if (remedy) remedy.textContent = pkg ? setupPkgRemedyText(pkg) : '';
  }

  // Items that are recommended rather than required to finish onboarding a
  // server: IRIS runs without a telemetry destination or image verification,
  // it just cannot prove either is happening. This is a per-ITEM judgment
  // call the setup-status payload does not itself encode (it only ever
  // reports each card's own ok/unset), so it lives here rather than in the
  // API -- widening that response is out of scope for this task.
  var SETUP_ITEM_OPTIONAL = { telemetry: true, image_verification: true };

  // M37 fold-in (carried from the KGV close-out): setup_status.py's
  // image_verification card reports ok only once a run has actually
  // SUCCEEDED (see its docstring) -- a scheduled-but-never-run config and a
  // truly unconfigured one both resolve to "unset" from that field alone.
  // The schedule's own mode -- the same data Settings > Image verification
  // already reads via /api/v1/settings/image-verification -- is what tells
  // them apart. A failed/thrown fetch here must never invent "configured"
  // without evidence, so it resolves to null (treated as "don't know",
  // never as configured).
  // Fix wave (reviewer Minor): the wizard's own showWizardStep needs this
  // same payload again the instant it lands on step 4 (to populate #iv-mode/
  // #iv-hour/#iv-last-run) -- entering the wizard and clicking Next both call
  // this via refreshSetupWizard immediately before showing the resulting
  // step, so without this cache that step 4 landing fetched the identical
  // endpoint twice in a row. wizardIvStatus is consumed (read, then cleared)
  // only by that one call site, landing on step 4 straight out of
  // refreshSetupWizard -- Back and a direct steplist click both call
  // showWizardStep directly, with no refresh first, so neither one clears
  // or renews this cache. Landing on step 4 that way renders whatever this
  // variable last held, however old: fresh if refreshSetupWizard only just
  // set it, stale if the operator lingered on another step or edited image
  // verification via Settings in between. The setup view is not polled, so
  // nothing else invalidates the cache in the meantime.
  var wizardIvStatus = null;
  async function fetchIvScheduleConfigured() {
    try {
      var r = await fetch('/api/v1/settings/image-verification');
      if (!r.ok) { wizardIvStatus = null; return null; }
      var iv = await r.json();
      wizardIvStatus = iv;
      return (iv.mode || 'off') !== 'off';
    } catch (e) {
      wizardIvStatus = null;
      return null;
    }
  }

  // One place that combines: the state a card reports, the M37 distinction
  // (image_verification only), and the required-vs-recommended pill level --
  // shared verbatim by the Settings > Setup status pane and the wizard's own
  // step list/chips, so the two surfaces can never disagree about how a step
  // reads (spec: "Step titles carry status indicators, reuse pill levels").
  function setupItemChipHTML(key, state, ivScheduleConfigured) {
    var effectiveState = state;
    if (key === 'image_verification' && state !== 'ok' && ivScheduleConfigured) {
      effectiveState = 'configured_unrun';
    }
    var override;
    if (effectiveState !== 'ok' && effectiveState !== 'configured_unrun' &&
        SETUP_ITEM_OPTIONAL[key]) {
      override = 'info';
    }
    return setupChip(effectiveState, override);
  }

  // ---- First-run setup wizard -------------------------------------------
  // A flow, not a checklist: the operator finishes setup here instead of being
  // sent back and forth to Settings pages. The telemetry step mounts the SAME
  // template Settings uses, so there is one implementation of that form.
  //
  // Every step is skippable and the wizard resumes at the first incomplete one.
  // That is forced, not a convenience: the packages step can never complete
  // in-console (the container has no Docker socket), so a wizard that insisted
  // on completion could never be finished.
  //
  // Step 3, Image verification (Task 9, USER DIRECTIVE): supersedes the
  // earlier decision that this card stays outside the wizard -- it now
  // mounts the SAME Settings > Image verification controls (schedule,
  // Refresh now, offline import) via mountImageVerification, the same
  // one-implementation precedent as the telemetry form mount.
  var WIZARD_STEPS = [
    { id: 'telemetry', pane: 'wz-step-telemetry', key: 'telemetry',  chip: 'wz-td-chip',  label: 'Telemetry destination' },
    { id: 'packages',  pane: 'wz-step-packages',  key: 'packages',   chip: 'wz-pkg-chip', label: 'Device packages' },
    { id: 'imageverification', pane: 'wz-step-imageverification', key: 'image_verification',
      chip: 'wz-iv-chip', label: 'Image verification' }
  ];
  var wizardStep = 0;
  var wizardStatus = null;
  // M37 fold-in for the wizard's own step list/chip -- fetched alongside
  // wizardStatus in refreshSetupWizard, same shared helper the Settings >
  // Setup status pane uses.
  var wizardIvConfigured = null;

  function wizardFirstIncompleteStep(status) {
    if (!status) return 0;
    for (var i = 0; i < WIZARD_STEPS.length; i++) {
      var item = status[WIZARD_STEPS[i].key] || {};
      // An optional step (the server says required: false, or the client
      // knows it is recommended-only) never counts as outstanding.
      if (item.required === false || SETUP_ITEM_OPTIONAL[WIZARD_STEPS[i].key]) continue;
      if (item.state !== 'ok') return i;
    }
    return WIZARD_STEPS.length - 1;   // all done: rest on the last step
  }

  // Every step is listed with its current state, whatever that state is, and
  // any of them can be opened directly. Without this the wizard opened on the
  // first INCOMPLETE step and rendered only that one, so a step already
  // satisfied by the deployment environment -- telemetry, when
  // IRIS_OTLP_ENDPOINT is set in the compose env -- was never visible at all
  // and read as missing.
  function renderWizardStepList() {
    var host = document.getElementById('wz-steplist');
    if (!host) return;
    host.innerHTML = WIZARD_STEPS.map(function (st, n) {
      var state = wizardStatus ? ((wizardStatus[st.key] || {}).state || 'unknown')
                               : 'unknown';
      var isCurrent = n === wizardStep;
      // Marker anatomy (captured Magnetic Stepper): completed = blue-outline
      // check, current = blue filled with the step number, upcoming = plain
      // number -- current always wins the marker even on an already-'ok'
      // step, since the operator is standing on it right now.
      var isDone = !isCurrent && state === 'ok';
      var markerCls = isCurrent ? 'is-current' : (isDone ? 'is-done' : 'is-upcoming');
      var marker = isDone
        ? '<svg aria-hidden="true"><use href="#i-check"></use></svg>'
        : String(n + 1);
      var pill = wizardStatus
        ? setupItemChipHTML(st.key, state, st.id === 'imageverification' ? wizardIvConfigured : null)
        : setupChip('unknown');
      return '<button type="button" role="listitem" class="wz-steplist-item' +
        (isCurrent ? ' current' : '') + '" data-step="' + n + '">' +
        '<span class="wz-steplist-n ' + markerCls + '">' + marker + '</span>' +
        '<span class="wz-steplist-label">' + esc(st.label) + '</span>' +
        pill + '</button>';
    }).join('');
    host.querySelectorAll('.wz-steplist-item').forEach(function (b) {
      b.addEventListener('click', function () {
        showWizardStep(parseInt(b.getAttribute('data-step'), 10));
      });
    });
  }

  function showWizardStep(i) {
    wizardStep = Math.max(0, Math.min(WIZARD_STEPS.length - 1, i));
    WIZARD_STEPS.forEach(function (st, n) {
      document.getElementById(st.pane).hidden = n !== wizardStep;
    });
    // Mount the shared form for whichever step is showing. Settings reclaims
    // it on its way back in, so only one clone is ever live.
    if (WIZARD_STEPS[wizardStep].id === 'telemetry') {
      mountSettingsForm('td', 'wz-td-mount');
      refreshSettings();
    } else if (WIZARD_STEPS[wizardStep].id === 'imageverification') {
      // Moved, not cloned (see mountImageVerification) -- Settings reclaims
      // the same live nodes back on its own way in.
      mountImageVerification('wz-iv-mount');
      if (wizardIvStatus) {
        // fetchIvScheduleConfigured (called via refreshSetupWizard, just
        // before this) already fetched this exact payload -- reuse it
        // instead of a second GET. See wizardIvStatus's own comment.
        renderIvStatusFields(wizardIvStatus);
        wizardIvStatus = null;
      } else {
        refreshImageVerificationSettings();
      }
    }
    document.getElementById('wz-progress').textContent =
      'Step ' + (wizardStep + 1) + ' of ' + WIZARD_STEPS.length;
    document.getElementById('wz-back').disabled = wizardStep === 0;
    document.getElementById('wz-next').textContent =
      wizardStep === WIZARD_STEPS.length - 1 ? 'Done' : 'Next \u203a';
    renderWizardStepList();
  }

  function renderWizardPackages(pkg) {
    renderPackageStatus(pkg, 'wz-pkg-chip', 'wz-pkg-table', 'wz-pkg-remedy');
  }

  async function refreshSetupWizard() {
    var s = null;
    try {
      var r = await fetch('/api/v1/settings/setup-status');
      if (r.ok) s = await r.json();
    } catch (e) { /* leave s null -- never report green on missing evidence */ }
    wizardStatus = s;
    wizardIvConfigured = await fetchIvScheduleConfigured();
    function chip(id, state) {
      var el = document.getElementById(id);
      if (el) el.innerHTML = setupChip(state);
    }
    chip('wz-admin-chip', s ? (s.admin || {}).state : 'unknown');
    WIZARD_STEPS.forEach(function (st) {
      var el = document.getElementById(st.chip);
      if (!el) return;
      var state = s ? (s[st.key] || {}).state : 'unknown';
      el.innerHTML = s
        ? setupItemChipHTML(st.key, state, st.id === 'imageverification' ? wizardIvConfigured : null)
        : setupChip('unknown');
    });
    renderWizardPackages(s ? s.packages : null);
    renderWizardStepList();
    updateSetupNudge(s);
    return s;
  }

  // The nudge is what brings an operator back to an unfinished setup. It
  // dismisses for the SESSION, not for good: a package that goes stale later
  // is a silent regression, and a permanently dismissed banner would hide
  // exactly the failure this feature exists to catch.
  function setupIncompleteCount(s) {
    if (!s) return 0;
    return WIZARD_STEPS.filter(function (st) {
      return (s[st.key] || {}).state !== 'ok';
    }).length;
  }
  function updateSetupNudge(s) {
    var el = document.getElementById('setup-nudge');
    if (!el) return;
    var n = setupIncompleteCount(s);
    if (!n || window.sessionStorage.getItem('iris_setup_nudge_dismissed')) {
      el.hidden = true; return;
    }
    document.getElementById('setup-nudge-text').textContent =
      n + ' setup step' + (n === 1 ? '' : 's') + ' still ' +
      (n === 1 ? 'needs' : 'need') + ' attention.';
    el.hidden = false;
  }

  async function enterSetupWizard() {
    var s = await refreshSetupWizard();
    showWizardStep(wizardFirstIncompleteStep(s));
  }

  document.getElementById('wz-back').addEventListener('click', function () {
    showWizardStep(wizardStep - 1);
  });
  document.getElementById('wz-skip').addEventListener('click', function () {
    if (wizardStep === WIZARD_STEPS.length - 1) { location.hash = '#overview'; return; }
    showWizardStep(wizardStep + 1);
  });
  document.getElementById('wz-next').addEventListener('click', async function () {
    await refreshSetupWizard();
    if (wizardStep === WIZARD_STEPS.length - 1) { location.hash = '#overview'; return; }
    showWizardStep(wizardStep + 1);
  });
  document.getElementById('wz-pkg-recheck').addEventListener('click', function () {
    var msg = document.getElementById('wz-msg');
    msg.textContent = 'Re-checking\u2026';
    refreshSetupWizard().then(function () { msg.textContent = ''; });
  });
  document.getElementById('setup-nudge-dismiss').addEventListener('click', function () {
    window.sessionStorage.setItem('iris_setup_nudge_dismissed', '1');
    document.getElementById('setup-nudge').hidden = true;
  });

  async function refreshSetup() {
    var s;
    try {
      var r = await fetch('/api/v1/settings/setup-status');
      if (!r.ok) { setupShowUnknown(); return; }
      s = await r.json();
    } catch (e) {
      setupShowUnknown();
      return;
    }
    var ivConfigured = await fetchIvScheduleConfigured();
    document.getElementById('setup-admin-chip').innerHTML =
      setupChip(s.admin.state);
    document.getElementById('setup-td-chip').innerHTML =
      setupItemChipHTML('telemetry', s.telemetry.state, null);
    document.getElementById('setup-td-note').textContent =
      setupTelemetryNote(s.telemetry);
    renderPackageStatus(s.packages, 'setup-pkg-chip', 'setup-pkg-table',
      'setup-pkg-remedy');
    document.getElementById('setup-iv-chip').innerHTML =
      setupItemChipHTML('image_verification', s.image_verification.state, ivConfigured);
  }

  async function refreshDevicePackages() {
    var msg = document.getElementById('device-packages-msg');
    try {
      var r = await fetch('/api/v1/settings/setup-status');
      if (!r.ok) throw new Error('status ' + r.status);
      var s = await r.json();
      renderPackageStatus(s.packages, 'device-packages-chip',
        'device-packages-table', 'device-packages-remedy');
      if (msg) msg.textContent = '';
    } catch (e) {
      renderPackageStatus(null, 'device-packages-chip',
        'device-packages-table', 'device-packages-remedy');
      if (msg) msg.textContent = 'Package state cannot be determined.';
    }
  }

  document.getElementById('device-packages-recheck').addEventListener('click', function () {
    var msg = document.getElementById('device-packages-msg');
    if (msg) msg.textContent = 'Re-checking…';
    refreshDevicePackages();
  });

  async function refreshSettings() {
    var r, s;
    try {
      r = await fetch('/api/v1/settings'); if (!r.ok) return;
      s = await r.json();
    } catch (e) { return; } // The shared fetch wrapper reports unavailable live data.
    var rows = [
      ['Version', s.version],
      ['Admin', s.admin_username],
      ['Server IP', s.host_ip || '(unset)', 'machine'],
      ['Console URL', s.console_url || location.origin, 'machine'],
      ['Ports', 'tracker ' + s.ports.tracker + ' · catalog ' + s.ports.catalog +
                ' · artifacts ' + s.ports.artifacts + ' · swarm ' + s.ports.swarm +
                ' · console ' + s.ports.console]
    ];
    document.querySelector('#settings-info tbody').innerHTML = rows.map(function (kv) {
      return '<tr><td class="muted">' + esc(kv[0]) + '</td><td' +
        (kv[2] ? ' class="' + kv[2] + '"' : '') + '>' + esc(kv[1]) + '</td></tr>';
    }).join('');
    document.getElementById('sessions-info').textContent =
      s.sessions.active + ' active session(s); idle timeout ' +
      s.sessions.idle_ttl_minutes + ' min.';
    // --- Certificate (metadata only — key material never reaches this page) ---
    var gc = s.gui_cert || {};
    var certStatus = document.getElementById('cert-status');
    if (gc.source === 'custom' || gc.source === 'built-in') {
      var expiry = Date.parse(gc.not_after || '');
      var expired = Number.isFinite(expiry) && expiry <= Date.now();
      var expiring = Number.isFinite(expiry) && !expired && expiry - Date.now() < 30 * 86400000;
      var expiryBadge = !Number.isFinite(expiry) ? '' : '<span class="badge ' +
        (expired ? 'badge-fail' : expiring ? 'badge-queued' : 'badge-ok') + '">' +
        (expired ? 'Expired' : expiring ? 'Expires soon' : 'In date') + '</span>';
      certStatus.innerHTML = '<div class="tls-certificate-heading"><strong>Active browser identity</strong>' +
        '<span class="badge badge-running">' + (gc.source === 'custom' ? 'Custom' : 'Deployment default') +
        '</span>' + expiryBadge + '</div><dl class="tls-certificate-facts">' +
        '<div><dt>Issued to</dt><dd>' + esc(gc.subject || 'Unavailable') + '</dd></div>' +
        '<div><dt>Expires</dt><dd>' + esc(gc.not_after || 'Unavailable') + '</dd></div>' +
        '<div class="tls-fingerprint"><dt>SHA-256 fingerprint</dt><dd>' +
        esc(gc.fingerprint_sha256 || 'Unavailable') + '</dd></div></dl>';
    } else {
      certStatus.textContent =
        'Certificate details are unavailable.';
    }
    // A saved override may still be pending after a failed reload. Keep the
    // default action available even when the active certificate is unchanged.
    document.getElementById('cert-revert').hidden = false;
    // --- Trusted CAs table (rows rebuilt per render, like the images table) ---
    var trust = s.trust || [];
    document.getElementById('trust-tbl').hidden = !trust.length;
    document.getElementById('trust-empty').hidden = !!trust.length;
    var caSrcNow = (s.ca_trust || {}).url;
    var bundleLabel = !caSrcNow || caSrcNow === CA_CISCO_URL ? 'Cisco Trusted Root Store'
      : (caSrcNow === CA_MOZILLA_URL ? 'Mozilla CA bundle (curl.se)' : 'Custom URL');
    document.getElementById('trust-rows').innerHTML = trust.length
      ? trust.map(function (t) {
          // The downloaded bundle is ONE store file holding the whole public
          // CA set — name it as such, not by its (arbitrary) first cert.
          var isBundle = t.source === 'downloaded';
          return '<tr data-name="' + esc(t.name) + '"><td>' +
            (isBundle
              ? esc('Public CA bundle — ' + bundleLabel)
              : esc(t.subject || 'unknown')) +
            '</td><td class="machine">' + esc(t.not_after || 'unknown') +
            '</td><td class="machine">' + esc((t.fingerprint_sha256 || '').slice(0, 16)) + '…</td><td>' +
            (isBundle
              ? '<span class="badge badge-queued">downloaded</span>'
              : '<span class="badge badge-ok">manual</span>') +
            '</td><td>' + esc(t.cert_count) +
            '</td><td><button class="linkish danger-link trust-del">' +
            (isBundle ? 'remove bundle' : 'remove') + '</button></td></tr>';
        }).join('')
      : '<tr><td colspan="6" class="muted">No CA certificates installed — ' +
        'outbound TLS uses the system store only.</td></tr>';
    document.querySelectorAll('#trust-rows .trust-del').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        var name = btn.closest('tr').getAttribute('data-name');
        if (!confirm('Remove trusted CA ' + name + '?\n\n' +
            'New connections will no longer trust certificates from this CA. ' +
            'Telemetry export and CA downloads may fail.')) return;
        var msg = document.getElementById('trust-msg');
        msg.textContent = ''; msg.classList.remove('ok');
        var r = await settingsWrite('/api/v1/settings/trust/' + encodeURIComponent(name), null, msg, 'DELETE');
        if (!r) return;
        refreshSettings();
      });
    });
    var ct = s.ca_trust || {};
    document.getElementById('ca-url').value = ct.url || '';
    document.getElementById('ca-auto').checked = !!ct.auto;
    var caSourceSel = document.getElementById('ca-source');
    caSourceSel.value = !ct.url || ct.url === CA_CISCO_URL ? 'cisco' : (ct.url === CA_MOZILLA_URL ? 'mozilla' : 'custom');
    document.getElementById('ca-url').hidden = caSourceSel.value !== 'custom';
    // --- Telemetry destination (replaces the old read-only Observability row) ---
    var td = s.telemetry_destination || {};
    var obs = s.observability || {};
    var tdStatus = document.getElementById('td-status');
    if (tdStatus) tdStatus.innerHTML =
      (td.source === 'override'
        ? '<span class="badge badge-running">console override</span> '
        : '<span class="badge badge-queued">deployment default</span> ') +
      (td.effective_enabled
        ? ('export on — ' + esc(td.effective_endpoint || '(no endpoint)'))
        : 'export off') +
      (obs.metrics_url
        ? ' · Prometheus scrape ' + esc(obs.metrics_url) : '');
    var tdEndpoint = document.getElementById('td-endpoint');
    if (tdEndpoint) tdEndpoint.value = td.effective_endpoint || '';
    var tdEnabled = document.getElementById('td-enabled');
    if (tdEnabled) tdEnabled.checked = !!td.effective_enabled;
    var tdRevert = document.getElementById('td-revert');
    if (tdRevert) tdRevert.hidden = td.source !== 'override';
    // --- Audit export (the settings echo never carries the password) ---
    var ae = s.audit_export || {};
    document.getElementById('ae-host').value = ae.host || '';
    document.getElementById('ae-port').value = ae.port == null ? '' : ae.port;
    document.getElementById('ae-user').value = ae.user || '';
    document.getElementById('ae-path').value = ae.path || '';
    document.getElementById('ae-recipient').value = ae.age_recipient || '';
    document.getElementById('ae-auto').checked = !!ae.auto;
    var aePass = document.getElementById('ae-pass');
    aePass.value = '';
    aePass.placeholder = ae.password_set ? 'unchanged' : 'Password';
    var aeStatus = document.getElementById('ae-status');
    if (!ae.host) {
      aeStatus.textContent = 'Not configured — the audit trail stays on this server.';
    } else {
      var last;
      if (ae.last_run_ts) {
        var lr = String(ae.last_result || '');
        var lrOk = lr.slice(0, 3) === 'ok:';
        last = ' · last export ' + esc(fmtDate(ae.last_run_ts)) +
          ' <span class="badge ' + (lrOk ? 'badge-ok">ok' : 'badge-fail">fail') + '</span>' +
          (lr ? ' <span class="muted">' + esc(lr.slice(lr.indexOf(':') + 1)) + '</span>' : '');
      } else {
        last = ' · never exported yet';
      }
      aeStatus.innerHTML = '<span class="badge badge-running">configured</span> ' +
        esc((ae.user || '?') + '@' + ae.host + ':' + (ae.path || '')) +
        (ae.auto ? ' · daily' : ' · manual only') + last;
    }
    // --- Image verification (KGV / Cisco Bulk Hash reconciler, Task 5) ---
    // Its own dedicated GET, unlike the panes above -- not part of the big
    // /api/v1/settings blob (see the endpoint contract in Task 4's report).
    await refreshPeerTls();
    await refreshImageVerificationSettings();
  }
  var peerTlsMode = null;
  var peerTlsCanChange = false;
  var peerTlsPoll = null;
  async function refreshPeerTls() {
    var toggle = document.getElementById('peer-tls-toggle');
    var save = document.getElementById('peer-tls-save');
    var status = document.getElementById('peer-tls-status');
    clearTimeout(peerTlsPoll);
    try {
      var r = await fetch('/api/v1/settings/peer-tls');
      if (!r.ok) throw new Error('unavailable');
      var data = await r.json();
      if (!data || !['disabled', 'required'].includes(data.mode) || !data.origin || typeof data.can_change !== 'boolean') throw new Error('invalid');
      peerTlsMode = data.mode;
      peerTlsCanChange = data.can_change;
      toggle.checked = data.mode === 'required';
      toggle.disabled = !peerTlsCanChange;
      save.disabled = true;
      var label = data.origin.active_mode === 'required' ? 'TLS required' : data.origin.active_mode === 'disabled' ? 'TLS off' : 'not active';
      status.textContent = 'Origin seeder: ' + label + ' · ' + data.origin.state +
        (data.active_devices ? ' · ' + data.active_devices + ' device(s) must be undeployed before switching.' : '') +
        (data.active_jobs ? ' · Wait for ' + data.active_jobs + ' device job(s) to finish.' : '');
      if (data.origin.active_mode !== data.mode || data.origin.state !== 'running') {
        peerTlsPoll = setTimeout(function () {
          if (!document.getElementById('settings-pane-tls').hidden) refreshPeerTls();
        }, 2000);
      }
    } catch (e) {
      toggle.disabled = true; save.disabled = true; peerTlsMode = null;
      status.textContent = 'Peer transport status unavailable. Reload before changing the mode.';
    }
  }
  document.getElementById('peer-tls-toggle').addEventListener('change', function () {
    document.getElementById('peer-tls-save').disabled = !peerTlsCanChange ||
      (this.checked ? 'required' : 'disabled') === peerTlsMode;
  });
  document.getElementById('peer-tls-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    if (!peerTlsCanChange || peerTlsMode === null) return;
    var next = document.getElementById('peer-tls-toggle').checked ? 'required' : 'disabled';
    if (next === peerTlsMode) return;
    if (!confirm(next === 'required' ? 'Require TLS for all torrent traffic? The origin seeder will restart. Onboard devices afterward so they receive the same mode.' : 'Turn off peer TLS? Torrent traffic will no longer require encryption. The origin seeder will restart.')) return;
    var msg = document.getElementById('peer-tls-msg');
    var save = document.getElementById('peer-tls-save');
    msg.textContent = ''; save.disabled = true;
    var r = await settingsWrite('/api/v1/settings/peer-tls', {mode: next, expected_mode: peerTlsMode}, msg);
    if (r) {
      var result = await settingsResult(r, msg, function (body) { return body.applied === true && body.mode === next; });
      if (result) msg.textContent = 'Mode saved. Checking the origin seeder…';
    }
    await refreshPeerTls();
  });
  // ---- Settings: Image verification (KGV / Cisco Bulk Hash reconciler) ----
  // Schedule select + hour, Refresh now, offline .tar upload. Its own
  // dedicated GET/POST at /api/v1/settings/image-verification and
  // /api/v1/image-verification/{refresh,offline} -- see Task 4's endpoint
  // contracts. Factored out of refreshSettings (rather than inlined like the
  // ae-/cert- panes above) because the Refresh now button and the offline
  // upload both need to re-render just the last-run line afterward, without
  // re-fetching the whole /api/v1/settings blob.
  //
  // last_run.outcome is "ok" or "fail: <detail>" -- NEVER compared with
  // equality against "fail" (the detail suffix always differs); this
  // function and its caller only ever test the "fail" PREFIX.
  function bulkhashOutcomeFailed(outcome) {
    return String(outcome || '').slice(0, 4) === 'fail';
  }
  function fmtBulkhashLastRun(lr) {
    if (!lr || !lr.at) return 'Never run.';
    var failed = bulkhashOutcomeFailed(lr.outcome);
    var badge = failed ? '<span class="badge badge-fail">fail</span>'
                       : '<span class="badge badge-ok">ok</span>';
    var counts = lr.matched == null ? ''
      : (' · ' + lr.matched + ' matched, ' + lr.mismatched + ' mismatched, ' +
         lr.not_in_feed + ' not in feed');
    var detail = failed && String(lr.outcome).indexOf(':') > -1
      ? (' · ' + esc(String(lr.outcome).slice(String(lr.outcome).indexOf(':') + 1).trim())) : '';
    return esc(fmtDate(lr.at)) + ' · ' + esc(lr.source || 'unknown') + ' ' + badge + counts + detail;
  }
  // Pure DOM write, factored out so a caller already holding a freshly
  // fetched payload (the wizard's own showWizardStep, fix wave below) can
  // populate these fields without a second, redundant GET to the same
  // endpoint refreshImageVerificationSettings already just made.
  function renderIvStatusFields(iv) {
    document.getElementById('iv-mode').value = iv.mode || 'off';
    document.getElementById('iv-hour').value = String(iv.hour_utc == null ? 0 : iv.hour_utc);
    document.getElementById('iv-last-run').innerHTML = fmtBulkhashLastRun(iv.last_run);
  }
  async function refreshImageVerificationSettings() {
    // Setup pane's never-render-stale-as-healthy pattern (setupShowUnknown):
    // a failed GET must not silently leave whatever was already in
    // #iv-last-run (the static "Never run." markup on first load, or a
    // stale prior successful render) standing in as if it were current.
    var lastRun = document.getElementById('iv-last-run');
    var r;
    try {
      r = await fetch('/api/v1/settings/image-verification');
    } catch (e) {
      lastRun.textContent = 'Could not load status.';
      return;
    }
    if (!r.ok) { lastRun.textContent = 'Could not load status.'; return; }
    var iv = await r.json();
    renderIvStatusFields(iv);
  }
  // Hour select is built once here (00:00-23:00 UTC) rather than spelled out
  // as 24 <option> elements in index.html.
  (function () {
    var sel = document.getElementById('iv-hour');
    if (!sel) return;
    var opts = [];
    for (var h = 0; h < 24; h++) {
      opts.push('<option value="' + h + '">' + (h < 10 ? '0' : '') + h + ':00</option>');
    }
    sel.innerHTML = opts.join('');
  })();
  document.getElementById('iv-schedule-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('iv-schedule-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var mode = document.getElementById('iv-mode').value;
    var hour = parseInt(document.getElementById('iv-hour').value, 10);
    var r = await settingsWrite('/api/v1/settings/image-verification', { mode: mode, hour_utc: hour }, msg);
    if (!r) return;
    msg.textContent = 'Schedule saved.'; msg.classList.add('ok');
    refreshImageVerificationSettings();
  });
  document.getElementById('iv-refresh').addEventListener('click', async function () {
    var btn = this;
    var msg = document.getElementById('iv-refresh-msg'); msg.textContent = ''; msg.classList.remove('ok');
    btn.disabled = true;
    try {
      var r = await settingsWrite('/api/v1/image-verification/refresh', {}, msg, null, [409]);
      if (!r) return;
      if (r.status === 409) {
        msg.textContent = 'A refresh is already in progress.';
      } else if (r.ok) {
        var body = await settingsResult(r, msg, function (result) {
          return ['matched', 'mismatched', 'not_in_feed'].every(function (key) {
            return Number.isInteger(result[key]) && result[key] >= 0;
          });
        });
        if (!body) return;
        msg.textContent = 'Refresh complete: ' + body.matched + ' matched, ' +
          body.mismatched + ' mismatched, ' + body.not_in_feed + ' not in feed.';
        msg.classList.add('ok');
      }
    } finally {
      btn.disabled = false;
      refreshImageVerificationSettings();
      refreshImages().catch(function () { });
      // Also refreshes imageQuarantined (the picker's block list) -- without
      // this it lagged the run by up to one periodic devices-view poll
      // interval, during which a freshly-quarantined image stayed pickable.
      refreshDevices().catch(function () { });
    }
  });
  // Offline upload: a raw-body POST of the tar bytes (not multipart, not
  // form-encoded -- see Task 4's endpoint contract), streamed via XHR the
  // same way the image-upload PUT route sends a raw File body. Reuses the
  // TLS pane's wireDropzone for the drag-drop mechanics; unlike the TLS
  // dropzones (which read the file as text into a textarea) this one sends
  // the file's raw bytes straight to the server.
  var ivOfflineBusy = false;
  function uploadOfflineTar(file) {
    if (!file || ivOfflineBusy) return;
    ivOfflineBusy = true;
    var msg = document.getElementById('iv-offline-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var prog = document.getElementById('iv-offline-progress');
    var bar = document.getElementById('iv-offline-bar');
    prog.hidden = false; bar.style.width = '0%'; prog.setAttribute('aria-valuenow', '0');
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/api/v1/image-verification/offline');
    xhr.setRequestHeader('X-CSRF-Token', info.csrf);
    xhr.upload.onprogress = function (e) {
      if (!e.lengthComputable) return;
      var pct = e.loaded / e.total * 100;
      bar.style.width = pct + '%';
      prog.setAttribute('aria-valuenow', String(Math.round(pct)));
    };
    function finish(text, ok) {
      ivOfflineBusy = false;
      prog.hidden = true;
      msg.textContent = text;
      if (ok) msg.classList.add('ok');
      refreshImageVerificationSettings();
      refreshImages().catch(function () { });
      // See the Refresh now handler's comment: keeps imageQuarantined (the
      // picker's block list) from lagging this run by a poll interval.
      refreshDevices().catch(function () { });
    }
    xhr.onload = function () {
      var body = {};
      try { body = JSON.parse(xhr.responseText); } catch (e) { }
      if (xhr.status === 409) {
        finish('A refresh is already in progress.', false);
      } else if (xhr.status === 200) {
        if (!body || !['matched', 'mismatched', 'not_in_feed'].every(function (key) {
          return Number.isInteger(body[key]) && body[key] >= 0;
        })) {
          finish('Response unavailable. The check may have completed; refresh its status before retrying.', false);
          return;
        }
        finish('Offline check complete: ' + body.matched + ' matched, ' +
          body.mismatched + ' mismatched, ' + body.not_in_feed + ' not in feed.', true);
      } else {
        finish('Offline check failed: ' + (body.detail || body.error || ('status ' + xhr.status)), false);
      }
    };
    xhr.onerror = function () { finish('Response unavailable. The check may have started; refresh its status before retrying.', false); };
    xhr.send(file);
  }
  wireDropzone(document.getElementById('iv-offline-dropzone'), document.getElementById('iv-offline-dropzone-input'),
    function (files) { uploadOfflineTar(files[0]); });
  document.getElementById('pw-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('pw-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var cur = document.getElementById('pw-cur').value;
    var nw = document.getElementById('pw-new').value;
    var cf = document.getElementById('pw-confirm').value;
    if (nw.length < 8) { msg.textContent = 'New password must be at least 8 characters.'; return; }
    if (nw !== cf) { msg.textContent = 'Passwords do not match.'; return; }
    var r = await settingsWrite('/api/v1/settings/password', { current: cur, new: nw, confirm: cf }, msg);
    if (!r) return;
    document.getElementById('pw-form').reset();
    msg.textContent = 'Password changed. Other sessions signed out.'; msg.classList.add('ok');
    refreshSettings();
  });
  document.getElementById('revoke-others').addEventListener('click', async function () {
    var m = document.getElementById('revoke-msg'); m.textContent = '';
    var r = await settingsWrite('/api/v1/settings/sessions/revoke-others', {}, m);
    if (!r) return;
    var result = await settingsResult(r, m, function (body) { return Number.isInteger(body.revoked) && body.revoked >= 0; });
    if (!result) return;
    m.textContent = 'Signed out ' + result.revoked + ' other session(s).';
    refreshSettings();
  });
  // ---- Shared settings forms: one markup source, mounted where it is needed
  // The telemetry form lives in a <template> in the settings pane and is
  // cloned into whichever surface is showing -- Settings, or a step of the
  // first-run wizard. Cloning rather than duplicating the markup keeps a
  // single source of truth, and only ever ONE clone is mounted, so the ids
  // inside stay unique. Handlers bind per mount, which is why they live in
  // wire*Form() rather than running once at startup.
  var FORM_MOUNTS = {
    td: { tpl: 'tpl-td-form', wire: function () { wireTelemetryForm(); } }
  };
  var formMountedAt = { td: null };

  function mountSettingsForm(which, hostId) {
    var spec = FORM_MOUNTS[which];
    var host = document.getElementById(hostId);
    var tpl = document.getElementById(spec.tpl);
    if (!host || !tpl) return false;
    if (formMountedAt[which] === hostId && host.firstChild) return true;
    // tear the previous clone down first -- two live clones would duplicate ids
    if (formMountedAt[which] && formMountedAt[which] !== hostId) {
      var prev = document.getElementById(formMountedAt[which]);
      if (prev) prev.innerHTML = '';
    }
    host.innerHTML = '';
    host.appendChild(tpl.content.cloneNode(true));
    formMountedAt[which] = hostId;
    spec.wire();
    return true;
  }

  // The Image verification content (schedule form, Refresh now, offline
  // import) is relocated the same way -- Settings and the wizard's step 3
  // share one implementation -- but by MOVING the live nodes rather than
  // cloning a <template>: unlike wireTelemetryForm above, its handlers
  // (the schedule-form submit listener, the iv-refresh click
  // handler, wireDropzone on the offline dropzone, the once-only hour-select
  // IIFE) are bound ONCE at load, not re-wired per mount. Moving the same
  // DOM node keeps every listener intact and needs no rewire step, and since
  // there is only ever the one instance, its ids can never duplicate.
  var ivMountedAt = 'settings-pane-bulkhash';
  function mountImageVerification(hostId) {
    if (ivMountedAt === hostId) return;
    var host = document.getElementById(hostId);
    var content = document.getElementById('iv-content');
    if (!host || !content) return;
    host.appendChild(content);
    ivMountedAt = hostId;
  }


  // ---- Settings: certificate / trust store / telemetry destination ----

  function settingsUnknown(msg) {
    msg.dataset.uncertain = 'true';
    msg.textContent = 'Response unavailable. Settings may have changed; reload to check before retrying.';
  }
  async function settingsResult(response, msg, validate) {
    try {
      var result = await response.json();
      if (!result || typeof result !== 'object' || Array.isArray(result) || !validate(result)) throw new Error('Invalid response');
      return result;
    } catch (e) { settingsUnknown(msg); return null; }
  }
  async function settingsWrite(url, body, msg, method, acceptedStatuses) {
    // Network loss can happen after a write commits. Never imply rollback or
    // silently retry, and tolerate non-JSON proxy errors without losing feedback.
    delete msg.dataset.uncertain;
    try {
      var response = method === 'DELETE'
        ? await fetch(url, { method: 'DELETE', headers: csrfHdr() })
        : await jpost(url, body);
      if (!response.ok && !(acceptedStatuses || []).includes(response.status)) {
        var problem = await response.json().catch(function () { return {}; });
        msg.textContent = (problem && (problem.detail || problem.error)) || ('Request failed (' + response.status + ').');
        return null;
      }
      return response;
    } catch (e) {
      settingsUnknown(msg);
      return null;
    }
  }

  // Drag-and-drop onto the TLS pane (Feature 2). Client-side only: a
  // FileReader read plus content sniffing, then the existing textareas /
  // endpoints do the rest — no new backend surface. Recognition is by PEM
  // block content, never filename/extension, since operators name these
  // files all sorts of things.
  var PEM_PRIVATE_KEY_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----/;
  // Mirrors gui_tls.key_is_encrypted: PKCS#8 and legacy PEM encodings. An
  // encrypted key reveals the passphrase field; the server decrypts at
  // import and stores the key age-encrypted at rest.
  function keyLooksEncrypted(text) {
    return text.indexOf('ENCRYPTED PRIVATE KEY') > -1
        || text.indexOf('Proc-Type: 4,ENCRYPTED') > -1;
  }
  function syncPassphraseRow() {
    var t = document.getElementById('cert-key').value;
    document.getElementById('cert-passphrase-row').hidden = !keyLooksEncrypted(t);
    if (keyLooksEncrypted(t)) document.querySelector('#cert-form details').open = true;
  }
  document.getElementById('cert-key').addEventListener('input', syncPassphraseRow);
  var PEM_CERTIFICATE_RE = /-----BEGIN CERTIFICATE-----/;
  function readFileAsText(file) {
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () { resolve(String(reader.result || '')); };
      reader.onerror = function () { reject(reader.error || new Error('read failed')); };
      reader.readAsText(file);
    });
  }
  // Wires a focusable drop-zone div to: click/Enter/Space -> hidden file
  // input; dragover/dragleave -> 'drag' class for the dashed-border hover
  // state; and a drop/file-pick callback receiving a FileList. Shared by
  // both TLS drop zones below.
  function wireDropzone(zone, input, onFiles) {
    zone.addEventListener('click', function () { input.click(); });
    zone.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ' || e.key === 'Spacebar') {
        e.preventDefault();
        input.click();
      }
    });
    ['dragenter', 'dragover'].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add('drag'); });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      zone.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.remove('drag'); });
    });
    zone.addEventListener('drop', function (e) {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) onFiles(e.dataTransfer.files);
    });
    input.addEventListener('change', function (e) {
      if (e.target.files && e.target.files.length) onFiles(e.target.files);
      input.value = '';   // allow re-dropping/re-picking the same file
    });
  }
  wireDropzone(document.getElementById('cert-dropzone'), document.getElementById('cert-dropzone-input'),
    async function (files) {
      var msg = document.getElementById('cert-msg'); msg.textContent = ''; msg.classList.remove('ok');
      var recognized = [], errors = [];
      for (var i = 0; i < files.length; i++) {
        var file = files[i];
        var text;
        try { text = await readFileAsText(file); } catch (err) { errors.push(file.name + ': could not read file'); continue; }
        var hasKey = PEM_PRIVATE_KEY_RE.test(text);
        var hasCert = PEM_CERTIFICATE_RE.test(text);
        if (!hasKey && !hasCert) { errors.push(file.name + ': no PEM block recognized'); continue; }
        var what = [];
        if (hasCert) { document.getElementById('cert-pem').value = text; what.push('certificate'); }
        if (hasKey) {
          document.getElementById('cert-key').value = text;
          what.push(keyLooksEncrypted(text)
            ? 'private key (passphrase-protected — enter it below)'
            : 'private key');
          syncPassphraseRow();
        }
        recognized.push(file.name + ': ' + what.join(' + ') + ' recognized');
      }
      msg.textContent = recognized.concat(errors).join('; ') || 'No files recognized.';
      if (recognized.length && !errors.length) msg.classList.add('ok');
      // Filled the textareas only — the existing Upload button still owns
      // the actual /api/v1/settings/gui-cert submit.
    });
  document.getElementById('cert-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('cert-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var cert = document.getElementById('cert-pem').value.trim();
    var key = document.getElementById('cert-key').value.trim();
    if (cert.indexOf('BEGIN CERTIFICATE') < 0) {
      msg.textContent = 'Certificate PEM is required (-----BEGIN CERTIFICATE-----).'; return;
    }
    if (key.indexOf('PRIVATE KEY') < 0) {
      msg.textContent = 'Private key PEM is required (-----BEGIN ... PRIVATE KEY-----).'; return;
    }
    var body = { cert_pem: cert, key_pem: key };
    if (keyLooksEncrypted(key)) {
      var pw = document.getElementById('cert-passphrase').value;
      if (!pw) {
        document.getElementById('cert-passphrase-row').hidden = false;
        document.querySelector('#cert-form details').open = true;
        msg.textContent = 'This private key is passphrase-protected — enter its passphrase.';
        return;
      }
      body.key_passphrase = pw;
    }
    var r = await settingsWrite('/api/v1/settings/gui-cert', body, msg);
    if (!r) return;
    var certRes = await settingsResult(r, msg, function (body) { return typeof body.applied === 'boolean'; });
    if (!certRes) return;
    document.getElementById('cert-form').reset();   // never leave the key in the DOM
    syncPassphraseRow();
    msg.textContent = certRes.applied === false
      ? 'Certificate ' + (certRes.note || 'saved; takes effect at the next restart') + '.'
      : 'Certificate replaced. New connections use it now; reload to see it on this one.';
    msg.classList.add('ok');
    refreshSettings();
  });
  document.getElementById('cert-revert').addEventListener('click', async function () {
    var msg = document.getElementById('cert-msg'); msg.textContent = ''; msg.classList.remove('ok');
    if (!confirm('Use the default Console certificate?\n\n' +
        'Deletes the uploaded certificate and key. New connections use the default; ' +
        'open sessions continue.')) return;
    var r = await settingsWrite('/api/v1/settings/gui-cert', null, msg, 'DELETE');
    if (!r) return;
    var certRes = await settingsResult(r, msg, function (body) { return typeof body.applied === 'boolean'; });
    if (!certRes) return;
    msg.textContent = certRes.applied === false
      ? 'Certificate ' + (certRes.note || 'saved; takes effect at the next restart') + '.'
      : 'Reverted to the deployment default certificate.';
    msg.classList.add('ok');
    refreshSettings();
  });
  document.getElementById('trust-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('trust-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var pem = document.getElementById('trust-pem').value.trim();
    if (pem.indexOf('BEGIN CERTIFICATE') < 0) {
      msg.textContent = 'Paste at least one PEM certificate block.'; return;
    }
    var r = await settingsWrite('/api/v1/settings/trust', { pem: pem }, msg);
    if (!r) return;
    document.getElementById('trust-form').reset();
    msg.textContent = 'CA installed.'; msg.classList.add('ok');
    refreshSettings();
  });
  wireDropzone(document.getElementById('trust-dropzone'), document.getElementById('trust-dropzone-input'),
    async function (files) {
      var msg = document.getElementById('trust-msg'); msg.textContent = ''; msg.classList.remove('ok');
      var ok = 0, fail = 0, skipped = 0, uncertain = false;
      for (var i = 0; i < files.length; i++) {
        var file = files[i];
        var text;
        try { text = await readFileAsText(file); } catch (err) { fail++; continue; }
        if (!PEM_CERTIFICATE_RE.test(text)) { skipped++; continue; }
        var r = await settingsWrite('/api/v1/settings/trust', { pem: text }, msg);
        if (r) ok++; else fail++;
        uncertain = uncertain || msg.dataset.uncertain === 'true';
      }
      var parts = [];
      if (ok) parts.push(ok + ' added');
      if (fail) parts.push(fail + ' failed');
      if (skipped) parts.push(skipped + ' skipped (no certificate PEM found)');
      msg.textContent = parts.length ? (parts.join(', ') + '.') : 'No files processed.';
      if (uncertain) msg.textContent += ' Some results are unknown; reload to check installed CAs before retrying.';
      if (ok && !fail && !skipped) msg.classList.add('ok');
      refreshSettings();
    });
  document.getElementById('ca-source').addEventListener('change', function () {
    document.getElementById('ca-url').hidden = this.value !== 'custom';
  });
  document.getElementById('ca-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('ca-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var source = document.getElementById('ca-source').value;
    // cisco -> null (server default, existing semantics); mozilla -> the
    // curated curl.se URL; custom -> whatever is typed in the (now visible)
    // free-text input. Either way this still posts to the one existing
    // ca-trust endpoint — the preset is purely a client-side URL picker.
    var url = source === 'cisco' ? '' :
      source === 'mozilla' ? CA_MOZILLA_URL :
      document.getElementById('ca-url').value.trim();
    var auto = document.getElementById('ca-auto').checked;
    if (url && url.indexOf('https://') !== 0) { msg.textContent = 'Bundle URL must be https://'; return; }
    if (source === 'custom' && !url) { msg.textContent = 'Enter a custom HTTPS bundle URL.'; return; }
    var r = await settingsWrite('/api/v1/settings/ca-trust', { url: url || null, auto: auto }, msg);
    if (!r) return;
    msg.textContent = 'CA download settings saved.'; msg.classList.add('ok');
    refreshSettings();
  });
  // "Download now" starts the server-side job and polls it, like image publish
  var caPollTimer = null;
  var caPollGen = 0;
  function pollCaRefresh(jobId) {
    var gen = ++caPollGen;
    var msg = document.getElementById('ca-msg');
    if (caPollTimer) { clearTimeout(caPollTimer); caPollTimer = null; }
    function next() { caPollTimer = setTimeout(poll, 1000); }
    async function poll() {
      try {
      var r = await fetch('/api/v1/settings/ca-trust/refresh/' + encodeURIComponent(jobId));
      if (gen !== caPollGen) return;
      if (!r.ok) { msg.textContent = 'Download status unavailable (' + r.status + '); retrying…'; next(); return; }
      var j = await r.json();
      if (gen !== caPollGen) return;
      if (j.state === 'done') {
        caPollTimer = null;
        msg.textContent = 'Downloaded ' + (j.certs == null ? '?' : j.certs) +
          ' certificate(s).'; msg.classList.add('ok');
        refreshSettings().catch(function () {});
      } else if (j.state === 'failed') {
        caPollTimer = null;
        msg.textContent = 'Download failed: ' + (j.detail || 'unknown error');
      } else {
        msg.textContent = 'Downloading…';
        next();
      }
      } catch (e) { msg.textContent = 'Download status unavailable; retrying…'; next(); }
    }
    poll();
  }
  document.getElementById('ca-refresh').addEventListener('click', async function () {
    var msg = document.getElementById('ca-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var r = await settingsWrite('/api/v1/settings/ca-trust/refresh', {}, msg);
    if (!r) return;
    var result = await settingsResult(r, msg, function (body) { return typeof body.job === 'string' && !!body.job; });
    if (!result) return;
    msg.textContent = 'Downloading…';
    pollCaRefresh(result.job);
  });
  function wireTelemetryForm() {
  document.getElementById('td-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('td-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var endpoint = document.getElementById('td-endpoint').value.trim().replace(/\/+$/, '');
    var enabled = document.getElementById('td-enabled').checked;
    if (enabled && !endpoint) { msg.textContent = 'An endpoint is required when export is enabled.'; return; }
    if (endpoint && !(endpoint.indexOf('http://') === 0 || endpoint.indexOf('https://') === 0)) {
      msg.textContent = 'Endpoint must be an http:// or https:// URL.'; return;
    }
    var r = await settingsWrite('/api/v1/settings/telemetry-destination',
                        { endpoint: endpoint || null, enabled: enabled }, msg);
    if (!r) return;
    msg.textContent = 'Telemetry destination saved. The exporter picks it up on the next sample pass.';
    msg.classList.add('ok');
    refreshSettings();
  });
  document.getElementById('td-revert').addEventListener('click', async function () {
    var msg = document.getElementById('td-msg'); msg.textContent = ''; msg.classList.remove('ok');
    if (!confirm('Use the default telemetry destination?\n\n' +
        'Removes the Console override. Telemetry uses the deployment settings from the next sample.')) return;
    var r = await settingsWrite('/api/v1/settings/telemetry-destination', null, msg, 'DELETE');
    if (!r) return;
    msg.textContent = 'Reverted to the deployment default.'; msg.classList.add('ok');
    refreshSettings();
  });
  }


  // ---- Settings: audit export (SCP + age) ----
  document.getElementById('ae-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    var msg = document.getElementById('ae-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var host = document.getElementById('ae-host').value.trim();
    var port = document.getElementById('ae-port').value.trim();
    var user = document.getElementById('ae-user').value.trim();
    var path = document.getElementById('ae-path').value.trim();
    var recipient = document.getElementById('ae-recipient').value.trim();
    var pass = document.getElementById('ae-pass').value;
    if (!host || !user || !path) { msg.textContent = 'Host, username and remote path are required.'; return; }
    if (!/^age1[0-9a-z]+$/.test(recipient)) {
      msg.textContent = 'A valid age recipient (age1…) is required — the export is always encrypted.'; return;
    }
    var portNum = port ? Number(port) : 22;
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      msg.textContent = 'Port must be a number between 1 and 65535.'; return;
    }
    var body = { host: host, port: portNum, user: user, path: path,
                 age_recipient: recipient,
                 auto: document.getElementById('ae-auto').checked };
    if (pass) body.password = pass;    // absent password keeps the stored one
    var r = await settingsWrite('/api/v1/settings/audit-export', body, msg);
    if (!r) return;
    document.getElementById('ae-pass').value = '';   // never leave the password in the DOM
    msg.textContent = 'Audit export settings saved.'; msg.classList.add('ok');
    refreshSettings();
  });
  // "Export now" starts the server-side job and polls it, like the CA refresh
  var aePollTimer = null;
  var aePollGen = 0;
  function pollAuditExport(jobId) {
    var gen = ++aePollGen;
    var msg = document.getElementById('ae-msg');
    if (aePollTimer) { clearTimeout(aePollTimer); aePollTimer = null; }
    function next() { aePollTimer = setTimeout(poll, 1000); }
    async function poll() {
      try {
      var r = await fetch('/api/v1/settings/audit-export/run/' + encodeURIComponent(jobId));
      if (gen !== aePollGen) return;
      if (!r.ok) { msg.textContent = 'Export status unavailable (' + r.status + '); retrying…'; next(); return; }
      var j = await r.json();
      if (gen !== aePollGen) return;
      if (j.state === 'done') {
        aePollTimer = null;
        msg.textContent = 'Exported: ' + (j.detail || 'ok'); msg.classList.add('ok');
        refreshSettings().catch(function () {});
      } else if (j.state === 'error') {
        aePollTimer = null;
        msg.textContent = 'Export failed: ' + (j.detail || 'unknown error');
        refreshSettings().catch(function () {});
      } else {
        msg.textContent = 'Exporting…';
        next();
      }
      } catch (e) { msg.textContent = 'Export status unavailable; retrying…'; next(); }
    }
    poll();
  }
  document.getElementById('ae-run').addEventListener('click', async function () {
    var msg = document.getElementById('ae-msg'); msg.textContent = ''; msg.classList.remove('ok');
    var r = await settingsWrite('/api/v1/settings/audit-export/run', {}, msg);
    if (!r) return;
    var result = await settingsResult(r, msg, function (body) { return typeof body.job_id === 'string' && !!body.job_id; });
    if (!result) return;
    msg.textContent = 'Exporting…';
    pollAuditExport(result.job_id);
  });
  document.getElementById('ae-clear').addEventListener('click', async function () {
    var msg = document.getElementById('ae-msg'); msg.textContent = ''; msg.classList.remove('ok');
    if (!confirm('Stop daily audit exports?\n\n' +
        'Deletes the export settings and saved password. ' +
        'Keeps audit events on this server and files already exported.')) return;
    var r = await settingsWrite('/api/v1/settings/audit-export', null, msg, 'DELETE');
    if (!r) return;
    msg.textContent = 'Audit export configuration cleared.'; msg.classList.add('ok');
    refreshSettings();
  });

  // ---- Certificate lifecycle ----
  var certificateRequest = null, certificateBusy = false, certificateRead = 0;
  function certificateControls() {
    document.getElementById('certificate-request').disabled = certificateBusy;
    document.getElementById('certificate-approved').disabled = certificateBusy || !certificateRequest;
    document.getElementById('certificate-renew').disabled = certificateBusy || !certificateRequest;
  }
  async function refreshCertificates() {
    var generation = ++certificateRead;
    var rows = document.getElementById('certificate-rows');
    var observed = document.getElementById('certificate-observed');
    rows.textContent = '';
    observed.textContent = 'Checking certificate files…';
    try {
      var r = await fetch('/api/v1/settings/certificates');
      if (!r.ok) throw new Error('Certificate inventory unavailable. Retry after checking the server connection.');
      var data = await r.json();
      if (generation !== certificateRead) return;
      if (!Array.isArray(data.items)) throw new Error('Certificate inventory is incomplete.');
      rows.innerHTML = data.items.map(function (item) {
        function date(value) { return value == null ? 'Unknown' : fmtDate(value); }
        return '<tr><td>' + esc(item.label) + '<br><small class="machine">' +
          esc(item.fingerprint_sha256 || 'Fingerprint unavailable') + '</small></td><td>' +
          esc(item.state.replaceAll('-', ' ')) + '</td><td>' + esc(item.kind === 'public-key' ? 'Policy / custody review' : date(item.renew_at)) + '</td><td>' +
          esc(item.kind === 'public-key' ? 'No expiry' : date(item.expires_at)) + '</td><td>' + esc(item.impact) +
          (item.refuse_at == null ? '' : '<br>Signing stops: ' + esc(date(item.refuse_at))) + '</td></tr>';
      }).join('');
      observed.textContent = 'Observed ' + fmtDate(data.observed_at) +
        '. Signing custody: ' + (data.custody ? data.custody.state : 'unknown; status evidence unavailable') + '.';
    } catch (error) {
      if (generation !== certificateRead) return;
      rows.textContent = '';
      observed.textContent = error.message || 'Certificate inventory unavailable.';
    }
  }
  document.getElementById('certificate-refresh').addEventListener('click', refreshCertificates);
  document.getElementById('certificate-request').addEventListener('click', async function () {
    if (certificateBusy) return;
    certificateBusy = true; certificateRequest = null; certificateControls();
    var result = document.getElementById('certificate-renew-result');
    document.getElementById('certificate-approved').value = '';
    result.textContent = 'Preparing public renewal request…';
    try {
      var r = await fetch('/api/v1/settings/certificates/instruction/request', {
        method: 'POST', headers: csrfHdr({'Content-Type': 'application/json'}), body: '{}'
      });
      var data = await r.json();
      if (!r.ok) throw new Error(data.error || data.detail || 'Could not prepare renewal.');
      if (typeof data.public_key !== 'string' || !data.public_key.startsWith('ssh-ed25519 ') ||
          !/^[0-9a-f]{64}$/.test(data.public_key_sha256) || !/^[0-9a-f]{64}$/.test(data.certificate_sha256)) {
        throw new Error('Public renewal request is incomplete.');
      }
      certificateRequest = data;
      var url = URL.createObjectURL(new Blob([data.public_key], {type: 'text/plain'}));
      var link = document.createElement('a');
      link.href = url; link.download = 'iris-online.pub'; link.click();
      setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      result.textContent = 'Send iris-online.pub to your offline custodian. Return the approved certificate, never the private root key. If you reopen this page, prepare the request again before importing.';
    } catch (error) { certificateRequest = null; result.textContent = error.message || 'Could not prepare renewal.'; }
    finally { certificateBusy = false; certificateControls(); }
  });
  document.getElementById('certificate-renew-form').addEventListener('submit', async function (event) {
    event.preventDefault();
    if (certificateBusy || !certificateRequest) return;
    var file = document.getElementById('certificate-approved').files[0];
    var result = document.getElementById('certificate-renew-result');
    if (!file || file.size > 16384) { result.textContent = 'Choose a public OpenSSH certificate smaller than 16 KiB.'; return; }
    certificateBusy = true; certificateControls();
    result.textContent = 'Validating and applying the approved certificate…';
    try {
      var certificate = await file.text();
      if (!certificate.startsWith('ssh-ed25519-cert-v01@openssh.com ') || certificate.includes('PRIVATE KEY')) {
        throw new Error('Choose the public certificate returned by your custodian, not a private key.');
      }
      var r = await fetch('/api/v1/settings/certificates/instruction/renew', {
        method: 'POST', headers: csrfHdr({'Content-Type': 'application/json'}),
        body: JSON.stringify({certificate: certificate,
          public_key_sha256: certificateRequest.public_key_sha256,
          certificate_sha256: certificateRequest.certificate_sha256})
      });
      var data = await r.json();
      if (!r.ok || !data.applied) throw new Error(data.error || data.detail || 'Renewal was not confirmed. Refresh before retrying.');
      result.textContent = 'Renewal applied. Expires ' + fmtDate(data.expires_at) +
        '; signing stops ' + fmtDate(data.refuse_at) + '. The signing key and device trust are unchanged.' +
        (data.status_refreshed ? '' : ' Custody status refresh is pending; check again shortly.');
      certificateRequest = null;
      document.getElementById('certificate-approved').value = '';
      await refreshCertificates();
    } catch (error) { result.textContent = error.message || 'Renewal was not confirmed. Refresh before retrying.'; }
    finally { certificateBusy = false; certificateControls(); }
  });
  // ---- End certificate lifecycle ----

  // ---- Journalled online signer rotation ----
  function maintenanceRequestId() {
    var bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
    var hex = Array.from(bytes).map(function (byte) { return byte.toString(16).padStart(2, '0'); }).join('');
    return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-');
  }
  var rotationStatus = null, rotationBusy = false, rotationNonce = null, rotationRead = 0;
  var rotationUrl = '/api/v1/settings/certificates/instruction/rotation';
  function validRotationStatus(data) {
    return data && ['idle', 'awaiting-approval', 'committing', 'retirement-pending', 'retiring', 'completed', 'cancelled'].includes(data.state) &&
      Array.isArray(data.root_ids) && data.root_ids.every(function (id) { return typeof id === 'string'; });
  }
  function renderRotation() {
    var state = rotationStatus ? rotationStatus.state : 'unknown';
    document.getElementById('rotation-state').textContent = 'Rotation: ' + state.replaceAll('-', ' ') +
      (state === 'completed' ? '. Previous key revoked at keylist sequence ' + rotationStatus.retired_keylist_seq + '.' : '.');
    document.getElementById('rotation-previous').textContent = rotationStatus && rotationStatus.previous_sha256 || 'No rotation evidence';
    document.getElementById('rotation-replacement').textContent = rotationStatus && rotationStatus.replacement_sha256 || 'No rotation evidence';
    document.getElementById('rotation-prepare').disabled = rotationBusy || !['idle', 'completed', 'cancelled'].includes(state);
    document.getElementById('rotation-approval').hidden = state !== 'awaiting-approval';
    document.getElementById('rotation-retirement').hidden = !['retirement-pending', 'retiring'].includes(state);
    document.querySelectorAll('#rotation-approval button,#rotation-approval input,#rotation-retirement button,#rotation-retirement input,#rotation-retirement select').forEach(function (el) { el.disabled = rotationBusy || !rotationStatus; });
    var root = document.getElementById('rotation-root'), selected = root.value;
    root.replaceChildren();
    (rotationStatus && rotationStatus.root_ids || []).forEach(function (id) {
      var option = document.createElement('option'); option.value = id; option.textContent = id; root.appendChild(option);
    });
    if (Array.from(root.options).some(function (option) { return option.value === selected; })) root.value = selected;
  }
  function rotationDownload(name, bytes) {
    var url = URL.createObjectURL(new Blob([bytes], {type: 'application/octet-stream'}));
    var link = document.createElement('a'); link.href = url; link.download = name; link.click();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  async function refreshRotation() {
    if (rotationBusy) return;
    var generation = ++rotationRead;
    rotationStatus = null; renderRotation();
    try {
      var response = await fetch(rotationUrl), data = await response.json();
      if (generation !== rotationRead) return;
      if (!response.ok || !validRotationStatus(data)) throw new Error(data.error || 'Rotation status unavailable. Check custody before retrying.');
      rotationStatus = data; renderRotation();
    } catch (error) {
      if (generation !== rotationRead) return;
      rotationStatus = null; renderRotation();
      document.getElementById('rotation-result').textContent = error.message;
    }
  }
  async function rotateSigner(action) {
    if (rotationBusy || !rotationStatus) return;
    var result = document.getElementById('rotation-result');
    var payload = {action: action, request_id: rotationStatus.request_id};
    try {
      if (action === 'prepare') {
        if (!confirm('Prepare a new online signing key for offline approval? The current signer keeps working until you apply approval.')) return;
        rotationNonce = rotationNonce || maintenanceRequestId(); payload.request_id = rotationNonce;
      } else if (action === 'activate' || action === 'retire') {
        var file = document.getElementById(action === 'activate' ? 'rotation-certificate' : 'rotation-keylist').files[0];
        if (!file || file.size > (action === 'activate' ? 65536 : 131072)) throw new Error('Choose the bounded public approval file returned by your custodian.');
        var raw = await file.text();
        if (raw.includes('PRIVATE KEY') || !raw.startsWith(action === 'activate' ? 'ssh-ed25519-cert-v01@openssh.com ' : 'IRIS-KEYLIST/1\n')) throw new Error('Upload the public approval, never a private key.');
        if (!confirm(action === 'activate' ? 'Switch to the approved replacement signer? This cannot be cancelled afterward. Device roots and counters stay unchanged.' : 'Publish the approved revocation of the previous signer? Devices must fetch current instructions and the new keylist. Verify fleet acceptance afterward.')) return;
        payload.confirm = true;
        if (action === 'activate') payload.certificate = raw;
        else payload.artifact = btoa(raw);
      } else if (action === 'retirement-request') payload.root_id = document.getElementById('rotation-root').value;
      else if (action === 'cancel' && !confirm('Discard the pending replacement? The current signer will be kept.')) return;
      rotationBusy = true; ++rotationRead; renderRotation(); result.textContent = 'Validating rotation request…';
      var response = await fetch(rotationUrl, {method: 'POST', headers: csrfHdr({'Content-Type': 'application/json'}), body: JSON.stringify(payload)});
      var data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Rotation outcome unknown. Refresh and retry the same request.');
      if (action === 'retirement-request') {
        rotationDownload('keylist.payload', Uint8Array.from(atob(data.payload), function (c) { return c.charCodeAt(0); }));
        result.textContent = 'Retirement request downloaded. Obtain approval from ' + data.root_id + ' on its offline station.';
      } else {
        if (!validRotationStatus(data)) throw new Error('Rotation outcome unknown. Refresh before continuing.');
        rotationStatus = data; rotationNonce = null;
        result.textContent = action === 'activate' ? 'Replacement signer active. Complete offline retirement approval next.' :
          action === 'retire' ? 'Retirement approval validated and published.' :
          action === 'cancel' ? 'Pending replacement cancelled; active signer unchanged.' : 'Replacement prepared. Download its public key for offline approval.';
      }
    } catch (error) { result.textContent = error.message || 'Rotation outcome unknown. Refresh and retry the same request.'; }
    finally { rotationBusy = false; renderRotation(); }
  }
  document.getElementById('rotation-refresh').addEventListener('click', refreshRotation);
  document.getElementById('rotation-download').addEventListener('click', function () {
    if (rotationStatus && rotationStatus.public_key) rotationDownload('iris-replacement.pub', rotationStatus.public_key);
  });
  ['prepare', 'activate', 'cancel', 'retirement-request', 'retire'].forEach(function (action) {
    document.getElementById('rotation-' + action).addEventListener('click', function () { rotateSigner(action); });
  });
  // ---- End signer rotation ----

  // ---- Browser TLS public request and approval ----
  var browserTls = null, browserTlsBusy = false, browserTlsRead = 0, browserTlsPending = null;
  var browserTlsUrl = '/api/v1/settings/certificates/browser/rotation';
  function browserTlsField(name) { return document.getElementById('browser-tls-' + name); }
  function validBrowserTls(data) {
    return data && ['idle', 'awaiting-approval', 'approved', 'committing', 'published', 'cancelled'].includes(data.state) &&
      Array.isArray(data.names) && (data.request_id === null || typeof data.request_id === 'string');
  }
  function renderBrowserTls() {
    var state = browserTls ? browserTls.state : 'unknown';
    browserTlsField('state').textContent = 'Browser certificate: ' + state.replaceAll('-', ' ') + '.';
    browserTlsField('identity').textContent = browserTls && browserTls.fingerprint_sha256 ?
      'Replacement SHA256: ' + browserTls.fingerprint_sha256 : '';
    browserTlsField('prepare').disabled = browserTlsBusy || !['idle', 'published', 'cancelled'].includes(state);
    browserTlsField('csr').disabled = browserTlsBusy || !browserTls || !browserTls.csr;
    browserTlsField('certificate').disabled = browserTlsBusy || !browserTls || !browserTls.certificate;
    browserTlsField('cancel').disabled = browserTlsBusy || !['awaiting-approval', 'approved'].includes(state);
    browserTlsField('apply').disabled = browserTlsBusy || !['approved', 'committing', 'published'].includes(state);
    browserTlsField('apply').textContent = state === 'committing' ? 'Recover approved publication' : state === 'published' ? 'Retry Console certificate reload' : 'Apply approved certificate';
    browserTlsField('approve-form').hidden = !['awaiting-approval', 'approved'].includes(state) || !browserTls || browserTls.mode !== 'ca';
    ['approve', 'approved', 'names', 'mode'].forEach(function (name) { browserTlsField(name).disabled = browserTlsBusy || !browserTls; });
  }
  async function refreshBrowserTls() {
    if (browserTlsBusy) return;
    var generation = ++browserTlsRead;
    browserTls = null; renderBrowserTls();
    try {
      var response = await fetch(browserTlsUrl), data = await response.json();
      if (generation !== browserTlsRead) return;
      if (!response.ok || !validBrowserTls(data)) throw new Error(data.error || 'Certificate request unavailable.');
      browserTls = data; renderBrowserTls();
      browserTlsField('result').textContent = 'Request status refreshed. Publication and browser trust are separate checks.';
    } catch (error) { if (generation === browserTlsRead) browserTlsField('result').textContent = error.message; }
  }
  async function browserTlsAction(action) {
    if (browserTlsBusy || !browserTls) return;
    var result = browserTlsField('result');
    var payload = {action: action, request_id: browserTls.request_id};
    try {
      if (action === 'prepare') {
        var names = browserTlsField('names').value.split(',').map(function (name) { return name.trim(); });
        var mode = browserTlsField('mode').value;
        if (!confirm(mode === 'self-signed' ? 'Generate a replacement key and self-signed certificate? Browser trust must be updated before applying it.' : 'Generate an encrypted replacement key and a public certificate request for CA approval?')) return;
        var parameters = JSON.stringify({names: names, mode: mode});
        if (!browserTlsPending || browserTlsPending.parameters !== parameters) browserTlsPending = {parameters: parameters, id: maintenanceRequestId()};
        payload = {action: action, request_id: browserTlsPending.id, names: names, mode: mode};
      } else if (action === 'approve') {
        var file = browserTlsField('approved').files[0];
        if (!file || file.size > 65536) throw new Error('Choose a public PEM certificate chain smaller than 64 KiB.');
        payload.certificate = await file.text();
        if (payload.certificate.includes('PRIVATE KEY') || !payload.certificate.includes('BEGIN CERTIFICATE')) throw new Error('Upload the public certificate chain, never a private key.');
      } else if (action === 'apply') {
        if (!confirm('Have you approved browser trust for this certificate and verified its names? Apply it to this Console now. Existing browser connections may need a reload; other Console instances must be updated and verified separately.')) return;
        payload.confirm = true;
      } else if (action === 'cancel' && !confirm('Discard this replacement request? The active certificate remains unchanged.')) return;
      browserTlsBusy = true; ++browserTlsRead; renderBrowserTls();
      var response = await fetch(browserTlsUrl, {method: 'POST', headers: csrfHdr({'Content-Type': 'application/json'}), body: JSON.stringify(payload)});
      var data = await response.json();
      if (!response.ok || !validBrowserTls(data)) throw new Error(data.error || 'Outcome unknown. Refresh the same request before retrying.');
      browserTls = data; browserTlsPending = null;
      result.textContent = action === 'apply' ? (data.applied ? 'Certificate published and this Console listener reloaded. Verify a new trusted browser connection.' : 'Certificate published; this Console has not confirmed reload. Preserve this request and retry the reload.') :
        action === 'prepare' ? 'Replacement prepared. Download the public request or approved certificate before continuing.' :
        action === 'approve' ? 'Certificate matches the replacement key, requested names and validity window. Review trust before applying.' : 'Replacement cancelled; active certificate unchanged.';
      if (action === 'approve') browserTlsField('approved').value = '';
    } catch (error) { result.textContent = error.message || 'Outcome unknown. Refresh the request before continuing.'; }
    finally { browserTlsBusy = false; renderBrowserTls(); }
  }
  browserTlsField('names').value = location.hostname;
  browserTlsField('refresh').addEventListener('click', refreshBrowserTls);
  ['prepare', 'approve'].forEach(function (action) {
    browserTlsField(action + '-form').addEventListener('submit', function (event) { event.preventDefault(); browserTlsAction(action); });
  });
  ['apply', 'cancel'].forEach(function (action) { browserTlsField(action).addEventListener('click', function () { browserTlsAction(action); }); });
  ['csr', 'certificate'].forEach(function (kind) {
    browserTlsField(kind).addEventListener('click', function () {
      if (browserTls && browserTls[kind]) rotationDownload(kind === 'csr' ? 'iris-console.csr' : 'iris-console.crt', browserTls[kind]);
    });
  });

  // ---- Opt-in key maintenance ----
  var serviceCredentialState = null, serviceCredentialBusy = false, serviceCredentialRead = 0, serviceCredentialPending = null;
  var serviceCredentialUrl = '/api/v1/settings/service-credentials';
  function serviceCredentialField(name) { return document.getElementById('service-credential-' + name); }
  function validServiceCredential(data) {
    return data && Array.isArray(data.items) && data.items.length === 2 && data.items.every(function (item) {
      return ['metrics-token', 'collector-headers'].includes(item.family) &&
        ['deployment-managed', 'awaiting-verification', 'completed', 'reverted'].includes(item.state);
    });
  }
  function renderServiceCredential() {
    var family = serviceCredentialField('family').value;
    var item = serviceCredentialState && serviceCredentialState.items.find(function (row) { return row.family === family; });
    serviceCredentialField('metrics').hidden = family !== 'metrics-token';
    serviceCredentialField('collector').hidden = family !== 'collector-headers';
    serviceCredentialField('state').textContent = item ? item.state.replaceAll('-', ' ') +
      (item.observed_at ? '. Successful use observed ' + new Date(item.observed_at * 1000).toISOString() + '.' : '. No replacement-use evidence recorded.') : 'Credential state unavailable. Refresh before changing credentials.';
    serviceCredentialField('replace').disabled = serviceCredentialBusy || !item || item.state === 'awaiting-verification';
    serviceCredentialField('retire').disabled = serviceCredentialBusy || !item || item.state !== 'awaiting-verification' || !item.observed_at;
    serviceCredentialField('revert').disabled = serviceCredentialBusy || !item || item.state !== 'awaiting-verification';
    document.querySelectorAll('#service-credential-workflow input,#service-credential-workflow select').forEach(function (el) { el.disabled = serviceCredentialBusy; });
  }
  function addServiceHeader() {
    var container = serviceCredentialField('headers');
    if (container.children.length >= 16) return;
    var row = document.createElement('div'); row.className = 'maintenance-form';
    var nameLabel = document.createElement('label'), valueLabel = document.createElement('label');
    nameLabel.textContent = 'Header name'; valueLabel.textContent = 'Secret value';
    var name = document.createElement('input'), value = document.createElement('input'), remove = document.createElement('button');
    name.type = 'text'; name.value = container.children.length ? '' : 'Authorization'; name.dataset.field = 'name';
    value.type = 'password'; value.autocomplete = 'new-password'; value.dataset.field = 'value';
    remove.type = 'button'; remove.className = 'btn ghost'; remove.textContent = 'Remove header';
    remove.addEventListener('click', function () { if (!serviceCredentialBusy) row.remove(); });
    nameLabel.appendChild(name); valueLabel.appendChild(value); row.append(nameLabel, valueLabel, remove); container.appendChild(row);
  }
  async function refreshServiceCredential() {
    if (serviceCredentialBusy) return;
    var generation = ++serviceCredentialRead;
    serviceCredentialState = null; renderServiceCredential();
    try {
      var response = await fetch(serviceCredentialUrl), data = await response.json();
      if (generation !== serviceCredentialRead) return;
      if (!response.ok || !validServiceCredential(data)) throw new Error(data.error || 'Credential state unavailable.');
      serviceCredentialState = data; renderServiceCredential();
    } catch (error) { if (generation === serviceCredentialRead) serviceCredentialField('result').textContent = error.message; }
  }
  async function changeServiceCredential(action) {
    if (!serviceCredentialState || serviceCredentialBusy) return;
    var family = serviceCredentialField('family').value;
    var item = serviceCredentialState.items.find(function (row) { return row.family === family; });
    var payload = {action: action, family: family, request_id: item.request_id, confirm: true};
    try {
      if (action === 'replace') {
        if (family === 'metrics-token') payload.token = serviceCredentialField('token').value;
        else {
          payload.endpoint = serviceCredentialField('endpoint').value;
          payload.headers = Object.create(null);
          serviceCredentialField('headers').querySelectorAll('.maintenance-form').forEach(function (row) {
            var name = row.querySelector('[data-field=name]').value.trim();
            if (!name || Object.keys(payload.headers).some(function (known) { return known.toLowerCase() === name.toLowerCase(); })) throw new Error('Provide distinct authentication header names.');
            payload.headers[name] = row.querySelector('[data-field=value]').value;
          });
        }
        if (!confirm(family === 'metrics-token' ? 'Have you saved the replacement token for every scraper? Apply it while retaining the previous token?' : 'Use these new credentials only at the specified HTTPS collector? Keep the old credential valid there until verification.')) return;
        var parameters = JSON.stringify(payload);
        if (!serviceCredentialPending || serviceCredentialPending.parameters !== parameters) serviceCredentialPending = {parameters: parameters, id: maintenanceRequestId()};
        payload.request_id = serviceCredentialPending.id;
      } else if (!confirm(action === 'revert' ? 'Restore the previous IRIS credential setting? External scraper or collector changes will not be rolled back.' :
        family === 'metrics-token' ? 'Have all scrapers moved to the replacement? At least one successful new-token scrape was observed. Remove the previous token now?' :
        'Have you revoked the previous credential at the collector after moving every sender? Remove the stored previous value from IRIS now?')) return;
      serviceCredentialBusy = true; ++serviceCredentialRead; renderServiceCredential();
      var response = await fetch(serviceCredentialUrl, {method: 'POST', headers: csrfHdr({'Content-Type': 'application/json'}), body: JSON.stringify(payload)});
      var data = await response.json();
      if (!response.ok || !validServiceCredential(data)) throw new Error(data.error || 'Outcome unknown. Refresh before retrying.');
      serviceCredentialState = data; serviceCredentialPending = null;
      serviceCredentialField('token').value = '';
      serviceCredentialField('headers').querySelectorAll('[data-field=value]').forEach(function (field) { field.value = ''; });
      serviceCredentialField('result').textContent = action === 'replace' ? 'Replacement saved in encrypted storage. Update consumers and refresh evidence before finishing.' :
        action === 'revert' ? 'Previous IRIS setting restored. Verify external consumers separately.' :
        family === 'metrics-token' ? 'Previous scrape token retired. Verify every scraper continues working.' :
        'Previous stored collector credentials removed after observed delivery and your retirement confirmation.';
    } catch (error) { serviceCredentialField('result').textContent = error.message; }
    finally { serviceCredentialBusy = false; renderServiceCredential(); }
  }
  serviceCredentialField('family').addEventListener('change', renderServiceCredential);
  serviceCredentialField('refresh').addEventListener('click', refreshServiceCredential);
  serviceCredentialField('add-header').addEventListener('click', addServiceHeader); addServiceHeader();
  serviceCredentialField('generate').addEventListener('click', function () {
    if (!serviceCredentialBusy) serviceCredentialField('token').value = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(function (v) { return v.toString(16).padStart(2, '0'); }).join('');
  });
  serviceCredentialField('download').addEventListener('click', function () {
    var value = serviceCredentialField('token').value;
    if (!/^[A-Za-z0-9._~+/-]{32,256}$/.test(value)) { serviceCredentialField('result').textContent = 'Generate or enter a valid replacement token first.'; return; }
    rotationDownload('iris-metrics-token', value + '\n');
    serviceCredentialField('result').textContent = 'Private credential downloaded. Store it securely and provision it only to authorized scrapers.';
  });
  ['replace', 'retire', 'revert'].forEach(function (action) { serviceCredentialField(action).addEventListener('click', function () { changeServiceCredential(action); }); });

  var deploymentRotation = null, deploymentTrust = null, deploymentBusy = false, deploymentRead = 0, deploymentPending = null;
  var deploymentRotationUrl = '/api/v1/settings/deployment-rotation', deploymentTrustUrl = '/api/v1/settings/trust-rotation';
  function deploymentField(name) { return document.getElementById('deployment-rotation-' + name); }
  function deploymentTrustItem() {
    return deploymentTrust && deploymentTrust.items.find(function (item) { return item.family === deploymentField('family').value; });
  }
  function renderDeploymentRotation() {
    var family = deploymentField('family').value, trust = ['device-tls', 'peer-ca', 'instruction-roots'].includes(family);
    var item = deploymentTrustItem(), state = item ? item.state : 'unavailable';
    var busyJob = deploymentRotation && deploymentRotation.jobs.some(function (job) { return ['running', 'recovery-required'].includes(job.state); });
    var topologyLabels = {'single-docker': 'Docker on one host', 'split-docker': 'Docker on separate hosts', 'kubernetes': 'Kubernetes'};
    deploymentField('worker').textContent = deploymentRotation ?
      (topologyLabels[deploymentRotation.target] ? 'Deployment: ' + topologyLabels[deploymentRotation.target] + '. ' : '') + deploymentRotation.note :
      'Worker state unavailable. Refresh before starting maintenance.';
    deploymentField('state').textContent = trust ? 'Trust request: ' + state.replaceAll('-', ' ') + '. Publication requires stopped writers and confirmed device removal.' :
      family === 'age-identity' ? 'Replace the server encryption identity and retain the independently held recovery recipient. Existing backups keep their original recovery requirements.' :
      family === 'seeder-announce' ? 'Pause normal writers while an isolated tracker and seeder verify the replacement credential against published torrents.' :
      'Replace the internal TLS key and certificate, update Console trust, and verify authenticated connections from every deployed Console.';
    deploymentField('trust').hidden = !trust;
    deploymentField('tls').hidden = family !== 'device-tls';
    deploymentField('roots').hidden = family !== 'instruction-roots';
    deploymentField('approval').hidden = !item || !['awaiting-approval', 'approved'].includes(state) || family === 'peer-ca' || item.mode === 'self-signed';
    deploymentField('keylist-label').hidden = family !== 'instruction-roots';
    var attest = family === 'instruction-roots' && ['idle', 'cancelled', 'published'].includes(state) && Object.keys(item.roots || {}).length === 2;
    deploymentField('attestation').hidden = !attest;
    var rootSelect = deploymentField('attestation-root'), selectedRoot = rootSelect.value;
    rootSelect.replaceChildren();
    if (attest) {
      Object.keys(item.roots).forEach(function (name) { var option = document.createElement('option'); option.value = name; option.textContent = name; rootSelect.appendChild(option); });
      if (Object.hasOwn(item.roots, selectedRoot)) rootSelect.value = selectedRoot;
      else if (item.attestation_root_id && Object.hasOwn(item.roots, item.attestation_root_id)) rootSelect.value = item.attestation_root_id;
      deploymentField('attested').textContent = 'Fresh signed custody evidence: ' + ((item.attested_root_ids || []).join(', ') || 'none') + '. Each root requires its own signed approval.';
    }
    ['attestation-request', 'attestation-apply'].forEach(function (name) { deploymentField(name).disabled = deploymentBusy || !attest || busyJob; });
    deploymentField('fingerprint').textContent = item && item.fingerprint_sha256 ? 'Replacement SHA256: ' + item.fingerprint_sha256 : '';
    if (trust && deploymentTrust && deploymentTrust.drain) deploymentField('state').textContent += deploymentTrust.drain.ready ?
      ' Recorded deployments are removed; the worker will check again after stopping writers.' :
      ' Removal required: ' + deploymentTrust.drain.blocked_device_ids.join(', ') + '.';
    document.querySelectorAll('#deployment-rotation-workflow input,#deployment-rotation-workflow select').forEach(function (el) { el.disabled = deploymentBusy; });
    deploymentField('prepare').disabled = deploymentBusy || !item || !['idle', 'published', 'cancelled'].includes(state) || busyJob;
    deploymentField('approve').disabled = deploymentBusy || !item || !['awaiting-approval', 'approved'].includes(state) || busyJob;
    deploymentField('cancel').disabled = deploymentBusy || !item || !['awaiting-approval', 'approved'].includes(state) || busyJob;
    deploymentField('download').disabled = deploymentBusy || !item || !(item.csr || item.certificate || item.online_public_key);
    deploymentField('apply').disabled = deploymentBusy || !deploymentRotation || !deploymentRotation.can_rotate || busyJob ||
      !deploymentRotation.families.includes(family) || (trust && (state !== 'approved' || !deploymentTrust.drain || !deploymentTrust.drain.ready));
    deploymentField('refresh').disabled = deploymentBusy;
    deploymentField('jobs').replaceChildren();
    if (deploymentRotation) deploymentRotation.jobs.slice().reverse().forEach(function (job) {
      var row = document.createElement('tr');
      [job.family + ' / ' + job.id, job.state.replaceAll('-', ' '), job.detail + (job.proof ? ' ' + JSON.stringify(job.proof) : '')].forEach(function (value) {
        var cell = document.createElement('td'); cell.textContent = value; row.appendChild(cell);
      });
      if (job.state === 'recovery-required') {
        var recover = document.createElement('button'); recover.className = 'btn ghost'; recover.textContent = 'Recover approved operation';
        recover.disabled = deploymentBusy || !deploymentRotation.can_rotate;
        recover.addEventListener('click', function () { recoverDeploymentRotation(job); });
        row.lastChild.appendChild(recover);
      }
      deploymentField('jobs').appendChild(row);
    });
  }
  async function refreshDeploymentRotation() {
    if (deploymentBusy) return;
    var generation = ++deploymentRead;
    deploymentRotation = null; deploymentTrust = null; renderDeploymentRotation();
    try {
      var results = await Promise.all([deploymentRotationUrl, deploymentTrustUrl].map(async function (url) {
        try {
        var response = await fetch(url), data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Maintenance status unavailable.');
        return data;
        } catch (error) { return {unavailable: error.message}; }
      }));
      if (generation !== deploymentRead) return;
      if (!Array.isArray(results[0].jobs) || !Array.isArray(results[0].families) || typeof results[0].can_rotate !== 'boolean') throw new Error(results[0].unavailable || 'Maintenance response invalid; no changes enabled.');
      deploymentRotation = results[0];
      if (Array.isArray(results[1].items) && results[1].items.length === 3) deploymentTrust = results[1];
      else deploymentField('result').textContent = results[1].unavailable || 'Trust requests unavailable. Independent credential operations remain available.';
      renderDeploymentRotation();
    } catch (error) { if (generation === deploymentRead) deploymentField('result').textContent = error.message; }
  }
  async function deploymentPublicFile(name, limit) {
    var file = deploymentField(name).files[0];
    if (!file || file.size > limit) throw new Error('Choose the required bounded public approval file.');
    var value = await file.text();
    if (/PRIVATE KEY|AGE-SECRET-KEY/i.test(value)) throw new Error('Private keys must stay with their custodian; upload only public material.');
    return value;
  }
  async function recoverDeploymentRotation(job) {
    if (deploymentBusy || !confirm('Resume only this previously approved operation? IRIS will recheck its backup and custody, stop writers and verify the replacement before restarting.')) return;
    deploymentBusy = true; ++deploymentRead; renderDeploymentRotation();
    try {
      var response = await fetch(deploymentRotationUrl, {method: 'POST', headers: csrfHdr({'Content-Type': 'application/json'}),
        body: JSON.stringify({action: 'recover-rotation', family: job.family, request_id: job.id, allow_downtime: true})});
      var data = await response.json();
      if (!response.ok || data.job_id !== job.id) throw new Error(data.error || 'Recovery outcome unknown. Refresh the same operation.');
      deploymentField('result').textContent = 'Recovery accepted for ' + job.id + '. Reconnect after downtime and check evidence.';
    } catch (error) { deploymentField('result').textContent = error.message; }
    finally { deploymentBusy = false; await refreshDeploymentRotation(); }
  }
  async function deploymentAction(action) {
    if (deploymentBusy || !deploymentRotation) return;
    var family = deploymentField('family').value, item = deploymentTrustItem();
    if (['device-tls', 'peer-ca', 'instruction-roots'].includes(family) && !item) return;
    var payload = {action: action, family: family, request_id: item && item.request_id}, endpoint = deploymentTrustUrl;
    try {
      if (action === 'prepare') {
        if (family === 'device-tls') {
          payload.names = deploymentField('names').value.split(',').map(function (value) { return value.trim(); });
          payload.mode = deploymentField('mode').value;
        } else if (family === 'instruction-roots') {
          var first = deploymentField('root-a-name').value.trim(), second = deploymentField('root-b-name').value.trim();
          if (!first || first === second) throw new Error('Provide two distinct existing root names.');
          payload.roots = Object.create(null);
          payload.roots[first] = await deploymentPublicFile('root-a', 4096);
          payload.roots[second] = await deploymentPublicFile('root-b', 4096);
          payload.keylist_signer = first;
        }
        if (!confirm('Prepare replacement trust? Active credentials remain unchanged until a separately confirmed maintenance operation.')) return;
        payload.request_id = null;
        var parameters = JSON.stringify(payload);
        if (!deploymentPending || deploymentPending.parameters !== parameters) deploymentPending = {parameters: parameters, id: maintenanceRequestId()};
        payload.request_id = deploymentPending.id;
      } else if (action === 'attestation-request' || action === 'attestation-apply') {
        payload.root_id = deploymentField('attestation-root').value;
        if (action === 'attestation-apply') {
          if (!item.attestation_request_id || item.attestation_root_id !== payload.root_id) throw new Error('Download and approve a request for the selected root first.');
          payload.request_id = item.attestation_request_id;
          payload.keylist = await deploymentPublicFile('attestation-keylist', 174764);
        } else {
          var attestationParameters = 'attestation:' + payload.root_id;
          if (!deploymentPending || deploymentPending.parameters !== attestationParameters) deploymentPending = {parameters: attestationParameters, id: maintenanceRequestId()};
          payload.request_id = deploymentPending.id;
        }
      } else if (action === 'approve') {
        payload.certificate = await deploymentPublicFile('certificate', 65536);
        if (family === 'instruction-roots') payload.keylist = await deploymentPublicFile('keylist', 174764);
      } else if (action === 'rotate') {
        if (!confirm('Stop this IRIS deployment, verify a cold backup, and rotate this credential? Trust changes require confirmed IRIS removal from devices. Wait for the recorded result and verify consumers before resuming use.')) return;
        endpoint = deploymentRotationUrl;
        if (!item) {
          var key = 'rotate:' + family;
          if (!deploymentPending || deploymentPending.parameters !== key) deploymentPending = {parameters: key, id: maintenanceRequestId()};
          payload.request_id = deploymentPending.id;
        }
        payload.allow_downtime = true;
      } else if (action === 'cancel' && !confirm('Discard this uncommitted trust request? Active trust will remain unchanged.')) return;
      deploymentBusy = true; ++deploymentRead; renderDeploymentRotation();
      var response = await fetch(endpoint, {method: 'POST', headers: csrfHdr({'Content-Type': 'application/json'}), body: JSON.stringify(payload)});
      var data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Outcome unknown. Refresh before retrying.');
      deploymentPending = null;
      if (action === 'attestation-request') rotationDownload('keylist-payload.json', data.payload);
      deploymentField('result').textContent = action === 'attestation-request' ? 'Public request downloaded. Approve it with the selected root in IRIS Offline signing, then import the signed revocation list here.' :
        action === 'attestation-apply' ? 'Signed root attestation validated. Review each root’s fresh evidence.' :
        action === 'rotate' ? 'Maintenance request accepted: ' + data.job_id + '. The Console will disconnect during downtime. Reconnect and refresh evidence; acceptance is not completion.' :
        action === 'approve' ? 'Public approval validated. Schedule downtime before applying it.' : action === 'cancel' ? 'Replacement request cancelled.' : 'Replacement prepared. Download public files and complete required approvals.';
    } catch (error) { deploymentField('result').textContent = error.message; }
    finally { deploymentBusy = false; renderDeploymentRotation(); await refreshDeploymentRotation(); }
  }
  deploymentField('family').addEventListener('change', renderDeploymentRotation);
  deploymentField('refresh').addEventListener('click', refreshDeploymentRotation);
  ['prepare', 'approve', 'cancel', 'attestation-request', 'attestation-apply'].forEach(function (action) { deploymentField(action).addEventListener('click', function () { deploymentAction(action); }); });
  deploymentField('apply').addEventListener('click', function () { deploymentAction('rotate'); });
  deploymentField('download').addEventListener('click', function () {
    var item = deploymentTrustItem();
    if (!item || deploymentBusy) return;
    [['csr', 'iris-device.csr'], ['certificate', 'iris-approved-certificate.pem'], ['online_public_key', 'online.pub'], ['keylist_payload', 'keylist-payload.json']].forEach(function (field) {
      if (item[field[0]]) rotationDownload(field[1], item[field[0]]);
    });
    deploymentField('result').textContent = 'Public files downloaded. For signing roots, use IRIS Offline signing to approve the online key and preserved revocation list, then import both approvals here.';
  });

  var maintenanceState = null, maintenanceBusy = false, maintenanceRead = 0;
  var maintenanceUrl = '/api/v1/settings/key-maintenance';
  function maintenanceField(name) { return document.getElementById('maintenance-' + name); }
  function validMaintenance(data) {
    return data && Number.isInteger(data.revision) && Array.isArray(data.policies) &&
      Array.isArray(data.jobs) && Array.isArray(data.families) && typeof data.worker === 'string';
  }
  function maintenanceControls() {
    document.querySelectorAll('#maintenance-form input,#maintenance-form select,#maintenance-form button,#maintenance-jobs button').forEach(function (el) {
      el.disabled = maintenanceBusy || !maintenanceState;
    });
    var device = maintenanceField('family').value === 'device-instruction';
    maintenanceField('target').disabled = maintenanceBusy || !maintenanceState || !device;
    maintenanceField('target').required = device;
    maintenanceField('interval').min = device ? '8' : '1';
    maintenanceField('interval').max = device ? '21' : '365';
  }
  function maintenanceEdit() {
    var policy = maintenanceState && maintenanceState.policies.find(function (p) { return p.id === maintenanceField('policy').value; });
    maintenanceField('family').value = policy ? policy.family : 'online-signer';
    maintenanceField('target').value = policy && policy.target !== 'deployment' ? policy.target : '';
    maintenanceField('next').value = new Date(policy ? policy.next_at * 1000 : Date.now() + 3600000).toISOString().slice(0, 19);
    maintenanceField('interval').value = policy ? policy.interval_days : 14;
    maintenanceField('window').value = policy ? policy.window_minutes : 30;
    maintenanceField('enabled').checked = Boolean(policy && policy.enabled);
    maintenanceControls();
  }
  function renderMaintenance() {
    maintenanceControls();
    if (!maintenanceState) { maintenanceField('worker').textContent = 'Scheduler status unavailable. Refresh before changing a schedule.'; return; }
    var data = maintenanceState;
    maintenanceField('worker').textContent = 'Scheduler: ' + data.worker.replaceAll('-', ' ') +
      (data.observed_at === null ? '.' : '. Last check ' + new Date(data.observed_at * 1000).toISOString() + '.');
    var familySelect = maintenanceField('family'), selectedFamily = familySelect.value;
    familySelect.replaceChildren(); maintenanceField('families').replaceChildren();
    data.families.forEach(function (family) {
      var option = document.createElement('option'); option.value = family.id; option.textContent = family.label; familySelect.appendChild(option);
      var row = document.createElement('tr');
      [family.label, {prepare: 'Prepare for approval', rotate: 'Rotate credential', review: 'Review reminder'}[family.action], family.requirement].forEach(function (value) {
        var cell = document.createElement('td'); cell.textContent = value; row.appendChild(cell);
      });
      maintenanceField('families').appendChild(row);
    });
    if (selectedFamily) familySelect.value = selectedFamily;
    var chosen = maintenanceField('policy').value;
    maintenanceField('policy').replaceChildren(new Option('New schedule', ''));
    data.policies.forEach(function (p) {
      maintenanceField('policy').appendChild(new Option(p.family + ' / ' + p.target + (p.enabled ? ' — enabled' : ' — disabled'), p.id));
    });
    maintenanceField('policy').value = chosen;
    maintenanceField('jobs').replaceChildren();
    data.jobs.slice().reverse().forEach(function (job) {
      var row = document.createElement('tr');
      [job.family + ' / ' + job.target, new Date(job.due_at * 1000).toISOString(), job.state.replaceAll('-', ' ') + ': ' + job.detail].forEach(function (value) {
        var cell = document.createElement('td'); cell.textContent = value; row.appendChild(cell);
      });
      var actions = document.createElement('td'); row.appendChild(actions);
      var action = job.state === 'review-required' ? 'reviewed' :
        job.state === 'verification-required' && job.family === 'management-token' ? 'retire-management' :
        job.state === 'intervention-required' && job.family === 'management-token' ? 'reconcile-management' :
        job.state === 'intervention-required' && ['online-signer', 'device-instruction'].includes(job.family) ? 'retry' : null;
      if (action) {
        var button = document.createElement('button'); button.className = 'btn ghost';
        button.textContent = {reviewed: 'Acknowledge review', 'retire-management': 'Retire previous credential', 'reconcile-management': 'Check credential recovery', retry: 'Retry after custody review'}[action];
        button.addEventListener('click', function () { maintenanceAction(action, job.id); }); actions.appendChild(button);
      } else if (job.state === 'approval-required') {
        var link = document.createElement('a'); link.href = '#signer-rotation'; link.textContent = 'Complete signer approval above';
        link.addEventListener('click', function (event) { event.preventDefault(); document.getElementById('signer-rotation').scrollIntoView(); refreshRotation(); });
        actions.appendChild(link);
      }
      maintenanceField('jobs').appendChild(row);
    });
    if (!data.jobs.length) {
      var empty = document.createElement('tr'), cell = document.createElement('td'); cell.colSpan = 4;
      cell.textContent = 'No maintenance operations yet.'; empty.appendChild(cell); maintenanceField('jobs').appendChild(empty);
    }
    maintenanceControls();
  }
  async function refreshMaintenance() {
    if (maintenanceBusy) return;
    var generation = ++maintenanceRead;
    maintenanceState = null; renderMaintenance();
    try {
      var response = await fetch(maintenanceUrl), data = await response.json();
      if (generation !== maintenanceRead) return;
      if (!response.ok || !validMaintenance(data)) throw new Error(data.error || 'Maintenance status unavailable.');
      maintenanceState = data; renderMaintenance(); maintenanceEdit();
      maintenanceField('result').textContent = 'Maintenance status refreshed.';
    } catch (error) { if (generation === maintenanceRead) maintenanceField('result').textContent = error.message; }
  }
  async function sendMaintenance(payload) {
    if (maintenanceBusy || !maintenanceState) return;
    maintenanceBusy = true; ++maintenanceRead; maintenanceControls();
    try {
      var response = await fetch(maintenanceUrl, {method: 'POST', headers: csrfHdr({'Content-Type': 'application/json'}), body: JSON.stringify(payload)});
      var data = await response.json();
      if (!response.ok || !validMaintenance(data)) throw new Error(data.error || 'Outcome unknown. Refresh before retrying.');
      maintenanceState = data;
      renderMaintenance();
      if (payload.action === 'save-policy') { maintenanceField('policy').value = payload.policy.id; maintenanceEdit(); }
      maintenanceField('result').textContent = payload.action === 'save-policy' ? 'Schedule saved.' : 'Operation state updated; check the evidence below.';
    } catch (error) {
      maintenanceState = null; maintenanceField('result').textContent = error.message + ' Refresh maintenance before continuing.';
    } finally { maintenanceBusy = false; renderMaintenance(); }
  }
  async function maintenanceAction(action, jobId) {
    var message = action === 'retire-management' ? 'Have you updated and verified every Console instance with the replacement credential? Retire the previous credential now?' :
      action === 'reviewed' ? 'Acknowledge that you reviewed the documented custody procedure? This does not record a completed rotation.' :
      action === 'retry' ? 'Have you reviewed custody and the interrupted operation? Retry this operation now?' :
      'Check the credential files against the interrupted operation? This does not retire either credential.';
    if (confirm(message)) await sendMaintenance({action: action, job_id: jobId, confirm: true});
  }
  maintenanceField('refresh').addEventListener('click', refreshMaintenance);
  maintenanceField('policy').addEventListener('change', maintenanceEdit);
  maintenanceField('family').addEventListener('change', maintenanceControls);
  maintenanceField('form').addEventListener('submit', async function (event) {
    event.preventDefault();
    if (!maintenanceState || maintenanceBusy) return;
    var family = maintenanceField('family').value, enabled = maintenanceField('enabled').checked;
    var next = Date.parse(maintenanceField('next').value + 'Z');
    if (!Number.isFinite(next)) { maintenanceField('result').textContent = 'Choose a valid UTC start time.'; return; }
    var capability = maintenanceState.families.find(function (item) { return item.id === family; });
    if (enabled && !confirm('Enable ' + (capability.action === 'review' ? 'review reminders' : capability.action === 'prepare' ? 'signer preparation for offline approval' : 'credential rotation') + ' for this UTC schedule? ' + capability.requirement + '.')) return;
    await sendMaintenance({action: 'save-policy', revision: maintenanceState.revision, policy: {
      id: maintenanceField('policy').value || maintenanceRequestId(), family: family,
      target: family === 'device-instruction' ? maintenanceField('target').value.trim() : 'deployment',
      enabled: enabled, next_at: Math.floor(next / 1000), interval_days: Number(maintenanceField('interval').value),
      window_minutes: Number(maintenanceField('window').value)
    }});
  });
  // ---- End key maintenance ----

  // ---- Deployment backup workflow ----
  var backupStatus = null, backupBusy = false, backupRead = 0, backupPending = null;
  function backupControls() {
    var active = backupStatus && backupStatus.available;
    var blocked = !active || backupBusy || backupStatus.jobs.some(function (job) {
      return job.state === 'running' || job.state === 'recovery-required';
    });
    document.getElementById('backup-create').disabled = blocked;
    document.getElementById('backup-selected').disabled = blocked;
    var chosen = Boolean(document.getElementById('backup-selected').value);
    document.getElementById('backup-verify').disabled = blocked || !chosen || !backupStatus.can_verify;
    document.getElementById('backup-extract').disabled = blocked || !chosen || !backupStatus.can_extract;
    document.getElementById('backup-restore').disabled = blocked || !chosen || !backupStatus.can_restore;
    document.getElementById('backup-recover').disabled = !active || backupBusy || !backupStatus.jobs.some(function (job) {
      return job.action === 'restore' && job.state === 'recovery-required';
    });
  }
  async function refreshBackups() {
    var generation = ++backupRead;
    backupStatus = null; backupControls();
    var note = document.getElementById('backup-worker-note');
    try {
      var r = await fetch('/api/v1/settings/backups');
      if (!r.ok) throw new Error('Backup worker status unavailable. During capture the Console may be temporarily offline; refresh after it returns.');
      var data = await r.json();
      if (generation !== backupRead) return;
      if (!Array.isArray(data.jobs) || typeof data.available !== 'boolean') throw new Error('Backup worker response is incomplete.');
      backupStatus = data;
      note.textContent = data.note;
      document.getElementById('backup-job-rows').innerHTML = data.jobs.slice().reverse().map(function (job) {
        return '<tr><td>' + esc(fmtDate(job.started_at)) + '</td><td>' + esc(job.action) +
          '</td><td class="machine">' + esc(job.backup_id) + '</td><td>' + esc(job.state) +
          '<br><small>' + esc(job.detail) + '</small></td></tr>';
      }).join('');
      var select = document.getElementById('backup-selected'), previous = select.value;
      select.innerHTML = '<option value="">Choose a backup</option>' + data.jobs.filter(function (job) {
        return job.action === 'backup' && job.state === 'captured';
      }).map(function (job) { return '<option value="' + esc(job.backup_id) + '">' + esc(fmtDate(job.started_at) + ' · ' + job.backup_id) + '</option>'; }).join('');
      select.value = previous;
    } catch (error) {
      if (generation !== backupRead) return;
      backupStatus = null;
      document.getElementById('backup-job-rows').textContent = '';
      note.textContent = error.message || 'Backup status unavailable.';
    }
    backupControls();
  }
  async function requestBackupAction(action) {
    if (backupBusy || !backupStatus || !backupStatus.available) return;
    if (action === 'backup' && !confirm('Stop IRIS and the Console briefly to capture a consistent encrypted backup? Active transfers and management requests will be interrupted.')) return;
    if (action === 'extract' && !confirm('Extract both sets into a new protected recovery directory? This includes secret recovery material. No services will be started.')) return;
    if ((action === 'restore' || action === 'recover-restore') && !confirm('Restore this deployment from the selected backup? IRIS and the Console will stop. Saved content replaces current content only after security checks pass. The worker preserves current instruction counters and retains the previous files for recovery.')) return;
    var selectedBackup = document.getElementById('backup-selected').value;
    if (!backupPending || backupPending.action !== action || (action !== 'backup' && backupPending.backup_id !== selectedBackup)) {
      var requestId = maintenanceRequestId();
      backupPending = action === 'backup' ? {action: action, allow_downtime: true, request_id: requestId}
        : {action: action, backup_id: selectedBackup, request_id: requestId};
      if (action === 'restore' || action === 'recover-restore') {
        backupPending.allow_downtime = true;
        backupPending.confirm_restore = true;
        if (action === 'recover-restore') {
          var interrupted = backupStatus.jobs.find(function (job) { return job.action === 'restore' && job.state === 'recovery-required'; });
          if (!interrupted) { backupPending = null; return; }
          backupPending.request_id = interrupted.id;
          backupPending.backup_id = interrupted.backup_id;
        }
      }
    }
    backupBusy = true; backupControls();
    var result = document.getElementById('backup-operation-result');
    result.textContent = 'Submitting maintenance request…';
    try {
      var r = await fetch('/api/v1/settings/backups', {
        method: 'POST', headers: csrfHdr({'Content-Type': 'application/json'}), body: JSON.stringify(backupPending)
      });
      var data = await r.json();
      if (!r.ok || typeof data.job_id !== 'string') throw new Error(data.error || data.detail || 'Request was not confirmed. Refresh history before retrying.');
      backupPending = null;
      result.textContent = 'Accepted. Refresh history to check the result. Backup and restore temporarily take the Console offline; the host worker continues running.';
      await refreshBackups();
    } catch (error) { result.textContent = error.message || 'Request was not confirmed. Refresh history before retrying.'; }
    finally { backupBusy = false; backupControls(); }
  }
  document.getElementById('backup-refresh').addEventListener('click', refreshBackups);
  document.getElementById('backup-selected').addEventListener('change', backupControls);
  ['create', 'verify', 'extract', 'restore', 'recover'].forEach(function (name) {
    document.getElementById('backup-' + name).addEventListener('click', function () {
      requestBackupAction(name === 'create' ? 'backup' : name === 'recover' ? 'recover-restore' : name);
    });
  });
  // ---- End deployment backup workflow ----

  // ---- Settings section routes (React renders the tab navigation) ----
  // refreshSettings() above always populates all panes' ids regardless of
  // which is visible, so switching sub-pages is pure class/hidden toggling.
  // The tabs use plain hash links (#settings/<sub>), so the router below
  // owns pane visibility and the sections remain deep-linkable.
  var SETTINGS_SUBS = ['general', 'tls', 'telemetry'];
  // The audit-export pane rides the same pane/nav id pattern; appended
  // separately so the original trio stays a literal for the source guard
  // that pins it.
  SETTINGS_SUBS.push('audit');
  // The setup pane rides the same pane/nav id pattern; appended for the
  // same reason (keeps the original trio a literal for the source guard).
  SETTINGS_SUBS.push('setup');
  // Device packages stay available after first-run setup is dismissed.
  SETTINGS_SUBS.push('packages');
  // The Image verification (KGV / Cisco Bulk Hash reconciler) pane rides the
  // same pane/nav id pattern; appended for the same reason.
  SETTINGS_SUBS.push('bulkhash');
  SETTINGS_SUBS.push('certificates');
  SETTINGS_SUBS.push('backups');
  function showSettingsSub(sub) {
    if (SETTINGS_SUBS.indexOf(sub) < 0) sub = 'general';
    SETTINGS_SUBS.forEach(function (t) {
      document.getElementById('settings-pane-' + t).hidden = t !== sub;
    });
    // Claim the shared form back from the wizard, then repopulate it --
    // a freshly cloned form is empty until refreshSettings writes to it.
    if (sub === 'telemetry') mountSettingsForm('td', 'td-mount');
    // Same reclaim, but a move rather than a re-mount -- see
    // mountImageVerification's own comment for why.
    if (sub === 'bulkhash') mountImageVerification('settings-pane-bulkhash');
    if (sub === 'packages') refreshDevicePackages();
    if (sub === 'certificates') { refreshCertificates(); refreshRotation(); refreshMaintenance(); refreshBrowserTls(); refreshServiceCredential(); refreshDeploymentRotation(); }
    if (sub === 'backups') refreshBackups();
    refreshSettings();
  }
  // React owns both Monitoring panes. Share authenticated reads and the
  // existing visible-view timer, without legacy DOM writes into its subtree.
  function monitoringCommand(action, services, sub) {
    return new Promise(function (resolve, reject) {
      window.dispatchEvent(new CustomEvent('iris:monitoring-command', {
        detail: {action: action, services: services, sub: sub, resolve: resolve, reject: reject}
      }));
    });
  }
  function showMonitoringSub(sub) { return monitoringCommand('select', null, sub); }
  function refreshMonitoring() { return monitoringCommand('refresh'); }
  function pollMonitoring() { return monitoringCommand('poll'); }
  await monitoringCommand('connect', {fetch: fetch});

  // OTLP export health badge (spec 8.3), via the console's session-gated
  // proxy — never the unauthenticated :9101 directly.
  var telemetryRefreshGeneration = 0;
  async function refreshTelemetryHealth() {
    var mine = ++telemetryRefreshGeneration;
    var state = 'unknown', detail = '';
    try {
      var r = await fetch('/api/v1/telemetry/health');
      if (!r.ok) throw new Error('health proxy ' + r.status);
      var d = await r.json();
      if (d && d.otlp_export && d.otlp_export.signals) {
        var signals = d.otlp_export.signals;
        state = d.otlp_export.state || 'unknown';
        detail = ['logs', 'metrics'].map(function (name) {
          var signal = signals[name] || {};
          var text = name + ': ' + (signal.state || 'unknown');
          if (name === 'logs') text += ', queued ' + (signal.queued || 0) + ', dropped ' + (signal.dropped_total || 0);
          return text;
        }).join('; ');
      } else if (d && d.otlp_export && d.otlp_export.state) state = d.otlp_export.state;
      else if (d && d.ok === false) state = 'unknown';
      else state = 'off';
    } catch (e) { state = 'unknown'; }
    if (mine !== telemetryRefreshGeneration) return;
    publishOverview({telemetry: {state: state, detail: detail}});
  }

  // React owns header rendering; the existing authenticated client supplies
  // its public help metadata without exposing the session's CSRF token.
  async function publishHelp() {
    var r;
    try { r = await fetch('/api/v1/help'); } catch (e) { return; }
    if (!r.ok) return;
    try {
      var h = await r.json();
      window.dispatchEvent(new CustomEvent('iris:shell-state', { detail: { help: h } }));
    } catch (e) { /* Help metadata must not prevent operational views loading. */ }
  }
  publishHelp();

  // The router remains the only Policies polling timer.
  function cancelPolicyReads() { policies.hide(); }
  function refreshPolicies() { return policies.refresh(); }

  // ---- hash router ----
  var VIEWS = ['overview', 'images', 'devices', 'policies', 'swarm', 'settings', 'monitoring', 'setup'];

  // Periodic refresh of whatever view is on screen. Without this the console
  // only updated on navigation or after an explicit action, so device state
  // that changes server-side -- heartbeats, staging progress, deployment
  // state -- stayed invisible until the operator navigated away and back.
  // refreshDevices() already preserves device selections across a
  // re-render, so a poll does not cost the operator their selection.
  var VIEW_POLL_MS = 10000;
  var viewPollTimer = null;
  var viewPollFn = null;
  function stopViewPoll() {
    if (viewPollTimer !== null) { clearInterval(viewPollTimer); viewPollTimer = null; }
  }
  function startViewPoll(fn) {
    stopViewPoll();
    viewPollFn = fn;
    if (!fn) return;
    viewPollTimer = setInterval(function () {
      // A backgrounded tab must not keep hitting the server. The
      // visibilitychange handler restarts the poll when the tab returns.
      if (document.hidden) return;
      backgroundPoll = true;   // see the fetch wrapper: not operator activity
      try { fn(); } catch (e) { /* a failed refresh must not kill the poll */ }
    }, VIEW_POLL_MS);
  }
  document.addEventListener('visibilitychange', function () {
    // Refresh immediately on return so the operator never reads stale state
    // while waiting out the rest of an interval.
    if (!document.hidden && viewPollFn) {
      try { viewPollFn(); } catch (e) { /* ignore */ }
    }
  });

  function show(view) {
    // "#settings/tls" style hashes: the part before the slash picks the view,
    // the rest picks the view's sub-page (showSettingsSub / showMonitoringSub
    // validate it).
    var sub = view.indexOf('/') > -1 ? view.slice(view.indexOf('/') + 1) : '';
    view = view.split('/')[0];
    if (VIEWS.indexOf(view) < 0) view = 'overview';
    if (view !== 'policies') {
      cancelPolicyReads();
    }
    if (view !== 'devices') { inventory.hide(); deviceForms.hide(); assignments.hide(); inventoryActions.hide(); schedules.hide(); roleActions.hide(); }
    VIEWS.forEach(function (v) {
      document.getElementById('view-' + v).hidden = v !== view;
    });
    if (view !== 'devices') closeDeployInfo(false);
    activityCommand('visibility', {visible: view === 'devices' && !document.hidden});
    var swarmFrame = document.getElementById('swarm-frame');
    if (swarmFrame && swarmFrame.contentWindow) {
      swarmFrame.contentWindow.postMessage(view === 'swarm' ? 'MAP_RESUME' : 'MAP_PAUSE', location.origin);
    }
    // Close legacy workflow popovers on navigation; React owns shell menus.
    if (view !== 'settings' && view !== 'monitoring') closeMenus();
    if (view === 'settings') showSettingsSub(sub || 'general');
    if (view === 'monitoring') showMonitoringSub(sub || 'audit');
    else monitoringCommand('hide');
    // Each view names the refresh the poll should repeat. Settings is
    // deliberately excluded: it is a set of forms, and re-rendering them
    // under the operator's cursor would discard half-typed input.
    var poll = null;
    if (view === 'overview') { refreshOverview(); poll = refreshOverview; }
    else if (view === 'images') {
      refreshImages(); refreshImportable();
      poll = function () { refreshImages(); refreshImportable(); };
    } else if (view === 'devices') { refreshDevices(); deviceForms.resume(); schedules.resume(); poll = pollDevices; }
    else if (view === 'policies') { refreshPolicies(); poll = refreshPolicies; }
    else if (view === 'swarm') { refreshSwarm(); poll = refreshSwarm; }
    else if (view === 'settings') { refreshSetup(); } // showSettingsSub already refreshes the form data.
    else if (view === 'monitoring') { refreshMonitoring(); poll = pollMonitoring; }
    else if (view === 'setup') enterSetupWizard();
    startViewPoll(poll);
  }
  function current() { return (location.hash || '#overview').slice(1); }
  window.addEventListener('hashchange', function () { show(current()); });
  show(current());
  } catch (e) {
    var notice = document.createElement('div');
    notice.textContent = 'Console initialization failed: ' + (e && e.message ? e.message : e) + '. Reload to retry.';
    notice.setAttribute('role', 'alert');
    notice.style.cssText = 'position:fixed;top:12px;left:12px;right:12px;z-index:9999;padding:12px;background:#5b1d1d;color:#fff;border:1px solid #d66;border-radius:4px';
    document.body.appendChild(notice);
  }
})();
