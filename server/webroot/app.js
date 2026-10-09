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
  var settings = window.irisSettings;
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
  // the page behind it, matching the map React drawer's keyboard behavior.
  // Attaching the listener
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
    outcome: function (message, failed) { inventory.report(message, failed); }
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
    var message = roleCapabilityMessage();
    inventory.update({roleAvailable: !message, roleCapabilityMessage: message, policy: peerPolicy, policyOk: peerPolicyReadOk});
  }
  function renderPeerPolicyPanel() {
    syncRoleActionAvailability();
    policies.policy(peerPolicy, peerPolicyReadOk);
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
    var or_, ov;
    try {
      or_ = await fetch('/api/v1/overview', { signal: signal });
      if (!or_.ok || mine !== overviewRefreshGeneration) return;
      // Cancellation can arrive after the headers while JSON is still being
      // read. The body belongs to this same guarded primary request.
      ov = await or_.json();
    } catch (e) {
      // Superseding a refresh is expected (a newer refreshOverview() call
      // already owns the render) and must not be treated as a real
      // failure; any other failure keeps the pre-existing hard bail: no
      // data, nothing to render.
      if (e && e.name === 'AbortError') return;
      return;
    }
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
  var swarmView = window.irisSwarmView;
  swarmView.connect({fetch: fetch, origin: location.origin, visible: function () {
    return !document.hidden && !document.getElementById('view-swarm').hidden;
  }});
  function refreshSwarm() { return swarmView.refresh(); }

  // React owns setup readiness, package tables, wizard steps and the nudge.
  var setupPackages = window.irisSetupPackages;
  setupPackages.connect({
    fetch: fetch, storage: {
      getItem: function (key) { return window.sessionStorage.getItem(key); },
      setItem: function (key, value) { window.sessionStorage.setItem(key, value); }
    },
    navigate: function (hash) { location.hash = hash; },
    visible: function (mode) {
      if (document.hidden) return false;
      if (mode === 'wizard') return !document.getElementById('view-setup').hidden;
      var section = document.getElementById('settings-pane-' + mode);
      return !document.getElementById('view-settings').hidden && !!section && !section.hidden;
    },
    wizardSelect: function (step) {
      if (step !== 'telemetry') settings.hide();
      if (step !== 'imageverification') hideImageVerification();
      if (step === 'telemetry') { settings.select('telemetry', 'wz-td-mount'); refreshSettings(); }
      if (step === 'imageverification') mountImageVerification('wz-iv-mount');
    }
  });
  function wizardSyncImageVerification(cfg) { setupPackages.annotation(cfg ? cfg.mode !== 'off' : null); }
  function enterSetupWizard() { return setupPackages.select('wizard'); }

  // React owns General, TLS/trust, Telemetry and Audit export.
  settings.connect({
    fetch: fetch, headers: csrfHdr, formatDate: fmtDate,
    confirm: function (message) { return confirm(message); },
    setTimeout: function (fn, delay) { return setTimeout(fn, delay); },
    clearTimeout: function (timer) { clearTimeout(timer); },
    visible: function (pane) {
      if (document.hidden) return false;
      if (pane === 'telemetry') {
        var host = document.getElementById(settings.state.telemetryHost);
        return !!(host && host.getClientRects().length);
      }
      var section = document.getElementById('settings-pane-' + pane);
      return !document.getElementById('view-settings').hidden && !!section && !section.hidden;
    }
  });
  async function refreshSettings() {
    await settings.refresh();
    await refreshImageVerificationSettings();
  }
  // React owns the shared Image verification settings/wizard workflow.
  var imageVerification = window.irisImageVerification;
  imageVerification.connect({
    fetch: fetch, headers: csrfHdr, formatDate: fmtDate,
    xhr: function () { return new XMLHttpRequest(); },
    confirm: function (message) { return confirm(message); },
    visible: function (host) {
      if (document.hidden) return false;
      var mount = document.getElementById(host);
      return !!mount && !mount.closest('[hidden]');
    },
    annotation: function (config) { wizardSyncImageVerification(config); },
    catalogChanged: function () {
      // Retire earlier catalog reads before any asynchronous refresh. Hidden
      // Inventory does not fetch; its picker stays unavailable until a fresh
      // catalog read confirms the new quarantine state after navigation.
      assignments.services.publishImages(assignments.acceptImages({ok: false}, assignments.beginImageRead()));
      return Promise.all([refreshImages().catch(function () { }), refreshDevices().catch(function () { })]);
    }
  });
  function mountImageVerification(hostId) {
    imageVerification.select(hostId);
    return imageVerification.refresh();
  }
  function hideImageVerification() { imageVerification.select(null); }
  function refreshImageVerificationSettings() { return imageVerification.refresh(); }


  // React owns certificate inventory, same-key renewal and signer rotation.
  function maintenanceRequestId() {
    var bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 15) | 64; bytes[8] = (bytes[8] & 63) | 128;
    var hex = Array.from(bytes).map(function (byte) { return byte.toString(16).padStart(2, '0'); }).join('');
    return [hex.slice(0, 8), hex.slice(8, 12), hex.slice(12, 16), hex.slice(16, 20), hex.slice(20)].join('-');
  }
  function rotationDownload(name, bytes) {
    var url = URL.createObjectURL(new Blob([bytes], {type: 'application/octet-stream'}));
    var link = document.createElement('a'); link.href = url; link.download = name; link.click();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  var certificates = window.irisCertificates;
  certificates.connect({
    fetch: fetch, headers: csrfHdr, formatDate: fmtDate, uuid: maintenanceRequestId,
    download: rotationDownload, confirm: function (message) { return confirm(message); },
    visible: function () {
      return !document.hidden && !document.getElementById('view-settings').hidden &&
        !document.getElementById('settings-pane-certificates').hidden;
    }
  });
  // Scheduled maintenance can direct the operator back to this public workflow.
  function refreshRotation() { return certificates.refresh('signer'); }

  // React owns public browser-TLS approvals and telemetry credentials.
  var securityLifecycle = window.irisSecurityLifecycle;
  securityLifecycle.connect({
    fetch: fetch, headers: csrfHdr, formatDate: fmtDate, uuid: maintenanceRequestId,
    download: rotationDownload, hostname: location.hostname.replace(/^\[|\]$/g, ''),
    confirm: function (message) { return confirm(message); },
    randomToken: function () {
      return Array.from(crypto.getRandomValues(new Uint8Array(32))).map(function (value) {
        return value.toString(16).padStart(2, '0');
      }).join('');
    },
    visible: function () { return certificates.visible(); }
  });

  // React owns deployment trust, scheduled keys and backup/recovery jobs.
  var workerLifecycle = window.irisWorkerLifecycle;
  workerLifecycle.connect({
    fetch: fetch, headers: csrfHdr, formatDate: fmtDate, uuid: maintenanceRequestId,
    download: rotationDownload, now: function () { return Date.now(); },
    confirm: function (message) { return confirm(message); },
    visible: function (pane) {
      return !document.hidden && !document.getElementById('view-settings').hidden &&
        !document.getElementById('settings-pane-' + pane).hidden;
    },
    openSigner: function () {
      refreshRotation();
      document.getElementById('signer-rotation').scrollIntoView({block: 'start'});
    }
  });

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
    if (sub !== 'certificates') { certificates.hide(); securityLifecycle.hide(); }
    settings.select(sub, 'td-mount');
    SETTINGS_SUBS.forEach(function (t) {
      document.getElementById('settings-pane-' + t).hidden = t !== sub;
    });
    if (sub === 'bulkhash') mountImageVerification('settings-pane-bulkhash');
    else hideImageVerification();
    setupPackages.select(sub === 'setup' || sub === 'packages' ? sub : null);
    if (sub === 'certificates') { certificates.refreshAll(); securityLifecycle.refreshAll(); }
    workerLifecycle.select(sub);
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
    swarmView.syncVisibility();
    if (document.hidden) imageVerification.hide();
    else if (imageVerification.visible()) imageVerification.refresh();
    if (document.hidden) setupPackages.hide();
    else if (setupPackages.visible()) setupPackages.refresh();
    if (document.hidden) settings.hide();
    else if (settings.visible()) settings.refresh();
    if (document.hidden) certificates.hide();
    else if (certificates.visible()) certificates.refreshAll();
    if (document.hidden) securityLifecycle.hide();
    else if (securityLifecycle.visible()) securityLifecycle.refreshAll();
    if (document.hidden) workerLifecycle.hide();
    else if (workerLifecycle.visible()) workerLifecycle.refreshAll();
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
    if (view !== 'settings' && view !== 'setup') { settings.hide(); setupPackages.select(null); hideImageVerification(); }
    if (view !== 'settings') { certificates.hide(); securityLifecycle.hide(); workerLifecycle.select(null); }
    if (view !== 'policies') {
      cancelPolicyReads();
    }
    if (view !== 'devices') { inventory.hide(); deviceForms.hide(); assignments.hide(); inventoryActions.hide(); schedules.hide(); roleActions.hide(); }
    VIEWS.forEach(function (v) {
      document.getElementById('view-' + v).hidden = v !== view;
    });
    if (view !== 'devices') closeDeployInfo(false);
    activityCommand('visibility', {visible: view === 'devices' && !document.hidden});
    swarmView.syncVisibility();
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
